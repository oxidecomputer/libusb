/*
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * Copyright 2022 Oxide Computer Company
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <config.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wait.h>
#include <unistd.h>
#include <aio.h>
#include <libdevinfo.h>
#include <sys/nvpair.h>
#include <sys/devctl.h>
#include <sys/usb/clients/ugen/usb_ugen.h>
#include <sys/usb/usba.h>
#include <sys/pci.h>

#include "libusbi.h"
#include "illumos_usb.h"

#define	UPDATEDRV_PATH	"/usr/sbin/update_drv"
#define	UPDATEDRV	"update_drv"

#define	DEFAULT_LISTSIZE	6

/*
 * Backend functions
 */
static int illumos_get_device_list(struct libusb_context *,
    struct discovered_devs **);
static int illumos_open(struct libusb_device_handle *);
static void illumos_close(struct libusb_device_handle *);
static int illumos_get_active_config_descriptor(struct libusb_device *,
    void *, size_t);
static int illumos_get_config_descriptor(struct libusb_device *, uint8_t,
    void *, size_t);
static int illumos_get_configuration(struct libusb_device_handle *, uint8_t *);
static int illumos_set_configuration(struct libusb_device_handle *, int);
static int illumos_claim_interface(struct libusb_device_handle *, uint8_t);
static int illumos_release_interface(struct libusb_device_handle *, uint8_t);
static int illumos_set_interface_altsetting(struct libusb_device_handle *,
    uint8_t, uint8_t);
static int illumos_clear_halt(struct libusb_device_handle *, unsigned char);
static void illumos_destroy_device(struct libusb_device *);
static int illumos_submit_transfer(struct usbi_transfer *);
static int illumos_cancel_transfer(struct usbi_transfer *);
static int illumos_handle_transfer_completion(struct usbi_transfer *);
static int illumos_kernel_driver_active(struct libusb_device_handle *, uint8_t);
static int illumos_usb_open_ep0(illumos_dev_handle_priv_t *hpriv,
    illumos_dev_priv_t *dpriv);

static int
illumos_get_link(di_devlink_t devlink, void *arg)
{
	walk_link_t *larg = (walk_link_t *)arg;
	const char *p;
	const char *q;

	if (larg->path) {
		char *content = (char *)di_devlink_content(devlink);
		char *start = strstr(content, "/devices/");
		start += strlen("/devices");
		usbi_dbg(NULL, "%s", start);

		/* line content must have minor node */
		if (start == NULL ||
		    strncmp(start, larg->path, larg->len) != 0 ||
		    start[larg->len] != ':') {
			return (DI_WALK_CONTINUE);
		}
	}

	p = di_devlink_path(devlink);
	q = strrchr(p, '/');
	usbi_dbg(NULL, "%s", q);

	*(larg->linkpp) = strndup(p, strlen(p) - strlen(q));

	return (DI_WALK_TERMINATE);
}


static int
illumos_physpath_to_devlink(
    const char *node_path, const char *match, char **link_path)
{
	walk_link_t larg;
	di_devlink_handle_t hdl;

	*link_path = NULL;
	larg.linkpp = link_path;
	if ((hdl = di_devlink_init(NULL, 0)) == NULL) {
		usbi_dbg(NULL, "di_devlink_init failure");
		return (-1);
	}

	larg.len = strlen(node_path);
	larg.path = (char *)node_path;

	(void) di_devlink_walk(hdl, match, NULL, DI_PRIMARY_LINK,
	    (void *)&larg, illumos_get_link);

	(void) di_devlink_fini(&hdl);

	if (*link_path == NULL) {
		usbi_dbg(NULL, "there is no devlink for this path");
		return (-1);
	}

	return (0);
}

static int
illumos_kernel_driver_active(struct libusb_device_handle *dev_handle,
    uint8_t interface)
{
	illumos_dev_priv_t *dpriv = usbi_get_device_priv(dev_handle->dev);

	UNUSED(interface);

	usbi_dbg(HANDLE_CTX(dev_handle), "%s", dpriv->ugenpath);

	return (dpriv->ugenpath == NULL);
}

/*
 * Private functions
 */
static int _errno_to_libusb(int);
static int illumos_usb_get_status(struct libusb_context *ctx, int fd);

static int
illumos_bus_number(struct node_args *nargs, di_node_t root_hub, uint8_t *bus)
{
	/*
	 * Determine the driver name and instance number for the root hub.
	 * We will use this to assign a USB bus number.
	 */
	char *driver;
	int inum;
	if ((driver = di_driver_name(root_hub)) == NULL ||
	    (inum = di_instance(root_hub)) < 0) {
		return (EIO);
	}

	char *instance;
	if (asprintf(&instance, "%s%d", driver, inum) < 0) {
		return (EIO);
	}

	/*
	 * Walk through to check if we have assigned this already:
	 */
	for (uint_t n = 0; n < MAX_BUSES; n++) {
		if (nargs->buses[n] == NULL) {
			/*
			 * If we reach an unused slot, use that slot for
			 * this root hub:
			 */
			nargs->buses[n] = instance;
			if (bus != NULL) {
				*bus = n;
			}
			return (0);
		} else if (strcmp(nargs->buses[n], instance) == 0) {
			/*
			 * This root hub was already assigned a device:
			 */
			free(instance);
			if (bus != NULL) {
				*bus = n;
			}
			return (0);
		}
	}

	/*
	 * We have run out of bus IDs!
	 */
	free(instance);
	return (EOVERFLOW);
}

/*
 * Our 64-bit session IDs for devices other than root hubs have the
 * following format:
 *
 *	BITS
 *	0-7		device assigned-address
 *	8-15		hub level 0 (immediate parent) assigned-address
 *	16-23		hub level 1 (if present)
 *	24-31		hub level 2 (if present)
 *	32-39		hub level 3 (if present)
 *	40-47		hub level 4 (if present)
 *	48-50		root hub PCI function
 *	51-55		root hub PCI device
 *	56-63		root hub PCI bus
 *
 * For a root hub, only bits 48-63 will be populated and the rest will be
 * zero.
 */
static int
illumos_make_session_id(struct node_args *nargs, di_node_t node,
     uint64_t *sidp, uint8_t *busp, int *is_root_hub)
{
	uint64_t sid = 0;
	uint_t byt = 0;

	if (is_root_hub != NULL) {
		*is_root_hub = 1;
	}

	while (node != DI_NODE_NIL) {
		int r;
		int *unused;
		int root_hub = 0;

		usbi_dbg(NULL, "loop %p", node);

		/*
		 * Look for the "root-hub" property on this device node.
		 * The property is a boolean, so its mere existence
		 * represents "true".  If true, this node is a root hub.
		 */
		if ((r = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "root-hub", &unused)) == 0) {
			root_hub = 1;
		} else if (r >= 1) {
			/*
			 * This should never happen for a boolean property.
			 */
			usbi_dbg(NULL, "unexpected root-hub "
			    "lookup return %d", r);
			return (EIO);
		} else if (r < 0 && errno != ENXIO) {
			/*
			 * Report errors other than a failure to find the
			 * property.
			 */
			usbi_dbg(NULL, "unexpected root-hub "
			    "lookup error %d", errno);
			return (EIO);
		}

		if (!root_hub) {
			int *addr;

			if (is_root_hub != NULL) {
				/*
				 * If we see any other device, this is not a
				 * root hub.
				 */
				*is_root_hub = 0;
			}

			/*
			 * Get the "assigned-address" value of the current
			 * node.  Root hubs don't have this property, but
			 * all other USB devices (including external hubs)
			 * must.
			 */
			if ((r = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
			    "assigned-address", &addr)) < 0) {
				/*
				 * XXX report error
				 */
				usbi_dbg(NULL, "unexpected address "
				    "lookup error %d", errno);
				return (EIO);
			} else if (r != 1) {
				/*
				 * XXX Expected just one integer here, not a
				 * boolean or a list.
				 */
				usbi_dbg(NULL, "unexpected address "
				    "lookup return %d", r);
				return (EIO);
			} else if (*addr > UINT8_MAX || *addr < 1) {
				/*
				 * We need USB addresses to fit in a byte
				 * and to be non-zero.
				 */
				usbi_dbg(NULL, "unexpected address %d",
				    *addr);
				return (EIO);
			}

			/*
			 * Store the USB address in the session ID in the
			 * next available byte.
			 */
			if (byt >= 5) {
				/*
				 * We have run out of slots.
				 */
				usbi_dbg(NULL, "ran out of slots");
				return (EIO);
			}
			usbi_dbg(NULL, "slot %u = %x", byt, *addr & 0xFF);
			sid |= (*addr & 0xFF) << (byt++ * 8);

			/*
			 * Walk one node up the device tree.
			 */
			node = di_parent_node(node);
			continue;
		}

		/*
		 * Assign a bus number to this root hub if we have not done
		 * that already.
		 */
		if ((r = illumos_bus_number(nargs, node, busp)) != 0) {
			usbi_dbg(NULL, "bus number failure %d", r);
			return (r);
		}

		/*
		 * This is the USB host controller.  Determine the PCI BDF
		 * for this device and include it at the top of the session
		 * ID:
		 */
		int *regs;
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "reg",
		    &regs) <= 0) {
			/*
			 * XXX
			 */
			usbi_dbg(NULL, "reg lookup failure %d %d", r, errno);
			return (EIO);
		}
		sid |= (uint64_t)(PCI_REG_FUNC_G(regs[0])) << 48;
		sid |= (uint64_t)(PCI_REG_DEV_G(regs[0])) << 51;
		sid |= (uint64_t)(PCI_REG_BUS_G(regs[0])) << 56;

		/*
		 * Once we have found the root hub, the session ID is
		 * complete.
		 */
		*sidp = sid;
		return (0);
	}

	/*
	 * If we get down here, it means we have walked out of the tree
	 * without finding the root hub.
	 */
	usbi_dbg(NULL, "could not find root hub!");
	return (ENOENT);
}


static int
illumos_fill_in_dev_info(struct node_args *nargs, di_node_t node,
    struct libusb_device *dev)
{
	int proplen;
	int *i, n, *addr, *port_prop;
	char *phypath;
	uint8_t *rdata;
	illumos_dev_priv_t *dpriv = usbi_get_device_priv(dev);
	char match_str[PATH_MAX];
	di_node_t parent;

	/* Device descriptors */
	proplen = di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
	    "usb-dev-descriptor", &rdata);
	if (proplen <= 0) {
		return (LIBUSB_ERROR_IO);
	}
	bcopy(rdata, &dev->device_descriptor, LIBUSB_DT_DEVICE_SIZE);

	/* Raw configuration descriptors */
	proplen = di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
	    "usb-raw-cfg-descriptors", &rdata);
	if (proplen <= 0) {
		usbi_dbg(DEVICE_CTX(dev), "can't find raw config descriptors");

		return (LIBUSB_ERROR_IO);
	}
	dpriv->raw_cfgdescr = calloc(1, proplen);
	if (dpriv->raw_cfgdescr == NULL) {
		return (LIBUSB_ERROR_NO_MEM);
	} else {
		bcopy(rdata, dpriv->raw_cfgdescr, proplen);
		dpriv->cfgvalue = ((struct libusb_config_descriptor *)
		    rdata)->bConfigurationValue;
	}

	/*
	 * The "reg" property contains the port number that this device
	 * is connected to, which is of course only unique within the hub
	 * to which the device is attached.
	 */
	n = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "reg", &port_prop);
	if (n != 1 || *port_prop <= 0) {
		return (LIBUSB_ERROR_IO);
	}
	dev->port_number = *port_prop;

	/*
	 * In addition to the port number, we must also populate the
	 * parent device pointer so that USB devices can be correctly
	 * treated as a tree.  The parent links are used by
	 * libusb_get_port_numbers() to construct the full path back to
	 * the root hub (not just the local port number), which is then
	 * used by software like hidapi to uniquely identify a device.
	 */
	if ((parent = di_parent_node(node)) == DI_NODE_NIL) {
		usbi_dbg(DEVICE_CTX(dev), "could not get parent node");
		return (LIBUSB_ERROR_IO);
	} else {
		uint64_t psid;
		int is_root_hub;
		if (illumos_make_session_id(nargs, parent, &psid, NULL,
		    &is_root_hub) != 0) {
			usbi_dbg(DEVICE_CTX(dev), "could not get "
			    "session ID for parent node");
			return (LIBUSB_ERROR_IO);
		}

		if (is_root_hub) {
			usbi_dbg(DEVICE_CTX(dev), "parent device %llx "
			    "for session ID %llx is a root hub",
			    (unsigned long long)psid,
			    (unsigned long long)dev->session_data);
			dev->parent_dev = NULL;
		} else if ((dev->parent_dev = usbi_get_device_by_session_id(
		    nargs->ctx, psid)) == NULL) {
			usbi_dbg(DEVICE_CTX(dev), "could not locate "
			    "parent device %llx for session ID %llx",
			    (unsigned long long)psid,
			    (unsigned long long)dev->session_data);
			return (LIBUSB_ERROR_IO);
		}
	}

	/* device physical path */
	phypath = di_devfs_path(node);
	if (phypath) {
		dpriv->phypath = strdup(phypath);
		snprintf(match_str, sizeof(match_str), "^usb/%x.%x",
		    dev->device_descriptor.idVendor,
		    dev->device_descriptor.idProduct);
		usbi_dbg(DEVICE_CTX(dev), "match is %s", match_str);
		illumos_physpath_to_devlink(dpriv->phypath, match_str,
		    &dpriv->ugenpath);
		di_devfs_path_free(phypath);
	} else {
		free(dpriv->raw_cfgdescr);

		return (LIBUSB_ERROR_IO);
	}

	/* address */
	n = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "assigned-address",
	    &addr);
	if (n != 1 || *addr == 0) {
		usbi_dbg(DEVICE_CTX(dev), "can't get address");
	} else {
		dev->device_address = *addr;
	}

	/* speed */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "low-speed", &i) >= 0) {
		dev->speed = LIBUSB_SPEED_LOW;
	} else if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "high-speed",
	    &i) >= 0) {
		dev->speed = LIBUSB_SPEED_HIGH;
	} else if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "full-speed",
	    &i) >= 0) {
		dev->speed = LIBUSB_SPEED_FULL;
	} else if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "super-speed",
	    &i) >= 0) {
		dev->speed = LIBUSB_SPEED_SUPER;
	}

	usbi_dbg(DEVICE_CTX(dev),
	    "vid=%x pid=%x, path=%s, bus=%u, port_number=%d, speed=%d",
	    dev->device_descriptor.idVendor,
	    dev->device_descriptor.idProduct,
	    dpriv->phypath, dev->bus_number, dev->port_number, dev->speed);

	return (LIBUSB_SUCCESS);
}

static int
illumos_add_devices(di_devlink_t link, void *arg)
{
	struct devlink_cbarg *largs = (struct devlink_cbarg *)arg;
	struct node_args *nargs = largs->nargs;
	struct libusb_device *dev;
	illumos_dev_priv_t *devpriv;
	int r;

	UNUSED(link);

	for (di_node_t node = di_child_node(largs->myself);
	    node != DI_NODE_NIL; node = di_sibling_node(node)) {
		uint64_t session_id = 0;
		uint8_t bus_number = 0;
		int root_hub = 0;
		if ((r = illumos_make_session_id(nargs, node, &session_id,
		    &bus_number, &root_hub)) != 0) {
			usbi_dbg(NULL, "could not generate session ID (%d)",
			    r);
			return (DI_WALK_TERMINATE);
		}

		char *path = di_devfs_path(node);
		if (path == NULL) {
			usbi_dbg(NULL, "di_devfs_path() failure!");
			return (DI_WALK_TERMINATE);
		}

		usbi_dbg(NULL,
		    "bus number = %u, session ID = 0x%llx, path = %s",
		    (uint_t)bus_number, (unsigned long long)session_id,
		    path);

		di_devfs_path_free(path);

		if (root_hub) {
			usbi_dbg(NULL, "skipping root hub (%llx)",
			    (unsigned long long)session_id);
			continue;
		}

		dev = usbi_get_device_by_session_id(nargs->ctx, session_id);
		if (dev == NULL) {
			dev = usbi_alloc_device(nargs->ctx, session_id);
			if (dev == NULL) {
				usbi_dbg(NULL, "can't alloc device");
				continue;
			}
			devpriv = usbi_get_device_priv(dev);
			dev->bus_number = bus_number;

			if (illumos_fill_in_dev_info(nargs, node, dev) !=
			    LIBUSB_SUCCESS) {
				libusb_unref_device(dev);
				usbi_dbg(NULL, "get information fail");
				continue;
			}
			if (usbi_sanitize_device(dev) < 0) {
				libusb_unref_device(dev);
				usbi_dbg(NULL, "sanatize failed: ");
				return (DI_WALK_TERMINATE);
			}
		} else {
			devpriv = usbi_get_device_priv(dev);
			usbi_dbg(NULL, "Dev %s exists", devpriv->ugenpath);
		}

		if (discovered_devs_append(*(nargs->discdevs), dev) == NULL) {
			usbi_dbg(NULL, "cannot append device");
		}

		/*
		 * we alloc and hence ref this dev. We don't need to ref it
		 * hereafter. Front end or app should take care of their ref.
		 */
		libusb_unref_device(dev);

		usbi_dbg(NULL, "Device %s %s id=0x%" PRIx64
		    ", devcount:%" PRIuPTR,
		    devpriv->ugenpath, devpriv->phypath,
		    (uint64_t)session_id, (*nargs->discdevs)->len);
	}

	return (DI_WALK_CONTINUE);
}

static int
illumos_walk_minor_node_link(di_node_t node, void *args)
{
	di_minor_t minor = DI_MINOR_NIL;
	char *minor_path;
	struct devlink_cbarg arg;
	struct node_args *nargs = (struct node_args *)args;
	di_devlink_handle_t devlink_hdl = nargs->dlink_hdl;

	/* walk each minor to find usb devices */
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		minor_path = di_devfs_minor_path(minor);
		arg.nargs = args;
		arg.myself = node;
		arg.minor = minor;
		(void) di_devlink_walk(devlink_hdl,
		    "^usb/hub[0-9]+", minor_path,
		    DI_PRIMARY_LINK, (void *)&arg, illumos_add_devices);
		di_devfs_path_free(minor_path);
	}

	/* switch to a different node */
	nargs->last_ugenpath = NULL;

	return (DI_WALK_CONTINUE);
}

int
illumos_get_device_list(struct libusb_context * ctx,
	struct discovered_devs **discdevs)
{
	di_node_t root_node;
	struct node_args args;
	di_devlink_handle_t devlink_hdl;

	args.ctx = ctx;
	args.discdevs = discdevs;
	args.last_ugenpath = NULL;
	bzero(args.buses, sizeof (args.buses));
	if ((root_node = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		usbi_dbg(ctx, "di_int() failed: errno %d (%s)", errno,
		    strerror(errno));
		return (LIBUSB_ERROR_IO);
	}

	if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
		di_fini(root_node);
		usbi_dbg(ctx, "di_devlink_init() failed: errno %d (%s)", errno,
		    strerror(errno));
		return (LIBUSB_ERROR_IO);
	}
	args.dlink_hdl = devlink_hdl;

	/* walk each node to find USB devices */
	if (di_walk_node(root_node, DI_WALK_SIBFIRST, &args,
	    illumos_walk_minor_node_link) == -1) {
		usbi_dbg(ctx, "di_walk_node() failed: errno %d (%s)", errno,
		    strerror(errno));
		di_fini(root_node);
		return (LIBUSB_ERROR_IO);
	}

	di_fini(root_node);
	di_devlink_fini(&devlink_hdl);

	usbi_dbg(ctx, "%zu devices", (*discdevs)->len);

	return ((*discdevs)->len);
}

static int
illumos_usb_open_ep0(illumos_dev_handle_priv_t *hpriv,
    illumos_dev_priv_t *dpriv)
{
	char filename[PATH_MAX + 1];

	if (hpriv->eps[0].datafd > 0) {
		return (LIBUSB_SUCCESS);
	}
	snprintf(filename, PATH_MAX, "%s/cntrl0", dpriv->ugenpath);

	usbi_dbg(NULL, "opening %s", filename);
	hpriv->eps[0].datafd = open(filename, O_RDWR);
	if (hpriv->eps[0].datafd < 0) {
		return (_errno_to_libusb(errno));
	}

	snprintf(filename, PATH_MAX, "%s/cntrl0stat", dpriv->ugenpath);
	hpriv->eps[0].statfd = open(filename, O_RDONLY);
	if (hpriv->eps[0].statfd < 0) {
		close(hpriv->eps[0].datafd);
		hpriv->eps[0].datafd = -1;
		return (_errno_to_libusb(errno));
	}

	return (LIBUSB_SUCCESS);
}

static void
illumos_usb_close_all_eps(illumos_dev_handle_priv_t *hdev)
{
	int i;

	/* not close ep0 */
	for (i = 1; i < USB_MAXENDPOINTS; i++) {
		if (hdev->eps[i].datafd != -1) {
			(void) close(hdev->eps[i].datafd);
			hdev->eps[i].datafd = -1;
		}
		if (hdev->eps[i].statfd != -1) {
			(void) close(hdev->eps[i].statfd);
			hdev->eps[i].statfd = -1;
		}
	}
}

static void
illumos_usb_close_ep0(illumos_dev_handle_priv_t *hdev)
{
	if (hdev->eps[0].datafd >= 0) {
		close(hdev->eps[0].datafd);
		close(hdev->eps[0].statfd);
		hdev->eps[0].datafd = -1;
		hdev->eps[0].statfd = -1;
	}
}

static uchar_t
illumos_usb_ep_index(uint8_t ep_addr)
{
	return ((ep_addr & LIBUSB_ENDPOINT_ADDRESS_MASK) +
	    ((ep_addr & LIBUSB_ENDPOINT_DIR_MASK) ? 16 : 0));
}

static int
illumos_find_interface(struct libusb_device_handle *hdev,
    uint8_t endpoint, uint8_t *interface)
{
	struct libusb_config_descriptor *config;
	int r;
	int iface_idx;

	r = libusb_get_active_config_descriptor(hdev->dev, &config);
	if (r < 0) {
		usbi_dbg(HANDLE_CTX(hdev), "could not get active desc");
		return (LIBUSB_ERROR_INVALID_PARAM);
	}

	for (iface_idx = 0; iface_idx < config->bNumInterfaces; iface_idx++) {
		const struct libusb_interface *iface =
		    &config->interface[iface_idx];
		int altsetting_idx;

		usbi_dbg(HANDLE_CTX(hdev), "check iface %d", iface_idx);
		for (altsetting_idx = 0; altsetting_idx < iface->num_altsetting;
		    altsetting_idx++) {
			const struct libusb_interface_descriptor *altsetting =
			    &iface->altsetting[altsetting_idx];
			int ep_idx;

			usbi_dbg(HANDLE_CTX(hdev), "check iface %d alt %d",
			    iface_idx, altsetting_idx);
			for (ep_idx = 0; ep_idx < altsetting->bNumEndpoints;
			    ep_idx++) {
				const struct libusb_endpoint_descriptor *ep =
				    &altsetting->endpoint[ep_idx];

				usbi_dbg(HANDLE_CTX(hdev), "check iface %d "
				    "alt %d ep_idx %d; has epa %02x",
				    iface_idx, altsetting_idx, ep_idx,
				    (uint32_t)ep->bEndpointAddress);

				if (ep->bEndpointAddress == endpoint) {
					*interface = iface_idx;
					libusb_free_config_descriptor(config);

					return (LIBUSB_SUCCESS);
				}
			}
		}
	}
	libusb_free_config_descriptor(config);

	return (LIBUSB_ERROR_INVALID_PARAM);
}

static int
illumos_check_device_and_status_open(struct libusb_device_handle *hdl,
    uint8_t ep_addr, int ep_type)
{
	char filename[PATH_MAX + 1], statfilename[PATH_MAX + 1];
	char cfg_num[16], alt_num[16];
	int fd, fdstat, mode, e;
	uint8_t ifc = 0;
	uint8_t ep_index;
	illumos_dev_handle_priv_t *hpriv;

	usbi_dbg(HANDLE_CTX(hdl), "open ep 0x%02x", ep_addr);
	hpriv = usbi_get_device_handle_priv(hdl);
	ep_index = illumos_usb_ep_index(ep_addr);
	/* ep already opened */
	if ((hpriv->eps[ep_index].datafd > 0) &&
	    (hpriv->eps[ep_index].statfd > 0)) {
		usbi_dbg(HANDLE_CTX(hdl),
		    "ep 0x%02x already opened, return success", ep_addr);

		return (0);
	}

	if (illumos_find_interface(hdl, ep_addr, &ifc) < 0) {
		usbi_dbg(HANDLE_CTX(hdl),
		    "can't find interface for endpoint 0x%02x", ep_addr);
		return (EACCES);
	}

	/* create filename */
	if (hpriv->config_index > 0) {
		(void) snprintf(cfg_num, sizeof(cfg_num), "cfg%d",
		    hpriv->config_index + 1);
	} else {
		bzero(cfg_num, sizeof(cfg_num));
	}

	if (hpriv->altsetting[ifc] > 0) {
		(void) snprintf(alt_num, sizeof(alt_num), ".%d",
		    hpriv->altsetting[ifc]);
	} else {
		bzero(alt_num, sizeof(alt_num));
	}

	if ((e = snprintf(filename, sizeof (filename), "%s/%sif%d%s%s%d",
	    hpriv->dpriv->ugenpath, cfg_num, ifc, alt_num,
	    (ep_addr & LIBUSB_ENDPOINT_DIR_MASK) ? "in" :
	    "out", (ep_addr & LIBUSB_ENDPOINT_ADDRESS_MASK))) < 0 ||
	    e >= (int)sizeof (filename) ||
	    (e = snprintf(statfilename, sizeof (statfilename), "%sstat",
	    filename)) < 0 || e >= (int)sizeof (statfilename)) {
		usbi_dbg(HANDLE_CTX(hdl),
		    "path buffer overflow for endpoint 0x%02x", ep_addr);
		return (EINVAL);
	}

	/*
	 * In case configuration has been switched, the xfer endpoint needs
	 * to be opened before the status endpoint, due to a ugen issue.
	 * However, to enable the one transfer mode for an Interrupt-In pipe,
	 * the status endpoint needs to be opened before the xfer endpoint.
	 * So, open the xfer mode first and close it immediately
	 * as a workaround. This will handle the configuration switch.
	 * Then, open the status endpoint.  If for an Interrupt-in pipe,
	 * write the USB_EP_INTR_ONE_XFER control to the status endpoint
	 * to enable the one transfer mode.  Then, re-open the xfer mode.
	 */
	if (ep_type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
		mode = O_RDWR;
	} else if (ep_addr & LIBUSB_ENDPOINT_IN) {
		mode = O_RDONLY;
	} else {
		mode = O_WRONLY;
	}
	/* Open the xfer endpoint first */
	if ((fd = open(filename, mode)) == -1) {
		usbi_dbg(HANDLE_CTX(hdl), "can't open %s: errno %d (%s)",
		    filename, errno, strerror(errno));
		return (errno);
	}
	/* And immediately close the xfer endpoint */
	(void) close(fd);

	/*
	 * Open the status endpoint.
	 * If for an Interrupt-IN pipe, need to enable the one transfer mode
	 * by writing USB_EP_INTR_ONE_XFER control to the status endpoint
	 * before opening the xfer endpoint
	 */
	if ((ep_type == LIBUSB_TRANSFER_TYPE_INTERRUPT) &&
	    (ep_addr & LIBUSB_ENDPOINT_IN)) {
		char control = USB_EP_INTR_ONE_XFER;
		ssize_t count;

		/* Open the status endpoint with RDWR */
		if ((fdstat = open(statfilename, O_RDWR)) == -1) {
			usbi_dbg(HANDLE_CTX(hdl),
			    "can't open %s RDWR: errno %d (%s)",
			    statfilename, errno, strerror(errno));
			return (errno);
		} else {
			count = write(fdstat, &control, sizeof(control));
			if (count != 1) {
				/* this should have worked */
				usbi_dbg(HANDLE_CTX(hdl),
				    "can't write to %s: errno %d (%s)",
				    statfilename, errno, strerror(errno));
				(void) close(fdstat);
				return (errno);
			}
		}
	} else {
		if ((fdstat = open(statfilename, O_RDONLY)) == -1) {
			usbi_dbg(HANDLE_CTX(hdl),
			    "can't open %s: errno %d (%s)", statfilename, errno,
			    strerror(errno));
			return (errno);
		}
	}

	/* Re-open the xfer endpoint */
	if ((fd = open(filename, mode)) == -1) {
		usbi_dbg(HANDLE_CTX(hdl), "can't open %s: errno %d (%s)",
		    filename, errno, strerror(errno));
		(void) close(fdstat);
		return (errno);
	}

	hpriv->eps[ep_index].datafd = fd;
	hpriv->eps[ep_index].statfd = fdstat;
	usbi_dbg(HANDLE_CTX(hdl), "ep=0x%02x datafd=%d, statfd=%d", ep_addr,
	    fd, fdstat);
	return (0);
}

int
illumos_open(struct libusb_device_handle *handle)
{
	illumos_dev_handle_priv_t *hpriv;
	illumos_dev_priv_t *dpriv;
	int i;
	int ret;

	hpriv = usbi_get_device_handle_priv(handle);
	dpriv = usbi_get_device_priv(handle->dev);
	hpriv->dpriv = dpriv;

	/* set all file descriptors to "closed" */
	for (i = 0; i < USB_MAXENDPOINTS; i++) {
		hpriv->eps[i].datafd = -1;
		hpriv->eps[i].statfd = -1;
	}

	if (illumos_kernel_driver_active(handle, 0)) {
		/* pretend we can open the device */
		return (LIBUSB_SUCCESS);
	}

	if ((ret = illumos_usb_open_ep0(hpriv, dpriv)) != LIBUSB_SUCCESS) {
		usbi_dbg(HANDLE_CTX(handle), "fail: %d", ret);
		return (ret);
	}

	return (LIBUSB_SUCCESS);
}

void
illumos_close(struct libusb_device_handle *handle)
{
	illumos_dev_handle_priv_t *hpriv;

	usbi_dbg(HANDLE_CTX(handle), " ");

	hpriv = usbi_get_device_handle_priv(handle);

	illumos_usb_close_all_eps(hpriv);
	illumos_usb_close_ep0(hpriv);
}

int
illumos_get_active_config_descriptor(struct libusb_device *dev,
    void *buf, size_t len)
{
	illumos_dev_priv_t *dpriv = usbi_get_device_priv(dev);
	struct libusb_config_descriptor *cfg;
	int proplen;
	di_node_t node;
	uint8_t *rdata;

	/*
	 * Keep raw configuration descriptors updated, in case config
	 * has ever been changed through setCfg.
	 */
	if ((node = di_init(dpriv->phypath, DINFOCPYALL)) == DI_NODE_NIL) {
		usbi_dbg(DEVICE_CTX(dev), "di_int() failed: errno %d (%s)",
		    errno, strerror(errno));
		return (LIBUSB_ERROR_IO);
	}
	proplen = di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
	    "usb-raw-cfg-descriptors", &rdata);
	if (proplen <= 0) {
		usbi_dbg(DEVICE_CTX(dev), "can't find raw config descriptors");
		return (LIBUSB_ERROR_IO);
	}
	dpriv->raw_cfgdescr = realloc(dpriv->raw_cfgdescr, proplen);
	if (dpriv->raw_cfgdescr == NULL) {
		return (LIBUSB_ERROR_NO_MEM);
	} else {
		bcopy(rdata, dpriv->raw_cfgdescr, proplen);
		dpriv->cfgvalue = ((struct libusb_config_descriptor *)
		    rdata)->bConfigurationValue;
	}
	di_fini(node);

	cfg = (struct libusb_config_descriptor *)dpriv->raw_cfgdescr;
	len = MIN(len, libusb_le16_to_cpu(cfg->wTotalLength));
	memcpy(buf, dpriv->raw_cfgdescr, len);
	usbi_dbg(DEVICE_CTX(dev), "path:%s len %zu", dpriv->phypath, len);

	return (len);
}

int
illumos_get_config_descriptor(struct libusb_device *dev, uint8_t idx,
    void *buf, size_t len)
{
	UNUSED(idx);
	/* XXX */
	return (illumos_get_active_config_descriptor(dev, buf, len));
}

int
illumos_get_configuration(struct libusb_device_handle *handle, uint8_t *config)
{
	illumos_dev_priv_t *dpriv = usbi_get_device_priv(handle->dev);

	*config = dpriv->cfgvalue;

	usbi_dbg(HANDLE_CTX(handle), "bConfigurationValue %u", *config);

	return (LIBUSB_SUCCESS);
}

int
illumos_set_configuration(struct libusb_device_handle *handle, int config)
{
	illumos_dev_priv_t *dpriv = usbi_get_device_priv(handle->dev);
	illumos_dev_handle_priv_t *hpriv;

	usbi_dbg(HANDLE_CTX(handle), "bConfigurationValue %d", config);
	hpriv = usbi_get_device_handle_priv(handle);

	if (dpriv->ugenpath == NULL)
		return (LIBUSB_ERROR_NOT_SUPPORTED);

	if (config < 1)
		return (LIBUSB_ERROR_NOT_SUPPORTED);

	dpriv->cfgvalue = config;
	hpriv->config_index = config - 1;

	return (LIBUSB_SUCCESS);
}

int
illumos_claim_interface(struct libusb_device_handle *handle, uint8_t iface)
{
	UNUSED(handle);

	usbi_dbg(HANDLE_CTX(handle), "iface %u", iface);

	return (LIBUSB_SUCCESS);
}

int
illumos_release_interface(struct libusb_device_handle *handle, uint8_t iface)
{
	illumos_dev_handle_priv_t *hpriv = usbi_get_device_handle_priv(handle);

	usbi_dbg(HANDLE_CTX(handle), "iface %u", iface);

	/* XXX: can we release it? */
	hpriv->altsetting[iface] = 0;

	return (LIBUSB_SUCCESS);
}

int
illumos_set_interface_altsetting(struct libusb_device_handle *handle,
    uint8_t iface, uint8_t altsetting)
{
	illumos_dev_priv_t *dpriv = usbi_get_device_priv(handle->dev);
	illumos_dev_handle_priv_t *hpriv = usbi_get_device_handle_priv(handle);

	usbi_dbg(HANDLE_CTX(handle), "iface %u, setting %u", iface, altsetting);

	if (dpriv->ugenpath == NULL)
		return (LIBUSB_ERROR_NOT_FOUND);

	/* XXX: can we switch altsetting? */
	hpriv->altsetting[iface] = altsetting;

	return (LIBUSB_SUCCESS);
}

static void
usb_dump_data(const void *data, size_t size)
{
	const uint8_t *p = data;
	size_t i;

	if (getenv("LIBUSB_DEBUG") == NULL) {
		return;
	}

	(void) fprintf(stderr, "data dump:");
	for (i = 0; i < size; i++) {
		if (i % 16 == 0) {
			(void) fprintf(stderr, "\n%08zx\t", i);
		}
		(void) fprintf(stderr, "%02x ", p[i]);
	}
	(void) fprintf(stderr, "\n");
}

static void
illumos_async_callback(union sigval arg)
{
	illumos_xfer_priv_t *tpriv = arg.sival_ptr;
	struct libusb_transfer *xfer = tpriv->transfer;
	struct usbi_transfer *ixfer = LIBUSB_TRANSFER_TO_USBI_TRANSFER(xfer);
	struct aiocb *aiocb = &tpriv->aiocb;
	illumos_dev_handle_priv_t *hpriv;
	uint8_t ep;
	libusb_device_handle *dev_handle;

	if ((dev_handle = xfer->dev_handle) == NULL) {
		/* libusb can forcibly interrupt transfer in do_close() */
		return;
	}

	if (aio_error(aiocb) != ECANCELED) {
		hpriv = usbi_get_device_handle_priv(dev_handle);
		ep = illumos_usb_ep_index(xfer->endpoint);

		/*
		 * Fetch the status for the last command on this endpoint from
		 * ugen(4D) so that we can translate and report it later.
		 */
		tpriv->ugen_status = illumos_usb_get_status(TRANSFER_CTX(xfer),
		    hpriv->eps[ep].statfd);
	} else {
		tpriv->ugen_status = USB_LC_STAT_NOERROR;
	}

	usbi_signal_transfer_completion(ixfer);
}

static int
illumos_do_async_io(struct libusb_transfer *transfer)
{
	int ret = -1;
	struct aiocb *aiocb;
	illumos_dev_handle_priv_t *hpriv;
	uint8_t ep;
	illumos_xfer_priv_t *tpriv;

	usbi_dbg(TRANSFER_CTX(transfer), " ");

	tpriv = usbi_get_transfer_priv(
	    LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer));
	hpriv = usbi_get_device_handle_priv(transfer->dev_handle);
	ep = illumos_usb_ep_index(transfer->endpoint);

	tpriv->type = ILLUMOS_XFT_AIO;
	tpriv->transfer = transfer;
	aiocb = &tpriv->aiocb;
	bzero(aiocb, sizeof(*aiocb));
	aiocb->aio_fildes = hpriv->eps[ep].datafd;
	aiocb->aio_buf = transfer->buffer;
	aiocb->aio_nbytes = transfer->length;
	aiocb->aio_lio_opcode =
	    ((transfer->endpoint & LIBUSB_ENDPOINT_DIR_MASK) ==
	    LIBUSB_ENDPOINT_IN) ? LIO_READ : LIO_WRITE;
	aiocb->aio_sigevent.sigev_notify = SIGEV_THREAD;
	aiocb->aio_sigevent.sigev_value.sival_ptr = tpriv;
	aiocb->aio_sigevent.sigev_notify_function = illumos_async_callback;

	if (aiocb->aio_lio_opcode == LIO_READ) {
		ret = aio_read(aiocb);
	} else {
		ret = aio_write(aiocb);
	}

	return (ret);
}

/* return the number of bytes read/written */
static ssize_t
illumos_usb_do_io(struct libusb_context *ctx, illumos_ep_priv_t *ep,
    illumos_xfer_priv_t *tpriv, void *data, size_t size, illumos_iodir_t dir)
{
	int error;
	ssize_t ret = -1;

	usbi_dbg(ctx,
	    "illumos_usb_do_io(): datafd=%d statfd=%d size=0x%zx dir=%s",
	    ep->datafd, ep->statfd, size,
	    dir == ILLUMOS_DIR_WRITE ? "WRITE" : "READ");

	switch (dir) {
	case ILLUMOS_DIR_READ:
		errno = 0;
		ret = read(ep->datafd, data, size);
		error = errno;
		usb_dump_data(data, size);
		break;
	case ILLUMOS_DIR_WRITE:
		usb_dump_data(data, size);
		errno = 0;
		ret = write(ep->datafd, data, size);
		error = errno;
		break;
	}

	/*
	 * Fetch the status for the last command on this endpoint from
	 * ugen(4D) so that we can translate and report it later.
	 */
	tpriv->ugen_status = illumos_usb_get_status(ctx, ep->statfd);

	usbi_dbg(ctx, "illumos_usb_do_io(): amount=%zd error=%d status=%d",
	    ret, error, tpriv->ugen_status);

	if (ret < 0) {
		usbi_dbg(ctx, "TID=%x io %s errno %d (%s)", pthread_self(),
		    dir == ILLUMOS_DIR_WRITE ? "WRITE" : "READ",
		    errno, strerror(errno));

		errno = error;
		return (-1);
	}

	return (ret);
}

static int
illumos_submit_ctrl_on_default(struct libusb_transfer *xfer)
{
	struct libusb_context *ctx = TRANSFER_CTX(xfer);
	struct usbi_transfer *ixfer = LIBUSB_TRANSFER_TO_USBI_TRANSFER(xfer);
	illumos_xfer_priv_t *tpriv = usbi_get_transfer_priv(ixfer);
	struct libusb_device_handle *hdl = xfer->dev_handle;
	illumos_dev_handle_priv_t *hpriv = usbi_get_device_handle_priv(hdl);
	uint8_t *data = xfer->buffer;
	size_t datalen = xfer->length;
	illumos_iodir_t dir =
	    (data[0] & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN ?
	    ILLUMOS_DIR_READ : ILLUMOS_DIR_WRITE;
	ssize_t ret;

	tpriv->type = ILLUMOS_XFT_CTRL;
	tpriv->transfer = xfer;
	tpriv->ctrl_len = 0;

	if (hpriv->eps[0].datafd < 0) {
		usbi_dbg(ctx, "ep0 not opened");
		return (LIBUSB_ERROR_NOT_FOUND);
	}

	if (dir == ILLUMOS_DIR_READ) {
		/*
		 * As per ugen(4D), to perform a control-IN transfer we must
		 * first write(2) the USB setup data.
		 */
		usbi_dbg(ctx, "IN request: write setup");
		if ((ret = illumos_usb_do_io(ctx, &hpriv->eps[0], tpriv,
		    data, LIBUSB_CONTROL_SETUP_SIZE, ILLUMOS_DIR_WRITE)) < 0) {
			int e = errno;
			usbi_dbg(ctx, "IN request: setup failed (%d, %s)",
			    e, strerror(e));
			return (_errno_to_libusb(e));
		} else if (ret != LIBUSB_CONTROL_SETUP_SIZE) {
			usbi_dbg(ctx, "IN request: setup short write (%d)",
			    (int)ret);
			return (LIBUSB_ERROR_IO);
		}

		/*
		 * Trim the setup data out of the buffer for the subsequent
		 * read:
		 */
		datalen -= LIBUSB_CONTROL_SETUP_SIZE;
		data += LIBUSB_CONTROL_SETUP_SIZE;
	}

	usbi_dbg(ctx, "%s request: data",
	    dir == ILLUMOS_DIR_READ ? "IN" : "OUT");
	ret = illumos_usb_do_io(ctx, &hpriv->eps[0], tpriv, data, datalen, dir);
	if (ret >= 0) {
		tpriv->ctrl_len += ret;
	}

	usbi_dbg(ctx, "Done: ctrl data bytes %zd", ret);
	usbi_signal_transfer_completion(ixfer);
	return (LIBUSB_SUCCESS);
}

int
illumos_clear_halt(struct libusb_device_handle *handle, unsigned char endpoint)
{
	int ret;

	usbi_dbg(HANDLE_CTX(handle), "endpoint=0x%02x", endpoint);

	ret = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT |
	    LIBUSB_RECIPIENT_ENDPOINT | LIBUSB_REQUEST_TYPE_STANDARD,
	    LIBUSB_REQUEST_CLEAR_FEATURE, 0, endpoint, NULL, 0, 1000);

	usbi_dbg(HANDLE_CTX(handle), "ret=%d", ret);

	return (ret);
}

void
illumos_destroy_device(struct libusb_device *dev)
{
	illumos_dev_priv_t *dpriv = usbi_get_device_priv(dev);

	usbi_dbg(DEVICE_CTX(dev), "destroy everything");
	free(dpriv->raw_cfgdescr);
	free(dpriv->ugenpath);
	free(dpriv->phypath);
}

int
illumos_submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer;
	struct libusb_device_handle *hdl;
	int err = 0;

	transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	hdl = transfer->dev_handle;

	err = illumos_check_device_and_status_open(hdl,
	    transfer->endpoint, transfer->type);
	if (err != 0) {
		return (_errno_to_libusb(err));
	}

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		/* sync transfer */
		usbi_dbg(ITRANSFER_CTX(itransfer),
		    "CTRL transfer: %d", transfer->length);
		err = illumos_submit_ctrl_on_default(transfer);
		break;

	case LIBUSB_TRANSFER_TYPE_BULK:
		usbi_dbg(ITRANSFER_CTX(itransfer),
		    "BULK transfer: %d", transfer->length);
		err = illumos_do_async_io(transfer);
		break;

	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		usbi_dbg(ITRANSFER_CTX(itransfer),
		    "INTR transfer: %d", transfer->length);
		err = illumos_do_async_io(transfer);
		break;

	/* Isochronous/Stream is not supported */
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		usbi_dbg(ITRANSFER_CTX(itransfer),
		    "ISOC transfer: %d", transfer->length);
		err = LIBUSB_ERROR_NOT_SUPPORTED;
		break;

	case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
		usbi_dbg(ITRANSFER_CTX(itransfer),
		    "BULK STREAM transfer: %d", transfer->length);
		err = LIBUSB_ERROR_NOT_SUPPORTED;
		break;
	}

	return (err);
}

int
illumos_cancel_transfer(struct usbi_transfer *itransfer)
{
	illumos_xfer_priv_t *tpriv;
	illumos_dev_handle_priv_t *hpriv;
	struct libusb_transfer *transfer;
	struct aiocb *aiocb;
	uint8_t ep;
	int ret;

	tpriv = usbi_get_transfer_priv(itransfer);
	aiocb = &tpriv->aiocb;
	transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	hpriv = usbi_get_device_handle_priv(transfer->dev_handle);
	ep = illumos_usb_ep_index(transfer->endpoint);

	ret = aio_cancel(hpriv->eps[ep].datafd, aiocb);

	usbi_dbg(ITRANSFER_CTX(itransfer), "aio->fd=%d fd=%d ret = %d, %s",
	    aiocb->aio_fildes, hpriv->eps[ep].datafd, ret,
	    (ret == AIO_CANCELED) ? "AIO canceled" : strerror(errno));

	if (ret != AIO_CANCELED) {
		ret = _errno_to_libusb(errno);
	} else {
		ret = LIBUSB_SUCCESS;
	}

	return (ret);
}

static int
illumos_libusb_status(illumos_xfer_priv_t *tpriv)
{
	/*
	 * Convert the ugen(4D)-level status to a libusb-level status:
	 */
	switch (tpriv->ugen_status) {
	case USB_LC_STAT_TIMEOUT:
		return (LIBUSB_TRANSFER_TIMED_OUT);
	case USB_LC_STAT_STALL:
		return (LIBUSB_TRANSFER_STALL);
	case USB_LC_STAT_DISCONNECTED:
		return (LIBUSB_TRANSFER_NO_DEVICE);
	case USB_LC_STAT_INTERRUPTED:
		return (LIBUSB_TRANSFER_CANCELLED);
	case USB_LC_STAT_BUFFER_OVERRUN:
		/*
		 * XXX Is this right? (*_DATA_OVERRUN?)
		 */
		return (LIBUSB_TRANSFER_OVERFLOW);
	default:
		/*
		 * Not every ugen(4D) status maps to a specific libusb-level
		 * failure case.  Nonetheless, we must report all failures as
		 * failures:
		 */
		return (LIBUSB_TRANSFER_ERROR);
	}
}

int
illumos_handle_transfer_completion(struct usbi_transfer *ixfer)
{
	illumos_xfer_priv_t *tpriv = usbi_get_transfer_priv(ixfer);
	struct libusb_transfer *xfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(ixfer);
	struct aiocb *aiocb = &tpriv->aiocb;
	int ret;
	enum libusb_transfer_status status;

	if (tpriv->type == ILLUMOS_XFT_CTRL) {
		ixfer->transferred = tpriv->ctrl_len;
		if (tpriv->ugen_status == USB_LC_STAT_NOERROR) {
			status = LIBUSB_TRANSFER_COMPLETED;
		} else {
			status = illumos_libusb_status(tpriv);
		}

	} else if ((ret = aio_error(aiocb)) == 0) {
		/*
		 * The command completed.  Update the transferred length:
		 */
		xfer->actual_length = ixfer->transferred = aio_return(aiocb);

		usbi_dbg(TRANSFER_CTX(xfer), "ret=%d, len=%d, actual_len=%d",
		    ret, xfer->length, xfer->actual_length);
		usb_dump_data(xfer->buffer, xfer->actual_length);

		status = LIBUSB_TRANSFER_COMPLETED;

	} else if (ret == ECANCELED) {
		/*
		 * We used aio_cancel() to cancel this; report cancellation to
		 * libusb so that timeouts can be handled correctly.
		 */
		usbi_dbg(TRANSFER_CTX(xfer),
		    "aio cancelled, len=%d, actual_len=%d",
		    xfer->length, xfer->actual_length);

		status = LIBUSB_TRANSFER_CANCELLED;

	} else {
		status = illumos_libusb_status(tpriv);
	}

	if (status == LIBUSB_TRANSFER_CANCELLED) {
		return (usbi_handle_transfer_cancellation(ixfer));
	} else {
		return (usbi_handle_transfer_completion(ixfer, status));
	}
}

int
_errno_to_libusb(int err)
{
	usbi_dbg(NULL, "error: %s (%d)", strerror(err), err);

	switch (err) {
	case EIO:
		return (LIBUSB_ERROR_IO);
	case EACCES:
		return (LIBUSB_ERROR_ACCESS);
	case ENOENT:
		return (LIBUSB_ERROR_NO_DEVICE);
	case ENOMEM:
		return (LIBUSB_ERROR_NO_MEM);
	case ETIMEDOUT:
		return (LIBUSB_ERROR_TIMEOUT);
	}

	return (LIBUSB_ERROR_OTHER);
}

/*
 * illumos_usb_get_status:
 *	gets status of endpoint
 *
 * Returns: ugen's last cmd status
 */
static int
illumos_usb_get_status(struct libusb_context *ctx, int fd)
{
	int status;
	ssize_t ret;

	usbi_dbg(ctx, "illumos_usb_get_status(): fd=%d", fd);

	errno = 0;
	ret = read(fd, &status, sizeof(status));
	if (ret == sizeof (status)) {
		switch (status) {
		case USB_LC_STAT_NOERROR:
			usbi_dbg(ctx, "No Error");
			break;
		case USB_LC_STAT_CRC:
			usbi_dbg(ctx, "CRC Timeout Detected\n");
			break;
		case USB_LC_STAT_BITSTUFFING:
			usbi_dbg(ctx, "Bit Stuffing Violation\n");
			break;
		case USB_LC_STAT_DATA_TOGGLE_MM:
			usbi_dbg(ctx, "Data Toggle Mismatch\n");
			break;
		case USB_LC_STAT_STALL:
			usbi_dbg(ctx, "End Point Stalled\n");
			break;
		case USB_LC_STAT_DEV_NOT_RESP:
			usbi_dbg(ctx, "Device is Not Responding\n");
			break;
		case USB_LC_STAT_PID_CHECKFAILURE:
			usbi_dbg(ctx, "PID Check Failure\n");
			break;
		case USB_LC_STAT_UNEXP_PID:
			usbi_dbg(ctx, "Unexpected PID\n");
			break;
		case USB_LC_STAT_DATA_OVERRUN:
			usbi_dbg(ctx, "Data Exceeded Size\n");
			break;
		case USB_LC_STAT_DATA_UNDERRUN:
			usbi_dbg(ctx, "Less data received\n");
			break;
		case USB_LC_STAT_BUFFER_OVERRUN:
			usbi_dbg(ctx, "Buffer Size Exceeded\n");
			break;
		case USB_LC_STAT_BUFFER_UNDERRUN:
			usbi_dbg(ctx, "Buffer Underrun\n");
			break;
		case USB_LC_STAT_TIMEOUT:
			usbi_dbg(ctx, "Command Timed Out\n");
			break;
		case USB_LC_STAT_NOT_ACCESSED:
			usbi_dbg(ctx, "Not Accessed by h/w\n");
			break;
		case USB_LC_STAT_UNSPECIFIED_ERR:
			usbi_dbg(ctx, "Unspecified Error\n");
			break;
		case USB_LC_STAT_NO_BANDWIDTH:
			usbi_dbg(ctx, "No Bandwidth\n");
			break;
		case USB_LC_STAT_HW_ERR:
			usbi_dbg(ctx, "Host Controller h/w Error\n");
			break;
		case USB_LC_STAT_SUSPENDED:
			usbi_dbg(ctx, "Device was Suspended\n");
			break;
		case USB_LC_STAT_DISCONNECTED:
			usbi_dbg(ctx, "Device was Disconnected\n");
			break;
		case USB_LC_STAT_INTR_BUF_FULL:
			usbi_dbg(ctx, "Interrupt buffer was full\n");
			break;
		case USB_LC_STAT_INVALID_REQ:
			usbi_dbg(ctx, "Request was Invalid\n");
			break;
		case USB_LC_STAT_INTERRUPTED:
			usbi_dbg(ctx, "Request was Interrupted\n");
			break;
		case USB_LC_STAT_NO_RESOURCES:
			usbi_dbg(ctx, "No resources available for "
			    "request\n");
			break;
		case USB_LC_STAT_INTR_POLLING_FAILED:
			usbi_dbg(ctx, "Failed to Restart Poll");
			break;
		default:
			usbi_dbg(ctx, "Error Not Determined %d\n",
			    status);
			status = USB_LC_STAT_UNSPECIFIED_ERR;
			break;
		}
	} else {
		usbi_dbg(ctx, "read stat error: (ret %ld, error %d) %s",
		    (long)ret, errno, strerror(errno));
		status = USB_LC_STAT_UNSPECIFIED_ERR;
	}

	return (status);
}

const struct usbi_os_backend usbi_backend = {
	.name = "illumos",
	.get_device_list = illumos_get_device_list,
	.open = illumos_open,
	.close = illumos_close,

	.get_active_config_descriptor = illumos_get_active_config_descriptor,
	.get_config_descriptor = illumos_get_config_descriptor,

	.get_configuration = illumos_get_configuration,
	.set_configuration = illumos_set_configuration,

	.claim_interface = illumos_claim_interface,
	.release_interface = illumos_release_interface,

	.set_interface_altsetting = illumos_set_interface_altsetting,
	.clear_halt = illumos_clear_halt,
	.destroy_device = illumos_destroy_device,

	.submit_transfer = illumos_submit_transfer,
	.cancel_transfer = illumos_cancel_transfer,

	.handle_transfer_completion = illumos_handle_transfer_completion,

	.device_priv_size = sizeof(illumos_dev_priv_t),
	.device_handle_priv_size = sizeof(illumos_dev_handle_priv_t),

	.kernel_driver_active = illumos_kernel_driver_active,
	.transfer_priv_size = sizeof(illumos_xfer_priv_t),
};
