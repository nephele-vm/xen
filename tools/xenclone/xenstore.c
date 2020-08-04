/******************************************************************************
 * xenstore functionality
 *
 * Copyright (c) 2020 Costin Lupu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <xen-tools/libs.h>
#define XC_WANT_COMPAT_MAP_FOREIGN_API 1
#include <xenctrl.h>
#include "log.h"
#include "xencloned.h"
#include "clone.h"
#include "xs.h"
#include "xenstore.h"


static int xs_paths_init(struct xs *xs, domid_t domid, bool is_parent)
{
	char *path;
	bool read_perms = xs_deep_copy;
	int rc;

	/* e.g. /local/domain/17 */
	path = xs_get_domain_path(xs_handle, domid);
	if (!path) {
		rc = errno;
		goto out;
	}
	rc = xs_path_init(&xs->path_local, path, read_perms && is_parent);
	if (rc) {
		free(path);
		goto out;
	}

	if (xs_deep_copy) {
		/* /local/domain/18/data */
		rc = xs_path_initf(&xs->path_data, is_parent,
				"%s/data", xs->path_local.value);
		if (rc)
			goto out;

		/* /local/domain/18/name */
		rc = xs_path_initf(&xs->path_name, is_parent,
				"%s/name", xs->path_local.value);
		if (rc)
			goto out;

		/* /local/domain/18/domid */
		rc = xs_path_initf(&xs->path_domid, is_parent,
				"%s/domid", xs->path_local.value);
		if (rc)
			goto out;

		/* /local/domain/18/control/shutdown */
		rc = xs_path_initf(&xs->path_shutdown, is_parent,
				"%s/control/shutdown", xs->path_local.value);
		if (rc)
			goto out;

		/* /local/domain/18/store */
		rc = xs_path_initf(&xs->path_store, is_parent,
				"%s/store", xs->path_local.value);
		if (rc)
			goto out;
	}

	/* e.g. /libxl/17 */
	rc = xs_path_initf(&xs->path_libxl, read_perms && is_parent,
			"/libxl/%d", domid);
	if (rc)
		goto out;

out:
	return rc;
}

static void xs_paths_fini(struct xs *xs)
{
	xs_path_fini(&xs->path_local);
	xs_path_fini(&xs->path_libxl);
	xs_path_fini(&xs->path_data);
	xs_path_fini(&xs->path_shutdown);
	xs_path_fini(&xs->path_name);
	xs_path_fini(&xs->path_domid);
	xs_path_fini(&xs->path_store);
}

int xs_init(struct xs *xs, domid_t domid, unsigned long mfn, bool is_parent)
{
	int rc;

	rc = xs_paths_init(xs, domid, is_parent);
	if (rc) {
		PERROR("Error initializing Xenstore paths");
		goto out;
	}

	xs->mfn = mfn;

	if (is_parent) {
		rc = xs_scanf_kv(XBT_NULL, xs->path_local.value, "store/port", "%u", &xs->port);
		if (rc) {
			rc = errno;
			goto out;
		}

		/* e.g. /local/domain/17/name = "minios" */
		rc = xs_read_kv(XBT_NULL, xs->path_local.value, "name", &xs->name);
		if (!xs->name) {
			rc = errno;
			goto out;
		}

		/* e.g. /libxl/17/type = "pv" */
		rc = xs_scanf_kv(XBT_NULL, xs->path_libxl.value,
				"type", "%s", &xs->libxl_type);
		if (rc) {
			PERROR("Could not read from key 'type'");
			rc = errno;
			goto out;
		}

		/* e.g. /libxl/17/dm-version = "qemu_xen" */
		rc = xs_scanf_kv(XBT_NULL, xs->path_libxl.value,
				"dm-version", "%s", &xs->libxl_dm_version);
		if (rc) {
			PERROR("Could not read from key 'dm-version'");
			rc = errno;
			goto out;
		}

	} else {
		xs->name = NULL;
		xs->libxl_type = NULL;
		xs->libxl_dm_version = NULL;
	}

out:
	if (rc)
		xs_paths_fini(xs);
	return rc;
}

int xs_fini(struct xs *xs)
{
	int rc = 0;

	if (!xs) {
		rc = -EINVAL;
		goto out;
	}

	if (xs->name) {
		free(xs->name);
		xs->name = NULL;
	}
	if (xs->libxl_type) {
		free(xs->libxl_type);
		xs->libxl_type = NULL;
	}
	if (xs->libxl_dm_version) {
		free(xs->libxl_dm_version);
		xs->libxl_dm_version = NULL;
	}
	xs_paths_fini(xs);
out:
	return rc;
}

static
int clone_deep_local(struct xenclone_domain *prnt, struct xenclone_domain *chld,
		xs_transaction_t t)
{
	int rc;

	/* /local/domain/18 */
	rc = xs_acl_clone(
			&prnt->xs.path_local.acl, prnt->domid,
			&chld->xs.path_local.acl, chld->domid);
	if (rc)
		goto out;
	rc = xs_path_make(&chld->xs.path_local, t);
	if (rc)
		goto out;

	/* /local/domain/18/data */
	rc = xs_acl_clone(
			&prnt->xs.path_data.acl, prnt->domid,
			&chld->xs.path_data.acl, chld->domid);
	if (rc)
		goto out;
	rc = xs_path_make(&chld->xs.path_data, t);
	if (rc)
		goto out;

	/* /local/domain/18/control/shutdown */
	rc = xs_acl_clone(
			&prnt->xs.path_shutdown.acl, prnt->domid,
			&chld->xs.path_shutdown.acl, chld->domid);
	if (rc)
		goto out;
	rc = xs_path_make(&chld->xs.path_shutdown, t);
	if (rc)
		goto out;

	/* /local/domain/18/name = "minios-child-18" */
	rc = asprintf(&chld->xs.name, "%s-child-%lu", prnt->xs.name, chld->domid);
	if (!chld->xs.name) {
		rc = errno;
		goto out;
	}

	rc = xs_acl_clone(
			&prnt->xs.path_name.acl, prnt->domid,
			&chld->xs.path_name.acl, chld->domid);
	if (rc)
		goto out;
	rc = xs_write_kv(t, &chld->xs.path_name.acl,
			chld->xs.path_name.value, NULL, chld->xs.name);
	if (rc) {
		PERROR("Could not write to key 'name'");
		rc = errno;
		goto out;
	}

	/* /local/domain/18/domid = "18" */
	rc = xs_acl_clone(
			&prnt->xs.path_domid.acl, prnt->domid,
			&chld->xs.path_domid.acl, chld->domid);
	if (rc)
		goto out;
	rc = xs_printf_kv(t, &chld->xs.path_domid.acl,
			chld->xs.path_domid.value, NULL, "%u", chld->domid);
	if (rc) {
		PERROR("Could not write to key 'domid'");
		rc = errno;
		goto out;
	}

	/*** Xenstore ***/
	rc = xs_acl_clone(
			&prnt->xs.path_store.acl, prnt->domid,
			&chld->xs.path_store.acl, chld->domid);
	if (rc)
		goto out;
	rc = xs_path_make(&chld->xs.path_store, t);
	if (rc)
		goto out;

	/* /local/domain/18/store/ring-ref = "2345" */
	rc = xs_printf_kv(t, &chld->xs.path_store.acl,
			chld->xs.path_store.value, "ring-ref",
			"%lu", chld->xs.mfn);
	if (rc) {
		PERROR("Could not write to key 'store/ring-ref'");
		rc = errno;
		goto out;
	}
	/* /local/domain/18/store/port = "1" */
	rc = xs_printf_kv(t, &chld->xs.path_store.acl,
			chld->xs.path_store.value, "port",
			"%u", prnt->xs.port);
	if (rc) {
		PERROR("Could not write to key 'store/port'");
		rc = errno;
		goto out;
	}

out:
	return rc;
}

static
int clone_deep_libxl(struct xenclone_domain *prnt, struct xenclone_domain *chld,
		xs_transaction_t t)
{
	int rc;

	/* e.g. /libxl/17 */
	rc = xs_acl_clone(
			&prnt->xs.path_libxl.acl, prnt->domid,
			&chld->xs.path_libxl.acl, chld->domid);
	if (rc)
		goto out;

	rc = xs_path_make(&chld->xs.path_libxl, t);
	if (rc)
		goto out;

	/* e.g. /libxl/17/device */
	rc = xs_write_kv(t, &chld->xs.path_libxl.acl,
			chld->xs.path_libxl.value, "device", "");
	if (rc) {
		PERROR("Could not make directory: %s/device", chld->xs.path_libxl.value);
		rc = errno;
		goto out;
	}

	/* e.g. /libxl/17/type */
	rc = xs_printf_kv(t, &chld->xs.path_libxl.acl,
			chld->xs.path_libxl.value, "type",
			"%s", prnt->xs.libxl_type);
	if (rc) {
		PERROR("Could not write to key 'type'");
		rc = errno;
		goto out;
	}

	/* e.g. /libxl/17/dm-version */
	rc = xs_printf_kv(t, &chld->xs.path_libxl.acl,
			chld->xs.path_libxl.value, "dm-version",
			"%s", prnt->xs.libxl_dm_version);
	if (rc) {
		PERROR("Could not write to key 'dm-version'");
		rc = errno;
		goto out;
	}

out:
	return rc;
}

static
int store_clone(struct xenclone_domain *prnt, struct xenclone_domain *chld)
{
	xs_transaction_t t;
	int rc;

trans_start:
	t = xs_transaction_start(xs_handle);

	if (xs_deep_copy) {
		rc = clone_deep_local(prnt, chld, t);
		if (rc) {
			rc = errno;
			PERROR("Error cloning xenstore data under /local");
			goto trans_end;
		}

		rc = clone_deep_libxl(prnt, chld, t);
		if (rc) {
			rc = errno;
			PERROR("Error cloning xenstore data under /libxl");
			goto trans_end;
		}

	} else {
		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_basic,
				prnt->xs.path_local.value, chld->xs.path_local.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_basic,
				prnt->xs.path_libxl.value, chld->xs.path_libxl.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = 0;
	}

trans_end:
	if (rc)
		xs_transaction_end(xs_handle, t, true);

	else {
		if (!xs_transaction_end(xs_handle, t, false)) {
			if (errno == EAGAIN)
				goto trans_start;
			else
				rc = errno;
		}
	}

	return rc;
}

#if XENCLONE_XS_WIRE_DEBUG
/*******************************************************************************
 * WIRE
 ******************************************************************************/

static int do_read(void *data, unsigned int len)
{
	printf("%s\n", (char *) data);
	return 0;
}

static int do_write(void *data, unsigned int len)
{
	char *str = (char *) data;

	printf("%s=%s\n", str, str + strlen(str) + 1);
	return 0;
}

static struct {
	const char *str;
	int (*func)(void *data, unsigned int len);
} const xs_type_str[XS_TYPE_COUNT] = {
	[XS_CONTROL]		   = { "CONTROL", NULL },
	[XS_DIRECTORY]		   = { "DIRECTORY", NULL },
	[XS_READ]			   = { "READ", do_read },
	[XS_GET_PERMS]		   = { "GET_PERMS", NULL },
	[XS_WATCH]			   = { "WATCH", NULL },
	[XS_UNWATCH]		   = { "UNWATCH", NULL },
	[XS_TRANSACTION_START] = { "TRANSACTION_START", NULL },
	[XS_TRANSACTION_END]   = { "TRANSACTION_END", NULL },
	[XS_INTRODUCE]		   = { "INTRODUCE", NULL },
	[XS_RELEASE]		   = { "RELEASE", NULL },
	[XS_GET_DOMAIN_PATH]   = { "GET_DOMAIN_PATH", NULL },
	[XS_WRITE]			   = { "WRITE", do_write },
	[XS_MKDIR]			   = { "MKDIR", NULL },
	[XS_RM]				   = { "RM", NULL },
	[XS_SET_PERMS]		   = { "SET_PERMS", NULL }, /* TODO maybe rewriting */
	[XS_WATCH_EVENT]	   = { "WATCH_EVENT", NULL },
	[XS_ERROR]			   = { "ERROR", NULL },
	[XS_IS_DOMAIN_INTRODUCED] = { "IS_DOMAIN_INTRODUCED", NULL },
	[XS_RESUME]			   = { "RESUME", NULL },
	[XS_SET_TARGET]		   = { "SET_TARGET", NULL },
	[XS_RESET_WATCHES]	   = { "RESET_WATCHES", NULL },
	[XS_DIRECTORY_PART]	   = { "DIRECTORY_PART", NULL },
	[XS_PAUSE]			   = { "PAUSE", NULL },
};

static void memcpy_from_ring(void *dest, const void *ring, int off, int len)
{
	int c1, c2;

	c1 = MIN(len, XENSTORE_RING_SIZE - off);
	memcpy(dest, ring + off, c1);

	c2 = len - c1;
	if (c2)
		memcpy(dest + c1, ring, c2);
}

static int print_requests(struct xenstore_domain_interface *xenstore_buf)
{
	struct xsd_sockmsg msg;
	char *data;
	unsigned long cons;
	int rc = 0;

	cons = xenstore_buf->req_cons;

	while (cons < xenstore_buf->req_prod) {
		/* TODO assert */
		if (xenstore_buf->req_prod - xenstore_buf->req_cons < sizeof(msg))
			break;

		/* TODO should not be needed rmb(); */

		/* copy message header */
		memcpy_from_ring(&msg,
				xenstore_buf->req,
				MASK_XENSTORE_IDX(cons),
				sizeof(msg));

		assert(xenstore_buf->req_prod - cons >= sizeof(msg) + msg.len);

		data = malloc(msg.len);
		if (!data) {
			rc = -ENOMEM;
			goto out;
		}

		memcpy_from_ring(data,
				xenstore_buf->req,
				MASK_XENSTORE_IDX(cons + sizeof(msg)),
				msg.len);

		printf("[cons=%lu] %s id=%u tx_id=%u len=%u\n",
			cons, xs_type_str[msg.type].str, msg.req_id, msg.tx_id, msg.len);
		if (xs_type_str[msg.type].func)
			xs_type_str[msg.type].func(data, msg.len);

		free(data);

		cons += sizeof(msg) + msg.len;
	}

	assert(cons == xenstore_buf->req_prod);

out:
	return rc;
}

static void print_responses(struct xenstore_domain_interface *xenstore_buf)
{
	struct xsd_sockmsg *m;
	unsigned long cons;

	cons = xenstore_buf->rsp_cons;

	while (cons < xenstore_buf->rsp_prod) {
		m = (struct xsd_sockmsg *) xenstore_buf->rsp + MASK_XENSTORE_IDX(cons);
		printf("[cons=%lu] m=%p %s id=%d tx_id=%d len=%d\n",
			cons, m, xs_type_str[m->type].str, m->req_id, m->tx_id, m->len);

		cons += sizeof(*m) + m->len;
	}
}
#endif

static int xenstore_ring_clone(struct xenclone_domain *prnt, struct xenclone_domain *chld)
{
	struct xenstore_domain_interface *prnt_xs_intf = NULL, *chld_xs_intf = NULL;

	prnt_xs_intf = xc_map_foreign_range(xc_handle, prnt->domid,
			XC_PAGE_SIZE, PROT_READ, prnt->xs.mfn);
	if (!prnt_xs_intf) {
		PERROR("Failed to map parent xenstore page");
		goto out;
	}

	chld_xs_intf = xc_map_foreign_range(xc_handle, chld->domid,
			XC_PAGE_SIZE, PROT_WRITE, chld->xs.mfn);
	if (!chld_xs_intf) {
		PERROR("Failed to map child xenstore page");
		goto out;
	}

#if XENCLONE_XS_WIRE_DEBUG
	DEBUG("req_prod=%d req_cons=%d",
		prnt_xs_intf->req_prod, prnt_xs_intf->req_cons);
	DEBUG("rsp_prod=%d rsp_cons=%d",
		prnt_xs_intf->rsp_prod, prnt_xs_intf->rsp_cons);
	print_requests(prnt_xs_intf);
	print_responses(prnt_xs_intf);
#endif

	/* TODO revisit and copy inflight requests */
	memcpy(chld_xs_intf, prnt_xs_intf, sizeof(*chld_xs_intf));

out:
	if (chld_xs_intf)
		munmap(chld_xs_intf, XC_PAGE_SIZE);
	if (prnt_xs_intf)
		munmap(prnt_xs_intf, XC_PAGE_SIZE);

	return 0;
}

int xenstore_clone(struct xenclone *clone)
{
	struct xenclone_domain *parent = clone->parent;
	struct xenclone_domain *child = &clone->domain;
	int rc;

	rc = store_clone(parent, child);
	if (rc) {
		PERROR("Error calling store_clone() rc=%d", rc);
		goto out;
	}

	rc = xenstore_ring_clone(parent, child);
	if (rc) {
		PERROR("Error calling xenstore_ring_clone() rc=%d", rc);
		goto out;
	}

	rc = xs_introduce_clone(xs_handle,
			child->domid, child->xs.mfn, child->xs.port,
			parent->domid);
	if (rc == false) {
		PERROR("Error calling xs_introduce_clone() rc=%d", rc);
		goto out;
	} else
		rc = 0;

out:
	return rc;
}

//TODO remove xenstore info
