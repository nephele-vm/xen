/******************************************************************************
 * console functionality
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
#include <sys/mman.h>
#define XC_WANT_COMPAT_MAP_FOREIGN_API 1
#include <xenctrl.h>
#include <xen/io/console.h>
#include <xen-tools/libs.h>
#include "log.h"
#include "xencloned.h"
#include "clone.h"
#include "xs.h"
#include "console.h"


static void xs_consfront_fini(struct xs_consfront *front)
{
	xs_path_fini(&front->path);
	xs_path_fini(&front->backend_path);
	if (front->backend_dom_path) {
		free(front->backend_dom_path);
		front->backend_dom_path = NULL;
	}
	if (front->type) {
		free(front->type);
		front->type = NULL;
	}
	if (front->output) {
		free(front->output);
		front->output = NULL;
	}
}

static int xs_consfront_init_parent(struct xs_consfront *front)
{
	const char *fe_path = front->path.value;
	char *be_path;
	bool read_perms = xs_deep_copy;
	int rc;

	XS_FE_GET("backend",           "%s", &be_path);
	XS_FE_GET("backend-id",        "%u", &front->backend_id);

	rc = xs_path_init(&front->backend_path, be_path, read_perms);
	if (rc) {
		free(be_path);
		goto out;
	}

	front->backend_dom_path = xs_get_domain_path(xs_handle, front->backend_id);
	if (!front->backend_dom_path) {
		rc = -errno;
		goto out;
	}

out:
	if (rc)
		xs_consfront_fini(front);

	return rc;
}

static int xs_consfront_init_child(
		struct xs_consfront *pconsfront,
		struct xs_consfront *cconsfront,
		struct xenclone_domain *chld)
{
	int rc;

	/* convert frontend path */
	rc = xs_path_initf(&cconsfront->path, false,
			"%s/console", chld->xs.path_local.value);
	if (rc)
		goto out;

	/* convert backend path */
	rc = xs_path_initf(&cconsfront->backend_path, false,
			"%s/backend/console/%lu/0",
			pconsfront->backend_dom_path, chld->domid);
	if (rc)
		goto out;

	cconsfront->backend_id = pconsfront->backend_id;
	cconsfront->backend_dom_path = strdup(pconsfront->backend_dom_path);
	if (!cconsfront->backend_dom_path) {
		rc = -ENOMEM;
		goto out;
	}

out:
	if (rc)
		xs_consfront_fini(cconsfront);

	return rc;
}

static int xs_consfront_read_fields(struct xs_consfront *front)
{
	const char *fe_path = front->path.value;
	int rc;

	XS_FE_GET("limit",             "%u", &front->limit);
	XS_FE_GET("type",              "%s", &front->type);
	XS_FE_GET("output",            "%s", &front->output);
	XS_FE_GET("port",              "%u", &front->port);
	XS_FE_GET("ring-ref",          "%u", &front->ring_ref);
out:
	return rc;
}

static int xs_consfront_write_deep(struct xs_consfront *front,
		xs_transaction_t t)
{
	int rc;

	XS_FE_SET("backend",           "%s", front->backend_path.value);
	XS_FE_SET("backend-id",        "%u", front->backend_id);
	XS_FE_SET("limit",             "%u", front->limit);
	XS_FE_SET("type",              "%s", front->type);
	XS_FE_SET("output",            "%s", front->output);
	XS_FE_SET("port",              "%u", front->port);
	XS_FE_SET("ring-ref",          "%u", front->ring_ref);
out:
	return rc;
}

static int xs_consfront_clone_deep(
		struct xs_consfront *pconsfront,
		struct xs_consfront *cconsfront,
		struct xenclone_domain *chld)
{
	int rc;

	rc = xs_acl_clone(&pconsfront->path.acl, chld->parent->domid,
			&cconsfront->path.acl, chld->domid);
	if (rc)
		goto out;

	rc = xs_acl_clone(&pconsfront->backend_path.acl, chld->parent->domid,
			&cconsfront->backend_path.acl, chld->domid);
	if (rc)
		goto out;

	cconsfront->limit = pconsfront->limit;
	cconsfront->type = strdup(pconsfront->type);
	if (!cconsfront->type) {
		rc = -ENOMEM;
		goto out;
	}
	cconsfront->output = strdup(pconsfront->output);
	if (!cconsfront->output) {
		rc = -ENOMEM;
		goto out;
	}
	cconsfront->port = pconsfront->port;
	cconsfront->ring_ref = chld->console.mfn;

out:
	if (rc)
		xs_consfront_fini(cconsfront);
	return rc;
}

static void xs_consback_fini(struct xs_consback *back)
{
	if (back->protocol)
		free(back->protocol);
}

static int xs_consback_read_deep(struct xs_consback *back)
{
	const char *be_path = back->path->value;
	int rc;

	XS_BE_GET("frontend-id",       "%d", &back->frontend_id);
	XS_BE_GET("online",            "%d", &back->online);
	XS_BE_GET("state",             "%d", &back->state);
	XS_BE_GET("protocol",          "%s", &back->protocol);
out:
	return rc;
}

static
int xs_consback_write_deep(struct xs_consback *back,
		xs_transaction_t t, struct xenclone_domain *chld)
{
	int rc;

	/* /local/domain/18/console */
	rc = xs_path_make(back->path, t);
	if (rc)
		goto out;

	XS_BE_SET("frontend",          "%s", back->frontend_path->value);
	XS_BE_SET("frontend-id",       "%d", back->frontend_id);
	XS_BE_SET("online",            "%d", back->online);
	XS_BE_SET("state",             "%d", back->state);
	XS_BE_SET("protocol",          "%s", back->protocol);
	/* TODO XS_BE_SET("cloned", "%s", "true"); */

out:
	return rc;
}

static int xs_consback_clone_deep(
		struct xs_consback *prnt_consback,
		struct xs_consback *chld_consback,
		struct xs_consfront *chld_consfront,
		struct xenclone_domain *chld)
{
	int rc = 0;

	chld_consback->path = &chld_consfront->backend_path;
	chld_consback->frontend_path = &chld_consfront->path;
	chld_consback->frontend_id = chld->domid;
	chld_consback->online = prnt_consback->online;
	chld_consback->state = prnt_consback->state;
	chld_consback->protocol = strdup(prnt_consback->protocol);
	if (!chld_consback->protocol) {
		rc = -ENOMEM;
		goto out;
	}
out:
	if (rc)
		xs_consback_fini(chld_consback);
	return rc;
}

int console_init_parent(struct xenclone_domain *domain)
{
	struct xs_console_dev *dev = &domain->console;
	struct xs_consfront *front = &dev->front;
	struct xs_consback *back = &dev->back;
	bool read_perms = xs_deep_copy;
	int rc;

	if (!domain) {
		rc = -EINVAL;
		goto out;
	}

	dev->domain = domain;

	rc = xs_path_initf(&front->path, read_perms,
			"%s/console", domain->xs.path_local.value);
	if (rc)
		goto out;

	rc = xs_consfront_init_parent(front);
	if (rc) {
		PERROR("Failed to init consfront Xenstore info");
		goto out;
	}

	if (xs_deep_copy) {
		rc = xs_consfront_read_fields(front);
		if (rc) {
			PERROR("Failed to read consfront Xenstore info");
			goto out;
		}

		back->path = &front->backend_path;
		back->frontend_path = &front->path;

		rc = xs_consback_read_deep(back);
		if (rc) {
			PERROR("Failed to read consback Xenstore info");
			goto out;
		}
	}

out:
	if (rc)
		xs_consfront_fini(front);

	return rc;
}

int console_fini(struct xenclone_domain *domain)
{
	struct xs_console_dev *dev = &domain->console;
	int rc;

	if (!domain) {
		rc = -EINVAL;
		goto out;
	}

	xs_consfront_fini(&dev->front);
	xs_consback_fini(&dev->back);
	rc = 0;
out:
	return rc;
}

static
int xs_libxl_console_write_deep(struct xs_console_dev *dev,
		struct xs_path *path_libxl, int dev_idx, xs_transaction_t t)
{
	char *libxl_path = NULL;
	int rc;

	rc = asprintf(&libxl_path, "%s/device/console/%d",
			path_libxl->value, dev_idx);
	if (!libxl_path) {
		rc = errno;
		goto out;
	}

	XS_LIBXL_SET("frontend",      "%s", dev->front.path.value);
	XS_LIBXL_SET("backend",       "%s", dev->front.backend_path.value);
	XS_LIBXL_SET("frontend-id",   "%d", dev->back.frontend_id);
	XS_LIBXL_SET("online",        "%d", dev->back.online);
	XS_LIBXL_SET("state",         "%d", dev->back.state);
	XS_LIBXL_SET("protocol",      "%s", dev->back.protocol);
out:
	if (libxl_path)
		free(libxl_path);
	return rc;
}

static
int xs_libxl_console_clone(
		unsigned long pdomid, struct xs_path *ppath_libxl,
		unsigned long cdomid, struct xs_path *cpath_libxl,
		int dev_idx, xs_transaction_t t)
{
	char *ppath = NULL, *cpath = NULL;
	int rc;

	rc = asprintf(&ppath, "%s/device/console/%d",
			ppath_libxl->value, dev_idx);
	if (!ppath) {
		rc = errno;
		goto out;
	}

	rc = asprintf(&cpath, "%s/device/console/%d",
			cpath_libxl->value, dev_idx);
	if (!cpath) {
		rc = errno;
		goto out;
	}

	rc = xs_clone(xs_handle, XBT_NULL,
			pdomid, cdomid, xs_clone_op_dev_console,
			ppath, cpath);
	if (rc == false) {
		rc = errno;
		PERROR("Error calling xs_clone() rc=%d", rc);
		goto out;
	}

	rc = 0;
out:
	if (ppath)
		free(ppath);
	if (cpath)
		free(cpath);
	return rc;
}

static int console_ring_clone(
		unsigned long prnt_mfn, domid_t prnt_domid,
		unsigned long chld_mfn, domid_t chld_domid)
{
	struct xencons_interface *prnt_cons_intf = NULL, *chld_cons_intf = NULL;

	prnt_cons_intf = xc_map_foreign_range(xc_handle, prnt_domid,
			XC_PAGE_SIZE, PROT_READ, prnt_mfn);
	if (!prnt_cons_intf) {
		PERROR("Failed to map parent xenstore page");
		goto out;
	}

	chld_cons_intf = xc_map_foreign_range(xc_handle, chld_domid,
			XC_PAGE_SIZE, PROT_WRITE, chld_mfn);
	if (!chld_cons_intf) {
		PERROR("Failed to map child xenstore page");
		goto out;
	}

	/*DEBUG("req_prod=%d req_cons=%d",
		prnt_cons_intf->out_prod, prnt_cons_intf->out_cons);
	DEBUG("rsp_prod=%d rsp_cons=%d",
		prnt_cons_intf->in_prod,  prnt_cons_intf->in_cons);*/

	memcpy(chld_cons_intf, prnt_cons_intf, sizeof(*chld_cons_intf));

out:
	if (chld_cons_intf)
		munmap(chld_cons_intf, XC_PAGE_SIZE);
	if (prnt_cons_intf)
		munmap(prnt_cons_intf, XC_PAGE_SIZE);

	return 0;
}

static int xs_console_dev_clone(
		struct xs_console_dev *pconsole,
		struct xs_console_dev *cconsole,
		struct xenclone_domain *chld)
{
	xs_transaction_t t;
	int rc;

	cconsole->domain = chld;

	rc = xs_consfront_init_child(&pconsole->front, &cconsole->front, chld);
	if (rc) {
		PERROR("Error xs_consfront_init_child() rc=%d", rc);
		goto out;
	}

	if (xs_deep_copy) {
		rc = xs_consfront_clone_deep(&pconsole->front, &cconsole->front, chld);
		if (rc) {
			PERROR("Error xs_consfront_clone() rc=%d", rc);
			goto out;
		}

		rc = xs_consback_clone_deep(&pconsole->back, &cconsole->back, &cconsole->front, chld);
		if (rc) {
			PERROR("Error xs_consback_clone() rc=%d", rc);
			goto out;
		}
	}

	rc = console_ring_clone(pconsole->mfn, pconsole->domain->domid,
			cconsole->mfn, chld->domid);
	if (rc) {
		PERROR("Failed to clone console ring");
		goto out;
	}

	/* write child data */
trans_start:
	t = xs_transaction_start(xs_handle);
	if (t == XBT_NULL)
		goto out;

	if (xs_deep_copy) {
		rc = xs_consfront_write_deep(&cconsole->front, t);
		if (rc) {
			PERROR("Failed to write netfront Xenstore info");
			goto trans_end;
		}

		rc = xs_consback_write_deep(&cconsole->back, t, chld);
		if (rc) {
			PERROR("Failed to write netback Xenstore info");
			goto trans_end;
		}

		rc = xs_libxl_console_write_deep(cconsole, &chld->xs.path_libxl, 0, t);
		if (rc) {
			PERROR("Failed to write console libxl info");
			goto trans_end;
		}

	} else {
		struct xenclone_domain *prnt = chld->parent;

		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_dev_console,
				pconsole->front.path.value, cconsole->front.path.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_dev_console,
				pconsole->front.backend_path.value, cconsole->front.backend_path.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = xs_libxl_console_clone(
				prnt->domid, &prnt->xs.path_libxl,
				chld->domid, &chld->xs.path_libxl,
				0, t);
		if (rc) {
			PERROR("Failed to clone console libxl info");
			goto trans_end;
		}
	}

trans_end:
	if (rc)
		xs_transaction_end(xs_handle, t, true);

	else {
		rc = xs_transaction_end(xs_handle, t, false);
		if (!rc) {
			if (errno == EAGAIN)
				goto trans_start;
			else
				rc = errno;
		} else
			rc = 0;
	}

out:
	return rc;
}

int console_clone(struct xenclone *clone)
{
	int rc;

	rc = xs_console_dev_clone(&clone->parent->console, &clone->domain.console,
			&clone->domain);
	if (rc) {
		PERROR("Failed to clone network device");
		goto out;
	}

out:
	return rc;
}
