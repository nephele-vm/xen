/******************************************************************************
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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <xen/io/9pfs.h>
#include "log.h"
#include "profile.h"
#include "os.h"
#include "xencloned.h"
#include "clone.h"
#include "ring.h"
#include "xs.h"
#include "9pfs.h"
#include "qemu.h"


static void xs_9pfsfront_fini(struct xs_9pfsfront *front)
{
	assert(front != NULL);
	xs_path_fini(&front->path);
	xs_path_fini(&front->backend_path);
	if (front->backend_dom_path) {
		free(front->backend_dom_path);
		front->backend_dom_path = NULL;
	}
	if (front->tag) {
		free(front->tag);
		front->tag = NULL;
	}
	if (front->rings) {
		free(front->rings);
		front->rings = NULL;
	}
}

static int xs_9pfsfront_init_parent(struct xs_9pfsfront *front)
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
		xs_9pfsfront_fini(front);

	return rc;
}

static int xs_9pfsfront_init_child(
		struct xs_9pfsfront *p9pfsfront,
		struct xs_9pfsfront *c9pfsfront,
		struct xenclone_domain *chld,
		int dev_idx)
{
	int rc;

	/* convert frontend path */
	rc = xs_path_initf(&c9pfsfront->path, false,
			"%s/device/9pfs/%d",
			chld->xs.path_local.value, dev_idx);
	if (rc)
		goto out;

	/* convert backend path */
	rc = xs_path_initf(&c9pfsfront->backend_path, false,
			"%s/backend/9pfs/%lu/%d",
			p9pfsfront->backend_dom_path, chld->domid, dev_idx);
	if (rc)
		goto out;

	c9pfsfront->backend_id = p9pfsfront->backend_id;
	c9pfsfront->backend_dom_path = strdup(p9pfsfront->backend_dom_path);
	if (!c9pfsfront->backend_dom_path) {
		rc = -ENOMEM;
		goto out;
	}

out:
	if (rc)
		xs_9pfsfront_fini(c9pfsfront);

	return rc;
}

static int xs_9pfsfront_read_deep(struct xs_9pfsfront *front, bool *skip)
{
	const char *fe_path = front->path.value;
	char key[strlen("event-channel-") + 5];
	int i, rc;

	XS_FE_GET("state",             "%u", &front->state);
	XS_FE_GET("tag",               "%s", &front->tag);
	XS_FE_GET_OPTIONAL("version",  "%u", &front->version);
	if (rc == 0)
		*skip = false;
	else if (rc == ENOENT) {
		*skip = true;
		goto out;
	} else
		goto out;
	XS_FE_GET("num-rings",         "%u", &front->num_rings);

	front->rings = malloc(front->num_rings * sizeof(struct xen_ring));
	if (!front->rings) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < front->num_rings; i++) {
		snprintf(key, sizeof(key), "ring-ref%d", i);
		XS_FE_GET(key, "%u", &front->rings[i].ring_ref);

		snprintf(key, sizeof(key), "event-channel-%d", i);
		XS_FE_GET(key, "%u", &front->rings[i].evtchn);
	}

out:
	if (rc)
		xs_9pfsfront_fini(front);

	return rc;
}

static int xs_9pfsfront_write_deep(struct xs_9pfsfront *front,
		xs_transaction_t t)
{
	char key[strlen("event-channel-") + 5];
	int i, rc;

	XS_FE_SET("backend",           "%s", front->backend_path.value);
	XS_FE_SET("backend-id",        "%u", front->backend_id);
	XS_FE_SET("state",             "%u", front->state);
	XS_FE_SET("tag",               "%s", front->tag);
	XS_FE_SET("version",           "%u", front->version);
	XS_FE_SET("num-rings",         "%u", front->num_rings);

	for (i = 0; i < front->num_rings; i++) {
		snprintf(key, sizeof(key), "ring-ref%d", i);
		XS_FE_SET(key, "%u", front->rings[i].ring_ref);

		snprintf(key, sizeof(key), "event-channel-%d", i);
		XS_FE_SET(key, "%u", front->rings[i].evtchn);
	}

out:
	return rc;
}

static int xs_9pfsfront_clone_deep(
		struct xs_9pfsfront *p9pfsfront,
		struct xs_9pfsfront *c9pfsfront,
		struct xenclone_domain *chld,
		int dev_idx)
{
	int rc;

	rc = xs_acl_clone(&p9pfsfront->path.acl, chld->parent->domid,
			&c9pfsfront->path.acl, chld->domid);
	if (rc)
		goto out;

	rc = xs_acl_clone(&p9pfsfront->backend_path.acl, chld->parent->domid,
			&c9pfsfront->backend_path.acl, chld->domid);
	if (rc)
		goto out;

	c9pfsfront->state = p9pfsfront->state;
	c9pfsfront->tag = strdup(p9pfsfront->tag);
	if (!c9pfsfront->tag) {
		rc = -ENOMEM;
		goto out;
	}
	c9pfsfront->version = p9pfsfront->version;
	c9pfsfront->num_rings = p9pfsfront->num_rings;
	c9pfsfront->rings = malloc(p9pfsfront->num_rings * sizeof(struct xen_ring));
	if (!c9pfsfront->rings) {
		rc = -ENOMEM;
		goto out;
	}
	for (int i = 0; i < p9pfsfront->num_rings; i++) {
		c9pfsfront->rings[i].ring_ref = p9pfsfront->rings[i].ring_ref;
		c9pfsfront->rings[i].evtchn = p9pfsfront->rings[i].evtchn;
	}
	rc = 0;
out:
	if (rc)
		xs_9pfsfront_fini(c9pfsfront);
	return rc;
}

static void xs_9pfsback_fini(struct xs_9pfsback *back)
{
	assert(back != NULL);
	if (back->host_fs_path) {
		free(back->host_fs_path);
		back->host_fs_path = NULL;
	}
	if (back->security_model) {
		free(back->security_model);
		back->security_model = NULL;
	}
	if (back->versions) {
		free(back->versions);
		back->versions = NULL;
	}
	if (back->hotplug_status) {
		free(back->hotplug_status);
		back->hotplug_status = NULL;
	}
}

static int xs_9pfsback_read_deep(struct xs_9pfsback *back)
{
	const char *be_path = back->path->value;
	int rc;

	XS_BE_GET("frontend-id",       "%d", &back->frontend_id);
	XS_BE_GET("online",            "%d", &back->online);
	XS_BE_GET("state",             "%d", &back->state);
	XS_BE_GET("path",              "%s", &back->host_fs_path);
	XS_BE_GET("security_model",    "%s", &back->security_model);
	XS_BE_GET("versions",          "%s", &back->versions);
	XS_BE_GET("max-rings",           "%d", &back->max_rings);
	XS_BE_GET("max-ring-page-order", "%d", &back->max_ring_page_order);
	XS_BE_GET("hotplug-status",    "%s", &back->hotplug_status);

out:
	return rc;
}

static int xs_9pfsback_write_deep(struct xs_9pfsback *back,
		xs_transaction_t t)
{
	int rc;

	XS_BE_SET("frontend",          "%s", back->frontend_path->value);
	XS_BE_SET("frontend-id",       "%d", back->frontend_id);
	XS_BE_SET("online",            "%d", back->online);
	XS_BE_SET("state",             "%d", back->state);
	XS_BE_SET("path",              "%s", back->host_fs_path);
	XS_BE_SET("security_model",    "%s", back->security_model);
	XS_BE_SET("versions",          "%s", back->versions);
	XS_BE_SET("max-rings",           "%d", back->max_rings);
	XS_BE_SET("max-ring-page-order", "%d", back->max_ring_page_order);
	XS_BE_SET("hotplug-status",    "%s", back->hotplug_status);

	XS_BE_SET("cloned", "%s", "true");

out:
	return rc;
}

static int xs_9pfsback_clone_deep(
		struct xs_9pfsback *p9pfsback,
		struct xs_9pfsback *c9pfsback,
		struct xs_9pfsfront *c9pfsfront,
		struct xenclone_domain *chld)
{
	int rc = 0;

	c9pfsback->path = &c9pfsfront->backend_path;
	c9pfsback->frontend_path = &c9pfsfront->path;
	c9pfsback->frontend_id = chld->domid;
	c9pfsback->online = p9pfsback->online;
	c9pfsback->state = p9pfsback->state;
	c9pfsback->host_fs_path = strdup(p9pfsback->host_fs_path);
	if (!c9pfsback->host_fs_path) {
		rc = -ENOMEM;
		goto out;
	}
	c9pfsback->security_model = strdup(p9pfsback->security_model);
	if (!c9pfsback->security_model) {
		rc = -ENOMEM;
		goto out;
	}
	c9pfsback->versions = strdup(p9pfsback->versions);
	if (!c9pfsback->versions) {
		rc = -ENOMEM;
		goto out;
	}
	c9pfsback->max_rings = p9pfsback->max_rings;
	c9pfsback->max_ring_page_order = p9pfsback->max_ring_page_order;
	c9pfsback->hotplug_status = strdup(p9pfsback->hotplug_status);
	if (!c9pfsback->hotplug_status) {
		rc = -ENOMEM;
		goto out;
	}

out:
	if (rc)
		xs_9pfsback_fini(c9pfsback);
	return rc;
}

static int xs_9pfs_dev_init(struct xs_9pfs_dev *dev,
		struct xenclone_domain *domain, char *fe_path)
{
	struct xs_9pfsfront *front = &dev->front;
	struct xs_9pfsback *back = &dev->back;
	bool read_perms = xs_deep_copy;
	int rc;

	dev->domain = domain;

	rc = xs_path_init(&front->path, fe_path, read_perms);
	if (rc) {
		PERROR("Failed to initializing path %s", fe_path);
		goto out;
	}

	rc = xs_9pfsfront_init_parent(front);
	if (rc) {
		PERROR("Failed to init 9pfsfront Xenstore info");
		goto out;
	}

	if (xs_deep_copy) {
		rc = xs_9pfsfront_read_deep(front, &dev->skip);
		if (rc) {
			if (!dev->skip)
				PERROR("Failed to read 9pfsfront Xenstore info");
			goto out;
		}

		back->path = &front->backend_path;
		back->frontend_path = &front->path;

		rc = xs_9pfsback_read_deep(back);
		if (rc) {
			PERROR("Failed to read 9pfsback Xenstore info");
			goto out;
		}
	}

out:
	if (rc)
		xs_9pfsfront_fini(front);

	return rc;
}

static void xs_9pfs_dev_fini(struct xs_9pfs_dev *dev)
{
	xs_9pfsfront_fini(&dev->front);
	xs_9pfsback_fini(&dev->back);
}

#if CLONE_RINGS
static int ring_clone(grant_ref_t ring_ref,
		domid_t prnt_domid, domid_t chld_domid)
{
	struct xen_9pfs_data_intf *pintf, *cintf;
	unsigned long pages_num;
	void *ppage, *cpage;
	int i, rc = 0;

	/* map interfaces */
	pintf = xengnttab_map_grant_ref(xgt_handle,
			prnt_domid, ring_ref, PROT_WRITE);
	if (!pintf) {
		PERROR("Failed to map parent intf grant ref");
		rc = -errno;
		goto out;
	}

	cintf = xengnttab_map_grant_ref(xgt_handle,
			chld_domid, ring_ref, PROT_WRITE);
	if (!cintf) {
		PERROR("Failed to map child intf grant ref");
		rc = -errno;
		goto unmap_parent_intf;
	}

	DEBUG("ref=%d in_cons=%d in_prod=%d out_cons=%d out_prod=%d ring_order=%d",
		ring_ref, pintf->in_cons, pintf->in_prod,
		pintf->out_cons, pintf->out_prod, pintf->ring_order);

	pages_num = (1 << pintf->ring_order);
	for (i = 0; i < pages_num; i++) {
		ppage = xengnttab_map_grant_ref(xgt_handle,
				prnt_domid, pintf->ref[i], PROT_WRITE);
		if (!ppage) {
			PERROR("Failed to map parent ring grant ref");
			rc = -errno;
			goto unmap_child_intf;
		}

		cpage = xengnttab_map_grant_ref(xgt_handle,
				chld_domid, pintf->ref[i], PROT_WRITE);
		if (!cpage) {
			PERROR("Failed to map child ring grant ref");
			rc = -errno;
			goto unmap_parent_ring;
		}

		memcpy(cpage, ppage, PAGE_SIZE);

		xengnttab_unmap(xgt_handle, cpage, 1);
unmap_parent_ring:
		xengnttab_unmap(xgt_handle, ppage, 1);
		if (rc)
			goto unmap_child_intf;
	}

	/* copy ring */
	memcpy(cintf, pintf, sizeof(struct xen_9pfs_data_intf)
			+ pages_num * sizeof(pintf->ref[0]));

unmap_child_intf:
	xengnttab_unmap(xgt_handle, cintf, 1);
unmap_parent_intf:
	xengnttab_unmap(xgt_handle, pintf, 1);
out:
	return rc;
}
#endif

static
int xs_libxl_9pfs_write_deep(struct xs_9pfs_dev *dev, struct xs_path *path_libxl,
		int dev_idx, xs_transaction_t t)
{
	char *libxl_path = NULL;
	int rc;

	rc = asprintf(&libxl_path, "%s/device/9pfs/%d", path_libxl->value, dev_idx);
	if (!libxl_path) {
		rc = errno;
		goto out;
	}

	XS_LIBXL_SET("frontend",      "%s", dev->front.path.value);
	XS_LIBXL_SET("backend",       "%s", dev->front.backend_path.value);
	XS_LIBXL_SET("frontend-id",   "%d", dev->back.frontend_id);
	XS_LIBXL_SET("online",        "%d", dev->back.online);
	XS_LIBXL_SET("state",         "%d", 1);
	XS_LIBXL_SET("path",          "%s", dev->back.host_fs_path);
	XS_LIBXL_SET("security_model","%s", dev->back.security_model);

out:
	if (libxl_path)
		free(libxl_path);
	return rc;
}

static
int xs_libxl_9pfs_clone(
		unsigned long pdomid, struct xs_path *ppath_libxl,
		unsigned long cdomid, struct xs_path *cpath_libxl,
		int dev_idx, xs_transaction_t t)
{
	char *ppath = NULL, *cpath = NULL;
	int rc;

	rc = asprintf(&ppath, "%s/device/9pfs/%d",
			ppath_libxl->value, dev_idx);
	if (!ppath) {
		rc = errno;
		goto out;
	}

	rc = asprintf(&cpath, "%s/device/9pfs/%d",
			cpath_libxl->value, dev_idx);
	if (!cpath) {
		rc = errno;
		goto out;
	}

	rc = xs_clone(xs_handle, XBT_NULL,
			pdomid, cdomid, xs_clone_op_dev_9pfs,
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

int p9fs_devices_init(struct xenclone_domain *domain)
{
	char *parent_vif_dir = NULL, **dir_entries = NULL;
	unsigned int dir_entries_num, i, j;
	struct xs_9pfs_dev *devs;
	int rc;

	rc = asprintf(&parent_vif_dir,
		"/local/domain/%lu/device/9pfs", domain->domid);
	if (rc == -1)
		goto out;

	dir_entries = xs_directory(xs_handle, XBT_NULL, parent_vif_dir,
		&dir_entries_num);
	if (dir_entries == NULL) {
		/* List is empty. */
		rc = 0;
		goto out_parent_vif_dir;
	}
	DEBUG("dir_entries_num=%d", dir_entries_num);
	if (!dir_entries_num)
		goto out_dir_entries;

	devs = calloc(dir_entries_num, sizeof(struct xs_9pfs_dev));
	if (devs == NULL) {
		rc = -ENOMEM;
		goto out_dir_entries;
	}

	for (i = 0; i < dir_entries_num; i++) {
		struct xs_9pfs_dev *dev;
		char *fe_path;

		dev = &devs[i];

		rc = asprintf(&fe_path, "%s/%s", parent_vif_dir, dir_entries[i]);
		if (rc == -1)
			goto out_of_loop;

		rc = xs_9pfs_dev_init(dev, domain, fe_path);
		if (dev->skip)
			rc = 0;
	}

out_of_loop:
	if (rc == 0) {
		domain->p9fs_devs = devs;
		domain->p9fs_devs_num = dir_entries_num;

	} else {
		//TODO unregister
		for (j = 0; j < i; j++)
			xs_9pfs_dev_fini(&devs[j]);
		free(devs);
	}
out_dir_entries:
	free(dir_entries);
out_parent_vif_dir:
	free(parent_vif_dir);
out:
	return rc;
}

int p9fs_devices_fini(struct xenclone_domain *domain)
{
	for (int i = 0; i < domain->p9fs_devs_num; i++)
		xs_9pfs_dev_fini(&domain->p9fs_devs[i]);
	free(domain->p9fs_devs);
	domain->p9fs_devs = NULL;
	domain->p9fs_devs_num = 0;

	return 0;
}

static int xs_9pfs_dev_clone(
		struct xs_9pfs_dev *pdev,
		struct xs_9pfs_dev *cdev,
		struct xenclone_domain *chld,
		int dev_idx)
{
	xs_transaction_t t;
	int rc;

	cdev->domain = chld;

	rc = xs_9pfsfront_init_child(&pdev->front, &cdev->front, chld, dev_idx);
	if (rc) {
		PERROR("Error xs_9pfsfront_init_child() rc=%d", rc);
		goto out;
	}

	if (xs_deep_copy) {
		rc = xs_9pfsfront_clone_deep(&pdev->front, &cdev->front, chld, dev_idx);
		if (rc) {
			PERROR("Error xs_9pfsfront_clone() rc=%d", rc);
			goto out;
		}

		rc = xs_9pfsback_clone_deep(&pdev->back, &cdev->back, &cdev->front, chld);
		if (rc) {
			PERROR("Error xs_9pfsback_clone() rc=%d", rc);
			goto out;
		}
	}

#if CLONE_RINGS
	/* rings cloning */
	for (int i = 0; i < dev->front.num_rings; i++) {
		rc = ring_clone(dev->front.rings[i].ring_ref, prnt->domid, chld->domid);
		if (rc) {
			PERROR("Failed to clone ring");
			goto out;
		}
	}
#endif

	/* write child data */
trans_start:
	t = xs_transaction_start(xs_handle);
	if (t == XBT_NULL)
		goto out;

	if (xs_deep_copy) {
		rc = xs_9pfsfront_write_deep(&cdev->front, t);
		if (rc) {
			PERROR("Failed to write 9pfsfront Xenstore info");
			goto trans_end;
		}

		rc = xs_9pfsback_write_deep(&cdev->back, t);
		if (rc) {
			PERROR("Failed to write 9pfsback Xenstore info");
			goto trans_end;
		}

		rc = xs_libxl_9pfs_write_deep(cdev, &chld->xs.path_libxl, dev_idx, t);
		if (rc) {
			PERROR("Failed to write 9pfs libxl info");
			goto trans_end;
		}

	} else {
		struct xenclone_domain *prnt = chld->parent;

		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_dev_9pfs,
				pdev->front.path.value, cdev->front.path.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_dev_9pfs,
				pdev->front.backend_path.value, cdev->front.backend_path.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = xs_libxl_9pfs_clone(
				prnt->domid, &prnt->xs.path_libxl,
				chld->domid, &chld->xs.path_libxl,
				0, t);
		if (rc) {
			PERROR("Failed to clone 9pfs libxl info");
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

static struct xenclone_hmap map_fd_to_qmp;
static struct xenclone_hmap map_parentid_to_qmp;

static int launch_qemu_dm(struct xenclone *clone)
{
	struct xenclone_domain *parent = clone->parent;
	struct qmp *qmp;
	int rc, cleanup_if_error = 0;

	qmp = xenclone_hmap_get(&map_parentid_to_qmp,
			(void *) parent->domid);
	if (!qmp) {
		qmp = qmp_create(parent->domid);
		if (!qmp) {
			ERROR("Error calling qmp_create()");
			rc = -1;
			goto out;
		}

		rc = xenclone_hmap_insert(&map_parentid_to_qmp,
				(void *) parent->domid, qmp);
		if (rc) {
			ERROR("Error calling xenclone_hmap_insert() rc=%d", rc);
			goto out;
		}
		qmp_get(qmp);
		cleanup_if_error = 1;
	}

	rc = xenclone_hmap_insert(&map_fd_to_qmp,
			(void *)(unsigned long) qmp->fd, qmp);
	if (rc) {
		ERROR("Error calling xenclone_hmap_insert() rc=%d", rc);
		goto out;
	}
	qmp_get(qmp);

	rc = qmp_announce_clone(qmp, clone->domain.domid, parent->domid);
	if (rc) {
		ERROR("Error calling qmp_announce_clone() rc=%d", rc);
		qmp_put(qmp);
		goto out;
	}

out:
	if (rc) {
		if (qmp && cleanup_if_error)
			qmp_put(qmp);
	}
	return rc;
}

int p9fs_devices_clone(struct xenclone *clone)
{
	struct xenclone_domain *parent = clone->parent;
	unsigned int i, j;
	struct xs_9pfs_dev *devs;
	int rc = 0, skipped = 0;

	if (parent->p9fs_devs_num == 0)
		goto out;

	devs = calloc(parent->p9fs_devs_num, sizeof(struct xs_9pfs_dev));
	if (devs == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < parent->p9fs_devs_num; i++) {
		struct xs_9pfs_dev *pdev, *cdev;

		pdev = &parent->p9fs_devs[i];
		cdev = &devs[i];

		rc = xs_9pfs_dev_clone(pdev, cdev, &clone->domain, i);
		if (rc) {
			PERROR("Failed to clone 9pfs device");
			break;
		}

		if (pdev->skip) {
			skipped++;
			rc = 0;
		} else if (rc) {
			PERROR("Failed to clone 9pfs device");
			break;
		}
	}

	for (j = 0; j < i; j++)
		xs_9pfs_dev_fini(&devs[j]);
	free(devs);

	if (skipped < parent->p9fs_devs_num) {
		rc = launch_qemu_dm(clone);
		if (rc) {
			PERROR("Error calling launch_qemu_dm() rc=%d", rc);
			/*TODO goto out;*/
		}
	}
out:
	return rc;
}

static bool p9fs_initialized = false;
static pthread_t p9fs_thread;


int p9fs_remove_qmp(struct qmp *qmp)
{
	struct qmp *tmp;
	int rc;

	if (!qmp) {
		rc = -EINVAL;
		goto out;
	}

	tmp = xenclone_hmap_remove(&map_fd_to_qmp,
			(void *)(unsigned long) qmp->fd, true);
	assert(tmp == qmp);
	tmp = xenclone_hmap_remove(&map_parentid_to_qmp,
			(void *)(unsigned long) qmp->parent_domid, true);
	assert(tmp == qmp);
out:
	return rc;
}

/* used with hashmaps */
static struct hmap_list_node *qmp_fd_hmap_list_node(void *arg)
{
	struct qmp *qmp = arg;

	return &qmp->map_fd_list_node;
}

static int qmp_fd_hmap_list_node_destroy(struct hmap_list_node *n)
{
	struct qmp *qmp;

	qmp = container_of(n, struct qmp, map_fd_list_node);
	assert(qmp != NULL);
	qmp_put(qmp);
	return 0;
}

static struct hmap_list_node *qmp_parentid_hmap_list_node(void *arg)
{
	struct qmp *qmp = arg;

	return &qmp->map_parentid_list_node;
}

static int qmp_parentid_hmap_list_node_destroy(struct hmap_list_node *n)
{
	struct qmp *qmp;

	qmp = container_of(n, struct qmp, map_parentid_list_node);
	assert(qmp != NULL);
	qmp_put(qmp);
	return 0;
}

static void *p9fs_loop(void *arg)
{
	fd_set rfds;
	struct qmp *qmp;
	int fd, max_fd;
	struct timeval tv;
	long rc = 0;

	DEBUG("9pfs thread running..");

	rc = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	if (rc) {
		PERROR("Error calling pthread_setcanceltype() rc=%ld", rc);
		goto out;
	}

	rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	if (rc) {
		PERROR("Error calling pthread_setcancelstate() rc=%ld", rc);
		goto out;
	}

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	/*
	 * 9pfs thread waits qmp ACK replies asynchronously.
	 */
	while (1) {
		FD_ZERO(&rfds);
		max_fd = 0;

		list_for_each_entry(qmp, &map_fd_to_qmp.elemlist, map_fd_list_node.node) {
			FD_SET(qmp->fd, &rfds);
			if (qmp->fd > max_fd)
				max_fd = qmp->fd;
		}

		/* TODO use smth smarter like poll/epoll */
		rc = select(max_fd + 1, &rfds, NULL, NULL, &tv);
		if (rc < 0) {
			PERROR("Error calling select() rc=%ld, errno=%d", rc, errno);
			goto out;
		}

		for (fd = 0; fd <= max_fd; ++fd) {
			if (FD_ISSET(fd, &rfds)) {
				qmp = xenclone_hmap_get(&map_fd_to_qmp,
						(void *)(unsigned long) fd);
				assert(qmp != NULL);
				qmp_put(qmp);
			}
		}
	}

out:
	return (void *) rc;
}

int p9fs_init(void)
{
	int rc;

	rc = xenclone_hmap_init(&map_fd_to_qmp, XENCLONE_KEY_ULONG,
			qmp_fd_hmap_list_node);
	if (rc) {
		PERROR("Error calling xenclone_hmap_init() rc=%d", rc);
		goto out;
	}

	rc = xenclone_hmap_init(&map_parentid_to_qmp, XENCLONE_KEY_ULONG,
			qmp_parentid_hmap_list_node);
	if (rc) {
		PERROR("Error calling xenclone_hmap_init() rc=%d", rc);
		goto out;
	}

	rc = pthread_create(&p9fs_thread, NULL, &p9fs_loop, NULL);
	if (rc != 0) {
		PERROR("Error calling pthread_create() rc=%d", rc);
		goto out;
	}

	p9fs_initialized = true;
out:
	return rc;
}

int p9fs_fini(void)
{
	void *thread_res;
	int rc = -1;

	if (!p9fs_initialized)
		goto out;

	rc = pthread_cancel(p9fs_thread);
	if (rc != 0) {
		PERROR("Error calling pthread_cancel() rc=%d", rc);
		goto out;
	}

	rc = pthread_join(p9fs_thread, &thread_res);
	if (rc != 0) {
		PERROR("Error calling pthread_join() rc=%d", rc);
		goto out;
	}

	if (thread_res == PTHREAD_CANCELED)
		INFO("p9fs_fini(): thread was canceled");
	else
		INFO("p9fs_fini(): thread wasn't canceled (shouldn't happen!)");

	rc = xenclone_hmap_fini(&map_parentid_to_qmp,
			qmp_parentid_hmap_list_node_destroy);
	if (rc) {
		PERROR("Error calling xenclone_hmap_fini() rc=%d", rc);
		goto out;
	}

	rc = xenclone_hmap_fini(&map_fd_to_qmp,
			qmp_fd_hmap_list_node_destroy);
	if (rc) {
		PERROR("Error calling xenclone_hmap_fini() rc=%d", rc);
		goto out;
	}

	p9fs_initialized = false;
out:
	return rc;
}
