/******************************************************************************
 * cloning functions
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

#define XC_WANT_COMPAT_MAP_FOREIGN_API 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xenstore.h>
#include "log.h"
#include "profile.h"
#include "os.h"
#include "hmap.h"
#include "xencloned.h"
#include "clone.h"
#include "xenstore.h"
#include "xs.h"
#include "network.h"
#include "9pfs.h"
#include "cache.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif


bool leave_clones_paused = false;
bool skip_io_cloning = false;
bool use_page_sharing_info_pool = false;

static struct clone_notification_ring *cnring;
static struct xenclone_hmap clones_map;


bool notification_ring_is_empty(void)
{
	return (cnring->hdr.prod_idx == cnring->hdr.cons_idx);
}

static int notification_ring_pop(struct clone_notification *notification)
{
	struct clone_notification *entry;
	int rc = 0;

	if (notification_ring_is_empty()) {
		rc = -ENOENT;
		goto out;
	}

//#define CONFIG_CNRING_PROTECT 1
#if CONFIG_CNRING_PROTECT
	rc = mprotect(cnring, PAGE_SIZE * ring_pages_num, PROT_READ | PROT_WRITE);
	if (rc) {
		PERROR("Error calling mprotect() rc=%d", rc);
		goto out;
	}
#endif

	//TODO should have space
	entry = &cnring->entries[CLONE_RING_CONS_IDX(cnring)];
	*notification = *entry;

	cnring->hdr.cons_idx++;

#if CONFIG_CNRING_PROTECT
	rc = mprotect(cnring, PAGE_SIZE * ring_pages_num, PROT_READ);
	if (rc) {
		PERROR("Error calling mprotect() rc=%d", rc);
		goto out;
	}
#endif

out:
	return rc;
}

static int xenclone_domain_add_child(struct xenclone_domain *domain,
		struct xenclone_domain *child);
static int xenclone_domain_remove_child(struct xenclone_domain *domain,
		struct xenclone_domain *child);
static int xenclone_domain_has_children(struct xenclone_domain *domain);

static int xenclone_domain_init(struct xenclone_domain *d, domid_t domid,
		unsigned long start_info_mfn, bool is_parent)
{
	start_info_t *si = NULL;
	int rc = 0;

	d->domid = domid;
	d->start_info_mfn = start_info_mfn;

	si = xc_map_foreign_range(xc_handle, d->domid,
			XC_PAGE_SIZE, PROT_READ, d->start_info_mfn);
	if (!si) {
		rc = -errno;
		PERROR("Failed to map parent start_info");
		goto out;
	}

	rc = xs_init(&d->xs, d->domid, si->store_mfn, is_parent);
	if (rc) {
		PERROR("Error calling xs_init() rc=%d", rc);
		goto out;
	}

	d->console.mfn = si->console.domU.mfn;

	d->children_num = 0;

out:
	if (si)
		munmap(si, XC_PAGE_SIZE);

	return rc;
}

int xenclone_domain_fini(struct xenclone_domain *domain)
{
	int rc = 0;

	if (!domain)
		goto out;

	rc = p9fs_devices_fini(domain);
	if (rc) {
		PERROR("Error calling p9fs_devices_fini() rc=%d", rc);
		goto out;
	}

	rc = network_devices_fini(domain);
	if (rc) {
		PERROR("Error calling network_fini() rc=%d", rc);
		goto out;
	}

	rc = console_fini(domain);
	if (rc) {
		PERROR("Error calling console_fini() rc=%d", rc);
		goto out;
	}

	rc = xs_fini(&domain->xs);
	if (rc) {
		PERROR("Error calling xs_fini() rc=%d", rc);
		goto out;
	}
out:
	return rc;
}

static int xenclone_domain_add_child(struct xenclone_domain *domain,
		struct xenclone_domain *child)
{
	child->parent = domain;
	domain->children_num++;
	return 0;
}

static int xenclone_domain_remove_child(struct xenclone_domain *domain,
		struct xenclone_domain *child)
{
	int rc = 0;

	if (child->parent != domain) {
		ERROR("Invalid parent");
		rc = -EINVAL;
		goto out;
	}

	domain->children_num--;
	child->parent = NULL;

out:
	return rc;
}

static int xenclone_domain_has_children(struct xenclone_domain *domain)
{
	return (domain->children_num > 0);
}

static struct xenclone_domain *parent_create(unsigned long domid,
		unsigned long start_info_mfn)
{
	struct xenclone_domain *parent;
	int rc;

	parent = calloc(1, sizeof(*parent));
	if (!parent) {
		PERROR("Error allocating parent");
		rc = -ENOMEM;
		goto out;
	}

	rc = xenclone_domain_init(parent, domid, start_info_mfn, true);
	if (rc) {
		PERROR("Error calling xenclone_domain_init() rc=%d", rc);
		goto out;
	}

	rc = console_init_parent(parent);
	if (rc) {
		PERROR("Error calling console_init() rc=%d", rc);
		goto out;
	}

	if (!skip_io_cloning) {
		char *skip_cloning;

		rc = xs_read_kv(XBT_NULL, parent->xs.path_local.value, "skip_cloning",
				&skip_cloning);
		if (skip_cloning) {
			char *token = strtok(skip_cloning, ";");
			while (token) {
				if (!strcmp(token, "network"))
					parent->skip_cloning.network = 1;
				else if (!strcmp(token, "9pfs"))
					parent->skip_cloning.p9fs = 1;
				else
					PERROR("Unknown skipping token: %s", token);
				token = strtok(NULL, ";");
			}
			free(skip_cloning);
		}

		if (!parent->skip_cloning.network) {
			rc = network_devices_init(parent);
			if (rc) {
				PERROR("Error calling network_init() rc=%d", rc);
				goto out;
			}
		}

		if (!parent->skip_cloning.p9fs) {
			rc = p9fs_devices_init(parent);
			if (rc) {
				PERROR("Error calling p9fs_devices_init() rc=%d", rc);
				goto out;
			}
		}
	}
out:
	if (rc) {
		xenclone_domain_fini(parent);
		parent = NULL;
	}

	return parent;
}

static void clone_destroy(struct xenclone *clone)
{
	struct xenclone *tmp;
	int rc;

	DEBUG("Deleting clone domid=%lu", clone->domain.domid);

	/* remove from collection */
	tmp = xenclone_hmap_remove(&clones_map, (void *) clone->domain.domid, true);
	if (tmp)
		assert(tmp == clone);

	if (clone->parent) {
		xenclone_domain_remove_child(clone->parent, &clone->domain);

		if (!do_cache_parents && !xenclone_domain_has_children(clone->parent)) {
			DEBUG("Deleting parent domid=%lu", clone->parent->domid);
			rc = xenclone_domain_fini(clone->parent);
			assert(rc == 0);

			free(clone->parent);
		}
	}

	rc = xenclone_domain_fini(&clone->domain);
	assert(rc == 0);

	rc = pthread_mutex_destroy(&clone->mtx);
	assert(rc == 0);

	free(clone);
}

static struct xenclone *clone_create(struct clone_notification *clone_notification)
{
	struct xenclone *clone;
	struct xenclone_domain *parent = NULL;
	int rc;

	PROFILE_NESTED_TICK(__FUNCTION__);

	clone = calloc(1, sizeof(*clone));
	if (!clone) {
		PERROR("Error allocating clone");
		rc = -ENOMEM;
		goto out;
	}
	clone->id = clone_notification->id;

	/* parent */
	if (do_cache_parents)
		parent = caching_get(clone_notification->parent_id);
	if (!parent) {
		parent = parent_create(
				clone_notification->parent_id,
				clone_notification->parent_start_info_mfn);
		if (!parent) {
			PERROR("Error parent_create()");
			rc = -ENOMEM;
			goto out;
		}

		if (do_cache_parents) {
			rc = caching_add(parent);
			if (rc) {
				PERROR("Error calling caching_add() rc=%d", rc);
				goto out;
			}
		}
	}
	clone->parent = parent;

	/* child */
	rc = xenclone_domain_init(&clone->domain,
			clone_notification->child_id,
			clone_notification->child_start_info_mfn,
			false);
	if (rc) {
		PERROR("Error calling xenclone_domain_init() rc=%d", rc);
		goto out;
	}

	xenclone_domain_add_child(parent, &clone->domain);

	clone->domain.xs.port = parent->xs.port;//TODO only child

	rc = pthread_mutex_init(&clone->mtx, NULL);
	assert(rc == 0);
	clone->pending_devices = 0;
	clone->wait_IO_completion = false;
	HMAP_LIST_NODE_INIT(&clone->node);

	/* add to collection */
	rc = xenclone_hmap_insert(&clones_map, (void *) clone->domain.domid, clone);

out:
	if (rc) {
		if (clone) {
			clone_destroy(clone);//TODO destroy
			clone = NULL;
		}
	}

	PROFILE_NESTED_TOCK_MSEC();
	return clone;
}


static struct hmap_list_node *xenclone_hmap_list_node(void *arg)
{
	struct xenclone *clone = arg;

	return &clone->node;
}

static int xenclone_hmap_list_node_destroy(struct hmap_list_node *n)
{
	struct xenclone *clone;

	clone = container_of(n, struct xenclone, node);
	assert(clone != NULL);
	clone_destroy(clone);

	return 0;
}

static int clone_io_done(struct xenclone *clone)
{
	int rc = 0;

	xenclone_lock(clone);
	assert(clone->pending_devices == 0 && !clone->wait_IO_completion);
	xenclone_unlock(clone);

	DEBUG("Clone domid=%lu created (id=%u)", clone->domain.domid, clone->id);

	rc = xc_cloning_completion(xc_handle, clone->id);
	if (rc) {
		PERROR("Error calling xc_cloning_completion() (rc=%d) id=%u", rc,
				clone->id);
		goto out;
	}

	if (!leave_clones_paused) {
		rc = xc_domain_unpause(xc_handle, clone->domain.domid);
		if (rc) {
			PERROR("Error calling xc_domain_unpause() (rc=%d)", rc);
			goto out;
		}
	}

#if XENCLONED_PROFILING
	rc = profile_stop(&clone->profile);
	if (rc) {
		PERROR("Error calling profile_stop() (rc=%d)", rc);
		goto out;
	}
	INFO("clone completion domid=%lu msec=%.6lf",
		clone->domain.domid, profile_msec(&clone->profile));
#endif
#if XENCLONED_MEASUREMENTS
	rc = run_cmd_redirected(DOM0_MEM_CONSUMPTION_SCRIPT,
			DOM0_MEM_CONSUMPTION_CSV, "a");
	if (rc) {
		PERROR("Failed writing memory consumption info");
		goto out;
	}
#endif

	clone_destroy(clone);
out:
	return rc;
}

int clone_start_IO_waiting(struct xenclone *clone)
{
	bool io_cloning_done;

	xenclone_lock(clone);
	io_cloning_done = (clone->pending_devices == 0);
	if (!io_cloning_done)
		clone->wait_IO_completion = true;
	xenclone_unlock(clone);
	if (io_cloning_done)
		clone_io_done(clone);
	return 0;
}

int clone_stop_IO_waiting(unsigned long cloneid)
{
	struct xenclone *clone;
	bool io_completed = false;
	int rc = 0;

	DEBUG("cloneid=%lu", cloneid);

	clone = xenclone_hmap_get(&clones_map, (void *) cloneid);
	if (!clone) {
		PERROR("No such domain domid=%lu", cloneid);
		rc = -ENOENT;
		goto out;
	}

	xenclone_lock(clone);
	assert(clone->pending_devices > 0);
	clone->pending_devices--;
	if (clone->pending_devices == 0 && clone->wait_IO_completion) {
		clone->wait_IO_completion = false;
		io_completed = true;
	}
	xenclone_unlock(clone);

	if (io_completed)
		rc = clone_io_done(clone);
out:
	return rc;
}

int handle_cloning(void)
{
#if XENCLONED_PROFILING
	struct timespec start;
#endif
	clone_notification_t clone_notification;
	struct xenclone *clone;
	int rc;

	PROFILE_NESTED_TICK(__FUNCTION__);
#if XENCLONED_PROFILING
	rc = clock_gettime(CLOCK_REALTIME, &start);
	if (rc) {
		PERROR("Error calling clock_gettime() rc=%d", rc);
		goto out;
	}
#endif

	rc = notification_ring_pop(&clone_notification);
	if (rc) {
		PERROR("Error retrieving clone notification");
		goto out;
	}

	INFO("cloned %d -> %d",
		clone_notification.parent_id, clone_notification.child_id);//TODO debug

	clone = clone_create(&clone_notification);
	if (!clone) {
		PERROR("Error creating clone");
		goto out;
	}

#if XENCLONED_PROFILING
	clone->profile.start = start;
#endif

	rc = xenstore_clone(clone);
	if (rc) {
		PERROR("Error calling xenstore_clone() rc=%d", rc);
		goto out_clone_info_fini;
	}

	rc = console_clone(clone);
	if (rc) {
		PERROR("Error calling console_clone() rc=%d", rc);
		goto out_clone_info_fini;
	}

	if (!skip_io_cloning) {
		if (!clone->parent->skip_cloning.network) {
			rc = network_devices_clone(clone);
			if (rc) {
				PERROR("Error calling network_devices_clone() rc=%d", rc);
				goto out_clone_info_fini;
			}
		}

		if (!clone->parent->skip_cloning.p9fs) {
			rc = p9fs_devices_clone(clone);
			if (rc) {
				PERROR("Error calling p9fs_devices_clone() rc=%d", rc);
				goto out_clone_info_fini;
			}
		}
	}

	rc = clone_start_IO_waiting(clone);
	if (rc) {
		PERROR("Error calling clone_start_IO_waiting() rc=%d", rc);
		goto out_clone_info_fini;
	}

out_clone_info_fini:
	if (rc)
		clone_destroy(clone);
out:
	PROFILE_NESTED_TOCK_MSEC();
	return rc;
}

/* #define PAGES_NUM 7 */ /* 1024 entries */
#define DEFAULT_RING_PAGES_NUM 1 /* 128 entries */

unsigned long ring_pages_num = DEFAULT_RING_PAGES_NUM;

static bool cloning_initialized = false;

int cloning_init(void)
{
	unsigned long flags;
	int rc;

	rc = xenclone_hmap_init(&clones_map, XENCLONE_KEY_ULONG,
			xenclone_hmap_list_node);
	if (rc) {
		PERROR("Error calling xenclone_hmap_init() rc=%d", rc);
		goto out;
	}

	/* Notification ring */
	cnring = mmap(NULL, PAGE_SIZE * ring_pages_num,
			PROT_READ|PROT_WRITE,
			MAP_ANON|MAP_SHARED,
			-1, 0);
	if (cnring == MAP_FAILED) {
		PERROR("Error calling mmap() rc=%d", rc);
		cnring = NULL;
		rc = -1;
		goto out;
	}

	rc = mlock(cnring, PAGE_SIZE * ring_pages_num);
	if (rc) {
		PERROR("Error calling mlock() rc=%d", rc);
		goto out;
	}

	memset(cnring, 0, PAGE_SIZE * ring_pages_num);

	flags = 0;
	if (use_page_sharing_info_pool)
		flags |= XC_CLONING_FLAG_USE_PAGE_SHARING_INFO_POOL;

	rc = xc_cloning_enable(xc_handle, cnring, ring_pages_num, flags);
	if (rc) {
		PERROR("Error calling xc_cloning_enable() rc=%d", rc);
		goto out;
	}

#if CONFIG_CNRING_PROTECT
	rc = mprotect(cnring, PAGE_SIZE * ring_pages_num, PROT_READ);
	if (rc) {
		PERROR("Error calling mprotect() rc=%d", rc);
		goto out;
	}
#endif

	cloning_initialized = true;

	INFO("notification ring=%p entries_num=%lu",
		cnring, cnring->hdr.entries_num);

out:
	if (rc) {
		if (cnring) {
			munmap(cnring, PAGE_SIZE * ring_pages_num);
			cnring = NULL;
		}
	}
	return rc;
}

int cloning_fini(void)
{
	int rc = -1;

	if (!cloning_initialized)
		goto out;

	rc = xc_cloning_disable(xc_handle);
	if (rc) {
		PERROR("Error calling xc_cloning_disable() rc=%d", rc);
		goto out;
	}

	rc = munmap(cnring, PAGE_SIZE * ring_pages_num);
	if (rc) {
		PERROR("Error calling munmap() rc=%d", rc);
		return 1;
	}
	cnring = NULL;

	rc = xenclone_hmap_fini(&clones_map,
			xenclone_hmap_list_node_destroy);
	if (rc) {
		PERROR("Error calling xenclone_hmap_fini() rc=%d", rc);
		goto out;
	}

	cloning_initialized = false;

out:
	return rc;
}
