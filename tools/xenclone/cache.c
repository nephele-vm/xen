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
#include <sys/select.h>
#include <xenstore.h>
#include "log.h"
#include "xencloned.h"
#include "clone.h"
#include "xs.h"
#include "cache.h"


bool do_cache_parents = false;

#define MAX_PARENTS_NUM 32

static struct xenclone_hmap cached_parents_map;


static int watch_domain(struct xenclone_domain *domain)
{
	int rc;

	rc = asprintf(&domain->cache.xs_watch_path,
			"/local/domain/%lu/control/shutdown", domain->domid);
	if (!domain->cache.xs_watch_path) {
		rc = -ENOMEM;
		goto out;
	}

	rc = asprintf(&domain->cache.xs_watch_token, "dom%lu", domain->domid);
	if (!domain->cache.xs_watch_token) {
		rc = -ENOMEM;
		goto out;
	}

	rc = xs_watch(xs_handle,
			domain->cache.xs_watch_path,
			domain->cache.xs_watch_token);
	if (rc == false) {
		PERROR("Error xs_watch() rc=%d", rc);
		goto out;
	}
	rc = 0;
out:
	if (rc) {
		if (domain->cache.xs_watch_path)
			free(domain->cache.xs_watch_path);
		if (domain->cache.xs_watch_token)
			free(domain->cache.xs_watch_token);
	}
	return rc;
}

static int unwatch_domain(struct xenclone_domain *domain)
{
	int rc;

	rc = xs_unwatch(xs_handle,
			domain->cache.xs_watch_path,
			domain->cache.xs_watch_token);
	if (rc == false) {
		PERROR("Error xs_unwatch() rc=%d", rc);
		goto out;
	}
	rc = 0;

	free(domain->cache.xs_watch_path);
	free(domain->cache.xs_watch_token);
out:
	return rc;
}

static int destroy_cached_domain(struct xenclone_domain *domain)
{
	int rc;

	DEBUG("Deleting cached parent domid=%lu", domain->domid);

	rc = unwatch_domain(domain);
	if (rc) {
		PERROR("Error unwatch_domain() rc=%d", rc);
		goto out;
	}

	/* remove from cache */
	rc = caching_remove(domain);
	assert(rc == 0);

	rc = xenclone_domain_fini(domain);
	if (rc) {
		PERROR("Error xenclone_domain_fini() rc=%d", rc);
	}
	free(domain);
out:
	return rc;
}

/* used with hashmaps */
static struct hmap_list_node *domain_hmap_list_node(void *arg)
{
	struct xenclone_domain *domain = arg;

	return &domain->parents_map_list_node;
}

/* used with hashmaps */
static int domain_hmap_list_node_destroy(struct hmap_list_node *n)
{
	struct xenclone_domain *domain;
	int rc;

	domain = container_of(n, struct xenclone_domain, parents_map_list_node);
	assert(domain != NULL);
	rc = destroy_cached_domain(domain);
	return rc;
}

static int handle_xs(void)
{
	char **vec;
	unsigned int num;
	unsigned long domid;
	struct xenclone_domain *domain;
	int rc = -1;

	vec = xs_read_watch(xs_handle, &num);
	if (!vec)
		goto out;

	if (sscanf(vec[XS_WATCH_TOKEN], "dom%lu", &domid) == 1) {
		domain = caching_get(domid);
		if (domain) {
			if (!xs_path_exists(XBT_NULL, domain->cache.xs_watch_path)) {
				rc = destroy_cached_domain(domain);
				if (rc) {
					PERROR("Error calling destroy_cached_domain() rc=%d", rc);
					goto out;
				}
			} else
				rc = 0;
		}
	}

out:
	if (vec)
		free(vec);
	return rc;
}

static void *caching_loop(void *arg)
{
	fd_set rfds;
	int xs_fd = xs_fileno(xs_handle);
	long rc = 0;

	DEBUG("caching thread running..");

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

	/*
	 * cache thread waits the deaths of domains
	 */
	while (1) {
		FD_ZERO(&rfds);
		FD_SET(xs_fd, &rfds);

		/* TODO use smth smarter like poll/epoll */
		rc = select(xs_fd + 1, &rfds, NULL, NULL, NULL);
		if (rc < 0) {
			PERROR("Error calling select() rc=%ld, errno=%d", rc, errno);
			goto out;
		}

		if (FD_ISSET(xs_fd, &rfds)) {
			rc = handle_xs();
			if (rc) {
				PERROR("Error calling handle_xs() rc=%ld", rc);
				goto out;
			}
		}
	}

out:
	return (void *) rc;
}

int caching_add(struct xenclone_domain *domain)
{
	int rc;

	if (!domain) {
		rc = -EINVAL;
		goto out;
	}

	if (xenclone_hmap_count(&cached_parents_map) == MAX_PARENTS_NUM) {
		struct xenclone_domain *tmp, *oldest = NULL;
		time_t oldest_timestamp = time(NULL);

		list_for_each_entry(tmp, &cached_parents_map.elemlist, parents_map_list_node.node) {
			if (oldest_timestamp > tmp->cache.timestamp) {
				oldest_timestamp = tmp->cache.timestamp;
				oldest = tmp;
			}
		}
		assert(oldest);

		rc = destroy_cached_domain(oldest);
		if (rc) {
			PERROR("Error calling destroy_cached_domain() rc=%d", rc);
			goto out;
		}
	}

	HMAP_LIST_NODE_INIT(&domain->parents_map_list_node);
	domain->cache.timestamp = time(NULL);

	rc = xenclone_hmap_insert(&cached_parents_map, (void *) domain->domid, domain);
	if (rc) {
		PERROR("Error calling xenclone_hmap_insert() rc=%d", rc);
		goto out;
	}

	rc = watch_domain(domain);
	if (rc) {
		PERROR("Error watch_domain() rc=%d", rc);
		goto out;
	}
out:
	return rc;
}

int caching_remove(struct xenclone_domain *domain)
{
	struct xenclone_domain *tmp;
	int rc;

	tmp = xenclone_hmap_remove(&cached_parents_map, (void*) domain->domid, true);
	if (tmp == domain)
		rc = 0;
	else
		rc = -ESRCH;

	return rc;
}

struct xenclone_domain *caching_get(unsigned long domid)
{
	struct xenclone_domain *domain;

	domain = xenclone_hmap_get(&cached_parents_map, (void *) domid);
	if (domain)
		domain->cache.timestamp = time(NULL);
	return domain;
}

static bool caching_initialized = false;
static pthread_t caching_thread;

int caching_init(void)
{
	int rc;

	rc = xenclone_hmap_init(&cached_parents_map, XENCLONE_KEY_ULONG,
			domain_hmap_list_node);
	if (rc) {
		PERROR("Error calling xenclone_hmap_init() rc=%d", rc);
		goto out;
	}

	rc = pthread_create(&caching_thread, NULL, &caching_loop, NULL);
	if (rc != 0) {
		PERROR("Error calling pthread_create() rc=%d", rc);
		goto out;
	}

	caching_initialized = true;
	out: return rc;
}

int caching_fini(void)
{
	void *thread_res;
	int rc = -1;

	if (!caching_initialized)
		goto out;

	rc = pthread_cancel(caching_thread);
	if (rc != 0) {
		PERROR("Error calling pthread_cancel() rc=%d", rc);
		goto out;
	}

	rc = pthread_join(caching_thread, &thread_res);
	if (rc != 0) {
		PERROR("Error calling pthread_join() rc=%d", rc);
		goto out;
	}
	if (thread_res == PTHREAD_CANCELED)
		INFO("p9fs_fini(): thread was canceled");
	else
		INFO("p9fs_fini(): thread wasn't canceled (shouldn't happen!)");

	rc = xenclone_hmap_fini(&cached_parents_map, domain_hmap_list_node_destroy);
	if (rc) {
		PERROR("Error calling xenclone_hmap_fini() rc=%d", rc);
		goto out;
	}

	caching_initialized = false;

out:
	return rc;
}
