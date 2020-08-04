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

#ifndef __XENCLONE_CLONE_H__
#define __XENCLONE_CLONE_H__

#include <stdint.h>
#include <time.h>
#include "profile.h"
#include "hmap.h"
#include "xenstore.h"
#include "console.h"
#include "vif.h"

extern unsigned long ring_pages_num;

int cloning_init(void);
int cloning_fini(void);

int handle_cloning(void);

int clone_start_IO_waiting(struct xenclone *clone);
int clone_stop_IO_waiting(unsigned long cloneid);


struct xenclone_domain {
	unsigned long domid;
	unsigned long start_info_mfn;
	struct xenclone_domain *parent;

	unsigned long children_num;
	unsigned long pending_children;//TODO use it

	/* IO */
	struct xs xs;
	struct xs_console_dev console;
	struct xs_network_dev *net_devs;
	unsigned long net_devs_num;
	struct xs_9pfs_dev *p9fs_devs;
	unsigned long p9fs_devs_num;
	struct {
		int network:1;
		int p9fs:1;
	} skip_cloning;

	/* Cache */
	struct {
		time_t timestamp;
		char *xs_watch_path;
		char *xs_watch_token;
	} cache;

	struct hmap_list_node parents_map_list_node;
};

int xenclone_domain_fini(struct xenclone_domain *domain);


struct xenclone {//TODO cloning
	uint32_t id;
	struct xenclone_domain *parent;
	struct xenclone_domain domain;
	pthread_mutex_t mtx;
	int pending_devices;
	bool wait_IO_completion;
	struct hmap_list_node node;
#if XENCLONED_PROFILING
	struct profile profile;
#endif
};

static inline void xenclone_lock(struct xenclone *clone)
{
	assert(pthread_mutex_lock(&clone->mtx) == 0);
}

static inline void xenclone_unlock(struct xenclone *clone)
{
	assert(pthread_mutex_unlock(&clone->mtx) == 0);
}



#if 0
struct clone_family {
	int id;

	struct xenclone_vif vif;//TODO hashmap
};
#endif

#endif /* __XENCLONE_CLONE_H__ */
