/******************************************************************************
 * hashmap
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

#ifndef __XENCLONE_HMAP_H__
#define __XENCLONE_HMAP_H__

#include <stdbool.h>
#include <pthread.h>
#include <hashtable.h>
#include <list.h>
#include <assert.h>


struct hmap_list_node {
	struct list_head node;
};

#define HMAP_LIST_NODE_INIT(ptr) \
	INIT_LIST_HEAD(&(ptr)->node);

typedef struct hmap_list_node *(*get_hmap_list_node_fn)(void *arg);

struct xenclone_hmap
{
	struct hashtable *htable;
	pthread_mutex_t mtx;
	struct list_head elemlist;
	get_hmap_list_node_fn get_hash_list_node_func;
};

enum xenclone_key_type
{
	XENCLONE_KEY_NONE,
	XENCLONE_KEY_STRING,
	XENCLONE_KEY_ULONG,
};

int xenclone_hmap_init(struct xenclone_hmap *h,
		enum xenclone_key_type t,
		get_hmap_list_node_fn func);

typedef int (*destroy_node_fn)(struct hmap_list_node *n);

int xenclone_hmap_fini(struct xenclone_hmap *h,
		destroy_node_fn destroy_node_func);


static inline void xenclone_hmap_lock(struct xenclone_hmap *h)
{
	assert(pthread_mutex_lock(&h->mtx) == 0);
}

static inline void xenclone_hmap_unlock(struct xenclone_hmap *h)
{
	assert(pthread_mutex_unlock(&h->mtx) == 0);
}


unsigned int xenclone_hmap_count(struct xenclone_hmap *h);

int xenclone_hmap_insert(struct xenclone_hmap *h,
		void *key, void *value);
void *xenclone_hmap_remove(struct xenclone_hmap *h,
		void *key, bool remove_from_list);

void *xenclone_hmap_get(struct xenclone_hmap *h, void *key);

#endif /* __XENCLONE_HMAP_H__ */
