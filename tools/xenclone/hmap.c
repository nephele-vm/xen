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

#include <string.h>
#include <errno.h>
#include "log.h"
#include "hmap.h"


static unsigned int string_hash_from_key_fn(void *k)
{
	char *str = k;
	unsigned int hash = 5381;
	char c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + (unsigned int) c;

	return hash;
}

static int string_keys_equal_fn(void *key1, void *key2)
{
	return (0 == strcmp(key1, key2));
}

static unsigned int uint_hash_from_key_fn(void *k)
{
	unsigned long value = (unsigned long) k;
	char *p = (char *) &value;
	unsigned int hash = 5381;
	char c;
	int i;

	for (i = 0; i < sizeof(value); i++) {
		c = *p++;
		hash = ((hash << 5) + hash) + (unsigned int) c;
	}

	return hash;
}

static int ulong_keys_equal_fn(void *key1, void *key2)
{
	return ((unsigned long) key1 == (unsigned long) key2);
}

int xenclone_hmap_init(struct xenclone_hmap *h,
		enum xenclone_key_type t,
		get_hmap_list_node_fn func)
{
	pthread_mutexattr_t mtx_attr;
	int rc;

	switch (t) {
	case XENCLONE_KEY_STRING:
		h->htable = create_hashtable(16,
				string_hash_from_key_fn, string_keys_equal_fn);
		break;
	case XENCLONE_KEY_ULONG:
		h->htable = create_hashtable(16,
				uint_hash_from_key_fn, ulong_keys_equal_fn);
		break;
	default:
		rc = -EINVAL;
		PERROR("Invalid key type %d", t);
		break;
	}

	if (!h->htable) {
		rc = -ENOMEM;
		PERROR("Error calling create_hashtable()");
		goto out;
	}

	/* recursive mutex */
	rc = pthread_mutexattr_init(&mtx_attr);
	assert(rc == 0);
	rc = pthread_mutexattr_settype(&mtx_attr, PTHREAD_MUTEX_RECURSIVE);
	assert(rc == 0);
	rc = pthread_mutex_init(&h->mtx, &mtx_attr);
	assert(rc == 0);

	INIT_LIST_HEAD(&h->elemlist);
	h->get_hash_list_node_func = func;

out:
	return rc;
}

int xenclone_hmap_fini(struct xenclone_hmap *h,
		destroy_node_fn destroy_node_func)
{
	struct hmap_list_node *n;
	int rc = 0, rc2;

	xenclone_hmap_lock(h);

	if (destroy_node_func) {
		/* we use the list especially for destroying elements */
		while ((n = list_top(&h->elemlist, struct hmap_list_node, node)))
			destroy_node_func(n);
	}
	else
		INIT_LIST_HEAD(&h->elemlist);

	if (h->htable) {
		hashtable_destroy(h->htable, 0);
		h->htable = NULL;
	}

	xenclone_hmap_unlock(h);

	rc2 = pthread_mutex_destroy(&h->mtx);
	assert(rc2 == 0);

	return rc;
}

unsigned int xenclone_hmap_count(struct xenclone_hmap *h)
{
	unsigned int count = 0;

	xenclone_hmap_lock(h);
	if (h->htable)
		count = hashtable_count(h->htable);
	xenclone_hmap_unlock(h);

	return count;
}

int xenclone_hmap_insert(struct xenclone_hmap *h,
		void *key, void *value)
{
	struct hmap_list_node *n;
	int rc;

	xenclone_hmap_lock(h);

	if (h->htable) {
		rc = hashtable_insert(h->htable, key, value);
		rc = (rc ? 0 : -1);

		if (rc == 0) {
			n = h->get_hash_list_node_func(value);
			list_del(&n->node);
			list_add_tail(&n->node, &h->elemlist);
		}
	} else
		rc = -1;

	xenclone_hmap_unlock(h);

	return rc;
}

void *xenclone_hmap_remove(struct xenclone_hmap *h,
		void *key, bool remove_from_list)
{
	void *value = NULL;

	xenclone_hmap_lock(h);

	if (h->htable) {
		value = hashtable_remove(h->htable, key);
		if (value && remove_from_list) {
			struct hmap_list_node *n;

			n = h->get_hash_list_node_func(value);
			list_del(&n->node);
		}
	}

	xenclone_hmap_unlock(h);

	return value;
}

void *xenclone_hmap_get(struct xenclone_hmap *h, void *key)
{
	void *value = NULL;

	xenclone_hmap_lock(h);
	if (h->htable)
		value = hashtable_search(h->htable, key);
	xenclone_hmap_unlock(h);

	return value;
}
