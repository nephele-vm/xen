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

#ifndef __XENCLONE_QEMU_H__
#define __XENCLONE_QEMU_H__

#include "hmap.h"

struct qmp {
	int ref;
	int fd;
	int hello_sent;
	unsigned long parent_domid;
	pthread_mutex_t mtx;
	struct hmap_list_node map_fd_list_node;
	struct hmap_list_node map_parentid_list_node;
};

struct qmp *qmp_create(unsigned long parent_domid);
int qmp_destroy(struct qmp *qmp);
void qmp_get(struct qmp *qmp);
void qmp_put(struct qmp *qmp);
int qmp_announce_clone(struct qmp *qmp,
		unsigned long domid, unsigned long parentid);

#endif /* __XENCLONE_QEMU_H__ */
