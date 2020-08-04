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

#ifndef __XENCLONE_9PFS_H__
#define __XENCLONE_9PFS_H__

#include <stdint.h>
#include <stdbool.h>
#include <xen/grant_table.h>
#include <xen/event_channel.h>
#include "xs.h"

struct xenclone;
struct qmp;

struct xen_ring {
	grant_ref_t ring_ref;
	evtchn_port_t evtchn;
};

struct xs_9pfsfront {
	struct xs_path path;
	struct xs_path backend_path;
	char *backend_dom_path;
	int backend_id;
	int state;
	char *tag;
	int version;
	int num_rings;
	struct xen_ring *rings;
};

struct xs_9pfsback {
	const struct xs_path *path;
	const struct xs_path *frontend_path;
	int frontend_id;
	int online;
	int state;
	char *host_fs_path;
	char *security_model;
	char *versions;
	int max_rings;
	int max_ring_page_order;
	char *hotplug_status;
};

struct xs_9pfs_dev {
	struct xenclone_domain *domain; /* back pointer */
	bool skip;
	struct xs_9pfsfront front;
	struct xs_9pfsback back;
};

int p9fs_devices_init(struct xenclone_domain *domain);
int p9fs_devices_fini(struct xenclone_domain *domain);
int p9fs_devices_clone(struct xenclone *clone);
int p9fs_remove_qmp(struct qmp *qmp);

int p9fs_init(void);
int p9fs_fini(void);

#endif /* __XENCLONE_9PFS_H__ */
