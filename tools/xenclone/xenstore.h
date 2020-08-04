/******************************************************************************
 * xs cloning definitions
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

#ifndef __XENCLONE_XENSTORE_H__
#define __XENCLONE_XENSTORE_H__

#include <xen/xen.h>
#include "xs.h"

struct xenclone;

struct xs {
	unsigned long mfn;
	unsigned long port;
	char *name;
	char *libxl_type;
	char *libxl_dm_version;
	struct xs_path path_local;
	struct xs_path path_libxl;
	struct xs_path path_data;
	struct xs_path path_shutdown;
	struct xs_path path_name;
	struct xs_path path_domid;
	struct xs_path path_store;
};

int xs_init(struct xs *xs, domid_t domid, unsigned long mfn, bool is_parent);
int xs_fini(struct xs *xs);

int xenstore_clone(struct xenclone *clone);

#endif /* __XENCLONE_XENSTORE_H__ */
