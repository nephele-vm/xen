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

#ifndef __XENCLONE_CONSOLE_H__
#define __XENCLONE_CONSOLE_H__

#include <xen/event_channel.h>

struct xs_consfront {
	struct xs_path path;
	struct xs_path backend_path;
	char *backend_dom_path;
	int backend_id;
	int limit;
	char *type;
	char *output;
	evtchn_port_t port;
	unsigned long ring_ref;
};

struct xs_consback {
	const struct xs_path *path;
	const struct xs_path *frontend_path;
	int frontend_id;
	int online;
	int state;
	char *protocol;
};

struct xenclone_domain;

struct xs_console_dev {
	struct xenclone_domain *domain; /* back pointer */
	unsigned long mfn;
	struct xs_consfront front;
	struct xs_consback back;
};


int console_init_parent(struct xenclone_domain *domain);
int console_fini(struct xenclone_domain *domain);
int console_clone(struct xenclone *clone);

#endif /* __XENCLONE_CONSOLE_H__ */
