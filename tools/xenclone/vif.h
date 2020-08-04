/******************************************************************************
 * vif
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

#ifndef __XENCLONE_VIF_H__
#define __XENCLONE_VIF_H__

#include "hmap.h"


int vif_hotplug_online(const char *xb_path, const char *ifname);
int vif_hotplug_offline(const char *xb_path, const char *ifname);


enum bridge_type {
	BRIDGE_TYPE_NONE,
	BRIDGE_TYPE_LINUX,
	BRIDGE_TYPE_OVS,
	BRIDGE_TYPE_BOND,
};

enum bridge_type script_to_bridge_type(const char *script, const char *bridge);


struct xenclone_vif {
	int id;
	int refcount;
	char *ifname;
	char *mac;
	char *ip;
	char *bridge;
	enum bridge_type bridge_type;
	void *priv;
	struct xenclone_hmap ifname2clone_map;
	struct hmap_list_node ifname2vif_map_list_node;
};

struct vif_clone {
	int id;
	char *ifname; /* owned */
	struct xenclone_vif *parent; /* back pointer */
	struct hmap_list_node ifname2clone_map_list_node;
};

struct xenclone_vif *xenclone_vif_create(int id,
		char *ifname, const char *mac, const char *ip,
		const char *bridge, enum bridge_type bridge_type);
void xenclone_vif_destroy(struct xenclone_vif *vif);

int xenclone_vif_add_clone(struct xenclone_vif *vif, char *ifname);
int xenclone_vif_del_clone(struct xenclone_vif *vif, const char *ifname);
bool xenclone_vif_has_clones(struct xenclone_vif *vif);

int xenclone_vif_remove_if(struct xenclone_vif *vif, const char *ifname);


struct xenclone_vif *xenclone_vif_get(const char *ifname);
struct vif_clone *xenclone_vif_get_clone(struct xenclone_vif *vif,
		const char *ifname);

int xenclone_vifs_init(void);
int xenclone_vifs_fini(void);

#endif /* __XENCLONE_VIF_H__ */
