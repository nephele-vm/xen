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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include "log.h"
#include "hmap.h"
#include "xencloned.h"
#include "clone.h"
#include "xs.h"
#include "ovs.h"
#include "bond.h"
#include "netif.h"
#include "vif.h"


#define SCRIPT_PATH_BRIDGE   "/etc/xen/scripts/vif-bridge"
#define SCRIPT_PATH_OVS      "/etc/xen/scripts/vif-openvswitch"


static int bridge_type_from_uevent(const char *bridge,
		enum bridge_type *bridge_type)
{
	FILE *f;
	char *path = NULL, *line = NULL;
	size_t len = 0;
	int rc = 0;

	asprintf(&path, "/sys/class/net/%s/uevent", bridge);
	if (!path) {
		PERROR("Error allocating file path");
		rc = -ENOMEM;
		goto out;
	}
	rc = access(path, F_OK);
	if (rc) {
		PERROR("File does not exist: %s", path);
		rc = -ENOENT;
		goto out;
	}

	f = fopen(path, "r");
	if (f == NULL) {
		rc = -errno;
		goto out;
	}

	while (getline(&line, &len, f) != -1) {
		if (strstr(line, "DEVTYPE=") == line) {
			const char *type = line + strlen("DEVTYPE=");

			if (!strcmp(type, "bond\n"))
				*bridge_type = BRIDGE_TYPE_BOND;
			else if (!strcmp(type, "bridge\n"))
				*bridge_type = BRIDGE_TYPE_LINUX;
			else
				rc = -EINVAL;
			break;
		}
	}
	if (line)
		free(line);
	fclose(f);
out:
	if (path)
		free(path);
	return rc;
}

enum bridge_type script_to_bridge_type(const char *script, const char *bridge)
{
	enum bridge_type bridge_type = BRIDGE_TYPE_NONE;
	int rc;

	if (!strcmp(script, SCRIPT_PATH_BRIDGE)) {
		rc = bridge_type_from_uevent(bridge, &bridge_type);
		if (rc)
			PERROR("Error getting bridge type from uevent rc=%d", rc);

	} else if (!strcmp(script, SCRIPT_PATH_OVS))
		bridge_type = BRIDGE_TYPE_OVS;
	else
		PERROR("Unknown script: %s", script);

	return bridge_type;
}

static enum bridge_type vif_to_bridge_type(const char *ifname,
		const char *xb_path)
{
	enum bridge_type bridge_type = BRIDGE_TYPE_NONE;
	struct xenclone_vif *vif;
	char *bridge = NULL, *script = NULL;
	int rc;

	vif = xenclone_vif_get(ifname);
	if (vif) {
		/*DEBUG("bridge=%s vif=%s", vif->bridge, ifname);*/
		bridge_type = vif->bridge_type;

	} else {
		/* maybe we can infer from Xenstore */
		rc = xs_read_kv(XBT_NULL, xb_path, "bridge", &bridge);
		if (rc)
			goto out;

		rc = xs_read_kv(XBT_NULL, xb_path, "script", &script);
		if (rc) {
			PERROR("Unable to read script value from xenstore");
			goto out;
		}
		/*DEBUG("bridge=%s vif=%s", bridge, ifname);*/
		bridge_type = script_to_bridge_type(script, bridge);
	}

out:
	if (script)
		free(script);
	if (bridge)
		free(bridge);

	return bridge_type;
}


int vif_hotplug_online(const char *xb_path, const char *ifname)
{
	enum bridge_type bridge_type;
	char *error_str;
	int cloneid, rc;

	bridge_type = vif_to_bridge_type(ifname, xb_path);
	switch (bridge_type) {
	case BRIDGE_TYPE_LINUX:
		rc = -ENOTSUP;
		PERROR("Linux bridge not supported for %s", ifname);
		goto out_err;
		break;

	case BRIDGE_TYPE_OVS: {
		char *vm_path = NULL, *vm_name = NULL;//TODO optimization: we should allocate this only once

		rc = xs_scanf_kv(XBT_NULL, xb_path, "frontend-id", "%d", &cloneid);
		if (rc) {
			PERROR("Error reading frontend id");
			goto out_free_ovs;
		}

		rc = asprintf(&vm_path, "/local/domain/%d", cloneid);
		if (rc == -1) {
			PERROR("Error reading vm path");
			goto out_free_ovs;
		}

		rc = xs_read_kv(XBT_NULL, vm_path, "name", &vm_name);
		if (rc) {
			PERROR("Error reading vm name");
			goto out_free_ovs;
		}

		rc = ovs_add_cloned_if(ifname, vm_name, NULL);

out_free_ovs:
		if (vm_name)
			free(vm_name);
		if (vm_path)
			free(vm_path);
		if (rc) {
			PERROR("Error calling ovs_add_if() rc=%d", rc);
			goto out_err;
		}
	}
		break;

	case BRIDGE_TYPE_BOND: {
		char *vm_path = NULL;

		rc = xs_scanf_kv(XBT_NULL, xb_path, "frontend-id", "%d", &cloneid);
		if (rc) {
			PERROR("Error reading frontend id");
			goto out_free_bond;
		}

		rc = asprintf(&vm_path, "/local/domain/%d", cloneid);
		if (rc == -1) {
			PERROR("Error reading vm path");
			goto out_free_bond;
		}

		rc = bond_add_cloned_if(ifname);

out_free_bond:
		if (vm_path)
			free(vm_path);
		if (rc) {
			PERROR("Error calling bond_add_cloned_if() rc=%d", rc);
			goto out_err;
		}
	}
		break;

	default:
		rc = -EINVAL;
		goto out_err;
	}

	rc = netif_up(ifname);
	if (rc) {
		PERROR("Error calling netif_up() rc=%d", rc);
		goto out_err;
	}

	rc = xs_write_kv(XBT_NULL, NULL, xb_path, "hotplug-status", "connected");
	if (rc) {
		PERROR("Error calling xs_write_kv() rc=%d", rc);
		goto out_err;
	}

	rc = clone_stop_IO_waiting(cloneid);
	if (rc) {
		PERROR("Error calling clone_io_done() rc=%d", rc);
		goto out_err;
	}

out_err:
	if (rc) {
		/* prepare error message */
		asprintf(&error_str, "xencloned error: %s: rc=%d errno=%d (%s)\n",
				__func__, rc, errno, strerror(errno));
		/* write it to Xenstore */
		xs_write_kv(XBT_NULL, NULL, xb_path, "hotplug-error", error_str);
		free(error_str);
		/* set the error in Xenstore */
		xs_write_kv(XBT_NULL, NULL, xb_path, "hotplug-status", "error");
	}

	return rc;
}

int vif_hotplug_offline(const char *xb_path, const char *ifname)
{
	enum bridge_type bridge_type;
	int rc;

	bridge_type = vif_to_bridge_type(ifname, xb_path);
	switch (bridge_type) {
	case BRIDGE_TYPE_LINUX:
		rc = -ENOTSUP;
		PERROR("Linux bridge not supported for %s", ifname);
		goto out;
		break;

	case BRIDGE_TYPE_OVS:
		rc = netif_down(ifname);
		if (rc)
			goto out;
		rc = ovs_del_cloned_if(ifname);
		break;

	case BRIDGE_TYPE_BOND:
		rc = bond_del_cloned_if(ifname);
		break;

	default:
		rc = -EINVAL;
		goto out;
	}

out:
	return rc;
}


static struct xenclone_hmap ifname2vif_map;

static struct hmap_list_node *xenclone_vif_to_hmap_list_node(void *arg);
static int hmap_list_node_destroy_xenclone_vif(struct hmap_list_node *n);

static int ifname2vif_map_init(void)
{
	int rc = 0;

	rc = xenclone_hmap_init(&ifname2vif_map, XENCLONE_KEY_STRING,
			xenclone_vif_to_hmap_list_node);
	if (rc) {
		PERROR("Error calling xenclone_hmap_init() rc=%d", rc);
		goto out;
	}

out:
	return rc;
}

static int ifname2vif_map_fini(void)
{
	int rc;

	rc = xenclone_hmap_fini(&ifname2vif_map,
			hmap_list_node_destroy_xenclone_vif);
	if (rc) {
		PERROR("Error calling xenclone_hmap_fini() rc=%d", rc);
		goto out;
	}

out:
	return rc;
}

struct xenclone_vif *ifname2vif_map_get(const char *ifname)
{
	return xenclone_hmap_get(&ifname2vif_map, (void *) ifname);
}

static int ifname2vif_map_add(char *ifname, struct xenclone_vif *vif)
{
	int rc;

	rc = xenclone_hmap_insert(&ifname2vif_map, ifname, vif);
	if (rc) {
		PERROR("Error calling xenclone_hmap_insert() rc=%d", rc);
		goto out;
	}
	vif->refcount++;

out:
	return rc;
}

static int ifname2vif_map_remove(const char *ifname, struct xenclone_vif *vif)
{
	struct xenclone_vif *tmp;
	bool remove_from_list = (vif->refcount == 1 ? true : false);
	int rc = 0;

	/* remove from the vifs map */
	tmp = xenclone_hmap_remove(&ifname2vif_map, (void *) ifname,
			remove_from_list);
	if (tmp) {
		if (tmp != vif) {
			//TODO put it back?
			rc = -EINVAL;
			goto out;
		}

		vif->refcount--;
	}

out:
	return rc;
}


struct vif_clone *vif_clone_create(int id, char *ifname)
{
	struct vif_clone *vif_clone;

	/* create clone */
	vif_clone = malloc(sizeof(*vif_clone));
	if (!vif_clone) {
		PERROR("Error calling malloc()");
		goto out;
	}
	vif_clone->id = id;
	vif_clone->ifname = ifname;
	vif_clone->parent = NULL;
	HMAP_LIST_NODE_INIT(&vif_clone->ifname2clone_map_list_node);

out:
	return vif_clone;
}

void vif_clone_destroy(struct vif_clone *vif_clone)
{
	if (!vif_clone)
		return;

	if (vif_clone->ifname)
		free(vif_clone->ifname);

	free(vif_clone);
}

static struct hmap_list_node *vif_clone_to_hmap_list_node(void *arg)
{
	struct vif_clone *vif_clone = arg;

	return &vif_clone->ifname2clone_map_list_node;
}

static int hmap_list_node_destroy_vif_clone(struct hmap_list_node *n)
{
	struct vif_clone *vif_clone;
	int rc;

	vif_clone = container_of(n, struct vif_clone, ifname2clone_map_list_node);
	assert(vif_clone != NULL);

	rc = xenclone_vif_del_clone(vif_clone->parent, vif_clone->ifname);

	return rc;
}

struct xenclone_vif *xenclone_vif_create(int id,
		char *ifname, const char *mac, const char *ip,
		const char *bridge, enum bridge_type bridge_type)
{
	struct xenclone_vif *vif;
	char *p;
	int n, rc;

	vif = malloc(sizeof(*vif));
	if (!vif) {
		PERROR("Error calling malloc()");
		rc = -ENOMEM;
		goto out;
	}

	vif->id = id;
	vif->refcount = 0;
	vif->ifname = ifname;
	vif->mac = strdup(mac);
	if (!vif->mac) {
		PERROR("Error calling strdup()");
		rc = -ENOMEM;
		goto out;
	}

	p = strchr(ip, ' ');
	n = p ? (p - ip) : strlen(ip);
	vif->ip = strndup(ip, n);
	if (!vif->ip) {
		PERROR("Error calling strdup()");
		rc = -ENOMEM;
		goto out;
	}

	vif->bridge = strdup(bridge);
	if (!vif->bridge) {
		PERROR("Error calling strdup()");
		rc = -ENOMEM;
		goto out;
	}
	vif->bridge_type = bridge_type;

	*((bool *) &vif->priv) = false;

	rc = xenclone_hmap_init(&vif->ifname2clone_map, XENCLONE_KEY_STRING,
			vif_clone_to_hmap_list_node);
	if (rc) {
		PERROR("Error calling xenclone_hmap_init() rc=%d", rc);
		goto out;
	}

	HMAP_LIST_NODE_INIT(&vif->ifname2vif_map_list_node);

	rc = ifname2vif_map_add(ifname, vif);
	if (rc) {
		PERROR("Error calling ifname2vif_map_add() rc=%d", rc);
		xenclone_hmap_fini(&vif->ifname2clone_map, NULL);
		goto out;
	}

out:
	if (rc) {
		/* error handling */
		if (vif->bridge)
			free(vif->bridge);
		if (vif->mac)
			free(vif->mac);
		if (vif->ip)
			free(vif->ip);
		if (vif) {
			free(vif);
			vif = NULL;
		}
	}

	return vif;
}

static int xenclone_vif_destroy_clones(struct xenclone_vif *vif);

void xenclone_vif_destroy(struct xenclone_vif *vif)
{
	int rc;

	assert(vif != NULL);

	rc = xenclone_vif_destroy_clones(vif);
	assert(rc == 0);

	ifname2vif_map_remove(vif->ifname, vif);

	free(vif->ifname);
	free(vif->bridge);
	free(vif->mac);
	free(vif->ip);
	free(vif);
}

/* used with hashmaps */
static struct hmap_list_node *xenclone_vif_to_hmap_list_node(void *arg)
{
	struct xenclone_vif *vif = arg;

	return &vif->ifname2vif_map_list_node;
}

/* used with hashmaps */
static int hmap_list_node_destroy_xenclone_vif(struct hmap_list_node *n)
{
	struct xenclone_vif *vif;

	vif = container_of(n, struct xenclone_vif, ifname2vif_map_list_node);
	assert(vif != NULL);

	xenclone_vif_destroy(vif);

	return 0;
}

int xenclone_vif_add_clone(struct xenclone_vif *vif, char *ifname)
{
	struct vif_clone *vif_clone;
	int id, rc = -1;

	id = xenclone_hmap_count(&vif->ifname2clone_map) + 1;/* TODO fix id */

	vif_clone = vif_clone_create(id, ifname);
	if (!vif_clone) {
		PERROR("Error calling vif_clone_create()");
		goto out;
	}

	rc = xenclone_hmap_insert(&vif->ifname2clone_map, ifname, vif_clone);
	if (rc) {
		PERROR("Error calling xenclone_hmap_insert() rc=%d", rc);
		goto out;
	}

	vif_clone->parent = vif;

	rc = ifname2vif_map_add(ifname, vif);
	if (rc) {
		PERROR("Error calling ifname2vif_map_add() rc=%d", rc);
		xenclone_hmap_remove(&vif->ifname2clone_map, ifname, true);
		goto out;
	}

out:
	if (rc)
		vif_clone_destroy(vif_clone);

	return rc;
}

int xenclone_vif_del_clone(struct xenclone_vif *vif, const char *ifname)
{
	struct vif_clone *vif_clone;
	int rc = 0;

	/* remove from the vifs map */
	rc = ifname2vif_map_remove(ifname, vif);
	if (rc) {
		PERROR("Error calling ifname2vif_map_remove() rc=%d", rc);
		goto out;
	}

	/* remove from the map of clones */
	vif_clone = xenclone_hmap_remove(&vif->ifname2clone_map,
			(void *) ifname, true);
	assert(vif_clone != NULL);

	vif_clone_destroy(vif_clone);

out:
	return rc;
}

static int xenclone_vif_destroy_clones(struct xenclone_vif *vif)
{
	return xenclone_hmap_fini(&vif->ifname2clone_map,
			hmap_list_node_destroy_vif_clone);
}

bool xenclone_vif_has_clones(struct xenclone_vif *vif)
{
	return (xenclone_hmap_count(&vif->ifname2clone_map) > 0);
}

int xenclone_vif_remove_if(struct xenclone_vif *vif, const char *ifname)
{
	int rc;

	DEBUG("%s(%s)", __FUNCTION__, ifname);

	if (!strcmp(vif->ifname, ifname)) {
		/* it's the parent vif */
		/* remove from the vifs map */
		rc = ifname2vif_map_remove(ifname, vif);
		if (rc) {
			PERROR("Error calling ifname2vif_map_remove() rc=%d", rc);
			goto out;
		}

	} else
		rc = xenclone_vif_del_clone(vif, ifname);

out:
	return rc;
}

struct xenclone_vif *xenclone_vif_get(const char *ifname)
{
	return ifname2vif_map_get(ifname);
}

struct vif_clone *xenclone_vif_get_clone(struct xenclone_vif *vif,
		const char *ifname)
{
	return xenclone_hmap_get(&vif->ifname2clone_map, (void *) ifname);
}

int xenclone_vifs_init(void)
{
	int rc;

	rc = ifname2vif_map_init();
	if (rc) {
		PERROR("Error calling ifname2vif_map_init() rc=%d", rc);
		goto out;
	}

out:
	return rc;
}

int xenclone_vifs_fini(void)
{
	int rc;

	rc = ifname2vif_map_fini();
	if (rc) {
		PERROR("Error calling ifname2vif_map_fini() rc=%d", rc);
		goto out;
	}

out:
	return rc;
}
