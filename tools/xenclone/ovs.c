/******************************************************************************
 * ovs functions
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
#define OVS_RUN_ONLY_AS_COMMAND
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>
#include <command-line.h>
#ifndef OVS_RUN_ONLY_AS_COMMAND
#include <ovs-ctl.h>
#endif
#include "log.h"
#include "profile.h"
#include "utils.h"
#include "os.h"
#include "vif.h"
#include "ovs.h"

#ifdef OVS_RUN_ONLY_AS_COMMAND
#define ofctl_add_group      NULL
#define ofctl_del_groups     NULL
#define ofctl_insert_bucket  NULL
#define ofctl_remove_bucket  NULL
#define ofctl_add_group      NULL
#define ofctl_add_flow       NULL
#endif

enum ovs_instantiation_type {
#ifndef OVS_RUN_ONLY_AS_COMMAND
	OVS_LIBRARY,
#endif
	OVS_COMMAND
};

static enum ovs_instantiation_type ovs_instantiation =
#ifndef OVS_RUN_ONLY_AS_COMMAND
		OVS_LIBRARY
#else
		OVS_COMMAND
#endif
;

int ovs_set_instantiation_type(const char *type)
{
	int rc = 0;

	if (!strcmp(type, "command"))
		ovs_instantiation = OVS_COMMAND;
#ifndef OVS_RUN_ONLY_AS_COMMAND
	else if (!strcmp(type, "library"))
		ovs_instantiation = OVS_LIBRARY;
#endif
	else {
		ERROR("OVS instantiation type not supported: %s\n", type);
		rc = -EINVAL;
	}

	return rc;
}

enum ovs_utility_type {
	OVS_VSCTL,
	OVS_OFCTL,
};

static int ovs_cmd_exec(char *cmd, enum ovs_utility_type utility_type)
{
	char *cmd0;
	int rc = 0;

	switch (utility_type) {
	case OVS_VSCTL:
		rc = run_cmd(cmd, true);
		if (rc > 0)
			rc = 0;
		break;
	case OVS_OFCTL: {
		asprintf(&cmd0, "ovs-ofctl %s", cmd);
		if (!cmd0) {
			rc = -ENOMEM;
			goto out;
		}
		rc = run_cmd(cmd0, true);
		if (rc > 0)
			rc = 0;
		free(cmd0);
		break;
	}
	default:
		assert(1);
		break;
	}
out:
	return rc;
}

typedef void (*ovs_cmd_func_t)(struct ovs_cmdl_context *ctx);

#ifndef OVS_RUN_ONLY_AS_COMMAND
static int ovs_cmd_lib(char *cmd, enum ovs_utility_type utility_type,
		ovs_cmd_func_t ovs_cmd_func)
{
	char **argv;
	int argc, rc = 0;

	argc = tokenize(cmd, &argv);
	if (argc < 0) {
		rc = -1;
		goto out;
	}

	switch (utility_type) {
	case OVS_VSCTL:
		rc = ovs_vsctl_run_command(argc, argv);
		break;
	case OVS_OFCTL: {
		struct ovs_cmdl_context ctx;

		ctx.argc = argc;
		ctx.argv = argv;
		ovs_cmd_func(&ctx);
		break;
	}
	default:
		assert(1);
		break;
	}

	free(argv);
out:
	return rc;
}
#endif


static int ovs_cmd(enum ovs_utility_type utility_type,
		ovs_cmd_func_t ovs_cmd_func, const char *fmt, ...)
{
	va_list ap;
	int rc;
	char *cmd;

	va_start(ap, fmt);
	rc = vasprintf(&cmd, fmt, ap);
	va_end(ap);
	if (rc < 0)
		goto out;
	else
		rc = 0;

	DEBUG("%s", cmd);

#ifndef OVS_RUN_ONLY_AS_COMMAND
	if (ovs_instantiation == OVS_LIBRARY)
		rc = ovs_cmd_lib(cmd, utility_type, ovs_cmd_func);
	else
#endif
		rc = ovs_cmd_exec(cmd, utility_type);

	free(cmd);
out:
	return rc;
}

static int ovs_add_if(const char *bridge, const char *netif,
	const char *vm_name, const char *vm_uuid, const char *vm_mac)
{
	return ovs_cmd(OVS_VSCTL, NULL, "ovs-vsctl "
		"--timeout=300000 -- "
		"--if-exists del-port %s -- "
		"add-port %s %s -- "
		"set interface %s external-ids:\"xen-vm-name\"=\"%s\" -- "
		"set interface %s external-ids:\"xen-vm-uuid\"=\"%s\" -- "
		"set interface %s external-ids:\"attached-mac\"=\"%s\"",
		netif, bridge, netif, netif, vm_name, netif, vm_uuid, netif, vm_mac);
}

static int ovs_del_if(const char *netif)
{
	return ovs_cmd(OVS_VSCTL, NULL, "ovs-vsctl "
		"--timeout=30 -- "
		"--if-exists del-port %s",
		netif);
}

static const char *selection_method = NULL;

int ovs_set_selection_method(const char *name)
{
	int rc = 0;

	if (!strcmp(name, "dp_hash"))
		selection_method = "selection_method=dp_hash";

	else if (!strcmp(name, "hash"))
		selection_method = "selection_method=hash,fields(ip_src,ip_dst,tcp_src,tcp_dst)";

	else if (!strcmp(name, "round-robin"))
		selection_method = "selection_method=round-robin,fields(ip_src,ip_dst,tcp_src,tcp_dst)";

	else {
		ERROR("Selection method not supported: %s\n", name);
		rc = -ENOTSUP;
	}

	return rc;
}

static int ovs_add_group(char *bridge, int id,
	const char *mac, const char *ip_str,
	const char *vif1, const char *vif2)
{
	int rc;

	if (!selection_method)
		ovs_set_selection_method("hash");

	rc = ovs_cmd(OVS_OFCTL, ofctl_add_group,
		"add-group %s group_id=%d,type=select,%s,bucket=output:%s,bucket=output:%s",
		bridge, id, selection_method, vif1, vif2);
	if (rc) {
		PERROR("Error adding group rc=%d\n", rc);
		goto out;
	}

	rc = ovs_cmd(OVS_OFCTL, ofctl_add_flow,
		"add-flow %s in_port=local,dl_type=0x0800,nw_dst=%s,actions=group:%d",
		bridge, ip_str, id);
	if (rc) {
		PERROR("Error adding flow rc=%d\n", rc);
		goto out;
	}

out:
	return rc;
}

static int ovs_del_group(const char *bridge, int id)
{
	int rc;

	rc = ovs_cmd(OVS_OFCTL, ofctl_del_groups, "del-groups %s group_id=%d", bridge, id);
	if (rc) {
		PERROR("Error deleting group rc=%d\n", rc);
		goto out;
	}

out:
	return rc;
}

static int ovs_add_bucket(const char *bridge, int group_id, const char *vif, int bucket_id)
{
	int rc;

	/*
	 * Vanilla ovs does not support setting select type on bucket.
	 * However this is a bug because without it ovs will set the
	 * weight to 0 for the new bucket.
	 */
	rc = ovs_cmd(OVS_OFCTL, ofctl_insert_bucket,
		"insert-buckets %s group_id=%d,type=select,command_bucket_id=last,bucket=bucket_id=%d,actions=output:%s",
		bridge, group_id, bucket_id, vif);
	if (rc) {
		PERROR("Error adding bucked rc=%d\n", rc);
		goto out;
	}

out:
	return rc;
}

static int ovs_del_bucket(const char *bridge, int group_id, int bucket_id)
{
	return ovs_cmd(OVS_OFCTL, ofctl_remove_bucket,
		"remove-buckets %s group_id=%d,command_bucket_id=%d",
		bridge, group_id, bucket_id);
}

int ovs_add_cloned_if(const char *ifname, const char *vm_name, const char *vm_uuid)
{
	struct xenclone_vif *vif;
	bool *group_created;
	int rc;

	PROFILE_NESTED_TICK(__FUNCTION__);

	vif = xenclone_vif_get(ifname);
	if (!vif) {
		rc = -ENOENT;
		PERROR("Error calling xenclone_vif_get(%s) rc=%d", ifname, rc);
		goto out;
	}

	/* add interface to switch */
	rc = ovs_add_if(vif->bridge, ifname, vm_name, vm_uuid, vif->mac);
	if (rc) {
		PERROR("Error calling ovs_add_if() rc=%d", rc);
		goto out;
	}

	/* TODO priv must have different semantics for each bridge type */
	/* enable the group bucket */
	group_created = (bool *) &vif->priv;
	if (*group_created == false) {
		rc = ovs_add_group(vif->bridge, vif->id,
				vif->mac, vif->ip,
				vif->ifname, ifname);
		if (rc) {
			PERROR("Error calling ovs_add_group() rc=%d", rc);
			goto out;
		}

		*group_created = true;

	} else {
		struct vif_clone *vif_clone;

		vif_clone = xenclone_vif_get_clone(vif, (void *) ifname);
		assert(vif_clone != NULL);

		rc = ovs_add_bucket(vif->bridge, vif->id, ifname, vif_clone->id);
		if (rc) {
			PERROR("Error calling ovs_add_bucket() rc=%d", rc);
			goto out;
		}
	}

out:
	PROFILE_NESTED_TOCK_MSEC();
	return rc;
}

int ovs_del_cloned_if(const char *ifname)
{
	struct xenclone_vif *vif;
	struct vif_clone *vif_clone;
	int rc;

	/* remove the interface from the switch */
	rc = ovs_del_if(ifname);
	if (rc) {
		PERROR("Error calling ovs_del_if() rc=%d", rc);
		goto out;
	}

	vif = xenclone_vif_get(ifname);
	if (!vif) {
		ERROR("Could not find cloned vif for %s", ifname);
		goto out;
	}

	vif_clone = xenclone_vif_get_clone(vif, ifname);
	if (!vif_clone) {
		ERROR("Could not find clone for vif %s", ifname);
		goto out;
	}

	rc = ovs_del_bucket(vif->bridge, vif->id, vif_clone->id);
	if (rc) {
		PERROR("Error calling ovs_del_bucket() rc=%d", rc);
		goto out;
	}

	rc = xenclone_vif_remove_if(vif, ifname);
	if (rc) {
		PERROR("Error calling xenclone_vif_remove_if() rc=%d", rc);
		goto out;
	}

	if (!xenclone_vif_has_clones(vif)) {
		rc = ovs_del_group(vif->bridge, vif->id);
		if (rc) {
			PERROR("Error calling ovs_del_group() rc=%d", rc);
			goto out;
		}
#if 0
		xenclone_vif_destroy(vif);
#endif
	}

out:
	return rc;
}

//TODO serialize

int ovs_init(void)
{
	int rc = 0;

#ifndef OVS_RUN_ONLY_AS_COMMAND
	rc = ovs_vsctl_init();
	if (rc) {
		PERROR("Error calling ovs_vsctl_init() rc=%d", rc);
		goto out;
	}

	rc = ovs_ofctl_init();
	if (rc) {
		PERROR("Error calling ovs_ofctl_init() rc=%d", rc);
		goto out;
	}

out:
#endif
	return rc;
}

int ovs_fini(void)
{
	int rc = 0;

#ifndef OVS_RUN_ONLY_AS_COMMAND
	rc = ovs_ofctl_fini();
#endif

	return rc;
}
