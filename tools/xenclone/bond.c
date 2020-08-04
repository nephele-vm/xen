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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "log.h"
#include "profile.h"
#include "os.h"
#include "vif.h"
#include "bond.h"


static int bond_add_if(const char *bond, const char *vif)
{
	char *cmd;
	int rc = 0;

	asprintf(&cmd, "ip link set %s master %s", vif, bond);
	if (!cmd) {
		rc = -ENOMEM;
		goto out;
	}
	rc = run_cmd(cmd, true);
	if (rc > 0)
		rc = 0;
	free(cmd);
#if 0
	if (rc)
		goto out;

	asprintf(&cmd, "ip link set dev %s up", vif);
	if (!cmd) {
		rc = -ENOMEM;
		goto out;
	}
	rc = run_cmd(cmd, true);
	free(cmd);
	if (rc > 0)
		rc = 0;
#endif
out:
	return rc;
}

#if 0
static int bond_del_if(const char *vif)
{
	char *cmd;
	int rc = 0;

	asprintf(&cmd, "ip link set %s nomaster", vif);
	if (!cmd) {
		rc = -ENOMEM;
		goto out;
	}
	rc = run_cmd(cmd, true);
	if (rc > 0)
		rc = 0;
	free(cmd);
#if 0
	if (rc)
		goto out;

	asprintf(&cmd, "ip link set dev %s down", vif);
	if (!cmd) {
		rc = -ENOMEM;
		goto out;
	}
	rc = run_cmd(cmd, true);
	free(cmd);
	if (rc > 0)
		rc = 0;
#endif
out:
	return rc;
}
#endif

int bond_add_cloned_if(const char *ifname)
{
	struct xenclone_vif *vif;
	struct vif_clone *vif_clone;
	int rc;

	PROFILE_NESTED_TICK(__FUNCTION__);

	DEBUG("%s(%s)", __FUNCTION__, ifname);

	vif = xenclone_vif_get(ifname);
	if (!vif) {
		rc = -ENOENT;
		PERROR("Error calling xenclone_vif_get(%s) rc=%d", ifname, rc);
		goto out;
	}

	vif_clone = xenclone_vif_get_clone(vif, (void *) ifname);
	assert(vif_clone != NULL);

	/* add interface to bond */
	rc = bond_add_if(vif->bridge, ifname);
	if (rc) {
		PERROR("Error calling bond_add_if() rc=%d", rc);
		goto out;
	}

	//TODO arping -c 1 -I vif13.0 10.8.0.2 -s 10.8.0.1

out:
	PROFILE_NESTED_TOCK_MSEC();
	return rc;
}

int bond_del_cloned_if(const char *ifname)
{
	struct xenclone_vif *vif;
	int rc;

	DEBUG("%s(%s)", __FUNCTION__, ifname);

#if 0 /* TODO */
	/* remove the interface from the bond */
	rc = bond_del_if(ifname);
	if (rc) {
		PERROR("Error calling ovs_del_if() rc=%d", rc);
		goto out;
	}
#endif

	vif = xenclone_vif_get(ifname);
	if (!vif) {
		DEBUG("Could not find cloned vif for %s", ifname);
		rc = -EINVAL;
		goto out;
	}
	else
		WARN("Found cloned vif for %s", ifname);

	rc = xenclone_vif_remove_if(vif, ifname);
	if (rc) {
		ERROR("Error calling xenclone_vif_remove_if() rc=%d", rc);
		goto out;
	}

#if 0
	if (!xenclone_vif_has_clones(vif))
		xenclone_vif_destroy(vif);
#endif
out:
	return rc;
}
