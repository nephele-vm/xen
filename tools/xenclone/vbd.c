/******************************************************************************
 * vbd
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "xencloned.h"
#include "xs.h"
#include "vbd.h"


int vbd_hotplug_online(const char *xb_path)
{
	char *device = NULL, *type = NULL, *dev_id_str = NULL, *errmsg = NULL;
	struct stat st;
	int rc;

	rc = xs_read_kv(XBT_NULL, xb_path, "type", &type);
	if (!rc)
		goto out_err;

	if (strcmp(type, "phy") != 0) {
		asprintf(&errmsg, "%s type not supported.", type);
		goto out_err;
	}

	rc = xs_read_kv(XBT_NULL, xb_path, "params", &device);
	if (!rc)
		goto out;

	rc = stat(device, &st);
	if (rc) {
		if (errno == ENOENT)
			asprintf(&errmsg, "%s does not exist.", device);
		else
			asprintf(&errmsg, "stat(%s) returned %d.", device, errno);
		goto out_err;
	}

	/* FIXME: Check if dev is block device */
	if (!S_ISBLK(st.st_mode)) {
		asprintf(&errmsg, "%s is not a block device.", device);
		goto out_err;
	}

	/* FIXME: Check device sharing */

	asprintf(&dev_id_str, "%x:%x", major(st.st_rdev), minor(st.st_rdev));//TODO check
	rc = xs_write_kv(XBT_NULL, NULL, xb_path, "physical-device", dev_id_str);
	free(dev_id_str);

	goto out;

out_err:
	xs_write_kv(XBT_NULL, NULL, xb_path, "hotplug-error", errmsg);
	free(errmsg);
	xs_write_kv(XBT_NULL, NULL, xb_path, "hotplug-status",  "error");

out:
	if (device)
		free(device);
	if (type)
		free(type);
	return 0;
}


