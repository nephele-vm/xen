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

#include <string.h>
#include <sys/mman.h>
#include <xengnttab.h>
#include "log.h"
#include "xencloned.h"
#include "mem.h"


int grant_ref_clone(grant_ref_t gref, domid_t prnt_domid, domid_t chld_domid)
{
	void *src, *dst;
	int rc = -1;

	src = xengnttab_map_grant_ref(xgt_handle, prnt_domid, gref, PROT_READ);
	if (!src) {
		PERROR("Failed to map parent grant ref=%u", gref);
		goto out;
	}

	dst = xengnttab_map_grant_ref(xgt_handle, chld_domid, gref, PROT_WRITE);
	if (!dst) {
		PERROR("Failed to map child grant ref=%u", gref);
		goto unmap_parent_ref;
	}

	memcpy(dst, src, PAGE_SIZE);

	rc = xengnttab_unmap(xgt_handle, dst, 1);
unmap_parent_ref:
	rc = xengnttab_unmap(xgt_handle, src, 1);
out:
	return rc;
}
