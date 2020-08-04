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

#ifndef __XENCLONE_MEM_H__
#define __XENCLONE_MEM_H__

#include <xen/xen.h>
#include <xen/grant_table.h>
#include <xenctrl.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE XC_PAGE_SIZE
#endif

int grant_ref_clone(grant_ref_t gref, domid_t prnt_domid, domid_t chld_domid);

#endif /* __XENCLONE_MEM_H__ */
