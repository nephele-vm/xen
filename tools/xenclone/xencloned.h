/******************************************************************************
 * Daemon definitions
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

#ifndef __XENCLONE_XENCLONED_H__
#define __XENCLONE_XENCLONED_H__

#include <xenctrl.h>
#include <xengnttab.h>

extern xc_interface *xc_handle;
extern xengnttab_handle *xgt_handle;
/*TODO extern xentoollog_logger *xtl_handle;*/
extern struct xs_handle *xs_handle;

#endif /* __XENCLONE_XENCLONED_H__ */
