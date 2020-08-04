/******************************************************************************
 * OS functions
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

#ifndef __XENCLONE_OS_H__
#define __XENCLONE_OS_H__

#include <stdbool.h>

int run_cmd(const char *cmd, bool wait);
int run_cmd_redirected(const char *cmd, bool wait,
		const char *out, char *outtype);

/* TODO move these to measurements header */
#define DOM0_MEM_CONSUMPTION_SCRIPT    "/root/scripts/sessions/clone/dom0-mem-consumption.sh"
#define DOM0_MEM_CONSUMPTION_CSV       "dom0-mem-consumption.csv"

#endif /* __XENCLONE_OS_H__ */
