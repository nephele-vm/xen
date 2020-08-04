/******************************************************************************
 * logging definitions
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

#ifndef __XENCLONE_LOG_H__
#define __XENCLONE_LOG_H__

#include <errno.h>
#include <xentoollog.h>

extern xentoollog_logger *xtl_handle;

#define INFO(_f, ...) \
	xtl_log(xtl_handle, XTL_INFO,  -1,    "xencloned", _f, ## __VA_ARGS__)
#define WARN(_f, ...) \
	xtl_log(xtl_handle, XTL_WARN, -1,    "xencloned", _f, ## __VA_ARGS__)
#define ERROR(_f, ...) \
	xtl_log(xtl_handle, XTL_ERROR, -1,    "xencloned", _f, ## __VA_ARGS__)
#define PERROR(_f, ...) \
	xtl_log(xtl_handle, XTL_ERROR, errno, "xencloned", "[%10s:%4d]: "_f, __FILE__, __LINE__, ## __VA_ARGS__)

#if XENCLONED_DEBUG
#define DEBUG(_f, ...) \
	xtl_log(xtl_handle, XTL_DEBUG, -1,    "xencloned", "[%10s:%4d] %s: "_f, __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#else
#define DEBUG(_f, ...)
#endif


#endif /* __XENCLONE_LOG_H__ */
