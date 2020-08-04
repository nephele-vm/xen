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

#ifndef __XENCLONE_CACHE_H__
#define __XENCLONE_CACHE_H__

struct xenclone_domain;

extern bool do_cache_parents;

int caching_init(void);
int caching_fini(void);

int caching_add(struct xenclone_domain *domain);
int caching_remove(struct xenclone_domain *domain);
struct xenclone_domain *caching_get(unsigned long domid);

#endif /* __XENCLONE_CACHE_H__ */
