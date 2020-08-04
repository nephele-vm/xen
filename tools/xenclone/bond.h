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

#ifndef __XENCLONE_BOND_H__
#define __XENCLONE_BOND_H__

#if 0
int ovs_init(void);
int ovs_fini(void);

int ovs_set_instantiation_type(const char *type);
int ovs_set_selection_method(const char *name);
#endif

int bond_add_cloned_if(const char *vif);
int bond_del_cloned_if(const char *vif);

#endif /* __XENCLONE_BOND_H__ */
