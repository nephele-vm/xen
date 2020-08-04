/******************************************************************************
 * Xenstore client utils
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

#ifndef __XENCLONE_XS_H__
#define __XENCLONE_XS_H__

#include <stdbool.h>
#include <xenstore.h>


extern bool xs_deep_copy;

struct xs_acl {
	struct xs_permissions *perms;
	unsigned int perms_num;
};

int xs_acl_get(xs_transaction_t t, const char *path, struct xs_acl *acl);
int xs_acl_set(xs_transaction_t t, const char *path, struct xs_acl *acl);
int xs_acl_clone(const struct xs_acl *parent_acl, int parent_id,
		struct xs_acl *child_acl, int child_id);

struct xs_path {
	struct xs_acl acl;
	char *value;
};

int xs_path_init(struct xs_path *path, char *path_str, bool read_perms);
int xs_path_initf(struct xs_path *path, bool read_perms, const char *fmt, ...);
int xs_path_fini(struct xs_path *path);
int xs_path_make(const struct xs_path *path, xs_transaction_t t);

bool xs_path_exists(xs_transaction_t t, const char *path);


int xs_write_kv(xs_transaction_t t, const struct xs_acl *acl,
		const char *path, const char *key, const char *value);
int xs_read_kv(xs_transaction_t t,
		const char *path, const char *key, char **value);

int xs_printf_kv(xs_transaction_t t, const struct xs_acl *acl,
		const char *path, const char *key, const char *fmt, ...);
int xs_scanf_kv(xs_transaction_t t,
		const char *path, const char *key, const char *fmt, ...);


/* Helpers for IO cloning */

#define XS_FE_GET_OPTIONAL(key, fmt, val) \
	do { \
		rc = xs_scanf_kv(XBT_NULL, fe_path, key, fmt, val); \
	} while (0)

#define XS_FE_GET(key, fmt, val) \
	do { \
		rc = xs_scanf_kv(XBT_NULL, fe_path, key, fmt, val); \
		if (rc) { \
			PERROR("Could not read %s/%s", fe_path, key); \
			goto out; \
		} \
	} while (0)

#define XS_FE_SET(key, fmt, val) \
	do { \
		rc = xs_printf_kv(t, &front->path.acl, front->path.value, key, fmt, val); \
		if (rc) { \
			PERROR("Could not write to %s/%s", front->path.value, key); \
			goto out; \
		} \
	} while (0)

#define XS_BE_GET(key, fmt, val) \
	do { \
		rc = xs_scanf_kv(XBT_NULL, be_path, key, fmt, val); \
		if (rc) { \
			PERROR("Could not read %s/%s", be_path, key); \
			goto out; \
		} \
	} while (0)

#define XS_BE_SET(key, fmt, val) \
	do { \
		rc = xs_printf_kv(t, &back->path->acl, back->path->value, key, fmt, val); \
		if (rc) { \
			PERROR("Could not write to %s/%s", back->path->value, key); \
			goto out; \
		} \
	} while (0)

#define XS_LIBXL_SET(key, fmt, val) \
	do { \
		rc = xs_printf_kv(t, &path_libxl->acl, libxl_path, key, fmt, val); \
		if (rc) { \
			PERROR("Could not write to %s/%s", libxl_path, key); \
			goto out; \
		} \
	} while (0)

#endif /* __XENCLONE_XS_H__ */
