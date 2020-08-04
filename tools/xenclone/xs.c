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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "log.h"
#include "xs.h"


//TODO
extern struct xs_handle *xs_handle;
bool xs_deep_copy;


bool xs_path_exists(xs_transaction_t t, const char *path)
{
	char *value;
	unsigned int len;
	bool result = false;

	value = xs_read(xs_handle, t, path, &len);
	if (value) {
		free(value);
		result = true;
	}
	return result;
}

int xs_write_kv(xs_transaction_t t, const struct xs_acl *acl,
		const char *path, const char *key, const char *value)
{
	char *fullpath;
	int rc;

	if (key) {
		rc = asprintf(&fullpath, "%s/%s", path, key);
		if (rc == -1)
			goto out;
	}
	else
		fullpath = (char *) path;

	if (!xs_write(xs_handle, t, fullpath, value, strlen(value))) {
		rc = errno;
		goto out_free;
	}

	if (acl) {
		if (!xs_set_permissions(xs_handle, t, fullpath,
				acl->perms, acl->perms_num)) {
			PERROR("Could not set permisions on %s", fullpath);
			rc = errno;
			goto out;
		}
	}
	rc = 0;
out_free:
	if (key)
		free(fullpath);
out:
	return rc;
}

int xs_read_kv(xs_transaction_t t, const char *path,
		const char *key, char **value)
{
	char *fpath;
	unsigned int len;
	int rc;

	rc = asprintf(&fpath, "%s/%s", path, key);
	if (rc == -1)
		goto out;

	(*value) = xs_read(xs_handle, t, fpath, &len);
	if (!(*value))
		rc = errno;
	else
		rc = 0;

	free(fpath);
out:
	return rc;
}

int xs_printf_kv(xs_transaction_t t, const struct xs_acl *acl,
		const char *path, const char *key, const char *fmt, ...)
{
	va_list va_args;
	char *value;
	int rc;

	if (fmt == NULL)
		return -EINVAL;

	va_start(va_args, fmt);
	rc = vasprintf(&value, fmt, va_args);
	va_end(va_args);

	if (rc >= 0)
		rc = xs_write_kv(t, acl, path, key, value);

	if (value)
		free(value);

	return rc;
}

int xs_scanf_kv(xs_transaction_t t, const char *path,
		const char *key, const char *fmt, ...)
{
	va_list va_args;
	char *value;
	int rc, do_free_value = 1;

	if (fmt == NULL)
		return -EINVAL;

	rc = xs_read_kv(XBT_NULL, path, key, &value);
	if (rc)
		goto out;

	va_start(va_args, fmt);
	if (!strcmp(fmt, "%s")) {
		char **pstr;

		pstr = va_arg(va_args, char **);
		*pstr = value;
		do_free_value = 0;

	} else {
		rc = vsscanf(value, fmt, va_args);
		if (rc > 0)
			rc = 0;
	}
	va_end(va_args);

	if (do_free_value)
		free(value);

out:
	return rc;
}

int xs_acl_get(xs_transaction_t t, const char *path, struct xs_acl *acl)
{
	struct xs_permissions *perms;
	unsigned int num;
	int rc = 0;

	if (!path || !acl) {
		rc = -EINVAL;
		goto out;
	}

	perms = xs_get_permissions(xs_handle, t, path, &num);
	if (!perms) {
		ERROR("Error getting permissions for %s", path);
		rc = -errno;
		goto out;
	}

	acl->perms = perms;
	acl->perms_num = num;

out:
	return rc;
}

int xs_acl_set(xs_transaction_t t, const char *path, struct xs_acl *acl)
{
	int rc = 0;

	if (!path || !acl) {
		rc = -EINVAL;
		goto out;
	}

	rc = xs_set_permissions(xs_handle, t, path, acl->perms, acl->perms_num);
	if (rc == false) {
		ERROR("Error setting permissions for %s", path);
		rc = -errno;
		goto out;
	}
out:
	return rc;
}

int xs_acl_clone(const struct xs_acl *parent_acl, int parent_id,
		struct xs_acl *child_acl, int child_id)
{
	int rc = 0;

	if (!parent_acl || !child_acl) {
		rc = -EINVAL;
		goto out;
	}

	child_acl->perms = malloc(sizeof(struct xs_permissions) *
			parent_acl->perms_num);
	if (!child_acl->perms) {
		rc = -ENOMEM;
		goto out;
	}

	for (int i = 0; i < (int) parent_acl->perms_num; i++) {
		if (parent_acl->perms[i].id == parent_id)
			child_acl->perms[i].id = child_id;
		else
			child_acl->perms[i].id = parent_acl->perms[i].id;

		child_acl->perms[i].perms = parent_acl->perms[i].perms;
	}
	child_acl->perms_num = parent_acl->perms_num;
out:
	return rc;
}

int xs_path_init(struct xs_path *path, char *path_str, bool read_perms)
{
	int rc = 0;

	if (!path || !path_str) {
		rc = -EINVAL;
		goto out;
	}

	if (read_perms) {
		rc = xs_acl_get(XBT_NULL, path_str, &path->acl);
		if (rc) {
			rc = -errno;
			goto out;
		}
	}
	path->value = path_str;
out:
	return rc;
}

int xs_path_fini(struct xs_path *path)
{
	int rc = 0;

	if (!path) {
		rc = -EINVAL;
		goto out;
	}
	if (path->acl.perms) {
		free(path->acl.perms);
		path->acl.perms = NULL;
		path->acl.perms_num = 0;
	}
	if (path->value) {
		free(path->value);
		path->value = NULL;
	}
out:
	return rc;
}

int xs_path_initf(struct xs_path *path, bool read_perms, const char *fmt, ...)
{
	va_list va_args;
	char *path_str;
	int rc;

	va_start(va_args, fmt);
	rc = vasprintf(&path_str, fmt, va_args);
	va_end(va_args);
	if (rc == -1)
		goto out;

	rc = xs_path_init(path, path_str, read_perms);
	if (rc) {
		free(path);
		goto out;
	}
out:
	return rc;
}

int xs_path_make(const struct xs_path *path, xs_transaction_t t)
{
	int rc = 0;

	if (!xs_mkdir(xs_handle, t, path->value)) {
		PERROR("Could not make directory: %s", path->value);
		rc = errno;
		goto out;
	}

	if (!xs_set_permissions(xs_handle, t, path->value,
			path->acl.perms, path->acl.perms_num)) {
		PERROR("Could not set permisions on %s", path->value);
		rc = errno;
		goto out;
	}
out:
	return rc;
}
