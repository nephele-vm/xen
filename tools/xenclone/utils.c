/******************************************************************************
 * Utils
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

#include <stdlib.h>


int tokens_num(char *str)
{
	char *p;
	int n;

	p = str;
	n = 1;
	while (*p) {
		if (*p++ == ' ')
			n++;
	}

	return n;
}

int tokenize(char *str, char ***pargv)
{
	int argc, i;
	char **argv, *p;

	argc = tokens_num(str);
	argv = malloc(sizeof(char *) * (argc + 1));
	if (!argv) {
		argc = -1;
		goto out;
	}

	i = 0;
	p = str;

	/* skip leading spaces */
	while (*p == ' ')
		p++;
	argv[i++] = p;

	/* TODO deal with consecutive spaces */
	while (*p) {
		if (*p == ' ') {
			*p = '\0';
			argv[i++] = ++p;
		} else
			p++;
	}

	argv[i++] = NULL;

	*pargv = argv;

out:
	return argc;
}
