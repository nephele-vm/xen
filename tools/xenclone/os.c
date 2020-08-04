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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "log.h"
#include "utils.h"
#include "os.h"


static int run_exec(const char *cmd0)
{
	int argc, rc;
	char *cmd = NULL, **argv;

	DEBUG("cmd: %s", cmd0);
	cmd = strdup(cmd0);
	if (!cmd) {
		ERROR("Error duplicating command\n");
		rc = -ENOMEM;
		goto out;
	}

	argc = tokenize(cmd, &argv);
	if (argc < 0) {
		ERROR("Error tokenizing\n");
		rc = -1;
		goto out_free_cmd;
	}

	rc = execvp(argv[0], argv);

	free(argv);
out_free_cmd:
	free(cmd);
out:
	return rc;
}

static
int __run_cmd_redirected(const char *cmd, bool wait,
		const char *out, char *outtype)
{
	pid_t pid;
	FILE *f;
	int status, rc = 0;

	pid = fork();
	if (pid > 0) {
		if (wait) {
			rc = waitpid(pid, &status, 0);
			if (rc != pid) {
				PERROR("Error calling waitpid() (rc=%d != pid=%d)\n", rc, pid);
				goto out;
			}
		} else
			rc = pid;
		goto out;
	} else if (pid < 0) {
		PERROR("Error calling fork()\n");
		rc = -errno;
		goto out;
	}

	if (out) {
		rc = fclose(stdout);
		assert(rc == 0);

		/* TODO not safe, we should convert outtype to flags */
		f = fopen(out, outtype);
		if (!f) {
			ERROR("Error opening %s\n", out);
			rc = -errno;
			goto out;
		}
	}

	rc = run_exec(cmd);

out:
	return rc;
}

int run_cmd_redirected(const char *cmd, bool wait,
		const char *out, char *outtype)
{
	int rc;

	if (!(out && outtype)) {
		rc = -EINVAL;
		goto out;
	}

	rc = __run_cmd_redirected(cmd, wait, out, outtype);
out:
	return rc;
}

int run_cmd(const char *cmd, bool wait)
{
	return __run_cmd_redirected(cmd, wait, NULL, NULL);
}
