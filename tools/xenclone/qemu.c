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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "log.h"
#include "9pfs.h"
#include "qemu.h"


struct qmp *qmp_create(unsigned long parent_domid)
{
	struct qmp *qmp;
	struct sockaddr_un addr;
	int rc = -1;

	qmp = malloc(sizeof(struct qmp));
	if (!qmp) {
		ERROR("Error allocating qmp");
		goto out;
	}
	qmp->ref = 0;
	qmp->hello_sent = 0;
	qmp->parent_domid = parent_domid;
	rc = pthread_mutex_init(&qmp->mtx, NULL);
	assert(rc == 0);

	qmp->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (qmp->fd < 0) {
		PERROR("Error calling socket()");
		goto out;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
		"/var/run/xen/qmp-libxl-%lu", parent_domid);
	DEBUG("path=%s", addr.sun_path);

	rc = connect(qmp->fd, (struct sockaddr *) &addr, sizeof(addr));
	if (rc) {
		PERROR("Error calling connect()");
		goto out;
	}

	HMAP_LIST_NODE_INIT(&qmp->map_fd_list_node);
	HMAP_LIST_NODE_INIT(&qmp->map_parentid_list_node);

	rc = 0;
out:
	if (rc) {
		if (qmp) {
			if (qmp->fd >= 0) {
				close(qmp->fd);
				qmp->fd = -1;
			}
			free(qmp);
			qmp = NULL;
		}
	}
	return qmp;
}

int qmp_destroy(struct qmp *qmp)
{
	int rc = 0;

	if (qmp->ref > 0) {
		rc = -EINVAL;
		goto out;
	}
	if (qmp->fd >= 0) {
		close(qmp->fd);
		qmp->fd = -1;
	}
	rc = pthread_mutex_destroy(&qmp->mtx);
	assert(rc == 0);
	free(qmp);
out:
	return rc;
}

void qmp_get(struct qmp *qmp)
{
	assert(pthread_mutex_lock(&qmp->mtx) == 0);
	qmp->ref++;
	assert(pthread_mutex_unlock(&qmp->mtx) == 0);
}

void qmp_put(struct qmp *qmp)
{
	bool destroy = false;

	assert(qmp);
	assert(pthread_mutex_lock(&qmp->mtx) == 0);
	assert(qmp->ref > 0);
	destroy = (--qmp->ref == 0);
	assert(pthread_mutex_unlock(&qmp->mtx) == 0);

	if (destroy) {
		p9fs_remove_qmp(qmp);
		qmp_destroy(qmp);
	}
}

static int qmp_recv(struct qmp *qmp, int msg_count)
{
	char recv_buf[128];
	int rc = 0;

	while (msg_count > 0) {
		rc = recv(qmp->fd, recv_buf, sizeof(recv_buf), 0);
		if (rc < 0) {
			PERROR("Error calling recv()");
			goto out;
		}
		recv_buf[rc] = '\0';
		/* DEBUG("recv=%s", recv_buf); */

		msg_count--;
	}
out:
	return rc;
}


int qmp_announce_clone(struct qmp *qmp,
		unsigned long domid, unsigned long parentid)
{
	static unsigned long id = 2020372000;
	const char *hello = "{\"execute\":\"qmp_capabilities\"}";
	char *send_buf = NULL;
	int rc;

	if (!qmp->hello_sent) {
		rc = qmp_recv(qmp, 1);
		if (rc < 0) {
			PERROR("Error calling qmp_recv()");
			goto out;
		}
		rc = send(qmp->fd, hello, strlen(hello), 0);
		if (rc < 0) {
			PERROR("Error calling send()");
			goto out;
		}
		rc = qmp_recv(qmp, 1);
		if (rc < 0) {
			PERROR("Error calling qmp_recv()");
			goto out;
		}
		qmp->hello_sent = 1;
	}

	asprintf(&send_buf, "{"
			"\"execute\":\"xen-clone\","
			"\"id\":%lu,"
			"\"arguments\":{"
				"\"domid\":%lu,"
				"\"parentid\":%lu}"
			"}", id++, domid, parentid);
	if (!send_buf) {
		PERROR("Error calling asprintf()");
		rc = -ENOMEM;
		goto out;
	}
	/* DEBUG("send=%s", send_buf); */

	rc = send(qmp->fd, send_buf, strlen(send_buf), 0);
	if (rc < 0) {
		PERROR("Error calling send()");
		goto out;
	}
	rc = qmp_recv(qmp, 1);
	if (rc < 0) {
		PERROR("Error calling qmp_recv()");
		goto out;
	}

	rc = 0;

out:
	if (send_buf)
		free(send_buf);

	return rc;
}
