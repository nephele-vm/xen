/******************************************************************************
 * network interface definitions
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include "netif.h"


static int iface_op(const char *netif, int flag)
{
	int sock_fd;
	struct ifreq ifr;
	int rc;

	sock_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		rc = errno;
		goto out;
	}

	strncpy(ifr.ifr_name, netif, IFNAMSIZ - 1);

	rc = ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
	if (rc < 0)
		goto out_close_sock_fd;

	if (flag < 0) {
		flag = -flag;
		ifr.ifr_flags &= ~flag;
	} else
		ifr.ifr_flags |= flag;

	rc = ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	if (rc < 0)
		goto out_close_sock_fd;

out_close_sock_fd:
	rc = close(sock_fd);
	if (rc < 0)
		goto out;
out:
	return rc;
}

int netif_up(const char *netif)
{
	return iface_op(netif, IFF_UP);
}

int netif_down(const char *netif)
{
	return iface_op(netif, -IFF_UP);
}
