/******************************************************************************
 * Networking definitions
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

#ifndef __XENCLONE_NETWORK_H__
#define __XENCLONE_NETWORK_H__

#include "xs.h"

struct xenclone;

struct xs_netfront {
	struct xs_path path;
	struct xs_path backend_path;
	char *backend_dom_path;
	int backend_id;
	int state;
	int handle;
	char *mac;
	grant_ref_t tx_ring_ref;
	grant_ref_t rx_ring_ref;
	evtchn_port_t evtchn_tx;
	evtchn_port_t evtchn_rx;
	int request_rx_copy;
};

struct xs_netback {
	const struct xs_path *path;
	const struct xs_path *frontend_path;
	int frontend_id;
	int online;
	int state;
	char *script;
	char *mac;
	char *ip;
	char *bridge;
	int handle;
	char *type;
	int feature_sg;
	int feature_gso_tcpv4;
	int feature_gso_tcpv6;
	int feature_ipv6_csum_offload;
	int feature_rx_copy;
	int feature_rx_flip;
	int feature_multicast_control;
	int feature_dynamic_multicast_control;
	int feature_split_event_channels;
	int feature_ctrl_ring;
	int multi_queue_max_queues;
	char *hotplug_status;
};

struct xs_network_dev {
	struct xenclone_domain *domain; /* back pointer */
	struct xenclone_vif *vif;
	struct xs_netfront front;
	struct xs_netback back;
};

int network_devices_init(struct xenclone_domain *domain);
int network_devices_fini(struct xenclone_domain *domain);
int network_devices_clone(struct xenclone *clone);

int networking_init(void);
int networking_fini(void);

#endif /* __XENCLONE_NETWORK_H__ */
