/******************************************************************************
 * networking functionality
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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <xen/io/netif.h>
#include <xen-tools/libs.h>
#include "log.h"
#include "xencloned.h"
#include "clone.h"
#include "ring.h"
#include "xs.h"
#include "ovs.h"
#include "vif.h"
#include "network.h"


static void xs_netfront_fini(struct xs_netfront *front)
{
	assert(front != NULL);
	xs_path_fini(&front->path);
	xs_path_fini(&front->backend_path);
	if (front->backend_dom_path) {
		free(front->backend_dom_path);
		front->backend_dom_path = NULL;
	}
	if (front->mac) {
		free(front->mac);
		front->mac = NULL;
	}
}

static int xs_netfront_init_parent(struct xs_netfront *front)
{
	const char *fe_path = front->path.value;
	char *be_path;
	bool read_perms = xs_deep_copy;
	int rc;

	XS_FE_GET("backend",           "%s", &be_path);
	XS_FE_GET("backend-id",        "%u", &front->backend_id);
	XS_FE_GET("rx-ring-ref",       "%u", &front->rx_ring_ref);

	rc = xs_path_init(&front->backend_path, be_path, read_perms);
	if (rc) {
		free(be_path);
		goto out;
	}

	front->backend_dom_path = xs_get_domain_path(xs_handle, front->backend_id);
	if (!front->backend_dom_path) {
		rc = -errno;
		goto out;
	}

out:
	if (rc)
		xs_netfront_fini(front);

	return rc;
}

static int xs_netfront_init_child(
		struct xs_netfront *pnetfront,
		struct xs_netfront *cnetfront,
		struct xenclone_domain *chld,
		int dev_idx)
{
	int rc;

	/* convert frontend path */
	rc = xs_path_initf(&cnetfront->path, false,
			"%s/device/vif/%d",
			chld->xs.path_local.value, dev_idx);
	if (rc)
		goto out;

	/* convert backend path */
	rc = xs_path_initf(&cnetfront->backend_path, false,
			"%s/backend/vif/%lu/%d",
			pnetfront->backend_dom_path, chld->domid, dev_idx);
	if (rc)
		goto out;

	cnetfront->backend_id = pnetfront->backend_id;
	cnetfront->backend_dom_path = strdup(pnetfront->backend_dom_path);
	if (!cnetfront->backend_dom_path) {
		rc = -ENOMEM;
		goto out;
	}

out:
	if (rc)
		xs_netfront_fini(cnetfront);

	return rc;
}

static int xs_netfront_read_deep(struct xs_netfront *front)
{
	const char *fe_path = front->path.value;
	int rc;

	XS_FE_GET("state",             "%u", &front->state);
	XS_FE_GET("handle",            "%u", &front->handle);
	XS_FE_GET("mac",               "%s", &front->mac);
	XS_FE_GET("tx-ring-ref",       "%u", &front->tx_ring_ref);

	rc = xs_scanf_kv(XBT_NULL, fe_path, "event-channel",
			"%u", &front->evtchn_tx);
	if (rc == 0)
		front->evtchn_rx = front->evtchn_tx;
	else {
		/* split event-channel */
		XS_FE_GET("event-channel-tx",     "%u", &front->evtchn_tx);
		XS_FE_GET("event-channel-rx",     "%u", &front->evtchn_rx);
	}

	XS_FE_GET("request-rx-copy",   "%d", &front->request_rx_copy);

out:
	if (rc)
		xs_netfront_fini(front);

	return rc;
}

static int xs_netfront_write_deep(struct xs_netfront *front,
		xs_transaction_t t)
{
	int rc;

	/* /local/domain/18/device/vif/0 (n18,r0) */
	rc = xs_path_make(&front->path, t);
	if (rc)
		goto out;

	XS_FE_SET("backend",           "%s", front->backend_path.value);
	XS_FE_SET("backend-id",        "%u", front->backend_id);
	XS_FE_SET("state",             "%u", front->state);
	XS_FE_SET("handle",            "%u", front->handle);
	XS_FE_SET("mac",               "%s", front->mac);
	XS_FE_SET("tx-ring-ref",       "%u", front->tx_ring_ref);
	XS_FE_SET("rx-ring-ref",       "%u", front->rx_ring_ref);
	if (front->evtchn_tx == front->evtchn_rx)
		XS_FE_SET("event-channel", "%u", front->evtchn_tx);
	else {
		XS_FE_SET("event-channel-tx", "%u", front->evtchn_tx);
		XS_FE_SET("event-channel-rx", "%u", front->evtchn_rx);
	}
	XS_FE_SET("request-rx-copy",   "%d", front->request_rx_copy);

out:
	return rc;
}

static int xs_netfront_clone_deep(
		struct xs_netfront *pnetfront,
		struct xs_netfront *cnetfront,
		struct xenclone_domain *chld,
		int dev_idx)
{
	int rc;

	rc = xs_acl_clone(&pnetfront->path.acl, chld->parent->domid,
			&cnetfront->path.acl, chld->domid);
	if (rc)
		goto out;

	rc = xs_acl_clone(&pnetfront->backend_path.acl, chld->parent->domid,
			&cnetfront->backend_path.acl, chld->domid);
	if (rc)
		goto out;

	cnetfront->state = pnetfront->state;
	cnetfront->handle = pnetfront->handle;
	cnetfront->mac = strdup(pnetfront->mac);
	if (!cnetfront->mac) {
		rc = -ENOMEM;
		goto out;
	}
	cnetfront->tx_ring_ref = pnetfront->tx_ring_ref;
	cnetfront->rx_ring_ref = pnetfront->rx_ring_ref;
	cnetfront->evtchn_tx = pnetfront->evtchn_tx;
	cnetfront->evtchn_rx = pnetfront->evtchn_rx;
	cnetfront->request_rx_copy = pnetfront->request_rx_copy;
	rc = 0;
out:
	if (rc)
		xs_netfront_fini(cnetfront);
	return rc;
}

static void xs_netback_fini(struct xs_netback *back)
{
	assert(back != NULL);
	if (back->script) {
		free(back->script);
		back->script = NULL;
	}
	if (back->mac) {
		free(back->mac);
		back->mac = NULL;
	}
	if (back->ip) {
		free(back->ip);
		back->ip = NULL;
	}
	if (back->bridge) {
		free(back->bridge);
		back->bridge = NULL;
	}
	if (back->type) {
		free(back->type);
		back->type = NULL;
	}
	if (back->hotplug_status) {
		free(back->hotplug_status);
		back->hotplug_status = NULL;
	}
}

static int xs_netback_read_essential(struct xs_netback *back)
{
	const char *be_path = back->path->value;
	int rc;

	XS_BE_GET("script",            "%s", &back->script);
	XS_BE_GET("mac",               "%s", &back->mac);
	XS_BE_GET("ip",                "%s", &back->ip);
	XS_BE_GET("bridge",            "%s", &back->bridge);
out:
	return rc;
}

static int xs_netback_read_deep(struct xs_netback *back)
{
	const char *be_path = back->path->value;
	int rc;

	XS_BE_GET("frontend-id",       "%d", &back->frontend_id);
	XS_BE_GET("online",            "%d", &back->online);
	XS_BE_GET("state",             "%d", &back->state);
	XS_BE_GET("handle",            "%d", &back->handle);
	XS_BE_GET("type",              "%s", &back->type);
	XS_BE_GET("feature-sg",        "%d", &back->feature_sg);
	XS_BE_GET("feature-gso-tcpv4", "%d", &back->feature_gso_tcpv4);
	XS_BE_GET("feature-gso-tcpv6", "%d", &back->feature_gso_tcpv6);
	XS_BE_GET("feature-ipv6-csum-offload",
			"%d", &back->feature_ipv6_csum_offload);
	XS_BE_GET("feature-rx-copy",   "%d", &back->feature_rx_copy);
	XS_BE_GET("feature-rx-flip",   "%d", &back->feature_rx_flip);
	XS_BE_GET("feature-multicast-control",
			"%d", &back->feature_multicast_control);
	XS_BE_GET("feature-dynamic-multicast-control",
			"%d", &back->feature_dynamic_multicast_control);
	XS_BE_GET("feature-split-event-channels",
			"%d", &back->feature_split_event_channels);
	XS_BE_GET("multi-queue-max-queues",
			"%d", &back->multi_queue_max_queues);
	XS_BE_GET("feature-ctrl-ring", "%d", &back->feature_ctrl_ring);
#if 0 /* TODO this is used for older versions of netback */
	XS_BE_GET("hotplug-status",    "%s", &back->hotplug_status);
#endif

out:
	return rc;
}

static int xs_netback_write_deep(struct xs_netback *back,
		xs_transaction_t t)
{
	int rc;

	/* /local/domain/0/backend/vif/18/0 (n0,r18) */
	rc = xs_path_make(back->path, t);
	if (rc)
		goto out;

	XS_BE_SET("frontend",          "%s", back->frontend_path->value);
	XS_BE_SET("frontend-id",       "%d", back->frontend_id);
	XS_BE_SET("online",            "%d", back->online);
	XS_BE_SET("state",             "%d", back->state);
	XS_BE_SET("script",            "%s", back->script);
	XS_BE_SET("mac",               "%s", back->mac);
	XS_BE_SET("ip",                "%s", back->ip);
	XS_BE_SET("bridge",            "%s", back->bridge);
	XS_BE_SET("handle",            "%d", back->handle);
	XS_BE_SET("type",              "%s", back->type);
	XS_BE_SET("feature-sg",        "%d", back->feature_sg);
	XS_BE_SET("feature-gso-tcpv4", "%d", back->feature_gso_tcpv4);
	XS_BE_SET("feature-gso-tcpv6", "%d", back->feature_gso_tcpv6);
	XS_BE_SET("feature-ipv6-csum-offload",
			"%d", back->feature_ipv6_csum_offload);
	XS_BE_SET("feature-rx-copy",   "%d", back->feature_rx_copy);
	XS_BE_SET("feature-rx-flip",   "%d", back->feature_rx_flip);
	XS_BE_SET("feature-multicast-control",
			"%d", back->feature_multicast_control);
	XS_BE_SET("feature-dynamic-multicast-control",
			"%d", back->feature_dynamic_multicast_control);
	XS_BE_SET("feature-split-event-channels",
			"%d", back->feature_split_event_channels);
	XS_BE_SET("multi-queue-max-queues",
			"%d", back->multi_queue_max_queues);
	XS_BE_SET("feature-ctrl-ring", "%d", back->feature_ctrl_ring);
	//XS_BE_SET("hotplug-status", "%s", back->hotplug_status);

	XS_BE_SET("cloned", "%s", "true");

out:
	return rc;
}

static int xs_netback_clone_deep(
		struct xs_netback *pnetback,
		struct xs_netback *cnetback,
		struct xs_netfront *cnetfront,
		struct xenclone_domain *chld)
{
	int rc = 0;

	cnetback->path = &cnetfront->backend_path;
	cnetback->frontend_path = &cnetfront->path;
	cnetback->frontend_id = chld->domid;
	cnetback->online = pnetback->online;
	cnetback->state = pnetback->state;
	cnetback->script = strdup(pnetback->script);
	if (!cnetback->script) {
		rc = -ENOMEM;
		goto out;
	}
	cnetback->mac = strdup(pnetback->mac);
	if (!cnetback->mac) {
		rc = -ENOMEM;
		goto out;
	}
	cnetback->ip = strdup(pnetback->ip);
	if (!cnetback->ip) {
		rc = -ENOMEM;
		goto out;
	}
	cnetback->bridge = strdup(pnetback->bridge);
	if (!cnetback->bridge) {
		rc = -ENOMEM;
		goto out;
	}
	cnetback->handle = pnetback->handle;
	cnetback->type = strdup(pnetback->type);
	if (!cnetback->type) {
		rc = -ENOMEM;
		goto out;
	}
	cnetback->feature_sg = pnetback->feature_sg;
	cnetback->feature_gso_tcpv4 = pnetback->feature_gso_tcpv4;
	cnetback->feature_gso_tcpv6 = pnetback->feature_gso_tcpv6;
	cnetback->feature_ipv6_csum_offload = pnetback->feature_ipv6_csum_offload;
	cnetback->feature_rx_copy = pnetback->feature_rx_copy;
	cnetback->feature_rx_flip = pnetback->feature_rx_flip;
	cnetback->feature_multicast_control = pnetback->feature_multicast_control;
	cnetback->feature_dynamic_multicast_control = pnetback->feature_dynamic_multicast_control;
	cnetback->feature_split_event_channels = pnetback->feature_split_event_channels;
	cnetback->feature_ctrl_ring = pnetback->feature_ctrl_ring;
	cnetback->multi_queue_max_queues = pnetback->multi_queue_max_queues;
out:
	if (rc)
		xs_netback_fini(cnetback);
	return rc;
}

static int xs_network_dev_init(struct xs_network_dev *dev,
		struct xenclone_domain *domain, char *fe_path)
{
	struct xs_netfront *front = &dev->front;
	struct xs_netback *back = &dev->back;
	bool read_perms = xs_deep_copy;
	int rc;

	dev->domain = domain;

	rc = xs_path_init(&front->path, fe_path, read_perms);
	if (rc) {
		PERROR("Failed to initializing path %s", fe_path);
		goto out;
	}

	rc = xs_netfront_init_parent(front);
	if (rc) {
		PERROR("Failed to init netfront Xenstore info");
		goto out;
	}

	back->path = &front->backend_path;

	rc = xs_netback_read_essential(back);
	if (rc) {
		PERROR("Failed to read netback Xenstore info");
		goto out;
	}

	if (xs_deep_copy) {
		rc = xs_netfront_read_deep(front);
		if (rc) {
			PERROR("Failed to read netfront Xenstore info");
			goto out;
		}

		back->frontend_path = &front->path;

		rc = xs_netback_read_deep(back);
		if (rc) {
			PERROR("Failed to read netback Xenstore info");
			goto out;
		}
	}

out:
	if (rc)
		xs_netfront_fini(front);

	return rc;
}

static void xs_network_dev_fini(struct xs_network_dev *dev)
{
	xs_netfront_fini(&dev->front);
	xs_netback_fini(&dev->back);
	if (dev->vif)
		xenclone_vif_destroy(dev->vif);
}

static
int xs_network_dev_register_parent(struct xs_network_dev *dev, int dev_idx)
{
	struct xs_netback *back = &dev->back;
	char *ifname = NULL;
	enum bridge_type bridge_type;
	struct xenclone_vif *vif = NULL;
	int id, free_vif = 0, rc;

	rc = asprintf(&ifname, "vif%d.%d", (int) dev->domain->domid, dev_idx);
	if (rc == -1)
		goto out;
	else
		rc = 0;

	vif = xenclone_vif_get(ifname);
	if (!vif) {
		/* new family */
		id = dev->domain->domid * 100 + dev_idx;

		bridge_type = script_to_bridge_type(back->script, back->bridge);
		if (bridge_type == BRIDGE_TYPE_NONE) {
			rc = -ENOTSUP;
			goto out;
		}

		vif = xenclone_vif_create(id, ifname,
				back->mac, back->ip, back->bridge,
				bridge_type);
		if (!vif) {
			rc = -ENOMEM;
			goto out;
		}

	} else if (strcmp(ifname, vif->ifname)) {
		/* this parent is a descendant of another cloned vif */
		rc = xenclone_vif_add_clone(vif, ifname);
		if (rc) {
			PERROR("Error calling xenclone_vif_add_clone() rc=%d", rc);
			goto out;
		}

	} else
		free_vif = 1;

	dev->vif = vif;

out:
	if ((rc || free_vif) && ifname)
		free(ifname);

	return rc;
}

static
int xs_network_dev_register_child(struct xs_network_dev *dev, int dev_idx,
		struct xenclone_vif *vif)
{
	char *ifname;
	int rc;

	rc = asprintf(&ifname, "vif%d.%d", (int) dev->domain->domid, dev_idx);
	if (rc == -1)
		goto out;

	rc = xenclone_vif_add_clone(vif, ifname);
	if (rc) {
		PERROR("Error calling xenclone_vif_add_clone() rc=%d", rc);
		goto out;
	}

out:
	if (rc)
		free(ifname);

	return rc;
}

int network_devices_init(struct xenclone_domain *domain)
{
	char *parent_vif_dir = NULL, **dir_entries = NULL;
	unsigned int dir_entries_num, i, j;
	struct xs_network_dev *devs;
	int rc;

	rc = asprintf(&parent_vif_dir,
		"/local/domain/%lu/device/vif", domain->domid);
	if (rc == -1)
		goto out;

	dir_entries = xs_directory(xs_handle, XBT_NULL, parent_vif_dir,
		&dir_entries_num);
	if (dir_entries == NULL) {
		/* List is empty. */
		rc = 0;
		goto out_parent_vif_dir;
	}
	DEBUG("dir_entries_num=%d", dir_entries_num);
	if (!dir_entries_num)
		goto out_dir_entries;

	devs = calloc(dir_entries_num, sizeof(struct xs_network_dev));
	if (devs == NULL) {
		rc = -ENOMEM;
		goto out_dir_entries;
	}

	for (i = 0; i < dir_entries_num; i++) {
		struct xs_network_dev *dev;
		char *fe_path;

		dev = &devs[i];

		rc = asprintf(&fe_path, "%s/%s", parent_vif_dir, dir_entries[i]);
		if (rc == -1)
			goto out_of_loop;

		rc = xs_network_dev_init(dev, domain, fe_path);
		if (rc) {
			PERROR("Failed calling xs_network_dev_init()");
			goto out_of_loop;
		}

		rc = xs_network_dev_register_parent(dev, i);
		if (rc) {
			PERROR("Failed calling xs_network_dev_register_parent()");
			goto out_of_loop;
		}
	}

out_of_loop:
	if (rc == 0) {
		domain->net_devs = devs;
		domain->net_devs_num = dir_entries_num;

	} else {
		//TODO unregister
		for (j = 0; j < i; j++)
			xs_network_dev_fini(&devs[j]);
		free(devs);
	}
out_dir_entries:
	free(dir_entries);
out_parent_vif_dir:
	free(parent_vif_dir);
out:
	return rc;
}

int network_devices_fini(struct xenclone_domain *domain)
{
	for (int i = 0; i < domain->net_devs_num; i++)
		xs_network_dev_fini(&domain->net_devs[i]);
	free(domain->net_devs);
	domain->net_devs = NULL;
	domain->net_devs_num = 0;
	return 0;
}

#if 1
#define MY_RING_MEMSIZE XC_PAGE_SIZE
#else
#define MY_RING_MEMSIZE 128
#endif

#if CLONE_RINGS
static int tx_ring_clone(grant_ref_t tx_ring_ref,
		domid_t prnt_domid, domid_t chld_domid)
{
	netif_tx_sring_t *ptxr, *ctxr;
	netif_tx_front_ring_t ptxf, ctxf;
	int rc = -1;

	/* map rings */
	ptxr = xengnttab_map_grant_ref(xgt_handle,
			prnt_domid, tx_ring_ref, PROT_WRITE);
	if (!ptxr) {
		PERROR("Failed to map parent tx grant ref");
		goto out;
	}

	ctxr = xengnttab_map_grant_ref(xgt_handle,
			chld_domid, tx_ring_ref, PROT_WRITE);
	if (!ctxr) {
		PERROR("Failed to map child tx grant ref");
		goto unmap_parent_tx_ring;
	}

	DEBUG("ref=%d req_prod=%d req_event=%d rsp_prod=%d rsp_event=%d",
		tx_ring_ref, ptxr->req_prod, ptxr->req_event,
		ptxr->rsp_prod, ptxr->rsp_event);

	/* initialize our helper structures */
	FRONT_RING_INIT(&ptxf, ptxr, MY_RING_MEMSIZE);
	FRONT_RING_INIT(&ctxf, ctxr, MY_RING_MEMSIZE);

	rc = RING_COPY(&ptxf, &ctxf, prnt_domid, chld_domid);
	if (rc)
		goto unmap_child_tx_ring;

	/* copy ring header */
	memcpy(ctxr, ptxr, offsetof(netif_tx_sring_t, ring));

unmap_child_tx_ring:
	rc = xengnttab_unmap(xgt_handle, ctxr, 1);
unmap_parent_tx_ring:
	rc = xengnttab_unmap(xgt_handle, ptxr, 1);
out:
	return rc;
}

static int rx_ring_clone(grant_ref_t rx_ring_ref,
		domid_t prnt_domid, domid_t chld_domid)
{
	netif_rx_sring_t *prxr, *crxr;
	netif_rx_front_ring_t prxf, crxf;
	int rc = -1;

	/* map rings */
	prxr = xengnttab_map_grant_ref(xgt_handle,
			prnt_domid, rx_ring_ref, PROT_WRITE);
	if (!prxr) {
		PERROR("Failed to map parent rx grant ref");
		goto out;
	}

	crxr = xengnttab_map_grant_ref(xgt_handle,
			chld_domid, rx_ring_ref, PROT_WRITE);
	if (!crxr) {
		PERROR("Failed to map child rx grant ref");
		goto unmap_parent_rx_ring;
	}

	DEBUG("ref=%d req_prod=%d req_event=%d rsp_prod=%d rsp_event=%d",
		rx_ring_ref, prxr->req_prod, prxr->req_event,
		prxr->rsp_prod, prxr->rsp_event);

	/* initialize our helper structures */
	FRONT_RING_INIT(&prxf, prxr, MY_RING_MEMSIZE);
	FRONT_RING_INIT(&crxf, crxr, MY_RING_MEMSIZE);

	rc = RING_COPY(&prxf, &crxf, prnt_domid, chld_domid);
	if (rc)
		goto unmap_child_rx_ring;

	/* copy ring header */
	memcpy(crxr, prxr, offsetof(netif_rx_sring_t, ring));
	crxr->rsp_event = crxr->rsp_prod + 1;

unmap_child_rx_ring:
	rc = xengnttab_unmap(xgt_handle, crxr, 1);
unmap_parent_rx_ring:
	rc = xengnttab_unmap(xgt_handle, prxr, 1);
out:
	return rc;
}
#else
static int rx_ring_clone(grant_ref_t rx_ring_ref,
		domid_t prnt_domid, domid_t chld_domid)
{
	netif_rx_sring_t *crxr;
	int rc = -1;

	crxr = xengnttab_map_grant_ref(xgt_handle,
			chld_domid, rx_ring_ref, PROT_WRITE);
	if (!crxr) {
		PERROR("Failed to map child rx grant ref");
		goto out;
	}
	crxr->rsp_event = crxr->rsp_prod + 1;
	rc = xengnttab_unmap(xgt_handle, crxr, 1);
out:
	return rc;
}
#endif

static
int xs_libxl_network_write_deep(struct xs_network_dev *dev,
		struct xs_path *path_libxl, int dev_idx, xs_transaction_t t)
{
	char *libxl_path = NULL;
	int rc;

	rc = asprintf(&libxl_path, "%s/device/vif/%d",
			path_libxl->value, dev_idx);
	if (!libxl_path) {
		rc = errno;
		goto out;
	}

	XS_LIBXL_SET("frontend",      "%s", dev->front.path.value);
	XS_LIBXL_SET("backend",       "%s", dev->front.backend_path.value);
	XS_LIBXL_SET("frontend-id",   "%d", dev->back.frontend_id);
	XS_LIBXL_SET("online",        "%d", dev->back.online);
	XS_LIBXL_SET("state",         "%d", dev->back.state);
	XS_LIBXL_SET("script",        "%s", dev->back.script);
	XS_LIBXL_SET("mac",           "%s", dev->back.mac);
	XS_LIBXL_SET("ip",            "%s", dev->back.ip);
	XS_LIBXL_SET("bridge",        "%s", dev->back.bridge);
	XS_LIBXL_SET("handle",        "%s", dev->back.handle);
	XS_LIBXL_SET("type",          "%s", dev->back.type);

out:
	if (libxl_path)
		free(libxl_path);
	return rc;
}

static
int xs_libxl_network_clone(
		unsigned long pdomid, struct xs_path *ppath_libxl,
		unsigned long cdomid, struct xs_path *cpath_libxl,
		int dev_idx, xs_transaction_t t)
{
	char *ppath = NULL, *cpath = NULL;
	int rc;

	rc = asprintf(&ppath, "%s/device/vif/%d",
			ppath_libxl->value, dev_idx);
	if (!ppath) {
		rc = errno;
		goto out;
	}

	rc = asprintf(&cpath, "%s/device/vif/%d",
			cpath_libxl->value, dev_idx);
	if (!cpath) {
		rc = errno;
		goto out;
	}

	rc = xs_clone(xs_handle, XBT_NULL,
			pdomid, cdomid, xs_clone_op_dev_vif,
			ppath, cpath);
	if (rc == false) {
		rc = errno;
		PERROR("Error calling xs_clone() rc=%d", rc);
		goto out;
	}

	rc = 0;
out:
	if (ppath)
		free(ppath);
	if (cpath)
		free(cpath);
	return rc;
}

static int xs_network_dev_clone(
		struct xs_network_dev *pdev,
		struct xs_network_dev *cdev,
		struct xenclone_domain *chld,
		int dev_idx)
{
	xs_transaction_t t;
	int rc;

	cdev->domain = chld;

	rc = xs_netfront_init_child(&pdev->front, &cdev->front, chld, dev_idx);
	if (rc) {
		PERROR("Error xs_netfront_init_child() rc=%d", rc);
		goto out;
	}

	if (xs_deep_copy) {
		rc = xs_netfront_clone_deep(&pdev->front, &cdev->front, chld, dev_idx);
		if (rc) {
			PERROR("Error xs_netfront_clone() rc=%d", rc);
			goto out;
		}

		rc = xs_netback_clone_deep(&pdev->back, &cdev->back, &cdev->front, chld);
		if (rc) {
			PERROR("Error xs_netback_clone() rc=%d", rc);
			goto out;
		}
	}

	/* rings cloning */
#if CLONE_RINGS
	rc = tx_ring_clone(dev->front.tx_ring_ref, prnt->domid, chld->domid);
	if (rc) {
		PERROR("Failed to clone tx ring");
		goto out;
	}
#endif
	rc = rx_ring_clone(pdev->front.rx_ring_ref, pdev->domain->domid, cdev->domain->domid);
	if (rc) {
		PERROR("Failed to clone rx ring");
		goto out;
	}

	rc = xs_network_dev_register_child(cdev, dev_idx, pdev->vif);
	if (rc) {
		PERROR("Error xs_network_dev_register_child() rc=%d", rc);
		goto out;
	}

	/* write child data */
trans_start:
	t = xs_transaction_start(xs_handle);
	if (t == XBT_NULL)
		goto out;

	if (xs_deep_copy) {
		rc = xs_netfront_write_deep(&cdev->front, t);
		if (rc) {
			PERROR("Failed to write netfront Xenstore info");
			goto trans_end;
		}

		rc = xs_netback_write_deep(&cdev->back, t);
		if (rc) {
			PERROR("Failed to write netback Xenstore info");
			goto trans_end;
		}

		rc = xs_libxl_network_write_deep(cdev, &chld->xs.path_libxl, dev_idx, t);
		if (rc) {
			PERROR("Failed to write network libxl info");
			goto trans_end;
		}

	} else {
		struct xenclone_domain *prnt = chld->parent;

		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_dev_vif,
				pdev->front.path.value, cdev->front.path.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = xs_clone(xs_handle, XBT_NULL,
				prnt->domid, chld->domid, xs_clone_op_dev_vif,
				pdev->front.backend_path.value, cdev->front.backend_path.value);
		if (rc == false) {
			rc = errno;
			PERROR("Error calling xs_clone() rc=%d", rc);
			goto trans_end;
		}

		rc = xs_libxl_network_clone(
				prnt->domid, &prnt->xs.path_libxl,
				chld->domid, &chld->xs.path_libxl,
				0, t);
		if (rc) {
			PERROR("Failed to clone network libxl info");
			goto trans_end;
		}
	}

trans_end:
	if (rc)
		xs_transaction_end(xs_handle, t, true);

	else {
		rc = xs_transaction_end(xs_handle, t, false);
		if (!rc) {
			if (errno == EAGAIN)
				goto trans_start;
			else
				rc = errno;
		} else
			rc = 0;
	}
out:
	return rc;
}

int network_devices_clone(struct xenclone *clone)
{
	struct xenclone_domain *parent = clone->parent;
	struct xs_network_dev *devs;
	unsigned int i, j;
	int rc = 0;

	if (parent->net_devs_num == 0)
		goto out;

	devs = calloc(parent->net_devs_num, sizeof(struct xs_network_dev));
	if (devs == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	xenclone_lock(clone);
	clone->pending_devices += parent->net_devs_num;
	xenclone_unlock(clone);

	for (i = 0; i < parent->net_devs_num; i++) {
		struct xs_network_dev *pdev, *cdev;

		pdev = &parent->net_devs[i];
		cdev = &devs[i];

		rc = xs_network_dev_clone(pdev, cdev, &clone->domain, i);
		if (rc) {
			PERROR("Failed to clone network device");
			break;
		}
	}

	for (j = 0; j < i; j++)
		xs_network_dev_fini(&devs[j]);
	free(devs);
out:
	return rc;
}

static bool networking_initialized = false;

int networking_init(void)
{
	int rc;

	rc = xenclone_vifs_init();
	if (rc) {
		PERROR("Error calling cloned_vifs_init() rc=%d", rc);
		goto out;
	}

	rc = ovs_init();
	if (rc) {
		PERROR("Error calling ovs_init() rc=%d", rc);
		xenclone_vifs_fini();
		goto out;
	}

	networking_initialized = true;

out:
	return rc;
}

int networking_fini(void)
{
	int rc = -1;

	if (!networking_initialized)
		goto out;

	rc = ovs_fini();
	if (rc) {
		PERROR("Error calling ovs_fini() rc=%d", rc);
		goto out;
	}

	rc = xenclone_vifs_fini();
	if (rc) {
		PERROR("Error calling cloned_vifs_fini() rc=%d", rc);
		goto out;
	}

	networking_initialized = false;

out:
	return rc;
}
