/******************************************************************************
 * udev
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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <libudev.h>
#include "log.h"
#include "profile.h"
#include "udev.h"
#include "vif.h"
#include "vbd.h"


static struct udev *udev = NULL;
static struct udev_monitor *mon = NULL;

static bool udev_thread_started = false;
static pthread_t udev_thread;


int udev_init(void)
{
	int mon_fd, flags, rc = -1;

	/* setup udev */
	udev = udev_new();
	if (!udev) {
		PERROR("Error calling udev_new()");
		goto out;
	}

	/* setup monitor */
	mon = udev_monitor_new_from_netlink(udev, "kernel");
	if (!mon) {
		PERROR("Error calling udev_monitor_new_from_netlink()");
		goto out_fini;
	}

	rc = udev_monitor_filter_add_match_subsystem_devtype(mon, "xen-backend",
			NULL);
	if (rc) {
		PERROR("Error calling udev_monitor_filter_add_match_subsystem_devtype() rc=%d",
			rc);
		goto out_fini;
	}

	rc = udev_monitor_enable_receiving(mon);
	if (rc) {
		PERROR("Error calling udev_monitor_enable_receiving() rc=%d", rc);
		goto out_fini;
	}

	mon_fd = udev_monitor_get_fd(mon);
	if (mon_fd < 0) {
		PERROR("Error calling udev_monitor_get_fd()");
		goto out_fini;
	}

	flags = fcntl(mon_fd, F_GETFL, 0);

	rc = fcntl(mon_fd, F_SETFL, flags & ~O_NONBLOCK);
	if (rc) {
		PERROR("Error calling fcntl() rc=%d", rc);
		goto out_fini;
	}

out_fini:
	if (rc)
		udev_fini();
out:
	return rc;
}

int udev_fini(void)
{
	if (udev_thread_started)
		udev_stop();

	if (mon) {
		udev_monitor_unref(mon);
		mon = NULL;
	}

	if (udev) {
		udev_unref(udev);
		udev = NULL;
	}

	return 0;
}

enum xen_udev_operation {
	ONLINE,
	OFFLINE,
};

static void do_vif_hotplug(struct udev_device *dev)
{
	const char *action, *xb_path, *vif;
	enum xen_udev_operation op;

	PROFILE_NESTED_TICK(__FUNCTION__);

	action = udev_device_get_action(dev);
	if (!action) {
		PERROR("Error getting xb action");
		goto out;
	}

	if (strcmp(action, "online") == 0)
		op = ONLINE;
	else if (strcmp(action, "offline") == 0)
		op = OFFLINE;
	else
		goto out;

	xb_path = udev_device_get_property_value(dev, "XENBUS_PATH");
	if (!xb_path) {
		PERROR("Error getting xb path");
		goto out;
	}

	vif = udev_device_get_property_value(dev, "vif");
	if (!vif) {
		PERROR("Error getting vif");
		goto out;
	}

	switch (op) {
	case ONLINE:
		vif_hotplug_online(xb_path, vif);
		break;
	case OFFLINE:
		vif_hotplug_offline(xb_path, vif);
		break;
	}

out:
	PROFILE_NESTED_TOCK_MSEC();
	return;
}

static void do_vbd_hotplug(struct udev_device *dev)
{
	const char *action, *xb_path;
	enum xen_udev_operation op;

	action = udev_device_get_action(dev);
	if (!action) {
		PERROR("Error getting xb action");
		goto out;
	}

	if (strcmp(action, "add") == 0)
		op = ONLINE;
	else
		return;

	xb_path = udev_device_get_property_value(dev, "XENBUS_PATH");
	if (!xb_path) {
		PERROR("Error getting xb path");
		goto out;
	}

	switch (op) {
	case ONLINE:
		vbd_hotplug_online(xb_path);
		break;
	case OFFLINE:
		break;
	}

out:
	return;
}

static void *udev_loop(void *arg)
{
	struct udev_device *dev;
	const char *sysname, *cloned;
	long rc = 0;

	DEBUG("udev thread running..");

	rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	if (rc) {
		PERROR("Error calling pthread_setcancelstate() rc=%ld", rc);
		goto out;
	}

	/* TODO find a proper way to set size, maybe according to max clones num */
	rc = udev_monitor_set_receive_buffer_size(mon, 128 * 1024 * 1024);
	if (rc) {
		PERROR("Error calling udev_monitor_set_receive_buffer_size() rc=%ld", rc);
		goto out;
	}

	/*  main loop */
	while (1) {
		dev = udev_monitor_receive_device(mon);
		if (!dev) {
			/* DEBUG("Spurious udev event"); */
			continue;
		}

		cloned = udev_device_get_property_value(dev, "cloned");
		if (!cloned)
			goto unref_dev;

		sysname = udev_device_get_sysname(dev);
		/*DEBUG("sysname=%s cloned=%s", sysname, cloned);*/

		if (strncmp(sysname, "vif-", 4) == 0)
			do_vif_hotplug(dev);//TODO check?

		else if (strncmp(sysname, "vbd", 3) == 0)
			do_vbd_hotplug(dev);

unref_dev:
		udev_device_unref(dev);
	}

out:
	return (void *) rc;
}

int udev_start(void)
{
	int rc;

	rc = pthread_create(&udev_thread, NULL, &udev_loop, NULL);
	if (rc != 0) {
		PERROR("Error calling pthread_create() rc=%d", rc);
		goto out;
	}

	udev_thread_started = true; /* TODO race */

out:
	return rc;
}

int udev_stop(void)
{
	void *res;
	int rc = 0;

	if (!udev_thread_started) /* TODO race */
		goto out;

	rc = pthread_cancel(udev_thread);
	if (rc != 0) {
		PERROR("Error calling pthread_cancel() rc=%d", rc);
		goto out;
	}

	rc = pthread_join(udev_thread, &res);
	if (rc != 0) {
		PERROR("Error calling pthread_join() rc=%d", rc);
		goto out;
	}

	if (res == PTHREAD_CANCELED)
		INFO("udev_stop(): thread was canceled");
	else
		INFO("udev_stop(): thread wasn't canceled (shouldn't happen!)");

	udev_thread_started = false;

out:
	return rc;
}
