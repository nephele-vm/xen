/******************************************************************************
 * Daemon functionality
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
#include <stdint.h>
#include <getopt.h>
#include <signal.h>
#include <sys/mman.h>
#include <xenevtchn.h>
#include <xengnttab.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xenstore.h>
#include "log.h"
#include "os.h"
#include "udev.h"
#include "ovs.h"
#include "clone.h"
#include "xencloned.h"
#include "network.h"
#include "9pfs.h"
#include "cache.h"

static bool daemonize = false;
extern bool leave_clones_paused;
extern bool skip_io_cloning;
extern bool use_page_sharing_info_pool;
extern bool xs_deep_copy;

static xenevtchn_handle *xev_handle = NULL;
xengnttab_handle *xgt_handle = NULL;
xc_interface *xc_handle = NULL;
struct xs_handle *xs_handle = NULL;
xentoollog_logger *xtl_handle = NULL;

static evtchn_port_t virq_port = ~0;


static void cleanup(void)
{
	if (do_cache_parents)
		caching_fini();
	udev_fini();
	p9fs_fini();
	networking_fini();

	cloning_fini();//TODO

	if (xgt_handle) {
		xengnttab_close(xgt_handle);
		xgt_handle = NULL;
	}
	if (virq_port != ~0) {
		xenevtchn_unbind(xev_handle, virq_port);
		virq_port = ~0;
	}
	if (xev_handle) {
		xenevtchn_close(xev_handle);
		xev_handle = NULL;
	}
	if (xs_handle) {
		xs_daemon_close(xs_handle);
		xs_handle = NULL;
	}
	if (xc_handle) {
		xc_interface_close(xc_handle);
		xc_handle = NULL;
	}
	if (xtl_handle) {
		xtl_logger_destroy(xtl_handle);
		xtl_handle = NULL;
	}
}

static bool running = false;

static void closing_signal_handler(int signo)
{
	//cleanup(); /* enable for valgrind */
	running = false;
}

static int set_signal_handlers(void)
{
	struct sigaction sa;
	int rc;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = closing_signal_handler;

	rc = sigaction(SIGQUIT, &sa, NULL);
	if (rc)
		goto out;
	rc = sigaction(SIGINT, &sa, NULL);
	if (rc)
		goto out;
	rc = sigaction(SIGTERM, &sa, NULL);
	if (rc)
		goto out;

out:
	return rc;
}

static void print_usage(char *cmd)
{
	printf("Usage: %s [OPTION]..\n", cmd);
	printf("\n");
	printf("Options:\n");
	printf("-D, --daemon                  Run in background\n");
	printf("-h, --help                    Display this help and exit\n");
	printf("-c, --cache                   Cache parents info\n");
	printf("-o, --ovs-instantiation_type (library|command)  OVS instantiation type [default: library]\n");
	printf("-p, --paused                  Leave clones in paused state\n");
	printf("-r, --ring-pages-num <num>    Ring pages number [default: 1]\n");
	printf("-s, --selection-method (hash|round-robin)    Selection method for OVS group buckets [default: hash]\n");
	printf("-n, --no-io                   Skip cloning IO\n");
	printf("-x, --use-page-sharing-info-pool   Use page-sharing-info pool\n");
	printf("-d, --xenstore-deep-copy      Xenstore deep copy\n");
	printf("-R, --reset                   Reset\n");
}

static int parse_args(int argc, char **argv)
{
	int opt, opt_index, rc = 0;
	const char *short_opts = "hDco:pr:s:nxdR";
	const struct option long_opts[] = {
		{ "help"               , no_argument       , NULL , 'h' },
		{ "daemon"             , no_argument       , NULL , 'D' },
		{ "cache"              , no_argument       , NULL , 'c' },
		{ "ovs-instantiation_type", required_argument , NULL , 'o' },
		{ "paused"             , no_argument       , NULL , 'p' },
		{ "ring-pages-num"     , required_argument , NULL , 'r' },
		{ "selection-method"   , required_argument , NULL , 's' },
		{ "no-io"              , no_argument       , NULL , 'n' },
		{ "use-page-sharing-info-pool", no_argument, NULL , 'x' },
		{ "xenstore-deep-copy" , no_argument,        NULL , 'd' },
		{ "reset"              , no_argument,        NULL , 'R' },
		{ NULL , 0 , NULL , 0 }
	};

	while (1) {
		opt = getopt_long(argc, argv, short_opts, long_opts, &opt_index);
		if (opt == -1)
			break;

		switch (opt) {
		case 'D':
			daemonize = true;
			break;

		case 'c':
			do_cache_parents = true;
			break;

		case 'h':
			print_usage(argv[0]);
			exit(0);
			break;

		case 'o': {
			rc = ovs_set_instantiation_type(optarg);
			if (rc) {
				print_usage(argv[0]);
				exit(-1);
			}
			break;
		}

		case 'p':
			leave_clones_paused = true;
			break;

		case 'r': {
			int n;

			n = atoi(optarg);
			if (!(n > 0)) {
				fprintf(stderr, "Invalid ring pages number: %d\n", n);
				exit(-1);
			}
			ring_pages_num = n;
			break;
		}

		case 's': {
			rc = ovs_set_selection_method(optarg);
			if (rc) {
				print_usage(argv[0]);
				exit(-1);
			}
			break;
		}

		case 'n':
			skip_io_cloning = true;
			break;

		case 'x':
			use_page_sharing_info_pool = true;
			break;

		case 'd':
			xs_deep_copy = true;
			break;

		case 'R': {
			xc_handle = xc_interface_open(xtl_handle, xtl_handle, 0);
			if (xc_handle == NULL) {
				PERROR("Failed to open xc interface");
				exit(-1);
			}

			rc = xc_cloning_disable(xc_handle);
			if (rc) {
				PERROR("Error calling xc_cloning_disable() rc=%d", rc);
			}

			xc_interface_close(xc_handle);
			xc_handle = NULL;
			exit(rc);
			break;
		}

		default:
			rc = -1;
			break;
		}
	}

	while (optind < argc) {
		printf("%s: invalid argument \'%s\'\n", argv[0], argv[optind]);
		rc = -1;
		optind++;
	}

	if (rc) {
		print_usage(argv[0]);
		exit(rc);
	}

	return rc;
}

extern bool notification_ring_is_empty(void);


int main(int argc, char *argv[])
{
	evtchn_port_t port;
	int rc = -1;

	xtl_handle = (xentoollog_logger *) xtl_createlogger_stdiostream(stderr,
			XTL_DEBUG, XTL_STDIOSTREAM_SHOW_DATE);
	if (xtl_handle == NULL) {
		perror("Failed to create logger");
		goto out;
	}

	/* Parse arguments */
	rc = parse_args(argc, argv);
	assert(rc == 0);

	atexit(cleanup);

	rc = set_signal_handlers();
	if (rc) {
		perror("Failed to set signal handlers");
		goto out;
	}

	if (daemonize) {
		rc = daemon(0, 0);
		if (rc) {
			perror("Error calling daemon()");
			goto out;
		}
	}

	xc_handle = xc_interface_open(xtl_handle, xtl_handle, 0);
	if (xc_handle == NULL) {
		PERROR("Failed to open xc interface");
		goto out;
	}

	xs_handle = xs_daemon_open();
	if (xs_handle == NULL) {
		PERROR("Failed to open xenstore connection");
		goto out;
	}

	xev_handle = xenevtchn_open(xtl_handle, 0);
	if (xev_handle == NULL) {
		PERROR("Failed to open evtchn device");
		goto out;
	}

	rc = xenevtchn_bind_virq(xev_handle, VIRQ_CLONED);
	if (rc == -1) {
		PERROR("Failed to bind VIRQ_CLONED");
		goto out;
	}
	virq_port = rc;

	xgt_handle = xengnttab_open(xtl_handle, 0);
	if (xgt_handle == NULL) {
		PERROR("Failed to open connection to gnttab");
		goto out;
	}

	rc = networking_init();
	if (rc) {
		PERROR("Error calling networking_init() rc=%d", rc);
		goto out;
	}

	rc = p9fs_init();
	if (rc) {
		PERROR("Error calling p9fs_init() rc=%d", rc);
		goto out;
	}

	rc = udev_init();
	if (rc) {
		PERROR("Error calling udev_init() rc=%d", rc);
		goto out;
	}

	rc = udev_start();
	if (rc) {
		PERROR("Error calling udev_start() rc=%d", rc);
		goto out;
	}

	rc = cloning_init();
	if (rc) {
		PERROR("Failed initializing cloning subsystem");
		goto out;
	}

	if (do_cache_parents) {
		rc = caching_init();
		if (rc) {
			PERROR("Failed initializing caching subsystem");
			goto out;
		}
	}

#if XENCLONED_MEASUREMENTS
	rc = run_cmd_redirected(DOM0_MEM_CONSUMPTION_SCRIPT,
			DOM0_MEM_CONSUMPTION_CSV, "w");
	if (rc) {
		PERROR("Failed writing memory consumption info");
		goto out;
	}
#endif

	running  = true;
	while (running) {
		port = xenevtchn_pending(xev_handle);
		if (port == -1) {
			PERROR("Failed to listen for pending event channel");
			goto out;
		}

		if (port != virq_port) {
			PERROR("Wrong port, got %d expected %d", port, virq_port);
			goto out;
		}

		rc = xenevtchn_unmask(xev_handle, port);
		if (rc == -1) {
			PERROR("Failed to unmask port");
			goto out;
		}

		while (!notification_ring_is_empty())
			handle_cloning();
	}

	rc = 0;

out:
	return rc;
}
