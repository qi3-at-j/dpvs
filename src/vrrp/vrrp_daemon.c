/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP child process handling.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include <sched.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <rte_lcore.h>

#ifdef THREAD_DUMP
#include "scheduler.h"
#endif
#include "vrrp_daemon.h"
#include "vrrp_scheduler.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_parser.h"
#include "vrrp.h"
#include "../lib/logger.h"
#include "memory.h"
#include "list.h"


/* VRRP thread init sequence */
static void
start_vrrp(void)
{
    vrrp_sync_conf();

	/* Set our copy of time */
	set_time_now();

	/* Init & start the VRRP packet dispatcher */
	if (vrrp_data->vrrp_startup_delay) {
		vrrp_delayed_start_time = timer_add_long(time_now, vrrp_data->vrrp_startup_delay);
		log_message(LOG_INFO, "Delaying startup for %g seconds", vrrp_data->vrrp_startup_delay / TIMER_HZ_DOUBLE);
	}
	thread_add_event(master, vrrp_dispatcher_init, NULL, 0);

	/* Complete VRRP initialization */
	vrrp_complete_init();

	vrrp_restore_interfaces_startup();

#if 0
	/* Set the process priority and non swappable if configured */
	set_process_priorities(global_data->vrrp_realtime_priority, global_data->max_auto_priority, global_data->min_auto_priority_delay,
			       global_data->vrrp_rlimit_rt, global_data->vrrp_process_priority, global_data->vrrp_no_swap ? 4096 : 0);

	/* Set the process cpu affinity if configured */
	set_process_cpu_affinity(&global_data->vrrp_cpu_mask, "vrrp");
#endif

    return;
}

#ifdef THREAD_DUMP
static void
register_vrrp_thread_addresses(void)
{
	/* Remove anything we might have inherited from parent */
	deregister_thread_addresses();

	register_scheduler_addresses();

	register_vrrp_scheduler_addresses();
}
#endif

/* The entry point of VRRP thread */
static void *
vrrp_thread_entry(void *args)
{
	/* Create the new master thread */
	master = thread_make_master();

	/* Start VRRP thread */
	start_vrrp();

	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

	return NULL;
}

/* The VRRP thread */
static pthread_t vrrp_thread_id;
int
vrrp_job_start(void)
{
	int ret;
	
	ret = pthread_create(&vrrp_thread_id, NULL, vrrp_thread_entry, NULL);
	if (ret) {
		log_message(LOG_ERR, "Error creating vrrp thread.");
		return -1;
	}

	ret = rte_thread_setname(vrrp_thread_id, "vrrp");
	if (ret < 0)
		log_message(LOG_ERR, "Error setting name for vrrp thread.");

	return 0;
}

