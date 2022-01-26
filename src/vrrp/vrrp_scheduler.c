/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Sheduling framework for vrrp code.
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

#include <errno.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <rte_mbuf.h>

#include "vrrp_scheduler.h"
#include "vrrp_data.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
//#include "global_data.h"
#include "memory.h"
#include "list.h"
#include "../lib/logger.h"
//#include "main.h"
//#include "signals.h"
//#include "utils.h"
//#include "bitops.h"


/* global vars */
timeval_t garp_next_time;
thread_ref_t garp_thread;
bool vrrp_initialised;
timeval_t vrrp_delayed_start_time;

#ifdef _TSM_DEBUG_
bool do_tsm_debug;
#endif

/* VRRP FSM (Finite State Machine) design.
 *
 * The state transition diagram implemented is :
 *
 *                         +---------------+
 *        +----------------|               |----------------+
 *        |                |     Fault     |                |
 *        |  +------------>|               |<------------+  |
 *        |  |             +---------------+             |  |
 *        |  |                     |                     |  |
 *        |  |                     V                     |  |
 *        |  |             +---------------+             |  |
 *        |  |  +--------->|               |<---------+  |  |
 *        |  |  |          |  Initialize   |          |  |  |
 *        |  |  |  +-------|               |-------+  |  |  |
 *        |  |  |  |       +---------------+       |  |  |  |
 *        |  |  |  |                               |  |  |  |
 *        V  |  |  V                               V  |  |  V
 *     +---------------+                       +---------------+
 *     |               |---------------------->|               |
 *     |    Master     |                       |    Backup     |
 *     |               |<----------------------|               |
 *     +---------------+                       +---------------+
 */

static void vrrp_read_dispatcher_thread(thread_ref_t);

/*
 * Initialize state handling
 * --rfc2338.6.4.1
 */
void
vrrp_init_state(vrrp_t *vrrp)
{
	int vrrp_begin_state = vrrp->state;

	set_time_now();

	if (vrrp->wantstate == VRRP_STATE_MAST) {
		/* The simplest way to become master is to timeout from the backup state
		 * very quickly (1usec) */
		vrrp->state = VRRP_STATE_BACK;
		vrrp->ms_down_timer = 1;
	} else {
		vrrp->ms_down_timer = VRRP_MS_DOWN_TIMER(vrrp);

		/* Set interface state */
		vrrp_restore_interface(vrrp, false, false);

        vrrp_state_refresh(VRRP_STATE_BACK);
		if (vrrp->state != VRRP_STATE_BACK) {
			log_message(LOG_INFO, "(%s) Entering BACKUP STATE (init)", vrrp->iname);
			vrrp->state = VRRP_STATE_BACK;
		}

		if (vrrp_begin_state != vrrp->state) {
			vrrp->last_transition = timer_now();
		}
	}
}

/* Declare vrrp_timer_cmp() rbtree compare function */
RB_TIMER_CMP(vrrp);

/* Compute the new instance sands */
void
vrrp_init_instance_sands(vrrp_t *vrrp)
{
	set_time_now();

	if (vrrp->state == VRRP_STATE_MAST) {
		vrrp->sands = timer_add_long(time_now, vrrp->adver_int);
	}
	else if (vrrp->state == VRRP_STATE_BACK) {
		/*
		 * When in the BACKUP state the expiry timer should be updated to
		 * time_now plus the Master Down Timer, when a non-preemptable packet is
		 * received.
		 */
		if (vrrp_delayed_start_time.tv_sec) {
			if (timercmp(&time_now, &vrrp_delayed_start_time, <))
				vrrp->sands = timer_add_long(vrrp_delayed_start_time, vrrp->ms_down_timer);
			else {
				/* If we clear the delayed_start_time once past, then
				 * the code will be slightly more efficient */
				if (time_now.tv_sec > vrrp_delayed_start_time.tv_sec)
					vrrp_delayed_start_time.tv_sec = 0;
				vrrp->sands = timer_add_long(time_now, vrrp->ms_down_timer);
			}
		} else
			vrrp->sands = timer_add_long(time_now, vrrp->ms_down_timer);
	}
	else if (vrrp->state == VRRP_STATE_FAULT || vrrp->state == VRRP_STATE_INIT)
		vrrp->sands.tv_sec = TIMER_DISABLED;

	/*rb_move_cached(&vrrp->sockets->rb_sands, vrrp, rb_sands, vrrp_timer_cmp);*/
}

void
vrrp_init_sands(vrrp_t *vrrp)
{
	vrrp->sands.tv_sec = TIMER_DISABLED;
	vrrp_init_instance_sands(vrrp);
}

/* Get the earliest sands of all vrrp instances */
static timeval_t *
vrrp_compute_timer(void)
{
    vrrp_t *vrrp = &vrrp_data->vrrp;
    
    return &vrrp->sands;
}

/* Thread functions */
static void
vrrp_register_workers(void)
{
	/* Init the VRRP instances state */
	vrrp_init_state(&vrrp_data->vrrp);

	/* Init VRRP instances sands */
	vrrp_init_sands(&vrrp_data->vrrp);

    /* Register single VRRP worker thread */
    vrrp_data->thread = thread_add_read_sands(master, vrrp_read_dispatcher_thread,
						       NULL, 0, vrrp_compute_timer(), 0);
}

static inline int
vrrp_vrid_cmp(const vrrp_t *v1, const vrrp_t *v2)
{
	return less_equal_greater_than(v1->vrid, v2->vrid);
}

void
vrrp_dispatcher_init(__attribute__((unused)) thread_ref_t thread)
{
	/* register read dispatcher worker thread */
	vrrp_register_workers();

	vrrp_initialised = true;
}

static void
vrrp_goto_master(vrrp_t * vrrp)
{
	/* handle master state transition */
	vrrp->wantstate = VRRP_STATE_MAST;
	vrrp_state_goto_master(vrrp);
}

/* Handle dispatcher read timeout */
static void
vrrp_dispatcher_read_timeout(void)
{
	vrrp_t *vrrp = &vrrp_data->vrrp;
	
	set_time_now();

		if (vrrp->sands.tv_sec == TIMER_DISABLED ||
		    timercmp(&vrrp->sands, &time_now, >))
		return;

	if (vrrp->state == VRRP_STATE_BACK) {
		#if 0
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s) Receive advertisement timeout", vrrp->iname);
		#endif
		vrrp_goto_master(vrrp);
	}
	else if (vrrp->state == VRRP_STATE_MAST)
		vrrp_state_master_tx(vrrp);

	vrrp_init_instance_sands(vrrp);

	return ;
}

static void vrrp_dispatcher_read_proc(void *pmbuf)
{
	vrrp_t *vrrp = &vrrp_data->vrrp;
	const vrrphdr_t *hd;
	const struct iphdr *iph;
    struct rte_mbuf *mbuf = pmbuf;
	uint32_t len = mbuf->pkt_len;
	
	/* Check the received data includes at least the IP, possibly
	 * the AH header and the VRRP header */
	if (!(hd = vrrp_get_header(mbuf, len)))
	    return;
	
	/* No instance found => ignore the advert */
	if (hd->vrid != vrrp->vrid) {
		//if (global_data->log_unknown_vrids)
			log_message(LOG_INFO, "Unknown VRID(%d) received. ignoring...", hd->vrid);
		return;
	}

	if (vrrp->state == VRRP_STATE_INIT) {
		/* We just ignore a message received when we are in fault state or
		 * not yet fully initialised */
		return;
	}
	
	/* Save non packet data */
	iph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, 0);
	vrrp->pkt_saddr = iph->saddr;
	
	if (vrrp->state == VRRP_STATE_BACK)
		vrrp_state_backup(vrrp, hd, mbuf, len);
	else if (vrrp->state == VRRP_STATE_MAST) {
		if (vrrp_state_master_rx(vrrp, hd, mbuf, len))
			vrrp_state_leave_master(vrrp, false);
	} else
		log_message(LOG_INFO, "(%s) In dispatcher_read with state %d"
				    , vrrp->iname, vrrp->state);

	/* If we have sent an advert, reset the timer */
	if (vrrp->state != VRRP_STATE_MAST)
		vrrp_init_instance_sands(vrrp);

	return ;
}

/* Handle dispatcher read packet */
extern void vrrp_dispatcher_read(void *pmbuf);
void vrrp_dispatcher_read(void *pmbuf)
{
	vrrp_dispatcher_read_proc(pmbuf);

	rte_pktmbuf_free_bulk(&pmbuf, 1);

	return ;
}

/* Our read packet dispatcher */
static void
vrrp_read_dispatcher_thread(thread_ref_t thread)
{
	/* Dispatcher state handler */
	if (thread->type == THREAD_READ_TIMEOUT)
		vrrp_dispatcher_read_timeout();

	/* register next dispatcher thread */
    vrrp_data->thread = thread_add_read_sands(thread->master, vrrp_read_dispatcher_thread,
						       NULL, 0, vrrp_compute_timer(), 0);
}

#ifdef THREAD_DUMP
void
register_vrrp_scheduler_addresses(void)
{
	register_thread_address("vrrp_dispatcher_init", vrrp_dispatcher_init);
	register_thread_address("vrrp_read_dispatcher_thread", vrrp_read_dispatcher_thread);
}
#endif
