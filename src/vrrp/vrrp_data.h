/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
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

#ifndef _VRRP_DATA_H
#define _VRRP_DATA_H

/* system includes */
#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>

#include <rte_rwlock.h>

/* local includes */
#include "list.h"

/* Configuration data root */
typedef struct _vrrp_data {
	vrrp_t          vrrp;           /* The vrrp instance */
	thread_ref_t	thread;         /* vrrp_read_dispatcher_thread */
	unsigned		garp_interval;
	unsigned		gna_interval;
	unsigned	    vrrp_startup_delay;
	bool            enable;
	int             fd_cfg_chg;     /* eventfd for notifying configuration change */
} vrrp_data_t;

/* Configuration changes, need to sync to vrrp_data */
typedef struct _vrrp_conf_chg {
    rte_rwlock_t    rwlock;
	void		    *ifp;			  /* Interface we belong to */
	uint32_t		unicast_peer;	  /* The peer to send unicast advert to */
	uint8_t			vrid;			  /* virtual id. from 1(!) to 255 */
	uint8_t			base_priority;	  /* configured priority value */
	uint32_t		vip;			  /* virtual ip addresse */
	uint32_t		vip6[4];	      /* virtual ipv6 addresse */
	unsigned		adver_int;		  /* Seconds*TIMER_HZ, locally configured delay between advertisements*/
	bool			preempt;		  /* true if higher prio preempts lower */
	unsigned long	preempt_delay;	  /* Seconds*TIMER_HZ after startup until
         							   * preemption based on higher prio over lower
         							   * prio is allowed.  0 means no delay.
         							   */
	bool            enable;           /* enabled or disabled */
	bool            changed;          /* vrrp_conf_chg is different from vrrp_data */
} vrrp_conf_chg_t;

/* Global Vars exported */
extern vrrp_data_t *vrrp_data;
extern void *vrrp_buffer;
extern size_t vrrp_buffer_len;

/* prototypes */
extern void alloc_vrrp_buffer(size_t);

extern void show_vrrp_stats_proc(void *cmdline, bool clear_stats);

extern void show_vrrp_proc(void *cmdline);

extern void init_vrrp_data(void);

#endif
