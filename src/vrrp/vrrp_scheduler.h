/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_scheduler.c include file.
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

#ifndef _VRRP_SCHEDULER_H
#define _VRRP_SCHEDULER_H

/* system include */
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

/* local includes */
#include "../lib/scheduler.h"
#include "timer.h"
#include "vrrp.h"
#include "vrrp_data.h"

/* global vars */
extern timeval_t garp_next_time;
extern thread_ref_t garp_thread;
extern bool vrrp_initialised;
extern timeval_t vrrp_delayed_start_time;


/* extern prototypes */
extern void vrrp_init_instance_sands(vrrp_t *);
extern void vrrp_dispatcher_init(thread_ref_t);
extern void vrrp_init_sands(vrrp_t *vrrp);
extern void vrrp_init_state(vrrp_t *vrrp);
#endif
