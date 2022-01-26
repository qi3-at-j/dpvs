/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        memory.c include file.
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.net>
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

#ifndef _MEMORY_H
#define _MEMORY_H

#include <rte_malloc.h>


/* Local defines */
#define PMALLOC(p)	{ p = rte_zmalloc(NULL, sizeof(*p), 0); }
/* Common defines */
typedef union _ptr_hack {
	void *p;
	const void *cp;
} ptr_hack_t;

#define FREE_CONST(ptr) { ptr_hack_t ptr_hack = { .cp = ptr }; rte_free(ptr_hack.p); ptr = NULL; }

#endif
