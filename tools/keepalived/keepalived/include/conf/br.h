/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __DPVS_BR_CONF_H__
#define __DPVS_BR_CONF_H__
#include <stdint.h>
#include <net/if.h>
#include "conf/sockopts.h"

struct br_port_info{
	char        ifName[IFNAMSIZ];
};

struct br_param {
	bool is_br;
	uint8_t     port_nb;
    char        brName[IFNAMSIZ];   /* bridge name eg. br0 */
	char        ifName[IFNAMSIZ];
	struct br_port_info br_port_infos[0];
} __attribute__((__packed__));

struct br_param_array {
    int         nparam;
    struct br_param params[0];
};

#endif /* __DPVS_BR_CONF_H__ */

