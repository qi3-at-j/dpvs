/*
 * Copyright (C) 2021 TYyun.
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

#ifndef	__MFILTER_H__
#define	__MFILTER_H__

#include <stdint.h>
#include "flow.h"

#define MAX_MFILTER_NUM 8

typedef struct mfilter_ent_ {
    struct rte_ether_addr d_addr;
    struct rte_ether_addr s_addr;
    char dev_name[IFNAMSIZ];
    int    in_out;
    uint32_t dev_id;
    uint16_t ether_type;
} mfilter_ent_t;

extern uint32_t total_mfilter;
extern mfilter_ent_t mfilter_ent[];

RTE_DECLARE_PER_LCORE(uint32_t, mfilter_show_this_pak);
#define this_mfilter_show_this_pak (RTE_PER_LCORE(mfilter_show_this_pak))

extern void mfilter_init (void);

void 
mac_filter_init (void);

int 
mac_match_filter (int node, struct rte_mbuf *mbuf);


/*
 * turn on debug for this packet if flow debug is on,
 * and packet matches filter conditions.
 */


#endif /* __MFILTER_H__ */

