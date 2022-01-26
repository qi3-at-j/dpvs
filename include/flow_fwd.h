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
 */

#ifndef __TYFLOW_FLOW_FWD_H__
#define __TYFLOW_FLOW_FWD_H__

extern uint8_t flow_worker_hash[UINT8_MAX];
extern int flow_worker_num;

static inline uint8_t
flow_fwd_hash(uint32_t sip, uint32_t dip, uint8_t protocol)
{
    uint8_t hash;
    hash = sip >> 24;
    hash = hash ^ (sip >> 16);
    hash = hash ^ (sip >> 8);
    hash = hash ^ sip;
    hash = hash ^ (dip >> 24);
    hash = hash ^ (dip >> 16);
    hash = hash ^ (dip >> 8);
    hash = hash ^ dip;
    hash = hash ^ protocol;
    return flow_worker_hash[hash];
}

int
flow_fwd_enq(lcoreid_t sid, lcoreid_t did, struct rte_mbuf *mbuf);
struct rte_mbuf *
flow_fwd_deq(lcoreid_t sid, lcoreid_t did);
void
flow_flush_fwd_q(lcoreid_t did);
int
flow_fwd_init_lcore(lcoreid_t cid);
int
flow_fwd_init(void);
#endif /* __TYFLOW_FLOW_FWD_H__ */
