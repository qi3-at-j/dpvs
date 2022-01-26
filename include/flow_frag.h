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
#ifndef __TYFLOW_FLOW_FRAG_H__
#define __TYFLOW_FLOW_FRAG_H__

#include "flow.h"

/* fragment control block */

typedef struct {
    uint32_t src_ip;
    uint32_t src_ip3[3];
    uint32_t dst_ip;
    uint32_t dst_ip3[3];
    uint32_t ipid;
    uint8_t  protocol;
    uint8_t  family;
    uint8_t  resv[2];
} fcb_key_t;

typedef struct fcb_ {
    /* hash list to match fcb */
    struct hlist_node hnode;
    /* timer node to ager fcb */
    struct list_head tnode;
    fcb_key_t key;
    conn_sub_t *csp;
} fcb_t;

#define FCB_MAX_TIMER 4
#define FCB_MAX_TO_BE_FREED 1024
/* 
 * the timer will be called with flow connection ager which 
 * is 2 seconds, so the max life time will be FCB_MAX_TIMER*2
 */
typedef struct {
    struct list_head head;
} fcb_timer_t[FCB_MAX_TIMER];

#define FLOW_FCB_ENTRY_MAX_NUMBER (FLOW_CONN_MAX_NUMBER>>2)
#define FLOW_FCB_HASH_TAB_SIZE (FLOW_FCB_ENTRY_MAX_NUMBER>>1)
#define FLOW_FCB_HASH_TAB_MASK (FLOW_FCB_HASH_TAB_SIZE-1)

#ifdef TYFLOW_PER_THREAD
/* per lcore fragment control block pool */
RTE_DECLARE_PER_LCORE(fcb_t *, fcbPoolBase);
/* per lcore fragment control block poll head */
RTE_DECLARE_PER_LCORE(fcb_t *, fcbPoolHead);
/* per lcore fragment control block hash table */
RTE_DECLARE_PER_LCORE(struct hlist_head *, fcbHashTable);
/* per lcore fragment control block timer */
RTE_DECLARE_PER_LCORE(fcb_timer_t, fcbTimer);
#else
extern fcb_t *fcbPoolBase;
extern fcb_t *fcbPoolHead;
extern rte_spinlock_t fcbPoolHead_sl;
extern struct hlist_head *fcbHashTable;
extern rte_rwlock_t *fcbHash_rwl;
#endif

#ifdef TYFLOW_PER_THREAD
#define this_fcbPoolBase  (RTE_PER_LCORE(fcbPoolBase))
#define this_fcbPoolHead  (RTE_PER_LCORE(fcbPoolHead))
#define this_fcbHashTable (RTE_PER_LCORE(fcbHashTable))
#else
#define this_fcbPoolBase  fcbPoolBase
#define this_fcbPoolHead  fcbPoolHead
#define this_fcbHashTable fcbHashTable
#define this_fcbHash_rwl  fcbHash_rwl
#endif
#define this_fcbTimer     (RTE_PER_LCORE(fcbTimer))

static inline int
_ip_frag_hash(uint32_t s, uint32_t d, uint32_t id)
{
    register uint32_t hash;

    hash = s ^ d ^ id;
    return hash;
}

extern void
fcp_init_key_from_lhdr(MBUF_IP_HDR_S *lhdr, fcb_key_t *key);
extern int
flow_defrag_nonfirst_vector(struct rte_mbuf *mbuf);
extern int
flow_defrag_first_vector(struct rte_mbuf *mbuf);
extern int
flow_fcb_ager(void);
extern void
flow_fcb_ager_init(void);
extern int
flow_fcb_init(uint32_t cid);

#endif /* __TYFLOW_FLOW_FRAG_H__ */
