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
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "dpdk.h"
#include "conf/common.h"
#include "netif.h"
#include "netif_addr.h"
#include "ctrl.h"
#include "list.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"
#include "timer.h"
#include "parser/parser.h"
#include "neigh.h"
#include "scheduler.h"

#include <rte_arp.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "ipv4.h"
#include "ipv6.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "flow.h"
#include "debug_flow.h"
#include "flow_cli.h"
#include "flow_frag.h"

#ifdef TYFLOW_PER_THREAD
/* per lcore fragment control block pool */
RTE_DEFINE_PER_LCORE(fcb_t *, fcbPoolBase);
/* per lcore fragment control block poll head */
RTE_DEFINE_PER_LCORE(fcb_t *, fcbPoolHead);
/* per lcore fragment control block hash table */
RTE_DEFINE_PER_LCORE(struct hlist_head *, fcbHashTable);
#else
fcb_t *fcbPoolBase;
fcb_t *fcbPoolHead;
rte_spinlock_t fcbPoolHead_sl;
struct hlist_head *fcbHashTable;
rte_rwlock_t *fcbHash_rwl;
#endif
/* per lcore fragment control block timer */
RTE_DEFINE_PER_LCORE(fcb_timer_t, fcbTimer);

static inline uint32_t
ip_frag_hash(fcb_key_t *key)
{
    register uint32_t hash;

    hash = _ip_frag_hash(key->src_ip, key->dst_ip, key->ipid);

    return (hash & FLOW_FCB_HASH_TAB_MASK);
}

static inline uint32_t
ip6_frag_hash(fcb_key_t *key)
{
    register uint32_t hash;

    hash  = _ip_frag_hash(key->src_ip, key->dst_ip, key->src_ip3[0]);
    hash ^= _ip_frag_hash(key->dst_ip3[0], key->src_ip3[1], key->dst_ip3[1]);
    hash ^= _ip_frag_hash(key->src_ip3[2], key->dst_ip3[2], key->ipid);

    return (hash & FLOW_FCB_HASH_TAB_MASK);
}

/*
 *	fcb entry to id.
 */
static inline uint32_t fcb2id(fcb_t *fcb)
{
	return (fcb? (fcb-this_fcbPoolBase):-1);
}

static inline fcb_t *
_alloc_fcb(void)
{
    fcb_t *fcb = NULL;

#ifndef TYFLOW_PER_THREAD
    rte_spinlock_lock(&fcbPoolHead_sl);
#endif
    if (this_fcbPoolHead) {
        fcb = this_fcbPoolHead;
        this_fcbPoolHead = (fcb_t *)this_fcbPoolHead->hnode.next;
    }
#ifndef TYFLOW_PER_THREAD
    rte_spinlock_unlock(&fcbPoolHead_sl);
#endif

    return fcb;
}

static fcb_t *
flow_create_fcb(fcb_key_t *key)
{
    fcb_t *fcb;

    fcb = _alloc_fcb();
    if (!fcb) {
        flow_print_basic("   no free fcb\n");
        this_flow_counter[FLOW_ERR_FCB_NO].counter++;
        return NULL;
    }

    memcpy(&fcb->key, key, sizeof(*key));
    fcb->csp = NULL;
    flow_print_basic("   flow create fcb %d\n", fcb2id(fcb));

    return fcb;
}

static inline void
_free_fcb(fcb_t *fcb)
{
#ifndef TYFLOW_PER_THREAD
    rte_spinlock_lock(&fcbPoolHead_sl);
#endif
    if (this_fcbPoolHead) {
        fcb->hnode.next = (struct hlist_node *)this_fcbPoolHead;
    }

    this_fcbPoolHead = fcb;
#ifndef TYFLOW_PER_THREAD
    rte_spinlock_unlock(&fcbPoolHead_sl);
#endif
}

static void
flow_free_fcb(fcb_t *fcb)
{
    memset(fcb, 0, sizeof(*fcb));
    _free_fcb(fcb);
}

static void
fcb_insert_to_hash(fcb_t *fcb, uint32_t hash)
{
#ifdef TYFLOW_PER_THREAD
    hlist_add_head(&fcb->hnode, this_fcbHashTable+hash);
#else
    rte_rwlock_write_lock(this_fcbHash_rwl+hash);
    hlist_add_head(&fcb->hnode, this_fcbHashTable+hash);
    rte_rwlock_write_unlock(this_fcbHash_rwl+hash);
#endif
}

static void
fcb_remove_from_hash(fcb_t *fcb)
{
#ifndef TYFLOW_PER_THREAD
    uint32_t hash;
    if (fcb->key.family == AF_INET6) {
        hash = ip6_frag_hash(&fcb->key);
    } else {
        hash = ip_frag_hash(&fcb->key);
    }
    rte_rwlock_write_lock(this_fcbHash_rwl+hash);
#endif
    hlist_del(&fcb->hnode);
#ifndef TYFLOW_PER_THREAD
    rte_rwlock_write_unlock(this_fcbHash_rwl+hash);
#endif
}

static void
fcb_insert_to_time(fcb_t *fcb)
{
    list_add_tail(&fcb->tnode, &this_fcbTimer[FCB_MAX_TIMER-1].head);
}

static void __rte_unused
fcb_remove_from_time(fcb_t *fcb)
{
    list_del(&fcb->tnode);
}

static fcb_t *
flow_match_fcb(fcb_key_t *key, uint32_t hash)
{
    fcb_t *fcb = NULL;
    fcb_t *fcb_hit = NULL;
    struct hlist_head *head = this_fcbHashTable + hash;

#ifndef TYFLOW_PER_THREAD
    rte_rwlock_read_lock(this_fcbHash_rwl+hash);
#endif
    hlist_for_each_entry(fcb, head, hnode) {
        if (!memcmp(&fcb->key, key, sizeof(*key))) {
            /* found */
            fcb_hit = fcb;
            break;
        }
    }

#ifndef TYFLOW_PER_THREAD
    rte_rwlock_read_unlock(this_fcbHash_rwl+hash);
#endif
    return fcb_hit;
}

void
fcp_init_key_from_lhdr(MBUF_IP_HDR_S *lhdr, fcb_key_t *key)
{
    ipv6_addr_copy((struct in6_addr *)&key->src_ip, (struct in6_addr *)lhdr->lhdr_src_ip_6);
    ipv6_addr_copy((struct in6_addr *)&key->dst_ip, (struct in6_addr *)lhdr->lhdr_dst_ip_6);
    key->ipid = lhdr->ipid;
    key->protocol = lhdr->ucNextHdr;
    key->family = lhdr->ucIsIpv6?AF_INET6:AF_INET;
    key->resv[0] = 0;
    key->resv[1] = 0;
} 

int
flow_defrag_nonfirst_vector(struct rte_mbuf *mbuf)
{
    uint32_t hash;
    fcb_key_t tmp;
    fcb_key_t *key;
    fcb_t *fcb;
    flow_connection_t *fcp;
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;

    flow_print_basic("%s entry\n", __FUNCTION__);

    key = &tmp;
    fcp_init_key_from_lhdr(lhdr, key);
    if (lhdr->ucIsIpv6) {
        hash = ip6_frag_hash(key);
    } else {
        hash = ip_frag_hash(key);
    }

    fcb = flow_match_fcb(key, hash);
    /* non-first fragment should match one fcb */
    if (!fcb) {
        flow_print_basic("  non-first fragment match no fcb\n");
        this_flow_counter[FLOW_ERR_FCB_NO_MATCH].counter++;
        return -1;
    }

    if (!fcb->csp) {
        flow_print_basic("  fcb %d have no csp\n", fcb2id(fcb));
        this_flow_counter[FLOW_ERR_FCB_NO_CSP].counter++;
        return -1;
    }

    fcp = csp2base(fcb->csp);
    if (!is_fcp_valid(fcp)) {
        flow_print_basic("  fcp(%d) on fcb(%d) is invalid\n",
                         fcp2id(fcp), fcb2id(fcb));
        this_flow_counter[FLOW_ERR_FCB_INVAL_CSP].counter++;
        return -1;
    }

    /*
     * todo ...
     * do we need to check the csp is good for the fcb??
     * or we can use the ager time to bypass this issue
     */

    SET_CSP_TO_LBUF(lbuf, fcb->csp);

    return 0;
}

int
flow_defrag_first_vector(struct rte_mbuf *mbuf)
{
    uint32_t hash;
    fcb_key_t  tmp;
    fcb_key_t *key;
    fcb_t *fcb;
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;
    conn_sub_t *csp, *csp_obs;

    flow_print_basic("%s entry\n", __FUNCTION__);

    key = &tmp;
    fcp_init_key_from_lhdr(lhdr, key);
    if (lhdr->ucIsIpv6) {
        hash = ip6_frag_hash(key);
    } else {
        hash = ip_frag_hash(key);
    }

    fcb = flow_match_fcb(key, hash);
    /* first fragment should not match any fcb */
    if (!fcb) {
        /* new fragment create fcb */
        fcb = flow_create_fcb(key);
        if (!fcb) {
            flow_print_basic("  fail to create fcb for this fragment.\nn");
            return -1;
        }

        fcb_insert_to_hash(fcb, hash);
        fcb_insert_to_time(fcb);

        fcb->csp = GET_CSP_FROM_LBUF(lbuf);
    } else {
        /* for some reason, we can match a fcb, then check if we can use it */
        csp_obs = fcb->csp;
        csp = GET_CSP_FROM_LBUF(lbuf);
        if (csp != csp_obs) {
            assert(0);
        }
    }

    return 0;
}

int
flow_fcb_ager(void)
{
    fcb_t *fcb, *next;
    uint32_t i, cnt = 0;
    struct list_head *head = &(this_fcbTimer[0].head);

    list_for_each_entry_safe(fcb, next, head, tnode) {
        cnt++;
        if (cnt > FCB_MAX_TO_BE_FREED) {
            break;
        }

        fcb_remove_from_hash(fcb);
        flow_free_fcb(fcb);
    }

    /* still some fcbs in this list */
    if (cnt > FCB_MAX_TO_BE_FREED) {
        this_fcbTimer[0].head.next = &fcb->tnode;
        fcb->tnode.prev = &this_fcbTimer[0].head;
        return 1;
    }

    /* shift timer link */
    for (i = 0; i < FCB_MAX_TIMER - 1; i++) {
        list_replace(&this_fcbTimer[i+1].head, &this_fcbTimer[i].head);
    }
    /* timer[FCB_MAX_TIMER - 1] is NULL list after shift */
    INIT_LIST_HEAD(&this_fcbTimer[i].head);

    return 0;
}

void
flow_fcb_ager_init(void)
{
    int i;
    for (i = 0; i < FCB_MAX_TIMER; i++) {
        INIT_LIST_HEAD(&this_fcbTimer[i].head);
    }
}

int
flow_fcb_init(uint32_t cid)
{
    fcb_t *fcb;
    int i;

    RTE_LOG(INFO, FLOW, "%s: start on lcore %d.\n", __FUNCTION__, cid);

    this_fcbPoolBase = (fcb_t *)rte_malloc("flow_fcb_pool", sizeof(fcb_t)*FLOW_FCB_ENTRY_MAX_NUMBER, 0);
    if (!this_fcbPoolBase) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow fcb pool\n",
                __FUNCTION__);
        return -1;
    }

    /*
     * init all fcb entry, fcb.hnode.next is reused here to link the free pool
     */
    fcb = this_fcbPoolBase;
    for (i = 0; i < FLOW_FCB_ENTRY_MAX_NUMBER; i++, fcb++) {
        fcb->hnode.next = (struct hlist_node *)(fcb + 1);
    }
    /* last fcb has no successive */
    fcb--;
    fcb->hnode.next = NULL;

    this_fcbPoolHead = this_fcbPoolBase;

    this_fcbHashTable = (struct hlist_head *)rte_zmalloc("flow_fcb_hash", sizeof(struct hlist_head)*FLOW_FCB_HASH_TAB_SIZE, 0);
    if (!this_fcbHashTable) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow fcb hash\n",
                __FUNCTION__);
        rte_free(this_fcbPoolBase);
        return -1;
    }
#ifndef TYFLOW_PER_THREAD
    rte_spinlock_init(&fcbPoolHead_sl);
    this_fcbHash_rwl = (rte_rwlock_t *)rte_zmalloc("flow_fcb_hash_rwl", sizeof(rte_rwlock_t)*FLOW_FCB_HASH_TAB_SIZE, 0);
    if (!this_fcbHash_rwl) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow fcb hash lock\n",
                __FUNCTION__);
        rte_free(this_fcbPoolBase);
        rte_free(this_fcbHashTable);
        return -1;
    }
#endif

    flow_fcb_ager_init();
    return 0;
}
