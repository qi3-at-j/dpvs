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
#include "flow_profile.h"
#include "flow_v6.h"
#include "flow_frag.h"
#include "flow_fwd.h"
#include "l3_node_priv.h"
#include "route6_priv.h"

/*Head/hdr is never need to be protected since we make it per lcore*/
/*other wants to use it need to be careful, maybe add a new lock version?*/
static inline void lifo_enqueue (void *head, void *y, int nxt_offset)
{
    char *yy = (char *)y;
    uint64_t **hdr = (uint64_t **)head;
	*(uint64_t *)(yy + nxt_offset) = (uint64_t)*hdr;
	*hdr = (uint64_t *)y;
}

static inline void *lifo_dequeue (void *head, int offset)
{
    uint64_t **hdr = (uint64_t **)head;
    uint64_t *y;
    y = *hdr;
	if (y == NULL) {
		goto end;
	}

	*hdr = (uint64_t *)(*(uint64_t *)((uint64_t)y + offset));

end:
	return (void *)y;
}

#ifdef TYFLOW_PER_THREAD
/* per lcore flow connection table */
RTE_DEFINE_PER_LCORE(flow_connection_t *, flowConnTable);
/* per lcore flow connection lifo head */
RTE_DEFINE_PER_LCORE(flow_connection_t *, flowConnHead);
/* per lcore flow connection hash context */
RTE_DEFINE_PER_LCORE(flow_conn_context_t *, flow_conn_ctx);

/* flow is ready to go? */
RTE_DEFINE_PER_LCORE(rte_atomic32_t, flow_status);
/* per lcore flow connection ager context */
RTE_DEFINE_PER_LCORE(flow_conn_ager_context_t, flow_conn_ager_ctx);

/* per lcore flow summary counter */
RTE_DEFINE_PER_LCORE(name_n_cnt_g, flow_counter_g);

#else 
flow_connection_t *flowConnTable;
flow_connection_t *flowConnHead;
rte_spinlock_t flowConnHead_sl;
flow_conn_context_t *flow_conn_ctx;
rte_atomic32_t flow_status;
flow_conn_ager_context_t flow_conn_ager_ctx;
name_n_cnt_g   flow_counter_g;
#endif

/* per lcore flow connection ager */
RTE_DEFINE_PER_LCORE(struct rte_timer, flow_conn_ager);

/* per lcore flow vector list */
RTE_DEFINE_PER_LCORE(flow_vector_t *, flow_vector_list);

/* per lcore flow connection control prototype */
RTE_DEFINE_PER_LCORE(flow_connection_t, flow_conn_crt_t);

/* per lcore flow connection statistics */
RTE_DEFINE_PER_LCORE(name_n_cnt, flow_counter);

static uint64_t g_policy_seq;

/*
 * Clean up leftovers in conn_sub_t block.
 * This cleanup is very important
 * as the conn_sub_t block will be allocated
 * later and most of its content will be used as is.
 */
static void 
init_conn_sub (conn_sub_t *csp)
{
    if (csp->route) {
        if (csp->cspflag & CSP_FLAG_IPV6) {
            graph_route6_put((struct route6_entry *)csp->route);
        } else {
            route4_put((struct route_entry *)csp->route);
        }
    }
	memset((void*)&csp->start,0,sizeof(conn_sub_t)-offsetof(conn_sub_t, start));
	csp->cspflag = CSP_FREE;
    set_csp_invalid(csp);
}

/*
 * free a flow_connection_t into free pool. 
 * this function may be called from the flow, or from the ager.
 * NOTE: this function is not protected by the lock. 
 */
static inline void 
flow_free_conn_into_free_pool(flow_connection_t *fcp)
{
	int offset = (int)(uint64_t)&(((flow_connection_t *)0)->next);
	
    fch_sl_lock();
	lifo_enqueue(&this_flowConnHead, fcp, offset);
    fch_sl_unlock();

	rte_atomic32_dec(&this_flow_curr_conn);
	rte_atomic32_inc(&this_flow_free_conn);
}
/*
 * this function initializes the flow connection before put it back
 * to the free pool.
 */
static inline void 
flow_init_connection (flow_connection_t *fcp)
{
	conn_sub_t *csp = &fcp->conn_sub0;
	conn_sub_t *csp2 = &fcp->conn_sub1;

    init_conn_sub(csp);
    init_conn_sub(csp2);

	if (fcp->fcflag & FC_INVALID) {
		/* decrease invalid flow connection counter */
        rte_atomic32_dec(&this_flow_invalid_conn);
	}
    fcp_rwl_read_lock(fcp);
    fca_rwl_write_lock(fcp->ager_index);
    if (fcp->fcflag & FC_IN_AGER) {
        hlist_del(&fcp->ager_node);
    }
    fca_rwl_write_unlock(fcp->ager_index);
    fcp_rwl_read_unlock(fcp);
		
    fcp->time = 0;
    fcp->time_const = 0;
    fcp->start_time = 0;
    fcp->duration = 0;
    fcp->fcflag = 0;
    fcp->byte_cnt = 0;
    fcp->pkt_cnt = 0;
    fcp->policy_seq = 0;
    fcp->reason = 0;
    fcp->fwsession = 0;
}

/* all resource attached to the flow connection should be freed here */
void 
flow_free_this_conn (flow_connection_t *fcp)
{
#if 0
    if(is_csp_l2info_arp(&fcp->conn_sub0))
        clear_csp_l2info_arp(&fcp->conn_sub0);

    /* clear arp ref_cnt for wing 2*/
    if(is_csp_l2info_arp(&fcp->conn_sub1))
        clear_csp_l2info_arp(&fcp->conn_sub1);
#endif

    flow_init_connection(fcp);

    flow_free_conn_into_free_pool(fcp);
}

static inline int 
conn_hash (uint32_t s, uint32_t d, uint32_t p)
{
	return (_conn_hash(s, d, p) & FLOW_CONN_HASH_TAB_MASK);
}

static inline void 
set_fcp_ageout_time(flow_connection_t *fcp, uint16_t time)
{
    if(fcp->fcflag & FC_INVALID) {
        flow_debug_trace(FLOW_DEBUG_AGER, 
                         "Trying to set the timeout for invalid connection id %d to %d\n", 
                         fcp2id(fcp), time);
    } else if (fcp->fcflag & FC_TIME_NO_REFRESH) {
        flow_debug_trace(FLOW_DEBUG_AGER, 
                         "Trying to set the timeout for no-fresh connection id %d to %d\n", 
                         fcp2id(fcp), time);
    } else {
        fcp->time = time;
    }
}

uint16_t
flow_get_fcp_time(flow_connection_t *fcp)
{
    if (fcp->fcflag & FC_TIME_NO_REFRESH) {
        return FLOW_CONN_NOTIMEOUT;
    }
    return (fcp->time >= this_flow_conn_ager_ctx.index)?
           (fcp->time-this_flow_conn_ager_ctx.index):
           (fcp->time+FLOW_CONN_MAXTIMEOUT-this_flow_conn_ager_ctx.index);
}

static uint16_t
add_fcp_to_ager(flow_connection_t *fcp, uint16_t timeout)
{
    uint16_t index;
    assert(fcp != this_flow_conn_crt);
    index = this_flow_conn_ager_ctx.index+timeout;
    if (index >= FLOW_CONN_MAXTIMEOUT) {
        index = index-FLOW_CONN_MAXTIMEOUT;
    }

    fcp->ager_index = index;
    fca_rwl_write_lock(index);
    hlist_add_head(&fcp->ager_node, this_flow_conn_ager_ctx.hash+index);
    fca_rwl_write_unlock(index);
    fcp->fcflag |= FC_IN_AGER;
    set_fcp_ageout_time(fcp, index);
    flow_debug_trace(FLOW_DEBUG_AGER, "add fcp %d to ager %d\n", fcp2id(fcp), index);
    return index;
}

static uint16_t
update_fcp_in_ager(flow_connection_t *fcp, uint16_t timeout)
{
    uint16_t index;
    fcp_rwl_write_lock(fcp);

    fca_rwl_write_lock(fcp->ager_index);
    if (fcp->fcflag & FC_IN_AGER) {
        hlist_del(&fcp->ager_node);
        fcp->fcflag &= ~FC_IN_AGER;
    }
    fca_rwl_write_unlock(fcp->ager_index);

    index = add_fcp_to_ager(fcp, timeout);
    fcp_rwl_write_unlock(fcp);

    return index;
}

/*
 * refreshed a connection's time to time_const
 * meanwhile update the connection position in ager
 */
void 
flow_refresh_connection(flow_connection_t *fcp)
{
    if (fcp->fcflag & FC_TIME_NO_REFRESH) {
        return;
    }
    update_fcp_in_ager(fcp, fcp->time_const);
}

static void
add_to_conn_hash(conn_sub_t *csp)
{
	int hash_value;
    uint32_t cnt;
	flow_connection_t *fcp = csp2base(csp);

    clr_csp_invalid(csp);
	hash_value = conn_hash(csp->csp_src_ip, csp->csp_dst_ip, *(uint32_t *)&csp->csp_src_port);

    fcc_rwl_write_lock(hash_value);
    hlist_add_head(&csp->hnode, &((this_flow_conn_hash_base+hash_value)->hash_base));
    fcc_rwl_write_unlock(hash_value);

    cnt = rte_atomic32_add_return(&((this_flow_conn_hash_base+hash_value)->conn_cnt), 1);
    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
        char saddr[16], daddr[16];
        inet_ntop(AF_INET, &csp->csp_src_ip, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &csp->csp_dst_ip, daddr, sizeof(daddr));
        flow_print("++ csp add %d/%d(0x%llx): %s/%d->%s/%d,%d, time %d, cspflag 0x%x\n",
                   hash_value, cnt, csp, 
                   saddr, ntohs(csp->csp_src_port),
                   daddr, ntohs(csp->csp_dst_port),
                   csp->csp_proto, fcp->time, csp->cspflag);
    }
}

static void
del_from_conn_hash(conn_sub_t *csp)
{
	int hash_value;
    uint32_t cnt;
	flow_connection_t *fcp = csp2base(csp);

	hash_value = conn_hash(csp->csp_src_ip, csp->csp_dst_ip, *(uint32_t *)&csp->csp_src_port);

    fcc_rwl_write_lock(hash_value);
    hlist_del(&csp->hnode);
    fcc_rwl_write_unlock(hash_value);

    cnt = rte_atomic32_sub_return(&((this_flow_conn_hash_base+hash_value)->conn_cnt), 1);
    if (flow_debug_flag & FLOW_DEBUG_AGER) {
        char saddr[16], daddr[16];
        inet_ntop(AF_INET, &csp->csp_src_ip, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &csp->csp_dst_ip, daddr, sizeof(daddr));
        flow_debug_trace_no_flag("-- csp del %d/%d(0x%llx): %s/%d->%s/%d,%d, time %d, cspflag 0x%x\n",
                                 hash_value, cnt, csp, 
                                 saddr, ntohs(csp->csp_src_port),
                                 daddr, ntohs(csp->csp_dst_port),
                                 csp->csp_proto, flow_get_fcp_time(fcp), csp->cspflag);
    }
}

void
set_fcp_invalid(flow_connection_t *fcp, uint32_t reason)
{
    flow_debug_trace(FLOW_DEBUG_AGER, "%s: fcp: %d, reason: %d\n", 
                     __FUNCTION__, fcp2id(fcp), reason);

    /* free the flow connection in 2 seconds */
    update_fcp_in_ager(fcp, 1);

    fcp->fcflag |= FC_INVALID;
    rte_atomic32_inc(&this_flow_invalid_conn);
    fcp->reason = reason;
    fcp->duration = (rte_get_tsc_cycles()-fcp->start_time)/g_cycles_per_sec;

    /* remove the two csp from hash */
    if (fcp->fcflag & FC_INSTALLED) {
        if (fcp->conn_sub0.cspflag & CSP_FLAG_IPV6) {
            del_from_conn_hash_v6(&fcp->conn_sub0);
            del_from_conn_hash_v6(&fcp->conn_sub1);
        } else {
            del_from_conn_hash(&fcp->conn_sub0);
            del_from_conn_hash(&fcp->conn_sub1);
        }
    }
}

static int is_flow_conn_init_log  = 1;
static int is_flow_conn_close_log  = 1;
static int
need_log_for_connection(flow_connection_t *fcp)
{
    return 0;
}

static int
gen_conn_log(flow_connection_t *fcp)
{
    return 0;
}

/*
 * since flow is using per lcore connection table, we 
 * can ignore the contend and release the fcp directly
 */
static void
flow_ager_service(__rte_unused struct rte_timer *tim, __rte_unused void *arg)
{
    lcoreid_t cid;
    flow_connection_t *fcp;
    struct hlist_node *n;
    int invalid = 0, free = 0;
    uint32_t key, *index;

    key = rte_atomic32_add_return(&this_flow_conn_ager_ctx.key, 1);
    if (key % flow_worker_num) {
        return;
    }
    flow_fcb_ager();
    if (key % (FLOW_CONN_AGER_RATE*flow_worker_num) != 0) {
        return;
    }

    cid = rte_lcore_id(); 
    rte_atomic32_set(&this_flow_conn_ager_ctx.cid, cid);
    index = &(this_flow_conn_ager_ctx.index);
    flow_debug_trace(FLOW_DEBUG_AGER, "%s: start ager %d on %d\n", 
                     __FUNCTION__, *index, cid);
    hlist_for_each_entry_safe(fcp, n, this_flow_conn_ager_ctx.hash+(*index), ager_node) {
        if (fcp->fcflag & FC_INVALID) {
            /*
             * Generate flow connection close log
             */
            if (is_flow_conn_close_log) {
                if (need_log_for_connection(fcp)) {
                    gen_conn_log(fcp);
                }
            }
            free++;
            flow_debug_trace(FLOW_DEBUG_AGER, "  free the fcp: %d, duration: %lu\n", 
                             fcp2id(fcp), fcp->duration);
            flow_free_this_conn(fcp);
        } else {
            invalid++;
            set_fcp_invalid(fcp, FC_CLOSE_AGEOUT);
        }
    }
    (*index)++;
    if (*index >= FLOW_CONN_MAXTIMEOUT) {
        *index = 0;
    }
    flow_debug_trace(FLOW_DEBUG_AGER, "ager finish invalid/free %d/%d, next %d\n", 
                     invalid, free, *index);
}

extern uint64_t g_cycles_per_sec;
static int
flow_ager_init_lcore(lcoreid_t cid)
{
    //dpvs_timer_sched(&g_minute_timer, &tv, minute_timer_expire, NULL, true);
    //rte_timer_init(&this_flow_conn_ager);
    //rte_timer_reset(&timer0, g_cycles_per_sec*2, PERIODICAL, lcore_id, timer0_cb, NULL);
    rte_timer_init(&this_flow_conn_ager);
    /* reuse this timer for fcb */
    return rte_timer_reset(&this_flow_conn_ager, 
                           g_cycles_per_sec, 
                           PERIODICAL, cid, flow_ager_service, NULL);
}

static int
flow_ager_init(lcoreid_t cid)
{
    rte_atomic32_set(&this_flow_conn_ager_ctx.key, -1);
    this_flow_conn_ager_ctx.index = 0;
    this_flow_conn_ager_ctx.hash = (struct hlist_head *)rte_zmalloc("flow_conn_ager_hash", sizeof(struct hlist_head)*FLOW_CONN_MAXTIMEOUT, 0); 
    if (!this_flow_conn_ager_ctx.hash) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow conn ager hash\n",
                __FUNCTION__);
        return -1;
    }
#ifndef TYFLOW_PER_THREAD
    this_flow_conn_ager_ctx.rwl = (rte_rwlock_t *)rte_zmalloc("flow_conn_ager_hash_lock", sizeof(rte_rwlock_t)*FLOW_CONN_MAXTIMEOUT, 0);
    if (!this_flow_conn_ager_ctx.rwl) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow conn ager hash lock\n",
                __FUNCTION__);
        rte_free(this_flow_conn_ager_ctx.hash);
        return -1;
    }
#endif

    return flow_ager_init_lcore(cid);
}

/* 
 * called during sys init time.
 */
static int
flow_conn_init (__rte_unused void *arg)
{
    flow_connection_t *fcp;
	uint32_t cnt;
	conn_sub_t *csp0;
	conn_sub_t *csp1;
    lcoreid_t cid = rte_lcore_id();

    if (g_lcore_role[cid] != LCORE_ROLE_FWD_WORKER) {
        RTE_LOG(INFO, FLOW, "%s: lcore %d: skip non-worker.\n",
                            __FUNCTION__, cid);
        return 0;
    }
#ifdef TYFLOW_PER_THREAD
    RTE_LOG(INFO, FLOW, "%s: start flow(per-thread) on lcore %d.\n", __FUNCTION__, cid);
    if (flow_fwd_init_lcore(cid)) {
        return -1;
    }
#else
    RTE_LOG(INFO, FLOW, "%s: start flow on lcore %d.\n", __FUNCTION__, cid);
    cnt = rte_atomic32_test_and_set(&this_flow_status);
    if (cnt == 0) {
        if (flow_ager_init_lcore(cid)) {
            return -1;
        }
        memcpy(this_flow_counter, flow_counter_template, sizeof(name_n_cnt));
        memcpy(this_flow_counter_g, flow_counter_g_template, sizeof(name_n_cnt_g));
        flow_fcb_ager_init();
        flow_profile_init();
        /*
         * init flow conn control prototype
         */
        csp0 = &this_flow_conn_crt->conn_sub0;
        csp1 = &this_flow_conn_crt->conn_sub1;
        csp0->peer_offset = (uint64_t)csp1 - (uint64_t)csp0;
        csp1->peer_offset = (uint64_t)csp0 - (uint64_t)csp1;
        csp0->base_offset = (uint64_t)this_flow_conn_crt - (uint64_t)csp0;
        csp1->base_offset = (uint64_t)this_flow_conn_crt - (uint64_t)csp1;
        csp0->resv = RESV_AA;
        csp1->resv = RESV_BB;
        return 0;
    }
#endif
    this_flowConnTable = (flow_connection_t *)rte_malloc("flow_conn_table", 
                                                         sizeof(flow_connection_t)*FLOW_CONN_MAX_NUMBER, 
                                                         0);
    if (!this_flowConnTable) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow connection\n",
                __FUNCTION__);
        goto bad;
    }

    this_flow_conn_hash_base = (flow_conn_context_t *)rte_zmalloc("flow_conn_hash", sizeof(flow_conn_context_t)*FLOW_CONN_HASH_TAB_SIZE, 0); 
    if (!this_flow_conn_hash_base) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow conn hash\n",
                __FUNCTION__);
        goto bad;
    }
#ifndef TYFLOW_PER_THREAD
    for (cnt = 0; cnt < FLOW_CONN_HASH_TAB_SIZE; cnt ++) {
        rte_rwlock_init(&((this_flow_conn_hash_base+cnt)->rwl));
    }
#endif
    if (flow_ager_init(cid)) {
        goto bad;
    }

    /* flow fragment control block init */
    if (flow_fcb_init(cid)) {
        goto bad;
    }

    /* flow profile init */
    flow_profile_init();

    memcpy(this_flow_counter, flow_counter_template, sizeof(name_n_cnt));
    memcpy(this_flow_counter_g, flow_counter_g_template, sizeof(name_n_cnt_g));

    /*
     * init flow conn control prototype
     */
    csp0 = &this_flow_conn_crt->conn_sub0;
    csp1 = &this_flow_conn_crt->conn_sub1;
    csp0->peer_offset = (uint64_t)csp1 - (uint64_t)csp0;
    csp1->peer_offset = (uint64_t)csp0 - (uint64_t)csp1;
    csp0->base_offset = (uint64_t)this_flow_conn_crt - (uint64_t)csp0;
    csp1->base_offset = (uint64_t)this_flow_conn_crt - (uint64_t)csp1;
    csp0->resv = RESV_AA;
    csp1->resv = RESV_BB;

	/*
	 * init flow conn table.
	 * we do not use the 0th flow conn entry since
	 * its index is 0, and 0 in udp/tcp lookup table
	 * means no entry.
	 */
	this_flowConnHead = NULL;
#ifndef TYFLOW_PER_THREAD
    rte_spinlock_init(&flowConnHead_sl);
#endif
	fcp = this_flowConnTable + 1;
	for (cnt = 1; cnt < FLOW_CONN_MAX_NUMBER; cnt++) {
		memset(fcp, 0, sizeof(flow_connection_t));
		/* assign session id, but not for 1000 */
		csp0 = &fcp->conn_sub0;
		csp1 = &fcp->conn_sub1;
		csp0->peer_offset = (uint64_t)csp1 - (uint64_t)csp0;
		csp1->peer_offset = (uint64_t)csp0 - (uint64_t)csp1;
		csp0->base_offset = (uint64_t)fcp - (uint64_t)csp0;
		csp1->base_offset = (uint64_t)fcp - (uint64_t)csp1;
        csp0->resv = RESV_AA;
        csp1->resv = RESV_BB;
#ifndef TYFLOW_PER_THREAD
        rte_rwlock_init(&fcp->rwl);
#endif
		/*
		 * put into free pool.
		 */
		flow_free_this_conn(fcp);

		fcp++;
	}

    rte_atomic32_init(&this_flow_curr_conn);
    rte_atomic32_init(&this_flow_invalid_conn);
    rte_atomic32_init(&this_flow_no_conn);
    rte_atomic32_set(&this_flow_free_conn, FLOW_CONN_MAX_NUMBER-1);

    memset(flow_protocol_timeout, 0, sizeof(flow_protocol_timeout));
	/*
	 * notify me if a policy is gone.
	 */
	//add_policy_delete_registry((void *)flow_age_conn_by_policy);

	/*
	 * notify me if ha peer state change
	 */
	//add_ha_peer_state_change_registry(flow_ha_peer_state_change);

	/*
	 * notify me if an interface is gone
	 */
	//add_delete_if_registry((void *)flow_clear_conn_by_ifp);

    rte_atomic32_test_and_set(&this_flow_status);
    RTE_LOG(INFO, FLOW, "  finish on lcore %d/%d\n", cid, rte_atomic32_read(&this_flow_status));
    return 0;
bad:
    if (this_flowConnTable) {
        rte_free(this_flowConnTable);
    }
    if (this_flow_conn_hash_base) {
        rte_free(this_flow_conn_hash_base);
    }
    rte_atomic32_init(&this_flow_status);
    return -1;
}

static flow_vector_t flow_first_vector_list[] =
{
    flow_first_sanity_check,
    flow_first_hole_search,
    flow_first_routing,
    flow_first_for_self,
    flow_first_alloc_connection,
    flow_first_fw_entry,
    NULL
};

static flow_vector_t flow_fast_vector_list[] =
{
    flow_fast_for_self,
    flow_fast_check_routing,
    flow_fast_reinject_out,
    flow_fast_fw_entry,
#ifdef TYFLOW_LEGACY
    flow_fast_send_out,
#endif
    NULL
};

static flow_vector_t flow_ipv4_vector_list[] = 
{
    flow_parse_vector,
    flow_filter_vector,
#ifdef TYFLOW_PER_THREAD
    flow_fwd_vector,
#endif
    flow_decap_vector,
    flow_main_body_vector,
    NULL
};

static inline int 
flow_terminate_vector(void)
{
    this_flow_vector_list = NULL;
    return 0;
}

/*
 * resume packet processing from the where it stops.
 * make the vector pacing by flow_next_pak_vector
 */
static inline int 
flow_walk_vector_list (struct rte_mbuf *mbuf)
{
	int rc;

    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
        char src_addr[INET6_ADDRSTRLEN];
        char dst_addr[INET6_ADDRSTRLEN];
        uint32_t protocol, *iptr;
        MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);

        if (lbuf->stIpHdr.ucIsIpv6) {
            struct ip6_hdr *hdr;

            hdr = ip6_hdr(mbuf);
            iptr = (uint32_t *)(hdr+1);
            inet_ntop(AF_INET6, &hdr->ip6_src, src_addr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &hdr->ip6_dst, dst_addr, INET6_ADDRSTRLEN);
            protocol = hdr->ip6_nxt;
        } else {
            struct rte_ipv4_hdr *iph;
            uint32_t iphdrlen;

            iph = ip4_hdr(mbuf);
            iphdrlen = ip4_hdrlen(mbuf);
            iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);
            inet_ntop(AF_INET, &iph->src_addr, src_addr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET, &iph->dst_addr, dst_addr, INET6_ADDRSTRLEN);
            protocol = iph->next_proto_id;
        }
        flow_debug_trace_no_flag("**** jump to packet: %s/%d->%s/%d@%d, rss %d\n",
                                 src_addr,
                                 ntohs(ip_src_port(*iptr)),
                                 dst_addr,
                                 ntohs(ip_dst_port(*iptr)),
                                 protocol, mbuf->hash.rss);
    }

	while (*this_flow_vector_list) {
		if ((rc = (*this_flow_vector_list)(mbuf))) {
			flow_debug_trace(FLOW_DEBUG_BASIC, "**** pak processing end(%d).\n", rc);
			return rc;
		}
	}
	flow_debug_trace(FLOW_DEBUG_BASIC, "**** pak processing end.\n");
	return 0;
}

#define IS_ICMP_REQ(tt)  (tt== ICMP_ECHO || tt== ICMP_TIMESTAMP || tt== ICMP_ADDRESS || tt== ICMP_INFO_REQUEST)
#define IS_ICMP_RSP(tt)  (tt== ICMP_ECHOREPLY || tt== ICMP_TIMESTAMPREPLY || tt== ICMP_ADDRESSREPLY || tt== ICMP_INFO_REPLY)
#define HAS_EMBEDDED_IP(tt) (tt== ICMP_DEST_UNREACH || tt== ICMP_SOURCE_QUENCH || tt== ICMP_REDIRECT || tt== ICMP_TIME_EXCEEDED || tt== ICMP_PARAMETERPROB)

/*
 * use seq number in icmp req, and id number in icmp rsp.
 * returns - the src port number in network byte order.
 */
static inline int ping_src_port (struct rte_icmp_hdr *icmp)
{
	if (icmp->icmp_type == ICMP_ECHO ||
		icmp->icmp_type == ICMP_TIMESTAMP ||
		icmp->icmp_type == ICMP_INFO_REQUEST)
		return icmp->icmp_seq_nb;
	else if (icmp->icmp_type == ICMP_ECHOREPLY ||
		     icmp->icmp_type == ICMP_TIMESTAMPREPLY ||
             icmp->icmp_type == ICMP_INFO_REPLY)
		return icmp->icmp_ident;
	return 0;
}

/*
 * use id number in icmp req, and seq number in icmp rsp.
 * returns - the dst port number in network byte order.
 */
static inline int ping_dst_port (struct rte_icmp_hdr *icmp)
{
	if (icmp->icmp_type == ICMP_ECHO      ||
		icmp->icmp_type == ICMP_TIMESTAMP ||
		icmp->icmp_type == ICMP_INFO_REQUEST)
		return icmp->icmp_ident;
	else if (icmp->icmp_type == ICMP_ECHOREPLY||
             icmp->icmp_type == ICMP_TIMESTAMPREPLY||
             icmp->icmp_type == ICMP_INFO_REPLY)
		return icmp->icmp_seq_nb;
	else
		return 0;
}

/* Forms ports for ICMP req/resp packets. */
static inline uint32_t 
icmp_ping_ports_form (struct rte_icmp_hdr *icmp)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return (ping_dst_port(icmp) << 16) | ping_src_port(icmp);
    else 
        return (ping_src_port(icmp) << 16) | ping_dst_port(icmp);
}

/* To ensure proper endianness use icmp_ping_ports_form to extract src/
 * dst ports from the value returned by this function. */
int 
icmp_ports (struct rte_icmp_hdr *icmp)
{
	if (icmp->icmp_type == ICMP_ECHO || icmp->icmp_type == ICMP_ECHOREPLY ||
		icmp->icmp_type == ICMP_TIMESTAMP || icmp->icmp_type == ICMP_TIMESTAMPREPLY ||
		icmp->icmp_type == ICMP_INFO_REQUEST || icmp->icmp_type== ICMP_INFO_REPLY) {
        return icmp_ping_ports_form (icmp);
	}

	/*
	 * the following value needs to be consistent with default
	 * return value of ip_proto_ports().
	 */
	return htonl(0x00010001);
}

static inline uint32_t 
ip_proto_ports_embed_icmp (uint8_t prot, uint32_t *iptr)
{
	if (prot == IPPROTO_TCP || prot == IPPROTO_UDP || prot == IPPROTO_ESP) {
		return *iptr;
	}
	else if (prot == IPPROTO_AH) {
		return *(iptr+1);			/* spi of AH is the second LONG of the header */
	}
	else if (prot == IPPROTO_ICMP) {
		return icmp_ports((struct rte_icmp_hdr *)iptr);
	}
	return htonl(0x00010001);
}

static void 
swap_ip_port (struct rte_ipv4_hdr *iphdr, uint32_t *iptr, uint32_t *ports)
{
	uint32_t value;

	value = iphdr->src_addr;
	iphdr->src_addr = iphdr->dst_addr;
	iphdr->dst_addr = value;
	value = ip_proto_ports_embed_icmp(iphdr->next_proto_id, iptr);
	value = ip_ports_form(ip_dst_port(value), ip_src_port(value));
	*ports = value;
}

/*
 * generate iphdr and ports info for flow connection lookup
 */
struct rte_ipv4_hdr *
gen_icmp_lookup_info (struct rte_ipv4_hdr *iphdr, 
                      uint32_t *iptr, 
                      struct rte_ipv4_hdr *iphdr_inner, 
                      uint32_t *ports,
                      uint32_t *icmp_err)
{
	struct rte_icmp_hdr *icmp;
    struct rte_ipv4_hdr *iphdr_tmp;

	icmp = (struct rte_icmp_hdr *)iptr;
	if (IS_ICMP_REQ(icmp->icmp_type) ||
		IS_ICMP_RSP(icmp->icmp_type)) {
		*ports = icmp_ping_ports_form(icmp);
	}
    else if (HAS_EMBEDDED_IP(icmp->icmp_type)) { 
        *icmp_err = 1;
        /*
         * for these icmp message, use embedded ip header
         * for session lookup
         */
        iphdr_tmp = (struct rte_ipv4_hdr *)((uint8_t *)iptr + sizeof(struct rte_icmp_hdr));
        /*
         * we copy the original iphdr out so only alter
         * the copy not the original.
         */
        memcpy(iphdr_inner, iphdr_tmp, sizeof(struct rte_ipv4_hdr));
        iptr = ((uint32_t *)iphdr_tmp + (iphdr_tmp->version_ihl & 0xf));
        swap_ip_port(iphdr_inner, iptr, ports);
        flow_print_detail("  icmp embed extern: 0x%x->0x%x, %d, %d, intern: 0x%x/%d->0x%x/%d, %d\n", 
                          ntohl(iphdr->src_addr),
                          ntohl(iphdr->dst_addr),
                          icmp->icmp_type, icmp->icmp_code,
                          ntohl(iphdr_inner->dst_addr),
                          ip_dst_port(*ports),
                          ntohl(iphdr_inner->src_addr),
                          ip_src_port(*ports),
                          iphdr_inner->next_proto_id);

        if (icmp->icmp_type == ICMP_REDIRECT) {
            return (struct rte_ipv4_hdr *)-1;
        }

        iphdr = iphdr_inner;

        /* we don't want to refresh flow connection for ICMP error cases */
        //mbuf->flag |= PAK_NO_REFRESH | PAK_EMBED_ICMP ;

    } else
        *ports = htonl(0x00010001);
    return iphdr;
}

/* generic way for flow conn_sub_t traverse */
#define FOR_ALL_CSP(node, src_adr, dst_adr, ports, head, csp, hash, cnt)   \
    hash = conn_hash(src_adr, dst_adr, ports);                             \
    fcc_rwl_read_lock(hash);                                               \
    FOR_ALL_CSP2(node, src_adr, dst_adr, ports, head, csp, hash, cnt)


/*
 * first path packet processing
 * similar to flow_walk_vector_list
 * give a meaningful wrapper name 
 * need to add some performance counter
 */
int
flow_proc_first_pak(struct rte_mbuf *mbuf)
{
    /* add some performance counter here */
    int rc;
    conn_sub_t *csp;

    flow_print_basic("  ---- first path entry.\n");
	while (*this_flow_vector_list) {
		if ((rc = (*this_flow_vector_list)(mbuf))) {
            break;
		}
	}
    if (rc) {
        csp = &this_flow_conn_crt->conn_sub0;
        if (csp->route) {
            if (csp->cspflag & CSP_FLAG_IPV6) {
                graph_route6_put((struct route6_entry *)csp->route);
            } else {
                route4_put((struct route_entry *)csp->route);
            }
            csp->route = 0;
        }
        csp = &this_flow_conn_crt->conn_sub1;
        if (csp->route) {
            if (csp->cspflag & CSP_FLAG_IPV6) {
                graph_route6_put((struct route6_entry *)csp->route);
            } else {
                route4_put((struct route_entry *)csp->route);
            }
            csp->route = 0;
        }
    }
    flow_print_basic("  ---- first path end (%d).\n", rc);
    return rc;
}

int
flow_first_install_connection(struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp = GET_FC_FROM_MBUF(mbuf);
    if (fcp->fcflag & FC_INSTALLED) {
        /* fw may help us to install the connection */
        return 0;
    }

    flow_install_conn(fcp);
    return 0;
}

static void 
flow_dump_hash(conn_sub_t *csp, int cnt)
{
    int hash;
    hash = conn_hash(csp->csp_src_ip, csp->csp_dst_ip, *(uint32_t *)&csp->csp_src_port);

	/* we only show hash bucket with connections to reduce the output */
	if (cnt > 0) {
		conn_sub_t *csp_next;
		int i = 0, line = 0;
		flow_print_detail("  hash %6d header: %8llx, cnt %4d: ", hash, (uint64_t)csp, cnt); 
		while (csp && i++ < cnt) {
			flow_connection_t *fcp = csp2base(csp);
			int fcp_id = fcp2id(fcp);
			csp_next = container_of(csp->hnode.next, conn_sub_t, hnode);
			flow_print_detail("%8d ", fcp_id);
			if (!line) {
				if (!(i & 0x7)) {
					line++;
					flow_print_detail("\n    ");
				}
			} else if(!(i & 0x1f)) {
				line++;
				flow_print_detail("\n    ");
			}
			csp = csp_next;
		}
		flow_print_detail("\n");
	}
}

uint16_t flow_protocol_timeout[IPPROTO_MAX];
uint16_t
flow_get_default_time(uint8_t proto)
{
	uint16_t timeout;

    timeout = flow_protocol_timeout[proto];
    if (timeout) {
        return timeout;
    }
    switch (proto) {
        case IPPROTO_TCP:
            timeout = FLOW_CONN_TCP_TIMEOUT;
            break;
        case IPPROTO_UDP:
            timeout = FLOW_CONN_UDP_TIMEOUT;
            break;
        case IPPROTO_ICMP:
            timeout = FLOW_CONN_PING_TIMEOUT;
            break;
        default:
            timeout = FLOW_CONN_DEF_TIMEOUT;
            break;
    }

	return timeout;
}

int 
flow_first_fcp_crt_init(struct rte_mbuf *mbuf, MBUF_IP_HDR_S *lhdr)
{
    conn_sub_t *csp1, *csp2;
    uint32_t len = sizeof(flow_connection_t)-offsetof(flow_connection_t, start);

    flow_print_basic("  %s entry, init fcp len %d\n", __FUNCTION__, len);
    /*
     * reset flow connection control prototype
     */
    csp1 = &this_flow_conn_crt->conn_sub0;
    csp2 = &this_flow_conn_crt->conn_sub1;
    init_conn_sub(csp1);
    init_conn_sub(csp2);
    memset(&this_flow_conn_crt->start, 0, len); 

    /* set the this_flow_conn_crt on the basis of mbuf */
    memcpy(&csp1->csp_src_ip, &lhdr->lhdr_src_ip_4, 4*sizeof(uint32_t));
    memcpy(&csp2->csp_dst_ip, &lhdr->lhdr_src_ip_4, 4*sizeof(uint32_t));
    memcpy(&csp1->csp_dst_ip, &lhdr->lhdr_dst_ip_4, 4*sizeof(uint32_t));
    memcpy(&csp2->csp_src_ip, &lhdr->lhdr_dst_ip_4, 4*sizeof(uint32_t));
    csp1->csp_src_port = csp2->csp_dst_port = lhdr->lhdr_src_port;
    csp1->csp_dst_port = csp2->csp_src_port = lhdr->lhdr_dst_port;
    csp1->csp_proto = csp2->csp_proto = lhdr->ucNextHdr;
    if (lhdr->ucNextHdr == IPPROTO_ICMP) {
        csp1->csp_type = lhdr->lhdr_icmp_type;
        csp1->csp_code = lhdr->lhdr_icmp_code;
    }
    csp1->csp_token = csp2->csp_token = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;
    csp2->cspflag = CSP_ECHO_SIDE;
    if (lhdr->ucIsIpv6) {
        csp1->cspflag |= CSP_FLAG_IPV6;
        csp2->cspflag |= CSP_FLAG_IPV6;
    }

    csp1->ifp = netif_port_get(mbuf->port);
    this_flow_conn_crt->start_time = rte_get_tsc_cycles() / g_cycles_per_sec;
    this_flow_conn_crt->time_const = flow_get_default_time(csp1->csp_proto);
    SET_CSP_TO_MBUF(mbuf, csp1);
    rte_mb();
    return 0;
}

int 
is_connection_list_loop(int cnt, int i, conn_sub_t *head)
{
/* to make sure we don't omit any thing */
#define MIN_HASH_COUNT 0x7F
/* to make sure we don't do stupid loop too much */
#define MAX_HASH_COUNT 0x1FFF
	int count = MAX(MIN_HASH_COUNT, MIN(MAX_HASH_COUNT, cnt<<1));
	if (i > count) {
        flow_print_detail("hash(0x%llx) abnormal, hash counter %d, hash connecetion wings %d.\n", head, cnt, i);
        flow_dump_hash(head, MIN(cnt + 1, 100));
		return 1;
	}
	return 0;
}

conn_sub_t *
flow_find_connection_by_key(csp_key_t *key)
{
    int cnt, hash, i = 0;
    struct hlist_node *node;
	conn_sub_t *csp = NULL, *head;
    flow_connection_t *fcp = NULL;

    FOR_ALL_CSP(node, key->src_ip, key->dst_ip, *(uint32_t *)(&key->src_port), head, csp, hash, cnt) {
        if (CONN_SUB_COMP(csp, key)) {
            fcp = csp2base(csp);
            if ((fcp->fcflag & FC_INVALID) == 0) {
                break;
            } else {
                fcp = NULL;
            }
        }
        if (!(++i & 0x7F) && is_connection_list_loop(cnt, i, head)) {
            break;
        }
    }
    FOR_ALL_CSP_END(hash);
    return fcp?csp:NULL;
}

/*
 * main entry point for first path
 * in this function we'll try to find a connection for incoming packet
 */
int 
flow_find_connection(struct rte_mbuf *mbuf)
{
	flow_vector_t *vector;
	int rc;
	conn_sub_t *csp = NULL;
    flow_connection_t *fcp = NULL;
    csp_key_t key = {0};
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;

    key.src_ip = lhdr->lhdr_src_ip_4;
    key.dst_ip = lhdr->lhdr_dst_ip_4;
    key.src_port = lhdr->lhdr_src_port;
    key.dst_port = lhdr->lhdr_dst_port;
    key.proto = lhdr->ucNextHdr;
    key.token = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;

    csp = flow_find_connection_by_key(&key);
    fcp = csp?csp2base(csp):NULL;

    if (fcp) {
        flow_print_basic("  existing connection found. id %d\n", fcp2id(fcp));
        SET_CSP_TO_MBUF(mbuf, csp);
        if (IS_CSP_DISABLE(csp)) {
            /* do something */
        }
    } else {
        if (SESSION_MBUF_HAVE_FLAG(lbuf, SESSION_MBUF_ICMPERR)) {
            flow_print_basic("  icmp error packet match no connection\n");
            return FLOW_RET_ERR;
        }
        /* 
         * first pak, try to creat a new one 
         */
        flow_print_basic("  no connection found\n");

        /*
         * keep original vector list
         */
        vector = this_flow_vector_list;
        flow_set_pak_vector(flow_first_vector_list);
        flow_first_fcp_crt_init(mbuf, lhdr);
        rc = flow_proc_first_pak(mbuf);
        /* restor vector list */
        flow_set_pak_vector(vector);
        if (rc) {
            return rc;
        }

        flow_first_install_connection(mbuf);
    }
    return 0;
}

int 
flow_first_sanity_check(struct rte_mbuf *mbuf)
{
    VECTOR_PROFILE(flow_first_sanity_check);
    flow_print_basic("  %s entry\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

int
flow_first_alloc_connection(struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp;
    conn_sub_t *csp1, *csp2;
    uint32_t len;

    VECTOR_PROFILE(flow_first_alloc_connection);

    fch_sl_lock();
    fcp = lifo_dequeue(&this_flowConnHead, offsetof(flow_connection_t, next));
    fch_sl_unlock();

    if (fcp) {
        rte_atomic32_inc(&this_flow_curr_conn);
        rte_atomic32_dec(&this_flow_free_conn);
        flow_print_basic("  alloc flow connection from pool\n");
    } else {
        rte_atomic32_inc(&this_flow_no_conn);
        flow_print_basic("  failed to alloc flow connection\n");
        return -1;
    }

    len = sizeof(conn_sub_t)-offsetof(conn_sub_t, start);
    csp1 = &fcp->conn_sub0; 
    csp2 = &fcp->conn_sub1;
    memcpy(&csp1->start, &this_flow_conn_crt->conn_sub0.start, len);
    memcpy(&csp2->start, &this_flow_conn_crt->conn_sub1.start, len);
    this_flow_conn_crt->conn_sub0.route = NULL;
    this_flow_conn_crt->conn_sub1.route = NULL;
    clr_csp_invalid(csp1);
    clr_csp_invalid(csp2);

    len = sizeof(flow_connection_t)-offsetof(flow_connection_t, start);
    memcpy(&fcp->start, &this_flow_conn_crt->start, len);
    SET_CSP_TO_MBUF(mbuf, csp1);
    return flow_next_pak_vector(mbuf);
}

int 
flow_first_hole_search(struct rte_mbuf *mbuf)
{
    VECTOR_PROFILE(flow_first_hole_search);
    flow_print_basic("  %s entry\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

extern uint16_t g_nports;
extern struct inet_device *dev_get_idev(const struct netif_port *dev);
extern struct inet_ifaddr *ifa_lookup(struct inet_device *idev,
        const union inet_addr *addr,
        uint8_t plen, int af);
int
pak_to_my_addrs(struct rte_ipv4_hdr *iph, uint32_t id)
{
    struct netif_port *dev;
    struct inet_device *idev;
    union inet_addr addr;
    struct inet_ifaddr *ifa;

    addr.in.s_addr = iph->dst_addr;

    for (id = 0; id < g_nports; id++) {
        dev = netif_port_get(id);
        if (!dev) {
            continue;
        }
        idev = dev_get_idev(dev);
        if (!idev) {
            continue;
        }
        /* we do not care about the prefix mask */
        ifa = ifa_lookup(idev, &addr, 0, AF_INET);
        if (ifa) {
            return 1;
        }
    }
    return 0;
}

int g_is_ping_enable = 1;

static int 
is_for_ping (MBUF_IP_HDR_S *lhdr)
{
	if (lhdr->ucNextHdr == IPPROTO_ICMP &&
        lhdr->lhdr_icmp_type == ICMP_ECHO) {
		/* regular ping */
		if (is_ping_on_()) {
			return 1;
		} 
	}
    return 0;
}

static int
flow_reply_ping(struct rte_ipv4_hdr *iph, uint32_t iphdrlen, uint32_t *iptr, struct rte_mbuf *mbuf, uint32_t *ipid)
{
    uint16_t csum;
    uint32_t temp;
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)iptr;
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;

    /* 
     * first fragment or non-fragment should make the icmp header as echo reply
     * non-first fragment will do nothing
     */
    if (!lhdr->ucIsFragment || lhdr->ucIsFirstFrag) {
        icmp->icmp_type = ICMP_ECHOREPLY;
        icmp->icmp_cksum = 0;
        csum = rte_raw_cksum(icmp, mbuf->pkt_len-iphdrlen);
        icmp->icmp_cksum = (csum == 0xffff) ? csum : ~csum;
    }

    iph->time_to_live = INET_DEF_TTL;
    temp = iph->src_addr;
    iph->src_addr = iph->dst_addr;
    iph->dst_addr = temp;
    if (*ipid) {
        iph->packet_id = *ipid;
    } else {
        iph->packet_id = ip4_select_id(iph);
        /* record the generated ipid */
        *ipid = iph->packet_id;
    }
    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }
    return 0;
}

#ifndef TYFLOW_LEGACY
extern struct route_entry *
flow_route_lookup(struct rte_mbuf *mbuf, uint32_t dst_ip);
#endif
int
flow_first_for_self(struct rte_mbuf *mbuf)
{
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;
    conn_sub_t *csp = GET_CSP_FROM_LBUF(lbuf);
    conn_sub_t *host_csp = csp2peer(csp);
    struct route_entry *rt = (struct route_entry *)host_csp->route;
    int my_pak = 0;

    VECTOR_PROFILE(flow_first_for_self);

    my_pak = rt->flag & RTF_LOCALIN;
    if (my_pak) {
        flow_print_basic("   the packet is destined to us\n");
        /* since we have no user-mode stack, we hack the icmp echo here
         * for other to-self packet, we just drop them, we may handle
         * later after having the user-mode stack
         */
        if (is_for_ping(lhdr)) {
            csp = GET_CSP_FROM_MBUF(mbuf);
            csp->cspflag |= CSP_TO_SELF | CSP_TO_SELF_PING;
            host_csp = csp2peer(csp);
            host_csp->cspflag |= CSP_FROM_SELF;
            flow_print_basic("   to self ping handle with fcp\n");
            this_flow_counter[FLOW_BRK_TO_SELF].counter++;
        } else {
            flow_print_basic("   to self but not ready to handle, drop the packet\n");
            this_flow_counter[FLOW_ERR_TO_SELF_DROP].counter++;
            return FLOW_RET_ERR;
        }
    }
    return flow_next_pak_vector(mbuf);
}

int
flow_first_routing(struct rte_mbuf *mbuf)
{
    struct route_entry *rt = NULL;
    struct netif_port *ifp = NULL;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    conn_sub_t *csp, *peer;

    VECTOR_PROFILE(flow_first_routing);

#ifndef TYFLOW_LEGACY
    //rt = flow_route_lookup(mbuf, iph->dst_addr);
    rt = GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
#else
    ifp = netif_port_get(mbuf->port);
    rt = route4_input(mbuf, (struct in_addr *)&iph->dst_addr,
                      (struct in_addr *)&iph->src_addr,
                      iph->type_of_service, NULL);
#endif
    if (!rt) {
        flow_print_basic("  no route to 0x%x\n", ntohl(iph->dst_addr));
        this_flow_counter[FLOW_ERR_NO_ROUTE].counter++;
        return FLOW_RET_ERR;
    } else if (!rt->port) {
        flow_print_basic("  route 0x%llx have no interface\n", rt);
        this_flow_counter[FLOW_ERR_NO_ROUTE_IFP].counter++;
        return FLOW_RET_ERR;
    }

    csp = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
    peer->route = rt;
#ifndef TYFLOW_LEGACY
    route4_get(rt);
#endif
    peer->ifp = rt->port;

    flow_print_basic("  routed(0x%x) from %s to %s\n", 
                     ntohl(iph->dst_addr),
                     ifp->name,
                     rt->port->name);

    return flow_next_pak_vector(mbuf);
}

int flow_skip_fw = 0;
int
flow_first_fw_entry(struct rte_mbuf *mbuf)
{
	int iRet;
    conn_sub_t *csp;
    flow_connection_t *fcp;

    VECTOR_PROFILE(flow_first_fw_entry);
	
    if (flow_skip_fw) {
        flow_print_basic("  %s flow skip firewall handling\n", __FUNCTION__);
        return flow_next_pak_vector(mbuf);
    }

    flow_print_basic("  %s entry\n", __FUNCTION__);
    csp = GET_CSP_FROM_MBUF(mbuf);
    if (csp->cspflag & (CSP_FROM_SELF | CSP_TO_SELF)) {
        flow_print_basic("    skip the to-self / from-self pak\n");
        return flow_next_pak_vector(mbuf);
    }

	if (csp->cspflag & CSP_FLAG_IPV6) {
	    iRet = ASPF_kpacket_zonepair_Ipv6(mbuf);
	} else {
        iRet = ASPF_kpacket_zonepair_Ipv4(mbuf);
	}
	
	if(FLOW_RET_OK != iRet)
	{
        this_flow_counter[FLOW_ERR_FIRST_FW].counter++;
		return iRet;
	}
	
    fcp = csp2base(csp);
    fcp->policy_seq = g_policy_seq;
    return flow_next_pak_vector(mbuf);
}

/*
 * fw may want to manage the connection itself
 */
void
flow_install_conn_no_refresh(flow_connection_t *fcp)
{
    /* we assume both of the two wings must be the same protocol */
    if (fcp->conn_sub0.cspflag & CSP_FLAG_IPV6) {
        add_to_conn_hash_v6(&fcp->conn_sub0);
        add_to_conn_hash_v6(&fcp->conn_sub1);
    } else {
        add_to_conn_hash(&fcp->conn_sub0);
        add_to_conn_hash(&fcp->conn_sub1);
    }

    /* do not insert fcp to ager and make it NO_REFRESH */
    fcp->fcflag |= FC_TIME_NO_REFRESH;

    /* Set the reason in the new connection to creation: this is used for traffic logging */	
    fcp->reason = FC_CREATION;

    /*
     * Generate flow connection init log
     */
    if (is_flow_conn_init_log) {
        if (need_log_for_connection(fcp)) {
            gen_conn_log(fcp);
        }
    }

    fcp->fcflag |= FC_INSTALLED;
}

/* install a flow connection
 * this vector never fail
 */
void
flow_install_conn(flow_connection_t *fcp)
{
    flow_print_basic("  %s: install the fcp %d\n", __FUNCTION__, fcp2id(fcp));
    flow_install_conn_no_refresh(fcp);

    /* remove the NO_REFRESH flag and insert it to ager */
    fcp->fcflag &= ~FC_TIME_NO_REFRESH;
}

void
flow_update_statistic(MBUF_IP_HDR_S *lhdr)
{
    if (lhdr->ucIsIcmpErr) {
        switch (lhdr->ucNextHdr) {
            case IPPROTO_TCP:
                this_flow_counter[FLOW_STAT_ICMP_ERR_TCP].counter++;
                break;
            case IPPROTO_UDP:
                this_flow_counter[FLOW_STAT_ICMP_ERR_UDP].counter++;
                break;
            case IPPROTO_ICMP:
                this_flow_counter[FLOW_STAT_ICMP_ERR_ICMP].counter++;
                break;
            default:
                this_flow_counter[FLOW_STAT_ICMP_ERR_OTHER].counter++;
                break;
        }
    } else {
        switch(lhdr->ucNextHdr) {
            case IPPROTO_TCP:
                if (!lhdr->ucIsFragment) {
                    this_flow_counter[FLOW_STAT_TCP].counter++;
                } else if (lhdr->ucIsFirstFrag) {
                    this_flow_counter[FLOW_STAT_TCP_FRAG_FST].counter++;
                } else if (lhdr->ucIsLastFrag) {
                    this_flow_counter[FLOW_STAT_TCP_FRAG_LST].counter++;
                } else {
                    this_flow_counter[FLOW_STAT_TCP_FRAG_MID].counter++;
                }
                break;
            case IPPROTO_UDP:
                if (!lhdr->ucIsFragment) {
                    this_flow_counter[FLOW_STAT_UDP].counter++;
                } else if (lhdr->ucIsFirstFrag) {
                    this_flow_counter[FLOW_STAT_UDP_FRAG_FST].counter++;
                } else if (lhdr->ucIsLastFrag) {
                    this_flow_counter[FLOW_STAT_UDP_FRAG_LST].counter++;
                } else {
                    this_flow_counter[FLOW_STAT_UDP_FRAG_MID].counter++;
                }
                break;
            case IPPROTO_ICMP:
                if (!lhdr->ucIsFragment) {
                    this_flow_counter[FLOW_STAT_ICMP].counter++;
                } else if (lhdr->ucIsFirstFrag) {
                    this_flow_counter[FLOW_STAT_ICMP_FRAG_FST].counter++;
                } else if (lhdr->ucIsLastFrag) {
                    this_flow_counter[FLOW_STAT_ICMP_FRAG_LST].counter++;
                } else {
                    this_flow_counter[FLOW_STAT_ICMP_FRAG_MID].counter++;
                }
                break;
            case IPPROTO_ICMPV6:
                if (!lhdr->ucIsFragment) {
                    this_flow_counter[FLOW_STAT_ICMP6].counter++;
                } else if (lhdr->ucIsFirstFrag) {
                    this_flow_counter[FLOW_STAT_ICMP6_FRAG_FST].counter++;
                } else if (lhdr->ucIsLastFrag) {
                    this_flow_counter[FLOW_STAT_ICMP6_FRAG_LST].counter++;
                } else {
                    this_flow_counter[FLOW_STAT_ICMP6_FRAG_MID].counter++;
                }
                break;
            default:
                if (!lhdr->ucIsFragment) {
                    this_flow_counter[FLOW_STAT_OTHER].counter++;
                } else if (lhdr->ucIsFirstFrag) {
                    this_flow_counter[FLOW_STAT_OTHER_FRAG_FST].counter++;
                } else if (lhdr->ucIsLastFrag) {
                    this_flow_counter[FLOW_STAT_OTHER_FRAG_LST].counter++;
                } else {
                    this_flow_counter[FLOW_STAT_OTHER_FRAG_MID].counter++;
                }
                break;
        }
    }
}

int
flow_parse_vector(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph;
    struct rte_ipv4_hdr iph_r;
    uint32_t iphdrlen, ports, icmp_err, non_first_frag;
    uint32_t *iptr;
    MBUF_S *lbuf;
    MBUF_IP_HDR_S *lhdr;
    uint16_t flag_offset;

    VECTOR_PROFILE(flow_parse_vector);

    lbuf = mbuf_from_rte_mbuf(mbuf);
    lhdr = &lbuf->stIpHdr;
    if (lhdr->ucFwd) {
        return flow_next_pak_vector(mbuf);
    }

    iph = ip4_hdr(mbuf);
    if ((iph->version_ihl & 0xf0) == 6) {
        return flow_parse_vector_v6(mbuf);
    }
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);
    ports = 0;
    non_first_frag = 0;

    flag_offset = rte_be_to_cpu_16(iph->fragment_offset);
    lhdr->ucIsFragment = ((flag_offset & RTE_IPV4_HDR_MF_FLAG) ||
                         (flag_offset & RTE_IPV4_HDR_OFFSET_MASK));
    if (lhdr->ucIsFragment) {
        lhdr->ucIsFirstFrag = !(flag_offset & RTE_IPV4_HDR_OFFSET_MASK);
        lhdr->ucIsLastFrag  = !(flag_offset & RTE_IPV4_HDR_MF_FLAG);
    }
    if (lhdr->ucIsFragment && !lhdr->ucIsFirstFrag) {
        non_first_frag = 1;
        goto assign_it;
    }

    switch(iph->next_proto_id) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            ports = *iptr;
            break;
        case IPPROTO_AH:
            /* spi of AH is the second LONG of the header */
            ports = *(iptr+1);
            break;
        case IPPROTO_ICMP:
            /*
             * for icmp, we return pointer to embedded ip packet,
             * address/port in the packet are also swapped to make
             * it appear as an returning packet for subsequent xlate.
             * icmp decoder can also decide abort session match by return NULL.
             */
            icmp_err = 0;
            iph = gen_icmp_lookup_info(iph, iptr, &iph_r, &ports, &icmp_err);
            if (iph == NULL) {
                this_flow_counter[FLOW_ERR_PARSE_ICMP_HEADER].counter++;
                return -1;
            } else if (iph == (struct rte_ipv4_hdr *)-1) {
                this_flow_counter[FLOW_ERR_PARSE_ICMP_REDIRECT].counter++;
                return -1;
            }
            break;
        default:
            this_flow_counter[FLOW_ERR_PARSE_NO_SUPPORT_PROT].counter++;
            return -1;
            break;
    }

assign_it:
    lhdr->lhdr_src_ip_4 = iph->src_addr;
    lhdr->lhdr_dst_ip_4 = iph->dst_addr;
    lhdr->ipid          = iph->packet_id;
    lhdr->lhdr_src_port = ip_src_port(ports);
    lhdr->lhdr_dst_port = ip_dst_port(ports);
    lhdr->ucNextHdr = iph->next_proto_id;
    if (iph->next_proto_id == IPPROTO_ICMP && !non_first_frag) {
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)iptr;
        lhdr->lhdr_icmp_type = icmp->icmp_type;
        lhdr->lhdr_icmp_code = icmp->icmp_code;
        lhdr->lhdr_icmp_id   = icmp->icmp_ident;
        if (icmp_err) {
            lhdr->ucIsIcmpErr = 1;
            SESSION_MBUF_SET_FLAG(lbuf, SESSION_MBUF_ICMPERR | SESSION_MBUF_PROCESSED);
        }
    }
    lhdr->iptr = iptr;
    flow_update_statistic(lhdr);

    return flow_next_pak_vector(mbuf);
}

int
flow_filter_vector(struct rte_mbuf *mbuf)
{
    MBUF_S *lbuf;
    MBUF_IP_HDR_S *lhdr;

    VECTOR_PROFILE(flow_filter_vector);

    lbuf = mbuf_from_rte_mbuf(mbuf);
    lhdr = &lbuf->stIpHdr;

    if (lhdr->ucFwd) {
        this_ffilter_show_this_pak = lhdr->ucMark;
    } else {
        flow_mark_pak(lhdr, 0);
    }
    flow_print_packet(mbuf);
    flow_print_basic("%s mark this packet.\n", __FUNCTION__);

    return flow_next_pak_vector(mbuf);
}

#ifdef TYFLOW_PER_THREAD
int
flow_fwd_vector(struct rte_mbuf *mbuf)
{
    MBUF_S *lbuf;
    MBUF_IP_HDR_S *lhdr;
    lcoreid_t hash;
    int rc;

    VECTOR_PROFILE(flow_filter_vector);
    if (flow_worker_num <= 1) {
        return flow_next_pak_vector(mbuf);
    }

    flow_print_basic("%s entry\n", __FUNCTION__);
    lbuf = mbuf_from_rte_mbuf(mbuf);
    lhdr = &lbuf->stIpHdr;

    if (lhdr->ucIsIpv6) {
        hash = flow_fwd_hash(lhdr->lhdr_src_ip_6_3, lhdr->lhdr_dst_ip_6_3, lhdr->ucNextHdr);
    } else {
        hash = flow_fwd_hash(lhdr->lhdr_src_ip_4, lhdr->lhdr_dst_ip_4, lhdr->ucNextHdr);
    }
    if (hash != rte_lcore_id()) {
        lhdr->ucFwd = 1;
        rc = flow_fwd_enq(rte_lcore_id(), hash, mbuf);
        flow_print_basic("  fwd mbuf %p %d->%d %s\n", 
                         mbuf, rte_lcore_id(), hash, 
                         rc?"failed":"ok");
        if (rc) {
            this_flow_counter[FLOW_ERR_FWD].counter++;
            return FLOW_RET_ERR;
        } else {
            this_flow_counter[FLOW_STAT_FWD].counter++;
            return (hash<<16);
        }
    }

    return flow_next_pak_vector(mbuf);
}
#endif

/*
 * flow tunnel vector
 */
int
flow_tunnel_handling(struct rte_mbuf *mbuf)
{
    return 0;
}

/*
 * flow decap vetor
 * in this vector we will handle tunnel decrypt & flow connection lookup
 */
int
flow_decap_vector(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp;
    flow_connection_t *fcp;
    uint32_t fcid;
    MBUF_S *lbuf;
    MBUF_IP_HDR_S *lhdr;

    VECTOR_PROFILE(flow_decap_vector);

    flow_print_basic("%s entry\n", __FUNCTION__);
    lbuf = mbuf_from_rte_mbuf(mbuf);
    lhdr = &lbuf->stIpHdr;
    csp = GET_CSP_FROM_LBUF(lbuf);
    if (!csp) {
        /* ip non-first fragment */
        if (lhdr->ucIsFragment && !lhdr->ucIsFirstFrag) {
            flow_defrag_nonfirst_vector(mbuf);
            /* non-first fragment without csp will be dropped */
            csp = GET_CSP_FROM_LBUF(lbuf);
            if (!csp) {
                flow_print_basic("  non-first fragment packet do not have connection.\n");
                return -1;
            } else {
                flow_print_basic("  non-first fragment packet re-enter, fcp id %d\n", fcp2id(csp2base(csp)));
                return 0;
            }
        }
        if (flow_find_connection(mbuf) < 0) {
            return -1;
        }
        if (lhdr->ucIsFragment && lhdr->ucIsFirstFrag) {
            /* 
             * for the first fragment, it's going to create fcb 
             * we do not check the rc since the following fragments
             * will not match the fcb and then be dropped always
             */
            flow_defrag_first_vector(mbuf);
        }
    } else {
        flow_print_basic("  flow packet already have connection.\n");
    }

    fcp = GET_FC_FROM_LBUF(lbuf);
    if (fcp == this_flow_conn_crt) {
        fcid = 0;
    } else {
        fcid = fcp2id(fcp);
        flow_refresh_connection(fcp);
    }
    flow_print_basic("  flow connection id %u\n", fcid);

    if (!is_tunnel_conn(fcp)) {
        return flow_next_pak_vector(mbuf);
    }

    return flow_tunnel_handling(mbuf);
}

struct rte_mbuf *
flow_gen_icmp_pak(uint8_t __rte_unused type, uint8_t __rte_unused code)
{
#if 0
    struct rte_mempool *pool;
    struct rte_mbuf *mbuf = NULL;
    pool = get_mbuf_pool(this_flow);
    mbuf = rte_pktmbuf_alloc(pool);
    if (!mbuf) {
        flow_print("  %s failed, no enough mbuf\n", __FUNCTION__);
        return NULL;
    }

    flow_set_icmp_pak();
#endif
    return 0;
}

int
flow_fast_for_self(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp, *peer;
    struct rte_ipv4_hdr *iph;
    uint32_t iphdrlen;
    uint32_t *iptr;

    VECTOR_PROFILE(flow_fast_for_self);

    flow_print_basic(" %s entry.\n", __FUNCTION__);

    csp  = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
    if (csp->cspflag & CSP_TO_SELF_PING &&
        peer->cspflag & CSP_FROM_SELF) {
        iph = ip4_hdr(mbuf);
        iphdrlen = ip4_hdrlen(mbuf);
        iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

        flow_reply_ping(iph, iphdrlen, iptr, mbuf, &peer->csp_ipid);
        SET_CSP_TO_MBUF(mbuf, peer);
    }

    return flow_next_pak_vector(mbuf);
}

extern int
is_route_del(struct route_entry *route);
int
flow_fast_check_routing(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp, *peer;
    struct route_entry *rt = NULL;

    VECTOR_PROFILE(flow_fast_check_routing);

    flow_print_basic(" %s entry.\n", __FUNCTION__);

    csp = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
#ifndef TYFLOW_LEGACY
    if (csp->cspflag & CSP_FROM_SELF &&
        peer->cspflag & CSP_TO_SELF_PING &&
        !peer->route) {
        rt = flow_route_lookup(mbuf, peer->csp_src_ip);
        flow_print_basic("  flow echo find route to %s\n",
                         rt?rt->port->name:"null");
        peer->route = rt;
        peer->ifp = rt?rt->port:NULL;
        return flow_next_pak_vector(mbuf);
    }
    rt = GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
#else
    rt = route4_input(mbuf, (struct in_addr *)&peer->csp_src_ip,
                      (struct in_addr *)&peer->csp_dst_ip,
                      0, NULL);
#endif
    if (peer->route != (void *)rt) {
        if (peer->route) {
            route4_put(peer->route);
            peer->cspflag |= CSP_IFP_UPDATE;
            flow_print_basic("  csp update the ifp %s->%s\n", 
                       (peer->ifp)?peer->ifp->name:"uncertain", 
                       (rt->port)?rt->port->name:"uncertain");
        }

        peer->route = (void *)rt;
#ifndef TYFLOW_LEGACY
        route4_get(rt);
#endif
        peer->ifp = rt->port;
    }
#if FLOW_B4_FORWARD
    if (peer->route && !is_route_del(peer->route)) {
        if (peer->route->port == peer->ifp) {
            flow_print_basic("  csp had been set already %s\n", peer->ifp->name);
        } else {
            flow_print_basic("  csp update the ifp %s->%s\n", 
                       (peer->ifp)?peer->ifp->name:"uncertain", 
                       (peer->route->port)?peer->route->port->name:"uncertain");
            peer->ifp = peer->route->port;
            peer->cspflag |= CSP_IFP_UPDATE;
        }
    } else {
        /* we are going to find a new valid route, put the old one if any */
        if (peer->route)
            route4_put(peer->route);
#ifndef TYFLOW_LEGACY
        rt = flow_route_lookup(mbuf, peer->csp_src_ip);
#else
        rt = route4_input(mbuf, (struct in_addr *)&peer->csp_src_ip,
                          (struct in_addr *)&peer->csp_dst_ip,
                          0, NULL);
#endif
        if (!rt) {
            flow_print_basic("  no reverse route to 0x%x\n", ntohl(peer->csp_src_ip));
            this_flow_counter[FLOW_ERR_NO_R_ROUTE].counter++;
            return FLOW_RET_ERR;
        } else if (!rt->port) {
            flow_print_basic("  reverse route 0x%llx have no interface\n", rt);
            this_flow_counter[FLOW_ERR_NO_R_ROUTE_IFP].counter++;
            return FLOW_RET_ERR;
        }
        peer->route = rt;
        if (rt->port != peer->ifp) {
            flow_print_basic("  csp update the ifp %s->%s\n", 
                       (peer->ifp)?peer->ifp->name:"uncertain", 
                       (rt->port)?rt->port->name:"uncertain");
            peer->ifp = rt->port;
            peer->cspflag |= CSP_IFP_UPDATE;
        }
    }

#endif
    return flow_next_pak_vector(mbuf);
}

int
flow_fast_reinject_out(struct rte_mbuf *mbuf)
{
    VECTOR_PROFILE(flow_fast_reinject_out);
    flow_print_basic(" %s entry.\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

int
flow_fast_fw_entry(struct rte_mbuf *mbuf)
{
	INT iRet;
    conn_sub_t *csp;
    flow_connection_t *fcp;

    VECTOR_PROFILE(flow_fast_fw_entry);

    if (flow_skip_fw) {
        flow_print_basic("  %s flow skip firewall handling\n", __FUNCTION__);
        return flow_next_pak_vector(mbuf);
    }

    csp = GET_CSP_FROM_MBUF(mbuf);
    fcp = csp2base(csp);
    if (csp->cspflag & CSP_DISABLE ||
        fcp->policy_seq < g_policy_seq) {
        return flow_first_fw_entry(mbuf);
    }
    flow_print_basic(" %s entry.\n", __FUNCTION__);
    if (csp->cspflag & (CSP_FROM_SELF | CSP_TO_SELF)) {
        flow_print_basic("  skip the to-self / from-self pak\n");
        return flow_next_pak_vector(mbuf);
    }

    if (csp->cspflag & CSP_FLAG_IPV6) {
        iRet = SESSION6_FsServiceProc(mbuf);
    } else {
        iRet = SESSION_FsServiceProc(mbuf);
    }
    
	if(FLOW_RET_OK != iRet)
	{
        this_flow_counter[FLOW_ERR_FAST_FW].counter++;
		return iRet;
	}
	
    return flow_next_pak_vector(mbuf);
}

extern int neigh_output(int af, union inet_addr *nexhop,
                 struct rte_mbuf *m, struct netif_port *port);
extern int
flow_ipv4_output(struct rte_mbuf *mbuf);
int 
flow_ipv4_output(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp = GET_CSP_FROM_MBUF(mbuf);
    struct route_entry *rt = (struct route_entry *)(csp2peer(csp)->route);
    int err;
    struct in_addr nexthop;

    if (rt->gw.s_addr == htonl(INADDR_ANY))
        nexthop.s_addr = ip4_hdr(mbuf)->dst_addr;
    else
        nexthop = rt->gw;

    /**
     * XXX:
     * because lacking of suitable fields in mbuf
     * (m.l3_type is only 4 bits, too short),
     * m.packet_type is used to save ether_type
     * e.g., 0x0800 for IPv4.
     * note it was used in RX path for eth_type_t.
     * really confusing.
     */
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;
    mbuf->l3_len = ip4_hdrlen(mbuf);

    /* reuse @userdata/@udata64 for prio (used by tc:pfifo_fast) */
	mbuf_udata64_set(mbuf, ((ip4_hdr(mbuf)->type_of_service >> 1) & 15));
    err = neigh_output(AF_INET, (union inet_addr *)&nexthop, mbuf, rt->port);
    return err;
}

#ifndef TYFLOW_LEGACY
#else
extern int ipv4_output_fin2(struct rte_mbuf *mbuf);
int
flow_fast_send_out(struct rte_mbuf *mbuf)
{
    int rc;

    VECTOR_PROFILE(flow_fast_send_out);

    flow_print_basic(" %s entry.\n", __FUNCTION__);
    conn_sub_t *csp = GET_CSP_FROM_MBUF(mbuf);
    struct route_entry *rt = (struct route_entry *)(csp2peer(csp)->route);
    if (!rt->port) {
        flow_print_basic(" route 0x%llx no interface, dest 0x%x, refcnt %d.\n",
                   rt, rt->dest, rte_atomic32_read(&rt->refcnt));
        return FLOW_RET_ERR;
    }
    rc = flow_ipv4_output(mbuf);
    if (rc) {
        this_flow_counter[FLOW_ERR_SEND_OUT].counter++;
        flow_print_basic("  failed to send out %s.\n", rt->port->name);
        return FLOW_RET_ERR;
    }
    return flow_next_pak_vector(mbuf);
}
#endif

int
flow_send_return_pak(struct rte_mbuf *mbuf)
{
    return 0;
}

/*
 * main flow functions.
 */
int 
flow_main_body_vector (struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp;
    conn_sub_t *csp;

    VECTOR_PROFILE(flow_main_body_vector);

    flow_print_basic("%s entry\n", __FUNCTION__);
    csp = GET_CSP_FROM_MBUF(mbuf);
    fcp = csp2base(csp);
    rte_prefetch0(csp);
    rte_prefetch0(fcp);

    if (is_tunnel_conn(fcp)) {
        /* tunnel handling here */
    }

    /* check mtu here */
    /*
     * 0. packet does not terminate at us
     * 1. packet has DF bit on
     * 2. packet is bigger than min mtu size
     */
    if (0/* need to send icmp */) {
        struct rte_mbuf *npak;
        npak = flow_gen_icmp_pak(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED);
        if (npak)
            flow_send_return_pak(npak);
        this_flow_counter[FLOW_ERR_ICMP_GEN].counter++;
        return -1;
    }

    csp->pkt_cnt ++;
    csp->byte_cnt += rte_pktmbuf_pkt_len(mbuf);

    /* goto fast path */
    flow_set_pak_vector((csp->cspflag & CSP_FLAG_IPV6)?
                        flow_fast_vector_list_v6:
                        flow_fast_vector_list);
    return 0;
}

void
flow_update_policy_seq(void)
{
    g_policy_seq++;
}

int
flow_drop_packet(struct rte_mbuf *mbuf)
{
#ifdef TYFLOW_LEGACY
    flow_print_basic("  drop the packet 0x%llx\n", mbuf);
    rte_pktmbuf_free(mbuf);
#endif
    return 0;
}

/*
 * the entry for one packet processing
 * give a meaningful wrapper name 
 * need to add some performance counter
 */
static int 
flow_proc_one_pak(struct rte_mbuf *mbuf)
{
    int rc = FLOW_RET_OK;
    uint8_t *version;
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    /* clear the lbuf part right after the struct rte_mbuf */
    if (!lbuf->stIpHdr.ucFwd) {
        memset(lbuf, 0, sizeof(MBUF_S));
    }

    version = rte_pktmbuf_mtod(mbuf, uint8_t *);
    if ((*version & 0xf0) == 0x60) {
        lbuf->stIpHdr.ucIsIpv6 = 1;
    }

    this_flow_vector_list = lbuf->stIpHdr.ucIsIpv6 ? 
                            flow_ipv6_vector_list: flow_ipv4_vector_list;

    rc = flow_walk_vector_list(mbuf);
#ifdef TYFLOW_LEGACY
    if (rc < 0) {
        flow_drop_packet(mbuf);
    }
#endif
    if (rc < FLOW_RET_FWD_BAR || rc > FLOW_RET_FWD_BAR2) {
        lbuf->stIpHdr.ucFwd = 0;
    }
    return rc;
    /* 
     * we do not actually send the packet out in this loop 
     * instead we call netif_hard_xmit to queue the packet 
     * in the xmit queue
     */
    /*
    if (rc == FLOW_RET_OK) {
        flow_free_packet(mbuf);
    }
    */
}

int
flow_handle_other_queue()
{
    return 0;
}
/*
 * top level pak processing scheduler.
 * better to add a poll queue
 */
int
flow_processing_paks(struct rte_mbuf *mbuf)
{
    int rc;

    FLOW_PROFILE_VECTOR_START;
    flow_debug_trace(FLOW_DEBUG_BASIC, "%s entry, packet 0x%llx\n", 
                     __FUNCTION__, mbuf); 

    this_flow_counter[FLOW_STAT_PAK].counter++;

    /* add some performance counter */
    /* add some cpu constraint */
    /* add some queue handling */
    if (rte_atomic32_read(&this_flow_status)) {
        rc = flow_proc_one_pak(mbuf);

        flow_handle_other_queue();
    }
    FLOW_PROFILE_VECTOR_END;
    return rc;
}

int
flow_init(void)
{
    lcoreid_t cid;
    int err;

    err = flow_cli_init();
    if (err < 0) {
        RTE_LOG(ERR, FLOW, "%s: flow init cli failed\n",
                __func__);
        return err;
    }

    rte_atomic32_init(&this_flow_status);
    err = flow_fwd_init();
    if (err < 0) {
        RTE_LOG(ERR, FLOW, "%s: flow init fwd failed\n",
                __func__);
        return err;
    }

    rte_eal_mp_remote_launch(flow_conn_init, NULL, SKIP_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(ERR, FLOW, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
            return err;
        }
    }
    return 0;
}
