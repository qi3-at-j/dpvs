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
#include "vlan.h"
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
#include <arpa/inet.h>
#include <ipvs/redirect.h>

#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"


/*Head/hdr is never need to be protected since we make it per lcore*/
/*other wants to use it need to be careful, maybe add a new lock version?*/
static inline void lifo_enqueue (void *head, void *y, int nxt_offset)
{
    char *yy = (char *)y;
    int **hdr = (int **)head;
	*(int *)(yy + nxt_offset) = (uint)*hdr;
	*hdr = (int *)y;
}

static inline void *lifo_dequeue (void *head, int offset)
{
    int **hdr = (int **)head;
    int *y;
    y = *hdr;
	if (y == NULL) {
		goto end;
	}

	*hdr = (uint *)(*(uint *)((uint)y + offset));

end:
	return (void *)y;
}

#define FLOW_CONN_MAX_NUMBER       (0x80000)   /*512K*/
#define FLOW_CONN_HASH_TAB_SIZE    (0x10000)   /*64K*/
#define FLOW_CONN_HASH_TAB_MASK    (FLOW_CONN_HASH_TAB_SIZE-1)

#define FLOW_CONN_NOTIMEOUT   65535     /* indicate no timeout */
#if 0
flow_connection_t *flowConnTable[RTE_MAX_LCORE];
flow_connection_t *flowConnHead[RTE_MAX_LCORE];
flow_connection_t **flow_conn_hash_base[RTE_MAX_LCORE];    /* per lcore flow connection hash tab base*/
uint32_t *flow_conn_hash_cnt_base[RTE_MAX_LCORE];       /* per lcore flow connection hash cnt table base */
#endif

/* per lcore flow connection table */
static RTE_DEFINE_PER_LCORE(flow_connection_t *, flowConnTable);
/* per lcore flow connection lifo head */
static RTE_DEFINE_PER_LCORE(flow_connection_t *, flowConnHead);
/* per lcore flow connection hash tab base*/
static RTE_DEFINE_PER_LCORE(struct hlist_head * /* conn_sub_t** */, flow_conn_hash_base);
/* per lcore flow connection hash cnt table base */
static RTE_DEFINE_PER_LCORE(uint32_t *, flow_conn_hash_cnt_base);

/* per lcore flow connection statistics */
static RTE_DEFINE_PER_LCORE(uint32_t, flow_curr_conn);
static RTE_DEFINE_PER_LCORE(uint32_t, flow_invalid_conn);
static RTE_DEFINE_PER_LCORE(uint32_t, flow_no_conn);
static RTE_DEFINE_PER_LCORE(uint32_t, flow_free_conn);

/* per lcore flow connection ager */
static RTE_DEFINE_PER_LCORE(struct rte_timer, flow_conn_ager);

/* per lcore flow vector list */
static RTE_DEFINE_PER_LCORE(flow_vector_t *, flow_vector_list);

#define this_flowConnTable           (RTE_PER_LCORE(flowConnTable))
#define this_flowConnHead            (RTE_PER_LCORE(flowConnHead))
#define this_flow_conn_hash_base     (RTE_PER_LCORE(flow_conn_hash_base))
#define this_flow_conn_hash_cnt_base (RTE_PER_LCORE(flow_conn_hash_cnt_base))
#define this_flow_curr_conn          (RTE_PER_LCORE(flow_curr_conn))
#define this_flow_invalid_conn       (RTE_PER_LCORE(flow_invalid_conn))
#define this_flow_no_conn            (RTE_PER_LCORE(flow_no_conn))
#define this_flow_free_conn          (RTE_PER_LCORE(flow_free_conn))
#define this_flow_conn_ager          (RTE_PER_LCORE(flow_conn_ager))
#define this_flow_vector_list        (RTE_PER_LCORE(flow_vector_list))

/*
 * Clean up leftovers in conn_sub_t block.
 * This cleanup is very important
 * as the conn_sub_t block will be allocated
 * later and most of its content will be used as is.
 */
void init_conn_sub (conn_sub_t *csp)
{
	memset((void*)&csp->start,0,sizeof(conn_sub_t)-3);
	csp->cspflag = CSP_FREE | CSP_INVALID;
}

/*
 * free a flow_connection_t into free pool. 
 * this function may be called from the flow, or from the ager.
 * NOTE: this function is not protected by the lock. 
 */
static inline void flow_free_conn_into_free_pool(flow_connection_t *fcp)
{
	int offset = (int)&((flow_connection_t *)0)->next;
	
	lifo_enqueue(&this_flowConnHead, fcp, offset);

	atomic_dec((atomic_t *)&flow_cur_connection);

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
		atomic_dec((atomic_t *)&flow_invalid_connection);
	}
		
    fcp->time = 0;
    fcp->time_const = 0;
    fcp->start_time = 0;
    fcp->duration = 0;
    fcp->fcflag = 0;
    fcp->byte_cnt = 0;
    fcp->pkt_cnt = 0;
    fcp->reason = 0;
    fcp->fwsession = 0;
}

/* all resource attached to the flow connection should be freed here */
void flow_free_this_conn (flow_connection_t *fcp)
{
    int status;

    if(is_csp_l2info_arp(&fcp->conn_sub0))
        clear_csp_l2info_arp(&fcp->conn_sub0);

    /* clear arp ref_cnt for wing 2*/
    if(is_csp_l2info_arp(&fcp->conn_sub1))
        clear_csp_l2info_arp(&fcp->conn_sub1);

    flow_init_connection(fcp);

    flow_free_conn_into_free_pool(fcp);
}

extern uint64_t g_cycles_per_sec;
/* 
 * called during sys init time.
 */
void flow_conn_init (void)
{
	natConnection *natp;
	natConnection_m *natmp;
#if !defined (NS5000) && !defined (NS2000) && !defined (NS5000P)
	server_t *server = NULL;
#endif
    uint32_t lcore_id, socket_id;
    uint32_t socket_cnt = rte_socket_count();
    uint32_t i;
    lcore_id = rte_lcore_id();
    flow_connection_t *fcp;
	uint32_t cnt;
	conn_sub_t *csp0;
	conn_sub_t *csp1;

    this_flowConnTable = (flow_connection_t *)rte_malloc("flow_conn_table", sizeof(flow_connection_t)*FLOW_CONN_MAX_NUMBER, 0);
    if (!this_flowConnTable) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow connection\n",
                __FUNCTION__);
        goto bad;
    }

    this_flow_conn_hash_base = (struct hlist_head *)rte_zmalloc("flow_conn_hash", sizeof(struct hlist_head)*FLOW_CONN_HASH_TAB_SIZE, 0); 
    if (!this_flow_conn_hash_base) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow conn hash\n",
                __FUNCTION__);
        goto bad;
    }

    this_flow_conn_hash_cnt_base = (uint32_t *)rte_zmalloc("flow_conn_hash_cnt", sizeof(uint32_t)*FLOW_CONN_HASH_TAB_SIZE, 0);
    if (!this_flow_conn_hash_cnt_base) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow conn hash cnt\n",
                __FUNCTION__);
        goto bad;
    }

	/*
	 * init nat conn table.
	 * we do not use the 0th flow conn entry since
	 * its index is 0, and 0 in udp/tcp lookup table
	 * means no entry.
	 */
	this_flowConnHead = NULL;
	fcp = this_flowConnHead + 1;
	for (cnt = 1; cnt < FLOW_CONN_MAX_NUMBER; cnt++) {
		memset(fcp, 0, sizeof(conn_sub_t));
		/* assign session id, but not for 1000 */
		csp0 = &fcp->conn_sub0;
		csp1 = &fcp->conn_sub1;
		csp0->peer_offset = (uint)csp1 - (uint)csp0;
		csp1->peer_offset = (uint)csp0 - (uint)csp1;
		csp0->base_offset = (uint)fcp - (uint)csp0;
		csp1->base_offset = (uint)fcp - (uint)csp1;
        csp0->resv = RESV_AA;
        csp1->resv = RESV_BB;
		/*
		 * put into free pool.
		 */
		flow_free_this_conn(fcp);

		fcp++;
	}

    this_flow_curr_conn = 0;
    this_flow_invalid_conn = 0;
    this_flow_no_conn = 0;
    this_flow_free_conn = FLOW_CONN_MAX_NUMBER-1;

	add_clr_cmd(&cnode(clr_session));
	add_get_cmd(&cnode(get_session));

	/*
	 * notify me if a policy is gone.
	 */
	add_policy_delete_registry((void *)flow_age_conn_by_policy);

	/*
	 * notify me if ha peer state change
	 */
	add_ha_peer_state_change_registry(flow_ha_peer_state_change);

	/*
	 * notify me if an interface is gone
	 */
	add_delete_if_registry((void *)flow_clear_conn_by_ifp);

    dpvs_timer_sched(&g_minute_timer, &tv, minute_timer_expire, NULL, true);
    rte_timer_init(&this_flow_conn_ager);
    rte_timer_reset(&timer0, g_cycles_per_sec*2, PERIODICAL, lcore_id, timer0_cb, NULL);
}

static flow_vector_t flow_first_vector_list[] =
{
    flow_first_sanity_check,
    flow_first_alloc_connection,
    flow_first_hole_search,
    flow_first_for_self,
    flow_first_fw_entry,
    flow_first_install_connection,
    NULL
};

static flow_vector_t flow_fast_vector_list[] =
{
    flow_fast_common,
    flow_fast_reinject,
    flow_fast_fw_entry,
    NULL
};

static flow_vector_t flow_ipv4_vector_list[] = 
{
    flow_filter_vector,
    flow_decap_vector,
    flow_main_body_vector,
    NULL
};

static inline int 
flow_set_pak_vector(flow_vector_t *vector)
{
    this_flow_vector_list = vector;
    return 0;
}

/*
 * resume packet processing from the where it stops.
 * make the vector pacing by flow_next_pak_vector
 */
int 
flow_walk_vector_list (struct rte_mbuf *mbuf)
{
	int rc;
    flow_vector_t *vector = this_flow_vector_list;

    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
        char saddr[16], daddr[16];
        struct rte_ipv4_hdr *iph;
        uint32_t iphdrlen;
        uint32_t *iptr;

        iph = ip4_hdr(mbuf);
        iphdrlen = ip4_hdrlen(mbuf);
        iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);
        inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr));
        flow_debug_trace_no_flag("\n**** jump to packet: %s/%d->%s/%d@%d\n",
                                 saddr,
                                 ip_src_port(*iptr),
                                 daddr,
                                 ip_dst_port(*iptr),
                                 iph->next_proto_id);
    }

	while (*vector) {
		if ((rc = (*vector)(mbuf))) {
			flow_debug_trace(FLOW_DEBUG_BASIC, "**** pak processing end(%d).\n", rc);
			return rc;
		}
	}
	flow_debug_trace(FLOW_DEBUG_BASIC, "**** pak processing end.\n");
	return 0;
}

/* goto next vector */
static inline int 
flow_next_pak_vector(struct rte_mbuf *mbuf)
{
    this_flow_vector_list++;
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
		icmp->type == ICMP_TIMESTAMP ||
		icmp->type == ICMP_INFO_REQUEST)
		return icmp->icmp_seq_nb;
	else if (icmp->type == ICMP_ECHOREPLY ||
		     icmp->type == ICMP_TIMESTAMPREPLY ||
             icmp->type == ICMP_INFO_REPLY)
		return icmp->icmp_ident;
	return 0;
}

/*
 * use id number in icmp req, and seq number in icmp rsp.
 * returns - the dst port number in network byte order.
 */
static inline int ping_dst_port (struct rte_icmp_hdr *icmp)
{
	if (icmp->type == ICMP_ECHO      ||
		icmp->type == ICMP_TIMESTAMP ||
		icmp->type == ICMP_INFO_REQUEST)
		return icmp->icmp_ident;
	else if (icmp->type == ICMP_ECHOREPLY||
             icmp->type == ICMP_TIMESTAMPREPLY||
             icmp->type == ICMP_INFO_REPLY)
		return icmp->icmp_seq_nb;
	else
		return 0;
}

/* Forms ports for ICMP req/resp packets. */
static __inline__ uint32_t icmp_ping_ports_form( icmp_hdr_t* icmp )
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return (ping_dst_port(icmp) << 16) | ping_src_port(icmp);
    else 
        return (ping_src_port(icmp) << 16) | ping_dst_port(icmp);
}

/* To ensure proper endianness use icmp_ping_ports_form to extract src/
 * dst ports from the value returned by this function. */
int icmp_ports (icmp_hdr_t *icmp)
{
	if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY ||
		icmp->type == ICMP_TIMESTAMP || icmp->type == ICMP_TIMESTAMPREPLY ||
		icmp->type == ICMP_INFO_REQUEST || icmp->type == ICMP_INFO_REPLY) {
        return icmp_ping_ports_form( icmp );
	}

	/*
	 * the following value needs to be consistent with default
	 * return value of ip_proto_ports().
	 */
	return htonl(0x00010001);
}

static inline uint ip_proto_ports_embed_icmp (uint8_t prot, uint32_t *iptr)
{
	if (prot == IPPROTO_TCP || prot == IPPROTO_UDP || prot == IPPROTO_ESP) {
		return *iptr;
	}
	else if (prot == IPPROTO_AH) {
		return *(iptr+1);			/* spi of AH is the second LONG of the header */
	}
	else if (prot == IP_PROT_ICMP) {
		return icmp_ports((struct rte_icmp_hdr *)iptr);
	}
	return htonl(0x00010001);
}

/*
 * return proper src port for udp/tcp
 */
static inline uint32_t ip_src_port (uint32_t ports)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return ports & 0xffff;
    else 
        return ports >> 16;
}
/*
 * return proper dst port for udp/tcp
 */
static inline uint32_t ip_dst_port (uint32_t ports)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return ports >> 16;
    else
        return ports & 0xffff;
}

/*
 * Endian safe way to form ports from src and dst ports.
 */
static __inline__ uint32_t ip_ports_form(uint16_t src_port, uint16_t dst_port)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return (dst_port << 16) | src_port;
    else 
        return (src_port << 16) | dst_port;
}

static void swap_ip_port (rte_ipv4_hdr *iphdr, uint32_t *iptr, uint32_t *ports)
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
gen_icmp_lookup_info (rte_ipv4_hdr *iphdr, uint32_t *iptr, struct rte_mbuf *mbuf, rte_ipv4_hdr *iphdr_inner, uint32_t *ports)
{
	rte_icmp_hdr *icmp;

	icmp = (rte_icmp_hdr *)iptr;
	if (IS_ICMP_REQ(icmp->icmp_type) ||
		IS_ICMP_RSP(icmp->icmp_type)) {
		*lports = icmp_ping_lports_form(icmp);
	}
    else if (HAS_EMBEDDED_IP(icmp->icmp_type)) { 
        /*
         * for these icmp message, use embedded ip header
         * for session lookup
         */
        iphdr = (rte_ipv4_hdr *)(iptr + sizeof(rte_icmp_hdr));
        /*
         * we copy the original iphdr out so only alter
         * the copy not the original.
         */
        memcpy(iphdr_inner, iphdr, sizeof(rte_ipv4_hdr));
        iptr = ((uint32_t *)iphdr + (iphdr->version_ihl & 0xf));
        swap_ip_port(iphdr_r, iptr, ports);
        /* todo
         * add some debug trace here
         */

        if (icmp->type == ICMP_REDIRECT) {
            return (struct rte_ipv4_hdr *)-1;
        }

        iphdr = iphdr_r;

        /* we don't want to refresh flow connection for ICMP error cases */
        mbuf->flag |= PAK_NO_REFRESH | PAK_EMBED_ICMP ;

    } else
        *ports = htonl(0x00010001);
    return iphdr;
}

/*
 * hash packet for flow conn_sub_t.
 * need to tune it in accordance with the real traffic
 */
static inline uint32_t _nat_hash (uint32_t s, uint32_t d, uint32_t p)
{
	register uint32_t a;
	register uint32_t m = 0xffff; /* mask for a short int */

	a = ((s>>16) ^ ((s<<8)&m));
	a = a ^ ((d>>16) ^ ((d<<8)&m));
	a = a ^ ((p>>16) ^ ((p<<8)&m));
	
	return a;
}

static inline int conn_hash (uint s, uint d, uint p)
{
	return (_nat_hash(s, d, p) & FLOW_CONN_HASH_TAB_MASK);
}

/* generic way for flow conn_sub_t comparison */
#define FOR_ALL_NAT_SESSION(node, src_adr, dst_adr, ports, head, csp, cnt)  					        \
        for (cnt = conn_hash(src_adr, dst_adr, ports), 													\
			node = (this_flow_conn_hash_base + cnt)->first,	                                            \
            csp = container_of(node, conn_sub_t, hnode), head = csp,                                    \
            cnt = *(this_flow_conn_hash_cnt_base + cnt);           					                    \
            node && csp = container_of(node, conn_sub_t, hnode) && ({ rte_prefetch0(node->next); 1;});  \
            node = node->next, csp = container_of(node, conn_sub_t, hnode))

/*
 * first path packet processing
 * give a meaningful wrapper name 
 * need to add some performance counter
 */
int
flow_proc_first_pak(struct rte_mbuf *mbuf)
{
    /* add some performance counter here */
    return flow_walk_vector_list(mbuf);
}

/*
 * main entry point for first path
 * in this function we'll try to find a connection for incoming packet
 *
 */
int 
flow_find_connection(struct rte_mbuf *mbuf)
{
	flow_vector_t *vector;
	int rc;
	conn_sub_t *csp = NULL;
    flow_connection_t *fcp = NULL;
    struct rte_ipv4_hdr *iph;
    struct rte_ipv4_hdr iph_r;
    uint32_t iphdrlen, ports;
    uint32_t *iptr;
    struct hlist_node *node;

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

    switch (iph->next_proto_id) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            ports = *iptr;
            break;
        case IPPROTO_AH:
            ports = *(iptr+1);         /* spi of AH is the second LONG of the header */
            break;
        case IPPROTO_ICMP:
            /*
             * for icmp, we return pointer to embedded ip packet,
             * address/port in the packet are also swapped to make
             * it appear as an returning packet for subsequent xlate.
             * icmp decoder can also decide abort session match by return NULL.
             */
            iph = gen_icmp_lookup_info(iph, iptr, mbuf, &iph_r, &ports);
            if (iph == NULL) {
                return NULL;
            } else if (iph == (struct rte_ipv4_hdr *)-1) {
                return -1;
            }
            break;
        default:
            break;
    }

    FOR_ALL_NAT_SESSION(node, iph->src_addr, iph->dst_addr, ports, head, csp, cnt) {
        if (CONN_SUB_COMP(csp, iph, ports, 1)) {
            fcp = csp2base(csp);
            if ((fcp->natflag & FC_INVALID) == 0) {
                break;
            }
        }
    }

    if (fcp) {
        flow_debug_trace(FLOW_DEBUG_BASIC, "  existing connection found. id %d\n", fcp2id(fcp));
        SET_CSP_TO_MBUF(mbuf, (uint64_t)csp);
        if (IS_CSP_DISABLE(csp)) {
            /* do something */
        }
    } else {
        /* 
         * first pak, try to creat a new one 
         */
        flow_debug_trace(FLOW_DEBUG_BASIC, "  no session found\n");

        /*
         * keep original vector list
         */
        vector = this_flow_vector_list;
        flow_set_pak_vector(flow_first_vector_list);
        rc = flow_proc_first_pak(mbuf);
        if (rc) {
            flow_set_pak_vector(vector);
            return rc;
        }
        /* restor vector list */
        flow_set_pak_vector(vector);
    }
    return 0;
}

int 
flow_first_sanity_check(struct rte_mbuf *mbuf)
{
    return 0;
}

int
flow_first_alloc_connection(struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp;
    conn_sub_t *csp1, *csp2;
    struct rte_ipv4_hdr *iph;
    uint32_t iphdrlen, ports;
    uint32_t *iptr;

    fcp = lifo_dequeue(&this_flowConnHead, offsetof(flow_connection_t, next));
    if (fcp) {
        this_flow_curr_conn++;
        this_flow_free_conn--;
        flow_debug_trace(FLOW_DEBUG_BASIC, "alloc flow connection from pool\n");
    } else {
        this_flow_no_conn++;
        flow_debug_trace(FLOW_DEBUG_BASIC, "failed to alloc flow connection\n");
        return -1;
    }

    csp1 = &fcp->conn_sub0; 
    csp2 = &fcp->conn_sub1;
    csp1->cspflag = CSP_INITIATE_SIDE;

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

    csp1->src_ip = csp2->dst_ip = iph->src_addr;
    csp1->dst_ip = csp2->src_ip = iph->dst_addr;
    csp1->src_port = csp2->dst_port = ip_src_port(*iptr);
    csp1->dst_port = csp2->src_port = ip_dst_port(*iptr);
    csp1->proto = csp2->proto = iph->next_proto_id;
    csp1->padding = csp2->padding = 0;
    csp1->csp_token = csp2->csp_token = 1; /* should be set to vrf */
    fcp->start_time = rte_get_tsc_cycles();
    SET_CSP_TO_MBUF(mbuf, (uint64_t)csp1);
    return 0;
}

int 
flow_first_hole_search(struct rte_mbuf *mbuf)
{
    return 0;
}

int
pak_to_my_addrs(struct rte_mbuf *mbuf)
{
    return 0;
}

static int g_is_ping_enable = 1;
static int
is_ping_on_()
{
    return g_is_ping_enable;
}

static int is_for_icmp (if_rec_t *ifp, ip_hdr_t *iphdr, uint lports, void *tunl)
{
    struct rte_ipv4_hdr *iph;
    uint32_t iphdrlen, ports;
    uint32_t *iptr;

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

	if (iph->next_proto_id == IPPROTO_ICMP) {
		/* regular ping */
		if (is_ping_on_(ifp)) {
			return 1;
		} 
	}
    return 0;
}

int
pak_for_self(struct rte_mbuf *mbuf)
{
    /* currently only support ping
     * need to add more and make it dynamic register */
    return 0;
}

int
flow_first_for_self(struct rte_mbuf *mbuf)
{
    conn_sub_t *host_csp = NULL;
    int my_pak = 0;

    my_pak = pak_to_my_addrs(mbuf);
    if (my_pak) {
        flow_debug_trace(FLOW_DEBUG_BASIC, " the packet is destined to us\n");
        my_pak=pak_for_self(pak_ptr->in_ifp, pak_ptr, &host_nsp)
        if (my_pak) {
            return FLOW_RET_BREAK;
        }
    }
    return FLOW_RET_OK;
}

int
flow_first_fw_entry(struct rte_mbuf *mbuf)
{
    return 0;
}

static int is_flow_conn_init_log  = 1;
static int is_flow_conn_close_log = 1;
int
need_log_for_connection(flow_connection_t *fcp)
{
    return 0;
}

int
gen_conn_log(flow_connection_t *fcp, int init)
{
    return 0;
}

void
add_to_conn_hash(conn_sub_t *csp)
{
	int hash_value;
    uint32_t cnt;
	nat_sub_t **nat_hash_base;
	flow_connection_t *fcp = csp2base(csp);

	hash_value = conn_hash(csp->src_ip, csp->dst_ip, *(uint32_t *)&csp->src_port);

    hlist_add_head(&csp->node, this_flow_conn_hash_base+hash_value);
    cnt = *(this_flow_conn_hash_cnt_base+hash_value);
    *(this_flow_conn_hash_cnt_base+hash_value) = cnt+1;
    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
        char saddr[16], daddr[16];
        inet_ntop(AF_INET, &csp->src_ip, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &csp->dst_ip, daddr, sizeof(daddr));
        flow_debug_trace_no_flag("++ csp add (0x%llx): %s/%d->%s/%d,%d, %d, 0x%x\n",
                                 csp, 
                                 saddr, ntohs(csp->src_port),
                                 daddr, ntohs(csp->dst_port),
                                 csp->proto, fcp->time, csp->cspflag);
    }
}

/* install a flow connection
 * this vector never fail
 */
void
flow_install_conn(flow_connection_t *fcp)
{
    conn_sub_t *csp1, *csp2;
    add_to_conn_hash(&fcp->conn_sub0);
    add_to_conn_hash(&fcp->conn_sub1);

    /* Set the reason in the new connection to creation: this is used for traffic logging */	
    fcp->reason = FC_CREATION;

    /*
     * Generate flow connection init log
     */
    if (is_flow_conn_init_log) {
        if (need_log_for_connection(fcp)) {
            gen_conn_log(fcp, 1/* init log */);
        }
    }
}

int
flow_first_install_connection(struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp = GET_FC_FROM_MBUF(mbuf);
    if (fcp & FC_INSTALLED) {
        /* fw may help us to install the connection */
        return 0;
    }

    flow_install_conn(fcp);
    fcp->fcflag &= ~FC_TIME_NO_REFRESH;
    return 0;
}

int
flow_filter_vector(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph;
    uint32_t iphdrlen;
    uint32_t *iptr;

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

    flow_mark_pak(iph, iptr);
    flow_print("%s mark this packet %d/%d->%d/%d, %d\n",
                __FUNCTION__,
                iph->src_addr, ip_src_port(*iptr),
                iph->dst_addr, ip_dst_port(*iptr),
                iph->next_proto_id);
    return FLOW_RET_OK;
}

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
 * in this vector we will handle tunnel decrypt & session lookup
 */
int
flow_decap_vector(struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp;
    conn_sub_t *csp;

    flow_print("%s entry\n", __FUNCTION__);
    fcp = GET_FC_FROM_MBUF(mbuf);
    if (!fcp) {
        if (flow_find_connection(mbuf)) {
            return -1;
        }
    } else {
        flow_print("  flow packet already have connection.\n");
    }
    fcp = GET_FC_FROM_MBUF(mbuf);
    flow_print("  flow connection id %u\n", fcp2id(fcp));

    if (!is_tunnel_session(fcp)) {
        return flow_next_pak_vector(pak_ptr);
    }

    return flow_tunnel_handling(fcp);
}

int
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

/*
 * main flow functions.
 */
static int 
flow_main_body_vector (struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp;
    conn_sub_t *csp;

    csp = GET_CSP_FROM_MBUF(mbuf);
    fcp = csp2base(mbuf);
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
        return -1;
    }

    csp->pkt_cnt ++;
    csp->byte_cnt += rte_pktmbuf_pkt_len(mbuf);
}

static void
flow_proc_one_pak(struct rte_mbuf *mbuf)
{
    flow_vector_t *vector;
    int rc = FLOW_RET_OK;

    this_flow_vector_list = flow_ipv4_vector_list;
    while (*this_flow_vector_list) {
        if ((rc = (*this_flow_vector_list)(mbuf))) {
            flow_drop_packet(mbuf);
            break;
        }
    }
    if (rc == FLOW_RET_OK) {
        flow_free_packet(mbuf);
    }
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
    /* add some performance counter */
    /* add some cpu constraint */
    /* add some queue handling */
    flow_proc_one_pak(mbuf);

    flow_handle_other_queue();
}
