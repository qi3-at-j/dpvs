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
#include <pthread.h>

#include <rte_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "global_data.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"
#include "flow_cli.h"
#include "flow_msg.h"

static inline uint32_t
flow_get_total_connection(void)
{
    return rte_atomic32_read(&this_flow_curr_conn);
}

/*
 * show one flow connection in brief format, which also indicates
 * connection location
 */
static int
show_one_flow_connection (flow_connection_t *fcp, void *args)
{
    cmd_blk_t *cbt = (cmd_blk_t *)args;
	conn_sub_t *csp;
    int family;
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
	
	tyflow_cmdline_printf(cbt->cl, "   id %d,flag 0x%x,time %d/%lu, reason %d\n",
			              (fcp2id(fcp)),
                          fcp->fcflag,
                          flow_get_fcp_time(fcp),
                          fcp->start_time,
                          fcp->reason);
	
	csp = &fcp->conn_sub0;
    family = (csp->cspflag & CSP_FLAG_IPV6)?AF_INET6:AF_INET;
    inet_ntop(family, &csp->csp_src_ip, src_addr, INET6_ADDRSTRLEN);
    inet_ntop(family, &csp->csp_dst_ip, dst_addr, INET6_ADDRSTRLEN);
    tyflow_cmdline_printf(cbt->cl, "      if %s(cspflag 0x%x): %s/%d->%s/%d, %d, vrf %d, route 0x%lx, packets/bytes %lu/%lu",
                          (csp->ifp)?csp->ifp->name:"uncertain", csp->cspflag,
                          src_addr, ntohs(csp->csp_src_port),
                          dst_addr, ntohs(csp->csp_dst_port),
                          csp->csp_proto, csp->csp_token,
                          (uint64_t)csp->route,
                          csp->pkt_cnt, csp->byte_cnt);
	if(csp->csp_proto == IPPROTO_TCP){
		tyflow_cmdline_printf(cbt->cl, ",wsf %d",csp->wsf);/*wsf sync*/
	} else if (csp->csp_proto == IPPROTO_ICMP) {
        tyflow_cmdline_printf(cbt->cl, ",type/code %d/%d", csp->csp_type, csp->csp_code);
    }
    tyflow_cmdline_printf(cbt->cl, "\n");

	csp = &fcp->conn_sub1;
    family = (csp->cspflag & CSP_FLAG_IPV6)?AF_INET6:AF_INET;
    inet_ntop(family, &csp->csp_src_ip, src_addr, INET6_ADDRSTRLEN);
    inet_ntop(family, &csp->csp_dst_ip, dst_addr, INET6_ADDRSTRLEN);
    tyflow_cmdline_printf(cbt->cl, "      if %s(cspflag 0x%x): %s/%d->%s/%d, %d, vrf %d, route 0x%lx, packets/bytes %lu/%lu",
                          (csp->ifp)?csp->ifp->name:"uncertain", csp->cspflag,
                          src_addr, ntohs(csp->csp_src_port),
                          dst_addr, ntohs(csp->csp_dst_port),
                          csp->csp_proto, csp->csp_token,
                          (uint64_t)csp->route,
                          csp->pkt_cnt, csp->byte_cnt);
	if(csp->csp_proto == IPPROTO_TCP){
		tyflow_cmdline_printf(cbt->cl, ",wsf %d",csp->wsf);/*wsf sync*/
	}
    tyflow_cmdline_printf(cbt->cl, "\n");

    return 0;
}

/* no parameters provided means ok, select it */
int 
select_this_connection(flow_connection_t *fcp, 
			           connection_op_para_t *paras)
{
	uint32_t mask;
	conn_sub_t *csp, *peer;

	if (fcp == NULL)
		return 0;
	if (paras == NULL || paras->mask == 0)
		return 1;

 	mask = paras->mask;

	if (mask & CLR_GET_CONN_FCFLAG) {
		if ((paras->fcflag & fcp->fcflag) != paras->fcflag) 
            return 0;
	}

	csp = &(fcp->conn_sub0);
	if ((csp->cspflag & CSP_ECHO_SIDE) == 1)
		csp = csp2peer(csp);
	peer = csp2peer(csp);

	/*
     * we may support showing connection by vrf, check the token here
	 */
	if (mask & CLR_GET_CONN_VRF_ID) {
		if (paras->vrf_id != csp->csp_token && 
			paras->vrf_id != peer->csp_token) 
            return 0;
    }

	if (mask & CLR_GET_CONN_SRCIP_MASK) {
        if (paras->src_ip != (ntohl(csp->csp_src_ip) & paras->src_mask))
            return 0;
	}
	else if (mask & CLR_GET_CONN_SRCIP) {
        if (paras->src_ip != ntohl(csp->csp_src_ip))
            return 0;
    }

	if (mask & CLR_GET_CONN_DESIP_MASK) {
        if (paras->dst_ip != (ntohl(csp->csp_dst_ip) & paras->dst_mask))
            return 0;
	}
	else if (mask & CLR_GET_CONN_DESIP) {
        if (paras->dst_ip != ntohl(csp->csp_dst_ip))
            return 0;
    }

	if (mask & CLR_GET_CONN_PROTOCOL_HIGH) {
		if (paras->protocol_low > csp->csp_proto ||
            paras->protocol_high < csp->csp_proto)
            return 0;
    }
	else if (mask & CLR_GET_CONN_PROTOCOL_LOW) {
        if (paras->protocol_low != csp->csp_proto)
            return 0;
    }

	if (mask & CLR_GET_CONN_SRCPORT_HIGH) {
		if (paras->srcport_low > ntohs(csp->csp_src_port) ||
			paras->srcport_high < ntohs(csp->csp_src_port))
			return 0;
	}
	else if (mask & CLR_GET_CONN_SRCPORT_LOW) {
		if (paras->srcport_low != ntohs(csp->csp_src_port))
			return 0;
	}

	if (mask & CLR_GET_CONN_DESPORT_HIGH) {
		if (paras->dstport_low > ntohs(csp->csp_dst_port) ||
			paras->dstport_high < ntohs(csp->csp_dst_port))
            return 0;
	}
	else if (mask & CLR_GET_CONN_DESPORT_LOW){
		if (paras->dstport_low != ntohs(csp->csp_dst_port))
            return 0;
    }

	if (mask & CLR_GET_CONN_FW_POLICY) { 
        /* 
         * todo
         * we may support it later, policy is so important to firewall 
         */
	}

	return 1; /* select this connection */
}

static int
_try_reschedule(void)
{
    return 0;
}

static int
page_stop(void)
{
    return 0;
}

/*
 * walk through all connections with given select condition,
 * call passed vector for each connection that matches the conditions.
 * return the number of matched connnections.
 */
static int 
traverse_all_flow_connection(connection_op_para_t *paras, void *args,
	                         selected_connection_vector_t vector)
{
	int total;
	int i, cnt, rc;
	flow_connection_t *fcp;

	total = flow_get_total_connection();
    cnt = 0;
	for (i = 1; (i < FLOW_CONN_MAX_NUMBER) && (cnt < total); i++) {
        fcp = this_flowConnTable + i;
        fcp_rwl_read_lock(fcp);
		if (is_fcp_valid(fcp)) {
            fcp_rwl_read_unlock(fcp);
			if (select_this_connection(fcp, paras)) {
				if (vector) {
					rc = (*vector)(fcp, args);
                    if (rc == 0) {
                        cnt++;
                    }
				}
				
				/*	to prevent hold cpu too long */
				if ((cnt & 0x3f) ==0)
					_try_reschedule();
				
                /* we may need to page the output */
				if (page_stop())
					goto done;
			}
		} else {
            fcp_rwl_read_unlock(fcp);
        }
        /*	to prevent hold cpu too long */
		if ((i & 0xffff) == 0)
			_try_reschedule();
	}
done:
	return cnt;
}

#define TOP_SIZE 10

static inline void
swap_value_uint(uint32_t *a, uint32_t *b)
{
    uint32_t c;
    c = *a;
    *a = *b;
    *b = c;
}

static int
show_flow_hash_top(cmd_msg_hdr_t *msg_hdr)
{
	int i, j;
    uint32_t cnt_top_id[TOP_SIZE] = {0};
    uint32_t cnt_top_val[TOP_SIZE] = {0};
    uint32_t temp;

    for (i = 0; i < FLOW_CONN_HASH_TAB_SIZE; i++) {
        temp = rte_atomic32_read(&((this_flow_conn_hash_base+i)->conn_cnt));
        j = TOP_SIZE-1;
        if (temp && temp >= cnt_top_val[j]) {
            cnt_top_val[j] = temp;
            cnt_top_id[j] = i;
        }
        j = j-1;
        while(j >= 0 && cnt_top_val[j] < temp) {
            swap_value_uint(&cnt_top_val[j], &cnt_top_val[j+1]);
            swap_value_uint(&cnt_top_id[j], &cnt_top_id[j+1]);
            j--;
        }
    }

    tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                          "  hash-value top %d\n", 
                          TOP_SIZE);
    for (j = 0; j < (TOP_SIZE>>2); j++) {
        tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl,
                              "    %d-%d, %d-%d, %d-%d, %d-%d\n",
                              cnt_top_id[(j<<2)], cnt_top_val[(j<<2)],
                              cnt_top_id[(j<<2)+1], cnt_top_val[(j<<2)+1],
                              cnt_top_id[(j<<2)+2], cnt_top_val[(j<<2)+2],
                              cnt_top_id[(j<<2)+3], cnt_top_val[(j<<2)+3]);
    }
    j = j<<2;
    switch (TOP_SIZE-j) {
        case 1:
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl,
                                  "    %d-%d\n",
                                  cnt_top_id[j], cnt_top_val[j]);
            break;
        case 2:
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl,
                                  "    %d-%d, %d-%d\n",
                                  cnt_top_id[j], cnt_top_val[j],
                                  cnt_top_id[j+1], cnt_top_val[j+1]);
            break;
        case 3:
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl,
                                  "    %d-%d, %d-%d, %d-%d\n",
                                  cnt_top_id[j], cnt_top_val[j],
                                  cnt_top_id[j+1], cnt_top_val[j+1],
                                  cnt_top_id[j+2], cnt_top_val[j+2]);
            break;
        default:
            break;
    }
    msg_hdr->rc = TOP_SIZE;
    return msg_hdr->rc;
}

/*
 * walk through all connections with given hash value
 */
static int
traverse_hash_flow_connection(cmd_msg_hdr_t *msg_hdr)
{
    show_flow_ctx_t *ctx = (show_flow_ctx_t *)msg_hdr;
    uint32_t hash = ctx->paras.hash;
    struct hlist_head *hash_flow;
    conn_sub_t *csp;
    flow_connection_t *fcp;

    fcc_rwl_read_lock(hash);
    hash_flow = &((this_flow_conn_hash_base + hash)->hash_base);

    hlist_for_each_entry(csp, hash_flow, hnode) {
        fcp = csp2base(csp);
        show_one_flow_connection(fcp, msg_hdr->cbt);
        msg_hdr->rc++;
    }
    fcc_rwl_read_unlock(hash);
    return hash;
}

/*
 * show all local flow connections, return count.
 * we need to filter them if required.
 */
static int
show_flow_connection(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
    show_flow_ctx_t *ctx = (show_flow_ctx_t *)msg_hdr;
    flow_connection_t *fcp;
    int i;

    assert(msg_hdr->length == sizeof(show_flow_ctx_t));

    tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, "\nlcore%d:\n", rte_lcore_id());
    if (!rte_atomic32_read(&this_flow_status)) {
        tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl,
                              "    flow is not ready yet\n");
        goto out;
    }

    switch(msg_hdr->subtype) {
        case FLOW_CMD_MSG_SUBTYPE_SUMMARY:
            msg_hdr->rc = flow_get_total_connection();
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                  "  total number on lcore%d: %d/%d/%d\n", 
                                  rte_lcore_id(), 
                                  msg_hdr->rc,
                                  rte_atomic32_read(&this_flow_free_conn),
                                  rte_atomic32_read(&this_flow_no_conn));
            break;
        case FLOW_CMD_MSG_SUBTYPE_ALL:
            /* traverse all connections. */
            msg_hdr->rc = traverse_all_flow_connection(&ctx->paras, 
                                                       msg_hdr->cbt, 
                                                       show_one_flow_connection);
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                  "  connections on lcore%d: %d\n", 
                                  rte_lcore_id(), msg_hdr->rc);
            pthread_mutex_lock(flow_cmd_mutex);
            msg_hdr->done = CMD_MSG_STATE_FIN;
            pthread_cond_signal(flow_cmd_cond);
            pthread_mutex_unlock(flow_cmd_mutex);
            break;
        case FLOW_CMD_MSG_SUBTYPE_DETAIL:
            fcp = this_flowConnTable + ctx->paras.fcid;
            fcp_rwl_read_lock(fcp);
            if (is_fcp_valid(fcp)) {
                fcp_rwl_read_unlock(fcp);
                show_one_flow_connection(fcp, msg_hdr->cbt);
            } else {
                fcp_rwl_read_unlock(fcp);
                tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                      "  no flow connection id %d\n", 
                                      ctx->paras.fcid); 
            }
            break;
        case FLOW_CMD_MSG_SUBTYPE_COUNTER:
            for (i = 0; i < FLOW_COUNTER_G_MAX; i++) {
                tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                      "  %s %d\n", 
                                      this_flow_counter_g[i].name, 
                                      rte_atomic32_read(&this_flow_counter_g[i].counter));
            }

            for (i = 0; i < FLOW_COUNTER_MAX; i++) {
                tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                      "  %s %d\n", 
                                      this_flow_counter[i].name, 
                                      this_flow_counter[i].counter);
            }
            break;
        case FLOW_CMD_MSG_SUBTYPE_HASH:
            /* traverse specific hash connections. */
            i = traverse_hash_flow_connection(msg_hdr);
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                  "  connections on hash %d: %d\n", 
                                  i, msg_hdr->rc);
            break;
        case FLOW_CMD_MSG_SUBTYPE_HASHTOP:
            show_flow_hash_top(msg_hdr);
            break;
        case FLOW_CMD_MSG_SUBTYPE_DENY:
            /* traverse all connections. */
            msg_hdr->rc = traverse_all_flow_connection(&ctx->paras, 
                                                       msg_hdr->cbt, 
                                                       show_one_flow_connection);
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                  "  deny connections on lcore%d: %d\n", 
                                  rte_lcore_id(), msg_hdr->rc);
            pthread_mutex_lock(flow_cmd_mutex);
            msg_hdr->done = CMD_MSG_STATE_FIN;
            pthread_cond_signal(flow_cmd_cond);
            pthread_mutex_unlock(flow_cmd_mutex);
            break;
        default:
            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                                  "  unsupport operation\n");
            break;
    }
out:
    return msg_hdr->rc;
}

static void
flow_parse_para(cmd_blk_t *cbt, connection_op_para_t *paras)
{
    /* deny */
    if (cbt->which[0] == 6) {
        paras->fcflag |= FC_DENY;
        paras->mask |= CLR_GET_CONN_FCFLAG;
    }

    /* src ip */
    if (cbt->which[1] == 1) {
        paras->src_ip = cbt->ipv4[0];
        paras->mask |= CLR_GET_CONN_SRCIP;
        if (cbt->number[1]) {
            paras->src_mask = number_2_mask(cbt->number[1]);
            paras->mask |= CLR_GET_CONN_SRCIP_MASK;
        }
    }

    /* dst ip */
    if (cbt->which[2] == 1) {
        paras->dst_ip = cbt->ipv4[1];
        paras->mask |= CLR_GET_CONN_DESIP;
        if (cbt->number[2]) {
            paras->dst_mask = number_2_mask(cbt->number[2]);
            paras->mask |= CLR_GET_CONN_DESIP_MASK;
        }
    }

    /* protocol */
    if (cbt->which[3] == 1) {
        paras->protocol_low = cbt->number[3];
        paras->mask |= CLR_GET_CONN_PROTOCOL_LOW;
        if (cbt->number[4]) {
            paras->protocol_high = cbt->number[4];
            paras->mask |= CLR_GET_CONN_PROTOCOL_HIGH;
        }
    }

    /* src port */
    if (cbt->which[4] == 1) {
        paras->srcport_low = cbt->number[5];
        paras->mask |= CLR_GET_CONN_SRCPORT_LOW;
        if (cbt->number[6]) {
            paras->srcport_high = cbt->number[6];
            paras->mask |= CLR_GET_CONN_SRCPORT_HIGH;
        }
    }

    /* dst port */
    if (cbt->which[5] == 1) {
        paras->dstport_low = cbt->number[7];
        paras->mask |= CLR_GET_CONN_DESPORT_LOW;
        if (cbt->number[8]) {
            paras->dstport_high = cbt->number[8];
            paras->mask |= CLR_GET_CONN_DESPORT_HIGH;
        }
    }

    /* vrf */
    if (cbt->which[6] == 1) {
        paras->vrf_id = cbt->number[9];
        paras->mask |= CLR_GET_CONN_VRF_ID;
    }

    /* policy */
    if (cbt->which[7] == 1) {
        paras->policy_id = cbt->number[10];
        paras->mask |= CLR_GET_CONN_FW_POLICY;
    }
}

static int
show_flow_connection_echo(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
    uint32_t *fc_cnt = (uint32_t *)cookie;
    assert(msg_hdr->type == CMD_MSG_FLOW_SHOW);

    switch(msg_hdr->subtype) {
        case FLOW_CMD_MSG_SUBTYPE_SUMMARY:
            *fc_cnt += msg_hdr->rc;
            break;
        case FLOW_CMD_MSG_SUBTYPE_ALL:
        case FLOW_CMD_MSG_SUBTYPE_DENY:
            *fc_cnt += msg_hdr->rc;
            break;
        case FLOW_CMD_MSG_SUBTYPE_DETAIL:
        case FLOW_CMD_MSG_SUBTYPE_COUNTER:
        case FLOW_CMD_MSG_SUBTYPE_HASH:
        case FLOW_CMD_MSG_SUBTYPE_HASHTOP:
            break;
        default:
            assert(0);
    }

    return 0;
}

static uint32_t fc_cnt;
static int
show_flow_connection_cli(cmd_blk_t *cbt)
{
    show_flow_ctx_t flow_ctx;
    connection_op_para_t *paras;

    flow_ctx.msg_hdr.type = CMD_MSG_FLOW_SHOW;
    flow_ctx.msg_hdr.length = sizeof(show_flow_ctx_t);
    flow_ctx.msg_hdr.rc = 0;
    flow_ctx.msg_hdr.done = 0;
    flow_ctx.msg_hdr.cbt = cbt;
    paras = &flow_ctx.paras;
    memset(paras, 0, sizeof(connection_op_para_t));
    flow_parse_para(cbt, paras);
    fc_cnt = 0;
    tyflow_cmdline_printf(cbt->cl, "flow connections:\n");
    switch(cbt->which[0]) {
        case 1:
            flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_SUBTYPE_SUMMARY;
#ifdef TYFLOW_PER_THREAD
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
#else
            send_cmd_msg_to_fwd_lcore_id(&flow_ctx.msg_hdr, rte_atomic32_read(&this_flow_conn_ager_ctx.cid));
#endif
            tyflow_cmdline_printf(cbt->cl, "total connection: %d\n", fc_cnt);
            break;
        case 0:
        case 2:
            flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_SUBTYPE_ALL;
#ifdef TYFLOW_PER_THREAD
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
#else
            /* print too many fcp will make the worker thread too busy to handle packet,
             * use the main thread to do it
             */
            send_cmd_msg_to_master(&flow_ctx.msg_hdr, rte_get_master_lcore());
#endif
            tyflow_cmdline_printf(cbt->cl, "total number %d\n", fc_cnt);
            break;
        case 3:
            flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_SUBTYPE_DETAIL;
            paras->fcid = cbt->number[0];
            tyflow_cmdline_printf(cbt->cl, "showing the connection %d:\n", paras->fcid);
#ifdef TYFLOW_PER_THREAD
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
#else
            send_cmd_msg_to_fwd_lcore_id(&flow_ctx.msg_hdr, rte_atomic32_read(&this_flow_conn_ager_ctx.cid));
#endif
            break;
        case 4:
            flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_SUBTYPE_COUNTER;
            tyflow_cmdline_printf(cbt->cl, " flow counters");
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
            break;
        case 5:
            if (cbt->which[1] == 2) {
                flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_SUBTYPE_HASHTOP;
                tyflow_cmdline_printf(cbt->cl, " flow hash top\n");
            } else {
                flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_SUBTYPE_HASH;
                paras->hash = cbt->number[0];
                tyflow_cmdline_printf(cbt->cl, " flow hash %d\n", paras->hash);
            }
#ifdef TYFLOW_PER_THREAD
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
#else
            send_cmd_msg_to_fwd_lcore_id(&flow_ctx.msg_hdr, rte_atomic32_read(&this_flow_conn_ager_ctx.cid));
#endif
            break;
        case 6:
            flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_SUBTYPE_DENY;
#ifdef TYFLOW_PER_THREAD
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
#else
            /* print too many fcp will make the worker thread too busy to handle packet,
             * use the main thread to do it
             */
            send_cmd_msg_to_master(&flow_ctx.msg_hdr, rte_get_master_lcore());
#endif
            tyflow_cmdline_printf(cbt->cl, "deny number %d\n", fc_cnt);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            break;
    }
    return 0;
}

EOL_NODE(flow_conn_eol, show_flow_connection_cli);
/* deny */
KW_NODE_WHICH(flow_conn_deny, flow_conn_eol, flow_conn_eol, "deny", "show deny flow connection", 1, 6);
/* policy */
VALUE_NODE(flow_conn_policyid, flow_conn_eol, none, "policy id", 11, NUM);
KW_NODE_WHICH(flow_conn_policy, flow_conn_policyid, flow_conn_deny, "policy", "specific a policy", 8, 1);
/* vrf id */
VALUE_NODE(flow_conn_vrfid, flow_conn_policy, none, "vrf id", 10, NUM);
KW_NODE_WHICH(flow_conn_vrf, flow_conn_vrfid, flow_conn_policy, "vrf", "specific a vrf", 7, 1);
/* destination port number low and high */
VALUE_NODE(flow_conn_dstport_high, flow_conn_vrf, flow_conn_vrf, "destination port upper boundary", 9, NUM);
VALUE_NODE(flow_conn_dstport_low, flow_conn_dstport_high, none, "destination port value or lower boundary", 8, NUM);
KW_NODE_WHICH(flow_conn_dstport, flow_conn_dstport_low, flow_conn_vrf, "dst-port", "destination port number or range", 6, 1);
/* source port number low and high */
VALUE_NODE(flow_conn_srcport_high, flow_conn_dstport, flow_conn_dstport, "source port upper boundary", 7, NUM);
VALUE_NODE(flow_conn_srcport_low, flow_conn_srcport_high, none, "source port value or lower boundary", 6, NUM);
KW_NODE_WHICH(flow_conn_srcport, flow_conn_srcport_low, flow_conn_dstport, "src-port", "source port number or range", 5, 1);
/* protocol number low and high */
VALUE_NODE(flow_conn_proto_high, flow_conn_srcport, flow_conn_srcport, "protocol upper boundary", 5, NUM);
VALUE_NODE(flow_conn_proto_low, flow_conn_proto_high, none, "protocol value or lower boundary", 4, NUM);
KW_NODE_WHICH(flow_conn_proto, flow_conn_proto_low, flow_conn_srcport, "protocol", "protocol number or range", 4, 1);
/* dst ip address and netmask */
/* we make srcip_mask as KW_NODE but not KW_NODE_WHICH, and we can use a different NUM index to differ to flow_conn_id_val */
/* flow_conn_dstip have to use a different index since it can co-exist with flow_conn_srcip */
VALUE_NODE(dstip_mask_val, flow_conn_proto, none, "provide netmask for destination ip", 3, NUM);
KW_NODE(dstip_mask, dstip_mask_val, flow_conn_proto, "netmask", "destination ip address netmask");
VALUE_NODE(flow_conn_dstip_val, dstip_mask, none, "provide an ip address", 2, IPV4);
KW_NODE_WHICH(flow_conn_dstip, flow_conn_dstip_val, flow_conn_proto, "dst-ip", "destination ip address", 3, 1);
/* src ip address and netmask */
/* we make srcip_mask as KW_NODE but not KW_NODE_WHICH, and we can use a different NUM index to differ to flow_conn_id_val */
/* flow_conn_srcip can use the same index to flow_conn_id/flow_conn_all/flow_conn_summary since they are mutual exclusive */
VALUE_NODE(srcip_mask_val, flow_conn_dstip, none, "provide netmask for source ip", 2, NUM);
KW_NODE(srcip_mask, srcip_mask_val, flow_conn_dstip, "netmask", "source ip address netmask");
VALUE_NODE(flow_conn_srcip_val, srcip_mask, none, "provide an ip address", 1, IPV4);
KW_NODE_WHICH(flow_conn_srcip, flow_conn_srcip_val, flow_conn_dstip, "src-ip", "source ip address", 2, 1);
/* show flow connection hash top/value */
VALUE_NODE(flow_conn_hashval, flow_conn_eol, none, "hash value", 1, NUM);
KW_NODE_WHICH(flow_conn_hashtop, flow_conn_eol, flow_conn_hashval, "top", "show top hash with maximum flow connections", 2, 2);
KW_NODE_WHICH(flow_conn_hash, flow_conn_hashtop, flow_conn_srcip, "hash", "show flow connection hash items", 1, 5);
/* show flow connection counter */
KW_NODE_WHICH(flow_conn_counter, flow_conn_eol, flow_conn_hash, "counter", "show flow connection counters", 1, 4);
/* show flow connection id */
VALUE_NODE(flow_conn_id_val, flow_conn_eol, none, "the flow connection id", 1, NUM);
KW_NODE_WHICH(flow_conn_id, flow_conn_id_val, flow_conn_counter, "id", "show one specific flow connection", 1, 3);
/* show flow connection all */
KW_NODE_WHICH(flow_conn_all, flow_conn_eol, flow_conn_id, "all", "show all flow connection", 1, 2);
/* show flow connection summary */
KW_NODE_WHICH(flow_conn_summary, flow_conn_eol, flow_conn_all, "summary", "show flow connection summary", 1, 1);


static int
show_flow_status_cli(cmd_blk_t *cbt)
{
    int i, set = 0;
    tyflow_cmdline_printf(cbt->cl, "flow skip-firewall: %s\n",
                          flow_skip_fw?"on":"off");
    tyflow_cmdline_printf(cbt->cl, "flow timeout:\n");
    for (i = 0; i < IPPROTO_MAX; i++) {
        if (flow_protocol_timeout[i]) {
            tyflow_cmdline_printf(cbt->cl, "\t%d: %d\n",
                                  i, flow_protocol_timeout[i]);
            set = 1;
        }
    }
    if (!set) {
        tyflow_cmdline_printf(cbt->cl, "\tno set\n");
    }
    return 0;
}

static int
show_flow_debug_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "flow status:\n");
    tyflow_cmdline_printf(cbt->cl, "\tdebug:\n");
    if (!flow_debug_flag) {
        tyflow_cmdline_printf(cbt->cl, "\t\tnone.\n");
    } else {
        if (flow_debug_flag & FLOW_DEBUG_BASIC)
            tyflow_cmdline_printf(cbt->cl, "\t\tbasic enabled.\n");
        if (flow_debug_flag & FLOW_DEBUG_EVENT)
            tyflow_cmdline_printf(cbt->cl, "\t\tevent enabled.\n");
        if (flow_debug_flag & FLOW_DEBUG_PACKET)
            tyflow_cmdline_printf(cbt->cl, "\t\tpacket enabled.\n");
        if (flow_debug_flag & FLOW_DEBUG_DETAIL)
            tyflow_cmdline_printf(cbt->cl, "\t\tdetail enabled.\n");
        if (flow_debug_flag & FLOW_DEBUG_CLI)
            tyflow_cmdline_printf(cbt->cl, "\t\tcli enabled.\n");
        if (flow_debug_flag & FLOW_DEBUG_AGER)
            tyflow_cmdline_printf(cbt->cl, "\t\tager enabled.\n");
    }
    return 0;
}

exnode(flow_show_prof_vector);
/* show flow profile */
KW_NODE(flow_show_profile, flow_show_prof_vector, none, "profile", "show flow profile");

EOL_NODE(flow_status_eol, show_flow_status_cli);
/* show flow status */
KW_NODE(flow_status, flow_status_eol, flow_show_profile, "status", "show flow status");

/* show flow connection */
KW_NODE(flow_connection, flow_conn_summary, flow_status, "connection", "show flow connection");

EOL_NODE(flow_debug_eol, show_flow_debug_cli);
/* show flow debug */
KW_NODE(flow_debug, flow_debug_eol, flow_connection, "debug", "show flow debug status");

/* show flow */
KW_NODE(show_flow, flow_debug, none, "flow", "show flow related items");

static int
set_flow_cli(cmd_blk_t *cbt)
{
    int timeout, protocol;
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    timeout = cbt->number[0];
    switch(cbt->which[0]) {
        case 1:
            if (cbt->mode & MODE_DO) {
                flow_skip_fw = 1;
            } else if (cbt->mode & MODE_UNDO) {
                flow_skip_fw = 0;
            }
            break;
        case 2:
            if (cbt->mode & MODE_DO) {
                flow_protocol_timeout[IPPROTO_TCP] = timeout;
            } else if (cbt->mode & MODE_UNDO) {
                flow_protocol_timeout[IPPROTO_TCP] = 0;
            }
            break;
        case 3:
            if (cbt->mode & MODE_DO) {
                flow_protocol_timeout[IPPROTO_UDP] = timeout;
            } else if (cbt->mode & MODE_UNDO) {
                flow_protocol_timeout[IPPROTO_UDP] = 0;
            }
            break;
        case 4:
            if (cbt->mode & MODE_DO) {
                flow_protocol_timeout[IPPROTO_ICMP] = timeout;
            } else if (cbt->mode & MODE_UNDO) {
                flow_protocol_timeout[IPPROTO_ICMP] = 0;
            }
            break;
        case 5:
            if (cbt->mode & MODE_DO) {
                flow_protocol_timeout[IPPROTO_ICMPV6] = timeout;
            } else if (cbt->mode & MODE_UNDO) {
                flow_protocol_timeout[IPPROTO_ICMPV6] = 0;
            }
            break;
        case 6:
            protocol = cbt->number[1];
            if (cbt->mode & MODE_DO) {
                flow_protocol_timeout[protocol] = timeout;
            } else if (cbt->mode & MODE_UNDO) {
                flow_protocol_timeout[protocol] = 0;
            }
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            break;
    }

    return 0;
}

EOL_NODE(flow_eol, set_flow_cli);
/* set flow timeout other <protocol> xx */
VALUE_NODE(flow_tm_spec_val, flow_eol, none, "timeout value", 1, NUM);
/* set flow timeout other <protocol> */
VALUE_NODE(flow_tm_spec, flow_tm_spec_val, none, "specify a protocol number", 2, NUM);
/* set flow timeout other */
KW_NODE_WHICH(flow_tm_other, flow_tm_spec, none, 
              "other", "set other protocol timeout", 1, 6);
/* set flow timeout icmp6 xx */
VALUE_NODE(flow_tm_icmp6_val, flow_eol, none, "timeout value", 1, NUM);
/* set flow timeout icmp6 */
KW_NODE_WHICH(flow_tm_icmp6, flow_tm_icmp6_val, flow_tm_other, 
              "icmp6", "set icmp6 timeout", 1, 5);
/* set flow timeout icmp xx */
VALUE_NODE(flow_tm_icmp_val, flow_eol, none, "timeout value", 1, NUM);
/* set flow timeout icmp */
KW_NODE_WHICH(flow_tm_icmp, flow_tm_icmp_val, flow_tm_icmp6, 
              "icmp", "set icmp timeout", 1, 4);
/* set flow timeout udp xx */
VALUE_NODE(flow_tm_udp_val, flow_eol, none, "timeout value", 1, NUM);
/* set flow timeout udp */
KW_NODE_WHICH(flow_tm_udp, flow_tm_udp_val, flow_tm_icmp, 
              "udp", "set udp timeout", 1, 3);
/* set flow timeout tcp xx */
VALUE_NODE(flow_tm_tcp_val, flow_eol, none, "timeout value", 1, NUM);
/* set flow timeout tcp */
KW_NODE_WHICH(flow_tm_tcp, flow_tm_tcp_val, flow_tm_udp, 
              "tcp", "set tcp timeout", 1, 2);

exnode(flow_prof_vector);
/* set flow profile */
KW_NODE(flow_prof, flow_prof_vector, none, "profile", "flow profile operation");

/* set flow timeout */
KW_NODE(flow_timeout, flow_tm_tcp, flow_prof, 
              "timeout", "set timeout in 2 seconds granularity");
/* set flow skip-firewall */
KW_NODE_WHICH(flow_skip_fw, flow_eol, flow_timeout, 
              "skip-firewall", "skip all firewall handling", 1, 1);
/* set flow */
KW_NODE(flow, flow_skip_fw, none, "flow", "flow related configuration");

static int
clear_flow_cli(cmd_blk_t *cbt)
{
    clear_flow_ctx_t flow_ctx;

    flow_ctx.msg_hdr.type = CMD_MSG_FLOW_CLEAR;
    flow_ctx.msg_hdr.length = sizeof(clear_flow_ctx_t);
    flow_ctx.msg_hdr.rc = 0;
    flow_ctx.msg_hdr.cbt = cbt;

    switch(cbt->which[0]) {
        case 1:
            flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_CLEAR_COUNTER;
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
            tyflow_cmdline_printf(cbt->cl, "all flow connection counter are cleared\n");
            break;
        case 2:
            flow_ctx.msg_hdr.subtype = FLOW_CMD_MSG_CLEAR_FCP;
#ifdef TYFLOW_PER_THREAD
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
#else
            send_cmd_msg_to_fwd_lcore_id(&flow_ctx.msg_hdr, rte_atomic32_read(&this_flow_conn_ager_ctx.cid));
#endif
            tyflow_cmdline_printf(cbt->cl, "clear %d flow connections\n", flow_ctx.msg_hdr.rc);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            return -1;
    }

    return 0;
}

/*
 * show one flow connection in brief format, which also indicates
 * connection location
 */
static int
clear_one_flow_connection (flow_connection_t *fcp, __rte_unused void *args)
{
    if (fcp->fcflag & FC_TIME_NO_REFRESH) {
        return -1;
    }
    set_fcp_invalid(fcp, FC_CLOSE_CLI);
    return 0;
}

static int
clear_flow_connection(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
    int i;
    assert(msg_hdr->type == CMD_MSG_FLOW_CLEAR);

    switch(msg_hdr->subtype) {
        case FLOW_CMD_MSG_CLEAR_COUNTER:
            for (i = FLOW_COUNTER_MUTAB_START; i < FLOW_COUNTER_MUTAB_END; i++) {
                this_flow_counter[i].counter = 0;
            }

            tyflow_cmdline_printf(((cmd_blk_t *)msg_hdr->cbt)->cl, 
                    "  lcore%d cleared the flow connection counter\n", 
                    rte_lcore_id());
            return 0;
        case FLOW_CMD_MSG_CLEAR_FCP:
            /* traverse all connections. performance may be an issue in heavy load */
            msg_hdr->rc = traverse_all_flow_connection(NULL, NULL, clear_one_flow_connection);
            break;
        default:
            break;
    }

    return 0;
}

EOL_NODE(flow_clear_eol, clear_flow_cli);
/* clear flow connection all */
KW_NODE_WHICH(flow_clear_conn_all, flow_clear_eol, none, "all", "clear all flow connections", 1, 2);
/* clear flow connection counter */
KW_NODE_WHICH(flow_clear_conn_counter, flow_clear_eol, flow_clear_conn_all, "counter", "clear flow connection counter", 1, 1);
/* clear flow connection */
KW_NODE(flow_clear_conn, flow_clear_conn_counter, none, "connection", "clear flow connection related items");
/* clear flow */
KW_NODE(flow_clear, flow_clear_conn, none, "flow", "clear flow related items");

exnode(show_l3);
extern int
show_flow_profile(cmd_msg_hdr_t *msg_hdr, void *cookie);
int
flow_cli_init(void)
{
    int rc;
    add_set_cmd(&cnode(flow));
    add_get_cmd(&cnode(show_flow));
    add_get_cmd(&cnode(show_l3));
    add_clear_cmd(&cnode(flow_clear));

    rc = cmd_msg_handler_register(CMD_MSG_FLOW_CLEAR,
                                  clear_flow_connection,
                                  NULL, NULL);
    if (rc) {
        return -1;
    }

    rc = cmd_msg_handler_register(CMD_MSG_FLOW_SHOW,
                                  show_flow_connection,
                                  show_flow_connection_echo,
                                  &fc_cnt);
    if (rc) {
        return -1;
    }

    rc = cmd_msg_handler_register(CMD_MSG_FLOW_PROF,
                                  show_flow_profile,
                                  NULL, NULL);
    return rc;
}

