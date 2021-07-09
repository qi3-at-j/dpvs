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

#include "global_data.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"
#include "flow_cli.h"

show_flow_ctx_t show_flow_ctx;
static inline uint32_t
flow_get_total_connection(void)
{
    return this_flow_curr_conn;
}

/*
 * show one flow connection in brief format, which also indicates
 * connection location
 */
static void 
show_one_flow_connection (flow_connection_t *fcp, void *args)
{
    cmd_blk_t *cbt = (cmd_blk_t *)args;
	conn_sub_t *csp;
    char saddr[16], daddr[16];
	
	tyflow_cmdline_printf(cbt->cl, "   id %d,flag 0x%x,time %d/%lu, reason %d\n",
			              (fcp2id(fcp)),
                          fcp->fcflag,
                          flow_get_fcp_time(fcp),
                          fcp->start_time,
                          fcp->reason);
	
	csp = &fcp->conn_sub0;
    inet_ntop(AF_INET, &csp->csp_src_ip, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &csp->csp_dst_ip, daddr, sizeof(daddr));
    tyflow_cmdline_printf(cbt->cl, "      if %s(cspflag 0x%x): %s/%d->%s/%d, %d, vrf %d, route 0x%lx, packets/bytes %lu/%lu",
                          (csp->ifp)?csp->ifp->name:"uncertain", csp->cspflag,
                          saddr, ntohs(csp->csp_src_port),
                          daddr, ntohs(csp->csp_dst_port),
                          csp->csp_proto, csp->csp_token,
                          (uint64_t)csp->route,
                          csp->pkt_cnt, csp->byte_cnt);
	if(csp->csp_proto == IPPROTO_TCP){
		tyflow_cmdline_printf(cbt->cl, ",wsf %d",csp->wsf);/*wsf sync*/
	}
    tyflow_cmdline_printf(cbt->cl, "\n");

	csp = &fcp->conn_sub1;
    inet_ntop(AF_INET, &csp->csp_src_ip, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &csp->csp_dst_ip, daddr, sizeof(daddr));
    tyflow_cmdline_printf(cbt->cl, "      if %s(cspflag 0x%x): %s/%d->%s/%d, %d, vrf %d, route 0x%lx, packets/bytes %lu/%lu",
                          (csp->ifp)?csp->ifp->name:"uncertain", csp->cspflag,
                          saddr, ntohs(csp->csp_src_port),
                          daddr, ntohs(csp->csp_dst_port),
                          csp->csp_proto, csp->csp_token,
                          (uint64_t)csp->route,
                          csp->pkt_cnt, csp->byte_cnt);
	if(csp->csp_proto == IPPROTO_TCP){
		tyflow_cmdline_printf(cbt->cl, ",wsf %d",csp->wsf);/*wsf sync*/
	}
    tyflow_cmdline_printf(cbt->cl, "\n");
}

/* no parameters provided means ok, select it */
static int 
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
	if ((csp->cspflag & CSP_INITIATE_SIDE) == 0)
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
	int i, cnt;
	flow_connection_t *fcp;

	total = flow_get_total_connection();
    cnt = 0;
	for (i = 1; (i < FLOW_CONN_MAX_NUMBER) && (cnt < total); i++) {
		fcp = this_flowConnTable + i;
		if (is_fcp_valid(fcp)) {
			if (select_this_connection(fcp, paras)) {
				cnt++;
				if (vector) {
					(*vector)(fcp, args);
				}
				
				/*	to prevent hold cpu too long */
				if ((cnt & 0x3f) ==0)
					_try_reschedule();
				
                /* we may need to page the output */
				if (page_stop())
					goto done;
			}
		}
        /*	to prevent hold cpu too long */
		if ((i & 0xffff) == 0)
			_try_reschedule();
	}
done:
	return cnt;
}

/*
 * show all local flow connections, return count.
 * we need to filter them if required.
 */
uint32_t 
show_flow_connection(show_flow_ctx_t *ctx)
{
    flow_connection_t *fcp;
    int i;

    tyflow_cmdline_printf((struct cmdline *)ctx->cbt, "  lcore%d:\n", rte_lcore_id());
    if (!this_flow_status) {
        tyflow_cmdline_printf((struct cmdline *)ctx->cbt,
                              "    flow is not ready yet\n");
        goto out;
    }

    switch(ctx->paras->op) {
        case CLR_GET_CONN_SUMMARY:
            ctx->number = flow_get_total_connection();
            tyflow_cmdline_printf((struct cmdline *)ctx->cbt, 
                                  "  total number on lcore%d: %d/%d/%d\n", 
                                  rte_lcore_id(), 
                                  ctx->number,
                                  this_flow_free_conn,
                                  this_flow_no_conn);
            break;
        case CLR_GET_CONN_ALL:
            /* traverse all connections. */
            ctx->number = traverse_all_flow_connection(ctx->paras, 
                                                       ctx->cbt, 
                                                       show_one_flow_connection);
            tyflow_cmdline_printf((struct cmdline *)ctx->cbt, 
                                  "  connections on lcore%d: %d\n", 
                                  rte_lcore_id(), ctx->number);
            break;
        case CLR_GET_CONN_DETAIL:
            fcp = this_flowConnTable+ctx->paras->fcid;
            if (is_fcp_valid(fcp)) {
                show_one_flow_connection(fcp, ctx->cbt);
            } else {
                tyflow_cmdline_printf((struct cmdline *)ctx->cbt, 
                                      "  no flow connection id %d\n", 
                                      ctx->paras->fcid); 
            }
            break;
        case CLR_GET_CONN_COUNTER:
            for (i = 0; i < FLOW_COUNTER_MAX; i++) {
                tyflow_cmdline_printf((struct cmdline *)ctx->cbt, 
                                      "  %s %d\n", 
                                      this_flow_counter[i].name, 
                                      this_flow_counter[i].counter);
            }
            break;
        default:
            tyflow_cmdline_printf((struct cmdline *)ctx->cbt, 
                                  "  unsupport operation\n");
            break;
    }
out:
    /* notify main thread */
    ctx->cid = 0;
    return(ctx->number);
}

    static uint32_t 
show_flow_connection_op(connection_op_para_t *paras, void *args)
{
    int rc, i;

    memset(&show_flow_ctx, 0, sizeof(show_flow_ctx));
    rc = 0;
    RTE_LCORE_FOREACH_WORKER(i) {
        if (g_lcore_role[i] == LCORE_ROLE_FWD_WORKER) {
            show_flow_ctx.cid = i;
            show_flow_ctx.cbt = args;
            show_flow_ctx.paras = paras;
            while(!!show_flow_ctx.cid);
            rc += show_flow_ctx.number;
        }
    }
    return rc;
}

static void
flow_parse_para(cmd_blk_t *cbt, connection_op_para_t *paras)
{
    if (cbt->which[1] == 1) {
        paras->src_ip = cbt->ipv4[0];
        paras->mask |= CLR_GET_CONN_SRCIP;
        if (cbt->number[1]) {
            paras->src_mask = number_2_mask(cbt->number[1]);
            paras->mask |= CLR_GET_CONN_SRCIP_MASK;
        }
    }
    if (cbt->which[2] == 1) {
        paras->dst_ip = cbt->ipv4[1];
        paras->mask |= CLR_GET_CONN_DESIP;
        if (cbt->number[2]) {
            paras->dst_mask = number_2_mask(cbt->number[2]);
            paras->mask |= CLR_GET_CONN_DESIP_MASK;
        }
    }
    if (cbt->which[3] == 1) {
        paras->protocol_low = cbt->number[3];
        paras->mask |= CLR_GET_CONN_PROTOCOL_LOW;
        if (cbt->number[4]) {
            paras->protocol_high = cbt->number[4];
            paras->mask |= CLR_GET_CONN_PROTOCOL_HIGH;
        }
    }
    if (cbt->which[4] == 1) {
        paras->srcport_low = cbt->number[5];
        paras->mask |= CLR_GET_CONN_SRCPORT_LOW;
        if (cbt->number[6]) {
            paras->srcport_high = cbt->number[6];
            paras->mask |= CLR_GET_CONN_SRCPORT_HIGH;
        }
    }
    if (cbt->which[5] == 1) {
        paras->dstport_low = cbt->number[7];
        paras->mask |= CLR_GET_CONN_DESPORT_LOW;
        if (cbt->number[8]) {
            paras->dstport_high = cbt->number[8];
            paras->mask |= CLR_GET_CONN_DESPORT_HIGH;
        }
    }
    if (cbt->which[6] == 1) {
        paras->vrf_id = cbt->number[9];
        paras->mask |= CLR_GET_CONN_VRF_ID;
    }
    if (cbt->which[7] == 1) {
        paras->policy_id = cbt->number[10];
        paras->mask |= CLR_GET_CONN_FW_POLICY;
    }
}

static int
show_flow_connection_cli(cmd_blk_t *cbt)
{
    connection_op_para_t paras;
    int rc;

    tyflow_cmdline_printf(cbt->cl, "flow connections:\n");
    memset(&paras, 0, sizeof(paras));
    flow_parse_para(cbt, &paras);
    switch(cbt->which[0]) {
        case 1:
            paras.op = CLR_GET_CONN_SUMMARY;
            rc = show_flow_connection_op(&paras, cbt);
            tyflow_cmdline_printf(cbt->cl, "total connection: %d\n", flow_get_total_connection());
            break;
        case 0:
        case 2:
            paras.op = CLR_GET_CONN_ALL;
            rc = show_flow_connection_op(&paras, (void *)cbt);
            tyflow_cmdline_printf(cbt->cl, "total number %d\n", rc);
            break;
        case 3:
            paras.op = CLR_GET_CONN_DETAIL;
            paras.fcid = cbt->number[0];
            tyflow_cmdline_printf(cbt->cl, "showing the connection %d:\n", paras.fcid);
            show_flow_connection_op(&paras, (void *)cbt);
            break;
        case 4:
            paras.op = CLR_GET_CONN_COUNTER;
            tyflow_cmdline_printf(cbt->cl, " flow counters");
            show_flow_connection_op(&paras, (void *)cbt);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            break;
    }
    return 0;
}

EOL_NODE(flow_conn_eol, show_flow_connection_cli);
/* policy */
VALUE_NODE(flow_conn_policyid, flow_conn_eol, none, "policy id", 11, NUM);
KW_NODE_WHICH(flow_conn_policy, flow_conn_policyid, flow_conn_eol, "policy", "specific a policy", 8, 1);
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
/* show flow connection counter */
KW_NODE_WHICH(flow_conn_counter, flow_conn_eol, flow_conn_srcip, "counter", "show flow connection counters", 1, 4);
/* show flow connection by id */
VALUE_NODE(flow_conn_id_val, flow_conn_eol, none, "the flow connection id", 1, NUM);
KW_NODE_WHICH(flow_conn_id, flow_conn_id_val, flow_conn_counter, "id", "show one specific flow connection", 1, 3);
/* show flow connection all */
KW_NODE_WHICH(flow_conn_all, flow_conn_eol, flow_conn_id, "all", "show all flow connection", 1, 2);
/* show flow connection summary */
KW_NODE_WHICH(flow_conn_summary, flow_conn_eol, flow_conn_all, "summary", "show flow connection summary", 1, 1);
/* show flow */
KW_NODE(flow_connection, flow_conn_summary, none, "connection", "show flow connection");
