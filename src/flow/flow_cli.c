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

static inline uint32_t
flow_get_total_connection()
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
	
	/*
     * we may support showing connection by vrf, check the token here
	 */
	
	tyflow_cmdline_printf(cbt->cl, " id %d,flag 0x%x,time %lld, reason %d\n",
			              (fcp2id(fcp)),
                          fcp->fcflag,
                          fcp->start_time,
                          fcp->reason);
	
	csp = &fcp->conn_sub0;
    inet_ntop(AF_INET, &csp->src_ip, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &csp->dst_ip, daddr, sizeof(daddr));
    tyflow_cmdline_printf(cbt->cl, "  if %d(cspflag 0x%x): %s/%d->%s/%d, %d, vrf %d, route %d, packets/bytes %lld/%lld",
                          (uint32_t)csp->ifp, csp->cspflag,
                          saddr, csp->src_port,
                          daddr, csp->dst_port,
                          csp->proto, csp->csp_token,
                          (uint32_t)csp->route,
                          csp->pkt_cnt, csp->byte_cnt);
	if(csp->proto == IPPROTO_TCP){
		tyflow_cmdline_printf(cbt->cl, ",wsf %d",csp->wsf);/*wsf sync*/
	}

	csp = &fcp->conn_sub1;
    inet_ntop(AF_INET, &csp->src_ip, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &csp->dst_ip, daddr, sizeof(daddr));
    tyflow_cmdline_printf(cbt->cl, "  if %d(cspflag 0x%x): %s/%d->%s/%d, %d, vrf %d, route %d, packets/bytes %lld/%lld",
                          (uint32_t)csp->ifp, csp->cspflag,
                          saddr, csp->src_port,
                          daddr, csp->dst_port,
                          csp->proto, csp->csp_token,
                          (uint32_t)csp->route,
                          csp->pkt_cnt, csp->byte_cnt);
	if(csp->proto == IPPROTO_TCP){
		tyflow_cmdline_printf(cbt->cl, ",wsf %d",csp->wsf);/*wsf sync*/
	}
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
		if ((paras->fcflag & fcp->natflag) != paras->fcflag) 
            return 0;
	}

	csp = &(fcp->conn_sub0);
	if ((csp->cspflag & CSP_INITIATE_SIDE) == 0)
		csp = csp2peer(csp);
	peer = csp2peer(csp);

	if (mask & CLR_GET_CONN_VRF_ID) {
		if (paras->vrf_id != csp->csp_token && 
			paras->vrf_id != peer->csp_token) 
            return 0;
    }

	if (mask & CLR_GET_CONN_SRCIP_MASK) {
        if (paras->src_ip != (csp->src_ip & paras->src_mask))
            return 0;
	}
	else if (mask & CLR_GET_CONN_SRCIP) {
        if (paras->src_ip != nsp->src_ip)
            return 0;
    }

	if (mask & CLR_GET_CONN_DESIP_MASK) {
        if (paras->dst_ip != (csp->dst_ip & paras->dst_mask))
            return 0;
	}
	else if (mask & CLR_GET_CONN_DESIP) {
        if (paras->dst_ip != csp->dst_ip)
            return 0;
    }

	if (mask & CLR_GET_CONN_PROTOCOL_HIGH) {
		if (paras->protocol_low > csp->proto ||
            paras->protocol_high < csp->proto)
            return 0;
    }
	else if (mask & CLR_GET_CONN_PROTOCOL_LOW) {
        if (paras->protocol_low != csp->proto)
            return 0;
    }

	if (mask & CLR_GET_CONN_SRCPORT_HIGH) {
		if (ntohs(paras->srcport_low) > ntohs(csp->src_port) ||
			ntohs(paras->srcport_high) < ntohs(csp->src_port))
			return 0;
	}
	else if (mask & CLR_GET_CONN_SRCPORT_LOW) {
		if (paras->srcport_low != csp->src_port)
			return 0;
	}

	if (mask & CLR_GET_CONN_DESPORT_HIGH) {
		if (ntohs(paras->dstport_low) > ntohs(csp->dst_port) ||
			ntohs(paras->dstport_high) < ntohs(csp->dst_port))
            return 0;
	}
	else if (mask & CLR_GET_CONN_DESPORT_LOW){
		if (paras->dstport_low != csp->dst_port)
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
static uint32_t 
show_flow_connection(connection_op_para_t *paras, void *args)
{
	int rc;

	/* traverse all connections. */
	rc = traverse_all_flow_connection(paras, args, show_one_flow_connection);

	return(rc);
}

static int
show_flow_connection_cli(cmd_blk_t *cbt)
{
    connection_op_para_t paras;
    int rc;

    tyflow_cmdline_printf(cbt->cl, "flow connection on lcore %d:\n", rte_lcore_id());
    switch(cbt->which[0]) {
        case 1:
            tyflow_cmdline_printf(cbt->cl, "total connection: %d\n", flow_get_total_connection());
            break;
        case 2:
            rc = show_flow_connection(NULL, (void *)cbt);
            tyflow_cmdline_printf(cbt->cl, "total number %d\n", rc);
            break;
        case 3:
            tyflow_cmdline_printf(cbt->cl, "showing the connection %d:\n", cbt->number[0]);
            break;
        case 0:
            memset(&paras, 0, sizeof(paras));
            if (cbt->which[1] == 1) {
                paras.src_ip = cbt->ipv4[0];
                paras.mask |= CLR_GET_CONN_SRCIP;
                if (cbt->number[1]) {
                    paras.src_mask = number_2_mask(cbt->number[1]);
                }
            }
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
KW_NODE_WHICH(flow_conn_policy, flow_conn_policyid, none, "policy", "specific a policy", 8, 1);
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
/* show flow connection by id */
VALUE_NODE(flow_conn_id_val, flow_conn_eol, none, "the flow connection id", 1, NUM);
KW_NODE_WHICH(flow_conn_id, flow_conn_id_val, flow_conn_srcip, "id", "show one specific flow connection", 1, 3);
/* show flow connection all */
KW_NODE_WHICH(flow_conn_all, flow_conn_eol, flow_conn_id, "all", "show all flow connection", 1, 2);
/* show flow connection summary */
KW_NODE_WHICH(flow_conn_summary, flow_conn_eol, flow_conn_all, "summary", "show flow connection summary", 1, 1);
/* show flow */
KW_NODE(flow_connection, flow_conn_summary, none, "connection", "show flow connection");
