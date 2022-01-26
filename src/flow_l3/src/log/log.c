/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <arpa/inet.h>
#include <rte_ethdev.h>

#include "debug.h"
#include "log_priv.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"

uint32_t l3_debug_flag;

static int
debug_l3_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, TYPE_L3, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch (cbt->which[0]) {
        case 1:
            if (cbt->mode & MODE_DO) {
                if (!(l3_debug_flag & L3_INFO)) {
                    tyflow_cmdline_printf(cbt->cl, "l3 info debug is enabled\n");
                    l3_debug_flag |= L3_INFO;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_debug_flag & L3_INFO) {
                    tyflow_cmdline_printf(cbt->cl, "l3 info debug is disabled\n");
                    l3_debug_flag &= ~L3_INFO;
                }
            }
            break;
        case 2:
            if (cbt->mode & MODE_DO) {
                if (!(l3_debug_flag & L3_ERR)) {
                    tyflow_cmdline_printf(cbt->cl, "l3 error debug is enabled\n");
                    l3_debug_flag |= L3_ERR;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_debug_flag & L3_ERR) {
                    tyflow_cmdline_printf(cbt->cl, "l3 error debug is disabled\n");
                    l3_debug_flag &= ~L3_ERR;
                }
            }
            break;
        case 3:
            if (cbt->mode & MODE_DO) {
                if (!(l3_debug_flag & L3_EVENT)) {
                    tyflow_cmdline_printf(cbt->cl, "l3 event debug is enabled\n");
                    l3_debug_flag |= L3_EVENT;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_debug_flag & L3_EVENT) {
                    tyflow_cmdline_printf(cbt->cl, "l3 event debug is disabled\n");
                    l3_debug_flag &= ~L3_EVENT;
                }
            }
            break;
        case 4:
            if (cbt->mode & MODE_DO) {
                if (!(l3_debug_flag & L3_PACKET)) {
                    tyflow_cmdline_printf(cbt->cl, "l3 packet debug is enabled\n");
                    l3_debug_flag |= L3_PACKET;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_debug_flag & L3_PACKET) {
                    tyflow_cmdline_printf(cbt->cl, "l3 packet debug is disabled\n");
                    l3_debug_flag &= ~L3_PACKET;
                }
            }
            break;
        case 5:
            if (cbt->mode & MODE_DO) {
                if (!(l3_debug_flag & L3_DETAIL)) {
                    tyflow_cmdline_printf(cbt->cl, "l3 detail debug is enabled\n");
                    l3_debug_flag |= L3_DETAIL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_debug_flag & L3_DETAIL) {
                    tyflow_cmdline_printf(cbt->cl, "l3 detail debug is disabled\n");
                    l3_debug_flag &= ~L3_DETAIL;
                }
            }
            break;
        case 6:
            if (cbt->mode & MODE_DO) {
                if ((l3_debug_flag & L3_ALL) != L3_ALL) {
                    tyflow_cmdline_printf(cbt->cl, "l3 all debug is enabled\n");
                    l3_debug_flag |= L3_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_debug_flag & L3_ALL) {
                    tyflow_cmdline_printf(cbt->cl, "l3 all debug is disabled\n");
                    l3_debug_flag &= ~L3_ALL;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

EOL_NODE(debug_l3_eol, debug_l3_cli);
KW_NODE_WHICH(l3_all, debug_l3_eol, none, "all", "enable/disable l3 all debug", 1, 6);
KW_NODE_WHICH(l3_detail, debug_l3_eol, l3_all, "detail", "enable/disable l3 detail debug", 1, 5);
KW_NODE_WHICH(l3_packet, debug_l3_eol, l3_detail, "packet", "enable/disable l3 packet debug", 1, 4);
KW_NODE_WHICH(l3_event, debug_l3_eol, l3_packet, "event", "enable/disable l3 event debug", 1, 3);
KW_NODE_WHICH(l3_err, debug_l3_eol, l3_event, "error", "enable/disable l3 error debug", 1, 2);
KW_NODE_WHICH(l3_info, debug_l3_eol, l3_err, "info", "enable/disable l3 info debug", 1, 1);
KW_NODE(debug_l3, l3_info, none, "l3", "enable/disable l3 related debug");

static int
show_l3_debug_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "l3 debug status:\n");
    if (!l3_debug_flag) {
        tyflow_cmdline_printf(cbt->cl, "\t\tnone.\n");
    } else {
        if (l3_debug_flag & L3_INFO)
            tyflow_cmdline_printf(cbt->cl, "\t\tinfo enabled.\n");
        if (l3_debug_flag & L3_ERR)
            tyflow_cmdline_printf(cbt->cl, "\t\terror enabled.\n");
        if (l3_debug_flag & L3_EVENT)
            tyflow_cmdline_printf(cbt->cl, "\t\tevent enabled.\n");
        if (l3_debug_flag & L3_PACKET)
            tyflow_cmdline_printf(cbt->cl, "\t\tpacket enabled.\n");
        if (l3_debug_flag & L3_DETAIL)
            tyflow_cmdline_printf(cbt->cl, "\t\tdetail enabled.\n");
    }
    return 0;
}

EOL_NODE(l3_debug_eol, show_l3_debug_cli);
KW_NODE(l3_debug, l3_debug_eol, none, "debug", "show l3 debug status");
KW_NODE(show_l3, l3_debug, none, "l3", "show l3 related items");

void PrintMbufPkt(struct rte_mbuf * mbuf,
    uint8_t have_ethhdr, uint8_t debug_iph)
{
    uint8_t *pkt;
    struct rte_ipv4_hdr *ip_header;
    rte_be16_t ptype;
    uint16_t seg_nb;
    struct rte_mbuf * seg = mbuf;
    char dst_addr[64] = {0};

/* This function affects forwarding performance, so add a switch here */
#if (NO_DEBUG_TRACE == 0)
    if (likely(!(l3_debug_flag & L3_PACKET)))
        return;
#endif

    L3_DEBUG_TRACE(L3_PACKET, "**************************start**************************\n");
    L3_DEBUG_TRACE(L3_PACKET, "pkt len:%u\n", mbuf->pkt_len);
    seg_nb = 0;
    while (seg) {
        L3_DEBUG_TRACE(L3_PACKET, "mbuf seg num[%u]:\n", seg_nb);
        l3_debug_mbuf_data(seg);
        seg = seg->next;
        seg_nb++;
    }
    L3_DEBUG_TRACE(L3_PACKET, "mbuf seg total num:%d\n", seg_nb);
    
    pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
    if (have_ethhdr) {
        ptype = *(rte_be16_t *)(pkt + sizeof(struct rte_ether_hdr) - 2);
        L3_DEBUG_TRACE(L3_PACKET, "packt type:%02X%02X\n", (uint8_t)ptype, (uint8_t)(ptype >> 8));
        //node_info(node_name, "packt type:%02X%02X\n", (uint8_t)ptype, (uint8_t)(ptype >> 8));
        ip_header = (struct rte_ipv4_hdr *)(pkt + sizeof(struct rte_ether_hdr));
        
        L3_DEBUG_TRACE(L3_PACKET, "d_addr:%02X:%02X:%02X:%02X:%02X:%02X\n",
               pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
        L3_DEBUG_TRACE(L3_PACKET, "s_addr:%02X:%02X:%02X:%02X:%02X:%02X\n",
               pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);
    } else {
        ip_header = (struct rte_ipv4_hdr *)pkt;
        ptype = 0x0008;
    }

    //L3_DEBUG_TRACE(L3_PACKET, "ptype_h:%02X, ptype_l:%02X, htons(ptype):%u\n", 
         //(uint8_t)(ptype >> 8), (uint8_t)ptype, ptype);

	if ((htons(ptype) == 0x0800) && (debug_iph)) {
		L3_DEBUG_TRACE(L3_PACKET, "ip version:%d\n", ip_header->version_ihl >> 4);
		L3_DEBUG_TRACE(L3_PACKET, "header len:%d\n", ip_header->version_ihl & 0x0F);
		L3_DEBUG_TRACE(L3_PACKET, "type_of_service:%d\n", ip_header->type_of_service);
		L3_DEBUG_TRACE(L3_PACKET, "total_length:%d\n", htons(ip_header->total_length));
		L3_DEBUG_TRACE(L3_PACKET, "packet_id:%d\n", htons(ip_header->packet_id));
		L3_DEBUG_TRACE(L3_PACKET, "DF:%d\n", (htons(ip_header->fragment_offset) & 0x4000) != 0);
		L3_DEBUG_TRACE(L3_PACKET, "MF:%d\n", (htons(ip_header->fragment_offset) & 0x2000) != 0);
		L3_DEBUG_TRACE(L3_PACKET, "fragment_offset:%d\n", htons(ip_header->fragment_offset) & 0x1FFF);
		L3_DEBUG_TRACE(L3_PACKET, "time_to_live:%d\n", ip_header->time_to_live);
		L3_DEBUG_TRACE(L3_PACKET, "next_proto_id:%d\n", ip_header->next_proto_id);
		L3_DEBUG_TRACE(L3_PACKET, "hdr_checksum:%d\n", htons(ip_header->hdr_checksum));
        inet_ntop(AF_INET, &ip_header->src_addr, dst_addr, sizeof(dst_addr));
		L3_DEBUG_TRACE(L3_PACKET, "src_addr:%s\n", dst_addr);
        memset(dst_addr, 0, sizeof(dst_addr));
        inet_ntop(AF_INET, &ip_header->dst_addr, dst_addr, sizeof(dst_addr));
		L3_DEBUG_TRACE(L3_PACKET, "dst_addr:%s\n", dst_addr);
	}
    L3_DEBUG_TRACE(L3_PACKET, "***************************end***************************\n");
}

