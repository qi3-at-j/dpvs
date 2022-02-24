#ifndef __NODE_LOG_PRIV_H__
#define __NODE_LOG_PRIV_H__

#include<stdio.h>
#include <stdarg.h>

#include "debug.h"

#define RTE_LOGTYPE_TYPE_L3 RTE_LOGTYPE_USER1

extern uint32_t l3_debug_flag;

#define L3_INFO   0x0001
#define L3_ERR    0x0002
#define L3_EVENT  0x0004
#define L3_PACKET 0x0008
#define L3_DETAIL 0x0010
#define L3_ALL    (L3_INFO | L3_ERR | L3_EVENT | L3_PACKET | L3_DETAIL)

#define NO_DEBUG_TRACE 0

#if NO_DEBUG_TRACE
#define L3_DEBUG_TRACE(flag, fmt, arg...) printf(fmt, ##arg)

#define l3_debug_mbuf_data(mbuf)                      \
    do {                                              \
        uint8_t *pkt_data;                            \
        int i;                                        \
        pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *); \
        for (i = 0; i < mbuf->data_len; i++) {        \
            printf("%02hhX ", pkt_data[i]);           \
        }                                             \
        printf("\n");                                 \
    }while(0)
#else
#define L3_DEBUG_TRACE(flag, fmt, arg...)   \
    do {                                    \
        if (l3_debug_flag & flag)           \
            debug_trace(fmt, ##arg);        \
    }while(0)

#define l3_debug_mbuf_data(mbuf)  \
        do {                                         \
            if (l3_debug_flag & L3_PACKET) \
                debug_trace_mbuf_data(mbuf); \
        }while(0)
#endif

static __rte_always_inline void
PrintMbufPkt(struct rte_mbuf * mbuf,
    uint8_t have_ethhdr, uint8_t debug_iph)
{
/* This function affects forwarding performance, so add a switch here */
#if (NO_DEBUG_TRACE == 0)
    if (likely(!(l3_debug_flag & L3_PACKET))) {
        return;
    } else {
#endif
        uint8_t *pkt;
        struct rte_ipv4_hdr *ip_header;
        rte_be16_t ptype;
        uint16_t seg_nb;
        struct rte_mbuf * seg = mbuf;

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

        if ((htons(ptype) == 0x0800) && (debug_iph)) {
            char dst_addr[64] = {0};
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
#if (NO_DEBUG_TRACE == 0)
    }
#endif
}
#endif
