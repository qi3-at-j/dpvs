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

void PrintMbufPkt(struct rte_mbuf * mbuf,
    uint8_t have_ethhdr, uint8_t debug_iph);

#endif
