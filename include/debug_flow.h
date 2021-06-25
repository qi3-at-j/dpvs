
#ifndef __DEBUG_FLOW_H__
#define __DEBUG_FLOW_H__

#include "debug.h"

#define RTE_LOGTYPE_FLOW RTE_LOGTYPE_USER1

extern uint32_t flow_debug_flag;
#define FLOW_DEBUG_BASIC  0x0001
#define FLOW_DEBUG_EVENT  0x0002
#define FLOW_DEBUG_PACKET 0x0004
#define FLOW_DEBUG_ALL (FLOW_DEBUG_BASIC | FLOW_DEBUG_EVENT | FLOW_DEBUG_PACKET)

#define flow_debug_trace(flag, fmt, arg...) \
    do {                                    \
        if (flow_debug_flag & flag)         \
            debug_trace(fmt, ##arg);        \
    }while(0)

#define flow_debug_trace_no_flag(fmt, arg...) \
    do {                                      \
        debug_trace(fmt, ##arg);              \
    }while(0)

#define flow_debug_packet(mac, mbuf)  \
    do {                                         \
        if (flow_debug_flag & FLOW_DEBUG_PACKET) \
            mac?debug_trace_packet_mac(mbuf):debug_trace_packet_ip(mbuf); \
    }while(0)

#define flow_print(fmt, arg...)              \
    if (ffilter_show_this_pak > 0) {         \
        flow_debug_trace_no_flag(fmt, ##arg) \
    }

extern void
debug_flow_init(void);
#endif
