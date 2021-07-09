/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <execinfo.h>
#include <rte_cycles.h>
#include <rte_per_lcore.h>
#include "global_data.h"
#include "dpdk.h"
#include "sys_time.h"
#include "debug.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"

RTE_DEFINE_PER_LCORE(uint64_t, cycles_start);
RTE_DEFINE_PER_LCORE(uint64_t, cycles_stop);

#define timing_cycle_var1 RTE_PER_LCORE(cycles_start)
#define timing_cycle_var2 RTE_PER_LCORE(cycles_stop)

int dpvs_backtrace(char *buf, int len)
{
    int ii, depth, slen;
    char **trace;
    void *btbuf[TRACE_STACK_DEPTH_MAX] = { NULL };

    if (len <= 0)
        return 0;
    buf[0] = '\0';

    depth = backtrace(btbuf, TRACE_STACK_DEPTH_MAX);
    trace = backtrace_symbols(btbuf, depth);
    if (!trace)
        return 0;

    for (ii = 0; ii < depth; ++ii) {
        slen = strlen(buf);
        if (slen + 1 >= len)
            break;
        snprintf(buf+slen, len-slen-1, "[%02d] %s\n", ii, trace[ii]);
    }
    free(trace);

    return strlen(buf);
}

void dpvs_timing_start(void)
{
    timing_cycle_var1 = rte_get_timer_cycles();
}

void dpvs_timing_stop(void)
{
    timing_cycle_var2 = rte_get_timer_cycles();
}

int dpvs_timing_get(void)
{
    if (timing_cycle_var2 < timing_cycle_var1)
        return 0;

    return (timing_cycle_var2 - timing_cycle_var1) * 1000000 / g_cycles_per_sec;
}

#define DEBUG_MAX_LINE_LEN     256
#define DEBUG_MAX_LINE_CNT     8192
#define DEBUG_MAX_BUF_LEN      (DEBUG_MAX_LINE_LEN<<2)

rte_atomic32_t debug_index;
char debug_global_buffer[DEBUG_MAX_LINE_CNT][DEBUG_MAX_LINE_LEN];

static void
debug_write_2_buffer(char *string)
{
    lcoreid_t cid;
    uint32_t sid;
    time_t tm;
    uint32_t hdr_len, body_len, n, start, i;
    char buf[DEBUG_MAX_LINE_LEN] = {0};

    cid = rte_lcore_id();
    sid = rte_socket_id();
    tm  = sys_current_time();
    hdr_len = snprintf(buf, DEBUG_MAX_LINE_LEN, "[T%d@%d] %d: ", cid, sid, (uint32_t)tm);
    body_len = strlen(string);
    n = 1;
    while ((body_len+hdr_len+n) >= n*DEBUG_MAX_LINE_LEN)
        n++;

    start = rte_atomic32_add_return(&debug_index, n) - n;
    i = snprintf(debug_global_buffer[start], DEBUG_MAX_LINE_LEN, "%s%s", buf, string);
    if (i >= DEBUG_MAX_LINE_LEN) {
        char *bp = string+DEBUG_MAX_LINE_LEN-1-hdr_len;
        while (--n && i >= DEBUG_MAX_LINE_LEN && start<DEBUG_MAX_LINE_CNT-1) {
            i = snprintf(debug_global_buffer[++start], DEBUG_MAX_LINE_LEN, "%s", bp);
        }
    }
}

#define HEXDUMP_BYTES_PER_LINE 16
static int
print_hex (const char *fmt, ...)
{
    char buf[DEBUG_MAX_LINE_LEN];
	va_list args;
	int ret;
    if (rte_atomic32_read(&debug_index) >= DEBUG_MAX_LINE_CNT)
        return -1;
	va_start(args, fmt);
	ret = vsnprintf(buf, DEBUG_MAX_LINE_LEN, fmt, args);
	va_end(args);
    debug_write_2_buffer(buf);
	return (ret);
}

#define EXTRACT_U_1(p)  ((uint8_t)(*(p))) 
#define get_u_1(p) EXTRACT_U_1(p)
#define GET_U_1(p) get_u_1((const u_char *)(p))

static void
debug_print_hex(const char *output, uint32_t size)
{
	const char *fmt0 = "%s0x%04x: ";
	const char *fmt1 = " %02x%02x";
    char line[64];

	uint32_t nshorts = size / sizeof(short);
	uint32_t i = 0, len = 0;
	uint32_t oset = 0;
	uint8_t b;

	while (nshorts != 0) {
		if ((i++ % 8) == 0) {
            if (len) {
                print_hex("%s\n", line);
            }
            memset(line, 0, sizeof(line));
            len = 0;
            len = snprintf(line, sizeof(line), fmt0, "\t", oset);
			//print_hex(fmt0, "\n\t", oset); 
			oset += HEXDUMP_BYTES_PER_LINE;
		}
		b = GET_U_1(output);
		output++;
        len += snprintf(line+len, sizeof(line)-len, fmt1, b, GET_U_1(output));
		//print_hex(fmt1, b, GET_U_1(output));
		output++;
		nshorts--;
	}
	if (size & 1) {
		if ((i % 8) == 0) {
            if (len) {
                print_hex("%s\n", line);
            }
            memset(line, 0, sizeof(line));
            len = 0;
            len = snprintf(line, sizeof(line), fmt0, "\t", oset);
        }
			//print_hex(fmt0, "\n\t", oset);
        snprintf(line+len, sizeof(line)-len, " %02x", GET_U_1(output));
		//print_hex(" %02x", GET_U_1(output));
	}
	print_hex("%s", "\n");
}

void
debug_trace_packet_mac(struct rte_mbuf *mbuf)
{
    void *mac = rte_pktmbuf_mtod_offset(mbuf, struct rte_ether_hdr*, 0);
    debug_print_hex(mac, 54);
}

void
debug_trace_packet_ip(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, 0);
    debug_print_hex((void *)ip, ntohs(ip->total_length));
}

void
debug_trace(const char *fmt, ...)
{
    char buf[DEBUG_MAX_BUF_LEN];
    va_list args;
    int ret;
    if (rte_atomic32_read(&debug_index) >= DEBUG_MAX_LINE_CNT)
        return;
    va_start(args, fmt);
    ret = vsnprintf(buf, DEBUG_MAX_BUF_LEN, fmt, args);
    va_end(args);
    if (ret >= DEBUG_MAX_BUF_LEN) {
        buf[DEBUG_MAX_BUF_LEN-4] = '.';
        buf[DEBUG_MAX_BUF_LEN-3] = '.';
        buf[DEBUG_MAX_BUF_LEN-2] = '.';
        buf[DEBUG_MAX_BUF_LEN-1] = '\0';
    }
    debug_write_2_buffer(buf);
}

static int
show_debug_trace(cmd_blk_t *cbt)
{
    uint32_t i, j;

    j = rte_atomic32_read(&debug_index);
    j = (j>=DEBUG_MAX_LINE_CNT)?DEBUG_MAX_LINE_CNT:j;
    for (i=0; i<j; i++) {
        tyflow_cmdline_printf(cbt->cl, "%4d %s", i, debug_global_buffer[i]);
    }
    tyflow_cmdline_printf(cbt->cl, "total line %d\n", j);
    return 0;
}

EOL_NODE(debug_trace_eol, show_debug_trace);
KW_NODE(debug_trace, debug_trace_eol, none, "trace", "show debug trace");
KW_NODE(get_debug, debug_trace, none, "debug", "show debug");

static int
clear_debug_trace(cmd_blk_t *cbt)
{
    uint32_t j;

    j = rte_atomic32_read(&debug_index);
    j = (j>=DEBUG_MAX_LINE_CNT)?DEBUG_MAX_LINE_CNT:j;
    rte_atomic32_set(&debug_index, 0);
    tyflow_cmdline_printf(cbt->cl, "clear %d lines of trace\n", j);
    return 0;
}
EOL_NODE(debug_trace2_eol, clear_debug_trace);
KW_NODE(debug_trace2, debug_trace2_eol, none, "trace", "clear debug trace");
KW_NODE(clear_debug, debug_trace2, none, "debug", "clear debug");

extern void
debug_flow_init(void);
void
debug_init(void)
{
    debug_flow_init();
#if 0
    debug_global_buffer = rte_zmalloc("debug_flow", DEBUG_MAX_LINE_LEN*DEBUG_MAX_LINE_CNT, RTE_CACHE_LINE_SIZE);
    if (!debug_global_buffer) {
        RTE_LOG(ERR, INIT, "failed to allocate memory for debug");
        return;
    }
#endif
    add_get_cmd(&cnode(get_debug));
    add_clear_cmd(&cnode(clear_debug));
    rte_atomic32_set(&debug_index, 0);
}

