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

#include <netinet/in.h>

#include "flow.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"
#include "ffilter.h"

/*
 * filter variables, 0 if don't care.
 */
uint32_t total_ffilter=0;
ffilter_ent_t ffilter_ent[MAX_FFILTER_NUM];

/*
 * clear to 0 when receive each packet.
 * set to 1 if debug this packet.
 */
RTE_DEFINE_PER_LCORE(uint32_t, ffilter_show_this_pak);

static int 
get_ffilter_cli (cmd_blk_t *cbt)
{
	ffilter_ent_t *cur_filter;
	int i;
    char addr[16];
	if (total_ffilter > 0) {
		tyflow_cmdline_printf(cbt->cl, "Flow filter based on:\n");
		for (i=0; i< total_ffilter; i++){
			cur_filter=&ffilter_ent[i];
			tyflow_cmdline_printf(cbt->cl, "  id:%d ", i);
			if (cur_filter->src_ip) {
                inet_ntop(AF_INET, &cur_filter->src_ip, addr, sizeof(addr));
				tyflow_cmdline_printf(cbt->cl, "src-ip %s ", addr);
            }
			if (cur_filter->dst_ip) {
                inet_ntop(AF_INET, &cur_filter->dst_ip, addr, sizeof(addr));
				tyflow_cmdline_printf(cbt->cl, " dst-ip %s ", addr);
            }
			if (cur_filter->proto)
				tyflow_cmdline_printf(cbt->cl, " ip-proto %d ", cur_filter->proto);
			if (cur_filter->src_port)
				tyflow_cmdline_printf(cbt->cl, " src-port %d ", ntohs(cur_filter->src_port));
			if (cur_filter->dst_port)
				tyflow_cmdline_printf(cbt->cl, " dst-port %d ", ntohs(cur_filter->dst_port));
			tyflow_cmdline_printf(cbt->cl, "\n");
		};
	}
	return 0;
}

EOL_NODE(get_ffilter_eol, get_ffilter_cli);
KW_NODE(get_ffilter, get_ffilter_eol, none, "ffilter", "show flow filter");

static int 
set_ffilter_cli (cmd_blk_t *cbt)
{
	ffilter_ent_t *cur_filter;
	int i, rc, src_ip, dst_ip;
    /* change to struct in6_addr later */
    char buf[sizeof(struct in_addr)];

	if (cbt->mode & MODE_UNDO) {
		if (cbt->number[0] >= total_ffilter){
			tyflow_cmdline_printf(cbt->cl, "invalid id\n");
			return 0;
		}
		for (i=cbt->number[0]; i< total_ffilter-1; i++)
			memcpy(&ffilter_ent[i], &ffilter_ent[i+1], sizeof(ffilter_ent_t));
		--total_ffilter;
        tyflow_cmdline_printf(cbt->cl, "filter %d removed\n", cbt->number[0]);
		return 0;
	}
	if (total_ffilter >= MAX_FFILTER_NUM){
		tyflow_cmdline_printf(cbt->cl, "max filter number reached\n");
		return 0;
	}
	if (cbt->which[0] == 1) {
        rc = inet_pton(AF_INET, cbt->string[0], buf);
        if (rc <= 0) {
            tyflow_cmdline_printf(cbt->cl, "invalid format for source address\n");
            return -1;
        }
        src_ip = *((int *)buf);
	}
	if (cbt->which[1] == 1) {
        rc = inet_pton(AF_INET, cbt->string[1], buf);
        if (rc <= 0) {
            tyflow_cmdline_printf(cbt->cl, "invalid format for destination address\n");
            return -1;
        }
        dst_ip = *((int *)buf);
	}
	cur_filter=&ffilter_ent[total_ffilter++];
	memset(cur_filter, 0, sizeof(ffilter_ent_t));
    cur_filter->src_ip = src_ip;
    cur_filter->dst_ip = dst_ip;
	if (cbt->which[2] == 1)
		cur_filter->proto = cbt->number[0];
	if (cbt->which[3] == 1)
		cur_filter->src_port = htons(cbt->number[1]);
	if (cbt->which[4] == 1)
		cur_filter->dst_port = htons(cbt->number[2]);
	printf("filter added\n");
	return 0;
}

EOL_NODE(set_ffilter_eol, set_ffilter_cli);

VALUE_NODE(ff_dst_port_val, set_ffilter_eol, none, "tcp/udp dst port", 3, NUM);
KW_NODE_WHICH(ff_dst_port, ff_dst_port_val, set_ffilter_eol,
	"dst-port", "flow filter dst port", 5, 1);

VALUE_NODE(ff_src_port_val, ff_dst_port, none, "tcp/udp src port", 2, NUM);
KW_NODE_WHICH(ff_src_port, ff_src_port_val, ff_dst_port,
	"src-port", "flow filter src port", 4, 1);

VALUE_NODE(ff_ip_proto_val, ff_src_port, none, "ip protocol", 1, NUM);
KW_NODE_WHICH(ff_ip_proto, ff_ip_proto_val, ff_src_port,
	"ip-proto", "flow filter ip proto", 3, 1);

VALUE_NODE(ff_dst_ip_val, ff_ip_proto, none, "the specific ip", 2, STR);
KW_NODE_WHICH(ff_dst_ip, ff_dst_ip_val, ff_ip_proto,
	"dst-ip", "flow filter dst ip", 2, 1);

VALUE_NODE(ff_src_ip_val, ff_dst_ip, none, "the specific ip", 1, STR);
KW_NODE_WHICH(ff_src_ip, ff_src_ip_val, ff_dst_ip,
	"src-ip", "flow filter src ip", 1, 1);
VALUE_NODE(unset_ffilter_id, set_ffilter_eol, none, "flow filter id", 1, NUM);
TEST_UNSET(test_unset_ffilter, unset_ffilter_id, ff_src_ip);
KW_NODE(set_ffilter, test_unset_ffilter, none, "ffilter", "flow filter configuration");

void 
flow_filter_init (void)
{
	total_ffilter=0;	
	
	this_ffilter_show_this_pak = 0;

	add_set_cmd(&cnode(set_ffilter));
	add_get_cmd(&cnode(get_ffilter));
}

static int 
pak_match_filter (struct rte_ipv4_hdr *iphdr, uint32_t *iptr)
{
	int src_port;
	int dst_port;
	int i;
	ffilter_ent_t *cur_filter;
    struct rte_ipv4_hdr iphdr_inner;
    uint32_t ports;

	if (total_ffilter==0) /* always match if none is defined */
		return 1;

    if (iphdr->next_proto_id == IPPROTO_ICMP) {
        iphdr = gen_icmp_lookup_info(iphdr, iptr, &iphdr_inner, &ports);
        if (!iphdr || iphdr == (struct rte_ipv4_hdr *)-1) {
            flow_debug_trace(FLOW_DEBUG_DETAIL, 
                             "    failed to parse the icmp packet\n");
            /* we may be interest in the corrupted packet */
            return 1;
        }
    } else {
        ports = *iptr;
    }
	src_port = ip_src_port(ports);
	dst_port = ip_dst_port(ports);
    flow_debug_trace(FLOW_DEBUG_DETAIL, 
                     "    try to match flow filter for 0x%x/%d->0x%x/%d,%d\n", 
                     iphdr->src_addr, src_port,
                     iphdr->dst_addr, dst_port,
                     iphdr->next_proto_id);
	
	for (i=0; i<total_ffilter; i++){
		cur_filter=&ffilter_ent[i];
		if ((cur_filter->src_ip == 0 || iphdr->src_addr == cur_filter->src_ip) &&
			(cur_filter->dst_ip == 0 || iphdr->dst_addr == cur_filter->dst_ip) &&
			(cur_filter->src_port == 0 || src_port == cur_filter->src_port) &&
			(cur_filter->dst_port == 0 || dst_port == cur_filter->dst_port) &&
			(cur_filter->proto == 0 || iphdr->next_proto_id == cur_filter->proto)) {
            flow_debug_trace(FLOW_DEBUG_DETAIL, "    match flow filter %d\n", i);
			return 1;
		}
	}
    flow_debug_trace(FLOW_DEBUG_DETAIL, "    no match any flow filter\n");
	return 0;
}

int 
static pak_match_filter_reverse (struct rte_ipv4_hdr *iphdr, uint *iptr)
{
	int src_port;
	int dst_port;
	int i;
	ffilter_ent_t *cur_filter;

	if (total_ffilter==0) /* always match if none is defined */
		return 1;

	src_port = ip_dst_port(*iptr);
	dst_port = ip_src_port(*iptr);
	for (i=0; i<total_ffilter; i++){
		cur_filter=&ffilter_ent[i];
		if ((cur_filter->src_ip == 0 || iphdr->dst_addr == cur_filter->src_ip) &&
			(cur_filter->dst_ip == 0 || iphdr->src_addr == cur_filter->dst_ip) &&
			(cur_filter->src_port == 0 || src_port == cur_filter->src_port) &&
			(cur_filter->dst_port == 0 || dst_port == cur_filter->dst_port) &&
			(cur_filter->proto == 0 || iphdr->next_proto_id == cur_filter->proto)) {
			return 1;
		}
	}
	return 0;
}

void 
flow_mark_pak_func(struct rte_ipv4_hdr *iphdr, uint *iptr) 
{
	if (pak_match_filter((iphdr), (iptr)) || pak_match_filter_reverse((iphdr), (iptr)))					
        this_ffilter_show_this_pak = 1;
}
