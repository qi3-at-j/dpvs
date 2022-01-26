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

#include "dpdk.h"
#include "rte_ether.h"
#include "flow.h"
#include "netif.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"
#include "../include/l2_debug.h"
#include "../include/mac_filter.h"

/*
 * filter variables, 0 if don't care.
 */
uint32_t total_mfilter=0;
mfilter_ent_t mfilter_ent[MAX_MFILTER_NUM];

/*
 * clear to 0 when receive each packet.
 * set to 1 if debug this packet.l2_debug
 */
RTE_DEFINE_PER_LCORE(uint32_t, mfilter_show_this_pak);

static int 
get_mfilter_cli (cmd_blk_t *cbt)
{
	mfilter_ent_t *cur_filter;
	int i;
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    struct netif_port *port = NULL;

	if (total_mfilter > 0) {
		tyflow_cmdline_printf(cbt->cl, "Mac filter based on:\n");
		for (i=0; i< total_mfilter; i++){
			cur_filter=&mfilter_ent[i];
			tyflow_cmdline_printf(cbt->cl, "  id:%d ", i);
            
            if (rte_is_valid_assigned_ether_addr(&cur_filter->d_addr)) {
                rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &cur_filter->d_addr);
                tyflow_cmdline_printf(cbt->cl, "dst mac %s ", buf);
            }
            if (rte_is_valid_assigned_ether_addr(&cur_filter->s_addr)) {
                rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &cur_filter->s_addr);
                tyflow_cmdline_printf(cbt->cl, "src mac %s ", buf);
            }
			if (cur_filter->ether_type)
				tyflow_cmdline_printf(cbt->cl, " ether type 0x%x ", cur_filter->ether_type);
			if (strlen(cur_filter->dev_name) != 0){
                port = netif_port_get(cur_filter->dev_id);
                if(port == NULL){
                    tyflow_cmdline_printf(cbt->cl, " interface name : NULL(invailed)");
                }else{
                    tyflow_cmdline_printf(cbt->cl, " interface name : %s", port->name);
                }
            }
			if (cur_filter->in_out){
                tyflow_cmdline_printf(cbt->cl, " in_out is %s ", (cur_filter->in_out == 1)? "in":"out");
            }
				
			tyflow_cmdline_printf(cbt->cl, "\n");
		};
	}
	return 0;
}

EOL_NODE(get_mfilter_eol, get_mfilter_cli);
KW_NODE(get_mfilter, get_mfilter_eol, none, "mfilter", "show mac filter");

static int 
set_mfilter_cli (cmd_blk_t *cbt)
{
	mfilter_ent_t *cur_filter;
	int i;
    struct rte_ether_addr s_addr;
    struct rte_ether_addr d_addr;
    struct netif_port *port = NULL;
    long data = 0;
	char* endptr = NULL;
    
    memset(&s_addr, 0, sizeof(s_addr));
    memset(&d_addr, 0, sizeof(d_addr));
    
	if (cbt->mode & MODE_UNDO) {
		if (cbt->number[0] >= total_mfilter){
			tyflow_cmdline_printf(cbt->cl, "invalid id\n");
			return 0;
		}
		for (i=cbt->number[0]; i< total_mfilter-1; i++)
			memcpy(&mfilter_ent[i], &mfilter_ent[i+1], sizeof(mfilter_ent_t));
		--total_mfilter;
        tyflow_cmdline_printf(cbt->cl, "filter %d removed\n", cbt->number[0]);
		return 0;
	}
	if (total_mfilter >= MAX_MFILTER_NUM){
		tyflow_cmdline_printf(cbt->cl, "max filter number reached\n");
		return 0;
	}
	if (cbt->which[0] == 1) {
        if (0 != rte_ether_unformat_addr(cbt->string[0], &s_addr)){
            tyflow_cmdline_printf(cbt->cl, "invalid format for source address\n");
            return -1;
        }
	}
	if (cbt->which[1] == 1) {
        if (0 != rte_ether_unformat_addr(cbt->string[1], &d_addr)){
            tyflow_cmdline_printf(cbt->cl, "invalid format for destination address\n");
            return -1;
        }
	}
	cur_filter=&mfilter_ent[total_mfilter++];
	memset(cur_filter, 0, sizeof(mfilter_ent_t));
    memcpy(&cur_filter->s_addr, &s_addr, sizeof(s_addr));
    memcpy(&cur_filter->d_addr, &d_addr, sizeof(d_addr));
	if (cbt->which[2] == 1){
        data = strtol(cbt->string[2], &endptr, 16);
        cur_filter->ether_type = (uint16_t)(data);
    }
		
	if (cbt->which[3] == 1){
        port = netif_port_get_by_name(cbt->string[3]);
        if(!port){
            tyflow_cmdline_printf(cbt->cl, "interface not exist\n");
            return -1;
        }
        cur_filter->dev_id = port->id;
        strlcpy(cur_filter->dev_name, cbt->string[3], sizeof(cur_filter->dev_name));
    }

	if (cbt->which[4] == 1){
        if(!strcmp(cbt->string[4], "in")){
            cur_filter->in_out = 1;
        }else if(!strcmp(cbt->string[3], "out")){
            cur_filter->in_out = 2;
        }else{
            tyflow_cmdline_printf(cbt->cl, "invaild parse of mac filter flow in/out, please check if in or out string\n");
        }
    }
	tyflow_cmdline_printf(cbt->cl, "filter added\n");
	return 0;
}

EOL_NODE(set_mfilter_eol, set_mfilter_cli);

VALUE_NODE(mf_in_out_val, set_mfilter_eol, none, "specfic the flow direction in or out", 5, STR);
KW_NODE_WHICH(mf_in_out, mf_in_out_val, set_mfilter_eol,
	"in/out", "mac filter flow in/out", 5, 1);

VALUE_NODE(mf_port_id_val, mf_in_out, none, "specfic the interface name", 4, STR);
KW_NODE_WHICH(mf_port_id, mf_port_id_val, mf_in_out,
	"interface", "mac filter port-id", 4, 1);

VALUE_NODE(mf_ether_type_val, mf_port_id, none, "specfic ether type by hex", 3, STR);
KW_NODE_WHICH(mf_ether_type, mf_ether_type_val, mf_port_id,
	"ether-type", "mac filter ether type", 3, 1);

VALUE_NODE(mf_dst_mac_val, mf_ether_type, none, "the specific mac", 2, STR);
KW_NODE_WHICH(mf_dst_mac, mf_dst_mac_val, mf_ether_type,
	"dst-mac", "mac filter dst mac", 2, 1);

VALUE_NODE(mf_src_mac_val, mf_dst_mac, none, "the specific mac", 1, STR);
KW_NODE_WHICH(mf_src_mac, mf_src_mac_val, mf_dst_mac,
	"src-mac", "mac filter src mac", 1, 1);
VALUE_NODE(unset_mfilter_id, set_mfilter_eol, none, "mac filter id", 1, NUM);
TEST_UNSET(test_unset_mfilter, unset_mfilter_id, mf_src_mac);
KW_NODE(set_mfilter, test_unset_mfilter, none, "mfilter", "mac filter configuration");

void 
mac_filter_init (void)
{
	total_mfilter=0;	
	
	this_mfilter_show_this_pak = 0;

	add_set_cmd(&cnode(set_mfilter));
	add_get_cmd(&cnode(get_mfilter));
}

static inline int is_zero_ether_addr(const struct rte_ether_addr *ea)
{
	const uint16_t *w = (const uint16_t *)ea;

	return (w[0] | w[1] | w[2]) == 0;
}


int 
mac_match_filter (int node, struct rte_mbuf *mbuf)
{
	
	int i;
	mfilter_ent_t *cur_filter;
    struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type;
	if (total_mfilter==0) /* always match if none is defined */
		return 1;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    ether_type = ntohs(eth_hdr->ether_type);
    
	for (i=0; i<total_mfilter; i++){
		cur_filter=&mfilter_ent[i];
        if ((strlen(cur_filter->dev_name) == 0 || mbuf->port == cur_filter->dev_id) &&
            (cur_filter->ether_type == 0 || ether_type == cur_filter->ether_type) &&
            (is_zero_ether_addr(&cur_filter->d_addr) || rte_is_same_ether_addr(&eth_hdr->d_addr, &cur_filter->d_addr)) &&
            (is_zero_ether_addr(&cur_filter->s_addr) || rte_is_same_ether_addr(&eth_hdr->s_addr, &cur_filter->s_addr)) &&
            (cur_filter->in_out == 0 || (cur_filter->in_out == 1 && node == L2_DEBUG_ETH_INPUT) || (cur_filter->in_out == 2 && node == L2_DEBUG_L2_XMIT))) 
            {
                return 1;
            }
    }
	return 0;
}


