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

#include <rte_arp.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "ipv4.h"
#include "ipv6.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "flow.h"
#include "debug_flow.h"
#include "flow_cli.h"
#include "flow_profile.h"

/* per lcore flow profile context */
RTE_DEFINE_PER_LCORE(flow_profile_ctx_t, flow_prof);

/* global flow profile valve */
uint32_t flow_profile_flag;

void
prof_vector(uint16_t id)
{
    uint64_t new_time = rte_get_tsc_cycles();
    uint64_t delta = (new_time > this_flow_prof.prof_old_time)?
                     (new_time-this_flow_prof.prof_old_time):
                     (new_time+(UINT64_MAX-this_flow_prof.prof_old_time));
    this_flow_prof.prof_old_time = new_time;
    if (this_flow_prof.prof_old_id < ID_flow_max) {
        this_flow_prof.record[this_flow_prof.prof_old_id].cycles += delta;
        this_flow_prof.record[this_flow_prof.prof_old_id].count++;
    }
    this_flow_prof.prof_old_id = id;
}

#define PROF_VECTOR_FMT_TITLE "%-20s %-4s %-16s %-10s %-10s %-12s\n"
#define PROF_VECTOR_FMT_ITEM  "%-20s %-4d %-16lu %-10d %-10d %-12d\n"
static int
show_flow_prof_vector(cmd_blk_t *cbt)
{
    uint16_t i;
    flow_profile_record_t *record;
    flow_profile_item_t   *vector;

    if (flow_profile_flag & FLOW_PROFILE_FLAG_VECTOR) {
        tyflow_cmdline_printf(cbt->cl, "stop profile vector firstly by \"set flow profile vector end\".\n");
        return -1;
    }
    this_flow_prof.toggle = 0;
    tyflow_cmdline_printf(cbt->cl, "  lcore%d:\n", rte_lcore_id());
    tyflow_cmdline_printf(cbt->cl, PROF_VECTOR_FMT_TITLE,
                          "vector", "ID", "cycles", "usecond", "count", "cycle/count");
    tyflow_cmdline_printf(cbt->cl, "----------------------------------------------------------------------------\n");
    for (i = 0; i < ID_flow_max; i++) {
        record = &this_flow_prof.record[i];
        if (record->count || record->cycles) {
            vector = &this_flow_prof.item[i];
            tyflow_cmdline_printf(cbt->cl, PROF_VECTOR_FMT_ITEM,
                                  vector->name, vector->id, 
                                  record->cycles, 
                                  (record->cycles/(g_cycles_per_sec>>20)), 
                                  record->count,
                                  (record->cycles/record->count));
        }
    }

    return 0;
}

int
show_flow_profile(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
    cmd_blk_t *cbt = (cmd_blk_t *)msg_hdr->cbt;

    assert(msg_hdr->type == CMD_MSG_FLOW_PROF);
    /* now only support profile vector */
    assert(msg_hdr->subtype == FLOW_PROFILE_FLAG_VECTOR);

    show_flow_prof_vector(cbt);
    return 0;
}

static int
show_flow_prof_cli(cmd_blk_t *cbt)
{
    cmd_msg_hdr_t msg;

    switch(cbt->which[0]) {
        case 1:
            msg.subtype = FLOW_PROFILE_FLAG_VECTOR;
            //show_flow_prof_vector(cbt);
            break;
        case 2:
            tyflow_cmdline_printf(cbt->cl, "not support yet.\n");
            msg.subtype = FLOW_PROFILE_FLAG_TRAFFIC;
            //show_flow_prof_traffic(cbt);
            return 0;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            return 0;
    }

    msg.type = CMD_MSG_FLOW_PROF;
    msg.length = sizeof(cmd_msg_hdr_t);
    msg.rc = 0;
    msg.cbt = cbt;
    send_cmd_msg_to_fwd_lcore(&msg);
    return 0;
}

EOL_NODE(show_prof_vector_eol, show_flow_prof_cli);
/* show flow profile traffic */
KW_NODE_WHICH(flow_show_prof_traffic, show_prof_vector_eol, none, 
              "traffic", "show flow profile traffic", 1, 2);
/* show flow profile vector */
KW_NODE_WHICH(flow_show_prof_vector, show_prof_vector_eol, flow_show_prof_traffic, 
              "vector", "show flow profile vector", 1, 1);

static int
set_flow_prof_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch(cbt->which[0]) {
        case 1:
            switch(cbt->which[1]) {
                case 1:
                    if (flow_profile_flag & FLOW_PROFILE_FLAG_VECTOR) {
                        tyflow_cmdline_printf(cbt->cl, "flow profile vector already start.\n");
                    } else {
                        tyflow_cmdline_printf(cbt->cl, "start flow profile vector...\n");
                        flow_profile_flag |= FLOW_PROFILE_FLAG_VECTOR;
                    }
                    break;
                case 2:
                    if (!(flow_profile_flag & FLOW_PROFILE_FLAG_VECTOR)) {
                        tyflow_cmdline_printf(cbt->cl, "flow profile had not been started.\n");
                    } else {
                        tyflow_cmdline_printf(cbt->cl, "stop flow profile vector...\n");
                        flow_profile_flag &= ~FLOW_PROFILE_FLAG_VECTOR;
                    }
                    break;
                default:
                    tyflow_cmdline_printf(cbt->cl, "unknown command\n");
                    break;
            }
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            break;
    }
}

EOL_NODE(set_prof_vector_eol, set_flow_prof_cli);
/* set flow profile vector end */
KW_NODE_WHICH(prof_vector_end, set_prof_vector_eol, none, 
              "end", "stop flow profile vector", 2, 2);

/* set flow profile vector start */
KW_NODE_WHICH(prof_vector_start, set_prof_vector_eol, prof_vector_end, 
              "start", "start flow profile vector", 2, 1);

/* set flow profile vector */
KW_NODE_WHICH(flow_prof_vector, prof_vector_start, none, 
              "vector", "flow profile vector operation", 1, 1);

int
flow_profile_init(void)
{
    memcpy(this_flow_prof.item, flow_prof_item_template, sizeof(flow_profile_item_t)*ID_flow_max);
    return 0;
}
