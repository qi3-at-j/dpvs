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
