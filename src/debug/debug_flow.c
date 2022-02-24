#include <unistd.h>
#include <stdint.h>
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"

uint32_t flow_debug_flag;

static int
debug_flow_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch (cbt->which[0]) {
        case 1:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_BASIC)) {
                    tyflow_cmdline_printf(cbt->cl, "flow basic debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_BASIC;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_BASIC) {
                    tyflow_cmdline_printf(cbt->cl, "flow basic debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_BASIC;
                }
            }
            break;
        case 2:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_EVENT)) {
                    tyflow_cmdline_printf(cbt->cl, "flow event debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_EVENT;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_EVENT) {
                    tyflow_cmdline_printf(cbt->cl, "flow event debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_EVENT;
                }
            }
            break;
        case 3:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_PACKET)) {
                    tyflow_cmdline_printf(cbt->cl, "flow packet debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_PACKET;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_PACKET) {
                    tyflow_cmdline_printf(cbt->cl, "flow packet debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_PACKET;
                }
            }
            break;
        case 4:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_DETAIL)) {
                    tyflow_cmdline_printf(cbt->cl, "flow detail debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_DETAIL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_DETAIL) {
                    tyflow_cmdline_printf(cbt->cl, "flow detail debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_DETAIL;
                }
            }
            break;
        case 5:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_CLI)) {
                    tyflow_cmdline_printf(cbt->cl, "flow cli debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_CLI;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_CLI) {
                    tyflow_cmdline_printf(cbt->cl, "flow cli debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_CLI;
                }
            }
            break;
        case 6:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_AGER)) {
                    tyflow_cmdline_printf(cbt->cl, "flow ager debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_AGER;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_AGER) {
                    tyflow_cmdline_printf(cbt->cl, "flow ager debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_AGER;
                }
            }
            break;
        case 7:
            if (cbt->mode & MODE_DO) {
                if ((flow_debug_flag & FLOW_DEBUG_ALL) != FLOW_DEBUG_ALL) {
                    tyflow_cmdline_printf(cbt->cl, "flow all debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_ALL) {
                    tyflow_cmdline_printf(cbt->cl, "flow all debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_ALL;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

EOL_NODE(debug_flow_eol, debug_flow_cli);
KW_NODE_WHICH(flow_all, debug_flow_eol, none, "all", "enable/disable flow all debug", 1, 7);
KW_NODE_WHICH(flow_ager, debug_flow_eol, flow_all, "ager", "enable/disable flow ager debug", 1, 6);
KW_NODE_WHICH(flow_cli, debug_flow_eol, flow_ager, "cli", "enable/disable flow cli debug", 1, 5);
KW_NODE_WHICH(flow_detail, debug_flow_eol, flow_cli, "detail", "enable/disable flow detail debug", 1, 4);
KW_NODE_WHICH(flow_packet, debug_flow_eol, flow_detail, "packet", "enable/disable flow packet debug", 1, 3);
KW_NODE_WHICH(flow_event, debug_flow_eol, flow_packet, "event", "enable/disable flow event debug", 1, 2);
KW_NODE_WHICH(flow_basic, debug_flow_eol, flow_event, "basic", "enable/disable flow basic debug", 1, 1);
KW_NODE(debug_flow, flow_basic, none, "flow", "enable/disable flow related debug");


exnode(debug_l3);
void
debug_flow_init(void)
{
    add_debug_cmd(&cnode(debug_flow));
    add_debug_cmd(&cnode(debug_l3));
}
