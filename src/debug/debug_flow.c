
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
                    printf("flow basic debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_BASIC;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_BASIC) {
                    printf("flow basic debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_BASIC;
                }
            }
            break;
        case 2:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_EVENT)) {
                    printf("flow event debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_EVENT;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_EVENT) {
                    printf("flow event debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_EVENT;
                }
            }
            break;
        case 3:
            if (cbt->mode & MODE_DO) {
                if (!(flow_debug_flag & FLOW_DEBUG_PACKET)) {
                    printf("flow packet debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_PACKET;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_PACKET) {
                    printf("flow packet debug is disabled\n");
                    flow_debug_flag &= ~FLOW_DEBUG_PACKET;
                }
            }
            break;
        case 4:
            if (cbt->mode & MODE_DO) {
                if ((flow_debug_flag & FLOW_DEBUG_ALL) != FLOW_DEBUG_ALL) {
                    printf("flow all debug is enabled\n");
                    flow_debug_flag |= FLOW_DEBUG_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (flow_debug_flag & FLOW_DEBUG_ALL) {
                    printf("flow all debug is disabled\n");
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
KW_NODE_WHICH(flow_all, debug_flow_eol, none, "all", "enable/disable flow all debug", 1, 4);
KW_NODE_WHICH(flow_packet, debug_flow_eol, flow_all, "packet", "enable/disable flow packet debug", 1, 3);
KW_NODE_WHICH(flow_event, debug_flow_eol, flow_packet, "event", "enable/disable flow event debug", 1, 2);
KW_NODE_WHICH(flow_basic, debug_flow_eol, flow_event, "basic", "enable/disable flow basic debug", 1, 1);
KW_NODE(debug_flow, flow_basic, none, "flow", "enable/disable flow related debug");

static int
show_flow_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "flow status:\n");
    tyflow_cmdline_printf(cbt->cl, "\tdebug:\n");
    if (!flow_debug_flag) {
        tyflow_cmdline_printf(cbt->cl, "\t\tnone.\n");
    } else {
        if (flow_debug_flag & FLOW_DEBUG_BASIC)
            tyflow_cmdline_printf(cbt->cl, "\t\tbasic enabled.\n");
        if (flow_debug_flag & FLOW_DEBUG_EVENT)
            tyflow_cmdline_printf(cbt->cl, "\t\tevent enabled.\n");
        if (flow_debug_flag & FLOW_DEBUG_PACKET)
            tyflow_cmdline_printf(cbt->cl, "\t\tpacket enabled.\n");
    }
    return 0;
}
EOL_NODE(flow_status_eol, show_flow_cli);
KW_NODE(flow_status, flow_status_eol, none, "status", "show flow status");
KW_NODE(show_flow, flow_status, none, "flow", "show flow related items");
void
debug_flow_init(void)
{
    add_debug_cmd(&cnode(debug_flow));
    add_get_cmd(&cnode(show_flow));
}
