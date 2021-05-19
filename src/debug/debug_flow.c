
uint32_t flow_debug_flag;
#define FLOW_DEBUG_BASIC  0x0001
#define FLOW_DEBUG_EVENT  0x0002
#define FLOW_DEBUG_PACKET 0x0004
#define FLOW_DEBUG_ALL (FLOW_DEBUG_BASIC | FLOW_DEBUG_EVENT | FLOW_DEBUG_PACKET)

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
                flow_debug_flag |= FLOW_DEBUG_BASIC;
            } else if (cbt->mode & MODE_UNDO) {
                flow_debug_flag &= ~FLOW_DEBUG_BASIC;
            }
            break;
        case 2:
            if (cbt->mode & MODE_DO) {
                flow_debug_flag |= FLOW_DEBUG_EVENT;
            } else if (cbt->mode & MODE_UNDO) {
                flow_debug_flag &= ~FLOW_DEBUG_EVENT;
            }
            break;
        case 3:
            if (cbt->mode & MODE_DO) {
                flow_debug_flag |= FLOW_DEBUG_PACKET;
            } else if (cbt->mode & MODE_UNDO) {
                flow_debug_flag &= ~FLOW_DEBUG_PACKET;
            }
            break;
        case 4:
            if (cbt->mode & MODE_DO) {
                flow_debug_flag |= FLOW_DEBUG_ALL;
            } else if (cbt->mode & MODE_UNDO) {
                flow_debug_flag &= ~FLOW_DEBUG_ALL;
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

void
debug_flow_init(void)
{
    add_debug_cmd(&cnode(debug_flow));
}
