
#include "switch_cli_priv.h"

extern struct common_cmd_notice_entry cmd_notice_entry;
struct common_cmd_switch *g_sw_p[RTE_MAX_LCORE];
RTE_DEFINE_PER_LCORE(struct common_cmd_switch, switch_lcore);

static inline int do_show_switch(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    uint8_t sw = 0;

    RTE_LCORE_FOREACH(lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            continue;
        }

        if (lcore_id == rte_get_main_lcore()) {
            continue;
        }

        if (netif_lcore_is_fwd_worker(lcore_id) == false) {
            continue;
        }
            
        switch (cbt->which[POS_WH_SW_1 - 1]) {
            case TYPE_SW_NF:
                sw = g_sw_p[lcore_id]->nf;
                break;
            case TYPE_SW_FWD:
                sw = g_sw_p[lcore_id]->fwd;
                break;
            case TYPE_SW_ARP:
                sw = g_sw_p[lcore_id]->arp;
                break;
            default:
                tyflow_cmdline_printf(cbt->cl, "unknown type:%u\n", cbt->which[POS_WH_SW_1 - 1]);
                return -EINVAL;
        }

        if (sw) {
            tyflow_cmdline_printf(cbt->cl, "enabled\n");
        } else {
            tyflow_cmdline_printf(cbt->cl, "disabled\n");
        }
        break;
    }

    return 0;
}

static int show_switch_cli(cmd_blk_t *cbt)
{   
    return(do_show_switch(cbt));
}

EOL_NODE(show_switch_eol, show_switch_cli);
KW_NODE_WHICH(show_switch_arp_node, show_switch_eol, none, "arp", "arp switch", POS_WH_SW_1, TYPE_SW_ARP);
KW_NODE_WHICH(show_switch_fwd_node, show_switch_eol, show_switch_arp_node, "fwd", "forward switch", POS_WH_SW_1, TYPE_SW_FWD);
KW_NODE_WHICH(show_switch_nf_node, show_switch_eol, show_switch_fwd_node, "nf", "netfilter switch", POS_WH_SW_1, TYPE_SW_NF);
KW_NODE(show_switch_node, show_switch_nf_node, none, "switch", "show switch related items");

static inline int set_route_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    uint8_t sw = 0;

    if (cbt->which[POS_WH_SW_2 - 1] == TYPE_SW_ON) {
        sw = 1;
    }

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    switch (cbt->which[POS_WH_SW_1 - 1]) {
        case TYPE_SW_NF:
            cmd_notice_entry.data.sw.nf = sw;
            cmd_notice_entry.type = NT_SET_SW_NF;
            break;
        case TYPE_SW_FWD:
            cmd_notice_entry.data.sw.fwd = sw;
            cmd_notice_entry.type = NT_SET_SW_FWD;
            break;
        case TYPE_SW_ARP:
            cmd_notice_entry.data.sw.arp = sw;
            cmd_notice_entry.type = NT_SET_SW_ARP;
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown type:%u\n", cbt->which[POS_WH_SW_1 - 1]);
            rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
            return -EINVAL;
    }

    cmd_notice_entry.cbt = cbt;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

    RTE_LCORE_FOREACH(lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            continue;
        }

        if (lcore_id == rte_get_main_lcore()) {
            continue;
        }

        if (netif_lcore_is_fwd_worker(lcore_id) == false) {
            continue;
        }

        cmd_notice_entry.lcore_id = lcore_id;
        while(rte_get_main_lcore() != cmd_notice_entry.lcore_id);
    }

    return 0;
}

static int set_switch_cli(cmd_blk_t *cbt)
{   
    return(set_route_notice(cbt));
}

EOL_NODE(set_switch_eol, set_switch_cli);
KW_NODE_WHICH(set_switch_val_off, set_switch_eol, none, "disable", "turn off the switch", POS_WH_SW_2, TYPE_SW_OFF);
KW_NODE_WHICH(set_switch_val_on, set_switch_eol, set_switch_val_off, "enable", "turn on the switch", POS_WH_SW_2, TYPE_SW_ON);
KW_NODE_WHICH(set_switch_arp_node, set_switch_val_on, none, "arp", "arp switch", POS_WH_SW_1, TYPE_SW_ARP);
KW_NODE_WHICH(set_switch_fwd_node, set_switch_val_on, set_switch_arp_node, "fwd", "forward switch", POS_WH_SW_1, TYPE_SW_FWD);
KW_NODE_WHICH(set_switch_nf_node, set_switch_val_on, set_switch_fwd_node, "nf", "netfilter switch", POS_WH_SW_1, TYPE_SW_NF);
KW_NODE(set_switch_node, set_switch_nf_node, none, "switch", "set switch related items");

void switch_cli_init(void)
{
    add_get_cmd(&cnode(show_switch_node));
    add_set_cmd(&cnode(set_switch_node));
    return;
}


