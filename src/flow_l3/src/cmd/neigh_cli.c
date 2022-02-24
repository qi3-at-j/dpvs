#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <rte_ether.h>

/* Internal header files */
#include "neigh_cli_priv.h"
#include "vrf_priv.h"
#include "neigh_priv.h"
#include "common_cli_priv.h"

/* External header files */
#include "netif.h"
#include "list.h"

extern struct common_cmd_notice_entry cmd_notice_entry;
extern struct neigh_table *g_lcores_neigh_tables_p[RTE_MAX_LCORE];

static const char *nud_state_names[] = {
    [CLI_NUD_S_NONE]      = "NONE",
    [CLI_NUD_S_SEND]      = "SEND",
    [CLI_NUD_S_REACHABLE] = "REACHABLE",
    [CLI_NUD_S_PROBE]     = "PROBE",
    [CLI_NUD_S_DELAY]     = "DELAY",
    [CLI_NUD_S_STATIC]     = "STATIC",
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int do_neigh_table_dump(cmd_blk_t *cbt, uint16_t lcore_id, uint32_t table_id)
{
    if (unlikely(table_id >= MAX_ROUTE_TBLS))
        return -EINVAL;

    int i;
    uint16_t cnt = 0;
    struct neigh_entry *neigh_node;
    char ip_str[INET6_ADDRSTRLEN] = {0};
    char mac_str[20] = {0};
    char flag_str[10] = {0};
    char status_str[10] = {0};
    struct neigh_table *neigh_table = &g_lcores_neigh_tables_p[lcore_id][table_id];

    if (neigh_table->cnt.cnt) {
        pthread_mutex_lock(&mutex);
        tyflow_cmdline_printf(cbt->cl, "\n");
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "neigh table id:%u\n", neigh_table->table_id);
        tyflow_cmdline_printf(cbt->cl, "neigh table cnt:%u\n", neigh_table->cnt.cnt);
        tyflow_cmdline_printf(cbt->cl, "%-18s%-20s%-9s%s\n", "Address", "HWaddress", "flag", "status");
        for (i = 0; i < NEIGH_BUCKETS_NUM; i++) {
            hlist_for_each_entry(neigh_node, &neigh_table->ht[i], hnode) {
                cnt++;
                if (neigh_node->flag & NEIGH_STATIC) {
                    strncpy(flag_str, "static", sizeof(flag_str));
                } else {
                    strncpy(flag_str, "arp", sizeof(flag_str));
                }
                strncpy(status_str, nud_state_names[neigh_node->state], sizeof(status_str));
                inet_ntop(neigh_node->af, (void *)&neigh_node->next_hop, ip_str, INET6_ADDRSTRLEN);
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    neigh_node->d_mac.addr_bytes[0], neigh_node->d_mac.addr_bytes[1],
                    neigh_node->d_mac.addr_bytes[2], neigh_node->d_mac.addr_bytes[3],
                    neigh_node->d_mac.addr_bytes[4], neigh_node->d_mac.addr_bytes[5]);
                if (likely(cnt < neigh_table->cnt.cnt))
                    tyflow_cmdline_printf(cbt->cl, "%-18s%-20s%-9s%s\n",
                        ip_str, mac_str, flag_str, status_str);
                else
                    tyflow_cmdline_printf(cbt->cl, "%-18s%-20s%-9s%s",
                        ip_str, mac_str, flag_str, status_str);
            }
        }
        tyflow_cmdline_in(cbt->cl, "\n", strlen("\n"));
        pthread_mutex_unlock(&mutex);
    }

    return 0;
}

static int neigh_table_dump_cli(cmd_blk_t *cbt, uint16_t lcore_id, uint32_t table_id)
{
    if (table_id == MAX_ROUTE_TBLS) {
        int ret;

        for (table_id = 0; table_id < MAX_ROUTE_TBLS; table_id++) {
            if(unlikely((ret = do_neigh_table_dump(cbt, lcore_id, table_id))))
                return ret;
        }

        return 0;
    } else {
        return(do_neigh_table_dump(cbt, lcore_id, table_id));
    }
}

static int show_neigh_tbl_cli(cmd_blk_t *cbt)
{
    return(common_dump_async(cbt, MAX_ROUTE_TBLS,
        neigh_table_dump_cli));
}

EOL_NODE(show_neigh_eol, show_neigh_tbl_cli);
KW_NODE_WHICH(show_neigh_tbls, show_neigh_eol, none, "tids", "all neigh tables", POS_WH_TBL, TYPE_TBLS);
VALUE_NODE(show_neigh_tbl_val, show_neigh_eol, none, "neigh table id value", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(show_neigh_tbl, show_neigh_tbl_val, show_neigh_tbls, "tid", "single neigh table", POS_WH_TBL, TYPE_TBL);
KW_NODE_WHICH(show_neigh_lcores, show_neigh_tbl, none, "lcores", "all lcores", POS_WH_LCORE, TYPE_LCORES);
VALUE_NODE(show_neigh_lcore_val, show_neigh_tbl, none, "lcore id value", POS_NUM_LCORE_ID, NUM);
KW_NODE_WHICH(show_neigh_lcore, show_neigh_lcore_val, show_neigh_lcores, "lcore", "single lcore", POS_WH_LCORE, TYPE_LCORE);
KW_NODE(show_neigh, show_neigh_lcore, none, "neigh", "show neigh related items");

static inline int clear_neigh_tbl_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.data.neigh_node.table_id = cbt->number[POS_NUM_TBL_ID - 1];
    cmd_notice_entry.type = NT_CLEAR_NEI_TBL;
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

static inline int clear_neigh_tbls_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_CLEAR_NEI_TBLS;
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

static int clear_neigh_tbl_cli(cmd_blk_t *cbt)
{   
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_TBL - 1]) {
        case TYPE_TBL:
            ret = clear_neigh_tbl_notice(cbt);
            break;
        case TYPE_TBLS:
            ret = clear_neigh_tbls_notice(cbt);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_TBL - 1]);
            break;
    }

    return ret;
}

EOL_NODE(clear_neigh_eol, clear_neigh_tbl_cli);

static inline int neigh_cpy(struct neigh_entry *neigh_node, cmd_blk_t *cbt)
{
    char *ip;
    int af;
    memset(neigh_node, 0, sizeof(struct neigh_entry));

    ip = cbt->string[POS_STR_DIP - 1];
    if (strchr(ip, '.')) {
        af = AF_INET;
    } else if (strchr(ip, ':')) {
        af = AF_INET6;
    } else {
        tyflow_cmdline_printf(cbt->cl, "neither v4 nor v6 ip address\n");
        return -1;
    }
    if (strlen(ip) > 0) {
        if (unlikely(inet_pton(af, ip, &neigh_node->next_hop) != 1)) {
            tyflow_cmdline_printf(cbt->cl, 
                                  "incorrect %s ip address\n", 
                                  (af==AF_INET)?"v4":"v6");
            return -1;
        }
    }
    if (strlen(cbt->string[POS_STR_MAC - 1]) > 0) {
        if (unlikely(neigh_atoi(neigh_node->d_mac.addr_bytes,
                cbt->string[POS_STR_MAC - 1]))) {
            tyflow_cmdline_printf(cbt->cl, 
                "mac %s is not available!!!\n",
                cbt->string[POS_STR_MAC - 1]);
            return -2;
        }
    }

    neigh_node->table_id = cbt->number[POS_NUM_TBL_ID - 1];
    neigh_node->flag |= NEIGH_STATIC;
    neigh_node->state = CLI_NUD_S_STATIC;
    neigh_node->af = af;
    INIT_LIST_HEAD(&neigh_node->queue_list);
    return 0;
}

static inline int del_neigh_tbl_cli(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = neigh_cpy(&cmd_notice_entry.data.neigh_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "neigh_cpy err %d\n", ret);        
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_DEL_NEI;
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

EOL_NODE(del_neigh_eol, del_neigh_tbl_cli);
VALUE_NODE(del_neigh_dip_val, del_neigh_eol, none, "IPv4 address", POS_STR_DIP, STR);
KW_NODE(del_neigh_dip, del_neigh_dip_val, clear_neigh_eol, "dip", "destination IP");
VALUE_NODE(del_neigh_tbl_val, del_neigh_dip, none, "neigh table id value", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(del_neigh_tbls, clear_neigh_eol, none, "tids", "all neigh tables", POS_WH_TBL, TYPE_TBLS);
KW_NODE_WHICH(del_neigh_tbl, del_neigh_tbl_val, del_neigh_tbls, "tid", "neigh table id", POS_WH_TBL, TYPE_TBL);
//KW_NODE(del_neigh_tbl, del_neigh_tbl_val, del_neigh_tbls, "tid", "del neigh table id value");
//KW_NODE(del_neigh, del_neigh_tbl, none, "neigh", "del neigh related items");

static inline int set_neigh_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = neigh_cpy(&cmd_notice_entry.data.neigh_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "neigh_cpy err %d\n", ret);
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_SET_NEI;
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

static int set_neigh_tbl_cli(cmd_blk_t *cbt)
{  
    return(set_neigh_notice(cbt));
}

EOL_NODE(set_neigh_eol, set_neigh_tbl_cli);
VALUE_NODE(set_neigh_mac_val, set_neigh_eol, none, "MAC address", POS_STR_MAC, STR);
KW_NODE(set_neigh_mac, set_neigh_mac_val, none, "mac", "set MAC address");
VALUE_NODE(set_neigh_dip_val, set_neigh_mac, none, "IPv4/v6 address", POS_STR_DIP, STR);
KW_NODE(set_neigh_dip, set_neigh_dip_val, none, "dip", "destination IP");
VALUE_NODE(set_neigh_tbl_val, set_neigh_dip, none, "neigh table id value", POS_NUM_TBL_ID, NUM);
KW_NODE(set_neigh_tbl, set_neigh_tbl_val, none, "tid", "set neigh table id value");
TEST_UNSET(test_unset_neigh, del_neigh_tbl, set_neigh_tbl);
KW_NODE(set_neigh, test_unset_neigh, none, "neigh", "set neigh related items");

void neigh_cli_init(void)
{
    add_get_cmd(&cnode(show_neigh));
    add_set_cmd(&cnode(set_neigh));
    //add_clear_cmd(&cnode(clear_neigh));
    //add_move_cmd(&cnode(del_neigh));
    return;
}

