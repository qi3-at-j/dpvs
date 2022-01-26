#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "parser/flow_cmdline.h"
#include "fw_conf/fw_cli.h"
#include "fw_conf/ips_policy_cli.h"
#include "fw_conf/ips_policy_conf.h"

extern unsigned int g_ips_enable;
extern unsigned int g_apr_enable;

static int set_ips_action_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "opt: %s\n", cbt->mode == MODE_DO ? "do":"undo");
    ips_policy_set_action(cbt->number[0], cbt->number[1], cbt->which[0] == ACTION_DROP ? "drop" : (cbt->which[0] == ACTION_PASS ? "pass" : "alert"));
    return 0;
}

static int show_ips_action_cli(cmd_blk_t *cbt)
{
    int action = ips_policy_get_action(cbt->number[0], cbt->number[1]);
    char *pcAction = NULL;
    switch(action)
    {
        case ACTION_ALERT:
            pcAction = "alert";
            break;
        case ACTION_DROP:
            pcAction = "drop";
            break;
        case ACTION_PASS:
            pcAction = "pass";
            break;
        default:
            pcAction = "get failed";
            break;
    }
    tyflow_cmdline_printf(cbt->cl, "vrfid %d userid %d action %s\n",
                          cbt->number[0], cbt->number[1], pcAction);
    return 0;
}

static int set_ips_enable_cli(cmd_blk_t *cbt)
{
    switch (cbt->which[0]) {
        case 1: /* set ips enable */
            g_ips_enable = 1;
            break;
        case 2: /* set ips disable */
        case 3: /* unset ips enable */
            g_ips_enable = 0;
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "\tunknown command\n");
    }

    return 0;
}

static int show_ips_info_cli(cmd_blk_t *cbt)
{
    /* show ips info */
    tyflow_cmdline_printf(cbt->cl, "  IPS:  %s\r\n", g_ips_enable ? "enable" : "disable");

    return 0;
}

static int set_apr_enable_cli(cmd_blk_t *cbt)
{
    switch (cbt->which[0]) {
        case 1: /* set apr enable */
            g_apr_enable = 1;
            break;
        case 2: /* set apr disable */
        case 3: /* unset apr enable */
            g_apr_enable = 0;
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "\tunknown command\n");
    }

    return 0;
}

static int show_apr_info_cli(cmd_blk_t *cbt)
{
    /* show ips info */
    tyflow_cmdline_printf(cbt->cl, "  APR:  %s\r\n", g_apr_enable ? "enable" : "disable");

    return 0;
}

static int set_dpi_mode_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "opt: %s\n", cbt->mode == MODE_DO ? "do":"undo");

    dpi_set_mode(cbt->number[0], cbt->which[0] == DPI_MODE_BLOCK ? "block" : "monitor");

    return 0;
}

static int show_dpi_mode_cli(cmd_blk_t *cbt)
{
    int mode = dpi_get_mode(cbt->number[0]);
    char *pcMode = NULL;
    switch(mode)
    {
        case DPI_MODE_BLOCK:
            pcMode = "block";
            break;
        case DPI_MODE_MONITOR:
            pcMode = "monitor";
            break;
        default:
            pcMode = "get failed";
            break;
    }

    tyflow_cmdline_printf(cbt->cl, "userid %d mode %s\n",
                          cbt->number[0], pcMode);

    return 0;
}

static int set_vpatch_switch_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "opt: %s\n", cbt->mode == MODE_DO ? "do":"undo");

    dpi_set_vpatch_switch(cbt->number[0], cbt->which[0] == VPATCH_ON ? "on" : "off");

    return 0;
}

static int show_vpatch_switch_cli(cmd_blk_t *cbt)
{
    int vpatch_switch = dpi_get_vpatch_switch(cbt->number[0]);
    char *pcSwitch = NULL;
    switch(vpatch_switch)
    {
        case VPATCH_ON:
            pcSwitch = "on";
            break;
        case VPATCH_OFF:
            pcSwitch = "off";
            break;
        default:
            pcSwitch = "get failed";
            break;
    }

    tyflow_cmdline_printf(cbt->cl, "userid %d vpatch is %s\n",
                          cbt->number[0], pcSwitch);

    return 0;
}

static int set_trace_switch_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "opt: %s\n", cbt->mode == MODE_DO ? "do":"undo");

    dpi_set_trace_switch(cbt->number[0], cbt->which[0] == TRACE_ON ? 1 : 0);

    return 0;
}

static int show_trace_switch_cli(cmd_blk_t *cbt)
{
    int module = dpi_get_trace_switch();
    tyflow_cmdline_printf(cbt->cl, "trace module is %u\n",
                          module);

    return 0;
}


EOL_NODE(set_ips_action_eol, set_ips_action_cli);
KW_NODE_WHICH(ips_alert, set_ips_action_eol, none,  "alert", "pass packet and raise alert log", 1, ACTION_ALERT);
KW_NODE_WHICH(ips_pass, set_ips_action_eol, ips_alert,  "pass",  "pass packet",  1, ACTION_PASS);
KW_NODE_WHICH(ips_drop, set_ips_action_eol, ips_pass,  "drop", "drop packet", 1, ACTION_DROP);
KW_NODE(set_ips_rule_action, ips_drop, none, "action", "ips rule action");
VALUE_NODE(set_ips_rule_id, set_ips_rule_action, none, "the id of rule", 2, NUM);
KW_NODE(set_ips_rule, set_ips_rule_id, none, "rule", "ips rule");
KW_NODE(set_ips_action, set_ips_rule, none, "ips-policy", "set ips policy configure");

EOL_NODE(show_ips_action_eol, show_ips_action_cli);
VALUE_NODE(show_ips_action_vrf_id, show_ips_action_eol, none, "the id of vrf", 1, NUM);
KW_NODE(show_ips_action_vrf, show_ips_action_vrf_id, none, "vrf", "VRF");
KW_NODE(show_ips_rule_action, show_ips_action_vrf, none, "action", "ips rule action");
VALUE_NODE(show_ips_rule_id, show_ips_rule_action, none, "the id of rule", 2, NUM);
KW_NODE(show_ips_rule, show_ips_rule_id, none, "rule", "ips rule");
KW_NODE(show_ips_action, show_ips_rule, none, "ips-policy", "show ips policy configure");

EOL_NODE(ips_enable_eol, set_ips_enable_cli);
KW_NODE_WHICH(unset_ips_enable, ips_enable_eol, none, "enable", "disable ips function", 1, 3);
KW_NODE_WHICH(ips_disable, ips_enable_eol, none, "disable", "disable ips function", 1, 2);
KW_NODE_WHICH(ips_enable, ips_enable_eol, ips_disable, "enable", "enable ips function(default)", 1, 1);
TEST_UNSET(test_unset_ips, unset_ips_enable, ips_enable);
KW_NODE(ips, test_unset_ips, none, "ips", "enable/disable ips function");

EOL_NODE(show_ips_info_eol, show_ips_info_cli);
KW_NODE(show_ips_info, show_ips_info_eol, none, "info", "ips info");
KW_NODE(show_ips, show_ips_info, none, "ips", "ips");

EOL_NODE(apr_enable_eol, set_apr_enable_cli);
KW_NODE_WHICH(unset_apr_enable, apr_enable_eol, none, "enable", "disable apr function", 1, 3);
KW_NODE_WHICH(apr_disable, apr_enable_eol, none, "disable", "disable apr function", 1, 2);
KW_NODE_WHICH(apr_enable, apr_enable_eol, apr_disable, "enable", "enable apr function(default)", 1, 1);
TEST_UNSET(test_unset_apr, unset_apr_enable, apr_enable);
KW_NODE(apr, test_unset_apr, none, "apr", "enable/disable apr function");

EOL_NODE(show_apr_info_eol, show_apr_info_cli);
KW_NODE(show_apr_info, show_apr_info_eol, none, "info", "apr info");
KW_NODE(show_apr, show_apr_info, none, "apr", "apr");

EOL_NODE(dpi_mode_eol, set_dpi_mode_cli);
KW_NODE_WHICH(dpi_monitor, dpi_mode_eol, none,  "monitor",  "monitor mode",  1, DPI_MODE_MONITOR);
KW_NODE_WHICH(dpi_block, dpi_mode_eol, dpi_monitor,  "block", "block mode", 1, DPI_MODE_BLOCK);
KW_NODE(set_dpi_mode, dpi_block, none, "dpi-mode", "set dpi mode configure");

EOL_NODE(show_dpi_mode_eol, show_dpi_mode_cli);
VALUE_NODE(show_dpi_mode_vrf_id, show_dpi_mode_eol, none, "the id of vrf", 1, NUM);
KW_NODE(show_dpi_mode_vrf, show_dpi_mode_vrf_id, none, "vrf", "VRF");
KW_NODE(show_dpi_mode, show_dpi_mode_vrf, none, "dpi-mode", "working mode");

EOL_NODE(vpatch_switch_eol, set_vpatch_switch_cli);
KW_NODE_WHICH(vpatch_off, vpatch_switch_eol, none,  "off",  "vpatch off",  1, VPATCH_OFF);
KW_NODE_WHICH(vpatch_on, vpatch_switch_eol, vpatch_off,  "on", "vpatch on", 1, VPATCH_ON);
KW_NODE(set_vpatch_switch, vpatch_on, none, "vpatch", "set vpatch switch configure");

EOL_NODE(show_vpatch_info_eol, show_vpatch_switch_cli);
VALUE_NODE(show_vpatch_vrf_id, show_vpatch_info_eol, none, "the id of vrf", 1, NUM);
KW_NODE(show_vpatch_vrf, show_vpatch_vrf_id, none, "vrf", "VRF");
KW_NODE(show_vpatch, show_vpatch_vrf, none, "vpatch", "vpatch info");

EOL_NODE(trace_switch_eol, set_trace_switch_cli);
VALUE_NODE(trace_module_id, trace_switch_eol, none, "the module of trace", 1, NUM);
KW_NODE_WHICH(trace_off, trace_module_id, none,  "off",  "trace off",  1, TRACE_OFF);
KW_NODE_WHICH(trace_on, trace_module_id, trace_off,  "on", "trace on", 1, TRACE_ON);
KW_NODE(set_trace_switch, trace_on, none, "trace", "set trace swtich");

EOL_NODE(show_trace_eol, show_trace_switch_cli);
KW_NODE(show_trace_switch, show_trace_eol, none, "trace", "trace info");

void ips_policy_cli_init(void)
{
    vrf_add_set_cmd(&cnode(set_ips_action));
    vrf_add_set_cmd(&cnode(set_dpi_mode));
    vrf_add_set_cmd(&cnode(set_vpatch_switch));
    add_set_cmd(&cnode(ips));
    add_get_cmd(&cnode(show_ips));
    add_set_cmd(&cnode(apr));
    add_get_cmd(&cnode(show_apr));
    add_get_cmd(&cnode(show_dpi_mode));
    add_get_cmd(&cnode(show_vpatch));
    add_get_cmd(&cnode(show_ips_action));
    add_set_cmd(&cnode(set_trace_switch));
    add_get_cmd(&cnode(show_trace_switch));
    return;
}

