#include <stdio.h>
#include <assert.h>

#include "parser/flow_cmdline.h"
#include "fw_conf/fw_cli.h"
#include "fw_conf/ips_policy_cli.h"


static int set_ips_cli(cmd_blk_t *cbt)
{
    tyflow_cmdline_printf(cbt->cl, "opt: %s\n", cbt->mode == MODE_DO ? "do":"undo");
    tyflow_cmdline_printf(cbt->cl, "vrf: %d\n", cbt->number[0]); 
    tyflow_cmdline_printf(cbt->cl, "rule id: %s\n", cbt->string[0]); 
    tyflow_cmdline_printf(cbt->cl, "action: %d\n", cbt->which[0]); 

    return 0;
}

EOL_NODE(ips_eol, set_ips_cli);

KW_NODE_WHICH(ips_pass, ips_eol, none,  "pass",  "detect sip",  1, 2);
KW_NODE_WHICH(ips_drop, ips_eol, ips_pass,  "drop", "detect tftp", 1, 1);

KW_NODE(ips_action, ips_drop, none, "action", "ips rule action");

VALUE_NODE(ips_rule_id, ips_action, none, "the id of rule", 1, STR);
KW_NODE(ips_rule, ips_rule_id, none, "rule", "ips rule");

KW_NODE(set_ips, ips_rule, none, "ips-policy", "set ips policy configure");

void ips_policy_cli_init(void)
{
    vrf_add_set_cmd(&cnode(set_ips));
    return;
}

