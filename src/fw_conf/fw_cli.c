#include <stdio.h>
#include <assert.h>

#include "parser/flow_cmdline.h"
#include "fw_conf/session_cli.h"
#include "fw_conf/security_policy_cli.h"
#include "fw_conf/aspf_policy_cli.h"
#include "fw_conf/ips_policy_cli.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/fw_cli.h"
#include "pfilter_cli.h"


#include "../access_control/error.h"
#include "../access_control/secpolicy_common.h"
#include "../access_control/secpolicy.h"

static void vrf_add_cmd(cmd_node_t *node, cmd_node_t **last, cmd_node_t *top)
{
    if (*last) {
        (*last)->sibl = node;
    } else {
        top->child = node;
    }

    while (node->sibl && node->sibl != &cnode(none)) {
        node = node->sibl;
    }

    *last = node;
}


/*  set vrf cmd */
cmd_node_t *last_set_vrf_cmd = NULL;
VALUE_NODE(vrf_value, none, none, "the id of vrf", 1, NUM);
KW_NODE(set_vrf, vrf_value, none, "vrf", "set vrf configure");

void vrf_add_set_cmd(cmd_node_t *node)
{
    vrf_add_cmd(node, &last_set_vrf_cmd, &cnode(vrf_value));
}
/*  set vrf cmd end */


/*  create vrf cmd */
static int create_vrf_cli(cmd_blk_t *cbt)
{
    printf("%s: %d %s\n", cbt->mode == MODE_DO ? "create":"delete", cbt->number[0], cbt->string[0]);

    if (cbt->mode == MODE_DO) {
        fw_vrf_create(cbt->number[0], cbt->string[0]);
    } else {
        fw_vrf_delete(cbt->number[0], cbt->string[0]);
    }

    return 0;
}

cmd_node_t *last_vrf_id_cmd = NULL;
EOL_NODE(vrf_eol, create_vrf_cli);

VALUE_NODE(user_id_v, vrf_eol, none, "the value of UUID", 1, STR);
KW_NODE(user_id, user_id_v, none, "user-id", "UUID");

VALUE_NODE(vrf_id, user_id, none, "the id of vrf", 1, NUM);
KW_NODE(create_vrf, vrf_id, none, "vrf", "create/delete vrf");

void vrf_add_create_cmd(cmd_node_t *node)
{
    vrf_add_cmd(node, &last_vrf_id_cmd, &cnode(vrf_id));
}
/* create vrf cmd end */


/* move vrf cmd */
cmd_node_t *last_move_id_cmd = NULL;
VALUE_NODE(move_id, none, none, "the id of vrf", 1, NUM);
KW_NODE(move_vrf, move_id, none, "vrf", "vrf");

void vrf_add_move_cmd(cmd_node_t *node)
{
    vrf_add_cmd(node, &last_move_id_cmd, &cnode(move_id));
}
/* move vrf cmd end */

static void fw_vrf_cli_init(void)
{
    add_set_cmd(&cnode(set_vrf));
    add_create_cmd(&cnode(create_vrf));
    //add_move_cmd(&cnode(move_vrf));

    return;
}

int fw_cli_init(void)
{
    fw_vrf_cli_init();
    session_cli_init();
    aspf_policy_cli_init();
    security_policy_cli_init();
    ips_policy_cli_init();
    Pfilter_Cli_Init();
    return 0;
}

int fw_cli_term(void)
{
    return 0;
}

