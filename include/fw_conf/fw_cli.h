#ifndef __FW_CLI_H__
#define __FW_CLI_H__

#include <inttypes.h>
#include "parser/flow_cmdline.h"

extern void vrf_add_set_cmd(cmd_node_t *node);
extern void vrf_add_create_cmd(cmd_node_t *node);
extern void vrf_add_move_cmd(cmd_node_t *node);
extern void vrf_add_show_cmd(cmd_node_t *node);

extern int fw_cli_init(void);
extern int fw_cli_term(void);

exnode(vrf_eol);

#endif
