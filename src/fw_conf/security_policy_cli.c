#include <stdio.h>
#include <assert.h>

#include <arpa/inet.h>

#include "parser/flow_cmdline.h"
#include "fw_conf/fw_cli.h"
#include "fw_conf/security_policy_conf.h"
#include "fw_conf/security_policy_cli.h"


enum __rule_which__ {
    rule_which_status = 1,
    rule_which_action,
    rule_which_service,
    rule_which_dst_ip,
    rule_which_dst_ip6,
    rule_which_src_ip,
    rule_which_src_ip6,
    rule_which_dst_port,
    rule_which_src_port,
};

enum __rule_string__ {
    rule_str_name = 1,
    rule_str_dst_ip = 2,
    rule_str_dst_ip6 = 2,
    rule_str_src_ip = 2,
    rule_str_src_ip6 = 2,
};

static int set_rule_cli(cmd_blk_t *cbt)
{
    int i;
    uint32_t vrf;
    uint32_t inbound = 0;
    char *srv[4] = {"none", "tcp", "udp", "icmp"}; 
    secpolicy_rule_s rule = {0};
    cidr_st ip = {0};

    if (cbt->which[0] == 1)
        inbound = 1;

    vrf = cbt->number[0];
    rule.id = cbt->number[1];
    if (security_policy_rule_get(vrf, inbound, rule.id, &rule) < 0) {
        tyflow_cmdline_printf(cbt->cl, "vrf:%d rule %d not exist.\n", vrf, rule.id);
        return -1;
    }

    for (i = 1; i < cbt->which_cnt; i++) {
        switch (cbt->which[i]) {
        case rule_which_status:
            ++i;
            tyflow_cmdline_printf(cbt->cl, "status: %s\n", cbt->which[i] == 1 ? "enable":"disable");
            rule.status = cbt->which[i] == 1 ? 1 : 0;
            security_policy_rule_modify_status(vrf, inbound, rule.id, cbt->which[i]);
            break;
        case rule_which_action:
            ++i;
            tyflow_cmdline_printf(cbt->cl, "action: %s\n", cbt->which[i] == 1 ? "drop":"pass");
            rule.action = cbt->which[i] == 1 ? 1 : 0;
            security_policy_rule_modify_action(vrf, inbound, rule.id, cbt->which[i]);
            break;
        case rule_which_service:
            ++i;
            tyflow_cmdline_printf(cbt->cl, "service: %s\n", srv[cbt->which[i]]);
            rule.action = cbt->which[i];
            security_policy_rule_modify_service(vrf, inbound, rule.id, cbt->which[1]);
            break;
        case rule_which_dst_ip:
            tyflow_cmdline_printf(cbt->cl, "dst ip: %s mask:%d \n", cbt->string[0], cbt->number[2]); 
            inet_pton(AF_INET, cbt->string[0], &ip.addr.ip4);
            ip.prefixlen = cbt->number[2];
            security_policy_rule_modify_dst_ip(vrf, inbound, rule.id, &ip);
            break;
        case rule_which_dst_ip6:
            tyflow_cmdline_printf(cbt->cl, "dst ip6: %s prefix:%d \n", cbt->string[0], cbt->number[2]); 
            inet_pton(AF_INET6, cbt->string[0], &ip.addr.ip6);
            ip.prefixlen = cbt->number[2];
            security_policy_rule_modify_dst_ip6(vrf, inbound, rule.id, &ip);
            break;
        case rule_which_src_ip:
            tyflow_cmdline_printf(cbt->cl, "src ip: %s mask:%d \n", cbt->string[0], cbt->number[2]); 
            inet_pton(AF_INET, cbt->string[0], &ip.addr.ip4);
            ip.prefixlen = cbt->number[2];
            security_policy_rule_modify_src_ip(vrf, inbound, rule.id, &ip);
            break;
        case rule_which_src_ip6:
            tyflow_cmdline_printf(cbt->cl, "src ip6: %s prefix:%d \n", cbt->string[0], cbt->number[2]); 
            inet_pton(AF_INET6, cbt->string[0], &ip.addr.ip6);
            ip.prefixlen = cbt->number[2];
            security_policy_rule_modify_src_ip6(vrf, inbound, rule.id, &ip);
            break;
        case rule_which_dst_port:
            /*
               inet_pton(AF_INET, ip_str, &ipaddr.addr.ipv4) == 1 &&
               cmdline_ipaddr_t ipaddr;
             */
            tyflow_cmdline_printf(cbt->cl, "dst port: %d -- %d \n", cbt->number[2], cbt->number[3]); 
            rule.dst_min_port = cbt->number[2];
            rule.dst_max_port = cbt->number[3];
            security_policy_rule_modify_dst_port(vrf, inbound, rule.id, rule.dst_min_port, rule.dst_max_port);
            break;
        case rule_which_src_port:
            tyflow_cmdline_printf(cbt->cl, "src port: %d -- %d \n", cbt->number[2], cbt->number[3]); 
            rule.src_min_port = cbt->number[2];
            rule.src_max_port = cbt->number[3];
            security_policy_rule_modify_src_port(vrf, inbound, rule.id, rule.src_min_port, rule.src_max_port);
            break;
        default:
            break;
        }
    }

    return 0;
}


/* set cmd */
EOL_NODE(rule_eol, set_rule_cli);
VALUE_NODE(src_port_max, rule_eol, none, "max port number", 4, NUM);
KW_NODE(src_port_to, src_port_max, none, "to", "port range");

VALUE_NODE(src_port_min, src_port_to, none, "min port number", 3, NUM);
KW_NODE_WHICH(src_port, src_port_min, none, "src-port", "source port", 2, rule_which_src_port);

VALUE_NODE(dst_port_max, rule_eol, none, "max port number", 4, NUM);
KW_NODE(dst_port_to, dst_port_max, none, "to", "port range");

VALUE_NODE(dst_port_min, dst_port_to, none, "min port number", 3, NUM);
KW_NODE_WHICH(dst_port, dst_port_min, src_port, "dst-port", "destination port", 2, rule_which_dst_port);

VALUE_NODE(src6_mask_value, rule_eol, none, "prefix value <1-128>", 3, NUM);
KW_NODE(src6_mask, src6_mask_value, none, "prefix", "IP address mask");

VALUE_NODE(src_ip6_value, src6_mask, none, "IPv6 address", 1, STR);
KW_NODE_WHICH(src_ip6, src_ip6_value, dst_port, "src-ip6", "source IPv6", 2, rule_which_src_ip6);

VALUE_NODE(src_mask_value, rule_eol, none, "mask value <1-32>", 3, NUM);
KW_NODE(src_mask, src_mask_value, none, "mask", "IP address mask");

VALUE_NODE(src_ip_value, src_mask, none, "IPv4 address", 1, STR);
KW_NODE_WHICH(src_ip, src_ip_value, src_ip6, "src-ip", "source IP", 2, rule_which_src_ip);

VALUE_NODE(dst6_mask_value, rule_eol, none, "prefix value <1-128>", 3, NUM);
KW_NODE(dst6_mask, dst6_mask_value, none, "prefix", "IP address mask");

VALUE_NODE(dst_ip6_value, dst6_mask, none, "IPv6 address", 1, STR);
KW_NODE_WHICH(dst_ip6, dst_ip6_value, src_ip, "dst-ip6", "destination IPv6", 2, rule_which_dst_ip6);

VALUE_NODE(dst_mask_value, rule_eol, none, "mask value <1-32>", 3, NUM);
KW_NODE(dst_mask, dst_mask_value, none, "mask", "IP address mask");

VALUE_NODE(dst_ip_value, dst_mask, none, "IPv4 address", 1, STR);
KW_NODE_WHICH(dst_ip, dst_ip_value, dst_ip6, "dst-ip", "destination IP", 2, rule_which_dst_ip);

KW_NODE_WHICH(service_icmp, rule_eol, none, "icmp", "icmp", 3, 3);
KW_NODE_WHICH(service_udp,  rule_eol, service_icmp, "udp", "udp", 3, 2);
KW_NODE_WHICH(service_tcp,  rule_eol, service_udp, "tcp", "tcp", 3, 1);
KW_NODE_WHICH(service, service_tcp, dst_ip, "service", "service", 2, rule_which_service);

KW_NODE_WHICH(action_pass,  rule_eol, none, "pass", "pass of action", 3, 2);
KW_NODE_WHICH(action_drop,  rule_eol, action_pass, "drop", "drop of action", 3, 1);
KW_NODE_WHICH(action, action_drop, service, "action", "action of rule", 2, rule_which_action);

KW_NODE_WHICH(status_off, rule_eol, none, "disable", "disable rule", 3, 2);
KW_NODE_WHICH(status_on,  rule_eol, status_off, "enable", "enable rule", 3, 1);
KW_NODE_WHICH(status, status_on, action, "status", "status of rule", 2, rule_which_status);

VALUE_NODE(rule_value, status, none, "id of rule", 2, NUM);
KW_NODE_WHICH(set_secpolicy_out, rule_value, none, "secpolicy-out", "set outbound security policy", 1, 2);
KW_NODE_WHICH(set_secpolicy_in,  rule_value, set_secpolicy_out, "secpolicy-in", "set inbound security policy", 1, 1);
/* set cmd end */


static int create_rule_cli(cmd_blk_t *cbt)
{
    printf("%s %s vrf:%d rule:%d\n", cbt->mode == MODE_DO ? "create":"delete", cbt->which[0]==1? "inbound":"outbound", cbt->number[0], cbt->number[1]);

    if (cbt->mode == MODE_DO) {
        security_policy_rule_create(cbt->number[0], cbt->which[0]==1, cbt->number[1]);
    } else {
        security_policy_rule_delete(cbt->number[0], cbt->which[0]==1, cbt->number[1]);
    }

    return 0;
}


/* create/delete cmd */
EOL_NODE(create_rules_eol, create_rule_cli);
VALUE_NODE(rule_id, create_rules_eol, none, "id of rule", 2, NUM);
KW_NODE_WHICH(create_secpolicy_out, rule_id, vrf_eol, "secpolicy-out", "create/delete outbound security policy", 1, 2);
KW_NODE_WHICH(create_secpolicy_in,  rule_id, create_secpolicy_out, "secpolicy-in", "create/delete inbound security policy", 1, 1);
/* create/delete cmd  end*/


enum __rule_move__ {
    rule_move_before = 1,
    rule_move_after = 2,
};

static int move_rule_cli(cmd_blk_t *cbt)
{
    switch (cbt->which[1]) {
    case rule_move_before:
        tyflow_cmdline_printf(cbt->cl, "vrf:%d %s before: %d -- %d \n", cbt->number[0], cbt->which[0]==1 ? "inbound":"outbound", cbt->number[1], cbt->number[2]);
        security_policy_rule_move(cbt->number[0], cbt->which[0]==1, cbt->number[1], cbt->number[2], SECPOLICY_MOVE_BEFORE);
        break;
    case rule_move_after:
        tyflow_cmdline_printf(cbt->cl, "vrf:%d %s after: %d -- %d \n", cbt->number[0], cbt->which[0]==1 ? "inbound":"outbound", cbt->number[1], cbt->number[2]);
        security_policy_rule_move(cbt->number[0], cbt->which[0]==1, cbt->number[1], cbt->number[2], SECPOLICY_MOVE_AFTER);
        break;
    }

    return 0;
}


/* move cmd */
EOL_NODE(move_rules_eol, move_rule_cli);
VALUE_NODE(after_id, move_rules_eol, none, "id of base rule", 3, NUM);
VALUE_NODE(before_id, move_rules_eol, none, "id of base rule", 3, NUM);
KW_NODE_WHICH(after, after_id, none, "after", "after action", 2, rule_move_after);
KW_NODE_WHICH(before, before_id, after, "before", "before action", 2, rule_move_before);
VALUE_NODE(move_rule_id, before, none, "id of rule", 2, NUM);

KW_NODE_WHICH(move_secpolicy_out, move_rule_id, none, "secpolicy-out", "move outbound security policy", 1, 2);
KW_NODE_WHICH(move_secpolicy_in,  move_rule_id, move_secpolicy_out, "secpolicy-in", "move inbound security policy", 1, 1);

/* mode cmd  end*/


void security_policy_cli_init(void)
{
    vrf_add_set_cmd(&cnode(set_secpolicy_in));
    vrf_add_create_cmd(&cnode(create_secpolicy_in));
    vrf_add_move_cmd(&cnode(move_secpolicy_in));
}

