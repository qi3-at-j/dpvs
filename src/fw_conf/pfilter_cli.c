#include <stdio.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "fw_lib.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_cli.h"

#include "../pfilter/pfilter.h"

static int set_pfilter_cli(cmd_blk_t *cbt)
{
    int i;
    char *pc;
    PFILTER_DATA_S stPfilter;

    memset(&stPfilter, 0, sizeof(PFILTER_DATA_S));

    /* pfilter index <1 - 16> */
    if ((cbt->number[0] >=1) && (cbt->number[0] <= 16))
    {
        stPfilter.uiIndex = cbt->number[0];
    }
    else
    {
        printf("pfilter index <1 - 16>\n");
        return 0;
    }

    /* rule id x */
    stPfilter.uiRuleID = cbt->number[1]; 

    if (1 == cbt->which[0])
    {
        stPfilter.uiIPType = IPPROTO_IP;
    }
    else
    {
        stPfilter.uiIPType = IPPROTO_IPV6;
    }

    /* src-ip | src-ip6 */
    if (1 == cbt->which[1])
    {
        /* ip/mask  cbt->string[0] */
        if (IPPROTO_IP == stPfilter.uiIPType)
        {
            if (true != FWLIB_Check_IPv4AndMask_IsLegal(cbt->string[0]))
            {
                return 0;
            }
            
            if (strchr(cbt->string[0], '/'))
            {
                /* example, 1.1.1.1/24 */
                pc = strtok(cbt->string[0], "/");
                inet_pton(AF_INET, pc, &stPfilter.stSrcIP.un_addr.stIP4Addr);
                pc = strtok(NULL, "/");
                stPfilter.stSrcIP.uiIPMask = atoi(pc);
            }
            else
            {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, cbt->string[0], &stPfilter.stSrcIP.un_addr.stIP4Addr);
                stPfilter.stSrcIP.uiIPMask = 32;
            }
        }
        else
        {
            if (true != FWLIB_Check_IPv6AndPrefix_IsLegal(cbt->string[0]))
            {
                return 0;
            }

            if (strchr(cbt->string[0], '/'))
            {
                /* example, 1::2/64 */
                pc = strtok(cbt->string[0], "/");
                inet_pton(AF_INET6, pc, &stPfilter.stSrcIP.un_addr.stIP6Addr);
                pc = strtok(NULL, "/");
                stPfilter.stSrcIP.uiIPMask = atoi(pc);
            }
            else
            {
                /* example, 1::2 */
                inet_pton(AF_INET6, cbt->string[0], &stPfilter.stSrcIP.un_addr.stIP6Addr);
                stPfilter.stSrcIP.uiIPMask = 128;
            }
        }
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_SIP;
    }

    /* dst-ip | dst-ip6 */
    if (1 == cbt->which[2])
    {
        /* ip/prefix cbt->string[1] */
        if (IPPROTO_IP == stPfilter.uiIPType)
        {
            if (true != FWLIB_Check_IPv4AndMask_IsLegal(cbt->string[1]))
            {
                return 0;
            }
            
            if (strchr(cbt->string[1], '/'))
            {
                /* example, 1.1.1.1/24 */
                pc = strtok(cbt->string[1], "/");
                inet_pton(AF_INET, pc, &stPfilter.stDstIP.un_addr.stIP4Addr);
                pc = strtok(NULL, "/");
                stPfilter.stDstIP.uiIPMask = atoi(pc);
            }
            else
            {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, cbt->string[1], &stPfilter.stDstIP.un_addr.stIP4Addr);
                stPfilter.stDstIP.uiIPMask = 32;
            }
        }
        else
        {
            if (true != FWLIB_Check_IPv6AndPrefix_IsLegal(cbt->string[0]))
            {
                return 0;
            }

            if (strchr(cbt->string[1], '/'))
            {
                /* example, 1::2/64 */
                pc = strtok(cbt->string[1], "/");
                inet_pton(AF_INET6, pc, &stPfilter.stDstIP.un_addr.stIP6Addr);
                pc = strtok(NULL, "/");
                stPfilter.stDstIP.uiIPMask = atoi(pc);
            }
            else
            {
                /* example, 1::2 */
                inet_pton(AF_INET6, cbt->string[1], &stPfilter.stDstIP.un_addr.stIP6Addr);
                stPfilter.stDstIP.uiIPMask = 128;
            }
        }
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_DIP;
    }

    /* protocol */
    if (1 == cbt->which[3])
    {
        /* icmp cbt->which[4] == 1 */
        if (1 == cbt->which[4])
        {
            stPfilter.ucProtocol = IPPROTO_ICMP;
        }
        /* udp cbt->which[4] == 2 */
        else if (2 == cbt->which[4])
        {
            stPfilter.ucProtocol = IPPROTO_UDP;
        }
        /* tcp cbt->which[4] == 3 */
        else if (3 == cbt->which[4])
        {
            stPfilter.ucProtocol = IPPROTO_TCP;
        }
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_PROTOCOL;
    }

    /* src port */
    if (1 == cbt->which[5])
    {
        //src port value cbt->number[2]
        stPfilter.usSPort = cbt->number[2];
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_SPORT;
    }

    /* dst port */
    if (1 == cbt->which[6])
    {
        //dst port value cbt->number[3]
        stPfilter.usDPort = cbt->number[3];
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_DPORT;
    }

    if (0 == stPfilter.uiMatchMask)
    {
        Pfilter_Add(&stPfilter);
    }
    else
    {
        Pfilter_Modify(&stPfilter, BOOL_FALSE);
    }

    return 0;
}

static int unset_pfilter_cli(cmd_blk_t *cbt)
{
    int i;
    PFILTER_DATA_S stPfilter;

    memset(&stPfilter, 0, sizeof(PFILTER_DATA_S));

    /* pfilter index <1 - 16> */
    if ((cbt->number[0] >=1) && (cbt->number[0] <= 16))
    {
        stPfilter.uiIndex = cbt->number[0];
    }
    else
    {
        printf("pfilter index <1 - 16>\n");
        return 0;
    }

    /* rule id x */
    stPfilter.uiRuleID = cbt->number[1]; 

    if (1 == cbt->which[0])
    {
        stPfilter.uiIPType = IPPROTO_IP;
    }
    else
    {
        stPfilter.uiIPType = IPPROTO_IPV6;
    }

    /* src-ip | src-ip6 */
    if (1 == cbt->which[1])
    {
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_SIP;
    }

    /* dst-ip | dst-ip6 */
    if (1 == cbt->which[2])
    {
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_DIP;
    }

    /* protocol */
    if (1 == cbt->which[3])
    {
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_PROTOCOL;
    }

    /* src port */
    if (1 == cbt->which[5])
    {
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_SPORT;
    }

    /* dst port */
    if (1 == cbt->which[6])
    {
        stPfilter.uiMatchMask |= PFILTER_MATCH_TYPE_DPORT;
    }

    if (0 == stPfilter.uiMatchMask)
    {
        Pfilter_Del(stPfilter.uiIndex, stPfilter.uiIPType, stPfilter.uiRuleID);
    }
    else
    {
        Pfilter_Modify(&stPfilter, BOOL_TRUE);
    }
    return 0;
}

EOL_NODE(set_pfilter_eol, set_pfilter_cli);
EOL_NODE(unset_pfilter_eol, unset_pfilter_cli);

/* dst port value :  number[3] = x */
VALUE_NODE(set_pfilter_ipv6_dport_value, set_pfilter_eol, none, "Destination port", 4, NUM);

/* dst port :  which[6] == 1 */
KW_NODE_WHICH(set_pfilter_ipv6_dport, set_pfilter_ipv6_dport_value, set_pfilter_eol, "dst-port", "Destination port", 7, 1);

/* src port value :  number[2] = x */
VALUE_NODE(set_pfilter_ipv6_sport_value, set_pfilter_ipv6_dport, none, "Source port", 3, NUM);

/*src port :  which[5] == 1 */
KW_NODE_WHICH(set_pfilter_ipv6_sport, set_pfilter_ipv6_sport_value, set_pfilter_ipv6_dport, "src-port", "Source port", 6, 1);

/* protocol tcp :  which[4] == 3 */
KW_NODE_WHICH(set_pfilter_ipv6_protocol_tcp, set_pfilter_ipv6_sport, none, "tcp", "TCP", 5, 3);

/* protocol udp :  which[4] == 2 */
KW_NODE_WHICH(set_pfilter_ipv6_protocol_udp, set_pfilter_ipv6_sport, set_pfilter_ipv6_protocol_tcp, "udp", "UDP", 5, 2);

/* protocol icmp :  which[4] == 1 */
KW_NODE_WHICH(set_pfilter_ipv6_protocol_icmp, set_pfilter_eol, set_pfilter_ipv6_protocol_udp, "icmp6", "ICMPv6", 5, 1);

/* protocol :  which[3] == 1 */
KW_NODE_WHICH(set_pfilter_ipv6_protocol, set_pfilter_ipv6_protocol_icmp, set_pfilter_ipv6_sport, "protocol", "Protocol", 4, 1);

/* dst-ip : string[1]  */
VALUE_NODE(set_pfilter_ipv6_dst_value, set_pfilter_ipv6_protocol, none, "ipv6 address/prefix value <1-128>", 2, STR);

/* dst-ip :  which[2] == 1 */
KW_NODE_WHICH(set_pfilter_ipv6_dst, set_pfilter_ipv6_dst_value, set_pfilter_ipv6_protocol, "dst-ip6", "Destination IPv6", 3, 1);

/* src-ip : string[0]  */
VALUE_NODE(set_pfilter_ipv6_src_value, set_pfilter_ipv6_dst, none, "ipv6 address/prefix value <1-128>", 1, STR);

/* src-ip :  which[1] == 1 */
KW_NODE_WHICH(set_pfilter_ipv6_src, set_pfilter_ipv6_src_value, set_pfilter_ipv6_dst, "src-ip6", "Source IPv6", 2, 1);

/* Rule ID : number[1] = x */
VALUE_NODE(set_pfilter_ipv6_rule_id, set_pfilter_ipv6_src, set_pfilter_ipv6_src, "Rule ID", 2, NUM);

KW_NODE_WHICH(unset_pfilter_ipv6_dport, unset_pfilter_eol, unset_pfilter_eol, "dst-port", "Destination port", 7, 1);
KW_NODE_WHICH(unset_pfilter_ipv6_sport, unset_pfilter_ipv6_dport, unset_pfilter_ipv6_dport, "src-port", "Source port", 6, 1);
KW_NODE_WHICH(unset_pfilter_ipv6_protocol, unset_pfilter_ipv6_sport, unset_pfilter_ipv6_sport, "protocol", "Protocol", 4, 1);
KW_NODE_WHICH(unset_pfilter_ipv6_dst, unset_pfilter_ipv6_protocol, unset_pfilter_ipv6_protocol, "dst-ip6", "Destination IPv6", 3, 1);
KW_NODE_WHICH(unset_pfilter_ipv6_src, unset_pfilter_ipv6_dst, unset_pfilter_ipv6_dst, "src-ip6", "Source IPv6", 2, 1);
VALUE_NODE(unset_pfilter_ipv6_rule_id, unset_pfilter_ipv6_src, none, "Rule ID", 2, NUM);
TEST_UNSET(unset_pfilter_ipv6, unset_pfilter_ipv6_rule_id, set_pfilter_ipv6_rule_id);


KW_NODE(set_pfilter_ipv6_rule, unset_pfilter_ipv6, none, "rule", "Rule");

/* pfilter index <1-16> : number[0] = <1-16> */
VALUE_NODE(set_pfilter_ipv6_id, set_pfilter_ipv6_rule, none, "pfilter index <1-16>", 1, NUM);

/* ipv6 : which[0] == 2 */
KW_NODE_WHICH(set_pfilter_ipv6, set_pfilter_ipv6_id, none, "ipv6", "IPv6", 1, 2);

/* ------ */

/* dst port :  number[3] = x */
VALUE_NODE(set_pfilter_ipv4_dport_value, set_pfilter_eol, none, "Destination port", 4, NUM);

/* protocol tcp :  which[6] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4_dport, set_pfilter_ipv4_dport_value, set_pfilter_eol, "dst-port", "Destination port", 7, 1);

/* src port value :  number[2] = x */
VALUE_NODE(set_pfilter_ipv4_sport_value, set_pfilter_ipv4_dport, none, "Source port", 3, NUM);

/* src port :  which[5] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4_sport, set_pfilter_ipv4_sport_value, set_pfilter_ipv4_dport, "src-port", "Source port", 6, 1);

/* protocol tcp :  which[4] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4_protocol_tcp, set_pfilter_ipv4_sport, none, "tcp", "TCP", 5, 3);

/* protocol udp :  which[4] == 2 */
KW_NODE_WHICH(set_pfilter_ipv4_protocol_udp, set_pfilter_ipv4_sport, set_pfilter_ipv4_protocol_tcp, "udp", "UDP", 5, 2);

/* protocol icmp :  which[4] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4_protocol_icmp, set_pfilter_eol, set_pfilter_ipv4_protocol_udp, "icmp", "ICMP", 5, 1);

/* protocol :  which[3] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4_protocol, set_pfilter_ipv4_protocol_icmp, set_pfilter_ipv4_sport, "protocol", "Protocol", 4, 1);

/* dst-ip : string[1]   */
VALUE_NODE(set_pfilter_ipv4_dst_value, set_pfilter_ipv4_protocol, none, "ipv4 address/mask value <1-32>", 2, STR);

/* dst-ip :  which[2] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4_dst, set_pfilter_ipv4_dst_value, set_pfilter_ipv4_protocol, "dst-ip", "Destination IP", 3, 1);

/* src-ip : string[0]  */
VALUE_NODE(set_pfilter_ipv4_src_value, set_pfilter_ipv4_dst, none, "ipv4 address/mask value <1-32>", 1, STR);

/* src-ip :  which[1] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4_src, set_pfilter_ipv4_src_value, set_pfilter_ipv4_dst, "src-ip", "Source IP", 2, 1);


/* Rule ID : number[1] = x */
VALUE_NODE(set_pfilter_ipv4_rule_id, set_pfilter_ipv4_src, set_pfilter_ipv4_src, "Rule ID", 2, NUM);


KW_NODE_WHICH(unset_pfilter_ipv4_dport, unset_pfilter_eol, unset_pfilter_eol, "dst-port", "Destination port", 7, 1);
KW_NODE_WHICH(unset_pfilter_ipv4_sport, unset_pfilter_ipv4_dport, unset_pfilter_ipv4_dport, "src-port", "Source port", 6, 1);
KW_NODE_WHICH(unset_pfilter_ipv4_protocol, unset_pfilter_ipv4_sport, unset_pfilter_ipv4_sport, "protocol", "Protocol", 4, 1);
KW_NODE_WHICH(unset_pfilter_ipv4_dst, unset_pfilter_ipv4_protocol, unset_pfilter_ipv4_protocol, "dst-ip", "Destination IP", 3, 1);
KW_NODE_WHICH(unset_pfilter_ipv4_src, unset_pfilter_ipv4_dst, unset_pfilter_ipv4_dst, "src-ip", "Source IP", 2, 1);
VALUE_NODE(unset_pfilter_ipv4_rule_id, unset_pfilter_ipv4_src, none, "Rule ID", 2, NUM);
TEST_UNSET(unset_pfilter_ipv4, unset_pfilter_ipv4_rule_id, set_pfilter_ipv4_rule_id);

KW_NODE(set_pfilter_ipv4_rule, unset_pfilter_ipv4, none, "rule", "Rule");

/* pfilter index <1-16> : number[0] = <1-16> */
VALUE_NODE(set_pfilter_ipv4_id, set_pfilter_ipv4_rule, none, "pfilter index <1-16>", 1, NUM);

/* ip : which[0] == 1 */
KW_NODE_WHICH(set_pfilter_ipv4, set_pfilter_ipv4_id, set_pfilter_ipv6, "ip", "IPv4", 1, 1);
KW_NODE(set_pfilter, set_pfilter_ipv4, none, "pfilter", "Packet filter");

static int show_pfilter_debug(cmd_blk_t *cbt)
{
    unsigned int uiIndex;
    unsigned int uiIPType  = cbt->which[0];

    if ((cbt->number[0] >=1) && (cbt->number[0] <= 16))
    {
        uiIndex = cbt->number[0];
    }
    else
    {
        printf("pfilter index <1 - 16>\n");
        return 0;
    }

    Pfilter_GetDebug(uiIndex, uiIPType);
    return 0;
}

EOL_NODE(show_pfilter_debug_eol, show_pfilter_debug);

static int show_pfilter_cli(cmd_blk_t *cbt)
{
    unsigned int uiIndex;
    unsigned int uiIPType  = cbt->which[0];
    unsigned int uiRuleID  = cbt->number[1];

    if ((cbt->number[0] >=1) && (cbt->number[0] <= 16))
    {
        uiIndex = cbt->number[0];
    }
    else
    {
        printf("pfilter index <1 - 16>\n");
        return 0;
    }

    if (1 == cbt->which[0])
    {
        uiIPType = IPPROTO_IP;
    }
    else if (2 == cbt->which[0])
    {
        uiIPType = IPPROTO_IPV6;
    }

    Pfilter_Get(uiIndex, uiIPType, uiRuleID);
    return 0;
}

EOL_NODE(show_pfilter_cli_eol, show_pfilter_cli);
VALUE_NODE(show_pfilter_rule_id, show_pfilter_cli_eol, none, "Rule ID", 2, NUM);
//KW_NODE(show_pfilter_rule_all, show_pfilter_cli_eol, show_pfilter_rule_id, "all", "all");
KW_NODE(show_pfilter_rule, show_pfilter_rule_id, show_pfilter_cli_eol, "rule", "rule");
KW_NODE(show_pfilter_debug, show_pfilter_debug_eol, show_pfilter_rule, "debug", "debug");
VALUE_NODE(show_pfilter_id, show_pfilter_debug, none, "pfilter index <1-16>", 1, NUM);
KW_NODE_WHICH(show_pfilter_ipv6,  show_pfilter_id, none, "ipv6", "IPv6", 1, 2);
KW_NODE_WHICH(show_pfilter_ipv4,  show_pfilter_id, show_pfilter_ipv6, "ip", "IPv4", 1, 1);
KW_NODE(show_pfilter, show_pfilter_ipv4, none, "pfilter", "packet filter");

static int debug_pfilter_cli(cmd_blk_t *cbt)
{
    unsigned int uiIndex;
    unsigned int uiDbgType;
    unsigned int uiIPType;

    if ((cbt->number[0] >=1) && (cbt->number[0] <= 16))
    {
        uiIndex = cbt->number[0];
    }
    else
    {
        printf("pfilter index <1 - 16>\n");
        return 0;
    }

    if (1 == cbt->which[0])
    {
        uiIPType = IPPROTO_IP;
    }
    else if (2 == cbt->which[0])
    {
        uiIPType = IPPROTO_IPV6;
    }

    if (1 == cbt->which[1])
    {
        uiDbgType = PFILTER_DEBUG_PACKET;
    }

    if (cbt->mode == MODE_DO)
    {
        Pfilter_SetDebug(uiIndex, uiIPType, uiDbgType, BOOL_FALSE);
        printf("Pfilter index %d debug packet is enabled\n", uiIndex);
    }
    else
    {
        Pfilter_SetDebug(uiIndex, uiIPType, uiDbgType, BOOL_TRUE);
        printf("Pfilter index %d debug packet is disabled\n", uiIndex);
    }

    return 0;
}

EOL_NODE(debug_pfilter_eol, debug_pfilter_cli);
KW_NODE_WHICH(debug_pfilter_type, debug_pfilter_eol, none, "packet", "packet", 2, 1);
VALUE_NODE(debug_pfilter_id, debug_pfilter_type, none, "pfilter index <1-16>", 1, NUM);
KW_NODE_WHICH(debug_pfilter_ipv6, debug_pfilter_id, none, "ipv6", "ipv6", 1, 2);
KW_NODE_WHICH(debug_pfilter_ipv4, debug_pfilter_id, debug_pfilter_ipv6, "ip", "ipv4", 1, 1);
KW_NODE(debug_pfilter, debug_pfilter_ipv4, none, "pfilter", "packet filter");

void Pfilter_Cli_Init()
{
    add_set_cmd(&cnode(set_pfilter));
    add_get_cmd(&cnode(show_pfilter));
    add_debug_cmd(&cnode(debug_pfilter));
    return 0;
}

