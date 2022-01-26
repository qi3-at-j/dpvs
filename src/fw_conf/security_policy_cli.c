#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "fw_lib.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_cli.h"
#include "fw_conf/security_policy_conf.h"
#include "fw_conf/security_policy_cli.h"

#include "../access_control/error.h"
#include "../access_control/secpolicy_common.h"
#include "../access_control/secpolicy.h"

/* set secpolicy cmd */
static int set_secpolicy_vpc_subnet_cli(cmd_blk_t *cbt)
{
    UINT uiVxlanID;
    CHAR *pc;
    IP_ADDR_MASK_S stIPAddrMask;

    uiVxlanID = cbt->number[0];

    if (1 == cbt->which[0])
    {

        if (true != FWLIB_Check_IPv4AndMask_IsLegal(cbt->string[0]))
        {
            return 0;
        }

        stIPAddrMask.stIPAddr.uiIPType = IPPROTO_IP;
        
        if (strchr(cbt->string[0], '/'))
        {
            /* example, 1.1.1.1/24 */
            pc = strtok(cbt->string[0], "/");
            inet_pton(AF_INET, pc, &stIPAddrMask.stIPAddr._ip_data.stIP4Addr);
            pc = strtok(NULL, "/");
            stIPAddrMask.uiIPMaskLen = atoi(pc);
        }
        else
        {
            /* example, 1.1.1.1 */
            inet_pton(AF_INET, cbt->string[0], &stIPAddrMask.stIPAddr._ip_data.stIP4Addr);
            stIPAddrMask.uiIPMaskLen = 32;
        }
    }
    else if (2 == cbt->which[0])
    {
        if (true != FWLIB_Check_IPv6AndPrefix_IsLegal(cbt->string[0]))
        {
            return 0;
        }
        
        stIPAddrMask.stIPAddr.uiIPType = IPPROTO_IPV6;
        
        if (strchr(cbt->string[0], '/'))
        {
            /* example, 1::2/64 */
            pc = strtok(cbt->string[0], "/");
            inet_pton(AF_INET6, pc, &stIPAddrMask.stIPAddr._ip_data.stIP6Addr);
            pc = strtok(NULL, "/");
            stIPAddrMask.uiIPMaskLen = atoi(pc);
        }
        else
        {
            /* example, 1::2 */
            inet_pton(AF_INET6, cbt->string[0], &stIPAddrMask.stIPAddr._ip_data.stIP6Addr);
            stIPAddrMask.uiIPMaskLen = 128;
        }
    }

    if (cbt->mode == MODE_DO)
    {
        (void)SecPolicy_VPCFlow_AddPubIP(uiVxlanID, &stIPAddrMask);
        tyflow_cmdline_printf(cbt->cl, "vrf:%d set ip/mask:%s/%d\n", cbt->number[0], cbt->string[0], stIPAddrMask.uiIPMaskLen);
    }
    else if (cbt->mode == MODE_UNDO)
    {
        (void)SecPolicy_VPCFlow_DelPubIP(uiVxlanID, &stIPAddrMask);
        tyflow_cmdline_printf(cbt->cl, "vrf:%d unset ip/mask:%s/%d\n", cbt->number[0], cbt->string[0], stIPAddrMask.uiIPMaskLen);
    }
    
    
    return;
}


/* set secpolicy cmd */
static int set_secpolicy_ext_subnet_cli(cmd_blk_t *cbt)
{
    UINT uiVxlanID;
    CHAR *pc;
    IP_ADDR_S stIPAddr;

    if (1 == cbt->which[0])
    {

        if (true != FWLIB_Check_IPv4AndMask_IsLegal(cbt->string[0]))
        {
            return 0;
        }

        stIPAddr.uiIPType = IPPROTO_IP;
        
        if (strchr(cbt->string[0], '/'))
        {
            /* example, 1.1.1.1/24 */
            pc = strtok(cbt->string[0], "/");
            inet_pton(AF_INET, pc, &stIPAddr._ip_data.stIP4Addr);
        }
        else
        {
            /* example, 1.1.1.1 */
            inet_pton(AF_INET, cbt->string[0], &stIPAddr._ip_data.stIP4Addr);
        }
    }
    else if (2 == cbt->which[0])
    {
        if (true != FWLIB_Check_IPv6AndPrefix_IsLegal(cbt->string[0]))
        {
            return 0;
        }
        
        stIPAddr.uiIPType = IPPROTO_IPV6;
        
        if (strchr(cbt->string[0], '/'))
        {
            /* example, 1::2/64 */
            pc = strtok(cbt->string[0], "/");
            inet_pton(AF_INET6, pc, &stIPAddr._ip_data.stIP6Addr);
        }
        else
        {
            /* example, 1::2 */
            inet_pton(AF_INET6, cbt->string[0], &stIPAddr._ip_data.stIP6Addr);
        }
    }

    if (cbt->mode == MODE_DO)
    {
        (void)SecPolicy_ExtFlow_AddPubIP(cbt->string[2], &stIPAddr);
        tyflow_cmdline_printf(cbt->cl, "tenant:%s set ip:%s\n", cbt->string[2], cbt->string[0]);
    }
    else if (cbt->mode == MODE_UNDO)
    {
        (void)SecPolicy_ExtFlow_DelPubIP(cbt->string[2], &stIPAddr);
        tyflow_cmdline_printf(cbt->cl, "tenant:%s unset ip:%s\n", cbt->string[2], cbt->string[0]);
    }
    
    
    return;
}


EOL_NODE(set_vpc_subnet_eol, set_secpolicy_vpc_subnet_cli);
EOL_NODE(set_ext_subnet_eol, set_secpolicy_ext_subnet_cli);

bool _Check_AppID_IsLegal(char *pcStr)
{
    int i = 0, ilen = strlen(pcStr);
    bool b = true;
    char *pc = pcStr;

    if (0 == pcStr)
    {
        return false;
    }

    while(i < ilen)
    {
        if (!isdigit(*(pc+i)) && (*(pc+i) != '-'))
        {
            b = false;
            break;
        }
        i++;
    }
    return b;
}


static int set_rule_cli(cmd_blk_t *cbt)
{
    unsigned int ui = 0;
    char *pc;
    SECPOLICY_RULE_CFG_S stRuleCfg;
    BOOL_T bIsUnset = BOOL_FALSE;
    unsigned char szApp[1024] = {0};

    memset(&stRuleCfg, 0, sizeof(stRuleCfg));

    if (0 != cbt->number[0])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_VPCBODER;
        stRuleCfg.uiVxlanID = cbt->number[0];
    }
    else if (0 != cbt->string[2])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_EXTBODER;
        strlcpy(stRuleCfg.szTenantID, cbt->string[2], TENANT_ID_MAX);
    }
    stRuleCfg.uiRuleID  = cbt->number[1];
    stRuleCfg.enActionType = SECPOLICY_ACTION_DENY;
    stRuleCfg.stL4Info.ucProtocol = INVALID_TCPIP_PROTOCOL_ID;

    if (1 == cbt->which[0])
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    if (1 == cbt->which[1])
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    }
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }

    
    /* action which[2] == 1 */
    if (1 == cbt->which[2])
    {
        /* action pass which[3] == 1*/
        if (1 == cbt->which[3])
        {
            stRuleCfg.enActionType = SECPOLICY_ACTION_PERMIT;
        }
        /* action drop which[3] == 2*/
        else if (2 == cbt->which[3])
        {
            stRuleCfg.enActionType = SECPOLICY_ACTION_DENY;
        }

        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_ACTION;
    }

    /* sip which[4] == 1*/
    if (1 == cbt->which[4])
    {
        /* ip/mask string[0] = 1 */
        if (IPPROTO_IP == stRuleCfg.uiIPType)
        {
            if (true != FWLIB_Check_IPv4AndMask_IsLegal(cbt->string[0]))
            {
                return 0;
            }

            stRuleCfg.stSrc.enIPType = MULTITYPE_SINGLEIP;
            stRuleCfg.stSrc._multi_ip_type = IPPROTO_IP;

            if (strchr(cbt->string[0], '/'))
            {
                /* example, 1.1.1.1/24 */
                pc = strtok(cbt->string[0], "/");
                inet_pton(AF_INET, pc, &stRuleCfg.stSrc._multi_ip.stIPAddr._ip_data.stIP4Addr);
                pc = strtok(NULL, "/");
                stRuleCfg.stSrc.uiIPMaskLen = atoi(pc);
            }
            else
            {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, cbt->string[0], &stRuleCfg.stSrc._multi_ip.stIPAddr._ip_data.stIP4Addr);
                stRuleCfg.stSrc.uiIPMaskLen = 32;
            }
        }
        /* ip6/prefix string[0] = 1 */
        else if (IPPROTO_IPV6 == stRuleCfg.uiIPType)
        {
            if (true != FWLIB_Check_IPv6AndPrefix_IsLegal(cbt->string[0]))
            {
                return 0;
            }

            stRuleCfg.stSrc.enIPType = MULTITYPE_SINGLEIP;
            stRuleCfg.stSrc._multi_ip_type = IPPROTO_IPV6;
            if (strchr(cbt->string[0], '/'))
            {
                /* example, 1::2/64 */
                pc = strtok(cbt->string[0], "/");
                inet_pton(AF_INET6, pc, &stRuleCfg.stSrc._multi_ip.stIPAddr._ip_data.stIP6Addr);
                pc = strtok(NULL, "/");
                stRuleCfg.stSrc.uiIPMaskLen = atoi(pc);
            }
            else
            {
                /* example, 1::2 */
                inet_pton(AF_INET6, cbt->string[0], &stRuleCfg.stSrc._multi_ip.stIPAddr._ip_data.stIP6Addr);
                stRuleCfg.stSrc.uiIPMaskLen = 128;
            }
        }

        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SIP;
    }

    /* dip which[5] == 1*/
    if (1 == cbt->which[5])
    {
        /* ip/mask string[1] */
        if (IPPROTO_IP == stRuleCfg.uiIPType)
        {
            if (true != FWLIB_Check_IPv4AndMask_IsLegal(cbt->string[1]))
            {
                return 0;
            }

            stRuleCfg.stDst.enIPType = MULTITYPE_SINGLEIP;
            stRuleCfg.stDst._multi_ip_type = IPPROTO_IP;
            if (strchr(cbt->string[1], '/'))
            {
                /* example, 1.1.1.1/24 */
                pc = strtok(cbt->string[1], "/");
                inet_pton(AF_INET, pc, &stRuleCfg.stDst._multi_ip.stIPAddr._ip_data.stIP4Addr);
                pc = strtok(NULL, "/");
                stRuleCfg.stDst.uiIPMaskLen = atoi(pc);
            }
            else
            {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, cbt->string[1], &stRuleCfg.stDst._multi_ip.stIPAddr._ip_data.stIP4Addr);
                stRuleCfg.stDst.uiIPMaskLen = 32;
            }
        }
        /* ip6/prefix string[1] */
        else if (IPPROTO_IPV6 == stRuleCfg.uiIPType)
        {
            if (true != FWLIB_Check_IPv6AndPrefix_IsLegal(cbt->string[1]))
            {
                return 0;
            }

            stRuleCfg.stDst.enIPType = MULTITYPE_SINGLEIP;
            stRuleCfg.stDst._multi_ip_type = IPPROTO_IPV6;
            if (strchr(cbt->string[1], '/'))
            {
                /* example, 1::2/64 */
                pc = strtok(cbt->string[1], "/");
                inet_pton(AF_INET6, pc, &stRuleCfg.stDst._multi_ip.stIPAddr._ip_data.stIP6Addr);
                pc = strtok(NULL, "/");
                stRuleCfg.stDst.uiIPMaskLen = atoi(pc);
            }
            else
            {
                /* example, 1::2 */
                inet_pton(AF_INET6, cbt->string[1], &stRuleCfg.stDst._multi_ip.stIPAddr._ip_data.stIP6Addr);
                stRuleCfg.stDst.uiIPMaskLen = 128;
            }
        }

        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DIP;
    }

    /* service which[6] == 1 */
    if (1 == cbt->which[6])
    {
        /* service tcp which[7] == 1 */
        /* service udp which[7] == 2 */
        if ((1 == cbt->which[7]) || (2 == cbt->which[7]))
        {
            stRuleCfg.stL4Info.ucProtocol = (1 == cbt->which[7]) ? IPPROTO_TCP : IPPROTO_UDP;
            /* sport which[8] == 1 */
            if (1 == cbt->which[8])
            {
                /* sport begin value number[2] */
                stRuleCfg.stL4Info.stPortRange.stSRange.usSPort = cbt->number[2];
                stRuleCfg.stL4Info.stPortRange.stSRange.usDPort = cbt->number[2];
                if (cbt->number[3])
                {
                    /* sport end value number[3] */
                    stRuleCfg.stL4Info.stPortRange.stSRange.usDPort = cbt->number[3];
                }
                stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SPORT;
            }
                
            /* dport which[9] == 1 */
            if (1 == cbt->which[9])
            {
                /* sport begin value number[4] */
                stRuleCfg.stL4Info.stPortRange.stDRange.usSPort = cbt->number[4];
                stRuleCfg.stL4Info.stPortRange.stDRange.usDPort = cbt->number[4];
                if (cbt->number[3])
                {
                    /* sport end value number[5] */
                    stRuleCfg.stL4Info.stPortRange.stDRange.usDPort = cbt->number[5];
                }
                stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DPORT;
            }
            
        }
        /* service icmp which[7] == 3 */
        else if (3 == cbt->which[7])
        {
            if (IPPROTO_IP == stRuleCfg.uiIPType)
            {
                stRuleCfg.stL4Info.ucProtocol = IPPROTO_ICMP;
            }
            else if (IPPROTO_IPV6 == stRuleCfg.uiIPType)
            {
                stRuleCfg.stL4Info.ucProtocol = IPPROTO_ICMPV6;
            }

            /* icmp type which[10] == 1 */
            if (1 == cbt->which[10])
            {
                /* icmp type value number[2] */
                stRuleCfg.stL4Info.stIcmp.ucType = cbt->number[2];
                stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE;
            }
            
            /* icmp code which[11] == 1 */
            if (1 == cbt->which[11])
            {
                /* icmp code value number[3] */
                stRuleCfg.stL4Info.stIcmp.ucCode = cbt->number[3];
                stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE;
            }
        }

        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SERVICE;
    }

    /* app which[16] == 1 */
    if (1 == cbt->which[16])
    {
        memcpy(szApp, cbt->string[3],strlen(cbt->string[3]));
        if (_Check_AppID_IsLegal(szApp))
        {
            ui = 0;
            pc = strtok(szApp, ",");
            while(NULL != pc && ui<SECPOLICY_APP_NUM_MAX)
            {
                stRuleCfg.szAppID[ui++] = atoi(pc);
                pc = strtok(NULL, ",");
            }
            stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_APP;
        }
        else
        {
            printf("app id is illegal, it should be for example 10-15-20\n");
            return 0;
        }

    }
            
    /* status which[12] == 1*/
    if (1 == cbt->which[12])
    {
        /* status enable which[13] == 1*/
        if (1 == cbt->which[13])
        {
            stRuleCfg.bIsEnable = BOOL_TRUE;
        }
        /* status disable which[13] == 2*/
        else if (2 == cbt->which[13])
        {
            stRuleCfg.bIsEnable = BOOL_FALSE;
        }

        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_STATUS;
    }
    
    /* statistics which[14] == 1*/
    if (1 ==  cbt->which[14])
    {
        /* statistics enable which[15] == 1*/
        if (1 == cbt->which[15])
        {
            stRuleCfg.bIsStatistics = BOOL_TRUE;
        }
        /* statistics disable which[15] == 2*/
        else if (2 == cbt->which[15])
        {
            stRuleCfg.bIsStatistics = BOOL_FALSE;
        }

        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_STATISTICS;
    }

    /* description which[17] == 1 */
    if (1 == cbt->which[17])
    {
        strlcpy(stRuleCfg.szDescInfo, cbt->string[4], (SECPOLICY_RULE_DECRIPTION_MAX+1));
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DESC;
    }

    if (0 == stRuleCfg.uiKeyMask)
    {
        (VOID)SecPolicy_Conf_AddRule(&stRuleCfg);
    }
    else
    {
        (VOID)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);
    }

    return 0;
}

static int unset_rule_cli(cmd_blk_t *cbt)
{
    char *pc;
    SECPOLICY_RULE_CFG_S stRuleCfg;
    BOOL_T bIsUnset = BOOL_FALSE;

    memset(&stRuleCfg, 0, sizeof(stRuleCfg));

    if (0 != cbt->number[0])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_VPCBODER;
        stRuleCfg.uiVxlanID = cbt->number[0];
    }
    else if (0 != cbt->string[2])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_EXTBODER;
        strlcpy(stRuleCfg.szTenantID, cbt->string[2], TENANT_ID_MAX);
    }
    stRuleCfg.uiRuleID  = cbt->number[1];
    stRuleCfg.enActionType = SECPOLICY_ACTION_DENY;
    stRuleCfg.stL4Info.ucProtocol = INVALID_TCPIP_PROTOCOL_ID;

    if (1 == cbt->which[0])
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    if (1 == cbt->which[1])
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    }
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }

        
    /* action which[2] == 1 */
    if (1 == cbt->which[2])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_ACTION;
    }

    /* sip which[3] == 1*/
    if (1 == cbt->which[3])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SIP;
    }

    /* dip which[4] == 1*/
    if (1 == cbt->which[4])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DIP;
    }

    /* service which[5] == 1 */
    if (1 == cbt->which[5])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SERVICE;
    }
            
    /* status which[6] == 1*/
    if (1 == cbt->which[6])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_STATUS;
    }
    
    /* statistics which[7] == 1*/
    if (1 ==  cbt->which[7])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_STATISTICS;
    }

    /* app which[8] == 1*/
    if (1 ==  cbt->which[8])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_APP;
    }

    /* desc which[9] == 1*/
    if (1 ==  cbt->which[8])
    {
        stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DESC;
    }

    if (0 == stRuleCfg.uiKeyMask)
    {
        (VOID)SecPolicy_Conf_DelRule(&stRuleCfg);
    }
    else
    {
        (VOID)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_TRUE);
    }

    return 0;
}

static int set_fw_type_cli(cmd_blk_t *cbt)
{
    //tyflow_cmdline_printf(cbt->cl, "fw type:%s\n", cbt->which[0]==1 ? "ExtFwType":"VPCFwType");
    if (MODE_DO == cbt->mode)
    {
        if (1 == cbt->which[0])
        {
            SecPolicy_SetFwType(SECPOLICY_TYPE_EXTBODER);
        }
        else if (2 == cbt->which[0])
        {
            SecPolicy_SetFwType(SECPOLICY_TYPE_VPCBODER);
        }
    }
    else if (MODE_UNDO == cbt->mode)
    {
        SecPolicy_SetFwType(SECPOLICY_TYPE_VPCBODER);
    }

    return 0;
}

static int set_secpolicy_status_cli(cmd_blk_t *cbt)
{
    if (cbt->mode == MODE_DO)
    {
        if (1 == cbt->which[0])
        {
            g_bIsSecPolicyStatusOn = BOOL_TRUE;
            printf("Enable SecPolicy.\n");
        }
        else if (2 == cbt->which[0])
        {
            g_bIsSecPolicyStatusOn = BOOL_FALSE;
            printf("Disable SecPolicy.\n");
        }
        
    }
    else
    {
        g_bIsSecPolicyStatusOn = BOOL_FALSE;
        printf("Disable SecPolicy.\n");
    }

    return;
}

EOL_NODE(set_secpolicy_status_eol, set_secpolicy_status_cli);
KW_NODE_WHICH(set_secpolicy_status_drop,  set_secpolicy_status_eol, none, "disable", "Disable secpolicy", 1, 2);
KW_NODE_WHICH(set_secpolicy_status_pass,  set_secpolicy_status_eol, set_secpolicy_status_drop, "enable", "Enable secpolicy(default)", 1, 1);
TEST_UNSET(unset_secpolicy_status_pass, set_secpolicy_status_eol, set_secpolicy_status_pass);


EOL_NODE(set_rule_eol, set_rule_cli);
EOL_NODE(unset_rule_eol, unset_rule_cli);
EOL_NODE(set_fw_type_eol, set_fw_type_cli);

/* description str string[4] */
VALUE_NODE(set_secpolicy_ipv6_description_str, set_rule_eol, none, "description <1-127>", 5, STR);

/* description which[17] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_description, set_secpolicy_ipv6_description_str, set_rule_eol, "desc", "description", 18, 1);

/* statistics disable which[15] == 2*/
KW_NODE_WHICH(set_secpolicy_ipv6_statistics_off, set_secpolicy_ipv6_description, none, "disable", "disable statistics(default)", 16, 2);

/* statistics enable which[15] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_statistics_on,  set_secpolicy_ipv6_description, set_secpolicy_ipv6_statistics_off, "enable", "enable statistics", 16, 1);

/* statistics which[14] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_statistics, set_secpolicy_ipv6_statistics_on, set_secpolicy_ipv6_description, "statistics", "packet statistics", 15, 1);

/* status disable which[13] == 2*/
KW_NODE_WHICH(set_secpolicy_ipv6_status_disable, set_secpolicy_ipv6_statistics, none, "disable", "disable rule(default)", 14, 2);

/* status enable which[13] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_status_enable,  set_secpolicy_ipv6_statistics, set_secpolicy_ipv6_status_disable, "enable", "enable rule", 14, 1);

/* status which[12] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_status, set_secpolicy_ipv6_status_enable, set_secpolicy_ipv6_statistics, "status", "status of rule", 13, 1);

/* app str string[3] */
VALUE_NODE(set_secpolicy_ipv6_app_str, set_secpolicy_ipv6_status, none, "application id <number>, example, 10,15.20", 4, STR);

/* app which[16] */
KW_NODE_WHICH(set_secpolicy_ipv6_app, set_secpolicy_ipv6_app_str, set_secpolicy_ipv6_status, "app", "application", 17, 1);

/* icmp code value number[3] */
VALUE_NODE(set_secpolicy_ipv6_icmp_code_num, set_secpolicy_ipv6_app, none, "code", 4, NUM);

/* icmp code which[11] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv6_icmp_code, set_secpolicy_ipv6_icmp_code_num, set_secpolicy_ipv6_app, "code", "icmp code", 12, 1);

/* icmp type value number[2] */
VALUE_NODE(set_secpolicy_ipv6_icmp_type_num, set_secpolicy_ipv6_icmp_code, none, "type", 3, NUM);

/* icmp type which[10] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv6_icmp_type, set_secpolicy_ipv6_icmp_type_num, set_secpolicy_ipv6_icmp_code, "type", "icmp type", 11, 1);

/* dport end value number[5] */
VALUE_NODE(set_secpolicy_ipv6_dst_port_value2, set_secpolicy_ipv6_app, none, "port number; for example, 80", 6, NUM);

KW_NODE(set_secpolicy_ipv6_dst_port_to, set_secpolicy_ipv6_dst_port_value2, set_secpolicy_ipv6_app, "to", "for example, 10 to 100");

/* dport begin value number[4] */
VALUE_NODE(set_secpolicy_ipv6_dst_port_value1, set_secpolicy_ipv6_dst_port_to, none, "port number; for example, 80", 5, NUM);

/* dport which[9] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv6_dst_port, set_secpolicy_ipv6_dst_port_value1, set_secpolicy_ipv6_app, "dst-port", "destination port, for example, 10 to 100 or 80", 10, 1);

/* sport end value number[3] */
VALUE_NODE(set_secpolicy_ipv6_src_port_value2, set_secpolicy_ipv6_dst_port, none, "port number; for example, 80", 4, NUM);

KW_NODE(set_secpolicy_ipv6_src_port_to, set_secpolicy_ipv6_src_port_value2, set_secpolicy_ipv6_dst_port, "to", "for example, 10 to 100");

/* sport begin value number[2] */
VALUE_NODE(set_secpolicy_ipv6_src_port_value1, set_secpolicy_ipv6_src_port_to, none, "port number, for example, 80", 3, NUM);

/* sport which[8] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv6_src_port, set_secpolicy_ipv6_src_port_value1, set_secpolicy_ipv6_dst_port, "src-port", "source port, for example, 10 to 100 or 80", 9, 1);

/* service icmp which[7] == 3 */
KW_NODE_WHICH(set_secpolicy_ipv6_service_icmp, set_secpolicy_ipv6_icmp_type, none, "icmpv6", "icmpv6", 8, 3);

/* service udp which[7] == 2 */
KW_NODE_WHICH(set_secpolicy_ipv6_service_udp, set_secpolicy_ipv6_src_port, set_secpolicy_ipv6_service_icmp, "udp", "udp", 8, 2);

/* service tcp which[7] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv6_service_tcp, set_secpolicy_ipv6_src_port, set_secpolicy_ipv6_service_udp, "tcp", "tcp", 8, 1);
    
/* service which[6] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv6_service, set_secpolicy_ipv6_service_tcp, set_secpolicy_ipv6_app, "service", "service", 7, 1);

/* ip6/prefix string[1] */
VALUE_NODE(set_secpolicy_ipv6_dst_value, set_secpolicy_ipv6_service, none, "ipv6 address/prefix value <1-128>", 2, STR);
    
/* dip6 which[5] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_dst, set_secpolicy_ipv6_dst_value, set_secpolicy_ipv6_service, "dst-ip6", "destination ipv6", 6, 1);
    
/* ip6/prefix string[0] */
VALUE_NODE(set_secpolicy_ipv6_src_value, set_secpolicy_ipv6_dst, none, "ipv6 address/prefix value <1-128>", 1, STR);
    
/* sip6 which[4] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_src, set_secpolicy_ipv6_src_value, set_secpolicy_ipv6_dst, "src-ip6", "source ipv6", 5, 1);

/* action drop which[3] == 2*/
KW_NODE_WHICH(set_secpolicy_ipv6_action_drop,  set_secpolicy_ipv6_src, none, "drop", "drop(default)", 4, 2);

/* action pass which[3] == 1*/
KW_NODE_WHICH(set_secpolicy_ipv6_action_pass,  set_secpolicy_ipv6_src, set_secpolicy_ipv6_action_drop, "pass", "pass", 4, 1);

/* action which[2] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv6_action, set_secpolicy_ipv6_action_pass, set_secpolicy_ipv6_src, "action", "action of rule", 3, 1);


/* unset part */
KW_NODE_WHICH(unset_secpolicy_ipv6_description, unset_rule_eol, unset_rule_eol, "desc", "description", 10, 1);
KW_NODE_WHICH(unset_secpolicy_ipv6_statistics, unset_secpolicy_ipv6_description, unset_secpolicy_ipv6_description, "statistics", "packet statistics", 8, 1);
KW_NODE_WHICH(unset_secpolicy_ipv6_status, unset_secpolicy_ipv6_statistics, unset_secpolicy_ipv6_statistics, "status", "status of rule", 7, 1);
KW_NODE_WHICH(unset_secpolicy_ipv6_app, unset_secpolicy_ipv6_status, unset_secpolicy_ipv6_status, "app", "application", 9, 1);
KW_NODE_WHICH(unset_secpolicy_ipv6_service, unset_secpolicy_ipv6_app, unset_secpolicy_ipv6_app, "service", "service", 6, 1);
KW_NODE_WHICH(unset_secpolicy_ipv6_dst_ip, unset_secpolicy_ipv6_service, unset_secpolicy_ipv6_service, "dst-ip6", "destination IP", 5, 1);
KW_NODE_WHICH(unset_secpolicy_ipv6_src_ip, unset_secpolicy_ipv6_dst_ip, unset_secpolicy_ipv6_dst_ip, "src-ip6", "source IP", 4, 1);
KW_NODE_WHICH(unset_secpolicy_ipv6_action, unset_secpolicy_ipv6_src_ip, unset_secpolicy_ipv6_src_ip, "action", "action of rule", 3, 1);
TEST_UNSET(unset_secpolicy_ipv6, unset_secpolicy_ipv6_action, set_secpolicy_ipv6_action);


VALUE_NODE(set_secpolicy_ipv6_rule_id, unset_secpolicy_ipv6, none, "id of rule", 2, NUM);
KW_NODE_WHICH(set_secpolicy_ipv6_out2in_rule,  set_secpolicy_ipv6_rule_id, none, "out2in-rule", "set security policy out2in rule", 2, 2);
KW_NODE_WHICH(set_secpolicy_ipv6_in2out_rule,  set_secpolicy_ipv6_rule_id, set_secpolicy_ipv6_out2in_rule, "in2out-rule", "set security policy in2out rule", 2, 1);

/* set secpolicy ipv6 vrf x vpc-subnet-ipv6 x::x/x */
VALUE_NODE(set_secpolicy_vpc_subnet_ipv6_addr, set_vpc_subnet_eol, none, "ipv6 address/prefix value <1-128>", 1, STR);
KW_NODE(set_secpolicy_vpc_subnet_ipv6, set_secpolicy_vpc_subnet_ipv6_addr, set_secpolicy_ipv6_in2out_rule, "vpc-subnet-ipv6", "VPC subnet IPv6");

VALUE_NODE(set_secpolicy_ipv6_vrf_id, set_secpolicy_vpc_subnet_ipv6, none, "vrf id", 1, NUM);
KW_NODE(set_secpolicy_ipv6_vrf, set_secpolicy_ipv6_vrf_id, none, "vrf", "VRF");

/* set secpolicy ipv6 tenant xxx ext-subnet-ipv6 x::x */
VALUE_NODE(set_secpolicy_ext_subnet_ipv6_addr, set_ext_subnet_eol, none, "ipv6 address", 1, STR);
KW_NODE(set_secpolicy_ext_subnet_ipv6, set_secpolicy_ext_subnet_ipv6_addr, set_secpolicy_ipv6_in2out_rule, "ext-subnet-ipv6", "Ext subnet IPv6");

/* tenant str string[2] */
VALUE_NODE(set_secpolicy_ipv6_tenant_str, set_secpolicy_ext_subnet_ipv6, none, "tenant <string>", 3, STR);
KW_NODE(set_secpolicy_ipv6_tenant, set_secpolicy_ipv6_tenant_str, set_secpolicy_ipv6_vrf, "tenant", "Tenant");

/* ipv6 which[0] == 2 */
KW_NODE_WHICH(set_secpolicy_ipv6, set_secpolicy_ipv6_tenant, unset_secpolicy_status_pass, "ipv6", "IPv6", 1, 2);

/************************************************************************************************/

/* description str string[4] */
VALUE_NODE(set_secpolicy_ip_description_str, set_rule_eol, none, "description <1-127>", 5, STR);

/* description which[17] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_description, set_secpolicy_ip_description_str, set_rule_eol, "desc", "description", 18, 1);

/* statistics disable which[15] == 2*/
KW_NODE_WHICH(set_secpolicy_ip_statistics_off, set_secpolicy_ip_description, none, "disable", "disable statistics(default)", 16, 2);

/* statistics enable which[15] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_statistics_on,  set_secpolicy_ip_description, set_secpolicy_ip_statistics_off, "enable", "enable statistics", 16, 1);

/* statistics which[14] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_statistics, set_secpolicy_ip_statistics_on, set_secpolicy_ip_description, "statistics", "packet statistics", 15, 1);

/* status disable which[13] == 2*/
KW_NODE_WHICH(set_secpolicy_ip_status_disable, set_secpolicy_ip_statistics, none, "disable", "disable rule(default)", 14, 2);

/* status enable which[13] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_status_enable,  set_secpolicy_ip_statistics, set_secpolicy_ip_status_disable, "enable", "enable rule", 14, 1);

/* status which[12] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_status, set_secpolicy_ip_status_enable, set_secpolicy_ip_statistics, "status", "status of rule", 13, 1);

/* app str string[3] */
VALUE_NODE(set_secpolicy_ipv4_app_str, set_secpolicy_ip_status, none, "application id <number>, example, 10,15,20", 4, STR);

/* app which[16] */
KW_NODE_WHICH(set_secpolicy_ipv4_app, set_secpolicy_ipv4_app_str, set_secpolicy_ip_status, "app", "application", 17, 1);

/* icmp code value number[3] */
VALUE_NODE(set_secpolicy_ip_icmp_code_num, set_secpolicy_ipv4_app, none, "code", 4, NUM);

/* icmp code which[11] == 1 */
KW_NODE_WHICH(set_secpolicy_ip_icmp_code, set_secpolicy_ip_icmp_code_num, set_secpolicy_ipv4_app, "code", "icmp code", 12, 1);

/* icmp type value number[2] */
VALUE_NODE(set_secpolicy_ip_icmp_type_num, set_secpolicy_ip_icmp_code, none, "type", 3, NUM);

/* icmp type which[10] == 1 */
KW_NODE_WHICH(set_secpolicy_ip_icmp_type, set_secpolicy_ip_icmp_type_num, set_secpolicy_ip_icmp_code, "type", "icmp type", 11, 1);

/* dport end value number[5] */
VALUE_NODE(set_secpolicy_ip_dst_port_value2, set_secpolicy_ipv4_app, none, "port number; for example, 80", 6, NUM);

KW_NODE(set_secpolicy_ip_dst_port_to, set_secpolicy_ip_dst_port_value2, set_secpolicy_ipv4_app, "to", "for example, 10 to 100");

/* dport begin value number[4] */
VALUE_NODE(set_secpolicy_ip_dst_port_value1, set_secpolicy_ip_dst_port_to, none, "port number; for example, 80", 5, NUM);

/* dport which[9] == 1 */
KW_NODE_WHICH(set_secpolicy_ip_dst_port, set_secpolicy_ip_dst_port_value1, set_secpolicy_ipv4_app, "dst-port", "destination port, for example, 10 to 100 or 80", 10, 1);

/* sport end value number[3] */
VALUE_NODE(set_secpolicy_ip_src_port_value2, set_secpolicy_ip_dst_port, none, "port number; for example, 80", 4, NUM);

KW_NODE(set_secpolicy_ip_src_port_to, set_secpolicy_ip_src_port_value2, set_secpolicy_ip_dst_port, "to", "for example, 10 to 100");

/* sport begin value number[2] */
VALUE_NODE(set_secpolicy_ip_src_port_value1, set_secpolicy_ip_src_port_to, none, "port number, for example, 80", 3, NUM);

/* sport which[8] == 1 */
KW_NODE_WHICH(set_secpolicy_ip_src_port, set_secpolicy_ip_src_port_value1, set_secpolicy_ip_dst_port, "src-port", "source port, for example, 10 to 100 or 80", 9, 1);

/* service icmp which[7] == 3 */
KW_NODE_WHICH(set_secpolicy_ip_service_icmp, set_secpolicy_ip_icmp_type, none, "icmp", "icmp", 8, 3);

/* service udp which[7] == 2 */
KW_NODE_WHICH(set_secpolicy_ip_service_udp, set_secpolicy_ip_src_port, set_secpolicy_ip_service_icmp, "udp", "udp", 8, 2);

/* service tcp which[7] == 1 */
KW_NODE_WHICH(set_secpolicy_ip_service_tcp, set_secpolicy_ip_src_port, set_secpolicy_ip_service_udp, "tcp", "tcp", 8, 1);
    
/* service which[6] == 1 */
KW_NODE_WHICH(set_secpolicy_ip_service, set_secpolicy_ip_service_tcp, set_secpolicy_ipv4_app, "service", "service", 7, 1);

/* ip/mask string[1] */
VALUE_NODE(set_secpolicy_ip_dst_value, set_secpolicy_ip_service, none, "ipv4 address/mask value <1-32>", 2, STR);
    
/* dip which[5] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_dst, set_secpolicy_ip_dst_value, set_secpolicy_ip_service, "dst-ip", "destination IP", 6, 1);
    
/* ip/mask string[0] */
VALUE_NODE(set_secpolicy_ip_src_value, set_secpolicy_ip_dst, none, "ipv4 address/mask value <1-32>", 1, STR);
    
/* sip which[4] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_src, set_secpolicy_ip_src_value, set_secpolicy_ip_dst, "src-ip", "source IP", 5, 1);

/* action drop which[3] == 2*/
KW_NODE_WHICH(set_secpolicy_ip_action_drop,  set_secpolicy_ip_src, none, "drop", "drop(default)", 4, 2);

/* action pass which[3] == 1*/
KW_NODE_WHICH(set_secpolicy_ip_action_pass,  set_secpolicy_ip_src, set_secpolicy_ip_action_drop, "pass", "pass", 4, 1);

/* action which[2] == 1 */
KW_NODE_WHICH(set_secpolicy_ip_action, set_secpolicy_ip_action_pass, set_secpolicy_ip_src, "action", "action of rule", 3, 1);


/* unset part */
KW_NODE_WHICH(unset_secpolicy_ip_description, unset_rule_eol, unset_rule_eol, "desc", "description", 10, 1);
KW_NODE_WHICH(unset_secpolicy_ip_statistics, unset_secpolicy_ip_description, unset_secpolicy_ip_description, "statistics", "packet statistics", 8, 1);
KW_NODE_WHICH(unset_secpolicy_ip_status, unset_secpolicy_ip_statistics, unset_secpolicy_ip_statistics, "status", "status of rule", 7, 1);
KW_NODE_WHICH(unset_secpolicy_ip_app, unset_secpolicy_ip_status, unset_secpolicy_ip_status, "app", "application", 9, 1);
KW_NODE_WHICH(unset_secpolicy_ip_service, unset_secpolicy_ip_app, unset_secpolicy_ip_app, "service", "service", 6, 1);
KW_NODE_WHICH(unset_secpolicy_ip_dst_ip, unset_secpolicy_ip_service, unset_secpolicy_ip_service, "dst-ip", "destination IP", 5, 1);
KW_NODE_WHICH(unset_secpolicy_ip_src_ip, unset_secpolicy_ip_dst_ip, unset_secpolicy_ip_dst_ip, "src-ip", "source IP", 4, 1);
KW_NODE_WHICH(unset_secpolicy_ip_action, unset_secpolicy_ip_src_ip, unset_secpolicy_ip_src_ip, "action", "action of rule", 3, 1);
TEST_UNSET(unset_secpolicy_ip, unset_secpolicy_ip_action, set_secpolicy_ip_action);

/* vrf id number[1] */
VALUE_NODE(set_secpolicy_ip_rule_id, unset_secpolicy_ip, none, "id of rule", 2, NUM);

/* out2in-rule which[1]==2  */
KW_NODE_WHICH(set_secpolicy_ip_out2in_rule,  set_secpolicy_ip_rule_id, none, "out2in-rule", "set security policy out2in rule", 2, 2);

/* in2out-rule which[1]==1  */
KW_NODE_WHICH(set_secpolicy_ip_in2out_rule,  set_secpolicy_ip_rule_id, set_secpolicy_ip_out2in_rule, "in2out-rule", "set security policy in2out rule", 2, 1);

/* set secpolicy ip vrf x vpc-subnet-ip x.x.x.x/x */
VALUE_NODE(set_secpolicy_vpc_subnet_ip_addr, set_vpc_subnet_eol, none, "ipv4 address/mask value <1-32>", 1, STR);
KW_NODE(set_secpolicy_vpc_subnet_ip, set_secpolicy_vpc_subnet_ip_addr, set_secpolicy_ip_in2out_rule, "vpc-subnet-ip", "VPC subnet ipv4");

/* vrf id number[0] */
VALUE_NODE(set_secpolicy_ipv4_vrf_id, set_secpolicy_vpc_subnet_ip, none, "vrf id", 1, NUM);
KW_NODE(set_secpolicy_ipv4_vrf, set_secpolicy_ipv4_vrf_id, none, "vrf", "VRF");

/* set secpolicy ip tenant xxx ext-subnet-ip x.x.x.x */
VALUE_NODE(set_secpolicy_ext_subnet_ip_addr, set_ext_subnet_eol, none, "ipv4 address", 1, STR);
KW_NODE(set_secpolicy_ext_subnet_ip, set_secpolicy_ext_subnet_ip_addr, set_secpolicy_ip_in2out_rule, "ext-subnet-ip", "Ext subnet ipv4");

/* tenant str string[2] */
VALUE_NODE(set_secpolicy_ipv4_tenant_str, set_secpolicy_ext_subnet_ip, none, "tenant <string>", 3, STR);
KW_NODE(set_secpolicy_ipv4_tenant, set_secpolicy_ipv4_tenant_str, set_secpolicy_ipv4_vrf, "tenant", "Tenant");

/* ip which[0] == 1 */
KW_NODE_WHICH(set_secpolicy_ipv4, set_secpolicy_ipv4_tenant, set_secpolicy_ipv6, "ip", "IPv4", 1, 1);

/* set secpolicy fw-type [ vpc-fw | ext-fw ] */
KW_NODE_WHICH(set_secpolicy_fwtype_ext,  set_fw_type_eol, none, "ext-fw", "ext type", 1, 1);
KW_NODE_WHICH(set_secpolicy_fwtype_vpc,  set_fw_type_eol, set_secpolicy_fwtype_ext, "vpc-fw", "vpc type(default)", 1, 2);
KW_NODE(set_secpolicy_fwtype, set_secpolicy_fwtype_vpc, set_secpolicy_ipv4, "fw-type", "Set fw type");
KW_NODE(unset_secpolicy_fwtype, set_fw_type_eol, set_secpolicy_ipv4, "fw-type", "Unset fw type");

TEST_UNSET(unset_secpolicy_fw_type, unset_secpolicy_fwtype, set_secpolicy_fwtype);
KW_NODE(set_secpolicy, unset_secpolicy_fw_type, none, "secpolicy", "The security policy");


/* set fw type cmd end */

static int debug_secpolicy_cli(cmd_blk_t *cbt)
{
    unsigned int uiDbgType;
    unsigned int uiIPType;

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
        uiDbgType = SECPOLICY_DEBUG_PACKET;
    }

    if (cbt->mode == MODE_DO)
    {
        SecPolicy_Conf_SetDbg(cbt->number[0], cbt->string[0], uiDbgType, BOOL_FALSE, uiIPType);
    }
    else
    {
        SecPolicy_Conf_SetDbg(cbt->number[0], cbt->string[0], uiDbgType, BOOL_TRUE, uiIPType);
    }

    return 0;
}

EOL_NODE(debug_secpolicy_eol, debug_secpolicy_cli);
KW_NODE_WHICH(debug_secpolicy_type, debug_secpolicy_eol, none, "packet", "packet", 2, 1);
VALUE_NODE(debug_secpolicy_vrf_id, debug_secpolicy_type, none, "vrf id", 1, NUM);
KW_NODE(debug_secpolicy_vrf, debug_secpolicy_vrf_id, none, "vrf", "VRF");
VALUE_NODE(debug_secpolicy_tennat_str, debug_secpolicy_type, none, "tenant <string>", 1, STR);
KW_NODE(debug_secpolicy_tenant, debug_secpolicy_tennat_str, debug_secpolicy_vrf, "tenant", "Tenant");
KW_NODE_WHICH(debug_secpolicy_ipv6, debug_secpolicy_tenant, none, "ipv6", "IPv6", 1, 2);
KW_NODE_WHICH(debug_secpolicy_ipv4, debug_secpolicy_tenant, debug_secpolicy_ipv6, "ip", "IPv4", 1, 1);
KW_NODE(debug_secpolicy, debug_secpolicy_ipv4, none, "secpolicy", "The security policy");


static int show_secpolicy_status_cli(cmd_blk_t *cbt)
{

    /* status */
    if (1 == cbt->which[0])
    {
        if (BOOL_TRUE == g_bIsSecPolicyStatusOn)
        {
            printf("The security policy status : Enable\n");
        }
        else
        {
            printf("The security policy status : Disable\n");
        }
    }


    return 0;
}

static int show_secpolicy_fwtype_cli(cmd_blk_t *cbt)
{
    SECPOLICY_TYPE_E enFwType;

    /* status */
    if (2 == cbt->which[0])
    {
        enFwType = SecPolicy_GetFwType();
        if (SECPOLICY_TYPE_VPCBODER == enFwType)
        {
            printf("The fw type : vpc-fw\n");
        }
        else
        {
            printf("The fw type : ext-fw\n");
        }
    }


    return 0;
}

static int show_secpolicy_debug_cli(cmd_blk_t *cbt)
{
    /* status */
    if (3 == cbt->which[0])
    {
        SecPolciy_Conf_GetDbg(cbt->number[0], cbt->string[0], IPPROTO_IP);
    }
    else if (4 == cbt->which[0])
    {
        SecPolciy_Conf_GetDbg(cbt->number[0], cbt->string[0], IPPROTO_IPV6);
    }


    return 0;
}


static int show_secpolicy_subnet_cli(cmd_blk_t *cbt)
{
    unsigned int uiIPType;

    if (3 == cbt->which[0])
    {
        uiIPType = IPPROTO_IP;
    }
    else if (4 == cbt->which[0])
    {
        uiIPType = IPPROTO_IPV6;
    }

    if (0 != cbt->number[0])
    {
        SecPolicy_VPCFlow_ShowVxlanID(cbt->number[0], uiIPType);  
    }
    else if (0 != cbt->string[0])
    {
        SecPolicy_ExtFlow_ShowTenantID(cbt->string[0], uiIPType);  
    }

    return 0;
}

static int show_rule_cli(cmd_blk_t *cbt)
{
    SECPOLICY_RULE_CFG_S stRuleCfg;

    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    if (3 == cbt->which[1])
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    }
    else if (4 == cbt->which[1])
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }

    if (0 != cbt->number[0])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_VPCBODER;
        stRuleCfg.uiVxlanID = cbt->number[0];
    }
    else if (0 != cbt->string[0])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_EXTBODER;
        strlcpy(stRuleCfg.szTenantID, cbt->string[0], TENANT_ID_MAX);
    }

    if (cbt->which[2] == 1)
    {
        stRuleCfg.uiRuleID  = 0;
    }
    else
    {
         stRuleCfg.uiRuleID  = cbt->number[1];
    }

    if (3 == cbt->which[0])
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else if (4 == cbt->which[0])
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    SecPolicy_Conf_Show(&stRuleCfg);
  

    return 0;
}

/* show cmd */
EOL_NODE(show_rules_eol, show_rule_cli);

EOL_NODE(show_secpolicy_subnet_eol, show_secpolicy_subnet_cli);

EOL_NODE(show_secpolicy_status_eol, show_secpolicy_status_cli);

EOL_NODE(show_secpolicy_fwtype_eol, show_secpolicy_fwtype_cli);

EOL_NODE(show_secpolicy_debug_eol, show_secpolicy_debug_cli);

/* show secpolicy [ ip | ipv6] vrf x [ in2out-rule | out2in-rule ]  [ x | all ] */
KW_NODE_WHICH(show_secpolicy_rule_all, show_rules_eol, none, "all", "show all secpolicy", 3, 1);
VALUE_NODE(show_secpolicy_rule_id, show_rules_eol, show_secpolicy_rule_all, "The id of rule", 2, NUM);
KW_NODE_WHICH(show_secpolicy_out2in_rule, show_secpolicy_rule_id, none, "out2in-rule", "show security policy ou2in rule", 2, 4);
KW_NODE_WHICH(show_secpolicy_in2out_rule, show_secpolicy_rule_id, show_secpolicy_out2in_rule, "in2out-rule", "show security policy in2out rule", 2, 3);

/* show secpolicy [ ip | ipv6] vrf x vpc-subnet */
KW_NODE_WHICH(show_secpolicy_vpc_subnet,  show_secpolicy_subnet_eol, show_secpolicy_in2out_rule, "network", "show vpc-subnet or ext-subnet", 2, 2);

/* show secpolicy [ ip | ipv6] vrf x debug */
KW_NODE_WHICH(show_secpolicy_debug,  show_secpolicy_debug_eol, show_secpolicy_vpc_subnet, "debug", "Debug", 2, 1);
VALUE_NODE(show_secpolicy_debug_vrf_id, show_secpolicy_debug, none, "The id of vrf", 1, NUM);
KW_NODE(show_secpolicy_debug_vrf, show_secpolicy_debug_vrf_id, none, "vrf", "VRF");

VALUE_NODE(show_secpolicy_debug_tenant_str, show_secpolicy_debug, none, "tenant <string>", 1, STR);
KW_NODE(show_secpolicy_debug_tenant, show_secpolicy_debug_tenant_str, show_secpolicy_debug_vrf, "tenant", "Tenant");

KW_NODE_WHICH(show_secpolicy_ipv6, show_secpolicy_debug_tenant, none, "ipv6", "IPv6", 1, 4);
KW_NODE_WHICH(show_secpolicy_ipv4, show_secpolicy_debug_tenant, show_secpolicy_ipv6, "ip", "IPv4", 1, 3);

/* show secpolicy fw-type */
KW_NODE_WHICH(show_secpolicy_fwtype,  show_secpolicy_fwtype_eol, show_secpolicy_ipv4, "fw-type", "Fw type", 1, 2);

/* show secpolicy status */
KW_NODE_WHICH(show_secpolicy_status,  show_secpolicy_status_eol, show_secpolicy_fwtype, "status", "Status", 1, 1);
KW_NODE(show_secpolicy, show_secpolicy_status, none, "secpolicy", "The security policy ");

/*  show secpolicy status end */

static int move_secpolicy_rule_cli(cmd_blk_t *cbt)
{
    unsigned long ulRet;
    SECPOLICY_MOVE_RULE_S stRuleCfg;
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));

    if (0 != cbt->number[0])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_VPCBODER;
        stRuleCfg.uiVxlanID = cbt->number[0];
    }
    else if (0 != cbt->string[0])
    {
        stRuleCfg.enFwType = SECPOLICY_TYPE_EXTBODER;
        strlcpy(stRuleCfg.szTenantID, cbt->string[0], TENANT_ID_MAX+1);
    }

    stRuleCfg.uiRuleID =  cbt->number[1];
    if (1 == cbt->which[0])
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else if (2 == cbt->which[0])
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }
    
    if (1 == cbt->which[1])
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    }
    else if (2 == cbt->which[1])
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    
    switch (cbt->which[2]) 
    {
        case SECPOLICY_MOVE_TYPE_HEAD:
        {
            stRuleCfg.enMoveType = SECPOLICY_MOVE_TYPE_HEAD;
            ulRet = SecPolicy_Conf_MoveRule(&stRuleCfg);
            if (0 == ulRet)
            {
                printf("%s %s move rule %d to head.\n",
                                         stRuleCfg.uiIPType == IPPROTO_IP ? "ipv4" : "ipv6",
                                         stRuleCfg.enFwDirect == SECPOLICY_DIRECTION_IN2OUT ? "in2out-rule" : "out2in-rule",
                                         stRuleCfg.uiRuleID);
            }
            break;
        }
        case SECPOLICY_MOVE_TYPE_BEFORE:
        {
            stRuleCfg.enMoveType = SECPOLICY_MOVE_TYPE_BEFORE;
            stRuleCfg.uiTargetID =  cbt->number[2];
            ulRet = SecPolicy_Conf_MoveRule(&stRuleCfg);
            if (0 == ulRet)
            {
                printf("%s %s move rule %d before %d.\n",  
                                         stRuleCfg.uiIPType == IPPROTO_IP ? "ipv4" : "ipv6",
                                         stRuleCfg.enFwDirect == SECPOLICY_DIRECTION_IN2OUT ? "in2out-rule" : "out2in-rule",
                                         stRuleCfg.uiRuleID,
                                         stRuleCfg.uiTargetID);
            }

            break;
        }
        case SECPOLICY_MOVE_TYPE_AFTER:
        {
            stRuleCfg.enMoveType = SECPOLICY_MOVE_TYPE_AFTER;
            stRuleCfg.uiTargetID =  cbt->number[2];
            ulRet = SecPolicy_Conf_MoveRule(&stRuleCfg);
            if (0 == ulRet)
            {
                printf("%s %s move rule %d after %d.\n", 
                                         stRuleCfg.uiIPType == IPPROTO_IP ? "ipv4" : "ipv6",
                                         stRuleCfg.enFwDirect == SECPOLICY_DIRECTION_IN2OUT ? "in2out-rule" : "out2in-rule",
                                         stRuleCfg.uiRuleID,
                                         stRuleCfg.uiTargetID);
            }
            break;
        }
        case SECPOLICY_MOVE_TYPE_TAIL:
        {
            stRuleCfg.enMoveType = SECPOLICY_MOVE_TYPE_TAIL;
            ulRet = SecPolicy_Conf_MoveRule(&stRuleCfg);
            if (0 == ulRet)
            {
                printf("%s %s move rule %d to tail.\n",
                                         stRuleCfg.uiIPType == IPPROTO_IP ? "ipv4" : "ipv6",
                                         stRuleCfg.enFwDirect == SECPOLICY_DIRECTION_IN2OUT ? "in2out-rule" : "out2in-rule",
                                         stRuleCfg.uiRuleID);
            }
            break;
        }
        default:
        {
            break;
        }
    }

    return 0;
}

EOL_NODE(move_secpolicy_rule_eol, move_secpolicy_rule_cli);
VALUE_NODE(move_secpolicy_rule_id2, move_secpolicy_rule_eol, none, "id of rule", 3, NUM);
KW_NODE_WHICH(move_secpolicy_rule_head, move_secpolicy_rule_eol, none, "head", "Move to head", 3, 1);
KW_NODE_WHICH(move_secpolicy_rule_before, move_secpolicy_rule_id2, move_secpolicy_rule_head, "before", "Move to before", 3, 3);
KW_NODE_WHICH(move_secpolicy_rule_after, move_secpolicy_rule_id2, move_secpolicy_rule_before, "after", "Move to after ", 3, 4);
KW_NODE_WHICH(move_secpolicy_rule_tail, move_secpolicy_rule_eol, move_secpolicy_rule_after, "tail", "Move to tail", 3, 2);

VALUE_NODE(move_secpolicy_rule_id1, move_secpolicy_rule_tail, none, "id of rule", 2, NUM);
KW_NODE_WHICH(move_secpolicy_out2in_rule, move_secpolicy_rule_id1, none, "out2in-rule", "move security policy out2in rule", 2, 2);
KW_NODE_WHICH(move_secpolicy_in2out_rule, move_secpolicy_rule_id1, move_secpolicy_out2in_rule, "in2out-rule", "move security policy in2out rule", 2, 1);
VALUE_NODE(move_secpolicy_vrf_id, move_secpolicy_in2out_rule, none, "The id of vrf", 1, NUM);
KW_NODE(move_secpolicy_vrf, move_secpolicy_vrf_id, none, "vrf", "VRF");
VALUE_NODE(move_secpolicy_tenant_str, move_secpolicy_in2out_rule, none, "tenant <string>", 1, STR);
KW_NODE(move_secpolicy_tenant, move_secpolicy_tenant_str, move_secpolicy_vrf, "tenant", "Tenant");
KW_NODE_WHICH(move_secpolicy_ipv6, move_secpolicy_tenant, none, "ipv6", "IPv6", 1, 2);
KW_NODE_WHICH(move_secpolicy_ipv4, move_secpolicy_tenant, move_secpolicy_ipv6, "ip", "IPv4", 1, 1);

KW_NODE(move_secpolicy,  move_secpolicy_ipv4, none, "secpolicy", "move security policy");


static int clear_secpolicy_rule_cli(cmd_blk_t *cbt)
{
    SECPOLICY_RULE_CFG_S stCfg;

    memset(&stCfg, 0, sizeof(SECPOLICY_RULE_CFG_S));

    if (1 == cbt->which[0])
    {
        stCfg.uiIPType = IPPROTO_IP;
    }
    else if (2 == cbt->which[0])
    {
        stCfg.uiIPType = IPPROTO_IPV6;
    }

    if (1 == cbt->which[1])
    {
        stCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    }
    else if (2 == cbt->which[1])
    {
        stCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    
    stCfg.enFwType = SecPolicy_GetFwType();
    stCfg.uiVxlanID = cbt->number[0];
    stCfg.uiRuleID =  cbt->number[1];

    SecPolicy_Conf_ClearStatistics(&stCfg);

    return 0;
}
EOL_NODE(clear_secpolicy_rule_eol, clear_secpolicy_rule_cli);
VALUE_NODE(clear_secpolicy_rule_id1, clear_secpolicy_rule_eol, none, "id of rule", 2, NUM);
KW_NODE_WHICH(clear_secpolicy_out2in_rule, clear_secpolicy_rule_id1, none, "out2in-rule", "clear security policy out2in rule statistics", 2, 2);
KW_NODE_WHICH(clear_secpolicy_in2out_rule, clear_secpolicy_rule_id1, clear_secpolicy_out2in_rule, "in2out-rule", "clear security policy in2out rule statistics", 2, 1);
VALUE_NODE(clear_secpolicy_vrf_id, clear_secpolicy_in2out_rule, none, "The id of vrf", 1, NUM);
KW_NODE(clear_secpolicy_vrf, clear_secpolicy_vrf_id, none, "vrf", "VRF");
VALUE_NODE(clear_secpolicy_tenant_str, clear_secpolicy_in2out_rule, none, "tenant <string>", 1, STR);
KW_NODE(clear_secpolicy_tenant, clear_secpolicy_tenant_str, clear_secpolicy_vrf, "tenant", "Tenant");
KW_NODE_WHICH(clear_secpolicy_ipv6, clear_secpolicy_tenant, none, "ipv6", "IPv6", 1, 2);
KW_NODE_WHICH(clear_secpolicy_ipv4, clear_secpolicy_tenant, clear_secpolicy_ipv6, "ip", "IPv4", 1, 1);

KW_NODE(clear_secpolicy,  clear_secpolicy_ipv4, none, "secpolicy", "clear security policy rule statistics");

void security_policy_cli_init(void)
{
    add_set_cmd(&cnode(set_secpolicy));
    add_debug_cmd(&cnode(debug_secpolicy));
    add_get_cmd(&cnode(show_secpolicy));
    add_move_cmd(&cnode(move_secpolicy));
    add_clear_cmd(&cnode(clear_secpolicy));
}

