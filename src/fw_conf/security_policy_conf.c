#include <stdio.h>
#include <assert.h>
//#include <netinet/in.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/security_policy_conf.h"

#include "../access_control/error.h"
#include "../access_control/secpolicy_common.h"
#include "../access_control/secpolicy.h"
#include "fw_lib.h"


#define SEC_POLICY_ZONE_NAME      "security policy conf"
#define SEC_POLICY_RULE_MP_NAME   "security policy rules"
#define SEC_POLICY_RULE_MP_SIZE    8192

static uint32_t sec_policy_dir;
static uint32_t sec_policy_ip_proto;
static uint32_t rule_id;

static void sec_policy_subnet(vector_t tokens)
{
    RTE_LOG(INFO, CFG_FILE, "%s\n", __func__);
    return;
}

static void sec_policy_in_handler(vector_t tokens)
{
    sec_policy_dir = 1;

    RTE_LOG(INFO, CFG_FILE, "%s\n", __func__);

    return;
}

static void sec_policy_out_handler(vector_t tokens)
{
    sec_policy_dir = 0;

    RTE_LOG(INFO, CFG_FILE, "%s\n", __func__);

    return;
}

static void sec_policy_ipv4_handler(vector_t tokens)
{
    sec_policy_ip_proto = 1;

    RTE_LOG(INFO, CFG_FILE, "%s\n", __func__);

    return;
}

static void sec_policy_ipv6_handler(vector_t tokens)
{
    sec_policy_ip_proto = 0;

    RTE_LOG(INFO, CFG_FILE, "%s\n", __func__);

    return;
}

static void sec_policy_subnet_ip(vector_t tokens)
{
    char *str = set_value(tokens);
    CHAR *pc;
    IP_ADDR_MASK_S stIPAddrMask;
    IP_ADDR_S stIPAddr;

    if (true != FWLIB_Check_IPv4AndMask_IsLegal(str))
    {
        FREE_PTR(str);
        return;
    }

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stIPAddrMask.stIPAddr.uiIPType = IPPROTO_IP;
        if (strchr(str, '/'))
        {
            /* example, 1.1.1.1/24 */
            pc = strtok(str, "/");
            inet_pton(AF_INET, pc, &stIPAddrMask.stIPAddr._ip_data.stIP4Addr);
            pc = strtok(NULL, "/");
            stIPAddrMask.uiIPMaskLen = atoi(pc);
        }
        else
        {
            /* example, 1.1.1.1 */
            inet_pton(AF_INET, str, &stIPAddrMask.stIPAddr._ip_data.stIP4Addr);
            stIPAddrMask.uiIPMaskLen = 32;
        }

        (void)SecPolicy_VPCFlow_AddPubIP(fw_parse_vrf, &stIPAddrMask);
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        stIPAddr.uiIPType = IPPROTO_IP;
        if (strchr(str, '/'))
        {
            /* example, 1.1.1.1/24 */
            pc = strtok(str, "/");
            inet_pton(AF_INET, pc, &stIPAddr._ip_data.stIP4Addr);
        }
        else
        {
            /* example, 1.1.1.1 */
            inet_pton(AF_INET, str, &stIPAddr._ip_data.stIP4Addr);
        }
        (void)SecPolicy_ExtFlow_AddPubIP(szSecPolicyTenantID, &stIPAddr);
    }

    FREE_PTR(str);
    return;
}

static void sec_policy_subnet_ipv6(vector_t tokens)
{
    char *str = set_value(tokens);
    CHAR *pc;
    IP_ADDR_MASK_S stIPAddrMask;
    IP_ADDR_S stIPAddr;

    if (true != FWLIB_Check_IPv6AndPrefix_IsLegal(str))
    {
        FREE_PTR(str);
        return;
    }

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stIPAddrMask.stIPAddr.uiIPType = IPPROTO_IPV6;
        
        if (strchr(str, '/'))
        {
            /* example, 1::2/64 */
            pc = strtok(str, "/");
            inet_pton(AF_INET6, pc, &stIPAddrMask.stIPAddr._ip_data.stIP6Addr);
            pc = strtok(NULL, "/");
            stIPAddrMask.uiIPMaskLen = atoi(pc);
        }
        else
        {
            /* example, 1::2 */
            inet_pton(AF_INET6, str, &stIPAddrMask.stIPAddr._ip_data.stIP6Addr);
            stIPAddrMask.uiIPMaskLen = 128;
        }

        (void)SecPolicy_VPCFlow_AddPubIP(fw_parse_vrf, &stIPAddrMask);
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        stIPAddr.uiIPType = IPPROTO_IPV6;
        
        if (strchr(str, '/'))
        {
            /* example, 1::2/64 */
            pc = strtok(str, "/");
            inet_pton(AF_INET6, pc, &stIPAddr._ip_data.stIP6Addr);
        }
        else
        {
            /* example, 1::2 */
            inet_pton(AF_INET6, str, &stIPAddr._ip_data.stIP6Addr);
        }
        (void)SecPolicy_ExtFlow_AddPubIP(szSecPolicyTenantID, &stIPAddr);
    }

    FREE_PTR(str);
    return;
}

static void rule_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %s\n", __func__, 
                                                 fw_parse_vrf,
                                                 sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                 sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                 str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %s\n", __func__, 
                                                 szSecPolicyTenantID,
                                                 sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                 sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                 str);
    }

    rule_id = atoi(str);

    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID = rule_id;
    stRuleCfg.enActionType = SECPOLICY_ACTION_DENY;
    stRuleCfg.stL4Info.ucProtocol = INVALID_TCPIP_PROTOCOL_ID;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }
    
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }

    (void)SecPolicy_Conf_AddRule(&stRuleCfg);

    FREE_PTR(str);

    return;
}

static void status_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t status;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d status %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", rule_id, str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d status %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", rule_id, str);
    }

    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    if (0 == strncmp(str, "enable", strlen("enable"))) 
    {
        stRuleCfg.bIsEnable = BOOL_TRUE;
    } 
    else 
    {
        stRuleCfg.bIsEnable = BOOL_FALSE;
    }

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_STATUS;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void action_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t action;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d action %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d action %s\n", __func__, 
                                                                szSecPolicyTenantID,
                                                                sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                                sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                                rule_id, 
                                                                str);
    }

    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    if (0 == strncmp(str, "drop", strlen("drop"))) 
    {
        stRuleCfg.enActionType = SECPOLICY_ACTION_DENY;
    } 
    else 
    {
        stRuleCfg.enActionType = SECPOLICY_ACTION_PERMIT;
    }
    
    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_ACTION;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void service_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t service = 0;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d service %s\n", __func__, 
                                                                  fw_parse_vrf,
                                                                  sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                                  sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                                  rule_id, 
                                                                  str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d service %s\n", __func__, 
                                                                  szSecPolicyTenantID,
                                                                  sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                                  sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                                  rule_id, 
                                                                  str);
    }

    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    if (0 == strncmp(str, "tcp", strlen("tcp"))) {
        stRuleCfg.stL4Info.ucProtocol = IPPROTO_TCP;
    }else if (0 == strncmp(str, "udp", strlen("udp"))) {
        stRuleCfg.stL4Info.ucProtocol = IPPROTO_UDP;
    }else if (0 == strncmp(str, "icmp", strlen("icmp"))) {
        stRuleCfg.stL4Info.ucProtocol = IPPROTO_ICMP;
    }else if (0 == strncmp(str, "icmpv6", strlen("icmpv6"))) {
        stRuleCfg.stL4Info.ucProtocol = IPPROTO_ICMPV6;
    }
   
    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SERVICE;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void dst_ip_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d dst-ip %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d dst-ip %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;
    stRuleCfg.uiIPType = IPPROTO_IP;

    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET, str, &ip.addr.ip4);
        ip.prefixlen = atoi(++pos);
    }

    stRuleCfg.stDst.enIPType = MULTITYPE_SINGLEIP;
    stRuleCfg.stDst._multi_ip_type = IPPROTO_IP;
    stRuleCfg.stDst._multi_ip4_addr = ip.addr.ip4.s_addr;
    stRuleCfg.stDst.uiIPMaskLen = ip.prefixlen;

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DIP;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void src_ip_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d src-ip %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d src-ip %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;
    stRuleCfg.uiIPType = IPPROTO_IP;

    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET, str, &ip.addr.ip4);
        ip.prefixlen = atoi(++pos);
    }

    stRuleCfg.stSrc.enIPType = MULTITYPE_SINGLEIP;
    stRuleCfg.stSrc._multi_ip_type = IPPROTO_IP;
    stRuleCfg.stSrc._multi_ip4_addr = ip.addr.ip4.s_addr;
    stRuleCfg.stSrc.uiIPMaskLen = ip.prefixlen;

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SIP;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void dst_ip6_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d dst-ip6 %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d dst-ip6 %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;
    stRuleCfg.uiIPType = IPPROTO_IPV6;

    stRuleCfg.stDst.enIPType = MULTITYPE_SINGLEIP;
    stRuleCfg.stDst._multi_ip_type = IPPROTO_IPV6;
    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET6, str, &stRuleCfg.stDst._multi_ip.stIPAddr._ip_data.stIP6Addr);
        stRuleCfg.stDst.uiIPMaskLen = atoi(++pos);
    }

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DIP;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);
    

    FREE_PTR(str);

    return;
}

static void src_ip6_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d src-ip6 %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d src-ip6 %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;
    stRuleCfg.uiIPType = IPPROTO_IPV6;

    stRuleCfg.stSrc.enIPType = MULTITYPE_SINGLEIP;
    stRuleCfg.stSrc._multi_ip_type = IPPROTO_IPV6;
    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET6, str, &stRuleCfg.stSrc._multi_ip.stIPAddr._ip_data.stIP6Addr);
        stRuleCfg.stSrc.uiIPMaskLen = atoi(++pos);
    }

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SIP;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}


static void dst_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t port_min;
    uint32_t port_max;
    char *p;
    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d dst-port %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d dst-port %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }


    port_min = atoi(str);

    p = strchr(str, '-');
    if (p) {
        port_max = atoi(++p);
    } else {
        port_max = port_min;
    }

    stRuleCfg.stL4Info.stPortRange.stDRange.usSPort = port_min;
    stRuleCfg.stL4Info.stPortRange.stDRange.usDPort = port_max;

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DPORT;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void src_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t port_min;
    uint32_t port_max;
    char *p;

    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d src-port %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d src-port %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    port_min = atoi(str);

    p = strchr(str, '-');
    if (p) {
        port_max = atoi(++p);
    } else {
        port_max = port_min;
    }

    stRuleCfg.stL4Info.stPortRange.stSRange.usSPort = port_min;
    stRuleCfg.stL4Info.stPortRange.stSRange.usDPort = port_max;

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SPORT;
    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void app_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    char *p;
    unsigned int ui;
    unsigned char szApp[1024];

    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d app %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d app %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    memcpy(szApp, str,strlen(str));
    ui = 0;
    p = strtok(szApp, ",");
    while(NULL != p && ui<SECPOLICY_APP_NUM_MAX)
    {
        stRuleCfg.szAppID[ui++] = atoi(p);
        p = strtok(NULL, ",");
    }

    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_APP;

    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

static void desc_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    SECPOLICY_RULE_CFG_S stRuleCfg;

    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw vrf %d %s %s %d desc %s\n", __func__, 
                                                        fw_parse_vrf,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    else
    {
        RTE_LOG(INFO, CFG_FILE, "%s fw tenant %s %s %s %d desc %s\n", __func__, 
                                                        szSecPolicyTenantID,
                                                        sec_policy_ip_proto ? "ipv4":"ipv6", 
                                                        sec_policy_dir ? "in2out-rule":"out2in-rule", 
                                                        rule_id, 
                                                        str);
    }
    memset(&stRuleCfg, 0, sizeof(stRuleCfg));
    stRuleCfg.enFwType = secpolicy_fw_type;
    if (1 == sec_policy_dir) 
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
    } 
    else
    {
        stRuleCfg.enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
    }
    if (secpolicy_fw_type == SECPOLICY_TYPE_VPCBODER)
    {
        stRuleCfg.uiVxlanID = fw_parse_vrf;
    }
    else if (secpolicy_fw_type == SECPOLICY_TYPE_EXTBODER)
    {
        memcpy(stRuleCfg.szTenantID, szSecPolicyTenantID, TENANT_ID_MAX+1);
    }
    stRuleCfg.uiRuleID  = rule_id;

    if (1 == sec_policy_ip_proto)
    {
        stRuleCfg.uiIPType = IPPROTO_IP;
    }
    else
    {
        stRuleCfg.uiIPType = IPPROTO_IPV6;
    }

    strlcpy(stRuleCfg.szDescInfo, str, (SECPOLICY_RULE_DECRIPTION_MAX+1));
    stRuleCfg.uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DESC;

    (void)SecPolicy_Conf_MdyRulePara(&stRuleCfg, BOOL_FALSE);

    FREE_PTR(str);

    return;
}

void install_security_policy_keywords(void)
{
    install_keyword("subnet", sec_policy_subnet, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("ip", sec_policy_subnet_ip,   KW_TYPE_NORMAL);
    install_keyword("ipv6", sec_policy_subnet_ipv6, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_keyword("security_policy_in", sec_policy_in_handler, KW_TYPE_NORMAL);
    install_sublevel();

    install_keyword("ipv4", sec_policy_ipv4_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("rule", rule_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("status",   status_handler, KW_TYPE_NORMAL);
    install_keyword("action",   action_handler, KW_TYPE_NORMAL);
    install_keyword("service",  service_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip",   dst_ip_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip",   src_ip_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip6",  dst_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip6",  src_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("dst_port", dst_port_handler, KW_TYPE_NORMAL);
    install_keyword("src_port", src_port_handler, KW_TYPE_NORMAL);
    install_keyword("app", app_handler, KW_TYPE_NORMAL);
    install_keyword("desc", desc_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_sublevel_end(); 

    install_keyword("ipv6", sec_policy_ipv6_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("rule", rule_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("status",   status_handler, KW_TYPE_NORMAL);
    install_keyword("action",   action_handler, KW_TYPE_NORMAL);
    install_keyword("service",  service_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip6",  dst_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip6",  src_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("dst_port", dst_port_handler, KW_TYPE_NORMAL);
    install_keyword("src_port", src_port_handler, KW_TYPE_NORMAL);
    install_keyword("app", app_handler, KW_TYPE_NORMAL);
    install_keyword("desc", desc_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_sublevel_end();

    install_sublevel_end(); // security_policy_in

    
    install_keyword("security_policy_out", sec_policy_out_handler, KW_TYPE_NORMAL);
    install_sublevel();

    install_keyword("ipv4", sec_policy_ipv4_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("rule", rule_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("status",   status_handler, KW_TYPE_NORMAL);
    install_keyword("action",   action_handler, KW_TYPE_NORMAL);
    install_keyword("service",  service_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip",   dst_ip_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip",   src_ip_handler, KW_TYPE_NORMAL);
    install_keyword("dst_port", dst_port_handler, KW_TYPE_NORMAL);
    install_keyword("src_port", src_port_handler, KW_TYPE_NORMAL);
    install_keyword("app", app_handler, KW_TYPE_NORMAL);
    install_keyword("desc", desc_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_sublevel_end();

    install_keyword("ipv6", sec_policy_ipv6_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("rule", rule_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("status",   status_handler, KW_TYPE_NORMAL);
    install_keyword("action",   action_handler, KW_TYPE_NORMAL);
    install_keyword("service",  service_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip6",  dst_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip6",  src_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("dst_port", dst_port_handler, KW_TYPE_NORMAL);
    install_keyword("src_port", src_port_handler, KW_TYPE_NORMAL);
    install_keyword("app", app_handler, KW_TYPE_NORMAL);
    install_keyword("desc", desc_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_sublevel_end();

    install_sublevel_end(); // end security_policy_out

    return;
}

void security_policy_keyword_value_init(void)
{
    //printf("%s\n", __func__);
    return;
}
