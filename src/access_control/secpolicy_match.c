#include <stdio.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <string.h>
#include <stdlib.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <netinet/in.h>
#include <rte_atomic.h>

#include "error.h"
#include "fw_lib.h"
#include "secbasetype.h"
//#include "../fw-base/in.h"
#include "secpolicy_common.h"
#include "secbasetype.h"
#include "secpolicy.h"
#include "secpolicy_match.h"
#include "proto_relation.h"
#include "../fw-base/apr.h"

/* 通过vxlan id找到对应策略节点 */
SECPOLICY_CONF_NODE_S * _secpolicy_match_FindCurConfNodeByVxlanID(IN UINT uiVxlanID, IN SL_HEAD_S *pstList)
{
    SECPOLICY_CONF_NODE_S *pstEntry, *pstConfNode = NULL;
    SL_FOREACH_ENTRY(pstList,pstEntry,stNode)
    {
        if (uiVxlanID == pstEntry->uiVxlanID)
        {
            pstConfNode = pstEntry;
            break;
        }
    }

    return pstConfNode;
}


/* 通过报文的源或者目的IP找到对应的VxlanID */
SECPOLICY_VPC_FLOW_NODE_S * _secpolicy_match_ip4_FindVxlanIDByPacket(INOUT SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4)
{
    BOOL_T bIsFind = BOOL_FALSE;
    SECPOLICY_VPC_FLOW_NODE_S *pstEntry, *pstConf = NULL;
    SECPOLICY_IPADDR_MASK_NODE_S *pstIPNode;
    UINT uiMask;
    SL_FOREACH_ENTRY(g_pstSecVPCFlowHead, pstEntry,stNode)
    {
        rte_rwlock_read_lock(&pstEntry->rwlock_vpc_flow);

        SL_FOREACH_ENTRY(&pstEntry->stHead, pstIPNode, stNode)
        {
            if (pstIPNode->stIPAddrMask.stIPAddr.uiIPType == IPPROTO_IP)
            {
                FWLIB_IP4ADDR_Len2Mask(pstIPNode->stIPAddrMask.uiIPMaskLen, &uiMask);
                if ((pstIPNode->stIPAddrMask.stIPAddr._ip4_addr & uiMask) == 
                    (pstSecPolicyPacketIP4->stSrcIP.s_addr & uiMask))
                {
                    pstSecPolicyPacketIP4->enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
                    bIsFind = BOOL_TRUE;
                    pstConf = pstEntry;
                    break;
                }
                else if ((pstIPNode->stIPAddrMask.stIPAddr._ip4_addr & uiMask) == 
                    (pstSecPolicyPacketIP4->stDstIP.s_addr & uiMask))
                {
                    pstSecPolicyPacketIP4->enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
                    bIsFind = BOOL_TRUE;
                    pstConf = pstEntry;
                    break;
                }
            }
        }

        rte_rwlock_read_unlock(&pstEntry->rwlock_vpc_flow);

        if (BOOL_TRUE == bIsFind)
        {
            pstConf = pstEntry;
            break;
        }
    }

    return pstConf;
}

/* 通过报文的源或者目的IP找到对应的VPC ID */
SECPOLICY_VPC_FLOW_NODE_S * _secpolicy_match_ip6_FindVxlanIDByPacket(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6)
{
    BOOL_T bIsFind = BOOL_FALSE;
    SECPOLICY_VPC_FLOW_NODE_S *pstEntry, *pstConf = NULL;
    SECPOLICY_IPADDR_MASK_NODE_S *pstIPNode;
    struct in6_addr  stMask;
    BOOL_T bIsEqual;
    SL_FOREACH_ENTRY(g_pstSecVPCFlowHead, pstEntry,stNode)
    {
        rte_rwlock_read_lock(&pstEntry->rwlock_vpc_flow);

        SL_FOREACH_ENTRY(&pstEntry->stHead, pstIPNode, stNode)
        {
            if (pstIPNode->stIPAddrMask.stIPAddr.uiIPType == IPPROTO_IPV6)
            {
                FWLIB_IP6ADDR_Len2Mask(pstIPNode->stIPAddrMask.uiIPMaskLen, &stMask);
                bIsEqual = FWLIB_IP6_COMPARE(&pstIPNode->stIPAddrMask.stIPAddr._ip_data.stIP6Addr, 
                                                        &pstSecPolicyPacketIP6->stSrcIP6, 
                                                        &stMask);
                if (BOOL_TRUE == bIsEqual)
                {
                    pstSecPolicyPacketIP6->enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
                    bIsFind = BOOL_TRUE;
                    break;
                }

                bIsEqual = FWLIB_IP6_COMPARE(&pstIPNode->stIPAddrMask.stIPAddr._ip_data.stIP6Addr, 
                                                        &pstSecPolicyPacketIP6->stDstIP6, 
                                                        &stMask);
                if (BOOL_TRUE == bIsEqual)
                {
                    pstSecPolicyPacketIP6->enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
                    bIsFind = BOOL_TRUE;
                    break;
                }
                
            }
        }

        rte_rwlock_read_unlock(&pstEntry->rwlock_vpc_flow);

        if (BOOL_TRUE == bIsFind)
        {
            pstConf = pstEntry;
            break;
        }
    }

    return pstConf;
}


/* 通过租户ID找到对应策略节点 */
SECPOLICY_CONF_NODE_S * _secpolicy_match_FindCurConfNodeByTenantID(IN UCHAR *pucTenantID, IN SL_HEAD_S *pstList)
{
    SECPOLICY_CONF_NODE_S *pstEntry, *pstConfNode = NULL;
    SL_FOREACH_ENTRY(pstList,pstEntry,stNode)
    {
        if (0 == strncasecmp((char *)pucTenantID, pstEntry->szTenantID, TENANT_ID_MAX+1))
        {
            pstConfNode = pstEntry;
            break;
        }
    }

    return pstConfNode;
}

/* 通过报文的源或者目的公网IP找到对应的租户ID */
SECPOLICY_EXT_FLOW_NODE_S * _secpolicy_match_ip4_FindTenantIDByPacket(INOUT SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4)
{
    BOOL_T bIsFind = BOOL_FALSE;
    SECPOLICY_EXT_FLOW_NODE_S *pstEntry, *pstConf = NULL;
    SECPOLICY_IPADDR_NODE_S *pstIPNode;
    
    SL_FOREACH_ENTRY(g_pstSecExtFlowHead, pstEntry,stNode)
    {
        rte_rwlock_read_lock(&pstEntry->rwlock_ext_flow);

        SL_FOREACH_ENTRY(&pstEntry->stHead, pstIPNode, stNode)
        {
            if (pstIPNode->stIPAddr.uiIPType == IPPROTO_IP)
            {
                if (pstIPNode->stIPAddr._ip4_addr == pstSecPolicyPacketIP4->stSrcIP.s_addr)
                {
                    pstSecPolicyPacketIP4->enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
                    bIsFind = BOOL_TRUE;
                    break;
                }
                else if (pstIPNode->stIPAddr._ip4_addr == pstSecPolicyPacketIP4->stDstIP.s_addr)
                {
                    pstSecPolicyPacketIP4->enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
                    bIsFind = BOOL_TRUE;
                    break;
                }
            }
        }

        rte_rwlock_read_unlock(&pstEntry->rwlock_ext_flow);
        if (BOOL_TRUE == bIsFind)
        {        
            pstConf = pstEntry;
            break;
        }
    }

    return pstConf;
}

/* 通过报文的源或者目的公网IP找到对应的租户ID */
SECPOLICY_EXT_FLOW_NODE_S * _secpolicy_match_ip6_FindTenantIDByPacket(INOUT SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6)
{
    BOOL_T bIsFind = BOOL_FALSE;
    SECPOLICY_EXT_FLOW_NODE_S *pstEntry, *pstConf = NULL;
    SECPOLICY_IPADDR_NODE_S *pstIPNode;
    struct in6_addr  stMask;
    SL_FOREACH_ENTRY(g_pstSecExtFlowHead, pstEntry,stNode)
    {
        rte_rwlock_read_lock(&pstEntry->rwlock_ext_flow);

        SL_FOREACH_ENTRY(&pstEntry->stHead, pstIPNode, stNode)
        {
            if (pstIPNode->stIPAddr.uiIPType == IPPROTO_IPV6)
            {

                FWLIB_IP6ADDR_Len2Mask(128, &stMask);
                        
                if (FWLIB_IP6_COMPARE(&pstIPNode->stIPAddr._ip_data.stIP6Addr, &pstSecPolicyPacketIP6->stSrcIP6, &stMask))
                {
                    pstSecPolicyPacketIP6->enFwDirect = SECPOLICY_DIRECTION_IN2OUT;
                    bIsFind = BOOL_TRUE;
                    break;
                }
                else if (FWLIB_IP6_COMPARE(&pstIPNode->stIPAddr._ip_data.stIP6Addr, &pstSecPolicyPacketIP6->stDstIP6, &stMask))
                {
                    pstSecPolicyPacketIP6->enFwDirect = SECPOLICY_DIRECTION_OUT2IN;
                    bIsFind = BOOL_TRUE;
                    break;
                }
            }
        }

        rte_rwlock_read_unlock(&pstEntry->rwlock_ext_flow);
        if (BOOL_TRUE == bIsFind)
        {
            pstConf = pstEntry;
            break;
        }
    }

    return pstConf;
}

/* 查找策略节点 */
SECPOLICY_CONF_NODE_S * _secpolicy_match_ip4_FindCurConfList(INOUT SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstExtFlowNode;
    SECPOLICY_VPC_FLOW_NODE_S * pstVPCFlowNdoe;
    SECPOLICY_CONF_NODE_S * pstConfNode = NULL;

    if (0 == pstSecPolicyPacketIP4->uiVxlanID)
    {
        pstExtFlowNode = _secpolicy_match_ip4_FindTenantIDByPacket(pstSecPolicyPacketIP4);
        if (NULL != pstExtFlowNode)
        {
            pstConfNode = _secpolicy_match_FindCurConfNodeByTenantID(pstExtFlowNode->szTenantID, g_pstExtSecConfHeadIP4);
        }
        
    }
    else
    {
        pstVPCFlowNdoe = _secpolicy_match_ip4_FindVxlanIDByPacket(pstSecPolicyPacketIP4);
        if (NULL != pstVPCFlowNdoe)
        {
            pstConfNode = _secpolicy_match_FindCurConfNodeByVxlanID(pstVPCFlowNdoe->uiVxlanID, g_pstVPCSecConfHeadIP4);
        }
    }

    return pstConfNode;
}

/* 查找策略节点 */
SECPOLICY_CONF_NODE_S * _secpolicy_match_ip6_FindCurConfList(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstExtFlowNode;
    SECPOLICY_VPC_FLOW_NODE_S * pstVPCFlowNdoe;
    SECPOLICY_CONF_NODE_S * pstConfNode = NULL;

    if (0 == pstSecPolicyPacketIP6->uiVxlanID)
    {
        pstExtFlowNode = _secpolicy_match_ip6_FindTenantIDByPacket(pstSecPolicyPacketIP6);
        if (NULL != pstExtFlowNode)
        {
            pstConfNode = _secpolicy_match_FindCurConfNodeByTenantID(pstExtFlowNode->szTenantID, g_pstExtSecConfHeadIP6);
        }
        
    }
    else
    {
        pstVPCFlowNdoe = _secpolicy_match_ip6_FindVxlanIDByPacket(pstSecPolicyPacketIP6);
        if (NULL != pstVPCFlowNdoe)
        {
            pstConfNode = _secpolicy_match_FindCurConfNodeByVxlanID(pstSecPolicyPacketIP6->uiVxlanID, g_pstVPCSecConfHeadIP6);
        }
    }

    return pstConfNode;
}

int secpolicy_find4_TenantID(INOUT SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4, UCHAR *pucTenantID)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstExtFlowNode;
    SECPOLICY_VPC_FLOW_NODE_S * pstVPCFlowNdoe;
    
     if (0 == pstSecPolicyPacketIP4->uiVxlanID)
    {
        pstExtFlowNode = _secpolicy_match_ip4_FindTenantIDByPacket(pstSecPolicyPacketIP4);
        if (NULL != pstExtFlowNode)
        {
            strlcpy(pucTenantID, pstExtFlowNode->szTenantID, TENANT_ID_MAX+1);
            return 0;
        }
        
    }
    else
    {
        pstVPCFlowNdoe = _secpolicy_match_ip4_FindVxlanIDByPacket(pstSecPolicyPacketIP4);
        if (NULL != pstVPCFlowNdoe)
        {
            strlcpy(pucTenantID, pstExtFlowNode->szTenantID, TENANT_ID_MAX+1);
            return 0;
        }
    }

    return -1;
}

/* 查找策略节点 */
int secpolicy_find6_TenantID(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6, UCHAR *pucTenantID)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstExtFlowNode;
    SECPOLICY_VPC_FLOW_NODE_S * pstVPCFlowNdoe;

    if (0 == pstSecPolicyPacketIP6->uiVxlanID)
    {
        pstExtFlowNode = _secpolicy_match_ip6_FindTenantIDByPacket(pstSecPolicyPacketIP6);
        if (NULL != pstExtFlowNode)
        {
            strlcpy(pucTenantID, pstExtFlowNode->szTenantID, TENANT_ID_MAX+1);
            return 0;
        }
    }
    else
    {
        pstVPCFlowNdoe = _secpolicy_match_ip6_FindVxlanIDByPacket(pstSecPolicyPacketIP6);
        if (NULL != pstVPCFlowNdoe)
        {
            strlcpy(pucTenantID, pstExtFlowNode->szTenantID, TENANT_ID_MAX+1);
            return 0;
        }
    }

    return -1;
}

/* 匹配报文参数 */
SECPOLICY_CONF_RULE_NODE_S* _secpolicy_match_PacketInfoIP4(IN SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4, DTQ_HEAD_S *pstList)
{
    SECPOLICY_CONF_RULE_NODE_S *pstEntry, *pstMatchEntry = NULL;
    SECPOLICY_ICMP_S *pstIcmp;
    SECPOLICY_PORTRANGE_S *pstSPortRange, *pstDPortRange;
    UINT uiMask;
    UINT ui = 0;
    UINT uj = 0;
    UINT uk = 0;
    BOOL_T bIsAppMatch = BOOL_FALSE;
    DTQ_FOREACH_ENTRY(pstList, pstEntry, stNode)
    {
        if (BOOL_TRUE != pstEntry->bIsEnable)
        {
            continue;
        }

        if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SIP)
        {
            FWLIB_IP4ADDR_Len2Mask(pstEntry->stSrc.uiIPMaskLen, &uiMask);
            if ((pstEntry->stSrc._multi_ip4_addr & uiMask) != 
                (pstSecPolicyPacketIP4->stSrcIP.s_addr & uiMask))
            {
                continue;
            }
        }

        if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DIP)
        {
            FWLIB_IP4ADDR_Len2Mask(pstEntry->stSrc.uiIPMaskLen, &uiMask);
            if ((pstEntry->stDst._multi_ip4_addr & uiMask) != 
                (pstSecPolicyPacketIP4->stDstIP.s_addr & uiMask))
            {
                continue;
            }
        }

        if ((pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_APP) && (pstSecPolicyPacketIP4->uiAppID != 0))
        {
            /* -1 : ips apr failed */
            if (pstSecPolicyPacketIP4->uiAppID == APR_ID_OTHER)
            {
                continue;
            }

            /* Get the layer 5 APP ID, or 0 if no */
            uj = proto_relation_get(pstSecPolicyPacketIP4->uiAppID);

            while(pstEntry->szAppID[ui] != 0 && ui < SECPOLICY_APP_NUM_MAX)
            {
                if (pstEntry->szAppID[ui] == pstSecPolicyPacketIP4->uiAppID)
                {
                    bIsAppMatch = BOOL_TRUE;
                    break;
                }
                else if ((uj > 0) && (pstEntry->szAppID[ui] == uj))
                {
                    bIsAppMatch = BOOL_TRUE;
                    break;
                }
                else if ((uk = proto_relation_get(pstEntry->szAppID[ui]) > 0) && (uk == pstSecPolicyPacketIP4->uiAppID))
                {
                    bIsAppMatch = BOOL_TRUE;
                    break;
                }
                ui++;
            }

            if (BOOL_FALSE == bIsAppMatch)
            {
                continue;
            }

            printf("\nSecPolicy ipv4 rule %d matching app id %d\n", pstEntry->uiRuleID, pstEntry->szAppID[ui]);
        }

        if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SERVICE)
        {
            if (pstEntry->stL4Info.ucProtocol == INVALID_TCPIP_PROTOCOL_ID)
            {
                goto SECPOLICY_MATCH_SERVICE_ANY;
            }

            if (pstEntry->stL4Info.ucProtocol != pstSecPolicyPacketIP4->ucProtocol)
            {
                continue;
            }
        }

        if ((pstSecPolicyPacketIP4->ucProtocol == IPPROTO_ICMP) && 
            (pstEntry->uiKeyMask & (SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE | SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE)))
        {
            pstIcmp = &pstEntry->stL4Info.stIcmp;
            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE)
            {
                if (pstIcmp->ucType != pstSecPolicyPacketIP4->stIcmp.ucType)
                {
                    continue;
                }
            }

            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE)
            {
                if (pstIcmp->ucCode != pstSecPolicyPacketIP4->stIcmp.ucCode)
                {
                    continue;
                }
            }
        }
        else if ((pstSecPolicyPacketIP4->ucProtocol == IPPROTO_TCP) || (pstSecPolicyPacketIP4->ucProtocol == IPPROTO_UDP))
        {
            pstSPortRange = &pstEntry->stL4Info.stPortRange.stSRange;
            pstDPortRange = &pstEntry->stL4Info.stPortRange.stDRange;
            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SPORT)
            {
                if ((pstSecPolicyPacketIP4->usSPort < pstSPortRange->usSPort) || 
                    (pstSecPolicyPacketIP4->usSPort > pstSPortRange->usDPort))
                {
                    continue;
                }    
            }

            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DPORT)
            {
                if ((pstSecPolicyPacketIP4->usDPort < pstDPortRange->usSPort) ||
                    (pstSecPolicyPacketIP4->usDPort > pstDPortRange->usDPort))
                {
                    continue;
                }
            }
            
        }

SECPOLICY_MATCH_SERVICE_ANY:
        pstMatchEntry = pstEntry;
        break;
    }

    return pstMatchEntry;
}

/* 匹配报文参数 */
SECPOLICY_CONF_RULE_NODE_S* _secpolicy_match_PacketInfoIP6(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6, DTQ_HEAD_S *pstList)
{
    SECPOLICY_CONF_RULE_NODE_S *pstEntry, *pstMatchEntry = NULL;
    SECPOLICY_ICMP_S *pstIcmp;
    SECPOLICY_PORTRANGE_S *pstSPortRange, *pstDPortRange;
    struct in6_addr  stMask;
    UINT ui = 0, uj = 0, uk = 0;
    BOOL_T bIsAppMatch = BOOL_FALSE;
    DTQ_FOREACH_ENTRY(pstList, pstEntry, stNode)
    {
        if (BOOL_TRUE != pstEntry->bIsEnable)
        {
            continue;
        }

        if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SIP)
        {
            FWLIB_IP6ADDR_Len2Mask(pstEntry->stSrc.uiIPMaskLen, &stMask);
            if (BOOL_TRUE != FWLIB_IP6_COMPARE(&pstEntry->stSrc._multi_ip.stIPAddr._ip_data.stIP6Addr, &pstSecPolicyPacketIP6->stSrcIP6, &stMask))
            {
                continue;
            }
        }

        if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DIP)
        {
            FWLIB_IP6ADDR_Len2Mask(pstEntry->stDst.uiIPMaskLen, &stMask);
            if (BOOL_TRUE != FWLIB_IP6_COMPARE(&pstEntry->stDst._multi_ip.stIPAddr._ip_data.stIP6Addr, &pstSecPolicyPacketIP6->stDstIP6, &stMask))
            {
                continue;
            }
        }

        if ((pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_APP) && (pstSecPolicyPacketIP6->uiAppID != 0))
        {
            /* -1 : ips apr failed */
            if (pstSecPolicyPacketIP6->uiAppID == APR_ID_OTHER)
            {
                continue;
            }

            /* Get the layer 5 APP ID, or 0 if no */
            uj = proto_relation_get(pstSecPolicyPacketIP6->uiAppID);

            while(pstEntry->szAppID[ui] != 0 && ui < SECPOLICY_APP_NUM_MAX)
            {
                if (pstEntry->szAppID[ui] == pstSecPolicyPacketIP6->uiAppID)
                {
                    bIsAppMatch = BOOL_TRUE;
                    break;
                }
                else if ((uj > 0) && (pstEntry->szAppID[ui] == uj))
                {
                    bIsAppMatch = BOOL_TRUE;
                    break;
                }
                else if ((uk = proto_relation_get(pstEntry->szAppID[ui]) > 0) && (uk == pstSecPolicyPacketIP6->uiAppID))
                {
                    bIsAppMatch = BOOL_TRUE;
                    break;
                }
                ui++;
            }

            if (BOOL_FALSE == bIsAppMatch)
            {
                continue;
            }

            printf("\nSecPolicy ipv6 rule %d matching app id %d\n", pstEntry->uiRuleID, pstEntry->szAppID[ui]);
        }

        if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SERVICE)
        {
            if (pstEntry->stL4Info.ucProtocol == INVALID_TCPIP_PROTOCOL_ID)
            {
                goto SECPOLICY_MATCH_SERVICE_ANY;
            }

            if (pstEntry->stL4Info.ucProtocol != pstSecPolicyPacketIP6->ucProtocol)
            {
                continue;
            }
        }


        if ((pstSecPolicyPacketIP6->ucProtocol == IPPROTO_ICMP) && 
            (pstEntry->uiKeyMask & (SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE | SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE)))
        {
            pstIcmp = &pstEntry->stL4Info.stIcmp;
            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE)
            {
                if (pstIcmp->ucType != pstSecPolicyPacketIP6->stIcmp.ucType)
                {
                    continue;
                }
            }

            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE)
            {
                if (pstIcmp->ucCode != pstSecPolicyPacketIP6->stIcmp.ucCode)
                {
                    continue;
                }
            }
        }
        else if ((pstSecPolicyPacketIP6->ucProtocol == IPPROTO_TCP) || (pstSecPolicyPacketIP6->ucProtocol == IPPROTO_UDP))
        {
            pstSPortRange = &pstEntry->stL4Info.stPortRange.stSRange;
            pstDPortRange = &pstEntry->stL4Info.stPortRange.stDRange;
            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SPORT)
            {
                if ((pstSecPolicyPacketIP6->usSPort < pstSPortRange->usSPort) || 
                    (pstSecPolicyPacketIP6->usSPort > pstSPortRange->usDPort))
                {
                    continue;
                }    
            }

            if (pstEntry->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DPORT)
            {
                if ((pstSecPolicyPacketIP6->usDPort < pstDPortRange->usSPort) ||
                    (pstSecPolicyPacketIP6->usDPort > pstDPortRange->usDPort))
                {
                    continue;
                }
            }            
        }

SECPOLICY_MATCH_SERVICE_ANY:
        pstMatchEntry = pstEntry;
        break;
    }

    return pstMatchEntry;
}

/* 打印调试接口 */
VOID DBG_packet_printf(IN SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4,
                       IN SECPOLICY_CONF_RULE_NODE_S *pstMatchEntry)
{

    CHAR cStr[INET6_ADDRSTRLEN] = "\0";

    printf("\nPacket Matching Result: %s\n", pstMatchEntry == NULL ? "Drop" : \
                                           pstMatchEntry->enActionType == SECPOLICY_ACTION_DENY ? "Drop" : "Pass");
    printf("Packet Matching info:\n");
    inet_ntop(AF_INET, &pstSecPolicyPacketIP4->stSrcIP, cStr, INET6_ADDRSTRLEN);
    printf("SrcIP:%s\n",cStr);

    inet_ntop(AF_INET, &pstSecPolicyPacketIP4->stDstIP, cStr, INET6_ADDRSTRLEN);
    printf("DstIP:%s\n",cStr);

    printf("Protocol:%s\n", ((pstSecPolicyPacketIP4->ucProtocol == 1) || (pstSecPolicyPacketIP4->ucProtocol == 58)) ? "ICMP" : \
                             pstSecPolicyPacketIP4->ucProtocol == 6    ? "TCP" : \
                             pstSecPolicyPacketIP4->ucProtocol == 17   ? "UDP" : "Any");

    printf("SPort:%d\nDPort:%d\n", pstSecPolicyPacketIP4->usSPort, pstSecPolicyPacketIP4->usDPort);

    printf("ICMP type/code : %d/%d\n", pstSecPolicyPacketIP4->stIcmp.ucType, pstSecPolicyPacketIP4->stIcmp.ucCode);

    printf("uiVxLanID:%d\nMatching Rule ID:%d\n", pstSecPolicyPacketIP4->uiVxlanID, 
                                                pstMatchEntry == NULL ? 0 : pstMatchEntry->uiRuleID);
    
    
    return;

}

/* 打印调试接口 */
VOID DBG_packet6_printf(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6,
                        IN SECPOLICY_CONF_RULE_NODE_S *pstMatchEntry)
{

    CHAR cStr[INET6_ADDRSTRLEN] = "\0";

    printf("\nPacket Matching Result: %s\n", pstMatchEntry == NULL ? "Drop" : \
                                           pstMatchEntry->enActionType == SECPOLICY_ACTION_DENY ? "Drop" : "Pass");
    printf("Packet Matching info:\n");
    inet_ntop(AF_INET6, &pstSecPolicyPacketIP6->stSrcIP6, cStr, INET6_ADDRSTRLEN);
    printf("SrcIP6:%s\n",cStr);

    inet_ntop(AF_INET6, &pstSecPolicyPacketIP6->stDstIP6, cStr, INET6_ADDRSTRLEN);
    printf("DstIP6:%s\n",cStr);

    printf("Protocol:%s\n", ((pstSecPolicyPacketIP6->ucProtocol == 1) || (pstSecPolicyPacketIP6->ucProtocol == 58)) ? "ICMP" : \
                             pstSecPolicyPacketIP6->ucProtocol == 6    ? "TCP" : \
                             pstSecPolicyPacketIP6->ucProtocol == 17   ? "UDP" : "Any");

    printf("SPort:%d\nDPort:%d\n", pstSecPolicyPacketIP6->usSPort, pstSecPolicyPacketIP6->usDPort);

    printf("ICMP type/code : %d/%d\n", pstSecPolicyPacketIP6->stIcmp.ucType, pstSecPolicyPacketIP6->stIcmp.ucCode);

    printf("uiVxLanID:%d\nMatching Rule ID:%d\n", pstSecPolicyPacketIP6->uiVxlanID, 
                                                pstMatchEntry == NULL ? 0 : pstMatchEntry->uiRuleID);
    
    
    return;

}


/* 全局开关是否需要做安全策略 */
BOOL_T g_bIsSecPolicyStatusOn = BOOL_TRUE;

SECPOLICY_ACTION_E SecPolicy_Match_IP4(IN SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4)
{
    SECPOLICY_CONF_RULE_NODE_S *pstMatchEntry = NULL;
    SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4 = *pstSecPolicyPacketIP4;

    /* 全局开关 */
    if (BOOL_FALSE == g_bIsSecPolicyStatusOn)
    {
        return SECPOLICY_ACTION_PERMIT;
    }
    
    stSecPolicyPacketIP4.uiVxlanID = stSecPolicyPacketIP4.uiVxlanID;
    stSecPolicyPacketIP4.usSPort = ntohs(stSecPolicyPacketIP4.usSPort);
    stSecPolicyPacketIP4.usDPort = ntohs(stSecPolicyPacketIP4.usDPort);

    SECPOLICY_ACTION_E enAction = SECPOLICY_ACTION_DENY;
    SECPOLICY_CONF_NODE_S *pstConfNode;
    pstConfNode = _secpolicy_match_ip4_FindCurConfList(&stSecPolicyPacketIP4);
    if (NULL != pstConfNode)
    {
        if (SECPOLICY_DIRECTION_IN2OUT == stSecPolicyPacketIP4.enFwDirect)
        {
            rte_rwlock_read_lock(&pstConfNode->rwlock_in2out);
            pstMatchEntry = _secpolicy_match_PacketInfoIP4(&stSecPolicyPacketIP4, &pstConfNode->stHeadIn2Out.stHead);
        }
        else if (SECPOLICY_DIRECTION_OUT2IN == stSecPolicyPacketIP4.enFwDirect)
        {
            rte_rwlock_read_lock(&pstConfNode->rwlock_out2in);
            pstMatchEntry = _secpolicy_match_PacketInfoIP4(&stSecPolicyPacketIP4, &pstConfNode->stHeadOut2In.stHead);
        }
        
        if (NULL != pstMatchEntry)
        {
            enAction = pstMatchEntry->enActionType;
            if ((pstMatchEntry->bIsStatistics == BOOL_TRUE) &&  (NULL != pstMatchEntry->puiCount))
            {
                pstMatchEntry->puiCount[rte_lcore_id()-1]++;
            }
        }
        
        /* DBG */
        if (pstConfNode->uiDebug & SECPOLICY_DEBUG_PACKET)
        {
            DBG_packet_printf(&stSecPolicyPacketIP4,  pstMatchEntry);
        }

        if (SECPOLICY_DIRECTION_IN2OUT == stSecPolicyPacketIP4.enFwDirect)
        {
            rte_rwlock_read_unlock(&pstConfNode->rwlock_in2out);
        }
        else if (SECPOLICY_DIRECTION_OUT2IN == stSecPolicyPacketIP4.enFwDirect)
        {
            rte_rwlock_read_unlock(&pstConfNode->rwlock_out2in);
        }
    }


    return enAction;
}

SECPOLICY_ACTION_E SecPolicy_Match_IP6(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6)
{
    SECPOLICY_CONF_RULE_NODE_S *pstMatchEntry = NULL;
    SECPOLICY_PACKET_IP6_S stSecPolicyPacketIP6 = *pstSecPolicyPacketIP6;

    /* 全局开关 */
    if (BOOL_FALSE == g_bIsSecPolicyStatusOn)
    {
        return SECPOLICY_ACTION_PERMIT;
    }

    stSecPolicyPacketIP6.uiVxlanID = stSecPolicyPacketIP6.uiVxlanID;
    stSecPolicyPacketIP6.usSPort = ntohs(stSecPolicyPacketIP6.usSPort);
    stSecPolicyPacketIP6.usDPort = ntohs(stSecPolicyPacketIP6.usDPort);

    SECPOLICY_ACTION_E enAction = SECPOLICY_ACTION_DENY;
    SECPOLICY_CONF_NODE_S *pstConfNode;


    pstConfNode = _secpolicy_match_ip6_FindCurConfList(&stSecPolicyPacketIP6);
    if (NULL != pstConfNode)
    {
        if (SECPOLICY_DIRECTION_IN2OUT == stSecPolicyPacketIP6.enFwDirect)
        {
            rte_rwlock_read_lock(&pstConfNode->rwlock_in2out);
            pstMatchEntry = _secpolicy_match_PacketInfoIP6(&stSecPolicyPacketIP6, &pstConfNode->stHeadIn2Out.stHead);
        }
        else if (SECPOLICY_DIRECTION_OUT2IN == stSecPolicyPacketIP6.enFwDirect)
        {
            rte_rwlock_read_lock(&pstConfNode->rwlock_out2in);
            pstMatchEntry = _secpolicy_match_PacketInfoIP6(&stSecPolicyPacketIP6, &pstConfNode->stHeadOut2In.stHead);
        }
        
        if (NULL != pstMatchEntry)
        {
            enAction = pstMatchEntry->enActionType;
            if ((pstMatchEntry->bIsStatistics == BOOL_TRUE) &&  (NULL != pstMatchEntry->puiCount))
            {
                pstMatchEntry->puiCount[rte_lcore_id()-1]++;
            }
        }
        
        /* DBG */
        if (pstConfNode->uiDebug & SECPOLICY_DEBUG_PACKET)
        {
            DBG_packet6_printf(&stSecPolicyPacketIP6,  pstMatchEntry);
        }

        if (SECPOLICY_DIRECTION_IN2OUT == stSecPolicyPacketIP6.enFwDirect)
        {
            rte_rwlock_read_unlock(&pstConfNode->rwlock_in2out);
        }
        else if (SECPOLICY_DIRECTION_OUT2IN == stSecPolicyPacketIP6.enFwDirect)
        {
            rte_rwlock_read_unlock(&pstConfNode->rwlock_out2in);
        }
    }

    return enAction;
}

BOOL_T SecPolicy_IP4_IsNeedAPR(IN unsigned int uiVrf, IN struct in_addr *pstSrcIP, IN struct in_addr *pstDstIP)
{
    SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4;
    SECPOLICY_CONF_NODE_S * pstConfNode;

    memset(&stSecPolicyPacketIP4, 0, sizeof(SECPOLICY_PACKET_IP4_S));

    if (uiVrf != 0)
    {
        stSecPolicyPacketIP4.uiVxlanID = uiVrf;
    }
    stSecPolicyPacketIP4.stSrcIP = *pstSrcIP;
    stSecPolicyPacketIP4.stDstIP = *pstDstIP;

    pstConfNode = _secpolicy_match_ip4_FindCurConfList(&stSecPolicyPacketIP4);
    if (NULL != pstConfNode)
    {
        if (stSecPolicyPacketIP4.enFwDirect == SECPOLICY_DIRECTION_IN2OUT)
        {
            if (rte_atomic16_read(&pstConfNode->stHeadIn2Out.stRuleCountOfRefApp) > 0)
            {
                return BOOL_TRUE;
            }
        }
        else
        {
            if (rte_atomic16_read(&pstConfNode->stHeadOut2In.stRuleCountOfRefApp) > 0)
            {
                return BOOL_TRUE;
            }
        }
    }

    return BOOL_FALSE;
}

BOOL_T SecPolicy_IP6_IsNeedAPR(IN unsigned int uiVrf, IN struct in6_addr *pstSrcIP6, IN struct in6_addr *pstDstIP6)
{
    SECPOLICY_PACKET_IP6_S stSecPolicyPacketIP6;
    SECPOLICY_CONF_NODE_S * pstConfNode;

    memset(&stSecPolicyPacketIP6, 0, sizeof(SECPOLICY_PACKET_IP6_S));

    if (uiVrf != 0)
    {
        stSecPolicyPacketIP6.uiVxlanID = uiVrf;
    }
    stSecPolicyPacketIP6.stSrcIP6 = *pstSrcIP6;
    stSecPolicyPacketIP6.stDstIP6 = *pstDstIP6;

    pstConfNode = _secpolicy_match_ip6_FindCurConfList(&stSecPolicyPacketIP6);
    if (NULL != pstConfNode)
    {
        if (stSecPolicyPacketIP6.enFwDirect == SECPOLICY_DIRECTION_IN2OUT)
        {
            if (rte_atomic16_read(&pstConfNode->stHeadIn2Out.stRuleCountOfRefApp) > 0)
            {
                return BOOL_TRUE;
            }
        }
        else
        {
            if (rte_atomic16_read(&pstConfNode->stHeadOut2In.stRuleCountOfRefApp) > 0)
            {
                return BOOL_TRUE;
            }
        }
    }

    return BOOL_FALSE;
}

SECPOLICY_DIRECTION_E SecPolicy_IP4_FlowDirect(unsigned int uiVxlanID, struct in_addr  stSrcIP,  struct in_addr stDstIP)
{
    SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4;

    memset(&stSecPolicyPacketIP4, 0, sizeof(stSecPolicyPacketIP4));
    stSecPolicyPacketIP4.stSrcIP = stSrcIP;
    stSecPolicyPacketIP4.stDstIP = stDstIP;
    stSecPolicyPacketIP4.uiVxlanID = uiVxlanID;

    if (0 == uiVxlanID)
    {
        (void)_secpolicy_match_ip4_FindTenantIDByPacket(&stSecPolicyPacketIP4);
        
    }
    else
    {
        (void)_secpolicy_match_ip4_FindVxlanIDByPacket(&stSecPolicyPacketIP4);
    }

    return stSecPolicyPacketIP4.enFwDirect;
}

SECPOLICY_DIRECTION_E SecPolicy_IP6_FlowDirect(unsigned int uiVxlanID, struct in6_addr stSrcIP6, struct in6_addr stDstIP6)
{
    SECPOLICY_PACKET_IP6_S stSecPolicyPacketIP6;
    
    memset(&stSecPolicyPacketIP6, 0, sizeof(stSecPolicyPacketIP6));
    stSecPolicyPacketIP6.stSrcIP6 = stSrcIP6;
    stSecPolicyPacketIP6.stDstIP6 = stDstIP6;
    stSecPolicyPacketIP6.uiVxlanID = uiVxlanID;

    if (0 == uiVxlanID)
    {
        (void)_secpolicy_match_ip6_FindTenantIDByPacket(&stSecPolicyPacketIP6);
        
    }
    else
    {
        (void)_secpolicy_match_ip6_FindVxlanIDByPacket(&stSecPolicyPacketIP6);
    }

    return stSecPolicyPacketIP6.enFwDirect;
}



