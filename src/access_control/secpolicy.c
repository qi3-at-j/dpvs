#include <stdio.h>
#include <stddef.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "error.h"
#include "secbasetype.h"
#include "flow.h"
#include "secpolicy_common.h"
#include "secpolicy.h"
#include "fw_lib.h"
#include "secpolicy_match.h"
#include "session_public.h"

#define IN6ADDR_SIZE8 8


VOID _secpolicy_extflow_FreeIPNode(IN SL_NODE_S * pstNode);
VOID _secpolicy_vpcflow_FreeIPNode(IN SL_NODE_S * pstNode);

SECPOLICY_TYPE_E g_enFwType = SECPOLICY_TYPE_VPCBODER;

VOID SecPolicy_SetFwType(SECPOLICY_TYPE_E enFwType)
{
    g_enFwType = enFwType;
}

SECPOLICY_TYPE_E  SecPolicy_GetFwType()
{
    return g_enFwType;
}

typedef struct tagSecPolicyConfCommon{
    SECPOLICY_TYPE_E enFwType;              /* 防火墙类型，南北�?SECPOLICY_TYPE_EXTBODER, 东西�?SECPOLICY_TYPE_VPCBODER */
    UINT uiVxlanID;                         /* SECPOLICY_TYPE_VPCBODER  */
    UCHAR  szTenantID[TENANT_ID_MAX+1];       /* SECPOLICY_TYPE_EXTBODER */
    SECPOLICY_DIRECTION_E   enFwDirect;     /* 内到�?SECPOLICY_DIRECTION_IN2OUT      外到�?SECPOLICY_DIRECTION_OUT2IN*/
    UINT uiIPType;                        /* IPPROTO_IPV4 = 4   PPROTO_IPV6 = 41 */
}SECPOLICY_CONF_COMMON_S;

/* 创建租户ID对应节点 */
SECPOLICY_EXT_FLOW_NODE_S * _secpolicy_extflow_MallocFlowNode(IN UCHAR *pucTenantID)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    
    pstSecPolicyFlow = (SECPOLICY_EXT_FLOW_NODE_S *)rte_malloc(NULL, sizeof(SECPOLICY_EXT_FLOW_NODE_S), 0);
    if (NULL != pstSecPolicyFlow)
    {
        memset(pstSecPolicyFlow, 0, sizeof(SECPOLICY_EXT_FLOW_NODE_S));
        strlcpy(pstSecPolicyFlow->szTenantID, pucTenantID, TENANT_ID_MAX+1);
        rte_rwlock_init(&pstSecPolicyFlow->rwlock_ext_flow);
        SL_AddHead(g_pstSecExtFlowHead,&pstSecPolicyFlow->stNode);
    }

    return pstSecPolicyFlow;
}

/* 释放租户ID对应节点内存 */
VOID _secpolicy_extflow_FreeFlowNode(IN SL_NODE_S * pstNode)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstData = NULL;
    if (NULL != pstNode)
    {
        pstData = SL_ENTRY(pstNode, SECPOLICY_EXT_FLOW_NODE_S, stNode);

        rte_rwlock_write_lock(&pstData->rwlock_ext_flow);
        SL_FreeAll(&pstData->stHead, _secpolicy_extflow_FreeIPNode);
        rte_rwlock_write_unlock(&pstData->rwlock_ext_flow);

        rte_free(pstData);
    }

    return ;
}


/* 通过租户ID找到对应节点 */
SECPOLICY_EXT_FLOW_NODE_S * _secpolicy_extflow_FindFlowNode(IN UCHAR *pucTenantID)
{
    SECPOLICY_EXT_FLOW_NODE_S *pstEntry, *pstCfg = NULL;
    SL_FOREACH_ENTRY(g_pstSecExtFlowHead, pstEntry, stNode)
    {
        if (0 == strncasecmp(pucTenantID, pstEntry->szTenantID, TENANT_ID_MAX+1))
        {
            pstCfg = pstEntry;
            break;
        }
    }

    return pstCfg;
}

/* 创建IP节点 */
SECPOLICY_IPADDR_NODE_S *_secpolicy_extflow_MallocIPNode(IN SL_HEAD_S *pstHead, IN IP_ADDR_S *pstIPAddr)
{
    SECPOLICY_IPADDR_NODE_S * pstSecPolicyIPNode = NULL;
        
    pstSecPolicyIPNode = (SECPOLICY_IPADDR_NODE_S *)rte_malloc(NULL, sizeof(SECPOLICY_IPADDR_NODE_S), 0);
    if (NULL != pstSecPolicyIPNode)
    {
        memset(pstSecPolicyIPNode, 0, sizeof(SECPOLICY_IPADDR_NODE_S));
        memcpy(&pstSecPolicyIPNode->stIPAddr, pstIPAddr, sizeof(SECPOLICY_IPADDR_NODE_S));
        SL_AddHead(pstHead, &pstSecPolicyIPNode->stNode);
    }

    return pstSecPolicyIPNode;
}

/* 释放IP节点 */
VOID _secpolicy_extflow_FreeIPNode(IN SL_NODE_S * pstNode)
{
    SECPOLICY_IPADDR_NODE_S * pstData = NULL;
    if (NULL != pstNode)
    {
        pstData = SL_ENTRY(pstNode, SECPOLICY_IPADDR_NODE_S, stNode);
        rte_free(pstData);
    }

    return ;
}

/* 查找指定租户节点上是否包含IP节点 */
SECPOLICY_IPADDR_NODE_S * _secpolicy_extflow_FindIPNode(IN SECPOLICY_EXT_FLOW_NODE_S *pstFlowNode, 
                                                      IN IP_ADDR_S *pstIPAddr)
{
    SECPOLICY_IPADDR_NODE_S *pstEntry, *pstCfg = NULL;
    SL_HEAD_S * pstHead = &pstFlowNode->stHead;
    SL_FOREACH_ENTRY(pstHead, pstEntry, stNode)
    {
        if (pstEntry->stIPAddr.uiIPType == pstIPAddr->uiIPType) 
        {
            if (((IPPROTO_IP == pstEntry->stIPAddr.uiIPType) &&
                (pstEntry->stIPAddr._ip4_addr == pstIPAddr->_ip4_addr)) ||
                ((IPPROTO_IPV6 == pstEntry->stIPAddr.uiIPType) &&
                (!strncasecmp(pstEntry->stIPAddr._ip6_addr, pstIPAddr->_ip6_addr, IN6ADDR_SIZE8))))
            {
                pstCfg = pstEntry;
                break;
            }
        }
        
    }

    return pstCfg;
}

/* 添加公网IP与租户ID的对应关�?*/
ULONG SecPolicy_ExtFlow_AddPubIP(IN UCHAR *pucTenantID, IN IP_ADDR_S *pstIPAddr)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    SECPOLICY_IPADDR_NODE_S * pstSecPlicyIP = NULL;

    pstSecPolicyFlow = _secpolicy_extflow_FindFlowNode(pucTenantID);
    if (NULL == pstSecPolicyFlow)
    {
        pstSecPolicyFlow = _secpolicy_extflow_MallocFlowNode(pucTenantID);
        if (NULL == pstSecPolicyFlow)
        {
            return ERROR_FAILED;
        }
    }

    rte_rwlock_write_lock(&pstSecPolicyFlow->rwlock_ext_flow);

    pstSecPlicyIP = _secpolicy_extflow_FindIPNode(pstSecPolicyFlow, pstIPAddr);
    if (NULL == pstSecPlicyIP)
    {
        (VOID)_secpolicy_extflow_MallocIPNode(&pstSecPolicyFlow->stHead, pstIPAddr);
        
    }

    rte_rwlock_write_unlock(&pstSecPolicyFlow->rwlock_ext_flow);

    return ERROR_SUCCESS;
}

/* 从租户节点上删除一个IP节点 */
VOID SecPolicy_ExtFlow_DelPubIP(IN UCHAR *pucTenantID, IN IP_ADDR_S *pstIPAddr)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    SECPOLICY_IPADDR_NODE_S * pstSecPlicyIP = NULL;

    /* 查找租户节点 */
    pstSecPolicyFlow = _secpolicy_extflow_FindFlowNode(pucTenantID);
    if (NULL != pstSecPolicyFlow)
    {
        rte_rwlock_write_lock(&pstSecPolicyFlow->rwlock_ext_flow);

        /* 查找租户节点上的IP节点 */
        pstSecPlicyIP = _secpolicy_extflow_FindIPNode(pstSecPolicyFlow, pstIPAddr);
        if (NULL != pstSecPlicyIP)
        {
            SL_Del(&pstSecPolicyFlow->stHead, &pstSecPlicyIP->stNode);
            rte_free(pstSecPlicyIP);
        }

        rte_rwlock_write_unlock(&pstSecPolicyFlow->rwlock_ext_flow);
    }

    return;
}

/* 删除租户节点及节点内的全部IP节点 */
VOID SecPolicy_ExtFlow_DelTenantID(IN UCHAR *pucTenantID)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstSecPolicyFlow = NULL;

    /* 查找租户节点 */
    pstSecPolicyFlow = _secpolicy_extflow_FindFlowNode(pucTenantID);
    if (NULL != pstSecPolicyFlow)
    {
        rte_rwlock_write_lock(&pstSecPolicyFlow->rwlock_ext_flow);

        SL_FreeAll(&pstSecPolicyFlow->stHead, _secpolicy_extflow_FreeIPNode);

        rte_rwlock_write_unlock(&pstSecPolicyFlow->rwlock_ext_flow);

        SL_Del(g_pstSecExtFlowHead, &pstSecPolicyFlow->stNode);

        rte_free(pstSecPolicyFlow);
    }

    return;
}

/* 删除全部租户节点及节点内全部IP节点 */
VOID SecPolicy_ExtFlow_DelAllTenantID()
{
    SL_FreeAll(g_pstSecExtFlowHead, _secpolicy_extflow_FreeFlowNode);
    return;
}


VOID SecPolicy_ExtFlow_ShowTenantID(IN unsigned char *pucTenantID, IN unsigned int uiIPType)
{
    SECPOLICY_EXT_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    SECPOLICY_IPADDR_NODE_S * pstNode = NULL;
    UCHAR ucStr[INET6_ADDRSTRLEN] = "\0";

    /* 查找VPC节点 */
    pstSecPolicyFlow = _secpolicy_extflow_FindFlowNode(pucTenantID);
    if (NULL != pstSecPolicyFlow)
    {
        rte_rwlock_read_lock(&pstSecPolicyFlow->rwlock_ext_flow);

        printf("Tenant:%s\n",pucTenantID);
        SL_FOREACH(&pstSecPolicyFlow->stHead , pstNode)
        {
            if ((pstNode->stIPAddr.uiIPType == IPPROTO_IP) && (uiIPType == IPPROTO_IP))
            {
                inet_ntop(AF_INET, &pstNode->stIPAddr._ip_data.stIP4Addr, ucStr, INET6_ADDRSTRLEN);
                printf("\tIP:%s\n",ucStr);
            }
            else if ((pstNode->stIPAddr.uiIPType == IPPROTO_IPV6) && (uiIPType == IPPROTO_IPV6))
            {
                inet_ntop(AF_INET6, &pstNode->stIPAddr._ip_data.stIP6Addr, ucStr, INET6_ADDRSTRLEN);
                printf("\tIP6:%s\n",ucStr);
            }
        }

        rte_rwlock_read_unlock(&pstSecPolicyFlow->rwlock_ext_flow);
    }
    else
    {
        printf("None Configuration data\n");
    }

    return;
}


/* 创建VPC ID对应节点 */
SECPOLICY_VPC_FLOW_NODE_S * _secpolicy_vpcflow_MallocFlowNode(IN UINT uiVxlanID)
{
    SECPOLICY_VPC_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    
    pstSecPolicyFlow = (SECPOLICY_VPC_FLOW_NODE_S *)rte_malloc(NULL, sizeof(SECPOLICY_VPC_FLOW_NODE_S), 0);
    if (NULL != pstSecPolicyFlow)
    {
        memset(pstSecPolicyFlow, 0, sizeof(SECPOLICY_VPC_FLOW_NODE_S));
        pstSecPolicyFlow->uiVxlanID = uiVxlanID;
        rte_rwlock_init(&pstSecPolicyFlow->rwlock_vpc_flow);
        SL_AddHead(g_pstSecVPCFlowHead,&pstSecPolicyFlow->stNode);
    }

    return pstSecPolicyFlow;
}

/* 释放VPC对应节点内存 */
VOID _secpolicy_vpcflow_FreeFlowNode(IN SL_NODE_S * pstNode)
{
    SECPOLICY_VPC_FLOW_NODE_S * pstData = NULL;
    if (NULL != pstNode)
    {
        pstData = SL_ENTRY(pstNode, SECPOLICY_VPC_FLOW_NODE_S, stNode);

        rte_rwlock_write_lock(&pstData->rwlock_vpc_flow);
        SL_FreeAll(&pstData->stHead, _secpolicy_vpcflow_FreeIPNode);

        rte_rwlock_write_unlock(&pstData->rwlock_vpc_flow);

        rte_free(pstData);
    }

    return ;
}

/* 通过VPC ID找到对应节点 */
SECPOLICY_VPC_FLOW_NODE_S * _secpolicy_vpcflow_FindFlowNode(IN UINT uiVxlanID)
{
    SECPOLICY_VPC_FLOW_NODE_S *pstEntry, *pstCfg = NULL;
    SL_FOREACH_ENTRY(g_pstSecVPCFlowHead, pstEntry, stNode)
    {
        if (uiVxlanID == pstEntry->uiVxlanID)
        {
            pstCfg = pstEntry;
            break;
        }
    }

    return pstCfg;
}
/* 创建IPMask节点 */
SECPOLICY_IPADDR_MASK_NODE_S *_secpolicy_vpcflow_MallocIPNode(IN SL_HEAD_S *pstHead, 
                                                              IN IP_ADDR_MASK_S *pstIPAddrMask)
{
    SECPOLICY_IPADDR_MASK_NODE_S * pstSecPolicyIPNode = NULL;
        
    pstSecPolicyIPNode = (SECPOLICY_IPADDR_MASK_NODE_S *)rte_malloc(NULL, sizeof(SECPOLICY_IPADDR_MASK_NODE_S), 0);
    if (NULL != pstSecPolicyIPNode)
    {
        memset(pstSecPolicyIPNode, 0, sizeof(SECPOLICY_IPADDR_MASK_NODE_S));
        memcpy(&pstSecPolicyIPNode->stIPAddrMask, pstIPAddrMask, sizeof(SECPOLICY_IPADDR_MASK_NODE_S));
        SL_AddHead(pstHead, &pstSecPolicyIPNode->stNode);
    }

    return pstSecPolicyIPNode;
}

/* 释放IPMask节点 */
VOID _secpolicy_vpcflow_FreeIPNode(IN SL_NODE_S * pstNode)
{
    SECPOLICY_IPADDR_MASK_NODE_S * pstData = NULL;
    if (NULL != pstNode)
    {
        pstData = SL_ENTRY(pstNode, SECPOLICY_IPADDR_MASK_NODE_S, stNode);
        rte_free(pstData);
    }

    return ;
}

/* 查找指定VPC节点上是否包含IPMask节点 */
SECPOLICY_IPADDR_MASK_NODE_S * _secpolicy_vpcflow_FindIPNode(IN SECPOLICY_VPC_FLOW_NODE_S *pstFlowNode, 
                                                      IN IP_ADDR_MASK_S *pstIPAddrMask)
{
    SECPOLICY_IPADDR_MASK_NODE_S *pstEntry, *pstCfg = NULL;
    SL_HEAD_S * pstHead = &pstFlowNode->stHead;
    IP_ADDR_S *pstIPAddr;
    UINT uiMaskLen;
    SL_FOREACH_ENTRY(pstHead, pstEntry, stNode)
    {
        pstIPAddr = &pstEntry->stIPAddrMask.stIPAddr;
        uiMaskLen = pstEntry->stIPAddrMask.uiIPMaskLen;
        if (pstIPAddr->uiIPType == pstIPAddrMask->stIPAddr.uiIPType) 
        {
            if (((IPPROTO_IP == pstIPAddr->uiIPType) &&
                (pstIPAddr->_ip4_addr == pstIPAddrMask->stIPAddr._ip4_addr) &&
                (uiMaskLen == pstIPAddrMask->uiIPMaskLen)) ||
                ((IPPROTO_IPV6 == pstIPAddr->uiIPType) &&
                (!strncasecmp(pstIPAddr->_ip6_addr, pstIPAddrMask->stIPAddr._ip6_addr, IN6ADDR_SIZE8)) &&
                (uiMaskLen == pstIPAddrMask->uiIPMaskLen)))
            {
                pstCfg = pstEntry;
                break;
            }
        }
        
    }

    return pstCfg;
}

/* 添加公网IP与vni的对应关�?*/
ULONG SecPolicy_VPCFlow_AddPubIP(IN UINT uiVxlanID, IN IP_ADDR_MASK_S *pstIPAddrMask)
{
    SECPOLICY_VPC_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    SECPOLICY_IPADDR_MASK_NODE_S * pstSecPlicyIP = NULL;

    pstSecPolicyFlow = _secpolicy_vpcflow_FindFlowNode(uiVxlanID);
    if (NULL == pstSecPolicyFlow)
    {
        pstSecPolicyFlow = _secpolicy_vpcflow_MallocFlowNode(uiVxlanID);
        if (NULL == pstSecPolicyFlow)
        {
            return ERROR_FAILED;
        }
    }

    rte_rwlock_write_lock(&pstSecPolicyFlow->rwlock_vpc_flow);
    pstSecPlicyIP = _secpolicy_vpcflow_FindIPNode(pstSecPolicyFlow, pstIPAddrMask);
    if (NULL == pstSecPlicyIP)
    {
        (VOID)_secpolicy_vpcflow_MallocIPNode(&pstSecPolicyFlow->stHead, pstIPAddrMask);
        
    }
    rte_rwlock_write_unlock(&pstSecPolicyFlow->rwlock_vpc_flow);

    return ERROR_SUCCESS;
}

/* 从VPC节点上删除一个IPMask节点 */
VOID SecPolicy_VPCFlow_DelPubIP(IN UINT uiVxlanID, IN IP_ADDR_MASK_S *pstIPAddrMask)
{
    SECPOLICY_VPC_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    SECPOLICY_IPADDR_MASK_NODE_S * pstSecPlicyIP = NULL;

    /* 查找租户节点 */
    pstSecPolicyFlow = _secpolicy_vpcflow_FindFlowNode(uiVxlanID);
    if (NULL != pstSecPolicyFlow)
    {
        /* 查找VPC节点上的IP节点 */
        pstSecPlicyIP = _secpolicy_vpcflow_FindIPNode(pstSecPolicyFlow, pstIPAddrMask);
        if (NULL != pstSecPlicyIP)
        {
            rte_rwlock_write_lock(&pstSecPolicyFlow->rwlock_vpc_flow);
            SL_Del(&pstSecPolicyFlow->stHead, &pstSecPlicyIP->stNode);
            rte_free(pstSecPlicyIP);
            rte_rwlock_write_unlock(&pstSecPolicyFlow->rwlock_vpc_flow);
        }

/*
        if (SL_IsEmpty(&pstSecPolicyFlow->stHead))
        {
            SL_Del(g_pstSecVPCFlowHead, &pstSecPolicyFlow->stNode);
            rte_free(pstSecPolicyFlow);
        }
*/
    }

    return;
}

/* 删除VPC节点及节点内的全部子网IP节点 */
VOID SecPolicy_VPCFlow_DelVxlanID(IN UINT uiVxlanID)
{
    SECPOLICY_VPC_FLOW_NODE_S * pstSecPolicyFlow = NULL;

    /* 查找VPC节点 */
    pstSecPolicyFlow = _secpolicy_vpcflow_FindFlowNode(uiVxlanID);
    if (NULL != pstSecPolicyFlow)
    {
        rte_rwlock_write_lock(&pstSecPolicyFlow->rwlock_vpc_flow);
        SL_FreeAll(&pstSecPolicyFlow->stHead, _secpolicy_vpcflow_FreeIPNode);
        rte_rwlock_write_unlock(&pstSecPolicyFlow->rwlock_vpc_flow);

        SL_Del(g_pstSecVPCFlowHead, &pstSecPolicyFlow->stNode);
        rte_free(pstSecPolicyFlow);
    }

    return;
}

/* 删除全部VPC节点及节点内全部子网IP节点 */
VOID SecPolicy_VPCFlow_DelAllVxlanID()
{
    SL_FreeAll(g_pstSecVPCFlowHead, _secpolicy_vpcflow_FreeFlowNode);
    return;
}

VOID SecPolicy_VPCFlow_ShowVxlanID(IN UINT uiVxlanID, IN UINT uiIPType)
{
    SECPOLICY_VPC_FLOW_NODE_S * pstSecPolicyFlow = NULL;
    SECPOLICY_IPADDR_MASK_NODE_S * pstNode = NULL;
    UCHAR ucStr[INET6_ADDRSTRLEN] = "\0";

    /* 查找VPC节点 */
    pstSecPolicyFlow = _secpolicy_vpcflow_FindFlowNode(uiVxlanID);
    if (NULL != pstSecPolicyFlow)
    {
        rte_rwlock_read_lock(&pstSecPolicyFlow->rwlock_vpc_flow);

        printf("ID:%d\n",uiVxlanID);
        SL_FOREACH(&pstSecPolicyFlow->stHead , pstNode)
        {
            if ((pstNode->stIPAddrMask.stIPAddr.uiIPType == IPPROTO_IP) && (uiIPType == IPPROTO_IP))
            {
                inet_ntop(AF_INET, &pstNode->stIPAddrMask.stIPAddr._ip_data.stIP4Addr, ucStr, INET6_ADDRSTRLEN);
                printf("\tIP/Mask:%s/%d\n",ucStr, pstNode->stIPAddrMask.uiIPMaskLen);
            }
            else if ((pstNode->stIPAddrMask.stIPAddr.uiIPType == IPPROTO_IPV6) && (uiIPType == IPPROTO_IPV6))
            {
                inet_ntop(AF_INET6, &pstNode->stIPAddrMask.stIPAddr._ip_data.stIP6Addr, ucStr, INET6_ADDRSTRLEN);
                printf("\tIP6/Mask:%s/%d\n",ucStr, pstNode->stIPAddrMask.uiIPMaskLen);
            }
        }

        rte_rwlock_read_unlock(&pstSecPolicyFlow->rwlock_vpc_flow);
    }
    else
    {
        printf("None Configuration data\n");
    }

    return;
}

/***************************************
策略规则操作接口
***************************************/

#define SECPOLICY_GET_CONF_SL_HEAD(uiFwType, uiIPType, pstList) \
{\
    if (SECPOLICY_TYPE_EXTBODER == uiFwType) \
    { \
        if (IPPROTO_IP == uiIPType) {pstList = g_pstExtSecConfHeadIP4;} \
        else if (IPPROTO_IPV6 == uiIPType) {pstList = g_pstExtSecConfHeadIP6;} \
    } \
    else if (SECPOLICY_TYPE_VPCBODER == uiFwType) \
    { \
        if (IPPROTO_IP == uiIPType) {pstList = g_pstVPCSecConfHeadIP4;} \
        else if (IPPROTO_IPV6 == uiIPType) {pstList = g_pstVPCSecConfHeadIP6;} \
    } \
}

/* 查找规则节点 */
SECPOLICY_CONF_RULE_NODE_S *_secpolicy_conf_FindRuleNode(IN DTQ_HEAD_S *pstHead, IN UINT uiRuleID)
{
    SECPOLICY_CONF_RULE_NODE_S *pstCurEntry, *pstEntry = NULL;
    DTQ_FOREACH_ENTRY(pstHead,pstCurEntry,stNode)
    {
        if (uiRuleID == pstCurEntry->uiRuleID)
        {
            pstEntry = pstCurEntry;
            break;
        }
    }

    return pstEntry;
}

/* 申请规则节点  */
SECPOLICY_CONF_RULE_NODE_S *_secpolicy_conf_MallocRuleNode(IN SECPOLICY_CONF_RULE_S * pstConfRule,
                                                           IN SECPOLICY_RULE_CFG_S *pstRuleCfg)
{
    SECPOLICY_CONF_RULE_NODE_S *pstConfRuleNode = NULL;
    UINT64 *puiCount = NULL;
    UINT uiCoreSum = rte_lcore_count()-1;
    pstConfRuleNode = (SECPOLICY_CONF_RULE_NODE_S *)rte_malloc(NULL, sizeof(SECPOLICY_CONF_RULE_NODE_S), 0);
    puiCount = (UINT64 *)rte_malloc(NULL, sizeof(UINT64) * uiCoreSum, 0);
    
    if ((NULL != pstConfRuleNode) && (NULL != puiCount))
    {
        memset(pstConfRuleNode, 0, sizeof(SECPOLICY_CONF_RULE_NODE_S));
        memset(puiCount, 0, sizeof(sizeof(UINT64) * uiCoreSum));
        pstConfRuleNode->uiRuleID = pstRuleCfg->uiRuleID;
        pstConfRuleNode->enActionType = pstRuleCfg->enActionType;
        pstConfRuleNode->stSrc  = pstRuleCfg->stSrc;
        pstConfRuleNode->stDst =  pstRuleCfg->stDst;
        pstConfRuleNode->stL4Info = pstRuleCfg->stL4Info;
        pstConfRuleNode->bIsEnable = pstRuleCfg->bIsEnable;
        pstConfRuleNode->uiKeyMask = pstRuleCfg->uiKeyMask;
        strlcpy(pstConfRuleNode->szDescInfo, pstRuleCfg->szDescInfo, SECPOLICY_RULE_DECRIPTION_MAX + 1);
        strlcpy(pstConfRuleNode->szAppID, pstRuleCfg->szAppID, strlen(pstRuleCfg->szAppID));
        pstConfRuleNode->puiCount = puiCount;
        
        DTQ_AddTail(&pstConfRule->stHead, &pstConfRuleNode->stNode);
        pstConfRule->uiSum++;

        if ((pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_APP) && 
            (pstConfRuleNode->bIsEnable == BOOL_TRUE))
        {
            rte_atomic16_inc(&pstConfRule->stRuleCountOfRefApp);
        }
    }
    else
    {
        if (NULL != pstConfRuleNode)
        {
            rte_free(pstConfRuleNode);
        }

        if (NULL != puiCount)
        {
            rte_free(puiCount);
        }
    }

    return pstConfRuleNode;
}

/* 释放规则节点     */
VOID _secpolicy_conf_FreeRuleNode(IN DTQ_NODE_S *pstNode)
{
    SECPOLICY_CONF_RULE_NODE_S *pstConfRule = NULL;

    if (NULL != pstNode)
    {
        pstConfRule = DTQ_ENTRY(pstNode, SECPOLICY_CONF_RULE_NODE_S, stNode);
        if (NULL != pstConfRule->puiCount)
        {
            rte_free(pstConfRule->puiCount);
        }
        rte_free(pstConfRule);
    }
    return;
}

/* 查找租户ID或vni对应策略节点 */
SECPOLICY_CONF_NODE_S *_secpolicy_conf_FindConfNode(IN SECPOLICY_CONF_COMMON_S *pstRuleCfg)
{
    SL_HEAD_S * pstHead = NULL;
    SECPOLICY_CONF_NODE_S *pstCurConf = NULL;

    SECPOLICY_GET_CONF_SL_HEAD(pstRuleCfg->enFwType, pstRuleCfg->uiIPType, pstHead);

    if (NULL == pstHead)
    {
        return NULL;
    }

    if (SECPOLICY_TYPE_EXTBODER == pstRuleCfg->enFwType)
    {
        SL_FOREACH_ENTRY(pstHead, pstCurConf, stNode)
        {
            if (!strncasecmp(pstCurConf->szTenantID, pstRuleCfg->szTenantID, TENANT_ID_MAX+1))
            {
                return pstCurConf;
            }
        }
    }
    else if (SECPOLICY_TYPE_VPCBODER == pstRuleCfg->enFwType)
    {
        SL_FOREACH_ENTRY(pstHead, pstCurConf, stNode)
        {
            if (pstRuleCfg->uiVxlanID == pstCurConf->uiVxlanID)
            {
                return pstCurConf;
            }
        }
    }

    return NULL;
}

/* 申请策略节点 */
SECPOLICY_CONF_NODE_S *_secpolicy_conf_MallocNode(IN SECPOLICY_TYPE_E enFwType,
                                                  IN UCHAR *pucTenantID,
                                                  IN UINT uiVxlanID,
                                                  IN UINT uiIPType)
{
    SECPOLICY_CONF_NODE_S * pstConf = NULL;
    SL_HEAD_S *pstListIP4, *pstListIP6;
    pstConf = (SECPOLICY_CONF_NODE_S *)rte_malloc(NULL, sizeof(SECPOLICY_CONF_NODE_S), 0);
    if (NULL != pstConf)
    {
        memset(pstConf, 0, sizeof(SECPOLICY_CONF_NODE_S));
        DTQ_Init(&pstConf->stHeadIn2Out.stHead);
        DTQ_Init(&pstConf->stHeadOut2In.stHead);
        rte_rwlock_init(&pstConf->rwlock_in2out);
        rte_rwlock_init(&pstConf->rwlock_out2in);
        if (SECPOLICY_TYPE_EXTBODER == enFwType)
        {
            strlcpy(pstConf->szTenantID, pucTenantID, TENANT_ID_MAX+1);
            pstListIP4 = g_pstExtSecConfHeadIP4;
            pstListIP6 = g_pstExtSecConfHeadIP6;
        }
        else if (SECPOLICY_TYPE_VPCBODER == enFwType)
        {
            pstConf->uiVxlanID = uiVxlanID;
            pstListIP4 = g_pstVPCSecConfHeadIP4;
            pstListIP6 = g_pstVPCSecConfHeadIP6;
        }

        if (IPPROTO_IP == uiIPType)
        {
            SL_AddHead(pstListIP4,&pstConf->stNode);
        }
        else if (IPPROTO_IPV6 == uiIPType)
        {
            SL_AddHead(pstListIP6,&pstConf->stNode);
        }
    }

    return pstConf;
}

/* 释放策略节点 */
VOID _secpolicy_conf_FreeNode(IN SL_NODE_S *pstNode)
{
    SECPOLICY_CONF_NODE_S *pstConf = NULL;
    if (NULL != pstNode)
    {
        pstConf = SL_ENTRY(pstNode, SECPOLICY_CONF_NODE_S, stNode);

        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
        DTQ_FreeAll(&pstConf->stHeadIn2Out.stHead, _secpolicy_conf_FreeRuleNode);
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);

        rte_rwlock_write_lock(&pstConf->rwlock_out2in);
        DTQ_FreeAll(&pstConf->stHeadOut2In.stHead, _secpolicy_conf_FreeRuleNode);
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);

        rte_free(pstConf);
    }
    return;
}

/* 添加规则节点 */
ULONG SecPolicy_Conf_AddRule(IN SECPOLICY_RULE_CFG_S *pstRuleCfg)
{
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_RULE_S * pstConfRule;
    SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode;
    SECPOLICY_CONF_COMMON_S stConfCommon;
    BOOL_T bIsUpdataSeq = BOOL_FALSE;

    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    stConfCommon.enFwDirect = pstRuleCfg->enFwDirect;
    stConfCommon.enFwType   = pstRuleCfg->enFwType;
    stConfCommon.uiIPType   = pstRuleCfg->uiIPType;
    stConfCommon.uiVxlanID  = pstRuleCfg->uiVxlanID;
    strlcpy(stConfCommon.szTenantID, pstRuleCfg->szTenantID, TENANT_ID_MAX+1);
    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        pstConf = _secpolicy_conf_MallocNode(pstRuleCfg->enFwType,
                                             pstRuleCfg->szTenantID,
                                             pstRuleCfg->uiVxlanID,
                                             pstRuleCfg->uiIPType);
        if (NULL == pstConf)
        {
            return ERROR_FAILED;
        }
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadIn2Out;
        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadOut2In;
        rte_rwlock_write_lock(&pstConf->rwlock_out2in);
    }

    pstConfRuleNode = _secpolicy_conf_FindRuleNode(&pstConfRule->stHead, pstRuleCfg->uiRuleID);
    if (NULL == pstConfRuleNode)
    {
        (VOID)_secpolicy_conf_MallocRuleNode(pstConfRule, pstRuleCfg);
        if (BOOL_TRUE ==  pstRuleCfg->bIsEnable)
        {
            /* Add valid rules to update the fast forwarding sequence number */
            bIsUpdataSeq = BOOL_TRUE;
        }
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);
    }

    if (bIsUpdataSeq == BOOL_TRUE)
    {
        ASPF_Inc_Cfg_Seq();
    }

    return ERROR_SUCCESS;    
}

/* 删除规则节点 */
ULONG SecPolicy_Conf_DelRule(IN SECPOLICY_RULE_CFG_S *pstRuleCfg)
{
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_RULE_S * pstConfRule;
    SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode;
    SECPOLICY_CONF_COMMON_S stConfCommon;
    BOOL_T bIsUpdateSeq = BOOL_FALSE;
    
    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    stConfCommon.enFwDirect = pstRuleCfg->enFwDirect;
    stConfCommon.enFwType   = pstRuleCfg->enFwType;
    stConfCommon.uiIPType   = pstRuleCfg->uiIPType;
    stConfCommon.uiVxlanID  = pstRuleCfg->uiVxlanID;
    strlcpy(stConfCommon.szTenantID, pstRuleCfg->szTenantID, TENANT_ID_MAX+1);
    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        return ERROR_NOT_FOUND;
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadIn2Out;
        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadOut2In;
        rte_rwlock_write_lock(&pstConf->stHeadOut2In);
    }

    pstConfRuleNode = _secpolicy_conf_FindRuleNode(&pstConfRule->stHead, pstRuleCfg->uiRuleID);
    if (NULL != pstConfRuleNode)
    {
        DTQ_Del(&pstConfRuleNode->stNode);
        pstConfRule->uiSum--;

        if (BOOL_TRUE ==  pstConfRuleNode->bIsEnable)
        {
            /* Del valid rules to update the fast forwarding sequence number */
            bIsUpdateSeq = BOOL_TRUE;
        }

        if ((pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_APP) && 
            (pstConfRuleNode->bIsEnable == BOOL_TRUE))
        {
            rte_atomic16_dec(&pstConfRule->stRuleCountOfRefApp);
        }
        _secpolicy_conf_FreeRuleNode(&pstConfRuleNode->stNode);
        
    }


    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);
    }

    if (bIsUpdateSeq == BOOL_TRUE)
    {
        ASPF_Inc_Cfg_Seq();
    }

    return ERROR_SUCCESS; 
}

VOID _secpolicy_Conf_AppIDSort(IN USHORT *pstOld, IN USHORT *pstNew)
{
    USHORT szTmpAppID[SECPOLICY_APP_NUM_MAX];
    UINT   ui, uj, uk, uiCount = 0;
    BOOL_T bIsSwitch = BOOL_FALSE;

    memcpy(szTmpAppID, pstOld, sizeof(USHORT) * SECPOLICY_APP_NUM_MAX);

    while(szTmpAppID[uiCount] != 0)
    {
        uiCount++;
    }

    for(ui = 0; ui < uiCount; ui++)
    {
        for (uj = 0; uj < uiCount - ui - 1; uj++)
        {
            if (szTmpAppID[uj] > szTmpAppID[uj + 1])
            {
                bIsSwitch = BOOL_TRUE;
                uk = szTmpAppID[uj];
                szTmpAppID[uj] = szTmpAppID[uj + 1];
                szTmpAppID[uj + 1] = uk;
            }
        }
        
        if (!bIsSwitch)
        {
            break;
        }
        
    }

    ui = 0;
    uk = 0;
    while(szTmpAppID[ui] != 0)
    {
        if (uk != szTmpAppID[ui])
        {
            *(pstNew + ui) = szTmpAppID[ui];
            uk = szTmpAppID[ui];
        }
        ui++;
    }

    return;
    
}
BOOL_T _secpolicy_Conf_CompareAppID(IN USHORT *pusOldAPP, IN USHORT *pusNewAPP)
{
    
    USHORT szOldAppID[SECPOLICY_APP_NUM_MAX];
    USHORT szNewAppID[SECPOLICY_APP_NUM_MAX];
    UINT ui=0;
    memset(szOldAppID, 0, sizeof(USHORT) * SECPOLICY_APP_NUM_MAX);
    memset(szNewAppID, 0, sizeof(USHORT) * SECPOLICY_APP_NUM_MAX);

    _secpolicy_Conf_AppIDSort(pusOldAPP, szOldAppID);
    _secpolicy_Conf_AppIDSort(pusNewAPP, szNewAppID);

    for (ui = 0; (ui < SECPOLICY_APP_NUM_MAX) && ((szOldAppID[ui]) != 0 || (szNewAppID[ui] != 0)); ui++)
    {
        if (szOldAppID[ui] != szNewAppID[ui])
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

BOOL_T _secpolicy_Conf_CompareIP(IN SECPOLICY_L3_MULTIIP_S *pstOldIP, IN SECPOLICY_L3_MULTIIP_S *pstNewIP)
{
    UINT uiMask;
    struct in6_addr  stMask;

    if (pstOldIP->uiIPMaskLen != pstNewIP->uiIPMaskLen)
    {
        return BOOL_FALSE;
    }

    if (pstOldIP->_multi_ip_type == IPPROTO_IP)
    {
        FWLIB_IP4ADDR_Len2Mask(pstNewIP->uiIPMaskLen, &uiMask);
        if ((pstOldIP->_multi_ip.stIPAddr._ip4_addr & uiMask) != 
            (pstNewIP->_multi_ip.stIPAddr._ip4_addr & uiMask))
        {
            return BOOL_FALSE;
        }
    }
    else
    {
        FWLIB_IP6ADDR_Len2Mask(pstNewIP->uiIPMaskLen, &stMask);
        return FWLIB_IP6_COMPARE(&pstOldIP->_multi_ip.stIPAddr._ip_data.stIP6Addr, 
                          &pstNewIP->_multi_ip.stIPAddr._ip_data.stIP6Addr, 
                          &stMask);
    }

    return BOOL_TRUE;
}

ULONG SecPolicy_Conf_MdyRulePara(IN SECPOLICY_RULE_CFG_S *pstRuleCfg,
                                 IN BOOL_T bIsUndo)
{
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_RULE_S * pstConfRule;
    SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode;
    SECPOLICY_CONF_COMMON_S stConfCommon;
    BOOL_T bIsUpdateSeq = BOOL_FALSE;
    
    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    stConfCommon.enFwDirect = pstRuleCfg->enFwDirect;
    stConfCommon.enFwType   = pstRuleCfg->enFwType;
    stConfCommon.uiIPType   = pstRuleCfg->uiIPType;
    stConfCommon.uiVxlanID  = pstRuleCfg->uiVxlanID;
    strlcpy(stConfCommon.szTenantID, pstRuleCfg->szTenantID, TENANT_ID_MAX+1);
    
    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        if (BOOL_TRUE == bIsUndo)
        {
            return ERROR_SUCCESS;
        }

        pstConf = _secpolicy_conf_MallocNode(pstRuleCfg->enFwType,
                                             pstRuleCfg->szTenantID,
                                             pstRuleCfg->uiVxlanID,
                                             pstRuleCfg->uiIPType);
        if (NULL == pstConf)
        {
            return ERROR_FAILED;
        }
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadIn2Out;
        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadOut2In;
        rte_rwlock_write_lock(&pstConf->rwlock_out2in);
    }

    pstConfRuleNode = _secpolicy_conf_FindRuleNode(&pstConfRule->stHead, pstRuleCfg->uiRuleID);
    if ((NULL == pstConfRuleNode) && (BOOL_TRUE != bIsUndo))
    {
        (VOID)_secpolicy_conf_MallocRuleNode(pstConfRule, pstRuleCfg);
        if (BOOL_TRUE ==  pstRuleCfg->bIsEnable)
        {
            /* Add valid rules to update the fast forwarding sequence number */
            ASPF_Inc_Cfg_Seq();
        }
    }
    else
    {
        /* action */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ACTION)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->enActionType != SECPOLICY_ACTION_DENY)
                {
                    pstConfRuleNode->enActionType = SECPOLICY_ACTION_DENY;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->enActionType != pstRuleCfg->enActionType)
                {
                    pstConfRuleNode->enActionType = pstRuleCfg->enActionType;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }
        
        /* sip */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SIP)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SIP)
                {
                    memset(&pstConfRuleNode->stSrc, 0, sizeof(SECPOLICY_L3_MULTIIP_S));
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_SIP;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SIP)
                {
                    if (!_secpolicy_Conf_CompareIP(&pstConfRuleNode->stSrc, &pstRuleCfg->stSrc))
                    {
                        pstConfRuleNode->stSrc = pstRuleCfg->stSrc;
                        bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    pstConfRuleNode->stSrc = pstRuleCfg->stSrc;
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SIP;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }
        
        /* dip */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DIP)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DIP)
                {
                    memset(&pstConfRuleNode->stDst, 0, sizeof(SECPOLICY_L3_MULTIIP_S));
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_DIP;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DIP)
                {
                    if (!_secpolicy_Conf_CompareIP(&pstConfRuleNode->stDst, &pstRuleCfg->stDst))
                    {
                        pstConfRuleNode->stDst = pstRuleCfg->stDst;
                        bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    pstConfRuleNode->stDst = pstRuleCfg->stDst;
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DIP;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }
        
        /* service */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SERVICE)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SERVICE)
                {
                    pstConfRuleNode->stL4Info.ucProtocol = INVALID_TCPIP_PROTOCOL_ID;
                    memset(&pstConfRuleNode->stL4Info.stPortRange, 0, sizeof(SECPOLICY_TCPUDP_PORTRANGE_S));
                    memset(&pstConfRuleNode->stL4Info.stIcmp, 0, sizeof(SECPOLICY_ICMP_S));
                    pstConfRuleNode->uiKeyMask &= ~(SECPOLICY_PACKET_MATCH_TYPE_SERVICE | \
                                                    SECPOLICY_PACKET_MATCH_TYPE_SPORT   | \
                                                    SECPOLICY_PACKET_MATCH_TYPE_DPORT   | \
                                                    SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE | \
                                                    SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE);
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SERVICE)
                {
                    if (pstConfRuleNode->stL4Info.ucProtocol != pstRuleCfg->stL4Info.ucProtocol)
                    {
                        pstConfRuleNode->stL4Info.ucProtocol = pstRuleCfg->stL4Info.ucProtocol;
                        bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    pstConfRuleNode->stL4Info.ucProtocol = pstRuleCfg->stL4Info.ucProtocol;
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SERVICE;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }
        
        /* sport */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SPORT)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SPORT)
                {
                    memset(&pstConfRuleNode->stL4Info.stPortRange.stSRange, 0, sizeof(SECPOLICY_PORTRANGE_S));
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_SPORT;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_SPORT)
                {
                    if ((pstConfRuleNode->stL4Info.stPortRange.stSRange.usSPort != pstRuleCfg->stL4Info.stPortRange.stSRange.usSPort) ||
                        (pstConfRuleNode->stL4Info.stPortRange.stSRange.usDPort != pstRuleCfg->stL4Info.stPortRange.stSRange.usDPort))
                    {
                            pstConfRuleNode->stL4Info.stPortRange.stSRange = pstRuleCfg->stL4Info.stPortRange.stSRange;
                            bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    pstConfRuleNode->stL4Info.stPortRange.stSRange = pstRuleCfg->stL4Info.stPortRange.stSRange;
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_SPORT;
                    bIsUpdateSeq = BOOL_TRUE;
                }

                /*
                if (bappstatus == true)
                {
                    unsigned int uiID = 0;
                    uiID = App_Rbt_GetAppIDBySubID(pstConfRuleNode->stL4Info.stPortRange.stSRange.usSPort);
                    printf("\nSubID %d ID %d\n", pstConfRuleNode->stL4Info.stPortRange.stSRange.usSPort, uiID);
                }
                */
            }
        }
        
        /* dport */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DPORT)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DPORT)
                {
                    memset(&pstConfRuleNode->stL4Info.stPortRange.stDRange, 0, sizeof(SECPOLICY_PORTRANGE_S));
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_DPORT;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DPORT)
                {
                    if ((pstConfRuleNode->stL4Info.stPortRange.stDRange.usSPort != pstRuleCfg->stL4Info.stPortRange.stDRange.usSPort) ||
                        (pstConfRuleNode->stL4Info.stPortRange.stDRange.usDPort != pstRuleCfg->stL4Info.stPortRange.stDRange.usDPort))
                    {
                        pstConfRuleNode->stL4Info.stPortRange.stDRange = pstRuleCfg->stL4Info.stPortRange.stDRange;
                        bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    pstConfRuleNode->stL4Info.stPortRange.stDRange = pstRuleCfg->stL4Info.stPortRange.stDRange;
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DPORT;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }
        
        /* icmp type */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE)
                {
                    pstConfRuleNode->stL4Info.stIcmp.ucType = 0;
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE)
                {
                    if (pstConfRuleNode->stL4Info.stIcmp.ucType != pstRuleCfg->stL4Info.stIcmp.ucType)
                    {
                        pstConfRuleNode->stL4Info.stIcmp.ucType = pstRuleCfg->stL4Info.stIcmp.ucType;
                        bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    pstConfRuleNode->stL4Info.stIcmp.ucType = pstRuleCfg->stL4Info.stIcmp.ucType;
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }
        
        /* icmp code */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE)
                {
                    pstConfRuleNode->stL4Info.stIcmp.ucCode = 0;
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE)
                {
                    if (pstConfRuleNode->stL4Info.stIcmp.ucCode != pstRuleCfg->stL4Info.stIcmp.ucCode)
                    {
                        pstConfRuleNode->stL4Info.stIcmp.ucCode = pstRuleCfg->stL4Info.stIcmp.ucCode;
                        bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    pstConfRuleNode->stL4Info.stIcmp.ucCode = pstRuleCfg->stL4Info.stIcmp.ucCode;
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }

        /* app */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_APP)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if ((pstConfRuleNode->uiKeyMask & (SECPOLICY_PACKET_MATCH_TYPE_APP | SECPOLICY_PACKET_MATCH_TYPE_STATUS)) == 
                    (SECPOLICY_PACKET_MATCH_TYPE_APP | SECPOLICY_PACKET_MATCH_TYPE_STATUS))
                {
                    rte_atomic16_dec(&pstConfRule->stRuleCountOfRefApp);
                }

                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_APP)
                {
                    memset(pstConfRuleNode->szAppID, 0, sizeof(USHORT) * SECPOLICY_APP_NUM_MAX);
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_APP;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if ((pstConfRuleNode->uiKeyMask & (SECPOLICY_PACKET_MATCH_TYPE_APP | SECPOLICY_PACKET_MATCH_TYPE_STATUS)) == 
                    SECPOLICY_PACKET_MATCH_TYPE_STATUS)
                {
                    rte_atomic16_inc(&pstConfRule->stRuleCountOfRefApp);
                }

                if (pstConfRuleNode->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_APP)
                {
                    if (!_secpolicy_Conf_CompareAppID(pstConfRuleNode->szAppID, pstRuleCfg->szAppID))
                    {
                        memcpy(pstConfRuleNode->szAppID, pstRuleCfg->szAppID, sizeof(USHORT) * SECPOLICY_APP_NUM_MAX);
                        bIsUpdateSeq = BOOL_TRUE;
                    }
                }
                else
                {
                    memcpy(pstConfRuleNode->szAppID, pstRuleCfg->szAppID, sizeof(USHORT) * SECPOLICY_APP_NUM_MAX);
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_APP;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
        }

        /* status */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_STATUS)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                if ((pstConfRuleNode->uiKeyMask & (SECPOLICY_PACKET_MATCH_TYPE_APP | SECPOLICY_PACKET_MATCH_TYPE_STATUS)) == 
                    (SECPOLICY_PACKET_MATCH_TYPE_APP | SECPOLICY_PACKET_MATCH_TYPE_STATUS))
                {
                    rte_atomic16_dec(&pstConfRule->stRuleCountOfRefApp);
                }

                if (pstConfRuleNode->bIsEnable == BOOL_TRUE)
                {
                    pstConfRuleNode->bIsEnable = BOOL_FALSE;
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_STATUS;
                    bIsUpdateSeq = BOOL_TRUE;
                }
            }
            else
            {
                if (((pstConfRuleNode->uiKeyMask & (SECPOLICY_PACKET_MATCH_TYPE_APP | SECPOLICY_PACKET_MATCH_TYPE_STATUS)) == 
                    (SECPOLICY_PACKET_MATCH_TYPE_APP)) && (pstRuleCfg->bIsEnable == BOOL_TRUE))
                {
                    rte_atomic16_inc(&pstConfRule->stRuleCountOfRefApp);
                }

                if (pstConfRuleNode->bIsEnable != pstRuleCfg->bIsEnable)
                {
                    pstConfRuleNode->bIsEnable = pstRuleCfg->bIsEnable;
                    bIsUpdateSeq = BOOL_TRUE;
                }

                if (pstConfRuleNode->bIsEnable == BOOL_TRUE)
                {
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_STATUS;
                }
                else if (pstConfRuleNode->bIsEnable == BOOL_FALSE)
                {
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_STATUS;
                }
            }
        }
        
        /* statistics */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_STATISTICS)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                pstConfRuleNode->bIsStatistics = BOOL_FALSE;
                pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_STATISTICS;
            }
            else
            {
                pstConfRuleNode->bIsStatistics = pstRuleCfg->bIsStatistics;
                if (pstConfRuleNode->bIsStatistics == BOOL_TRUE)
                {
                    pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_STATISTICS;
                }
                else if (pstConfRuleNode->bIsStatistics == BOOL_FALSE)
                {
                    pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_STATISTICS;
                }
            }
        }

        /* description */
        if (pstRuleCfg->uiKeyMask & SECPOLICY_PACKET_MATCH_TYPE_DESC)
        {
            if (BOOL_TRUE == bIsUndo)
            {
                memset(pstConfRuleNode->szDescInfo, 0, (SECPOLICY_RULE_DECRIPTION_MAX+1));
                pstConfRuleNode->uiKeyMask &= ~SECPOLICY_PACKET_MATCH_TYPE_DESC;
            }
            else
            {
                strlcpy(pstConfRuleNode->szDescInfo, pstRuleCfg->szDescInfo, (SECPOLICY_RULE_DECRIPTION_MAX+1));
                pstConfRuleNode->uiKeyMask |= SECPOLICY_PACKET_MATCH_TYPE_DESC;
            }
        }
    }


    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);
    }

    if (bIsUpdateSeq == BOOL_TRUE)
    {
        ASPF_Inc_Cfg_Seq();
    }

    return ERROR_SUCCESS;
}
/* 移动规则 */
VOID  _secpolicy_conf_Move(IN DTQ_HEAD_S *pstList,
                           IN SECPOLICY_MOVE_TYPE_E enMoveType,
                           IN DTQ_NODE_S *pstRuleIDNode,
                           IN DTQ_NODE_S *pstTargetIDNode,
                           OUT BOOL_T *pbIsUpdateSeq)
{
    SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode = NULL;

    /* 链表为空直接返回 */
    if (DTQ_IsEmpty(pstList))
    {
        return;
    }

    /* 规则节点摘链 */
    if (SECPOLICY_MOVE_TYPE_HEAD == enMoveType)
    {
        if (pstRuleIDNode != DTQ_First(pstList))
        {
            DTQ_Del(pstRuleIDNode);
            DTQ_AddHead(pstList, pstRuleIDNode);
            pstConfRuleNode = DTQ_ENTRY(pstRuleIDNode, SECPOLICY_CONF_RULE_NODE_S, stNode);
            if (pstConfRuleNode->bIsEnable == BOOL_TRUE)
            {
                *pbIsUpdateSeq = BOOL_TRUE;
            }
        }

    }
    else if (SECPOLICY_MOVE_TYPE_TAIL == enMoveType)
    {
        if (pstRuleIDNode != DTQ_Last(pstList))
        {
            DTQ_Del(pstRuleIDNode);
            DTQ_AddTail(pstList, pstRuleIDNode);
            pstConfRuleNode = DTQ_ENTRY(pstRuleIDNode, SECPOLICY_CONF_RULE_NODE_S, stNode);
            if (pstConfRuleNode->bIsEnable == BOOL_TRUE)
            {
                *pbIsUpdateSeq = BOOL_TRUE;
            }
        }
    }
    else if (SECPOLICY_MOVE_TYPE_BEFORE == enMoveType)
    {
        if ((pstRuleIDNode != pstTargetIDNode) && (pstTargetIDNode != DTQ_Next(pstRuleIDNode)))
        {
            DTQ_Del(pstRuleIDNode);
            DTQ_AddBefore(pstTargetIDNode, pstRuleIDNode);
            pstConfRuleNode = DTQ_ENTRY(pstRuleIDNode, SECPOLICY_CONF_RULE_NODE_S, stNode);
            if (pstConfRuleNode->bIsEnable == BOOL_TRUE)
            {
                *pbIsUpdateSeq = BOOL_TRUE;
            }
        }
    }
    else if (SECPOLICY_MOVE_TYPE_AFTER == enMoveType)
    {
        if ((pstRuleIDNode != pstTargetIDNode) && (pstTargetIDNode != DTQ_Prev(pstRuleIDNode)))
        {
            DTQ_Del(pstRuleIDNode);
            DTQ_AddAfter(pstTargetIDNode, pstRuleIDNode);
            pstConfRuleNode = DTQ_ENTRY(pstRuleIDNode, SECPOLICY_CONF_RULE_NODE_S, stNode);
            if (pstConfRuleNode->bIsEnable == BOOL_TRUE)
            {
                *pbIsUpdateSeq = BOOL_TRUE;
            }
        }
    }
    return;
}


ULONG SecPolicy_Conf_MoveRule(IN SECPOLICY_MOVE_RULE_S *pstRuleCfg)
{
    unsigned long ulErrCode = ERROR_SUCCESS;
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_RULE_S * pstConfRule;
    SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode, * pstConfRuletargetNode = NULL;
    SECPOLICY_CONF_COMMON_S stConfCommon;
    BOOL_T bIsUpdateSeq = BOOL_FALSE;
    
    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    stConfCommon.enFwDirect = pstRuleCfg->enFwDirect;
    stConfCommon.enFwType   = pstRuleCfg->enFwType;
    stConfCommon.uiIPType   = pstRuleCfg->uiIPType;
    stConfCommon.uiVxlanID  = pstRuleCfg->uiVxlanID;
    strlcpy(stConfCommon.szTenantID, pstRuleCfg->szTenantID, TENANT_ID_MAX+1);
    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        printf("Policy does not exist.\n");
        return ERROR_NOT_FOUND;
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadIn2Out;
        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadOut2In;
        rte_rwlock_write_lock(&pstConf->rwlock_out2in);
    }

    pstConfRuleNode = _secpolicy_conf_FindRuleNode(&pstConfRule->stHead, pstRuleCfg->uiRuleID);
    if (NULL != pstConfRuleNode)
    {
        if ((SECPOLICY_MOVE_TYPE_BEFORE == pstRuleCfg->enMoveType) || 
            (SECPOLICY_MOVE_TYPE_AFTER == pstRuleCfg->enMoveType))
        {
            pstConfRuletargetNode = _secpolicy_conf_FindRuleNode(&pstConfRule->stHead, pstRuleCfg->uiTargetID);
            if (NULL == pstConfRuletargetNode)
            {
                printf("Target rule does not exist.\n");
                ulErrCode = ERROR_NOT_FOUND;
                goto SECPOLICY_CONF_MOVE_RULE_NONE;
            }
        
            if (pstRuleCfg->uiRuleID == pstRuleCfg->uiTargetID)
            {
                printf("Rules are the same.\n");
                ulErrCode = ERROR_NOT_FOUND;
                goto SECPOLICY_CONF_MOVE_RULE_NONE;
            }
        }
        
        _secpolicy_conf_Move(&pstConfRule->stHead, pstRuleCfg->enMoveType,
                             &pstConfRuleNode->stNode, &pstConfRuletargetNode->stNode, &bIsUpdateSeq);
    }
    else
    {
        printf("Rule does not exist.\n");
    }

SECPOLICY_CONF_MOVE_RULE_NONE:
    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);
    }

    if (bIsUpdateSeq == BOOL_TRUE)
    {
        ASPF_Inc_Cfg_Seq();
    }

    return ulErrCode; 
}

VOID _secpolicy_conf_FreeTenantID(IN SL_HEAD_S * pstList, IN UCHAR *pucTenantID)
{
    SECPOLICY_CONF_NODE_S * pstConf = NULL, *pstEntry;

    /* 释放指定租户下得全部规则节点 */
    SL_FOREACH_ENTRY(pstList, pstEntry, stNode)
    {
        if (!strncasecmp(pucTenantID, pstEntry->szTenantID, TENANT_ID_MAX+1))
        {
            pstConf = pstEntry;
            break;
        }
    }
    
    if (NULL != pstConf)
    {
        SL_Del(pstList, &pstConf->stNode);
        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
        DTQ_FreeAll(&pstConf->stHeadIn2Out.stHead, _secpolicy_conf_FreeRuleNode);
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);

        rte_rwlock_write_lock(&pstConf->rwlock_out2in);
        DTQ_FreeAll(&pstConf->stHeadOut2In.stHead, _secpolicy_conf_FreeRuleNode);
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);

        rte_free(pstConf);
    }

    return;
}

/* 删除租户节点及节点内全部规则节点 */
VOID SecPolicy_Conf_DelTenantID(IN UCHAR *pucTenantID)
{
    _secpolicy_conf_FreeTenantID(g_pstExtSecConfHeadIP4, pucTenantID);
    _secpolicy_conf_FreeTenantID(g_pstExtSecConfHeadIP6, pucTenantID);
    SecPolicy_ExtFlow_DelTenantID(pucTenantID);
    return;
}

/* 删除全部租户节点及节点内全部IP节点 */
VOID SecPolicy_Conf_DelAllTenantID()
{
    SL_FreeAll(g_pstExtSecConfHeadIP4, _secpolicy_conf_FreeNode);
    SL_FreeAll(g_pstExtSecConfHeadIP6, _secpolicy_conf_FreeNode);
    SecPolicy_ExtFlow_DelAllTenantID();
    return;
}

VOID _secpolicy_conf_FreeVxlanID(IN SL_HEAD_S * pstList, IN UINT uiVxlanID)
{
    SECPOLICY_CONF_NODE_S * pstConf = NULL, *pstEntry;

    SL_FOREACH_ENTRY(pstList, pstEntry, stNode)
    {
        if (pstEntry->uiVxlanID == uiVxlanID)
        {
            pstConf = pstEntry;
            break;
        }
    }
    
    if (NULL != pstConf)
    {
        SL_Del(pstList, &pstConf->stNode);

        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
        DTQ_FreeAll(&pstConf->stHeadIn2Out.stHead, _secpolicy_conf_FreeRuleNode);
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);

        rte_rwlock_write_lock(&pstConf->rwlock_out2in);
        DTQ_FreeAll(&pstConf->stHeadOut2In.stHead, _secpolicy_conf_FreeRuleNode);
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);

        rte_free(pstConf);
    }

    return;
}

ULONG SecPolicy_Conf_AddVxlanID(IN UINT uiVxlanID, IN UINT uiIPType)
{
    SECPOLICY_CONF_NODE_S   *pstConf;
    SECPOLICY_CONF_COMMON_S stConfCommon;

    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    
    stConfCommon.enFwType   = SECPOLICY_TYPE_VPCBODER;
    stConfCommon.uiIPType   = uiIPType;
    stConfCommon.uiVxlanID  = uiVxlanID;
    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        pstConf = _secpolicy_conf_MallocNode(SECPOLICY_TYPE_VPCBODER, NULL, uiVxlanID, uiIPType);
        if (NULL == pstConf)
        {
            printf("初始化IPv%d安全策略%d失败", uiIPType==IPPROTO_IP ? 4 : 6, uiVxlanID);
        }
    }

    return ERROR_SUCCESS;
}

VOID SecPolicy_Conf_DelVxlanID(IN UINT uiVxlanID)
{
    _secpolicy_conf_FreeVxlanID(g_pstVPCSecConfHeadIP4, uiVxlanID);
    _secpolicy_conf_FreeVxlanID(g_pstVPCSecConfHeadIP6, uiVxlanID);
    SecPolicy_VPCFlow_DelVxlanID(uiVxlanID);
    return;
}

VOID SecPolicy_Conf_DelAllVxlanID()
{
    SL_FreeAll(g_pstVPCSecConfHeadIP4, _secpolicy_conf_FreeNode);
    SL_FreeAll(g_pstVPCSecConfHeadIP6, _secpolicy_conf_FreeNode);
    SecPolicy_VPCFlow_DelAllVxlanID();
    return;
}

VOID _secpolicy_conf_printf(IN SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode)
{
    int i;
    UINT uiSum = 0;

    if (NULL == pstConfRuleNode)
    {
        return;
    }

    UCHAR ucStr[INET6_ADDRSTRLEN] = "\0";
    
    printf("\tRuleID:%d\n", pstConfRuleNode->uiRuleID);
    printf("\tDesc:%s\n", pstConfRuleNode->szDescInfo);
    printf("\tAction:%s\n", pstConfRuleNode->enActionType == SECPOLICY_ACTION_PERMIT ? "Pass" : "Drop");
    printf("\tStatus:%s\n",pstConfRuleNode->bIsEnable == BOOL_TRUE ? "Enable" : "Disable");
    printf("\tStatistics:%s\n",pstConfRuleNode->bIsStatistics == BOOL_TRUE ? "Enable" : "Disable");
    if (pstConfRuleNode->stSrc._multi_ip_type == IPPROTO_IP)
    {
        inet_ntop(AF_INET, &pstConfRuleNode->stSrc._multi_ip.stIPAddr._ip_data.stIP4Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tSrcIP:%s/%d\n",ucStr, pstConfRuleNode->stSrc.uiIPMaskLen);
    }
    else if (pstConfRuleNode->stSrc._multi_ip_type == IPPROTO_IPV6)
    {
        inet_ntop(AF_INET6, &pstConfRuleNode->stSrc._multi_ip.stIPAddr._ip_data.stIP6Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tSrcIP6:%s/%d\n",ucStr, pstConfRuleNode->stSrc.uiIPMaskLen);
    }
    else
    {
        printf("\tSrcIP:Any\n");
    }
    
    if (pstConfRuleNode->stDst._multi_ip_type == IPPROTO_IP)
    {
        inet_ntop(AF_INET, &pstConfRuleNode->stDst._multi_ip.stIPAddr._ip_data.stIP4Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tDstIP:%s/%d\n",ucStr, pstConfRuleNode->stDst.uiIPMaskLen);
    }
    else if (pstConfRuleNode->stDst._multi_ip_type == IPPROTO_IPV6)
    {
        inet_ntop(AF_INET6, &pstConfRuleNode->stDst._multi_ip.stIPAddr._ip_data.stIP6Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tDstIP6:%s/%d\n",ucStr, pstConfRuleNode->stDst.uiIPMaskLen);
    }
    else
    {
        printf("\tDstIP:Any\n");
    }

    printf("\tService:%s\n", pstConfRuleNode->stL4Info.ucProtocol == IPPROTO_TCP ? "TCP" : \
                           pstConfRuleNode->stL4Info.ucProtocol == IPPROTO_UDP ? "UDP" : \
                           pstConfRuleNode->stL4Info.ucProtocol == IPPROTO_ICMP ? "ICMP" : \
                           pstConfRuleNode->stL4Info.ucProtocol == IPPROTO_ICMPV6 ? "ICMPv6" : "Any");


    printf("\tSPort:%d-%d, DPort:%d-%d\n",pstConfRuleNode->stL4Info.stPortRange.stSRange.usSPort,
                                        pstConfRuleNode->stL4Info.stPortRange.stSRange.usDPort,
                                        pstConfRuleNode->stL4Info.stPortRange.stDRange.usSPort,
                                        pstConfRuleNode->stL4Info.stPortRange.stDRange.usDPort);

    printf("\tType:%d, Code:%d\n",pstConfRuleNode->stL4Info.stIcmp.ucType,
                                              pstConfRuleNode->stL4Info.stIcmp.ucCode);

    printf("\tApp ID:");
    i = 0;
    if (pstConfRuleNode->szAppID[i])
    {
        while (pstConfRuleNode->szAppID[i])
        {
            printf("%d ", pstConfRuleNode->szAppID[i]);
            i++;
        }
        printf("\n");
    }
    else
    {
        printf("Any\n");
    }

    printf("\tPacket matching mask: ");
    i = 0;
    if (SECPOLICY_PACKET_MATCH_TYPE_SIP & pstConfRuleNode->uiKeyMask)
    {
        printf("SIP");
        i++;
    }
    if (SECPOLICY_PACKET_MATCH_TYPE_DIP & pstConfRuleNode->uiKeyMask)
    {
        printf("%sDIP", i++ > 0 ? " | " : "");
    }
    if (SECPOLICY_PACKET_MATCH_TYPE_SERVICE & pstConfRuleNode->uiKeyMask)
    {
        printf("%sSERVICE", i++ > 0 ? " | " : "");
    }
    if (SECPOLICY_PACKET_MATCH_TYPE_SPORT & pstConfRuleNode->uiKeyMask)
    {
        printf("%sSPORT", i++ > 0 ? " | " : "");
    }
    if (SECPOLICY_PACKET_MATCH_TYPE_DPORT & pstConfRuleNode->uiKeyMask)
    {
        printf("%sDPORT", i++ > 0 ? " | " : "");
    }
    if (SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE & pstConfRuleNode->uiKeyMask)
    {
        printf("%sICMP-TYPE", i++ > 0 ? " | " : "");
    }
    if (SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE & pstConfRuleNode->uiKeyMask)
    {
        printf("%sICMP-CODE", i++ > 0 ? " | " : "");
    }
    if (SECPOLICY_PACKET_MATCH_TYPE_APP & pstConfRuleNode->uiKeyMask)
    {
        printf("%sAPP", i++ > 0 ? " | " : "");
    }
    if (i)
    {
        printf("\n");
    }
    else
    {
        printf("NULL\n");
    }

    if (NULL != pstConfRuleNode->puiCount)
    {
        for(i = 0; i < (rte_lcore_count()-1); i++)
        {
            uiSum += pstConfRuleNode->puiCount[i];
        }
    }
    printf("\tPacket matching statistics:%lld\n", uiSum);
    printf("\n");

    return;
}

VOID SecPolicy_Conf_Show(IN SECPOLICY_RULE_CFG_S *pstRuleCfg)
{
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_RULE_S * pstConfRule;
    SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode;
    SECPOLICY_CONF_COMMON_S stConfCommon;
    BOOL_T bIsExist = BOOL_FALSE;

    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    stConfCommon.enFwDirect = pstRuleCfg->enFwDirect;
    stConfCommon.enFwType   = pstRuleCfg->enFwType;
    stConfCommon.uiIPType   = pstRuleCfg->uiIPType;
    stConfCommon.uiVxlanID  = pstRuleCfg->uiVxlanID;
    strlcpy(stConfCommon.szTenantID, pstRuleCfg->szTenantID, TENANT_ID_MAX+1);
    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        printf("The security policy is not configured.\n");
        return;
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadIn2Out;
        rte_rwlock_read_lock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadOut2In;
        rte_rwlock_read_lock(&pstConf->rwlock_out2in);
    }

    printf("show rules:\n");
    if (pstRuleCfg->uiRuleID)
    {
        pstConfRuleNode = _secpolicy_conf_FindRuleNode(&pstConfRule->stHead, pstRuleCfg->uiRuleID);
        if (NULL != pstConfRuleNode)
        {
            bIsExist = BOOL_TRUE;
            _secpolicy_conf_printf(pstConfRuleNode);
        }
    }
    else
    {
        DTQ_FOREACH_ENTRY(&pstConfRule->stHead, pstConfRuleNode, stNode)
        {
            bIsExist = BOOL_TRUE;
            _secpolicy_conf_printf(pstConfRuleNode);
        }
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_read_unlock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_read_unlock(&pstConf->rwlock_out2in);
    }


    if (BOOL_FALSE == bIsExist)
    {
        printf("No configuration.\n");
    }

    return; 
}

VOID SecPolicy_Conf_SetDbg(IN UINT uiVxlanID, IN unsigned char *pucTenantID, IN UINT uiDbgType, IN BOOL_T bIsUndo, IN UINT uiIPType)
{
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_COMMON_S stConfCommon;

    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    
    stConfCommon.uiIPType   = uiIPType;
    if (0 != uiVxlanID)
    {
        stConfCommon.uiVxlanID  = uiVxlanID;
        stConfCommon.enFwType   = SECPOLICY_TYPE_VPCBODER;
    }
    else if (0 != pucTenantID)
    {
        strlcpy(stConfCommon.szTenantID, pucTenantID, TENANT_ID_MAX+1);
        stConfCommon.enFwType   = SECPOLICY_TYPE_EXTBODER;
    }

    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        printf("Policy does not exist.\n");
        return;
    }

    if (BOOL_TRUE == bIsUndo)
    {
        pstConf->uiDebug &= ~SECPOLICY_DEBUG_PACKET;
        printf("debug packet is disabled\n");
    }
    else
    {
        pstConf->uiDebug |= SECPOLICY_DEBUG_PACKET;
        printf("debug packet is enabled\n");
    }

    return;
}

VOID SecPolciy_Conf_GetDbg(IN UINT uiVxlanID, IN unsigned char *pucTenantID, IN UINT uiIPType)
{
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_COMMON_S stConfCommon;

    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));

    stConfCommon.uiIPType   = uiIPType;
    if (0 != uiVxlanID)
    {
        stConfCommon.uiVxlanID  = uiVxlanID;
        stConfCommon.enFwType   = SECPOLICY_TYPE_VPCBODER;
    }
    else if (0 != pucTenantID)
    {
        strlcpy(stConfCommon.szTenantID, pucTenantID, TENANT_ID_MAX+1);
        stConfCommon.enFwType   = SECPOLICY_TYPE_EXTBODER;
    }
    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        printf("Policy does not exist.\n");
        return;
    }

    if (0 != uiVxlanID)
    {
        printf("Vxlan %d %s Debug:\n", uiVxlanID, uiIPType == IPPROTO_IP ? "ip" : "ipv6");
    }
    else if (0 != pucTenantID)
    {
        printf("Tenant %s %s Debug:\n", pucTenantID, uiIPType == IPPROTO_IP ? "ip" : "ipv6");
    }
    printf("\tpacket:");
    if (pstConf->uiDebug & SECPOLICY_DEBUG_PACKET)
    {
        printf("Enable\n");
    }
    else
    {
        printf("Disable\n");
    }

    return;
}


VOID SecPolicy_Conf_ClearStatistics(IN SECPOLICY_RULE_CFG_S *pstRuleCfg)
{
    int i;
    SECPOLICY_CONF_NODE_S * pstConf;
    SECPOLICY_CONF_RULE_S * pstConfRule;
    SECPOLICY_CONF_RULE_NODE_S * pstConfRuleNode;
    SECPOLICY_CONF_COMMON_S stConfCommon;

    memset(&stConfCommon, 0, sizeof(SECPOLICY_CONF_COMMON_S));
    stConfCommon.enFwType   = pstRuleCfg->enFwType;
    stConfCommon.uiIPType   = pstRuleCfg->uiIPType;
    stConfCommon.uiVxlanID  = pstRuleCfg->uiVxlanID;

    pstConf = _secpolicy_conf_FindConfNode(&stConfCommon);
    if (NULL == pstConf)
    {
        return;
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadIn2Out;
        rte_rwlock_write_lock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        pstConfRule = &pstConf->stHeadOut2In;
        rte_rwlock_write_lock(&pstConf->rwlock_out2in);
    }

    pstConfRuleNode = _secpolicy_conf_FindRuleNode(&pstConfRule->stHead, pstRuleCfg->uiRuleID);
    if ((NULL != pstConfRuleNode) && (NULL != pstConfRuleNode->puiCount))
    {
        for(i = 0; i < (rte_lcore_count()-1); i++)
        {
            pstConfRuleNode->puiCount[i] = 0;;
        }
        
        printf("clear vxlan %d %s rule %d statistics.\n", pstRuleCfg->uiVxlanID,
                                    pstRuleCfg->uiIPType == IPPROTO_IP ? "ipv4" : "ipv6",
                                    pstRuleCfg->uiRuleID);
    }

    if (SECPOLICY_DIRECTION_IN2OUT == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_in2out);
    }
    else if (SECPOLICY_DIRECTION_OUT2IN == pstRuleCfg->enFwDirect)
    {
        rte_rwlock_write_unlock(&pstConf->rwlock_out2in);
    }

    return;
}

