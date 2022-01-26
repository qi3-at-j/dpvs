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
#include "fw_lib.h"
#include "pfilter.h"
#include "pfilter_match.h"

#define IN6ADDR_SIZE32 4

static VOID IP4ADDR_Len2Mask(IN UINT uiLen, OUT UINT32 *puiMask)
{
    UINT uiMask;
    if (0 == uiLen)
    {
        uiMask = 0;
    }
    else
    {
        uiMask = 0xFFFFFFFF << (32 - uiLen);
    }

    /* The IP mask is converted to the network sequence  */
    *puiMask = htonl(uiMask);
    return;
}

static VOID IP6ADDR_Len2Mask(IN UINT uiLen, OUT struct in6_addr *pstMask)
{
    UINT uiUintLen, uiBitLen, uiLoop, *puiMask;

    puiMask = pstMask->s6_addr32;
    puiMask[0] = 0;
    puiMask[1] = 0;
    puiMask[2] = 0;
    puiMask[3] = 0;

    uiUintLen = uiLen >> 5;
    uiBitLen  = uiLen &31;

    for(uiLoop = 0; uiLoop < uiUintLen; uiLoop++)
    {
        puiMask[uiLoop] = 0xffffffff;
    }

    if (uiBitLen != 0)
    {
        puiMask[uiUintLen] = 0xffffffff << (32 - uiBitLen);

        /* converted to the network sequence */
        puiMask[uiUintLen] = htonl(puiMask[uiUintLen]);
    }
    

    return;
}

static BOOL_T IP6_COMPARE(IN struct in6_addr *pstSrcIP6, IN struct in6_addr *pstDstIP6, IN struct in6_addr *pstMask)
{
    struct in6_addr stSrcIP6, stDstIP6;
    UINT uiLoop;
    BOOL_T bIsEqual = BOOL_TRUE;

    stSrcIP6.s6_addr32[0] = pstSrcIP6->s6_addr32[0] & pstMask->s6_addr32[0];
    stSrcIP6.s6_addr32[1] = pstSrcIP6->s6_addr32[1] & pstMask->s6_addr32[1];
    stSrcIP6.s6_addr32[2] = pstSrcIP6->s6_addr32[2] & pstMask->s6_addr32[2];
    stSrcIP6.s6_addr32[3] = pstSrcIP6->s6_addr32[3] & pstMask->s6_addr32[3];

    stDstIP6.s6_addr32[0] = pstDstIP6->s6_addr32[0] & pstMask->s6_addr32[0];
    stDstIP6.s6_addr32[1] = pstDstIP6->s6_addr32[1] & pstMask->s6_addr32[1];
    stDstIP6.s6_addr32[2] = pstDstIP6->s6_addr32[2] & pstMask->s6_addr32[2];
    stDstIP6.s6_addr32[3] = pstDstIP6->s6_addr32[3] & pstMask->s6_addr32[3];

    for (uiLoop = 0; uiLoop < IN6ADDR_SIZE32; uiLoop++)
    {
        if (stSrcIP6.s6_addr32[uiLoop] != stDstIP6.s6_addr32[uiLoop])
        {
            bIsEqual = BOOL_FALSE;
            break;
        }
    }

    return bIsEqual;
}

PFILTER_CONF_S* _pfilter_Malloc()
{
    PFILTER_CONF_S * pstFliterNode = NULL;
        
    pstFliterNode = (PFILTER_CONF_S *)rte_malloc(NULL, sizeof(PFILTER_CONF_S), 0);
    if (NULL != pstFliterNode)
    {
        memset(pstFliterNode, 0, sizeof(PFILTER_CONF_S));
        DTQ_NodeInit(&pstFliterNode->stNode);
    }

    return pstFliterNode;
}

PFILTER_CONF_S* _pfilter_Find(IN DTQ_HEAD_S *pstDTQHead, IN UINT uiRuleID)
{
    PFILTER_CONF_S *pstEntry = NULL, *pstNextEntry, *pstCurEntry;


    DTQ_FOREACH_ENTRY_SAFE(pstDTQHead, pstCurEntry, pstNextEntry, stNode)
    {
        if (pstCurEntry->stPfilterData.uiRuleID == uiRuleID)
        {
            pstEntry = pstCurEntry;
            break;
        }
    }
    
    return pstEntry;
}

VOID _pfilter_Add2List(IN DTQ_HEAD_S *pstList, PFILTER_CONF_S *pstPfilterNode)
{
    DTQ_NODE_S *pstNode;
    PFILTER_CONF_S *pstEntry, *pstNextEntry, *pstFirst, *pstLast;

    if (DTQ_IsEmpty(pstList))
    {
        DTQ_AddHead(pstList, &pstPfilterNode->stNode);
        return;
    }

    pstFirst = DTQ_ENTRY_FIRST(pstList, PFILTER_CONF_S, stNode);
    if (pstFirst->stPfilterData.uiRuleID > pstPfilterNode->stPfilterData.uiRuleID)
    {
        DTQ_AddHead(pstList, &pstPfilterNode->stNode);
        return;
    }

    pstLast = DTQ_ENTRY_LAST(pstList, PFILTER_CONF_S, stNode);
    if (pstLast->stPfilterData.uiRuleID < pstPfilterNode->stPfilterData.uiRuleID)
    {
        DTQ_AddTail(pstList, &pstPfilterNode->stNode);
        return;
    }

    DTQ_FOREACH_ENTRY_SAFE(pstList, pstEntry, pstNextEntry, stNode)
    {
        if ((pstEntry->stPfilterData.uiRuleID < pstPfilterNode->stPfilterData.uiRuleID) &&
            (pstPfilterNode->stPfilterData.uiRuleID < pstNextEntry->stPfilterData.uiRuleID))
        {
            DTQ_AddAfter(&pstEntry->stNode, &pstPfilterNode->stNode);
            break;
        }
    }

    return;
}

UINT _pfilter_AutoRuleID(IN DTQ_HEAD_S *pstList)
{
    PFILTER_CONF_S *pstEntry = NULL;
    DTQ_NODE_S *pstNode = NULL;

    if (DTQ_IsEmpty(pstList))
    {
        return 1;
    }

    pstNode = DTQ_Last(pstList);
    pstEntry = DTQ_ENTRY(pstNode, PFILTER_CONF_S, stNode);
    return pstEntry->stPfilterData.uiRuleID + 5;
}

ULONG Pfilter_Add(IN PFILTER_DATA_S *pstPfilterData)
{
    PFILTER_CONF_S *pstEntry = NULL;
    DTQ_HEAD_S *pstDTQHead;
    UINT uiIndex = pstPfilterData->uiIndex;
    rte_rwlock_write_lock(&g_stPfilterConf[uiIndex].stPfilter_rwlock);

    pstDTQHead = IPPROTO_IP == pstPfilterData->uiIPType ? \
                 &g_stPfilterConf[uiIndex].stIP4Head : \
                 &g_stPfilterConf[uiIndex].stIP6Head;

    if (0 != pstPfilterData->uiRuleID)
    {
        pstEntry = _pfilter_Find(pstDTQHead, pstPfilterData->uiRuleID);
    }
    else
    {
        pstPfilterData->uiRuleID = _pfilter_AutoRuleID(pstDTQHead);
    }

    if (NULL == pstEntry)
    {
        pstEntry = _pfilter_Malloc();
        if (NULL != pstEntry)
        {
            pstEntry->stPfilterData = *pstPfilterData;
            _pfilter_Add2List(pstDTQHead, pstEntry);
        }
        else
        {
            printf("Pfilter %s index %d rule id %d rte_malloc failed.\n.", 
                IPPROTO_IP == pstPfilterData->uiIPType ? "ipv4" : "ipv6",
                pstPfilterData->uiIndex, 
                pstPfilterData->uiRuleID);
        }
    }
    else
    {
        printf("Pfilter %s index %d rule id %d already exists\n.", 
            IPPROTO_IP == pstPfilterData->uiIPType ? "ipv4" : "ipv6",
            pstPfilterData->uiIndex, 
            pstPfilterData->uiRuleID);
    }

    rte_rwlock_write_unlock(&g_stPfilterConf[pstPfilterData->uiIndex].stPfilter_rwlock);

    return 0;
}

ULONG Pfilter_Del(IN UINT uiIndex, IN UINT uiIPType, IN UINT uiRuleID)
{
    PFILTER_CONF_S *pstEntry;
    DTQ_HEAD_S *pstDTQHead;
    rte_rwlock_write_lock(&g_stPfilterConf[uiIndex].stPfilter_rwlock);

    pstDTQHead = IPPROTO_IP == uiIPType ? \
                 &g_stPfilterConf[uiIndex].stIP4Head : \
                 &g_stPfilterConf[uiIndex].stIP6Head;

    pstEntry = _pfilter_Find(pstDTQHead, uiRuleID);
    if (NULL != pstEntry)
    {
        DTQ_Del(&pstEntry->stNode);
        rte_free(pstEntry);
    }

    rte_rwlock_write_unlock(&g_stPfilterConf[uiIndex].stPfilter_rwlock);

    return 0;
}

ULONG Pfilter_Modify(IN PFILTER_DATA_S *pstPfilterData, IN BOOL_T bIsUnSet)
{
    PFILTER_CONF_S *pstEntry = NULL;
    DTQ_HEAD_S *pstDTQHead;
    UINT uiIndex = pstPfilterData->uiIndex;
    PFILTER_DATA_S *pstTmp;

    rte_rwlock_write_lock(&g_stPfilterConf[uiIndex].stPfilter_rwlock);

    pstDTQHead = IPPROTO_IP == pstPfilterData->uiIPType ? \
                 &g_stPfilterConf[uiIndex].stIP4Head : \
                 &g_stPfilterConf[uiIndex].stIP6Head;

    if (0 != pstPfilterData->uiRuleID)
    {
        pstEntry = _pfilter_Find(pstDTQHead, pstPfilterData->uiRuleID);
    }
    else
    {
        pstPfilterData->uiRuleID = _pfilter_AutoRuleID(pstDTQHead);
    }

    if (NULL == pstEntry)
    {
        pstEntry = _pfilter_Malloc();
        if (NULL != pstEntry)
        {
            pstEntry->stPfilterData = *pstPfilterData;
            _pfilter_Add2List(pstDTQHead, pstEntry);
        }
    }
    else
    {
        pstTmp = &pstEntry->stPfilterData;
        if (pstPfilterData->uiMatchMask & PFILTER_MATCH_TYPE_SIP)
        {
            if (BOOL_TRUE == bIsUnSet)
            {
                memset(&pstTmp->stSrcIP, 0, sizeof(PFILTER_ADDR_S));
                pstTmp->uiMatchMask &= ~PFILTER_MATCH_TYPE_SIP;
            }
            else
            {
                memcpy(&pstTmp->stSrcIP, &pstPfilterData->stSrcIP, sizeof(PFILTER_ADDR_S));
                pstTmp->uiMatchMask |= PFILTER_MATCH_TYPE_SIP;
            }
        }

        if (pstPfilterData->uiMatchMask & PFILTER_MATCH_TYPE_DIP)
        {
            if (BOOL_TRUE == bIsUnSet)
            {
                memset(&pstTmp->stDstIP, 0, sizeof(PFILTER_ADDR_S));
                pstTmp->uiMatchMask &= ~PFILTER_MATCH_TYPE_DIP;
            }
            else
            {
                memcpy(&pstTmp->stDstIP, &pstPfilterData->stDstIP, sizeof(PFILTER_ADDR_S));
                pstTmp->uiMatchMask |= PFILTER_MATCH_TYPE_DIP;
            }
        }

        if (pstPfilterData->uiMatchMask & PFILTER_MATCH_TYPE_SPORT)
        {
            if (BOOL_TRUE == bIsUnSet)
            {
                pstTmp->usSPort = 0;
                pstTmp->uiMatchMask &= ~PFILTER_MATCH_TYPE_SPORT;
            }
            else
            {
                pstTmp->usSPort = pstPfilterData->usSPort;
                pstTmp->uiMatchMask |= PFILTER_MATCH_TYPE_SPORT;
            }
        }

        if (pstPfilterData->uiMatchMask & PFILTER_MATCH_TYPE_DPORT)
        {
            if (BOOL_TRUE == bIsUnSet)
            {
                pstTmp->usDPort = 0;
                pstTmp->uiMatchMask &= ~PFILTER_MATCH_TYPE_DPORT;
            }
            else
            {
                pstTmp->usDPort = pstPfilterData->usDPort;
                pstTmp->uiMatchMask |= PFILTER_MATCH_TYPE_DPORT;
            }
        }

        if (pstPfilterData->uiMatchMask & PFILTER_MATCH_TYPE_PROTOCOL)
        {
            if (BOOL_TRUE == bIsUnSet)
            {
                pstTmp->ucProtocol = 0;
                pstTmp->uiMatchMask &= ~PFILTER_MATCH_TYPE_PROTOCOL;
            }
            else
            {
                pstTmp->ucProtocol = pstPfilterData->ucProtocol;
                pstTmp->uiMatchMask |= PFILTER_MATCH_TYPE_PROTOCOL;
            }
        }
    }

    rte_rwlock_write_unlock(&g_stPfilterConf[uiIndex].stPfilter_rwlock);

    return 0;
}

VOID _pfilter_PrintRule(IN UINT uiIPType, IN PFILTER_DATA_S *pstPfilterData)
{
    int i;
    UINT uiSum = 0;

    if (NULL == pstPfilterData)
    {
        return;
    }

    UCHAR ucStr[INET6_ADDRSTRLEN] = "\0";
    
    printf("\tIndex:%d\n", pstPfilterData->uiIndex);
    printf("\tRule ID:%d\n", pstPfilterData->uiRuleID);
    if (uiIPType == IPPROTO_IP)
    {
        inet_ntop(AF_INET, &pstPfilterData->stSrcIP.un_addr.stIP4Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tSrcIP:%s/%d\n",ucStr, pstPfilterData->stSrcIP.uiIPMask);
    }
    else if (uiIPType == IPPROTO_IPV6)
    {
        inet_ntop(AF_INET6, &pstPfilterData->stSrcIP.un_addr.stIP6Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tSrcIP6:%s/%d\n",ucStr, pstPfilterData->stSrcIP.uiIPMask);
    }
    else
    {
        printf("\tSrcIP:Any\n");
    }
    
    if (uiIPType == IPPROTO_IP)
    {
        inet_ntop(AF_INET, &pstPfilterData->stDstIP.un_addr.stIP4Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tDstIP:%s/%d\n",ucStr, pstPfilterData->stDstIP.uiIPMask);
    }
    else if (uiIPType == IPPROTO_IPV6)
    {
        inet_ntop(AF_INET6, &pstPfilterData->stDstIP.un_addr.stIP6Addr, ucStr, INET6_ADDRSTRLEN);
        printf("\tDstIP6:%s/%d\n",ucStr, pstPfilterData->stDstIP.uiIPMask);
    }
    else
    {
        printf("\tDstIP:Any\n");
    }

    printf("\tProtocol:%s\n", pstPfilterData->ucProtocol == IPPROTO_TCP ? "TCP" : \
                            pstPfilterData->ucProtocol == IPPROTO_UDP ? "UDP" : \
                            pstPfilterData->ucProtocol == IPPROTO_ICMP ? "ICMP" : \
                            pstPfilterData->ucProtocol == IPPROTO_ICMPV6 ? "ICMPv6" : "Any");


    printf("\tSPort:%d\n",pstPfilterData->usSPort);
    printf("\tDPort:%d\n",pstPfilterData->usDPort);


    printf("\tPfilter matching mask: ");
    i = 0;
    if (PFILTER_MATCH_TYPE_SIP & pstPfilterData->uiMatchMask)
    {
        printf("SIP");
        i++;
    }
    if (PFILTER_MATCH_TYPE_DIP & pstPfilterData->uiMatchMask)
    {
        printf("%sDIP", i++ > 0 ? " | " : "");
    }
    if (PFILTER_MATCH_TYPE_PROTOCOL & pstPfilterData->uiMatchMask)
    {
        printf("%sPROTOCOl", i++ > 0 ? " | " : "");
    }
    if (PFILTER_MATCH_TYPE_SPORT & pstPfilterData->uiMatchMask)
    {
        printf("%sSPORT", i++ > 0 ? " | " : "");
    }
    if (PFILTER_MATCH_TYPE_DPORT & pstPfilterData->uiMatchMask)
    {
        printf("%sDPORT", i++ > 0 ? " | " : "");
    }
    if (i)
    {
        printf("\n\n");
    }
    else
    {
        printf("Any\n\n");
    }
    return;
}

VOID Pfilter_Get(IN UINT uiIndex, IN UINT uiIPType, IN UINT uiRuleID)
{
    DTQ_HEAD_S *pstDTQHead;
    PFILTER_CONF_S *pstEntry, *pstNextEntry;
    
    rte_rwlock_read_lock(&g_stPfilterConf[uiIndex].stPfilter_rwlock);

    pstDTQHead = (IPPROTO_IP == uiIPType) ? \
                 &g_stPfilterConf[uiIndex].stIP4Head : \
                 &g_stPfilterConf[uiIndex].stIP6Head;

    printf("show pfilter : \n");
    if (0 != uiRuleID)
    {
        pstEntry = _pfilter_Find(pstDTQHead, uiRuleID);
        if (NULL != pstEntry)
        {
            _pfilter_PrintRule(uiIPType, &pstEntry->stPfilterData);
        }
        else
        {
            printf("Not exist.\n");
        }
    }
    else
    {
        DTQ_FOREACH_ENTRY_SAFE(pstDTQHead, pstEntry, pstNextEntry, stNode)
        {
            _pfilter_PrintRule(uiIPType, &pstEntry->stPfilterData);
        }
    }

    rte_rwlock_read_unlock(&g_stPfilterConf[uiIndex].stPfilter_rwlock);
    return;
}

BOOL_T Pfilter_Match_IPv4(IN PFILTER_PACKET_IPV4_S *pstPfilterPacket)
{
    DTQ_HEAD_S *pstHead = &g_stPfilterConf[pstPfilterPacket->uiIndex].stIP4Head;
    PFILTER_CONF_S *pstEntry, *pstNextEntry;
    PFILTER_DATA_S *pstData, *pstMatchEntry = NULL;
    UINT uiMask;

    rte_rwlock_read_lock(&g_stPfilterConf[pstPfilterPacket->uiIndex].stPfilter_rwlock);

    DTQ_FOREACH_ENTRY_SAFE(pstHead, pstEntry, pstNextEntry, stNode)
    {
        pstData = &pstEntry->stPfilterData;
        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_SIP)
        {
            FWLIB_IP4ADDR_Len2Mask(pstData->stSrcIP.uiIPMask, &uiMask);
            if ((pstData->stSrcIP.un_addr.stIP4Addr.s_addr & uiMask) !=
                (pstPfilterPacket->uiSrcIP & uiMask))
            {
                continue;
            }
        }

        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_DIP)
        {
            FWLIB_IP4ADDR_Len2Mask(pstData->stDstIP.uiIPMask, &uiMask);
            if ((pstData->stDstIP.un_addr.stIP4Addr.s_addr & uiMask) !=
                (pstPfilterPacket->uiDstIP & uiMask))
            {
                continue;
            }
        }

        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_SPORT)
        {
            if (pstData->usSPort != pstPfilterPacket->usSPort)
            {
                continue;
            }
        }

        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_DPORT)
        {
            if (pstData->usDPort != pstPfilterPacket->usDPort)
            {
                continue;
            }
        }
        
        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_PROTOCOL)
        {
            if (pstData->ucProtocol != pstPfilterPacket->ucProto)
            {
                continue;
            }
        }

        pstMatchEntry = pstData;
        break;
    }

    rte_rwlock_read_unlock(&g_stPfilterConf[pstPfilterPacket->uiIndex].stPfilter_rwlock);

    if (NULL != pstMatchEntry)
    {
        if (g_stPfilterConf[pstPfilterPacket->uiIndex].uiIP4DebugFlag & PFILTER_DEBUG_PACKET)
        {
            printf("\npfilter match rule info: \n");
            _pfilter_PrintRule(IPPROTO_IP, pstMatchEntry);
        }
        return BOOL_TRUE;
    }
    else
    {
        return BOOL_FALSE; 
    }
}

BOOL_T Pfilter_Match_IPv6(IN PFILTER_PACKET_IPV6_S *pstPfilterPacket)
{
    DTQ_HEAD_S *pstHead = &g_stPfilterConf[pstPfilterPacket->uiIndex].stIP6Head;
    PFILTER_CONF_S *pstEntry, *pstNextEntry;
    PFILTER_DATA_S *pstData, *pstMatchEntry = NULL;
    struct in6_addr  stMask;

    rte_rwlock_read_lock(&g_stPfilterConf[pstPfilterPacket->uiIndex].stPfilter_rwlock);

    DTQ_FOREACH_ENTRY_SAFE(pstHead, pstEntry, pstNextEntry, stNode)
    {
        pstData = &pstEntry->stPfilterData;
        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_SIP)
        {
            FWLIB_IP6ADDR_Len2Mask(pstData->stSrcIP.uiIPMask, &stMask);
            if (BOOL_TRUE != FWLIB_IP6_COMPARE(&pstData->stSrcIP.un_addr.stIP6Addr, &pstPfilterPacket->stSrcIP6, &stMask))
            {
                continue;
            }
        }

        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_DIP)
        {
            FWLIB_IP6ADDR_Len2Mask(pstData->stDstIP.uiIPMask, &stMask);
            if (BOOL_TRUE != FWLIB_IP6_COMPARE(&pstData->stDstIP.un_addr.stIP6Addr, &pstPfilterPacket->stDstIP6, &stMask))
            {
                continue;
            }
        }

        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_SPORT)
        {
            if (pstData->usSPort != pstPfilterPacket->usSPort)
            {
                continue;
            }
        }

        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_DPORT)
        {
            if (pstData->usDPort != pstPfilterPacket->usDPort)
            {
                continue;
            }
        }
        
        if (pstData->uiMatchMask & PFILTER_MATCH_TYPE_PROTOCOL)
        {
            if (pstData->ucProtocol != pstPfilterPacket->ucProto)
            {
                continue;
            }
        }

        pstMatchEntry = pstData;
        break;
    }

    rte_rwlock_read_unlock(&g_stPfilterConf[pstPfilterPacket->uiIndex].stPfilter_rwlock);

    if (NULL != pstMatchEntry)
    {
        if (g_stPfilterConf[pstPfilterPacket->uiIndex].uiIP6DebugFlag & PFILTER_DEBUG_PACKET)
        {
            printf("\npfilter match rule info: \n");
            _pfilter_PrintRule(IPPROTO_IPV6, pstMatchEntry);
        }
        return BOOL_TRUE;
    }
    else
    {
        return BOOL_FALSE; 
    }
}

VOID Pfilter_SetDebug(IN UINT uiIndex, IN UINT uiIPType, IN UINT uiDebugType, IN BOOL_T bIsUndo)
{
    if (IPPROTO_IP == uiIPType)
    {
        if (bIsUndo)
        {
            g_stPfilterConf[uiIndex].uiIP4DebugFlag &= ~uiDebugType;
        }
        else
        {
            g_stPfilterConf[uiIndex].uiIP4DebugFlag |= uiDebugType;
        }
    }
    else if (IPPROTO_IPV6 == uiIPType)
    {
        if (bIsUndo)
        {
            g_stPfilterConf[uiIndex].uiIP6DebugFlag &= ~uiDebugType;
        }
        else
        {
            g_stPfilterConf[uiIndex].uiIP6DebugFlag |= uiDebugType;
        }
    }
    return;
}

VOID Pfilter_GetDebug(IN UINT uiIndex, IN UINT uiIPType)
{
    UINT uiDebugFlag;
    if (IPPROTO_IP == uiIPType)
    {
        uiDebugFlag = g_stPfilterConf[uiIndex].uiIP4DebugFlag;
    }
    else if (IPPROTO_IPV6 == uiIPType)
    {
        uiDebugFlag = g_stPfilterConf[uiIndex].uiIP6DebugFlag;
    }

    printf("Pfilter index %d %s Debug:\n", uiIndex, uiIPType == IPPROTO_IP ? "ip" : "ipv6");
    printf("\tpacket:");
    if (uiDebugFlag & PFILTER_DEBUG_PACKET)
    {
        printf("Enable\n");
    }
    else
    {
        printf("Disable\n");
    }
    return;
}

VOID Pfilter_Init(void)
{
    INT i;
    for(i = 0; i < PFILTER_COUNT_MAX; i++)
    {
        DTQ_Init(&g_stPfilterConf[i].stIP4Head);
        DTQ_Init(&g_stPfilterConf[i].stIP6Head);
        g_stPfilterConf[i].uiIP4DebugFlag = 0;
        g_stPfilterConf[i].uiIP6DebugFlag = 0;
        rte_rwlock_init(&g_stPfilterConf[i].stPfilter_rwlock);
    }
    return;
}

VOID _pfilter_Destroy(IN DTQ_NODE_S *pstNode)
{
    PFILTER_CONF_S *pstEntry;
    pstEntry = DTQ_ENTRY(pstNode, PFILTER_CONF_S, stNode);
    rte_free(pstEntry);
    return;
}

VOID Pfilter_Fini(void)
{
    INT i;
    for(i = 0; i < PFILTER_COUNT_MAX; i++)
    {
        DTQ_FreeAll(&g_stPfilterConf[i].stIP4Head, _pfilter_Destroy);
        DTQ_Init(&g_stPfilterConf[i].stIP4Head);
        DTQ_FreeAll(&g_stPfilterConf[i].stIP6Head, _pfilter_Destroy);
        DTQ_Init(&g_stPfilterConf[i].stIP6Head);

        g_stPfilterConf[i].uiIP4DebugFlag = 0;
        g_stPfilterConf[i].uiIP6DebugFlag = 0;
        rte_rwlock_init(&g_stPfilterConf[i].stPfilter_rwlock);
    }
    return;
}

