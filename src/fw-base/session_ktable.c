
#include "socket.h"
#include "session_ktable.h"
#include "session_kdebug.h"
#include "session_krelationhash.h"
#include "general_rcu.h"


/* 会话中挂模块扩展信息改为动态分配，依次分配2、4、6、12个指针长度 */
#define SESSION_ALLOC_SERVICE_NUM_2    2    /* 第一次分配指针个数为2 */
#define SESSION_ALLOC_SERVICE_NUM_4    4    /* 第二次分配指针个数为4 */
#define SESSION_ALLOC_SERVICE_NUM_6    6    /* 第三次分配指针个数为6 */
#define SESSION_ALLOC_SERVICE_NUM_12   12   /* 第四次分配指针个数为12 */

/* 记录各协议注册扩展数据信息 */
SESSION_EXT_REGINFO_S g_stSessionExtRegInfo;

UINT g_auiSessTotalLen[SESSION_TYPE_MAX];
rte_atomic32_t g_stSessionCount;

AGINGQUEUE_CHANGEABLE_S    g_stSessChangeableQueue;

#define SESSION_HASH_LEN2 (64 * 1024 * 1024UL)

/* 会话池 */
struct rte_mempool *g_apstSessPool[SESSION_TYPE_MAX];


/* 业务模块是否向会话表设置了ALG处理标记 */
BOOL_T SESSION_KIsAlgFlagSet(IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule)
{
    return SESSION_TABLE_IS_ALGFLAG_SET((SESSION_S *)hSession, enModule);
}

/******************************************************************
   Func Name:SESSION_KFreeResetObject
Date Created:2021/04/25
      Author:wangxiaohua
 Description:释放reset session节点内存
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KFreeResetObject(IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj;

    pstSessionRstObj = container_of(pstObject, SESSION_RESET_OBJ_S, stRstObj);
    rte_free(pstSessionRstObj);
    return;
}

/******************************************************************
   Func Name:SESSION_KMallocResetObject
Date Created:2021/04/25
      Author:wangxiaohua
 Description:申请reset session节点内存
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
AGINGQUEUE_RST_MSG_OBJECT_S * SESSION_KMallocResetObject(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj;
    SESSION_RESET_OBJ_S *pstSessionRstObjTmp;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstObjectTmp;

    pstSessionRstObj = container_of(pstObject, SESSION_RESET_OBJ_S, stRstObj);
    pstSessionRstObjTmp = rte_zmalloc(NULL, sizeof(SESSION_RESET_OBJ_S), 0);
    if(NULL != pstSessionRstObjTmp)
    {
        *pstSessionRstObjTmp = *pstSessionRstObj;

        pstObjectTmp = &(pstSessionRstObjTmp->stRstObj);
        SL_NodeInit(&(pstObjectTmp->stNode));
    }
    return (AGINGQUEUE_RST_MSG_OBJECT_S *)pstSessionRstObjTmp;
}

/******************************************************************
   Func Name:IN6ADDR_Cmp
Date Created:2021/04/25
      Author:wangxiaohua
 Description:比较IPv6地址大小
       INPUT:pstAddr1:待比较地址1
             pstAddr2:带比较地址2
      Output:无
      Return:大于0:地址1大于地址2
             小于0:地址1小于地址2
             等于0:地址1等于地址2
     Caution:IPV6地址按网络序输入
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline INT IN6ADDR_Cmp(IN const struct in6_addr *pstAddr1, IN const struct in6_addr *pstAddr2)
{
    UINT i;
    INT iRet;

    for(i=0; i < INET_ADDRSTRLEN; i++)
    {
        iRet = pstAddr1->s6_addr[i] - pstAddr2->s6_addr[i];
        if(0 != iRet)
        {
            break;
        }
    }

    return iRet;
}

/******************************************************************
   Func Name:_session_KIsSameSessionTuple
Date Created:2021/04/25
      Author:wangxiaohua
 Description:判断会话五元组是否相同
       INPUT:IN const SESSION_TUPLE_S *pstTupel1,
             IN const SESSION_TUPLE_S *pstTupel2
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T _session_KIsSameSessionTuple(IN const SESSION_TUPLE_S *pstTupel1,
                                                  IN const SESSION_TUPLE_S *pstTupel2)
{
    BOOL_T bRet = BOOL_FALSE;

    if((pstTupel1->ucL3Family == pstTupel2->ucL3Family)&&
       (pstTupel1->ucProtocol == pstTupel2->ucProtocol)&&
       (pstTupel1->ucType == pstTupel2->ucType)&&
       (pstTupel1->uiTunnelID == pstTupel2->uiTunnelID)&&
       (pstTupel1->vrfIndex == pstTupel2->vrfIndex)&&
       (pstTupel1->unL4Src.usAll == pstTupel2->unL4Src.usAll)&&
       (pstTupel1->unL4Dst.usAll == pstTupel2->unL4Dst.usAll))
    {
        if(AF_INET == pstTupel1->ucL3Family)
        {
            if((pstTupel1->unL3Src.uiIp == pstTupel2->unL3Src.uiIp) &&
               (pstTupel1->unL3Dst.uiIp == pstTupel2->unL3Dst.uiIp))
            {
                bRet = BOOL_TRUE;
            }
        }
        else if (AF_INET6 == pstTupel1->ucL3Family)
        {
            if((0 == IN6ADDR_Cmp(&pstTupel1->unL3Src.stin6, &pstTupel2->unL3Src.stin6)) &&
               (0 == IN6ADDR_Cmp(&pstTupel1->unL3Dst.stin6, &pstTupel2->unL3Dst.stin6)))
            {
                bRet = BOOL_TRUE;
            }
        }
        else if (AF_MAX == pstTupel1->ucL3Family)
        {
            bRet = BOOL_TRUE;
        }
    }
    return bRet;
}

/******************************************************************
   Func Name:_session_KIsSameSessionKey
Date Created:2021/04/25
      Author:wangxiaohua
 Description:判断reset session 关键字是否相同
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey1,
             IN const SESSION_TABLE_KEY_S *pstKey2
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T _session_KIsSameSessionKey(IN const SESSION_TABLE_KEY_S *pstKey1,
                                                 IN const SESSION_TABLE_KEY_S *pstKey2)
{
    BOOL_T bRet = BOOL_FALSE;

    if(((pstKey1->uiMask & ~SESSION_TABLE_BIT_STOP) == (pstKey2->uiMask & ~SESSION_TABLE_BIT_STOP))&&
       (pstKey1->uiModuleFlag == pstKey2->uiModuleFlag)&&
       (pstKey1->ucSessType == pstKey2->ucSessType))
    {
        bRet = _session_KIsSameSessionTuple(&pstKey1->stTuple, &pstKey2->stTuple);
    }

    return bRet;
}

/******************************************************************
   Func Name:SESSION_KIsSameResetMsg
Date Created:2021/04/25
      Author:wangxiaohua
 Description:判断reset session命令是否相同
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
BOOL_T SESSION_KIsSameResetMsg(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject1,
                               IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject2)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj1;
    SESSION_RESET_OBJ_S *pstSessionRstObj2;
    BOOL_T bRet = BOOL_FALSE;

    pstSessionRstObj1 = container_of(pstObject1, SESSION_RESET_OBJ_S, stRstObj);    
    pstSessionRstObj2 = container_of(pstObject2, SESSION_RESET_OBJ_S, stRstObj);

    if(BOOL_TRUE == _session_KIsSameSessionKey(&pstSessionRstObj1->stKey, &pstSessionRstObj2->stKey))
    {
        bRet = BOOL_TRUE;
    }

    return bRet;
}

static inline BOOL_T SESSION_KIsTmpSession(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;

    return SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);
}

/******************************************************************
   Func Name:SESSION_KIsIPv6
Date Created:2021/04/25
      Author:wangxiaohua
 Description:判断会话是否是IPv6会话
       INPUT:SESSION_HANDEL hSession, 会话
      Output:无
      Return:BOOL_TRUE, 是IPv6会话
             BOOL_FALSE,不是IPv6会话
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T SESSION_KIsIPv6(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;

    return SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_IPV6);
}

/******************************************************************
   Func Name:_session_KTable_ResetCheckIFVRF
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset会话的接口VRF检查
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      会话表信息Key
             IN const csp_key_t *pstcspkey,             快转表信息key
             IN UINT uiMask,                            标记
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckIFVRF(IN const SESSION_TABLE_KEY_S *pstKey,
                                               IN const csp_key_t *pstcspkey,
                                               IN UINT uiMask)
{
    UINT uiToken;

    /* VRF检查 */
    if(SESSION_KEY_IS_VPNIDSET(uiMask))
    {
        uiToken = pstcspkey->token;
        if(ntohl(uiToken) != pstKey->stTuple.vrfIndex)
        {
            return BOOL_FALSE;
        }
    }
#if 0
        if(0 == pstKey->stTuple.ucType)
        {
            if(BIT_TEST(pstcspkey->ucType, IPFS_CACHEKEYFLAG_MACFW|
                IPFS_CACHEKEYFLAG_BRIDGE|IPFS_CACHEKEYFLAG_INLINE))
            {
                return BOOL_FALSE;
            }
        }
        else if (0 == ((pstKey->stTuple.ucType) & (pstcspkey->ucType)))
        {
            return BOOL_FALSE;
        }
    }

    /* IFINDEX 检查 */
    if(SESSION_KEY_IS_IFINDEX(uiMask))
    {
        if(pstcspkey->ifIndexRcv != pstKey->pstcspkey)
        {
            return BOOL_FALSE;
        }
    }
#endif

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session6_KTable_ResetCheckSrcDes
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset会话的源目的IP端口检查
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      会话表信息Key
             IN const csp_key_t           *pstcspkey,   快转表信息key
             IN UINT uiMask,                            标记
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session6_KTable_ResetCheckSrcDes(IN const SESSION_TABLE_KEY_S *pstKey,
                                                IN const csp_key_t *pstcspkey,
                                                IN UINT uiMask)
{
    /* 源地址检查 */
    if(SESSION_KEY_IS_SRCIPSET(uiMask))
    {
        if(0 != memcmp(&pstcspkey->src_ip, &pstKey->stTuple.unL3Src.stin6, sizeof(struct in6_addr)))
        {
            return BOOL_FALSE;
        }
    }

    /* 目的地址检查 */
    if(SESSION_KEY_IS_DSTIPSET(uiMask))
    {
        if(0 != memcmp(&pstcspkey->dst_ip, &pstKey->stTuple.unL3Dst.stin6, sizeof(struct in6_addr)))
        {
            return BOOL_FALSE;
        }
    }

    /* 源端口检查 */
    if(SESSION_KEY_IS_SRCPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->src_port) != pstKey->stTuple.unL4Src.usAll)
        {
            return BOOL_FALSE;
        }
    }

    /* 目的端口检查 */
    if(SESSION_KEY_IS_DSTPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->dst_port) != pstKey->stTuple.unL4Dst.usAll)
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session6_KTable_ResetCheckAppStatePro
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset会话的应用协议状态检查
       INPUT:IN const SESSION_S *pstSession             会话
             IN const SESSION_TABLE_KEY_S *pstKey,      会话表信息Key
             IN UINT uiMask,                            标记
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session6_KTable_ResetCheckAppStatePro(IN const SESSION_S *pstSession,
                                                     IN const SESSION_TABLE_KEY_S *pstKey,
                                                     IN UINT uiMask)
{
    /* APP 检查 */
    if(SESSION_KEY_IS_APPSET(uiMask))
    {
        if(pstKey->uiAppID != pstSession->uiAppID)
        {
            return BOOL_FALSE;
        }
    }

    /* 4层协议检查 */
    if(SESSION_KEY_IS_PROTSET(uiMask))
    {
        if(pstSession->stSessionBase.ucSessionL4Type != pstKey->ucSessType)
        {
            return BOOL_FALSE;
        }
    }

    /* 状态检查 */
    if(SESSION_KEY_IS_STATESET(uiMask))
    {
        if((pstKey->ucSessType != pstSession->stSessionBase.ucSessionL4Type) ||
           (pstKey->ucState != pstSession->ucState)) 
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session6_KTable_ResetCheckZoneTimeID
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset会话的域时间段安全策略检查
       INPUT:IN const SESSION_S *pstSession             会话
             IN const SESSION_TABLE_KEY_S *pstKey,      会话表信息Key
             IN UINT uiMask,                            标记
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session6_KTable_ResetCheckZoneTimeID(IN const SESSION_S *pstSession,
                                                     IN const SESSION_TABLE_KEY_S *pstKey,
                                                     IN UINT uiMask)
{
#if 0
    /* 域间检查 */
    if(SESSION_KEY_IS_ZONESET(uiMask))
    {
        if(pstKey->zoneIDSrcID != pstSession->zoneIDSrcID)
        {
            return BOOL_FALSE;
        }
    }

    if(SESSION_KEY_IS_DSTZONESET(uiMask))
    {
        if(pstKey->zoneIDDestID != pstSession->zoneIDDestID)
        {
            return BOOL_FALSE;
        }
    }
#endif

    /* 时间段检查 */
    if(SESSION_KEY_IS_TIMERANGESET(uiMask))
    {
        if(pstKey->uiStartTime > (UINT)pstSession->stSessionBase.uiSessCreateTime ||
           pstKey->uiEndTime < (UINT)pstSession->stSessionBase.uiSessCreateTime)
        {
            return BOOL_FALSE;
        }
    }

#if 0
    /* 安全策略检查 */
    if(SESSION_KEY_IS_SECPNAME(uiMask))
    {
        if((pstKey->uiPolicyID != pstSession->uiPolicyID) ||
           (pstKey->uiRuleID != pstSession->uiRuleID)) 
        {
            return BOOL_FALSE;
        }
    }
#endif

    return BOOL_TRUE;
}


STATIC BOOL_T _session6_KTable_ResetCmp(IN SESSION_S *pstSession,
                                        IN const SESSION_TABLE_KEY_S *pstKey)
{
    UINT uiMask = pstKey->uiMask;
    csp_key_t *pstcspkey;
    BOOL_T bflag;

    /* 模块ID检查 */
    if(SESSION_KEY_IS_MODULESET(uiMask))
    {
        if(!SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, pstKey->uiModuleFlag))
        {
            return BOOL_FALSE;
        }
    }
    if(SESSION_KEY_IS_RESPONDER(uiMask))
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_REPLY);
    }
    else
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    }

    /* 必须是单播 */
    if(IN6ADDR_IsMulticast((struct in6_addr *)&pstcspkey->dst_ip))
    {
        return BOOL_FALSE;
    }

    bflag = _session6_KTable_ResetCheckSrcDes(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckIFVRF(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session6_KTable_ResetCheckAppStatePro(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session6_KTable_ResetCheckZoneTimeID(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    return BOOL_TRUE;
}


/******************************************************************
   Func Name:_session_KTable_ResetCheckSrcDes
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset会话的源目的IP端口检查
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      会话表信息Key
             IN const csp_key_t *pstcspkey,             快转表信息key
             IN UINT uiMask,                            标记
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckSrcDes(IN const SESSION_TABLE_KEY_S *pstKey,
                                               IN const csp_key_t *pstcspkey,
                                               IN UINT uiMask)
{
    /* 源地址检查 */
    if(SESSION_KEY_IS_SRCIPSET(uiMask))
    {
        if(pstcspkey->src_ip != pstKey->stTuple.unL3Src.uiIp)
        {
            return BOOL_FALSE;
        }
    }

    /* 目的地址检查 */
    if(SESSION_KEY_IS_DSTIPSET(uiMask))
    {
        if(pstcspkey->dst_ip != pstKey->stTuple.unL3Dst.uiIp)
        {
            return BOOL_FALSE;
        }
    }

    /* 源端口检查 */
    if(SESSION_KEY_IS_SRCPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->src_port) != pstKey->stTuple.unL4Src.usAll)
        {
            return BOOL_FALSE;
        }
    }

    /* 目的端口检查 */
    if(SESSION_KEY_IS_DSTPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->dst_port) != pstKey->stTuple.unL4Dst.usAll)
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session_KTable_ResetCheckAppStatePro
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset会话的应用协议状态检查
       INPUT:IN const SESSION_S *pstSession             会话
             IN const SESSION_TABLE_KEY_S *pstKey,      会话表信息Key
             IN UINT uiMask,                            标记
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckAppStatePro(IN const SESSION_S *pstSession,
                                                    IN const SESSION_TABLE_KEY_S *pstKey,
                                                    IN UINT uiMask)
{
    /* APP 检查 */
    if(SESSION_KEY_IS_APPSET(uiMask))
    {
        if(pstKey->uiAppID != pstSession->uiAppID)
        {
            return BOOL_FALSE;
        }
    }

    /* 4层协议检查 */
    if(SESSION_KEY_IS_PROTSET(uiMask))
    {
        if(pstSession->stSessionBase.ucSessionL4Type != pstKey->ucSessType)
        {
            return BOOL_FALSE;
        }
    }

    /* 状态检查 */
    if(SESSION_KEY_IS_STATESET(uiMask))
    {
        if((pstKey->ucSessType != pstSession->stSessionBase.ucSessionL4Type) ||
           (pstKey->ucState != pstSession->ucState)) 
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session_KTable_ResetCheckZoneTimeID
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset会话的域时间段安全策略检查
       INPUT:IN const SESSION_S *pstSession             会话
             IN const SESSION_TABLE_KEY_S *pstKey,      会话表信息Key
             IN UINT uiMask,                            标记
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckZoneTimeID(IN const SESSION_S *pstSession,
                                                   IN const SESSION_TABLE_KEY_S *pstKey,
                                                   IN UINT uiMask)
{
#if 0
    /* 域间检查 */
    if(SESSION_KEY_IS_ZONESET(uiMask))
    {
        if(pstKey->zoneIDSrcID != pstSession->zoneIDSrcID)
        {
            return BOOL_FALSE;
        }
    }

    if(SESSION_KEY_IS_DSTZONESET(uiMask))
    {
        if(pstKey->zoneIDDestID != pstSession->zoneIDDestID)
        {
            return BOOL_FALSE;
        }
    }
#endif
    /* 时间段检查 */
    if(SESSION_KEY_IS_TIMERANGESET(uiMask))
    {
        if(pstKey->uiStartTime > (UINT)pstSession->stSessionBase.uiSessCreateTime
          || pstKey->uiEndTime < (UINT)pstSession->stSessionBase.uiSessCreateTime)
        {
            return BOOL_FALSE;
        }
    }
#if 0
    /* 安全策略检查 */
    if(SESSION_KEY_IS_SECPNAME(uiMask))
    {
        if((pstKey->uiPolicyID != pstSession->uiPolicyID) ||
           (pstKey->uiRuleID != pstSession->uiRuleID)) 
        {
            return BOOL_FALSE;
        }
    }
#endif

    return BOOL_TRUE;
}


STATIC BOOL_T _session_KTable_ResetCmp(IN SESSION_S *pstSession,
                                       IN const SESSION_TABLE_KEY_S *pstKey)
{
    UINT uiMask = pstKey->uiMask;
	csp_key_t *pstcspkey;
    BOOL_T bflag;

    /* 模块ID检查 */
    if(SESSION_KEY_IS_MODULESET(uiMask))
    {
        if(!SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, pstKey->uiModuleFlag))
        {
            return BOOL_FALSE;
        }
    }

    if(SESSION_KEY_IS_RESPONDER(uiMask))
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_REPLY);
    }
    else
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    }

    /* 必须是单播 */
    if(IN_MULTICAST(ntohl(pstcspkey->dst_ip)))
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckSrcDes(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }
    
    bflag = _session_KTable_ResetCheckIFVRF(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckAppStatePro(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckZoneTimeID(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session_KNeedResetProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:判断会话是否该reset
       INPUT:IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
             IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
BOOL_T _session_KNeedResetProc(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
                               IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject)
{
    SESSION_TABLE_KEY_S *pstKey;
    SESSION_S *pstSession;
    SESSION_RESET_OBJ_S *pstSessionRstObj;
    BOOL_T bRet = BOOL_FALSE;

    pstSessionRstObj = container_of(pstResetObj, SESSION_RESET_OBJ_S, stRstObj);
    pstKey = (SESSION_TABLE_KEY_S *)&pstSessionRstObj->stKey;

    pstSession = container_of(pstAgingObject, SESSION_S, stSessionBase.unAgingRcuInfo.stAgingInfo);

    if(((INT)pstResetObj->uiResetTime - (INT)pstSession->stSessionBase.uiSessCreateTime) <= 1)
    {
        return BOOL_FALSE;
    }

    if((0 == pstKey->uiMask) &&
       (AF_MAX == pstKey->stTuple.ucL3Family))
    {
        /*通配，直接返回true*/
        /*设置删除日志类型为配置删除*/
        /*指定了ipv4或ipv6的情况逐条删除*/
        SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,
                                    (USHORT)SESSION_DELTYPE_CFG);
        /*通配情况在外面下驱动删除，此处仅打deleting标记*/        
        SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING);
        return BOOL_TRUE;
    }

    if(SESSION_KIsIPv6((SESSION_HANDLE)pstSession))
    {
        if((AF_MAX == pstKey->stTuple.ucL3Family) ||
           (AF_INET6 == pstKey->stTuple.ucL3Family))
        {
            bRet = _session6_KTable_ResetCmp(pstSession, pstKey);
        }
    }
    else
    {        
        if((AF_MAX == pstKey->stTuple.ucL3Family) ||
           (AF_INET == pstKey->stTuple.ucL3Family))
        {
            bRet = _session_KTable_ResetCmp(pstSession, pstKey);
        }
        
    }

    if(BOOL_TRUE == bRet)
    {
        /* 设置删除日志类型为配置删除 */            
        SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,
                                    (USHORT)SESSION_DELTYPE_CFG);

        SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
    }
    return bRet;
}

VOID SESSION_KReset(IN const SESSION_TABLE_KEY_S *pstKey)
{
    SESSION_RESET_OBJ_S stSessionRstObj;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstRstObj;
    UINT uiMDCLocalIndex = 0; //MDC_GetCurrentLocalIndex4FFW();

    memset(&stSessionRstObj, 0, sizeof(SESSION_RESET_OBJ_S));
    stSessionRstObj.stKey = *pstKey;

    pstRstObj = &(stSessionRstObj.stRstObj);
    pstRstObj->bNeedAdjCurson = BOOL_TRUE;
    pstRstObj->enRetsetType = AGINGQUE_RESET_TYPE_DEFAULT;
    pstRstObj->uiMDCLocalIndex = uiMDCLocalIndex;
    SL_NodeInit(&(pstRstObj->stNode));
    pstRstObj->pfFree = SESSION_KFreeResetObject;
    pstRstObj->pfMalloc = SESSION_KMallocResetObject;
    pstRstObj->pfIsSameMsg = SESSION_KIsSameResetMsg;
    pstRstObj->pfNeedResetProc = _session_KNeedResetProc;

    AGINGQUEUE_UnStable_AddResetObj(&(g_stSessionstAgingQueue), pstRstObj);
    return;
}

/******************************************************************
   Func Name:SESSION_KModuleExtDestroy
Date Created:2021/04/25
      Author:wangxiaohua
 Description:释放业务模块扩展信息
       INPUT:IN SESSION_S *pstSession
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID SESSION_KModuleExtDestroy(IN SESSION_S *pstSession)
{
    SESSION_EXT_DESTROY_CB_PF pfExtDestroy;
    VOID *pCb;

    if (0 == pstSession->usAttachFlag)
    {
        return;
    }

    /* 通过业务回调释放扩展信息 */
    pCb = SESSION_KGetALGCb((SESSION_HANDLE)pstSession);
    if (pCb != NULL) 
    {
        pfExtDestroy = g_stSessionExtRegInfo.astCustomExtInfo[SESSION_MODULE_ALG].pfExtDestroy;
        pfExtDestroy((SESSION_HANDLE)pstSession, pCb);
    }
    
    return;
}

/******************************************************************
   Func Name:SESSION_KDestroy
Date Created:2021/04/25
      Author:wangxiaohua
 Description:释放会话内存，提供给RCU的回调函数
       INPUT:RCU_REG_S *pstRcuHead, RCU头
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KDestroy(IN VOID *pSession)
{
    UCHAR ucSessionType;
	flow_connection_t *fcp;
	conn_sub_t *csp;
	SESSION_S *pstSession = (SESSION_S *)pSession;

    /* 设置快转失效 */
    csp = pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL];
	fcp = csp2base(csp);	
	set_fcp_invalid(fcp, FC_CLOSE_OTHER);

    ucSessionType = pstSession->stSessionBase.ucSessionType;
	
    /*释放扩展信息*/
    SESSION_KModuleExtDestroy(pstSession);
    
    rte_mempool_put(g_apstSessPool[ucSessionType], pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_KNotify_TableCreate
Date Created:2021/04/25
      Author:wangxiaohua
 Description:调用各模块注册的会话创建事件回调函数.
       INPUT:SESSION_HANDLE hSession
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KNotify_TableCreate(IN SESSION_HANDLE hSession)
{
    SESSION_MODULE_E enModule;
    SESSION_KCREATE_CB_PF pfSessCreate;
    SESSION_S *pstSession = (SESSION_S *)hSession;

    if(0 == pstSession->usAttachFlag)
    {
        return;
    }

    for (enModule = (SESSION_MODULE_E)0; enModule < SESSION_MODULE_MAX; enModule++)
    {
        /* 目前各模块的create函数都是去获取扩展信息，因此可提前判断
           此会话扩展标识信息来判断是否需要调用create函数，假如有扩展信息之外的处理
           这里需要同步修改
        */
        if(SESSION_TABLE_IS_ATTACHFLAG_SET((SESSION_S *)hSession, enModule))
        {
            pfSessCreate = g_astModuleRegInfo[enModule].pfSessCreate;
            if(NULL != pfSessCreate)
            {
                pfSessCreate(hSession);
            }
        }
    }
    
    return;
}

/******************************************************************
   Func Name:SESSION_KNotify_TableDelete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:调用各模块注册的会话删除事件回调函数
       INPUT:SESSION_HANDLE hSession, 会话表
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KNotify_TableDelete(IN SESSION_HANDLE hSession)
{
    SESSION_MODULE_E enModule;
    UINT uiModule;
    SESSION_KDELETE_CB_PF pfSessDelete;
    SESSION_S *pstSession = (SESSION_S *)hSession;

    if(0 == pstSession->usAttachFlag)
    {
        return;
    }

    for(uiModule = 0; uiModule < SESSION_MODULE_MAX; uiModule++)
    {
        enModule = (SESSION_MODULE_E)uiModule;
        if (SESSION_TABLE_IS_ATTACHFLAG_SET((SESSION_S *)hSession, enModule))
        {
            pfSessDelete = g_astModuleRegInfo[enModule].pfSessDelete;
            if(NULL != pfSessDelete)
            {
                pfSessDelete(hSession);
            }
        }

        /* 会话需要在RCU_CALL之前把扩展信息删除的debug信息提前打印，因为在RCU_CALL时已无法跟踪会话所属的邋VD了，
        打debug信息的时候，实际上扩展信息还没有释放掉，但是，认为RCU_CALL之后，内存很快就会真正释放掉 */
        if (SESSION_TABLE_IS_ATTACHFLAG_SET((SESSION_S *)hSession, enModule))
        {
            SESSION_DBG_EXT_EVENT_SWTICH((SESSION_S *)hSession, enModule, EVENT_DEL);
        }
    }

    return;
}


/* 会话表扩展信息注册 */
STATIC VOID SESSION_KRegExtNum(IN USHORT usModule,
                               IN SESSION_EXT_DESTROY_CB_PF pfExtDestroy)
{
    g_stSessionExtRegInfo.astCustomExtInfo[usModule].pfExtDestroy = pfExtDestroy;

    return;
}


/******************************************************************
   Func Name:SESSION_KRegisterModule
Date Created:2021/04/25
      Author:wangxiaohua
 Description:基于会话的业务向会话模块注册
             注册包括会话上模块数据的大小，以及会话各事件的回调函数.
             回调函数的指针可以是NULL.
       INPUT:enModule   ---- 会话业务模块ID. 模块ID由会话模块统一分配管理
             pstRegInfo ---- 模块的信息结构，包括事件回调函数，以及模块数据大小
      Output:无
      Return:ERROR_SUCCESS ---- 注册成功
             ERROR_FAILED  ---- 输入参数不合法
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG SESSION_KRegisterModule(IN SESSION_MODULE_E enModule, IN const SESSION_MODULE_REG_S *pstRegInfo)
{
    ULONG ulErrCode = ERROR_SUCCESS;

    if ((enModule >= SESSION_MODULE_MAX) || (NULL == pstRegInfo))
    {
        return ERROR_FAILED;
    }

    g_astModuleRegInfo [enModule] = *pstRegInfo;

    /* 注册业务模块的扩展数据个数 */
    SESSION_KRegExtNum ((USHORT)enModule, pstRegInfo->pfExtDestroy);

    return ulErrCode;
}

/******************************************************************
   Func Name:SESSION_KPut
Date Created:2021/04/25
      Author:wangxiaohua
 Description:减引用计数处理，减到0时触发会话内存释放
       INPUT:IN SESSION_S *pstSession, 会话
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KPut(IN SESSION_S *pstSession)
{
    if(rte_atomic32_dec_and_test(&pstSession->stSessionBase.stRefCount.stCount))
    {
        /* 删除父会话的引用计数 */
        if (NULL != pstSession->pstParent)
        {
            SESSION_KPut(pstSession->pstParent);
        }

        /* 恢复规格统计数值 */
        SESSION_InfoCountDec();

		general_rcu_qsbr_dq_enqueue((void *)pstSession, SESSION_KDestroy);
    }
    return;
}

STATIC inline VOID _session4_KMbufDestroy(IN SESSION_S *pstSession)
{
    /* 如果是临时会话，在这里通知删除 */
    SESSION_KNotify_TableDelete((SESSION_HANDLE) pstSession);

    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_DELETE);

    /* 删除父会话的引用计数 */
    if(NULL!= pstSession->pstParent)
    {
        SESSION_KPut((SESSION_S *)(pstSession->pstParent));
        pstSession->pstParent = NULL;
    }

    /* 临时会话肯定还没有使用引用计数，因此直接删除 */
    SESSION_KDestroy(pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_KRelationListProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话表删除时对挂在会话上的关联表进行处理
       INPUT:DL_HEAD_S *pstRelationList, 关联表链表
      Output:无
      Return:无
     Caution:对于关心父会话的关联表:摘链、设DELETING标志、父会话指针置空
             对于不关心父会话的关联表:不做任何处理
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID SESSION_KRelationListProc(IN DL_HEAD_S *pstRelationList, IN SESSION_S *pstSession)
{
    RELATION_S *pstRelation;
    DL_NODE_S *pstCurNode;
    DL_NODE_S *pstNextNode;

    DL_FOREACH_SAFE(pstRelationList, pstCurNode, pstNextNode)
    {
        pstRelation = container_of(pstCurNode, RELATION_S, stNodeInSession);
        if(BOOL_TRUE == pstRelation->bCareParentFlag)
        {
            DL_Del(pstCurNode);
            RELATION_SET_DELETING(pstRelation);
            pstRelation->pstParent = NULL;
        }
    }

    if (BOOL_TRUE == DL_IsEmpty(pstRelationList))
    {
        DL_Init(pstRelationList);
    }

    return;
}

/******************************************************************
   Func Name:SESSION_Delete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话表摘HASH
       INPUT:IN SESSION_S *pstSession, 会话
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID SESSION_Delete(IN SESSION_S *pstSession)
{
    SESSION_CTRL_S *pstSessionMdc;

    pstSessionMdc = SESSION_CtrlData_Get();

    #if 0
    /* 发送日志 */
    if ( SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_LOG_ENABLE) &&
         (BOOL_TRUE == SESSION_IsOwner(pstSession)))
    {
        SESSION_LOG_PROC_Delete(pstSession, pstSessionMdc);
    }

    /* GDX 调用ntop接口发送会话流量报表 */
    if (BOOL_TRUE == pstSessionMdc->bStatEnable)
    {
        NTOP_KSession_SendLog((SESSION_HANDLE)pstSession);
    }
    #endif

    /* 通知删除 */
    SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);

    /* 更新统计信息 */
    SESSION_KDecStat(pstSessionMdc, (SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                                            pstSession->uiOriginalAppID);


    //rte_spinlock_lock(&(pstSession->stLock));
    /* 删除所有本会化创建的关联表 */
    SESSION_KRelationListProc(&(pstSession->stRelationList), pstSession);
    //rte_spinlock_unlock(&(pstSession->stLock));

    SESSION_KPut(pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_DisDelete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话删除，会话同步删除备份的会话
       INPUT:IN SESSION_S *pstSession, 会话
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_DisDelete(IN SESSION_S *pstSession)
{
    SESSION_Delete(pstSession);
}

/* 会话表删除时对挂在会话上的关联表进行处理 */
STATIC VOID SESSION6_KRelationListProc(IN DL_HEAD_S *pstRelationList, IN SESSION_S *pstSession)
{
    RELATION6_S *pstRelation;
    DL_NODE_S *pstCurNode;
    DL_NODE_S *pstNextNode;

    DL_FOREACH_SAFE(pstRelationList, pstCurNode, pstNextNode)
    {
        pstRelation = container_of(pstCurNode, RELATION6_S, stNodeInSession);
        if(BOOL_TRUE == pstRelation->bCareParentFlag)
        {
            DL_Del(pstCurNode);
            RELATION_SET_DELETING(pstRelation);
            pstRelation->pstParent = NULL;
        }
    }

    if (BOOL_TRUE == DL_IsEmpty(pstRelationList))
    {
        DL_Init(pstRelationList);
    }

    return;
}

/* 会话表摘HASH */
VOID SESSION6_Delete(IN SESSION_S *pstSession)
{
    SESSION_CTRL_S *pstSessionMdc;

    /* 摘hash表和删除，确保打了delete标记的会话不再用于报文匹配 */
    if (!SESSION_TABLE_IS_TABLEFLAG(&(pstSession->stSessionBase), SESSION_CACHE_DELETED))
    {
        IP6FS_DeletePairFromHash(pstSession);
    }

    pstSessionMdc = SESSION_CtrlData_Get();

#if 0
    /* 发送日志 */
    if ( SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_LOG_ENABLE) &&
         (BOOL_TRUE == SESSION_IsOwner(pstSession)))
    {
        SESSION6_KLOG_PROC_Delete(pstSession, pstSessionMdc);
    }

    /* GDX 调用ntop接口发送会话流量报表 */
    if (BOOL_TRUE == pstSessionMdc->bStatEnable)
    {
        NTOP_KSession6_SendLog((SESSION_HANDLE)pstSession);
    }
#endif

    /* 通知删除 */
    SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);

    /* 更新统计信息 */
    SESSION_KDecStat(pstSessionMdc, (SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                                            pstSession->uiOriginalAppID);


    //rte_spinlock_lock(&(pstSession->stLock));
    /* 删除所有本会化创建的关联表 */
    SESSION6_KRelationListProc(&(pstSession->stRelationList), pstSession);
    //rte_spinlock_unlock(&(pstSession->stLock));

    SESSION6_KPut(pstSession);

    return;
}


/******************************************************************
   Func Name:SESSION6_KPut
Date Created:2021/04/25
      Author:wangxiaohua
 Description:减引用计数处理，减到0时触发会话内存释放
       INPUT:IN SESSION_S *pstSession, 会话
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION6_KPut(IN SESSION_S *pstSession)
{
    if(rte_atomic32_dec_and_test(&pstSession->stSessionBase.stRefCount.stCount))
    {
        /* 删除父会话的引用计数 */
        if (NULL != pstSession->pstParent)
        {
            SESSION6_KPut(pstSession->pstParent);
        }

        /* 恢复规格统计数值 */
        SESSION_InfoCountDec();
		
		general_rcu_qsbr_dq_enqueue((void *)pstSession, SESSION_KDestroy);
    }
    return;
}

/* MBUF释放时解除MBuf对会话的引用。
   该函数通过调用MBUF_RegExtCacheFreeFunc进行注册，
   在MBuf释放时，会调用该回调函数。如果MBuf中会话指针不为空，则减引用计数，
   引用计数减为0时，释放会话。
*/
STATIC inline VOID _session6_KMbufDestroy(IN SESSION_S *pstSession)
{
    /* 如果是临时会话，在这里通知删除 */
    SESSION_KNotify_TableDelete((SESSION_HANDLE) pstSession);

    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_DELETE);

    /* 删除父会话的引用计数 */
    if (NULL!= pstSession->pstParent)
    {
        SESSION6_KPut((SESSION_S *)(pstSession->pstParent));
        pstSession->pstParent = NULL;
    }

    /* 临时会话肯定还没有使用引用计数，因此直接删除 */
    SESSION_KDestroy(pstSession);

    return;
}

/* MBUF释放时解除MBuf对会话的引用。
   该函数通过调用MBUF_RegExtCacheFreeFunc进行注册，
   在MBuf释放时，会调用该函数。如果MBuf中会话指针不为空，则减引用计数，
   引用计数减为0时，释放会话。
*/
ULONG SESSION_KMbufDestroy(IN MBUF_S *pstMbuf)
{
    SESSION_S *pstSession;
    flow_connection_t *fcp;
		      
    pstSession = (SESSION_S *)GET_FWSESSION_FROM_LBUF(pstMbuf);
    if(pstSession != NULL)
    {
        /*只有是临时会话才删除*/
        if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
        {
            /* ipv4 会话 */
            if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_IPV6))
            {
                _session4_KMbufDestroy(pstSession);
            }
            else
            {   
                _session6_KMbufDestroy(pstSession);
            }
        }

        /* 将会话标志清0 */
        MBUF_SET_SESSION_FLAG(pstMbuf, 0);
    }
	else
	{		
		fcp = GET_FC_FROM_LBUF(pstMbuf);
		set_fcp_invalid(fcp, FC_CLOSE_OTHER); 
	}
	
    return ERROR_SUCCESS;
}

/* 会话表项管理一阶段初始化函数 */
ULONG SESSION_KTableInit(VOID)
{
    ULONG ulErrCode;

    memset (&g_stSessionExtRegInfo, 0, sizeof(g_stSessionExtRegInfo));

    memset (&g_auiSessTotalLen, 0, sizeof(g_auiSessTotalLen));
    g_auiSessTotalLen[SESSION_TYPE_NORMAL] = SESS_MEMPOOL_ELT_SIZE_NORMAL;
    
    memset (&g_stSessChangeableQueue, 0, sizeof(g_stSessChangeableQueue));
    
    /* 当前只有alg在用changeablequeue,其不再区分mdc */
    ulErrCode = AGINGQUEUE_Changeable_InitQueue(&g_stSessChangeableQueue);

	ulErrCode |= SESSION_RelationHash_Init();

    /* 初始化会话的mempool */
	/* create a mempool (with cache) for normal session */
	g_apstSessPool[SESSION_TYPE_NORMAL] = rte_mempool_create("normal_session", SESS_MEMPOOL_SIZE_NORMAL,
		SESS_MEMPOOL_ELT_SIZE_NORMAL,
		RTE_MEMPOOL_CACHE_MAX_SIZE, 0,
		NULL, NULL,
		NULL, NULL,
		SOCKET_ID_ANY, 0);

    /* 如果转发或其它地方已经调过，这里就不用调了;   
       需要在转发模块的大循环中调rte_timer_manage()来保证timer精度,
       建议每10ms或1ms调用一次rte_timer_manage() */
    //在main函数中调用 rte_timer_subsystem_init();

    return ulErrCode;
}


VOID SESSION_KTableFini(VOID)
{
    AGINGQUEUE_Changeable_DestroyQueue(&g_stSessChangeableQueue);

    /* 释放会话的mempool */
    rte_mempool_free(g_apstSessPool[SESSION_TYPE_NORMAL]);

    return;
}
							 
/*
函数描述:  获取并创建会话扩展信息的接口, 通过锁机制支持并发添加扩展信息
输入参数:  SESSION_HANDLE hSession,             会话
		 SESSION_MODULE_E enModule,         业务模块
		 SESSION_ATTACH_CREATE_PF pfCreate, 扩展信息创建函数, 当pfGet获取为空时调用
		 ULONG ulPara,                      入参, 由调用者定义
注意点:     此函数修改会影响转发性能, 修改前需要跟设计组确认
***************************************************************************/
VOID *SESSION_KGetExtInfoSafe(IN SESSION_HANDLE hSession,
                              IN SESSION_MODULE_E enModule,
                              IN SESSION_ATTACH_CREATE_PF pfCreate,
                              IN ULONG ulPara)
{
	VOID *pExtInfo;

	/* 预取扩展信息，如果已经有扩展信息就直接返回 
	pExtInfo = SESSION_KGetStaticExtInfo(hSession, enModule);
	if(NULL != pExtInfo)
	{
		return pExtInfo;
	}*/

	/*spin_lock_bh(&pstSession->stLock);*/
	/* 锁里面重新获取扩展信息，规避并发创建的场景 */
	pExtInfo = SESSION_KGetStaticExtInfo(hSession, enModule);
	if(NULL == pExtInfo)
	{
		pExtInfo = pfCreate(hSession, ulPara);
	}
	/*spin_unlock_bh(&pstSession->stLock);*/

	return pExtInfo;
}

