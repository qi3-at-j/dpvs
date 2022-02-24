#include "session.h"
#include "session_kl4proto.h"
#include "session_ktable.h"
#include "session_kdebug.h"
#include "session_ktableaging.h"
#include "ac.h"
#include "session_kalg.h"
#include "session_util.h"
#include "session_ext.h"
#include "agingqueue.h"
#include "ip6_util.h"
#include "dpi.h"
#include "apr.h"
#include "../access_control/secpolicy_match.h"

/* 各协议对应的会话类型 */
extern SESSION_L4_TYPE_E g_aenSessionType[IPPROTO_MAX];
extern UCHAR g_aucIcmpv6ReverType[];
extern RELATION6_S *SESSION6_RelationHash_Find(IN const csp_key_t *pstcspkey);

/* 异常统计 */
VOID SESSION6_KStatFailInc(IN SESSION_STAT_FAIL_TYPE_E enStatFailType, INOUT SESSION_CTRL_S *pstSessionCtrl)
{
    rte_atomic32_inc(&pstSessionCtrl->astStatFailCnt[SESSION_STAT_IPV6][enStatFailType]);
    return;
}

/* 获取ipv6四层偏移 */
STATIC INLINE ULONG session6_kGetL4Offset(IN MBUF_S *pstMbuf, IN UINT uiL3Offset,
                                          OUT UINT *puiIpLen, OUT UINT *puiL4Offset)
{
    ULONG ulRet;
    UCHAR ucHdrProto = IPPROTO_IPV6;
    UINT uiHdrOff = uiL3Offset;
    IP6_S *pstIP6;

    /* 偏移IP头到上层协议 */
    ulRet = IP6_GetLastHdr(pstMbuf, &uiHdrOff, &ucHdrProto);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    *puiL4Offset = uiHdrOff;

    pstIP6 = MBUF_BTOD_OFFSET(pstMbuf, uiL3Offset, IP6_S *);

    *puiIpLen = ntohs(pstIP6->ip6_usPLen) + sizeof(IP6_S);

    return ulRet;
}

/* IPv6合法性检查 */
STATIC BOOL_T session6_KIPv6addr_IsInValid(IN const struct in6_addr *pstAddr)
{
    return IN6ADDR_IsUnspecified(pstAddr);
}

/* IP合法性检查 */
STATIC ULONG session6_kCheckAddress(IN const csp_key_t *pstcskey)
{
    if(session6_KIPv6addr_IsInValid((struct in6_addr *)&pstcskey->dst_ip) ||
       session6_KIPv6addr_IsInValid((struct in6_addr *)&pstcskey->src_ip))
    {
        return ERROR_FAILED;
    }
    
    return ERROR_SUCCESS;
}

/* 报文单包合法性检查 */
STATIC ULONG session6_kcheckPacket(IN MBUF_S *pstMbuf,
                                   IN const csp_key_t *pstcskey,
                                   IN UCHAR ucSessL4Type,
                                   IN UINT uiL3OffSet,
                                   IN UINT uiL4OffSet,
                                   OUT UCHAR *pucNewState)
{
    ULONG ulRet;
    
    /*进行报文单包检查:可能是一个畸形包，或者是一个ICMP错误消息报文。
     *对于畸形报文，直接返回错误。
     *对于ICMP错误消息，需要检查是否属于某个会话引起的错误报文，但不进行统计以及状态机处理。
     *对于属于会话的ICMP Error 通知报文，标识出报文所属会话。
     *对于不属于会话的，按不匹配会话处理。
     */

    ulRet = session6_kCheckAddress(pstcskey);

    if(SESSION_L4_TYPE_TCP == ucSessL4Type)
    {
        ulRet |= SESSION_KCheckTcpNew(pstMbuf, uiL4OffSet, pucNewState);
    }
    else if((SESSION_L4_TYPE_UDP != ucSessL4Type) && (SESSION_L4_TYPE_RAWIP != ucSessL4Type))
    {
        ulRet |= SESSION_KCheckOtherNew(pstMbuf, uiL3OffSet, uiL4OffSet, pstcskey->proto);
    }
    else
    {
        *pucNewState = UDP_ST_OPEN;
    }

    return ulRet;
}

/* 链表指针、Updtelime不需要初始化，会在加入链表，老化队列时赋值 */
STATIC VOID session6_kInitSession(IN UCHAR ucSessL4Type,
							      IN UINT uiAppID,
								  IN UINT uiTrustValue,
                                  IN SESSION_CTRL_S *pstSessionCtrl,
								  INOUT SESSION_S *pstSess)
{
	pstSess->stSessionBase.uiSessCreateTime = (UINT)time(NULL);
	pstSess->stSessionBase.ucSessionL4Type = ucSessL4Type;

	SESSION_KAgingRefresh(pstSess);

	/* 通过APPID识别会话的ALG类型 */
	pstSess->uiAppID = uiAppID;
	pstSess->uiTrustValue = uiTrustValue;

	/*记录会话的初始AppID（给alg扩展快老化来用），后续不会随着appchange而变化*/
	pstSess->uiOriginalAppID = uiAppID;

	/* 设置配置序号 */
	pstSess->usCfgSeq = pstSessionCtrl->usCfgSeq;

	/* 设置临时会话标志位 */
	SESSION_TABLE_SET_TABLEFLAG(&pstSess->stSessionBase, SESSION_TEMP);

	return;
}

/*
初始化会话结构的参数
Caution∶ 链表指针、Updatelime不需要初始化，会在加入链表，老化队列时赋值
这个函数无需内联，故定义为外部函数
*/
STATIC VOID session6_kInitExtSession(IN const MBUF_S *pstMbuf, 
							         IN USHORT usSessAlgType,
						        	 IN const RELATION6_S *pstRelation,
							         INOUT SESSION_S *pstSess)
{
	SESSION_S *pstParent;
	NEW_SESSION_BY_RELATION_PF pfNewNotify; 
	ULONG ulRet;

	/* 如果匹配关联表，根据关联项设置会话的参数 */ 
	if (NULL != pstRelation)
	{
		/* 由于会话中指向了父会话， 需要对父会话的引用计数 +1 */
		pstParent = RCU_Deref(pstRelation->pstParent);
		if(NULL != pstParent)
		{
			ulRet = SESSION_KGetNotZero((SESSION_S*)pstParent);
			if (ERROR_SUCCESS == ulRet)
			{
				pstSess->pstParent = pstParent;
				pstSess->ucDirAssociateWithParent = (UCHAR)pstRelation->enChildDir;

				/* 双主alg业务需要透传到同一板上处理
				SESSION_KTrans_Enable(pstSess);*/
			}
		}

		/* 关联表匹配事件通知 */
		pfNewNotify = pstRelation->pfNewSession; 
		if (NULL != pfNewNotify)
		{
			(VOID)pfNewNotify((SESSION_HANDLE)pstSess, &pstRelation->stAttachData, pstMbuf);
		}

		if (!RELATION_IS_PERSIST(pstRelation))
		{
			/* 子会话命中非persist关联表的时候，不立即删除关联表,
			需要等到子会话正式化的时候再删除关联表，因此先给会话设置一个标记. */
			SESSION_TABLE_SET_TABLEFLAG(&pstSess->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION);
		}
	}

	pstSess->usSessAlgType = usSessAlgType;
	rte_spinlock_init(&(pstSess->stLock));

	return;
}

STATIC SESSION_S* session6_kCreateWithRelation(IN MBUF_S *pstMbuf,
                                               IN UCHAR ucSessL4Type,
                                               IN VOID *pcsp,
                                               IN SESSION_CTRL_S *pstSessionCtrl,
                                               IN const RELATION6_S *pstRelation,
                                               IN UINT uiL3OffSet)
{
    SESSION_S *pstSession = NULL;
    UINT uiAppID;	
	UINT uiTrustValue;
    USHORT usSessAlgType;
    flow_connection_t *fcp;
	conn_sub_t *csp, *peer;
	csp_key_t *pstcskey;
    USHORT usDport;	
    struct in6_addr stSrcIP6;
    struct in6_addr stDstIP6;

    csp = (conn_sub_t *)pcsp;
	pstcskey = GET_CSP_KEY(csp);

    if ((NULL == pstRelation) || (NULL == pstRelation->pstParent))
    {
        usDport = htons(pstcskey->dst_port);
        uiAppID = APR_GetAppByPort(usDport, pstcskey->proto);
		uiTrustValue = APR_TRUST_PORT;
    }
    else
    {
        uiAppID = pstRelation->uiAppID;
		uiTrustValue = APR_TRUST_SIG_FINAL;
    }

    usSessAlgType = SESSION_KGetSessionAlgType(uiAppID);
  
    pstSession = SESSION_Malloc(SESSION_TYPE_NORMAL);
    if(NULL ==pstSession)
    {
        SESSION_DBG_SESSION_ERROR_SWTICH(ERROR_SESSION_MEMORY_NOT_ENOUGH);
        return NULL;
    }

    peer = csp2peer(csp);
	fcp  = csp2base(csp);

    /* 快转的方向自己设置，由我们触发创建的为接收方 */
    pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL] = csp;
    pstSession->stSessionBase.pCache[SESSION_DIR_REPLY] = peer;
    SET_FWSESSION_TO_FC(fcp, pstSession);

    session6_kInitSession(ucSessL4Type, uiAppID, uiTrustValue, pstSessionCtrl, pstSession);

    /* 设置AppID到MBUF */
    MBUF_SET_APP_ID(pstMbuf, uiAppID);

    /*设置流量方向 内到外 或 外到内 */
	memcpy(&stSrcIP6, &(pstcskey->src_ip), sizeof(struct in6_addr));
    memcpy(&stDstIP6, &(pstcskey->dst_ip), sizeof(struct in6_addr));
	pstSession->uiDirect = SecPolicy_IP6_FlowDirect(pstcskey->token, stSrcIP6, stDstIP6);

    /*设置会话的ipv6类型标记*/
    SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, SESSION_IPV6);
    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_CREATE);

    session6_kInitExtSession(pstMbuf, usSessAlgType, pstRelation, pstSession);

    return pstSession;
}

static inline VOID SESSION6_KAging_SetClass(IN const MBUF_S *pstMBuf,
											IN SESSION_CTRL_S *pstSessionCtrl,
											IN SESSION_S *pstSession)
{
	AGINGQUEUE_UNSTABLE_CLASS_S *pstClass = NULL;
	UCHAR ucSessionL4Type;

	ucSessionL4Type = pstSession->stSessionBase.ucSessionL4Type;
    pstClass = &pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV6][ucSessionL4Type][pstSession->ucState];
    SESSION_DBG_AGING_EVENT_SWITCH(pstSession, DBG_AGING_L4AGING);

	SESSION_KAgingRefresh(pstSession);
	AGINGQUEUE_UnStable_Switch(&pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo, pstClass);

	return;
}

/******************************************************************
   Func Name:SESSION_KRefreshParents
Date Created:2021/04/25
      Author:wangxiaohua
 Description:更新本会话所有上层父会话的老化时间
       INPUT:IN SESSION_S *pstSession,  会话
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KRefreshParents(IN const SESSION_S *pstSession)
{
    SESSION_S *pstParent;

    pstParent = pstSession->pstParent;
    while (NULL != pstParent)
    {
        SESSION_KAgingRefresh((SESSION_S *) pstParent);
        pstParent = pstParent->pstParent;
    }

    return;
}

STATIC VOID session6_kLayer4StateNewExt(IN SESSION_S *pstSession,
										IN USHORT usL3_Offset,
										IN UINT uiL4_Offset,
										IN MBUF_S  *pstMBuf,
										IN UCHAR ucPro,
										IN SESSION_CTRL_S *pstSessionCtrl)
{
	SESSION_L4_PROTO_S *pstL4Proto;
	ULONG ulRet;

	pstL4Proto = SESSION_KGetL4Proto_Proc(ucPro);
    
	ulRet = pstL4Proto->pfFirstPacket(pstMBuf, uiL4_Offset, pstSession);
    
	ulRet |= pstL4Proto->pfState(pstSession,pstMBuf,usL3_Offset,uiL4_Offset);
	if (ulRet != ERROR_SUCCESS)
	{
		SESSION_DBG_PACKETS_EVENT_SWITCH(pstMBuf,usL3_Offset, DBG_ABNORM_PKT_INVALID);

		/* 设置非法报文标记，但报文还是属于会话，只不过状态不对 */
		SESSION_BAK_SetInvalidFlag(pstMBuf);
		SESSION6_KStatFailInc(SESSION_STAT_FAIL_EXTNEW_STATE, pstSessionCtrl);
	}

	/* 重新设置老化类并更新老化时间 */
	SESSION6_KAging_SetClass(pstMBuf, pstSessionCtrl, pstSession);
	
	/* 刷新父会话的老化时间 */
    SESSION_KRefreshParents(pstSession);

	return;
}

SESSION_HANDLE SESSION6_KCreateProcess(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset)
{
    SESSION_S *pstSession;
    RELATION6_S *pstRelation = NULL;
    SESSION_CTRL_S *pstSessionCtrl;
    conn_sub_t *csp;
    csp_key_t *pstcskey;
    ULONG ulRet;
    UINT uiL4OffSet = 0;
    UINT uiIPLen = 0;
    UCHAR ucSessL4Type;
    UCHAR ucNewState = UDP_ST_OPEN;

    pstSessionCtrl = SESSION_CtrlData_Get();

    csp = GET_CSP_FROM_LBUF(pstMbuf);	
    if (unlikely(NULL == csp))
    {
        SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, uiL3Offset, DBG_ABNORM_PKT_FIRST_NOIPCACHE);
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_PROCESSED);
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_CREATE_CACHE_NULL, pstSessionCtrl);
        return SESSION_INVALID_HANDLE;
    }
    pstcskey = GET_CSP_KEY(csp);

    /*检查是否允许创建会话，如果不允许创建，则设置MBUF中的会话INVALID标记*/
    ucSessL4Type = (UCHAR)SESSION_KGetSessTypeByProto(pstcskey->proto);

    /*获取4层长度*/
    ulRet = session6_kGetL4Offset(pstMbuf, uiL3Offset, &uiIPLen, &uiL4OffSet);
    if(ERROR_SUCCESS != ulRet)
    {        
        SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, uiL3Offset, DBG_ABNORM_PKT_CHECK_FAIL);
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_INVALID | (USHORT)SESSION_MBUF_PROCESSED);
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_GETL4OFFSET, pstSessionCtrl);
        return SESSION_INVALID_HANDLE;
    }

    /* 检查不通过，直接返回NULL */
    ulRet = session6_kcheckPacket(pstMbuf, pstcskey, ucSessL4Type, uiL3Offset, uiL4OffSet, &ucNewState);
    if(unlikely(ERROR_SUCCESS != ulRet))
    {
        /*当前newsessioncheck提前，icmp_err必然不会创建会话，会走此分支，
            但是icmp_err不能打invalid标记，否则aspf会直接丢包*/
        if(!SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_ICMPERR))
        {
          
            SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_INVALID);
            SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_PROCESSED);
            SESSION6_KStatFailInc(SESSION_STAT_FAIL_PKT_CHECK, pstSessionCtrl);            
            SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, uiL3Offset, DBG_ABNORM_PKT_CHECK_FAIL);
        }
        else
        {            
            SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_PROCESSED);
        }

        return SESSION_INVALID_HANDLE;
    }

    /* 会话首报文处理 */
    pstRelation = SESSION6_RelationHash_Find(pstcskey);
    pstSession = session6_kCreateWithRelation(pstMbuf, ucSessL4Type, csp,
                                              pstSessionCtrl, pstRelation, uiL3Offset);
    if(unlikely(NULL == pstSession))
    {
        SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_PROCESSED);
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_ALLOC_SESSION, pstSessionCtrl);
        SESSION_DBG_SESSION_ERROR_SWITCH(ERROR_SESSION_CREATE_SESSION);
        return SESSION_INVALID_HANDLE;
    }

    /* 设置首包标记到MBUF, 设置temp会话标记到MBUF, 报文为正向*/
    SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_FIRSTPKT | SESSION_MBUF_PROCESSED);

    /* 进行状态机处理 */
    session6_kLayer4StateNewExt(pstSession, (USHORT)uiL3Offset, uiL4OffSet, pstMbuf, pstcskey->proto, pstSessionCtrl);

    /* 统计开关打开，会话增加统计信息 */
    if(unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
    {
        /* 初始化会话的流量统计信息 */
        SESSION_KInitFlowRate(pstMbuf, pstSession);
        SESSION_KAddTotalState((SESSION_L4_TYPE_E)ucSessL4Type, 1, uiIPLen, pstSessionCtrl);
    }

    return (SESSION_HANDLE)pstSession;
}

STATIC INLINE VOID session6_kProcStateError(IN SESSION_CTRL_S *pstSessionCtrl,
											IN SESSION_S *pstSession,
											IN MBUF_S *pstMBuf,
											IN USHORT usIPOffset,
											IN UINT uiL4Offset,
											IN SESSION_PKT_DIR_E enDir,
											IN SESSION_STAT_FAIL_TYPE_E enFailType)
{
	
    SESSION_DBG_PACKETS_EVENT_SWITCH(pstMBuf, usIPOffset, DBG_ABNORM_PKT_INVALID);
	/* 设置非法报文标记，但报文还是属于会话，只不过状态不对 */
	SESSION_BAK_SetInvalidFlag(pstMBuf);
	SESSION6_KStatFailInc(enFailType, pstSessionCtrl);

	return;
}

/* 快转tcp状态机处理 */
#if 0
STATIC VOID session6_kTcpState(IN SESSION_S *pstSession,
							   IN MBUF_S *pstMBuf,
							   IN SESSION_PKT_DIR_E enDir,
                               IN SESSION_CTRL_S *pstSessionCtrl,
							   IN USHORT usIPOffset,
							   IN UINT uiL4Offset)
{
	AGINGQUEUE_UNSTABLE_CLASS_S *pstClass;
	TCPHDR_S *pstTcpHdr;
	UCHAR ucFlags;
	UCHAR ucOldState;
	UCHAR ucNewState;
	INT iIndex;

	pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4Offset, TCPHDR_S *); 
	ucFlags = (pstTcpHdr->th_flags) & TCP_FLAGS_CARE_MASK;

	ucOldState = pstSession->ucState;
	
	iIndex = (enDir*TCP_PKT_MAX*TCP_ST_MAX)+(g_aucTcpPktType[ucFlags]*TCP_ST_MAX)+ucOldState;
	ucNewState = (pstSessionCtrl->pucTcpStateTable)[iIndex];

	/* 序列号检查不通过的，直接返回 */
	if(SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
	{
		return;
	}

	if(ucOldState == ucNewState)
	{
		/* 重新设置老化类并更新老化时间 */ 
		SESSION_KAgingRefresh(pstSession);
		return;
	}


	switch (ucNewState)
	{
	    case sTCP_IV:
		{
			session6_kProcStateError(pstSessionCtrl, pstSession, pstMBuf,usIPOffset,uiL4Offset,
									enDir, SESSION_STAT_FAIL_TCP_STATE);
			break; 
		}
		case sTCP_IG:
		{
			/* 不更新状态和pstClass */
			break;
		}
		default:
		{
			pstSession->ucState = ucNewState;
			pstClass = &pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV6][SESSION_L4_TYPE_TCP][ucNewState];
			AGINGQUEUE_UnStable_Switch(&pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo, pstClass);
			break;
		}
	}

	/* 重新设置老化类并更新老化时间 */
	if (!SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
	{
		SESSION_KAgingRefresh(pstSession);
	}

	IGNORE_PARAM(pstSessionCtrl);

	return;
}
#endif

/* 
会话4层协议状态处理
Caution∶协议状态处理结果直接设置在MBuf中
*/
STATIC VOID session6_kStateProc(IN const SESSION_L4_PROTO_S *pstL4Proto,
								IN USHORT usIPOffset, 
								IN UINT uiL4_Offset,
								IN SESSION_S *pstSession, 
								IN MBUF_S *pstMBuf,
								IN SESSION_CTRL_S *pstSessionCtrl)
{
	UCHAR ucOldState;
	UCHAR ucNewState;
	ULONG ulRet;

	//rte_spinlock_lock(&(pstSession->stLock));

	ucOldState = pstSession->ucState;
    
	ulRet = pstL4Proto->pfState(pstSession, pstMBuf, usIPOffset, uiL4_Offset);
	if(ulRet != ERROR_SUCCESS)
	{
		SESSION_DBG_PACKETS_EVENT_SWITCH(pstMBuf, usIPOffset, DBG_ABNORM_PKT_INVALID);

		/* 设置非法报文标记，但报文还是属于会话，只不过状态不对 */
		SESSION_BAK_SetInvalidFlag(pstMBuf);
		SESSION6_KStatFailInc(SESSION_STAT_FAIL_TOUCH_STATE, pstSessionCtrl);
	}

	ucNewState = pstSession->ucState;
	if (ucOldState != ucNewState)
	{
		/* 重新设置老化类并更新老化时间 */
		SESSION6_KAging_SetClass(pstMBuf, pstSessionCtrl, pstSession);
	}
	else
	{
		/* 刷新老化时间 */
		if(!SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
		{
			SESSION_KAging_Refresh(pstSession);
		}
	}
	
    //rte_spinlock_unlock(&(pstSession->stLock));
		
	return;
}

static inline VOID session6_kLayer4TouchState(IN const csp_key_t *pstcskey,
                                              IN USHORT usIPOffset,
                                              IN UINT uiL4Offset,
                                              IN SESSION_S *pstSession,
                                              IN MBUF_S *pstMBuf,
                                              IN SESSION_CTRL_S *pstSessionCtrl)
{
    SESSION_L4_PROTO_S *pstL4Proto;

    pstL4Proto = SESSION_KGetL4Proto_Proc(pstcskey->proto);

    /*多核并发时，为保证状态会话计数、Aging_setClass正确，需加锁*/
    if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
    {
        /*进行状态机处理*/
        session6_kStateProc(pstL4Proto, usIPOffset, uiL4Offset, pstSession, pstMBuf, pstSessionCtrl);
    }

    /*刷新父会话的老化时间*/
    SESSION_KRefreshParents(pstSession);
	
    return;
}

VOID SESSION6_KTouchProcess(INOUT MBUF_S *pstMbuf, IN SESSION_HANDLE hSession, IN UINT uiL3Offset)
{
    ULONG ulRet;
    SESSION_S *pstSession;
    conn_sub_t       *csp;		
    csp_key_t        *pstcskey;
    SESSION_CTRL_S   *pstSessionCtrl;
    UINT              uiL4OffSet = uiL3Offset;
    UINT              uiIPLen;
    SESSION_PKT_DIR_E enDir;
    IP6_S *pstIP6;
    UCHAR ucHdrProto = IPPROTO_IPV6;

    pstSession = (SESSION_S *)hSession;

    pstSessionCtrl = SESSION_CtrlData_Get();

    csp = GET_CSP_FROM_LBUF(pstMbuf);	
    if(NULL == csp)
    {
        SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, uiL3Offset, DBG_ABNORM_PKT_FOLLOW_NOIPCACHE);
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_INVALID | (USHORT)SESSION_MBUF_PROCESSED);
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_TOUCH_CACHE_NULL, pstSessionCtrl);
        return;
    }

    pstcskey = GET_CSP_KEY(csp);

    enDir = (SESSION_PKT_DIR_E)GET_PACKETDIR_FROM_CSP(csp);

    /* 配置序列变更 */
    if(unlikely(pstSession->usCfgSeq != pstSessionCtrl->usCfgSeq))
    {
        if(SESSION_DIR_ORIGINAL == enDir)
        {
            pstSession->usCfgSeq = pstSessionCtrl->usCfgSeq;
        }
        
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_CFGCHECK | 
                                (USHORT)SESSION_MBUF_PROCESSED | enDir);
    }
    else
    {
        /* 设置报文处理标志和方向标志 */
        SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_PROCESSED | enDir);
    }

    MBUF_SET_APP_ID(pstMbuf, SESSION_KGetAppID(hSession));

    /* 对非分片或者分片首片报文做状态机处理 */
    if(!SESSION6_IsLatterFrag(pstMbuf)/* && 0 == pstSession->uiStatusTime*/)
    {
        ulRet = IP6_GetLastHdr(pstMbuf, &uiL4OffSet, &ucHdrProto);
        if(ERROR_SUCCESS != ulRet)
        {            
            SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, uiL3Offset, DBG_ABNORM_PKT_CHECK_FAIL);
            SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_INVALID | (USHORT)SESSION_MBUF_PROCESSED);
            SESSION6_KStatFailInc(SESSION_STAT_FAIL_PKT_CHECK, pstSessionCtrl);
            return;
        }

        /* 进行状态机处理 */
        session6_kLayer4TouchState(pstcskey, (USHORT)uiL3Offset, uiL4OffSet, pstSession, pstMbuf, pstSessionCtrl);
    }

    /*统计开关打开，会话增加统计信息*/
    if(BOOL_TRUE == pstSessionCtrl->bStatEnable)
    {
        if(SESSION_DIR_REPLY == enDir)
        {
            SESSION_KAddReplyFlowStat(pstMbuf, pstSession);
        }
        else
        {
            SESSION_KAddOriginalFlowStat(pstMbuf, pstSession);
        }

        /* 更新会话的流量统计信息 */
        pstIP6 = MBUF_BTOD_OFFSET(pstMbuf, uiL3Offset, IP6_S *);
        uiIPLen = ntohs(pstIP6->ip6_usPLen) + sizeof(IP6_S);
        SESSION_KAddTotalState((SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                               1, uiIPLen, pstSessionCtrl);
    }

    /* 设置会话的ipv6类型标记 */
    SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, (USHORT)SESSION_IPV6);

#if 0
    /* 需要发送日志 */
    if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase,
                                  ((USHORT)SESSION_LOG_FLOW_PACKET | (USHORT)SESSION_LOG_FLOW_BYTE)))
    {
        SESSION6_KLOG_PROC_ActiveFlow(pstSession, pstSessionCtrl);
    }
#endif

    return;
}

/* 检查是否达到并发数和新建速率的上限 */
STATIC ULONG SESSION6_kCapabitityTest(IN SESSION_CTRL_S *pstSessionCtrl, IN const MBUF_S *pstMBuf)
{
	ULONG ulErrCode = ERROR_FAILED;

	/* 软件规格数据判断 */
	ulErrCode = SESSION_Info_Specification();
	if (ERROR_SUCCESS != ulErrCode)
	{
		return PKT_DROPPED;
	}

	rte_atomic32_inc(&pstSessionCtrl->stSessStat.stTotalSessNum);

    return PKT_CONTINUE;
}

/* 删除该子会话在创建的时候命中的non-persist关联表 */
STATIC VOID session6_kDeleteNonPersistRelation(IN SESSION_S *pstSession)
{
	csp_key_t *pstcskey;
	RELATION6_S *pstRelationEntry;
	BOOL_T bMatch; 

	if(NULL == pstSession->pstParent)
	{
		SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION);
		return;
	}

	/* 获取关联表的正向key */
	pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);

	//rte_spinlock_lock(&pstSession->stLock);
	/* 遍历父会话的关联链表 */
	DL_FOREACH_ENTRY(&(pstSession->pstParent->stRelationList),pstRelationEntry, stNodeInSession)
	{
		bMatch = SESSION6_Relation_IsTupleMatch(&(pstRelationEntry->stTupleHash.stIp6fsKey),
												pstcskey,
												pstRelationEntry->stTupleHash.uiMask);

		if (BOOL_TRUE == bMatch)
		{
			DBGASSERT(!RELATION_IS_PERSIST(pstRelationEntry));

			RELATION_SET_DELETING(pstRelationEntry);

			/* 报文匹配非Persist类型关联表建立子会话，向对端发送删除消息，需要清除非OWNER标记 */ 
			RELATION6_BAK_SendDelete(pstSession->pstParent, pstRelationEntry);

			SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase,SESSION_DEL_NON_PERSIST_RELATION); 
			break;
		}
	}

	//rte_spinlock_unlock(&pstSession->stLock); 
	return ;
}

STATIC VOID session6_kFirstPktEnd(IN MBUF_S *pstMBuf,
								  IN SESSION_CTRL_S *pstSessionCtrl,
								  IN USHORT usIPOffset,
								  INOUT SESSION_S *pstSession)
{
	SESSION_L4_TYPE_E enSessType = (SESSION_L4_TYPE_E)(pstSession->stSessionBase.ucSessionL4Type);

	/* 增加计数 */
	SESSION_KAddStat(pstSessionCtrl, enSessType, pstSession->uiOriginalAppID);

	if (SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION))
	{
		session6_kDeleteNonPersistRelation(pstSession);
	}

	enSessType = (SESSION_L4_TYPE_E)(pstSession->stSessionBase.ucSessionL4Type);

	/* 发送会话创建日志 */
	if (BOOL_TRUE == pstSessionCtrl->stSessionLogInfo.bLogSwitchEnable)
	{
		SESSION6_KLOG_PROC_Create(pstMBuf,usIPOffset,pstSession,pstSessionCtrl);
	}

	SESSION_KNotify_TableCreate((SESSION_HANDLE)pstSession);

	/* 会话加入老化队列 */
	SESSION_KAging_Add(&(g_stSessionstAgingQueue), pstSession);

	return;
}

/* 转发流程中基于会话处理结束处理点 */
STATIC ULONG session6_kFirstEnd(IN MBUF_S *pstMBuf,
								IN USHORT usIPOffset,
								IN SESSION_S *pstSession,
								IN SESSION_CTRL_S *pstSessionCtrl)
{
	ULONG ulRet = ERROR_SUCCESS;
	SESSION_KALG_IPV6_PROC_PF pfAlgIPv6Proc;

	/* 会话首包，会话计数增1，将临时会话加入hash表中，以及老化链表中 */
	session6_kFirstPktEnd(pstMBuf, pstSessionCtrl, usIPOffset, pstSession);

	if (0 != pstSession->usAlgFlag)
	{
		/* IPv6当前要支持ftp ALG处理 ASPF */
		pfAlgIPv6Proc = g_stSessionIPv6KAlgProc.pfAlgIPv6Proc;
		if (NULL != pfAlgIPv6Proc)
		{
			ulRet = pfAlgIPv6Proc(pstMBuf,usIPOffset,(SESSION_HANDLE)pstSession);
		}
	}

	if (ERROR_SUCCESS != ulRet)
	{
		SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
        return PKT_DROPPED;
	}

	return PKT_CONTINUE;
}
								
#if 0
/* 删除temp会话 */
STATIC ULONG session6_kTempSessionPut(IN SESSION_S *pstSession,
								      IN USHORT usIPOffset,
									  INOUT MBUF_S *pstMBuf,
								      INOUT SESSION_CTRL_S *pstSessionCtrl)
{
	ULONG ulPktRet = PKT_CONTINUE;

	IGNORE_PARAM(usIPOffset);
    
	rte_atomic32_dec(&(pstSessionCtrl->stSessStat.stTotalSessNum));

	/* 业务删除时可能会根据是否有SESSION_TEMP标记，做相应处理，因此这里加上标记 */
	SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,SESSION_TEMP);
	/*通知删除*/
	/*local_bh_disable();*/
	SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);
	/*local_bh_enable();*/

	/* 清空MBUF中的会话指针和flag位 */
	MBUF_CLEAR_CACHE(pstMBuf,MBUF_CACHE_SESSION);
	MBUF_SET_SESSION_FLAG(pstMBuf,0);

	/* 通知AFT丢包 */
	ulPktRet = session6_kEstablishFailedNotify(pstSession,usIPOffset,pstMBuf);

	/* 最新版本cache由会话释放: old--释放的时候仅仅需要释放会话，Cache已经释放了 */
	SESSION6_KPut(pstSession);
        
	return ulPktRet;
}
#endif

#if 0
/* 清除会话和关联表的非OWN标记 */
VOID SESSION6_BAK_SetOwnerFlag(INOUT SESSION_S *pstSession) 
{
	LIP_ADDR stDst;

	if (!SESSION_IS_CHARACTER(pstSession, SESSION_DIRECTOR))
	{
		return;
	}

	if (SESSION_IS_BACKUP_FLAG(pstSession, SESSION_DONOTBACKUP))
	{
		SESSION_DBG_BACKUP_ERROR_SWTICH(pstSession, SESSION_SENDERR_DONOTBACKUP);
		return; 
	}

	SESSION_SET_CHARACTER(pstSession, SESSION_OWNER);

	stDst = HOTBACKUP_GetDstLip(NULL); 
	if(LIPC_LIP_ADDR_ANY != stDst)
	{
		(VOID)SESSION6_BAK_UpdateRole(stDst, pstSession);
	}

	if (BOOL_TRUE == RBM_KCFG_IsBackupEnable())
	{
		(VOID)SESSION6_VRRPBAK_UpdateRole(pstSession);
	}

	return;
}
#endif

/*
转发流程中基于会话处理结束处理点，
由IPv4/IPv6流程中的session end处理函数调用
如果所属会话为临时会话，则加入会话表中。对于所有报文，还进行ALG处理
*/
STATIC ULONG session6_kAfterEnd(IN MBUF_S *pstMBuf, IN USHORT usIPOffset, IN SESSION_S *pstSession)
{
	ULONG ulPktRet = PKT_CONTINUE;
	ULONG ulRet    = ERROR_SUCCESS;
	SESSION_KALG_IPV6_PROC_PF pfAlgIPv6Proc;

	if (0 != pstSession->usAlgFlag)
	{
		/* 会话ALG处理 ASPF */
		pfAlgIPv6Proc = g_stSessionIPv6KAlgProc.pfAlgIPv6Proc;
		if(NULL != pfAlgIPv6Proc)
		{
			ulRet = pfAlgIPv6Proc(pstMBuf, usIPOffset, (SESSION_HANDLE)pstSession);
		}
	}

	if (ERROR_SUCCESS != ulRet)
	{        
		ulPktRet = PKT_DROPPED;

	}

	return ulPktRet;
}

/* IPv6转发流程中Session End 业务点的处理函数 */
ULONG SESSION6_IpfsEndProc(IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf)
{
    SESSION_S *pstSession;
    SESSION_CTRL_S *pstSessionCtrl;
    ULONG ulPktRet = PKT_CONTINUE;
    flow_connection_t *fcp;

    /* 从报文获取会话pstSession */
    pstSession = GET_FWSESSION_FROM_LBUF(pstMBuf);

    pstSessionCtrl = SESSION_CtrlData_Get();

    if (NULL == pstSession)
    {
        /* 如果会话尝试处理但是建不了表项，则不创建快转表 */
	    /* 此处需要跟flow沟通，flow目前逻辑是 会话不安装快转，flow肯定就自己安装了， 但此处不希望flow安装 */
        MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_TRY_FAIL_UNICAST, pstSessionCtrl);
        return PKT_CONTINUE;
    }

    /* 两种报文不处理:1.ICMP差错 2.后续分片非首片报文 */
    if ((SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_ICMPERR)) ||
        (SESSION6_IsLatterFrag(pstMBuf)))
    {
        if (!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
        {
            /* 正式会话不能释放会话信息*/
            MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        }

        return PKT_CONTINUE;
    }

    /* SESSION 正式化 肯定是普通会话 */
    if (SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        ulPktRet = SESSION6_kCapabitityTest(pstSessionCtrl, pstMBuf); 
        if(PKT_DROPPED == ulPktRet)
        {
            SESSION6_KStatFailInc(SESSION_STAT_FAIL_CAPABITITY_UNICAST, pstSessionCtrl); 
            return PKT_DROPPED;
        }

        /* 增加引用计数 */
        rte_atomic32_set(&pstSession->stSessionBase.stRefCount.stCount, 1); 

        /* 清除临时会话标志位 */
        SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);

        fcp = GET_FC_FROM_LBUF(pstMBuf);
		flow_install_conn_no_refresh(fcp);
        ulPktRet = session6_kFirstEnd(pstMBuf, usIPOffset, pstSession, pstSessionCtrl);
    }
    else
    {
        ulPktRet = session6_kAfterEnd(pstMBuf, usIPOffset, pstSession);
    }

    /*正式化会话清除mbuf的会话指针*/
    if ((PKT_CONTINUE == ulPktRet) &&
        !SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        /* 清空MBUF中的会话指针和flag位 */
        MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_SLOW_FORWARDING);
    }

    return ulPktRet;
}

/* 会话4层协议状态处理 */
STATIC inline VOID session6_kExtStateProc(IN SESSION_PKT_DIR_E enDir,
										  IN SESSION_S *pstSession,
										  INOUT MBUF_S *pstMBuf, 
                                          IN SESSION_CTRL_S *pstSessionCtrl,
                                          IN UINT uiL3Offset,
                                          IN UINT uiL4Offset)
{
	csp_key_t *pstcspkey;
	SESSION_L4_PROTO_S *pstL4Proto; 
	UCHAR ucOldState; 
	UCHAR ucNewState; 
	ULONG ulRet; 
 
	SESSION_IGNORE_CONST(pstMBuf);

	pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, enDir);
	pstL4Proto = SESSION_KGetL4Proto_Proc(pstcspkey->proto); 

	//rte_spinlock_lock(&(pstSession->stLock));

	ucOldState = pstSession->ucState;

	ulRet = pstL4Proto->pfFastState(pstSession, uiL3Offset, uiL4Offset, pstMBuf, enDir);
	if (ulRet != ERROR_SUCCESS)
	{
		/* 设置非法报文标记， 但报文还是属于会话，只不过状态不对 */
		SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID);
		SESSION6_KStatFailInc(SESSION_STAT_FAIL_EXT_STATE, pstSessionCtrl);
	}

	ucNewState = pstSession->ucState;
	if ( ucOldState != ucNewState )
	{
		/* 重新设置老化类并更新老化时间 */
		SESSION6_KAging_SetClass(pstMBuf,pstSessionCtrl,pstSession);
	}
	else
	{
		/* 刷新老化时间 */
		if (!SESSION_MBUF_TEST_FLAG(pstMBuf,(USHORT)SESSION_MBUF_INVALID))
		{
			SESSION_KAgingRefresh(pstSession);
		}
	}

	//rte_spinlock_unlock(&(pstSession->stLock));

	return;
}

/* 会话4层协议状态处理
Caution:
协议状态处理结果直接设置在MBuf中
*/
STATIC VOID session6_kExtLayer4State(IN SESSION_PKT_DIR_E enDir,
									IN SESSION_S *pstSession,
									IN MBUF_S *pstMbuf,
                                    IN SESSION_CTRL_S *pstSessionCtrl,
									IN UINT uiL3Offset,
									IN UINT uiL4Offset)
{
	/*多核并发时，为保证状态会话计数、Aging_setClass正确，需加锁*/
	if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
	{
		/* 进行状态机处理 */
		session6_kExtStateProc(enDir, pstSession, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
	}

	/* 刷新父会话的老化时间 */
	SESSION_KRefreshParents(pstSession);

	return;
}

/* 大会话快转处理 */
STATIC ULONG SESSION6_KExtProc(IN SESSION_S *pstSession,
                               IN VOID *csp,
						       IN IP6_S *pstIP6,
						       IN MBUF_S *pstMbuf, 
                               IN SESSION_CTRL_S *pstSessionCtrl,
						       IN UINT uiL3Offset,
                               IN UINT uiL4Offset)
{
	ULONG ulRet = PKT_CONTINUE;
	BOOL_T bIsLatterFrag;
	SESSION_PKT_DIR_E enDir;

    enDir = (SESSION_PKT_DIR_E)GET_PACKETDIR_FROM_CSP((conn_sub_t *)csp);
    SESSION_MBUF_SET_FLAG(pstMbuf, enDir);
    
	bIsLatterFrag = SESSION6_IsLatterFrag(pstMbuf);
	if (BOOL_TRUE == bIsLatterFrag)
	{
		return ulRet;
	}
	else
	{
        /* 进行状态机处理 */
        session6_kExtLayer4State(enDir, pstSession, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
	}

	/* 会话ALG处理 */
	if ((0 != pstSession->usAlgFlag) &&
	    (!IN6ADDR_IsMulticast(&(*pstIP6).stIp6Dst)))
	{
		if (NULL != g_stSessionIPv6KAlgProc.pfAlgIPv6Proc)
		{
			ulRet = g_stSessionIPv6KAlgProc.pfAlgIPv6Proc(pstMbuf, uiL3Offset, (SESSION_HANDLE)pstSession);
		}

		if (ERROR_SUCCESS != ulRet)
		{
			ulRet = PKT_DROPPED;
		}
	}

	return ulRet;
}

STATIC inline ULONG SESSION6_FsModuleProc(IN SESSION_S *pstSession, 
                                          IN SESSION_CTRL_S *pstSessionCtrl,
										  IN MBUF_S *pstMBuf)
{
	ULONG ulRet = PKT_CONTINUE;

	/* ASPF快转 */
	if (unlikely(SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID)))
	{
    	if (SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, SESSION_MODULE_ASPF))
    	{
    		ulRet = SESSION_Proc_Aspf(pstSession, pstMBuf);
    	}
	}

	/* 发送日志 */
	if (SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase,
		((USHORT)SESSION_LOG_FLOW_PACKET | (USHORT)SESSION_LOG_FLOW_BYTE)) &&
		(PKT_CONTINUE == ulRet))
	{
		SESSION6_KLOG_PROC_ActiveFlow(pstSession, pstSessionCtrl);
	}

	return ulRet;
}

STATIC ULONG SESSION6_FsSecpolicyMatch(IN SESSION_S *pstSession)
{
	SECPOLICY_PACKET_IP6_S stSecPolicyPacketIP6;
	conn_sub_t *csp;
	csp_key_t *pstcspkey;
	SECPOLICY_ACTION_E enAction;  
		
	csp       = SESSION_KGetCsp((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    pstcspkey = &csp->key;
	
	stSecPolicyPacketIP6.ucProtocol     = pstcspkey->proto;
    memcpy(&stSecPolicyPacketIP6.stSrcIP6, &(pstcspkey->src_ip), sizeof(struct in6_addr));
	memcpy(&stSecPolicyPacketIP6.stDstIP6, &(pstcspkey->dst_ip), sizeof(struct in6_addr));	
	stSecPolicyPacketIP6.uiVxlanID      = pstcspkey->token;
    stSecPolicyPacketIP6.uiAppID         = pstSession->uiAppID;    
	switch (stSecPolicyPacketIP6.ucProtocol)
	{
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		{
			stSecPolicyPacketIP6.usDPort = pstcspkey->dst_port;
			stSecPolicyPacketIP6.usSPort = pstcspkey->src_port;
			break;
		}
		case IPPROTO_ICMP:
		{
			stSecPolicyPacketIP6.stIcmp.ucType = csp->csp_type;
			stSecPolicyPacketIP6.stIcmp.ucCode = csp->csp_code;
			break;
		}
		default:
		{
			break;
		}
	}
	
	enAction = SecPolicy_Match_IP6(&stSecPolicyPacketIP6);
	if(SECPOLICY_ACTION_PERMIT == enAction)
	{
		return PKT_CONTINUE;
	}
	else
	{
		return PKT_DROPPED;
	}
}

/* 基于会话的安全业务快转入口 */
ULONG SESSION6_FsService(struct rte_mbuf *pstRteMbuf)
{
	MBUF_S            *pstMbuf;
    SESSION_S         *pstSession;	
    SESSION_CTRL_S    *pstSessionCtrl;		
	conn_sub_t        *csp;	
	IP6_S              *pstIP6;
    SESSION_PKT_DIR_E enPktDir;    
    UINT              uiL4Offset;    
	UINT              uiL3Offset = 0;       
    ULONG             ulRet      = PKT_CONTINUE;
    UINT uiIp6Len;
	csp_key_t  *pstcspkey;
	struct in6_addr stSrcIP6;
    struct in6_addr stDstIP6;
	UINT uiVrf;
	UINT uiPreAppID;
	BOOL_T bNeedApr;
	APR_PARA_S stAprPara;
    IPS_PARA_S stIpsPara;
	pstMbuf = mbuf_from_rte_mbuf(pstRteMbuf);
    /* 本报文已经经过FW慢转处理过了，快转无需处理了直接返回continue即可 */
    if(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_SLOW_FORWARDING))
    {
        return PKT_CONTINUE;
    }
	
    pstSessionCtrl = SESSION_CtrlData_Get();
    pstSession = GET_FWSESSION_FROM_MBUF(pstRteMbuf);
	csp        = GET_CSP_FROM_MBUF(pstRteMbuf);	
    enPktDir   = (SESSION_PKT_DIR_E)GET_PACKETDIR_FROM_CSP(csp);

    if (NULL == pstSession)
        return PKT_CONTINUE;

    /* 获取4层长度 */
    (VOID)session6_kGetL4Offset(pstMbuf, uiL3Offset, &uiIp6Len, &uiL4Offset);

    /* 取报文数据域的IP头 */
    pstIP6 = rte_pktmbuf_mtod_offset(pstRteMbuf, IP6_S *, uiL3Offset);

	/* 扩展方式的安全业务处理，无需快 */
	ulRet = SESSION6_KExtProc(pstSession, csp, pstIP6, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);

	if (unlikely(PKT_CONTINUE != ulRet))
	{
		/* 丢包处理 */ 
		return ulRet;
	}

	
	uiPreAppID = pstSession->uiAppID;

	/* 是否需要做应用识别 */		
	pstcspkey = GET_CSP_KEY(csp);

	uiVrf = pstcspkey->token;
    memcpy(&stSrcIP6, &(pstcspkey->src_ip), sizeof(struct in6_addr));
	memcpy(&stDstIP6, &(pstcspkey->dst_ip), sizeof(struct in6_addr));

    bNeedApr = SecPolicy_IP6_IsNeedAPR(uiVrf, &stSrcIP6, &stDstIP6);
	if(bNeedApr)
	{
		stAprPara.uiAppID	   = pstSession->uiAppID;
		stAprPara.uiTrustValue = pstSession->uiTrustValue;
		
		APR_Check(pstMbuf, &stAprPara);
		
		pstSession->uiAppID = stAprPara.uiAppID;
		pstSession->uiTrustValue = stAprPara.uiTrustValue;
	}

	/* APPID发生变更，需要重新做一遍安全策略 */ 
	if(uiPreAppID != pstSession->uiAppID)
	{
		ulRet = SESSION6_FsSecpolicyMatch(pstSession);
		if(unlikely(PKT_CONTINUE != ulRet))
		{
			/* 丢包处理 */		
			SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
			return ulRet;
		}
	}

	/* 调用dpi处理 */
	stIpsPara.uiDirect = pstSession->uiDirect;
    IPS_Check(pstMbuf, &stIpsPara);
    ulRet = stIpsPara.uiAction;
    if(unlikely(PKT_CONTINUE != ulRet))
    {
 	   /* 丢包处理 */
 	   return ulRet;
    }

	/*统计开关打开，会话增加统计信息*/
	if (unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
	{
		SESSION_FsAddStat(pstSession, pstMbuf, pstSessionCtrl, enPktDir);
	}


	/*快转业务处理*/
	ulRet = SESSION6_FsModuleProc(pstSession, pstSessionCtrl, pstMbuf);

	return ulRet;
}

INT SESSION6_FsServiceProc(struct rte_mbuf *pstRteMbuf)
{
	ULONG ulRet;
	INT iRet;

    if (unlikely(!SESSION_CtrlData_Get()->bSecEnable))
    {
        return FLOW_RET_OK;
    }

	ulRet = SESSION6_FsService(pstRteMbuf);
	if (PKT_CONTINUE != ulRet)
	{
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_FAST_PATH, SESSION_CtrlData_Get());
		iRet = FLOW_RET_ERR;
	}
	else
    {
		iRet = FLOW_RET_OK;
	}

	return iRet;
}

