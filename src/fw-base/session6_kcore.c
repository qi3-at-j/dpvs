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

/* ��Э���Ӧ�ĻỰ���� */
extern SESSION_L4_TYPE_E g_aenSessionType[IPPROTO_MAX];
extern UCHAR g_aucIcmpv6ReverType[];
extern RELATION6_S *SESSION6_RelationHash_Find(IN const csp_key_t *pstcspkey);

/* �쳣ͳ�� */
VOID SESSION6_KStatFailInc(IN SESSION_STAT_FAIL_TYPE_E enStatFailType, INOUT SESSION_CTRL_S *pstSessionCtrl)
{
    rte_atomic32_inc(&pstSessionCtrl->astStatFailCnt[SESSION_STAT_IPV6][enStatFailType]);
    return;
}

/* ��ȡipv6�Ĳ�ƫ�� */
STATIC INLINE ULONG session6_kGetL4Offset(IN MBUF_S *pstMbuf, IN UINT uiL3Offset,
                                          OUT UINT *puiIpLen, OUT UINT *puiL4Offset)
{
    ULONG ulRet;
    UCHAR ucHdrProto = IPPROTO_IPV6;
    UINT uiHdrOff = uiL3Offset;
    IP6_S *pstIP6;

    /* ƫ��IPͷ���ϲ�Э�� */
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

/* IPv6�Ϸ��Լ�� */
STATIC BOOL_T session6_KIPv6addr_IsInValid(IN const struct in6_addr *pstAddr)
{
    return IN6ADDR_IsUnspecified(pstAddr);
}

/* IP�Ϸ��Լ�� */
STATIC ULONG session6_kCheckAddress(IN const csp_key_t *pstcskey)
{
    if(session6_KIPv6addr_IsInValid((struct in6_addr *)&pstcskey->dst_ip) ||
       session6_KIPv6addr_IsInValid((struct in6_addr *)&pstcskey->src_ip))
    {
        return ERROR_FAILED;
    }
    
    return ERROR_SUCCESS;
}

/* ���ĵ����Ϸ��Լ�� */
STATIC ULONG session6_kcheckPacket(IN MBUF_S *pstMbuf,
                                   IN const csp_key_t *pstcskey,
                                   IN UCHAR ucSessL4Type,
                                   IN UINT uiL3OffSet,
                                   IN UINT uiL4OffSet,
                                   OUT UCHAR *pucNewState)
{
    ULONG ulRet;
    
    /*���б��ĵ������:������һ�����ΰ���������һ��ICMP������Ϣ���ġ�
     *���ڻ��α��ģ�ֱ�ӷ��ش���
     *����ICMP������Ϣ����Ҫ����Ƿ�����ĳ���Ự����Ĵ����ģ���������ͳ���Լ�״̬������
     *�������ڻỰ��ICMP Error ֪ͨ���ģ���ʶ�����������Ự��
     *���ڲ����ڻỰ�ģ�����ƥ��Ự����
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

/* ����ָ�롢Updtelime����Ҫ��ʼ�������ڼ��������ϻ�����ʱ��ֵ */
STATIC VOID session6_kInitSession(IN UCHAR ucSessL4Type,
							      IN UINT uiAppID,
								  IN UINT uiTrustValue,
                                  IN SESSION_CTRL_S *pstSessionCtrl,
								  INOUT SESSION_S *pstSess)
{
	pstSess->stSessionBase.uiSessCreateTime = (UINT)time(NULL);
	pstSess->stSessionBase.ucSessionL4Type = ucSessL4Type;

	SESSION_KAgingRefresh(pstSess);

	/* ͨ��APPIDʶ��Ự��ALG���� */
	pstSess->uiAppID = uiAppID;
	pstSess->uiTrustValue = uiTrustValue;

	/*��¼�Ự�ĳ�ʼAppID����alg��չ���ϻ����ã���������������appchange���仯*/
	pstSess->uiOriginalAppID = uiAppID;

	/* ����������� */
	pstSess->usCfgSeq = pstSessionCtrl->usCfgSeq;

	/* ������ʱ�Ự��־λ */
	SESSION_TABLE_SET_TABLEFLAG(&pstSess->stSessionBase, SESSION_TEMP);

	return;
}

/*
��ʼ���Ự�ṹ�Ĳ���
Caution�� ����ָ�롢Updatelime����Ҫ��ʼ�������ڼ��������ϻ�����ʱ��ֵ
������������������ʶ���Ϊ�ⲿ����
*/
STATIC VOID session6_kInitExtSession(IN const MBUF_S *pstMbuf, 
							         IN USHORT usSessAlgType,
						        	 IN const RELATION6_S *pstRelation,
							         INOUT SESSION_S *pstSess)
{
	SESSION_S *pstParent;
	NEW_SESSION_BY_RELATION_PF pfNewNotify; 
	ULONG ulRet;

	/* ���ƥ����������ݹ��������ûỰ�Ĳ��� */ 
	if (NULL != pstRelation)
	{
		/* ���ڻỰ��ָ���˸��Ự�� ��Ҫ�Ը��Ự�����ü��� +1 */
		pstParent = RCU_Deref(pstRelation->pstParent);
		if(NULL != pstParent)
		{
			ulRet = SESSION_KGetNotZero((SESSION_S*)pstParent);
			if (ERROR_SUCCESS == ulRet)
			{
				pstSess->pstParent = pstParent;
				pstSess->ucDirAssociateWithParent = (UCHAR)pstRelation->enChildDir;

				/* ˫��algҵ����Ҫ͸����ͬһ���ϴ���
				SESSION_KTrans_Enable(pstSess);*/
			}
		}

		/* ������ƥ���¼�֪ͨ */
		pfNewNotify = pstRelation->pfNewSession; 
		if (NULL != pfNewNotify)
		{
			(VOID)pfNewNotify((SESSION_HANDLE)pstSess, &pstRelation->stAttachData, pstMbuf);
		}

		if (!RELATION_IS_PERSIST(pstRelation))
		{
			/* �ӻỰ���з�persist�������ʱ�򣬲�����ɾ��������,
			��Ҫ�ȵ��ӻỰ��ʽ����ʱ����ɾ������������ȸ��Ự����һ�����. */
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

    /* ��ת�ķ����Լ����ã������Ǵ���������Ϊ���շ� */
    pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL] = csp;
    pstSession->stSessionBase.pCache[SESSION_DIR_REPLY] = peer;
    SET_FWSESSION_TO_FC(fcp, pstSession);

    session6_kInitSession(ucSessL4Type, uiAppID, uiTrustValue, pstSessionCtrl, pstSession);

    /* ����AppID��MBUF */
    MBUF_SET_APP_ID(pstMbuf, uiAppID);

    /*������������ �ڵ��� �� �⵽�� */
	memcpy(&stSrcIP6, &(pstcskey->src_ip), sizeof(struct in6_addr));
    memcpy(&stDstIP6, &(pstcskey->dst_ip), sizeof(struct in6_addr));
	pstSession->uiDirect = SecPolicy_IP6_FlowDirect(pstcskey->token, stSrcIP6, stDstIP6);

    /*���ûỰ��ipv6���ͱ��*/
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
 Description:���±��Ự�����ϲ㸸�Ự���ϻ�ʱ��
       INPUT:IN SESSION_S *pstSession,  �Ự
      Output:��
      Return:��
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

		/* ���÷Ƿ����ı�ǣ������Ļ������ڻỰ��ֻ����״̬���� */
		SESSION_BAK_SetInvalidFlag(pstMBuf);
		SESSION6_KStatFailInc(SESSION_STAT_FAIL_EXTNEW_STATE, pstSessionCtrl);
	}

	/* ���������ϻ��ಢ�����ϻ�ʱ�� */
	SESSION6_KAging_SetClass(pstMBuf, pstSessionCtrl, pstSession);
	
	/* ˢ�¸��Ự���ϻ�ʱ�� */
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

    /*����Ƿ��������Ự���������������������MBUF�еĻỰINVALID���*/
    ucSessL4Type = (UCHAR)SESSION_KGetSessTypeByProto(pstcskey->proto);

    /*��ȡ4�㳤��*/
    ulRet = session6_kGetL4Offset(pstMbuf, uiL3Offset, &uiIPLen, &uiL4OffSet);
    if(ERROR_SUCCESS != ulRet)
    {        
        SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, uiL3Offset, DBG_ABNORM_PKT_CHECK_FAIL);
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_INVALID | (USHORT)SESSION_MBUF_PROCESSED);
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_GETL4OFFSET, pstSessionCtrl);
        return SESSION_INVALID_HANDLE;
    }

    /* ��鲻ͨ����ֱ�ӷ���NULL */
    ulRet = session6_kcheckPacket(pstMbuf, pstcskey, ucSessL4Type, uiL3Offset, uiL4OffSet, &ucNewState);
    if(unlikely(ERROR_SUCCESS != ulRet))
    {
        /*��ǰnewsessioncheck��ǰ��icmp_err��Ȼ���ᴴ���Ự�����ߴ˷�֧��
            ����icmp_err���ܴ�invalid��ǣ�����aspf��ֱ�Ӷ���*/
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

    /* �Ự�ױ��Ĵ��� */
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

    /* �����װ���ǵ�MBUF, ����temp�Ự��ǵ�MBUF, ����Ϊ����*/
    SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_FIRSTPKT | SESSION_MBUF_PROCESSED);

    /* ����״̬������ */
    session6_kLayer4StateNewExt(pstSession, (USHORT)uiL3Offset, uiL4OffSet, pstMbuf, pstcskey->proto, pstSessionCtrl);

    /* ͳ�ƿ��ش򿪣��Ự����ͳ����Ϣ */
    if(unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
    {
        /* ��ʼ���Ự������ͳ����Ϣ */
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
	/* ���÷Ƿ����ı�ǣ������Ļ������ڻỰ��ֻ����״̬���� */
	SESSION_BAK_SetInvalidFlag(pstMBuf);
	SESSION6_KStatFailInc(enFailType, pstSessionCtrl);

	return;
}

/* ��תtcp״̬������ */
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

	/* ���кż�鲻ͨ���ģ�ֱ�ӷ��� */
	if(SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
	{
		return;
	}

	if(ucOldState == ucNewState)
	{
		/* ���������ϻ��ಢ�����ϻ�ʱ�� */ 
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
			/* ������״̬��pstClass */
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

	/* ���������ϻ��ಢ�����ϻ�ʱ�� */
	if (!SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
	{
		SESSION_KAgingRefresh(pstSession);
	}

	IGNORE_PARAM(pstSessionCtrl);

	return;
}
#endif

/* 
�Ự4��Э��״̬����
Caution��Э��״̬������ֱ��������MBuf��
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

		/* ���÷Ƿ����ı�ǣ������Ļ������ڻỰ��ֻ����״̬���� */
		SESSION_BAK_SetInvalidFlag(pstMBuf);
		SESSION6_KStatFailInc(SESSION_STAT_FAIL_TOUCH_STATE, pstSessionCtrl);
	}

	ucNewState = pstSession->ucState;
	if (ucOldState != ucNewState)
	{
		/* ���������ϻ��ಢ�����ϻ�ʱ�� */
		SESSION6_KAging_SetClass(pstMBuf, pstSessionCtrl, pstSession);
	}
	else
	{
		/* ˢ���ϻ�ʱ�� */
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

    /*��˲���ʱ��Ϊ��֤״̬�Ự������Aging_setClass��ȷ�������*/
    if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
    {
        /*����״̬������*/
        session6_kStateProc(pstL4Proto, usIPOffset, uiL4Offset, pstSession, pstMBuf, pstSessionCtrl);
    }

    /*ˢ�¸��Ự���ϻ�ʱ��*/
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

    /* �������б�� */
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
        /* ���ñ��Ĵ����־�ͷ����־ */
        SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_PROCESSED | enDir);
    }

    MBUF_SET_APP_ID(pstMbuf, SESSION_KGetAppID(hSession));

    /* �ԷǷ�Ƭ���߷�Ƭ��Ƭ������״̬������ */
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

        /* ����״̬������ */
        session6_kLayer4TouchState(pstcskey, (USHORT)uiL3Offset, uiL4OffSet, pstSession, pstMbuf, pstSessionCtrl);
    }

    /*ͳ�ƿ��ش򿪣��Ự����ͳ����Ϣ*/
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

        /* ���»Ự������ͳ����Ϣ */
        pstIP6 = MBUF_BTOD_OFFSET(pstMbuf, uiL3Offset, IP6_S *);
        uiIPLen = ntohs(pstIP6->ip6_usPLen) + sizeof(IP6_S);
        SESSION_KAddTotalState((SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                               1, uiIPLen, pstSessionCtrl);
    }

    /* ���ûỰ��ipv6���ͱ�� */
    SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, (USHORT)SESSION_IPV6);

#if 0
    /* ��Ҫ������־ */
    if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase,
                                  ((USHORT)SESSION_LOG_FLOW_PACKET | (USHORT)SESSION_LOG_FLOW_BYTE)))
    {
        SESSION6_KLOG_PROC_ActiveFlow(pstSession, pstSessionCtrl);
    }
#endif

    return;
}

/* ����Ƿ�ﵽ���������½����ʵ����� */
STATIC ULONG SESSION6_kCapabitityTest(IN SESSION_CTRL_S *pstSessionCtrl, IN const MBUF_S *pstMBuf)
{
	ULONG ulErrCode = ERROR_FAILED;

	/* �����������ж� */
	ulErrCode = SESSION_Info_Specification();
	if (ERROR_SUCCESS != ulErrCode)
	{
		return PKT_DROPPED;
	}

	rte_atomic32_inc(&pstSessionCtrl->stSessStat.stTotalSessNum);

    return PKT_CONTINUE;
}

/* ɾ�����ӻỰ�ڴ�����ʱ�����е�non-persist������ */
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

	/* ��ȡ�����������key */
	pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);

	//rte_spinlock_lock(&pstSession->stLock);
	/* �������Ự�Ĺ������� */
	DL_FOREACH_ENTRY(&(pstSession->pstParent->stRelationList),pstRelationEntry, stNodeInSession)
	{
		bMatch = SESSION6_Relation_IsTupleMatch(&(pstRelationEntry->stTupleHash.stIp6fsKey),
												pstcskey,
												pstRelationEntry->stTupleHash.uiMask);

		if (BOOL_TRUE == bMatch)
		{
			DBGASSERT(!RELATION_IS_PERSIST(pstRelationEntry));

			RELATION_SET_DELETING(pstRelationEntry);

			/* ����ƥ���Persist���͹��������ӻỰ����Զ˷���ɾ����Ϣ����Ҫ�����OWNER��� */ 
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

	/* ���Ӽ��� */
	SESSION_KAddStat(pstSessionCtrl, enSessType, pstSession->uiOriginalAppID);

	if (SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION))
	{
		session6_kDeleteNonPersistRelation(pstSession);
	}

	enSessType = (SESSION_L4_TYPE_E)(pstSession->stSessionBase.ucSessionL4Type);

	/* ���ͻỰ������־ */
	if (BOOL_TRUE == pstSessionCtrl->stSessionLogInfo.bLogSwitchEnable)
	{
		SESSION6_KLOG_PROC_Create(pstMBuf,usIPOffset,pstSession,pstSessionCtrl);
	}

	SESSION_KNotify_TableCreate((SESSION_HANDLE)pstSession);

	/* �Ự�����ϻ����� */
	SESSION_KAging_Add(&(g_stSessionstAgingQueue), pstSession);

	return;
}

/* ת�������л��ڻỰ������������ */
STATIC ULONG session6_kFirstEnd(IN MBUF_S *pstMBuf,
								IN USHORT usIPOffset,
								IN SESSION_S *pstSession,
								IN SESSION_CTRL_S *pstSessionCtrl)
{
	ULONG ulRet = ERROR_SUCCESS;
	SESSION_KALG_IPV6_PROC_PF pfAlgIPv6Proc;

	/* �Ự�װ����Ự������1������ʱ�Ự����hash���У��Լ��ϻ������� */
	session6_kFirstPktEnd(pstMBuf, pstSessionCtrl, usIPOffset, pstSession);

	if (0 != pstSession->usAlgFlag)
	{
		/* IPv6��ǰҪ֧��ftp ALG���� ASPF */
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
/* ɾ��temp�Ự */
STATIC ULONG session6_kTempSessionPut(IN SESSION_S *pstSession,
								      IN USHORT usIPOffset,
									  INOUT MBUF_S *pstMBuf,
								      INOUT SESSION_CTRL_S *pstSessionCtrl)
{
	ULONG ulPktRet = PKT_CONTINUE;

	IGNORE_PARAM(usIPOffset);
    
	rte_atomic32_dec(&(pstSessionCtrl->stSessStat.stTotalSessNum));

	/* ҵ��ɾ��ʱ���ܻ�����Ƿ���SESSION_TEMP��ǣ�����Ӧ�������������ϱ�� */
	SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,SESSION_TEMP);
	/*֪ͨɾ��*/
	/*local_bh_disable();*/
	SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);
	/*local_bh_enable();*/

	/* ���MBUF�еĻỰָ���flagλ */
	MBUF_CLEAR_CACHE(pstMBuf,MBUF_CACHE_SESSION);
	MBUF_SET_SESSION_FLAG(pstMBuf,0);

	/* ֪ͨAFT���� */
	ulPktRet = session6_kEstablishFailedNotify(pstSession,usIPOffset,pstMBuf);

	/* ���°汾cache�ɻỰ�ͷ�: old--�ͷŵ�ʱ�������Ҫ�ͷŻỰ��Cache�Ѿ��ͷ��� */
	SESSION6_KPut(pstSession);
        
	return ulPktRet;
}
#endif

#if 0
/* ����Ự�͹�����ķ�OWN��� */
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
ת�������л��ڻỰ�����������㣬
��IPv4/IPv6�����е�session end����������
��������ỰΪ��ʱ�Ự�������Ự���С��������б��ģ�������ALG����
*/
STATIC ULONG session6_kAfterEnd(IN MBUF_S *pstMBuf, IN USHORT usIPOffset, IN SESSION_S *pstSession)
{
	ULONG ulPktRet = PKT_CONTINUE;
	ULONG ulRet    = ERROR_SUCCESS;
	SESSION_KALG_IPV6_PROC_PF pfAlgIPv6Proc;

	if (0 != pstSession->usAlgFlag)
	{
		/* �ỰALG���� ASPF */
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

/* IPv6ת��������Session End ҵ���Ĵ����� */
ULONG SESSION6_IpfsEndProc(IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf)
{
    SESSION_S *pstSession;
    SESSION_CTRL_S *pstSessionCtrl;
    ULONG ulPktRet = PKT_CONTINUE;
    flow_connection_t *fcp;

    /* �ӱ��Ļ�ȡ�ỰpstSession */
    pstSession = GET_FWSESSION_FROM_LBUF(pstMBuf);

    pstSessionCtrl = SESSION_CtrlData_Get();

    if (NULL == pstSession)
    {
        /* ����Ự���Դ����ǽ����˱���򲻴�����ת�� */
	    /* �˴���Ҫ��flow��ͨ��flowĿǰ�߼��� �Ự����װ��ת��flow�϶����Լ���װ�ˣ� ���˴���ϣ��flow��װ */
        MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        SESSION6_KStatFailInc(SESSION_STAT_FAIL_TRY_FAIL_UNICAST, pstSessionCtrl);
        return PKT_CONTINUE;
    }

    /* ���ֱ��Ĳ�����:1.ICMP��� 2.������Ƭ����Ƭ���� */
    if ((SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_ICMPERR)) ||
        (SESSION6_IsLatterFrag(pstMBuf)))
    {
        if (!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
        {
            /* ��ʽ�Ự�����ͷŻỰ��Ϣ*/
            MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        }

        return PKT_CONTINUE;
    }

    /* SESSION ��ʽ�� �϶�����ͨ�Ự */
    if (SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        ulPktRet = SESSION6_kCapabitityTest(pstSessionCtrl, pstMBuf); 
        if(PKT_DROPPED == ulPktRet)
        {
            SESSION6_KStatFailInc(SESSION_STAT_FAIL_CAPABITITY_UNICAST, pstSessionCtrl); 
            return PKT_DROPPED;
        }

        /* �������ü��� */
        rte_atomic32_set(&pstSession->stSessionBase.stRefCount.stCount, 1); 

        /* �����ʱ�Ự��־λ */
        SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);

        fcp = GET_FC_FROM_LBUF(pstMBuf);
		flow_install_conn_no_refresh(fcp);
        ulPktRet = session6_kFirstEnd(pstMBuf, usIPOffset, pstSession, pstSessionCtrl);
    }
    else
    {
        ulPktRet = session6_kAfterEnd(pstMBuf, usIPOffset, pstSession);
    }

    /*��ʽ���Ự���mbuf�ĻỰָ��*/
    if ((PKT_CONTINUE == ulPktRet) &&
        !SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        /* ���MBUF�еĻỰָ���flagλ */
        MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_SLOW_FORWARDING);
    }

    return ulPktRet;
}

/* �Ự4��Э��״̬���� */
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
		/* ���÷Ƿ����ı�ǣ� �����Ļ������ڻỰ��ֻ����״̬���� */
		SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID);
		SESSION6_KStatFailInc(SESSION_STAT_FAIL_EXT_STATE, pstSessionCtrl);
	}

	ucNewState = pstSession->ucState;
	if ( ucOldState != ucNewState )
	{
		/* ���������ϻ��ಢ�����ϻ�ʱ�� */
		SESSION6_KAging_SetClass(pstMBuf,pstSessionCtrl,pstSession);
	}
	else
	{
		/* ˢ���ϻ�ʱ�� */
		if (!SESSION_MBUF_TEST_FLAG(pstMBuf,(USHORT)SESSION_MBUF_INVALID))
		{
			SESSION_KAgingRefresh(pstSession);
		}
	}

	//rte_spinlock_unlock(&(pstSession->stLock));

	return;
}

/* �Ự4��Э��״̬����
Caution:
Э��״̬������ֱ��������MBuf��
*/
STATIC VOID session6_kExtLayer4State(IN SESSION_PKT_DIR_E enDir,
									IN SESSION_S *pstSession,
									IN MBUF_S *pstMbuf,
                                    IN SESSION_CTRL_S *pstSessionCtrl,
									IN UINT uiL3Offset,
									IN UINT uiL4Offset)
{
	/*��˲���ʱ��Ϊ��֤״̬�Ự������Aging_setClass��ȷ�������*/
	if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
	{
		/* ����״̬������ */
		session6_kExtStateProc(enDir, pstSession, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
	}

	/* ˢ�¸��Ự���ϻ�ʱ�� */
	SESSION_KRefreshParents(pstSession);

	return;
}

/* ��Ự��ת���� */
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
        /* ����״̬������ */
        session6_kExtLayer4State(enDir, pstSession, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
	}

	/* �ỰALG���� */
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

	/* ASPF��ת */
	if (unlikely(SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID)))
	{
    	if (SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, SESSION_MODULE_ASPF))
    	{
    		ulRet = SESSION_Proc_Aspf(pstSession, pstMBuf);
    	}
	}

	/* ������־ */
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

/* ���ڻỰ�İ�ȫҵ���ת��� */
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
    /* �������Ѿ�����FW��ת������ˣ���ת���账����ֱ�ӷ���continue���� */
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

    /* ��ȡ4�㳤�� */
    (VOID)session6_kGetL4Offset(pstMbuf, uiL3Offset, &uiIp6Len, &uiL4Offset);

    /* ȡ�����������IPͷ */
    pstIP6 = rte_pktmbuf_mtod_offset(pstRteMbuf, IP6_S *, uiL3Offset);

	/* ��չ��ʽ�İ�ȫҵ��������� */
	ulRet = SESSION6_KExtProc(pstSession, csp, pstIP6, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);

	if (unlikely(PKT_CONTINUE != ulRet))
	{
		/* �������� */ 
		return ulRet;
	}

	
	uiPreAppID = pstSession->uiAppID;

	/* �Ƿ���Ҫ��Ӧ��ʶ�� */		
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

	/* APPID�����������Ҫ������һ�鰲ȫ���� */ 
	if(uiPreAppID != pstSession->uiAppID)
	{
		ulRet = SESSION6_FsSecpolicyMatch(pstSession);
		if(unlikely(PKT_CONTINUE != ulRet))
		{
			/* �������� */		
			SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
			return ulRet;
		}
	}

	/* ����dpi���� */
	stIpsPara.uiDirect = pstSession->uiDirect;
    IPS_Check(pstMbuf, &stIpsPara);
    ulRet = stIpsPara.uiAction;
    if(unlikely(PKT_CONTINUE != ulRet))
    {
 	   /* �������� */
 	   return ulRet;
    }

	/*ͳ�ƿ��ش򿪣��Ự����ͳ����Ϣ*/
	if (unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
	{
		SESSION_FsAddStat(pstSession, pstMbuf, pstSessionCtrl, enPktDir);
	}


	/*��תҵ����*/
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

