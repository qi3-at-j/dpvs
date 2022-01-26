
#include "session.h"
#include "session_kcore.h"
#include "session_kdebug.h"
#include "session_ktableaging.h"
#include "apr.h"

#define SESSION_INACTIVE_STATE_AGING_TIME    300
#define SESSION_APP_CODE_AGING_MAX 5  /* 协议最多支持几种具体应用 */

AGINGQUEUE_UNSTABLE_CLASS_S g_stSessionInactiveAgingClass;
AGINGQUEUE_UNSTABLE_CLASS_S *g_apstPersistClass[SESSION_L3_TYPE_MAX];
static UINT g_auiKL4AgingTime[SESSION_PROT_AGING_MAX];    /* 四层协议状态老化时间 */


/* 会话支持配置老化时间的各APP对应的APPID */
UINT g_auiSessAppType[SESSION_APP_AGING_MAX][SESSION_APP_CODE_AGING_MAX] = 
{
	[SESSION_APP_AGING_DNS]     = {APP_ID_DNS, 0},
	[SESSION_APP_AGING_FTP]     = {APP_ID_FTP, 0},
	[SESSION_APP_AGING_SIP]     = {APP_ID_SIP, 0},
	[SESSION_APP_AGING_RAS]     = {APP_ID_RAS, 0},
	[SESSION_APP_AGING_H225]    = {APP_ID_H225, 0},
	[SESSION_APP_AGING_H245]    = {APP_ID_H245, 0},
	[SESSION_APP_AGING_TFTP]    = {APP_ID_TFTP, 0},
	[SESSION_APP_AGING_GTP]     = {APP_ID_GTPC, APP_ID_GTPU, APP_ID_GPRSDATA, APP_ID_GPRSSIG, 0},
	[SESSION_APP_AGING_RTSP]    = {APP_ID_RTSP, 0},
	[SESSION_APP_AGING_PPTP]    = {APP_ID_PPTP, 0},
	[SESSION_APP_AGING_ILS]     = {APP_ID_ILS, 0},
	[SESSION_APP_AGING_NBT]     = {APP_ID_NETBIOSNS, APP_ID_NETBIOSDGM, APP_ID_NETBIOSSSN, 0},
	[SESSION_APP_AGING_SCCP]    = {APP_ID_SCCP, 0},
	[SESSION_APP_AGING_SQLNET]  = {APP_ID_SQLNET, 0},
	[SESSION_APP_AGING_MGCP]    = {APP_ID_MGCPC, APP_ID_MGCPG, 0},
	[SESSION_APP_AGING_RSH]     = {APP_ID_RSH, 0},
	[SESSION_APP_AGING_XDMCP]   = {APP_ID_XDMCP, 0}
};

#if 0
static inline BOOL_T SESSION_IsRuleAgeSeq(SESSION_S *pstSession)
{
	UINT uiAgeCfgSeq;
	BOOL_T bRetVal;

	uiAgeCfgSeq = SECP_GetCfgSeq();
	if (uiAgeCfgSeq != pstSession->uiRuleAgeSeq)
	{
		bRetVal = BOOL_FALSE;
		pstSession->uiRuleAgeSeq = uiAgeCfgSeq;
	}
	else
	{
		bRetVal = BOOL_TRUE;
	}

	return bRetVal;
}
#endif

static VOID _kgcfg_SetL4LowAging(IN SESSION_CTRL_S *pstSessionCtrl, 
								 IN SESSION_L3_TYPE_E enL3Type, 
								 IN SESSION_PROT_AGING_TYPE_E enType, 
								 IN UINT uiTime)
{
	ULONG ulTimeOut = uiTime * rte_get_timer_hz();
	AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass;

	switch(enType)
	{
		case SESSION_PROT_AGING_TCPSYN:
		{
			/* 保存用户配置的老化时间 */
			pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_TCP]; 
			pstL4AgingClass[TCP_ST_SYN_SENT].ulTimeout = ulTimeOut;
			pstL4AgingClass[TCP_ST_SYN_RECV].ulTimeout = ulTimeOut;
			pstL4AgingClass[TCP_ST_SYN_SENT2].ulTimeout = ulTimeOut;

			break;
		}

		case SESSION_PROT_AGING_TCPFIN:
		{
			/* 保存用户配置的老化时间 */
			pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_TCP];
			pstL4AgingClass[TCP_ST_FIN_WAIT].ulTimeout = ulTimeOut;
			pstL4AgingClass[TCP_ST_CLOSE_WAIT].ulTimeout = ulTimeOut;
			pstL4AgingClass[TCP_ST_LAST_ACK].ulTimeout = ulTimeOut;
			break;
		}
		
		case SESSION_PROT_AGING_TCPEST:
		{
			/* 保存用户配置的老化时间 */
			pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_TCP][TCP_ST_ESTABLISHED].ulTimeout = ulTimeOut;
			break;
		}
		
		case SESSION_PROT_AGING_UDPOPEN:
		{
			/* 保存用户配置的老化时间 */
			pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_UDP][UDP_ST_OPEN].ulTimeout = ulTimeOut;
            
			break;
		}
		
		case SESSION_PROT_AGING_UDPREADY:
		{
			/* 保存用户配置的老化时间 */
			pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_UDP][UDP_ST_READY].ulTimeout = ulTimeOut;
			break;
		}
		
		case SESSION_PROT_AGING_ICMPREQUEST:
		{
			/* 保存用户配置的老化时间 */
            pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_ICMP][ICMP_ST_REQUEST].ulTimeout = ulTimeOut;
            
			break;
		}

        case SESSION_PROT_AGING_ICMPREPLY:
		{
			/* 保存用户配置的老化时间 */
            pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_ICMP][ICMP_ST_REPLY].ulTimeout = ulTimeOut;
			break;
		}

        case SESSION_PROT_AGING_RAWIPOPEN:
		{
			/* 保存用户配置的老化时间 */
            pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_RAWIP][RAWIP_ST_OPEN].ulTimeout = ulTimeOut;
            
			break;
		}

        case SESSION_PROT_AGING_RAWIPREADY:
		{
			/* 保存用户配置的老化时间 */
            pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_RAWIP][RAWIP_ST_READY].ulTimeout = ulTimeOut;
			break;
		}

        default:
        {
            DBGASSERT(0);
            break;
        }
		
	}

    return;
}

static VOID _kgcfg_SetL4HighAging(IN SESSION_CTRL_S *pstSessionCtrl, 
								  IN SESSION_L3_TYPE_E enL3Type, 
								  IN SESSION_PROT_AGING_TYPE_E enType, 
								  IN UINT uiTime)
{
	ULONG ulTimeOut = uiTime * rte_get_timer_hz();
	AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass;

	switch(enType)
	{
		case SESSION_PROT_AGING_UDPLITEOPEN:
		{
			/* 保存用户配置的老化时间 */
			pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_UDPLITE][UDPLITE_ST_OPEN].ulTimeout = ulTimeOut;

			break;
		}

		case SESSION_PROT_AGING_UDPLITEREADY:
		{
			/* 保存用户配置的老化时间 */
			pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_UDPLITE][UDPLITE_ST_READY].ulTimeout = ulTimeOut;
			break;
		}
		
		case SESSION_PROT_AGING_DCCPREQUEST:
		{
			/* 保存用户配置的老化时间 */
			pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_DCCP];
			pstL4AgingClass[DCCP_ST_REQUEST].ulTimeout = ulTimeOut;
			pstL4AgingClass[DCCP_ST_RESPOND].ulTimeout = ulTimeOut;
			pstL4AgingClass[DCCP_ST_PARTOPEN].ulTimeout = ulTimeOut;

			break;
		}
		
		case SESSION_PROT_AGING_DCCPCLOSEREQ:
		{
			/* 保存用户配置的老化时间 */
			pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_DCCP];
			pstL4AgingClass[DCCP_ST_CLOSEREQ].ulTimeout = ulTimeOut;
			pstL4AgingClass[DCCP_ST_TIMEWAIT].ulTimeout = ulTimeOut;
			break;
		}
		
		case SESSION_PROT_AGING_DCCPEST:
		{
			/* 保存用户配置的老化时间 */
			pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_DCCP];
			pstL4AgingClass[DCCP_ST_OPEN].ulTimeout = ulTimeOut;
			break;
		}
		
		
    	case SESSION_PROT_AGING_SCTPINIT:
    	{
    		/* 保存用户配置的老化时间 */
    		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_SCTP];
    		pstL4AgingClass[SCTP_ST_COOKIE_ECHOED].ulTimeout = ulTimeOut; 
    		pstL4AgingClass[SCTP_ST_COOKIE_WAIT].ulTimeout = ulTimeOut;

    		break;
    	}

    	case SESSION_PROT_AGING_SCTPSHUTDOWN:
    	{
    		/* 保存用户配置的老化时间 */
    		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_SCTP];

    		pstL4AgingClass[SCTP_ST_SHUTDOWN_SENT].ulTimeout = ulTimeOut;
    		pstL4AgingClass[SCTP_ST_SHUTDOWN_RECD].ulTimeout = ulTimeOut;
    		pstL4AgingClass[SCTP_ST_SHUTDOWN_ACK_SENT].ulTimeout = ulTimeOut;
    		break;
    	}

    	case SESSION_PROT_AGING_SCTPEST:
    	{
    		/* 保存用户配置的老化时间 */
    		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_SCTP];
    		pstL4AgingClass[SCTP_ST_ESTABLISHED].ulTimeout = ulTimeOut;
    		break;
    	}

    	case SESSION_PROT_AGING_ICMPV6REQUEST:
    	{
    		/* 保存用户配置的老化时间 */
    		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_ICMPV6];
    		pstL4AgingClass[ICMP_ST_REQUEST].ulTimeout = ulTimeOut;

    		break;
    	}

    	case SESSION_PROT_AGING_ICMPV6REPLY:
    	{
    		/* 保存用户配置的老化时间 */
    		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[enL3Type][SESSION_L4_TYPE_ICMPV6];
    		pstL4AgingClass[ICMP_ST_REPLY].ulTimeout = ulTimeOut;
    		break;
    	}

    	default:
    	{
    		DBGASSERT(0);
    		break;
    	}
    }
	
	return;
}

/***************************************************
   Func Name: _kgcfg_SetL4Aging
Date Created: 
      Author: 
 Description:命令行设置会话表老化时间，内核态保存的处理
       Input:SESSION_CTRL_S *pstSessionCtrl   
		     SESSION_PROT_AGING_TYPE_E enType
		     UINT uiTime                    
      Output: 无
      Return: 无
     Caution: 
------------------------------------------------------------
Modification History
DATE   NAME     DESCRIPTION
------------------------------------------------------------
*******************************************************/
static VOID _kgcfg_SetL4Aging(IN SESSION_CTRL_S *pstSessionCtrl, IN SESSION_PROT_AGING_TYPE_E enType, IN  UINT uiTime)
{
	if(enType < SESSION_PROT_AGING_UDPLITEOPEN)
	{
		_kgcfg_SetL4LowAging(pstSessionCtrl, SESSION_L3_TYPE_IPV4, enType, uiTime);
		_kgcfg_SetL4LowAging(pstSessionCtrl, SESSION_L3_TYPE_IPV6, enType, uiTime);
	}
	else
	{
		_kgcfg_SetL4HighAging(pstSessionCtrl, SESSION_L3_TYPE_IPV4, enType, uiTime);
		_kgcfg_SetL4HighAging(pstSessionCtrl, SESSION_L3_TYPE_IPV6, enType, uiTime);
	}
	
	return;
}

VOID SESSION_KGCFG_SetL4Aging(IN SESSION_CTRL_S *pstSessionCtrl, IN const SESSION_L4AGING_S *pstAging)
{
	SESSION_PROT_AGING_TYPE_E enL4Type;
	ULONG ulTimeOut;
	AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass;

	enL4Type = pstAging->enL4Type;
	if (enL4Type < SESSION_PROT_AGING_MAX)
	{
		_kgcfg_SetL4Aging(pstSessionCtrl, enL4Type, pstAging->uiTimeValue);
	}
	else if (pstAging->uiTimeWaitAging > 0)
	{
		ulTimeOut = (pstAging->uiTimeWaitAging) * rte_get_timer_hz() + 1;
		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV4][SESSION_L4_TYPE_TCP];
		pstL4AgingClass[TCP_ST_TIME_WAIT].ulTimeout = ulTimeOut;
		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV6][SESSION_L4_TYPE_TCP];
		pstL4AgingClass[TCP_ST_TIME_WAIT].ulTimeout = ulTimeOut;
    }
    else if (pstAging->uiCloseAging > 0)
    {
		ulTimeOut = (pstAging->uiCloseAging) * rte_get_timer_hz() + 1;
		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV4][SESSION_L4_TYPE_TCP];
		pstL4AgingClass[TCP_ST_CLOSE].ulTimeout = ulTimeOut;
		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV6][SESSION_L4_TYPE_TCP];
		pstL4AgingClass[TCP_ST_CLOSE].ulTimeout = ulTimeOut;
	}
	
	return;
}

#if 0
BOOL_T SESSION_AgingCb_IsTimeout(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
	SESSION_BASE_S *pstSessionBase;
	ULONG ulTimeout;

	pstSessionBase = container_of(pstObject, SESSION_BASE_S, unAgingRcuInfo.stAgingInfo);

	if (!SESSION_TABLE_IS_TABLEFLAG(pstSessionBase,SESSION_DELETING))
	{
		ulTimeout = pstSessionBase->unAgingRcuInfo.stAgingInfo.pstClass->ulTimeout;

		if (((LONG)pstSessionBase->uiUpdateTime + (LONG)ulTimeout -(LONG)rte_get_timer_cycles()) > 0)
		{
			return BOOL_FALSE;
		}
		
	}

	return BOOL_TRUE;
}

/********************************************************************

Description:老化节点触发删除函数

*********************************************************************/ 
static inline VOID _session_KAgingCb_Delete(IN SESSION_BASE_S *pstSessionBase)
{
	/* 通过原子来保护会话的切换 */
	if (rte_atomic32_dec_and_test(&pstSessionBase->stRefCount.stCount))
	{        
        SESSION_KDestroy((SESSION_S *)(VOID *)pstSessionBase);
	}
    
	return;
}

/***************************************************************************

会话老化时间到达

****************************************************************************/

VOID SESSION_AgingCb_TimeOut(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
	SESSION_BASE_S *pstSessionBase;

	pstSessionBase = container_of(pstObject, SESSION_BASE_S, unAgingRcuInfo.stAgingInfo);
    
	_session_KAgingCb_Delete(pstSessionBase);

	return;
}
#endif

/******************************************************************
   Func Name:_session_KAging_IsTimeout
Date Created:2021/04/25
      Author:wangxiaohua
 Description:老化判断函数
       INPUT:SESSION_AGING_OBJECT_S *pstObject, 老化对象
      Output:无
      Return:BOOL_TRUE, 超时
             BOOL_FALSE,未超时
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KAging_IsTimeout(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    BOOL_T bTimeOut = BOOL_TRUE;
    SESSION_S *pstSession;
    SESSION_HANDLE hParent;

    pstSession = container_of(pstObject, SESSION_S, stSessionBase.unAgingRcuInfo.stAgingInfo);

    /* deleting 会话不需要发确认消息 */
    if (SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
    {
        return bTimeOut;
    }
    
    /*sip 协议父会话删除时，子会话也需要删除*/
    hParent = SESSION_KGetParentSession((SESSION_HANDLE)pstSession);
    if (SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, SESSION_MODULE_LB) && (SESSION_INVALID_HANDLE != hParent) &&
        (APP_ID_SIP == SESSION_KGetAppID(hParent)) &&
        (SESSION_TABLE_IS_TABLEFLAG((SESSION_BASE_S *)hParent, SESSION_DELETING)))
    {
        return bTimeOut;
    }
    
    return AGINGQUEUE_Unstable_IsTimeout(pstObject, pstSession->stSessionBase.uiUpdateTime);
}

/******************************************************************
   Func Name:_session_KAging_Delete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:老化节点触发删除函数
       INPUT:SESSION_AGING_OBJECT_S *pstObject 老化对象
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID _session_KAging_Delete(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    SESSION_S *pstSession;

    pstSession = container_of(pstObject, SESSION_S, stSessionBase.unAgingRcuInfo.stAgingInfo);

    /* 设置删除日志类型为老化 */
    SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,
               ((USHORT)SESSION_DELTYPE_AGING | (USHORT)SESSION_DELETING));

    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_DELETE);
    SESSION_DisDelete(pstSession);

    return ;
}

#if 0
VOID SESSION_KPersistAging_Delete(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
	_session_KAging_Delete(pstObject);
}

/* 老化节点触发删除函数 */
STATIC INLINE VOID _session6_KAgingCb_Delete(IN SESSION_BASE_S *pstSessionBase)
{
    IP6FS_DeletePairFromHash(pstSessionBase);

    /* 通过原子来保护会话的切换 */
    if(rte_atomic32_dec_and_test(&pstSessionBase->stRefCount.stCount))
    {        
        SESSION6_KDestroy((SESSION_S *)(VOID *)pstSessionBase);
    }

    return;
}


/* ipv6会话老化时间到达 */
VOID SESSION6_AgingCb_TimeOut(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    SESSION_BASE_S *pstSessionBase;

    pstSessionBase = container_of(pstObject, SESSION_BASE_S, unAgingRcuInfo.stAgingInfo);

    _session6_KAgingCb_Delete(pstSessionBase);

    return;
}
#endif

/* 老化节点触发删除函数 */
STATIC VOID _session6_KAging_Delete(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    SESSION_S *pstSession;

    pstSession = container_of(pstObject, SESSION_S, stSessionBase.unAgingRcuInfo.stAgingInfo);

    /* 设置删除日志类型为老化 */
    SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,
               ((USHORT)SESSION_DELTYPE_AGING | (USHORT)SESSION_DELETING));

    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_DELETE);
    SESSION6_Delete(pstSession);

    return ;
}

/***************************************************************************
   Func Name: _session_KAging_InitL4Aging 
Date Created: 
      Author: 
 Description:初始化L4协议状态会话的老化时间 
       Input:UINT uiTimeout
             AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass
      Output: 
      Return: 
     Caution:
------------------------------------------------------------------
Modification History 
DATE        NAME          DESCRIPTION
************************************************************************/
static inline VOID _session_KAging_InitL4Aging(IN ULONG ulTimeout,
											   INOUT AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass)
{
	UINT uiIndex;

	for (uiIndex = 0; uiIndex < SESSION_PROTOCOL_STATE_MAX; uiIndex++)
	{
		/* 初始化实际采用的老化时间 */
		pstL4AgingClass[uiIndex].pfIsTimeout = _session_KAging_IsTimeout;
		pstL4AgingClass[uiIndex].pfDelete    = _session_KAging_Delete;
		pstL4AgingClass[uiIndex].ulTimeout   = ulTimeout;
	}
	
	return;
}											   

static inline VOID _session6_KAging_InitL4Aging(IN ULONG ulTimeout,
											    INOUT AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass)
{
	UINT uiIndex;

	for (uiIndex = 0; uiIndex < SESSION_PROTOCOL_STATE_MAX; uiIndex++)
	{
		/* 初始化实际采用的老化时间 */
		pstL4AgingClass[uiIndex].pfIsTimeout = _session_KAging_IsTimeout;
		pstL4AgingClass[uiIndex].pfDelete    = _session6_KAging_Delete;
		pstL4AgingClass[uiIndex].ulTimeout   = ulTimeout;
	}
	
	return;
}

/*******************************************************************
   Func Name:_session_KAgingTime_Init
Date Created:
      Author:
 Description:会话老化处理初始化函数
       Input:IN V_SESSION MDC_S *pstSessionMdc, MDC
      Output:无
      Return: ERROR_SUCCESS
     Caution:!!!请注意agingclass中的timeout值初始化建议不填写为0，
	       	 因为0是长连接永不老化。建议使用宏∶SESSION_TABLE_DEFAULT_TIMEOUT
-------------------------------------------------------------------
Modification History
DATE        NAME             DESCRIPTION
-------------------------------------------------------------------
********************************************************************/
static inline VOID _session_KAgingTime_Init(IN SESSION_CTRL_S *pstSessionCtrl)
{
	INT iIndex;
	ULONG ulTimeout = SESSION_TABLE_DEFAULT_TIMEOUT * rte_get_timer_hz();
	AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass;

	/* 初始化四层协议老化时间 */
	g_auiKL4AgingTime[SESSION_PROT_AGING_TCPSYN] = SESSION_TCP_SYN_OPEN_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_TCPEST] = SESSION_TCP_ESTABILISHED_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_TCPFIN] = SESSION_TCP_FIN_CLOSE_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_UDPOPEN] = SESSION_UDP_OPEN_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_UDPREADY] = SESSION_UDP_READY_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_ICMPREQUEST] = SESSION_ICMP_REQUEST_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_ICMPREPLY] = SESSION_ICMP_REPLY_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_RAWIPOPEN] = SESSION_RAWIP_OPEN_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_RAWIPREADY] = SESSION_RAWIP_READY_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_UDPLITEOPEN] = SESSION_UDPLITE_OPEN_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_UDPLITEREADY] = SESSION_UDPLITE_READY_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_DCCPREQUEST] = SESSION_DCCP_REQUEST_OPEN_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_DCCPEST] = SESSION_DCCP_ESTABILISHED_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_DCCPCLOSEREQ] = SESSION_DCCP_CLOSEREQ_CLOSE_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_SCTPINIT] = SESSION_SCTP_INIT_OPEN_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_SCTPEST] = SESSION_SCTP_ESTABILISHED_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_SCTPSHUTDOWN] = SESSION_SCTP_SHUTDOWN_CLOSE_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_ICMPV6REQUEST] = SESSION_ICMPV6_REQUEST_TIME;
	g_auiKL4AgingTime[SESSION_PROT_AGING_ICMPV6REPLY] = SESSION_ICMPV6_REPLY_TIME;

	/* 此初始化还是必要的，，因为并非所有状态的老化时间
		都是用户可配各协议状态老化类设置 */
	for (iIndex = SESSION_L4_TYPE_TCP; iIndex < SESSION_L4_TYPE_MAX; iIndex++)
	{
		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV4][iIndex];
		_session_KAging_InitL4Aging(ulTimeout, pstL4AgingClass);
		pstL4AgingClass = pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV6][iIndex];
		_session6_KAging_InitL4Aging(ulTimeout, pstL4AgingClass);
	}

	return;
}

/**********************************************************
   Func Name: _session_KAging_InitL4Aging
Date Created:
      Author: 
 Description:初始化L4协议状态会话的老化时间
       Input:AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass 
      Output:
      Return: 
     Caution:

************************************************************/
static inline VOID _session_KAging_InitL4AgingClass(INOUT AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass)
{
	UINT uiIndex;
	for (uiIndex = 0; uiIndex < SESSION_PROTOCOL_STATE_MAX; uiIndex++)
	{
	    /* 初始化实际采用的老化时间 */
		pstL4AgingClass[uiIndex].pfIsTimeout = _session_KAging_IsTimeout;
		pstL4AgingClass[uiIndex].pfDelete    = _session_KAging_Delete;
	}

	return;
}

/*****************************

初始化L4协议状态会话的老化时间

******************************/ 
static inline VOID _session6_KAging_InitL4AgingClass(INOUT AGINGQUEUE_UNSTABLE_CLASS_S *pstL4AgingClass)
{
	UINT uiIndex;
	for (uiIndex = 0; uiIndex < SESSION_PROTOCOL_STATE_MAX; uiIndex++)
	{
		pstL4AgingClass[uiIndex].pfIsTimeout = _session_KAging_IsTimeout;
		pstL4AgingClass[uiIndex].pfDelete    = _session6_KAging_Delete;
	}
	
	return;
}

/********************************************************************
   Func Name: SESSION KAgingClass_Init
Date Created: 
      Author: 
 Description:会话老化处理初始化函数
       Input:IN V_SESSION MDC_S *pstSessionMdc, MDC
      Output:无
      Return:ERROR_SUCCESS
     Caution:!!请注意agingclass中的timeout值初始化建议不填写为0，
		     因为0是长连接永不老化。建议使用宏∶SESSION_TABLE_DEFAULT_TIMEOUT
---------------------------------------------------------------------
Modification History
DATE         NAME              DESCRIPTION
---------------------------------------------------------------------
****************************************************/
ULONG SESSION_KAgingClass_Init(IN SESSION_CTRL_S *pstSessionMdc)
{
    INT iIndex;
    SESSION_L4AGING_S stAging;

    _session_KAgingTime_Init(pstSessionMdc);

    for (iIndex = SESSION_PROT_AGING_TCPSYN; iIndex < SESSION_PROT_AGING_MAX; iIndex++)
    {
    	stAging.enL4Type = (SESSION_PROT_AGING_TYPE_E)iIndex;
    	stAging.uiTimeValue = g_auiKL4AgingTime[iIndex];
    	SESSION_KGCFG_SetL4Aging(pstSessionMdc, &stAging);
    }

    /* 各协议状态老化类设置 */
    for (iIndex = SESSION_L4_TYPE_TCP; iIndex < SESSION_L4_TYPE_MAX; iIndex++)
    {
    	_session_KAging_InitL4AgingClass(pstSessionMdc->astTableAgingClass[SESSION_L3_TYPE_IPV4][iIndex]);
    	_session6_KAging_InitL4AgingClass(pstSessionMdc->astTableAgingClass[SESSION_L3_TYPE_IPV6][iIndex]);
    }

    /* 初始化自定义应用默认老化类 */
    pstSessionMdc->stAppDefaultClass.pfIsTimeout = _session_KAging_IsTimeout;
    pstSessionMdc->stAppDefaultClass.pfDelete = _session_KAging_Delete;
    pstSessionMdc->stAppDefaultClass.ulTimeout = SESSION_APP_DEFAULT_AGING * rte_get_timer_hz();

    /* 初始化自定义应用默认老化类 */
    pstSessionMdc->stApp6DefaultClass.pfIsTimeout = _session_KAging_IsTimeout;
    pstSessionMdc->stApp6DefaultClass.pfDelete = _session6_KAging_Delete;
    pstSessionMdc->stApp6DefaultClass.ulTimeout = SESSION_APP_DEFAULT_AGING * rte_get_timer_hz();
   
    return ERROR_SUCCESS;
}

