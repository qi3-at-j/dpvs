
#include "session.h"

/*应用层老化时间特殊的App信息*/
#define SESSION_APP_AGING_COUNT 37
#define SESSION_MSG_SET_L4AGING 0    /* forcompile */


UINT g_auiL4AgingTime[SESSION_PROT_AGING_MAX];
UINT g_uiTimeWaitAging;
UINT g_uiCloseAging;

/* 应用层老化时间特殊的App对应的老化时间 */
static SESS_AGINGSPECIAL_S g_astSessAppAging[SESSION_APP_AGING_COUNT] =
{
	{"bootpc", 120},
    {"bootps", 120},
    {"dns", 1},
    {"ftp", 3600},
    {"ftp-data", 240},
    {"gprs-data", 60},
    {"gprs-sig", 60},
    {"gtp-control", 60},
    {"gtp-user", 60},
    {"h225", 3600},
    {"h245", 3600},
    {"https", 600},
    {"ils", 3600},
    {"l2tp", 120},
    {"mgcp-callagent", 60},
    {"mgcp-gateway", 60},
    {"netbios-dgm", 3600},
    {"netbios-ns", 3600},
    {"netbios-ssn", 3600},
    {"ntp", 120},
    {"pptp", 3600},
    {"qq", 120},
    {"ras", 300},
    {"rip", 120},
    {"rsh", 60},
    {"rtsp", 3600},
    {"sccp", 3600},
    {"sip", 300},
    {"snmp", 120},
    {"snmp trap", 120},
    {"sqlnet", 600},
    {"stun", 600},
    {"syslog", 120},
    {"tacacs-ds", 120},
    {"tftp", 60},
    {"who", 120},
    {"xdmcp", 3600}
};

/* 四层协议默认老化时间 */
static UINT g_auiL4DefaultAgingTime[SESSION_PROT_AGING_MAX] =
{
	[SESSION_PROT_AGING_TCPSYN] = SESSION_TCP_SYN_OPEN_TIME,
	[SESSION_PROT_AGING_TCPEST] = SESSION_TCP_ESTABILISHED_TIME,
	[SESSION_PROT_AGING_TCPFIN] = SESSION_TCP_FIN_CLOSE_TIME,
	[SESSION_PROT_AGING_UDPOPEN] = SESSION_UDP_OPEN_TIME,
	[SESSION_PROT_AGING_UDPREADY] = SESSION_UDP_READY_TIME,
	[SESSION_PROT_AGING_ICMPREQUEST] = SESSION_ICMP_REQUEST_TIME,
	[SESSION_PROT_AGING_ICMPREPLY] = SESSION_ICMP_REPLY_TIME,
	[SESSION_PROT_AGING_RAWIPOPEN] = SESSION_RAWIP_OPEN_TIME, 
	[SESSION_PROT_AGING_RAWIPREADY] = SESSION_RAWIP_READY_TIME,
	[SESSION_PROT_AGING_UDPLITEOPEN] = SESSION_UDPLITE_OPEN_TIME,
	[SESSION_PROT_AGING_UDPLITEREADY] =  SESSION_UDPLITE_READY_TIME,
	[SESSION_PROT_AGING_DCCPREQUEST] = SESSION_DCCP_REQUEST_OPEN_TIME,
	[SESSION_PROT_AGING_DCCPEST] = SESSION_DCCP_ESTABILISHED_TIME,
	[SESSION_PROT_AGING_DCCPCLOSEREQ] = SESSION_DCCP_CLOSEREQ_CLOSE_TIME,
	[SESSION_PROT_AGING_SCTPINIT] = SESSION_SCTP_INIT_OPEN_TIME,
	[SESSION_PROT_AGING_SCTPEST] = SESSION_SCTP_ESTABILISHED_TIME,
	[SESSION_PROT_AGING_SCTPSHUTDOWN] = SESSION_SCTP_SHUTDOWN_CLOSE_TIME,
	[SESSION_PROT_AGING_ICMPV6REQUEST] = SESSION_ICMPV6_REQUEST_TIME,
	[SESSION_PROT_AGING_ICMPV6REPLY]= SESSION_ICMPV6_REPLY_TIME
};

#if 0
STATIC VOID SESSION_NTOH_L4AGING(SESSION_L4AGING_S *pstAging)
{
    pstAging->enL4Type = ntohl(pstAging->enL4Type);
    pstAging->uiTimeValue = ntohl(pstAging->uiTimeValue);
    pstAging->uiTimeWaitAging = ntohl(pstAging->uiTimeWaitAging);
    pstAging->uiCloseAging = ntohl(pstAging->uiCloseAging);
    return;
}
#endif

STATIC ULONG SESSION_GCFG_SetL4Aging(IN const SESSION_L4AGING_S *pstAging)
{
	ULONG ulErrCode = ERROR_FAILED; 
	SESSION_PROT_AGING_TYPE_E enL4Type; 

	enL4Type = pstAging->enL4Type;
	if (enL4Type < SESSION_PROT_AGING_MAX)
	{
		if (g_auiL4AgingTime[enL4Type] != pstAging->uiTimeValue)
		{
			g_auiL4AgingTime[enL4Type] = pstAging->uiTimeValue;
			ulErrCode = ERROR_SUCCESS;
		}
		else
		{
			ulErrCode = ERROR_ALREADY_EXIST;
		}
	}
	else
	{
		if ((g_uiTimeWaitAging == pstAging->uiTimeWaitAging) && (g_uiCloseAging == pstAging->uiCloseAging))
		{
			ulErrCode = ERROR_ALREADY_EXIST;
		}

		if (g_uiTimeWaitAging != pstAging->uiTimeWaitAging)
		{
			g_uiTimeWaitAging = pstAging->uiTimeWaitAging;
			ulErrCode = ERROR_SUCCESS;
		}

		if (g_uiCloseAging != pstAging->uiCloseAging)
		{
			g_uiCloseAging = pstAging->uiCloseAging;
			ulErrCode = ERROR_SUCCESS;
		}
	}

	return ulErrCode;
}

/*******************************************************

设置单个四层协议的老化时间
SESSION_L4AGING_S *pstAging，老化配置结构

*********************************************************/
static ULONG _proc_SetOneL4Aging(IN const SESSION_L4AGING_S *pstAging)
{
	ULONG ulErrCode;

	ulErrCode = SESSION_GCFG_SetL4Aging(pstAging);

	if (ERROR_SUCCESS == ulErrCode)
	{
		(VOID)SESSION_DBM_SetL4Aging(pstAging);
		SESSION_SYNC_SetL4Aging(pstAging);
	}
	else if (ERROR_ALREADY_EXIST == ulErrCode)
	{
		ulErrCode = ERROR_SUCCESS;
	}
	
	return ulErrCode;
}

#if 0
UINT SESSION_GetAppDefaultAgingTimeByName(IN const CHAR *pcAppName)
{
	UINT uiDefaultAgingTm = 0;
	UINT uiCount;

	for (uiCount = 0; uiCount < SESSION_APP_AGING_COUNT; uiCount++)
	{
		if (0 == strcasecmp(g_astSessAppAging[uiCount].pcStr, pcAppName))
		{
			uiDefaultAgingTm = g_astSessAppAging[uiCount].uiTimeValue;
			break;
		}
	}

	if (0 == uiDefaultAgingTm)
	{
		uiDefaultAgingTm = SESSION_APP_DEFAULT_AGING;
	}
	
	return uiDefaultAgingTm;
}

/***********************************************************************
   Func Name: SESSION_GetL4DefaultAgingTime
Date Created:
      Author:
 Description:获取四层协议的默认老化时间
       Input:SESSION_PROT_AGING_TYPE_E enAgingType
      Output:无
      Return:UINT，老化时间
************************************************************************/
STATIC UINT SESSION_GetL4DefaultAgingTime(IN SESSION_PROT_AGING_TYPE_E enAgingType)
{
	return g_auiL4DefaultAgingTime[enAgingType];
}

static ULONG _proc_ClearAllL4Aging(VOID)
{
	ULONG ulErrCode;
	SESSION_PROT_AGING_TYPE_E enType;
	SESSION_L4AGING_S stAging;

	stAging.enL4Type = SESSION_PROT_AGING_MAX;
	stAging.uiTimeWaitAging = SESSION_TABLE_DEFAULT_TIMEOUT;
	stAging.uiCloseAging    = SESSION_TABLE_DEFAULT_TIMEOUT;

	(VOID)_proc_SetOneL4Aging(&stAging);

	for (enType = SESSION_PROT_AGING_TCPSYN; enType < SESSION_PROT_AGING_MAX; enType++)
	{
		stAging.enL4Type = enType;
		stAging.uiTimeValue = SESSION_GetL4DefaultAgingTime(enType);
		ulErrCode = _proc_SetOneL4Aging(&stAging);
		if (ERROR_SUCCESS != ulErrCode)
		{
			break;
		}
	}

	return ulErrCode;
}

static ULONG _proc_SetL4AgingMsg(IN VOID *pData,IN UINT uiDataLen, IN INT iSocketFd)
{
	ULONG ulErrCode;
	SESSION_L4AGING_S stAging;
	SESSION_L4AGING_S *pstAging;

	/* 检查消息长度 */
	if (sizeof(SESSION_L4AGING_S) != uiDataLen)
	{
		SESSION_MSG_ErrorMsgReply(iSocketFd);
		return ERROR_FAILED;
	}
	
	/* 获取消息内容 */
	pstAging = (SESSION_L4AGING_S *)pData;
	stAging = *pstAging;
	SESSION_NTOH_L4AGING(&stAging);

	/* 消息类型为SESSION_PROT_AGING_MAX表示undo所有协议，
	否则为设置某指定协议 */
	if ((SESSION_PROT_AGING_MAX == stAging.enL4Type) &&
	    (SESSION_CLEARALL_VALUE == stAging.uiTimeWaitAging) &&
	    (SESSION_CLEARALL_VALUE == stAging.uiCloseAging))
	{
	    ulErrCode = _proc_ClearAllL4Aging();
	}
	else
	{
		ulErrCode = _proc_SetOneL4Aging(&stAging);
	}
	
	/* 回复响应消息 */
	_proc_SetMsgReply(iSocketFd, SESSION_MSG_SET_L4AGING, ulErrCode);

	return ulErrCode;
}
#endif

