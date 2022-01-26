#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "socket.h"
#include "debug.h"
#include "session.h"
#include "session_kcore.h"
#include "session_kdebug.h"
#include "apr.h"

#define SESSION_DBG_BUF_SIZE    256UL

#if 0
STATIC CHAR* g_apcTcpPacketType[] = {
    "SYN",
    "SYNACK",
    "FIN",
    "ACK",
    "RST",
    "NONE"
};
#endif

enum tagSessionDebugFmtIndex
{
    SESSION_DBG_FMT_AGING,        
    SESSION_DBG_FMT_OPERATION,
    SESSION_DBG_FMT_ERROR,
    SESSION_DBG_FMT_RECEIVED,
    SESSION_DBG_FMT_FSM_RECEIVED,
    SESSION_DBG_FMT_RELATION,
    SESSION_DBG_FMT_EXTINFO_ERROR,
    SESSION_DBG_FMT_EXTINFO,
    SESSION_DBG_FMT_ALG_ERROR,
    SESSION_DBG_FMT_ALG,
    SESSION_DBG_FMT_SET_DEL_FLAG,
    SESSION_DBG_FMT_MAX
};

STATIC CHAR *g_apcSession_DebugFmt[SESSION_DBG_FMT_MAX]=
{
    [SESSION_DBG_FMT_AGING]             = "\r\n Aging: %s\r\n", 
    [SESSION_DBG_FMT_OPERATION]         = "\r\n Session entry was %s.\r\n", 
    [SESSION_DBG_FMT_ERROR]             = "\r\n Error:%s\r\n", 
    [SESSION_DBG_FMT_RECEIVED]          = "\r\n Received: %s\r\n", 
    [SESSION_DBG_FMT_FSM_RECEIVED]      = "\r\n FSM:%s-->%s, dir:%s, PacketType:%s(%d)\r\n", 
    [SESSION_DBG_FMT_RELATION]          = "\r\n Relation entry was %s for %s\r\n", 
    [SESSION_DBG_FMT_EXTINFO_ERROR]     = "\r\n Ext-Info ERROR: %s %s\r\n", 
    [SESSION_DBG_FMT_EXTINFO]           = "\r\n Ext-Info: %s %s\r\n", 
    [SESSION_DBG_FMT_ALG_ERROR]         = "\r\n ALG Error: %s\r\n", 
    [SESSION_DBG_FMT_ALG]               = "\r\n Received packet, ALG Type: %s.\r\n", 
    [SESSION_DBG_FMT_SET_DEL_FLAG]      = "\r\n Modules%s set deleted flag.\r\n" 
};

STATIC CHAR *g_apcSession_DebugOpReason[DBG_REASON_MAX+1] =
{
    [DBG_REASON_MODCALL]           = "module calling ",
    [DBG_REASON_TIMEOUT]           = "time out ",
    [DBG_REASON_CHILDFUL]          = "child full ",
    [DBG_REASON_MODCALLORCHILDFUL] = "module calling / child full ",
    [DBG_REASON_WITH_SESSION]      = "with session ",
    [DBG_REASON_WITH_PARENTKEY]    = "with session key ",
    [DBG_REASON_CREATE]            = "create",
    [DBG_REASON_ADDASSQUE]         = "add associate queue ",
    [DBG_REASON_UPDATE]            = "update ",
    [DBG_REASON_DELETE]            = "delete ",
    [DBG_REASON_FILLINFO]          = "fill info ",
    [DBG_REASON_ADD_GLOBAL]        = "failed to add global hash",
    [DBG_REASON_ADD_LOCAL]         = "failed to add local hash",
    [DBG_REASON_MAX]               = "Error Max",
};

STATIC CHAR *g_apcSession_DebugTuple5Fmt[SESSION_L3_TYPE_MAX]=
{
    "\r\n Tuple5%7s: %s/%d-->%s/%d(%s(%d))",    
    "\r\n Tuple5%7s: %s%s/%d-->\r\n                %s%d(%s(%d))"
        
};

/*
STATIC CHAR *g_apcSession_DebugTuple3Fmt[SESSION_L3_TYPE_MAX]=
{
    "\r\n Tuple3%7s: %s%s-->%s(%s(%d))",    
    "\r\n Tuple3%7s: %s%s-->\r\n                %s(%s(%d))"
        
};
*/

STATIC CHAR *g_apcSession_DebugRelationFmt[SESSION_L3_TYPE_MAX]=
{
    "\r\n Tuple%7s: %s/- -->%s/%d(%s(%d))",    
    "\r\n Tuple%7s: %s/- -->\r\n               %s/%d(%s(%d))"
        
};

STATIC CHAR *g_apcSession_DebugRelationPortFmt[SESSION_L3_TYPE_MAX]=
{
    "\r\n Tuple%7s: %s/%d -->%s/%d(%s(%d))",    
    "\r\n Tuple%7s: %s/%d -->\r\n               %s/%d(%s(%d))"
        
};

/* 事件字符描述数组 */
STATIC CHAR *g_apcSession_DebugEventType[EVENT_MAX+1] =
{
    [EVENT_CREATE]       = "created",        
    [EVENT_DELETE]       = "deleted",
    [EVENT_CLEAR]        = "clear",
    [EVENT_UPDATE]       = "updated",
    [EVENT_BACKUP]       = "backuped",
    [EVENT_RESTORE]      = "restored",
    [EVENT_ADD]          = "Add",
    [EVENT_DEL]          = "Del",
    [EVENT_GET]          = "Get",
    [EVENT_FORMATFAILED] = "Add Hash failed",
    [EVENT]              = "Event",
    [EVENT_DROPPKT]      = "Dropped packet",
    [EVENT_MAX]          = "Error Max",
};

STATIC CHAR *g_apcSession_DebugRelationErrorType[ERROR_RELATION_DEBUG_MAX + 1] =
{
	[ERROR_RELATION_MEMORY_NOT_ENOUGH] = "Not enough memory for relation entry.",
	[ERROR_RELATION_EXCEED_MAX]        = "Number of relation entries exceeded the max.",
	[ERROR_RELATION_DEBUG_MAX]         = "Error Max"
};

/*
STATIC CHAR *g_apcSession_DebugAbnormPktType[DBG_ABNORM_PKT_MAX+1] =
{
    [DBG_ABNORM_PKT_NOT_RESOLVE]             = " Packet can't be resolved",  
    [DBG_ABNORM_PKT_CHECK_FAIL]              = " Packet checking failed",
    [DBG_ABNORM_PKT_UNKNOWN_ICMP_ERROR_CTRL] = " Unknown ICMP error control packet",
    [DBG_ABNORM_PKT_FIRST_NOIPCACHE]         = " First Packet Cache is NULL",
    [DBG_ABNORM_PKT_FOLLOW_NOIPCACHE]        = " Follow Packet Cache is NULL",
    [DBG_ABNORM_PKT_ICMPERROR_OR_LATTERFRAG] = " This is a IcmpErr or LatterFrag packet",
    [DBG_ABNORM_PKT_INVALID]                 = " Packet state is inValid",
    [DBG_ABNORM_PKT_SESSION_PROCESSED_FAILED]= " The session of mbuf is also null after being processed",    
    [DBG_ABNORM_PKT_MAX]                     = " Unknown error",
};
*/

STATIC CHAR *g_apcSession_ModuleName[SESSION_MODULE_MAX+1]=
{
    [SESSION_MODULE_ASPF]       = " ASPF ",
    [SESSION_MODULE_LOG]        = " LOG ",
    [SESSION_MODULE_CONNLMT]    = " CONNLMT ",
    [SESSION_MODULE_ALG]        = " ALG ",
    [SESSION_MODULE_NAT]        = " NAT ",
    [SESSION_MODULE_LB]         = " LB ",
    [SESSION_MODULE_DSLITE]     = " DSLITE ",
    [SESSION_MODULE_WAAS]       = " WAAS ",
    [SESSION_MODULE_TCPCHECK]   = " TCPCHECK ",
    [SESSION_MODULE_AFT]        = " AFT ",
    [SESSION_MODULE_TRAFFICLOG] = " SCD LOG ",
    [SESSION_MODULE_MAX]        = " MODULE_MAX ",
};

STATIC CHAR *g_apcSession_DebugAlgErrorType[DBG_ALG_ERROR_MAX+1] = 
{
	[DBG_ALG_ERROR_MEMORY] = "No enough memory for ALG process.",
    [DBG_ALG_ERROR_DECODE] = "Decoding failed.",
    [DBG_ALG_ERROR_ENCODE] = "Encoding failed.",
    [DBG_ALG_ERROR_LEN_INVALID] = "Payload length invalid.",
    [DBG_ALG_ERROR_STRIP]  = "Strip Off gtp header failed.",
    [DBG_ALG_ERROR_FSM]    = "FSM Error.",
    [DBG_ALG_ERROR_IP]     = "IP Error.",
    [DBG_ALG_ERROR_MAX]    = "Error Max."
};

VOID APR_GetProtoNameByID(IN UCHAR ucProto, OUT CHAR szName[APR_PROTO_NAME_MAX_LEN+1])
{
    CHAR * apcProtoTable[IPPROTO_MAX] = {
    "HOPOPT","ICMP","IGMP","GGP","IPv4","ST","TCP","CBT",
    "EGP","IGP","BBN-RCC-MON","NVP-II","PUP","ARGUS","EMCON","XNET",    
    "CHAOS","UDP","MUX","DCN-MEAS","HMP","PRM","XNS-IDP","TRUNK-1",
    "TRUNK-2","LEAF-1","LEAF-2","RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP",
    "MERIT-INP","DCCP","3PC","IDPR","XTP","DDP","IDPR-CMTP","TP++",
    "IL","IPV6","SDRP","IPv6-Route","IPv6-Frag","IDRP","RSVP","GRE",    
    "DSR","BNA","ESP","AH","I-NLSP","SWIPE","NARP","MOBILE",
    "TLSP","SKIP","IPv6-ICMP","IPv6-NoNxt","IPv6-Opts","RAWIP","CFTP","RAWIP",
    "SAT-EXPAK","KRYPTOLAN","RVD","IPPC","RAWIP","SAT-MON","VISA","IPCV",    
    "CPNX","CPHB","WSN","PVP","BR-SAT-MON","SUN-ND","WB-MON","WB-EXPAK",
    "ISO-IP","VMTP","SECURE-VMTP","VINES","TTP","NSFNET-IGP","DGP","TCF",
    "EIGRP","OSPFIGP","Sprite-RPC","LARP","MTP","AX.25","IPIP","MICP",
    "SCC-SP","ETHERIP","ENCAP","RAWIP","GMTP","IFMP","PNNI","PIM",
    "ARIS","SCPS","QNX","A/N","IPComp","SNP","Compag-Peer","IPX-in-IP",
    "VRRP","PGM","RAWIP","L2TP","DDX","IATP","STP","SRP",
    "UTI","SMP","SM","PTP","ISIS over IPv4","FIRE","CRTP","CRUDP",
    "SSCOPMCE","IPLT","SPS","PIPE","SCTP","FC","RSVP-E2E-IGNORE","Mobility Header",
    "UDPLite","MPLS-in-IP","manet","HIP","Shim6","WESP","ROHC","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP",
    "RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","RAWIP","Reserved"};
    strlcpy(szName, apcProtoTable[ucProto], APR_PROTO_NAME_MAX_LEN+1);
    return;
}

INT scnprintf(OUT CHAR *pcBuf, IN size_t ulSize, IN const CHAR *pcFmt,...)
{
	va_list args;
	INT iRetLen = 0;

	va_start(args, pcFmt);
	iRetLen = vsnprintf(pcBuf, ulSize, pcFmt, args);
	va_end(args);

	return ((iRetLen >= (INT)(UINT)ulSize) ? ((INT)(UINT)ulSize - 1) : iRetLen);
}

/* 格式化Tuple的五元组信息为字符串 */
STATIC INT session_tuple5_snprintf(INOUT CHAR *pcMsgBuf,
                                   IN size_t ulsize,
                                   IN const csp_key_t *pstcspKey,
                                   IN const CHAR *pcDebugInfo)
{
    INT iLen;
    CHAR szSrcIPAddr[INET6_ADDRSTRLEN];    
    CHAR szDstIPAddr[INET6_ADDRSTRLEN];
    CHAR szProtoName[APR_PROTO_NAME_MAX_LEN+1];

    /* 1.取协议名 */
    APR_GetProtoNameByID(pstcspKey->proto, szProtoName);

    /* 2.取tuple中的IP地址 */
    (VOID)inet_ntop(AF_INET, &pstcspKey->src_ip, szSrcIPAddr, (UINT)sizeof(szSrcIPAddr));    
    (VOID)inet_ntop(AF_INET, &pstcspKey->dst_ip, szDstIPAddr, (UINT)sizeof(szDstIPAddr));

    /*IPV4地址以这样的形式显示:
    Tuple5(EVENT):192.168.0.2/8-->192.168.1.58/3840(tcp(6)) */

    iLen = scnprintf(pcMsgBuf,
                     ulsize,
                     g_apcSession_DebugTuple5Fmt[SESSION_L3_TYPE_IPV4],
                     pcDebugInfo,
                     szSrcIPAddr,
                     ntohs(pstcspKey->src_port),
                     szDstIPAddr,
                     ntohs(pstcspKey->dst_port),
                     szProtoName,
                     pstcspKey->proto);

    return iLen;
}

/* 会话表项事件调试信息输出 */
STATIC VOID session_kdebugTableSetDelEvent(IN const SESSION_S *pstSession,
                                           IN SESSION_MODULE_E enMoudle)
{
    CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
    ULONG ulLen;
    csp_key_t *pstcskey;

    DBGASSERT(NULL != pstSession);
    DBGASSERT(enMoudle < SESSION_MODULE_MAX);

    pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);

    ulLen = (UINT)session_tuple5_snprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pstcskey, "(EVENT)");

    /* 再写Event */
    ulLen += (UINT)scnprintf(szMsgBuf + ulLen,
                             SESSION_DBG_BUF_SIZE - ulLen,
                             g_apcSession_DebugFmt[SESSION_DBG_FMT_SET_DEL_FLAG],
                             g_apcSession_ModuleName[enMoudle]);
							 
    debug_trace("%s", szMsgBuf);

    //forcompile syslog2(SESSLOG_SYSLOG_PRIORITY, SESSION_NAME, "TABLE", "%s", szMsgBuf);

    return;
}

VOID SESSION_KDeleteSessionByModule(IN SESSION_HANDLE hSession,
                                    IN SESSION_MODULE_E enModule)
{
    SESSION_CTRL_S *pstSessionCtrl;
    SESSION_S *pstSession = (SESSION_S *)hSession;
	
	if(NULL == pstSession)
	 {
		 return;
	 }

    pstSessionCtrl = SESSION_CtrlData_Get();
 
    if(0 == (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_SWITCH_EVENT))
    {
        return;
    }
	
	session_kdebugTableSetDelEvent(pstSession, enModule);

    #if 0
    if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, (USHORT)SESSION_IPV6))
    {
        if(BOOL_TRUE == SESSION_KMatchACL(pstSession, pstSessionCtrl->stDebug.uiAclNum))
        {
            session_kdebugTableSetDelEvent(pstSession, enModule);
        }
    }
    else
    {
        if(BOOL_TRUE == SESSION6_KMatchACL(pstSession, pstSessionCtrl->stDebug.uiAclNum))
        {
            session6_kdebugTableSetDelEvent(pstSession, enModule);
        }
    }
	#endif

    return;
}


STATIC VOID session_kdebugTableEvent(IN const SESSION_S *pstSession,
                                     IN SESSION_DEBUG_EVENT_E enEventType)
{
    CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
    ULONG ulLen;
    csp_key_t *pstcskey;

    DBGASSERT(NULL != pstSession);
    DBGASSERT(enEventType < EVENT_MAX);

    pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);

    ulLen = (UINT)session_tuple5_snprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pstcskey, "EVENT");

    /* 再写Event */
    ulLen += (UINT)scnprintf(szMsgBuf + ulLen,
                             SESSION_DBG_BUF_SIZE - ulLen,
                             g_apcSession_DebugFmt[SESSION_DBG_FMT_OPERATION],
                             g_apcSession_DebugEventType[enEventType]);
	
    debug_trace("%s", szMsgBuf);

    //forcompile syslog2(SESSION_SYSLOG_PRIORITY, SESSION_NAME, "TABLE", "%s", szMsgBuf);

    return;
}

#if 0
/* 格式化Tuple的五元组信息为字符串 */
STATIC INT session6_tuple5_snprintf(INOUT CHAR *pcMsgBuf,
                                    IN size_t ulsize,
                                    IN const csp_key_t *pstcspkey,
                                    IN const CHAR *pcDbugInfo)
{
    INT iLen;
    CHAR szSrcIPAddr[INET6_ADDRSTRLEN];
    CHAR szDstIPAddr[INET6_ADDRSTRLEN];
    CHAR SZProtoName[APR_PROTO_NAME_MAX_LEN+1];
    CHAR szB4Info[INET6_ADDRSTRLEN+2];

    /* 1.取协议名 */
    (VOID)APR_GetProtoNameByID(pstcspkey->proto, SZProtoName);

    /* 2.取tuple中的IP地址 */
    (VOID)inet_ntop(AF_INET6, &pstcspkey->src_ip, szSrcIPAddr, (UINT)sizeof(szSrcIPAddr));    
    (VOID)inet_ntop(AF_INET6, &pstcspkey->dst_ip, szDstIPAddr, (UINT)sizeof(szDstIPAddr));

    /* IPV6地址以这样的形式显示:
    Tuple5(EVENT): XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:/8-->
                   XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX:/3840(tcp(6)) */

    /* 获取DS-Lite模式tunnel对端 */
    szB4Info[0] = 0;
    iLen = scnprintf(pcMsgBuf,
                     ulsize,
                     g_apcSession_DebugTuple5Fmt[SESSION_L3_TYPE_IPV6],
                     pcDbugInfo,
                     szSrcIPAddr,
                     szB4Info,
                     ntohs(pstcspkey->src_port),
                     szDstIPAddr,
                     ntohs(pstcspkey->dst_port),
                     SZProtoName,
                     pstcspkey->proto);
    return iLen;
}

/* 会话表项事件调试信息输出 */
STATIC VOID session6_kdebugTableEvent(IN const SESSION_S *pstSession,
                                      IN SESSION_DEBUG_EVENT_E enEventType)
{
    CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
    ULONG ulLen;
    csp_key_t *pstcspkey;

    DBGASSERT(NULL!= pstSession);
    DBGASSERT(enEventType < EVENT_MAX);

    pstcspkey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);
    if (NULL == pstcspkey)
    {
        return;
    }

    ulLen = (UINT)session6_tuple5_snprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pstcspkey, "EVENT");

    /* 再写Event */
    ulLen += (UINT)scnprintf(szMsgBuf + ulLen,
                             SESSION_DBG_BUF_SIZE - ulLen,
                             g_apcSession_DebugFmt[SESSION_DBG_FMT_OPERATION],
                             g_apcSession_DebugEventType[enEventType]);

    //forcompile syslog2(SESSLOG_SYSLOG_PRIORITY, SESSION_NAME, "TABLE", "%s", szMsgBuf);

    return;
}
#endif

VOID SESSION_DBG_SESSION_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                               IN const SESSION_S *pstSession,
                               IN SESSION_DEBUG_EVENT_E enEventType)
{
	
	session_kdebugTableEvent(pstSession, enEventType);

	#if 0
    if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, (USHORT)SESSION_IPV6))
    {
        if(BOOL_TRUE == SESSION_KMatchACL(pstSession, pstSessionCtrl->stDebug.uiAclNum))
        {
            session_kdebugTableEvent(pstSession, enEventType);
            return;
        }
    }
    else
    {
        if(BOOL_TRUE == SESSION6_KMatchACL(pstSession, pstSessionCtrl->stDebug.uiAclNum))
        {
            session6_kdebugTableEvent(pstSession, enEventType);
            return;
        }
    }
    #endif
    return;
}

/* 关联表处理错误调试信息输出 */
STATIC VOID session_kdebugRelationError(IN SESSION_DEBUG_RELATION_ERROR_E enErrorType)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];

	DBGASSERT(enErrorType < ERROR_RELATION_DEBUG_MAX);

	(VOID)scnprintf(szMsgBuf,
		            SESSION_DBG_BUF_SIZE,
		            g_apcSession_DebugFmt[SESSION_DBG_FMT_ERROR],
		            g_apcSession_DebugRelationErrorType[enErrorType]);
					
    debug_trace("%s", szMsgBuf);

	return;
}

/* 关联表处理错误调试信息输出 */
VOID SESSION_DBG_RELATION_ERROR(IN const SESSION_CTRL_S *pstSessionCtrl, IN SESSION_DEBUG_RELATION_ERROR_E enErrorType)
{
    session_kdebugRelationError(enErrorType);

	return;
}

STATIC VOID session_kdebugExtInfo(IN const SESSION_S *pstSession,
                                  IN SESSION_MODULE_E enMoudle,
                                  IN SESSION_DEBUG_EVENT_E enEventType)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
	ULONG ulLen;
	csp_key_t *pstcskey;

	DBGASSERT(NULL != pstSession);
	DBGASSERT(NULL != pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);
	DBGASSERT(enEventType < EVENT_MAX);
	DBGASSERT(enMoudle < SESSION_MODULE_MAX);

	ulLen = (UINT)scnprintf(szMsgBuf,
		                    SESSION_DBG_BUF_SIZE,
		                    g_apcSession_DebugFmt[SESSION_DBG_FMT_EXTINFO],
		                    g_apcSession_DebugEventType[enEventType],
		                    g_apcSession_ModuleName[enMoudle]);

    pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);
	ulLen += (UINT)session_tuple5_snprintf(szMsgBuf+ulLen,
		                                   SESSION_DBG_BUF_SIZE - ulLen,
		                                   pstcskey,
		                                   "(EVENT)");

										   
    debug_trace("%s", szMsgBuf);
	
	/*syslog2(SESSION_SYSLOG_PRIORITY, SESSION_NAME, "EXTINFO", "%s", szMsgBuf);*/

	return;
}

#if 0
STATIC VOID session6_kdebugExtInfo(IN const SESSION_S *pstSession,
                                   IN SESSION_MODULE_E enMoudle,
                                   IN SESSION_DEBUG_EVENT_E enEventType)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
	ULONG ulLen;
	csp_key_t *pstIp6fsKey;

	DBGASSERT(NULL != pstSession);
	DBGASSERT(enEventType < EVENT_MAX);
	DBGASSERT(enMoudle < SESSION_MODULE_MAX);

	ulLen = (UINT)scnprintf(szMsgBuf,
		                    SESSION_DBG_BUF_SIZE,
		                    g_apcSession_DebugFmt[SESSION_DBG_FMT_EXTINFO],
		                    g_apcSession_DebugEventType[enEventType],
		                    g_apcSession_ModuleName[enMoudle]);
	
    pstIp6fsKey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);
	if(NULL == pstIp6fsKey)
	{
		return;
	}
	
	ulLen += (UINT)session6_tuple5_snprintf(szMsgBuf+ulLen,
		                                   SESSION_DBG_BUF_SIZE - ulLen,
		                                   pstIp6fsKey,
		                                   "(EVENT)");
	
    debug_trace("%s", szMsgBuf);
	
	/*syslog2(SESSION_SYSLOG_PRIORITY, SESSION_NAME, "EXTINFO", "%s", szMsgBuf);*/

	return;
}
#endif

VOID SESSION_DBG_EXT_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                           IN const SESSION_S *pstSession,
                           IN SESSION_MODULE_E enModule,
                           IN SESSION_DEBUG_EVENT_E enEventType)
{
	
	session_kdebugExtInfo(pstSession, enModule, enEventType);

	
    /*
	if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, (USHORT)SESSION_IPV6))
	{
		if(BOOL_TRUE == SESSION_KMatchACL(pstSession, pstMDC->stDebug.uiAclNum_Event_ExtInfo))
		{
			session_kdebugExtInfo(pstSession, enModule, enEventType);
			return;
		}
	}
	else
	{
		if(BOOL_TRUE == SESSION6_KMatchACL(pstSession, pstMDC->stDebug.uiAclNum_Event_ExtInfo))
		{
			session6_kdebugExtInfo(pstSession, enModule, enEventType);
			return;
		}
	}
	*/
	
	return;
}

#if 0
STATIC inline VOID session_kdebugAlgArgs(IN UINT uiDbgType, IN const CHAR *pcFormat, IN va_list args)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
	CHAR *pcFlag;

	if(SESSION_DEBUG_SWITCH_EVENT == uiDbgType)
	{
		pcFlag = "ALG-EVENT";
	}
	else if(SESSION_DEBUG_SWITCH_ERROR == uiDbgType)
	{
		pcFlag = "ALG-ERROR";
	}
	else
	{
		return;
	}

	/* 写格式化字符串 */
	(VOID)vscnprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pcFormat, args);

	syslog2(SESSION_SYSLOG_PRIORITY, SESSION_NAME, pcFlag, "%s", szMsgBuf);
	return;
}

VOID SESSION_DBG_ALG_ARGS(IN const V_SESSION_MDC_S *pstMDC,
                          IN const SESSION_S *pstSession,
                          IN UINT uiDbgType,
                          IN const CHAR *pcFormat, ...)
{
	va_list args;
	UINT uiDbgFlag;

	if (0 == (pstMDC->stDebug.auiDebugSwitch[SESSION_DEBUG_ALG] & uiDbgType))
	{
		return;
	}

	if(SESSION_DEBUG_SWITCH_EVENT == uiDbgType)
	{
		uiDbgFlag = pstMDC->stDebug.uiAclNum_Event_Alg;
	}
	else if (SESSION_DEBUG_SWITCH_ERROR == uiDbgType)
	{
		uiDbgFlag = pstMDC->stDebug.uiAclNum_Error_Alg;
	}
	else
	{
		return;
	}

	if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, (USHORT)SESSION_IPV6)
	{
		if(BOOL_TRUE != SESSION_KMatchACL(pstSession, uiDbgFlag))
		{
			return;
		}
	}
	else
	{
		if(BOOL_TRUE != SESSION6_KMatchACL(pstSession, uiDbgFlag))
		{
			return;
		}
	}

	va_start(args, pcFormat);
	session_kdebugAlgArgs(uiDbgType, pcFormat, args);
	va_end(args);

	return;
}
#endif

/* 格式化relation的四元组信息为字符串 */
STATIC INT session_relation_snprintf(INOUT CHAR *pcMsgBuf,
                                     IN size_t ulSize,
									 IN const csp_key_t *pstcskey,
                                     IN const CHAR *pcDebugInfo)
{
	INT iLen;
	CHAR szSrcIPAddr[INET6_ADDRSTRLEN];
	CHAR szDstIPAddr[INET6_ADDRSTRLEN];
	CHAR szProtoname[APR_PROTO_NAME_MAX_LEN+1];

	/* 1.取协议名 */
	(VOID)APR_GetProtoNameByID(pstcskey->proto, szProtoname);

	/*2.取tuple中的IP地址*/
	if(0 != pstcskey->src_ip)
	{
		(VOID)inet_ntop(AF_INET, &pstcskey->src_ip, szSrcIPAddr, (UINT)sizeof(szSrcIPAddr));
	}
	else
	{
		scnprintf(szSrcIPAddr, sizeof(szSrcIPAddr), "%s", "-");
	}

	(VOID)inet_ntop(AF_INET, &pstcskey->dst_ip, szDstIPAddr, (UINT)sizeof(szDstIPAddr));

	/*IPV4地址以这样的形式显示:
	Tuple(EVENT):192.168.0.2/1620 -->192.168.1.58/3840(TCP)
	假如不关心源地址或源端口，对应位置会显示为"-"*/

	if(0 == pstcskey->src_ip)
	{
		iLen = scnprintf(pcMsgBuf,
			             ulSize,
			             g_apcSession_DebugRelationFmt[SESSION_L3_TYPE_IPV4],
			             pcDebugInfo,
			             szSrcIPAddr,
			             szDstIPAddr,
			             ntohs(pstcskey->dst_port),
			             szProtoname,
			             pstcskey->proto);
	}
	else
	{
		iLen = scnprintf(pcMsgBuf,
			             ulSize,
			             g_apcSession_DebugRelationPortFmt[SESSION_L3_TYPE_IPV4],
			             pcDebugInfo,
			             szSrcIPAddr,
			             ntohs(pstcskey->src_port),
			             szDstIPAddr,
			             ntohs(pstcskey->dst_port),
			             szProtoname,
			             pstcskey->proto);
	}

	return iLen;
}
									 
STATIC VOID session_kdebugRelationEvent(IN RELATION_S*pstRelation,
                                        IN SESSION_DEBUG_EVENT_E enEventType,
                                        IN SESSION_REASON_OP_E enOpReasion)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
    ULONG ulLen;
    csp_key_t *pstcskey;

	DBGASSERT(enEventType < EVENT_MAX);

	pstcskey = &pstRelation->stTupleHash.stIpfsKey;

	ulLen = (UINT)session_relation_snprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pstcskey, "(EVENT)");

	/* 再写Event */
	ulLen += (UINT)scnprintf(szMsgBuf + ulLen,
	                         SESSION_DBG_BUF_SIZE - ulLen,
	                         g_apcSession_DebugFmt[SESSION_DBG_FMT_RELATION],
	                         g_apcSession_DebugEventType[enEventType],
	                         g_apcSession_DebugOpReason[enOpReasion]);

    debug_trace("%s", szMsgBuf);

	return;
}
										
/* 关联表项事件调试信息输出 */
VOID SESSION_DBG_RELATION_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                                IN RELATION_S *pstRelation,
                                IN SESSION_DEBUG_EVENT_E enEventType,
                                IN SESSION_REASON_OP_E enOpReason)
{
    session_kdebugRelationEvent(pstRelation, enEventType, enOpReason);
	
	return;
}

STATIC VOID session_kdebugAlgError(IN const SESSION_S *pstSession, IN ALG_DEBUG_ERROR_E enAlgErrorType)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
	ULONG ulLen;
    csp_key_t *pstcskey;

	DBGASSERT(NULL != pstSession);
	DBGASSERT(enAlgErrorType < DBG_ALG_ERROR_MAX);
	
    pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);

	ulLen = (UINT)session_tuple5_snprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pstcskey, "(EVENT)");

	/* 再写Event */
	ulLen += (UINT)scnprintf(szMsgBuf +ulLen,
	                         SESSION_DBG_BUF_SIZE - ulLen,
	                         g_apcSession_DebugFmt[SESSION_DBG_FMT_ALG_ERROR],
	                         g_apcSession_DebugAlgErrorType[enAlgErrorType]);

    debug_trace("%s", szMsgBuf);
							 
	return;
}

#if 0
STATIC VOID session6_kdebugAlgError(IN const SESSION_S *pstSession, IN ALG_DEBUG_ERROR_E enAlgErrorType)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
	ULONG ulLen;
	csp_key_t *pstIp6fsKey;

	DBGASSERT(NULL != pstSession);
	DBGASSERT(enAlgErrorType < DBG_ALG_ERROR_MAX);
	
    pstIp6fsKey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);
	if(NULL == pstIp6fsKey)
	{
		return;
	}

	ulLen = (UINT)session6_tuple5_snprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pstIp6fsKey, "(EVENT)");

	/* 再写Event */
	ulLen += (UINT)scnprintf(szMsgBuf +ulLen,
	                         SESSION_DBG_BUF_SIZE - ulLen,
	                         g_apcSession_DebugFmt[SESSION_DBG_FMT_ALG_ERROR],
	                         g_apcSession_DebugAlgErrorType[enAlgErrorType]);

							 
    debug_trace("%s", szMsgBuf);

    /*syslog2(SESSION_SYSLOG_PRIORITY, SESSION_NAME, "ALG", "%s", szMsgBuf);*/

	return;
}
#endif

/* ALG错误调试信息输出 */
VOID SESSION_DBG_ALG_ERROR(IN const SESSION_CTRL_S *pstSessionCtrl,
                           IN const SESSION_S *pstSession,
                           IN ALG_DEBUG_ERROR_E enAlgErrorType)
{
	
	session_kdebugAlgError((SESSION_S *)pstSession, enAlgErrorType);

	/**
	if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, (USHORT)SESSION_IPV6))
	{
		if(BOOL_TRUE == SESSION_KMatchACL(pstSession, pstSessionCtrl->stDebug.uiAclNum_Error_Alg))
		{
			session_kdebugAlgError((SESSION_S *)pstSession, enAlgErrorType);
			return;
		}
	}
	else
	{
		if(BOOL_TRUE == SESSION6_KMatchACL((SESSION_S *)pstSession, pstMDC->stDebug.uiAclNum_Error_Alg))
		{
			session6_kdebugAlgError((SESSION_S *)pstSession, enAlgErrorType);
			return;
		}
	}
	**/
	return;
}
						   
/* 格式化relation的四元组信息为字符串 */
STATIC INT session6_relation_snprintf(INOUT CHAR *pcMsgBuf,
                                      IN size_t ulsize,
                                      IN const csp_key_t *pstIp6fsKey,
                                      IN const CHAR *pcDebugInfo)
{
	INT iLen;
	CHAR szSrcIPAddr[INET6_ADDRSTRLEN];
	CHAR szDstIPAddr[INET6_ADDRSTRLEN];
	CHAR szProtoName[APR_PROTO_NAME_MAX_LEN+1];

	/* 1.取协议名 */
	(VOID)APR_GetProtoNameByID(pstIp6fsKey->proto, szProtoName);

	/*2.取tuple中的IP地址 */
	(VOID)inet_ntop(AF_INET6, &pstIp6fsKey->src_ip, szSrcIPAddr, (UINT)sizeof(szSrcIPAddr));
    (VOID)inet_ntop(AF_INET6, &pstIp6fsKey->dst_ip, szDstIPAddr, (UINT)sizeof(szDstIPAddr));

	/* IPV6地址以这样的形式显示:
	Tuple(EVNET): 192.168.0.2/1620 -->
	               xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx/3840(TCP)
	假如不关心源地址或源端口，对应位置会显示为"-" */

	if(0 == pstIp6fsKey->src_port)
	{
		iLen = scnprintf(pcMsgBuf,
			             ulsize,
			             g_apcSession_DebugRelationFmt[SESSION_L3_TYPE_IPV6],
			             pcDebugInfo,
			             szSrcIPAddr,
			             szDstIPAddr,
			             ntohs(pstIp6fsKey->dst_port),
			             szProtoName,
			             pstIp6fsKey->proto);
	}
	else
	{
		iLen = scnprintf(pcMsgBuf,
			            ulsize,
			            g_apcSession_DebugRelationPortFmt[SESSION_L3_TYPE_IPV6],
			            pcDebugInfo,
			            szSrcIPAddr,
			            ntohs(pstIp6fsKey->src_port),
			            szDstIPAddr,
			            ntohs(pstIp6fsKey->dst_port),
			            szProtoName,
			            pstIp6fsKey->proto);
    }

	return iLen;
}
									  
STATIC VOID session6_kdebugRelationEvent(IN RELATION6_S* pstRelation,
                                         IN SESSION_DEBUG_EVENT_E enEventType,
                                         IN SESSION_REASON_OP_E enOpReasion)
{
	CHAR szMsgBuf[SESSION_DBG_BUF_SIZE];
	ULONG ulLen;
	csp_key_t *pstIp6fsKey;

	DBGASSERT(enEventType < EVENT_MAX);

	pstIp6fsKey = &pstRelation->stTupleHash.stIp6fsKey;

	ulLen = (UINT)session6_relation_snprintf(szMsgBuf, SESSION_DBG_BUF_SIZE, pstIp6fsKey, "(EVENT)");

	/* 再写Event */
	ulLen += (UINT)scnprintf(szMsgBuf + ulLen,
	                         SESSION_DBG_BUF_SIZE - ulLen,
	                         g_apcSession_DebugFmt[SESSION_DBG_FMT_RELATION],
	                         g_apcSession_DebugEventType[enEventType],
	                         g_apcSession_DebugOpReason[enOpReasion]);
	
    debug_trace("%s", szMsgBuf);

    /*syslog2(SESSLOG_SYSLOG_PRIORITY, SESSION_NAME, "RELATION6", "%s", szMsgBuf);*/

	return;
}
										 
VOID SESSION6_DBG_RELATION_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                                 IN RELATION6_S *pstRelation,
                                 IN SESSION_DEBUG_EVENT_E enEventType,
                                 IN SESSION_REASON_OP_E enOpReason)
{
	session6_kdebugRelationEvent(pstRelation, enEventType, enOpReason);

	return;
}
