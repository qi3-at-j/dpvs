
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "dpdk.h"
#include "conf/common.h"
#include "netif.h"
#include "netif_addr.h"
#include "ctrl.h"
#include "extlist.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"
#include "timer.h"
#include "parser/parser.h"
//#include "neigh.h"
#include "scheduler.h"

#include <rte_arp.h>
#include <rte_cycles.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "global_data.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"
#include "flow_cli.h"
#include "flow_msg.h"
#include "session.h"
#include "l3vpn.h"
#include "if.h"
#include "secp.h"
#include "flow.h"
#include "session_kutil.h"
#include "fw_conf/session_cli.h"
#include "apr.h"
#include "fw_lib.h"
#include "session_kcore.h"
#include "session_khash.h"
#include "session_krelation.h"


typedef enum __show_clear_sess_type__ {
    sess_t_show_stat = 1,
    sess_t_show_stat_full,
    sess_t_show_dbg_status,
    sess_t_show_other,
    sess_t_show_v4,
    sess_t_show_v6,
    sess_t_clear_stat,
    sess_t_clear_table_all,
    sess_t_clear_table_v4,
    sess_t_clear_table_v6
} SHOW_CLEAR_SESSION_TYPE_E;

typedef enum __show_clear_sess_para__ {
    sess_para_type = 0,
    sess_para_sipv6,
    sess_para_dipv6,
    sess_para_sip,
    sess_para_dip,
    sess_para_proto,
    sess_para_sport,
    sess_para_dport,
    sess_para_vrf,
    sess_para_state,
    sess_para_responder,
    sess_para_verbose
} SHOW_CLEAR_SESSION_PARA_E;

typedef enum __show_clear_sess_numid__ {
    sess_numid_sport = 0,
    sess_numid_dport,
    sess_numid_vrf,
} SHOW_CLEAR_SESSION_NUMID_E;

typedef enum __show_clear_sess_strid__ {
    sess_strid_sip = 0,
    sess_strid_dip,
    sess_strid_sipv6,
    sess_strid_dipv6
} SHOW_CLEAR_SESSION_STRID_E;

#define L4_COMPOUND_STATE(l4_type, state) ((l4_type) * SESSION_PROTOCOL_STATE_MAX + (state))

#define DATE_MAX_LENGTH 128
#define YEAR_BASED      1900
#define RULE_NAME_MAX_LENGTH 256

STATIC CHAR* g_apcSessionException[SESSION_STAT_FAIL_TYPE_MAX] = 
{
    [SESSION_STAT_FAIL_CREATE_CACHE_NULL]    = "Cache for session creating was null",
    [SESSION_STAT_FAIL_GETL4OFFSET]          = "Failed to get Layer 4 offset",
    [SESSION_STAT_FAIL_PKT_CHECK]            = "Packet check failures",
    [SESSION_STAT_FAIL_ALLOC_CACHE]          = "Cache allocation failures",
    [SESSION_STAT_FAIL_ALLOC_SESSION]        = "session allocation failures",
    [SESSION_STAT_FAIL_EXTNEW_STATE]         = "State errors in ext-session creating",
    [SESSION_STAT_FAIL_TRY_FAIL_UNICAST]     = "Unicast session end processing failures",
    [SESSION_STAT_FAIL_CAPABITITY_UNICAST]   = "Limit for concurrent unicast sessions",
    [SESSION_STAT_FAIL_FORMALIZE_UNICAST]    = "Unicast session formalization failures",
//    [SESSION_STAT_FAIL_TRY_FAIL_MULTICAST]   = "Multicast session end processing failures",
//    [SESSION_STAT_FAIL_CAPABITITY_MULTICAST] = "Limit for concurrent multicast sessions",
//    [SESSION_STAT_FAIL_FORMALIZE_MULTICAST]  = "Multicast session formalization failures",
    [SESSION_STAT_FAIL_TOUCH_CACHE_NULL]     = "Cache for session touch was null",
    [SESSION_STAT_FAIL_TOUCH_STATE]          = "State errors in session touch",
    [SESSION_STAT_FAIL_EXT_STATE]            = "Ext-session state errors",
    [SESSION_STAT_FAIL_TCP_STATE]            = "TCP state errors",    
    [SESSION_STAT_FAIL_FAST_TCP_STATE]       = "TCP state errors in fast process",
    [SESSION_STAT_FAIL_HOTBACKUP_DELETE_FAIL]= "Hot-backup force delete session failures",
    [SESSION_STAT_FAIL_HOTBACKUP_HASHFAIL]   = "Hot-backup session adding cache failures",
    [SESSION_STAT_FAIL_RELATION_LOCAL_HASH]  = "Failed to add relation local hash",
    [SESSION_STAT_FAIL_RELATION_GLOBAL_HASH] = "Failed to add relation global hash",
//    [SESSION_STAT_FAIL_MBUF_RELAY_OUTPUT]    = "Session relay output recv failures",
//    [SESSION_STAT_FAIL_MBUF_RELAY_INPUT]     = "Session relay input recv failures",
    [SESSION_STAT_FAIL_FIRST_PATH]           = "First path failures",
    [SESSION_STAT_FAIL_FAST_PATH]            = "Fast path failures",
};

typedef void (* selected_session_vector_t)(flow_connection_t *fcp, void *args, void *paras);

VOID APR_GetProtoNameByID(IN UCHAR ucProto, OUT CHAR szName[APR_PROTO_NAME_MAX_LEN+1]);
int select_this_connection(flow_connection_t *fcp, connection_op_para_t *paras);

extern CHAR *g_apcSessionStatusName[SESSION_L4_TYPE_MAX][SESSION_PROTOCOL_STATE_MAX];

static struct cmdline *cl = NULL;
static uint32_t sess_cnt;
static uint32_t relation_cnt;


extern SESSION_HASH_HANDLE     g_hV4RelationHash3;
extern SESSION_HASH_HANDLE     g_hV4RelationHash5;
extern SESSION_HASH_HANDLE     g_hV6RelationHash;


STATIC VOID _PrintSessionStatCounter(BOOL_T bFull)
{
    SESSION_STAT_FAIL_TYPE_E enType;
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();
    uint32_t uiFailCnt;

    tyflow_cmdline_printf(cl, "\r\n  Abnormal packets:\r\n");
    
    for (enType = SESSION_STAT_FAIL_CREATE_CACHE_NULL; enType < SESSION_STAT_FAIL_TYPE_MAX; enType++)
    {
        uiFailCnt =  rte_atomic32_read(&pstSessionCtrl->astStatFailCnt[SESSION_STAT_IPV4][enType]);
        uiFailCnt += rte_atomic32_read(&pstSessionCtrl->astStatFailCnt[SESSION_STAT_IPV6][enType]);
        if ((uiFailCnt != 0) || bFull)
            tyflow_cmdline_printf(cl, "    %s: %u\r\n", g_apcSessionException[enType], uiFailCnt);
    }

    return;
}

STATIC VOID agingqueue_print_statistics(struct cmdline *cl)
{
    int i;
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstData = g_stSessionstAgingQueue.pstVcpuData;

    if (NULL == pstData)
        return;

    tyflow_cmdline_printf(cl, "\r\n  Aging queue statistics:\r\n");
    tyflow_cmdline_printf(cl, "    CoreID  UnstableNum  ResetMsgNum\r\n");
    for (i = 0; i < worker_thread_total(); i++) {
        tyflow_cmdline_printf(cl, "    %-7d %-12lu %-11lu\r\n", 
            i+1, pstData[i].ulUnstableNumber, pstData[i].ulResetMsgNum);
    }

    return;
}

STATIC VOID SESSION_KGetTuple(IN conn_sub_t *conn_sub, OUT SESSION_TUPLE_S *pstTuple)
{
	/* AFT性能优化：不再对pstTuple整体清零 */
    UINT32 uiVrf = conn_sub->key.token;
	
	pstTuple->ucType = 0;
	pstTuple->ucRsv2 = 0;
	if (conn_sub->cspflag & CSP_FLAG_IPV6) {
        pstTuple->ucL3Family = AF_INET6;
        memcpy(pstTuple->unL3Src.auiIp6, &conn_sub->key.src_ip, sizeof(pstTuple->unL3Src.auiIp6));
        memcpy(pstTuple->unL3Dst.auiIp6, &conn_sub->key.dst_ip, sizeof(pstTuple->unL3Dst.auiIp6));
	}
	else {
        pstTuple->ucL3Family = AF_INET;
        pstTuple->unL3Src.uiIp = conn_sub->csp_src_ip;
	    pstTuple->unL3Dst.uiIp = conn_sub->csp_dst_ip;
	}

	pstTuple->ucProtocol = conn_sub->csp_proto;
	pstTuple->unL4Src.usAll = ntohs(conn_sub->csp_src_port);
	pstTuple->unL4Dst.usAll = ntohs(conn_sub->csp_dst_port);
	pstTuple->uiTunnelID = 0; //TODO
	pstTuple->vrfIndex = ntohl(uiVrf);

	return;
}

/* 计算老化对象剩余老化时间 */
static inline UINT64 AGINGQUEUE_Unstable_GetTTL(IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject,
                                              IN UINT64 uiUpdateTime)
{
	LONG lTemp;
	ULONG ulCycles = rte_get_timer_cycles();

	lTemp = (LONG)uiUpdateTime + (LONG)pstObject->pstClass->ulTimeout;
	if((lTemp - (LONG)ulCycles) > 0)
	{
		lTemp -= (LONG)ulCycles;
		return lTemp;
	}
	else
	{
		return 0;
	}
}

/* 获取会话老化时间 */
UINT _session_Kdump_GetTTL(IN SESSION_S *pstSession)
{
	UINT uiTTL = 0;
#if 0
	if((NULL != g_stSessionKalgPacketProc.pfAlgSipEstProc) &&
	   (BOOL_TRUE == g_stSessionKalgPacketProc.pfAlgSipEstProc(pstSession)))
	{
		uiTTL = _session_Kdump_GetAlgSipTTL(pstSession);
	}
	else
#endif
	{
		/* 获取会话表剩余老化时间，对于已经超时但是未被删除的会话表，剩余时间统一传0 */
	    uiTTL = AGINGQUEUE_Unstable_GetTTL(&pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo,
	                                             pstSession->stSessionBase.uiUpdateTime) / rte_get_timer_hz();
	}

	return uiTTL;
}

/******************************************************************
   Func Name:_getTotalRate
Date Created:2021/04/25
      Author:wangxiaohua
 Description:获取会话总速率
       INPUT:SESSION_STATISTICS_S *pstStatics       会话统计信息
      Output:
      Return:UINT uiRateTotal,   总的会话速率
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static UINT _getTotalRate(IN const SESSION_STATISTICS_S *pstStatics)
{
    UINT uiRateTotal = 0;
    UINT uiTypeCounter;

    for(uiTypeCounter = 0; uiTypeCounter < SESSION_L4_TYPE_MAX; uiTypeCounter++)
    {
        uiRateTotal += pstStatics->auiRateStat[uiTypeCounter];
    }

    return uiRateTotal;
}

/******************************************************************
   Func Name:_dis_SessionStaticsSummary
Date Created:2021/04/25
      Author:wangxiaohua
 Description:显示统计信息
       INPUT:IN const SESSION_STATISTICS_S *pstStatics
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID _dis_SessionStaticsSummary(IN const SESSION_STATISTICS_S *pstStatics)
{
    UINT uiRateTotal;
    CHAR szRateTotal[16];
    CHAR szRateTCP[16];
    CHAR szRateUDP[16];
    UINT64 uiPktTotal = 0;
    int i;

    uiRateTotal = _getTotalRate(pstStatics);
    for(i = 0; i < SESSION_L4_TYPE_MAX; i++)
    {
        uiPktTotal += pstStatics->astFlowStat[i].uiPacketsCount;
    }

    scnprintf(szRateTotal, sizeof(szRateTotal), "%u/s", uiRateTotal);    
    scnprintf(szRateTCP,   sizeof(szRateTCP),   "%u/s", pstStatics->auiRateStat[SESSION_L4_TYPE_TCP]);
    scnprintf(szRateUDP,   sizeof(szRateUDP),   "%u/s", pstStatics->auiRateStat[SESSION_L4_TYPE_UDP]);

    tyflow_cmdline_printf(cl, "    %-9u %-9u %-9u %-9s %-9s %-9s\r\n",
           pstStatics->uiTotalSessNum,
           pstStatics->auiProtoStateCount[SESSION_L4_TYPE_TCP][0],
           pstStatics->auiProtoStateCount[SESSION_L4_TYPE_UDP][0],
           szRateTotal,
           szRateTCP,
           szRateUDP);

    tyflow_cmdline_printf(cl, "    Packets\r\n    %lu\r\n", uiPktTotal);
    return;
}

/******************************************************************
   Func Name:session_global_stat_get_flow_static
Date Created:2021/04/25
      Author:wangxiaohua
 Description:从内核获取四层协议的流统计(报文数，字节数)并填写到指定的出参
       INPUT:IN SESSION_K_STATISTICS_S  *pstKstatistics    ---全局统计数据结构
             INOUT SESSION_STATISTICS_S *pstStatistics     ---会话统计信息
      Output:INOUT SESSION_STATISTICS_S *pstStatistics     ---会话统计信息
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID session_global_stat_get_flow_static(IN const SESSION_K_STATISTICS_S *pstKstatistics,
                                                INOUT SESSION_STATISTICS_S *pstStatistics)
{
    INT iVcpu;
    ULONG ulL4Type;
    UINT *puiOutRate;
    UINT uiOutRelationRate;
    SESSION_STAT_VCPU_S *pstPerCpuStat;
    SESSION_RATE_STAT_S *pstPerCpuRate;
    SESSION_STAT_VCPU_S *pstVcpuStat;
    SESSION_FLOW_STAT_S *pstOutFlowStat;
    SESSION_FLOW_STAT_S *pstPerCpuFlow;

    pstOutFlowStat = pstStatistics->astFlowStat;
    puiOutRate     = pstStatistics->auiRateStat;
    pstVcpuStat    = pstKstatistics->pstVcpuStat;
    uiOutRelationRate = 0;
    for(iVcpu = 0; iVcpu < worker_thread_total(); iVcpu++)
    {
        pstPerCpuStat = SESSION_GET_PERCPU_PTR(pstVcpuStat, iVcpu);
        pstPerCpuRate = pstPerCpuStat->astRateStat;
        pstPerCpuFlow = pstPerCpuStat->astFlowStat;

        for (ulL4Type = 0; ulL4Type < SESSION_L4_TYPE_MAX; ulL4Type++)
        {
            pstOutFlowStat[ulL4Type].uiBytesCount   += pstPerCpuFlow[ulL4Type].uiBytesCount;
            pstOutFlowStat[ulL4Type].uiPacketsCount += pstPerCpuFlow[ulL4Type].uiPacketsCount;
            SESSION_KUpdateRateStat(&pstPerCpuRate[ulL4Type]);
            puiOutRate[ulL4Type]                    += pstPerCpuRate[ulL4Type].uiLastSecondRate;
        }
        SESSION_KUpdateRateStat(&pstPerCpuStat->stRelateTableRateStat);
        uiOutRelationRate   += pstPerCpuStat->stRelateTableRateStat.uiLastSecondRate;
    }
    pstStatistics->auiRelationRateStat = uiOutRelationRate;

    return;
}

STATIC VOID session_global_stat_get_app_proto_state_count(IN const SESSION_K_STATISTICS_S *pstKstatistics,
                                                          INOUT SESSION_STATISTICS_S *pstStatistics)
{
	UINT uiAppType;

	for(uiAppType = 0; uiAppType < SESSION_APP_STATIC_MAX; uiAppType++)
	{
		pstStatistics->auiAppStat[uiAppType] = rte_atomic32_read(&(pstKstatistics->astAppCount[uiAppType]));
	}

	return;
}
														  
/******************************************************************
   Func Name:session_global_stat_get
Date Created:2021/04/25
      Author:wangxiaohua
 Description:获取统计信息
       INPUT:SESSION_STATISTICS_S *pstStatistics    ---会话统计信息
      Output:SESSION_STATISTICS_S *pstStatistics    ---会话统计信息
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID session_global_stat_get(INOUT SESSION_STATISTICS_S *pstStatistics)
{
    SESSION_K_STATISTICS_S *pstKstatistics;
    SESSION_CTRL_S *pstSessionCtrl;

    pstSessionCtrl = SESSION_CtrlData_Get();
    pstKstatistics = &(pstSessionCtrl->stSessStat);

    memset(pstStatistics, 0, sizeof(SESSION_STATISTICS_S));
    pstStatistics->uiTotalSessNum = (UINT)rte_atomic32_read(&(pstKstatistics->stTotalSessNum));
    pstStatistics->uiTotalRelationNum = (UINT)rte_atomic32_read(&(pstKstatistics->stTotalRelationNum));

#if 0
    SESSION_Update_AgentStatics(pstStatistics->auiAgentCount);

    SESSION_global_stat_get_maxsess_count(pstKstatistics, pstStatistics);
    /*MIB*/
    session_global_stat_get_all_stat_count(pstKstatistics, pstStatistics);
    
    session_global_stat_get_proto_state_count(pstKstatistics, pstStatistics);
#endif
    session_global_stat_get_flow_static(pstKstatistics, pstStatistics);
    session_global_stat_get_app_proto_state_count(pstKstatistics, pstStatistics);

    return;
}

STATIC VOID _ShowStatisticsSummaryTitle(VOID)
{
	tyflow_cmdline_printf(cl, "  Summary:\r\n    %-9s %-9s %-9s %-9s %-9s %-9s\r\n",
		   "Sessions", "TCP", "UDP",
		   "Rate", "TCP rate", "UDP rate");
}


STATIC VOID _cfg_SessionDisStatisticsSummary(BOOL_T bFull)
{
    SESSION_STATISTICS_S stStatics;
    
	/* 打印表头 */
    _ShowStatisticsSummaryTitle();
    session_global_stat_get(&stStatics);
	_dis_SessionStaticsSummary(&stStatics);

    _PrintSessionStatCounter(bFull);
    
    agingqueue_print_statistics(cl);
    
	tyflow_cmdline_printf(cl, "\r\n");

	return;
}

CHAR * SESSION_GetStatusName(SESSION_L4_TYPE_E enL4Type, UINT uiState)
{
    if ((enL4Type < SESSION_L4_TYPE_MAX) && (uiState < SESSION_PROTOCOL_STATE_MAX))
        return g_apcSessionStatusName[enL4Type][uiState];
    else
        return "-";
}

VOID APR_GetAppNameByID(UINT uiAppID, CHAR *pcAppName)
{
    switch(uiAppID)
    {
		case APR_ID_INVALID:			
			strlcpy(pcAppName, "-", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_HTTP:			
			strlcpy(pcAppName, "HTTP", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_FTPDATA:
			strlcpy(pcAppName, "FTP-DATA", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_FTP:	
			strlcpy(pcAppName, "FTP", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_SSH:
			strlcpy(pcAppName, "SSH", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_SMTP:			
			strlcpy(pcAppName, "SMTP", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_IMAP:
			strlcpy(pcAppName, "IMAP", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_POP3:
			strlcpy(pcAppName, "POP3", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_TELNET:
			strlcpy(pcAppName, "TELNET", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_DNS:
			strlcpy(pcAppName, "DNS", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_SMB:
			strlcpy(pcAppName, "SMB", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_NFS:
			strlcpy(pcAppName, "NFS", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_SIP:
			strlcpy(pcAppName, "SIP", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_TFTP:
			strlcpy(pcAppName, "TFTP", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_SNMP:
			strlcpy(pcAppName, "SNMP", APR_NAME_MAX_LEN+1);
			break;
		
		case APP_ID_NTP:
			strlcpy(pcAppName, "NTP", APR_NAME_MAX_LEN+1);
			break;
		
		default:
			strlcpy(pcAppName, "-", APR_NAME_MAX_LEN+1);
			break;
    }
	
    return ;
}

/* 获取IPV4的会话表地址信息并显示 */
STATIC VOID _session_ShowSessTableIpv4(IN const SESSION_TUPLE_S *pstTuple)
{
	CHAR szSrcIPv4[INET_ADDRSTRLEN];
    CHAR szDstIPv4[INET_ADDRSTRLEN];
	CHAR szTunnelPeer[INET6_ADDRSTRLEN];

	strlcpy(szSrcIPv4, "-", sizeof(szSrcIPv4));
	strlcpy(szDstIPv4, "-", sizeof(szDstIPv4));
	strlcpy(szTunnelPeer, "-", sizeof(szTunnelPeer));

	(VOID)inet_ntop(AF_INET, &(pstTuple->unL3Src.stin), szSrcIPv4, (UINT)INET_ADDRSTRLEN);
	(VOID)inet_ntop(AF_INET, &(pstTuple->unL3Dst.stin), szDstIPv4, (UINT)INET_ADDRSTRLEN);

	tyflow_cmdline_printf(cl, " Source      IP/port: %s/%u\r\n", szSrcIPv4, pstTuple->unL4Src.usAll);
	tyflow_cmdline_printf(cl, " Destination IP/port: %s/%u\r\n", szDstIPv4, pstTuple->unL4Dst.usAll);

	//tyflow_cmdline_printf(cl, " DS-Lite tunnel peer: %s\r\n", szTunnelPeer);

	return;
}

/* 获取IPV6的会话表地址信息并显示 */
STATIC VOID _session_ShowSessTableIpv6(IN const SESSION_TUPLE_S *pstTuple)
{
	CHAR szSrcIPv6[INET6_ADDRSTRLEN];
	CHAR szDstIPv6[INET6_ADDRSTRLEN];

	strlcpy(szSrcIPv6, "---", sizeof(szSrcIPv6));
	strlcpy(szDstIPv6, "---", sizeof(szDstIPv6));

	(VOID)inet_ntop(AF_INET6, &(pstTuple->unL3Src.stin6), szSrcIPv6, (UINT)INET6_ADDRSTRLEN);
	(VOID)inet_ntop(AF_INET6, &(pstTuple->unL3Dst.stin6), szDstIPv6, (UINT)INET6_ADDRSTRLEN);

	tyflow_cmdline_printf(cl, " Source      IP/port:  %s/%u\r\n", szSrcIPv6, pstTuple->unL4Src.usAll);
	tyflow_cmdline_printf(cl, " Destination IP/port:  %s/%u\r\n", szDstIPv6, pstTuple->unL4Dst.usAll);

	return;
}

/* 获取会话的协议名称，应用等信息并显示 */
STATIC VOID _session_ShowSessTable_ProtAndVpnInfo(IN const SESSION_TABLE_INFO_S* pstSessionInfo,
                                                 IN SESSION_PKT_DIR_E enDir)
{
	const SESSION_TUPLE_S *pstTuple;
	CHAR szProtName[APR_PROTO_NAME_MAX_LEN+1];
	CHAR szVPNName[L3VPN_MAX_VRFNAME_LEN+1];
	//CHAR szIFName[IF_MAX_NAME_LEN + 1];
	UCHAR ucProtocol;

	pstTuple = &(pstSessionInfo->astTuple[enDir]);
	ucProtocol = pstTuple->ucProtocol;

	strlcpy(szProtName, "-", sizeof(szProtName));
	strlcpy(szVPNName, "-", sizeof(szVPNName));
	//strlcpy(szIFName,  "N/A", sizeof(szIFName));

	APR_GetProtoNameByID(ucProtocol, szProtName);
	//uppercase(szProtName);

	/* 是否为二层转发 */
	if(BIT_TEST(pstTuple->ucType, SESSION_MACFW))
	{
		tyflow_cmdline_printf(cl, " VPN instance/VLAN ID/Inline ID: -/%u/-\r\n", pstTuple->vrfIndex);
	}
	else if(BIT_TEST(pstTuple->ucType, SESSION_BRIDGE))
	{
		//strlcpy(szIFName, "N/A", sizeof(szIFName));
		tyflow_cmdline_printf(cl, " VPN instance/VLAN ID/Inline ID: -/%u/-\r\n", pstTuple->vrfIndex);
	}
	else if(BIT_TEST(pstTuple->ucType, SESSION_INLINE))
	{
		tyflow_cmdline_printf(cl, " VPN instance/VLAN ID/Inline ID: -/-/%u\r\n", pstTuple->vrfIndex);
	}
	else
	{
		//TODO
		tyflow_cmdline_printf(cl, " VPN instance/VLAN ID/Inline ID: %s/-/-\r\n", szVPNName);
	}

	tyflow_cmdline_printf(cl, " Protocol: %s(%u)\r\n", szProtName, ucProtocol);
	//tyflow_cmdline_printf(cl, " Inboune interface: %s\r\n", szIFName);

	return;
}

/* 获取会话简要信息 */
STATIC VOID _session_ShowBriefInfo(IN const SESSION_TABLE_INFO_S *pstSessionInfo,
                                   IN SESSION_PKT_DIR_E enDir)
{
	if(AF_INET == (INT)pstSessionInfo->astTuple[enDir].ucL3Family)
	{
		_session_ShowSessTableIpv4(&(pstSessionInfo->astTuple[enDir]));
	}
	else
	{
		_session_ShowSessTableIpv6(&(pstSessionInfo->astTuple[enDir]));
	}

	_session_ShowSessTable_ProtAndVpnInfo(pstSessionInfo, enDir);

	return;
}

/* 获取会话表的其他信息 */
STATIC VOID _session_ShowTableOtherInfo(IN const SESSION_TABLE_INFO_S* pstSessionInfo)
{
	CHAR *pcStatus;
	CHAR szAppName[APR_NAME_MAX_LEN+1];
	//CHAR szRuleName[RULE_NAME_MAX_LENGTH];
	//UINT uiRuleID;
	time_t stTime;
	struct tm stStartTime;
	CHAR szDate[DATE_MAX_LENGTH];

    //szRuleName[0] = '\0';
	strlcpy(szAppName, "-", sizeof(szAppName));

	pcStatus = SESSION_GetStatusName((SESSION_L4_TYPE_E)pstSessionInfo->ucSessProto, pstSessionInfo->ucState);

	APR_GetAppNameByID(pstSessionInfo->uiAppID, szAppName);
    //uppercace(szAppName);	

	tyflow_cmdline_printf(cl, "State: %s\r\n", pcStatus);
	tyflow_cmdline_printf(cl, "Application: %s\r\n", szAppName);

	/*
	uiRuleID = pstSessionInfo->uiRuleID;
	if(SECP_RULE_INVALID_INDEX == uiRuleID)
	{
		tyflow_cmdline_printf(cl, "Rule ID: -/-/-\r\n");
	}
	else
	{
		tyflow_cmdline_printf(cl, "Rule ID: %u\r\n", uiRuleID);
	}
	if(ERROR_SUCCESS == ulErrCode)
	{
		tyflow_cmdline_printf(cl, "Rule name: %s\r\n", szRuleName);
	}
	else
	{
		tyflow_cmdline_printf(cl, "Rule Name: \r\n");
	}
	*/

    stTime = (time_t)pstSessionInfo->ulStartTime;
	(VOID)localtime_r(&stTime, &stStartTime);
	(VOID)scnprintf(szDate,
		            (size_t)DATE_MAX_LENGTH,
		            "%d-%02d-%02d %02d:%02d:%02d",
		            stStartTime.tm_year+YEAR_BASED,
		            stStartTime.tm_mon+1,
		            stStartTime.tm_mday,
		            stStartTime.tm_hour,
		            stStartTime.tm_min,
		            stStartTime.tm_sec);
	tyflow_cmdline_printf(cl, "Start time:%s", szDate);

	if(SESSION_TIME_NO_AGING == pstSessionInfo->uiTTL)
	{
		tyflow_cmdline_printf(cl, " TTL: -\r\n");
	}
	else
	{
		tyflow_cmdline_printf(cl, " TTL: %us\r\n", pstSessionInfo->uiTTL);
	}

	tyflow_cmdline_printf(cl, "Initiator->Responder: %10u packets %10u bytes\r\n",
	       pstSessionInfo->auiPackets[SESSION_DIR_ORIGINAL],
	       pstSessionInfo->auiBytes[SESSION_DIR_ORIGINAL]);
	tyflow_cmdline_printf(cl, "Responder->Initiator: %10u packets %10u bytes\r\n",
       pstSessionInfo->auiPackets[SESSION_DIR_REPLY],
       pstSessionInfo->auiBytes[SESSION_DIR_REPLY]);

    return;
}

/* 获取会话详细信息 */
STATIC VOID  _session_ShowVerboseInfo(IN const SESSION_TABLE_INFO_S* pstSessionInfo)
{
	tyflow_cmdline_printf(cl, "Initiator:\r\n");
	_session_ShowBriefInfo(pstSessionInfo, SESSION_DIR_ORIGINAL);

	tyflow_cmdline_printf(cl, "Responder:\r\n");
	_session_ShowBriefInfo(pstSessionInfo, SESSION_DIR_REPLY);

	_session_ShowTableOtherInfo(pstSessionInfo);

	return;
}

static void _session_ShowTable(flow_connection_t *fcp, void *args, void *paras)
{
    cmd_blk_t *cbt = (cmd_blk_t *)args;
    SESSION_TABLE_INFO_S stSessionInfo;
    SESSION_S *pstSession = (SESSION_S *)fcp->fwsession;

    if (NULL == fcp->fwsession)
        return;

    cl = cbt->cl;

    stSessionInfo.uiAppID         = pstSession->uiAppID;
    stSessionInfo.ucState         = pstSession->ucState;
    stSessionInfo.ucSessProto     = pstSession->stSessionBase.ucSessionL4Type;
    stSessionInfo.ulStartTime     = pstSession->stSessionBase.uiSessCreateTime;
    stSessionInfo.uiTTL = _session_Kdump_GetTTL(pstSession);
    stSessionInfo.uiRuleID = 0; //TODO

    if (1 == cbt->which[sess_para_verbose]) {
        /* show session table ipv4 [src-ip x.x.x.x/x] [dst-ip x.x.x.x/x] [src-port x] [dst-port x] [protocol x] [vrf x] verbose
           show session table ipv6 [src-ipv6 x::x/x]  [dst-ipv6 x::x/x]  [src-port x] [dst-port x] [protocol x] [vrf x] verbose */
        SESSION_KGetTuple(&fcp->conn_sub0, &stSessionInfo.astTuple[SESSION_DIR_ORIGINAL]);
        stSessionInfo.auiPackets[SESSION_DIR_ORIGINAL] = (UINT)rte_atomic32_read(&(pstSession->_astPackets[SESSION_DIR_ORIGINAL]));
        stSessionInfo.auiBytes[SESSION_DIR_ORIGINAL] = (UINT)rte_atomic32_read(&(pstSession->_astBytes[SESSION_DIR_ORIGINAL]));
        SESSION_KGetTuple(&fcp->conn_sub1, &stSessionInfo.astTuple[SESSION_DIR_REPLY]);
        stSessionInfo.auiPackets[SESSION_DIR_REPLY] = (UINT)rte_atomic32_read(&(pstSession->_astPackets[SESSION_DIR_REPLY]));
        stSessionInfo.auiBytes[SESSION_DIR_REPLY] = (UINT)rte_atomic32_read(&(pstSession->_astBytes[SESSION_DIR_REPLY]));

        /*显示详细信息*/
        _session_ShowVerboseInfo(&stSessionInfo);
    } else if (1 == cbt->which[sess_para_responder]) {
        /* show session table ipv4 [src-ip x.x.x.x/x] [dst-ip x.x.x.x/x] [src-port x] [dst-port x] [protocol x] [vrf x] responder
           show session table ipv6 [src-ipv6 x::x/x]  [dst-ipv6 x::x/x]  [src-port x] [dst-port x] [protocol x] [vrf x] responder */
        SESSION_KGetTuple(&fcp->conn_sub1, &stSessionInfo.astTuple[SESSION_DIR_REPLY]);
        stSessionInfo.auiPackets[SESSION_DIR_REPLY] = (UINT)rte_atomic32_read(&(pstSession->_astPackets[SESSION_DIR_REPLY]));
        stSessionInfo.auiBytes[SESSION_DIR_REPLY] = (UINT)rte_atomic32_read(&(pstSession->_astBytes[SESSION_DIR_REPLY]));

        /*只显示反向的简要信息*/
        tyflow_cmdline_printf(cl, "Responder:\r\n");
        _session_ShowBriefInfo(&stSessionInfo, SESSION_DIR_REPLY);
    } else {
        /* show session table ipv4 [src-ip x.x.x.x/x] [dst-ip x.x.x.x/x] [src-port x] [dst-port x] [protocol x] [vrf x]
           show session table ipv6 [src-ipv6 x::x/x]  [dst-ipv6 x::x/x]  [src-port x] [dst-port x] [protocol x] [vrf x] */
        SESSION_KGetTuple(&fcp->conn_sub0, &stSessionInfo.astTuple[SESSION_DIR_ORIGINAL]);
        stSessionInfo.auiPackets[SESSION_DIR_ORIGINAL] = (UINT)rte_atomic32_read(&(pstSession->_astPackets[SESSION_DIR_ORIGINAL]));
        stSessionInfo.auiBytes[SESSION_DIR_ORIGINAL] = (UINT)rte_atomic32_read(&(pstSession->_astBytes[SESSION_DIR_ORIGINAL]));

        /*只显示正向的简要信息*/
        tyflow_cmdline_printf(cl, "Initiator:\r\n");
        _session_ShowBriefInfo(&stSessionInfo, SESSION_DIR_ORIGINAL);
    }

	tyflow_cmdline_printf(cl, "\r\n");
	return;
}

/* no parameters provided means ok, select it */
int 
select_this_connection_for_fwsession(flow_connection_t *fcp, void *args,
			           connection_op_para_t *paras)
{
	uint32_t mask;
	conn_sub_t *csp, *peer;
	struct in6_addr mask_v6;
	uint32_t mask_v4;
    cmd_blk_t *cbt = (cmd_blk_t *)args;
    SESSION_S *pstSession;

	if ((NULL == fcp) || (NULL == fcp->fwsession))
		return 0;

	csp = &(fcp->conn_sub0);
	if (csp->cspflag & CSP_ECHO_SIDE)
		csp = csp2peer(csp);
	peer = csp2peer(csp);

    if ((sess_t_show_v4 == cbt->which[sess_para_type]) && ((csp->cspflag & CSP_FLAG_IPV6) != 0))
        return 0;

    if ((sess_t_show_v6 == cbt->which[sess_para_type]) && ((csp->cspflag & CSP_FLAG_IPV6) == 0))
        return 0;

    pstSession = (SESSION_S *)fcp->fwsession;
    if ((cbt->which[sess_para_state] != 0) && 
        (cbt->which[sess_para_state] != L4_COMPOUND_STATE(pstSession->stSessionBase.ucSessionL4Type, pstSession->ucState)))
        return 0;

	if (paras == NULL || paras->mask == 0)
		return 1;

 	mask = paras->mask;

	if (mask & CLR_GET_CONN_SRCIP) {
        if (cbt->which[sess_para_sipv6] == 1) {
            FWLIB_IP6ADDR_Len2Mask(paras->src_mask, &mask_v6);
            if (BOOL_TRUE != FWLIB_IP6_COMPARE((struct in6_addr *)&paras->src_ip, (struct in6_addr *)&csp->csp_src_ip, (struct in6_addr *)&mask_v6))
                return 0;
        } else {
            FWLIB_IP4ADDR_Len2Mask(paras->src_mask, &mask_v4);
            if ((paras->src_ip & mask_v4) != (csp->csp_src_ip & mask_v4))
                return 0;
        }
    }

	if (mask & CLR_GET_CONN_DESIP) {
        if (cbt->which[sess_para_dipv6] == 1) {
            FWLIB_IP6ADDR_Len2Mask(paras->dst_mask, &mask_v6);
            if (BOOL_TRUE != FWLIB_IP6_COMPARE((struct in6_addr *)&paras->dst_ip, (struct in6_addr *)&csp->csp_dst_ip, (struct in6_addr *)&mask_v6))
                return 0;
        } else {
            FWLIB_IP4ADDR_Len2Mask(paras->dst_mask, &mask_v4);
            if ((paras->dst_ip & mask_v4) != (csp->csp_dst_ip & mask_v4))
                return 0;
        }
    }

    if (mask & CLR_GET_CONN_SRCPORT_LOW) {
		if (paras->srcport_low != ntohs(csp->csp_src_port))
			return 0;
	}

    if (mask & CLR_GET_CONN_DESPORT_LOW){
		if (paras->dstport_low != ntohs(csp->csp_dst_port))
            return 0;
    }

    if (mask & CLR_GET_CONN_PROTOCOL_LOW) {
        if (paras->protocol_low != pstSession->stSessionBase.ucSessionL4Type)
            return 0;
    }

    if (mask & CLR_GET_CONN_VRF_ID) {
		if (paras->vrf_id != csp->csp_token && 
			paras->vrf_id != peer->csp_token) 
            return 0;
    }

	return 1; /* select this connection */
}

static int
_try_reschedule(void)
{
    return 0;
}

static int
page_stop(void)
{
    return 0;
}

/*
 * walk through all connections with given select condition,
 * call passed vector for each connection that matches the conditions.
 * return the number of matched connnections.
 */
static int 
traverse_all_session(connection_op_para_t *paras, void *args,
	                         selected_session_vector_t vector)
{
	int total;
	int i, cnt;
	flow_connection_t *fcp;

	total = rte_atomic32_read(&this_flow_curr_conn); //forcompile flow_get_total_connection();
    cnt = 0;
	for (i = 1; (i < FLOW_CONN_MAX_NUMBER) && (cnt < total); i++) {
		fcp = this_flowConnTable + i;
        fcp_rwl_read_lock(fcp);
		if (is_fcp_valid(fcp)) {
            fcp_rwl_read_unlock(fcp);
			if (select_this_connection_for_fwsession(fcp, args, paras)) {
				cnt++;
				if (vector) {
					(*vector)(fcp, args, paras);
				}
				
				/*	to prevent hold cpu too long */
				if ((cnt & 0x3f) ==0)
					_try_reschedule();
				
                /* we may need to page the output */
				if (page_stop())
					goto done;
			}
		} else {
            fcp_rwl_read_unlock(fcp);
        }
        /*	to prevent hold cpu too long */
		if ((i & 0xffff) == 0)
			_try_reschedule();
	}
done:
	return cnt;
}

/*
 * show all local fw sessions, return count.
 * we need to filter them if required.
 */
static int
show_sess_proc(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
    show_flow_ctx_t *ctx = (show_flow_ctx_t *)msg_hdr;
    SESSION_TABLE_KEY_S stKey;

    assert(msg_hdr->length == sizeof(show_flow_ctx_t));

    tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt, "  lcore%d:\n", rte_lcore_id());
    if (!rte_atomic32_read(&this_flow_status)) {
        tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt,
                              "    flow is not ready yet\n");
        goto out;
    }

    switch(msg_hdr->subtype) {
        case SESS_CMD_MSG_SUBTYPE_SHOW:
            /* traverse all connections. */
            msg_hdr->rc = traverse_all_session(&ctx->paras, msg_hdr->cbt, _session_ShowTable);
            tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt, "  sessions on lcore%d: %d\n", 
                rte_lcore_id(), msg_hdr->rc);
            break;

        case SESS_CMD_MSG_SUBTYPE_CLEAR:
            memset(&stKey, 0, sizeof(SESSION_TABLE_KEY_S));

            switch (((cmd_blk_t *)msg_hdr->cbt)->which[sess_para_type]) {
                case sess_t_clear_table_all:
                    /* clear session table */
                    /* 传入ucL3Family为AF_MAX将ipv4 ipv6会话一起删除 */
                    stKey.stTuple.ucL3Family = AF_MAX;
                    break;
                case sess_t_clear_table_v4:
                    /* clear session table ipv4 [src-ip x.x.x.x/x] [dst-ip x.x.x.x/x] [src-port x] [dst-port x] [protocol x] [vrf x] */
                    stKey.stTuple.ucL3Family = AF_INET;
                    if (ctx->paras.mask & CLR_GET_CONN_SRCIP) {
                        stKey.stTuple.unL3Src.uiIp = ctx->paras.src_ip;
                        SESSION_KEY_SET_SRCIP(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_SRCPORT_LOW) {
                        stKey.stTuple.unL4Src.usAll = ctx->paras.srcport_low;
                        SESSION_KEY_SET_SRCPORT(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_DESIP) {
                        stKey.stTuple.unL3Dst.uiIp = ctx->paras.dst_ip;
                        SESSION_KEY_SET_DSTIP(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_DESPORT_LOW) {
                        stKey.stTuple.unL4Dst.usAll = ctx->paras.dstport_low;
                        SESSION_KEY_SET_DSTORT(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_PROTOCOL_LOW) {
                        stKey.ucSessType = ctx->paras.protocol_low;
                        SESSION_KEY_SET_PROT(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_VRF_ID) {
                        stKey.stTuple.vrfIndex = ctx->paras.vrf_id;
                        SESSION_KEY_SET_VPNID(stKey.uiMask);
                    }

                    break;
                case sess_t_clear_table_v6:
                    /* clear session table ipv6 [src-ipv6 x::x/x]  [dst-ipv6 x::x/x]  [src-port x] [dst-port x] [protocol x] [vrf x] */
                    stKey.stTuple.ucL3Family = AF_INET6;
                    if (ctx->paras.mask & CLR_GET_CONN_SRCIP) {
                        memcpy(stKey.stTuple.unL3Src.auiIp6, &ctx->paras.src_ip, sizeof(stKey.stTuple.unL3Src.auiIp6));
                        SESSION_KEY_SET_SRCIP(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_SRCPORT_LOW) {
                        stKey.stTuple.unL4Src.usAll = ctx->paras.srcport_low;
                        SESSION_KEY_SET_SRCPORT(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_DESIP) {
                        memcpy(stKey.stTuple.unL3Dst.auiIp6, &ctx->paras.dst_ip, sizeof(stKey.stTuple.unL3Dst.auiIp6));
                        SESSION_KEY_SET_DSTIP(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_DESPORT_LOW) {
                        stKey.stTuple.unL4Dst.usAll = ctx->paras.dstport_low;
                        SESSION_KEY_SET_DSTORT(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_PROTOCOL_LOW) {
                        stKey.ucSessType = ctx->paras.protocol_low;
                        SESSION_KEY_SET_PROT(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_VRF_ID) {
                        stKey.stTuple.vrfIndex = ctx->paras.vrf_id;
                        SESSION_KEY_SET_VPNID(stKey.uiMask);
                    }

                    break;
                default:
                    tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt, 
                                  "  unsupport operation\n");
                    goto out;
            }

            SESSION_KReset(&stKey);
            break;
        default:
            tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt, 
                                  "  unsupport operation\n");
            break;
   }

out:
    return msg_hdr->rc;
}

static int
show_sess_echo_proc(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
    uint32_t *sess_cnt = (uint32_t *)cookie;

    assert(msg_hdr->type == CMD_MSG_SESS);

    if (SESS_CMD_MSG_SUBTYPE_SHOW == msg_hdr->subtype)
        *sess_cnt += msg_hdr->rc;

    return 0;
}

static void
sess_parse_para(cmd_blk_t *cbt, connection_op_para_t *paras)
{
    char *pc;
    char *str;

    /* src-ipv6 x::x/x */
    if (cbt->which[sess_para_sipv6] == 1) {
        str = cbt->string[sess_strid_sipv6];
        if (FWLIB_Check_IPv6AndPrefix_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_SRCIP;
            if (strchr(str, '/')) {
                /* example, 1::2/64 */
                pc = strtok(str, "/");
                inet_pton(AF_INET6, pc, &paras->src_ip);
                pc = strtok(NULL, "/");
                paras->src_mask = atoi(pc);
            }
            else {
                /* example, 1::2 */
                inet_pton(AF_INET6, str, &paras->src_ip);
                paras->src_mask = 128;
            }
        }
    }

    /* dst-ipv6 x::x/x */
    if (cbt->which[sess_para_dipv6] == 1) {
        str = cbt->string[sess_strid_dipv6];
        if (FWLIB_Check_IPv6AndPrefix_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_DESIP;
            if (strchr(str, '/')) {
                /* example, 1::2/64 */
                pc = strtok(str, "/");
                inet_pton(AF_INET6, pc, &paras->dst_ip);
                pc = strtok(NULL, "/");
                paras->dst_mask = atoi(pc);
            }
            else {
                /* example, 1::2 */
                inet_pton(AF_INET6, str, &paras->dst_ip);
                paras->dst_mask = 128;
            }
        }
    }

    /* src-ip x.x.x.x/x */
    if (cbt->which[sess_para_sip] == 1) {
        str = cbt->string[sess_strid_sip];
        if (FWLIB_Check_IPv4AndMask_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_SRCIP;
            if (strchr(str, '/')) {
                /* example, 1.1.1.1/24 */
                pc = strtok(str, "/");
                inet_pton(AF_INET, pc, &paras->src_ip);
                pc = strtok(NULL, "/");
                paras->src_mask = atoi(pc);
            }
            else {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, str, &paras->src_ip);
                paras->src_mask = 32;
            }
        }
    }

    /* dst-ip x.x.x.x/x */
    if (cbt->which[sess_para_dip] == 1) {
        str = cbt->string[sess_strid_dip];
        if (FWLIB_Check_IPv4AndMask_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_DESIP;
            if (strchr(str, '/')) {
                /* example, 1.1.1.1/24 */
                pc = strtok(str, "/");
                inet_pton(AF_INET, pc, &paras->dst_ip);
                pc = strtok(NULL, "/");
                paras->dst_mask = atoi(pc);
            }
            else {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, str, &paras->dst_ip);
                paras->dst_mask = 32;
            }
        }
    }

    /* src-port */
    if (cbt->which[sess_para_sport] == 1) {
        paras->srcport_low = cbt->number[sess_numid_sport];
        paras->mask |= CLR_GET_CONN_SRCPORT_LOW;
    }

    /* dst-port */
    if (cbt->which[sess_para_dport] == 1) {
        paras->dstport_low = cbt->number[sess_numid_dport];
        paras->mask |= CLR_GET_CONN_DESPORT_LOW;
    }

    /* protocol */
    if (cbt->which[sess_para_proto] != 0) {
        paras->protocol_low = cbt->which[sess_para_proto] - 1;
        paras->mask |= CLR_GET_CONN_PROTOCOL_LOW;
    }

    /* vrf */
    if (cbt->which[sess_para_vrf] == 1) {
        paras->vrf_id = cbt->number[sess_numid_vrf];
        paras->mask |= CLR_GET_CONN_VRF_ID;
    }

    return;
}

static int show_session_debug(cmd_blk_t *cbt)
{	
	SESSION_CTRL_S *pstSessionCtrl;	
	UINT uiDbgSwitch;

	pstSessionCtrl = SESSION_CtrlData_Get();
	uiDbgSwitch = pstSessionCtrl->stDebug.uiDbgSwitch; 

    tyflow_cmdline_printf(cbt->cl, "session status:\n");
    tyflow_cmdline_printf(cbt->cl, "\tdebug:\n");
    if (0 == uiDbgSwitch) {
        tyflow_cmdline_printf(cbt->cl, "\t\tnone.\n");
    } 
	else {
        if (0 != (uiDbgSwitch & SESSION_DEBUG_SWITCH_EVENT)) {
            tyflow_cmdline_printf(cbt->cl, "\t\tevent enabled.\n");
        }
    }

    return 0;
}

static int
show_clear_sess_cli(cmd_blk_t *cbt)
{
    show_flow_ctx_t flow_ctx;
    connection_op_para_t *paras;
    SESSION_STAT_FAIL_TYPE_E enType;
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();

    cl = cbt->cl;
    sess_cnt = 0;

    flow_ctx.msg_hdr.type = CMD_MSG_SESS;
    flow_ctx.msg_hdr.length = sizeof(show_flow_ctx_t);
    flow_ctx.msg_hdr.rc = 0;
    flow_ctx.msg_hdr.cbt = cbt;
    paras = &flow_ctx.paras;
    memset(paras, 0, sizeof(connection_op_para_t));
    sess_parse_para(cbt, paras);
    
    switch(cbt->which[sess_para_type]) {
        case sess_t_show_stat:  /* show session statistics */
            _cfg_SessionDisStatisticsSummary(BOOL_FALSE);
            break;
        case sess_t_show_stat_full:  /* show session statistics full */
            _cfg_SessionDisStatisticsSummary(BOOL_TRUE);
            break;
        case sess_t_show_dbg_status:  /* show session debug status */
            show_session_debug(cbt);
            break;
        case sess_t_show_other:  /* show session other */
            Session_Print_Status(cl);
            break;
        case sess_t_show_v4:  /* show session table ipv4 [...] */
        case sess_t_show_v6:  /* show session table ipv6 [...] */
            flow_ctx.msg_hdr.subtype = SESS_CMD_MSG_SUBTYPE_SHOW;
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);
            tyflow_cmdline_printf(cbt->cl, "total session: %d\r\n", sess_cnt);
            tyflow_cmdline_printf(cbt->cl, "\r\n");
            break;
        case sess_t_clear_stat: /* clear session statistics */
            for (enType = SESSION_STAT_FAIL_CREATE_CACHE_NULL; enType < SESSION_STAT_FAIL_TYPE_MAX; enType++) {
                rte_atomic32_set(&pstSessionCtrl->astStatFailCnt[SESSION_STAT_IPV4][enType], 0);
            }
            
            memset(pstSessionCtrl->stSessStat.pstVcpuStat, 0, 
                sizeof(SESSION_STAT_VCPU_S)*worker_thread_total());

            tyflow_cmdline_printf(cbt->cl, "session statistics reset\r\n");
            
            break;
        case sess_t_clear_table_all: /* clear session table */
        case sess_t_clear_table_v4: /* clear session table ipv4 [...] */
        case sess_t_clear_table_v6: /* clear session table ipv6 [...] */
            flow_ctx.msg_hdr.subtype = SESS_CMD_MSG_SUBTYPE_CLEAR;
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);

            tyflow_cmdline_printf(cbt->cl, "all related sessions deleted\r\n");

            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            break;
    }
    return 0;
}

/*
    show session
    		   |
    		   |___ table
    		            |
    		            |___ ipv4 [src-ip x.x.x.x[/x]] [dst-ip x.x.x.x[/x]] [protocol icmp|...]   [src-port x] [dst-port x] [vrf x] [state icmp-request|...]   [responder|verbose]
                        |___ ipv6 [src-ipv6 x::x[/x]]  [dst-ip x::x[/x]]    [protocol icmpv6|...] [src-port x] [dst-port x] [vrf x] [state icmpv6-request|...] [responder|verbose]
                        |___ debug status
                        |___ statistics [full]
                        |___ other

    clear session
                |
                |___ table
                         |___                //default to clear all sessions
                         |___ ipv4 [src-ip x.x.x.x[/x]] [dst-ip x.x.x.x[/x]] [protocol icmp|...]   [src-port x] [dst-port x] [vrf x]
                         |___ ipv6 [src-ipv6 x::x[/x]]  [dst-ipv6 x::x[/x]]  [protocol icmpv6|...] [src-port x] [dst-port x] [vrf x]
                         |___ statistics

    set
      |
      |___ session
      |          |
      |          |___ aging-time state {fin|...} x
      |          |___ log enable
      |          |___ statistics enable
      |
      |___ security {enable|disable}

    unset
        |
        |___ session
        |         |
        |         |___ aging-time state
        |         |___ log enable
        |         |___ statistics enable
        |
        |___ security enable
*/

EOL_NODE(show_clear_sess_eol, show_clear_sess_cli);

/* verbose */
KW_NODE_WHICH(sess_table_verbose, show_clear_sess_eol, show_clear_sess_eol, "verbose", "verbose", sess_para_verbose+1, 1);
/* responder */
KW_NODE_WHICH(sess_table_responder, show_clear_sess_eol, sess_table_verbose, "responder", "responder", sess_para_responder+1, 1);
/* state "tcp-est|tcp-syn-sent|..." */
KW_NODE_WHICH(sess_table_state_udp_ready, sess_table_responder, none, "udp-ready", "udp-ready", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_UDP, UDP_ST_READY));
KW_NODE_WHICH(sess_table_state_udp_open, sess_table_responder, sess_table_state_udp_ready, "udp-open", "udp open", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_UDP, UDP_ST_OPEN));
KW_NODE_WHICH(sess_table_state_tcp_time_wait, sess_table_responder, sess_table_state_udp_open, "tcp-time-wait", "tcp time wait", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_TIME_WAIT));
KW_NODE_WHICH(sess_table_state_tcp_syn_sent2, sess_table_responder, sess_table_state_tcp_time_wait, "tcp-syn-sent2", "tcp syn sent2", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_SYN_SENT2));
KW_NODE_WHICH(sess_table_state_tcp_syn_sent, sess_table_responder, sess_table_state_tcp_syn_sent2, "tcp-syn-sent", "tcp syn sent", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_SYN_SENT));
KW_NODE_WHICH(sess_table_state_tcp_syn_recv, sess_table_responder, sess_table_state_tcp_syn_sent, "tcp-syn-recv", "tcp syn recv", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_SYN_RECV));
KW_NODE_WHICH(sess_table_state_tcp_last_ack, sess_table_responder, sess_table_state_tcp_syn_recv, "tcp-last-ack", "tcp last ack", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_LAST_ACK));
KW_NODE_WHICH(sess_table_state_tcp_fin_wait, sess_table_responder, sess_table_state_tcp_last_ack, "tcp-fin-wait", "tcp fin wait", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_FIN_WAIT));
KW_NODE_WHICH(sess_table_state_tcp_est, sess_table_responder, sess_table_state_tcp_fin_wait, "tcp-est", "tcp est", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_ESTABLISHED));
KW_NODE_WHICH(sess_table_state_tcp_close_wait, sess_table_responder, sess_table_state_tcp_est, "tcp-close-wait", "tcp close wait", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_CLOSE_WAIT));
KW_NODE_WHICH(sess_table_state_tcp_close, sess_table_responder, sess_table_state_tcp_close_wait, "tcp-close", "tcp close", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_TCP, TCP_ST_CLOSE));
KW_NODE_WHICH(sess_table_state_rawip_ready, sess_table_responder, sess_table_state_tcp_close, "rawip-ready", "rawip ready", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_RAWIP, RAWIP_ST_READY));
KW_NODE_WHICH(sess_table_state_rawip_open, sess_table_responder, sess_table_state_rawip_ready, "rawip-open", "rawip open", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_RAWIP, RAWIP_ST_OPEN));
KW_NODE_WHICH(sess_table_state_icmp_request, sess_table_responder, sess_table_state_rawip_open, "icmp-request", "icmp request", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_ICMP, ICMP_ST_REQUEST));
KW_NODE_WHICH(sess_table_state_icmp_reply, sess_table_responder, sess_table_state_icmp_request, "icmp-reply", "icmp reply", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_ICMP, ICMP_ST_REPLY));
KW_NODE_WHICH(sess_table_state_icmpv6_request, sess_table_responder, sess_table_state_icmp_reply, "icmpv6-request", "icmpv6 request", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_ICMPV6, ICMP_ST_REQUEST));
KW_NODE_WHICH(sess_table_state_icmpv6_reply, sess_table_responder, sess_table_state_icmpv6_request, "icmpv6-reply", "icmpv6 reply", 
    sess_para_state+1, L4_COMPOUND_STATE(SESSION_L4_TYPE_ICMPV6, ICMP_ST_REPLY));
KW_NODE(sess_table_state, sess_table_state_icmpv6_reply, sess_table_responder, "state", "l4 state");
/* vrf <vrf-id> */
VALUE_NODE(sess_table_vrf_val, sess_table_state, none, "vrf id", sess_numid_vrf+1, NUM);
KW_NODE_WHICH(sess_table_vrf, sess_table_vrf_val, sess_table_state, "vrf", "vrf", sess_para_vrf+1, 1);
/* dst-port <dport> */
VALUE_NODE(sess_table_dport_val, sess_table_vrf, none, "dest port number", sess_numid_dport+1, NUM);
KW_NODE_WHICH(sess_table_dport, sess_table_dport_val, sess_table_vrf, "dst-port", "dest port", sess_para_dport+1, 1);
/* src-port <sport> */
VALUE_NODE(sess_table_sport_val, sess_table_dport, none, "source port number", sess_numid_sport+1, NUM);
KW_NODE_WHICH(sess_table_sport, sess_table_sport_val, sess_table_dport, "src-port", "source port", sess_para_sport+1, 1);
/* protocol "icmp|tcp|..." */
KW_NODE_WHICH(sess_table_proto_rawip, sess_table_sport, none, "raw-ip", "raw-ip", sess_para_proto+1, SESSION_L4_TYPE_RAWIP+1);
KW_NODE_WHICH(sess_table_proto_udp, sess_table_sport, sess_table_proto_rawip, "udp", "udp", sess_para_proto+1, SESSION_L4_TYPE_UDP+1);
KW_NODE_WHICH(sess_table_proto_tcp, sess_table_sport, sess_table_proto_udp, "tcp", "tcp", sess_para_proto+1, SESSION_L4_TYPE_TCP+1);
KW_NODE_WHICH(sess_table_proto_icmp, sess_table_sport, sess_table_proto_tcp, "icmp", "icmp", sess_para_proto+1, SESSION_L4_TYPE_ICMP+1);
KW_NODE_WHICH(sess_table_proto_icmpv6, sess_table_sport, sess_table_proto_tcp, "icmpv6", "icmpv6", sess_para_proto+1, SESSION_L4_TYPE_ICMPV6+1);
KW_NODE(sess_table_proto, sess_table_proto_icmp, sess_table_sport, "protocol", "L4 protocol");
KW_NODE(sess_table_protov6, sess_table_proto_icmpv6, sess_table_sport, "protocol", "L4 protocol");
/* dst-ip x.x.x.x/x */
VALUE_NODE(sess_table_dip_val, sess_table_proto, none, "ipv4 address: x.x.x.x[/x]", sess_strid_dip+1, STR);
KW_NODE_WHICH(sess_table_dip, sess_table_dip_val, sess_table_proto, "dst-ip", "dest ip address", sess_para_dip+1, 1);
/* src-ip x.x.x.x/x */
VALUE_NODE(sess_table_sip_val, sess_table_dip, none, "ipv4 address: x.x.x.x[/x]", sess_strid_sip+1, STR);
KW_NODE_WHICH(sess_table_sip, sess_table_sip_val, sess_table_dip, "src-ip", "source ip address", sess_para_sip+1, 1);
/* dst-ipv6 x::x/x */
VALUE_NODE(sess_table_dipv6_val, sess_table_protov6, none, "ipv6 address: x::x[/x]", sess_strid_dipv6+1, STR);
KW_NODE_WHICH(sess_table_dipv6, sess_table_dipv6_val, sess_table_protov6, "dst-ipv6", "dest ipv6 address", sess_para_dipv6+1, 1);
/* src-ipv6 x::x/x */
VALUE_NODE(sess_table_sipv6_val, sess_table_dipv6, none, "ipv6 address: x::x[/x]", sess_strid_sipv6+1, STR);
KW_NODE_WHICH(sess_table_sipv6, sess_table_sipv6_val, sess_table_dipv6, "src-ipv6", "source ipv6 address", sess_para_sipv6+1, 1);
/* show session table ipv6 [src-ipv6 x::x/x]  [dst-ipv6 x::x/x]  [protocol x] [src-port x] [dst-port x] [vrf x] [state x] [responder|verbose] */
KW_NODE_WHICH(show_sess_table_v6, sess_table_sipv6, none, "ipv6", "show session table of ipv6", sess_para_type+1, sess_t_show_v6);
/* show session table ipv4 [src-ip x.x.x.x/x] [dst-ip x.x.x.x/x] [protocol x] [src-port x] [dst-port x] [vrf x] [state x] [responder|verbose] */
KW_NODE_WHICH(show_sess_table_v4, sess_table_sip, show_sess_table_v6, "ipv4", "show session table of ipv4", sess_para_type+1, sess_t_show_v4);
KW_NODE(show_sess_table, show_sess_table_v4, none, "table", "show session table");
/* show session other */
KW_NODE_WHICH(show_sess_other, show_clear_sess_eol, show_sess_table, "other", "show session other info", sess_para_type+1, sess_t_show_other);
/* show session debug status */
KW_NODE_WHICH(show_sess_status, show_clear_sess_eol, none, "status", "show session debug status", sess_para_type+1, sess_t_show_dbg_status);
KW_NODE(show_sess_debug, show_sess_status, show_sess_other, "debug", "show session debug");
/* show session statistics [full] */
KW_NODE_WHICH(show_sess_statistics_full, show_clear_sess_eol, show_clear_sess_eol, "full", "show full statistics", sess_para_type+1, sess_t_show_stat_full);
KW_NODE_WHICH(show_sess_statistics, show_sess_statistics_full, show_sess_debug, "statistics", "show session statistics", sess_para_type+1, sess_t_show_stat);
KW_NODE(show_sess, show_sess_statistics, none, "session", "show session table/statistics");

/* vrf <vrf-id> */
VALUE_NODE(clear_sess_table_vrf_val, show_clear_sess_eol, show_clear_sess_eol, "vrf id", sess_numid_vrf+1, NUM);
KW_NODE_WHICH(clear_sess_table_vrf, clear_sess_table_vrf_val, show_clear_sess_eol, "vrf", "vrf", sess_para_vrf+1, 1);
/* dst-port <dport> */
VALUE_NODE(clear_sess_table_dport_val, clear_sess_table_vrf, none, "dest port number", sess_numid_dport+1, NUM);
KW_NODE_WHICH(clear_sess_table_dport, clear_sess_table_dport_val, clear_sess_table_vrf, "dst-port", "dest port", sess_para_dport+1, 1);
/* src-port <sport> */
VALUE_NODE(clear_sess_table_sport_val, clear_sess_table_dport, none, "source port number", sess_numid_sport+1, NUM);
KW_NODE_WHICH(clear_sess_table_sport, clear_sess_table_sport_val, clear_sess_table_dport, "src-port", "source port", sess_para_sport+1, 1);
/* protocol <proto> */
KW_NODE_WHICH(clear_sess_table_proto_rawip, clear_sess_table_sport, none, "raw-ip", "raw-ip", sess_para_proto+1, SESSION_L4_TYPE_RAWIP+1);
KW_NODE_WHICH(clear_sess_table_proto_udp, clear_sess_table_sport, clear_sess_table_proto_rawip, "udp", "udp", sess_para_proto+1, SESSION_L4_TYPE_UDP+1);
KW_NODE_WHICH(clear_sess_table_proto_tcp, clear_sess_table_sport, clear_sess_table_proto_udp, "tcp", "tcp", sess_para_proto+1, SESSION_L4_TYPE_TCP+1);
KW_NODE_WHICH(clear_sess_table_proto_icmp, clear_sess_table_sport, clear_sess_table_proto_tcp, "icmp", "icmp", sess_para_proto+1, SESSION_L4_TYPE_ICMP+1);
KW_NODE_WHICH(clear_sess_table_proto_icmpv6, clear_sess_table_sport, clear_sess_table_proto_tcp, "icmpv6", "icmpv6", sess_para_proto+1, SESSION_L4_TYPE_ICMPV6+1);
KW_NODE(clear_sess_table_proto, clear_sess_table_proto_icmp, clear_sess_table_sport, "protocol", "L4 protocol");
KW_NODE(clear_sess_table_protov6, clear_sess_table_proto_icmpv6, clear_sess_table_sport, "protocol", "L4 protocol");
/* dst-ip x.x.x.x */
VALUE_NODE(clear_sess_table_dip_val, clear_sess_table_proto, none, "ipv4 address: x.x.x.x", sess_strid_dip+1, STR);
KW_NODE_WHICH(clear_sess_table_dip, clear_sess_table_dip_val, clear_sess_table_proto, "dst-ip", "dest ip address", sess_para_dip+1, 1);
/* src-ip x.x.x.x */
VALUE_NODE(clear_sess_table_sip_val, clear_sess_table_dip, none, "ipv4 address: x.x.x.x", sess_strid_sip+1, STR);
KW_NODE_WHICH(clear_sess_table_sip, clear_sess_table_sip_val, clear_sess_table_dip, "src-ip", "source ip address", sess_para_sip+1, 1);
/* dst-ipv6 x::x */
VALUE_NODE(clear_sess_table_dipv6_val, clear_sess_table_protov6, none, "ipv6 address: x::x", sess_strid_dipv6+1, STR);
KW_NODE_WHICH(clear_sess_table_dipv6, clear_sess_table_dipv6_val, clear_sess_table_protov6, "dst-ipv6", "dest ipv6 address", sess_para_dipv6+1, 1);
/* src-ipv6 x::x */
VALUE_NODE(clear_sess_table_sipv6_val, clear_sess_table_dipv6, none, "ipv6 address: x::x", sess_strid_sipv6+1, STR);
KW_NODE_WHICH(clear_sess_table_sipv6, clear_sess_table_sipv6_val, clear_sess_table_dipv6, "src-ipv6", "source ipv6 address", sess_para_sipv6+1, 1);
/* clear session table ipv6 [src-ipv6 x::x/x]  [dst-ipv6 x::x/x]  [protocol x] [src-port x] [dst-port x] [vrf x] */
KW_NODE_WHICH(clear_sess_table_v6, clear_sess_table_sipv6, show_clear_sess_eol, "ipv6", "clear session table of ipv6", sess_para_type+1, sess_t_clear_table_v6);
/* clear session table ipv4 [src-ip x.x.x.x/x] [dst-ip x.x.x.x/x] [protocol x] [src-port x] [dst-port x] [vrf x] */
KW_NODE_WHICH(clear_sess_table_v4, clear_sess_table_sip, clear_sess_table_v6, "ipv4", "clear session table of ipv4", sess_para_type+1, sess_t_clear_table_v4);
/* clear session table */
KW_NODE_WHICH(clear_sess_table, clear_sess_table_v4, none, "table", "clear session table", sess_para_type+1, sess_t_clear_table_all);
/* clear session statistics */
KW_NODE_WHICH(clear_sess_statistics, show_clear_sess_eol, clear_sess_table, "statistics", "clear session statistics", sess_para_type+1, sess_t_clear_stat);
KW_NODE(clear_sess, clear_sess_statistics, none, "session", "clear session table/statistics");


static int debug_session_table_cli(cmd_blk_t *cbt)
{		
	SESSION_CTRL_S *pstSessionCtrl;	

    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

	pstSessionCtrl = SESSION_CtrlData_Get();

    if (cbt->mode & MODE_DO) {
	    if (0 == (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_SWITCH_EVENT)) {
	        printf("session event debug is enabled\n");
	        pstSessionCtrl->stDebug.uiDbgSwitch |= SESSION_DEBUG_SWITCH_EVENT;
	    }
    } 
	else if (cbt->mode & MODE_UNDO) {
	    if (0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_SWITCH_EVENT)) {
	        printf("session event debug is disabled\n");
	        pstSessionCtrl->stDebug.uiDbgSwitch &= ~SESSION_DEBUG_SWITCH_EVENT;
	    }
	}
	
    return 0;
}

static int debug_session_relation_cli(cmd_blk_t *cbt)
{		
	SESSION_CTRL_S *pstSessionCtrl;	

    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

	pstSessionCtrl = SESSION_CtrlData_Get();

    if (cbt->mode & MODE_DO) 
	{
	    if (0 == (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_RELATION_EVENT))
	    {
	        printf("session event debug is enabled\n");
	        pstSessionCtrl->stDebug.uiDbgSwitch |= SESSION_DEBUG_RELATION_EVENT;
	    }
    } 
	else if (cbt->mode & MODE_UNDO) 
	{
	    if (0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_RELATION_EVENT)) 
		{
	        printf("session event debug is disabled\n");
	        pstSessionCtrl->stDebug.uiDbgSwitch &= ~SESSION_DEBUG_RELATION_EVENT;
	    }
	}
	
    return 0;
}

EOL_NODE(debug_session_relation_eol, debug_session_relation_cli);

KW_NODE(session_relation_event, debug_session_relation_eol, none, "event", "enable/disable session relation evnet debug");

KW_NODE(session_relation, session_relation_event, none, "relation", "enable/disable session relation debug");

EOL_NODE(debug_session_table_eol, debug_session_table_cli);

KW_NODE(session_table_event, debug_session_table_eol, none, "event", "enable/disable session table evnet debug");

KW_NODE(session_table, session_table_event, session_relation, "table", "enable/disable session table debug");


KW_NODE(debug_session, session_table, none, "session", "enable/disable session related debug");


int
sess_cli_init(void)
{	
    add_debug_cmd(&cnode(debug_session));
    add_get_cmd(&cnode(show_sess));
    add_clear_cmd(&cnode(clear_sess));
    return cmd_msg_handler_register(CMD_MSG_SESS,
                                    show_sess_proc,
                                    show_sess_echo_proc,
                                    &sess_cnt);
}

#if 0
STATIC VOID _session_ShowRelationTableOtherInfo(IN SESSION_RELATION_INFOALL_S* pstRelationInfo, IN UINT uiL3Family)
{
	ULONG ulErrCode;
	CHAR szProtName[APR_PROTO_NAME_MAX_LEN+1];
    CHAR szDstIPV4[INET_ADDRSTRLEN];
	CHAR szDstIPV6[INET6_ADDRSTRLEN];

	printf("  Tuple mask:        %-20u    Tuple LockIndex: %u\r\n",
		      pstRelationInfo->uiMask, pstRelationInfo->usTupLockIndex);

    printf("  Local LockIndex:   %-20u    uiRelationFlag: %#-x\r\n",
		      pstRelationInfo->usLocalLockIndex, pstRelationInfo->uiRelationFlag);
	
	printf("  Expect ChildDir:   %-20u    Class:            %-u\r\n",
		      pstRelationInfo->enChildDir,pstRelationInfo->uiClass);
	
	printf("  AgingType:    %-u\r\n", pstRelationInfo->uiAgingType);

	printf("  bCareParentFlag: %-20u    uiUpdateTime:    %-u\r\n",
		      pstRelationInfo->bCareParentFlag, pstRelationInfo->uiUpdateTime);

	printf(" pstParen:         %-20p    pstSelfRelation: %-p\r\n",
		     (VOID *)(ULONG)pstRelationInfo->uiParentPtr, (VOID *)(ULONG)pstRelationInfo->uiSelfRelationPtr);

    printf(" ID:               %-20lu\r\n", pstRelationInfo->ulId);


	return;	
}

STATIC ULONG _session_ShowRelationInfo(IN SESSION_RELATION_INFOALL_S *pstRelationInfo)
{
	SESSION_TUPLE_S* pstTuple;

	pstTuple = &(pstRelationInfo->stTuple);

	UINT uiL3Famiy = (INT)pstTuple->ucL3Family;

	if(AF_INET == uiL3Famiy)
	{
		_session_ShowRelationTableIpv4(pstTuple);
	}
	else
	{
		_session_ShowRelationTableIpv6(pstTuple);
	}

	_session_ShowRelationTable_PortAndVpnInfo(pstTuple, pstRelationInfo->uiAddID, pstRelationInfo->uiTTL);
	
	/*_session_ShowRelationTableOtherInfo(pstRelationInfo, uiL3Famiy);*/

	return ERROR_SUCCESS;
}

STATIC BOOL_T _session_KDump_RelationKeyCmp(IN RELATION_S *pstRelation,
                                            IN const SESSION_RELATIONINFO_KEY_S *pstKey)
{
	csp_key_t *pstIPfsKey;
	UINT uiMask;

	if(NULL == pstKey)
	{
		return BOOL_FALSE;
	}

	pstIPfsKey = &pstRelation->stTupleHash.stIpfsKey;

	/* DELETE标记、MDC检查 */
	if(RELATION_IS_DELETING(pstRelation))
	{
		return BOOL_FALSE;
	}

	uiMask = pstKey->uiMask;

	/* 源地址检查 */
	if(SESSION_KEY_IS_SRCIPSET(uiMask))
	{
		if(ntohl(pstIPfsKey->src_ip) != pstKey->unL3Src.uiIp)
		{
			return BOOL_FALSE;
		}
	}

	/* 目的地址检查 */
	if(SESSION_KEY_IS_DSTIPSET(uiMask))
	{
		if(ntohl(pstIPfsKey->dst_ip) != pstKey->unL3Des.uiIp)
		{
			return BOOL_FALSE;
		}
	}

	return BOOL_TRUE;
}
											
STATIC VOID _session_KDump_RelationInfoCmpAndFill(IN RELATION_S *pstRelation,
                                                  IN const SESSION_RELATIONINFO_KEY_S *pstKey,
                                                  INOUT UINT *puiCount,
                                                  OUT SESSION_RELATION_INFOALL_S *pstGetInfo)
{
	if(BOOL_TRUE != _session_KDump_RelationKeyCmp(pstRelation, pstKey))
	{
		return ;
	}
	_session_ShowRelationTableIpv4(pstRelation);
	_session_ShowRelationTable_PortAndVpnInfo(pstRelation);

	*puiCount += 1;

	return ;
}

STATIC BOOL_T _session6_KDump_RelationKeyCmp(IN RELATION_S *pstRelation,
                                             IN const SESSION_RELATIONINFO_KEY_S *pstKey,
                                             IN USHOR usMDC)
{
	IP6FS_CACHEKEY_S *pstIP6fsKey;
	UINT uiMask;

	if(NULL == pstKey)
    {
		return BOOL_FALSE;
    }

	pstIP6fsKey = &pstRelation->stTupleHash.stIp6fsKey;

	/* DELETE标记、MDC检查 */
	if(RELATION_IS_DELETING(pstRelation) || pstIP6fsKey->usMDCID != usMDC)
	{
		return BOOL_FALSE;
	}

	uiMask = pstKey->uiMask;

	/* 源地址检查 */
	if(SESSION_KEY_IS_SRCIPSET(uiMask))
	{
		if(0 != IN6ADDR_Cmp(&pstKey->unL3Src.stin6, &pstIP6fsKey->stIP6SrcAddr))
		{
			return BOOL_FALSE;
		}
	}

	/* 目的地址检查 */
	if(SESSION_KEY_IS_DSTIPSET(uiMask))
	{
	    if(0 != IN6ADDR_Cmp(&pstKey->unL3Des.stin6, &pstIP6fsKey->stIP6DstAddr))
	    {
			return BOOL_FALSE;
	    }
	}

	return BOOL_TRUE;
}

STATIC VOID _session6_KDump_RelationInfoCmpAndFill(IN RELATION6_S *pstRelation,
                                                   IN const SESSION_RELATIONINFO_KEY_S *pstKey,
                                                   IN USHOR usMDC,
                                                   INOUT UINT *puiCount,
                                                   OUT  SESSION_RELATION_INFOALL_S *pstGetInfo)
{
	if(BOOL_TRUE != _session6_KDump_RelationKeyCmp(pstRelation，pstKey, usMDC))
	{
		return;
	}
	
	_session_ShowRelationTableIpv6(pstRelation);
	_session_ShowRelationTable_PortAndVpnInfo(pstRelation);

	*puiCount += 1;
	
	return ;
}

STATIC VOID _session_KDump_GetRelationInfoFromChain(IN const SESSION_HASH_S *pstTblHash,
                                                    IN const SESSION_RELATIONINFO_KEY_S *pstKey,
                                                    IN UINT uiIndex,
                                                    IN USHORT usMDC,
                                                    INOUT SESSION_RELATION_INFOALL_S *pstReplyBuf,
                                                    INOUT UINT *puiCount,
                                                    INOUT UINT *puiLastPos)
	
{
	DL_NODE_S *pstCurNode;
	RELATION_S *pstRelation;
	UINT uiCur = 0; /* 当前正在遍历的HASH节点位置游标 */
	UINT uiCount = *puiCount;

	RCU_ReadLock();
	DL_FOREACH_RCU(&pstTblHash->pstBuckets[uiIndex], pstCurNode)
	{
		/* 从上次遍历到的位置开始装填信息，并将位置游标uiCur后移 */
	    if(uiCur++ >= *puiLastPos)
	    {
			pstRelation = container_of(pstCurNode, RELATION_S, stTupleHash.stNodeInHash);
			_session_KDump_RelationInfoCmpAndFill(pstRelation, pstKey, usMDC, &uiCount, &pstReplyBuf[uiCount]);
	    }

		if(uiCount >= SESSION_DUMP_RELATIONALL_MAX_COUNT)
		{
			*puiLastPos = uiCur;
			break;
		}
	}

	RCU_ReadUnlock();

	/* 如果遍历到冲突链的末尾 */
	if(NULL == pstCurNode)
	{
		*puiLastPos = 0;
	}

	*puiCount = uiCount;

	return;
}

STATIC UINT _session_KDump_GetRelationInfoFromHash(IN const SESSION_HASH_S *pstTblHash,
                                                   IN const SESSION_RELATIONINFO_KEY_S *pstKey,
                                                   INOUT UINT *puiIndex,
                                                   INOUT UINT *puiLastPos,
                                                   INOUT SESSION_RELATION_INFOALL_S *pstReplyBuf)
{
	UINT uiCount = 0;
	UINT uiLastPos = *puiLastPos;
	UINT uiIndex   = *puiIndex;
    DL_NODE_S *pstCurNode;
	RELATION_S *pstRelation;

	/* 根据HASH索引继续遍历 */
	for(; uiIndex < SESSION_RELATION_HASH_LENGTH; uiIndex++)
	{
		DL_FOREACH(&pstTblHash->pstBuckets[uiIndex], pstCurNode)
		{
			pstRelation = container_of(pstCurNode, RELATION_S, stTupleHash.stNodeInHash);
			_session_KDump_RelationInfoCmpAndFill(pstRelation, pstKey, &uiCount, &pstReplyBuf[uiCount]);
		    
		}    
	}

	return uiCount;
}

STATIC UINT _session6_KDump_GetRelationInfoFromHash(IN const SESSION_HASH_S *pstTblHash,
                                                   IN const SESSION_RELATIONINFO_KEY_S *pstKey,
                                                   INOUT UINT *puiIndex,
                                                   INOUT UINT *puiLastPos,
                                                   INOUT SESSION_RELATION_INFOALL_S *pstReplyBuf)
{
	UINT uiCount = 0;
	UINT uiLastPos = *puiLastPos;
	UINT uiIndex   = *puiIndex;
    DL_NODE_S *pstCurNode;
	RELATION_S *pstRelation;

	/* 根据HASH索引继续遍历 */
	for(; uiIndex < SESSION_RELATION_HASH_LENGTH; uiIndex++)
	{
		DL_FOREACH(&pstTblHash->pstBuckets[uiIndex], pstCurNode)
		{
			pstRelation = container_of(pstCurNode, RELATION_S, stTupleHash.stNodeInHash);
			_session6_KDump_RelationInfoCmpAndFill(pstRelation, pstKey, &uiCount, &pstReplyBuf[uiCount]);
		    
		}    
	}

	return uiCount;
}

_session_KDump_RelationInfoMsgProc()
{
    SESSION_RELATIONINFO_KEY_S stKey;
	SESSION_HASH_S *pstTableHash;
	UINT uiLastPos;
	UINT uiCount;
	UINT uiReplyLen = 0;
	UINT uiIndex;
	ULONG ulRet = ERROR_FAILED;
	ULONG ulLen;

	
    if(AF_INET == stKey.ucFamily)
    {
		if(RELATION_TYPE3 == stKey.enVer)
		{
			pstTableHash = g_hV4RelationHash3;
		}
		else
		{
			pstTableHash = g_hV4RelationHash5;
		}

        /* 遍历关联表并写入pstReplyBuf */
		uiCount = _session_KDump_GetRelationInfoFromHash(pstTableHash, &stKey, &uiIndex, &uiLastPos, pstReplyBuf);
    }
	else
	{
		pstTableHash = g_hV6RelationHash;		
        /* 遍历关联表并写入pstReplyBuf */
		uiCount = _session6_KDump_GetRelationInfoFromHash(pstTableHash, &stKey, &uiIndex, &uiLastPos, pstReplyBuf);
		
	}
	
}
#endif


STATIC VOID _session_ShowRelationTableIpv4(IN RELATION_S *pstRelation)
{
	CHAR szSrcIPV4[INET_ADDRSTRLEN];
	CHAR szDstIPv4[INET_ADDRSTRLEN];
	csp_key_t *pstIpfsKey;

	strlcpy(szSrcIPV4, "-", sizeof(szSrcIPV4));
	strlcpy(szDstIPv4, "-", sizeof(szDstIPv4));

	pstIpfsKey = &(pstRelation->stTupleHash.stIpfsKey);

	(VOID)inet_ntop(AF_INET, &pstIpfsKey->dst_ip, szDstIPv4, (UINT)INET_ADDRSTRLEN);

	if(0 != pstIpfsKey->src_ip)
	{
		(VOID)inet_ntop(AF_INET, &pstIpfsKey->src_ip, szSrcIPV4, (UINT)INET_ADDRSTRLEN);
	}

	if(0 != pstIpfsKey->src_port)
	{
		printf("Source IP/port:      %s/%u\r\n", szSrcIPV4, pstIpfsKey->src_port);		
	}
	else
	{
		printf("Source IP/port:      %s/%s\r\n", szSrcIPV4, "-");		
	}

	printf("Destination IP/port: %s/%u\r\n", szDstIPv4, pstIpfsKey->dst_port);

	return;
}

STATIC VOID _session_ShowRelationTableIpv6(IN RELATION6_S *pstRelation)
{
	CHAR szSrcIPV6[INET6_ADDRSTRLEN];
	CHAR szDstIPV6[INET6_ADDRSTRLEN];	
	csp_key_t *pstIpfsKey;

	strlcpy(szSrcIPV6, "---", sizeof(szSrcIPV6));
	strlcpy(szDstIPV6, "---", sizeof(szDstIPV6));
	
	pstIpfsKey = &(pstRelation->stTupleHash.stIp6fsKey);

	(VOID)inet_ntop(AF_INET6, &pstIpfsKey->src_ip, szSrcIPV6, (UINT)INET6_ADDRSTRLEN);	
	(VOID)inet_ntop(AF_INET6, &pstIpfsKey->dst_ip, szDstIPV6, (UINT)INET6_ADDRSTRLEN);

	printf("Source IP:           %s\r\n", szSrcIPV6);
	printf("Destination IP/port: %s/%u\r\n", szDstIPV6, pstIpfsKey->dst_port);

	return;
}

STATIC VOID _session_ShowRelationTable_PortAndVpnInfo(IN RELATION_S *pstRelation)
{
	SESSION_S *pstSession;
	ULONG ulErrCode;
	CHAR szAppName[APR_NAME_MAX_LEN+1];
	CHAR szProtName[APR_PROTO_NAME_MAX_LEN+1];
	UINT uiTTL;
	UCHAR ucProtocol;

	strlcpy(szAppName, "-", sizeof(szAppName));
	strlcpy(szProtName, "-", sizeof(szProtName));
	
	ucProtocol = pstRelation->stTupleHash.stIpfsKey.proto;

	APR_GetProtoNameByID(ucProtocol, szProtName);

	APR_GetAppNameByID(pstRelation->uiAppID, szAppName);

	if((BOOL_TRUE == pstRelation->bCareParentFlag) &&
	   (RELATION_IS_PERSIST(pstRelation)) && 
	   (!RELATION_IS_TABLEFLAG(pstRelation, RELATION_FLAG_TEMP)))
	{
		/* 关心父会话，并且有持久化标记时，此时关联表的老化时间没有意义，显示父会话老化时间 */
	    DBGASSERT(pstRelation->pstParent != NULL);
		pstSession = pstRelation->pstParent;
		uiTTL = _session_Kdump_GetTTL(pstSession);
    }
    else
    {
		/*
		if(RELATION_IS_CHANGABLEAGING(pstRelation))
		{
			pstGetInfo->uiTTL = (UINT)AGINGQOUE_CHANGEABLE_GetTTL(&pstRelation->stChangeable)/HZ;
		}
		else
		{
			pstGetInfo->uiTTL = (UINT)AGINGQUEUE_Unstable_GetTTL(&pstRelation->stUnstable,
				                                                pstRelation->uiUpdateTime)/HZ;
		}
		*/
		
		uiTTL = AGINGQUEUE_Unstable_GetTTL(&pstRelation->stUnstable, pstRelation->uiUpdateTime) / rte_get_timer_hz();

		
    }

	printf("Protocol: %s(%u)     TTL: %us\r\n", szProtName, ucProtocol, uiTTL);
	printf("Application: %s\r\n", szAppName);

	printf("\r\n");

	return;
}

STATIC BOOL_T _session_RelationKeyCmp(IN RELATION_S *pstRelation)
{

	/* DELETE标记检查 */
	if(RELATION_IS_DELETING(pstRelation))
	{
		return BOOL_FALSE;
	}

	return BOOL_TRUE;
}

STATIC VOID _session_RelationInfoCmpAndShow(IN RELATION_S *pstRelation, INOUT UINT *puiCount)
{
	if(BOOL_TRUE != _session_RelationKeyCmp(pstRelation))
	{
		return ;
	}
	_session_ShowRelationTableIpv4(pstRelation);
	_session_ShowRelationTable_PortAndVpnInfo(pstRelation);

	*puiCount += 1;

	return ;
}
												  

STATIC UINT _session_GetRelationInfoFromHash(IN const SESSION_HASH_S *pstTblHash)
{
	UINT uiCount = 0;
	UINT uiIndex = 0;
    DL_NODE_S *pstCurNode;
	RELATION_S *pstRelation;

	/* 根据HASH索引继续遍历 */
	for(; uiIndex < SESSION_RELATION_HASH_LENGTH; uiIndex++)
	{
		DL_FOREACH(&pstTblHash->pstBuckets[uiIndex], pstCurNode)
		{
			pstRelation = container_of(pstCurNode, RELATION_S, stTupleHash.stNodeInHash);
			_session_RelationInfoCmpAndShow(pstRelation, &uiCount);
		    
		}    
	}

	return uiCount;
}


STATIC BOOL_T _session6_RelationKeyCmp(IN RELATION_S *pstRelation)
{
	
	/* DELETE标记检查 */
	if(RELATION_IS_DELETING(pstRelation))
	{
		return BOOL_FALSE;
	}
	
	return BOOL_TRUE;
}

STATIC VOID _session6_RelationInfoCmpAndShow(IN RELATION6_S *pstRelation, INOUT UINT *puiCount)
{
	if(BOOL_TRUE != _session6_RelationKeyCmp(pstRelation))
	{
		return;
	}
	
	_session_ShowRelationTableIpv6(pstRelation);
	_session_ShowRelationTable_PortAndVpnInfo(pstRelation);

	*puiCount += 1;
	
	return ;
}


STATIC UINT _session6_GetRelationInfoFromHash(IN const SESSION_HASH_S *pstTblHash)
{
	UINT uiCount = 0;
	UINT uiIndex   = 0;
    DL_NODE_S *pstCurNode;
	RELATION_S *pstRelation;

	/* 根据HASH索引继续遍历 */
	for(; uiIndex < SESSION_RELATION_HASH_LENGTH; uiIndex++)
	{
		DL_FOREACH(&pstTblHash->pstBuckets[uiIndex], pstCurNode)
		{
			pstRelation = container_of(pstCurNode, RELATION_S, stTupleHash.stNodeInHash);
			_session6_RelationInfoCmpAndShow(pstRelation, &uiCount);
		    
		}    
	}

	return uiCount;
}

static int show_relation_table_ipv4_proc(cmd_blk_t *cbt)
{
	UINT uiCount = 0;


	uiCount = _session_GetRelationInfoFromHash(g_hV4RelationHash3);
	
	uiCount += _session_GetRelationInfoFromHash(g_hV4RelationHash5);
	
	printf("Total entries found: %u\r\n", uiCount);
	
    return 0;
}

static int show_relation_table_ipv6_proc(cmd_blk_t *cbt)
{		
	UINT uiCount;	

	uiCount = _session6_GetRelationInfoFromHash(g_hV6RelationHash);
	
	printf("Total entries found: %u\r\n", uiCount);
	
    return 0;
}


EOL_NODE(relation_table_ipv6_eol, show_relation_table_ipv6_proc);

KW_NODE(relation_table_ipv6, relation_table_ipv6_eol, none, "ipv6", "show relation table ipv6");

EOL_NODE(relation_table_ipv4_eol, show_relation_table_ipv4_proc);

KW_NODE(relation_table_ipv4, relation_table_ipv4_eol, relation_table_ipv6, "ipv4", "show relation table ipv4");

KW_NODE(show_relation, relation_table_ipv4, none, "relation-table", "show relation table");





static int clear_relation_table_proc(cmd_blk_t *cbt)
{
	if(cbt->which[0] == 1)
	{		
		printf("\r\n*** clear_relation_table ***\r\n");
	}
	else if(cbt->which[0] == 2)
	{
		printf("\r\n*** clear_relation_table_ipv4 ***\r\n");
	}
    else if(cbt->which[0] == 3)
	{
		printf("\r\n*** clear_relation_table_ipv6 ***\r\n");
	}
	else
	{
		printf("\r\n*** other ***\r\n");
	}
	
    return 0;
}


static int
clear_relation_proc(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
    show_flow_ctx_t *ctx = (show_flow_ctx_t *)msg_hdr;
    SESSION_TABLE_KEY_S stKey;

    assert(msg_hdr->length == sizeof(show_flow_ctx_t));

    tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt, "  lcore%d:\n", rte_lcore_id());
    if (!rte_atomic32_read(&this_flow_status)) {
        tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt,
                              "    flow is not ready yet\n");
        goto out;
    }

    switch(msg_hdr->subtype) {

        case SESS_CMD_MSG_SUBTYPE_CLEAR:
            memset(&stKey, 0, sizeof(SESSION_TABLE_KEY_S));

            switch (((cmd_blk_t *)msg_hdr->cbt)->which[0]) {
                case 1:
                    /* clear session table */
                    /* 传入ucL3Family为AF_MAX将ipv4 ipv6会话一起删除 */
                    stKey.stTuple.ucL3Family = AF_MAX;
                    break;
                case 2:
                    /* clear relation table ipv4 */
                    stKey.stTuple.ucL3Family = AF_INET;
					
					if (ctx->paras.mask & CLR_GET_CONN_SRCIP) {
                        stKey.stTuple.unL3Src.uiIp = ctx->paras.src_ip;
                        SESSION_KEY_SET_SRCIP(stKey.uiMask);
                    }

                    if (ctx->paras.mask & CLR_GET_CONN_DESIP) {
                        stKey.stTuple.unL3Dst.uiIp = ctx->paras.dst_ip;
                        SESSION_KEY_SET_DSTIP(stKey.uiMask);
                    }
                    
                    break;
                case 3:
                    /* clear relation table ipv6 */
                    stKey.stTuple.ucL3Family = AF_INET6;
					
					if (ctx->paras.mask & CLR_GET_CONN_SRCIP) {
						memcpy(stKey.stTuple.unL3Src.auiIp6, &ctx->paras.src_ip, sizeof(stKey.stTuple.unL3Src.auiIp6));
				        SESSION_KEY_SET_SRCIP(stKey.uiMask);
					}
					
					if (ctx->paras.mask & CLR_GET_CONN_DESIP) {
				        memcpy(stKey.stTuple.unL3Dst.auiIp6, &ctx->paras.dst_ip, sizeof(stKey.stTuple.unL3Dst.auiIp6));
				        SESSION_KEY_SET_DSTIP(stKey.uiMask);
					}
					
                    break;
                default:
                    tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt, 
                                  "  unsupport operation\n");
                    goto out;
            }

            RELATION_KReset(&stKey);
            break;
        default:
            tyflow_cmdline_printf((struct cmdline *)msg_hdr->cbt, 
                                  "  unsupport operation\n");
            break;
   }

out:
    return msg_hdr->rc;
}

static int
clear_relation_echo_proc(cmd_msg_hdr_t *msg_hdr, void *cookie)
{
	
    assert(msg_hdr->type == CMD_MSG_RELATION_CLEAR);
	
    return 0;
}

static void
relation_parse_para(cmd_blk_t *cbt, connection_op_para_t *paras)
{
    char *pc;
    char *str;

    /* src-ipv6 x::x/x */
    if (cbt->which[1] == 1) {
        str = cbt->string[2];
        if (FWLIB_Check_IPv6AndPrefix_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_SRCIP;
            if (strchr(str, '/')) {
                /* example, 1::2/64 */
                pc = strtok(str, "/");
                inet_pton(AF_INET6, pc, &paras->src_ip);
                pc = strtok(NULL, "/");
                paras->src_mask = atoi(pc);
            }
            else {
                /* example, 1::2 */
                inet_pton(AF_INET6, str, &paras->src_ip);
                paras->src_mask = 128;
            }
        }
    }

    /* dst-ipv6 x::x/x */
    if (cbt->which[2] == 1) {
        str = cbt->string[3];
        if (FWLIB_Check_IPv6AndPrefix_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_DESIP;
            if (strchr(str, '/')) {
                /* example, 1::2/64 */
                pc = strtok(str, "/");
                inet_pton(AF_INET6, pc, &paras->dst_ip);
                pc = strtok(NULL, "/");
                paras->dst_mask = atoi(pc);
            }
            else {
                /* example, 1::2 */
                inet_pton(AF_INET6, str, &paras->dst_ip);
                paras->dst_mask = 128;
            }
        }
    }

    /* src-ip x.x.x.x/x */
    if (cbt->which[3] == 1) {
        str = cbt->string[0];
        if (FWLIB_Check_IPv4AndMask_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_SRCIP;
            if (strchr(str, '/')) {
                /* example, 1.1.1.1/24 */
                pc = strtok(str, "/");
                inet_pton(AF_INET, pc, &paras->src_ip);
                pc = strtok(NULL, "/");
                paras->src_mask = atoi(pc);
            }
            else {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, str, &paras->src_ip);
                paras->src_mask = 32;
            }
        }
    }

    /* dst-ip x.x.x.x/x */
    if (cbt->which[4] == 1) {
        str = cbt->string[1];
        if (FWLIB_Check_IPv4AndMask_IsLegal(str)) {
            paras->mask |= CLR_GET_CONN_DESIP;
            if (strchr(str, '/')) {
                /* example, 1.1.1.1/24 */
                pc = strtok(str, "/");
                inet_pton(AF_INET, pc, &paras->dst_ip);
                pc = strtok(NULL, "/");
                paras->dst_mask = atoi(pc);
            }
            else {
                /* example, 1.1.1.1 */
                inet_pton(AF_INET, str, &paras->dst_ip);
                paras->dst_mask = 32;
            }
        }
    }
	
    return;
}


static int
clear_relation_cli_proc(cmd_blk_t *cbt)
{
    show_flow_ctx_t flow_ctx;
    connection_op_para_t *paras;

    cl = cbt->cl;
    sess_cnt = 0;

    flow_ctx.msg_hdr.type = CMD_MSG_RELATION_CLEAR;
    flow_ctx.msg_hdr.length = sizeof(show_flow_ctx_t);
    flow_ctx.msg_hdr.rc = 0;
    flow_ctx.msg_hdr.cbt = cbt;
    paras = &flow_ctx.paras;
    memset(paras, 0, sizeof(connection_op_para_t));	
    relation_parse_para(cbt, paras);
    
    switch(cbt->which[0]) {
   
        case 1: /* clear relation table */
        case 2: /* clear relation table ipv4 [...] */
        case 3: /* clear relation table ipv6 [...] */
            flow_ctx.msg_hdr.subtype = SESS_CMD_MSG_SUBTYPE_CLEAR;
            send_cmd_msg_to_fwd_lcore(&flow_ctx.msg_hdr);

            tyflow_cmdline_printf(cbt->cl, "all related relations deleted\r\n");

            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown command\n");
            break;
    }
	
    return 0;
}


EOL_NODE(clear_relation_eol, clear_relation_cli_proc);

/* dst-ip x.x.x.x */
VALUE_NODE(clear_relation_table_dip_val, clear_relation_eol, none, "ipv4 address: x.x.x.x", 2, STR);
KW_NODE_WHICH(clear_relation_table_dip, clear_relation_table_dip_val, clear_relation_eol, "dst-ip", "dest ip address", 5, 1);

/* src-ip x.x.x.x */
VALUE_NODE(clear_relation_table_sip_val, clear_relation_table_dip, none, "ipv4 address: x.x.x.x", 1, STR);
KW_NODE_WHICH(clear_relation_table_sip, clear_relation_table_sip_val, clear_relation_table_dip, "src-ip", "source ip address", 4, 1);

/* dst-ipv6 x::x */
VALUE_NODE(clear_relation_table_dipv6_val, clear_relation_eol, none, "ipv6 address: x::x", 4, STR);
KW_NODE_WHICH(clear_relation_table_dipv6, clear_relation_table_dipv6_val, clear_relation_eol, "dst-ipv6", "dest ipv6 address", 3, 1);

/* src-ipv6 x::x */
VALUE_NODE(clear_relation_table_sipv6_val, clear_relation_table_dipv6, none, "ipv6 address: x::x", 3, STR);
KW_NODE_WHICH(clear_relation_table_sipv6, clear_relation_table_sipv6_val, clear_relation_table_dipv6, "src-ipv6", "source ipv6 address", 2, 1);


/* clear session table ipv6 [src-ipv6 x::x/x]  [dst-ipv6 x::x/x] */
KW_NODE_WHICH(clear_relation_table_v6, clear_relation_table_sipv6, clear_relation_eol, "ipv6", "clear session table of ipv6", 1, 3);

/* clear relation table ipv4 [src-ip x.x.x.x/x] [dst-ip x.x.x.x/x] */
KW_NODE_WHICH(clear_relation_table_v4, clear_relation_table_sip, clear_relation_table_v6, "ipv4", "clear relation table of ipv4", 1, 2);

/* clear relation table */
KW_NODE_WHICH(clear_relation_table, clear_relation_table_v4, none, "table", "clear relation table", 1, 1);
KW_NODE(clear_relation, clear_relation_table, none, "relation", "clear relation table");

int
relation_cli_init(void)
{	
    add_get_cmd(&cnode(show_relation));
    add_clear_cmd(&cnode(clear_relation));
    return cmd_msg_handler_register(CMD_MSG_RELATION_CLEAR,
                                    clear_relation_proc,
                                    clear_relation_echo_proc,
                                    &relation_cnt);
}

