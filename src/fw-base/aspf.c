
//#include "in.h"
#include <netinet/in.h>

#include "tcp.h"
#include "udp.h"
#include "ip_icmp.h"
#include "icmp6.h"
#include "acl.h"
#include "session.h"
#include "aspf_kutil.h"
#include "aspf.h"
#include "aspf_kdbg.h"
#include "session.h"
#include "session_ktable.h"
#include "session_kdebug.h"
#include "dpi.h"
#include "pflt_pkt_info.h"
#include "fw_conf/aspf_policy_conf.h"
#include "../access_control/secpolicy_common.h"
#include "../access_control/secpolicy_match.h"
#include "aspf_dbg_cli.h"
#include "flow.h"


#define ASPF_TCP_CARE_FLAGS   (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG)
#define ASPF_TCP_NOCARE_FLAGS (TH_PUSH | TH_ECE | TH_CWR)


#define SESSION_GetL4Type(hSession) \
	(((SESSION_S *)hSession)->stSessionBase.ucSessionL4Type)

#define PKT_INCOMPLETE  PKT_ENQUEUED

/* table of valid flag combinations - PUSH, ECE and CWR are always valid */
STATIC BOOL_T g_abASPF_TCP_Valid_Flags[ASPF_TCP_CARE_FLAGS + 1] =
{
    [TH_SYN]        = BOOL_TRUE,
    [TH_SYN|TH_URG] = BOOL_TRUE,
};

#define IP_LOOPBACKIP    0x7f000001

#define INDEX(x)  ((x)-1)

/*
BOOL_T IP6ADDR_IsLoopback(IN const IN6ADDR_S *pstAddr)
{
    const UINT *puiAddr;

    puiAddr = pstAddr->_u6_addr._u6_addr32;

    return ((puiAddr[0] == 0) && (puiAddr[1] == 0) && 
            (puiAddr[2] == 0) && (puiAddr[3] == htonl(1)));
}
*/
#define ASPF_MAX_APP_NUM 4

ASPF_CTRL_S g_stAspfCtrl;

/* 向会话设置ASPF配置序号 */
static inline VOID ASPF_SetCfgSeq(IN SESSION_HANDLE hSession)
{
	ASPF_CTRL_S *pstAspfCtrl;
	SESSION_S *pstSess = (SESSION_S *)hSession;

	pstAspfCtrl = ASPF_CtrlData_Get();
	DBGASSERT(NULL != pstAspfCtrl)
	pstSess->ucAspfCfgSeq = pstAspfCtrl->ucCfgSeq;

	return;
}

/*********************
Description∶ 会话配置序号变更****/
static inline VOID SESSION_CfgSeq_Inc(VOID)
{
    SESSION_CTRL_S *pstSessionCtrl;

	/* 写内存屏障，防止先修改配置序号，后修改配置数据 
	smp_wmb();*/

    pstSessionCtrl = SESSION_CtrlData_Get();

	pstSessionCtrl->usCfgSeq++;

	if (0 == pstSessionCtrl->usCfgSeq)
	{
		pstSessionCtrl->usCfgSeq++;
	}

	return;
}

/*** Description∶增加配置序号 ***/
VOID ASPF_Inc_Cfg_Seq(VOID)
{
	ASPF_CTRL_S *pstAspfCtrl;
	
	pstAspfCtrl = ASPF_CtrlData_Get();
	pstAspfCtrl->ucCfgSeq++;

	SESSION_CfgSeq_Inc();
	
	flow_update_policy_seq();

	return;
}


/*** Description∶增加配置序号 
STATIC VOID _kcfgdata_inc_cfg_seq(INOUT ASPF_CTRL_S *pstAspfCtrl)
{
	pstAspfCtrl->ucCfgSeq++;

	SESSION_CfgSeq_Inc();

	IPFS_Inc_CFGSeq();
	IP6FS_Inc_CfgSeq();

	return;
}***/


/* 增加ASPF配置序号 
VOID ASPF_kcfgdata_IncCfgSeq(VOID)
{
	ASPF_CTRL_S *pstAspfCtrl;

	pstAspfCtrl = ASPF_CtrlData_Get();

	_kcfgdata_inc_cfg_seq(pstAspfCtrl);

	return;
}*/


STATIC INLINE IPFW_SERVICE_RET_E _kpacket_zonepair_needproc(IN USHORT usL3Offset,
															IN ACL_VERSION_E enAclVer,
															IN MBUF_S *pstMBuf)
{
	BOOL_T bIsIcmpv6Nd;

	if (ACL_VERSION_ACL6 == enAclVer)
	{
        /*判断是否为ND报文,邻居发现报文直接放过*/
		bIsIcmpv6Nd = ASPF_kutil_ipv6_IsIcmpv6Nd(pstMBuf, usL3Offset);
		if (BOOL_TRUE == bIsIcmpv6Nd)
		{
			return PKT_CONTINUE;
		}
	}

    
    return PKT_INCOMPLETE;
}

/* packet的丢包发送icmp4 err报文
IPFW_SERVICE_RET_E _kpacket_zonepair_send_icmp4err(IN MBUF_S *pstMBuf)
{
	IPFW_SERVICE_RET_E enRet = PKT_DROPPED;
	ASPF_CTRL_S *pstAspfCtrl;

	pstAspfCtrl = ASPF_CtrlData_Get();
	DBGASSERT(NULL != pstAspfCtrl);

	if(BOOL_TRUE == pstAspfCtrl->bIcmpErrReply)
	{
		icmp_error(pstMBuf,ICMP_UNREACH,ICMP_UNREACH_FILTER_PROHIB, 0, 0);
		enRet = PKT_CONSUMED;
	}

	return enRet;
} */

/* 根据MBuf获取报文的SECPOLICY_PACKET_IP4_S数据结构 */
STATIC VOID pflt_ipv4_get_adv_pkt_info(IN MBUF_S *pstMBuf,
                                       INOUT SECPOLICY_PACKET_IP4_S *pstPktInfo,
                                       IN UINT uiAppID)
{
	conn_sub_t *csp;
	csp_key_t *pstcspkey;

    DBGASSERT(NULL != pstMBuf);

    memset(pstPktInfo, 0, sizeof(SECPOLICY_PACKET_IP4_S));

    pstPktInfo->uiAppID = uiAppID;

    csp = GET_CSP_FROM_LBUF(pstMBuf);
	pstcspkey = GET_CSP_KEY(csp);

    /* 获取IP地址 */
    pstPktInfo->stSrcIP.s_addr = pstcspkey->src_ip;
    pstPktInfo->stDstIP.s_addr = pstcspkey->dst_ip;
    pstPktInfo->ucProtocol     = pstcspkey->proto;
	pstPktInfo->uiVxlanID      = pstcspkey->token;    

	switch (pstPktInfo->ucProtocol)
	{
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		{
			pstPktInfo->usDPort = pstcspkey->dst_port;
			pstPktInfo->usSPort = pstcspkey->src_port;
			break;
		}
		case IPPROTO_ICMP:
		{
			pstPktInfo->stIcmp.ucType = csp->csp_type;
			pstPktInfo->stIcmp.ucCode = csp->csp_code;
			break;
		}
		default:
		{
			break;
		}
	}

    return;
}

STATIC SECPOLICY_ACTION_E pflt_ip4_packet_match_zonepair_policy(IN MBUF_S *pstMBuf,
																IN UINT uiAppID)
{
	SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4;
	SECPOLICY_ACTION_E enAction;  
	
	pflt_ipv4_get_adv_pkt_info(pstMBuf, &stSecPolicyPacketIP4, uiAppID);	
	
	enAction = SecPolicy_Match_IP4(&stSecPolicyPacketIP4);

	return enAction;
}

STATIC IPFW_SERVICE_RET_E PFLT_PacketIPv4ZonePairNormalProc(IN USHORT usIPOff,
													        IN SESSION_HANDLE hSession,
													        INOUT MBUF_S *pstMBuf)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	SESSION_S *pstSession = (SESSION_S*)hSession;
	SECPOLICY_ACTION_E enAction;  
	APR_PARA_S stAprPara;
	BOOL_T bNeedApr;	
	conn_sub_t *csp;	
	csp_key_t *pstcspkey;
	struct in_addr stSrcIP;
    struct in_addr stDstIP;
	UINT uiVrf;

	if (NULL != pstSession)
	{	
		csp       = SESSION_KGetCsp((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
	    pstcspkey = GET_CSP_KEY(csp);

		uiVrf = pstcspkey->token;
		stSrcIP.s_addr = pstcspkey->src_ip;
		stDstIP.s_addr = pstcspkey->dst_ip;
	}
	else
	{
		csp = GET_CSP_FROM_LBUF(pstMBuf);
		pstcspkey = GET_CSP_KEY(csp);

		uiVrf = pstcspkey->token;
		stSrcIP.s_addr = pstcspkey->src_ip;
		stDstIP.s_addr = pstcspkey->dst_ip;
	}

	bNeedApr = SecPolicy_IP4_IsNeedAPR(uiVrf, &stSrcIP, &stDstIP);	
	
    if(bNeedApr)
    {
		if(NULL != pstSession)
		{
			stAprPara.uiAppID      = pstSession->uiAppID;
			stAprPara.uiTrustValue = pstSession->uiTrustValue;
			
			APR_Check(pstMBuf, &stAprPara);
			
		    pstSession->uiAppID = stAprPara.uiAppID;
			pstSession->uiTrustValue = stAprPara.uiTrustValue;
		}
		else
		{		
			stAprPara.uiAppID = APR_ID_INVALID;
		    stAprPara.uiTrustValue = APR_TRUST_INIT;
			APR_Check(pstMBuf, &stAprPara);		
		}
    }
	else
	{
		stAprPara.uiAppID = APR_ID_INVALID;
	}
	
	enAction = pflt_ip4_packet_match_zonepair_policy(pstMBuf, stAprPara.uiAppID);
	if (SECPOLICY_ACTION_DENY == enAction)	
	{
		enRet = PKT_DROPPED;
	}

	return enRet;
}


/* packet的丢包统计和debug信息输出 */
STATIC VOID _kpacket_zonepair_dropstat_dbg(IN CHAR *pcDbgDesc,
                                           IN ACL_VERSION_E enAclVer,
                                           IN MBUF_S *pstMBuf,
                                           IN USHORT usL3Offset,
                                           IN ASPF_DROP_TYPE_E enDropType)
{
    ASPF_CTRL_S *pstAspfCtrl;
    ASPF_STAT_VERSION_E enStatsVer = (ASPF_STAT_VERSION_E)INDEX(enAclVer);

    if(NULL != pstMBuf)
    {
        pstAspfCtrl = ASPF_CtrlData_Get();
        rte_atomic32_inc(&pstAspfCtrl->astDropCount[enStatsVer][enDropType]);
        ASPF_DBG_ZONEPAIR_PACKETS_EVENT_SWITCH(pcDbgDesc, enAclVer, pstMBuf, usL3Offset, pstAspfCtrl);
    }

    return;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_pflt_no_session(IN MBUF_S *pstMBuf, 
																		IN USHORT usL3Offset)
{
	IPFW_SERVICE_RET_E enRet;

	enRet = PFLT_PacketIPv4ZonePairNormalProc(usL3Offset, SESSION_INVALID_HANDLE, pstMBuf);
	if(PKT_DROPPED == enRet)
	{
	    _kpacket_zonepair_dropstat_dbg("The packet that matches no session was dropped "\
								   	   "by sec-policy",
								       ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_NOSESSION_PFLT);

		/*
		enRet = _kpacket_zonepair_send_icmp4err(pstMBuf);
		*/
	}
	

	return enRet;
}

/*** Deseription∶ 获取ipv4报文的14的类型和偏移量 ***/
STATIC ULONG ASPF_kutil_ipv4_GetL4Proto(IN const MBUF_S *pstMBuf,
								        IN USHORT usL3Offset,
								        OUT UCHAR *pucL4Proto,
								        OUT USHORT *pusL4Offset)
{
	struct iphdr* pstIP;
	USHORT usIPHLen;

	pstIP = MBUF_BTOD_OFFSET(pstMBuf, usL3Offset, struct iphdr *);
	usIPHLen = pstIP->ihl;
	usIPHLen =(USHORT)((UINT)usIPHLen << 2);

	if(usIPHLen > MBUF_GET_TOTALDATASIZE(pstMBuf) - usL3Offset)
	{
		return ERROR_FAILED;
	}

	*pucL4Proto = pstIP->protocol;
	*pusL4Offset = usL3Offset + usIPHLen;

	return ERROR_SUCCESS;
}

/* Description∶检测指定报文是否是tcp报文，且是否是tcp-syn报文 */
STATIC VOID _kpacket_is_tcp_syn_packet(IN MBUF_S *pstMBuf,
									   IN USHORT usL4Offset,
									   OUT BOOL_T *pbTcpPacket, 
									   OUT BOOL_T *pbTcpSynPacket)
{
	ULONG ulErr = ERROR_FAILED;
	TCPHDR_S* pstTcpHdr;
	UCHAR ucFlags;

	/* 设置tcp报文标记 */
	*pbTcpPacket = BOOL_TRUE;

	ulErr = MBUF_PULLUP(pstMBuf, usL4Offset+(UINT32)sizeof(TCPHDR_S));
	if (ERROR_SUCCESS == ulErr)
	{
		pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, usL4Offset, TCPHDR_S *);
		ucFlags = (pstTcpHdr->th_flags) & (~ASPF_TCP_NOCARE_FLAGS);

		/* 检测是否是tcp-syn报文 */
		if (BOOL_TRUE == g_abASPF_TCP_Valid_Flags[ucFlags])
		{
			*pbTcpSynPacket = BOOL_TRUE;
		}
	}

	return;
}

/*** Description∶对mbuf进行tcp syn-check检查 ***/
STATIC IPFW_SERVICE_RET_E ASPF_kpacket_ipv4_tcp_syn_Check(IN MBUF_S *pstMBuf, IN USHORT usL3Offset)
{
	BOOL_T bTcpPacket;
	BOOL_T bTcpSynPacket;

	ULONG ulErr;
	UCHAR ucL4Proto; 
	USHORT usL4Offset; 

	bTcpPacket = BOOL_FALSE;
	bTcpSynPacket = BOOL_FALSE;
	ulErr = ASPF_kutil_ipv4_GetL4Proto(pstMBuf,usL3Offset, &ucL4Proto, &usL4Offset);

	if ((ERROR_SUCCESS == ulErr) && (IPPROTO_TCP == ucL4Proto))
	{
		_kpacket_is_tcp_syn_packet(pstMBuf, usL4Offset, &bTcpPacket, &bTcpSynPacket);
	}

	if ((BOOL_TRUE == bTcpPacket) && (BOOL_TRUE != bTcpSynPacket))
	{
		return PKT_DROPPED;
	}

	return PKT_CONTINUE;
}

/* 判断是否要将报文丢弃 */
STATIC BOOL_T ASPF_kpacket_ipv4_IsDropPacket(IN const MBUF_S *pstMBuf, IN USHORT usL3Offset)
{
    TCPHDR_S *pstTcpHdr;
    struct icmphdr *pstIcmpHdr;
    UCHAR ucFlags;
    UCHAR ucL4Proto;
    USHORT usL4Offset;
    BOOL_T bDropPacket = BOOL_FALSE;
    ULONG ulRet = ERROR_FAILED;

    ulRet = ASPF_kutil_ipv4_GetL4Proto(pstMBuf, usL3Offset, &ucL4Proto, &usL4Offset);
    if(ERROR_SUCCESS != ulRet)
    {
        return bDropPacket;
    }

    if(IPPROTO_TCP == ucL4Proto)
    {
        pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, usL4Offset, TCPHDR_S *);
        ucFlags = (pstTcpHdr->th_flags) & (~ASPF_TCP_NOCARE_FLAGS) & (~TH_URG);
        if((TH_SYN != ucFlags) && (TH_ACK != ucFlags))
        {
            bDropPacket = BOOL_TRUE;
        }
    }
    else if (IPPROTO_ICMP == ucL4Proto)
    {
        pstIcmpHdr = MBUF_BTOD_OFFSET(pstMBuf, usL4Offset, struct icmphdr *);
        bDropPacket = ASPF_kutil_ipv4_IsIcmpReplay(pstIcmpHdr->icmp_type, pstIcmpHdr->icmp_code);
    }
  
    return bDropPacket;
}

/*
STATIC IPFW_SERVICE_RET_E ASPF_kpacket_icmp_err_Check(IN const MBUF_S *pstMBuf)
{
    if(SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_ICMPERR))
    {
        return PKT_DROPPED;
    }
    
    return PKT_CONTINUE;
}
*/

STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_aspf_no_session(IN MBUF_S *pstMBuf, IN USHORT usL3Offset)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	//UINT32 uiPktType;
    aspf_policy_conf_s *pstAspfPolicy;
	BOOL_T bDropPacket;
	UINT32 uiVrf = 0;

    #if 0
	/* 非本机发送的报文才做TCP SYN-CHECK或ICMP-ERROR CHECK检查，否则直接放行 */
	uiPktType = MBUF_GET_IP_PKTTYPE(pstMBuf);
	if (IP_PKT_HOSTSENDPKT == (uiPktType & IP_PKT_HOSTSENDPKT))
	{
		return enRet;
	}
	#endif

	pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
	if (NULL == pstAspfPolicy)
	{
		return enRet;
	}

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID))
	{
		bDropPacket = ASPF_kpacket_ipv4_IsDropPacket(pstMBuf, usL3Offset);
		if (BOOL_TRUE == bDropPacket)
		{
			_kpacket_zonepair_dropstat_dbg("The first packet was dropped by ASPF for invalid status",
										   ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_FIRST_IV_STATUS);
			return PKT_DROPPED;
		}
	}

	/* icmp-error drop
	if (BOOL_TRUE == pstKPolicy->bIcmpErrDrop)
	{
		enRet = ASPF_kpacket_icmp_err_Check(pstMBuf);
		if (PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The packet that matches no session was dropped by ASPF,"\
										   "because the ICMP error checking failed", ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_NOSESSION_ICMPERR);
			return enRet;
		}
	} */

	/* tcp syn-check */
	if (BOOL_TRUE == pstAspfPolicy->bTcpSynCheck)
	{
        enRet = ASPF_kpacket_ipv4_tcp_syn_Check(pstMBuf, usL3Offset);
    	if (PKT_DROPPED == enRet)
    	{
    		_kpacket_zonepair_dropstat_dbg("The packet that matches no session was dropped by ASPF,"\
    								       "because the TCP SYN checking failed",
    								       ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_NOSESSION_SYN);
    	}
	}
	

	return enRet;
}

/*
Return: PKT_CONTINUE  报文通过检查，继续转发 
       PKT_DROPPED    报文没有通过检查，丢弃
*/
STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_pflt_first(IN SESSION_HANDLE hSession, 
																   IN MBUF_S *pstMBuf, 
																   IN USHORT usL3Offset) 
{
	IPFW_SERVICE_RET_E enRet;

	enRet = PFLT_PacketIPv4ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	if(PKT_DROPPED == enRet)
    {
		_kpacket_zonepair_dropstat_dbg("The first packet was dropped by sec-policy",
								       ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_FIRST_PFLT);

		/*
		enRet = _kpacket_zonepair_send_icmp4err(pstMBuf);
		*/
	}

	return enRet;
}

#define  ASPF_DETECT_FTP         0x0000000000000001
#define  ASPF_DETECT_HTTP        0x0000000000000002
#define  ASPF_DETECT_DNS         0x0000000000000004
#define  ASPF_DETECT_SIP         0x0000000000000008
#define  ASPF_DETECT_TFTP        0x0000000000000010


STATIC UINT64 ASPF_GetDetectFlagByAppID(IN UINT uiAppID)
{
	UINT64 uiDetectFlag = 0;

	switch (uiAppID)
	{
		case APP_ID_FTP:
		{
			uiDetectFlag = ASPF_DETECT_FTP;
			break;
		}
	    case APP_ID_HTTP:
		{
			uiDetectFlag = ASPF_DETECT_HTTP;
			break;
		}
		case APP_ID_DNS:
		{
			uiDetectFlag = ASPF_DETECT_DNS;
			break;
		}
		case APP_ID_SIP:
		{
			uiDetectFlag = ASPF_DETECT_SIP;
			break;
		}
		case APP_ID_TFTP:
		{
			uiDetectFlag = ASPF_DETECT_TFTP;
			break;
		}
		default:
		{
			break;
		}		
    }

	return uiDetectFlag;
}

/* Description∶检测在aspf-policy中是否detect指定的app-id */
STATIC BOOL_T ASPF_kpolicy_IsAppDetect(IN UINT uiAppID,
							           IN const aspf_policy_conf_s *pstAspfPolicy)
{
	BOOL_T bExist = BOOL_FALSE;
	UINT64 uiAppFlag;
	UINT64 uiCfgDetectFlag;

	uiAppFlag = ASPF_GetDetectFlagByAppID(uiAppID);
	uiCfgDetectFlag  = pstAspfPolicy->detect;

	if((uiAppFlag & uiCfgDetectFlag) != 0)
	{
		bExist = BOOL_TRUE;
	}

	return bExist;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_aspf_first(IN MBUF_S *pstMBuf,
															IN USHORT usL3Offset,
															INOUT SESSION_HANDLE hSession)
{
	UINT uiAppID;
	aspf_policy_conf_s *pstAspfPolicy;
	UINT32 uiVrf = 0;
	
	pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
	if (NULL == pstAspfPolicy)
	{
		return PKT_CONTINUE;
	}

	/* tcp syn-check */
	if ((BOOL_TRUE == pstAspfPolicy->bTcpSynCheck) &&
		(SESSION_GetL4Type(hSession)== SESSION_L4_TYPE_TCP))
	{
		IPFW_SERVICE_RET_E enRet;
		enRet = ASPF_kpacket_ipv4_tcp_syn_Check(pstMBuf,usL3Offset);
		if (PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The first packet was dropped by ASPF,"\
									   "because the TCP SYN checking failed",
									   ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_FTRST_SYN);
			return PKT_DROPPED;
		}
	}

	/* 根据策略获取会话的动作 */
	uiAppID = SESSION_KGetAppID(hSession);
	if (BOOL_TRUE == ASPF_kpolicy_IsAppDetect(uiAppID, pstAspfPolicy))
	{
		ASPF_SetCfgSeq(hSession);
		SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
	}
	
    return PKT_CONTINUE;
}

STATIC VOID _kpacket_zonepair_filter_get_matchinfo_Ipv4(IN SESSION_HANDLE hSession,
                       				                    OUT SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4)
{
	struct in_addr stSrcIP;
	struct in_addr stDstIP;
	USHORT usSrcPort;
	USHORT usDstPort;
	UCHAR ucProtocol;	
	conn_sub_t *csp;
	csp_key_t *pstcspkey;	
    SESSION_S *pstSession = (SESSION_S *)hSession;	
	
    memset(pstSecPolicyPacketIP4, 0, sizeof(SECPOLICY_PACKET_IP4_S));

	
	csp = SESSION_KGetCsp(hSession, SESSION_DIR_ORIGINAL);
	pstcspkey = &(csp->key);
	stSrcIP.s_addr = pstcspkey->src_ip;
	usSrcPort = pstcspkey->src_port;
	stDstIP.s_addr = pstcspkey->dst_ip;
	usDstPort = pstcspkey->dst_port;
	ucProtocol = pstcspkey->proto;

	pstSecPolicyPacketIP4->uiVxlanID  = pstcspkey->token;
	pstSecPolicyPacketIP4->ucProtocol = ucProtocol;
	pstSecPolicyPacketIP4->stSrcIP.s_addr = stSrcIP.s_addr;
	pstSecPolicyPacketIP4->stDstIP.s_addr = stDstIP.s_addr;

	if ((IPPROTO_TCP == ucProtocol) || (IPPROTO_UDP == ucProtocol))
	{
		pstSecPolicyPacketIP4->usSPort = usSrcPort; 
		pstSecPolicyPacketIP4->usDPort = usDstPort; 
	}
	else if (IPPROTO_ICMP == ucProtocol)
	{
		pstSecPolicyPacketIP4->stIcmp.ucType = csp->csp_type;
		pstSecPolicyPacketIP4->stIcmp.ucCode = csp->csp_code;
	}

	pstSecPolicyPacketIP4->uiAppID = pstSession->uiAppID;

	return;
}

STATIC ULONG PFLT_PacketIPv4ZonePairPktInfoProc(IN SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4)
{
	IPFW_SERVICE_RET_E enIpfwRet = PKT_DROPPED;
	SECPOLICY_ACTION_E enAction;  	
	
	enAction = SecPolicy_Match_IP4(pstSecPolicyPacketIP4);
    
	if (SECPOLICY_ACTION_PERMIT == enAction)
	{
		enIpfwRet = PKT_CONTINUE;
	}
	else
	{
		enIpfwRet = PKT_DROPPED;
	}

	return (ULONG)enIpfwRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_update_aspf_zonepair_action_by_parent(IN MBUF_S *pstMBuf,
																              IN SESSION_HANDLE hSession,
															                  IN SESSION_HANDLE hParentSession,
																              IN BOOL_T bFirstPkt)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	ASPF_CTRL_S *pstAspfCtrl;
	SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4;

	pstAspfCtrl = ASPF_CtrlData_Get();

	DBGASSERT(NULL != pstAspfCtrl);

	if (unlikely(pstAspfCtrl->ucCfgSeq != ((SESSION_S *)hParentSession)->ucAspfCfgSeq))
	{
		_kpacket_zonepair_filter_get_matchinfo_Ipv4(hParentSession, &stSecPolicyPacketIP4);
		enRet = (IPFW_SERVICE_RET_E)PFLT_PacketIPv4ZonePairPktInfoProc(&stSecPolicyPacketIP4);

		/* 如果根据父会话的最新FILTER策略需要丢包，则使子会话后续报文直接走FILTER */
		if (PKT_CONTINUE != enRet)
		{
			enRet = PKT_INCOMPLETE;
		}

		ASPF_SetCfgSeq(hParentSession);
	}

	return enRet;
}

/* 对报文做tcp首包syn检查 */
STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_tcp_syn_check(IN MBUF_S *pstMBuf,
															   IN USHORT usL3Offset,
															   IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	aspf_policy_conf_s *pstAspfPolicy;
	UINT32 uiVrf = 0;
	
	pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
	if (NULL == pstAspfPolicy)
	{
		return PKT_CONTINUE;
	}

	/* tcp syn-check */
	if ((BOOL_TRUE == pstAspfPolicy->bTcpSynCheck) &&
	    (SESSION_GetL4Type(hSession) == SESSION_L4_TYPE_TCP))
	{
		enRet = ASPF_kpacket_ipv4_tcp_syn_Check(pstMBuf, usL3Offset);
		if (PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The first packet of child session was dropped by ASPF,"\
			                               "because the TCP SYN checking failed",
										   ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_CHILD_SYN);
			return PKT_DROPPED;
		}
	}

	return enRet;
}

/* app-id是否需要alg处理 */
static inline BOOL_T _kpacket_is_app_id_for_alg(IN UINT uiAppID)
{
	BOOL_T bFlag;

	switch(uiAppID)
	{
		case APP_ID_FTP:
		case APP_ID_RAS:
		case APP_ID_H225:
		case APP_ID_H245:
		case APP_ID_SIP:
		case APP_ID_TFTP:
		case APP_ID_GTPC:
		case APP_ID_GTPU:
		case APP_ID_GPRSDATA:
		case APP_ID_GPRSSIG:
		case APP_ID_RTSP:
		case APP_ID_PPTP:
		case APP_ID_ILS:
		case APP_ID_NETBIOSNS:
		case APP_ID_NETBIOSDGM:
		case APP_ID_NETBIOSSSN:
		case APP_ID_SCCP:
		case APP_ID_SQLNET:
		case APP_ID_XDMCP:
		case APP_ID_MGCPC:
		case APP_ID_MGCPG:
		case APP_ID_RSH:
		case APP_ID_HTTP:
		case APP_ID_SMTP:
		case APP_ID_DNS:
		{
			bFlag = BOOL_TRUE;
			break;
		}
		default:
		{
			bFlag = BOOL_FALSE;
			break;
		}
	}

	return bFlag;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_aspf_child_first(IN MBUF_S *pstMBuf,
																  IN USHORT usL3Offset,
																  IN SESSION_HANDLE hSession,
																  IN SESSION_HANDLE hParentSession)
{
	UINT uiAppID;
    IPFW_SERVICE_RET_E enRet;	

    enRet = _kpacket_ipv4_update_aspf_zonepair_action_by_parent(pstMBuf, hSession, hParentSession,BOOL_TRUE);	
    if (PKT_CONTINUE != enRet)	
    {       
        enRet = _kpacket_ipv4_zonepair_tcp_syn_check(pstMBuf, usL3Offset, hSession);       
        if (PKT_CONTINUE == enRet)      
        {           
            /* filter process */            
            enRet = PKT_INCOMPLETE;     
        }  
    }
    else
    {
        enRet = PKT_CONTINUE;     

    	/* 如果父会话需要做ALG，并且子会话的应用层协议支持ALG，则认为子会话也需要做ALG*/
    	uiAppID = SESSION_KGetAppID(hSession);
    	if ((BOOL_TRUE == SESSION_KIsAlgFlagSet(hParentSession, SESSION_MODULE_ASPF)) &&
    		(BOOL_TRUE == _kpacket_is_app_id_for_alg(uiAppID)))
    	{
    		ASPF_SetCfgSeq(hSession);
    		SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
    	}
    }

	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_pflt_child_first(IN SESSION_HANDLE hSession,
                                                                         IN MBUF_S *pstMBuf,
                                                                         IN USHORT usL3Offset)
{
    IPFW_SERVICE_RET_E enRet;

    enRet = PFLT_PacketIPv4ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
    if (PKT_DROPPED == enRet)
    {
        _kpacket_zonepair_dropstat_dbg("The first packet of child session was dropped"\
                                       "by sec-policy",
                                       ACL_VERSION_ACL4, pstMBuf,
                                       usL3Offset, ASPF_CHILDFIRST_PFLT);        
		/*
        enRet = _kpacket_zonepair_send_icmp4err(pstMBuf);
        */
    }

    return enRet;
}

/* 根据会话信息进行包过滤处理 */
STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_change_filter_by_session(IN MBUF_S *pstMBuf,
                                                                          IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet = PKT_DROPPED; 	
    SESSION_S *pstSession = (SESSION_S *)hSession;	
	SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4;
	APR_PARA_S stAprPara;
    BOOL_T bNeedApr;
	conn_sub_t *csp;	
	csp_key_t *pstcspkey;
	struct in_addr stSrcIP;
    struct in_addr stDstIP;
	UINT uiVrf;
		
	csp       = SESSION_KGetCsp((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    pstcspkey = GET_CSP_KEY(csp);

	uiVrf = pstcspkey->token;
	stSrcIP.s_addr = pstcspkey->src_ip;
	stDstIP.s_addr = pstcspkey->dst_ip;

	bNeedApr = SecPolicy_IP4_IsNeedAPR(uiVrf, &stSrcIP, &stDstIP);	
    if(bNeedApr)
    {
	    stAprPara.uiAppID        = pstSession->uiAppID;
		stAprPara.uiTrustValue   = pstSession->uiTrustValue;
		
		APR_Check(pstMBuf, &stAprPara);
		
		pstSession->uiAppID      = stAprPara.uiAppID;
		pstSession->uiTrustValue = stAprPara.uiTrustValue;
    }

	_kpacket_zonepair_filter_get_matchinfo_Ipv4(hSession, &stSecPolicyPacketIP4);
	enRet = (IPFW_SERVICE_RET_E)PFLT_PacketIPv4ZonePairPktInfoProc(&stSecPolicyPacketIP4);

	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_cfg_change(IN MBUF_S *pstMBuf,
																   IN USHORT usL3Offset,
																   IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet;

	if (!SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_REPLYPKT))
	{
		enRet = PFLT_PacketIPv4ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	}
	else
	{
		enRet = _kpacket_ipv4_zonepair_change_filter_by_session(pstMBuf, hSession);
	}

	if (PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The non-first packet was dropped because of config changes",
							ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_NOFIRST_CFG_CHANGE);

		/* 如果丢包，则删除会话，后续报文重走首包流程（域间关心的应用或者应用组和DPI丢包会话不删除）*/
		SESSION_KDeleteSessionByModule(hSession, SESSION_MODULE_ASPF);
		SESSION_KDeleteSession(hSession);
        /*
		enRet = _kpacket_zonepair_send_icmp4err(pstMBuf);
		*/
	}

	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_aspf_no_first(IN MBUF_S *pstMBuf,
															   IN USHORT usL3Offset,
															   IN SESSION_HANDLE hSession)
{
	aspf_policy_conf_s *pstAspfPolicy;	
	UINT32 uiVrf = 0;
	UINT uiAppID;
	IPFW_SERVICE_RET_E enRet;
	BOOL_T bCfgChanged = BOOL_FALSE;
	
	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_CFGCHECK)) /* 配置变更处理 */
	{
		/* 先清除下alg标记 */
		SESSION_TABLE_UNSET_ALGFLAG((SESSION_S *)hSession, SESSION_MODULE_ASPF);

		pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
    	if (NULL != pstAspfPolicy)
    	{
    		uiAppID = SESSION_KGetAppID(hSession);
    		if (BOOL_TRUE == ASPF_kpolicy_IsAppDetect(uiAppID, pstAspfPolicy))
    		{
    			SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
    		}
    	}
        
		/* 之前已经有会话，没有ASPF业务，再配上ASPF业务，需要重新设上ASPF标记 */
		SESSION_KSetModuleFlag(hSession, SESSION_MODULE_ASPF);
        
		bCfgChanged = BOOL_TRUE;
	}

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID))
	{
		enRet = PKT_DROPPED;
		_kpacket_zonepair_dropstat_dbg("The non-first packet was dropped by ASPF for invalid status",
									   ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_NOFIRST_IV_STATUS);
	}
	else
	{
		if (BOOL_TRUE == bCfgChanged)
		{
			/* 如果配置变更了，需要重新走一遍包过滤 */
			enRet = _kpacket_ipv4_zonepair_cfg_change(pstMBuf, usL3Offset, hSession);
			return enRet;
		}
		/* 正向后续报文需走一遍filter */
		if (!SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_REPLYPKT))
		{
			enRet = PKT_INCOMPLETE;
		}
		else
		{
			enRet = PKT_CONTINUE;
		}
	}
    
	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_pflt_no_first(IN MBUF_S *pstMBuf,
																	  IN USHORT usL3Offset,
																	  IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet;

	enRet = PFLT_PacketIPv4ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	if(PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The non-first packet was dropped "\
								   "by sec-policy",
								   ACL_VERSION_ACL4,
								   pstMBuf, usL3Offset, ASPF_NOFIRST_PFLT);
		
		/* 如果丢包，则删除会话（如果是域间关心的应用组或者应用和DPI丢包的会话则不删除）*/
		SESSION_KDeleteSessionByModule(hSession, SESSION_MODULE_ASPF);		
		SESSION_KDeleteSession(hSession);
		/*
		enRet = _kpacket_zonepair_send_icmp4err(pstMBuf)
		*/
	}
		
	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_aspf_child_no_first(IN MBUF_S *pstMBuf,
																	 IN USHORT usL3Offset,
																	 IN SESSION_HANDLE hSession,
																	 IN SESSION_HANDLE hParentSession)
{
	IPFW_SERVICE_RET_E enRet;
	UINT uiAppID;

	/* 配置变更处理 */
	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_CFGCHECK))
	{
		/* 先清除下alg标记 */
		SESSION_TABLE_UNSET_ALGFLAG((SESSION_S *)hSession, SESSION_MODULE_ASPF);

		uiAppID = SESSION_KGetAppID(hSession);
		if ((BOOL_TRUE == SESSION_KIsAlgFlagSet(hParentSession, SESSION_MODULE_ASPF)) &&
			(BOOL_TRUE == _kpacket_is_app_id_for_alg(uiAppID)))
		{
			SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
		}

		/*之前已经有会话，没有ASPF业务，再配上ASPF业务，需要重新设上ASPF标记*/
		SESSION_KSetModuleFlag(hSession, SESSION_MODULE_ASPF);
	}

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID))
	{
		enRet = PKT_DROPPED;
		_kpacket_zonepair_dropstat_dbg("The non-first packet of child session was dropped by ASPF"\
									   "for invalid status",
									   ACL_VERSION_ACL4,pstMBuf,usL3Offset,ASPF_CHILD_IV_STATUS);
	}
	else
	{
        enRet = _kpacket_ipv4_update_aspf_zonepair_action_by_parent(pstMBuf, hSession, hParentSession, BOOL_FALSE);
	}

	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_pflt_child_no_first(IN MBUF_S *pstMBuf,
																			IN USHORT usL3Offset,
																			IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet;

	enRet = PFLT_PacketIPv4ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	if(PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The non-first packet of child session was dropped"\
								   "by sec-policy",
								   ACL_VERSION_ACL4, pstMBuf,
								   usL3Offset, ASPF_NOCHILDFIRST_PFLT);

		/* 如果丢包，则删除会话（如果是域间关心的应用组或者应用和DPI丢包的会话则不删除）*/
		SESSION_KDeleteSessionByModule(hSession, SESSION_MODULE_ASPF);		
		SESSION_KDeleteSession(hSession);
		/*
		enRet = _kpacket_zonepair_send_icmp4err(pstMBuf);
		*/
	}

	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv4_zonepair_process(IN MBUF_S *pstMBuf, 
                                                         IN USHORT usL3Offset)
{
	IPFW_SERVICE_RET_E enRet; 
	SESSION_HANDLE hSession;
	SESSION_HANDLE hParentSession;
	SESSION_S *pstSession;
    IPS_PARA_S stIpsPara;
 
	hSession = SESSION_KGetSessionFromMbuf(pstMBuf, usL3Offset);

    #if 0
	if(unlikely(SESSION_MBUF_TEST_FLAG(pstMBuf,SESSION_MBUF_ICMPERR)))
	{
		/* 检查是否本机发送的差错报文 */
		if (IP_PKT_HOSTSENDPKT == (MBUF_GET_IP_PKTTYPE(pstMBuf) & IP_PKT_HOSTSENDPKT))
		{
			/* 本机发送的差错报文应被放行，否则会再次受到域间检查丢包 */
			return PKT_CONTINUE;
		}
	}
	#endif

	if (SESSION_INVALID_HANDLE == hSession)
	{
    	/* 无会话的报文处理 */
    	enRet = _kpacket_ipv4_zonepair_pflt_no_session(pstMBuf, usL3Offset);

    	if (PKT_CONTINUE == enRet)
    	{
    		enRet = _kpacket_ipv4_zonepair_aspf_no_session(pstMBuf, usL3Offset);
			if(PKT_CONTINUE == enRet)
			{
			    /*调用DPI处理*/
			    stIpsPara.uiDirect = 0;
				IPS_Check(pstMBuf, &stIpsPara);
                enRet = (IPFW_SERVICE_RET_E)stIpsPara.uiAction;
				if(PKT_DROPPED == enRet)
				{
					_kpacket_zonepair_dropstat_dbg("The packet was dropped because DIM packet deep inspect",
												   ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_PFLT_DIM);
				}
			}
    	}

		return enRet;
	}
	
	hParentSession = SESSION_KGetParentSession(hSession);

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_FIRSTPKT))
	{
		if (SESSION_INVALID_HANDLE == hParentSession)
		{
			/* 普通会话首报文处理 */
			enRet = _kpacket_ipv4_zonepair_pflt_first(hSession, pstMBuf, usL3Offset);
			if (PKT_CONTINUE == enRet)
			{
				enRet = _kpacket_ipv4_zonepair_aspf_first(pstMBuf,usL3Offset,hSession);
			}
		}
		else
		{
			/* 子会话首报文处理 */
			enRet = _kpacket_ipv4_zonepair_aspf_child_first(pstMBuf, usL3Offset, hSession, hParentSession);
			if (PKT_INCOMPLETE == enRet)
			{
				enRet = _kpacket_ipv4_zonepair_pflt_child_first(hSession, pstMBuf, usL3Offset);
			}
		}

		SESSION_KSetModuleFlag(hSession,SESSION_MODULE_ASPF);
	}
	else
	{
		if (SESSION_INVALID_HANDLE == hParentSession)
		{
			/* 父会话后续报文处理 */
			enRet = _kpacket_ipv4_zonepair_aspf_no_first(pstMBuf, usL3Offset, hSession);
			if (PKT_INCOMPLETE == enRet)
			{
				enRet = _kpacket_ipv4_zonepair_pflt_no_first(pstMBuf, usL3Offset, hSession);
			}
		}
        else
        {
            /* 子会话后续报文处理 */
            enRet = _kpacket_ipv4_zonepair_aspf_child_no_first(pstMBuf, usL3Offset, hSession, hParentSession);
            if (PKT_INCOMPLETE == enRet)
            {
                enRet = _kpacket_ipv4_zonepair_pflt_child_no_first(pstMBuf, usL3Offset, hSession);
            }
        }
    }

	if(PKT_CONTINUE == enRet)
	{
		pstSession = hSession;
		if(pstSession == NULL)
		{
			stIpsPara.uiDirect = 0;
		}
		else
		{
			stIpsPara.uiDirect = pstSession->uiDirect;
		}
		/*调用DPI处理*/
	    IPS_Check(pstMBuf, &stIpsPara);
        enRet = (IPFW_SERVICE_RET_E)stIpsPara.uiAction;
		if(PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The packet was dropped because DIM packet deep inspect",
									       ACL_VERSION_ACL4, pstMBuf, usL3Offset, ASPF_PFLT_DIM);
		}
	}

    return enRet;
}


INT ASPF_kpacket_zonepair_Ipv4(struct rte_mbuf *pstRteMbuf)
{
	IPFW_SERVICE_RET_E enRet;
	INT iRet;
	USHORT usL3Offset = 0;
	MBUF_S *pstMBuf;

    if (unlikely(!SESSION_CtrlData_Get()->bSecEnable))
    {
        return FLOW_RET_OK;
    }

    pstMBuf = mbuf_from_rte_mbuf(pstRteMbuf);
	
    /* 标记该报文已进入FW慢转函数处理流程 */
	SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_SLOW_FORWARDING);

	enRet = _kpacket_zonepair_needproc(usL3Offset ,ACL_VERSION_ACL4, pstMBuf);
	if(PKT_INCOMPLETE == enRet)
	{
		enRet = _kpacket_ipv4_zonepair_process(pstMBuf, usL3Offset);
	}

	if (PKT_CONTINUE == enRet)
	{
		enRet = (IPFW_SERVICE_RET_E) SESSION_IpfsEndProc(usL3Offset, pstMBuf);
	}

	if(PKT_CONTINUE != enRet)
	{	
		(VOID)SESSION_KMbufDestroy(pstMBuf);
		/*释放资源，比如会话*/
		iRet = FLOW_RET_ERR;
		SESSION_KStatFailInc(SESSION_STAT_FAIL_FIRST_PATH, SESSION_CtrlData_Get());
	}
	else
    {
		iRet = FLOW_RET_OK;
	}

	return iRet;
}


VOID ASPF_Init(VOID)
{
	debug_aspf_init();
	(VOID)PFLT_Init();
	
	return;
}

/* 根据MBuf获取报文的SECPOLICY_PACKET_IP6_S数据结构 */
STATIC VOID pflt_ipv6_get_adv_pkt_info(IN MBUF_S *pstMBuf,
                                INOUT SECPOLICY_PACKET_IP6_EX_S *pstPktInfo,
                                IN UINT uiAppID)
{
	conn_sub_t *csp;
	csp_key_t *pstcspkey;

    DBGASSERT(NULL != pstMBuf);	
    DBGASSERT(NULL != pstPktInfo);

    memset(pstPktInfo, 0, sizeof(SECPOLICY_PACKET_IP6_EX_S));

	pstPktInfo->stPolicy.uiAppID = uiAppID;

	csp = GET_CSP_FROM_LBUF(pstMBuf);
	pstcspkey = GET_CSP_KEY(csp);
	
	pstPktInfo->stPolicy.uiVxlanID  = pstcspkey->token;	
	pstPktInfo->stPolicy.ucProtocol = pstcspkey->proto;	
    memcpy(&pstPktInfo->stPolicy.stSrcIP6, &(pstcspkey->src_ip), sizeof(struct in6_addr));
    memcpy(&pstPktInfo->stPolicy.stDstIP6, &(pstcspkey->dst_ip), sizeof(struct in6_addr));
	switch (pstPktInfo->stPolicy.ucProtocol)
	{
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		{
			pstPktInfo->stPolicy.usDPort = pstcspkey->dst_port;
			pstPktInfo->stPolicy.usSPort = pstcspkey->src_port;
			break;
		}
		case IPPROTO_ICMPV6:
		{
			pstPktInfo->stPolicy.stIcmp.ucType = csp->csp_type;
			pstPktInfo->stPolicy.stIcmp.ucCode = csp->csp_code;
			break;
		}
		default:
		{
			break;
		}
	}	
 
    return;
}

STATIC SECPOLICY_ACTION_E pflt_ip6_packet_match_zonepair_policy(IN MBUF_S *pstMBuf,
																IN UINT uiAppID)
{
	SECPOLICY_PACKET_IP6_EX_S stSecPolicyPacketIP6;
	SECPOLICY_ACTION_E enAction;  
	
	pflt_ipv6_get_adv_pkt_info(pstMBuf, &stSecPolicyPacketIP6, uiAppID);	
	
	enAction = SecPolicy_Match_IP6(&stSecPolicyPacketIP6.stPolicy);

	return enAction;
}

STATIC IPFW_SERVICE_RET_E PFLT_PacketIPv6ZonePairNormalProc(IN USHORT usIPOff,
        												    IN SESSION_HANDLE hSession,
        													INOUT MBUF_S *pstMBuf)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	SESSION_S *pstSession = (SESSION_S*)hSession;
	SECPOLICY_ACTION_E enAction; 
	APR_PARA_S stAprPara;
	BOOL_T bNeedApr;	
	conn_sub_t *csp;	
	csp_key_t *pstcspkey;
	struct in6_addr stSrcIP6;
    struct in6_addr stDstIP6;
	UINT uiVrf;
	
	if (NULL != pstSession)
	{	
		csp       = SESSION_KGetCsp((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
	    pstcspkey = GET_CSP_KEY(csp);

		uiVrf = pstcspkey->token;		
		memcpy(&stSrcIP6, &(pstcspkey->src_ip), sizeof(struct in6_addr));
		memcpy(&stDstIP6, &(pstcspkey->dst_ip), sizeof(struct in6_addr));
	}
	else
	{
		csp = GET_CSP_FROM_LBUF(pstMBuf);
		pstcspkey = GET_CSP_KEY(csp);

		uiVrf = pstcspkey->token;
		memcpy(&stSrcIP6, &(pstcspkey->src_ip), sizeof(struct in6_addr));
		memcpy(&stDstIP6, &(pstcspkey->dst_ip), sizeof(struct in6_addr));
	}

	bNeedApr = SecPolicy_IP6_IsNeedAPR(uiVrf, &stSrcIP6, &stDstIP6);	
	
    if(bNeedApr)
    {
		if(NULL != pstSession)
		{
			stAprPara.uiAppID      = pstSession->uiAppID;
			stAprPara.uiTrustValue = pstSession->uiTrustValue;
			
			APR_Check(pstMBuf, &stAprPara);
			
		    pstSession->uiAppID = stAprPara.uiAppID;
			pstSession->uiTrustValue = stAprPara.uiTrustValue;
		}
		else
		{		
			stAprPara.uiAppID = APR_ID_INVALID;
		    stAprPara.uiTrustValue = APR_TRUST_INIT;
			APR_Check(pstMBuf, &stAprPara);		
		}
    }
	else
	{
		stAprPara.uiAppID = APR_ID_INVALID;
	}
	
	enAction = pflt_ip6_packet_match_zonepair_policy(pstMBuf, stAprPara.uiAppID);
	
	/* DENY的报文不建快转 */
	if (SECPOLICY_ACTION_DENY == enAction)	
	{
		enRet = PKT_DROPPED;
	}

	return enRet;
}


STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_pflt_no_session(IN MBUF_S *pstMBuf, 
																		IN USHORT usL3Offset)
{
	IPFW_SERVICE_RET_E enRet;

	enRet = PFLT_PacketIPv6ZonePairNormalProc(usL3Offset, SESSION_INVALID_HANDLE, pstMBuf);
	if(PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The packet that matches no session was dropped "\
								   	   "by sec-policy",
								       ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_NOSESSION_PFLT);
        /*
		enRet = _kpacket_zonepair_send_icmp6err(pstMBuf);
		*/
	}
	

	return enRet;
}

/* 判断是否要将报文丢弃 */
STATIC BOOL_T ASPF_kpacket_ipv6_IsDropPacket(IN MBUF_S *pstMBuf, IN USHORT usL3Offset)
{
    TCPHDR_S *pstTcpHdr;
    struct icmphdr *pstIcmp6Hdr;
    UCHAR ucFlags;
    UCHAR ucL4Proto;
    USHORT usL4Offset;
    BOOL_T bDropPacket = BOOL_FALSE;
    ULONG ulRet = ERROR_FAILED;
	IP6_S *pstIP6;

    ulRet = ASPF_kutil_ipv6_GetL4Proto(pstMBuf, usL3Offset, &ucL4Proto, &usL4Offset);
    if(ERROR_SUCCESS != ulRet)
    {
        return bDropPacket;
    }

    if(IPPROTO_TCP == ucL4Proto)
    {
        pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, usL4Offset, TCPHDR_S *);
        ucFlags = (pstTcpHdr->th_flags) & (~ASPF_TCP_NOCARE_FLAGS) & (~TH_URG);
        if((TH_SYN != ucFlags) && (TH_ACK != ucFlags))
        {
            bDropPacket = BOOL_TRUE;
        }
    }
    else if (IPPROTO_ICMPV6 == ucL4Proto)
    {
        pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf, usL4Offset, struct icmphdr *);
        if(BOOL_TRUE == ASPF_kutil_ipv6_IsIcmpv6Replay(pstIcmp6Hdr->icmp_type, pstIcmp6Hdr->icmp_code))
        {
			pstIP6 = MBUF_BTOD_OFFSET(pstMBuf, usL3Offset, IP6_S *);
			/* 针对ping FF02::1 FFO2::2地址，增加判断，放行echo reply报文，否则ping报文不通
			   只要有一个地址不是link-local地址就Drop */
	        if((BOOL_TRUE != IN6ADDR_IsLinkLocal(&pstIP6->stIp6Dst) ||
			   (BOOL_TRUE != IN6ADDR_IsLinkLocal(&pstIP6->stIp6Src))))
	        {
				bDropPacket = BOOL_TRUE;
			}
        }
    }
  
    return bDropPacket;
}

/*** Description∶对mbuf进行tcp syn-check检查 ***/
STATIC IPFW_SERVICE_RET_E ASPF_kpacket_ipv6_tcp_syn_Check(IN MBUF_S *pstMBuf, IN USHORT usL3Offset)
{
	BOOL_T bTcpPacket;
	BOOL_T bTcpSynPacket;

	ULONG ulErr;
	UCHAR ucL4Proto; 
	USHORT usL4Offset; 

	bTcpPacket = BOOL_FALSE;
	bTcpSynPacket = BOOL_FALSE;
	
	ulErr = ASPF_kutil_ipv6_GetL4Proto(pstMBuf,usL3Offset, &ucL4Proto, &usL4Offset);

	if ((ERROR_SUCCESS == ulErr) && (IPPROTO_TCP == ucL4Proto))
	{
		_kpacket_is_tcp_syn_packet(pstMBuf, usL4Offset, &bTcpPacket, &bTcpSynPacket);
	}

	if ((BOOL_TRUE == bTcpPacket) && (BOOL_TRUE != bTcpSynPacket))
	{
		return PKT_DROPPED;
	}

	return PKT_CONTINUE;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_aspf_no_session(IN MBUF_S *pstMBuf, IN USHORT usL3Offset)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	aspf_policy_conf_s *pstAspfPolicy;
	UINT32 uiVrf = 0;
	BOOL_T bDropPacket;

#if 0
	/* 非本机发送的报文才做TCP SYN-CHECK或ICMP-ERROR CHECK检查，否则直接放行 */
	uiPktType = MBUF_GET_IP6_PKTTYPE(pstMBuf);
	if (IP6_PKT_HOSTSENDPKT == (uiPktType & IP6_PKT_HOSTSENDPKT))
	{
		return enRet;
	}
#endif

	pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
	if (NULL == pstAspfPolicy)
	{
		return enRet;
	}

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID))
	{
		bDropPacket = ASPF_kpacket_ipv6_IsDropPacket(pstMBuf, usL3Offset);
		if (BOOL_TRUE == bDropPacket)
		{
			_kpacket_zonepair_dropstat_dbg("The first packet was dropped by ASPF for invalid status",
										   ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_FIRST_IV_STATUS);
			return PKT_DROPPED;
		}
	}

	/* icmp-error drop 
	if (BOOL_TRUE == pstKPolicy->bIcmpErrDrop)
	{
		enRet = ASPF_kpacket_icmp_err_Check(pstMBuf);
		if (PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The packet that matches no session was dropped by ASPF,"\
										   "because the ICMP error checking failed", ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_NOSESSION_ICMPERR);
			return enRet;
		}
	}*/

	/* tcp syn-check */
	if (BOOL_TRUE == pstAspfPolicy->bTcpSynCheck)
	{
        enRet = ASPF_kpacket_ipv6_tcp_syn_Check(pstMBuf, usL3Offset);
    	if (PKT_DROPPED == enRet)
    	{
    		_kpacket_zonepair_dropstat_dbg("The packet that matches no session was dropped by ASPF,"\
    								       "because the TCP SYN checking failed",
    								       ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_NOSESSION_SYN);
    	}
	}
	
	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_pflt_first(IN SESSION_HANDLE hSession, 
																   IN MBUF_S *pstMBuf, 
																   IN USHORT usL3Offset) 
{
	IPFW_SERVICE_RET_E enRet;
	
	enRet = PFLT_PacketIPv6ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	if(PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The first packet was dropped by sec-policy",
								       ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_FIRST_PFLT);
        /*
		enRet = _kpacket_zonepair_send_icmp6err(pstMBuf);
		*/
	}

	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_aspf_first(IN MBUF_S *pstMBuf,
															IN USHORT usL3Offset,
															INOUT SESSION_HANDLE hSession)
{
	UINT uiAppID;
	aspf_policy_conf_s *pstAspfPolicy;
	UINT32 uiVrf = 0;
	
	pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
	if (NULL == pstAspfPolicy)
	{
		return PKT_CONTINUE;
	}

	/* tcp syn-check */
	if ((BOOL_TRUE == pstAspfPolicy->bTcpSynCheck) &&
		(SESSION_GetL4Type(hSession)== SESSION_L4_TYPE_TCP))
	{
		IPFW_SERVICE_RET_E enRet;
		enRet = ASPF_kpacket_ipv6_tcp_syn_Check(pstMBuf,usL3Offset);
		if (PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The first packet was dropped by ASPF,"\
									   "because the TCP SYN checking failed",
									   ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_FTRST_SYN);
			return PKT_DROPPED;
		}
	}

	/* 根据策略获取会话的动作 */
	uiAppID = SESSION_KGetAppID(hSession);
	if (BOOL_TRUE == ASPF_kpolicy_IsAppDetect(uiAppID, pstAspfPolicy))
	{
		ASPF_SetCfgSeq(hSession);
		SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
	}
	
    return PKT_CONTINUE;
}

STATIC VOID _kpacket_zonepair_filter_get_matchinfo_Ipv6(IN SESSION_HANDLE hSession,
                       				             OUT SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6)
{
	UCHAR ucProtocol;
	conn_sub_t *csp;
	csp_key_t *pstcspkey;
    SESSION_S *pstSession = (SESSION_S *)hSession;	
	
    memset(pstSecPolicyPacketIP6, 0, sizeof(SECPOLICY_PACKET_IP6_S));

	csp = SESSION_KGetCsp(hSession, SESSION_DIR_ORIGINAL);
	pstcspkey = &(csp->key);

	pstSecPolicyPacketIP6->uiVxlanID = pstcspkey->token;
	ucProtocol = pstSecPolicyPacketIP6->ucProtocol = pstcspkey->proto;
	memcpy(&pstSecPolicyPacketIP6->stSrcIP6, &(pstcspkey->src_ip), sizeof(struct in6_addr));
	memcpy(&pstSecPolicyPacketIP6->stDstIP6, &(pstcspkey->dst_ip), sizeof(struct in6_addr));

	if ((IPPROTO_TCP == ucProtocol) || (IPPROTO_UDP == ucProtocol))
	{
		pstSecPolicyPacketIP6->usSPort = ntohs(pstcspkey->src_port); 
		pstSecPolicyPacketIP6->usDPort = ntohs(pstcspkey->dst_port); 
	}
	else if (IPPROTO_ICMPV6 == ucProtocol)
	{
		pstSecPolicyPacketIP6->stIcmp.ucType = csp->csp_type;
		pstSecPolicyPacketIP6->stIcmp.ucCode = csp->csp_code;
	}

    pstSecPolicyPacketIP6->uiAppID = pstSession->uiAppID;

	return;
}
												 
STATIC ULONG PFLT_PacketIPv6ZonePairPktInfoProc(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6)
{
	IPFW_SERVICE_RET_E enIpfwRet = PKT_DROPPED;
	SECPOLICY_ACTION_E enAction;  	
	
	enAction = SecPolicy_Match_IP6(pstSecPolicyPacketIP6);
    
	if (SECPOLICY_ACTION_PERMIT == enAction)
	{
		enIpfwRet = PKT_CONTINUE;
	}
	else
	{
		enIpfwRet = PKT_DROPPED;
	}

	return (ULONG)enIpfwRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_update_aspf_zonepair_action_by_parent(IN MBUF_S *pstMBuf,
																              IN SESSION_HANDLE hSession,
															                  IN SESSION_HANDLE hParentSession,
																              IN BOOL_T bFirstPkt)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	ASPF_CTRL_S *pstAspfCtrl;
	SECPOLICY_PACKET_IP6_S stSecPolicyPacketIP6;

	pstAspfCtrl = ASPF_CtrlData_Get();

	DBGASSERT(NULL != pstAspfCtrl);

	if (unlikely(pstAspfCtrl->ucCfgSeq != ((SESSION_S *)hParentSession)->ucAspfCfgSeq))
	{
		_kpacket_zonepair_filter_get_matchinfo_Ipv6(hParentSession, &stSecPolicyPacketIP6);
		enRet = (IPFW_SERVICE_RET_E)PFLT_PacketIPv6ZonePairPktInfoProc(&stSecPolicyPacketIP6);

		/* 如果根据父会话的最新FILTER策略需要丢包，则使子会话后续报文直接走FILTER */
		if (PKT_CONTINUE != enRet)
		{
			enRet = PKT_INCOMPLETE;
		}

		ASPF_SetCfgSeq(hParentSession);
	}

	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_tcp_syn_check(IN MBUF_S *pstMBuf,
															   IN USHORT usL3Offset,
															   IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet = PKT_CONTINUE;
	aspf_policy_conf_s *pstAspfPolicy;
	UINT32 uiVrf;
	
	pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
	if (NULL == pstAspfPolicy)
	{
		return PKT_CONTINUE;
	}

	/* tcp syn-check */
	if ((BOOL_TRUE == pstAspfPolicy->bTcpSynCheck) &&
	    (SESSION_GetL4Type(hSession) == SESSION_L4_TYPE_TCP))
	{
		enRet = ASPF_kpacket_ipv6_tcp_syn_Check(pstMBuf, usL3Offset);
		if (PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The first packet of child session was dropped by ASPF,"\
			                               "because the TCP SYN checking failed",
										   ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_CHILD_SYN);
			return PKT_DROPPED;
		}
	}

	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_aspf_child_first(IN MBUF_S *pstMBuf,
																  IN USHORT usL3Offset,
																  IN SESSION_HANDLE hSession,
																  IN SESSION_HANDLE hParentSession)
{
	UINT uiAppID;
    IPFW_SERVICE_RET_E enRet;	

    enRet = _kpacket_ipv6_update_aspf_zonepair_action_by_parent(pstMBuf, hSession, hParentSession,BOOL_TRUE);	
    if (PKT_CONTINUE != enRet)	
    {       
        enRet = _kpacket_ipv6_zonepair_tcp_syn_check(pstMBuf, usL3Offset, hSession);       
        if (PKT_CONTINUE == enRet)      
        {           
            /* filter process */            
            enRet = PKT_INCOMPLETE;     
        }  
    }
    else
    {
        enRet = PKT_CONTINUE;     

    	/* 如果父会话需要做ALG，并且子会话的应用层协议支持ALG，则认为子会话也需要做ALG*/
    	uiAppID = SESSION_KGetAppID(hSession);
    	if ((BOOL_TRUE == SESSION_KIsAlgFlagSet(hParentSession, SESSION_MODULE_ASPF)) &&
    		(BOOL_TRUE == _kpacket_is_app_id_for_alg(uiAppID)))
    	{
    		ASPF_SetCfgSeq(hSession);
    		SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
    	}
    }

	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_pflt_child_first(IN SESSION_HANDLE hSession,
                                                                         IN MBUF_S *pstMBuf,
                                                                         IN USHORT usL3Offset)
{
    IPFW_SERVICE_RET_E enRet;

    enRet = PFLT_PacketIPv6ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
    if (PKT_DROPPED == enRet)
    {
        _kpacket_zonepair_dropstat_dbg("The first packet of child session was dropped"\
                                       "by sec-policy",
                                       ACL_VERSION_ACL6, pstMBuf,
                                       usL3Offset, ASPF_CHILDFIRST_PFLT);
		/*
        enRet = _kpacket_zonepair_send_icmp6err(pstMBuf);
        */
    }

    return enRet;
}

/* 根据会话信息进行包过滤处理 */
STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_change_filter_by_session(IN MBUF_S *pstMBuf,
                                                                          IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet = PKT_DROPPED; 	
    SESSION_S *pstSession = (SESSION_S *)hSession;	
	SECPOLICY_PACKET_IP6_S stSecPolicyPacketIP6;
	APR_PARA_S stAprPara;
    BOOL_T bNeedApr;
	conn_sub_t *csp;	
	csp_key_t *pstcspkey;
	struct in6_addr stSrcIP6;
    struct in6_addr stDstIP6;
	UINT uiVrf;

	csp       = SESSION_KGetCsp((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    pstcspkey = GET_CSP_KEY(csp);

	uiVrf = pstcspkey->token;
    memcpy(&stSrcIP6, &(pstcspkey->src_ip), sizeof(struct in6_addr));
	memcpy(&stDstIP6, &(pstcspkey->dst_ip), sizeof(struct in6_addr));

	bNeedApr = SecPolicy_IP6_IsNeedAPR(uiVrf, &stSrcIP6, &stDstIP6);	
    if(bNeedApr)
    {
	    stAprPara.uiAppID        = pstSession->uiAppID;
		stAprPara.uiTrustValue   = pstSession->uiTrustValue;
		
		APR_Check(pstMBuf, &stAprPara);
		
		pstSession->uiAppID      = stAprPara.uiAppID;
		pstSession->uiTrustValue = stAprPara.uiTrustValue;
    }

	_kpacket_zonepair_filter_get_matchinfo_Ipv6(hSession, &stSecPolicyPacketIP6);
	enRet = (IPFW_SERVICE_RET_E)PFLT_PacketIPv6ZonePairPktInfoProc(&stSecPolicyPacketIP6);

	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_cfg_change(IN MBUF_S *pstMBuf,
																   IN USHORT usL3Offset,
																   IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet;

	if (!SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_REPLYPKT))
	{
		enRet = PFLT_PacketIPv6ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	}
	else
	{
		enRet = _kpacket_ipv6_zonepair_change_filter_by_session(pstMBuf, hSession);
	}

	if (PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The non-first packet was dropped because of config changes",
							ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_NOFIRST_CFG_CHANGE);
	
		/* 如果丢包，则删除会话，后续报文重走首包流程（域间关心的应用或者应用组和DPI丢包会话不删除）*/
		SESSION_KDeleteSessionByModule(hSession, SESSION_MODULE_ASPF);
		SESSION_KDeleteSession(hSession);
        /*
		enRet = _kpacket_zonepair_send_icmp6err(pstMBuf);
		*/
	}

	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_aspf_no_first(IN MBUF_S *pstMBuf,
															   IN USHORT usL3Offset,
															   IN SESSION_HANDLE hSession)
{
	aspf_policy_conf_s *pstAspfPolicy;
	UINT32 uiVrf = 0;	
	UINT uiAppID;
	IPFW_SERVICE_RET_E enRet;
	BOOL_T bCfgChanged = BOOL_FALSE;

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_CFGCHECK)) /* 配置变更处理 */
	{
		/* 先清除下alg标记 */
		SESSION_TABLE_UNSET_ALGFLAG((SESSION_S *)hSession, SESSION_MODULE_ASPF);

		pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
    	if (NULL != pstAspfPolicy)
    	{
    		uiAppID = SESSION_KGetAppID(hSession);
    		if (BOOL_TRUE == ASPF_kpolicy_IsAppDetect(uiAppID, pstAspfPolicy))
    		{
    			SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
    		}
    	}
        
		/* 之前已经有会话，没有ASPF业务，再配上ASPF业务，需要重新设上ASPF标记 */
		SESSION_KSetModuleFlag(hSession, SESSION_MODULE_ASPF);
        
		bCfgChanged = BOOL_TRUE;
	}

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID))
	{
		enRet = PKT_DROPPED;
		_kpacket_zonepair_dropstat_dbg("The non-first packet was dropped by ASPF for invalid status",
									   ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_NOFIRST_IV_STATUS);
	}
	else
	{
		if (BOOL_TRUE == bCfgChanged)
		{
			/* 如果配置变更了，需要重新走一遍包过滤 */
			enRet = _kpacket_ipv6_zonepair_cfg_change(pstMBuf, usL3Offset, hSession);
			return enRet;
		}
		/* 正向后续报文需走一遍filter */
		if (!SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_REPLYPKT))
		{
			enRet = PKT_INCOMPLETE;
		}
		else
		{
			enRet = PKT_CONTINUE;
		}
	}
    
	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_pflt_no_first(IN MBUF_S *pstMBuf,
																	  IN USHORT usL3Offset,
																	  IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet;

	enRet = PFLT_PacketIPv6ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	if(PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The non-first packet was dropped "\
								   "by sec-policy",
								   ACL_VERSION_ACL6,
								   pstMBuf, usL3Offset, ASPF_NOFIRST_PFLT);

		/* 如果丢包，则删除会话（如果是域间关心的应用组或者应用和DPI丢包的会话则不删除）*/
		SESSION_KDeleteSessionByModule(hSession, SESSION_MODULE_ASPF);
        SESSION_KDeleteSession(hSession);
		/*
		enRet = _kpacket_zonepair_send_icmp6err(pstMBuf)
		*/
	}
		
	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_aspf_child_no_first(IN MBUF_S *pstMBuf,
																	 IN USHORT usL3Offset,
																	 IN SESSION_HANDLE hSession,
																	 IN SESSION_HANDLE hParentSession)
{
	IPFW_SERVICE_RET_E enRet;
	UINT uiAppID;

	/* 配置变更处理 */
	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_CFGCHECK))
	{
		/* 先清除下alg标记 */
		SESSION_TABLE_UNSET_ALGFLAG((SESSION_S *)hSession, SESSION_MODULE_ASPF);

		uiAppID = SESSION_KGetAppID(hSession);
		if ((BOOL_TRUE == SESSION_KIsAlgFlagSet(hParentSession, SESSION_MODULE_ASPF)) &&
			(BOOL_TRUE == _kpacket_is_app_id_for_alg(uiAppID)))
		{
			SESSION_KSetAlgFlag(hSession, SESSION_MODULE_ASPF);
		}

		/*之前已经有会话，没有ASPF业务，再配上ASPF业务，需要重新设上ASPF标记*/
		SESSION_KSetModuleFlag(hSession, SESSION_MODULE_ASPF);
	}

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_INVALID))
	{
		enRet = PKT_DROPPED;
		_kpacket_zonepair_dropstat_dbg("The non-first packet of child session was dropped by ASPF"\
									   "for invalid status",
									   ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_CHILD_IV_STATUS);
	}
	else
	{
        enRet = _kpacket_ipv6_update_aspf_zonepair_action_by_parent(pstMBuf, hSession, hParentSession, BOOL_FALSE);
	}

	return enRet;
}

STATIC INLINE IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_pflt_child_no_first(IN MBUF_S *pstMBuf,
																			IN USHORT usL3Offset,
																			IN SESSION_HANDLE hSession)
{
	IPFW_SERVICE_RET_E enRet;

	enRet = PFLT_PacketIPv6ZonePairNormalProc(usL3Offset, hSession, pstMBuf);
	if(PKT_DROPPED == enRet)
	{
		_kpacket_zonepair_dropstat_dbg("The non-first packet of child session was dropped"\
									   "by sec-policy",
									   ACL_VERSION_ACL6, pstMBuf,
									   usL3Offset, ASPF_NOCHILDFIRST_PFLT);

		/* 如果丢包，则删除会话（如果是域间关心的应用组或者应用和DPI丢包的会话则不删除）*/
		SESSION_KDeleteSessionByModule(hSession, SESSION_MODULE_ASPF);
		SESSION_KDeleteSession(hSession);
		/*
		enRet = _kpacket_zonepair_send_icmp6err(pstMBuf);
		*/
	}

	return enRet;
}

STATIC IPFW_SERVICE_RET_E _kpacket_ipv6_zonepair_process(IN MBUF_S *pstMBuf, 
                                                         IN USHORT usL3Offset)
{
	IPFW_SERVICE_RET_E enRet; 
	SESSION_HANDLE hSession;
	SESSION_HANDLE hParentSession;
	SESSION_S *pstSession;
    IPS_PARA_S stIpsPara;
	hSession = SESSION6_KGetSessionFromMbuf(pstMBuf, usL3Offset);

	if (SESSION_INVALID_HANDLE == hSession)
	{
    	/* 无会话的报文处理 */
    	enRet = _kpacket_ipv6_zonepair_pflt_no_session(pstMBuf, usL3Offset);

    	if (PKT_CONTINUE == enRet)
    	{
    		enRet = _kpacket_ipv6_zonepair_aspf_no_session(pstMBuf, usL3Offset);
			if (PKT_CONTINUE == enRet)
			{
			    /*调用DPI处理*/
			    stIpsPara.uiDirect = 0;
	            IPS_Check(pstMBuf, &stIpsPara);
	            enRet = (IPFW_SERVICE_RET_E)stIpsPara.uiAction;
				if (PKT_DROPPED == enRet)
				{
					_kpacket_zonepair_dropstat_dbg("The packet was dropped because DIM packet deep inspect",
												   ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_PFLT_DIM);
				}
			}
    	}

		return enRet;
	}
	
	hParentSession = SESSION_KGetParentSession(hSession);

	if (SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_FIRSTPKT))
	{
		if (SESSION_INVALID_HANDLE == hParentSession)
		{
			/* 普通会话首报文处理 */
			enRet = _kpacket_ipv6_zonepair_pflt_first(hSession, pstMBuf, usL3Offset);
			if (PKT_CONTINUE == enRet)
			{
				enRet = _kpacket_ipv6_zonepair_aspf_first(pstMBuf,usL3Offset,hSession);
			}
		}
		else
		{
			/* 子会话首报文处理 */
			enRet = _kpacket_ipv6_zonepair_aspf_child_first(pstMBuf, usL3Offset, hSession, hParentSession);
			if (PKT_INCOMPLETE == enRet)
			{
				enRet = _kpacket_ipv6_zonepair_pflt_child_first(hSession, pstMBuf, usL3Offset);
			}
		}

		SESSION_KSetModuleFlag(hSession, SESSION_MODULE_ASPF);
	}
	else
	{
		if (SESSION_INVALID_HANDLE == hParentSession)
		{
			/* 父会话后续报文处理 */
			enRet = _kpacket_ipv6_zonepair_aspf_no_first(pstMBuf, usL3Offset, hSession);
			if (PKT_INCOMPLETE == enRet)
			{
				enRet = _kpacket_ipv6_zonepair_pflt_no_first(pstMBuf, usL3Offset, hSession);
			}
		}
        else
        {
            /* 子会话后续报文处理 */
            enRet = _kpacket_ipv6_zonepair_aspf_child_no_first(pstMBuf, usL3Offset, hSession, hParentSession);
            if (PKT_INCOMPLETE == enRet)
            {
                enRet = _kpacket_ipv6_zonepair_pflt_child_no_first(pstMBuf, usL3Offset, hSession);
            }
        }
    }

	if (PKT_CONTINUE == enRet)
	{
		pstSession = hSession;
		if(pstSession == NULL)
		{
			stIpsPara.uiDirect = 0;
		}
		else
		{
			stIpsPara.uiDirect = pstSession->uiDirect;
		}
		/*调用DPI处理*/
	    IPS_Check(pstMBuf, &stIpsPara);
        enRet = (IPFW_SERVICE_RET_E)stIpsPara.uiAction;
		if (PKT_DROPPED == enRet)
		{
			_kpacket_zonepair_dropstat_dbg("The packet was dropped because DIM packet deep inspect",
									       ACL_VERSION_ACL6, pstMBuf, usL3Offset, ASPF_PFLT_DIM);
		}
	}

    return enRet;
}

INT ASPF_kpacket_zonepair_Ipv6(struct rte_mbuf *pstRteMbuf)
{
	IPFW_SERVICE_RET_E enRet;
	INT iRet;
	USHORT usL3Offset = 0;
	MBUF_S *pstMBuf;

    if (unlikely(!SESSION_CtrlData_Get()->bSecEnable))
    {
        return FLOW_RET_OK;
    }

    pstMBuf = mbuf_from_rte_mbuf(pstRteMbuf);
	
    /* 标记该报文已进入FW慢转函数处理流程 */
	SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_SLOW_FORWARDING);

	enRet = _kpacket_zonepair_needproc(usL3Offset, ACL_VERSION_ACL6, pstMBuf);
	if(PKT_INCOMPLETE == enRet)
	{
		enRet = _kpacket_ipv6_zonepair_process(pstMBuf, usL3Offset);
	}

	if (PKT_CONTINUE == enRet)
	{
		enRet = (IPFW_SERVICE_RET_E)SESSION6_IpfsEndProc(usL3Offset, pstMBuf);
	}

	if(PKT_CONTINUE != enRet)
	{	
		(VOID)SESSION_KMbufDestroy(pstMBuf);
		/*释放资源，比如会话*/
		iRet = FLOW_RET_ERR;
		SESSION6_KStatFailInc(SESSION_STAT_FAIL_FIRST_PATH, SESSION_CtrlData_Get());
	}
	else
    {
		iRet = FLOW_RET_OK;
	}

	return iRet;
}
