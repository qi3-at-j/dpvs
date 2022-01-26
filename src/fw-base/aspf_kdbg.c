
#include <rte_ip.h>

#include "baseype.h"
#include "session.h"
#include "acl.h"
#include "aspf.h"
#include "ffilter.h"
#include "ipv4.h"
#include "session_kcore.h"
#include "aspf_kdbg.h"
#include "debug.h"
#include "ip6_util.h"


/*TCP Flags */
#define  FLAG_FIN               0x01
#define  FLAG_SYN               0x02
#define  FLAG_RST               0x04
#define  FLAG_ACK               0x10
#define  FLAG_FIN_ACK           0x11
#define  FLAG_SYN_ACK           0x12
#define  FLAG_RST_ACK           0x14
#define  FLAG_SYN_URG           0x22
#define  FLAG_ACK_URG           0x30
#define  FLAG_FIN_ACK_URG       0x31
#define  SESSION_DBG_FLAG_SIZE  20UL


#define aspf_mark_pak(lhdr)   do {  \
	this_ffilter_show_this_pak = 0; \
    flow_mark_pak_func(lhdr);       \
}while (0)


/* 用户输出debug信息的报文信息 */
typedef struct tagASPF_KDBG_PACKET_INFO
{
    CHAR szSrcIP[INET6_ADDRSTRLEN];
    CHAR szDstIP[INET6_ADDRSTRLEN];
    //CHAR szVPNName[L3VPN_MAX_VRFNAME_LEN + 1];
    USHORT usSrcPort;
    USHORT usDstPort;
    CHAR szProtoName[APR_PROTO_NAME_MAX_LEN + 1];
    UCHAR ucProtoID;
    UCHAR ucFlag;
    UINT  uiSeq;
}ASPF_KDBG_PACKET_INFO_S;


STATIC CHAR *g_pcDbgZonepairFmt  = "\r\n %s %s:%s."
                                   "Packet Info:"
                                   "Src-IP=%s, Dst-IP=%s, "
                                   "Src-Port=%d, Dst-Port=%d. Protocol=%s(%d).\r\n";

STATIC CHAR *g_pcDbgZonepairAddFlagFmt  = "\r\n %s %s:%s."
                                          "Packet Info:"
                                          "Src-IP=%s, Dst-IP=%s, "
                                          "Src-Port=%d, Dst-Port=%d. Protocol=%s(%d). Flag=%s. Seq=%u.\r\n";


#define ASPF_VLAN_INFO_LEN  31



extern VOID APR_GetProtoNameByID(IN UCHAR ucProto, OUT CHAR szName[APR_PROTO_NAME_MAX_LEN+1]);

#if 0
/* 检测mbuf是否匹配acl */
STATIC BOOL_T _kdbg_is_packet_match_acl(IN ACL_VERSION_E enAclVer,
                                        IN MBUF_S *pstMBuf,
                                        IN USHORT usL3Offset,
                                        IN const ASPF_CTRL_S *pstAspfCtrl)
{
    ULONG ulErr;
    BOOL_T bMatch;
    ACL_ACTION_E enRuleAction;

    bMatch = BOOL_FALSE;
    /* 如果没有配置acl-number,认为全部匹配 */
    if(ACL_GROUP_INVALID_INDEX == pstAspfCtrl->stDbgInfo.uiAclNum)
    {
        bMatch = BOOL_TRUE;
    }
    else
    {
        ulErr = ACL_MatchWithMbuf(enAclVer,
                                  pstAspfCtrl->stDbgInfo.uiAclNum,
                                  pstMBuf,
                                  usL3Offset,
                                  BOOL_TRUE,
                                  NULL,
                                  &enRuleAction);
        if(ERROR_SUCCESS == ulErr) && (ACL_PERMIT == enRuleAction)
        {
            bMatch = BOOL_TRUE;
        }
    }

    return bMatch;
}
#endif

STATIC ULONG ASPF_KGetTcpFlagFromMbuf(IN MBUF_S* pstMBuf, IN UINT uiL3OffSet, OUT UCHAR *pucFlag, OUT UINT *puiSeq)
{
    UINT uiL4OffSet;
    struct iphdr *pstIP;
    UINT uiIPHLen;
    TCPHDR_S *pstTcpHdr;
    UCHAR ucHdrProto = IPPROTO_IPV6;
    UINT uiHdrOff = uiL3OffSet;
    UCHAR ucFamily;
    ULONG ulRet;
    conn_sub_t *csp;
    
	csp = GET_CSP_FROM_LBUF(pstMBuf);
	ucFamily = GET_CSP_FAMILY(csp); 
    if(AF_INET == ucFamily)
    {
        pstIP = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, struct iphdr *);

        uiIPHLen = pstIP->ihl;
        uiIPHLen = uiIPHLen << 2;

        if(uiIPHLen > MBUF_GET_TOTALDATASIZE(pstMBuf) - uiL3OffSet)
        {
            return ERROR_FAILED;
        }

        uiL4OffSet = uiL3OffSet + uiIPHLen;
    }
    else
    {
        ulRet = IP6_GetLastHdr(pstMBuf, &uiHdrOff, &ucHdrProto);
        if(ERROR_SUCCESS != ulRet)
        {
            return ERROR_FAILED;
        }

        uiL4OffSet = uiHdrOff;
    }

    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);

    *pucFlag = pstTcpHdr->th_flags;
    *puiSeq  = pstTcpHdr->th_seq;

    return ERROR_SUCCESS;
}

STATIC ULONG _kdbg_get_packet_info_from_mbuf(IN ACL_VERSION_E enAclVer,
                                             IN MBUF_S *pstMBuf,
                                             IN USHORT usL3Offset,
                                             OUT ASPF_KDBG_PACKET_INFO_S *pstPacketInfo)
{
    SESSION_TUPLE_S stTuple;
    UCHAR ucFlag = 0;
    UINT uiSeq = 0;

    if(ERROR_SUCCESS != SESSION_KGetTupleFromMbuf(pstMBuf, usL3Offset, &stTuple))
    {
        return ERROR_FAILED;
    }

    if(IPPROTO_TCP == stTuple.ucProtocol)
    {
        (VOID)ASPF_KGetTcpFlagFromMbuf(pstMBuf, usL3Offset, &ucFlag, &uiSeq);
    }

    pstPacketInfo->usSrcPort = ntohs(stTuple.unL4Src.usAll);    
    pstPacketInfo->usDstPort = ntohs(stTuple.unL4Dst.usAll);

    pstPacketInfo->szSrcIP[0] = '\0';
    pstPacketInfo->szDstIP[0] = '\0';
    if(ACL_VERSION_ACL4 == enAclVer)
    {
        (VOID)inet_ntop(AF_INET, &(stTuple.unL3Src.stin), pstPacketInfo->szSrcIP, (UINT)INET6_ADDRSTRLEN);        
        (VOID)inet_ntop(AF_INET, &(stTuple.unL3Dst.stin), pstPacketInfo->szDstIP, (UINT)INET6_ADDRSTRLEN);
    }
    else
    {
        (VOID)inet_ntop(AF_INET6, &(stTuple.unL3Src.stin6), pstPacketInfo->szSrcIP, (UINT)INET6_ADDRSTRLEN);        
        (VOID)inet_ntop(AF_INET6, &(stTuple.unL3Dst.stin6), pstPacketInfo->szDstIP, (UINT)INET6_ADDRSTRLEN);
    }

    (VOID)APR_GetProtoNameByID(stTuple.ucProtocol, pstPacketInfo->szProtoName);
    pstPacketInfo->ucProtoID = stTuple.ucProtocol;
    pstPacketInfo->ucFlag = ucFlag;
    pstPacketInfo->uiSeq = ntohl(uiSeq);
    return ERROR_SUCCESS;
}

/* Flag转换为直接可读的字符串 */
STATIC VOID ASPF_kdbg_GetFlagName(IN UCHAR ucFlag, INOUT CHAR *pszFlagName)
{
    UINT uiFlagFind = (UINT)(ucFlag);
    switch (uiFlagFind)
    {
        case FLAG_FIN:
        {
            memcpy(pszFlagName, "FIN", sizeof("FIN"));
            break;
        }                
        case FLAG_ACK:
        {
            memcpy(pszFlagName, "ACK", sizeof("ACK"));
            break;
        }
        case FLAG_SYN:
        {
            memcpy(pszFlagName, "SYN", sizeof("SYN"));
            break;
        }
        case FLAG_RST:
        {
            memcpy(pszFlagName, "RST", sizeof("RST"));
            break;
        }
        case FLAG_FIN_ACK:
        {
            memcpy(pszFlagName, "FIN/ACK", sizeof("FIN/ACK"));
            break;
        }
        case FLAG_SYN_ACK:
        {
            memcpy(pszFlagName, "SYN/ACK", sizeof("SYN/ACK"));
            break;
        }
        case FLAG_RST_ACK:
        {
            memcpy(pszFlagName, "RST/ACK", sizeof("RST/ACK"));
            break;
        }
        case FLAG_SYN_URG:
        {
            memcpy(pszFlagName, "SYN/URG", sizeof("SYN/URG"));
            break;
        }
        case FLAG_ACK_URG:
        {
            memcpy(pszFlagName, "ACK/URG", sizeof("ACK/URG"));
            break;
        }
        case FLAG_FIN_ACK_URG:
        {
            memcpy(pszFlagName, "FIN/ACK/URG", sizeof("FIN/ACK/URG"));
            break;
        }
        default:
        {
            (VOID)snprintf(pszFlagName, SESSION_DBG_FLAG_SIZE, "0x%02x", uiFlagFind);
            break;
        }
    }

    return;
}

/* 根据dbg-type获取对应的消息类型名 */
STATIC const CHAR * _kdbg_get_msg_name(IN UINT uiDbgType)
{
    const CHAR *pcName = "";

    switch (uiDbgType)
    {
        case ASPF_DBG_BIT_EVENT:
        {
            pcName = "EVENT";
            break;
        }
        case ASPF_DBG_BIT_PACKET:
        {
            pcName = "PACKET";
            break;
        }
        default:
        {
            DBGASSERT(BOOL_FALSE);
            break;
       }
    }

    return pcName;
}

VOID ASPF_kdbg_Zonepair_Output_Packet(IN CHAR *pcDbgDesc,
                                      IN ACL_VERSION_E enAclVer,
                                      IN MBUF_S *pstMBuf,
                                      IN USHORT usL3Offset,
                                      IN const ASPF_CTRL_S *pstAspfCtrl)
{
    ULONG ulErr;
    //BOOL_T bMatch;
    ASPF_KDBG_PACKET_INFO_S stPacketInfo;
    MBUF_IP_HDR_S *lhdr = &pstMBuf->stIpHdr;

    aspf_mark_pak(lhdr);

    /* 没匹配上acl规则，不打印*/
	if(this_ffilter_show_this_pak == 0)
	{
		return;
	}

    /* 检测当前mbuf是否匹配acl 
    bMatch = _kdbg_is_packet_match_acl(enAclVer, pstMBuf, usL3Offset, pstAspfCtrl);
    if(BOOL_TRUE != bMatch)
    {
        return;
    }
    */

    /* 从mbuf中获取debug需要的相关信息 */
    ulErr = _kdbg_get_packet_info_from_mbuf(enAclVer, pstMBuf, usL3Offset, &stPacketInfo);
    if(ERROR_SUCCESS != ulErr)
    {
        return;
    }

    if(0 != stPacketInfo.ucFlag)
    {
        CHAR szFlagName[SESSION_DBG_FLAG_SIZE] = {0};
        ASPF_kdbg_GetFlagName(stPacketInfo.ucFlag, szFlagName);


		debug_trace(g_pcDbgZonepairAddFlagFmt,
	                ASPF_MODULE_NAME,	                
	                _kdbg_get_msg_name(ASPF_DBG_BIT_PACKET),
	                pcDbgDesc,
	                stPacketInfo.szSrcIP,
	                stPacketInfo.szDstIP,
	                (UINT)stPacketInfo.usSrcPort,
	                (UINT)stPacketInfo.usDstPort,
	                stPacketInfo.szProtoName,
	                stPacketInfo.ucProtoID,
	                szFlagName,
	                stPacketInfo.uiSeq);
    }
    else
    {
		
		debug_trace(g_pcDbgZonepairFmt,
	                ASPF_MODULE_NAME,	                
	                _kdbg_get_msg_name(ASPF_DBG_BIT_PACKET),
	                pcDbgDesc,
	                stPacketInfo.szSrcIP,
	                stPacketInfo.szDstIP,
	                (UINT)stPacketInfo.usSrcPort,
	                (UINT)stPacketInfo.usDstPort,
	                stPacketInfo.szProtoName,
	                stPacketInfo.ucProtoID);
    }

    return;
}

