#include "session.h"
#include "pflt_pkt_info.h"
#include "tcp.h"
#include "udp.h"
#include "icmp6.h"

PFLT_GET_OPT_HDR_PF g_apfGetOptHdrFunc[IPPROTO_MAX];

/* 读取option扩展信息，并填写pstPktInfo: ucprotocol */
STATIC ULONG pflt_ipv6_get_option_default(IN MBUF_S *pstMBuf,
                                          IN UINT uiLenTraversed,
                                          IN UCHAR ucNxtHdr,
                                          INOUT SECPOLICY_PACKET_IP6_EX_S *pstPktInfo)
{
	IGNORE_PARAM(pstMBuf);
	IGNORE_PARAM(uiLenTraversed);

	pstPktInfo->stPolicy.ucProtocol = ucNxtHdr;

	return ERROR_SUCCESS;
}

/* 读取fragment option hdr中的fragment 并填写pstPktInfo->bNIFrag */
STATIC ULONG pflt_ipv6_get_option_fragment(IN MBUF_S *pstMBuf,
                                           IN UINT uiLenTraversed,
                                           IN UCHAR ucNxtHdr,
                                           INOUT SECPOLICY_PACKET_IP6_EX_S *pstPktInfo)
{
	struct ip6_frag *pstIp6FragHdr;
	USHORT          usFragOffSet;
	ULONG           ulRet = ERROR_SUCCESS;

	IGNORE_PARAM(ucNxtHdr);

	/* 获取：fragment hdr */
	pstIp6FragHdr = IP6_GetExtHdr(pstMBuf, uiLenTraversed, (UINT)sizeof(struct ip6_frag));
	if(NULL != pstIp6FragHdr)
	{
		usFragOffSet = (ntohs(pstIp6FragHdr->ip6f_offlg) & (USHORT)IP6F_OFF_MASK) >> 3;

		/* 后续分片仍可以继续向后分析扩展头，区别于IPv4报文 */
		if(0 != usFragOffSet)
		{
			pstPktInfo->bNIFrag = BOOL_TRUE;
		}
	}
	else
	{
		ulRet = ERROR_FAILED;
	}

	return ulRet;
}

/* 获取后续分片报文的L4信息 */
STATIC VOID pflt_ipv6_get_LatterFragL4Info(IN const MBUF_S *pstMBuf,
                                           OUT USHORT *pusSrcPort,
                                           OUT USHORT *pusDstPort)
{
	csp_key_t *pstcspkey;
	SESSION_HANDLE hSession;

	hSession = (SESSION_HANDLE)GET_FWSESSION_FROM_LBUF(pstMBuf);
	if (SESSION_INVALID_HANDLE != hSession)
	{
		pstcspkey = SESSION_KGetIPfsKey(hSession, SESSION_GetDirFromMBuf(pstMBuf));

		*pusSrcPort = pstcspkey->src_port;
		*pusDstPort = pstcspkey->dst_port;
	}
	else
	{
		*pusSrcPort = MBUF_GET_IP6_SOURCEPORT(pstMBuf);
		*pusDstPort = MBUF_GET_IP6_DESTPORT(pstMBuf);
	}

	return;
}

/* 读取tcp option hdr 并填写pstPktInfo:tcp6, 源端口，目的端口，tcp flag */
STATIC ULONG pflt_ipv6_get_option_tcp(IN MBUF_S *pstMBuf,
                                      IN UINT uiLenTraversed,
                                      IN UCHAR ucNxtHdr,
                                      INOUT SECPOLICY_PACKET_IP6_EX_S *pstPktInfo)
{
	struct tcphdr *pstTCPHdr;
	USHORT usSrcPort;
	USHORT usDstPort;

	IGNORE_PARAM(ucNxtHdr);

	if(BOOL_TRUE != pstPktInfo->bNIFrag)
	{
		pstTCPHdr = IP6_GetExtHdr(pstMBuf, uiLenTraversed, (UINT)sizeof(struct tcphdr));
		if(NULL != pstTCPHdr)
		{
			pstPktInfo->stPolicy.usSPort = pstTCPHdr->th_sport;
			pstPktInfo->stPolicy.usDPort = pstTCPHdr->th_dport;
	    }
		else
		{
			return ERROR_FAILED;
		}
	}
	else
	{
		pflt_ipv6_get_LatterFragL4Info(pstMBuf, &usSrcPort, &usDstPort);
		pstPktInfo->stPolicy.usSPort  = usSrcPort;
		pstPktInfo->stPolicy.usDPort  = usDstPort;
	}

	pstPktInfo->stPolicy.ucProtocol = IPPROTO_TCP;

	return ERROR_SUCCESS;
}

STATIC ULONG pflt_ipv6_get_option_udp(IN MBUF_S *pstMBuf,
                                      IN UINT uiLenTraversed,
                                      IN UCHAR ucNxtHdr,
                                      INOUT SECPOLICY_PACKET_IP6_EX_S *pstPktInfo)
{
	struct udphdr *pstUDPHdr;
	USHORT usSrcPort;
	USHORT usDstPort;

	IGNORE_PARAM(ucNxtHdr);

	if(BOOL_TRUE != pstPktInfo->bNIFrag)
	{
		pstUDPHdr = IP6_GetExtHdr(pstMBuf, uiLenTraversed, (UINT)sizeof(struct udphdr));
		if(NULL != pstUDPHdr)
		{
			pstPktInfo->stPolicy.usSPort = pstUDPHdr->uh_sport;
			pstPktInfo->stPolicy.usDPort = pstUDPHdr->uh_dport;
		}
		else
		{
			return ERROR_FAILED;
		}
		
	}
	else
	{
		pflt_ipv6_get_LatterFragL4Info(pstMBuf, &usSrcPort, &usDstPort);
		pstPktInfo->stPolicy.usSPort = usSrcPort;
		pstPktInfo->stPolicy.usDPort = usDstPort;
	}

	pstPktInfo->stPolicy.ucProtocol = IPPROTO_UDP;

	return ERROR_SUCCESS;
}

/* 读取icmpv6 option hdr 并返回填写pstPktInfo:icmpv6, type, code */
STATIC ULONG pflt_ipv6_get_option_icmpv6(IN MBUF_S *pstMBuf,
                                         IN UINT uiLenTraversed,
                                         IN UCHAR ucNxtHdr,
                                         INOUT SECPOLICY_PACKET_IP6_EX_S *pstPktInfo)
{
	struct icmp6_hdr *pstIcmp6Hdr;
	USHORT usSrcPort;
	USHORT usDstPort;

	IGNORE_PARAM(ucNxtHdr);

	if(BOOL_TRUE != pstPktInfo->bNIFrag)
	{
		/* 获取:icmp head hdr */
	    pstIcmp6Hdr = IP6_GetExtHdr(pstMBuf, uiLenTraversed, (UINT)sizeof(struct icmp6_hdr));
		if (NULL != pstIcmp6Hdr)
		{
			pstPktInfo->stPolicy.stIcmp.ucType = pstIcmp6Hdr->icmp6_type;
			pstPktInfo->stPolicy.stIcmp.ucCode = pstIcmp6Hdr->icmp6_code;
		}
		else
		{
			return ERROR_FAILED;
		}
	}
	else
	{
		pflt_ipv6_get_LatterFragL4Info(pstMBuf, &usSrcPort, &usDstPort);
		pstPktInfo->stPolicy.stIcmp.ucType = ((UINT)usDstPort) >> 8;
		pstPktInfo->stPolicy.stIcmp.ucCode = ((UINT)usDstPort) & 0xFF;
	}

	pstPktInfo->stPolicy.ucProtocol = IPPROTO_ICMPV6;

	return ERROR_SUCCESS;
}

/* 获取函数指针数组动态初始化 */
STATIC VOID pflt_ipv6_func_init(VOID)
{
	UINT uiProType;

	for (uiProType = IPPROTO_IP; uiProType < IPPROTO_MAX; uiProType++)
	{
		g_apfGetOptHdrFunc[uiProType] = pflt_ipv6_get_option_default;
	}

	g_apfGetOptHdrFunc[IPPROTO_FRAGMENT] = pflt_ipv6_get_option_fragment;
	g_apfGetOptHdrFunc[IPPROTO_TCP]      = pflt_ipv6_get_option_tcp;
	g_apfGetOptHdrFunc[IPPROTO_UDP]      = pflt_ipv6_get_option_udp;
	g_apfGetOptHdrFunc[IPPROTO_ICMPV6]   = pflt_ipv6_get_option_icmpv6;

	return;
}


/* Packet Filter模块初始化 */
ULONG PFLT_Init(VOID)
{
	pflt_ipv6_func_init();

	return ERROR_SUCCESS;
}

