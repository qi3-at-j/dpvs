#ifndef _SESSION_MBUF_H_
#define _SESSION_MBUF_H_


#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include "baseype.h"
#include "mbuf.h"
#include "netif.h"
#include "session_public.h"


/* ����MBUF͸��û�����ֽ���ת����
   ��ˣ���Ҫ�ø�16λ���ֽ���ת��ʹ�ã���˸ñ�־λֻ����16λ */
#define IP_PKT_HOST                  0x00000001       /* ��ʾ��IP���ĵ�Ŀ�ĵ�ַ�Ǳ���ĳ���ӿڵ�IP��ַ */
#define IP_PKT_HOSTSENDPKT           0x00000002       /* �������͵�IP���� */
#define IP_PKT_IIFBRAODCAST          0x00000008       /* ��������ӿڵĹ㲥���� */
#define IP_PKT_OIFBRAODCAST          0x00000010       /* ��������ӿڵĹ㲥���� */
#define IP_PKT_MULTICAST             0x00000020       /* ������IP�鲥���� */
#define IP_PKT_ETHBCAST              0x00000040       /* ��ʾ�ñ�������̫���Ĺ㲥���� */
#define IP_PKT_ETHMCAST              0x00000080       /* ��ʾ�ñ�������̫�����鲥���� */
#define IP_PKT_SRCROUTE              0x00000100       /* ��ʾ�ñ�����Դ·�ɴ���ı��� */
#define IP_PKT_FILLTAG               0x00000200       /* ��дMBUF IPv4��������Ϣ  */
#define IP_PKT_FILLTWAMPTIMESTAMP    0x00000400       /* ��дTWAMPʱ��� */
#define IP_PKT_NOCHECKSESSION        0x00000800       /* �����лỰ��Ч�����滻 */
#define IP_PKT_SENDTOLASTHOP         0x00001000       /* �������������ı�����һ����Ϣ����ת���ı���*/
#define IP_PKT_SENDBYTUNNEL          0x00002000       /* ��Ǳ�����TUNNEL���� */
#define IP_PKT_NOCLEARSERVICE        0x00004000       /* ҵ��˽����Ϣ��Ч������Ҫ��� */
#define IP_PKT_SENDBYAFT             0x00008000       /* aftת������ */


#define IP6_PKT_HOST                 0x00000001       /* ��ʾ��IPv6���ĵ�Ŀ�ĵ�ַ�Ǳ���ĳ���ӿڵ�IP��ַ */
#define IP6_PKT_HOSTSENDPKT          0x00000002       /* ��ʾ�������͵�IPv6���� */
#define IP6_PKT_UNSPECSRC            0x00000004       /* ��ʾӦ�ò�Ҫ��ԴIPv6��ַΪ::*/
#define IP6_PKT_SENDBYAFT            0x00000008

/* MBUF FLAG���壬���õ�stTag.uiFlag�У�
   ���ڿ��λ��ģ�鴫�ݼ���Ϣ.
   ����ģ��mbuf��ؽṹ�м�¼���ݵĲ�Ҫ�ڴ˱�� */
#define MBUF_FLAG_BROADCAST 		  	0X00000001		/* ����㲥��������㲥����Ҫ�ô˱�־�����ڲ���Ҫ��������ӿڵĳ��� */
#define MBUF_FLAG_MULTICAST				0X00000002		/* �����鲥���������鲥����Ҫ�ô˱�־ */
#define MBUF_FLAG_IPRELAY 				0X00000004		/* ͸�����Ľ���IPv4��IPv6�Ŀ�ת���� */
#define MBUF_FLAG_NETSTREAM_IN 			0X00000008		/* ��ʶMBUF�뷽���Ѿ���Netstreamͳ�ƹ�, �����ظ�ͳ�ƣ��ñ����ҪRelay */
#define MBUF_FLAG_NETSTREAM_OUT 		0X00000010		/* ��ʶMBUF�������Ѿ���Netstreamͳ�ƹ�, �����ظ�ͳ�ƣ��ñ����ҪRelay */
#define MBUF_FLAG_NETSTREAM_EXPORT		0X00000020		/* ��ʶ��Netstream������ģ���������ͳ�� */
#define MBUF_FLAG_L3_SEND_PORT			0X00000040		/* ����ָ�����Ͷ˿ڱ�־λ */
#define MBUF_FLAG_PROTOCOL 				0X00000080		/* �ڲ�Э�鱨�ĵı�־������QoS */
#define MBUF_FLAG_RELAY 				0X00000100		/* ��ʶ������Relay������ */
#define MBUF_FLAG_TXIGNORESTPSTATE 		0X00000200		/* ����STP״̬���ͱ��� */
#define MBUF_FLAG_URGENT_PACKET 		0X00000400		/* �������� */
#define MBUF_FLAG_TXIGNOREMACSTATE 		0X00000800		/* ����MAC��״̬���ͱ��� */
#define MBUF_FLAG_TRILLIN 				0X00001000		/* �뱨����TRILL��װ���ģ�ָ��VLAN���ͱ��Ĳ���Ҫ��Զ�˶˿ڷ��� */
#define MBUF_FLAG_EXCLUDESRCPORT 		0X00002000		/* �ų�Դ�˿ڷ��� */
#define MBUF_FLAG_TRILLPORTNOENCAP 		0X00004000		/* ָ���˿ڷ���ʱ��ֻ��Ҫ����һ�ݣ�����TRILL��װ */
#define MBUF_FLAG_TRILLPORTENCAP 		0X00008000		/* ָ���˿ڷ���ʱ��ֻ��Ҫ����һ�ݣ���TRILI��װ */
#define MBUF_FLAG_L3HEAD_NOT_EXIST 		0X00010000		/* ����ƫ����·�㳤��ȥ��ȡ������Ϣ */
#define MBUF_FLAG_LLQ_PACKET 			0X00020000		/* ��ʶ������LLQ���� */
#define MBUF_FLAG_INIPSEC 				0X00040000		/* �뷽��IPsecҵ�� */
#define MBUF_FLAG_OUTIPSEC				0X00080000		/* ������IPsecҵ�� */
#define MBUF_FLAG_INVRFSET				0X00100000		/* ��ʶ�뷽�� VRF �Ѿ����ù� */
#define MBUF_FLAG_L4INFOFILLED_BYVFR 	0X00200000		/* ��ʶ��������VFR�����Ĳ���Ϣ */
#define MBUF_FLAG_PTP_PACKET 			0X00400000		/* PTP���� */
#define MBUF_FLAG_LINK_RECUR			0X00800000		/* ��·������ */
#define MBUF_FLAG_IPFS_NOREPLYCACHE		0X01000000		/* �Ự��ת��������cache */
#define MBUF_FLAG_TCP_NSR_TOMASTER		0X02000000		/* ��ʶ������TCP NSR͸���������ӵı��ģ�������͸����NSR���� */
#define MBUF_FLAG_VPLS					0X04000000		/* ��ʶ��VPLS���� */
#define MBUF_FLAG_MINM					0X08000000		/* ��ʶ��MINM���� */
#define MBUF_FLAG_SIB					0X10000000		/* ��ʶ��SIB������ı��� */
#define MBUF_FLAG_LIPC_TRANSMIT_DONE 	MBUF_FLAG_NETSTREAM_IN		/* LIPC���ĵ��ڲ���־�������������־һ��ʹ�� */
#define MBUF_FLAG_LIPC_MULTI			MBUF_FLAG_NETSTREAM_OUT		/* LIPC���ĵ��ڲ���־ */
#define MBUF_FLAG_IPOEPROC				0X20000000		/* ��ʶ����Ҫ����IPOE���� */
#define MBUF_FLAG_FORBIDFASTFORWRAD		0X40000000		/* ��ֹ�߿�ת��� */
#define MBUF_FLAG_FORBIDADDFLOW			0X80000000		/* ��ֹ�������� */
#define MBUF_FLAG_PNP_AGENT				MBUF_FLAG_SIB	/* ��ʾ���ľ������弴�ô����� */

/* �ͷ�MBUF�ĺ���ԭ�Ͷ��� */
typedef ULONG (* MBUF_EXTINFOFREEFUNC_PF)(IN MBUF_S *);

#define MBUF_BTOD(pstMBufM, DataTypeM) \
    rte_pktmbuf_mtod(rte_mbuf_from_mbuf(pstMBufM), DataTypeM)

#define MBUF_BTOD_OFFSET(pstMBufM, usOffsetM, DataTypeM) \
    rte_pktmbuf_mtod_offset(rte_mbuf_from_mbuf(pstMBufM), DataTypeM, usOffsetM)

/*****************MBUF_S �����ӿ�***********************/
/* stub begin */
static inline USHORT MBUF_GET_OUTBOUND_FIRSTVLANID(IN const MBUF_S *pstMBuf)
{
    return 0;
}
/* stub end */

/* ��ȡMBUF�����ܳ��� */
static inline UINT32 MBUF_GET_TOTALDATASIZE(IN const MBUF_S *pstMBuf)
{
    return rte_pktmbuf_pkt_len(rte_mbuf_from_mbuf(pstMBuf));
}

/* ��IP����Ӧ�ò�Э����صĲ��� */

/* IP�����չ��Ϣ���� */
static inline VOID MBUF_SET_IP_CACHE(INOUT MBUF_S* pstMBuf, IN VOID* pCache)
{
    pstMBuf->apCache[MBUF_CACHE_IP] = pCache;
    if(NULL != pCache)
    {
        pstMBuf->ucCacheBitmap |= (1UL << MBUF_CACHE_IP);
    }
    else
    {
        pstMBuf->ucCacheBitmap &= ~(1UL << MBUF_CACHE_IP);
    }
    return;
}

static inline VOID* MBUF_GET_IP_CACHE(IN const MBUF_S* pstMBuf)
{
    return (pstMBuf->apCache[MBUF_CACHE_IP]);
}

/* IPv6�����չ��Ϣ���� */
static inline VOID MBUF_SET_IP6_CACHE(INOUT MBUF_S* pstMBuf, IN VOID* pCache)
{
    pstMBuf->apCache[MBUF_CACHE_IPV6] = pCache;
    if(NULL != pCache)
    {
        pstMBuf->ucCacheBitmap |= (1UL << MBUF_CACHE_IPV6);
    }
    else
    {
        pstMBuf->ucCacheBitmap &= ~(1UL << MBUF_CACHE_IPV6);
    }
    return;
}

static inline VOID* MBUF_GET_IP6_CACHE(IN const MBUF_S* pstMBuf)
{
    return (pstMBuf->apCache[MBUF_CACHE_IPV6]);
}

static inline VOID MBUF_SET_CACHE(INOUT MBUF_S *pstMBuf, IN VOID *pCache, IN MBUF_CACHE_ID_E enCacheType)
{
    pstMBuf->apCache[enCacheType] = pCache;
    if(NULL != pCache)
    {
        pstMBuf->ucCacheBitmap |= ((UCHAR)(UINT)(1 << enCacheType));
    }
    else
    {
        pstMBuf->ucCacheBitmap &= ~(1UL << enCacheType);
    }
    return;
}

static inline VOID* MBUF_GET_CACHE(IN const MBUF_S *pstMBuf, IN MBUF_CACHE_ID_E enCacheType)
{
    return (pstMBuf->apCache[enCacheType]);
}

static inline VOID MBUF_ASSIGN_CACHE(IN MBUF_S *pstMBuf, IN VOID *pCache, IN MBUF_CACHE_ID_E enCacheType)
{
    pstMBuf->apCache[enCacheType] = pCache;
    pstMBuf->ucCacheBitmap |= ((UCHAR)(UINT)(1UL << enCacheType));
    return;
}

static inline VOID MBUF_CLEAR_CACHE(IN MBUF_S *pstMBuf, IN MBUF_CACHE_ID_E enCacheType)
{
    pstMBuf->apCache[enCacheType] = NULL;
    pstMBuf->ucCacheBitmap &= ~(1UL << enCacheType);
    return;
}

/* IP�������͵�Get�Ͱ�λ����Set�����Clear,�μ�IP_PKT_XXXϵ�к� 
static inline UINT32 MBUF_GET_IP_PKTTYPE(IN const MBUF_S *pstMBuf)
{
    return pstMBuf->stIpHdr.uiIpPktType;
}

static inline VOID MBUF_SET_IP_PKTTYPE(INOUT MBUF_S *pstMBuf, IN UINT32 uiIpPktType)
{
    pstMBuf->stIpHdr.uiIpPktType |= uiIpPktType;
    return;
}

static inline VOID MBUF_CLEAR_IP_PKTTYPE(INOUT MBUF_S *pstMBuf, IN UINT32 uiIpPktType)
{
    pstMBuf->stIpHdr.uiIpPktType &= ~uiIpPktType;
    return;
}*/

/* ������Ϣ��Flag��Get��Set,Clear,��λ�ĺ����ɺ�MBUF_FLAG_XXXXXXXX���� */
static inline VOID MBUF_SET_FLAG(INOUT MBUF_S *pstMBuf, IN UINT32 uiFlag)
{
    pstMBuf->uiFlag |= uiFlag;
    return ;
}

static inline UINT32 MBUF_GET_FLAG(IN const MBUF_S *pstMBuf)
{
    return pstMBuf->uiFlag;
}

static inline VOID MBUF_CLEAR_FLAG(INOUT MBUF_S *pstMBuf, IN UINT32 uiFlag)
{
    pstMBuf->uiFlag &= ~uiFlag;
    return ;
}

/* ���ĵĳ�ʼ���VPN������Get��Set */
static inline VOID MBUF_SET_RAWINVPNID(OUT MBUF_S *pstMBuf, IN VRF_INDEX vrfIndexRawIn)
{
    pstMBuf->u1.stVrf.vrfIndexRawIn = vrfIndexRawIn;
    return;
}

static inline VRF_INDEX MBUF_GET_RAWINVPNID(IN const MBUF_S *pstMBuf)
{
    return (pstMBuf->u1.stVrf.vrfIndexRawIn);
}

/* ���ĵ����VPN������Get��Set */
static inline VOID MBUF_SET_INVPNID(OUT MBUF_S *pstMBuf, IN VRF_INDEX vrfIndexIn)
{
    pstMBuf->u1.stVrf.vrfIndexIn = vrfIndexIn;
    return;
}

static inline VRF_INDEX MBUF_GET_INVPNID(IN const MBUF_S *pstMBuf)
{
    return (pstMBuf->u1.stVrf.vrfIndexIn);
}

/* ���ĵĳ���VPN������Get��Set */
static inline VOID MBUF_SET_OUTVPNID(OUT MBUF_S *pstMBuf, IN VRF_INDEX vrfIndexOut)
{
    pstMBuf->u1.stVrf.vrfIndexOut = vrfIndexOut;
    return;
}

static inline VRF_INDEX MBUF_GET_OUTVPNID(IN const MBUF_S *pstMBuf)
{
    return (pstMBuf->u1.stVrf.vrfIndexOut);
}

/* ��·��ͷ�е�ԴVLAN ID��Get��Set 
static inline VOID MBUF_SET_INBOUND_FIRSTVLANID(OUT MBUF_S *pstMBuf, IN USHORT usVlanID)
{
    pstMBuf->stEthHdr.usInboundFirstVlanID = usVlanID;
    return;
}

static inline USHORT MBUF_GET_INBOUND_FIRSTVLANID(OUT MBUF_S *pstMBuf)
{
    return pstMBuf->stEthHdr.usInboundFirstVlanID;
}*/

/* ��MBuf��Ƭ��صĲ������� */
/* ����MBufΪIPv6��Ƭ���� */
static inline VOID MBUF_SET_IP6_FRAGMENT(OUT MBUF_S *pstMBuf)
{
	pstMBuf->stIpHdr.ucIsFragment = BOOL_TRUE;
	return;
}

/* �б�MBuf�Ƿ�ΪIP��Ƭ���� */
static inline BOOL_T MBUF_IS_IP6_FRAGMENT(IN const MBUF_S *pstMBuf)
{
	return (BOOL_FALSE != pstMBuf->stIpHdr.ucIsFragment);
}

/* ����MBufΪIP��Ƭ��Ƭ���� */
static inline VOID MBUF_SET_IP6_FIRSTFRAG(OUT MBUF_S *pstMBuf)
{
	pstMBuf->stIpHdr.ucIsFirstFrag = BOOL_TRUE;
	return;
}

/* �б�MBuf�Ƿ�ΪIP��Ƭ��Ƭ���� */
static inline BOOL_T MBUF_IS_IP6_FIRSTFRAG(IN const MBUF_S *pstMBuf)
{
	return (BOOL_FALSE != pstMBuf->stIpHdr.ucIsFirstFrag);
}

/* TCP flag Get,Set */
static inline UCHAR MBUF_GET_IP6_TCPFLAGS(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.ucTCPFlags);
}

static inline VOID MBUF_SET_IP6_TCPFLAGS(OUT MBUF_S *pstMBuf, IN UCHAR ucTCPFlags)
{
	pstMBuf->stIpHdr.ucTCPFlags = ucTCPFlags;
	return;
}

/* IPv6�������͵ĵ�Get��Set */
static inline USHORT MBUF_GET_IP6_PKTTYPE(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.usIpPktType);
}


static inline VOID MBUF_SET_IP6_PKTTYPE(INOUT MBUF_S *pstMBuf, IN USHORT usIpPktType)
{
	pstMBuf->stIpHdr.usIpPktType = usIpPktType;
	return;
}

static inline VOID MBUF_CLEAR_IP6_PKTTYPE(INOUT MBUF_S *pstMBuf, IN USHORT usIpPktType)
{
	pstMBuf->stIpHdr.usIpPktType &= (USHORT)~usIpPktType;
	return;
}

/* IPV6����ͷ��һ����չЭ�����͵�Get��Set */
static inline UCHAR MBUT_GET_IP6_NEXTHDR(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.ucNextHdr);
}

static inline VOID MBUF_SET_IP6_NEXTHDR(OUT MBUF_S *pstMBuf, IN UCHAR ucType)
{
	pstMBuf->stIpHdr.ucNextHdr = ucType;
	return;
}

/* IPV6�����Դ�˿ڣ�����ICMP���͵�Get��Set */
static inline USHORT MBUF_GET_IP6_SOURCEPORT(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.lhdr_src_port);
}

static inline VOID MBUF_SET_IP6_SOURCEPORT(OUT MBUF_S *pstMBuf, IN USHORT usSourcePort)
{
	pstMBuf->stIpHdr.lhdr_src_port = usSourcePort;
	return;
}

static inline UCHAR MBUF_GET_IP6_ICMPTYPE(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.lhdr_icmp_type);
}

static inline VOID MBUF_SET_IP6_ICMPTYPE(OUT MBUF_S *pstMBuf, IN UCHAR ucIcmpType)
{
	pstMBuf->stIpHdr.lhdr_icmp_type = ucIcmpType;
	return;
}


/* IPV6�����Ŀ�Ķ˿ڣ�����ICMP���͵�Get��Set */
static inline USHORT MBUF_GET_IP6_DESTPORT(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.lhdr_dst_port);
}

static inline VOID MBUF_SET_IP6_DESTPORT(OUT MBUF_S *pstMBuf, IN USHORT usDstPort)
{
	pstMBuf->stIpHdr.lhdr_dst_port = usDstPort;
	return;
}

static inline UCHAR MBUF_GET_IP6_ICMPCODE(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.lhdr_icmp_code);
}

static inline VOID MBUF_SET_IP6_ICMPCODE(OUT MBUF_S *pstMBuf, IN UCHAR ucIcmpCode)
{
	pstMBuf->stIpHdr.lhdr_icmp_code = ucIcmpCode;
	return;
}

static inline USHORT MBUF_GET_IP6_ICMPID(IN const MBUF_S *pstMBuf)
{
	return (USHORT)(pstMBuf->stIpHdr.lhdr_icmp_id);
}

static inline VOID MBUF_SET_IP6_ICMPID(OUT MBUF_S *pstMBuf, IN USHORT usIcmpID)
{
	pstMBuf->stIpHdr.lhdr_icmp_id = usIcmpID;
	return;

}

/* IPv6��һ����ַ��Get��Set
static inline UINT32* MBUF_GET_IP6_NEXTHOP(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.auiNextHop);
} */

static inline VOID MBUF_SET_IP6_NEXTHOP(OUT MBUF_S *pstMBuf, IN const UINT32 *puiAddr)
{
	pstMBuf->stIpHdr.auiNextHop[0] = puiAddr[0];
	pstMBuf->stIpHdr.auiNextHop[1] = puiAddr[1];
	pstMBuf->stIpHdr.auiNextHop[2] = puiAddr[2];
	pstMBuf->stIpHdr.auiNextHop[3] = puiAddr[3];
	return;
}

/* IPv6������ԴIPv6��ַGet��Set */
static inline UINT32* MBUF_GET_IP6_SOURCEIP(IN const MBUF_S *pstMBuf)
{
	return ((UINT32*)(pstMBuf->stIpHdr.auiSrc));
}

static inline VOID MBUF_SET_IP6_SOURCEIP(OUT MBUF_S *pstMBuf, IN const UINT32 *puiAddr)
{
	pstMBuf->stIpHdr.auiSrc[0] = puiAddr[0];
	pstMBuf->stIpHdr.auiSrc[1] = puiAddr[1];
	pstMBuf->stIpHdr.auiSrc[2] = puiAddr[2];
	pstMBuf->stIpHdr.auiSrc[3] = puiAddr[3];
	return;
}

/* IPv6������Ŀ��IPv6��ַGet��Set */
static inline UINT32* MBUF_GET_IP6_DESTIP(IN const MBUF_S *pstMBuf)
{
	return ((UINT32*)(pstMBuf->stIpHdr.auiDst));
}

static inline VOID MBUF_SET_IP6_DESTIP(OUT MBUF_S *pstMBuf, IN const UINT32 *puiAddr)
{
	pstMBuf->stIpHdr.auiDst[0] = puiAddr[0];
	pstMBuf->stIpHdr.auiDst[1] = puiAddr[1];
	pstMBuf->stIpHdr.auiDst[2] = puiAddr[2];
	pstMBuf->stIpHdr.auiDst[3] = puiAddr[3];
	return;
}

static inline ULONG MBUF_PULLUP(MBUF_S *pstMBuf, UINT uiTotalOffSet)
{	
	INT iRet;
	ULONG ulRet;
	
    struct rte_mbuf  *pstRteMbuf = rte_mbuf_from_mbuf(pstMBuf);
	
    iRet = mbuf_may_pull(pstRteMbuf, uiTotalOffSet);
	ulRet = (ULONG)iRet;

	return ulRet;
}


VOID MBUF_RegExtCacheFreeFunc(IN MBUF_CACHE_ID_E enId, IN MBUF_EXTINFOFREEFUNC_PF pfFunc);

#endif
