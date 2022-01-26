#ifndef _SESSION_MBUF_H_
#define _SESSION_MBUF_H_


#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include "baseype.h"
#include "mbuf.h"
#include "netif.h"
#include "session_public.h"


/* 由于MBUF透传没有做字节序转换，
   因此，需要用高16位做字节序转换使用，因此该标志位只能用16位 */
#define IP_PKT_HOST                  0x00000001       /* 表示该IP报文的目的地址是本机某个接口的IP地址 */
#define IP_PKT_HOSTSENDPKT           0x00000002       /* 本机发送的IP报文 */
#define IP_PKT_IIFBRAODCAST          0x00000008       /* 报文输入接口的广播报文 */
#define IP_PKT_OIFBRAODCAST          0x00000010       /* 报文输出接口的广播报文 */
#define IP_PKT_MULTICAST             0x00000020       /* 报文是IP组播报文 */
#define IP_PKT_ETHBCAST              0x00000040       /* 表示该报文是以太网的广播报文 */
#define IP_PKT_ETHMCAST              0x00000080       /* 表示该报文是以太网的组播报文 */
#define IP_PKT_SRCROUTE              0x00000100       /* 表示该报文是源路由处理的报文 */
#define IP_PKT_FILLTAG               0x00000200       /* 填写MBUF IPv4控制域信息  */
#define IP_PKT_FILLTWAMPTIMESTAMP    0x00000400       /* 填写TWAMP时间戳 */
#define IP_PKT_NOCHECKSESSION        0x00000800       /* 报文中会话有效无需替换 */
#define IP_PKT_SENDTOLASTHOP         0x00001000       /* 根据正向流量的保存上一跳信息进行转发的报文*/
#define IP_PKT_SENDBYTUNNEL          0x00002000       /* 标记报文是TUNNEL发送 */
#define IP_PKT_NOCLEARSERVICE        0x00004000       /* 业务私有信息有效，无需要清楚 */
#define IP_PKT_SENDBYAFT             0x00008000       /* aft转换报文 */


#define IP6_PKT_HOST                 0x00000001       /* 表示该IPv6报文的目的地址是本机某个接口的IP地址 */
#define IP6_PKT_HOSTSENDPKT          0x00000002       /* 表示本机发送的IPv6报文 */
#define IP6_PKT_UNSPECSRC            0x00000004       /* 表示应用层要求源IPv6地址为::*/
#define IP6_PKT_SENDBYAFT            0x00000008

/* MBUF FLAG定义，设置到stTag.uiFlag中，
   用于跨层次或跨模块传递简单信息.
   能在模块mbuf相关结构中记录传递的不要在此标记 */
#define MBUF_FLAG_BROADCAST 		  	0X00000001		/* 二层广播或者三层广播，都要置此标志，用在不需要区分入出接口的场合 */
#define MBUF_FLAG_MULTICAST				0X00000002		/* 二层组播或者三层组播，都要置此标志 */
#define MBUF_FLAG_IPRELAY 				0X00000004		/* 透传报文建立IPv4或IPv6的快转表项 */
#define MBUF_FLAG_NETSTREAM_IN 			0X00000008		/* 标识MBUF入方向已经被Netstream统计过, 避免重复统计，该标记需要Relay */
#define MBUF_FLAG_NETSTREAM_OUT 		0X00000010		/* 标识MBUF出方向已经被Netstream统计过, 避免重复统计，该标记需要Relay */
#define MBUF_FLAG_NETSTREAM_EXPORT		0X00000020		/* 标识是Netstream输出报文，不被本机统计 */
#define MBUF_FLAG_L3_SEND_PORT			0X00000040		/* 三层指定发送端口标志位 */
#define MBUF_FLAG_PROTOCOL 				0X00000080		/* 内部协议报文的标志，用于QoS */
#define MBUF_FLAG_RELAY 				0X00000100		/* 标识报文是Relay过来的 */
#define MBUF_FLAG_TXIGNORESTPSTATE 		0X00000200		/* 忽略STP状态发送报文 */
#define MBUF_FLAG_URGENT_PACKET 		0X00000400		/* 紧急报文 */
#define MBUF_FLAG_TXIGNOREMACSTATE 		0X00000800		/* 忽略MAC层状态发送报文 */
#define MBUF_FLAG_TRILLIN 				0X00001000		/* 入报文是TRILL封装报文，指定VLAN发送报文不需要向远端端口发送 */
#define MBUF_FLAG_EXCLUDESRCPORT 		0X00002000		/* 排除源端口发送 */
#define MBUF_FLAG_TRILLPORTNOENCAP 		0X00004000		/* 指定端口发送时，只需要发送一份，不做TRILL封装 */
#define MBUF_FLAG_TRILLPORTENCAP 		0X00008000		/* 指定端口发送时，只需要发送一份，做TRILI封装 */
#define MBUF_FLAG_L3HEAD_NOT_EXIST 		0X00010000		/* 不能偏移链路层长度去读取三层信息 */
#define MBUF_FLAG_LLQ_PACKET 			0X00020000		/* 标识报文是LLQ报文 */
#define MBUF_FLAG_INIPSEC 				0X00040000		/* 入方向IPsec业务 */
#define MBUF_FLAG_OUTIPSEC				0X00080000		/* 出方向IPsec业务 */
#define MBUF_FLAG_INVRFSET				0X00100000		/* 标识入方向 VRF 已经设置过 */
#define MBUF_FLAG_L4INFOFILLED_BYVFR 	0X00200000		/* 标识报文已由VFR填充过四层信息 */
#define MBUF_FLAG_PTP_PACKET 			0X00400000		/* PTP报文 */
#define MBUF_FLAG_LINK_RECUR			0X00800000		/* 链路层重入 */
#define MBUF_FLAG_IPFS_NOREPLYCACHE		0X01000000		/* 会话快转不建反向cache */
#define MBUF_FLAG_TCP_NSR_TOMASTER		0X02000000		/* 标识报文是TCP NSR透传到主连接的报文，不能再透传到NSR备板 */
#define MBUF_FLAG_VPLS					0X04000000		/* 标识是VPLS报文 */
#define MBUF_FLAG_MINM					0X08000000		/* 标识是MINM报文 */
#define MBUF_FLAG_SIB					0X10000000		/* 标识是SIB处理过的报文 */
#define MBUF_FLAG_LIPC_TRANSMIT_DONE 	MBUF_FLAG_NETSTREAM_IN		/* LIPC报文的内部标志，不会和其他标志一起使用 */
#define MBUF_FLAG_LIPC_MULTI			MBUF_FLAG_NETSTREAM_OUT		/* LIPC报文的内部标志 */
#define MBUF_FLAG_IPOEPROC				0X20000000		/* 标识报文要进行IPOE处理 */
#define MBUF_FLAG_FORBIDFASTFORWRAD		0X40000000		/* 禁止走快转标记 */
#define MBUF_FLAG_FORBIDADDFLOW			0X80000000		/* 禁止加流表标记 */
#define MBUF_FLAG_PNP_AGENT				MBUF_FLAG_SIB	/* 表示报文经过即插即用代理处理 */

/* 释放MBUF的函数原型定义 */
typedef ULONG (* MBUF_EXTINFOFREEFUNC_PF)(IN MBUF_S *);

#define MBUF_BTOD(pstMBufM, DataTypeM) \
    rte_pktmbuf_mtod(rte_mbuf_from_mbuf(pstMBufM), DataTypeM)

#define MBUF_BTOD_OFFSET(pstMBufM, usOffsetM, DataTypeM) \
    rte_pktmbuf_mtod_offset(rte_mbuf_from_mbuf(pstMBufM), DataTypeM, usOffsetM)

/*****************MBUF_S 操作接口***********************/
/* stub begin */
static inline USHORT MBUF_GET_OUTBOUND_FIRSTVLANID(IN const MBUF_S *pstMBuf)
{
    return 0;
}
/* stub end */

/* 获取MBUF数据总长度 */
static inline UINT32 MBUF_GET_TOTALDATASIZE(IN const MBUF_S *pstMBuf)
{
    return rte_pktmbuf_pkt_len(rte_mbuf_from_mbuf(pstMBuf));
}

/* 与IP报文应用层协议相关的操作 */

/* IP外挂扩展信息操作 */
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

/* IPv6外挂扩展信息操作 */
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

/* IP报文类型的Get和按位设置Set、清楚Clear,参见IP_PKT_XXX系列宏 
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

/* 基础信息的Flag的Get和Set,Clear,各位的含义由宏MBUF_FLAG_XXXXXXXX定义 */
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

/* 报文的初始入口VPN索引的Get和Set */
static inline VOID MBUF_SET_RAWINVPNID(OUT MBUF_S *pstMBuf, IN VRF_INDEX vrfIndexRawIn)
{
    pstMBuf->u1.stVrf.vrfIndexRawIn = vrfIndexRawIn;
    return;
}

static inline VRF_INDEX MBUF_GET_RAWINVPNID(IN const MBUF_S *pstMBuf)
{
    return (pstMBuf->u1.stVrf.vrfIndexRawIn);
}

/* 报文的入口VPN索引的Get和Set */
static inline VOID MBUF_SET_INVPNID(OUT MBUF_S *pstMBuf, IN VRF_INDEX vrfIndexIn)
{
    pstMBuf->u1.stVrf.vrfIndexIn = vrfIndexIn;
    return;
}

static inline VRF_INDEX MBUF_GET_INVPNID(IN const MBUF_S *pstMBuf)
{
    return (pstMBuf->u1.stVrf.vrfIndexIn);
}

/* 报文的出口VPN索引的Get和Set */
static inline VOID MBUF_SET_OUTVPNID(OUT MBUF_S *pstMBuf, IN VRF_INDEX vrfIndexOut)
{
    pstMBuf->u1.stVrf.vrfIndexOut = vrfIndexOut;
    return;
}

static inline VRF_INDEX MBUF_GET_OUTVPNID(IN const MBUF_S *pstMBuf)
{
    return (pstMBuf->u1.stVrf.vrfIndexOut);
}

/* 链路层头中的源VLAN ID的Get和Set 
static inline VOID MBUF_SET_INBOUND_FIRSTVLANID(OUT MBUF_S *pstMBuf, IN USHORT usVlanID)
{
    pstMBuf->stEthHdr.usInboundFirstVlanID = usVlanID;
    return;
}

static inline USHORT MBUF_GET_INBOUND_FIRSTVLANID(OUT MBUF_S *pstMBuf)
{
    return pstMBuf->stEthHdr.usInboundFirstVlanID;
}*/

/* 与MBuf分片相关的操作定义 */
/* 设置MBuf为IPv6分片报文 */
static inline VOID MBUF_SET_IP6_FRAGMENT(OUT MBUF_S *pstMBuf)
{
	pstMBuf->stIpHdr.ucIsFragment = BOOL_TRUE;
	return;
}

/* 判别MBuf是否为IP分片报文 */
static inline BOOL_T MBUF_IS_IP6_FRAGMENT(IN const MBUF_S *pstMBuf)
{
	return (BOOL_FALSE != pstMBuf->stIpHdr.ucIsFragment);
}

/* 设置MBuf为IP分片首片报文 */
static inline VOID MBUF_SET_IP6_FIRSTFRAG(OUT MBUF_S *pstMBuf)
{
	pstMBuf->stIpHdr.ucIsFirstFrag = BOOL_TRUE;
	return;
}

/* 判别MBuf是否为IP分片首片报文 */
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

/* IPv6报文类型的的Get，Set */
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

/* IPV6报文头下一个扩展协议类型的Get，Set */
static inline UCHAR MBUT_GET_IP6_NEXTHDR(IN const MBUF_S *pstMBuf)
{
	return (pstMBuf->stIpHdr.ucNextHdr);
}

static inline VOID MBUF_SET_IP6_NEXTHDR(OUT MBUF_S *pstMBuf, IN UCHAR ucType)
{
	pstMBuf->stIpHdr.ucNextHdr = ucType;
	return;
}

/* IPV6传输层源端口，或者ICMP类型的Get，Set */
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


/* IPV6传输层目的端口，或者ICMP类型的Get，Set */
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

/* IPv6下一跳地址的Get，Set
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

/* IPv6报文中源IPv6地址Get，Set */
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

/* IPv6报文中目的IPv6地址Get，Set */
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
