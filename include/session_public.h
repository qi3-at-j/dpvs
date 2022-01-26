#ifndef _SESSION_PUBLIC_H_
#define _SESSION_PUBLIC_H_

#include "baseype.h"


/*外挂扩展信息枚举定义*/
typedef enum tagMBUF_Cach_ID
{
    MBUF_CACHE_SESSION,
    MBUF_CACHE_IP,    
    MBUF_CACHE_IPV6,
    MBUF_CACHE_MAX
}MBUF_CACHE_ID_E;

typedef struct tagMBuf_Ethernet_Hdr
{
    USHORT usInboundFirstVlanID;
} MBUF_ETHERNET_HDR_S;

/* use this ip hdr for both v4 and v6 */
typedef struct tagMBuf_IP_Hdr
{
    UCHAR ucIsFragment:1;
    UCHAR ucIsFirstFrag:1;
    UCHAR ucIsLastFrag:1;
    UCHAR ucIsIpv6:1;
    UCHAR ucIsIcmpErr:1;
    UCHAR ucFwd:1;
    UCHAR ucMark:1;
    UCHAR ucRsv:1;
    UCHAR ucTCPFlags;
    UCHAR ucNextHdr;
    USHORT usIpPktType;
    /* 
     * store ipv4 in the first element 
     */
    UINT auiSrc[4];
#define lhdr_src_ip_4 auiSrc[0]
#define lhdr_src_ip_6 auiSrc
#define lhdr_src_ip_6_0 auiSrc[0]
#define lhdr_src_ip_6_1 auiSrc[1]
#define lhdr_src_ip_6_2 auiSrc[2]
#define lhdr_src_ip_6_3 auiSrc[3]
    UINT auiDst[4];
#define lhdr_dst_ip_4 auiDst[0]
#define lhdr_dst_ip_6 auiDst
#define lhdr_dst_ip_6_0 auiDst[0]
#define lhdr_dst_ip_6_1 auiDst[1]
#define lhdr_dst_ip_6_2 auiDst[2]
#define lhdr_dst_ip_6_3 auiDst[3]
    /* !!!
     * fragment control block require the ipid is adjacent
     * the dst ip
     */
    UINT ipid;
    UINT auiNextHop[4];
    struct {
        UCHAR ucIcmpType;
        UCHAR ucIcmpCode;
        USHORT usIcmpID;
    } stIcmpInfo;
    struct {
        USHORT usSourcePort;
        USHORT usDestinationPort;
    } stTcpUdpPort;
#define lhdr_icmp_type stIcmpInfo.ucIcmpType
#define lhdr_icmp_code stIcmpInfo.ucIcmpCode
#define lhdr_icmp_id   stIcmpInfo.usIcmpID
#define lhdr_src_port   stTcpUdpPort.usSourcePort
#define lhdr_dst_port   stTcpUdpPort.usDestinationPort
    void *iptr;
} MBUF_IP_HDR_S;

typedef struct tagMBuf
{
    VOID *csp;
    UCHAR ucCacheBitmap;
    USHORT usSessionFlag;              /* 会话管理的报文处理结果Sessionflag,网络序 */
    VOID *apCache[MBUF_CACHE_MAX];     /*IPv4 快转外挂指针，内存由IPV4模块负责管理*/
    
    UINT32 uiFlag;                     /* 标志，各位的含义由宏MBUF_FLAG_XXXXXXXX定义，主机序 */
    
    union    {
        struct tagVrf {
            VRF_INDEX vrfIndexRawIn;   /* 主机序 */
            VRF_INDEX vrfIndexIn;      /* 主机序 */
            VRF_INDEX vrfIndexOut;     /* 主机序 */
        }stVrf;
        USHORT usVLL;
    }u1;

    UINT32 uiAppIDNew;                 /* 报文的应用层协议ID *//* 主机序 */
    UINT32 uiTunnelID;
    //MBUF_ETHERNET_HDR_S stEthHdr;
    MBUF_IP_HDR_S       stIpHdr;
} __rte_cache_aligned MBUF_S;


ULONG SESSION_Init(IN LPVOID pStartContext);
ULONG SESSION_KMDC_Init (VOID);
ULONG SESSION_Run(IN LPVOID pStartContext);
INT SESSION_FsServiceProc(struct rte_mbuf *pstRteMbuf);
INT SESSION6_FsServiceProc(struct rte_mbuf *pstRteMbuf);

UINT SESSION_GetMbufSize(VOID);
VOID ASPF_Init(VOID);
INT ASPF_kpacket_zonepair_Ipv4(struct rte_mbuf *pstRteMbuf);
INT ASPF_kpacket_zonepair_Ipv6(struct rte_mbuf *pstRteMbuf);


VOID ASPF_Inc_Cfg_Seq(VOID);

#define SESSION_MBUF_REPLYPKT   0x0001 /* 报文方向标记     :0-正向报文,1-反向报文 */
#define SESSION_MBUF_FIRSTPKT   0x0002 /* 首报文标记       :0-后续报文,1-首报文 */
#define SESSION_MBUF_ICMPERR    0x0004 /* ICMP差错报文标记 :0-不是,1-是 */
#define SESSION_MBUF_PROCESSED  0x0008 /* 报文已处理标记   :0-未处理,1-已处理 */
#define SESSION_MBUF_INVALID          0x0010 /* 报文不合法标记    :0-报文合法，1-报文不合法 */
#define SESSION_MBUF_ESTABLISH        0x0020 /* 稳态会话标记      :0-非稳态，1-稳态 */
#define SESSION_MBUF_CFGCHECK         0x0040 /* 配置变更检查标记  :0-不需要检查，1-需要检查 */
#define SESSION_MBUF_SLOW_FORWARDING  0x0080 /* FW慢转函数处理标记          :0-没有经过慢转处理，1-已经经过慢转处理 */
#define SESSION_MBUF_TEMP       0x0100 /* 临时会话标记      :0-不是临时会话，1-是临时会话 */
#define SESSION_MBUF_SEQCHECKED 0x0200 /* 报文已经经过tcp序列号处理 */
#define SESSION_MBUF_DIM_DONE   0x0400 /* 报文已被DIM处理标记 :0-未处理，1-已处理 */
#define SESSION_MBUF_SYNC_NEEDRELAY 0x0800   /* 报文需要Relay   :0-未处理，1-已处理 */
#define SESSION_MBUF_SSLVPN_NEEDRELAY 0x1000 /* SSLVPN报文需要透传标记 */
#define SESSION_MBUF_SSLVPN_DONTRELAY 0x2000 /* SSLVPN报文不需要被双主hash选板功能透传标记 */


#define rte_mbuf_from_mbuf(x) \
    ((struct rte_mbuf *)RTE_PTR_SUB(x, sizeof(struct rte_mbuf) + sizeof(struct mbuf_priv_data)))

#define mbuf_from_rte_mbuf(x) \
    ((MBUF_S *)RTE_PTR_ADD(x, sizeof(struct rte_mbuf) + sizeof(struct mbuf_priv_data)))


/* add the specific flag(represented by usFlagBit) to lbuf usSessionFlag */
static inline VOID SESSION_MBUF_SET_FLAG(IN MBUF_S *pstMBuf, IN USHORT usFlagBit)
{
    pstMBuf->usSessionFlag |= usFlagBit;

    return;
}

static inline VOID SESSION_MBUF_CLEAR_FLAG(IN MBUF_S *pstMBuf)
{
    pstMBuf->usSessionFlag = 0;

    return;
}

static inline UINT
SESSION_MBUF_HAVE_FLAG(IN MBUF_S *pstMBuf, IN USHORT usFlagBit)
{
    return (pstMBuf->usSessionFlag & usFlagBit);
}

#endif
