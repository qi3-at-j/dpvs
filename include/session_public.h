#ifndef _SESSION_PUBLIC_H_
#define _SESSION_PUBLIC_H_

#include "baseype.h"


/*�����չ��Ϣö�ٶ���*/
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
    USHORT usSessionFlag;              /* �Ự����ı��Ĵ�����Sessionflag,������ */
    VOID *apCache[MBUF_CACHE_MAX];     /*IPv4 ��ת���ָ�룬�ڴ���IPV4ģ�鸺�����*/
    
    UINT32 uiFlag;                     /* ��־����λ�ĺ����ɺ�MBUF_FLAG_XXXXXXXX���壬������ */
    
    union    {
        struct tagVrf {
            VRF_INDEX vrfIndexRawIn;   /* ������ */
            VRF_INDEX vrfIndexIn;      /* ������ */
            VRF_INDEX vrfIndexOut;     /* ������ */
        }stVrf;
        USHORT usVLL;
    }u1;

    UINT32 uiAppIDNew;                 /* ���ĵ�Ӧ�ò�Э��ID *//* ������ */
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

#define SESSION_MBUF_REPLYPKT   0x0001 /* ���ķ�����     :0-������,1-������ */
#define SESSION_MBUF_FIRSTPKT   0x0002 /* �ױ��ı��       :0-��������,1-�ױ��� */
#define SESSION_MBUF_ICMPERR    0x0004 /* ICMP����ı�� :0-����,1-�� */
#define SESSION_MBUF_PROCESSED  0x0008 /* �����Ѵ�����   :0-δ����,1-�Ѵ��� */
#define SESSION_MBUF_INVALID          0x0010 /* ���Ĳ��Ϸ����    :0-���ĺϷ���1-���Ĳ��Ϸ� */
#define SESSION_MBUF_ESTABLISH        0x0020 /* ��̬�Ự���      :0-����̬��1-��̬ */
#define SESSION_MBUF_CFGCHECK         0x0040 /* ���ñ�������  :0-����Ҫ��飬1-��Ҫ��� */
#define SESSION_MBUF_SLOW_FORWARDING  0x0080 /* FW��ת����������          :0-û�о�����ת����1-�Ѿ�������ת���� */
#define SESSION_MBUF_TEMP       0x0100 /* ��ʱ�Ự���      :0-������ʱ�Ự��1-����ʱ�Ự */
#define SESSION_MBUF_SEQCHECKED 0x0200 /* �����Ѿ�����tcp���кŴ��� */
#define SESSION_MBUF_DIM_DONE   0x0400 /* �����ѱ�DIM������ :0-δ����1-�Ѵ��� */
#define SESSION_MBUF_SYNC_NEEDRELAY 0x0800   /* ������ҪRelay   :0-δ����1-�Ѵ��� */
#define SESSION_MBUF_SSLVPN_NEEDRELAY 0x1000 /* SSLVPN������Ҫ͸����� */
#define SESSION_MBUF_SSLVPN_DONTRELAY 0x2000 /* SSLVPN���Ĳ���Ҫ��˫��hashѡ�幦��͸����� */


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
