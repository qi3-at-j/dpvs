

#include "baseype.h"
#include "session_kl3proto.h"
//#include "socket.h"
#include "session_mbuf.h"
#include "ipfw.h"
#include "error.h"
#include "session_util.h"
#include "session.h"

/* IP合法性检查 */
STATIC ULONG _session_IPv4_PktCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3OffSet)
{
    struct iphdr *pstIP;

    pstIP = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, struct iphdr *);

    if(SESSION_IPv4Addr_IsInValid(ntohl(pstIP->daddr)) ||
       SESSION_IPv4Addr_IsInValid(ntohl(pstIP->saddr)))
    {
        return ERROR_FAILED;
    }

    return ERROR_SUCCESS;
}

/* 从MBUF获取IP信息 */
STATIC VOID _session_IPv4_Pkt2Tuple(IN const MBUF_S *pstMBuf,
                                    IN UINT uiL3OffSet,
                                    INOUT SESSION_TUPLE_S *pstTuple)
{
    struct iphdr *pstIP;

    pstIP = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, struct iphdr *);

    pstTuple->ucL3Family = AF_INET;
    pstTuple->unL3Dst.stin.s_addr = pstIP->daddr;
    pstTuple->unL3Src.stin.s_addr = pstIP->saddr;
    pstTuple->uiTunnelID = MBUF_GET_TUNNEL_ID(pstMBuf);
    pstTuple->vrfIndex = MBUF_GET_RAWINVPNID(pstMBuf);

    return;
}

/* 从正向IP信息获取反向IP信息 */
STATIC VOID _session_IPv4_GetInvertTuple(IN const SESSION_TUPLE_S *pstOrigTuple,
                                         INOUT SESSION_TUPLE_S *pstInverseTuple)
{
    DBGASSERT(NULL != pstOrigTuple);
    DBGASSERT(NULL != pstInverseTuple);

    pstInverseTuple->ucL3Family = pstOrigTuple->ucL3Family;
    pstInverseTuple->ucProtocol = pstOrigTuple->ucProtocol;
    pstInverseTuple->unL3Dst.stin = pstOrigTuple->unL3Src.stin;
    pstInverseTuple->unL3Src.stin = pstOrigTuple->unL3Dst.stin;

    /* 反向报文的tunnelID为无效值。反向VRF INDEX需要在session end时再重新确定 */
    pstInverseTuple->uiTunnelID = TUNNEL_INVALID_TUNNEL_ID;
    pstInverseTuple->vrfIndex   = pstOrigTuple->vrfIndex;

    return;
}

/* 获取L4的协议号及协议头偏移位置 */
STATIC ULONG _session_IPv4_GetL4Proto(IN MBUF_S *pstMBuf,
                                      IN UINT   uiL3OffSet,
                                      OUT UINT  *puiL4Offset,
                                      OUT UCHAR *pucL4ProtoNum,
                                      OUT UINT  *puiIPLen)
{
    struct iphdr *pstIP;
    UINT uiIPHLen;

    SESSION_IGNORE_CONST(pstMBuf);

    pstIP = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, struct iphdr*);

    uiIPHLen = pstIP->ihl;
    uiIPHLen = uiIPHLen << 2;

    if(uiIPHLen > MBUF_GET_TOTALDATASIZE(pstMBuf) - uiL3OffSet)
    {
        return ERROR_FAILED;
    }

    *pucL4ProtoNum = pstIP->protocol;
    *puiL4Offset   = uiL3OffSet + uiIPHLen;
    *puiIPLen      = pstIP->tot_len;

    return ERROR_SUCCESS;
}

/* ipv4初始化函数 */
VOID SESSION_IPv4_Init(VOID)
{
    SESSION_L3_PROTO_S stRegInfo;

    stRegInfo.pfPktCheck       = _session_IPv4_PktCheck;
    stRegInfo.pfPktToTuple     = _session_IPv4_Pkt2Tuple;
    stRegInfo.pfGetInvertTuple = _session_IPv4_GetInvertTuple;
    stRegInfo.pfGetL4Proto     = _session_IPv4_GetL4Proto;

    SESSION_KL3_Reg(&stRegInfo, AF_INET);

    return;
}

/* ipv4去初始化函数 */
VOID SESSION_IPv4_Fini(VOID)
{
    SESSION_KL3_DeReg(AF_INET);

    return;
}
