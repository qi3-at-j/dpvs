#include "socket.h"
#include "session.h"
#include "ip6_util.h"
#include "session_kl3_ipv6.h"


/* IPv6�Ϸ��Լ�� */
STATIC BOOL_T _session_IPv6Addr_IsInValid(IN const struct in6_addr *pstAddr)
{
    return (IN6ADDR_IsUnspecified(pstAddr) ||
            IN6ADDR_IsMulticast(pstAddr));
}



/* IPv6�Ϸ��Լ�� */
STATIC ULONG _session_IPv6_PktCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3OffSet)
{
    IP6_S *pstIP6;

    pstIP6 = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, IP6_S *);

    /* Ŀ�ĵ�ַ��� */

    if(_session_IPv6Addr_IsInValid(&pstIP6->stIp6Dst) ||
       _session_IPv6Addr_IsInValid(&pstIP6->stIp6Src))
    {
        return ERROR_FAILED;
    }

    return ERROR_SUCCESS;
}

/* ��MBUF��ȡIPv6��Ϣ */
STATIC VOID _session_IPv6_Pkt2Tuple(IN const MBUF_S *pstMBuf,
                                    IN UINT uiL3OffSet,
                                    INOUT SESSION_TUPLE_S *pstTuple)
{
    IP6_S* pstIP6;

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstTuple);
    
    pstIP6 = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, IP6_S *);

    pstTuple->ucL3Family = AF_INET6;
    pstTuple->unL3Dst.stin6 = pstIP6->stIp6Dst;
    pstTuple->unL3Src.stin6 = pstIP6->stIp6Src;
    pstTuple->uiTunnelID    = MBUF_GET_TUNNEL_ID(pstMBuf);
    pstTuple->vrfIndex      = MBUF_GET_RAWINVPNID(pstMBuf);

    return;
}

/* ������IP��Ϣ��ȡ����IP��Ϣ */
STATIC VOID _session_IPv6_GetInvertTuple(IN const SESSION_TUPLE_S *pstOrigTuple,
                                  INOUT SESSION_TUPLE_S *pstInverseTuple)
{
    DBGASSERT(NULL != pstOrigTuple);
    DBGASSERT(NULL != pstInverseTuple);

    pstInverseTuple->ucL3Family = pstOrigTuple->ucL3Family;
    pstInverseTuple->ucProtocol = pstOrigTuple->ucProtocol;
    pstInverseTuple->unL3Dst.stin6 = pstOrigTuple->unL3Src.stin6;
    pstInverseTuple->unL3Src.stin6 = pstOrigTuple->unL3Dst.stin6;

    /* �����ĵ�tunnelIDΪ��Чֵ������VRF INDEX��Ҫ��sesson end ʱ������ȷ�� */
    pstInverseTuple->uiTunnelID = TUNNEL_INVALID_TUNNEL_ID;
    pstInverseTuple->vrfIndex = pstOrigTuple->vrfIndex;

    return;
}

/* ��ȡL4��Э����Լ�Э��ͷƫ��λ�� */
STATIC ULONG _session_IPv6_GetL4Proto(IN MBUF_S *pstMBuf,
                                      IN UINT uiL3OffSet,
                                      OUT UINT *puiL4Offset,
                                      OUT UCHAR *pucL4ProtoNum,
                                      OUT UINT *puiIPLen)
{
    IP6_S *pstIP6;
    ULONG ulRet;
    UCHAR ucHdrProto;
    UINT uiHdrOff;

    DBGASSERT(NULL != pstMBuf);

    uiHdrOff = uiL3OffSet;
    ucHdrProto = IPPROTO_IPV6;

    /* ƫ��IPͷ���ϲ�Э��ͷ */
    ulRet = IP6_GetLastHdr(pstMBuf, &uiHdrOff, &ucHdrProto);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    pstIP6 = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, IP6_S *);

    *puiL4Offset = uiHdrOff;
    *pucL4ProtoNum = ucHdrProto;
    *puiIPLen = ntohs(pstIP6->ip6_usPLen) + sizeof(IP6_S);

    return ERROR_SUCCESS;
}

/* ipv6��ʼ������ */
VOID SESSION_IPv6_Init(VOID)
{
    SESSION_L3_PROTO_S stRegInfo;

    stRegInfo.pfPktCheck        = _session_IPv6_PktCheck;        
    stRegInfo.pfPktToTuple      = _session_IPv6_Pkt2Tuple;
    stRegInfo.pfGetInvertTuple  = _session_IPv6_GetInvertTuple;
    stRegInfo.pfGetL4Proto      = _session_IPv6_GetL4Proto;

    SESSION_KL3_Reg(&stRegInfo, AF_INET6);
    
    return;
}

/* ipv6ȥ��ʼ������ */
VOID SESSION_IPv6_Fini(VOID)
{
    SESSION_KL3_DeReg(AF_INET6);

    return;
}

