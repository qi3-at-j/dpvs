
#include "baseype.h"
#include "socket.h"
#include "ipfw.h"
#include "ip6fw.h"
#include "session_util.h"
#include "flow.h"
#include "session.h"


/* 获得四层以上的负载和负载长度 */
ULONG SESSION_Util_GetL4Payload_Default(IN MBUF_S *pstMBuf,
                                        IN UINT uiL4OffSet,
                                        IN UINT uiL4HdrLen,
                                        OUT UINT *puiPayloadOff,
                                        OUT UINT *puiPayloadLen)
{
    ULONG ulRet;
    UINT uiTotalOffSet;
    UINT uiPayloadOff;
    struct iphdr *pstIP;
    IP6_S *pstIP6;
    UINT uiL3TotalLen;
    UCHAR ucFamily;
    conn_sub_t *csp;
    
	csp = GET_CSP_FROM_LBUF(pstMBuf);
	ucFamily = GET_CSP_FAMILY(csp); 

    uiTotalOffSet = MBUF_GET_TOTALDATASIZE(pstMBuf);

    ulRet = MBUF_PULLUP(pstMBuf, uiTotalOffSet);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /* L4层头之后的部分不一定都是载荷，可能还有L2层的字节填充 */
    /* 先从IP头获取报文长度，该长度必须合法 */
    if(AF_INET == ucFamily)
    {
        pstIP = MBUF_BTOD_OFFSET(pstMBuf, 0, struct iphdr*);
        uiL3TotalLen = pstIP->tot_len;
    }
    else
    {
        pstIP6 = MBUF_BTOD_OFFSET(pstMBuf, 0,IP6_S*);
        /* IPV6有可能有扩展头，因此这里应该用4层头偏移 */
        uiL3TotalLen = ntohs(pstIP6->ip6_usPLen) + uiL4OffSet;
    }

    if(uiL3TotalLen > uiTotalOffSet)
    {
        uiL3TotalLen = uiTotalOffSet;
    }

    uiPayloadOff = uiL4OffSet + uiL4HdrLen;
    if(uiL3TotalLen < uiPayloadOff)
    {
        return ERROR_FAILED;
    }

    *puiPayloadOff = uiPayloadOff;
    *puiPayloadLen = uiL3TotalLen - uiPayloadOff;

    return ERROR_SUCCESS;
}

/* 获得四层以上的负载和负载长度 */
ULONG SESSION_Util_FsbufGetL4Payload_Default(IN const MBUF_S *pstMBuf,
                                             IN const struct iphdr *pstIP,
                                             IN UINT uiL4OffSet,
                                             IN UINT uiL4HdrLen,
                                             OUT UINT *puiPayloadOff,
                                             OUT UINT *puiPayloadLen)
{
    UINT uiTotalOffSet;
    UINT uiPayloadOff;
    UINT uiTotalLen;
    UINT uiL2Len;

    uiTotalOffSet = MBUF_GET_TOTALDATASIZE(pstMBuf);

    /* L4层头之后的部分不一定都是载荷，可能还有L2层的字节填充,先从IP头获取报文长度，该长度必须合法,*/
    /* 三层快转uiL4OffSet为ip头长度，二层转发uiL4OffSet为ip头长度加链路头长度 */
    uiL2Len = uiL4OffSet - ((UINT)pstIP->ihl << 2);
    uiTotalLen = pstIP->tot_len + uiL2Len;
    if(uiTotalLen > uiTotalOffSet)
    {
        uiTotalLen = uiTotalOffSet;
    }

    uiPayloadOff = uiL4OffSet + uiL4HdrLen;
    if (uiTotalLen < uiPayloadOff)
    {
        return ERROR_FAILED;
    }

    *puiPayloadOff = uiPayloadOff;
    *puiPayloadLen = uiTotalLen - uiPayloadOff;

    return ERROR_SUCCESS;
}

/* 获得四层以上的负载和负载长度 */
ULONG SESSION6_Util_FsbufGetL4Payload_Default(IN const MBUF_S *pstMBuf,
                                              IN const IP6_S *pstIP6,
                                              IN UINT uiL4OffSet,
                                              IN UINT uiL4HdrLen,
                                              OUT UINT *puiPayloadOff,
                                              OUT UINT *puiPayloadLen)
{
    UINT uiTotalOffSet;
    UINT uiPayloadOff;
    UINT uiL3TotalLen;

    uiTotalOffSet = MBUF_GET_TOTALDATASIZE(pstMBuf);

    /* L4层头之后的部分不一定都是载荷，可能还有L2层的字节填充 */
    /* 先从IP头获取报文长度，该长度必须合法 */
    /* IPv6有可能有扩展头，因此这里应该用4层头偏移 */
    uiL3TotalLen = ntohs(pstIP6->ip6_usPLen) + uiL4OffSet;
    if(uiL3TotalLen > uiTotalOffSet)
    {
        uiL3TotalLen = uiTotalOffSet;
    }

    uiPayloadOff = uiL4OffSet + uiL4HdrLen;
    if(uiL3TotalLen < uiPayloadOff)
    {
        return ERROR_FAILED;
    }

    *puiPayloadOff = uiPayloadOff;
    *puiPayloadLen = uiL3TotalLen - uiPayloadOff;

    return ERROR_SUCCESS;
}

