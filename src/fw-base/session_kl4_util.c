
#include "baseype.h"
#include "socket.h"
#include "ipfw.h"
#include "ip6fw.h"
#include "session_util.h"
#include "flow.h"
#include "session.h"


/* ����Ĳ����ϵĸ��غ͸��س��� */
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

    /* L4��ͷ֮��Ĳ��ֲ�һ�������غɣ����ܻ���L2����ֽ���� */
    /* �ȴ�IPͷ��ȡ���ĳ��ȣ��ó��ȱ���Ϸ� */
    if(AF_INET == ucFamily)
    {
        pstIP = MBUF_BTOD_OFFSET(pstMBuf, 0, struct iphdr*);
        uiL3TotalLen = pstIP->tot_len;
    }
    else
    {
        pstIP6 = MBUF_BTOD_OFFSET(pstMBuf, 0,IP6_S*);
        /* IPV6�п�������չͷ���������Ӧ����4��ͷƫ�� */
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

/* ����Ĳ����ϵĸ��غ͸��س��� */
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

    /* L4��ͷ֮��Ĳ��ֲ�һ�������غɣ����ܻ���L2����ֽ����,�ȴ�IPͷ��ȡ���ĳ��ȣ��ó��ȱ���Ϸ�,*/
    /* �����תuiL4OffSetΪipͷ���ȣ�����ת��uiL4OffSetΪipͷ���ȼ���·ͷ���� */
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

/* ����Ĳ����ϵĸ��غ͸��س��� */
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

    /* L4��ͷ֮��Ĳ��ֲ�һ�������غɣ����ܻ���L2����ֽ���� */
    /* �ȴ�IPͷ��ȡ���ĳ��ȣ��ó��ȱ���Ϸ� */
    /* IPv6�п�������չͷ���������Ӧ����4��ͷƫ�� */
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

