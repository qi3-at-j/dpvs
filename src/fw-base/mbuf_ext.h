#ifndef _MBUF_EXT_H_
#define _MBUF_EXT_H_


/* MBUF �лỰ��ǵ�Set �� Get ���� */
static inline VOID MBUF_SET_SESSION_FLAG(IN MBUF_S *pstMBuf, IN USHORT usFlag)
{
    pstMBuf->usSessionFlag = usFlag;
    return;
}

static inline USHORT MBUF_GET_SESSION_FLAG(IN const MBUF_S *pstMBuf)
{
    return pstMBuf->usSessionFlag;
}

/* MBUF��Ӧ�ò�Э��AppID �� Set �� Get���� */
static inline VOID MBUF_SET_APP_ID(IN MBUF_S *pstMBuf, IN UINT uiAppID)
{
    pstMBuf->uiAppIDNew = uiAppID;
    return;
}

static inline UINT MBUF_GET_APP_ID(IN const MBUF_S *pstMBuf)
{
    return pstMBuf->uiAppIDNew;
}

/* MBUF��TunnelID �� Set �� Get���� */
static inline VOID MBUF_SET_TUNNEL_ID(IN MBUF_S *pstMBuf, IN UINT uiTunnelID)
{
    pstMBuf->uiTunnelID = uiTunnelID;
    return;
}

static inline UINT MBUF_GET_TUNNEL_ID(IN const MBUF_S *pstMBuf)
{
    UINT uiTunnelID = 0;

    if (0 == (MBUF_GET_FLAG(pstMBuf) & MBUF_FLAG_VPLS))
    {
        uiTunnelID = pstMBuf->uiTunnelID;
    }

    return uiTunnelID;
}

#define MBUF_SESSION_FLAG_REPLYPKT  0x0001   /* ���ķ�����   :0-������,1-������ */
#define MBUF_SESSION_FLAG_FIRSTPKT  0x0002   /* �ױ��ı��     :0-��������,1-�ױ��� */
#define MBUF_SESSION_FLAG_ICMPERR   0x0004   /* ���ķ�����   :0-������,1-������ */
#define MBUF_SESSION_FLAG_PROCESSED 0x0008   /* �����Ѵ����� :0-δ����,1-�Ѵ��� */

#endif
