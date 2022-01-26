#ifndef _MBUF_EXT_H_
#define _MBUF_EXT_H_


/* MBUF 中会话标记的Set 和 Get 操作 */
static inline VOID MBUF_SET_SESSION_FLAG(IN MBUF_S *pstMBuf, IN USHORT usFlag)
{
    pstMBuf->usSessionFlag = usFlag;
    return;
}

static inline USHORT MBUF_GET_SESSION_FLAG(IN const MBUF_S *pstMBuf)
{
    return pstMBuf->usSessionFlag;
}

/* MBUF中应用层协议AppID 的 Set 和 Get操作 */
static inline VOID MBUF_SET_APP_ID(IN MBUF_S *pstMBuf, IN UINT uiAppID)
{
    pstMBuf->uiAppIDNew = uiAppID;
    return;
}

static inline UINT MBUF_GET_APP_ID(IN const MBUF_S *pstMBuf)
{
    return pstMBuf->uiAppIDNew;
}

/* MBUF中TunnelID 的 Set 和 Get操作 */
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

#define MBUF_SESSION_FLAG_REPLYPKT  0x0001   /* 报文方向标记   :0-正向报文,1-反向报文 */
#define MBUF_SESSION_FLAG_FIRSTPKT  0x0002   /* 首报文标记     :0-后续报文,1-首报文 */
#define MBUF_SESSION_FLAG_ICMPERR   0x0004   /* 报文方向标记   :0-正向报文,1-反向报文 */
#define MBUF_SESSION_FLAG_PROCESSED 0x0008   /* 报文已处理标记 :0-未处理,1-已处理 */

#endif
