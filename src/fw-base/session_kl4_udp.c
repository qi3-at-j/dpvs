#include "udp.h"
#include "session.h"
#include "session_kl4_udp.h"

#define sNO UDP_ST_NONE
#define sOP UDP_ST_OPEN
#define sRD UDP_ST_READY

static UCHAR g_aucUdp_state_table[SESSION_DIR_BOTH][UDP_ST_MAX] = {
/* ORIGINAL */
/*      sNO, sOP, sRD */
/*any*/ {sOP, sOP, sRD},
/* REPLY */
/*      sNO, sOP, sRD */
/*any*/ {sNO, sRD, sRD},

};

/* 获取UDP四层数据 */
STATIC VOID _session_Udp_Pkt2Tuple(IN const MBUF_S *pstMBuf,
                                   IN UINT uiL3OffSet,
                                   IN UINT uiL4OffSet,
                                   INOUT SESSION_TUPLE_S *pstTuple)
{
    UDPHDR_S *pstUdpHdr;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstTuple);

    pstUdpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, UDPHDR_S *);

    pstTuple->unL4Dst.stUdp.usPort = pstUdpHdr->uh_dport;
    pstTuple->unL4Src.stUdp.usPort = pstUdpHdr->uh_sport;
    
    return;
}

/* 获取UDP反向数据 */
STATIC VOID _session_Udp_GetInvertTuple(IN SESSION_S *pstSession,
                                        IN const SESSION_TUPLE_S *pstOrigTuple,
                                        INOUT SESSION_TUPLE_S *pstInverseTuple)
{
    
    DBGASSERT(NULL != pstOrigTuple);
    DBGASSERT(NULL != pstInverseTuple);
    IGNORE_PARAM(pstSession);

    pstInverseTuple->unL4Dst.stUdp.usPort = pstOrigTuple->unL4Src.stUdp.usPort;
    pstInverseTuple->unL4Src.stUdp.usPort = pstOrigTuple->unL4Dst.stUdp.usPort;

    return;
}

/* UDP单包合法性检查 */
STATIC ULONG _session_Udp_PacketCheck(IN MBUF_S *pstMBuf, IN UINT uiL3OffSet, IN UINT uiL4OffSet)
{
    ULONG ulRet;

    IGNORE_PARAM(uiL3OffSet);

    ulRet = MBUF_PULLUP(pstMBuf, uiL4OffSet + (UINT32)sizeof(UDPHDR_S));
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    return ERROR_SUCCESS;
}

/* UDP新建会话报文合法性检查 */
STATIC ULONG _session_Udp_NewSessCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3, IN UINT uiL4OffSet)
{    
    DBGASSERT(NULL != pstMBuf);
    
    IGNORE_PARAM(uiL4OffSet);
    IGNORE_PARAM(uiL3);
    
    return ERROR_SUCCESS;
}

/* 会话首包处理 */
static ULONG _session_Udp_FirstPacket(IN const MBUF_S *pstMBuf,
                                      IN UINT uiL4OffSet,
                                      INOUT SESSION_S *pstSession)
{
    
    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstSession);

    IGNORE_PARAM(uiL4OffSet);

    pstSession->ucState = sNO;

    return ERROR_SUCCESS;
}

/* UDP状态机处理 */
static ULONG _session_Udp_State(IN SESSION_S *pstSession,
                                IN MBUF_S *pstMBuf,
                                IN UINT uiL3OffSet,
                                IN UINT uiL4OffSet)
{
    UCHAR ucOldState;
    SESSION_PKT_DIR_E enDir;
    UCHAR ucNewStae;

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstSession);

    IGNORE_PARAM(uiL4OffSet);    
    IGNORE_PARAM(uiL3OffSet);

    ucOldState = pstSession->ucState;
    enDir = SESSION_GetDirFromMBuf(pstMBuf);

    ucNewStae = g_aucUdp_state_table[enDir][ucOldState];
    if(sRD == ucNewStae)
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ESTABLISH);
    }

    pstSession->ucState = ucNewStae;

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, 0, 0, enDir, ucOldState, ucNewStae);

    return ERROR_SUCCESS;
}

/* UDP获得四层以上的负载偏移和负载长度 */
STATIC ULONG _session_Udp_GetPayload(IN MBUF_S *pstMBuf,
                                     IN UINT uiL4OffSet,
                                     OUT UINT *puiPayloadOff,
                                     OUT UINT *puiPayloadLen)
{
    return SESSION_Util_GetL4Payload_Default(pstMBuf,
                                             uiL4OffSet,
                                             (UINT32)sizeof(UDPHDR_S),
                                             puiPayloadOff,
                                             puiPayloadLen);
}

/* Udp获得ReadyState */
UCHAR _session_Udp_GetReadyState(VOID)
{
    return (sRD);
}

/* UDP FSBUF状态机处理 */
STATIC ULONG _session_Fast_Udp_State(IN SESSION_S *pstSession,
                                     IN UINT uiL3OffSet,
                                     IN UINT uiL4OffSet,
                                     IN MBUF_S *pstMBuf,
                                     IN SESSION_PKT_DIR_E enDir)
{
    UCHAR ucOldState;
    UCHAR ucNewState;
    
    DBGASSERT(NULL != pstSession);
    DBGASSERT(NULL != pstMBuf);

    IGNORE_PARAM(uiL3OffSet);    
    IGNORE_PARAM(uiL4OffSet);  

    ucOldState = pstSession->ucState;

    ucNewState = g_aucUdp_state_table[enDir][ucOldState];

    if(sRD == ucNewState)
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ESTABLISH);
    }

    pstSession->ucState = ucNewState;

    return ERROR_SUCCESS;
}

/* 从fsbuf中获取载荷偏移及长度 */
STATIC ULONG _session_Udp_FsbufGetPayload(IN const MBUF_S *pstMBuf,
                                          IN const struct iphdr *pstIP,
                                          IN UINT uiL4OffSet,
                                          OUT UINT *puiPayloadOff,
                                          OUT UINT *puiPayloadLen)
{
    return SESSION_Util_FsbufGetL4Payload_Default(pstMBuf,
                                                  pstIP,
                                                  uiL4OffSet,
                                                  (UINT32)sizeof(UDPHDR_S),
                                                  puiPayloadOff,
                                                  puiPayloadLen);
}

STATIC ULONG _session6_Udp_FsbufGetPayload(IN const MBUF_S *pstMBuf,
                                           IN const IP6_S *pstIP6,
                                           IN UINT uiL4OffSet,
                                           OUT UINT *puiPayloadOff,
                                           OUT UINT *puiPayloadLen)
{
    return SESSION6_Util_FsbufGetL4Payload_Default(pstMBuf,
                                                   pstIP6,
                                                   uiL4OffSet,
                                                   (UINT32)sizeof(UDPHDR_S),
                                                   puiPayloadOff,
                                                   puiPayloadLen);
}


/******************************************************************
   Func Name:SESSION_KL4_UdpInit
Date Created:2021/04/25
      Author:wangxiaohua
 Description:UDP协议初始化
       INPUT:无
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KL4_UdpInit(VOID)
{
    SESSION_L4_PROTO_S stRegInfo;

    stRegInfo.pfPktToTuple            =_session_Udp_Pkt2Tuple;
    stRegInfo.pfGetInvertTuple        =_session_Udp_GetInvertTuple;
    stRegInfo.pfPacketCheck           =_session_Udp_PacketCheck;
    stRegInfo.pfNewSessCheck          =_session_Udp_NewSessCheck;
    stRegInfo.pfFirstPacket           =_session_Udp_FirstPacket;
    stRegInfo.pfState                 =_session_Udp_State;
    stRegInfo.pfGetL4Payload          =_session_Udp_GetPayload;
    stRegInfo.pfGetReadyState         =_session_Udp_GetReadyState;
    stRegInfo.pfFastState             =_session_Fast_Udp_State;
    stRegInfo.pfFsbufGetL4Payload     =_session_Udp_FsbufGetPayload;
    stRegInfo.pfFsbufIPv6GetL4Payload =_session6_Udp_FsbufGetPayload;

    SESSION_KL4_Reg(&stRegInfo, IPPROTO_UDP);

    return;
}

/******************************************************************
   Func Name:SESSION_KL4_UdpFini
Date Created:2021/04/25
      Author:wangxiaohua
 Description:UDP协议反初始化
       INPUT:无
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KL4_UdpFini(VOID)
{
    SESSION_KL4_DeReg(IPPROTO_UDP);

    return;
}

