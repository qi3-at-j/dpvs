
#include "session.h"
#include "session_kl4_rawip.h"


#define sNO RAWIP_ST_NONE
#define sOP RAWIP_ST_OPEN
#define sRD RAWIP_ST_READY

static UCHAR g_aucRawip_state_table[SESSION_DIR_BOTH][RAWIP_ST_MAX] = {
/* ORIGINAL */
/*        sNO, sOP, sRD */
/*any*/   { sOP, sOP, sRD },
/* REPLY */
/*        sNO, sOP, sRD */
/*any*/   { sNO, sRD, sRD }
};

/* 获取RAWIP四层数据 */
STATIC VOID _session_Rawip_Pkt2Tuple(IN const MBUF_S *pstMBuf,
                                     IN UINT uiL3OffSet,
                                     IN UINT uiL4OffSet,
                                     INOUT SESSION_TUPLE_S *pstTuple)
{
    DBGASSERT(NULL!= pstTuple);
 
    pstTuple->unL4Src.usAll = 0;
    pstTuple->unL4Dst.usAll = 0;

    return;

}

/* 获取RAWIP反向数据 */
STATIC VOID _session_Rawip_GetInvertTuple(IN SESSION_S *pstSession,
                                          IN const SESSION_TUPLE_S *pstOrigTuple,
                                          INOUT SESSION_TUPLE_S *pstInverseTuple)
{
    DBGASSERT(NULL!= pstInverseTuple);

    pstInverseTuple->unL4Src.usAll = 0;
    pstInverseTuple->unL4Dst.usAll = 0;

    return;
}

/* RAWIP单包合法性检查 */
STATIC ULONG _session_Rawip_PacketCheck(IN MBUF_S *pstMBuf, IN UINT uiL3OffSet, IN UINT uiL4OffSet)
{
    
    IGNORE_PARAM(pstMBuf);
    IGNORE_PARAM(uiL3OffSet);
    IGNORE_PARAM(uiL4OffSet);

    return ERROR_SUCCESS;
}

/* RAWIP新建会话报文合法性检查 */
STATIC ULONG _session_Rawip_NewSessCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3, IN UINT uiL4OffSet)
{   
    IGNORE_PARAM(pstMBuf);
    IGNORE_PARAM(uiL3);
    IGNORE_PARAM(uiL4OffSet);

    return ERROR_SUCCESS;
}

static ULONG _session_Rawip_FirstPacket(IN const MBUF_S *pstMBuf,
                                        IN UINT uiL4OffSet,
                                        INOUT SESSION_S *pstSession)
{
    DBGASSERT(NULL != pstMBuf);    
    DBGASSERT(NULL != pstSession);

    IGNORE_PARAM(uiL4OffSet);

    pstSession->ucState = sNO;

    return ERROR_SUCCESS;
}

static ULONG _session_Rawip_State(IN SESSION_S *pstSession,
                                  IN MBUF_S *pstMBuf,
                                  IN UINT uiL3Offset,
                                  IN UINT uiL4Offset)
{
    UCHAR ucOldState;
    SESSION_PKT_DIR_E enDir;
    UCHAR ucNewState;
    
    DBGASSERT(NULL != pstMBuf);    
    DBGASSERT(NULL != pstSession);
    
    IGNORE_PARAM(uiL4Offset);    
    IGNORE_PARAM(uiL3Offset);

    ucOldState = pstSession->ucState;
    enDir = SESSION_GetDirFromMBuf(pstMBuf);

    ucNewState = g_aucRawip_state_table[enDir][ucOldState];

    if(sRD == ucNewState)
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ESTABLISH);
    }

    pstSession->ucState = ucNewState;

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, 0, 0, enDir, ucOldState, ucNewState);

    return ERROR_SUCCESS;
}

/* RAWIP获得四层以上的负载偏移和负载长度 */
STATIC ULONG _session_Rawip_GetPayload(IN MBUF_S *pstMBuf,
                                       IN UINT uiL4OffSet,
                                       OUT UINT *puiPayloadOff,
                                       OUT UINT *puiPayloadLen)
{
    DBGASSERT(NULL != pstMBuf);

    IGNORE_PARAM(uiL4OffSet);    
    IGNORE_PARAM(puiPayloadOff);
    IGNORE_PARAM(puiPayloadLen);

    SESSION_IGNORE_CONST(pstMBuf);

    return ERROR_FAILED;
}

STATIC UCHAR _session_Rawip_GetReadyState(VOID)
{
    return (sRD);
}

STATIC ULONG _session_Fast_Rawip_State(IN SESSION_S *pstSession,
                                       IN UINT uiL3OffSet,
                                       IN UINT uiL4OffSet,
                                       IN MBUF_S *pstMBuf,
                                       IN SESSION_PKT_DIR_E enDir)
{
    UCHAR ucOldState;
    UCHAR ucNewState;

    DBGASSERT(NULL != pstSession);
    DBGASSERT(NULL != pstMBuf);

    IGNORE_PARAM(uiL4OffSet);
    IGNORE_PARAM(uiL3OffSet);

    ucOldState = pstSession->ucState;

    ucNewState = g_aucRawip_state_table[enDir][ucOldState];

    if(sRD == ucNewState)
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ESTABLISH);
    }

    pstSession->ucState = ucNewState;

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, 0, 0, enDir, ucOldState, ucNewState);

    return ERROR_SUCCESS;
}

/* 从fsbuf中获取载荷偏移及长度 */
STATIC ULONG _session_Rawip_FsbufGetPayload(IN const MBUF_S *pstMBuf,
                                            IN const struct iphdr *pstIP,
                                            IN UINT uiL4OffSet,
                                            OUT UINT *puiPayloadOff,
                                            OUT UINT *puiPayloadLen)
{
    DBGASSERT(NULL != pstMBuf);    
    DBGASSERT(NULL != pstIP);

    IGNORE_PARAM(uiL4OffSet);    
    IGNORE_PARAM(puiPayloadOff);
    IGNORE_PARAM(puiPayloadLen);

    return ERROR_FAILED;
}

/* 从fsbuf中获取载荷偏移及长度 */
STATIC ULONG _session6_Rawip_FsbufGetPayload(IN const MBUF_S *pstMBuf,
                                             IN const IP6_S *pstIP6,
                                             IN UINT uiL4OffSet,
                                             OUT UINT *puiPayloadOff,
                                             OUT UINT *puiPayloadLen)
{
    DBGASSERT(NULL != pstMBuf);    
    DBGASSERT(NULL != pstIP6);

    IGNORE_PARAM(uiL4OffSet);    
    IGNORE_PARAM(puiPayloadOff);
    IGNORE_PARAM(puiPayloadLen);

    return ERROR_FAILED;
}

/******************************************************************
   Func Name:SESSION_KL4_RawipInit
Date Created:2021/04/25
      Author:wangxiaohua
 Description:RAWIP协议初始化
       INPUT:无
      Output:无
      Return:ERROR_SUCCESS  ----成功
             ERROR_FAILED   ----失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KL4_RawipInit(VOID)
{
    SESSION_L4_PROTO_S stRegInfo;
    UINT uiIndex;

    stRegInfo.pfPktToTuple            = _session_Rawip_Pkt2Tuple;
    stRegInfo.pfGetInvertTuple        = _session_Rawip_GetInvertTuple;
    stRegInfo.pfPacketCheck           = _session_Rawip_PacketCheck;
    stRegInfo.pfNewSessCheck          = _session_Rawip_NewSessCheck;
    stRegInfo.pfFirstPacket           = _session_Rawip_FirstPacket;
    stRegInfo.pfState                 = _session_Rawip_State;
    stRegInfo.pfGetL4Payload          = _session_Rawip_GetPayload;
    stRegInfo.pfGetReadyState         = _session_Rawip_GetReadyState;
    stRegInfo.pfFastState             = _session_Fast_Rawip_State;
    stRegInfo.pfFsbufGetL4Payload     = _session_Rawip_FsbufGetPayload;
    stRegInfo.pfFsbufIPv6GetL4Payload = _session6_Rawip_FsbufGetPayload;

    for(uiIndex = 0; uiIndex < IPPROTO_MAX; uiIndex++)
    {
        SESSION_KL4_Reg(&stRegInfo, (UCHAR)uiIndex);
    }

    return;
}

/******************************************************************
   Func Name:SESSION_KL4_RawipFini
Date Created:2021/04/25
      Author:wangxiaohua
 Description:RAWIP协议反初始化
       INPUT:无
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KL4_RawipFini(VOID)
{
    UINT uiIndex;

    for (uiIndex = 0; uiIndex < IPPROTO_MAX; uiIndex++)
    {
        SESSION_KL4_DeReg((UCHAR)uiIndex);
    }
    
    return;
}

