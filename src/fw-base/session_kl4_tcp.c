#include <netinet/ip.h>

#include "session.h"
#include "session_kl4_tcp.h"

UCHAR g_aucTcp_state_table[SESSION_DIR_BOTH][TCP_PKT_MAX][TCP_ST_MAX] = {
    {
/* ORIGINAL */
/*           sTCP_NO, sTCP_SS, sTCP_SR, sTCP_ES, sTCP_FW, sTCP_CW, sTCP_LA, sTCP_TW, sTCP_CL, sTCP_S2 */
/*syn*/    { sTCP_SS, sTCP_SS, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_SS, sTCP_SS, sTCP_S2 },
/*synack*/ { sTCP_IV, sTCP_IV, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_SR },
/*fin*/    { sTCP_IV, sTCP_IV, sTCP_FW, sTCP_FW, sTCP_LA, sTCP_LA, sTCP_LA, sTCP_TW, sTCP_CL, sTCP_IV},
/*ack*/    { sTCP_ES, sTCP_ES, sTCP_ES, sTCP_ES, sTCP_CW, sTCP_CW, sTCP_TW, sTCP_TW, sTCP_CL, sTCP_IV },
/*rst*/    { sTCP_IV, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL },
/*none*/   { sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV }
    },
    {
/* REPLY */  
/*           sTCP_NO, sTCP_SS, sTCP_SR, sTCP_ES, sTCP_FW, sTCP_CW, sTCP_LA, sTCP_TW, sTCP_CL, sTCP_S2 */
/*syn*/    { sTCP_IV, sTCP_S2, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_S2 },
/*synack*/ { sTCP_IV, sTCP_SR, sTCP_SR, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_IG, sTCP_SR},
/*fin*/    { sTCP_IV, sTCP_IV, sTCP_FW, sTCP_FW, sTCP_LA, sTCP_LA, sTCP_LA, sTCP_TW, sTCP_CL, sTCP_IV},
/*ack*/    { sTCP_IV, sTCP_IG, sTCP_SR, sTCP_ES, sTCP_CW, sTCP_CW, sTCP_TW, sTCP_TW, sTCP_CL, sTCP_IG},
/*rst*/    { sTCP_IV, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL, sTCP_CL },
/*none*/   { sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV, sTCP_IV }

    }
};

/*initialized by SESSION_KL4_TcpInit()*/
UCHAR g_aucTcpPktType[TCP_PKT_BITTYPE_MAX];

/* table of valid flag combinations - PUSH, ECE and CWR are always valid */
BOOL_T g_abTcp_valid_flags[TCP_PKT_BITTYPE_MAX] = 
{
    [TH_SYN]               = BOOL_TRUE,
    [TH_SYN|TH_URG]        = BOOL_TRUE,
    [TH_SYN|TH_ACK]        = BOOL_TRUE,    
    [TH_RST]               = BOOL_TRUE,
    [TH_RST|TH_ACK]        = BOOL_TRUE,      
    [TH_FIN|TH_ACK]        = BOOL_TRUE,    
    [TH_FIN|TH_ACK|TH_URG] = BOOL_TRUE,     
    [TH_ACK]               = BOOL_TRUE,    
    [TH_ACK|TH_URG]        = BOOL_TRUE,
};

static inline UCHAR _session_Tcp_get_pkt_type(IN const TCPHDR_S *pstTcpHdr)
{
    UCHAR ucFlags;

    ucFlags = (pstTcpHdr->th_flags) & TCP_FLAGS_CARE_MASK;
    
    return g_aucTcpPktType[ucFlags];
}


/* 获取TCP四层数据 */
STATIC VOID _session_Tcp_Pkt2Tuple(IN const MBUF_S *pstMBuf,
                                   IN UINT uiL3OffSet,
                                   IN UINT uiL4OffSet,
                                   INOUT SESSION_TUPLE_S *pstTuple)
{
    TCPHDR_S *pstTcpHdr;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstTuple);

    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);

    pstTuple->unL4Dst.stTcp.usPort = pstTcpHdr->th_dport;
    pstTuple->unL4Src.stTcp.usPort = pstTcpHdr->th_sport;

    return;
}

/* 获取TCP反向数据 */
STATIC VOID _session_Tcp_GetInvertTuple(IN SESSION_S *pstSession,
                                        IN const SESSION_TUPLE_S *pstOrigTuple,
                                        INOUT SESSION_TUPLE_S *pstInverseTuple)
{
    DBGASSERT(NULL != pstOrigTuple);
    DBGASSERT(NULL != pstInverseTuple);
    IGNORE_PARAM(pstSession);

    pstInverseTuple->unL4Dst.stTcp.usPort = pstOrigTuple->unL4Src.stTcp.usPort;
    pstInverseTuple->unL4Src.stTcp.usPort = pstOrigTuple->unL4Dst.stTcp.usPort;

    return;
}

/* TCP单包合法性检查 */
STATIC ULONG _session_Tcp_PacketCheck(IN MBUF_S *pstMBuf, 
                                      IN UINT uiL3OffSet, 
                                      IN UINT uiL4OffSet)
{
    ULONG ulRet;
    TCPHDR_S *pstTcpHdr;
    UCHAR ucFlags;

    DBGASSERT(NULL != pstMBuf);
    IGNORE_PARAM(uiL3OffSet);

    ulRet = MBUF_PULLUP(pstMBuf, uiL4OffSet + (UINT32)sizeof(TCPHDR_S));
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);
    ucFlags = (pstTcpHdr->th_flags) & TCP_FLAGS_CARE_MASK;

    if(BOOL_TRUE == g_abTcp_valid_flags[ucFlags])
    {
        return ERROR_SUCCESS;
    }

    return ERROR_FAILED;
}

/* TCP新建会话报文合法性检查 */
STATIC ULONG _session_Tcp_NewSessCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3, IN UINT uiL4OffSet)
{
    TCPHDR_S* pstTcpHdr;
    UCHAR ucFlags;

    DBGASSERT(NULL != pstMBuf);
    IGNORE_PARAM(uiL3);

    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);    
    ucFlags = (pstTcpHdr->th_flags) & TCP_FLAGS_CARE_MASK & (~TH_URG);

    if((TH_SYN == ucFlags) || (TH_ACK == ucFlags))
    {
        return ERROR_SUCCESS;
    }

    return ERROR_FAILED;
}

static ULONG _session_Tcp_FirstPacket(IN const MBUF_S *pstMBuf,
                                      IN UINT uiL4OffSet,
                                      INOUT SESSION_S *pstSession)
{
    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstSession);

    IGNORE_PARAM(uiL4OffSet);

    pstSession->ucState = sTCP_NO;

    return ERROR_SUCCESS;
}

static ULONG _session_Tcp_State(IN SESSION_S *pstSession,
                                IN MBUF_S *pstMBuf,
                                IN UINT uiL3OffSet,
                                IN UINT uiL4OffSet)
{
    TCPHDR_S *pstTcpHdr;
    UCHAR ucOldState;
    SESSION_PKT_DIR_E enDir;
    UCHAR ucIndex;
    UCHAR ucNewState;
    BOOL_T bNeedSetNewState = BOOL_TRUE;
    ULONG ulRet = ERROR_SUCCESS;
    SESSION_CTRL_S *pstSessionCtrl;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstSession);

    pstSessionCtrl = SESSION_CtrlData_Get();
    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);

    ucOldState = pstSession->ucState;
    enDir = SESSION_GetDirFromMBuf(pstMBuf);

    ucIndex = _session_Tcp_get_pkt_type(pstTcpHdr);
    ucNewState = (pstSessionCtrl->pucTcpStateTable)[((enDir*TCP_PKT_MAX*TCP_ST_MAX)+(ucIndex*TCP_ST_MAX))+ucOldState];

    switch(ucNewState)
    {
        case sTCP_ES:
        {
            SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ESTABLISH);
            break;
        }
        case sTCP_CL:
        {
            /*如果是正常流结束，设置删除日志类型*/

            break;
        }
        case sTCP_IV:
        {
            bNeedSetNewState = BOOL_FALSE;
            ulRet = ERROR_FAILED;
            break;
        }
        case sTCP_IG:
        {
            bNeedSetNewState = BOOL_FALSE;
            break;
        }
        default:
        {
            ulRet = ERROR_SUCCESS;
            break;
        }
    }

    if(BOOL_TRUE == bNeedSetNewState)
    {
        pstSession->ucState = ucNewState;
    }

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, pstTcpHdr->th_flags, ucIndex, enDir, ucOldState, pstSession->ucState);

    return ulRet;
}

/* TCP获得四层以上的负载偏移和负载长度 */
STATIC ULONG _session_Tcp_GetPayload(IN MBUF_S *pstMBuf,
                                     IN UINT uiL4OffSet,
                                     OUT UINT *puiPayloadOff,
                                     OUT UINT *puiPayloadLen)
{
    TCPHDR_S *pstTcpHdr;
    UINT uiHLen;

    DBGASSERT(NULL!= pstMBuf);

    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *); 
    uiHLen = pstTcpHdr->th_off*4;

    return SESSION_Util_GetL4Payload_Default(pstMBuf, uiL4OffSet, uiHLen, puiPayloadOff, puiPayloadLen);
}

/* TCP获得ReadyState */
STATIC inline UCHAR _session_Tcp_GetReadyState(VOID)
{
    return (sTCP_ES);
}

/* Tcp FSBUF状态机处理 */
static ULONG _session_Fast_Tcp_State(IN SESSION_S *pstSession,
                                     IN UINT uiL3OffSet,
                                     IN UINT uiL4OffSet,
                                     IN MBUF_S *pstMBuf,
                                     IN SESSION_PKT_DIR_E enDir)
{
    TCPHDR_S *pstTcpHdr;
    UCHAR ucOldState;
    UCHAR ucIndex;
    UCHAR ucNewState;
    BOOL_T bNeedSetNewState = BOOL_TRUE;
    ULONG ulRet = ERROR_SUCCESS;
    SESSION_CTRL_S *pstSessionCtrl;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstSession);
    DBGASSERT(NULL != pstMBuf);

    pstSessionCtrl = SESSION_CtrlData_Get();
    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);

    ucOldState = pstSession->ucState;

    ucIndex = _session_Tcp_get_pkt_type(pstTcpHdr);
    ucNewState = (pstSessionCtrl->pucTcpStateTable)[(((UCHAR)enDir*(UCHAR)TCP_PKT_MAX*(UCHAR)TCP_ST_MAX)+
                                      (ucIndex*(UCHAR)TCP_ST_MAX))+ucOldState];
    /* 调用TCP Mss业务处理 */
    SESSION_FsTcpMssProc(pstSession, ucIndex, pstMBuf, pstTcpHdr);

    switch(ucNewState)
    {
        case sTCP_ES:
        {
            SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ESTABLISH);
            break;
        }
        case sTCP_CL:
        {
            /* 如果是正常流结束，设置删除日志类型 */
            break;
        }
        case sTCP_IV:
        {
            bNeedSetNewState = BOOL_FALSE;
            ulRet = ERROR_FAILED;
            break;
        }
        case sTCP_IG:
        {
            bNeedSetNewState = BOOL_FALSE;
            break;
        }
        default:
        {
            pstSession->ucState = ucNewState;
            break;
        }
    }

    if(BOOL_TRUE == bNeedSetNewState)
    {
        pstSession->ucState = ucNewState;
    }

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, pstTcpHdr->th_flags, ucIndex, enDir, ucOldState, pstSession->ucState);
    return ulRet;
}

/* 从fsbuf中获取载荷偏移及长度 */
STATIC ULONG _session_Tcp_FsbufGetPayload(IN const MBUF_S *pstMBuf,
                                          IN const struct iphdr *pstIP,
                                          IN UINT uiL4OffSet,
                                          OUT UINT *puiPayloadOff,
                                          OUT UINT *puiPayloadLen)
{
    TCPHDR_S* pstTcpHdr;
    UINT uiHLen;

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstIP);
    
    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);
    uiHLen = pstTcpHdr->th_off*4;

    return SESSION_Util_FsbufGetL4Payload_Default(pstMBuf,
                                                  pstIP,
                                                  uiL4OffSet,
                                                  uiHLen,
                                                  puiPayloadOff,
                                                  puiPayloadLen);
}

/* 从fsbuf中获取载荷偏移及长度 */
STATIC ULONG _session6_Tcp_FsbufGetPayload(IN const MBUF_S *pstMBuf,
                                           IN const IP6_S *pstIP,
                                           IN UINT uiL4OffSet,
                                           OUT UINT *puiPayloadOff,
                                           OUT UINT *puiPayloadLen)
{
    TCPHDR_S* pstTcpHdr;
    UINT uiHLen;

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstIP);
    
    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, TCPHDR_S *);
    uiHLen = pstTcpHdr->th_off*4;

    return SESSION6_Util_FsbufGetL4Payload_Default(pstMBuf,
                                                   pstIP,
                                                   uiL4OffSet,
                                                   uiHLen,
                                                   puiPayloadOff,
                                                   puiPayloadLen);
}

/******************************************************************
   Func Name:SESSION_KL4_TcpInit
Date Created:2021/04/25
      Author:wangxiaohua
 Description:TCP协议初始化
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
VOID SESSION_KL4_TcpInit(VOID)
{
    SESSION_L4_PROTO_S stRegInfo;
    UINT uiIndex;

    stRegInfo.pfPktToTuple            =_session_Tcp_Pkt2Tuple;
    stRegInfo.pfGetInvertTuple        =_session_Tcp_GetInvertTuple;
    stRegInfo.pfPacketCheck           =_session_Tcp_PacketCheck;
    stRegInfo.pfNewSessCheck          =_session_Tcp_NewSessCheck;
    stRegInfo.pfFirstPacket           =_session_Tcp_FirstPacket;
    stRegInfo.pfState                 =_session_Tcp_State;
    stRegInfo.pfGetL4Payload          =_session_Tcp_GetPayload;
    stRegInfo.pfGetReadyState         =_session_Tcp_GetReadyState;
    stRegInfo.pfFastState             =_session_Fast_Tcp_State;
    stRegInfo.pfFsbufGetL4Payload     =_session_Tcp_FsbufGetPayload;
    stRegInfo.pfFsbufIPv6GetL4Payload =_session6_Tcp_FsbufGetPayload;

    for (uiIndex=0; uiIndex < TCP_PKT_BITTYPE_MAX; uiIndex++)
    {
        g_aucTcpPktType[uiIndex] = TCP_PKT_NONE;
    }

    g_aucTcpPktType[TH_SYN]          = TCP_PKT_SYN;
    g_aucTcpPktType[TH_SYN|TH_URG]   = TCP_PKT_SYN;
    g_aucTcpPktType[TH_SYN|TH_ACK]   = TCP_PKT_SYNACK;
    
    g_aucTcpPktType[TH_RST]          = TCP_PKT_RST;
    g_aucTcpPktType[TH_RST|TH_ACK]   = TCP_PKT_RST;
    g_aucTcpPktType[TH_FIN|TH_ACK]   = TCP_PKT_FIN;
    g_aucTcpPktType[TH_FIN|TH_ACK|TH_URG]   = TCP_PKT_FIN;
    g_aucTcpPktType[TH_ACK]          = TCP_PKT_ACK;    
    g_aucTcpPktType[TH_ACK|TH_URG]   = TCP_PKT_ACK;

    SESSION_KL4_Reg(&stRegInfo, IPPROTO_TCP);

    return;
}

/* TCP协议反初始化 */
VOID SESSION_KL4_TcpFini(VOID)
{
    SESSION_KL4_DeReg(IPPROTO_TCP);
    return;
}
