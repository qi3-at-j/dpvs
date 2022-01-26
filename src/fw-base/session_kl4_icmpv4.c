
#include <netinet/ip.h>

#include "session.h"
#include "session_kl4proto.h"
#include "ip_icmp.h"
#include "session_kcore.h"
#include "session_kdebug.h"


/*ICMP、ICMPv6状态机*/
extern UCHAR g_aucIcmp_state_table[ICMP_PKT_MAX][ICMP_ST_MAX];

/*只考虑<=ICMP_MASKREPLY的type*/
UCHAR g_aucIcmpPktType[] = {
    ICMP_PKT_REPLY,         /*ICMP_ECHOREPLY  0*/
    ICMP_PKT_OTHER,
    ICMP_PKT_OTHER,
    ICMP_PKT_OTHER,         /*ICMP_UNREACH        3*/
    ICMP_PKT_OTHER,         /*ICMP_SOURCEQUENCH   4*/
    ICMP_PKT_OTHER,         /*ICMP_REDIRECT       5*/
    ICMP_PKT_OTHER,         /*ICMP_ALTHOSTADDR    6*/
    ICMP_PKT_OTHER,
    ICMP_PKT_REQUEST,       /*ICMP_ECHO           8*/
    ICMP_PKT_REPLY,         /*ICMP_ROUTERADVERT   9*/
    ICMP_PKT_REQUEST,       /*ICMP_ROUTERSOLICIT  10*/
    ICMP_PKT_OTHER,         /*ICMP_TIMXCEED       11*/
    ICMP_PKT_OTHER,         /*ICMP_PARAMPROB      12*/
    ICMP_PKT_REQUEST,       /*ICMP_TSTAMP         13*/
    ICMP_PKT_REPLY,         /*ICMP_TSTAMPREPLY    14*/
    ICMP_PKT_REQUEST,       /*ICMP_IREQ           15*/
    ICMP_PKT_REPLY,         /*ICMP_IREQREPLY      16*/
    ICMP_PKT_REQUEST,       /*ICMP_MASKREQ        17*/
    ICMP_PKT_REPLY,         /*ICMP_MASKREPLY      18*/
};

/*只考虑<=ICMP_MASKREPLY的type*/
UCHAR g_aucIcmpReverType[] = {
    ICMP_ECHO,
    0,                    /* 非法ICMP的TYPE类型 */
    0,                    /* 非法ICMP的TYPE类型 */
    0,                    /* 差错控制报文: ICMP_UNREACH */
    0,                    /* 差错控制报文: ICMP_SOURCEQUENCH */
    0,                    /* 差错控制报文: ICMP_REDIRECT */
    0,                    /* 非法ICMP的TYPE类型 */
    0,                    /* 非法ICMP的TYPE类型 */
    ICMP_ECHOREPLY,
    ICMP_ROUTERSOLICIT,
    ICMP_ROUTERADVERT,
    0,                    /* 差错控制报文: ICMP_TIMXCEED */    
    0,                    /* 差错控制报文: ICMP_PARAMPROB */
    ICMP_TSTAMPREPLY,
    ICMP_TSTAMP,
    ICMP_IREQREPLY,
    ICMP_IREQ,
    ICMP_MASKREPLY,
    ICMP_MASKREQ
};

UCHAR g_aucIcmp_state_table[ICMP_PKT_MAX][ICMP_ST_MAX] = {
/*                sNO,  sOP, sCL */
/*icmp_request*/    {sOP, sOP, sOP},
/*icmp_reply*/      {sIV, sCL, sCL},
};

/* 根据报文的type和code判断是否是需要关心的ICMP查询请求应答报文 */
STATIC BOOL_T SESSION_KL4_IsIcmpReq(IN UCHAR ucType, IN UCHAR ucCode)
{
    /*type 和 code 是以下取值范围才是期望的icmp查询请求应答报文
   
            type                             code  
        ICMP_ECHOREPLY          0             0
        ICMP_ECHO               8             0
        ICMP_ROUTERADVERT       9             0
        ICMP_ROUTERSOLICIT      10            0
        ICMP_TSTAMP             13            0
        ICMP_ISTAMPREPLY        14            0
        ICMP_IREQ               15            0
        ICMP_IREQREPLY          16            0
        ICMP_MASKREQ            17            0
        ICMP_MASKREPLY          18            0
    */
    return ((ucType <= ICMP_MASKREPLY) &&
            (ICMP_PKT_OTHER != g_aucIcmpPktType[ucType]) &&
            (0 == ucCode));
}

/******************************************************************
   Func Name:_session_Icmp_IsIcmpErr
Date Created:2021/04/25
      Author:wangxiaohua
 Description:根据报文的type和code判断是否是需要关心的ICMP差错控制报文
       INPUT:IN UCHAR ucType  ----报文的type
             IN UCHAR ucCode  ----报文的code
      Output:无
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/

static inline BOOL_T _session_Icmp_IsIcmpErr(IN UCHAR ucType, IN UCHAR ucCode)
{
    /*type 和 code是以下组合和取值范围才是期望的icmp差错控制报文

          type            code
      ICMP_UNREACH        [0, 13]
      ICMP_SOURCEQUENCH   [0, 0]
      ICMP_REDIRECT       [0, 3]
      ICMP_TIMXCEED       [0, 1]
      ICMP_PARAMPROB      [0, 1]
    */
    
    return (((ICMP_UNREACH == ucType)&&(ucCode <=13))||
            ((ICMP_SOURCEQUENCH == ucType)&&(0 == ucCode)) ||
            ((ICMP_REDIRECT == ucType)&&(ucCode <= 3)) ||
            ((ICMP_TIMXCEED == ucType)&&(ucCode <= 1)) ||
            ((ICMP_PARAMPROB == ucType)&&(ucCode <= 1)));
}

/* 获取ICMP四层数据 */
STATIC VOID _session_Icmp_Pkt2Tuple(IN const MBUF_S *pstMBuf,
                                    IN UINT uiL3OffSet,
                                    IN UINT uiL4OffSet,
                                    INOUT SESSION_TUPLE_S *pstTuple)
{
    ICMP_S* pstIcmp;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstTuple);

    pstIcmp = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP_S *);
    pstTuple->unL4Src.stIcmp.usSeq = pstIcmp->icmp_seq;
    pstTuple->unL4Dst.stIcmp.usId  = pstIcmp->icmp_id;

    return;
}

/* 获取ICMP反向数据 */
STATIC VOID _session_Icmp_GetInvertTuple(IN SESSION_S *pstSession,
                                         IN const SESSION_TUPLE_S *pstOrigTuple,
                                         INOUT SESSION_TUPLE_S *pstInverseTuple)
{
	/*
    DBGASSERT(NULL != pstOrigTuple);
    DBGASSERT(NULL != pstInverseTuple);
    IGNORE_PARAM(pstSession);

    pstInverseTuple->unL4Dst.stIcmp.ucType = g_aucIcmpReverType[pstOrigTuple->unL4Dst.stIcmp.ucType];
    pstInverseTuple->unL4Dst.stIcmp.ucCode = pstOrigTuple->unL4Dst.stIcmp.ucCode;
    pstInverseTuple->unL4Src.stIcmp.usId   = pstOrigTuple->unL4Src.stIcmp.usId;
    */

    return;
}


static ULONG _session_Icmp_PacketCheck(IN MBUF_S *pstMBuf,
                                       IN UINT uiL3OffSet,
                                       IN UINT uiL4OffSet)
{
    ULONG ulRet;
    ICMP_S* pstIcmp;
    UCHAR ucType;
    UCHAR ucCode;

    DBGASSERT(NULL != pstMBuf);

    IGNORE_PARAM(uiL3OffSet);

    ulRet = MBUF_PULLUP(pstMBuf, uiL4OffSet + ICMP_MINLEN);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    pstIcmp = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP_S *);

    ucType = pstIcmp->icmp_type;
    ucCode = pstIcmp->icmp_code;

    /* 查询请求+应答报文 */
    if(BOOL_TRUE == SESSION_KL4_IsIcmpReq(ucType, ucCode))
    {
        return ERROR_SUCCESS;
    }

	#if 0
    /*差错控制报文 */
    if(BOOL_TRUE == _session_Icmp_IsIcmpErr(ucType, ucCode))
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ICMPERR);

        /* 设置icmp载荷匹配的会话方向 */
        SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)ucDir);
    }
	#endif

    return ERROR_FAILED;
}

/******************************************************************
   Func Name:_session_Icmp_NewSessCheck
Date Created:2021/04/25
      Author:wangxiaohua
 Description:ICMP新建会话报文合法性检查
       INPUT:IN MBUF_S *pstMBuf  ----报文
             IN UINT uiL4OffSet  ----四层偏移
      Output:无
      Return:ERROR_SUCCESS
             ERROR_FAILED
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG _session_Icmp_NewSessCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3, IN UINT uiL4OffSet)
{
    ICMP_S *pstIcmp;
    UCHAR ucType;

    DBGASSERT(NULL != pstMBuf);
    IGNORE_PARAM(uiL3);

    pstIcmp = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP_S *);
    ucType = pstIcmp->icmp_type;

    /*当前icmp差错报文不会走这个分支，将返回ERROR_FAILED*/
    if (ICMP_PKT_REQUEST == g_aucIcmpPktType[ucType])
    {
        return ERROR_SUCCESS;
    }

    return ERROR_FAILED;
}

static ULONG _session_Icmp_FirstPacket(IN const MBUF_S *pstMBuf,
                                       IN UINT uiL4OffSet,
                                       INOUT SESSION_S *pstSession)
{
    
    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstSession);

    IGNORE_PARAM(uiL4OffSet);

    pstSession->ucState = sNO;

    return ERROR_SUCCESS;
}

/******************************************************************
   Func Name:_session_Icmp_State
Date Created:2021/04/25
      Author:wangxiaohua
 Description:ICMP 状态机处理
       INPUT:IN SESSION_S *pstSession  ----会话
             IN MBUF_S *pstMbuf        ----报文
             IN UINT uiL4OffSet        ----四层偏移
      Output:无
      Return:ERROR_SUCCESS
             ERROR_FAILED
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG _session_Icmp_State(IN SESSION_S *pstSession,
                                IN MBUF_S *pstMBuf,
                                IN UINT uiL3OffSet,
                                IN UINT uiL4Offset)
{
    ICMP_S *pstIcmp;
    UCHAR ucOldState;
    SESSION_PKT_DIR_E enDir;
    UCHAR ucIndex;
    UCHAR ucNewState;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstMBuf);    
    DBGASSERT(NULL != pstSession);

    pstIcmp = MBUF_BTOD_OFFSET(pstMBuf, uiL4Offset, ICMP_S *);

    ucOldState = pstSession->ucState;
    enDir = SESSION_GetDirFromMBuf(pstMBuf);

    ucIndex = g_aucIcmpPktType[pstIcmp->icmp_type];

    /*防止越界保护*/
    if(unlikely((ucIndex >= ICMP_PKT_MAX) || (ucOldState >= ICMP_ST_MAX)))
    {
        return ERROR_FAILED;
    }

    ucNewState = g_aucIcmp_state_table[ucIndex][ucOldState];
    if(sIV == ucNewState)
    {
        return ERROR_FAILED;
    }

    pstSession->ucState = ucNewState;

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, pstIcmp->icmp_type, ucIndex,
                                   enDir, ucOldState, pstSession->ucState);

    SESSION_IGNORE_CONST(pstMBuf);

    return ERROR_SUCCESS;
}

/* ICMP获得四层以上的负载偏移和负载长度 */
STATIC ULONG _session_Icmp_GetPayload(IN MBUF_S *pstMBuf,
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

/* ICMP获得ReadyState */
STATIC UCHAR _session_Icmp_GetReadyState(VOID)
{
    return (sCL);
}

/* ICMP状态机处理 */
STATIC ULONG _session_Fast_Icmp_State(IN SESSION_S *pstSession,
                                      IN UINT uiL3OffSet,
                                      IN UINT uiL4OffSet,
                                      IN MBUF_S *pstMBuf,
                                      IN SESSION_PKT_DIR_E enDir)
{
    ICMP_S *pstIcmp;
    UCHAR ucOldState;
    UCHAR ucIndex;
    UCHAR ucNewState;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstSession);
    DBGASSERT(NULL != pstMBuf)

    pstIcmp = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP_S *);

    ucOldState = pstSession->ucState;

    ucIndex = g_aucIcmpPktType[pstIcmp->icmp_type];

    /* 防止越界保护 */
    if(unlikely((ucIndex >= ICMP_PKT_MAX) || (ucOldState >= ICMP_ST_MAX)))
    {
        return ERROR_FAILED;
    }

    ucNewState = g_aucIcmp_state_table[ucIndex][ucOldState];

    if(sIV == ucNewState)
    {
        return ERROR_FAILED;
    }

    pstSession->ucState = ucNewState;

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, pstIcmp->icmp_type, ucIndex,
                                   enDir, ucOldState, pstSession->ucState);

    SESSION_IGNORE_CONST(pstMBuf);

    return ERROR_SUCCESS;
}

/* 从fsbuf中获取载荷偏移及长度 */
STATIC ULONG _session_Icmp_FsbufGetPayload(IN const MBUF_S *pstMBuf,
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
STATIC ULONG _session6_Icmp_FsbufGetPayload(IN const MBUF_S *pstMBuf,
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

/* ICMP协议初始化 */
VOID SESSION_KL4_IcmpInit(VOID)
{
    SESSION_L4_PROTO_S stRegInfo;

    stRegInfo.pfPktToTuple            =_session_Icmp_Pkt2Tuple;
    stRegInfo.pfGetInvertTuple        =_session_Icmp_GetInvertTuple;
    stRegInfo.pfPacketCheck           =_session_Icmp_PacketCheck;
    stRegInfo.pfNewSessCheck          =_session_Icmp_NewSessCheck;
    stRegInfo.pfFirstPacket           =_session_Icmp_FirstPacket;
    stRegInfo.pfState                 =_session_Icmp_State;
    stRegInfo.pfGetL4Payload          =_session_Icmp_GetPayload;
    stRegInfo.pfGetReadyState         =_session_Icmp_GetReadyState;
    stRegInfo.pfFastState             =_session_Fast_Icmp_State;
    stRegInfo.pfFsbufGetL4Payload     =_session_Icmp_FsbufGetPayload;
    stRegInfo.pfFsbufIPv6GetL4Payload =_session6_Icmp_FsbufGetPayload;

    SESSION_KL4_Reg(&stRegInfo, IPPROTO_ICMP);

    return;
}

/* ICMP协议反初始化 */
VOID SESSION_KL4_IcmpFini(VOID)
{
    SESSION_KL4_DeReg(IPPROTO_ICMP);

    return;
}
