

#include "session.h"
#include "session_kl4proto.h"
#include "icmp6.h"
#include "ip_icmp.h"
#include "session_kcore.h"
#include "session_kdebug.h"
#include "session_kl4_icmpv6.h"

/*只考虑[ICMP6_ECHO_REQUEST - 1, ICMP6_DHAAD_REPLY]之间的type，
  所以没有必要使用很大的数组来存放，所以将type-ICMPV6_RANG_OFFSET作为数组索引*/
UCHAR g_aucIcmp6PktType[ICMP6_DHAAD_REPLY + 1 - ICMPV6_RANG_OFFSET] = {
    ICMP_PKT_OTHER,    /*                        127                           */        
    ICMP_PKT_REQUEST,  /*ICMP6_ECHO_REQUEST      128  echo service             */    
    ICMP_PKT_REPLY,    /*ICMP6_ECHO_REPLY        129  echo reply               */
    ICMP_PKT_REQUEST,  /*ICMP6_MEMBERSHIP_QUERY  130  gruop membership query   */        
    ICMP_PKT_REPLY,    /*ICMP6_MEMBERSHIP_REPORT 131  gruop membership report  */    
    ICMP_PKT_OTHER,    /*                        132                           */        
    ICMP_PKT_OTHER,    /*                        133                           */            
    ICMP_PKT_OTHER,    /*                        134                           */        
    ICMP_PKT_OTHER,    /*                        135                           */     
    ICMP_PKT_OTHER,    /*                        136                           */            
    ICMP_PKT_OTHER,    /*                        137                           */        
    ICMP_PKT_OTHER,    /*                        138                           */     
    ICMP_PKT_REQUEST,  /*ICMP6_NI_QUERY          139  node information request */        
    ICMP_PKT_REPLY,    /*ICMP6_NI_REPLY          140  node information reply   */  
    ICMP_PKT_OTHER,    /*                        141                           */     
    ICMP_PKT_OTHER,    /*                        142                           */            
    ICMP_PKT_OTHER,    /*                        143                           */        
    ICMP_PKT_REQUEST,  /*ICMP6_DHAAD_REQUEST     144  DHAAD request            */        
    ICMP_PKT_REPLY,    /*ICMP6_DHAAD_REPLY       145  DHAAD reply              */   
};

UCHAR g_aucIcmpv6ReverType[] = {
    [ICMP6_ECHO_REQUEST - ICMPV6_RANG_OFFSET]      = ICMP6_ECHO_REPLY,        
    [ICMP6_ECHO_REPLY - ICMPV6_RANG_OFFSET]        = ICMP6_ECHO_REQUEST,    
    [ICMP6_MEMBERSHIP_QUERY - ICMPV6_RANG_OFFSET]  = ICMP6_MEMBERSHIP_REPORT,    
    [ICMP6_MEMBERSHIP_REPORT - ICMPV6_RANG_OFFSET] = ICMP6_MEMBERSHIP_QUERY,
    [ICMP6_NI_QUERY - ICMPV6_RANG_OFFSET]          = ICMP6_NI_REPLY,        
    [ICMP6_NI_REPLY - ICMPV6_RANG_OFFSET]          = ICMP6_NI_QUERY,    
    [ICMP6_DHAAD_REQUEST - ICMPV6_RANG_OFFSET]     = ICMP6_DHAAD_REPLY,    
    [ICMP6_DHAAD_REPLY - ICMPV6_RANG_OFFSET]       = ICMP6_DHAAD_REQUEST,
};

extern UCHAR g_aucIcmp_state_table[ICMP_PKT_MAX][ICMP_ST_MAX];

/* 根据报文的type和code判断是否是需要关心的ICMPv6差错控制报文 */
static inline BOOL_T _session_Icmpv6_IsIcmpErr(IN UCHAR ucType, IN UCHAR ucCode)
{
    /* type 和 code 是以下组合和取值范围才是期望的icmp差错控制报文

            type            code
        ICMP6_DST_UNREACH  [0, 6]        
        ICMP6_DST_UNREACH  [0, 0]
        ICMP6_DST_UNREACH  [0, 1]
        ICMP6_DST_UNREACH  [0, 2]
    */

    return (((ICMP6_DST_UNREACH == ucType)&&(ucCode <= 6)) ||
            ((ICMP6_PACKET_TOO_BIG == ucType)&&(0 == ucCode)) ||
            ((ICMP6_TIME_EXCEEDED == ucType)&&(ucCode <= 1)) ||
            ((ICMP6_PARAM_PROB == ucType)&&(ucCode <= 2)));
}

/* 根据报文的type和code判断是否是需要关心的ICMPv6查询请求应答报文 */
STATIC BOOL_T SESSION_KL4_IsIcmpv6Req(IN UCHAR ucType, IN UCHAR ucCode)
{
    /* type 和 code 是以下取值范围才是期望的icmp查询请求应答报文

            type                             code
        ICMP6_ECHO_REQUEST          128        0        
        ICMP6_ECHO_REPLY            129        0
        ICMP6_MEMBERSHIP_QUERY      130        0    
        ICMP6_MEMBERSHIP_REPORT     131        0
        ICMP6_NI_QUERY              139        0        
        ICMP6_NI_REPLY              140        0
        ICMP6_DHAAD_REQUEST         144        0    
        ICMP6_DHAAD_REPLY           145        0
    */
    return ((ucType >= ICMP6_ECHO_REQUEST) &&
            (ucType <= ICMP6_DHAAD_REPLY) &&
            (ICMP_PKT_OTHER != g_aucIcmp6PktType[ucType - ICMPV6_RANG_OFFSET]) &&
            (0 == ucCode));
}

#if 0
/* 对ICMP和ICMPv6差错控制报文的内嵌报文进行处理 */
ULONG SESSION6_Kl4_IcmpErr(IN MBUF_S *pstMBuf, IN UINT uiInterL3OffSet, IN UINT uiInterL3Hlen)
{
    UINT uiInterL4OffSet;
    UCHAR ucInterL4Proto;
    UINT uiInterIPLen;
    SESSION_L3_PROTO_S *pstL3Proto;
    SESSION_L4_PROTO_S *pstL4Proto;
    SESSION_TUPLE_S stOrigTuple;
    SESSION_TUPLE_S stInverseTuple;
    IP6FS_CACHEKEY_S stIp6Key;
    ULONG ulRet;
    SESSION_S *pstSession;
    UCHAR ucDir = SESSION_MBUF_REPLYPKT;

    /*保证至少能取到三层头信息且连续*/
    ulRet = MBUF_PULLUP(pstMBuf, uiInterL3OffSet + uiInterL3Hlen);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /* 获取3层、4层协议处理模块 */
    ulRet = session_kGetModule(pstMBuf,
                               uiInterL3OffSet,
                               &uiInterL4OffSet,
                               &ucInterL4Proto,
                               &uiInterIPLen,
                               &pstL3Proto,
                               &pstL4Proto);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /*保证至少要能取到6字节的port信息
      对于TCP/UDP等协议，实际需要4字节；对于ICMP协议，需要6字节 */
    ulRet = MBUF_PULLUP(pstMBuf, uiInterL4OffSet + 6);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /*对ICMP差错控制报文的内嵌报文进行检查*/
    if(ERROR_SUCCESS != session_Icmp_InterCheck(pstMBuf, ucInterL4Proto, uiInterL4OffSet))
    {
        return ERROR_FAILED;
    }

    /* 获取报文的Tuple信息 */
    session_kGetTuple(pstMBuf, uiInterL3OffSet, uiInterL4OffSet,
                      ucInterL4Proto, pstL3Proto, pstL4Proto, &stOrigTuple);

    session_invert_tuple(NULL, &stOrigTuple, pstL3Proto, pstL4Proto, &stInverseTuple);

    SESSION6_KChangeTupleToKey(&stInverseTuple, &stIp6Key);
   
    ulRet = ERROR_FAILED;
    pstSession = IP6FS_SearchSession(&stIp6Key, &ucDir);
    if (NULL != pstSession)
    {
        /* 会话指针记录在MBUF中 */
        MBUF_ASSIGN_CACHE(pstMBuf, pstSession, MBUF_CACHE_SESSION);
        /* 设置icmp载荷匹配的会话方向 */
        SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)ucDir);
        SESSION_DBG_SESSION_PRINTF_SWITCH(pstSession, "ICMPv6_ERROR_INTERNAL_MATCHED");
        ulRet = ERROR_SUCCESS;
    }

    return ulRet;
}
#endif

/* 获取ICMPV6四层数据 */
STATIC VOID _session_Icmpv6_Pkt2Tuple(IN const MBUF_S *pstMBuf,
                                      IN UINT uiL3OffSet,
                                      IN UINT uiL4OffSet,
                                      INOUT SESSION_TUPLE_S *pstTuple)
{
    ICMP6HDR_S *pstIcmp6Hdr;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstTuple);

    pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP6HDR_S *);
	pstTuple->unL4Src.stIcmp.usSeq = pstIcmp6Hdr->icmp6_seq;
    pstTuple->unL4Dst.stIcmp.usId  = pstIcmp6Hdr->icmp6_id;

    return;
}

/* 获取ICMPV6反向数据 */
STATIC VOID _session_Icmpv6_GetInvertTuple(IN SESSION_S *pstSession,
                                           IN const SESSION_TUPLE_S *pstOrigTuple,
                                           INOUT SESSION_TUPLE_S *pstInverseTuple)
{
	/*
    UCHAR ucOrigType;

    DBGASSERT(NULL != pstOrigTuple);
    DBGASSERT(NULL != pstInverseTuple);
    IGNORE_PARAM(pstSession);

    ucOrigType = pstOrigTuple->unL4Dst.stIcmp.ucType;

    pstInverseTuple->unL4Dst.stIcmp.ucType = g_aucIcmpv6ReverType[ucOrigType - ICMPV6_RANG_OFFSET];
    pstInverseTuple->unL4Dst.stIcmp.ucCode = pstOrigTuple->unL4Dst.stIcmp.ucCode;
    pstInverseTuple->unL4Src.stIcmp.usId   = pstOrigTuple->unL4Src.stIcmp.usId;
    */

    return;
}

/* ICMPV6单包合法性检查 */
STATIC ULONG _session_Icmpv6_PacketCheck(IN MBUF_S *pstMBuf, IN UINT uiL3OffSet, IN UINT uiL4OffSet)
{
    ULONG ulRet;
    ICMP6HDR_S *pstIcmp6Hdr;
    UCHAR ucType;
    UCHAR ucCode;

    DBGASSERT(NULL != pstMBuf);
    IGNORE_PARAM(uiL3OffSet);

    ulRet = MBUF_PULLUP(pstMBuf, uiL4OffSet + (UINT32)sizeof(ICMP6HDR_S));
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP6HDR_S *);
    ucType = pstIcmp6Hdr->icmp6_type;
    ucCode = pstIcmp6Hdr->icmp6_code;

    /*查询请求+应答报文*/
    if(BOOL_TRUE == SESSION_KL4_IsIcmpv6Req(ucType, ucCode))
    {
        return ERROR_SUCCESS;
    }

#if 0
    /*差错控制报文*/
    if (BOOL_TRUE == _session_Icmpv6_IsIcmpErr(ucType, ucCode))
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ICMPERR);

        /*协议规定ICMPv6差错控制报文必须包括生成该差错报文的数据报文的拷贝，
        尽量多带*/

        return SESSION6_Kl4_IcmpErr(pstMBuf, uiL4OffSet + (UINT32)sizeof(ICMP6HDR_S), (UINT32)sizeof(IP6_S));
    }
#endif

    return ERROR_FAILED;
}

/* ICMPV6新建会话报文合法性检查 */
STATIC ULONG _session_Icmpv6_NewSessCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3, IN UINT uiL4OffSet)
{
    ICMP6HDR_S * pstIcmp6Hdr;
    UCHAR ucType;
    
    DBGASSERT(NULL != pstMBuf);
    IGNORE_PARAM(uiL3);

    pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP6HDR_S *);
    ucType = pstIcmp6Hdr->icmp6_type;

    /* 当前icmp差错报文不会走这个分支，将返回ERROR_FAILED */
    if(ICMP_PKT_REQUEST == g_aucIcmp6PktType[ucType - ICMPV6_RANG_OFFSET])
    {
        return ERROR_SUCCESS;
    }

    return ERROR_FAILED;
}

/******************************************************************
   Func Name:_session_Icmpv6_FirstPacket
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话首包处理
       INPUT:IN MBUF_S *pstMbuf           ----报文
             IN UINT uiL4OffSet           ----四层偏移
             INOUT SESSION_S *pstSession  ----会话
      Output:INOUT SESSION_S *pstSession  ----会话
      Return:ERROR_SUCCESS
             ERROR_FAILED
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG _session_Icmpv6_FirstPacket(IN const MBUF_S *pstMBuf,
                                         IN UINT uiL4OffSet,
                                         INOUT SESSION_S *pstSession)
{
    
    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != pstSession);

    IGNORE_PARAM(uiL4OffSet);

    pstSession->ucState = sNO;

    return ERROR_SUCCESS;
}

static ULONG _session_Icmpv6_State(IN SESSION_S *pstSession,
                                   IN MBUF_S *pstMBuf,
                                   IN UINT uiL3OffSet,
                                   IN UINT uiL4Offset)
{
    ICMP6HDR_S *pstIcmp6Hdr;
    UCHAR ucOldState;
    SESSION_PKT_DIR_E enDir;
    UCHAR ucIndex;
    UCHAR ucNewState;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstMBuf);    
    DBGASSERT(NULL != pstSession);

    pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4Offset, ICMP6HDR_S *);

    ucOldState = pstSession->ucState;
    enDir = SESSION_GetDirFromMBuf(pstMBuf);

    ucIndex = g_aucIcmp6PktType[pstIcmp6Hdr->icmp6_type - ICMPV6_RANG_OFFSET];

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

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, pstIcmp6Hdr->icmp6_type, ucIndex,
                                   enDir, ucOldState, pstSession->ucState);

    SESSION_IGNORE_CONST(pstMBuf);

    return ERROR_SUCCESS;
}

/* ICMPV6获得四层以上的负载偏移和负载长度 */
STATIC ULONG _session_Icmpv6_GetPayload(IN MBUF_S *pstMBuf,
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
STATIC UCHAR _session_Icmpv6_GetReadyState(VOID)
{
    return (sCL);
}

STATIC ULONG _session_Fast_Icmpv6_State(IN SESSION_S *pstSession,
                                        IN UINT uiL3OffSet,
                                        IN UINT uiL4OffSet,
                                        IN MBUF_S *pstMBuf,
                                        IN SESSION_PKT_DIR_E enDir)
{
    ICMP6HDR_S *pstIcmp6Hdr;
    UCHAR ucOldState;
    UCHAR ucIndex;
    UCHAR ucNewState;

    IGNORE_PARAM(uiL3OffSet);

    DBGASSERT(NULL != pstSession);
    DBGASSERT(NULL != pstMBuf);

    pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP6HDR_S *);
    ucOldState = pstSession->ucState;

    ucIndex = g_aucIcmp6PktType[pstIcmp6Hdr->icmp6_type - ICMPV6_RANG_OFFSET];

    /* 防止越界保护 */
    if (unlikely(ucIndex >= ICMP_PKT_MAX) || (ucOldState >= ICMP_ST_MAX))
    {
        return ERROR_FAILED;
    }

    ucNewState = g_aucIcmp_state_table[ucIndex][ucOldState];

    if(sIV == ucNewState)
    {
        return ERROR_FAILED;
    }

    pstSession->ucState = ucNewState;

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, pstIcmp6Hdr->icmp6_type, ucIndex, 
                                   enDir, ucOldState, pstSession->ucState);

    SESSION_IGNORE_CONST(pstMBuf);

    return ERROR_SUCCESS;
}

/* 从fsbuf中获取载荷偏移及长度 */
STATIC ULONG _session_Icmpv6_FsbufGetPayload(IN const MBUF_S *pstMBuf,
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
STATIC ULONG _session6_Icmpv6_FsbufGetPayload(IN const MBUF_S *pstMBuf,
                                              IN const IP6_S *pstIP,
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

/* ICMPV6协议初始化 */
VOID SESSION_KL4_Icmpv6Init(VOID)
{
    SESSION_L4_PROTO_S stRegInfo;

    stRegInfo.pfPktToTuple            =_session_Icmpv6_Pkt2Tuple;
    stRegInfo.pfGetInvertTuple        =_session_Icmpv6_GetInvertTuple;
    stRegInfo.pfPacketCheck           =_session_Icmpv6_PacketCheck;
    stRegInfo.pfNewSessCheck          =_session_Icmpv6_NewSessCheck;
    stRegInfo.pfFirstPacket           =_session_Icmpv6_FirstPacket;
    stRegInfo.pfState                 =_session_Icmpv6_State;
    stRegInfo.pfGetL4Payload          =_session_Icmpv6_GetPayload;
    stRegInfo.pfGetReadyState         =_session_Icmpv6_GetReadyState;
    stRegInfo.pfFastState             =_session_Fast_Icmpv6_State;
    stRegInfo.pfFsbufGetL4Payload     =_session_Icmpv6_FsbufGetPayload;
    stRegInfo.pfFsbufIPv6GetL4Payload =_session6_Icmpv6_FsbufGetPayload;

    SESSION_KL4_Reg(&stRegInfo, IPPROTO_ICMPV6);

    return;
}

/* ICMPV6 协议反初始化 */
VOID SESSION_KL4_Icmpv6Fini(VOID)
{
    SESSION_KL4_DeReg(IPPROTO_ICMPV6);

    return;
}

