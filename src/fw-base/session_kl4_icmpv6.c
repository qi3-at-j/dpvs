

#include "session.h"
#include "session_kl4proto.h"
#include "icmp6.h"
#include "ip_icmp.h"
#include "session_kcore.h"
#include "session_kdebug.h"
#include "session_kl4_icmpv6.h"

/*ֻ����[ICMP6_ECHO_REQUEST - 1, ICMP6_DHAAD_REPLY]֮���type��
  ����û�б�Ҫʹ�úܴ����������ţ����Խ�type-ICMPV6_RANG_OFFSET��Ϊ��������*/
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

/* ���ݱ��ĵ�type��code�ж��Ƿ�����Ҫ���ĵ�ICMPv6�����Ʊ��� */
static inline BOOL_T _session_Icmpv6_IsIcmpErr(IN UCHAR ucType, IN UCHAR ucCode)
{
    /* type �� code ��������Ϻ�ȡֵ��Χ����������icmp�����Ʊ���

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

/* ���ݱ��ĵ�type��code�ж��Ƿ�����Ҫ���ĵ�ICMPv6��ѯ����Ӧ���� */
STATIC BOOL_T SESSION_KL4_IsIcmpv6Req(IN UCHAR ucType, IN UCHAR ucCode)
{
    /* type �� code ������ȡֵ��Χ����������icmp��ѯ����Ӧ����

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
/* ��ICMP��ICMPv6�����Ʊ��ĵ���Ƕ���Ľ��д��� */
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

    /*��֤������ȡ������ͷ��Ϣ������*/
    ulRet = MBUF_PULLUP(pstMBuf, uiInterL3OffSet + uiInterL3Hlen);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /* ��ȡ3�㡢4��Э�鴦��ģ�� */
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

    /*��֤����Ҫ��ȡ��6�ֽڵ�port��Ϣ
      ����TCP/UDP��Э�飬ʵ����Ҫ4�ֽڣ�����ICMPЭ�飬��Ҫ6�ֽ� */
    ulRet = MBUF_PULLUP(pstMBuf, uiInterL4OffSet + 6);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /*��ICMP�����Ʊ��ĵ���Ƕ���Ľ��м��*/
    if(ERROR_SUCCESS != session_Icmp_InterCheck(pstMBuf, ucInterL4Proto, uiInterL4OffSet))
    {
        return ERROR_FAILED;
    }

    /* ��ȡ���ĵ�Tuple��Ϣ */
    session_kGetTuple(pstMBuf, uiInterL3OffSet, uiInterL4OffSet,
                      ucInterL4Proto, pstL3Proto, pstL4Proto, &stOrigTuple);

    session_invert_tuple(NULL, &stOrigTuple, pstL3Proto, pstL4Proto, &stInverseTuple);

    SESSION6_KChangeTupleToKey(&stInverseTuple, &stIp6Key);
   
    ulRet = ERROR_FAILED;
    pstSession = IP6FS_SearchSession(&stIp6Key, &ucDir);
    if (NULL != pstSession)
    {
        /* �Ựָ���¼��MBUF�� */
        MBUF_ASSIGN_CACHE(pstMBuf, pstSession, MBUF_CACHE_SESSION);
        /* ����icmp�غ�ƥ��ĻỰ���� */
        SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)ucDir);
        SESSION_DBG_SESSION_PRINTF_SWITCH(pstSession, "ICMPv6_ERROR_INTERNAL_MATCHED");
        ulRet = ERROR_SUCCESS;
    }

    return ulRet;
}
#endif

/* ��ȡICMPV6�Ĳ����� */
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

/* ��ȡICMPV6�������� */
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

/* ICMPV6�����Ϸ��Լ�� */
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

    /*��ѯ����+Ӧ����*/
    if(BOOL_TRUE == SESSION_KL4_IsIcmpv6Req(ucType, ucCode))
    {
        return ERROR_SUCCESS;
    }

#if 0
    /*�����Ʊ���*/
    if (BOOL_TRUE == _session_Icmpv6_IsIcmpErr(ucType, ucCode))
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ICMPERR);

        /*Э��涨ICMPv6�����Ʊ��ı���������ɸò���ĵ����ݱ��ĵĿ�����
        �������*/

        return SESSION6_Kl4_IcmpErr(pstMBuf, uiL4OffSet + (UINT32)sizeof(ICMP6HDR_S), (UINT32)sizeof(IP6_S));
    }
#endif

    return ERROR_FAILED;
}

/* ICMPV6�½��Ự���ĺϷ��Լ�� */
STATIC ULONG _session_Icmpv6_NewSessCheck(IN const MBUF_S *pstMBuf, IN UINT uiL3, IN UINT uiL4OffSet)
{
    ICMP6HDR_S * pstIcmp6Hdr;
    UCHAR ucType;
    
    DBGASSERT(NULL != pstMBuf);
    IGNORE_PARAM(uiL3);

    pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4OffSet, ICMP6HDR_S *);
    ucType = pstIcmp6Hdr->icmp6_type;

    /* ��ǰicmp����Ĳ����������֧��������ERROR_FAILED */
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
 Description:�Ự�װ�����
       INPUT:IN MBUF_S *pstMbuf           ----����
             IN UINT uiL4OffSet           ----�Ĳ�ƫ��
             INOUT SESSION_S *pstSession  ----�Ự
      Output:INOUT SESSION_S *pstSession  ----�Ự
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

    /*��ֹԽ�籣��*/
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

/* ICMPV6����Ĳ����ϵĸ���ƫ�ƺ͸��س��� */
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

/* ICMP���ReadyState */
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

    /* ��ֹԽ�籣�� */
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

/* ��fsbuf�л�ȡ�غ�ƫ�Ƽ����� */
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

/* ��fsbuf�л�ȡ�غ�ƫ�Ƽ����� */
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

/* ICMPV6Э���ʼ�� */
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

/* ICMPV6 Э�鷴��ʼ�� */
VOID SESSION_KL4_Icmpv6Fini(VOID)
{
    SESSION_KL4_DeReg(IPPROTO_ICMPV6);

    return;
}

