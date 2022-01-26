
#include <netinet/ip.h>

#include "session.h"
#include "session_kl4proto.h"
#include "ip_icmp.h"
#include "session_kcore.h"
#include "session_kdebug.h"


/*ICMP��ICMPv6״̬��*/
extern UCHAR g_aucIcmp_state_table[ICMP_PKT_MAX][ICMP_ST_MAX];

/*ֻ����<=ICMP_MASKREPLY��type*/
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

/*ֻ����<=ICMP_MASKREPLY��type*/
UCHAR g_aucIcmpReverType[] = {
    ICMP_ECHO,
    0,                    /* �Ƿ�ICMP��TYPE���� */
    0,                    /* �Ƿ�ICMP��TYPE���� */
    0,                    /* �����Ʊ���: ICMP_UNREACH */
    0,                    /* �����Ʊ���: ICMP_SOURCEQUENCH */
    0,                    /* �����Ʊ���: ICMP_REDIRECT */
    0,                    /* �Ƿ�ICMP��TYPE���� */
    0,                    /* �Ƿ�ICMP��TYPE���� */
    ICMP_ECHOREPLY,
    ICMP_ROUTERSOLICIT,
    ICMP_ROUTERADVERT,
    0,                    /* �����Ʊ���: ICMP_TIMXCEED */    
    0,                    /* �����Ʊ���: ICMP_PARAMPROB */
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

/* ���ݱ��ĵ�type��code�ж��Ƿ�����Ҫ���ĵ�ICMP��ѯ����Ӧ���� */
STATIC BOOL_T SESSION_KL4_IsIcmpReq(IN UCHAR ucType, IN UCHAR ucCode)
{
    /*type �� code ������ȡֵ��Χ����������icmp��ѯ����Ӧ����
   
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
 Description:���ݱ��ĵ�type��code�ж��Ƿ�����Ҫ���ĵ�ICMP�����Ʊ���
       INPUT:IN UCHAR ucType  ----���ĵ�type
             IN UCHAR ucCode  ----���ĵ�code
      Output:��
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
    /*type �� code��������Ϻ�ȡֵ��Χ����������icmp�����Ʊ���

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

/* ��ȡICMP�Ĳ����� */
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

/* ��ȡICMP�������� */
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

    /* ��ѯ����+Ӧ���� */
    if(BOOL_TRUE == SESSION_KL4_IsIcmpReq(ucType, ucCode))
    {
        return ERROR_SUCCESS;
    }

	#if 0
    /*�����Ʊ��� */
    if(BOOL_TRUE == _session_Icmp_IsIcmpErr(ucType, ucCode))
    {
        SESSION_MBUF_SET_FLAG(pstMBuf, SESSION_MBUF_ICMPERR);

        /* ����icmp�غ�ƥ��ĻỰ���� */
        SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)ucDir);
    }
	#endif

    return ERROR_FAILED;
}

/******************************************************************
   Func Name:_session_Icmp_NewSessCheck
Date Created:2021/04/25
      Author:wangxiaohua
 Description:ICMP�½��Ự���ĺϷ��Լ��
       INPUT:IN MBUF_S *pstMBuf  ----����
             IN UINT uiL4OffSet  ----�Ĳ�ƫ��
      Output:��
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

    /*��ǰicmp����Ĳ����������֧��������ERROR_FAILED*/
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
 Description:ICMP ״̬������
       INPUT:IN SESSION_S *pstSession  ----�Ự
             IN MBUF_S *pstMbuf        ----����
             IN UINT uiL4OffSet        ----�Ĳ�ƫ��
      Output:��
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

    SESSION_DBG_SESSION_FSM_SWITCH(pstSession, pstIcmp->icmp_type, ucIndex,
                                   enDir, ucOldState, pstSession->ucState);

    SESSION_IGNORE_CONST(pstMBuf);

    return ERROR_SUCCESS;
}

/* ICMP����Ĳ����ϵĸ���ƫ�ƺ͸��س��� */
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

/* ICMP���ReadyState */
STATIC UCHAR _session_Icmp_GetReadyState(VOID)
{
    return (sCL);
}

/* ICMP״̬������ */
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

    /* ��ֹԽ�籣�� */
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

/* ��fsbuf�л�ȡ�غ�ƫ�Ƽ����� */
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

/* ��fsbuf�л�ȡ�غ�ƫ�Ƽ����� */
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

/* ICMPЭ���ʼ�� */
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

/* ICMPЭ�鷴��ʼ�� */
VOID SESSION_KL4_IcmpFini(VOID)
{
    SESSION_KL4_DeReg(IPPROTO_ICMP);

    return;
}
