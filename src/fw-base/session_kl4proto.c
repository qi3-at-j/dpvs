
#include <rte_malloc.h>
#include "session.h"
#include "session_kl4_icmpv4.h"
#include "session_kl4_icmpv6.h"
#include "session_kl4_rawip.h"
#include "session_kl4_tcp.h"
#include "session_kl4_udp.h"


STATIC SESSION_L4_PROTO_S *g_pstSessionL4ProtoInfo = NULL; /* ��¼�Ự����֧�ֵ�4��Э�鴦��ṹ */

/******************************************************************
   Func Name:SESSION_KL4_Reg
Date Created:2021/04/25
      Author:wangxiaohua
 Description:4��Э��ע�ắ��
       INPUT:IN SESSION_L4_PROTO_S *pstRegInfo    ----�Ĳ�ṹ
             IN UCHAR ucProto                     ----Э��
      Output:��
      Return:�� 
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/

VOID SESSION_KL4_Reg(IN const SESSION_L4_PROTO_S *pstRegInfo, IN UCHAR ucProto)
{
    g_pstSessionL4ProtoInfo[ucProto] = *pstRegInfo;

    return;
}

/******************************************************************
   Func Name:SESSION_KL4_DeReg
Date Created:2021/04/25
      Author:wangxiaohua
 Description:4��Э��ע������
       INPUT:IN UCHAR ucProto  ----Э��
      Output:��
      Return:�� 
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KL4_DeReg(IN UCHAR ucProto)
{
    if(NULL != g_pstSessionL4ProtoInfo)
    {
        memset(&g_pstSessionL4ProtoInfo[ucProto], 0, sizeof(SESSION_L4_PROTO_S));
    }
    
    return;
}

/* ��ȡ4��Э�鴦��ṹ */
SESSION_L4_PROTO_S *SESSION_KGetL4Proto_Proc(IN UCHAR ucProto)
{
    /* �Ѿ���֤�����ĵ�Э�����rawip�Ĵ���ṹ */
    return &g_pstSessionL4ProtoInfo[ucProto];
}



/******************************************************************
   Func Name:SESSION_KL4PROTO_Init
Date Created:2021/04/25
      Author:wangxiaohua
 Description:4��Э���ʼ������
       INPUT:��
      Output:��
      Return:ERROR_SUCCESS  ----�ɹ�
             ERROR_FAILED   ----ʧ��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG SESSION_KL4PROTO_Init(VOID)
{   
    SESSION_L4_PROTO_S *pstProtoInfo;
    ULONG ulLen;

    ulLen = sizeof(SESSION_L4_PROTO_S) * IPPROTO_MAX;
    pstProtoInfo = rte_zmalloc(NULL, ulLen, 0);
    if (NULL == pstProtoInfo)
    {
        return ERROR_FAILED;
    }

    g_pstSessionL4ProtoInfo = pstProtoInfo;

    /* ��ע�⣬��ʼ��ʱ���ȳ�ʼ��Rawip, �������Э�鶼��дΪrawip����
     * TCP��Э���ʼ��ʱ��������д���ԵĽṹ
     */
    SESSION_KL4_RawipInit();
    SESSION_KL4_TcpInit();
    SESSION_KL4_UdpInit();
    SESSION_KL4_IcmpInit();
    SESSION_KL4_Icmpv6Init();
    
    return ERROR_SUCCESS;
}

/* 4��Э��ע������ */
VOID SESSION_KL4PROTO_Fini(VOID)
{
    /* ��ʵֱ�Ӱ�ȫ�ֱ�����0���С������ȷֵ�����Э��ȥfini����������Э�鴦��Ƚ϶Գơ�
       �������Э��������˽�����ݿ�������ͷš�*/
    SESSION_KL4_Icmpv6Fini();
    SESSION_KL4_IcmpFini();
    SESSION_KL4_UdpFini();
    SESSION_KL4_TcpFini();
    SESSION_KL4_RawipFini();

    if(NULL != g_pstSessionL4ProtoInfo)
    {
        rte_free(g_pstSessionL4ProtoInfo);
        g_pstSessionL4ProtoInfo = NULL;
    }
    
    return;
}

/* ��ȡ4���غ�ƫ�ƺͳ��� */

ULONG SESSION_KGetL4Payload(IN MBUF_S *pstMBuf,
                            IN UCHAR ucProtocol, /* �Ĳ��׼Э���, ig. TCP(6), UDP(17) */ 
                            IN UINT uiL4OffSet,
                            OUT UINT *puiPayloadOff,
                            OUT UINT *puiPayloadLen)
{
    SESSION_L4_PROTO_S *pstProto;

    DBGASSERT(NULL != pstMBuf);

    pstProto = &g_pstSessionL4ProtoInfo[ucProtocol];

    return pstProto->pfGetL4Payload(pstMBuf, uiL4OffSet, puiPayloadOff, puiPayloadLen);
}

/*
Description:��ȡ�Ĳ�ʵ�ʵ��غɼ����� 
      Input:IN MBUF_S *pstMBuf        --�������ݿ�
            IN UCHAR  ucProtocol      --Э�� �Ĳ��׼Э��ţ�ig. TCP(6), UDP(17)
            IN UINT   uiL4OffSet      --�Ĳ�ƫ��
            IN BOOL_T bGetValid       --�Ƿ���Ҫ��ȡʵ��ֵ
     Output:OUT UINT *puiPayloadOff   --�غ�
            OUT UINT *puiPayloadLen   --�غɳ���
*/
ULONG SESSION_KGetValidL4Payload(IN MBUF_S *pstMBuf, 
                                 IN UCHAR ucProtocol,
                                 IN UINT uiL4OffSet,
                                 OUT UINT *puiPayloadOff,
                                 OUT UINT *puiPayloadLen)
{
	ULONG ulRet;
	UINT uiPayloadLen;
	UINT uiPayloadOff;
	UINT uiOffset = 0;

	ulRet = SESSION_KGetL4Payload(pstMBuf, ucProtocol, uiL4OffSet, &uiPayloadOff, &uiPayloadLen);
	if(ERROR_SUCCESS == ulRet)
	{
		*puiPayloadOff = uiPayloadOff;
		*puiPayloadLen = uiPayloadLen;
	}

	return ulRet;
}

