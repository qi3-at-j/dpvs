
#include <rte_malloc.h>
#include "session.h"
#include "session_kl4_icmpv4.h"
#include "session_kl4_icmpv6.h"
#include "session_kl4_rawip.h"
#include "session_kl4_tcp.h"
#include "session_kl4_udp.h"


STATIC SESSION_L4_PROTO_S *g_pstSessionL4ProtoInfo = NULL; /* 记录会话管理支持的4层协议处理结构 */

/******************************************************************
   Func Name:SESSION_KL4_Reg
Date Created:2021/04/25
      Author:wangxiaohua
 Description:4层协议注册函数
       INPUT:IN SESSION_L4_PROTO_S *pstRegInfo    ----四层结构
             IN UCHAR ucProto                     ----协议
      Output:无
      Return:无 
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
 Description:4层协议注销函数
       INPUT:IN UCHAR ucProto  ----协议
      Output:无
      Return:无 
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

/* 获取4层协议处理结构 */
SESSION_L4_PROTO_S *SESSION_KGetL4Proto_Proc(IN UCHAR ucProto)
{
    /* 已经保证不关心的协议挂上rawip的处理结构 */
    return &g_pstSessionL4ProtoInfo[ucProto];
}



/******************************************************************
   Func Name:SESSION_KL4PROTO_Init
Date Created:2021/04/25
      Author:wangxiaohua
 Description:4层协议初始化函数
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

    /* 请注意，初始化时首先初始化Rawip, 会把所有协议都填写为rawip处理
     * TCP等协议初始化时再重新填写各自的结构
     */
    SESSION_KL4_RawipInit();
    SESSION_KL4_TcpInit();
    SESSION_KL4_UdpInit();
    SESSION_KL4_IcmpInit();
    SESSION_KL4_Icmpv6Init();
    
    return ERROR_SUCCESS;
}

/* 4层协议注销函数 */
VOID SESSION_KL4PROTO_Fini(VOID)
{
    /* 其实直接把全局变量清0就行。这里先分到所有协议去fini，这样各个协议处理比较对称。
       如果将来协议有其他私有数据可以完成释放。*/
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

/* 获取4层载荷偏移和长度 */

ULONG SESSION_KGetL4Payload(IN MBUF_S *pstMBuf,
                            IN UCHAR ucProtocol, /* 四层标准协议号, ig. TCP(6), UDP(17) */ 
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
Description:获取四层实际的载荷及长度 
      Input:IN MBUF_S *pstMBuf        --报文数据块
            IN UCHAR  ucProtocol      --协议 四层标准协议号，ig. TCP(6), UDP(17)
            IN UINT   uiL4OffSet      --四层偏移
            IN BOOL_T bGetValid       --是否需要获取实际值
     Output:OUT UINT *puiPayloadOff   --载荷
            OUT UINT *puiPayloadLen   --载荷长度
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

