#include "session.h"
#include "socket.h"
#include "session_kl3_ipv4.h"
#include "session_kl3_ipv6.h"


STATIC SESSION_L3_PROTO_S g_astSessionL3ProtoInfo[AF_MAX]; /* 记录会话管理支持的4层协议对应的处理结构 */


/* L3协议注册处理函数 */
VOID SESSION_KL3_Reg(IN const SESSION_L3_PROTO_S *pstRegInfo, IN UCHAR ucFamily)
{
    DBGASSERT(ucFamily < AF_MAX);

    g_astSessionL3ProtoInfo[ucFamily] = *pstRegInfo;

    return;
}

/* L3协议注销处理函数 */
VOID SESSION_KL3_DeReg(IN UCHAR ucFamily)
{
    DBGASSERT(ucFamily < AF_MAX);

    memset(&g_astSessionL3ProtoInfo[ucFamily], 0, sizeof(SESSION_L3_PROTO_S));

    return;
}

/* L3初始化 */
VOID SESSION_KL3_Init(VOID)
{
    SESSION_IPv4_Init();
    SESSION_IPv6_Init();

    return;
}

/* L3去初始化 */
VOID SESSION_KL3_Fini(VOID)
{
    SESSION_IPv4_Fini();
    SESSION_IPv6_Fini();

    return;
}

/* 根据3层协议类型获取3层协议处理结构 */
SESSION_L3_PROTO_S *SESSION_KGetL3Proto_Proc(UCHAR ucFamily)
{
    if(ucFamily < AF_MAX)
    {
        return &g_astSessionL3ProtoInfo[ucFamily];
    }

    return NULL;
}
