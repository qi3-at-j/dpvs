#include "session.h"
#include "session_kcore.h"

SESSION_APP_STATIC_TYPE_E g_aenAppIndex[SESSION_APPID_MAX];

VOID _proc_SetMsgReply(INT iSocketFd, UINT uiVar, ULONG ulErrCode)
{
    return;
}

VOID session6_kdebugTableSetDelEvent(SESSION_S *pstSession, SESSION_MODULE_E enModule)
{
    return;
}

ULONG AGINGQUEUE_Changeable_InitQueue(AGINGQUEUE_CHANGEABLE_S *pstQue)
{
    return ERROR_SUCCESS;
}

VOID AGINGQUEUE_Changeable_DestroyQueue(AGINGQUEUE_CHANGEABLE_S *pstQue)
{
    return;
}

VOID IP6FS_DeletePairFromHash(INOUT VOID *pSession)
{
    return;
}

VOID SESSION_DBG_SESSION_FSM_SWITCH(SESSION_S * pstSession, UINT uiVar, UINT uiVar2, DIRECTION_E enDir, UCHAR ucOldState, UCHAR ucNewState)
{
    return;
}

VOID SESSION_FsTcpMssProc(SESSION_S *pstSession, UCHAR ucIndex, MBUF_S *pstMBuf, TCPHDR_S *pstTcpHdr)
{
    return;
}

VOID SESSION_Packet_Module_Exit(VOID)
{
    return;
}

/* ALG协议去初始化 */
VOID SESSION_KALG_Fini(VOID)
{
    return;
}

/* 关联表子模块去初始化 */
VOID SESSION_KRelation_Exit(VOID)
{
    return;
}

VOID SESSION6_KRelation_Exit(VOID)
{
    return;
}

/* 关联表老化去初始化 */
VOID RELATION_KAging_Fini(VOID)
{
    return;
}

VOID RELATION6_KAging_Fini(VOID)
{
    return;
}

VOID AGINGQUEUE_UnStable_Destroy(AGINGQUEUE_UNSTABLE_S *pstAgingQue)
{
    return;
}

/* 去注册App Change事件*/
VOID APR_KAppChange_DeregFun(UINT uiModule)
{
    return;
}

/* 初始化会话表信息 */
ULONG SESSION_KTableRun(VOID)
{
    return ERROR_SUCCESS;
}

VOID IP6FS_FreeCache(IN VOID *pCache)
{
    return;
}

BOOL_T APR_IfAppIdentified(UINT uiAppID)
{
    return BOOL_FALSE;
}

VOID SESSION6_KLOG_PROC_ActiveFlow(SESSION_S * pstSession, SESSION_CTRL_S *pstCtrl)
{
    return;
}

VOID RELATION6_BAK_SendDelete(SESSION_S *pstSession, RELATION6_S *pstRelation)
{
    return;
}

BOOL_T RBM_KCFG_IsBackupEnable(VOID)
{
    return BOOL_FALSE;
}

VOID SESSION6_KLOG_PROC_Create(MBUF_S *pstMBuf, UINT uiIPOffset, SESSION_S *pstSession, SESSION_CTRL_S *pstSessionCtrl)
{
    return;
}

ULONG session6_kEstablishFailedNotify(SESSION_S *pstSession, UINT uiIPOffset, MBUF_S *pstMBuf)
{
    return ERROR_SUCCESS;
}

ULONG DIM_KPKT6_IPv6FastProc(SESSION_HANDLE hSession, SESSION_PKT_DIR_E enPktDir, UINT uiVar, IP6_S **ppstIP6, MBUF_S *pstMBuf)
{
    return ERROR_SUCCESS;
}

VOID SESSION_KStop(SESSION_TABLE_KEY_S *pstKey)
{
    return;
}

ULONG SESSION_DBM_SetL4Aging(const SESSION_L4AGING_S *pstAging)
{
    return ERROR_SUCCESS;
}

VOID SESSION_SYNC_SetL4Aging(const SESSION_L4AGING_S *pstAging)
{
    return;
}

VOID SESSION_MSG_ErrorMsgReply(INT iSocketFd)
{
    return;
}

BOOL_T SESSION_MatchKeyIpv6AclRule(const SESSION_S *pstSession, UINT uiAclNum)
{
    return BOOL_FALSE;
}

BOOL_T SESSION_MatchKeyIpv4AclRule(const SESSION_S *pstSession, UINT uiAclNum)
{
    return BOOL_FALSE;
}

VOID SESSION_KLOG_PROC_Create(MBUF_S *pstMBuf, UINT uiIPOffset, SESSION_S *pstSession, SESSION_CTRL_S *pstSessionCtrl)
{
    return;
}

VOID SESSION_KLOG_PROC_ActiveFlow(SESSION_S *pstSession, SESSION_CTRL_S *pstSessionCtrl)
{
    return;
}

