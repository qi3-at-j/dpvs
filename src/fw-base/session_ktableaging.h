#ifndef _SESSION_KTABLEAGING_H_
#define _SESSION_KTABLEAGING_H_

#include "session.h"
#include "session_kdebug.h"

#define SESSION_HOURS  3600
#define SESSION_APP_CODE_AGING_MAX  5  /* 协议最多支持集中具体应用 */

/*VOID AGINGQUEUE_UnStable_Add(IN AGINGQUEUE_UNSTABLE_S *pstQueue,
                             IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject);*/

static inline VOID SESSION_KAging_Refresh (IN SESSION_S *pstSession)
{
    pstSession->stSessionBase.uiUpdateTime = rte_get_timer_cycles();
    return;
}

/*
static inline VOID SESSION_KAging_Add(IN AGINGQUEUE_UNSTABLE_S *pstAgingQueue, IN SESSION_S *pstSession)
{
    SESSION_KAgingRefresh(pstSession);
    AGINGQUEUE_UnStable_Add(pstAgingQueue, &pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo);

    return;
}*/


/******************************************************************
 Description:ipv4慢转会话老化设置
*********************************************************************/

/******************************************************************
   Func Name:SESSION_KAging_SetClassNew
Date Created:2021/04/25
      Author:wangxiaohua
 Description:ipv4慢转会话老化设置
       INPUT:IN SESSION_CTRL_S   *pstSessionCtrl,     
             IN SESSION_S *pstSession
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_KAging_SetClassNew(IN SESSION_CTRL_S *pstSessionCtrl,
                                              IN SESSION_S *pstSession)
{
    AGINGQUEUE_UNSTABLE_CLASS_S *pstClass = NULL;
    UCHAR ucSessionL4Type = SESSION_L4_TYPE_MAX;

    ucSessionL4Type = pstSession->stSessionBase.ucSessionL4Type;
    pstClass = &pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV4][ucSessionL4Type][pstSession->ucState];
    SESSION_DBG_AGING_EVENT_SWITCH(pstSession, DBG_AGING_L4AGING);

    SESSION_KAgingRefresh(pstSession);
    AGINGQUEUE_UnStable_Switch(&pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo, pstClass);

    return;
}

ULONG SESSION_KAgingClass_Init(IN SESSION_CTRL_S *pstSessionMdc);
#endif