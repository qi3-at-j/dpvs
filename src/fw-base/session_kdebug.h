#ifndef _SESSION_KDEBUG_H_
#define _SESSION_KDEBUG_H_

#include "session.h"



typedef enum tagDebugRelationErrorType
{
	ERROR_RELATION_MEMORY_NOT_ENOUGH,    /* ÄÚ´æ·ÖÅä²»×ã */
    ERROR_RELATION_EXCEED_MAX,
    ERROR_RELATION_DEBUG_MAX
}SESSION_DEBUG_RELATION_ERROR_E;


typedef enum tagDebugAlgError
{
	DBG_ALG_ERROR_MEMORY,
    DBG_ALG_ERROR_DECODE,
    DBG_ALG_ERROR_ENCODE,
    DBG_ALG_ERROR_LEN_INVALID,
    DBG_ALG_ERROR_STRIP,
    DBG_ALG_ERROR_FSM,
    DBG_ALG_ERROR_IP,
    DBG_ALG_ERROR_MAX,
}ALG_DEBUG_ERROR_E;


VOID SESSION_DBG_RELATION_ERROR(IN const SESSION_CTRL_S *pstSessionCtrl, IN SESSION_DEBUG_RELATION_ERROR_E enErrorType);

#define SESSION_DBG_RELATION_ERROR_SWTICH(enErrorType)\
{\
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();\
    if(0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_RELATION_ERROR)) \
	{\
		SESSION_DBG_RELATION_ERROR(pstSessionCtrl, enErrorType);\
	}\
}


VOID SESSION_DBG_RELATION_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                                IN RELATION_S *pstRelation,
                                IN SESSION_DEBUG_EVENT_E enEventType,
                                IN SESSION_REASON_OP_E enOpReason);

#define SESSION_DBG_RELATION_EVENT_SWITCH(pstRelation, enEventType, enOpReason)\
{\
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();\
    if(0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_RELATION_EVENT)) \
	{\
		SESSION_DBG_RELATION_EVENT(pstSessionCtrl, pstRelation, enEventType, enOpReason);\
	}\
}

/***
#define SESSION_DBG_ALG_EVENT_ARGS(_pstSessionM_, _pcFormatM_, args...) \
{\
	V_SESSION_MDC_S *pstSessionMDC = SESSION_KMDC_GetCB();\
	if((NULL != pstSessionMDC) && (BOOL_TRUE == pstSessionMDC->bIsDebugSwitch))\
	{\
		SESSION_DBG_ALG_ARGS(pstSessionMDC, (_pstSessionM_), (SESSION_DEBUG_SWITCH_EVENT), (_pcFormatM_), ##args);\
	}\
}
***/

VOID SESSION_DBG_SESSION_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                               IN const SESSION_S *pstSession,
                               IN SESSION_DEBUG_EVENT_E enEventType);

#define SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, enEventType)\
{\
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();\
    if(0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_SWITCH_EVENT)) \
    {\
        SESSION_DBG_SESSION_EVENT(pstSessionCtrl, pstSession, enEventType); \
    }\
}


VOID SESSION_DBG_EXT_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                           IN const SESSION_S *pstSession,
                           IN SESSION_MODULE_E enModule,
                           IN SESSION_DEBUG_EVENT_E enEventType);

#define SESSION_DBG_EXT_EVENT_SWTICH(pstSession, enModule, enEventType)\
{\
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();\
    if(0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_SWITCH_EVENT)) \
	{\
		SESSION_DBG_EXT_EVENT(pstSessionCtrl, pstSession, enModule, enEventType);\
	}\
}

VOID SESSION6_DBG_RELATION_EVENT(IN const SESSION_CTRL_S *pstSessionCtrl,
                                 IN RELATION6_S *pstRelation,
                                 IN SESSION_DEBUG_EVENT_E enEventType,
                                 IN SESSION_REASON_OP_E enOpReason);

#define SESSION6_DBG_RELATION_EVENT_SWITCH(pstRelation, enEventType, enOpReason)\
{\
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();\
    if(0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_RELATION_EVENT)) \
	{\
		SESSION6_DBG_RELATION_EVENT(pstSessionCtrl, pstRelation, enEventType, enOpReason);\
	}\
}

VOID SESSION_DBG_ALG_ERROR(IN const SESSION_CTRL_S *pstSessionCtrl,
                           IN const SESSION_S *pstSession,
                           IN ALG_DEBUG_ERROR_E enAlgErrorType);

#define SESSION_DBG_ALG_ERROR_SWITCH(pstSession, enAlgErrorType)\
{\
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();\
    if(0 != (pstSessionCtrl->stDebug.uiDbgSwitch & SESSION_DEBUG_ALG_ERROR)) \
	{\
		SESSION_DBG_ALG_ERROR(pstSessionCtrl, pstSession, enAlgErrorType);\
	}\
}

VOID SESSION_KDeleteSessionByModule(IN SESSION_HANDLE hSession,
                                    IN SESSION_MODULE_E enModule);

VOID APR_GetProtoNameByID(IN UCHAR ucProto, OUT CHAR szName[APR_PROTO_NAME_MAX_LEN+1]);

#endif
