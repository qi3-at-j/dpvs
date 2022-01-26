#ifndef _SESSION_KTABLE_H_
#define _SESSION_KTABLE_H_

#include "session_kutil.h"
#include "session_kcore.h"

#define SESSION_SERVICE_INVALID_POS    ((UINT64)-1)

/* 声明软件规格全局变量 */
extern rte_atomic32_t g_stSessionCount;
/* 会话池 */
extern struct rte_mempool *g_apstSessPool[SESSION_TYPE_MAX];
extern UINT g_auiSessTotalLen[SESSION_TYPE_MAX];

/* 保存业务定制扩展信息的内容 */
typedef struct tagSessionCustomExtInfo
{
    SESSION_EXT_DESTROY_CB_PF pfExtDestroy;
}SESSION_CUSTOM_EXTINFO_S;

typedef struct tagSessionExtRegInfo
{
    SESSION_CUSTOM_EXTINFO_S astCustomExtInfo[SESSION_MODULE_MAX];
}SESSION_EXT_REGINFO_S;

/* 删除会话的参数信息 */
typedef struct tag_SESSION_RESET_PARAM
{
    UINT uiMdcNum;
    SESSION_TABLE_KEY_S *pstKey;
} SESSION_RESET_PARAM_S;


static inline VOID SESSION_KDecStat(IN SESSION_CTRL_S *pstSessionCtrl, IN SESSION_L4_TYPE_E enSessType, IN UINT uiAppID)
{
    SESSION_K_STATISTICS_S *pstKstatistics;

    pstKstatistics = &pstSessionCtrl->stSessStat;
    rte_atomic32_dec(&pstKstatistics->stTotalSessNum);    
    rte_atomic32_dec(&pstKstatistics->astProtoCount[enSessType]);
    SESSION_KAppProtoDec(uiAppID, pstKstatistics);
    
    return;
}

/******************************************************************
   Func Name:SESSION_InfoCountDec
Date Created:2021/04/25
      Author:wangxiaohua
 Description:软件规格会话全局统计减一
       INPUT:VOID
      Output:无
      Return:ULONG
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_InfoCountDec(VOID)
{
    if (rte_atomic32_read(&g_stSessionCount) > 0)
    {
        rte_atomic32_dec(&g_stSessionCount);
    }

    return;
}

/******************************************************************
   Func Name:_session_KTableMemZero
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话内存清零函数
       INPUT:UINT uiLen
      Output:VOID *pData, 待清空的内存
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID _session_KTableMemZero(IN ULONG ulLen, OUT VOID *pData)
{
    ULONG *pulData = (ULONG *)pData;
    ULONG ulIndex;

    for(ulIndex = 0; ulIndex < (ulLen / (16 * sizeof(ULONG))); ulIndex++)
    {
        pulData[0] = 0; pulData[1] = 0;  pulData[2] = 0; pulData[3] = 0;         
        pulData[4] = 0; pulData[5] = 0;  pulData[6] = 0; pulData[7] = 0; 
        pulData[8] = 0; pulData[9] = 0;  pulData[10] = 0; pulData[11] = 0; 
        pulData[12] = 0; pulData[13] = 0;  pulData[14] = 0; pulData[15] = 0; 
        pulData += 16;
    }

    if(__builtin_constant_p(ulLen))
    {
        switch ((ulLen / sizeof(ULONG)) & 0xF)
        {
            case 15:
                pulData[14] = 0;
            case 14:
                pulData[13] = 0;
            case 13:
                pulData[12] = 0;
            case 12:
                pulData[11] = 0;
            case 11:
                pulData[10] = 0;
            case 10:
                pulData[9] = 0;
            case 9:
                pulData[8] = 0;
            case 8:
                pulData[7] = 0;
            case 7:
                pulData[6] = 0;
            case 6:
                pulData[5] = 0;
            case 5:
                pulData[4] = 0;
            case 4:
                pulData[3] = 0;
            case 3:
                pulData[2] = 0;
            case 2:
                pulData[1] = 0;
            case 1:
                pulData[0] = 0;
            default:
                break;
        }
    }
    else
    {
        for(ulIndex = 0; ulIndex < ((ulLen / (4 * sizeof(ULONG))) & 0x03); ulIndex++)
        {
            pulData[0] = 0; pulData[1] = 0; pulData[2] = 0; pulData[3] = 0;
            pulData += 4;
        }

        for(ulIndex = 0; ulIndex < ((ulLen / sizeof(ULONG)) & 0x03); ulIndex++)
        {
            pulData[0] = 0;
            pulData += 1;
        }
        
    }

    return;
}

static inline SESSION_S *SESSION_Malloc(UCHAR ucSessionType)
{
    SESSION_S *pstSession = NULL;

    if (0 == rte_mempool_get(g_apstSessPool[ucSessionType], (VOID **)&pstSession))
    {
        _session_KTableMemZero((ULONG)g_auiSessTotalLen[ucSessionType], (VOID*)pstSession);
        pstSession->stSessionBase.ucSessionType = ucSessionType;
    }

    return pstSession;
}

/********************************************************************
从会话表获取业务模块扩展信息
*************************************************************/
static inline VOID* SESSION_KGetStaticExtInfo(IN SESSION_HANDLE hSession,
                                              IN SESSION_MODULE_E enModule)
{
	SESSION_S *pstSession =(SESSION_S *)hSession; 
	VOID *pExtCb;

	DBGASSERT(NULL != pstSession); 

	switch(enModule)
	{
		case SESSION_MODULE_ALG:/* 会话管理-ALG子模块 */
		{
			pExtCb = pstSession->pAlgCb;
			break;
		}

		/* 会话日志 模块 
		case SESSION_MODULE_LOG:
		{
			pExtCb = pstSession->stSession.pLogCb; 
			break;
		}
		*/

		default:
		{
			pExtCb = NULL; 
			break;
		}
	}

	return pExtCb;
}

VOID SESSION_KFreeResetObject(IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject);
AGINGQUEUE_RST_MSG_OBJECT_S * SESSION_KMallocResetObject(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject);
BOOL_T SESSION_KIsSameResetMsg(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject1,
                               IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject2);
BOOL_T _session_KNeedResetProc(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
                               IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject);
BOOL_T SESSION_KIsAlgFlagSet(IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule);
VOID SESSION_KNotify_TableCreate(IN SESSION_HANDLE hSession);
VOID SESSION_KNotify_TableDelete(IN SESSION_HANDLE hSession);
ULONG SESSION_KMbufDestroy(IN MBUF_S *pstMbuf);
/* 会话表项管理一阶段初始化函数 */
ULONG SESSION_KTableInit(VOID);
VOID SESSION_KTableFini(VOID);

ULONG SESSION_KRegisterModule(IN SESSION_MODULE_E enModule, IN const SESSION_MODULE_REG_S *pstRegInfo);
VOID *SESSION_KGetExtInfoSafe(IN SESSION_HANDLE hSession,
                              IN SESSION_MODULE_E enModule,
                              IN SESSION_ATTACH_CREATE_PF pfCreate,
                              IN ULONG ulPara);


#endif
