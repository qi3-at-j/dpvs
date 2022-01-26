
#include "session.h"
#include "session_kcore.h"
#include "session_ktableaging.h"
#include "session_kmdc.h"
#include "apr.h"


SESSION_CTRL_S g_stSessionCtrl;
extern AGINGQUEUE_UNSTABLE_S g_stSessionstRelationQueue;
extern AGINGQUEUE_UNSTABLE_S g_stSessionstRelationAssociateQueue;
extern AGINGQUEUE_UNSTABLE_S g_stSessionstRelation6AssociateQueue;

ULONG session_global_stat_init(IN SESSION_K_STATISTICS_S* pstGlobalStat);
ULONG session_global_algfail_cnt_init(IN SESSION_ALGFAILCNT_S* pstAlgFailCnt);
int sess_cli_init(void);
int relation_cli_init(void);


static ULONG _kmdc_Data_Init(INOUT SESSION_CTRL_S *pstSessionCtrl)
{
	ULONG ulRet = ERROR_SUCCESS;
	//UINT uiRate;
	//UINT uiMdcID;

	memset(pstSessionCtrl, 0, sizeof(SESSION_CTRL_S));
#if 0
	/* 初始化最大并发会话数 */
	uiMdcID = MDC_GetLocalIndexByMDCID(MDC_GetCurrentMDC());
	pstSessionCtrl->uiMaximum = SESSION_KGCFG_GetMaximum(uiMdcID);

	/* 初始化新建速率令牌桶 */
	uiRate = SESSION_KGCFG_GetRate(uiMdcID);
	CARTB_Pps_Init(uiRate, (UINT64)uiRate, &(pstSessionCtrl->stCarTb));
#endif
	/* 初始状态，允许新建会话 */
	pstSessionCtrl->bIsNewSessPermit = BOOL_TRUE;
	pstSessionCtrl->bIsDelSessPermit = BOOL_FALSE;
	pstSessionCtrl->bStatEnable = BOOL_FALSE;
	pstSessionCtrl->bSecEnable = BOOL_TRUE;

#if 0
	/* 初始化session backup开关 */
	pstSessionCtrl->stBackup.bIsEnable = BOOL_FALSE;
	pstSessionCtrl->stBackup.bAsymmetric = BOOL_FALSE;
	pstSessionCtrl->bIsBroadcastEnable = BOOL_TRUE;
	pstSessionCtrl->bIsAgingRequestEnable = BOOL_TRUE;
	pstSessionCtrl->bIsAgingResponseEnable = BOOL_TRUE;
	pstSessionCtrl->bIsForceDeleteEnable = BOOL_TRUE;
	pstSessionCtrl->bIsRelationSyncEnable = BOOL_TRUE;
	pstSessionCtrl->bIsRelationUpdateEnable = BOOL_TRUE;
	pstSessionCtrl->bIsRelationDeleteEnable = BOOL_TRUE;
	pstSessionCtrl->bIsL4StateLoose = BOOL_FALSE;
	pstSessionCtrl->enSessBackupState = SESSION_REALTIME_BACKUP;
#endif

	/* 初始化为严格状态机即默认状态机 */
	pstSessionCtrl->pucTcpStateTable = (UCHAR *)g_aucTcp_state_table;

	/* 初始化session debug全局开关 */
	pstSessionCtrl->bIsDebugSwitch = BOOL_FALSE;
#if 0
	/* 初始化会话应用HASH表 */
	ulRet |= SESSION_KGCFG_AppHashInit(pstSessionCtrl);
	ulRet |= SESSION6_KGCFG_AppHashInit(pstSessionCtrl);

	/* 接口名称和索引映射关系hash表项初始化 */
	ulRet = SESSION_KIfList_Init(pstSessionCtrl);
#endif
	/* 初始化老化类 */
	ulRet |= SESSION_KAgingClass_Init(pstSessionCtrl);
#if 0
	SESSION_KInitInactiveAgingClass();
	SESSION6_KInitInactiveAgingClass();
	RELATION_KAging_ChangeableClassInit(pstSessionCtrl);
	RELATION6_KAging_ChangeableClassInit(pstSessionCtrl);

	/* 初始化会话日志、流量日志*/
	SESSION_KLOG_MDC_Init(pstSessionCtrl);
#endif
    return ulRet;
}

ULONG SESSION_KMDC_Init (VOID)
{
	ULONG ulErrCode;
	SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();

	/* MDC数据初始化（该部分数据不区分启动阶段） */
	ulErrCode = _kmdc_Data_Init(pstSessionCtrl);

	/* 统计信息，第一阶段初始化 */
	ulErrCode |= session_global_stat_init(&(pstSessionCtrl->stSessStat));

	/* alg 异常统计信息初始化*/
	ulErrCode |= session_global_algfail_cnt_init(&(pstSessionCtrl->stAlgFail));

    sess_cli_init();
    vrrp_cli_init();

	relation_cli_init();
    
	return ulErrCode;
}

/******************************************************************
   Func Name:SESSION_KMDC_Start
Date Created:2021/04/25
      Author:wangxiaohua
 Description:MDC Start
       INPUT:无
      Output:无
      Return:ERROR_SUCCESS 成功
             ERROR_FAILED  失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG SESSION_KMDC_Start(VOID)
{
    ULONG ulErrCode;

    //SESSION_CTRL_S *pstSessionCtrl;

    /* 老化队列初始化 */
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstAgingQueue));
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstRelationQueue));
#if 0
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstRelationAssociateQueue));
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstRelation6AssociateQueue));

    /* 获取MDC控制块 */
    pstSessionCtrl = SESSION_CtrlData_Get();
    SESSION_KInitAppObj(pstSessionCtrl);
#endif

    if(ERROR_SUCCESS != ulErrCode)
    {
        ulErrCode = ERROR_FAILED;
    }

    return ulErrCode;
}

