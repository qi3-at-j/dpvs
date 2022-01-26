
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
	/* ��ʼ����󲢷��Ự�� */
	uiMdcID = MDC_GetLocalIndexByMDCID(MDC_GetCurrentMDC());
	pstSessionCtrl->uiMaximum = SESSION_KGCFG_GetMaximum(uiMdcID);

	/* ��ʼ���½���������Ͱ */
	uiRate = SESSION_KGCFG_GetRate(uiMdcID);
	CARTB_Pps_Init(uiRate, (UINT64)uiRate, &(pstSessionCtrl->stCarTb));
#endif
	/* ��ʼ״̬�������½��Ự */
	pstSessionCtrl->bIsNewSessPermit = BOOL_TRUE;
	pstSessionCtrl->bIsDelSessPermit = BOOL_FALSE;
	pstSessionCtrl->bStatEnable = BOOL_FALSE;
	pstSessionCtrl->bSecEnable = BOOL_TRUE;

#if 0
	/* ��ʼ��session backup���� */
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

	/* ��ʼ��Ϊ�ϸ�״̬����Ĭ��״̬�� */
	pstSessionCtrl->pucTcpStateTable = (UCHAR *)g_aucTcp_state_table;

	/* ��ʼ��session debugȫ�ֿ��� */
	pstSessionCtrl->bIsDebugSwitch = BOOL_FALSE;
#if 0
	/* ��ʼ���ỰӦ��HASH�� */
	ulRet |= SESSION_KGCFG_AppHashInit(pstSessionCtrl);
	ulRet |= SESSION6_KGCFG_AppHashInit(pstSessionCtrl);

	/* �ӿ����ƺ�����ӳ���ϵhash�����ʼ�� */
	ulRet = SESSION_KIfList_Init(pstSessionCtrl);
#endif
	/* ��ʼ���ϻ��� */
	ulRet |= SESSION_KAgingClass_Init(pstSessionCtrl);
#if 0
	SESSION_KInitInactiveAgingClass();
	SESSION6_KInitInactiveAgingClass();
	RELATION_KAging_ChangeableClassInit(pstSessionCtrl);
	RELATION6_KAging_ChangeableClassInit(pstSessionCtrl);

	/* ��ʼ���Ự��־��������־*/
	SESSION_KLOG_MDC_Init(pstSessionCtrl);
#endif
    return ulRet;
}

ULONG SESSION_KMDC_Init (VOID)
{
	ULONG ulErrCode;
	SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();

	/* MDC���ݳ�ʼ�����ò������ݲ����������׶Σ� */
	ulErrCode = _kmdc_Data_Init(pstSessionCtrl);

	/* ͳ����Ϣ����һ�׶γ�ʼ�� */
	ulErrCode |= session_global_stat_init(&(pstSessionCtrl->stSessStat));

	/* alg �쳣ͳ����Ϣ��ʼ��*/
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
       INPUT:��
      Output:��
      Return:ERROR_SUCCESS �ɹ�
             ERROR_FAILED  ʧ��
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

    /* �ϻ����г�ʼ�� */
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstAgingQueue));
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstRelationQueue));
#if 0
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstRelationAssociateQueue));
    ulErrCode = AGINGQUEUE_UnStable_MDCInit(&(g_stSessionstRelation6AssociateQueue));

    /* ��ȡMDC���ƿ� */
    pstSessionCtrl = SESSION_CtrlData_Get();
    SESSION_KInitAppObj(pstSessionCtrl);
#endif

    if(ERROR_SUCCESS != ulErrCode)
    {
        ulErrCode = ERROR_FAILED;
    }

    return ulErrCode;
}

