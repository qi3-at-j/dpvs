#include "session_mbuf.h"
#include "session.h"
#include "session_kcore.h"
#include "session_ktable.h"
#include "session_kl3proto.h"
#include "session_kl4proto.h"
#include "session_kmdc.h"


extern VOID SESSION_KL4PROTO_Fini(VOID);
extern VOID SESSION_KL3_Fini(VOID);


SESSION_AGINGQUE_CONF_S g_stSessAgingqueConfInfo = {160, 40, 100}; /* ��ʼ��һ��Ĭ��ֵ */

AGINGQUEUE_UNSTABLE_S g_stSessionstAgingQueue;
AGINGQUEUE_UNSTABLE_S g_stSessionstRelationQueue;
AGINGQUEUE_UNSTABLE_S g_stSessionstRelationAssociateQueue;
AGINGQUEUE_UNSTABLE_S g_stSessionstRelation6AssociateQueue;

#if 0
AGINGQUEUE_UNSTABLE_S *SESSION_GET_GloableAgingQueue(VOID)
{
    return &g_stSessionstAgingQueue;
}

AGINGQUEUE_UNSTABLE_S *SESSION_GET_GloableRelationQueue(VOID)
{
    return &g_stSessionstRelationQueue;
}

AGINGQUEUE_UNSTABLE_S *SESSION_GET_GloableRelationAssociateQueue(VOID)
{
    return &g_stSessionstRelationAssociateQueue;
}

AGINGQUEUE_UNSTABLE_S *SESSION_GET_GloableRelation6AssociateQueue(VOID)
{
    return &g_stSessionstRelation6AssociateQueue;
}
#endif

/* ��ȡ������Ϣ */
SESSION_AGINGQUE_CONF_S* SESSION_GetAgingqueConfInfo(VOID)
{
    return &g_stSessAgingqueConfInfo;
}

UINT SESSION_GetMbufSize(VOID)
{
    return (UINT)sizeof(MBUF_S);
}

/* ����ʱ��Run�׶εı��Ĵ�����ģ�鴦������
   ��ת������ע��ҵ����ע��MBuf�ͷŻص����� */

STATIC ULONG SESSION_Packet_Module_Run(VOID)
{
    /* ��ʼ��Э��ת���� */
    SESSION_init_l4type_map();

    /* ע��MBuf�ͷ�ʱ��MBuf�����ûỰ���ͷź��� */
    MBUF_RegExtCacheFreeFunc(MBUF_CACHE_SESSION, SESSION_KMbufDestroy);

    return ERROR_SUCCESS;
}

/* SESSION�ں�ģ���˳� */
STATIC VOID SESSION_Exit(VOID)
{
    SESSION_Packet_Module_Exit();

    /* ALGЭ��ȥ��ʼ�� */
    SESSION_KALG_Fini();

    /* L4��Э��ȥ��ʼ�� */
    SESSION_KL4PROTO_Fini();

    /* L3��Э��ȥ��ʼ�� */
    SESSION_KL3_Fini();

    /* ��������ģ��ȥ��ʼ�� */
    SESSION_KRelation_Exit();
    SESSION6_KRelation_Exit();

    /* �������ϻ�ȥ��ʼ�� */
    RELATION_KAging_Fini();
    RELATION6_KAging_Fini();

    /* �Ự��ȥ��ʼ�� */
    SESSION_KTableFini();

    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstAgingQueue));    
    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstRelationQueue));    
    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstRelationAssociateQueue));
    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstRelation6AssociateQueue));

    /* ȥע��App Change�¼�*/
    APR_KAppChange_DeregFun(APR_MODULE_SESSION);
    
    return;
}


/* �ں�ģ���һ�׶γ�ʼ�� */
ULONG SESSION_Init(IN LPVOID pStartContext)
{
    ULONG ulErrCode = 0;
    SESSION_AGINGQUE_CONF_S *pstConfInfo;
    UINT uiMaxCheckNum;
    UINT uiMaxDeleteNum;

    IGNORE_PARAM(pStartContext);

    /* �ϻ����е�һ�׶γ�ʼ�� */
    pstConfInfo = SESSION_GetAgingqueConfInfo();
    uiMaxCheckNum = pstConfInfo->uiMaxCheckNum;
    uiMaxDeleteNum = pstConfInfo->uiMaxDeleteNum;
    g_stSessionstAgingQueue.uiMaxCheckNum = uiMaxCheckNum;
    g_stSessionstAgingQueue.uiMaxDeleteNum = uiMaxDeleteNum;
    g_stSessionstAgingQueue.uiInterval = SESSION_TIMER_INTERVAL;
    g_stSessionstAgingQueue.usModuleId = AGINGQUEUE_MODULE_SESSION;
    ulErrCode |= AGINGQUEUE_UnStable_Create(&(g_stSessionstAgingQueue));

    g_stSessionstRelationQueue.uiMaxCheckNum = uiMaxCheckNum / 10;
    g_stSessionstRelationQueue.uiMaxDeleteNum = uiMaxDeleteNum / 5;
    g_stSessionstRelationQueue.uiInterval = SESSION_TIMER_INTERVAL*5;
    g_stSessionstRelationQueue.usModuleId = AGINGQUEUE_MODULE_RELATION;
    ulErrCode |= AGINGQUEUE_UnStable_Create(&(g_stSessionstRelationQueue));

    /* ��ʼ���Ự��չ��Ϣ */
    ulErrCode |= SESSION_KTableInit();

    /* ��ʼ��AppID�������� */
    SESSION_InitMapAppType();

    /* �������ϻ���ʼ�� */
    RELATION_KAging_Init();
    RELATION6_KAging_Init();

    /* ALG��������ʼ�� */
    ulErrCode |= SESSION_KALG_Init();

    /* ��ʼ��ʧ�ܣ����˴��� */
    if(unlikely(ERROR_SUCCESS != ulErrCode))
    {
        SESSION_Exit();
        ulErrCode = ERROR_FAILED;
    }

    return ulErrCode;
}

/* �ں�ģ��ڶ��׶γ�ʼ�� */
ULONG SESSION_Run(IN LPVOID pStartContext)
{
    ULONG ulErrCode = ERROR_SUCCESS;

    IGNORE_PARAM(pStartContext);

    /* ��ʼ���Ự����Ϣ */
    ulErrCode = SESSION_KTableRun();

    /* ��ʼ����������Ϣ */
    ulErrCode |= SESSION_KRelation_Run();    
    ulErrCode |= SESSION6_KRelation_Run();

    /* MDC�ڶ��׶γ�ʼ�� */    
    ulErrCode |= SESSION_KMDC_Start();

    /* L3��������ʼ�� */
    SESSION_KL3_Init();

    /* L4��������ʼ�� */
    ulErrCode |= SESSION_KL4PROTO_Init();

    /* ���Ĵ���ģ���ʼ�� */
    ulErrCode |= SESSION_Packet_Module_Run();

#if 0
    /* ��APRע��Ӧ�ñ仯���� */
    APR_KAppChange_RegFun(APR_MODULE_SESSION,
                          _session_ipv4_procAppChange,
                          NULL);
#endif

    if(ERROR_SUCCESS != ulErrCode)
    {
        SESSION_Exit();
        ulErrCode = ERROR_FAILED;
    }

    return ulErrCode;
}
