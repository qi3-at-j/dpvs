#include "session_mbuf.h"
#include "session.h"
#include "session_kcore.h"
#include "session_ktable.h"
#include "session_kl3proto.h"
#include "session_kl4proto.h"
#include "session_kmdc.h"


extern VOID SESSION_KL4PROTO_Fini(VOID);
extern VOID SESSION_KL3_Fini(VOID);


SESSION_AGINGQUE_CONF_S g_stSessAgingqueConfInfo = {160, 40, 100}; /* 初始化一个默认值 */

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

/* 获取定制信息 */
SESSION_AGINGQUE_CONF_S* SESSION_GetAgingqueConfInfo(VOID)
{
    return &g_stSessAgingqueConfInfo;
}

UINT SESSION_GetMbufSize(VOID)
{
    return (UINT)sizeof(MBUF_S);
}

/* 启动时，Run阶段的报文处理子模块处理函数，
   向转发流程注册业务处理，注册MBuf释放回调函数 */

STATIC ULONG SESSION_Packet_Module_Run(VOID)
{
    /* 初始化协议转换表 */
    SESSION_init_l4type_map();

    /* 注册MBuf释放时，MBuf中引用会话的释放函数 */
    MBUF_RegExtCacheFreeFunc(MBUF_CACHE_SESSION, SESSION_KMbufDestroy);

    return ERROR_SUCCESS;
}

/* SESSION内核模块退出 */
STATIC VOID SESSION_Exit(VOID)
{
    SESSION_Packet_Module_Exit();

    /* ALG协议去初始化 */
    SESSION_KALG_Fini();

    /* L4层协议去初始化 */
    SESSION_KL4PROTO_Fini();

    /* L3层协议去初始化 */
    SESSION_KL3_Fini();

    /* 关联表子模块去初始化 */
    SESSION_KRelation_Exit();
    SESSION6_KRelation_Exit();

    /* 关联表老化去初始化 */
    RELATION_KAging_Fini();
    RELATION6_KAging_Fini();

    /* 会话表去初始化 */
    SESSION_KTableFini();

    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstAgingQueue));    
    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstRelationQueue));    
    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstRelationAssociateQueue));
    AGINGQUEUE_UnStable_Destroy(&(g_stSessionstRelation6AssociateQueue));

    /* 去注册App Change事件*/
    APR_KAppChange_DeregFun(APR_MODULE_SESSION);
    
    return;
}


/* 内核模块第一阶段初始化 */
ULONG SESSION_Init(IN LPVOID pStartContext)
{
    ULONG ulErrCode = 0;
    SESSION_AGINGQUE_CONF_S *pstConfInfo;
    UINT uiMaxCheckNum;
    UINT uiMaxDeleteNum;

    IGNORE_PARAM(pStartContext);

    /* 老化队列第一阶段初始化 */
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

    /* 初始化会话扩展信息 */
    ulErrCode |= SESSION_KTableInit();

    /* 初始化AppID索引数组 */
    SESSION_InitMapAppType();

    /* 关联表老化初始化 */
    RELATION_KAging_Init();
    RELATION6_KAging_Init();

    /* ALG处理函数初始化 */
    ulErrCode |= SESSION_KALG_Init();

    /* 初始化失败，回退处理 */
    if(unlikely(ERROR_SUCCESS != ulErrCode))
    {
        SESSION_Exit();
        ulErrCode = ERROR_FAILED;
    }

    return ulErrCode;
}

/* 内核模块第二阶段初始化 */
ULONG SESSION_Run(IN LPVOID pStartContext)
{
    ULONG ulErrCode = ERROR_SUCCESS;

    IGNORE_PARAM(pStartContext);

    /* 初始化会话表信息 */
    ulErrCode = SESSION_KTableRun();

    /* 初始化关联表信息 */
    ulErrCode |= SESSION_KRelation_Run();    
    ulErrCode |= SESSION6_KRelation_Run();

    /* MDC第二阶段初始化 */    
    ulErrCode |= SESSION_KMDC_Start();

    /* L3处理函数初始化 */
    SESSION_KL3_Init();

    /* L4处理函数初始化 */
    ulErrCode |= SESSION_KL4PROTO_Init();

    /* 报文处理模块初始化 */
    ulErrCode |= SESSION_Packet_Module_Run();

#if 0
    /* 向APR注册应用变化处理 */
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
