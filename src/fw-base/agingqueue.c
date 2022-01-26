#include <stdio.h>
#include <time.h>
#include <rte_timer.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include "baseype.h"
#include "agingqueue.h"
#include "session.h"

#define AGINGQUEUE_NR_PER_PACKET   1          /* 每次报文处理个数，两种类型对象各处理这么多 */
#define AGINGQUEUE_NR_PER_TIMER    (25000/HZ) /* 每次定时器删除最大个数，两种类型对象各处理这么多 */

#define AGINGQUEUE_TICKS_PER_SCHEDULE 10  /* 在响应MDC STOP事件时，每隔这么多TICK释放一次CPU */

/* 稳定对象相关宏*/
#define AGINGQUEUE_STABLE_START_PULSE 0xFFFF0000UL

/* 不稳定对象相关宏 */
#define AGINGQUEUE_CHECK_NR_PER_TIMER   (120000/HZ) /* 每次定时器检查最大个数 */
#define AGINGQUEUE_CHECK_MDC_PER_TIMER2 (64)        /* 每次定时器检查最大个数 */

#define AGINGQUEUE_TERMINAL_DEVICE  10

#define AGINGQUEUE_RST_MSG_NUM_PER_CPU 250

typedef struct tagAgingQueueStableVcpuData
{
    struct rte_timer stTimer;
    BOOL_T bTimerActiveFlag;
    ULONG ulStableNumber;
    UINT uiStablePulse;
    ULONG ulStableJiffies;
    AGINGQUEUE_STABLE_ARRAY_S astStableLevels[AGINGQUEUE_STABLE_LEVEL_NR];
    UINT uiMdcNumber;
}AGINGQUEUE_STABLE_VCPU_DATA_S;

typedef struct tagAgingQueueChangeableData
{
    struct rte_timer stTimer;
    INT iCPU;
    BOOL_T bTimerActiveFlag;
    ULONG ulChangableNumber;
    UINT uiChangeablePulse;
    ULONG ulChangeableJiffies;
    AGINGQUEUE_CHANGEABLE_ARRAY_S astChangeableLevels[AGINGQUEUE_STABLE_LEVEL_NR];
    USHORT usMdcNumber;
    rte_spinlock_t stLock;
}AGINGQUEUE_CHANGEABLE_DATA_S;

typedef struct tagAgingQueueAddResetMsgParam
{
    AGINGQUEUE_UNSTABLE_S *pstQueue;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj;
}AGINGQUEUE_ADD_RST_MSG_PARAM_S;

#define AGINGQUEUE_TIMER_TYPE_ONE_CPU 0
#define AGINGQUEUE_TIMER_TYPE_ALL_CPU 1
#define AGINGQUEUE_OBJ_MAX_NUM (0x040000UL)

/******************************************************************
   Func Name:_agingqueue_UnStable_FakeIsTimeout
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列老化对象超时回调
       INPUT:AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _agingqueue_UnStable_FakeIsTimeout(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    IGNORE_PARAM(pstObject);
    return BOOL_FALSE;
}

/******************************************************************
   Func Name:_agingqueue_UnStable_FakeDelete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列老化对象删除回调
       INPUT:AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID _agingqueue_UnStable_FakeDelete(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    IGNORE_PARAM(pstObject);
    return;
}

static AGINGQUEUE_UNSTABLE_CLASS_S g_stAgingUnstableFakeClass = {
    0,
    _agingqueue_UnStable_FakeIsTimeout,
    _agingqueue_UnStable_FakeDelete
};

/******************************************************************
   Func Name:_agingqueue_UnStable_GetResetMsg
Date Created:2021/04/25
      Author:wangxiaohua
 Description:获取reset消息节点
       INPUT:IN AGINGQUEUE_UNSTABLE_VCPU_DTAT_S *pstVcpuData
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC AGINGQUEUE_RST_MSG_OBJECT_S *_agingqueue_UnStable_GetResetMsg(IN AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData)
{
    SL_HEAD_S *pstRstMsgList;
    SL_NODE_S *pstRstNode;
    AGINGQUEUE_RST_MSG_OBJECT_S * pstRstObj = NULL;

    pstRstMsgList = &(pstVcpuData->stResetMsgList.stList);
    pstRstNode = SL_First(pstRstMsgList);
    if (NULL != pstRstNode)
    {
        pstRstObj = SL_ENTRY(pstRstNode, AGINGQUEUE_RST_MSG_OBJECT_S, stNode);
    }
    return pstRstObj;
}

/******************************************************************
   Func Name:_agingqueue_UnStable_AdjustCurson
Date Created:2021/04/25
      Author:wangxiaohua
 Description:如果有reset消息，则调整当前curson
       INPUT:IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstRstObj,
             INOUT AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID _agingqueue_UnStable_AdjustCurson(INOUT AGINGQUEUE_RST_MSG_OBJECT_S *pstRstObj,
                                              INOUT AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData)
{
    SL_HEAD_S *pstObjList;
    AGINGQUEUE_UNSTABLE_CURSON_S *pstUnstableCurson;

    pstRstObj->bNeedAdjCurson = BOOL_FALSE;
    pstObjList = &(pstVcpuData->stUnstableList.stList);
    pstUnstableCurson = &(pstVcpuData->stUnstableCurson);

    pstUnstableCurson->pstUnstableCursor = SL_First(pstObjList);
    
    return;
}

/******************************************************************
   Func Name:_agingqueue_Unstable_NextCurson
Date Created:2021/04/25
      Author:wangxiaohua
 Description:设置游标指向下一个mdc
       INPUT:IN AGINGQUEUE_UNSTABLE_VCPU_DTAT_S *pstVcpuData
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID _agingqueue_Unstable_NextCurson(INOUT AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData)
{
    pstVcpuData->stUnstableCurson.pstUnstableCursor = SL_First(&(pstVcpuData->stUnstableList.stList));

    return;
}

#define AGINGQUEUE_ADJ_CURSON_BY_RSTMSG(pstVcpuData_x, pstRstObj_x)\
{\
    if(0 != (pstVcpuData_x)->ulResetMsgNum)\
    {\
        (pstRstObj_x) = _agingqueue_UnStable_GetResetMsg((pstVcpuData_x));\
        if ((NULL != (pstRstObj_x))&&(BOOL_TRUE == (pstRstObj_x)->bNeedAdjCurson))\
        {\
            _agingqueue_UnStable_AdjustCurson((pstRstObj_x),(pstVcpuData_x));\
        }\
    }\
}

static inline BOOL_T AGINGQUEUE_Unstable_AgingOne(IN AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData,
                                                  IN AGINGQUEUE_UNSTABLE_S *pstQueue,
                                                  IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstRstObj,
                                                  INOUT BOOL_T *pbModtimer)
{
    SL_NODE_S *pstCursor;
    SL_NODE_S *pstCurrentNode = NULL;
    AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject;
    AGINGQUEUE_UNSTABLE_CLASS_S *pstClass;
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuBarrier;
    BOOL_T bDelete;

    /* 获取游标 */
    pstCursor = pstVcpuData->stUnstableCurson.pstUnstableCursor;
    pstVcpuBarrier = pstVcpuData;

    /* 获取游标的下一个节点，外层循环条件可以保证pstCursor不为NULL */
    pstCurrentNode = SL_Next(pstCursor);

    /* 遍历到队尾 */
    if(NULL == pstCurrentNode)
    {
        /* 已经到达队列尾部 */
        pstVcpuData->stUnstableCurson.pstUnstableCursor = NULL;
        return BOOL_FALSE;
    }

    pstObject = SL_ENTRY(pstCurrentNode, AGINGQUEUE_UNSTABLE_OBJECT_S, stNode);

    /* 老化操作 */
    pstClass = pstObject->pstClass;

    /* 判断是否需要reset或者老化 */
    if(((NULL != pstRstObj) && (BOOL_TRUE == pstRstObj->pfNeedResetProc(pstRstObj, pstObject))) ||
       (BOOL_TRUE == pstClass->pfIsTimeout(pstObject)))
    {
        rte_spinlock_lock(&pstVcpuData->stLock);

        /* 控制核老化时，可能出现中间插入新节点的情况 */
        if(likely(pstCurrentNode == SL_Next(pstCursor)))
        {
            /* 下面的函数当第二个参数非空，第一个参数不用 */
            (VOID)SL_DelAfter(&(pstVcpuBarrier->stUnstableList.stList), pstCursor);

            /* 老化队列中对象个数减1 */
            pstVcpuData->ulUnstableNumber--;
            bDelete = BOOL_TRUE;
        }
        else
        {
            /* 本次老化由于并发冲突暂不老化，下次函数重入时老化 */
            pstVcpuData->stUnstableCurson.pstUnstableCursor = SL_Next(pstCursor);
            bDelete = BOOL_FALSE;
        }

        rte_spinlock_unlock(&pstVcpuData->stLock);
    }
    else
    {
        /* 移动游标到当前处理节点 */
        pstVcpuData->stUnstableCurson.pstUnstableCursor = pstCurrentNode;
        bDelete = BOOL_FALSE;
    }

    if(BOOL_TRUE == bDelete)
    {
        pstClass->pfDelete(pstObject);

        if(NULL != pstQueue)
        {
            if(rte_atomic32_sub_return(&pstQueue->stCount, 1) == 0)
            {
                *pbModtimer = BOOL_FALSE;
            }
        }
    }

    return bDelete;
}

/* 删除reset消息节点 */
STATIC VOID _agingqueue_UnStable_DelResetMsg(IN AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData,
                                             IN AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj)
{
    SL_HEAD_S *pstRstMsgList;
    //ULONG ulIrqFlag;

    pstRstMsgList = &(pstVcpuData->stResetMsgList.stList);

    //forcompile local_irq_save(ulIrqFlag);
    SL_Del(pstRstMsgList, &(pstResetObj->stNode));
    pstVcpuData->ulResetMsgNum--;
    //forcompile local_irq_restore(ulIrqFlag);

    pstResetObj->pfFree(pstResetObj);

    return;
}

static inline BOOL_T AGINGQUEUE_Unstable_AgingMdcList2(IN AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData,
                                                       IN ULONG ulMaxCheckNumber,
                                                       IN ULONG ulMaxDeleteNumber,
                                                       IN ULONG ulExpireTime,
                                                       INOUT ULONG *pulCheckNumber,
                                                       INOUT ULONG *pulDeleteNumber)
{
    BOOL_T bTimeOut = BOOL_FALSE;
    AGINGQUEUE_RST_MSG_OBJECT_S * pstRstObj = NULL;

    AGINGQUEUE_ADJ_CURSON_BY_RSTMSG(pstVcpuData, pstRstObj);

    while (NULL != pstVcpuData->stUnstableCurson.pstUnstableCursor)
    {
        if(BOOL_TRUE == AGINGQUEUE_Unstable_AgingOne(pstVcpuData, NULL, pstRstObj, NULL))
        {
            (*pulDeleteNumber)++;
        }

        (*pulCheckNumber)++;

        if(((*pulCheckNumber) > ulMaxCheckNumber) ||
            ((*pulDeleteNumber) > ulMaxDeleteNumber) ||
            (time_after(rte_get_timer_cycles(), ulExpireTime)))
        {
            bTimeOut = BOOL_TRUE;
            break;
        }
    }

    /*游标为NULL, 说明遍历到链表尾部，需要重置游标开始新的遍历*/
    if((NULL == pstVcpuData->stUnstableCurson.pstUnstableCursor) || 
       (0 == pstVcpuData->ulUnstableNumber))
    {
        /* 删除rst消息节点 */
        if(NULL != pstRstObj)
        {
            _agingqueue_UnStable_DelResetMsg(pstVcpuData, pstRstObj);
        }
        _agingqueue_Unstable_NextCurson(pstVcpuData);
    }

    return bTimeOut;
}

static VOID _agingqueue_unstable_Timer2(struct rte_timer *ptr_timer, VOID *pData)
{
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData;
    ULONG ulMaxCheckNumber;
    ULONG ulExpireTime;
    ULONG ulLoopNumber = 0;
    ULONG ulCheckNumber = 0;
    ULONG ulDeleteNumber = 0;
    BOOL_T bTimeOut = BOOL_FALSE;
    SESSION_AGINGQUE_CONF_S *pstConfInfo;

    pstVcpuData = (AGINGQUEUE_UNSTABLE_VCPU_DATA_S *)pData;
    ulMaxCheckNumber = MIN(pstVcpuData->ulUnstableNumber, pstVcpuData->uiMaxCheckNum);
    pstConfInfo = SESSION_GetAgingqueConfInfo();
    ulExpireTime = rte_get_timer_cycles() + pstConfInfo->ulExpireTime;

    do
    {
        bTimeOut = AGINGQUEUE_Unstable_AgingMdcList2(pstVcpuData, ulMaxCheckNumber,
                                                     (ULONG)pstVcpuData->uiMaxDeleteNum,
                                                     ulExpireTime,
                                                     &ulCheckNumber,
                                                     &ulDeleteNumber);
        ulLoopNumber ++;

        if (ulLoopNumber > AGINGQUEUE_CHECK_MDC_PER_TIMER2)
        {
            break;
        }
        
    }while (BOOL_FALSE == bTimeOut);

    return;
}

static ULONG _agingqueue_UnStable_VCpuData_InitOne(INOUT AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData)
{   
    SL_Init(&(pstVcpuData->stUnstableList.stList));
    SL_NodeInit(&(pstVcpuData->stUnstableList.stFakeObject.stNode));

    SL_Init(&(pstVcpuData->stResetMsgList.stList));

    pstVcpuData->stUnstableCurson.pstUnstableCursor = SL_First(&(pstVcpuData->stUnstableList.stList));

    pstVcpuData->ulUnstableNumber = 0;
    pstVcpuData->bTimerActiveFlag = BOOL_FALSE;
    rte_spinlock_init(&(pstVcpuData->stLock));

    return ERROR_SUCCESS;
}

/******************************************************************
   Func Name:_agingqueue_UnStable_VCpuData_InitOne2
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列初始化函数
       INPUT:AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData
      Output:
      Return:ERROR_SUCCESS 成功
             ERROR_FAILED  失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG _agingqueue_UnStable_VCpuData_InitOne2(INOUT AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData)
{
    return _agingqueue_UnStable_VCpuData_InitOne(pstVcpuData);
}


/******************************************************************
   Func Name:_agingqueue_UnStable_VCpuData_Fini
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列去初始化函数
       INPUT:AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstTemp
      Output:
      Return:ERROR_SUCCESS 成功
             ERROR_FAILED  失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID _agingqueue_UnStable_VCpuData_Fini(INOUT AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstTemp)
{
    return;
}


/******************************************************************
   Func Name:_agingqueue_UnStable_VCpuData_Init2
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列初始化函数
       INPUT:AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstTemp
      Output:
      Return:ERROR_SUCCESS 成功
             ERROR_FAILED  失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG _agingqueue_UnStable_VCpuData_Init2(IN const AGINGQUEUE_UNSTABLE_S *pstQueue)
{
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData;
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstTemp;
    UINT uiIndex;
    ULONG ulErrorCode = ERROR_SUCCESS;

    pstTemp = (AGINGQUEUE_UNSTABLE_VCPU_DATA_S *)pstQueue->pstVcpuData;

    for(uiIndex = 0; uiIndex < worker_thread_total(); uiIndex++)
    {
        pstVcpuData = &(pstTemp[uiIndex]);
        pstVcpuData->uiMaxCheckNum = pstQueue->uiMaxCheckNum;
        pstVcpuData->uiMaxDeleteNum = pstQueue->uiMaxDeleteNum;
        pstVcpuData->uiInterval = pstQueue->uiInterval;
        pstVcpuData->usModuleId = pstQueue->usModuleId;

        ulErrorCode= _agingqueue_UnStable_VCpuData_InitOne2(pstVcpuData);
        if(ERROR_SUCCESS != ulErrorCode)
        {
            break;
        }
    }

    if(ERROR_SUCCESS != ulErrorCode)
    {
        _agingqueue_UnStable_VCpuData_Fini(pstTemp);
    }

    return ulErrorCode;
}



/******************************************************************
   Func Name:AGINGQUEUE_UnStable_InitQueue2
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列初始化函数
       INPUT:pstQueue ----老化队列
      Output:
      Return:ERROR_SUCCESS 成功
             ERROR_FAILED  失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG AGINGQUEUE_UnStable_InitQueue2(INOUT AGINGQUEUE_UNSTABLE_S *pstQueue)
{
    ULONG ulErrorCode;
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData;
    
    /* 分配每个VCPU的老化队列链数据 */
    pstVcpuData = (AGINGQUEUE_UNSTABLE_VCPU_DATA_S *)rte_zmalloc(NULL, 
                            sizeof(AGINGQUEUE_UNSTABLE_VCPU_DATA_S)*worker_thread_total(), 0);
    if(NULL == pstVcpuData)
    {
        return ERROR_FAILED;
    }

    pstQueue->pstVcpuData = pstVcpuData;

    ulErrorCode = _agingqueue_UnStable_VCpuData_Init2(pstQueue);
    if(ERROR_SUCCESS != ulErrorCode)
    {
        rte_free(pstQueue->pstVcpuData);
        pstQueue->pstVcpuData = NULL;
        return ERROR_FAILED;
    }

    return ERROR_SUCCESS;
}

/******************************************************************
   Func Name:AGINGQUEUE_UnStable_Create
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列初始化函数
       INPUT:pstQueue ----老化队列
      Output:
      Return:ERROR_SUCCESS 成功
             ERROR_FAILED  失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG AGINGQUEUE_UnStable_Create(INOUT AGINGQUEUE_UNSTABLE_S *pstQueue)
{
    //AGINGQUEUE_KSYSLOG("AGINGQUEUE_UnStable_Create:ModuleId = %d\r\n", pstQueue->usModuleId);
    return AGINGQUEUE_UnStable_InitQueue2(pstQueue);
}

/******************************************************************
   Func Name:AGINGQUEUE_UnStable_Add2
Date Created:2021/04/25
      Author:wangxiaohua
 Description:添加不稳定对象
       INPUT:pstQueue  ----队列
             pstObject ----要添加的对象
      Output:
      Return:ERROR_SUCCESS 成功
             ERROR_FAILED  失败
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID AGINGQUEUE_UnStable_Add2(IN const AGINGQUEUE_UNSTABLE_S *pstQueue,
                                     IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData;    
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstTemp;
    UINT                            uiCpuID;
    
    DBGASSERT(NULL != pstObject);
    pstTemp = (AGINGQUEUE_UNSTABLE_VCPU_DATA_S *)pstQueue->pstVcpuData;

    uiCpuID = index_from_lcore_id();

    local_bh_disable();

    pstVcpuData = &(pstTemp[uiCpuID]);
    
    if(BOOL_TRUE != pstVcpuData->bTimerActiveFlag)
    {
        rte_timer_init(&pstVcpuData->stTimer);
        (VOID)rte_timer_reset(&pstVcpuData->stTimer,
                              (pstQueue->uiInterval * rte_get_timer_hz()) / 1000,
                              PERIODICAL,
                              rte_lcore_id(),
                              &_agingqueue_unstable_Timer2, 
                              pstVcpuData);
        pstVcpuData->bTimerActiveFlag = BOOL_TRUE;
    }

    SL_AddAfter_Rcu(&(pstVcpuData->stUnstableList.stList),
                    &(pstVcpuData->stUnstableList.stFakeObject.stNode),
                    &pstObject->stNode);
    pstVcpuData->ulUnstableNumber++;


    local_bh_enable();

    return;
}

VOID AGINGQUEUE_UnStable_Add(IN AGINGQUEUE_UNSTABLE_S *pstQueue,
                             IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
    DBGASSERT(NULL != pstObject);

    AGINGQUEUE_UnStable_Add2(pstQueue, pstObject);

    return;
    
}


/******************************************************************
   Func Name:_agingqueue_UnStable_InitUnstableList
Date Created:2021/04/25
      Author:wangxiaohua
 Description:不稳定老化队列初始化函数
       INPUT:AGINGQUEUE_UNSTABLE_LIST_S *pstUnstableList
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID _agingqueue_UnStable_InitUnstableList(INOUT AGINGQUEUE_UNSTABLE_LIST_S *pstUnstableList)
{
    AGINGQUEUE_UNSTABLE_OBJECT_S *pstFakeObject;

    SL_Init(&pstUnstableList->stList);

    pstFakeObject = &pstUnstableList->stFakeObject;
    memset(pstFakeObject, 0, sizeof(AGINGQUEUE_UNSTABLE_OBJECT_S));
    SL_NodeInit(&pstFakeObject->stNode);
    pstFakeObject->pstClass = &g_stAgingUnstableFakeClass;

    SL_AddHead_Rcu(&pstUnstableList->stList, &pstFakeObject->stNode);

    return ;
}

/******************************************************************
   Func Name:AGINGQUEUE_UnStable_MDCInit
Date Created:2021/04/25
      Author:wangxiaohua
 Description:MDC初始化
       INPUT:IN AGINGQUEUE_UNSTABLE_S *pstQueue
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG AGINGQUEUE_UnStable_MDCInit(IN const AGINGQUEUE_UNSTABLE_S *pstQueue)
{
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstTemp;    
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData;
    UINT uiIndex;

    pstTemp = (AGINGQUEUE_UNSTABLE_VCPU_DATA_S *)pstQueue->pstVcpuData;
    if(NULL == pstTemp)
    {
        DBGASSERT(0);
        return ERROR_FAILED;
    }

    for(uiIndex = 0; uiIndex < worker_thread_total(); uiIndex++)
    {
        pstVcpuData = &(pstTemp[uiIndex]);

        DBGASSERT(SL_IsEmpty(&pstVcpuData->stUnstableList.stList));
        
        _agingqueue_UnStable_InitUnstableList(&pstVcpuData->stUnstableList);
    }

    return ERROR_SUCCESS;
}

/******************************************************************
   Func Name:_agingqueue_UnStable_AddResetObjList
Date Created:2021/04/25
      Author:wangxiaohua
 Description:添加reset消息节点
       INPUT:IN SL_HEAD_S *pstRstMsgList
             IN AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC ULONG _agingqueue_UnStable_AddResetObjList(IN SL_HEAD_S *pstRstMsgList,
                                                  IN AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj)
{
    SL_NODE_S *pstCurrenNode;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstObject;
    ULONG ulRet = ERROR_FAILED;

    SL_FOREACH(pstRstMsgList, pstCurrenNode)
    {
        pstObject = SL_ENTRY(pstCurrenNode, AGINGQUEUE_RST_MSG_OBJECT_S, stNode);

        /* 配置消息相同，则返回 */
        if(BOOL_TRUE == pstResetObj->pfIsSameMsg(pstObject, pstResetObj))
        {
            break;
        }

        /* 保证reset session消息执行顺序，将消息加到表尾;
           对于reset session命令添加reset节点，则添加到第二个节点位置 */
        if((AGINGQUE_RESET_SESSION_BY_TABLEKEY == pstResetObj->enRetsetType) || (NULL == pstCurrenNode->pstNext))
        {
            SL_AddAfter(pstRstMsgList, pstCurrenNode, &(pstResetObj->stNode));
            ulRet = ERROR_SUCCESS;
            break;
        }        
    }

    return ulRet;
}

/******************************************************************
   Func Name:_agingqueue_UnStable_AddResetObj
Date Created:2021/04/25
      Author:wangxiaohua
 Description:添加reset消息节点
       INPUT:IN AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData
             IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID _agingqueue_UnStable_AddResetObj(IN AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData,
                                      IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj)
{
    SL_HEAD_S *pstRstMsgList;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstAddResetObj;
    ULONG ulRet = ERROR_SUCCESS;

    /* 如果老化队列中没有会话则不用添加 */
    if (NULL == SL_Next(&pstVcpuData->stUnstableList.stFakeObject.stNode))
    {
        return;
    }

    pstAddResetObj = pstResetObj->pfMalloc(pstResetObj);
    if (NULL == pstAddResetObj)
    {
        return;
    }

    pstAddResetObj->uiResetTime = (UINT)time(NULL);

    pstRstMsgList = &(pstVcpuData->stResetMsgList.stList);
    if (SL_IsEmpty(pstRstMsgList))
    {
        SL_AddHead(pstRstMsgList, &(pstAddResetObj->stNode));
    }
    else
    {
        ulRet = _agingqueue_UnStable_AddResetObjList(pstRstMsgList, pstAddResetObj);
    }

    if (ERROR_SUCCESS == ulRet)
    {
        pstVcpuData->ulResetMsgNum++;
    }
    else
    {
        pstResetObj->pfFree(pstAddResetObj);
    }

    return;
}

/******************************************************************
   Func Name:_agingqueue_UnStable_AddResetObj2
Date Created:2021/04/25
      Author:wangxiaohua
 Description:添加reset消息节点
       INPUT:IN VOID * pRstMsgParam
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID _agingqueue_UnStable_AddResetObj2(IN VOID * pRstMsgParam)
{
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData;
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstTemp; 
    AGINGQUEUE_UNSTABLE_S *pstQueue;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj;
    AGINGQUEUE_ADD_RST_MSG_PARAM_S *pstRstMsgParam;

    pstRstMsgParam = (AGINGQUEUE_ADD_RST_MSG_PARAM_S *)pRstMsgParam;

    pstQueue = pstRstMsgParam->pstQueue;
    pstResetObj = pstRstMsgParam->pstResetObj;

    pstTemp = (AGINGQUEUE_UNSTABLE_VCPU_DATA_S *)pstQueue->pstVcpuData;

    pstVcpuData = &(pstTemp[index_from_lcore_id()]);

    _agingqueue_UnStable_AddResetObj(pstVcpuData, pstResetObj);

    return;
}

/******************************************************************
   Func Name:AGINGQUEUE_UnStable_AddResetObj
Date Created:2021/04/25
      Author:wangxiaohua
 Description:给外部模块提供的添加reset消息节点函数
       INPUT:IN AGINGQUEUE_UNSTABLE_S *pstQueue
             IN AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID AGINGQUEUE_UnStable_AddResetObj(IN AGINGQUEUE_UNSTABLE_S *pstQueue,
                                     IN AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj)
{
    AGINGQUEUE_ADD_RST_MSG_PARAM_S stRstMsgParam;

    stRstMsgParam.pstQueue = pstQueue;
    stRstMsgParam.pstResetObj = pstResetObj;

    local_bh_disable();
    _agingqueue_UnStable_AddResetObj2(&stRstMsgParam);
    local_bh_enable();

    //forcompile (VOID)SMP_CALL_FUNCTION_NO_RETRY(_agingqueue_UnStable_AddResetObj2, (VOID *)&stRstMsgParam, 1);

    return;
}


