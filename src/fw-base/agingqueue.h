#ifndef _AGINGQUEUE_H_
#define _AGINGQUEUE_H_


#include <rte_timer.h>
#include "extlist.h"

/* ��Ʒ���ƻỰ��������� */
typedef struct tagSESSIONAgingqueConf
{
    UINT uiMaxCheckNum;
    UINT uiMaxDeleteNum;
    ULONG ulExpireTime;    /* ��λΪcycles */
}SESSION_AGINGQUE_CONF_S;

typedef struct tagAgingQueueUnstableObject AGINGQUEUE_UNSTABLE_OBJECT_S;

typedef struct tagAgingQueueUnstableClass
{
    ULONG ulTimeout;  /* ��λΪcycles */
    BOOL_T (*pfIsTimeout)(AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject);
    VOID (*pfDelete)(AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject);
}AGINGQUEUE_UNSTABLE_CLASS_S;

struct tagAgingQueueUnstableObject
{
    SL_NODE_S stNode;
    ULONG     ulRcuReserve;/*��Ϊ�Ự�и�ָ��ͬRCU�ص��������ã���˱������ӱ���λ*/
    AGINGQUEUE_UNSTABLE_CLASS_S *pstClass;
};

typedef struct tagAgingQueueUnStableList
{
    SL_HEAD_S stList;
    AGINGQUEUE_UNSTABLE_OBJECT_S stFakeObject;
}AGINGQUEUE_UNSTABLE_LIST_S;

typedef enum AGINGQUEUE_Reset_Type
{
    AGINGQUE_RESET_TYPE_DEFAULT,
    AGINGQUE_RESET_SESSION_BY_TABLEKEY,  /* sessionģ�����ͨ���Ự����keyɾ���Ự��reset�ڵ� */
    AGINGQUE_RESET_TYPE_MAX,
}AGINGQUEUE_RESET_TYPE_E;

typedef struct tagAgingQueueResetMsgObject AGINGQUEUE_RST_MSG_OBJECT_S;

struct tagAgingQueueResetMsgObject
{
    SL_NODE_S stNode;
    UINT uiResetTime;            /* reset��Ϣ�·�ʱ��� */
    UINT uiMDCLocalIndex; 
    BOOL_T bNeedAdjCurson;       /* ��һ����Ϣ������ñ�� */
    AGINGQUEUE_RESET_TYPE_E enRetsetType;
    AGINGQUEUE_RST_MSG_OBJECT_S * (*pfMalloc)(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject);
    VOID (*pfFree)(IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject);
    BOOL_T (*pfIsSameMsg)(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject1,
                          IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject2);
    BOOL_T (*pfNeedResetProc)(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
                              IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject);
};

typedef struct tagAgingQueueResetMsgList
{
    SL_HEAD_S stList;
}AGINGQUEUE_RST_MSG_LIST_S;

typedef struct tagAgingQueueUnStableCurson
{
    SL_NODE_S *pstUnstableCursor;     /* �α꣬����һ�ڵ�Ϊ������ڵ� */
}AGINGQUEUE_UNSTABLE_CURSON_S;

#define AGINGQUEUE_USTABLE_STATUS_NORMAL    0
#define AGINGQUEUE_USTABLE_STATUS_DELETING  1
#define AGINGQUEUE_USTABLE_STATUS_DESTROIED 2


typedef struct tagAgingQueueUnStableVcpuData
{
    UINT uiInterval;
    BOOL_T bTimerActiveFlag;
    USHORT usModuleId;
    struct rte_timer stTimer;
    AGINGQUEUE_RST_MSG_LIST_S stResetMsgList;
    AGINGQUEUE_UNSTABLE_LIST_S stUnstableList;
    AGINGQUEUE_UNSTABLE_CURSON_S stUnstableCurson;
    ULONG ulUnstableNumber;
    ULONG ulResetMsgNum;
    UINT uiMaxCheckNum;
    UINT uiMaxDeleteNum;
    rte_spinlock_t stLock;
}AGINGQUEUE_UNSTABLE_VCPU_DATA_S;

typedef struct tagAgingQueueUnstable
{
    UINT uiCpuID;
    BOOL_T bTimerActiveFlag;
    USHORT usModuleId;
    AGINGQUEUE_UNSTABLE_VCPU_DATA_S *pstVcpuData;
    struct rte_timer stTimer; /* ��ʱû���ã� */
    rte_atomic32_t stCount;
    UINT uiMdcNumber;
    UINT uiMaxCheckNum;
    UINT uiMaxDeleteNum;
    UINT uiInterval;  /* ��λ�Ǻ��� */
}AGINGQUEUE_UNSTABLE_S;


/*���ȶ������л��ϻ���*/
static inline VOID AGINGQUEUE_UnStable_Switch(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject,
                                              IN AGINGQUEUE_UNSTABLE_CLASS_S *pstClass)
{
    pstObject->pstClass = pstClass;

    return;
}

/******************************************************************
   Func Name:AGINGQUEUE_Unstable_IsTimeout
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�жϲ��ȶ������Ƿ���ϻ���Ĭ�Ϻ���
       INPUT:AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject
      Output:��
      Return:BOOL_TRUE  ��Ҫ�ϻ�
             BOOL_FALSE ����Ҫ�ϻ�
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T AGINGQUEUE_Unstable_IsTimeout(IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject,
                                                   IN ULONG ulUpdateTime)
{
    LONG lTemp;
    lTemp = (LONG)ulUpdateTime + (LONG)pstObject->pstClass->ulTimeout;
    if ((lTemp - (LONG)rte_get_timer_cycles()) <= 0)
    {
        return BOOL_TRUE;
    }
    else
    {
        return BOOL_FALSE;
    }
}

VOID AGINGQUEUE_UnStable_Add(IN AGINGQUEUE_UNSTABLE_S *pstQueue,
                             IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject);
ULONG AGINGQUEUE_UnStable_Create(INOUT AGINGQUEUE_UNSTABLE_S *pstQueue);
ULONG AGINGQUEUE_UnStable_MDCInit(IN const AGINGQUEUE_UNSTABLE_S *pstQueue);

#endif
