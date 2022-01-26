
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <ctype.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>


#include "session.h"
#include "ac.h"
#include "session_kcore.h"
#include "session_kalg.h"
#include "session_kalg_ftp.h"
#include "session_kdebug.h"
#include "session_khash.h"
#include "session_krelationhash.h"
#include "session6_krelationhash.h"
#include "session_kutil.h"
#include "session_krelation.h"
#include "apr.h"
#include "general_rcu.h"


extern AGINGQUEUE_UNSTABLE_S g_stSessionstRelationQueue;

struct rte_mempool *g_apstRelationPool;

struct rte_mempool *g_apstRelation6Pool;



STATIC AGINGQUEUE_UNSTABLE_CLASS_S g_astRelationClass[RELATION_AGING_TYPE_MAX];
STATIC AGINGQUEUE_UNSTABLE_CLASS_S g_astRelation6Class[RELATION_AGING_TYPE_MAX];



#define RELATION_MAX_KEEP_NORMAL (1*1024)
#define RELATION_MEMPOOL_SIZE_NORMAL    ((worker_thread_total()*(RELATION_MAX_KEEP_NORMAL+RTE_MEMPOOL_CACHE_MAX_SIZE))-1)
#define RELATION_MEMPOOL_ELT_SIZE    sizeof(RELATION_S)
#define RELATION6_MEMPOOL_ELT_SIZE    sizeof(RELATION6_S)



#define RELATION_AGING_TIME_DEFAULT  600  /* ������Ĭ���ϻ�ʱ�� */
#define RELATION_AGING_TIME_FTPDATA  600  /* FTP������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_H245     600  /* h225������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_RTPRTCP  600  /* h245������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_T120     600  /* h245������������ϻ�ʱ�� */
//#define RELATION_AGING_TIME_ILS      3600 /* ILS������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_NBT      600  /* NBT������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_SCCP     600  /* SCCP������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_SQLNET   600  /* SQLNET������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_XDMCP    600  /* SCCP������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_MGCP     600  /* SCCp������������ϻ�ʱ�� */
#define RELATION_AGING_TIME_SDP      3600 /* SDP������������ϻ�ʱ�� */

/* ����Ƿ�ﵽ������ֵ 
static inline ULONG SESSION_Relation_Specification(VOID)
{
	ULONG ulErrCode = ERROR_SUCCESS;

	if(0 == atomic_add_unless(&g_stRelationCount, 1, (INT)g_uiRelationSpecificationValue))
	{
		ulErrCode = ERROR_FAILED;
	}

	return ulErrCode;
}*/

/* �����������ȫ��ͳ�Ƽ�һ
static inline VOID SESSION_RelationCountDec(VOID)
{
	(VOID)atomic_add_unless(&g_stRelationCount, -1, 0);
} */



/******************************************************************
   Func Name:RELATION_KFreeResetObject
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ͷ�reset session�ڵ��ڴ�
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID RELATION_KFreeResetObject(IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj;

    pstSessionRstObj = container_of(pstObject, SESSION_RESET_OBJ_S, stRstObj);
    rte_free(pstSessionRstObj);
    return;
}

/******************************************************************
   Func Name:RELATION_KMallocResetObject
Date Created:2021/04/25
      Author:wangxiaohua
 Description:����reset session�ڵ��ڴ�
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
AGINGQUEUE_RST_MSG_OBJECT_S * RELATION_KMallocResetObject(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj;
    SESSION_RESET_OBJ_S *pstSessionRstObjTmp;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstObjectTmp;

    pstSessionRstObj = container_of(pstObject, SESSION_RESET_OBJ_S, stRstObj);
    pstSessionRstObjTmp = rte_zmalloc(NULL, sizeof(SESSION_RESET_OBJ_S), 0);
    if(NULL != pstSessionRstObjTmp)
    {
        *pstSessionRstObjTmp = *pstSessionRstObj;

        pstObjectTmp = &(pstSessionRstObjTmp->stRstObj);
        SL_NodeInit(&(pstObjectTmp->stNode));
    }
    return (AGINGQUEUE_RST_MSG_OBJECT_S *)pstSessionRstObjTmp;
}

/******************************************************************
   Func Name:IN6ADDR_Cmp
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�Ƚ�IPv6��ַ��С
       INPUT:pstAddr1:���Ƚϵ�ַ1
             pstAddr2:���Ƚϵ�ַ2
      Output:��
      Return:����0:��ַ1���ڵ�ַ2
             С��0:��ַ1С�ڵ�ַ2
             ����0:��ַ1���ڵ�ַ2
     Caution:IPV6��ַ������������
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline INT IN6ADDR_Cmp(IN const struct in6_addr *pstAddr1, IN const struct in6_addr *pstAddr2)
{
    UINT i;
    INT iRet;

    for(i=0; i < INET_ADDRSTRLEN; i++)
    {
        iRet = pstAddr1->s6_addr[i] - pstAddr2->s6_addr[i];
        if(0 != iRet)
        {
            break;
        }
    }

    return iRet;
}

/******************************************************************
   Func Name:_relation_KIsSameSessionKey
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�жϻỰ��Ԫ���Ƿ���ͬ
       INPUT:IN const SESSION_TUPLE_S *pstTupel1,
             IN const SESSION_TUPLE_S *pstTupel2
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T _relation_KIsSameSessionKey(IN const SESSION_TUPLE_S *pstTupel1,
                                                 IN const SESSION_TUPLE_S *pstTupel2)
{
    BOOL_T bRet = BOOL_FALSE;

    if(pstTupel1->ucL3Family == pstTupel2->ucL3Family)
    {
		if(AF_INET == pstTupel1->ucL3Family)
        {
            if((pstTupel1->unL3Src.uiIp == pstTupel2->unL3Src.uiIp) &&
               (pstTupel1->unL3Dst.uiIp == pstTupel2->unL3Dst.uiIp))
            {
                bRet = BOOL_TRUE;
            }
        }
        else if (AF_INET6 == pstTupel1->ucL3Family)
        {
            if((0 == IN6ADDR_Cmp(&pstTupel1->unL3Src.stin6, &pstTupel2->unL3Src.stin6)) &&
               (0 == IN6ADDR_Cmp(&pstTupel1->unL3Dst.stin6, &pstTupel2->unL3Dst.stin6)))
            {
                bRet = BOOL_TRUE;
            }
        }
        else if (AF_MAX == pstTupel1->ucL3Family)
        {
            bRet = BOOL_TRUE;
        }
    }
	
    return bRet;
}

/******************************************************************
   Func Name:RELATION_KIsSameResetMsg
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ж�reset session�����Ƿ���ͬ
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
BOOL_T RELATION_KIsSameResetMsg(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject1,
                               IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject2)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj1;
    SESSION_RESET_OBJ_S *pstSessionRstObj2;
    BOOL_T bRet = BOOL_FALSE;

    pstSessionRstObj1 = container_of(pstObject1, SESSION_RESET_OBJ_S, stRstObj);    
    pstSessionRstObj2 = container_of(pstObject2, SESSION_RESET_OBJ_S, stRstObj);

    if(BOOL_TRUE == _relation_KIsSameSessionKey(&pstSessionRstObj1->stKey, &pstSessionRstObj2->stKey))
    {
        bRet = BOOL_TRUE;
    }

    return bRet;
}

/******************************************************************
   Func Name:_relation_KTable_ResetCheckSrcDes
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�������ԴĿ��IP�˿ڼ��
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN const csp_key_t *pstcspkey,             ��ת����Ϣkey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _relation_KTable_ResetCheckSrcDes(IN const SESSION_TABLE_KEY_S *pstKey,
                                                IN const csp_key_t *pstcspkey,
                                                IN UINT uiMask)
{	
    /* Դ��ַ��� */
    if(SESSION_KEY_IS_SRCIPSET(uiMask))
    {		
        if(pstcspkey->src_ip != pstKey->stTuple.unL3Src.uiIp)
        {
            return BOOL_FALSE;
        }
    }
	
    /* Ŀ�ĵ�ַ��� */
    if(SESSION_KEY_IS_DSTIPSET(uiMask))
    {		
        if(pstcspkey->dst_ip != pstKey->stTuple.unL3Dst.uiIp)
        {			
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_relation6_KTable_ResetCheckSrcDes
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�������ԴĿ��IP�˿ڼ��
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN const csp_key_t           *pstcspkey,   ��ת����Ϣkey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _relation6_KTable_ResetCheckSrcDes(IN const SESSION_TABLE_KEY_S *pstKey,
                                                IN const csp_key_t *pstcspkey,
                                                IN UINT uiMask)
{	
    /* Դ��ַ��� */
    if(SESSION_KEY_IS_SRCIPSET(uiMask))
    {		
        if(0 != memcmp(&pstcspkey->src_ip, &pstKey->stTuple.unL3Src.stin6, sizeof(struct in6_addr)))
        {
            return BOOL_FALSE;
        }
    }

    /* Ŀ�ĵ�ַ��� */
    if(SESSION_KEY_IS_DSTIPSET(uiMask))
    {		
        if(0 != memcmp(&pstcspkey->dst_ip, &pstKey->stTuple.unL3Dst.stin6, sizeof(struct in6_addr)))
        {			
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

STATIC BOOL_T _relation_KTable_ResetCmp(IN RELATION_S *pstRelation,
                                        IN const SESSION_TABLE_KEY_S *pstKey)
{
    UINT uiMask = pstKey->uiMask;
	csp_key_t *pstcspkey;
    BOOL_T bflag;
	
	pstcspkey = &(pstRelation->stTupleHash.stIpfsKey);

    /* �����ǵ��� */
    if(IN_MULTICAST(ntohl(pstcspkey->dst_ip)))
    {
        return BOOL_FALSE;
    }

    bflag = _relation_KTable_ResetCheckSrcDes(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    return BOOL_TRUE;
}

STATIC BOOL_T _relation6_KTable_ResetCmp(IN RELATION_S *pstRelation,
                                         IN const SESSION_TABLE_KEY_S *pstKey)
{
    UINT uiMask = pstKey->uiMask;
    csp_key_t *pstcspkey;
    BOOL_T bflag;
	
	pstcspkey = &(pstRelation->stTupleHash.stIpfsKey);

    /* �����ǵ��� */
    if(IN6ADDR_IsMulticast((struct in6_addr *)&pstcspkey->dst_ip))
    {
        return BOOL_FALSE;
    }

    bflag = _relation6_KTable_ResetCheckSrcDes(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session_KNeedResetProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�жϻỰ�Ƿ��reset
       INPUT:IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
             IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
BOOL_T _relation_KNeedResetProc(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
                                IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject)
{
    SESSION_TABLE_KEY_S *pstKey;
	RELATION_S *pstRelation;
    SESSION_RESET_OBJ_S *pstSessionRstObj;
    BOOL_T bRet = BOOL_FALSE;

    pstSessionRstObj = container_of(pstResetObj, SESSION_RESET_OBJ_S, stRstObj);
    pstKey = (SESSION_TABLE_KEY_S *)&pstSessionRstObj->stKey;

	pstRelation = container_of(pstAgingObject, RELATION_S, unAgingObj.stUnstableAgingInfo);


    if (AF_MAX == pstKey->stTuple.ucL3Family)
    {
        bRet = BOOL_TRUE;
    }
    else if(AF_INET == pstKey->stTuple.ucL3Family)
    {
		if(!RELATION_IS_IPV6(pstRelation))
		{
            bRet = _relation_KTable_ResetCmp(pstRelation, pstKey);
		}
    }
    else
    {        
		if(RELATION_IS_IPV6(pstRelation))
        {
            bRet = _relation6_KTable_ResetCmp(pstRelation, pstKey);
        }
        
    }

    return bRet;
}

VOID RELATION_KReset(IN const SESSION_TABLE_KEY_S *pstKey)
{
    SESSION_RESET_OBJ_S stSessionRstObj;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstRstObj;

    memset(&stSessionRstObj, 0, sizeof(SESSION_RESET_OBJ_S));
    stSessionRstObj.stKey = *pstKey;

    pstRstObj = &(stSessionRstObj.stRstObj);
    pstRstObj->bNeedAdjCurson = BOOL_TRUE;
    pstRstObj->enRetsetType = AGINGQUE_RESET_TYPE_DEFAULT;
    SL_NodeInit(&(pstRstObj->stNode));
    pstRstObj->pfFree = RELATION_KFreeResetObject;
    pstRstObj->pfMalloc = RELATION_KMallocResetObject;
    pstRstObj->pfIsSameMsg = RELATION_KIsSameResetMsg;
    pstRstObj->pfNeedResetProc = _relation_KNeedResetProc;

    AGINGQUEUE_UnStable_AddResetObj(&(g_stSessionstRelationQueue), pstRstObj);
    return;
}


STATIC VOID RELATION_KAging_SetClass(IN SESSION_CTRL_S *pstSessionCtrl,
                              IN RELATION_S *pstRelation,
                              IN RELATION_AGING_TYPE_E enAgingType)
{
	switch(enAgingType)
	{
		case RELATION_AGING_TYPE_RAS:
	    case RELATION_AGING_TYPE_RAS_H225:
		case RELATION_AGING_TYPE_SIP:
		case RELATION_AGING_TYPE_ILS:
		{
			/*
			pstRelation->stChangeable.bTimerDone = BOOL_TRUE;
			pstRelation->stChangeable.pstClass = &pstSessionCtrl->stIpv4RelationChangeClass;
			RELATION_SET_CHANGABLEAGING(pstRelation);
			*/
			break;
		}
		case RELATION_AGING_TYPE_RTSP:
		{
			RELATION_SET_SELFAGED(pstRelation);
			pstRelation->stUnstable.pstClass = &g_astRelationClass[enAgingType];
			break;
		}
		default:
		{
			pstRelation->stUnstable.pstClass = &g_astRelationClass[enAgingType];
			break;
		}
	}

	return;
}

STATIC BOOL_T _relation_KAging_IsTimeout(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
	RELATION_S *pstRelation;

	pstRelation = container_of(pstObject, RELATION_S, stUnstable);

	if(RELATION_IS_DELETING(pstRelation))
	{
		return BOOL_TRUE;
	}

	/* �����������ĸ��Ự����������Persist��ǣ����游�Ự�ϻ��������ϻ�ʱ��Ӱ�� �ҷ��Լ��ϻ� */
	if((BOOL_TRUE == pstRelation->bCareParentFlag) && RELATION_IS_PERSIST(pstRelation)
	   && !RELATION_IS_SELFAGED(pstRelation))
	{
		return BOOL_FALSE;
	}
    
    return AGINGQUEUE_Unstable_IsTimeout(pstObject, pstRelation->uiUpdateTime);
}

/* �ͷŹ������ڴ棬�ṩ��RCU�Ļص����� 
VOID SESSION_Relation_Destroy(IN RCU_REG_S *pstRcu)
{
	RELATION_S *pstRelation;

	pstRelation = container_of(pstRcu, RELATION_S, stRcu);

	kmem_cache_free(g_pstRelationCache, pstRelation);

	return;
}*/

VOID SESSION_Relation_Destroy(IN VOID *pRelation)
{
	RELATION_S *pstRelation = (RELATION_S *)pRelation;
	
	rte_mempool_put(g_apstRelationPool, pstRelation);

	return;
}


/* ������ɾ������ */
STATIC VOID SESSION_Relation_Delete(IN RELATION_S *pstRelation)
{
	SESSION_CTRL_S *pstSessionCtrl;
	SESSION_S *pstSession;
	SESSION_S *pstSessionCheck;

	/* ������ժHASH */
	SESSION_RelationHash_Delete(pstRelation);

	/* ������ӻỰ����ժ�� */
	/*pstSession = RCU_DeRef(pstRelation->pstParent);*/	
	pstSession = pstRelation->pstParent;
    if(NULL != pstSession)
    {
		/*
		if(RELATION_IS_TABLEFLAG(pstRelation, RELATION_FLAG_VRRPBACKUPED))
		{
			RELATION_BAK_VrrpSendDelete(pstSession, pstRelation);
		}
		*/

		rte_spinlock_lock(&pstSession->stLock);
        /* �Ự���ϻ�ɾ�����������ܲ�����������������֮����Ҫ���»�ȡ�Ự��
		   ����Ựָ�뱻��գ�˵���Ự����ɾ�������ﲻ��Ҫ�ٴ�ժHASH�� */

		/*pstSessionCheck = RCU_Deref(pstRelation->pstParent);*/		
		pstSessionCheck = pstRelation->pstParent;
		if(NULL != pstSessionCheck)
		{
			DL_Del(&pstRelation->stNodeInSession);

			if(BOOL_TRUE != pstRelation->bCareParentFlag)
			{
				SESSION_KPut((SESSION_S *)(pstRelation->pstParent));
				pstRelation->pstParent = NULL;
			}
		}
		rte_spinlock_unlock(&pstSession->stLock);
    }

	/*SESSION_KNotify_RelationDelete((RELATION_HANDLE)pstRelation);*/

	/* ͳ�� */
    pstSessionCtrl = SESSION_CtrlData_Get();
	if(NULL != pstSessionCtrl)
	{
		rte_atomic32_dec(&pstSessionCtrl->stSessStat.stTotalRelationNum);
		/*SESSION_RelationCountDec();*/
	}

    /*
	pstRelation->stRcu.pfCallback = SESSION_Relation_Destroy;
    RCU_CALL(&pstRelation->stRcu);
    */
	
	general_rcu_qsbr_dq_enqueue((void *)pstRelation, SESSION_Relation_Destroy);

	return;	
}

STATIC VOID _relation_KAging_Delete(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
	RELATION_S *pstRelation;

	pstRelation = container_of(pstObject, RELATION_S, stUnstable);

	SESSION_Relation_Delete(pstRelation);

	SESSION_DBG_RELATION_EVENT_SWITCH(pstRelation, EVENT_DELETE, DBG_REASON_TIMEOUT);

	return;
}

/* �������ϻ������ʼ�� */
VOID RELATION_KAging_Init (VOID)
{
	ULONG ulIndex;
	AGINGQUEUE_UNSTABLE_CLASS_S *pstClass;

	memset(g_astRelationClass, 0, sizeof(g_astRelationClass));
	for (ulIndex = 0; ulIndex < RELATION_AGING_TYPE_MAX; ulIndex++)
	{
		pstClass = &g_astRelationClass[ulIndex];
		pstClass->pfDelete    = _relation_KAging_Delete;
		pstClass->pfIsTimeout = _relation_KAging_IsTimeout;
		pstClass->ulTimeout   = 0;
	}

	g_astRelationClass[RELATION_AGING_TYPE_FTPDATA].ulTimeout = RELATION_AGING_TIME_FTPDATA * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_H245].ulTimeout    = RELATION_AGING_TIME_H245 * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_RTPRTCP].ulTimeout = RELATION_AGING_TIME_RTPRTCP * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_T120].ulTimeout    = RELATION_AGING_TIME_T120 * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_SIP].ulTimeout     = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_TFTP].ulTimeout    = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_RTSP].ulTimeout    = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_PPTP].ulTimeout    = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_NBT].ulTimeout     = RELATION_AGING_TIME_NBT * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_SCCP].ulTimeout    = RELATION_AGING_TIME_SCCP * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_SQLNET].ulTimeout  = RELATION_AGING_TIME_SQLNET * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_XDMCP].ulTimeout   = RELATION_AGING_TIME_XDMCP * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_MGCP].ulTimeout    = RELATION_AGING_TIME_MGCP * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_SDP].ulTimeout     = RELATION_AGING_TIME_SDP * rte_get_timer_hz();
	g_astRelationClass[RELATION_AGING_TYPE_RSH].ulTimeout     = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();	

	return;
}

/* �������hash */
STATIC ULONG RELATION_Add2Hash(IN RELATION_S *pstRelation)
{
	ULONG ulRet;
    SESSION_CTRL_S *pstSessionCtrl;
	
    pstSessionCtrl = SESSION_CtrlData_Get();

	/* ��global hash */
	ulRet = SESSION_RelationHash_Add(pstRelation);
	if(ERROR_SUCCESS != ulRet)
	{
		SESSION_DBG_RELATION_EVENT_SWITCH(pstRelation, EVENT_ADD, DBG_REASON_ADD_GLOBAL);
	    SESSION_KStatFailInc(SESSION_STAT_FAIL_RELATION_GLOBAL_HASH, pstSessionCtrl);
	}

	return ulRet;
}

/* ���ӹ�����������ͳ�� */
static inline VOID SESSION_KRelateTableAddStat(IN SESSION_CTRL_S *pstSessionCtrl)
{
	SESSION_K_STATISTICS_S *pstStat;
	SESSION_STAT_VCPU_S *pstVcpuStat;
	UINT uiCpuIndex;

	pstStat = &(pstSessionCtrl->stSessStat);

	/* ���ӻỰ�½�����ͳ�� */
    uiCpuIndex = index_from_lcore_id();
	pstVcpuStat = SESSION_GET_PERCPU_PTR(pstStat->pstVcpuStat, uiCpuIndex);
	SESSION_KUpdateRateStat(&pstVcpuStat->stRelateTableRateStat);
	pstVcpuStat->stRelateTableRateStat.uiCurrCount++;

	return;
}

static inline VOID RELATION_KAging_Add(IN RELATION_S *pstRelation,
                                       IN RELATION_AGING_TYPE_E enAgingType)
{
	pstRelation->uiUpdateTime = rte_get_timer_cycles();

	switch (enAgingType)
    {
		case RELATION_AGING_TYPE_RAS:
		case RELATION_AGING_TYPE_RAS_H225:
	    case RELATION_AGING_TYPE_SIP:
		case RELATION_AGING_TYPE_ILS:
	    {
			/*SESSION_KChangeableQueue_Add(&(pstRelation->stChangeable));*/
			break;
		}
		default:
		{
			AGINGQUEUE_UnStable_Add(&(g_stSessionstRelationQueue), &pstRelation->stUnstable);
			break;
		}
	}

	return;
}

ULONG SESSION_Relation_Add(IN RELATION_S *pstRelation,
                           IN SESSION_S *pstParentSess,
                           IN RELATION_AGING_TYPE_E enAgingType)
{
	ULONG ulRet = ERROR_FAILED;
	SESSION_CTRL_S *pstSessionCtrl;
	SESSION_K_STATISTICS_S *pstStat;
 
    pstSessionCtrl = SESSION_CtrlData_Get();

	rte_spinlock_lock(&pstParentSess->stLock);
    pstRelation->uiAgingType = (UINT)enAgingType;

	if(!SESSION_TABLE_IS_TABLEFLAG(&pstParentSess->stSessionBase, SESSION_DELETING))
	{
		/* �����������ϻ��� */
	    RELATION_KAging_SetClass(pstSessionCtrl, pstRelation, enAgingType);

		/* �������HASH */
		ulRet = RELATION_Add2Hash(pstRelation);
		if(ERROR_SUCCESS == ulRet)
		{
			/* �������¼�ڸ��Ự�� */
		    /*DL_AddAfterPtr_Rcu(&(pstParentSess->stRelationList.pstFirst), &pstRelation->stNodeInSession);*/			
			DL_AddAfterPtr(&(pstParentSess->stRelationList.pstFirst), &pstRelation->stNodeInSession);
		}
	}
	
	rte_spinlock_unlock(&pstParentSess->stLock);

	if(ERROR_SUCCESS == ulRet)
	{
		pstStat = &(pstSessionCtrl->stSessStat);
		rte_atomic32_inc(&(pstStat->stTotalRelationNum));
        /* ͳ�ƹ����������� */
		SESSION_KRelateTableAddStat(pstSessionCtrl);
		RELATION_KAging_Add(pstRelation, enAgingType);

        /* ����������Ҫ֪ͨ��Щģ��?
		SESSION_KNotify_RelationCreate((RELATION_HANDLE)pstRelation);*/

		SESSION_DBG_RELATION_EVENT_SWITCH(pstRelation, EVENT_CREATE, DBG_REASON_MODCALL);
	}

	return ulRet;
}


/* �Ự�������һ�׶γ�ʼ������ */
ULONG SESSION_KRelation_Run(VOID)
{
    ULONG ulErrCode = ERROR_SUCCESS;


    /* ��ʼ���Ự��mempool */
	/* create a mempool (with cache) for normal session */
	g_apstRelationPool = rte_mempool_create("session_relation_table", 
	                                         RELATION_MEMPOOL_SIZE_NORMAL,
	                                         RELATION_MEMPOOL_ELT_SIZE,
		                                     RTE_MEMPOOL_CACHE_MAX_SIZE,
                                             0,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             SOCKET_ID_ANY, 
                                             0);

    if(NULL == g_apstRelationPool)
    {
		ulErrCode = ERROR_FAILED;
    }

    return ulErrCode;
}

/* ������������ */
RELATION_S *SESSION_Relation_Create(VOID)
{
	RELATION_S *pstRelation = NULL;

	if(0 == rte_mempool_get(g_apstRelationPool, (VOID **)&pstRelation))
	{
		memset(pstRelation, 0, sizeof(RELATION_S));
	}

	return pstRelation;
}

VOID SESSION6_Relation_Destroy(IN VOID *pRelation)
{
	RELATION6_S *pstRelation = (RELATION6_S *)pRelation;
	
	rte_mempool_put(g_apstRelation6Pool, pstRelation);

	return;
}

/* ������ɾ������ */
STATIC VOID SESSION6_Relation_Delete(IN RELATION6_S *pstRelation)
{
	SESSION_CTRL_S *pstSessionCtrl;
	SESSION_S *pstSession;
	SESSION_S *pstSessionCheck;

	/* ������ժHASH */
	SESSION6_RelationHash_Delete(pstRelation);

	/* ������ӻỰ����ժ�� */
	/*pstSession = RCU_DeRef(pstRelation->pstParent);*/
	pstSession = pstRelation->pstParent;
    if(NULL != pstSession)
    {
		/*
		if(RELATION_IS_TABLEFLAG(pstRelation, RELATION_FLAG_VRRPBACKUPED))
		{
			RELATION6_VRRPBAK_SendDelete(pstSession, pstRelation);
		}
		*/

		rte_spinlock_lock(&pstSession->stLock);
        /* �Ự���ϻ�ɾ�����������ܲ�����������������֮����Ҫ���»�ȡ�Ự��
		   ����Ựָ�뱻��գ�˵���Ự����ɾ�������ﲻ��Ҫ�ٴ�ժHASH�� */

		pstSessionCheck = RCU_Deref(pstRelation->pstParent);
		if(NULL != pstSessionCheck)
		{
			DL_Del(&pstRelation->stNodeInSession);

			if(BOOL_TRUE != pstRelation->bCareParentFlag)
			{
				SESSION6_KPut((SESSION_S *)(pstRelation->pstParent));
				pstRelation->pstParent = NULL;
			}
		}
		rte_spinlock_unlock(&pstSession->stLock);	
    }

	/*SESSION_KNotify_RelationDelete((RELATION_HANDLE)pstRelation);*/

	/* ͳ�� */
	pstSessionCtrl = SESSION_CtrlData_Get();
	if(NULL != pstSessionCtrl)
	{
		rte_atomic32_dec(&pstSessionCtrl->stSessStat.stTotalRelationNum);
		/*SESSION_RelationCountDec();*/
	}
	
    /*
	pstRelation->stRcu.pfCallback = SESSION6_Relation_Destroy;
    RCU_CALL(&pstRelation->stRcu);
    */	
	general_rcu_qsbr_dq_enqueue((void *)pstRelation, SESSION6_Relation_Destroy);

	return;	
}


/***********************************************************************
  �ϻ��ڵ㴥��ɾ������
***********************************************************************/
STATIC VOID _relation6_KAging_Delete(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
	RELATION6_S *pstRelation;

	pstRelation = container_of(pstObject, RELATION6_S, stUnstable);

	SESSION6_Relation_Delete(pstRelation);

	SESSION6_DBG_RELATION_EVENT_SWITCH(pstRelation, EVENT_DELETE, DBG_REASON_TIMEOUT);

	return; 
}


/***********************************************************************
  �������ϻ��жϺ���
***********************************************************************/
STATIC BOOL_T _relation6_KAging_IsTimeout(IN AGINGQUEUE_UNSTABLE_OBJECT_S *pstObject)
{
	RELATION6_S *pstRelation;

	pstRelation = container_of(pstObject, RELATION6_S,stUnstable);

	if (RELATION_IS_DELETING(pstRelation))
	{
		return BOOL_TRUE;
	}

	/* �����������ĸ��Ự����������Persist��ǣ����游�Ự�ϻ��������ϻ�ʱ��Ӱ�� */
	if ((BOOL_TRUE == pstRelation->bCareParentFlag) && RELATION_IS_PERSIST(pstRelation)
	    && !RELATION_IS_SELFAGED(pstRelation))
	{
		return BOOL_FALSE;
	}

	return AGINGQUEUE_Unstable_IsTimeout(pstObject, pstRelation->uiUpdateTime);
}


/* �������ϻ������ʼ�� */
VOID RELATION6_KAging_Init (VOID)
{
	ULONG ulIndex;
	AGINGQUEUE_UNSTABLE_CLASS_S *pstClass;

	memset(g_astRelation6Class, 0, sizeof(g_astRelation6Class));
	for (ulIndex = 0; ulIndex < RELATION_AGING_TYPE_MAX; ulIndex++)
	{
		pstClass = &g_astRelation6Class[ulIndex];
		pstClass->pfDelete    = _relation6_KAging_Delete;
		pstClass->pfIsTimeout = _relation6_KAging_IsTimeout;
		pstClass->ulTimeout   = 0;
	}

	g_astRelation6Class[RELATION_AGING_TYPE_FTPDATA].ulTimeout = RELATION_AGING_TIME_FTPDATA * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_H245].ulTimeout    = RELATION_AGING_TIME_H245 * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_RTPRTCP].ulTimeout = RELATION_AGING_TIME_RTPRTCP * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_T120].ulTimeout    = RELATION_AGING_TIME_T120 * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_SIP].ulTimeout     = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_TFTP].ulTimeout    = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_RTSP].ulTimeout    = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_PPTP].ulTimeout    = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_NBT].ulTimeout     = RELATION_AGING_TIME_NBT * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_SCCP].ulTimeout    = RELATION_AGING_TIME_SCCP * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_SQLNET].ulTimeout  = RELATION_AGING_TIME_SQLNET * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_XDMCP].ulTimeout   = RELATION_AGING_TIME_XDMCP * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_MGCP].ulTimeout    = RELATION_AGING_TIME_MGCP * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_SDP].ulTimeout     = RELATION_AGING_TIME_SDP * rte_get_timer_hz();
	g_astRelation6Class[RELATION_AGING_TYPE_RSH].ulTimeout     = RELATION_AGING_TIME_DEFAULT * rte_get_timer_hz();	

	return;
}

/*************************************************************************
Description�ûỰ������ϻ�ͳһ����
**************************************************************************/
STATIC VOID RELATION6_KAging_SetClass(IN SESSION_CTRL_S *pstSessionCtrl,
                               IN RELATION6_S *pstRelation,
                               IN RELATION_AGING_TYPE_E enAgingType)
{
    switch(enAgingType)
    {
        case RELATION_AGING_TYPE_RAS:
        case RELATION_AGING_TYPE_RAS_H225:
        case RELATION_AGING_TYPE_SIP: 
        case RELATION_AGING_TYPE_ILS:
        { 
			/*
            pstRelation->stChangeable.pstClass = &pstSessionCtrl->stIpv6RelationChangeClass;
            RELATION_SET_CHANGABLEAGING(pstRelation); 
            */
            break;
        }
        case RELATION_AGING_TYPE_RTSP:
        {
			/*
            RELATION_SET_SELFAGED(pstRelation);
            pstRelation->stUnstable.pstClass = &g_astRelation6Class[enAgingType];
            */
            break;
        }
        default:
        {
            pstRelation->stUnstable.pstClass = &g_astRelation6Class[enAgingType]; 
            break;
        }
    }

    return;
}

STATIC ULONG _relation6_Add2Hash(IN RELATION6_S *pstRelation)
{
	ULONG ulRet;

	/* ��global hash */
	ulRet = SESSION6_RelationHash_Add(pstRelation);

	return ulRet;
}

/*
Description�� ����������ϻ�����
*/
static inline VOID RELATION6_KAging_Add(IN RELATION6_S *pstRelation,
									    IN RELATION_AGING_TYPE_E enAgingType)
{
	/* Ŀǰipv6����Ҫ�����������algֻ��ftp��ftp�ǲ���Ҫ
	   changeable�ϻ����е� */
	pstRelation->uiUpdateTime = rte_get_timer_cycles();

	switch(enAgingType)
	{
		case RELATION_AGING_TYPE_RAS:
		case RELATION_AGING_TYPE_RAS_H225:
		case RELATION_AGING_TYPE_SIP:
		case RELATION_AGING_TYPE_ILS:
		{
			/*
			SESSION_KChangeableQueue_Add(&(pstRelation->stChangeable));
			*/
			break;
		}
		default:
		{
			AGINGQUEUE_UnStable_Add(&(g_stSessionstRelationQueue), &pstRelation->stUnstable);
			break;
		}
	}

	return;
}

ULONG SESSION6_Relation_Add(IN RELATION6_S *pstRelation, 
							IN SESSION_S *pstParentSess, 
							IN RELATION_AGING_TYPE_E enAgingType)
{
	ULONG ulRet = ERROR_FAILED;
	SESSION_CTRL_S *pstSessionCtrl;
	SESSION_K_STATISTICS_S *pstStat;

    pstSessionCtrl = SESSION_CtrlData_Get();

	rte_spinlock_lock(&pstParentSess->stLock); 
	pstRelation->uiAgingType = (UINT)enAgingType;

	if (!SESSION_TABLE_IS_TABLEFLAG(&pstParentSess->stSessionBase, SESSION_DELETING))
	{
		/* �����������ϻ��ಢ���ϻ����� */
		RELATION6_KAging_SetClass(pstSessionCtrl, pstRelation, enAgingType);
		/* �������HASH */
		ulRet = _relation6_Add2Hash(pstRelation); 
		if (ERROR_SUCCESS == ulRet)
		{
			/* �������¼�ڸ��Ự�� */
			/*DL_AddAfterPtr_Rcu(&(pstParentSess->stRelationList.pstFirst), &pstRelation->stNodeInSession);*/
			DL_AddAfterPtr(&(pstParentSess->stRelationList.pstFirst), &pstRelation->stNodeInSession);
		}
	}


	if (ERROR_SUCCESS == ulRet)
	{		
		RELATION_SET_IPV6(pstRelation);
		RELATION6_KAging_Add(pstRelation, enAgingType);		
		rte_spinlock_unlock(&pstParentSess->stLock); 
		pstStat = &(pstSessionCtrl->stSessStat);		
		rte_atomic32_inc(&(pstStat->stTotalRelationNum));
		/*SESSION_KNotify_RelationCreate((RELATION_HANDLE)pstRelation);*/
		SESSION6_DBG_RELATION_EVENT_SWITCH(pstRelation, EVENT_CREATE, DBG_REASON_MODCALL);
	}
	else
	{		
		rte_spinlock_unlock(&pstParentSess->stLock); 
	}

	return ulRet;
}

/* �Ự�������һ�׶γ�ʼ������ */
ULONG SESSION6_KRelation_Run(VOID)
{
    ULONG ulErrCode = ERROR_SUCCESS;


    /* ��ʼ���Ự��mempool */
	/* create a mempool (with cache) for normal session */
	g_apstRelation6Pool = rte_mempool_create("session_relation6_table", 
	                                         RELATION_MEMPOOL_SIZE_NORMAL,
	                                         RELATION6_MEMPOOL_ELT_SIZE,
		                                     RTE_MEMPOOL_CACHE_MAX_SIZE,
                                             0,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             SOCKET_ID_ANY, 
                                             0);

    if(NULL == g_apstRelation6Pool)
    {
		ulErrCode = ERROR_FAILED;
    }

    return ulErrCode;
}

/*********************************************************************
Description�� ������������
*********************************************************************/
RELATION6_S *SESSION6_Relation_Create(VOID)
{
	RELATION6_S *pstRelation;
	
	if(0 == rte_mempool_get(g_apstRelation6Pool, (VOID **)&pstRelation))
	{
		memset(pstRelation, 0, sizeof(RELATION6_S));
	}

	return pstRelation;
}

/*****************************************************************
Description���ͷŹ������ڴ棬�ṩ��RCU�Ļص�����
**************************************************************************/
/*
VOID SESSION6_Relation_Destroy(IN RCU_REG_S *pstRcu)
{
	RELATION6_S *pstRelation;

	pstRelation = container_of(pstRcu, RELATION6_S, stRcu);

	kmem_cache_free(g_pstRelation6Cache, pstRelation);

	return;
}
*/

