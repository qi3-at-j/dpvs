#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>

#include "session_kcore.h"
#include "session_khash.h"


#define SESSION_RELATION_LOCALHASH_SIZE         (SESSION_TABLE_HASH_LENGTH / 32)

#define RELATION_HASH5(uiSrcIPM,uiDstIPM,usSrcPortM,usDstPortM,ucPrM,vrfIndexM,usMDCIdM, \
                       uiTunnelIDM, ulHashMaskM, ulHashIndexM) \
{\
    ( ulHashIndexM ) = (((( ULONG )( usSrcPortM))<<3) - ( ULONG )( usSrcPortM )) +\
                    (((( ULONG )( usDstPortM ))<<2) - ( ULONG )( usDstPortM )) +\
                    (((( ULONG )( uiSrcIPM ))<<2) + (uiSrcIPM)) +\
                    (((( ULONG )( uiDstIPM ))<<1) + (vrfIndexM)) + (usMDCIdM) + (uiTunnelIDM);\
    (ulHashIndexM) = (((( ULONG )( ucPrM ) << 2 ) | ( ( ulHashIndexM ) >> 30 ) ) ^ \
                    ( ( ulHashIndexM ) >> 20 ) ^ ( ( ulHashIndexM ) >> 10) ^ \
                    ( ulHashIndexM ) ) & (ulHashMaskM) ;\
}

SESSION_HASH_HANDLE     g_hV4RelationHash3 =  RELATION_INVALID_HANDLE;
SESSION_HASH_HANDLE     g_hV4RelationHash5 =  RELATION_INVALID_HANDLE;
SESSION_HASH_HANDLE     g_hV6RelationHash  =  RELATION_INVALID_HANDLE;
SESSION_HASH_HANDLE     g_hV4RelationLocalHash =  RELATION_INVALID_HANDLE;



/* 初始化HASH表 */ 
ULONG SESSION_KHash_Init(IN SESSION_HASH_HANDLE *phHash, UINT uiBucketNumber)
{
	SESSION_HASH_S *pstHashTable; 
	ULONG ulIndex;

	pstHashTable = rte_malloc(NULL, sizeof(SESSION_HASH_S), 0); 
	if (NULL == pstHashTable)
	{
		return ERROR_FAILED;
	}

	pstHashTable->uiBucketNumber = uiBucketNumber;
	pstHashTable->uiBucketMask = uiBucketNumber - 1;
	for (ulIndex = 0; ulIndex < SESSION_HASH_LOCK_NR; ulIndex++)
	{
		rte_spinlock_init(&(pstHashTable->astHashLock[ulIndex]));
	}

	/* TODO: */
	pstHashTable->pstBuckets = (DL_HEAD_S *)rte_zmalloc(NULL,
	                                                    pstHashTable->uiBucketNumber * sizeof(DL_HEAD_S),
														0);
	if (unlikely(NULL == pstHashTable->pstBuckets))
	{
		rte_free(pstHashTable); 
		return ERROR_FAILED;
	}

	for (ulIndex = 0; ulIndex < pstHashTable->uiBucketNumber; ulIndex++)
	{
		DL_Init(&pstHashTable->pstBuckets[ulIndex]);
	}

	*phHash = (SESSION_HASH_HANDLE)pstHashTable; 

	return ERROR_SUCCESS;
}


/******************************************************************
   Func Name:SESSION_RelationHash_Init(VOID)
Date Created:2021/04/25
      Author:wangxiaohua
 Description:初始化HASH表
       INPUT:
      Output:
      Return:ERROR_SUCCESS 操作成功
             其他错误码
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG SESSION_RelationHash_Init(VOID)
{
    ULONG ulRet = ERROR_SUCCESS;

    ulRet |= SESSION_KHash_Init(&g_hV4RelationHash3, SESSION_RELATION_HASH_LENGTH);    
    ulRet |= SESSION_KHash_Init(&g_hV4RelationHash5, SESSION_RELATION_HASH_LENGTH);
    ulRet |= SESSION_KHash_Init(&g_hV6RelationHash, SESSION_RELATION_HASH_LENGTH);

    return ulRet;
}


/******************************************************************
   Func Name:_relation_Hash_IsTupleMatch
Date Created:2021/04/25
      Author:wangxiaohua
 Description:比较HASH节点是否匹配
       INPUT:csp_key_t *pstTupleFromHash, 快转Key
             csp_key_t *pstNewTuple     快转Key
             UINT uiCmpMashk
      Output:无
      Return:BOOL_TRUE  ---匹配
             BOOL_FALSE ---不匹配
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T _relation_Hash_IsTupleMatch(IN const csp_key_t *pstTupleFromHash,
                                                 IN const csp_key_t *pstNewTuple,
                                                 IN UINT uiCmpMask)
{

    /* 检查协议号是否一致 */
    if(pstTupleFromHash->proto != pstNewTuple->proto)
    {
        return BOOL_FALSE;
    }

    /*检查VRF是否匹配
    if(pstTupleFromHash->vrfIndex != pstNewTuple->vrfIndex)
    {
        return BOOL_FALSE;
    }*/

    /*检查关联表的目的地址与报文目的地址是否一致*/
    if(pstTupleFromHash->dst_ip != pstNewTuple->dst_ip)
    {
        return BOOL_FALSE;
    }

    /*检查关联表的目的端口与报文目的端口是否一致*/
    if(pstTupleFromHash->dst_port != pstNewTuple->dst_port)
    {
        return BOOL_FALSE;
    }
    
    /*检查源地址是否一致*/
    if(RELATION_TUPLEFLAG_IS_IPSET(uiCmpMask))
    {
        if(pstTupleFromHash->src_ip != pstNewTuple->src_ip)
        {
            return BOOL_FALSE;
        }
    }

    /*检查源端口是否一致*/
    if(RELATION_TUPLEFLAG_IS_PORTSET(uiCmpMask))
    {
        if(pstTupleFromHash->src_port != pstNewTuple->src_port)
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}


/******************************************************************
   Func Name:SESSION_Relation_IsTupleMatch
Date Created:2021/04/25
      Author:wangxiaohua
 Description:比较关联表HASH节点是否匹配
       INPUT:IN csp_key_t *pstTupleFromHash
             IN csp_key_t *pstNewTuple
             UINT uiCmpMashk
      Output:
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
BOOL_T SESSION_Relation_IsTupleMatch(IN const csp_key_t *pstTupleFromHash,
                                     IN const csp_key_t *pstNewTuple,
                                     IN UINT uiCmpMask)
{
    return _relation_Hash_IsTupleMatch(pstTupleFromHash, pstNewTuple, uiCmpMask);
}

/* 计算三元组relation HASH索引 */
STATIC inline ULONG _relation_GetHash3(IN const csp_key_t *pstcspkey, IN UINT uiMask)
{
    UINT uiV1;
    UINT uiV2;
    UINT uiV3;

    /* 计算hash值 */
    uiV1 = pstcspkey->dst_ip;

    uiV2 = (UINT)(pstcspkey->dst_port) | ((UINT)(pstcspkey->proto) << 16);

    //uiV3 = (UINT)pstcspkey->vrfIndex ^ pstcspkey->uiTunnelID;

	uiV3 = 0;

    SESSION_HASH_MIX(uiV1, uiV2, uiV3);

    return ( (uiV3 & 0xFFFF) ^ (uiV3 >> 16) ) & uiMask;
}

/* 比较关联表四元组和会话Tuple,匹配则返回关联表指针，否则返回NULL */
STATIC inline RELATION_S* _relation_Hash_CmpRelation(IN const csp_key_t *pstcspkey,
                                                     IN RELATION_TUPLE_HASH_S *pstCurrent)
{
    RELATION_S* pstRelation = NULL;

    if(BOOL_TRUE == _relation_Hash_IsTupleMatch(&pstCurrent->stIpfsKey, pstcspkey, pstCurrent->uiMask))
    {
        pstRelation = container_of(pstCurrent, RELATION_S, stTupleHash);
        if(RELATION_IS_DELETING(pstRelation))
        {
            pstRelation = NULL;
        }
    }

    return pstRelation;
}


/* 在HASH链表中查找节点 */
STATIC inline RELATION_S * _relation_Hash_Find(IN const DL_HEAD_S *pstBucketHead,
                                  IN const csp_key_t *pstcspkey)
{
    RELATION_TUPLE_HASH_S *pstCurrent;
    RELATION_S *pstRelation = NULL;
    DL_NODE_S *pstNode;

    /*DL_FOREACH_RCU(pstBucketHead, pstNode)*/
    DL_FOREACH(pstBucketHead, pstNode)
    {
        pstCurrent = DL_ENTRY(pstNode, RELATION_TUPLE_HASH_S, stNodeInHash);

        pstRelation = _relation_Hash_CmpRelation(pstcspkey, pstCurrent);
        if(NULL != pstRelation)
        {
            break;
        }
    }

    return pstRelation;
}

/* 计算五元组relation HASH索引 */
STATIC inline ULONG _relation_GetHash5(IN const csp_key_t *pstcspkey, IN UINT uiMask)
{
    ULONG ulHashIndex;

    /*
    RELATION_HASH5(pstcspkey->src_ip,
                   pstcspkey->dst_ip,
                   pstcspkey->src_port,
                   pstcspkey->dst_port,
                   pstcspkey->proto,
                   pstcspkey->vrfIndex,
                   pstcspkey->usMDCID,
                   pstcspkey->uiTunnelID,
                   uiMask,
                   ulHashIndex);
    */

    return ulHashIndex;
}

STATIC ULONG _relation_Hash_Add(IN RELATION_TUPLE_HASH_S *pstTupleHash)
{
	SESSION_HASH_S *pstHashTable;
	ULONG ulHashIndex;
	USHORT usLockIndex;
	ULONG ulRet = ERROR_FAILED;

	/* uiMask不为0，使用五元组hash表 */
	if((RELATION_TUPLEFLAG_IS_IPSET(pstTupleHash->uiMask)) &&
	   (RELATION_TUPLEFLAG_IS_PORTSET(pstTupleHash->uiMask)))
	{
		pstHashTable = (SESSION_HASH_S *)g_hV4RelationHash5;
		ulHashIndex = _relation_GetHash5(&pstTupleHash->stIpfsKey, pstHashTable->uiBucketMask);
	}
	else
	{
		pstHashTable = (SESSION_HASH_S *)g_hV4RelationHash3;
		ulHashIndex = _relation_GetHash3(&pstTupleHash->stIpfsKey, pstHashTable->uiBucketMask);
	}

    
	usLockIndex = (USHORT)ulHashIndex & SESSION_HASH_LOCK_MASK;

	pstTupleHash->usLockIndex = usLockIndex;
	
    rte_spinlock_lock(&pstHashTable->astHashLock[usLockIndex]);
    

	if(likely(NULL == _relation_Hash_Find(&pstHashTable->pstBuckets[ulHashIndex], &pstTupleHash->stIpfsKey)))
	{
		/*DL_AddAfterPtr_Rcu(&(pstHashTable->pstBuckets[ulHashIndex].pstFirst), &pstTupleHash->stNodeInHash);*/		
		DL_AddAfterPtr(&(pstHashTable->pstBuckets[ulHashIndex].pstFirst), &pstTupleHash->stNodeInHash);
		ulRet = ERROR_SUCCESS;
	}

	rte_spinlock_unlock(&pstHashTable->astHashLock[usLockIndex]);

	return ulRet;
}

ULONG SESSION_RelationHash_Add(IN RELATION_S *pstRelation)
{
	RELATION_TUPLE_HASH_S *pstTupleHash;
	ULONG ulRet;

	pstTupleHash = &pstRelation->stTupleHash;

	ulRet = _relation_Hash_Add(pstTupleHash);
		
	return ulRet;
}

STATIC VOID _relation_Hash_Delete(IN SESSION_HASH_S *pstHashTable,
                                  IN RELATION_TUPLE_HASH_S *pstTupleHash)
{
	rte_spinlock_lock(&pstHashTable->astHashLock[pstTupleHash->usLockIndex]);
	DL_Del(&pstTupleHash->stNodeInHash);
	rte_spinlock_unlock(&pstHashTable->astHashLock[pstTupleHash->usLockIndex]);

	return;
}

VOID SESSION_RelationHash_Delete(IN RELATION_S *pstRelation)
{
	RELATION_TUPLE_HASH_S *pstTupleHash;
	SESSION_HASH_S *pstHashTable;

	pstTupleHash = &pstRelation->stTupleHash;
	/* uiMask不为0，使用五元组hash表 */
	if((RELATION_TUPLEFLAG_IS_IPSET(pstRelation->stTupleHash.uiMask)) &&
	   (RELATION_TUPLEFLAG_IS_PORTSET(pstRelation->stTupleHash.uiMask)))
	{
		pstHashTable = (SESSION_HASH_S *)g_hV4RelationHash5;
    }
	else
	{
		pstHashTable = (SESSION_HASH_S *)g_hV4RelationHash3;
	}

	_relation_Hash_Delete(pstHashTable, pstTupleHash);

	return;
}


RELATION_S *SESSION_RelationHash_Find(IN const csp_key_t *pstcspkey)
{
    RELATION_S *pstRelation;
    SESSION_CTRL_S *pstSessionMdc;
    SESSION_HASH_S *pstHashTable;
    ULONG ulHashIndex;
    
    pstSessionMdc = SESSION_CtrlData_Get();

    /* 如果关联表统计计数是0，就不再HASH查找了 */
    if (0 == rte_atomic32_read(&(pstSessionMdc->stSessStat.stTotalRelationNum)))
    {
        return NULL;
    }

    pstHashTable = (SESSION_HASH_S *)g_hV4RelationHash3;

    ulHashIndex = _relation_GetHash3(pstcspkey, pstHashTable->uiBucketMask);
        
    pstRelation = _relation_Hash_Find(&pstHashTable->pstBuckets[ulHashIndex], pstcspkey);
    if(NULL == pstRelation)
    {
        /*先查一遍三元组关联表，再查一遍五元组关联表*/
        pstHashTable = (SESSION_HASH_S *)g_hV4RelationHash5;
        
        ulHashIndex = _relation_GetHash5(pstcspkey, pstHashTable->uiBucketMask);
        pstRelation = _relation_Hash_Find(&pstHashTable->pstBuckets[ulHashIndex], pstcspkey);        
    }

    if((NULL != pstRelation) && (RELATION_IS_SELFAGED(pstRelation)))
    {
        pstRelation->uiUpdateTime = rte_get_timer_cycles();
    }

    /* 如果匹配上临时关联表，返回空，这时候父会话还没有正式化 */
    if((NULL != pstRelation) && (RELATION_IS_TEMP(pstRelation)))
    {
        pstRelation = NULL;
    }

    return pstRelation;
}



