#include <string.h>
#include "session_kcore.h"
#include "session_khash.h"


extern SESSION_HASH_HANDLE g_hV6RelationHash;


/* �Ƚ�HASH�ڵ��Ƿ�ƥ�� */
STATIC inline BOOL_T _relation6_Hash_IsTupleMatch(IN const csp_key_t *pstIp6fsKeyFromHash,
												  IN const csp_key_t *pstNewIp6fsKey,
												  IN UINT uiCmpMask)
{
#if 0
	if(pstIp6fsKeyFromHash->usMDCID != pstNewIp6fsKey->usMDCID)
	{
		return BOOL_FALSE;
	}
#endif

	/* ���Э����Ƿ�һ�� */
	if(pstIp6fsKeyFromHash->proto != pstNewIp6fsKey->proto)
	{
		return BOOL_FALSE;
	}

	/* ���VRF�Ƿ�ƥ�� */
	if (pstIp6fsKeyFromHash->token != pstNewIp6fsKey->token)
	{
		return BOOL_FALSE;
	}

	/* ���������Ŀ�ĵ�ַ�뱨��Ŀ�ĵ�ַ�Ƿ�һ�� */
	if (0 != memcmp(&pstIp6fsKeyFromHash->dst_ip, &pstNewIp6fsKey->dst_ip, sizeof(struct in6_addr)))
	{
		return BOOL_FALSE;
	}

	/* ���������Ŀ�Ķ˿��뱨��Ŀ�Ķ˿��Ƿ�һ�� */
	if (pstIp6fsKeyFromHash->dst_port != pstNewIp6fsKey->dst_port)
	{
		return BOOL_FALSE;
	}

	/* ���Դ��ַ�Ƿ�һ�� */
	if (RELATION_TUPLEFLAG_IS_IPSET(uiCmpMask))
	{
		if(0 != memcmp(&pstIp6fsKeyFromHash->src_ip, &pstNewIp6fsKey->src_ip, sizeof(struct in6_addr)))
		{
			return BOOL_FALSE;
		}
	}

	/* ���Դ�˿��Ƿ�һ�� */
	if (RELATION_TUPLEFLAG_IS_PORTSET(uiCmpMask))
	{
		if(pstIp6fsKeyFromHash->src_port != pstNewIp6fsKey->src_port)
		{
			return BOOL_FALSE;
		}
	}

#if 0
	/* ������������һ�£����㻹������ */
	if (pstIp6fsKeyFromHash->ucType != pstNewIp6fsKey->ucType)
	{
		return BOOL_FALSE;
	}
#endif

	return BOOL_TRUE;
}


/* �ȽϹ�����HASH�ڵ��Ƿ�ƥ�� */
BOOL_T SESSION6_Relation_IsTupleMatch(IN const csp_key_t *pstTupleFromHash,
                                      IN const csp_key_t *pstNewTuple,
                                      IN UINT uiCmpMask)
{
    return _relation6_Hash_IsTupleMatch(pstTupleFromHash, pstNewTuple, uiCmpMask);
}

STATIC inline ULONG _relation6_GetHash(IN const csp_key_t *pstIp6fsKey, IN UINT uiMask)
{
	UINT uiV1;
	UINT uiV2;
	UINT uiV3;

	/* ����Hashֵ */
	uiV1 = pstIp6fsKey->src_ip
	     ^ pstIp6fsKey->src_ip3[0]
      	 ^ pstIp6fsKey->src_ip3[1]
	     ^ pstIp6fsKey->src_ip3[2];

    uiV2 = (UINT)(pstIp6fsKey->dst_port) | ((UINT)(pstIp6fsKey->proto) << 16);

	uiV3 = (UINT)pstIp6fsKey->token;

	SESSION_HASH_MIX(uiV1, uiV2, uiV3);

	return ( (uiV3 & 0xffff) ^ (uiV3 >> 16) ) & uiMask;
}


STATIC inline RELATION6_S * _relation6_Hash_CmpRelation(IN const csp_key_t *pstIp6fsKey,
                                                        IN RELATION6_TUPLE_HASH_S *pstCurrent)
{
	RELATION6_S *pstRelation = NULL;

	if(BOOL_TRUE == _relation6_Hash_IsTupleMatch(&pstCurrent->stIp6fsKey, pstIp6fsKey, pstCurrent->uiMask))
	{
		pstRelation = container_of(pstCurrent, RELATION6_S, stTupleHash);
		if(RELATION_IS_DELETING(pstRelation))
		{
			pstRelation = NULL;
		}
	}

	return pstRelation;
}

STATIC inline RELATION6_S *_relation6_Hash_Find(IN const DL_HEAD_S *pstBucketHead,
                                                IN const csp_key_t *pstIp6fsKey)
{
	RELATION6_TUPLE_HASH_S *pstCurrent;
	RELATION6_S *pstRelation = NULL;
	DL_NODE_S *pstNode;

	/*DL_FOREACH_RCU(pstBucketHead, pstNode)*/
	DL_FOREACH(pstBucketHead, pstNode)
	{
		pstCurrent = DL_ENTRY(pstNode, RELATION6_TUPLE_HASH_S, stNodeInHash);

		pstRelation = _relation6_Hash_CmpRelation(pstIp6fsKey, pstCurrent);
		if(NULL != pstRelation)
		{
			break;
		}
	}

	return pstRelation;
}

/* ����������ӵ�HASH�� */
STATIC ULONG _relation6_Hash_Add(IN SESSION_HASH_S *pstHashTbale, IN RELATION6_TUPLE_HASH_S *pstTupleHash)
{
	ULONG  ulHashIndex;
	USHORT usLockIndex;
	ULONG  ulRet = ERROR_FAILED;

	ulHashIndex = _relation6_GetHash(&pstTupleHash->stIp6fsKey, pstHashTbale->uiBucketMask);
	usLockIndex = (USHORT)ulHashIndex & SESSION_HASH_LOCK_MASK;

	pstTupleHash->usLockIndex = usLockIndex;

	rte_spinlock_lock(&pstHashTbale->astHashLock[usLockIndex]);

	if(NULL == _relation6_Hash_Find(&pstHashTbale->pstBuckets[ulHashIndex], &pstTupleHash->stIp6fsKey))
	{
 		/* DL_AddAfterPtr_Rcu(&(pstHashTbale->pstBuckets[ulHashIndex].pstFirst), &pstTupleHash->stNodeInHash); */		
		DL_AddAfterPtr(&(pstHashTbale->pstBuckets[ulHashIndex].pstFirst), &pstTupleHash->stNodeInHash);
		ulRet = ERROR_SUCCESS;
	}

	rte_spinlock_unlock(&pstHashTbale->astHashLock[usLockIndex]);

	return ulRet;
}

STATIC VOID _relation6_Hash_Delete(IN SESSION_HASH_S *pstHashTable,
                                   IN RELATION6_TUPLE_HASH_S *pstTupleHash)
{
	rte_spinlock_lock(&pstHashTable->astHashLock[pstTupleHash->usLockIndex]);

	DL_Del(&pstTupleHash->stNodeInHash);

	rte_spinlock_unlock(&pstHashTable->astHashLock[pstTupleHash->usLockIndex]);

	return;
}
								   
ULONG SESSION6_RelationHash_Add(IN RELATION6_S *pstRelation)
{
	RELATION6_TUPLE_HASH_S *pstTupleHash;
	SESSION_HASH_S *pstHashTable;
	ULONG ulRet;

	pstHashTable = (SESSION_HASH_S *)g_hV6RelationHash;

	pstTupleHash = &pstRelation->stTupleHash;

	ulRet = _relation6_Hash_Add(pstHashTable, pstTupleHash);

	return ulRet;
}

VOID SESSION6_RelationHash_Delete(IN RELATION6_S *pstRelation)
{
	RELATION6_TUPLE_HASH_S *pstTupleHash;
	SESSION_HASH_S *pstHashTable;

	pstTupleHash = &pstRelation->stTupleHash;
	pstHashTable = (SESSION_HASH_S *)g_hV6RelationHash;
	_relation6_Hash_Delete(pstHashTable, pstTupleHash);

	return;
}

RELATION6_S *SESSION6_RelationHash_Find(IN const csp_key_t *pstIp6fsKey)
{
    RELATION6_S *pstRelation;
    SESSION_CTRL_S *pstSessionMdc;
    SESSION_HASH_S *pstHashTable;
    ULONG ulHashIndex;
    
    pstSessionMdc = SESSION_CtrlData_Get();

    /* ���������ͳ�Ƽ�����0���Ͳ���HASH������ */
    if (0 == rte_atomic32_read(&(pstSessionMdc->stSessStat.stTotalRelationNum)))
    {
        return NULL;
    }

    pstHashTable = (SESSION_HASH_S *)g_hV6RelationHash;
    ulHashIndex = _relation6_GetHash(pstIp6fsKey, pstHashTable->uiBucketMask);
    pstRelation = _relation6_Hash_Find(&pstHashTable->pstBuckets[ulHashIndex], pstIp6fsKey);        
    
    if((NULL != pstRelation) && (RELATION_IS_SELFAGED(pstRelation)))
    {
        pstRelation->uiUpdateTime = rte_get_timer_cycles();
    }

    return pstRelation;
}

