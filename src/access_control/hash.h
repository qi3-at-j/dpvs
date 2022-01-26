
#ifndef _SYS_HASH_H_
#define _SYS_HASH_H_

#ifdef __cplusplus
extern "C"{
#endif



typedef DL_NODE_S HASH_NODE_S; /* hash table node */
typedef DL_HEAD_S HASH_LIST_S; /* hash confic list */
#define HASH_ENTRY(ptr, type, member) container_of(ptr, type, member)

#define HASH_TBL_FOREACH(pstTbl, ulIndex) \
    for((ulIndex) = 0UL; (ulIndex) < (pstTbl)->ulSize; (ulIndex)++)

#define HASH_GET_INDEX(pstTbl, pKey)           ((pstTbl)->pfHash(pKey))
#define HASH_IS_VALID_INDEX(pstTbl, ulIndex)   ((ulIndex) < (pstTbl)->ulSize)
#define HASH_GET_LIST(pstTbl, ulIndex)         (&(pstTbl)->pstBckt[ulIndex])
#define HASH_IS_HASHED(pstNode)                (NULL != (pstNode)->ppstPre)

/****************************GENERAL HASH TABLE DEFINITION *********************/
typedef struct tagHASH_TABLE
{
    ULONG ulSize;
    ULONG (*pfHash)(const VOID *);
    HASH_LIST_S *pstBckt;
}HASH_TABLE_S;

#define HASH_BCKT_FOREACH(pstList, pstNode) \
    DL_FOREACH(pstList, pstNode)

#define HASH_BCKT_FOREACH_SAFE(pstList, pstNode, pstNext) \
    DL_FROEACH_SAFE(pstList, pstNode, pstNext)

#define HASH_SCAN_BCKT(pstTbl, ulIndex, pstNode) \
    HASH_BCKT_FOREACH(&(pstTbl)->pstBckt[ulIndex], pstNode)

#define HASH_SCAN_BCKT_SAFE(pstTbl, ulIndex, pstNode, pstNext) \
    HASH_BCKT_FOREACH_SAFE(&(pstTbl)->pstBckt[ulIndex], pstNode, pstNext)

#define HASH_SCAN_TBL(pstTbl, ulIndex, pstNode) \
    HASH_TBL_FOREACH(pstTbl, ulIndex)\
    HASH_SCAN_BCKT(pstTbl, ulIndex, pstNode)

#define HASH_SCAN_TBL_SAFE(pstTbl, ulIndex, pstNode, pstNext) \
    HASH_TBL_FOREACH(pstTbl, ulIndex) \
    HASH_SCAN_BCKT_SAFE(pstTbl, ulIndex, pstNode, pstNext)

#define __JHASH_MIX(uia, uib, uic) \
{ \
    uia -= uib; uia -= uic; uia ^= (uic>>13); \
    uib -= uic; uib -= uia; uib ^= (uia<<8);  \
    uic -= uia; uic -= uib; uic ^= (uib>>13); \
    uia -= uib; uia -= uic; uia ^= (uic>>12); \
    uib -= uic; uib -= uia; uib ^= (uia<<16); \
    uic -= uia; uic -= uib; uic ^= (uib>>5);  \
    uia -= uib; uia -= uic; uia ^= (uic>>3);  \
    uib -= uic; uib -= uia; uib ^= (uia<<10); \
    uic -= uia; uic -= uib; uic ^= (uib>>15); \
}

#define JHASH_GOLDEN_RATIO 0x9e3779b9    

UINT JHASH_GeneralBuffer(const VOID *pkey, UINT uiLen)
{
    UINT uia, uib, uic, uiRemainlen;
    const UCHAR *pucKey = (const UCHAR *)pkey;

    uiRemainlen = uiLen;
    uia = uib = JHASH_GOLDEN_RATIO;
    uic = 0;

    while (uiRemainlen >= 12)
    {
        uia += (pucKey[0] + ((UINT)pucKey[1]<<8) + ((UINT)pucKey[2]<<16) + ((UINT)pucKey[3]<<24));
        uib += (pucKey[4] + ((UINT)pucKey[5]<<8) + ((UINT)pucKey[6]<<16) + ((UINT)pucKey[7]<<24));
        uic += (pucKey[8] + ((UINT)pucKey[9]<<8) + ((UINT)pucKey[10]<<16) + ((UINT)pucKey[11]<<24));

        __JHASH_MIX(uia, uib, uic);
        pucKey   += 12;
        uiRemainlen -= 12;
    }

    switch(uiRemainlen)
    {
        case 11:
            uic += ((UINT)pucKey[10]<<24);
        case 10:
            uic += ((UINT)pucKey[9]<<16);
        case 9:
            uic += ((UINT)pucKey[8]<<8);
        case 8:
            uib += ((UINT)pucKey[7]<<24);
        case 7:
            uib += ((UINT)pucKey[6]<<16);
        case 6:
            uib += ((UINT)pucKey[5]<<8);
        case 5:
            uib += pucKey[4];
        case 4:
            uia += ((UINT)pucKey[3]<<24);
        case 3:
            uia += ((UINT)pucKey[2]<<16);
        case 2:
            uia += ((UINT)pucKey[1]<<8);
        case 1:
            uia += pucKey[0];
        default:
            uic += uiLen;
    }

    __JHASH_MIX(uia,uib,uic);

    return uic;
}


ULONG SecPolicy_GetHashKey(IN const VOID *pKey)
{
    ULONG ulKey = 0;
    UINT uiLen = strlen((char *)pKey);;
    ulKey = JHASH_GeneralBuffer(pKey, (UINT)uiLen);
    ulKey = ulKey % 0xffff;
    return ulKey;    
}

static inline HASH_NODE_S *HASH_ListFirst(IN const HASH_LIST_S *pstList)
{
    return DL_First(pstList);
}

static inline void HASH_ListAdd(IN HASH_LIST_S *pstList, IN HASH_NODE_S *pstNode)
{
    DL_AddHead((DL_HEAD_S *)pstList, (DL_NODE_S *)pstNode);
    return;
}

static inline void HASH_ListAddAfter(IN HASH_LIST_S *pstList, IN HASH_NODE_S *pstPrev, IN HASH_NODE_S *pstInst)
{
    if (NULL == pstPrev)
    {
        DL_AddHead((DL_HEAD_S *)pstList, (DL_NODE_S *)pstInst);
    }
    else
    {
        DL_AddAfter((DL_NODE_S *)pstPrev, (DL_NODE_S *)pstInst);
    }
    return;
}

static inline HASH_TABLE_S * HASH_Create(IN ULONG ulSize, ULONG (*pfHash)(const VOID *))
{
    HASH_TABLE_S *pstTbl;
    HASH_LIST_S  *pstHead;
    if (uiLen <=0)
    {
        return NULL;
    }

    pstTbl = (HASH_TABLE_S *)ret_malloc(sizeof(HASH_TABLE_S), GFP_ATOMIC);
    if (NULL == pstTbl)
    {
        return NULL;
    }

    pstHead = (HASH_LIST_S *)ret_malloc(ulSize * sizeof(HASH_LIST_S), GFP_ATOMIC);
    if (NULL == pstHead)
    {
        if (NULL != pstTbl)
        {
            rte_free(pstTbl)
        }
        return NULL;
    }

    pstTbl->ulSize = ulSize;
    pstTbl->pfHash = pfHash;
    pstTbl->pstBckt = pstHead;

    return pstTbl;
}

static inline void HASH_Add(INOUT HASH_TABLE_S *pstTbl, IN HASH_NODE_S *pstNode, IN const void * pKey)
{
    HASH_LIST_S *pstList;
    ULONG ulIndex;

    ulIndex = HASH_GET_INDEX(pstTbl, pKey);
    pstList = HASH_GET_LIST(pstTbl, ulIndex);
    HASH_ListAdd(pstList, pstNode);
    return;
}

#endif
