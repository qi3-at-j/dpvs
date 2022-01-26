
#ifndef _HASH_H_
#define _HASH_H_

#ifdef __cplusplus
extern "C"{
#endif

#include "baseype.h"
#include "extlist.h"

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

#endif
