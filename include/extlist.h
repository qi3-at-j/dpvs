#ifndef _LIST_H_
#define _LIST_H_

#include <stdio.h>
#include "baseype.h"


#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((UINT64) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif


/* single link list */
typedef struct tagSL_NODE
{
    struct tagSL_NODE* pstNext;
}SL_NODE_S;

#define SL_ENTRY(p, t, m)   (container_of(p, t, m))

typedef struct tagSL_HEAD
{
    SL_NODE_S* pstFirst;
}SL_HEAD_S;

static inline VOID SL_Init(OUT SL_HEAD_S* pstList);
static inline VOID SL_NodeInit(OUT SL_NODE_S* pstNode);
static inline BOOL_T SL_IsEmpty(IN const SL_HEAD_S* pstList);
static inline SL_NODE_S* SL_First(IN const SL_HEAD_S* pstList);
static inline SL_NODE_S* SL_Next(IN const SL_NODE_S* pstNode);
static inline VOID SL_AddHead(IN SL_HEAD_S* pstList, IN SL_NODE_S* pstNode);
static inline SL_NODE_S* SL_DelHead(IN SL_HEAD_S* pstList);
static inline VOID SL_AddAfter(IN SL_HEAD_S* pstList, IN SL_NODE_S* pstPrev, IN SL_NODE_S* pstInst);
static inline SL_NODE_S* SL_DelAfter(IN SL_HEAD_S* pstList, IN SL_NODE_S* pstPrev);
static inline VOID SL_Del(IN SL_HEAD_S* pstList, IN const SL_NODE_S* pstNode);
static inline VOID SL_Append(IN SL_HEAD_S* pstDstList, IN SL_HEAD_S* pstSrcList);
static inline VOID SL_FreeAll(IN SL_HEAD_S* pstList, IN VOID (*pfFree)(SL_NODE_S *));

static inline VOID SL_Init(OUT SL_HEAD_S* pstList)
{
    pstList->pstFirst = NULL;
    return;
}

static inline VOID SL_NodeInit(OUT SL_NODE_S* pstNode)
{
    pstNode->pstNext = NULL;
    return;
}

static inline BOOL_T SL_IsEmpty(IN const SL_HEAD_S* pstList)
{
    return (pstList->pstFirst == NULL);
}

static inline SL_NODE_S* SL_First(IN const SL_HEAD_S* pstList)
{
    return (pstList->pstFirst);
}

static inline SL_NODE_S* SL_Next(IN const SL_NODE_S* pstNode)
{
    return (pstNode->pstNext);
}

static inline VOID SL_AddHead(IN SL_HEAD_S* pstList, IN SL_NODE_S* pstNode)
{
    pstNode->pstNext = pstList->pstFirst;
    pstList->pstFirst = pstNode;
    return;
}

static inline SL_NODE_S* SL_DelHead(IN SL_HEAD_S* pstList)
{
    SL_NODE_S* pstNode = pstList->pstFirst;
    if (NULL != pstNode)
    {
        pstList->pstFirst = pstNode->pstNext;
    }
    
    return pstNode;
}

static inline VOID SL_AddAfter(IN SL_HEAD_S* pstList, 
                               IN SL_NODE_S* pstPrev, 
                               IN SL_NODE_S* pstInst)
{
    if (NULL == pstPrev)
    {
        SL_AddHead(pstList, pstInst);
    }
    else
    {
        pstInst->pstNext = pstPrev->pstNext;
        pstPrev->pstNext = pstInst;
    }
    return;
}

static inline SL_NODE_S* SL_DelAfter(IN SL_HEAD_S* pstList, IN SL_NODE_S* pstPrev)
{
    SL_NODE_S* pstNode;

    if (NULL == pstPrev)
    {
        SL_DelHead(pstList);
    }
    else
    {
        pstNode = pstPrev->pstNext;
        if (NULL != pstNode)
        {
            pstPrev->pstNext = pstNode->pstNext;
        }
    }
    return pstNode;
}

#define SL_FOREACH(pstList, pstNode)\
    for((pstNode) = SL_First(pstList);\
        NULL != (pstNode);\
        (pstNode) = SL_Next(pstNode))

#define SL_FOREACH_SAFE(pstList, pstNode, pstNext)\
    for((pstNode) = SL_First(pstList);\
        (NULL != (pstNode)) && ({(pstNext) = SL_Next(pstNode); BOOL_TRUE;});\
        (pstNode) = (pstNext))

#define SL_FOREACH_PREVPTR(pstList, pstNode, pstPrev)\
    for((pstNode) = SL_First(pstList), pstPrev = (SL_NODE_S *)NULL;\
        NULL != (pstNode);\
        (VOID)({(pstPrev) = (pstNode); (pstNode) = SL_Next(pstNode);}))

#define SL_ENTRY_FIRST(pstList, type, member)\
    (SL_IsEmpty(pstList) ? NULL : SL_ENTRY(SL_First(pstList), type, member))

#define SL_ENTRY_NEXT(pstEntry, member)\
    (NULL == (pstEntry) ? NULL : \
        (NULL == SL_Next(&((pstEntry)->member)) ? NULL : \
            SL_ENTRY(SL_Next(&((pstEntry)->member)), typeof(*(pstEntry)), member)))

#define SL_FOREACH_ENTRY(pstList, pstEntry, member)\
    for((pstEntry) = SL_ENTRY_FIRST(pstList, typeof(*(pstEntry)), member);\
        NULL != (pstEntry);\
        (pstEntry) = SL_ENTRY_NEXT(pstEntry,member))

#define SL_FOREACH_ENTRY_SAFE(pstList, pstEntry, pstNextEntry, member)\
    for((pstEntry) = SL_ENTRY_FIRST(pstList, typeof(*(pstEntry)), member);\
        NULL != (pstEntry) && ({(pstNextEntry) = SL_ENTRY_NEXT(pstEntry,member);BOOL_TRUE;});\
        (pstEntry) = (pstNextEntry))

#define SL_FOREACH_ENTRY_SAFE_PREVPTR(pstList, pstEntry, pstPrevEntry, member)\
    for((pstEntry) = SL_ENTRY_FIRST(pstList, typeof(*(pstEntry)), member), (pstPrevEntry) = NULL;\
        NULL != (pstEntry);\
        (VOID)({(pstPrevEntry) = (pstEntry);\
        (pstEntry) = SL_ENTRY_NEXT(pstEntry,member);}))


static inline VOID SL_Del(IN SL_HEAD_S* pstList, IN const SL_NODE_S* pstNode)
{
    SL_NODE_S * pstPrev, *pstCur;

    SL_FOREACH_PREVPTR(pstList,pstCur,pstPrev)
    {
        if (pstCur == pstNode)
        {
            (VOID)SL_DelAfter(pstList, pstPrev);
            break;
        }
    }
    return;
}

static inline VOID SL_Append(IN SL_HEAD_S* pstDstList, IN SL_HEAD_S* pstSrcList)
{
    SL_NODE_S * pstPrev, * pstNode;

    if (BOOL_TRUE != SL_IsEmpty(pstSrcList))
    {
        SL_FOREACH_PREVPTR(pstDstList,pstNode,pstPrev);

        if (NULL == pstPrev)
        {
            pstDstList->pstFirst = SL_First(pstSrcList);
        }
        else
        {
            pstPrev->pstNext = SL_First(pstSrcList);
        }

        SL_Init(pstSrcList);
    }

    return;
}

static inline VOID SL_FreeAll(IN SL_HEAD_S* pstList, IN VOID (*pfFree)(SL_NODE_S *))
{
    SL_NODE_S * pstCur, *pstNext;

    SL_FOREACH_SAFE(pstList,pstCur,pstNext)
    {
        pfFree(pstCur);
    }

    SL_Init(pstList);
    return;
}

/* single link list tail queue*/
typedef struct tagSTQ_NODE
{
    struct tagSTQ_NODE * pstNext;
}STQ_NODE_S;

typedef struct tagSTQ_HEAD
{
    struct tagSTQ_NODE * pstFirst;
    struct tagSTQ_NODE * pstLast;
}STQ_HEAD_S;

#define STQ_ENTRY(p, t, m) (container_of(p, t, m))

static inline VOID STQ_Init(IN STQ_HEAD_S * pstList);
static inline VOID STQ_NodeInit(IN STQ_NODE_S * pstNode);
static inline BOOL_T STQ_IsEmpty(IN const STQ_HEAD_S * pstList);
static inline STQ_NODE_S * STQ_First(IN const STQ_HEAD_S * pstList);
static inline STQ_NODE_S * STQ_Last(IN const STQ_HEAD_S * pstList);
static inline STQ_NODE_S * STQ_Next(IN const STQ_NODE_S * pstNode);
static inline VOID STQ_AddHead(IN STQ_HEAD_S * pstList, IN STQ_NODE_S * pstNode);
static inline STQ_NODE_S * STQ_DelHead(IN STQ_HEAD_S * pstList);
static inline VOID STQ_AddTail(STQ_HEAD_S * pstList, STQ_NODE_S * pstNode);
static inline VOID STQ_AddAfter(IN STQ_HEAD_S * pstList,
                                IN STQ_NODE_S * pstPrev,
                                IN STQ_NODE_S * pstInst);
static inline STQ_NODE_S * STQ_DelAfter(IN STQ_HEAD_S * pstList,
                                        IN STQ_NODE_S * pstPrev);
static inline VOID STQ_Del(IN STQ_HEAD_S * pstList, IN const STQ_NODE_S * pstNode);
static inline VOID STQ_Append(IN STQ_HEAD_S * pstDstList, IN STQ_HEAD_S * pstSrcList);
static inline VOID STQ_FreeAll(IN STQ_HEAD_S * pstList, IN VOID (*pfFree)(STQ_NODE_S *));



static inline VOID STQ_Init(IN STQ_HEAD_S * pstList)
{
    pstList->pstFirst = (STQ_NODE_S *)NULL;
    pstList->pstLast  = (STQ_NODE_S *)NULL;
    return;
}

static inline VOID STQ_NodeInit(IN STQ_NODE_S * pstNode)
{
    pstNode->pstNext = (STQ_NODE_S *)NULL;
    return;
}

static inline BOOL_T STQ_IsEmpty(IN const STQ_HEAD_S * pstList)
{
    return (pstList->pstLast == NULL);
}

static inline STQ_NODE_S * STQ_First(IN const STQ_HEAD_S * pstList)
{
    return pstList->pstFirst;
}

static inline STQ_NODE_S * STQ_Last(IN const STQ_HEAD_S * pstList)
{
    return pstList->pstLast;
}

static inline STQ_NODE_S * STQ_Next(IN const STQ_NODE_S * pstNode)
{
    return pstNode->pstNext;
}

static inline VOID STQ_AddHead(IN STQ_HEAD_S * pstList, IN STQ_NODE_S * pstNode)
{
    pstNode->pstNext = pstList->pstFirst;
    pstList->pstFirst = pstNode;
    if (NULL == pstList->pstLast)
    {
        pstList->pstLast = pstNode;
    }
    return;
}

static inline STQ_NODE_S * STQ_DelHead(IN STQ_HEAD_S * pstList)
{
    STQ_NODE_S * pstNode = pstList->pstFirst;
    if (NULL != pstNode)
    {
        pstList->pstFirst = pstNode->pstNext;
    }

    if (NULL == pstList->pstFirst)
    {
        pstList->pstLast = (STQ_NODE_S *)NULL;
    }

    return pstNode;
}

static inline VOID STQ_AddTail(STQ_HEAD_S * pstList, STQ_NODE_S * pstNode)
{
    pstNode->pstNext = (STQ_NODE_S *)NULL;
    if (NULL != pstList->pstLast)
    {
        pstList->pstLast->pstNext = pstNode;
        pstList->pstLast = pstNode;
    }
    else
    {
        pstList->pstLast  = pstNode;
        pstList->pstFirst = pstNode;
    }
    return;
}

static inline VOID STQ_AddAfter(IN STQ_HEAD_S * pstList,
                                IN STQ_NODE_S * pstPrev,
                                IN STQ_NODE_S * pstInst)
{
    if (NULL == pstPrev)
    {
        STQ_AddHead(pstList, pstInst);
    }
    else
    {
        pstInst->pstNext = pstPrev->pstNext;
        pstPrev->pstNext = pstInst;
        if (pstPrev == pstList->pstLast)
        {
            pstList->pstLast = pstInst;
        }
    }
    return;
}

static inline STQ_NODE_S * STQ_DelAfter(IN STQ_HEAD_S * pstList,
                                        IN STQ_NODE_S * pstPrev)
{
    STQ_NODE_S * pstNode;
    if (NULL == pstPrev)
    {
        pstNode = STQ_DelHead(pstList);
    }
    else
    {
        pstNode = pstPrev->pstNext;
        if (NULL != pstNode)
        {
            pstPrev->pstNext = pstNode->pstNext;
        }

        if (pstList->pstLast == pstNode)
        {
            pstList->pstLast = pstPrev;
        }
    }
    return pstNode;
}

#define STQ_FOREACH(pstList, pstNode)\
    for((pstNode) = STQ_First(pstList);\
        NULL != (pstNode);\
        (pstNode) = STQ_Next(pstNode))

#define STQ_FOREACH_SAFE(pstList, pstNode, pstNext)\
    for((pstNode) = STQ_First(pstList);\
        NULL != (pstNode) && ({(pstNext) = STQ_Next(pstNode); BOOL_TRUE;});\
        (pstNode) = (pstNext))

#define STQ_FOREACH_PREVPTR(pstList, pstNode, pstPrev)\
    for((pstNode) = STQ_First(pstList), (pstPrev) = (STQ_NODE_S *)NULL;\
        NULL != (pstNode);\
        ({(pstPrev) = (pstNode); (pstNode) = STQ_Next(pstNode);}))

#define STQ_ENTRY_FIRST(pstList, type, member)\
    for(STQ_IsEmpty(pstList) ? NULL : STQ_ENTRY(STQ_First(pstList),type,member))

#define STQ_ENTRY_LAST(pstList, type, member)\
    for(STQ_IsEmpty(pstList) ? NULL : STQ_ENTRY(STQ_Last(pstList),type,member))

#define STQ_ENTRY_NEXT(pstEntry, member)\
    for(NULL == pstEntry ? NULL : (NULL == STQ_Next(&((pstEntry)->member)) ? NULL :\
        STQ_ENTRY(STQ_Next(&((pstEntry)->member)),typeof(*(pstEntry)),member)))

#define STQ_FOREACH_ENTRY(pstList, pstEntry, member)\
    for ((pstEntry) = STQ_ENTRY_FIRST(pstList,typeof(*(pstEntry)),member);\
          NULL != (pstEntry);\
          (pstEntry) = STQ_ENTRY_NEXT(pstEntry,member))

#define STQ_FOREACH_ENTRY_SAFE(pstList, pstEntry, pstNextEntry, member)\
    for ((pstEntry) = STQ_ENTRY_FIRST(pstList,typeof(*(pstEntry)),member);\
          NULL != (pstEntry) && ({(pstNextEntry) = STQ_ENTRY_NEXT(pstEntry,member); BOOL_TRUE;});\
          (pstEntry) = (pstNextEntry))

#define STQ_FOREACH_ENTRY_PREVPTR(pstList, pstEntry, pstPrevEntry, member)\
    for ((pstEntry) = STQ_ENTRY_FIRST(pstList,typeof(*(pstEntry)),member),\
          (pstPrevEntry) = NULL;\
          NULL != (pstEntry);\
          (VOID)({(pstPrevEntry) = (pstEntry); (pstEntry) = STQ_ENTRY_NEXT(pstEntry,member);}))

static inline VOID STQ_Del(IN STQ_HEAD_S * pstList, IN const STQ_NODE_S * pstNode)
{
    STQ_NODE_S * pstCur, *pstPrev;
    STQ_FOREACH_PREVPTR(pstList,pstCur,pstPrev)
    {
        if (pstNode == pstCur)
        {
            STQ_DelAfter(pstList,pstPrev);
            break;
        }
    }

    return;
}
    
static inline VOID STQ_Append(IN STQ_HEAD_S * pstDstList, IN STQ_HEAD_S * pstSrcList)
{
    if (BOOL_TRUE != STQ_IsEmpty(pstSrcList))
    {
        if (NULL != pstDstList->pstLast)
        {
            pstDstList->pstLast->pstNext = STQ_First(pstSrcList);
        }
        else
        {
            pstDstList->pstFirst = STQ_First(pstSrcList);
        }

        pstDstList->pstLast = STQ_Last(pstSrcList);
        STQ_Init(pstSrcList);
    }
    return;
}

static inline VOID STQ_FreeAll(IN STQ_HEAD_S * pstList, IN VOID (*pfFree)(STQ_NODE_S *))
{
    STQ_NODE_S * pstCur, *pstNext;

    STQ_FOREACH_SAFE(pstList,pstCur,pstNext)
    {
        pfFree(pstCur);
    }

    STQ_Init(pstList);
    return;
}

/* double link list */
typedef struct tagDL_NODE
{
    struct tagDL_NODE * pstNext;
    struct tagDL_NODE ** ppstPre;
}DL_NODE_S;

typedef struct tagDL_HEAD
{
    DL_NODE_S * pstFirst;
}DL_HEAD_S;

#define DL_ENTRY(p, t, m)  (container_of(p,t,m))
#define DL_NODE_FROM_PPRE(ppstPre) (container_of(ppstPre, DL_NODE_S, pstNext))
#define DL_ENTRY_FORM_PPRE(ppstPre, type, member) DL_ENTRY(DL_NODE_FROM_PPRE(ppstPre), type, member)

static inline VOID DL_Init(IN DL_HEAD_S * pstList);
static inline VOID DL_NodeInit(IN DL_NODE_S * pstNode);
static inline BOOL_T DL_IsEmpty(IN const DL_HEAD_S * pstList);
static inline DL_NODE_S * DL_First(IN const DL_HEAD_S * pstList);
static inline DL_NODE_S * DL_Next(IN const DL_NODE_S * pstNode);
static inline DL_NODE_S * DL_Prev(IN const DL_NODE_S * pstNode);
static inline VOID DL_Del(INOUT DL_NODE_S * pstNode);
static inline VOID DL_AddHead(IN DL_HEAD_S * pstList, IN DL_NODE_S * pstNode);
static inline DL_NODE_S * DL_DelHead(IN const DL_HEAD_S * pstList);
static inline VOID DL_AddAfter(IN DL_NODE_S * pstPrev, IN DL_NODE_S * pstInst);
static inline VOID DL_AddAfterPtr(IN DL_NODE_S ** ppstPre, IN DL_NODE_S * pstInst);
static inline VOID DL_AddBefore(IN DL_NODE_S * pstNext, IN DL_NODE_S * pstInst);
static inline VOID DL_Append(IN DL_HEAD_S * pstDstList, IN DL_HEAD_S * pstSrcList);
static inline VOID DL_FreeAll(IN DL_HEAD_S * pstList, IN VOID (*pfFree)(DL_NODE_S *));

static inline VOID DL_Init(IN DL_HEAD_S * pstList)
{
    pstList->pstFirst = (DL_NODE_S *)NULL;
    return;
}

static inline VOID DL_NodeInit(IN DL_NODE_S * pstNode)
{
    pstNode->ppstPre = (DL_NODE_S **)NULL;
    pstNode->pstNext = (DL_NODE_S *)NULL;
    return;
}

static inline BOOL_T DL_IsEmpty(IN const DL_HEAD_S * pstList)
{
    return (pstList->pstFirst == NULL);
}

static inline DL_NODE_S * DL_First(IN const DL_HEAD_S * pstList)
{
    return (pstList->pstFirst);
}

static inline DL_NODE_S * DL_Next(IN const DL_NODE_S * pstNode)
{
    return (pstNode->pstNext);
}

static inline DL_NODE_S * DL_Prev(IN const DL_NODE_S * pstNode)
{
    return DL_NODE_FROM_PPRE(pstNode->ppstPre);
}

static inline VOID DL_Del(INOUT DL_NODE_S * pstNode)
{
    if (NULL != pstNode->ppstPre)
    {
        *pstNode->ppstPre = pstNode->pstNext;
        
    }
    if (NULL != pstNode->pstNext)
    {
        pstNode->pstNext->ppstPre = pstNode->ppstPre;
    }
    return;
}

static inline VOID DL_AddHead(IN DL_HEAD_S * pstList, IN DL_NODE_S * pstNode)
{
    pstNode->ppstPre = &pstList->pstFirst;
    pstNode->pstNext = pstList->pstFirst;
    if (NULL != pstNode->pstNext)
    {
        pstNode->pstNext->ppstPre = &pstNode->pstNext;
    }
    pstList->pstFirst = pstNode;
    return;
}

static inline DL_NODE_S * DL_DelHead(IN const DL_HEAD_S * pstList)
{
    DL_NODE_S * pstNode = DL_First(pstList);
    if (NULL != pstNode)
    {
        DL_Del(pstNode);
    }
    return pstNode;
}

static inline VOID DL_AddAfter(IN DL_NODE_S * pstPrev, IN DL_NODE_S * pstInst)
{
    pstInst->ppstPre = &pstPrev->pstNext;
    pstInst->pstNext = pstPrev->pstNext;
    pstPrev->pstNext = pstInst;
    if (NULL != pstInst->pstNext)
    {
        pstInst->pstNext->ppstPre = &pstInst->pstNext;
    }
    return;
}

static inline VOID DL_AddAfterPtr(IN DL_NODE_S ** ppstPre, IN DL_NODE_S * pstInst)
{
    pstInst->ppstPre = ppstPre;
    pstInst->pstNext = *ppstPre;
    *ppstPre = pstInst;
    if (NULL != pstInst->pstNext)
    {
        pstInst->pstNext->ppstPre = &pstInst->pstNext;
    }
    return;
}

static inline VOID DL_AddBefore(IN DL_NODE_S * pstNext, IN DL_NODE_S * pstInst)
{
    pstInst->ppstPre = pstNext->ppstPre;
    pstInst->pstNext = pstNext;
    if (NULL != pstInst->ppstPre)
    {
        *pstInst->ppstPre = pstInst;
    }
    pstInst->pstNext->ppstPre = &pstInst->pstNext;
    return;
}

#define DL_FOREACH(pstList, pstNode)\
    for((pstNode) = DL_First((pstList));\
        NULL != (pstNode);\
        (pstNode) = DL_Next(pstNode))

#define DL_FOREACH_SAFE(pstList, pstNode, pstNext)\
    for((pstNode) = DL_First((pstList));\
        (NULL != (pstNode)) && ({(pstNext) = DL_Next(pstNode);BOOL_TRUE;});\
        (pstNode) = (pstNext))

#define DL_FOREACH_PREVPTR(pstList, pstNode, ppstPre)\
    for ((pstNode) = DL_First((pstList)), (ppstPre) = &((pstList)->pstFirst);\
        NULL != (pstNode);\
        (VOID)({(ppstPre) = &((pstNode)->pstNext); (pstNode) = DL_Next(pstNode);}))

#define DL_ENTRY_FIRST(pstList, type, member)\
    (DL_IsEmpty(pstList) ? NULL : DL_ENTRY(DL_First(pstList), type, member))

#define DL_ENTRY_NEXT(pstEntry, member)\
    (NULL == (pstEntry) ? NULL : \
        (NULL == DL_Next(&((pstEntry)->member)) ? NULL : \
            DL_ENTRY(DL_Next(&((pstEntry)->member)), typeof(*(pstEntry)), member)))

#define DL_ENTRY_PREV(pstEntry, member)\
    (NULL = (pstEntry) ? NULL : \
        (NULL == DL_Next(&((pstEntry)->member)) ? NULL : \
            DL_ENTRY(DL_Next(&((pstEntry)->member)), typeof(*(pstEntry)), member)))

#define DL_FOREACH_ENTRY(pstList, pstEntry, member)\
    for ((pstEntry) = DL_ENTRY_FIRST(pstList, typeof(*(pstEntry)),member);\
          NULL != (pstEntry);\
          (pstEntry) = DL_ENTRY_NEXT(pstEntry, member))

#define DL_FOREACH_ENTRY_SAFE(pstList, pstEntry, pstNextEntry, member)\
    for ((pstEntry) = DL_ENTRY_FIRST(pstList, typeof(*(pstEntry)),member);\
          (NULL != (pstEntry)) && ({(pstNextEntry) = DL_ENTRY_NEXT(pstEntry,member); BOOL_TRUE;});\
          (pstEntry) = (pstNextEntry))

#define DL_FOREACH_ENTRY_PREVPTR(pstList, pstEntry, ppstPre, member)\
    for ((pstEntry) = DL_ENTRY_FIRST(pstList, typeof(*(pstEntry)),member) ,\
         (ppstPre) = &((pstList)->pstFirst);\
         NULL != (pstEntry);\
         (VOID)({(ppstPre) = &((pstEntry)->member.pstNext);\
            (pstEntry) = DL_ENTRY_NEXT(pstEntry,member);}))

static inline VOID DL_Append(IN DL_HEAD_S * pstDstList, IN DL_HEAD_S * pstSrcList)
{
    DL_NODE_S * pstNode, ** ppstPre;
    if (BOOL_TRUE != DL_IsEmpty(pstSrcList))
    {
        DL_FOREACH_PREVPTR(pstDstList,pstNode,ppstPre);

        *ppstPre = pstSrcList->pstFirst;
        pstSrcList->pstFirst->ppstPre = ppstPre;
        DL_Init(pstSrcList);
    }
    return;
}
    
static inline VOID DL_FreeAll(IN DL_HEAD_S * pstList, IN VOID (*pfFree)(DL_NODE_S *))
{
    DL_NODE_S *pstCurNode, *pstNextNode;
    DL_FOREACH_SAFE(pstList,pstCurNode,pstNextNode)
    {
        pfFree(pstCurNode);
    }
    DL_Init(pstList);
    return;
}



/* double link tail queue */
typedef struct tagDTQ_NODE
{
    struct tagDTQ_NODE* pstPrev;
    struct tagDTQ_NODE* pstNext;
}DTQ_NODE_S;

typedef struct tagDTQ_HEAD
{
    DTQ_NODE_S stHead;
}DTQ_HEAD_S;

#define DTQ_ENTRY(p, t, m)  (container_of(p,t,m))

static inline VOID DTQ_Init(IN DTQ_HEAD_S* pstList);
static inline VOID DTQ_NodeInit(IN DTQ_NODE_S* pstNode);
static inline BOOL_T DTQ_IsEmpty(IN const DTQ_HEAD_S* pstList);
static inline DTQ_NODE_S* DTQ_First(IN const DTQ_HEAD_S* pstList);
static inline DTQ_NODE_S* DTQ_Last(IN const DTQ_HEAD_S* pstList);
static inline BOOL_T DTQ_IsEndOfQ(IN const DTQ_HEAD_S* pstList, IN const DTQ_NODE_S* pstNode);
static inline DTQ_NODE_S* DTQ_Prev(IN const DTQ_NODE_S* pstNode);
static inline DTQ_NODE_S* DTQ_Next(IN const DTQ_NODE_S* pstNode);
static inline VOID DTQ_AddAfter(IN DTQ_NODE_S* pstPrev, IN DTQ_NODE_S* pstInst);
static inline VOID DTQ_AddBefore(IN DTQ_NODE_S* pstNext, IN DTQ_NODE_S* pstInst);
static inline VOID DTQ_Del(IN const DTQ_NODE_S* pstNode);
static inline VOID DTQ_AddHead(IN DTQ_HEAD_S* pstList, IN DTQ_NODE_S* pstNode);
static inline DTQ_NODE_S* DTQ_DelHead(IN const DTQ_HEAD_S* pstList);
static inline VOID DTQ_AddTail(IN DTQ_HEAD_S* pstList, IN DTQ_NODE_S* pstNode);
static inline DTQ_NODE_S* DTQ_DelTail(IN const DTQ_HEAD_S* pstList);
static inline VOID DTQ_Append(IN DTQ_HEAD_S* pstDstList, IN DTQ_HEAD_S* pstSrcList);
static inline VOID DTQ_FreeAll(IN DTQ_HEAD_S* pstList, IN VOID (*pfFree)(DTQ_NODE_S *));


static inline VOID DTQ_Init(IN DTQ_HEAD_S* pstList)
{
    pstList->stHead.pstPrev = &pstList->stHead;
    pstList->stHead.pstNext = &pstList->stHead;
    return;
}

static inline VOID DTQ_NodeInit(IN DTQ_NODE_S* pstNode)
{
    pstNode->pstPrev = (DTQ_NODE_S*)NULL;
    pstNode->pstNext = (DTQ_NODE_S*)NULL;
    return;
}

static inline BOOL_T DTQ_IsEmpty(IN const DTQ_HEAD_S* pstList)
{
    return (pstList->stHead.pstNext == &pstList->stHead);
}

static inline DTQ_NODE_S* DTQ_First(IN const DTQ_HEAD_S* pstList)
{
    DTQ_NODE_S * pstNode = pstList->stHead.pstNext;
    if (pstNode == &(pstList->stHead))
    {
        return (DTQ_NODE_S *)NULL;
    }

    return pstNode;
}

static inline DTQ_NODE_S* DTQ_Last(IN const DTQ_HEAD_S* pstList)
{
    DTQ_NODE_S* pstNode = pstList->stHead.pstPrev;
    if (pstNode == &(pstList->stHead))
    {
        return (DTQ_NODE_S*)NULL;
    }
    return pstNode;
}

static inline BOOL_T DTQ_IsEndOfQ(IN const DTQ_HEAD_S* pstList, IN const DTQ_NODE_S* pstNode)
{
    if (DTQ_IsEmpty(pstList))
    {
        return BOOL_TRUE;
    }

    if (NULL == pstNode)
    {
        return BOOL_TRUE;
    }

    return (pstNode == &(pstList->stHead));
}

static inline DTQ_NODE_S* DTQ_Prev(IN const DTQ_NODE_S* pstNode)
{
    return (pstNode->pstPrev);
}

static inline DTQ_NODE_S* DTQ_Next(IN const DTQ_NODE_S* pstNode)
{
    return (pstNode->pstNext);
}

static inline VOID DTQ_AddAfter(IN DTQ_NODE_S* pstPrev, IN DTQ_NODE_S* pstInst)
{
    pstInst->pstPrev = pstPrev;
    pstInst->pstNext = pstPrev->pstNext;
    pstPrev->pstNext = pstInst;
    pstInst->pstNext->pstPrev = pstInst;
    return;
}

static inline VOID DTQ_AddBefore(IN DTQ_NODE_S* pstNext, IN DTQ_NODE_S* pstInst)
{
    pstInst->pstPrev = pstNext->pstPrev;
    pstInst->pstNext = pstNext;
    pstInst->pstPrev->pstNext = pstInst;
    pstInst->pstNext->pstPrev = pstInst;
    return;
}

static inline VOID DTQ_Del(IN const DTQ_NODE_S* pstNode)
{
    pstNode->pstPrev->pstNext = pstNode->pstNext;
    pstNode->pstNext->pstPrev = pstNode->pstPrev;
    return;
}

static inline VOID DTQ_AddHead(IN DTQ_HEAD_S* pstList, IN DTQ_NODE_S* pstNode)
{
    DTQ_AddAfter(&pstList->stHead, pstNode);
    return;
}

static inline DTQ_NODE_S* DTQ_DelHead(IN const DTQ_HEAD_S* pstList)
{
    DTQ_NODE_S* pstNode = DTQ_First(pstList);
    if(DTQ_IsEndOfQ(pstList, pstNode))
    {
        pstNode = (DTQ_NODE_S *)NULL;
    }
    else
    {
        DTQ_Del(pstNode);
    }
    return pstNode;
}

static inline VOID DTQ_AddTail(IN DTQ_HEAD_S* pstList, IN DTQ_NODE_S* pstNode)
{
    DTQ_AddBefore(&pstList->stHead, pstNode);
    return;
}

static inline DTQ_NODE_S* DTQ_DelTail(IN const DTQ_HEAD_S* pstList)
{
    DTQ_NODE_S* pstNode = DTQ_Last(pstList);
    if (DTQ_IsEndOfQ(pstList, pstNode))
    {
        pstNode = (DTQ_NODE_S*)NULL;
    }
    else
    {
        DTQ_Del(pstNode);
    }
    
    return pstNode;
}

#define DTQ_FOREACH(pstList, pstNode)\
    for((pstNode) = (pstList)->stHead.pstNext;\
        ((pstNode) != &((pstList)->stHead));\
        (pstNode) = DTQ_Next(pstNode))

#define DTQ_FOREACH_SAFE(pstList, pstNode ,pstNextNode)\
    for((pstNode) = (pstList)->stHead.pstNext;\
        (((pstNode) != &((pstList)->stHead)) &&\
        ({(pstNextNode) = DTQ_Next(pstNode); BOOL_TRUE;}));\
        (pstNode) = (pstNextNode))

#define DTQ_FOREACH_REVERSE(pstList, pstNode)\
    for ((pstNode) = DTQ_Last(psList);\
        (BOOL_TRUE != DTQ_IsEndOfQ(pstList, pstNode));\
        (pstNode) = DTQ_Prev(pstNode))

#define DTQ_FOREACH_REVERSE_SAFE(pstList, pstNode, pstPrev)\
    for ((pstNode) = DTQ_Last(psList);\
        (BOOL_TRUE != DTQ_IsEndOfQ(pstList, pstNode)) && \
        ({(pstPrev) = DTQ_Prev(pstNode); BOOL_TRUE;});\
        (pstNode) = (pstPrev))

#define DTQ_ENTRY_FIRST(pstList, type, member)\
    ({DTQ_NODE_S * pstNode__Tmp__Mx = DTQ_First(pstList); \
      (NULL == pstNode__Tmp__Mx) ? NULL : DTQ_ENTRY(pstNode__Tmp__Mx, type, member);})

#define DTQ_ENTRY_LAST(pstList, type, member)\
    ({DTQ_NODE_S * pstNode__Tmp__Mx = DTQ_Last(pstList); \
      (NULL == pstNode__Tmp__Mx) ? NULL : DTQ_ENTRY(pstNode__Tmp__Mx, type, member);})

#define DTQ_ENTRY_NEXT(pstList, pstEntry, member)\
    (DTQ_IsEndOfQ(pstList, (NULL == (pstEntry) ? NULL : DTQ_Next(&((pstEntry)->member)))) ? \
     NULL : \
     DTQ_ENTRY(DTQ_Next(&((pstEntry)->member)), typeof(*(pstEntry)), member))

#define DTQ_ENTRY_PREV(pstList, pstEntry, member)\
    (DTQ_IsEndOfQ(pstList, (NULL == (pstEntry) ? NULL : DTQ_Prev(&((pstEntry)->member)))) ? \
     NULL : \
     DTQ_ENTRY(DTQ_Prev(&((pstEntry)->member)), typeof(*(pstEntry)), member))

#define DTQ_FOREACH_ENTRY(pstList, pstEntry, member)\
    for ((pstEntry) = DTQ_ENTRY((pstList)->stHead.pstNext, typeof(*(pstEntry)), member);\
          ((&(pstEntry)->member != &(pstList)->stHead) || ({pstEntry = NULL; BOOL_FALSE;}));\
          (pstEntry) = DTQ_ENTRY((pstEntry)->member.pstNext, typeof(*(pstEntry)), member))

#define DTQ_FOREACH_ENTRY_SAFE(pstList, pstEntry, pstNextEntry, member)\
    for ((pstEntry) = DTQ_ENTRY((pstList)->stHead.pstNext, typeof(*(pstEntry)),member);\
         (((&(pstEntry)->member != &(pstList)->stHead) && \
          ({(pstNextEntry) = DTQ_ENTRY((pstEntry)->member.pstNext,typeof(*(pstEntry)), member); BOOL_TRUE;})) || \
          ({pstEntry = NULL; BOOL_FALSE;}));\
          (pstEntry) = (pstNextEntry))

#define DTQ_FOREACH_ENTRY_REVERSE(pstList, pstEntry, member) \
    for ((pstEntry) = DTQ_ENTRY_LAST(pstList,typeof(*(pstEntry)),member);\
          NULL != (pstEntry);\
          (pstEntry) = DTQ_ENTRY_PREV(pstList, pstEntry, member))

#define DTQ_FOREACH_ENTRY_REVERSE_SAFE(pstList, pstEntry, pstPrevEntry, member) \
    for ((pstEntry) = DTQ_ENTRY_LAST(pstList,typeof(*(pstEntry)),member); \
          (NULL != (pstEntry)) &&  \
          ({(pstPrevEntry) = DTQ_ENTRY_PREV(pstList pstEntry, member); BOOL_TRUE;}); \
          (pstEntry) = DTQ_ENTRY_PREV(pstList, pstEntry, member))



static inline VOID DTQ_Append(IN DTQ_HEAD_S* pstDstList, IN DTQ_HEAD_S* pstSrcList)
{
    if (BOOL_TRUE != DTQ_IsEmpty(pstSrcList))
    {
        pstSrcList->stHead.pstNext->pstPrev = pstDstList->stHead.pstPrev;
        pstSrcList->stHead.pstPrev->pstNext = pstDstList->stHead.pstPrev->pstNext;
        pstDstList->stHead.pstPrev->pstNext = pstSrcList->stHead.pstNext;
        pstDstList->stHead.pstPrev = pstSrcList->stHead.pstPrev;
        DTQ_Init(pstSrcList);
    }
    return;
}

static inline VOID DTQ_FreeAll(IN DTQ_HEAD_S* pstList, IN VOID (*pfFree)(DTQ_NODE_S *))
{
    DTQ_NODE_S * pstCurNode, * pstNextNode;
    DTQ_FOREACH_SAFE(pstList, pstCurNode, pstNextNode)
    {
        pfFree(pstCurNode);
    }

    DTQ_Init(pstList);
    return;
}

#endif

