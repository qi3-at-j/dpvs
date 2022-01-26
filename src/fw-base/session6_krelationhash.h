#ifndef __SESSION6_KRELATIONHASH_H__
#define __SESSION6_KRELATIONHASH_H__


extern ULONG SESSION6_RelationHash_Add(IN RELATION6_S *pstRelation);

extern VOID SESSION6_RelationHash_Delete(IN RELATION6_S *pstRelation);

extern RELATION6_S *SESSION6_RelationHash_Find(IN const csp_key_t *pstIp6fsKey);

#endif
