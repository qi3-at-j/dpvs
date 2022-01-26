
#ifndef _SESSION_KRELATIONHASH_H_
#define _SESSION_KRELATIONHASH_H_


extern ULONG SESSION_RelationHash_Add(IN RELATION_S *pstRelation);
extern VOID SESSION_RelationHash_Delete(IN RELATION_S *pstRelation);
extern RELATION_S *SESSION_RelationHash_Find(IN const csp_key_t *pstcspkey);
extern ULONG SESSION_RelationHash_Init(VOID);



#endif
