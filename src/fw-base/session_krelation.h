#ifndef _SESSION_KRELATION_H_
#define _SESSION_KRELATION_H_

extern RELATION_S *SESSION_Relation_Create(VOID);

extern ULONG SESSION_Relation_Add(IN RELATION_S *pstRelation,
                           IN SESSION_S *pstParentSess,
                           IN RELATION_AGING_TYPE_E enAgingType);


extern RELATION6_S *SESSION6_Relation_Create(VOID);

extern ULONG SESSION6_Relation_Add(IN RELATION6_S *pstRelation, 
							IN SESSION_S *pstParentSess, 
							IN RELATION_AGING_TYPE_E enAgingType);


extern VOID RELATION_KReset(IN const SESSION_TABLE_KEY_S *pstKey);

extern VOID SESSION_Relation_Destroy(IN VOID *pRelation);

extern VOID SESSION6_Relation_Destroy(IN VOID *pRelation);

#endif
