#ifndef _PFILTER_H_
#define _PFILTER_H_

#ifdef __cplusplus
extern "C"{
#endif


#include <netinet/in.h>

#include "baseype.h"
#include "extlist.h"
//#include "../fw-base/in.h"
#include <rte_rwlock.h>

typedef struct tagPFilterAddr
{
    unsigned int uiIPMask;
    union
    {
        struct in6_addr stIP6Addr;
        struct in_addr  stIP4Addr;
    } un_addr;
}PFILTER_ADDR_S;


typedef struct tagPfilterData
{
    UINT uiIndex;  //<1 -16>
    UINT uiRuleID;
    UINT uiIPType;     /* MY_IPPROTO_IPV4  MY_IPPROTO_IPV6 */
    UINT uiMatchMask;
    USHORT usSPort;
    USHORT usDPort;
    UCHAR  ucProtocol;
    PFILTER_ADDR_S stSrcIP;
    PFILTER_ADDR_S stDstIP;
}PFILTER_DATA_S;

#define PFILTER_COUNT_MAX           17
    
#define PFILTER_MATCH_TYPE_SIP      0x1
#define PFILTER_MATCH_TYPE_DIP      0x2
#define PFILTER_MATCH_TYPE_SPORT    0x4
#define PFILTER_MATCH_TYPE_DPORT    0x8
#define PFILTER_MATCH_TYPE_PROTOCOL 0x10
    
typedef struct tagPfilterConf
{
    DTQ_NODE_S  stNode;
    PFILTER_DATA_S stPfilterData;
}PFILTER_CONF_S;

#define PFILTER_DEBUG_PACKET    0x1

struct tagpFilterHead
{
    DTQ_HEAD_S stIP4Head;
    DTQ_HEAD_S stIP6Head;
    UINT uiIP4DebugFlag;
    UINT uiIP6DebugFlag;
    rte_rwlock_t stPfilter_rwlock;
}g_stPfilterConf[PFILTER_COUNT_MAX];

extern ULONG Pfilter_Add(IN PFILTER_DATA_S *pstPfliterData);
extern ULONG Pfilter_Del(IN UINT uiIndex, IN UINT uiIPType, IN UINT uiRuleID);
extern ULONG Pfilter_Modify(IN PFILTER_DATA_S *pstPfilterData, IN BOOL_T bIsUnSet);
extern VOID  Pfilter_Get(IN UINT uiIndex, IN UINT uiIPType, IN UINT uiRuleID);
extern VOID  Pfilter_SetDebug(IN UINT uiIndex, IN UINT uiIPType, IN UINT uiDebugType, IN BOOL_T bIsUndo);
extern VOID Pfilter_GetDebug(IN UINT uiIndex, IN UINT uiIPType);

extern VOID Pfilter_Init(void);
extern VOID Pfilter_Fini(void);

#ifdef __cplusplus
}
#endif
#endif
