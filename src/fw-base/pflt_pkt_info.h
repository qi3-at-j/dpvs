#ifndef _PFLT_PKT_INFO_H_
#define _PFLT_PKT_INFO_H_

#include "baseype.h"
#include "../access_control/secpolicy_match.h"

typedef struct tagSecPolicyPacketIP6Ex
{
    SECPOLICY_PACKET_IP6_S stPolicy;
    BOOL_T bNIFrag;
} SECPOLICY_PACKET_IP6_EX_S;

typedef ULONG (*PFLT_GET_OPT_HDR_PF)(IN MBUF_S *pstMBuf, IN UINT uiLenTraversed,
                                     IN UCHAR ucNxtHdr, INOUT SECPOLICY_PACKET_IP6_EX_S *pstPktInfo);

extern PFLT_GET_OPT_HDR_PF g_apfGetOptHdrFunc[IPPROTO_MAX];

/* Packet FilterÄ£¿é³õÊ¼»¯ */
ULONG PFLT_Init(VOID);

#endif
