#ifndef _SECPOLICY_MATCH_H_
#define _SECPOLICY_MATCH_H_

#ifdef __cplusplus
extern "C"{
#endif

#include "basetype.h"

/*#include "in.h"*/


#include <netinet/in.h>

#include "secpolicy_common.h"

#define MBUF_CONTIUNE    1
#define MBUF_DESTORY     2

typedef struct tagSecPolicyPacketIP4
{
    UINT uiVxlanID;
    SECPOLICY_DIRECTION_E   enFwDirect;     /* 内到外 SECPOLICY_DIRECTION_IN2OUT       外到内 SECPOLICY_DIRECTION_OUT2IN*/
    struct in_addr stSrcIP;
    struct in_addr stDstIP;
    UCHAR ucProtocol;  /* tcp udp icmp icmp6 any */
    USHORT usSPort;
    USHORT usDPort;
    SECPOLICY_ICMP_S stIcmp;
    UINT uiAppID;
}SECPOLICY_PACKET_IP4_S;

typedef struct tagSecPolicyPacketIP6
{
    UINT uiVxlanID;
    SECPOLICY_DIRECTION_E   enFwDirect;     
    struct in6_addr stSrcIP6;
    struct in6_addr stDstIP6;
    UCHAR ucProtocol;  /* tcp udp icmp icmp6 any */
    USHORT usSPort;
    USHORT usDPort;
    SECPOLICY_ICMP_S stIcmp; 
    UINT uiAppID;
}SECPOLICY_PACKET_IP6_S;

extern SECPOLICY_ACTION_E SecPolicy_Match_IP4(IN SECPOLICY_PACKET_IP4_S *pstSecPolicyPacketIP4);
extern SECPOLICY_ACTION_E SecPolicy_Match_IP6(IN SECPOLICY_PACKET_IP6_S *pstSecPolicyPacketIP6);
extern BOOL_T SecPolicy_IP4_IsNeedAPR(IN unsigned int uiVrf, IN struct in_addr *pstSrcIP, IN struct in_addr *pstDstIP);
extern BOOL_T SecPolicy_IP6_IsNeedAPR(IN unsigned int uiVrf, IN struct in6_addr *pstSrcIP6, IN struct in6_addr *pstDstIP6);
extern SECPOLICY_DIRECTION_E SecPolicy_IP4_FlowDirect(unsigned int uiVxlanID, struct in_addr  stSrcIP,  struct in_addr stDstIP);
extern SECPOLICY_DIRECTION_E SecPolicy_IP6_FlowDirect(unsigned int uiVxlanID, struct in6_addr stSrcIP6, struct in6_addr stDstIP6);

/* 计算校验和 */
static SHORT checksum(USHORT* buffer, int size)
{
    unsigned long cksum = 0;
    while(size>1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if(size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum>>16) + (cksum&0xffff); 
    cksum += (cksum>>16); 
    return (USHORT)(~cksum);
} 


#ifdef __cplusplus
}
#endif

#endif

