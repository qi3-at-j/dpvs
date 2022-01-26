#ifndef _PFILTER_MATCH_H_
#define _PFILTER_MATCH_H_

#ifndef _BASETYPE_H_
#include "baseype.h"
#endif

typedef struct tagPfilterPacketIP4
{
    UINT   uiIndex;
	UINT   uiSrcIP;
	UINT   uiDstIP;
	USHORT usSPort;
	USHORT usDPort;
	UCHAR  ucProto;
}PFILTER_PACKET_IPV4_S;


typedef struct tagPfilterPacketIP6
{
    UINT   uiIndex;
	struct in6_addr stSrcIP6;
	struct in6_addr stDstIP6;
	USHORT usSPort;
	USHORT usDPort;
	UCHAR  ucProto;
}PFILTER_PACKET_IPV6_S;

extern BOOL_T Pfilter_Match_IPv4(IN PFILTER_PACKET_IPV4_S *pstPfilterPacket);
extern BOOL_T Pfilter_Match_IPv6(IN PFILTER_PACKET_IPV6_S *pstPfilterPacket);
#endif