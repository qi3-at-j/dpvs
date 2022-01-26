#ifndef _FW_LIB_H_
#define _FW_LIB_H_

#include "baseype.h"
#include <stdbool.h>

//#include "../src/fw-base/in.h"

extern bool FWLIB_Check_IPv4AndMask_IsLegal(char *pcStr);
extern bool FWLIB_Check_IPv6AndPrefix_IsLegal(char *pcStr);
extern VOID FWLIB_IP4ADDR_Len2Mask(IN UINT uiLen, OUT UINT32 *puiMask);
extern VOID FWLIB_IP6ADDR_Len2Mask(IN UINT uiLen, OUT struct in6_addr *pstMask);
extern BOOL_T FWLIB_IP6_COMPARE(IN struct in6_addr *pstSrcIP6, IN struct in6_addr *pstDstIP6, IN struct in6_addr *pstMask);

#endif