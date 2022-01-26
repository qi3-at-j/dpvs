#ifndef _SESSION_KL3PROTO_H_
#define _SESSION_KL3PROTO_H_

//#include "in.h"

#include <netinet/in.h>

#define SESSION_LOOPBACK_NET ((INADDR_LOOPBACK) & 0xFF000000) /*net 127.0.0.0*/

/*IP合法性检查
  uiIPAddr IP地址(主机序)
*/
static inline BOOL_T SESSION_IPv4Addr_IsInValid(IN UINT uiIPAddr)
{
    UINT uiNet;

    if((INADDR_BROADCAST == uiIPAddr) || (INADDR_ANY == uiIPAddr))
    {
        return BOOL_TRUE;
    }

    uiNet = uiIPAddr & (0xFF000000);
    if (SESSION_LOOPBACK_NET == uiNet)
    {
        return BOOL_TRUE;
    }

    return BOOL_FALSE;
}


VOID SESSION_KL3_Init(VOID);

#endif