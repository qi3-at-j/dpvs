#ifndef _SESSION_KL4PROTO_H_
#define _SESSION_KL4PROTO_H_

#include "baseype.h"

#define ICMPV6_RANG_OFFSET 127

ULONG SESSION_KL4PROTO_Init(VOID);


ULONG SESSION_KGetValidL4Payload(IN MBUF_S *pstMBuf, 
                                 IN UCHAR ucProtocol,
                                 IN UINT uiL4OffSet,
                                 OUT UINT *puiPayloadOff,
                                 OUT UINT *puiPayloadLen);
#endif
