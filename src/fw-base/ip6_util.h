
#ifndef _IP6_UTIL_H_
#define _IP6_UTIL_H_

ULONG IP6_GetBufLastHdr (IN const MBUF_S *pstMBuf, INOUT UINT *puiOff, INOUT UCHAR *pucProto);
ULONG IP6_GetLastHdr(IN MBUF_S *pstMBuf, INOUT UINT *puiOff, INOUT UCHAR *pucProto);

#endif
