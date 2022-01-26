#ifndef _SESSION_EXT_H_
#define _SESSION_EXT_H_

#include "session.h"

/*****************************************************************************
ASPF快转处理（不区分IPv4和IPV6）
*************************************************************************/
static inline ULONG SESSION_Proc_Aspf(IN const SESSION_S *pstSession,
									  IN MBUF_S *pstMbuf)
{
	return PKT_DROPPED;
}
#endif