#ifndef _IP6FW_H_
#define _IP6FW_H_

#include "error.h"
//#include "in.h"


#include <netinet/in.h>

#include "session_mbuf.h"

/* IPv6版本 */
#define IPV6_VERSION      0x6

/* IPV6报文载荷的最大长度 */
#define IPV6_MAXPACKET    65535

/* IPv6 报文头 */
typedef struct tagIP6_S
{
    union
    {
        struct tagIP6_HDRCTL
        {
            UINT32 uiIp6TclassFlow;    /* 4 bits unused, 8 bits traffic class and 20 bits of flow-ID */
            UINT16 usIp6PLen;          /* payload length */
            UINT8 ucIp6Nxt;            /* next header */ 
            UINT8 ucIp6HLim;           /* hop limit */
        } stIp6Ctl1;

        struct tagIP6_HDRCTL1
        {
            #if defined(_LITTLE_ENDIAN_BITFIELD)
            UINT8 ucIp6Unused:4;       /* traffic class */
            UINT8 ucIp6Ver:4;          /* version */
            #elif defined(_BIG_ENDIAN_BITFIELD)
            UINT8 ucIp6Ver:4;          /* version */
            UINT8 ucIp6Unused:4;       /* traffic class */
            #else
            #error "Adjust your <asm/byteorder.h> defines"
            #endif
        } stIp6Ctl2;
    } unIp6Ctl;

    struct in6_addr stIp6Src;                /* source address */
    struct in6_addr stIp6Dst;                /* destination address */
} IP6_S;

#define ip6_ucVer    unIp6Ctl.stIp6Ctl2.ucIp6Ver
#define ip6_uiFlow   unIp6Ctl.stIp6Ctl1.uiIp6TclassFlow
#define ip6_usPLen   unIp6Ctl.stIp6Ctl1.usIp6PLen
#define ip6_ucNxtHdr unIp6Ctl.stIp6Ctl1.ucIp6Nxt
#define ip6_ucHLim   unIptCtl.stIp6Ctl1.ucIp6HLim


/* 根据扩展头相对于IPv6头的偏移和扩展头长度，获取扩展头指针.
   uiOff, 扩展头相对于IPv6头的偏移;
   uiLen, 扩展头需要进行连续的长度
   uiMid, 模块ID
*/
static inline VOID* IP6_GetExtHdr(IN MBUF_S *pstMBuf, IN UINT uiOff, IN UINT uiLen)
{
    ULONG ulRet;
    VOID *pstExt = NULL;

    ulRet = MBUF_PULLUP(pstMBuf, uiOff + uiLen);
    if(ERROR_SUCCESS == ulRet)
    {
        pstExt = (VOID *)(MBUF_BTOD(pstMBuf, UCHAR *) + uiOff);
    }

    return pstExt;
}


static inline VOID* IP6_GetBufExtHdr(IN const MBUF_S *pstMBuf, IN UINT uiOff)
{
	VOID *pstExt = NULL;

	pstExt = (VOID *)(MBUF_BTOD_OFFSET(pstMBuf, 0U, UCHAR *) + uiOff);

	return pstExt;
}

#endif
