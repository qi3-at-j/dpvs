#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "fw_lib.h"

#define IN6ADDR_SIZE32 4

/* Check the legality, In the form of x.x.x.x/x */
bool FWLIB_Check_IPv4AndMask_IsLegal(char *pcStr)
{
    int i = 0, ilen = strlen(pcStr);
    bool b = true;
    char *pc = pcStr;

    if (0 == pcStr)
    {
        return false;
    }

    while(i < ilen)
    {
        if (!isdigit(*(pc+i)) && (*(pc+i) != '.') && (*(pc+i) != '/'))
        {
            b = false;
            break;
        }
        i++;
    }
    return b;
}

/* Check the legality, In the form of x.x.x.x/x */
bool FWLIB_Check_IPv6AndPrefix_IsLegal(char *pcStr)
{
    int i = 0, ilen = strlen(pcStr);
    bool b = true;
    char *pc = pcStr;

    if (0 == pcStr)
    {
        return false;
    }

    while(i < ilen)
    {
        if (!isxdigit(*(pc+i)) && (*(pc+i) != ':') && (*(pc+i) != '/'))
        {
            b = false;
            break;
        }
        i++;
    }
    return b;
}

VOID FWLIB_IP4ADDR_Len2Mask(IN UINT uiLen, OUT UINT32 *puiMask)
{
    UINT uiMask;
    if (0 == uiLen)
    {
        uiMask = 0;
    }
    else
    {
        uiMask = 0xFFFFFFFF << (32 - uiLen);
    }

    /* The IP mask is converted to the network sequence  */
    *puiMask = htonl(uiMask);
    return;
}

VOID FWLIB_IP6ADDR_Len2Mask(IN UINT uiLen, OUT struct in6_addr *pstMask)
{
    UINT uiUintLen, uiBitLen, uiLoop, *puiMask;

    puiMask = pstMask->s6_addr32;
    puiMask[0] = 0;
    puiMask[1] = 0;
    puiMask[2] = 0;
    puiMask[3] = 0;

    uiUintLen = uiLen >> 5;
    uiBitLen  = uiLen &31;

    for(uiLoop = 0; uiLoop < uiUintLen; uiLoop++)
    {
        puiMask[uiLoop] = 0xffffffff;
    }

    if (uiBitLen != 0)
    {
        puiMask[uiUintLen] = 0xffffffff << (32 - uiBitLen);

        /* converted to the network sequence */
        puiMask[uiUintLen] = htonl(puiMask[uiUintLen]);
    }
    

    return;
}

/* Compare the two IPv6 addresses */
BOOL_T FWLIB_IP6_COMPARE(IN struct in6_addr *pstSrcIP6, IN struct in6_addr *pstDstIP6, IN struct in6_addr *pstMask)
{
    struct in6_addr stSrcIP6, stDstIP6;
    UINT uiLoop;
    BOOL_T bIsEqual = BOOL_TRUE;

    stSrcIP6.s6_addr32[0] = pstSrcIP6->s6_addr32[0] & pstMask->s6_addr32[0];
    stSrcIP6.s6_addr32[1] = pstSrcIP6->s6_addr32[1] & pstMask->s6_addr32[1];
    stSrcIP6.s6_addr32[2] = pstSrcIP6->s6_addr32[2] & pstMask->s6_addr32[2];
    stSrcIP6.s6_addr32[3] = pstSrcIP6->s6_addr32[3] & pstMask->s6_addr32[3];

    stDstIP6.s6_addr32[0] = pstDstIP6->s6_addr32[0] & pstMask->s6_addr32[0];
    stDstIP6.s6_addr32[1] = pstDstIP6->s6_addr32[1] & pstMask->s6_addr32[1];
    stDstIP6.s6_addr32[2] = pstDstIP6->s6_addr32[2] & pstMask->s6_addr32[2];
    stDstIP6.s6_addr32[3] = pstDstIP6->s6_addr32[3] & pstMask->s6_addr32[3];

    for (uiLoop = 0; uiLoop < IN6ADDR_SIZE32; uiLoop++)
    {
        if (stSrcIP6.s6_addr32[uiLoop] != stDstIP6.s6_addr32[uiLoop])
        {
            bIsEqual = BOOL_FALSE;
            break;
        }
    }

    return bIsEqual;
}
