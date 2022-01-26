#ifndef _SECBASETYPE_H_
#define _SECBASETYPE_H_

#ifdef __cplusplus
extern "C"{
#endif

#define PORT_ID_MIN 0
#define PORT_ID_MAX 65535
#define PROTOCOL_ID_MAX 255


#if 0

#ifndef BIT_TEST
#define BIT_TEST(f, b) (0 != ((f) & (b)))
#endif

#ifndef BIT_SET
#define BIT_SET(f, b) ((f) |= (b))
#endif

#ifndef BIT_RESET
#define BIT_RESET(f, b) ((f) &= ~(b))
#endif

#ifndef BIT_MATCH
#define BIT_MATCH(f, b) (((f) & (b)) == (b))
#endif

#ifndef BIT_COMPARE
#define BIT_COMPARE(f, b1, b2) (((f) & (b1)) == (b2))
#endif


#define __JHASH_MIX(uia, uib, uic) \
{ \
    uia -= uib; uia -= uic; uia ^= (uic>>13); \
    uib -= uic; uib -= uia; uib ^= (uia<<8);  \
    uic -= uia; uic -= uib; uic ^= (uib>>13); \
    uia -= uib; uia -= uic; uia ^= (uic>>12); \
    uib -= uic; uib -= uia; uib ^= (uia<<16); \
    uic -= uia; uic -= uib; uic ^= (uib>>5);  \
    uia -= uib; uia -= uic; uia ^= (uic>>3);  \
    uib -= uic; uib -= uia; uib ^= (uia<<10); \
    uic -= uia; uic -= uib; uic ^= (uib>>15); \
}

#define JHASH_GOLDEN_RATIO 0x9e3779b9    

UINT JHASH_GeneralBuffer(const VOID *pkey, UINT uiLen)
{
    UINT uia, uib, uic, uiRemainlen;
    const UCHAR *pucKey = (const UCHAR *)pkey;

    uiRemainlen = uiLen;
    uia = uib = JHASH_GOLDEN_RATIO;
    uic = 0;

    while (uiRemainlen >= 12)
    {
        uia += (pucKey[0] + ((UINT)pucKey[1]<<8) + ((UINT)pucKey[2]<<16) + ((UINT)pucKey[3]<<24));
        uib += (pucKey[4] + ((UINT)pucKey[5]<<8) + ((UINT)pucKey[6]<<16) + ((UINT)pucKey[7]<<24));
        uic += (pucKey[8] + ((UINT)pucKey[9]<<8) + ((UINT)pucKey[10]<<16) + ((UINT)pucKey[11]<<24));

        __JHASH_MIX(uia, uib, uic);
        pucKey   += 12;
        uiRemainlen -= 12;
    }

    switch(uiRemainlen)
    {
        case 11:
            uic += ((UINT)pucKey[10]<<24);
        case 10:
            uic += ((UINT)pucKey[9]<<16);
        case 9:
            uic += ((UINT)pucKey[8]<<8);
        case 8:
            uib += ((UINT)pucKey[7]<<24);
        case 7:
            uib += ((UINT)pucKey[6]<<16);
        case 6:
            uib += ((UINT)pucKey[5]<<8);
        case 5:
            uib += pucKey[4];
        case 4:
            uia += ((UINT)pucKey[3]<<24);
        case 3:
            uia += ((UINT)pucKey[2]<<16);
        case 2:
            uia += ((UINT)pucKey[1]<<8);
        case 1:
            uia += pucKey[0];
        default:
            uic += uiLen;
    }

    __JHASH_MIX(uia,uib,uic);

    return uic;
}


ULONG SecPolicy_GetHashKey(IN const VOID *pKey)
{
    ULONG ulKey = 0;
    UINT uiLen = 0;
    ulKey = JHASH_GeneralBuffer(pKey, (UINT)uiLen);
    ulKey = ulKey % 0xffff;
    return ulKey;    
}
#endif

extern unsigned int strlcpy(unsigned char *dst, const unsigned char *src, unsigned int siz);
extern unsigned int strlcat(unsigned char *dst, const unsigned char *src, unsigned int siz);

#ifdef __cplusplus
}
#endif

#endif
