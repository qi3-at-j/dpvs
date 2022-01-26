
#ifndef _ASPF_KUTIL_H_
#define _ASPF_KUTIL_H_

extern BOOL_T ASPF_kutil_ipv4_IsIcmpReplay(IN UCHAR ucType, IN UCHAR ucCode);
extern BOOL_T ASPF_kutil_ipv6_IsIcmpReplay(IN UCHAR ucType, IN UCHAR ucCode);
extern BOOL_T ASPF_kutil_ipv6_IsIcmpv6Nd(IN MBUF_S *pstMBuf, IN USHORT usL3Offset);
extern ULONG ASPF_kutil_ipv6_GetL4Proto(IN MBUF_S *pstMBuf,
                                 IN USHORT usL3Offset,
                                 OUT UCHAR *pucL4Proto,
                                 OUT USHORT *pusL4Offset);

extern BOOL_T ASPF_kutil_ipv6_IsIcmpv6Replay(IN UCHAR ucType, IN UCHAR ucCode);

#endif