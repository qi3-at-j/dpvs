#ifndef _BASETYPE_H_
#define _BASETYPE_H_

#ifndef STATIC
#define STATIC static
#endif

#ifndef INLINE
#define INLINE inline
#endif

#ifndef VOID
#define VOID void
#endif

#ifndef CHAR
#define CHAR char
#endif

#ifndef UCHAR
#define UCHAR unsigned char
#endif

#ifndef SHORT
#define SHORT short
#endif


#ifndef USHORT
#define USHORT unsigned short
#endif

#ifndef LONG 
#define LONG long
#endif

#ifndef ULONG
#define ULONG unsigned long
#endif

#ifndef UINT
#define UINT unsigned int
#endif

#ifndef IF_INDEX
#define IF_INDEX unsigned int
#endif

#ifndef INT
#define INT int
#endif

#ifndef BOOL_T
typedef USHORT BOOL_T;
#endif

#ifndef FLOAT
#define FLOAT float
#endif

#ifndef DOUBLE
#define DOUBLE double
#endif

#ifndef INT8
#define INT8 CHAR
#endif

#ifndef UINT8
#define UINT8 UCHAR
#endif

#ifndef INT16
#define INT16 SHORT
#endif

#ifndef UINT16
#define UINT16 USHORT
#endif

#ifndef INT32
#define INT32 INT
#endif

#ifndef UINT32
#define UINT32 UINT
#endif

#ifndef VRF_INDEX
#define VRF_INDEX USHORT
#endif

#ifndef MT_INDEX
#define MT_INDEX USHORT
#endif

#ifndef VRF_ANY
#define VRF_ANY (VRF_INDEX)0xffff
#endif

#ifndef LIP_ADDR
#define LIP_ADDR USHORT
#endif

#ifndef ZONE_ID
#define ZONE_ID USHORT
#endif

#ifndef NULL
#define NULL 0
#endif

typedef void * LPVOID;

typedef unsigned long long __attribute__((aligned(8)))   UINT64;
typedef long long __attribute__((aligned(8)))            INT64;

#define BOOL_TRUE    ((BOOL_T)1)
#define BOOL_FALSE   ((BOOL_T)0)

#define ENABALE 1
#define DISABLE 2

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif

#define MAC_ADDR_LEN 6

#define IGNORE_PARAM(x)  ((x) = (x))

typedef ULONG SESSION_HANDLE;

#endif
