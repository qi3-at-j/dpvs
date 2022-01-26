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
typedef unsigned char UCHAR;
#endif

#ifndef SHORT
#define SHORT short
#endif


#ifndef USHORT
typedef unsigned short USHORT;
#endif

#ifndef LONG 
#define LONG long
#endif

#ifndef ULONG
typedef unsigned long ULONG;
#endif

#ifndef UINT
typedef unsigned int UINT;
#endif

#ifndef IF_INDEX
typedef unsigned int IF_INDEX;
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

typedef void * LPVOID;

typedef unsigned long long __attribute__((aligned(8)))   UINT64;
typedef long long __attribute__((aligned(8)))            INT64;

#define BOOL_TRUE    ((uint16_t)1)
#define BOOL_FALSE   ((uint16_t)0)

#define ENABLE 1
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

#define BIT_TEST(val, bit)    (val & (1UL << bit))
#define BIT_SET(val, bit)     (val |= (1UL << (bit)))
#define BIT_CLEAR(val, bit)   (val &= ~(1UL << (bit)))
#define IF_INVALID_INDEX   0UL
#define DBGASSERT(x)

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif /* likely */

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif /* unlikely */

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((UINT64) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
    (type *)((char *)(ptr) - (char *) &((type *)0)->member)
#endif

/*
 * time_after(a,b) returns true if the time a is after time b.
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A
 * good compiler would generate better code (and a really good compiler
 * wouldn't care). Gcc is currently neither.
 */
#define time_after(a, b)	((long)((b) - (a)) < 0)
#define time_before(a, b)	time_after(b, a)

#define time_after_eq(a, b)     ((long)((a) - (b)) >= 0)
#define time_before_eq(a, b)	time_after_eq(b, a)

#define HZ    1000

typedef ULONG SESSION_HANDLE;

#ifndef MAX
#define MAX(v1, v2)	((v1) > (v2) ? (v1) : (v2))
#endif
#ifndef MIN
#define MIN(v1, v2)	((v1) < (v2) ? (v1) : (v2))
#endif

#endif
