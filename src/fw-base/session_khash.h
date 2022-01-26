#ifndef _SESSION_KHASH_H_
#define _SESSION_KHASH_H_

#include <rte_spinlock.h>
#include "extlist.h"

extern UINT g_uiSessTableHashLength;
#define SESSION_TABLE_HASH_LENGTH   g_uiSessTableHashLength           /* HASH表长度，根据定制的会话规格确定 */
#define SESSION_RELATIONH_HASH_LENGTH (SESSION_TABLE_HASH_LENGTH / 8) /* 关联表规格为会话表1/6,HASH长度定为1/8 */

#define SESSION_HASH_LOCK_NR 0x10000
#define SESSION_HASH_LOCK_MASK (SESSION_HASH_LOCK_NR-1)

typedef struct tagSessionHashTable
{
    UINT uiBucketNumber;          /* HASH桶个数，为了提高效率，必须为2的幂 */
    UINT uiBucketMask;            /* uiBucketNumber-1, 计算HASH索引的掩码 */
    rte_spinlock_t astHashLock[SESSION_HASH_LOCK_NR];
    DL_HEAD_S *pstBuckets;        /* HASH桶数组 */
} SESSION_HASH_S;

#define SESSION_HASH_MIX(a, b, c) \
{\
    a -= b; a -= c; a ^= (c>>13); \
    b -= c; b -= a; b ^= (a<<8); \
    c -= a; c -= b; c ^= (b>>13); \
}

#endif