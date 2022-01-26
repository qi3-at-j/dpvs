#ifndef _SESSION_KHASH_H_
#define _SESSION_KHASH_H_

#include <rte_spinlock.h>
#include "extlist.h"

extern UINT g_uiSessTableHashLength;
#define SESSION_TABLE_HASH_LENGTH   g_uiSessTableHashLength           /* HASH���ȣ����ݶ��ƵĻỰ���ȷ�� */
#define SESSION_RELATIONH_HASH_LENGTH (SESSION_TABLE_HASH_LENGTH / 8) /* ��������Ϊ�Ự��1/6,HASH���ȶ�Ϊ1/8 */

#define SESSION_HASH_LOCK_NR 0x10000
#define SESSION_HASH_LOCK_MASK (SESSION_HASH_LOCK_NR-1)

typedef struct tagSessionHashTable
{
    UINT uiBucketNumber;          /* HASHͰ������Ϊ�����Ч�ʣ�����Ϊ2���� */
    UINT uiBucketMask;            /* uiBucketNumber-1, ����HASH���������� */
    rte_spinlock_t astHashLock[SESSION_HASH_LOCK_NR];
    DL_HEAD_S *pstBuckets;        /* HASHͰ���� */
} SESSION_HASH_S;

#define SESSION_HASH_MIX(a, b, c) \
{\
    a -= b; a -= c; a ^= (c>>13); \
    b -= c; b -= a; b ^= (a<<8); \
    c -= a; c -= b; c ^= (b>>13); \
}

#endif