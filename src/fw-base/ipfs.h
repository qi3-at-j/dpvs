#ifndef _IPFS_H_
#define _IPFS_H_

#include "hash.h"

#define IPFS_DIRECTION_ORIGINAL 0
#define IPFS_DIRECTION_REPLY    1

#define IPFS_ROUTETYPE_FIB      0
#define IPFS_ROUTETYPE_PBR      1

#define IPFS_ADJTYPE_ADJ        0
#define IPFS_ADJTYPE_NHLFE      1
#define IPFS_ADJTYPE_OFP        2


/* ��ת�����ͣ�������ת������ʱ��ע�ⲻ����ͬ��������������ת��������һ��ת������������keyһ�������ֻ����һ����ת�� */
#define IPFS_CACHEKEYFLAG_MACFW  0x1
#define IPFS_CACHEKEYFLAG_BRIDGE 0x2
#define IPFS_CACHEKEYFLAG_GRE    0x4
#define IPFS_CACHEKEYFLAG_INLINE 0x8
#define IPFS_CACHEKEYFLAG_L2     0x0B
#define IPFS_CACHEKEYFLAG_SRVCHN 0x10

/* ��ת����Я����ҵ���� */
#define IPFS_FLAG_NODELSERVICE   0x1    /* ����Ҫɾ��pservice */
#define IPFS_FLAG_FIBSTAT        0x2    /* FIBͳ�Ʊ�� */
#define IPFS_FLAG_VPNSTAT        0x4    /* VPNͳ��ʹ�� */
#define IPFS_FLAG_IPRELAY        0x8    /* IP RELAY ���Ľ����Ŀ�ת */

/* ��ת����ȱʡ�ϻ�ʱ��(s)*/
#define IPFS_CACHE_AGING_TIME    30

#endif
