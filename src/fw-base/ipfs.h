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


/* 快转表类型，新增加转发类型时须注意不允许同条流产生两条快转表的情况，一个转发类型在其他key一样情况下只能有一条快转表 */
#define IPFS_CACHEKEYFLAG_MACFW  0x1
#define IPFS_CACHEKEYFLAG_BRIDGE 0x2
#define IPFS_CACHEKEYFLAG_GRE    0x4
#define IPFS_CACHEKEYFLAG_INLINE 0x8
#define IPFS_CACHEKEYFLAG_L2     0x0B
#define IPFS_CACHEKEYFLAG_SRVCHN 0x10

/* 快转表里携带的业务标记 */
#define IPFS_FLAG_NODELSERVICE   0x1    /* 不需要删除pservice */
#define IPFS_FLAG_FIBSTAT        0x2    /* FIB统计标记 */
#define IPFS_FLAG_VPNSTAT        0x4    /* VPN统计使能 */
#define IPFS_FLAG_IPRELAY        0x8    /* IP RELAY 报文建立的快转 */

/* 快转表项缺省老化时间(s)*/
#define IPFS_CACHE_AGING_TIME    30

#endif
