
#ifndef __NODE_COMMON_PRIV_H__
#define __NODE_COMMON_PRIV_H__

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_net.h>
#include <rte_vxlan.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>

#include "l3_node_priv.h"
#include "vxlan_ctrl_priv.h"
#include "log_priv.h"

/* for each mbuf including heading mbuf and segments */
#define new_mbuf_foreach(m, pos)    \
    for (pos = m; pos != NULL; pos = pos->next)

/* for each segments of mbuf */
#define new_mbuf_foreach_seg(m, s)    \
    for (s = m->next; s != NULL; s = s->next)

#define new_mbuf_foreach_seg_safe(m, n, s)    \
    for (s = m->next, n = s ? s->next : NULL; \
        s != NULL; \
        s = n, n = s ? s->next : NULL)

static __rte_always_inline void *
new_mbuf_tail_point(const struct rte_mbuf *mbuf)
{
    return rte_pktmbuf_mtod_offset(mbuf, void *, mbuf->data_len);
}

/**
 * mbuf_copy_bits - copy bits from mbuf to buffer.
 * see skb_copy_bits().
 */
static __rte_always_inline int 
new_mbuf_copy_bits(const struct rte_mbuf *mbuf,
                 int offset, void *in_to, int len)
{
    const struct rte_mbuf *seg;
    int start, copy, end;
	char *to = in_to;

    if (offset + len > (int)mbuf->pkt_len)
        return -1;

    start = 0;
    new_mbuf_foreach(mbuf, seg) {
        end = start + seg->data_len;

        if ((copy = end - offset) > 0) {
            if (copy > len)
                copy = len;

            rte_memcpy(to, rte_pktmbuf_mtod_offset(
                        seg, void *, offset - start),
                   copy);

            if ((len -= copy) == 0)
                return 0;
            offset += copy;
            to += copy;
        }

        start = end;
    }

    if (!len)
        return 0;

    return -1;
}

static __rte_always_inline int
new_mbuf_may_pull(struct rte_mbuf *mbuf, unsigned int len)
{
    int delta, eat;
    struct rte_mbuf *seg, *next;

    if (likely(len <= mbuf->data_len))
        return 0;

    if (unlikely(len > mbuf->pkt_len))
        return -1;

    delta = len - mbuf->data_len;

    /* different from skb, there's no way to expand mbuf's tail room,
     * because mbuf size is determined when init mbuf pool */
    if (rte_pktmbuf_tailroom(mbuf) < delta) {
        //node_err("ip4_rcv", "%s: no tail room\n", __func__);
        L3_DEBUG_TRACE(L3_ERR, "%s: no tail room\n", __func__);
        return -1;
    }

    /* pull bits needed from segments to tail room of heading mbuf */
    if (new_mbuf_copy_bits(mbuf, mbuf->data_len,
               new_mbuf_tail_point(mbuf), delta) != 0)
        return -1;

    /* free fully eaten segments and leave left segs attached,
     * points need be reload if partial bits was eaten for a seg. */
    eat = delta;
    new_mbuf_foreach_seg_safe(mbuf, next, seg) {
        if (eat <= 0)
            break;

        if (seg->data_len <= eat) {
            assert(mbuf->next == seg);
            eat -= seg->data_len;
            rte_pktmbuf_free_seg(seg);
            mbuf->next = next;
            mbuf->nb_segs--;
        } else {
            rte_pktmbuf_adj(seg, eat);
            eat = 0;
            break;
        }
    }

    assert(!eat && mbuf->data_off + mbuf->data_len + delta <= mbuf->buf_len);

    /* mbuf points must be updated */
    mbuf->data_len += delta;

    return 0;
}

#define USE_HASH_3 1

#if USE_HASH_3
#define	MY_PRIME_VALUE	0xeaad8405
//boundary must be log2
static inline uint32_t
my_hash3(uint8_t af, union inet_addr *ip, uint32_t boundary)
{
    uint32_t v;
    const uint32_t *p = (const uint32_t *)ip;

    if (af == AF_INET) {
#ifdef RTE_ARCH_X86
        v = rte_hash_crc_4byte(p[0], MY_PRIME_VALUE);
#else   
        v = rte_jhash_1word(p[0], MY_PRIME_VALUE);
#endif /* RTE_ARCH_X86 */
    } else {        
#ifdef RTE_ARCH_X86
        v = rte_hash_crc_4byte(p[0], MY_PRIME_VALUE);
        v = rte_hash_crc_4byte(p[1], v);
        v = rte_hash_crc_4byte(p[2], v);
        v = rte_hash_crc_4byte(p[3], v);
#else   
        v = rte_jhash_2words(p[0], p[1], MY_PRIME_VALUE);
        v = rte_jhash_2words(p[2], p[3], v);
#endif /* RTE_ARCH_X86 */
    }

    return (v & (boundary - 1));
}
#else
//boundary must be log2
static inline uint32_t
my_hash2(const void *key, uint32_t length, uint32_t boundary)
{
    uint32_t value = rte_jhash(key, length, 0);
    return (value & (boundary - 1));
}
#endif

//boundary must be log2
static inline uint32_t
my_hash1(uint32_t value, uint32_t boundary)
{
#if USE_HASH_3
    return (my_hash3(AF_INET, (union inet_addr *)&value, boundary));
#else
    return (value & (boundary - 1));
#endif
}

static inline bool new_entry(char *name, uint32_t socket_id, uint32_t size,
    void *s_node, void **d_node)
{
    *d_node = rte_zmalloc_socket(name, size, RTE_CACHE_LINE_SIZE, socket_id);
    if (unlikely(*d_node == NULL)) {
        return false;
    }

    rte_memcpy(*d_node, s_node, size);
    return true;
}

#define HLIST_TABLE_INIT(num, table, member1) do {\
    int i;\
\
    for (i = 0; i < num; i++)\
        INIT_HLIST_HEAD(&(table).member1[i]);\
\
} while(0)

#define HLIST_TABLE_LOOKUP(v, b, hash, pos, table, member1, member2, member4) do {\
    uint32_t key;\
\
    key = hash(v, b);\
    hlist_for_each_entry(pos, &(table).member1[key], member2) {\
        if ((pos)->member4 == v) {\
            return pos;\
        }\
    }\
\
    return NULL;\
} while(0)

#define HLIST_TABLE_ADD(v, b, hash, node, table, member1, member3) do {\
    uint32_t key = hash(v, b);\
\
    hlist_add_head(&(node), &(table).member1[key]);\
    rte_atomic32_inc(&(table).member3);\
} while(0)

#define HLIST_TABLE_DEL(v, b, hash, pos, table, member1, member2, member3, member4) do {\
    uint32_t key;\
\
    key = hash(v, b);\
    hlist_for_each_entry(pos, &(table).member1[key], member2) {\
        if ((pos)->member4 == v) {\
            hlist_del(&(pos)->member2);\
            rte_atomic32_dec(&(table).member3);\
            rte_free((void *)(pos));\
            return 0;\
        }\
    }\
\
    return -ENOENT;\
} while(0)

#define HLIST_TABLE_CLEAR(num, pos, table, member1, member2, member3) do {\
    int i;\
    struct hlist_node *next_node;\
\
    for (i = 0; i < num; i++) {\
        hlist_for_each_entry_safe(pos, next_node,\
            &(table).member1[i], member2) {\
            hlist_del(&(pos)->member2);\
            rte_atomic32_dec(&(table).member3);\
            rte_free((void *)(pos));\
        }\
    }\
\
} while(0)

/* internal */
static inline void
pktmbuf_copy_hdr(struct rte_mbuf *mdst, struct rte_mbuf *msrc)
{
    mdst->port = msrc->port;
    mdst->vlan_tci = msrc->vlan_tci;
    mdst->vlan_tci_outer = msrc->vlan_tci_outer;
    mdst->tx_offload = msrc->tx_offload;
    mdst->hash = msrc->hash;
    mdst->packet_type = msrc->packet_type;
    rte_memcpy(&mdst->dynfield1, msrc->dynfield1,
        sizeof(mdst->dynfield1));
    rte_memcpy(rte_mbuf_to_priv(mdst),
        rte_mbuf_to_priv(msrc), msrc->priv_size);
}

#if 0
static __rte_always_inline void
cpy_vxlan_info(struct rte_mbuf *mdst, struct rte_mbuf *msrc)
{
    GET_MBUF_PRIV_DATA(mdst)->priv_data_is_vxlan =
        GET_MBUF_PRIV_DATA(msrc)->priv_data_is_vxlan;
    GET_MBUF_PRIV_DATA(mdst)->priv_data_vxlan_hdr =
        GET_MBUF_PRIV_DATA(msrc)->priv_data_vxlan_hdr;
    GET_MBUF_PRIV_DATA(mdst)->priv_data_vxlan_family =
        GET_MBUF_PRIV_DATA(msrc)->priv_data_vxlan_family;
    GET_MBUF_PRIV_DATA(mdst)->priv_data_vxlan_src_addr =
        GET_MBUF_PRIV_DATA(msrc)->priv_data_vxlan_src_addr;
    GET_MBUF_PRIV_DATA(mdst)->priv_data_vxlan_dst_addr =
        GET_MBUF_PRIV_DATA(msrc)->priv_data_vxlan_dst_addr;
}
#endif

static inline bool inet_addr_eq(uint8_t af, const union inet_addr *a1,
                     const union inet_addr *a2)
{
    switch (af) {
        case AF_INET:
            return a1->in.s_addr == a2->in.s_addr;
        case AF_INET6:
            return memcmp(a1->in6.s6_addr, a2->in6.s6_addr, 16) == 0;
        default:
            return memcmp(a1, a2, sizeof(union inet_addr)) == 0;
    }
}

#endif
