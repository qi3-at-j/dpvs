
#include <rte_branch_prediction.h>
#include <rte_per_lcore.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>

#include "vxlan_ctrl_priv.h"
#include "common_priv.h"

struct vxlan_tunnel_table *g_lcores_vxlan_tunnel_table_p[RTE_MAX_LCORE]; // for cmd pthread

#define this_lcore_vxlan_tunnel_table      (RTE_PER_LCORE(vxlan_tunnel_table_lcore))
#define this_lcore_socket_id        (RTE_PER_LCORE(socket_id_lcore))

static RTE_DEFINE_PER_LCORE(struct vxlan_tunnel_table, vxlan_tunnel_table_lcore);
static RTE_DEFINE_PER_LCORE(uint32_t, socket_id_lcore);

#if 0
static int vxlan_tunnel_init(void)
{
    int i;

    this_lcore_socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    for (i = 0; i < VXLAN_TUNNEL_BUCKETS_NUM; i++)
        INIT_HLIST_HEAD(&this_lcore_vxlan_tunnel_table.ht[i]);

    return 0;
}

static struct vxlan_tunnel_entry *vxlan_tunnel_lookup(uint32_t vni)
{
    uint32_t key;
    struct vxlan_tunnel_entry *vxlan_tunnel_node;
    
    key = my_hash1(vni, VXLAN_TUNNEL_BUCKETS_NUM);
    hlist_for_each_entry(vxlan_tunnel_node, &this_lcore_vxlan_tunnel_table.ht[key], hnode) {
        if (vxlan_tunnel_node->vni == vni) {
            return vxlan_tunnel_node;
        }
    }

    return NULL;
}

static int vxlan_tunnel_add(struct vxlan_tunnel_entry *vxlan_tunnel_node)
{
    struct vxlan_tunnel_entry *new_node;

    if (vxlan_tunnel_lookup(vxlan_tunnel_node->vni)) {
        return -EEXIST;
    }

#if 0
    struct vxlan_tunnel_entry *new_node = (struct vxlan_tunnel_entry *)rte_zmalloc_socket(
        "new_vxlan_tunnel_entry", sizeof(struct vxlan_tunnel_entry), RTE_CACHE_LINE_SIZE, 
        this_lcore_socket_id);
    if (new_node == NULL){
        return -ENOMEM;
    }
#endif

    if (unlikely(new_entry("new_vxlan_tunnel_entry", this_lcore_socket_id,
        sizeof(struct vxlan_tunnel_entry), (void *)vxlan_tunnel_node,
        (void **)&new_node) == false)) {
        return -ENOMEM;
    }

    uint32_t key = my_hash1(vxlan_tunnel_node->vni, VXLAN_TUNNEL_BUCKETS_NUM);
    hlist_add_head(&new_node->hnode, &this_lcore_vxlan_tunnel_table.ht[key]);
    rte_atomic32_inc(&this_lcore_vxlan_tunnel_table.cnt);
    return 0;
}

static int vxlan_tunnel_del(struct vxlan_tunnel_entry *vxlan_tunnel_node)
{
    if (unlikely(vxlan_tunnel_node == NULL)) {
        return -EINVAL;
    }

    if (likely(vxlan_tunnel_node = vxlan_tunnel_lookup(vxlan_tunnel_node->vni))) {
        hlist_del(&vxlan_tunnel_node->hnode);
        rte_atomic32_dec(&this_lcore_vxlan_tunnel_table.cnt);
        return 0;
    }

    return -ENOENT;
}

static int vxlan_tunnel_clear(void)
{
    int i;
    struct vxlan_tunnel_entry *vxlan_tunnel_node;
    struct hlist_node *next_node;

    for (i = 0; i < VXLAN_TUNNEL_BUCKETS_NUM; i++) {
        hlist_for_each_entry_safe(vxlan_tunnel_node, next_node,
            &this_lcore_vxlan_tunnel_table.ht[i], hnode) {
            hlist_del(&vxlan_tunnel_node->hnode);
            rte_atomic32_dec(&this_lcore_vxlan_tunnel_table.cnt);
            rte_free((void *)vxlan_tunnel_node);
        }
    }

    return 0;
}
#else
static int vxlan_tunnel_init(void)
{

    this_lcore_socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    HLIST_TABLE_INIT(VXLAN_TUNNEL_BUCKETS_NUM, this_lcore_vxlan_tunnel_table, ht);
    g_lcores_vxlan_tunnel_table_p[rte_lcore_id()] = &this_lcore_vxlan_tunnel_table;
    return 0;
}

struct vxlan_tunnel_entry * vxlan_tunnel_lookup(
    struct vxlan_tunnel_entry *vxlan_tunnel_node)
{
    struct vxlan_tunnel_entry *pos;
    HLIST_TABLE_LOOKUP(vxlan_tunnel_node->vni, VXLAN_TUNNEL_BUCKETS_NUM, my_hash1, 
        pos, this_lcore_vxlan_tunnel_table, ht, hnode, vni);
}

static int vxlan_tunnel_add(struct vxlan_tunnel_entry *vxlan_tunnel_node)
{
    if (vxlan_tunnel_lookup(vxlan_tunnel_node)) {
        return -EEXIST;
    }

    struct vxlan_tunnel_entry *new_node = NULL;
    if (unlikely(new_entry("new_vxlan_tunnel_entry", this_lcore_socket_id,
        sizeof(struct vxlan_tunnel_entry), (void *)vxlan_tunnel_node,
        (void **)&new_node) == false)) {
        return -ENOMEM;
    }

    HLIST_TABLE_ADD(vxlan_tunnel_node->vni, VXLAN_TUNNEL_BUCKETS_NUM, my_hash1, 
        new_node->hnode, this_lcore_vxlan_tunnel_table, ht, cnt); 
    return 0;
}

static int vxlan_tunnel_del(struct vxlan_tunnel_entry *vxlan_tunnel_node)
{
    struct vxlan_tunnel_entry *pos;
    HLIST_TABLE_DEL(vxlan_tunnel_node->vni, VXLAN_TUNNEL_BUCKETS_NUM, my_hash1, pos, 
        this_lcore_vxlan_tunnel_table, ht, hnode, cnt, vni);
}

static int vxlan_tunnel_clear(void)
{
    struct vxlan_tunnel_entry *vxlan_tunnel_node;
    HLIST_TABLE_CLEAR(VXLAN_TUNNEL_BUCKETS_NUM, vxlan_tunnel_node, 
        this_lcore_vxlan_tunnel_table, ht, hnode, cnt);
    return 0;
}
#endif

//========api start==========
int api_vxlan_tunnel_init(void *arg)
{
    RTE_SET_USED(arg);
    return(vxlan_tunnel_init());
}

int api_vxlan_tunnel_lookup(void *arg)
{
    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    struct vxlan_tunnel_entry * vxlan_tunnel_node = 
        vxlan_tunnel_lookup((struct vxlan_tunnel_entry *)arg);
    if (vxlan_tunnel_node == NULL) {
        return -EINVAL;
    }

    return 0;
}

int api_vxlan_tunnel_add(void *arg)
{
    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    return(vxlan_tunnel_add((struct vxlan_tunnel_entry *)arg));
}

int api_vxlan_tunnel_del(void *arg)
{
    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    return(vxlan_tunnel_del((struct vxlan_tunnel_entry *)arg));
}

int api_vxlan_tunnel_clear(void *arg)
{
    RTE_SET_USED(arg);
    return(vxlan_tunnel_clear());
}

int api_vxlan_tunnel_dump(void *arg)
{
    int i;
    struct vxlan_tunnel_entry *vxlan_tunnel_node;
    char dst_addr[64];

    RTE_SET_USED(arg);
    L3_DEBUG_TRACE(L3_INFO, "=========vni cnt:%u=========\n", this_lcore_vxlan_tunnel_table.cnt.cnt);
    for (i = 0; i < VXLAN_TUNNEL_BUCKETS_NUM; i++) {
        hlist_for_each_entry(vxlan_tunnel_node, &this_lcore_vxlan_tunnel_table.ht[i], hnode) {
            L3_DEBUG_TRACE(L3_INFO, "====ht[%d]=====vni:%u==r_ip:%s=========\n", 
                i, vxlan_tunnel_node->vni,
                inet_ntop(AF_INET, &vxlan_tunnel_node->remote_ip,
                    dst_addr, sizeof(dst_addr)));
        }
    }

    return 0;
}

//========api end==========


