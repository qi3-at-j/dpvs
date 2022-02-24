
#include <rte_branch_prediction.h>
#include <rte_per_lcore.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>

#include "vrf_priv.h"
#include "common_priv.h"
#include "log_priv.h"
#include "flow_l3_cfg_init_priv.h"

extern struct conf_tbl_entry_size g_conf_tbl_entry_size;

struct vrf_map *g_lcores_vrf_table_p[RTE_MAX_LCORE];
#if VRF_USE_VNI_HASH
struct vrf_vni_map *g_lcores_vrf_vni_table_p[RTE_MAX_LCORE];
#endif

#if VRF_USE_IP_HASH
struct vrf_ip_map *g_lcores_vrf_ip_table_p[RTE_MAX_LCORE];
#endif

#define this_lcore_vrf_map      (RTE_PER_LCORE(vrf_map_lcore))
#define this_lcore_socket_id        (RTE_PER_LCORE(socket_id_lcore))

static RTE_DEFINE_PER_LCORE(struct vrf_map, vrf_map_lcore);
static RTE_DEFINE_PER_LCORE(uint32_t, socket_id_lcore);

#if VRF_USE_VNI_HASH
#define this_lcore_vrf_vni_map      (RTE_PER_LCORE(vrf_vni_map_lcore))
static RTE_DEFINE_PER_LCORE(struct vrf_vni_map, vrf_vni_map_lcore);
#endif

#if VRF_USE_IP_HASH
#define this_lcore_vrf_ip_map      (RTE_PER_LCORE(vrf_ip_map_lcore))
static RTE_DEFINE_PER_LCORE(struct vrf_ip_map, vrf_ip_map_lcore);
#endif

#ifdef VRF_USE_MEMPOOL
#define this_lcore_vrf_mempool_p      (RTE_PER_LCORE(vrf_mempool_lcore))
static RTE_DEFINE_PER_LCORE(struct rte_mempool *, vrf_mempool_lcore);
#define this_lcore_vrf_bind_mempool_p      (RTE_PER_LCORE(vrf_bind_mempool_lcore))
static RTE_DEFINE_PER_LCORE(struct rte_mempool *, vrf_bind_mempool_lcore);
#endif

#if VRF_USE_VNI_HASH
struct net_vrf *vrf_vni_lookup(uint32_t vni)
{
    uint32_t key = my_hash1(vni, VNI_BUCKETS_NUM);
    struct net_vrf *vni_node;

    hlist_for_each_entry(vni_node, &this_lcore_vrf_vni_map.ht[key], hnode) {
        if (vni_node->vni == vni) {
            return vni_node;
        }
    }

    return NULL; 
}

static inline int vrf_vni_add(struct net_vrf *vrf_bind_node)
{
    struct net_vrf *vni_node;
    uint32_t key = my_hash1(vrf_bind_node->vni, VNI_BUCKETS_NUM);

    hlist_for_each_entry(vni_node, &this_lcore_vrf_vni_map.ht[key], hnode) {
        if (unlikely(vni_node->vni == vrf_bind_node->vni)) {
            return -EEXIST;
        }
    }

    hlist_add_head(&vrf_bind_node->hnode, &this_lcore_vrf_vni_map.ht[key]);
    rte_atomic32_inc(&this_lcore_vrf_vni_map.cnt);

    return 0;
}

static inline int vrf_vni_del(uint32_t vni)
{
    struct net_vrf *vni_node = vrf_vni_lookup(vni);

    if (unlikely(vni_node == NULL)) {
        return -ENOENT;
    }

    hlist_del(&vni_node->hnode);
    rte_atomic32_dec(&this_lcore_vrf_vni_map.cnt);

    return 0;
}
#endif

#if VRF_USE_IP_HASH
struct net_vrf *vrf_ip_lookup(uint8_t af, union inet_addr *ip)
{
#if USE_HASH_3
    uint32_t key = my_hash3(af, ip, IP_BUCKETS_NUM);
#else
    uint32_t key = my_hash2(ip, sizeof(union inet_addr), IP_BUCKETS_NUM);
#endif

    struct net_vrf *ip_node;

    hlist_for_each_entry(ip_node, &this_lcore_vrf_ip_map.ht[key], hnode) {
        if ((af == ip_node->family) &&
            (inet_addr_eq(af, &ip_node->ip, ip))) {
            return ip_node;
        }
    }

    return NULL; 
}

static inline int vrf_ip_add(struct net_vrf *vrf_bind_node)
{
    struct net_vrf *ip_node;

#if USE_HASH_3
    uint32_t key = my_hash3(vrf_bind_node->family,
        &vrf_bind_node->ip, IP_BUCKETS_NUM);
#else
    uint32_t key = my_hash2(&vrf_bind_node->ip,
        sizeof(union inet_addr), IP_BUCKETS_NUM);
#endif

    hlist_for_each_entry(ip_node, &this_lcore_vrf_ip_map.ht[key], hnode) {
        if ((vrf_bind_node->family == ip_node->family) &&
            (inet_addr_eq(vrf_bind_node->family,
            &ip_node->ip, &vrf_bind_node->ip))) {
            return -EEXIST;
        }
    }

    hlist_add_head(&vrf_bind_node->hnode, &this_lcore_vrf_ip_map.ht[key]);
    rte_atomic32_inc(&this_lcore_vrf_ip_map.cnt);

    return 0;
}

static inline int vrf_ip_del(struct net_vrf *vrf_bind_node)
{
    struct net_vrf *ip_node = vrf_ip_lookup(vrf_bind_node->family,
        &vrf_bind_node->ip);

    if (unlikely(ip_node == NULL)) {
        return -ENOENT;
    }

    hlist_del(&ip_node->hnode);
    rte_atomic32_dec(&this_lcore_vrf_ip_map.cnt);

    return 0;
}
#endif

static inline struct vrf_map_elem *vrf_lookup(uint32_t table_id)
{
    uint32_t key;
    struct vrf_map_elem *vrf_node;
    
    key = my_hash1(table_id, VRF_BUCKETS_NUM);
    hlist_for_each_entry(vrf_node, &this_lcore_vrf_map.ht[key], hnode) {
        if (vrf_node->table_id == table_id) {
            return vrf_node;
        }
    }

    return NULL;
}

static inline int vrf_add(uint32_t table_id)
{
    uint32_t key;
    struct vrf_map_elem *new_vrf_node;
    
    if (unlikely((table_id >= MAX_ROUTE_TBLS) || 
        (table_id == GLOBAL_ROUTE_TBL_ID))) {
        return -EINVAL;
    }

    key = my_hash1(table_id, VRF_BUCKETS_NUM);
    hlist_for_each_entry(new_vrf_node, &this_lcore_vrf_map.ht[key], hnode) {
        if (new_vrf_node->table_id == table_id) {
            return -EEXIST;
        }
    }

#ifdef VRF_USE_MEMPOOL
    if (unlikely(rte_mempool_get(this_lcore_vrf_mempool_p, (void **)&new_vrf_node)))
        return -ENOMEM;
    new_vrf_node->mp = this_lcore_vrf_mempool_p;
#else
    new_vrf_node = (struct vrf_map_elem *)rte_zmalloc_socket("new_vrf_map_elem", 
        sizeof(struct vrf_map_elem), RTE_CACHE_LINE_SIZE, this_lcore_socket_id);
    if (new_vrf_node == NULL) {
        return -ENOMEM;
    }
#endif

    new_vrf_node->table_id = table_id;
    INIT_LIST_HEAD(&new_vrf_node->vrf_list);
    hlist_add_head(&new_vrf_node->hnode, &this_lcore_vrf_map.ht[key]);
    rte_atomic32_inc(&this_lcore_vrf_map.cnt);

    return 0;
}

#if VRF_USE_DEV_HASH
static inline int vrf_bind_port(struct net_vrf *vrf_bind_node)
{   
    struct net_vrf *net_vrf;

    if (unlikely((vrf_bind_node == NULL) ||
        (vrf_bind_node->port == NULL))) {
        return -EINVAL;
    }

    struct vrf_map_elem *vrf_node = vrf_lookup(vrf_bind_node->table_id);
    if (unlikely(vrf_node == NULL)) {
        return -ENOENT;
    }

    list_for_each_entry(net_vrf, &vrf_node->vrf_list, me_list) {  
        if ((net_vrf->type == vrf_bind_node->type) &&
            (net_vrf->port->id == vrf_bind_node->port->id)) {
            return -EEXIST;
        }
    }

#ifdef VRF_USE_MEMPOOL
    if (unlikely(rte_mempool_get(this_lcore_vrf_bind_mempool_p, (void **)&net_vrf)))
        return -ENOMEM;
    net_vrf->mp = this_lcore_vrf_bind_mempool_p;
#else
    net_vrf = (struct net_vrf *)rte_zmalloc_socket("new_net_vrf",
            sizeof(struct net_vrf),
            RTE_CACHE_LINE_SIZE,
            this_lcore_socket_id);
    if (net_vrf == NULL) {
        return -ENOMEM;
    }
#endif

    net_vrf->type = VRF_TYPE_PORT;
    net_vrf->port = vrf_bind_node->port;
    net_vrf->table_id = vrf_bind_node->table_id;
    list_add(&net_vrf->me_list, &vrf_node->vrf_list);
    rte_atomic32_inc(&vrf_node->cnt);
    vrf_bind_node->port->table_id = vrf_bind_node->table_id; //should be use lock!!!

    return 0;
}
#endif

#if VRF_USE_VNI_HASH
static inline int vrf_bind_vni(struct net_vrf *vrf_bind_node)
{   
    struct net_vrf *net_vrf;

    if (unlikely(vrf_bind_node == NULL)) {
        return -EINVAL;
    }

    struct vrf_map_elem *vrf_node = vrf_lookup(vrf_bind_node->table_id);
    if (unlikely(vrf_node == NULL)) {
        return -ENOENT;
    }

    list_for_each_entry(net_vrf, &vrf_node->vrf_list, me_list) {  
        if ((net_vrf->type == vrf_bind_node->type) &&
            (net_vrf->vni == vrf_bind_node->vni)) {
            return -EEXIST;
        }
    }

#ifdef VRF_USE_MEMPOOL
    if (unlikely(rte_mempool_get(this_lcore_vrf_bind_mempool_p, (void **)&net_vrf)))
        return -ENOMEM;
    net_vrf->mp = this_lcore_vrf_bind_mempool_p;
#else
    net_vrf = (struct net_vrf *)rte_zmalloc_socket("new_net_vrf",
            sizeof(struct net_vrf),
            RTE_CACHE_LINE_SIZE,
            this_lcore_socket_id);
    if (net_vrf == NULL) {
        return -ENOMEM;
    }
#endif

    net_vrf->type = VRF_TYPE_VNI;
    net_vrf->vni = vrf_bind_node->vni;
    net_vrf->table_id = vrf_bind_node->table_id;
    int ret = vrf_vni_add(net_vrf);
    if (unlikely(ret)) {
#ifdef VRF_USE_MEMPOOL
        rte_mempool_put(net_vrf->mp, net_vrf);
#else
        rte_free(net_vrf);
#endif
        return ret;
    }

    list_add(&net_vrf->me_list, &vrf_node->vrf_list);
    rte_atomic32_inc(&vrf_node->cnt);

    return 0;
}
#endif

#if VRF_USE_IP_HASH
static inline int vrf_bind_ip(struct net_vrf *vrf_bind_node)
{   
    struct net_vrf *net_vrf;

    if (unlikely(vrf_bind_node == NULL)) {
        return -EINVAL;
    }

    struct vrf_map_elem *vrf_node = vrf_lookup(vrf_bind_node->table_id);
    if (unlikely(vrf_node == NULL)) {
        return -ENOENT;
    }

    list_for_each_entry(net_vrf, &vrf_node->vrf_list, me_list) {  
        if ((net_vrf->type == vrf_bind_node->type) &&
            (vrf_bind_node->family == net_vrf->family) &&
            (inet_addr_eq(vrf_bind_node->family,
                &net_vrf->ip, &vrf_bind_node->ip))) {
            return -EEXIST;
        }
    }

#ifdef VRF_USE_MEMPOOL
    if (unlikely(rte_mempool_get(this_lcore_vrf_bind_mempool_p, (void **)&net_vrf)))
        return -ENOMEM;
    net_vrf->mp = this_lcore_vrf_bind_mempool_p;
#else
    net_vrf = (struct net_vrf *)rte_zmalloc_socket("new_net_vrf",
            sizeof(struct net_vrf),
            RTE_CACHE_LINE_SIZE,
            this_lcore_socket_id);
    if (net_vrf == NULL) {
        return -ENOMEM;
    }
#endif

    net_vrf->type = VRF_TYPE_IP;
    net_vrf->family = vrf_bind_node->family;
    net_vrf->ip = vrf_bind_node->ip;
    net_vrf->table_id = vrf_bind_node->table_id;
    int ret = vrf_ip_add(net_vrf);
    if (unlikely(ret)) {
#ifdef VRF_USE_MEMPOOL
        rte_mempool_put(net_vrf->mp, net_vrf);
#else
        rte_free(net_vrf);
#endif
        return ret;
    }

    list_add(&net_vrf->me_list, &vrf_node->vrf_list);
    rte_atomic32_inc(&vrf_node->cnt);

    return 0;
}
#endif

static inline int vrf_bind(struct net_vrf *vrf_bind_node)
{
    switch (vrf_bind_node->type) {
#if VRF_USE_DEV_HASH
        case VRF_TYPE_PORT:
            return(vrf_bind_port(vrf_bind_node));
            break;
#endif
#if VRF_USE_VNI_HASH
        case VRF_TYPE_VNI:
            return(vrf_bind_vni(vrf_bind_node));
            break;
#endif
#if VRF_USE_IP_HASH
        case VRF_TYPE_IP:
            return(vrf_bind_ip(vrf_bind_node));
            break;
#endif
        default:
            return -EINVAL;
    }
}

#if VRF_USE_DEV_HASH
static inline int vrf_unbind_port(struct net_vrf *vrf_bind_node)
{  
    struct net_vrf *net_vrf;

    if (unlikely((vrf_bind_node == NULL) ||
        (vrf_bind_node->port == NULL))) {
        return -EINVAL;
    }

    struct vrf_map_elem *vrf_node = vrf_lookup(vrf_bind_node->table_id);
    if (unlikely(vrf_node == NULL)) {
        return -ENOENT;
    }

    list_for_each_entry(net_vrf, &vrf_node->vrf_list, me_list) {
        if ((net_vrf->type == vrf_bind_node->type) &&
                (net_vrf->port->id == vrf_bind_node->port->id)) {
            vrf_bind_node->port->table_id = GLOBAL_ROUTE_TBL_ID; //should be use lock!!!
            list_del(&net_vrf->me_list);
            rte_atomic32_dec(&vrf_node->cnt);
#ifdef VRF_USE_MEMPOOL
            rte_mempool_put(net_vrf->mp, net_vrf);
#else
            rte_free(net_vrf);
#endif
            return 0;
        }
    }

    return -ENOENT;
}
#endif

#if VRF_USE_VNI_HASH
static inline int vrf_unbind_vni(struct net_vrf *vrf_bind_node)
{  
    struct net_vrf *net_vrf;

    if (unlikely(vrf_bind_node == NULL)) {
        return -EINVAL;
    }

    struct vrf_map_elem *vrf_node = vrf_lookup(vrf_bind_node->table_id);
    if (unlikely(vrf_node == NULL)) {
        return -ENOENT;
    }

    list_for_each_entry(net_vrf, &vrf_node->vrf_list, me_list) {
        if ((net_vrf->type == vrf_bind_node->type) &&
                (net_vrf->vni == vrf_bind_node->vni)) {
            vrf_vni_del(net_vrf->vni);
            list_del(&net_vrf->me_list);
            rte_atomic32_dec(&vrf_node->cnt);
#ifdef VRF_USE_MEMPOOL
            rte_mempool_put(net_vrf->mp, net_vrf);
#else
            rte_free(net_vrf);
#endif
            return 0;
        }
    }

    return -ENOENT;
}
#endif

#if VRF_USE_IP_HASH
static inline int vrf_unbind_ip(struct net_vrf *vrf_bind_node)
{  
    struct net_vrf *net_vrf;

    if (unlikely(vrf_bind_node == NULL)) {
        return -EINVAL;
    }

    struct vrf_map_elem *vrf_node = vrf_lookup(vrf_bind_node->table_id);
    if (unlikely(vrf_node == NULL)) {
        return -ENOENT;
    }

    list_for_each_entry(net_vrf, &vrf_node->vrf_list, me_list) {
        if ((net_vrf->type == vrf_bind_node->type) &&
                (vrf_bind_node->family == net_vrf->family) &&
                (inet_addr_eq(vrf_bind_node->family,
                &net_vrf->ip, &vrf_bind_node->ip))) {
            vrf_ip_del(net_vrf);
            list_del(&net_vrf->me_list);
            rte_atomic32_dec(&vrf_node->cnt);
#ifdef VRF_USE_MEMPOOL
            rte_mempool_put(net_vrf->mp, net_vrf);
#else
            rte_free(net_vrf);
#endif
            return 0;
        }
    }

    return -ENOENT;
}
#endif

static inline int vrf_unbind(struct net_vrf *vrf_bind_node)
{

    switch (vrf_bind_node->type) {
#if VRF_USE_DEV_HASH
        case VRF_TYPE_PORT:
            return(vrf_unbind_port(vrf_bind_node));
            break;
#endif
#if VRF_USE_VNI_HASH
        case VRF_TYPE_VNI:
            return(vrf_unbind_vni(vrf_bind_node));
            break;
#endif
#if VRF_USE_IP_HASH
        case VRF_TYPE_IP:
            return(vrf_unbind_ip(vrf_bind_node));
            break;
#endif
        default:
            return -EINVAL;
    }
}

static inline int vrf_del_clear_id(uint32_t table_id, int del_flag)
{
    struct vrf_map_elem *vrf_node;
    struct net_vrf *net_vrf, *next_net_vrf;

    if ((vrf_node = vrf_lookup(table_id)) == NULL) {
        return -ENOENT;
    }

    list_for_each_entry_safe(net_vrf, next_net_vrf,
        &vrf_node->vrf_list, me_list) {
        switch (net_vrf->type) {
#if VRF_USE_DEV_HASH
            case VRF_TYPE_PORT:
                net_vrf->port->table_id = GLOBAL_ROUTE_TBL_ID; //should be use lock!!!
                break;
#endif
#if VRF_USE_VNI_HASH
            case VRF_TYPE_VNI:
                vrf_vni_del(net_vrf->vni);
                break;
#endif
#if VRF_USE_IP_HASH
            case VRF_TYPE_IP:
                vrf_ip_del(&net_vrf->ip);
                break;
#endif
            default:
                return -EINVAL;
        }

        list_del(&net_vrf->me_list);
        rte_atomic32_dec(&vrf_node->cnt);
#ifdef VRF_USE_MEMPOOL
        rte_mempool_put(net_vrf->mp, net_vrf);
#else
        rte_free(net_vrf);
#endif
    }

    if (del_flag) {   
        hlist_del(&vrf_node->hnode);
        rte_atomic32_dec(&this_lcore_vrf_map.cnt);
#ifdef VRF_USE_MEMPOOL
        rte_mempool_put(vrf_node->mp, vrf_node);
#else
        rte_free((void *)vrf_node);
#endif
    }

    return 0;
}

#if 0
static int vrf_del_clear_all(int del_flag)
{
    int i;
    struct vrf_map_elem *vrf_node;
    struct hlist_node *next_vrf_node;
    struct net_vrf *net_vrf, *next_net_vrf;

    for (i = 0; i < VRF_BUCKETS_NUM; i++) {
        hlist_for_each_entry_safe(vrf_node, next_vrf_node,
            &this_lcore_vrf_map.ht[i], hnode) {
            vrf_del_clear_id(vrf_node->table_id, del_flag);
        }
    }    

    return 0;
}
#else
static inline int vrf_del_clear_all(int del_flag)
{
    int i;
    struct vrf_map_elem *vrf_node;
    struct hlist_node *next_vrf_node;
    struct net_vrf *net_vrf, *next_net_vrf;

    for (i = 0; i < VRF_BUCKETS_NUM; i++) {
        hlist_for_each_entry_safe(vrf_node, next_vrf_node,
            &this_lcore_vrf_map.ht[i], hnode) {
            list_for_each_entry_safe(net_vrf, next_net_vrf,
                &vrf_node->vrf_list, me_list) {
                switch (net_vrf->type) {
#if VRF_USE_DEV_HASH
                    case VRF_TYPE_PORT:
                        net_vrf->port->table_id = GLOBAL_ROUTE_TBL_ID; //should be use lock!!!
                        break;
#endif
#if VRF_USE_VNI_HASH
                    case VRF_TYPE_VNI:
                        vrf_vni_del(net_vrf->vni);
                        break;
#endif
#if VRF_USE_IP_HASH
                    case VRF_TYPE_IP:
                        vrf_ip_del(&net_vrf->ip);
                        break;
#endif
                    default:
                        return -EINVAL;
                }
                list_del(&net_vrf->me_list);
                rte_atomic32_dec(&vrf_node->cnt);
#ifdef VRF_USE_MEMPOOL
                rte_mempool_put(net_vrf->mp, net_vrf);
#else
                rte_free(net_vrf);
#endif
            }
            if (del_flag) {                
                hlist_del(&vrf_node->hnode);
                rte_atomic32_dec(&this_lcore_vrf_map.cnt);
#ifdef VRF_USE_MEMPOOL
                rte_mempool_put(vrf_node->mp, vrf_node);
#else
                rte_free((void *)vrf_node);
#endif
            }
        }
    }    

    return 0;
}
#endif

/********************API start*************************/
int api_vrf_init(void *arg)
{
    int i;

    RTE_SET_USED(arg);
    this_lcore_socket_id = rte_lcore_to_socket_id(rte_lcore_id());

#ifdef VRF_USE_MEMPOOL
    char name[RTE_MEMZONE_NAMESIZE] = {0};
    int ret = snprintf(name, sizeof(name), "vrf_mempool_%u", rte_lcore_id());
    if (unlikely(ret < 0 || ret >= (int)sizeof(name))) {
        return -EINVAL;
    }
    this_lcore_vrf_mempool_p = rte_mempool_create(
        name,
        g_conf_tbl_entry_size.tbl_size,
        sizeof(struct vrf_map_elem),
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        this_lcore_socket_id,
        MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (unlikely(this_lcore_vrf_mempool_p == NULL)) {
        return -ENOMEM;
    }

    ret = snprintf(name, sizeof(name), "vrf_bind_mempool_%u", rte_lcore_id());
    if (unlikely(ret < 0 || ret >= (int)sizeof(name))) {
        return -EINVAL;
    }
    this_lcore_vrf_bind_mempool_p = rte_mempool_create(
        name,
        g_conf_tbl_entry_size.vrf_bind_size,
        sizeof(struct net_vrf),
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        this_lcore_socket_id,
        MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (unlikely(this_lcore_vrf_bind_mempool_p == NULL)) {
        return -ENOMEM;
    }
#endif

    for (i = 0; i < VRF_BUCKETS_NUM; i++)
        INIT_HLIST_HEAD(&this_lcore_vrf_map.ht[i]);

    g_lcores_vrf_table_p[rte_lcore_id()] = &this_lcore_vrf_map;

#if VRF_USE_VNI_HASH
    for (i = 0; i < VNI_BUCKETS_NUM; i++)
        INIT_HLIST_HEAD(&this_lcore_vrf_vni_map.ht[i]);

    g_lcores_vrf_vni_table_p[rte_lcore_id()] = &this_lcore_vrf_vni_map;
#endif

#if VRF_USE_IP_HASH
        for (i = 0; i < IP_BUCKETS_NUM; i++)
            INIT_HLIST_HEAD(&this_lcore_vrf_ip_map.ht[i]);
    
        g_lcores_vrf_ip_table_p[rte_lcore_id()] = &this_lcore_vrf_ip_map;
#endif

    return 0;
}

int api_vrf_add(void *arg)
{
    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    struct vrf_map_elem *vrf_node = (struct vrf_map_elem *)arg;
    return(vrf_add(vrf_node->table_id));
}

int api_vrf_bind(void *arg)
{
    struct net_vrf *vrf_bind_node;

    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }
    vrf_bind_node = (struct net_vrf *)arg;
    return(vrf_bind(vrf_bind_node));
}

int api_vrf_unbind(void *arg)
{
    struct net_vrf *vrf_bind_node;

    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    vrf_bind_node = (struct net_vrf *)arg;
    return(vrf_unbind(vrf_bind_node));
}

int api_vrf_del_id(void *arg)
{
    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    return(vrf_del_clear_id(*(uint32_t *)arg, 1));
}

int api_vrf_del_all(void *arg)
{
    RTE_SET_USED(arg);
    return(vrf_del_clear_all(1));
}

int api_vrf_clear_id(void *arg)
{
    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    return(vrf_del_clear_id(*(uint32_t *)arg, 0));
}

int api_vrf_clear_all(void *arg)
{
    RTE_SET_USED(arg);
    return(vrf_del_clear_all(0));
}

int api_vrf_dump(void *arg)
{
    int i;
    struct vrf_map_elem *vrf_node;
    struct net_vrf *net_vrf;

    RTE_SET_USED(arg);
    L3_DEBUG_TRACE(L3_INFO, "=========vrf cnt:%u=========\n", this_lcore_vrf_map.cnt.cnt);
    for (i = 0; i < VRF_BUCKETS_NUM; i++) {
        hlist_for_each_entry(vrf_node, &this_lcore_vrf_map.ht[i], hnode) {
            L3_DEBUG_TRACE(L3_INFO, "====ht[%d]=====vrf id:%u=========\n", i, vrf_node->table_id);
        }
    }

    for (i = 0; i < VRF_BUCKETS_NUM; i++) {
        hlist_for_each_entry(vrf_node, &this_lcore_vrf_map.ht[i], hnode) {
            list_for_each_entry(net_vrf, &vrf_node->vrf_list, me_list) {
#if VRF_USE_DEV_HASH
        L3_DEBUG_TRACE(L3_INFO, "===ht[%d]======vrf id:%u, port id:%u=========\n", 
            i, vrf_node->table_id, net_vrf->port->id);
#endif

#if VRF_USE_VNI_HASH
        L3_DEBUG_TRACE(L3_INFO, "===ht[%d]======vrf id:%u, vni:%u=========\n", 
            i, vrf_node->table_id, net_vrf->vni);
#endif                
            }
        }
    }

    return 0;
}

/********************API end*************************/


