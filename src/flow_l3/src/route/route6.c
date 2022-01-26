#include <rte_byteorder.h>
#include <assert.h>
#include <rte_jhash.h>

#include "dpdk.h"
#include "ctrl.h"
#include "linux_ipv6.h"
#include "flow.h"
#include "conf/inetaddr.h"
#include "route6_priv.h"
#include "ip6_graph.h"
#include "conf/route6.h"
#include "vrf_priv.h"
#include "log_priv.h"
#include "flow_l3_cli_priv.h"
#include "common_cli_priv.h"

static RTE_DEFINE_PER_LCORE(struct route6_htable *, route6_htable_lcore);
static RTE_DEFINE_PER_LCORE(uint32_t, socket_id_lcore);
static RTE_DEFINE_PER_LCORE(struct route6_dustbin, route6_dustbin);

struct route6_htable *g_lcores_route6_tables_p[RTE_MAX_LCORE]; // for cmd pthread

#define this_route6_dustbin        (RTE_PER_LCORE(route6_dustbin))
#define this_lcore_route6_tables_p      (RTE_PER_LCORE(route6_htable_lcore))
#define this_lcore_socket_id        (RTE_PER_LCORE(socket_id_lcore))

#define RT6_HLIST_MAX_BUCKET_BITS   8
#define RT6_HLIST_MAX_BUCKETS       (1U<<RT6_HLIST_MAX_BUCKET_BITS)

static int route6_recycle(void *arg)
{
    struct route6_entry *rt6, *next;
#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif
    list_for_each_entry_safe(rt6, next, &this_route6_dustbin.routes, hnode) {
        if (rte_atomic32_read(&rt6->refcnt) <= 1) {
            list_del(&rt6->hnode);
#ifdef DPVS_ROUTE6_DEBUG
            dump_route6_prefix(&rt6->rt6_dst, buf, sizeof(buf));
            RTE_LOG(DEBUG, RT6, "[%d] %s: delete dustbin route %s->%s\n", rte_lcore_id(),
                    __func__, buf, rt6->rt6_dev ? rt6->rt6_dev->name : "");
#endif
            rte_free(rt6);
        }
    }

    return EDPVS_OK;
}

int new_route6_init(void *arg)
{
    int j;
    struct timeval tv;
    bool global;
    int err= 0;
    RTE_SET_USED(arg);

    this_lcore_socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    this_lcore_route6_tables_p = (struct route6_htable *)rte_zmalloc_socket
        ("new_route6_table", sizeof(struct route6_htable) * MAX_ROUTE_TBLS, 
        RTE_CACHE_LINE_SIZE, this_lcore_socket_id);
    if (this_lcore_route6_tables_p == NULL){
        return -ENOMEM;
    }

    tv.tv_sec = ROUTE6_RECYCLE_TIME_DEF,
    tv.tv_usec = 0,
    global = (rte_lcore_id() == rte_get_master_lcore());

    INIT_LIST_HEAD(&this_route6_dustbin.routes);
    err = dpvs_timer_sched_period(&this_route6_dustbin.tm, &tv, route6_recycle, NULL, global);
    if (err != EDPVS_OK)
        return err;
    
    for (j = 0; j < MAX_ROUTE_TBLS; j++) {
        INIT_LIST_HEAD(&this_lcore_route6_tables_p[j].htable);
        this_lcore_route6_tables_p[j].nroutes = 0;
    }

    g_lcores_route6_tables_p[rte_lcore_id()] = this_lcore_route6_tables_p;

    return 0;
}

static inline void route6_fill_with_cfg(struct route6_entry *rt6,
        const struct dp_vs_route6_conf *cf)
{
    memset(rt6, 0, sizeof(struct route6_entry));

    rt6->rt6_dst = cf->dst;
    rt6->rt6_src = cf->src;
    rt6->rt6_prefsrc = cf->prefsrc;
    rt6->rt6_dev = netif_port_get_by_name(cf->ifname);
    rt6->rt6_gateway = cf->gateway;
    rt6->rt6_flags = cf->flags;
    rt6->rt6_mtu = cf->mtu;
    if (!cf->mtu && rt6->rt6_dev)
        rt6->rt6_mtu = rt6->rt6_dev->mtu;
    rt6->table_id = cf->table_id;
}

static void 
route6_entry_free(struct route6_entry *rt6)
{
    if (unlikely(rte_atomic32_read(&rt6->refcnt) > 1))
        list_add_tail(&rt6->hnode, &this_route6_dustbin.routes);
    else
        rte_free(rt6);
}

int route6_hlist_clear_lcore(void *arg)
{
    int i;
    struct route6_hlist *hlist, *hnext;
    struct route6_entry *rt6, *rnext;
    struct route6_htable *route_table;
    uint32_t table_id;

    if (unlikely((arg == NULL) || ((table_id = *(uint32_t *)arg) >= MAX_ROUTE_TBLS))) {
        return EDPVS_INVAL;
    }

    route_table = &this_lcore_route6_tables_p[table_id];
    list_for_each_entry_safe(hlist, hnext, &route_table->htable, node)
    {
        for (i = 0; i < hlist->nbuckets; i++) {
            list_for_each_entry_safe(rt6, rnext, &hlist->hlist[i], hnode) {
                list_del(&rt6->hnode);
                route6_entry_free(rt6);
                hlist->nroutes--;
                route_table->nroutes--;
            }
        }
        assert(hlist->nroutes == 0);
        list_del(&hlist->node);
        rte_free(hlist);
    }

    assert(route_table->nroutes == 0);
    return EDPVS_OK;
}

int route6_hlists_clear_lcore(void *arg)
{
    uint32_t table_id;
    int ret;

    RTE_SET_USED(arg);
    for (table_id = 0; table_id < MAX_ROUTE_TBLS; table_id++) {
        if ((ret = route6_hlist_clear_lcore((void *)&table_id)) < 0) {
            return ret;
        }
    }

    return 0;
}
static int route6_hlist_buckets(int plen)
{
    /* caller should ensure 0 <= plen <= 128 */
    if (plen < RT6_HLIST_MAX_BUCKET_BITS)
        return (1U << plen);
    else
        return RT6_HLIST_MAX_BUCKETS;
}

static inline int route6_hlist_hashkey(const struct in6_addr *addr, int plen, int nbuckets)
{
    struct in6_addr pfx;

    ipv6_addr_prefix(&pfx, addr, plen);
    return rte_jhash_32b((const uint32_t *)&pfx, 4, 0) % nbuckets;
}

static inline bool route6_match(const struct route6_entry *rt6, const struct dp_vs_route6_conf *cf)
{
    /* Note: Do not use `ipv6_masked_addr_cmp` here for performance consideration
     *      here. We ensure the route6 entry is masked when added to route table. */
    if (ipv6_addr_cmp(&rt6->rt6_dst.addr, &cf->dst.addr) != 0)
        return false;
    if (rt6->rt6_dst.plen != cf->dst.plen)
        return false;
    if (rt6->rt6_dev && strlen(cf->ifname) != 0) {
        struct netif_port *dev;
        dev = netif_port_get_by_name(cf->ifname);
        if (!dev || dev->id != rt6->rt6_dev->id)
            return false;
    }

    /* other fields to be checked? */

    return true;
}

static struct route6_entry *__route6_hlist_get(const struct dp_vs_route6_conf *cf,
                                              struct route6_htable *route_table,
                                              struct route6_hlist **phlist)
{
    int hashkey;
    struct route6_hlist *hlist;
    struct route6_entry *rt6;

    list_for_each_entry(hlist, &route_table->htable, node) {
        if (hlist->plen > cf->dst.plen)
            continue;
        if (hlist->plen < cf->dst.plen)
            break;
        hashkey = route6_hlist_hashkey(&cf->dst.addr, hlist->plen, hlist->nbuckets);
        list_for_each_entry(rt6, &hlist->hlist[hashkey], hnode) {
            if (route6_match(rt6, cf)) {
                if (phlist)
                    *phlist = hlist;
                return rt6;
            }
        }
    }

    return NULL;
}

static inline struct route6_entry *route6_hlist_get(const struct dp_vs_route6_conf *cf,
                                                   struct route6_htable *route_table)
{
    return __route6_hlist_get(cf, route_table, NULL);
}

static int 
_route6_hlist_add_lcore(struct dp_vs_route6_conf *cf)
{
    struct route6_htable *route_table = NULL;
    struct route6_hlist *hlist = NULL;
    struct route6_entry *rt6;
    int hashkey;
    bool hlist_exist = false;
#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif

    route_table = &this_lcore_route6_tables_p[cf->table_id];
    if (route6_hlist_get(cf, route_table))
        return EDPVS_EXIST;

    list_for_each_entry(hlist, &route_table->htable, node) {
        if (hlist->plen <= cf->dst.plen) {
            if (hlist->plen == cf->dst.plen)
                hlist_exist = true;
            break;
        }
    }

    if (!hlist_exist) { /* hlist for this prefix not exist, create it! */
        int i, nbuckets, size;
        struct route6_hlist *new_hlist;

        nbuckets = route6_hlist_buckets(cf->dst.plen);
        size = sizeof(struct route6_hlist) + nbuckets * sizeof(struct list_head);
        new_hlist = rte_zmalloc("rt6_hlist", size, 0);
        if (unlikely(!new_hlist)) {
            RTE_LOG(ERR, ROUTE6, "[%d] %s: fail to alloc rt6_hlist\n",
                    rte_lcore_id(), __func__);
            return EDPVS_NOMEM;
        }

        new_hlist->plen = cf->dst.plen;
        new_hlist->nbuckets = nbuckets;
        new_hlist->nroutes = 0;
        for (i = 0; i < nbuckets; i++)
            INIT_LIST_HEAD(&new_hlist->hlist[i]);

        /* add new_hlist to plen-sorted htable */
        __list_add(&new_hlist->node, hlist->node.prev, &hlist->node);

#ifdef DPVS_ROUTE6_DEBUG
        RTE_LOG(DEBUG, ROUTE6, "[%d] %s: new rt6_hlist: plen=%d, nbuckets=%d\n",
                rte_lcore_id(), __func__, new_hlist->plen, new_hlist->nbuckets);
#endif

        hlist = new_hlist; /* replace current hlist with new_hlist */
    }

    /* create route6 entry and hash it into current hlist */
    rt6 = rte_zmalloc("route6_entry", sizeof(struct route6_entry), 0);
    if (unlikely(!rt6)) {
        RTE_LOG(ERR, ROUTE6, "[%d] %s: fail to alloc rt6_entry!\n",
                rte_lcore_id(), __func__);
        if (hlist->nroutes == 0) {
            list_del(&hlist->node);
            rte_free(hlist);
        }
        return EDPVS_NOMEM;
    }

    route6_fill_with_cfg(rt6, cf);
    rte_atomic32_set(&rt6->refcnt, 1);

    hashkey = route6_hlist_hashkey(&cf->dst.addr, cf->dst.plen, hlist->nbuckets);
    list_add_tail(&rt6->hnode, &hlist->hlist[hashkey]);
    hlist->nroutes++;
    route_table->nroutes++;

#ifdef DPVS_ROUTE6_DEBUG
    dump_route6_prefix(&rt6->rt6_dst, buf, sizeof(buf));
    RTE_LOG(DEBUG, ROUTE6, "[%d] %s: new route6 node: %s->%s plen=%d, hashkey=%d/%d\n",
            rte_lcore_id(), __func__, buf, cf->ifname, hlist->plen,
            hashkey, hlist->nbuckets);
#endif

    return EDPVS_OK;
}

static int 
_route6_hlist_del_lcore(struct dp_vs_route6_conf *cf)
{
    struct route6_entry *rt6;
    struct route6_hlist *hlist = NULL;
    struct route6_htable *route_table = NULL;

#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif

    route_table = &this_lcore_route6_tables_p[cf->table_id];

    rt6 = __route6_hlist_get(cf, route_table, &hlist);
    if (!rt6)
        return EDPVS_NOTEXIST;

#ifdef DPVS_ROUTE6_DEBUG
    dump_route6_prefix(&rt6->rt6_dst, buf, sizeof(buf));
    RTE_LOG(DEBUG, ROUTE6, "[%d] %s: del route6 node: %s->%s\n",
            rte_lcore_id(), __func__, buf, cf->ifname);
#endif
    list_del(&rt6->hnode);
    route6_entry_free(rt6);

    assert(hlist != NULL);
    hlist->nroutes--;
    route_table->nroutes--;

    if (hlist->nroutes == 0) {
#ifdef DPVS_ROUTE6_DEBUG
        RTE_LOG(DEBUG, ROUTE6, "[%d] %s: del rt6_hlist: plen=%d, nbuckets=%d\n",
                rte_lcore_id(), __func__, hlist->plen, hlist->nbuckets);
#endif
        list_del(&hlist->node);
        rte_free(hlist);
    }

    return EDPVS_OK;
}

int 
route6_hlist_add_lcore(void *arg)
{
    struct dp_vs_route6_conf *cf;

    if (unlikely(arg == NULL)) {
        return -EDPVS_INVAL;
    }
    cf = (struct dp_vs_route6_conf *)arg;

    return _route6_hlist_add_lcore(cf);
}

int 
route6_hlist_del_lcore(void *arg)
{
    struct dp_vs_route6_conf *cf;

    if (unlikely(arg == NULL)) {
        return -EDPVS_INVAL;
    }

    cf = (struct dp_vs_route6_conf *)arg;

    return _route6_hlist_del_lcore(cf);
}
int 
route6_hlist_add_lcore_auto(void *arg)
{
    int err;
    struct dp_vs_route6_conf *cf;
    struct dp_vs_route6_conf cf_tmp;

    if (unlikely(arg == NULL)) {
        return -EDPVS_INVAL;
    }
    cf = (struct dp_vs_route6_conf *)arg;
    memcpy(&cf_tmp, cf, sizeof(cf_tmp));
    cf_tmp.dst.plen = 128;
    cf_tmp.flags = RTF_LOCALIN;
    err = _route6_hlist_add_lcore(&cf_tmp);
    if (err != EDPVS_OK && err != EDPVS_EXIST)
        return err;

    if (cf->dst.plen == 128)
        return EDPVS_OK;

    ipv6_addr_prefix(&cf_tmp.dst.addr, &cf->dst.addr, cf->dst.plen);
    cf_tmp.dst.plen = cf->dst.plen;
    cf_tmp.flags = RTF_FORWARD;
    err = _route6_hlist_add_lcore(&cf_tmp);
    if (err != EDPVS_OK && err != EDPVS_EXIST) {
        ipv6_addr_copy(&cf_tmp.dst.addr, &cf->dst.addr);
        cf_tmp.dst.plen = 128;
        cf_tmp.flags = RTF_LOCALIN;
        _route6_hlist_del_lcore(&cf_tmp);
        return err;
    }

    return EDPVS_OK;
}

int 
route6_hlist_del_lcore_auto(void *arg)
{
    struct dp_vs_route6_conf *cf;
    struct dp_vs_route6_conf cf_tmp;

    if (unlikely(arg == NULL)) {
        return -EDPVS_INVAL;
    }
#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif

    cf = (struct dp_vs_route6_conf *)arg;
    memcpy(&cf_tmp, cf, sizeof(cf_tmp));
    cf_tmp.dst.plen = 128;
    cf_tmp.flags = RTF_LOCALIN;
    _route6_hlist_del_lcore(&cf_tmp);
    if (cf->dst.plen == 128)
        return EDPVS_OK;

    ipv6_addr_prefix(&cf_tmp.dst.addr, &cf->dst.addr, cf->dst.plen);
    cf_tmp.dst.plen = cf->dst.plen;
    cf_tmp.flags = RTF_FORWARD;
    _route6_hlist_del_lcore(&cf_tmp);

    return EDPVS_OK;
}

static inline bool
route6_hlist_flow_match(const struct route6_entry *rt6, const struct flow6 *fl6)
{
    if (rt6->rt6_dst.plen < 128) {
        if (!ipv6_prefix_equal(&fl6->fl6_daddr, &rt6->rt6_dst.addr, rt6->rt6_dst.plen))
            return false;
    } else {
        if (!ipv6_addr_equal(&fl6->fl6_daddr, &rt6->rt6_dst.addr))
            return false;
    }

    if (fl6->fl6_oif && rt6->rt6_dev && (fl6->fl6_oif->id != rt6->rt6_dev->id))
        return false;

    /* anything else to check ? */

    return true;
}

static struct route6_entry *route6_hlist_lookup(struct route6_htable *route_table, struct flow6 *fl6)
{
    struct route6_hlist *hlist;
    struct route6_entry *rt6;
    int hashkey;

    list_for_each_entry(hlist, &route_table->htable, node) {
        hashkey = route6_hlist_hashkey(&fl6->fl6_daddr, hlist->plen, hlist->nbuckets);
        list_for_each_entry(rt6, &hlist->hlist[hashkey], hnode) {
            if (route6_hlist_flow_match(rt6, fl6)) {
                rte_atomic32_inc(&rt6->refcnt);
                return rt6;
            }
        }
    }

    return NULL;
}

struct route6_entry *
flow_route6_lookup(struct rte_mbuf *mbuf)
{
    struct route6_entry *route_node = NULL;
    uint32_t table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;
    route_node = route6_hlist_input(table_id, mbuf);
    return route_node;
}

struct route6_entry *route6_hlist_output(uint32_t table_id, const struct rte_mbuf *mbuf)
{   
    struct rte_ipv6_hdr *hdr = rte_ip6_hdr(mbuf);
    struct flow6 fl6;
    memset(&fl6, 0, sizeof(fl6));

    fl6.fl6_iif    = netif_port_get(mbuf->port);
    memcpy(fl6.fl6_daddr.s6_addr, hdr->dst_addr, sizeof(fl6.fl6_daddr.s6_addr));
    memcpy(fl6.fl6_saddr.s6_addr, hdr->src_addr, sizeof(fl6.fl6_saddr.s6_addr));
    fl6.fl6_proto  = hdr->proto;
    
    struct route6_htable *route_table = &this_lcore_route6_tables_p[table_id];
    
    return route6_hlist_lookup(route_table, &fl6);
}

struct route6_entry *route6_hlist_input(uint32_t table_id, struct rte_mbuf *mbuf)
{
    struct rte_ipv6_hdr *hdr = rte_ip6_hdr(mbuf);
    struct flow6 fl6;
    memset(&fl6, 0, sizeof(fl6));

    fl6.fl6_iif    = netif_port_get(mbuf->port);
    memcpy(fl6.fl6_daddr.s6_addr, hdr->dst_addr, sizeof(fl6.fl6_daddr.s6_addr));
    memcpy(fl6.fl6_saddr.s6_addr, hdr->src_addr, sizeof(fl6.fl6_saddr.s6_addr));
    fl6.fl6_proto  = hdr->proto;

    struct route6_htable *route_table = &this_lcore_route6_tables_p[table_id];

    return route6_hlist_lookup(route_table, &fl6);
}

static const char *af_itoa(int af)
{
    struct {
        uint8_t i_af;
        const char *s_af;
    } family_tab[] = {
        { AF_INET,  "inet" },
        { AF_INET6, "inet6" },
        { AF_UNSPEC, "unspec" },
    };
    int i;

    for (i = 0; i < NELEMS(family_tab); i++) {
        if (af == family_tab[i].i_af)
            return family_tab[i].s_af;
    }

    return "<unknow>";
}

void route6_entry_dump(const struct route6_entry *route)
{
    char dst[64], gateway[64], src[64], scope[32];

    if (route->rt6_flags & RTF_KNI)
        snprintf(scope, sizeof(scope), "%s", "kni_host");
    else if (route->rt6_flags & RTF_LOCALIN)
        snprintf(scope, sizeof(scope), "%s", "host");
    else if (route->rt6_flags & RTF_FORWARD) {
        if (ipv6_addr_any(&route->rt6_gateway))
            snprintf(scope, sizeof(scope), "%s", "link");
        else
            snprintf(scope, sizeof(scope), "%s", "global");
    } else
        snprintf(scope, sizeof(scope), "%s", "::");

    if (ipv6_addr_any(&route->rt6_dst.addr) && route->rt6_dst.plen == 0) {
        snprintf(dst, sizeof(dst), "%s", "default");
        printf("%s %s", af_itoa(AF_INET6), dst);
    } else {
        inet_ntop(AF_INET6, (union inet_addr*)&route->rt6_dst.addr, dst, sizeof(dst));
        printf("%s %s/%d", af_itoa(AF_INET6), dst, route->rt6_dst.plen);
    }

    if (!ipv6_addr_any(&route->rt6_gateway))
        printf(" via %s", inet_ntop(AF_INET6, (union inet_addr*)&route->rt6_gateway,
                    gateway, sizeof(gateway)) ? gateway : "::");
    if (!ipv6_addr_any(&route->rt6_src.addr))
        printf(" src %s", inet_ntop(AF_INET6, (union inet_addr*)&route->rt6_src.addr,
                    src, sizeof(src)) ? src : "::");
    printf(" dev %s", route->rt6_dev->name);

    if (route->rt6_mtu > 0)
        printf(" mtu %d", route->rt6_mtu);

    printf(" scope %s", scope);

    printf("\n");
}

int
route_add_ifaddr_v6(struct inet_addr_param *param)
{
    int ret = 0;
    struct dp_vs_route6_conf *rt6_conf;

    pthread_mutex_lock(&mutex); //for cmd and main lcore
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock); //for multi work lcore or r/w mutual exclusion
    memset(&cmd_notice_entry.data, 0, sizeof(cmd_notice_entry.data));
    rt6_conf = &cmd_notice_entry.data.route6_conf;
    ipv6_addr_copy(&rt6_conf->dst.addr, &param->ifa_entry.addr.in6);
    rt6_conf->dst.plen = param->ifa_entry.plen;
    snprintf(rt6_conf->ifname, sizeof(rt6_conf->ifname), "%s", param->ifa_entry.ifname);
    cmd_notice_entry.type = NT_SET_RT6_AUTO;

    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

#if 0
    uint16_t lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            continue;
        }

        if (lcore_id == rte_get_main_lcore()) {
            continue;
        }

        if (netif_lcore_is_fwd_worker(lcore_id) == false) {
            continue;
        }

        cmd_notice_entry.lcore_id = lcore_id;
        while(rte_get_main_lcore() != cmd_notice_entry.lcore_id);
    }
#else
    ret = common_cmd_entry_enq(LCORE_ID_ANY,
        &cmd_notice_entry, sizeof(struct common_cmd_notice_entry));
#endif

    pthread_mutex_unlock(&mutex);

    return ret;
}

int
route_del_ifaddr_v6(struct inet_addr_param *param)
{
    int ret = 0;
    struct dp_vs_route6_conf *rt6_conf;

    pthread_mutex_lock(&mutex); //for cmd and main lcore
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock); //for multi work lcore or r/w mutual exclusion
    memset(&cmd_notice_entry.data, 0, sizeof(cmd_notice_entry.data));
    rt6_conf = &cmd_notice_entry.data.route6_conf;
    ipv6_addr_copy(&rt6_conf->dst.addr, &param->ifa_entry.addr.in6);
    rt6_conf->dst.plen = param->ifa_entry.plen;
    snprintf(rt6_conf->ifname, sizeof(rt6_conf->ifname), "%s", param->ifa_entry.ifname);
    cmd_notice_entry.type = NT_DEL_RT6_AUTO;

    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

#if 0
    uint16_t lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            continue;
        }

        if (lcore_id == rte_get_main_lcore()) {
            continue;
        }

        if (netif_lcore_is_fwd_worker(lcore_id) == false) {
            continue;
        }

        cmd_notice_entry.lcore_id = lcore_id;
        while(rte_get_main_lcore() != cmd_notice_entry.lcore_id);
    }
#else
    ret = common_cmd_entry_enq(LCORE_ID_ANY,
        &cmd_notice_entry, sizeof(struct common_cmd_notice_entry));
#endif

    pthread_mutex_unlock(&mutex);

    return ret;
}
