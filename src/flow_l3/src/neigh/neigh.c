
#include <rte_malloc.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include "linux_ipv6.h"
#include "mempool.h"
#include "neigh_priv.h"
#include "vrf_priv.h"
#include "arp_priv.h"
#include "ndisc.h"
#include "vrrp_send_priv.h"

struct neigh_table *g_lcores_neigh_tables_p[RTE_MAX_LCORE];

#define this_lcore_neigh_tables_p      (RTE_PER_LCORE(neigh_table_lcore))
#define this_lcore_socket_id        (RTE_PER_LCORE(socket_id_lcore))

static RTE_DEFINE_PER_LCORE(struct neigh_table *, neigh_table_lcore);
static RTE_DEFINE_PER_LCORE(uint32_t, socket_id_lcore);

#define NEIGH_ENTRY_SIZE_DEF 128
#define NODE_NEIGH_TIMEOUT_DEF 60

extern struct dpvs_mempool *neigh_mempool;

#define s_NNO NODE_NUD_S_NONE
#define s_NSD NODE_NUD_S_SEND
#define s_NRE NODE_NUD_S_REACHABLE
#define s_NPR NODE_NUD_S_PROBE
#define s_NDE NODE_NUD_S_DELAY

#define NODE_NUD_S_KEEP NODE_NUD_S_MAX
#define s_NKP NODE_NUD_S_KEEP /*Keep state and do not reset timer*/

static int nud_timeouts[NODE_NUD_S_MAX] = {
    [NODE_NUD_S_NONE]        = 2,
    [NODE_NUD_S_SEND]        = 3,
    [NODE_NUD_S_REACHABLE]   = NODE_NEIGH_TIMEOUT_DEF,
    [NODE_NUD_S_PROBE]       = 30,
    [NODE_NUD_S_DELAY]       = 3,
};

static struct nud_state nud_states[] = {
/*                s_NNO, s_NSD, s_NRE, s_NPR, s_NDE*/
/*send arp*/    {{s_NSD, s_NSD, s_NKP, s_NDE, s_NDE}},
/*recv arp*/    {{s_NRE, s_NRE, s_NRE, s_NRE, s_NRE}},
/*ack confirm*/ {{s_NKP, s_NKP, s_NRE, s_NRE, s_NRE}},
/*mbuf ref*/    {{s_NKP, s_NKP, s_NKP, s_NPR, s_NKP}},
/*timeout*/     {{s_NNO, s_NNO, s_NPR, s_NNO, s_NNO}},
};

/* params from config file */
static int arp_unres_qlen = NEIGH_ENTRY_SIZE_DEF;

static struct neigh_entry *neigh_new_entry(struct neigh_entry *neigh_node)
{
    struct neigh_entry *new_neigh_node = NULL;

    if (unlikely(neigh_node == NULL)) {
        return NULL;
    }

    new_neigh_node = (struct neigh_entry *)rte_zmalloc_socket("new_neigh_entry", 
        sizeof(struct neigh_entry), RTE_CACHE_LINE_SIZE, this_lcore_socket_id);
    if (unlikely(new_neigh_node == NULL)) {
        return NULL;
    }

    *new_neigh_node = *neigh_node;
    return new_neigh_node;
}

struct neigh_entry *
neigh_lookup(uint32_t table_id, int af, union inet_addr *next_hop)
{
    uint32_t hashkey;
    struct neigh_entry *neigh_node;

    hashkey = neigh_hashkey(af, next_hop);
    hlist_for_each_entry(neigh_node, &this_lcore_neigh_tables_p[table_id].ht[hashkey], hnode) {
        if(neigh_node->af == af &&
           inet_addr_equal(af, next_hop, &neigh_node->next_hop)) {
            return neigh_node;
        }
    }

    return NULL;
}

int arp_neigh_add_ht(struct neigh_entry *neigh_node)
{
    uint32_t hashkey;

    if (unlikely(neigh_node == NULL)) {
        return -EINVAL;
    }

    if (likely(!(neigh_node->flag & NEIGH_HASHED))) {
        hashkey = neigh_hashkey(neigh_node->af, &neigh_node->next_hop);
        hlist_add_head(&neigh_node->hnode,
            &this_lcore_neigh_tables_p[neigh_node->table_id].ht[hashkey]);
        rte_atomic32_inc(&this_lcore_neigh_tables_p[neigh_node->table_id].cnt);
        neigh_node->flag |= NEIGH_HASHED;
        return 0;
    }

    return -EEXIST;
}

int arp_neigh_del_ht(struct neigh_entry *neigh_node)
{
    if (unlikely(neigh_node == NULL)) {
        return -EINVAL;
    }

    if (likely(neigh_node->flag & NEIGH_HASHED)) {
        hlist_del(&neigh_node->hnode);
        rte_atomic32_dec(&this_lcore_neigh_tables_p[neigh_node->table_id].cnt);
        neigh_node->flag &= ~NEIGH_HASHED;
        return 0;
    }

    return -ENOENT;
}

/***********************fill mac hdr before send pkt************************************/
void neigh_populate_mac(struct neigh_entry *neighbour,
                        struct rte_mbuf *m,
                        struct netif_port *port,
                        int af)
{
    struct rte_ether_hdr *eth;
    uint16_t pkt_type;

    m->l2_len = sizeof(struct rte_ether_hdr);
    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct rte_ether_hdr));

    rte_ether_addr_copy(&neighbour->d_mac, &eth->d_addr);
    if ((GET_MBUF_PRIV_DATA(m)->priv_data_vrrp_type == VRRP_TYPE_IP4) ||
        (GET_MBUF_PRIV_DATA(m)->priv_data_vrrp_type == VRRP_TYPE_IP6))
        rte_memcpy(&eth->s_addr, GET_MBUF_PRIV_DATA(m)->priv_data_smac,
            RTE_ETHER_ADDR_LEN);
    else
        rte_ether_addr_copy(&port->addr, &eth->s_addr);
    //pkt_type = (uint16_t)m->packet_type;
    pkt_type = (af == AF_INET)?RTE_ETHER_TYPE_IPV4:RTE_ETHER_TYPE_IPV6;
    eth->ether_type = rte_cpu_to_be_16(pkt_type);
}

int neigh_add(void *arg)
{
    uint32_t hashkey;
    struct neigh_entry *neigh_node, *neigh_node_tmp;

    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    neigh_node = (struct neigh_entry *)arg;
    hashkey = neigh_hashkey(neigh_node->af, &neigh_node->next_hop);
    hlist_for_each_entry(neigh_node_tmp, &this_lcore_neigh_tables_p[neigh_node->table_id].ht[hashkey], hnode) {
        if (inet_addr_equal(neigh_node->af, &neigh_node_tmp->next_hop, &neigh_node->next_hop)) {
            if (neigh_node_tmp->flag & NEIGH_HASHED) {
                neigh_node_tmp->state = NODE_NUD_S_NONE;
                arp_neigh_del_ht(neigh_node_tmp);
                break;
            } else {
                return -EEXIST;
            }
        }
    }

    neigh_node = neigh_new_entry(neigh_node);
    if (unlikely(!neigh_node)) {
        return -ENOMEM;
    }

    hlist_add_head(&neigh_node->hnode, 
        &this_lcore_neigh_tables_p[neigh_node->table_id].ht[hashkey]);
    rte_atomic32_inc(&this_lcore_neigh_tables_p[neigh_node->table_id].cnt);
    return 0;
}

int neigh_del(void *arg)
{
    struct neigh_entry *neigh_node;

    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    neigh_node = (struct neigh_entry *)arg;
    if (likely(neigh_node = neigh_lookup(neigh_node->table_id, AF_INET, &neigh_node->next_hop))) {
        if (unlikely(!(neigh_node->flag & NEIGH_STATIC))) {
            return -EBUSY;
        }

        hlist_del(&neigh_node->hnode);
        rte_atomic32_dec(&this_lcore_neigh_tables_p[neigh_node->table_id].cnt);
        rte_free((void *)neigh_node);
        return 0;
    }

    return -ENOENT;
}

int neigh_table_clear(void *arg)
{
    int i;  
    uint32_t table_id;
    struct neigh_entry *neigh_node;
    struct hlist_node *next_neigh_node;

    if (unlikely((arg == NULL) || ((table_id = *(uint32_t *)arg) >= MAX_ROUTE_TBLS))) {
        return -EINVAL;
    }

    if (this_lcore_neigh_tables_p[table_id].cnt.cnt) {
        for (i = 0; i < NEIGH_BUCKETS_NUM; i++) {
            hlist_for_each_entry_safe(neigh_node, next_neigh_node,
                &this_lcore_neigh_tables_p[table_id].ht[i], hnode) {
                if (!(neigh_node->flag & NEIGH_STATIC)) {
                    continue;
                }
                hlist_del(&neigh_node->hnode);
                rte_atomic32_dec(&this_lcore_neigh_tables_p[table_id].cnt);
                rte_free((void *)neigh_node);
            }
        }
    }

    return 0;
}

int neigh_tables_clear(void *arg)
{
    uint32_t table_id;
    int ret;

    RTE_SET_USED(arg);
    for (table_id = 0; table_id < MAX_ROUTE_TBLS; table_id++) {
        if ((ret = neigh_table_clear((void *)&table_id)) < 0) {
            return ret;
        }
    }

    return 0;
}

int new_neigh_init(void *arg)
{
    int i, j;

    RTE_SET_USED(arg);
    this_lcore_socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    this_lcore_neigh_tables_p = (struct neigh_table *)rte_zmalloc_socket
        ("new_neigh_table", sizeof(struct neigh_table) * MAX_ROUTE_TBLS, 
        RTE_CACHE_LINE_SIZE, this_lcore_socket_id);
    if (this_lcore_neigh_tables_p == NULL){
        return -ENOMEM;
    }

    for (j = 0; j < MAX_ROUTE_TBLS; j++) {
        for (i = 0; i < NEIGH_BUCKETS_NUM; i++) {
            INIT_HLIST_HEAD(&this_lcore_neigh_tables_p[j].ht[i]);
        }
        rte_atomic32_set(&this_lcore_neigh_tables_p[j].cnt, 0);
        this_lcore_neigh_tables_p[j].table_id = j;          
    }

    g_lcores_neigh_tables_p[rte_lcore_id()] = this_lcore_neigh_tables_p;

    return 0;
}

int neigh_table_dump(void *arg)
{
    int i;
    struct neigh_entry *neigh_node;
    uint32_t table_id;
    char ip_str[INET6_ADDRSTRLEN] = {0};

    if (unlikely((arg == NULL) || ((table_id = *(uint32_t *)arg) >= MAX_ROUTE_TBLS))) {
        return -EINVAL;
    }

    if (this_lcore_neigh_tables_p[table_id].cnt.cnt) {
        
        L3_DEBUG_TRACE(L3_INFO, "neigh table:%u=========cnt:%d\n", 
            table_id, this_lcore_neigh_tables_p[table_id].cnt.cnt);
        for (i = 0; i < NEIGH_BUCKETS_NUM; i++) {
            hlist_for_each_entry(neigh_node, &this_lcore_neigh_tables_p[table_id].ht[i], hnode) {
                L3_DEBUG_TRACE(L3_INFO, "neigh table=====%s=%02X:%02X:%02X:%02X:%02X:%02X\n", 
                    inet_ntop(neigh_node->af, (void *)&neigh_node->next_hop, ip_str, INET6_ADDRSTRLEN),
                    neigh_node->d_mac.addr_bytes[0],
                    neigh_node->d_mac.addr_bytes[1],
                    neigh_node->d_mac.addr_bytes[2],
                    neigh_node->d_mac.addr_bytes[3],
                    neigh_node->d_mac.addr_bytes[4],
                    neigh_node->d_mac.addr_bytes[5]);
            }
        }
    }

    return 0;
}

int neigh_tables_dump(void *arg)
{
    uint32_t table_id;
    int ret;
    
    RTE_SET_USED(arg);
    for (table_id = 0; table_id < MAX_ROUTE_TBLS; table_id++) {
        if ((ret = neigh_table_dump((void *)&table_id)) < 0) {
            return ret;
        }
    }
    return 0;
}

static int neigh_entry_expire(struct neigh_entry *neighbour)
{
    struct neigh_mbuf_entry *mbuf, *mbuf_next;

    dpvs_timer_cancel_nolock(&neighbour->timer, false);
    arp_neigh_del_ht(neighbour);

    /* release pkts saved in neighbour entry */
    list_for_each_entry_safe(mbuf, mbuf_next,
              &neighbour->queue_list, neigh_mbuf_list) {
        list_del(&mbuf->neigh_mbuf_list);
        rte_pktmbuf_free(mbuf->m);
        dpvs_mempool_put(neigh_mempool, mbuf);
    }

    dpvs_mempool_put(neigh_mempool, neighbour);

    return DTIMER_STOP;
}

static int neighbour_timer_event(void *data)
{
    struct neigh_entry *neighbour = data;

    if (neighbour->state == NODE_NUD_S_NONE) {
        return neigh_entry_expire(neighbour);
    }
    neigh_entry_state_trans_graph(neighbour, 4);
    return DTIMER_OK;
}

struct neigh_entry *
neigh_add_tbl(uint32_t table_id, int af, 
              union inet_addr *ipaddr,
              const struct rte_ether_addr *eth_addr,
              struct netif_port *port,
              int flag)
{
    struct neigh_entry *new_neighbour = NULL;
    struct timeval delay;

    new_neighbour = (struct neigh_entry *)dpvs_mempool_get(
        neigh_mempool, sizeof(struct neigh_entry));
    if (unlikely(new_neighbour == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:new_neighbour is null\n", __func__);
        return NULL;
    }

    rte_memcpy(&new_neighbour->next_hop, ipaddr, sizeof(union inet_addr));
    new_neighbour->flag = flag;
    new_neighbour->af   = af;
    new_neighbour->table_id = table_id;

    if (eth_addr) {
        rte_memcpy(&new_neighbour->d_mac, eth_addr, 6);
        new_neighbour->state = NODE_NUD_S_REACHABLE;
    } else {
        new_neighbour->state = NODE_NUD_S_NONE;
    }

    new_neighbour->port = port;
    new_neighbour->que_num = 0;
    delay.tv_sec = nud_timeouts[new_neighbour->state];
    delay.tv_usec = 0;

    INIT_LIST_HEAD(&new_neighbour->queue_list);

    if (!(new_neighbour->flag & NEIGH_STATIC)) {
        dpvs_time_rand_delay(&delay, 200000); /* delay 200ms randomly to avoid timer performance problem */
        dpvs_timer_sched(&new_neighbour->timer, &delay,
                neighbour_timer_event, new_neighbour, false);
    }

    if (arp_neigh_add_ht(new_neighbour)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:arp_neigh_add_ht err\n", __func__);
        return NULL;
    }

    return new_neighbour;
}

/* dup from dpvs neigh.c */
/***********************fill mac hdr before send pkt************************************/
static void 
neigh_fill_mac_graph(struct neigh_entry *neighbour,
                     struct rte_mbuf *m,
                     const struct in6_addr *target,
                     struct netif_port *port)
{
    struct rte_ether_hdr *eth;
    struct rte_ether_addr mult_eth;
    uint16_t pkt_type;

    m->l2_len = sizeof(struct rte_ether_hdr);
    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct rte_ether_hdr));

    if (!neighbour && target) {
        ipv6_mac_mult(target, &mult_eth);
        rte_ether_addr_copy(&mult_eth, &eth->d_addr);
    } else {
        rte_ether_addr_copy(&neighbour->d_mac, &eth->d_addr);
    }

    rte_ether_addr_copy(&port->addr, &eth->s_addr);
    //pkt_type = (uint16_t)m->packet_type;
    pkt_type = RTE_ETHER_TYPE_IPV6;
    eth->ether_type = rte_cpu_to_be_16(pkt_type);
}

/* saddr can be 0 in ns for dad in addrconf_dad_timer */
static struct rte_mbuf *
ndisc_send_ns_graph(struct netif_port *dev,
                    const struct in6_addr *solicit,
                    const struct in6_addr *daddr,
                    const struct in6_addr *saddr)
{
    struct rte_mbuf *mbuf;
    struct icmp6_hdr icmp6h;
    struct ip6_hdr *hdr;

    if (saddr == NULL) {
        /* in route module */
        return NULL;
    }

    memset(&icmp6h, 0, sizeof(icmp6h));
    icmp6h.icmp6_type = ND_NEIGHBOR_SOLICIT;

    mbuf = ndisc_build_mbuf(dev, daddr, saddr, &icmp6h, solicit,
              !ipv6_addr_any(saddr) ? ND_OPT_SOURCE_LINKADDR : 0);
    if (!mbuf)
        return NULL;

    hdr = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*hdr));
    if (unlikely(!hdr)) {
        return mbuf;
    }

    memset(hdr, 0, sizeof(*hdr));
    hdr->ip6_vfc    = 0x60;
    /*
     * na packet do not need to set tos and flow-lable
    hdr->ip6_flow  |= htonl(((uint64_t)fl6->fl6_tos<<20) | \
                            (ntohl(fl6->fl6_flow)&0xfffffUL));
    */
    hdr->ip6_plen   = htons(mbuf->pkt_len - sizeof(*hdr));
    hdr->ip6_nxt    = IPPROTO_ICMPV6;
    hdr->ip6_hlim   = 255;
    hdr->ip6_src    = *saddr;
    hdr->ip6_dst    = *daddr;

#ifdef CONFIG_NDISC_DEBUG
    ndisc_show_addr(__func__, saddr, daddr);
#endif

    neigh_fill_mac_graph(NULL, mbuf, daddr, dev);
    mbuf->l2_len = sizeof(struct rte_ether_hdr);
    mbuf->l3_len = sizeof(struct ip6_hdr);
    /* set out port to L2 */
    mbuf_dev_set(mbuf, dev);

    return mbuf;
}

static struct rte_mbuf *
ndisc_solicit_graph(struct neigh_entry *neigh,
                   const struct in6_addr *saddr)
{
    struct in6_addr mcaddr;
    struct netif_port *dev = neigh->port;
    struct in6_addr *target = &neigh->next_hop.in6;

    addrconf_addr_solict_mult(target, &mcaddr);
    return ndisc_send_ns_graph(dev, target, &mcaddr, saddr);
}

static struct rte_mbuf *
neigh_state_confirm_graph(struct neigh_entry *neighbour)
{
    union inet_addr saddr, daddr;

    memset(&saddr, 0, sizeof(saddr));

    if (neighbour->af == AF_INET) {
        daddr.in.s_addr = neighbour->next_hop.in.s_addr;
        inet_addr_select(AF_INET, neighbour->port, &daddr, 0, &saddr);
        if (!saddr.in.s_addr)
            L3_DEBUG_TRACE(L3_ERR, "%s: no source ip\n", __func__);

        return(arp_pack_req(neighbour->port, saddr.in.s_addr, daddr.in.s_addr));
    } else if (neighbour->af == AF_INET6) {
        ipv6_addr_copy(&daddr.in6, &neighbour->next_hop.in6);
        inet_addr_select(AF_INET6, neighbour->port, &daddr, 0, &saddr);

        if (ipv6_addr_any(&saddr.in6))
            L3_DEBUG_TRACE(L3_ERR, "%s: no source ip\n", __func__);

        return ndisc_solicit_graph(neighbour, &saddr.in6);
    }

    return NULL;
}

void 
neigh_entry_state_trans_graph(struct neigh_entry *neighbour, int idx)
{
    struct timeval timeout;

    /* NODE_NUD_S_KEEP is not a real state, just use it to keep original state */
    if ((nud_states[idx].next_state[neighbour->state] != NODE_NUD_S_KEEP)
        && !(neighbour->flag & NEIGH_STATIC)) {
        int old_state = neighbour->state;
        struct timespec now = { 0 };

        neighbour->state = nud_states[idx].next_state[neighbour->state];
        if (neighbour->state == old_state) {
            if (likely(clock_gettime(CLOCK_REALTIME_COARSE, &now)) == 0)
                /* frequent timer updates hurt performance,
                 * do not update timer unless half timeout passed */
                if ((now.tv_sec - neighbour->ts) * 2 < nud_timeouts[old_state])
                    return;
        }

        timeout.tv_sec = nud_timeouts[neighbour->state];
        timeout.tv_usec = 0;
        dpvs_time_rand_delay(&timeout, 200000); /* delay 200ms randomly to avoid timer performance problem */
        dpvs_timer_update_nolock(&neighbour->timer, &timeout, false);
        neighbour->ts = now.tv_sec;
    }
}

uint16_t 
neigh_output_graph(uint32_t table_id, int af, 
                   union inet_addr *nexhop,
                   struct rte_mbuf *m, struct netif_port *port,
                   struct rte_mbuf **m2,
                   struct rte_graph *graph,
                   struct rte_node *node,
                   rte_edge_t next)
{
    struct neigh_entry *neighbour;
    struct neigh_mbuf_entry *m_buf;

    *m2 = NULL;
    if (port->flags & NETIF_PORT_FLAG_NO_ARP)
        return NEIGH_OUT_RS_OK;

    if (af == AF_INET6 && ipv6_addr_is_multicast((struct in6_addr *)nexhop)) {
        neigh_fill_mac_graph(NULL, m, (struct in6_addr *)nexhop, port);
        return NEIGH_OUT_RS_OK;
    }

#ifdef CONFIG_DPVS_NEIGH_DEBUG
    neigh_show_nexthop(__func__, af, nexhop, port);
#endif

    neighbour = neigh_lookup(table_id, af, nexhop);

    if (neighbour) {
        if (neighbour->flag & NEIGH_STATIC) {
            neigh_populate_mac(neighbour, m, port, af);
            return NEIGH_OUT_RS_OK;
        }

        switch (neighbour->state) {
        case NODE_NUD_S_NONE:
        case NODE_NUD_S_SEND:
            if (neighbour->que_num > arp_unres_qlen) {
                /*
                 * don't need arp request now,
                 * since neighbour will not be confirmed
                 * and it will be released late
                 */
                return NEIGH_OUT_RS_DROP;
            }

            m_buf = (struct neigh_mbuf_entry *)dpvs_mempool_get(
                neigh_mempool, sizeof(struct neigh_mbuf_entry));
            if (unlikely(!m_buf)) {
                return NEIGH_OUT_RS_DROP;
            }

            m_buf->m = m;
            m_buf->graph = graph;
            m_buf->node  = node;
            m_buf->next  = next;
            list_add_tail(&m_buf->neigh_mbuf_list, &neighbour->queue_list);
            neighbour->que_num++;

            if (neighbour->state == NODE_NUD_S_NONE) {
                *m2 = neigh_state_confirm_graph(neighbour);
                neigh_entry_state_trans_graph(neighbour, 0);
            }

            return NEIGH_OUT_RS_HANG;

        case NODE_NUD_S_REACHABLE:
        case NODE_NUD_S_PROBE:
        case NODE_NUD_S_DELAY:
            neigh_populate_mac(neighbour, m, port, af);
            if (neighbour->state == NODE_NUD_S_PROBE) {
                *m2 = neigh_state_confirm_graph(neighbour);
                neigh_entry_state_trans_graph(neighbour, 0);
            }
            return NEIGH_OUT_RS_OK;
        default:
            return NEIGH_OUT_RS_MAX;
        }
    }

    /* create the neighbour entry if not found */
    neighbour = neigh_add_tbl(table_id, af, nexhop, NULL, port, 0);
    if (!neighbour) {
        L3_DEBUG_TRACE(L3_ERR, "%s:neigh_add_tbl failed\n", __func__);
        return NEIGH_OUT_RS_DROP;
    }

    m_buf = (struct neigh_mbuf_entry *)dpvs_mempool_get(
        neigh_mempool, sizeof(struct neigh_mbuf_entry));
    if (unlikely(!m_buf)) {
        return NEIGH_OUT_RS_DROP;
    }
    m_buf->m = m;
    m_buf->graph = graph;
    m_buf->node  = node;
    m_buf->next  = next;
    list_add_tail(&m_buf->neigh_mbuf_list, &neighbour->queue_list);
    neighbour->que_num++;

    if (neighbour->state == NODE_NUD_S_NONE) {
        *m2 = neigh_state_confirm_graph(neighbour);
        neigh_entry_state_trans_graph(neighbour, 0);
    }

    return NEIGH_OUT_RS_HANG;
}

void 
neigh_send_mbuf_cach_graph(struct neigh_entry *neighbour)
{
    struct neigh_mbuf_entry *mbuf, *mbuf_next;
    struct rte_mbuf *m;

    list_for_each_entry_safe(mbuf, mbuf_next,
                             &neighbour->queue_list, neigh_mbuf_list) {
        list_del(&mbuf->neigh_mbuf_list);
        m = mbuf->m;
        neigh_populate_mac(neighbour, m, neighbour->port, neighbour->af);                
        rte_node_enqueue_x1(mbuf->graph, mbuf->node, mbuf->next, m);
        neighbour->que_num--;
        dpvs_mempool_put(get_neigh_mempool(), mbuf);
    }
}

struct raw_neigh* 
neigh_ring_clone_graph(void *param, bool add)
{
    struct raw_neigh* mac_param;
    struct neigh_entry *neighbour = (struct neigh_entry *)param;

    mac_param = dpvs_mempool_get(neigh_mempool, sizeof(struct raw_neigh));
    if (unlikely(mac_param == NULL))
        return NULL;
    mac_param->af = neighbour->af;
    mac_param->table_id = neighbour->table_id;
    rte_memcpy(&mac_param->ip_addr, &neighbour->next_hop, sizeof(union inet_addr));
    mac_param->flag = neighbour->flag & ~NEIGH_HASHED;
    mac_param->type = NEIGH_GRAPH;
    mac_param->port = neighbour->port;
    mac_param->add = add;
    /*just copy*/
    rte_memcpy(&mac_param->eth_addr, &neighbour->d_mac, 6);

    return mac_param;
}

void 
neigh_add_by_param_graph(struct raw_neigh *param)
{
    unsigned int hash;
    struct neigh_entry *neighbour;

    neighbour = neigh_lookup(param->table_id, param->af,
                             &param->ip_addr);
    if (param->add) {
        if (neighbour) {
            rte_memcpy(&neighbour->d_mac, &param->eth_addr, 6);
        } else {
            neighbour = neigh_add_tbl(param->table_id, param->af,
                                      &param->ip_addr,
                                      &param->eth_addr, 
                                      param->port,
                                      param->flag);
            if (unlikely(!neighbour))
                return;
        }
        if (!(param->flag & NEIGH_STATIC))
            neigh_entry_state_trans_graph(neighbour, 1);
        neigh_send_mbuf_cach_graph(neighbour);
    } else {
        if (neighbour) {
            struct neigh_mbuf_entry *mbuf, *mbuf_next;
            if (!(neighbour->flag & NEIGH_STATIC))
                dpvs_timer_cancel_nolock(&neighbour->timer, false);
            arp_neigh_del_ht(neighbour);
            /* release pkts saved in neighbour entry */
            list_for_each_entry_safe(mbuf, mbuf_next,
                                     &neighbour->queue_list, 
                                     neigh_mbuf_list) {
                list_del(&mbuf->neigh_mbuf_list);
                rte_pktmbuf_free(mbuf->m);
                dpvs_mempool_put(neigh_mempool, mbuf);
            }
            dpvs_mempool_put(neigh_mempool, neighbour);
        } /* else {
            RTE_LOG(WARNING, NEIGHBOUR, "%s: not exist\n", __func__);
        }
        */
    }
}

int 
neigh_init_graph(void)
{
    /* mempool for "neigh_entry"(128 bytes), "raw_neigh"(64 byte) and
     * "neigh_mbuf_entry"(64 bytes), mempool use 4MB memory in total,
     * and can provide memory for up to 8K neighbour entries. */
    /* try to use legacy neigh_mempool
    neigh_mempool = dpvs_mempool_create("neigh_mempool_graph", 32, 256, 1024);
    if (!neigh_mempool) {
        RTE_LOG(ERR, NEIGH_GRAPH, "neigh_mempool_graph create faied\n");
        return -1;
    }
    */

    return 0;
}

struct dpvs_mempool *get_neigh_mempool(void)
{
   return neigh_mempool;
}

