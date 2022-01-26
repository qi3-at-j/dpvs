
#ifndef __NODE_NEIGH_PRIV_H__
#define __NODE_NEIGH_PRIV_H__

#include "inet.h"
#include <arpa/inet.h>
#include <rte_ether.h>

#include "list.h"
#include "timer.h"
#include "neigh_sync.h"

#define RTE_LOGTYPE_NEIGH_GRAPH RTE_LOGTYPE_USER2
#define NEIGH_BUCKETS_NUM (1 << 8)
#define NEIGH_HASHED     0x01
#define NEIGH_STATIC     0x02

struct neigh_entry {
    struct hlist_node hnode;
    union inet_addr   next_hop;
    struct rte_ether_addr d_mac;
    uint32_t table_id;//for vrf
    int                 af;
    struct netif_port   *port;
    struct dpvs_timer   timer;
    struct list_head    queue_list;
    uint32_t            que_num;
    uint32_t            state;
    uint32_t            ts;
    uint8_t             flag;
} __rte_cache_aligned;

struct neigh_table { 
    struct hlist_head ht[NEIGH_BUCKETS_NUM];
    rte_atomic32_t cnt;    
    uint32_t table_id;//for vrf
};

static inline uint32_t
neigh_hashkey(int af, union inet_addr *ip_addr)
{    
    return (uint32_t)(rte_be_to_cpu_32(inet_addr_fold(af, ip_addr)) & (NEIGH_BUCKETS_NUM - 1));
}

struct neigh_entry *neigh_lookup(uint32_t table_id, int af, union inet_addr *next_hop);
int arp_neigh_add_ht(struct neigh_entry *neigh_node);
int arp_neigh_del_ht(struct neigh_entry *neigh_node);
int neigh_add(void *arg);
int neigh_del(void *arg);
int new_neigh_init(void *arg);
int neigh_table_dump(void *arg);
int neigh_tables_dump(void *arg);
int neigh_table_clear(void *arg);
int neigh_tables_clear(void *arg);

enum {
    NODE_NUD_S_NONE        = 0,
    NODE_NUD_S_SEND,
    NODE_NUD_S_REACHABLE,
    NODE_NUD_S_PROBE,
    NODE_NUD_S_DELAY,
    NODE_NUD_S_MAX /*Reserved*/
};

enum {
    NEIGH_OUT_RS_OK        = 0,
    NEIGH_OUT_RS_DROP,
    NEIGH_OUT_RS_HANG,
    NEIGH_OUT_RS_MAX /*Reserved*/
};

struct neigh_mbuf_entry {
    struct rte_mbuf   *m;
    struct rte_graph *graph;
    struct rte_node *node;
    rte_edge_t next;
    struct list_head  neigh_mbuf_list;
} __rte_cache_aligned;

struct nud_state {
    int next_state[NODE_NUD_S_MAX];
};

struct neigh_entry *
neigh_add_tbl(uint32_t table_id, int af, 
              union inet_addr *ipaddr,
              const struct rte_ether_addr *eth_addr,
              struct netif_port *port,
              int flag);

static inline void ipv6_mac_mult(const struct in6_addr *mult_target,
                                 struct rte_ether_addr *mult_eth)
{
    uint8_t *w = (uint8_t *)mult_eth;
    w[0] = 0x33;
    w[1] = 0x33;
    rte_memcpy(&w[2], &mult_target->s6_addr32[3], 4);
}

void neigh_populate_mac(struct neigh_entry *neighbour,
                        struct rte_mbuf *m,
                        struct netif_port *port,
                        int af);

void 
neigh_send_mbuf_cach_graph(struct neigh_entry *neighbour);
void 
neigh_entry_state_trans_graph(struct neigh_entry *neighbour, int idx);
uint16_t 
neigh_output_graph(uint32_t table_id, int af, 
                   union inet_addr *nexhop,
                   struct rte_mbuf *m, struct netif_port *port,
                   struct rte_mbuf **nd_req,
                   struct rte_graph *graph,
                   struct rte_node *node,
                   rte_edge_t next);
struct raw_neigh* 
neigh_ring_clone_graph(void *param, bool add);
void 
neigh_add_by_param_graph(struct raw_neigh *param);

int 
neigh_init_graph(void);
struct dpvs_mempool *get_neigh_mempool(void);
#endif
