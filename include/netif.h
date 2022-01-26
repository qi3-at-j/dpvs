/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __DPVS_NETIF_H__
#define __DPVS_NETIF_H__
#include <rte_vxlan.h>
#include <net/if.h>
#include "list.h"
#include "dpdk.h"
#include "inetaddr.h"
#include "global_data.h"
#include "timer.h"
#include "tc/tc.h"
#include "session_public.h"

struct mbuf_priv_data {
    /* vrrp */
    uint8_t priv_data_vrrp_type;
    uint8_t priv_data_smac[RTE_ETHER_ADDR_LEN];

    /* vxlan */
    uint8_t priv_data_family;
    union inet_addr priv_data_src_addr;
    union inet_addr priv_data_dst_addr;
    bool priv_data_is_vxlan;
    struct rte_vxlan_hdr priv_data_vxlan_hdr;
    uint8_t priv_data_vxlan_family;
    union inet_addr priv_data_vxlan_src_addr;
    union inet_addr priv_data_vxlan_dst_addr;

    /* route */
    void *p_priv_data_route;

    /* vrf */
    uint32_t priv_data_table_id;
} __rte_cache_aligned;

#define MBUF_PRIV2_MIN_SIZE (sizeof(struct mbuf_priv_data) + SESSION_GetMbufSize())

#define RTE_LOGTYPE_NETIF RTE_LOGTYPE_USER1

#ifndef DPVS_MAX_LCORE
#define DPVS_MAX_LCORE RTE_MAX_LCORE
#endif

typedef uint64_t netdev_features_t;

enum {
    NETIF_PORT_RX_IP_CSUM_OFFLOAD      = (0x1<<1),
    NETIF_PORT_TX_IP_CSUM_OFFLOAD      = (0x1<<2),
    NETIF_PORT_TX_TCP_CSUM_OFFLOAD     = (0x1<<3),
    NETIF_PORT_TX_UDP_CSUM_OFFLOAD     = (0x1<<4),
    NETIF_PORT_TX_VLAN_INSERT_OFFLOAD  = (0x1<<5),
    NETIF_PORT_RX_VLAN_STRIP_OFFLOAD   = (0x1<<6),
    NETIF_PORT_RX_VLAN_FILTER_OFFLOAD  = (0x1<<7),

};

enum {
	NETIF_PORT_FLAG_ENABLED                 = (0x1<<0),
    NETIF_PORT_FLAG_RUNNING                 = (0x1<<1),
    NETIF_PORT_FLAG_STOPPED                 = (0x1<<2),
    NETIF_PORT_FLAG_FORWARD2KNI             = (0x1<<3),
    NETIF_PORT_FLAG_TC_EGRESS               = (0x1<<4),
    NETIF_PORT_FLAG_TC_INGRESS              = (0x1<<5),
    NETIF_PORT_FLAG_NO_ARP                  = (0x1<<6),
    NETIF_PORT_FLAG_LOOPBACK                = (0x1<<7),
    NETIF_PORT_FLAG_PROMISC                 = (0x1<<8),
    NETIF_PORT_FLAG_UP                      = (0x1<<9),
};


enum{
	/* Private (from user) interface flags (netdevice->priv_flags). */
	PRIV_FLAG_802_1Q_VLAN                   = (0x1<<0),			  /* 802.1Q VLAN device.		  */
	PRIV_FLAG_EBRIDGE	                    = (0x1<<1), 	/* Ethernet bridging device.	*/
	PRIV_FLAG_SLAVE_INACTIVE	            = (0x1<<2), /* bonding slave not the curr. active */
	PRIV_FLAG_MASTER_8023AD                 = (0x1<<3), /* bonding master, 802.3ad. 	*/
	PRIV_FLAG_MASTER_ALB	                = (0x1<<4),		/* bonding master, balance-alb. */
	PRIV_FLAG_BONDING	                    = (0x1<<5),		/* bonding master or slave	*/
	PRIV_FLAG_SLAVE_NEEDARP                 = (0x1<<6),		/* need ARPs for validation */
	PRIV_FLAG_ISATAP	                    = (0x1<<7),		/* ISATAP interface (RFC4214)	*/
	PRIV_FLAG_MASTER_ARPMON                 = (0x1<<8),		/* bonding master, ARP mon in use */
	PRIV_FLAG_WAN_HDLC	                    = (0x1<<9),		/* WAN HDLC device		*/
	PRIV_FLAG_XMIT_DST_RELEASE              = (0x1<<10),	/* dev_hard_start_xmit() is allowed to * release skb->dst  */
	PRIV_FLAG_DONT_BRIDGE                   = (0x1<<11), 	/* disallow bridging this ether dev */
	PRIV_FLAG_DISABLE_NETPOLL	            = (0x1<<12),	/* disable netpoll at run-time */
	PRIV_FLAG_MACVLAN_PORT	                = (0x1<<13),	/* device used as macvlan port */
	PRIV_FLAG_BRIDGE_PORT	                = (0x1<<14),		/* device used as bridge port */
	PRIV_FLAG_OVS_DATAPATH	                = (0x1<<15),	/* device used as Open vSwitch* datapath port */
	PRIV_FLAG_TX_SKB_SHARING	            = (0x1<<16), /* The interface supports sharing * skbs on transmit */
	PRIV_FLAG_UNICAST_FLT	                = (0x1<<17), 	/* Supports unicast filtering	*/
	PRIV_FLAG_TEAM_PORT                     = (0x1<<18), 	/* device used as team port */
	PRIV_FLAG_SUPP_NOFCS	                = (0x1<<19), 	/* device supports sending custom FCS */
	PRIV_FLAG_LIVE_ADDR_CHANGE              = (0x1<<20), /* device supports hardware address
						 * change when it's running */
};


/* max tx/rx queue number for each nic */
#define NETIF_MAX_QUEUES            16
/* max nic number used in the program */
#define NETIF_MAX_PORTS             4096
/* maximum pkt number at a single burst */
#define NETIF_MAX_PKT_BURST         32
/* maximum bonding slave number */
#define NETIF_MAX_BOND_SLAVES       32
/* maximum number of hw addr */
#define NETIF_MAX_HWADDR            1024
/* maximum number of kni device */
#define NETIF_MAX_KNI               64
/* maximum number of DPDK rte device */
#define NETIF_MAX_RTE_PORTS         64

#define NETIF_ALIGN                 32

#define NETIF_PORT_ID_INVALID       0xFF
#define NETIF_PORT_ID_ALL           NETIF_PORT_ID_INVALID

#define NETIF_LCORE_ID_INVALID      0xFF

#define MAX_RX_QUEUE_PER_LCORE 16

/************************* lcore conf  ***************************/
struct rx_partner;

/* RX/TX queue conf for lcore */
struct netif_queue_conf
{
    queueid_t id;
    uint16_t len;
    struct rx_partner *isol_rxq;
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
} __rte_cache_aligned;

struct lcore_rx_queue {
	uint16_t port_id;
	uint8_t queue_id;
	char node_name[RTE_NODE_NAMESIZE];
};

/*
 * RX/TX port conf for lcore.
 * Multiple queues of a port may be processed by a lcore.
 */
struct netif_port_conf
{
    portid_t id;
    /* rx/tx queues for this lcore to process*/
    int nrxq;
    int ntxq;
    /* rx/tx queue list for this lcore to process */
    struct netif_queue_conf rxqs[NETIF_MAX_QUEUES];
    struct netif_queue_conf txqs[NETIF_MAX_QUEUES];
} __rte_cache_aligned;

/*
 *  lcore conf
 *  Multiple ports may be processed by a lcore.
 */
struct netif_lcore_conf
{
    lcoreid_t id;
    enum dpvs_lcore_role_type type;
    /* nic number of this lcore to process */
    int nports;
    /* port list of this lcore to process */
    struct netif_port_conf pqs[NETIF_MAX_RTE_PORTS];
	//new add
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;
} __rte_cache_aligned;

/* isolate RX lcore */
struct rx_partner {
    lcoreid_t cid;
    portid_t pid;
    queueid_t qid;
    struct rte_ring *rb;
    struct netif_queue_conf *rxq; /* reverse rxq pointer */
    struct list_head lnode;
};

/**************************** lcore statistics ***************************/
struct netif_lcore_stats
{
    uint64_t lcore_loop;        /* Total number of loops since start */
    uint64_t pktburst;          /* Total number of receive bursts */
    uint64_t zpktburst;         /* Total number of receive bursts with ZERO packets */
    uint64_t fpktburst;         /* Total number of receive bursts with MAX packets */
    uint64_t z2hpktburst;       /* Total number of receive bursts with [0, 0.5*MAX] packets */
    uint64_t h2fpktburst;       /* Total number of receive bursts with (0.5*MAX, MAX] packets */
    uint64_t ipackets;          /* Total number of successfully received packets. */
    uint64_t ibytes;            /* Total number of successfully received bytes. */
    uint64_t opackets;          /* Total number of successfully transmitted packets. */
    uint64_t obytes;            /* Total number of successfully transmitted bytes. */
    uint64_t dropped;           /* Total number of dropped packets by software. */
} __rte_cache_aligned;

/******************* packet type for upper protocol *********************/
struct pkt_type {
    uint16_t type; /* htons(ether-type) */
    struct netif_port *port; /* NULL for wildcard */
    int (*func)(struct rte_mbuf *mbuf, struct netif_port *port);
    struct list_head list;
} __rte_cache_aligned;

typedef enum {
    ETH_PKT_HOST,
    ETH_PKT_BROADCAST,
    ETH_PKT_MULTICAST,
    ETH_PKT_OTHERHOST,
} eth_type_t;

/************************ data type for NIC ****************************/
typedef enum {
    PORT_TYPE_GENERAL,
    PORT_TYPE_BOND_MASTER,
    PORT_TYPE_BOND_SLAVE,
    PORT_TYPE_VLAN,
    PORT_TYPE_TUNNEL,
    PORT_TYPE_BRIDGE,
    PORT_TYPE_BRIDGE_IF,
    PORT_TYPE_INVAL,
} port_type_t;

struct netif_kni {
    char name[IFNAMSIZ];
    struct rte_kni *kni;
    struct rte_ether_addr addr;
    struct dpvs_timer kni_rtnl_timer;
    int kni_rtnl_fd;
    struct rte_ring *rx_ring;
} __rte_cache_aligned;

union netif_bond {
    struct {
        int mode; /* bonding mode */
        int slave_nb; /* slave number */
        struct netif_port *primary; /* primary device */
        struct netif_port *slaves[NETIF_MAX_BOND_SLAVES]; /* slave devices */
    } master;
    struct {
        struct netif_port *master;
    } slave;
} __rte_cache_aligned;

struct dpvs_ndmsg {
	__u8		ndm_family;
	__u8		ndm_pad1;
	__u16		ndm_pad2;
	__s32		ndm_ifindex;
	__u16		ndm_state;
	__u8		ndm_flags;
	__u8		ndm_type;
};

struct netif_ops {
    int (*op_init)(struct netif_port *dev);
    int (*op_uninit)(struct netif_port *dev);
    int (*op_open)(struct netif_port *dev);
    int (*op_stop)(struct netif_port *dev);
    int (*op_xmit)(struct rte_mbuf *m, struct netif_port *dev);
	uint16_t (*op_graph_xmit)(s_nc_param *param, struct rte_mbuf *m, struct netif_port *dev);
	int (*op_set_mac_address)(struct netif_port *dev,
						       void *addr);
    int (*op_set_mc_list)(struct netif_port *dev);
    int (*op_filter_supported)(struct netif_port *dev, enum rte_filter_type fltype);
    int (*op_set_fdir_filt)(struct netif_port *dev, enum rte_filter_op op,
                           const struct rte_eth_fdir_filter *filt);
    int (*op_get_queue)(struct netif_port *dev, lcoreid_t cid, queueid_t *qid);
    int (*op_get_link)(struct netif_port *dev, struct rte_eth_link *link);
    int (*op_get_promisc)(struct netif_port *dev, bool *promisc);
    int (*op_get_stats)(struct netif_port *dev, struct rte_eth_stats *stats);
	int	(*op_change_mtu)(struct netif_port *dev, int new_mtu);
	int (*op_add_slave)(struct netif_port *dev, struct netif_port *slave_dev);
	int (*op_del_slave)(struct netif_port *dev, struct netif_port *slave_dev);
	int	(*op_fdb_add)(struct dpvs_ndmsg *ndm,
					       struct netif_port *dev,
					       struct rte_ether_addr *addr,
					       u16 flags);
	int (*op_fdb_del)(struct dpvs_ndmsg *ndm,
					       struct netif_port *dev,
					       struct rte_ether_addr *addr);
	int (*op_vlan_rx_add_vid)(struct netif_port *dev, uint16_t vlan_id, int on);
};

struct netif_hw_addr {
    struct list_head        list;
    struct rte_ether_addr       addr;
    rte_atomic32_t          refcnt;
    /*
     * - sync only once!
     *
     *   for HA in upper dev, no matter how many times it's added,
     *   only sync once to lower (when sync_cnt is zero).
     *
     *   and HA (upper)'s refcnt++, to mark lower dev own's it.
     *
     * - when to unsync?
     *
     *   when del if HA (upper dev)'s refcnt is 1 and syn_cnt is not zero.
     *   means lower dev is the only owner and need be unsync.
     */
    int                     sync_cnt;
};

struct netif_hw_addr_list {
    struct list_head        addrs;
    int                     count;
};

struct netif_port {
    char                    name[IFNAMSIZ];  /* device name */
    portid_t                id;                         /* device id */
    port_type_t             type;                       /* device type */
    netdev_features_t       offload;                    /* device offload */
	uint32_t                flags;						/*网络设备接口的标识符,其状态类型被定义�?linux/if.h>之中� */
	uint32_t                priv_flags;
    int                     nrxq;                       /* rx queue number */
    int                     ntxq;                       /* tx queue numbe */
    uint16_t                rxq_desc_nb;                /* rx queue descriptor number */
    uint16_t                txq_desc_nb;                /* tx queue descriptor number */
    struct rte_ether_addr       addr;                       /* MAC address */
    struct netif_hw_addr_list mc;                       /* HW multicast list */
    int                     socket;                     /* socket id */
    int                     hw_header_len;              /* HW header length */
    uint16_t                mtu;                        /* device mtu */
    struct rte_mempool      *mbuf_pool;                 /* packet mempool */
    struct rte_eth_dev_info dev_info;                   /* PCI Info + driver name */
    struct rte_eth_conf     dev_conf;                   /* device configuration */
    struct rte_eth_stats    stats;                      /* last device statistics */
    rte_rwlock_t            dev_lock;                   /* device lock */
    struct list_head        list;                       /* device list node hashed by id */
    struct list_head        nlist;                      /* device list node hashed by name */
    struct inet_device      *in_ptr;
    struct netif_kni        kni;                        /* kni device */
    union netif_bond        *bond;                      /* bonding conf */
    struct vlan_info        *vlan_info;                 /* VLANs info for real device */
	struct net_bridge_port  *br_port;
	struct list_head	    upper_dev_list;             /* List of upper devices */
    struct netif_tc         tc;                         /* traffic control */
    struct netif_ops        *netif_ops;
	void (*destructor)(struct netif_port *dev);
	rte_atomic32_t      	refcnt;
    struct list_head	    dev_list;
    struct list_head	    unreg_list;
    struct list_head	    todo_list;
    	/* register/unregister state machine */
	enum { NETREG_UNINITIALIZED=0,
	       NETREG_REGISTERED,	/* completed register_netdevice */
	       NETREG_UNREGISTERING,	/* called unregister_netdevice */
	       NETREG_UNREGISTERED,	/* completed unregister todo */
	       NETREG_RELEASED,		/* called free_netdev */
	       NETREG_DUMMY,		/* dummy device for NAPI poll */
	} reg_state:8;
#ifdef CONFIG_NET_NS
        /* Network namespace this network device is inside */
        struct net      *nd_net;
#endif
    bool dismantle; /* device is going do be freed */
    struct list_head vrf_list;                          /* insert the vrf list */
    uint32_t table_id;                                  /* table id for vrf */
} __rte_cache_aligned;

/**************************** lcore API *******************************/
int netif_xmit(struct rte_mbuf *mbuf, struct netif_port *dev);
int netif_hard_xmit(struct rte_mbuf *mbuf, struct netif_port *dev);
int netif_rcv(struct netif_port *dev, __be16 eth_type, struct rte_mbuf *mbuf);
int netif_print_lcore_conf(char *buf, int *len, bool is_all, portid_t pid);
int netif_print_lcore_queue_conf(lcoreid_t cid, char *buf, int *len, bool title);
void netif_get_slave_lcores(uint8_t *nb, uint64_t *mask);
void netif_update_worker_loop_cnt(void);
// function only for init or termination //
int netif_register_master_xmit_msg(void);
int netif_lcore_conf_set(int lcores, const struct netif_lcore_conf *lconf);
bool is_lcore_id_valid(lcoreid_t cid);
bool netif_lcore_is_fwd_worker(lcoreid_t cid);
void lcore_process_packets(struct netif_queue_conf *qconf, struct rte_mbuf **mbufs,
                           lcoreid_t cid, uint16_t count, bool pkts_from_ring);
uint32_t netif_get_all_enabled_cores_nb(void);
int get_lcore_stats(lcoreid_t cid, void **out, size_t *out_len);
int get_lcore_mask(void **out, size_t *out_len);
int get_lcore_basic(lcoreid_t cid, void **out, size_t *out_len);

/************************** protocol API *****************************/
int netif_register_pkt(struct pkt_type *pt);
int netif_unregister_pkt(struct pkt_type *pt);

/**************************** port API ******************************/
int netif_fdir_filter_set(struct netif_port *port, enum rte_filter_op opcode,
                          const struct rte_eth_fdir_filter *fdir_flt);
void netif_mask_fdir_filter(int af, const struct netif_port *port,
                            struct rte_eth_fdir_filter *filt);
struct netif_port* netif_port_get(portid_t id);
/* port_conf can be NULL for default port configure */
int netif_print_port_conf(const struct rte_eth_conf *port_conf, char *buf, int *len);
int netif_print_port_queue_conf(portid_t pid, char *buf, int *len);
/* get netif by name, fail return NULL */
struct netif_port* netif_port_get_by_name(const char *name);
// function only for init or termination //
int netif_port_conf_get(struct netif_port *port, struct rte_eth_conf *eth_conf);
int netif_port_conf_set(struct netif_port *port, const struct rte_eth_conf *conf);
int netif_port_start(struct netif_port *port); // start nic and wait until up
int netif_port_stop(struct netif_port *port); // stop nic
int netif_set_mc_list(struct netif_port *port);
int __netif_set_mc_list(struct netif_port *port);
int netif_get_queue(struct netif_port *port, lcoreid_t id, queueid_t *qid);
int netif_get_link(struct netif_port *dev, struct rte_eth_link *link);
int netif_get_promisc(struct netif_port *dev, bool *promisc);
int netif_get_stats(struct netif_port *dev, struct rte_eth_stats *stats);
struct netif_port *netif_alloc(size_t priv_size, const char *namefmt,
                               unsigned int nrxq, unsigned int ntxq,
                               void (*setup)(struct netif_port *));
void netif_hold(struct netif_port *dev);
int netif_refcnt_read(struct netif_port *dev);

portid_t netif_port_count(void);
int netif_free(struct netif_port *dev);
int netif_free_rcu(struct netif_port *dev);

int netif_port_register(struct netif_port *dev);
int netif_port_unregister(struct netif_port *dev);

void netif_put(struct netif_port *dev);
void netdev_upper_dev_unlink(struct netif_port *dev,
			     struct netif_port *upper_dev);
int netdev_master_upper_dev_link(struct netif_port *dev,
				 struct netif_port *upper_dev);
int netif_set_mtu(struct netif_port *dev, int new_mtu);
int get_port_list(void **out, size_t *out_len);
int get_port_basic(struct netif_port *port, void **out, size_t *out_len);
int get_port_stats(struct netif_port *port, void **out, size_t *out_len);
int get_port_ext_info(struct netif_port *port, void **out, size_t *out_len);
int get_bond_status(struct netif_port *port, void **out, size_t *out_len);



/**************************graph API**********************************/
struct rte_node_ethdev_config *get_node_ethdev_config(void);
uint16_t get_node_ethdev_config_nb(void);
void netif_init_graph_need_to_create(void);
uint16_t  netif_get_graph_need_to_create(void);

extern volatile bool force_quit;

inline eth_type_t eth_type_parse(const struct rte_ether_hdr *eth_hdr,
                                        const struct netif_port *dev);


/************************** module API *****************************/
int netif_vdevs_add(void);
int netif_init(void);
int netif_term(void); /* netif layer cleanup */
int netif_ctrl_init(void); /* netif ctrl plane init */
int netif_ctrl_term(void); /* netif ctrl plane cleanup */

void netif_cfgfile_init(void);
void netif_keyword_value_init(void);
void install_netif_keywords(void);


static inline void *netif_priv(struct netif_port *dev)
{
    return (char *)dev + __ALIGN_KERNEL(sizeof(struct netif_port), NETIF_ALIGN);
}

static inline struct netif_tc *netif_tc(struct netif_port *dev)
{
    return &dev->tc;
}

struct rte_mempool *get_mbuf_mempool(void);

static inline uint16_t dpvs_rte_eth_dev_count(void)
{
#if RTE_VERSION < RTE_VERSION_NUM(18, 11, 0, 0)
    return rte_eth_dev_count();
#else
    return rte_eth_dev_count_avail();
#endif
}

extern bool dp_vs_fdir_filter_enable;

/*************************************************************netif port rcu 相关***********************************************/
#define PORT_RCU_DQ_SIZE				1024
#define PORT_RCU_DQ_RECLAIM_THD	    1//256//64
#define PORT_RCU_DQ_RECLAIM_MAX	    16

void netif_free_defer(struct rte_hash_rcu_config *cfg, struct netif_port *dev);
void netif_free_defer_dq(void *p, void *element, unsigned int n);
int netif_port_slave_rcu_reader_register_and_online(void);
void netif_port_rcu_report_quiescent(lcoreid_t cid);



#endif /* __DPVS_NETIF_H__ */
