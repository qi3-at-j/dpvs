
#ifndef __NODE_VRRP_SEND_PRIV_H__
#define __NODE_VRRP_SEND_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_ether.h>

#include "conf/inet.h"
#include "netif.h"

enum vrrp_status {
    VRRP_ST_NONE,
    VRRP_ST_SLAVE,
    VRRP_ST_MASTER,
    VRRP_ST_MAX,
};

struct vrrp_entry {
    uint8_t family; /* AF_INET or AF_INET6 */
    union inet_addr addr;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    struct netif_port *port;
    uint8_t status; /* enum vrrp_status */
};

enum vrrp_type {
    VRRP_TYPE_NONE,
    VRRP_TYPE_IP4,
    VRRP_TYPE_IP6,
    VRRP_TYPE_ARP,
    VRRP_TYPE_ND,
    VRRP_TYPE_MAX,
};

enum vrrp_send_next_nodes {
    VRRP_SEND_NEXT_DROP,
    VRRP_SEND_NEXT_IP4_OUTPUT,
    VRRP_SEND_NEXT_IP6_OUTPUT,
    VRRP_SEND_NEXT_L2_OUT,
    VRRP_SEND_NEXT_MAX,
};

struct vrrp_entry *lookup_vrrp_mac(uint8_t *mac);
struct vrrp_entry *lookup_vrrp_ip(union inet_addr *addr, uint8_t family);
int get_vrrp_status(void);

#ifdef __cplusplus
}
#endif

#endif
