#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include <string.h>
#include<net/if.h>
#include<net/if_arp.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<errno.h>
#include "sys_time.h"
#include "scheduler.h"
#include "l2/include/dev.h"
#include "l2.h"

int skfd = 0;

static void
ifstate_log(char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
}

static int 
link_detect(uint16_t port_id, struct netif_port **port_out)
{
    struct netif_port *port;
	struct rte_eth_link link;
	int rc;

	port = netif_port_get(port_id);
	if (!port)
		return EDPVS_NOTEXIST;
	rc = netif_get_link(port, &link);
	if (rc != EDPVS_OK) {
		return rc;
	}
    *port_out = port; 
	return (link.link_status==ETH_LINK_UP)?0:1;
#if 0
	strcpy((char *)ifr.ifr_name, net_name);
	rc = ioctl(skfd, SIOCGIFFLAGS, &ifr);
	if (rc < 0) {
		printf("%s:%d IOCTL error!\n", __FILE__, __LINE__);
		printf("Maybe inferface %s is not valid!", ifr.ifr_name);
		return -1;
	}

	if(ifr.ifr_flags & IFF_RUNNING) {
		return 0;
	} else {
		return -1;
	}
#endif
}
static uint16_t phy_netdev_nb; 
struct timeval *link_time_record = NULL;
static int g_ifp_status[NETIF_MAX_PORTS];
static char if_name[NETIF_MAX_PORTS][IFNAMSIZ];

/**
 ******************************************************************************
 * @brief   tv0 与 tv1 相减, 相差1ms返回true
******************************************************************************
 */

bool timval_diff_1ms(struct timeval *tv0, struct timeval *tv1){
    double time1, time2;
    if(tv0->tv_sec != tv1->tv_sec)
        return true;
    time1 = tv0->tv_usec;
    time2 = tv1->tv_usec;
    
    time1 = time1 - time2;
    if (time1 < 0)
        time1 = -time1;

    if(time1>1000)
        return true;
    else
        return false;
}

static void
ifstate_proc(void *dummy)
{
	int ifp_status = 0;
    uint16_t i=0;
	struct timeval tv;
    struct netif_port *port;
    unsigned long event;
    static struct timeval last_time = {0, 0};
	gettimeofday(&tv, NULL);
    if (timval_diff_1ms(&last_time, &tv)) {
        for(; i<phy_netdev_nb; i++){
    		ifp_status = link_detect(i, &port);
    		if ((ifp_status >= 0) &&(ifp_status != g_ifp_status[i])) {
    			ifstate_log("%s is %s\n", if_name[i], (ifp_status==0)?"UP":"DOWN");
                g_ifp_status[i] = ifp_status;
    		    rte_memcpy(&link_time_record[i], &tv, sizeof(struct timeval));
                (ifp_status==0)?(event = NETDEV_UP,port->flags |= NETIF_PORT_FLAG_UP):
                    (event = NETDEV_DOWN,port->flags &= ~NETIF_PORT_FLAG_UP);
                call_netdevice_notifiers(event, port);
    	    }
        }
        rte_memcpy(&last_time, &tv, sizeof(struct timeval));
    }
    

}

static struct dpvs_lcore_job ifstate_job = {
    .name = "ifstate_proc",
    .type = LCORE_JOB_LOOP,
    .func = ifstate_proc,
};

extern int
ifstate_init(void);
int
ifstate_init(void)
{
	int err;
    int i;
    struct netif_port *port;
    
	//if_name = "dpdk0";
	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd < 0) {
		printf("%s:%d Open socket error!\n", __FILE__, __LINE__);
		return -1;
	}
    
    phy_netdev_nb = netif_port_count();
    link_time_record = rte_malloc("link_time_record", sizeof(struct timeval) * phy_netdev_nb,
			RTE_CACHE_LINE_SIZE);
    if(link_time_record == NULL){
        printf("%s:%d malloc link_time_record error!\n", __FILE__, __LINE__);
        return -1;
    }

    memset(&g_ifp_status, 0, sizeof(g_ifp_status));
    for(i=0; i<phy_netdev_nb; i++){
        port = netif_port_get(i);
        strlcpy(if_name[i], port->name, IFNAMSIZ);
    }
        
    if ((err = dpvs_lcore_job_register(&ifstate_job, LCORE_ROLE_MASTER)) != EDPVS_OK)
        return err;
	return EDPVS_OK;
}

extern int
ifstate_term(void);
extern int
ifstate_term(void)
{
	close(skfd);
	skfd = -1;

	dpvs_lcore_job_unregister(&ifstate_job, LCORE_ROLE_MASTER);
	return EDPVS_OK;
}
