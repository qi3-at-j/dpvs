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
link_detect(char* name)
{
    struct netif_port *port;
	struct rte_eth_link link;
	int rc;

	port = netif_port_get_by_name(name);
	if (!port)
		return EDPVS_NOTEXIST;
	rc = netif_get_link(port, &link);
	if (rc != EDPVS_OK) {
		return rc;
	}
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

static char *if_name;
static void
ifstate_proc(void *dummy)
{
	int ifp_status = 0;
	static struct timeval last_tv = {0};
	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (tv.tv_sec >= (last_tv.tv_sec+1)) {
		ifp_status = link_detect(if_name);
		if (ifp_status)
			ifstate_log("%s is %s\n", if_name, (ifp_status==0)?"UP":"DOWN");
		last_tv.tv_sec = tv.tv_sec;
	}
	//if (ifp_status) {
	//}
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

	if_name = "dpdk0";
	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd < 0) {
		printf("%s:%d Open socket error!\n", __FILE__, __LINE__);
		return -1;
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
