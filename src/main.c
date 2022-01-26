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

/*
 * '_GNU_SOURCE' has been defined in newer DPDK's makefile
 * (e.g., 18.11) but not in order DPDK (e.g., 17.11).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pidfile.h"
#include "dpdk.h"
#include "conf/common.h"
#include "netif.h"
#include "vlan.h"
#include "inet.h"
#include "timer.h"
#include "ctrl.h"
#include "ipv4.h"
#include "neigh.h"
#include "sa_pool.h"
#include "ipvs/ipvs.h"
#include "cfgfile.h"
#include "ip_tunnel.h"
#include "sys_time.h"
#include "route6.h"
#include "iftraf.h"
#include "eal_mem.h"
#include "scheduler.h"
#include "pdump.h"
#include "general_rcu.h"
#include "fw_conf/fw_cli.h"
#include "fw_conf/fw_conf.h"
#include "l2.h"
#include "fw_conf/fw_cli.h"
#include "fw_conf/fw_conf.h"
#include "setproctitle.h"
#include "start_process.h"
#include "session_public.h"
#include "fw-base/session_mbuf.h"
#include "fw-base/dpi.h"
#include "flow_l3_cfg_init_priv.h"
#include "lib/scheduler.h"
#include "vrrp/vrrp.h"
#include "vrrp/vrrp_daemon.h"
#include "vrrp/vrrp_data.h"
#include "vrrp/vrrp_ring.h"

#define DPVS    "dpvs"
#define RTE_LOGTYPE_DPVS RTE_LOGTYPE_USER1

#define LCORE_CONF_BUFFER_LEN 4096

#ifdef CONFIG_DPVS_PDUMP
extern bool g_dpvs_pdump;
#endif
extern int log_slave_init(void);
struct dpvs_timer   graph_print_timer;


/*
 * the initialization order of all the modules
 */
extern int
ifstate_init(void);
extern int
ifstate_term(void);
#define DPVS_MODULES {                                          \
        DPVS_MODULE(MODULE_FIRST,       "scheduler",            \
                    dpvs_scheduler_init, dpvs_scheduler_term),  \
        DPVS_MODULE(MODULE_GLOBAL_DATA, "global data",          \
                    global_data_init,    global_data_term),     \
        DPVS_MODULE(MODULE_FWCLI,       "fw cli init",          \
                    fw_cli_init,         fw_cli_term),          \
        DPVS_MODULE(MODULE_FWCONF,      "fw conf init",         \
                    fw_conf_init,        fw_conf_term),         \
        DPVS_MODULE(MODULE_PROCESS,     "fw process",           \
                    start_process_cfg_irrelevant, NULL),        \
        DPVS_MODULE(MODULE_CFG,         "config file",          \
                    cfgfile_init,        cfgfile_term),         \
        DPVS_MODULE(MODULE_PDUMP,        "pdump",               \
                    pdump_init,          pdump_term),           \
        DPVS_MODULE(MODULE_NETIF_VDEV,  "vdevs",                \
                    netif_vdevs_add,     NULL),                 \
        DPVS_MODULE(MODULE_TIMER,       "timer",                \
                    dpvs_timer_init,     dpvs_timer_term),      \
        DPVS_MODULE(MODULE_TC,          "tc",                   \
                    tc_init,             NULL),                 \
        DPVS_MODULE(MODULE_NETIF,       "netif",                \
                    netif_init,          netif_term),           \
        DPVS_MODULE(MODULE_CTRL,        "cp",                   \
                    ctrl_init,           ctrl_term),            \
        DPVS_MODULE(MODULE_TC_CTRL,     "tc cp",                \
                    tc_ctrl_init,        NULL),                 \
        DPVS_MODULE(MODULE_VLAN,        "vlan",                 \
                    vlan_init,           NULL),                 \
        DPVS_MODULE(MODULE_INET,        "inet",                 \
                    inet_init,           inet_term),            \
        DPVS_MODULE(MODULE_SA_POOL,     "sa_pool",              \
                    sa_pool_init,        sa_pool_term),         \
        DPVS_MODULE(MODULE_IP_TUNNEL,   "tunnel",               \
                    ip_tunnel_init,      ip_tunnel_term),       \
		DPVS_MODULE(MODULE_BRIDGE,        "brctl",              \
            		br_init,              NULL),                \
        DPVS_MODULE(MODULE_L2,            "l2",                 \
            		l2_init,               NULL),               \
		DPVS_MODULE(MODULE_VS,          "ipvs",                 \
                    dp_vs_init,          dp_vs_term),           \
        DPVS_MODULE(MODULE_NETIF_CTRL,  "netif ctrl",           \
                    netif_ctrl_init,     netif_ctrl_term),      \
        DPVS_MODULE(MODULE_GENER_RCU,   "gener_rcu",            \
                    RCU_init,           NULL),                  \
        DPVS_MODULE(MODULE_IFTRAF,      "iftraf",               \
                    iftraf_init,         iftraf_term),          \
        DPVS_MODULE(MODULE_IFSTAT,      "ifstate",              \
                    ifstate_init,         ifstate_term),        \
        DPVS_MODULE(MODULE_eal_mem,        "ifstate",           \
                    eal_mem_init,        eal_mem_term),         \
        DPVS_MODULE(MODULE_FLOW_L3,     "flow l3 init",         \
                    flow_l3_init,       NULL),                  \
        DPVS_MODULE(MODULE_LAST,        "flow config file",     \
                    flow_cfgfile_init,  NULL)                   \
    }

                          
#define DPVS_MODULE(a, b, c, d)  a
enum dpvs_modules DPVS_MODULES;
#undef DPVS_MODULE

#define DPVS_MODULE(a, b, c, d)  b
static const char *dpvs_modules[] = DPVS_MODULES;
#undef DPVS_MODULE

typedef int (*dpvs_module_init_pt)(void);
typedef int (*dpvs_module_term_pt)(void);

#define DPVS_MODULE(a, b, c, d)  c
dpvs_module_init_pt dpvs_module_inits[] = DPVS_MODULES;
#undef DPVS_MODULE

#define DPVS_MODULE(a, b, c, d)  d
dpvs_module_term_pt dpvs_module_terms[] = DPVS_MODULES;

static void modules_init(void)
{
    int m, err;

    for (m = MODULE_FIRST; m <= MODULE_LAST; m++) {
        if (dpvs_module_inits[m]) {
            if ((err = dpvs_module_inits[m]()) != EDPVS_OK) {
                rte_exit(EXIT_FAILURE, "failed to init %s: %s\n",
                         dpvs_modules[m], dpvs_strerror(err));
            }
        }
    }
}

static void modules_term(void)
{
    int m, err;

    for (m = MODULE_LAST ; m >= MODULE_FIRST; m--) {
        if (dpvs_module_terms[m]) {
            if ((err = dpvs_module_terms[m]()) != EDPVS_OK) {
                rte_exit(EXIT_FAILURE, "failed to term %s: %s\n",
                         dpvs_modules[m], dpvs_strerror(err));
            }
        }
    }
}

static int set_all_thread_affinity(void)
{
    int s;
    lcoreid_t cid;
    pthread_t tid;
    cpu_set_t cpuset;
    unsigned long long cpumask=0;

    tid = pthread_self();
    CPU_ZERO(&cpuset);
    for (cid = 0; cid < RTE_MAX_LCORE; cid++)
        CPU_SET(cid, &cpuset);

    s = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        errno = s;
        perror("fail to set thread affinty");
        return -1;
    }

    CPU_ZERO(&cpuset);
    s = pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        errno = s;
        perror("fail to get thread affinity");
        return -2;
    }

    for (cid = 0; cid < RTE_MAX_LCORE; cid++) {
        if (CPU_ISSET(cid, &cpuset))
            cpumask |= (1LL << cid);
    }
    printf("current thread affinity is set to %llX\n", cpumask);

    return 0;
}

static void dpvs_usage(const char *prgname)
{
    printf("\nUsage: %s ", prgname);
    printf("DPVS application options:\n"
            "   -v  version     display DPVS version info\n"
            "   -h  help        display DPVS help info\n"
    );
}

static int parse_app_args(int argc, char **argv)
{
    const char *short_options = "vh";
    char *prgname = argv[0];
    int c, ret = -1;

    const int old_optind = optind;
    const int old_optopt = optopt;
    char * const old_optarg = optarg;

    struct option long_options[] = {
        {"version", 0, NULL, 'v'},
        {"help", 0, NULL, 'h'},
        {NULL, 0, 0, 0}
    };

    optind = 1;

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                fprintf(stderr, "dpvs version: %s, build on %s\n",
                        DPVS_VERSION,
                        DPVS_BUILD_DATE);
                exit(EXIT_SUCCESS);
            case 'h':
                dpvs_usage(prgname);
                exit(EXIT_SUCCESS);
            case '?':
            default:
                dpvs_usage(prgname);
                exit(EXIT_FAILURE);
        }
    }

    if (optind > 0)
        argv[optind-1] = prgname;

    ret = optind - 1;

    /* restore getopt lib */
    optind = old_optind;
    optopt = old_optopt;
    optarg = old_optarg;

    return ret;
}

static struct rte_graph_cluster_stats *graph_stats = NULL;

int
print_stats(void *arg)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	int err =  0;
	
	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);
	rte_graph_cluster_stats_get(graph_stats, 0);
	rte_delay_ms(1E3);

	/*cnt++;
	if(cnt == 3){
		err = dpvs_timer_cancel(&graph_print_timer, true);
		cnt = 0;
	}
	printf("finish print status\n");
	*/
	return err;
}


void init_graph_print(void){
	//struct timeval tv;
	struct rte_graph_cluster_stats_param s_param;
	const char *pattern = "worker_*";

	/* Prepare graph_stats object */
	memset(&s_param, 0, sizeof(s_param));
	s_param.f = stdout;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = &pattern;
	s_param.nb_graph_patterns = 1;

	graph_stats = rte_graph_cluster_stats_create(&s_param);
	if (graph_stats == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create graph_stats object\n");
	rte_graph_stat_printf(graph_stats);
	//tv.tv_sec = 1; /* one second */
    //tv.tv_usec = 0;

	//rte_graph_cluster_stats_destroy(graph_stats);
	//dpvs_timer_sched_period(&graph_print_timer, &tv, print_stats, NULL, true);
	
}

static int
show_graph_cli(cmd_blk_t *cbt)
{
	struct timeval tv;
	static int off = 0;
	tv.tv_sec = 1; /* one second */
    tv.tv_usec = 0;
	int err = 0;
	if(off == 0){
		dpvs_timer_sched_period(&graph_print_timer, &tv, print_stats, NULL, true);
		off = 1;
	}else{
		err = dpvs_timer_cancel(&graph_print_timer, true);
		off = 0;
	}
	//return print_stats(NULL);
    return err;
}


EOL_NODE_NEED_MAIN_EXEC(graph_status_eol, show_graph_cli);
KW_NODE(graph_status, graph_status_eol, none, "graph", "the running status of graph");

static void
graph_stauts_print_cli_init(void)
{
    add_get_cmd(&cnode(graph_status));
}

static void dpvs_final_exit(void)
{

    dpvs_state_set(DPVS_STATE_FINISH);

    /* stop child process */
    terminate_tasks();

    modules_term();

    pidfile_rm(DPVS_PIDFILE);

    return;
}

static
void sig_callback(int sig)
{
    pid_t pid;
    int err;

    switch(sig) {
    case SIGCHLD:
        pid = waitpid(-1, NULL, WNOHANG);
        set_task_exit(pid);
        break;
    case SIGINT:
    case SIGTERM:
        printf("Got signal %d pid:%d.\n", sig, getpid());
        err = dpvs_timer_cancel(&graph_print_timer, true);
        printf("timer cancel err = %u.\n", err);
        dpvs_terminate = 1;
        break;
    default:
        printf("Unkown signal type %d.\n", sig);
        break;
    }

    return;
}

static
int signal_register(int sig_no)
{
    int ret;
    struct sigaction sig;

    memset(&sig, 0, sizeof(struct sigaction));
    sig.sa_handler = sig_callback;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    ret = sigaction(sig_no, &sig, NULL);
    if (ret < 0) {
        printf("sigaction ret:%d errno:%d\n", ret, errno);
        return -1;
    }

    return 0;
}

void
cmd_init(void);
int main(int argc, char *argv[])
{
    int err, nports;
    portid_t pid;
    struct netif_port *dev;
    struct timeval tv;
    char pql_conf_buf[LCORE_CONF_BUFFER_LEN];
    int pql_conf_buf_len = LCORE_CONF_BUFFER_LEN;

    /**
     * add application agruments parse before EAL ones.
     * use it like the following:
     * ./dpvs -v
     * OR
     * ./dpvs -- -n 4 -l 0-11 (if you want to use eal arguments)
     */
    err = parse_app_args(argc, argv);
    if (err < 0) {
        fprintf(stderr, "fail to parse application options\n");
        exit(EXIT_FAILURE);
    }

    save_argv(argv);

    argc -= err, argv += err;

	//æ‰‹åŠ¨åœæ�??	//force_quit = false;
    signal_register(SIGCHLD);
    signal_register(SIGINT);
    signal_register(SIGTERM);
	
    /* check if dpvs is running and remove zombie pidfile */
    if (dpvs_running(DPVS_PIDFILE)) {
        fprintf(stderr, "dpvs is already running\n");
        exit(EXIT_FAILURE);
    }

    init_task_pcb();

    dpvs_state_set(DPVS_STATE_INIT);

    gettimeofday(&tv, NULL);
    srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());
    sys_start_time();

    if (get_numa_nodes() > DPVS_MAX_SOCKET) {
        fprintf(stderr, "DPVS_MAX_SOCKET is smaller than system numa nodes!\n");
        return -1;
    }

    if (set_all_thread_affinity() != 0) {
        fprintf(stderr, "set_all_thread_affinity failed\n");
        exit(EXIT_FAILURE);
    }

    err = rte_eal_init(argc, argv);
    if (err < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

    RTE_LOG(INFO, DPVS, "dpvs version: %s, build on %s\n", DPVS_VERSION, DPVS_BUILD_DATE);

    init_vrrp_data();
    if (vrrp_ring_init() < 0)
    {
        RTE_LOG(ERR, DPVS, "%s: vrrp ring init failed.\n", __func__);
    }

    setproctitle_init();
    DPI_Init();

	/*adapter 18*/
	err = dpdk_priv_userdata_register();
	err |= dpdk_priv_dev_register();
	if(err != EDPVS_OK){
		 RTE_LOG(ERR, DPVS, "register mbuf dyn failed = %d\n", err);
            goto end;
	}
    rte_timer_subsystem_init();

    //start_process_cfg_irrelevant();

    modules_init();

    cmd_init();
	graph_stauts_print_cli_init();

    /* config and start all available dpdk ports */
    nports = dpvs_rte_eth_dev_count();
    for (pid = 0; pid < nports; pid++) {
        dev = netif_port_get(pid);
        if (!dev) {
            RTE_LOG(WARNING, DPVS, "port %d not found\n", pid);
            continue;
        }

        err = netif_port_start(dev);
		printf("netif_port_start .........done ,err = %d\n", err);
        if(dev->type == PORT_TYPE_BOND_MASTER){
            //temp : let's bond's start to be succeed
            err = EDPVS_OK;
        }
        if (err != EDPVS_OK){
            RTE_LOG(WARNING, DPVS, "Start %s failed, skipping ...\n", dev->name);
        }else{
			init_rte_node_ethdev_config(pid);
		}
	}

	netif_init_graph_need_to_create();

	err = rte_node_eth_config(get_node_ethdev_config(), get_node_ethdev_config_nb(), netif_get_graph_need_to_create());
	if (err < 0){
		RTE_LOG(ERR, DPVS, "Init rx tx node failed err = %d\n", err);
		goto end;
	}
	
    /* print port-queue-lcore relation */
    netif_print_lcore_conf(pql_conf_buf, &pql_conf_buf_len, true, 0);
    RTE_LOG(INFO, DPVS, "\nport-queue-lcore relation array: \n%s\n",
            pql_conf_buf);

	err = init_graph_for_per_slave_core();
	if (err < 0){
		RTE_LOG(ERR, DPVS, "Init graph_for_per_slave_core failed err = %d\n", err);
		goto end;
	}

	if (rte_graph_has_stats_feature())
		init_graph_print();

    log_slave_init();

    start_process();

    err = flow_init();
    if (err < 0) {
        goto end;
    }

    SESSION_Init(NULL);
    SESSION_KMDC_Init();
    SESSION_Run(NULL);
	ASPF_Init();

    /* start slave worker threads */
    dpvs_lcore_start(0);

    /* write pid file */
    if (!pidfile_write(DPVS_PIDFILE, getpid()))
        goto end;

    dpvs_state_set(DPVS_STATE_NORMAL);

    sleep(1);
	err = RCU_start();
	if (err < 0){
		RTE_LOG(ERR, DPVS, "RCU start failed. err = %d\n", err);
		goto end;
	}
	
    //cmd_init();
	//graph_stauts_print_cli_init();
    ctflow_console_job_start();
    tyflow_vty_job_start();
    vrrp_job_start();
    /* start control plane thread loop */
    dpvs_lcore_start(1);
end:
	dpvs_final_exit();

    return 0;
}
