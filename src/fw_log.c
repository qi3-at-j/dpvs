#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <rte_ring.h>
//#include <rte_errno.h>
#include <rte_mempool.h>

#include "parser/parser.h"
#include "fw_log.h"

#define FW_LOG_RING_NAME     "fw-log-ring"
#define FW_LOG_MEMPOOL_NAME  "fw-log-mempool"
#define FW_LOG_SIZE           4096  // min size

typedef void (*sighandler_t)(int);

enum {
    FW_LOG_TYPE_OP = 1,
    FW_LOG_TYPE_EVENT,
    FW_LOG_TYPE_FLOW,
    FW_LOG_TYPE_ATTACK,
    FW_LOG_TYPE_MAX
};

typedef struct _fw_log_cfg_ {
    char server_ip[INET6_ADDRSTRLEN];
    uint16_t server_port;
    uint32_t ring_size;
} fw_log_cfg_s;

typedef struct _fw_log_op_ {
    time_t   time;
    uint32_t level;
    uint16_t  tenant;
    char msg[64];
} fw_log_op_s;

typedef struct _ip_addr_ {
    uint16_t in_type;  // AF_INET AF_INET6
    union {
        struct in_addr  ip4;
        struct in6_addr ip6;
    };
} ip_addr_s;

typedef struct _fw_log_event_ {
    time_t    time;
    uint16_t  class;
    uint16_t  origin;
    uint32_t  ips_rule_id;
    ip_addr_s src;
    ip_addr_s dst;
    uint16_t  d_port;
    uint16_t  direction;
    uint16_t  app_type;
    uint16_t  level;
    uint16_t  action;
    uint16_t  tenant;
} fw_log_event_s;

typedef struct _fw_log_flow_ {
    time_t    time;
    ip_addr_s src;
    ip_addr_s dst;
    uint16_t  d_port;
    uint16_t  direction;
    uint16_t  app_type;
    uint16_t  protocol;
    uint16_t  action;
    uint64_t  bytes;
    uint64_t  packets;
    uint16_t  sec_policy_id;
    uint16_t  tenant;
} fw_log_flow_s;

typedef struct _fw_log_item_ {
    uint16_t type; /* In gui, conversion type to name */
    uint16_t vrf;  // user id
    union {
        fw_log_op_s op;
        fw_log_event_s event;
        fw_log_flow_s flow;
    } un;
} __rte_cache_aligned fw_log_item_s;


static fw_log_cfg_s log_cfg;
static struct rte_ring *log_ring;
static struct rte_mempool *log_mempool;

static void log_cfg_handler(vector_t tokens)
{
    return;
}

static void server_ip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    in_addr_t ip;
    int32_t s;

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);

    s = inet_pton(AF_INET, str, &ip);
    if (s > 0) {
        if (ip != INADDR_ANY && ip != INADDR_BROADCAST) {
            snprintf(log_cfg.server_ip, INET6_ADDRSTRLEN, "%s", str);
            FREE_PTR(str);
            return;
        }
    }

    RTE_LOG(ERR, CFG_FILE, "%s: %s\n", __func__, str);

    FREE_PTR(str);

    return;
}

static void server_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    log_cfg.server_port = atoi(str);

    FREE_PTR(str);

    return;
}

static void ring_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    log_cfg.ring_size = atoi(str);

    FREE_PTR(str);

    return;
}

void install_log_keywords(void)
{
    install_keyword_root("fw_log_conf", log_cfg_handler);
    install_keyword("server_ip", server_ip_handler, KW_TYPE_NORMAL);
    install_keyword("server_port", server_port_handler, KW_TYPE_NORMAL);
    install_keyword("ring_size", ring_size_handler, KW_TYPE_NORMAL);

    return;
}

static int32_t log_setup(void)
{
    sighandler_t old_handler;
    char *setup_file = "./fw_tools/fw_log_setup.sh";
    char cmd[256];
    int32_t ret;

    if (log_cfg.server_ip[0] == 0) {
        return -1;
    }

    snprintf(cmd, 256, "%s %s %d", setup_file, log_cfg.server_ip, log_cfg.server_port);
    old_handler = signal(SIGCHLD, SIG_DFL);
    ret = system(cmd);
    signal(SIGCHLD, old_handler);
    if (ret == 0 && WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
        return 0;
    }

    return -1;
}

static int32_t log_init(void)
{
    struct rte_ring *ring;
    struct rte_mempool *mempool;
    uint32_t size;

    size = RTE_MAX(log_cfg.ring_size, FW_LOG_SIZE);

    ring = rte_ring_create(FW_LOG_RING_NAME, size, SOCKET_ID_ANY, RING_F_SC_DEQ);
    if (!ring) {
        return -1;
    }

    mempool = rte_mempool_create(FW_LOG_MEMPOOL_NAME, size, sizeof(fw_log_item_s),
            0, 0, NULL, NULL, NULL, NULL, SOCKET_ID_ANY, MEMPOOL_F_SP_PUT);
    if (!mempool) {
        rte_ring_free(ring);
        return -1;
    }

    log_ring = ring;
    log_mempool = mempool;

    return 0;
}

static void log_output(void)
{
    int ret;
#define MSG_SIZE 256
    char msg_data[MSG_SIZE] = {0};
    fw_log_item_s *item;

    ret = rte_ring_dequeue(log_ring, (void **)&item);
    if (ret < 0) {
        // -ENOENT
        return;
    }

    switch (item->type) {
    case FW_LOG_TYPE_OP:
        snprintf(msg_data, MSG_SIZE, "%s", "hello");
        break;
    case FW_LOG_TYPE_EVENT:
        snprintf(msg_data, MSG_SIZE, "%s", "hello");
        break;
    case FW_LOG_TYPE_FLOW:
        snprintf(msg_data, MSG_SIZE, "%s", "hello");
        break;
    case FW_LOG_TYPE_ATTACK:
    default:
        break;
    }

    /* output to log server */
    if (msg_data[0] != 0) {
        syslog(LOG_INFO, "%s", msg_data);
    }

    rte_mempool_put(log_mempool, item);

    return;
}

int fw_log_op_out(void)
{
    int ret;
    fw_log_item_s *item = NULL;
    
    if (unlikely(!log_ring || !log_mempool)) {
        return -1;
    }

    ret = rte_mempool_get(log_mempool, (void **)&item);
    if (unlikely(ret < 0 || item == NULL)) {
        RTE_LOG(ERR, EAL, "fw-log mempool get error.\n");
        return -1;
    }

    /* init item */
    //TODO

    ret = rte_ring_enqueue(log_ring, item);
    if (unlikely(ret < 0)) {
        // -ENOBUFS
        RTE_LOG(ERR, EAL, "fw-log ring enqueue error.\n");
        rte_mempool_put(log_mempool, item);
        return -1;
    }

    return 0;
}

void *fw_log_work(void *data)
{
    time_t tm;
    struct tm mm;
    char time_fmt[64] = {0};
    int ret;

    ret = log_setup();
    if (ret < 0) {
        RTE_LOG(ERR, EAL, "fw-log setup error.\n");
        return NULL;
    }

    ret = log_init();
    if (ret < 0) {
        RTE_LOG(ERR, EAL, "fw-log log_init error.\n");
        return NULL;
    }

    openlog("fw", LOG_NDELAY|LOG_PID, LOG_LOCAL0);

#if 1
    #define FORMAT "%Y-%m-%d %H:%M:%S"
    tm = time(NULL);
    localtime_r(&tm , &mm);
    strftime(time_fmt, 64, FORMAT, &mm);

    syslog(LOG_INFO, "%s %s running.\n", time_fmt, __func__);
#endif

    while (1) {

        log_output();

        // 0.1s
        usleep(1000 * 100);
    }

    return NULL;
}
