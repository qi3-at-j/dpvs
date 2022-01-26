#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/queue.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>

#include <rte_mempool.h>
#include <rte_malloc.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_log.h>

#include "parser/flow_cmdline_socket.h"
#include "scheduler.h"
#include "setproctitle.h"
#include "fw_log.h"
#include "fw_conf/ips_policy_conf.h"
#include "start_process.h"


#define FW_CFG_WORK_NAME    "fw-cfg-work"
#define FW_LOG_WORK_NAME    "fw-log-work"
#define FW_AGENT_WORK_NAME  "fw-agent"
#define FW_DPI_WORK_NAME    "suricata"

#define TASK_MAX_NUM 32
#define TASK_RUNNING 1
#define TASK_EXIT    0

typedef struct _process_cb {
    pid_t pid;
    char  name[16];
    uint32_t status;
} process_cb_t;

process_cb_t tasks[TASK_MAX_NUM];
int32_t task_index = 0;

pthread_t fw_cfg_id;
pthread_t fw_log_id;

static int set_task_info(pid_t pid, char *name)
{
    int index = -1;
    int i;

    for (i = 0; i < TASK_MAX_NUM; ++i) {
        if (tasks[i].status == TASK_EXIT) {
            index = i;
            break;
        }
    }

    if (index < 0 || index >= TASK_MAX_NUM) {
        return -1;
    }

    tasks[index].pid = pid;
    strcpy(tasks[i].name, name);
    tasks[i].status = TASK_RUNNING;

    if (index >= task_index) {
        task_index++;
    }

    return 0;
}

int set_task_exit(pid_t pid)
{
    int i;

    for (i = 0; i < task_index; ++i) {
        if (tasks[i].pid == pid) {
            tasks[i].status = TASK_EXIT;
            printf("%s exit!!!!!\n", tasks[i].name);
            break;
        }
    }

    return 0;
}

static int kill_process(char *name)
{
    char buf[64] = {0};
    char cmd[256] = {0};
    FILE *fd;
    pid_t pid, ppid;

    snprintf(cmd, sizeof(cmd), "ps -ef | grep %s | grep -v grep | awk '{print $2,$3}'", name);
    fd = popen(cmd, "r");
    if (!fd) {
        return -1;
    }

    while (fgets(buf, sizeof(buf), fd)) {
        sscanf(buf, "%d %d", &pid, &ppid);
        if (pid > 1) {
            kill(pid, SIGKILL);
        }
    }

    /*
    buf[0] = 0;
    fread(buf, 32, 1, fd);
    pid = atoi(buf);
    if (pid > 1) {
        kill(pid, SIGKILL);
    }
    */

    pclose(fd);

    return 0;
}

void init_task_pcb(void)
{
    int i;

    for (i = 0; i < TASK_MAX_NUM; ++i) {
        tasks[i].pid = -1;
        tasks[i].name[0] = '\0';
        tasks[i].status = TASK_EXIT;
    }

    //kill_process(FW_CFG_WORK_NAME);
    kill_process(FW_AGENT_WORK_NAME);
    kill_process(FW_DPI_WORK_NAME);

    sleep(1);

    return;
}


#define fork_and_run_process(fun, pid, wait, title)    {\
    if (wait) {\
        snprintf(name, sizeof(name), "%s-%d", title, rte_lcore_id());\
    } else {\
        snprintf(name, sizeof(name), "%s", title);\
    }\
    pid = fork();\
    if (pid < 0) {\
        printf("fork_and_run error.\n");\
    }\
    if (pid == 0) {\
        /* setproctitle */\
        setproctitle(name);\
        fun();\
    } else {\
        set_task_info(pid, name);\
        if (wait) {\
            int id = waitpid(pid, NULL, 0);\
            printf("exit id:%d\n", id);\
            set_task_exit(pid);\
        }\
    }\
}

static int agent_work(void)
{
    char *argv[5] = {"/usr/bin/python3", "./fw_agent/fw-agent.py", NULL};

    argv[0] = "/usr/bin/python3";
    argv[1] = "./fw_agent/fw-agent.py";
    printf("ip %s.\n", fw_agent_cfg.ip);
    printf("port %s.\n", fw_agent_cfg.port);
    argv[2] = fw_agent_cfg.ip;
    argv[3] = fw_agent_cfg.port;
    argv[4] = NULL;

    execve(argv[0], argv, NULL);

    printf("fw-agent lcore:%d run failed.\n", rte_lcore_id());

    /*
    while (!terminate) {
        sleep(1);
    }
    */
    exit(0);
}

static int ips_work(void)
{
    char *argv[] = {"/usr/bin/suricata", "dpdk", "-l", "0", "-n", "4", "--proc-type=secondary","--", "-r", NULL};
    //char *argv[] = {"/usr/bin/suricata", "-r", NULL};/*when #define MEMPOOL==0, uncomment this line and comment above line*/
    
    //printf("ips lcore:%d run.\n", rte_lcore_id());

    execve(argv[0], argv, NULL);

    printf("ips lcore:%d run failed.\n", rte_lcore_id());

    /*
    while (!terminate) {
        sleep(1);
    }
    */
    exit(0);
}

static void loop_tasks(void *arg)
{
    int i;
    pid_t pid;
    char name[16];

    for (i = 0; i < task_index; ++i) {
        if (tasks[i].status == TASK_EXIT && tasks[i].pid != -1) {
            /*
            if (0 == strcmp(tasks[i].name, FW_CFG_WORK_NAME)) {
                fork_and_run_process(fw_cfgd_work, pid, 0, FW_CFG_WORK_NAME);
            }
            */

            if (0 == strcmp(tasks[i].name, FW_AGENT_WORK_NAME)) {
                fork_and_run_process(agent_work, pid, 0, FW_AGENT_WORK_NAME);
            }
            
            if (0 == strcmp(tasks[i].name, FW_DPI_WORK_NAME)) {
              //  fork_and_run_process(ips_work, pid, 0, FW_DPI_WORK_NAME);
            }
        }
    }

    /*
    if (0) {
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            if (RUNNING != rte_eal_get_lcore_state(lcore_id)) {
                rte_eal_wait_lcore(lcore_id);
                //rte_eal_remote_launch(fork_run, NULL, lcore_id);
            }
        }
    }
    */

    return;
}

static struct dpvs_lcore_job loop_tasks_job = {
    .name = "loop_tasks",
    .type = LCORE_JOB_LOOP,
    .func = loop_tasks,
};


static int task_is_running(char *task_name)
{
    char buf[64];
    char cmd[256];
    FILE *fd;
    int running = 0;

    snprintf(cmd, 256, "ps -ef | grep %s | grep -v grep | awk '{print $2}'", task_name);
    fd = popen(cmd, "r");
    if (!fd) {
        return 0;
    }

    if (fgets(buf, 64, fd)) {
        running = 1;
    }

    pclose(fd);

    return running;
}

static int wait_for_running(char *task_name)
{
    struct stat st = {0};
    int loop = 5;

    do {
        if (task_is_running(task_name)) {
            break;
        }
        sleep(1);

    } while(--loop);

    if (0 == strcmp(task_name, FW_DPI_WORK_NAME)) {
        loop = 30;

        do {
            if (0 == stat(IPS_SOCKET_FILE, &st) && S_ISSOCK(st.st_mode)) {
                break;
            }

            sleep(1);
        } while(--loop);
    }

    if (loop) {
        return 0;
    } else {
        return -1;
    }
}

void start_process_cfg_irrelevant(void)
{
    pid_t pid = -1;
    char name[16];

    /* clean up environment */
    unlink(IPS_SOCKET_FILE);

    fork_and_run_process(ips_work, pid, 0, FW_DPI_WORK_NAME);

    if (0 != wait_for_running(FW_DPI_WORK_NAME)) {
        RTE_LOG(ERR, EAL, "%s %s start error.\n", __func__, FW_DPI_WORK_NAME);
    }

    return;
}

void start_process(void)
{
    pid_t pid = -1;
    char name[16];
    int ret;

    fork_and_run_process(agent_work, pid, 0, FW_AGENT_WORK_NAME);
    if (0 != wait_for_running(FW_AGENT_WORK_NAME)) {
        RTE_LOG(ERR, EAL, "%s %s start error.\n", __func__, FW_AGENT_WORK_NAME);
    }

    /* cfg work */
    ret = pthread_create(&fw_cfg_id, NULL, fw_cfgd_work, NULL);
    if (0 < ret) {
        RTE_LOG(ERR, EAL, "%s: Fail to start fw_cfgd_work.\n", __func__);
    }
	rte_thread_setname(fw_cfg_id, FW_CFG_WORK_NAME);

    /* log work */
    ret = pthread_create(&fw_log_id, NULL, fw_log_work, NULL);
    if (0 < ret) {
        RTE_LOG(ERR, EAL, "%s: Fail to start fw_log_work.\n", __func__);
    }
	rte_thread_setname(fw_log_id, FW_LOG_WORK_NAME);

    if ((dpvs_lcore_job_register(&loop_tasks_job, LCORE_ROLE_MASTER)) != EDPVS_OK) {
        RTE_LOG(ERR, EAL, "%s: Fail to register loop_tasks_job into master\n", __func__);
        return;
    }

    return;
}

int terminate_tasks(void)
{
    int i;
    uint32_t loop = 10;
    uint32_t found;

    while (loop) {
        found = 0;
        for (i = 0; i < task_index; ++i) {
            if (tasks[i].status == TASK_RUNNING && tasks[i].pid != -1) {
                ++found;
                kill(tasks[i].pid, SIGINT);
            }
        }

        if (!found) {
            break;
        }

        sleep(1);
        --loop;
    }

    return 0;
}

bool DPI_IsRun(void)
{
    bool bRun = false;
    int i;
    for (i = 0; i < task_index; ++i) {
        if (strcmp(tasks[i].name, FW_DPI_WORK_NAME)) {
            if (tasks[i].status == TASK_RUNNING)
            {
                bRun = true;
            }
            break;
        }
    }

    return bRun;
}


