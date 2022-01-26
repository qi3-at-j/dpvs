#ifndef __START_PROCESS_H__
#define __START_PROCESS_H__

typedef struct _fw_agent_cfg_ {
    char ip[INET6_ADDRSTRLEN];
    char port[16];
} fw_agent_cfg_s;

extern fw_agent_cfg_s fw_agent_cfg;

extern void init_task_pcb(void);
extern void start_process(void);
extern void start_process_cfg_irrelevant(void);
extern int terminate_tasks(void);
extern int set_task_exit(pid_t pid);
extern bool DPI_IsRun(void);

#endif
