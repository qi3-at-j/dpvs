
#ifndef __NODE_FLOW_L3_CLI_PRIV_H__
#define __NODE_FLOW_L3_CLI_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "conf/common.h"

extern struct common_cmd_notice_entry cmd_notice_entry;
extern pthread_mutex_t mutex;

void resp_flow_l3_cmd_notice(struct rte_graph *graph,
    lcoreid_t cid);
void flow_l3_cli_init(void);
int api_flow_cmd_ring_init(void *arg);
int api_deq_l3_cmd_ring(void *arg);

#ifdef __cplusplus
}
#endif

#endif
