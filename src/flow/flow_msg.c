/*
 * Copyright (C) 2021 TYyun.
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

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <pthread.h>

#include "flow.h"
#include "debug_flow.h"
#include "flow_cli.h"
#include "flow_msg.h"

pthread_mutex_t cmd_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cmd_cond  = PTHREAD_COND_INITIALIZER;
pthread_mutex_t *flow_cmd_mutex = &cmd_mutex;
pthread_cond_t  *flow_cmd_cond  = &cmd_cond;

static cmd_msg_callback_t cmd_msg_callbacks[CMD_MSG_MAX];

/*
 * Register a message handler for a given type.
 */
int
cmd_msg_handler_register (cmd_msg_tpye_t type, 
                          cmd_msg_handler_t handler, 
                          cmd_msg_handler_t echo_handler, 
                          void *cookie)
{
    cmd_msg_callback_t *callback = cmd_msg_callbacks + type;
    if (type < CMD_MSG_START || type >= CMD_MSG_MAX) {
        return -1;
    }

    /* already exist */
    if (callback->handler != NULL) {
        return 1;
    }

    callback->handler      = handler;
    callback->echo_handler = echo_handler;
    callback->cookie       = cookie;
    return 0;
}

volatile static void *exec_cmd_ctx;
/* condition variable to execute the command in master lcore */
int
send_cmd_msg_to_master(cmd_msg_hdr_t *msg, lcoreid_t cid)
{
    cmd_msg_callback_t *callback = cmd_msg_callbacks + msg->type;
    if (!callback->handler) {
        flow_debug_trace(FLOW_DEBUG_CLI, "%s: no handler for type %d\n",
                         __FUNCTION__, msg->type);
        return -1;
    }

    msg->cid = cid;
    rte_mb();
    exec_cmd_ctx = msg;
    if (g_lcore_role[cid] == LCORE_ROLE_MASTER) {
        pthread_mutex_lock(flow_cmd_mutex);
        msg->done = CMD_MSG_STATE_START;
        while(msg->done != CMD_MSG_STATE_FIN) {
            pthread_cond_wait(flow_cmd_cond, flow_cmd_mutex);
        }
        pthread_mutex_unlock(flow_cmd_mutex);
    } else {
        flow_debug_trace(FLOW_DEBUG_CLI, "%s: the lcore %d role is incorrect %d\n",
                         __FUNCTION__, cid, g_lcore_role[cid]);
        exec_cmd_ctx = NULL;
        return 0;
    }
    if (callback->echo_handler) {
        (*callback->echo_handler)(msg, callback->cookie);
    }
    exec_cmd_ctx = NULL;
    return 0;
}
/* busy wait for the fwd lcore to execute the command */
int
send_cmd_msg_to_fwd_lcore_id(cmd_msg_hdr_t *msg, lcoreid_t cid)
{
    cmd_msg_callback_t *callback = cmd_msg_callbacks + msg->type;
    if (!callback->handler) {
        flow_debug_trace(FLOW_DEBUG_CLI, "%s: no handler for type %d\n",
                         __FUNCTION__, msg->type);
        return -1;
    }

    msg->cid = cid;
    rte_mb();
    exec_cmd_ctx = msg;
    if (g_lcore_role[cid] == LCORE_ROLE_FWD_WORKER) {
        while(!!msg->cid) {
            rte_pause();
        }
    } else {
        flow_debug_trace(FLOW_DEBUG_CLI, "%s: the lcore %d role is incorrect %d\n",
                         __FUNCTION__, cid, g_lcore_role[cid]);
        exec_cmd_ctx = NULL;
        return 0;
    }
    if (callback->echo_handler) {
        (*callback->echo_handler)(msg, callback->cookie);
    }
    exec_cmd_ctx = NULL;
    return 0;
}

int
send_cmd_msg_to_fwd_lcore(cmd_msg_hdr_t *msg)
{
    int i;
    cmd_msg_callback_t *callback = cmd_msg_callbacks + msg->type;
    if (!callback->handler) {
        flow_debug_trace(FLOW_DEBUG_CLI, "%s: no handler for type %d\n",
                         __FUNCTION__, msg->type);
        return -1;
    }

    RTE_LCORE_FOREACH_WORKER(i) {
        if (g_lcore_role[i] == LCORE_ROLE_FWD_WORKER) {
            msg->cid = i;
            msg->done = CMD_MSG_STATE_START;
            rte_mb();
            exec_cmd_ctx = msg;
            while(!!msg->cid) {
                rte_pause();
            }
            if (callback->echo_handler) {
                (*callback->echo_handler)(msg, callback->cookie);
            }
        }
    }
    exec_cmd_ctx = NULL;
    return 0;
}

/* synchronized to execute the cmd */
int
exec_cmd_on_fwd_lcore(void)
{
    cmd_msg_hdr_t *msg;
    cmd_msg_callback_t *callback;

    if (!exec_cmd_ctx) {
        return 0;
    }

    msg = (cmd_msg_hdr_t *)exec_cmd_ctx;
    if ((msg->cid || msg->done == CMD_MSG_STATE_START) && 
        msg->cbt && rte_lcore_id() == msg->cid) {
        msg->done = CMD_MSG_STATE_EXEC;
        callback = cmd_msg_callbacks + msg->type;
        msg->rc = 0;
        if (callback->handler) {
            (*callback->handler)(msg, callback->cookie);
        }
        /* notify main thread */
        msg->cid = 0;
    }
    return 0;
}

