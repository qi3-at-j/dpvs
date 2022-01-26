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
 */

#ifndef __TYFLOW_FLOW_MSG_H__
#define __TYFLOW_FLOW_MSG_H__

#include <sys/types.h>
#include <rte_mbuf.h>
#include "conf/common.h"
#include "conf/flow.h"
#include "netif.h"
#include "inet.h"
#include "flow.h"
/*
 * Generic show command message structure.
 */
typedef struct cmd_msg_hdr_ {
    volatile lcoreid_t cid;
    uint16_t type;
    uint16_t subtype;
    uint16_t length;
    uint32_t rc;
    void     *cbt; /* cmd_blk_t */
    uint8_t  data[0];
} cmd_msg_hdr_t;

typedef enum {
    /* do not use the first element */
    CMD_MSG_START = 0,
    CMD_MSG_FLOW_SHOW,
    CMD_MSG_FLOW_CLEAR,
    CMD_MSG_FLOW_PROF,
    CMD_MSG_SESS,    
    CMD_MSG_RELATION_CLEAR,
    CMD_MSG_MAX
} cmd_msg_tpye_t;

typedef int (*cmd_msg_handler_t)(cmd_msg_hdr_t *msg, void *cookie);

typedef struct {
    cmd_msg_handler_t handler;
    cmd_msg_handler_t echo_handler;
    void *cookie;
} cmd_msg_callback_t;

int
cmd_msg_handler_register (cmd_msg_tpye_t type, 
                          cmd_msg_handler_t handler, 
                          cmd_msg_handler_t echo_handler, 
                          void *cookie);
int
send_cmd_msg_to_fwd_lcore_id(cmd_msg_hdr_t *msg, lcoreid_t cid);
int
send_cmd_msg_to_fwd_lcore(cmd_msg_hdr_t *msg);
int
exec_cmd_on_fwd_lcore(void);

#endif /* __TYFLOW_FLOW_MSG_H__ */
