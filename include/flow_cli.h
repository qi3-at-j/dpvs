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

#ifndef __TYFLOW_FLOW_CLI_H__
#define __TYFLOW_FLOW_CLI_H__

#include <sys/types.h>
#include <rte_mbuf.h>
#include "conf/common.h"
#include "conf/flow.h"
#include "netif.h"
#include "inet.h"
#include "flow.h"
#include "flow_msg.h"

/* serveral macro defined for operation */
enum {
    FLOW_CMD_MSG_SUBTYPE_SUMMARY = 1,
    FLOW_CMD_MSG_SUBTYPE_ALL,
    FLOW_CMD_MSG_SUBTYPE_DETAIL,
    FLOW_CMD_MSG_SUBTYPE_COUNTER,
    FLOW_CMD_MSG_SUBTYPE_HASHTOP,
    FLOW_CMD_MSG_SUBTYPE_HASH,
    FLOW_CMD_MSG_SUBTYPE_DENY,
    SESS_CMD_MSG_SUBTYPE_SHOW,
    SESS_CMD_MSG_SUBTYPE_CLEAR,
};

enum {
    FLOW_CMD_MSG_CLEAR_COUNTER = 1,
    FLOW_CMD_MSG_CLEAR_FCP,
};


#define number_2_mask(x) (((2<<(x))-1)<<(32-(x)))
/*** used for get or clear connections ***/
typedef struct connection_op_para_{
	/* serveral macro defined for mask */
#define CLR_GET_CONN_SRCIP          0x0001
#define CLR_GET_CONN_SRCIP_MASK     0x0002
#define CLR_GET_CONN_DESIP          0x0004
#define CLR_GET_CONN_DESIP_MASK     0x0008
#define CLR_GET_CONN_PROTOCOL_LOW   0x0010
#define CLR_GET_CONN_PROTOCOL_HIGH  0x0020
#define CLR_GET_CONN_SRCPORT_LOW    0x0040
#define CLR_GET_CONN_SRCPORT_HIGH   0x0080
#define CLR_GET_CONN_DESPORT_LOW    0x0100
#define CLR_GET_CONN_DESPORT_HIGH   0x0200
#define CLR_GET_CONN_VRF_ID         0x0400
#define CLR_GET_CONN_FCFLAG         0x0800
#define CLR_GET_CONN_FW_POLICY      0x1000
	uint16_t mask;		/* identify which fitler is set */

    uint32_t fcid;      /* flow connection id */
	/* if address netmask is provided the address is the */
	/* results applied by the netmask */
	uint32_t src_ip;	   /* source ip address */
	uint32_t src_ip3[3];   /* more values for ipv6 */
	uint32_t src_mask;	   /* source ip netmask */
	uint32_t dst_ip;	   /* destination ip address */
	uint32_t dst_ip3[3];   /* more values for ipv6 */
	uint32_t dst_mask;	   /* destination ip netmask */

	/* if port low boundary is set the high boundary must be set */
    uint16_t srcport_low;	 /* source port low boundary */
    uint16_t srcport_high; /* source port high boundary */
    uint16_t dstport_low;	 /* destination port low boundary */
	uint16_t dstport_high; /* destination port high boundary */

	/* if low boundary is set the high boundary must be set */
	uint8_t  protocol_low;	 /* protocol low boundary */
	uint8_t  protocol_high; /* protocol high boundary */
	/* vrf/vni id */
	uint32_t vrf_id;

	/* show flow connection with specific flag */
	uint32_t fcflag;
	/* show flow connection with specific fw_policy */
	uint32_t policy_id;
	/* show flow connection with specific hash */
	uint32_t hash;
} connection_op_para_t;

typedef struct {
    cmd_msg_hdr_t msg_hdr;
    connection_op_para_t paras;
} show_flow_ctx_t;

typedef struct {
    cmd_msg_hdr_t msg_hdr;
} clear_flow_ctx_t;

typedef int (* selected_connection_vector_t)(flow_connection_t *, void *);

int 
select_this_connection(flow_connection_t *fcp, 
			           connection_op_para_t *paras);
int
flow_cli_init(void);

#endif /* __TYFLOW_FLOW_CLI_H__ */
