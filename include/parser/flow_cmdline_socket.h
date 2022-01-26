/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#ifndef _CMDLINE_SOCKET_H_
#define _CMDLINE_SOCKET_H_

#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cmdline *tyflow_cmdline_file_new(const char *prompt, const char *path);
struct cmdline *tyflow_cmdline_stdin_new(const char *prompt);
void tyflow_cmdline_stdin_exit(struct cmdline *cl);

#define RTE_LOGTYPE_CMDBATCH RTE_LOGTYPE_USER1

extern uint32_t cmdbatch_debug_flag;
#define CMDBATCH_DEBUG_BASIC  0x0001
#define CMDBATCH_DEBUG_ALL (CMDBATCH_DEBUG_BASIC)

#define cmdbatch_debug_trace(flag, fmt, arg...) \
    do {                                    \
        if (cmdbatch_debug_flag & flag)     \
            debug_trace(fmt, ##arg);        \
    }while(0)

extern void
cmd_batch_init(void);
extern void * fw_cfgd_work(void*);

#ifdef __cplusplus
}
#endif

#endif /* _CMDLINE_SOCKET_H_ */
