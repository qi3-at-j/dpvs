/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#ifndef _CMDLINE_H_
#define _CMDLINE_H_

#include <termios.h>
#include "parser/flow_cmdline_rdline.h"
#include "parser/flow_cmdline_parse.h"

/**
 * @file
 *
 * Command line API
 */

#ifdef __cplusplus
extern "C" {
#endif

struct cmdline {
	int s_in;
	int s_out;
    int vty;
	struct rdline rdl;
	char prompt[RDLINE_PROMPT_SIZE];
	struct termios oldterm;
	cmdline_parse_ctx_t *ctx;
};

struct cmdline *tyflow_cmdline_new(const char *prompt, int s_in, int s_out);
void tyflow_cmdline_set_prompt(struct cmdline *cl, const char *prompt);
void
tyflow_cmdline_show_prompt(struct cmdline *cl);
void tyflow_cmdline_free(struct cmdline *cl);
void tyflow_cmdline_printf(const struct cmdline *cl, const char *fmt, ...)
	__attribute__((format(printf,2,3)));
int tyflow_cmdline_in(struct cmdline *cl, const char *buf, int size);
int tyflow_cmdline_write_char(struct rdline *rdl, char c);

/**
 * This function is nonblocking equivalent of ``cmdline_interact()``. It polls
 * *cl* for one character and interpret it. If return value is *RDLINE_EXITED*
 * it mean that ``cmdline_quit()`` was invoked.
 *
 * @param cl
 *   The command line object.
 *
 * @return
 *   On success return object status - one of *enum rdline_status*.
 *   On error return negative value.
 */
int tyflow_cmdline_poll(struct cmdline *cl);

void tyflow_cmdline_interact(struct cmdline *cl);
void tyflow_cmdline_quit(struct cmdline *cl);

#ifdef __cplusplus
}
#endif

#endif /* _CMDLINE_SOCKET_H_ */
