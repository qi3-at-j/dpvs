/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <termios.h>
#include <netinet/in.h>

#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline_rdline.h"
#include "parser/flow_cmdline.h"

static void
cmdline_valid_buffer(struct rdline *rdl, const char *buf,
		     __attribute__((unused)) unsigned int size)
{
	struct cmdline *cl = rdl->opaque;
	int ret, space, i;
    char *errstr = NULL;
	char message[RDLINE_BUF_SIZE] = {0};
	ret = tyflow_cmdline_parse(cl, buf, 1);
	if (ret) {
        if (ret < 0)
            errstr = "^ Incomplete command\n";
        else 
            errstr = "^ Command not found\n";
		space = abs(ret)-1+rdl->prompt_size;
		for (i=0; i<space; i++) {
            message[i] = ' ';
		}
		snprintf(&message[space], RDLINE_BUF_SIZE-space, "%s", errstr);
		tyflow_cmdline_printf(cl, "%s", message);
#ifdef VTY_SYN
        if (cl->vty) {
            close(cl->s_out);
            cl->s_out = -1;
        }
#endif
	}

#if 0
	if (ret == CMDLINE_PARSE_AMBIGUOUS)
		cmdline_printf(cl, "Ambiguous command\n");
	else if (ret == CMDLINE_PARSE_NOMATCH)
		cmdline_printf(cl, "Command not found\n");
	else if (ret == CMDLINE_PARSE_BAD_ARGS)
		cmdline_printf(cl, "Bad arguments\n");
#endif
}

/*
 * the semantics of "action" may be changed.
 * it means '?' or '\t' corresponding to CA_NOTIFY and CA_APPEND in the entry;
 * meanwhile in the exit, it means the action really happened.
 */
static int
cmdline_complete_buffer(struct rdline *rdl, const char *buf,
			char *dstbuf, unsigned int dstsize,
			int *action)
{
	struct cmdline *cl = rdl->opaque;
	char message[RDLINE_BUF_SIZE] = {0};
	int ret, space, i;
	ret = tyflow_cmdline_complete(cl, buf, action, dstbuf, dstsize);
    if (ret > 0) {
        space = ret-1+rdl->prompt_size;
		for (i=0; i<(space); i++) {
            message[i] = ' ';
		}
		snprintf(&message[space], RDLINE_BUF_SIZE-space, "%s", "^ Command not found\n");
        tyflow_cmdline_printf(cl, "\r\n");
		tyflow_cmdline_printf(cl, "%s", message);
        return -1;
    }
    return 0;
}

int
tyflow_cmdline_write_char(struct rdline *rdl, char c)
{
	int ret = -1;
	struct cmdline *cl;

	if (!rdl)
		return -1;

	cl = rdl->opaque;

	if (cl->s_out >= 0)
		ret = write(cl->s_out, &c, 1);

	return ret;
}


void
tyflow_cmdline_set_prompt(struct cmdline *cl, const char *prompt)
{
	if (!cl || !prompt)
		return;
	snprintf(cl->prompt, sizeof(cl->prompt), "%s", prompt);
}

void
tyflow_cmdline_show_prompt(struct cmdline *cl)
{
	if (!cl)
		return;
    tyflow_cmdline_printf(cl, "%s", cl->prompt);
}

struct cmdline *
tyflow_cmdline_new(const char *prompt, int s_in, int s_out)
{
	struct cmdline *cl;
	int ret;

	if (!prompt)
		return NULL;

	cl = malloc(sizeof(struct cmdline));
	if (cl == NULL)
		return NULL;
	memset(cl, 0, sizeof(struct cmdline));
	cl->s_in = s_in;
	cl->s_out = s_out;

	ret = tyflow_rdline_init(&cl->rdl, tyflow_cmdline_write_char, cmdline_valid_buffer,
			cmdline_complete_buffer);
	if (ret != 0) {
		free(cl);
		return NULL;
	}

	cl->rdl.opaque = cl;
	tyflow_cmdline_set_prompt(cl, prompt);
	tyflow_rdline_newline(&cl->rdl, cl->prompt);

	return cl;
}

void
tyflow_cmdline_free(struct cmdline *cl)
{
	dprintf("called\n");

	if (!cl)
		return;

	if (cl->s_in > 2)
		close(cl->s_in);
	if (cl->s_out != cl->s_in && cl->s_out > 2)
		close(cl->s_out);
	free(cl);
}

void
tyflow_cmdline_printf(const struct cmdline *cl, const char *fmt, ...)
{
	va_list ap;

	if (!cl || !fmt)
		return;

	if (cl->s_out < 0)
		return;
	va_start(ap, fmt);
	vdprintf(cl->s_out, fmt, ap);
	va_end(ap);
}

int
tyflow_cmdline_in(struct cmdline *cl, const char *buf, int size)
{
	const char *history, *buffer;
	size_t histlen, buflen;
	int ret = 0;
	int i, same;

	if (!cl || !buf)
		return -1;

	for (i=0; i<size; i++) {
		ret = tyflow_rdline_char_in(&cl->rdl, buf[i]);

		if (ret == RDLINE_RES_VALIDATED) {
			buffer = tyflow_rdline_get_buffer(&cl->rdl);
			history = tyflow_rdline_get_history_item(&cl->rdl, 0);
			if (history) {
				histlen = strnlen(history, RDLINE_BUF_SIZE);
				same = !memcmp(buffer, history, histlen) &&
					buffer[histlen] == '\n';
			}
			else
				same = 0;
			buflen = strnlen(buffer, RDLINE_BUF_SIZE);
			if (buflen > 1 && !same)
				tyflow_rdline_add_history(&cl->rdl, buffer);
			tyflow_rdline_newline(&cl->rdl, cl->prompt);
		}
		else if (ret == RDLINE_RES_EOF)
			return -1;
		else if (ret == RDLINE_RES_EXITED)
			return -1;
	}
	return i;
}

void
tyflow_cmdline_quit(struct cmdline *cl)
{
	if (!cl)
		return;
	tyflow_rdline_quit(&cl->rdl);
}

int
tyflow_cmdline_poll(struct cmdline *cl)
{
	struct pollfd pfd;
	int status;
	ssize_t read_status;
	char c;

	if (!cl)
		return -EINVAL;
	else if (cl->rdl.status == RDLINE_EXITED)
		return RDLINE_EXITED;

	pfd.fd = cl->s_in;
	pfd.events = POLLIN;
	pfd.revents = 0;

	status = poll(&pfd, 1, 0);
	if (status < 0)
		return status;
	else if (status > 0) {
		c = -1;
		read_status = read(cl->s_in, &c, 1);
		if (read_status < 0)
			return read_status;

		status = tyflow_cmdline_in(cl, &c, 1);
		if (status < 0 && cl->rdl.status != RDLINE_EXITED)
			return status;
	}

	return cl->rdl.status;
}

void
tyflow_cmdline_interact(struct cmdline *cl)
{
	char c;

	if (!cl)
		return;

	c = -1;
	while (1) {
		if (read(cl->s_in, &c, 1) <= 0)
			break;
		if (tyflow_cmdline_in(cl, &c, 1) < 0)
			break;
	}
}