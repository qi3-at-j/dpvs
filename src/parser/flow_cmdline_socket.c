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
#include <sys/un.h>
#include <fcntl.h>
#include <termios.h>

#include "scheduler.h"
#include "start_process.h"
#include "proto_relation.h"
#include "app_rbt.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline_rdline.h"
#include "parser/flow_cmdline_socket.h"
#include "parser/flow_cmdline.h"

struct cmdline *
tyflow_cmdline_file_new(const char *prompt, const char *path)
{
	int fd;

	/* everything else is checked in cmdline_new() */
	if (!path)
		return NULL;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		dprintf("open() failed\n");
		return NULL;
	}
    return tyflow_cmdline_new(prompt, fd, -1);
}

struct cmdline *
tyflow_cmdline_stdin_new(const char *prompt)
{
	struct cmdline *cl;
	struct termios oldterm, term;

	tcgetattr(0, &oldterm);
	memcpy(&term, &oldterm, sizeof(term));
	term.c_lflag &= ~(ICANON | ECHO | ISIG);
	tcsetattr(0, TCSANOW, &term);
	setbuf(stdin, NULL);

	cl = tyflow_cmdline_new(prompt, 0, 1);

	if (cl)
		memcpy(&cl->oldterm, &oldterm, sizeof(term));

	return cl;
}

void
tyflow_cmdline_stdin_exit(struct cmdline *cl)
{
	if (!cl)
		return;

	tcsetattr(fileno(stdin), TCSANOW, &cl->oldterm);
}

uint32_t cmdbatch_debug_flag;
static int
debug_cmdbatch_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, CMDBATCH, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch (cbt->which[0]) {
        case 1:
            if (cbt->mode & MODE_DO) {
                if (!(cmdbatch_debug_flag & CMDBATCH_DEBUG_BASIC)) {
                    printf("cmd-batch basic debug is enabled\n");
                    cmdbatch_debug_flag |= CMDBATCH_DEBUG_BASIC;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (cmdbatch_debug_flag & CMDBATCH_DEBUG_BASIC) {
                    printf("cmd-batch basic debug is disabled\n");
                    cmdbatch_debug_flag &= ~CMDBATCH_DEBUG_BASIC;
                }
            }
            break;
        case 2:
            if (cbt->mode & MODE_DO) {
                if ((cmdbatch_debug_flag & CMDBATCH_DEBUG_ALL) != CMDBATCH_DEBUG_ALL) {
                    printf("cmd-batch all debug is enabled\n");
                    cmdbatch_debug_flag |= CMDBATCH_DEBUG_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (cmdbatch_debug_flag & CMDBATCH_DEBUG_ALL) {
                    printf("cmd-batch all debug is disabled\n");
                    cmdbatch_debug_flag &= ~CMDBATCH_DEBUG_ALL;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

EOL_NODE(debug_cmdbatch_eol, debug_cmdbatch_cli);
KW_NODE_WHICH(cmdbatch_all, debug_cmdbatch_eol, none, "all", "enable/disable cmd-batch all debug", 1, 2);
KW_NODE_WHICH(cmdbatch_basic, debug_cmdbatch_eol, cmdbatch_all, "basic", "enable/disable cmd-batch basic debug", 1, 1);
KW_NODE(debug_cmdbatch, cmdbatch_basic, none, "cmd-batch", "enable/disable cmd-batch related debug");

#define TYFLOW_UD_CMD_BATCH "/var/run/tyflow_cmd_batch"
char tyflow_cmd_batch_ud[256];
static int srv_fd;


struct tyflow_cmd_batch_msg {
#define CMD_BATCH_MAGIC 0x434D4442
    uint32_t magic;
    char buf[RDLINE_BUF_SIZE];
};

static inline void 
tyflow_cmd_batch_job_func(void *dummy)
{
    int clt_fd;
    int ret;
    socklen_t clt_len;
    struct sockaddr_un clt_addr;
    struct tyflow_cmd_batch_msg msg;
    char cmd_dup[RDLINE_BUF_SIZE] = {0};

    memset(&clt_addr, 0, sizeof(struct sockaddr_un));
    clt_len = sizeof(clt_addr);

    /* Note: srv_fd is nonblock */
    clt_fd = accept(srv_fd, (struct sockaddr*)&clt_addr, &clt_len);
    if (clt_fd < 0) {
        if (EWOULDBLOCK != errno) {
#if 0
            RTE_LOG(WARNING, CMDBATCH, "%s: Fail to accept client request\n", __func__);
#endif
            cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC, "%s: Fail to accept client request\n", __func__);
        }
        goto cleanup;
    }

    ret = readn(clt_fd, &msg, sizeof(msg));
    if (ret <= sizeof(msg.magic)) {
#if 0
        RTE_LOG(WARNING, CMDBATCH, "%s: cmd batch recv fail -- %d/%d recieved\n",
                __func__, ret, len);
#endif
        cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC, 
                             "%s: cmd batch recv fail -- %d/%d recieved\n",
                             __func__, ret, sizeof(msg));
        goto cleanup;
    } else if (ntohl(msg.magic) != CMD_BATCH_MAGIC) {
#if 0
        RTE_LOG(WARNING, CMDBATCH, "%s: cmd batch recv corrupted msg -- %d/%d \n",
                __func__, ret, msg.magic);
#endif
        cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC, 
                             "%s: cmd batch recv corrupted msg -- %d/%x\n",
                             __func__, ret, msg.magic);
        goto cleanup;
    } 

    ret -= sizeof(msg.magic);
    memcpy(cmd_dup, msg.buf, ret);
    if (cmd_dup[ret-1] == '\n')
        cmd_dup[ret-1] = 0;
    cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC, 
                         "%s: cmd batch recv msg %d -- (%s)\n",
                         __func__, ret, cmd_dup);

    ret = tyflow_cmdline_parse(NULL, msg.buf, 0);
    if (ret) {
        int space, i;
        char *errstr = NULL;
        char message[RDLINE_BUF_SIZE] = {0};
        cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC, 
                             "%s: cmd batch failed to perform command:\n", __func__);
        cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC,
                             "%s", cmd_dup);
        if (ret < 0)
            errstr = "^ Incomplete command\n";
        else 
            errstr = "^ Command not found\n";
		space = abs(ret)-1;
		for (i=0; i<space; i++) {
            message[i] = ' ';
		}
		snprintf(&message[space], RDLINE_BUF_SIZE-space, "%s", errstr);
		cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC, "%s\n", message);
    }

cleanup:
    close(clt_fd);
}

/*
static struct dpvs_lcore_job tyflow_cmd_batch_job = {
    .name = "cmd_batch_job",
    .type = LCORE_JOB_LOOP,
    .func = tyflow_cmd_batch_job_func,
};
*/

static int
cmd_batch_sock_init(void)
{
    struct sockaddr_un srv_addr;
    int srv_fd_flags = 0;

    srv_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        RTE_LOG(ERR, CMDBATCH, "%s: Fail to create server socket\n", __func__);
        return -1;
    }

    srv_fd_flags = fcntl(srv_fd, F_GETFL, 0);
    srv_fd_flags |= O_NONBLOCK;
    if (-1 == fcntl(srv_fd, F_SETFL, srv_fd_flags)) {
        RTE_LOG(ERR, CMDBATCH, "%s: Fail to set server socket NONBLOCK\n", __func__);
        return -1;
    }

    memset(&srv_addr, 0, sizeof(struct sockaddr_un));
    srv_addr.sun_family = AF_UNIX;
    strncpy(srv_addr.sun_path, TYFLOW_UD_CMD_BATCH, sizeof(srv_addr.sun_path) - 1);
    unlink(TYFLOW_UD_CMD_BATCH);

    if (-1 == bind(srv_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr))) {
        RTE_LOG(ERR, CMDBATCH, "%s: Fail to bind server socket\n", __func__);
        close(srv_fd);
        unlink(TYFLOW_UD_CMD_BATCH);
        return -1;
    }

    if (-1 == listen(srv_fd, 1)) {
        RTE_LOG(ERR, CMDBATCH, "%s: Server socket listen failed\n", __func__);
        close(srv_fd);
        unlink(TYFLOW_UD_CMD_BATCH);
        return -1;
    }

    /*
    if ((dpvs_lcore_job_register(&tyflow_cmd_batch_job, LCORE_ROLE_MASTER)) != EDPVS_OK) {
        RTE_LOG(ERR, CMDBATCH, "%s: Fail to register cmd_batch_job into master\n", __func__);
        close(srv_fd);
        unlink(TYFLOW_UD_CMD_BATCH);
        return -1;
    }
    */

    return 0;
}

void
cmd_batch_init(void)
{
    //cmd_batch_sock_init();
    add_debug_cmd(&cnode(debug_cmdbatch));
}

void *fw_cfgd_work(void *data)
{
    cmd_batch_sock_init();

    App_Rbt_Process();

    proto_relation_process();

    //printf("l5:%d l7:%d\n", proto_relation_get(12981), 12981);
    //printf("l5:%d l7:%d\n", proto_relation_get(354), 354);
    //printf("l5:%d l7:%d\n", proto_relation_get(369), 369);
    //printf("l5:%d l7:%d\n", proto_relation_get(27), 27);

    /* init */
    //cmd_init();

    while (!dpvs_terminate) {
        tyflow_cmd_batch_job_func(NULL);
        sleep(1);
    }

    return NULL;
}

