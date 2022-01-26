/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021-2022 CTyun Corporation.
 * Copyright (c) 2021, qicen <qic1@chinatelecom.cn>
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <termios.h>

#include "scheduler.h"
#include "ctrl.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline_rdline.h"
#include "parser/flow_cmdline_socket.h"
#include "parser/flow_cmdline.h"
#include "flow_fifo.h"

#define RTE_LOGTYPE_CONSOLE RTE_LOGTYPE_USER1

struct cmdline *console_cl;

extern void
tyflow_cmdline_vty_exit(void);
static int
exit_func(cmd_blk_t *cbt)
{
	struct cmdline *cl = cbt->cl;

    if (cl->vty) {
        tyflow_cmdline_printf(cl, EXIT_STR);
        tyflow_cmdline_printf(console_cl, "close by vty.\n");
    }
    tyflow_cmdline_stdin_exit(console_cl);
    tyflow_cmdline_vty_exit();
    exit(0);
}
EOL_NODE(exit_eol, exit_func);
KW_NODE(exit, exit_eol, none, "exit", "exit the system");

/* console entry function, called from main on MASTER lcore */
extern void *
console_entry(void *args);
void *
console_entry(void *args)
{
	struct cmdline *cl;
	cl = tyflow_cmdline_stdin_new(PROMPT);
	if (cl == NULL)
		return NULL;
    console_cl = cl;
	tyflow_cmdline_interact(cl);
	tyflow_cmdline_stdin_exit(cl);
    return NULL;
}

static int console_msg_seq(void)
{
    static uint32_t seq = 0;

    return seq++;
}

extern void *
console_entry(void *args);

static int do_console_job_by_main(struct dpvs_msg *msg){
	int err = 0;
	assert(msg);

	struct console_msg_data * data = (struct console_msg_data *)msg->data;

	err = data->func(&data->cbt);

	msg_destroy(&msg);
	return err;
}

static struct dpvs_msg_type console_msg = {
    .type           = MSG_TYPE_CONSOLE,
    .prio           = MSG_PRIO_LOW,
    .mode           = DPVS_MSG_UNICAST,
    .cid            = 0,//send to main
    .unicast_msg_cb = do_console_job_by_main,
};

void
make_console_msg(struct console_msg_data *data,cmd_blk_t *cbt, cmd_fn_t func)
{
	
	rte_memcpy(&data->cbt, cbt, sizeof(*cbt));
	data->func = func;
}


int tyflow_send_to_main_do_func(cmd_blk_t *cbt, cmd_fn_t func){
	int err = 0;
	int errcode = 0;
	struct dpvs_msg * msg = NULL;
	lcoreid_t cid = 0;
	struct console_msg_data data;

    memset(&data, 0, sizeof(data));
	make_console_msg(&data, cbt, func);
	msg = msg_make(MSG_TYPE_CONSOLE, console_msg_seq(), DPVS_MSG_UNICAST, cid, sizeof(data), &data);    
	if (unlikely(msg == NULL)) {
		RTE_LOG(ERR, CONSOLE, "%s: fail to make msg -- %s\n",
				__func__, dpvs_strerror(err));
		err = EDPVS_NOMEM;
		goto done;
	}

	err = msg_send(msg, 0, DPVS_MSG_F_ASYNC, NULL);
	if (err != EDPVS_OK) {
		RTE_LOG(ERR, CONSOLE, "%s: send msg: %s\n", __func__, dpvs_strerror(err));
		goto ret1;
	}
done:
	return err;
ret1:
	msg_destroy(&msg);
	goto done;
}

/* master handling thread */
static pthread_t ctflow_console_thread;
extern int ctflow_console_job_start(void);

int
ctflow_console_job_start(void)
{
	int ret;
	
	ret = msg_type_register(&console_msg);
	if (ret != EDPVS_OK) {
		RTE_LOG(ERR, DSCHED, "faile to register console msg\n");
		return -1;
	}

	ret = pthread_create(&ctflow_console_thread, NULL, console_entry, NULL);
	if (ret) {
		RTE_LOG(ERR, DSCHED, "faile to create console\n");
		return -1;
	}

	ret = rte_thread_setname(ctflow_console_thread, "ctflow-console");
	if (ret < 0)
		RTE_LOG(DEBUG, DSCHED, "Failed to set name for ctflow-console thread\n");

	return 0;
}


