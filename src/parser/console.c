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

#include "cmdline_parse.h"
#include "cmdline_rdline.h"
#include "cmdline_socket.h"
#include "cmdline.h"

static char *console_prompt = "tyflow > ";
static int
exit_func(cmd_blk_t *cbt)
{
    tyflow_cmdline_stdin_exit(cbt->cl);
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
	cl = tyflow_cmdline_stdin_new(console_prompt);
	if (cl == NULL)
		return NULL;
	tyflow_cmdline_interact(cl);
	tyflow_cmdline_stdin_exit(cl);
    return NULL;
}
