/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021-2022 TYyun Corporation.
 * Copyright (c) 2021, qicen <qic1@chinatelecom.cn>
 * All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <strings.h>

#include "scheduler.h"
#include "ctrl.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline_rdline.h"
#include "parser/flow_cmdline_socket.h"
#include "parser/flow_cmdline.h"
#include "flow_fifo.h"

struct cmdline *vty_cl;

static struct cmdline *
tyflow_cmdline_vty_new(int in, int out)
{
    if (vty_cl) {
        tyflow_cmdline_free(vty_cl);
    }
    vty_cl = tyflow_cmdline_new(PROMPT, in, out);
    if (vty_cl == NULL) {
        RTE_LOG(ERR, DSCHED, "%s: faile to create cmdline\n", __FUNCTION__);
        return NULL;
    }
    vty_cl->vty = 1;
    return vty_cl;
}

static void
tyflow_cmdline_vty_update(int in, int out)
{
    vty_cl->s_in = in;
    vty_cl->s_out = out;
}

extern void
tyflow_cmdline_vty_exit(void);
void
tyflow_cmdline_vty_exit(void)
{
    if (vty_cl->s_in != -1) {
        close(vty_cl->s_in);
    }
    if (vty_cl->s_out != -1) {
        close(vty_cl->s_out);
    }
}

static int
flow_vty_fifo_init(void)
{
    struct stat statbuf;

    /* do the named pipe(fifo) exist? */
    if (access(C2SFIFO_E, F_OK) == -1) {
        /* create the named pipe(fifo) */
        if (mkfifo(C2SFIFO_E, 0666) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to create %s\n", __FUNCTION__, C2SFIFO_E);
            return -1;
        }
    } else {
        /* retrieve the file infomation */
        if (lstat(C2SFIFO_E, &statbuf) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to retrieve %s\n", __FUNCTION__, C2SFIFO_E);
            return -1;
        }
        /* is the file fifo? */
        if (!S_ISFIFO(statbuf.st_mode)) {

            /* delete the file if not fifo */
            unlink(C2SFIFO_E);

            /* create the fifo */
            if (mkfifo(C2SFIFO_E, 0666) == -1) {
                RTE_LOG(ERR, DSCHED, "%s: faile to create2 %s\n", __FUNCTION__, C2SFIFO_E);
                return -1;
            }           
        }
    }
    /* do the named pipe(fifo) exist? */
    if (access(S2CFIFO_E, F_OK) == -1) {
        /* create the named pipe(fifo) */
        if (mkfifo(S2CFIFO_E, 0666) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to create %s\n", __FUNCTION__, S2CFIFO_E);
            return -1;
        }
    } else {

        /* retrieve the file infomation */
        if (lstat(S2CFIFO_E, &statbuf) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to retrieve %s\n", __FUNCTION__, S2CFIFO_E);
            return -1;
        }
        /* is the file fifo? */
        if (!S_ISFIFO(statbuf.st_mode)) {

            /* delete the file if not fifo */
            unlink(S2CFIFO_E);

            /* create the fifo */
            if (mkfifo(S2CFIFO_E, 0666) == -1) {
                RTE_LOG(ERR, DSCHED, "%s: faile to create2 %s\n", __FUNCTION__, S2CFIFO_E);
                return -1;
            }           
        }
    }

    /* do the named pipe(fifo) exist? */
    if (access(C2SFIFO_O, F_OK) == -1) {
        /* create the named pipe(fifo) */
        if (mkfifo(C2SFIFO_O, 0666) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to create %s\n", __FUNCTION__, C2SFIFO_O);
            return -1;
        }
    } else {
        /* retrieve the file infomation */
        if (lstat(C2SFIFO_O, &statbuf) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to retrieve %s\n", __FUNCTION__, C2SFIFO_O);
            return -1;
        }
        /* is the file fifo? */
        if (!S_ISFIFO(statbuf.st_mode)) {

            /* delete the file if not fifo */
            unlink(C2SFIFO_O);

            /* create the fifo */
            if (mkfifo(C2SFIFO_O, 0666) == -1) {
                RTE_LOG(ERR, DSCHED, "%s: faile to create2 %s\n", __FUNCTION__, C2SFIFO_O);
                return -1;
            }           
        }
    }
    /* do the named pipe(fifo) exist? */
    if (access(S2CFIFO_O, F_OK) == -1) {
        /* create the named pipe(fifo) */
        if (mkfifo(S2CFIFO_O, 0666) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to create %s\n", __FUNCTION__, S2CFIFO_O);
            return -1;
        }
    } else {

        /* retrieve the file infomation */
        if (lstat(S2CFIFO_O, &statbuf) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to retrieve %s\n", __FUNCTION__, S2CFIFO_O);
            return -1;
        }
        /* is the file fifo? */
        if (!S_ISFIFO(statbuf.st_mode)) {

            /* delete the file if not fifo */
            unlink(S2CFIFO_O);

            /* create the fifo */
            if (mkfifo(S2CFIFO_O, 0666) == -1) {
                RTE_LOG(ERR, DSCHED, "%s: faile to create2 %s\n", __FUNCTION__, S2CFIFO_O);
                return -1;
            }           
        }
    }
    return 0;
}

static int vty_seq;
static void *
flow_vty_entry(void *arg) 
{
    int fd, fd2;
    char *c2sfifo, *s2cfifo;

    if (flow_vty_fifo_init() < 0) {
        return NULL;
    }

new_login:
    vty_seq = 0;
    if (!tyflow_cmdline_vty_new(-1, -1)) {
        RTE_LOG(ERR, DSCHED, "%s: faile to create vty cmdline \n", __FUNCTION__);
        return NULL;
    }
    while(1){
        flow_vty_pick_fifo(vty_seq, c2sfifo, s2cfifo);

        if ((fd=open(c2sfifo, O_RDONLY)) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to open %s\n", __FUNCTION__, c2sfifo);
            return NULL;
        }
        if ((fd2=open(s2cfifo, O_WRONLY)) == -1) {
            RTE_LOG(ERR, DSCHED, "%s: faile to open %s\n", __FUNCTION__, s2cfifo);
            return NULL;
        }
        tyflow_cmdline_vty_update(fd, fd2);
        tyflow_cmdline_show_prompt(vty_cl);
        /* we should retain the content unless the '\t' and '?'
         * would not have the previous inputs *
        tyflow_rdline_newline(&vty_cl->rdl, vty_cl->prompt);
        */
        tyflow_cmdline_interact(vty_cl);

        /* vty synchronized mode will close s_out due to issue anything */
        if (vty_cl->s_out == -1 && vty_cl->s_in != -1) {
            close(vty_cl->s_in);
            vty_cl->s_in = -1;
            continue;
        }
        /* another vty come it */
        if (vty_cl->s_in != -1 && vty_cl->s_out != -1) {
            close(vty_cl->s_in);
            close(vty_cl->s_out);
            vty_cl->s_in = -1;
            vty_cl->s_out = -1;
            goto new_login;
        }
    }
    if (vty_cl->s_in != -1) {
        close(vty_cl->s_in);
    }
    if (vty_cl->s_out != -1) {
        close(vty_cl->s_out);
    }
    return NULL;
}

/* master handling thread */
static pthread_t tyflow_vty_thread;
int
tyflow_vty_job_start(void)
{
	int ret;
	
	ret = pthread_create(&tyflow_vty_thread, NULL, flow_vty_entry, NULL);
	if (ret) {
		RTE_LOG(ERR, DSCHED, "faile to create vty\n");
		return -1;
	}

	ret = rte_thread_setname(tyflow_vty_thread, "tyflow-vty");
	if (ret < 0)
		RTE_LOG(DEBUG, DSCHED, "Failed to set name for tyflow-vty thread\n");

	return 0;
}


