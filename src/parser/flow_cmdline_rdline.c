/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include "parser/flow_cmdline_cirbuf.h"
#include "parser/flow_cmdline_rdline.h"
#include "parser/flow_cmdline_vt100.h"
#include "parser/flow_cmdline.h"

static void rdline_puts(struct rdline *rdl, const char *buf);
static void rdline_miniprintf(struct rdline *rdl,
			      const char *buf, unsigned int val);

static void rdline_remove_old_history_item(struct rdline *rdl);
static void rdline_remove_first_history_item(struct rdline *rdl);
static unsigned int rdline_get_history_size(struct rdline *rdl);


/* isblank() needs _XOPEN_SOURCE >= 600 || _ISOC99_SOURCE, so use our
 * own. */
#if 0 /* use the definition in flow_cmdline_parse.h*/
static int
isblank2(char c)
{
	if (c == ' ' ||
	    c == '\t' )
		return 1;
	return 0;
}
#endif

int
tyflow_rdline_init(struct rdline *rdl,
		 rdline_write_char_t *write_char,
		 rdline_validate_t *validate,
		 rdline_complete_t *complete)
{
	if (!rdl || !write_char || !validate || !complete)
		return -EINVAL;
	memset(rdl, 0, sizeof(*rdl));
	rdl->validate = validate;
	rdl->complete = complete;
	rdl->write_char = write_char;
	rdl->status = RDLINE_INIT;
	return tyflow_cirbuf_init(&rdl->history, rdl->history_buf, 0, RDLINE_HISTORY_BUF_SIZE);
}

void
tyflow_rdline_newline(struct rdline *rdl, const char *prompt)
{
	unsigned int i;

	if (!rdl || !prompt)
		return;

	tyflow_vt100_init(&rdl->vt100);
	tyflow_cirbuf_init(&rdl->left, rdl->left_buf, 0, RDLINE_BUF_SIZE);
	tyflow_cirbuf_init(&rdl->right, rdl->right_buf, 0, RDLINE_BUF_SIZE);

	rdl->prompt_size = strnlen(prompt, RDLINE_PROMPT_SIZE-1);
	if (prompt != rdl->prompt)
		memcpy(rdl->prompt, prompt, rdl->prompt_size);
	rdl->prompt[RDLINE_PROMPT_SIZE-1] = '\0';

	for (i=0 ; i<rdl->prompt_size ; i++)
		rdl->write_char(rdl, rdl->prompt[i]);
	rdl->status = RDLINE_RUNNING;

	rdl->history_cur_line = -1;
}

void
tyflow_rdline_stop(struct rdline *rdl)
{
	if (!rdl)
		return;
	rdl->status = RDLINE_INIT;
}

void
tyflow_rdline_quit(struct rdline *rdl)
{
	if (!rdl)
		return;
	rdl->status = RDLINE_EXITED;
}

void
tyflow_rdline_restart(struct rdline *rdl)
{
	if (!rdl)
		return;
	rdl->status = RDLINE_RUNNING;
}

void
tyflow_rdline_reset(struct rdline *rdl)
{
	if (!rdl)
		return;
	tyflow_vt100_init(&rdl->vt100);
	tyflow_cirbuf_init(&rdl->left, rdl->left_buf, 0, RDLINE_BUF_SIZE);
	tyflow_cirbuf_init(&rdl->right, rdl->right_buf, 0, RDLINE_BUF_SIZE);

	rdl->status = RDLINE_RUNNING;

	rdl->history_cur_line = -1;
}

const char *
tyflow_rdline_get_buffer(struct rdline *rdl)
{
	if (!rdl)
		return NULL;
	unsigned int len_l, len_r;
	tyflow_cirbuf_align_left(&rdl->left);
	tyflow_cirbuf_align_left(&rdl->right);

	len_l = CIRBUF_GET_LEN(&rdl->left);
	len_r = CIRBUF_GET_LEN(&rdl->right);
	memcpy(rdl->left_buf+len_l, rdl->right_buf, len_r);

	rdl->left_buf[len_l + len_r] = '\n';
	rdl->left_buf[len_l + len_r + 1] = '\0';
	return rdl->left_buf;
}

static void
display_right_buffer(struct rdline *rdl, int force)
{
	unsigned int i;
	char tmp;

	if (!force && CIRBUF_IS_EMPTY(&rdl->right))
		return;

	rdline_puts(rdl, vt100_clear_right);
	CIRBUF_FOREACH(&rdl->right, i, tmp) {
		rdl->write_char(rdl, tmp);
	}
	if (!CIRBUF_IS_EMPTY(&rdl->right))
		rdline_miniprintf(rdl, vt100_multi_left,
				  CIRBUF_GET_LEN(&rdl->right));
}

void
tyflow_rdline_redisplay(struct rdline *rdl)
{
	unsigned int i;
	char tmp;

	if (!rdl)
		return;

	rdline_puts(rdl, vt100_home);
	for (i=0 ; i<rdl->prompt_size ; i++)
		rdl->write_char(rdl, rdl->prompt[i]);
	CIRBUF_FOREACH(&rdl->left, i, tmp) {
		rdl->write_char(rdl, tmp);
	}
	display_right_buffer(rdl, 1);
}

int
tyflow_rdline_char_in(struct rdline *rdl, char c)
{
	unsigned int i;
	int cmd;
	char tmp;
	char *buf;
    int action;
    struct cmdline *cl = rdl->opaque;

	if (!rdl)
		return -EINVAL;

	if (rdl->status == RDLINE_EXITED)
		return RDLINE_RES_EXITED;
	if (rdl->status != RDLINE_RUNNING)
		return RDLINE_RES_NOT_RUNNING;

	cmd = tyflow_vt100_parser(&rdl->vt100, c);
	if (cmd == -2)
		return RDLINE_RES_SUCCESS;

	if (cmd >= 0) {
		switch (cmd) {
		/* move caret 1 char to the left */
		case CMDLINE_KEY_CTRL_B:
		case CMDLINE_KEY_LEFT_ARR:
			if (CIRBUF_IS_EMPTY(&rdl->left))
				break;
			tmp = tyflow_cirbuf_get_tail(&rdl->left);
			tyflow_cirbuf_del_tail(&rdl->left);
			tyflow_cirbuf_add_head(&rdl->right, tmp);
			rdline_puts(rdl, vt100_left_arr);
			break;

		/* move caret 1 char to the right */
		case CMDLINE_KEY_CTRL_F:
		case CMDLINE_KEY_RIGHT_ARR:
			if (CIRBUF_IS_EMPTY(&rdl->right))
				break;
			tmp = tyflow_cirbuf_get_head(&rdl->right);
			tyflow_cirbuf_del_head(&rdl->right);
			tyflow_cirbuf_add_tail(&rdl->left, tmp);
			rdline_puts(rdl, vt100_right_arr);
			break;

		/* move caret 1 word to the left */
		/* keyboard equivalent: Alt+B */
		case CMDLINE_KEY_WLEFT:
			while (! CIRBUF_IS_EMPTY(&rdl->left) &&
			       (tmp = tyflow_cirbuf_get_tail(&rdl->left)) &&
			       isblank2(tmp)) {
				rdline_puts(rdl, vt100_left_arr);
				tyflow_cirbuf_del_tail(&rdl->left);
				tyflow_cirbuf_add_head(&rdl->right, tmp);
			}
			while (! CIRBUF_IS_EMPTY(&rdl->left) &&
			       (tmp = tyflow_cirbuf_get_tail(&rdl->left)) &&
			       !isblank2(tmp)) {
				rdline_puts(rdl, vt100_left_arr);
				tyflow_cirbuf_del_tail(&rdl->left);
				tyflow_cirbuf_add_head(&rdl->right, tmp);
			}
			break;

		/* move caret 1 word to the right */
		/* keyboard equivalent: Alt+F */
		case CMDLINE_KEY_WRIGHT:
			while (! CIRBUF_IS_EMPTY(&rdl->right) &&
			       (tmp = tyflow_cirbuf_get_head(&rdl->right)) &&
			       isblank2(tmp)) {
				rdline_puts(rdl, vt100_right_arr);
				tyflow_cirbuf_del_head(&rdl->right);
				tyflow_cirbuf_add_tail(&rdl->left, tmp);
			}
			while (! CIRBUF_IS_EMPTY(&rdl->right) &&
			       (tmp = tyflow_cirbuf_get_head(&rdl->right)) &&
			       !isblank2(tmp)) {
				rdline_puts(rdl, vt100_right_arr);
				tyflow_cirbuf_del_head(&rdl->right);
				tyflow_cirbuf_add_tail(&rdl->left, tmp);
			}
			break;

		/* move caret to the left */
		case CMDLINE_KEY_CTRL_A:
			if (CIRBUF_IS_EMPTY(&rdl->left))
				break;
			rdline_miniprintf(rdl, vt100_multi_left,
						CIRBUF_GET_LEN(&rdl->left));
			while (! CIRBUF_IS_EMPTY(&rdl->left)) {
				tmp = tyflow_cirbuf_get_tail(&rdl->left);
				tyflow_cirbuf_del_tail(&rdl->left);
				tyflow_cirbuf_add_head(&rdl->right, tmp);
			}
			break;

		/* move caret to the right */
		case CMDLINE_KEY_CTRL_E:
			if (CIRBUF_IS_EMPTY(&rdl->right))
				break;
			rdline_miniprintf(rdl, vt100_multi_right,
						CIRBUF_GET_LEN(&rdl->right));
			while (! CIRBUF_IS_EMPTY(&rdl->right)) {
				tmp = tyflow_cirbuf_get_head(&rdl->right);
				tyflow_cirbuf_del_head(&rdl->right);
				tyflow_cirbuf_add_tail(&rdl->left, tmp);
			}
			break;

		/* delete 1 char from the left */
		case CMDLINE_KEY_BKSPACE:
		case CMDLINE_KEY_BKSPACE2:
			if(!tyflow_cirbuf_del_tail_safe(&rdl->left)) {
				rdline_puts(rdl, vt100_bs);
				display_right_buffer(rdl, 1);
#ifdef VTY_SYN
                if (cl->vty) {
                    close(cl->s_out);
                    cl->s_out = -1;
                }
#endif
			}
			break;

		/* delete 1 char from the right */
		case CMDLINE_KEY_SUPPR:
		case CMDLINE_KEY_CTRL_D:
			if (cmd == CMDLINE_KEY_CTRL_D &&
			    CIRBUF_IS_EMPTY(&rdl->left) &&
			    CIRBUF_IS_EMPTY(&rdl->right)) {
				return RDLINE_RES_EOF;
			}
			if (!tyflow_cirbuf_del_head_safe(&rdl->right)) {
				display_right_buffer(rdl, 1);
			}
			break;

		/* delete 1 word from the left */
		case CMDLINE_KEY_META_BKSPACE:
		case CMDLINE_KEY_CTRL_W:
			while (! CIRBUF_IS_EMPTY(&rdl->left) && isblank2(tyflow_cirbuf_get_tail(&rdl->left))) {
				rdline_puts(rdl, vt100_bs);
				tyflow_cirbuf_del_tail(&rdl->left);
			}
			while (! CIRBUF_IS_EMPTY(&rdl->left) && !isblank2(tyflow_cirbuf_get_tail(&rdl->left))) {
				rdline_puts(rdl, vt100_bs);
				tyflow_cirbuf_del_tail(&rdl->left);
			}
			display_right_buffer(rdl, 1);
			break;

		/* delete 1 word from the right */
		case CMDLINE_KEY_META_D:
			while (! CIRBUF_IS_EMPTY(&rdl->right) && isblank2(tyflow_cirbuf_get_head(&rdl->right)))
				tyflow_cirbuf_del_head(&rdl->right);
			while (! CIRBUF_IS_EMPTY(&rdl->right) && !isblank2(tyflow_cirbuf_get_head(&rdl->right)))
				tyflow_cirbuf_del_head(&rdl->right);
			display_right_buffer(rdl, 1);
			break;

		/* set kill buffer to contents on the right side of caret */
		case CMDLINE_KEY_CTRL_K:
			tyflow_cirbuf_get_buf_head(&rdl->right, rdl->kill_buf, RDLINE_BUF_SIZE);
			rdl->kill_size = CIRBUF_GET_LEN(&rdl->right);
			tyflow_cirbuf_del_buf_head(&rdl->right, rdl->kill_size);
			rdline_puts(rdl, vt100_clear_right);
			break;

		/* paste contents of kill buffer to the left side of caret */
		case CMDLINE_KEY_CTRL_Y:
			i=0;
			while(CIRBUF_GET_LEN(&rdl->right) + CIRBUF_GET_LEN(&rdl->left) <
			      RDLINE_BUF_SIZE &&
			      i < rdl->kill_size) {
				tyflow_cirbuf_add_tail(&rdl->left, rdl->kill_buf[i]);
				rdl->write_char(rdl, rdl->kill_buf[i]);
				i++;
			}
			display_right_buffer(rdl, 0);
			break;

		/* clear and newline */
		case CMDLINE_KEY_CTRL_C:
			rdline_puts(rdl, "\r\n");
			tyflow_rdline_newline(rdl, rdl->prompt);
			break;

		/* redisplay (helps when prompt is lost in other output) */
		case CMDLINE_KEY_CTRL_L:
			tyflow_rdline_redisplay(rdl);
			break;

		/* autocomplete */
		case CMDLINE_KEY_TAB:
		case CMDLINE_KEY_HELP:
            if (cmd == CMDLINE_KEY_TAB) {
                action = CA_APPEND;
            } else {
                action = CA_NOTIFY;
                rdl->write_char(rdl, '?');
            }

			tyflow_cirbuf_align_left(&rdl->left);
			rdl->left_buf[CIRBUF_GET_LEN(&rdl->left)] = '\0';
			if (rdl->complete) {
				char tmp_buf[BUFSIZ] = {0};
				char *tmp_buf_notify = tmp_buf;
				int ret, tmp_size;
                ret = rdl->complete(rdl, rdl->left_buf,
                                    tmp_buf, sizeof(tmp_buf),
                                    &action);
                if (ret < 0) {
                    tyflow_rdline_redisplay(rdl);
#ifdef VTY_SYN
                    if (cl->vty) {
                        close(cl->s_out);
                        cl->s_out = -1;
                    }
#endif
                    return RDLINE_RES_COMPLETE;
                }
                tmp_size = strnlen(tmp_buf, sizeof(tmp_buf));
                /* add chars */
                if (action & CA_APPEND) {
                    i=0;
                    while(CIRBUF_GET_LEN(&rdl->right) + CIRBUF_GET_LEN(&rdl->left) <
                          RDLINE_BUF_SIZE &&
                          i < tmp_size) {
                        tyflow_cirbuf_add_tail(&rdl->left, tmp_buf[i]);
                        rdl->write_char(rdl, tmp_buf[i]);
                        i++;
                    }
                    display_right_buffer(rdl, 1);
                    tmp_buf_notify = tmp_buf + tmp_size + 1;
#ifdef VTY_SYN
                    if (cl->vty) {
                        close(cl->s_out);
                        cl->s_out = -1;
                    }
#endif
                }

                if (action & CA_NOTIFY) {
                    rdline_puts(rdl, "\r\n");
                    for (i=0 ; tmp_buf_notify[i] ; i++)
                        rdl->write_char(rdl, tmp_buf_notify[i]);
                    tyflow_rdline_redisplay(rdl);
#ifdef VTY_SYN
                    if (cl->vty) {
                        close(cl->s_out);
                        cl->s_out = -1;
                    }
#endif
                }
            }

			return RDLINE_RES_COMPLETE;

		/* complete buffer */
		case CMDLINE_KEY_RETURN:
		case CMDLINE_KEY_RETURN2:
			tyflow_rdline_get_buffer(rdl);
			rdl->status = RDLINE_INIT;
			rdline_puts(rdl, "\r\n");
			if (rdl->history_cur_line != -1)
				rdline_remove_first_history_item(rdl);

			if (rdl->validate)
				rdl->validate(rdl, rdl->left_buf, CIRBUF_GET_LEN(&rdl->left)+2);
			/* user may have stopped rdline */
			if (rdl->status == RDLINE_EXITED)
				return RDLINE_RES_EXITED;
			return RDLINE_RES_VALIDATED;

		/* previous element in history */
		case CMDLINE_KEY_UP_ARR:
		case CMDLINE_KEY_CTRL_P:
			if (rdl->history_cur_line == 0) {
				rdline_remove_first_history_item(rdl);
			}
			if (rdl->history_cur_line <= 0) {
				tyflow_rdline_add_history(rdl, tyflow_rdline_get_buffer(rdl));
				rdl->history_cur_line = 0;
			}

			buf = tyflow_rdline_get_history_item(rdl, rdl->history_cur_line + 1);
			if (!buf)
				break;

			rdl->history_cur_line ++;
			tyflow_vt100_init(&rdl->vt100);
			tyflow_cirbuf_init(&rdl->left, rdl->left_buf, 0, RDLINE_BUF_SIZE);
			tyflow_cirbuf_init(&rdl->right, rdl->right_buf, 0, RDLINE_BUF_SIZE);
			tyflow_cirbuf_add_buf_tail(&rdl->left, buf, strnlen(buf, RDLINE_BUF_SIZE));
			tyflow_rdline_redisplay(rdl);
			break;

		/* next element in history */
		case CMDLINE_KEY_DOWN_ARR:
		case CMDLINE_KEY_CTRL_N:
			if (rdl->history_cur_line - 1 < 0)
				break;

			rdl->history_cur_line --;
			buf = tyflow_rdline_get_history_item(rdl, rdl->history_cur_line);
			if (!buf)
				break;
			tyflow_vt100_init(&rdl->vt100);
			tyflow_cirbuf_init(&rdl->left, rdl->left_buf, 0, RDLINE_BUF_SIZE);
			tyflow_cirbuf_init(&rdl->right, rdl->right_buf, 0, RDLINE_BUF_SIZE);
			tyflow_cirbuf_add_buf_tail(&rdl->left, buf, strnlen(buf, RDLINE_BUF_SIZE));
			tyflow_rdline_redisplay(rdl);

			break;


		default:
			break;
		}

		return RDLINE_RES_SUCCESS;
	}

	if (!isprint((int)c))
		return RDLINE_RES_SUCCESS;

	/* standard chars */
	if (CIRBUF_GET_LEN(&rdl->left) + CIRBUF_GET_LEN(&rdl->right) >= RDLINE_BUF_SIZE)
		return RDLINE_RES_SUCCESS;

	if (tyflow_cirbuf_add_tail_safe(&rdl->left, c))
		return RDLINE_RES_SUCCESS;

	rdl->write_char(rdl, c);
	display_right_buffer(rdl, 0);

	return RDLINE_RES_SUCCESS;
}


/* HISTORY */

static void
rdline_remove_old_history_item(struct rdline * rdl)
{
	char tmp;

	while (! CIRBUF_IS_EMPTY(&rdl->history) ) {
		tmp = tyflow_cirbuf_get_head(&rdl->history);
		tyflow_cirbuf_del_head(&rdl->history);
		if (!tmp)
			break;
	}
}

static void
rdline_remove_first_history_item(struct rdline * rdl)
{
	char tmp;

	if ( CIRBUF_IS_EMPTY(&rdl->history) ) {
		return;
	}
	else {
		tyflow_cirbuf_del_tail(&rdl->history);
	}

	while (! CIRBUF_IS_EMPTY(&rdl->history) ) {
		tmp = tyflow_cirbuf_get_tail(&rdl->history);
		if (!tmp)
			break;
		tyflow_cirbuf_del_tail(&rdl->history);
	}
}

static unsigned int
rdline_get_history_size(struct rdline * rdl)
{
	unsigned int i, tmp, ret=0;

	CIRBUF_FOREACH(&rdl->history, i, tmp) {
		if (tmp == 0)
			ret ++;
	}

	return ret;
}

char *
tyflow_rdline_get_history_item(struct rdline * rdl, unsigned int idx)
{
	unsigned int len, i, tmp;

	if (!rdl)
		return NULL;

	len = rdline_get_history_size(rdl);
	if ( idx >= len ) {
		return NULL;
	}

	tyflow_cirbuf_align_left(&rdl->history);

	CIRBUF_FOREACH(&rdl->history, i, tmp) {
		if ( idx == len - 1) {
			return rdl->history_buf + i;
		}
		if (tmp == 0)
			len --;
	}

	return NULL;
}

int
tyflow_rdline_add_history(struct rdline * rdl, const char * buf)
{
	unsigned int len, i;

	if (!rdl || !buf)
		return -EINVAL;

	len = strnlen(buf, RDLINE_BUF_SIZE);
	for (i=0; i<len ; i++) {
		if (buf[i] == '\n') {
			len = i;
			break;
		}
	}

	if ( len >= RDLINE_HISTORY_BUF_SIZE )
		return -1;

	while ( len >= CIRBUF_GET_FREELEN(&rdl->history) ) {
		rdline_remove_old_history_item(rdl);
	}

	tyflow_cirbuf_add_buf_tail(&rdl->history, buf, len);
	tyflow_cirbuf_add_tail(&rdl->history, 0);

	return 0;
}

void
tyflow_rdline_clear_history(struct rdline * rdl)
{
	if (!rdl)
		return;
	tyflow_cirbuf_init(&rdl->history, rdl->history_buf, 0, RDLINE_HISTORY_BUF_SIZE);
}


/* STATIC USEFUL FUNCS */

static void
rdline_puts(struct rdline * rdl, const char * buf)
{
	char c;
	while ( (c = *(buf++)) != '\0' ) {
		rdl->write_char(rdl, c);
	}
}

/* a very very basic printf with one arg and one format 'u' */
static void
rdline_miniprintf(struct rdline *rdl, const char * buf, unsigned int val)
{
	char c, started=0, div=100;

	while ( (c=*(buf++)) ) {
		if (c != '%') {
			rdl->write_char(rdl, c);
			continue;
		}
		c = *(buf++);
		if (c != 'u') {
			rdl->write_char(rdl, '%');
			rdl->write_char(rdl, c);
			continue;
		}
		/* val is never more than 255 */
		while (div) {
			c = (char)(val / div);
			if (c || started) {
				rdl->write_char(rdl, (char)(c+'0'));
				started = 1;
			}
			val %= div;
			div /= 10;
		}
	}
}
