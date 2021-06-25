/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <termios.h>

#include <netinet/in.h>

#include <rte_string_fns.h>

#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "parser/flow_cmdline_rdline.h"
#include "parser/flow_cmdline_parse_string.h"
#include "parser/flow_cmdline_socket.h"

#ifdef RTE_LIBRTE_CMDLINE_DEBUG
#define debug_printf printf
#else
#define debug_printf(args...) do {} while(0)
#endif

#define CMDLINE_BUFFER_SIZE 64

int
tyflow_cmdline_isendoftoken(char c)
{
	if (!c || iscomment(c) || isblank2(c) || isendofline(c))
		return 1;
	return 0;
}

int
tyflow_cmdline_isendofcommand(char c)
{
	if (!c || iscomment(c) || isendofline(c))
		return 1;
	return 0;
}

#if 0
static unsigned int
nb_common_chars(const char * s1, const char * s2)
{
	unsigned int i=0;

	while (*s1==*s2 && *s1) {
		s1++;
		s2++;
		i++;
	}
	return i;
}

/** Retrieve either static or dynamic token at a given index. */
static cmdline_parse_token_hdr_t *
get_token(cmdline_parse_inst_t *inst, unsigned int index)
{
	cmdline_parse_token_hdr_t *token_p;

	/* check presence of static tokens first */
	if (inst->tokens[0] || !inst->f)
		return inst->tokens[index];
	/* generate dynamic token */
	token_p = NULL;
	inst->f(&token_p, NULL, &inst->tokens[index]);
	return token_p;
}
#endif

static inline int
add_to_res(unsigned int c, uint32_t *res, unsigned int base)
{
	/* overflow */
	if ( (UINT32_MAX - c) / base < *res ) {
		return -1;
	}

	*res = (uint32_t) (*res * base + c);
	return 0;
}

/**
 * try to match the buffer with an instruction (only the first
 * nb_match_token tokens if != 0). Return 0 if we match all the
 * tokens, else the number of matched tokens, else -1.
 */
extern int
match_node(cmd_node_t *node, const char *buf,
	       int partial, int partial_len, cmd_blk_t *cmd_blk);
int
match_node(cmd_node_t *node, const char *buf,
	       int partial, int partial_len, cmd_blk_t *cmd_blk)
{
	int rc;
	char *token;
	int len = 0, str_len, quote;
	uint32_t uint_value;
	char c;
    /* change to struct in6_addr later */
    char tmp[INET_ADDRSTRLEN];
    char ipv4[sizeof(struct in_addr)];
	if (!node || !buf || !cmd_blk)
		return -1;

	if (node->type == CMD_NODE_TYPE_STR ||
        node->type == CMD_NODE_TYPE_NUM ||
        node->type == CMD_NODE_TYPE_IPV4 ||
        node->type == CMD_NODE_TYPE_NONE ||
		node->type == CMD_NODE_TYPE_EOL) {
		rc = 0;
		goto parse_it;
	}
    token = node->token;
	len = strlen(token);

    if (partial && partial_len<=len) {
        rc = strncmp(buf, token, partial_len);
        if (!rc) {
            return partial_len;
        } else {
            return -1;
        }
    }
	rc = strncmp(buf, token, len);
	if (rc || !(isblank2(*(buf+len)) || isendofline(*(buf+len)))) {
		return -1;
	} else {
parse_it:
		switch (node->type) {
			case CMD_NODE_TYPE_KW:
				switch (node->subtype) {
					case CMD_KW_TYPE_WHICH:
						cmd_blk->which_cnt++;
						cmd_blk->which[node->index-1] = node->value;
						break;
					case CMD_KW_TYPE_SET:
					case CMD_KW_TYPE_DEBUG:
                    case CMD_KW_TYPE_CREATE:
                        if (!strcmp(token, "set") ||
                            !strcmp(token, "debug") ||
                            !strcmp(token, "create"))
                            cmd_blk->mode = MODE_DO;
                        break;
                    case CMD_KW_TYPE_UNSET:
                    case CMD_KW_TYPE_UNDEB:
                    case CMD_KW_TYPE_DELETE:
                        if (!strcmp(token, "unset") ||
                            !strcmp(token, "undebug") ||
                            !strcmp(token, "delete"))
                            cmd_blk->mode = MODE_UNDO;
                        break;
                    case CMD_KW_TYPE_MOVE:
					default:
						break;
				}
				rc = len;
				break;
			case CMD_NODE_TYPE_STR:
			case CMD_NODE_TYPE_IPV4:
				str_len = 0;
                /* string type need to support "xxx yyy" */
                quote = (buf[0]=='"')?1:0;
				while((!quote && !tyflow_cmdline_isendoftoken(buf[str_len])) ||
                      (quote && tyflow_cmdline_isendofcommand(buf[str_len]))) {
					str_len++;
                    /* if the string is not begin with '"', treat it as a common charactor */
                    if (quote && buf[str_len] == '"')
                        quote = 0;
				}
                if (!str_len && !partial)
                    return -1;
                if (node->type == CMD_NODE_TYPE_STR) {
                    cmd_blk->string_cnt++;
                    strncpy(cmd_blk->string[node->index-1], buf, str_len);
                    rc = str_len;
                } else if (node->type == CMD_NODE_TYPE_IPV4) {
                    if (str_len >= INET_ADDRSTRLEN)
                        return -1;
                    strncpy(tmp, buf, str_len);
                    tmp[str_len] = '\0';
                    rc = inet_pton(AF_INET, tmp, ipv4);
                    if (rc <= 0) {
                        return -1;
                    }
                    cmd_blk->ipv4_cnt++;
                    cmd_blk->ipv4[node->index-1] = htonl(*((uint32_t *)ipv4));
                }
				break;
			case CMD_NODE_TYPE_NUM:
				uint_value = 0;
				str_len = 0;
				c = *buf;
				while (!tyflow_cmdline_isendoftoken(c)) {
					if (add_to_res(c - '0', &uint_value, 10) < 0) {
						return -1;
					}
					buf++;
					str_len++;
					c = *buf;
				}
				cmd_blk->number_cnt++;
				cmd_blk->number[node->index-1] = uint_value;
				rc = str_len;
				break;
			case CMD_NODE_TYPE_EOL:
				while (isblank2(*buf)) {
					buf++;
				}
				if (!isendofline(*buf) && !iscomment(*buf) && !(partial && !*buf)) {
					return -1;
				}
				rc = 0;
				break;
			case CMD_NODE_TYPE_NONE:
			default:
                return -1;
		}
	}

	return rc;
#if 0
	cmdline_parse_token_hdr_t *token_p = NULL;
	unsigned int i=0;
	int n = 0;
	struct cmdline_token_hdr token_hdr;

	if (resbuf != NULL)
		memset(resbuf, 0, resbuf_size);
	/* check if we match all tokens of inst */
	while (!nb_match_token || i < nb_match_token) {
		token_p = get_token(inst, i);
		if (!token_p)
			break;
		memcpy(&token_hdr, token_p, sizeof(token_hdr));

		debug_printf("TK\n");
		/* skip spaces */
		while (isblank2(*buf)) {
			buf++;
		}

		/* end of buf */
		if ( isendofline(*buf) || iscomment(*buf) )
			break;

		if (resbuf == NULL) {
			n = token_hdr.ops->parse(token_p, buf, NULL, 0);
		} else {
			unsigned rb_sz;

			if (token_hdr.offset > resbuf_size) {
				printf("Parse error(%s:%d): Token offset(%u) "
					"exceeds maximum size(%u)\n",
					__FILE__, __LINE__,
					token_hdr.offset, resbuf_size);
				return -ENOBUFS;
			}
			rb_sz = resbuf_size - token_hdr.offset;

			n = token_hdr.ops->parse(token_p, buf, (char *)resbuf +
				token_hdr.offset, rb_sz);
		}

		if (n < 0)
			break;

		debug_printf("TK parsed (len=%d)\n", n);
		i++;
		buf += n;
	}

	/* does not match */
	if (i==0)
		return -1;

	/* in case we want to match a specific num of token */
	if (nb_match_token) {
		if (i == nb_match_token) {
			return 0;
		}
		return i;
	}

	/* we don't match all the tokens */
	if (token_p) {
		return i;
	}

	/* are there are some tokens more */
	while (isblank2(*buf)) {
		buf++;
	}

	/* end of buf */
	if ( isendofline(*buf) || iscomment(*buf) )
		return 0;

	/* garbage after inst */
	return i;
#endif
}

int
tyflow_cmdline_parse(struct cmdline *cl, const char * buf, int console)
{
	cmd_node_t *node;
	char *curbuf;
	cmd_blk_t cmd_blk = {0};
	cmd_fn_t f = NULL;
	int comment = 0;
	int linelen = 0;
	int parse_it = 0;
	int tok = 0, ret;

	if ((!cl && console) || !buf)
		return CMDLINE_PARSE_BAD_ARGS;

	/*
	 * - look if the buffer contains at least one line
	 * - look if line contains only spaces or comments
	 * - count line length
	 */
	curbuf = (char *)buf;
	while (! isendofline(*curbuf)) {
		if ( *curbuf == '\0' ) {
			debug_printf("Incomplete buf (len=%d)\n", linelen);
			return 0;
		}
		if ( iscomment(*curbuf) ) {
			comment = 1;
		}
		if ( ! isblank2(*curbuf) && ! comment) {
			parse_it = 1;
		}
		curbuf++;
		linelen++;
	}

	/* skip all endofline chars */
	while (isendofline(buf[linelen])) {
		linelen++;
	}

	/* empty line */
	if ( parse_it == 0 ) {
		debug_printf("Empty line (len=%d)\n", linelen);
		return 0;
	}

	debug_printf("Parse line : len=%d, <%.*s>\n",
		     linelen, linelen > 64 ? 64 : linelen, buf);

	/* parse it !! */
	node = cnode(root).child;
    curbuf = (char *)buf;
	while (node) {
		debug_printf("Node %s\n", node->token);

        while (isblank2(*curbuf)){
            curbuf++;
        }

		/* fully parsed */
		tok = match_node(node, curbuf, 0, 0, &cmd_blk);

		if (tok < 0) {
			node = node->sibl;
		} else if (tok == 0) {
			/* exactly match a command */
			f = node->func;
			if (!f) {
				debug_printf("\tEnd node without func!\n");
			}
			break;
		} else {
			curbuf+=tok;
			node = node->child;
		}
	}
	if (tok < 0) {
        if (!(isendofline(*curbuf) || iscomment(*curbuf))) {
            /* hack it by adding 1 */
            return curbuf-buf+1;
        } else {
            return buf-curbuf-1;
        }
    } else if (f) {
		cmd_blk.cl = cl;
		ret = f(&cmd_blk);
        if (!console) {
            /* curbuf now has a brand new semantic */
            curbuf = strdup(buf);
            if (curbuf) {
                if (curbuf[strlen(curbuf)-1] == '\n')
                    curbuf[strlen(curbuf)-1] = 0;
                cmdbatch_debug_trace(CMDBATCH_DEBUG_BASIC, 
                                     "%s: the command (%s) is issued %d/%s\n", 
                                     __func__, curbuf, ret,
                                     ret==0?"successfully":"failed");
                free(curbuf);
            }
        }
		return 0;
	} else {
		/* should never be there */
		return -1;
	}

#if 0

		if (tok > 0) /* we matched at least one token */
			err = CMDLINE_PARSE_BAD_ARGS;

		else if (!tok) {
			debug_printf("INST fully parsed\n");
			/* skip spaces */
			while (isblank2(*curbuf)) {
				curbuf++;
			}

			/* if end of buf -> there is no garbage after inst */
			if (isendofline(*curbuf) || iscomment(*curbuf)) {
				if (!f) {
					memcpy(&f, &inst->f, sizeof(f));
					memcpy(&data, &inst->data, sizeof(data));
					result_buf = tmp_result.buf;
				}
				else {
					/* more than 1 inst matches */
					err = CMDLINE_PARSE_AMBIGUOUS;
					f=NULL;
					debug_printf("Ambiguous cmd\n");
					break;
				}
			}
		}

		inst_num ++;
		inst = ctx[inst_num];
	}
	/* call func */
	if (f) {
		f(result.buf, cl, data);
	}

	/* no match */
	else {
		debug_printf("No match err=%d\n", err);
		return err;
	}

	return linelen;
#endif
}

#pragma GCC push_options
#pragma GCC optimize (0)
int
tyflow_cmdline_complete(struct cmdline *cl, const char *buf, int *action, char *dst, unsigned int size)
{
    int i, len;
    const char *partial_buf, *curbuf;
    int partial_len = 0, partial = 0, node_partial_index = 0;
	cmd_node_t *node;
	cmd_node_t *node_partial_match[256] = {0};
	cmd_blk_t cmd_blk = {0};
    int tok = 0;

	if (!cl || !buf || !action || !dst)
		return -1;

    partial_buf = buf;
	for (i=0; buf[i]; i++) {
        if (isblank2(buf[i]) && !isblank2(buf[i+1])) {
            partial_buf = &buf[i+1];
            partial_len = 0;
        } else {
            partial_len++;
        }
    }
    /*
    if (*partial_buf == 0) {
        *action = CA_NOTIFY;
    }
    */

    node = cnode(root).child;
    curbuf = buf;
    while (node) {
        while (*curbuf == ' '){
            curbuf++;
        }

        partial = (curbuf<partial_buf)?0:1;
        tok = match_node(node, curbuf, partial, partial_len, &cmd_blk);
        if (tok < 0) {
            node = node->sibl;
            continue;
        }
        if (partial) {
            node_partial_match[node_partial_index++] = node;
            node = node->sibl;
        } else {
            if (tok == 0) {
                break;
            } else {
                curbuf+=tok;
                node = node->child;
            }
        }
    }

    len = 0;
    if (!node_partial_index) {
        if (!(isendofline(*curbuf) || iscomment(*curbuf))) {
            return curbuf-buf+1;
        }
    } else if (node_partial_index==1) {
        node = node_partial_match[0];
        if (*action == CA_APPEND) {
            if (node_partial_match[0]->type == CMD_NODE_TYPE_KW) {
                snprintf(dst+len, size-len, "%s ", node_partial_match[0]->token+partial_len);
            } else {
                if (*partial_buf) {
                    *dst = ' ';
                } else {
                    char *token = cmd_get_value_node_token(node_partial_match[0]);
                    *action = CA_NOTIFY;
                    snprintf(dst+len, size-len, "%-24s%s\r\n", token, node_partial_match[0]->help);
                }
            }
        } else {
            if (node_partial_match[0]->type == CMD_NODE_TYPE_KW) {
                snprintf(dst+len, size-len, "%-24s%s\r\n", node_partial_match[0]->token, node_partial_match[0]->help);
            } else {
                char *token = cmd_get_value_node_token(node_partial_match[0]);
                snprintf(dst+len, size-len, "%-24s%s\r\n", token, node_partial_match[0]->help);
            }
        }
        return 0;
    } else {
        /* node_partial_index > 1 */
        if (*action == CA_APPEND) {
            *action = CA_NOTIFY;
        }
        node = node_partial_match[0];
        for (i=node_partial_index-1; i>=0; i--) {
            if (node_partial_match[0]->type == CMD_NODE_TYPE_KW) {
                len += snprintf(dst+len, size-len, "%-24s%s\r\n", node_partial_match[i]->token, node_partial_match[i]->help);
            } else {
                char *token = cmd_get_value_node_token(node_partial_match[i]);
                len += snprintf(dst+len, size-len, "%-24s%s\r\n", token, node_partial_match[i]->help);
            }
        }
    }
    return 0;
}
#pragma GCC pop_options

cmd_node_t cnode(root) = {
	NULL,
	NULL,
	CMD_NODE_TYPE_ROOT,
	0,
	0,
	0,
	NULL,
	NULL,
	NULL
};

cmd_node_t cnode(none) = {
	NULL,
	NULL,
	CMD_NODE_TYPE_NONE,
	0,
	0,
	0,
	NULL,
	NULL,
	NULL
};

cmd_node_t *root_cmd = &cnode(root);
cmd_node_t *last_top_cmd = NULL;
cmd_node_t *last_set_cmd = NULL;
cmd_node_t *last_get_cmd = NULL;
cmd_node_t *last_clear_cmd = NULL;
cmd_node_t *last_debug_cmd = NULL;
cmd_node_t *last_create_cmd = NULL;
cmd_node_t *last_move_cmd = NULL;

KW_NODE(set, none, none, "set", "configure system parameters");
KW_NODE_UNSET(unset, none, none, "unset", "unconfigure system parameters");
KW_NODE(get, none, none, "show", "show system infomation");
KW_NODE(clear, none, none, "clear", "clear system statistic/trace/message/log/etc");
KW_NODE_DEBUG(debug, none, none, "debug", "debug system modules");
KW_NODE_UNDEB(undebug, none, none, "undebug", "undebug system modules");
KW_NODE_CREATE(create, none, none, "create", "create system configure");
KW_NODE_DELETE(delete, none, none, "delete", "delete system configure");
KW_NODE_MOVE(move, none, none, "move", "move system configure");

static void
add_cmd(cmd_node_t *node, cmd_node_t **last, cmd_node_t *top)
{
	if (*last) {
		(*last)->sibl = node;
	} else {
		top->child = node;
	}
	*last = node;
}

void
add_top_cmd(cmd_node_t *node)
{
	add_cmd(node, &last_top_cmd, root_cmd);
}

void
add_set_cmd(cmd_node_t *node)
{
	add_cmd(node, &last_set_cmd, &cnode(set));
}

void
add_get_cmd(cmd_node_t *node)
{
	add_cmd(node, &last_get_cmd, &cnode(get));
}

void
add_clear_cmd(cmd_node_t *node)
{
	add_cmd(node, &last_clear_cmd, &cnode(clear));
}

void
add_debug_cmd(cmd_node_t *node)
{
	add_cmd(node, &last_debug_cmd, &cnode(debug));
}

void
add_create_cmd(cmd_node_t *node)
{
	add_cmd(node, &last_create_cmd, &cnode(create));
}

void
add_move_cmd(cmd_node_t *node)
{
	add_cmd(node, &last_move_cmd, &cnode(move));
}

static void
cmd_dup_child(cmd_node_t *dst, cmd_node_t *src)
{
    dst->child = src->child;
}

extern void
debug_init(void);
extern void
cmd_batch_init(void);
void
cmd_init(void)
{
	add_top_cmd(&cnode(exit));
	add_top_cmd(&cnode(get));
	add_top_cmd(&cnode(clear));
	add_top_cmd(&cnode(set));
    add_top_cmd(&cnode(unset));
    cmd_dup_child(&cnode(unset), &cnode(set));

    debug_init();
    add_top_cmd(&cnode(debug));
    add_top_cmd(&cnode(undebug));
    cmd_dup_child(&cnode(undebug), &cnode(debug));

    cmd_batch_init();

    add_top_cmd(&cnode(create));
    add_top_cmd(&cnode(delete));
    cmd_dup_child(&cnode(delete), &cnode(create));

    add_top_cmd(&cnode(move));
}

