/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#ifndef _PARSE_STRING_H_
#define _PARSE_STRING_H_

#include "cmdline_parse.h"

#ifdef __cplusplus
extern "C" {
#endif

/* size of a parsed string */
#define STR_TOKEN_SIZE 128

/* size of a parsed multi string */
#define STR_MULTI_TOKEN_SIZE 4096

typedef char cmdline_fixed_string_t[STR_TOKEN_SIZE];

typedef char cmdline_multi_string_t[STR_MULTI_TOKEN_SIZE];

struct cmdline_token_string_data {
	const char *str;
};

struct cmdline_token_string {
	struct cmdline_token_hdr hdr;
	struct cmdline_token_string_data string_data;
};
typedef struct cmdline_token_string cmdline_parse_token_string_t;

extern struct cmdline_token_ops tyflow_cmdline_token_string_ops;

int tyflow_cmdline_parse_string(cmd_node_t *node, const char *srcbuf, cmd_blk_t *cmd_blk);
int tyflow_cmdline_complete_get_nb_string(cmdline_parse_token_hdr_t *tk);
int tyflow_cmdline_complete_get_elt_string(cmdline_parse_token_hdr_t *tk, int idx,
				    char *dstbuf, unsigned int size);
int tyflow_cmdline_get_help_string(cmdline_parse_token_hdr_t *tk, char *dstbuf,
			    unsigned int size);

/**
* Token marked as TOKEN_STRING_MULTI takes entire parsing string
* until “#” sign appear. Everything after “#” sign is treated as a comment.
*
* Note:
* In this case second parameter of TOKEN_STRING_INITIALIZER must be a type of
* cmdline_multi_string_t.
*/
#define TOKEN_STRING_MULTI ""

#define TOKEN_STRING_INITIALIZER(structure, field, string)  \
{                                                           \
	/* hdr */                                               \
	{                                                       \
		&tyflow_cmdline_token_string_ops,      /* ops */           \
		offsetof(structure, field),     /* offset */        \
	},                                                      \
	/* string_data */                                       \
	{                                                       \
		string,                         /* str */           \
	},                                                      \
}

#ifdef __cplusplus
}
#endif

#endif /* _PARSE_STRING_H_ */
