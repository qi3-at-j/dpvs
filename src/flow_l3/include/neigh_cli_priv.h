#ifndef __NODE_NEIGH_CLI_PRIV_H__
#define __NODE_NEIGH_CLI_PRIV_H__

enum {
    CLI_NUD_S_NONE        = 0,
    CLI_NUD_S_SEND,
    CLI_NUD_S_REACHABLE,
    CLI_NUD_S_PROBE,
    CLI_NUD_S_DELAY,
    CLI_NUD_S_MAX ,/*Reserved*/
    CLI_NUD_S_STATIC,
};

void neigh_cli_init(void);

#endif
