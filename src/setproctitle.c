#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/queue.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <rte_mempool.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_log.h>

#include "setproctitle.h"

extern char **environ;

static char **os_argv;
static char  *os_argv_last;

static char *cpystrn(char *dst, char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}

uint32_t save_argv(char **argv)
{
    os_argv = argv;

    return 0;
}

uint32_t setproctitle_init(void)
{
    char *p;
    uint32_t size;
    uint32_t i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = rte_malloc("", size, 0);
    if (p == NULL) {
        return -1;
    }

    os_argv_last = os_argv[0];

    for (i = 0; os_argv[i]; i++) {
        if (os_argv_last == os_argv[i]) {
            os_argv_last = os_argv[i] + strlen(os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            os_argv_last = environ[i] + size;

            cpystrn(p, environ[i], size);
            environ[i] = p;
            p += size;
        }
    }

    os_argv_last--;

    return 0;
}

void setproctitle(char title[16])
{
    char *p;

    os_argv[1] = NULL;

    p = cpystrn(os_argv[0], title, os_argv_last - os_argv[0]);

    if (os_argv_last -  p) {
        memset(p, '\0', os_argv_last - p);
    }

    prctl(PR_SET_NAME, title);

    return;
}
