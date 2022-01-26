#ifndef __SETPROCTITLE_H__
#define __SETPROCTITLE_H__

#include <inttypes.h>

extern uint32_t save_argv(char **argv);
extern uint32_t setproctitle_init(void);
extern void setproctitle(char title[16]);

#endif
