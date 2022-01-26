#ifndef __PROTO_RELATION_H__
#define __PROTO_RELATION_H__

#ifdef __cplusplus
extern "C"{
#endif

#include <inttypes.h>

extern int32_t proto_relation_init(void);
extern void proto_relation_fini(void);
extern uint32_t proto_relation_get(uint32_t app_id);
extern uint32_t proto_relation_process(void);

#ifdef __cplusplus
}
#endif

#endif

