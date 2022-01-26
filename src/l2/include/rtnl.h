
#ifndef __INCLUDE_RTNL_H__
#define __INCLUDE_RTNL_H__

#ifdef __cplusplus
    extern "C" {
#endif

#define ASSERT_RTNL() do { /*if you want to realize, ref to kernel */} while(0)

void rtnl_lock(void);
void rtnl_unlock(void);
void __rtnl_unlock(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_RTNL_H__ */

