
#ifndef __INCLUDE_L2_COMPAT_H__
#define __INCLUDE_L2_COMPAT_H__

#ifdef __cplusplus
    extern "C" {
#endif

#define RTE_LOGTYPE_DEV RTE_LOGTYPE_USER1


#define pr_debug(fmt, ...) \
	RTE_LOG(DEBUG, DEV, "%s(): " fmt "\n", __func__, ##__VA_ARGS__)

#define ASSERT(x) do {\
        if (!(x)) \
            rte_panic("dev: x"); \
    } while (0)

#define BUG_ON(x) ASSERT(!(x))

#ifndef pr_warn
#define pr_warn(fmt, ...) \
            RTE_LOG(WARNING, DEV, "%s(): " fmt "\n", __func__, ##__VA_ARGS__)
#endif

#ifndef pr_err
#define pr_err(fmt, ...) \
            RTE_LOG(ERR, DEV, "%s(): " fmt "\n", __func__, ##__VA_ARGS__)
#endif

#ifndef WARN_ON
#define WARN_ON(x) do { \
        int ret = !!(x); \
        if (unlikely(ret)) \
            pr_warn("WARN_ON: \"" #x "\" at %s:%d\n", __func__, __LINE__); \
    } while (0)
#endif


#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_L2_COMPAT_H__ */

