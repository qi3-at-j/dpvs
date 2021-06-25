
#include "dpdk_version_adapter.h"

int mbuf_userdata_dynfield_offset = -1;

int dpdk_priv_userdata_register(void){
	if (-1 == mbuf_userdata_dynfield_offset) {
			mbuf_userdata_dynfield_offset = rte_mbuf_dynfield_register(&mbuf_userdata_dynfield_desc);
			if (mbuf_userdata_dynfield_offset < 0)
				return -rte_errno;;
	}

	return 0;
}


__rte_always_inline void *
mbuf_userdata_get(struct rte_mbuf *m)
{
	return RTE_MBUF_DYNFIELD(m, mbuf_userdata_dynfield_offset, struct mbuf_priv_userdata *)->userdata;
}

__rte_always_inline void
mbuf_userdata_set(struct rte_mbuf *m, void *userdata)
{
	RTE_MBUF_DYNFIELD(m, mbuf_userdata_dynfield_offset, struct mbuf_priv_userdata *)->userdata = userdata;
}

__rte_always_inline uint64_t
mbuf_udata64_get(struct rte_mbuf *m)
{
	return RTE_MBUF_DYNFIELD(m, mbuf_userdata_dynfield_offset, struct mbuf_priv_userdata *)->udata64;
}

__rte_always_inline void
mbuf_udata64_set(struct rte_mbuf *m, uint64_t udata64)
{
	RTE_MBUF_DYNFIELD(m, mbuf_userdata_dynfield_offset, struct mbuf_priv_userdata *)->udata64 = udata64;
}



