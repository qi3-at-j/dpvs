
#include "dpdk_version_adapter.h"

int mbuf_userdata_dynfield_offset = -1;
int mbuf_dev_dynfield_offset = -1;


int dpdk_priv_userdata_register(void){
	if (-1 == mbuf_userdata_dynfield_offset) {
			mbuf_userdata_dynfield_offset = rte_mbuf_dynfield_register(&mbuf_userdata_dynfield_desc);
			if (mbuf_userdata_dynfield_offset < 0)
				return -rte_errno;;
	}

	return 0;
}

int dpdk_priv_dev_register(void){
	if (-1 == mbuf_dev_dynfield_offset) {
			mbuf_dev_dynfield_offset = rte_mbuf_dynfield_register(&mbuf_dev_dynfield_desc);
			if (mbuf_dev_dynfield_offset < 0)
				return -rte_errno;
	}

	return 0;
}
