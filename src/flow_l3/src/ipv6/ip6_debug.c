#include "conf/inet.h"


//static RTE_DEFINE_PER_LCORE(struct inet_stats, ipv6_stats);
__thread struct inet_stats per_lcore_ipv6_stats;




