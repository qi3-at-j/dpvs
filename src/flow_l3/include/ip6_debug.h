

extern __thread struct inet_stats per_lcore_ipv6_stats;

#define this_ipv6_stats_graph  RTE_PER_LCORE(ipv6_stats)

#define IPv6_INC_STATS(__f__) \
    do { \
        this_ipv6_stats_graph.__f__++; \
    } while (0)

#define IPv6_DEC_STATS(__f__) \
    do { \
        this_ipv6_stats_graph.__f__--; \
    } while (0)

#define IPv6_ADD_STATS(__f__, val) \
    do { \
        this_ipv6_stats_graph.__f__ += (val); \
    } while (0)

#define IPv6_UPD_PO_STATS(__f__, val) \
    do { \
        this_ipv6_stats_graph.__f__##pkts ++; \
        this_ipv6_stats_graph.__f__##octets += (val); \
    } while (0)

