
#include <rte_ip.h>
#include <rte_byteorder.h>

#define RTE_IP6_VERSION_MASK 0xF0000000
#define RTE_IP6_VERSION_SHIFT 28

void static inline
rte_ipv6_hdr_print(struct rte_ipv6_hdr *hdr)
{
	uint8_t *addr;

	addr = hdr->src_addr;
	printf("src: %4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx \t",
	       (uint16_t)((addr[0] << 8) | addr[1]),
	       (uint16_t)((addr[2] << 8) | addr[3]),
	       (uint16_t)((addr[4] << 8) | addr[5]),
	       (uint16_t)((addr[6] << 8) | addr[7]),
	       (uint16_t)((addr[8] << 8) | addr[9]),
	       (uint16_t)((addr[10] << 8) | addr[11]),
	       (uint16_t)((addr[12] << 8) | addr[13]),
	       (uint16_t)((addr[14] << 8) | addr[15]));

	addr = hdr->dst_addr;
	printf("dst: %4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx",
	       (uint16_t)((addr[0] << 8) | addr[1]),
	       (uint16_t)((addr[2] << 8) | addr[3]),
	       (uint16_t)((addr[4] << 8) | addr[5]),
	       (uint16_t)((addr[6] << 8) | addr[7]),
	       (uint16_t)((addr[8] << 8) | addr[9]),
	       (uint16_t)((addr[10] << 8) | addr[11]),
	       (uint16_t)((addr[12] << 8) | addr[13]),
	       (uint16_t)((addr[14] << 8) | addr[15]));
}

static inline bool ipv6_version_check(const struct rte_ipv6_hdr *hdr){
    uint32_t vtc;
    vtc = rte_be_to_cpu_32(hdr->vtc_flow);

    if (unlikely(((vtc>>RTE_IP6_VERSION_SHIFT)&0xf) != 6))
        return false;
    else
        return true;
}

static inline struct rte_ipv6_hdr *rte_ip6_hdr(const struct rte_mbuf *mbuf)
{
    /* can only invoked at L3 */
    return rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
}

static inline bool rte_ipv6_addr_loopback(const uint8_t *src_addr){
    return (src_addr[0] | src_addr[1] | src_addr[2] | (src_addr[3] ^ rte_cpu_to_be_32(1))) == 0;
}

static inline bool rte_ipv6_addr_is_multicast(const uint8_t *src_addr)
{
    return (src_addr[0] & rte_cpu_to_be_32(0xFF000000)) == rte_cpu_to_be_32(0xFF000000);
}

#define RTE_IPV6_ADDR_MC_SCOPE(addr)   ((addr[1] & 0x0f))    /* nonstandard */
#define RTE_IPV6_ADDR_SCOPE_TYPE(scope)    ((scope) << 16)
#define RTE_IPV6_ADDR_ANY           0x0000U

#define RTE_IPV6_ADDR_UNICAST       0x0001U
#define RTE_IPV6_ADDR_MULTICAST     0x0002U

#define RTE_IPV6_ADDR_LOOPBACK      0x0010U
#define RTE_IPV6_ADDR_LINKLOCAL     0x0020U
#define RTE_IPV6_ADDR_SITELOCAL     0x0040U

#define RTE_IPV6_ADDR_COMPATv4      0x0080U

#define RTE_IPV6_ADDR_SCOPE_MASK    0x00f0U

#define RTE_IPV6_ADDR_MAPPED        0x1000U

#define RTE_IPV6_ADDR_RESERVED      0x2000U    /* reserved address space */

#define __RTE_IPV6_ADDR_SCOPE_INVALID    -1
#define RTE_IPV6_ADDR_SCOPE_NODELOCAL    0x01
#define RTE_IPV6_ADDR_SCOPE_LINKLOCAL    0x02
#define RTE_IPV6_ADDR_SCOPE_SITELOCAL    0x05
#define RTE_IPV6_ADDR_SCOPE_ORGLOCAL     0x08
#define RTE_IPV6_ADDR_SCOPE_GLOBAL       0x0e

static inline unsigned int rte_ipv6_addr_scope2type(unsigned int scope)
{
    switch (scope) {
    case RTE_IPV6_ADDR_SCOPE_NODELOCAL:
        return (RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_NODELOCAL) |
            RTE_IPV6_ADDR_LOOPBACK);
    case RTE_IPV6_ADDR_SCOPE_LINKLOCAL:
        return (RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_LINKLOCAL) |
            RTE_IPV6_ADDR_LINKLOCAL);
    case RTE_IPV6_ADDR_SCOPE_SITELOCAL:
        return (RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_SITELOCAL) |
            RTE_IPV6_ADDR_SITELOCAL);
    }
    return RTE_IPV6_ADDR_SCOPE_TYPE(scope);
}

static inline int __rte_ipv6_addr_type(const uint8_t *addr)
{
    uint32_t *pst = (uint32_t *)addr;
    uint32_t  st = *pst;

    /* Consider all addresses with the first three bits different of
       000 and 111 as unicasts.
     */
    if ((st & rte_cpu_to_be_32(0xE0000000)) != rte_cpu_to_be_32(0x00000000) &&
        (st & rte_cpu_to_be_32(0xE0000000)) != rte_cpu_to_be_32(0xE0000000))
        return (RTE_IPV6_ADDR_UNICAST |
            RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_GLOBAL));

    if ((st & rte_cpu_to_be_32(0xFF000000)) == rte_cpu_to_be_32(0xFF000000)) {
        /* multicast */
        /* addr-select 3.1 */
        return (RTE_IPV6_ADDR_MULTICAST |
            rte_ipv6_addr_scope2type(RTE_IPV6_ADDR_MC_SCOPE(addr)));
    }

    if ((st & rte_cpu_to_be_32(0xFFC00000)) == rte_cpu_to_be_32(0xFE800000))
        return (RTE_IPV6_ADDR_LINKLOCAL | RTE_IPV6_ADDR_UNICAST |
            RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_LINKLOCAL));        /* addr-select 3.1 */
    if ((st & rte_cpu_to_be_32(0xFFC00000)) == rte_cpu_to_be_32(0xFEC00000))
        return (RTE_IPV6_ADDR_SITELOCAL | RTE_IPV6_ADDR_UNICAST |
            RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_SITELOCAL));        /* addr-select 3.1 */
    if ((st & rte_cpu_to_be_32(0xFE000000)) == rte_cpu_to_be_32(0xFC000000))
        return (RTE_IPV6_ADDR_UNICAST |
            RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_GLOBAL));            /* RFC 4193 */

    if ((addr[0] | addr[1]) == 0) {
        if (addr[2] == 0) {
            if (addr[3] == 0)
                return RTE_IPV6_ADDR_ANY;

            if (addr[3] == htonl(0x00000001))
                return (RTE_IPV6_ADDR_LOOPBACK | RTE_IPV6_ADDR_UNICAST |
                    RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_LINKLOCAL));    /* addr-select 3.4 */

            return (RTE_IPV6_ADDR_COMPATv4 | RTE_IPV6_ADDR_UNICAST |
                RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_GLOBAL));    /* addr-select 3.3 */
        }

        if (addr[2] == rte_cpu_to_be_32(0x0000ffff))
            return (RTE_IPV6_ADDR_MAPPED |
                RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_GLOBAL));    /* addr-select 3.3 */
    }

    return (RTE_IPV6_ADDR_UNICAST |
        RTE_IPV6_ADDR_SCOPE_TYPE(RTE_IPV6_ADDR_SCOPE_GLOBAL));    /* addr-select 3.4 */
}

static inline int rte_ipv6_addr_type(const uint8_t *addr)
{
    return __rte_ipv6_addr_type(addr) & 0xffff;
}

