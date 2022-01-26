/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 chc
 */

#include <stddef.h>
#include <rte_debug.h>

#include "ip_frag_common.h"

static inline int
frag_reassemble_virt(struct ip_frag_pkt *fp,
    struct rte_mbuf **mb_out, uint8_t flag, uint32_t idx)
{
    int i, cnt;

    if ((fp->frags[IP_FIRST_FRAG_IDX].mb == NULL) &&
        (!(fp->frags[IP_FIRST_FRAG_IDX].len & 0x8000))) {
        return 0;
    }

    cnt = 0;
    if (flag == 0) {
        if (likely(fp->frags[IP_FIRST_FRAG_IDX].len & 0x8000)) {
            fp->frags[idx].len |= 0x8000;
            mb_out[cnt++] = fp->frags[idx].mb;
            fp->frags[idx].mb = NULL;
            return cnt;
        }

        for (i = IP_FIRST_FRAG_IDX; i < IP_MAX_FRAG_NUM; i++) {
            if (fp->frags[i].mb) {
                fp->frags[i].len |= 0x8000;
                mb_out[cnt++] = fp->frags[i].mb;
                fp->frags[i].mb = NULL;
            }
        }

        if (unlikely(fp->frags[IP_LAST_FRAG_IDX].mb)) {
            fp->frags[IP_LAST_FRAG_IDX].len |= 0x8000;
            mb_out[cnt++] = fp->frags[IP_LAST_FRAG_IDX].mb;
            fp->frags[IP_LAST_FRAG_IDX].mb = NULL;
        }

        return cnt;
    } else if (flag == 1) {
        for (i = IP_FIRST_FRAG_IDX; i < IP_MAX_FRAG_NUM; i++) {
            if ((fp->frags[i].mb == NULL)) {
                if(fp->frags[i].len & 0x8000) {
                    continue;
                } else {
                    break;
                }
            }

            if (fp->frags[i].mb) {
                fp->frags[i].len |= 0x8000;
                mb_out[cnt++] = fp->frags[i].mb;
                fp->frags[i].mb = NULL;
            }
        }

        if (unlikely((fp->frag_size == fp->total_size) &&
            (fp->frags[IP_LAST_FRAG_IDX].mb))) {
            fp->frags[IP_LAST_FRAG_IDX].len |= 0x8000;
            mb_out[cnt++] = fp->frags[IP_LAST_FRAG_IDX].mb;
            fp->frags[IP_LAST_FRAG_IDX].mb = NULL;
        }

        return cnt;
    } else {
        if (unlikely(fp->frag_size == fp->total_size)) {           
            for (i = IP_FIRST_FRAG_IDX; i < IP_MAX_FRAG_NUM; i++) {                
                if (fp->frags[i].mb) {
                    fp->frags[i].len |= 0x8000;
                    mb_out[cnt++] = fp->frags[i].mb;
                    fp->frags[i].mb = NULL;
                }
            }
            fp->frags[IP_LAST_FRAG_IDX].len |= 0x8000;
            mb_out[cnt++] = fp->frags[IP_LAST_FRAG_IDX].mb;
            fp->frags[IP_LAST_FRAG_IDX].mb = NULL;
        }

        return cnt;       
    }
}

static int
ip_frag_process_virt(struct ip_frag_pkt *fp,
    struct rte_ip_frag_death_row *dr, struct rte_mbuf *mb, uint16_t ofs,
    uint16_t len, uint16_t more_frags, struct rte_mbuf **mb_out, uint8_t flag)
{
	uint32_t idx;
    int cnt = 0;

	fp->frag_size += len;

	/* this is the first fragment. */
	if (ofs == 0) {
		idx = (fp->frags[IP_FIRST_FRAG_IDX].mb == NULL) ?
				IP_FIRST_FRAG_IDX : UINT32_MAX;

	/* this is the last fragment. */
	} else if (more_frags == 0) {
		fp->total_size = ofs + len;
		idx = (fp->frags[IP_LAST_FRAG_IDX].mb == NULL) ?
				IP_LAST_FRAG_IDX : UINT32_MAX;

	/* this is the intermediate fragment. */
	} else if ((idx = fp->last_idx) < RTE_DIM(fp->frags)) {
		fp->last_idx++;
	}

	/*
	 * erroneous packet: either exceed max allowed number of fragments,
	 * or duplicate first/last/intermediate fragment encountered.
	 */
	if (idx >= RTE_DIM(fp->frags)) {

		/* report an error. */
		if (fp->key.key_len == IPV4_KEYLEN)
			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
				"ipv4_frag_pkt: %p, key: <%" PRIx64 ", %#x>, "
				"total_size: %u, frag_size: %u, last_idx: %u\n"
				"first fragment: ofs: %u, len: %u\n"
				"last fragment: ofs: %u, len: %u\n\n",
				__func__, __LINE__,
				fp, fp->key.src_dst[0], fp->key.id,
				fp->total_size, fp->frag_size, fp->last_idx,
				fp->frags[IP_FIRST_FRAG_IDX].ofs,
				fp->frags[IP_FIRST_FRAG_IDX].len,
				fp->frags[IP_LAST_FRAG_IDX].ofs,
				fp->frags[IP_LAST_FRAG_IDX].len);
		else
			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
				"ipv6_frag_pkt: %p, key: <" IPv6_KEY_BYTES_FMT ", %#x>, "
				"total_size: %u, frag_size: %u, last_idx: %u\n"
				"first fragment: ofs: %u, len: %u\n"
				"last fragment: ofs: %u, len: %u\n\n",
				__func__, __LINE__,
				fp, IPv6_KEY_BYTES(fp->key.src_dst), fp->key.id,
				fp->total_size, fp->frag_size, fp->last_idx,
				fp->frags[IP_FIRST_FRAG_IDX].ofs,
				fp->frags[IP_FIRST_FRAG_IDX].len,
				fp->frags[IP_LAST_FRAG_IDX].ofs,
				fp->frags[IP_LAST_FRAG_IDX].len);

		/* free all fragments, invalidate the entry. */
		ip_frag_free(fp, dr);
		ip_frag_key_invalidate(&fp->key);
		IP_FRAG_MBUF2DR(dr, mb);

		return -1;
	}

	fp->frags[idx].ofs = ofs;
	fp->frags[idx].len = len & 0x7FFF;
	fp->frags[idx].mb = mb;

    cnt = frag_reassemble_virt(fp, mb_out, flag, idx);

	/* we collected all fragments. */
    if (fp->frag_size == fp->total_size) {
		if (fp->frags[IP_FIRST_FRAG_IDX].mb == NULL) {
		    /* report an error. */
    		if (fp->key.key_len == IPV4_KEYLEN)
    			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
    				"ipv4_frag_pkt: %p, key: <%" PRIx64 ", %#x>, "
    				"total_size: %u, frag_size: %u, last_idx: %u\n"
    				"first fragment: ofs: %u, len: %u\n"
    				"last fragment: ofs: %u, len: %u\n\n",
    				__func__, __LINE__,
    				fp, fp->key.src_dst[0], fp->key.id,
    				fp->total_size, fp->frag_size, fp->last_idx,
    				fp->frags[IP_FIRST_FRAG_IDX].ofs,
    				fp->frags[IP_FIRST_FRAG_IDX].len,
    				fp->frags[IP_LAST_FRAG_IDX].ofs,
    				fp->frags[IP_LAST_FRAG_IDX].len);
    		else
    			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
    				"ipv6_frag_pkt: %p, key: <" IPv6_KEY_BYTES_FMT ", %#x>, "
    				"total_size: %u, frag_size: %u, last_idx: %u\n"
    				"first fragment: ofs: %u, len: %u\n"
    				"last fragment: ofs: %u, len: %u\n\n",
    				__func__, __LINE__,
    				fp, IPv6_KEY_BYTES(fp->key.src_dst), fp->key.id,
    				fp->total_size, fp->frag_size, fp->last_idx,
    				fp->frags[IP_FIRST_FRAG_IDX].ofs,
    				fp->frags[IP_FIRST_FRAG_IDX].len,
    				fp->frags[IP_LAST_FRAG_IDX].ofs,
    				fp->frags[IP_LAST_FRAG_IDX].len);

    		/* free associated resources. */
    		ip_frag_free(fp, dr);
        }
        /* we are done with that entry, invalidate it. */
        ip_frag_key_invalidate(&fp->key);
	}

	return cnt;
}

/*
 * Process new mbuf with fragment of IPV4 packet.
 * Priority returns the first package, after which
 * the package performs a disorderly or sequential
 * virtual reassemble based on the flag.
 * @param tbl
 *   Table where to lookup/add the fragmented packet.
 * @param mb
 *   Incoming mbuf with IPV4 fragment.
 * @param tms
 *   Fragment arrival timestamp.
 * @param ip_hdr
 *   Pointer to the IPV4 header inside the fragment.
 * @param mb_out
 *   Host the virtual reassemble packages.
 * @param flag
 *   Indicates disorder or sequential reassemble.
 *   0: disorder
 *   1: sequential
 *   other: sequential full
 * @return
 *   >0: the number of virtual reassemble packages.
 *   0: no packages were returned, but that doesn't
 *      mean there was an error.
 *   -1: an error occurred.
 */
int
rte_ipv4_frag_reassemble_virt(struct rte_ip_frag_tbl *tbl,
	struct rte_ip_frag_death_row *dr, struct rte_mbuf *mb, uint64_t tms,
	struct rte_ipv4_hdr *ip_hdr, struct rte_mbuf **mb_out, uint8_t flag)
{
	struct ip_frag_pkt *fp;
	struct ip_frag_key key;
	const unaligned_uint64_t *psd;
	uint16_t flag_offset, ip_ofs, ip_flag;
	int32_t ip_len;
	int32_t trim;

	flag_offset = rte_be_to_cpu_16(ip_hdr->fragment_offset);
	ip_ofs = (uint16_t)(flag_offset & RTE_IPV4_HDR_OFFSET_MASK);
	ip_flag = (uint16_t)(flag_offset & RTE_IPV4_HDR_MF_FLAG);

	psd = (unaligned_uint64_t *)&ip_hdr->src_addr;
	/* use first 8 bytes only */
	key.src_dst[0] = psd[0];
	key.id = ip_hdr->packet_id;
	key.key_len = IPV4_KEYLEN;

	ip_ofs *= RTE_IPV4_HDR_OFFSET_UNITS;
	ip_len = rte_be_to_cpu_16(ip_hdr->total_length) - mb->l3_len;
	trim = mb->pkt_len - (ip_len + mb->l3_len + mb->l2_len);

	IP_FRAG_LOG(DEBUG, "%s:%d:\n"
		"mbuf: %p, tms: %" PRIu64 ", key: <%" PRIx64 ", %#x>"
		"ofs: %u, len: %d, padding: %d, flags: %#x\n"
		"tbl: %p, max_cycles: %" PRIu64 ", entry_mask: %#x, "
		"max_entries: %u, use_entries: %u\n\n",
		__func__, __LINE__,
		mb, tms, key.src_dst[0], key.id, ip_ofs, ip_len, trim, ip_flag,
		tbl, tbl->max_cycles, tbl->entry_mask, tbl->max_entries,
		tbl->use_entries);

	/* check that fragment length is greater then zero. */
	if (ip_len <= 0) {
		IP_FRAG_MBUF2DR(dr, mb);
		return -1;
	}

	if (unlikely(trim > 0))
		rte_pktmbuf_trim(mb, trim);

	/* try to find/add entry into the fragment's table. */
	if ((fp = ip_frag_find(tbl, dr, &key, tms)) == NULL) {
		IP_FRAG_MBUF2DR(dr, mb);
		return -1;
	}

	IP_FRAG_LOG(DEBUG, "%s:%d:\n"
		"tbl: %p, max_entries: %u, use_entries: %u\n"
		"ipv4_frag_pkt: %p, key: <%" PRIx64 ", %#x>, start: %" PRIu64
		", total_size: %u, frag_size: %u, last_idx: %u\n\n",
		__func__, __LINE__,
		tbl, tbl->max_entries, tbl->use_entries,
		fp, fp->key.src_dst[0], fp->key.id, fp->start,
		fp->total_size, fp->frag_size, fp->last_idx);


	/* process the fragmented packet. */
	int cnt = ip_frag_process_virt(fp, dr, mb, ip_ofs, ip_len, ip_flag, mb_out, flag);
	ip_frag_inuse(tbl, fp);

	IP_FRAG_LOG(DEBUG, "%s:%d:\n"
		"mbuf: %p\n"
		"tbl: %p, max_entries: %u, use_entries: %u\n"
		"ipv4_frag_pkt: %p, key: <%" PRIx64 ", %#x>, start: %" PRIu64
		", total_size: %u, frag_size: %u, last_idx: %u, cnt: %d\n\n",
		__func__, __LINE__, mb,
		tbl, tbl->max_entries, tbl->use_entries,
		fp, fp->key.src_dst[0], fp->key.id, fp->start,
		fp->total_size, fp->frag_size, fp->last_idx, cnt);

	return cnt;
}

/*
 * Process new mbuf with fragment of IPV6 datagram.
 * Priority returns the first package, after which
 * the package performs a disorderly or sequential
 * virtual reassemble based on the flag.
 * @param tbl
 *   Table where to lookup/add the fragmented packet.
 * @param mb
 *   Incoming mbuf with IPV6 fragment.
 * @param tms
 *   Fragment arrival timestamp.
 * @param ip_hdr
 *   Pointer to the IPV6 header.
 * @param frag_hdr
 *   Pointer to the IPV6 fragment extension header.
 * @param mb_out
 *   Host the virtual reassemble packages.
 * @param flag
 *   Indicates disorder or sequential reassemble.
 *   0: disorder
 *   1: sequential
 *   other: sequential full
 * @return
 *   >0: the number of virtual reassemble packages.
 *   0: no packages were returned, but that doesn't
 *      mean there was an error.
 *   -1: an error occurred.
 */
#define MORE_FRAGS(x) (((x) & 0x100) >> 8)
#define FRAG_OFFSET(x) (rte_cpu_to_be_16(x) >> 3)
int
rte_ipv6_frag_reassemble_virt(struct rte_ip_frag_tbl *tbl,
	struct rte_ip_frag_death_row *dr, struct rte_mbuf *mb, uint64_t tms,
	struct rte_ipv6_hdr *ip_hdr, struct ipv6_extension_fragment *frag_hdr,
	struct rte_mbuf **mb_out, uint8_t flag)
{
	struct ip_frag_pkt *fp;
	struct ip_frag_key key;
	uint16_t ip_ofs;
	int32_t ip_len;
	int32_t trim;

	rte_memcpy(&key.src_dst[0], ip_hdr->src_addr, 16);
	rte_memcpy(&key.src_dst[2], ip_hdr->dst_addr, 16);

	key.id = frag_hdr->id;
	key.key_len = IPV6_KEYLEN;

	ip_ofs = FRAG_OFFSET(frag_hdr->frag_data) * 8;

	/*
	 * as per RFC2460, payload length contains all extension headers
	 * as well.
	 * since we don't support anything but frag headers,
	 * this is what we remove from the payload len.
	 */
	ip_len = rte_be_to_cpu_16(ip_hdr->payload_len) - sizeof(*frag_hdr);
	trim = mb->pkt_len - (ip_len + mb->l3_len + mb->l2_len);

	IP_FRAG_LOG(DEBUG, "%s:%d:\n"
		"mbuf: %p, tms: %" PRIu64
		", key: <" IPv6_KEY_BYTES_FMT ", %#x>, "
		"ofs: %u, len: %d, padding: %d, flags: %#x\n"
		"tbl: %p, max_cycles: %" PRIu64 ", entry_mask: %#x, "
		"max_entries: %u, use_entries: %u\n\n",
		__func__, __LINE__,
		mb, tms, IPv6_KEY_BYTES(key.src_dst), key.id, ip_ofs, ip_len,
		trim, RTE_IPV6_GET_MF(frag_hdr->frag_data),
		tbl, tbl->max_cycles, tbl->entry_mask, tbl->max_entries,
		tbl->use_entries);

	/* check that fragment length is greater then zero. */
	if (ip_len <= 0) {
		IP_FRAG_MBUF2DR(dr, mb);
		return -1;
	}

	if (unlikely(trim > 0))
		rte_pktmbuf_trim(mb, trim);

	/* try to find/add entry into the fragment's table. */
	fp = ip_frag_find(tbl, dr, &key, tms);
	if (fp == NULL) {
		IP_FRAG_MBUF2DR(dr, mb);
		return -1;
	}

	IP_FRAG_LOG(DEBUG, "%s:%d:\n"
		"tbl: %p, max_entries: %u, use_entries: %u\n"
		"ipv6_frag_pkt: %p, key: <" IPv6_KEY_BYTES_FMT ", %#x>, start: %" PRIu64
		", total_size: %u, frag_size: %u, last_idx: %u\n\n",
		__func__, __LINE__,
		tbl, tbl->max_entries, tbl->use_entries,
		fp, IPv6_KEY_BYTES(fp->key.src_dst), fp->key.id, fp->start,
		fp->total_size, fp->frag_size, fp->last_idx);


	/* process the fragmented packet. */
	int cnt = ip_frag_process_virt(fp, dr, mb, ip_ofs, ip_len,
	    MORE_FRAGS(frag_hdr->frag_data), mb_out, flag);
	ip_frag_inuse(tbl, fp);

	IP_FRAG_LOG(DEBUG, "%s:%d:\n"
		"mbuf: %p\n"
		"tbl: %p, max_entries: %u, use_entries: %u\n"
		"ipv6_frag_pkt: %p, key: <" IPv6_KEY_BYTES_FMT ", %#x>, start: %" PRIu64
		", total_size: %u, frag_size: %u, last_idx: %u, cnt: %d\n\n",
		__func__, __LINE__, mb,
		tbl, tbl->max_entries, tbl->use_entries,
		fp, IPv6_KEY_BYTES(fp->key.src_dst), fp->key.id, fp->start,
		fp->total_size, fp->frag_size, fp->last_idx, cnt);

	return cnt;
}
