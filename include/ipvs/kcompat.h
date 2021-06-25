/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __KCOMPAT_H__
#define __KCOMPAT_H__

#include <linux/types.h>

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE (8)
#endif

#ifndef BITS_PER_TYPE
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d)  (((n) + (d) - 1) / (d))
#endif

#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#endif

#ifndef BITOP_WORD
#define BITOP_WORD(nr)		((nr) / __BITS_PER_LONG)
#endif

/**
 * taken from definition in include/linux/kernel.h
 *
 * swap - swap values of @a and @b
 * @a: first value
 * @b: second value
 */
#define swap(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
inline unsigned long __ffs(unsigned long word);

#ifndef ffz
#define ffz(x)  __ffs(~(x))
#endif

/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
inline int ffls(unsigned int x);

/**
 * taken from definition in include/linux/gcd.h
 */
unsigned long gcd(unsigned long a, unsigned long b) __attribute__((const));

/**
 * taken from definition in include/linux/bits.h
 */
#define BIT_MASK(nr) (1UL << ((nr) % __BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / __BITS_PER_LONG)

/**
 * taken from definition in tools/include/asm-generic/bitops/non-atomic.h
 *
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void
__set_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

    *p |= mask;
}

/**
 * taken from definition in tools/include/asm-generic/bitops/non-atomic.h
 *
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int 
test_bit(int nr, const unsigned long *addr)
{
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (__BITS_PER_LONG - 1)));
}

static inline void
clear_bit(unsigned long nr, void *addr)
{
	int *m = ((int *)addr) + (nr >> 5);
	*m &= ~(1 << (nr & 31));
}

#ifndef find_next_zero_bit
/*
 * This implementation of find_{first,next}_zero_bit was stolen from
 * Linus' asm-alpha/bitops.h.
 */
static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(__BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= __BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (__BITS_PER_LONG - offset);
		if (size < __BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= __BITS_PER_LONG;
		result += __BITS_PER_LONG;
	}
	while (size & ~(__BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found_middle;
		result += __BITS_PER_LONG;
		size -= __BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found_middle:
	return result + ffz(tmp);
}
#endif

#define find_first_zero_bit(addr, size) find_next_zero_bit((addr), (size), 0)

#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)

#ifndef find_next_bit

static inline unsigned long
find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(__BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= __BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < __BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= __BITS_PER_LONG;
		result += __BITS_PER_LONG;
	}
	while (size & ~(__BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += __BITS_PER_LONG;
		size -= __BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp &= (~0UL >> (__BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}
#endif 

#ifndef for_each_set_bit_from
/* same as for_each_set_bit() but use bit as value to start with */
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#endif 

#ifndef small_const_nbits
#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= __BITS_PER_LONG)

#endif

#ifndef BITMAP_LAST_WORD_MASK
#define BITMAP_LAST_WORD_MASK(nbits)					\
(									\
	((nbits) % __BITS_PER_LONG) ?					\
		(1UL<<((nbits) % __BITS_PER_LONG))-1 : ~0UL		\
)
#endif

#ifndef bitmap_zero
static inline void bitmap_zero(unsigned long *dst, int nbits)
{
	if (small_const_nbits(nbits))
		*dst = 0UL;
	else {
		int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
		memset(dst, 0, len);
	}
}
#endif

#ifndef __bitmap_empty
static inline int __bitmap_empty(const unsigned long *bitmap, int bits)
{
	int k, lim = bits/__BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bitmap[k])
			return 0;

	if (bits % __BITS_PER_LONG)
		if (bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
			return 0;

	return 1;
}
#endif

#ifndef bitmap_empty
static inline int bitmap_empty(const unsigned long *src, int nbits)
{
	if (small_const_nbits(nbits))
		return ! (*src & BITMAP_LAST_WORD_MASK(nbits));
	else
		return __bitmap_empty(src, nbits);
}
#endif

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))


#endif /* __KCOMPAT_H__ */

