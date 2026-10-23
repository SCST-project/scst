// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MD5 Message Digest Algorithm (RFC1321).
 *
 * Derived from cryptoapi implementation, originally based on the
 * public domain implementation written by Colin Plumb in 1993.
 *
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include "md5.h"

/* MD5 transforms */
static inline u32 md5_f1(u32 x, u32 y, u32 z)
{
	return z ^ (x & (y ^ z));
}

static inline u32 md5_f2(u32 x, u32 y, u32 z)
{
	return md5_f1(z, x, y);
}

static inline u32 md5_f3(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

static inline u32 md5_f4(u32 x, u32 y, u32 z)
{
	return y ^ (x | ~z);
}

static inline u32 md5_step(u32 w, u32 f, u32 x, u32 i, u32 k, unsigned int s)
{
	w += f + i + k;
	return ((w << s) | (w >> (32 - s))) + x;
}

static void __md5_transform(u32 hash[MD5_DIGEST_WORDS],
			    const u32 in[MD5_BLOCK_WORDS])
{
	register u32 a, b, c, d;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];

	a = md5_step(a, md5_f1(b, c, d), b, in[0], 0xD76AA478UL, 7);
	d = md5_step(d, md5_f1(a, b, c), a, in[1], 0xE8C7B756UL, 12);
	c = md5_step(c, md5_f1(d, a, b), d, in[2], 0x242070DBUL, 17);
	b = md5_step(b, md5_f1(c, d, a), c, in[3], 0xC1BDCEEEUL, 22);
	a = md5_step(a, md5_f1(b, c, d), b, in[4], 0xF57C0FAFUL, 7);
	d = md5_step(d, md5_f1(a, b, c), a, in[5], 0x4787C62AUL, 12);
	c = md5_step(c, md5_f1(d, a, b), d, in[6], 0xA8304613UL, 17);
	b = md5_step(b, md5_f1(c, d, a), c, in[7], 0xFD469501UL, 22);
	a = md5_step(a, md5_f1(b, c, d), b, in[8], 0x698098D8UL, 7);
	d = md5_step(d, md5_f1(a, b, c), a, in[9], 0x8B44F7AFUL, 12);
	c = md5_step(c, md5_f1(d, a, b), d, in[10], 0xFFFF5BB1UL, 17);
	b = md5_step(b, md5_f1(c, d, a), c, in[11], 0x895CD7BEUL, 22);
	a = md5_step(a, md5_f1(b, c, d), b, in[12], 0x6B901122UL, 7);
	d = md5_step(d, md5_f1(a, b, c), a, in[13], 0xFD987193UL, 12);
	c = md5_step(c, md5_f1(d, a, b), d, in[14], 0xA679438EUL, 17);
	b = md5_step(b, md5_f1(c, d, a), c, in[15], 0x49B40821UL, 22);

	a = md5_step(a, md5_f2(b, c, d), b, in[1], 0xF61E2562UL, 5);
	d = md5_step(d, md5_f2(a, b, c), a, in[6], 0xC040B340UL, 9);
	c = md5_step(c, md5_f2(d, a, b), d, in[11], 0x265E5A51UL, 14);
	b = md5_step(b, md5_f2(c, d, a), c, in[0], 0xE9B6C7AAUL, 20);
	a = md5_step(a, md5_f2(b, c, d), b, in[5], 0xD62F105DUL, 5);
	d = md5_step(d, md5_f2(a, b, c), a, in[10], 0x02441453UL, 9);
	c = md5_step(c, md5_f2(d, a, b), d, in[15], 0xD8A1E681UL, 14);
	b = md5_step(b, md5_f2(c, d, a), c, in[4], 0xE7D3FBC8UL, 20);
	a = md5_step(a, md5_f2(b, c, d), b, in[9], 0x21E1CDE6UL, 5);
	d = md5_step(d, md5_f2(a, b, c), a, in[14], 0xC33707D6UL, 9);
	c = md5_step(c, md5_f2(d, a, b), d, in[3], 0xF4D50D87UL, 14);
	b = md5_step(b, md5_f2(c, d, a), c, in[8], 0x455A14EDUL, 20);
	a = md5_step(a, md5_f2(b, c, d), b, in[13], 0xA9E3E905UL, 5);
	d = md5_step(d, md5_f2(a, b, c), a, in[2], 0xFCEFA3F8UL, 9);
	c = md5_step(c, md5_f2(d, a, b), d, in[7], 0x676F02D9UL, 14);
	b = md5_step(b, md5_f2(c, d, a), c, in[12], 0x8D2A4C8AUL, 20);

	a = md5_step(a, md5_f3(b, c, d), b, in[5], 0xFFFA3942UL, 4);
	d = md5_step(d, md5_f3(a, b, c), a, in[8], 0x8771F681UL, 11);
	c = md5_step(c, md5_f3(d, a, b), d, in[11], 0x6D9D6122UL, 16);
	b = md5_step(b, md5_f3(c, d, a), c, in[14], 0xFDE5380CUL, 23);
	a = md5_step(a, md5_f3(b, c, d), b, in[1], 0xA4BEEA44UL, 4);
	d = md5_step(d, md5_f3(a, b, c), a, in[4], 0x4BDECFA9UL, 11);
	c = md5_step(c, md5_f3(d, a, b), d, in[7], 0xF6BB4B60UL, 16);
	b = md5_step(b, md5_f3(c, d, a), c, in[10], 0xBEBFBC70UL, 23);
	a = md5_step(a, md5_f3(b, c, d), b, in[13], 0x289B7EC6UL, 4);
	d = md5_step(d, md5_f3(a, b, c), a, in[0], 0xEAA127FAUL, 11);
	c = md5_step(c, md5_f3(d, a, b), d, in[3], 0xD4EF3085UL, 16);
	b = md5_step(b, md5_f3(c, d, a), c, in[6], 0x04881D05UL, 23);
	a = md5_step(a, md5_f3(b, c, d), b, in[9], 0xD9D4D039UL, 4);
	d = md5_step(d, md5_f3(a, b, c), a, in[12], 0xE6DB99E5UL, 11);
	c = md5_step(c, md5_f3(d, a, b), d, in[15], 0x1FA27CF8UL, 16);
	b = md5_step(b, md5_f3(c, d, a), c, in[2], 0xC4AC5665UL, 23);

	a = md5_step(a, md5_f4(b, c, d), b, in[0], 0xF4292244UL, 6);
	d = md5_step(d, md5_f4(a, b, c), a, in[7], 0x432AFF97UL, 10);
	c = md5_step(c, md5_f4(d, a, b), d, in[14], 0xAB9423A7UL, 15);
	b = md5_step(b, md5_f4(c, d, a), c, in[5], 0xFC93A039UL, 21);
	a = md5_step(a, md5_f4(b, c, d), b, in[12], 0x655B59C3UL, 6);
	d = md5_step(d, md5_f4(a, b, c), a, in[3], 0x8F0CCC92UL, 10);
	c = md5_step(c, md5_f4(d, a, b), d, in[10], 0xFFEFF47DUL, 15);
	b = md5_step(b, md5_f4(c, d, a), c, in[1], 0x85845DD1UL, 21);
	a = md5_step(a, md5_f4(b, c, d), b, in[8], 0x6FA87E4FUL, 6);
	d = md5_step(d, md5_f4(a, b, c), a, in[15], 0xFE2CE6E0UL, 10);
	c = md5_step(c, md5_f4(d, a, b), d, in[6], 0xA3014314UL, 15);
	b = md5_step(b, md5_f4(c, d, a), c, in[13], 0x4E0811A1UL, 21);
	a = md5_step(a, md5_f4(b, c, d), b, in[4], 0xF7537E82UL, 6);
	d = md5_step(d, md5_f4(a, b, c), a, in[11], 0xBD3AF235UL, 10);
	c = md5_step(c, md5_f4(d, a, b), d, in[2], 0x2AD7D2BBUL, 15);
	b = md5_step(b, md5_f4(c, d, a), c, in[9], 0xEB86D391UL, 21);

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

static inline void md5_transform(u32 digest[MD5_DIGEST_WORDS],
				 u32 block[MD5_BLOCK_WORDS])
{
	int i;

	for (i = 0; i < MD5_BLOCK_WORDS; i++)
		block[i] = cpu_to_le32(block[i]);

	__md5_transform(digest, block);
}

void md5_init(struct md5_ctx *ctx)
{
	ctx->digest[0] = 0x67452301UL;
	ctx->digest[1] = 0xEFCDAB89UL;
	ctx->digest[2] = 0x98BADCFEUL;
	ctx->digest[3] = 0x10325476UL;

	ctx->count = 0;
}

void md5_update(struct md5_ctx *ctx, const void *data_in, size_t len)
{
	const size_t offset = ctx->count & 0x3f;
	const size_t avail = MD5_BLOCK_BYTES - offset;
	const u8 *data = data_in;

	ctx->count += len;

	if (avail > len) {
		memcpy((u8 *)ctx->block + offset, data, len);
		return;
	}

	memcpy((u8 *)ctx->block + offset, data, avail);
	md5_transform(ctx->digest, ctx->block);
	data += avail;
	len -= avail;

	while (len >= MD5_BLOCK_BYTES) {
		memcpy(ctx->block, data, MD5_BLOCK_BYTES);
		md5_transform(ctx->digest, ctx->block);
		data += MD5_BLOCK_BYTES;
		len -= MD5_BLOCK_BYTES;
	}

	if (len)
		memcpy(ctx->block, data, len);
}

void md5_final(struct md5_ctx *ctx, u8 *out)
{
	const size_t offset = ctx->count & 0x3f;
	char *p = (char *)ctx->block + offset;
	int padding = (MD5_BLOCK_BYTES - MD5_COUNTER_BYTES) - (offset + 1);
	int i;

	*p++ = 0x80;

	if (padding < 0) {
		memset(p, 0, (padding + MD5_COUNTER_BYTES));
		md5_transform(ctx->digest, ctx->block);
		p = (char *)ctx->block;
		padding = (MD5_BLOCK_BYTES - MD5_COUNTER_BYTES);
	}

	memset(p, 0, padding);

	/* 64-bit bit counter stored in LSW/LSB format */
	ctx->block[14] = cpu_to_le32(ctx->count << 3);
	ctx->block[15] = cpu_to_le32(ctx->count >> 29);

	md5_transform(ctx->digest, ctx->block);

	for (i = 0; i < MD5_DIGEST_WORDS; i++)
		ctx->digest[i] = le32_to_cpu(ctx->digest[i]);

	memcpy(out, ctx->digest, MD5_DIGEST_BYTES);
	memset(ctx, 0, sizeof(*ctx));
}

