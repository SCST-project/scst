/*
 * This is the header file for the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 *
 * Changed so as no longer to depend on Colin Plumb's `usual.h'
 * header definitions; now uses stuff from dpkg's config.h
 *  - Ian Jackson <ijackson@nyx.cs.du.edu>.
 * Still in the public domain.
 */

#ifndef MD5_H
#define MD5_H

#include "types.h"
#include <string.h>

#define MD5_BLOCK_WORDS		16
#define MD5_BLOCK_BYTES		(MD5_BLOCK_WORDS * 4)
#define MD5_DIGEST_WORDS	4
#define MD5_DIGEST_BYTES	(MD5_DIGEST_WORDS * 4)
#define MD5_COUNTER_BYTES	8

struct md5_ctx {
	u32 block[MD5_BLOCK_WORDS];
	u32 digest[MD5_DIGEST_WORDS];
	u64 count;
};

void md5_init(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, const void *data_in, size_t len);
void md5_final(struct md5_ctx *ctx, u8 *out);

#endif /* !MD5_H */
