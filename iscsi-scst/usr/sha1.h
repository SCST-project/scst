/*
 * Common values for SHA algorithms
 */

#ifndef SHA1_H
#define SHA1_H

#include "types.h"
#include <string.h>

#define SHA1_DIGEST_WORDS	5
#define SHA1_DIGEST_BYTES	(SHA1_DIGEST_WORDS * 4)
#define SHA1_BLOCK_WORDS	16
#define SHA1_BLOCK_BYTES	(SHA1_BLOCK_WORDS * 4)
#define SHA1_WORKSPACE_WORDS	80
#define SHA1_COUNTER_BYTES	8

struct sha1_ctx {
	u32 digest[SHA1_DIGEST_WORDS];
	u32 block[SHA1_BLOCK_WORDS];
	u64 count;
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const void *data_in, size_t len);
void sha1_final(struct sha1_ctx *ctx, u8 *out);

#endif
