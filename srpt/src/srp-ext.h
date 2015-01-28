/*
 * Extensions to the SRPr16a protocol
 *
 * Copyright (C) 2013 Fusion-io, Inc. All rights reserved.
 */

#ifndef _SRP_EXT_H_
#define _SRP_EXT_H_

/*
 * Data is present as immediate data instead of being referred to via a
 * descriptor.
 */
enum { SRP_DATA_DESC_IMM = 3 };
enum { SRP_BUF_FORMAT_IMM = 1 << 3 };

struct srp_imm_buf {
	__be32	len;
	__be32	offset;
};

#endif /* _SRP_EXT_H_ */
