#ifndef __ISER_HDR_H__
#define __ISER_HDR_H__

#include "iscsi.h"

#define ISCSI_LOGIN_MAX_RDSL      (8 * 1024)

struct isert_hdr {
	u8	flags;
	u8	rsvd[3];
	__be32	write_stag; /* write rkey */
	__be64	write_va;
	__be32	read_stag;  /* read rkey */
	__be64	read_va;
} __packed;

#define ISER_WSV		0x08
#define ISER_RSV		0x04

#define ISER_ISCSI_CTRL		0x10
#define ISER_HELLO		0x20
#define ISER_HELLORPLY		0x30

#define ISER_HDRS_SZ		(sizeof(struct isert_hdr) + sizeof(struct iscsi_hdr))

#endif

