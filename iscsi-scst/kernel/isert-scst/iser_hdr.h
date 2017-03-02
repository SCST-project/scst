/*
 * This file is part of iser target kernel module.
 *
 * Copyright (c) 2013 - 2014 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2013 - 2014 Yan Burman (yanb@mellanox.com)
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *            - Redistributions of source code must retain the above
 *              copyright notice, this list of conditions and the following
 *              disclaimer.
 *
 *            - Redistributions in binary form must reproduce the above
 *              copyright notice, this list of conditions and the following
 *              disclaimer in the documentation and/or other materials
 *              provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __ISER_HDR_H__
#define __ISER_HDR_H__

#include "../iscsi.h"

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

#define ISER_MAX_LOGIN_RDSL	(ISCSI_LOGIN_MAX_RDSL + ISER_HDRS_SZ)

#define ISER_ZBVA_NOT_SUPPORTED         0x80
#define ISER_SEND_W_INV_NOT_SUPPORTED   0x40

struct isert_cm_hdr {
	u8	flags;
	u8	rsvd[3];
} __packed;

#endif

