/*
 * Copyright (c) 2006 - 2009 Mellanox Technology Inc.  All rights reserved.
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
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef IB_SRPT_H
#define IB_SRPT_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_cm.h>

#include <scsi/srp.h>

#include <scst.h>

#include "ib_dm_mad.h"

/*
 * The prefix the ServiceName field of the ServiceName/ServiceID pair in the
 * device management ServiceEntries attribute pair must start with, as specified
 * in the SRP r16a document.
 */
#define SRP_SERVICE_NAME_PREFIX		"SRP.T10:"

enum {
	/*
	 * SRP IOControllerProfile attributes for SRP target ports that have
	 * not been defined in <scsi/srp.h>. Source: section B.7, table B.7
	 * in the T10 SRP r16a document.
	 */
	SRP_PROTOCOL = 0x0108,
	SRP_PROTOCOL_VERSION = 0x0001,
	SRP_IO_SUBCLASS = 0x609e,
	SRP_SEND_TO_IOC = 0x01,
	SRP_SEND_FROM_IOC = 0x02,
	SRP_RDMA_READ_FROM_IOC = 0x08,
	SRP_RDMA_WRITE_FROM_IOC = 0x20,

	/* See also table 24 in the T10 r16a document. */
	SRP_TSK_MGMT_SUCCESS = 0x00,
	SRP_TSK_MGMT_FUNC_NOT_SUPP = 0x04,
	SRP_TSK_MGMT_FAILED = 0x05,

	/* See also table 21 in the T10 r16a document. */
	SRP_CMD_SIMPLE_Q = 0x0,
	SRP_CMD_HEAD_OF_Q = 0x1,
	SRP_CMD_ORDERED_Q = 0x2,
	SRP_CMD_ACA = 0x4,

	SRP_LOGIN_RSP_MULTICHAN_NO_CHAN = 0x0,
	SRP_LOGIN_RSP_MULTICHAN_TERMINATED = 0x1,
	SRP_LOGIN_RSP_MULTICHAN_MAINTAINED = 0x2,

	SRPT_DEF_SG_TABLESIZE = 128,
	SRPT_DEF_SG_PER_WQE = 16,

	SRPT_SQ_SIZE = 128 * SRPT_DEF_SG_PER_WQE,
	SRPT_RQ_SIZE = 128,
	SRPT_SRQ_SIZE = 4095,

	MAX_MESSAGE_SIZE = 996,
	MAX_RDMA_SIZE = 65536
};

#define SRPT_OP_RECV			(1 << 31)

struct rdma_iu {
	u64 raddr;
	u32 rkey;
	struct ib_sge *sge;
	u32 sge_cnt;
	int mem_id;
};

/* Command states. */
enum srpt_command_state {
	/* New command arrived and is being processed. */
	SRPT_STATE_NEW = 0,
	/* Processing a write or bidir command and waiting for data arrival. */
	SRPT_STATE_NEED_DATA = 1,
	/* Data for the write or bidir command arrived and is being processed.*/
	SRPT_STATE_DATA_IN = 2,
	/* Command processing finished. */
	SRPT_STATE_PROCESSED = 3,
	/* Command processing has been aborted. */
	SRPT_STATE_ABORTED = 4,
};

/* SRPT I/O context: SRPT-private data associated with a struct scst_cmd. */
struct srpt_ioctx {
	int index;
	void *buf;
	dma_addr_t dma;
	struct rdma_iu *rdma_ius;
	struct srp_direct_buf *rbufs;
	struct srp_direct_buf single_rbuf;
	/* Node for insertion in srpt_rdma_ch::cmd_wait_list. */
	struct list_head wait_list;
	/* Node for insertion in srpt_rdma_ch::active_scmnd_list. */
	struct list_head scmnd_list;
	u16 n_rdma_ius;
	u8 n_rdma;
	u8 n_rbuf;

	enum ib_wc_opcode op;
	/* Node for insertion in the srpt_thread::thread_ioctx_list. */
	struct list_head comp_list;
	struct srpt_rdma_ch *ch;
	struct scst_cmd *scmnd;
	u64 data_len;
	enum srpt_command_state state;
};

/* Additional context information for SCST management commands. */
struct srpt_mgmt_ioctx {
	struct srpt_ioctx *ioctx;
	struct srpt_rdma_ch *ch;
	u64 tag;
};

/* channel state */
enum rdma_ch_state {
	RDMA_CHANNEL_CONNECTING,
	RDMA_CHANNEL_LIVE,
	RDMA_CHANNEL_DISCONNECTING
};

struct srpt_rdma_ch {
	struct ib_cm_id *cm_id;
	struct ib_qp *qp;
	struct ib_cq *cq;
	struct srpt_port *sport;
	/* 128-bit initiator port identifier copied from SRP_LOGIN_REQ. */
	u8 i_port_id[16];
	/* 128-bit target port identifier copied from SRP_LOGIN_REQ. */
	u8 t_port_id[16];
	atomic_t req_lim_delta;
	spinlock_t spinlock;
	enum rdma_ch_state state;
	/* Node for insertion in the srpt_device::rch_list list. */
	struct list_head list;
	/* List of waiting SCST commands (containt struct srpt_ioctx elem's). */
	struct list_head cmd_wait_list;
	/* SCST commands being processed (contains struct srpt_ioctx elem's). */
	struct list_head active_scmnd_list;
	u32 active_scmnd_cnt;

	struct scst_session *scst_sess;
	u8 sess_name[36];
};

struct srpt_port {
	struct srpt_device *sdev;
	struct ib_mad_agent *mad_agent;
	/* One-based port number. */
	u8 port;
	/* Cached values of the port's sm_lid, lid and gid. */
	u16 sm_lid;
	u16 lid;
	union ib_gid gid;
	/* Work structure for refreshing the aforementioned cached values. */
	struct work_struct work;
};

/*
 * Data stored by the ib_srpt kernel module per InfiniBand device
 * (struct ib_device).
 */
struct srpt_device {
	/* Backpointer to the struct ib_device managed by the IB core. */
	struct ib_device *device;
	/* Protection domain. */
	struct ib_pd *pd;
	/* L_Key (local key) with write access to all local memory. */
	struct ib_mr *mr;
	/* SRQ (shared receive queue). */
	struct ib_srq *srq;
	/* Connection identifier. */
	struct ib_cm_id *cm_id;
	/*
	 * Attributes of the InfiniBand device as obtained during the
	 * ib_client::add() callback.
	 */
	struct ib_device_attr dev_attr;
	struct srpt_ioctx *ioctx_ring[SRPT_SRQ_SIZE];
	/*
	 * List node for insertion in the srpt_rdma_ch::list list.
	 * This list is protected by srpt_device::spinlock.
	 */
	struct list_head rch_list;
	spinlock_t spinlock;
	struct srpt_port port[2];
	struct ib_event_handler event_handler;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	/* per-port srpt-<portname> device instance. */
	struct class_device class_dev;
#else
	struct device dev;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	char init_name[20];
#endif

	struct scst_tgt *scst_tgt;
};

/* sense code/qualifier pairs */
enum {
	NO_ADD_SENSE = 0x00,
	LUN_NOT_READY = 0x04,
	INVALID_CDB = 0x24,
	INTERNAL_TARGET_FAILURE = 0x44
};

struct sense_data {
	u8 err_code;
	u8 segment_number;
	u8 key;
	u8 info_bytes[4];
	u8 addl_sense_len;
	u8 cmd_info_bytes[4];
	u8 addl_sense_code;
	u8 addl_sense_code_qual;
	u16 asc_ascq;
	u8 fru_code;
	u8 sense_bytes[3];
};

#endif				/* IB_SRPT_H */
