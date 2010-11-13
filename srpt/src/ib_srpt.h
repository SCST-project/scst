/*
 * Copyright (c) 2006 - 2009 Mellanox Technology Inc.  All rights reserved.
 * Copyright (C) 2009 - 2010 Bart Van Assche <bart.vanassche@gmail.com>
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

#include <rdma/ib_verbs.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_cm.h>

#include <scsi/srp.h>

#if defined(INSIDE_KERNEL_TREE)
#include <scst/scst.h>
#else
#include <scst.h>
#endif

#include "ib_dm_mad.h"

/*
 * The prefix the ServiceName field must start with in the device management
 * ServiceEntries attribute pair. See also the SRP r16a document.
 */
#define SRP_SERVICE_NAME_PREFIX		"SRP.T10:"

enum {
	/*
	 * SRP IOControllerProfile attributes for SRP target ports that have
	 * not been defined in <scsi/srp.h>. Source: section B.7, table B.7
	 * in the SRP r16a document.
	 */
	SRP_PROTOCOL = 0x0108,
	SRP_PROTOCOL_VERSION = 0x0001,
	SRP_IO_SUBCLASS = 0x609e,
	SRP_SEND_TO_IOC = 0x01,
	SRP_SEND_FROM_IOC = 0x02,
	SRP_RDMA_READ_FROM_IOC = 0x08,
	SRP_RDMA_WRITE_FROM_IOC = 0x20,

	/*
	 * srp_login_cmd.req_flags bitmasks. See also table 9 in the SRP r16a
	 * document.
	 */
	SRP_MTCH_ACTION = 0x03, /* MULTI-CHANNEL ACTION */
	SRP_LOSOLNT = 0x10, /* logout solicited notification */
	SRP_CRSOLNT = 0x20, /* credit request solicited notification */
	SRP_AESOLNT = 0x40, /* asynchronous event solicited notification */

	/*
	 * srp_cmd.sol_nt / srp_tsk_mgmt.sol_not bitmasks. See also tables
	 * 18 and 20 in the T10 r16a document.
	 */
	SRP_SCSOLNT = 0x02, /* SCSOLNT = successful solicited notification */
	SRP_UCSOLNT = 0x04, /* UCSOLNT = unsuccessful solicited notification */

	/*
	 * srp_rsp.sol_not / srp_t_logout.sol_not bitmasks. See also tables
	 * 16 and 22 in the T10 r16a document.
	 */
	SRP_SOLNT = 0x01, /* SOLNT = solicited notification */

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

	MIN_SRPT_SQ_SIZE = 16,
	DEF_SRPT_SQ_SIZE = 4096,
	SRPT_RQ_SIZE = 128,
	MIN_SRPT_SRQ_SIZE = 4,
	DEFAULT_SRPT_SRQ_SIZE = 4095,
	MAX_SRPT_SRQ_SIZE = 65535,

	MIN_MAX_REQ_SIZE = 996,
	DEFAULT_MAX_REQ_SIZE
		= sizeof(struct srp_cmd)/*48*/
		+ sizeof(struct srp_indirect_buf)/*20*/
		+ 128 * sizeof(struct srp_direct_buf)/*16*/,

	MIN_MAX_RSP_SIZE = sizeof(struct srp_rsp)/*36*/ + 4,
	DEFAULT_MAX_RSP_SIZE = 256, /* leaves 220 bytes for sense data */

	DEFAULT_MAX_RDMA_SIZE = 65536,
};

static inline u64 encode_wr_id(u8 opcode, u32 idx)
{ return ((u64)opcode << 32) | idx; }
static inline u8 opcode_from_wr_id(u64 wr_id)
{ return wr_id >> 32; }
static inline u32 idx_from_wr_id(u64 wr_id)
{ return (u32)wr_id; }

struct rdma_iu {
	u64 raddr;
	u32 rkey;
	struct ib_sge *sge;
	u32 sge_cnt;
	int mem_id;
};

/**
 * enum srpt_command_state - SCSI command state managed by SRPT.
 * @SRPT_STATE_NEW:           New command arrived and is being processed.
 * @SRPT_STATE_NEED_DATA:     Processing a write or bidir command and waiting
 *                            for data arrival.
 * @SRPT_STATE_DATA_IN:       Data for the write or bidir command arrived and is
 *                            being processed.
 * @SRPT_STATE_CMD_RSP_SENT:  SRP_RSP for SRP_CMD has been sent.
 * @SRPT_STATE_MGMT_RSP_SENT: SRP_RSP for SRP_TSK_MGMT has been sent.
 * @SRPT_STATE_DONE:          Command processing finished successfully, command
 *                            processing has been aborted or command processing
 *                            failed.
 */
enum srpt_command_state {
	SRPT_STATE_NEW = 0,
	SRPT_STATE_NEED_DATA = 1,
	SRPT_STATE_DATA_IN = 2,
	SRPT_STATE_CMD_RSP_SENT = 3,
	SRPT_STATE_MGMT_RSP_SENT = 4,
	SRPT_STATE_DONE = 5,
};

/**
 * struct srpt_ioctx - Shared SRPT I/O context information.
 * @buf:   Pointer to the buffer.
 * @dma:   DMA address of the buffer.
 * @index: Index of the I/O context in its ioctx_ring array.
 */
struct srpt_ioctx {
	void			*buf;
	dma_addr_t		dma;
	uint32_t		index;
};

/**
 * struct srpt_recv_ioctx - SRPT receive I/O context.
 * @ioctx:     See above.
 * @wait_list: Node for insertion in srpt_rdma_ch.cmd_wait_list.
 */
struct srpt_recv_ioctx {
	struct srpt_ioctx	ioctx;
	struct list_head	wait_list;
};

/**
 * struct srpt_send_ioctx - SRPT send I/O context.
 * @ioctx:     See above.
 * @free_list: Allows to make this struct an entry in srpt_rdma_ch.free_list.
 * @state:     I/O context state. See also enum srpt_command_state.
 */
struct srpt_send_ioctx {
	struct srpt_ioctx	ioctx;
	struct srpt_rdma_ch	*ch;
	struct rdma_iu		*rdma_ius;
	struct srp_direct_buf	*rbufs;
	struct srp_direct_buf	single_rbuf;
	struct scatterlist	*sg;
	struct list_head	free_list;
	int			sg_cnt;
	int			mapped_sg_count;
	u16			n_rdma_ius;
	u8			n_rdma;
	u8			n_rbuf;

	struct scst_cmd		*scmnd;
	scst_data_direction	dir;
	atomic_t		state;
};

/**
 * struct srpt_mgmt_ioctx - SCST management command context information.
 * @ioctx: SRPT I/O context associated with the management command.
 * @tag:   SCSI tag of the management command.
 */
struct srpt_mgmt_ioctx {
	struct srpt_send_ioctx	*ioctx;
	u64			tag;
};

/**
 * enum rdma_ch_state - SRP channel state.
 */
enum rdma_ch_state {
	RDMA_CHANNEL_CONNECTING,
	RDMA_CHANNEL_LIVE,
	RDMA_CHANNEL_DISCONNECTING
};

/**
 * struct srpt_rdma_ch - RDMA channel.
 * @wait_queue:    Allows the kernel thread to wait for more work.
 * @thread:        Kernel thread that processes the IB queues associated with
 *                 the channel.
 * @cm_id:         IB CM ID associated with the channel.
 * @rq_size:       IB receive queue size.
 * @processing_compl: whether or not an IB completion is being processed.
 * @qp:            IB queue pair used for communicating over this channel.
 * @sq_wr_avail:   number of work requests available in the send queue.
 * @cq:            IB completion queue for this channel.
 * @sport:         pointer to the information of the HCA port used by this
 *                 channel.
 * @i_port_id:     128-bit initiator port identifier copied from SRP_LOGIN_REQ.
 * @t_port_id:     128-bit target port identifier copied from SRP_LOGIN_REQ.
 * @max_ti_iu_len: maximum target-to-initiator information unit length.
 * @supports_cred_req: whether or not the initiator supports SRP_CRED_REQ.
 * @req_lim:       request limit: maximum number of requests that may be sent
 *                 by the initiator without having received a response.
 * @state:         channel state. See also enum rdma_ch_state.
 * @list:          node for insertion in the srpt_device.rch_list list.
 * @cmd_wait_list: list of SCST commands that arrived before the RTU event. This
 *                 list contains struct srpt_ioctx elements and is protected
 *                 against concurrent modification by the cm_id spinlock.
 * @spinlock:      Protects free_list.
 * @free_list:     Head of list with free send I/O contexts.
 * @scst_sess:     SCST session information associated with this SRP channel.
 * @sess_name:     SCST session name.
 */
struct srpt_rdma_ch {
	wait_queue_head_t	wait_queue;
	struct task_struct	*thread;
	struct ib_cm_id		*cm_id;
	struct ib_qp		*qp;
	int			rq_size;
	atomic_t		processing_compl;
	struct ib_cq		*cq;
	atomic_t		sq_wr_avail;
	struct srpt_port	*sport;
	u8			i_port_id[16];
	u8			t_port_id[16];
	int			max_ti_iu_len;
	atomic_t		req_lim;
	atomic_t		req_lim_delta;
	spinlock_t		spinlock;
	struct list_head	free_list;
	struct srpt_send_ioctx	**ioctx_ring;
	struct ib_wc		wc[16];
	atomic_t		state;
	struct list_head	list;
	struct list_head	cmd_wait_list;

	struct scst_session	*scst_sess;
	u8			sess_name[36];
};

/**
 * struct srpt_port - Information associated by SRPT with a single IB port.
 * @sdev:      backpointer to the HCA information.
 * @mad_agent: per-port management datagram processing information.
 * @port:      one-based port number.
 * @sm_lid:    cached value of the port's sm_lid.
 * @lid:       cached value of the port's lid.
 * @gid:       cached value of the port's gid.
 * @work:      work structure for refreshing the aforementioned cached values.
 */
struct srpt_port {
	struct srpt_device *sdev;
	struct ib_mad_agent *mad_agent;
	u8 port;
	u16 sm_lid;
	u16 lid;
	union ib_gid gid;
	struct work_struct work;
};

/**
 * struct srpt_device - Information associated by SRPT with a single HCA.
 * @device:        backpointer to the struct ib_device managed by the IB core.
 * @pd:            IB protection domain.
 * @mr:            L_Key (local key) with write access to all local memory.
 * @srq:           Per-HCA SRQ (shared receive queue).
 * @cm_id:         connection identifier.
 * @dev_attr:      attributes of the InfiniBand device as obtained during the
 *                 ib_client.add() callback.
 * @ioctx_ring:    Per-HCA I/O context ring.
 * @rch_list:      per-device channel list -- see also srpt_rdma_ch.list.
 * @spinlock:      protects rch_list.
 * @srpt_port:     information about the ports owned by this HCA.
 * @event_handler: per-HCA asynchronous IB event handler.
 * @dev:           per-port srpt-<portname> device instance.
 * @scst_tgt:      SCST target information associated with this HCA.
 * @enabled:       Whether or not this SCST target is enabled.
 */
struct srpt_device {
	struct ib_device *device;
	struct ib_pd *pd;
	struct ib_mr *mr;
	struct ib_srq *srq;
	struct ib_cm_id *cm_id;
	struct ib_device_attr dev_attr;
	int srq_size;
	struct srpt_recv_ioctx **ioctx_ring;
	struct list_head rch_list;
	spinlock_t spinlock;
	struct srpt_port port[2];
	struct ib_event_handler event_handler;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	struct class_device dev;
#else
	struct device dev;
#endif
	struct scst_tgt *scst_tgt;
	bool enabled;
};

#endif				/* IB_SRPT_H */

/*
 * Local variables:
 * c-basic-offset:   8
 * indent-tabs-mode: t
 * End:
 */
