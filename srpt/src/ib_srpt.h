/*
 * Copyright (c) 2006 - 2009 Mellanox Technology Inc.  All rights reserved.
 * Copyright (C) 2009 - 2013 Bart Van Assche <bvanassche@acm.org>.
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

#include <linux/types.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_cm.h>
#include <scsi/srp.h>
#if defined(INSIDE_KERNEL_TREE)
#include <scst/scst.h>
#else
#include <linux/version.h>
#include <scst.h>
#endif
#include "ib_dm_mad.h"

/*
 * The prefix the ServiceName field must start with in the device management
 * ServiceEntries attribute pair. See also the SRP specification.
 */
#define SRP_SERVICE_NAME_PREFIX		"SRP.T10:"

struct srpt_tgt;

enum {
	/*
	 * SRP IOControllerProfile attributes for SRP target ports that have
	 * not been defined in <scsi/srp.h>. Source: section B.7, table B.7
	 * in the SRP specification.
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
	 * 18 and 20 in the SRP specification.
	 */
	SRP_SCSOLNT = 0x02, /* SCSOLNT = successful solicited notification */
	SRP_UCSOLNT = 0x04, /* UCSOLNT = unsuccessful solicited notification */

	/*
	 * srp_rsp.sol_not / srp_t_logout.sol_not bitmasks. See also tables
	 * 16 and 22 in the SRP specification.
	 */
	SRP_SOLNT = 0x01, /* SOLNT = solicited notification */

	/* See also table 24 in the SRP specification. */
	SRP_TSK_MGMT_SUCCESS = 0x00,
	SRP_TSK_MGMT_FUNC_NOT_SUPP = 0x04,
	SRP_TSK_MGMT_FAILED = 0x05,

	/* See also table 21 in the SRP specification. */
	SRP_CMD_SIMPLE_Q = 0x0,
	SRP_CMD_HEAD_OF_Q = 0x1,
	SRP_CMD_ORDERED_Q = 0x2,
	SRP_CMD_ACA = 0x4,

	SRP_LOGIN_RSP_MULTICHAN_NO_CHAN = 0x0,
	SRP_LOGIN_RSP_MULTICHAN_TERMINATED = 0x1,
	SRP_LOGIN_RSP_MULTICHAN_MAINTAINED = 0x2,

	SRPT_DEF_SG_TABLESIZE = 128,

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
		+ 255 * sizeof(struct srp_direct_buf)/*16*/,

	MIN_MAX_RSP_SIZE = sizeof(struct srp_rsp)/*36*/ + 4,
	DEFAULT_MAX_RSP_SIZE = 256, /* leaves 220 bytes for sense data */

	DEFAULT_MAX_RDMA_SIZE = 65536,

	RDMA_COMPL_TIMEOUT_S = 80,
};

enum srpt_opcode {
	SRPT_RECV,
	SRPT_SEND,
	SRPT_RDMA_MID,
	SRPT_RDMA_ABORT,
	SRPT_RDMA_READ_LAST,
	SRPT_RDMA_WRITE_LAST,
};

static inline u64 encode_wr_id(enum srpt_opcode opcode, u32 idx)
{
	return ((u64)opcode << 32) | idx;
}

static inline enum srpt_opcode opcode_from_wr_id(u64 wr_id)
{
	return wr_id >> 32;
}

static inline u32 idx_from_wr_id(u64 wr_id)
{
	return (u32)wr_id;
}

struct rdma_iu {
	u64 raddr;
	u32 rkey;
	struct ib_sge *sge;
	u32 sge_cnt;
};

/**
 * enum srpt_command_state - SCSI command state managed by SRPT.
 * @SRPT_STATE_NEW:           New command arrived and is being processed.
 * @SRPT_STATE_NEED_DATA:     Processing a write or bidir command and waiting
 *                            for data arrival.
 * @SRPT_STATE_DATA_IN:       Data for the write or bidir command arrived and is
 *                            being processed.
 * @SRPT_STATE_CMD_RSP_SENT:  SRP_RSP for SRP_CMD has been sent.
 * @SRPT_STATE_MGMT:          Processing a SCSI task management command.
 * @SRPT_STATE_MGMT_RSP_SENT: SRP_RSP for SRP_TSK_MGMT has been sent.
 * @SRPT_STATE_DONE:          Command processing finished successfully, command
 *                            processing has been aborted or command processing
 *                            failed.
 */
enum srpt_command_state {
	SRPT_STATE_NEW		 = 0,
	SRPT_STATE_NEED_DATA	 = 1,
	SRPT_STATE_DATA_IN	 = 2,
	SRPT_STATE_CMD_RSP_SENT	 = 3,
	SRPT_STATE_MGMT		 = 4,
	SRPT_STATE_MGMT_RSP_SENT = 5,
	SRPT_STATE_DONE		 = 6,
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
 * struct srpt_tsk_mgmt - SCST management command context information.
 * @tag:   SCSI tag of the management command.
 */
struct srpt_tsk_mgmt {
	u64			tag;
};

/**
 * struct srpt_send_ioctx - SRPT send I/O context.
 * @ioctx:       See above.
 * @ch:          Channel pointer.
 * @rdma_ius:    Array with information about the RDMA mapping.
 * @rbufs:       Pointer to SRP data buffer array.
 * @single_rbuf: SRP data buffer if the command has only a single buffer.
 * @sg:          Pointer to sg-list associated with this I/O context.
 * @spinlock:    Protects 'state'.
 * @state:       I/O context state.
 * @rdma_aborted: If initiating a multipart RDMA transfer failed, whether
 *               the already initiated transfers have finished.
 * @scmnd:       SCST command data structure.
 * @dir:         Data direction.
 * @free_list:   Node in srpt_rdma_ch.free_list.
 * @sg_cnt:      SG-list size.
 * @mapped_sg_count: ib_dma_map_sg() return value.
 * @n_rdma_ius:  Size of the rdma_ius array.
 * @n_rdma:      Number of elements used of the rdma_ius array.
 * @n_rbuf:      Number of data buffers in the received SRP command.
 * @req_lim_delta: Value of the req_lim_delta value field in the latest
 *               SRP response sent.
 * @tsk_mgmt:    SRPT task management function context information.
 * @rdma_ius_buf: DMA mapping context information.
 */
struct srpt_send_ioctx {
	struct srpt_ioctx	ioctx;
	struct srpt_rdma_ch	*ch;
	struct rdma_iu		*rdma_ius;
	struct srp_direct_buf	*rbufs;
	struct srp_direct_buf	single_rbuf;
	struct scatterlist	*sg;
	struct list_head	free_list;
	spinlock_t		spinlock;
	enum srpt_command_state	state;
	bool			rdma_aborted;
	struct scst_cmd		scmnd;
	scst_data_direction	dir;
	int			sg_cnt;
	int			mapped_sg_count;
	u16			n_rdma_ius;
	u8			n_rdma;
	u8			n_rbuf;
	int			req_lim_delta;
	struct srpt_tsk_mgmt	tsk_mgmt;
	u8			rdma_ius_buf[2 * sizeof(struct rdma_iu)
					     + 2 * sizeof(struct ib_sge)]
				__aligned(sizeof(uint64_t));
};

/**
 * enum rdma_ch_state - SRP channel state.
 * @CH_CONNECTING:    QP is in RTR state; waiting for RTU.
 * @CH_LIVE:	      QP is in RTS state.
 * @CH_DISCONNECTING: DREQ has been received and waiting for DREP or DREQ has
 *                    been sent and waiting for DREP or channel is being closed
 *                    for another reason.
 * @CH_DRAINING:      QP is in ERR state.
 */
enum rdma_ch_state {
	CH_CONNECTING,
	CH_LIVE,
	CH_DISCONNECTING,
	CH_DRAINING,
};

/**
 * struct srpt_rdma_ch - RDMA channel.
 * @thread:        Kernel thread that processes the IB queues associated with
 *                 the channel.
 * @cm_id:         IB CM ID associated with the channel.
 * @qp:            IB queue pair used for communicating over this channel.
 * @cq:            IB completion queue for this channel.
 * @kref:          Per-channel reference count.
 * @rq_size:       IB receive queue size.
 * @max_sge:       Maximum length of RDMA scatter list.
 * @max_rsp_size:  Maximum size of an SRP response messages in bytes.
 * @sq_wr_avail:   number of work requests available in the send queue.
 * @sport:         pointer to the information of the HCA port used by this
 *                 channel.
 * @srpt_tgt:      Target port used by this channel.
 * @i_port_id:     128-bit initiator port identifier copied from SRP_LOGIN_REQ.
 * @t_port_id:     128-bit target port identifier copied from SRP_LOGIN_REQ.
 * @max_ti_iu_len: maximum target-to-initiator information unit length.
 * @req_lim:       request limit: maximum number of requests that may be sent
 *                 by the initiator without having received a response.
 * @req_lim_delta: One less than the req_lim_delta value that will be included
 *                 in the next reply sent to the initiator. See also the SRP
 *                 credit algorithm in the SRP spec.
 * @spinlock:      Protects free_list.
 * @free_list:     Head of list with free send I/O contexts.
 * @ioctx_ring:    Send I/O context ring.
 * @wc:            Work completion array.
 * @state:         channel state. See also enum rdma_ch_state.
 * @dreq_received: Whether an IB CM DREQ event has been received.
 * @last_wqe_received: Whether the Last WQE QP event has been received.
 * @list:          node for insertion in the srpt_device.rch_list list.
 * @cmd_wait_list: list of SCST commands that arrived before the RTU event. This
 *                 list contains struct srpt_ioctx elements and is protected
 *                 against concurrent modification by the cm_id spinlock.
 * @pkey_index:    P_Key index of the IB partition for this SRP channel.
 * @scst_sess:     SCST session information associated with this SRP channel.
 * @sess_name:     SCST session name.
 */
struct srpt_rdma_ch {
	struct task_struct	*thread;
	struct ib_cm_id		*cm_id;
	struct ib_qp		*qp;
	struct ib_cq		*cq;
	struct kref		kref;
	int			rq_size;
	int			max_sge;
	int			max_rsp_size;
	int			sq_wr_avail;
	struct srpt_port	*sport;
	struct srpt_tgt		*srpt_tgt;
	u8			i_port_id[16];
	u8			t_port_id[16];
	int			max_ti_iu_len;
	int			req_lim;
	int			req_lim_delta;
	spinlock_t		spinlock;
	struct list_head	free_list;
	struct srpt_send_ioctx	**ioctx_ring;
	struct ib_wc		wc[16];
	enum rdma_ch_state	state;
	struct list_head	list;
	struct list_head	cmd_wait_list;
	uint16_t		pkey_index;
	bool			dreq_received;
	bool			last_wqe_received;

	struct scst_session	*scst_sess;
	u8			sess_name[40];
};

/**
 * struct srpt_tgt
 * @ch_releaseQ:   Enables waiting for removal from rch_list.
 * @spinlock:  Protects rch_list.
 * @rch_list:  Per-device channel list -- see also srpt_rdma_ch.list.
 * @scst_tgt:  SCST target information associated with this HCA.
 * @enabled:   Whether or not this SCST target is enabled.
 */
struct srpt_tgt {
	wait_queue_head_t	ch_releaseQ;
	spinlock_t		spinlock;
	struct list_head	rch_list;
	struct scst_tgt		*scst_tgt;
	bool			enabled;
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
 * @srpt_tgt:  Target port information. Only used if one-target-per-port
 *             mode is enabled.
 */
struct srpt_port {
	struct srpt_device	*sdev;
	struct ib_mad_agent	*mad_agent;
	u8			port;
	u16			sm_lid;
	u16			lid;
	union ib_gid		gid;
	struct work_struct	work;
	struct srpt_tgt		srpt_tgt;
};

/**
 * struct srpt_device - Information associated by SRPT with a single HCA.
 * @device:        Backpointer to the struct ib_device managed by the IB core.
 * @pd:            IB protection domain.
 * @mr:            L_Key (local key) with write access to all local memory.
 * @srq:           Per-HCA SRQ (shared receive queue).
 * @cm_id:         Connection identifier.
 * @dev_attr:      Attributes of the InfiniBand device as obtained during the
 *                 ib_client.add() callback.
 * @srq_size:      SRQ size.
 * @ioctx_ring:    Per-HCA SRQ.
 * @port:	   Information about the ports owned by this HCA.
 * @event_handler: Per-HCA asynchronous IB event handler.
 * @srpt_tgt:      Target port information. Only used if one-target-per-port
 *                 mode is disabled.
 */
struct srpt_device {
	struct ib_device	*device;
	struct ib_pd		*pd;
	struct ib_mr		*mr;
	struct ib_srq		*srq;
	struct ib_cm_id		*cm_id;
	struct ib_device_attr	dev_attr;
	int			srq_size;
	struct srpt_recv_ioctx	**ioctx_ring;
	struct srpt_port	port[2];
	struct ib_event_handler	event_handler;
	struct srpt_tgt		srpt_tgt;
};

#endif				/* IB_SRPT_H */

/*
 * Local variables:
 * c-basic-offset:   8
 * indent-tabs-mode: t
 * End:
 */
