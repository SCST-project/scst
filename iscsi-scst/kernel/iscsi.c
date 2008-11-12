/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2008 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/hash.h>
#include <linux/kthread.h>
#include <net/tcp.h>
#include <scsi/scsi.h>

#include "iscsi.h"
#include "digest.h"

#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
#warning "Patch put_page_callback-<kernel-version>.patch not applied on your \
	kernel. ISCSI-SCST will run in the performance degraded mode. Refer \
	README file for details."
#endif

#define ISCSI_INIT_WRITE_WAKE		0x1
#define ISCSI_INIT_WRITE_REMOVE_HASH	0x2

static int ctr_major;
static char ctr_name[] = "iscsi-scst-ctl";
static int iscsi_template_registered;

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
unsigned long iscsi_trace_flag = ISCSI_DEFAULT_LOG_FLAGS;
#endif

static struct kmem_cache *iscsi_cmnd_cache;

DEFINE_SPINLOCK(iscsi_rd_lock);
LIST_HEAD(iscsi_rd_list);
DECLARE_WAIT_QUEUE_HEAD(iscsi_rd_waitQ);

DEFINE_SPINLOCK(iscsi_wr_lock);
LIST_HEAD(iscsi_wr_list);
DECLARE_WAIT_QUEUE_HEAD(iscsi_wr_waitQ);

static struct page *dummy_page;
static struct scatterlist dummy_sg;

struct iscsi_thread_t {
	struct task_struct *thr;
	struct list_head threads_list_entry;
};

static LIST_HEAD(iscsi_threads_list);

static void cmnd_remove_hash(struct iscsi_cmnd *cmnd);
static void iscsi_send_task_mgmt_resp(struct iscsi_cmnd *req, int status);
static void cmnd_prepare_get_rejected_cmd_data(struct iscsi_cmnd *cmnd);
static void iscsi_check_send_delayed_tm_resp(struct iscsi_session *sess);
static void iscsi_session_push_cmnd(struct iscsi_cmnd *cmnd);

static inline u32 cmnd_write_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_CMD_WRITE)
		return be32_to_cpu(hdr->data_length);
	return 0;
}

static inline u32 cmnd_read_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_CMD_READ) {
		struct iscsi_rlength_ahdr *ahdr =
			(struct iscsi_rlength_ahdr *)cmnd->pdu.ahs;

		if (!(hdr->flags & ISCSI_CMD_WRITE))
			return be32_to_cpu(hdr->data_length);
		if (ahdr && ahdr->ahstype == ISCSI_AHSTYPE_RLENGTH)
			return be32_to_cpu(ahdr->read_length);
	}
	return 0;
}

static inline void iscsi_restart_cmnd(struct iscsi_cmnd *cmnd)
{
	EXTRACHECKS_BUG_ON(cmnd->data_waiting);

	cmnd->scst_state = ISCSI_CMD_STATE_RESTARTED;
	scst_restart_cmd(cmnd->scst_cmd, SCST_PREPROCESS_STATUS_SUCCESS,
		SCST_CONTEXT_THREAD);
}

static inline void iscsi_restart_waiting_cmnd(struct iscsi_cmnd *cmnd)
{
	/*
	 * There is no race with conn_abort(), since all functions
	 * called from single read thread
	 */
	iscsi_extracheck_is_rd_thread(cmnd->conn);
	cmnd->data_waiting = 0;

	iscsi_restart_cmnd(cmnd);
}

static inline void iscsi_fail_waiting_cmnd(struct iscsi_cmnd *cmnd)
{
	TRACE_MGMT_DBG("Failing data waiting cmd %p", cmnd);

	/*
	 * There is no race with conn_abort(), since all functions
	 * called from single read thread
	 */
	iscsi_extracheck_is_rd_thread(cmnd->conn);
	cmnd->data_waiting = 0;

	req_cmnd_release_force(cmnd, ISCSI_FORCE_RELEASE_WRITE);
}

struct iscsi_cmnd *cmnd_alloc(struct iscsi_conn *conn,
			      struct iscsi_cmnd *parent)
{
	struct iscsi_cmnd *cmnd;

	/* ToDo: __GFP_NOFAIL?? */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	cmnd = kmem_cache_alloc(iscsi_cmnd_cache, GFP_KERNEL|__GFP_NOFAIL);
	memset(cmnd, 0, sizeof(*cmnd));
#else
	cmnd = kmem_cache_zalloc(iscsi_cmnd_cache, GFP_KERNEL|__GFP_NOFAIL);
#endif

	atomic_set(&cmnd->ref_cnt, 1);
	cmnd->scst_state = ISCSI_CMD_STATE_NEW;
	cmnd->conn = conn;
	cmnd->parent_req = parent;
	init_waitqueue_head(&cmnd->scst_waitQ);

	if (parent == NULL) {
		conn_get(conn);

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
		atomic_set(&cmnd->net_ref_cnt, 0);
#endif
		spin_lock_init(&cmnd->rsp_cmd_lock);
		INIT_LIST_HEAD(&cmnd->rsp_cmd_list);
		INIT_LIST_HEAD(&cmnd->rx_ddigest_cmd_list);

		spin_lock_bh(&conn->cmd_list_lock);
		list_add_tail(&cmnd->cmd_list_entry, &conn->cmd_list);
		spin_unlock_bh(&conn->cmd_list_lock);
	}

	TRACE_DBG("conn %p, parent %p, cmnd %p", conn, parent, cmnd);
	return cmnd;
}

/* Frees a command. Also frees the additional header. */
static void cmnd_free(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);

	if (unlikely(cmnd->tm_aborted)) {
		TRACE_MGMT_DBG("Free aborted cmd %p (scst cmd %p, state %d, "
			"parent_req %p)", cmnd, cmnd->scst_cmd,
			cmnd->scst_state, cmnd->parent_req);
	}

	/* Catch users from cmd_list or rsp_cmd_list */
	EXTRACHECKS_BUG_ON(atomic_read(&cmnd->ref_cnt) != 0);

	kfree(cmnd->pdu.ahs);

	if (unlikely(cmnd->on_write_list || cmnd->on_written_list)) {
		struct iscsi_scsi_cmd_hdr *req = cmnd_hdr(cmnd);

		PRINT_CRIT_ERROR("cmnd %p still on some list?, %x, %x, %x, "
			"%x, %x, %x, %x", cmnd, req->opcode, req->scb[0],
			req->flags, req->itt, be32_to_cpu(req->data_length),
			req->cmd_sn, be32_to_cpu(cmnd->pdu.datasize));

		if (unlikely(cmnd->parent_req)) {
			struct iscsi_scsi_cmd_hdr *preq =
					cmnd_hdr(cmnd->parent_req);
			PRINT_CRIT_ERROR("%p %x %u", preq, preq->opcode,
				preq->scb[0]);
		}
		sBUG();
	}

	kmem_cache_free(iscsi_cmnd_cache, cmnd);
	return;
}

void cmnd_done(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);

	if (unlikely(cmnd->tm_aborted)) {
		TRACE_MGMT_DBG("Done aborted cmd %p (scst cmd %p, state %d, "
			"parent_req %p)", cmnd, cmnd->scst_cmd,
			cmnd->scst_state, cmnd->parent_req);
	}

	EXTRACHECKS_BUG_ON(cmnd->on_rx_digest_list);

	if (cmnd->on_written_list) {
		struct iscsi_conn *conn = cmnd->conn;
		TRACE_DBG("Deleting cmd %p from conn %p written_list", cmnd,
			conn);
		spin_lock_bh(&conn->write_list_lock);
		list_del(&cmnd->write_list_entry);
		cmnd->on_written_list = 0;
		spin_unlock_bh(&conn->write_list_lock);
	}

	if (cmnd->parent_req == NULL) {
		struct iscsi_conn *conn = cmnd->conn;
		TRACE_DBG("Deleting req %p from conn %p", cmnd, conn);

		spin_lock_bh(&conn->cmd_list_lock);
		list_del(&cmnd->cmd_list_entry);
		spin_unlock_bh(&conn->cmd_list_lock);

		conn_put(conn);

		EXTRACHECKS_BUG_ON(!list_empty(&cmnd->rsp_cmd_list));
		EXTRACHECKS_BUG_ON(!list_empty(&cmnd->rx_ddigest_cmd_list));

		/* Order between above and below code is important! */

		if (cmnd->scst_cmd) {
			switch (cmnd->scst_state) {
			case ISCSI_CMD_STATE_PROCESSED:
				TRACE_DBG("cmd %p PROCESSED", cmnd);
				scst_tgt_cmd_done(cmnd->scst_cmd,
					SCST_CONTEXT_DIRECT);
				break;
			case ISCSI_CMD_STATE_AFTER_PREPROC:
			{
				struct scst_cmd *scst_cmd = cmnd->scst_cmd;
				TRACE_DBG("cmd %p AFTER_PREPROC", cmnd);
				cmnd->scst_state = ISCSI_CMD_STATE_RESTARTED;
				cmnd->scst_cmd = NULL;
				scst_restart_cmd(scst_cmd,
					SCST_PREPROCESS_STATUS_ERROR_FATAL,
					SCST_CONTEXT_THREAD);
				break;
			}
			default:
				PRINT_CRIT_ERROR("Unexpected cmnd scst state "
					"%d", cmnd->scst_state);
				sBUG();
				break;
			}
		}
	} else {
		EXTRACHECKS_BUG_ON(cmnd->scst_cmd != NULL);
		TRACE_DBG("Deleting rsp %p from parent %p", cmnd,
			cmnd->parent_req);

		spin_lock_bh(&cmnd->parent_req->rsp_cmd_lock);
		list_del(&cmnd->rsp_cmd_list_entry);
		spin_unlock_bh(&cmnd->parent_req->rsp_cmd_lock);

		cmnd_put(cmnd->parent_req);
	}

	/* Order between above and below code is important! */

	if (cmnd->own_sg) {
		TRACE_DBG("%s", "own_sg");
		if (cmnd->sg != &dummy_sg)
			scst_free(cmnd->sg, cmnd->sg_cnt);
#ifdef CONFIG_SCST_DEBUG
		cmnd->own_sg = 0;
		cmnd->sg = NULL;
		cmnd->sg_cnt = -1;
#endif
	}

	if (cmnd->dec_active_cmnds) {
		struct iscsi_session *sess = cmnd->conn->session;
		TRACE_DBG("Decrementing active_cmds (cmd %p, sess %p, "
			"new value %d)", cmnd, sess,
			atomic_read(&sess->active_cmds)-1);
		atomic_dec(&sess->active_cmds);
#ifdef CONFIG_SCST_EXTRACHECKS
		if (unlikely(atomic_read(&sess->active_cmds) < 0)) {
			PRINT_CRIT_ERROR("active_cmds < 0 (%d)!!",
				atomic_read(&sess->active_cmds));
			sBUG();
		}
#endif
	}

	cmnd_free(cmnd);
	return;
}

/*
 * Corresponding conn may also gets destroyed atfer this function, except only
 * if it's called from the read thread!
 *
 * It can't be called in parallel with iscsi_cmnds_init_write()!
 */
void req_cmnd_release_force(struct iscsi_cmnd *req, int flags)
{
	struct iscsi_cmnd *rsp, *t;
	struct iscsi_conn *conn = req->conn;
	LIST_HEAD(cmds_list);

	TRACE_ENTRY();

	TRACE_MGMT_DBG("%p", req);

	sBUG_ON(req == conn->read_cmnd);

	if (flags & ISCSI_FORCE_RELEASE_WRITE) {
		spin_lock_bh(&conn->write_list_lock);
		list_for_each_entry_safe(rsp, t, &conn->write_list,
						write_list_entry) {
			if (rsp->parent_req != req)
				continue;

			cmd_del_from_write_list(rsp);

			list_add_tail(&rsp->write_list_entry, &cmds_list);
		}
		spin_unlock_bh(&conn->write_list_lock);

		list_for_each_entry_safe(rsp, t, &cmds_list,
						write_list_entry) {
			TRACE_MGMT_DBG("Putting write rsp %p", rsp);
			list_del(&rsp->write_list_entry);
			cmnd_put(rsp);
		}
	}

again_rsp:
	spin_lock_bh(&req->rsp_cmd_lock);
	list_for_each_entry_reverse(rsp, &req->rsp_cmd_list,
			rsp_cmd_list_entry) {
		bool r;

		if (rsp->force_cleanup_done)
			continue;

		rsp->force_cleanup_done = 1;

		if (cmnd_get_check(rsp))
			continue;

		spin_unlock_bh(&req->rsp_cmd_lock);

		spin_lock_bh(&conn->write_list_lock);
		r = rsp->on_write_list || rsp->write_processing_started;
		spin_unlock_bh(&conn->write_list_lock);

		cmnd_put(rsp);

		if (r)
			goto again_rsp;

		/*
		 * If both on_write_list and write_processing_started not set,
		 * we can safely put() rsp.
		 */
		TRACE_MGMT_DBG("Putting rsp %p", rsp);
		cmnd_put(rsp);
		goto again_rsp;
	}
	spin_unlock_bh(&req->rsp_cmd_lock);

	req_cmnd_release(req);

	TRACE_EXIT();
	return;
}

/*
 * Corresponding conn may also gets destroyed atfer this function, except only
 * if it's called from the read thread!
 */
void req_cmnd_release(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *c, *t;

	TRACE_ENTRY();

	TRACE_DBG("%p", req);

#ifdef CONFIG_SCST_EXTRACHECKS
	sBUG_ON(req->release_called);
	req->release_called = 1;
#endif

	if (unlikely(req->tm_aborted)) {
		TRACE_MGMT_DBG("Release aborted req cmd %p (scst cmd %p, "
			"state %d)", req, req->scst_cmd, req->scst_state);
	}

	sBUG_ON(req->parent_req != NULL);

	list_for_each_entry_safe(c, t, &req->rx_ddigest_cmd_list,
				rx_ddigest_cmd_list_entry) {
		cmd_del_from_rx_ddigest_list(c);
		cmnd_put(c);
	}

	if (req->hashed)
		cmnd_remove_hash(req);

	if (req->dec_active_cmnds) {
		struct iscsi_session *sess = req->conn->session;
		TRACE_DBG("Decrementing active_cmds (cmd %p, sess %p, "
			"new value %d)", req, sess,
			atomic_read(&sess->active_cmds)-1);
		atomic_dec(&sess->active_cmds);
		req->dec_active_cmnds = 0;
#ifdef CONFIG_SCST_EXTRACHECKS
		if (unlikely(atomic_read(&sess->active_cmds) < 0)) {
			PRINT_CRIT_ERROR("active_cmds < 0 (%d)!!",
				atomic_read(&sess->active_cmds));
			sBUG();
		}
#endif
	}

	cmnd_put(req);

	TRACE_EXIT();
	return;
}

/*
 * Corresponding conn may also gets destroyed atfer this function, except only
 * if it's called from the read thread!
 */
void rsp_cmnd_release(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);

#ifdef CONFIG_SCST_EXTRACHECKS
	sBUG_ON(cmnd->release_called);
	cmnd->release_called = 1;
#endif

	sBUG_ON(cmnd->hashed);
	sBUG_ON(cmnd->parent_req == NULL);

	cmnd_put(cmnd);
	return;
}

/**
 * create a new command used as response.
 *
 * iscsi_cmnd_create_rsp_cmnd -
 * @cmnd: ptr to request command
 *
 * @return    ptr to response command or NULL
 */
static struct iscsi_cmnd *iscsi_cmnd_create_rsp_cmnd(struct iscsi_cmnd *parent)
{
	struct iscsi_cmnd *rsp;

	rsp = cmnd_alloc(parent->conn, parent);

	spin_lock_bh(&parent->rsp_cmd_lock);
	TRACE_DBG("Adding rsp %p to parent %p", rsp, parent);
	list_add_tail(&rsp->rsp_cmd_list_entry, &parent->rsp_cmd_list);
	spin_unlock_bh(&parent->rsp_cmd_lock);
	cmnd_get(parent);
	return rsp;
}

static inline struct iscsi_cmnd *get_rsp_cmnd(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *res = NULL;

	/* Currently this lock isn't needed, but just in case.. */
	spin_lock_bh(&req->rsp_cmd_lock);
	if (!list_empty(&req->rsp_cmd_list)) {
		res = list_entry(req->rsp_cmd_list.prev, struct iscsi_cmnd,
			rsp_cmd_list_entry);
	}
	spin_unlock_bh(&req->rsp_cmd_lock);

	return res;
}

static void iscsi_cmnds_init_write(struct list_head *send, int flags)
{
	struct iscsi_cmnd *rsp = list_entry(send->next, struct iscsi_cmnd,
						write_list_entry);
	struct iscsi_conn *conn = rsp->conn;
	struct list_head *pos, *next;

	sBUG_ON(list_empty(send));

	/*
	 * If we don't remove hashed req cmd from the hash list here, before
	 * submitting it for transmittion, we will have a race, when for
	 * some reason cmd's release is delayed after transmittion and
	 * initiator sends cmd with the same ITT => this command will be
	 * erroneously rejected as a duplicate.
	 */
	if ((flags & ISCSI_INIT_WRITE_REMOVE_HASH) &&
	    rsp->parent_req->hashed &&
	    (rsp->parent_req->r2t_length == 0) &&
	    (rsp->parent_req->outstanding_r2t == 0))
		cmnd_remove_hash(rsp->parent_req);

	if (!(conn->ddigest_type & DIGEST_NONE)) {
		list_for_each(pos, send) {
			rsp = list_entry(pos, struct iscsi_cmnd,
						write_list_entry);

			if (rsp->pdu.datasize != 0) {
				TRACE_DBG("Doing data digest (%p:%x)", rsp,
					cmnd_opcode(rsp));
				digest_tx_data(rsp);
			}
		}
	}

	spin_lock_bh(&conn->write_list_lock);
	list_for_each_safe(pos, next, send) {
		rsp = list_entry(pos, struct iscsi_cmnd, write_list_entry);

		TRACE_DBG("%p:%x", rsp, cmnd_opcode(rsp));

		sBUG_ON(conn != rsp->conn);

		list_del(&rsp->write_list_entry);
		cmd_add_on_write_list(conn, rsp);
	}
	spin_unlock_bh(&conn->write_list_lock);

	if (flags & ISCSI_INIT_WRITE_WAKE)
		iscsi_make_conn_wr_active(conn);

	return;
}

static void iscsi_cmnd_init_write(struct iscsi_cmnd *rsp, int flags)
{
	LIST_HEAD(head);

	if (unlikely(rsp->on_write_list)) {
		PRINT_CRIT_ERROR("cmd already on write list (%x %x %x %x %u "
			"%u %u %u %u %u %u %d %d",
			cmnd_itt(rsp), cmnd_ttt(rsp), cmnd_opcode(rsp),
			cmnd_scsicode(rsp), rsp->r2t_sn,
			rsp->r2t_length, rsp->is_unsolicited_data,
			rsp->target_task_tag, rsp->outstanding_r2t,
			rsp->hdigest, rsp->ddigest,
			list_empty(&rsp->rsp_cmd_list), rsp->hashed);
		sBUG();
	}
	list_add(&rsp->write_list_entry, &head);
	iscsi_cmnds_init_write(&head, flags);
	return;
}

static void iscsi_set_datasize(struct iscsi_cmnd *cmnd, u32 offset, u32 size)
{
	cmnd->pdu.datasize = size;

	if (size & 3) {
		u32 last_off = offset + size;
		int idx = last_off >> PAGE_SHIFT;
		u8 *p = (u8 *)page_address(sg_page(&cmnd->sg[idx])) +
			(last_off & ~PAGE_MASK);
		int i = 4 - (size & 3);
		while (i--)
			*p++ = 0;
	}
	return;
}

static void send_data_rsp(struct iscsi_cmnd *req, u8 status, int send_status)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);
	struct iscsi_data_in_hdr *rsp_hdr;
	u32 pdusize, expsize, scsisize, size, offset, sn;
	LIST_HEAD(send);

	TRACE_DBG("req %p", req);

	pdusize = req->conn->session->sess_param.max_xmit_data_length;
	expsize = cmnd_read_size(req);
	size = min(expsize, (u32)req->bufflen);
	offset = 0;
	sn = 0;

	while (1) {
		rsp = iscsi_cmnd_create_rsp_cmnd(req);
		TRACE_DBG("rsp %p", rsp);
		rsp->sg = req->sg;
		rsp->sg_cnt = req->sg_cnt;
		rsp->bufflen = req->bufflen;
		rsp_hdr = (struct iscsi_data_in_hdr *)&rsp->pdu.bhs;

		rsp_hdr->opcode = ISCSI_OP_SCSI_DATA_IN;
		rsp_hdr->itt = req_hdr->itt;
		rsp_hdr->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
		rsp_hdr->buffer_offset = cpu_to_be32(offset);
		rsp_hdr->data_sn = cpu_to_be32(sn);

		if (size <= pdusize) {
			TRACE_DBG("offset %d, size %d", offset, size);
			iscsi_set_datasize(rsp, offset, size);
			if (send_status) {
				TRACE_DBG("status %x", status);
				rsp_hdr->flags =
					ISCSI_FLG_FINAL | ISCSI_FLG_STATUS;
				rsp_hdr->cmd_status = status;
			}
			scsisize = req->bufflen;
			if (scsisize < expsize) {
				rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
				size = expsize - scsisize;
			} else if (scsisize > expsize) {
				rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
				size = scsisize - expsize;
			} else
				size = 0;
			rsp_hdr->residual_count = cpu_to_be32(size);
			list_add_tail(&rsp->write_list_entry, &send);
			break;
		}

		TRACE_DBG("pdusize %d, offset %d, size %d", pdusize, offset,
			size);

		iscsi_set_datasize(rsp, offset, pdusize);

		size -= pdusize;
		offset += pdusize;
		sn++;

		list_add_tail(&rsp->write_list_entry, &send);
	}
	iscsi_cmnds_init_write(&send, ISCSI_INIT_WRITE_REMOVE_HASH);
	return;
}

static struct iscsi_cmnd *create_status_rsp(struct iscsi_cmnd *req, int status,
	const u8 *sense_buf, int sense_len)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_scsi_rsp_hdr *rsp_hdr;
	struct iscsi_sense_data *sense;
	struct scatterlist *sg;

	rsp = iscsi_cmnd_create_rsp_cmnd(req);
	TRACE_DBG("%p", rsp);

	rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_SCSI_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->response = ISCSI_RESPONSE_COMMAND_COMPLETED;
	rsp_hdr->cmd_status = status;
	rsp_hdr->itt = cmnd_hdr(req)->itt;

	if (SCST_SENSE_VALID(sense_buf)) {
		TRACE_DBG("%s", "SENSE VALID");
		/* ToDo: __GFP_NOFAIL ?? */
		sg = rsp->sg = scst_alloc(PAGE_SIZE, GFP_KERNEL|__GFP_NOFAIL,
					&rsp->sg_cnt);
		if (sg == NULL) {
			;/* ToDo */;
		}
		rsp->own_sg = 1;
		sense = (struct iscsi_sense_data *)page_address(sg_page(&sg[0]));
		sense->length = cpu_to_be16(sense_len);
		memcpy(sense->data, sense_buf, sense_len);
		rsp->pdu.datasize = sizeof(struct iscsi_sense_data) + sense_len;
		rsp->bufflen = (rsp->pdu.datasize + 3) & -4;
		if (rsp->bufflen - rsp->pdu.datasize) {
			int i = rsp->pdu.datasize;
			u8 *p = (u8 *)sense + i;

			while (i < rsp->bufflen) {
				*p++ = 0;
				i++;
			}
		}
	} else {
		rsp->pdu.datasize = 0;
		rsp->bufflen = 0;
	}

	return rsp;
}

static struct iscsi_cmnd *create_sense_rsp(struct iscsi_cmnd *req,
	u8 sense_key, u8 asc, u8 ascq)
{
	u8 sense[14];
	memset(sense, 0, sizeof(sense));
	sense[0] = 0xf0;
	sense[2] = sense_key;
	sense[7] = 6;	/* Additional sense length */
	sense[12] = asc;
	sense[13] = ascq;
	return create_status_rsp(req, SAM_STAT_CHECK_CONDITION, sense,
		sizeof(sense));
}

static void iscsi_cmnd_reject(struct iscsi_cmnd *req, int reason)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_reject_hdr *rsp_hdr;
	struct scatterlist *sg;
	char *addr;

	TRACE_MGMT_DBG("Reject: req %p, reason %x", req, reason);

	sBUG_ON(req->rejected);
	req->rejected = 1;
	req->reject_reason = ISCSI_REJECT_CMD;

	rsp = iscsi_cmnd_create_rsp_cmnd(req);
	rsp_hdr = (struct iscsi_reject_hdr *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_REJECT;
	rsp_hdr->ffffffff = ISCSI_RESERVED_TAG;
	rsp_hdr->reason = reason;

	/* ToDo: __GFP_NOFAIL ?? */
	sg = rsp->sg = scst_alloc(PAGE_SIZE, GFP_KERNEL|__GFP_NOFAIL,
				&rsp->sg_cnt);
	if (sg == NULL) {
		;/* ToDo */;
	}
	rsp->own_sg = 1;
	addr = page_address(sg_page(&sg[0]));
	clear_page(addr);
	memcpy(addr, &req->pdu.bhs, sizeof(struct iscsi_hdr));
	rsp->bufflen = rsp->pdu.datasize = sizeof(struct iscsi_hdr);

	iscsi_cmnd_init_write(rsp, ISCSI_INIT_WRITE_REMOVE_HASH |
					 ISCSI_INIT_WRITE_WAKE);

	cmnd_prepare_get_rejected_cmd_data(req);
}

static inline int iscsi_get_allowed_cmds(struct iscsi_session *sess)
{
	int res = max(-1, (int)sess->max_queued_cmnds -
				atomic_read(&sess->active_cmds)-1);
	TRACE_DBG("allowed cmds %d (sess %p, active_cmds %d)", res,
		sess, atomic_read(&sess->active_cmds));
	return res;
}

static u32 cmnd_set_sn(struct iscsi_cmnd *cmnd, int set_stat_sn)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_session *sess = conn->session;
	u32 res;

	spin_lock(&sess->sn_lock);

	if (set_stat_sn)
		cmnd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn++);
	cmnd->pdu.bhs.exp_sn = cpu_to_be32(sess->exp_cmd_sn);
	cmnd->pdu.bhs.max_sn = cpu_to_be32(sess->exp_cmd_sn +
				 iscsi_get_allowed_cmds(sess));

	res = cpu_to_be32(conn->stat_sn);

	spin_unlock(&sess->sn_lock);
	return res;
}

/* Called under sn_lock */
static void __update_stat_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	u32 exp_stat_sn;

	cmnd->pdu.bhs.exp_sn = exp_stat_sn = be32_to_cpu(cmnd->pdu.bhs.exp_sn);
	TRACE_DBG("%x,%x", cmnd_opcode(cmnd), exp_stat_sn);
	if ((int)(exp_stat_sn - conn->exp_stat_sn) > 0 &&
	    (int)(exp_stat_sn - conn->stat_sn) <= 0) {
		/* free pdu resources */
		cmnd->conn->exp_stat_sn = exp_stat_sn;
	}
}

static inline void update_stat_sn(struct iscsi_cmnd *cmnd)
{
	spin_lock(&cmnd->conn->session->sn_lock);
	__update_stat_sn(cmnd);
	spin_unlock(&cmnd->conn->session->sn_lock);
}

/* Called under sn_lock */
static int check_cmd_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	u32 cmd_sn;

	cmnd->pdu.bhs.sn = cmd_sn = be32_to_cpu(cmnd->pdu.bhs.sn);
	TRACE_DBG("%d(%d)", cmd_sn, session->exp_cmd_sn);
	if (likely((s32)(cmd_sn - session->exp_cmd_sn) >= 0))
		return 0;
	PRINT_ERROR("sequence error (%x,%x)", cmd_sn, session->exp_cmd_sn);
	return -ISCSI_REASON_PROTOCOL_ERROR;
}

static inline struct iscsi_cmnd *__cmnd_find_hash(
	struct iscsi_session *session, u32 itt, u32 ttt)
{
	struct list_head *head;
	struct iscsi_cmnd *cmnd;

	head = &session->cmnd_hash[cmnd_hashfn(itt)];

	list_for_each_entry(cmnd, head, hash_list_entry) {
		if (cmnd->pdu.bhs.itt == itt) {
			if (ttt != ISCSI_RESERVED_TAG &&
			    ttt != cmnd->target_task_tag)
				continue;
			return cmnd;
		}
	}
	return NULL;
}

static struct iscsi_cmnd *cmnd_find_hash(struct iscsi_session *session,
	u32 itt, u32 ttt)
{
	struct iscsi_cmnd *cmnd;

	spin_lock(&session->cmnd_hash_lock);
	cmnd = __cmnd_find_hash(session, itt, ttt);
	spin_unlock(&session->cmnd_hash_lock);

	return cmnd;
}

static struct iscsi_cmnd *cmnd_find_hash_get(struct iscsi_session *session,
	u32 itt, u32 ttt)
{
	struct iscsi_cmnd *cmnd;

	spin_lock(&session->cmnd_hash_lock);
	cmnd = __cmnd_find_hash(session, itt, ttt);
	if (cmnd != NULL) {
		if (unlikely(cmnd_get_check(cmnd)))
			cmnd = NULL;
	}
	spin_unlock(&session->cmnd_hash_lock);

	return cmnd;
}

static int cmnd_insert_hash(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;
	struct list_head *head;
	int err = 0;
	u32 itt = cmnd->pdu.bhs.itt;

	TRACE_DBG("%p:%x", cmnd, itt);
	if (unlikely(itt == ISCSI_RESERVED_TAG)) {
		PRINT_ERROR("%s", "ITT is RESERVED_TAG");
		PRINT_BUFFER("Incorrect BHS", &cmnd->pdu.bhs,
			sizeof(cmnd->pdu.bhs));
		err = -ISCSI_REASON_PROTOCOL_ERROR;
		goto out;
	}

	spin_lock(&session->cmnd_hash_lock);

	head = &session->cmnd_hash[cmnd_hashfn(cmnd->pdu.bhs.itt)];

	tmp = __cmnd_find_hash(session, itt, ISCSI_RESERVED_TAG);
	if (likely(!tmp)) {
		list_add_tail(&cmnd->hash_list_entry, head);
		cmnd->hashed = 1;
	} else {
		PRINT_ERROR("Task %x in progress, cmnd %p", itt, cmnd);
		err = -ISCSI_REASON_TASK_IN_PROGRESS;
	}

	spin_unlock(&session->cmnd_hash_lock);

	if (likely(!err)) {
		spin_lock(&session->sn_lock);
		__update_stat_sn(cmnd);
		err = check_cmd_sn(cmnd);
		spin_unlock(&session->sn_lock);
	}

out:
	return err;
}

static void cmnd_remove_hash(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;

	spin_lock(&session->cmnd_hash_lock);

	tmp = __cmnd_find_hash(session, cmnd->pdu.bhs.itt, ISCSI_RESERVED_TAG);

	if (likely(tmp && tmp == cmnd)) {
		list_del(&cmnd->hash_list_entry);
		cmnd->hashed = 0;
	} else {
		PRINT_ERROR("%p:%x not found", cmnd, cmnd_itt(cmnd));
	}

	spin_unlock(&session->cmnd_hash_lock);
}

static void cmnd_prepare_get_rejected_cmd_data(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct scatterlist *sg = cmnd->sg;
	char __user *addr;
	u32 size;
	int i;

	TRACE_MGMT_DBG("Skipping (%p, %x %x %x %u, %p, scst state %d)", cmnd,
		cmnd_itt(cmnd), cmnd_opcode(cmnd), cmnd_hdr(cmnd)->scb[0],
		cmnd->pdu.datasize, cmnd->scst_cmd, cmnd->scst_state);

	iscsi_extracheck_is_rd_thread(conn);

	size = cmnd->pdu.datasize;
	if (!size)
		return;

	if (sg == NULL) {
		/*
		 * There are no problems with the safety from concurrent
		 * accesses to dummy_page in dummy_sg, since data only
		 * will be read and then discarded.
		 */
		sg = cmnd->sg = &dummy_sg;
		cmnd->bufflen = PAGE_SIZE;
		cmnd->own_sg = 1;
	}

	addr = page_address(sg_page(&sg[0]));
	sBUG_ON(addr == NULL);
	size = (size + 3) & -4;
	conn->read_size = size;
	for (i = 0; size > PAGE_SIZE; i++, size -= cmnd->bufflen) {
		sBUG_ON(i >= ISCSI_CONN_IOV_MAX);
		conn->read_iov[i].iov_base = addr;
		conn->read_iov[i].iov_len = cmnd->bufflen;
	}
	conn->read_iov[i].iov_base = addr;
	conn->read_iov[i].iov_len = size;
	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_msg.msg_iovlen = ++i;

	return;
}

static void cmnd_reject_scsi_cmd(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_scsi_rsp_hdr *rsp_hdr;
	u32 size;

	TRACE_DBG("%p", req);

	sBUG_ON(req->rejected);
	req->rejected = 1;
	req->reject_reason = ISCSI_REJECT_SCSI_CMD;

	rsp = get_rsp_cmnd(req);
	if (rsp == NULL) {
		/* That can be true for aborted commands */
		goto out_reject;
	}

	rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;

	sBUG_ON(cmnd_opcode(rsp) != ISCSI_OP_SCSI_RSP);

	size = cmnd_write_size(req);
	if (size) {
		rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
		rsp_hdr->residual_count = cpu_to_be32(size);
	}
	size = cmnd_read_size(req);
	if (size) {
		if (cmnd_hdr(req)->flags & ISCSI_CMD_WRITE) {
			rsp_hdr->flags |= ISCSI_FLG_BIRESIDUAL_UNDERFLOW;
			rsp_hdr->bi_residual_count = cpu_to_be32(size);
		} else {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(size);
		}
	}

	iscsi_cmnd_init_write(rsp, ISCSI_INIT_WRITE_REMOVE_HASH |
					 ISCSI_INIT_WRITE_WAKE);

out_reject:
	cmnd_prepare_get_rejected_cmd_data(req);
	return;
}

static int cmnd_prepare_recv_pdu(struct iscsi_conn *conn,
	struct iscsi_cmnd *cmd,	u32 offset, u32 size)
{
	struct scatterlist *sg = cmd->sg;
	int bufflen = cmd->bufflen;
	int idx, i;
	char *addr;
	int res = 0;

	TRACE_DBG("%p %u,%u", cmd->sg, offset, size);

	iscsi_extracheck_is_rd_thread(conn);

	if (unlikely((offset >= bufflen) ||
		     (offset + size > bufflen))) {
		PRINT_ERROR("Wrong ltn (%u %u %u)", offset, size, bufflen);
		mark_conn_closed(conn);
		res = -EIO;
		goto out;
	}

	offset += sg[0].offset;
	idx = offset >> PAGE_SHIFT;
	offset &= ~PAGE_MASK;

	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_size = size = (size + 3) & -4;

	i = 0;
	while (1) {
		addr = page_address(sg_page(&sg[idx]));
		sBUG_ON(addr == NULL);
		conn->read_iov[i].iov_base = addr + offset;
		if (offset + size <= PAGE_SIZE) {
			TRACE_DBG("idx=%d, offset=%u, size=%d, addr=%p",
				idx, offset, size, addr);
			conn->read_iov[i].iov_len = size;
			conn->read_msg.msg_iovlen = ++i;
			break;
		}
		conn->read_iov[i].iov_len = PAGE_SIZE - offset;
		TRACE_DBG("idx=%d, offset=%u, size=%d, iov_len=%zd, addr=%p",
			idx, offset, size, conn->read_iov[i].iov_len, addr);
		size -= conn->read_iov[i].iov_len;
		offset = 0;
		if (unlikely(++i >= ISCSI_CONN_IOV_MAX)) {
			PRINT_ERROR("Initiator %s violated negotiated "
				"parameters by sending too much data (size "
				"left %d)", conn->session->initiator_name,
				size);
			mark_conn_closed(conn);
			res = -EINVAL;
			break;
		}
		idx++;
	}
	TRACE_DBG("msg_iov=%p, msg_iovlen=%zd",
		conn->read_msg.msg_iov, conn->read_msg.msg_iovlen);

out:
	return res;
}

static void send_r2t(struct iscsi_cmnd *req)
{
	struct iscsi_session *session = req->conn->session;
	struct iscsi_cmnd *rsp;
	struct iscsi_r2t_hdr *rsp_hdr;
	u32 offset, burst;
	LIST_HEAD(send);

	if (unlikely(req->tm_aborted)) {
		TRACE_MGMT_DBG("req %p (scst_cmd %p) aborted on R2T "
			"(r2t_length %d, outstanding_r2t %d)", req,
			req->scst_cmd, req->r2t_length, req->outstanding_r2t);
		if (req->outstanding_r2t == 0)
			iscsi_fail_waiting_cmnd(req);
		goto out;
	}

	/*
	 * There is no race with data_out_start() and conn_abort(), since
	 * all functions called from single read thread
	 */
	iscsi_extracheck_is_rd_thread(req->conn);

	burst = session->sess_param.max_burst_length;
	offset = be32_to_cpu(cmnd_hdr(req)->data_length) - req->r2t_length;

	do {
		rsp = iscsi_cmnd_create_rsp_cmnd(req);
		rsp->pdu.bhs.ttt = req->target_task_tag;
		rsp_hdr = (struct iscsi_r2t_hdr *)&rsp->pdu.bhs;
		rsp_hdr->opcode = ISCSI_OP_R2T;
		rsp_hdr->flags = ISCSI_FLG_FINAL;
		rsp_hdr->lun = cmnd_hdr(req)->lun;
		rsp_hdr->itt = cmnd_hdr(req)->itt;
		rsp_hdr->r2t_sn = cpu_to_be32(req->r2t_sn++);
		rsp_hdr->buffer_offset = cpu_to_be32(offset);
		if (req->r2t_length > burst) {
			rsp_hdr->data_length = cpu_to_be32(burst);
			req->r2t_length -= burst;
			offset += burst;
		} else {
			rsp_hdr->data_length = cpu_to_be32(req->r2t_length);
			req->r2t_length = 0;
		}

		TRACE_WRITE("%x %u %u %u %u", cmnd_itt(req),
			be32_to_cpu(rsp_hdr->data_length),
			be32_to_cpu(rsp_hdr->buffer_offset),
			be32_to_cpu(rsp_hdr->r2t_sn), req->outstanding_r2t);

		list_add_tail(&rsp->write_list_entry, &send);

		if (++req->outstanding_r2t >= session->sess_param.max_outstanding_r2t)
			break;

	} while (req->r2t_length != 0);

	iscsi_cmnds_init_write(&send, ISCSI_INIT_WRITE_WAKE);

out:
	return;
}

static int iscsi_pre_exec(struct scst_cmd *scst_cmd)
{
	int res = SCST_PREPROCESS_STATUS_SUCCESS;
	struct iscsi_cmnd *req = (struct iscsi_cmnd *)
		scst_cmd_get_tgt_priv(scst_cmd);
	struct iscsi_cmnd *c, *t;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(scst_cmd_atomic(scst_cmd));

	if (scst_cmd_get_data_direction(scst_cmd) == SCST_DATA_READ) {
		EXTRACHECKS_BUG_ON(!list_empty(&req->rx_ddigest_cmd_list));
		goto out;
	}

	/* If data digest isn't used this list will be empty */
	list_for_each_entry_safe(c, t, &req->rx_ddigest_cmd_list,
				rx_ddigest_cmd_list_entry) {
		TRACE_DBG("Checking digest of RX ddigest cmd %p", c);
		if (digest_rx_data(c) != 0) {
			scst_set_cmd_error(scst_cmd,
				SCST_LOAD_SENSE(iscsi_sense_crc_error));
			res = SCST_PREPROCESS_STATUS_ERROR_SENSE_SET;
			/*
			 * The rest of rx_ddigest_cmd_list will be freed
			 * in req_cmnd_release()
			 */
			goto out;
		}
		cmd_del_from_rx_ddigest_list(c);
		cmnd_put(c);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int noop_out_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	u32 size, tmp;
	int i, err = 0;

	TRACE_DBG("%p", cmnd);

	iscsi_extracheck_is_rd_thread(conn);

	if (unlikely(cmnd_ttt(cmnd) != cpu_to_be32(ISCSI_RESERVED_TAG))) {
		/*
		 * We don't request a NOP-Out by sending a NOP-In.
		 * See 10.18.2 in the draft 20.
		 */
		PRINT_ERROR("Initiator sent command with not RESERVED tag and "
			"TTT %x", cmnd_itt(cmnd));
		err = -ISCSI_REASON_PROTOCOL_ERROR;
		goto out;
	}

	if (cmnd_itt(cmnd) == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		if (unlikely(!(cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE)))
			PRINT_ERROR("%s", "Initiator sent RESERVED tag for "
				"non-immediate command");
		spin_lock(&conn->session->sn_lock);
		__update_stat_sn(cmnd);
		err = check_cmd_sn(cmnd);
		spin_unlock(&conn->session->sn_lock);
		if (unlikely(err))
			goto out;
	} else {
		err = cmnd_insert_hash(cmnd);
		if (unlikely(err < 0)) {
			PRINT_ERROR("Can't insert in hash: ignore this "
				"request %x", cmnd_itt(cmnd));
			goto out;
		}
	}

	size = cmnd->pdu.datasize;

	if (size) {
		size = (size + 3) & -4;
		conn->read_msg.msg_iov = conn->read_iov;
		if (cmnd->pdu.bhs.itt != cpu_to_be32(ISCSI_RESERVED_TAG)) {
			struct scatterlist *sg;

			cmnd->sg = sg = scst_alloc(size, GFP_KERNEL,
						&cmnd->sg_cnt);
			if (sg == NULL) {
				TRACE(TRACE_OUT_OF_MEM, "Allocating buffer for"
				      " %d NOP-Out payload failed", size);
				err = -ISCSI_REASON_OUT_OF_RESOURCES;
				goto out;
			}

			/* We already checked it in check_segment_length() */
			sBUG_ON(cmnd->sg_cnt > ISCSI_CONN_IOV_MAX);

			cmnd->own_sg = 1;
			cmnd->bufflen = size;

			for (i = 0; i < cmnd->sg_cnt; i++) {
				conn->read_iov[i].iov_base =
					page_address(sg_page(&sg[i]));
				tmp = min_t(u32, size, PAGE_SIZE);
				conn->read_iov[i].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
			}
			sBUG_ON(size != 0);
		} else {
			/*
			 * There are no problems with the safety from concurrent
			 * accesses to dummy_page, since for ISCSI_RESERVED_TAG
			 * the data only read and then discarded.
			 */
			for (i = 0; i < ISCSI_CONN_IOV_MAX; i++) {
				conn->read_iov[i].iov_base =
					page_address(dummy_page);
				tmp = min_t(u32, size, PAGE_SIZE);
				conn->read_iov[i].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
			}

			/* We already checked size in check_segment_length() */
			sBUG_ON(size != 0);
		}

		conn->read_msg.msg_iovlen = i;
		TRACE_DBG("msg_iov=%p, msg_iovlen=%zd", conn->read_msg.msg_iov,
			conn->read_msg.msg_iovlen);
	}

out:
	return err;
}

static inline u32 get_next_ttt(struct iscsi_conn *conn)
{
	u32 ttt;
	struct iscsi_session *session = conn->session;

	iscsi_extracheck_is_rd_thread(conn);

	if (session->next_ttt == ISCSI_RESERVED_TAG)
		session->next_ttt++;
	ttt = session->next_ttt++;

	return cpu_to_be32(ttt);
}

static int scsi_cmnd_start(struct iscsi_cmnd *req)
{
	struct iscsi_conn *conn = req->conn;
	struct iscsi_session *session = conn->session;
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);
	struct scst_cmd *scst_cmd;
	scst_data_direction dir;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("scsi command: %02x", req_hdr->scb[0]);

	TRACE_DBG("Incrementing active_cmds (cmd %p, sess %p, "
		"new value %d)", req, session,
		atomic_read(&session->active_cmds)+1);
	atomic_inc(&session->active_cmds);
	req->dec_active_cmnds = 1;

	scst_cmd = scst_rx_cmd(session->scst_sess,
		(uint8_t *)&req_hdr->lun, sizeof(req_hdr->lun),
		req_hdr->scb, sizeof(req_hdr->scb), SCST_NON_ATOMIC);
	if (scst_cmd == NULL) {
		create_status_rsp(req, SAM_STAT_BUSY, NULL, 0);
		cmnd_reject_scsi_cmd(req);
		goto out;
	}

	req->scst_cmd = scst_cmd;
	scst_cmd_set_tag(scst_cmd, req_hdr->itt);
	scst_cmd_set_tgt_priv(scst_cmd, req);

	if (req_hdr->flags & ISCSI_CMD_READ) {
		dir = SCST_DATA_READ;
#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
		scst_cmd_set_tgt_need_alloc_data_buf(scst_cmd);
#endif
	} else if (req_hdr->flags & ISCSI_CMD_WRITE)
		dir = SCST_DATA_WRITE;
	else
		dir = SCST_DATA_NONE;
	scst_cmd_set_expected(scst_cmd, dir,
		be32_to_cpu(req_hdr->data_length));

	switch (req_hdr->flags & ISCSI_CMD_ATTR_MASK) {
	case ISCSI_CMD_SIMPLE:
		scst_cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
		break;
	case ISCSI_CMD_HEAD_OF_QUEUE:
		scst_cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
		break;
	case ISCSI_CMD_ORDERED:
		scst_cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
		break;
	case ISCSI_CMD_ACA:
		scst_cmd->queue_type = SCST_CMD_QUEUE_ACA;
		break;
	case ISCSI_CMD_UNTAGGED:
		scst_cmd->queue_type = SCST_CMD_QUEUE_UNTAGGED;
		break;
	default:
		PRINT_ERROR("Unknown task code %x, use ORDERED instead",
			req_hdr->flags & ISCSI_CMD_ATTR_MASK);
		scst_cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
		break;
	}

	/* cmd_sn is already in CPU format converted in check_cmd_sn() */
	scst_cmd_set_tgt_sn(scst_cmd, req_hdr->cmd_sn);

	TRACE_DBG("START Command (tag %d, queue_type %d)",
		req_hdr->itt, scst_cmd->queue_type);
	req->scst_state = ISCSI_CMD_STATE_RX_CMD;
	scst_cmd_init_stage1_done(scst_cmd, SCST_CONTEXT_DIRECT, 0);

	wait_event(req->scst_waitQ, req->scst_state != ISCSI_CMD_STATE_RX_CMD);

	if (unlikely(req->scst_state != ISCSI_CMD_STATE_AFTER_PREPROC)) {
		TRACE_DBG("req %p is in %x state", req, req->scst_state);
		if (req->scst_state == ISCSI_CMD_STATE_PROCESSED) {
			cmnd_reject_scsi_cmd(req);
			goto out;
		}
		if (unlikely(req->tm_aborted)) {
			TRACE_MGMT_DBG("req %p (scst_cmd %p) aborted", req,
				req->scst_cmd);
			cmnd_prepare_get_rejected_cmd_data(req);
			goto out;
		}
		sBUG();
	}

	dir = scst_cmd_get_data_direction(scst_cmd);
	if (dir != SCST_DATA_WRITE) {
		if (unlikely(!(req_hdr->flags & ISCSI_CMD_FINAL) ||
			     req->pdu.datasize)) {
			PRINT_ERROR("Unexpected unsolicited data (ITT %x "
				"CDB %x", cmnd_itt(req), req_hdr->scb[0]);
			create_sense_rsp(req, ABORTED_COMMAND, 0xc, 0xc);
			cmnd_reject_scsi_cmd(req);
			goto out;
		}
	}

	if (dir == SCST_DATA_WRITE) {
		req->is_unsolicited_data = !(req_hdr->flags & ISCSI_CMD_FINAL);
		req->r2t_length = be32_to_cpu(req_hdr->data_length) -
					req->pdu.datasize;
		if (req->r2t_length > 0)
			req->data_waiting = 1;
	}
	req->target_task_tag = get_next_ttt(conn);
	req->sg = scst_cmd_get_sg(scst_cmd);
	req->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	req->bufflen = scst_cmd_get_bufflen(scst_cmd);
	if (unlikely(req->r2t_length > req->bufflen)) {
		PRINT_ERROR("req->r2t_length %d > req->bufflen %d",
			req->r2t_length, req->bufflen);
		req->r2t_length = req->bufflen;
	}

	TRACE_DBG("req=%p, dir=%d, is_unsolicited_data=%d, "
		"r2t_length=%d, bufflen=%d", req, dir,
		req->is_unsolicited_data, req->r2t_length, req->bufflen);

	if (unlikely(!session->sess_param.immediate_data &&
		     req->pdu.datasize)) {
		PRINT_ERROR("Initiator %s violated negotiated paremeters: "
			"forbidden immediate data sent (ITT %x, op  %x)",
			session->initiator_name, cmnd_itt(req),
			req_hdr->scb[0]);
		res = -EINVAL;
		goto out;
	}

	if (unlikely(session->sess_param.initial_r2t &&
		     !(req_hdr->flags & ISCSI_CMD_FINAL))) {
		PRINT_ERROR("Initiator %s violated negotiated paremeters: "
			"initial R2T is required (ITT %x, op  %x)",
			session->initiator_name, cmnd_itt(req),
			req_hdr->scb[0]);
		res = -EINVAL;
		goto out;
	}

	if (req->pdu.datasize) {
		if (unlikely(dir != SCST_DATA_WRITE)) {
			PRINT_ERROR("pdu.datasize(%d) >0, but dir(%x) isn't "
				"WRITE", req->pdu.datasize, dir);
			create_sense_rsp(req, ABORTED_COMMAND, 0xc, 0xc);
			cmnd_reject_scsi_cmd(req);
		} else
			res = cmnd_prepare_recv_pdu(conn, req, 0,
				req->pdu.datasize);
	}
out:
	/* Aborted commands will be freed in cmnd_rx_end() */
	TRACE_EXIT_RES(res);
	return res;
}

static int data_out_start(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	struct iscsi_data_out_hdr *req_hdr =
		(struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
	struct iscsi_cmnd *orig_req = NULL;
	u32 offset = be32_to_cpu(req_hdr->buffer_offset);
	int res = 0;

	TRACE_ENTRY();

	/*
	 * There is no race with send_r2t() and conn_abort(), since
	 * all functions called from single read thread
	 */
	iscsi_extracheck_is_rd_thread(cmnd->conn);

	update_stat_sn(cmnd);

	cmnd->cmd_req = orig_req = cmnd_find_hash(conn->session, req_hdr->itt,
					req_hdr->ttt);
	if (unlikely(orig_req == NULL)) {
		/* It might happen if req was aborted and then freed */
		TRACE(TRACE_MGMT_MINOR, "Unable to find scsi task %x %x",
			cmnd_itt(cmnd), cmnd_ttt(cmnd));
		goto out_reject;
	}

	if (orig_req->is_unsolicited_data) {
		if (unlikely(orig_req->r2t_length < cmnd->pdu.datasize)) {
			PRINT_ERROR("Data size (%d) > R2T length (%d)",
				cmnd->pdu.datasize, orig_req->r2t_length);
			mark_conn_closed(conn);
			res = -EINVAL;
			goto out;
		}
		orig_req->r2t_length -= cmnd->pdu.datasize;
	}

	/* Check unsolicited burst data */
	if (unlikely((req_hdr->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) &&
		     (orig_req->pdu.bhs.flags & ISCSI_FLG_FINAL))) {
		PRINT_ERROR("Unexpected data from %x %x",
			cmnd_itt(cmnd), cmnd_ttt(cmnd));
		mark_conn_closed(conn);
		res = -EINVAL;
		goto out;
	}

	TRACE_WRITE("%u %p %p %u %u", req_hdr->ttt, cmnd, orig_req,
		offset, cmnd->pdu.datasize);

	res = cmnd_prepare_recv_pdu(conn, orig_req, offset, cmnd->pdu.datasize);

out:
	TRACE_EXIT_RES(res);
	return res;

out_reject:
	sBUG_ON(cmnd->rejected);
	cmnd->rejected = 1;
	cmnd->reject_reason = ISCSI_REJECT_DATA;
	cmnd_prepare_get_rejected_cmd_data(cmnd);
	goto out;
}

static void data_out_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_data_out_hdr *req_hdr =
		(struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
	struct iscsi_cmnd *req;

	sBUG_ON(cmnd == NULL);
	req = cmnd->cmd_req;
	sBUG_ON(req == NULL);

	TRACE_DBG("cmnd %p, req %p", cmnd, req);

	iscsi_extracheck_is_rd_thread(cmnd->conn);

	if (!(cmnd->conn->ddigest_type & DIGEST_NONE) &&
	    !cmnd->ddigest_checked) {
		cmd_add_on_rx_ddigest_list(req, cmnd);
		cmnd_get(cmnd);
	}

	if (req_hdr->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		TRACE_DBG("ISCSI_RESERVED_TAG, FINAL %x",
			req_hdr->flags & ISCSI_FLG_FINAL);

		if (req_hdr->flags & ISCSI_FLG_FINAL) {
			req->is_unsolicited_data = 0;
			if (req->pending)
				goto out_put;
		} else
			goto out_put;
	} else {
		TRACE_DBG("FINAL %x, outstanding_r2t %d, r2t_length %d",
			req_hdr->flags & ISCSI_FLG_FINAL,
			req->outstanding_r2t, req->r2t_length);

		if (req_hdr->flags & ISCSI_FLG_FINAL) {
			if (unlikely(req->is_unsolicited_data)) {
				PRINT_ERROR("Unexpected unsolicited data "
					"(r2t_length %u, outstanding_r2t %d)",
					req->r2t_length,
					req->is_unsolicited_data);
				mark_conn_closed(req->conn);
				goto out_put;
			}
			req->outstanding_r2t--;
		} else
			goto out_put;
	}

	if (req->r2t_length != 0) {
		if (!req->is_unsolicited_data)
			send_r2t(req);
	} else
		iscsi_restart_waiting_cmnd(req);

out_put:
	cmnd_put(cmnd);
	return;
}

static void __cmnd_abort(struct iscsi_cmnd *cmnd)
{
	/*
	 * Here, if cmnd is data_waiting, we should iscsi_fail_waiting_cmnd()
	 * it. But, since this function can be called from any thread, not only
	 * from the read one, we at the moment can't do that, because of
	 * absence of appropriate locking protection. But this isn't a stuff
	 * for 1.0.0. So, currently a misbehaving initiator, not sending
	 * data in R2T state for a sharing between targets device, for which
	 * for some reason an aborting TM command, e.g. TARGET RESET, from
	 * another initiator is issued, can block response for this TM command
	 * virtually forever and by this make the issuing initiator eventually
	 * put the device offline.
	 *
	 * ToDo in the next version, possibly a simple connection mutex, taken
	 * by the read thread before starting any processing and by this
	 * function, should be sufficient.
	 */

	TRACE_MGMT_DBG("Aborting cmd %p, scst_cmd %p (scst state %x, "
		"ref_cnt %d, itt %x, sn %u, op %x, r2t_len %x, CDB op %x, "
		"size to write %u, is_unsolicited_data %d, "
		"outstanding_r2t %d, data_waiting %d, sess->exp_cmd_sn %u, "
		"conn %p, rd_task %p)", cmnd, cmnd->scst_cmd, cmnd->scst_state,
		atomic_read(&cmnd->ref_cnt), cmnd_itt(cmnd), cmnd->pdu.bhs.sn,
		cmnd_opcode(cmnd), cmnd->r2t_length, cmnd_scsicode(cmnd),
		cmnd_write_size(cmnd), cmnd->is_unsolicited_data,
		cmnd->outstanding_r2t, cmnd->data_waiting,
		cmnd->conn->session->exp_cmd_sn, cmnd->conn,
		cmnd->conn->rd_task);

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	TRACE_MGMT_DBG("net_ref_cnt %d", atomic_read(&cmnd->net_ref_cnt));
#endif

	cmnd->tm_aborted = 1;

	return;
}

/* Must be called from the read thread */
static int cmnd_abort(struct iscsi_cmnd *req)
{
	struct iscsi_session *session = req->conn->session;
	struct iscsi_task_mgt_hdr *req_hdr =
		(struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
	struct iscsi_cmnd *cmnd;
	int err;

	req_hdr->ref_cmd_sn = be32_to_cpu(req_hdr->ref_cmd_sn);

	if (after(req_hdr->ref_cmd_sn, req_hdr->cmd_sn)) {
		PRINT_ERROR("ABORT TASK: RefCmdSN(%u) > CmdSN(%u)",
			req_hdr->ref_cmd_sn, req_hdr->cmd_sn);
		err = ISCSI_RESPONSE_FUNCTION_REJECTED;
		goto out;
	}

	cmnd = cmnd_find_hash_get(session, req_hdr->rtt, ISCSI_RESERVED_TAG);
	if (cmnd) {
		struct iscsi_conn *conn = cmnd->conn;
		struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

		if (req_hdr->lun != hdr->lun) {
			PRINT_ERROR("ABORT TASK: LUN mismatch: req LUN "
				    "%llx, cmd LUN %llx, rtt %u",
				    (long long unsigned int)req_hdr->lun,
				    (long long unsigned int)hdr->lun,
				    req_hdr->rtt);
			err = ISCSI_RESPONSE_FUNCTION_REJECTED;
			goto out_put;
		}

		if (cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) {
			if (req_hdr->ref_cmd_sn != req_hdr->cmd_sn) {
				PRINT_ERROR("ABORT TASK: RefCmdSN(%u) != TM "
					"cmd CmdSN(%u) for immediate command "
					"%p", req_hdr->ref_cmd_sn,
					req_hdr->cmd_sn, cmnd);
				err = ISCSI_RESPONSE_FUNCTION_REJECTED;
				goto out_put;
			}
		} else {
			if (req_hdr->ref_cmd_sn != hdr->cmd_sn) {
				PRINT_ERROR("ABORT TASK: RefCmdSN(%u) != "
					"CmdSN(%u) for command %p",
					req_hdr->ref_cmd_sn, req_hdr->cmd_sn,
					cmnd);
				err = ISCSI_RESPONSE_FUNCTION_REJECTED;
				goto out_put;
			}
		}

		if (before(req_hdr->cmd_sn, hdr->cmd_sn) ||
		    (req_hdr->cmd_sn == hdr->cmd_sn)) {
			PRINT_ERROR("ABORT TASK: SN mismatch: req SN %x, "
				"cmd SN %x, rtt %u", req_hdr->cmd_sn,
				hdr->cmd_sn, req_hdr->rtt);
			err = ISCSI_RESPONSE_FUNCTION_REJECTED;
			goto out_put;
		}

		spin_lock_bh(&conn->cmd_list_lock);
		__cmnd_abort(cmnd);
		spin_unlock_bh(&conn->cmd_list_lock);

		cmnd_put(cmnd);
		err = 0;
	} else {
		TRACE_MGMT_DBG("cmd RTT %x not found", req_hdr->rtt);
		err = ISCSI_RESPONSE_UNKNOWN_TASK;
	}

out:
	return err;

out_put:
	cmnd_put(cmnd);
	goto out;
}

/* Must be called from the read thread */
static int target_abort(struct iscsi_cmnd *req, int all)
{
	struct iscsi_target *target = req->conn->session->target;
	struct iscsi_task_mgt_hdr *req_hdr =
		(struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
	struct iscsi_session *session;
	struct iscsi_conn *conn;
	struct iscsi_cmnd *cmnd;

	mutex_lock(&target->target_mutex);

	list_for_each_entry(session, &target->session_list,
			    session_list_entry) {
		list_for_each_entry(conn, &session->conn_list,
				    conn_list_entry) {
			spin_lock_bh(&conn->cmd_list_lock);
			list_for_each_entry(cmnd, &conn->cmd_list,
					    cmd_list_entry) {
				if (cmnd == req)
					continue;
				if (all)
					__cmnd_abort(cmnd);
				else if (req_hdr->lun == cmnd_hdr(cmnd)->lun)
					__cmnd_abort(cmnd);
			}
			spin_unlock_bh(&conn->cmd_list_lock);
		}
	}

	mutex_unlock(&target->target_mutex);
	return 0;
}

/* Must be called from the read thread */
static void task_set_abort(struct iscsi_cmnd *req)
{
	struct iscsi_session *session = req->conn->session;
	struct iscsi_task_mgt_hdr *req_hdr =
		(struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
	struct iscsi_target *target = session->target;
	struct iscsi_conn *conn;
	struct iscsi_cmnd *cmnd;

	mutex_lock(&target->target_mutex);

	list_for_each_entry(conn, &session->conn_list, conn_list_entry) {
		spin_lock_bh(&conn->cmd_list_lock);
		list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
			struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);
			if (cmnd == req)
				continue;
			if (req_hdr->lun != hdr->lun)
				continue;
			if (before(req_hdr->cmd_sn, hdr->cmd_sn) ||
			    req_hdr->cmd_sn == hdr->cmd_sn)
				continue;
			__cmnd_abort(cmnd);
		}
		spin_unlock_bh(&conn->cmd_list_lock);
	}

	mutex_unlock(&target->target_mutex);
	return;
}

/* Must be called from the read thread */
void conn_abort(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd;

	TRACE_MGMT_DBG("Aborting conn %p", conn);

	iscsi_extracheck_is_rd_thread(conn);

	spin_lock_bh(&conn->cmd_list_lock);
again:
	list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
		__cmnd_abort(cmnd);
		if (cmnd->data_waiting) {
			if (!cmnd_get_check(cmnd)) {
				spin_unlock_bh(&conn->cmd_list_lock);

				/* ToDo: this is racy for MC/S */
				TRACE_MGMT_DBG("Restarting data waiting cmd "
					"%p", cmnd);
				iscsi_fail_waiting_cmnd(cmnd);

				cmnd_put(cmnd);

				/*
				 * We are in the read thread, so we may not
				 * worry that after cmnd release conn gets
				 * released as well.
				 */
				spin_lock_bh(&conn->cmd_list_lock);
				goto again;
			}
		}
	}
	spin_unlock_bh(&conn->cmd_list_lock);

	return;
}

static void execute_task_management(struct iscsi_cmnd *req)
{
	struct iscsi_conn *conn = req->conn;
	struct iscsi_session *sess = conn->session;
	struct iscsi_task_mgt_hdr *req_hdr =
		(struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
	int rc, status, function = req_hdr->function & ISCSI_FUNCTION_MASK;
	struct scst_rx_mgmt_params params;

	TRACE((function == ISCSI_FUNCTION_ABORT_TASK) ?
			TRACE_MGMT_MINOR : TRACE_MGMT,
		"TM fn %d", function);

	TRACE_MGMT_DBG("TM req %p, itt %x, rtt %x, sn %u, con %p", req,
		cmnd_itt(req), req_hdr->rtt, req_hdr->cmd_sn, conn);

	iscsi_extracheck_is_rd_thread(conn);

	spin_lock(&sess->sn_lock);
	sess->tm_active++;
	sess->tm_sn = req_hdr->cmd_sn;
	if (sess->tm_rsp != NULL) {
		struct iscsi_cmnd *tm_rsp = sess->tm_rsp;

		TRACE(TRACE_MGMT_MINOR, "Dropping delayed TM rsp %p", tm_rsp);

		sess->tm_rsp = NULL;
		sess->tm_active--;

		spin_unlock(&sess->sn_lock);

		sBUG_ON(sess->tm_active < 0);

		rsp_cmnd_release(tm_rsp);
	} else
		spin_unlock(&sess->sn_lock);

	memset(&params, 0, sizeof(params));
	params.atomic = SCST_NON_ATOMIC;
	params.tgt_priv = req;

	if ((function != ISCSI_FUNCTION_ABORT_TASK) &&
	    (req_hdr->rtt != ISCSI_RESERVED_TAG)) {
		PRINT_ERROR("Invalid RTT %x (TM fn %x)", req_hdr->rtt,
			function);
		rc = -1;
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		goto reject;
	}

	/* cmd_sn is already in CPU format converted in check_cmd_sn() */

	switch (function) {
	case ISCSI_FUNCTION_ABORT_TASK:
		rc = -1;
		status = cmnd_abort(req);
		if (status == 0) {
			params.fn = SCST_ABORT_TASK;
			params.tag = req_hdr->rtt;
			params.tag_set = 1;
			params.lun = (uint8_t *)&req_hdr->lun;
			params.lun_len = sizeof(req_hdr->lun);
			params.lun_set = 1;
			params.cmd_sn = req_hdr->cmd_sn;
			params.cmd_sn_set = 1;
			rc = scst_rx_mgmt_fn(conn->session->scst_sess,
				&params);
			status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		}
		break;
	case ISCSI_FUNCTION_ABORT_TASK_SET:
		task_set_abort(req);
		params.fn = SCST_ABORT_TASK_SET;
		params.lun = (uint8_t *)&req_hdr->lun;
		params.lun_len = sizeof(req_hdr->lun);
		params.lun_set = 1;
		params.cmd_sn = req_hdr->cmd_sn;
		params.cmd_sn_set = 1;
		rc = scst_rx_mgmt_fn(conn->session->scst_sess,
			&params);
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	case ISCSI_FUNCTION_CLEAR_TASK_SET:
		task_set_abort(req);
		params.fn = SCST_CLEAR_TASK_SET;
		params.lun = (uint8_t *)&req_hdr->lun;
		params.lun_len = sizeof(req_hdr->lun);
		params.lun_set = 1;
		params.cmd_sn = req_hdr->cmd_sn;
		params.cmd_sn_set = 1;
		rc = scst_rx_mgmt_fn(conn->session->scst_sess,
			&params);
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	case ISCSI_FUNCTION_CLEAR_ACA:
		params.fn = SCST_CLEAR_ACA;
		params.lun = (uint8_t *)&req_hdr->lun;
		params.lun_len = sizeof(req_hdr->lun);
		params.lun_set = 1;
		params.cmd_sn = req_hdr->cmd_sn;
		params.cmd_sn_set = 1;
		rc = scst_rx_mgmt_fn(conn->session->scst_sess,
			&params);
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	case ISCSI_FUNCTION_TARGET_COLD_RESET:
	case ISCSI_FUNCTION_TARGET_WARM_RESET:
		target_abort(req, 1);
		params.fn = SCST_TARGET_RESET;
		params.cmd_sn = req_hdr->cmd_sn;
		params.cmd_sn_set = 1;
		rc = scst_rx_mgmt_fn(conn->session->scst_sess,
			&params);
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	case ISCSI_FUNCTION_LOGICAL_UNIT_RESET:
		target_abort(req, 0);
		params.fn = SCST_LUN_RESET;
		params.lun = (uint8_t *)&req_hdr->lun;
		params.lun_len = sizeof(req_hdr->lun);
		params.lun_set = 1;
		params.cmd_sn = req_hdr->cmd_sn;
		params.cmd_sn_set = 1;
		rc = scst_rx_mgmt_fn(conn->session->scst_sess,
			&params);
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	case ISCSI_FUNCTION_TASK_REASSIGN:
		rc = -1;
		status = ISCSI_RESPONSE_ALLEGIANCE_REASSIGNMENT_UNSUPPORTED;
		break;
	default:
		PRINT_ERROR("Unknown TM function %d", function);
		rc = -1;
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	}

reject:
	if (rc != 0)
		iscsi_send_task_mgmt_resp(req, status);

	return;
}

static void noop_out_exec(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_nop_in_hdr *rsp_hdr;

	TRACE_DBG("%p", req);

	if (cmnd_itt(req) != cpu_to_be32(ISCSI_RESERVED_TAG)) {
		rsp = iscsi_cmnd_create_rsp_cmnd(req);

		rsp_hdr = (struct iscsi_nop_in_hdr *)&rsp->pdu.bhs;
		rsp_hdr->opcode = ISCSI_OP_NOOP_IN;
		rsp_hdr->flags = ISCSI_FLG_FINAL;
		rsp_hdr->itt = req->pdu.bhs.itt;
		rsp_hdr->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);

		if (req->pdu.datasize)
			sBUG_ON(req->sg == NULL);
		else
			sBUG_ON(req->sg != NULL);

		if (req->sg) {
			rsp->sg = req->sg;
			rsp->sg_cnt = req->sg_cnt;
			rsp->bufflen = req->bufflen;
		}

		sBUG_ON(get_pgcnt(req->pdu.datasize, 0) > ISCSI_CONN_IOV_MAX);

		rsp->pdu.datasize = req->pdu.datasize;
		iscsi_cmnd_init_write(rsp,
			ISCSI_INIT_WRITE_REMOVE_HASH | ISCSI_INIT_WRITE_WAKE);
		req_cmnd_release(req);
	} else
		cmnd_put(req);
}

static void logout_exec(struct iscsi_cmnd *req)
{
	struct iscsi_logout_req_hdr *req_hdr;
	struct iscsi_cmnd *rsp;
	struct iscsi_logout_rsp_hdr *rsp_hdr;

	PRINT_INFO("Logout received from initiator %s",
		req->conn->session->initiator_name);
	TRACE_DBG("%p", req);

	req_hdr = (struct iscsi_logout_req_hdr *)&req->pdu.bhs;
	rsp = iscsi_cmnd_create_rsp_cmnd(req);
	rsp_hdr = (struct iscsi_logout_rsp_hdr *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->itt = req_hdr->itt;
	rsp->should_close_conn = 1;
	iscsi_cmnd_init_write(rsp,
		ISCSI_INIT_WRITE_REMOVE_HASH | ISCSI_INIT_WRITE_WAKE);
	req_cmnd_release(req);
}

static void iscsi_cmnd_exec(struct iscsi_cmnd *cmnd)
{
	TRACE_ENTRY();

	TRACE_DBG("%p,%x,%u", cmnd, cmnd_opcode(cmnd), cmnd->pdu.bhs.sn);

	iscsi_extracheck_is_rd_thread(cmnd->conn);

	if (unlikely(cmnd->tm_aborted)) {
		TRACE_MGMT_DBG("cmnd %p (scst_cmd %p) aborted", cmnd,
			cmnd->scst_cmd);
		req_cmnd_release_force(cmnd, ISCSI_FORCE_RELEASE_WRITE);
		goto out;
	}

	if (unlikely(cmnd->rejected))
		goto out_rejected;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_CMD:
		if (cmnd->r2t_length != 0) {
			if (!cmnd->is_unsolicited_data) {
				send_r2t(cmnd);
				break;
			}
		} else
			iscsi_restart_cmnd(cmnd);
		break;
	case ISCSI_OP_NOOP_OUT:
		noop_out_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		execute_task_management(cmnd);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		logout_exec(cmnd);
		break;
	default:
		PRINT_ERROR("unexpected cmnd op %x", cmnd_opcode(cmnd));
		req_cmnd_release(cmnd);
		break;
	}
out:
	TRACE_EXIT();
	return;

out_rejected:
	TRACE_MGMT_DBG("Rejected cmd %p (reason %d)", cmnd,
		cmnd->reject_reason);
	switch (cmnd->reject_reason) {
	default:
		PRINT_ERROR("Unexpected reject reason %d",
			    cmnd->reject_reason);
		/* go through */
	case ISCSI_REJECT_SCSI_CMD:
		req_cmnd_release(cmnd);
		break;
	}
	goto out;
}

static void __cmnd_send_pdu(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd,
	u32 offset, u32 size)
{
	TRACE_DBG("%p %u,%u,%u", cmnd, offset, size, cmnd->bufflen);

	iscsi_extracheck_is_wr_thread(conn);

	sBUG_ON(offset > cmnd->bufflen);
	sBUG_ON(offset + size > cmnd->bufflen);

	conn->write_offset = offset;
	conn->write_size += size;
}

static void cmnd_send_pdu(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	u32 size;

	if (!cmnd->pdu.datasize)
		return;

	size = (cmnd->pdu.datasize + 3) & -4;
	sBUG_ON(cmnd->sg == NULL);
	sBUG_ON(cmnd->bufflen != size);
	__cmnd_send_pdu(conn, cmnd, 0, size);
}

static void set_cork(struct socket *sock, int on)
{
	int opt = on;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	sock->ops->setsockopt(sock, SOL_TCP, TCP_CORK,
			      (void *)&opt, sizeof(opt));
	set_fs(oldfs);
}

void cmnd_tx_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	TRACE_DBG("%p:%p:%x", conn, cmnd, cmnd_opcode(cmnd));
	iscsi_cmnd_set_length(&cmnd->pdu);

	iscsi_extracheck_is_wr_thread(conn);

	set_cork(conn->sock, 1);

	conn->write_iop = conn->write_iov;
	conn->write_iop->iov_base = &cmnd->pdu.bhs;
	conn->write_iop->iov_len = sizeof(cmnd->pdu.bhs);
	conn->write_iop_used = 1;
	conn->write_size = sizeof(cmnd->pdu.bhs);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOOP_IN:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_RSP:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_TEXT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_DATA_IN:
	{
		struct iscsi_data_in_hdr *rsp =
			(struct iscsi_data_in_hdr *)&cmnd->pdu.bhs;
		u32 offset = cpu_to_be32(rsp->buffer_offset);

		cmnd_set_sn(cmnd, (rsp->flags & ISCSI_FLG_FINAL) ? 1 : 0);
		__cmnd_send_pdu(conn, cmnd, offset, cmnd->pdu.datasize);
		break;
	}
	case ISCSI_OP_LOGOUT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_R2T:
		cmnd->pdu.bhs.sn = cmnd_set_sn(cmnd, 0);
		break;
	case ISCSI_OP_ASYNC_MSG:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_REJECT:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	default:
		PRINT_ERROR("unexpected cmnd op %x", cmnd_opcode(cmnd));
		break;
	}

	/* move this? */
	conn->write_size = (conn->write_size + 3) & -4;
	iscsi_dump_pdu(&cmnd->pdu);
}

void cmnd_tx_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	TRACE_DBG("%p:%x (should_close_conn %d)", cmnd, cmnd_opcode(cmnd),
		cmnd->should_close_conn);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOOP_IN:
	case ISCSI_OP_SCSI_RSP:
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_R2T:
	case ISCSI_OP_ASYNC_MSG:
	case ISCSI_OP_REJECT:
	case ISCSI_OP_SCSI_DATA_IN:
	case ISCSI_OP_LOGOUT_RSP:
		break;
	default:
		PRINT_CRIT_ERROR("unexpected cmnd op %x", cmnd_opcode(cmnd));
		sBUG();
		break;
	}

	if (cmnd->should_close_conn) {
		PRINT_INFO("Closing connection at initiator %s request",
			conn->session->initiator_name);
		mark_conn_closed(conn);
	}

	set_cork(cmnd->conn->sock, 0);
}

/*
 * Push the command for execution. This functions reorders the commands.
 * Called from the read thread.
 */
static void iscsi_session_push_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct list_head *entry;
	u32 cmd_sn;

	TRACE_DBG("%p:%x %u,%u",
		cmnd, cmnd_opcode(cmnd), cmnd->pdu.bhs.sn,
		session->exp_cmd_sn);

	iscsi_extracheck_is_rd_thread(cmnd->conn);

	sBUG_ON(cmnd->parent_req != NULL);

	if (cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) {
		TRACE_DBG("Immediate cmd %p (cmd_sn %u)", cmnd,
			cmnd->pdu.bhs.sn);
		iscsi_cmnd_exec(cmnd);
		goto out;
	}

	spin_lock(&session->sn_lock);

	cmd_sn = cmnd->pdu.bhs.sn;
	if (cmd_sn == session->exp_cmd_sn) {
		while (1) {
			session->exp_cmd_sn = ++cmd_sn;

			if (unlikely(session->tm_active > 0)) {
				if (before(cmd_sn, session->tm_sn)) {
					struct iscsi_conn *conn = cmnd->conn;

					spin_unlock(&session->sn_lock);

					spin_lock_bh(&conn->cmd_list_lock);
					__cmnd_abort(cmnd);
					spin_unlock_bh(&conn->cmd_list_lock);

					spin_lock(&session->sn_lock);
				}
				iscsi_check_send_delayed_tm_resp(session);
			}

			spin_unlock(&session->sn_lock);

			iscsi_cmnd_exec(cmnd);

			if (list_empty(&session->pending_list))
				break;
			cmnd = list_entry(session->pending_list.next,
					  struct iscsi_cmnd,
					  pending_list_entry);
			if (cmnd->pdu.bhs.sn != cmd_sn)
				break;

			list_del(&cmnd->pending_list_entry);
			cmnd->pending = 0;

			TRACE_DBG("Processing pending cmd %p (cmd_sn %u)",
				cmnd, cmd_sn);

			spin_lock(&session->sn_lock);
		}
	} else {
		int drop = 0;

		TRACE_DBG("Pending cmd %p (cmd_sn %u, exp_cmd_sn %u)",
			cmnd, cmd_sn, session->exp_cmd_sn);

		/*
		 * iSCSI RFC 3720: "The target MUST silently ignore any
		 * non-immediate command outside of [from ExpCmdSN to MaxCmdSN
		 * inclusive] range". But we won't honor the MaxCmdSN
		 * requirement, because, since we adjust MaxCmdSN from the
		 * separate write thread, rarery it is possible that initiator
		 * can legally send command with CmdSN>MaxSN. But it won't
		 * hurt anything, in the worst case it will lead to
		 * additional QUEUE FULL status.
		 */

		if (unlikely(before(cmd_sn, session->exp_cmd_sn))) {
			PRINT_ERROR("Unexpected cmd_sn (%u,%u)", cmd_sn,
				session->exp_cmd_sn);
			drop = 1;
		}

#if 0
		if (unlikely(after(cmd_sn, session->exp_cmd_sn +
					iscsi_get_allowed_cmds(session)))) {
			TRACE_MGMT_DBG("Too large cmd_sn %u (exp_cmd_sn %u, "
				"max_sn %u)", cmd_sn, session->exp_cmd_sn,
				iscsi_get_allowed_cmds(session));
		}
#endif

		spin_unlock(&session->sn_lock);

		if (unlikely(drop)) {
			req_cmnd_release_force(cmnd,
					       ISCSI_FORCE_RELEASE_WRITE);
			goto out;
		}

		if (unlikely(cmnd->tm_aborted)) {
			struct iscsi_cmnd *tm_clone;

			TRACE_MGMT_DBG("Pending aborted cmnd %p, creating TM "
				"clone (scst cmd %p, state %d)", cmnd,
				cmnd->scst_cmd, cmnd->scst_state);

			tm_clone = cmnd_alloc(cmnd->conn, NULL);
			if (tm_clone != NULL) {
				tm_clone->tm_aborted = 1;
				tm_clone->pdu = cmnd->pdu;

				TRACE_MGMT_DBG("TM clone %p created",
					       tm_clone);

				iscsi_cmnd_exec(cmnd);
				cmnd = tm_clone;
			} else
				PRINT_ERROR("%s", "Unable to create TM clone");
		}

		list_for_each(entry, &session->pending_list) {
			struct iscsi_cmnd *tmp =
				list_entry(entry, struct iscsi_cmnd,
					   pending_list_entry);
			if (before(cmd_sn, tmp->pdu.bhs.sn))
				break;
		}

		list_add_tail(&cmnd->pending_list_entry, entry);
		cmnd->pending = 1;
	}
out:
	return;
}

static int check_segment_length(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_session *session = conn->session;

	if (unlikely(cmnd->pdu.datasize > session->sess_param.max_recv_data_length)) {
		PRINT_ERROR("Initiator %s violated negotiated parameters: "
			"data too long (ITT %x, datasize %u, "
			"max_recv_data_length %u", session->initiator_name,
			cmnd_itt(cmnd), cmnd->pdu.datasize,
			session->sess_param.max_recv_data_length);
		mark_conn_closed(conn);
		return -EINVAL;
	}
	return 0;
}

int cmnd_rx_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	int res, rc;

	iscsi_dump_pdu(&cmnd->pdu);

	res = check_segment_length(cmnd);
	if (res != 0)
		goto out;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOOP_OUT:
		rc = noop_out_start(cmnd);
		break;
	case ISCSI_OP_SCSI_CMD:
		rc = cmnd_insert_hash(cmnd);
		if (likely(rc == 0)) {
			res = scsi_cmnd_start(cmnd);
			if (unlikely(res != 0))
				goto out;
		}
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		rc = cmnd_insert_hash(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		res = data_out_start(conn, cmnd);
		rc = 0; /* to avoid compiler warning */
		if (unlikely(res != 0))
			goto out;
		break;
	case ISCSI_OP_LOGOUT_CMD:
		rc = cmnd_insert_hash(cmnd);
		break;
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_SNACK_CMD:
		rc = -ISCSI_REASON_UNSUPPORTED_COMMAND;
		break;
	default:
		rc = -ISCSI_REASON_UNSUPPORTED_COMMAND;
		break;
	}

	if (unlikely(rc < 0)) {
		struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);
		PRINT_ERROR("Error %d (iSCSI opcode %x, ITT %x, op %x)", rc,
			cmnd_opcode(cmnd), cmnd_itt(cmnd),
			(cmnd_opcode(cmnd) == ISCSI_OP_SCSI_CMD ?
				hdr->scb[0] : -1));
		iscsi_cmnd_reject(cmnd, -rc);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

void cmnd_rx_end(struct iscsi_cmnd *cmnd)
{
	TRACE_ENTRY();

	TRACE_DBG("%p:%x", cmnd, cmnd_opcode(cmnd));

	if (unlikely(cmnd->rejected))
		goto out_rejected;

cont:
	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	case ISCSI_OP_LOGOUT_CMD:
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		data_out_end(cmnd);
		break;
	default:
		PRINT_ERROR("unexpected cmnd op %x", cmnd_opcode(cmnd));
		req_cmnd_release(cmnd);
		break;
	}

out:
	TRACE_EXIT();
	return;

out_rejected:
	switch (cmnd->reject_reason) {
	default:
		PRINT_ERROR("Unexpected reject reason %d",
			    cmnd->reject_reason);
		/* go through */
	case ISCSI_REJECT_CMD:
	case ISCSI_REJECT_DATA:
		req_cmnd_release(cmnd);
		break;
	case ISCSI_REJECT_SCSI_CMD:
		goto cont;
	}
	goto out;
}

#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
static int iscsi_alloc_data_buf(struct scst_cmd *cmd)
{
	/*
	 * sock->ops->sendpage() is async zero copy operation,
	 * so we must be sure not to free and reuse
	 * the command's buffer before the sending was completed
	 * by the network layers. It is possible only if we
	 * don't use SGV cache.
	 */
	EXTRACHECKS_BUG_ON(scst_cmd_get_data_direction(cmd) != SCST_DATA_READ);
	scst_cmd_set_no_sgv(cmd);
	return 1;
}
#endif

static inline void iscsi_set_state_wake_up(struct iscsi_cmnd *req,
	int new_state)
{
	/*
	 * We use wait_event() to wait for the state change, but it checks its
	 * condition without any protection, so without cmnd_get() it is
	 * possible that req will die "immediately" after the state assignment
	 * and wake_up() will operate on dead data.
	 */
	cmnd_get_ordered(req);
	req->scst_state = new_state;
	wake_up(&req->scst_waitQ);
	cmnd_put(req);
	return;
}

static void iscsi_preprocessing_done(struct scst_cmd *scst_cmd)
{
	struct iscsi_cmnd *req = (struct iscsi_cmnd *)
				scst_cmd_get_tgt_priv(scst_cmd);

	TRACE_DBG("req %p", req);

	EXTRACHECKS_BUG_ON(req->scst_state != ISCSI_CMD_STATE_RX_CMD);

	iscsi_set_state_wake_up(req, ISCSI_CMD_STATE_AFTER_PREPROC);
	return;
}

/*
 * No locks.
 *
 * IMPORTANT! Connection conn must be protected by additional conn_get()
 * upon entrance in this function, because otherwise it could be destroyed
 * inside as a result of iscsi_send(), which releases sent commands.
 */
static void iscsi_try_local_processing(struct iscsi_conn *conn)
{
	int local;

	TRACE_ENTRY();

	spin_lock_bh(&iscsi_wr_lock);
	switch (conn->wr_state) {
	case ISCSI_CONN_WR_STATE_IN_LIST:
		list_del(&conn->wr_list_entry);
		/* go through */
	case ISCSI_CONN_WR_STATE_IDLE:
#ifdef CONFIG_SCST_EXTRACHECKS
		conn->wr_task = current;
#endif
		conn->wr_state = ISCSI_CONN_WR_STATE_PROCESSING;
		conn->wr_space_ready = 0;
		local = 1;
		break;
	default:
		local = 0;
		break;
	}
	spin_unlock_bh(&iscsi_wr_lock);

	if (local) {
		int rc = 1;

		if (test_write_ready(conn))
			rc = iscsi_send(conn);

		spin_lock_bh(&iscsi_wr_lock);
#ifdef CONFIG_SCST_EXTRACHECKS
		conn->wr_task = NULL;
#endif
		if ((rc <= 0) || test_write_ready(conn)) {
			list_add_tail(&conn->wr_list_entry, &iscsi_wr_list);
			conn->wr_state = ISCSI_CONN_WR_STATE_IN_LIST;
			wake_up(&iscsi_wr_waitQ);
		} else
			conn->wr_state = ISCSI_CONN_WR_STATE_IDLE;
		spin_unlock_bh(&iscsi_wr_lock);
	}

	TRACE_EXIT();
	return;
}

static int iscsi_xmit_response(struct scst_cmd *scst_cmd)
{
	int is_send_status = scst_cmd_get_is_send_status(scst_cmd);
	struct iscsi_cmnd *req = (struct iscsi_cmnd *)
					scst_cmd_get_tgt_priv(scst_cmd);
	struct iscsi_conn *conn = req->conn;
	int status = scst_cmd_get_status(scst_cmd);
	u8 *sense = scst_cmd_get_sense_buffer(scst_cmd);
	int sense_len = scst_cmd_get_sense_buffer_len(scst_cmd);
	int old_state = req->scst_state;

	if (scst_cmd_atomic(scst_cmd))
		return SCST_TGT_RES_NEED_THREAD_CTX;

	scst_cmd_set_tgt_priv(scst_cmd, NULL);

	req->tm_aborted |= scst_cmd_aborted(scst_cmd) ? 1 : 0;
	if (unlikely(req->tm_aborted)) {
		TRACE_MGMT_DBG("req %p (scst_cmd %p) aborted", req,
			req->scst_cmd);

		scst_set_delivery_status(req->scst_cmd,
			SCST_CMD_DELIVERY_ABORTED);

		if (old_state == ISCSI_CMD_STATE_RESTARTED) {
			req->scst_state = ISCSI_CMD_STATE_PROCESSED;
			req_cmnd_release_force(req, ISCSI_FORCE_RELEASE_WRITE);
		} else
			iscsi_set_state_wake_up(req,
						ISCSI_CMD_STATE_PROCESSED);

		goto out;
	}

	if (unlikely(old_state != ISCSI_CMD_STATE_RESTARTED)) {
		TRACE_DBG("req %p on %d state", req, old_state);

		create_status_rsp(req, status, sense, sense_len);

		switch (old_state) {
		case ISCSI_CMD_STATE_RX_CMD:
		case ISCSI_CMD_STATE_AFTER_PREPROC:
			break;
		default:
			sBUG();
		}

		iscsi_set_state_wake_up(req, ISCSI_CMD_STATE_PROCESSED);
		goto out;
	}

	req->scst_state = ISCSI_CMD_STATE_PROCESSED;

	req->bufflen = scst_cmd_get_resp_data_len(scst_cmd);
	req->sg = scst_cmd_get_sg(scst_cmd);
	req->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);

	TRACE_DBG("req %p, is_send_status=%x, req->bufflen=%d, req->sg=%p, "
		"req->sg_cnt %d", req, is_send_status, req->bufflen, req->sg,
		req->sg_cnt);

	if (unlikely((req->bufflen != 0) && !is_send_status)) {
		PRINT_CRIT_ERROR("%s", "Sending DATA without STATUS is "
			"unsupported");
		scst_set_cmd_error(scst_cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
		sBUG();
	}

	if (req->bufflen != 0) {
		/*
		 * Check above makes sure that is_send_status is set,
		 * so status is valid here, but in future that could change.
		 * ToDo
		 */
		if (status != SAM_STAT_CHECK_CONDITION) {
			send_data_rsp(req, status, is_send_status);
		} else {
			struct iscsi_cmnd *rsp;
			struct iscsi_scsi_rsp_hdr *rsp_hdr;
			int resid;
			send_data_rsp(req, 0, 0);
			if (is_send_status) {
				rsp = create_status_rsp(req, status, sense,
					sense_len);
				rsp_hdr =
				    (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
				resid = cmnd_read_size(req) - req->bufflen;
				if (resid > 0) {
					rsp_hdr->flags |=
						ISCSI_FLG_RESIDUAL_UNDERFLOW;
					rsp_hdr->residual_count =
						cpu_to_be32(resid);
				} else if (resid < 0) {
					rsp_hdr->flags |=
						ISCSI_FLG_RESIDUAL_OVERFLOW;
					rsp_hdr->residual_count =
						cpu_to_be32(-resid);
				}
				iscsi_cmnd_init_write(rsp,
					ISCSI_INIT_WRITE_REMOVE_HASH);
			}
		}
	} else if (is_send_status) {
		struct iscsi_cmnd *rsp;
		struct iscsi_scsi_rsp_hdr *rsp_hdr;
		u32 resid;
		rsp = create_status_rsp(req, status, sense, sense_len);
		rsp_hdr = (struct iscsi_scsi_rsp_hdr *) &rsp->pdu.bhs;
		resid = cmnd_read_size(req);
		if (resid != 0) {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(resid);
		}
		iscsi_cmnd_init_write(rsp, ISCSI_INIT_WRITE_REMOVE_HASH);
	}
#ifdef CONFIG_SCST_EXTRACHECKS
	else
		sBUG();
#endif

	conn_get_ordered(conn);
	req_cmnd_release(req);
	iscsi_try_local_processing(conn);
	conn_put(conn);

out:
	return SCST_TGT_RES_SUCCESS;
}

/* Called under sn_lock */
static bool iscsi_is_delay_tm_resp(struct iscsi_cmnd *rsp)
{
	bool res = 0;
	struct iscsi_task_mgt_hdr *req_hdr =
		(struct iscsi_task_mgt_hdr *)&rsp->parent_req->pdu.bhs;
	int function = req_hdr->function & ISCSI_FUNCTION_MASK;
	struct iscsi_session *sess = rsp->conn->session;

	TRACE_ENTRY();

	/* This should be checked for immediate TM commands as well */

	switch (function) {
	default:
		if (before(sess->exp_cmd_sn, req_hdr->cmd_sn))
			res = 1;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* Called under sn_lock, but might drop it inside, then reaquire */
static void iscsi_check_send_delayed_tm_resp(struct iscsi_session *sess)
{
	struct iscsi_cmnd *tm_rsp = sess->tm_rsp;

	TRACE_ENTRY();

	if (tm_rsp == NULL)
		goto out;

	if (iscsi_is_delay_tm_resp(tm_rsp))
		goto out;

	TRACE(TRACE_MGMT_MINOR, "Sending delayed rsp %p", tm_rsp);

	sess->tm_rsp = NULL;
	sess->tm_active--;

	spin_unlock(&sess->sn_lock);

	sBUG_ON(sess->tm_active < 0);

	iscsi_cmnd_init_write(tm_rsp,
		ISCSI_INIT_WRITE_REMOVE_HASH | ISCSI_INIT_WRITE_WAKE);

	spin_lock(&sess->sn_lock);

out:
	TRACE_EXIT();
	return;
}

static void iscsi_send_task_mgmt_resp(struct iscsi_cmnd *req, int status)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_task_mgt_hdr *req_hdr =
				(struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
	struct iscsi_task_rsp_hdr *rsp_hdr;
	struct iscsi_session *sess = req->conn->session;
	int fn = req_hdr->function & ISCSI_FUNCTION_MASK;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("TM req %p finished", req);
	TRACE((req_hdr->function == ISCSI_FUNCTION_ABORT_TASK) ?
			 TRACE_MGMT_MINOR : TRACE_MGMT,
		"TM fn %d finished, status %d", fn, status);

	rsp = iscsi_cmnd_create_rsp_cmnd(req);
	rsp_hdr = (struct iscsi_task_rsp_hdr *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_SCSI_TASK_MGT_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->itt = req_hdr->itt;
	rsp_hdr->response = status;

	if (fn == ISCSI_FUNCTION_TARGET_COLD_RESET)
		rsp->should_close_conn = 1;

	sBUG_ON(sess->tm_rsp != NULL);

	spin_lock(&sess->sn_lock);
	if (iscsi_is_delay_tm_resp(rsp)) {
		TRACE(TRACE_MGMT_MINOR, "Delaying TM fn %x response %p "
			"(req %p), because not all affected commands received "
			"(TM cmd sn %u, exp sn %u)",
			req_hdr->function & ISCSI_FUNCTION_MASK, rsp, req,
			req_hdr->cmd_sn, sess->exp_cmd_sn);
		sess->tm_rsp = rsp;
		spin_unlock(&sess->sn_lock);
		goto out_release;
	}
	sess->tm_active--;
	spin_unlock(&sess->sn_lock);

	sBUG_ON(sess->tm_active < 0);

	iscsi_cmnd_init_write(rsp,
		ISCSI_INIT_WRITE_REMOVE_HASH | ISCSI_INIT_WRITE_WAKE);

out_release:
	req_cmnd_release(req);

	TRACE_EXIT();
	return;
}

static inline int iscsi_get_mgmt_response(int status)
{
	switch (status) {
	case SCST_MGMT_STATUS_SUCCESS:
		return ISCSI_RESPONSE_FUNCTION_COMPLETE;

	case SCST_MGMT_STATUS_TASK_NOT_EXIST:
		return ISCSI_RESPONSE_UNKNOWN_TASK;

	case SCST_MGMT_STATUS_LUN_NOT_EXIST:
		return ISCSI_RESPONSE_UNKNOWN_LUN;

	case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
		return ISCSI_RESPONSE_FUNCTION_UNSUPPORTED;

	case SCST_MGMT_STATUS_REJECTED:
	case SCST_MGMT_STATUS_FAILED:
	default:
		return ISCSI_RESPONSE_FUNCTION_REJECTED;
	}
}

static void iscsi_task_mgmt_fn_done(struct scst_mgmt_cmd *scst_mcmd)
{
	struct iscsi_cmnd *req = (struct iscsi_cmnd *)
				scst_mgmt_cmd_get_tgt_priv(scst_mcmd);
	int status =
		iscsi_get_mgmt_response(scst_mgmt_cmd_get_status(scst_mcmd));

	TRACE_MGMT_DBG("req %p, scst_mcmd %p, fn %d, scst status %d",
		req, scst_mcmd, scst_mgmt_cmd_get_fn(scst_mcmd),
		scst_mgmt_cmd_get_status(scst_mcmd));

	iscsi_send_task_mgmt_resp(req, status);

	scst_mgmt_cmd_set_tgt_priv(scst_mcmd, NULL);

	return;
}

static int iscsi_target_detect(struct scst_tgt_template *templ)
{
	/* Nothing to do */
	return 0;
}

static int iscsi_target_release(struct scst_tgt *scst_tgt)
{
	/* Nothing to do */
	return 0;
}

struct scst_tgt_template iscsi_template = {
	.name = "iscsi",
	.sg_tablesize = ISCSI_CONN_IOV_MAX,
	.threads_num = 0,
	.no_clustering = 1,
	.xmit_response_atomic = 0,
	.detect = iscsi_target_detect,
	.release = iscsi_target_release,
	.xmit_response = iscsi_xmit_response,
#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	.alloc_data_buf = iscsi_alloc_data_buf,
#endif
	.preprocessing_done = iscsi_preprocessing_done,
	.pre_exec = iscsi_pre_exec,
	.task_mgmt_fn_done = iscsi_task_mgmt_fn_done,
};

static __init int iscsi_run_threads(int count, char *name, int (*fn)(void *))
{
	int res = 0;
	int i;
	struct iscsi_thread_t *thr;

	for (i = 0; i < count; i++) {
		thr = kmalloc(sizeof(*thr), GFP_KERNEL);
		if (!thr) {
			res = -ENOMEM;
			PRINT_ERROR("Failed to allocate thr %d", res);
			goto out;
		}
		thr->thr = kthread_run(fn, NULL, "%s%d", name, i);
		if (IS_ERR(thr->thr)) {
			res = PTR_ERR(thr->thr);
			PRINT_ERROR("kthread_create() failed: %d", res);
			kfree(thr);
			goto out;
		}
		list_add(&thr->threads_list_entry, &iscsi_threads_list);
	}

out:
	return res;
}

static void iscsi_stop_threads(void)
{
	struct iscsi_thread_t *t, *tmp;

	list_for_each_entry_safe(t, tmp, &iscsi_threads_list,
				threads_list_entry) {
		int rc = kthread_stop(t->thr);
		if (rc < 0)
			TRACE_MGMT_DBG("kthread_stop() failed: %d", rc);
		list_del(&t->threads_list_entry);
		kfree(t);
	}
}

static int __init iscsi_init(void)
{
	int err = 0;
	int num;

	PRINT_INFO("iSCSI SCST Target - version %s", ISCSI_VERSION_STRING);

	dummy_page = alloc_pages(GFP_KERNEL, 0);
	if (dummy_page == NULL) {
		PRINT_ERROR("%s", "Dummy page allocation failed");
		goto out;
	}

	sg_init_table(&dummy_sg, 1);
	sg_set_page(&dummy_sg, dummy_page, PAGE_SIZE, 0);

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	err = net_set_get_put_page_callbacks(iscsi_get_page_callback,
			iscsi_put_page_callback);
	if (err != 0) {
		PRINT_INFO("Unable to set page callbackes: %d", err);
		goto out_free_dummy;
	}
#else
	PRINT_INFO("%s", "Patch put_page_callback-<kernel-version>.patch "
		"not applied on your kernel. Running in the performance "
		"degraded mode. Refer README file for details");
#endif

	ctr_major = register_chrdev(0, ctr_name, &ctr_fops);
	if (ctr_major < 0) {
		PRINT_ERROR("failed to register the control device %d",
			    ctr_major);
		err = ctr_major;
		goto out_callb;
	}

	err = event_init();
	if (err < 0)
		goto out_reg;

	iscsi_cmnd_cache = KMEM_CACHE(iscsi_cmnd, SCST_SLAB_FLAGS);
	if (!iscsi_cmnd_cache) {
		err = -ENOMEM;
		goto out_event;
	}

	err = scst_register_target_template(&iscsi_template);
	if (err < 0)
		goto out_kmem;

	iscsi_template_registered = 1;

	err = iscsi_procfs_init();
	if (err < 0)
		goto out_reg_tmpl;

	num = max(num_online_cpus(), 2);

	err = iscsi_run_threads(num, "iscsird", istrd);
	if (err != 0)
		goto out_thr;

	err = iscsi_run_threads(num, "iscsiwr", istwr);
	if (err != 0)
		goto out_thr;

out:
	return err;

out_thr:
	iscsi_procfs_exit();
	iscsi_stop_threads();

out_reg_tmpl:
	scst_unregister_target_template(&iscsi_template);

out_kmem:
	kmem_cache_destroy(iscsi_cmnd_cache);

out_event:
	event_exit();

out_reg:
	unregister_chrdev(ctr_major, ctr_name);

out_callb:
#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	net_set_get_put_page_callbacks(NULL, NULL);

out_free_dummy:
#endif
	__free_pages(dummy_page, 0);
	goto out;
}

static void __exit iscsi_exit(void)
{
	iscsi_stop_threads();

	unregister_chrdev(ctr_major, ctr_name);

	iscsi_procfs_exit();
	event_exit();

	kmem_cache_destroy(iscsi_cmnd_cache);

	scst_unregister_target_template(&iscsi_template);

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	net_set_get_put_page_callbacks(NULL, NULL);
#endif

	__free_pages(dummy_page, 0);
	return;
}

module_init(iscsi_init);
module_exit(iscsi_exit);

MODULE_LICENSE("GPL");
