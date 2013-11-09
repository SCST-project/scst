/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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
#include <linux/scatterlist.h>
#include <linux/ctype.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>

#include "iscsi.h"
#include "digest.h"

#ifndef GENERATING_UPSTREAM_PATCH
#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
#warning Patch put_page_callback-<kernel-version>.patch not applied on your \
kernel or CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION \
config option not set. ISCSI-SCST will be working with not the best \
performance. Refer README file for details.
#endif
#endif

#define ISCSI_INIT_WRITE_WAKE		0x1

static int ctr_major;
static const char ctr_name[] = "iscsi-scst-ctl";

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
unsigned long iscsi_trace_flag = ISCSI_DEFAULT_LOG_FLAGS;
#endif

static struct kmem_cache *iscsi_cmnd_cache;

static DEFINE_MUTEX(iscsi_threads_pool_mutex);
static LIST_HEAD(iscsi_thread_pools_list);

static struct kmem_cache *iscsi_thread_pool_cache;

static struct iscsi_thread_pool *iscsi_main_thread_pool;

struct kmem_cache *iscsi_conn_cache;
struct kmem_cache *iscsi_sess_cache;

static struct page *dummy_page;
static struct scatterlist dummy_sg;

static void cmnd_remove_data_wait_hash(struct iscsi_cmnd *cmnd);
static void iscsi_send_task_mgmt_resp(struct iscsi_cmnd *req, int status);
static void iscsi_check_send_delayed_tm_resp(struct iscsi_session *sess);
static void req_cmnd_release(struct iscsi_cmnd *req);
static int cmnd_insert_data_wait_hash(struct iscsi_cmnd *cmnd);
static void iscsi_cmnd_init_write(struct iscsi_cmnd *rsp, int flags);
static void iscsi_set_resid_no_scst_cmd(struct iscsi_cmnd *rsp);
static void iscsi_set_resid(struct iscsi_cmnd *rsp);

static void iscsi_set_not_received_data_len(struct iscsi_cmnd *req,
	unsigned int not_received)
{
	req->not_received_data_len = not_received;
	if (req->scst_cmd != NULL)
		scst_cmd_set_write_not_received_data_len(req->scst_cmd,
			not_received);
	return;
}

static void req_del_from_write_timeout_list(struct iscsi_cmnd *req)
{
	struct iscsi_conn *conn;

	TRACE_ENTRY();

	if (!req->on_write_timeout_list)
		goto out;

	conn = req->conn;

	TRACE_DBG("Deleting cmd %p from conn %p write_timeout_list",
		req, conn);

	spin_lock_bh(&conn->write_list_lock);

	/* Recheck, since it can be changed behind us */
	if (unlikely(!req->on_write_timeout_list))
		goto out_unlock;

	list_del(&req->write_timeout_list_entry);
	req->on_write_timeout_list = 0;

out_unlock:
	spin_unlock_bh(&conn->write_list_lock);

out:
	TRACE_EXIT();
	return;
}

static inline u32 cmnd_write_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_CMD_WRITE)
		return be32_to_cpu(hdr->data_length);
	return 0;
}

static inline int cmnd_read_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_CMD_READ) {
		struct iscsi_ahs_hdr *ahdr;

		if (!(hdr->flags & ISCSI_CMD_WRITE))
			return be32_to_cpu(hdr->data_length);

		ahdr = (struct iscsi_ahs_hdr *)cmnd->pdu.ahs;
		if (ahdr != NULL) {
			uint8_t *p = (uint8_t *)ahdr;
			unsigned int size = 0;
			do {
				int s;

				ahdr = (struct iscsi_ahs_hdr *)p;

				if (ahdr->ahstype == ISCSI_AHSTYPE_RLENGTH) {
					struct iscsi_rlength_ahdr *rh =
					      (struct iscsi_rlength_ahdr *)ahdr;
					return be32_to_cpu(rh->read_length);
				}

				s = 3 + be16_to_cpu(ahdr->ahslength);
				s = (s + 3) & -4;
				size += s;
				p += s;
			} while (size < cmnd->pdu.ahssize);
		}
		return -1;
	}
	return 0;
}

void iscsi_restart_cmnd(struct iscsi_cmnd *cmnd)
{
	int status;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmnd->r2t_len_to_receive != 0);
	EXTRACHECKS_BUG_ON(cmnd->r2t_len_to_send != 0);

	req_del_from_write_timeout_list(cmnd);

	/*
	 * Let's remove cmnd from the hash earlier to keep it smaller.
	 * Also we have to remove hashed req from the hash before sending
	 * response. Otherwise we can have a race, when for some reason cmd's
	 * release (and, hence, removal from the hash) is delayed after the
	 * transmission and initiator sends cmd with the same ITT, hence
	 * the new command will be erroneously rejected as a duplicate.
	 */
	if (cmnd->hashed)
		cmnd_remove_data_wait_hash(cmnd);

	if (unlikely(test_bit(ISCSI_CONN_REINSTATING,
			&cmnd->conn->conn_aflags))) {
		struct iscsi_target *target = cmnd->conn->session->target;
		bool get_out;

		mutex_lock(&target->target_mutex);

		get_out = test_bit(ISCSI_CONN_REINSTATING,
				&cmnd->conn->conn_aflags);
		/* Let's don't look dead */
		if (scst_cmd_get_cdb(cmnd->scst_cmd)[0] == TEST_UNIT_READY)
			get_out = false;

		if (!get_out)
			goto unlock_cont;

		TRACE_MGMT_DBG("Pending cmnd %p, because conn %p is "
			"reinstated", cmnd, cmnd->conn);

		cmnd->scst_state = ISCSI_CMD_STATE_REINST_PENDING;
		list_add_tail(&cmnd->reinst_pending_cmd_list_entry,
			&cmnd->conn->reinst_pending_cmd_list);

unlock_cont:
		mutex_unlock(&target->target_mutex);

		if (get_out)
			goto out;
	}

	if (unlikely(cmnd->prelim_compl_flags != 0)) {
		if (test_bit(ISCSI_CMD_ABORTED, &cmnd->prelim_compl_flags)) {
			TRACE_MGMT_DBG("cmnd %p (scst_cmd %p) aborted", cmnd,
				cmnd->scst_cmd);
			req_cmnd_release_force(cmnd);
			goto out;
		}

		if (cmnd->scst_cmd == NULL) {
			TRACE_MGMT_DBG("Finishing preliminary completed cmd %p "
				"with NULL scst_cmd", cmnd);
			req_cmnd_release(cmnd);
			goto out;
		}

		status = SCST_PREPROCESS_STATUS_ERROR_SENSE_SET;
	} else
		status = SCST_PREPROCESS_STATUS_SUCCESS;

	cmnd->scst_state = ISCSI_CMD_STATE_RESTARTED;

	scst_restart_cmd(cmnd->scst_cmd, status, SCST_CONTEXT_THREAD);

out:
	TRACE_EXIT();
	return;
}

static struct iscsi_cmnd *iscsi_create_tm_clone(struct iscsi_cmnd *cmnd)
{
	struct iscsi_cmnd *tm_clone;

	TRACE_ENTRY();

	tm_clone = cmnd_alloc(cmnd->conn, NULL);
	if (tm_clone != NULL) {
		set_bit(ISCSI_CMD_ABORTED, &tm_clone->prelim_compl_flags);
		tm_clone->pdu = cmnd->pdu;

		TRACE_MGMT_DBG("TM clone %p for cmnd %p created",
			tm_clone, cmnd);
	} else
		PRINT_ERROR("Failed to create TM clone for cmnd %p", cmnd);

	TRACE_EXIT_HRES((unsigned long)tm_clone);
	return tm_clone;
}

void iscsi_fail_data_waiting_cmnd(struct iscsi_cmnd *cmnd)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("Failing data waiting cmnd %p (data_out_in_data_receiving %d)",
		cmnd, cmnd->data_out_in_data_receiving);

	/*
	 * There is no race with conn_abort(), since all functions
	 * called from single read thread
	 */
	iscsi_extracheck_is_rd_thread(cmnd->conn);

	/* This cmnd is going to die without response */
	cmnd->r2t_len_to_receive = 0;
	cmnd->r2t_len_to_send = 0;

	if (cmnd->pending) {
		struct iscsi_session *session = cmnd->conn->session;
		struct iscsi_cmnd *tm_clone;

		TRACE_MGMT_DBG("Unpending cmnd %p (sn %u, exp_cmd_sn %u)", cmnd,
			cmnd->pdu.bhs.sn, session->exp_cmd_sn);

		/*
		 * If cmnd is pending, then the next command, if any, must be
		 * pending too. So, just insert a clone instead of cmnd to
		 * fill the hole in SNs. Then we can release cmnd.
		 */

		tm_clone = iscsi_create_tm_clone(cmnd);

		spin_lock(&session->sn_lock);

		if (tm_clone != NULL) {
			TRACE_MGMT_DBG("Adding tm_clone %p after its cmnd",
				tm_clone);
			list_add(&tm_clone->pending_list_entry,
				&cmnd->pending_list_entry);
		}

		list_del(&cmnd->pending_list_entry);
		cmnd->pending = 0;

		spin_unlock(&session->sn_lock);
	}

	req_cmnd_release_force(cmnd);

	TRACE_EXIT();
	return;
}

struct iscsi_cmnd *cmnd_alloc(struct iscsi_conn *conn,
			      struct iscsi_cmnd *parent)
{
	struct iscsi_cmnd *cmnd;

	/* ToDo: __GFP_NOFAIL?? */
	cmnd = kmem_cache_zalloc(iscsi_cmnd_cache, GFP_KERNEL|__GFP_NOFAIL);

	atomic_set(&cmnd->ref_cnt, 1);
	cmnd->scst_state = ISCSI_CMD_STATE_NEW;
	cmnd->conn = conn;
	cmnd->parent_req = parent;

	if (parent == NULL) {
		conn_get(conn);

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
		atomic_set(&cmnd->net_ref_cnt, 0);
#endif
		INIT_LIST_HEAD(&cmnd->rsp_cmd_list);
		INIT_LIST_HEAD(&cmnd->rx_ddigest_cmd_list);
		cmnd->target_task_tag = ISCSI_RESERVED_TAG_CPU32;

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
	TRACE_ENTRY();

	TRACE_DBG("cmnd %p", cmnd);

	if (unlikely(test_bit(ISCSI_CMD_ABORTED, &cmnd->prelim_compl_flags))) {
		TRACE_MGMT_DBG("Free aborted cmd %p (scst cmd %p, state %d, "
			"parent_req %p)", cmnd, cmnd->scst_cmd,
			cmnd->scst_state, cmnd->parent_req);
	}

	/* Catch users from cmd_list or rsp_cmd_list */
	EXTRACHECKS_BUG_ON(atomic_read(&cmnd->ref_cnt) != 0);

	kfree(cmnd->pdu.ahs);

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(cmnd->on_write_list || cmnd->on_write_timeout_list)) {
		struct iscsi_scsi_cmd_hdr *req = cmnd_hdr(cmnd);

		PRINT_CRIT_ERROR("cmnd %p still on some list?, %x, %x, %x, "
			"%x, %x, %x, %x", cmnd, req->opcode, req->scb[0],
			req->flags, req->itt, be32_to_cpu(req->data_length),
			req->cmd_sn, be32_to_cpu((__force __be32)(cmnd->pdu.datasize)));

		if (unlikely(cmnd->parent_req)) {
			struct iscsi_scsi_cmd_hdr *preq =
					cmnd_hdr(cmnd->parent_req);
			PRINT_CRIT_ERROR("%p %x %u", preq, preq->opcode,
				preq->scb[0]);
		}
		sBUG();
	}
#endif

	kmem_cache_free(iscsi_cmnd_cache, cmnd);

	TRACE_EXIT();
	return;
}

static void iscsi_dec_active_cmds(struct iscsi_cmnd *req)
{
	struct iscsi_session *sess = req->conn->session;

	TRACE_DBG("Decrementing active_cmds (req %p, sess %p, "
		"new value %d)", req, sess,
		atomic_read(&sess->active_cmds)-1);

	EXTRACHECKS_BUG_ON(!req->dec_active_cmds);

	atomic_dec(&sess->active_cmds);
	smp_mb__after_atomic_dec();
	req->dec_active_cmds = 0;
#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(atomic_read(&sess->active_cmds) < 0)) {
		PRINT_CRIT_ERROR("active_cmds < 0 (%d)!!",
			atomic_read(&sess->active_cmds));
		sBUG();
	}
#endif
	return;
}

/* Might be called under some lock and on SIRQ */
void cmnd_done(struct iscsi_cmnd *cmnd)
{
	TRACE_ENTRY();

	TRACE_DBG("cmnd %p", cmnd);

	if (unlikely(test_bit(ISCSI_CMD_ABORTED, &cmnd->prelim_compl_flags))) {
		TRACE_MGMT_DBG("Done aborted cmd %p (scst cmd %p, state %d, "
			"parent_req %p)", cmnd, cmnd->scst_cmd,
			cmnd->scst_state, cmnd->parent_req);
	}

	EXTRACHECKS_BUG_ON(cmnd->on_rx_digest_list);
	EXTRACHECKS_BUG_ON(cmnd->hashed);
	EXTRACHECKS_BUG_ON(cmnd->cmd_req);
	EXTRACHECKS_BUG_ON(cmnd->data_out_in_data_receiving);

	req_del_from_write_timeout_list(cmnd);

	if (cmnd->parent_req == NULL) {
		struct iscsi_conn *conn = cmnd->conn;
		struct iscsi_cmnd *rsp, *t;

		TRACE_DBG("Deleting req %p from conn %p", cmnd, conn);

		spin_lock_bh(&conn->cmd_list_lock);
		list_del(&cmnd->cmd_list_entry);
		spin_unlock_bh(&conn->cmd_list_lock);

		conn_put(conn);

		EXTRACHECKS_BUG_ON(!list_empty(&cmnd->rx_ddigest_cmd_list));

		/* Order between above and below code is important! */

		if ((cmnd->scst_cmd != NULL) || (cmnd->scst_aen != NULL)) {
			switch (cmnd->scst_state) {
			case ISCSI_CMD_STATE_PROCESSED:
				TRACE_DBG("cmd %p PROCESSED", cmnd);
				scst_tgt_cmd_done(cmnd->scst_cmd,
					SCST_CONTEXT_DIRECT_ATOMIC);
				break;

			case ISCSI_CMD_STATE_AFTER_PREPROC:
			{
				/* It can be for some aborted commands */
				struct scst_cmd *scst_cmd = cmnd->scst_cmd;
				TRACE_DBG("cmd %p AFTER_PREPROC", cmnd);
				cmnd->scst_state = ISCSI_CMD_STATE_RESTARTED;
				cmnd->scst_cmd = NULL;
				scst_restart_cmd(scst_cmd,
					SCST_PREPROCESS_STATUS_ERROR_FATAL,
					SCST_CONTEXT_THREAD);
				break;
			}

			case ISCSI_CMD_STATE_AEN:
				TRACE_DBG("cmd %p AEN PROCESSED", cmnd);
				scst_aen_done(cmnd->scst_aen);
				break;

			case ISCSI_CMD_STATE_OUT_OF_SCST_PRELIM_COMPL:
				break;

			default:
				PRINT_CRIT_ERROR("Unexpected cmnd scst state "
					"%d", cmnd->scst_state);
				sBUG();
				break;
			}
		}

		if (cmnd->own_sg) {
			TRACE_DBG("own_sg for req %p", cmnd);
			if (cmnd->sg != &dummy_sg)
				scst_free_sg(cmnd->sg, cmnd->sg_cnt);
#ifdef CONFIG_SCST_DEBUG
			cmnd->own_sg = 0;
			cmnd->sg = NULL;
			cmnd->sg_cnt = -1;
#endif
		}

		if (unlikely(cmnd->dec_active_cmds))
			iscsi_dec_active_cmds(cmnd);

		list_for_each_entry_safe(rsp, t, &cmnd->rsp_cmd_list,
					rsp_cmd_list_entry) {
			cmnd_free(rsp);
		}

		cmnd_free(cmnd);
	} else {
		struct iscsi_cmnd *parent = cmnd->parent_req;

		if (cmnd->own_sg) {
			TRACE_DBG("own_sg for rsp %p", cmnd);
			if ((cmnd->sg != &dummy_sg) && (cmnd->sg != cmnd->rsp_sg))
				scst_free_sg(cmnd->sg, cmnd->sg_cnt);
#ifdef CONFIG_SCST_DEBUG
			cmnd->own_sg = 0;
			cmnd->sg = NULL;
			cmnd->sg_cnt = -1;
#endif
		}

		EXTRACHECKS_BUG_ON(cmnd->dec_active_cmds);

		if (cmnd == parent->main_rsp) {
			TRACE_DBG("Finishing main rsp %p (req %p)", cmnd,
				parent);
			parent->main_rsp = NULL;
		}

		cmnd_put(parent);
		/*
		 * cmnd will be freed on the last parent's put and can already
		 * be freed!!
		 */
	}

	TRACE_EXIT();
	return;
}

/*
 * Corresponding conn may also get destroyed after this function, except only
 * if it's called from the read thread!
 *
 * It can't be called in parallel with iscsi_cmnds_init_write()!
 */
void req_cmnd_release_force(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp, *t;
	struct iscsi_conn *conn = req->conn;
	LIST_HEAD(cmds_list);

	TRACE_ENTRY();

	if (req->force_release_done) {
		/*
		 * There are some scenarios when this function can be called
		 * more, than once, for the same req. For instance, dropped
		 * command in iscsi_push_cmnd() and then for it
		 * iscsi_fail_data_waiting_cmnd() during closing (aborting) this
		 * connection or from iscsi_check_tm_data_wait_timeouts().
		 */
		TRACE_MGMT_DBG("Double force release for req %p", req);

		EXTRACHECKS_BUG_ON(!req->release_called);
		sBUG_ON(req->hashed);
		sBUG_ON(req->cmd_req);
		sBUG_ON(req->main_rsp != NULL);
		sBUG_ON(!list_empty(&req->rx_ddigest_cmd_list));
		sBUG_ON(!list_empty(&req->rsp_cmd_list));
		sBUG_ON(req->pending);

		cmnd_put(req);
		goto out;
	} else
		TRACE_MGMT_DBG("req %p", req);

	req->force_release_done = 1;

	sBUG_ON(req == conn->read_cmnd);

	spin_lock_bh(&conn->write_list_lock);
	list_for_each_entry_safe(rsp, t, &conn->write_list, write_list_entry) {
		if (rsp->parent_req != req)
			continue;

		cmd_del_from_write_list(rsp);

		list_add_tail(&rsp->write_list_entry, &cmds_list);
	}
	spin_unlock_bh(&conn->write_list_lock);

	list_for_each_entry_safe(rsp, t, &cmds_list, write_list_entry) {
		TRACE_MGMT_DBG("Putting write rsp %p", rsp);
		list_del(&rsp->write_list_entry);
		cmnd_put(rsp);
	}

	/* Supposed nobody can add responses in the list anymore */
	list_for_each_entry_reverse(rsp, &req->rsp_cmd_list,
			rsp_cmd_list_entry) {
		bool r;

		if (rsp->force_cleanup_done)
			continue;

		rsp->force_cleanup_done = 1;

		if (cmnd_get_check(rsp))
			continue;

		spin_lock_bh(&conn->write_list_lock);
		r = rsp->on_write_list || rsp->write_processing_started;
		spin_unlock_bh(&conn->write_list_lock);

		cmnd_put(rsp);

		if (r)
			continue;

		/*
		 * If both on_write_list and write_processing_started not set,
		 * we can safely put() rsp.
		 */
		TRACE_MGMT_DBG("Putting rsp %p", rsp);
		cmnd_put(rsp);
	}

	if (req->main_rsp != NULL) {
		TRACE_MGMT_DBG("Putting main rsp %p", req->main_rsp);
		cmnd_put(req->main_rsp);
		req->main_rsp = NULL;
	}

	req_cmnd_release(req);

out:
	TRACE_EXIT();
	return;
}

static void req_cmnd_pre_release(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *c, *t;

	TRACE_ENTRY();

	TRACE_DBG("req %p", req);

#ifdef CONFIG_SCST_EXTRACHECKS
	sBUG_ON(req->release_called);
	req->release_called = 1;
#endif

	if (unlikely(test_bit(ISCSI_CMD_ABORTED, &req->prelim_compl_flags))) {
		TRACE_MGMT_DBG("Release aborted req cmd %p (scst cmd %p, "
			"state %d)", req, req->scst_cmd, req->scst_state);
	}

	sBUG_ON(req->parent_req != NULL);

	if (unlikely(req->hashed)) {
		/* It sometimes can happen during errors recovery */
		TRACE_MGMT_DBG("Removing req %p from hash", req);
		cmnd_remove_data_wait_hash(req);
	}

	if (unlikely(req->cmd_req)) {
		/* It sometimes can happen during errors recovery */
		TRACE_MGMT_DBG("Putting cmd_req %p (req %p)", req->cmd_req, req);
		req->cmd_req->data_out_in_data_receiving = 0;
		cmnd_put(req->cmd_req);
		req->cmd_req = NULL;
	}

	if (unlikely(req->main_rsp != NULL)) {
		TRACE_DBG("Sending main rsp %p", req->main_rsp);
		if (cmnd_opcode(req) == ISCSI_OP_SCSI_CMD) {
			if (req->scst_cmd != NULL)
				iscsi_set_resid(req->main_rsp);
			else
				iscsi_set_resid_no_scst_cmd(req->main_rsp);
		}
		iscsi_cmnd_init_write(req->main_rsp, ISCSI_INIT_WRITE_WAKE);
		req->main_rsp = NULL;
	}

	list_for_each_entry_safe(c, t, &req->rx_ddigest_cmd_list,
				rx_ddigest_cmd_list_entry) {
		cmd_del_from_rx_ddigest_list(c);
		cmnd_put(c);
	}

	EXTRACHECKS_BUG_ON(req->pending);

	if (unlikely(req->dec_active_cmds))
		iscsi_dec_active_cmds(req);

	TRACE_EXIT();
	return;
}

/*
 * Corresponding conn may also get destroyed after this function, except only
 * if it's called from the read thread!
 */
static void req_cmnd_release(struct iscsi_cmnd *req)
{
	TRACE_ENTRY();

	req_cmnd_pre_release(req);
	cmnd_put(req);

	TRACE_EXIT();
	return;
}

/*
 * Corresponding conn may also get destroyed after this function, except only
 * if it's called from the read thread!
 */
void rsp_cmnd_release(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);

#ifdef CONFIG_SCST_EXTRACHECKS
	sBUG_ON(cmnd->release_called);
	cmnd->release_called = 1;
#endif

	EXTRACHECKS_BUG_ON(cmnd->parent_req == NULL);

	cmnd_put(cmnd);
	return;
}

static struct iscsi_cmnd *iscsi_alloc_rsp(struct iscsi_cmnd *parent)
{
	struct iscsi_cmnd *rsp;

	TRACE_ENTRY();

	rsp = cmnd_alloc(parent->conn, parent);

	TRACE_DBG("Adding rsp %p to parent %p", rsp, parent);
	list_add_tail(&rsp->rsp_cmd_list_entry, &parent->rsp_cmd_list);

	cmnd_get(parent);

	TRACE_EXIT_HRES((unsigned long)rsp);
	return rsp;
}

static inline struct iscsi_cmnd *iscsi_alloc_main_rsp(struct iscsi_cmnd *parent)
{
	struct iscsi_cmnd *rsp;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(parent->main_rsp != NULL);

	rsp = iscsi_alloc_rsp(parent);
	parent->main_rsp = rsp;

	TRACE_EXIT_HRES((unsigned long)rsp);
	return rsp;
}

static void iscsi_cmnds_init_write(struct list_head *send, int flags)
{
	struct iscsi_cmnd *rsp = list_first_entry(send, struct iscsi_cmnd,
						write_list_entry);
	struct iscsi_conn *conn = rsp->conn;
	struct list_head *pos, *next;

	sBUG_ON(list_empty(send));

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

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(rsp->on_write_list)) {
		PRINT_CRIT_ERROR("cmd already on write list (%x %x %x "
			"%u %u %d %d", rsp->pdu.bhs.itt,
			cmnd_opcode(rsp), cmnd_scsicode(rsp),
			rsp->hdigest, rsp->ddigest,
			list_empty(&rsp->rsp_cmd_list), rsp->hashed);
		sBUG();
	}
#endif
	list_add_tail(&rsp->write_list_entry, &head);
	iscsi_cmnds_init_write(&head, flags);
	return;
}

static void iscsi_set_resid_no_scst_cmd(struct iscsi_cmnd *rsp)
{
	struct iscsi_cmnd *req = rsp->parent_req;
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);
	struct iscsi_scsi_rsp_hdr *rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
	int resid, out_resid;

	TRACE_ENTRY();

	sBUG_ON(req->scst_cmd != NULL);

	TRACE_DBG("req %p, rsp %p, outstanding_r2t %d, r2t_len_to_receive %d, "
		"r2t_len_to_send %d, not_received_data_len %d", req, rsp,
		req->outstanding_r2t, req->r2t_len_to_receive,
		req->r2t_len_to_send, req->not_received_data_len);

	if ((req_hdr->flags & ISCSI_CMD_READ) &&
	    (req_hdr->flags & ISCSI_CMD_WRITE)) {
		out_resid = req->not_received_data_len;
		if (out_resid > 0) {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(out_resid);
		} else if (out_resid < 0) {
			out_resid = -out_resid;
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(out_resid);
		}

		resid = cmnd_read_size(req);
		if (resid > 0) {
			rsp_hdr->flags |= ISCSI_FLG_BIRESIDUAL_UNDERFLOW;
			rsp_hdr->bi_residual_count = cpu_to_be32(resid);
		} else if (resid < 0) {
			resid = -resid;
			rsp_hdr->flags |= ISCSI_FLG_BIRESIDUAL_OVERFLOW;
			rsp_hdr->bi_residual_count = cpu_to_be32(resid);
		}
	} else if (req_hdr->flags & ISCSI_CMD_READ) {
		resid = be32_to_cpu(req_hdr->data_length);
		if (resid > 0) {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(resid);
		}
	} else if (req_hdr->flags & ISCSI_CMD_WRITE) {
		resid = req->not_received_data_len;
		if (resid > 0) {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(resid);
		}
	}

	TRACE_EXIT();
	return;
}

static void iscsi_set_resid(struct iscsi_cmnd *rsp)
{
	struct iscsi_cmnd *req = rsp->parent_req;
	struct scst_cmd *scst_cmd = req->scst_cmd;
	struct iscsi_scsi_cmd_hdr *req_hdr;
	struct iscsi_scsi_rsp_hdr *rsp_hdr;
	int resid, out_resid;

	TRACE_ENTRY();

	if (likely(!scst_get_resid(scst_cmd, &resid, &out_resid))) {
		TRACE_DBG("No residuals for req %p", req);
		goto out;
	}

	TRACE_DBG("req %p, resid %d, out_resid %d", req, resid, out_resid);

	req_hdr = cmnd_hdr(req);
	rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;

	if ((req_hdr->flags & ISCSI_CMD_READ) &&
	    (req_hdr->flags & ISCSI_CMD_WRITE)) {
		if (out_resid > 0) {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(out_resid);
		} else if (out_resid < 0) {
			out_resid = -out_resid;
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(out_resid);
		}

		if (resid > 0) {
			rsp_hdr->flags |= ISCSI_FLG_BIRESIDUAL_UNDERFLOW;
			rsp_hdr->bi_residual_count = cpu_to_be32(resid);
		} else if (resid < 0) {
			resid = -resid;
			rsp_hdr->flags |= ISCSI_FLG_BIRESIDUAL_OVERFLOW;
			rsp_hdr->bi_residual_count = cpu_to_be32(resid);
		}
	} else {
		if (resid > 0) {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(resid);
		} else if (resid < 0) {
			resid = -resid;
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(resid);
		}
	}

out:
	TRACE_EXIT();
	return;
}

static void send_data_rsp(struct iscsi_cmnd *req, u8 status, int send_status)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);
	struct iscsi_data_in_hdr *rsp_hdr;
	u32 pdusize, size, offset, sn;
	LIST_HEAD(send);

	TRACE_DBG("req %p", req);

	pdusize = req->conn->session->sess_params.max_xmit_data_length;
	size = req->bufflen;
	offset = 0;
	sn = 0;

	while (1) {
		rsp = iscsi_alloc_rsp(req);
		TRACE_DBG("rsp %p", rsp);
		rsp->sg = req->sg;
		rsp->sg_cnt = req->sg_cnt;
		rsp->bufflen = req->bufflen;
		rsp_hdr = (struct iscsi_data_in_hdr *)&rsp->pdu.bhs;

		rsp_hdr->opcode = ISCSI_OP_SCSI_DATA_IN;
		rsp_hdr->itt = req_hdr->itt;
		rsp_hdr->ttt = ISCSI_RESERVED_TAG;
		rsp_hdr->buffer_offset = cpu_to_be32(offset);
		rsp_hdr->data_sn = cpu_to_be32(sn);

		if (size <= pdusize) {
			TRACE_DBG("offset %d, size %d", offset, size);
			rsp->pdu.datasize = size;
			if (send_status) {
				TRACE_DBG("status %x", status);

				EXTRACHECKS_BUG_ON((cmnd_hdr(req)->flags & ISCSI_CMD_WRITE) != 0);

				rsp_hdr->flags = ISCSI_FLG_FINAL | ISCSI_FLG_STATUS;
				rsp_hdr->cmd_status = status;

				iscsi_set_resid(rsp);
			}
			list_add_tail(&rsp->write_list_entry, &send);
			break;
		}

		TRACE_DBG("pdusize %d, offset %d, size %d", pdusize, offset,
			size);

		rsp->pdu.datasize = pdusize;

		size -= pdusize;
		offset += pdusize;
		sn++;

		list_add_tail(&rsp->write_list_entry, &send);
	}
	iscsi_cmnds_init_write(&send, 0);
	return;
}

static void iscsi_init_status_rsp(struct iscsi_cmnd *rsp,
	int status, const u8 *sense_buf, int sense_len)
{
	struct iscsi_cmnd *req = rsp->parent_req;
	struct iscsi_scsi_rsp_hdr *rsp_hdr;
	struct scatterlist *sg;

	TRACE_ENTRY();

	rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_SCSI_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->response = ISCSI_RESPONSE_COMMAND_COMPLETED;
	rsp_hdr->cmd_status = status;
	rsp_hdr->itt = cmnd_hdr(req)->itt;

	if (scst_sense_valid(sense_buf)) {
		TRACE_DBG("%s", "SENSE VALID");

		sg = rsp->sg = rsp->rsp_sg;
		rsp->sg_cnt = 2;
		rsp->own_sg = 1;

		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], &rsp->sense_hdr, sizeof(rsp->sense_hdr));
		sg_set_buf(&sg[1], sense_buf, sense_len);

		rsp->sense_hdr.length = cpu_to_be16(sense_len);

		rsp->pdu.datasize = sizeof(rsp->sense_hdr) + sense_len;
		rsp->bufflen = rsp->pdu.datasize;
	} else {
		rsp->pdu.datasize = 0;
		rsp->bufflen = 0;
	}

	TRACE_EXIT();
	return;
}

static inline struct iscsi_cmnd *create_status_rsp(struct iscsi_cmnd *req,
	int status, const u8 *sense_buf, int sense_len)
{
	struct iscsi_cmnd *rsp;

	TRACE_ENTRY();

	rsp = iscsi_alloc_rsp(req);
	TRACE_DBG("rsp %p", rsp);

	iscsi_init_status_rsp(rsp, status, sense_buf, sense_len);
	iscsi_set_resid(rsp);

	TRACE_EXIT_HRES((unsigned long)rsp);
	return rsp;
}

/*
 * Initializes data receive fields. Can be called only when they have not been
 * initialized yet.
 */
static int iscsi_set_prelim_r2t_len_to_receive(struct iscsi_cmnd *req)
{
	struct iscsi_scsi_cmd_hdr *req_hdr = (struct iscsi_scsi_cmd_hdr *)&req->pdu.bhs;
	int res = 0;
	unsigned int not_received;

	TRACE_ENTRY();

	if (req_hdr->flags & ISCSI_CMD_FINAL) {
		if (req_hdr->flags & ISCSI_CMD_WRITE)
			iscsi_set_not_received_data_len(req,
				be32_to_cpu(req_hdr->data_length) -
				req->pdu.datasize);
		goto out;
	}

	sBUG_ON(req->outstanding_r2t != 0);

	res = cmnd_insert_data_wait_hash(req);
	if (res != 0) {
		/*
		 * We have to close connection, because otherwise a data
		 * corruption is possible if we allow to receive data
		 * for this request in another request with duplicated ITT.
		 */
		mark_conn_closed(req->conn);
		goto out;
	}

	/*
	 * We need to wait for one or more PDUs. Let's simplify
	 * other code and pretend we need to receive 1 byte.
	 * In data_out_start() we will correct it.
	 */
	req->outstanding_r2t = 1;
	req_add_to_write_timeout_list(req);
	req->r2t_len_to_receive = 1;
	req->r2t_len_to_send = 0;

	not_received = be32_to_cpu(req_hdr->data_length) - req->pdu.datasize;
	not_received -= min_t(unsigned int, not_received,
			req->conn->session->sess_params.first_burst_length);
	iscsi_set_not_received_data_len(req, not_received);

	TRACE_DBG("req %p, op %x, outstanding_r2t %d, r2t_len_to_receive %d, "
		"r2t_len_to_send %d, not_received_data_len %d", req,
		cmnd_opcode(req), req->outstanding_r2t, req->r2t_len_to_receive,
		req->r2t_len_to_send, req->not_received_data_len);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int create_preliminary_no_scst_rsp(struct iscsi_cmnd *req,
	int status, const u8 *sense_buf, int sense_len)
{
	struct iscsi_cmnd *rsp;
	int res = 0;

	TRACE_ENTRY();

	if (req->prelim_compl_flags != 0) {
		TRACE_MGMT_DBG("req %p already prelim completed", req);
		goto out;
	}

	req->scst_state = ISCSI_CMD_STATE_OUT_OF_SCST_PRELIM_COMPL;

	sBUG_ON(req->scst_cmd != NULL);

	res = iscsi_preliminary_complete(req, req, true);

	rsp = iscsi_alloc_main_rsp(req);
	TRACE_DBG("main rsp %p", rsp);

	iscsi_init_status_rsp(rsp, status, sense_buf, sense_len);

	/* Resid will be set in req_cmnd_release() */

out:
	TRACE_EXIT_RES(res);
	return res;
}

int set_scst_preliminary_status_rsp(struct iscsi_cmnd *req,
	bool get_data, int key, int asc, int ascq)
{
	int res = 0;

	TRACE_ENTRY();

	if (req->scst_cmd == NULL) {
		/* There must be already error set */
		goto complete;
	}

	scst_set_cmd_error(req->scst_cmd, key, asc, ascq);

complete:
	res = iscsi_preliminary_complete(req, req, get_data);

	TRACE_EXIT_RES(res);
	return res;
}

static int create_reject_rsp(struct iscsi_cmnd *req, int reason, bool get_data)
{
	int res = 0;
	struct iscsi_cmnd *rsp;
	struct iscsi_reject_hdr *rsp_hdr;
	struct scatterlist *sg;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Reject: req %p, reason %x", req, reason);

	if (cmnd_opcode(req) == ISCSI_OP_SCSI_CMD) {
		if (req->scst_cmd == NULL) {
			/* BUSY status must be already set */
			struct iscsi_scsi_rsp_hdr *rsp_hdr1;
			rsp_hdr1 = (struct iscsi_scsi_rsp_hdr *)&req->main_rsp->pdu.bhs;
			sBUG_ON(rsp_hdr1->cmd_status == 0);
			/*
			 * Let's not send REJECT here. The initiator will retry
			 * and, hopefully, next time we will not fail allocating
			 * scst_cmd, so we will then send the REJECT.
			 */
			goto out;
		} else {
			/*
			 * "In all the cases in which a pre-instantiated SCSI
			 * task is terminated because of the reject, the target
			 * MUST issue a proper SCSI command response with CHECK
			 * CONDITION as described in Section 10.4.3 Response" -
			 * RFC 3720.
			 */
			set_scst_preliminary_status_rsp(req, get_data,
				SCST_LOAD_SENSE(scst_sense_invalid_message));
		}
	}

	rsp = iscsi_alloc_main_rsp(req);
	rsp_hdr = (struct iscsi_reject_hdr *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_REJECT;
	rsp_hdr->ffffffff = ISCSI_RESERVED_TAG;
	rsp_hdr->reason = reason;

	sg = rsp->sg = rsp->rsp_sg;
	rsp->sg_cnt = 1;
	rsp->own_sg = 1;
	sg_init_one(sg, &req->pdu.bhs, sizeof(struct iscsi_hdr));
	rsp->bufflen = rsp->pdu.datasize = sizeof(struct iscsi_hdr);

	res = iscsi_preliminary_complete(req, req, true);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static inline int iscsi_get_allowed_cmds(struct iscsi_session *sess)
{
	int res = max(-1, (int)sess->tgt_params.queued_cmnds -
				atomic_read(&sess->active_cmds)-1);
	TRACE_DBG("allowed cmds %d (sess %p, active_cmds %d)", res,
		sess, atomic_read(&sess->active_cmds));
	return res;
}

static __be32 cmnd_set_sn(struct iscsi_cmnd *cmnd, int set_stat_sn)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_session *sess = conn->session;
	__be32 res;

	spin_lock(&sess->sn_lock);

	if (set_stat_sn)
		cmnd->pdu.bhs.sn = (__force u32)cpu_to_be32(conn->stat_sn++);
	cmnd->pdu.bhs.exp_sn = (__force u32)cpu_to_be32(sess->exp_cmd_sn);
	cmnd->pdu.bhs.max_sn = (__force u32)cpu_to_be32(sess->exp_cmd_sn +
				 iscsi_get_allowed_cmds(sess));

	res = cpu_to_be32(conn->stat_sn);

	spin_unlock(&sess->sn_lock);
	return res;
}

/* Called under sn_lock */
static void update_stat_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	u32 exp_stat_sn;

	cmnd->pdu.bhs.exp_sn = exp_stat_sn = be32_to_cpu((__force __be32)cmnd->pdu.bhs.exp_sn);
	TRACE_DBG("%x,%x", cmnd_opcode(cmnd), exp_stat_sn);
	if ((int)(exp_stat_sn - conn->exp_stat_sn) > 0 &&
	    (int)(exp_stat_sn - conn->stat_sn) <= 0) {
		/* free pdu resources */
		cmnd->conn->exp_stat_sn = exp_stat_sn;
	}
	return;
}

static struct iscsi_cmnd *cmnd_find_itt_get(struct iscsi_conn *conn, __be32 itt)
{
	struct iscsi_cmnd *cmnd, *found_cmnd = NULL;

	spin_lock_bh(&conn->cmd_list_lock);
	list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
		if ((cmnd->pdu.bhs.itt == itt) && !cmnd_get_check(cmnd)) {
			found_cmnd = cmnd;
			break;
		}
	}
	spin_unlock_bh(&conn->cmd_list_lock);

	return found_cmnd;
}

/**
 ** We use the ITT hash only to find original request PDU for subsequent
 ** Data-Out PDUs.
 **/

/* Must be called under cmnd_data_wait_hash_lock */
static struct iscsi_cmnd *__cmnd_find_data_wait_hash(struct iscsi_conn *conn,
	__be32 itt)
{
	struct list_head *head;
	struct iscsi_cmnd *cmnd;

	head = &conn->session->cmnd_data_wait_hash[cmnd_hashfn((__force u32)itt)];

	list_for_each_entry(cmnd, head, hash_list_entry) {
		if (cmnd->pdu.bhs.itt == itt)
			return cmnd;
	}
	return NULL;
}

static struct iscsi_cmnd *cmnd_find_data_wait_hash(struct iscsi_conn *conn,
	__be32 itt)
{
	struct iscsi_cmnd *res;
	struct iscsi_session *session = conn->session;

	spin_lock(&session->cmnd_data_wait_hash_lock);
	res = __cmnd_find_data_wait_hash(conn, itt);
	spin_unlock(&session->cmnd_data_wait_hash_lock);

	return res;
}

static inline u32 get_next_ttt(struct iscsi_conn *conn)
{
	u32 ttt;
	struct iscsi_session *session = conn->session;

	/* Not compatible with MC/S! */

	iscsi_extracheck_is_rd_thread(conn);

	if (unlikely(session->next_ttt == ISCSI_RESERVED_TAG_CPU32))
		session->next_ttt++;
	ttt = session->next_ttt++;

	return ttt;
}

static int cmnd_insert_data_wait_hash(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;
	struct list_head *head;
	int err = 0;
	__be32 itt = cmnd->pdu.bhs.itt;

	if (unlikely(cmnd->hashed)) {
		/*
		 * It can be for preliminary completed commands, when this
		 * function already failed.
		 */
		goto out;
	}

	/*
	 * We don't need TTT, because ITT/buffer_offset pair is sufficient
	 * to find out the original request and buffer for Data-Out PDUs, but
	 * crazy iSCSI spec requires us to send this superfluous field in
	 * R2T PDUs and some initiators may rely on it.
	 */
	cmnd->target_task_tag = get_next_ttt(cmnd->conn);

	TRACE_DBG("%p:%x", cmnd, itt);
	if (unlikely(itt == ISCSI_RESERVED_TAG)) {
		PRINT_ERROR("%s", "ITT is RESERVED_TAG");
		PRINT_BUFFER("Incorrect BHS", &cmnd->pdu.bhs,
			sizeof(cmnd->pdu.bhs));
		err = -ISCSI_REASON_PROTOCOL_ERROR;
		goto out;
	}

	spin_lock(&session->cmnd_data_wait_hash_lock);

	head = &session->cmnd_data_wait_hash[cmnd_hashfn((__force u32)itt)];

	tmp = __cmnd_find_data_wait_hash(cmnd->conn, itt);
	if (likely(!tmp)) {
		TRACE_DBG("Adding cmnd %p to the hash (ITT %x)", cmnd,
			cmnd->pdu.bhs.itt);
		list_add_tail(&cmnd->hash_list_entry, head);
		cmnd->hashed = 1;
	} else {
		PRINT_ERROR("Task %x in progress, cmnd %p", itt, cmnd);
		err = -ISCSI_REASON_TASK_IN_PROGRESS;
	}

	spin_unlock(&session->cmnd_data_wait_hash_lock);

out:
	return err;
}

static void cmnd_remove_data_wait_hash(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;

	spin_lock(&session->cmnd_data_wait_hash_lock);

	tmp = __cmnd_find_data_wait_hash(cmnd->conn, cmnd->pdu.bhs.itt);

	if (likely(tmp && tmp == cmnd)) {
		TRACE_DBG("Deleting cmnd %p from the hash (ITT %x)", cmnd,
			cmnd->pdu.bhs.itt);
		list_del(&cmnd->hash_list_entry);
		cmnd->hashed = 0;
	} else
		PRINT_ERROR("%p:%x not found", cmnd, cmnd->pdu.bhs.itt);

	spin_unlock(&session->cmnd_data_wait_hash_lock);

	return;
}

static void cmnd_prepare_get_rejected_immed_data(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct scatterlist *sg = cmnd->sg;
	char __user *addr;
	u32 size;
	unsigned int i;

	TRACE_ENTRY();

	TRACE_DBG_FLAG(iscsi_get_flow_ctrl_or_mgmt_dbg_log_flag(cmnd),
		"Skipping (cmnd %p, ITT %x, op %x, cmd op %x, "
		"datasize %u, scst_cmd %p, scst state %d)", cmnd,
		cmnd->pdu.bhs.itt, cmnd_opcode(cmnd), cmnd_hdr(cmnd)->scb[0],
		cmnd->pdu.datasize, cmnd->scst_cmd, cmnd->scst_state);

	iscsi_extracheck_is_rd_thread(conn);

	size = cmnd->pdu.datasize;
	if (!size)
		goto out;

	/* We already checked pdu.datasize in check_segment_length() */

	/*
	 * There are no problems with the safety from concurrent
	 * accesses to dummy_page in dummy_sg, since data only
	 * will be read and then discarded.
	 */
	sg = &dummy_sg;
	if (cmnd->sg == NULL) {
		/* just in case */
		cmnd->sg = sg;
		cmnd->bufflen = PAGE_SIZE;
		cmnd->own_sg = 1;
	}

	addr = (char __force __user *)(page_address(sg_page(&sg[0])));
	conn->read_size = size;
	for (i = 0; size > PAGE_SIZE; i++, size -= PAGE_SIZE) {
		/* We already checked pdu.datasize in check_segment_length() */
		sBUG_ON(i >= ISCSI_CONN_IOV_MAX);
		conn->read_iov[i].iov_base = addr;
		conn->read_iov[i].iov_len = PAGE_SIZE;
	}
	conn->read_iov[i].iov_base = addr;
	conn->read_iov[i].iov_len = size;
	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_msg.msg_iovlen = ++i;

out:
	TRACE_EXIT();
	return;
}

int iscsi_preliminary_complete(struct iscsi_cmnd *req,
	struct iscsi_cmnd *orig_req, bool get_data)
{
	int res = 0;
	bool set_r2t_len;
	struct iscsi_hdr *orig_req_hdr = &orig_req->pdu.bhs;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_DEBUG
	{
		struct iscsi_hdr *req_hdr = &req->pdu.bhs;
		TRACE_DBG_FLAG(iscsi_get_flow_ctrl_or_mgmt_dbg_log_flag(orig_req),
			"Prelim completed req %p, orig_req %p (FINAL %x, "
			"outstanding_r2t %d)", req, orig_req,
			(req_hdr->flags & ISCSI_CMD_FINAL),
			orig_req->outstanding_r2t);
	}
#endif

	iscsi_extracheck_is_rd_thread(req->conn);
	sBUG_ON(req->parent_req != NULL);

	if (test_bit(ISCSI_CMD_PRELIM_COMPLETED, &req->prelim_compl_flags)) {
		TRACE_MGMT_DBG("req %p already prelim completed", req);
		/* To not try to get data twice */
		get_data = false;
	}

	/*
	 * We need to receive all outstanding PDUs, even if direction isn't
	 * WRITE. Test of PRELIM_COMPLETED is needed, because
	 * iscsi_set_prelim_r2t_len_to_receive() could also have failed before.
	 */
	set_r2t_len = !orig_req->hashed &&
		      (cmnd_opcode(orig_req) == ISCSI_OP_SCSI_CMD) &&
		      !test_bit(ISCSI_CMD_PRELIM_COMPLETED,
				&orig_req->prelim_compl_flags);

	TRACE_DBG("get_data %d, set_r2t_len %d", get_data, set_r2t_len);

	if (get_data)
		cmnd_prepare_get_rejected_immed_data(req);

	if (test_bit(ISCSI_CMD_PRELIM_COMPLETED, &orig_req->prelim_compl_flags))
		goto out_set;

	if (set_r2t_len)
		res = iscsi_set_prelim_r2t_len_to_receive(orig_req);
	else if (orig_req_hdr->flags & ISCSI_CMD_WRITE) {
		/*
		 * We will get here if orig_req prelim completed in the middle
		 * of data receiving. We won't send more R2T's, so
		 * r2t_len_to_send is final and won't be updated anymore in
		 * future.
		 */
		iscsi_set_not_received_data_len(orig_req,
			orig_req->r2t_len_to_send);
	}

out_set:
	set_bit(ISCSI_CMD_PRELIM_COMPLETED, &orig_req->prelim_compl_flags);
	set_bit(ISCSI_CMD_PRELIM_COMPLETED, &req->prelim_compl_flags);

	TRACE_EXIT_RES(res);
	return res;
}

static int cmnd_prepare_recv_pdu(struct iscsi_conn *conn,
	struct iscsi_cmnd *cmd,	u32 offset, u32 size)
{
	struct scatterlist *sg = cmd->sg;
	unsigned int bufflen = cmd->bufflen;
	unsigned int idx, i, buff_offs;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("cmd %p, sg %p, offset %u, size %u", cmd, cmd->sg,
		offset, size);

	iscsi_extracheck_is_rd_thread(conn);

	buff_offs = offset;
	idx = (offset + sg[0].offset) >> PAGE_SHIFT;
	offset &= ~PAGE_MASK;

	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_size = size;

	i = 0;
	while (1) {
		unsigned int sg_len;
		char __user *addr;

		if (unlikely(buff_offs >= bufflen)) {
			TRACE_DBG("Residual overflow (cmd %p, buff_offs %d, "
				"bufflen %d)", cmd, buff_offs, bufflen);
			idx = 0;
			sg = &dummy_sg;
			offset = 0;
		}

		addr = (char __force __user *)(sg_virt(&sg[idx]));
		EXTRACHECKS_BUG_ON(addr == NULL);
		sg_len = sg[idx].length - offset;

		conn->read_iov[i].iov_base = addr + offset;

		if (size <= sg_len) {
			TRACE_DBG("idx=%d, i=%d, offset=%u, size=%d, addr=%p",
				idx, i, offset, size, addr);
			conn->read_iov[i].iov_len = size;
			conn->read_msg.msg_iovlen = i+1;
			break;
		}
		conn->read_iov[i].iov_len = sg_len;

		TRACE_DBG("idx=%d, i=%d, offset=%u, size=%d, sg_len=%u, "
			"addr=%p", idx, i, offset, size, sg_len, addr);

		size -= sg_len;
		buff_offs += sg_len;

		i++;
		if (unlikely(i >= ISCSI_CONN_IOV_MAX)) {
			PRINT_ERROR("Initiator %s violated negotiated "
				"parameters by sending too much data (size "
				"left %d)", conn->session->initiator_name,
				size);
			mark_conn_closed(conn);
			res = -EINVAL;
			break;
		}

		idx++;
		offset = 0;
	}

	TRACE_DBG("msg_iov=%p, msg_iovlen=%zd",
		conn->read_msg.msg_iov, conn->read_msg.msg_iovlen);

	TRACE_EXIT_RES(res);
	return res;
}

static void send_r2t(struct iscsi_cmnd *req)
{
	struct iscsi_session *sess = req->conn->session;
	struct iscsi_cmnd *rsp;
	struct iscsi_r2t_hdr *rsp_hdr;
	u32 offset, burst;
	LIST_HEAD(send);

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(req->r2t_len_to_send == 0);

	/*
	 * There is no race with data_out_start() and conn_abort(), since
	 * all functions called from single read thread
	 */
	iscsi_extracheck_is_rd_thread(req->conn);

	/*
	 * We don't need to check for PRELIM_COMPLETED here, because for such
	 * commands we set r2t_len_to_send = 0, hence made sure we won't be
	 * called here.
	 */

	EXTRACHECKS_BUG_ON(req->outstanding_r2t >
			   sess->sess_params.max_outstanding_r2t);

	if (req->outstanding_r2t == sess->sess_params.max_outstanding_r2t)
		goto out;

	burst = sess->sess_params.max_burst_length;
	offset = be32_to_cpu(cmnd_hdr(req)->data_length) -
			req->r2t_len_to_send;

	do {
		rsp = iscsi_alloc_rsp(req);
		rsp->pdu.bhs.ttt = (__force __be32)req->target_task_tag;
		rsp_hdr = (struct iscsi_r2t_hdr *)&rsp->pdu.bhs;
		rsp_hdr->opcode = ISCSI_OP_R2T;
		rsp_hdr->flags = ISCSI_FLG_FINAL;
		rsp_hdr->lun = cmnd_hdr(req)->lun;
		rsp_hdr->itt = cmnd_hdr(req)->itt;
		rsp_hdr->r2t_sn = (__force u32)cpu_to_be32(req->r2t_sn++);
		rsp_hdr->buffer_offset = cpu_to_be32(offset);
		if (req->r2t_len_to_send > burst) {
			rsp_hdr->data_length = cpu_to_be32(burst);
			req->r2t_len_to_send -= burst;
			offset += burst;
		} else {
			rsp_hdr->data_length = cpu_to_be32(req->r2t_len_to_send);
			req->r2t_len_to_send = 0;
		}

		TRACE_WRITE("req %p, data_length %u, buffer_offset %u, "
			"r2t_sn %u, outstanding_r2t %u", req,
			be32_to_cpu(rsp_hdr->data_length),
			be32_to_cpu(rsp_hdr->buffer_offset),
			be32_to_cpu((__force __be32)rsp_hdr->r2t_sn), req->outstanding_r2t);

		list_add_tail(&rsp->write_list_entry, &send);
		req->outstanding_r2t++;

	} while ((req->outstanding_r2t < sess->sess_params.max_outstanding_r2t) &&
		 (req->r2t_len_to_send != 0));

	iscsi_cmnds_init_write(&send, ISCSI_INIT_WRITE_WAKE);

out:
	TRACE_EXIT();
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

static int nop_out_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_hdr *req_hdr = &cmnd->pdu.bhs;
	u32 size, tmp;
	int i, err = 0;

	TRACE_DBG("%p", cmnd);

	iscsi_extracheck_is_rd_thread(conn);

	if (!(req_hdr->flags & ISCSI_FLG_FINAL)) {
		PRINT_ERROR("%s", "Initiator sent Nop-Out with not a single "
			"PDU");
		err = -ISCSI_REASON_PROTOCOL_ERROR;
		goto out;
	}

	if (cmnd->pdu.bhs.itt == ISCSI_RESERVED_TAG) {
		if (unlikely(!(cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE)))
			PRINT_ERROR("%s", "Initiator sent RESERVED tag for "
				"non-immediate Nop-Out command");
	}

	update_stat_sn(cmnd);

	size = cmnd->pdu.datasize;

	if (size) {
		conn->read_msg.msg_iov = conn->read_iov;
		if (cmnd->pdu.bhs.itt != ISCSI_RESERVED_TAG) {
			struct scatterlist *sg;

			cmnd->sg = sg = scst_alloc_sg(size, GFP_KERNEL,
						&cmnd->sg_cnt);
			if (sg == NULL) {
				TRACE(TRACE_OUT_OF_MEM, "Allocation of buffer "
					"for %d Nop-Out payload failed", size);
				err = -ISCSI_REASON_OUT_OF_RESOURCES;
				goto out;
			}

			/* We already checked it in check_segment_length() */
			sBUG_ON(cmnd->sg_cnt > (signed)ISCSI_CONN_IOV_MAX);

			cmnd->own_sg = 1;
			cmnd->bufflen = size;

			for (i = 0; i < cmnd->sg_cnt; i++) {
				conn->read_iov[i].iov_base =
					(void __force __user *)(page_address(sg_page(&sg[i])));
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
			for (i = 0; i < (signed)ISCSI_CONN_IOV_MAX; i++) {
				conn->read_iov[i].iov_base =
					(void __force __user *)(page_address(dummy_page));
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

int cmnd_rx_continue(struct iscsi_cmnd *req)
{
	struct iscsi_conn *conn = req->conn;
	struct iscsi_session *session = conn->session;
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);
	struct scst_cmd *scst_cmd = req->scst_cmd;
	scst_data_direction dir;
	bool unsolicited_data_expected = false;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("scsi command: %x", req_hdr->scb[0]);

	EXTRACHECKS_BUG_ON(req->scst_state != ISCSI_CMD_STATE_AFTER_PREPROC);

	dir = scst_cmd_get_data_direction(scst_cmd);

	/*
	 * Check for preliminary completion here to save R2Ts. For TASK QUEUE
	 * FULL statuses that might be a big performance win.
	 */
	if (unlikely(scst_cmd_prelim_completed(scst_cmd) ||
	    unlikely(req->prelim_compl_flags != 0))) {
		/*
		 * If necessary, ISCSI_CMD_ABORTED will be set by
		 * iscsi_xmit_response().
		 */
		res = iscsi_preliminary_complete(req, req, true);
		goto trace;
	}

	/* For prelim completed commands sg & K can be already set! */

	if (dir & SCST_DATA_WRITE) {
		req->bufflen = scst_cmd_get_write_fields(scst_cmd, &req->sg,
				&req->sg_cnt);
		unsolicited_data_expected = !(req_hdr->flags & ISCSI_CMD_FINAL);

		if (unlikely(session->sess_params.initial_r2t &&
		    unsolicited_data_expected)) {
			PRINT_ERROR("Initiator %s violated negotiated "
				"parameters: initial R2T is required (ITT %x, "
				"op  %x)", session->initiator_name,
				req->pdu.bhs.itt, req_hdr->scb[0]);
			goto out_close;
		}

		if (unlikely(!session->sess_params.immediate_data &&
		    req->pdu.datasize)) {
			PRINT_ERROR("Initiator %s violated negotiated "
				"parameters: forbidden immediate data sent "
				"(ITT %x, op  %x)", session->initiator_name,
				req->pdu.bhs.itt, req_hdr->scb[0]);
			goto out_close;
		}

		if (unlikely(session->sess_params.first_burst_length < req->pdu.datasize)) {
			PRINT_ERROR("Initiator %s violated negotiated "
				"parameters: immediate data len (%d) > "
				"first_burst_length (%d) (ITT %x, op  %x)",
				session->initiator_name,
				req->pdu.datasize,
				session->sess_params.first_burst_length,
				req->pdu.bhs.itt, req_hdr->scb[0]);
			goto out_close;
		}

		req->r2t_len_to_receive = be32_to_cpu(req_hdr->data_length) -
					  req->pdu.datasize;

		/*
		 * In case of residual overflow req->r2t_len_to_receive and
		 * req->pdu.datasize might be > req->bufflen
		 */

		res = cmnd_insert_data_wait_hash(req);
		if (unlikely(res != 0)) {
			/*
			 * We have to close connection, because otherwise a data
			 * corruption is possible if we allow to receive data
			 * for this request in another request with duplicated
			 * ITT.
			 */
			goto out_close;
		}

		if (unsolicited_data_expected) {
			req->outstanding_r2t = 1;
			req->r2t_len_to_send = req->r2t_len_to_receive -
				min_t(unsigned int,
				      session->sess_params.first_burst_length -
						req->pdu.datasize,
				      req->r2t_len_to_receive);
		} else
			req->r2t_len_to_send = req->r2t_len_to_receive;

		req_add_to_write_timeout_list(req);

		if (req->pdu.datasize) {
			res = cmnd_prepare_recv_pdu(conn, req, 0, req->pdu.datasize);
			/* For performance better to send R2Ts ASAP */
			if (likely(res == 0) && (req->r2t_len_to_send != 0))
				send_r2t(req);
		}
	} else {
		req->sg = scst_cmd_get_sg(scst_cmd);
		req->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
		req->bufflen = scst_cmd_get_bufflen(scst_cmd);

		if (unlikely(!(req_hdr->flags & ISCSI_CMD_FINAL) ||
			     req->pdu.datasize)) {
			PRINT_ERROR("Unexpected unsolicited data (ITT %x "
				"CDB %x)", req->pdu.bhs.itt, req_hdr->scb[0]);
			set_scst_preliminary_status_rsp(req, true,
				SCST_LOAD_SENSE(iscsi_sense_unexpected_unsolicited_data));
		}
	}

trace:
	TRACE_DBG("req=%p, dir=%d, unsolicited_data_expected=%d, "
		"r2t_len_to_receive=%d, r2t_len_to_send=%d, bufflen=%d, "
		"own_sg %d", req, dir, unsolicited_data_expected,
		req->r2t_len_to_receive, req->r2t_len_to_send, req->bufflen,
		req->own_sg);

out:
	TRACE_EXIT_RES(res);
	return res;

out_close:
	mark_conn_closed(conn);
	res = -EINVAL;
	goto out;
}

static int scsi_cmnd_start(struct iscsi_cmnd *req)
{
	struct iscsi_conn *conn = req->conn;
	struct iscsi_session *session = conn->session;
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);
	struct scst_cmd *scst_cmd;
	scst_data_direction dir;
	struct iscsi_ahs_hdr *ahdr;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("scsi command: %x", req_hdr->scb[0]);

	TRACE_DBG("Incrementing active_cmds (cmd %p, sess %p, "
		"new value %d)", req, session,
		atomic_read(&session->active_cmds)+1);
	atomic_inc(&session->active_cmds);
	req->dec_active_cmds = 1;

	scst_cmd = scst_rx_cmd(session->scst_sess,
		(uint8_t *)&req_hdr->lun, sizeof(req_hdr->lun),
		req_hdr->scb, sizeof(req_hdr->scb), SCST_NON_ATOMIC);
	if (scst_cmd == NULL) {
		res = create_preliminary_no_scst_rsp(req, SAM_STAT_BUSY,
			NULL, 0);
		goto out;
	}

	req->scst_cmd = scst_cmd;
	scst_cmd_set_tag(scst_cmd, (__force u32)req_hdr->itt);
	scst_cmd_set_tgt_priv(scst_cmd, req);

	if ((req_hdr->flags & ISCSI_CMD_READ) &&
	    (req_hdr->flags & ISCSI_CMD_WRITE)) {
		int sz = cmnd_read_size(req);
		if (unlikely(sz < 0)) {
			PRINT_ERROR("%s", "BIDI data transfer, but initiator "
				"not supplied Bidirectional Read Expected Data "
				"Transfer Length AHS");
			set_scst_preliminary_status_rsp(req, true,
			   SCST_LOAD_SENSE(scst_sense_parameter_value_invalid));
		} else {
			dir = SCST_DATA_BIDI;
			scst_cmd_set_expected(scst_cmd, dir, sz);
			scst_cmd_set_expected_out_transfer_len(scst_cmd,
				be32_to_cpu(req_hdr->data_length));
#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
			scst_cmd_set_tgt_need_alloc_data_buf(scst_cmd);
#endif
		}
	} else if (req_hdr->flags & ISCSI_CMD_READ) {
		dir = SCST_DATA_READ;
		scst_cmd_set_expected(scst_cmd, dir,
			be32_to_cpu(req_hdr->data_length));
#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
		scst_cmd_set_tgt_need_alloc_data_buf(scst_cmd);
#endif
	} else if (req_hdr->flags & ISCSI_CMD_WRITE) {
		dir = SCST_DATA_WRITE;
		scst_cmd_set_expected(scst_cmd, dir,
			be32_to_cpu(req_hdr->data_length));
	} else {
		dir = SCST_DATA_NONE;
		scst_cmd_set_expected(scst_cmd, dir, 0);
	}

	switch (req_hdr->flags & ISCSI_CMD_ATTR_MASK) {
	case ISCSI_CMD_SIMPLE:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case ISCSI_CMD_HEAD_OF_QUEUE:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case ISCSI_CMD_ORDERED:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case ISCSI_CMD_ACA:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ACA);
		break;
	case ISCSI_CMD_UNTAGGED:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	default:
		PRINT_WARNING("Unknown task code %x, use ORDERED instead",
			req_hdr->flags & ISCSI_CMD_ATTR_MASK);
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

	scst_cmd_set_tgt_sn(scst_cmd, req_hdr->cmd_sn);

	ahdr = (struct iscsi_ahs_hdr *)req->pdu.ahs;
	if (ahdr != NULL) {
		uint8_t *p = (uint8_t *)ahdr;
		unsigned int size = 0;
		do {
			int s;

			ahdr = (struct iscsi_ahs_hdr *)p;

			if (ahdr->ahstype == ISCSI_AHSTYPE_CDB) {
				struct iscsi_cdb_ahdr *eca =
					(struct iscsi_cdb_ahdr *)ahdr;
				scst_cmd_set_ext_cdb(scst_cmd, eca->cdb,
					be16_to_cpu(ahdr->ahslength) - 1,
					GFP_KERNEL);
				break;
			}
			s = 3 + be16_to_cpu(ahdr->ahslength);
			s = (s + 3) & -4;
			size += s;
			p += s;
		} while (size < req->pdu.ahssize);
	}

	TRACE_DBG("START Command (itt %x, queue_type %d)",
		req_hdr->itt, scst_cmd_get_queue_type(scst_cmd));
	req->scst_state = ISCSI_CMD_STATE_RX_CMD;
	conn->rx_task = current;
	scst_cmd_init_stage1_done(scst_cmd, SCST_CONTEXT_DIRECT, 0);

	if (req->scst_state != ISCSI_CMD_STATE_RX_CMD)
		res = cmnd_rx_continue(req);
	else {
		TRACE_DBG("Delaying req %p post processing (scst_state %d)",
			req, req->scst_state);
		res = 1;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int data_out_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_data_out_hdr *req_hdr =
		(struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
	struct iscsi_cmnd *orig_req;
#if 0
	struct iscsi_hdr *orig_req_hdr;
#endif
	u32 offset = be32_to_cpu(req_hdr->buffer_offset);
	int res = 0;

	TRACE_ENTRY();

	/*
	 * There is no race with send_r2t(), conn_abort() and
	 * iscsi_check_tm_data_wait_timeouts(), since
	 * all the functions called from single read thread
	 */
	iscsi_extracheck_is_rd_thread(cmnd->conn);

	update_stat_sn(cmnd);

	orig_req = cmnd_find_data_wait_hash(conn, req_hdr->itt);
	cmnd->cmd_req = orig_req;
	if (unlikely(orig_req == NULL)) {
		/*
		 * It shouldn't happen, since we don't abort any request until
		 * we received all related PDUs from the initiator or timeout
		 * them. Let's quietly drop such PDUs.
		 */
		TRACE_MGMT_DBG("Unable to find scsi task ITT %x",
			cmnd->pdu.bhs.itt);
		res = iscsi_preliminary_complete(cmnd, cmnd, true);
		goto out;
	}

	cmnd_get(orig_req);

	if (unlikely(orig_req->r2t_len_to_receive < cmnd->pdu.datasize)) {
		if (orig_req->prelim_compl_flags != 0) {
			/* We can have fake r2t_len_to_receive */
			goto go;
		}
		PRINT_ERROR("Data size (%d) > R2T length to receive (%d)",
			cmnd->pdu.datasize, orig_req->r2t_len_to_receive);
		set_scst_preliminary_status_rsp(orig_req, false,
			SCST_LOAD_SENSE(iscsi_sense_incorrect_amount_of_data));
		goto go;
	}

	/* Crazy iSCSI spec requires us to make this unneeded check */
#if 0 /* ...but some initiators (Windows) don't care to correctly set it */
	orig_req_hdr = &orig_req->pdu.bhs;
	if (unlikely(orig_req_hdr->lun != req_hdr->lun)) {
		PRINT_ERROR("Wrong LUN (%lld) in Data-Out PDU (expected %lld), "
			"orig_req %p, cmnd %p", (unsigned long long)req_hdr->lun,
			(unsigned long long)orig_req_hdr->lun, orig_req, cmnd);
		create_reject_rsp(orig_req, ISCSI_REASON_PROTOCOL_ERROR, false);
		goto go;
	}
#endif

go:
	if (req_hdr->flags & ISCSI_FLG_FINAL)
		orig_req->outstanding_r2t--;

	EXTRACHECKS_BUG_ON(orig_req->data_out_in_data_receiving);
	orig_req->data_out_in_data_receiving = 1;

	TRACE_WRITE("cmnd %p, orig_req %p, offset %u, datasize %u", cmnd,
		orig_req, offset, cmnd->pdu.datasize);

	if (unlikely(orig_req->prelim_compl_flags != 0))
		res = iscsi_preliminary_complete(cmnd, orig_req, true);
	else
		res = cmnd_prepare_recv_pdu(conn, orig_req, offset, cmnd->pdu.datasize);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void data_out_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_data_out_hdr *req_hdr =
		(struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
	struct iscsi_cmnd *req;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmnd == NULL);
	req = cmnd->cmd_req;
	if (unlikely(req == NULL))
		goto out;

	TRACE_DBG("cmnd %p, req %p", cmnd, req);

	iscsi_extracheck_is_rd_thread(cmnd->conn);

	req->data_out_in_data_receiving = 0;

	if (!(cmnd->conn->ddigest_type & DIGEST_NONE) &&
	    !cmnd->ddigest_checked) {
		cmd_add_on_rx_ddigest_list(req, cmnd);
		cmnd_get(cmnd);
	}

	/*
	 * Now we received the data and can adjust r2t_len_to_receive of the
	 * orig req. We couldn't do it earlier, because it will break data
	 * receiving errors recovery (calls of iscsi_fail_data_waiting_cmnd()).
	 */
	req->r2t_len_to_receive -= cmnd->pdu.datasize;

	if (unlikely(req->prelim_compl_flags != 0)) {
		/*
		 * We need to call iscsi_preliminary_complete() again
		 * to handle the case if we just been aborted. This call must
		 * be done before zeroing r2t_len_to_send to correctly calc.
		 * residual.
		 */
		iscsi_preliminary_complete(cmnd, req, false);

		/*
		 * We might need to wait for one or more PDUs. Let's simplify
		 * other code and not perform exact r2t_len_to_receive
		 * calculation.
		 */
		req->r2t_len_to_receive = req->outstanding_r2t;
		req->r2t_len_to_send = 0;
	}

	TRACE_DBG("req %p, FINAL %x, outstanding_r2t %d, r2t_len_to_receive %d,"
		" r2t_len_to_send %d", req, req_hdr->flags & ISCSI_FLG_FINAL,
		req->outstanding_r2t, req->r2t_len_to_receive,
		req->r2t_len_to_send);

	if (!(req_hdr->flags & ISCSI_FLG_FINAL))
		goto out_put;

	if (req->r2t_len_to_receive == 0) {
		if (!req->pending)
			iscsi_restart_cmnd(req);
	} else if (req->r2t_len_to_send != 0)
		send_r2t(req);

out_put:
	cmnd_put(req);
	cmnd->cmd_req = NULL;

out:
	TRACE_EXIT();
	return;
}

/* Might be called under target_mutex and cmd_list_lock */
static void __cmnd_abort(struct iscsi_cmnd *cmnd)
{
	unsigned long timeout_time = jiffies + ISCSI_TM_DATA_WAIT_TIMEOUT +
					ISCSI_ADD_SCHED_TIME;
	struct iscsi_conn *conn = cmnd->conn;

	TRACE_MGMT_DBG("Aborting cmd %p, scst_cmd %p (scst state %x, "
		"ref_cnt %d, on_write_timeout_list %d, write_start %ld, ITT %x, "
		"sn %u, op %x, r2t_len_to_receive %d, r2t_len_to_send %d, "
		"CDB op %x, size to write %u, outstanding_r2t %d, "
		"sess->exp_cmd_sn %u, conn %p, rd_task %p, read_cmnd %p, "
		"read_state %d)", cmnd, cmnd->scst_cmd, cmnd->scst_state,
		atomic_read(&cmnd->ref_cnt), cmnd->on_write_timeout_list,
		cmnd->write_start, cmnd->pdu.bhs.itt, cmnd->pdu.bhs.sn,
		cmnd_opcode(cmnd), cmnd->r2t_len_to_receive,
		cmnd->r2t_len_to_send, cmnd_scsicode(cmnd),
		cmnd_write_size(cmnd), cmnd->outstanding_r2t,
		cmnd->conn->session->exp_cmd_sn, cmnd->conn,
		cmnd->conn->rd_task, cmnd->conn->read_cmnd,
		cmnd->conn->read_state);

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	TRACE_MGMT_DBG("net_ref_cnt %d", atomic_read(&cmnd->net_ref_cnt));
#endif

	/*
	 * Lock to sync with iscsi_check_tm_data_wait_timeouts(), including
	 * CMD_ABORTED bit set.
	 */
	spin_lock_bh(&conn->conn_thr_pool->rd_lock);

	/*
	 * We suppose that preliminary commands completion is tested by
	 * comparing prelim_compl_flags with 0. Otherwise a race is possible,
	 * like sending command in SCST core as PRELIM_COMPLETED, while it
	 * wasn't aborted in it yet and have as the result a wrong success
	 * status sent to the initiator.
	 */
	set_bit(ISCSI_CMD_ABORTED, &cmnd->prelim_compl_flags);

	TRACE_MGMT_DBG("Setting conn_tm_active for conn %p", conn);
	conn->conn_tm_active = 1;

	spin_unlock_bh(&conn->conn_thr_pool->rd_lock);

	/*
	 * We need the lock to sync with req_add_to_write_timeout_list() and
	 * close races for rsp_timer.expires.
	 */
	spin_lock_bh(&conn->write_list_lock);
	if (!timer_pending(&conn->rsp_timer) ||
	    time_after(conn->rsp_timer.expires, timeout_time)) {
		TRACE_MGMT_DBG("Mod timer on %ld (conn %p)", timeout_time,
			conn);
		mod_timer(&conn->rsp_timer, timeout_time);
	} else
		TRACE_MGMT_DBG("Timer for conn %p is going to fire on %ld "
			"(timeout time %ld)", conn, conn->rsp_timer.expires,
			timeout_time);
	spin_unlock_bh(&conn->write_list_lock);

	return;
}

/* Must be called from the read or conn close thread */
static int cmnd_abort_pre_checks(struct iscsi_cmnd *req, int *status)
{
	struct iscsi_task_mgt_hdr *req_hdr =
		(struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
	struct iscsi_cmnd *cmnd;
	int res = -1;

	req_hdr->ref_cmd_sn = be32_to_cpu((__force __be32)req_hdr->ref_cmd_sn);

	if (!before(req_hdr->ref_cmd_sn, req_hdr->cmd_sn)) {
		TRACE(TRACE_MGMT, "ABORT TASK: RefCmdSN(%u) > CmdSN(%u)",
			req_hdr->ref_cmd_sn, req_hdr->cmd_sn);
		*status = ISCSI_RESPONSE_UNKNOWN_TASK;
		goto out;
	}

	cmnd = cmnd_find_itt_get(req->conn, req_hdr->rtt);
	if (cmnd) {
		struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

		if (req_hdr->lun != hdr->lun) {
			PRINT_ERROR("ABORT TASK: LUN mismatch: req LUN "
				    "%llx, cmd LUN %llx, rtt %u",
				    (long long unsigned)be64_to_cpu(req_hdr->lun),
				    (long long unsigned)be64_to_cpu(hdr->lun),
				    req_hdr->rtt);
			*status = ISCSI_RESPONSE_FUNCTION_REJECTED;
			goto out_put;
		}

		if (cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) {
			if (req_hdr->ref_cmd_sn != req_hdr->cmd_sn) {
				PRINT_ERROR("ABORT TASK: RefCmdSN(%u) != TM "
					"cmd CmdSN(%u) for immediate command "
					"%p", req_hdr->ref_cmd_sn,
					req_hdr->cmd_sn, cmnd);
				*status = ISCSI_RESPONSE_FUNCTION_REJECTED;
				goto out_put;
			}
		} else {
			if (req_hdr->ref_cmd_sn != hdr->cmd_sn) {
				PRINT_ERROR("ABORT TASK: RefCmdSN(%u) != "
					"CmdSN(%u) for command %p",
					req_hdr->ref_cmd_sn, req_hdr->cmd_sn,
					cmnd);
				*status = ISCSI_RESPONSE_FUNCTION_REJECTED;
				goto out_put;
			}
		}

		if (before(req_hdr->cmd_sn, hdr->cmd_sn) ||
		    (req_hdr->cmd_sn == hdr->cmd_sn)) {
			PRINT_ERROR("ABORT TASK: SN mismatch: req SN %x, "
				"cmd SN %x, rtt %u", req_hdr->cmd_sn,
				hdr->cmd_sn, req_hdr->rtt);
			*status = ISCSI_RESPONSE_FUNCTION_REJECTED;
			goto out_put;
		}

		cmnd_put(cmnd);
		res = 0;
	} else {
		TRACE_MGMT_DBG("cmd RTT %x not found", req_hdr->rtt);
		/*
		 * iSCSI RFC:
		 *
		 * b)  If the Referenced Task Tag does not identify an existing task,
		 * but if the CmdSN indicated by the RefCmdSN field in the Task
		 * Management function request is within the valid CmdSN window
		 * and less than the CmdSN of the Task Management function
		 * request itself, then targets must consider the CmdSN received
		 * and return the "Function complete" response.
		 *
		 * c)  If the Referenced Task Tag does not identify an existing task
		 * and if the CmdSN indicated by the RefCmdSN field in the Task
		 * Management function request is outside the valid CmdSN window,
		 * then targets must return the "Task does not exist" response.
		 *
		 * 128 seems to be a good "window".
		 */
		if (between(req_hdr->ref_cmd_sn, req_hdr->cmd_sn - 128,
			    req_hdr->cmd_sn)) {
			*status = ISCSI_RESPONSE_FUNCTION_COMPLETE;
			res = 0;
		} else
			*status = ISCSI_RESPONSE_UNKNOWN_TASK;
	}

out:
	return res;

out_put:
	cmnd_put(cmnd);
	goto out;
}

struct iscsi_cmnd_abort_params {
	struct work_struct iscsi_cmnd_abort_work;
	struct scst_cmd *scst_cmd;
};

static mempool_t *iscsi_cmnd_abort_mempool;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void iscsi_cmnd_abort_fn(void *ctx)
#else
static void iscsi_cmnd_abort_fn(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct iscsi_cmnd_abort_params *params = ctx;
#else
	struct iscsi_cmnd_abort_params *params = container_of(work,
		struct iscsi_cmnd_abort_params, iscsi_cmnd_abort_work);
#endif
	struct scst_cmd *scst_cmd = params->scst_cmd;
	struct iscsi_session *session = scst_sess_get_tgt_priv(scst_cmd->sess);
	struct iscsi_conn *conn;
	struct iscsi_cmnd *cmnd = scst_cmd_get_tgt_priv(scst_cmd);
	bool done = false;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Checking aborted scst_cmd %p (cmnd %p)", scst_cmd, cmnd);

	mutex_lock(&session->target->target_mutex);

	/*
	 * cmnd pointer is valid only under cmd_list_lock, but we can't know the
	 * corresponding conn without dereferencing cmnd at first, so let's
	 * check all conns and cmnds to find out if our cmnd is still valid
	 * under lock.
	 */
	list_for_each_entry(conn, &session->conn_list, conn_list_entry) {
		struct iscsi_cmnd *c;
		spin_lock_bh(&conn->cmd_list_lock);
		list_for_each_entry(c, &conn->cmd_list, cmd_list_entry) {
			if (c == cmnd) {
				__cmnd_abort(cmnd);
				done = true;
				break;
			}
		}
		spin_unlock_bh(&conn->cmd_list_lock);
		if (done)
			break;
	}

	mutex_unlock(&session->target->target_mutex);

	scst_cmd_put(scst_cmd);

	mempool_free(params, iscsi_cmnd_abort_mempool);

	TRACE_EXIT();
	return;
}

static void iscsi_on_abort_cmd(struct scst_cmd *scst_cmd)
{
	struct iscsi_cmnd_abort_params *params;

	TRACE_ENTRY();

	params = mempool_alloc(iscsi_cmnd_abort_mempool, GFP_ATOMIC);
	if (params == NULL) {
		PRINT_CRIT_ERROR("Unable to create iscsi_cmnd_abort_params, "
			"iSCSI cmnd for scst_cmd %p may not be aborted",
			scst_cmd);
		goto out;
	}

	memset(params, 0, sizeof(*params));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&params->iscsi_cmnd_abort_work, iscsi_cmnd_abort_fn, params);
#else
	INIT_WORK(&params->iscsi_cmnd_abort_work, iscsi_cmnd_abort_fn);
#endif
	params->scst_cmd = scst_cmd;

	scst_cmd_get(scst_cmd);

	TRACE_MGMT_DBG("Scheduling abort check for scst_cmd %p", scst_cmd);

	schedule_work(&params->iscsi_cmnd_abort_work);

out:
	TRACE_EXIT();
	return;
}

/* Must be called from the read or conn close thread */
void conn_abort(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd, *r, *t;

	TRACE_MGMT_DBG("Aborting conn %p", conn);

	iscsi_extracheck_is_rd_thread(conn);

	cancel_delayed_work_sync(&conn->nop_in_delayed_work);

	/* No locks, we are the only user */
	list_for_each_entry_safe(r, t, &conn->nop_req_list,
			nop_req_list_entry) {
		list_del(&r->nop_req_list_entry);
		cmnd_put(r);
	}

	spin_lock_bh(&conn->cmd_list_lock);
again:
	list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
		__cmnd_abort(cmnd);
		if (cmnd->r2t_len_to_receive != 0) {
			if (!cmnd_get_check(cmnd)) {
				spin_unlock_bh(&conn->cmd_list_lock);

				/* ToDo: this is racy for MC/S */
				iscsi_fail_data_waiting_cmnd(cmnd);

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
	int rc, status = ISCSI_RESPONSE_FUNCTION_REJECTED;
	int function = req_hdr->function & ISCSI_FUNCTION_MASK;
	struct scst_rx_mgmt_params params;

	TRACE(TRACE_MGMT, "iSCSI TM fn %d", function);

	TRACE_MGMT_DBG("TM req %p, ITT %x, RTT %x, sn %u, con %p", req,
		req->pdu.bhs.itt, req_hdr->rtt, req_hdr->cmd_sn, conn);

	iscsi_extracheck_is_rd_thread(conn);

	spin_lock(&sess->sn_lock);
	sess->tm_active++;
	sess->tm_sn = req_hdr->cmd_sn;
	if (sess->tm_rsp != NULL) {
		struct iscsi_cmnd *tm_rsp = sess->tm_rsp;

		TRACE_MGMT_DBG("Dropping delayed TM rsp %p", tm_rsp);

		sess->tm_rsp = NULL;
		sess->tm_active--;

		spin_unlock(&sess->sn_lock);

		sBUG_ON(sess->tm_active < 0);

		rsp_cmnd_release(tm_rsp);
	} else
		spin_unlock(&sess->sn_lock);

	scst_rx_mgmt_params_init(&params);

	params.atomic = SCST_NON_ATOMIC;
	params.tgt_priv = req;

	if ((function != ISCSI_FUNCTION_ABORT_TASK) &&
	    (req_hdr->rtt != ISCSI_RESERVED_TAG)) {
		PRINT_ERROR("Invalid RTT %x (TM fn %d)", req_hdr->rtt,
			function);
		rc = -1;
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		goto reject;
	}

	/* cmd_sn is already in CPU format converted in cmnd_rx_start() */

	switch (function) {
	case ISCSI_FUNCTION_ABORT_TASK:
		rc = cmnd_abort_pre_checks(req, &status);
		if (rc == 0) {
			params.fn = SCST_ABORT_TASK;
			params.tag = (__force u32)req_hdr->rtt;
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
		params.fn = SCST_TARGET_RESET;
		params.cmd_sn = req_hdr->cmd_sn;
		params.cmd_sn_set = 1;
		rc = scst_rx_mgmt_fn(conn->session->scst_sess,
			&params);
		status = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	case ISCSI_FUNCTION_LOGICAL_UNIT_RESET:
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

static void nop_out_exec(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_nop_in_hdr *rsp_hdr;

	TRACE_ENTRY();

	TRACE_DBG("%p", req);

	if (req->pdu.bhs.itt != ISCSI_RESERVED_TAG) {
		rsp = iscsi_alloc_main_rsp(req);

		rsp_hdr = (struct iscsi_nop_in_hdr *)&rsp->pdu.bhs;
		rsp_hdr->opcode = ISCSI_OP_NOP_IN;
		rsp_hdr->flags = ISCSI_FLG_FINAL;
		rsp_hdr->itt = req->pdu.bhs.itt;
		rsp_hdr->ttt = ISCSI_RESERVED_TAG;

		if (req->pdu.datasize)
			sBUG_ON(req->sg == NULL);
		else
			sBUG_ON(req->sg != NULL);

		if (req->sg) {
			rsp->sg = req->sg;
			rsp->sg_cnt = req->sg_cnt;
			rsp->bufflen = req->bufflen;
		}

		/* We already checked it in check_segment_length() */
		sBUG_ON(get_pgcnt(req->pdu.datasize, 0) > ISCSI_CONN_IOV_MAX);

		rsp->pdu.datasize = req->pdu.datasize;
	} else {
		bool found = false;
		struct iscsi_cmnd *r;
		struct iscsi_conn *conn = req->conn;

		TRACE_DBG("Receive Nop-In response (ttt 0x%08x)",
			  be32_to_cpu(req->pdu.bhs.ttt));

		spin_lock_bh(&conn->nop_req_list_lock);
		list_for_each_entry(r, &conn->nop_req_list,
				nop_req_list_entry) {
			if (req->pdu.bhs.ttt == r->pdu.bhs.ttt) {
				list_del(&r->nop_req_list_entry);
				found = true;
				break;
			}
		}
		spin_unlock_bh(&conn->nop_req_list_lock);

		if (found)
			cmnd_put(r);
		else
			TRACE_MGMT_DBG("%s", "Got Nop-out response without "
				"corresponding Nop-In request");
	}

	req_cmnd_release(req);

	TRACE_EXIT();
	return;
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
	rsp = iscsi_alloc_main_rsp(req);
	rsp_hdr = (struct iscsi_logout_rsp_hdr *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->itt = req_hdr->itt;
	rsp->should_close_conn = 1;

	req_cmnd_release(req);

	return;
}

static void iscsi_cmnd_exec(struct iscsi_cmnd *cmnd)
{
	TRACE_ENTRY();

	TRACE_DBG("cmnd %p, op %x, SN %u", cmnd, cmnd_opcode(cmnd),
		cmnd->pdu.bhs.sn);

	iscsi_extracheck_is_rd_thread(cmnd->conn);

	if (cmnd_opcode(cmnd) == ISCSI_OP_SCSI_CMD) {
		if (cmnd->r2t_len_to_receive == 0)
			iscsi_restart_cmnd(cmnd);
		else if (cmnd->r2t_len_to_send != 0)
			send_r2t(cmnd);
		goto out;
	}

	if (cmnd->prelim_compl_flags != 0) {
		TRACE_MGMT_DBG("Terminating prelim completed non-SCSI cmnd %p "
			"(op %x)", cmnd, cmnd_opcode(cmnd));
		req_cmnd_release(cmnd);
		goto out;
	}

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_OUT:
		nop_out_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		execute_task_management(cmnd);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		logout_exec(cmnd);
		break;
	default:
		PRINT_CRIT_ERROR("Unexpected cmnd op %x", cmnd_opcode(cmnd));
		sBUG();
		break;
	}

out:
	TRACE_EXIT();
	return;
}

static void set_cork(struct socket *sock, int on)
{
	int opt = on;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	sock->ops->setsockopt(sock, SOL_TCP, TCP_CORK,
			      (void __force __user *)&opt, sizeof(opt));
	set_fs(oldfs);
	return;
}

void cmnd_tx_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	TRACE_DBG("conn %p, cmnd %p, opcode %x", conn, cmnd, cmnd_opcode(cmnd));
	iscsi_cmnd_set_length(&cmnd->pdu);

	iscsi_extracheck_is_wr_thread(conn);

	set_cork(conn->sock, 1);

	conn->write_iop = conn->write_iov;
	conn->write_iop->iov_base = (void __force __user *)(&cmnd->pdu.bhs);
	conn->write_iop->iov_len = sizeof(cmnd->pdu.bhs);
	conn->write_iop_used = 1;
	conn->write_size = sizeof(cmnd->pdu.bhs) + cmnd->pdu.datasize;
	conn->write_offset = 0;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_IN:
		if (cmnd->pdu.bhs.itt == ISCSI_RESERVED_TAG)
			cmnd->pdu.bhs.sn = (__force u32)cmnd_set_sn(cmnd, 0);
		else
			cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_RSP:
		cmnd_set_sn(cmnd, 1);
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
		u32 offset = be32_to_cpu(rsp->buffer_offset);

		TRACE_DBG("cmnd %p, offset %u, datasize %u, bufflen %u", cmnd,
			offset, cmnd->pdu.datasize, cmnd->bufflen);

		sBUG_ON(offset > cmnd->bufflen);
		sBUG_ON(offset + cmnd->pdu.datasize > cmnd->bufflen);

		conn->write_offset = offset;

		cmnd_set_sn(cmnd, (rsp->flags & ISCSI_FLG_FINAL) ? 1 : 0);
		break;
	}
	case ISCSI_OP_LOGOUT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_R2T:
		cmnd->pdu.bhs.sn = (__force u32)cmnd_set_sn(cmnd, 0);
		break;
	case ISCSI_OP_ASYNC_MSG:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_REJECT:
		cmnd_set_sn(cmnd, 1);
		break;
	default:
		PRINT_ERROR("Unexpected cmnd op %x", cmnd_opcode(cmnd));
		break;
	}

	iscsi_dump_pdu(&cmnd->pdu);
	return;
}

void cmnd_tx_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	TRACE_DBG("%p:%x (should_close_conn %d, should_close_all_conn %d)",
		cmnd, cmnd_opcode(cmnd), cmnd->should_close_conn,
		cmnd->should_close_all_conn);

#ifdef CONFIG_SCST_EXTRACHECKS
	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_IN:
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
#endif

	if (unlikely(cmnd->should_close_conn)) {
		if (cmnd->should_close_all_conn) {
			struct iscsi_target *target = cmnd->conn->session->target;

			PRINT_INFO("Closing all connections for target %x at "
				"initiator's %s request", target->tid,
				conn->session->initiator_name);

			mutex_lock(&target->target_mutex);
			target_del_all_sess(target, 0);
			mutex_unlock(&target->target_mutex);
		} else {
			PRINT_INFO("Closing connection at initiator's %s "
				"request", conn->session->initiator_name);
			mark_conn_closed(conn);
		}
	}

	set_cork(cmnd->conn->sock, 0);
	return;
}

/*
 * Push the command for execution. This functions reorders the commands.
 * Called from the read thread.
 *
 * Basically, since we don't support MC/S and TCP guarantees data delivery
 * order, all that SN's stuff isn't needed at all (commands delivery order is
 * a natural commands execution order), but insane iSCSI spec requires
 * us to check it and we have to, because some crazy initiators can rely
 * on the SN's based order and reorder requests during sending. For all other
 * normal initiators all that code is a NOP.
 */
static void iscsi_push_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct list_head *entry;
	u32 cmd_sn;

	TRACE_DBG("cmnd %p, iSCSI opcode %x, sn %u, exp sn %u", cmnd,
		cmnd_opcode(cmnd), cmnd->pdu.bhs.sn, session->exp_cmd_sn);

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

			spin_lock(&session->sn_lock);

			if (list_empty(&session->pending_list))
				break;
			cmnd = list_first_entry(&session->pending_list,
					  struct iscsi_cmnd,
					  pending_list_entry);
			if (cmnd->pdu.bhs.sn != cmd_sn)
				break;

			list_del(&cmnd->pending_list_entry);
			cmnd->pending = 0;

			TRACE_MGMT_DBG("Processing pending cmd %p (cmd_sn %u)",
				cmnd, cmd_sn);
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
		 * separate write thread, rarely it is possible that initiator
		 * can legally send command with CmdSN>MaxSN. But it won't
		 * hurt anything, in the worst case it will lead to
		 * additional QUEUE FULL status.
		 */

		if (unlikely(before(cmd_sn, session->exp_cmd_sn))) {
			TRACE_MGMT_DBG("Ignoring out of expected range cmd_sn "
				"(sn %u, exp_sn %u, cmd %p, op %x, CDB op %x)",
				cmd_sn, session->exp_cmd_sn, cmnd,
				cmnd_opcode(cmnd), cmnd_scsicode(cmnd));
			drop = 1;
		}

#if 0
		if (unlikely(after(cmd_sn, session->exp_cmd_sn +
					iscsi_get_allowed_cmds(session)))) {
			TRACE_MGMT_DBG("Too large cmd_sn %u (exp_cmd_sn %u, "
				"max_sn %u)", cmd_sn, session->exp_cmd_sn,
				iscsi_get_allowed_cmds(session));
			drop = 1;
		}
#endif

		spin_unlock(&session->sn_lock);

		if (unlikely(drop)) {
			req_cmnd_release_force(cmnd);
			goto out;
		}

		if (unlikely(test_bit(ISCSI_CMD_ABORTED,
					&cmnd->prelim_compl_flags))) {
			struct iscsi_cmnd *tm_clone;

			TRACE_MGMT_DBG("Aborted pending cmnd %p, creating TM "
				"clone (scst cmd %p, state %d)", cmnd,
				cmnd->scst_cmd, cmnd->scst_state);

			tm_clone = iscsi_create_tm_clone(cmnd);
			if (tm_clone != NULL) {
				iscsi_cmnd_exec(cmnd);
				cmnd = tm_clone;
			}
		}

		TRACE_MGMT_DBG("Pending cmnd %p (op %x, sn %u, exp sn %u)",
			cmnd, cmnd_opcode(cmnd), cmd_sn, session->exp_cmd_sn);

		spin_lock(&session->sn_lock);
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

	spin_unlock(&session->sn_lock);
out:
	return;
}

static int check_segment_length(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_session *session = conn->session;

	if (unlikely(cmnd->pdu.datasize > session->sess_params.max_recv_data_length)) {
		PRINT_ERROR("Initiator %s violated negotiated parameters: "
			"data too long (ITT %x, datasize %u, "
			"max_recv_data_length %u", session->initiator_name,
			cmnd->pdu.bhs.itt, cmnd->pdu.datasize,
			session->sess_params.max_recv_data_length);
		mark_conn_closed(conn);
		return -EINVAL;
	}
	return 0;
}

int cmnd_rx_start(struct iscsi_cmnd *cmnd)
{
	int res, rc = 0;

	iscsi_dump_pdu(&cmnd->pdu);

	res = check_segment_length(cmnd);
	if (res != 0)
		goto out;

	cmnd->pdu.bhs.sn = be32_to_cpu((__force __be32)cmnd->pdu.bhs.sn);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_CMD:
		res = scsi_cmnd_start(cmnd);
		if (unlikely(res < 0))
			goto out;
		update_stat_sn(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		res = data_out_start(cmnd);
		goto out;
	case ISCSI_OP_NOP_OUT:
		rc = nop_out_start(cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	case ISCSI_OP_LOGOUT_CMD:
		update_stat_sn(cmnd);
		break;
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_SNACK_CMD:
	default:
		rc = -ISCSI_REASON_UNSUPPORTED_COMMAND;
		break;
	}

	if (unlikely(rc < 0)) {
		PRINT_ERROR("Error %d (iSCSI opcode %x, ITT %x)", rc,
			cmnd_opcode(cmnd), cmnd->pdu.bhs.itt);
		res = create_reject_rsp(cmnd, -rc, true);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

void cmnd_rx_end(struct iscsi_cmnd *cmnd)
{
	TRACE_ENTRY();

	TRACE_DBG("cmnd %p, opcode %x", cmnd, cmnd_opcode(cmnd));

	cmnd->conn->last_rcv_time = jiffies;
	TRACE_DBG("Updated last_rcv_time %ld", cmnd->conn->last_rcv_time);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_NOP_OUT:
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	case ISCSI_OP_LOGOUT_CMD:
		iscsi_push_cmnd(cmnd);
		goto out;
	case ISCSI_OP_SCSI_DATA_OUT:
		data_out_end(cmnd);
		break;
	default:
		PRINT_ERROR("Unexpected cmnd op %x", cmnd_opcode(cmnd));
		break;
	}

	req_cmnd_release(cmnd);

out:
	TRACE_EXIT();
	return;
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
	EXTRACHECKS_BUG_ON(!(scst_cmd_get_data_direction(cmd) & SCST_DATA_READ));
	scst_cmd_set_no_sgv(cmd);
	return 1;
}
#endif

static void iscsi_preprocessing_done(struct scst_cmd *scst_cmd)
{
	struct iscsi_cmnd *req = (struct iscsi_cmnd *)
				scst_cmd_get_tgt_priv(scst_cmd);

	TRACE_DBG("req %p", req);

	if (req->conn->rx_task == current)
		req->scst_state = ISCSI_CMD_STATE_AFTER_PREPROC;
	else {
		/*
		 * We wait for the state change without any protection, so
		 * without cmnd_get() it is possible that req will die
		 * "immediately" after the state assignment and
		 * iscsi_make_conn_rd_active() will operate on dead data.
		 * We use the ordered version of cmnd_get(), because "get"
		 * must be done before the state assignment.
		 *
		 * We protected from the race on calling cmnd_rx_continue(),
		 * because there can be only one read thread processing
		 * connection.
		 */
		cmnd_get(req);
		req->scst_state = ISCSI_CMD_STATE_AFTER_PREPROC;
		iscsi_make_conn_rd_active(req->conn);
		if (unlikely(req->conn->closing)) {
			TRACE_DBG("Waking up closing conn %p", req->conn);
			wake_up(&req->conn->read_state_waitQ);
		}
		cmnd_put(req);
	}

	return;
}

/* No locks */
static void iscsi_try_local_processing(struct iscsi_cmnd *req)
{
	struct iscsi_conn *conn = req->conn;
	struct iscsi_thread_pool *p = conn->conn_thr_pool;
	bool local;

	TRACE_ENTRY();

	spin_lock_bh(&p->wr_lock);
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
		local = true;
		break;
	default:
		local = false;
		break;
	}
	spin_unlock_bh(&p->wr_lock);

	if (local) {
		int rc = 1;

		do {
			rc = iscsi_send(conn);
			if (rc <= 0)
				break;
		} while (req->not_processed_rsp_cnt != 0);

		spin_lock_bh(&p->wr_lock);
#ifdef CONFIG_SCST_EXTRACHECKS
		conn->wr_task = NULL;
#endif
		if ((rc == -EAGAIN) && !conn->wr_space_ready) {
			TRACE_DBG("EAGAIN, setting WR_STATE_SPACE_WAIT "
				"(conn %p)", conn);
			conn->wr_state = ISCSI_CONN_WR_STATE_SPACE_WAIT;
		} else if (test_write_ready(conn)) {
			list_add_tail(&conn->wr_list_entry, &p->wr_list);
			conn->wr_state = ISCSI_CONN_WR_STATE_IN_LIST;
			wake_up(&p->wr_waitQ);
		} else
			conn->wr_state = ISCSI_CONN_WR_STATE_IDLE;
		spin_unlock_bh(&p->wr_lock);
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
	struct iscsi_cmnd *wr_rsp, *our_rsp;

	EXTRACHECKS_BUG_ON(scst_cmd_atomic(scst_cmd));

	scst_cmd_set_tgt_priv(scst_cmd, NULL);

	EXTRACHECKS_BUG_ON(req->scst_state != ISCSI_CMD_STATE_RESTARTED);

	if (unlikely(scst_cmd_aborted_on_xmit(scst_cmd)))
		set_bit(ISCSI_CMD_ABORTED, &req->prelim_compl_flags);

	if (unlikely(req->prelim_compl_flags != 0)) {
		if (test_bit(ISCSI_CMD_ABORTED, &req->prelim_compl_flags)) {
			TRACE_MGMT_DBG("req %p (scst_cmd %p) aborted", req,
				req->scst_cmd);
			scst_set_delivery_status(req->scst_cmd,
				SCST_CMD_DELIVERY_ABORTED);
			req->scst_state = ISCSI_CMD_STATE_PROCESSED;
			req_cmnd_release_force(req);
			goto out;
		}

		TRACE_DBG("Prelim completed req %p", req);

		/*
		 * We could preliminary have finished req before we
		 * knew its device, so check if we return correct sense
		 * format.
		 */
		scst_check_convert_sense(scst_cmd);

		if (!req->own_sg) {
			req->sg = scst_cmd_get_sg(scst_cmd);
			req->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
		}
	} else {
		EXTRACHECKS_BUG_ON(req->own_sg);
		req->sg = scst_cmd_get_sg(scst_cmd);
		req->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	}

	req->bufflen = scst_cmd_get_adjusted_resp_data_len(scst_cmd);

	req->scst_state = ISCSI_CMD_STATE_PROCESSED;

	TRACE_DBG("req %p, is_send_status=%x, req->bufflen=%d, req->sg=%p, "
		"req->sg_cnt %d", req, is_send_status, req->bufflen, req->sg,
		req->sg_cnt);

	EXTRACHECKS_BUG_ON(req->hashed);
	if (req->main_rsp != NULL)
		EXTRACHECKS_BUG_ON(cmnd_opcode(req->main_rsp) != ISCSI_OP_REJECT);

	if (unlikely((req->bufflen != 0) && !is_send_status)) {
		PRINT_CRIT_ERROR("%s", "Sending DATA without STATUS is "
			"unsupported");
		scst_set_cmd_error(scst_cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
		sBUG(); /* ToDo */
	}

	/*
	 * We need to decrement active_cmds before adding any responses into
	 * the write queue to eliminate a race, when all responses sent
	 * with wrong MaxCmdSN.
	 */
	if (likely(req->dec_active_cmds))
		iscsi_dec_active_cmds(req);

	if (req->bufflen != 0) {
		/*
		 * Check above makes sure that is_send_status is set,
		 * so status is valid here, but in future that could change.
		 * ToDo
		 */
		if ((status != SAM_STAT_CHECK_CONDITION) &&
		    ((cmnd_hdr(req)->flags & (ISCSI_CMD_WRITE|ISCSI_CMD_READ)) !=
				(ISCSI_CMD_WRITE|ISCSI_CMD_READ))) {
			send_data_rsp(req, status, is_send_status);
		} else {
			struct iscsi_cmnd *rsp;
			send_data_rsp(req, 0, 0);
			if (is_send_status) {
				rsp = create_status_rsp(req, status, sense,
						sense_len);
				iscsi_cmnd_init_write(rsp, 0);
			}
		}
	} else if (is_send_status) {
		struct iscsi_cmnd *rsp;
		rsp = create_status_rsp(req, status, sense, sense_len);
		iscsi_cmnd_init_write(rsp, 0);
	}
#ifdef CONFIG_SCST_EXTRACHECKS
	else
		sBUG();
#endif

	/*
	 * There's no need for protection, since we are not going to
	 * dereference them.
	 */
	wr_rsp = list_first_entry(&conn->write_list, struct iscsi_cmnd,
			write_list_entry);
	our_rsp = list_first_entry(&req->rsp_cmd_list, struct iscsi_cmnd,
			rsp_cmd_list_entry);
	if (wr_rsp == our_rsp) {
		/*
		 * This is our rsp, so let's try to process it locally to
		 * decrease latency. We need to call pre_release before
		 * processing to handle some error recovery cases.
		 */
		if (scst_get_active_cmd_count(scst_cmd) <= 2) {
			req_cmnd_pre_release(req);
			iscsi_try_local_processing(req);
			cmnd_put(req);
		} else {
			/*
			 * There's too much backend activity, so it could be
			 * better to push it to the write thread.
			 */
			goto out_push_to_wr_thread;
		}
	} else
		goto out_push_to_wr_thread;

out:
	return SCST_TGT_RES_SUCCESS;

out_push_to_wr_thread:
	TRACE_DBG("Waking up write thread (conn %p)", conn);
	req_cmnd_release(req);
	iscsi_make_conn_wr_active(conn);
	goto out;
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

/* Called under sn_lock, but might drop it inside, then reacquire */
static void iscsi_check_send_delayed_tm_resp(struct iscsi_session *sess)
	__acquires(&sn_lock)
	__releases(&sn_lock)
{
	struct iscsi_cmnd *tm_rsp = sess->tm_rsp;

	TRACE_ENTRY();

	if (tm_rsp == NULL)
		goto out;

	if (iscsi_is_delay_tm_resp(tm_rsp))
		goto out;

	TRACE_MGMT_DBG("Sending delayed rsp %p", tm_rsp);

	sess->tm_rsp = NULL;
	sess->tm_active--;

	spin_unlock(&sess->sn_lock);

	sBUG_ON(sess->tm_active < 0);

	iscsi_cmnd_init_write(tm_rsp, ISCSI_INIT_WRITE_WAKE);

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
	TRACE(TRACE_MGMT, "iSCSI TM fn %d finished, status %d", fn, status);

	rsp = iscsi_alloc_rsp(req);
	rsp_hdr = (struct iscsi_task_rsp_hdr *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_SCSI_TASK_MGT_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->itt = req_hdr->itt;
	rsp_hdr->response = status;

	if (fn == ISCSI_FUNCTION_TARGET_COLD_RESET) {
		rsp->should_close_conn = 1;
		rsp->should_close_all_conn = 1;
	}

	sBUG_ON(sess->tm_rsp != NULL);

	spin_lock(&sess->sn_lock);
	if (iscsi_is_delay_tm_resp(rsp)) {
		TRACE_MGMT_DBG("Delaying TM fn %d response %p "
			"(req %p), because not all affected commands "
			"received (TM cmd sn %u, exp sn %u)",
			req_hdr->function & ISCSI_FUNCTION_MASK, rsp, req,
			req_hdr->cmd_sn, sess->exp_cmd_sn);
		sess->tm_rsp = rsp;
		spin_unlock(&sess->sn_lock);
		goto out_release;
	}
	sess->tm_active--;
	spin_unlock(&sess->sn_lock);

	sBUG_ON(sess->tm_active < 0);

	iscsi_cmnd_init_write(rsp, ISCSI_INIT_WRITE_WAKE);

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
	int fn = scst_mgmt_cmd_get_fn(scst_mcmd);
	struct iscsi_cmnd *req = (struct iscsi_cmnd *)
				scst_mgmt_cmd_get_tgt_priv(scst_mcmd);
	int status =
		iscsi_get_mgmt_response(scst_mgmt_cmd_get_status(scst_mcmd));

	if ((status == ISCSI_RESPONSE_UNKNOWN_TASK) &&
	    (fn == SCST_ABORT_TASK)) {
		/* If we are here, we found the task, so must succeed */
		status = ISCSI_RESPONSE_FUNCTION_COMPLETE;
	}

	TRACE_MGMT_DBG("req %p, scst_mcmd %p, fn %d, scst status %d, status %d",
		req, scst_mcmd, fn, scst_mgmt_cmd_get_status(scst_mcmd),
		status);

	switch (fn) {
	case SCST_NEXUS_LOSS_SESS:
		/* Internal */
		break;
	case SCST_ABORT_ALL_TASKS_SESS:
	case SCST_ABORT_ALL_TASKS:
	case SCST_NEXUS_LOSS:
		sBUG_ON(1);
		break;
	default:
		iscsi_send_task_mgmt_resp(req, status);
		scst_mgmt_cmd_set_tgt_priv(scst_mcmd, NULL);
		break;
	}
	return;
}

static int iscsi_scsi_aen(struct scst_aen *aen)
{
	int res = SCST_AEN_RES_SUCCESS;
	__be64 lun = scst_aen_get_lun(aen);
	const uint8_t *sense = scst_aen_get_sense(aen);
	int sense_len = scst_aen_get_sense_len(aen);
	struct iscsi_session *sess = scst_sess_get_tgt_priv(
					scst_aen_get_sess(aen));
	struct iscsi_conn *conn;
	bool found;
	struct iscsi_cmnd *fake_req, *rsp;
	struct iscsi_async_msg_hdr *rsp_hdr;
	struct scatterlist *sg;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("SCSI AEN to sess %p (initiator %s)", sess,
		sess->initiator_name);

	mutex_lock(&sess->target->target_mutex);

	found = false;
	list_for_each_entry_reverse(conn, &sess->conn_list, conn_list_entry) {
		if (!test_bit(ISCSI_CONN_SHUTTINGDOWN, &conn->conn_aflags) &&
		    (conn->conn_reinst_successor == NULL)) {
			found = true;
			break;
		}
	}
	if (!found) {
		TRACE_MGMT_DBG("Unable to find alive conn for sess %p", sess);
		goto out_err_unlock;
	}

	/* Create a fake request */
	fake_req = cmnd_alloc(conn, NULL);
	if (fake_req == NULL) {
		PRINT_ERROR("%s", "Unable to alloc fake AEN request");
		goto out_err_unlock;
	}

	mutex_unlock(&sess->target->target_mutex);

	rsp = iscsi_alloc_main_rsp(fake_req);
	if (rsp == NULL) {
		PRINT_ERROR("%s", "Unable to alloc AEN rsp");
		goto out_err_free_req;
	}

	fake_req->scst_state = ISCSI_CMD_STATE_AEN;
	fake_req->scst_aen = aen;

	rsp_hdr = (struct iscsi_async_msg_hdr *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_ASYNC_MSG;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->lun = lun; /* it's already in SCSI form */
	rsp_hdr->ffffffff = cpu_to_be32(0xffffffff);
	rsp_hdr->async_event = ISCSI_ASYNC_SCSI;

	sg = rsp->sg = rsp->rsp_sg;
	rsp->sg_cnt = 2;
	rsp->own_sg = 1;

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], &rsp->sense_hdr, sizeof(rsp->sense_hdr));
	sg_set_buf(&sg[1], sense, sense_len);

	rsp->sense_hdr.length = cpu_to_be16(sense_len);
	rsp->pdu.datasize = sizeof(rsp->sense_hdr) + sense_len;
	rsp->bufflen = rsp->pdu.datasize;

	req_cmnd_release(fake_req);

out:
	TRACE_EXIT_RES(res);
	return res;

out_err_free_req:
	req_cmnd_release(fake_req);
	goto out_set_res;

out_err_unlock:
	mutex_unlock(&sess->target->target_mutex);

out_set_res:
	res = SCST_AEN_RES_FAILED;
	goto out;
}

static int iscsi_cpu_mask_changed_aen(struct scst_aen *aen)
{
	int res = SCST_AEN_RES_SUCCESS;
	struct scst_session *scst_sess = scst_aen_get_sess(aen);
	struct iscsi_session *sess = scst_sess_get_tgt_priv(scst_sess);

	TRACE_ENTRY();

	TRACE_MGMT_DBG("CPU mask changed AEN to sess %p (initiator %s)", sess,
		sess->initiator_name);

	mutex_lock(&sess->target->target_mutex);
	iscsi_sess_force_close(sess);
	mutex_unlock(&sess->target->target_mutex);

	scst_aen_done(aen);

	TRACE_EXIT_RES(res);
	return res;
}

static int iscsi_report_aen(struct scst_aen *aen)
{
	int res;
	int event_fn = scst_aen_get_event_fn(aen);

	TRACE_ENTRY();

	switch (event_fn) {
	case SCST_AEN_SCSI:
		res = iscsi_scsi_aen(aen);
		break;
	case SCST_AEN_CPU_MASK_CHANGED:
		res = iscsi_cpu_mask_changed_aen(aen);
		break;
	default:
		TRACE_MGMT_DBG("Unsupported AEN %d", event_fn);
		res = SCST_AEN_RES_NOT_SUPPORTED;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int iscsi_get_initiator_port_transport_id(struct scst_tgt *tgt,
	struct scst_session *scst_sess, uint8_t **transport_id)
{
	struct iscsi_session *sess;
	int res = 0;
	union iscsi_sid sid;
	int tr_id_size;
	uint8_t *tr_id;
	uint8_t q;

	TRACE_ENTRY();

	if (scst_sess == NULL) {
		res = SCSI_TRANSPORTID_PROTOCOLID_ISCSI;
		goto out;
	}

	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);

	sid = *(union iscsi_sid *)&sess->sid;
	sid.id.tsih = 0;

	tr_id_size = 4 + strlen(sess->initiator_name) + 5 +
		snprintf(&q, sizeof(q), "%llx", sid.id64) + 1;
	tr_id_size = (tr_id_size + 3) & -4;

	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (tr_id == NULL) {
		PRINT_ERROR("Allocation of TransportID (size %d) failed",
			tr_id_size);
		res = -ENOMEM;
		goto out;
	}

	tr_id[0] = 0x40 | SCSI_TRANSPORTID_PROTOCOLID_ISCSI;
	sprintf(&tr_id[4], "%s,i,0x%llx", sess->initiator_name, sid.id64);

	put_unaligned_be16(tr_id_size - 4, &tr_id[2]);

	*transport_id = tr_id;

	TRACE_DBG("Created tid '%s'", &tr_id[4]);

out:
	TRACE_EXIT_RES(res);
	return res;
}

void iscsi_send_nop_in(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *req, *rsp;
	struct iscsi_nop_in_hdr *rsp_hdr;

	TRACE_ENTRY();

	req = cmnd_alloc(conn, NULL);
	if (req == NULL) {
		PRINT_ERROR("%s", "Unable to alloc fake Nop-In request");
		goto out_err;
	}

	rsp = iscsi_alloc_main_rsp(req);
	if (rsp == NULL) {
		PRINT_ERROR("%s", "Unable to alloc Nop-In rsp");
		goto out_err_free_req;
	}

	cmnd_get(rsp);

	rsp_hdr = (struct iscsi_nop_in_hdr *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_NOP_IN;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->itt = ISCSI_RESERVED_TAG;
	rsp_hdr->ttt = (__force __be32)conn->nop_in_ttt++;

	if (conn->nop_in_ttt == ISCSI_RESERVED_TAG_CPU32)
		conn->nop_in_ttt = 0;

	/* Supposed that all other fields are zeroed */

	TRACE_DBG("Sending Nop-In request (ttt 0x%08x)", rsp_hdr->ttt);
	spin_lock_bh(&conn->nop_req_list_lock);
	list_add_tail(&rsp->nop_req_list_entry, &conn->nop_req_list);
	spin_unlock_bh(&conn->nop_req_list_lock);

	/*
	 * Start NopRsp timer now to catch case where send buffer is full due
	 * to connection being down, so this is never even sent to tcp layer.
	 * This prevent us from having to wait for the CmdRsp timer which
	 * is normally much longer.
	 */
	req_add_to_write_timeout_list(req);

out_err_free_req:
	req_cmnd_release(req);

out_err:
	TRACE_EXIT();
	return;
}

#ifndef CONFIG_SCST_PROC
static int iscsi_close_sess(struct scst_session *scst_sess)
{
	struct iscsi_session *sess = scst_sess_get_tgt_priv(scst_sess);
	struct iscsi_target *target = sess->target;
	int res;

	res = mutex_lock_interruptible(&target->target_mutex);
	if (res)
		goto out;
	iscsi_sess_force_close(sess);
	mutex_unlock(&target->target_mutex);

	res = 0;

out:
	return res;
}
#endif

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

#if !defined(CONFIG_SCST_PROC) && \
	(defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING))
static struct scst_trace_log iscsi_local_trace_tbl[] = {
	{ TRACE_D_WRITE,		"d_write" },
	{ TRACE_CONN_OC,		"conn" },
	{ TRACE_CONN_OC_DBG,	"conn_dbg" },
	{ TRACE_D_IOV,		"iov" },
	{ TRACE_D_DUMP_PDU,		"pdu" },
	{ TRACE_NET_PG,		"net_page" },
	{ 0,			NULL }
};

#define ISCSI_TRACE_TBL_HELP	", d_write, conn, conn_dbg, iov, pdu, net_page"
#endif

static uint16_t iscsi_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	return 0x0960; /* iSCSI */
}

struct scst_tgt_template iscsi_template = {
	.name = "iscsi",
	.sg_tablesize = 0xFFFF /* no limit */,
	.threads_num = 0,
	.no_clustering = 1,
	.xmit_response_atomic = 0,
#ifndef CONFIG_SCST_PROC
	.tgtt_attrs = iscsi_attrs,
	.tgt_attrs = iscsi_tgt_attrs,
	.sess_attrs = iscsi_sess_attrs,
	.enable_target = iscsi_enable_target,
	.is_target_enabled = iscsi_is_target_enabled,
	.add_target = iscsi_sysfs_add_target,
	.del_target = iscsi_sysfs_del_target,
	.mgmt_cmd = iscsi_sysfs_mgmt_cmd,
	.close_session = iscsi_close_sess,
	.tgtt_optional_attributes = "IncomingUser, OutgoingUser",
	.tgt_optional_attributes = "IncomingUser, OutgoingUser, allowed_portal",
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags = ISCSI_DEFAULT_LOG_FLAGS,
	.trace_flags = &trace_flag,
#if !defined(CONFIG_SCST_PROC) && \
	(defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING))
	.trace_tbl = iscsi_local_trace_tbl,
	.trace_tbl_help = ISCSI_TRACE_TBL_HELP,
#endif
#endif
	.detect = iscsi_target_detect,
	.release = iscsi_target_release,
	.xmit_response = iscsi_xmit_response,
#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	.tgt_alloc_data_buf = iscsi_alloc_data_buf,
#endif
	.preprocessing_done = iscsi_preprocessing_done,
	.pre_exec = iscsi_pre_exec,
	.task_mgmt_affected_cmds_done = iscsi_task_mgmt_affected_cmds_done,
	.task_mgmt_fn_done = iscsi_task_mgmt_fn_done,
	.on_abort_cmd = iscsi_on_abort_cmd,
	.report_aen = iscsi_report_aen,
	.get_initiator_port_transport_id = iscsi_get_initiator_port_transport_id,
	.get_scsi_transport_version = iscsi_get_scsi_transport_version,
};

static void __iscsi_threads_pool_put(struct iscsi_thread_pool *p)
{
	struct iscsi_thread *t, *tt;

	TRACE_ENTRY();

	p->thread_pool_ref--;
	if (p->thread_pool_ref > 0) {
		TRACE_DBG("iSCSI thread pool %p still has %d references)",
			p, p->thread_pool_ref);
		goto out;
	}

	TRACE_DBG("Freeing iSCSI thread pool %p", p);

	list_for_each_entry_safe(t, tt, &p->threads_list, threads_list_entry) {
		kthread_stop(t->thr);
		list_del(&t->threads_list_entry);
		kfree(t);
	}

	list_del(&p->thread_pools_list_entry);

	kmem_cache_free(iscsi_thread_pool_cache, p);

out:
	TRACE_EXIT();
	return;
}

void iscsi_threads_pool_put(struct iscsi_thread_pool *p)
{
	TRACE_ENTRY();

	mutex_lock(&iscsi_threads_pool_mutex);
	__iscsi_threads_pool_put(p);
	mutex_unlock(&iscsi_threads_pool_mutex);

	TRACE_EXIT();
	return;
}

int iscsi_threads_pool_get(const cpumask_t *cpu_mask,
	struct iscsi_thread_pool **out_pool)
{
	int res;
	struct iscsi_thread_pool *p;
	struct iscsi_thread *t;
	int i, j, count;

	TRACE_ENTRY();

	mutex_lock(&iscsi_threads_pool_mutex);

	list_for_each_entry(p, &iscsi_thread_pools_list,
			thread_pools_list_entry) {
		if ((cpu_mask == NULL) ||
		    __cpus_equal(cpu_mask, &p->cpu_mask, nr_cpumask_bits)) {
			p->thread_pool_ref++;
			TRACE_DBG("iSCSI thread pool %p found (new ref %d)",
				p, p->thread_pool_ref);
			res = 0;
			goto out_unlock;
		}
	}

	TRACE_DBG("%s", "Creating new iSCSI thread pool");

	p = kmem_cache_zalloc(iscsi_thread_pool_cache, GFP_KERNEL);
	if (p == NULL) {
		PRINT_ERROR("Unable to allocate iSCSI thread pool (size %zd)",
			sizeof(*p));
		res = -ENOMEM;
		if (!list_empty(&iscsi_thread_pools_list)) {
			PRINT_WARNING("%s", "Using global iSCSI thread pool "
				"instead");
			p = list_first_entry(&iscsi_thread_pools_list,
				struct iscsi_thread_pool,
				thread_pools_list_entry);
		} else
			res = -ENOMEM;
		goto out_unlock;
	}

	spin_lock_init(&p->rd_lock);
	INIT_LIST_HEAD(&p->rd_list);
	init_waitqueue_head(&p->rd_waitQ);
	spin_lock_init(&p->wr_lock);
	INIT_LIST_HEAD(&p->wr_list);
	init_waitqueue_head(&p->wr_waitQ);
	if (cpu_mask == NULL)
		cpus_setall(p->cpu_mask);
	else {
		cpus_clear(p->cpu_mask);
		for_each_cpu(i, cpu_mask)
			cpu_set(i, p->cpu_mask);
	}
	p->thread_pool_ref = 1;
	INIT_LIST_HEAD(&p->threads_list);

	if (cpu_mask == NULL)
		count = max_t(int, num_online_cpus(), 2);
	else {
		count = 0;
		for_each_cpu(i, cpu_mask)
			count++;
	}

	list_add_tail(&p->thread_pools_list_entry, &iscsi_thread_pools_list);

	for (j = 0; j < 2; j++) {
		int (*fn)(void *);
		char name[25];
		static int major;

		if (j == 0)
			fn = istrd;
		else
			fn = istwr;

		for (i = 0; i < count; i++) {
			if (j == 0) {
				major++;
				if (cpu_mask == NULL)
					snprintf(name, sizeof(name), "iscsird%d", i);
				else
					snprintf(name, sizeof(name), "iscsird%d_%d",
						major, i);
			} else {
				if (cpu_mask == NULL)
					snprintf(name, sizeof(name), "iscsiwr%d", i);
				else
					snprintf(name, sizeof(name), "iscsiwr%d_%d",
						major, i);
			}

			t = kmalloc(sizeof(*t), GFP_KERNEL);
			if (t == NULL) {
				res = -ENOMEM;
				PRINT_ERROR("Failed to allocate thread %s "
					"(size %zd)", name, sizeof(*t));
				goto out_free;
			}

			t->thr = kthread_run(fn, p, name);
			if (IS_ERR(t->thr)) {
				res = PTR_ERR(t->thr);
				PRINT_ERROR("kthread_run() for thread %s failed: %d",
					name, res);
				kfree(t);
				goto out_free;
			}
			list_add_tail(&t->threads_list_entry, &p->threads_list);
		}
	}

	res = 0;

	TRACE_DBG("Created iSCSI thread pool %p", p);

out_unlock:
	mutex_unlock(&iscsi_threads_pool_mutex);

	*out_pool = p;

	TRACE_EXIT_RES(res);
	return res;

out_free:
	__iscsi_threads_pool_put(p);
	p = NULL;
	goto out_unlock;
}

static int __init iscsi_init(void)
{
	int err = 0;

	PRINT_INFO("iSCSI SCST Target - version %s", ISCSI_VERSION_STRING);

	dummy_page = alloc_pages(GFP_KERNEL, 0);
	if (dummy_page == NULL) {
		PRINT_ERROR("%s", "Dummy page allocation failed");
		goto out;
	}

	sg_init_table(&dummy_sg, 1);
	sg_set_page(&dummy_sg, dummy_page, PAGE_SIZE, 0);

	iscsi_cmnd_abort_mempool = mempool_create_kmalloc_pool(2500,
		sizeof(struct iscsi_cmnd_abort_params));
	if (iscsi_cmnd_abort_mempool == NULL) {
		err = -ENOMEM;
		goto out_free_dummy;
	}

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	err = net_set_get_put_page_callbacks(iscsi_get_page_callback,
			iscsi_put_page_callback);
	if (err != 0) {
		PRINT_INFO("Unable to set page callbacks: %d", err);
		goto out_destroy_mempool;
	}
#else
#ifndef GENERATING_UPSTREAM_PATCH
	PRINT_WARNING("%s",
		"CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION "
		"not enabled in your kernel. ISCSI-SCST will be working with "
		"not the best performance. Refer README file for details.");
#endif
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

	iscsi_cmnd_cache = KMEM_CACHE(iscsi_cmnd, SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (!iscsi_cmnd_cache) {
		err = -ENOMEM;
		goto out_event;
	}

	iscsi_thread_pool_cache = KMEM_CACHE(iscsi_thread_pool,
					SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (!iscsi_thread_pool_cache) {
		err = -ENOMEM;
		goto out_kmem_cmd;
	}

	iscsi_conn_cache = KMEM_CACHE(iscsi_conn, SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (!iscsi_conn_cache) {
		err = -ENOMEM;
		goto out_kmem_tp;
	}

	iscsi_sess_cache = KMEM_CACHE(iscsi_session,
				SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (!iscsi_sess_cache) {
		err = -ENOMEM;
		goto out_kmem_conn;
	}

	err = scst_register_target_template(&iscsi_template);
	if (err < 0)
		goto out_kmem;

#ifdef CONFIG_SCST_PROC
	err = iscsi_procfs_init();
	if (err < 0)
		goto out_reg_tmpl;
#else
	iscsi_conn_ktype.sysfs_ops = scst_sysfs_get_sysfs_ops();
#endif

	err = iscsi_threads_pool_get(NULL, &iscsi_main_thread_pool);
	if (err != 0)
		goto out_thr;

out:
	return err;

out_thr:
#ifdef CONFIG_SCST_PROC
	iscsi_procfs_exit();
#endif

#ifdef CONFIG_SCST_PROC
out_reg_tmpl:
#endif
	scst_unregister_target_template(&iscsi_template);

out_kmem:
	kmem_cache_destroy(iscsi_sess_cache);

out_kmem_conn:
	kmem_cache_destroy(iscsi_conn_cache);

out_kmem_tp:
	kmem_cache_destroy(iscsi_thread_pool_cache);

out_kmem_cmd:
	kmem_cache_destroy(iscsi_cmnd_cache);

out_event:
	event_exit();

out_reg:
	unregister_chrdev(ctr_major, ctr_name);

out_callb:
#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	net_set_get_put_page_callbacks(NULL, NULL);

out_destroy_mempool:
#endif
	mempool_destroy(iscsi_cmnd_abort_mempool);

out_free_dummy:
	__free_pages(dummy_page, 0);
	goto out;
}

static void __exit iscsi_exit(void)
{
	iscsi_threads_pool_put(iscsi_main_thread_pool);

	sBUG_ON(!list_empty(&iscsi_thread_pools_list));

	unregister_chrdev(ctr_major, ctr_name);

#ifdef CONFIG_SCST_PROC
	iscsi_procfs_exit();
#endif
	event_exit();

	kmem_cache_destroy(iscsi_sess_cache);
	kmem_cache_destroy(iscsi_conn_cache);
	kmem_cache_destroy(iscsi_thread_pool_cache);
	kmem_cache_destroy(iscsi_cmnd_cache);

	scst_unregister_target_template(&iscsi_template);

#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	net_set_get_put_page_callbacks(NULL, NULL);
#endif

	mempool_destroy(iscsi_cmnd_abort_mempool);

	__free_pages(dummy_page, 0);
	return;
}

module_init(iscsi_init);
module_exit(iscsi_exit);

MODULE_VERSION(ISCSI_VERSION_STRING);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCST iSCSI Target");
