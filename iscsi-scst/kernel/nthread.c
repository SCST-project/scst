/*
 *  Network threads.
 *
 *  Copyright (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 Vladislav Bolkhovitin
 *  Copyright (C) 2007 CMS Distribution Limited
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/sched.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <asm/ioctls.h>
#include <linux/delay.h>
#include <net/tcp.h>

#include "iscsi.h"
#include "digest.h"

enum rx_state {
	RX_INIT_BHS, /* Must be zero. */
	RX_BHS,

	RX_INIT_AHS,
	RX_AHS,

	RX_INIT_HDIGEST,
	RX_HDIGEST,
	RX_CHECK_HDIGEST,

	RX_INIT_DATA,
	RX_DATA,

	RX_INIT_DDIGEST,
	RX_DDIGEST,
	RX_CHECK_DDIGEST,

	RX_END,
};

enum tx_state {
	TX_INIT, /* Must be zero. */
	TX_BHS_DATA,
	TX_INIT_DDIGEST,
	TX_DDIGEST,
	TX_END,
};

#if defined(NET_PAGE_CALLBACKS_DEFINED)
static void iscsi_check_closewait(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd;

	TRACE_ENTRY();

	TRACE_CONN_CLOSE_DBG("conn %p, sk_state %d", conn,
		conn->sock->sk->sk_state);

	if (conn->sock->sk->sk_state != TCP_CLOSE) {
		TRACE_CONN_CLOSE_DBG("conn %p, skipping", conn);
		goto out;
	}

	/*
	 * No data are going to be sent, so all queued buffers can be freed
	 * now. In many cases TCP does that only in close(), but we can't rely
	 * on user space on calling it.
	 */

again:
	spin_lock_bh(&conn->cmd_list_lock);
	list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
		struct iscsi_cmnd *rsp;
		int restart = 0;

		TRACE_CONN_CLOSE_DBG("cmd %p, scst_state %x, data_waiting %d, "
			"ref_cnt %d, parent_req %p, net_ref_cnt %d, sg %p",
			cmnd, cmnd->scst_state, cmnd->data_waiting,
			atomic_read(&cmnd->ref_cnt), cmnd->parent_req,
			atomic_read(&cmnd->net_ref_cnt), cmnd->sg);

		sBUG_ON(cmnd->parent_req != NULL);

		if (cmnd->sg != NULL) {
			int i;

			if (cmnd_get_check(cmnd))
				continue;

			for (i = 0; i < cmnd->sg_cnt; i++) {
				struct page *page = sg_page(&cmnd->sg[i]);
				TRACE_CONN_CLOSE_DBG("page %p, net_priv %p, "
					"_count %d", page, page->net_priv,
					atomic_read(&page->_count));

				if (page->net_priv != NULL) {
					if (restart == 0) {
						spin_unlock_bh(&conn->cmd_list_lock);
						restart = 1;
					}
					while (page->net_priv != NULL)
						iscsi_put_page_callback(page);
				}
			}
			cmnd_put(cmnd);

			if (restart)
				goto again;
		}

		spin_lock_bh(&cmnd->rsp_cmd_lock);
		list_for_each_entry(rsp, &cmnd->rsp_cmd_list, rsp_cmd_list_entry) {
			TRACE_CONN_CLOSE_DBG("  rsp %p, ref_cnt %d, net_ref_cnt %d, "
				"sg %p", rsp, atomic_read(&rsp->ref_cnt),
				atomic_read(&rsp->net_ref_cnt), rsp->sg);

			if ((rsp->sg != cmnd->sg) && (rsp->sg != NULL)) {
				int i;

				if (cmnd_get_check(rsp))
					continue;

				for (i = 0; i < rsp->sg_cnt; i++) {
					struct page *page = sg_page(&rsp->sg[i]);
					TRACE_CONN_CLOSE_DBG("    page %p, net_priv %p, "
						"_count %d", page, page->net_priv,
						atomic_read(&page->_count));

					if (page->net_priv != NULL) {
						if (restart == 0) {
							spin_unlock_bh(&cmnd->rsp_cmd_lock);
							spin_unlock_bh(&conn->cmd_list_lock);
							restart = 1;
						}
						while (page->net_priv != NULL)
							iscsi_put_page_callback(page);
					}
				}
				cmnd_put(rsp);

				if (restart)
					goto again;
			}
		}
		spin_unlock_bh(&cmnd->rsp_cmd_lock);
	}
	spin_unlock_bh(&conn->cmd_list_lock);

out:
	TRACE_EXIT();
	return;
}
#else
static inline void iscsi_check_closewait(struct iscsi_conn *conn) {};
#endif

static void iscsi_unreg_cmds_done_fn(struct scst_session *scst_sess)
{
	struct iscsi_session *sess =
		(struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);

	TRACE_ENTRY();

	TRACE_CONN_CLOSE_DBG("sess %p (scst_sess %p)", sess, scst_sess);

	sess->shutting_down = 1;
	complete_all(&sess->unreg_compl);

	TRACE_EXIT();
	return;
}

/* No locks */
static void close_conn(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;
	struct iscsi_target *target = conn->target;
	typeof(jiffies) start_waiting = jiffies;
	typeof(jiffies) shut_start_waiting = start_waiting;
	bool pending_reported = 0, wait_expired = 0, shut_expired = 0;

#define CONN_PENDING_TIMEOUT	((typeof(jiffies))10*HZ)
#define CONN_WAIT_TIMEOUT	((typeof(jiffies))10*HZ)
#define CONN_REG_SHUT_TIMEOUT	((typeof(jiffies))125*HZ)
#define CONN_DEL_SHUT_TIMEOUT	((typeof(jiffies))10*HZ)

	TRACE_ENTRY();

	TRACE_CONN_CLOSE("Closing connection %p (conn_ref_cnt=%d)", conn,
		atomic_read(&conn->conn_ref_cnt));

	iscsi_extracheck_is_rd_thread(conn);

	sBUG_ON(!conn->closing);

	if (conn->active_close) {
		/* We want all our already send operations to complete */
		conn->sock->ops->shutdown(conn->sock, RCV_SHUTDOWN);
	} else {
		conn->sock->ops->shutdown(conn->sock,
			RCV_SHUTDOWN|SEND_SHUTDOWN);
	}

	/*
	 * We need to call scst_unregister_session() ASAP to make SCST start
	 * stuck commands recovery.
	 *
	 * ToDo: this is incompatible with MC/S
	 */
	scst_unregister_session_ex(session->scst_sess, 0,
		NULL, iscsi_unreg_cmds_done_fn);
	session->scst_sess = NULL;

	if (conn->read_state != RX_INIT_BHS) {
		struct iscsi_cmnd *cmnd = conn->read_cmnd;
		conn->read_cmnd = NULL;
		conn->read_state = RX_INIT_BHS;
		req_cmnd_release_force(cmnd, 0);
	}

	conn_abort(conn);

	/* ToDo: not the best way to wait */
	while (atomic_read(&conn->conn_ref_cnt) != 0) {
		struct iscsi_cmnd *cmnd;

		mutex_lock(&target->target_mutex);
		spin_lock(&session->sn_lock);
		if ((session->tm_rsp != NULL) && (session->tm_rsp->conn == conn)) {
			struct iscsi_cmnd *tm_rsp = session->tm_rsp;
			TRACE(TRACE_MGMT_MINOR, "Dropping delayed TM rsp %p",
				tm_rsp);
			session->tm_rsp = NULL;
			session->tm_active--;
			WARN_ON(session->tm_active < 0);
			spin_unlock(&session->sn_lock);
			mutex_unlock(&target->target_mutex);

			rsp_cmnd_release(tm_rsp);
		} else {
			spin_unlock(&session->sn_lock);
			mutex_unlock(&target->target_mutex);
		}

		if (!list_empty(&session->pending_list)) {
			struct list_head *pending_list = &session->pending_list;
			int req_freed;

			TRACE_CONN_CLOSE_DBG("Disposing pending commands on "
					     "connection %p (conn_ref_cnt=%d)", conn,
					     atomic_read(&conn->conn_ref_cnt));

			/*
			 * Such complicated approach currently isn't necessary,
			 * but it will be necessary for MC/S, if we won't want
			 * to reestablish the whole session on a connection
			 * failure.
			 */

			spin_lock(&session->sn_lock);
			do {
				req_freed = 0;
				list_for_each_entry(cmnd, pending_list,
							pending_list_entry) {
					TRACE_CONN_CLOSE_DBG("Pending cmd %p"
						"(conn %p, cmd_sn %u, exp_cmd_sn %u)",
						cmnd, conn, cmnd->pdu.bhs.sn,
						session->exp_cmd_sn);
					if ((cmnd->conn == conn) &&
					    (session->exp_cmd_sn == cmnd->pdu.bhs.sn)) {
						TRACE_CONN_CLOSE_DBG("Freeing pending cmd %p",
							cmnd);

						list_del(&cmnd->pending_list_entry);
						cmnd->pending = 0;

						session->exp_cmd_sn++;

						spin_unlock(&session->sn_lock);

						req_cmnd_release_force(cmnd, 0);

						req_freed = 1;
						spin_lock(&session->sn_lock);
						break;
					}
				}
			} while (req_freed);
			spin_unlock(&session->sn_lock);

			if (time_after(jiffies, start_waiting + CONN_PENDING_TIMEOUT)) {
				if (!pending_reported) {
					TRACE_CONN_CLOSE("%s", "Pending wait time expired");
					pending_reported = 1;
				}
				spin_lock(&session->sn_lock);
				do {
					req_freed = 0;
					list_for_each_entry(cmnd, pending_list,
							pending_list_entry) {
						TRACE_CONN_CLOSE_DBG("Pending cmd %p"
							"(conn %p, cmd_sn %u, exp_cmd_sn %u)",
							cmnd, conn, cmnd->pdu.bhs.sn,
							session->exp_cmd_sn);
						if (cmnd->conn == conn) {
							PRINT_ERROR("Freeing orphaned "
								"pending cmd %p", cmnd);

							list_del(&cmnd->pending_list_entry);
							cmnd->pending = 0;

							if (session->exp_cmd_sn == cmnd->pdu.bhs.sn)
								session->exp_cmd_sn++;

							spin_unlock(&session->sn_lock);

							req_cmnd_release_force(cmnd, 0);

							req_freed = 1;
							spin_lock(&session->sn_lock);
							break;
						}
					}
				} while (req_freed);
				spin_unlock(&session->sn_lock);
			}
		}

		iscsi_make_conn_wr_active(conn);

		/* That's for active close only, actually */
		if (time_after(jiffies, start_waiting + CONN_WAIT_TIMEOUT) &&
		    !wait_expired) {
			TRACE_CONN_CLOSE("Wait time expired (conn %p, "
				"sk_state %d)", conn, conn->sock->sk->sk_state);
			conn->sock->ops->shutdown(conn->sock, SEND_SHUTDOWN);
			wait_expired = 1;
			shut_start_waiting = jiffies;
		}

		if (wait_expired && !shut_expired &&
		    time_after(jiffies, shut_start_waiting +
				conn->deleting ? CONN_DEL_SHUT_TIMEOUT :
						 CONN_REG_SHUT_TIMEOUT)) {
			TRACE_CONN_CLOSE("Wait time after shutdown expired "
				"(conn %p, sk_state %d)", conn,
				conn->sock->sk->sk_state);
			conn->sock->sk->sk_prot->disconnect(conn->sock->sk, 0);
			shut_expired = 1;
		}

		if (conn->deleting)
			msleep(200);
		else
			msleep(1000);

		TRACE_CONN_CLOSE_DBG("conn %p, conn_ref_cnt %d left, wr_state %d, "
			"exp_cmd_sn %u", conn, atomic_read(&conn->conn_ref_cnt),
			conn->wr_state, session->exp_cmd_sn);
#ifdef DEBUG
		{
#ifdef NET_PAGE_CALLBACKS_DEFINED
			struct iscsi_cmnd *rsp;
#endif

#if 0
			if (time_after(jiffies, start_waiting + 10*HZ))
				trace_flag |= TRACE_CONN_OC_DBG;
#endif

			spin_lock_bh(&conn->cmd_list_lock);
			list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
				TRACE_CONN_CLOSE_DBG("cmd %p, scst_state %x, scst_cmd "
					"state %d, data_waiting %d, ref_cnt %d, sn %u, "
					"parent_req %p, pending %d", cmnd, cmnd->scst_state,
					(cmnd->scst_cmd != NULL) ? cmnd->scst_cmd->state : -1,
					cmnd->data_waiting, atomic_read(&cmnd->ref_cnt),
					cmnd->pdu.bhs.sn, cmnd->parent_req, cmnd->pending);
#ifdef NET_PAGE_CALLBACKS_DEFINED
				TRACE_CONN_CLOSE_DBG("net_ref_cnt %d, sg %p",
					atomic_read(&cmnd->net_ref_cnt), cmnd->sg);
				if (cmnd->sg != NULL) {
					int i;
					for (i = 0; i < cmnd->sg_cnt; i++) {
						struct page *page = sg_page(&cmnd->sg[i]);
						TRACE_CONN_CLOSE_DBG("page %p, net_priv %p, _count %d",
							page, page->net_priv,
							atomic_read(&page->_count));
					}
				}

				sBUG_ON(cmnd->parent_req != NULL);

				spin_lock_bh(&cmnd->rsp_cmd_lock);
				list_for_each_entry(rsp, &cmnd->rsp_cmd_list, rsp_cmd_list_entry) {
					TRACE_CONN_CLOSE_DBG("  rsp %p, ref_cnt %d, net_ref_cnt %d, "
						"sg %p", rsp, atomic_read(&rsp->ref_cnt),
						atomic_read(&rsp->net_ref_cnt), rsp->sg);
					if ((rsp->sg != cmnd->sg) && (rsp->sg != NULL)) {
						int i;
						for (i = 0; i < rsp->sg_cnt; i++) {
							TRACE_CONN_CLOSE_DBG("    page %p, net_priv %p, "
								"_count %d", sg_page(&rsp->sg[i]),
								sg_page(&rsp->sg[i])->net_priv,
								atomic_read(&sg_page(&rsp->sg[i])->_count));
						}
					}
				}
				spin_unlock_bh(&cmnd->rsp_cmd_lock);
#endif
			}
			spin_unlock_bh(&conn->cmd_list_lock);
		}
#endif
		iscsi_check_closewait(conn);
	}

	write_lock_bh(&conn->sock->sk->sk_callback_lock);
	conn->sock->sk->sk_state_change = conn->old_state_change;
	conn->sock->sk->sk_data_ready = conn->old_data_ready;
	conn->sock->sk->sk_write_space = conn->old_write_space;
	write_unlock_bh(&conn->sock->sk->sk_callback_lock);

	while (1) {
		bool t;

		spin_lock_bh(&iscsi_wr_lock);
		t = (conn->wr_state == ISCSI_CONN_WR_STATE_IDLE);
		spin_unlock_bh(&iscsi_wr_lock);

		if (t && (atomic_read(&conn->conn_ref_cnt) == 0))
			break;

		TRACE_CONN_CLOSE_DBG("Waiting for wr thread (conn %p), "
			"wr_state %x", conn, conn->wr_state);
		msleep(50);
	}

	TRACE_CONN_CLOSE("Notifying user space about closing connection %p", conn);
	event_send(target->tid, session->sid, conn->cid, E_CONN_CLOSE, 0);

	wait_for_completion(&session->unreg_compl);

	sBUG_ON(!session->shutting_down);

	mutex_lock(&target->target_mutex);
	conn_free(conn);
	/* ToDo: this is incompatible with MC/S */
	session_free(session);
	mutex_unlock(&target->target_mutex);

	TRACE_EXIT();
	return;
}

static int close_conn_thr(void *arg)
{
	struct iscsi_conn *conn = (struct iscsi_conn *)arg;

	TRACE_ENTRY();

#ifdef EXTRACHECKS
	conn->rd_task = current;
#endif
	close_conn(conn);

	TRACE_EXIT();
	return 0;
}

/* No locks */
static void start_close_conn(struct iscsi_conn *conn)
{
	struct task_struct *t;

	TRACE_ENTRY();

	t = kthread_run(close_conn_thr, conn, "iscsi_conn_cleanup");
	if (IS_ERR(t)) {
		PRINT_ERROR("kthread_run() failed (%ld), closing conn %p "
			"directly", PTR_ERR(t), conn);
		close_conn(conn);
	}

	TRACE_EXIT();
	return;
}

static inline void iscsi_conn_init_read(struct iscsi_conn *conn, void *data, size_t len)
{
	len = (len + 3) & -4; // XXX ???
	conn->read_iov[0].iov_base = data;
	conn->read_iov[0].iov_len = len;
	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_msg.msg_iovlen = 1;
	conn->read_size = (len + 3) & -4;
}

static void iscsi_conn_read_ahs(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	/* ToDo: __GFP_NOFAIL ?? */
	cmnd->pdu.ahs = kmalloc(cmnd->pdu.ahssize, __GFP_NOFAIL|GFP_KERNEL);
	sBUG_ON(cmnd->pdu.ahs == NULL);
	iscsi_conn_init_read(conn, cmnd->pdu.ahs, cmnd->pdu.ahssize);
}

static struct iscsi_cmnd *iscsi_get_send_cmnd(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd = NULL;

	spin_lock_bh(&conn->write_list_lock);
	if (!list_empty(&conn->write_list)) {
		cmnd = list_entry(conn->write_list.next, struct iscsi_cmnd,
				write_list_entry);
		cmd_del_from_write_list(cmnd);
		cmnd->write_processing_started = 1;
	}
	spin_unlock_bh(&conn->write_list_lock);

	return cmnd;
}

static int do_recv(struct iscsi_conn *conn, int state)
{
	mm_segment_t oldfs;
	struct msghdr msg;
	int res, first_len;

	sBUG_ON(conn->read_cmnd == NULL);

	if (unlikely(conn->closing)) {
		res = -EIO;
		goto out;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = conn->read_msg.msg_iov;
	msg.msg_iovlen = conn->read_msg.msg_iovlen;
	first_len = msg.msg_iov->iov_len;

	oldfs = get_fs();
	set_fs(get_ds());
	res = sock_recvmsg(conn->sock, &msg, conn->read_size, MSG_DONTWAIT | MSG_NOSIGNAL);
	set_fs(oldfs);

	if (res <= 0) {
		switch (res) {
		case -EAGAIN:
		case -ERESTARTSYS:
			TRACE_DBG("EAGAIN or ERESTARTSYS (%d) received for "
				"conn %p", res, conn);
			break;
		default:
			PRINT_ERROR("sock_recvmsg() failed: %d", res);
			mark_conn_closed(conn);
			break;
		}
	} else {
		/*
		 * To save some considerable effort and CPU power we suppose
		 * that TCP functions adjust conn->read_msg.msg_iov and
		 * conn->read_msg.msg_iovlen on amount of copied data. This
		 * BUG_ON is intended to catch if it is changed in the future.
		 */
		sBUG_ON((res >= first_len) &&
			(conn->read_msg.msg_iov->iov_len != 0));
		conn->read_size -= res;
		if (conn->read_size) {
			if (res >= first_len) {
				int done = 1 + ((res - first_len) >> PAGE_SHIFT);
				conn->read_msg.msg_iov += done;
				conn->read_msg.msg_iovlen -= done;
			}
		} else
			conn->read_state = state;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int rx_hdigest(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd = conn->read_cmnd;
	int res = digest_rx_header(cmnd);

	if (unlikely(res != 0)) {
		PRINT_ERROR("rx header digest for initiator %s failed "
			"(%d)", conn->session->initiator_name, res);
		mark_conn_closed(conn);
	}
	return res;
}

static struct iscsi_cmnd *create_cmnd(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd;

	cmnd = cmnd_alloc(conn, NULL);
	iscsi_conn_init_read(cmnd->conn, &cmnd->pdu.bhs, sizeof(cmnd->pdu.bhs));
	conn->read_state = RX_BHS;

	return cmnd;
}

/* Returns >0 for success, <=0 for error or successful finish */
static int recv(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd = conn->read_cmnd;
	int hdigest, ddigest, res = 1, rc;

	TRACE_ENTRY();

	hdigest = conn->hdigest_type & DIGEST_NONE ? 0 : 1;
	ddigest = conn->ddigest_type & DIGEST_NONE ? 0 : 1;

	switch (conn->read_state) {
	case RX_INIT_BHS:
		sBUG_ON(cmnd != NULL);
		cmnd = conn->read_cmnd = create_cmnd(conn);
	case RX_BHS:
		res = do_recv(conn, RX_INIT_AHS);
		if (res <= 0 || conn->read_state != RX_INIT_AHS)
			break;
	case RX_INIT_AHS:
		iscsi_cmnd_get_length(&cmnd->pdu);
		if (cmnd->pdu.ahssize) {
			iscsi_conn_read_ahs(conn, cmnd);
			conn->read_state = RX_AHS;
		} else
			conn->read_state = hdigest ? RX_INIT_HDIGEST : RX_INIT_DATA;

		if (conn->read_state != RX_AHS)
			break;
	case RX_AHS:
		res = do_recv(conn, hdigest ? RX_INIT_HDIGEST : RX_INIT_DATA);
		if (res <= 0 || conn->read_state != RX_INIT_HDIGEST)
			break;
	case RX_INIT_HDIGEST:
		iscsi_conn_init_read(conn, &cmnd->hdigest, sizeof(u32));
		conn->read_state = RX_HDIGEST;
	case RX_HDIGEST:
		res = do_recv(conn, RX_CHECK_HDIGEST);
		if (res <= 0 || conn->read_state != RX_CHECK_HDIGEST)
			break;
	case RX_CHECK_HDIGEST:
		rc = rx_hdigest(conn);
		if (likely(rc == 0))
			conn->read_state = RX_INIT_DATA;
		else {
			res = rc;
			break;
		}
	case RX_INIT_DATA:
		rc = cmnd_rx_start(cmnd);
		if (unlikely(rc != 0)) {
			sBUG_ON(!conn->closing);
			conn->read_state = RX_END;
			res = rc;
			/* cmnd will be freed in close_conn() */
			goto out;
		}
		conn->read_state = cmnd->pdu.datasize ? RX_DATA : RX_END;
		if (conn->read_state != RX_DATA)
			break;
	case RX_DATA:
		res = do_recv(conn, ddigest ? RX_INIT_DDIGEST : RX_END);
		if (res <= 0 || conn->read_state != RX_INIT_DDIGEST)
			break;
	case RX_INIT_DDIGEST:
		iscsi_conn_init_read(conn, &cmnd->ddigest, sizeof(u32));
		conn->read_state = RX_DDIGEST;
	case RX_DDIGEST:
		res = do_recv(conn, RX_CHECK_DDIGEST);
		if (res <= 0 || conn->read_state != RX_CHECK_DDIGEST)
			break;
	case RX_CHECK_DDIGEST:
		conn->read_state = RX_END;
		if (cmnd->pdu.datasize <= 256*1024) {
			/* It's cache hot, so let's compute it inline */
			TRACE_DBG("cmnd %p, opcode %x: checking RX "
				"ddigest inline", cmnd, cmnd_opcode(cmnd));
			cmnd->ddigest_checked = 1;
			rc = digest_rx_data(cmnd);
			if (unlikely(rc != 0)) {
				mark_conn_closed(conn);
				goto out;
			}
		} else if (cmnd_opcode(cmnd) == ISCSI_OP_SCSI_CMD) {
			cmd_add_on_rx_ddigest_list(cmnd, cmnd);
			cmnd_get(cmnd);
		} else if (cmnd_opcode(cmnd) != ISCSI_OP_SCSI_DATA_OUT) {
			/*
			 * We could get here only for NOP-Out. ISCSI RFC doesn't
			 * specify how to deal with digest errors in this case.
			 * Is closing connection correct?
			 */
			TRACE_DBG("cmnd %p, opcode %x: checking NOP RX "
				"ddigest", cmnd, cmnd_opcode(cmnd));
			rc = digest_rx_data(cmnd);
			if (unlikely(rc != 0)) {
				mark_conn_closed(conn);
				goto out;
			}
		}
		break;
	default:
		PRINT_CRIT_ERROR("%d %x", conn->read_state, cmnd_opcode(cmnd));
		sBUG();
	}

	if (res <= 0)
		goto out;

	if (conn->read_state != RX_END)
		goto out;

	if (unlikely(conn->read_size)) {
		PRINT_CRIT_ERROR("%d %x %d", res, cmnd_opcode(cmnd),
			conn->read_size);
		sBUG();
	}

	conn->read_cmnd = NULL;
	conn->read_state = RX_INIT_BHS;

	cmnd_rx_end(cmnd);

	sBUG_ON(conn->read_size != 0);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* No locks, conn is rd processing */
static int process_read_io(struct iscsi_conn *conn, int *closed)
{
	int res;

	do {
		res = recv(conn);
		if (unlikely(conn->closing)) {
			start_close_conn(conn);
			*closed = 1;
			break;
		}
	} while (res > 0);

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Called under iscsi_rd_lock and BHs disabled, but will drop it inside,
 * then reaquire.
 */
static void scst_do_job_rd(void)
{
	TRACE_ENTRY();

	/* We delete/add to tail connections to maintain fairness between them */

	while (!list_empty(&iscsi_rd_list)) {
		int rc, closed = 0;
		struct iscsi_conn *conn = list_entry(iscsi_rd_list.next,
			typeof(*conn), rd_list_entry);

		list_del(&conn->rd_list_entry);

		sBUG_ON(conn->rd_state == ISCSI_CONN_RD_STATE_PROCESSING);
		conn->rd_data_ready = 0;
		conn->rd_state = ISCSI_CONN_RD_STATE_PROCESSING;
#ifdef EXTRACHECKS
		conn->rd_task = current;
#endif
		spin_unlock_bh(&iscsi_rd_lock);

		rc = process_read_io(conn, &closed);

		spin_lock_bh(&iscsi_rd_lock);

		if (closed)
			continue;

#ifdef EXTRACHECKS
		conn->rd_task = NULL;
#endif
		if ((rc == 0) || conn->rd_data_ready) {
			list_add_tail(&conn->rd_list_entry, &iscsi_rd_list);
			conn->rd_state = ISCSI_CONN_RD_STATE_IN_LIST;
		} else
			conn->rd_state = ISCSI_CONN_RD_STATE_IDLE;
	}

	TRACE_EXIT();
	return;
}

static inline int test_rd_list(void)
{
	int res = !list_empty(&iscsi_rd_list) ||
		  unlikely(kthread_should_stop());
	return res;
}

int istrd(void *arg)
{
	TRACE_ENTRY();

	PRINT_INFO("Read thread started, PID %d", current->pid);

	current->flags |= PF_NOFREEZE;

	spin_lock_bh(&iscsi_rd_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_rd_list()) {
			add_wait_queue_exclusive(&iscsi_rd_waitQ, &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_rd_list())
					break;
				spin_unlock_bh(&iscsi_rd_lock);
				schedule();
				spin_lock_bh(&iscsi_rd_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&iscsi_rd_waitQ, &wait);
		}
		scst_do_job_rd();
	}
	spin_unlock_bh(&iscsi_rd_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so iscsi_rd_list must be empty.
	 */
	sBUG_ON(!list_empty(&iscsi_rd_list));

	PRINT_INFO("Read thread PID %d finished", current->pid);

	TRACE_EXIT();
	return 0;
}

#ifdef NET_PAGE_CALLBACKS_DEFINED
static inline void __iscsi_get_page_callback(struct iscsi_cmnd *cmd)
{
	int v;

	TRACE_NET_PAGE("cmd %p, new net_ref_cnt %d",
		cmd, atomic_read(&cmd->net_ref_cnt)+1);

	v = atomic_inc_return(&cmd->net_ref_cnt);
	if (v == 1) {
		TRACE_NET_PAGE("getting cmd %p", cmd);
		cmnd_get(cmd);
	}
}

void iscsi_get_page_callback(struct page *page)
{
	struct iscsi_cmnd *cmd = (struct iscsi_cmnd *)page->net_priv;

	TRACE_NET_PAGE("page %p, _count %d", page,
		atomic_read(&page->_count));

	__iscsi_get_page_callback(cmd);
}

static inline void __iscsi_put_page_callback(struct iscsi_cmnd *cmd)
{
	TRACE_NET_PAGE("cmd %p, new net_ref_cnt %d", cmd,
		atomic_read(&cmd->net_ref_cnt)-1);

	if (atomic_dec_and_test(&cmd->net_ref_cnt)) {
		int i, sg_cnt = cmd->sg_cnt;
		for (i = 0; i < sg_cnt; i++) {
			struct page *page = sg_page(&cmd->sg[i]);
			TRACE_NET_PAGE("Clearing page %p", page);
			if (page->net_priv == cmd)
				page->net_priv = NULL;
		}
		cmnd_put(cmd);
	}
}

void iscsi_put_page_callback(struct page *page)
{
	struct iscsi_cmnd *cmd = (struct iscsi_cmnd *)page->net_priv;

	TRACE_NET_PAGE("page %p, _count %d", page,
		atomic_read(&page->_count));

	__iscsi_put_page_callback(cmd);
}

static void check_net_priv(struct iscsi_cmnd *cmd, struct page *page)
{
	if ((atomic_read(&cmd->net_ref_cnt) == 1) && (page->net_priv == cmd)) {
		TRACE_DBG("sendpage() not called get_page(), zeroing net_priv "
			"%p (page %p)", page->net_priv, page);
		page->net_priv = NULL;
	}
}
#else
static inline void check_net_priv(struct iscsi_cmnd *cmd, struct page *page) {}
static inline void __iscsi_get_page_callback(struct iscsi_cmnd *cmd) {}
static inline void __iscsi_put_page_callback(struct iscsi_cmnd *cmd) {}
#endif

/* This is partially taken from the Ardis code. */
static int write_data(struct iscsi_conn *conn)
{
	mm_segment_t oldfs;
	struct file *file;
	struct socket *sock;
	ssize_t (*sock_sendpage)(struct socket *, struct page *, int, size_t, int);
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	struct iscsi_cmnd *write_cmnd = conn->write_cmnd;
	struct iscsi_cmnd *ref_cmd;
	struct scatterlist *sg;
	struct iovec *iop;
	int saved_size, size, sendsize;
	int offset, idx, sg_offset;
	int flags, res, count;
	bool do_put = false;

	TRACE_ENTRY();

	iscsi_extracheck_is_wr_thread(conn);

	if (write_cmnd->own_sg == 0)
		ref_cmd = write_cmnd->parent_req;
	else
		ref_cmd = write_cmnd;

	if (!ref_cmd->on_written_list) {
		TRACE_DBG("Adding cmd %p to conn %p written_list", ref_cmd,
			conn);
		spin_lock_bh(&conn->write_list_lock);
		ref_cmd->on_written_list = 1;
		ref_cmd->write_timeout = jiffies + ISCSI_RSP_TIMEOUT;
		list_add_tail(&ref_cmd->write_list_entry, &conn->written_list);
		spin_unlock_bh(&conn->write_list_lock);
	}

	if (!timer_pending(&conn->rsp_timer)) {
		sBUG_ON(!ref_cmd->on_written_list);
		spin_lock_bh(&conn->write_list_lock);
		if (likely(!timer_pending(&conn->rsp_timer))) {
			TRACE_DBG("Starting timer on %ld (conn %p)",
				ref_cmd->write_timeout, conn);
			conn->rsp_timer.expires = ref_cmd->write_timeout;
			add_timer(&conn->rsp_timer);
		}
		spin_unlock_bh(&conn->write_list_lock);
	}

	file = conn->file;
	saved_size = size = conn->write_size;
	iop = conn->write_iop;
	count = conn->write_iop_used;

	if (iop) {
		while (1) {
			loff_t off = 0;
			int rest;

			sBUG_ON(count > sizeof(conn->write_iov)
					/ sizeof(conn->write_iov[0]));
 retry:
			oldfs = get_fs();
			set_fs(KERNEL_DS);
			res = vfs_writev(file, (struct iovec __user *)iop,
					 count, &off);
			set_fs(oldfs);
			TRACE_WRITE("%#Lx:%u: %d(%ld)",
				    (long long unsigned int)conn->session->sid,
				    conn->cid,
				    res, (long)iop->iov_len);
			if (unlikely(res <= 0)) {
				if (res == -EAGAIN) {
					conn->write_iop = iop;
					conn->write_iop_used = count;
					goto out_iov;
				} else if (res == -EINTR)
					goto retry;
				goto out_err;
			}

			rest = res;
			size -= res;
			while (iop->iov_len <= rest && rest) {
				rest -= iop->iov_len;
				iop++;
				count--;
			}
			if (count == 0) {
				conn->write_iop = NULL;
				conn->write_iop_used = 0;
				if (size)
					break;
				goto out_iov;
			}
			sBUG_ON(iop > conn->write_iov + sizeof(conn->write_iov)
						  /sizeof(conn->write_iov[0]));
			iop->iov_base += rest;
			iop->iov_len -= rest;
		}
	}

	sg = write_cmnd->sg;
	if (unlikely(sg == NULL)) {
		PRINT_INFO("WARNING: Data missed (cmd %p)!", write_cmnd);
		res = 0;
		goto out;
	}

	/* To protect from too early transfer completion race */
	__iscsi_get_page_callback(ref_cmd);
	do_put = true;

	sg_offset = sg[0].offset;
	offset = conn->write_offset + sg_offset;
	idx = offset >> PAGE_SHIFT;
	offset &= ~PAGE_MASK;

	sock = conn->sock;

#ifdef NET_PAGE_CALLBACKS_DEFINED
	sock_sendpage = sock->ops->sendpage;
#else
	if ((write_cmnd->parent_req->scst_cmd != NULL) &&
	    scst_cmd_get_data_buff_alloced(write_cmnd->parent_req->scst_cmd))
		sock_sendpage = sock_no_sendpage;
	else
		sock_sendpage = sock->ops->sendpage;
#endif

	flags = MSG_DONTWAIT;

	while (1) {
		sendpage = sock_sendpage;

#ifdef NET_PAGE_CALLBACKS_DEFINED
		{
			static spinlock_t net_priv_lock = SPIN_LOCK_UNLOCKED;
			spin_lock(&net_priv_lock);
			if (sg_page(&sg[idx])->net_priv != NULL) {
				if (sg_page(&sg[idx])->net_priv != ref_cmd) {
					/*
					 * This might happen if user space supplies
					 * to scst_user the same pages in different
					 * commands or in case of zero-copy FILEIO,
					 * when several initiators request the same
					 * data simultaneously.
					 */
					TRACE_DBG("net_priv isn't NULL and != "
						"ref_cmd (write_cmnd %p, ref_cmd %p, "
						"sg %p, idx %d, page %p, net_priv %p)",
						write_cmnd, ref_cmd, sg, idx,
						sg_page(&sg[idx]),
						sg_page(&sg[idx])->net_priv);
					sendpage = sock_no_sendpage;
				}
			} else
				sg_page(&sg[idx])->net_priv = ref_cmd;
			spin_unlock(&net_priv_lock);
		}
#endif
		sendsize = PAGE_SIZE - offset;
		if (size <= sendsize) {
retry2:
			res = sendpage(sock, sg_page(&sg[idx]), offset, size, flags);
			TRACE_WRITE("Final %s %#Lx:%u: %d(%lu,%u,%u, cmd %p, page %p)",
				(sendpage != sock_no_sendpage) ? "sendpage" :
								 "sock_no_sendpage",
				(long long unsigned int)conn->session->sid,
				conn->cid,
				res, sg_page(&sg[idx])->index, offset, size,
				write_cmnd, sg_page(&sg[idx]));
			if (unlikely(res <= 0)) {
				if (res == -EINTR)
					goto retry2;
				else
					goto out_res;
			}

			check_net_priv(ref_cmd, sg_page(&sg[idx]));
			if (res == size) {
				conn->write_size = 0;
				res = saved_size;
				goto out_put;
			}

			offset += res;
			size -= res;
			continue;
		}

retry1:
		res = sendpage(sock, sg_page(&sg[idx]), offset, sendsize,
			flags | MSG_MORE);
		TRACE_WRITE("%s %#Lx:%u: %d(%lu,%u,%u, cmd %p, page %p)",
			(sendpage != sock_no_sendpage) ? "sendpage" :
							 "sock_no_sendpage",
			(unsigned long long)conn->session->sid, conn->cid,
			res, sg_page(&sg[idx])->index, offset, sendsize,
			write_cmnd, sg_page(&sg[idx]));
		if (unlikely(res <= 0)) {
			if (res == -EINTR)
				goto retry1;
			else
				goto out_res;
		}

		check_net_priv(ref_cmd, sg_page(&sg[idx]));
		if (res == sendsize) {
			idx++;
			offset = 0;
			EXTRACHECKS_BUG_ON(idx >= ref_cmd->sg_cnt);
		} else
			offset += res;

		size -= res;
	}

out_off:
	conn->write_offset = (idx << PAGE_SHIFT) + offset - sg_offset;

out_iov:
	conn->write_size = size;
	if ((saved_size == size) && res == -EAGAIN)
		goto out_put;

	res = saved_size - size;

out_put:
	if (do_put)
		__iscsi_put_page_callback(ref_cmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_res:
	check_net_priv(ref_cmd, sg_page(&sg[idx]));
	if (res == -EAGAIN)
		goto out_off;
	/* else go through */

out_err:
#ifndef DEBUG
	if (!conn->closing)
#endif
	{
		PRINT_ERROR("error %d at sid:cid %#Lx:%u, cmnd %p", res,
			    (long long unsigned int)conn->session->sid,
			    conn->cid, conn->write_cmnd);
	}
	if (ref_cmd->scst_cmd != NULL)
		scst_set_delivery_status(ref_cmd->scst_cmd,
			SCST_CMD_DELIVERY_FAILED);
	goto out_put;
}

static int exit_tx(struct iscsi_conn *conn, int res)
{
	iscsi_extracheck_is_wr_thread(conn);

	switch (res) {
	case -EAGAIN:
	case -ERESTARTSYS:
		res = 0;
		break;
	default:
#ifndef DEBUG
		if (!conn->closing)
#endif
		{
			PRINT_ERROR("Sending data failed: initiator %s, "
				"write_size %d, write_state %d, res %d",
				conn->session->initiator_name, conn->write_size,
				conn->write_state, res);
		}
		conn->write_state = TX_END;
		conn->write_size = 0;
		mark_conn_closed(conn);
		break;
	}
	return res;
}

static int tx_ddigest(struct iscsi_cmnd *cmnd, int state)
{
	int res, rest = cmnd->conn->write_size;
	struct msghdr msg = {.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT};
	struct kvec iov;

	iscsi_extracheck_is_wr_thread(cmnd->conn);

	TRACE_DBG("Sending data digest %x (cmd %p)", cmnd->ddigest, cmnd);

	iov.iov_base = (char *) (&cmnd->ddigest) + (sizeof(u32) - rest);
	iov.iov_len = rest;

	res = kernel_sendmsg(cmnd->conn->sock, &msg, &iov, 1, rest);
	if (res > 0) {
		cmnd->conn->write_size -= res;
		if (!cmnd->conn->write_size)
			cmnd->conn->write_state = state;
	} else
		res = exit_tx(cmnd->conn, res);

	return res;
}

static void init_tx_hdigest(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iovec *iop;

	iscsi_extracheck_is_wr_thread(conn);

	digest_tx_header(cmnd);

	sBUG_ON(conn->write_iop_used >= sizeof(conn->write_iov)/sizeof(conn->write_iov[0]));
	iop = &conn->write_iop[conn->write_iop_used];
	conn->write_iop_used++;
	iop->iov_base = &(cmnd->hdigest);
	iop->iov_len = sizeof(u32);
	conn->write_size += sizeof(u32);

	return;
}

static int iscsi_do_send(struct iscsi_conn *conn, int state)
{
	int res;

	iscsi_extracheck_is_wr_thread(conn);

	res = write_data(conn);
	if (res > 0) {
		if (!conn->write_size)
			conn->write_state = state;
	} else
		res = exit_tx(conn, res);

	return res;
}

/*
 * No locks, conn is wr processing.
 *
 * IMPORTANT! Connection conn must be protected by additional conn_get()
 * upon entrance in this function, because otherwise it could be destroyed
 * inside as a result of cmnd release.
 */
int iscsi_send(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd = conn->write_cmnd;
	int ddigest, res = 0;

	TRACE_ENTRY();

	TRACE_DBG("conn %p, write_cmnd %p", conn, cmnd);

	iscsi_extracheck_is_wr_thread(conn);

	ddigest = conn->ddigest_type != DIGEST_NONE ? 1 : 0;

	switch (conn->write_state) {
	case TX_INIT:
		sBUG_ON(cmnd != NULL);
		cmnd = conn->write_cmnd = iscsi_get_send_cmnd(conn);
		if (!cmnd)
			goto out;
		cmnd_tx_start(cmnd);
		if (!(conn->hdigest_type & DIGEST_NONE))
		    init_tx_hdigest(cmnd);
		conn->write_state = TX_BHS_DATA;
	case TX_BHS_DATA:
		res = iscsi_do_send(conn, ddigest && cmnd->pdu.datasize ?
					TX_INIT_DDIGEST : TX_END);
		if (res <= 0 || conn->write_state != TX_INIT_DDIGEST)
			break;
	case TX_INIT_DDIGEST:
		cmnd->conn->write_size = sizeof(u32);
		conn->write_state = TX_DDIGEST;
	case TX_DDIGEST:
		res = tx_ddigest(cmnd, TX_END);
		break;
	default:
		PRINT_CRIT_ERROR("%d %d %x", res, conn->write_state,
			cmnd_opcode(cmnd));
		sBUG();
	}

	if (res == 0)
		goto out;

	if (conn->write_state != TX_END)
		goto out;

	if (unlikely(conn->write_size)) {
		PRINT_CRIT_ERROR("%d %x %u", res, cmnd_opcode(cmnd),
			conn->write_size);
		sBUG();
	}
	cmnd_tx_end(cmnd);

	rsp_cmnd_release(cmnd);

	conn->write_cmnd = NULL;
	conn->write_state = TX_INIT;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* No locks, conn is wr processing.
 *
 * IMPORTANT! Connection conn must be protected by additional conn_get()
 * upon entrance in this function, because otherwise it could be destroyed
 * inside as a result of iscsi_send(), which releases sent commands.
 */
static int process_write_queue(struct iscsi_conn *conn)
{
	int res = 0;

	TRACE_ENTRY();

	if (likely(test_write_ready(conn)))
		res = iscsi_send(conn);

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Called under iscsi_wr_lock and BHs disabled, but will drop it inside,
 * then reaquire.
 */
static void scst_do_job_wr(void)
{
	TRACE_ENTRY();

	/* We delete/add to tail connections to maintain fairness between them */

	while (!list_empty(&iscsi_wr_list)) {
		int rc;
		struct iscsi_conn *conn = list_entry(iscsi_wr_list.next,
			typeof(*conn), wr_list_entry);

		TRACE_DBG("conn %p, wr_state %x, wr_space_ready %d, "
			"write ready %d", conn, conn->wr_state,
			conn->wr_space_ready, test_write_ready(conn));

		list_del(&conn->wr_list_entry);

		sBUG_ON(conn->wr_state == ISCSI_CONN_WR_STATE_PROCESSING);

		conn->wr_state = ISCSI_CONN_WR_STATE_PROCESSING;
		conn->wr_space_ready = 0;
#ifdef EXTRACHECKS
		conn->wr_task = current;
#endif
		spin_unlock_bh(&iscsi_wr_lock);

		conn_get(conn);

		rc = process_write_queue(conn);

		spin_lock_bh(&iscsi_wr_lock);
#ifdef EXTRACHECKS
		conn->wr_task = NULL;
#endif
		if ((rc == -EAGAIN) && !conn->wr_space_ready) {
			conn->wr_state = ISCSI_CONN_WR_STATE_SPACE_WAIT;
			goto cont;
		}

		if (test_write_ready(conn)) {
			list_add_tail(&conn->wr_list_entry, &iscsi_wr_list);
			conn->wr_state = ISCSI_CONN_WR_STATE_IN_LIST;
		} else
			conn->wr_state = ISCSI_CONN_WR_STATE_IDLE;

cont:
		conn_put(conn);
	}

	TRACE_EXIT();
	return;
}

static inline int test_wr_list(void)
{
	int res = !list_empty(&iscsi_wr_list) ||
		  unlikely(kthread_should_stop());
	return res;
}

int istwr(void *arg)
{
	TRACE_ENTRY();

	PRINT_INFO("Write thread started, PID %d", current->pid);

	current->flags |= PF_NOFREEZE;

	spin_lock_bh(&iscsi_wr_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_wr_list()) {
			add_wait_queue_exclusive(&iscsi_wr_waitQ, &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_wr_list())
					break;
				spin_unlock_bh(&iscsi_wr_lock);
				schedule();
				spin_lock_bh(&iscsi_wr_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&iscsi_wr_waitQ, &wait);
		}
		scst_do_job_wr();
	}
	spin_unlock_bh(&iscsi_wr_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so iscsi_wr_list must be empty.
	 */
	sBUG_ON(!list_empty(&iscsi_wr_list));

	PRINT_INFO("Write thread PID %d finished", current->pid);

	TRACE_EXIT();
	return 0;
}
