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

	if ((conn->sock->sk->sk_state != TCP_CLOSE_WAIT) &&
	    (conn->sock->sk->sk_state != TCP_CLOSE)) {
		TRACE_CONN_CLOSE_DBG("sk_state %d, skipping",
			conn->sock->sk->sk_state);
		goto out;
	}

	/*
	 * No data are going to be sent, so all being sent buffers can be freed
	 * now. Strange that TCP doesn't do that itself.
	 */

again:
	spin_lock_bh(&conn->cmd_list_lock);
	list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
		TRACE_CONN_CLOSE_DBG("cmd %p, scst_state %x, data_waiting %d, "
			"ref_cnt %d, parent_req %p, net_ref_cnt %d, sg %p",
			cmnd, cmnd->scst_state, cmnd->data_waiting,
			atomic_read(&cmnd->ref_cnt), cmnd->parent_req,
			atomic_read(&cmnd->net_ref_cnt), cmnd->sg);
		sBUG_ON(cmnd->parent_req != NULL);
		if (cmnd->sg != NULL) {
			int sg_cnt, i, restart = 0;
			sg_cnt = get_pgcnt(cmnd->bufflen,
				cmnd->sg[0].offset);
			cmnd_get(cmnd);
			for(i = 0; i < sg_cnt; i++) {
				TRACE_CONN_CLOSE_DBG("page %p, net_priv %p, _count %d",
					cmnd->sg[i].page, cmnd->sg[i].page->net_priv,
					atomic_read(&cmnd->sg[i].page->_count));
				if (cmnd->sg[i].page->net_priv != NULL) {
					if (restart == 0) {
						spin_unlock_bh(&conn->cmd_list_lock);
						restart = 1;
					}
					while(cmnd->sg[i].page->net_priv != NULL)
						iscsi_put_page_callback(cmnd->sg[i].page);
				}
			}
			cmnd_put(cmnd);
			if (restart)
				goto again;
		}
	}
	spin_unlock_bh(&conn->cmd_list_lock);

out:
	TRACE_EXIT();
	return;
}
#else
static inline void iscsi_check_closewait(struct iscsi_conn *conn) {};
#endif

/* No locks */
static void close_conn(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;
	struct iscsi_target *target = conn->target;

	TRACE_ENTRY();

	TRACE_CONN_CLOSE("Closing connection %p (conn_ref_cnt=%d)", conn,
		atomic_read(&conn->conn_ref_cnt));

	iscsi_extracheck_is_rd_thread(conn);

	/* We want all our already send operations to complete */
	conn->sock->ops->shutdown(conn->sock, RCV_SHUTDOWN);

	conn_abort(conn);

	if (conn->read_state != RX_INIT_BHS) {
		req_cmnd_release_force(conn->read_cmnd, 0);
		conn->read_cmnd = NULL;
		conn->read_state = RX_INIT_BHS;
	}

	/* ToDo: not the best way to wait */
	while(atomic_read(&conn->conn_ref_cnt) != 0) {
		struct iscsi_cmnd *cmnd;

		if (!list_empty(&session->pending_list)) {
			struct list_head *pending_list = &session->pending_list;
	 		struct iscsi_cmnd *tmp;

	 		TRACE_CONN_CLOSE("Disposing pending commands on "
	 			"connection %p (conn_ref_cnt=%d)", conn,
	 			atomic_read(&conn->conn_ref_cnt));
 
			list_for_each_entry_safe(cmnd, tmp, pending_list,
						pending_list_entry) {
				if (cmnd->conn == conn) {
					TRACE_CONN_CLOSE("Freeing pending cmd %p",
						cmnd);
					list_del(&cmnd->pending_list_entry);
					cmnd->pending = 0;
					req_cmnd_release_force(cmnd, 0);
				}
			}
		}

		iscsi_make_conn_wr_active(conn);
		msleep(50);

		TRACE_CONN_CLOSE("conn %p, conn_ref_cnt %d left, wr_state %d",
			conn, atomic_read(&conn->conn_ref_cnt), conn->wr_state);
#ifdef DEBUG
		{
#ifdef NET_PAGE_CALLBACKS_DEFINED
			struct iscsi_cmnd *rsp;
#endif
			spin_lock_bh(&conn->cmd_list_lock);
			list_for_each_entry(cmnd, &conn->cmd_list, cmd_list_entry) {
				TRACE_CONN_CLOSE_DBG("cmd %p, scst_state %x, data_waiting "
					"%d, ref_cnt %d, parent_req %p", cmnd,
					cmnd->scst_state, cmnd->data_waiting,
					atomic_read(&cmnd->ref_cnt), cmnd->parent_req);
#ifdef NET_PAGE_CALLBACKS_DEFINED
				TRACE_CONN_CLOSE_DBG("net_ref_cnt %d, sg %p",
					atomic_read(&cmnd->net_ref_cnt), cmnd->sg);
				if (cmnd->sg != NULL) {
					int sg_cnt, i;
					sg_cnt = get_pgcnt(cmnd->bufflen,
						cmnd->sg[0].offset);
					for(i = 0; i < sg_cnt; i++) {
						TRACE_CONN_CLOSE_DBG("page %p, net_priv %p, _count %d",
							cmnd->sg[i].page, cmnd->sg[i].page->net_priv,
							atomic_read(&cmnd->sg[i].page->_count));
					}
				}

				sBUG_ON(cmnd->parent_req != NULL);
				
				spin_lock_bh(&cmnd->rsp_cmd_lock);
				list_for_each_entry(rsp, &cmnd->rsp_cmd_list, rsp_cmd_list_entry) {
					TRACE_CONN_CLOSE_DBG("  rsp %p, ref_cnt %d, net_ref_cnt %d, "
						"sg %p", rsp, atomic_read(&rsp->ref_cnt),
						atomic_read(&rsp->net_ref_cnt), rsp->sg);
					if ((rsp->sg != cmnd->sg) && (rsp->sg != NULL)) {
						int sg_cnt, i;
						sg_cnt = get_pgcnt(rsp->bufflen,
							rsp->sg[0].offset);
						sBUG_ON(rsp->sg_cnt != sg_cnt);
						for(i = 0; i < sg_cnt; i++) {
							TRACE_CONN_CLOSE_DBG("    page %p, net_priv %p, "
								"_count %d", rsp->sg[i].page,
								rsp->sg[i].page->net_priv,
								atomic_read(&rsp->sg[i].page->_count));
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

	while(conn->wr_state != ISCSI_CONN_WR_STATE_IDLE) {
		TRACE_CONN_CLOSE("Waiting for wr thread (conn %p), wr_state %x",
			conn, conn->wr_state);
		msleep(50);
	}

	TRACE_CONN_CLOSE("Notifying user space about closing connection %p", conn);
	event_send(target->tid, session->sid, conn->cid, E_CONN_CLOSE, 0);

	mutex_lock(&target->target_mutex);
	conn_free(conn);
	if (list_empty(&session->conn_list))
		session_del(target, session->sid);
	mutex_unlock(&target->target_mutex);

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

	spin_lock(&conn->write_list_lock);
	if (!list_empty(&conn->write_list)) {
		cmnd = list_entry(conn->write_list.next, struct iscsi_cmnd,
				write_list_entry);
		cmd_del_from_write_list(cmnd);
		cmnd->write_processing_started = 1;
	}
	spin_unlock(&conn->write_list_lock);

	return cmnd;
}

static int do_recv(struct iscsi_conn *conn, int state)
{
	mm_segment_t oldfs;
	struct msghdr msg;
	int res, first_len;

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
		if (cmnd_opcode(cmnd) == ISCSI_OP_SCSI_CMD) {
			TRACE_DBG("Adding RX ddigest cmd %p to digest list "
				"of self", cmnd);
			list_add_tail(&cmnd->rx_ddigest_cmd_list_entry,
				&cmnd->rx_ddigest_cmd_list);
			cmnd_get(cmnd);
			conn->read_state = RX_END;
		} else if (cmnd_opcode(cmnd) != ISCSI_OP_SCSI_DATA_OUT) {
			/*
			 * We could get here only for NOP-Out. ISCSI RFC doesn't
			 * specify how to deal with digest errors in this case.
			 * Is closing connection correct?
			 */
			TRACE_DBG("cmnd %p, opcode %x: checking RX "
				"ddigest inline", cmnd, cmnd_opcode(cmnd));
			rc = digest_rx_data(cmnd);
			if (unlikely(rc != 0)) {
				conn->read_state = RX_CHECK_DDIGEST;
				mark_conn_closed(conn);
			}
		}
		break;
	default:
		PRINT_ERROR("%d %x", conn->read_state, cmnd_opcode(cmnd));
		sBUG();
	}

	if (res <= 0)
		goto out;

	if (conn->read_state != RX_END)
		goto out;

	if (conn->read_size) {
		PRINT_ERROR("%d %x %d", res, cmnd_opcode(cmnd), conn->read_size);
		sBUG();
	}

	cmnd_rx_end(cmnd);

	sBUG_ON(conn->read_size != 0);

	conn->read_cmnd = NULL;
	conn->read_state = RX_INIT_BHS;
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
			close_conn(conn);
			*closed = 1;
			break;
		}
	} while(res > 0);

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

	while(!list_empty(&iscsi_rd_list)) {
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

	current->flags |= PF_NOFREEZE;

	spin_lock_bh(&iscsi_rd_lock);
	while(!kthread_should_stop()) {
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

	TRACE_EXIT();
	return 0;
}

#ifdef NET_PAGE_CALLBACKS_DEFINED
void iscsi_get_page_callback(struct page *page)
{
	struct iscsi_cmnd *cmd = (struct iscsi_cmnd*)page->net_priv;
	int v;

	TRACE_NET_PAGE("cmd %p, page %p, _count %d, new net_ref_cnt %d",
		cmd, page, atomic_read(&page->_count),
		atomic_read(&cmd->net_ref_cnt)+1);

	v = atomic_inc_return(&cmd->net_ref_cnt);
	if (v == 1) {
		TRACE_NET_PAGE("getting cmd %p for page %p", cmd, page);
		cmnd_get(cmd);
	}
}

void iscsi_put_page_callback(struct page *page)
{
	struct iscsi_cmnd *cmd = (struct iscsi_cmnd*)page->net_priv;

	TRACE_NET_PAGE("cmd %p, page %p, _count %d, new net_ref_cnt %d",
		cmd, page, atomic_read(&page->_count),
		atomic_read(&cmd->net_ref_cnt)-1);

	if (atomic_dec_and_test(&cmd->net_ref_cnt)) {
		int i, sg_cnt = get_pgcnt(cmd->bufflen,	cmd->sg[0].offset);
		for(i = 0; i < sg_cnt; i++) {
			TRACE_NET_PAGE("Clearing page %p", cmd->sg[i].page);
			cmd->sg[i].page->net_priv = NULL;
		}
		cmnd_put(cmd);
	}
}

static void check_net_priv(struct iscsi_cmnd *cmd, struct page *page)
{
	if (atomic_read(&cmd->net_ref_cnt) == 0) {
		TRACE_DBG("%s", "sendpage() not called get_page(), "
			"zeroing net_priv");
		page->net_priv = NULL;
	}
}
#else
static inline void check_net_priv(struct iscsi_cmnd *cmd, struct page *page) {}
#endif

/* This is partially taken from the Ardis code. */
static int write_data(struct iscsi_conn *conn)
{
	mm_segment_t oldfs;
	struct file *file;
	struct socket *sock;
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	struct iscsi_cmnd *write_cmnd = conn->write_cmnd;
	struct iscsi_cmnd *ref_cmd;
	struct scatterlist *sg;
	struct iovec *iop;
	int saved_size, size, sendsize;
	int offset, idx;
	int flags, res, count;

	iscsi_extracheck_is_wr_thread(conn);

	if (write_cmnd->own_sg == 0)
		ref_cmd = write_cmnd->parent_req;
	else
		ref_cmd = write_cmnd;

	file = conn->file;
	saved_size = size = conn->write_size;
	iop = conn->write_iop;
	count = conn->write_iop_used;

	if (iop) while (1) {
		loff_t off = 0;
		int rest;

		sBUG_ON(count > sizeof(conn->write_iov)/sizeof(conn->write_iov[0]));
retry:
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		res = vfs_writev(file, (struct iovec __user *)iop, count, &off);
		set_fs(oldfs);
		TRACE(TRACE_D_WRITE, "%#Lx:%u: %d(%ld)",
			(unsigned long long) conn->session->sid, conn->cid,
			res, (long) iop->iov_len);
		if (unlikely(res <= 0)) {
			if (res == -EAGAIN) {
				conn->write_iop = iop;
				conn->write_iop_used = count;
				goto out_iov;
			} else if (res == -EINTR)
				goto retry;
			goto err;
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
		sBUG_ON(iop > conn->write_iov + 
			sizeof(conn->write_iov)/sizeof(conn->write_iov[0]));
		iop->iov_base += rest;
		iop->iov_len -= rest;
	}

	sg = write_cmnd->sg;
	if (sg == NULL) {
		PRINT_ERROR("%s", "warning data missing!");
		return 0;
	}
	offset = conn->write_offset;
	idx = offset >> PAGE_SHIFT;
	offset &= ~PAGE_MASK;

	sock = conn->sock;

#ifdef NET_PAGE_CALLBACKS_DEFINED
	sendpage = sock->ops->sendpage;
#else
	if ((write_cmnd->parent_req->scst_cmd != NULL) &&
	    scst_cmd_get_data_buff_alloced(write_cmnd->parent_req->scst_cmd))
		sendpage = sock_no_sendpage;
	else
		sendpage = sock->ops->sendpage;
#endif

	flags = MSG_DONTWAIT;

	while (1) {
#ifdef NET_PAGE_CALLBACKS_DEFINED
		if (unlikely((sg[idx].page->net_priv != NULL) &&
				(sg[idx].page->net_priv != ref_cmd))) {
			PRINT_ERROR("net_priv isn't NULL and != ref_cmd "
				"(write_cmnd %p, ref_cmd %p, sg %p, idx %d, "
				"net_priv %p)", write_cmnd, ref_cmd, sg, idx,
				sg[idx].page->net_priv);
			sBUG();
		}
		sg[idx].page->net_priv = ref_cmd;
#endif
		sendsize = PAGE_SIZE - offset;
		if (size <= sendsize) {
retry2:
			res = sendpage(sock, sg[idx].page, offset, size, flags);
			TRACE(TRACE_D_WRITE, "%s %#Lx:%u: %d(%lu,%u,%u)",
				sock->ops->sendpage ? "sendpage" : "sock_no_sendpage",
				(unsigned long long)conn->session->sid, conn->cid,
				res, sg[idx].page->index, offset, size);
			if (unlikely(res <= 0)) {
				if (res == -EINTR)
					goto retry2;
				else
					goto out_res;
			}
			check_net_priv(ref_cmd, sg[idx].page);
			if (res == size) {
				conn->write_size = 0;
				return saved_size;
			}
			offset += res;
			size -= res;
			continue;
		}

retry1:
		res = sendpage(sock, sg[idx].page, offset, sendsize,
			flags | MSG_MORE);
		TRACE(TRACE_D_WRITE, "%s %#Lx:%u: %d(%lu,%u,%u)",
			sock->ops->sendpage ? "sendpage" : "sock_no_sendpage",
			(unsigned long long ) conn->session->sid, conn->cid,
			res, sg[idx].page->index, offset, sendsize);
		if (unlikely(res <= 0)) {
			if (res == -EINTR)
				goto retry1;
			else
				goto out_res;
		}
		check_net_priv(ref_cmd, sg[idx].page);
		if (res == sendsize) {
			idx++;
			offset = 0;
		} else
			offset += res;
		size -= res;
	}
out:
	conn->write_offset = (idx << PAGE_SHIFT) + offset;
out_iov:
	conn->write_size = size;
	if ((saved_size == size) && res == -EAGAIN)
		return res;

	return saved_size - size;

out_res:
	check_net_priv(ref_cmd, sg[idx].page);
	if (res == -EAGAIN)
		goto out;
	/* else go through */

err:
#ifndef DEBUG
	if (!conn->closing)
#endif
	{
		PRINT_ERROR("error %d at sid:cid %#Lx:%u, cmnd %p", res,
			(unsigned long long)conn->session->sid, conn->cid,
			conn->write_cmnd);
	}
	if (ref_cmd->scst_cmd != NULL)
		scst_set_delivery_status(ref_cmd->scst_cmd,
			SCST_CMD_DELIVERY_FAILED);
	return res;
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
		PRINT_ERROR("%d %d %x", res, conn->write_state,
			cmnd_opcode(cmnd));
		sBUG();
	}

	if (res == 0)
		goto out;

	if (conn->write_state != TX_END)
		goto out;

	if (conn->write_size) {
		PRINT_ERROR("%d %x %u", res, cmnd_opcode(cmnd),
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

	while(!list_empty(&iscsi_wr_list)) {
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

	current->flags |= PF_NOFREEZE;

	spin_lock_bh(&iscsi_wr_lock);
	while(!kthread_should_stop()) {
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

	TRACE_EXIT();
	return 0;
}
