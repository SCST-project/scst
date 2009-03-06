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

#include <linux/file.h>
#include <linux/ip.h>
#include <net/tcp.h>

#include "iscsi.h"
#include "digest.h"

static void print_conn_state(char *p, size_t size, struct iscsi_conn *conn)
{
	int printed = 0;

	if (conn->closing) {
		snprintf(p, size, "%s", "closing");
		return;
	}

	switch (conn->rd_state) {
	case ISCSI_CONN_RD_STATE_PROCESSING:
		size -= scnprintf(p, size, "%s", "read_processing ");
		printed = 1;
		break;
	case ISCSI_CONN_RD_STATE_IN_LIST:
		size -= scnprintf(p, size, "%s", "in_read_list ");
		printed = 1;
		break;
	}

	switch (conn->wr_state) {
	case ISCSI_CONN_WR_STATE_PROCESSING:
		size -= scnprintf(p, size, "%s", "write_processing ");
		printed = 1;
		break;
	case ISCSI_CONN_WR_STATE_IN_LIST:
		size -= scnprintf(p, size, "%s", "in_write_list ");
		printed = 1;
		break;
	case ISCSI_CONN_WR_STATE_SPACE_WAIT:
		size -= scnprintf(p, size, "%s", "space_waiting ");
		printed = 1;
		break;
	}

	if (conn->conn_reinstating)
		snprintf(p, size, "%s", "reinstating ");
	else if (!printed)
		snprintf(p, size, "%s", "established idle ");

	return;
}

static void print_digest_state(char *p, size_t size, unsigned long flags)
{
	if (DIGEST_NONE & flags)
		snprintf(p, size, "%s", "none");
	else if (DIGEST_CRC32C & flags)
		snprintf(p, size, "%s", "crc32c");
	else
		snprintf(p, size, "%s", "unknown");
}

/* target_mutex supposed to be locked */
void conn_info_show(struct seq_file *seq, struct iscsi_session *session)
{
	struct iscsi_conn *conn;
	struct sock *sk;
	char buf[64];

	list_for_each_entry(conn, &session->conn_list, conn_list_entry) {
		sk = conn->sock->sk;
		switch (sk->sk_family) {
		case AF_INET:
			snprintf(buf, sizeof(buf),
				 "%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->daddr));
			break;
		case AF_INET6:
			snprintf(buf, sizeof(buf),
				 "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]",
				 NIP6(inet6_sk(sk)->daddr));
			break;
		default:
			break;
		}
		seq_printf(seq, "\t\tcid:%u ip:%s ", conn->cid, buf);
		print_conn_state(buf, sizeof(buf), conn);
		seq_printf(seq, "state:%s ", buf);
		print_digest_state(buf, sizeof(buf), conn->hdigest_type);
		seq_printf(seq, "hd:%s ", buf);
		print_digest_state(buf, sizeof(buf), conn->ddigest_type);
		seq_printf(seq, "dd:%s\n", buf);
	}
}

/* target_mutex supposed to be locked */
struct iscsi_conn *conn_lookup(struct iscsi_session *session, u16 cid)
{
	struct iscsi_conn *conn;

	/*
	 * We need to find the latest conn to correctly handle
	 * multi-reinstatements
	 */
	list_for_each_entry_reverse(conn, &session->conn_list,
					conn_list_entry) {
		if (conn->cid == cid)
			return conn;
	}
	return NULL;
}

static void iscsi_make_conn_rd_active(struct iscsi_conn *conn)
{
	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(conn->conn_reinstating);

	spin_lock_bh(&iscsi_rd_lock);

	TRACE_DBG("conn %p, rd_state %x, rd_data_ready %d", conn,
		conn->rd_state, conn->rd_data_ready);

	conn->rd_data_ready = 1;

	if (conn->rd_state == ISCSI_CONN_RD_STATE_IDLE) {
		list_add_tail(&conn->rd_list_entry, &iscsi_rd_list);
		conn->rd_state = ISCSI_CONN_RD_STATE_IN_LIST;
		wake_up(&iscsi_rd_waitQ);
	}

	spin_unlock_bh(&iscsi_rd_lock);

	TRACE_EXIT();
	return;
}

void iscsi_make_conn_wr_active(struct iscsi_conn *conn)
{
	TRACE_ENTRY();

	spin_lock_bh(&iscsi_wr_lock);

	TRACE_DBG("conn %p, wr_state %x, wr_space_ready %d", conn,
		conn->wr_state, conn->wr_space_ready);

	if (conn->wr_state == ISCSI_CONN_WR_STATE_IDLE) {
		list_add_tail(&conn->wr_list_entry, &iscsi_wr_list);
		conn->wr_state = ISCSI_CONN_WR_STATE_IN_LIST;
		wake_up(&iscsi_wr_waitQ);
	}

	spin_unlock_bh(&iscsi_wr_lock);

	TRACE_EXIT();
	return;
}

void __mark_conn_closed(struct iscsi_conn *conn, int flags)
{
	spin_lock_bh(&iscsi_rd_lock);
	conn->closing = 1;
	if (flags & ISCSI_CONN_ACTIVE_CLOSE)
		conn->active_close = 1;
	if (flags & ISCSI_CONN_DELETING)
		conn->deleting = 1;
	spin_unlock_bh(&iscsi_rd_lock);

	if (!conn->conn_reinstating)
		iscsi_make_conn_rd_active(conn);
}

void mark_conn_closed(struct iscsi_conn *conn)
{
	__mark_conn_closed(conn, ISCSI_CONN_ACTIVE_CLOSE);
}

static void __iscsi_state_change(struct sock *sk)
{
	struct iscsi_conn *conn = sk->sk_user_data;

	TRACE_ENTRY();

	if (unlikely(sk->sk_state != TCP_ESTABLISHED)) {
		if (!conn->closing) {
			PRINT_ERROR("Connection with initiator %s "
				"unexpectedly closed!",
				conn->session->initiator_name);
			TRACE_MGMT_DBG("conn %p, sk state %d", conn,
				sk->sk_state);
			__mark_conn_closed(conn, 0);
		}
	} else
		iscsi_make_conn_rd_active(conn);

	TRACE_EXIT();
	return;
}

static void iscsi_state_change(struct sock *sk)
{
	struct iscsi_conn *conn = sk->sk_user_data;

	__iscsi_state_change(sk);
	conn->old_state_change(sk);

	return;
}

static void iscsi_data_ready(struct sock *sk, int len)
{
	struct iscsi_conn *conn = sk->sk_user_data;

	TRACE_ENTRY();

	iscsi_make_conn_rd_active(conn);

	conn->old_data_ready(sk, len);

	TRACE_EXIT();
	return;
}

static void iscsi_write_space_ready(struct sock *sk)
{
	struct iscsi_conn *conn = sk->sk_user_data;

	TRACE_ENTRY();

	TRACE_DBG("Write space ready for conn %p", conn);

	spin_lock_bh(&iscsi_wr_lock);
	conn->wr_space_ready = 1;
	if ((conn->wr_state == ISCSI_CONN_WR_STATE_SPACE_WAIT)) {
		list_add_tail(&conn->wr_list_entry, &iscsi_wr_list);
		conn->wr_state = ISCSI_CONN_WR_STATE_IN_LIST;
		wake_up(&iscsi_wr_waitQ);
	}
	spin_unlock_bh(&iscsi_wr_lock);

	conn->old_write_space(sk);

	TRACE_EXIT();
	return;
}

static void conn_rsp_timer_fn(unsigned long arg)
{
	struct iscsi_conn *conn = (struct iscsi_conn *)arg;

	TRACE_ENTRY();

	TRACE_DBG("Timer (conn %p)", conn);

	spin_lock_bh(&conn->write_list_lock);

	if (!list_empty(&conn->written_list)) {
		struct iscsi_cmnd *wr_cmd = list_entry(conn->written_list.next,
				struct iscsi_cmnd, write_list_entry);

		if (unlikely(time_after_eq(jiffies, wr_cmd->write_timeout))) {
			if (!conn->closing) {
				PRINT_ERROR("Timeout sending data to initiator"
					" %s (SID %llx), closing connection",
					conn->session->initiator_name,
					(long long unsigned int)
						conn->session->sid);
				mark_conn_closed(conn);
			}
		} else {
			TRACE_DBG("Restarting timer on %ld (conn %p)",
				wr_cmd->write_timeout, conn);
			/*
			 * Timer might have been restarted while we were
			 * entering here.
			 */
			mod_timer(&conn->rsp_timer, wr_cmd->write_timeout);
		}
	}

	spin_unlock_bh(&conn->write_list_lock);

	TRACE_EXIT();
	return;
}

void __iscsi_socket_bind(struct iscsi_conn *conn)
{
	TRACE_MGMT_DBG("Enabling conn %p", conn);

	/* Catch double bind */
	sBUG_ON(conn->sock->sk->sk_state_change == iscsi_state_change);

	/* Let's reset this flag in one place */
	conn->conn_reinstating = 0;

	write_lock_bh(&conn->sock->sk->sk_callback_lock);

	conn->old_state_change = conn->sock->sk->sk_state_change;
	conn->sock->sk->sk_state_change = iscsi_state_change;

	conn->old_data_ready = conn->sock->sk->sk_data_ready;
	conn->sock->sk->sk_data_ready = iscsi_data_ready;

	conn->old_write_space = conn->sock->sk->sk_write_space;
	conn->sock->sk->sk_write_space = iscsi_write_space_ready;

	write_unlock_bh(&conn->sock->sk->sk_callback_lock);

	/*
	 * Check, if conn was closed while we were initializing it.
	 * This function will make conn rd_active, if necessary.
	 */
	__iscsi_state_change(conn->sock->sk);

	return;
}

/*
 * Note: the code below passes a kernel space pointer (&opt) to setsockopt()
 * while the declaration of setsockopt specifies that it expects a user space
 * pointer. This seems to work fine, and this approach is also used in some
 * other parts of the Linux kernel (see e.g. fs/ocfs2/cluster/tcp.c).
 */
static int iscsi_socket_bind(struct iscsi_conn *conn, bool reinstating)
{
	int res = 0;
	int opt = 1;
	mm_segment_t oldfs;
	struct iscsi_session *session = conn->session;

	TRACE_DBG("%llu", (long long unsigned int)session->sid);

	conn->sock = SOCKET_I(conn->file->f_dentry->d_inode);

	if (conn->sock->ops->sendpage == NULL) {
		PRINT_ERROR("Socket for sid %llu doesn't support sendpage()",
			    (long long unsigned int)session->sid);
		res = -EINVAL;
		goto out;
	}

#if 0
	conn->sock->sk->sk_allocation = GFP_NOIO;
#endif
	conn->sock->sk->sk_user_data = conn;

	oldfs = get_fs();
	set_fs(get_ds());
	conn->sock->ops->setsockopt(conn->sock, SOL_TCP, TCP_NODELAY,
		(void __force __user *)&opt, sizeof(opt));
	set_fs(oldfs);

	if (!reinstating) {
		/*
		 * We will delay full conn serving until all commands in
		 * replacing connections are done to prevent them from
		 * spoil our data by writing to them too late.
		 */
		__iscsi_socket_bind(conn);
	} else
		TRACE_MGMT_DBG("conn %p is reinstating, delaying enabling it",
			conn);

out:
	return res;
}

/* target_mutex supposed to be locked */
int conn_free(struct iscsi_conn *conn)
{
	TRACE_MGMT_DBG("Freeing conn %p (sess=%p, %#Lx %u)", conn,
		       conn->session,
		       (long long unsigned int)conn->session->sid,
		       conn->cid);

	del_timer_sync(&conn->rsp_timer);

	sBUG_ON(atomic_read(&conn->conn_ref_cnt) != 0);
	sBUG_ON(!list_empty(&conn->cmd_list));
	sBUG_ON(!list_empty(&conn->write_list));
	sBUG_ON(!list_empty(&conn->written_list));
	sBUG_ON(conn->conn_reinst_successor != NULL);
	sBUG_ON(!conn->conn_shutting_down);

	if (conn->conn_reinstating) {
		struct iscsi_conn *c;
		TRACE_MGMT_DBG("Freeing being reinstated conn %p", conn);
		list_for_each_entry(c, &conn->session->conn_list,
					conn_list_entry) {
			if (c->conn_reinst_successor == conn) {
				c->conn_reinst_successor = NULL;
				break;
			}
		}
	}

	list_del(&conn->conn_list_entry);

	fput(conn->file);
	conn->file = NULL;
	conn->sock = NULL;

	free_page((unsigned long)conn->read_iov);

	kfree(conn);

	return 0;
}

/* target_mutex supposed to be locked */
static int iscsi_conn_alloc(struct iscsi_session *session,
	struct iscsi_kern_conn_info *info, bool reinstating,
	struct iscsi_conn **new_conn)
{
	struct iscsi_conn *conn;
	int res = 0;

	reinstating |= session->sess_reinstating;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn) {
		res = -ENOMEM;
		goto out_err;
	}

	TRACE_MGMT_DBG("Creating connection %p for sid %#Lx, cid %u", conn,
		       (long long unsigned int)session->sid, info->cid);

	/* Changing it, change ISCSI_CONN_IOV_MAX as well !! */
	conn->read_iov = (struct iovec *)get_zeroed_page(GFP_KERNEL);
	if (conn->read_iov == NULL) {
		res = -ENOMEM;
		goto out_err_free_conn;
	}

	atomic_set(&conn->conn_ref_cnt, 0);
	conn->session = session;
	conn->conn_reinstating = reinstating;
	conn->cid = info->cid;
	conn->stat_sn = info->stat_sn;
	conn->exp_stat_sn = info->exp_stat_sn;
	conn->rd_state = ISCSI_CONN_RD_STATE_IDLE;
	conn->wr_state = ISCSI_CONN_WR_STATE_IDLE;

	conn->hdigest_type = info->header_digest;
	conn->ddigest_type = info->data_digest;
	res = digest_init(conn);
	if (res != 0)
		goto out_err_free1;

	conn->target = session->target;
	spin_lock_init(&conn->cmd_list_lock);
	INIT_LIST_HEAD(&conn->cmd_list);
	spin_lock_init(&conn->write_list_lock);
	INIT_LIST_HEAD(&conn->write_list);
	INIT_LIST_HEAD(&conn->written_list);
	setup_timer(&conn->rsp_timer, conn_rsp_timer_fn, (unsigned long)conn);
	init_completion(&conn->ready_to_free);

	conn->file = fget(info->fd);

	res = iscsi_socket_bind(conn, reinstating);
	if (res != 0)
		goto out_err_free2;

	list_add_tail(&conn->conn_list_entry, &session->conn_list);

	*new_conn = conn;

out:
	return res;

out_err_free2:
	fput(conn->file);

out_err_free1:
	free_page((unsigned long)conn->read_iov);

out_err_free_conn:
	kfree(conn);

out_err:
	goto out;
}

/* target_mutex supposed to be locked */
int conn_add(struct iscsi_session *session, struct iscsi_kern_conn_info *info)
{
	struct iscsi_conn *conn, *new_conn;
	int err;
	bool reinstatement = false;

	conn = conn_lookup(session, info->cid);
	if ((conn != NULL) && !conn->conn_shutting_down) {
		/* conn reinstatement */
		reinstatement = true;
	} else if (!list_empty(&session->conn_list)) {
		err = -EEXIST;
		goto out;
	}

	err = iscsi_conn_alloc(session, info, reinstatement, &new_conn);
	if (err != 0)
		goto out;

	if (reinstatement) {
		TRACE_MGMT_DBG("Reinstating conn (old %p, new %p)", conn,
			new_conn);
		conn->conn_reinst_successor = new_conn;
		new_conn->conn_reinstating = 1;
		__mark_conn_closed(conn, 0);
	}

out:
	return err;
}

/* target_mutex supposed to be locked */
int conn_del(struct iscsi_session *session, struct iscsi_kern_conn_info *info)
{
	struct iscsi_conn *conn;
	int err = -EEXIST;

	conn = conn_lookup(session, info->cid);
	if (!conn)
		return err;

	PRINT_INFO("Deleting connection with initiator %s (%p)",
		conn->session->initiator_name, conn);

	__mark_conn_closed(conn, ISCSI_CONN_ACTIVE_CLOSE|ISCSI_CONN_DELETING);

	return 0;
}

#ifdef CONFIG_SCST_EXTRACHECKS

void iscsi_extracheck_is_rd_thread(struct iscsi_conn *conn)
{
	if (unlikely(current != conn->rd_task)) {
		printk(KERN_EMERG "conn %p rd_task != current %p (pid %d)\n",
			conn, current, current->pid);
		while (in_softirq())
			local_bh_enable();
		printk(KERN_EMERG "rd_state %x\n", conn->rd_state);
		printk(KERN_EMERG "rd_task %p\n", conn->rd_task);
		printk(KERN_EMERG "rd_task->pid %d\n", conn->rd_task->pid);
		BUG();
	}
}

void iscsi_extracheck_is_wr_thread(struct iscsi_conn *conn)
{
	if (unlikely(current != conn->wr_task)) {
		printk(KERN_EMERG "conn %p wr_task != current %p (pid %d)\n",
			conn, current, current->pid);
		while (in_softirq())
			local_bh_enable();
		printk(KERN_EMERG "wr_state %x\n", conn->wr_state);
		printk(KERN_EMERG "wr_task %p\n", conn->wr_task);
		printk(KERN_EMERG "wr_task->pid %d\n", conn->wr_task->pid);
		BUG();
	}
}

#endif /* CONFIG_SCST_EXTRACHECKS */
