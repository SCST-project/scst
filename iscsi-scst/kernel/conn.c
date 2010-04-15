/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2010 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
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

static int print_conn_state(char *p, size_t size, struct iscsi_conn *conn)
{
	int pos = 0;

	if (conn->closing) {
		pos += scnprintf(p, size, "%s", "closing");
		goto out;
	}

	switch (conn->rd_state) {
	case ISCSI_CONN_RD_STATE_PROCESSING:
		pos += scnprintf(&p[pos], size - pos, "%s", "read_processing ");
		break;
	case ISCSI_CONN_RD_STATE_IN_LIST:
		pos += scnprintf(&p[pos], size - pos, "%s", "in_read_list ");
		break;
	}

	switch (conn->wr_state) {
	case ISCSI_CONN_WR_STATE_PROCESSING:
		pos += scnprintf(&p[pos], size - pos, "%s", "write_processing ");
		break;
	case ISCSI_CONN_WR_STATE_IN_LIST:
		pos += scnprintf(&p[pos], size - pos, "%s", "in_write_list ");
		break;
	case ISCSI_CONN_WR_STATE_SPACE_WAIT:
		pos += scnprintf(&p[pos], size - pos, "%s", "space_waiting ");
		break;
	}

	if (test_bit(ISCSI_CONN_REINSTATING, &conn->conn_aflags))
		pos += scnprintf(&p[pos], size - pos, "%s", "reinstating ");
	else if (pos == 0)
		pos += scnprintf(&p[pos], size - pos, "%s", "established idle ");

out:
	return pos;
}

#ifdef CONFIG_SCST_PROC

static int print_digest_state(char *p, size_t size, unsigned long flags)
{
	int pos;

	if (DIGEST_NONE & flags)
		pos = scnprintf(p, size, "%s", "none");
	else if (DIGEST_CRC32C & flags)
		pos = scnprintf(p, size, "%s", "crc32c");
	else
		pos = scnprintf(p, size, "%s", "unknown");

	return pos;
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
				 "%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->daddr));
#else
				 "%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->inet_daddr));
#endif
			break;
		case AF_INET6:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
			snprintf(buf, sizeof(buf),
				 "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]",
				 NIP6(inet6_sk(sk)->daddr));
#else
			snprintf(buf, sizeof(buf), "[%p6]",
				&inet6_sk(sk)->daddr);
#endif
			break;
		default:
			snprintf(buf, sizeof(buf), "Unknown family %d",
				sk->sk_family);
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

#else /* CONFIG_SCST_PROC */

static int conn_free(struct iscsi_conn *conn);

static void iscsi_conn_release(struct kobject *kobj)
{
	struct iscsi_conn *conn;
	struct iscsi_target *target;

	TRACE_ENTRY();

	conn = container_of(kobj, struct iscsi_conn, iscsi_conn_kobj);
	target = conn->target;

	mutex_lock(&target->target_mutex);
	conn_free(conn);
	mutex_unlock(&target->target_mutex);

	TRACE_EXIT();
	return;
}

static struct kobj_type iscsi_conn_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = iscsi_conn_release,
};

static ssize_t iscsi_get_initiator_ip(struct iscsi_conn *conn,
	char *buf, int size)
{
	int pos;
	struct sock *sk;

	TRACE_ENTRY();

	sk = conn->sock->sk;
	switch (sk->sk_family) {
	case AF_INET:
		pos = scnprintf(buf, size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			 "%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->daddr));
#else
			"%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->inet_daddr));
#endif
		break;
	case AF_INET6:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
		pos = scnprintf(buf, size,
			 "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]",
			 NIP6(inet6_sk(sk)->daddr));
#else
		pos = scnprintf(buf, size, "[%p6]",
			&inet6_sk(sk)->daddr);
#endif
		break;
	default:
		pos = scnprintf(buf, size, "Unknown family %d",
			sk->sk_family);
		break;
	}

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t iscsi_conn_ip_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct iscsi_conn *conn;

	TRACE_ENTRY();

	conn = container_of(kobj, struct iscsi_conn, iscsi_conn_kobj);

	pos = iscsi_get_initiator_ip(conn, buf, SCST_SYSFS_BLOCK_SIZE);

	TRACE_EXIT_RES(pos);
	return pos;
}

static struct kobj_attribute iscsi_conn_ip_attr =
	__ATTR(ip, S_IRUGO, iscsi_conn_ip_show, NULL);

static ssize_t iscsi_conn_cid_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct iscsi_conn *conn;

	TRACE_ENTRY();

	conn = container_of(kobj, struct iscsi_conn, iscsi_conn_kobj);

	pos = sprintf(buf, "%u", conn->cid);

	TRACE_EXIT_RES(pos);
	return pos;
}

static struct kobj_attribute iscsi_conn_cid_attr =
	__ATTR(cid, S_IRUGO, iscsi_conn_cid_show, NULL);

static ssize_t iscsi_conn_state_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct iscsi_conn *conn;

	TRACE_ENTRY();

	conn = container_of(kobj, struct iscsi_conn, iscsi_conn_kobj);

	pos = print_conn_state(buf, SCST_SYSFS_BLOCK_SIZE, conn);

	TRACE_EXIT_RES(pos);
	return pos;
}

static struct kobj_attribute iscsi_conn_state_attr =
	__ATTR(state, S_IRUGO, iscsi_conn_state_show, NULL);

#endif /* CONFIG_SCST_PROC */

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

void iscsi_make_conn_rd_active(struct iscsi_conn *conn)
{
	TRACE_ENTRY();

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
	struct iscsi_cmnd *cmnd;
	unsigned long j = jiffies;

	TRACE_ENTRY();

	TRACE_DBG("Timer (conn %p)", conn);

	spin_lock_bh(&conn->write_list_lock);

	if (!list_empty(&conn->write_timeout_list)) {
		unsigned long timeout_time;
		cmnd = list_entry(conn->write_timeout_list.next,
				struct iscsi_cmnd, write_timeout_list_entry);

		timeout_time = j + conn->rsp_timeout + ISCSI_ADD_SCHED_TIME;

		if (unlikely(time_after_eq(j, cmnd->write_start +
						conn->rsp_timeout))) {
			if (!conn->closing) {
				PRINT_ERROR("Timeout sending data/waiting "
					"for reply to/from initiator "
					"%s (SID %llx), closing connection",
					conn->session->initiator_name,
					(long long unsigned int)
						conn->session->sid);
				/*
				 * We must call mark_conn_closed() outside of
				 * write_list_lock or we will have a circular
				 * locking dependency with iscsi_rd_lock.
				 */
				spin_unlock_bh(&conn->write_list_lock);
				mark_conn_closed(conn);
				goto out;
			}
		} else if (!timer_pending(&conn->rsp_timer) ||
			   time_after(conn->rsp_timer.expires, timeout_time)) {
			TRACE_DBG("Restarting timer on %ld (conn %p)",
				timeout_time, conn);
			/*
			 * Timer might have been restarted while we were
			 * entering here.
			 */
			mod_timer(&conn->rsp_timer, timeout_time);
		}
	}

	spin_unlock_bh(&conn->write_list_lock);

	if (unlikely(conn->conn_tm_active)) {
		TRACE_MGMT_DBG("TM active: making conn %p RD active", conn);
		iscsi_make_conn_rd_active(conn);
	}

out:
	TRACE_EXIT();
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void conn_nop_in_delayed_work_fn(void *p)
#else
static void conn_nop_in_delayed_work_fn(struct delayed_work *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct iscsi_conn *conn = (struct iscsi_conn *)p;
#else
	struct iscsi_conn *conn = container_of(work, struct iscsi_conn,
		nop_in_delayed_work);
#endif

	TRACE_ENTRY();

	if (time_after_eq(jiffies, conn->last_rcv_time +
				conn->nop_in_interval)) {
		iscsi_send_nop_in(conn);
	}

	if (conn->nop_in_interval > 0) {
		TRACE_DBG("Reschedule Nop-In work for conn %p", conn);
		schedule_delayed_work(&conn->nop_in_delayed_work,
			conn->nop_in_interval + ISCSI_ADD_SCHED_TIME);
	}

	TRACE_EXIT();
	return;
}

/* Must be called from rd thread only */
void iscsi_check_tm_data_wait_timeouts(struct iscsi_conn *conn, bool force)
{
	struct iscsi_cmnd *cmnd;
	unsigned long j = jiffies;
	bool aborted_cmds_pending;
	unsigned long timeout_time = j + ISCSI_TM_DATA_WAIT_TIMEOUT +
					ISCSI_ADD_SCHED_TIME;

	TRACE_ENTRY();

	TRACE_DBG_FLAG(force ? TRACE_CONN_OC_DBG : TRACE_MGMT_DEBUG,
		"j %ld (TIMEOUT %d, force %d)", j,
		ISCSI_TM_DATA_WAIT_TIMEOUT + ISCSI_ADD_SCHED_TIME, force);

	iscsi_extracheck_is_rd_thread(conn);

again:
	spin_lock_bh(&iscsi_rd_lock);
	spin_lock(&conn->write_list_lock);

	aborted_cmds_pending = false;
	list_for_each_entry(cmnd, &conn->write_timeout_list,
				write_timeout_list_entry) {
		if (test_bit(ISCSI_CMD_ABORTED, &cmnd->prelim_compl_flags)) {
			TRACE_DBG_FLAG(force ? TRACE_CONN_OC_DBG : TRACE_MGMT_DEBUG,
				"Checking aborted cmnd %p (scst_state %d, "
				"on_write_timeout_list %d, write_start %ld, "
				"r2t_len_to_receive %d)", cmnd,
				cmnd->scst_state, cmnd->on_write_timeout_list,
				cmnd->write_start, cmnd->r2t_len_to_receive);
			if ((cmnd->r2t_len_to_receive != 0) &&
			    (time_after_eq(j, cmnd->write_start + ISCSI_TM_DATA_WAIT_TIMEOUT) ||
			     force)) {
				spin_unlock(&conn->write_list_lock);
				spin_unlock_bh(&iscsi_rd_lock);
				iscsi_fail_data_waiting_cmnd(cmnd);
				goto again;
			}
			aborted_cmds_pending = true;
		}
	}

	if (aborted_cmds_pending) {
		if (!force &&
		    (!timer_pending(&conn->rsp_timer) ||
		     time_after(conn->rsp_timer.expires, timeout_time))) {
			TRACE_MGMT_DBG("Mod timer on %ld (conn %p)",
				timeout_time, conn);
			mod_timer(&conn->rsp_timer, timeout_time);
		}
	} else {
		TRACE_MGMT_DBG("Clearing conn_tm_active for conn %p", conn);
		conn->conn_tm_active = 0;
	}

	spin_unlock(&conn->write_list_lock);
	spin_unlock_bh(&iscsi_rd_lock);

	TRACE_EXIT();
	return;
}

/* target_mutex supposed to be locked */
void conn_reinst_finished(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd, *t;

	TRACE_ENTRY();

	clear_bit(ISCSI_CONN_REINSTATING, &conn->conn_aflags);

	list_for_each_entry_safe(cmnd, t, &conn->reinst_pending_cmd_list,
					reinst_pending_cmd_list_entry) {
		TRACE_MGMT_DBG("Restarting reinst pending cmnd %p",
			cmnd);

		list_del(&cmnd->reinst_pending_cmd_list_entry);

		/* Restore the state for preliminary completion/cmnd_done() */
		cmnd->scst_state = ISCSI_CMD_STATE_AFTER_PREPROC;

		iscsi_restart_cmnd(cmnd);
	}

	TRACE_EXIT();
	return;
}

static void conn_activate(struct iscsi_conn *conn)
{
	TRACE_MGMT_DBG("Enabling conn %p", conn);

	/* Catch double bind */
	sBUG_ON(conn->sock->sk->sk_state_change == iscsi_state_change);

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
static int conn_setup_sock(struct iscsi_conn *conn)
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

out:
	return res;
}

/* target_mutex supposed to be locked */
#ifdef CONFIG_SCST_PROC
int conn_free(struct iscsi_conn *conn)
#else
static int conn_free(struct iscsi_conn *conn)
#endif
{
	struct iscsi_session *session = conn->session;

	TRACE_MGMT_DBG("Freeing conn %p (sess=%p, %#Lx %u)", conn,
		session, (long long unsigned int)session->sid, conn->cid);

	del_timer_sync(&conn->rsp_timer);

	sBUG_ON(atomic_read(&conn->conn_ref_cnt) != 0);
	sBUG_ON(!list_empty(&conn->cmd_list));
	sBUG_ON(!list_empty(&conn->write_list));
	sBUG_ON(!list_empty(&conn->write_timeout_list));
	sBUG_ON(conn->conn_reinst_successor != NULL);
	sBUG_ON(!test_bit(ISCSI_CONN_SHUTTINGDOWN, &conn->conn_aflags));

	/* Just in case if new conn gets freed before the old one */
	if (test_bit(ISCSI_CONN_REINSTATING, &conn->conn_aflags)) {
		struct iscsi_conn *c;
		TRACE_MGMT_DBG("Freeing being reinstated conn %p", conn);
		list_for_each_entry(c, &session->conn_list,
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

	if (list_empty(&session->conn_list)) {
		sBUG_ON(session->sess_reinst_successor != NULL);
		session_free(session, true);
	}

	return 0;
}

/* target_mutex supposed to be locked */
static int iscsi_conn_alloc(struct iscsi_session *session,
	struct iscsi_kern_conn_info *info, struct iscsi_conn **new_conn)
{
	struct iscsi_conn *conn;
	int res = 0;
#ifndef CONFIG_SCST_PROC
	struct iscsi_conn *c;
	int n = 1;
	char addr[64];
#endif

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
	if (session->sess_reinstating)
		__set_bit(ISCSI_CONN_REINSTATING, &conn->conn_aflags);
	conn->cid = info->cid;
	conn->stat_sn = info->stat_sn;
	conn->exp_stat_sn = info->exp_stat_sn;
	conn->rd_state = ISCSI_CONN_RD_STATE_IDLE;
	conn->wr_state = ISCSI_CONN_WR_STATE_IDLE;

	conn->hdigest_type = session->sess_params.header_digest;
	conn->ddigest_type = session->sess_params.data_digest;
	res = digest_init(conn);
	if (res != 0)
		goto out_err_free1;

	conn->target = session->target;
	spin_lock_init(&conn->cmd_list_lock);
	INIT_LIST_HEAD(&conn->cmd_list);
	spin_lock_init(&conn->write_list_lock);
	INIT_LIST_HEAD(&conn->write_list);
	INIT_LIST_HEAD(&conn->write_timeout_list);
	setup_timer(&conn->rsp_timer, conn_rsp_timer_fn, (unsigned long)conn);
	init_waitqueue_head(&conn->read_state_waitQ);
	init_completion(&conn->ready_to_free);
	INIT_LIST_HEAD(&conn->reinst_pending_cmd_list);
	INIT_LIST_HEAD(&conn->nop_req_list);
	spin_lock_init(&conn->nop_req_list_lock);

	conn->nop_in_ttt = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
	INIT_DELAYED_WORK(&conn->nop_in_delayed_work,
		(void (*)(struct work_struct *))conn_nop_in_delayed_work_fn);
#else
	INIT_WORK(&conn->nop_in_delayed_work, conn_nop_in_delayed_work_fn,
		conn);
#endif
	conn->last_rcv_time = jiffies;
	conn->rsp_timeout = session->tgt_params.rsp_timeout * HZ;
	conn->nop_in_interval = session->tgt_params.nop_in_interval * HZ;
	if (conn->nop_in_interval > 0) {
		TRACE_DBG("Schedule Nop-In work for conn %p", conn);
		schedule_delayed_work(&conn->nop_in_delayed_work,
			conn->nop_in_interval + ISCSI_ADD_SCHED_TIME);
	}

	conn->file = fget(info->fd);

	res = conn_setup_sock(conn);
	if (res != 0)
		goto out_err_free2;

#ifndef CONFIG_SCST_PROC
	iscsi_get_initiator_ip(conn, addr, sizeof(addr));

restart:
	list_for_each_entry(c, &session->conn_list, conn_list_entry) {
		if (strcmp(addr, kobject_name(&conn->iscsi_conn_kobj)) == 0) {
			char c_addr[64];

			iscsi_get_initiator_ip(conn, c_addr, sizeof(c_addr));

			TRACE_DBG("Duplicated conn from the same initiator "
				"%s found", c_addr);

			snprintf(addr, sizeof(addr), "%s_%d", c_addr, n);
			n++;
			goto restart;
		}
	}

	res = kobject_init_and_add(&conn->iscsi_conn_kobj, &iscsi_conn_ktype,
		scst_sysfs_get_sess_kobj(session->scst_sess), addr);
	if (res != 0) {
		PRINT_ERROR("Unable create sysfs entries for conn %s",
			addr);
		goto out_err_free2;
	}

	TRACE_DBG("conn %p, iscsi_conn_kobj %p", conn, &conn->iscsi_conn_kobj);

	res = sysfs_create_file(&conn->iscsi_conn_kobj,
			&iscsi_conn_state_attr.attr);
	if (res != 0) {
		PRINT_ERROR("Unable create sysfs attribute %s for conn %s",
			iscsi_conn_state_attr.attr.name, addr);
		goto out_err_free3;
	}

	res = sysfs_create_file(&conn->iscsi_conn_kobj,
			&iscsi_conn_cid_attr.attr);
	if (res != 0) {
		PRINT_ERROR("Unable create sysfs attribute %s for conn %s",
			iscsi_conn_cid_attr.attr.name, addr);
		goto out_err_free3;
	}

	res = sysfs_create_file(&conn->iscsi_conn_kobj,
			&iscsi_conn_ip_attr.attr);
	if (res != 0) {
		PRINT_ERROR("Unable create sysfs attribute %s for conn %s",
			iscsi_conn_ip_attr.attr.name, addr);
		goto out_err_free3;
	}
#endif /* CONFIG_SCST_PROC */

	list_add_tail(&conn->conn_list_entry, &session->conn_list);

	*new_conn = conn;

out:
	return res;

#ifndef CONFIG_SCST_PROC
out_err_free3:
	kobject_put(&conn->iscsi_conn_kobj);
	goto out;
#endif

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
int __add_conn(struct iscsi_session *session, struct iscsi_kern_conn_info *info)
{
	struct iscsi_conn *conn, *new_conn = NULL;
	int err;
	bool reinstatement = false;

	conn = conn_lookup(session, info->cid);
	if ((conn != NULL) &&
	    !test_bit(ISCSI_CONN_SHUTTINGDOWN, &conn->conn_aflags)) {
		/* conn reinstatement */
		reinstatement = true;
	} else if (!list_empty(&session->conn_list)) {
		err = -EEXIST;
		goto out;
	}

	err = iscsi_conn_alloc(session, info, &new_conn);
	if (err != 0)
		goto out;

	if (reinstatement) {
		TRACE_MGMT_DBG("Reinstating conn (old %p, new %p)", conn,
			new_conn);
		conn->conn_reinst_successor = new_conn;
		__set_bit(ISCSI_CONN_REINSTATING, &new_conn->conn_aflags);
		__mark_conn_closed(conn, 0);
	}

	conn_activate(new_conn);

out:
	return err;
}

/* target_mutex supposed to be locked */
int __del_conn(struct iscsi_session *session, struct iscsi_kern_conn_info *info)
{
	struct iscsi_conn *conn;
	int err = -EEXIST;

	conn = conn_lookup(session, info->cid);
	if (!conn) {
		PRINT_ERROR("Connection %d not found", info->cid);
		return err;
	}

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
