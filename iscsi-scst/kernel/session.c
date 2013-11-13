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

#include "iscsi.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
#include <linux/export.h>
#endif

/* target_mutex supposed to be locked */
struct iscsi_session *session_lookup(struct iscsi_target *target, u64 sid)
{
	struct iscsi_session *session;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target->target_mutex);
#endif

	list_for_each_entry(session, &target->session_list,
			session_list_entry) {
		if (session->sid == sid)
			return session;
	}
	return NULL;
}

/* target_mgmt_mutex supposed to be locked */
static int iscsi_session_alloc(struct iscsi_target *target,
	struct iscsi_kern_session_info *info, struct iscsi_session **result)
{
	int err;
	unsigned int i;
	struct iscsi_session *session;
	char *name = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

	session = kmem_cache_zalloc(iscsi_sess_cache, GFP_KERNEL);
	if (!session)
		return -ENOMEM;

	session->target = target;
	session->sid = info->sid;
	atomic_set(&session->active_cmds, 0);
	session->exp_cmd_sn = info->exp_cmd_sn;

	session->initiator_name = kstrdup(info->initiator_name, GFP_KERNEL);
	if (!session->initiator_name) {
		err = -ENOMEM;
		goto err;
	}

#ifdef CONFIG_SCST_PROC
	name = kmalloc(strlen(info->user_name) + strlen(info->initiator_name) +
			1, GFP_KERNEL);
	if (name == NULL) {
		err = -ENOMEM;
		goto err;
	}

	if (info->user_name[0] != '\0')
		sprintf(name, "%s@%s", info->user_name, info->initiator_name);
	else
		sprintf(name, "%s", info->initiator_name);
#else
	name = info->full_initiator_name;
#endif

	INIT_LIST_HEAD(&session->conn_list);
	INIT_LIST_HEAD(&session->pending_list);

	spin_lock_init(&session->sn_lock);

	spin_lock_init(&session->cmnd_data_wait_hash_lock);
	for (i = 0; i < ARRAY_SIZE(session->cmnd_data_wait_hash); i++)
		INIT_LIST_HEAD(&session->cmnd_data_wait_hash[i]);

	session->next_ttt = 1;

	session->scst_sess = scst_register_session(target->scst_tgt, 0,
		name, session, NULL, NULL);
	if (session->scst_sess == NULL) {
		PRINT_ERROR("%s", "scst_register_session() failed");
		err = -ENOMEM;
		goto err;
	}

	err = iscsi_threads_pool_get(&session->scst_sess->acg->acg_cpu_mask,
		&session->sess_thr_pool);
	if (err != 0)
		goto err_unreg;

#ifdef CONFIG_SCST_PROC
	kfree(name);
#endif

	TRACE_MGMT_DBG("Session %p created: target %p, tid %u, sid %#Lx",
		session, target, target->tid, info->sid);

	*result = session;
	return 0;

err_unreg:
	scst_unregister_session(session->scst_sess, 1, NULL);

err:
	if (session) {
		kfree(session->initiator_name);
		kmem_cache_free(iscsi_sess_cache, session);
#ifdef CONFIG_SCST_PROC
		kfree(name);
#endif
	}
	return err;
}

/* target_mutex supposed to be locked */
void sess_reinst_finished(struct iscsi_session *sess)
{
	struct iscsi_conn *c;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Enabling reinstate successor sess %p", sess);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&sess->target->target_mutex);
#endif

	sBUG_ON(!sess->sess_reinstating);

	list_for_each_entry(c, &sess->conn_list, conn_list_entry) {
		conn_reinst_finished(c);
	}
	sess->sess_reinstating = 0;

	TRACE_EXIT();
	return;
}

/* target_mgmt_mutex supposed to be locked */
int __add_session(struct iscsi_target *target,
	struct iscsi_kern_session_info *info)
{
	struct iscsi_session *new_sess = NULL, *sess, *old_sess;
	int err = 0, i;
	union iscsi_sid sid;
	bool reinstatement = false;
	struct iscsi_kern_params_info *params_info;

	TRACE_MGMT_DBG("Adding session SID %llx", info->sid);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

	err = iscsi_session_alloc(target, info, &new_sess);
	if (err != 0)
		goto out;

	mutex_lock(&target->target_mutex);

	sess = session_lookup(target, info->sid);
	if (sess != NULL) {
		PRINT_ERROR("Attempt to add session with existing SID %llx",
			info->sid);
		err = -EEXIST;
		goto out_err_unlock;
	}

	params_info = kmalloc(sizeof(*params_info), GFP_KERNEL);
	if (params_info == NULL) {
		PRINT_ERROR("Unable to allocate params info (size %zd)",
			sizeof(*params_info));
		err = -ENOMEM;
		goto out_err_unlock;
	}

	sid = *(union iscsi_sid *)&info->sid;
	sid.id.tsih = 0;
	old_sess = NULL;

	/*
	 * We need to find the latest session to correctly handle
	 * multi-reinstatements
	 */
	list_for_each_entry_reverse(sess, &target->session_list,
			session_list_entry) {
		union iscsi_sid s = *(union iscsi_sid *)&sess->sid;
		s.id.tsih = 0;
		if ((sid.id64 == s.id64) &&
		    (strcmp(info->initiator_name, sess->initiator_name) == 0)) {
			if (!sess->sess_shutting_down) {
				/* session reinstatement */
				old_sess = sess;
			}
			break;
		}
	}
	sess = NULL;

	list_add_tail(&new_sess->session_list_entry, &target->session_list);

	memset(params_info, 0, sizeof(*params_info));
	params_info->tid = target->tid;
	params_info->sid = info->sid;
	params_info->params_type = key_session;
	for (i = 0; i < session_key_last; i++)
		params_info->session_params[i] = info->session_params[i];

	err = iscsi_params_set(target, params_info, 1);
	if (err != 0)
		goto out_del;

	memset(params_info, 0, sizeof(*params_info));
	params_info->tid = target->tid;
	params_info->sid = info->sid;
	params_info->params_type = key_target;
	for (i = 0; i < target_key_last; i++)
		params_info->target_params[i] = info->target_params[i];

	err = iscsi_params_set(target, params_info, 1);
	if (err != 0)
		goto out_del;

	kfree(params_info);
	params_info = NULL;

	if (old_sess != NULL) {
		reinstatement = true;

		TRACE_MGMT_DBG("Reinstating sess %p with SID %llx (old %p, "
			"SID %llx)", new_sess, new_sess->sid, old_sess,
			old_sess->sid);

		new_sess->sess_reinstating = 1;
		old_sess->sess_reinst_successor = new_sess;

		target_del_session(old_sess->target, old_sess, 0);
	}

	mutex_unlock(&target->target_mutex);

	if (reinstatement) {
		/*
		 * Mutex target_mgmt_mutex won't allow to add connections to
		 * the new session after target_mutex was dropped, so it's safe
		 * to replace the initial UA without it. We can't do it under
		 * target_mutex, because otherwise we can establish a
		 * circular locking dependency between target_mutex and
		 * scst_mutex in SCST core (iscsi_report_aen() called by
		 * SCST core under scst_mutex).
		 */
		scst_set_initial_UA(new_sess->scst_sess,
			SCST_LOAD_SENSE(scst_sense_nexus_loss_UA));
	}

out:
	return err;

out_del:
	list_del(&new_sess->session_list_entry);
	kfree(params_info);

out_err_unlock:
	mutex_unlock(&target->target_mutex);

	scst_unregister_session(new_sess->scst_sess, 1, NULL);
	new_sess->scst_sess = NULL;

	mutex_lock(&target->target_mutex);
	session_free(new_sess, false);
	mutex_unlock(&target->target_mutex);
	goto out;
}

static void __session_free(struct iscsi_session *session)
{
	kfree(session->initiator_name);
	kmem_cache_free(iscsi_sess_cache, session);
}

static void iscsi_unreg_sess_done(struct scst_session *scst_sess)
{
	struct iscsi_session *session;

	TRACE_ENTRY();

	session = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);

	session->scst_sess = NULL;
	__session_free(session);

	TRACE_EXIT();
	return;
}

/* target_mutex supposed to be locked */
int session_free(struct iscsi_session *session, bool del)
{
	unsigned int i;

	TRACE_MGMT_DBG("Freeing session %p (SID %llx)",
		session, session->sid);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&session->target->target_mutex);
#endif

	sBUG_ON(!list_empty(&session->conn_list));
	if (unlikely(atomic_read(&session->active_cmds) != 0)) {
		PRINT_CRIT_ERROR("active_cmds not 0 (%d)!!",
			atomic_read(&session->active_cmds));
		sBUG();
	}

	for (i = 0; i < ARRAY_SIZE(session->cmnd_data_wait_hash); i++)
		sBUG_ON(!list_empty(&session->cmnd_data_wait_hash[i]));

	if (session->sess_reinst_successor != NULL)
		sess_reinst_finished(session->sess_reinst_successor);

	if (session->sess_reinstating) {
		struct iscsi_session *s;
		TRACE_MGMT_DBG("Freeing being reinstated sess %p", session);
		list_for_each_entry(s, &session->target->session_list,
						session_list_entry) {
			if (s->sess_reinst_successor == session) {
				s->sess_reinst_successor = NULL;
				break;
			}
		}
	}

	if (del)
		list_del(&session->session_list_entry);

	if (session->sess_thr_pool != NULL) {
		iscsi_threads_pool_put(session->sess_thr_pool);
		session->sess_thr_pool = NULL;
	}

	if (session->scst_sess != NULL) {
		/*
		 * We must NOT call scst_unregister_session() in the waiting
		 * mode, since we are under target_mutex. Otherwise we can
		 * establish a circular locking dependency between target_mutex
		 * and scst_mutex in SCST core (iscsi_report_aen() called by
		 * SCST core under scst_mutex).
		 */
		scst_unregister_session(session->scst_sess, 0,
			iscsi_unreg_sess_done);
	} else
		__session_free(session);

	return 0;
}

/* target_mutex supposed to be locked */
int __del_session(struct iscsi_target *target, u64 sid)
{
	struct iscsi_session *session;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target->target_mutex);
#endif

	session = session_lookup(target, sid);
	if (!session)
		return -ENOENT;

	if (!list_empty(&session->conn_list)) {
		PRINT_ERROR("%llx still have connections",
			    (long long unsigned int)session->sid);
		return -EBUSY;
	}

	return session_free(session, true);
}

/* Must be called under target_mutex */
void iscsi_sess_force_close(struct iscsi_session *sess)
{
	struct iscsi_conn *conn;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&sess->target->target_mutex);
#endif

	PRINT_INFO("Deleting session %llx with initiator %s (%p)",
		(long long unsigned int)sess->sid, sess->initiator_name, sess);

	list_for_each_entry(conn, &sess->conn_list, conn_list_entry) {
		TRACE_MGMT_DBG("Deleting connection with initiator %p", conn);
		__mark_conn_closed(conn, ISCSI_CONN_ACTIVE_CLOSE|ISCSI_CONN_DELETING);
	}

	TRACE_EXIT();
	return;
}

#ifdef CONFIG_SCST_PROC

/* target_mutex supposed to be locked */
static void iscsi_session_info_show(struct seq_file *seq,
				    struct iscsi_target *target)
{
	struct iscsi_session *session;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target->target_mutex);
#endif

	list_for_each_entry(session, &target->session_list,
			    session_list_entry) {
		seq_printf(seq, "\tsid:%llx initiator:%s (reinstating %s)\n",
			(long long unsigned int)session->sid,
			session->initiator_name,
			session->sess_reinstating ? "yes" : "no");
		conn_info_show(seq, session);
	}
	return;
}

static int iscsi_session_seq_open(struct inode *inode, struct file *file)
{
	int res;
	res = seq_open(file, &iscsi_seq_op);
	if (!res)
		((struct seq_file *)file->private_data)->private =
			iscsi_session_info_show;
	return res;
}

const struct file_operations session_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= iscsi_session_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

#else /* CONFIG_SCST_PROC */

#define ISCSI_SESS_BOOL_PARAM_ATTR(name, exported_name)				\
static ssize_t iscsi_sess_show_##name(struct kobject *kobj,			\
	struct kobj_attribute *attr, char *buf)					\
{										\
	int pos;								\
	struct scst_session *scst_sess;						\
	struct iscsi_session *sess;						\
										\
	scst_sess = container_of(kobj, struct scst_session, sess_kobj);		\
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);	\
										\
	pos = sprintf(buf, "%s\n",						\
		iscsi_get_bool_value(sess->sess_params.name));			\
										\
	return pos;								\
}										\
										\
static struct kobj_attribute iscsi_sess_attr_##name =				\
	__ATTR(exported_name, S_IRUGO, iscsi_sess_show_##name, NULL);

#define ISCSI_SESS_INT_PARAM_ATTR(name, exported_name)				\
static ssize_t iscsi_sess_show_##name(struct kobject *kobj,			\
	struct kobj_attribute *attr, char *buf)					\
{										\
	int pos;								\
	struct scst_session *scst_sess;						\
	struct iscsi_session *sess;						\
										\
	scst_sess = container_of(kobj, struct scst_session, sess_kobj);		\
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);	\
										\
	pos = sprintf(buf, "%d\n", sess->sess_params.name);			\
										\
	return pos;								\
}										\
										\
static struct kobj_attribute iscsi_sess_attr_##name =				\
	__ATTR(exported_name, S_IRUGO, iscsi_sess_show_##name, NULL);

#define ISCSI_SESS_DIGEST_PARAM_ATTR(name, exported_name)			\
static ssize_t iscsi_sess_show_##name(struct kobject *kobj,			\
	struct kobj_attribute *attr, char *buf)					\
{										\
	int pos;								\
	struct scst_session *scst_sess;						\
	struct iscsi_session *sess;						\
	char digest_name[64];							\
										\
	scst_sess = container_of(kobj, struct scst_session, sess_kobj);		\
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);	\
										\
	pos = sprintf(buf, "%s\n", iscsi_get_digest_name(			\
			sess->sess_params.name, digest_name));			\
										\
	return pos;								\
}										\
										\
static struct kobj_attribute iscsi_sess_attr_##name =				\
	__ATTR(exported_name, S_IRUGO, iscsi_sess_show_##name, NULL);

ISCSI_SESS_BOOL_PARAM_ATTR(initial_r2t, InitialR2T);
ISCSI_SESS_BOOL_PARAM_ATTR(immediate_data, ImmediateData);
ISCSI_SESS_INT_PARAM_ATTR(max_recv_data_length, MaxRecvDataSegmentLength);
ISCSI_SESS_INT_PARAM_ATTR(max_xmit_data_length, MaxXmitDataSegmentLength);
ISCSI_SESS_INT_PARAM_ATTR(max_burst_length, MaxBurstLength);
ISCSI_SESS_INT_PARAM_ATTR(first_burst_length, FirstBurstLength);
ISCSI_SESS_INT_PARAM_ATTR(max_outstanding_r2t, MaxOutstandingR2T);
ISCSI_SESS_DIGEST_PARAM_ATTR(header_digest, HeaderDigest);
ISCSI_SESS_DIGEST_PARAM_ATTR(data_digest, DataDigest);

static ssize_t iscsi_sess_sid_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct scst_session *scst_sess;
	struct iscsi_session *sess;

	TRACE_ENTRY();

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);

	pos = sprintf(buf, "%llx\n", sess->sid);

	TRACE_EXIT_RES(pos);
	return pos;
}

static struct kobj_attribute iscsi_attr_sess_sid =
	__ATTR(sid, S_IRUGO, iscsi_sess_sid_show, NULL);

static ssize_t iscsi_sess_reinstating_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct scst_session *scst_sess;
	struct iscsi_session *sess;

	TRACE_ENTRY();

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);

	pos = sprintf(buf, "%d\n", sess->sess_reinstating ? 1 : 0);

	TRACE_EXIT_RES(pos);
	return pos;
}

static struct kobj_attribute iscsi_sess_attr_reinstating =
	__ATTR(reinstating, S_IRUGO, iscsi_sess_reinstating_show, NULL);

const struct attribute *iscsi_sess_attrs[] = {
	&iscsi_sess_attr_initial_r2t.attr,
	&iscsi_sess_attr_immediate_data.attr,
	&iscsi_sess_attr_max_recv_data_length.attr,
	&iscsi_sess_attr_max_xmit_data_length.attr,
	&iscsi_sess_attr_max_burst_length.attr,
	&iscsi_sess_attr_first_burst_length.attr,
	&iscsi_sess_attr_max_outstanding_r2t.attr,
	&iscsi_sess_attr_header_digest.attr,
	&iscsi_sess_attr_data_digest.attr,
	&iscsi_attr_sess_sid.attr,
	&iscsi_sess_attr_reinstating.attr,
	NULL,
};

#endif /* CONFIG_SCST_PROC */
