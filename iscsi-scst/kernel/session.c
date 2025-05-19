/*
 *  Copyright (C) 2002 - 2003 Ardis Technologies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2018 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
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

#ifndef INSIDE_KERNEL_TREE
#include <linux/version.h>
#endif
#include <linux/export.h>

#include "iscsi_trace_flag.h"
#include "iscsi.h"

/* target_mutex supposed to be locked */
struct iscsi_session *session_lookup(struct iscsi_target *target, u64 sid)
{
	struct iscsi_session *session;

	lockdep_assert_held(&target->target_mutex);

	list_for_each_entry(session, &target->session_list, session_list_entry) {
		if (session->sid == sid)
			return session;
	}
	return NULL;
}

/* target_mgmt_mutex supposed to be locked */
static int iscsi_session_alloc(struct iscsi_target *target, struct iscsi_kern_session_info *info,
			       struct iscsi_session **result)
{
	int err;
	unsigned int i;
	struct iscsi_session *session;
	char *name = NULL;

	lockdep_assert_held(&target_mgmt_mutex);

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

	name = info->full_initiator_name;

	INIT_LIST_HEAD(&session->conn_list);
	INIT_LIST_HEAD(&session->pending_list);

	spin_lock_init(&session->sn_lock);

	spin_lock_init(&session->cmnd_data_wait_hash_lock);
	for (i = 0; i < ARRAY_SIZE(session->cmnd_data_wait_hash); i++)
		INIT_LIST_HEAD(&session->cmnd_data_wait_hash[i]);

	session->next_ttt = 1;

	session->scst_sess = scst_register_session(target->scst_tgt, 0, name, session, NULL, NULL);
	if (!session->scst_sess) {
		PRINT_ERROR("%s", "scst_register_session() failed");
		err = -ENOMEM;
		goto err;
	}

	if (!session->sess_params.rdma_extensions) {
		err = iscsi_threads_pool_get((bool)scst_get_acg_tgt_priv(session->scst_sess->acg),
					     &session->scst_sess->acg->acg_cpu_mask,
					     &session->sess_thr_pool);
		if (err != 0)
			goto err_unreg;
	}

	TRACE(TRACE_MGMT, "Session %p created: target %p, tid %u, sid %#Lx, initiator %s",
	      session, target, target->tid, info->sid,
	      session->scst_sess->initiator_name);

	*result = session;
	return 0;

err_unreg:
	scst_unregister_session(session->scst_sess, 1, NULL);

err:
	if (session) {
		kfree(session->initiator_name);
		kmem_cache_free(iscsi_sess_cache, session);
	}
	return err;
}

/* target_mutex supposed to be locked */
void sess_reinst_finished(struct iscsi_session *sess)
{
	struct iscsi_conn *c;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Enabling reinstate successor sess %p", sess);

	lockdep_assert_held(&sess->target->target_mutex);

	sBUG_ON(!sess->sess_reinstating);

	list_for_each_entry(c, &sess->conn_list, conn_list_entry) {
		conn_reinst_finished(c);
	}
	sess->sess_reinstating = 0;

	TRACE_EXIT();
}

/* target_mgmt_mutex supposed to be locked */
int __add_session(struct iscsi_target *target, struct iscsi_kern_session_info *info)
{
	struct iscsi_session *new_sess = NULL, *sess, *old_sess;
	int err = 0, i;
	union iscsi_sid sid;
	bool reinstatement = false;
	struct iscsi_kern_params_info *params_info;

	TRACE_MGMT_DBG("Adding session SID %llx", info->sid);

	lockdep_assert_held(&target_mgmt_mutex);

	err = iscsi_session_alloc(target, info, &new_sess);
	if (err != 0)
		goto out;

	mutex_lock(&target->target_mutex);

	sess = session_lookup(target, info->sid);
	if (sess) {
		PRINT_ERROR("Attempt to add session with existing SID %llx",
			    info->sid);
		err = -EEXIST;
		goto out_err_unlock;
	}

	params_info = kmalloc(sizeof(*params_info), GFP_KERNEL);
	if (!params_info) {
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
	list_for_each_entry_reverse(sess, &target->session_list, session_list_entry) {
		union iscsi_sid s = *(union iscsi_sid *)&sess->sid;

		s.id.tsih = 0;
		if (sid.id64 == s.id64 &&
		    strcmp(info->initiator_name, sess->initiator_name) == 0) {
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

	if (old_sess) {
		reinstatement = true;

		TRACE_MGMT_DBG("Reinstating sess %p with SID %llx (old %p, SID %llx)",
			       new_sess, new_sess->sid, old_sess, old_sess->sid);

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
	if (session->sess_thr_pool)
		iscsi_threads_pool_put(session->sess_thr_pool);
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
}

/* target_mutex supposed to be locked */
int session_free(struct iscsi_session *session, bool del)
{
	unsigned int i;

	TRACE(TRACE_MGMT, "Freeing session %p (SID %llx)",
	      session, session->sid);

	lockdep_assert_held(&session->target->target_mutex);

	sBUG_ON(!list_empty(&session->conn_list));
	if (unlikely(atomic_read(&session->active_cmds) != 0)) {
		PRINT_CRIT_ERROR("active_cmds not 0 (%d)!!",
				 atomic_read(&session->active_cmds));
		sBUG();
	}

	for (i = 0; i < ARRAY_SIZE(session->cmnd_data_wait_hash); i++)
		sBUG_ON(!list_empty(&session->cmnd_data_wait_hash[i]));

	if (session->sess_reinst_successor)
		sess_reinst_finished(session->sess_reinst_successor);

	if (session->sess_reinstating) {
		struct iscsi_session *s;

		TRACE_MGMT_DBG("Freeing being reinstated sess %p", session);
		list_for_each_entry(s, &session->target->session_list, session_list_entry) {
			if (s->sess_reinst_successor == session) {
				s->sess_reinst_successor = NULL;
				break;
			}
		}
	}

	if (del)
		list_del(&session->session_list_entry);

	if (session->scst_sess) {
		/*
		 * We must NOT call scst_unregister_session() in the waiting
		 * mode, since we are under target_mutex. Otherwise we can
		 * establish a circular locking dependency between target_mutex
		 * and scst_mutex in SCST core (iscsi_report_aen() called by
		 * SCST core under scst_mutex).
		 */
		scst_unregister_session(session->scst_sess, 0, iscsi_unreg_sess_done);
	} else {
		__session_free(session);
	}

	return 0;
}

/* target_mutex supposed to be locked */
int __del_session(struct iscsi_target *target, u64 sid)
{
	struct iscsi_session *session;

	lockdep_assert_held(&target->target_mutex);

	session = session_lookup(target, sid);
	if (!session)
		return -ENOENT;

	if (!list_empty(&session->conn_list)) {
		PRINT_ERROR("%llx still have connections",
			    (unsigned long long)session->sid);
		return -EBUSY;
	}

	return session_free(session, true);
}

/* Must be called under target_mutex */
void iscsi_sess_force_close(struct iscsi_session *sess)
{
	struct iscsi_conn *conn;

	TRACE_ENTRY();

	lockdep_assert_held(&sess->target->target_mutex);

	PRINT_INFO("Force closing session %llx with initiator %s (%p)",
		   (unsigned long long)sess->sid, sess->initiator_name, sess);

	list_for_each_entry(conn, &sess->conn_list, conn_list_entry) {
		TRACE(TRACE_MGMT, "Force closing connection %p", conn);
		__mark_conn_closed(conn,
				   ISCSI_CONN_ACTIVE_CLOSE | ISCSI_CONN_DELETING);
	}

	TRACE_EXIT();
}

#define ISCSI_SESS_BOOL_PARAM_ATTR(name, exported_name)				\
static ssize_t iscsi_sess_show_##name(struct kobject *kobj,			\
				      struct kobj_attribute *attr, char *buf)	\
{										\
	struct scst_session *scst_sess;						\
	struct iscsi_session *sess;						\
										\
	scst_sess = container_of(kobj, struct scst_session, sess_kobj);		\
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);	\
										\
	return sysfs_emit(buf, "%s\n",						\
			  iscsi_get_bool_value(sess->sess_params.name));	\
}										\
										\
static struct kobj_attribute iscsi_sess_attr_##name =				\
	__ATTR(exported_name, 0444, iscsi_sess_show_##name, NULL)

#define ISCSI_SESS_INT_PARAM_ATTR(name, exported_name)				\
static ssize_t iscsi_sess_show_##name(struct kobject *kobj,			\
				      struct kobj_attribute *attr, char *buf)	\
{										\
	struct scst_session *scst_sess;						\
	struct iscsi_session *sess;						\
										\
	scst_sess = container_of(kobj, struct scst_session, sess_kobj);		\
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);	\
										\
	return sysfs_emit(buf, "%d\n",						\
			  sess->sess_params.name);				\
}										\
										\
static struct kobj_attribute iscsi_sess_attr_##name =				\
	__ATTR(exported_name, 0444, iscsi_sess_show_##name, NULL)

#define ISCSI_SESS_DIGEST_PARAM_ATTR(name, exported_name)				\
static ssize_t iscsi_sess_show_##name(struct kobject *kobj,				\
				      struct kobj_attribute *attr, char *buf)		\
{											\
	struct scst_session *scst_sess;							\
	struct iscsi_session *sess;							\
	char digest_name[64];								\
											\
	scst_sess = container_of(kobj, struct scst_session, sess_kobj);			\
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);		\
											\
	return sysfs_emit(buf, "%s\n",							\
			  iscsi_get_digest_name(sess->sess_params.name, digest_name));	\
}											\
											\
static struct kobj_attribute iscsi_sess_attr_##name =					\
	__ATTR(exported_name, 0444, iscsi_sess_show_##name, NULL)

ISCSI_SESS_BOOL_PARAM_ATTR(initial_r2t, InitialR2T);
ISCSI_SESS_BOOL_PARAM_ATTR(immediate_data, ImmediateData);
ISCSI_SESS_INT_PARAM_ATTR(max_recv_data_length, MaxRecvDataSegmentLength);
ISCSI_SESS_INT_PARAM_ATTR(max_xmit_data_length, MaxXmitDataSegmentLength);
ISCSI_SESS_INT_PARAM_ATTR(max_burst_length, MaxBurstLength);
ISCSI_SESS_INT_PARAM_ATTR(first_burst_length, FirstBurstLength);
ISCSI_SESS_INT_PARAM_ATTR(max_outstanding_r2t, MaxOutstandingR2T);
ISCSI_SESS_DIGEST_PARAM_ATTR(header_digest, HeaderDigest);
ISCSI_SESS_DIGEST_PARAM_ATTR(data_digest, DataDigest);

static ssize_t iscsi_sess_sid_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_session *scst_sess;
	struct iscsi_session *sess;
	ssize_t ret;

	TRACE_ENTRY();

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);

	ret = sysfs_emit(buf, "%llx\n", sess->sid);

	TRACE_EXIT_RES(ret);
	return ret;
}

static struct kobj_attribute iscsi_attr_sess_sid =
	__ATTR(sid, 0444, iscsi_sess_sid_show, NULL);

static ssize_t iscsi_sess_reinstating_show(struct kobject *kobj, struct kobj_attribute *attr,
					   char *buf)
{
	struct scst_session *scst_sess;
	struct iscsi_session *sess;
	ssize_t ret;

	TRACE_ENTRY();

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = (struct iscsi_session *)scst_sess_get_tgt_priv(scst_sess);

	ret = sysfs_emit(buf, "%d\n", sess->sess_reinstating ? 1 : 0);

	TRACE_EXIT_RES(ret);
	return ret;
}

static struct kobj_attribute iscsi_sess_attr_reinstating =
	__ATTR(reinstating, 0444, iscsi_sess_reinstating_show, NULL);

static ssize_t iscsi_sess_thread_pid_show(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buf)
{
	struct scst_session *scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	struct iscsi_session *sess = scst_sess_get_tgt_priv(scst_sess);
	struct iscsi_thread_pool *thr_pool = sess->sess_thr_pool;
	struct iscsi_thread *t;
	ssize_t res = -ENOENT;

	if (!thr_pool)
		goto out;

	res = 0;

	mutex_lock(&thr_pool->tp_mutex);
	list_for_each_entry(t, &thr_pool->threads_list, threads_list_entry)
		res += sysfs_emit_at(buf, res, "%d%s",
				     task_pid_vnr(t->thr),
				     list_is_last(&t->threads_list_entry,
						  &thr_pool->threads_list) ?
				     "\n" : " ");
	mutex_unlock(&thr_pool->tp_mutex);

out:
	return res;
}

static struct kobj_attribute iscsi_sess_thread_pid =
	__ATTR(thread_pid, 0444, iscsi_sess_thread_pid_show, NULL);

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
	&iscsi_sess_thread_pid.attr,
	NULL,
};
