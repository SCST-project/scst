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

#include "iscsi.h"

/* target_mutex supposed to be locked */
struct iscsi_session *session_lookup(struct iscsi_target *target, u64 sid)
{
	struct iscsi_session *session;

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

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;

	session->target = target;
	session->sid = info->sid;
	session->sess_param = target->trgt_sess_param;
	session->max_queued_cmnds = target->trgt_param.queued_cmnds;
	atomic_set(&session->active_cmds, 0);

	session->exp_cmd_sn = info->exp_cmd_sn;

	session->initiator_name = kstrdup(info->initiator_name, GFP_KERNEL);
	if (!session->initiator_name) {
		err = -ENOMEM;
		goto err;
	}

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

	INIT_LIST_HEAD(&session->conn_list);
	INIT_LIST_HEAD(&session->pending_list);

	spin_lock_init(&session->sn_lock);

	spin_lock_init(&session->cmnd_hash_lock);
	for (i = 0; i < ARRAY_SIZE(session->cmnd_hash); i++)
		INIT_LIST_HEAD(&session->cmnd_hash[i]);

	session->next_ttt = 1;

	session->scst_sess = scst_register_session(target->scst_tgt, 0,
		name, NULL, NULL);
	if (session->scst_sess == NULL) {
		PRINT_ERROR("%s", "scst_register_session() failed");
		err = -ENOMEM;
		goto err;
	}

	kfree(name);

	scst_sess_set_tgt_priv(session->scst_sess, session);

	TRACE_MGMT_DBG("Session %p created: target %p, tid %u, sid %#Lx",
		session, target, target->tid, info->sid);

	*result = session;
	return 0;

err:
	if (session) {
		kfree(session->initiator_name);
		kfree(session);
		kfree(name);
	}
	return err;
}

/* target_mutex supposed to be locked */
void sess_enable_reinstated_sess(struct iscsi_session *sess)
{
	struct iscsi_conn *c;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Enabling reinstate successor sess %p", sess);

	sBUG_ON(!sess->sess_reinstating);

	list_for_each_entry(c, &sess->conn_list, conn_list_entry) {
		__iscsi_socket_bind(c);
	}
	sess->sess_reinstating = 0;

	TRACE_EXIT();
	return;
}

/* target_mutex supposed to be locked */
static void session_reinstate(struct iscsi_session *old_sess,
	struct iscsi_session *new_sess)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("Reinstating sess %p with SID %llx (old %p, SID %llx)",
		new_sess, new_sess->sid, old_sess, old_sess->sid);

	new_sess->sess_reinstating = 1;
	old_sess->sess_reinst_successor = new_sess;

	scst_set_initial_UA(new_sess->scst_sess,
		SCST_LOAD_SENSE(scst_sense_nexus_loss_UA));

	target_del_session(old_sess->target, old_sess, 0);

	TRACE_EXIT();
	return;
}

/* target_mgmt_mutex supposed to be locked */
int session_add(struct iscsi_target *target,
	struct iscsi_kern_session_info *info)
{
	struct iscsi_session *new_sess, *session, *old_sess;
	int err = 0;
	union iscsi_sid sid;

	TRACE_MGMT_DBG("Adding session SID %llx", info->sid);

	err = iscsi_session_alloc(target, info, &new_sess);
	if (err != 0)
		goto out;

	mutex_lock(&target->target_mutex);

	session = session_lookup(target, info->sid);
	if (session) {
		PRINT_ERROR("Attempt to add session with existing SID %llx",
			info->sid);
		err = -EEXIST;
		goto out_err_unlock;
	}

	sid = *(union iscsi_sid *)&info->sid;
	sid.id.tsih = 0;
	old_sess = NULL;

	/*
	 * We need to find the latest session to correctly handle
	 * multi-reinstatements
	 */
	list_for_each_entry_reverse(session, &target->session_list,
			session_list_entry) {
		union iscsi_sid i = *(union iscsi_sid *)&session->sid;
		i.id.tsih = 0;
		if ((sid.id64 == i.id64) &&
		    (strcmp(info->initiator_name, session->initiator_name) == 0)) {
			if (!session->sess_shutting_down) {
				/* session reinstatement */
				old_sess = session;
			}
			break;
		}
	}

	session = new_sess;
	list_add_tail(&session->session_list_entry, &target->session_list);

	if (old_sess != NULL)
		session_reinstate(old_sess, session);

out_unlock:
	mutex_unlock(&target->target_mutex);

out:
	return err;

out_err_unlock:
	new_sess->deleted_from_session_list = 1;
	session_free(new_sess);
	goto out_unlock;
}

/* target_mutex supposed to be locked */
int session_free(struct iscsi_session *session)
{
	unsigned int i;

	TRACE_MGMT_DBG("Freeing session %p (SID %llx)",
		session, session->sid);

	sBUG_ON(!list_empty(&session->conn_list));
	if (unlikely(atomic_read(&session->active_cmds) != 0)) {
		PRINT_CRIT_ERROR("active_cmds not 0 (%d)!!",
			atomic_read(&session->active_cmds));
		sBUG();
	}

	for (i = 0; i < ARRAY_SIZE(session->cmnd_hash); i++)
		sBUG_ON(!list_empty(&session->cmnd_hash[i]));

	sBUG_ON(session->scst_sess != NULL);

	if (session->sess_reinst_successor != NULL)
		sess_enable_reinstated_sess(session->sess_reinst_successor);

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

	if (!session->deleted_from_session_list)
		list_del(&session->session_list_entry);

	kfree(session->initiator_name);
	kfree(session);

	return 0;
}

/* target_mutex supposed to be locked */
int session_del(struct iscsi_target *target, u64 sid)
{
	struct iscsi_session *session;

	session = session_lookup(target, sid);
	if (!session)
		return -ENOENT;

	if (!list_empty(&session->conn_list)) {
		PRINT_ERROR("%llu still have connections",
			    (long long unsigned int)session->sid);
		return -EBUSY;
	}

	return session_free(session);
}

/* target_mutex supposed to be locked */
static void iscsi_session_info_show(struct seq_file *seq,
				    struct iscsi_target *target)
{
	struct iscsi_session *session;

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
