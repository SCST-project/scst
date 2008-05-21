/*
 *  Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 Vladislav Bolkhovitin
 *  Copyright (C) 2007 CMS Distribution Limited
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

	list_for_each_entry(session, &target->session_list, session_list_entry) {
		if ((session->sid == sid) && !session->shutting_down)
			return session;
	}
	return NULL;
}

/* target_mutex supposed to be locked */
static int iscsi_session_alloc(struct iscsi_target *target, struct session_info *info)
{
	int err, i;
	struct iscsi_session *session;
	char *name = NULL;

	if (!(session = kzalloc(sizeof(*session), GFP_KERNEL)))
		return -ENOMEM;

	session->target = target;
	session->sid = info->sid;
	BUILD_BUG_ON(sizeof(session->sess_param) !=
		sizeof(target->trgt_sess_param));
	memcpy(&session->sess_param, &target->trgt_sess_param,
		sizeof(session->sess_param));
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
	init_completion(&session->unreg_compl);

	list_add(&session->session_list_entry, &target->session_list);

	TRACE_MGMT_DBG("Session %p created: target %p, tid %u, sid %#Lx",
		session, target, target->tid, info->sid);

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
int session_add(struct iscsi_target *target, struct session_info *info)
{
	struct iscsi_session *session;
	int err = -EEXIST;

	session = session_lookup(target, info->sid);
	if (session) {
		PRINT_ERROR("Attempt to add session with existing SID %Lx",
			info->sid);
		return err;
	}

	err = iscsi_session_alloc(target, info);

	return err;
}

/* target_mutex supposed to be locked */
int session_free(struct iscsi_session *session)
{
	int i;

	TRACE_MGMT_DBG("Freeing session %p:%#Lx", session, session->sid);

	sBUG_ON(!list_empty(&session->conn_list));
	if (unlikely(atomic_read(&session->active_cmds) != 0)) {
		PRINT_CRIT_ERROR("active_cmds not 0 (%d)!!",
			atomic_read(&session->active_cmds));
		sBUG();
	}

	for (i = 0; i < ARRAY_SIZE(session->cmnd_hash); i++)
		sBUG_ON(!list_empty(&session->cmnd_hash[i]));

	if (session->scst_sess != NULL)
		scst_unregister_session(session->scst_sess, 1, NULL);

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
		PRINT_ERROR("%llu still have connections", session->sid);
		return -EBUSY;
	}

	return session_free(session);
}

/* target_mutex supposed to be locked */
static void iscsi_session_info_show(struct seq_file *seq, struct iscsi_target *target)
{
	struct iscsi_session *session;

	list_for_each_entry(session, &target->session_list, session_list_entry) {
		seq_printf(seq, "\tsid:%llu initiator:%s shutting down %d\n",
			session->sid, session->initiator_name,
			session->shutting_down);
		conn_info_show(seq, session);
	}
}

static int iscsi_sessions_info_show(struct seq_file *seq, void *v)
{
	return iscsi_info_show(seq, iscsi_session_info_show);
}

static int iscsi_session_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, iscsi_sessions_info_show, NULL);
}

struct file_operations session_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= iscsi_session_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
