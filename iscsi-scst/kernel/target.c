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

#include <linux/delay.h>

#include "iscsi.h"
#include "digest.h"

#define	MAX_NR_TARGETS	(1UL << 30)

DEFINE_MUTEX(target_mgmt_mutex);

/* All 3 protected by target_mgmt_mutex */
static LIST_HEAD(target_list);
static u32 next_target_id;
static u32 nr_targets;

static struct iscsi_sess_param default_session_param = {
	.initial_r2t = 1,
	.immediate_data = 1,
	.max_connections = 1,
	.max_recv_data_length = 8192,
	.max_xmit_data_length = 8192,
	.max_burst_length = 262144,
	.first_burst_length = 65536,
	.default_wait_time = 2,
	.default_retain_time = 20,
	.max_outstanding_r2t = 1,
	.data_pdu_inorder = 1,
	.data_sequence_inorder = 1,
	.error_recovery_level = 0,
	.header_digest = DIGEST_NONE,
	.data_digest = DIGEST_NONE,
	.ofmarker = 0,
	.ifmarker = 0,
	.ofmarkint = 2048,
	.ifmarkint = 2048,
};

static struct iscsi_trgt_param default_target_param = {
	.queued_cmnds = DEFAULT_NR_QUEUED_CMNDS,
};

/* target_mgmt_mutex supposed to be locked */
struct iscsi_target *target_lookup_by_id(u32 id)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &target_list, target_list_entry) {
		if (target->tid == id)
			return target;
	}
	return NULL;
}

/* target_mgmt_mutex supposed to be locked */
static struct iscsi_target *target_lookup_by_name(char *name)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &target_list, target_list_entry) {
		if (!strcmp(target->name, name))
			return target;
	}
	return NULL;
}

/* target_mgmt_mutex supposed to be locked */
static int iscsi_target_create(struct target_info *info, u32 tid)
{
	int err = -EINVAL, len;
	char *name = info->name;
	struct iscsi_target *target;

	TRACE_MGMT_DBG("Creating target tid %u, name %s", tid, name);

	len = strlen(name);
	if (!len) {
		PRINT_ERROR("The length of the target name is zero %u", tid);
		goto out;
	}

	if (!try_module_get(THIS_MODULE)) {
		PRINT_ERROR("Fail to get module %u", tid);
		goto out;
	}

	target = kzalloc(sizeof(*target), GFP_KERNEL);
	if (!target) {
		err = -ENOMEM;
		goto out_put;
	}

	target->tid = info->tid = tid;

	memcpy(&target->trgt_sess_param, &default_session_param,
		sizeof(default_session_param));
	memcpy(&target->trgt_param, &default_target_param,
		sizeof(default_target_param));

	strncpy(target->name, name, sizeof(target->name) - 1);

	mutex_init(&target->target_mutex);
	INIT_LIST_HEAD(&target->session_list);

	list_add(&target->target_list_entry, &target_list);

	target->scst_tgt = scst_register(&iscsi_template, target->name);
	if (!target->scst_tgt) {
		PRINT_ERROR("%s", "scst_register() failed");
		err = -EBUSY;
		goto out_free;
	}

	return 0;

out_free:
	kfree(target);

out_put:
	module_put(THIS_MODULE);

out:
	return err;
}

/* target_mgmt_mutex supposed to be locked */
int target_add(struct target_info *info)
{
	int err = -EEXIST;
	u32 tid = info->tid;

	if (nr_targets > MAX_NR_TARGETS) {
		err = -EBUSY;
		goto out;
	}

	if (target_lookup_by_name(info->name))
		goto out;

	if (tid && target_lookup_by_id(tid))
		goto out;

	if (!tid) {
		do {
			if (!++next_target_id)
				++next_target_id;
		} while (target_lookup_by_id(next_target_id));

		tid = next_target_id;
	}

	err = iscsi_target_create(info, tid);
	if (!err)
		nr_targets++;
out:
	return err;
}

static void target_destroy(struct iscsi_target *target)
{
	TRACE_MGMT_DBG("Destroying target tid %u", target->tid);

	scst_unregister(target->scst_tgt);

	kfree(target);

	module_put(THIS_MODULE);
}

/* target_mgmt_mutex supposed to be locked */
int target_del(u32 id)
{
	struct iscsi_target *target;
	int err;

	target = target_lookup_by_id(id);
	if (!target) {
		err = -ENOENT;
		goto out;
	}

	mutex_lock(&target->target_mutex);

	if (!list_empty(&target->session_list)) {
		err = -EBUSY;
		goto out_unlock;
	}

	list_del(&target->target_list_entry);
	nr_targets--;

	mutex_unlock(&target->target_mutex);

	target_destroy(target);
	return 0;

out_unlock:
	mutex_unlock(&target->target_mutex);

out:
	return err;
}

static void target_del_session(struct iscsi_target *target,
	struct iscsi_session *session, bool deleting)
{
	int flags = ISCSI_CONN_ACTIVE_CLOSE;

	if (deleting)
		flags |= ISCSI_CONN_DELETING;

	TRACE_MGMT_DBG("Cleaning up session %p", session);
	if (!list_empty(&session->conn_list)) {
		struct iscsi_conn *conn, *tc;
		list_for_each_entry_safe(conn, tc, &session->conn_list,
					 conn_list_entry) {
			TRACE_MGMT_DBG("Mark conn %p closing", conn);
			__mark_conn_closed(conn, flags);
		}
	} else {
		TRACE_MGMT_DBG("Freeing session %p without connections",
			       session);
		session_del(target, session->sid);
	}
}

/* target_mutex supposed to be locked */
void target_del_all_sess(struct iscsi_target *target, bool deleting)
{
	struct iscsi_session *session, *ts;

	TRACE_ENTRY();

	if (!list_empty(&target->session_list)) {
		TRACE_MGMT_DBG("Deleting all sessions from target %p", target);
		list_for_each_entry_safe(session, ts, &target->session_list,
						session_list_entry) {
			target_del_session(target, session, deleting);
		}
	}

	TRACE_EXIT();
	return;
}

void target_del_all(void)
{
	struct iscsi_target *target, *t;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("%s", "Deleting all targets");

	/* Not the best, ToDo */
	while (1) {
		mutex_lock(&target_mgmt_mutex);

		if (list_empty(&target_list))
			break;

		list_for_each_entry_safe(target, t, &target_list,
					 target_list_entry) {
			mutex_lock(&target->target_mutex);
			if (!list_empty(&target->session_list)) {
				target_del_all_sess(target, true);
				mutex_unlock(&target->target_mutex);
			} else {
				TRACE_MGMT_DBG("Deleting target %p", target);
				list_del(&target->target_list_entry);
				nr_targets--;
				mutex_unlock(&target->target_mutex);
				target_destroy(target);
				continue;
			}
		}
		mutex_unlock(&target_mgmt_mutex);
		msleep(100);
	}

	mutex_unlock(&target_mgmt_mutex);

	TRACE_MGMT_DBG("%s", "Deleting all targets finished");

	TRACE_EXIT();
	return;
}

int iscsi_info_show(struct seq_file *seq, iscsi_show_info_t *func)
{
	int err;
	struct iscsi_target *target;

	err = mutex_lock_interruptible(&target_mgmt_mutex);
	if (err < 0)
		return err;

	list_for_each_entry(target, &target_list, target_list_entry) {
		seq_printf(seq, "tid:%u name:%s\n", target->tid, target->name);

		mutex_lock(&target->target_mutex);
		func(seq, target);
		mutex_unlock(&target->target_mutex);
	}

	mutex_unlock(&target_mgmt_mutex);

	return 0;
}
