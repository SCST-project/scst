/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2009 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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
static int iscsi_target_create(struct iscsi_kern_target_info *info, u32 tid)
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

	strncpy(target->name, name, sizeof(target->name) - 1);

	mutex_init(&target->target_mutex);
	INIT_LIST_HEAD(&target->session_list);

	target->scst_tgt = scst_register(&iscsi_template, target->name);
	if (!target->scst_tgt) {
		PRINT_ERROR("%s", "scst_register() failed");
		err = -EBUSY;
		goto out_free;
	}

	list_add_tail(&target->target_list_entry, &target_list);

	return 0;

out_free:
	kfree(target);

out_put:
	module_put(THIS_MODULE);

out:
	return err;
}

/* target_mgmt_mutex supposed to be locked */
int target_add(struct iscsi_kern_target_info *info)
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

/* target_mutex supposed to be locked */
void target_del_session(struct iscsi_target *target,
	struct iscsi_session *session, int flags)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("Deleting session %p", session);

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

	TRACE_EXIT();
	return;
}

/* target_mutex supposed to be locked */
void target_del_all_sess(struct iscsi_target *target, int flags)
{
	struct iscsi_session *session, *ts;

	TRACE_ENTRY();

	if (!list_empty(&target->session_list)) {
		TRACE_MGMT_DBG("Deleting all sessions from target %p", target);
		list_for_each_entry_safe(session, ts, &target->session_list,
						session_list_entry) {
			target_del_session(target, session, flags);
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
				target_del_all_sess(target,
					ISCSI_CONN_ACTIVE_CLOSE |
					ISCSI_CONN_DELETING);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static struct list_head *seq_list_start(struct list_head *head, loff_t pos)
{
	struct list_head *lh;

	list_for_each(lh, head)
		if (pos-- == 0)
			return lh;

	return NULL;
}

static struct list_head *seq_list_next(void *v, struct list_head *head,
				       loff_t *ppos)
{
	struct list_head *lh;

	lh = ((struct list_head *)v)->next;
	++*ppos;
	return lh == head ? NULL : lh;
}
#endif

static void *iscsi_seq_start(struct seq_file *m, loff_t *pos)
{
	int err;

	err = mutex_lock_interruptible(&target_mgmt_mutex);
	if (err < 0)
		return ERR_PTR(err);

	return seq_list_start(&target_list, *pos);
}

static void *iscsi_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &target_list, pos);
}

static void iscsi_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&target_mgmt_mutex);
}

static int iscsi_seq_show(struct seq_file *m, void *p)
{
	iscsi_show_info_t *func = (iscsi_show_info_t *)m->private;
	struct iscsi_target *target =
		list_entry(p, struct iscsi_target, target_list_entry);

	seq_printf(m, "tid:%u name:%s\n", target->tid, target->name);

	mutex_lock(&target->target_mutex);
	func(m, target);
	mutex_unlock(&target->target_mutex);

	return 0;
}

const struct seq_operations iscsi_seq_op = {
	.start = iscsi_seq_start,
	.next = iscsi_seq_next,
	.stop = iscsi_seq_stop,
	.show = iscsi_seq_show,
};
