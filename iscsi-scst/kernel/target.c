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

#include <linux/delay.h>
#include <linux/module.h>

#include "iscsi.h"
#include "digest.h"

#define MAX_NR_TARGETS		(1UL << 30)

DEFINE_MUTEX(target_mgmt_mutex);

/* All 3 protected by target_mgmt_mutex */
static LIST_HEAD(target_list);
static u32 next_target_id;
static u32 nr_targets;

/* target_mgmt_mutex supposed to be locked */
struct iscsi_target *target_lookup_by_id(u32 id)
{
	struct iscsi_target *target;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

	list_for_each_entry(target, &target_list, target_list_entry) {
		if (target->tid == id)
			return target;
	}
	return NULL;
}

/* target_mgmt_mutex supposed to be locked */
static struct iscsi_target *target_lookup_by_name(const char *name)
{
	struct iscsi_target *target;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

	list_for_each_entry(target, &target_list, target_list_entry) {
		if (!strcmp(target->name, name))
			return target;
	}
	return NULL;
}

/* target_mgmt_mutex supposed to be locked */
static int iscsi_target_create(struct iscsi_kern_target_info *info, u32 tid,
	struct iscsi_target **out_target)
{
	int err = -EINVAL, len;
	char *name = info->name;
	struct iscsi_target *target;

	TRACE_MGMT_DBG("Creating target tid %u, name %s", tid, name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

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

	strlcpy(target->name, name, sizeof(target->name));

	mutex_init(&target->target_mutex);
	INIT_LIST_HEAD(&target->session_list);
#ifndef CONFIG_SCST_PROC
	INIT_LIST_HEAD(&target->attrs_list);
#endif

	target->scst_tgt = scst_register_target(&iscsi_template, target->name);
	if (!target->scst_tgt) {
		PRINT_ERROR("%s", "scst_register_target() failed");
		err = -EBUSY;
		goto out_free;
	}

	scst_tgt_set_tgt_priv(target->scst_tgt, target);

	list_add_tail(&target->target_list_entry, &target_list);

	*out_target = target;

	return 0;

out_free:
	kfree(target);

out_put:
	module_put(THIS_MODULE);

out:
	return err;
}

/* target_mgmt_mutex supposed to be locked */
int __add_target(struct iscsi_kern_target_info *info)
{
	int err;
	u32 tid = info->tid;
	struct iscsi_target *target = NULL; /* to calm down sparse */
	struct iscsi_kern_attr *attr_info;
	union add_info_union {
		struct iscsi_kern_params_info params_info;
		struct iscsi_kern_attr attr_info;
	} *add_info;
#ifndef CONFIG_SCST_PROC
	int i, rc;
	unsigned long attrs_ptr_long;
	struct iscsi_kern_attr __user *attrs_ptr;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

	if (nr_targets > MAX_NR_TARGETS) {
		err = -EBUSY;
		goto out;
	}

	if (target_lookup_by_name(info->name)) {
		PRINT_ERROR("Target %s already exist!", info->name);
		err = -EEXIST;
		goto out;
	}

	if (tid && target_lookup_by_id(tid)) {
		PRINT_ERROR("Target %u already exist!", tid);
		err = -EEXIST;
		goto out;
	}

	add_info = kmalloc(sizeof(*add_info), GFP_KERNEL);
	if (add_info == NULL) {
		PRINT_ERROR("Unable to allocate additional info (size %zd)",
			sizeof(*add_info));
		err = -ENOMEM;
		goto out;
	}
	attr_info = (struct iscsi_kern_attr *)add_info;

	if (tid == 0) {
		do {
			if (!++next_target_id)
				++next_target_id;
		} while (target_lookup_by_id(next_target_id));

		tid = next_target_id;
	}

	err = iscsi_target_create(info, tid, &target);
	if (err != 0)
		goto out_free;

	nr_targets++;

#ifndef CONFIG_SCST_PROC
	mutex_lock(&target->target_mutex);

	attrs_ptr_long = info->attrs_ptr;
	attrs_ptr = (struct iscsi_kern_attr __user *)attrs_ptr_long;
	for (i = 0; i < info->attrs_num; i++) {
		memset(attr_info, 0, sizeof(*attr_info));

		rc = copy_from_user(attr_info, attrs_ptr, sizeof(*attr_info));
		if (rc != 0) {
			PRINT_ERROR("Failed to copy users of target %s "
				"failed", info->name);
			err = -EFAULT;
			goto out_del_unlock;
		}

		attr_info->name[sizeof(attr_info->name)-1] = '\0';

		err = iscsi_add_attr(target, attr_info);
		if (err != 0)
			goto out_del_unlock;

		attrs_ptr++;
	}

	mutex_unlock(&target->target_mutex);
#endif

	err = tid;

out_free:
	kfree(add_info);

out:
	return err;

#ifndef CONFIG_SCST_PROC
out_del_unlock:
	mutex_unlock(&target->target_mutex);
	__del_target(tid);
	goto out_free;
#endif
}

static void target_destroy(struct iscsi_target *target)
{
#ifndef CONFIG_SCST_PROC
	struct iscsi_attr *attr, *t;
#endif

	TRACE_MGMT_DBG("Destroying target tid %u", target->tid);

#ifndef CONFIG_SCST_PROC
	list_for_each_entry_safe(attr, t, &target->attrs_list,
				attrs_list_entry) {
		__iscsi_del_attr(target, attr);
	}
#endif

	scst_unregister_target(target->scst_tgt);

	kfree(target);

	module_put(THIS_MODULE);
	return;
}

/* target_mgmt_mutex supposed to be locked */
int __del_target(u32 id)
{
	struct iscsi_target *target;
	int err;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target->target_mutex);
#endif

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
		__del_session(target, session->sid);
	}

	TRACE_EXIT();
	return;
}

/* target_mutex supposed to be locked */
void target_del_all_sess(struct iscsi_target *target, int flags)
{
	struct iscsi_session *session, *ts;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target->target_mutex);
#endif

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
	bool first = true;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("%s", "Deleting all targets");

	/* Not the best, ToDo */
	while (1) {
		mutex_lock(&target_mgmt_mutex);

		if (list_empty(&target_list))
			break;

		/*
		 * In the first iteration we won't delete targets to go at
		 * first through all sessions of all targets and close their
		 * connections. Otherwise we can stuck for noticeable time
		 * waiting during a target's unregistration for the activities
		 * suspending over active connection. This can especially got
		 * bad if any being wait connection itself stuck waiting for
		 * something and can be recovered only by connection close.
		 * Let's for such cases not wait while such connection recover
		 * theyself, but act in advance.
		 */

		list_for_each_entry_safe(target, t, &target_list,
					 target_list_entry) {
			mutex_lock(&target->target_mutex);

			if (!list_empty(&target->session_list)) {
				target_del_all_sess(target,
					ISCSI_CONN_ACTIVE_CLOSE |
					ISCSI_CONN_DELETING);
			} else if (!first) {
				TRACE_MGMT_DBG("Deleting target %p", target);
				list_del(&target->target_list_entry);
				nr_targets--;
				mutex_unlock(&target->target_mutex);
				target_destroy(target);
				continue;
			}

			mutex_unlock(&target->target_mutex);
		}
		mutex_unlock(&target_mgmt_mutex);
		msleep(100);

		first = false;
	}

	mutex_unlock(&target_mgmt_mutex);

	TRACE_MGMT_DBG("%s", "Deleting all targets finished");

	TRACE_EXIT();
	return;
}

#ifdef CONFIG_SCST_PROC

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 <= 5 && RHEL_MINOR -0 <= 6)
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

#else /* CONFIG_SCST_PROC */

static ssize_t iscsi_tgt_tid_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int res = -E_TGT_PRIV_NOT_YET_SET;
	struct scst_tgt *scst_tgt;
	struct iscsi_target *tgt;

	TRACE_ENTRY();

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;

	res = sprintf(buf, "%u\n", tgt->tid);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute iscsi_tgt_attr_tid =
	__ATTR(tid, S_IRUGO, iscsi_tgt_tid_show, NULL);

const struct attribute *iscsi_tgt_attrs[] = {
	&iscsi_tgt_attr_tid.attr,
	NULL,
};

ssize_t iscsi_sysfs_send_event(uint32_t tid, enum iscsi_kern_event_code code,
	const char *param1, const char *param2, void **data)
{
	int res;
	struct scst_sysfs_user_info *info;

	TRACE_ENTRY();

	if (ctr_open_state != ISCSI_CTR_OPEN_STATE_OPEN) {
		PRINT_ERROR("%s", "User space process not connected");
		res = -EPERM;
		goto out;
	}

	res = scst_sysfs_user_add_info(&info);
	if (res != 0)
		goto out;

	TRACE_DBG("Sending event %d (tid %d, param1 %s, param2 %s, cookie %d, "
		"info %p)", tid, code, param1, param2, info->info_cookie, info);

	res = event_send(tid, 0, 0, info->info_cookie, code, param1, param2);
	if (res <= 0) {
		PRINT_ERROR("event_send() failed: %d", res);
		if (res == 0)
			res = -EFAULT;
		goto out_free;
	}

	/*
	 * It may wait 30 secs in blocking connect to an unreacheable
	 * iSNS server. It must be fixed, but not now. ToDo.
	 */
	res = scst_wait_info_completion(info, 31 * HZ);

	if (data != NULL)
		*data = info->data;

out_free:
	scst_sysfs_user_del_info(info);

out:
	TRACE_EXIT_RES(res);
	return res;
}

int iscsi_enable_target(struct scst_tgt *scst_tgt, bool enable)
{
	struct iscsi_target *tgt =
		(struct iscsi_target *)scst_tgt_get_tgt_priv(scst_tgt);
	int res;
	uint32_t type;

	TRACE_ENTRY();

	if (tgt == NULL) {
		res = -E_TGT_PRIV_NOT_YET_SET;
		goto out;
	}

	if (enable)
		type = E_ENABLE_TARGET;
	else
		type = E_DISABLE_TARGET;

	TRACE_DBG("%s target %d", enable ? "Enabling" : "Disabling", tgt->tid);

	res = iscsi_sysfs_send_event(tgt->tid, type, NULL, NULL, NULL);

out:
	TRACE_EXIT_RES(res);
	return res;
}

bool iscsi_is_target_enabled(struct scst_tgt *scst_tgt)
{
	struct iscsi_target *tgt =
		(struct iscsi_target *)scst_tgt_get_tgt_priv(scst_tgt);

	if (tgt != NULL)
		return tgt->tgt_enabled;
	else
		return false;
}

ssize_t iscsi_sysfs_add_target(const char *target_name, char *params)
{
	int res;

	TRACE_ENTRY();

	res = iscsi_sysfs_send_event(0, E_ADD_TARGET, target_name,
			params, NULL);
	if (res > 0) {
		/* It's tid */
		res = 0;
	}

	TRACE_EXIT_RES(res);
	return res;
}

ssize_t iscsi_sysfs_del_target(const char *target_name)
{
	int res = 0, tid;

	TRACE_ENTRY();

	/* We don't want to have tgt visible after the mutex unlock */
	{
		struct iscsi_target *tgt;
		mutex_lock(&target_mgmt_mutex);
		tgt = target_lookup_by_name(target_name);
		if (tgt == NULL) {
			PRINT_ERROR("Target %s not found", target_name);
			mutex_unlock(&target_mgmt_mutex);
			res = -ENOENT;
			goto out;
		}
		tid = tgt->tid;
		mutex_unlock(&target_mgmt_mutex);
	}

	TRACE_DBG("Deleting target %s (tid %d)", target_name, tid);

	res = iscsi_sysfs_send_event(tid, E_DEL_TARGET, NULL, NULL, NULL);

out:
	TRACE_EXIT_RES(res);
	return res;
}

ssize_t iscsi_sysfs_mgmt_cmd(char *cmd)
{
	int res;

	TRACE_ENTRY();

	TRACE_DBG("Sending mgmt cmd %s", cmd);

	res = iscsi_sysfs_send_event(0, E_MGMT_CMD, cmd, NULL, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

#endif /* CONFIG_SCST_PROC */
