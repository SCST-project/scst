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

#include <linux/delay.h>
#include <linux/module.h>

#include "iscsi_trace_flag.h"
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

	lockdep_assert_held(&target_mgmt_mutex);

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

	lockdep_assert_held(&target_mgmt_mutex);

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

	lockdep_assert_held(&target_mgmt_mutex);

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

	strscpy(target->name, name, sizeof(target->name));

	mutex_init(&target->target_mutex);
	INIT_LIST_HEAD(&target->session_list);
	INIT_LIST_HEAD(&target->attrs_list);

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
	union add_info_union {
		struct iscsi_kern_params_info params_info;
		struct iscsi_kern_attr attr_info;
	} *add_info;
	int i, rc;
	unsigned long attrs_ptr_long;
	struct iscsi_kern_attr __user *attrs_ptr;

	lockdep_assert_held(&target_mgmt_mutex);

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

	{
	struct iscsi_kern_attr *attr_info = &add_info->attr_info;

	mutex_lock(&target->target_mutex);

	attrs_ptr_long = info->attrs_ptr;
	attrs_ptr = (struct iscsi_kern_attr __user *)attrs_ptr_long;
	for (i = 0; i < info->attrs_num; i++) {
		memset(attr_info, 0, sizeof(*attr_info));

		rc = copy_from_user(attr_info, attrs_ptr, sizeof(*attr_info));
		if (rc != 0) {
			PRINT_ERROR("Failed to copy users of target %s failed",
				    info->name);
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
	}

	err = tid;

out_free:
	kfree(add_info);

out:
	return err;

out_del_unlock:
	mutex_unlock(&target->target_mutex);
	__del_target(tid);
	goto out_free;
}

static void target_destroy(struct iscsi_target *target)
{
	struct iscsi_attr *attr, *t;

	TRACE_MGMT_DBG("Destroying target tid %u", target->tid);

	list_for_each_entry_safe(attr, t, &target->attrs_list,
				attrs_list_entry) {
		__iscsi_del_attr(target, attr);
	}

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

	lockdep_assert_held(&target_mgmt_mutex);

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

	TRACE(TRACE_MGMT, "Deleting session %p (initiator %s)", session,
		session->scst_sess->initiator_name);

	lockdep_assert_held(&target->target_mutex);

	if (!list_empty(&session->conn_list)) {
		struct iscsi_conn *conn, *tc;

		list_for_each_entry_safe(conn, tc, &session->conn_list,
					 conn_list_entry) {
			TRACE_MGMT_DBG("Del session: closing conn %p", conn);
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

	lockdep_assert_held(&target->target_mutex);

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
EXPORT_SYMBOL(target_del_all_sess);

void target_del_all(void)
{
	struct iscsit_transport *transport;
	struct iscsi_target *target, *t;
	bool first = true;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("%s", "Deleting all targets");

	transport = iscsit_get_transport(ISCSI_TCP);
	if (transport && transport->iscsit_close_all_portals)
		transport->iscsit_close_all_portals();

	transport = iscsit_get_transport(ISCSI_RDMA);
	if (transport && transport->iscsit_close_all_portals)
		transport->iscsit_close_all_portals();

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
		PRINT_ERROR("User space process is not connected. Is iscsi-scstd running?");
		res = -EPERM;
		goto out;
	}

	res = scst_sysfs_user_add_info(&info);
	if (res != 0)
		goto out;

	TRACE_DBG("Sending event %d (tid %d, param1 %s, param2 %s, cookie %d, info %p)",
		  code, tid, param1, param2, info->info_cookie, info);

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

static ssize_t iscsi_acg_sess_dedicated_threads_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct scst_acg *acg;
	bool dedicated;

	TRACE_ENTRY();

	acg = container_of(kobj, struct scst_acg, acg_kobj);
	dedicated = scst_get_acg_tgt_priv(acg) != NULL;

	pos = sprintf(buf, "%d\n%s", dedicated,
		dedicated ? SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t iscsi_acg_sess_dedicated_threads_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	unsigned long val;

	TRACE_ENTRY();

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	res = kstrtoul(buf, 0, &val);
	if (res != 0) {
		PRINT_ERROR("kstrtoul() for %s failed: %d ", buf, res);
		goto out;
	}

	scst_set_acg_tgt_priv(acg, (void *)(unsigned long)(val != 0));

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute iscsi_acg_attr_sess_dedicated_threads =
	__ATTR(per_sess_dedicated_tgt_threads, S_IRUGO | S_IWUSR,
		iscsi_acg_sess_dedicated_threads_show,
		iscsi_acg_sess_dedicated_threads_store);

const struct attribute *iscsi_acg_attrs[] = {
	&iscsi_acg_attr_sess_dedicated_threads.attr,
	NULL,
};
