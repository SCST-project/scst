/*
 *  Copyright (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/module.h>
#include "iscsi.h"

/* Protected by target_mgmt_mutex */
int ctr_open_state;

#ifdef CONFIG_SCST_PROC

#include <linux/proc_fs.h>

#define ISCSI_PROC_VERSION_NAME		"version"

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define ISCSI_PROC_LOG_ENTRY_NAME	"trace_level"

static struct scst_trace_log iscsi_local_trace_tbl[] = {
    { TRACE_D_WRITE,		"d_write" },
    { TRACE_CONN_OC,		"conn" },
    { TRACE_CONN_OC_DBG,	"conn_dbg" },
    { TRACE_D_IOV,		"iov" },
    { TRACE_D_DUMP_PDU,		"pdu" },
    { TRACE_NET_PG,		"net_page" },
    { 0,			NULL }
};

static int iscsi_log_info_show(struct seq_file *seq, void *v)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_read(seq, trace_flag,
		iscsi_local_trace_tbl);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t iscsi_proc_log_entry_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, &trace_flag,
		ISCSI_DEFAULT_LOG_FLAGS, iscsi_local_trace_tbl);

	TRACE_EXIT_RES(res);
	return res;
}

#endif /* DEBUG or TRACE */

static int iscsi_version_info_show(struct seq_file *seq, void *v)
{
	TRACE_ENTRY();

	seq_printf(seq, "%s\n", ISCSI_VERSION_STRING);

#ifdef CONFIG_SCST_EXTRACHECKS
	seq_printf(seq, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_SCST_TRACING
	seq_printf(seq, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	seq_printf(seq, "DEBUG\n");
#endif

#ifdef CONFIG_SCST_ISCSI_DEBUG_DIGEST_FAILURES
	seq_printf(seq, "DEBUG_DIGEST_FAILURES\n");
#endif

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data iscsi_version_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = iscsi_version_info_show,
};

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static struct scst_proc_data iscsi_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(iscsi_proc_log_entry_write)
	.show = iscsi_log_info_show,
};
#endif

static __init int iscsi_proc_log_entry_build(struct scst_tgt_template *templ)
{
	int res = 0;
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
		p = scst_create_proc_entry(root, ISCSI_PROC_VERSION_NAME,
					   &iscsi_version_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register "
			     "target driver %s entry %s in /proc",
			      templ->name, ISCSI_PROC_VERSION_NAME);
			res = -ENOMEM;
			goto out;
		}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
		/* create the proc file entry for the device */
		iscsi_log_proc_data.data = (void *)templ->name;
		p = scst_create_proc_entry(root, ISCSI_PROC_LOG_ENTRY_NAME,
					   &iscsi_log_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register "
			     "target driver %s entry %s in /proc",
			      templ->name, ISCSI_PROC_LOG_ENTRY_NAME);
			res = -ENOMEM;
			goto out_remove_ver;
		}
#endif
	}

out:
	TRACE_EXIT_RES(res);
	return res;

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
out_remove_ver:
	remove_proc_entry(ISCSI_PROC_VERSION_NAME, root);
	goto out;
#endif
}

static void iscsi_proc_log_entry_clean(struct scst_tgt_template *templ)
{
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
		remove_proc_entry(ISCSI_PROC_LOG_ENTRY_NAME, root);
#endif
		remove_proc_entry(ISCSI_PROC_VERSION_NAME, root);
	}

	TRACE_EXIT();
	return;
}

struct proc_entries {
	const char *name;
	const struct file_operations *const fops;
};

static struct proc_entries iscsi_proc_entries[] = {
	{"session", &session_seq_fops},
};

static struct proc_dir_entry *proc_iscsi_dir;

void iscsi_procfs_exit(void)
{
	unsigned int i;

	if (!proc_iscsi_dir)
		return;

	for (i = 0; i < ARRAY_SIZE(iscsi_proc_entries); i++)
		remove_proc_entry(iscsi_proc_entries[i].name, proc_iscsi_dir);

	iscsi_proc_log_entry_clean(&iscsi_template);
}

int __init iscsi_procfs_init(void)
{
	unsigned int i;
	int err = 0;
	struct proc_dir_entry *ent;

	proc_iscsi_dir = scst_proc_get_tgt_root(&iscsi_template);
	if (proc_iscsi_dir == NULL) {
		err = -ESRCH;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	proc_iscsi_dir->owner = THIS_MODULE;
#endif

	err = iscsi_proc_log_entry_build(&iscsi_template);
	if (err < 0)
		goto out;

	for (i = 0; i < ARRAY_SIZE(iscsi_proc_entries); i++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		ent = proc_create(iscsi_proc_entries[i].name, 0, proc_iscsi_dir,
				  iscsi_proc_entries[i].fops);
#else
		/*
		 * proc_create() was introduced via commit "proc: fix
		 * ->open'less usage due to ->proc_fops flip"
		 * (2d3a4e3666325a9709cc8ea2e88151394e8f20fc).
		 */
		ent = create_proc_entry(iscsi_proc_entries[i].name, 0,
					proc_iscsi_dir);
		if (ent)
			ent->proc_fops = iscsi_proc_entries[i].fops;
#endif
		if (!ent) {
			err = -ENOMEM;
			goto err;
		}
	}

out:
	return err;

err:
	if (proc_iscsi_dir)
		iscsi_procfs_exit();
	goto out;
}

#else /* CONFIG_SCST_PROC */

/* Protected by target_mgmt_mutex */
static LIST_HEAD(iscsi_attrs_list);

static ssize_t iscsi_version_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	TRACE_ENTRY();

	sprintf(buf, "%s\n", ISCSI_VERSION_STRING);

#ifdef CONFIG_SCST_EXTRACHECKS
	strcat(buf, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_SCST_TRACING
	strcat(buf, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	strcat(buf, "DEBUG\n");
#endif

#ifdef CONFIG_SCST_ISCSI_DEBUG_DIGEST_FAILURES
	strcat(buf, "DEBUG_DIGEST_FAILURES\n");
#endif

	TRACE_EXIT();
	return strlen(buf);
}

static struct kobj_attribute iscsi_version_attr =
	__ATTR(version, S_IRUGO, iscsi_version_show, NULL);

static ssize_t iscsi_open_state_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	switch (ctr_open_state) {
	case ISCSI_CTR_OPEN_STATE_CLOSED:
		sprintf(buf, "%s\n", "closed");
		break;
	case ISCSI_CTR_OPEN_STATE_OPEN:
		sprintf(buf, "%s\n", "open");
		break;
	case ISCSI_CTR_OPEN_STATE_CLOSING:
		sprintf(buf, "%s\n", "closing");
		break;
	default:
		sprintf(buf, "%s\n", "unknown");
		break;
	}

	return strlen(buf);
}

static struct kobj_attribute iscsi_open_state_attr =
	__ATTR(open_state, S_IRUGO, iscsi_open_state_show, NULL);

const struct attribute *iscsi_attrs[] = {
	&iscsi_version_attr.attr,
	&iscsi_open_state_attr.attr,
	NULL,
};

#endif /* CONFIG_SCST_PROC */

/* target_mgmt_mutex supposed to be locked */
static int add_conn(void __user *ptr)
{
	int err, rc;
	struct iscsi_session *session;
	struct iscsi_kern_conn_info info;
	struct iscsi_target *target;

	TRACE_ENTRY();

	rc = copy_from_user(&info, ptr, sizeof(info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out;
	}

	target = target_lookup_by_id(info.tid);
	if (target == NULL) {
		PRINT_ERROR("Target %d not found", info.tid);
		err = -ENOENT;
		goto out;
	}

	mutex_lock(&target->target_mutex);

	session = session_lookup(target, info.sid);
	if (!session) {
		PRINT_ERROR("Session %lld not found",
			(long long unsigned int)info.tid);
		err = -ENOENT;
		goto out_unlock;
	}

	err = __add_conn(session, &info);

out_unlock:
	mutex_unlock(&target->target_mutex);

out:
	TRACE_EXIT_RES(err);
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int del_conn(void __user *ptr)
{
	int err, rc;
	struct iscsi_session *session;
	struct iscsi_kern_conn_info info;
	struct iscsi_target *target;

	TRACE_ENTRY();

	rc = copy_from_user(&info, ptr, sizeof(info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out;
	}

	target = target_lookup_by_id(info.tid);
	if (target == NULL) {
		PRINT_ERROR("Target %d not found", info.tid);
		err = -ENOENT;
		goto out;
	}

	mutex_lock(&target->target_mutex);

	session = session_lookup(target, info.sid);
	if (!session) {
		PRINT_ERROR("Session %llx not found",
			(long long unsigned int)info.sid);
		err = -ENOENT;
		goto out_unlock;
	}

	err = __del_conn(session, &info);

out_unlock:
	mutex_unlock(&target->target_mutex);

out:
	TRACE_EXIT_RES(err);
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int add_session(void __user *ptr)
{
	int err, rc;
	struct iscsi_kern_session_info *info;
	struct iscsi_target *target;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target_mgmt_mutex);
#endif

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL) {
		PRINT_ERROR("Can't alloc info (size %zd)", sizeof(*info));
		err = -ENOMEM;
		goto out;
	}

	rc = copy_from_user(info, ptr, sizeof(*info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out_free;
	}

	info->initiator_name[sizeof(info->initiator_name)-1] = '\0';
#ifdef CONFIG_SCST_PROC
	info->user_name[sizeof(info->user_name)-1] = '\0';
#endif
	info->full_initiator_name[sizeof(info->full_initiator_name)-1] = '\0';

	target = target_lookup_by_id(info->tid);
	if (target == NULL) {
		PRINT_ERROR("Target %d not found", info->tid);
		err = -ENOENT;
		goto out_free;
	}

	err = __add_session(target, info);

out_free:
	kfree(info);

out:
	TRACE_EXIT_RES(err);
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int del_session(void __user *ptr)
{
	int err, rc;
	struct iscsi_kern_session_info *info;
	struct iscsi_target *target;

	TRACE_ENTRY();

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL) {
		PRINT_ERROR("Can't alloc info (size %zd)", sizeof(*info));
		err = -ENOMEM;
		goto out;
	}

	rc = copy_from_user(info, ptr, sizeof(*info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out_free;
	}

	info->initiator_name[sizeof(info->initiator_name)-1] = '\0';
#ifdef CONFIG_SCST_PROC
	info->user_name[sizeof(info->user_name)-1] = '\0';
#endif

	target = target_lookup_by_id(info->tid);
	if (target == NULL) {
		PRINT_ERROR("Target %d not found", info->tid);
		err = -ENOENT;
		goto out_free;
	}

	mutex_lock(&target->target_mutex);
	err = __del_session(target, info->sid);
	mutex_unlock(&target->target_mutex);

out_free:
	kfree(info);

out:
	TRACE_EXIT_RES(err);
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int iscsi_params_config(void __user *ptr, int set)
{
	int err, rc;
	struct iscsi_kern_params_info info;
	struct iscsi_target *target;

	TRACE_ENTRY();

	rc = copy_from_user(&info, ptr, sizeof(info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out;
	}

	target = target_lookup_by_id(info.tid);
	if (target == NULL) {
		PRINT_ERROR("Target %d not found", info.tid);
		err = -ENOENT;
		goto out;
	}

	mutex_lock(&target->target_mutex);
	err = iscsi_params_set(target, &info, set);
	mutex_unlock(&target->target_mutex);

	if (err < 0)
		goto out;

	if (!set) {
		rc = copy_to_user(ptr, &info, sizeof(info));
		if (rc != 0) {
			PRINT_ERROR("Failed to copy to user %d bytes", rc);
			err = -EFAULT;
			goto out;
		}
	}

out:
	TRACE_EXIT_RES(err);
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int iscsi_initiator_allowed(void __user *ptr)
{
	int err = 0, rc;
	struct iscsi_kern_initiator_info cinfo;
	struct iscsi_target *target;

	TRACE_ENTRY();

	rc = copy_from_user(&cinfo, ptr, sizeof(cinfo));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out;
	}

	cinfo.full_initiator_name[sizeof(cinfo.full_initiator_name)-1] = '\0';

	target = target_lookup_by_id(cinfo.tid);
	if (target == NULL) {
		PRINT_ERROR("Target %d not found", cinfo.tid);
		err = -ENOENT;
		goto out;
	}

	err = scst_initiator_has_luns(target->scst_tgt,
		cinfo.full_initiator_name);

out:
	TRACE_EXIT_RES(err);
	return err;
}

#ifndef CONFIG_SCST_PROC

/* target_mgmt_mutex supposed to be locked */
static int mgmt_cmd_callback(void __user *ptr)
{
	int err = 0, rc;
	struct iscsi_kern_mgmt_cmd_res_info cinfo;
	struct scst_sysfs_user_info *info;

	TRACE_ENTRY();

	rc = copy_from_user(&cinfo, ptr, sizeof(cinfo));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out;
	}

	cinfo.value[sizeof(cinfo.value)-1] = '\0';

	info = scst_sysfs_user_get_info(cinfo.cookie);
	TRACE_DBG("cookie %u, info %p, result %d", cinfo.cookie, info,
		cinfo.result);
	if (info == NULL) {
		err = -EINVAL;
		goto out;
	}

	info->info_status = 0;

	if (cinfo.result != 0) {
		info->info_status = cinfo.result;
		goto out_complete;
	}

	switch (cinfo.req_cmd) {
	case E_ENABLE_TARGET:
	case E_DISABLE_TARGET:
	{
		struct iscsi_target *target;

		target = target_lookup_by_id(cinfo.tid);
		if (target == NULL) {
			PRINT_ERROR("Target %d not found", cinfo.tid);
			err = -ENOENT;
			goto out_status;
		}

		target->tgt_enabled = (cinfo.req_cmd == E_ENABLE_TARGET) ? 1 : 0;
		break;
	}

	case E_GET_ATTR_VALUE:
		info->data = kstrdup(cinfo.value, GFP_KERNEL);
		if (info->data == NULL) {
			PRINT_ERROR("Can't duplicate value %s", cinfo.value);
			info->info_status = -ENOMEM;
			goto out_complete;
		}
		break;
	}

out_complete:
	complete(&info->info_completion);

out:
	TRACE_EXIT_RES(err);
	return err;

out_status:
	info->info_status = err;
	goto out_complete;
}

static ssize_t iscsi_attr_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct iscsi_attr *tgt_attr;
	void *value;

	TRACE_ENTRY();

	tgt_attr = container_of(attr, struct iscsi_attr, attr);

	pos = iscsi_sysfs_send_event(
		(tgt_attr->target != NULL) ? tgt_attr->target->tid : 0,
		E_GET_ATTR_VALUE, tgt_attr->name, NULL, &value);

	if (pos != 0)
		goto out;

	pos = scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%s\n", (char *)value);

	kfree(value);

out:
	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t iscsi_attr_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	char *buffer;
	struct iscsi_attr *tgt_attr;

	TRACE_ENTRY();

	buffer = kzalloc(count+1, GFP_KERNEL);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}
	memcpy(buffer, buf, count);
	buffer[count] = '\0';

	tgt_attr = container_of(attr, struct iscsi_attr, attr);

	TRACE_DBG("attr %s, buffer %s", tgt_attr->attr.attr.name, buffer);

	res = iscsi_sysfs_send_event(
		(tgt_attr->target != NULL) ? tgt_attr->target->tid : 0,
		E_SET_ATTR_VALUE, tgt_attr->name, buffer, NULL);

	kfree(buffer);

	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * target_mgmt_mutex supposed to be locked. If target != 0, target_mutex
 * supposed to be locked as well.
 */
int iscsi_add_attr(struct iscsi_target *target,
	const struct iscsi_kern_attr *attr_info)
{
	int res = 0;
	struct iscsi_attr *tgt_attr;
	struct list_head *attrs_list;
	const char *name;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	static struct lock_class_key __key;
#endif
#endif

	TRACE_ENTRY();

	if (target != NULL) {
		attrs_list = &target->attrs_list;
		name = target->name;
	} else {
		attrs_list = &iscsi_attrs_list;
		name = "global";
	}

	list_for_each_entry(tgt_attr, attrs_list, attrs_list_entry) {
		/* Both for sure NULL-terminated */
		if (strcmp(tgt_attr->name, attr_info->name) == 0) {
			PRINT_ERROR("Attribute %s for %s already exist",
				attr_info->name, name);
			res = -EEXIST;
			goto out;
		}
	}

	TRACE_DBG("Adding %s's attr %s with mode %x", name,
		attr_info->name, attr_info->mode);

	tgt_attr = kzalloc(sizeof(*tgt_attr), GFP_KERNEL);
	if (tgt_attr == NULL) {
		PRINT_ERROR("Unable to allocate user (size %zd)",
			sizeof(*tgt_attr));
		res = -ENOMEM;
		goto out;
	}

	tgt_attr->target = target;

	tgt_attr->name = kstrdup(attr_info->name, GFP_KERNEL);
	if (tgt_attr->name == NULL) {
		PRINT_ERROR("Unable to allocate attr %s name/value (target %s)",
			attr_info->name, name);
		res = -ENOMEM;
		goto out_free;
	}

	list_add(&tgt_attr->attrs_list_entry, attrs_list);

	tgt_attr->attr.attr.name = tgt_attr->name;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
	tgt_attr->attr.attr.owner = THIS_MODULE;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	tgt_attr->attr.attr.key = &__key;
#endif
#endif
	tgt_attr->attr.attr.mode = attr_info->mode & (S_IRUGO | S_IWUGO);
	tgt_attr->attr.show = iscsi_attr_show;
	tgt_attr->attr.store = iscsi_attr_store;

	TRACE_DBG("tgt_attr %p, attr %p", tgt_attr, &tgt_attr->attr.attr);

	res = sysfs_create_file(
		(target != NULL) ? scst_sysfs_get_tgt_kobj(target->scst_tgt) :
				scst_sysfs_get_tgtt_kobj(&iscsi_template),
		&tgt_attr->attr.attr);
	if (res != 0) {
		PRINT_ERROR("Unable to create file '%s' for target '%s'",
			tgt_attr->attr.attr.name, name);
		goto out_del;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	list_del(&tgt_attr->attrs_list_entry);

out_free:
	kfree(tgt_attr->name);
	kfree(tgt_attr);
	goto out;
}

void __iscsi_del_attr(struct iscsi_target *target,
	struct iscsi_attr *tgt_attr)
{
	TRACE_ENTRY();

	TRACE_DBG("Deleting attr %s (target %s, tgt_attr %p, attr %p)",
		tgt_attr->name, (target != NULL) ? target->name : "global",
		tgt_attr, &tgt_attr->attr.attr);

	list_del(&tgt_attr->attrs_list_entry);

	sysfs_remove_file((target != NULL) ?
			scst_sysfs_get_tgt_kobj(target->scst_tgt) :
			scst_sysfs_get_tgtt_kobj(&iscsi_template),
		&tgt_attr->attr.attr);

	kfree(tgt_attr->name);
	kfree(tgt_attr);

	TRACE_EXIT();
	return;
}

/*
 * target_mgmt_mutex supposed to be locked. If target != 0, target_mutex
 * supposed to be locked as well.
 */
static int iscsi_del_attr(struct iscsi_target *target,
	const char *attr_name)
{
	int res = 0;
	struct iscsi_attr *tgt_attr, *a;
	struct list_head *attrs_list;

	TRACE_ENTRY();

	if (target != NULL)
		attrs_list = &target->attrs_list;
	else
		attrs_list = &iscsi_attrs_list;

	tgt_attr = NULL;
	list_for_each_entry(a, attrs_list, attrs_list_entry) {
		/* Both for sure NULL-terminated */
		if (strcmp(a->name, attr_name) == 0) {
			tgt_attr = a;
			break;
		}
	}

	if (tgt_attr == NULL) {
		PRINT_ERROR("attr %s not found (target %s)", attr_name,
			(target != NULL) ? target->name : "global");
		res = -ENOENT;
		goto out;
	}

	__iscsi_del_attr(target, tgt_attr);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* target_mgmt_mutex supposed to be locked */
static int iscsi_attr_cmd(void __user *ptr, unsigned int cmd)
{
	int rc, err = 0;
	struct iscsi_kern_attr_info info;
	struct iscsi_target *target;
	struct scst_sysfs_user_info *i = NULL;

	TRACE_ENTRY();

	rc = copy_from_user(&info, ptr, sizeof(info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out;
	}

	info.attr.name[sizeof(info.attr.name)-1] = '\0';

	if (info.cookie != 0) {
		i = scst_sysfs_user_get_info(info.cookie);
		TRACE_DBG("cookie %u, uinfo %p", info.cookie, i);
		if (i == NULL) {
			err = -EINVAL;
			goto out;
		}
	}

	target = target_lookup_by_id(info.tid);

	if (target != NULL)
		mutex_lock(&target->target_mutex);

	switch (cmd) {
	case ISCSI_ATTR_ADD:
		err = iscsi_add_attr(target, &info.attr);
		break;
	case ISCSI_ATTR_DEL:
		err = iscsi_del_attr(target, info.attr.name);
		break;
	default:
		sBUG();
	}

	if (target != NULL)
		mutex_unlock(&target->target_mutex);

	if (i != NULL) {
		i->info_status = err;
		complete(&i->info_completion);
	}

out:
	TRACE_EXIT_RES(err);
	return err;
}

#endif /* CONFIG_SCST_PROC */

/* target_mgmt_mutex supposed to be locked */
static int add_target(void __user *ptr)
{
	int err, rc;
	struct iscsi_kern_target_info *info;
#ifndef CONFIG_SCST_PROC
	struct scst_sysfs_user_info *uinfo;
#endif

	TRACE_ENTRY();

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL) {
		PRINT_ERROR("Can't alloc info (size %zd)", sizeof(*info));
		err = -ENOMEM;
		goto out;
	}

	rc = copy_from_user(info, ptr, sizeof(*info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out_free;
	}

	if (target_lookup_by_id(info->tid) != NULL) {
		PRINT_ERROR("Target %u already exist!", info->tid);
		err = -EEXIST;
		goto out_free;
	}

	info->name[sizeof(info->name)-1] = '\0';

#ifndef CONFIG_SCST_PROC
	if (info->cookie != 0) {
		uinfo = scst_sysfs_user_get_info(info->cookie);
		TRACE_DBG("cookie %u, uinfo %p", info->cookie, uinfo);
		if (uinfo == NULL) {
			err = -EINVAL;
			goto out_free;
		}
	} else
		uinfo = NULL;
#endif

	err = __add_target(info);

#ifndef CONFIG_SCST_PROC
	if (uinfo != NULL) {
		uinfo->info_status = err;
		complete(&uinfo->info_completion);
	}
#endif

out_free:
	kfree(info);

out:
	TRACE_EXIT_RES(err);
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int del_target(void __user *ptr)
{
	int err, rc;
	struct iscsi_kern_target_info info;
#ifndef CONFIG_SCST_PROC
	struct scst_sysfs_user_info *uinfo;
#endif

	TRACE_ENTRY();

	rc = copy_from_user(&info, ptr, sizeof(info));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		err = -EFAULT;
		goto out;
	}

	info.name[sizeof(info.name)-1] = '\0';

#ifndef CONFIG_SCST_PROC
	if (info.cookie != 0) {
		uinfo = scst_sysfs_user_get_info(info.cookie);
		TRACE_DBG("cookie %u, uinfo %p", info.cookie, uinfo);
		if (uinfo == NULL) {
			err = -EINVAL;
			goto out;
		}
	} else
		uinfo = NULL;
#endif

	err = __del_target(info.tid);

#ifndef CONFIG_SCST_PROC
	if (uinfo != NULL) {
		uinfo->info_status = err;
		complete(&uinfo->info_completion);
	}
#endif

out:
	TRACE_EXIT_RES(err);
	return err;
}

static int iscsi_register(void __user *arg)
{
	struct iscsi_kern_register_info reg;
	char ver[sizeof(ISCSI_SCST_INTERFACE_VERSION)+1];
	int res, rc;

	TRACE_ENTRY();

	rc = copy_from_user(&reg, arg, sizeof(reg));
	if (rc != 0) {
		PRINT_ERROR("%s", "Unable to get register info");
		res = -EFAULT;
		goto out;
	}

	rc = copy_from_user(ver, (void __user *)(unsigned long)reg.version,
				sizeof(ver));
	if (rc != 0) {
		PRINT_ERROR("%s", "Unable to get version string");
		res = -EFAULT;
		goto out;
	}
	ver[sizeof(ver)-1] = '\0';

	if (strcmp(ver, ISCSI_SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of user space %s (expected %s)",
			ver, ISCSI_SCST_INTERFACE_VERSION);
		res = -EINVAL;
		goto out;
	}

	memset(&reg, 0, sizeof(reg));
	reg.max_data_seg_len = ISCSI_CONN_IOV_MAX << PAGE_SHIFT;

	/*
	 * In iSCSI all LUs in a session share queue depth, so let's not
	 * limit it too much for thousands of LUs VMware and other similar
	 * systems cases.
	 */
#if 0
	reg.max_queued_cmds = scst_get_max_lun_commands(NULL, NO_SUCH_LUN);
#else
	reg.max_queued_cmds = MAX_NR_QUEUED_CMNDS;
#endif

	res = 0;

	rc = copy_to_user(arg, &reg, sizeof(reg));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy to user %d bytes", rc);
		res = -EFAULT;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long err;

	TRACE_ENTRY();

	if (cmd == REGISTER_USERD) {
		err = iscsi_register((void __user *)arg);
		goto out;
	}

	err = mutex_lock_interruptible(&target_mgmt_mutex);
	if (err < 0)
		goto out;

	switch (cmd) {
	case ADD_TARGET:
		err = add_target((void __user *)arg);
		break;

	case DEL_TARGET:
		err = del_target((void __user *)arg);
		break;

#ifndef CONFIG_SCST_PROC
	case ISCSI_ATTR_ADD:
	case ISCSI_ATTR_DEL:
		err = iscsi_attr_cmd((void __user *)arg, cmd);
		break;

	case MGMT_CMD_CALLBACK:
		err = mgmt_cmd_callback((void __user *)arg);
		break;
#endif

	case ISCSI_INITIATOR_ALLOWED:
		err = iscsi_initiator_allowed((void __user *)arg);
		break;

	case ADD_SESSION:
		err = add_session((void __user *)arg);
		break;

	case DEL_SESSION:
		err = del_session((void __user *)arg);
		break;

	case ISCSI_PARAM_SET:
		err = iscsi_params_config((void __user *)arg, 1);
		break;

	case ISCSI_PARAM_GET:
		err = iscsi_params_config((void __user *)arg, 0);
		break;

	case ADD_CONN:
		err = add_conn((void __user *)arg);
		break;

	case DEL_CONN:
		err = del_conn((void __user *)arg);
		break;

	default:
		PRINT_ERROR("Invalid ioctl cmd %x", cmd);
		err = -EINVAL;
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&target_mgmt_mutex);

out:
	TRACE_EXIT_RES(err);
	return err;
}

static int open(struct inode *inode, struct file *file)
{
	bool already;

	mutex_lock(&target_mgmt_mutex);
	already = (ctr_open_state != ISCSI_CTR_OPEN_STATE_CLOSED);
	if (!already)
		ctr_open_state = ISCSI_CTR_OPEN_STATE_OPEN;
	mutex_unlock(&target_mgmt_mutex);

	if (already) {
		PRINT_WARNING("%s", "Attempt to second open the control "
			"device!");
		return -EBUSY;
	} else
		return 0;
}

static int release(struct inode *inode, struct file *filp)
{
#ifndef CONFIG_SCST_PROC
	struct iscsi_attr *attr, *t;
#endif

	TRACE(TRACE_MGMT, "%s", "Releasing allocated resources");

	mutex_lock(&target_mgmt_mutex);
	ctr_open_state = ISCSI_CTR_OPEN_STATE_CLOSING;
	mutex_unlock(&target_mgmt_mutex);

	target_del_all();

	mutex_lock(&target_mgmt_mutex);

#ifndef CONFIG_SCST_PROC
	list_for_each_entry_safe(attr, t, &iscsi_attrs_list,
					attrs_list_entry) {
		__iscsi_del_attr(NULL, attr);
	}
#endif

	ctr_open_state = ISCSI_CTR_OPEN_STATE_CLOSED;

	mutex_unlock(&target_mgmt_mutex);

	return 0;
}

const struct file_operations ctr_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ioctl,
	.compat_ioctl	= ioctl,
	.open		= open,
	.release	= release,
};

#ifdef CONFIG_SCST_DEBUG
static void iscsi_dump_char(int ch, unsigned char *text, int *pos)
{
	int i = *pos;

	if (ch < 0) {
		while ((i % 16) != 0) {
			pr_cont("   ");
			text[i] = ' ';
			i++;
			if ((i % 16) == 0)
				pr_cont(" | %.16s |\n", text);
			else if ((i % 4) == 0)
				pr_cont(" |");
		}
		i = 0;
		goto out;
	}

	text[i] = (ch < 0x20 || (ch >= 0x80 && ch <= 0xa0)) ? ' ' : ch;
	pr_cont(" %02x", ch);
	i++;
	if ((i % 16) == 0) {
		pr_cont(" | %.16s |\n", text);
		i = 0;
	} else if ((i % 4) == 0)
		pr_cont(" |");

out:
	*pos = i;
	return;
}

void iscsi_dump_pdu(struct iscsi_pdu *pdu)
{
	unsigned char text[16];
	int pos = 0;

	if (trace_flag & TRACE_D_DUMP_PDU) {
		unsigned char *buf;
		int i;

		buf = (void *)&pdu->bhs;
		printk(KERN_DEBUG "BHS: (%p,%zd)\n", buf, sizeof(pdu->bhs));
		for (i = 0; i < (int)sizeof(pdu->bhs); i++)
			iscsi_dump_char(*buf++, text, &pos);
		iscsi_dump_char(-1, text, &pos);

		buf = (void *)pdu->ahs;
		printk(KERN_DEBUG "AHS: (%p,%d)\n", buf, pdu->ahssize);
		for (i = 0; i < pdu->ahssize; i++)
			iscsi_dump_char(*buf++, text, &pos);
		iscsi_dump_char(-1, text, &pos);

		printk(KERN_DEBUG "Data: (%d)\n", pdu->datasize);
	}
}

unsigned long iscsi_get_flow_ctrl_or_mgmt_dbg_log_flag(struct iscsi_cmnd *cmnd)
{
	unsigned long flag;

	if (cmnd->cmd_req != NULL)
		cmnd = cmnd->cmd_req;

	if (cmnd->scst_cmd == NULL)
		flag = TRACE_MGMT_DEBUG;
	else {
		int status = scst_cmd_get_status(cmnd->scst_cmd);
		if ((status == SAM_STAT_TASK_SET_FULL) ||
		    (status == SAM_STAT_BUSY))
			flag = TRACE_FLOW_CONTROL;
		else
			flag = TRACE_MGMT_DEBUG;
	}
	return flag;
}

#endif /* CONFIG_SCST_DEBUG */
