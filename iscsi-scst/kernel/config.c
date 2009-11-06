/*
 *  Copyright (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 - 2009 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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

#include "iscsi.h"

#ifdef CONFIG_SCST_PROC

#include <linux/proc_fs.h>

#define ISCSI_PROC_VERSION_NAME		"version"

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define ISCSI_PROC_LOG_ENTRY_NAME	"trace_level"

static struct scst_trace_log iscsi_local_trace_tbl[] =
{
    { TRACE_D_READ,		"d_read" },
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
#endif

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

static struct proc_entries iscsi_proc_entries[] =
{
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
		ent = create_proc_entry(iscsi_proc_entries[i].name, 0,
					proc_iscsi_dir);
		if (ent)
			ent->proc_fops = iscsi_proc_entries[i].fops;
		else {
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

const struct attribute *iscsi_attrs[] = {
	&iscsi_version_attr.attr,
	NULL,
};

#endif /* CONFIG_SCST_PROC */

/* target_mutex supposed to be locked */
static int add_conn(struct iscsi_target *target, void __user *ptr)
{
	int err;
	struct iscsi_session *session;
	struct iscsi_kern_conn_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		return err;

	session = session_lookup(target, info.sid);
	if (!session)
		return -ENOENT;

	return conn_add(session, &info);
}

/* target_mutex supposed to be locked */
static int del_conn(struct iscsi_target *target, void __user *ptr)
{
	int err;
	struct iscsi_session *session;
	struct iscsi_kern_conn_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		return err;

	session = session_lookup(target, info.sid);
	if (!session) {
		PRINT_ERROR("Session %llx not found",
			(long long unsigned int)info.sid);
		return -ENOENT;
	}

	return conn_del(session, &info);
}

/* target_mgmt_mutex supposed to be locked */
static int add_session(struct iscsi_target *target, void __user *ptr)
{
	int err;
	struct iscsi_kern_session_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		return err;

	info.initiator_name[ISCSI_NAME_LEN-1] = '\0';
	info.user_name[ISCSI_NAME_LEN-1] = '\0';

	return session_add(target, &info);
}

/* target_mutex supposed to be locked */
static int del_session(struct iscsi_target *target, void __user *ptr)
{
	int err;
	struct iscsi_kern_session_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		return err;

	return session_del(target, info.sid);
}

/* target_mutex supposed to be locked */
static int iscsi_param_config(struct iscsi_target *target, void __user *ptr,
			      int set)
{
	int err;
	struct iscsi_kern_param_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		goto out;

	err = iscsi_param_set(target, &info, set);
	if (err < 0)
		goto out;

	if (!set)
		err = copy_to_user(ptr, &info, sizeof(info));

out:
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int enable_target(void __user *ptr)
{
	int err;
	struct iscsi_kern_target_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		return err;

	err = target_enable(&info);

	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int disable_target(void __user *ptr)
{
	int err;
	struct iscsi_kern_target_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		return err;

	err = target_disable(&info);

	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int add_target(void __user *ptr)
{
	int err;
	struct iscsi_kern_target_info info;

	err = copy_from_user(&info, ptr, sizeof(info));
	if (err < 0)
		return err;

	err = target_add(&info);
	if (!err)
		err = copy_to_user(ptr, &info, sizeof(info));

	return err;
}

static int iscsi_check_version(void __user *arg)
{
	struct iscsi_kern_register_info reg;
	char ver[sizeof(ISCSI_SCST_INTERFACE_VERSION)+1];
	int res;

	res = copy_from_user(&reg, arg, sizeof(reg));
	if (res < 0) {
		PRINT_ERROR("%s", "Unable to get register info");
		goto out;
	}

	res = copy_from_user(ver, (void __user *)(unsigned long)reg.version,
				sizeof(ver));
	if (res < 0) {
		PRINT_ERROR("%s", "Unable to get version string");
		goto out;
	}
	ver[sizeof(ver)-1] = '\0';

	if (strcmp(ver, ISCSI_SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of user space %s (expected %s)",
			ver, ISCSI_SCST_INTERFACE_VERSION);
		res = -EINVAL;
		goto out;
	}

	res = ISCSI_CONN_IOV_MAX << PAGE_SHIFT;

out:
	return res;
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct iscsi_target *target = NULL;
	long err;
	u32 id;

	switch (cmd) {
	case ADD_TARGET:
	case DEL_TARGET:
	case ENABLE_TARGET:
	case DISABLE_TARGET:
	case ADD_SESSION:
	case DEL_SESSION:
	case ISCSI_PARAM_SET:
	case ISCSI_PARAM_GET:
	case ADD_CONN:
	case DEL_CONN:
		break;

	case REGISTER_USERD:
		err = iscsi_check_version((void __user *) arg);
		goto out;

	default:
		PRINT_ERROR("Invalid ioctl cmd %x", cmd);
		err = -EINVAL;
		goto out;
	}

	err = get_user(id, (u32 __user *) arg);
	if (err != 0)
		goto out;

	err = mutex_lock_interruptible(&target_mgmt_mutex);
	if (err < 0)
		goto out;

	if (cmd == DEL_TARGET) {
		err = target_del(id);
		goto out_unlock;
	}

	target = target_lookup_by_id(id);

	if (cmd == ADD_TARGET)
		if (target) {
			err = -EEXIST;
			PRINT_ERROR("Target %u already exist!", id);
			goto out_unlock;
		}

	switch (cmd) {
	case ADD_TARGET:
		err = add_target((void __user *) arg);
		goto out_unlock;
	case ENABLE_TARGET:
		err = enable_target((void __user *) arg);
		goto out_unlock;
	case DISABLE_TARGET:
		err = disable_target((void __user *) arg);
		goto out_unlock;
	case ADD_SESSION:
		err = add_session(target, (void __user *) arg);
		goto out_unlock;
	}

	if (!target) {
		PRINT_ERROR("Can't find the target %u", id);
		err = -EINVAL;
		goto out_unlock;
	}

	mutex_lock(&target->target_mutex);

	switch (cmd) {
	case DEL_SESSION:
		err = del_session(target, (void __user *) arg);
		break;

	case ISCSI_PARAM_SET:
		err = iscsi_param_config(target, (void __user *) arg, 1);
		break;

	case ISCSI_PARAM_GET:
		err = iscsi_param_config(target, (void __user *) arg, 0);
		break;

	case ADD_CONN:
		err = add_conn(target, (void __user *) arg);
		break;

	case DEL_CONN:
		err = del_conn(target, (void __user *) arg);
		break;

	default:
		sBUG();
		break;
	}

	mutex_unlock(&target->target_mutex);

out_unlock:
	mutex_unlock(&target_mgmt_mutex);

out:
	return err;
}

static int release(struct inode *inode, struct file *filp)
{
	TRACE(TRACE_MGMT, "%s", "Releasing allocated resources");
	target_del_all();
	return 0;
}

const struct file_operations ctr_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ioctl,
	.compat_ioctl	= ioctl,
	.release	= release,
};

#ifdef CONFIG_SCST_DEBUG
static void iscsi_dump_char(int ch, unsigned char *text, int *pos)
{
	int i = *pos;

	if (ch < 0) {
		while ((i % 16) != 0) {
			printk(KERN_CONT "   ");
			text[i] = ' ';
			i++;
			if ((i % 16) == 0)
				printk(KERN_CONT " | %.16s |\n", text);
			else if ((i % 4) == 0)
				printk(KERN_CONT " |");
		}
		i = 0;
		goto out;
	}

	text[i] = (ch < 0x20 || (ch >= 0x80 && ch <= 0xa0)) ? ' ' : ch;
	printk(KERN_CONT " %02x", ch);
	i++;
	if ((i % 16) == 0) {
		printk(KERN_CONT " | %.16s |\n", text);
		i = 0;
	} else if ((i % 4) == 0)
		printk(KERN_CONT " |");

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
		for (i = 0; i < sizeof(pdu->bhs); i++)
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
#endif /* CONFIG_SCST_DEBUG */
