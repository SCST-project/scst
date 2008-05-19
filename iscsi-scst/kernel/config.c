/*
 *  Copyright (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 Vladislav Bolkhovitin
 *  Copyright (C) 2007 CMS Distribution Limited
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

#include <linux/proc_fs.h>

#include "iscsi.h"

#define ISCSI_PROC_VERSION_NAME		"version"

#if defined(DEBUG) || defined(TRACING)

#define ISCSI_PROC_LOG_ENTRY_NAME	"trace_level"

#include <linux/proc_fs.h>

static struct scst_proc_log iscsi_proc_local_trace_tbl[] =
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
		iscsi_proc_local_trace_tbl);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t iscsi_proc_log_entry_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, &trace_flag,
		ISCSI_DEFAULT_LOG_FLAGS, iscsi_proc_local_trace_tbl);

	TRACE_EXIT_RES(res);
	return res;
}
#endif

static int iscsi_version_info_show(struct seq_file *seq, void *v)
{
	TRACE_ENTRY();

	seq_printf(seq, "%s\n", ISCSI_VERSION_STRING);

#ifdef EXTRACHECKS
	seq_printf(seq, "EXTRACHECKS\n");
#endif

#ifdef TRACING
	seq_printf(seq, "TRACING\n");
#endif

#ifdef DEBUG
	seq_printf(seq, "DEBUG\n");
#endif

#ifdef DEBUG_DIGEST_FAILURES
	seq_printf(seq, "DEBUG_DIGEST_FAILURES\n");
#endif

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data iscsi_version_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = iscsi_version_info_show,
};

#if defined(DEBUG) || defined(TRACING)
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

#if defined(DEBUG) || defined(TRACING)
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

#if defined(DEBUG) || defined(TRACING)
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
#if defined(DEBUG) || defined(TRACING)
		remove_proc_entry(ISCSI_PROC_LOG_ENTRY_NAME, root);
#endif
		remove_proc_entry(ISCSI_PROC_VERSION_NAME, root);
	}

	TRACE_EXIT();
	return;
}

struct proc_entries {
	const char *name;
	struct file_operations *fops;
};

static struct proc_entries iscsi_proc_entries[] =
{
	{"session", &session_seq_fops},
};

static struct proc_dir_entry *proc_iscsi_dir;

void iscsi_procfs_exit(void)
{
	int i;

	if (!proc_iscsi_dir)
		return;

	for (i = 0; i < ARRAY_SIZE(iscsi_proc_entries); i++)
		remove_proc_entry(iscsi_proc_entries[i].name, proc_iscsi_dir);

	iscsi_proc_log_entry_clean(&iscsi_template);
}

int __init iscsi_procfs_init(void)
{
	int i, err = 0;
	struct proc_dir_entry *ent;

	proc_iscsi_dir = scst_proc_get_tgt_root(&iscsi_template);
	if (proc_iscsi_dir == NULL) {
		err = -ESRCH;
		goto out;
	}

	proc_iscsi_dir->owner = THIS_MODULE;

	err = iscsi_proc_log_entry_build(&iscsi_template);
	if (err < 0)
		goto out;

	for (i = 0; i < ARRAY_SIZE(iscsi_proc_entries); i++) {
		ent = create_proc_entry(iscsi_proc_entries[i].name, 0, proc_iscsi_dir);
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

/* target_mutex supposed to be locked */
static int get_conn_info(struct iscsi_target *target, unsigned long ptr)
{
	int err;
	struct iscsi_session *session;
	struct conn_info info;
	struct iscsi_conn *conn;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return err;

	session = session_lookup(target, info.sid);
	if (!session)
		return -ENOENT;
	conn = conn_lookup(session, info.cid);

	info.cid = conn->cid;
	info.stat_sn = conn->stat_sn;
	info.exp_stat_sn = conn->exp_stat_sn;

	if (copy_to_user((void *) ptr, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

/* target_mutex supposed to be locked */
static int add_conn(struct iscsi_target *target, unsigned long ptr)
{
	int err;
	struct iscsi_session *session;
	struct conn_info info;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return err;

	if (!(session = session_lookup(target, info.sid)))
		return -ENOENT;

	return conn_add(session, &info);
}

/* target_mutex supposed to be locked */
static int del_conn(struct iscsi_target *target, unsigned long ptr)
{
	int err;
	struct iscsi_session *session;
	struct conn_info info;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return err;

	if (!(session = session_lookup(target, info.sid)))
		return -ENOENT;

	return conn_del(session, &info);
}

/* target_mutex supposed to be locked */
static int get_session_info(struct iscsi_target *target, unsigned long ptr)
{
	int err;
	struct iscsi_session *session;
	struct session_info info;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return err;

	session = session_lookup(target, info.sid);

	if (!session)
		return -ENOENT;

	info.exp_cmd_sn = session->exp_cmd_sn;

	if (copy_to_user((void *) ptr, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

/* target_mutex supposed to be locked */
static int add_session(struct iscsi_target *target, unsigned long ptr)
{
	int err;
	struct session_info info;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return err;

	info.initiator_name[ISCSI_NAME_LEN-1] = '\0';
	info.user_name[ISCSI_NAME_LEN-1] = '\0';

	return session_add(target, &info);
}

/* target_mutex supposed to be locked */
static int del_session(struct iscsi_target *target, unsigned long ptr)
{
	int err;
	struct session_info info;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return err;

	return session_del(target, info.sid);
}

/* target_mutex supposed to be locked */
static int iscsi_param_config(struct iscsi_target *target, unsigned long ptr, int set)
{
	int err;
	struct iscsi_param_info info;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		goto out;

	if ((err = iscsi_param_set(target, &info, set)) < 0)
		goto out;

	if (!set)
		err = copy_to_user((void *) ptr, &info, sizeof(info));

out:
	return err;
}

/* target_mgmt_mutex supposed to be locked */
static int add_target(unsigned long ptr)
{
	int err;
	struct target_info info;

	if ((err = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return err;

	if (!(err = target_add(&info)))
		err = copy_to_user((void *) ptr, &info, sizeof(info));

	return err;
}

static int iscsi_check_version(unsigned long arg)
{
	char ver[sizeof(ISCSI_SCST_INTERFACE_VERSION)+1];
	int res;

	res = copy_from_user(ver, (void*)arg, sizeof(ver));
	if (res < 0) {
		PRINT_ERROR("%s", "Unable to get version string");
		goto out;
	}
	ver[sizeof(ver)-1] = '\0';

	if (strcmp(ver, ISCSI_SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of user space %s (needed %s)",
			ver, ISCSI_SCST_INTERFACE_VERSION);
		res = -EINVAL;
		goto out;
	}

out:
	return res;
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct iscsi_target *target = NULL;
	long err;
	u32 id;

	if (cmd == REGISTER_USERD) {
		err = iscsi_check_version(arg);
		goto out;
	}

	if ((err = get_user(id, (u32 *) arg)) != 0)
		goto out;

	if ((err = mutex_lock_interruptible(&target_mgmt_mutex)) < 0)
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
		err = add_target(arg);
		goto out_unlock;
	}

	if (!target) {
		PRINT_ERROR("can't find the target %u", id);
		err = -EINVAL;
		goto out_unlock;
	}

	mutex_lock(&target->target_mutex);

	switch (cmd) {
	case ADD_SESSION:
		err = add_session(target, arg);
		break;

	case DEL_SESSION:
		err = del_session(target, arg);
		break;

	case GET_SESSION_INFO:
		err = get_session_info(target, arg);
		break;

	case ISCSI_PARAM_SET:
		err = iscsi_param_config(target, arg, 1);
		break;

	case ISCSI_PARAM_GET:
		err = iscsi_param_config(target, arg, 0);
		break;

	case ADD_CONN:
		err = add_conn(target, arg);
		break;

	case DEL_CONN:
		err = del_conn(target, arg);
		break;

	case GET_CONN_INFO:
		err = get_conn_info(target, arg);
		break;

	default:
		PRINT_ERROR("invalid ioctl cmd %x", cmd);
		err = -EINVAL;
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

struct file_operations ctr_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ioctl,
	.compat_ioctl	= ioctl,
	.release	= release,
};

#ifdef DEBUG
void iscsi_dump_iov(struct msghdr *msg)
{
	if (trace_flag & TRACE_D_IOV) {
		int i;
		printk("%p, %zd\n", msg->msg_iov, msg->msg_iovlen);
		for (i = 0; i < min_t(size_t, msg->msg_iovlen,
				ISCSI_CONN_IOV_MAX); i++) {
			printk("%d: %p,%zd\n", i, msg->msg_iov[i].iov_base,
				msg->msg_iov[i].iov_len);
		}
	}
}

static void iscsi_dump_char(int ch)
{
	static unsigned char text[16];
	static int i = 0;

	if (ch < 0) {
		while ((i % 16) != 0) {
			printk("   ");
			text[i] = ' ';
			i++;
			if ((i % 16) == 0)
				printk(" | %.16s |\n", text);
			else if ((i % 4) == 0)
				printk(" |");
		}
		i = 0;
		return;
	}

	text[i] = (ch < 0x20 || (ch >= 0x80 && ch <= 0xa0)) ? ' ' : ch;
	printk(" %02x", ch);
	i++;
	if ((i % 16) == 0) {
		printk(" | %.16s |\n", text);
		i = 0;
	} else if ((i % 4) == 0)
		printk(" |");
}

void iscsi_dump_pdu(struct iscsi_pdu *pdu)
{
	if (trace_flag & TRACE_D_DUMP_PDU) {
		unsigned char *buf;
		int i;

		buf = (void *)&pdu->bhs;
		printk("BHS: (%p,%zd)\n", buf, sizeof(pdu->bhs));
		for (i = 0; i < sizeof(pdu->bhs); i++)
			iscsi_dump_char(*buf++);
		iscsi_dump_char(-1);

		buf = (void *)pdu->ahs;
		printk("AHS: (%p,%d)\n", buf, pdu->ahssize);
		for (i = 0; i < pdu->ahssize; i++)
			iscsi_dump_char(*buf++);
		iscsi_dump_char(-1);

		printk("Data: (%d)\n", pdu->datasize);
	}
}
#endif /* DEBUG */
