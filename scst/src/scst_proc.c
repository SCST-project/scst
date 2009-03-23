/*
 *  scst_proc.c
 *
 *  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
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

#include <linux/module.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "scst.h"
#include "scst_priv.h"
#include "scst_mem.h"

static int scst_proc_init_groups(void);
static void scst_proc_cleanup_groups(void);
static int scst_proc_assign_handler(char *buf);
static int scst_proc_group_add(const char *p);
static int scst_proc_del_free_acg(struct scst_acg *acg, int remove_proc);

static struct scst_proc_data scst_version_proc_data;
static struct scst_proc_data scst_help_proc_data;
static struct scst_proc_data scst_sgv_proc_data;
static struct scst_proc_data scst_groups_names_proc_data;
static struct scst_proc_data scst_groups_devices_proc_data;
static struct scst_proc_data scst_sessions_proc_data;
static struct scst_proc_data scst_dev_handler_type_proc_data;
static struct scst_proc_data scst_tgt_proc_data;
static struct scst_proc_data scst_threads_proc_data;
static struct scst_proc_data scst_scsi_tgt_proc_data;
static struct scst_proc_data scst_dev_handler_proc_data;

/*
 * Must be less than 4K page size, since our output routines
 * use some slack for overruns
 */
#define SCST_PROC_BLOCK_SIZE (PAGE_SIZE - 512)

#define SCST_PROC_LOG_ENTRY_NAME		"trace_level"
#define SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME	"type"
#define SCST_PROC_VERSION_NAME			"version"
#define SCST_PROC_SESSIONS_NAME			"sessions"
#define SCST_PROC_HELP_NAME			"help"
#define SCST_PROC_THREADS_NAME			"threads"
#define SCST_PROC_GROUPS_ENTRY_NAME		"groups"
#define SCST_PROC_GROUPS_DEVICES_ENTRY_NAME	"devices"
#define SCST_PROC_GROUPS_USERS_ENTRY_NAME	"names"

#ifdef CONFIG_SCST_MEASURE_LATENCY
#define SCST_PROC_LAT_ENTRY_NAME		"latency"
#endif

#define SCST_PROC_ACTION_ALL		 1
#define SCST_PROC_ACTION_NONE		 2
#define SCST_PROC_ACTION_DEFAULT	 3
#define SCST_PROC_ACTION_SET		 4
#define SCST_PROC_ACTION_ADD		 5
#define SCST_PROC_ACTION_CLEAR		 6
#define SCST_PROC_ACTION_DEL		 7
#define SCST_PROC_ACTION_VALUE		 8
#define SCST_PROC_ACTION_ASSIGN		 9
#define SCST_PROC_ACTION_ADD_GROUP	10
#define SCST_PROC_ACTION_DEL_GROUP	11

static struct proc_dir_entry *scst_proc_scsi_tgt;
static struct proc_dir_entry *scst_proc_groups_root;

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static struct scst_proc_data scst_log_proc_data;

static struct scst_proc_log scst_proc_trace_tbl[] =
{
    { TRACE_OUT_OF_MEM,		"out_of_mem" },
    { TRACE_MINOR,		"minor" },
    { TRACE_SG_OP,		"sg" },
    { TRACE_MEMORY,		"mem" },
    { TRACE_BUFF,		"buff" },
    { TRACE_ENTRYEXIT,		"entryexit" },
    { TRACE_PID,		"pid" },
    { TRACE_LINE,		"line" },
    { TRACE_FUNCTION,		"function" },
    { TRACE_DEBUG,		"debug" },
    { TRACE_SPECIAL,		"special" },
    { TRACE_SCSI,		"scsi" },
    { TRACE_MGMT,		"mgmt" },
    { TRACE_MGMT_MINOR,		"mgmt_minor" },
    { TRACE_MGMT_DEBUG,		"mgmt_dbg" },
    { 0,			NULL }
};

static struct scst_proc_log scst_proc_local_trace_tbl[] =
{
    { TRACE_RTRY,		"retry" },
    { TRACE_SCSI_SERIALIZING,	"scsi_serializing" },
    { TRACE_RCV_BOT,		"recv_bot" },
    { TRACE_SND_BOT,		"send_bot" },
    { TRACE_RCV_TOP,		"recv_top" },
    { TRACE_SND_TOP,		"send_top" },
    { 0,			NULL }
};
#endif

static char *scst_proc_help_string =
"   echo \"assign H:C:I:L HANDLER_NAME\" >/proc/scsi_tgt/scsi_tgt\n"
"\n"
"   echo \"add_group GROUP\" >/proc/scsi_tgt/scsi_tgt\n"
"   echo \"del_group GROUP\" >/proc/scsi_tgt/scsi_tgt\n"
"\n"
"   echo \"add|del H:C:I:L lun [READ_ONLY]\""
" >/proc/scsi_tgt/groups/GROUP/devices\n"
"   echo \"add|del V_NAME lun [READ_ONLY]\""
" >/proc/scsi_tgt/groups/GROUP/devices\n"
"   echo \"clear\" >/proc/scsi_tgt/groups/GROUP/devices\n"
"\n"
"   echo \"add|del NAME\" >/proc/scsi_tgt/groups/GROUP/names\n"
"   echo \"clear\" >/proc/scsi_tgt/groups/GROUP/names\n"
"\n"
"   echo \"DEC|0xHEX|0OCT\" >/proc/scsi_tgt/threads\n"
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
"\n"
"   echo \"all|none|default\" >/proc/scsi_tgt/[DEV_HANDLER_NAME/]trace_level\n"
"   echo \"value DEC|0xHEX|0OCT\""
" >/proc/scsi_tgt/[DEV_HANDLER_NAME/]trace_level\n"
"   echo \"set|add|del TOKEN\""
" >/proc/scsi_tgt/[DEV_HANDLER_NAME/]trace_level\n"
"     where TOKEN is one of [debug,function,line,pid,entryexit,\n"
"                            buff,mem,sg,out_of_mem,special,scsi,mgmt,minor]\n"
"     Additionally for /proc/scsi_tgt/trace_level there are these TOKENs\n"
"       [scsi_serializing,retry,recv_bot,send_bot,recv_top,send_top]\n"
#endif
;

static char *scst_proc_dev_handler_type[] =
{
    "Direct-access device (e.g., magnetic disk)",
    "Sequential-access device (e.g., magnetic tape)",
    "Printer device",
    "Processor device",
    "Write-once device (e.g., some optical disks)",
    "CD-ROM device",
    "Scanner device (obsolete)",
    "Optical memory device (e.g., some optical disks)",
    "Medium changer device (e.g., jukeboxes)",
    "Communications device (obsolete)",
    "Defined by ASC IT8 (Graphic arts pre-press devices)",
    "Defined by ASC IT8 (Graphic arts pre-press devices)",
    "Storage array controller device (e.g., RAID)",
    "Enclosure services device",
    "Simplified direct-access device (e.g., magnetic disk)",
    "Optical card reader/writer device"
};

static DEFINE_MUTEX(scst_proc_mutex);

#include <linux/ctype.h>

#if !defined(CONFIG_PPC) && (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22))

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static int strcasecmp(const char *s1, const char *s2)
{
	int c1, c2;
	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while (c1 == c2 && c1 != 0);
	return c1 - c2;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
static int strncasecmp(const char *s1, const char *s2, int n)
#else
static int strncasecmp(const char *s1, const char *s2, size_t n)
#endif
{
	int c1, c2;
	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}

#endif /* !CONFIG_PPC && (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)) */

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static DEFINE_MUTEX(scst_log_mutex);

int scst_proc_log_entry_write(struct file *file, const char __user *buf,
	unsigned long length, unsigned long *log_level,
	unsigned long default_level, const struct scst_proc_log *tbl)
{
	int res = length;
	int action;
	unsigned long level = 0, oldlevel;
	char *buffer, *p, *e;
	const struct scst_proc_log *t;
	char *data = (char *)PDE(file->f_dentry->d_inode)->data;

	TRACE_ENTRY();

	if (length > SCST_PROC_BLOCK_SIZE) {
		res = -EOVERFLOW;
		goto out;
	}
	if (!buf) {
		res = -EINVAL;
		goto out;
	}
	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}
	if (copy_from_user(buffer, buf, length)) {
		res = -EFAULT;
		goto out_free;
	}
	if (length < PAGE_SIZE) {
		buffer[length] = '\0';
	} else if (buffer[PAGE_SIZE-1]) {
		res = -EINVAL;
		goto out_free;
	}

	/*
	 * Usage:
	 *   echo "all|none|default" >/proc/scsi_tgt/trace_level
	 *   echo "value DEC|0xHEX|0OCT" >/proc/scsi_tgt/trace_level
	 *   echo "set|add|clear|del TOKEN" >/proc/scsi_tgt/trace_level
	 * where TOKEN is one of [debug,function,line,pid,entryexit,
	 *                        buff,mem,sg,out_of_mem,retry,
	 *                        scsi_serializing,special,scsi,mgmt,minor,...]
	 */
	p = buffer;
	if (!strncasecmp("all", p, 3)) {
		action = SCST_PROC_ACTION_ALL;
	} else if (!strncasecmp("none", p, 4) || !strncasecmp("null", p, 4)) {
		action = SCST_PROC_ACTION_NONE;
	} else if (!strncasecmp("default", p, 7)) {
		action = SCST_PROC_ACTION_DEFAULT;
	} else if (!strncasecmp("set ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_SET;
	} else if (!strncasecmp("add ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_ADD;
	} else if (!strncasecmp("del ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_DEL;
	} else if (!strncasecmp("value ", p, 6)) {
		p += 6;
		action = SCST_PROC_ACTION_VALUE;
	} else {
		if (p[strlen(p) - 1] == '\n')
			p[strlen(p) - 1] = '\0';
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	switch (action) {
	case SCST_PROC_ACTION_ALL:
		level = TRACE_ALL;
		break;
	case SCST_PROC_ACTION_DEFAULT:
		level = default_level;
		break;
	case SCST_PROC_ACTION_NONE:
		level = TRACE_NULL;
		break;
	case SCST_PROC_ACTION_SET:
	case SCST_PROC_ACTION_ADD:
	case SCST_PROC_ACTION_DEL:
		while (isspace(*p) && *p != '\0')
			p++;
		e = p;
		while (!isspace(*e) && *e != '\0')
			e++;
		*e = 0;
		if (tbl) {
			t = tbl;
			while (t->token) {
				if (!strcasecmp(p, t->token)) {
					level = t->val;
					break;
				}
				t++;
			}
		}
		if (level == 0) {
			t = scst_proc_trace_tbl;
			while (t->token) {
				if (!strcasecmp(p, t->token)) {
					level = t->val;
					break;
				}
				t++;
			}
		}
		if (level == 0) {
			PRINT_ERROR("Unknown token \"%s\"", p);
			res = -EINVAL;
			goto out_free;
		}
		break;
	case SCST_PROC_ACTION_VALUE:
		while (isspace(*p) && *p != '\0')
			p++;
		level = simple_strtoul(p, NULL, 0);
		break;
	}

	oldlevel = *log_level;

	switch (action) {
	case SCST_PROC_ACTION_ADD:
		*log_level |= level;
		break;
	case SCST_PROC_ACTION_DEL:
		*log_level &= ~level;
		break;
	default:
		*log_level = level;
		break;
	}

	PRINT_INFO("Changed trace level for \"%s\": "
		   "old 0x%08lx, new 0x%08lx",
		   (char *)data, oldlevel, *log_level);

out_free:
	free_page((unsigned long)buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_proc_log_entry_write);

static ssize_t scst_proc_scsi_tgt_gen_write_log(struct file *file,
					const char __user *buf,
					size_t length, loff_t *off)
{
	int res;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_log_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	res = scst_proc_log_entry_write(file, buf, length,
		&trace_flag, SCST_DEFAULT_LOG_FLAGS,
		scst_proc_local_trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

#ifdef CONFIG_SCST_MEASURE_LATENCY

static int lat_info_show(struct seq_file *seq, void *v)
{
	int res = 0;
	struct scst_acg *acg;
	struct scst_session *sess;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	seq_printf(seq, "%-20s %-45s %-15s %15s\n",
		   "Target name",
		   "Initiator name",
		   "SCST latency",
		   "Processing latency (us)");

	list_for_each_entry(acg, &scst_acg_list, scst_acg_list_entry) {
		list_for_each_entry(sess, &acg->acg_sess_list,
				acg_sess_list_entry) {
			unsigned long proc_lat = 0, scst_lat = 0;
			uint64_t proc_time, scst_time;
			unsigned int processed_cmds;

			spin_lock_bh(&sess->meas_lock);
			proc_time = sess->processing_time;
			scst_time = sess->scst_time;
			processed_cmds = sess->processed_cmds;
			spin_unlock_bh(&sess->meas_lock);

			TRACE_DBG("sess %p, scst_time %lld, proc_time %lld, "
				"processed_cmds %d", sess, scst_time,
				proc_time, processed_cmds);

#if BITS_PER_LONG == 32
			/* Unfortunately, do_div() doesn't work too well */
			while (((proc_time & 0xFFFFFFFF00000000LL) != 0) ||
			       ((scst_time & 0xFFFFFFFF00000000LL) != 0)) {
				TRACE_DBG("%s", "Gathered time too big");
				proc_time >>= 1;
				scst_time >>= 1;
				processed_cmds >>= 1;
			}
#endif

			if (sess->processed_cmds != 0) {
				proc_lat = (unsigned long)proc_time /
						processed_cmds;
				scst_lat = (unsigned long)scst_time /
						processed_cmds;
			}

			seq_printf(seq, "%-20s %-45s %-15ld %-15ld\n",
					sess->tgt->tgtt->name,
					sess->initiator_name,
					scst_lat, proc_lat);
		}
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_proc_scsi_tgt_gen_write_lat(struct file *file,
					const char __user *buf,
					size_t length, loff_t *off)
{
	int res = length;
	struct scst_acg *acg;
	struct scst_session *sess;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	list_for_each_entry(acg, &scst_acg_list, scst_acg_list_entry) {
		list_for_each_entry(sess, &acg->acg_sess_list,
				acg_sess_list_entry) {
			PRINT_INFO("Zeroing latency statistics for initiator"
				" %s",
				sess->initiator_name);
			spin_lock_bh(&sess->meas_lock);
			sess->processing_time = 0;
			sess->processed_cmds = 0;
			spin_unlock_bh(&sess->meas_lock);
		}
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_lat_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_scsi_tgt_gen_write_lat)
	.show = lat_info_show,
	.data = "scsi_tgt",
};

#endif /* CONFIG_SCST_MEASURE_LATENCY */

static int __init scst_proc_init_module_log(void)
{
	int res = 0;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) || \
    defined(CONFIG_SCST_MEASURE_LATENCY)
	struct proc_dir_entry *generic;
#endif

	TRACE_ENTRY();

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	generic = scst_create_proc_entry(scst_proc_scsi_tgt,
					 SCST_PROC_LOG_ENTRY_NAME,
					 &scst_log_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_LOG_ENTRY_NAME);
		res = -ENOMEM;
	}
#endif

#ifdef CONFIG_SCST_MEASURE_LATENCY
	if (res == 0) {
		generic = scst_create_proc_entry(scst_proc_scsi_tgt,
					 SCST_PROC_LAT_ENTRY_NAME,
					 &scst_lat_proc_data);
		if (!generic) {
			PRINT_ERROR("cannot init /proc/%s/%s",
				    SCST_PROC_ENTRY_NAME,
				    SCST_PROC_LAT_ENTRY_NAME);
			res = -ENOMEM;
		}
	}
#endif

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_proc_cleanup_module_log(void)
{
	TRACE_ENTRY();

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	remove_proc_entry(SCST_PROC_LOG_ENTRY_NAME, scst_proc_scsi_tgt);
#endif

#ifdef CONFIG_SCST_MEASURE_LATENCY
	remove_proc_entry(SCST_PROC_LAT_ENTRY_NAME, scst_proc_scsi_tgt);
#endif

	TRACE_EXIT();
	return;
}

static int scst_proc_group_add_tree(struct scst_acg *acg, const char *name)
{
	int res = 0;
	struct proc_dir_entry *generic;

	TRACE_ENTRY();

	acg->acg_proc_root = proc_mkdir(name, scst_proc_groups_root);
	if (acg->acg_proc_root == NULL) {
		PRINT_ERROR("Not enough memory to register %s entry in "
			       "/proc/%s/%s", name, SCST_PROC_ENTRY_NAME,
			       SCST_PROC_GROUPS_ENTRY_NAME);
		goto out;
	}

	scst_groups_devices_proc_data.data = acg;
	generic = scst_create_proc_entry(acg->acg_proc_root,
					 SCST_PROC_GROUPS_DEVICES_ENTRY_NAME,
					 &scst_groups_devices_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s/%s/%s",
			       SCST_PROC_ENTRY_NAME,
			       SCST_PROC_GROUPS_ENTRY_NAME,
			       name, SCST_PROC_GROUPS_DEVICES_ENTRY_NAME);
		res = -ENOMEM;
		goto out_remove;
	}

	scst_groups_names_proc_data.data = acg;
	generic = scst_create_proc_entry(acg->acg_proc_root,
					 SCST_PROC_GROUPS_USERS_ENTRY_NAME,
					 &scst_groups_names_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s/%s/%s",
			       SCST_PROC_ENTRY_NAME,
			       SCST_PROC_GROUPS_ENTRY_NAME,
			       name, SCST_PROC_GROUPS_USERS_ENTRY_NAME);
		res = -ENOMEM;
		goto out_remove1;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_remove1:
	remove_proc_entry(SCST_PROC_GROUPS_DEVICES_ENTRY_NAME,
			  acg->acg_proc_root);

out_remove:
	remove_proc_entry(name, scst_proc_groups_root);
	goto out;
}

static void scst_proc_del_acg_tree(struct proc_dir_entry *acg_proc_root,
	const char *name)
{
	TRACE_ENTRY();

	remove_proc_entry(SCST_PROC_GROUPS_USERS_ENTRY_NAME, acg_proc_root);
	remove_proc_entry(SCST_PROC_GROUPS_DEVICES_ENTRY_NAME,
				acg_proc_root);
	remove_proc_entry(name, scst_proc_groups_root);

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
static int scst_proc_group_add(const char *p)
{
	int res = 0, len = strlen(p) + 1;
	struct scst_acg *acg;
	char *name = NULL;

	TRACE_ENTRY();

	name = kmalloc(len, GFP_KERNEL);
	if (name == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of name failed");
		goto out_nomem;
	}
	strncpy(name, p, len);

	acg = scst_alloc_add_acg(name);
	if (acg == NULL) {
		PRINT_ERROR("scst_alloc_add_acg() (name %s) failed", name);
		goto out_free;
	}

	res = scst_proc_group_add_tree(acg, p);
	if (res != 0)
		goto out_free_acg;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_acg:
	scst_proc_del_free_acg(acg, 0);

out_free:
	kfree(name);

out_nomem:
	res = -ENOMEM;
	goto out;
}

/* The activity supposed to be suspended and scst_mutex held */
static int scst_proc_del_free_acg(struct scst_acg *acg, int remove_proc)
{
	const char *name;
	struct proc_dir_entry *acg_proc_root = acg->acg_proc_root;
	int res = 0;

	TRACE_ENTRY();

	if (acg != scst_default_acg) {
		name = acg->acg_name;
		res = scst_destroy_acg(acg);
		if (res == 0) {
			if (remove_proc)
				scst_proc_del_acg_tree(acg_proc_root, name);
			kfree(name);
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int __init scst_proc_init_groups(void)
{
	int res = 0;

	TRACE_ENTRY();

	/* create the proc directory entry for the device */
	scst_proc_groups_root = proc_mkdir(SCST_PROC_GROUPS_ENTRY_NAME,
					   scst_proc_scsi_tgt);
	if (scst_proc_groups_root == NULL) {
		PRINT_ERROR("Not enough memory to register %s entry in "
			       "/proc/%s", SCST_PROC_GROUPS_ENTRY_NAME,
			       SCST_PROC_ENTRY_NAME);
		goto out_nomem;
	}

	res = scst_proc_group_add_tree(scst_default_acg,
					SCST_DEFAULT_ACG_NAME);
	if (res != 0)
		goto out_remove;

out:
	TRACE_EXIT_RES(res);
	return res;

out_remove:
	remove_proc_entry(SCST_PROC_GROUPS_ENTRY_NAME, scst_proc_scsi_tgt);

out_nomem:
	res = -ENOMEM;
	goto out;
}

static void scst_proc_cleanup_groups(void)
{
	struct scst_acg *acg_tmp, *acg;

	TRACE_ENTRY();

	/* remove all groups (dir & entries) */
	list_for_each_entry_safe(acg, acg_tmp, &scst_acg_list,
				 scst_acg_list_entry) {
		scst_proc_del_free_acg(acg, 1);
	}

	scst_proc_del_acg_tree(scst_default_acg->acg_proc_root,
				SCST_DEFAULT_ACG_NAME);
	TRACE_DBG("remove_proc_entry(%s, %p)",
		  SCST_PROC_GROUPS_ENTRY_NAME, scst_proc_scsi_tgt);
	remove_proc_entry(SCST_PROC_GROUPS_ENTRY_NAME, scst_proc_scsi_tgt);

	TRACE_EXIT();
}

static int __init scst_proc_init_sgv(void)
{
	int res = 0;
	struct proc_dir_entry *pr;

	TRACE_ENTRY();

	pr = scst_create_proc_entry(scst_proc_scsi_tgt, "sgv",
				&scst_sgv_proc_data);
	if (pr == NULL) {
		PRINT_ERROR("%s", "cannot create sgv /proc entry");
		res = -ENOMEM;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static void __exit scst_proc_cleanup_sgv(void)
{
	TRACE_ENTRY();
	remove_proc_entry("sgv", scst_proc_scsi_tgt);
	TRACE_EXIT();
}

int __init scst_proc_init_module(void)
{
	int res = 0;
	struct proc_dir_entry *generic;

	TRACE_ENTRY();

	scst_proc_scsi_tgt = proc_mkdir(SCST_PROC_ENTRY_NAME, NULL);
	if (!scst_proc_scsi_tgt) {
		PRINT_ERROR("cannot init /proc/%s", SCST_PROC_ENTRY_NAME);
		goto out_nomem;
	}

	generic = scst_create_proc_entry(scst_proc_scsi_tgt,
					 SCST_PROC_ENTRY_NAME,
					 &scst_tgt_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_ENTRY_NAME);
		goto out_remove;
	}

	generic = scst_create_proc_entry(scst_proc_scsi_tgt,
					 SCST_PROC_VERSION_NAME,
					 &scst_version_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_VERSION_NAME);
		goto out_remove1;
	}

	generic = scst_create_proc_entry(scst_proc_scsi_tgt,
					 SCST_PROC_SESSIONS_NAME,
					 &scst_sessions_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_SESSIONS_NAME);
		goto out_remove2;
	}

	generic = scst_create_proc_entry(scst_proc_scsi_tgt,
					 SCST_PROC_HELP_NAME,
					 &scst_help_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_HELP_NAME);
		goto out_remove3;
	}

	generic = scst_create_proc_entry(scst_proc_scsi_tgt,
					 SCST_PROC_THREADS_NAME,
					 &scst_threads_proc_data);
	if (!generic) {
		PRINT_ERROR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_THREADS_NAME);
		goto out_remove4;
	}

	if (scst_proc_init_module_log() < 0)
		goto out_remove5;

	if (scst_proc_init_groups() < 0)
		goto out_remove6;

	if (scst_proc_init_sgv() < 0)
		goto out_remove7;

out:
	TRACE_EXIT_RES(res);
	return res;

out_remove7:
	scst_proc_cleanup_groups();

out_remove6:
	scst_proc_cleanup_module_log();

out_remove5:
	remove_proc_entry(SCST_PROC_THREADS_NAME, scst_proc_scsi_tgt);

out_remove4:
	remove_proc_entry(SCST_PROC_HELP_NAME, scst_proc_scsi_tgt);

out_remove3:
	remove_proc_entry(SCST_PROC_SESSIONS_NAME, scst_proc_scsi_tgt);

out_remove2:
	remove_proc_entry(SCST_PROC_VERSION_NAME, scst_proc_scsi_tgt);

out_remove1:
	remove_proc_entry(SCST_PROC_ENTRY_NAME, scst_proc_scsi_tgt);

out_remove:
	remove_proc_entry(SCST_PROC_ENTRY_NAME, NULL);

out_nomem:
	res = -ENOMEM;
	goto out;
}

void __exit scst_proc_cleanup_module(void)
{
	TRACE_ENTRY();

	/* We may not bother about locks here */
	scst_proc_cleanup_sgv();
	scst_proc_cleanup_groups();
	scst_proc_cleanup_module_log();
	remove_proc_entry(SCST_PROC_THREADS_NAME, scst_proc_scsi_tgt);
	remove_proc_entry(SCST_PROC_HELP_NAME, scst_proc_scsi_tgt);
	remove_proc_entry(SCST_PROC_SESSIONS_NAME, scst_proc_scsi_tgt);
	remove_proc_entry(SCST_PROC_VERSION_NAME, scst_proc_scsi_tgt);
	remove_proc_entry(SCST_PROC_ENTRY_NAME, scst_proc_scsi_tgt);
	remove_proc_entry(SCST_PROC_ENTRY_NAME, NULL);

	TRACE_EXIT();
}

static ssize_t scst_proc_threads_write(struct file *file,
				       const char __user *buf,
				       size_t length, loff_t *off)
{
	int res = length;
	int oldtn, newtn, delta;
	char *buffer;

	TRACE_ENTRY();

	if (length > SCST_PROC_BLOCK_SIZE) {
		res = -EOVERFLOW;
		goto out;
	}
	if (!buf) {
		res = -EINVAL;
		goto out;
	}
	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}
	if (copy_from_user(buffer, buf, length)) {
		res = -EFAULT;
		goto out_free;
	}
	if (length < PAGE_SIZE) {
		buffer[length] = '\0';
	} else if (buffer[PAGE_SIZE-1]) {
		res = -EINVAL;
		goto out_free;
	}

	if (mutex_lock_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	mutex_lock(&scst_global_threads_mutex);

	oldtn = scst_nr_global_threads;
	newtn = simple_strtoul(buffer, NULL, 0);
	if (newtn <= 0) {
		PRINT_ERROR("Illegal threads num value %d", newtn);
		res = -EINVAL;
		goto out_up_thr_free;
	}
	delta = newtn - oldtn;
	if (delta < 0)
		__scst_del_global_threads(-delta);
	else
		__scst_add_global_threads(delta);

	PRINT_INFO("Changed cmd threads num: old %d, new %d", oldtn, newtn);

out_up_thr_free:
	mutex_unlock(&scst_global_threads_mutex);

	mutex_unlock(&scst_proc_mutex);

out_free:
	free_page((unsigned long)buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}

int scst_build_proc_target_dir_entries(struct scst_tgt_template *vtt)
{
	int res = 0;

	TRACE_ENTRY();

	/* create the proc directory entry for the device */
	vtt->proc_tgt_root = proc_mkdir(vtt->name, scst_proc_scsi_tgt);
	if (vtt->proc_tgt_root == NULL) {
		PRINT_ERROR("Not enough memory to register SCSI target %s "
		    "in /proc/%s", vtt->name, SCST_PROC_ENTRY_NAME);
		goto out_nomem;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_nomem:
	res = -ENOMEM;
	goto out;
}

void scst_cleanup_proc_target_dir_entries(struct scst_tgt_template *vtt)
{
	TRACE_ENTRY();

	remove_proc_entry(vtt->name, scst_proc_scsi_tgt);

	TRACE_EXIT();
	return;
}

/* Called under scst_mutex */
int scst_build_proc_target_entries(struct scst_tgt *vtt)
{
	int res = 0;
	struct proc_dir_entry *p;
	char name[20];

	TRACE_ENTRY();

	if (vtt->tgtt->read_proc || vtt->tgtt->write_proc) {
		/* create the proc file entry for the device */
		scnprintf(name, sizeof(name), "%d", vtt->tgtt->proc_dev_num);
		scst_scsi_tgt_proc_data.data = (void *)vtt;
		p = scst_create_proc_entry(vtt->tgtt->proc_tgt_root,
					   name,
					   &scst_scsi_tgt_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register SCSI "
			     "target entry %s in /proc/%s/%s", name,
			     SCST_PROC_ENTRY_NAME, vtt->tgtt->name);
			res = -ENOMEM;
			goto out;
		}
		vtt->proc_num = vtt->tgtt->proc_dev_num;
		vtt->tgtt->proc_dev_num++;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

void scst_cleanup_proc_target_entries(struct scst_tgt *vtt)
{
	char name[20];

	TRACE_ENTRY();

	if (vtt->tgtt->read_proc || vtt->tgtt->write_proc) {
		scnprintf(name, sizeof(name), "%d", vtt->proc_num);
		remove_proc_entry(name, vtt->tgtt->proc_tgt_root);
	}

	TRACE_EXIT();
	return;
}

static ssize_t scst_proc_scsi_tgt_write(struct file *file,
					const char __user *buf,
					size_t length, loff_t *off)
{
	struct scst_tgt *vtt =
		(struct scst_tgt *)PDE(file->f_dentry->d_inode)->data;
	ssize_t res = 0;
	char *buffer;
	char *start;
	int eof = 0;

	TRACE_ENTRY();

	if (vtt->tgtt->write_proc == NULL) {
		res = -ENOSYS;
		goto out;
	}

	if (length > SCST_PROC_BLOCK_SIZE) {
		res = -EOVERFLOW;
		goto out;
	}
	if (!buf) {
		res = -EINVAL;
		goto out;
	}
	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}
	if (copy_from_user(buffer, buf, length)) {
		res = -EFAULT;
		goto out_free;
	}
	if (length < PAGE_SIZE) {
		buffer[length] = '\0';
	} else if (buffer[PAGE_SIZE-1]) {
		res = -EINVAL;
		goto out_free;
	}

	TRACE_BUFFER("Buffer", buffer, length);

	if (mutex_lock_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	res = vtt->tgtt->write_proc(buffer, &start, 0, length, &eof, vtt);

	mutex_unlock(&scst_proc_mutex);

out_free:
	free_page((unsigned long)buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}

int scst_build_proc_dev_handler_dir_entries(struct scst_dev_type *dev_type)
{
	int res = 0;
	struct proc_dir_entry *p;

	TRACE_ENTRY();

	sBUG_ON(dev_type->proc_dev_type_root);

	/* create the proc directory entry for the dev type handler */
	dev_type->proc_dev_type_root = proc_mkdir(dev_type->name,
						  scst_proc_scsi_tgt);
	if (dev_type->proc_dev_type_root == NULL) {
		PRINT_ERROR("Not enough memory to register dev handler dir "
		    "%s in /proc/%s", dev_type->name, SCST_PROC_ENTRY_NAME);
		goto out_nomem;
	}

	scst_dev_handler_type_proc_data.data = dev_type;
	if (dev_type->type >= 0) {
		p = scst_create_proc_entry(dev_type->proc_dev_type_root,
				   SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME,
				   &scst_dev_handler_type_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register dev "
			     "handler entry %s in /proc/%s/%s",
			     SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME,
			     SCST_PROC_ENTRY_NAME, dev_type->name);
			goto out_remove;
		}
	}

	if (dev_type->read_proc || dev_type->write_proc) {
		/* create the proc file entry for the dev type handler */
		scst_dev_handler_proc_data.data = (void *)dev_type;
		p = scst_create_proc_entry(dev_type->proc_dev_type_root,
					   dev_type->name,
					   &scst_dev_handler_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register dev "
			     "handler entry %s in /proc/%s/%s", dev_type->name,
			     SCST_PROC_ENTRY_NAME, dev_type->name);
			goto out_remove1;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_remove1:
	if (dev_type->type >= 0)
		remove_proc_entry(SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME,
				  dev_type->proc_dev_type_root);

out_remove:
	remove_proc_entry(dev_type->name, scst_proc_scsi_tgt);

out_nomem:
	res = -ENOMEM;
	goto out;
}

void scst_cleanup_proc_dev_handler_dir_entries(struct scst_dev_type *dev_type)
{
	TRACE_ENTRY();

	sBUG_ON(dev_type->proc_dev_type_root == NULL);

	if (dev_type->type >= 0) {
		remove_proc_entry(SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME,
				  dev_type->proc_dev_type_root);
	}
	if (dev_type->read_proc || dev_type->write_proc)
		remove_proc_entry(dev_type->name, dev_type->proc_dev_type_root);
	remove_proc_entry(dev_type->name, scst_proc_scsi_tgt);
	dev_type->proc_dev_type_root = NULL;

	TRACE_EXIT();
	return;
}

static ssize_t scst_proc_scsi_dev_handler_write(struct file *file,
						const char __user *buf,
						size_t length, loff_t *off)
{
	struct scst_dev_type *dev_type =
		(struct scst_dev_type *)PDE(file->f_dentry->d_inode)->data;
	ssize_t res = 0;
	char *buffer;
	char *start;
	int eof = 0;

	TRACE_ENTRY();

	if (dev_type->write_proc == NULL) {
		res = -ENOSYS;
		goto out;
	}

	if (length > SCST_PROC_BLOCK_SIZE) {
		res = -EOVERFLOW;
		goto out;
	}
	if (!buf) {
		res = -EINVAL;
		goto out;
	}

	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}

	if (copy_from_user(buffer, buf, length)) {
		res = -EFAULT;
		goto out_free;
	}
	if (length < PAGE_SIZE) {
		buffer[length] = '\0';
	} else if (buffer[PAGE_SIZE-1]) {
		res = -EINVAL;
		goto out_free;
	}

	TRACE_BUFFER("Buffer", buffer, length);

	if (mutex_lock_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	res = dev_type->write_proc(buffer, &start, 0, length, &eof, dev_type);

	mutex_unlock(&scst_proc_mutex);

out_free:
	free_page((unsigned long)buffer);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_proc_scsi_tgt_gen_write(struct file *file,
					const char __user *buf,
					size_t length, loff_t *off)
{
	int res, rc = 0, action;
	char *buffer, *p;
	struct scst_acg *a, *acg = NULL;

	TRACE_ENTRY();

	if (length > SCST_PROC_BLOCK_SIZE) {
		res = -EOVERFLOW;
		goto out;
	}
	if (!buf) {
		res = -EINVAL;
		goto out;
	}
	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}
	if (copy_from_user(buffer, buf, length)) {
		res = -EFAULT;
		goto out_free;
	}
	if (length < PAGE_SIZE) {
		buffer[length] = '\0';
	} else if (buffer[PAGE_SIZE-1]) {
		res = -EINVAL;
		goto out_free;
	}

	/*
	 * Usage: echo "add_group GROUP" >/proc/scsi_tgt/scsi_tgt
	 *   or   echo "del_group GROUP" >/proc/scsi_tgt/scsi_tgt
	 *   or   echo "assign H:C:I:L HANDLER_NAME" >/proc/scsi_tgt/scsi_tgt
	 */
	p = buffer;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncasecmp("assign ", p, 7)) {
		p += 7;
		action = SCST_PROC_ACTION_ASSIGN;
	} else if (!strncasecmp("add_group ", p, 10)) {
		p += 10;
		action = SCST_PROC_ACTION_ADD_GROUP;
	} else if (!strncasecmp("del_group ", p, 10)) {
		p += 10;
		action = SCST_PROC_ACTION_DEL_GROUP;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out_free;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_free_resume;
	}

	res = length;

	switch (action) {
	case SCST_PROC_ACTION_ADD_GROUP:
	case SCST_PROC_ACTION_DEL_GROUP:
		if (strcmp(p, SCST_DEFAULT_ACG_NAME) == 0) {
			PRINT_ERROR("Attempt to add/delete predefined "
				"group \"%s\"", p);
			res = -EINVAL;
			goto out_up_free;
		}
		list_for_each_entry(a, &scst_acg_list, scst_acg_list_entry) {
			if (strcmp(a->acg_name, p) == 0) {
				TRACE_DBG("group (acg) %p %s found",
					  a, a->acg_name);
				acg = a;
				break;
			}
		}
		switch (action) {
		case SCST_PROC_ACTION_ADD_GROUP:
			if (acg) {
				PRINT_ERROR("acg name %s exist", p);
				res = -EINVAL;
				goto out_up_free;
			}
			rc = scst_proc_group_add(p);
			break;
		case SCST_PROC_ACTION_DEL_GROUP:
			if (acg == NULL) {
				PRINT_ERROR("acg name %s not found", p);
				res = -EINVAL;
				goto out_up_free;
			}
			rc = scst_proc_del_free_acg(acg, 1);
			break;
		}
		break;
	case SCST_PROC_ACTION_ASSIGN:
		rc = scst_proc_assign_handler(p);
		break;
	}

	if (rc != 0)
		res = rc;

out_up_free:
	mutex_unlock(&scst_mutex);

out_free_resume:
	scst_resume_activity();

out_free:
	free_page((unsigned long)buffer);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* The activity supposed to be suspended and scst_mutex held */
static int scst_proc_assign_handler(char *buf)
{
	int res = 0;
	char *p = buf, *e, *ee;
	unsigned long host, channel = 0, id = 0, lun = 0;
	struct scst_device *d, *dev = NULL;
	struct scst_dev_type *dt, *handler = NULL;

	TRACE_ENTRY();

	while (isspace(*p) && *p != '\0')
		p++;

	host = simple_strtoul(p, &p, 0);
	if ((host == ULONG_MAX) || (*p != ':'))
		goto out_synt_err;
	p++;
	channel = simple_strtoul(p, &p, 0);
	if ((channel == ULONG_MAX) || (*p != ':'))
		goto out_synt_err;
	p++;
	id = simple_strtoul(p, &p, 0);
	if ((channel == ULONG_MAX) || (*p != ':'))
		goto out_synt_err;
	p++;
	lun = simple_strtoul(p, &p, 0);
	if (lun == ULONG_MAX)
		goto out_synt_err;

	e = p;
	e++;
	while (isspace(*e) && *e != '\0')
		e++;
	ee = e;
	while (!isspace(*ee) && *ee != '\0')
		ee++;
	*ee = '\0';

	TRACE_DBG("Dev %ld:%ld:%ld:%ld, handler %s", host, channel, id, lun, e);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if ((d->virt_id == 0) &&
		    d->scsi_dev->host->host_no == host &&
		    d->scsi_dev->channel == channel &&
		    d->scsi_dev->id == id &&
		    d->scsi_dev->lun == lun) {
			dev = d;
			TRACE_DBG("Dev %p (%ld:%ld:%ld:%ld) found",
				  dev, host, channel, id, lun);
			break;
		}
	}

	if (dev == NULL) {
		PRINT_ERROR("Device %ld:%ld:%ld:%ld not found",
			       host, channel, id, lun);
		res = -EINVAL;
		goto out;
	}

	list_for_each_entry(dt, &scst_dev_type_list, dev_type_list_entry) {
		if (!strcmp(dt->name, e)) {
			handler = dt;
			TRACE_DBG("Dev handler %p with name %s found",
				  dt, dt->name);
			break;
		}
	}

	if (handler == NULL) {
		PRINT_ERROR("Handler %s not found", e);
		res = -EINVAL;
		goto out;
	}

	if (dev->scsi_dev->type != handler->type) {
		PRINT_ERROR("Type %d of device %s differs from type "
			"%d of dev handler %s", dev->handler->type,
			dev->handler->name, handler->type, handler->name);
		res = -EINVAL;
		goto out;
	}

	res = scst_assign_dev_handler(dev, handler);

out:
	TRACE_EXIT_RES(res);
	return res;

out_synt_err:
	PRINT_ERROR("Syntax error on %s", p);
	res = -EINVAL;
	goto out;
}

static ssize_t scst_proc_groups_devices_write(struct file *file,
					const char __user *buf,
					size_t length, loff_t *off)
{
	int res, action, virt = 0, rc, read_only = 0;
	char *buffer, *p, *e = NULL;
	unsigned int host, channel = 0, id = 0, lun = 0, virt_lun;
	struct scst_acg *acg =
		(struct scst_acg *)PDE(file->f_dentry->d_inode)->data;
	struct scst_acg_dev *acg_dev = NULL, *acg_dev_tmp;
	struct scst_device *d, *dev = NULL;

	TRACE_ENTRY();

	if (length > SCST_PROC_BLOCK_SIZE) {
		res = -EOVERFLOW;
		goto out;
	}
	if (!buf) {
		res = -EINVAL;
		goto out;
	}
	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}
	if (copy_from_user(buffer, buf, length)) {
		res = -EFAULT;
		goto out_free;
	}
	if (length < PAGE_SIZE) {
		buffer[length] = '\0';
	} else if (buffer[PAGE_SIZE-1]) {
		res = -EINVAL;
		goto out_free;
	}

	/*
	 * Usage: echo "add|del H:C:I:L lun [READ_ONLY]" \
	 *          >/proc/scsi_tgt/groups/GROUP/devices
	 *   or   echo "add|del V_NAME lun [READ_ONLY]" \
	 *          >/proc/scsi_tgt/groups/GROUP/devices
	 *   or   echo "clear" >/proc/scsi_tgt/groups/GROUP/devices
	 */
	p = buffer;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncasecmp("clear", p, 5)) {
		action = SCST_PROC_ACTION_CLEAR;
	} else if (!strncasecmp("add ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_ADD;
	} else if (!strncasecmp("del ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_DEL;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out_free;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_free_resume;
	}

	res = length;

	switch (action) {
	case SCST_PROC_ACTION_ADD:
	case SCST_PROC_ACTION_DEL:
		while (isspace(*p) && *p != '\0')
			p++;
		e = p; /* save p */
		host = simple_strtoul(p, &p, 0);
		if (*p == ':') {
			channel = simple_strtoul(p + 1, &p, 0);
			id = simple_strtoul(p + 1, &p, 0);
			lun = simple_strtoul(p + 1, &p, 0);
			e = p;
		} else {
			virt++;
			p = e; /* restore p */
			while (!isspace(*e) && *e != '\0')
				e++;
			*e = 0;
		}

		list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
			if (virt) {
				if (d->virt_id && !strcmp(d->virt_name, p)) {
					dev = d;
					TRACE_DBG("Virt device %p (%s) found",
						  dev, p);
					break;
				}
			} else {
				if (d->scsi_dev &&
				    d->scsi_dev->host->host_no == host &&
				    d->scsi_dev->channel == channel &&
				    d->scsi_dev->id == id &&
				    d->scsi_dev->lun == lun) {
					dev = d;
					TRACE_DBG("Dev %p (%d:%d:%d:%d) found",
						  dev, host, channel, id, lun);
					break;
				}
			}
		}
		if (dev == NULL) {
			if (virt) {
				PRINT_ERROR("Virt device %s not found", p);
			} else {
				PRINT_ERROR("Device %d:%d:%d:%d not found",
					       host, channel, id, lun);
			}
			res = -EINVAL;
			goto out_free_up;
		}
		break;
	}

	/* ToDo: create separate functions */

	switch (action) {
	case SCST_PROC_ACTION_ADD:
		e++;
		while (isspace(*e) && *e != '\0')
			e++;
		virt_lun = simple_strtoul(e, &e, 0);

		while (isspace(*e) && *e != '\0')
			e++;

		if (*e != '\0') {
			if (!strncasecmp("READ_ONLY", e, 9))
				read_only = 1;
			else {
				PRINT_ERROR("Unknown option \"%s\"", e);
				res = -EINVAL;
				goto out_free_up;
			}
		}

		list_for_each_entry(acg_dev_tmp, &acg->acg_dev_list,
				    acg_dev_list_entry) {
			if (acg_dev_tmp->lun == virt_lun) {
				acg_dev = acg_dev_tmp;
				break;
			}
		}
		if (acg_dev) {
			acg_dev = acg_dev_tmp;
			PRINT_ERROR("virt lun %d already exists in group %s",
				       virt_lun, acg->acg_name);
			res = -EINVAL;
			goto out_free_up;
		}
		rc = scst_acg_add_dev(acg, dev, virt_lun, read_only);
		if (rc) {
			PRINT_ERROR("scst_acg_add_dev() returned %d", rc);
			res = rc;
		}
		break;
	case SCST_PROC_ACTION_DEL:
		rc = scst_acg_remove_dev(acg, dev);
		if (rc) {
			PRINT_ERROR("scst_acg_remove_dev() returned %d", rc);
			res = rc;
		}
		break;
	case SCST_PROC_ACTION_CLEAR:
		list_for_each_entry_safe(acg_dev, acg_dev_tmp,
					 &acg->acg_dev_list,
					 acg_dev_list_entry) {
			rc = scst_acg_remove_dev(acg, acg_dev->dev);
			if (rc) {
				PRINT_ERROR("scst_acg_remove_dev() "
					       "return %d", rc);
				res = rc;
			}
		}
		break;
	}

out_free_up:
	mutex_unlock(&scst_mutex);

out_free_resume:
	scst_resume_activity();

out_free:
	free_page((unsigned long)buffer);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_proc_groups_names_write(struct file *file,
					const char __user *buf,
					size_t length, loff_t *off)
{
	int res = length, action;
	char *buffer, *p, *e;
	struct scst_acg *acg =
		(struct scst_acg *)PDE(file->f_dentry->d_inode)->data;
	struct scst_acn *n, *nn;

	TRACE_ENTRY();

	if (length > SCST_PROC_BLOCK_SIZE) {
		res = -EOVERFLOW;
		goto out;
	}
	if (!buf) {
		res = -EINVAL;
		goto out;
	}
	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}
	if (copy_from_user(buffer, buf, length)) {
		res = -EFAULT;
		goto out_free;
	}
	if (length < PAGE_SIZE) {
		buffer[length] = '\0';
	} else if (buffer[PAGE_SIZE-1]) {
		res = -EINVAL;
		goto out_free;
	}

	/*
	 * Usage: echo "add|del NAME" >/proc/scsi_tgt/groups/GROUP/names
	 *   or   echo "clear" >/proc/scsi_tgt/groups/GROUP/names
	 */
	p = buffer;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncasecmp("clear", p, 5)) {
		action = SCST_PROC_ACTION_CLEAR;
	} else if (!strncasecmp("add ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_ADD;
	} else if (!strncasecmp("del ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_DEL;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	switch (action) {
	case SCST_PROC_ACTION_ADD:
	case SCST_PROC_ACTION_DEL:
		while (isspace(*p) && *p != '\0')
			p++;
		e = p;
		while (!isspace(*e) && *e != '\0')
			e++;
		*e = 0;
		break;
	}

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	switch (action) {
	case SCST_PROC_ACTION_ADD:
		scst_acg_add_name(acg, p);
		break;
	case SCST_PROC_ACTION_DEL:
		scst_acg_remove_name(acg, p);
		break;
	case SCST_PROC_ACTION_CLEAR:
		list_for_each_entry_safe(n, nn, &acg->acn_list,
					 acn_list_entry) {
			list_del(&n->acn_list_entry);
			kfree(n->name);
			kfree(n);
		}
		break;
	}

	mutex_unlock(&scst_mutex);

out_free:
	free_page((unsigned long)buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_version_info_show(struct seq_file *seq, void *v)
{
	TRACE_ENTRY();

	seq_printf(seq, "%s\n", SCST_VERSION_STRING);

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	seq_printf(seq, "Strict serializing enabled\n");
#endif

#ifdef CONFIG_SCST_EXTRACHECKS
	seq_printf(seq, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_SCST_TRACING
	seq_printf(seq, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	seq_printf(seq, "DEBUG\n");
#endif

#ifdef CONFIG_SCST_DEBUG_TM
	seq_printf(seq, "DEBUG_TM\n");
#endif

#ifdef CONFIG_SCST_DEBUG_RETRY
	seq_printf(seq, "DEBUG_RETRY\n");
#endif

#ifdef CONFIG_SCST_DEBUG_OOM
	seq_printf(seq, "DEBUG_OOM\n");
#endif

#ifdef CONFIG_SCST_DEBUG_SN
	seq_printf(seq, "DEBUG_SN\n");
#endif

#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
	seq_printf(seq, "USE_EXPECTED_VALUES\n");
#endif

#ifdef CONFIG_SCST_ALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ
	seq_printf(seq, "ALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ\n");
#endif

#ifdef CONFIG_SCST_STRICT_SECURITY
	seq_printf(seq, "SCST_STRICT_SECURITY\n");
#endif

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data scst_version_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = scst_version_info_show,
};

static int scst_help_info_show(struct seq_file *seq, void *v)
{
	TRACE_ENTRY();

	seq_printf(seq, "%s\n", scst_proc_help_string);

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data scst_help_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = scst_help_info_show,
};

static int scst_dev_handler_type_info_show(struct seq_file *seq, void *v)
{
	struct scst_dev_type *dev_type = (struct scst_dev_type *)seq->private;

	TRACE_ENTRY();

	seq_printf(seq, "%d - %s\n", dev_type->type,
		   dev_type->type > (int)ARRAY_SIZE(scst_proc_dev_handler_type)
		   ? "unknown" : scst_proc_dev_handler_type[dev_type->type]);

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data scst_dev_handler_type_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = scst_dev_handler_type_info_show,
};

static int scst_sessions_info_show(struct seq_file *seq, void *v)
{
	int res = 0;
	struct scst_acg *acg;
	struct scst_session *sess;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	seq_printf(seq, "%-20s %-45s %-35s %-15s\n",
		   "Target name", "Initiator name",
		   "Group name", "Command Count");

	list_for_each_entry(acg, &scst_acg_list, scst_acg_list_entry) {
		list_for_each_entry(sess, &acg->acg_sess_list,
			acg_sess_list_entry) {
			seq_printf(seq, "%-20s %-45s %-35s %-15d\n",
					sess->tgt->tgtt->name,
					sess->initiator_name,
					acg->acg_name,
					atomic_read(&sess->sess_cmd_count));
		}
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_sessions_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = scst_sessions_info_show,
};


static struct scst_proc_data scst_sgv_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = sgv_pool_procinfo_show,
};

static int scst_groups_names_show(struct seq_file *seq, void *v)
{
	int res = 0;
	struct scst_acg *acg = (struct scst_acg *)seq->private;
	struct scst_acn *name;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	list_for_each_entry(name, &acg->acn_list, acn_list_entry) {
		seq_printf(seq, "%s\n", name->name);
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_groups_names_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_groups_names_write)
	.show = scst_groups_names_show,
};

static int scst_groups_devices_show(struct seq_file *seq, void *v)
{
	int res = 0;
	struct scst_acg *acg = (struct scst_acg *)seq->private;
	struct scst_acg_dev *acg_dev;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	seq_printf(seq, "%-60s%-13s%s\n", "Device (host:ch:id:lun or name)",
		       "LUN", "Options");

	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		if (acg_dev->dev->virt_id == 0) {
			char conv[60];
			int size = sizeof(conv);

			memset(conv, 0, size);
			size = snprintf(conv, size, "%d:%d:%d:",
					acg_dev->dev->scsi_dev->host->host_no,
					acg_dev->dev->scsi_dev->channel,
					acg_dev->dev->scsi_dev->id);
			seq_printf(seq, "%s", conv);

			/*
			 * For some reason the third string argument always
			 * shown as NULL, so we have to split it on 2 calls.
			 */
			sprintf(conv, "%%-%dd%%-13d", 60 - size);
			size += seq_printf(seq, conv,
					acg_dev->dev->scsi_dev->lun,
					acg_dev->lun);
			seq_printf(seq, "%s\n",
				acg_dev->rd_only_flag ? "RO" : "");
		} else {
			seq_printf(seq, "%-60s%-13lld%s\n",
				       acg_dev->dev->virt_name,
				       (long long unsigned int)acg_dev->lun,
				       acg_dev->rd_only_flag ? "RO" : "");
		}
	}
	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_groups_devices_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_groups_devices_write)
	.show = scst_groups_devices_show,
};

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static int scst_proc_read_tlb(const struct scst_proc_log *tbl,
			      struct seq_file *seq,
	unsigned long log_level, int *first)
{
	const struct scst_proc_log *t = tbl;
	int res = 0;

	while (t->token) {
		if (log_level & t->val) {
			seq_printf(seq, "%s%s", *first ? "" : " | ", t->token);
			*first = 0;
		}
		t++;
	}
	return res;
}

int scst_proc_log_entry_read(struct seq_file *seq, unsigned long log_level,
			     const struct scst_proc_log *tbl)
{
	int res = 0, first = 1;

	TRACE_ENTRY();

	scst_proc_read_tlb(scst_proc_trace_tbl, seq, log_level, &first);

	if (tbl)
		scst_proc_read_tlb(tbl, seq, log_level, &first);

	seq_printf(seq, "%s\n", first ? "none" : "");

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_proc_log_entry_read);

static int log_info_show(struct seq_file *seq, void *v)
{
	int res;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_log_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	res = scst_proc_log_entry_read(seq, trace_flag,
				       scst_proc_local_trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_scsi_tgt_gen_write_log)
	.show = log_info_show,
	.data = "scsi_tgt",
};

#endif

static int scst_tgt_info_show(struct seq_file *seq, void *v)
{
	int res = 0;
	struct scst_device *dev;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	seq_printf(seq, "%-60s%s\n", "Device (host:ch:id:lun or name)",
		   "Device handler");
	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		if (dev->virt_id == 0) {
			char conv[60];
			int size = sizeof(conv);
			size = snprintf(conv, size, "%d:%d:%d:",
					dev->scsi_dev->host->host_no,
					dev->scsi_dev->channel,
					dev->scsi_dev->id);
			seq_printf(seq, "%s", conv);
			sprintf(conv, "%%-%dd%%s\n", 60 - size);
			seq_printf(seq, conv, dev->scsi_dev->lun,
				   dev->handler ? dev->handler->name : "-");
		} else
			seq_printf(seq, "%-60s%s\n",
				   dev->virt_name, dev->handler->name);
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_tgt_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_scsi_tgt_gen_write)
	.show = scst_tgt_info_show,
};

static int scst_threads_info_show(struct seq_file *seq, void *v)
{
	TRACE_ENTRY();

	seq_printf(seq, "%d\n", scst_global_threads_count());

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data scst_threads_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_threads_write)
	.show = scst_threads_info_show,
};

static int scst_scsi_tgtinfo_show(struct seq_file *seq, void *v)
{
	struct scst_tgt *vtt = seq->private;
	int res = 0;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	if (vtt->tgtt->read_proc)
		res = vtt->tgtt->read_proc(seq, vtt);

	mutex_unlock(&scst_proc_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_scsi_tgt_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_scsi_tgt_write)
	.show = scst_scsi_tgtinfo_show,
};

static int scst_dev_handler_info_show(struct seq_file *seq, void *v)
{
	struct scst_dev_type *dev_type = seq->private;
	int res = 0;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	if (dev_type->read_proc)
		res = dev_type->read_proc(seq, dev_type);

	mutex_unlock(&scst_proc_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data scst_dev_handler_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_proc_scsi_dev_handler_write)
	.show = scst_dev_handler_info_show,
};

struct proc_dir_entry *scst_create_proc_entry(struct proc_dir_entry *root,
	const char *name, struct scst_proc_data *pdata)
{
	struct proc_dir_entry *p = NULL;

	TRACE_ENTRY();

	if (root) {
		mode_t mode;

		mode = S_IFREG | S_IRUGO | (pdata->seq_op.write ? S_IWUSR : 0);
		p = create_proc_entry(name, mode, root);
		if (p == NULL) {
			PRINT_ERROR("Fail to create entry %s in /proc", name);
		} else {
			p->proc_fops = &pdata->seq_op;
			p->data = pdata->data;
		}
	}

	TRACE_EXIT();
	return p;
}
EXPORT_SYMBOL(scst_create_proc_entry);

int scst_single_seq_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
	struct scst_proc_data *pdata = container_of(PDE(inode)->proc_fops,
		struct scst_proc_data, seq_op);
#else
	struct scst_proc_data *pdata = container_of(inode->i_fop,
		struct scst_proc_data, seq_op);
#endif
	return single_open(file, pdata->show, PDE(inode)->data);
}
EXPORT_SYMBOL(scst_single_seq_open);
