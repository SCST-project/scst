/*
 *  scst_proc.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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
#include <asm/unistd.h>
#include <asm/string.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>

#include "scst_debug.h"
#include "scsi_tgt.h"
#include "scst_mem.h"
#include "scst_priv.h"

static int scst_scsi_tgt_proc_info(char *buffer, char **start,
				   off_t offset, int length, int *eof,
				   void *data);
static int scst_proc_scsi_tgt_gen_write(struct file *file,
					const char *buf,
					unsigned long length, void *data);
static int scst_proc_version_read(char *buffer, char **start,off_t offset,
				  int length, int *eof, void *data);
static int scst_proc_sessions_read(char *buffer, char **start, off_t offset,
				   int length, int *eof, void *data);
static int scst_proc_help_read(char *buffer, char **start,off_t offset,
			       int length, int *eof, void *data);
static int scst_proc_threads_read(char *buffer, char **start,off_t offset,
				  int length, int *eof, void *data);
static int scst_proc_threads_write(struct file *file, const char *buf,
				   unsigned long length, void *data);
static int scst_proc_scsi_tgt_read(char *buffer, char **start, off_t offset,
				   int length, int *eof, void *data);
static int scst_proc_scsi_tgt_write(struct file *file, const char *buf,
				    unsigned long count, void *data);
static int scst_proc_scsi_dev_handler_read(char *buffer, char **start,
					   off_t offset, int length, int *eof,
					   void *data);
static int scst_proc_scsi_dev_handler_write(struct file *file, const char *buf,
					    unsigned long count, void *data);
static int scst_proc_scsi_dev_handler_type_read(char *buffer, char **start,
						off_t offset, int length,
						int *eof, void *data);
static int scst_proc_init_groups(void);
static void scst_proc_cleanup_groups(void);
static int scst_proc_assign_handler(char *buf);
static int scst_proc_group_add(const char *p);
static int scst_proc_groups_devices_read(char *buffer, char **start,
					 off_t offset, int length, int *eof,
					 void *data);
static int scst_proc_groups_devices_write(struct file *file, const char *buf,
					  unsigned long length, void *data);
static int scst_proc_groups_names_read(char *buffer, char **start,
				       off_t offset, int length, int *eof,
				       void *data);
static int scst_proc_groups_names_write(struct file *file, const char *buf,
					unsigned long length, void *data);
static int scst_proc_del_free_acg(struct scst_acg *acg, int remove_proc);

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

#if defined(DEBUG) || defined(TRACING)
static struct scst_proc_log scst_proc_trace_tbl[] =
{
    { TRACE_OUT_OF_MEM,		"out_of_mem" },
    { TRACE_MINOR,		"minor" },
    { TRACE_SG,			"sg" },
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
    { TRACE_MGMT_DEBUG,		"mgmt_dbg" },
    { 0,			NULL }
};

static struct scst_proc_log scst_proc_local_trace_tbl[] =
{
    { TRACE_RETRY,		"retry" },
    { TRACE_SCSI_SERIALIZING,	"scsi_serializing" },
    { TRACE_RECV_BOT,		"recv_bot" },
    { TRACE_SEND_BOT,		"send_bot" },
    { TRACE_RECV_TOP,		"recv_top" },
    { TRACE_SEND_TOP,		"send_top" },
    { 0,			NULL }
};
#endif

static char *scst_proc_help_string =
"   echo \"assign H:C:I:L HANDLER_NAME\" >/proc/scsi_tgt/scsi_tgt\n"
"\n"
"   echo \"add_group GROUP\" >/proc/scsi_tgt/scsi_tgt\n"
"   echo \"del_group GROUP\" >/proc/scsi_tgt/scsi_tgt\n"
"\n"
"   echo \"add|del H:C:I:L lun [READ_ONLY]\" >/proc/scsi_tgt/groups/GROUP/devices\n"
"   echo \"add|del V_NAME lun [READ_ONLY]\" >/proc/scsi_tgt/groups/GROUP/devices\n"
"   echo \"clear\" >/proc/scsi_tgt/groups/GROUP/devices\n"
"\n"
"   echo \"add|del NAME\" >/proc/scsi_tgt/groups/GROUP/names\n"
"   echo \"clear\" >/proc/scsi_tgt/groups/GROUP/names\n"
"\n"
"   echo \"DEC|0xHEX|0OCT\" >/proc/scsi_tgt/threads\n"
#if defined(DEBUG) || defined(TRACING)
"\n"
"   echo \"all|none|default\" >/proc/scsi_tgt/[DEV_HANDLER_NAME/]trace_level\n"
"   echo \"value DEC|0xHEX|0OCT\" >/proc/scsi_tgt/[DEV_HANDLER_NAME/]trace_level\n"
"   echo \"set|add|del TOKEN\" >/proc/scsi_tgt/[DEV_HANDLER_NAME/]trace_level\n"
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

static DECLARE_MUTEX(scst_proc_mutex);

#include <linux/ctype.h>

#if defined(DEBUG) || defined(TRACING)
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

static int strncasecmp(const char *s1, const char *s2, int n)
{
	int c1, c2;
	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}

int scst_proc_read_tlb(const struct scst_proc_log *tbl, char *buffer,
	int length, off_t offset, unsigned long log_level, int *first,
	int *size, int *len, off_t *begin, off_t *pos)
{
	const struct scst_proc_log *t = tbl;
	int res = 0;

	while (t->token) {
		if (log_level & t->val) {
			*size = scnprintf(buffer + *len, length - *len,
			    "%s%s", *first ? "" : " | ", t->token);
			*first = 0;
			if (*size > 0) {
				*len += *size;
				*pos = *begin + *len;
				if (*pos <= offset) {
					*len = 0;
					*begin = *pos;
				} else if (*pos >= offset + length)
					goto out_end;
			} else
				goto out_end;
		}
		t++;
	}
out:
	return res;

out_end:
	res = 1;
	goto out;
}

#if defined(DEBUG) || defined(TRACING)

int scst_proc_log_entry_read(char *buffer, char **start,
			     off_t offset, int length, int *eof, void *data,
			     unsigned long log_level,
			     const struct scst_proc_log *tbl)
{
	int res = 0, first = 1;
	int size, len = 0;
	off_t begin = 0, pos = 0;

	TRACE_ENTRY();

	TRACE_DBG("offset: %d, length %d", (int) offset, length);

	if (scst_proc_read_tlb(scst_proc_trace_tbl, buffer, length, offset,
			log_level, &first, &size, &len, &begin, &pos))
		goto stop_output;

	if (tbl) {
		TRACE_DBG("Reading private tlb, offset: %d, length %d",
			(int) offset, length);
		if (scst_proc_read_tlb(tbl, buffer, length, offset, 
				log_level, &first, &size, &len, &begin, &pos))
			goto stop_output;
	}

	size = scnprintf(buffer + len, length - len, "%s\n", first ? "none" : "");
	if (size > 0) {
		len += size;
		pos = begin + len;
		if (pos <= offset) {
			len = 0;
			begin = pos;
		} else if (pos >= offset + length)
			goto stop_output;
	} else
		goto stop_output;

stop_output:
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;
	res = max(0, len);
	TRACE_EXIT_RES(res);
	return res;
}

int scst_proc_log_entry_write(struct file *file, const char *buf,
	unsigned long length, void *data, unsigned long *log_level,
	unsigned long default_level, const struct scst_proc_log *tbl)
{
	int res = length;
	int action;
	unsigned long level = 0, oldlevel;
	char *buffer, *p, *e;
	const struct scst_proc_log *t;

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
	 *   echo "all|none|default" >/proc/scsi_tgt/trace_log_level
	 *   echo "value DEC|0xHEX|0OCT" >/proc/scsi_tgt/trace_log_level
	 *   echo "set|add|clear|del TOKEN" >/proc/scsi_tgt/trace_log_level
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
		if (p[strlen(p) - 1] == '\n') {
			p[strlen(p) - 1] = '\0';
		}
		PRINT_ERROR_PR("Unknown action \"%s\"", p);
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
		while (isspace(*p) && *p != '\0') {
			p++;
		}
		e = p;
		while (!isspace(*e) && *e != '\0') {
			e++;
		}
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
		while (isspace(*p) && *p != '\0') {
			p++;
		}
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

static int scst_scsi_tgt_proc_info_log(char *buffer, char **start,
				       off_t offset, int length, int *eof,
				       void *data)
{
	int res;

	TRACE_ENTRY();


	if (down_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	res = scst_proc_log_entry_read(buffer, start, offset, length, eof,
			data, trace_flag, scst_proc_local_trace_tbl);

	up(&scst_proc_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_scsi_tgt_gen_write_log(struct file *file,
					const char *buf,
					unsigned long length, void *data)
{
	int res;

	TRACE_ENTRY();

	if (down_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	res = scst_proc_log_entry_write(file, buf, length, data,
		&trace_flag, SCST_DEFAULT_LOG_FLAGS, scst_proc_local_trace_tbl);

	up(&scst_proc_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#endif /* defined(DEBUG) || defined(TRACING) */

static int scst_proc_init_module_log(void)
{
	int res = 0;
#if defined(DEBUG) || defined(TRACING)
	struct proc_dir_entry *generic;

	TRACE_ENTRY();

	generic = create_proc_read_entry(SCST_PROC_LOG_ENTRY_NAME,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 scst_proc_scsi_tgt,
					 scst_scsi_tgt_proc_info_log,
					 (void *)"scsi_tgt");
	if (generic) {
		generic->write_proc = scst_proc_scsi_tgt_gen_write_log;
	} else {
		PRINT_ERROR_PR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_LOG_ENTRY_NAME);
		res = -ENOMEM;
	}

	TRACE_EXIT_RES(res);
#endif
	return res;
}

static void scst_proc_cleanup_module_log(void)
{
#if defined(DEBUG) || defined(TRACING)
	TRACE_ENTRY();

	remove_proc_entry(SCST_PROC_LOG_ENTRY_NAME, scst_proc_scsi_tgt);

	TRACE_EXIT();
#endif
}

static int scst_proc_group_add_tree(struct scst_acg *acg, const char *p)
{
	int res = 0;
	struct proc_dir_entry *generic;

	TRACE_ENTRY();

	acg->acg_proc_root = proc_mkdir(p, scst_proc_groups_root);
	if (acg->acg_proc_root == NULL) {
		PRINT_ERROR_PR("Not enough memory to register %s entry in "
			       "/proc/%s/%s", p, SCST_PROC_ENTRY_NAME,
			       SCST_PROC_GROUPS_ENTRY_NAME);
		goto out;
	}

	generic = create_proc_read_entry(SCST_PROC_GROUPS_DEVICES_ENTRY_NAME,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 acg->acg_proc_root,
					 scst_proc_groups_devices_read,
					 (void *)acg);
	if (generic) {
		generic->write_proc = scst_proc_groups_devices_write;
	} else {
		PRINT_ERROR_PR("cannot init /proc/%s/%s/%s/%s",
			       SCST_PROC_ENTRY_NAME,
			       SCST_PROC_GROUPS_ENTRY_NAME,
			       p, SCST_PROC_GROUPS_DEVICES_ENTRY_NAME);
		res = -ENOMEM;
		goto out_remove;
	}

	generic = create_proc_read_entry(SCST_PROC_GROUPS_USERS_ENTRY_NAME,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 acg->acg_proc_root,
					 scst_proc_groups_names_read,
					 (void *)acg);
	if (generic) {
		generic->write_proc = scst_proc_groups_names_write;
	} else {
		PRINT_ERROR_PR("cannot init /proc/%s/%s/%s/%s",
			       SCST_PROC_ENTRY_NAME,
			       SCST_PROC_GROUPS_ENTRY_NAME,
			       p, SCST_PROC_GROUPS_USERS_ENTRY_NAME);
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
	remove_proc_entry(p, scst_proc_groups_root);
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
		PRINT_ERROR_PR("scst_alloc_add_acg() (name %s) failed", name);
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

static int scst_proc_init_groups(void)
{
	int res = 0;

	TRACE_ENTRY();

	/* create the proc directory entry for the device */
	scst_proc_groups_root = proc_mkdir(SCST_PROC_GROUPS_ENTRY_NAME,
					   scst_proc_scsi_tgt);
	if (scst_proc_groups_root == NULL) {
		PRINT_ERROR_PR("Not enough memory to register %s entry in "
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

struct scst_proc_update_struct {
	int len, plen, pplen;
	off_t begin, pbegin, ppbegin;
	off_t pos;
};

static int scst_proc_update_size(int size, off_t offset, int length,
	struct scst_proc_update_struct *p)
{
	int res;
	if (size > 0) {
		p->len += size;
		p->pos = p->begin + p->len;
		if (p->pos <= offset) {
			p->len = 0;
			p->begin = p->pos;
		} else if (p->pos >= offset + length) {
			res = 1;
			goto out;
		} else
			res = 0;
	} else {
		p->begin = p->ppbegin;
		p->len = p->pplen;
		res = 1;
		goto out;
	}
	p->ppbegin = p->pbegin;
	p->pplen = p->plen;
	p->pbegin = p->begin;
	p->plen = p->len;
out:
	return res;
}

static int scst_proc_sgv_read_1(char *buffer, off_t offset, int length,
	struct scst_proc_update_struct *p,
	const struct sgv_pool *pool, const char *name)
{
	int i, size;

	size = scnprintf(buffer + p->len, length - p->len, "\n%-20s %-11d %-11d\n",
		name, atomic_read(&pool->acc.hit_alloc),
		atomic_read(&pool->acc.total_alloc));
	if (scst_proc_update_size(size, offset, length, p))
		return 1;

	for(i = 0; i < SGV_POOL_ELEMENTS; i++) {
		size = scnprintf(buffer + p->len, length - p->len, 
			"  %-18s %-11d %-11d\n", pool->cache_names[i], 
			atomic_read(&pool->cache_acc[i].hit_alloc),
			atomic_read(&pool->cache_acc[i].total_alloc));
		if (scst_proc_update_size(size, offset, length, p))
			return 1;
	}
	return 0;
}

static int scst_proc_sgv_read(char *buffer, char **start,
	off_t offset, int length, int *eof, void *data)
{
	int res = 0;
	int size;
	struct scst_proc_update_struct st;

	TRACE_ENTRY();

	TRACE_DBG("offset: %d, length %d", (int) offset, length);

	memset(&st, 0, sizeof(st));

	size = scnprintf(buffer + st.len, length - st.len, "%-20s %-11s %-11s",
		"Name", "Hit", "Total");
	if (scst_proc_update_size(size, offset, length, &st))
		goto stop_output;

	if (scst_proc_sgv_read_1(buffer, offset, length, &st, &scst_sgv.norm,
			"sgv"))
		goto stop_output;

	if (scst_proc_sgv_read_1(buffer, offset, length, &st,
			&scst_sgv.norm_clust, "sgv-clust"))
		goto stop_output;

	if (scst_proc_sgv_read_1(buffer, offset, length, &st,
			&scst_sgv.dma, "sgv-dma"))
		goto stop_output;

#ifdef SCST_HIGHMEM
	if (scst_proc_sgv_read_1(buffer, offset, length, &st,
			&scst_sgv.highmem, "sgv-highmem"))
		goto stop_output;

#endif

	size = scnprintf(buffer + st.len, length - st.len, "\n%-32s %-11d\n", 
		"big", atomic_read(&sgv_big_total_alloc));
	if (scst_proc_update_size(size, offset, length, &st))
		goto stop_output;

	*eof = 1;

stop_output:
	*start = buffer + (offset - st.begin);
	st.len -= (offset - st.begin);
	if (st.len > length)
		st.len = length;
	res = max(0, st.len);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_init_sgv(void)
{
	int res = 0;
	struct proc_dir_entry *pr;

	TRACE_ENTRY();

	pr = create_proc_read_entry("sgv", S_IFREG | S_IRUGO,
		 scst_proc_scsi_tgt, scst_proc_sgv_read, NULL);
	if (pr == NULL) {
		PRINT_ERROR_PR("%s", "cannot create sgv /proc entry");
		res = -ENOMEM;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_proc_cleanup_sgv(void)
{
	TRACE_ENTRY();
	remove_proc_entry("sgv", scst_proc_scsi_tgt);
	TRACE_EXIT();
}

int scst_proc_init_module(void)
{
	int res = 0;
	struct proc_dir_entry *generic;

	TRACE_ENTRY();

	scst_proc_scsi_tgt = proc_mkdir(SCST_PROC_ENTRY_NAME, 0);
	if (!scst_proc_scsi_tgt) {
		PRINT_ERROR_PR("cannot init /proc/%s", SCST_PROC_ENTRY_NAME);
		goto out_nomem;
	}

	generic = create_proc_read_entry(SCST_PROC_ENTRY_NAME,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 scst_proc_scsi_tgt,
					 scst_scsi_tgt_proc_info, NULL);
	if (!generic) {
		PRINT_ERROR_PR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_ENTRY_NAME);
		goto out_remove;
	}
	generic->write_proc = scst_proc_scsi_tgt_gen_write;

	generic = create_proc_read_entry(SCST_PROC_VERSION_NAME,
					 S_IFREG | S_IRUGO,
					 scst_proc_scsi_tgt,
					 scst_proc_version_read, NULL);
	if (!generic) {
		PRINT_ERROR_PR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_VERSION_NAME);
		goto out_remove1;
	}

	generic = create_proc_read_entry(SCST_PROC_SESSIONS_NAME,
					 S_IFREG | S_IRUGO,
					 scst_proc_scsi_tgt,
					 scst_proc_sessions_read, NULL);
	if (!generic) {
		PRINT_ERROR_PR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_SESSIONS_NAME);
		goto out_remove2;
	}

	generic = create_proc_read_entry(SCST_PROC_HELP_NAME,
					 S_IFREG | S_IRUGO,
					 scst_proc_scsi_tgt,
					 scst_proc_help_read, NULL);
	if (!generic) {
		PRINT_ERROR_PR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_HELP_NAME);
		goto out_remove3;
	}

	generic = create_proc_read_entry(SCST_PROC_THREADS_NAME,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 scst_proc_scsi_tgt,
					 scst_proc_threads_read, NULL);
	if (!generic) {
		PRINT_ERROR_PR("cannot init /proc/%s/%s",
			    SCST_PROC_ENTRY_NAME, SCST_PROC_THREADS_NAME);
		goto out_remove4;
	}
	generic->write_proc = scst_proc_threads_write;

	if (scst_proc_init_module_log() < 0) {
		goto out_remove5;
	}

	if (scst_proc_init_groups() < 0) {
		goto out_remove6;
	}

	if (scst_proc_init_sgv() < 0) {
		goto out_remove7;
	}

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
	remove_proc_entry(SCST_PROC_ENTRY_NAME, 0);

out_nomem:
	res = -ENOMEM;
	goto out;
}

void scst_proc_cleanup_module(void)
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
	remove_proc_entry(SCST_PROC_ENTRY_NAME, 0);

	TRACE_EXIT();
}

static int scst_scsi_tgt_proc_info(char *buffer, char **start,
				   off_t offset, int length, int *eof,
				   void *data)
{
	int res = 0;
	int size, len = 0, plen, pplen;
	off_t begin = 0, pos = 0, pbegin, ppbegin;
	struct scst_device *dev;

	TRACE_ENTRY();

//TRACE(TRACE_SPECIAL, "offset=%ld, length=%d", offset, length);

	if (down_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	size = scnprintf(buffer + len, length - len, "%-60s%s\n",
		       "Device (host:ch:id:lun or name)",
		       "Device handler");

//TRACE(TRACE_SPECIAL, "size=%d, pos=%ld, begin=%ld, len=%d, buf %s",
//	size, pos, begin, len, buffer+len);

	if (size > 0) {
		len += size;
		pos = begin + len;
		if (pos <= offset) {
			len = 0;
			begin = pos;
		} else if (pos >= offset + length)
			goto stop_output;
	} else
		goto stop_output;

	ppbegin = pbegin = begin;
	pplen = plen = len;
	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		if (dev->virt_id == 0) {
			char conv[12];
			size = scnprintf(buffer + len, length - len,
				       "%d:%d:%d:",
					dev->scsi_dev->host->host_no,
					dev->scsi_dev->channel,
					dev->scsi_dev->id);
			sprintf(conv, "%%-%dd%%s\n", 60-size);
			size += scnprintf(buffer + len + size, length - len - size,
				        conv, dev->scsi_dev->lun,
					dev->handler ? dev->handler->name : "-");
		} else {
			size = scnprintf(buffer + len, length - len,
				       "%-60s%s\n",
				       dev->virt_name, dev->handler->name);
		}

//printk("size=%d, pbegin=%ld, plen=%d, ppbegin=%ld, pplen=%d, buf %s",
//	size, pbegin, plen, ppbegin, pplen, buffer+len);

		if (size > 0) {
			len += size;
			pos = begin + len;
			if (pos <= offset) {
				len = 0;
				begin = pos;
			}
//TRACE(TRACE_SPECIAL, "pos=%ld, begin=%ld, len=%d", pos, begin, len);
			if (pos >= offset + length)
				goto stop_output;
		} else {
			begin = ppbegin;
			len = pplen;
			goto stop_output;
		}
		ppbegin = pbegin;
		pplen = plen;
		pbegin = begin;
		plen = len;
	}

	*eof = 1;

stop_output:
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;
	res = max(0, len);

//TRACE(TRACE_SPECIAL, "res=%d, start=%ld, len=%d, begin=%ld, eof=%d", res, offset-begin, len, begin, *eof);

	up(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_version_read(char *buffer, char **start,off_t offset,
				  int length, int *eof, void *data)
{
	int res;

	TRACE_ENTRY();

	res = scnprintf(buffer, length, "%s\n", SCST_VERSION_STRING);

#ifdef STRICT_SERIALIZING
	if (res < length)
		res += scnprintf(&buffer[res], length-res, "Strict "
			"serializing enabled\n");
#endif

#ifdef EXTRACHECKS
	if (res < length)
		res += scnprintf(&buffer[res], length-res, "EXTRACHECKS\n");
#endif

#ifdef TRACING
	if (res < length)
		res += scnprintf(&buffer[res], length-res, "TRACING\n");
#endif

#ifdef DEBUG
	if (res < length)
		res += scnprintf(&buffer[res], length-res, "DEBUG\n");
#endif

#ifdef DEBUG_TM
	if (res < length)
		res += scnprintf(&buffer[res], length-res, "DEBUG_TM\n");
#endif

#ifdef DEBUG_RETRY
	if (res < length)
		res += scnprintf(&buffer[res], length-res, "DEBUG_RETRY\n");
#endif

#ifdef DEBUG_OOM
	if (res < length)
		res += scnprintf(&buffer[res], length-res, "DEBUG_OOM\n");
#endif

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_help_read(char *buffer, char **start, off_t offset,
			       int length, int *eof, void *data)
{
	int res;

	TRACE_ENTRY();

	res = scnprintf(buffer, length, "%s", scst_proc_help_string);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_threads_read(char *buffer, char **start,off_t offset,
				   int length, int *eof, void *data)
{
	int res;

	TRACE_ENTRY();

	/* 2 mgmt threads */
	res = scnprintf(buffer, length, "%d\n",
		atomic_read(&scst_threads_count) - 2);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_threads_write(struct file *file, const char *buf,
				   unsigned long length, void *data)
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

	if (down_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	oldtn = atomic_read(&scst_threads_count);
	newtn = simple_strtoul(buffer, NULL, 0) + 2; /* 2 mgmt threads */
	if (newtn <= 0) {
		PRINT_ERROR_PR("Illegal threads num value %d", newtn);
		res = -EINVAL;
		goto out_up_free;
	}
	delta = newtn - oldtn;
	if (delta < 0) {
		scst_del_threads(-delta);
	}
	else {
		scst_add_threads(delta);
	}

	PRINT_INFO_PR("Changed threads num: old %d, new %d(%d)", oldtn, newtn,
		       atomic_read(&scst_threads_count));

out_up_free:
	up(&scst_proc_mutex);

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
		PRINT_ERROR_PR("Not enough memory to register SCSI target %s "
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

int scst_build_proc_target_entries(struct scst_tgt *vtt)
{
	int res = 0;
	struct proc_dir_entry *p;
	char name[20];

	TRACE_ENTRY();

	if (vtt->tgtt->proc_info) {
		/* create the proc file entry for the device */
		scnprintf(name, sizeof(name), "%d", vtt->tgtt->proc_dev_num);
		p = create_proc_read_entry(name, S_IFREG | S_IRUGO | S_IWUSR,
					   vtt->tgtt->proc_tgt_root,
					   scst_proc_scsi_tgt_read,
					   (void *)vtt);
		if (p == NULL) {
			PRINT_ERROR_PR("Not enough memory to register SCSI "
			     "target entry %s in /proc/%s/%s", name,
			     SCST_PROC_ENTRY_NAME, vtt->tgtt->name);
			res = -ENOMEM;
			goto out;
		}
		p->write_proc = scst_proc_scsi_tgt_write;
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

	if (vtt->tgtt->proc_info) {
		scnprintf(name, sizeof(name), "%d", vtt->proc_num);
		remove_proc_entry(name, vtt->tgtt->proc_tgt_root);
	}

	TRACE_EXIT();
	return;
}

static int scst_proc_scsi_tgt_read(char *buffer, char **start,
				   off_t offset, int length, int *eof,
				   void *data)
{
	struct scst_tgt *vtt = data;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("offset: %d, length %d, id: %d",
	      (int) offset, length, vtt->proc_num);

	if (down_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	if (vtt->tgtt->proc_info) {
		res = vtt->tgtt->proc_info(buffer, start, offset, length, eof,
		    vtt, 0);
	}

	up(&scst_proc_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_scsi_tgt_write(struct file *file, const char *buf,
				    unsigned long length, void *data)
{
	struct scst_tgt *vtt = data;
	ssize_t res = 0;
	char *buffer;
	char *start;
	int eof = 0;

	TRACE_ENTRY();

	if (vtt->tgtt->proc_info == NULL) {
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

	if (down_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	res = vtt->tgtt->proc_info(buffer, &start, 0, length, &eof, vtt, 1);

	up(&scst_proc_mutex);

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

	if (dev_type->proc_dev_type_root) {
		goto out;
	}
	/* create the proc directory entry for the dev type handler */
	dev_type->proc_dev_type_root = proc_mkdir(dev_type->name,
						  scst_proc_scsi_tgt);
	if (dev_type->proc_dev_type_root == NULL) {
		PRINT_ERROR_PR("Not enough memory to register dev handler dir "
		    "%s in /proc/%s", dev_type->name, SCST_PROC_ENTRY_NAME);
		goto out_nomem;
	}

	p = create_proc_read_entry(SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME,
				   S_IFREG | S_IRUGO,
				   dev_type->proc_dev_type_root,
				   scst_proc_scsi_dev_handler_type_read,
				   (void *)dev_type);
	if (p == NULL) {
		PRINT_ERROR_PR("Not enough memory to register dev "
		     "handler entry %s in /proc/%s/%s",
		     SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME,
		     SCST_PROC_ENTRY_NAME, dev_type->name);
		goto out_remove;
	}

	if (dev_type->proc_info) {
		/* create the proc file entry for the dev type handler */
		p = create_proc_read_entry(dev_type->name,
					   S_IFREG | S_IRUGO | S_IWUSR,
					   dev_type->proc_dev_type_root,
					   scst_proc_scsi_dev_handler_read,
					   (void *)dev_type);
		if (p == NULL) {
			PRINT_ERROR_PR("Not enough memory to register dev "
			     "handler entry %s in /proc/%s/%s", dev_type->name,
			     SCST_PROC_ENTRY_NAME, dev_type->name);
			goto out_remove1;
		}
		p->write_proc = scst_proc_scsi_dev_handler_write;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_remove1:
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

	if (dev_type->proc_dev_type_root) {
		remove_proc_entry(SCST_PROC_DEV_HANDLER_TYPE_ENTRY_NAME,
				  dev_type->proc_dev_type_root);
		if (dev_type->proc_info) {
			remove_proc_entry(dev_type->name,
					  dev_type->proc_dev_type_root);
		}
		remove_proc_entry(dev_type->name, scst_proc_scsi_tgt);
		dev_type->proc_dev_type_root = NULL;
	}

	TRACE_EXIT();
	return;
}

static int scst_proc_scsi_dev_handler_type_read(char *buffer, char **start,
						off_t offset, int length,
						int *eof, void *data)
{
	struct scst_dev_type *dev_type = data;
	int n = 0;

	TRACE_ENTRY();

	n = scnprintf(buffer, length, "%d - %s\n", dev_type->type,
		    dev_type->type > 0x0f ?
		    "unknown" : scst_proc_dev_handler_type[dev_type->type]);

	TRACE_EXIT_RES(n);
	return n;
}

static int scst_proc_scsi_dev_handler_read(char *buffer, char **start,
					   off_t offset, int length, int *eof,
					   void *data)
{
	struct scst_dev_type *dev_type = data;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("offset: %d, length %d, name: %s",
	      (int) offset, length, dev_type->name);

	if (down_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	if (dev_type->proc_info) {
		res = dev_type->proc_info(buffer, start, offset, length, eof,
		    dev_type, 0);
	}

	up(&scst_proc_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_scsi_dev_handler_write(struct file *file, const char *buf,
					    unsigned long length, void *data)
{
	struct scst_dev_type *dev_type = data;
	ssize_t res = 0;
	char *buffer;
	char *start;
	int eof = 0;

	TRACE_ENTRY();

	if (dev_type->proc_info == NULL) {
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

	if (!(buffer = (char *)__get_free_page(GFP_KERNEL))) {
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

	if (down_interruptible(&scst_proc_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	res = dev_type->proc_info(buffer, &start, 0, length, &eof, dev_type, 1);

	up(&scst_proc_mutex);

out_free:
	free_page((unsigned long)buffer);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_scsi_tgt_gen_write(struct file *file,
					const char *buf,
					unsigned long length, void *data)
{
	int res = length, rc = 0, action;
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
	if (p[strlen(p) - 1] == '\n') {
		p[strlen(p) - 1] = '\0';
	}
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
		PRINT_ERROR_PR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	if (down_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	switch (action) {
	case SCST_PROC_ACTION_ADD_GROUP:
	case SCST_PROC_ACTION_DEL_GROUP:
		if (strcmp(p, SCST_DEFAULT_ACG_NAME) == 0) {
			PRINT_ERROR_PR("Attempt to add/delete predefined "
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
				PRINT_ERROR_PR("acg name %s exist", p);
				res = -EINVAL;
				goto out_up_free;
			}
			rc = scst_proc_group_add(p);
			break;
		case SCST_PROC_ACTION_DEL_GROUP:
			if (acg == NULL) {
				PRINT_ERROR_PR("acg name %s not found", p);
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
	up(&scst_mutex);

out_free:
	free_page((unsigned long)buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_mutex */
static int scst_proc_assign_handler(char *buf)
{
	int res = 0;
	char *p = buf, *e, *ee;
	int host, channel = 0, id = 0, lun = 0;
	struct scst_device *d, *dev = NULL;
	struct scst_dev_type *dt, *handler = NULL;

	TRACE_ENTRY();

	while (isspace(*p) && *p != '\0') {
		p++;
	}

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
	while (isspace(*e) && *e != '\0') {
		e++;
	}
	ee = e;
	while (!isspace(*ee) && *ee != '\0') {
		ee++;
	}
	*ee = '\0';

	TRACE_DBG("Dev %d:%d:%d:%d, handler %s", host, channel, id, lun, e);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if ((d->virt_id == 0) &&
		    d->scsi_dev->host->host_no == host &&
		    d->scsi_dev->channel == channel &&
		    d->scsi_dev->id == id &&
		    d->scsi_dev->lun == lun)
		{
			dev = d;
			TRACE_DBG("Dev %p (%d:%d:%d:%d) found",
				  dev, host, channel, id, lun);
			break;
		}
	}

	if (dev == NULL) {
		PRINT_ERROR_PR("Device %d:%d:%d:%d not found",
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
		PRINT_ERROR_PR("Handler %s not found", e);
		res = -EINVAL;
		goto out;
	}

	if (dev->scsi_dev->type != handler->type) {
		PRINT_ERROR_PR("Type %d of device %s differs from type "
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
	PRINT_ERROR_PR("Syntax error on %s", p);
	res = -EINVAL;
	goto out;
}

static int scst_proc_groups_devices_read(char *buffer, char **start,
					 off_t offset, int length, int *eof,
					 void *data)
{
	int res = 0;
	struct scst_acg *acg = (struct scst_acg *)data;
	struct scst_acg_dev *acg_dev;
	int size, len = 0, plen, pplen;
	off_t begin = 0, pos = 0, pbegin, ppbegin;

	TRACE_ENTRY();

	if (down_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	size = scnprintf(buffer + len, length - len, "%-60s%s  %s\n",
		       "Device (host:ch:id:lun or name)",
		       "Virtual lun", "Options");
	if (size > 0) {
		len += size;
		pos = begin + len;
		if (pos <= offset) {
			len = 0;
			begin = pos;
		} else if (pos >= offset + length)
			goto stop_output;
	} else
		goto stop_output;

	ppbegin = pbegin = begin;
	pplen = plen = len;
	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		if (acg_dev->dev->virt_id == 0) {
			char conv[20];
			size = scnprintf(buffer + len, length - len,
				        "%d:%d:%d:",
					acg_dev->dev->scsi_dev->host->host_no,
					acg_dev->dev->scsi_dev->channel,
					acg_dev->dev->scsi_dev->id);
			sprintf(conv, "%%-%dd%%4d%%12s\n", 60-size);
			size += scnprintf(buffer + len + size,
					length - len - size, conv,
					acg_dev->dev->scsi_dev->lun,
					acg_dev->lun,
					acg_dev->rd_only_flag ? "RO" : "");
		} else {
			size = scnprintf(buffer + len, length - len,
				       "%-60s%4d%12s\n",
				       acg_dev->dev->virt_name, acg_dev->lun,
				       acg_dev->rd_only_flag ? "RO" : "");
		}
		if (size > 0) {
			len += size;
			pos = begin + len;
			if (pos <= offset) {
				len = 0;
				begin = pos;
			} else if (pos >= offset + length)
				goto stop_output;
		} else {
			begin = ppbegin;
			len = pplen;
			goto stop_output;
		}
		ppbegin = pbegin;
		pplen = plen;
		pbegin = begin;
		plen = len;
	}

	*eof = 1;

stop_output:
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;
	res = max(0, len);

	up(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_groups_devices_write(struct file *file, const char *buf,
					  unsigned long length, void *data)
{
	int res = length, action, virt = 0, rc, read_only = 0;
	char *buffer, *p, *e = NULL;
	int host, channel = 0, id = 0, lun = 0, virt_lun;
	struct scst_acg *acg = (struct scst_acg *)data;
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
	 * Usage: echo "add|del H:C:I:L lun [READ_ONLY]" >/proc/scsi_tgt/groups/GROUP/devices
	 *   or   echo "add|del V_NAME lun [READ_ONLY]" >/proc/scsi_tgt/groups/GROUP/devices
	 *   or   echo "clear" >/proc/scsi_tgt/groups/GROUP/devices
	 */
	p = buffer;
	if (p[strlen(p) - 1] == '\n') {
		p[strlen(p) - 1] = '\0';
	}
	if (!strncasecmp("clear", p, 5)) {
		action = SCST_PROC_ACTION_CLEAR;
	} else if (!strncasecmp("add ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_ADD;
	} else if (!strncasecmp("del ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_DEL;
	} else {
		PRINT_ERROR_PR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	if (down_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	switch (action) {
	case SCST_PROC_ACTION_ADD:
	case SCST_PROC_ACTION_DEL:
		while (isspace(*p) && *p != '\0') {
			p++;
		}
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
			while (!isspace(*e) && *e != '\0') {
				e++;
			}
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
				PRINT_ERROR_PR("Virt device %s not found", p);
			} else {
				PRINT_ERROR_PR("Device %d:%d:%d:%d not found",
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
		while (isspace(*e) && *e != '\0') {
			e++;
		}
		virt_lun = simple_strtoul(e, &e, 0);

		while (isspace(*e) && *e != '\0') {
			e++;
		}
		if (!strncasecmp("READ_ONLY", e, 9)) {
			read_only = 1;
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
			PRINT_ERROR_PR("virt lun %d exist in group %s",
				       virt_lun, acg->acg_name);
			res = -EINVAL;
			goto out_free_up;
		}
		rc = scst_acg_add_dev(acg, dev, virt_lun, read_only);
		if (rc) {
			PRINT_ERROR_PR("scst_acg_add_dev() returned %d", rc);
			res = rc;
		}
		break;
	case SCST_PROC_ACTION_DEL:
		rc = scst_acg_remove_dev(acg, dev);
		if (rc) {
			PRINT_ERROR_PR("scst_acg_remove_dev() returned %d", rc);
			res = rc;
		}
		break;
	case SCST_PROC_ACTION_CLEAR:
		list_for_each_entry_safe(acg_dev, acg_dev_tmp,
					 &acg->acg_dev_list,
					 acg_dev_list_entry) {
			rc = scst_acg_remove_dev(acg, acg_dev->dev);
			if (rc) {
				PRINT_ERROR_PR("scst_acg_remove_dev() "
					       "return %d", rc);
				res = rc;
			}
		}
		break;
	}

out_free_up:
	up(&scst_mutex);

out_free:
	free_page((unsigned long)buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_sessions_read(char *buffer, char **start,
					 off_t offset, int length, int *eof,
					 void *data)
{
	int res = 0;
	struct scst_acg *acg;
	struct scst_session *sess;
	int size, len = 0, plen, pplen;
	off_t begin = 0, pos = 0,  pbegin, ppbegin;

	TRACE_ENTRY();

	if (down_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	size = scnprintf(buffer + len, length - len, "%-20s%-35s%-20s%-15s\n",
		       "Target name", "Initiator name", "Group name", 
		       "Command Count");
	if (size > 0) {
		len += size;
		pos = begin + len;
		if (pos <= offset) {
			len = 0;
			begin = pos;
		} else if (pos >= offset + length)
			goto stop_output;
	} else
		goto stop_output;

	ppbegin = pbegin = begin;
	pplen = plen = len;
	list_for_each_entry(acg, &scst_acg_list, scst_acg_list_entry) {
		list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) {
			size = scnprintf(buffer + len, length - len,
				       "%-20s%-35s%-20s%-15d\n",
					sess->tgt->tgtt->name,
					sess->initiator_name,
				       acg->acg_name,
				       sess->sess_cmd_count);
			if (size > 0) {
				len += size;
				pos = begin + len;
				if (pos <= offset) {
					len = 0;
					begin = pos;
				} else if (pos >= offset + length)
					goto stop_output;
			} else {
				begin = ppbegin;
				len = pplen;
				goto stop_output;
			}
			ppbegin = pbegin;
			pplen = plen;
			pbegin = begin;
			plen = len;
		}
	}

	*eof = 1;

stop_output:
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;
	res = max(0, len);

	up(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_groups_names_read(char *buffer, char **start,
				       off_t offset, int length, int *eof,
				       void *data)
{
	int res = 0;
	struct scst_acg *acg = (struct scst_acg *)data;
	struct scst_acn *name;
	int size, len = 0, plen, pplen;
	off_t begin = 0, pos = 0, pbegin, ppbegin;

	TRACE_ENTRY();

	if (down_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	ppbegin = pbegin = begin;
	pplen = plen = len;
	list_for_each_entry(name, &acg->acn_list, acn_list_entry) {
		size = scnprintf(buffer + len, length - len, "%s\n",
			name->name);
		if (size > 0) {
			len += size;
			pos = begin + len;
			if (pos <= offset) {
				len = 0;
				begin = pos;
			} else if (pos >= offset + length)
				goto stop_output;
		} else {
			begin = ppbegin;
			len = pplen;
			goto stop_output;
		}
		ppbegin = pbegin;
		pplen = plen;
		pbegin = begin;
		plen = len;
	}

	*eof = 1;

stop_output:
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;
	res = max(0, len);

	up(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_proc_groups_names_write(struct file *file, const char *buf,
					unsigned long length, void *data)
{
	int res = length, action;
	char *buffer, *p, *e;
	struct scst_acg *acg = (struct scst_acg *)data;
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
	if (p[strlen(p) - 1] == '\n') {
		p[strlen(p) - 1] = '\0';
	}
	if (!strncasecmp("clear", p, 5)) {
		action = SCST_PROC_ACTION_CLEAR;
	} else if (!strncasecmp("add ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_ADD;
	} else if (!strncasecmp("del ", p, 4)) {
		p += 4;
		action = SCST_PROC_ACTION_DEL;
	} else {
		PRINT_ERROR_PR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	switch (action) {
	case SCST_PROC_ACTION_ADD:
	case SCST_PROC_ACTION_DEL:
		while (isspace(*p) && *p != '\0') {
			p++;
		}
		e = p;
		while (!isspace(*e) && *e != '\0') {
			e++;
		}
		*e = 0;
		break;
	}

	if (down_interruptible(&scst_mutex) != 0) {
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

	up(&scst_mutex);

out_free:
	free_page((unsigned long)buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}
