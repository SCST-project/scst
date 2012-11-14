#ifndef __SCST_DEV_HANDLER_H
#define __SCST_DEV_HANDLER_H

#include <linux/module.h>
#include <scsi/scsi_eh.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_debug.h>
#else
#include "scst_debug.h"
#endif

#define SCST_DEV_RETRIES_ON_UA 5
#define SCST_PASSTHROUGH_RETRIES	0

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#ifdef CONFIG_SCST_DEBUG
#define SCST_DEFAULT_DEV_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_PID | \
	TRACE_LINE | TRACE_FUNCTION | TRACE_MGMT | TRACE_MINOR | \
	TRACE_MGMT_DEBUG | TRACE_SPECIAL)
#else
#define SCST_DEFAULT_DEV_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_SPECIAL)
#endif

static unsigned long dh_trace_flag = SCST_DEFAULT_DEV_LOG_FLAGS;
#define trace_flag dh_trace_flag

#ifdef CONFIG_SCST_PROC

#define DEV_HANDLER_LOG_ENTRY_NAME "trace_level"

#ifndef trace_log_tbl
#define trace_log_tbl	NULL
#endif

static struct scst_proc_data dev_handler_log_proc_data;

static int dev_handler_log_info_show(struct seq_file *seq, void *v)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_read(seq, trace_flag, trace_log_tbl);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_dev_handler_proc_log_entry_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, &trace_flag,
			SCST_DEFAULT_DEV_LOG_FLAGS, trace_log_tbl);

	TRACE_EXIT_RES(res);
	return res;
}

#endif /* CONFIG_SCST_PROC */

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

#ifdef CONFIG_SCST_PROC

static int scst_dev_handler_build_std_proc(struct scst_dev_type *dev_type)
{
	int res = 0;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	if (root) {
		/* Create the proc file entry for the device */
		/* Workaround to keep /proc ABI intact */
		const char *name;
		if (strcmp(dev_type->name, "vdisk_fileio") == 0)
			name = "vdisk";
		else
			name = dev_type->name;
		dev_handler_log_proc_data.data = (void *)name;
		p = scst_create_proc_entry(root, DEV_HANDLER_LOG_ENTRY_NAME,
					   &dev_handler_log_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register dev "
			     "handler %s entry %s in /proc",
			     name, DEV_HANDLER_LOG_ENTRY_NAME);
			res = -ENOMEM;
			goto out;
		}
	}

out:
	TRACE_EXIT_RES(res);
#endif
	return res;
}

static void scst_dev_handler_destroy_std_proc(struct scst_dev_type *dev_type)
{
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	if (root)
		remove_proc_entry(DEV_HANDLER_LOG_ENTRY_NAME, root);

	TRACE_EXIT();
#endif
}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static struct scst_proc_data dev_handler_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(scst_dev_handler_proc_log_entry_write)
	.show = dev_handler_log_info_show,
};
#endif

#endif /* CONFIG_SCST_PROC */

#endif /* __SCST_DEV_HANDLER_H */
