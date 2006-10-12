#include <scsi/scsi_eh.h>

#define SCST_DEV_UA_RETRIES 5

#if defined(DEBUG) || defined(TRACING)

#define DEV_HANDLER_LOG_ENTRY_NAME "trace_level"

#include <linux/module.h>
#include <linux/proc_fs.h>

#ifdef DEBUG
#define SCST_DEFAULT_DEV_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_PID | \
        TRACE_FUNCTION | TRACE_MGMT | TRACE_MINOR | TRACE_MGMT_DEBUG)
#else
#define SCST_DEFAULT_DEV_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MINOR)
#endif

static int scst_dev_handler_proc_log_entry_read(char *buffer, char **start,
	off_t offset, int length, int *eof, void *data)
{
	int res = 0;

	TRACE_ENTRY();
	res = scst_proc_log_entry_read(buffer, start, offset, length, eof,
				       data, trace_flag, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_dev_handler_proc_log_entry_write(struct file *file,
	const char *buf, unsigned long length, void *data)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, data,
				&trace_flag, SCST_DEFAULT_DEV_LOG_FLAGS, NULL);

	TRACE_EXIT_RES(res);
	return res;
}
#endif /* defined(DEBUG) || defined(TRACING) */

static int scst_dev_handler_build_std_proc(struct scst_dev_type *dev_type)
{
	int res = 0;
#if defined(DEBUG) || defined(TRACING)
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);

	if (root) {
		/* create the proc file entry for the device */
		p = create_proc_read_entry(DEV_HANDLER_LOG_ENTRY_NAME,
					   S_IFREG | S_IRUGO | S_IWUSR, root,
					   scst_dev_handler_proc_log_entry_read,
					   (void *)dev_type->name);
		if (p == NULL) {
			PRINT_ERROR_PR("Not enough memory to register dev "
			     "handler %s entry %s in /proc",
			      dev_type->name, DEV_HANDLER_LOG_ENTRY_NAME);
			res = -ENOMEM;
			goto out;
		}
		p->write_proc = scst_dev_handler_proc_log_entry_write;
	}

out:
	TRACE_EXIT_RES(res);
#endif
	return res;
}

static void scst_dev_handler_destroy_std_proc(struct scst_dev_type *dev_type)
{
#if defined(DEBUG) || defined(TRACING)
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);

	if (root) {
		remove_proc_entry(DEV_HANDLER_LOG_ENTRY_NAME, root);
	}
	TRACE_EXIT();
#endif
}

