/*
 *  scst_vdisk.c
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 *  Copyright (C) 2007 Ross Walker <rswwalker at hotmail dot com>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *  Copyright (C) 2008 - 2013 Bart Van Assche <bvanassche@acm.org>
 *
 *  SCSI disk (type 0) and CDROM (type 5) dev handler using files
 *  on file systems or block devices (VDISK)
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

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/uio.h>
#include <linux/list.h>
#include <linux/ctype.h>
#include <linux/writeback.h>
#include <linux/vmalloc.h>
#include <asm/atomic.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#ifndef INSIDE_KERNEL_TREE
#include <linux/version.h>
#endif
#include <asm/div64.h>
#include <asm/unaligned.h>
#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/crc32c.h>
#include <linux/swap.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
#include <linux/falloc.h>
#endif

#define LOG_PREFIX			"dev_vdisk"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define TRACE_ORDER	0x80000000

static struct scst_trace_log vdisk_local_trace_tbl[] = {
	{ TRACE_ORDER,		"order" },
	{ 0,			NULL }
};
#define trace_log_tbl			vdisk_local_trace_tbl

#define VDISK_TRACE_TBL_HELP	", order"

#endif

#include "scst_dev_handler.h"

/* 8 byte ASCII Vendor */
#define SCST_FIO_VENDOR			"SCST_FIO"
#define SCST_BIO_VENDOR			"SCST_BIO"
/* 4 byte ASCII Product Revision Level - left aligned */
#define SCST_FIO_REV			" 300"

#define MAX_USN_LEN			(20+1) /* For '\0' */

#define INQ_BUF_SZ			256
#define EVPD				0x01
#define CMDDT				0x02

#define MSENSE_BUF_SZ			256
#define DBD				0x08	/* disable block descriptor */
#define WP				0x80	/* write protect */
#define DPOFUA				0x10	/* DPOFUA bit */
#define WCE				0x04	/* write cache enable */

#define PF				0x10	/* page format */
#define SP				0x01	/* save pages */
#define PS				0x80	/* parameter saveable */

#define	DEF_DISK_BLOCK_SHIFT		9
#define	DEF_CDROM_BLOCK_SHIFT		11
#define	DEF_SECTORS			56
#define	DEF_HEADS			255
#define LEN_MEM				(32 * 1024)
#define DEF_RD_ONLY			0
#define DEF_WRITE_THROUGH		0
#define DEF_NV_CACHE			0
#define DEF_O_DIRECT			0
#define DEF_DUMMY			0
#define DEF_REMOVABLE			0
#define DEF_ROTATIONAL			1
#define DEF_THIN_PROVISIONED		0

#define VDISK_NULLIO_SIZE		(5LL*1024*1024*1024*1024/2)

#define DEF_TST				SCST_CONTR_MODE_SEP_TASK_SETS

/*
 * Since we can't control backstorage device's reordering, we have to always
 * report unrestricted reordering.
 */
#define DEF_QUEUE_ALG_WT	SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER
#define DEF_QUEUE_ALG		SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER
#define DEF_SWP			0
#define DEF_TAS			0

#define DEF_DSENSE		SCST_CONTR_MODE_FIXED_SENSE

#ifdef CONFIG_SCST_PROC
#define VDISK_PROC_HELP		"help"
#endif

struct scst_vdisk_dev {
	uint64_t nblocks;
	loff_t file_size;	/* in bytes */

	/*
	 * This lock can be taken on both SIRQ and thread context, but in
	 * all cases for each particular instance it's taken consistenly either
	 * on SIRQ or thread context. Mix of them is forbidden.
	 */
	spinlock_t flags_lock;

	/*
	 * Below flags are protected by flags_lock or suspended activity
	 * with scst_vdisk_mutex.
	 */
	unsigned int rd_only:1;
	unsigned int wt_flag:1;
	unsigned int nv_cache:1;
	unsigned int o_direct_flag:1;
	unsigned int zero_copy:1;
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int blockio:1;
	unsigned int cdrom_empty:1;
	unsigned int dummy:1;
	unsigned int removable:1;
	unsigned int thin_provisioned:1;
	unsigned int thin_provisioned_manually_set:1;
	unsigned int dev_thin_provisioned:1;
	unsigned int rotational:1;
	unsigned int format_active:1;

	struct file *fd;
	struct block_device *bdev;

	uint64_t format_progress_to_do, format_progress_done;

	int virt_id;
	char name[16+1];	/* Name of the virtual device,
				   must be <= SCSI Model + 1 */
	char *filename;		/* File name, protected by
				   scst_mutex and suspended activities */
	uint16_t command_set_version;

	/* All 4 protected by vdisk_serial_rwlock */
	unsigned int t10_dev_id_set:1; /* true if t10_dev_id manually set */
	unsigned int usn_set:1; /* true if usn manually set */
	char t10_dev_id[16+8+2]; /* T10 device ID */
	char usn[MAX_USN_LEN];

	struct scst_device *dev;
	struct list_head vdev_list_entry;

	struct scst_dev_type *vdev_devt;

	int tgt_dev_cnt;

	/* Only to pass it to attach() callback. Don't use it anywhere else! */
	int blk_shift;
};

struct vdisk_cmd_params {
	struct scatterlist small_sg[4];
	struct iovec *iv;
	int iv_count;
	struct iovec small_iv[4];
	struct scst_cmd *cmd;
	loff_t loff;
	int fua;
	bool use_zero_copy;
};

enum compl_status_e {
#if defined(SCST_DEBUG)
	COMPL_STATUS_START_AT = 777,
#endif
	CMD_SUCCEEDED,
	CMD_FAILED,
	RUNNING_ASYNC,
	INVALID_OPCODE,
};

typedef enum compl_status_e (*vdisk_op_fn)(struct vdisk_cmd_params *p);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#define DEF_NUM_THREADS		5
#else
/* Context RA patch supposed to be applied on the kernel */
#define DEF_NUM_THREADS		8
#endif
static int num_threads = DEF_NUM_THREADS;

module_param_named(num_threads, num_threads, int, S_IRUGO);
MODULE_PARM_DESC(num_threads, "vdisk threads count");

static int vdisk_attach(struct scst_device *dev);
static void vdisk_detach(struct scst_device *dev);
static int vdisk_attach_tgt(struct scst_tgt_dev *tgt_dev);
static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev);
static int fileio_alloc_data_buf(struct scst_cmd *cmd);
static int vdisk_parse(struct scst_cmd *);
static int vcdrom_parse(struct scst_cmd *);
static int non_fileio_parse(struct scst_cmd *);
static int vdisk_exec(struct scst_cmd *cmd);
static int vcdrom_exec(struct scst_cmd *cmd);
static int non_fileio_exec(struct scst_cmd *cmd);
static void fileio_on_free_cmd(struct scst_cmd *cmd);
static enum compl_status_e nullio_exec_read(struct vdisk_cmd_params *p);
static enum compl_status_e blockio_exec_read(struct vdisk_cmd_params *p);
static enum compl_status_e fileio_exec_read(struct vdisk_cmd_params *p);
static enum compl_status_e nullio_exec_write(struct vdisk_cmd_params *p);
static enum compl_status_e blockio_exec_write(struct vdisk_cmd_params *p);
static enum compl_status_e fileio_exec_write(struct vdisk_cmd_params *p);
static void blockio_exec_rw(struct vdisk_cmd_params *p, bool write, bool fua);
static int vdisk_blockio_flush(struct block_device *bdev, gfp_t gfp_mask,
	bool report_error, struct scst_cmd *cmd, bool async);
static enum compl_status_e blockio_exec_verify(struct vdisk_cmd_params *p);
static enum compl_status_e fileio_exec_verify(struct vdisk_cmd_params *p);
static enum compl_status_e blockio_exec_write_verify(struct vdisk_cmd_params *p);
static enum compl_status_e fileio_exec_write_verify(struct vdisk_cmd_params *p);
static enum compl_status_e nullio_exec_write_verify(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_read_capacity(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_read_capacity16(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_get_lba_status(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_report_tpgs(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_inquiry(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_request_sense(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_mode_sense(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_mode_select(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_log(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_read_toc(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_prevent_allow_medium_removal(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_unmap(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_write_same(struct vdisk_cmd_params *p);
static int vdisk_fsync(struct vdisk_cmd_params *p, loff_t loff,
	loff_t len, struct scst_device *dev, gfp_t gfp_flags,
	struct scst_cmd *cmd, bool async);
#ifdef CONFIG_SCST_PROC
static int vdisk_read_proc(struct seq_file *seq,
	struct scst_dev_type *dev_type);
static int vdisk_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type);
static int vcdrom_read_proc(struct seq_file *seq,
	struct scst_dev_type *dev_type);
static int vcdrom_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type);
#else
static ssize_t vdisk_add_fileio_device(const char *device_name, char *params);
static ssize_t vdisk_add_blockio_device(const char *device_name, char *params);
static ssize_t vdisk_add_nullio_device(const char *device_name, char *params);
static ssize_t vdisk_del_device(const char *device_name);
static ssize_t vcdrom_add_device(const char *device_name, char *params);
static ssize_t vcdrom_del_device(const char *device_name);
#endif
static void vdisk_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev);
static uint64_t vdisk_gen_dev_id_num(const char *virt_dev_name);
static int vdisk_unmap_range(struct scst_cmd *cmd,
	struct scst_vdisk_dev *virt_dev, uint64_t start_lba, uint32_t blocks);

/** SYSFS **/

#ifndef CONFIG_SCST_PROC

static ssize_t vdev_sysfs_size_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_blocksize_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_rd_only_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_wt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_tp_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_rotational_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_nv_cache_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_o_direct_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdev_sysfs_dummy_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_removable_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdev_sysfs_filename_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_resync_size_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);
static ssize_t vdev_sysfs_t10_dev_id_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);
static ssize_t vdev_sysfs_t10_dev_id_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdev_sysfs_usn_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);
static ssize_t vdev_sysfs_usn_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdev_zero_copy_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);

static ssize_t vcdrom_sysfs_filename_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);

static struct kobj_attribute vdev_size_attr =
	__ATTR(size_mb, S_IRUGO, vdev_sysfs_size_show, NULL);
static struct kobj_attribute vdisk_blocksize_attr =
	__ATTR(blocksize, S_IRUGO, vdisk_sysfs_blocksize_show, NULL);
static struct kobj_attribute vdisk_rd_only_attr =
	__ATTR(read_only, S_IRUGO, vdisk_sysfs_rd_only_show, NULL);
static struct kobj_attribute vdisk_wt_attr =
	__ATTR(write_through, S_IRUGO, vdisk_sysfs_wt_show, NULL);
static struct kobj_attribute vdisk_tp_attr =
	__ATTR(thin_provisioned, S_IRUGO, vdisk_sysfs_tp_show, NULL);
static struct kobj_attribute vdisk_rotational_attr =
	__ATTR(rotational, S_IRUGO, vdisk_sysfs_rotational_show, NULL);
static struct kobj_attribute vdisk_nv_cache_attr =
	__ATTR(nv_cache, S_IRUGO, vdisk_sysfs_nv_cache_show, NULL);
static struct kobj_attribute vdisk_o_direct_attr =
	__ATTR(o_direct, S_IRUGO, vdisk_sysfs_o_direct_show, NULL);
static struct kobj_attribute vdev_dummy_attr =
	__ATTR(dummy, S_IRUGO, vdev_sysfs_dummy_show, NULL);
static struct kobj_attribute vdisk_removable_attr =
	__ATTR(removable, S_IRUGO, vdisk_sysfs_removable_show, NULL);
static struct kobj_attribute vdisk_filename_attr =
	__ATTR(filename, S_IRUGO, vdev_sysfs_filename_show, NULL);
static struct kobj_attribute vdisk_resync_size_attr =
	__ATTR(resync_size, S_IWUSR, NULL, vdisk_sysfs_resync_size_store);
static struct kobj_attribute vdev_t10_dev_id_attr =
	__ATTR(t10_dev_id, S_IWUSR|S_IRUGO, vdev_sysfs_t10_dev_id_show,
		vdev_sysfs_t10_dev_id_store);
static struct kobj_attribute vdev_usn_attr =
	__ATTR(usn, S_IWUSR|S_IRUGO, vdev_sysfs_usn_show, vdev_sysfs_usn_store);
static struct kobj_attribute vdev_zero_copy_attr =
	__ATTR(zero_copy, S_IRUGO, vdev_zero_copy_show, NULL);

static struct kobj_attribute vcdrom_filename_attr =
	__ATTR(filename, S_IRUGO|S_IWUSR, vdev_sysfs_filename_show,
		vcdrom_sysfs_filename_store);

static const struct attribute *vdisk_fileio_attrs[] = {
	&vdev_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_wt_attr.attr,
	&vdisk_tp_attr.attr,
	&vdisk_rotational_attr.attr,
	&vdisk_nv_cache_attr.attr,
	&vdisk_o_direct_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_filename_attr.attr,
	&vdisk_resync_size_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_usn_attr.attr,
	&vdev_zero_copy_attr.attr,
	NULL,
};

static const struct attribute *vdisk_blockio_attrs[] = {
	&vdev_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_wt_attr.attr,
	&vdisk_nv_cache_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_rotational_attr.attr,
	&vdisk_filename_attr.attr,
	&vdisk_resync_size_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_usn_attr.attr,
	&vdisk_tp_attr.attr,
	NULL,
};

static const struct attribute *vdisk_nullio_attrs[] = {
	&vdev_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdev_dummy_attr.attr,
	&vdisk_removable_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_usn_attr.attr,
	&vdisk_rotational_attr.attr,
	NULL,
};

static const struct attribute *vcdrom_attrs[] = {
	&vdev_size_attr.attr,
	&vcdrom_filename_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_usn_attr.attr,
	NULL,
};

#endif /* CONFIG_SCST_PROC */

/* Protects vdisks addition/deletion and related activities, like search */
static DEFINE_MUTEX(scst_vdisk_mutex);

/* Protects devices t10_dev_id and usn */
static DEFINE_RWLOCK(vdisk_serial_rwlock);

/* Protected by scst_vdisk_mutex */
static LIST_HEAD(vdev_list);

static struct kmem_cache *vdisk_cmd_param_cachep;

static vdisk_op_fn fileio_ops[256];
static vdisk_op_fn blockio_ops[256];
static vdisk_op_fn nullio_ops[256];

/*
 * Be careful changing "name" field, since it is the name of the corresponding
 * /sys/kernel/scst_tgt entry, hence a part of user space ABI.
 */

static struct scst_dev_type vdisk_file_devtype = {
	.name =			"vdisk_fileio",
	.type =			TYPE_DISK,
	.exec_sync =		1,
	.threads_num =		-1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		vdisk_parse,
	.dev_alloc_data_buf =	fileio_alloc_data_buf,
	.exec =			vdisk_exec,
	.on_free_cmd =		fileio_on_free_cmd,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
	.devt_priv =		(void *)fileio_ops,
#ifdef CONFIG_SCST_PROC
	.read_proc =		vdisk_read_proc,
	.write_proc =		vdisk_write_proc,
#else
	.add_device =		vdisk_add_fileio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_fileio_attrs,
	.add_device_parameters = "filename, blocksize, write_through, "
		"nv_cache, o_direct, read_only, removable, rotational, "
		"thin_provisioned, zero_copy",
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
#ifndef CONFIG_SCST_PROC
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
#endif
};

static struct kmem_cache *blockio_work_cachep;

static struct scst_dev_type vdisk_blk_devtype = {
	.name =			"vdisk_blockio",
	.type =			TYPE_DISK,
	.threads_num =		1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
#ifdef CONFIG_SCST_PROC
	.no_proc =		1,
#endif
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		non_fileio_parse,
	.exec =			non_fileio_exec,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
	.devt_priv =		(void *)blockio_ops,
#ifndef CONFIG_SCST_PROC
	.add_device =		vdisk_add_blockio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_blockio_attrs,
	.add_device_parameters = "filename, blocksize, write_through, "
		"nv_cache, read_only, removable, rotational, "
		"thin_provisioned",
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
#ifndef CONFIG_SCST_PROC
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
#endif
};

static struct scst_dev_type vdisk_null_devtype = {
	.name =			"vdisk_nullio",
	.type =			TYPE_DISK,
	.threads_num =		0,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
#ifdef CONFIG_SCST_PROC
	.no_proc =		1,
#endif
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		non_fileio_parse,
	.exec =			non_fileio_exec,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
	.devt_priv =		(void *)nullio_ops,
#ifndef CONFIG_SCST_PROC
	.add_device =		vdisk_add_nullio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_nullio_attrs,
	.add_device_parameters = "blocksize, read_only, dummy, removable,"
		" rotational",
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
#ifndef CONFIG_SCST_PROC
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
#endif
};

static struct scst_dev_type vcdrom_devtype = {
	.name =			"vcdrom",
	.type =			TYPE_ROM,
	.exec_sync =		1,
	.threads_num =		-1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		vcdrom_parse,
	.dev_alloc_data_buf =	fileio_alloc_data_buf,
	.exec =			vcdrom_exec,
	.on_free_cmd =		fileio_on_free_cmd,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
#ifdef CONFIG_SCST_PROC
	.read_proc =		vcdrom_read_proc,
	.write_proc =		vcdrom_write_proc,
#else
	.add_device =		vcdrom_add_device,
	.del_device =		vcdrom_del_device,
	.dev_attrs =		vcdrom_attrs,
	.add_device_parameters = NULL,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
#ifndef CONFIG_SCST_PROC
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
#endif
};

#ifdef CONFIG_SCST_PROC

static char *vdisk_proc_help_string =
	"echo \"open|close|resync_size NAME [FILE_NAME [BLOCK_SIZE] "
	"[WRITE_THROUGH READ_ONLY O_DIRECT NULLIO NV_CACHE BLOCKIO]]\" "
	">/proc/scsi_tgt/vdisk/vdisk\n"
	"echo \"set_t10_dev_id NAME t10_dev_id\" "
	">/proc/scsi_tgt/vdisk/vdisk\n";

static char *vcdrom_proc_help_string =
	"echo \"open|change|close NAME [FILE_NAME]\" "
	">/proc/scsi_tgt/vcdrom/vcdrom\n";

static int scst_vdisk_ID;

module_param_named(scst_vdisk_ID, scst_vdisk_ID, int, S_IRUGO);
MODULE_PARM_DESC(scst_vdisk_ID, "SCST virtual disk subsystem ID");

#endif /* CONFIG_SCST_PROC */

static const char *vdev_get_filename(const struct scst_vdisk_dev *virt_dev)
{
	if (virt_dev->filename != NULL)
		return virt_dev->filename;
	else
		return "none";
}

/* Returns fd, use IS_ERR(fd) to get error status */
static struct file *vdev_open_fd(const struct scst_vdisk_dev *virt_dev,
	bool read_only)
{
	int open_flags = 0;
	struct file *fd;

	TRACE_ENTRY();

	sBUG_ON(!virt_dev->filename);

	if (read_only)
		open_flags |= O_RDONLY;
	else
		open_flags |= O_RDWR;
	if (virt_dev->o_direct_flag)
		open_flags |= O_DIRECT;
	if (virt_dev->wt_flag && !virt_dev->nv_cache)
		open_flags |= O_DSYNC;
	TRACE_DBG("Opening file %s, flags 0x%x",
		  virt_dev->filename, open_flags);
	fd = filp_open(virt_dev->filename, O_LARGEFILE | open_flags, 0600);

	TRACE_EXIT();
	return fd;
}

static void vdisk_blockio_check_flush_support(struct scst_vdisk_dev *virt_dev)
{
	struct inode *inode;
	struct file *fd;

	TRACE_ENTRY();

	if (!virt_dev->blockio || virt_dev->rd_only || virt_dev->nv_cache)
		goto out;

	fd = filp_open(virt_dev->filename, O_LARGEFILE, 0600);
	if (IS_ERR(fd)) {
		PRINT_ERROR("filp_open(%s) failed: %ld",
			virt_dev->filename, PTR_ERR(fd));
		goto out;
	}

	inode = fd->f_dentry->d_inode;

	if (!S_ISBLK(inode->i_mode)) {
		PRINT_ERROR("%s is NOT a block device", virt_dev->filename);
		goto out_close;
	}

	if (vdisk_blockio_flush(inode->i_bdev, GFP_KERNEL, false, NULL, false) != 0) {
		PRINT_WARNING("Device %s doesn't support barriers, switching "
			"to NV_CACHE mode. Read README for more details.",
			virt_dev->filename);
		virt_dev->nv_cache = 1;
	}

out_close:
	filp_close(fd, NULL);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_check_tp_support(struct scst_vdisk_dev *virt_dev)
{
	struct file *fd;

	TRACE_ENTRY();

	virt_dev->dev_thin_provisioned = 0;

	if (virt_dev->rd_only || (virt_dev->filename == NULL))
		goto out_check;

	fd = filp_open(virt_dev->filename, O_LARGEFILE, 0600);
	if (IS_ERR(fd)) {
		PRINT_ERROR("filp_open(%s) failed: %ld",
			virt_dev->filename, PTR_ERR(fd));
		goto out_check;
	}

	if (virt_dev->blockio) {
		struct inode *inode = fd->f_dentry->d_inode;
		if (!S_ISBLK(inode->i_mode)) {
			PRINT_ERROR("%s is NOT a block device",
				virt_dev->filename);
			goto out_close;
		}
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32) || (defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 6)
		virt_dev->dev_thin_provisioned =
			blk_queue_discard(bdev_get_queue(inode->i_bdev));
#endif
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
		virt_dev->dev_thin_provisioned = (fd->f_op->fallocate != NULL);
#else
		virt_dev->dev_thin_provisioned = 0;
#endif
	}

out_close:
	filp_close(fd, NULL);

out_check:
	if (virt_dev->thin_provisioned_manually_set) {
		if (virt_dev->thin_provisioned && !virt_dev->dev_thin_provisioned) {
			PRINT_WARNING("Device %s doesn't support thin "
				"provisioning, disabling it.",
				virt_dev->filename);
			virt_dev->thin_provisioned = 0;
		}
	} else if (virt_dev->blockio) {
		virt_dev->thin_provisioned = virt_dev->dev_thin_provisioned;
		if (virt_dev->thin_provisioned)
			PRINT_INFO("Auto enable thin provisioning for device "
				"%s", virt_dev->filename);

	}

	TRACE_EXIT();
	return;
}

/* Returns 0 on success and file size in *file_size, error code otherwise */
static int vdisk_get_file_size(const char *filename, bool blockio,
	loff_t *file_size)
{
	struct inode *inode;
	int res = 0;
	struct file *fd;

	TRACE_ENTRY();

	sBUG_ON(!filename);

	*file_size = 0;

	fd = filp_open(filename, O_LARGEFILE | O_RDONLY, 0600);
	if (IS_ERR(fd)) {
		res = PTR_ERR(fd);
		PRINT_ERROR("filp_open(%s) failed: %d", filename, res);
		goto out;
	}

	inode = fd->f_dentry->d_inode;

	if (blockio && !S_ISBLK(inode->i_mode)) {
		PRINT_ERROR("File %s is NOT a block device", filename);
		res = -EINVAL;
		goto out_close;
	}

	if (S_ISREG(inode->i_mode))
		/* Nothing to do */;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		res = -EINVAL;
		goto out_close;
	}

	*file_size = inode->i_size;

out_close:
	filp_close(fd, NULL);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static struct scst_vdisk_dev *vdev_find(const char *name)
{
	struct scst_vdisk_dev *res, *vv;

	TRACE_ENTRY();

	res = NULL;
	list_for_each_entry(vv, &vdev_list, vdev_list_entry) {
		if (strcmp(vv->name, name) == 0) {
			res = vv;
			break;
		}
	}

	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

static int vdisk_attach(struct scst_device *dev)
{
	int res = 0;
	loff_t err;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d (%s)", dev->virt_id, dev->virt_name);

	if (dev->virt_id == 0) {
		PRINT_ERROR("%s", "Not a virtual device");
		res = -EINVAL;
		goto out;
	}

	/*
	 * scst_vdisk_mutex must be already taken before
	 * scst_register_virtual_device()
	 */
	virt_dev = vdev_find(dev->virt_name);
	if (virt_dev == NULL) {
		PRINT_ERROR("Device %s not found", dev->virt_name);
		res = -EINVAL;
		goto out;
	}

	virt_dev->dev = dev;

	dev->block_shift = virt_dev->blk_shift;
	dev->block_size = 1 << dev->block_shift;

	if (virt_dev->zero_copy && virt_dev->o_direct_flag) {
		PRINT_ERROR("%s: combining zero_copy with o_direct is not"
			    " supported", virt_dev->filename);
		res = -EINVAL;
		goto out;
	}

	dev->dev_rd_only = virt_dev->rd_only;

	if (!virt_dev->cdrom_empty) {
		if (virt_dev->nullio)
			err = VDISK_NULLIO_SIZE;
		else {
			res = vdisk_get_file_size(virt_dev->filename,
				virt_dev->blockio, &err);
			if (res != 0)
				goto out;
		}
		virt_dev->file_size = err;

		TRACE_DBG("size of file: %lld", (long long unsigned int)err);

		vdisk_blockio_check_flush_support(virt_dev);
		vdisk_check_tp_support(virt_dev);
	} else
		virt_dev->file_size = 0;

	virt_dev->nblocks = virt_dev->file_size >> dev->block_shift;

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO("Attached SCSI target virtual %s %s "
		      "(file=\"%s\", fs=%lldMB, bs=%d, nblocks=%lld,"
		      " cyln=%lld%s)",
		      (dev->type == TYPE_DISK) ? "disk" : "cdrom",
		      virt_dev->name, vdev_get_filename(virt_dev),
		      virt_dev->file_size >> 20, dev->block_size,
		      (long long unsigned int)virt_dev->nblocks,
		      (long long unsigned int)virt_dev->nblocks/64/32,
		      virt_dev->nblocks < 64*32
		      ? " !WARNING! cyln less than 1" : "");
	} else {
		PRINT_INFO("Attached empty SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	dev->dh_priv = virt_dev;

	dev->tst = DEF_TST;
	dev->d_sense = DEF_DSENSE;
	if (virt_dev->wt_flag && !virt_dev->nv_cache)
		dev->queue_alg = DEF_QUEUE_ALG_WT;
	else
		dev->queue_alg = DEF_QUEUE_ALG;
	dev->swp = DEF_SWP;
	dev->tas = DEF_TAS;

out:
	TRACE_EXIT();
	return res;
}

/* scst_mutex supposed to be held */
static void vdisk_detach(struct scst_device *dev)
{
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	TRACE_DBG("virt_id %d", dev->virt_id);

	PRINT_INFO("Detached virtual device %s (\"%s\")",
		      virt_dev->name, vdev_get_filename(virt_dev));

	/* virt_dev will be freed by the caller */
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static int vdisk_open_fd(struct scst_vdisk_dev *virt_dev, bool read_only)
{
	int res;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif
	sBUG_ON(!virt_dev->filename);

	virt_dev->fd = vdev_open_fd(virt_dev, read_only);
	if (IS_ERR(virt_dev->fd)) {
		res = PTR_ERR(virt_dev->fd);
		virt_dev->fd = NULL;
		PRINT_ERROR("filp_open(%s) failed: %d",
			    virt_dev->filename, res);
		goto out;
	}
	virt_dev->bdev = virt_dev->blockio ?
		virt_dev->fd->f_dentry->d_inode->i_bdev : NULL;
	res = 0;

out:
	return res;
}

/* Invoked with scst_mutex held, so no further locking is necessary here. */
static int vdisk_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_dev *virt_dev = tgt_dev->dev->dh_priv;
	int res = 0;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	if (virt_dev->tgt_dev_cnt++ > 0)
		goto out;

	if (!virt_dev->nullio && !virt_dev->cdrom_empty) {
		res = vdisk_open_fd(virt_dev, tgt_dev->tgt_dev_rd_only);
		if (res != 0) {
			virt_dev->tgt_dev_cnt--;
			goto out;
		}
	} else
		virt_dev->fd = NULL;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Invoked with scst_mutex held, so no further locking is necessary here. */
static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_dev *virt_dev = tgt_dev->dev->dh_priv;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	if (--virt_dev->tgt_dev_cnt > 0)
		goto out;

	virt_dev->bdev = NULL;
	if (virt_dev->fd) {
		filp_close(virt_dev->fd, NULL);
		virt_dev->fd = NULL;
	}

out:
	TRACE_EXIT();
	return;
}

static enum compl_status_e vdisk_synchronize_cache(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	const uint8_t *cdb = cmd->cdb;
	struct scst_device *dev = cmd->dev;
	const loff_t loff = p->loff;
	int64_t data_len = scst_cmd_get_data_len(cmd);
	int immed = cdb[1] & 0x2;
	enum compl_status_e res;

	TRACE_ENTRY();

	TRACE(TRACE_ORDER, "SYNCHRONIZE_CACHE: "
	      "loff=%lld, data_len=%lld, immed=%d",
	      (long long unsigned int)loff,
	      (long long unsigned int)data_len, immed);

	if (data_len == 0) {
		struct scst_vdisk_dev *virt_dev = dev->dh_priv;
		data_len = virt_dev->file_size -
			((loff_t)scst_cmd_get_lba(cmd) << dev->block_shift);
	}

	if (immed) {
		scst_cmd_get(cmd); /* to protect dev */
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
				   SCST_CONTEXT_SAME);
		vdisk_fsync(p, loff, data_len, dev, cmd->cmd_gfp_mask, NULL, true);
		/* ToDo: vdisk_fsync() error processing */
		scst_cmd_put(cmd);
		res = RUNNING_ASYNC;
	} else {
		vdisk_fsync(p, loff, data_len, dev, cmd->cmd_gfp_mask, cmd, true);
		res = RUNNING_ASYNC;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e vdisk_exec_start_stop(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

	vdisk_fsync(p, 0, virt_dev->file_size, dev, cmd->cmd_gfp_mask, cmd, false);

	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_nop(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_srv_action_in(struct vdisk_cmd_params *p)
{
	switch (p->cmd->cdb[1] & 0x1f) {
	case SAI_READ_CAPACITY_16:
		vdisk_exec_read_capacity16(p);
		return CMD_SUCCEEDED;
	case SAI_GET_LBA_STATUS:
		return vdisk_exec_get_lba_status(p);
	}
	return INVALID_OPCODE;
}

static enum compl_status_e vdisk_exec_maintenance_in(struct vdisk_cmd_params *p)
{
	switch (p->cmd->cdb[1] & 0x1f) {
	case MI_REPORT_TARGET_PGS:
		vdisk_exec_report_tpgs(p);
		return CMD_SUCCEEDED;
	}
	return INVALID_OPCODE;
}

static enum compl_status_e vdisk_exec_send_diagnostic(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_format_unit(struct vdisk_cmd_params *p)
{
	int res = CMD_SUCCEEDED;
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	int prot_type = 0, pinfo;
	bool immed = false;

	TRACE_ENTRY();

	pinfo = (cmd->cdb[1] & 0xC0) >> 6;
	if (((cmd->cdb[1] & 0x10) == 0) && (pinfo != 0)) {
		/* FMTDATA zero and FMTPINFO not zero are illegal */
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 6);
		goto out;
	}

	if (cmd->cdb[1] & 0x10) { /* FMTDATA */
		int length, prot_usage;
		uint8_t *buf;
		bool err = false;

		length = scst_get_buf_full_sense(cmd, &buf);
		TRACE_DBG("length %d", length);
		if (unlikely(length <= 0))
			goto out;

		TRACE_BUFF_FLAG(TRACE_DEBUG, "Format buf", buf, 64);

		if (length < 4) {
			PRINT_ERROR("FORMAT UNIT: too small parameters list "
				"header %d (dev %s)", length, dev->virt_name);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			err = true;
			goto out_put;
		}

		prot_usage = buf[0] & 7;
		immed = buf[1] & 2;

		if ((buf[1] & 8) != 0) {
			PRINT_ERROR("FORMAT UNIT: initialization pattern not "
				"supported");
			scst_set_invalid_field_in_parm_list(cmd, 1,
				SCST_INVAL_FIELD_BIT_OFFS_VALID | 3);
			err = true;
			goto out_put;
		}

		if (cmd->cdb[1] & 0x20) { /* LONGLIST */
			if (length < 8) {
				PRINT_ERROR("FORMAT UNIT: too small long "
					"parameters list header %d (dev %s)",
					length, dev->virt_name);
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
				err = true;
				goto out_put;
			}
			if ((buf[3] & 0xF0) != 0) {
				PRINT_ERROR("FORMAT UNIT: P_I_INFORMATION must "
					"be 0 (dev %s)", dev->virt_name);
				scst_set_invalid_field_in_parm_list(cmd, 3,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
				err = true;
				goto out_put;
			}
			if ((buf[3] & 0xF) != 0) {
				PRINT_ERROR("FORMAT UNIT: PROTECTION INTERVAL "
					"EXPONENT %d not supported (dev %s)",
					buf[3] & 0xF, dev->virt_name);
				scst_set_invalid_field_in_parm_list(cmd, 3,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
				err = true;
				goto out_put;
			}
		} else {
			/* Nothing to do */
		}

out_put:
		scst_put_buf_full(cmd, buf);
		if (err)
			goto out;

		switch (pinfo) {
		case 0:
			switch (prot_usage) {
			case 0:
				prot_type = 0;
				break;
			default:
				scst_set_invalid_field_in_parm_list(cmd, 0,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
				goto out;
			}
			break;
		case 1:
			switch (prot_usage) {
			default:
				scst_set_invalid_field_in_parm_list(cmd, 0,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
				goto out;
			}
			break;
		case 2:
			switch (prot_usage) {
			case 0:
				prot_type = 1;
				break;
			default:
				scst_set_invalid_field_in_parm_list(cmd, 0,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
				goto out;
			}
			break;
		case 3:
			switch (prot_usage) {
			case 0:
				prot_type = 2;
				break;
			case 1:
				prot_type = 3;
				break;
			default:
				scst_set_invalid_field_in_parm_list(cmd, 0,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
				goto out;
			}
			break;
		default:
			sBUG_ON(1);
			break;
		}
	}

	TRACE_DBG("prot_type %d, pinfo %d, immed %d (cmd %p)", prot_type,
		pinfo, immed, cmd);

	if (prot_type != 0) {
		PRINT_ERROR("FORMAT UNIT: DIF type %d not supported (dev %s)",
			prot_type, dev->virt_name);
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 6);
		goto out;
	}

	if (immed) {
		scst_cmd_get(cmd); /* to protect dev */
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
		res = RUNNING_ASYNC;
	}

	spin_lock(&virt_dev->flags_lock);
	virt_dev->format_active = 1;
	spin_unlock(&virt_dev->flags_lock);

	virt_dev->format_progress_done = 0;
	virt_dev->format_progress_to_do = 100;

	if (virt_dev->thin_provisioned) {
		int rc = vdisk_unmap_range(cmd, virt_dev, 0, virt_dev->nblocks);
		if (rc != 0)
			goto finished;
	}

finished:
	spin_lock(&virt_dev->flags_lock);
	virt_dev->format_active = 0;
	spin_unlock(&virt_dev->flags_lock);

	if (immed)
		scst_cmd_put(cmd);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e vdisk_invalid_opcode(struct vdisk_cmd_params *p)
{
	TRACE_DBG("Invalid opcode %d", p->cmd->cdb[0]);
	return INVALID_OPCODE;
}

#define SHARED_OPS							\
	[SYNCHRONIZE_CACHE] = vdisk_synchronize_cache,			\
	[MODE_SENSE] = vdisk_exec_mode_sense,				\
	[MODE_SENSE_10] = vdisk_exec_mode_sense,			\
	[MODE_SELECT] = vdisk_exec_mode_select,				\
	[MODE_SELECT_10] = vdisk_exec_mode_select,			\
	[LOG_SELECT] = vdisk_exec_log,					\
	[LOG_SENSE] = vdisk_exec_log,					\
	[ALLOW_MEDIUM_REMOVAL] = vdisk_exec_prevent_allow_medium_removal, \
	[READ_TOC] = vdisk_exec_read_toc,				\
	[START_STOP] = vdisk_exec_start_stop,				\
	[RESERVE] = vdisk_nop,						\
	[RESERVE_10] = vdisk_nop,					\
	[RELEASE] = vdisk_nop,						\
	[RELEASE_10] = vdisk_nop,					\
	[TEST_UNIT_READY] = vdisk_nop,					\
	[INQUIRY] = vdisk_exec_inquiry,					\
	[REQUEST_SENSE] = vdisk_exec_request_sense,			\
	[READ_CAPACITY] = vdisk_exec_read_capacity,			\
	[SERVICE_ACTION_IN] = vdisk_exec_srv_action_in,			\
	[UNMAP] = vdisk_exec_unmap,					\
	[WRITE_SAME] = vdisk_exec_write_same,				\
	[WRITE_SAME_16] = vdisk_exec_write_same,			\
	[MAINTENANCE_IN] = vdisk_exec_maintenance_in,			\
	[SEND_DIAGNOSTIC] = vdisk_exec_send_diagnostic,			\
	[FORMAT_UNIT] = vdisk_exec_format_unit,

static vdisk_op_fn blockio_ops[256] = {
	[READ_6] = blockio_exec_read,
	[READ_10] = blockio_exec_read,
	[READ_12] = blockio_exec_read,
	[READ_16] = blockio_exec_read,
	[WRITE_6] = blockio_exec_write,
	[WRITE_10] = blockio_exec_write,
	[WRITE_12] = blockio_exec_write,
	[WRITE_16] = blockio_exec_write,
	[WRITE_VERIFY] = blockio_exec_write_verify,
	[WRITE_VERIFY_12] = blockio_exec_write_verify,
	[WRITE_VERIFY_16] = blockio_exec_write_verify,
	[VERIFY] = blockio_exec_verify,
	[VERIFY_12] = blockio_exec_verify,
	[VERIFY_16] = blockio_exec_verify,
	SHARED_OPS
};

static vdisk_op_fn fileio_ops[256] = {
	[READ_6] = fileio_exec_read,
	[READ_10] = fileio_exec_read,
	[READ_12] = fileio_exec_read,
	[READ_16] = fileio_exec_read,
	[WRITE_6] = fileio_exec_write,
	[WRITE_10] = fileio_exec_write,
	[WRITE_12] = fileio_exec_write,
	[WRITE_16] = fileio_exec_write,
	[WRITE_VERIFY] = fileio_exec_write_verify,
	[WRITE_VERIFY_12] = fileio_exec_write_verify,
	[WRITE_VERIFY_16] = fileio_exec_write_verify,
	[VERIFY] = fileio_exec_verify,
	[VERIFY_12] = fileio_exec_verify,
	[VERIFY_16] = fileio_exec_verify,
	SHARED_OPS
};

static vdisk_op_fn nullio_ops[256] = {
	[READ_6] = nullio_exec_read,
	[READ_10] = nullio_exec_read,
	[READ_12] = nullio_exec_read,
	[READ_16] = nullio_exec_read,
	[WRITE_6] = nullio_exec_write,
	[WRITE_10] = nullio_exec_write,
	[WRITE_12] = nullio_exec_write,
	[WRITE_16] = nullio_exec_write,
	[WRITE_VERIFY] = nullio_exec_write_verify,
	[WRITE_VERIFY_12] = nullio_exec_write_verify,
	[WRITE_VERIFY_16] = nullio_exec_write_verify,
	SHARED_OPS
};

/*
 * Compute p->loff and p->fua.
 * Returns true for success or false otherwise and set error in the commeand.
 */
static bool vdisk_parse_offset(struct vdisk_cmd_params *p, struct scst_cmd *cmd)
{
	uint64_t lba_start;
	int64_t data_len;
	uint8_t *cdb = cmd->cdb;
	int opcode = cdb[0];
	loff_t loff;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	bool use_zero_copy = false, res;
	int fua = 0;

	TRACE_ENTRY();

	if (unlikely(!(cmd->op_flags & SCST_INFO_VALID))) {
		TRACE(TRACE_MINOR, "Unknown opcode 0x%02x", cmd->cdb[0]);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		res = false;
		goto out;
	}

	p->cmd = cmd;

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	switch (cmd->queue_type) {
	case SCST_CMD_QUEUE_ORDERED:
		TRACE(TRACE_ORDER, "ORDERED cmd %p (op %x)", cmd, cmd->cdb[0]);
		break;
	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		TRACE(TRACE_ORDER, "HQ cmd %p (op %x)", cmd, cmd->cdb[0]);
		break;
	default:
		break;
	}

	lba_start = scst_cmd_get_lba(cmd);
	data_len = scst_cmd_get_data_len(cmd);

	loff = (loff_t)lba_start << dev->block_shift;
	TRACE_DBG("cmd %p, lba_start %lld, loff %lld, data_len %lld", cmd,
		  (long long unsigned int)lba_start,
		  (long long unsigned int)loff,
		  (long long unsigned int)data_len);

	EXTRACHECKS_BUG_ON((loff < 0) || unlikely(data_len < 0));

	if (unlikely((loff + data_len) > virt_dev->file_size) &&
	    (!(cmd->op_flags & SCST_LBA_NOT_VALID))) {
		PRINT_INFO("Access beyond the end of device %s "
			"(%lld of %lld, data len %lld)",
			   virt_dev->name,
			   (long long unsigned int)loff,
			   (long long unsigned int)virt_dev->file_size,
			   (long long unsigned int)data_len);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
					scst_sense_block_out_range_error));
		res = false;
		goto out;
	}

	switch (opcode) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		use_zero_copy = true;
		break;
	}

	switch (opcode) {
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		fua = (cdb[1] & 0x8);
		if (fua) {
			TRACE(TRACE_ORDER, "FUA: loff=%lld, "
				"data_len=%lld", (long long unsigned int)loff,
				(long long unsigned int)data_len);
		}
		break;
	}

	p->loff = loff;
	p->fua = fua;
	p->use_zero_copy = use_zero_copy && virt_dev->zero_copy;

	res = true;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int fileio_alloc_and_parse(struct scst_cmd *cmd)
{
	struct vdisk_cmd_params *p;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	p = kmem_cache_zalloc(vdisk_cmd_param_cachep, cmd->cmd_gfp_mask);
	if (!p) {
		scst_set_busy(cmd);
		goto out_err;
	}

	if (unlikely(!vdisk_parse_offset(p, cmd)))
		goto out_err_free_cmd_params;

	cmd->dh_priv = p;

out:
	TRACE_EXIT_RES(res);
	return res;

out_err_free_cmd_params:
	kmem_cache_free(vdisk_cmd_param_cachep, p);

out_err:
	res = scst_get_cmd_abnormal_done_state(cmd);
	goto out;
}

static int vdisk_parse(struct scst_cmd *cmd)
{
	int res, rc;

	rc = scst_sbc_generic_parse(cmd);
	if (rc != 0) {
		res = scst_get_cmd_abnormal_done_state(cmd);
		goto out;
	}

	res = fileio_alloc_and_parse(cmd);
out:
	return res;
}

static int vcdrom_parse(struct scst_cmd *cmd)
{
	int res, rc;
	rc = scst_cdrom_generic_parse(cmd);
	if (rc != 0) {
		res = scst_get_cmd_abnormal_done_state(cmd);
		goto out;
	}

	res = fileio_alloc_and_parse(cmd);
out:
	return res;
}

/* blockio and nullio */
static int non_fileio_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT, rc;

	rc = scst_sbc_generic_parse(cmd);
	if (rc != 0) {
		res = scst_get_cmd_abnormal_done_state(cmd);
		goto out;
	}
out:
	return res;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
/**
 * finish_read - Release the pages referenced by prepare_read().
 */
static void finish_read(struct scatterlist *sg, int sg_cnt)
{
	struct page *page;
	int i;

	TRACE_ENTRY();

	for (i = 0; i < sg_cnt; ++i) {
		page = sg_page(&sg[i]);
		EXTRACHECKS_BUG_ON(!page);
		page_cache_release(page);
	}

	TRACE_EXIT();
	return;
}

/**
 * prepare_read_page - Bring a single page into the page cache.
 *
 * @filp: file pointer
 * @len: number of bytes to read from the file
 * @offset: offset of first byte to read (from start of file)
 * @last: offset of first byte that will not be read - used for readahead
 * @pageptr: page pointer output variable.
 *
 * Returns a negative number if an error occurred, zero upon EOF or a positive
 * number - the number of bytes that can be read from the file via the returned
 * page. If a positive number is returned, it is the responsibility of the
 * caller to release the returned page.
 *
 * Based on do_generic_file_read().
 */
static int prepare_read_page(struct file *filp, int len,
			     loff_t offset, loff_t last, struct page **pageptr)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	struct page *page;
	unsigned long index, last_index;
	long end_index, nr;
	loff_t isize;
	read_descriptor_t desc = { .count = len };
	int error;

	TRACE_ENTRY();

	WARN((offset & ~PAGE_CACHE_MASK) + len > PAGE_CACHE_SIZE,
	     "offset = %lld + %lld, len = %d\n", offset & PAGE_CACHE_MASK,
	     offset & ~PAGE_CACHE_MASK, len);
	sBUG_ON(!mapping->a_ops);

	index = offset >> PAGE_CACHE_SHIFT;
	last_index = (last + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

find_page:
	page = find_get_page(mapping, index);
	if (!page) {
		page_cache_sync_readahead(mapping, ra, filp, index,
					  last_index - index);
		page = find_get_page(mapping, index);
		if (unlikely(!page)) {
			/*
			 * Not cached so create a new page.
			 */
			page = page_cache_alloc_cold(mapping);
			if (!page) {
				error = -ENOMEM;
				goto err;
			}
			error = add_to_page_cache_lru(page, mapping, index,
						      GFP_KERNEL);
			if (error) {
				page_cache_release(page);
				if (error == -EEXIST)
					goto find_page;
				else
					goto err;
			} else {
				goto readpage;
			}
		}
	}
	if (PageReadahead(page))
		page_cache_async_readahead(mapping, ra, filp, page,
					   index, last_index - index);
	if (!PageUptodate(page)) {
		if (inode->i_blkbits == PAGE_CACHE_SHIFT ||
		    !mapping->a_ops->is_partially_uptodate)
			goto page_not_up_to_date;
		if (!trylock_page(page))
			goto page_not_up_to_date;
		/* Did it get truncated before we got the lock? */
		if (!page->mapping)
			goto page_not_up_to_date_locked;
		if (!mapping->a_ops->is_partially_uptodate(page, &desc,
						offset & ~PAGE_CACHE_MASK))
			goto page_not_up_to_date_locked;
		unlock_page(page);
	}
page_ok:
	/*
	 * i_size must be checked after we know the page is Uptodate.
	 *
	 * Checking i_size after the check allows us to calculate the correct
	 * value for "nr", which means the zero-filled part of the page is not
	 * accessed (unless another truncate extends the file - this is
	 * desired though).
	 */

	isize = i_size_read(inode);
	end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	if (unlikely(isize == 0 || index > end_index)) {
		page_cache_release(page);
		goto eof;
	}

	/* nr is the maximum number of bytes to copy from this page */
	if (index < end_index) {
		nr = PAGE_CACHE_SIZE - (offset & ~PAGE_CACHE_MASK);
	} else {
		nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1 -
			(offset & ~PAGE_CACHE_MASK);
		if (nr <= 0) {
			page_cache_release(page);
			goto eof;
		}
	}

	/*
	 * If users can be writing to this page using arbitrary virtual
	 * addresses, take care about potential aliasing before reading the
	 * page on the kernel side.
	 */
	if (mapping_writably_mapped(mapping))
		flush_dcache_page(page);

	mark_page_accessed(page);

	/* Ok, we have the page and it's up to date. */
	*pageptr = page;
	TRACE_EXIT_RES(nr);
	return nr;
eof:
	TRACE_EXIT();
	return 0;
err:
	TRACE_EXIT_RES(error);
	return error;

page_not_up_to_date:
	/* Try to get exclusive access to the page. */
	error = lock_page_killable(page);
	if (unlikely(error != 0)) {
		page_cache_release(page);
		goto err;
	}

page_not_up_to_date_locked:
	/* Did it get truncated before we got the lock? */
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto find_page;
	}

	/* Did somebody else fill it already? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto page_ok;
	}

readpage:
	/*
	 * A previous I/O error may have been due to temporary
	 * failures, eg. multipath errors.
	 * PG_error will be set again if readpage fails.
	 */
	ClearPageError(page);
	/* Start the actual read. The read will unlock the page. */
	error = mapping->a_ops->readpage(filp, page);
	if (unlikely(error)) {
		if (error == AOP_TRUNCATED_PAGE) {
			page_cache_release(page);
			goto find_page;
		}
		WARN(error >= 0, "error = %d\n", error);
		page_cache_release(page);
		goto err;
	}

	if (!PageUptodate(page)) {
		error = lock_page_killable(page);
		if (unlikely(error != 0)) {
			page_cache_release(page);
			goto err;
		}
		if (!PageUptodate(page)) {
			if (page->mapping == NULL) {
				/*
				 * invalidate_mapping_pages got it
				 */
				unlock_page(page);
				page_cache_release(page);
				goto find_page;
			}
			unlock_page(page);
			page_cache_release(page);
			error = -EIO;
			goto err;
		}
		unlock_page(page);
	}

	goto page_ok;
}

/**
 * prepare_read - Lock page cache pages corresponding to an sg vector
 * @filp: file the sg vector applies to
 * @sg: sg vector
 * @sg_cnt: sg vector size
 * @offset: file offset the first byte of the first sg element corresponds to
 */
static int prepare_read(struct file *filp, struct scatterlist *sg, int sg_cnt,
			pgoff_t offset)
{
	struct page *page = NULL;
	int i, res;
	loff_t off, last = ((offset + sg_cnt - 1) << PAGE_SHIFT) +
		sg[sg_cnt - 1].offset + sg[sg_cnt - 1].length;

	TRACE_ENTRY();

	for (i = 0; i < sg_cnt; ++i) {
		off = (offset + i) << PAGE_SHIFT | sg[i].offset;
		res = prepare_read_page(filp, sg[i].length, off, last, &page);
		if (res <= 0)
			goto err;
		if (res < sg[i].length) {
			page_cache_release(page);
			goto err;
		}
		sg_assign_page(&sg[i], page);
	}

	file_accessed(filp);

out:
	TRACE_EXIT_RES(i);
	return i;

err:
	finish_read(sg, i);
	i = -EIO;
	goto out;
}

/**
 * alloc_sg - Allocate an SG vector.
 * @size: number of bytes that will be stored in the pages of the sg vector
 * @off: first page data offset
 * @gfp_mask: allocation flags for dynamic sg vector allocation
 * @small_sg: pointer to a candidate sg vector
 * @small_sg_size: size of @small_sg
 * @p_sg_cnt: pointer to an int where the sg vector size will be written
 */
static struct scatterlist *alloc_sg(size_t size, unsigned off, gfp_t gfp_mask,
				    struct scatterlist *small_sg,
				    int small_sg_size, int *p_sg_cnt)
{
	struct scatterlist *sg;
	int i, sg_cnt, remaining_sz, sg_sz, sg_off;

	TRACE_ENTRY();

	sg_cnt = PAGE_ALIGN(size + off) >> PAGE_SHIFT;
	sg = sg_cnt <= small_sg_size ? small_sg :
		kmalloc(sg_cnt * sizeof(*sg), gfp_mask);
	if (!sg)
		goto out;

	sg_init_table(sg, sg_cnt);
	remaining_sz = size;
	sg_off = off;
	for (i = 0; i < sg_cnt; ++i) {
		sg_sz = min_t(int, PAGE_SIZE - sg_off, remaining_sz);
		sg_set_page(&sg[i], NULL, sg_sz, sg_off);
		remaining_sz -= sg_sz;
		sg_off = 0;
	}
	*p_sg_cnt = sg_cnt;

out:
	TRACE_EXIT();
	return sg;
}

static int fileio_alloc_data_buf(struct scst_cmd *cmd)
{
	struct vdisk_cmd_params *p;
	struct scst_vdisk_dev *virt_dev;
	int sg_cnt, nr;
	const gfp_t gfp_mask = GFP_KERNEL;
	struct scatterlist *sg;

	TRACE_ENTRY();

	p = cmd->dh_priv;
	EXTRACHECKS_BUG_ON(!p);
	virt_dev = cmd->dev->dh_priv;
	/*
	 * If the target driver (e.g. scst_local) allocates the sg vector
	 * itself or the command is a write or bidi command, don't use zero
	 * copy.
	 */
	if (cmd->tgt_i_data_buf_alloced ||
	    (cmd->data_direction & SCST_DATA_READ) == 0) {
		p->use_zero_copy = false;
	}
	if (!p->use_zero_copy)
		goto out;

	EXTRACHECKS_BUG_ON(!(cmd->data_direction & SCST_DATA_READ));

	scst_cmd_set_dh_data_buff_alloced(cmd);

	cmd->sg = alloc_sg(cmd->bufflen, p->loff & ~PAGE_MASK, gfp_mask,
			   p->small_sg, ARRAY_SIZE(p->small_sg), &cmd->sg_cnt);
	if (!cmd->sg) {
		PRINT_ERROR("sg allocation failed (bufflen = %d, off = %lld)\n",
			    cmd->bufflen, p->loff & ~PAGE_MASK);
		goto enomem;
	}
	sg_cnt = scst_cmd_get_sg_cnt(cmd);
	sg = cmd->sg;
	nr = prepare_read(virt_dev->fd, sg, sg_cnt, p->loff >> PAGE_SHIFT);
	if (nr < 0) {
		PRINT_ERROR("prepare_read() failed: %d", nr);
		goto out_free_sg;
	}
out:
	TRACE_EXIT();
	return SCST_CMD_STATE_DEFAULT;

out_free_sg:
	kfree(cmd->sg);
	cmd->sg = NULL;
	cmd->sg_cnt = 0;

enomem:
	scst_set_busy(cmd);
	TRACE_EXIT_RES(-ENOMEM);
	return scst_get_cmd_abnormal_done_state(cmd);
}
#else
static int fileio_alloc_data_buf(struct scst_cmd *cmd)
{
	struct vdisk_cmd_params *p;

	TRACE_ENTRY();

	p = cmd->dh_priv;
	EXTRACHECKS_BUG_ON(!p);
	p->use_zero_copy = false;

	TRACE_EXIT();
	return SCST_CMD_STATE_DEFAULT;
}

static void finish_read(struct scatterlist *sg, int sg_cnt)
{
}
#endif

static int vdev_do_job(struct scst_cmd *cmd, const vdisk_op_fn *ops)
{
	int res;
	uint8_t *cdb = cmd->cdb;
	int opcode = cdb[0];
	struct vdisk_cmd_params *p = cmd->dh_priv;
	struct scst_vdisk_dev *virt_dev;
	vdisk_op_fn op = ops[opcode];
	enum compl_status_e s;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(!p);

	virt_dev = cmd->dev->dh_priv;

	EXTRACHECKS_BUG_ON(p->cmd != cmd);
	EXTRACHECKS_BUG_ON(ops != blockio_ops && ops != fileio_ops && ops != nullio_ops);

	/*
	 * No need to make it volatile, because at worst we will have a couple
	 * of extra commands refused after formatting actually finished, which
	 * is acceptable.
	 */
	if (unlikely(virt_dev->format_active)) {
		switch (cmd->cdb[0]) {
		case INQUIRY:
		case REPORT_LUNS:
		case REQUEST_SENSE:
			break;
		default:
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_format_in_progress));
			goto out_compl;
		}
	}

	s = op(p);
	if (s == CMD_SUCCEEDED)
		;
	else if (s == RUNNING_ASYNC)
		goto out_thr;
	else if (s == CMD_FAILED)
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	else if (s == INVALID_OPCODE)
		goto out_invalid_opcode;
	else
		WARN_ON(true);

out_compl:
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

out_thr:
	res = SCST_EXEC_COMPLETED;

	TRACE_EXIT_RES(res);
	return res;

out_invalid_opcode:
	TRACE_DBG("Invalid opcode 0x%x", opcode);
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	goto out_compl;
}

static int vdisk_exec(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	const vdisk_op_fn *ops = virt_dev->vdev_devt->devt_priv;

	EXTRACHECKS_BUG_ON(!ops);
	return vdev_do_job(cmd, ops);
}

static void fileio_on_free_cmd(struct scst_cmd *cmd)
{
	struct vdisk_cmd_params *p = cmd->dh_priv;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if (!p)
		goto out;

	virt_dev = cmd->dev->dh_priv;

	if (p->use_zero_copy) {
		if ((cmd->data_direction & SCST_DATA_READ) &&
		    virt_dev->zero_copy)
			finish_read(cmd->sg, cmd->sg_cnt);
		if (cmd->sg != p->small_sg)
			kfree(cmd->sg);
		cmd->sg_cnt = 0;
		cmd->sg = NULL;
		cmd->bufflen = 0;
		cmd->data_len = 0;
	}

	if (p->iv != p->small_iv)
		kfree(p->iv);

	kmem_cache_free(vdisk_cmd_param_cachep, p);

out:
	TRACE_EXIT();
	return;
}

/* blockio and nullio */
static int non_fileio_exec(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	const vdisk_op_fn *ops = virt_dev->vdev_devt->devt_priv;
	struct vdisk_cmd_params p;
	int res;

	EXTRACHECKS_BUG_ON(!ops);

	memset(&p, 0, sizeof(p));
	if (unlikely(!vdisk_parse_offset(&p, cmd)))
		goto err;

	cmd->dh_priv = &p;
	res = vdev_do_job(cmd, ops);
	cmd->dh_priv = NULL;

out:
	return res;

err:
	res = SCST_EXEC_COMPLETED;
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

static int vcdrom_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
	int opcode = cmd->cdb[0];
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (virt_dev->cdrom_empty && (opcode != INQUIRY)) {
		TRACE_DBG("%s", "CDROM empty");
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_no_medium));
		goto out_done;
	}

	if (virt_dev->media_changed && ((cmd->op_flags & SCST_SKIP_UA) == 0)) {
		spin_lock(&virt_dev->flags_lock);
		if (virt_dev->media_changed) {
			virt_dev->media_changed = 0;
			TRACE_DBG("%s", "Reporting media changed");
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_medium_changed_UA));
			spin_unlock(&virt_dev->flags_lock);
			goto out_done;
		}
		spin_unlock(&virt_dev->flags_lock);
	}

	res = vdev_do_job(cmd, virt_dev->blockio ? blockio_ops : fileio_ops);

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

static uint64_t vdisk_gen_dev_id_num(const char *virt_dev_name)
{
	uint32_t dev_id_num;

	dev_id_num = crc32c(0, virt_dev_name, strlen(virt_dev_name)+1);

#ifdef CONFIG_SCST_PROC
	return ((uint64_t)scst_vdisk_ID << 32) | dev_id_num;
#else
	return ((uint64_t)scst_get_setup_id() << 32) | dev_id_num;
#endif
}

static int vdisk_unmap_range(struct scst_cmd *cmd,
	struct scst_vdisk_dev *virt_dev, uint64_t start_lba, uint32_t blocks)
{
	int res, err;
	struct file *fd = virt_dev->fd;

	TRACE_ENTRY();

	if (blocks == 0)
		goto success;

	if ((start_lba > virt_dev->nblocks) ||
	    ((start_lba + blocks) > virt_dev->nblocks)) {
		PRINT_ERROR("Device %s: attempt to write beyond max "
			"size", virt_dev->name);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_block_out_range_error));
		res = -EINVAL;
		goto out;
	}

	TRACE_DBG("Unmapping lba %lld (blocks %lld)",
		(unsigned long long)start_lba, (unsigned long long)blocks);

	if (virt_dev->blockio) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 27)
		struct inode *inode = fd->f_dentry->d_inode;
		gfp_t gfp = cmd->cmd_gfp_mask;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 31)
		err = blkdev_issue_discard(inode->i_bdev, start_lba, blocks, gfp);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)       \
      && !(LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 34) \
           && defined(CONFIG_SUSE_KERNEL))
		err = blkdev_issue_discard(inode->i_bdev, start_lba, blocks,
				gfp, DISCARD_FL_WAIT);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
		err = blkdev_issue_discard(inode->i_bdev, start_lba, blocks,
				gfp, BLKDEV_IFL_WAIT);
#else
		err = blkdev_issue_discard(inode->i_bdev, start_lba, blocks, gfp, 0);
#endif
		if (unlikely(err != 0)) {
			PRINT_ERROR("blkdev_issue_discard() for "
				"LBA %lld, blocks %d failed: %d",
				(unsigned long long)start_lba, blocks, err);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
			res = -EIO;
			goto out;
		}
#else
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		res = -EIO;
		goto out;
#endif
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
		struct scst_device *dev = cmd->dev;
		const int block_shift = dev->block_shift;
		const loff_t s = start_lba << block_shift;
		const loff_t l = blocks << block_shift;

		TRACE_DBG("Fallocating range %lld, len %lld",
			(unsigned long long)s, (unsigned long long)l);

		err = fd->f_op->fallocate(fd,
			FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, s, l);
		if (unlikely(err != 0)) {
			PRINT_ERROR("fallocate() for LBA %lld len %lld "
				"failed: %d", (unsigned long long)start_lba,
				(unsigned long long)blocks, err);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
			res = -EIO;
			goto out;
		}
#else
		sBUG();
#endif
	}

success:
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_exec_write_same_unmap(struct vdisk_cmd_params *p)
{
	int rc;
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

	if (unlikely(!virt_dev->thin_provisioned)) {
		TRACE_DBG("%s", "Device not thin provisioned");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out;
	}

	rc = vdisk_unmap_range(cmd, virt_dev, cmd->lba,
		cmd->data_len >> dev->block_shift);
	if (rc != 0)
		goto out;

out:
	TRACE_EXIT();
	return;
}

static enum compl_status_e vdisk_exec_write_same(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	enum compl_status_e res = CMD_SUCCEEDED;

	TRACE_ENTRY();

	if (unlikely(cmd->cdb[1] & 1)) {
		TRACE_DBG("%s", "ANCHOR not supported");
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out;
	}

	if (unlikely(cmd->cdb[1] & 0xE0)) {
		TRACE_DBG("%s", "WRPROTECT not supported");
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 5);
		goto out;
	}

	if (unlikely(cmd->data_len <= 0)) {
		scst_set_invalid_field_in_cdb(cmd, cmd->len_off, 0);
		goto out;
	}

	if (cmd->cdb[1] & 0x8) {
		vdisk_exec_write_same_unmap(p);
		goto out;
	}

	scst_write_same(cmd);
	res = RUNNING_ASYNC;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e vdisk_exec_unmap(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct scst_data_descriptor *pd = cmd->cmd_data_descriptors;
	int i, cnt = cmd->cmd_data_descriptors_cnt;

	TRACE_ENTRY();

	if (unlikely(!virt_dev->thin_provisioned)) {
		TRACE_DBG("%s", "Device not thin provisioned");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out;
	}

	if (unlikely(cmd->cdb[1] & 1)) {
		TRACE_DBG("%s", "ANCHOR not supported");
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out;
	}

	if (pd == NULL)
		goto out;

	for (i = 0; i < cnt; i++) {
		int rc;

		if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
			TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
			goto out;
		}

		rc = vdisk_unmap_range(cmd, virt_dev, pd[i].sdd_lba,
			pd[i].sdd_blocks);
		if (rc != 0)
			goto out;
	}

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static void vdev_blockio_get_unmap_params(struct scst_vdisk_dev *virt_dev,
	uint32_t *unmap_gran, uint32_t *unmap_alignment,
	uint32_t *max_unmap_lba)
{
	int block_shift = virt_dev->dev->block_shift;

	TRACE_ENTRY();

	sBUG_ON(!virt_dev->filename);

	if (virt_dev->blockio) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32) || (defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 6)
		struct file *fd;
		struct request_queue *q;

		fd = filp_open(virt_dev->filename, O_LARGEFILE, 0600);
		if (IS_ERR(fd)) {
			PRINT_ERROR("filp_open(%s) failed: %ld",
				virt_dev->filename, PTR_ERR(fd));
			goto out;
		}

		q = bdev_get_queue(fd->f_dentry->d_inode->i_bdev);
		if (q == NULL) {
			PRINT_ERROR("No queue for device %s", virt_dev->filename);
			goto out_close;
		}

		*unmap_gran = q->limits.discard_granularity >> block_shift;
		*unmap_alignment = q->limits.discard_alignment >> block_shift;
		*max_unmap_lba = q->limits.max_discard_sectors >> (block_shift - 9);

out_close:
		filp_close(fd, NULL);
#else
		sBUG_ON(1);
#endif
	} else {
		*unmap_gran = 1;
		*unmap_alignment = 0;
		*max_unmap_lba = min_t(loff_t, 0xFFFFFFFF, virt_dev->file_size >> block_shift);
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32) || (defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 6)
out:
#endif
	TRACE_DBG("unmap_gran %d, unmap_alignment %d, max_unmap_lba %u",
			*unmap_gran, *unmap_alignment, *max_unmap_lba);

	TRACE_EXIT();
	return;
}

static enum compl_status_e vdisk_exec_inquiry(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length, i, resp_len = 0;
	uint8_t *address;
	uint8_t *buf;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	uint16_t tg_id;

	TRACE_ENTRY();

	buf = kzalloc(INQ_BUF_SZ, cmd->cmd_gfp_mask);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	length = scst_get_buf_full_sense(cmd, &address);
	TRACE_DBG("length %d", length);
	if (unlikely(length <= 0))
		goto out_free;

	if (cmd->cdb[1] & CMDDT) {
		TRACE_DBG("%s", "INQUIRY: CMDDT is unsupported");
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 1);
		goto out_put;
	}

	buf[0] = virt_dev->dummy ? SCSI_INQ_PQ_NOT_CON << 5 | 0x1f :
		 SCSI_INQ_PQ_CON << 5 | dev->type;
	/* Vital Product */
	if (cmd->cdb[1] & EVPD) {
		if (0 == cmd->cdb[2]) {
			/* supported vital product data pages */
			buf[3] = 3;
			buf[4] = 0x0; /* this page */
			buf[5] = 0x80; /* unit serial number */
			buf[6] = 0x83; /* device identification */
			if (dev->type == TYPE_DISK) {
				buf[3] += 2;
				buf[7] = 0xB0; /* block limits */
				buf[8] = 0xB1; /* block limits */
				if (virt_dev->thin_provisioned) {
					buf[3] += 1;
					buf[9] = 0xB2; /* thin provisioning */
				}
			}
			resp_len = buf[3] + 4;
		} else if (0x80 == cmd->cdb[2]) {
			/* unit serial number */
			buf[1] = 0x80;
			if (cmd->tgtt->get_serial) {
				buf[3] = cmd->tgtt->get_serial(cmd->tgt_dev,
						       &buf[4], INQ_BUF_SZ - 4);
			} else {
				int usn_len;
				read_lock(&vdisk_serial_rwlock);
				usn_len = strlen(virt_dev->usn);
				buf[3] = usn_len;
				strncpy(&buf[4], virt_dev->usn, usn_len);
				read_unlock(&vdisk_serial_rwlock);
			}
			resp_len = buf[3] + 4;
		} else if (0x83 == cmd->cdb[2]) {
			/* device identification */
			int num = 4;

			buf[1] = 0x83;
			/* T10 vendor identifier field format (faked) */
			buf[num + 0] = 0x2;	/* ASCII */
			buf[num + 1] = 0x1;	/* Vendor ID */
			if (cmd->tgtt->vendor)
				memcpy(&buf[num + 4], cmd->tgtt->vendor, 8);
			else if (virt_dev->blockio)
				memcpy(&buf[num + 4], SCST_BIO_VENDOR, 8);
			else
				memcpy(&buf[num + 4], SCST_FIO_VENDOR, 8);

			read_lock(&vdisk_serial_rwlock);
			i = strlen(virt_dev->t10_dev_id);
			memcpy(&buf[num + 12], virt_dev->t10_dev_id, i);
			read_unlock(&vdisk_serial_rwlock);

			buf[num + 3] = 8 + i;
			num += buf[num + 3];

			num += 4;

			/*
			 * Relative target port identifier
			 */
			buf[num + 0] = 0x01; /* binary */
			/* Relative target port id */
			buf[num + 1] = 0x10 | 0x04;

			put_unaligned_be16(cmd->tgt->rel_tgt_id,
					   &buf[num + 4 + 2]);

			buf[num + 3] = 4;
			num += buf[num + 3];

			num += 4;

			tg_id = scst_lookup_tg_id(dev, cmd->tgt);
			if (tg_id) {
				/*
				 * Target port group designator
				 */
				buf[num + 0] = 0x01; /* binary */
				/* Target port group id */
				buf[num + 1] = 0x10 | 0x05;

				put_unaligned_be16(tg_id, &buf[num + 4 + 2]);

				buf[num + 3] = 4;
				num += 4 + buf[num + 3];
			}

			/*
			 * IEEE id
			 */
			buf[num + 0] = 0x01; /* binary */

			/* EUI-64 */
			buf[num + 1] = 0x02;
			buf[num + 2] = 0x00;
			buf[num + 3] = 0x08;

			/* IEEE id */
			buf[num + 4] = virt_dev->t10_dev_id[0];
			buf[num + 5] = virt_dev->t10_dev_id[1];
			buf[num + 6] = virt_dev->t10_dev_id[2];

			/* IEEE ext id */
			buf[num + 7] = virt_dev->t10_dev_id[3];
			buf[num + 8] = virt_dev->t10_dev_id[4];
			buf[num + 9] = virt_dev->t10_dev_id[5];
			buf[num + 10] = virt_dev->t10_dev_id[6];
			buf[num + 11] = virt_dev->t10_dev_id[7];
			num += buf[num + 3];

			resp_len = num;
			put_unaligned_be16(resp_len, &buf[2]);
			resp_len += 4;
		} else if ((0xB0 == cmd->cdb[2]) && (dev->type == TYPE_DISK)) {
			/* Block Limits */
			int max_transfer;
			buf[1] = 0xB0;
			buf[3] = 0x3C;
			buf[4] = 1; /* WSNZ set */
			/* Optimal transfer granuality is PAGE_SIZE */
			put_unaligned_be16(max_t(int, PAGE_SIZE/dev->block_size, 1), &buf[6]);

			/* Max transfer len is min of sg limit and 8M */
			max_transfer = min_t(int,
					cmd->tgt_dev->max_sg_cnt << PAGE_SHIFT,
					8*1024*1024) / dev->block_size;
			put_unaligned_be32(max_transfer, &buf[8]);

			/*
			 * Let's have optimal transfer len 512KB. Better to not
			 * set it at all, because we don't have such limit,
			 * but some initiators may not understand that (?).
			 * From other side, too big transfers  are not optimal,
			 * because SGV cache supports only <4M buffers.
			 */
			put_unaligned_be32(min_t(int,
					max_transfer, 512*1024 / dev->block_size),
						&buf[12]);

			if (virt_dev->thin_provisioned) {
				uint32_t gran = 1, align = 0, max_lba = 1;

				/* MAXIMUM UNMAP BLOCK DESCRIPTOR COUNT is UNLIMITED */
				put_unaligned_be32(0xFFFFFFFF, &buf[24]);
				if (virt_dev->blockio) {
					vdev_blockio_get_unmap_params(virt_dev,
						&gran, &align, &max_lba);
				} else {
					max_lba = min_t(loff_t, 0xFFFFFFFFU,
							virt_dev->file_size >>
							dev->block_shift);
				}
				/*
				 * MAXIMUM UNMAP LBA COUNT, OPTIMAL UNMAP
				 * GRANULARITY and ALIGNMENT
				 */
				put_unaligned_be32(max_lba, &buf[20]);
				put_unaligned_be32(gran, &buf[28]);
				if (align != 0) {
					put_unaligned_be32(align, &buf[32]);
					buf[32] |= 0x80;
				}
			}

			/* MAXIMUM WRITE SAME LENGTH (measured in blocks) */
			put_unaligned_be64(dev->max_write_same_len >>
					   dev->block_shift, &buf[36]);

			resp_len = buf[3] + 4;
		} else if ((0xB1 == cmd->cdb[2]) && (dev->type == TYPE_DISK)) {
			/* Block Device Characteristics */
			buf[1] = 0xB1;
			buf[3] = 0x3C;
			if (virt_dev->rotational) {
				/* 15K RPM */
				put_unaligned_be16(0x3A98, &buf[4]);
			} else
				put_unaligned_be16(1, &buf[4]);
			resp_len = buf[3] + 4;
		} else if ((0xB2 == cmd->cdb[2]) && (dev->type == TYPE_DISK) &&
			   virt_dev->thin_provisioned) {
			/* Thin Provisioning */
			buf[1] = 0xB2;
			buf[3] = 4;
			buf[5] = 0xE0;
#if 0 /*
       * Might be a big performance and functionality win, but might be
       * dangerous as well, although generally nearly always it should be set,
       * because nearly all devices should return zero for unmapped blocks.
       * But let's be on the safe side and disable it for now.
       *
       * Changing it change also READ CAPACITY(16)!
       */
			buf[5] |= 0x4; /* LBPRZ */
#endif
			buf[6] = 2; /* thin provisioned */
			resp_len = buf[3] + 4;
		} else {
			TRACE_DBG("INQUIRY: Unsupported EVPD page %x", cmd->cdb[2]);
			scst_set_invalid_field_in_cdb(cmd, 2, 0);
			goto out_put;
		}
	} else {
		int len, num;

		if (cmd->cdb[2] != 0) {
			TRACE_DBG("INQUIRY: Unsupported page %x", cmd->cdb[2]);
			scst_set_invalid_field_in_cdb(cmd, 2, 0);
			goto out_put;
		}

		if (virt_dev->removable)
			buf[1] = 0x80;      /* removable */
		buf[2] = 6; /* Device complies to SPC-4 */
		buf[3] = 0x02;	/* Data in format specified in SPC */
		if (cmd->tgtt->fake_aca)
			buf[3] |= 0x20;
		buf[4] = 31;/* n - 4 = 35 - 4 = 31 for full 36 byte data */
		if (scst_impl_alua_configured(dev))
			buf[5] = SCST_INQ_TPGS_MODE_IMPLICIT;
		buf[6] = 0x10; /* MultiP 1 */
		buf[7] = 2; /* CMDQUE 1, BQue 0 => commands queuing supported */

		/*
		 * 8 byte ASCII Vendor Identification of the target
		 * - left aligned.
		 */
		if (cmd->tgtt->vendor)
			memcpy(&buf[8], cmd->tgtt->vendor, 8);
		else if (virt_dev->blockio)
			memcpy(&buf[8], SCST_BIO_VENDOR, 8);
		else
			memcpy(&buf[8], SCST_FIO_VENDOR, 8);

		/*
		 * 16 byte ASCII Product Identification of the target - left
		 * aligned.
		 */
		memset(&buf[16], ' ', 16);
		if (cmd->tgtt->get_product_id)
			cmd->tgtt->get_product_id(cmd->tgt_dev, &buf[16], 16);
		else {
			len = min_t(size_t, strlen(virt_dev->name), 16);
			memcpy(&buf[16], virt_dev->name, len);
		}

		/*
		 * 4 byte ASCII Product Revision Level of the target - left
		 * aligned.
		 */
		if (cmd->tgtt->revision)
			memcpy(&buf[32], cmd->tgtt->revision, 4);
		else
			memcpy(&buf[32], SCST_FIO_REV, 4);

		/** Version descriptors **/

		buf[4] += 58 - 36;
		num = 0;

		/* SAM-4 T10/1683-D revision 14 */
		buf[58 + num] = 0x0;
		buf[58 + num + 1] = 0x8B;
		num += 2;

		/* Physical transport */
		if (cmd->tgtt->get_phys_transport_version != NULL) {
			uint16_t v = cmd->tgtt->get_phys_transport_version(cmd->tgt);
			if (v != 0) {
				*((__be16 *)&buf[58 + num]) = cpu_to_be16(v);
				num += 2;
			}
		}

		/* SCSI transport */
		if (cmd->tgtt->get_scsi_transport_version != NULL) {
			*((__be16 *)&buf[58 + num]) =
				cpu_to_be16(cmd->tgtt->get_scsi_transport_version(cmd->tgt));
			num += 2;
		}

		/* SPC-4 T10/1731-D revision 23 */
		buf[58 + num] = 0x4;
		buf[58 + num + 1] = 0x63;
		num += 2;

		/* Device command set */
		if (virt_dev->command_set_version != 0) {
			*((__be16 *)&buf[58 + num]) =
				cpu_to_be16(virt_dev->command_set_version);
			num += 2;
		}

		/* Vendor specific information. */
		if (cmd->tgtt->get_vend_specific) {
			/* Skip to byte 96. */
			num = 96 - 58;
			num += cmd->tgtt->get_vend_specific(cmd->tgt_dev,
						    &buf[96], INQ_BUF_SZ - 96);
		}

		buf[4] += num;
		resp_len = buf[4] + 5;
	}

	sBUG_ON(resp_len > INQ_BUF_SZ);

	if (length > resp_len)
		length = resp_len;
	memcpy(address, buf, length);

out_put:
	scst_put_buf_full(cmd, address);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_free:
	kfree(buf);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_request_sense(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	int32_t length, sl;
	uint8_t *address;
	uint8_t b[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	/*
	 * No need to make it volatile, because at worst we will have a couple
	 * of extra commands refused after formatting actually finished, which
	 * is acceptable.
	 */
	if (virt_dev->format_active) {
		uint64_t d, div;
		uint16_t v;

		div = virt_dev->format_progress_to_do >> 16;
		d = virt_dev->format_progress_done;
		do_div(d, div);
		v = d;

		TRACE_DBG("Format progress %d", v);

		sl = scst_set_sense(b, sizeof(b), dev->d_sense,
			SCST_LOAD_SENSE(scst_sense_format_in_progress));

		BUILD_BUG_ON(SCST_STANDARD_SENSE_LEN < 18);
		if (dev->d_sense) {
			uint8_t *p = &b[7];
			int o = 8;
			*p += 8;
			b[o] = 2;
			b[o+1] = 6;
			b[o+4] = 0x80;
			put_unaligned_be16(v, &b[o+5]);
		} else {
			b[15] = 0x80;
			put_unaligned_be16(v, &b[16]);
		}
		TRACE_BUFF_FLAG(TRACE_DEBUG, "Format sense", b, sizeof(b));
	} else
		sl = scst_set_sense(b, sizeof(b), cmd->dev->d_sense,
			SCST_LOAD_SENSE(scst_sense_no_sense));

	length = scst_get_buf_full_sense(cmd, &address);
	TRACE_DBG("length %d", length);
	if (length <= 0)
		goto out;

	length = min(sl, length);
	memcpy(address, b, length);
	scst_set_resp_data_len(cmd, length);

	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static int vdisk_err_recov_pg(unsigned char *p, int pcontrol,
			       struct scst_vdisk_dev *virt_dev)
{	/* Read-Write Error Recovery page for mode_sense */
	const unsigned char err_recov_pg[] = {0x1, 0xa, 0xc0, 1, 0, 0, 0, 0,
					      1, 0, 0xff, 0xff};

	memcpy(p, err_recov_pg, sizeof(err_recov_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(err_recov_pg) - 2);
	return sizeof(err_recov_pg);
}

static int vdisk_disconnect_pg(unsigned char *p, int pcontrol,
				struct scst_vdisk_dev *virt_dev)
{	/* Disconnect-Reconnect page for mode_sense */
	const unsigned char disconnect_pg[] = {0x2, 0xe, 128, 128, 0, 10, 0, 0,
					       0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(p, disconnect_pg, sizeof(disconnect_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(disconnect_pg) - 2);
	return sizeof(disconnect_pg);
}

static int vdisk_rigid_geo_pg(unsigned char *p, int pcontrol,
	struct scst_vdisk_dev *virt_dev)
{
	unsigned char geo_m_pg[] = {0x04, 0x16, 0, 0, 0, DEF_HEADS, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0x3a, 0x98/* 15K RPM */, 0, 0};
	int32_t ncyl, n, rem;
	uint64_t dividend;

	memcpy(p, geo_m_pg, sizeof(geo_m_pg));
	/*
	 * Divide virt_dev->nblocks by (DEF_HEADS * DEF_SECTORS) and store
	 * the quotient in ncyl and the remainder in rem.
	 */
	dividend = virt_dev->nblocks;
	rem = do_div(dividend, DEF_HEADS * DEF_SECTORS);
	ncyl = dividend;
	if (rem != 0)
		ncyl++;
	memcpy(&n, p + 2, sizeof(u32));
	n = n | ((__force u32)cpu_to_be32(ncyl) >> 8);
	memcpy(p + 2, &n, sizeof(u32));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(geo_m_pg) - 2);
	return sizeof(geo_m_pg);
}

static int vdisk_format_pg(unsigned char *p, int pcontrol,
			    struct scst_vdisk_dev *virt_dev)
{       /* Format device page for mode_sense */
	const unsigned char format_pg[] = {0x3, 0x16, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0x40, 0, 0, 0};

	memcpy(p, format_pg, sizeof(format_pg));
	put_unaligned_be16(DEF_SECTORS, &p[10]);
	put_unaligned_be16(virt_dev->dev->block_size, &p[12]);
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(format_pg) - 2);
	return sizeof(format_pg);
}

static int vdisk_caching_pg(unsigned char *p, int pcontrol,
			     struct scst_vdisk_dev *virt_dev)
{	/* Caching page for mode_sense */
	const unsigned char caching_pg[] = {0x8, 0x12, 0x0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0x80, 0x14, 0, 0, 0, 0, 0, 0};

	memcpy(p, caching_pg, sizeof(caching_pg));
	p[2] |= !(virt_dev->wt_flag || virt_dev->nv_cache) ? WCE : 0;
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(caching_pg) - 2);
	return sizeof(caching_pg);
}

static int vdisk_ctrl_m_pg(unsigned char *p, int pcontrol,
			    struct scst_vdisk_dev *virt_dev)
{	/* Control mode page for mode_sense */
	const unsigned char ctrl_m_pg[] = {0xa, 0xa, 0, 0, 0, 0, 0, 0,
					   0, 0, 0x2, 0x4b};

	memcpy(p, ctrl_m_pg, sizeof(ctrl_m_pg));
	switch (pcontrol) {
	case 0: /* current */
		p[2] |= virt_dev->dev->tst << 5;
		p[2] |= virt_dev->dev->d_sense << 2;
		p[3] |= virt_dev->dev->queue_alg << 4;
		p[4] |= virt_dev->dev->swp << 3;
		p[5] |= virt_dev->dev->tas << 6;
		break;
	case 1: /* changeable */
		memset(p + 2, 0, sizeof(ctrl_m_pg) - 2);
#if 0	/*
	 * It's too early to implement it, since we can't control the
	 * backstorage device parameters. ToDo
	 */
		p[2] |= 7 << 5;		/* TST */
		p[3] |= 0xF << 4;	/* QUEUE ALGORITHM MODIFIER */
#endif
		p[2] |= 1 << 2;		/* D_SENSE */
		p[4] |= 1 << 3;		/* SWP */
		p[5] |= 1 << 6;		/* TAS */
		break;
	case 2: /* default */
		p[2] |= DEF_TST << 5;
		p[2] |= DEF_DSENSE << 2;
		if (virt_dev->wt_flag || virt_dev->nv_cache)
			p[3] |= DEF_QUEUE_ALG_WT << 4;
		else
			p[3] |= DEF_QUEUE_ALG << 4;
		p[4] |= DEF_SWP << 3;
		p[5] |= DEF_TAS << 6;
		break;
	case 3: /* saved, blocked by the caller */
	default:
		sBUG();
	}
	return sizeof(ctrl_m_pg);
}

static int vdisk_iec_m_pg(unsigned char *p, int pcontrol,
			   struct scst_vdisk_dev *virt_dev)
{	/* Informational Exceptions control mode page for mode_sense */
	const unsigned char iec_m_pg[] = {0x1c, 0xa, 0x08, 0, 0, 0, 0, 0,
					  0, 0, 0x0, 0x0};
	memcpy(p, iec_m_pg, sizeof(iec_m_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(iec_m_pg) - 2);
	return sizeof(iec_m_pg);
}

static enum compl_status_e vdisk_exec_mode_sense(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length;
	uint8_t *address;
	uint8_t *buf;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	unsigned char dbd, type;
	int pcontrol, pcode, subpcode;
	unsigned char dev_spec;
	int msense_6, offset = 0, len;
	unsigned char *bp;

	TRACE_ENTRY();

	buf = kzalloc(MSENSE_BUF_SZ, cmd->cmd_gfp_mask);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	virt_dev = cmd->dev->dh_priv;
	blocksize = cmd->dev->block_size;
	nblocks = virt_dev->nblocks;

	type = cmd->dev->type;
	dbd = cmd->cdb[1] & DBD;
	pcontrol = (cmd->cdb[2] & 0xc0) >> 6;
	pcode = cmd->cdb[2] & 0x3f;
	subpcode = cmd->cdb[3];
	msense_6 = (MODE_SENSE == cmd->cdb[0]);
	dev_spec = cmd->tgt_dev->tgt_dev_rd_only ? WP : 0;

	if (type != TYPE_ROM)
		dev_spec |= DPOFUA;

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0))
		goto out_free;

	if (0x3 == pcontrol) {
		TRACE_DBG("%s", "MODE SENSE: Saving values not supported");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_saving_params_unsup));
		goto out_put;
	}

	if (msense_6) {
		buf[1] = type;
		buf[2] = dev_spec;
		offset = 4;
	} else {
		buf[2] = type;
		buf[3] = dev_spec;
		offset = 8;
	}

	if (0 != subpcode) {
		/* TODO: Control Extension page */
		TRACE_DBG("%s", "MODE SENSE: Only subpage 0 is supported");
		scst_set_invalid_field_in_cdb(cmd, 3, 0);
		goto out_put;
	}

	if (!dbd) {
		/* Create block descriptor */
		buf[offset - 1] = 0x08;		/* block descriptor length */
		put_unaligned_be32(nblocks >> 32 ? 0xffffffffU : nblocks,
				   &buf[offset]);
		buf[offset + 4] = 0;			/* density code */
		put_unaligned_be24(blocksize, &buf[offset + 5]); /* blklen */

		offset += 8;			/* increment offset */
	}

	bp = buf + offset;

	switch (pcode) {
	case 0x1:	/* Read-Write error recovery page, direct access */
		len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
		break;
	case 0x2:	/* Disconnect-Reconnect page, all devices */
		if (type == TYPE_ROM)
			goto out_not_sup;
		len = vdisk_disconnect_pg(bp, pcontrol, virt_dev);
		break;
	case 0x3:       /* Format device page, direct access */
		if (type == TYPE_ROM)
			goto out_not_sup;
		len = vdisk_format_pg(bp, pcontrol, virt_dev);
		break;
	case 0x4:	/* Rigid disk geometry */
		if (type == TYPE_ROM)
			goto out_not_sup;
		len = vdisk_rigid_geo_pg(bp, pcontrol, virt_dev);
		break;
	case 0x8:	/* Caching page, direct access */
		if (type == TYPE_ROM)
			goto out_not_sup;
		len = vdisk_caching_pg(bp, pcontrol, virt_dev);
		break;
	case 0xa:	/* Control Mode page, all devices */
		len = vdisk_ctrl_m_pg(bp, pcontrol, virt_dev);
		break;
	case 0x1c:	/* Informational Exceptions Mode page, all devices */
		len = vdisk_iec_m_pg(bp, pcontrol, virt_dev);
		break;
	case 0x3f:	/* Read all Mode pages */
		if (type == TYPE_ROM) {
			len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
			len += vdisk_ctrl_m_pg(bp + len, pcontrol, virt_dev);
			len += vdisk_iec_m_pg(bp + len, pcontrol, virt_dev);
		} else {
			len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
			len += vdisk_disconnect_pg(bp + len, pcontrol, virt_dev);
			len += vdisk_format_pg(bp + len, pcontrol, virt_dev);
			len += vdisk_caching_pg(bp + len, pcontrol, virt_dev);
			len += vdisk_ctrl_m_pg(bp + len, pcontrol, virt_dev);
			len += vdisk_iec_m_pg(bp + len, pcontrol, virt_dev);
			len += vdisk_rigid_geo_pg(bp + len, pcontrol, virt_dev);
		}
		break;
	default:
		goto out_not_sup;
	}

	offset += len;

	if (msense_6)
		buf[0] = offset - 1;
	else
		put_unaligned_be16(offset - 2, &buf[0]);

	if (offset > length)
		offset = length;
	memcpy(address, buf, offset);

out_put:
	scst_put_buf_full(cmd, address);
	if (offset < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, offset);

out_free:
	kfree(buf);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;

out_not_sup:
	TRACE(TRACE_MINOR, "MODE SENSE: Unsupported page %x", pcode);
	scst_set_invalid_field_in_cdb(cmd, 2, SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
	goto out_put;
}

static int vdisk_set_wt(struct scst_vdisk_dev *virt_dev, int wt, bool read_only)
{
	int res = 0;
	struct file *fd;
	bool old_wt = virt_dev->wt_flag;

	TRACE_ENTRY();

	if ((virt_dev->wt_flag == wt) || virt_dev->nullio || virt_dev->nv_cache)
		goto out;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->wt_flag = wt;
	spin_unlock(&virt_dev->flags_lock);

	/*
	 * MODE SELECT is strictly serialized command, so it's safe here
	 * to reopen fd.
	 */

	fd = vdev_open_fd(virt_dev, read_only);
	if (IS_ERR(fd)) {
		PRINT_ERROR("filp_open(%s) returned an error %ld",
			    virt_dev->filename, PTR_ERR(fd));
		spin_lock(&virt_dev->flags_lock);
		virt_dev->wt_flag = old_wt;
		spin_unlock(&virt_dev->flags_lock);
		res = PTR_ERR(fd);
		goto out;
	}

	if (virt_dev->fd)
		filp_close(virt_dev->fd, NULL);

	virt_dev->fd = fd;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_ctrl_m_pg_select(unsigned char *p,
	struct scst_vdisk_dev *virt_dev, struct scst_cmd *cmd)
{
	struct scst_device *dev = virt_dev->dev;
	int old_swp = dev->swp, old_tas = dev->tas, old_dsense = dev->d_sense;

#if 0 /* Not implemented yet, see comment in vdisk_ctrl_m_pg() */
	dev->tst = (p[2] >> 5) & 1;
	dev->queue_alg = p[3] >> 4;
#else
	if ((dev->tst != ((p[2] >> 5) & 1)) || (dev->queue_alg != (p[3] >> 4))) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "%s", "MODE SELECT: Changing of "
			"TST and QUEUE ALGORITHM not supported");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		return;
	}
#endif
	dev->swp = (p[4] & 0x8) >> 3;
	dev->tas = (p[5] & 0x40) >> 6;
	dev->d_sense = (p[2] & 0x4) >> 2;

	PRINT_INFO("Device %s: new control mode page parameters: SWP %x "
		"(was %x), TAS %x (was %x), D_SENSE %d (was %d)",
		virt_dev->name, dev->swp, old_swp, dev->tas, old_tas,
		dev->d_sense, old_dsense);
	return;
}

static enum compl_status_e vdisk_exec_mode_select(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	int mselect_6, offset, type;

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	mselect_6 = (MODE_SELECT == cmd->cdb[0]);
	type = cmd->dev->type;

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0))
		goto out;

	if (!(cmd->cdb[1] & PF) || (cmd->cdb[1] & SP)) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "MODE SELECT: Unsupported "
			"value(s) of PF and/or SP bits (cdb[1]=%x)",
			cmd->cdb[1]);
		scst_set_invalid_field_in_cdb(cmd, 1, 0);
		goto out_put;
	}

	if (mselect_6)
		offset = 4;
	else
		offset = 8;

	if (address[offset - 1] == 8) {
		offset += 8;
	} else if (address[offset - 1] != 0) {
		PRINT_ERROR("%s", "MODE SELECT: Wrong parameters list length");
		scst_set_invalid_field_in_parm_list(cmd, offset-1, 0);
		goto out_put;
	}

	while (length > offset + 2) {
		if (address[offset] & PS) {
			PRINT_ERROR("%s", "MODE SELECT: Illegal PS bit");
			scst_set_invalid_field_in_parm_list(cmd, offset,
				SCST_INVAL_FIELD_BIT_OFFS_VALID | 7);
			goto out_put;
		}
		if (((address[offset] & 0x3f) == 0x8) && (type != TYPE_ROM)) {
			/* Caching page */
			if (address[offset + 1] != 18) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"caching page request");
				scst_set_invalid_field_in_parm_list(cmd, offset+1, 0);
				goto out_put;
			}
			if (vdisk_set_wt(virt_dev, (address[offset + 2] & WCE) ? 0 : 1,
					cmd->tgt_dev->tgt_dev_rd_only) != 0) {
				scst_set_busy(cmd);
				goto out_put;
			}
			break;
		} else if ((address[offset] & 0x3f) == 0xA) {
			/* Control page */
			if (address[offset + 1] != 0xA) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"control page request");
				scst_set_invalid_field_in_parm_list(cmd, offset+1, 0);
				goto out_put;
			}
			vdisk_ctrl_m_pg_select(&address[offset], virt_dev, cmd);
		} else {
			TRACE(TRACE_MINOR, "MODE SELECT: Invalid request %x",
				address[offset] & 0x3f);
			scst_set_invalid_field_in_parm_list(cmd, offset,
				SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
			goto out_put;
		}
		offset += address[offset + 1];
	}

out_put:
	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_log(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;

	TRACE_ENTRY();

	/* No log pages are supported */
	scst_set_invalid_field_in_cdb(cmd, 2, SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);

	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_read_capacity(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[8];

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	blocksize = cmd->dev->block_size;
	nblocks = virt_dev->nblocks;

	if ((cmd->cdb[8] & 1) == 0) {
		uint64_t lba = get_unaligned_be64(&cmd->cdb[2]);
		if (lba != 0) {
			TRACE_DBG("PMI zero and LBA not zero (cmd %p)", cmd);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out;
		}
	}

	memset(buffer, 0, sizeof(buffer));

	/* Last block on the virt_dev is (nblocks-1) */
#if 0 /* we don't need this workaround anymore */
	/*
	 * If we are thinly provisioned, we must ensure that the initiator
	 * issues a READ_CAPACITY(16) so we can return the LBPME bit. By
	 * returning 0xFFFFFFFF we do that.
	 */
	put_unaligned_be32(nblocks >> 32 || virt_dev->thin_provisioned ?
			   0xffffffffU : nblocks - 1, &buffer[0]);
#else
	put_unaligned_be32((nblocks >> 32) ? 0xffffffffU : nblocks - 1, &buffer[0]);
#endif

	put_unaligned_be32(blocksize, &buffer[4]);

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0))
		goto out;

	length = min_t(int, length, sizeof(buffer));

	memcpy(address, buffer, length);

	scst_put_buf_full(cmd, address);

	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_read_capacity16(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[32];

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	blocksize = cmd->dev->block_size;
	nblocks = virt_dev->nblocks - 1;

	if ((cmd->cdb[14] & 1) == 0) {
		uint32_t lba = get_unaligned_be32(&cmd->cdb[2]);
		if (lba != 0) {
			TRACE_DBG("PMI zero and LBA not zero (cmd %p)", cmd);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out;
		}
	}

	memset(buffer, 0, sizeof(buffer));

	put_unaligned_be64(nblocks, &buffer[0]);
	put_unaligned_be32(blocksize, &buffer[8]);

	switch (blocksize) {
	case 512:
		buffer[13] = 3;
		break;
	case 1024:
		buffer[13] = 2;
		break;
	case 2048:
		buffer[13] = 1;
		break;
	case 4096:
	default:
		buffer[13] = 0;
		break;
	}

	if (virt_dev->thin_provisioned) {
		buffer[14] |= 0x80;     /* Add LBPME */
#if 0 /*
       * Might be a big performance and functionality win, but might be
       * dangerous as well, although generally nearly always it should be set,
       * because nearly all devices should return zero for unmapped blocks.
       * But let's be on the safe side and disable it for now.
       *
       * Changing it change also 0xB2 INQUIRY page!
       */
		buffer[14] |= 0x40;     /* Add LBPRZ */
#endif
	}

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0))
		goto out;

	length = min_t(int, length, sizeof(buffer));

	memcpy(address, buffer, length);

	scst_put_buf_full(cmd, address);

	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_get_lba_status(struct vdisk_cmd_params *p)
{
	return INVALID_OPCODE;
}

/* SPC-4 REPORT TARGET PORT GROUPS command */
static enum compl_status_e vdisk_exec_report_tpgs(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev;
	uint8_t *address;
	void *buf;
	int32_t buf_len;
	uint32_t data_length, length;
	uint8_t data_format;
	int res;

	TRACE_ENTRY();

	buf_len = scst_get_buf_full_sense(cmd, &address);
	if (buf_len <= 0)
		goto out;

	dev = cmd->dev;
	data_format = cmd->cdb[1] >> 5;

	res = scst_tg_get_group_info(&buf, &data_length, dev, data_format);
	if (res == -ENOMEM) {
		scst_set_busy(cmd);
		goto out_put;
	} else if (res < 0) {
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	length = min_t(uint32_t, data_length, buf_len);
	memcpy(address, buf, length);
	kfree(buf);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_put:
	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_read_toc(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length, off = 0;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t nblocks;
	uint8_t buffer[4+8+8] = { 0x00, 0x0a, 0x01, 0x01, 0x00, 0x14,
				  0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

	TRACE_ENTRY();

	if (cmd->dev->type != TYPE_ROM) {
		PRINT_ERROR("%s", "READ TOC for non-CDROM device");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out;
	}

	if (cmd->cdb[2] & 0x0e/*Format*/) {
		PRINT_ERROR("%s", "READ TOC: invalid requested data format");
		scst_set_invalid_field_in_cdb(cmd, 2,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 5);
		goto out;
	}

	if ((cmd->cdb[6] != 0 && (cmd->cdb[2] & 0x01)) ||
	    (cmd->cdb[6] > 1 && cmd->cdb[6] != 0xAA)) {
		PRINT_ERROR("READ TOC: invalid requested track number %x",
			cmd->cdb[6]);
		scst_set_invalid_field_in_cdb(cmd, 6, 0);
		goto out;
	}

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0))
		goto out;

	virt_dev = cmd->dev->dh_priv;
	/* ToDo when you have > 8TB ROM device. */
	nblocks = (uint32_t)virt_dev->nblocks;

	/* Header */
	memset(buffer, 0, sizeof(buffer));
	buffer[2] = 0x01;    /* First Track/Session */
	buffer[3] = 0x01;    /* Last Track/Session */
	off = 4;
	if (cmd->cdb[6] <= 1) {
		/* Fistr TOC Track Descriptor */
		/* ADDR    0x10 - Q Sub-channel encodes current position data
		   CONTROL 0x04 - Data track, recoreded uninterrupted */
		buffer[off+1] = 0x14;
		/* Track Number */
		buffer[off+2] = 0x01;
		off += 8;
	}
	if (!(cmd->cdb[2] & 0x01)) {
		/* Lead-out area TOC Track Descriptor */
		buffer[off+1] = 0x14;
		/* Track Number */
		buffer[off+2] = 0xAA;
		/* Track Start Address */
		put_unaligned_be32(nblocks, &buffer[off + 4]);
		off += 8;
	}

	buffer[1] = off - 2;    /* Data  Length */

	if (off > length)
		off = length;
	memcpy(address, buffer, off);

	scst_put_buf_full(cmd, address);

	if (off < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, off);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_prevent_allow_medium_removal(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;

	TRACE_DBG("PERSIST/PREVENT 0x%02x", cmd->cdb[4]);

	spin_lock(&virt_dev->flags_lock);
	virt_dev->prevent_allow_medium_removal = cmd->cdb[4] & 0x01 ? 1 : 0;
	spin_unlock(&virt_dev->flags_lock);

	return CMD_SUCCEEDED;
}

static int vdisk_fsync_blockio(struct vdisk_cmd_params *p, loff_t loff,
	loff_t len, struct scst_device *dev, gfp_t gfp_flags,
	struct scst_cmd *cmd, bool async)
{
	int res;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

	/**
	 ** !!! CAUTION !!!: cmd can be NULL here! Don't use it for
	 ** anything without checking for NULL at first !!!
	 **/

	EXTRACHECKS_BUG_ON(!virt_dev->blockio);

	res = vdisk_blockio_flush(virt_dev->bdev, gfp_flags, true,
		cmd, async);

	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_fsync_fileio(struct vdisk_cmd_params *p, loff_t loff,
	loff_t len, struct scst_device *dev, struct scst_cmd *cmd, bool async)
{
	int res;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	struct file *file;

	TRACE_ENTRY();

	/**
	 ** !!! CAUTION !!!: cmd can be NULL here! Don't use it for
	 ** anything without checking for NULL at first !!!
	 **/

	EXTRACHECKS_BUG_ON(virt_dev->blockio);

	file = virt_dev->fd;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
	res = sync_page_range(file->f_dentry->d_inode, file->f_mapping,
		loff, len);
#else
#if 0	/* For sparse files we might need to sync metadata as well */
	res = generic_write_sync(file, loff, len);
#else
	res = filemap_write_and_wait_range(file->f_mapping, loff, len);
#endif
#endif
	if (unlikely(res != 0)) {
		PRINT_ERROR("sync range failed (%d)", res);
		if (cmd != NULL) {
			if (res == -ENOMEM)
				scst_set_busy(cmd);
			else
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(scst_sense_write_error));
		}
	}

	if (async) {
		if (cmd != NULL) {
			cmd->completed = 1;
			cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
				scst_estimate_context());
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_fsync(struct vdisk_cmd_params *p, loff_t loff,
	loff_t len, struct scst_device *dev, gfp_t gfp_flags,
	struct scst_cmd *cmd, bool async)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

	/**
	 ** !!! CAUTION !!!: cmd can be NULL here! Don't use it for
	 ** anything without checking for NULL at first !!!
	 **/

	/* It should be generated by compiler as a single comparison */
	if (virt_dev->nv_cache || virt_dev->wt_flag ||
	    virt_dev->o_direct_flag || virt_dev->nullio) {
		if (async) {
			cmd->completed = 1;
			cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
				scst_estimate_context());
		}
		goto out;
	}

	if (virt_dev->blockio)
		res = vdisk_fsync_blockio(p, loff, len, dev, gfp_flags, cmd, async);
	else
		res = vdisk_fsync_fileio(p, loff, len, dev, cmd, async);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct iovec *vdisk_alloc_iv(struct scst_cmd *cmd,
				    struct vdisk_cmd_params *p)
{
	int iv_count;

	iv_count = min_t(int, scst_get_buf_count(cmd), UIO_MAXIOV);
	if (iv_count > p->iv_count) {
		if (p->iv != p->small_iv)
			kfree(p->iv);
		p->iv_count = 0;
		/* It can't be called in atomic context */
		p->iv = (iv_count <= ARRAY_SIZE(p->small_iv)) ? p->small_iv :
			kmalloc(sizeof(*p->iv) * iv_count, cmd->cmd_gfp_mask);
		if (p->iv == NULL) {
			PRINT_ERROR("Unable to allocate iv (%d)", iv_count);
			goto out;
		}
		p->iv_count = iv_count;
	}

out:
	return p->iv;
}

static enum compl_status_e nullio_exec_read(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static enum compl_status_e blockio_exec_read(struct vdisk_cmd_params *p)
{
	blockio_exec_rw(p, false, false);
	return RUNNING_ASYNC;
}

static enum compl_status_e fileio_exec_read(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	loff_t loff = p->loff;
	mm_segment_t old_fs;
	loff_t err = 0;
	ssize_t length, full_len;
	uint8_t __user *address;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = virt_dev->fd;
	struct iovec *iv;
	int iv_count, i;
	bool finished = false;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

	if (p->use_zero_copy)
		goto out;

	iv = vdisk_alloc_iv(cmd, p);
	if (iv == NULL)
		goto out_nomem;

	length = scst_get_buf_first(cmd, (uint8_t __force **)&address);
	if (unlikely(length < 0)) {
		PRINT_ERROR("scst_get_buf_first() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	old_fs = get_fs();
	set_fs(get_ds());

	while (1) {
		iv_count = 0;
		full_len = 0;
		i = -1;
		while (length > 0) {
			full_len += length;
			i++;
			iv_count++;
			iv[i].iov_base = address;
			iv[i].iov_len = length;
			if (iv_count == UIO_MAXIOV)
				break;
			length = scst_get_buf_next(cmd,
				(uint8_t __force **)&address);
		}
		if (length == 0) {
			finished = true;
			if (unlikely(iv_count == 0))
				break;
		} else if (unlikely(length < 0)) {
			PRINT_ERROR("scst_get_buf_next() failed: %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}

		TRACE_DBG("(iv_count %d, full_len %zd)", iv_count, full_len);

		/* READ */
		err = vfs_readv(fd, (struct iovec __force __user *)iv, iv_count,
				&loff);

		if ((err < 0) || (err < full_len)) {
			PRINT_ERROR("readv() returned %lld from %zd",
				    (long long unsigned int)err,
				    full_len);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			goto out_set_fs;
		}

		for (i = 0; i < iv_count; i++)
			scst_put_buf(cmd, (void __force *)(iv[i].iov_base));

		if (finished)
			break;

		length = scst_get_buf_next(cmd, (uint8_t __force **)&address);
	};

	set_fs(old_fs);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;

out_set_fs:
	set_fs(old_fs);
	for (i = 0; i < iv_count; i++)
		scst_put_buf(cmd, (void __force *)(iv[i].iov_base));
	goto out;

out_nomem:
	scst_set_busy(cmd);
	err = 0;
	goto out;
}

static enum compl_status_e nullio_exec_write(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static enum compl_status_e blockio_exec_write(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	blockio_exec_rw(p, true, p->fua || virt_dev->wt_flag);
	return RUNNING_ASYNC;
}

static enum compl_status_e fileio_exec_write(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	loff_t loff = p->loff;
	mm_segment_t old_fs;
	loff_t err = 0;
	ssize_t length, full_len, saved_full_len;
	uint8_t __user *address;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = virt_dev->fd;
	struct iovec *iv, *eiv;
	int i, iv_count, eiv_count;
	bool finished = false;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

	if (p->use_zero_copy)
		goto out_sync;

	iv = vdisk_alloc_iv(cmd, p);
	if (iv == NULL)
		goto out_nomem;

	length = scst_get_buf_first(cmd, (uint8_t __force **)&address);
	if (unlikely(length < 0)) {
		PRINT_ERROR("scst_get_buf_first() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	old_fs = get_fs();
	set_fs(get_ds());

	while (1) {
		iv_count = 0;
		full_len = 0;
		i = -1;
		while (length > 0) {
			full_len += length;
			i++;
			iv_count++;
			iv[i].iov_base = address;
			iv[i].iov_len = length;
			if (iv_count == UIO_MAXIOV)
				break;
			length = scst_get_buf_next(cmd,
				(uint8_t __force **)&address);
		}
		if (length == 0) {
			finished = true;
			if (unlikely(iv_count == 0))
				break;
		} else if (unlikely(length < 0)) {
			PRINT_ERROR("scst_get_buf_next() failed: %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}

		saved_full_len = full_len;
		eiv = iv;
		eiv_count = iv_count;
restart:
		TRACE_DBG("writing(eiv_count %d, full_len %zd)", eiv_count, full_len);

		/* WRITE */
		err = vfs_writev(fd, (struct iovec __force __user *)eiv, eiv_count,
				 &loff);

		if (err < 0) {
			PRINT_ERROR("write() returned %lld from %zd",
				    (long long unsigned int)err,
				    full_len);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_write_error));
			}
			goto out_set_fs;
		} else if (err < full_len) {
			/*
			 * Probably that's wrong, but sometimes write() returns
			 * value less, than requested. Let's restart.
			 */
			int e = eiv_count;
			TRACE_MGMT_DBG("write() returned %d from %zd "
				"(iv_count=%d)", (int)err, full_len,
				eiv_count);
			if (err == 0) {
				PRINT_INFO("Suspicious: write() returned 0 from "
					"%zd (iv_count=%d)", full_len, eiv_count);
			}
			full_len -= err;
			for (i = 0; i < e; i++) {
				if ((long long)eiv->iov_len < err) {
					err -= eiv->iov_len;
					eiv++;
					eiv_count--;
				} else {
					eiv->iov_base =
					    (uint8_t __force __user *)eiv->iov_base + err;
					eiv->iov_len -= err;
					break;
				}
			}
			goto restart;
		}

		for (i = 0; i < iv_count; i++)
			scst_put_buf(cmd, (void __force *)(iv[i].iov_base));

		if (finished)
			break;

		length = scst_get_buf_next(cmd, (uint8_t __force **)&address);
	}

	set_fs(old_fs);

out_sync:
	/* O_DSYNC flag is used for WT devices */
	if (p->fua)
		vdisk_fsync(p, loff, scst_cmd_get_data_len(cmd), cmd->dev,
			    cmd->cmd_gfp_mask, cmd, false);
out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;

out_set_fs:
	set_fs(old_fs);
	for (i = 0; i < iv_count; i++)
		scst_put_buf(cmd, (void __force *)(iv[i].iov_base));
	goto out_sync;

out_nomem:
	scst_set_busy(cmd);
	err = 0;
	goto out;
}

struct scst_blockio_work {
	atomic_t bios_inflight;
	struct scst_cmd *cmd;
};

static inline void blockio_check_finish(struct scst_blockio_work *blockio_work)
{
	/* Decrement the bios in processing, and if zero signal completion */
	if (atomic_dec_and_test(&blockio_work->bios_inflight)) {
		blockio_work->cmd->completed = 1;
		blockio_work->cmd->scst_cmd_done(blockio_work->cmd,
			SCST_CMD_STATE_DEFAULT, scst_estimate_context());
		kmem_cache_free(blockio_work_cachep, blockio_work);
	}
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
static int blockio_endio(struct bio *bio, unsigned int bytes_done, int error)
#else
static void blockio_endio(struct bio *bio, int error)
#endif
{
	struct scst_blockio_work *blockio_work = bio->bi_private;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	if (bio->bi_size)
		return 1;
#endif

	if (unlikely(!bio_flagged(bio, BIO_UPTODATE))) {
		if (error == 0) {
			PRINT_ERROR("Not up to date bio with error 0 for "
				"cmd %p, returning -EIO", blockio_work->cmd);
			error = -EIO;
		}
	}

	if (unlikely(error != 0)) {
		static DEFINE_SPINLOCK(blockio_endio_lock);
		unsigned long flags;

		PRINT_ERROR("BLOCKIO for cmd %p finished with error %d",
			blockio_work->cmd, error);

		/* To protect from several bios finishing simultaneously */
		spin_lock_irqsave(&blockio_endio_lock, flags);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		if (bio->bi_rw & (1 << BIO_RW))
#else
		if (bio->bi_rw & REQ_WRITE)
#endif
			scst_set_cmd_error(blockio_work->cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		else
			scst_set_cmd_error(blockio_work->cmd,
				SCST_LOAD_SENSE(scst_sense_read_error));

		spin_unlock_irqrestore(&blockio_endio_lock, flags);
	}

	blockio_check_finish(blockio_work);

	bio_put(bio);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	return 0;
#else
	return;
#endif
}

static void blockio_exec_rw(struct vdisk_cmd_params *p, bool write, bool fua)
{
	struct scst_cmd *cmd = p->cmd;
	u64 lba_start = scst_cmd_get_lba(cmd);
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	int block_shift = cmd->dev->block_shift;
	struct block_device *bdev = virt_dev->bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	int length, max_nr_vecs = 0, offset;
	struct page *page;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	int need_new_bio;
	struct scst_blockio_work *blockio_work;
	int bios = 0;
	gfp_t gfp_mask = cmd->cmd_gfp_mask;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	struct blk_plug plug;
#endif

	TRACE_ENTRY();

	WARN_ON(virt_dev->nullio);

	/* Allocate and initialize blockio_work struct */
	blockio_work = kmem_cache_alloc(blockio_work_cachep, gfp_mask);
	if (blockio_work == NULL)
		goto out_no_mem;

#if 0
	{
		static int err_inj_cntr;
		if (++err_inj_cntr % 256 == 0) {
			PRINT_INFO("blockio_exec_rw() error injection");
			goto out_no_bio;
		}
	}
#endif

	blockio_work->cmd = cmd;

	if (q)
		max_nr_vecs = min(bio_get_nr_vecs(bdev), BIO_MAX_PAGES);
	else
		max_nr_vecs = 1;

	need_new_bio = 1;

	length = scst_get_sg_page_first(cmd, &page, &offset);
	while (length > 0) {
		int len, bytes, off, thislen;
		struct page *pg;
		u64 lba_start0;

		pg = page;
		len = length;
		off = offset;
		thislen = 0;
		lba_start0 = lba_start;

		while (len > 0) {
			int rc;

			if (need_new_bio) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
				bio = bio_kmalloc(gfp_mask, max_nr_vecs);
#else
				bio = bio_alloc(gfp_mask, max_nr_vecs);
#endif
				if (!bio) {
					PRINT_ERROR("Failed to create bio "
						"for data segment %d (cmd %p)",
						cmd->get_sg_buf_entry_num, cmd);
					goto out_no_bio;
				}

				bios++;
				need_new_bio = 0;
				bio->bi_end_io = blockio_endio;
				bio->bi_sector = lba_start0 << (block_shift - 9);
				bio->bi_bdev = bdev;
				bio->bi_private = blockio_work;
				/*
				 * Better to fail fast w/o any local recovery
				 * and retries.
				 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
				bio->bi_rw |= (1 << BIO_RW_FAILFAST);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
				bio->bi_rw |= (1 << BIO_RW_FAILFAST_DEV) |
					      (1 << BIO_RW_FAILFAST_TRANSPORT) |
					      (1 << BIO_RW_FAILFAST_DRIVER);
#else
				bio->bi_rw |= REQ_FAILFAST_DEV |
					      REQ_FAILFAST_TRANSPORT |
					      REQ_FAILFAST_DRIVER;
#endif
#if 0 /* It could be win, but could be not, so a performance study is needed */
				bio->bi_rw |= REQ_SYNC;
#endif
				if (fua)
					bio->bi_rw |= REQ_FUA;

				if (cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) || \
	defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 6
					bio->bi_rw |= REQ_META;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
					/*
					 * Priority boosting was separated
					 * from REQ_META in commit 65299a3b
					 * (kernel 3.1.0).
					 */
					bio->bi_rw |= REQ_PRIO;
#endif
#elif !defined(RHEL_MAJOR) || RHEL_MAJOR -0 >= 6
					/*
					 * BIO_* and REQ_* flags were unified
					 * in commit 7b6d91da (kernel 2.6.36).
					 */
					bio->bi_rw |= BIO_RW_META;
#endif
				}

				if (!hbio)
					hbio = tbio = bio;
				else
					tbio = tbio->bi_next = bio;
			}

			bytes = min_t(unsigned int, len, PAGE_SIZE - off);

			rc = bio_add_page(bio, pg, bytes, off);
			if (rc < bytes) {
				sBUG_ON(rc != 0);
				need_new_bio = 1;
				lba_start0 += thislen >> block_shift;
				thislen = 0;
				continue;
			}

			pg++;
			thislen += bytes;
			len -= bytes;
			off = 0;
		}

		lba_start += length >> block_shift;

		scst_put_sg_page(cmd, page, offset);
		length = scst_get_sg_page_next(cmd, &page, &offset);
	}

	/* +1 to prevent erroneous too early command completion */
	atomic_set(&blockio_work->bios_inflight, bios+1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	blk_start_plug(&plug);
#endif

	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		submit_bio((write != 0), bio);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	blk_finish_plug(&plug);
#else
	if (q && q->unplug_fn)
		q->unplug_fn(q);
#endif

	blockio_check_finish(blockio_work);

out:
	TRACE_EXIT();
	return;

out_no_bio:
	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio_put(bio);
	}
	kmem_cache_free(blockio_work_cachep, blockio_work);

out_no_mem:
	scst_set_busy(cmd);
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
static void vdev_flush_end_io(struct bio *bio, int error)
{
	struct scst_cmd *cmd = bio->bi_private;

	TRACE_ENTRY();

	if (unlikely(error != 0)) {
		PRINT_ERROR("FLUSH bio failed: %d (cmd %p)",
			error, cmd);
		if (cmd != NULL)
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_write_error));
	}

	if (cmd == NULL)
		goto out_put;

	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, scst_estimate_context());

out_put:
	bio_put(bio);

	TRACE_EXIT();
	return;
}
#endif

static int vdisk_blockio_flush(struct block_device *bdev, gfp_t gfp_mask,
	bool report_error, struct scst_cmd *cmd, bool async)
{
	int res = 0;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
	if (async) {
		struct bio *bio = bio_alloc(gfp_mask, 0);
		if (bio == NULL) {
			res = -ENOMEM;
			goto out_rep;
		}
		bio->bi_end_io = vdev_flush_end_io;
		bio->bi_private = cmd;
		bio->bi_bdev = bdev;
		submit_bio(WRITE_FLUSH, bio);
		goto out;
	} else {
#else
	{
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)           \
    && !(defined(CONFIG_SUSE_KERNEL)                        \
	 && LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 34))
		res = blkdev_issue_flush(bdev, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
		res = blkdev_issue_flush(bdev, gfp_mask, NULL, BLKDEV_IFL_WAIT);
#else
		res = blkdev_issue_flush(bdev, gfp_mask, NULL);
#endif
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
out_rep:
#endif
	if ((res != 0) && report_error)
		PRINT_ERROR("%s() failed: %d",
			async ? "bio_alloc" : "blkdev_issue_flush", res);

	if (async && (cmd != NULL)) {
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
			scst_estimate_context());
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
out:
#endif
	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e fileio_exec_verify(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	loff_t loff = p->loff;
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, len_mem = 0;
	uint8_t *address_sav, *address = NULL;
	int compare;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = virt_dev->fd;
	uint8_t *mem_verify = NULL;
	int64_t data_len = scst_cmd_get_data_len(cmd);

	TRACE_ENTRY();

	sBUG_ON(virt_dev->blockio);

	if (vdisk_fsync(p, loff, data_len, cmd->dev,
			cmd->cmd_gfp_mask, cmd, false) != 0)
		goto out;

	/*
	 * Until the cache is cleared prior the verifying, there is not
	 * much point in this code. ToDo.
	 *
	 * Nevertherless, this code is valuable if the data have not been read
	 * from the file/disk yet.
	 */

	compare = scst_cmd_get_data_direction(cmd) == SCST_DATA_WRITE;
	TRACE_DBG("VERIFY with BYTCHK=%d at offset %lld and len %lld\n",
		  compare, loff, (long long)data_len);

	/* SEEK */
	old_fs = get_fs();
	set_fs(get_ds());

	if (!virt_dev->nullio) {
		if (fd->f_op->llseek)
			err = fd->f_op->llseek(fd, loff, 0/*SEEK_SET*/);
		else
			err = default_llseek(fd, loff, 0/*SEEK_SET*/);
		if (err != loff) {
			PRINT_ERROR("lseek trouble %lld != %lld",
				    (long long unsigned int)err,
				    (long long unsigned int)loff);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_read_error));
			goto out_set_fs;
		}
	}

	mem_verify = vmalloc(LEN_MEM);
	if (mem_verify == NULL) {
		PRINT_ERROR("Unable to allocate memory %d for verify",
			       LEN_MEM);
		scst_set_busy(cmd);
		goto out_set_fs;
	}

	if (compare) {
		length = scst_get_buf_first(cmd, &address);
		address_sav = address;
	} else
		length = data_len;

	while (length > 0) {
		len_mem = (length > LEN_MEM) ? LEN_MEM : length;
		TRACE_DBG("Verify: length %zd - len_mem %zd", length, len_mem);

		if (!virt_dev->nullio)
			err = vfs_read(fd, (char __force __user *)mem_verify,
				       len_mem, &loff);
		else
			err = len_mem;
		if ((err < 0) || (err < len_mem)) {
			PRINT_ERROR("verify() returned %lld from %zd",
				    (long long unsigned int)err, len_mem);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			if (compare)
				scst_put_buf(cmd, address_sav);
			goto out_set_fs;
		}
		if (compare && memcmp(address, mem_verify, len_mem) != 0) {
			TRACE_DBG("Verify: error memcmp length %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_miscompare_error));
			scst_put_buf(cmd, address_sav);
			goto out_set_fs;
		}
		length -= len_mem;
		if (compare)
			address += len_mem;
		if (compare && length <= 0) {
			scst_put_buf(cmd, address_sav);
			length = scst_get_buf_next(cmd, &address);
			address_sav = address;
		}
	}

	if (length < 0) {
		PRINT_ERROR("scst_get_buf_() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
	}

out_set_fs:
	set_fs(old_fs);
	if (mem_verify)
		vfree(mem_verify);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e blockio_exec_write_verify(struct vdisk_cmd_params *p)
{
	/* Not yet implemented */
	WARN_ON(true);
	return blockio_exec_write(p);
}

static enum compl_status_e blockio_exec_verify(struct vdisk_cmd_params *p)
{
	/* Not yet implemented */
	return CMD_SUCCEEDED;
}

static enum compl_status_e fileio_exec_write_verify(struct vdisk_cmd_params *p)
{
	fileio_exec_write(p);
	/* O_DSYNC flag is used for WT devices */
	if (scsi_status_is_good(p->cmd->status))
		fileio_exec_verify(p);
	return CMD_SUCCEEDED;
}

static enum compl_status_e nullio_exec_write_verify(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static void vdisk_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();

	if ((mcmd->fn == SCST_LUN_RESET) || (mcmd->fn == SCST_TARGET_RESET)) {
		/* Restore default values */
		struct scst_device *dev = tgt_dev->dev;
		struct scst_vdisk_dev *virt_dev = dev->dh_priv;
		int rc;

		dev->tst = DEF_TST;
		dev->d_sense = DEF_DSENSE;
		dev->swp = DEF_SWP;
		dev->tas = DEF_TAS;

		if (virt_dev->wt_flag && !virt_dev->nv_cache)
			dev->queue_alg = DEF_QUEUE_ALG_WT;
		else
			dev->queue_alg = DEF_QUEUE_ALG;

		rc = vdisk_set_wt(virt_dev, DEF_WRITE_THROUGH,
			tgt_dev->tgt_dev_rd_only);
		if (rc != 0) {
			PRINT_CRIT_ERROR("Unable to reset caching mode to %d",
				DEF_WRITE_THROUGH);
		}

		spin_lock(&virt_dev->flags_lock);
		virt_dev->prevent_allow_medium_removal = 0;
		spin_unlock(&virt_dev->flags_lock);
	} else if (mcmd->fn == SCST_PR_ABORT_ALL) {
		struct scst_device *dev = tgt_dev->dev;
		struct scst_vdisk_dev *virt_dev = dev->dh_priv;
		spin_lock(&virt_dev->flags_lock);
		virt_dev->prevent_allow_medium_removal = 0;
		spin_unlock(&virt_dev->flags_lock);
	}

	TRACE_EXIT();
	return;
}

static void vdisk_report_registering(const struct scst_vdisk_dev *virt_dev)
{
	char buf[128];
	int i, j;

	i = snprintf(buf, sizeof(buf), "Registering virtual %s device %s ",
		virt_dev->vdev_devt->name, virt_dev->name);
	j = i;

	if (virt_dev->wt_flag)
		i += snprintf(&buf[i], sizeof(buf) - i, "(WRITE_THROUGH");

	if (virt_dev->nv_cache)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sNV_CACHE",
			(j == i) ? "(" : ", ");

	if (virt_dev->rd_only)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sREAD_ONLY",
			(j == i) ? "(" : ", ");

	if (virt_dev->o_direct_flag)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sO_DIRECT",
			(j == i) ? "(" : ", ");

	if (virt_dev->nullio)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sNULLIO",
			(j == i) ? "(" : ", ");

	if (virt_dev->blockio)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sBLOCKIO",
			(j == i) ? "(" : ", ");

	if (virt_dev->removable)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sREMOVABLE",
			(j == i) ? "(" : ", ");

	if (virt_dev->rotational)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sROTATIONAL",
			(j == i) ? "(" : ", ");

	if (virt_dev->thin_provisioned)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sTHIN_PROVISIONED",
			(j == i) ? "(" : ", ");

	if (virt_dev->zero_copy)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sZERO_COPY",
			(j == i) ? "(" : ", ");

	if (virt_dev->dummy)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sDUMMY",
			(j == i) ? "(" : ", ");

	if (j == i)
		PRINT_INFO("%s", buf);
	else
		PRINT_INFO("%s)", buf);

	return;
}

static int vdisk_resync_size(struct scst_vdisk_dev *virt_dev)
{
	loff_t file_size;
	int res = 0;

	sBUG_ON(virt_dev->nullio);
	sBUG_ON(!virt_dev->filename);

	res = vdisk_get_file_size(virt_dev->filename,
			virt_dev->blockio, &file_size);
	if (res != 0)
		goto out;

	if (file_size == virt_dev->file_size) {
		PRINT_INFO("Size of virtual disk %s remained the same",
			virt_dev->name);
		goto out;
	}

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	virt_dev->file_size = file_size;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->dev->block_shift;

	PRINT_INFO("New size of SCSI target virtual disk %s "
		"(fs=%lldMB, bs=%d, nblocks=%lld, cyln=%lld%s)",
		virt_dev->name, virt_dev->file_size >> 20,
		virt_dev->dev->block_size,
		(long long unsigned int)virt_dev->nblocks,
		(long long unsigned int)virt_dev->nblocks/64/32,
		virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
						"than 1" : "");

	scst_capacity_data_changed(virt_dev->dev);

	scst_resume_activity();
out:
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static int vdev_create(struct scst_dev_type *devt,
	const char *name, struct scst_vdisk_dev **res_virt_dev)
{
	int res;
	struct scst_vdisk_dev *virt_dev, *vv;
	uint64_t dev_id_num;

	res = -EEXIST;
	if (vdev_find(name))
		goto out;

	/* It's read-mostly, so cache alignment isn't needed */
	virt_dev = kzalloc(sizeof(*virt_dev), GFP_KERNEL);
	if (virt_dev == NULL) {
		PRINT_ERROR("Allocation of virtual device %s failed",
			devt->name);
		res = -ENOMEM;
		goto out;
	}

	spin_lock_init(&virt_dev->flags_lock);
	virt_dev->vdev_devt = devt;

	virt_dev->rd_only = DEF_RD_ONLY;
	virt_dev->dummy = DEF_DUMMY;
	virt_dev->removable = DEF_REMOVABLE;
	virt_dev->rotational = DEF_ROTATIONAL;
	virt_dev->thin_provisioned = DEF_THIN_PROVISIONED;

	virt_dev->blk_shift = DEF_DISK_BLOCK_SHIFT;

	if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR("Name %s is too long (max allowed %zd)", name,
			sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_free;
	}
	strcpy(virt_dev->name, name);

	dev_id_num = vdisk_gen_dev_id_num(virt_dev->name);

	snprintf(virt_dev->t10_dev_id, sizeof(virt_dev->t10_dev_id),
		"%llx-%s", dev_id_num, virt_dev->name);
	TRACE_DBG("t10_dev_id %s", virt_dev->t10_dev_id);

	scnprintf(virt_dev->usn, sizeof(virt_dev->usn), "%llx", dev_id_num);
	TRACE_DBG("usn %s", virt_dev->usn);

	list_for_each_entry(vv, &vdev_list, vdev_list_entry) {
		if (strcmp(virt_dev->usn, vv->usn) == 0) {
			PRINT_ERROR("New usn %s conflicts with one of dev %s",
				virt_dev->usn, vv->name);
			res = -EEXIST;
			goto out_free;
		}
	}

	*res_virt_dev = virt_dev;
	res = 0;

out:
	return res;

out_free:
	kfree(virt_dev);
	goto out;
}

static void vdev_destroy(struct scst_vdisk_dev *virt_dev)
{
	kfree(virt_dev->filename);
	kfree(virt_dev);
	return;
}

#ifndef CONFIG_SCST_PROC

static int vdev_parse_add_dev_params(struct scst_vdisk_dev *virt_dev,
	char *params, const char *const allowed_params[])
{
	int res = 0;
	unsigned long val;
	char *param, *p, *pp;

	TRACE_ENTRY();

	while (1) {
		param = scst_get_next_token_str(&params);
		if (param == NULL)
			break;

		p = scst_get_next_lexem(&param);
		if (*p == '\0') {
			PRINT_ERROR("Syntax error at %s (device %s)",
				param, virt_dev->name);
			res = -EINVAL;
			goto out;
		}

		if (allowed_params != NULL) {
			const char *const *a = allowed_params;
			bool allowed = false;

			while (*a != NULL) {
				if (!strcasecmp(*a, p)) {
					allowed = true;
					break;
				}
				a++;
			}

			if (!allowed) {
				PRINT_ERROR("Unknown parameter %s (device %s)", p,
					virt_dev->name);
				res = -EINVAL;
				goto out;
			}
		}

		pp = scst_get_next_lexem(&param);
		if (*pp == '\0') {
			PRINT_ERROR("Parameter %s value missed for device %s",
				p, virt_dev->name);
			res = -EINVAL;
			goto out;
		}

		if (scst_get_next_lexem(&param)[0] != '\0') {
			PRINT_ERROR("Too many parameter's %s values (device %s)",
				p, virt_dev->name);
			res = -EINVAL;
			goto out;
		}

		if (!strcasecmp("filename", p)) {
			if (*pp != '/') {
				PRINT_ERROR("Filename %s must be global "
					"(device %s)", pp, virt_dev->name);
				res = -EINVAL;
				goto out;
			}

			virt_dev->filename = kstrdup(pp, GFP_KERNEL);
			if (virt_dev->filename == NULL) {
				PRINT_ERROR("Unable to duplicate file name %s "
					"(device %s)", pp, virt_dev->name);
				res = -ENOMEM;
				goto out;
			}
			continue;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		res = kstrtoul(pp, 0, &val);
#else
		res = strict_strtoul(pp, 0, &val);
#endif
		if (res != 0) {
			PRINT_ERROR("strtoul() for %s failed: %d (device %s)",
				    pp, res, virt_dev->name);
			goto out;
		}

		if (!strcasecmp("write_through", p)) {
			virt_dev->wt_flag = val;
			TRACE_DBG("WRITE THROUGH %d", virt_dev->wt_flag);
		} else if (!strcasecmp("nv_cache", p)) {
			virt_dev->nv_cache = val;
			TRACE_DBG("NON-VOLATILE CACHE %d", virt_dev->nv_cache);
		} else if (!strcasecmp("o_direct", p)) {
#if 0
			virt_dev->o_direct_flag = val;
			TRACE_DBG("O_DIRECT %d", virt_dev->o_direct_flag);
#else
			PRINT_INFO("O_DIRECT flag doesn't currently"
				" work, ignoring it, use fileio_tgt "
				"in O_DIRECT mode instead (device %s)", virt_dev->name);
#endif
		} else if (!strcasecmp("read_only", p)) {
			virt_dev->rd_only = val;
			TRACE_DBG("READ ONLY %d", virt_dev->rd_only);
		} else if (!strcasecmp("dummy", p)) {
			if (val > 1) {
				res = -EINVAL;
				goto out;
			}
			virt_dev->dummy = val;
			TRACE_DBG("DUMMY %d", virt_dev->dummy);
		} else if (!strcasecmp("removable", p)) {
			virt_dev->removable = val;
			TRACE_DBG("REMOVABLE %d", virt_dev->removable);
		} else if (!strcasecmp("rotational", p)) {
			virt_dev->rotational = val;
			TRACE_DBG("ROTATIONAL %d", virt_dev->rotational);
		} else if (!strcasecmp("thin_provisioned", p)) {
			virt_dev->thin_provisioned = val;
			virt_dev->thin_provisioned_manually_set = 1;
			TRACE_DBG("THIN PROVISIONED %d",
				virt_dev->thin_provisioned);
		} else if (!strcasecmp("zero_copy", p)) {
			virt_dev->zero_copy = !!val;
		} else if (!strcasecmp("blocksize", p)) {
			virt_dev->blk_shift = scst_calc_block_shift(val);
			if (virt_dev->blk_shift < 9) {
				res = -EINVAL;
				goto out;
			}
			TRACE_DBG("block size %ld, block shift %d",
				val, virt_dev->blk_shift);
		} else {
			PRINT_ERROR("Unknown parameter %s (device %s)", p,
				virt_dev->name);
			res = -EINVAL;
			goto out;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static int vdev_fileio_add_device(const char *device_name, char *params)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = vdev_create(&vdisk_file_devtype, device_name, &virt_dev);
	if (res != 0)
		goto out;

	virt_dev->command_set_version = 0x04C0; /* SBC-3 */

	virt_dev->wt_flag = DEF_WRITE_THROUGH;
	virt_dev->nv_cache = DEF_NV_CACHE;
	virt_dev->o_direct_flag = DEF_O_DIRECT;

	res = vdev_parse_add_dev_params(virt_dev, params, NULL);
	if (res != 0)
		goto out_destroy;

	if (virt_dev->rd_only && (virt_dev->wt_flag || virt_dev->nv_cache)) {
		PRINT_ERROR("Write options on read only device %s",
			virt_dev->name);
		res = -EINVAL;
		goto out_destroy;
	}

	if (virt_dev->filename == NULL) {
		PRINT_ERROR("File name required (device %s)", virt_dev->name);
		res = -EINVAL;
		goto out_destroy;
	}

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	vdisk_report_registering(virt_dev);

	virt_dev->virt_id = scst_register_virtual_device(virt_dev->vdev_devt,
					virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_del;
	}

	TRACE_DBG("Registered virt_dev %s with id %d", virt_dev->name,
		virt_dev->virt_id);

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	list_del(&virt_dev->vdev_list_entry);

out_destroy:
	vdev_destroy(virt_dev);
	goto out;
}

/* scst_vdisk_mutex supposed to be held */
static int vdev_blockio_add_device(const char *device_name, char *params)
{
	int res = 0;
	const char *const allowed_params[] = { "filename", "read_only", "write_through",
					 "removable", "blocksize", "nv_cache",
					 "rotational", "thin_provisioned", NULL };
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = vdev_create(&vdisk_blk_devtype, device_name, &virt_dev);
	if (res != 0)
		goto out;

	virt_dev->command_set_version = 0x04C0; /* SBC-3 */

	virt_dev->blockio = 1;
	virt_dev->wt_flag = DEF_WRITE_THROUGH;

	res = vdev_parse_add_dev_params(virt_dev, params, allowed_params);
	if (res != 0)
		goto out_destroy;

	if (virt_dev->filename == NULL) {
		PRINT_ERROR("File name required (device %s)", virt_dev->name);
		res = -EINVAL;
		goto out_destroy;
	}

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	vdisk_report_registering(virt_dev);

	virt_dev->virt_id = scst_register_virtual_device(virt_dev->vdev_devt,
					virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_del;
	}

	TRACE_DBG("Registered virt_dev %s with id %d", virt_dev->name,
		virt_dev->virt_id);

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	list_del(&virt_dev->vdev_list_entry);

out_destroy:
	vdev_destroy(virt_dev);
	goto out;
}

/* scst_vdisk_mutex supposed to be held */
static int vdev_nullio_add_device(const char *device_name, char *params)
{
	int res = 0;
	static const char *const allowed_params[] = {
		"read_only", "dummy", "removable", "blocksize", "rotational",
		NULL
	};
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = vdev_create(&vdisk_null_devtype, device_name, &virt_dev);
	if (res != 0)
		goto out;

	virt_dev->command_set_version = 0x04C0; /* SBC-3 */

	virt_dev->nullio = 1;

	res = vdev_parse_add_dev_params(virt_dev, params, allowed_params);
	if (res != 0)
		goto out_destroy;

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	vdisk_report_registering(virt_dev);

	virt_dev->virt_id = scst_register_virtual_device(virt_dev->vdev_devt,
					virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_del;
	}

	TRACE_DBG("Registered virt_dev %s with id %d", virt_dev->name,
		virt_dev->virt_id);

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	list_del(&virt_dev->vdev_list_entry);

out_destroy:
	vdev_destroy(virt_dev);
	goto out;
}

static ssize_t vdisk_add_fileio_device(const char *device_name, char *params)
{
	int res;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out;

	res = vdev_fileio_add_device(device_name, params);

	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdisk_add_blockio_device(const char *device_name, char *params)
{
	int res;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out;

	res = vdev_blockio_add_device(device_name, params);

	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

}

static ssize_t vdisk_add_nullio_device(const char *device_name, char *params)
{
	int res;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res)
		goto out;

	res = vdev_nullio_add_device(device_name, params);

	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

}

#endif /* CONFIG_SCST_PROC */

/* scst_vdisk_mutex supposed to be held */
static void vdev_del_device(struct scst_vdisk_dev *virt_dev)
{
	TRACE_ENTRY();

	scst_unregister_virtual_device(virt_dev->virt_id);

	list_del(&virt_dev->vdev_list_entry);

	PRINT_INFO("Virtual device %s unregistered", virt_dev->name);
	TRACE_DBG("virt_id %d unregistered", virt_dev->virt_id);

	vdev_destroy(virt_dev);

	return;
}

#ifndef CONFIG_SCST_PROC

static ssize_t vdisk_del_device(const char *device_name)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out;

	virt_dev = vdev_find(device_name);
	if (virt_dev == NULL) {
		PRINT_ERROR("Device %s not found", device_name);
		res = -EINVAL;
		goto out_unlock;
	}

	vdev_del_device(virt_dev);

out_unlock:
	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static ssize_t __vcdrom_add_device(const char *device_name, char *params)
{
	int res = 0;
	const char *allowed_params[] = { NULL }; /* no params */
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = vdev_create(&vcdrom_devtype, device_name, &virt_dev);
	if (res != 0)
		goto out;

#if 0  /*
	* Our implementation is pretty minimalistic and doesn't support all
	* mandatory commands, so it's better to not claim any standard
	* confirmance.
	*/
	virt_dev->command_set_version = 0x02A0; /* MMC-3 */
#endif

	virt_dev->rd_only = 1;
	virt_dev->removable = 1;
	virt_dev->cdrom_empty = 1;

	virt_dev->blk_shift = DEF_CDROM_BLOCK_SHIFT;

	res = vdev_parse_add_dev_params(virt_dev, params, allowed_params);
	if (res != 0)
		goto out_destroy;

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	vdisk_report_registering(virt_dev);

	virt_dev->virt_id = scst_register_virtual_device(virt_dev->vdev_devt,
					virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_del;
	}

	TRACE_DBG("Registered virt_dev %s with id %d", virt_dev->name,
		virt_dev->virt_id);

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	list_del(&virt_dev->vdev_list_entry);

out_destroy:
	vdev_destroy(virt_dev);
	goto out;
}

static ssize_t vcdrom_add_device(const char *device_name, char *params)
{
	int res;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out;

	res = __vcdrom_add_device(device_name, params);

	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

}

static ssize_t vcdrom_del_device(const char *device_name)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out;

	virt_dev = vdev_find(device_name);
	if (virt_dev == NULL) {
		PRINT_ERROR("Device %s not found", device_name);
		res = -EINVAL;
		goto out_unlock;
	}

	vdev_del_device(virt_dev);

out_unlock:
	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#endif /* CONFIG_SCST_PROC */

static int vcdrom_change(struct scst_vdisk_dev *virt_dev,
	char *buffer)
{
	loff_t err;
	char *old_fn, *p, *pp;
	bool old_empty;
	struct file *old_fd;
	const char *filename = NULL;
	int length = strlen(buffer);
	int res = 0;

	TRACE_ENTRY();

	p = buffer;

	while (isspace(*p) && *p != '\0')
		p++;
	filename = p;
	p = &buffer[length-1];
	pp = &buffer[length];
	while (isspace(*p) && (*p != '\0')) {
		pp = p;
		p--;
	}
	*pp = '\0';

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	/* To sync with detach*() functions */
	mutex_lock(&scst_mutex);

	old_empty = virt_dev->cdrom_empty;
	old_fd = virt_dev->fd;

	if (*filename == '\0') {
		virt_dev->cdrom_empty = 1;
		TRACE_DBG("%s", "No media");
	} else if (*filename != '/') {
		PRINT_ERROR("File path \"%s\" is not absolute", filename);
		res = -EINVAL;
		goto out_e_unlock;
	} else
		virt_dev->cdrom_empty = 0;

	old_fn = virt_dev->filename;

	if (!virt_dev->cdrom_empty) {
		char *fn = kstrdup(filename, GFP_KERNEL);
		if (fn == NULL) {
			PRINT_ERROR("%s", "Allocation of filename failed");
			res = -ENOMEM;
			goto out_e_unlock;
		}

		virt_dev->filename = fn;

		res = vdisk_get_file_size(virt_dev->filename,
				virt_dev->blockio, &err);
		if (res != 0)
			goto out_free_fn;
		if (virt_dev->tgt_dev_cnt > 0) {
			res = vdisk_open_fd(virt_dev, true);
			if (res != 0)
				goto out_free_fn;
			sBUG_ON(!virt_dev->fd);
		}
	} else {
		err = 0;
		virt_dev->filename = NULL;
		virt_dev->fd = NULL;
	}

	if (virt_dev->prevent_allow_medium_removal) {
		PRINT_ERROR("Prevent medium removal for "
			"virtual device with name %s", virt_dev->name);
		res = -EBUSY;
		goto out_free_fn;
	}

	virt_dev->file_size = err;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->dev->block_shift;
	if (!virt_dev->cdrom_empty)
		virt_dev->media_changed = 1;

	mutex_unlock(&scst_mutex);

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO("Changed SCSI target virtual cdrom %s "
			"(file=\"%s\", fs=%lldMB, bs=%d, nblocks=%lld,"
			" cyln=%lld%s)", virt_dev->name,
			vdev_get_filename(virt_dev),
			virt_dev->file_size >> 20, virt_dev->dev->block_size,
			(long long unsigned int)virt_dev->nblocks,
			(long long unsigned int)virt_dev->nblocks/64/32,
			virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
							"than 1" : "");
	} else {
		PRINT_INFO("Removed media from SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	if (old_fd)
		filp_close(old_fd, NULL);
	kfree(old_fn);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_fn:
	virt_dev->fd = old_fd;
	kfree(virt_dev->filename);
	virt_dev->filename = old_fn;

out_e_unlock:
	virt_dev->cdrom_empty = old_empty;

	mutex_unlock(&scst_mutex);
	goto out_resume;
}

#ifndef CONFIG_SCST_PROC

static int vcdrom_sysfs_process_filename_store(struct scst_sysfs_work_item *work)
{
	int res;
	struct scst_device *dev = work->dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	/* It's safe, since we taken dev_kobj and dh_priv NULLed in attach() */
	virt_dev = dev->dh_priv;

	res = vcdrom_change(virt_dev, work->buf);

	kobject_put(&dev->dev_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vcdrom_sysfs_filename_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	char *i_buf;
	struct scst_sysfs_work_item *work;
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	i_buf = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (i_buf == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer with size %zd",
			count+1);
		res = -ENOMEM;
		goto out;
	}

	res = scst_alloc_sysfs_work(vcdrom_sysfs_process_filename_store,
					false, &work);
	if (res != 0)
		goto out_free;

	work->buf = i_buf;
	work->dev = dev;

	SCST_SET_DEP_MAP(work, &scst_dev_dep_map);
	kobject_get(&dev->dev_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(i_buf);
	goto out;
}

static ssize_t vdev_sysfs_size_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%lld\n", virt_dev->file_size / 1024 / 1024);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_blocksize_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	pos = sprintf(buf, "%d\n%s", dev->block_size,
		(dev->block_size == (1 << DEF_DISK_BLOCK_SHIFT)) ? "" :
			SCST_SYSFS_KEY_MARK "\n");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_rd_only_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n%s", virt_dev->rd_only ? 1 : 0,
		(virt_dev->rd_only == DEF_RD_ONLY) ? "" :
			SCST_SYSFS_KEY_MARK "\n");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_wt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n%s", virt_dev->wt_flag ? 1 : 0,
		(virt_dev->wt_flag == DEF_WRITE_THROUGH) ? "" :
			SCST_SYSFS_KEY_MARK "\n");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_tp_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n%s", virt_dev->thin_provisioned ? 1 : 0,
		      virt_dev->thin_provisioned_manually_set &&
		      (virt_dev->thin_provisioned !=
		       virt_dev->dev_thin_provisioned) ?
		      SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_nv_cache_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n%s", virt_dev->nv_cache ? 1 : 0,
		(virt_dev->nv_cache == DEF_NV_CACHE) ? "" :
			SCST_SYSFS_KEY_MARK "\n");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_o_direct_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n%s", virt_dev->o_direct_flag ? 1 : 0,
		(virt_dev->o_direct_flag == DEF_O_DIRECT) ? "" :
			SCST_SYSFS_KEY_MARK "\n");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_sysfs_dummy_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	return sprintf(buf, "%d\n%s", virt_dev->dummy,
		 virt_dev->dummy != DEF_DUMMY ? SCST_SYSFS_KEY_MARK "\n" : "");
}

static ssize_t vdisk_sysfs_removable_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->removable ? 1 : 0);

	if ((virt_dev->dev->type != TYPE_ROM) &&
	    (virt_dev->removable != DEF_REMOVABLE))
		pos += sprintf(&buf[pos], "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_rotational_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->rotational ? 1 : 0);

	if (virt_dev->rotational != DEF_ROTATIONAL)
		pos += sprintf(&buf[pos], "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(pos);
	return pos;
}

static int vdev_sysfs_process_get_filename(struct scst_sysfs_work_item *work)
{
	int res = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = work->dev;

	/*
	 * Since we have a get() on dev->dev_kobj, we can not simply mutex_lock
	 * scst_vdisk_mutex, because otherwise we can fall in a deadlock with
	 * vdisk_del_device(), which is waiting for the last ref to dev_kobj
	 * under scst_vdisk_mutex.
	 */
	while (!mutex_trylock(&scst_vdisk_mutex)) {
		if (dev->dev_unregistering) {
			TRACE_MGMT_DBG("Skipping being unregistered dev %s",
				dev->virt_name);
			res = -ENOENT;
			goto out_put;
		}
		if (signal_pending(current)) {
			res = -EINTR;
			goto out_put;
		}
		msleep(100);
		/*
		 * We need to reread dev_unregistering from memory, hence
		 * prevent compiler from putting it in a register. Generally,
		 * it shouldn't happen, because the compiler isn't allowed to do
		 * such a transformation if any functions that can cause side
		 * effects are called between successive accesses, but let's be
		 * on the safe side. We can't cast dev_unregistering to
		 * volatile, because it has no effect we need, and can't cast
		 * it to *(volatile bool*)&, because it isn't possible to get
		 * address of a bit field.
		 */
		barrier();
	}

	virt_dev = dev->dh_priv;

	if (virt_dev == NULL)
		goto out_unlock;

	if (virt_dev->filename != NULL)
		work->res_buf = kasprintf(GFP_KERNEL, "%s\n%s\n",
			vdev_get_filename(virt_dev), SCST_SYSFS_KEY_MARK);
	else
		work->res_buf = kasprintf(GFP_KERNEL, "%s\n",
					vdev_get_filename(virt_dev));

out_unlock:
	mutex_unlock(&scst_vdisk_mutex);

out_put:
	kobject_put(&dev->dev_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_filename_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int res = 0;
	struct scst_device *dev;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = scst_alloc_sysfs_work(vdev_sysfs_process_get_filename,
					true, &work);
	if (res != 0)
		goto out;

	work->dev = dev;

	SCST_SET_DEP_MAP(work, &scst_dev_dep_map);
	kobject_get(&dev->dev_kobj);

	scst_sysfs_work_get(work);

	res = scst_sysfs_queue_wait_work(work);
	if (res != 0)
		goto out_put;

	res = snprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%s\n", work->res_buf);

out_put:
	scst_sysfs_work_put(work);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_sysfs_process_resync_size_store(
	struct scst_sysfs_work_item *work)
{
	int res;
	struct scst_device *dev = work->dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	/* It's safe, since we taken dev_kobj and dh_priv NULLed in attach() */
	virt_dev = dev->dh_priv;

	res = vdisk_resync_size(virt_dev);

	kobject_put(&dev->dev_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdisk_sysfs_resync_size_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = scst_alloc_sysfs_work(vdisk_sysfs_process_resync_size_store,
					false, &work);
	if (res != 0)
		goto out;

	work->dev = dev;

	SCST_SET_DEP_MAP(work, &scst_dev_dep_map);
	kobject_get(&dev->dev_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_t10_dev_id_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res, i;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	write_lock(&vdisk_serial_rwlock);

	if ((count > sizeof(virt_dev->t10_dev_id)) ||
	    ((count == sizeof(virt_dev->t10_dev_id)) &&
	     (buf[count-1] != '\n'))) {
		PRINT_ERROR("T10 device id is too long (max %zd "
			"characters)", sizeof(virt_dev->t10_dev_id)-1);
		res = -EINVAL;
		goto out_unlock;
	}

	memset(virt_dev->t10_dev_id, 0, sizeof(virt_dev->t10_dev_id));
	memcpy(virt_dev->t10_dev_id, buf, count);

	i = 0;
	while (i < sizeof(virt_dev->t10_dev_id)) {
		if (virt_dev->t10_dev_id[i] == '\n') {
			virt_dev->t10_dev_id[i] = '\0';
			break;
		}
		i++;
	}

	virt_dev->t10_dev_id_set = 1;

	res = count;

	PRINT_INFO("T10 device id for device %s changed to %s", virt_dev->name,
		virt_dev->t10_dev_id);

out_unlock:
	write_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_t10_dev_id_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = sprintf(buf, "%s\n%s", virt_dev->t10_dev_id,
		virt_dev->t10_dev_id_set ? SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_sysfs_usn_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res, i;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	write_lock(&vdisk_serial_rwlock);

	if ((count > sizeof(virt_dev->usn)) ||
	    ((count == sizeof(virt_dev->usn)) &&
	     (buf[count-1] != '\n'))) {
		PRINT_ERROR("USN is too long (max %zd "
			"characters)", sizeof(virt_dev->usn)-1);
		res = -EINVAL;
		goto out_unlock;
	}

	memset(virt_dev->usn, 0, sizeof(virt_dev->usn));
	memcpy(virt_dev->usn, buf, count);

	i = 0;
	while (i < sizeof(virt_dev->usn)) {
		if (virt_dev->usn[i] == '\n') {
			virt_dev->usn[i] = '\0';
			break;
		}
		i++;
	}

	virt_dev->usn_set = 1;

	res = count;

	PRINT_INFO("USN for device %s changed to %s", virt_dev->name,
		virt_dev->usn);

out_unlock:
	write_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_usn_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = sprintf(buf, "%s\n%s", virt_dev->usn,
		virt_dev->usn_set ? SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_zero_copy_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n%s", virt_dev->zero_copy,
		      virt_dev->zero_copy ? SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(pos);
	return pos;
}

#else /* CONFIG_SCST_PROC */

/*
 * ProcFS
 */

/*
 * Called when a file in the /proc/VDISK_NAME/VDISK_NAME is read
 */
static int vdisk_read_proc(struct seq_file *seq, struct scst_dev_type *dev_type)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out;

	seq_printf(seq, "%-17s %-11s %-11s %-15s %-45s %-16s\n",
		"Name", "Size(MB)", "Block size", "Options", "File name",
		"T10 device id");

	list_for_each_entry(virt_dev, &vdev_list, vdev_list_entry) {
		int c;

		sBUG_ON(!virt_dev->dev);

		if (virt_dev->dev->type != TYPE_DISK)
			continue;
		seq_printf(seq, "%-17s %-11d %-12d", virt_dev->name,
			(uint32_t)(virt_dev->file_size >> 20),
			1 << virt_dev->blk_shift);
		c = 0;
		if (virt_dev->wt_flag) {
			seq_printf(seq, "WT ");
			c += 3;
		}
		if (virt_dev->nv_cache) {
			seq_printf(seq, "NV ");
			c += 3;
		}
		if (virt_dev->dev->dev_rd_only) {
			seq_printf(seq, "RO ");
			c += 3;
		}
		if (virt_dev->o_direct_flag) {
			seq_printf(seq, "DR ");
			c += 3;
		}
		if (virt_dev->nullio) {
			seq_printf(seq, "NIO ");
			c += 4;
		}
		if (virt_dev->blockio) {
			seq_printf(seq, "BIO ");
			c += 4;
		}
		if (virt_dev->removable) {
			seq_printf(seq, "RM ");
			c += 3;
		}
		while (c < 16) {
			seq_printf(seq, " ");
			c++;
		}
		read_lock(&vdisk_serial_rwlock);
		seq_printf(seq, "%-45s %-16s\n", vdev_get_filename(virt_dev),
			virt_dev->t10_dev_id);
		read_unlock(&vdisk_serial_rwlock);
	}
	mutex_unlock(&scst_vdisk_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Called when a file in the /proc/VDISK_NAME/VDISK_NAME is written
 */
static int vdisk_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type)
{
	int res = 0, action;
	char *p, *name, *filename, *i_buf, *t10_dev_id;
	struct scst_vdisk_dev *virt_dev;
	int block_shift = DEF_DISK_BLOCK_SHIFT;
	uint32_t block_size = 1 << block_shift;
	size_t slen;

	TRACE_ENTRY();

	if ((length == 0) || (buffer == NULL) || (buffer[0] == '\0'))
		goto out;

	i_buf = kasprintf(GFP_KERNEL, "%.*s", (int)length, buffer);
	if (i_buf == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer with size %d",
			length+1);
		res = -ENOMEM;
		goto out;
	}

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out_free;

	p = i_buf;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncmp("close ", p, 6)) {
		p += 6;
		action = 0;
	} else if (!strncmp("open ", p, 5)) {
		p += 5;
		action = 1;
	} else if (!strncmp("resync_size ", p, 12)) {
		p += 12;
		action = 2;
	} else if (!strncmp("set_t10_dev_id ", p, 15)) {
		p += 15;
		action = 3;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_up;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	name = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*name == '\0') {
		PRINT_ERROR("%s", "Name required");
		res = -EINVAL;
		goto out_up;
	} else if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR("Name is too long (max %zd "
			"characters)", sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_up;
	}

	if (action == 1) {
		/* open */
		while (isspace(*p) && *p != '\0')
			p++;
		filename = p;
		while (!isspace(*p) && *p != '\0')
			p++;
		*p++ = '\0';
		if (*filename == '\0') {
			PRINT_ERROR("%s", "File name required");
			res = -EINVAL;
			goto out_up;
		}

		res = vdev_create(dev_type, name, &virt_dev);
		if (res != 0)
			goto out_up;

		virt_dev->wt_flag = DEF_WRITE_THROUGH;
		virt_dev->nv_cache = DEF_NV_CACHE;
		virt_dev->o_direct_flag = DEF_O_DIRECT;

		while (isspace(*p) && *p != '\0')
			p++;

		if (isdigit(*p)) {
			char *pp;
			block_size = simple_strtoul(p, &pp, 0);
			p = pp;
			if ((*p != '\0') && !isspace(*p)) {
				PRINT_ERROR("Parse error: \"%s\"", p);
				res = -EINVAL;
				goto out_free_vdev;
			}
			while (isspace(*p) && *p != '\0')
				p++;

			block_shift = scst_calc_block_shift(block_size);
			if (block_shift < 9) {
				res = -EINVAL;
				goto out_free_vdev;
			}
		}
		virt_dev->blk_shift = block_shift;

		while (*p != '\0') {
			if (!strncmp("WRITE_THROUGH", p, 13)) {
				p += 13;
				virt_dev->wt_flag = 1;
				TRACE_DBG("%s", "WRITE_THROUGH");
			} else if (!strncmp("NV_CACHE", p, 8)) {
				p += 8;
				virt_dev->nv_cache = 1;
				TRACE_DBG("%s", "NON-VOLATILE CACHE");
			} else if (!strncmp("READ_ONLY", p, 9)) {
				p += 9;
				virt_dev->rd_only = 1;
				TRACE_DBG("%s", "READ_ONLY");
			} else if (!strncmp("O_DIRECT", p, 8)) {
				p += 8;
#if 0

				virt_dev->o_direct_flag = 1;
				TRACE_DBG("%s", "O_DIRECT");
#else
				PRINT_INFO("%s flag doesn't currently"
					" work, ignoring it, use fileio_tgt "
					"in O_DIRECT mode instead", "O_DIRECT");
#endif
			} else if (!strncmp("NULLIO", p, 6)) {
				p += 6;
				virt_dev->nullio = 1;
				/* Bad hack for anyway going out procfs */
				virt_dev->vdev_devt = &vdisk_null_devtype;
				TRACE_DBG("%s", "NULLIO");
			} else if (!strncmp("BLOCKIO", p, 7)) {
				p += 7;
				virt_dev->blockio = 1;
				/* Bad hack for anyway going out procfs */
				virt_dev->vdev_devt = &vdisk_blk_devtype;
				TRACE_DBG("%s", "BLOCKIO");
			} else if (!strncmp("REMOVABLE", p, 9)) {
				p += 9;
				virt_dev->removable = 1;
				TRACE_DBG("%s", "REMOVABLE");
			} else {
				PRINT_ERROR("Unknown flag \"%s\"", p);
				res = -EINVAL;
				goto out_free_vdev;
			}
			while (isspace(*p) && *p != '\0')
				p++;
		}

		if (!virt_dev->nullio && (*filename != '/')) {
			PRINT_ERROR("File path \"%s\" is not "
				"absolute", filename);
			res = -EINVAL;
			goto out_up;
		}

		virt_dev->filename = kstrdup(filename, GFP_KERNEL);
		if (virt_dev->filename == NULL) {
			PRINT_ERROR("%s", "Allocation of filename failed");
			res = -ENOMEM;
			goto out_free_vdev;
		}

		list_add_tail(&virt_dev->vdev_list_entry,
				  &vdev_list);

		vdisk_report_registering(virt_dev);
		virt_dev->virt_id = scst_register_virtual_device(
			virt_dev->vdev_devt, virt_dev->name);
		if (virt_dev->virt_id < 0) {
			res = virt_dev->virt_id;
			goto out_free_vpath;
		}
		TRACE_DBG("Added virt_dev (name %s, file name %s, "
			"id %d, block size %d) to "
			"vdev_list", virt_dev->name,
			vdev_get_filename(virt_dev), virt_dev->virt_id,
			1 << virt_dev->blk_shift);
	} else if (action == 0) {	/* close */
		virt_dev = vdev_find(name);
		if (virt_dev == NULL) {
			PRINT_ERROR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}
		vdev_del_device(virt_dev);
	} else if (action == 2) {	/* resync_size */
		virt_dev = vdev_find(name);
		if (virt_dev == NULL) {
			PRINT_ERROR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}

		res = vdisk_resync_size(virt_dev);
		if (res != 0)
			goto out_up;
	} else if (action == 3) {	/* set T10 device id */
		virt_dev = vdev_find(name);
		if (virt_dev == NULL) {
			PRINT_ERROR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}

		while (isspace(*p) && *p != '\0')
			p++;
		t10_dev_id = p;
		while (*p != '\0')
			p++;
		*p++ = '\0';
		if (*t10_dev_id == '\0') {
			PRINT_ERROR("%s", "T10 device id required");
			res = -EINVAL;
			goto out_up;
		}

		write_lock(&vdisk_serial_rwlock);

		slen = (strlen(t10_dev_id) <= (sizeof(virt_dev->t10_dev_id)-1) ?
			strlen(t10_dev_id) :
			(sizeof(virt_dev->t10_dev_id)-1));

		memset(virt_dev->t10_dev_id, 0, sizeof(virt_dev->t10_dev_id));
		memcpy(virt_dev->t10_dev_id, t10_dev_id, slen);

		PRINT_INFO("T10 device id for device %s changed to %s",
			virt_dev->name, virt_dev->t10_dev_id);

		write_unlock(&vdisk_serial_rwlock);
	}
	res = length;

out_up:
	mutex_unlock(&scst_vdisk_mutex);

out_free:
	kfree(i_buf);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_vpath:
	list_del(&virt_dev->vdev_list_entry);
	kfree(virt_dev->filename);
	virt_dev->filename = NULL;

out_free_vdev:
	vdev_destroy(virt_dev);
	goto out_up;
}

/*
 * Called when a file in the /proc/VCDROM_NAME/VCDROM_NAME is read
 */
static int vcdrom_read_proc(struct seq_file *seq,
			    struct scst_dev_type *dev_type)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out;

	seq_printf(seq, "%-17s %-9s %s\n", "Name", "Size(MB)", "File name");

	list_for_each_entry(virt_dev, &vdev_list, vdev_list_entry) {
		if (virt_dev->dev->type != TYPE_ROM)
			continue;
		seq_printf(seq, "%-17s %-9d %s\n", virt_dev->name,
			(uint32_t)(virt_dev->file_size >> 20),
			vdev_get_filename(virt_dev));
	}

	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static int vcdrom_open(char *p, char *name)
{
	struct scst_vdisk_dev *virt_dev;
	char *filename;
	int res = 0;
	int cdrom_empty;

	while (isspace(*p) && *p != '\0')
		p++;
	filename = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*filename == '\0') {
		cdrom_empty = 1;
		TRACE_DBG("%s", "No media");
	} else if (*filename != '/') {
		PRINT_ERROR("File path \"%s\" is not absolute", filename);
		res = -EINVAL;
		goto out;
	} else
		cdrom_empty = 0;

	res = vdev_create(&vcdrom_devtype, name, &virt_dev);
	if (res != 0)
		goto out;

	virt_dev->cdrom_empty = cdrom_empty;
	virt_dev->rd_only = 1;
	virt_dev->removable = 1;

	if (!virt_dev->cdrom_empty) {
		virt_dev->filename = kstrdup(filename, GFP_KERNEL);
		if (virt_dev->filename == NULL) {
			PRINT_ERROR("%s", "Allocation of filename failed");
			res = -ENOMEM;
			goto out_free_vdev;
		}
	}

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	PRINT_INFO("Registering virtual CDROM %s", name);

	virt_dev->virt_id =
	    scst_register_virtual_device(&vcdrom_devtype,
					 virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_free_vpath;
	}
	TRACE_DBG("Added virt_dev (name %s filename %s id %d) "
		  "to vdev_list", virt_dev->name,
		  vdev_get_filename(virt_dev), virt_dev->virt_id);

out:
	return res;

out_free_vpath:
	list_del(&virt_dev->vdev_list_entry);
	kfree(virt_dev->filename);
	virt_dev->filename = NULL;

out_free_vdev:
	vdev_destroy(virt_dev);
	goto out;
}

/* scst_vdisk_mutex supposed to be held */
static int vcdrom_close(char *name)
{
	struct scst_vdisk_dev *virt_dev;
	int res = 0;

	virt_dev = vdev_find(name);
	if (virt_dev == NULL) {
		PRINT_ERROR("Virtual device with name "
		       "%s not found", name);
		res = -EINVAL;
		goto out;
	}

	vdev_del_device(virt_dev);

out:
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static int vcdrom_proc_change(char *p, const char *name)
{
	struct scst_vdisk_dev *virt_dev;
	int res;

	virt_dev = vdev_find(name);
	if (virt_dev == NULL) {
		PRINT_ERROR("Virtual cdrom with name "
		       "%s not found", name);
		res = -EINVAL;
		goto out;
	}

	res = vcdrom_change(virt_dev, p);

out:
	return res;
}

/*
 * Called when a file in the /proc/VCDROM_NAME/VCDROM_NAME is written
 */
static int vcdrom_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type)
{
	int res = 0, action;
	char *p, *name, *i_buf;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if ((length == 0) || (buffer == NULL) || (buffer[0] == '\0'))
		goto out;

	i_buf = kasprintf(GFP_KERNEL, "%.*s", (int)length, buffer);
	if (i_buf == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer with size %d",
			length+1);
		res = -ENOMEM;
		goto out;
	}

	res = mutex_lock_interruptible(&scst_vdisk_mutex);
	if (res != 0)
		goto out_free;

	p = i_buf;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncmp("close ", p, 6)) {
		p += 6;
		action = 0;
	} else if (!strncmp("change ", p, 7)) {
		p += 7;
		action = 1;
	} else if (!strncmp("open ", p, 5)) {
		p += 5;
		action = 2;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_up;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	name = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*name == '\0') {
		PRINT_ERROR("%s", "Name required");
		res = -EINVAL;
		goto out_up;
	} else if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR("Name is too long (max %zd "
			"characters)", sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_up;
	}

	if (action == 2) {
		/* open */
		res = vcdrom_open(p, name);
		if (res != 0)
			goto out_up;
	} else if (action == 1) {
		/* change */
		res = vcdrom_proc_change(p, name);
		if (res != 0)
			goto out_up;
	} else {
		/* close */
		res = vcdrom_close(name);
		if (res != 0)
			goto out_up;
	}
	res = length;

out_up:
	mutex_unlock(&scst_vdisk_mutex);

out_free:
	kfree(i_buf);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_help_info_show(struct seq_file *seq, void *v)
{
	char *s = (char *)seq->private;

	TRACE_ENTRY();

	seq_printf(seq, "%s", s);

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data vdisk_help_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = vdisk_help_info_show,
};

static int vdisk_proc_help_build(struct scst_dev_type *dev_type)
{
	int res = 0;
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	vdisk_help_proc_data.data = (dev_type->type == TYPE_DISK) ?
					vdisk_proc_help_string :
					vcdrom_proc_help_string;
	p = scst_create_proc_entry(root, VDISK_PROC_HELP,
				   &vdisk_help_proc_data);
	if (p == NULL) {
		PRINT_ERROR("Not enough memory to register dev "
		     "handler %s entry %s in /proc", "vdisk", VDISK_PROC_HELP);
		res = -ENOMEM;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_proc_help_destroy(struct scst_dev_type *dev_type)
{
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	if (root)
		remove_proc_entry(VDISK_PROC_HELP, root);

	TRACE_EXIT();
}

#endif /* CONFIG_SCST_PROC */

static int __init init_scst_vdisk(struct scst_dev_type *devtype)
{
	int res = 0;

	TRACE_ENTRY();

	devtype->module = THIS_MODULE;

	res = scst_register_virtual_dev_driver(devtype);
	if (res < 0)
		goto out;

#ifdef CONFIG_SCST_PROC
	if (!devtype->no_proc) {
		res = scst_dev_handler_build_std_proc(devtype);
		if (res < 0)
			goto out_unreg;

		res = vdisk_proc_help_build(devtype);
		if (res < 0)
			goto out_destroy_proc;
	}
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

#ifdef CONFIG_SCST_PROC
out_destroy_proc:
	if (!devtype->no_proc)
		scst_dev_handler_destroy_std_proc(devtype);

out_unreg:
	scst_unregister_virtual_dev_driver(devtype);
	goto out;
#endif
}

static void exit_scst_vdisk(struct scst_dev_type *devtype)
{
	TRACE_ENTRY();

	mutex_lock(&scst_vdisk_mutex);
	while (1) {
		struct scst_vdisk_dev *virt_dev;

		if (list_empty(&vdev_list))
			break;

		virt_dev = list_first_entry(&vdev_list, typeof(*virt_dev),
				vdev_list_entry);

		vdev_del_device(virt_dev);
	}
	mutex_unlock(&scst_vdisk_mutex);

#ifdef CONFIG_SCST_PROC
	if (!devtype->no_proc) {
		vdisk_proc_help_destroy(devtype);
		scst_dev_handler_destroy_std_proc(devtype);
	}
#endif

	scst_unregister_virtual_dev_driver(devtype);

	TRACE_EXIT();
	return;
}

static void init_ops(vdisk_op_fn *ops, int count)
{
	int i;
	for (i = 0; i < count; i++)
		if (ops[i] == NULL)
			ops[i] = vdisk_invalid_opcode;
	return;
}

static int __init init_scst_vdisk_driver(void)
{
	int res;

	init_ops(fileio_ops, ARRAY_SIZE(fileio_ops));
	init_ops(blockio_ops, ARRAY_SIZE(blockio_ops));
	init_ops(nullio_ops, ARRAY_SIZE(nullio_ops));

	vdisk_cmd_param_cachep = KMEM_CACHE(vdisk_cmd_params,
					SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (vdisk_cmd_param_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	blockio_work_cachep = KMEM_CACHE(scst_blockio_work,
				SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (blockio_work_cachep == NULL) {
		res = -ENOMEM;
		goto out_free_vdisk_cache;
	}

	if (num_threads < 1) {
		PRINT_ERROR("num_threads can not be less than 1, use "
			"default %d", DEF_NUM_THREADS);
		num_threads = DEF_NUM_THREADS;
	}

	vdisk_file_devtype.threads_num = num_threads;
	vcdrom_devtype.threads_num = num_threads;

	res = init_scst_vdisk(&vdisk_file_devtype);
	if (res != 0)
		goto out_free_slab;

	res = init_scst_vdisk(&vdisk_blk_devtype);
	if (res != 0)
		goto out_free_vdisk;

	res = init_scst_vdisk(&vdisk_null_devtype);
	if (res != 0)
		goto out_free_blk;

	res = init_scst_vdisk(&vcdrom_devtype);
	if (res != 0)
		goto out_free_null;

out:
	return res;

out_free_null:
	exit_scst_vdisk(&vdisk_null_devtype);

out_free_blk:
	exit_scst_vdisk(&vdisk_blk_devtype);

out_free_vdisk:
	exit_scst_vdisk(&vdisk_file_devtype);

out_free_slab:
	kmem_cache_destroy(blockio_work_cachep);

out_free_vdisk_cache:
	kmem_cache_destroy(vdisk_cmd_param_cachep);
	goto out;
}

static void __exit exit_scst_vdisk_driver(void)
{
	exit_scst_vdisk(&vdisk_null_devtype);
	exit_scst_vdisk(&vdisk_blk_devtype);
	exit_scst_vdisk(&vdisk_file_devtype);
	exit_scst_vdisk(&vcdrom_devtype);

	kmem_cache_destroy(blockio_work_cachep);
	kmem_cache_destroy(vdisk_cmd_param_cachep);
}

module_init(init_scst_vdisk_driver);
module_exit(exit_scst_vdisk_driver);

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI disk (type 0) and CDROM (type 5) dev handler for "
	"SCST using files on file systems or block devices");
MODULE_VERSION(SCST_VERSION_STRING);
