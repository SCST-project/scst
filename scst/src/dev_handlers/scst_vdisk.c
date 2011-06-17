/*
 *  scst_vdisk.c
 *
 *  Copyright (C) 2004 - 2011 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 *  Copyright (C) 2007 Ross Walker <rswwalker at hotmail dot com>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2011 SCST Ltd.
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
#ifndef INSIDE_KERNEL_TREE
#include <linux/version.h>
#endif
#include <asm/div64.h>
#include <asm/unaligned.h>
#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/crc32c.h>

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

#define VDISK_TRACE_TLB_HELP	", order"

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

#define	BYTE				8
#define	DEF_DISK_BLOCKSIZE_SHIFT	9
#define	DEF_DISK_BLOCKSIZE		(1 << DEF_DISK_BLOCKSIZE_SHIFT)
#define	DEF_CDROM_BLOCKSIZE_SHIFT	11
#define	DEF_CDROM_BLOCKSIZE		(1 << DEF_CDROM_BLOCKSIZE_SHIFT)
#define	DEF_SECTORS			56
#define	DEF_HEADS			255
#define LEN_MEM				(32 * 1024)
#define DEF_RD_ONLY			0
#define DEF_WRITE_THROUGH		0
#define DEF_NV_CACHE			0
#define DEF_O_DIRECT			0
#define DEF_REMOVABLE			0
#define DEF_THIN_PROVISIONED		0

#define VDISK_NULLIO_SIZE		(3LL*1024*1024*1024*1024/2)

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
	uint32_t block_size;
	uint64_t nblocks;
	int block_shift;
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
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int blockio:1;
	unsigned int cdrom_empty:1;
	unsigned int removable:1;
	unsigned int thin_provisioned:1;

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
};

struct scst_vdisk_thr {
	struct scst_thr_data_hdr hdr;
	struct file *fd;
	struct block_device *bdev;
	struct iovec *iv;
	int iv_count;
};

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
static int vdisk_parse(struct scst_cmd *);
static int vdisk_do_job(struct scst_cmd *cmd);
static int vcdrom_parse(struct scst_cmd *);
static int vcdrom_exec(struct scst_cmd *cmd);
static void vdisk_exec_read(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void vdisk_exec_write(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void blockio_exec_rw(struct scst_cmd *cmd, struct scst_vdisk_thr *thr,
	u64 lba_start, int write);
static int vdisk_blockio_flush(struct block_device *bdev, gfp_t gfp_mask,
	bool report_error);
static void vdisk_exec_verify(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void vdisk_exec_read_capacity(struct scst_cmd *cmd);
static void vdisk_exec_read_capacity16(struct scst_cmd *cmd);
static void vdisk_exec_report_tpgs(struct scst_cmd *cmd);
static void vdisk_exec_inquiry(struct scst_cmd *cmd);
static void vdisk_exec_request_sense(struct scst_cmd *cmd);
static void vdisk_exec_mode_sense(struct scst_cmd *cmd);
static void vdisk_exec_mode_select(struct scst_cmd *cmd);
static void vdisk_exec_log(struct scst_cmd *cmd);
static void vdisk_exec_read_toc(struct scst_cmd *cmd);
static void vdisk_exec_prevent_allow_medium_removal(struct scst_cmd *cmd);
static void vdisk_exec_unmap(struct scst_cmd *cmd, struct scst_vdisk_thr *thr);
static int vdisk_fsync(struct scst_vdisk_thr *thr, loff_t loff,
	loff_t len, struct scst_cmd *cmd, struct scst_device *dev);
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
static int vdisk_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev);
static uint64_t vdisk_gen_dev_id_num(const char *virt_dev_name);

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
static ssize_t vdisk_sysfs_nv_cache_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_o_direct_show(struct kobject *kobj,
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
static struct kobj_attribute vdisk_nv_cache_attr =
	__ATTR(nv_cache, S_IRUGO, vdisk_sysfs_nv_cache_show, NULL);
static struct kobj_attribute vdisk_o_direct_attr =
	__ATTR(o_direct, S_IRUGO, vdisk_sysfs_o_direct_show, NULL);
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

static struct kobj_attribute vcdrom_filename_attr =
	__ATTR(filename, S_IRUGO|S_IWUSR, vdev_sysfs_filename_show,
		vcdrom_sysfs_filename_store);

static const struct attribute *vdisk_fileio_attrs[] = {
	&vdev_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_wt_attr.attr,
	&vdisk_tp_attr.attr,
	&vdisk_nv_cache_attr.attr,
	&vdisk_o_direct_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_filename_attr.attr,
	&vdisk_resync_size_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_usn_attr.attr,
	NULL,
};

static const struct attribute *vdisk_blockio_attrs[] = {
	&vdev_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_nv_cache_attr.attr,
	&vdisk_removable_attr.attr,
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
	&vdisk_removable_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_usn_attr.attr,
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

static struct kmem_cache *vdisk_thr_cachep;

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
	.exec =			vdisk_do_job,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
#ifdef CONFIG_SCST_PROC
	.read_proc =		vdisk_read_proc,
	.write_proc =		vdisk_write_proc,
#else
	.add_device =		vdisk_add_fileio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_fileio_attrs,
	.add_device_parameters = "filename, blocksize, write_through, "
		"nv_cache, o_direct, read_only, removable, thin_provisioned",
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
#ifndef CONFIG_SCST_PROC
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
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
	.parse =		vdisk_parse,
	.exec =			vdisk_do_job,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
#ifndef CONFIG_SCST_PROC
	.add_device =		vdisk_add_blockio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_blockio_attrs,
	.add_device_parameters = "filename, blocksize, nv_cache, read_only, "
		"removable, thin_provisioned",
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
#ifndef CONFIG_SCST_PROC
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
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
	.parse =		vdisk_parse,
	.exec =			vdisk_do_job,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
#ifndef CONFIG_SCST_PROC
	.add_device =		vdisk_add_nullio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_nullio_attrs,
	.add_device_parameters = "blocksize, read_only, removable",
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
#ifndef CONFIG_SCST_PROC
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
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
	.exec =			vcdrom_exec,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
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
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
#endif
#endif
};

static struct scst_vdisk_thr nullio_thr_data;

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
static struct file *vdev_open_fd(const struct scst_vdisk_dev *virt_dev)
{
	int open_flags = 0;
	struct file *fd;

	TRACE_ENTRY();

	if (virt_dev->dev->rd_only)
		open_flags |= O_RDONLY;
	else
		open_flags |= O_RDWR;
	if (virt_dev->o_direct_flag)
		open_flags |= O_DIRECT;
	if (virt_dev->wt_flag && !virt_dev->nv_cache)
		open_flags |= O_SYNC;
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
		PRINT_ERROR("filp_open(%s) returned error %ld",
			virt_dev->filename, PTR_ERR(fd));
		goto out;
	}

	inode = fd->f_dentry->d_inode;

	if (!S_ISBLK(inode->i_mode)) {
		PRINT_ERROR("%s is NOT a block device", virt_dev->filename);
		goto out_close;
	}

	if (vdisk_blockio_flush(inode->i_bdev, GFP_KERNEL, false) != 0) {
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
	struct inode *inode;
	struct file *fd;
	bool supported = false;

	TRACE_ENTRY();

	if (virt_dev->rd_only || !virt_dev->thin_provisioned)
		goto out;

	fd = filp_open(virt_dev->filename, O_LARGEFILE, 0600);
	if (IS_ERR(fd)) {
		PRINT_ERROR("filp_open(%s) returned error %ld",
			virt_dev->filename, PTR_ERR(fd));
		goto out;
	}

	inode = fd->f_dentry->d_inode;

	if (virt_dev->blockio) {
		if (!S_ISBLK(inode->i_mode)) {
			PRINT_ERROR("%s is NOT a block device",
				virt_dev->filename);
			goto out_close;
		}
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 31)
		supported = blk_queue_discard(bdev_get_queue(inode->i_bdev));
#else
		supported = false;
#endif

	} else {
		/*
		 * truncate_range() was chosen rather as a sample. In future,
		 * when unmap of range of blocks in file become standard, we
		 * will just switch to the new call.
		 */
		supported = (inode->i_op->truncate_range != NULL);
	}

	if (!supported) {
		PRINT_WARNING("Device %s doesn't support thin "
			"provisioning, disabling it.",
			virt_dev->filename);
		virt_dev->thin_provisioned = 0;
	}

out_close:
	filp_close(fd, NULL);

out:
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

	*file_size = 0;

	fd = filp_open(filename, O_LARGEFILE | O_RDONLY, 0600);
	if (IS_ERR(fd)) {
		res = PTR_ERR(fd);
		PRINT_ERROR("filp_open(%s) returned error %d", filename, res);
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

static int vdisk_attach(struct scst_device *dev)
{
	int res = 0;
	loff_t err;
	struct scst_vdisk_dev *virt_dev = NULL, *vv;

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
	list_for_each_entry(vv, &vdev_list, vdev_list_entry) {
		if (strcmp(vv->name, dev->virt_name) == 0) {
			virt_dev = vv;
			break;
		}
	}

	if (virt_dev == NULL) {
		PRINT_ERROR("Device %s not found", dev->virt_name);
		res = -EINVAL;
		goto out;
	}

	virt_dev->dev = dev;

	dev->rd_only = virt_dev->rd_only;

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

	virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO("Attached SCSI target virtual %s %s "
		      "(file=\"%s\", fs=%lldMB, bs=%d, nblocks=%lld,"
		      " cyln=%lld%s)",
		      (dev->type == TYPE_DISK) ? "disk" : "cdrom",
		      virt_dev->name, vdev_get_filename(virt_dev),
		      virt_dev->file_size >> 20, virt_dev->block_size,
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

	TRACE_DBG("virt_id %d", dev->virt_id);

	PRINT_INFO("Detached virtual device %s (\"%s\")",
		      virt_dev->name, vdev_get_filename(virt_dev));

	/* virt_dev will be freed by the caller */
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static void vdisk_free_thr_data(struct scst_thr_data_hdr *d)
{
	struct scst_vdisk_thr *thr =
		container_of(d, struct scst_vdisk_thr, hdr);

	TRACE_ENTRY();

	if (thr->fd)
		filp_close(thr->fd, NULL);

	kfree(thr->iv);

	kmem_cache_free(vdisk_thr_cachep, thr);

	TRACE_EXIT();
	return;
}

static struct scst_vdisk_thr *vdisk_init_thr_data(
	struct scst_tgt_dev *tgt_dev, gfp_t gfp_mask)
{
	struct scst_vdisk_thr *res;
	struct scst_vdisk_dev *virt_dev = tgt_dev->dev->dh_priv;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

	res = kmem_cache_zalloc(vdisk_thr_cachep, gfp_mask);
	if (res == NULL) {
		PRINT_ERROR("Unable to allocate struct scst_vdisk_thr"
			    " (size %zd)", sizeof(*res));
		goto out;
	}

	if (!virt_dev->cdrom_empty) {
		res->fd = vdev_open_fd(virt_dev);
		if (IS_ERR(res->fd)) {
			PRINT_ERROR("filp_open(%s) returned an error %ld",
				virt_dev->filename, PTR_ERR(res->fd));
			goto out_free;
		}
		if (virt_dev->blockio)
			res->bdev = res->fd->f_dentry->d_inode->i_bdev;
		else
			res->bdev = NULL;
	} else
		res->fd = NULL;

	scst_add_thr_data(tgt_dev, &res->hdr, vdisk_free_thr_data);

out:
	TRACE_EXIT_HRES((unsigned long)res);
	return res;

out_free:
	kmem_cache_free(vdisk_thr_cachep, res);
	res = NULL;
	goto out;
}

static int vdisk_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
	int res = 0;

	TRACE_ENTRY();

	/* Nothing to do */

	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();

	scst_del_all_thr_data(tgt_dev);

	TRACE_EXIT();
	return;
}

static int vdisk_do_job(struct scst_cmd *cmd)
{
	int rc, res;
	uint64_t lba_start = 0;
	loff_t data_len = 0;
	uint8_t *cdb = cmd->cdb;
	int opcode = cdb[0];
	loff_t loff;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	struct scst_thr_data_hdr *d;
	struct scst_vdisk_thr *thr = NULL;
	int fua = 0;

	TRACE_ENTRY();

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

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (!virt_dev->nullio) {
		d = scst_find_thr_data(tgt_dev);
		if (unlikely(d == NULL)) {
			thr = vdisk_init_thr_data(tgt_dev,
				cmd->noio_mem_alloc ? GFP_NOIO : GFP_KERNEL);
			if (thr == NULL) {
				scst_set_busy(cmd);
				goto out_compl;
			}
			scst_thr_data_get(&thr->hdr);
		} else
			thr = container_of(d, struct scst_vdisk_thr, hdr);
	} else {
		thr = &nullio_thr_data;
		scst_thr_data_get(&thr->hdr);
	}

	switch (opcode) {
	case READ_6:
	case WRITE_6:
	case VERIFY_6:
		lba_start = (((cdb[1] & 0x1f) << (BYTE * 2)) +
			     (cdb[2] << (BYTE * 1)) +
			     (cdb[3] << (BYTE * 0)));
		data_len = cmd->bufflen;
		break;
	case READ_10:
	case READ_12:
	case WRITE_10:
	case WRITE_12:
	case VERIFY:
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case VERIFY_12:
		lba_start |= ((u64)cdb[2]) << 24;
		lba_start |= ((u64)cdb[3]) << 16;
		lba_start |= ((u64)cdb[4]) << 8;
		lba_start |= ((u64)cdb[5]);
		data_len = cmd->bufflen;
		break;
	case READ_16:
	case WRITE_16:
	case WRITE_VERIFY_16:
	case VERIFY_16:
		lba_start |= ((u64)cdb[2]) << 56;
		lba_start |= ((u64)cdb[3]) << 48;
		lba_start |= ((u64)cdb[4]) << 40;
		lba_start |= ((u64)cdb[5]) << 32;
		lba_start |= ((u64)cdb[6]) << 24;
		lba_start |= ((u64)cdb[7]) << 16;
		lba_start |= ((u64)cdb[8]) << 8;
		lba_start |= ((u64)cdb[9]);
		data_len = cmd->bufflen;
		break;
	case SYNCHRONIZE_CACHE:
		lba_start |= ((u64)cdb[2]) << 24;
		lba_start |= ((u64)cdb[3]) << 16;
		lba_start |= ((u64)cdb[4]) << 8;
		lba_start |= ((u64)cdb[5]);
		data_len = ((cdb[7] << (BYTE * 1)) + (cdb[8] << (BYTE * 0)))
				<< virt_dev->block_shift;
		if (data_len == 0)
			data_len = virt_dev->file_size -
				((loff_t)lba_start << virt_dev->block_shift);
		break;
	}

	loff = (loff_t)lba_start << virt_dev->block_shift;
	TRACE_DBG("cmd %p, lba_start %lld, loff %lld, data_len %lld", cmd,
		  (long long unsigned int)lba_start,
		  (long long unsigned int)loff,
		  (long long unsigned int)data_len);
	if (unlikely(loff < 0) || unlikely(data_len < 0) ||
	    unlikely((loff + data_len) > virt_dev->file_size)) {
		PRINT_INFO("Access beyond the end of the device "
			"(%lld of %lld, len %lld)",
			   (long long unsigned int)loff,
			   (long long unsigned int)virt_dev->file_size,
			   (long long unsigned int)data_len);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
					scst_sense_block_out_range_error));
		goto out_compl;
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

	switch (opcode) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		if (virt_dev->blockio) {
			blockio_exec_rw(cmd, thr, lba_start, 0);
			goto out_thr;
		} else
			vdisk_exec_read(cmd, thr, loff);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	{
		if (virt_dev->blockio) {
			blockio_exec_rw(cmd, thr, lba_start, 1);
			goto out_thr;
		} else
			vdisk_exec_write(cmd, thr, loff);
		/* O_SYNC flag is used for WT devices */
		if (fua)
			vdisk_fsync(thr, loff, data_len, cmd, dev);
		break;
	}
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
	{
		/* ToDo: BLOCKIO VERIFY */
		vdisk_exec_write(cmd, thr, loff);
		/* O_SYNC flag is used for WT devices */
		if (scsi_status_is_good(cmd->status))
			vdisk_exec_verify(cmd, thr, loff);
		break;
	}
	case SYNCHRONIZE_CACHE:
	{
		int immed = cdb[1] & 0x2;
		TRACE(TRACE_ORDER, "SYNCHRONIZE_CACHE: "
			"loff=%lld, data_len=%lld, immed=%d",
			(long long unsigned int)loff,
			(long long unsigned int)data_len, immed);
		if (immed) {
			scst_cmd_get(cmd); /* to protect dev */
			cmd->completed = 1;
			cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
				SCST_CONTEXT_SAME);
			vdisk_fsync(thr, loff, data_len, NULL, dev);
			/* ToDo: vdisk_fsync() error processing */
			scst_cmd_put(cmd);
			goto out_thr;
		} else {
			vdisk_fsync(thr, loff, data_len, cmd, dev);
			break;
		}
	}
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		vdisk_exec_verify(cmd, thr, loff);
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		vdisk_exec_mode_sense(cmd);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		vdisk_exec_mode_select(cmd);
		break;
	case LOG_SELECT:
	case LOG_SENSE:
		vdisk_exec_log(cmd);
		break;
	case ALLOW_MEDIUM_REMOVAL:
		vdisk_exec_prevent_allow_medium_removal(cmd);
		break;
	case READ_TOC:
		vdisk_exec_read_toc(cmd);
		break;
	case START_STOP:
		vdisk_fsync(thr, 0, virt_dev->file_size, cmd, dev);
		break;
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
	case TEST_UNIT_READY:
		break;
	case INQUIRY:
		vdisk_exec_inquiry(cmd);
		break;
	case REQUEST_SENSE:
		vdisk_exec_request_sense(cmd);
		break;
	case READ_CAPACITY:
		vdisk_exec_read_capacity(cmd);
		break;
	case SERVICE_ACTION_IN:
		if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
			vdisk_exec_read_capacity16(cmd);
			break;
		}
		goto out_invalid_opcode;
	case UNMAP:
		vdisk_exec_unmap(cmd, thr);
		break;
	case MAINTENANCE_IN:
		switch (cmd->cdb[1] & 0x1f) {
		case MI_REPORT_TARGET_PGS:
			vdisk_exec_report_tpgs(cmd);
			break;
		default:
			goto out_invalid_opcode;
		}
		break;
	case REPORT_LUNS:
	default:
		goto out_invalid_opcode;
	}

out_compl:
	cmd->completed = 1;

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

out_thr:
	if (likely(thr != NULL))
		scst_thr_data_put(&thr->hdr);

	res = SCST_EXEC_COMPLETED;

	TRACE_EXIT_RES(res);
	return res;

out_invalid_opcode:
	TRACE_DBG("Invalid opcode %d", opcode);
	scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	goto out_compl;
}

static int vdisk_get_block_shift(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	return virt_dev->block_shift;
}

static int vdisk_parse(struct scst_cmd *cmd)
{
	scst_sbc_generic_parse(cmd, vdisk_get_block_shift);
	return SCST_CMD_STATE_DEFAULT;
}

static int vcdrom_parse(struct scst_cmd *cmd)
{
	scst_cdrom_generic_parse(cmd, vdisk_get_block_shift);
	return SCST_CMD_STATE_DEFAULT;
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
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_not_ready));
		goto out_done;
	}

	if (virt_dev->media_changed && scst_is_ua_command(cmd)) {
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

	res = vdisk_do_job(cmd);

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

static void vdisk_exec_unmap(struct scst_cmd *cmd, struct scst_vdisk_thr *thr)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	ssize_t length = 0;
	struct file *fd = thr->fd;
	struct inode *inode;
	uint8_t *address;
	int offset, descriptor_len, total_len;

	TRACE_ENTRY();

	if (unlikely(!virt_dev->thin_provisioned)) {
		TRACE_DBG("%s", "Invalid opcode UNMAP");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out;
	}

	if (unlikely(cmd->cdb[1] & 1)) {
		/* ANCHOR not supported */
		TRACE_DBG("%s", "Invalid ANCHOR field");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	length = scst_get_buf_full(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length == 0)
			goto out_put;
		else if (length == -ENOMEM)
			scst_set_busy(cmd);
		else
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	inode = fd->f_dentry->d_inode;

	total_len = cmd->cdb[7] << 8 | cmd->cdb[8]; /* length */
	offset = 8;

	descriptor_len = address[2] << 8 | address[3];

	TRACE_DBG("total_len %d, descriptor_len %d", total_len, descriptor_len);

	if (descriptor_len == 0)
		goto out_put;

	if (unlikely((descriptor_len > (total_len - 8)) ||
		     ((descriptor_len % 16) != 0))) {
		PRINT_ERROR("Bad descriptor length: %d < %d - 8",
			descriptor_len, total_len);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out_put;
	}

	while ((offset - 8) < descriptor_len) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 27)
		int err;
#endif
		uint64_t start;
		uint32_t len;
		start = be64_to_cpu(get_unaligned((__be64 *)&address[offset]));
		offset += 8;
		len = be32_to_cpu(get_unaligned((__be32 *)&address[offset]));
		offset += 8;

		if ((start > virt_dev->nblocks) ||
		    ((start + len) > virt_dev->nblocks)) {
			PRINT_ERROR("Device %s: attempt to write beyond max "
				"size", virt_dev->name);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out_put;
		}

		TRACE_DBG("Unmapping lba %lld (blocks %d)",
			(unsigned long long)start, len);

		if (virt_dev->blockio) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 27)
			gfp_t gfp = cmd->noio_mem_alloc ? GFP_NOIO : GFP_KERNEL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 31)
			err = blkdev_issue_discard(inode->i_bdev, start, len,
					gfp);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)       \
      && !(LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 34) \
           && defined(CONFIG_SUSE_KERNEL))
			err = blkdev_issue_discard(inode->i_bdev, start, len,
					gfp, DISCARD_FL_WAIT);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
			err = blkdev_issue_discard(inode->i_bdev, start, len,
					gfp, BLKDEV_IFL_WAIT);
#else
			err = blkdev_issue_discard(inode->i_bdev, start, len,
						   gfp, 0);
#endif
			if (unlikely(err != 0)) {
				PRINT_ERROR("blkdev_issue_discard() for "
					"LBA %lld len %d failed with err %d",
					(unsigned long long)start, len, err);
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(scst_sense_write_error));
				goto out_put;
			}
#else
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_put;
#endif
		} else {
			/*
			 * We are guaranteed by thin_provisioned flag
			 * that truncate_range is not NULL.
			 */
			inode->i_op->truncate_range(inode,
				start, start + len);
		}
	}

out_put:
	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT();
	return;
}

static void vdev_blockio_get_unmap_params(struct scst_vdisk_dev *virt_dev,
	uint32_t *unmap_gran, uint32_t *unmap_alignment)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32) || (defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 6)
	struct file *fd;
	struct request_queue *q;
#endif

	TRACE_ENTRY();

	*unmap_gran = 1;
	*unmap_alignment = 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32) || (defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 6)
	fd = filp_open(virt_dev->filename, O_LARGEFILE, 0600);
	if (IS_ERR(fd)) {
		PRINT_ERROR("filp_open(%s) returned error %ld",
			virt_dev->filename, PTR_ERR(fd));
		goto out;
	}

	q = bdev_get_queue(fd->f_dentry->d_inode->i_bdev);
	if (q == NULL) {
		PRINT_ERROR("No queue for device %s", virt_dev->filename);
		goto out_close;
	}

	*unmap_gran = q->limits.discard_granularity;
	*unmap_alignment = q->limits.discard_alignment;

out_close:
	filp_close(fd, NULL);

out:
#endif
	TRACE_EXIT();
	return;
}

static void vdisk_exec_inquiry(struct scst_cmd *cmd)
{
	int32_t length, i, resp_len = 0;
	uint8_t *address;
	uint8_t *buf;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	uint16_t tg_id;

	TRACE_ENTRY();

	buf = kzalloc(INQ_BUF_SZ, GFP_KERNEL);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	length = scst_get_buf_full(cmd, &address);
	TRACE_DBG("length %d", length);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_full() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out_free;
	}

	if (cmd->cdb[1] & CMDDT) {
		TRACE_DBG("%s", "INQUIRY: CMDDT is unsupported");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	buf[0] = cmd->dev->type;      /* type dev */
	/* Vital Product */
	if (cmd->cdb[1] & EVPD) {
		if (0 == cmd->cdb[2]) {
			/* supported vital product data pages */
			buf[3] = 3;
			buf[4] = 0x0; /* this page */
			buf[5] = 0x80; /* unit serial number */
			buf[6] = 0x83; /* device identification */
			if (virt_dev->dev->type == TYPE_DISK) {
				buf[3] += 1;
				buf[7] = 0xB0; /* block limits */
				if (virt_dev->thin_provisioned) {
					buf[3] += 1;
					buf[8] = 0xB2; /* thin provisioning */
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

			put_unaligned(cpu_to_be16(cmd->tgt->rel_tgt_id),
				(__be16 *)&buf[num + 4 + 2]);

			buf[num + 3] = 4;
			num += buf[num + 3];

			num += 4;

			tg_id = scst_lookup_tg_id(cmd->dev, cmd->tgt);
			if (tg_id) {
				/*
				 * Target port group designator
				 */
				buf[num + 0] = 0x01; /* binary */
				/* Target port group id */
				buf[num + 1] = 0x10 | 0x05;

				put_unaligned(cpu_to_be16(tg_id),
					      (__be16 *)&buf[num + 4 + 2]);

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
			buf[2] = (resp_len >> 8) & 0xFF;
			buf[3] = resp_len & 0xFF;
			resp_len += 4;
		} else if ((0xB0 == cmd->cdb[2]) &&
			   (virt_dev->dev->type == TYPE_DISK)) {
			/* Block Limits */
			int max_transfer;
			buf[1] = 0xB0;
			buf[3] = 0x3C;
			/* Optimal transfer granuality is PAGE_SIZE */
			put_unaligned(cpu_to_be16(max_t(int,
					PAGE_SIZE/virt_dev->block_size, 1)),
				      (uint16_t *)&buf[6]);
			/* Max transfer len is min of sg limit and 8M */
			max_transfer = min_t(int,
					cmd->tgt_dev->max_sg_cnt << PAGE_SHIFT,
					8*1024*1024) / virt_dev->block_size;
			put_unaligned(cpu_to_be32(max_transfer),
					(uint32_t *)&buf[8]);
			/*
			 * Let's have optimal transfer len 512KB. Better to not
			 * set it at all, because we don't have such limit,
			 * but some initiators may not understand that (?).
			 * From other side, too big transfers  are not optimal,
			 * because SGV cache supports only <4M buffers.
			 */
			put_unaligned(cpu_to_be32(min_t(int,
					max_transfer,
					512*1024 / virt_dev->block_size)),
				      (uint32_t *)&buf[12]);
			if (virt_dev->thin_provisioned) {
				/* MAXIMUM UNMAP LBA COUNT is UNLIMITED */
				put_unaligned(__constant_cpu_to_be32(0xFFFFFFFF),
					      (uint32_t *)&buf[20]);
				/* MAXIMUM UNMAP BLOCK DESCRIPTOR COUNT is UNLIMITED */
				put_unaligned(__constant_cpu_to_be32(0xFFFFFFFF),
					      (uint32_t *)&buf[24]);
				if (virt_dev->blockio) {
					/* OPTIMAL UNMAP GRANULARITY AND ALIGNMENT*/
					uint32_t gran, align;
					vdev_blockio_get_unmap_params(virt_dev,
						&gran, &align);
					put_unaligned(cpu_to_be32(gran),
						(uint32_t *)&buf[28]);
					put_unaligned(cpu_to_be32(align),
						(uint32_t *)&buf[32]);
				} else {
					/* OPTIMAL UNMAP GRANULARITY is 1 */
					put_unaligned(__constant_cpu_to_be32(1),
						(uint32_t *)&buf[28]);
				}
			}
			resp_len = buf[3] + 4;
		} else if ((0xB2 == cmd->cdb[2]) &&
			   (virt_dev->dev->type == TYPE_DISK) &&
			   virt_dev->thin_provisioned) {
			/* Thin Provisioning */
			buf[1] = 0xB2;
			buf[3] = 2;
			buf[5] = 0x80;
			resp_len = buf[3] + 4;
		} else {
			TRACE_DBG("INQUIRY: Unsupported EVPD page %x",
				cmd->cdb[2]);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out_put;
		}
	} else {
		int len, num;

		if (cmd->cdb[2] != 0) {
			TRACE_DBG("INQUIRY: Unsupported page %x", cmd->cdb[2]);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out_put;
		}

		if (virt_dev->removable)
			buf[1] = 0x80;      /* removable */
		buf[2] = 5; /* Device complies to SPC-3 */
		buf[3] = 0x02;	/* Data in format specified in SPC */
		if (cmd->tgtt->fake_aca)
			buf[3] |= 0x20;
		buf[4] = 31;/* n - 4 = 35 - 4 = 31 for full 36 byte data */
		if (scst_impl_alua_configured(cmd->dev))
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

		/* SAM-3 T10/1561-D revision 14 */
		buf[58 + num] = 0x0;
		buf[58 + num + 1] = 0x76;
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

		/* SPC-3 T10/1416-D revision 23 */
		buf[58 + num] = 0x3;
		buf[58 + num + 1] = 0x12;
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

	sBUG_ON(resp_len >= INQ_BUF_SZ);

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
	return;
}

static void vdisk_exec_request_sense(struct scst_cmd *cmd)
{
	int32_t length, sl;
	uint8_t *address;
	uint8_t b[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	sl = scst_set_sense(b, sizeof(b), cmd->dev->d_sense,
		SCST_LOAD_SENSE(scst_sense_no_sense));

	length = scst_get_buf_full(cmd, &address);
	TRACE_DBG("length %d", length);
	if (length < 0) {
		PRINT_ERROR("scst_get_buf_full() failed: %d)", length);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	length = min(sl, length);
	memcpy(address, b, length);
	scst_set_resp_data_len(cmd, length);

	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT();
	return;
}

/*
 * <<Following mode pages info copied from ST318451LW with some corrections>>
 *
 * ToDo: revise them
 */
static int vdisk_err_recov_pg(unsigned char *p, int pcontrol,
			       struct scst_vdisk_dev *virt_dev)
{	/* Read-Write Error Recovery page for mode_sense */
	const unsigned char err_recov_pg[] = {0x1, 0xa, 0xc0, 11, 240, 0, 0, 0,
					      5, 0, 0xff, 0xff};

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
	p[10] = (DEF_SECTORS >> 8) & 0xff;
	p[11] = DEF_SECTORS & 0xff;
	p[12] = (virt_dev->block_size >> 8) & 0xff;
	p[13] = virt_dev->block_size & 0xff;
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(format_pg) - 2);
	return sizeof(format_pg);
}

static int vdisk_caching_pg(unsigned char *p, int pcontrol,
			     struct scst_vdisk_dev *virt_dev)
{	/* Caching page for mode_sense */
	const unsigned char caching_pg[] = {0x8, 18, 0x10, 0, 0xff, 0xff, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0, 0, 0, 0, 0, 0};

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
	case 0:
		p[2] |= virt_dev->dev->tst << 5;
		p[2] |= virt_dev->dev->d_sense << 2;
		p[3] |= virt_dev->dev->queue_alg << 4;
		p[4] |= virt_dev->dev->swp << 3;
		p[5] |= virt_dev->dev->tas << 6;
		break;
	case 1:
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
	case 2:
		p[2] |= DEF_TST << 5;
		p[2] |= DEF_DSENSE << 2;
		if (virt_dev->wt_flag || virt_dev->nv_cache)
			p[3] |= DEF_QUEUE_ALG_WT << 4;
		else
			p[3] |= DEF_QUEUE_ALG << 4;
		p[4] |= DEF_SWP << 3;
		p[5] |= DEF_TAS << 6;
		break;
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

static void vdisk_exec_mode_sense(struct scst_cmd *cmd)
{
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

	buf = kzalloc(MSENSE_BUF_SZ, GFP_KERNEL);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	virt_dev = cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks;

	type = cmd->dev->type;    /* type dev */
	dbd = cmd->cdb[1] & DBD;
	pcontrol = (cmd->cdb[2] & 0xc0) >> 6;
	pcode = cmd->cdb[2] & 0x3f;
	subpcode = cmd->cdb[3];
	msense_6 = (MODE_SENSE == cmd->cdb[0]);
	dev_spec = (virt_dev->dev->rd_only ||
		     cmd->tgt_dev->acg_dev->rd_only) ? WP : 0;

	if (!virt_dev->blockio)
		dev_spec |= DPOFUA;

	length = scst_get_buf_full(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_full() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out_free;
	}

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
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	if (!dbd) {
		/* Create block descriptor */
		buf[offset - 1] = 0x08;		/* block descriptor length */
		if (nblocks >> 32) {
			buf[offset + 0] = 0xFF;
			buf[offset + 1] = 0xFF;
			buf[offset + 2] = 0xFF;
			buf[offset + 3] = 0xFF;
		} else {
			/* num blks */
			buf[offset + 0] = (nblocks >> (BYTE * 3)) & 0xFF;
			buf[offset + 1] = (nblocks >> (BYTE * 2)) & 0xFF;
			buf[offset + 2] = (nblocks >> (BYTE * 1)) & 0xFF;
			buf[offset + 3] = (nblocks >> (BYTE * 0)) & 0xFF;
		}
		buf[offset + 4] = 0;			/* density code */
		buf[offset + 5] = (blocksize >> (BYTE * 2)) & 0xFF;/* blklen */
		buf[offset + 6] = (blocksize >> (BYTE * 1)) & 0xFF;
		buf[offset + 7] = (blocksize >> (BYTE * 0)) & 0xFF;

		offset += 8;			/* increment offset */
	}

	bp = buf + offset;

	switch (pcode) {
	case 0x1:	/* Read-Write error recovery page, direct access */
		len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
		break;
	case 0x2:	/* Disconnect-Reconnect page, all devices */
		len = vdisk_disconnect_pg(bp, pcontrol, virt_dev);
		break;
	case 0x3:       /* Format device page, direct access */
		len = vdisk_format_pg(bp, pcontrol, virt_dev);
		break;
	case 0x4:	/* Rigid disk geometry */
		len = vdisk_rigid_geo_pg(bp, pcontrol, virt_dev);
		break;
	case 0x8:	/* Caching page, direct access */
		len = vdisk_caching_pg(bp, pcontrol, virt_dev);
		break;
	case 0xa:	/* Control Mode page, all devices */
		len = vdisk_ctrl_m_pg(bp, pcontrol, virt_dev);
		break;
	case 0x1c:	/* Informational Exceptions Mode page, all devices */
		len = vdisk_iec_m_pg(bp, pcontrol, virt_dev);
		break;
	case 0x3f:	/* Read all Mode pages */
		len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
		len += vdisk_disconnect_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_format_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_caching_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_ctrl_m_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_iec_m_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_rigid_geo_pg(bp + len, pcontrol, virt_dev);
		break;
	default:
		TRACE_DBG("MODE SENSE: Unsupported page %x", pcode);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	offset += len;

	if (msense_6)
		buf[0] = offset - 1;
	else {
		buf[0] = ((offset - 2) >> 8) & 0xff;
		buf[1] = (offset - 2) & 0xff;
	}

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
	return;
}

static int vdisk_set_wt(struct scst_vdisk_dev *virt_dev, int wt)
{
	int res = 0;

	TRACE_ENTRY();

	if ((virt_dev->wt_flag == wt) || virt_dev->nullio || virt_dev->nv_cache)
		goto out;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->wt_flag = wt;
	spin_unlock(&virt_dev->flags_lock);

	scst_dev_del_all_thr_data(virt_dev->dev);

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

static void vdisk_exec_mode_select(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	int mselect_6, offset;

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	mselect_6 = (MODE_SELECT == cmd->cdb[0]);

	length = scst_get_buf_full(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_full() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out;
	}

	if (!(cmd->cdb[1] & PF) || (cmd->cdb[1] & SP)) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "MODE SELECT: Unsupported "
			"value(s) of PF and/or SP bits (cdb[1]=%x)",
			cmd->cdb[1]);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	if (mselect_6)
		offset = 4;
	else
		offset = 8;

	if (address[offset - 1] == 8) {
		offset += 8;
	} else if (address[offset - 1] != 0) {
		PRINT_ERROR("%s", "MODE SELECT: Wrong parameters list "
			"lenght");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out_put;
	}

	while (length > offset + 2) {
		if (address[offset] & PS) {
			PRINT_ERROR("%s", "MODE SELECT: Illegal PS bit");
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				scst_sense_invalid_field_in_parm_list));
			goto out_put;
		}
		if ((address[offset] & 0x3f) == 0x8) {
			/* Caching page */
			if (address[offset + 1] != 18) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"caching page request");
				scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				    scst_sense_invalid_field_in_parm_list));
				goto out_put;
			}
			if (vdisk_set_wt(virt_dev,
			      (address[offset + 2] & WCE) ? 0 : 1) != 0) {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_hardw_error));
				goto out_put;
			}
			break;
		} else if ((address[offset] & 0x3f) == 0xA) {
			/* Control page */
			if (address[offset + 1] != 0xA) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"control page request");
				scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				    scst_sense_invalid_field_in_parm_list));
				goto out_put;
			}
			vdisk_ctrl_m_pg_select(&address[offset], virt_dev, cmd);
		} else {
			PRINT_ERROR("MODE SELECT: Invalid request %x",
				address[offset] & 0x3f);
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
			    scst_sense_invalid_field_in_parm_list));
			goto out_put;
		}
		offset += address[offset + 1];
	}

out_put:
	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_log(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	/* No log pages are supported */
	scst_set_cmd_error(cmd,
		SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));

	TRACE_EXIT();
	return;
}

static void vdisk_exec_read_capacity(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[8];

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks;

	if ((cmd->cdb[8] & 1) == 0) {
		uint64_t lba = be64_to_cpu(get_unaligned((__be64 *)&cmd->cdb[2]));
		if (lba != 0) {
			TRACE_DBG("PMI zero and LBA not zero (cmd %p)", cmd);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out;
		}
	}

	/* Last block on the virt_dev is (nblocks-1) */
	memset(buffer, 0, sizeof(buffer));

	/*
	 * If we are thinly provisioned, we must ensure that the initiator
	 * issues a READ_CAPACITY(16) so we can return the TPE bit. By
	 * returning 0xFFFFFFFF we do that.
	 */
	if (nblocks >> 32 || virt_dev->thin_provisioned) {
		buffer[0] = 0xFF;
		buffer[1] = 0xFF;
		buffer[2] = 0xFF;
		buffer[3] = 0xFF;
	} else {
		buffer[0] = ((nblocks - 1) >> (BYTE * 3)) & 0xFF;
		buffer[1] = ((nblocks - 1) >> (BYTE * 2)) & 0xFF;
		buffer[2] = ((nblocks - 1) >> (BYTE * 1)) & 0xFF;
		buffer[3] = ((nblocks - 1) >> (BYTE * 0)) & 0xFF;
	}
	buffer[4] = (blocksize >> (BYTE * 3)) & 0xFF;
	buffer[5] = (blocksize >> (BYTE * 2)) & 0xFF;
	buffer[6] = (blocksize >> (BYTE * 1)) & 0xFF;
	buffer[7] = (blocksize >> (BYTE * 0)) & 0xFF;

	length = scst_get_buf_full(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_full() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out;
	}

	length = min_t(int, length, sizeof(buffer));

	memcpy(address, buffer, length);

	scst_put_buf_full(cmd, address);

	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_read_capacity16(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[32];

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks - 1;

	if ((cmd->cdb[14] & 1) == 0) {
		uint64_t lba = be64_to_cpu(get_unaligned((__be64 *)&cmd->cdb[2]));
		if (lba != 0) {
			TRACE_DBG("PMI zero and LBA not zero (cmd %p)", cmd);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out;
		}
	}

	memset(buffer, 0, sizeof(buffer));

	buffer[0] = nblocks >> 56;
	buffer[1] = (nblocks >> 48) & 0xFF;
	buffer[2] = (nblocks >> 40) & 0xFF;
	buffer[3] = (nblocks >> 32) & 0xFF;
	buffer[4] = (nblocks >> 24) & 0xFF;
	buffer[5] = (nblocks >> 16) & 0xFF;
	buffer[6] = (nblocks >> 8) & 0xFF;
	buffer[7] = nblocks & 0xFF;

	buffer[8] = (blocksize >> (BYTE * 3)) & 0xFF;
	buffer[9] = (blocksize >> (BYTE * 2)) & 0xFF;
	buffer[10] = (blocksize >> (BYTE * 1)) & 0xFF;
	buffer[11] = (blocksize >> (BYTE * 0)) & 0xFF;

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
		buffer[14] |= 0x80;     /* Add TPE */
#if 0  /*
	* Might be a big performance and functionality win, but might be
	* dangerous as well, although generally nearly always it should be set,
	* because nearly all devices should return zero for unmapped blocks.
	* But let's be on the safe side and disable it for now.
	*/
		buffer[14] |= 0x40;     /* Add TPRZ */
#endif
	}

	length = scst_get_buf_full(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_full() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
			}
		goto out;
	}

	length = min_t(int, length, sizeof(buffer));

	memcpy(address, buffer, length);

	scst_put_buf_full(cmd, address);

	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out:
	TRACE_EXIT();
	return;
}

/* SPC-4 REPORT TARGET PORT GROUPS command */
static void vdisk_exec_report_tpgs(struct scst_cmd *cmd)
{
	struct scst_device *dev;
	uint8_t *address;
	void *buf;
	int32_t buf_len;
	uint32_t allocation_length, data_length, length;
	uint8_t data_format;
	int res;

	TRACE_ENTRY();

	buf_len = scst_get_buf_full(cmd, &address);
	if (buf_len < 0) {
		PRINT_ERROR("scst_get_buf_full() failed: %d", buf_len);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	if (cmd->cdb_len < 12)
		PRINT_WARNING("received invalid REPORT TARGET PORT GROUPS "
			      "command - length %d is too small (should be at "
			      "least 12 bytes)", cmd->cdb_len);

	dev = cmd->dev;
	data_format = cmd->cdb_len > 1 ? cmd->cdb[1] >> 5 : 0;
	allocation_length = cmd->cdb_len >= 10 ?
		be32_to_cpu(get_unaligned((__be32 *)(cmd->cdb + 6))) : 1024;

	res = scst_tg_get_group_info(&buf, &data_length, dev, data_format);
	if (res == -ENOMEM) {
		scst_set_busy(cmd);
		goto out_put;
	} else if (res < 0) {
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	length = min_t(uint32_t, min(allocation_length, data_length), buf_len);
	memcpy(address, buf, length);
	kfree(buf);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_put:
	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_read_toc(struct scst_cmd *cmd)
{
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
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	if ((cmd->cdb[6] != 0 && (cmd->cdb[2] & 0x01)) ||
	    (cmd->cdb[6] > 1 && cmd->cdb[6] != 0xAA)) {
		PRINT_ERROR("READ TOC: invalid requested track number %x",
			cmd->cdb[6]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	length = scst_get_buf_full(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_full() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out;
	}

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
		buffer[off+4] = (nblocks >> (BYTE * 3)) & 0xFF;
		buffer[off+5] = (nblocks >> (BYTE * 2)) & 0xFF;
		buffer[off+6] = (nblocks >> (BYTE * 1)) & 0xFF;
		buffer[off+7] = (nblocks >> (BYTE * 0)) & 0xFF;
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
	return;
}

static void vdisk_exec_prevent_allow_medium_removal(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;

	TRACE_DBG("PERSIST/PREVENT 0x%02x", cmd->cdb[4]);

	spin_lock(&virt_dev->flags_lock);
	virt_dev->prevent_allow_medium_removal = cmd->cdb[4] & 0x01 ? 1 : 0;
	spin_unlock(&virt_dev->flags_lock);

	return;
}

static int vdisk_fsync(struct scst_vdisk_thr *thr, loff_t loff,
	loff_t len, struct scst_cmd *cmd, struct scst_device *dev)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	struct file *file;

	TRACE_ENTRY();

	/* Hopefully, the compiler will generate the single comparison */
	if (virt_dev->nv_cache || virt_dev->wt_flag ||
	    virt_dev->o_direct_flag || virt_dev->nullio)
		goto out;

	if (virt_dev->blockio) {
		res = vdisk_blockio_flush(thr->bdev,
			(cmd->noio_mem_alloc ? GFP_NOIO : GFP_KERNEL), true);
		goto out;
	}

	file = thr->fd;

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
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct iovec *vdisk_alloc_iv(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr)
{
	int iv_count;

	iv_count = min_t(int, scst_get_buf_count(cmd), UIO_MAXIOV);
	if (iv_count > thr->iv_count) {
		kfree(thr->iv);
		/* It can't be called in atomic context */
		thr->iv = kmalloc(sizeof(*thr->iv) * iv_count, GFP_KERNEL);
		if (thr->iv == NULL) {
			PRINT_ERROR("Unable to allocate iv (%d)", iv_count);
			scst_set_busy(cmd);
			goto out;
		}
		thr->iv_count = iv_count;
	}

out:
	return thr->iv;
}

static void vdisk_exec_read(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len;
	uint8_t __user *address;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	struct iovec *iv;
	int iv_count, i;
	bool finished = false;

	TRACE_ENTRY();

	if (virt_dev->nullio)
		goto out;

	iv = vdisk_alloc_iv(cmd, thr);
	if (iv == NULL)
		goto out;

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
		/* SEEK */
		if (fd->f_op->llseek)
			err = fd->f_op->llseek(fd, loff, 0/*SEEK_SET*/);
		else
			err = default_llseek(fd, loff, 0/*SEEK_SET*/);
		if (err != loff) {
			PRINT_ERROR("lseek trouble %lld != %lld",
				    (long long unsigned int)err,
				    (long long unsigned int)loff);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}

		/* READ */
		err = vfs_readv(fd, (struct iovec __force __user *)iv, iv_count,
				&fd->f_pos);

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

		loff += full_len;
		length = scst_get_buf_next(cmd, (uint8_t __force **)&address);
	};

	set_fs(old_fs);

out:
	TRACE_EXIT();
	return;

out_set_fs:
	set_fs(old_fs);
	for (i = 0; i < iv_count; i++)
		scst_put_buf(cmd, (void __force *)(iv[i].iov_base));
	goto out;
}

static void vdisk_exec_write(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len, saved_full_len;
	uint8_t __user *address;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	struct iovec *iv, *eiv;
	int i, iv_count, eiv_count;
	bool finished = false;

	TRACE_ENTRY();

	if (virt_dev->nullio)
		goto out;

	iv = vdisk_alloc_iv(cmd, thr);
	if (iv == NULL)
		goto out;

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

		/* SEEK */
		if (fd->f_op->llseek)
			err = fd->f_op->llseek(fd, loff, 0 /*SEEK_SET */);
		else
			err = default_llseek(fd, loff, 0 /*SEEK_SET */);
		if (err != loff) {
			PRINT_ERROR("lseek trouble %lld != %lld",
				    (long long unsigned int)err,
				    (long long unsigned int)loff);
			scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}

		/* WRITE */
		err = vfs_writev(fd, (struct iovec __force __user *)eiv, eiv_count,
				 &fd->f_pos);

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

		loff += saved_full_len;
		length = scst_get_buf_next(cmd, (uint8_t __force **)&address);
	}

	set_fs(old_fs);

out:
	TRACE_EXIT();
	return;

out_set_fs:
	set_fs(old_fs);
	for (i = 0; i < iv_count; i++)
		scst_put_buf(cmd, (void __force *)(iv[i].iov_base));
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

		PRINT_ERROR("cmd %p returned error %d", blockio_work->cmd,
			error);

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

static void blockio_exec_rw(struct scst_cmd *cmd, struct scst_vdisk_thr *thr,
	u64 lba_start, int write)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct block_device *bdev = thr->bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	int length, max_nr_vecs = 0, offset;
	struct page *page;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	int need_new_bio;
	struct scst_blockio_work *blockio_work;
	int bios = 0;
	gfp_t gfp_mask = (cmd->noio_mem_alloc ? GFP_NOIO : GFP_KERNEL);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	struct blk_plug plug;
#endif

	TRACE_ENTRY();

	if (virt_dev->nullio)
		goto out;

	/* Allocate and initialize blockio_work struct */
	blockio_work = kmem_cache_alloc(blockio_work_cachep, gfp_mask);
	if (blockio_work == NULL)
		goto out_no_mem;

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
				bio->bi_sector = lba_start0 <<
					(virt_dev->block_shift - 9);
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
				lba_start0 += thislen >> virt_dev->block_shift;
				thislen = 0;
				continue;
			}

			pg++;
			thislen += bytes;
			len -= bytes;
			off = 0;
		}

		lba_start += length >> virt_dev->block_shift;

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
	goto out;
}

static int vdisk_blockio_flush(struct block_device *bdev, gfp_t gfp_mask,
	bool report_error)
{
	int res = 0;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)           \
    && !(defined(CONFIG_SUSE_KERNEL)                        \
	 && LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 34))
	res = blkdev_issue_flush(bdev, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
	res = blkdev_issue_flush(bdev, gfp_mask, NULL, BLKDEV_IFL_WAIT);
#else
	res = blkdev_issue_flush(bdev, gfp_mask, NULL);
#endif
	if ((res != 0) && report_error)
		PRINT_ERROR("blkdev_issue_flush() failed: %d", res);

	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_exec_verify(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, len_mem = 0;
	uint8_t *address_sav, *address;
	int compare;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	uint8_t *mem_verify = NULL;

	TRACE_ENTRY();

	if (vdisk_fsync(thr, loff, cmd->bufflen, cmd, cmd->dev) != 0)
		goto out;

	/*
	 * Until the cache is cleared prior the verifying, there is not
	 * much point in this code. ToDo.
	 *
	 * Nevertherless, this code is valuable if the data have not read
	 * from the file/disk yet.
	 */

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
				SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}
	}

	mem_verify = vmalloc(LEN_MEM);
	if (mem_verify == NULL) {
		PRINT_ERROR("Unable to allocate memory %d for verify",
			       LEN_MEM);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_set_fs;
	}

	length = scst_get_buf_first(cmd, &address);
	address_sav = address;
	if (!length && cmd->data_len) {
		length = cmd->data_len;
		compare = 0;
	} else
		compare = 1;

	while (length > 0) {
		len_mem = (length > LEN_MEM) ? LEN_MEM : length;
		TRACE_DBG("Verify: length %zd - len_mem %zd", length, len_mem);

		if (!virt_dev->nullio)
			err = vfs_read(fd, (char __force __user *)mem_verify,
				len_mem, &fd->f_pos);
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
	return;
}

static int vdisk_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();

	if ((mcmd->fn == SCST_LUN_RESET) || (mcmd->fn == SCST_TARGET_RESET)) {
		/* Restore default values */
		struct scst_device *dev = tgt_dev->dev;
		struct scst_vdisk_dev *virt_dev = dev->dh_priv;

		dev->tst = DEF_TST;
		dev->d_sense = DEF_DSENSE;
		if (virt_dev->wt_flag && !virt_dev->nv_cache)
			dev->queue_alg = DEF_QUEUE_ALG_WT;
		else
			dev->queue_alg = DEF_QUEUE_ALG;
		dev->swp = DEF_SWP;
		dev->tas = DEF_TAS;

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
	return SCST_DEV_TM_NOT_COMPLETED;
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

	if (virt_dev->thin_provisioned)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sTHIN PROVISIONED",
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

	res = vdisk_get_file_size(virt_dev->filename,
			virt_dev->blockio, &file_size);
	if (res != 0)
		goto out;

	if (file_size == virt_dev->file_size) {
		PRINT_INFO("Size of virtual disk %s remained the same",
			virt_dev->name);
		goto out;
	}

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out;

	virt_dev->file_size = file_size;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;

	scst_dev_del_all_thr_data(virt_dev->dev);

	PRINT_INFO("New size of SCSI target virtual disk %s "
		"(fs=%lldMB, bs=%d, nblocks=%lld, cyln=%lld%s)",
		virt_dev->name, virt_dev->file_size >> 20,
		virt_dev->block_size,
		(long long unsigned int)virt_dev->nblocks,
		(long long unsigned int)virt_dev->nblocks/64/32,
		virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
						"than 1" : "");

	scst_capacity_data_changed(virt_dev->dev);

	scst_resume_activity();

out:
	return res;
}

static int vdev_create(struct scst_dev_type *devt,
	const char *name, struct scst_vdisk_dev **res_virt_dev)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;
	uint64_t dev_id_num;

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
	virt_dev->removable = DEF_REMOVABLE;
	virt_dev->thin_provisioned = DEF_THIN_PROVISIONED;

	virt_dev->block_size = DEF_DISK_BLOCKSIZE;
	virt_dev->block_shift = DEF_DISK_BLOCKSIZE_SHIFT;

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

	*res_virt_dev = virt_dev;

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

#ifndef CONFIG_SCST_PROC

static int vdev_parse_add_dev_params(struct scst_vdisk_dev *virt_dev,
	char *params, const char *allowed_params[])
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
			const char **a = allowed_params;
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

		res = strict_strtoul(pp, 0, &val);
		if (res != 0) {
			PRINT_ERROR("strict_strtoul() for %s failed: %d "
				"(device %s)", pp, res, virt_dev->name);
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
		} else if (!strcasecmp("removable", p)) {
			virt_dev->removable = val;
			TRACE_DBG("REMOVABLE %d", virt_dev->removable);
		} else if (!strcasecmp("thin_provisioned", p)) {
			virt_dev->thin_provisioned = val;
			TRACE_DBG("THIN PROVISIONED %d",
				virt_dev->thin_provisioned);
		} else if (!strcasecmp("blocksize", p)) {
			virt_dev->block_size = val;
			virt_dev->block_shift = scst_calc_block_shift(
							virt_dev->block_size);
			if (virt_dev->block_shift < 9) {
				res = -EINVAL;
				goto out;
			}
			TRACE_DBG("block_size %d, block_shift %d",
				virt_dev->block_size,
				virt_dev->block_shift);
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
	const char *allowed_params[] = { "filename", "read_only", "removable",
					 "blocksize", "nv_cache",
					 "thin_provisioned", NULL };
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	res = vdev_create(&vdisk_blk_devtype, device_name, &virt_dev);
	if (res != 0)
		goto out;

	virt_dev->command_set_version = 0x04C0; /* SBC-3 */

	virt_dev->blockio = 1;

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
	const char *allowed_params[] = { "read_only", "removable",
					 "blocksize", NULL };
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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

	virt_dev->block_size = DEF_CDROM_BLOCKSIZE;
	virt_dev->block_shift = DEF_CDROM_BLOCKSIZE_SHIFT;

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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out;

	/* To sync with detach*() functions */
	mutex_lock(&scst_mutex);

	if (*filename == '\0') {
		virt_dev->cdrom_empty = 1;
		TRACE_DBG("%s", "No media");
	} else if (*filename != '/') {
		PRINT_ERROR("File path \"%s\" is not absolute", filename);
		res = -EINVAL;
		goto out_unlock;
	} else
		virt_dev->cdrom_empty = 0;

	old_fn = virt_dev->filename;

	if (!virt_dev->cdrom_empty) {
		char *fn = kstrdup(filename, GFP_KERNEL);
		if (fn == NULL) {
			PRINT_ERROR("%s", "Allocation of filename failed");
			res = -ENOMEM;
			goto out_unlock;
		}

		virt_dev->filename = fn;

		res = vdisk_get_file_size(virt_dev->filename,
				virt_dev->blockio, &err);
		if (res != 0)
			goto out_free_fn;
	} else {
		err = 0;
		virt_dev->filename = NULL;
	}

	if (virt_dev->prevent_allow_medium_removal) {
		PRINT_ERROR("Prevent medium removal for "
			"virtual device with name %s", virt_dev->name);
		res = -EINVAL;
		goto out_free_fn;
	}

	virt_dev->file_size = err;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;
	if (!virt_dev->cdrom_empty)
		virt_dev->media_changed = 1;

	mutex_unlock(&scst_mutex);

	scst_dev_del_all_thr_data(virt_dev->dev);

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO("Changed SCSI target virtual cdrom %s "
			"(file=\"%s\", fs=%lldMB, bs=%d, nblocks=%lld,"
			" cyln=%lld%s)", virt_dev->name,
			vdev_get_filename(virt_dev),
			virt_dev->file_size >> 20, virt_dev->block_size,
			(long long unsigned int)virt_dev->nblocks,
			(long long unsigned int)virt_dev->nblocks/64/32,
			virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
							"than 1" : "");
	} else {
		PRINT_INFO("Removed media from SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	kfree(old_fn);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_fn:
	kfree(virt_dev->filename);
	virt_dev->filename = old_fn;

out_unlock:
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
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n%s", (int)virt_dev->block_size,
		(virt_dev->block_size == DEF_DISK_BLOCKSIZE) ? "" :
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
			SCST_SYSFS_KEY_MARK "");

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
			SCST_SYSFS_KEY_MARK "");

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
		(virt_dev->thin_provisioned == DEF_THIN_PROVISIONED) ? "" :
			SCST_SYSFS_KEY_MARK "");

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
			SCST_SYSFS_KEY_MARK "");

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
			SCST_SYSFS_KEY_MARK "");

	TRACE_EXIT_RES(pos);
	return pos;
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

static int vdev_sysfs_process_get_filename(struct scst_sysfs_work_item *work)
{
	int res = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = work->dev;

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out_put;
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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	seq_printf(seq, "%-17s %-11s %-11s %-15s %-45s %-16s\n",
		"Name", "Size(MB)", "Block size", "Options", "File name",
		"T10 device id");

	list_for_each_entry(virt_dev, &vdev_list, vdev_list_entry) {
		int c;
		if (virt_dev->dev->type != TYPE_DISK)
			continue;
		seq_printf(seq, "%-17s %-11d %-12d", virt_dev->name,
			(uint32_t)(virt_dev->file_size >> 20),
			virt_dev->block_size);
		c = 0;
		if (virt_dev->wt_flag) {
			seq_printf(seq, "WT ");
			c += 3;
		}
		if (virt_dev->nv_cache) {
			seq_printf(seq, "NV ");
			c += 3;
		}
		if (virt_dev->dev != NULL) {
			if (virt_dev->dev->rd_only) {
				seq_printf(seq, "RO ");
				c += 3;
			}
		} else if (virt_dev->rd_only) {
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
			c += 4;
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
	struct scst_vdisk_dev *virt_dev, *vv;
	uint32_t block_size = DEF_DISK_BLOCKSIZE;
	int block_shift = DEF_DISK_BLOCKSIZE_SHIFT;
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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

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
		virt_dev = NULL;
		list_for_each_entry(vv, &vdev_list,
					vdev_list_entry) {
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev) {
			PRINT_ERROR("Virtual device with name "
				   "%s already exist", name);
			res = -EINVAL;
			goto out_up;
		}

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
		virt_dev->block_size = block_size;
		virt_dev->block_shift = block_shift;

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
			virt_dev->block_size);
	} else if (action == 0) {	/* close */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdev_list,
					vdev_list_entry) {
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev == NULL) {
			PRINT_ERROR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}
		vdev_del_device(virt_dev);
	} else if (action == 2) {	/* resync_size */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdev_list,
					vdev_list_entry) {
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev == NULL) {
			PRINT_ERROR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}

		res = vdisk_resync_size(virt_dev);
		if (res != 0)
			goto out_up;
	} else if (action == 3) {	/* set T10 device id */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdev_list,
					vdev_list_entry) {
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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
	struct scst_vdisk_dev *virt_dev, *vv;
	char *filename;
	int res = 0;
	int cdrom_empty;

	virt_dev = NULL;
	list_for_each_entry(vv, &vdev_list, vdev_list_entry) {
		if (strcmp(vv->name, name) == 0) {
			virt_dev = vv;
			break;
		}
	}
	if (virt_dev) {
		PRINT_ERROR("Virtual device with name "
		       "%s already exist", name);
		res = -EINVAL;
		goto out;
	}

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
		PRINT_ERROR("File path \"%s\" is not "
			"absolute", filename);
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
	struct scst_vdisk_dev *virt_dev, *vv;
	int res = 0;

	virt_dev = NULL;
	list_for_each_entry(vv, &vdev_list, vdev_list_entry) {
		if (strcmp(vv->name, name) == 0) {
			virt_dev = vv;
			break;
		}
	}

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

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

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

		virt_dev = list_entry(vdev_list.next, typeof(*virt_dev),
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

static int __init init_scst_vdisk_driver(void)
{
	int res;

	vdisk_thr_cachep = KMEM_CACHE(scst_vdisk_thr, SCST_SLAB_FLAGS);
	if (vdisk_thr_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	blockio_work_cachep = KMEM_CACHE(scst_blockio_work, SCST_SLAB_FLAGS);
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

	atomic_set(&nullio_thr_data.hdr.ref, 1); /* never destroy it */

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
	kmem_cache_destroy(vdisk_thr_cachep);
	goto out;
}

static void __exit exit_scst_vdisk_driver(void)
{
	exit_scst_vdisk(&vdisk_null_devtype);
	exit_scst_vdisk(&vdisk_blk_devtype);
	exit_scst_vdisk(&vdisk_file_devtype);
	exit_scst_vdisk(&vcdrom_devtype);

	kmem_cache_destroy(blockio_work_cachep);
	kmem_cache_destroy(vdisk_thr_cachep);
}

module_init(init_scst_vdisk_driver);
module_exit(exit_scst_vdisk_driver);

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI disk (type 0) and CDROM (type 5) dev handler for "
	"SCST using files on file systems or block devices");
MODULE_VERSION(SCST_VERSION_STRING);
