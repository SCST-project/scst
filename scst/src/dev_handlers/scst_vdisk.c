/*
 *  scst_vdisk.c
 *
 *  Copyright (C) 2004 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 *  Copyright (C) 2007 Ross Walker <rswwalker at hotmail dot com>
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
 *  Copyright (C) 2008 - 2020 Bart Van Assche <bvanassche@acm.org>
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

#ifndef INSIDE_KERNEL_TREE
#include <linux/version.h>
#endif
#include <linux/wait.h>
#include <linux/aio.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
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
#include <linux/atomic.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0) || \
	(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 9)
#include <linux/blk-integrity.h>
#endif
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/namei.h>
#include <asm/div64.h>
#include <asm/unaligned.h>
#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/crc32c.h>
#include <linux/falloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

#define LOG_PREFIX			"dev_vdisk"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif

#define TRACE_ORDER	0x80000000

#include "scst_dev_handler.h"

/* 8 byte ASCII Vendor */
#define SCST_FIO_VENDOR			"SCST_FIO"
#define SCST_BIO_VENDOR			"SCST_BIO"
/* 4 byte ASCII Product Revision Level - left aligned */
#define SCST_FIO_REV			"370 "

#define MAX_USN_LEN			(20+1) /* For '\0' */
#define MAX_INQ_VEND_SPECIFIC_LEN	(INQ_BUF_SZ - 96)

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
#define	DEF_OPT_TRANS_LEN		524288
#define	DEF_CDROM_BLOCK_SHIFT		11
#define	DEF_SECTORS			56
#define	DEF_HEADS			255
#define LEN_MEM				(32 * 1024)
#define DEF_RD_ONLY			0
#define DEF_WRITE_THROUGH		0
#define DEF_NV_CACHE			0
#define DEF_O_DIRECT			0
#define DEF_DUMMY			0
#define DEF_READ_ZERO			0
#define DEF_REMOVABLE			0
#define DEF_ROTATIONAL			1
#define DEF_THIN_PROVISIONED		0
#define DEF_EXPL_ALUA			0
#define DEF_DEV_ACTIVE			1
#define DEF_BIND_ALUA_STATE		1

#define VDISK_NULLIO_SIZE		(5LL*1024*1024*1024*1024/2)

#define DEF_TST				SCST_TST_1_SEP_TASK_SETS
#define DEF_TMF_ONLY			0

/*
 * Since we can't control backstorage device's reordering, we have to always
 * report unrestricted reordering.
 */
#define DEF_QUEUE_ALG_WT	SCST_QUEUE_ALG_1_UNRESTRICTED_REORDER
#define DEF_QUEUE_ALG		SCST_QUEUE_ALG_1_UNRESTRICTED_REORDER

#define DEF_QERR		SCST_QERR_0_ALL_RESUME
#define DEF_SWP			0
#define DEF_TAS			0
#define DEF_DSENSE		SCST_D_SENSE_0_FIXED_SENSE

#define DEF_DPICZ		SCST_DPICZ_CHECK_ON_xPROT_0

#define DEF_DIF_FILENAME_TMPL	SCST_VAR_DIR "/dif_tags/%s.dif"


struct scst_vdisk_dev {
	uint64_t nblocks;
	unsigned int opt_trans_len;

	/*
	 * Not protected, because assignments to aligned 64-bit integers are
	 * atomic. At worst, accesses to it should be covered by READ_ONCE(),
	 * but not sure if that is really needed, so would prefer to keep it
	 * away from the fast path.
	 */
	loff_t file_size;	/* in bytes */

	/*
	 * This lock can be taken on both SIRQ and thread context, but in
	 * all cases for each particular instance it's taken consistently either
	 * on SIRQ or thread context. Mix of them is forbidden.
	 */
	spinlock_t flags_lock;

	/*
	 * Below flags are protected by flags_lock or suspended activity
	 * with scst_vdisk_mutex.
	 */
	unsigned int dev_active:1;
	unsigned int bind_alua_state:1;
	unsigned int rd_only:1;
	unsigned int wt_flag:1;
	unsigned int nv_cache:1;
	unsigned int o_direct_flag:1;
	unsigned int async:1;
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int blockio:1;
	unsigned int blk_integrity:1;
	unsigned int cdrom_empty:1;
	unsigned int dummy:1;
	unsigned int read_zero:1;
	unsigned int removable:1;
	unsigned int thin_provisioned:1;
	unsigned int thin_provisioned_manually_set:1;
	unsigned int dev_thin_provisioned:1;
	unsigned int rotational:1;
	unsigned int wt_flag_saved:1;
	unsigned int tst:3;
	unsigned int format_active:1;
	unsigned int discard_zeroes_data:1;
	unsigned int reexam_pending:1;
	unsigned int size_key:1;
	unsigned int opt_trans_len_set:1;

	struct file *fd;
	struct file *dif_fd;
	struct block_device *bdev;
	fmode_t bdev_mode;
	struct bio_set *vdisk_bioset;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	struct bio_set vdisk_bioset_struct;
#endif

	uint64_t format_progress_to_do, format_progress_done;

	int virt_id;
	/* Name of the virtual device, must be <= SCSI Model + 1 */
	char name[64+1];
	/* File name, protected by scst_mutex and suspended activities */
	char *filename;
	uint16_t command_set_version;

	unsigned int initial_cluster_mode:1;

	/* All 14 protected by vdisk_serial_rwlock */
	unsigned int t10_vend_id_set:1;   /* true if t10_vend_id manually set */
	/* true if vend_specific_id manually set */
	unsigned int vend_specific_id_set:1;
	unsigned int prod_id_set:1;          /* true if prod_id manually set */
	unsigned int prod_rev_lvl_set:1; /* true if prod_rev_lvl manually set */
	unsigned int scsi_device_name_set:1; /* true if scsi_device_name manually set */
	unsigned int t10_dev_id_set:1; /* true if t10_dev_id manually set */
	unsigned int usn_set:1; /* true if usn manually set */
	char t10_vend_id[8 + 1];
	char vend_specific_id[128 + 1];
	char prod_id[16 + 1];
	char prod_rev_lvl[4 + 1];
	char scsi_device_name[256 + 1];
	char t10_dev_id[16+8+2]; /* T10 device ID */
	int eui64_id_len;
	uint8_t eui64_id[16];
	int naa_id_len;
	uint8_t naa_id[16];
	char usn[MAX_USN_LEN];
	uint8_t inq_vend_specific[MAX_INQ_VEND_SPECIFIC_LEN];
	int inq_vend_specific_len;

	/* Unmap INQUIRY parameters */
	uint32_t unmap_opt_gran, unmap_align, unmap_max_lba_cnt;

	struct scst_device *dev;
	struct list_head vdev_list_entry;

	struct scst_dev_type *vdev_devt;

	int tgt_dev_cnt;

	char *dif_filename;

	struct work_struct vdev_inq_changed_work;

	/* Only to pass it to attach() callback. Don't use them anywhere else! */
	int blk_shift;
	int numa_node_id;
	enum scst_dif_mode dif_mode;
	int dif_type;
	__be64 dif_static_app_tag_combined;
};

struct vdisk_cmd_params {
	union {
		struct {
			struct kvec	*kvec;
			int		kvec_segs;
			struct kvec	small_kvec[4];
		} sync;
		struct {
			struct kiocb	iocb;
			struct bio_vec	*bvec;
			struct bio_vec	small_bvec[4];
		} async;
	};
	struct scst_cmd *cmd;
	loff_t loff;
	unsigned int fua:1;
	unsigned int execute_async:1;
};

static bool vdev_saved_mode_pages_enabled = true;

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

/* Context RA patch supposed to be applied on the kernel */
#define DEF_NUM_THREADS		8
static int num_threads = DEF_NUM_THREADS;

module_param_named(num_threads, num_threads, int, S_IRUGO);
MODULE_PARM_DESC(num_threads, "vdisk threads count");

/*
 * Used to serialize sense setting between blockio data and DIF tags
 * unsuccessful readings/writings
 */
static spinlock_t vdev_err_lock;


/** SYSFS **/

static ssize_t vdisk_sysfs_gen_tp_soft_threshold_reached_UA(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);
static ssize_t vdev_dif_filename_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static struct kobj_attribute gen_tp_soft_threshold_reached_UA_attr =
	__ATTR(gen_tp_soft_threshold_reached_UA, S_IWUSR, NULL,
		vdisk_sysfs_gen_tp_soft_threshold_reached_UA);
static struct kobj_attribute vdev_dif_filename_attr =
	__ATTR(dif_filename, S_IRUGO, vdev_dif_filename_show, NULL);



/*
 * Protects vdisks addition/deletion and related activities, like search.
 * Outer mutex regarding scst_mutex.
 */
static DEFINE_MUTEX(scst_vdisk_mutex);

/*
 * Protects the device attributes t10_vend_id, vend_specific_id, prod_id,
 * prod_rev_lvl, scsi_device_name, t10_dev_id, eui64_id, naa_id, usn and
 * inq_vend_specific.
 */
static DEFINE_RWLOCK(vdisk_serial_rwlock);

/* Protected by scst_vdisk_mutex */
static LIST_HEAD(vdev_list);

static struct kmem_cache *vdisk_cmd_param_cachep;
static struct kmem_cache *blockio_work_cachep;

static vdisk_op_fn fileio_ops[256];
static const vdisk_op_fn fileio_var_len_ops[256];
static vdisk_op_fn blockio_ops[256];
static const vdisk_op_fn blockio_var_len_ops[256];
static vdisk_op_fn nullio_ops[256];
static const vdisk_op_fn nullio_var_len_ops[256];

static struct scst_dev_type vdisk_file_devtype;
static struct scst_dev_type vdisk_blk_devtype;
static struct scst_dev_type vdisk_null_devtype;
static struct scst_dev_type vcdrom_devtype;


static const char *vdev_get_filename(const struct scst_vdisk_dev *virt_dev)
{
	if (virt_dev->filename != NULL)
		return virt_dev->filename;
	else
		return "none";
}

/* Returns fd, use IS_ERR(fd) to get error status */
static struct file *vdev_open_fd(const struct scst_vdisk_dev *virt_dev,
	const char *name, bool read_only)
{
	int open_flags = 0;
	struct file *fd;

	TRACE_ENTRY();

	sBUG_ON(!name);

	if (read_only)
		open_flags |= O_RDONLY;
	else
		open_flags |= O_RDWR;
	if (virt_dev->wt_flag && !virt_dev->nv_cache)
		open_flags |= O_DSYNC;

	TRACE_DBG("Opening file %s, flags 0x%x", name, open_flags);
	fd = filp_open(name, O_LARGEFILE | open_flags, 0600);
	if (IS_ERR(fd)) {
		if (PTR_ERR(fd) == -EMEDIUMTYPE)
			TRACE(TRACE_MINOR, "Unable to open %s with EMEDIUMTYPE, "
				"DRBD passive?", name);
		else
			PRINT_ERROR("filp_open(%s) failed: %d", name, (int)PTR_ERR(fd));
	}

	TRACE_EXIT();
	return fd;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
static void vdev_flush_end_io(struct bio *bio, int error)
{
#else
static void vdev_flush_end_io(struct bio *bio)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0) &&	\
	!defined(CONFIG_SUSE_KERNEL)
	int error = bio->bi_error;
#else
	int error = blk_status_to_errno(bio->bi_status);
#endif
#endif
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

static int vdisk_blockio_flush(struct block_device *bdev, gfp_t gfp_mask,
	bool report_error, struct scst_cmd *cmd, bool async)
{
	int res = 0;

	TRACE_ENTRY();

	if (async) {
		struct bio *bio;

		bio = bio_alloc(/*bdev=*/NULL, 0, /*opf=*/0, gfp_mask);
		if (bio == NULL) {
			res = -ENOMEM;
			goto out_rep;
		}

		bio->bi_end_io = vdev_flush_end_io;
		bio->bi_private = cmd;

		bio_set_dev(bio, bdev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0) ||	\
	(defined(CONFIG_SUSE_KERNEL) &&			\
	 LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
		/*
		 * For the introduction of REQ_PREFLUSH, see also commit
		 * 28a8f0d317bf ("block, drivers, fs: rename REQ_FLUSH to
		 * REQ_PREFLUSH") # v4.8.
		 */
		bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_PREFLUSH);
		submit_bio(bio);
#else
		/*
		 * For the introduction of WRITE_FLUSH, see also commit
		 * 4fed947cb311 ("block: implement REQ_FLUSH/FUA based
		 * interface for FLUSH/FUA requests") # v2.6.37.
		 */
		submit_bio(WRITE_FLUSH, bio);
#endif
		goto out;
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 4)
		res = blkdev_issue_flush(bdev, gfp_mask, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 6)
		res = blkdev_issue_flush(bdev, gfp_mask);
#else
		res = blkdev_issue_flush(bdev);
#endif
	}

out_rep:
	if ((res != 0) && report_error)
		PRINT_ERROR("%s() failed: %d",
			async ? "bio_alloc" : "blkdev_issue_flush", res);

	if (async && (cmd != NULL)) {
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
			scst_estimate_context());
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_blockio_check_flush_support(struct scst_vdisk_dev *virt_dev)
{
	struct block_device *bdev;

	TRACE_ENTRY();

	if (!virt_dev->blockio || virt_dev->rd_only || virt_dev->nv_cache ||
	    virt_dev->wt_flag || !virt_dev->dev_active)
		goto out;

	bdev = blkdev_get_by_path(virt_dev->filename, FMODE_READ,
				  (void *)__func__);
	if (IS_ERR(bdev)) {
		if (PTR_ERR(bdev) == -EMEDIUMTYPE)
			TRACE(TRACE_MINOR, "Unable to open %s with EMEDIUMTYPE, "
				"DRBD passive?", virt_dev->filename);
		else
			PRINT_ERROR("blkdev_get_by_path(%s) failed: %ld",
				virt_dev->filename, PTR_ERR(bdev));
		goto out;
	}

	if (vdisk_blockio_flush(bdev, GFP_KERNEL, false, NULL, false) != 0) {
		PRINT_WARNING("Device %s doesn't support barriers, switching "
			"to NV_CACHE mode. Read README for more details.",
			virt_dev->filename);
		virt_dev->nv_cache = 1;
	}

	blkdev_put(bdev, FMODE_READ);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_check_tp_support(struct scst_vdisk_dev *virt_dev)
{
	struct block_device *bdev = NULL;
	struct file *fd = NULL;
	bool fd_open = false;
	int res;

	TRACE_ENTRY();

	virt_dev->dev_thin_provisioned = 0;

	if (virt_dev->rd_only || !virt_dev->filename || !virt_dev->dev_active)
		goto check;

	if (virt_dev->blockio) {
		bdev = blkdev_get_by_path(virt_dev->filename, FMODE_READ,
					  (void *)__func__);
		res = IS_ERR(bdev) ? PTR_ERR(bdev) : 0;
	} else {
		fd = filp_open(virt_dev->filename, O_LARGEFILE, 0600);
		res = IS_ERR(fd) ? PTR_ERR(fd) : 0;
	}
	if (res) {
		if (res == -EMEDIUMTYPE && virt_dev->blockio)
			TRACE(TRACE_MINOR,
			      "Unable to open %s with EMEDIUMTYPE, DRBD passive?",
			      virt_dev->filename);
		else
			PRINT_ERROR("opening %s failed: %d",
				    virt_dev->filename, res);
		goto check;
	}

	fd_open = true;

	if (virt_dev->blockio) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
		virt_dev->dev_thin_provisioned =
			!!bdev_max_discard_sectors(bdev);
#else
		virt_dev->dev_thin_provisioned =
			blk_queue_discard(bdev_get_queue(bdev));
#endif
	} else {
		virt_dev->dev_thin_provisioned = (fd->f_op->fallocate != NULL);
	}

check:
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

	if (virt_dev->thin_provisioned) {
		int block_shift = virt_dev->dev->block_shift;
		int rc;

		rc = sysfs_create_file(&virt_dev->dev->dev_kobj,
				&gen_tp_soft_threshold_reached_UA_attr.attr);
		if (rc != 0) {
			PRINT_ERROR("Can't create attr %s for dev %s",
				gen_tp_soft_threshold_reached_UA_attr.attr.name,
				virt_dev->name);
		}

		if (virt_dev->blockio) {
			struct request_queue *q;

			sBUG_ON(!fd_open);
			q = bdev_get_queue(bdev);
			virt_dev->unmap_opt_gran = q->limits.discard_granularity >> block_shift;
			virt_dev->unmap_align = q->limits.discard_alignment >> block_shift;
			if (virt_dev->unmap_opt_gran == virt_dev->unmap_align)
				virt_dev->unmap_align = 0;
			virt_dev->unmap_max_lba_cnt = q->limits.max_discard_sectors >> (block_shift - 9);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
			virt_dev->discard_zeroes_data = q->limits.discard_zeroes_data;
#endif
		} else {
			virt_dev->unmap_opt_gran = 1;
			virt_dev->unmap_align = 0;
			/* 256 MB */
			virt_dev->unmap_max_lba_cnt = (256 * 1024 * 1024) >> block_shift;
#if 0 /*
       * Might be a big performance and functionality win, but might be
       * dangerous as well. But let's be on the safe side and disable it
       * for now.
       */
			virt_dev->discard_zeroes_data = 1;
#else
			virt_dev->discard_zeroes_data = 0;
#endif
		}
		TRACE_DBG("unmap_gran %d, unmap_alignment %d, max_unmap_lba %u, "
			"discard_zeroes_data %d", virt_dev->unmap_opt_gran,
			virt_dev->unmap_align, virt_dev->unmap_max_lba_cnt,
			virt_dev->discard_zeroes_data);
	}

	if (fd_open) {
		if (virt_dev->blockio)
			blkdev_put(bdev, FMODE_READ);
		else
			filp_close(fd, NULL);
	}

	TRACE_EXIT();
	return;
}

/* Returns 0 on success and file size in *file_size, error code otherwise */
static int vdisk_get_file_size(const struct scst_vdisk_dev *virt_dev,
	loff_t *file_size)
{
	loff_t res;

	TRACE_ENTRY();

	sBUG_ON(!virt_dev->filename);

	if (!virt_dev->dev_active) {
		TRACE_DBG("Not active dev %s, skip reexaming",
			  virt_dev->dev->virt_name);
		res = -EMEDIUMTYPE;
		goto out;
	}

	res = scst_file_or_bdev_size(virt_dev->filename);
	if (res == -EMEDIUMTYPE && virt_dev->blockio) {
		TRACE(TRACE_MINOR,
		      "Unable to open %s with EMEDIUMTYPE, DRBD passive?",
		      virt_dev->filename);
		goto out;
	}
	if (res < 0) {
		PRINT_ERROR("opening %s failed: %lld", virt_dev->filename, res);
		goto out;
	}
	*file_size = res;
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_vdisk_dev *vdev_find(const char *name)
{
	struct scst_vdisk_dev *res, *vv;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_vdisk_mutex);

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

#define VDEV_WT_LABEL			"WRITE_THROUGH"
#define VDEV_MODE_PAGES_BUF_SIZE	(64*1024)
#define VDEV_MODE_PAGES_DIR		(SCST_VAR_DIR "/vdev_mode_pages")

static int __vdev_save_mode_pages(const struct scst_vdisk_dev *virt_dev,
	uint8_t *buf, int size)
{
	int res = 0;

	TRACE_ENTRY();

	if (virt_dev->wt_flag != DEF_WRITE_THROUGH) {
		res += scnprintf(&buf[res], size - res, "%s=%d\n",
			VDEV_WT_LABEL, virt_dev->wt_flag);
		if (res >= size-1)
			goto out_overflow;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_overflow:
	PRINT_ERROR("Mode pages buffer overflow (size %d)", size);
	res = -EOVERFLOW;
	goto out;
}

static int vdev_save_mode_pages(const struct scst_vdisk_dev *virt_dev)
{
	int res, rc, offs;
	uint8_t *buf;
	int size;
	char *name, *name1;

	TRACE_ENTRY();

	size = VDEV_MODE_PAGES_BUF_SIZE;

	buf = vzalloc(size);
	if (buf == NULL) {
		PRINT_ERROR("Unable to alloc mode pages buffer (size %d)", size);
		res = -ENOMEM;
		goto out;
	}

	name = kasprintf(GFP_KERNEL, "%s/%s", VDEV_MODE_PAGES_DIR, virt_dev->name);
	if (name == NULL) {
		PRINT_ERROR("Unable to create name %s/%s", VDEV_MODE_PAGES_DIR,
			virt_dev->name);
		res = -ENOMEM;
		goto out_vfree;
	}

	name1 = kasprintf(GFP_KERNEL, "%s/%s1", VDEV_MODE_PAGES_DIR, virt_dev->name);
	if (name1 == NULL) {
		PRINT_ERROR("Unable to create name %s/%s1", VDEV_MODE_PAGES_DIR,
			virt_dev->name);
		res = -ENOMEM;
		goto out_free_name;
	}

	offs = scst_save_global_mode_pages(virt_dev->dev, buf, size);
	if (offs < 0) {
		res = offs;
		goto out_free_name1;
	}

	rc = __vdev_save_mode_pages(virt_dev, &buf[offs], size - offs);
	if (rc < 0) {
		res = rc;
		goto out_free_name1;
	}

	offs += rc;
	if (offs == 0) {
		res = 0;
		scst_remove_file(name);
		scst_remove_file(name1);
		goto out_free_name1;
	}

	res = scst_write_file_transactional(name, name1,
			virt_dev->name, strlen(virt_dev->name), buf, offs);

out_free_name1:
	kfree(name1);

out_free_name:
	kfree(name);

out_vfree:
	vfree(buf);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdev_restore_wt(struct scst_vdisk_dev *virt_dev, unsigned int val)
{
	int res;

	TRACE_ENTRY();

	if (val > 1) {
		PRINT_ERROR("Invalid value %d for parameter %s (device %s)",
			val, VDEV_WT_LABEL, virt_dev->name);
		res = -EINVAL;
		goto out;
	}

	virt_dev->wt_flag = val;
	virt_dev->wt_flag_saved = val;

	PRINT_INFO("WT_FLAG restored to %d for vdev %s", virt_dev->wt_flag,
		virt_dev->name);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Params are NULL-terminated */
static int __vdev_load_mode_pages(struct scst_vdisk_dev *virt_dev, char *params)
{
	int res = 0;
	char *param, *p, *pp;
	unsigned long val;

	TRACE_ENTRY();

	while (1) {
		param = scst_get_next_token_str(&params);
		if (param == NULL)
			break;

		p = scst_get_next_lexem(&param);
		if (*p == '\0')
			break;

		pp = scst_get_next_lexem(&param);
		if (*pp == '\0')
			goto out_need_param;

		if (scst_get_next_lexem(&param)[0] != '\0')
			goto out_too_many;

		res = kstrtoul(pp, 0, &val);
		if (res != 0)
			goto out_strtoul_failed;

		if (strcasecmp(VDEV_WT_LABEL, p) == 0)
			res = vdev_restore_wt(virt_dev, val);
		else {
			TRACE_DBG("Unknown parameter %s", p);
			res = -EINVAL;
		}
		if (res != 0)
			break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_strtoul_failed:
	PRINT_ERROR("strtoul() for %s failed: %d (device %s)", pp, res,
		virt_dev->name);
	goto out;

out_need_param:
	PRINT_ERROR("Parameter %s value missed for device %s", p, virt_dev->name);
	res = -EINVAL;
	goto out;

out_too_many:
	PRINT_ERROR("Too many parameter's %s values (device %s)", p, virt_dev->name);
	res = -EINVAL;
	goto out;
}

static int vdev_load_mode_pages(struct scst_vdisk_dev *virt_dev)
{
	int res;
	struct scst_device *dev = virt_dev->dev;
	uint8_t *buf;
	int size;
	char *name, *name1, *params;

	TRACE_ENTRY();

	size = VDEV_MODE_PAGES_BUF_SIZE;

	buf = vzalloc(size);
	if (buf == NULL) {
		PRINT_ERROR("Unable to alloc mode pages buffer (size %d)", size);
		res = -ENOMEM;
		goto out;
	}

	name = kasprintf(GFP_KERNEL, "%s/%s", VDEV_MODE_PAGES_DIR, virt_dev->name);
	if (name == NULL) {
		PRINT_ERROR("Unable to create name %s/%s", VDEV_MODE_PAGES_DIR,
			virt_dev->name);
		res = -ENOMEM;
		goto out_vfree;
	}

	name1 = kasprintf(GFP_KERNEL, "%s/%s1", VDEV_MODE_PAGES_DIR, virt_dev->name);
	if (name1 == NULL) {
		PRINT_ERROR("Unable to create name %s/%s1", VDEV_MODE_PAGES_DIR,
			virt_dev->name);
		res = -ENOMEM;
		goto out_free_name;
	}

	size = scst_read_file_transactional(name, name1,
			virt_dev->name, strlen(virt_dev->name), buf, size-1);
	if (size <= 0) {
		res = size;
		goto out_free_name1;
	}

	buf[size-1] = '\0';

	res = scst_restore_global_mode_pages(dev, &buf[strlen(virt_dev->name)+1],
				&params);
	if ((res != 0) || (params == NULL))
		goto out_free_name1;

	res = __vdev_load_mode_pages(virt_dev, params);

out_free_name1:
	kfree(name1);

out_free_name:
	kfree(name);

out_vfree:
	vfree(buf);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#if defined(CONFIG_BLK_DEV_INTEGRITY)
static int vdisk_init_block_integrity(struct scst_vdisk_dev *virt_dev)
{
	int res;
	struct scst_device *dev = virt_dev->dev;
	struct block_device *bdev;
	struct blk_integrity *bi;
	const char *bi_profile_name;

	TRACE_ENTRY();

	bdev = blkdev_get_by_path(virt_dev->filename, FMODE_READ,
				  (void *)__func__);
	if (IS_ERR(bdev)) {
		res = PTR_ERR(bdev);
		goto out;
	}

	bi = bdev_get_integrity(bdev);
	if (bi == NULL) {
		TRACE_DBG("Block integrity not supported");
		goto out_no_bi;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	bi_profile_name = bi->name;
#else
	bi_profile_name = bi->profile->name;
#endif
	TRACE_DBG("BI name %s", bi_profile_name);

	if (!strcmp(bi_profile_name, "T10-DIF-TYPE1-CRC")) {
		dev->dev_dif_ip_not_supported = 1;
		if (virt_dev->dif_type != 1) {
			PRINT_ERROR("Integrity type mismatch, %d expected, "
				"but block device has 1 (dev %s)",
				virt_dev->dif_type, dev->virt_name);
			res = -EINVAL;
			goto out_close;
		}
	} else if (!strcmp(bi_profile_name, "T10-DIF-TYPE1-IP")) {
		if (virt_dev->dif_type != 1) {
			PRINT_ERROR("Integrity type mismatch, %d expected, "
				"but block device has 1 (dev %s)",
				virt_dev->dif_type, dev->virt_name);
			res = -EINVAL;
			goto out_close;
		}
	} else if (!strcmp(bi_profile_name, "T10-DIF-TYPE3-CRC")) {
		dev->dev_dif_ip_not_supported = 1;
		if (virt_dev->dif_type != 3) {
			PRINT_ERROR("Integrity type mismatch, %d expected, "
				"but block device has 1 (dev %s)",
				virt_dev->dif_type, dev->virt_name);
			res = -EINVAL;
			goto out_close;
		}
	} else if (!strcmp(bi_profile_name, "T10-DIF-TYPE3-IP")) {
		if (virt_dev->dif_type != 3) {
			PRINT_ERROR("Integrity type mismatch, %d expected, "
				"but block device has 3 (dev %s)",
				virt_dev->dif_type, dev->virt_name);
			res = -EINVAL;
			goto out_close;
		}
	} else {
		PRINT_ERROR("Unable to understand integrity name %s"
			"(dev %s)", bi_profile_name, dev->virt_name);
		res = -EINVAL;
		goto out_close;
	}

	virt_dev->blk_integrity = 1;

	if ((virt_dev->dif_mode & SCST_DIF_MODE_DEV_CHECK) &&
	    !(virt_dev->dif_mode & SCST_DIF_MODE_DEV_STORE)) {
		PRINT_ERROR("Blockio dev_check is not possible without "
			"dev_store (dev %s)", dev->virt_name);
		res = -EINVAL;
		goto out_close;
	}

	if (!(virt_dev->dif_mode & SCST_DIF_MODE_DEV_CHECK))
		PRINT_WARNING("Blk integrity implies dev_check (dev %s)",
			dev->virt_name);

out_no_bi:
	res = 0;

out_close:
	blkdev_put(bdev, FMODE_READ);

out:
	TRACE_EXIT_RES(res);
	return res;
}
#else /* defined(CONFIG_BLK_DEV_INTEGRITY) */
static int vdisk_init_block_integrity(struct scst_vdisk_dev *virt_dev)
{
	PRINT_ERROR("Kernel does not support block device integrity");
	return -EINVAL;
}
#endif /* defined(CONFIG_BLK_DEV_INTEGRITY) */

/*
 * Reexamine size, flush support and thin provisioning support for
 * vdisk_fileio, vdisk_blockio and vdisk_cdrom devices. Do not modify the size
 * of vdisk_nullio devices.
 */
static int vdisk_reexamine(struct scst_vdisk_dev *virt_dev)
{
	int res = 0;

	if (!virt_dev->nullio && !virt_dev->cdrom_empty) {
		loff_t file_size;

		res = vdisk_get_file_size(virt_dev, &file_size);
		if (res < 0) {
			if ((res == -EMEDIUMTYPE) && virt_dev->blockio) {
				TRACE_DBG("Reexam pending (dev %s)", virt_dev->name);
				virt_dev->reexam_pending = 1;
				res = 0;
			}
			goto out;
		}
		virt_dev->file_size = file_size;
		vdisk_blockio_check_flush_support(virt_dev);
		vdisk_check_tp_support(virt_dev);
	} else if (virt_dev->cdrom_empty) {
		virt_dev->file_size = 0;
	}

	virt_dev->nblocks = virt_dev->file_size >> virt_dev->blk_shift;

out:
	return res;
}

static int vdisk_attach(struct scst_device *dev)
{
	int res = 0;
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
	dev->cluster_mode = virt_dev->initial_cluster_mode;

	if ((virt_dev->dif_type == 0) &&
	    ((virt_dev->dif_mode != SCST_DIF_MODE_NONE) ||
	     (virt_dev->dif_filename != NULL))) {
		PRINT_ERROR("Device %s cannot have DIF TYPE 0 if DIF MODE is "
			"not NONE or DIF FILENAME is not NULL", virt_dev->name);
		res = -EINVAL;
		goto out;
	}

	if (virt_dev->blockio) {
		if (!(virt_dev->dif_mode & SCST_DIF_MODE_DEV))
			goto next;

		res = vdisk_init_block_integrity(virt_dev);
		if (res != 0)
			goto out;
	} else if (virt_dev->dif_mode & SCST_DIF_MODE_DEV_CHECK) {
		PRINT_ERROR("dev_check supported only for BLOCKIO devices "
			"(dev %s)!", dev->virt_name);
		res = -EINVAL;
		goto out;
	}

next:
	if ((virt_dev->dif_mode & SCST_DIF_MODE_DEV_STORE) &&
	    (virt_dev->dif_filename == NULL) && !virt_dev->blk_integrity) {
		virt_dev->dif_filename = kasprintf(GFP_KERNEL,
				DEF_DIF_FILENAME_TMPL, dev->virt_name);
		if (virt_dev->dif_filename == NULL) {
			PRINT_ERROR("Allocation of default dif_filename "
				"failed (dev %s)", dev->virt_name);
			res = -ENOMEM;
			goto out;
		}
	}

	if (virt_dev->dev_active && virt_dev->dif_filename != NULL) {
		/* Check if it can be used */
		struct file *dfd = vdev_open_fd(virt_dev, virt_dev->dif_filename,
					virt_dev->rd_only);
		if (IS_ERR(dfd)) {
			res = PTR_ERR(dfd);
			goto out;
		}
		filp_close(dfd, NULL);
	}

	res = scst_set_dif_params(dev, virt_dev->dif_mode, virt_dev->dif_type);
	if (res != 0)
		goto out;

	if (virt_dev->dif_type != 2)
		scst_dev_set_dif_static_app_tag_combined(dev,
			virt_dev->dif_static_app_tag_combined);
	else if (virt_dev->dif_static_app_tag_combined != SCST_DIF_NO_CHECK_APP_TAG)
		PRINT_WARNING("Device %s: static app tag is ignored for DIF "
			"mode 2", dev->virt_name);

	if (virt_dev->dif_filename != NULL) {
		res = scst_create_dev_attr(dev, &vdev_dif_filename_attr);
		if (res != 0) {
			PRINT_ERROR("Can't create attr %s for dev %s",
				vdev_dif_filename_attr.attr.name,
				dev->virt_name);
			goto out;
		}
	}

	if (!virt_dev->async && virt_dev->o_direct_flag) {
		PRINT_ERROR("%s: using o_direct without setting async is not"
			    " supported", virt_dev->filename);
		res = -EINVAL;
		goto out;
	}

	dev->dev_rd_only = virt_dev->rd_only;


	res = vdisk_reexamine(virt_dev);
	if (res < 0)
		goto out;

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO("Attached SCSI target virtual %s %s "
		      "(file=\"%s\", fs=%lldMB, bs=%d, nblocks=%lld,"
		      " cyln=%lld%s)",
		      (dev->type == TYPE_DISK) ? "disk" : "cdrom",
		      virt_dev->name, vdev_get_filename(virt_dev),
		      virt_dev->file_size >> 20, dev->block_size,
		      (unsigned long long)virt_dev->nblocks,
		      (unsigned long long)virt_dev->nblocks/64/32,
		      virt_dev->nblocks < 64*32
		      ? " !WARNING! cyln less than 1" : "");
	} else {
		PRINT_INFO("Attached empty SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	dev->dh_priv = virt_dev;

	dev->tst = virt_dev->tst;
	dev->tmf_only = DEF_TMF_ONLY;
	dev->tmf_only_saved = DEF_TMF_ONLY;
	dev->tmf_only_default = DEF_TMF_ONLY;
	dev->d_sense = DEF_DSENSE;
	dev->d_sense_saved = DEF_DSENSE;
	dev->d_sense_default = DEF_DSENSE;
	if (virt_dev->wt_flag && !virt_dev->nv_cache)
		dev->queue_alg = DEF_QUEUE_ALG_WT;
	else
		dev->queue_alg = DEF_QUEUE_ALG;
	dev->queue_alg_saved = dev->queue_alg;
	dev->queue_alg_default = dev->queue_alg;
	dev->qerr = DEF_QERR;
	dev->qerr_saved = DEF_QERR;
	dev->qerr_default = DEF_QERR;
	dev->swp = DEF_SWP;
	dev->swp_saved = DEF_SWP;
	dev->swp_default = DEF_SWP;
	dev->tas = DEF_TAS;
	dev->tas_saved = DEF_TAS;
	dev->tas_default = DEF_TAS;
	dev->dpicz = DEF_DPICZ;
	dev->dpicz_saved = DEF_DPICZ;
	dev->dpicz_default = DEF_DPICZ;
	if ((virt_dev->dif_filename == NULL) && !virt_dev->blk_integrity)
		dev->ato = SCST_ATO_0_MODIFIED_BY_STORAGE;
	else
		dev->ato = SCST_ATO_1_NOT_MODIFIED_BY_STORAGE;

	if (vdev_saved_mode_pages_enabled)
		vdev_load_mode_pages(virt_dev);

	res = scst_pr_set_cluster_mode(dev, dev->cluster_mode,
				       virt_dev->t10_dev_id);
	if (res)
		goto out;

out:
	TRACE_EXIT();
	return res;
}

/* Detach a virtual device from a device. scst_mutex is supposed to be held. */
static void vdisk_detach(struct scst_device *dev)
{
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_mutex);

	TRACE_DBG("virt_id %d", dev->virt_id);

	scst_pr_set_cluster_mode(dev, false, virt_dev->t10_dev_id);

	PRINT_INFO("Detached virtual device %s (\"%s\")",
		      virt_dev->name, vdev_get_filename(virt_dev));

	/* virt_dev will be freed by the caller */
	dev->dh_priv = NULL;
	virt_dev->dev = NULL;

	TRACE_EXIT();
	return;
}

static bool vdisk_is_open(const struct scst_vdisk_dev *virt_dev)
{
	return virt_dev->fd || virt_dev->bdev;
}

static int vdisk_open_fd(struct scst_vdisk_dev *virt_dev, bool read_only)
{
	int res;

	sBUG_ON(!virt_dev->filename);
	sBUG_ON(vdisk_is_open(virt_dev));

	if (!virt_dev->dev_active) {
		TRACE_MGMT_DBG("Skip opening for not active dev %s",
			       virt_dev->dev->virt_name);
		res = -EMEDIUMTYPE;
	} else if (virt_dev->blockio) {
		virt_dev->bdev_mode = FMODE_READ;
		if (!read_only)
			virt_dev->bdev_mode |= FMODE_WRITE;
		virt_dev->bdev = blkdev_get_by_path(virt_dev->filename,
					virt_dev->bdev_mode, (void *)__func__);
		res = IS_ERR(virt_dev->bdev) ? PTR_ERR(virt_dev->bdev) : 0;
	} else {
		virt_dev->fd = vdev_open_fd(virt_dev, virt_dev->filename,
					    read_only);
		res = IS_ERR(virt_dev->fd) ? PTR_ERR(virt_dev->fd) : 0;
	}
	if (res) {
		virt_dev->bdev = NULL;
		virt_dev->fd = NULL;
		goto out;
	}

	/*
	 * For block devices, get the optimal I/O size from the block device
	 * characteristics.
	 */
	if (virt_dev->bdev && !virt_dev->opt_trans_len_set)
		virt_dev->opt_trans_len = bdev_io_opt(virt_dev->bdev) ? :
					  virt_dev->opt_trans_len;

	if (virt_dev->dif_filename != NULL) {
		virt_dev->dif_fd = vdev_open_fd(virt_dev,
			virt_dev->dif_filename, read_only);
		if (IS_ERR(virt_dev->dif_fd)) {
			res = PTR_ERR(virt_dev->dif_fd);
			virt_dev->dif_fd = NULL;
			goto out_close_fd;
		}
	}

	TRACE_DBG("virt_dev %s: fd %p %p open (dif_fd %p)", virt_dev->name,
		  virt_dev->fd, virt_dev->bdev, virt_dev->dif_fd);

out:
	return res;

out_close_fd:
	if (virt_dev->blockio) {
		blkdev_put(virt_dev->bdev, virt_dev->bdev_mode);
		virt_dev->bdev = NULL;
	} else {
		filp_close(virt_dev->fd, NULL);
		virt_dev->fd = NULL;
	}
	goto out;
}

static void vdisk_close_fd(struct scst_vdisk_dev *virt_dev)
{
	TRACE_DBG("virt_dev %s: closing fd %p %p (dif_fd %p)", virt_dev->name,
		  virt_dev->fd, virt_dev->bdev, virt_dev->dif_fd);

	if (virt_dev->bdev) {
		blkdev_put(virt_dev->bdev, virt_dev->bdev_mode);
		virt_dev->bdev = NULL;
	} else if (virt_dev->fd) {
		filp_close(virt_dev->fd, NULL);
		virt_dev->fd = NULL;
	}
	if (virt_dev->dif_fd) {
		filp_close(virt_dev->dif_fd, NULL);
		virt_dev->dif_fd = NULL;
	}
}

static int vdisk_reopen_fd(struct scst_vdisk_dev *virt_dev, bool read_only)
{
	/*
	 * To do: make this function transactional. That means that it either
	 * succeeds or does not modify the state of @virt_dev.
	 */
	vdisk_close_fd(virt_dev);
	return vdisk_open_fd(virt_dev, read_only);
}

static int vdisk_activate_dev(struct scst_vdisk_dev *virt_dev, bool rd_only)
{
	int rc = 0;

	virt_dev->dev_active = 1;

	/*
	 * Only re-open FD if tgt_dev_cnt is not zero,
	 * otherwise we will leak reference.
	 */
	if (virt_dev->tgt_dev_cnt) {
		rc = vdisk_open_fd(virt_dev, rd_only);
		if (rc) {
			PRINT_ERROR("vdev %s: Unable to open FD: rd_only=%d, rc=%d",
				    virt_dev->name, rd_only, rc);
			virt_dev->dev_active = 0;
			goto out;
		}
	}

	if (virt_dev->reexam_pending) {
		rc = vdisk_reexamine(virt_dev);
		WARN_ON(rc != 0);
		virt_dev->reexam_pending = 0;
	}

out:
	return rc;
}

static void vdisk_disable_dev(struct scst_vdisk_dev *virt_dev)
{
	/* Close the FD here */
	vdisk_close_fd(virt_dev);
	virt_dev->dev_active = 0;
}

/* Invoked with scst_mutex held, so no further locking is necessary here. */
static int vdisk_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_dev *virt_dev = tgt_dev->dev->dh_priv;
	int res = 0;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_mutex);

	virt_dev->tgt_dev_cnt++;

	if (vdisk_is_open(virt_dev))
		goto out;

	if (!virt_dev->nullio && !virt_dev->cdrom_empty) {
		res = vdisk_open_fd(virt_dev, tgt_dev->dev->dev_rd_only);
		if (res != 0) {
			if ((res == -EMEDIUMTYPE) && virt_dev->blockio) {
				/* It's OK, it will be reopen on exec */
				res = 0;
			} else {
				virt_dev->tgt_dev_cnt--;
				goto out;
			}
		}
	} else {
		virt_dev->fd = NULL;
		virt_dev->bdev = NULL;
		virt_dev->dif_fd = NULL;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Invoked with scst_mutex held, so no further locking is necessary here. */
static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_dev *virt_dev = tgt_dev->dev->dh_priv;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_mutex);

	if (--virt_dev->tgt_dev_cnt == 0)
		vdisk_close_fd(virt_dev);

	TRACE_EXIT();
	return;
}

static int __vdisk_fsync_fileio(loff_t loff,
	loff_t len, struct scst_device *dev, struct scst_cmd *cmd,
	struct file *file)
{
	int res;

	TRACE_ENTRY();

	/**
	 ** !!! CAUTION !!!: cmd can be NULL here! Don't use it for
	 ** anything without checking for NULL at first !!!
	 **/

	/* BLOCKIO can be here for DIF tags fsync */

#if 0	/* For sparse files we might need to sync metadata as well */
	res = generic_write_sync(file, loff, len);
#else
	res = filemap_write_and_wait_range(file->f_mapping, loff, len);
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

	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_fsync_blockio(loff_t loff,
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

	/* Must be first, because vdisk_blockio_flush() can call scst_cmd_done()! */
	if (virt_dev->dif_fd != NULL) {
		loff = (loff >> dev->block_shift) << SCST_DIF_TAG_SHIFT;
		len = (len >> dev->block_shift) << SCST_DIF_TAG_SHIFT;
		res = __vdisk_fsync_fileio(loff, len, dev, cmd,
			virt_dev->dif_fd);
		if (unlikely(res != 0))
			goto out;
	}

	res = vdisk_blockio_flush(virt_dev->bdev, gfp_flags, true,
		cmd, async);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_fsync_fileio(loff_t loff,
	loff_t len, struct scst_device *dev, struct scst_cmd *cmd, bool async)
{
	int res;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

	/**
	 ** !!! CAUTION !!!: cmd can be NULL here! Don't use it for
	 ** anything without checking for NULL at first !!!
	 **/

	res = __vdisk_fsync_fileio(loff, len, dev, cmd, virt_dev->fd);
	if (unlikely(res != 0))
		goto done;

	if (virt_dev->dif_fd != NULL) {
		loff = (loff >> dev->block_shift) << SCST_DIF_TAG_SHIFT;
		len = (len >> dev->block_shift) << SCST_DIF_TAG_SHIFT;
		res = __vdisk_fsync_fileio(loff, len, dev, cmd,
			virt_dev->dif_fd);
	}

done:
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

static int vdisk_fsync(loff_t loff,
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

	if (virt_dev->nullio)
		;
	else if (virt_dev->blockio)
		res = vdisk_fsync_blockio(loff, len, dev, gfp_flags, cmd, async);
	else
		res = vdisk_fsync_fileio(loff, len, dev, cmd, async);

out:
	TRACE_EXIT_RES(res);
	return res;
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
	      (unsigned long long)loff,
	      (unsigned long long)data_len, immed);

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
		vdisk_fsync(loff, data_len, dev, cmd->cmd_gfp_mask, NULL, true);
		/* ToDo: vdisk_fsync() error processing */
		scst_cmd_put(cmd);
		res = RUNNING_ASYNC;
	} else {
		vdisk_fsync(loff, data_len, dev, cmd->cmd_gfp_mask, cmd, true);
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

	vdisk_fsync(0, virt_dev->file_size, dev, cmd->cmd_gfp_mask, cmd, false);

	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_nop(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_send_diagnostic(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static int vdisk_format_dif(struct scst_cmd *cmd, uint64_t start_lba,
	uint64_t blocks)
{
	int res = 0;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	loff_t loff;
	loff_t err = 0;
	ssize_t full_len;
	struct file *fd = virt_dev->dif_fd;
	struct kvec *kvec;
	int max_kvec_segs, kvec_segs, i;
	struct page *kvec_page, *data_page;
	uint8_t *data_buf;
	int64_t left, done;

	TRACE_ENTRY();

	if (virt_dev->dif_fd == NULL)
		goto out;

	EXTRACHECKS_BUG_ON(!(dev->dev_dif_mode & SCST_DIF_MODE_DEV_STORE));

	kvec_page = alloc_page(GFP_KERNEL);
	if (kvec_page == NULL) {
		PRINT_ERROR("Unable to allocate kvec page");
		scst_set_busy(cmd);
		res = -ENOMEM;
		goto out;
	}

	data_page = alloc_page(GFP_KERNEL);
	if (data_page == NULL) {
		PRINT_ERROR("Unable to allocate tags data page");
		scst_set_busy(cmd);
		res = -ENOMEM;
		goto out_free_kvec;
	}

	data_buf = page_address(data_page);
	memset(data_buf, 0xFF, PAGE_SIZE);

	kvec = page_address(kvec_page);
	max_kvec_segs = min_t(int, UIO_MAXIOV, (int)PAGE_SIZE/sizeof(*kvec));

	for (i = 0; i < max_kvec_segs; i++)
		kvec[i].iov_base = data_buf;

	loff = start_lba << SCST_DIF_TAG_SHIFT;
	left = blocks << SCST_DIF_TAG_SHIFT;
	done = 0;
	while (left > 0) {
		kvec_segs = 0;
		full_len = 0;
		i = -1;
		while (1) {
			int len = min_t(size_t, (size_t)left, PAGE_SIZE);

			full_len += len;
			i++;
			kvec_segs++;
			kvec[i].iov_len = len;
			left -= len;
			done += len;
			EXTRACHECKS_BUG_ON(left < 0);
			if (kvec_segs == max_kvec_segs || left == 0)
				break;
		}

		TRACE_DBG("Formatting DIF: full_len %zd, off %lld",
			full_len, (long long)loff);

		/* WRITE */
		err = scst_writev(fd, kvec, kvec_segs, &loff);
		if (err < 0) {
			PRINT_ERROR("Formatting DIF write() returned %lld from "
				"%zd", err, full_len);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_write_error));
			res = err;
			goto out_free_data_page;
		} else if (err < full_len) {
			/*
			 * If a write() is interrupted by a signal handler before
			 * any bytes are written, then the call fails with the
			 * error EINTR; if it is interrupted after at least one
			 * byte has been written, the call succeeds, and returns
			 * the number of bytes written  --  manpage write(2)
			 */
			left += full_len - err;
			done -= full_len - err;
		}

		virt_dev->format_progress_done = done;
	}

out_free_data_page:
	__free_page(data_page);

out_free_kvec:
	__free_page(kvec_page);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_unmap_file_range(struct scst_cmd *cmd,
	struct scst_vdisk_dev *virt_dev, loff_t off, loff_t len,
	struct file *fd)
{
	int res;

	TRACE_ENTRY();

	TRACE_DBG("Fallocating range %lld, len %lld",
		(unsigned long long)off, (unsigned long long)len);

	res = fd->f_op->fallocate(fd,
		FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off, len);
	if (unlikely(res == -EOPNOTSUPP)) {
		PRINT_WARNING_ONCE("%s: fallocate() is not supported by the filesystem. Consider setting 'thin_provisioned' to 0 in scst.conf for %s.\n",
				   virt_dev->name, virt_dev->name);
		res = 0;
	} else if (unlikely(res != 0)) {
		PRINT_WARNING_ONCE("fallocate() for %lld, len %lld "
			"failed: %d", (unsigned long long)off,
			(unsigned long long)len, res);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_write_error));
		res = -EIO;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_unmap_range(struct scst_cmd *cmd,
	struct scst_vdisk_dev *virt_dev, uint64_t start_lba, uint64_t blocks)
{
	int res, err;

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
		  (unsigned long long)start_lba, blocks);

	if (virt_dev->blockio) {
		struct block_device *bdev = virt_dev->bdev;
		sector_t start_sector = start_lba << (cmd->dev->block_shift - 9);
		sector_t nr_sects = blocks << (cmd->dev->block_shift - 9);
		gfp_t gfp = cmd->cmd_gfp_mask;

		err = blkdev_issue_discard(bdev, start_sector, nr_sects, gfp);
		if (unlikely(err != 0)) {
			PRINT_ERROR("blkdev_issue_discard() for "
				"LBA %lld, blocks %lld failed: %d",
				(unsigned long long)start_lba, blocks, err);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
			res = -EIO;
			goto out;
		}
	} else {
		loff_t off = start_lba << cmd->dev->block_shift;
		loff_t len = blocks << cmd->dev->block_shift;
		struct file *fd = virt_dev->fd;

		res = vdisk_unmap_file_range(cmd, virt_dev, off, len, fd);
		if (unlikely(res != 0))
			goto out;
	}

	if (virt_dev->dif_fd != NULL) {
		res = vdisk_format_dif(cmd, start_lba, blocks);
		if (unlikely(res != 0))
			goto out;
	}

success:
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e vdisk_exec_format_unit(struct vdisk_cmd_params *p)
{
	int res = CMD_SUCCEEDED;
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	uint8_t *buf;
	int prot_type = dev->dev_dif_type, pinfo;
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

		length = scst_get_buf_full_sense(cmd, &buf);
		TRACE_DBG("length %d", length);
		if (unlikely(length <= 0))
			goto out;

		TRACE_BUFF_FLAG(TRACE_DEBUG, "Format buf", buf, 64);

		if (length < 4) {
			PRINT_ERROR("FORMAT UNIT: too small parameters list "
				"header %d (dev %s)", length, dev->virt_name);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
			goto out_put;
		}

		prot_usage = buf[0] & 7;
		immed = buf[1] & 2;

		if ((buf[1] & 8) != 0) {
			PRINT_ERROR("FORMAT UNIT: initialization pattern not "
				"supported");
			scst_set_invalid_field_in_parm_list(cmd, 1,
				SCST_INVAL_FIELD_BIT_OFFS_VALID | 3);
			goto out_put;
		}

		if (cmd->cdb[1] & 0x20) { /* LONGLIST */
			if (length < 8) {
				PRINT_ERROR("FORMAT UNIT: too small long "
					"parameters list header %d (dev %s)",
					length, dev->virt_name);
				scst_set_invalid_field_in_cdb(cmd, 1,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 5);
				goto out_put;
			}
			if ((buf[3] & 0xF0) != 0) {
				PRINT_ERROR("FORMAT UNIT: P_I_INFORMATION must "
					"be 0 (dev %s)", dev->virt_name);
				scst_set_invalid_field_in_parm_list(cmd, 3,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
				goto out_put;
			}
			if ((buf[3] & 0xF) != 0) {
				PRINT_ERROR("FORMAT UNIT: PROTECTION INTERVAL "
					"EXPONENT %d not supported (dev %s)",
					buf[3] & 0xF, dev->virt_name);
				scst_set_invalid_field_in_parm_list(cmd, 3,
					SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
				goto out_put;
			}
		} else {
			/* Nothing to do */
		}

		scst_put_buf_full(cmd, buf);

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
			sBUG();
			break;
		}
	}

	TRACE_DBG("prot_type %d, pinfo %d, immed %d (cmd %p)", prot_type,
		pinfo, immed, cmd);

	if (prot_type != dev->dev_dif_type) {
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
	virt_dev->format_progress_to_do = virt_dev->nblocks << SCST_DIF_TAG_SHIFT;

	if (virt_dev->thin_provisioned) {
		int rc = vdisk_unmap_range(cmd, virt_dev, 0, virt_dev->nblocks);

		if (rc != 0)
			goto finished;
	}

	if (pinfo != 0)
		vdisk_format_dif(cmd, 0, virt_dev->nblocks);

finished:
	spin_lock(&virt_dev->flags_lock);
	virt_dev->format_active = 0;
	spin_unlock(&virt_dev->flags_lock);

	if (immed)
		scst_cmd_put(cmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_put:
	scst_put_buf_full(cmd, buf);
	goto out;
}

static enum compl_status_e vdisk_invalid_opcode(struct vdisk_cmd_params *p)
{
	TRACE_DBG("Invalid opcode %s", scst_get_opcode_name(p->cmd));
	return INVALID_OPCODE;
}

#define VDEV_DEF_RDPROTECT	0xE0
#define VDEV_DEF_WRPROTECT	0xE0
#define VDEV_DEF_VRPROTECT	0xE0

#define VDEF_DEF_GROUP_NUM	0

static const struct scst_opcode_descriptor scst_op_descr_cwr = {
	.od_opcode = COMPARE_AND_WRITE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { COMPARE_AND_WRITE, VDEV_DEF_WRPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0, 0, 0, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_format_unit = {
	.od_opcode = FORMAT_UNIT,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_LONG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { FORMAT_UNIT, 0xF0, 0, 0, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};

#if 0
static const struct scst_opcode_descriptor scst_op_descr_get_lba_status = {
	.od_opcode = SERVICE_ACTION_IN_16,
	.od_serv_action = SAI_GET_LBA_STATUS,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SERVICE_ACTION_IN_16, SAI_GET_LBA_STATUS,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
#endif

static const struct scst_opcode_descriptor scst_op_descr_allow_medium_removal = {
	.od_opcode = ALLOW_MEDIUM_REMOVAL,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { ALLOW_MEDIUM_REMOVAL, 0, 0, 0, 3, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read6 = {
	.od_opcode = READ_6,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_6, 0x1F,
			       0xFF, 0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read10 = {
	.od_opcode = READ_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_10, VDEV_DEF_RDPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read12 = {
	.od_opcode = READ_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_12, VDEV_DEF_RDPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read16 = {
	.od_opcode = READ_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_16, VDEV_DEF_RDPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_READ_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_READ_32, VDEV_DEF_RDPROTECT | 0x18, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_read_capacity = {
	.od_opcode = READ_CAPACITY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_CAPACITY, 0, 0, 0, 0, 0, 0,
			       0, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read_capacity16 = {
	.od_opcode = SERVICE_ACTION_IN_16,
	.od_serv_action = SAI_READ_CAPACITY_16,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SERVICE_ACTION_IN_16, SAI_READ_CAPACITY_16,
			       0, 0, 0, 0, 0, 0, 0, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_start_stop_unit = {
	.od_opcode = START_STOP,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { START_STOP, 1, 0, 0xF, 0xF7, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_sync_cache10 = {
	.od_opcode = SYNCHRONIZE_CACHE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SYNCHRONIZE_CACHE, 2,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_sync_cache16 = {
	.od_opcode = SYNCHRONIZE_CACHE_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SYNCHRONIZE_CACHE_16, 2,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_unmap = {
	.od_opcode = UNMAP,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { UNMAP, 0, 0, 0, 0, 0, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify10 = {
	.od_opcode = VERIFY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VERIFY, VDEV_DEF_VRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify12 = {
	.od_opcode = VERIFY_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VERIFY_12, VDEV_DEF_VRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify16 = {
	.od_opcode = VERIFY_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VERIFY_16, VDEV_DEF_VRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_VERIFY_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_VERIFY_32, VDEV_DEF_VRPROTECT | 0x16, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_write6 = {
	.od_opcode = WRITE_6,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_6, 0x1F,
			       0xFF, 0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write10 = {
	.od_opcode = WRITE_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_10, VDEV_DEF_WRPROTECT | 0x1A,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write12 = {
	.od_opcode = WRITE_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_12, VDEV_DEF_WRPROTECT | 0x1A,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write16 = {
	.od_opcode = WRITE_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_16, VDEV_DEF_WRPROTECT | 0x1A,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_WRITE_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_WRITE_32, VDEV_DEF_WRPROTECT | 0x1A, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify10 = {
	.od_opcode = WRITE_VERIFY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_VERIFY, VDEV_DEF_WRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify12 = {
	.od_opcode = WRITE_VERIFY_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_VERIFY_12, VDEV_DEF_WRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify16 = {
	.od_opcode = WRITE_VERIFY_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_VERIFY_16, VDEV_DEF_WRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_WRITE_VERIFY_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_WRITE_VERIFY_32, VDEV_DEF_WRPROTECT | 0x16, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_write_same10 = {
	.od_opcode = WRITE_SAME,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_SAME, VDEV_DEF_WRPROTECT | 0x8,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_same16 = {
	.od_opcode = WRITE_SAME_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_SAME_16, VDEV_DEF_WRPROTECT | 0x8,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_same32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_WRITE_SAME_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_WRITE_SAME_32, VDEV_DEF_WRPROTECT | 0x8, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_read_toc = {
	.od_opcode = READ_TOC,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_TOC, 0, 0xF, 0, 0, 0, 0xFF,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

#define SHARED_OPCODE_DESCRIPTORS					\
	&scst_op_descr_sync_cache10,					\
	&scst_op_descr_sync_cache16,					\
	&scst_op_descr_mode_sense6,					\
	&scst_op_descr_mode_sense10,					\
	&scst_op_descr_mode_select6,					\
	&scst_op_descr_mode_select10,					\
	&scst_op_descr_log_select,					\
	&scst_op_descr_log_sense,					\
	&scst_op_descr_start_stop_unit,					\
	&scst_op_descr_read_capacity,					\
	&scst_op_descr_send_diagnostic,					\
	&scst_op_descr_rtpg,						\
	&scst_op_descr_read6,						\
	&scst_op_descr_read10,						\
	&scst_op_descr_read12,						\
	&scst_op_descr_read16,						\
	&scst_op_descr_write6,						\
	&scst_op_descr_write10,						\
	&scst_op_descr_write12,						\
	&scst_op_descr_write16,						\
	&scst_op_descr_write_verify10,					\
	&scst_op_descr_write_verify12,					\
	&scst_op_descr_write_verify16,					\
	&scst_op_descr_verify10,					\
	&scst_op_descr_verify12,					\
	&scst_op_descr_verify16,

#define VDISK_OPCODE_DESCRIPTORS					\
	/* &scst_op_descr_get_lba_status, */				\
	&scst_op_descr_read_capacity16,					\
	&scst_op_descr_write_same10,					\
	&scst_op_descr_write_same16,					\
	&scst_op_descr_unmap,						\
	&scst_op_descr_format_unit,					\
	&scst_op_descr_extended_copy,					\
	&scst_op_descr_cwr,

static const struct scst_opcode_descriptor *vdisk_opcode_descriptors[] = {
	SHARED_OPCODE_DESCRIPTORS
	VDISK_OPCODE_DESCRIPTORS
	SCST_OPCODE_DESCRIPTORS
	&scst_op_descr_stpg, /* must be last, see vdisk_get_supported_opcodes()! */
};

static const struct scst_opcode_descriptor *vdisk_opcode_descriptors_type2[] = {
	SHARED_OPCODE_DESCRIPTORS
	VDISK_OPCODE_DESCRIPTORS
	&scst_op_descr_read32,
	&scst_op_descr_write32,
	&scst_op_descr_verify32,
	&scst_op_descr_write_verify32,
	&scst_op_descr_write_same32,
	SCST_OPCODE_DESCRIPTORS
	&scst_op_descr_stpg, /* must be last, see vdisk_get_supported_opcodes()! */
};

static const struct scst_opcode_descriptor *vcdrom_opcode_descriptors[] = {
	SHARED_OPCODE_DESCRIPTORS
	&scst_op_descr_allow_medium_removal,
	&scst_op_descr_read_toc,
	SCST_OPCODE_DESCRIPTORS
};

static int vdisk_get_supported_opcodes(struct scst_cmd *cmd,
	const struct scst_opcode_descriptor ***out_supp_opcodes,
	int *out_supp_opcodes_cnt)
{
	struct scst_device *dev = cmd->dev;

	if (cmd->dev->dev_dif_type != 2) {
		*out_supp_opcodes = vdisk_opcode_descriptors;
		*out_supp_opcodes_cnt = ARRAY_SIZE(vdisk_opcode_descriptors);
	} else {
		*out_supp_opcodes = vdisk_opcode_descriptors_type2;
		*out_supp_opcodes_cnt = ARRAY_SIZE(vdisk_opcode_descriptors_type2);
	}
	if (!dev->expl_alua) {
		(*out_supp_opcodes_cnt)--;
		sBUG_ON((*out_supp_opcodes)[*out_supp_opcodes_cnt]->od_serv_action != MO_SET_TARGET_PGS);
	}
	return 0;
}

static int vcdrom_get_supported_opcodes(struct scst_cmd *cmd,
	const struct scst_opcode_descriptor ***out_supp_opcodes,
	int *out_supp_opcodes_cnt)
{
	*out_supp_opcodes = vcdrom_opcode_descriptors;
	*out_supp_opcodes_cnt = ARRAY_SIZE(vcdrom_opcode_descriptors);
	return 0;
}

/*
 * Compute p->loff and p->fua.
 * Returns true for success or false otherwise and set error in the command.
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
	bool res;
	bool fua = false;

	TRACE_ENTRY();

	if (unlikely(!(cmd->op_flags & SCST_INFO_VALID))) {
		TRACE(TRACE_MINOR, "Unknown opcode %s", scst_get_opcode_name(cmd));
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
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
		TRACE(TRACE_ORDER, "ORDERED cmd %p (op %s)", cmd,
			scst_get_opcode_name(cmd));
		break;
	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		TRACE(TRACE_ORDER, "HQ cmd %p (op %s)", cmd,
			scst_get_opcode_name(cmd));
		break;
	case SCST_CMD_QUEUE_ACA:
	case SCST_CMD_QUEUE_SIMPLE:
	case SCST_CMD_QUEUE_UNTAGGED:
	default:
		break;
	}

	lba_start = scst_cmd_get_lba(cmd);
	data_len = scst_cmd_get_data_len(cmd);

	loff = (loff_t)lba_start << dev->block_shift;
	TRACE_DBG("cmd %p, lba_start %lld, loff %lld, data_len %lld", cmd,
		  (unsigned long long)lba_start,
		  (unsigned long long)loff,
		  (unsigned long long)data_len);

	EXTRACHECKS_BUG_ON((loff < 0) || unlikely(data_len < 0));

	if (unlikely((loff + data_len) > virt_dev->file_size) &&
	    (!(cmd->op_flags & SCST_LBA_NOT_VALID))) {
		if (virt_dev->cdrom_empty) {
			TRACE_DBG("%s", "CDROM empty");
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_no_medium));
		} else {
			PRINT_INFO("Access beyond the end of device %s "
				"(%lld of %lld, data len %lld)", virt_dev->name,
				(unsigned long long)loff,
				(unsigned long long)virt_dev->file_size,
				(unsigned long long)data_len);
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
					scst_sense_block_out_range_error));
		}
		res = false;
		goto out;
	}

	switch (opcode) {
	case VARIABLE_LENGTH_CMD:
		if (cmd->cdb[9] == SUBCODE_WRITE_32) {
			fua = (cdb[10] & 0x8);
			if (fua)
				TRACE(TRACE_ORDER, "FUA: loff=%lld, data_len=%lld",
					loff, data_len);
		}
		break;
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		fua = (cdb[1] & 0x8);
		if (fua) {
			TRACE(TRACE_ORDER, "FUA: loff=%lld, "
				"data_len=%lld", (unsigned long long)loff,
				(unsigned long long)data_len);
		}
		break;
	}

	p->loff = loff;
	p->fua = fua;

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

	p = kmem_cache_zalloc(vdisk_cmd_param_cachep,
			      in_interrupt() ? GFP_ATOMIC : cmd->cmd_gfp_mask);
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

static int fileio_parse(struct scst_cmd *cmd)
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

static enum scst_exec_res vdev_do_job(struct scst_cmd *cmd,
				      const vdisk_op_fn *ops)
{
	enum scst_exec_res res;
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
	TRACE_DBG("Invalid opcode %s", scst_get_opcode_name(cmd));
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	goto out_compl;
}

static enum scst_exec_res fileio_exec(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	const vdisk_op_fn *ops = virt_dev->vdev_devt->devt_priv;

	EXTRACHECKS_BUG_ON(!ops);
	return vdev_do_job(cmd, ops);
}

struct bio_priv_sync {
	struct completion c;
	int error;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
static void blockio_end_sync_io(struct bio *bio, int error)
{
#else
static void blockio_end_sync_io(struct bio *bio)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0) &&	\
	!defined(CONFIG_SUSE_KERNEL)
	int error = bio->bi_error;
#else
	int error = blk_status_to_errno(bio->bi_status);
#endif
#endif
	struct bio_priv_sync *s = bio->bi_private;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	if (!bio_flagged(bio, BIO_UPTODATE) && error == 0) {
		PRINT_ERROR("Not up to date bio with error 0; returning -EIO");
		error = -EIO;
	}
#endif

	s->error = error;
	complete(&s->c);

	return;
}

/*
 * blockio_read_sync() - read up to @len bytes from a block I/O device
 *
 * Returns:
 * - A negative value if an error occurred.
 * - Zero if len == 0.
 * - A positive value <= len if I/O succeeded.
 *
 * Note:
 * Increments *@loff with the number of bytes transferred upon success.
 */
static ssize_t blockio_read_sync(struct scst_vdisk_dev *virt_dev, void *buf,
				 size_t len, loff_t *loff)
{
	struct bio_priv_sync s = {
		COMPLETION_INITIALIZER_ONSTACK(s.c), 0,
	};
	struct block_device *bdev = virt_dev->bdev;
	const bool is_vmalloc = is_vmalloc_addr(buf);
	struct bio *bio;
	void *p;
	struct page *q;
	int max_nr_vecs, rc;
	unsigned int bytes, off;
	ssize_t ret = -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	max_nr_vecs = BIO_MAX_VECS;
#else
	max_nr_vecs = min(bio_get_nr_vecs(bdev), BIO_MAX_VECS);
#endif

	bio = bio_alloc_bioset(/*bdev=*/NULL, max_nr_vecs, /*opf=*/0,
			       GFP_KERNEL, virt_dev->vdisk_bioset);
	if (!bio)
		goto out;

#if (!defined(CONFIG_SUSE_KERNEL) &&			\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	bio->bi_rw = READ_SYNC;
#else
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
#endif
	bio_set_dev(bio, bdev);
	bio->bi_end_io = blockio_end_sync_io;
	bio->bi_private = &s;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
	bio->bi_sector = *loff >> 9;
#else
	bio->bi_iter.bi_sector = *loff >> 9;
#endif
	for (p = buf; p < buf + len; p += bytes) {
		off = offset_in_page(p);
		bytes = min_t(size_t, PAGE_SIZE - off, buf + len - p);
		q = is_vmalloc ? vmalloc_to_page(p) : virt_to_page(p);
		rc = bio_add_page(bio, q, bytes, off);
		if (rc < bytes) {
			if (rc <= 0 && p == buf) {
				goto free;
			} else {
				if (rc > 0)
					p += rc;
				break;
			}
		}
	}
#if (!defined(CONFIG_SUSE_KERNEL) &&			 \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	submit_bio(bio->bi_rw, bio);
#else
	submit_bio(bio);
#endif
	wait_for_completion(&s.c);
	ret = (unsigned long)s.error;
	if (likely(ret == 0)) {
		ret = p - buf;
		*loff += ret;
	}

free:
	bio_put(bio);

out:
	return ret;
}

/* Note: Updates *@loff if reading succeeded except for NULLIO devices. */
static ssize_t vdev_read_sync(struct scst_vdisk_dev *virt_dev, void *buf,
			      size_t len, loff_t *loff)
{
	ssize_t read, res;

	if (virt_dev->nullio) {
		return len;
	} else if (virt_dev->blockio) {
		for (read = 0; read < len; read += res) {
			res = blockio_read_sync(virt_dev, buf + read,
						len - read, loff);
			if (res < 0)
				return res;
		}
		return read;
	} else {
		return kernel_read(virt_dev->fd, buf, len, loff);
	}
}

static enum compl_status_e vdev_verify(struct scst_cmd *cmd, loff_t loff)
{
	loff_t err;
	ssize_t length, len_mem = 0;
	uint8_t *address_sav, *address = NULL;
	int compare;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	uint8_t *mem_verify = NULL;
	int64_t data_len = scst_cmd_get_data_len(cmd);
	enum scst_dif_actions checks = scst_get_dif_checks(cmd->cmd_dif_actions);

	TRACE_ENTRY();

	if (vdisk_fsync(loff, data_len, cmd->dev,
			cmd->cmd_gfp_mask, cmd, false) != 0)
		goto out;

	/*
	 * For file I/O, unless the cache is cleared prior the verifying,
	 * there is not much point in this code. ToDo.
	 *
	 * Nevertherless, this code is valuable if the data have not been read
	 * from the file/disk yet.
	 */

	compare = scst_cmd_get_data_direction(cmd) == SCST_DATA_WRITE;
	TRACE_DBG("VERIFY with compare %d at offset %lld and len %lld\n",
		  compare, loff, (long long)data_len);

	mem_verify = vmalloc(LEN_MEM);
	if (mem_verify == NULL) {
		PRINT_ERROR("Unable to allocate memory %d for verify",
			       LEN_MEM);
		scst_set_busy(cmd);
		goto out;
	}

	if (compare) {
		length = scst_get_buf_first(cmd, &address);
		address_sav = address;
	} else
		length = data_len;

	while (length > 0) {
		len_mem = (length > LEN_MEM) ? LEN_MEM : length;
		TRACE_DBG("Verify: length %zd - len_mem %zd", length, len_mem);

		err = vdev_read_sync(virt_dev, mem_verify, len_mem, &loff);
		if ((err < 0) || (err < len_mem)) {
			PRINT_ERROR("verify() returned %lld from %zd",
				    (unsigned long long)err, len_mem);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			if (compare)
				scst_put_buf(cmd, address_sav);
			goto out_free;
		}

		if (compare && memcmp(address, mem_verify, len_mem) != 0) {
			TRACE_DBG("Verify: error memcmp length %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_miscompare_error));
			scst_put_buf(cmd, address_sav);
			goto out_free;
		}

		if (checks != 0) {
			/* ToDo: check DIF tags as well */
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
		    SCST_LOAD_SENSE(scst_sense_internal_failure));
	}

out_free:
	if (mem_verify)
		vfree(mem_verify);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

struct scst_verify_work {
	struct work_struct work;
	struct scst_cmd *cmd;
};

static void scst_do_verify_work(struct work_struct *work)
{
	struct scst_verify_work *w = container_of(work, typeof(*w), work);
	struct scst_cmd *cmd = w->cmd;
	struct scst_device *dev = cmd->dev;
	loff_t loff = scst_cmd_get_lba(cmd) << dev->block_shift;

	kfree(w);
	WARN_ON_ONCE(vdev_verify(cmd, loff) != CMD_SUCCEEDED);
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
/*
 * See also commit 2ba48ce513c4 ("mirror O_APPEND and O_DIRECT into
 * iocb->ki_flags") # v4.1.
 */
static bool do_fileio_async(const struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	if (!virt_dev->async || dev->dev_dif_mode != SCST_DIF_MODE_NONE)
		return false;
	switch (cmd->data_direction) {
	case SCST_DATA_READ:
	case SCST_DATA_WRITE:
		return true;
	default:
		return false;
	}
}

static bool vdisk_alloc_async_bvec(struct scst_cmd *cmd,
				   struct vdisk_cmd_params *p)
{
	int n;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	n = scst_get_buf_page_count(cmd);
#else
	n = scst_get_buf_count(cmd);
#endif
	if (n <= ARRAY_SIZE(p->async.small_bvec)) {
		p->async.bvec = &p->async.small_bvec[0];
		return true;
	}

	p->async.bvec = kmalloc_array(n, sizeof(*p->async.bvec),
				      cmd->cmd_gfp_mask);
	if (p->async.bvec == NULL) {
		PRINT_ERROR("Unable to allocate bvec (%d)", n);
		return false;
	}

	return true;
}

static inline
struct bio_vec *vdisk_map_pages_to_bvec(struct bio_vec *bvec, struct page *page,
					ssize_t length, int offset)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	ssize_t page_len = min_t(ssize_t, length, PAGE_SIZE - offset);
#else
	ssize_t page_len = length;
#endif

	*bvec++ = (struct bio_vec) {
		.bv_page   = page,
		.bv_offset = offset,
		.bv_len    = page_len,
	};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	length -= page_len;

	while (length > 0) {
		page++;
		page_len = min_t(ssize_t, length, PAGE_SIZE);

		*bvec++ = (struct bio_vec) {
			.bv_page   = page,
			.bv_offset = 0,
			.bv_len    = page_len,
		};

		length -= page_len;
	}
#endif

	return bvec;
}

static void fileio_async_complete(struct kiocb *iocb, long ret
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
				  , long ret2
#endif
				  )
{
	struct vdisk_cmd_params *p = container_of(iocb, typeof(*p), async.iocb);
	struct scst_cmd *cmd = p->cmd;

	if (ret >= 0 && ret != cmd->bufflen)
		scst_set_resp_data_len(cmd, ret);

	if (ret < 0 &&
	    scst_cmd_get_data_direction(cmd) & SCST_DATA_WRITE) {
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_write_error));
	} else if (ret < 0) {
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
	} else if (cmd->do_verify) {
		struct scst_verify_work *w = kmalloc(sizeof(*w), GFP_ATOMIC);

		cmd->do_verify = false;
		if (w) {
			INIT_WORK(&w->work, scst_do_verify_work);
			w->cmd = cmd;
			schedule_work(&w->work);
			return;
		} else {
			scst_set_busy(cmd);
		}
	}
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, scst_estimate_context());
}

static enum compl_status_e fileio_exec_async(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	struct file *fd = virt_dev->fd;
	struct iov_iter iter = { };
	ssize_t length, total = 0;
	struct bio_vec *bvec;
	struct page *page;
	struct kiocb *iocb = &p->async.iocb;
	int offset, sg_cnt = 0, dir, ret;

	switch (cmd->data_direction) {
	case SCST_DATA_READ:
		dir = READ;
		break;
	case SCST_DATA_WRITE:
		dir = WRITE;
		break;
	default:
		WARN_ON_ONCE(true);
		return CMD_FAILED;
	}

	if (!vdisk_alloc_async_bvec(cmd, p)) {
		scst_set_busy(cmd);
		return CMD_SUCCEEDED;
	}

	p->execute_async = true;

	bvec = p->async.bvec;
	length = scst_get_sg_page_first(cmd, &page, &offset);
	while (length) {
		bvec = vdisk_map_pages_to_bvec(bvec, page, length, offset);

		total += length;
		sg_cnt++;
		length = scst_get_sg_page_next(cmd, &page, &offset);
	}

	WARN_ON_ONCE(sg_cnt != cmd->sg_cnt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || 	\
		(defined(RHEL_RELEASE_CODE) && 		\
		 RHEL_RELEASE_CODE -0 >= RHEL_RELEASE_VERSION(8, 2))
	iov_iter_bvec(&iter, dir, p->async.bvec, sg_cnt, total);
#else
	iov_iter_bvec(&iter, ITER_BVEC | dir, p->async.bvec, sg_cnt, total);
#endif
	*iocb = (struct kiocb) {
		.ki_pos = p->loff,
		.ki_filp = fd,
		.ki_complete = fileio_async_complete,
	};
	if (virt_dev->o_direct_flag)
		iocb->ki_flags |= IOCB_DIRECT | IOCB_NOWAIT;
	if (dir == WRITE && virt_dev->wt_flag && !virt_dev->nv_cache)
		iocb->ki_flags |= IOCB_DSYNC;
	for (;;) {
		if (dir == WRITE)
			ret = call_write_iter(fd, iocb, &iter);
		else
			ret = call_read_iter(fd, iocb, &iter);
		if (ret >= 0 || (ret != -EOPNOTSUPP && ret != -EAGAIN))
			break;
		if (iocb->ki_flags & IOCB_NOWAIT)
			iocb->ki_flags &= ~IOCB_NOWAIT;
		else
			break;
	}
	if (p->async.bvec != p->async.small_bvec)
		kfree(p->async.bvec);
	if (ret != -EIOCBQUEUED) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
		fileio_async_complete(iocb, ret, 0);
#else
		fileio_async_complete(iocb, ret);
#endif
	}
	/*
	 * Return RUNNING_ASYNC even if fileio_async_complete() has been
	 * called because that function calls cmd->scst_cmd_done().
	 */
	return RUNNING_ASYNC;
}
#else
static bool do_fileio_async(const struct vdisk_cmd_params *p)
{
	return false;
}

static enum compl_status_e fileio_exec_async(struct vdisk_cmd_params *p)
{
	WARN_ON_ONCE(true);
	return CMD_FAILED;
}
#endif

static void vdisk_on_free_cmd_params(const struct vdisk_cmd_params *p)
{
	if (!p->execute_async) {
		if (p->sync.kvec != p->sync.small_kvec)
			kfree(p->sync.kvec);
	}
}

static void fileio_on_free_cmd(struct scst_cmd *cmd)
{
	struct vdisk_cmd_params *p = cmd->dh_priv;

	TRACE_ENTRY();

	if (!p)
		goto out;

	vdisk_on_free_cmd_params(p);

	kmem_cache_free(vdisk_cmd_param_cachep, p);

out:
	TRACE_EXIT();
	return;
}

/*
 * Functionally identical to scst_tg_accept_standby(), but separated, because,
 * generally, they are checking for different things. Better to keep different
 * things separately.
 */
static bool vdisk_no_fd_allowed_commands(const struct scst_cmd *cmd)
{
	bool res;

	TRACE_ENTRY();

	switch (cmd->cdb[0]) {
	case TEST_UNIT_READY:
	case INQUIRY:
	case MODE_SENSE:
	case MODE_SENSE_10:
	case READ_CAPACITY:
	case REPORT_LUNS:
	case REQUEST_SENSE:
	case RELEASE:
	case RELEASE_10:
	case RESERVE:
	case RESERVE_10:
	case READ_BUFFER:
	case WRITE_BUFFER:
	case MODE_SELECT:
	case MODE_SELECT_10:
	case LOG_SELECT:
	case LOG_SENSE:
	case RECEIVE_DIAGNOSTIC:
	case SEND_DIAGNOSTIC:
	case PERSISTENT_RESERVE_IN:
	case PERSISTENT_RESERVE_OUT:
		res = true;
		goto out;
	case SERVICE_ACTION_IN_16:
		switch (cmd->cdb[1] & 0x1f) {
		case SAI_READ_CAPACITY_16:
			res = true;
			goto out;
		}
		break;
	case MAINTENANCE_IN:
		switch (cmd->cdb[1] & 0x1f) {
		case MI_REPORT_TARGET_PGS:
			res = true;
			goto out;
		}
		break;
	case MAINTENANCE_OUT:
		switch (cmd->cdb[1] & 0x1f) {
		case MO_SET_TARGET_PGS:
			res = true;
			goto out;
		}
		break;
	}

	res = false;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static enum scst_exec_res blockio_exec(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	const vdisk_op_fn *ops = virt_dev->vdev_devt->devt_priv;
	struct vdisk_cmd_params p;
	enum scst_exec_res res;

	EXTRACHECKS_BUG_ON(!ops);

	memset(&p, 0, sizeof(p));
	if (unlikely(!vdisk_parse_offset(&p, cmd)))
		goto err;

	if (unlikely(virt_dev->bdev == NULL)) {
		if (!vdisk_no_fd_allowed_commands(cmd)) {
			/*
			 * We should not get here, unless the user space
			 * misconfiguring something, e.g. set optimized
			 * ALUA state for secondary DRBD device. See
			 * "DRBD and other replication/failover SW
			 * compatibility" section in SCST README.
			 */
			PRINT_WARNING("Closed FD on exec. Not active ALUA state "
				"or not blocked dev before ALUA state change? "
				"(cmd %p, op %s, dev %s)", cmd, cmd->op_name,
				cmd->dev->virt_name);
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_no_medium));
			goto err;
		}
	}

	cmd->dh_priv = &p;
	res = vdev_do_job(cmd, ops);
	cmd->dh_priv = NULL;

out:
	vdisk_on_free_cmd_params(&p);
	return res;

err:
	res = SCST_EXEC_COMPLETED;
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

static enum scst_exec_res nullio_exec(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	const vdisk_op_fn *ops = virt_dev->vdev_devt->devt_priv;
	struct vdisk_cmd_params p;
	enum scst_exec_res res;

	EXTRACHECKS_BUG_ON(!ops);

	memset(&p, 0, sizeof(p));
	if (unlikely(!vdisk_parse_offset(&p, cmd)))
		goto err;

	cmd->dh_priv = &p;
	res = vdev_do_job(cmd, ops);
	cmd->dh_priv = NULL;

out:
	vdisk_on_free_cmd_params(&p);
	return res;

err:
	res = SCST_EXEC_COMPLETED;
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

static enum scst_exec_res vcdrom_exec(struct scst_cmd *cmd)
{
	enum scst_exec_res res = SCST_EXEC_COMPLETED;
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

	return ((uint64_t)scst_get_setup_id() << 32) | dev_id_num;
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

	if (unlikely((uint64_t)cmd->data_len > cmd->dev->max_write_same_len)) {
		PRINT_WARNING("Invalid WRITE SAME data len %lld (max allowed "
			"%lld)", (long long)cmd->data_len,
			(long long)cmd->dev->max_write_same_len);
		scst_set_invalid_field_in_cdb(cmd, cmd->len_off, 0);
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

/*
 * Copy a zero-terminated string into a fixed-size byte array and fill the
 * trailing bytes with @fill_byte.
 */
static void scst_copy_and_fill_b(char *dst, const char *src, int len,
				 uint8_t fill_byte)
{
	int cpy_len = min_t(int, strlen(src), len);

	memcpy(dst, src, cpy_len);
	memset(dst + cpy_len, fill_byte, len - cpy_len);
}

/*
 * Copy a zero-terminated string into a fixed-size char array and fill the
 * trailing characters with spaces.
 */
static void scst_copy_and_fill(char *dst, const char *src, int len)
{
	scst_copy_and_fill_b(dst, src, len, ' ');
}

static enum compl_status_e vdisk_exec_write_same(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	enum compl_status_e res = CMD_SUCCEEDED;
	uint8_t ctrl_offs = (cmd->cdb_len < 32) ? 1 : 10;

	TRACE_ENTRY();

	if (unlikely(cmd->cdb[ctrl_offs] & 0x10)) {
		TRACE_DBG("%s", "ANCHOR not supported");
		scst_set_invalid_field_in_cdb(cmd, ctrl_offs,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
		goto out;
	}

	if (unlikely(cmd->data_len <= 0)) {
		PRINT_ERROR("WRITE SAME: refused data_len = %#llx",
			    cmd->data_len);
		scst_set_invalid_field_in_cdb(cmd, cmd->len_off, 0);
		goto out;
	}

	if (cmd->cdb[ctrl_offs] & 0x8)
		vdisk_exec_write_same_unmap(p);
	else {
		scst_write_same(cmd, NULL);
		res = RUNNING_ASYNC;
	}

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
	uint32_t blocks_to_unmap;

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

	/* Sanity check to avoid too long latencies */
	blocks_to_unmap = 0;
	for (i = 0; i < cnt; i++) {
		blocks_to_unmap += pd[i].sdd_blocks;
		if (blocks_to_unmap > virt_dev->unmap_max_lba_cnt) {
			PRINT_WARNING("Too many UNMAP LBAs %u (max allowed %u, "
				"dev %s)", blocks_to_unmap,
				virt_dev->unmap_max_lba_cnt,
				virt_dev->dev->virt_name);
			scst_set_invalid_field_in_parm_list(cmd, 0, 0);
			goto out;
		}
	}

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

/* Supported VPD Pages VPD page (00h). */
static int vdisk_sup_vpd(uint8_t *buf, struct scst_cmd *cmd,
			 struct scst_vdisk_dev *virt_dev)
{
	char *page_list = &buf[4], *p = page_list;

	*p++ = 0x0; /* this page */
	*p++ = 0x80; /* unit serial number */
	*p++ = 0x83; /* device identification */
	*p++ = 0x86; /* extended inquiry */
	if (cmd->dev->type == TYPE_DISK) {
		*p++ = 0xB0; /* block limits */
		*p++ = 0xB1; /* block device characteristics */
		if (virt_dev->thin_provisioned)
			*p++ = 0xB2; /* thin provisioning */
	}
	buf[3] = p - page_list; /* page length */

	return buf[3] + 4;
}

/* Unit Serial Number VPD page (80h) */
static int vdisk_usn_vpd(uint8_t *buf, struct scst_cmd *cmd,
			 struct scst_vdisk_dev *virt_dev)
{
	uint16_t usn_len, max_len = INQ_BUF_SZ - 4;

	BUILD_BUG_ON(sizeof(virt_dev->usn) > INQ_BUF_SZ - 4);

	buf[1] = 0x80;
	if (cmd->tgtt->get_serial) {
		usn_len = cmd->tgtt->get_serial(cmd->tgt_dev, &buf[4], max_len);
	} else {
		read_lock(&vdisk_serial_rwlock);
		usn_len = strlen(virt_dev->usn);
		memcpy(&buf[4], virt_dev->usn, usn_len);
		read_unlock(&vdisk_serial_rwlock);
	}
	put_unaligned_be16(usn_len, &buf[2]);
	return usn_len + 4;
}

/* Device Identification VPD page (83h) */
static int vdisk_dev_id_vpd(uint8_t *buf, struct scst_cmd *cmd,
			    struct scst_vdisk_dev *virt_dev)
{
	int i, eui64_len = 0, naa_len = 0, resp_len, num = 4;
	uint16_t tg_id;
	u8 *eui64_id = NULL, *naa_id = NULL;

	buf[1] = 0x83;

	read_lock(&vdisk_serial_rwlock);
	i = strlen(virt_dev->scsi_device_name);
	if (i > 0) {
		/* SCSI target device name */
		buf[num + 0] = 0x3;	/* ASCII */
		buf[num + 1] = 0x20 | 0x8; /* Target device SCSI name */
		i += 4 - i % 4; /* align to required 4 bytes */
		scst_copy_and_fill_b(&buf[num + 4], virt_dev->scsi_device_name,
				     i, '\0');

		buf[num + 3] = i;
		num += buf[num + 3];

		num += 4;
	}
	read_unlock(&vdisk_serial_rwlock);

	/* T10 vendor identifier field format (faked) */
	buf[num + 0] = 0x2;	/* ASCII */
	buf[num + 1] = 0x1;	/* Vendor ID */
	read_lock(&vdisk_serial_rwlock);
	scst_copy_and_fill(&buf[num + 4], virt_dev->t10_vend_id, 8);
	i = strlen(virt_dev->vend_specific_id);
	memcpy(&buf[num + 12], virt_dev->vend_specific_id, i);
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

	put_unaligned_be16(cmd->tgt->rel_tgt_id, &buf[num + 4 + 2]);

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

		put_unaligned_be16(tg_id, &buf[num + 4 + 2]);

		buf[num + 3] = 4;
		num += 4 + buf[num + 3];
	}

	read_lock(&vdisk_serial_rwlock);

	if (virt_dev->eui64_id_len == 0 && virt_dev->naa_id_len == 0) {
		/*
		 * Compatibility mode: export the first eight bytes of the
		 * t10_dev_id as an EUI-64 ID. This is not entirely standards
		 * compliant since t10_dev_id contains an ASCII string and the
		 * first three bytes of an eight-byte EUI-64 ID are a OUI.
		 */
		eui64_len = 8;
		eui64_id  = virt_dev->t10_dev_id;
	} else {
		if (virt_dev->eui64_id_len) {
			eui64_len = virt_dev->eui64_id_len;
			eui64_id  = virt_dev->eui64_id;
		}
		if (virt_dev->naa_id_len) {
			naa_len = virt_dev->naa_id_len;
			naa_id  = virt_dev->naa_id;
		}
	}
	if (eui64_len) {
		buf[num + 0] = 0x01; /* binary */
		buf[num + 1] = 0x02; /* EUI-64 */
		buf[num + 2] = 0x00; /* reserved */
		buf[num + 3] = eui64_len;
		memcpy(&buf[num + 4], eui64_id, eui64_len);
		num += 4 + eui64_len;
	}
	if (naa_len) {
		buf[num + 0] = 0x01; /* binary */
		buf[num + 1] = 0x03; /* NAA */
		buf[num + 2] = 0x00; /* reserved */
		buf[num + 3] = naa_len;
		memcpy(&buf[num + 4], naa_id, naa_len);
		num += 4 + naa_len;
	}

	read_unlock(&vdisk_serial_rwlock);

	resp_len = num - 4;

	put_unaligned_be16(resp_len, &buf[2]);
	resp_len += 4;

	return resp_len;
}

/* Extended INQUIRY Data (86h) */
static int vdisk_ext_inq(uint8_t *buf, struct scst_cmd *cmd,
			 struct scst_vdisk_dev *virt_dev)
{
	struct scst_device *dev = cmd->dev;

	buf[1] = 0x86;
	buf[3] = 0x3C;
	if (dev->dev_dif_mode != SCST_DIF_MODE_NONE) {
		switch (dev->dev_dif_type) {
		case 1:
			buf[4] = 0; /* SPT=0, type 1 only supported */
			break;
		case 2:
			buf[4] = 0x10; /* SPT=010, type 2 only supported */
			break;
		case 3:
			buf[4] = 0x20; /* SPT=100, type 3 only supported */
			break;
		default:
			sBUG_ON(1);
			break;
		}
		buf[4] |= 4; /* GRD_CHK */
		if (dev->dif_app_chk)
			buf[4] |= 2; /* APP_CHK */
		if (dev->dif_ref_chk)
			buf[4] |= 1; /* REF_CHK */
	}
	buf[5] = 7; /* HEADSUP=1, ORDSUP=1, SIMPSUP=1 */
	buf[6] = (virt_dev->wt_flag || virt_dev->nv_cache) ? 0 : 1; /* V_SUP */
	buf[7] = 1; /* LUICLR=1 */
	return buf[3] + 4;
}

/* Block Limits VPD page (B0h) */
static int vdisk_block_limits(uint8_t *buf, struct scst_cmd *cmd,
			      struct scst_vdisk_dev *virt_dev)
{
	struct scst_device *dev = cmd->dev;
	int max_transfer;

	buf[1] = 0xB0;
	buf[3] = 0x3C;
	buf[4] = 1; /* WSNZ set */
	buf[5] = 0xFF; /* No MAXIMUM COMPARE AND WRITE LENGTH limit */
	/* Optimal transfer granuality is PAGE_SIZE */
	put_unaligned_be16(max_t(int, PAGE_SIZE / dev->block_size, 1), &buf[6]);

	/* Max transfer len is min of sg limit and 8M */
	max_transfer = min((long)cmd->tgt_dev->max_sg_cnt << PAGE_SHIFT,
			   8*1024*1024l) / dev->block_size;
	put_unaligned_be32(max_transfer, &buf[8]);

	put_unaligned_be32(min_t(int, max_transfer,
				 virt_dev->opt_trans_len >> dev->block_shift),
			   &buf[12]);

	if (virt_dev->thin_provisioned) {
		/* MAXIMUM UNMAP BLOCK DESCRIPTOR COUNT is UNLIMITED */
		put_unaligned_be32(0xFFFFFFFF, &buf[24]);
		/*
		 * MAXIMUM UNMAP LBA COUNT, OPTIMAL UNMAP
		 * GRANULARITY and ALIGNMENT
		 */
		put_unaligned_be32(virt_dev->unmap_max_lba_cnt, &buf[20]);
		put_unaligned_be32(virt_dev->unmap_opt_gran, &buf[28]);
		if (virt_dev->unmap_align != 0) {
			put_unaligned_be32(virt_dev->unmap_align, &buf[32]);
			buf[32] |= 0x80;
		}
	}

	/* MAXIMUM WRITE SAME LENGTH (measured in blocks) */
	put_unaligned_be64(dev->max_write_same_len >> dev->block_shift,
			   &buf[36]);

	return buf[3] + 4;
}

/* Block Device Characteristics VPD Page (B1h) */
static int vdisk_bdev_char(uint8_t *buf, struct scst_cmd *cmd,
			   struct scst_vdisk_dev *virt_dev)
{
	buf[1] = 0xB1;
	buf[3] = 0x3C;
	if (virt_dev->rotational) {
		/* 15K RPM */
		put_unaligned_be16(0x3A98, &buf[4]);
	} else
		put_unaligned_be16(1, &buf[4]);
	return buf[3] + 4;
}

/* Logical Block Provisioning a.k.a. Thin Provisioning VPD page (B2h) */
static int vdisk_tp_vpd(uint8_t *buf, struct scst_cmd *cmd,
			struct scst_vdisk_dev *virt_dev)
{
	buf[1] = 0xB2;
	buf[3] = 4;
	buf[5] = 0xE0;
	if (virt_dev->discard_zeroes_data)
		buf[5] |= 0x4; /* LBPRZ */
	buf[6] = 2; /* thin provisioned */
	return buf[3] + 4;
}

/* Standard INQUIRY response */
static int vdisk_inq(uint8_t *buf, struct scst_cmd *cmd,
		     struct scst_vdisk_dev *virt_dev)
{
	struct scst_device *dev = cmd->dev;
	int num;

	if (virt_dev->removable)
		buf[1] = 0x80;      /* removable */
	buf[2] = 6; /* Device complies to SPC-4 */
	buf[3] = 0x02;	/* Data in format specified in SPC */
	buf[3] |= 0x20; /* ACA supported */
	buf[4] = 31;/* n - 4 = 35 - 4 = 31 for full 36 byte data */
	if (cmd->dev->dev_dif_mode != SCST_DIF_MODE_NONE)
		buf[5] |= 1; /* PROTECT */
	if (scst_alua_configured(cmd->dev)) {
		buf[5] |= SCST_INQ_TPGS_MODE_IMPLICIT;
		if (dev->expl_alua)
			buf[5] |= SCST_INQ_TPGS_MODE_EXPLICIT;
	}
	buf[5] |= 8; /* 3PC */
	buf[6] = 0x10; /* MultiP 1 */
	buf[7] = 2; /* CMDQUE 1, BQue 0 => commands queuing supported */

	read_lock(&vdisk_serial_rwlock);

	/*
	 * 8 byte ASCII Vendor Identification of the target
	 * - left aligned.
	 */
	scst_copy_and_fill(&buf[8], virt_dev->t10_vend_id, 8);

	/*
	 * 16 byte ASCII Product Identification of the target - left
	 * aligned.
	 */
	scst_copy_and_fill(&buf[16], virt_dev->prod_id, 16);

	/*
	 * 4 byte ASCII Product Revision Level of the target - left
	 * aligned.
	 */
	scst_copy_and_fill(&buf[32], virt_dev->prod_rev_lvl, 4);

	/* Vendor specific information. */
	if (virt_dev->inq_vend_specific_len <= 20)
		memcpy(&buf[36], virt_dev->inq_vend_specific,
		       virt_dev->inq_vend_specific_len);

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
			put_unaligned_be16(v, &buf[58 + num]);
			num += 2;
		}
	}

	/* SCSI transport */
	if (cmd->tgtt->get_scsi_transport_version != NULL) {
		put_unaligned_be16(
			cmd->tgtt->get_scsi_transport_version(cmd->tgt),
			&buf[58 + num]);
		num += 2;
	}

	/* SPC-4 T10/1731-D revision 23 */
	buf[58 + num] = 0x4;
	buf[58 + num + 1] = 0x63;
	num += 2;

	/* Device command set */
	if (virt_dev->command_set_version != 0) {
		put_unaligned_be16(virt_dev->command_set_version,
				   &buf[58 + num]);
		num += 2;
	}

	/* Vendor specific information. */
	if (virt_dev->inq_vend_specific_len > 20) {
		memcpy(&buf[96], virt_dev->inq_vend_specific,
		       virt_dev->inq_vend_specific_len);
		num = 96 - 58 + virt_dev->inq_vend_specific_len;
	}

	read_unlock(&vdisk_serial_rwlock);

	buf[4] += num;
	return buf[4] + 5;
}

static enum compl_status_e vdisk_exec_inquiry(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length, resp_len;
	uint8_t *address;
	uint8_t *buf;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	enum scst_tg_state alua_state;

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

	alua_state = scst_get_alua_state(cmd->dev, cmd->tgt);
	if ((alua_state == SCST_TG_STATE_UNAVAILABLE) ||
	    (alua_state == SCST_TG_STATE_OFFLINE))
		buf[0] = SCSI_INQ_PQ_NOT_CON << 5 | dev->type;
	else
		buf[0] = virt_dev->dummy ? SCSI_INQ_PQ_NOT_CON << 5 | 0x1f :
			 SCSI_INQ_PQ_CON << 5 | dev->type;
	/* Vital Product */
	if (cmd->cdb[1] & EVPD) {
		if (cmd->cdb[2] == 0) {
			resp_len = vdisk_sup_vpd(buf, cmd, virt_dev);
		} else if (cmd->cdb[2] == 0x80) {
			resp_len = vdisk_usn_vpd(buf, cmd, virt_dev);
		} else if (cmd->cdb[2] == 0x83) {
			resp_len = vdisk_dev_id_vpd(buf, cmd, virt_dev);
		} else if (cmd->cdb[2] == 0x86) {
			resp_len = vdisk_ext_inq(buf, cmd, virt_dev);
		} else if (cmd->cdb[2] == 0xB0 && dev->type == TYPE_DISK) {
			resp_len = vdisk_block_limits(buf, cmd, virt_dev);
		} else if (cmd->cdb[2] == 0xB1 && dev->type == TYPE_DISK) {
			resp_len = vdisk_bdev_char(buf, cmd, virt_dev);
		} else if (cmd->cdb[2] == 0xB2 && dev->type == TYPE_DISK &&
			   virt_dev->thin_provisioned) {
			resp_len = vdisk_tp_vpd(buf, cmd, virt_dev);
		} else {
			TRACE_DBG("INQUIRY: Unsupported EVPD page %x", cmd->cdb[2]);
			scst_set_invalid_field_in_cdb(cmd, 2, 0);
			goto out_put;
		}
	} else {
		if (cmd->cdb[2] != 0) {
			TRACE_DBG("INQUIRY: Unsupported page %x", cmd->cdb[2]);
			scst_set_invalid_field_in_cdb(cmd, 2, 0);
			goto out_put;
		}
		resp_len = vdisk_inq(buf, cmd, virt_dev);
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
	if (pcontrol == 1)
		memset(p + 2, 0, sizeof(err_recov_pg) - 2);
	return sizeof(err_recov_pg);
}

static int vdisk_disconnect_pg(unsigned char *p, int pcontrol,
				struct scst_vdisk_dev *virt_dev)
{	/* Disconnect-Reconnect page for mode_sense */
	const unsigned char disconnect_pg[] = {0x2, 0xe, 128, 128, 0, 10, 0, 0,
					       0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(p, disconnect_pg, sizeof(disconnect_pg));
	if (pcontrol == 1)
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
	if (pcontrol == 1)
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
	if (pcontrol == 1)
		memset(p + 2, 0, sizeof(format_pg) - 2);
	return sizeof(format_pg);
}

static int vdisk_caching_pg(unsigned char *p, int pcontrol,
			     struct scst_vdisk_dev *virt_dev)
{
	/* Caching page for mode_sense */
	static const unsigned char caching_pg[] = {
		0x8, 0x12, 0x0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0x80, 0x14, 0, 0,
		0, 0, 0, 0
	};

	memcpy(p, caching_pg, sizeof(caching_pg));

	if (!virt_dev->nv_cache && vdev_saved_mode_pages_enabled)
		p[0] |= 0x80;

	switch (pcontrol) {
	case 0: /* current */
		p[2] |= (virt_dev->wt_flag || virt_dev->nv_cache) ? 0 : WCE;
		break;
	case 1: /* changeable */
		memset(p + 2, 0, sizeof(caching_pg) - 2);
		if (!virt_dev->nv_cache)
			p[2] |= WCE;
		break;
	case 2: /* default */
		p[2] |= (DEF_WRITE_THROUGH || virt_dev->nv_cache) ? 0 : WCE;
		break;
	case 3: /* saved */
		p[2] |= (virt_dev->wt_flag_saved || virt_dev->nv_cache) ? 0 : WCE;
		break;
	default:
		sBUG();
		break;
	}

	return sizeof(caching_pg);
}

static int vdisk_ctrl_m_pg(unsigned char *p, int pcontrol,
			    struct scst_vdisk_dev *virt_dev)
{	/* Control mode page for mode_sense */
	unsigned char ctrl_m_pg[] = {0xa, 0xa, 0, 0, 0, 0, 0, 0,
					   0, 0, 0x2, 0x4b};

	if (vdev_saved_mode_pages_enabled)
		ctrl_m_pg[0] |= 0x80;

	memcpy(p, ctrl_m_pg, sizeof(ctrl_m_pg));
	switch (pcontrol) {
	case 0: /* current */
		p[2] |= virt_dev->dev->tst << 5;
		p[2] |= virt_dev->dev->d_sense << 2;
		p[2] |= virt_dev->dev->dpicz << 3;
		p[2] |= virt_dev->dev->tmf_only << 4;
		p[3] |= virt_dev->dev->queue_alg << 4;
		p[3] |= virt_dev->dev->qerr << 1;
		p[4] |= virt_dev->dev->swp << 3;
		p[5] |= virt_dev->dev->tas << 6;
		p[5] |= virt_dev->dev->ato << 7;
		break;
	case 1: /* changeable */
		memset(p + 2, 0, sizeof(ctrl_m_pg) - 2);
#if 0	/*
	 * See comment in struct scst_device definition.
	 *
	 * If enable it, fix the default and saved cases below!
	 */
		p[2] |= 7 << 5;		/* TST */
#endif
		if (!virt_dev->dev->cluster_mode) {
			p[2] |= 1 << 2;		/* D_SENSE */
			p[2] |= 1 << 3;		/* DPICZ */
			p[2] |= 1 << 4;		/* TMF_ONLY */
			p[3] |= 0xF << 4;	/* QUEUE ALGORITHM MODIFIER */
			p[3] |= 3 << 1;		/* QErr */
			p[4] |= 1 << 3;		/* SWP */
			p[5] |= 1 << 6;		/* TAS */
			p[5] |= 0 << 7;		/* ATO */
		}
		break;
	case 2: /* default */
		p[2] |= virt_dev->tst << 5;
		p[2] |= virt_dev->dev->d_sense_default << 2;
		p[2] |= virt_dev->dev->dpicz_default << 3;
		p[2] |= virt_dev->dev->tmf_only_default << 4;
		p[3] |= virt_dev->dev->queue_alg_default << 4;
		p[3] |= virt_dev->dev->qerr_default << 1;
		p[4] |= virt_dev->dev->swp_default << 3;
		p[5] |= virt_dev->dev->tas_default << 6;
		p[5] |= virt_dev->dev->ato << 7;
		break;
	case 3: /* saved */
		p[2] |= virt_dev->dev->tst << 5;
		p[2] |= virt_dev->dev->d_sense_saved << 2;
		p[2] |= virt_dev->dev->dpicz_saved << 3;
		p[2] |= virt_dev->dev->tmf_only_default << 4;
		p[3] |= virt_dev->dev->queue_alg_saved << 4;
		p[3] |= virt_dev->dev->qerr_saved << 1;
		p[4] |= virt_dev->dev->swp_saved << 3;
		p[5] |= virt_dev->dev->tas_saved << 6;
		p[5] |= virt_dev->dev->ato << 7;
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
	if (pcontrol == 1)
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
	msense_6 = (cmd->cdb[0] == MODE_SENSE);
	dev_spec = cmd->tgt_dev->tgt_dev_rd_only ? WP : 0;

	if (type != TYPE_ROM)
		dev_spec |= DPOFUA;

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0))
		goto out_free;

	if (!vdev_saved_mode_pages_enabled && (pcontrol == 0x3)) {
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

	if (subpcode != 0) {
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
	bool old_wt = virt_dev->wt_flag;

	TRACE_ENTRY();

	if ((virt_dev->wt_flag == wt) || virt_dev->nullio || virt_dev->nv_cache)
		goto out;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->wt_flag = wt;
	spin_unlock(&virt_dev->flags_lock);

	/*
	 * MODE SELECT is a strictly serialized command so it's safe to reopen
	 * the fd.
	 */
	if (vdisk_is_open(virt_dev)) {
		res = vdisk_reopen_fd(virt_dev, read_only);
		if (res < 0)
			goto out_err;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	spin_lock(&virt_dev->flags_lock);
	virt_dev->wt_flag = old_wt;
	spin_unlock(&virt_dev->flags_lock);
	goto out;
}

static void vdisk_ctrl_m_pg_select(unsigned char *p,
	struct scst_vdisk_dev *virt_dev, struct scst_cmd *cmd, bool save,
	int param_offset)
{
	struct scst_device *dev = virt_dev->dev;
	int old_swp = dev->swp, old_tas = dev->tas, old_dsense = dev->d_sense;
	int old_queue_alg = dev->queue_alg, old_dpicz = dev->dpicz;
	int rc, old_tmf_only = dev->tmf_only, old_qerr = dev->qerr;
	int queue_alg, swp, tas, tmf_only, qerr, d_sense, dpicz;

	TRACE_ENTRY();

	if (save && !vdev_saved_mode_pages_enabled) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "MODE SELECT: saved control page "
			"not supported");
		scst_set_invalid_field_in_cdb(cmd, 2,
				SCST_INVAL_FIELD_BIT_OFFS_VALID | 1);
		goto out;
	}

	/*
	 * MODE SELECT is a strictly serialized cmd, so it is safe to
	 * perform direct assignment here.
	 */

#if 0 /* Not implemented yet, see comment in struct scst_device */
	dev->tst = (p[2] >> 5) & 7;
	/* ToDo: check validity of the new value */
#else
	if (dev->tst != ((p[2] >> 5) & 7)) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "%s", "MODE SELECT: Changing of "
			"TST not supported");
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 2,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 5);
		goto out;
	}
#endif

	queue_alg = p[3] >> 4;
	if ((queue_alg != SCST_QUEUE_ALG_0_RESTRICTED_REORDER) &&
	    (queue_alg != SCST_QUEUE_ALG_1_UNRESTRICTED_REORDER)) {
		PRINT_WARNING("Attempt to set invalid Control mode page QUEUE "
			"ALGORITHM MODIFIER value %d (initiator %s, dev %s)",
			queue_alg, cmd->sess->initiator_name, dev->virt_name);
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 3,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
		goto out;
	}

	swp = (p[4] & 0x8) >> 3;
	if (swp > 1) {
		PRINT_WARNING("Attempt to set invalid Control mode page SWP "
			"value %d (initiator %s, dev %s)", swp,
			cmd->sess->initiator_name, dev->virt_name);
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 4,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 3);
		goto out;
	}

	tas = (p[5] & 0x40) >> 6;
	if (tas > 1) {
		PRINT_WARNING("Attempt to set invalid Control mode page TAS "
			"value %d (initiator %s, dev %s)", tas,
			cmd->sess->initiator_name, dev->virt_name);
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 5,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 6);
		goto out;
	}

	tmf_only = (p[2] & 0x10) >> 4;
	if (tmf_only > 1) {
		PRINT_WARNING("Attempt to set invalid Control mode page "
			"TMF_ONLY value %d (initiator %s, dev %s)", tmf_only,
			cmd->sess->initiator_name, dev->virt_name);
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 2,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
		goto out;
	}

	dpicz = (p[2] & 0x8) >> 3;
	if (dpicz > 1) {
		PRINT_WARNING("Attempt to set invalid Control mode page "
			"dpicz value %d (initiator %s, dev %s)", dpicz,
			cmd->sess->initiator_name, dev->virt_name);
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 2,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 3);
		goto out;
	}

	qerr = (p[3] & 0x6) >> 1;
	if ((qerr == SCST_QERR_2_RESERVED) ||
	    (qerr > SCST_QERR_3_ABORT_THIS_NEXUS_ONLY)) {
		PRINT_WARNING("Attempt to set invalid Control mode page QErr "
			"value %d (initiator %s, dev %s)", qerr,
			cmd->sess->initiator_name, dev->virt_name);
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 3,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 1);
		goto out;
	}

	d_sense = (p[2] & 0x4) >> 2;
	if (d_sense > 1) {
		PRINT_WARNING("Attempt to set invalid Control mode page D_SENSE "
			"value %d (initiator %s, dev %s)", d_sense,
			cmd->sess->initiator_name, dev->virt_name);
		scst_set_invalid_field_in_parm_list(cmd, param_offset + 2,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 2);
		goto out;
	}

	dev->queue_alg = queue_alg;
	dev->swp = swp;
	dev->tas = tas;
	dev->tmf_only = tmf_only;
	dev->dpicz = dpicz;
	dev->qerr = qerr;
	dev->d_sense = d_sense;

	if ((dev->swp == old_swp) && (dev->tas == old_tas) &&
	    (dev->d_sense == old_dsense) && (dev->queue_alg == old_queue_alg) &&
	    (dev->qerr == old_qerr) && (dev->tmf_only == old_tmf_only) &&
	    (dev->dpicz == old_dpicz))
		goto out;

	if (!save)
		goto out_ok;

	rc = vdev_save_mode_pages(virt_dev);
	if (rc != 0) {
		dev->swp = old_swp;
		dev->tas = old_tas;
		dev->d_sense = old_dsense;
		dev->queue_alg = old_queue_alg;
		dev->tmf_only = old_tmf_only;
		dev->qerr = old_qerr;
		dev->dpicz = old_dpicz;
		/* Hopefully, the error is temporary */
		scst_set_busy(cmd);
		goto out;
	}

	dev->swp_saved = dev->swp;
	dev->tas_saved = dev->tas;
	dev->d_sense_saved = dev->d_sense;
	dev->queue_alg_saved = dev->queue_alg;
	dev->tmf_only_saved = dev->tmf_only;
	dev->qerr_saved = dev->qerr;
	dev->dpicz_saved = dev->dpicz;

out_ok:
	PRINT_INFO("Device %s: new control mode page parameters: SWP %x "
		"(was %x), TAS %x (was %x), TMF_ONLY %d (was %x), QErr %x "
		"(was %x), D_SENSE %d (was %d), QUEUE ALG %d (was %d), "
		"DPICZ %d (was %d)", virt_dev->name, dev->swp, old_swp,
		dev->tas, old_tas, dev->tmf_only, old_tmf_only, dev->qerr,
		old_qerr, dev->d_sense, old_dsense, dev->queue_alg,
		old_queue_alg, dev->dpicz, old_dpicz);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_caching_m_pg_select(unsigned char *p,
	struct scst_vdisk_dev *virt_dev, struct scst_cmd *cmd, bool save,
	bool read_only)
{
	int old_wt = virt_dev->wt_flag, new_wt, rc;

	TRACE_ENTRY();

	if (save && (!vdev_saved_mode_pages_enabled || virt_dev->nv_cache)) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "MODE SELECT: saved cache page "
			"not supported");
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out;
	}

	new_wt = (p[2] & WCE) ? 0 : 1;

	if (new_wt == old_wt)
		goto out;

	if (vdisk_set_wt(virt_dev, new_wt, read_only) != 0) {
		scst_set_busy(cmd);
		goto out;
	}

	if (!save)
		goto out_ok;

	rc = vdev_save_mode_pages(virt_dev);
	if (rc != 0) {
		vdisk_set_wt(virt_dev, old_wt, read_only);
		/* Hopefully, the error is temporary */
		scst_set_busy(cmd);
		goto out;
	}

	virt_dev->wt_flag_saved = virt_dev->wt_flag;

out_ok:
	PRINT_INFO("Device %s: new wt_flag: %x (was %x)", virt_dev->name,
		virt_dev->wt_flag, old_wt);

out:
	TRACE_EXIT();
	return;
}

static enum compl_status_e vdisk_exec_mode_select(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	int mselect_6, offset, bdl, type;

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	if (cmd->dev->cluster_mode) {
		PRINT_ERROR("MODE SELECT: not supported in cluster mode\n");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	mselect_6 = (cmd->cdb[0] == MODE_SELECT);
	type = cmd->dev->type;

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0))
		goto out;

	if (!(cmd->cdb[1] & PF)) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "MODE SELECT: Unsupported "
			"PF bit zero (cdb[1]=%x)", cmd->cdb[1]);
		scst_set_invalid_field_in_cdb(cmd, 1, 0);
		goto out_put;
	}

	if (mselect_6) {
		bdl = address[3];
		offset = 4;
	} else {
		bdl = get_unaligned_be16(&address[6]);
		offset = 8;
	}

	if (bdl == 8)
		offset += 8;
	else if (bdl != 0) {
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
			vdisk_caching_m_pg_select(&address[offset], virt_dev,
				cmd, cmd->cdb[1] & SP, cmd->tgt_dev->tgt_dev_rd_only);
			break;
		} else if ((address[offset] & 0x3f) == 0xA) {
			/* Control page */
			if (address[offset + 1] != 0xA) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"control page request");
				scst_set_invalid_field_in_parm_list(cmd, offset+1, 0);
				goto out_put;
			}
			vdisk_ctrl_m_pg_select(&address[offset], virt_dev, cmd,
				cmd->cdb[1] & SP, offset);
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
		uint32_t lba = get_unaligned_be32(&cmd->cdb[2]);

		if (lba != 0) {
			TRACE_DBG("PMI zero and LBA not zero (cmd %p)", cmd);
			scst_set_invalid_field_in_cdb(cmd, 2, 0);
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
	struct block_device *bdev;
	struct request_queue *q;
	uint32_t blocksize, physical_blocksize;
	uint64_t nblocks;
	uint8_t buffer[32];

	TRACE_ENTRY();

	virt_dev = cmd->dev->dh_priv;
	bdev = virt_dev->bdev;
	q = bdev ? bdev_get_queue(bdev) : NULL;
	blocksize = cmd->dev->block_size;
	nblocks = virt_dev->nblocks - 1;

	if ((cmd->cdb[14] & 1) == 0) {
		uint32_t lba = get_unaligned_be32(&cmd->cdb[2]);

		if (lba != 0) {
			TRACE_DBG("PMI zero and LBA not zero (cmd %p)", cmd);
			scst_set_invalid_field_in_cdb(cmd, 2, 0);
			goto out;
		}
	}

	memset(buffer, 0, sizeof(buffer));

	put_unaligned_be64(nblocks, &buffer[0]);
	put_unaligned_be32(blocksize, &buffer[8]);

	if (cmd->dev->dev_dif_mode != SCST_DIF_MODE_NONE) {
		switch (cmd->dev->dev_dif_type) {
		case 1:
			buffer[12] = 1;
			break;
		case 2:
			buffer[12] = 3;
			break;
		case 3:
			buffer[12] = 5;
			break;
		default:
			sBUG_ON(1);
			break;
		}
	}

	/* LOGICAL BLOCKS PER PHYSICAL BLOCK EXPONENT */
	physical_blocksize = q ? queue_physical_block_size(q) : 4096;
	buffer[13] = max(ilog2(physical_blocksize) - ilog2(blocksize), 0);

	if (virt_dev->thin_provisioned) {
		buffer[14] |= 0x80;     /* LBPME */
		if (virt_dev->discard_zeroes_data)
			buffer[14] |= 0x40;     /* LBPRZ */
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
	/* Changing it don't forget to add it to vdisk_opcode_descriptors! */
	scst_set_invalid_field_in_cdb(p->cmd, 1,
			0 | SCST_INVAL_FIELD_BIT_OFFS_VALID);
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_sai_16(struct vdisk_cmd_params *p)
{
	switch (p->cmd->cdb[1] & 0x1f) {
	case SAI_READ_CAPACITY_16:
		vdisk_exec_read_capacity16(p);
		return CMD_SUCCEEDED;
	case SAI_GET_LBA_STATUS:
		return vdisk_exec_get_lba_status(p);
	}
	scst_set_invalid_field_in_cdb(p->cmd, 1,
			0 | SCST_INVAL_FIELD_BIT_OFFS_VALID);
	return CMD_SUCCEEDED;
}

static enum compl_status_e vdisk_exec_maintenance_in(struct vdisk_cmd_params *p)
{
	/* For the code that handles RTPG, see also scst_local_cmd.c. */
	return CMD_FAILED;
}

static enum compl_status_e
vdisk_exec_maintenance_out(struct vdisk_cmd_params *p)
{
	/* For the code that handles RTPG, see also scst_local_cmd.c. */
	return CMD_FAILED;
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
		/*
		 * ADDR    0x10 - Q Sub-channel encodes current position data
		 * CONTROL 0x04 - Data track, recoreded uninterrupted
		 */
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

static struct kvec *vdisk_alloc_sync_kvec(struct scst_cmd *cmd,
					  struct vdisk_cmd_params *p)
{
	int kvec_segs;

	kvec_segs = min_t(int, scst_get_buf_count(cmd), UIO_MAXIOV);
	if (kvec_segs > p->sync.kvec_segs) {
		if (p->sync.kvec != p->sync.small_kvec)
			kfree(p->sync.kvec);
		p->sync.kvec_segs = 0;
		/* It can't be called in atomic context */
		p->sync.kvec = kvec_segs <= ARRAY_SIZE(p->sync.small_kvec) ?
			p->sync.small_kvec :
			kmalloc_array(kvec_segs, sizeof(*p->sync.kvec),
				      cmd->cmd_gfp_mask);
		if (p->sync.kvec == NULL) {
			PRINT_ERROR("Unable to allocate kvec (%d)", kvec_segs);
			goto out;
		}
		p->sync.kvec_segs = kvec_segs;
	}

out:
	return p->sync.kvec;
}

static enum compl_status_e nullio_exec_read(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();

	if (virt_dev->read_zero) {
		struct scatterlist *sge;
		struct page *page;
		int i;
		void *p;

		for_each_sg(cmd->sg, sge, cmd->sg_cnt, i) {
			page = sg_page(sge);
			p = kmap(page);
			if (sge->offset == 0 && sge->length == PAGE_SIZE)
				clear_page(p);
			else
				memset(p + sge->offset, 0, sge->length);
			kunmap(page);
		}
	}

	scst_dif_process_read(p->cmd);

	TRACE_EXIT();
	return CMD_SUCCEEDED;
}

static int vdev_read_dif_tags(struct vdisk_cmd_params *p)
{
	int res = 0;
	struct scst_cmd *cmd = p->cmd;
	loff_t loff;
	loff_t err = 0;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = virt_dev->dif_fd;
	struct kvec *kvec;
	int kvec_segs, max_kvec_segs, i;
	bool finished = false;
	int tags_num, l;
	struct scatterlist *tags_sg;

	TRACE_ENTRY();

	/*
	 * !! Data for this cmd can be read simultaneously !!
	 */

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

	EXTRACHECKS_BUG_ON(!(cmd->dev->dev_dif_mode & SCST_DIF_MODE_DEV_STORE) ||
	    (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions)) == SCST_DIF_ACTION_NONE));

	tags_num = (cmd->bufflen >> cmd->dev->block_shift);
	if (unlikely(tags_num == 0))
		goto out;

	kvec = p->sync.kvec;
	if (kvec == NULL) {
		kvec = vdisk_alloc_sync_kvec(cmd, p);
		if (kvec == NULL) {
			unsigned long flags;

			/* To protect sense setting against blockio data reads */
			spin_lock_irqsave(&vdev_err_lock, flags);
			scst_set_busy(cmd);
			spin_unlock_irqrestore(&vdev_err_lock, flags);
			res = -ENOMEM;
			goto out;
		}
	}
	max_kvec_segs = p->sync.kvec_segs;

	tags_sg = NULL;
	loff = (p->loff >> cmd->dev->block_shift) << SCST_DIF_TAG_SHIFT;
	while (1) {
		kvec_segs = 0;
		full_len = 0;
		i = -1;
		address = scst_get_dif_buf(cmd, &tags_sg, &l);
		length = l;
		EXTRACHECKS_BUG_ON(length <= 0);
		while (1) {
			full_len += length;
			i++;
			kvec_segs++;
			kvec[i].iov_base = address;
			kvec[i].iov_len = length;
			tags_num -= length >> SCST_DIF_TAG_SHIFT;
			EXTRACHECKS_BUG_ON(tags_num < 0);
			if (kvec_segs == max_kvec_segs || tags_num == 0)
				break;
			address = scst_get_dif_buf(cmd, &tags_sg, &l);
			length = l;
			EXTRACHECKS_BUG_ON(length <= 0);
		}
		if (tags_num == 0)
			finished = true;

		TRACE_DBG("Reading DIF kvec_segs %d, full_len %zd, loff %lld",
			kvec_segs, full_len, (long long)loff);

		/* READ */
		err = scst_readv(fd, kvec, kvec_segs, &loff);
		if ((err < 0) || (err < full_len)) {
			unsigned long flags;

			PRINT_ERROR("DIF readv() returned %lld from %zd "
				"(offs %lld, dev %s)", (long long)err,
				full_len, (long long)loff, cmd->dev->virt_name);
			/* To protect sense setting with blockio */
			spin_lock_irqsave(&vdev_err_lock, flags);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			spin_unlock_irqrestore(&vdev_err_lock, flags);
			res = err;
			goto out_put_dif_buf;
		}

		for (i = 0; i < kvec_segs; i++)
			scst_put_dif_buf(cmd, kvec[i].iov_base);

		if (finished)
			break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_put_dif_buf:
	for (i = 0; i < kvec_segs; i++)
		scst_put_dif_buf(cmd, kvec[i].iov_base);
	goto out;
}

static int vdev_write_dif_tags(struct vdisk_cmd_params *p)
{
	int res = 0;
	struct scst_cmd *cmd = p->cmd;
	loff_t loff;
	loff_t err = 0;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = virt_dev->dif_fd;
	struct kvec *kvec, *ekvec;
	int kvec_segs, ekvec_segs, max_kvec_segs, i;
	bool finished = false;
	int tags_num, l;
	struct scatterlist *tags_sg;

	TRACE_ENTRY();

	/*
	 * !! Data for this cmd can be written simultaneously !!
	 */

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

	EXTRACHECKS_BUG_ON(!(cmd->dev->dev_dif_mode & SCST_DIF_MODE_DEV_STORE) ||
	    (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions)) == SCST_DIF_ACTION_NONE));

	tags_num = (cmd->bufflen >> cmd->dev->block_shift);
	if (unlikely(tags_num == 0))
		goto out;

	kvec = p->sync.kvec;
	if (kvec == NULL) {
		kvec = vdisk_alloc_sync_kvec(cmd, p);
		if (kvec == NULL) {
			unsigned long flags;

			/* To protect sense setting against blockio data writes */
			spin_lock_irqsave(&vdev_err_lock, flags);
			scst_set_busy(cmd);
			spin_unlock_irqrestore(&vdev_err_lock, flags);
			res = -ENOMEM;
			goto out;
		}
	}
	max_kvec_segs = p->sync.kvec_segs;

	tags_sg = NULL;
	loff = (p->loff >> cmd->dev->block_shift) << SCST_DIF_TAG_SHIFT;
	while (1) {
		kvec_segs = 0;
		full_len = 0;
		i = -1;
		address = scst_get_dif_buf(cmd, &tags_sg, &l);
		length = l;
		EXTRACHECKS_BUG_ON(length <= 0);
		while (1) {
			full_len += length;
			i++;
			kvec_segs++;
			kvec[i].iov_base = address;
			kvec[i].iov_len = length;
			tags_num -= length >> SCST_DIF_TAG_SHIFT;
			EXTRACHECKS_BUG_ON(tags_num < 0);
			if (kvec_segs == max_kvec_segs || tags_num == 0)
				break;
			address = scst_get_dif_buf(cmd, &tags_sg, &l);
			length = l;
			EXTRACHECKS_BUG_ON(length <= 0);
		}
		if (tags_num == 0)
			finished = true;

		ekvec = kvec;
		ekvec_segs = kvec_segs;
restart:
		TRACE_DBG("Writing DIF: ekvec_segs %d, full_len %zd", ekvec_segs, full_len);

		/* WRITE */
		err = scst_writev(fd, ekvec, ekvec_segs, &loff);
		if (err < 0) {
			unsigned long flags;

			PRINT_ERROR("DIF write() returned %lld from %zd",
				    err, full_len);
			/* To protect sense setting with blockio */
			spin_lock_irqsave(&vdev_err_lock, flags);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_write_error));
			}
			spin_unlock_irqrestore(&vdev_err_lock, flags);
			res = err;
			goto out_put_dif_buf;
		} else if (err < full_len) {
			/*
			 * Probably that's wrong, but sometimes write() returns
			 * value less, than requested. Let's restart.
			 */
			int e = ekvec_segs;

			TRACE_MGMT_DBG("DIF write() returned %d from %zd "
				"(kvec_segs=%d)", (int)err, full_len,
				ekvec_segs);
			if (err == 0) {
				PRINT_INFO("Suspicious: DIF write() returned 0 from "
					"%zd (kvec_segs=%d)", full_len, ekvec_segs);
			}
			full_len -= err;
			for (i = 0; i < e; i++) {
				if ((long long)ekvec->iov_len < err) {
					err -= ekvec->iov_len;
					ekvec++;
					ekvec_segs--;
				} else {
					ekvec->iov_base = ekvec->iov_base + err;
					ekvec->iov_len -= err;
					break;
				}
			}
			goto restart;
		}

		for (i = 0; i < kvec_segs; i++)
			scst_put_dif_buf(cmd, kvec[i].iov_base);

		if (finished)
			break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_put_dif_buf:
	for (i = 0; i < kvec_segs; i++)
		scst_put_dif_buf(cmd, kvec[i].iov_base);
	goto out;
}

static enum compl_status_e blockio_exec_var_len_cmd(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int res;

	TRACE_ENTRY();

	res = blockio_var_len_ops[cmd->cdb[9]](p);

	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e nullio_exec_var_len_cmd(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int res;

	TRACE_ENTRY();

	res = nullio_var_len_ops[cmd->cdb[9]](p);

	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e fileio_exec_var_len_cmd(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	int res;

	TRACE_ENTRY();

	res = fileio_var_len_ops[cmd->cdb[9]](p);

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Execute a SCSI write command against a file. If this function returns
 * RUNNING_ASYNC the SCST command may already have completed before this
 * function returns.
 */
static enum compl_status_e fileio_exec_write(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	loff_t loff = p->loff;
	loff_t err = 0;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev = cmd->dev->dh_priv;
	struct file *fd = virt_dev->fd;
	struct kvec *kvec, *ekvec;
	int rc, i, kvec_segs, ekvec_segs, max_kvec_segs;
	bool finished = false;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

	if (do_fileio_async(p))
		return fileio_exec_async(p);

	rc = scst_dif_process_write(cmd);
	if (unlikely(rc != 0))
		goto out;

	kvec = vdisk_alloc_sync_kvec(cmd, p);
	if (kvec == NULL)
		goto out_nomem;

	max_kvec_segs = p->sync.kvec_segs;

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length < 0)) {
		PRINT_ERROR("scst_get_buf_first() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_internal_failure));
		goto out;
	}

	while (1) {
		kvec_segs = 0;
		full_len = 0;
		i = -1;
		while (length > 0) {
			full_len += length;
			i++;
			kvec_segs++;
			kvec[i].iov_base = address;
			kvec[i].iov_len = length;
			if (kvec_segs == max_kvec_segs)
				break;
			length = scst_get_buf_next(cmd, &address);
		}
		if (length == 0) {
			finished = true;
			if (unlikely(kvec_segs == 0))
				break;
		} else if (unlikely(length < 0)) {
			PRINT_ERROR("scst_get_buf_next() failed: %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_internal_failure));
			goto out_put_buf;
		}

		ekvec = kvec;
		ekvec_segs = kvec_segs;
restart:
		TRACE_DBG("Writing: ekvec_segs %d, full_len %zd", ekvec_segs, full_len);

		/* WRITE */
		err = scst_writev(fd, ekvec, ekvec_segs, &loff);
		if (err < 0) {
			PRINT_ERROR("write() returned %lld from %zd",
				    (unsigned long long)err,
				    full_len);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else if (err == -ENOSPC) {
				WARN_ON(!virt_dev->thin_provisioned);
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(scst_space_allocation_failed_write_protect));
			} else
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_write_error));
			goto out_put_buf;
		} else if (err < full_len) {
			/*
			 * Probably that's wrong, but sometimes write() returns
			 * value less, than requested. Let's restart.
			 */
			int e = ekvec_segs;

			TRACE_MGMT_DBG("write() returned %d from %zd "
				"(kvec_segs=%d)", (int)err, full_len,
				ekvec_segs);
			if (err == 0) {
				PRINT_INFO("Suspicious: write() returned 0 from "
					"%zd (kvec_segs=%d)", full_len, ekvec_segs);
			}
			full_len -= err;
			for (i = 0; i < e; i++) {
				if ((long long)ekvec->iov_len < err) {
					err -= ekvec->iov_len;
					ekvec++;
					ekvec_segs--;
				} else {
					ekvec->iov_base += err;
					ekvec->iov_len -= err;
					break;
				}
			}
			goto restart;
		}

		for (i = 0; i < kvec_segs; i++)
			scst_put_buf(cmd, kvec[i].iov_base);

		if (finished)
			break;

		length = scst_get_buf_next(cmd, &address);
	}

	if ((dev->dev_dif_mode & SCST_DIF_MODE_DEV_STORE) &&
	    (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions)) != SCST_DIF_ACTION_NONE)) {
		err = vdev_write_dif_tags(p);
		if (err != 0)
			goto out;
	}

out_sync:
	/* O_DSYNC flag is used for WT devices */
	if (p->fua)
		vdisk_fsync(loff, scst_cmd_get_data_len(cmd), cmd->dev,
			    cmd->cmd_gfp_mask, cmd, false);
out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;

out_put_buf:
	for (i = 0; i < kvec_segs; i++)
		scst_put_buf(cmd, kvec[i].iov_base);
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
	struct scst_cmd *cmd;

	/* Decrement the bios in processing, and if zero signal completion */
	if (!atomic_dec_and_test(&blockio_work->bios_inflight))
		return;

	cmd = blockio_work->cmd;

	if (unlikely(cmd->do_verify)) {
		struct scst_verify_work *w = kmalloc(sizeof(*w), GFP_ATOMIC);

		cmd->do_verify = false;
		if (w) {
			INIT_WORK(&w->work, scst_do_verify_work);
			w->cmd = cmd;
			schedule_work(&w->work);
		} else {
			scst_set_busy(cmd);
			cmd->completed = 1;
			cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
					   scst_estimate_context());
		}
	} else {
		if ((cmd->data_direction & SCST_DATA_READ) &&
		    likely(cmd->status == SAM_STAT_GOOD)) {
			/*
			 * We, most likely, on interrupt, so defer DIF
			 * checking to later stage in thread context
			 */
			cmd->deferred_dif_read_check = 1;
		}

		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
				   scst_estimate_context());
	}
	kmem_cache_free(blockio_work_cachep, blockio_work);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
static void blockio_endio(struct bio *bio, int error)
{
#else
static void blockio_endio(struct bio *bio)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0) &&	\
	!defined(CONFIG_SUSE_KERNEL)
	int error = bio->bi_error;
#else
	int error = blk_status_to_errno(bio->bi_status);
#endif
#endif
	struct scst_blockio_work *blockio_work = bio->bi_private;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	if (unlikely(!bio_flagged(bio, BIO_UPTODATE))) {
		if (error == 0) {
			PRINT_ERROR("Not up to date bio with error 0 for "
				"cmd %p, returning -EIO", blockio_work->cmd);
			error = -EIO;
		}
	}
#endif

	if (unlikely(error != 0)) {
		unsigned long flags;

		PRINT_ERROR_RATELIMITED(
			"BLOCKIO for cmd %p finished with error %d",
			blockio_work->cmd, error);

		/*
		 * To protect from several bios finishing simultaneously +
		 * unsuccessful DIF tags reading/writing
		 */
		spin_lock_irqsave(&vdev_err_lock, flags);

#if (!defined(CONFIG_SUSE_KERNEL) &&			 \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		if (bio->bi_rw & REQ_WRITE) {
#else
		if (op_is_write(bio_op(bio))) {
#endif
			if (error == -ENOSPC) {
				struct scst_vdisk_dev *virt_dev = blockio_work->cmd->dev->dh_priv;

				WARN_ON(!virt_dev->thin_provisioned);
				scst_set_cmd_error(blockio_work->cmd,
					SCST_LOAD_SENSE(scst_space_allocation_failed_write_protect));
			} else
				scst_set_cmd_error(blockio_work->cmd,
					SCST_LOAD_SENSE(scst_sense_write_error));
		} else
			scst_set_cmd_error(blockio_work->cmd,
				SCST_LOAD_SENSE(scst_sense_read_error));

		spin_unlock_irqrestore(&vdev_err_lock, flags);
	}

	blockio_check_finish(blockio_work);

	bio_put(bio);
	return;
}

static void vdisk_bio_set_failfast(struct bio *bio)
{
#if (!defined(CONFIG_SUSE_KERNEL) &&			 \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	bio->bi_rw |= REQ_FAILFAST_DEV |
		      REQ_FAILFAST_TRANSPORT |
		      REQ_FAILFAST_DRIVER;
#else
	bio->bi_opf |= REQ_FAILFAST_DEV |
		       REQ_FAILFAST_TRANSPORT |
		       REQ_FAILFAST_DRIVER;
#endif
}

static void vdisk_bio_set_hoq(struct bio *bio)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0) ||			\
defined(CONFIG_SUSE_KERNEL) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	bio->bi_opf |= REQ_SYNC;
#else
	bio->bi_rw |= REQ_SYNC;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0) ||			\
defined(CONFIG_SUSE_KERNEL) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	bio->bi_opf |= REQ_PRIO;
#else
	bio->bi_rw |= REQ_META;
	/*
	 * Priority boosting was separated from REQ_META in commit 65299a3b
	 * (kernel 3.1.0).
	 */
	bio->bi_rw |= REQ_PRIO;
#endif
}

#if defined(CONFIG_BLK_DEV_INTEGRITY)
static void vdisk_blk_add_dif(struct bio *bio, gfp_t gfp_mask,
	const struct scst_device *dev, struct scatterlist **pdsg,
	int *pdsg_offs, int *pdsg_len, bool last)
{
	int block_shift = dev->block_shift;
	struct scatterlist *orig_dsg = *pdsg;
	struct scatterlist *sg;
	int sg_offs = *pdsg_offs, sg_len = *pdsg_len;
	int pages, left, len, tags_len, rc;
	struct bio_integrity_payload *bip;

	TRACE_ENTRY();

	tags_len = ((bio_sectors(bio) << 9) >> block_shift) << SCST_DIF_TAG_SHIFT;

	TRACE_DBG("bio %p, tags_len %d, pdsg %p, pdsg_offs %d, pdsg_len %d, "
		"last %d", bio, tags_len, *pdsg, *pdsg_offs, *pdsg_len, last);

	pages = 0;
	left = tags_len;
	sg = orig_dsg;
	len = sg->length;
	while (1) {
		pages++;
		left -= len;
		if (left <= 0) {
			if (!last) {
				left = -left;
				sg = __sg_next_inline(sg);
				*pdsg = sg;
				*pdsg_offs = sg->offset + left;
				*pdsg_len = sg->length - left;
				TRACE_DBG("left %d, pdsg %p, pdsg_offs %d, pdsg_len %d",
					left, *pdsg, *pdsg_offs, *pdsg_len);
			}
			break;
		}
		sg = __sg_next_inline(sg);
		len = sg->length;
	}

	bip = bio_integrity_alloc(bio, gfp_mask, pages);
	if (IS_ERR_OR_NULL(bip)) {
		PRINT_WARNING("Allocation of %d pages for DIF tags "
			"failed! (dev %s)", pages, dev->virt_name);
		goto out; /* proceed without integrity */
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	bip->bip_iter.bi_size = tags_len;
	bip->bip_iter.bi_sector = bio->bi_iter.bi_sector;
#else
	bip->bip_size = tags_len;
	bip->bip_sector = bio->bi_sector;
#endif

	left = tags_len;
	sg = orig_dsg;
	while (1) {
		TRACE_DBG("page %p (buf %p), sg_len %d, sg_offs %d",
			sg_page(sg), page_address(sg_page(sg)),
			sg_len, sg_offs);

		rc = bio_integrity_add_page(bio, sg_page(sg), sg_len, sg_offs);
		if (rc != sg_len) {
			PRINT_WARNING("Can not add DIF tags page! "
				"(dev %s)", dev->virt_name);
			/* bio_integrity_free() will be called as part of bio_free() */
			goto out; /* proceed without integrity */
		}

		if (left < sg_len) {
			TRACE_DBG("left %d, sg_len %d, sg_offs %d",
				left, sg_len, sg_offs);
			break;
		}

		left -= sg_len;
		EXTRACHECKS_BUG_ON(left < 0);

		TRACE_DBG("left %d", left);

		if (left == 0)
			break;

		sg = __sg_next_inline(sg);
		sg_len = sg->length;
		sg_offs = sg->offset;
	}

out:
	TRACE_EXIT();
	return;
}
#else /* defined(CONFIG_BLK_DEV_INTEGRITY) */
static void vdisk_blk_add_dif(struct bio *bio, gfp_t gfp_mask,
	const struct scst_device *dev, struct scatterlist **pdsg,
	int *pdsg_offs, int *pdsg_len, bool last)
{
	BUG();
}
#endif /* defined(CONFIG_BLK_DEV_INTEGRITY) */

static void blockio_exec_rw(struct vdisk_cmd_params *p, bool write, bool fua)
{
	struct scst_cmd *cmd = p->cmd;
	u64 lba_start = scst_cmd_get_lba(cmd);
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	int block_shift = dev->block_shift;
	struct block_device *bdev = virt_dev->bdev;
	struct bio_set *bs = virt_dev->vdisk_bioset;
	struct request_queue *q = bdev_get_queue(bdev);
	int length, max_nr_vecs = 0, offset;
	struct page *page;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	int need_new_bio;
	struct scst_blockio_work *blockio_work;
	int bios = 0;
	gfp_t gfp_mask = cmd->cmd_gfp_mask;
	struct blk_plug plug;
	struct scatterlist *dsg;
	int dsg_offs, dsg_len;
	bool dif = virt_dev->blk_integrity &&
		   (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions)) != SCST_DIF_ACTION_NONE);

	TRACE_ENTRY();

	WARN_ON(virt_dev->nullio);

	if (dif) {
		dsg = cmd->dif_sg;
		dsg_offs = dsg->offset;
		dsg_len = dsg->length;
	}

	/* Allocate and initialize blockio_work struct */
	blockio_work = kmem_cache_alloc(blockio_work_cachep, gfp_mask);
	if (blockio_work == NULL) {
		scst_set_busy(cmd);
		goto finish_cmd;
	}

#if 0
	{
		static int err_inj_cntr;

		if (++err_inj_cntr % 256 == 0) {
			PRINT_INFO("%s() error injection", __func__);
			scst_set_busy(cmd);
			goto free_bio;
		}
	}
#endif

	blockio_work->cmd = cmd;

	if (q)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
		max_nr_vecs = BIO_MAX_VECS;
#else
		max_nr_vecs = min(bio_get_nr_vecs(bdev), BIO_MAX_VECS);
#endif
	else
		max_nr_vecs = 1;

	need_new_bio = 1;

	length = scst_get_sg_page_first(cmd, &page, &offset);
	/*
	 * bv_len and bv_offset must be a multiple of 512 (SECTOR_SIZE), so
	 * check this here.
	 */
	if (WARN_ONCE((length & 511) != 0 || (offset & 511) != 0,
		      "Refused bio with invalid length %d and/or offset %d.\n",
		      length, offset)) {
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto free_bio;
	}

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
				bio = bio_alloc_bioset(/*bdev=*/NULL, max_nr_vecs, /*opf=*/0,
						       gfp_mask, bs);
				if (!bio) {
					PRINT_ERROR("Failed to create bio "
						"for data segment %d (cmd %p)",
						cmd->get_sg_buf_entry_num, cmd);
					scst_set_busy(cmd);
					goto free_bio;
				}

				bios++;
				need_new_bio = 0;
				bio->bi_end_io = blockio_endio;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
				bio->bi_iter.bi_sector = lba_start0 << (block_shift - 9);
#else
				bio->bi_sector = lba_start0 << (block_shift - 9);
#endif
				bio_set_dev(bio, bdev);
				bio->bi_private = blockio_work;
				if (write)
#if (!defined(CONFIG_SUSE_KERNEL) &&			\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
					bio->bi_rw |= REQ_WRITE;
#else
					bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
#endif
				/*
				 * Better to fail fast w/o any local recovery
				 * and retries.
				 */
				vdisk_bio_set_failfast(bio);

#if 0 /* It could be win, but could be not, so a performance study is needed */
				bio->bi_rw |= REQ_SYNC;
#endif
				if (fua)
#if (!defined(CONFIG_SUSE_KERNEL) &&			 \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
					bio->bi_rw |= REQ_FUA;
#else
					bio->bi_opf |= REQ_FUA;
#endif

				if (cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE)
					vdisk_bio_set_hoq(bio);

				if (!hbio)
					hbio = tbio = bio;
				else
					tbio = tbio->bi_next = bio;
			}

			bytes = min_t(unsigned int, len, PAGE_SIZE - off);

			rc = bio_add_page(bio, pg, bytes, off);
			if (rc < bytes) {
				WARN_ON(rc != 0);
				if (dif)
					vdisk_blk_add_dif(bio, gfp_mask, dev, &dsg,
						&dsg_offs, &dsg_len, false);
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

		length = scst_get_sg_page_next(cmd, &page, &offset);
	}

	if (dif)
		vdisk_blk_add_dif(bio, gfp_mask, dev, &dsg, &dsg_offs,
			&dsg_len, true);

	/* +1 to prevent erroneous too early command completion */
	atomic_set(&blockio_work->bios_inflight, bios+1);

	blk_start_plug(&plug);

	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;

#if (!defined(CONFIG_SUSE_KERNEL) &&			 \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		submit_bio(bio->bi_rw, bio);
#else
		submit_bio(bio);
#endif
	}

	blk_finish_plug(&plug);

	if ((dev->dev_dif_mode & SCST_DIF_MODE_DEV_STORE) &&
	    (virt_dev->dif_fd != NULL) &&
	    (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions)) != SCST_DIF_ACTION_NONE)) {
		if (write)
			vdev_write_dif_tags(p);
		else
			vdev_read_dif_tags(p);
	}

	blockio_check_finish(blockio_work);

out:
	TRACE_EXIT();
	return;

free_bio:
	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio_put(bio);
	}
	kmem_cache_free(blockio_work_cachep, blockio_work);

finish_cmd:
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
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
	loff_t err = 0;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	struct file *fd = virt_dev->fd;
	struct kvec *kvec;
	int kvec_segs, i, max_kvec_segs;
	bool finished = false;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

	if (do_fileio_async(p))
		return fileio_exec_async(p);

	kvec = vdisk_alloc_sync_kvec(cmd, p);
	if (kvec == NULL)
		goto out_nomem;

	max_kvec_segs = p->sync.kvec_segs;

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length < 0)) {
		PRINT_ERROR("scst_get_buf_first() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_internal_failure));
		goto out;
	}

	while (1) {
		kvec_segs = 0;
		full_len = 0;
		i = -1;
		while (length > 0) {
			full_len += length;
			i++;
			kvec_segs++;
			kvec[i].iov_base = address;
			kvec[i].iov_len = length;
			if (kvec_segs == max_kvec_segs)
				break;
			length = scst_get_buf_next(cmd, &address);
		}
		if (length == 0) {
			finished = true;
			if (unlikely(kvec_segs == 0))
				break;
		} else if (unlikely(length < 0)) {
			PRINT_ERROR("scst_get_buf_next() failed: %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_internal_failure));
			goto out_put_buf;
		}

		TRACE_DBG("Reading kvec_segs %d, full_len %zd", kvec_segs, full_len);

		/* READ */
		err = scst_readv(fd, kvec, kvec_segs, &loff);
		if ((err < 0) || (err < full_len)) {
			PRINT_ERROR("readv() returned %lld from %zd",
				    (unsigned long long)err,
				    full_len);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			goto out_put_buf;
		}

		for (i = 0; i < kvec_segs; i++)
			scst_put_buf(cmd, kvec[i].iov_base);

		if (finished)
			break;

		length = scst_get_buf_next(cmd, &address);
	}

	if ((dev->dev_dif_mode & SCST_DIF_MODE_DEV_STORE) &&
	    (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions)) != SCST_DIF_ACTION_NONE)) {
		err = vdev_read_dif_tags(p);
		if (err != 0)
			goto out;
	}

	scst_dif_process_read(cmd);

out:
	TRACE_EXIT();
	return CMD_SUCCEEDED;

out_put_buf:
	for (i = 0; i < kvec_segs; i++)
		scst_put_buf(cmd, kvec[i].iov_base);
	goto out;

out_nomem:
	scst_set_busy(cmd);
	err = 0;
	goto out;
}

static enum compl_status_e nullio_exec_write(struct vdisk_cmd_params *p)
{
	scst_dif_process_write(p->cmd);
	return CMD_SUCCEEDED;
}

static enum compl_status_e blockio_exec_write(struct vdisk_cmd_params *p)
{
	struct scst_cmd *cmd = p->cmd;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	int res, rc;

	TRACE_ENTRY();

	rc = scst_dif_process_write(cmd);
	if (unlikely(rc != 0)) {
		res = CMD_SUCCEEDED;
		goto out;
	}

	blockio_exec_rw(p, true, p->fua || virt_dev->wt_flag);
	res = RUNNING_ASYNC;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static enum compl_status_e vdev_exec_verify(struct vdisk_cmd_params *p)
{
	return vdev_verify(p->cmd, p->loff);
}

static enum compl_status_e blockio_exec_write_verify(struct vdisk_cmd_params *p)
{
	p->cmd->do_verify = true;
	return blockio_exec_write(p);
}

static enum compl_status_e fileio_exec_write_verify(struct vdisk_cmd_params *p)
{
	enum compl_status_e ret;

	p->cmd->do_verify = true;
	ret = fileio_exec_write(p);
	if (ret != CMD_SUCCEEDED)
		return ret;
	p->cmd->do_verify = false;
	/* O_DSYNC flag is used for WT devices */
	if (scsi_status_is_good(p->cmd->status))
		vdev_exec_verify(p);
	return CMD_SUCCEEDED;
}

static enum compl_status_e nullio_exec_write_verify(struct vdisk_cmd_params *p)
{
	scst_dif_process_write(p->cmd);
	return CMD_SUCCEEDED;
}

static enum compl_status_e nullio_exec_verify(struct vdisk_cmd_params *p)
{
	return CMD_SUCCEEDED;
}

static void blockio_on_alua_state_change_start(struct scst_device *dev,
	enum scst_tg_state old_state, enum scst_tg_state new_state)
{
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	const bool close = virt_dev->dev_active &&
		new_state != SCST_TG_STATE_OPTIMIZED &&
		new_state != SCST_TG_STATE_NONOPTIMIZED;

	TRACE_ENTRY();

	/* No other fd activity may happen concurrently with this function. */
	lockdep_assert_alua_lock_held();

	if (!virt_dev->bind_alua_state)
		return;

	PRINT_INFO("dev %s: ALUA state change from %s to %s started,%s closing FD",
		   dev->virt_name, scst_alua_state_name(old_state),
		   scst_alua_state_name(new_state), close ? "" : " not");

	if (!close)
		return;

	vdisk_disable_dev(virt_dev);

	TRACE_EXIT();
	return;
}

static void blockio_on_alua_state_change_finish(struct scst_device *dev,
	enum scst_tg_state old_state, enum scst_tg_state new_state)
{
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	const bool open = !virt_dev->dev_active &&
		(new_state == SCST_TG_STATE_OPTIMIZED ||
		 new_state == SCST_TG_STATE_NONOPTIMIZED);
	int rc = 0;

	TRACE_ENTRY();

	/* No other fd activity may happen concurrently with this function. */
	lockdep_assert_alua_lock_held();

	if (!virt_dev->bind_alua_state)
		return;

	PRINT_INFO("dev %s: ALUA state change from %s to %s finished,%s reopening FD",
		   dev->virt_name, scst_alua_state_name(old_state),
		   scst_alua_state_name(new_state), open ? "" : " not");

	if (!open)
		return;

	rc = vdisk_activate_dev(virt_dev, dev->dev_rd_only);
	if (rc) {
		PRINT_ERROR("dev %s: Activating after ALUA state change to %s failed",
			    dev->virt_name,
			    scst_alua_state_name(new_state));
	}

	TRACE_EXIT();
	return;
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

		dev->tmf_only = dev->tmf_only_saved;
		dev->d_sense = dev->d_sense_saved;
		dev->dpicz = dev->dpicz_saved;
		dev->swp = dev->swp_saved;
		dev->tas = dev->tas_saved;
		dev->queue_alg = dev->queue_alg_saved;
		dev->qerr = dev->qerr_saved;

		dev->tst = virt_dev->tst;

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

#ifdef CONFIG_DEBUG_EXT_COPY_REMAP
static void vdev_ext_copy_remap(struct scst_cmd *cmd,
	struct scst_ext_copy_seg_descr *seg)
{
	struct scst_ext_copy_data_descr *d;
	static int shift;
	static DEFINE_SPINLOCK(lock);
	int s;

	TRACE_ENTRY();

	if (seg->data_descr.data_len <= 4096) {
		/* No way to split */
		goto out_done;
	}

	d = kzalloc(sizeof(*d)*2, GFP_KERNEL);
	if (d == NULL)
		goto out_busy;

	spin_lock(&lock);

	shift += 4096;

	if (shift >= seg->data_descr.data_len) {
		shift = 0;
		s = 0;
	} else
		s = shift;

	TRACE_DBG("cmd %p, seg %p, data_len %d, shift %d, s %d", cmd, seg,
		seg->data_descr.data_len, shift, s);

	spin_unlock(&lock);

	if (s == 0)
		goto out_free_done;

	d[0].data_len = s;
	d[0].src_lba = seg->data_descr.src_lba;
	d[0].dst_lba = seg->data_descr.dst_lba;

	d[1].data_len = seg->data_descr.data_len - s;
	d[1].src_lba = seg->data_descr.src_lba + (s >> seg->src_tgt_dev->dev->block_shift);
	d[1].dst_lba = seg->data_descr.dst_lba + (s >> seg->dst_tgt_dev->dev->block_shift);

	scst_ext_copy_remap_done(cmd, d, 2);

out:
	TRACE_EXIT();
	return;

out_busy:
	scst_set_busy(cmd);

out_free_done:
	kfree(d);

out_done:
#if 1
	scst_ext_copy_remap_done(cmd, &seg->data_descr, 1);
#else
	scst_ext_copy_remap_done(cmd, NULL, 0);
#endif
	goto out;
}
#endif

static void vdisk_report_registering(const struct scst_vdisk_dev *virt_dev)
{
	enum { buf_size = 256 };
	char *buf = kmalloc(buf_size, GFP_KERNEL);
	int i, j;

	if (!buf) {
		PRINT_ERROR("%s: out of memory", __func__);
		return;
	}

	i = snprintf(buf, buf_size, "Registering virtual %s device %s ",
		virt_dev->vdev_devt->name, virt_dev->name);
	j = i;

	if (virt_dev->wt_flag)
		i += snprintf(&buf[i], buf_size - i, "(WRITE_THROUGH");

	if (virt_dev->nv_cache)
		i += snprintf(&buf[i], buf_size - i, "%sNV_CACHE",
			(j == i) ? "(" : ", ");

	if (virt_dev->rd_only)
		i += snprintf(&buf[i], buf_size - i, "%sREAD_ONLY",
			(j == i) ? "(" : ", ");

	if (virt_dev->o_direct_flag)
		i += snprintf(&buf[i], buf_size - i, "%sO_DIRECT",
			(j == i) ? "(" : ", ");

	if (virt_dev->nullio)
		i += snprintf(&buf[i], buf_size - i, "%sNULLIO",
			(j == i) ? "(" : ", ");

	if (virt_dev->blockio)
		i += snprintf(&buf[i], buf_size - i, "%sBLOCKIO",
			(j == i) ? "(" : ", ");

	if (virt_dev->removable)
		i += snprintf(&buf[i], buf_size - i, "%sREMOVABLE",
			(j == i) ? "(" : ", ");

	if (!virt_dev->dev_active)
		i += snprintf(&buf[i], buf_size - i, "%sINACTIVE",
			(j == i) ? "(" : ", ");

	if (virt_dev->tst != DEF_TST)
		i += snprintf(&buf[i], buf_size - i, "%sTST %d",
			(j == i) ? "(" : ", ", virt_dev->tst);

	if (virt_dev->rotational)
		i += snprintf(&buf[i], buf_size - i, "%sROTATIONAL",
			(j == i) ? "(" : ", ");

	if (virt_dev->thin_provisioned)
		i += snprintf(&buf[i], buf_size - i, "%sTHIN_PROVISIONED",
			(j == i) ? "(" : ", ");

	if (virt_dev->dif_mode != SCST_DIF_MODE_NONE) {
		i += snprintf(&buf[i], buf_size - i, "%sDIF MODE %x, "
			"DIF TYPE %d", (j == i) ? "(" : ", ",
			virt_dev->dif_mode, virt_dev->dif_type);
		if (virt_dev->dif_filename != NULL)
			i += snprintf(&buf[i], buf_size - i, ", DIF FILENAME %s",
				virt_dev->dif_filename);
		else if (virt_dev->dif_static_app_tag_combined != SCST_DIF_NO_CHECK_APP_TAG)
			i += snprintf(&buf[i], buf_size - i, ", DIF STATIC APP TAG %llx",
				(long long)be64_to_cpu(virt_dev->dif_static_app_tag_combined));
	}

	if (virt_dev->async)
		i += snprintf(&buf[i], buf_size - i, "%sASYNC",
			(j == i) ? "(" : ", ");

	if (virt_dev->dummy)
		i += snprintf(&buf[i], buf_size - i, "%sDUMMY",
			(j == i) ? "(" : ", ");

	PRINT_INFO("%s%s", buf, j == i ? "" : ")");

	kfree(buf);

	return;
}

static int vdisk_resync_size(struct scst_vdisk_dev *virt_dev)
{
	loff_t file_size;
	int res = 0;

	sBUG_ON(virt_dev->nullio);
	sBUG_ON(!virt_dev->filename);

	if ((!virt_dev->fd && !virt_dev->bdev) || !virt_dev->dev_active) {
		res = -EMEDIUMTYPE;
		goto out;
	}

	res = vdisk_get_file_size(virt_dev, &file_size);
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

	virt_dev->size_key = 0;

	PRINT_INFO("New size of SCSI target virtual disk %s "
		"(fs=%lldMB, bs=%d, nblocks=%lld, cyln=%lld%s)",
		virt_dev->name, virt_dev->file_size >> 20,
		virt_dev->dev->block_size,
		(unsigned long long)virt_dev->nblocks,
		(unsigned long long)virt_dev->nblocks/64/32,
		virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
						"than 1" : "");

	scst_capacity_data_changed(virt_dev->dev);

	scst_resume_activity();
out:
	return res;
}

static int vdisk_create_bioset(struct scst_vdisk_dev *virt_dev)
{
	int res = 0;

	EXTRACHECKS_BUG_ON(virt_dev->vdisk_bioset || !virt_dev->blockio);

	/* Pool size doesn't really matter */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	virt_dev->vdisk_bioset = &virt_dev->vdisk_bioset_struct;
	res = bioset_init(&virt_dev->vdisk_bioset_struct, 2, 0,
			  BIOSET_NEED_BVECS);
#else
	virt_dev->vdisk_bioset = bioset_create(2, 0, BIOSET_NEED_BVECS);
	if (virt_dev->vdisk_bioset == NULL)
		res = -ENOMEM;
#endif
	if (res < 0) {
		PRINT_ERROR("Failed to create bioset (dev %s)", virt_dev->name);
		goto out;
	}

	if (virt_dev->dif_mode & SCST_DIF_MODE_DEV) {
		/* The same, pool size doesn't really matter */
		res = bioset_integrity_create(virt_dev->vdisk_bioset, 2);
		if (res != 0) {
			PRINT_ERROR("Failed to create integrity bioset "
				"(dev %s)", virt_dev->name);
			goto out_free;
		}
	}

	res = 0;

out:
	return res;

out_free:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	bioset_exit(virt_dev->vdisk_bioset);
#else
	bioset_free(virt_dev->vdisk_bioset);
#endif
	virt_dev->vdisk_bioset = NULL;
	goto out;
}

static void vdisk_free_bioset(struct scst_vdisk_dev *virt_dev)
{
	if (virt_dev->vdisk_bioset == NULL)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	bioset_exit(virt_dev->vdisk_bioset);
#else
	bioset_free(virt_dev->vdisk_bioset);
#endif
}

static void vdev_inq_changed_fn(struct work_struct *work)
{
	struct scst_vdisk_dev *virt_dev = container_of(work,
		struct scst_vdisk_dev, vdev_inq_changed_work);
	struct scst_device *dev = virt_dev->dev;

	TRACE_ENTRY();

	TRACE_DBG("Updating INQUIRY data for virt_dev %p (dev %s)",
		virt_dev, dev->virt_name);

	scst_dev_inquiry_data_changed(dev);

	TRACE_EXIT();
	return;
}

static int vdev_create_node(struct scst_dev_type *devt,
	const char *name, int nodeid, struct scst_vdisk_dev **res_virt_dev)
{
	int res;
	struct scst_vdisk_dev *virt_dev, *vv;
	uint64_t dev_id_num;

	lockdep_assert_held(&scst_vdisk_mutex);

	res = -EEXIST;
	if (vdev_find(name))
		goto out;

	/* It's read-mostly, so cache alignment isn't needed */
	virt_dev = kzalloc_node(sizeof(*virt_dev), GFP_KERNEL, nodeid);
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
	virt_dev->read_zero = DEF_READ_ZERO;
	virt_dev->removable = DEF_REMOVABLE;
	virt_dev->rotational = DEF_ROTATIONAL;
	virt_dev->thin_provisioned = DEF_THIN_PROVISIONED;
	virt_dev->tst = DEF_TST;
	INIT_WORK(&virt_dev->vdev_inq_changed_work, vdev_inq_changed_fn);

	virt_dev->blk_shift = DEF_DISK_BLOCK_SHIFT;
	virt_dev->opt_trans_len = DEF_OPT_TRANS_LEN;
	virt_dev->numa_node_id = NUMA_NO_NODE;
	virt_dev->dev_active = DEF_DEV_ACTIVE;
	virt_dev->bind_alua_state = DEF_BIND_ALUA_STATE;

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

	sprintf(virt_dev->t10_vend_id, "%.*s",
		(int)sizeof(virt_dev->t10_vend_id) - 1, SCST_FIO_VENDOR);

	sprintf(virt_dev->vend_specific_id, "%.*s",
		(int)(sizeof(virt_dev->vend_specific_id) - 1),
		virt_dev->t10_dev_id);

	sprintf(virt_dev->prod_id, "%.*s", (int)(sizeof(virt_dev->prod_id) - 1),
		virt_dev->name);

	sprintf(virt_dev->prod_rev_lvl, "%.*s",
		(int)(sizeof(virt_dev->prod_rev_lvl) - 1), SCST_FIO_REV);

	sprintf(virt_dev->scsi_device_name, "%.*s",
		(int)(sizeof(virt_dev->scsi_device_name) - 1), "");

	virt_dev->eui64_id_len = 0;
	virt_dev->naa_id_len = 0;

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

static inline int vdev_create(struct scst_dev_type *devt,
	const char *name, struct scst_vdisk_dev **res_virt_dev)
{
	return vdev_create_node(devt, name, NUMA_NO_NODE, res_virt_dev);
}

static void vdev_destroy(struct scst_vdisk_dev *virt_dev)
{
	vdisk_free_bioset(virt_dev);
	kfree(virt_dev->filename);
	kfree(virt_dev->dif_filename);
	kfree(virt_dev);
	return;
}


static void vdev_check_node(struct scst_vdisk_dev **pvirt_dev, int orig_nodeid)
{
	struct scst_vdisk_dev *virt_dev = *pvirt_dev;
	int nodeid = virt_dev->numa_node_id;

	TRACE_ENTRY();

	if (virt_dev->numa_node_id != orig_nodeid) {
		struct scst_vdisk_dev *v;

		TRACE_MEM("Realloc virt_dev %s on node %d", virt_dev->name, nodeid);
		/* It's read-mostly, so cache alignment isn't needed */
		v = kzalloc_node(sizeof(*v), GFP_KERNEL, nodeid);
		if (v == NULL) {
			PRINT_ERROR("Reallocation of virtual device %s failed",
				virt_dev->name);
			goto out;
		}
		*v = *virt_dev;
		kfree(virt_dev);
		/*
		 * Since the address of the virtual device changed, update all
		 * pointers in the virtual device that point to the virtual
		 * device itself.
		 */
		INIT_WORK(&v->vdev_inq_changed_work, vdev_inq_changed_fn);
		*pvirt_dev = v;
	}

out:
	TRACE_EXIT();
	return;
}

/*
 * Parse the add_device parameters. @allowed_params restricts which
 * parameters can be specified at device creation time.
 */
static int vdev_parse_add_dev_params(struct scst_vdisk_dev *virt_dev,
	char *params, const char *const allowed_params[])
{
	int res = 0;
	unsigned long long ull_val;
	long long ll_val;
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
			if (virt_dev->filename) {
				PRINT_ERROR("%s specified more than once"
					    " (device %s)", p, virt_dev->name);
				res = -EINVAL;
				goto out;
			}
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

		if (!strcasecmp("dif_filename", p)) {
			if (*pp != '/') {
				PRINT_ERROR("DIF filename %s must be global "
					"(device %s)", pp, virt_dev->name);
				res = -EINVAL;
				goto out;
			}

			virt_dev->dif_filename = kstrdup(pp, GFP_KERNEL);
			if (virt_dev->dif_filename == NULL) {
				PRINT_ERROR("Unable to duplicate DIF filename %s "
					"(device %s)", pp, virt_dev->name);
				res = -ENOMEM;
				goto out;
			}
			continue;
		}

		if (!strcasecmp("dif_mode", p)) {
			char *d = pp;

			while (1) {
				char *dd;

				for (; (*d != '\0') && isspace(*d); d++)
					;
				if (*d == '\0')
					break;

				dd = strchr(d, '|');
				if (dd != NULL)
					*dd = '\0';
				if (!strcasecmp(SCST_DIF_MODE_TGT_STR, d))
					virt_dev->dif_mode |= SCST_DIF_MODE_TGT;
				else if (!strcasecmp(SCST_DIF_MODE_SCST_STR, d))
					virt_dev->dif_mode |= SCST_DIF_MODE_SCST;
				else if (!strcasecmp(SCST_DIF_MODE_DEV_CHECK_STR, d)) {
					virt_dev->dif_mode |= SCST_DIF_MODE_DEV_CHECK;
				} else if (!strcasecmp(SCST_DIF_MODE_DEV_STORE_STR, d))
					virt_dev->dif_mode |= SCST_DIF_MODE_DEV_STORE;
				else {
					PRINT_ERROR("Error parsing DIF mode %s", pp);
					res = -EINVAL;
					goto out;
				}
				if (dd == NULL)
					break;
				else
					*dd = '|';
				d = dd+1;
			}
			TRACE_DBG("DIF DEV mode %x", virt_dev->dif_mode);
			continue;
		}

		res = kstrtoll(pp, 0, &ll_val);
		if (res != 0) {
			PRINT_ERROR("strtoll() for %s failed: %d (device %s)",
				    pp, res, virt_dev->name);
			goto out;
		}

		if (!strcasecmp("numa_node_id", p)) {
			virt_dev->numa_node_id = ll_val;
			BUILD_BUG_ON(NUMA_NO_NODE != -1);
			if (virt_dev->numa_node_id < NUMA_NO_NODE) {
				res = -EINVAL;
				goto out;
			}
			TRACE_DBG("numa_node_id %d", virt_dev->numa_node_id);
			continue;
		}

		res = kstrtoull(pp, 0, &ull_val);
		if (res != 0) {
			PRINT_ERROR("strtoull() for %s failed: %d (device %s)",
				    pp, res, virt_dev->name);
			goto out;
		}

		if (!strcasecmp("write_through", p)) {
			virt_dev->wt_flag = ull_val;
			TRACE_DBG("WRITE THROUGH %d", virt_dev->wt_flag);
		} else if (!strcasecmp("nv_cache", p)) {
			virt_dev->nv_cache = ull_val;
			TRACE_DBG("NON-VOLATILE CACHE %d", virt_dev->nv_cache);
		} else if (!strcasecmp("o_direct", p)) {
			virt_dev->o_direct_flag = ull_val;
			TRACE_DBG("O_DIRECT %d", virt_dev->o_direct_flag);
		} else if (!strcasecmp("read_only", p)) {
			virt_dev->rd_only = ull_val;
			TRACE_DBG("READ ONLY %d", virt_dev->rd_only);
		} else if (!strcasecmp("dummy", p)) {
			if (ull_val > 1) {
				res = -EINVAL;
				goto out;
			}
			virt_dev->dummy = ull_val;
			TRACE_DBG("DUMMY %d", virt_dev->dummy);
		} else if (!strcasecmp("removable", p)) {
			virt_dev->removable = ull_val;
			TRACE_DBG("REMOVABLE %d", virt_dev->removable);
		} else if (!strcasecmp("active", p)) {
			virt_dev->dev_active = ull_val;
			TRACE_DBG("ACTIVE %d", virt_dev->dev_active);
		} else if (!strcasecmp("bind_alua_state", p)) {
			virt_dev->bind_alua_state = ull_val;
			TRACE_DBG("BIND_ALUA_STATE %d",
				  virt_dev->bind_alua_state);
		} else if (!strcasecmp("rotational", p)) {
			virt_dev->rotational = ull_val;
			TRACE_DBG("ROTATIONAL %d", virt_dev->rotational);
		} else if (!strcasecmp("tst", p)) {
			if ((ull_val != SCST_TST_0_SINGLE_TASK_SET) &&
			    (ull_val != SCST_TST_1_SEP_TASK_SETS)) {
				PRINT_ERROR("Invalid TST value %lld", ull_val);
				res = -EINVAL;
				goto out;
			}
			virt_dev->tst = ull_val;
			TRACE_DBG("TST %d", virt_dev->tst);
		} else if (!strcasecmp("thin_provisioned", p)) {
			virt_dev->thin_provisioned = ull_val;
			virt_dev->thin_provisioned_manually_set = 1;
			TRACE_DBG("THIN PROVISIONED %d",
				virt_dev->thin_provisioned);
		} else if (!strcasecmp("async", p)) {
			virt_dev->async = !!ull_val;
		} else if (!strcasecmp("size", p)) {
			virt_dev->file_size = ull_val;
		} else if (!strcasecmp("size_mb", p)) {
			virt_dev->file_size = ull_val * 1024 * 1024;
		} else if (!strcasecmp("cluster_mode", p)) {
			virt_dev->initial_cluster_mode = ull_val;
			TRACE_DBG("CLUSTER_MODE %d",
				  virt_dev->initial_cluster_mode);
		} else if (!strcasecmp("blocksize", p)) {
			virt_dev->blk_shift = scst_calc_block_shift(ull_val);
			if (virt_dev->blk_shift < 9) {
				PRINT_ERROR("blocksize %llu too small", ull_val);
				res = -EINVAL;
				goto out;
			}
			TRACE_DBG("block size %lld, block shift %d",
				ull_val, virt_dev->blk_shift);
		} else if (!strcasecmp("dif_type", p)) {
			virt_dev->dif_type = ull_val;
			TRACE_DBG("DIF type %d", virt_dev->dif_type);
		} else if (!strcasecmp("dif_static_app_tag", p)) {
			virt_dev->dif_static_app_tag_combined = cpu_to_be64(ull_val);
			TRACE_DBG("DIF static app tag %llx",
				(long long)be64_to_cpu(virt_dev->dif_static_app_tag_combined));
		} else {
			PRINT_ERROR("Unknown parameter %s (device %s)", p,
				virt_dev->name);
			res = -EINVAL;
			goto out;
		}
	}

	if ((virt_dev->file_size & ((1 << virt_dev->blk_shift) - 1)) != 0) {
		PRINT_ERROR("Device size %lld is not a multiple of the block"
			    " size %d", virt_dev->file_size,
			    1 << virt_dev->blk_shift);
		res = -EINVAL;
	}
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdev_fileio_add_device(const char *device_name, char *params)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_vdisk_mutex);

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

	vdev_check_node(&virt_dev, NUMA_NO_NODE);

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	vdisk_report_registering(virt_dev);

	virt_dev->virt_id = scst_register_virtual_device_node(virt_dev->vdev_devt,
					virt_dev->name, virt_dev->numa_node_id);
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

static int vdev_blockio_add_device(const char *device_name, char *params)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_vdisk_mutex);

	res = vdev_create(&vdisk_blk_devtype, device_name, &virt_dev);
	if (res != 0)
		goto out;

	virt_dev->command_set_version = 0x04C0; /* SBC-3 */

	virt_dev->blockio = 1;
	virt_dev->wt_flag = DEF_WRITE_THROUGH;
	sprintf(virt_dev->t10_vend_id, "%.*s",
		(int)sizeof(virt_dev->t10_vend_id) - 1, SCST_BIO_VENDOR);

	res = vdev_parse_add_dev_params(virt_dev, params,
			virt_dev->vdev_devt->add_device_parameters);
	if (res != 0)
		goto out_destroy;

	if (virt_dev->filename == NULL) {
		PRINT_ERROR("File name required (device %s)", virt_dev->name);
		res = -EINVAL;
		goto out_destroy;
	}

	vdev_check_node(&virt_dev, NUMA_NO_NODE);

	res = vdisk_create_bioset(virt_dev);
	if (res != 0)
		goto out_destroy;

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	vdisk_report_registering(virt_dev);

	virt_dev->virt_id = scst_register_virtual_device_node(virt_dev->vdev_devt,
					virt_dev->name, virt_dev->numa_node_id);
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

static int vdev_nullio_add_device(const char *device_name, char *params)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_vdisk_mutex);

	res = vdev_create(&vdisk_null_devtype, device_name, &virt_dev);
	if (res != 0)
		goto out;

	virt_dev->command_set_version = 0x04C0; /* SBC-3 */

	virt_dev->nullio = 1;
	virt_dev->file_size = VDISK_NULLIO_SIZE;

	res = vdev_parse_add_dev_params(virt_dev, params,
			virt_dev->vdev_devt->add_device_parameters);
	if (res != 0)
		goto out_destroy;

	vdev_check_node(&virt_dev, NUMA_NO_NODE);

	list_add_tail(&virt_dev->vdev_list_entry, &vdev_list);

	vdisk_report_registering(virt_dev);

	virt_dev->virt_id = scst_register_virtual_device_node(virt_dev->vdev_devt,
					virt_dev->name, virt_dev->numa_node_id);
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


static void vdev_on_free(struct scst_device *dev, void *arg)
{
	struct scst_vdisk_dev *virt_dev = arg;

	TRACE_DBG("%s(%s)", __func__, dev->virt_name ? : "(?)");

	/*
	 * This call must happen after scst_unregister_virtual_device()
	 * has called scst_dev_sysfs_del() and before scst_free_device()
	 * starts deallocating *dev.
	 */
	cancel_work_sync(&virt_dev->vdev_inq_changed_work);
}

static void vdev_del_device(struct scst_vdisk_dev *virt_dev)
{
	TRACE_ENTRY();

	lockdep_assert_held(&scst_vdisk_mutex);

	scst_unregister_virtual_device(virt_dev->virt_id, vdev_on_free,
				       virt_dev);

	list_del(&virt_dev->vdev_list_entry);

	PRINT_INFO("Virtual device %s unregistered", virt_dev->name);
	TRACE_DBG("virt_id %d unregistered", virt_dev->virt_id);

	vdev_destroy(virt_dev);

	return;
}


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

static ssize_t __vcdrom_add_device(const char *device_name, char *params)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_vdisk_mutex);

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

	res = vdev_parse_add_dev_params(virt_dev, params,
			virt_dev->vdev_devt->add_device_parameters);
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


static int vcdrom_change(struct scst_vdisk_dev *virt_dev, char *buffer)
{
	loff_t err;
	char *old_fn, *p;
	bool old_empty;
	const char *filename = NULL;
	int length = strlen(buffer);
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("virt_dev %s, empty %d, fd %p (dif_fd %p), filename %p",
		  virt_dev->name, virt_dev->cdrom_empty, virt_dev->fd,
		  virt_dev->dif_fd, virt_dev->filename);

	if (virt_dev->prevent_allow_medium_removal) {
		PRINT_ERROR("Prevent medium removal for "
			"virtual device with name %s", virt_dev->name);
		res = -EBUSY;
		goto out;
	}

	p = buffer;

	/* Skip leading whitespace */
	while (isspace(*p) && *p != '\0')
		p++;
	filename = p;
	/* Strip trailing whitespace */
	WARN_ON_ONCE(length == 0);
	p = &buffer[length-1];
	while (p > buffer && isspace(*p))
		p--;
	p[1] = '\0';

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	/* To sync with detach*() functions */
	mutex_lock(&scst_mutex);

	old_empty = virt_dev->cdrom_empty;
	old_fn = virt_dev->filename;

	if (*filename == '\0') {
		virt_dev->cdrom_empty = 1;
		TRACE_DBG("%s", "No media");
	} else if (*filename != '/') {
		PRINT_ERROR("File path \"%s\" is not absolute", filename);
		res = -EINVAL;
		goto out_e_unlock;
	} else
		virt_dev->cdrom_empty = 0;

	if (!virt_dev->cdrom_empty) {
		char *fn = kstrdup(filename, GFP_KERNEL);

		if (fn == NULL) {
			PRINT_ERROR("%s", "Allocation of filename failed");
			res = -ENOMEM;
			goto out_e_unlock;
		}

		virt_dev->filename = fn;

		res = vdisk_get_file_size(virt_dev, &err);
		if (res != 0)
			goto out_free_fn;
		if (!vdisk_is_open(virt_dev)) {
			res = vdisk_reopen_fd(virt_dev, true);
			if (res != 0)
				goto out_free_fn;
			sBUG_ON(!virt_dev->fd);
		}
	} else {
		err = 0;
		virt_dev->filename = NULL;
		virt_dev->fd = NULL;
		virt_dev->bdev = NULL;
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
			(unsigned long long)virt_dev->nblocks,
			(unsigned long long)virt_dev->nblocks/64/32,
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
	TRACE_DBG("virt_dev %s, empty %d, fd %p (dif_fd %p), filename %p", virt_dev->name,
		virt_dev->cdrom_empty, virt_dev->fd, virt_dev->dif_fd, virt_dev->filename);

	TRACE_EXIT_RES(res);
	return res;

out_free_fn:
	kfree(virt_dev->filename);
	virt_dev->filename = old_fn;

out_e_unlock:
	virt_dev->cdrom_empty = old_empty;

	mutex_unlock(&scst_mutex);
	goto out_resume;
}


static ssize_t vdisk_sysfs_sync_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_device *dev =
		container_of(kobj, struct scst_device, dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	int res;

	if (virt_dev->nullio)
		res = 0;
	else if (virt_dev->blockio)
		res = vdisk_blockio_flush(virt_dev->bdev, GFP_KERNEL, false,
					  NULL, false);
	else
		res = __vdisk_fsync_fileio(0, i_size_read(file_inode(virt_dev->fd)),
					   dev, NULL, virt_dev->fd);

	return res ? : count;
}

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

static int vdev_size_process_store(struct scst_sysfs_work_item *work)
{
	struct scst_device *dev = work->dev;
	struct scst_vdisk_dev *virt_dev;
	unsigned long long new_size;
	int size_shift, res = -EINVAL;
	bool queue_ua;

	if (sscanf(work->buf, "%d %lld", &size_shift, &new_size) != 2 ||
	    new_size > (ULLONG_MAX >> size_shift))
		goto put;

	new_size <<= size_shift;

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res)
		goto put;

	/* To sync with detach*() functions */
	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto resume;

	virt_dev = dev->dh_priv;

	queue_ua = vdisk_is_open(virt_dev);

	if ((new_size & ((1 << virt_dev->blk_shift) - 1)) == 0) {
		virt_dev->file_size = new_size;
		virt_dev->nblocks = virt_dev->file_size >> dev->block_shift;
		virt_dev->size_key = 1;
	} else {
		res = -EINVAL;
	}

	mutex_unlock(&scst_mutex);

	if ((res == 0) || queue_ua)
		scst_capacity_data_changed(dev);

resume:
	scst_resume_activity();

put:
	kobject_put(&dev->dev_kobj);
	return res;
}

static ssize_t vdev_size_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf,
		size_t count, int size_shift)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	struct scst_sysfs_work_item *work;
	char *new_size;
	int res = -ENOMEM;

	new_size = kasprintf(GFP_KERNEL, "%d %.*s", size_shift, (int)count,
			     buf);
	if (!new_size)
		goto out;

	res = scst_alloc_sysfs_work(vdev_size_process_store, false, &work);
	if (res)
		goto out_free;

	work->buf = new_size;
	work->dev = dev;

	SCST_SET_DEP_MAP(work, &scst_dev_dep_map);
	kobject_get(&dev->dev_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	return res;

out_free:
	kfree(new_size);
	goto out;
}

static ssize_t vdev_sysfs_size_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	return vdev_size_store(kobj, attr, buf, count, 0);
}

static ssize_t vdev_size_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf, int size_shift)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	unsigned long long size;
	bool key;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	size = READ_ONCE(virt_dev->file_size);
	/*
	 * Make sure that scstadmin only stores the 'size' attribute and that
	 * the 'size_mb' attribute is not stored. Otherwise when restoring
	 * scst.conf if 'size' is not a multiple of 1 MB it will be rounded
	 * down.
	 */
	key = !(virt_dev->nullio && size == VDISK_NULLIO_SIZE) && !size_shift;

	return sprintf(buf, "%llu\n%s", size >> size_shift,
		       key ? SCST_SYSFS_KEY_MARK "\n" : "");
}

static ssize_t vdev_sysfs_size_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return vdev_size_show(kobj, attr, buf, 0);
}

static ssize_t vdev_sysfs_size_mb_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	return vdev_size_store(kobj, attr, buf, count, 20);
}

static ssize_t vdev_sysfs_size_mb_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return vdev_size_show(kobj, attr, buf, 20);
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

static ssize_t vdisk_opt_trans_len_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct scst_device *dev =
		container_of(kobj, struct scst_device, dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	unsigned long val;
	int res;

	res = kstrtoul(buf, 0, &val);
	if (res)
		return res;
	if (val & (dev->block_size - 1))
		return -EINVAL;

	/*
	 * To do: generate a unit attention because of the opt_trans_len
	 * change.
	 */
	spin_lock(&virt_dev->flags_lock);
	virt_dev->opt_trans_len_set = 1;
	virt_dev->opt_trans_len = val;
	spin_unlock(&virt_dev->flags_lock);

	return count;
}

static ssize_t vdisk_opt_trans_len_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev =
		container_of(kobj, struct scst_device, dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	return sprintf(buf, "%d\n%s", virt_dev->opt_trans_len,
		       virt_dev->opt_trans_len_set ? SCST_SYSFS_KEY_MARK "\n" :
		       "");
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

	pos = sprintf(buf, "%d\n%s", virt_dev->rd_only,
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

	pos = sprintf(buf, "%d\n%s", virt_dev->wt_flag,
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

	pos = sprintf(buf, "%d\n%s", virt_dev->thin_provisioned,
		      virt_dev->thin_provisioned_manually_set ?
		      SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_gen_tp_soft_threshold_reached_UA(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	if (!virt_dev->thin_provisioned)
		return -EINVAL;

	spin_lock_bh(&dev->dev_lock);
	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
		scst_set_tp_soft_threshold_reached_UA(tgt_dev);
	}
	spin_unlock_bh(&dev->dev_lock);

	TRACE_EXIT_RES(count);
	return count;
}

static ssize_t vdisk_sysfs_expl_alua_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);

	return sprintf(buf, "%d\n%s", dev->expl_alua,
		      dev->expl_alua != DEF_EXPL_ALUA ?
		      SCST_SYSFS_KEY_MARK "\n" : "");

}

static ssize_t vdisk_sysfs_expl_alua_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	unsigned long expl_alua;
	int res;

	res = kstrtoul(buf, 0, &expl_alua);
	if (res < 0)
		return res;

	spin_lock_bh(&dev->dev_lock);
	dev->expl_alua = !!expl_alua;
	spin_unlock_bh(&dev->dev_lock);

	return count;
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

	pos = sprintf(buf, "%d\n%s", virt_dev->nv_cache,
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

	pos = sprintf(buf, "%d\n%s", virt_dev->o_direct_flag,
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

static ssize_t vdev_sysfs_rz_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	bool read_zero = virt_dev->read_zero;

	return sprintf(buf, "%d\n%s", read_zero, read_zero != DEF_READ_ZERO ?
		       SCST_SYSFS_KEY_MARK "\n" : "");
}

static ssize_t vdev_sysfs_rz_store(struct kobject *kobj,
				   struct kobj_attribute *attr, const char *buf,
				   size_t count)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	long read_zero;
	int res;
	char ch[16];

	sprintf(ch, "%.*s", min_t(int, sizeof(ch) - 1, count), buf);
	res = kstrtol(ch, 0, &read_zero);
	if (res)
		goto out;
	res = -EINVAL;
	if (read_zero != 0 && read_zero != 1)
		goto out;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->read_zero = read_zero;
	spin_unlock(&virt_dev->flags_lock);

	res = count;

out:
	return res;
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

	pos = sprintf(buf, "%d\n", virt_dev->removable);

	if ((virt_dev->dev->type != TYPE_ROM) &&
	    (virt_dev->removable != DEF_REMOVABLE))
		pos += sprintf(&buf[pos], "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_tst_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->tst);

	if (virt_dev->tst != DEF_TST)
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

	pos = sprintf(buf, "%d\n", virt_dev->rotational);

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

static int vdev_sysfs_process_filename_store(struct scst_sysfs_work_item *work)
{
	struct scst_device *dev = work->dev;
	struct scst_vdisk_dev *virt_dev;
	int length = strlen(work->buf);
	char *p, *fn;
	const char *filename = NULL;
	int res;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;

	res = -EINVAL;

	/* Serialize against vdisk_open_fd() and vdisk_close_fd() calls. */
	scst_alua_lock();

	/*
	 * This is safe since we hold a reference on dev_kobj and since
	 * scst_assign_dev_handler() waits until all dev_kobj references
	 * have been dropped before invoking .detach().
	 */
	virt_dev = dev->dh_priv;
	if (virt_dev->dev_active) {
		PRINT_ERROR("vdev %s: can't change the filename because the device is still active",
			    dev->virt_name);
		goto unlock;
	}

	p = work->buf;
	while (isspace(*p) && *p)
		p++;
	if (*p == '\0') {
		PRINT_ERROR("Filename is missing");
		goto unlock;
	}
	filename = p;
	p = &work->buf[length - 1];
	while (isspace(*p))
		p--;
	*(p + 1) = '\0';
	if (*filename != '/') {
		PRINT_ERROR("Path \"%s\" is not absolute", filename);
		goto unlock;
	}
	fn = kstrdup(filename, GFP_KERNEL);
	if (fn == NULL) {
		PRINT_ERROR("Filename allocation failed");
		goto unlock;
	}
	swap(virt_dev->filename, fn);
	kfree(fn);
	PRINT_INFO("vdev %s: changed filename into \"%s\"", virt_dev->name,
		   virt_dev->filename);
	res = 0;

unlock:
	scst_alua_unlock();
	mutex_unlock(&scst_mutex);

out:
	kobject_put(&dev->dev_kobj);

	return res;
}

static ssize_t vdev_sysfs_filename_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	struct scst_sysfs_work_item *work;
	char *arg;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	arg = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!arg)
		goto out;

	res = scst_alloc_sysfs_work(vdev_sysfs_process_filename_store,
				    false, &work);
	if (res)
		goto out;
	work->dev = dev;
	swap(work->buf, arg);
	kobject_get(&dev->dev_kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(arg);
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_cluster_mode_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);

	return sprintf(buf, "%d\n%s", dev->cluster_mode,
		       dev->cluster_mode ?
		       SCST_SYSFS_KEY_MARK "\n" : "");
}

static int vdev_sysfs_process_cluster_mode_store(
	struct scst_sysfs_work_item *work)
{
	struct scst_device *dev = work->dev;
	struct scst_vdisk_dev *virt_dev;
	long clm;
	int res;

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto resume;

	/*
	 * This is safe since we hold a reference on dev_kobj and since
	 * scst_assign_dev_handler() waits until all dev_kobj references
	 * have been dropped before invoking .detach().
	 */
	virt_dev = dev->dh_priv;
	res = kstrtol(work->buf, 0, &clm);
	if (res)
		goto unlock;
	res = -EINVAL;
	if (clm < 0 || clm > 1)
		goto unlock;
	if (clm != dev->cluster_mode) {
		res = scst_pr_set_cluster_mode(dev, clm, virt_dev->t10_dev_id);
		if (res)
			goto unlock;
		dev->cluster_mode = clm;
	} else {
		res = 0;
	}

unlock:
	mutex_unlock(&scst_mutex);

resume:
	scst_resume_activity();

out:
	kobject_put(&dev->dev_kobj);

	return res;
}

static ssize_t vdev_sysfs_cluster_mode_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	struct scst_sysfs_work_item *work;
	char *arg;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	arg = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!arg)
		goto out;

	res = scst_alloc_sysfs_work(vdev_sysfs_process_cluster_mode_store,
				    false, &work);
	if (res)
		goto out;
	work->dev = dev;
	swap(work->buf, arg);
	kobject_get(&dev->dev_kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(arg);
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

static ssize_t vdev_sysfs_t10_vend_id_store(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	char *p;
	int res, len;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	p = memchr(buf, '\n', count);
	len = p ? p - buf : count;

	if (len >= sizeof(virt_dev->t10_vend_id)) {
		PRINT_ERROR("T10 vendor id is too long (max %zd characters)",
			    sizeof(virt_dev->t10_vend_id));
		res = -EINVAL;
		goto out;
	}

	write_lock(&vdisk_serial_rwlock);
	sprintf(virt_dev->t10_vend_id, "%.*s", len, buf);
	virt_dev->t10_vend_id_set = 1;
	write_unlock(&vdisk_serial_rwlock);

	schedule_work(&virt_dev->vdev_inq_changed_work);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_t10_vend_id_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	int pos;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = sprintf(buf, "%s\n%s", virt_dev->t10_vend_id,
		      virt_dev->t10_vend_id_set ? SCST_SYSFS_KEY_MARK "\n" :
		      "");
	read_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_sysfs_vend_specific_id_store(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	char *p;
	int res, len;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	p = memchr(buf, '\n', count);
	len = p ? p - buf : count;

	if (len >= sizeof(virt_dev->vend_specific_id)) {
		PRINT_ERROR("Vendor specific id is too long (max %zd"
			    " characters)",
			    sizeof(virt_dev->vend_specific_id) - 1);
		res = -EINVAL;
		goto out;
	}

	write_lock(&vdisk_serial_rwlock);
	sprintf(virt_dev->vend_specific_id, "%.*s", len, buf);
	virt_dev->vend_specific_id_set = 1;
	write_unlock(&vdisk_serial_rwlock);

	schedule_work(&virt_dev->vdev_inq_changed_work);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_vend_specific_id_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	int pos;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = sprintf(buf, "%s\n%s", virt_dev->vend_specific_id,
		      virt_dev->vend_specific_id_set ?
		      SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_sysfs_prod_id_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	char *p;
	int res, len;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	p = memchr(buf, '\n', count);
	len = p ? p - buf : count;

	if (len >= sizeof(virt_dev->prod_id)) {
		PRINT_ERROR("Product id is too long (max %zd characters)",
			    sizeof(virt_dev->prod_id));
		res = -EINVAL;
		goto out;
	}

	write_lock(&vdisk_serial_rwlock);
	sprintf(virt_dev->prod_id, "%.*s", len, buf);
	virt_dev->prod_id_set = 1;
	write_unlock(&vdisk_serial_rwlock);

	schedule_work(&virt_dev->vdev_inq_changed_work);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_prod_id_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buf)
{
	int pos;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = sprintf(buf, "%s\n%s", virt_dev->prod_id,
		      virt_dev->prod_id_set ? SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_sysfs_prod_rev_lvl_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	char *p;
	int res, len;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	p = memchr(buf, '\n', count);
	len = p ? p - buf : count;

	if (len >= sizeof(virt_dev->prod_rev_lvl)) {
		PRINT_ERROR("Product revision level is too long (max %zd"
			    " characters)",
			    sizeof(virt_dev->prod_rev_lvl));
		res = -EINVAL;
		goto out;
	}

	write_lock(&vdisk_serial_rwlock);
	sprintf(virt_dev->prod_rev_lvl, "%.*s", len, buf);
	virt_dev->prod_rev_lvl_set = 1;
	write_unlock(&vdisk_serial_rwlock);

	schedule_work(&virt_dev->vdev_inq_changed_work);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_prod_rev_lvl_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	int pos;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = sprintf(buf, "%s\n%s", virt_dev->prod_rev_lvl,
		      virt_dev->prod_rev_lvl_set ? SCST_SYSFS_KEY_MARK "\n" :
		      "");
	read_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_sysfs_scsi_device_name_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	char *p;
	int res, len;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	p = memchr(buf, '\n', count);
	len = p ? p - buf : count;

	if (len >= sizeof(virt_dev->scsi_device_name)) {
		PRINT_ERROR("SCSI device namel is too long (max %zd characters)",
			sizeof(virt_dev->scsi_device_name));
		res = -EINVAL;
		goto out;
	}

	write_lock(&vdisk_serial_rwlock);
	sprintf(virt_dev->scsi_device_name, "%.*s", len, buf);
	if (strlen(virt_dev->scsi_device_name) > 0)
		virt_dev->scsi_device_name_set = 1;
	else
		virt_dev->scsi_device_name_set = 0;
	write_unlock(&vdisk_serial_rwlock);

	schedule_work(&virt_dev->vdev_inq_changed_work);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_scsi_device_name_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	int pos;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = sprintf(buf, "%s\n%s", virt_dev->scsi_device_name,
		      virt_dev->scsi_device_name_set ? SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

	TRACE_EXIT_RES(pos);
	return pos;
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

	res = -EPERM;
	if (dev->cluster_mode)
		goto out;

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

	schedule_work(&virt_dev->vdev_inq_changed_work);

	res = count;

	PRINT_INFO("T10 device id for device %s changed to %s", virt_dev->name,
		virt_dev->t10_dev_id);

out_unlock:
	write_unlock(&vdisk_serial_rwlock);

out:
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

static ssize_t vdev_sysfs_eui64_id_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	int res = count;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	while (count > 0 && isspace((uint8_t)buf[0])) {
		buf++;
		count--;
	}
	while (count > 0 && isspace((uint8_t)buf[count - 1]))
		count--;
	if (count >= 2 && buf[0] == '0' && buf[1] == 'x') {
		buf += 2;
		count -= 2;
	}

	switch (count) {
	case 0:
	case 2 * 8:
	case 2 * 12:
	case 2 * 16:
		break;
	default:
		res = -EINVAL;
		goto out;
	}

	write_lock(&vdisk_serial_rwlock);
	if (hex2bin(virt_dev->eui64_id, buf, count / 2) == 0)
		virt_dev->eui64_id_len = count / 2;
	else
		res = -EINVAL;
	write_unlock(&vdisk_serial_rwlock);

	if (res >= 0)
		schedule_work(&virt_dev->vdev_inq_changed_work);

out:
	return res;
}

static ssize_t vdev_sysfs_eui64_id_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int i, pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	if (virt_dev->eui64_id_len)
		pos += sprintf(buf + pos, "0x");
	for (i = 0; i < virt_dev->eui64_id_len; i++)
		pos += sprintf(buf + pos, "%02x", virt_dev->eui64_id[i]);
	pos += sprintf(buf + pos, "\n%s", virt_dev->eui64_id_len ?
		       SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

	return pos;
}

static ssize_t vdev_sysfs_naa_id_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	int res = -EINVAL, c = count;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	while (c > 0 && isspace((uint8_t)buf[0])) {
		buf++;
		c--;
	}
	while (c > 0 && isspace((uint8_t)buf[c - 1]))
		c--;
	if (c >= 2 && buf[0] == '0' && buf[1] == 'x') {
		buf += 2;
		c -= 2;
	}

	switch (c) {
	case 0:
	case 2 * 8:
		if (strchr("235", buf[0]))
			break;
		else
			goto out;
	case 2 * 16:
		if (strchr("6", buf[0]))
			break;
		else
			goto out;
	default:
		goto out;
	}

	res = count;

	write_lock(&vdisk_serial_rwlock);
	if (hex2bin(virt_dev->naa_id, buf, c / 2) == 0)
		virt_dev->naa_id_len = c / 2;
	else
		res = -EINVAL;
	write_unlock(&vdisk_serial_rwlock);

	if (res >= 0)
		schedule_work(&virt_dev->vdev_inq_changed_work);

out:
	return res;
}

static ssize_t vdev_sysfs_naa_id_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int i, pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	if (virt_dev->naa_id_len)
		pos += sprintf(buf + pos, "0x");
	for (i = 0; i < virt_dev->naa_id_len; i++)
		pos += sprintf(buf + pos, "%02x", virt_dev->naa_id[i]);
	pos += sprintf(buf + pos, "\n%s", virt_dev->naa_id_len ?
		       SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

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

	schedule_work(&virt_dev->vdev_inq_changed_work);

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

static ssize_t vdev_sysfs_inq_vend_specific_store(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	char *p;
	int res = -EINVAL, len;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	p = memchr(buf, '\n', count);
	len = p ? p - buf : count;
	if (len > MAX_INQ_VEND_SPECIFIC_LEN)
		goto out;

	write_lock(&vdisk_serial_rwlock);
	memcpy(virt_dev->inq_vend_specific, buf, len);
	virt_dev->inq_vend_specific_len = len;
	write_unlock(&vdisk_serial_rwlock);

	schedule_work(&virt_dev->vdev_inq_changed_work);

	res = count;

out:
	return res;
}

static ssize_t vdev_sysfs_inq_vend_specific_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	int pos;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	read_lock(&vdisk_serial_rwlock);
	pos = snprintf(buf, PAGE_SIZE, "%.*s\n%s",
		       virt_dev->inq_vend_specific_len,
		       virt_dev->inq_vend_specific,
		       virt_dev->inq_vend_specific_len ?
		       SCST_SYSFS_KEY_MARK "\n" : "");
	read_unlock(&vdisk_serial_rwlock);

	return pos;
}

static ssize_t vdev_sysfs_active_show(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      char *buf)
{
	int pos;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = snprintf(buf, PAGE_SIZE, "%d\n%s",
		       virt_dev->dev_active,
		       virt_dev->dev_active != DEF_DEV_ACTIVE ?
			       SCST_SYSFS_KEY_MARK "\n" : "");

	return pos;
}

static int vdev_sysfs_process_active_store(
	struct scst_sysfs_work_item *work)
{
	struct scst_device *dev = work->dev;
	struct scst_vdisk_dev *virt_dev;
	long dev_active;
	int res;

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto resume;
	/*
	 * This is used to serialize against the *_on_alua_state_change_*()
	 * calls in scst_tg.c
	 */
	scst_alua_lock();

	/*
	 * This is safe since we hold a reference on dev_kobj and since
	 * scst_assign_dev_handler() waits until all dev_kobj references
	 * have been dropped before invoking .detach().
	 */
	virt_dev = dev->dh_priv;
	res = kstrtol(work->buf, 0, &dev_active);
	if (res)
		goto unlock;

	if (dev_active < 0 || dev_active > 1) {
		res = -EINVAL;
		goto unlock;
	}

	if (dev_active == virt_dev->dev_active)
		goto unlock;

	if (dev_active == 0) {
		vdisk_disable_dev(virt_dev);
	} else {
		res = vdisk_activate_dev(virt_dev, dev->dev_rd_only);
		if (res) {
			PRINT_ERROR("dev %s: Activating failed",
				    dev->virt_name);
			goto unlock;
		}
	}

unlock:
	scst_alua_unlock();
	mutex_unlock(&scst_mutex);

resume:
	scst_resume_activity();

out:
	kobject_put(&dev->dev_kobj);

	return res;
}

static ssize_t vdev_sysfs_active_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_device *dev = container_of(kobj, struct scst_device,
					       dev_kobj);
	struct scst_sysfs_work_item *work;
	char *arg;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	arg = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!arg)
		goto out;

	res = scst_alloc_sysfs_work(vdev_sysfs_process_active_store,
				    false, &work);
	if (res)
		goto out;
	work->dev = dev;
	swap(work->buf, arg);
	kobject_get(&dev->dev_kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(arg);
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_sysfs_bind_alua_state_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	int pos;
	unsigned int bind_alua_state;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	spin_lock(&virt_dev->flags_lock);
	bind_alua_state = virt_dev->bind_alua_state;
	spin_unlock(&virt_dev->flags_lock);
	pos = sprintf(buf, "%d\n%s", bind_alua_state,
		      bind_alua_state != DEF_BIND_ALUA_STATE ?
		      SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdev_sysfs_bind_alua_state_store(struct kobject *kobj,
						struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;
	char ch[16];
	unsigned long bind_alua_state;
	int res;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;
	strlcpy(ch, buf, 16);
	res = kstrtoul(ch, 0, &bind_alua_state);
	if (res < 0)
		goto out;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->bind_alua_state = !!bind_alua_state;
	spin_unlock(&virt_dev->flags_lock);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdev_async_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_device *dev =
		container_of(kobj, struct scst_device, dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;
	long val;
	int res;

	res = kstrtol(buf, 0, &val);
	if (res)
		return res;
	if (val != !!val)
		return -EINVAL;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->async = val;
	spin_unlock(&virt_dev->flags_lock);

	return count;
}

static ssize_t vdev_async_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev =
		container_of(kobj, struct scst_device, dev_kobj);
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	return sprintf(buf, "%d\n%s", virt_dev->async,
		      virt_dev->async ? SCST_SYSFS_KEY_MARK "\n" : "");
}

static ssize_t vdev_dif_filename_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = dev->dh_priv;

	pos = sprintf(buf, "%s\n%s", virt_dev->dif_filename,
		      (virt_dev->dif_filename != NULL) ? SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(pos);
	return pos;
}


static struct kobj_attribute vdev_active_attr =
	__ATTR(active, S_IWUSR|S_IRUGO, vdev_sysfs_active_show,
	       vdev_sysfs_active_store);
static struct kobj_attribute vdev_bind_alua_state_attr =
	__ATTR(bind_alua_state, S_IWUSR|S_IRUGO,
	       vdev_sysfs_bind_alua_state_show,
	       vdev_sysfs_bind_alua_state_store);
static struct kobj_attribute vdev_size_ro_attr =
	__ATTR(size, S_IRUGO, vdev_sysfs_size_show, NULL);
static struct kobj_attribute vdev_size_rw_attr =
	__ATTR(size, S_IWUSR|S_IRUGO, vdev_sysfs_size_show,
	       vdev_sysfs_size_store);
static struct kobj_attribute vdev_size_mb_ro_attr =
	__ATTR(size_mb, S_IRUGO, vdev_sysfs_size_mb_show, NULL);
static struct kobj_attribute vdev_size_mb_rw_attr =
	__ATTR(size_mb, S_IWUSR|S_IRUGO, vdev_sysfs_size_mb_show,
	       vdev_sysfs_size_mb_store);
static struct kobj_attribute vdisk_blocksize_attr =
	__ATTR(blocksize, S_IRUGO, vdisk_sysfs_blocksize_show, NULL);
static struct kobj_attribute vdisk_opt_trans_len_attr =
	__ATTR(opt_trans_len, S_IWUSR|S_IRUGO, vdisk_opt_trans_len_show,
	       vdisk_opt_trans_len_store);
static struct kobj_attribute vdisk_rd_only_attr =
	__ATTR(read_only, S_IRUGO, vdisk_sysfs_rd_only_show, NULL);
static struct kobj_attribute vdisk_wt_attr =
	__ATTR(write_through, S_IRUGO, vdisk_sysfs_wt_show, NULL);
static struct kobj_attribute vdisk_tp_attr =
	__ATTR(thin_provisioned, S_IRUGO, vdisk_sysfs_tp_show, NULL);
static struct kobj_attribute vdisk_tst_attr =
	__ATTR(tst, S_IRUGO, vdisk_sysfs_tst_show, NULL);
static struct kobj_attribute vdisk_rotational_attr =
	__ATTR(rotational, S_IRUGO, vdisk_sysfs_rotational_show, NULL);
static struct kobj_attribute vdisk_expl_alua_attr =
	__ATTR(expl_alua, S_IWUSR|S_IRUGO, vdisk_sysfs_expl_alua_show,
	       vdisk_sysfs_expl_alua_store);
static struct kobj_attribute vdisk_nv_cache_attr =
	__ATTR(nv_cache, S_IRUGO, vdisk_sysfs_nv_cache_show, NULL);
static struct kobj_attribute vdisk_o_direct_attr =
	__ATTR(o_direct, S_IRUGO, vdisk_sysfs_o_direct_show, NULL);
static struct kobj_attribute vdev_dummy_attr =
	__ATTR(dummy, S_IRUGO, vdev_sysfs_dummy_show, NULL);
static struct kobj_attribute vdev_read_zero_attr =
	__ATTR(read_zero, S_IWUSR|S_IRUGO, vdev_sysfs_rz_show,
	       vdev_sysfs_rz_store);
static struct kobj_attribute vdisk_removable_attr =
	__ATTR(removable, S_IRUGO, vdisk_sysfs_removable_show, NULL);
static struct kobj_attribute vdisk_filename_attr =
	__ATTR(filename, S_IWUSR|S_IRUGO, vdev_sysfs_filename_show,
	       vdev_sysfs_filename_store);
static struct kobj_attribute vdisk_cluster_mode_attr =
	__ATTR(cluster_mode, S_IWUSR|S_IRUGO, vdev_sysfs_cluster_mode_show,
	       vdev_sysfs_cluster_mode_store);
static struct kobj_attribute vdisk_resync_size_attr =
	__ATTR(resync_size, S_IWUSR, NULL, vdisk_sysfs_resync_size_store);
static struct kobj_attribute vdisk_sync_attr =
	__ATTR(sync, S_IWUSR, NULL, vdisk_sysfs_sync_store);
static struct kobj_attribute vdev_t10_vend_id_attr =
	__ATTR(t10_vend_id, S_IWUSR|S_IRUGO, vdev_sysfs_t10_vend_id_show,
	       vdev_sysfs_t10_vend_id_store);
static struct kobj_attribute vdev_vend_specific_id_attr =
	__ATTR(vend_specific_id, S_IWUSR|S_IRUGO,
	       vdev_sysfs_vend_specific_id_show,
	       vdev_sysfs_vend_specific_id_store);
static struct kobj_attribute vdev_prod_id_attr =
	__ATTR(prod_id, S_IWUSR|S_IRUGO, vdev_sysfs_prod_id_show,
	       vdev_sysfs_prod_id_store);
static struct kobj_attribute vdev_prod_rev_lvl_attr =
	__ATTR(prod_rev_lvl, S_IWUSR|S_IRUGO, vdev_sysfs_prod_rev_lvl_show,
	       vdev_sysfs_prod_rev_lvl_store);
static struct kobj_attribute vdev_scsi_device_name_attr =
	__ATTR(scsi_device_name, S_IWUSR|S_IRUGO, vdev_sysfs_scsi_device_name_show,
	       vdev_sysfs_scsi_device_name_store);
static struct kobj_attribute vdev_t10_dev_id_attr =
	__ATTR(t10_dev_id, S_IWUSR|S_IRUGO, vdev_sysfs_t10_dev_id_show,
		vdev_sysfs_t10_dev_id_store);
static struct kobj_attribute vdev_eui64_id_attr =
	__ATTR(eui64_id, S_IWUSR|S_IRUGO, vdev_sysfs_eui64_id_show,
	       vdev_sysfs_eui64_id_store);
static struct kobj_attribute vdev_naa_id_attr =
	__ATTR(naa_id, S_IWUSR|S_IRUGO, vdev_sysfs_naa_id_show,
	       vdev_sysfs_naa_id_store);
static struct kobj_attribute vdev_usn_attr =
	__ATTR(usn, S_IWUSR|S_IRUGO, vdev_sysfs_usn_show, vdev_sysfs_usn_store);
static struct kobj_attribute vdev_inq_vend_specific_attr =
	__ATTR(inq_vend_specific, S_IWUSR|S_IRUGO,
	       vdev_sysfs_inq_vend_specific_show,
	       vdev_sysfs_inq_vend_specific_store);
static struct kobj_attribute vdev_async_attr =
	__ATTR(async, S_IWUSR|S_IRUGO, vdev_async_show, vdev_async_store);

static struct kobj_attribute vcdrom_filename_attr =
	__ATTR(filename, S_IRUGO|S_IWUSR, vdev_sysfs_filename_show,
		vcdrom_sysfs_filename_store);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static struct scst_trace_log vdisk_local_trace_tbl[] = {
	{ TRACE_ORDER,		"order" },
	{ 0,			NULL }
};
#define trace_log_tbl			vdisk_local_trace_tbl

#define VDISK_TRACE_TBL_HELP	", order"

#endif

static const struct attribute *vdisk_fileio_attrs[] = {
	&vdev_size_ro_attr.attr,
	&vdev_size_mb_ro_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_opt_trans_len_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_wt_attr.attr,
	&vdisk_tp_attr.attr,
	&vdisk_tst_attr.attr,
	&vdisk_rotational_attr.attr,
	&vdisk_expl_alua_attr.attr,
	&vdisk_nv_cache_attr.attr,
	&vdisk_o_direct_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_filename_attr.attr,
	&vdisk_cluster_mode_attr.attr,
	&vdisk_resync_size_attr.attr,
	&vdisk_sync_attr.attr,
	&vdev_t10_vend_id_attr.attr,
	&vdev_vend_specific_id_attr.attr,
	&vdev_prod_id_attr.attr,
	&vdev_prod_rev_lvl_attr.attr,
	&vdev_scsi_device_name_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_naa_id_attr.attr,
	&vdev_eui64_id_attr.attr,
	&vdev_usn_attr.attr,
	&vdev_inq_vend_specific_attr.attr,
	&vdev_async_attr.attr,
	NULL,
};

static const char *const fileio_add_dev_params[] = {
	"async",
	"blocksize",
	"cluster_mode",
	"dif_filename",
	"dif_mode",
	"dif_static_app_tag",
	"dif_type",
	"filename",
	"numa_node_id",
	"nv_cache",
	"o_direct",
	"read_only",
	"removable",
	"rotational",
	"thin_provisioned",
	"tst",
	"write_through",
	NULL
};

/*
 * Be careful changing "name" field, since it is the name of the corresponding
 * /sys/kernel/scst_tgt entry, hence a part of user space ABI.
 */

static struct scst_dev_type vdisk_file_devtype = {
	.name =			"vdisk_fileio",
	.type =			TYPE_DISK,
	.threads_num =		-1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.auto_cm_assignment_possible = 1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		fileio_parse,
	.exec =			fileio_exec,
	.on_free_cmd =		fileio_on_free_cmd,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
#ifdef CONFIG_DEBUG_EXT_COPY_REMAP
	.ext_copy_remap =	vdev_ext_copy_remap,
#endif
	.get_supported_opcodes = vdisk_get_supported_opcodes,
	.devt_priv =		(void *)fileio_ops,
	.add_device =		vdisk_add_fileio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_fileio_attrs,
	.add_device_parameters = fileio_add_dev_params,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
};

static const struct attribute *vdisk_blockio_attrs[] = {
	&vdev_active_attr.attr,
	&vdev_bind_alua_state_attr.attr,
	&vdev_size_rw_attr.attr,
	&vdev_size_mb_rw_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_opt_trans_len_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_wt_attr.attr,
	&vdisk_expl_alua_attr.attr,
	&vdisk_nv_cache_attr.attr,
	&vdisk_tst_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_rotational_attr.attr,
	&vdisk_filename_attr.attr,
	&vdisk_cluster_mode_attr.attr,
	&vdisk_resync_size_attr.attr,
	&vdisk_sync_attr.attr,
	&vdev_t10_vend_id_attr.attr,
	&vdev_vend_specific_id_attr.attr,
	&vdev_prod_id_attr.attr,
	&vdev_prod_rev_lvl_attr.attr,
	&vdev_scsi_device_name_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_naa_id_attr.attr,
	&vdev_eui64_id_attr.attr,
	&vdev_usn_attr.attr,
	&vdev_inq_vend_specific_attr.attr,
	&vdisk_tp_attr.attr,
	NULL,
};

static const char *const blockio_add_dev_params[] = {
	"active",
	"bind_alua_state",
	"blocksize",
	"cluster_mode",
	"dif_filename",
	"dif_mode",
	"dif_static_app_tag",
	"dif_type",
	"filename",
	"numa_node_id",
	"nv_cache",
	"read_only",
	"removable",
	"rotational",
	"thin_provisioned",
	"tst",
	"write_through",
	NULL
};

static struct scst_dev_type vdisk_blk_devtype = {
	.name =			"vdisk_blockio",
	.type =			TYPE_DISK,
	.threads_num =		1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.auto_cm_assignment_possible = 1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		non_fileio_parse,
	.exec =			blockio_exec,
	.on_alua_state_change_start = blockio_on_alua_state_change_start,
	.on_alua_state_change_finish = blockio_on_alua_state_change_finish,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
	.get_supported_opcodes = vdisk_get_supported_opcodes,
	.devt_priv =		(void *)blockio_ops,
	.add_device =		vdisk_add_blockio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_blockio_attrs,
	.add_device_parameters = blockio_add_dev_params,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
};

static const struct attribute *vdisk_nullio_attrs[] = {
	&vdev_size_rw_attr.attr,
	&vdev_size_mb_rw_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_opt_trans_len_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_tst_attr.attr,
	&vdev_dummy_attr.attr,
	&vdev_read_zero_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_cluster_mode_attr.attr,
	&vdev_t10_vend_id_attr.attr,
	&vdev_vend_specific_id_attr.attr,
	&vdev_prod_id_attr.attr,
	&vdev_prod_rev_lvl_attr.attr,
	&vdev_scsi_device_name_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_naa_id_attr.attr,
	&vdev_eui64_id_attr.attr,
	&vdev_usn_attr.attr,
	&vdev_inq_vend_specific_attr.attr,
	&vdisk_rotational_attr.attr,
	NULL,
};

static const char *const nullio_add_dev_params[] = {
	"blocksize",
	"cluster_mode",
	"dif_mode",
	"dif_static_app_tag",
	"dif_type",
	"dummy",
	"numa_node_id",
	"read_only",
	"removable",
	"rotational",
	"size",
	"size_mb",
	"tst",
	NULL
};

static struct scst_dev_type vdisk_null_devtype = {
	.name =			"vdisk_nullio",
	.type =			TYPE_DISK,
	.threads_num =		1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.auto_cm_assignment_possible = 1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		non_fileio_parse,
	.exec =			nullio_exec,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
	.devt_priv =		(void *)nullio_ops,
	.get_supported_opcodes = vdisk_get_supported_opcodes,
	.add_device =		vdisk_add_nullio_device,
	.del_device =		vdisk_del_device,
	.dev_attrs =		vdisk_nullio_attrs,
	.add_device_parameters = nullio_add_dev_params,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
};

static const struct attribute *vcdrom_attrs[] = {
	&vdev_size_ro_attr.attr,
	&vdev_size_mb_ro_attr.attr,
	&vcdrom_filename_attr.attr,
	&vdisk_tst_attr.attr,
	&vdev_t10_vend_id_attr.attr,
	&vdev_vend_specific_id_attr.attr,
	&vdev_prod_id_attr.attr,
	&vdev_prod_rev_lvl_attr.attr,
	&vdev_scsi_device_name_attr.attr,
	&vdev_t10_dev_id_attr.attr,
	&vdev_naa_id_attr.attr,
	&vdev_eui64_id_attr.attr,
	&vdev_usn_attr.attr,
	&vdev_inq_vend_specific_attr.attr,
	NULL,
};

static const char *const cdrom_add_dev_params[] = {
	"tst",
	NULL,
};

static struct scst_dev_type vcdrom_devtype = {
	.name =			"vcdrom",
	.type =			TYPE_ROM,
	.threads_num =		-1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.auto_cm_assignment_possible = 1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		vcdrom_parse,
	.exec =			vcdrom_exec,
	.on_free_cmd =		fileio_on_free_cmd,
	.task_mgmt_fn_done =	vdisk_task_mgmt_fn_done,
	.get_supported_opcodes = vcdrom_get_supported_opcodes,
	.add_device =		vcdrom_add_device,
	.del_device =		vcdrom_del_device,
	.dev_attrs =		vcdrom_attrs,
	.add_device_parameters = cdrom_add_dev_params,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TBL_HELP,
#endif
};

static int __init init_scst_vdisk(struct scst_dev_type *devtype)
{
	int res = 0;

	TRACE_ENTRY();

	devtype->module = THIS_MODULE;

	res = scst_register_virtual_dev_driver(devtype);
	if (res < 0)
		goto out;


out:
	TRACE_EXIT_RES(res);
	return res;

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

static int __init vdev_check_mode_pages_path(void)
{
	int res;
	struct path path;

	TRACE_ENTRY();

	res = kern_path(VDEV_MODE_PAGES_DIR, 0, &path);
	if (res == 0)
		path_put(&path);
	if (res != 0) {
		PRINT_WARNING("Unable to find %s (err %d), saved mode pages "
			"disabled. You should create this directory manually "
			"or reinstall SCST", VDEV_MODE_PAGES_DIR, res);
		vdev_saved_mode_pages_enabled = false;
	}

	res = 0; /* always succeed */

	TRACE_EXIT_RES(res);
	return res;
}

#define SHARED_OPS							\
	[SYNCHRONIZE_CACHE] = vdisk_synchronize_cache,			\
	[SYNCHRONIZE_CACHE_16] = vdisk_synchronize_cache,		\
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
	[SERVICE_ACTION_IN_16] = vdisk_exec_sai_16,			\
	[UNMAP] = vdisk_exec_unmap,					\
	[WRITE_SAME] = vdisk_exec_write_same,				\
	[WRITE_SAME_16] = vdisk_exec_write_same,			\
	[MAINTENANCE_IN] = vdisk_exec_maintenance_in,			\
	[MAINTENANCE_OUT] = vdisk_exec_maintenance_out,			\
	[SEND_DIAGNOSTIC] = vdisk_exec_send_diagnostic,			\
	[FORMAT_UNIT] = vdisk_exec_format_unit,

static const vdisk_op_fn blockio_var_len_ops[] = {
	[SUBCODE_READ_32] = blockio_exec_read,
	[SUBCODE_WRITE_32] = blockio_exec_write,
	[SUBCODE_WRITE_VERIFY_32] = blockio_exec_write_verify,
	[SUBCODE_VERIFY_32] = vdev_exec_verify,
	[SUBCODE_WRITE_SAME_32] = vdisk_exec_write_same,
};

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
	[VARIABLE_LENGTH_CMD] = blockio_exec_var_len_cmd,
	[VERIFY] = vdev_exec_verify,
	[VERIFY_12] = vdev_exec_verify,
	[VERIFY_16] = vdev_exec_verify,
	SHARED_OPS
};

static const vdisk_op_fn fileio_var_len_ops[] = {
	[SUBCODE_READ_32] = fileio_exec_read,
	[SUBCODE_WRITE_32] = fileio_exec_write,
	[SUBCODE_WRITE_VERIFY_32] = fileio_exec_write_verify,
	[SUBCODE_VERIFY_32] = vdev_exec_verify,
	[SUBCODE_WRITE_SAME_32] = vdisk_exec_write_same,
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
	[VARIABLE_LENGTH_CMD] = fileio_exec_var_len_cmd,
	[VERIFY] = vdev_exec_verify,
	[VERIFY_12] = vdev_exec_verify,
	[VERIFY_16] = vdev_exec_verify,
	SHARED_OPS
};

static const vdisk_op_fn nullio_var_len_ops[] = {
	[SUBCODE_READ_32] = nullio_exec_read,
	[SUBCODE_WRITE_32] = nullio_exec_write,
	[SUBCODE_WRITE_VERIFY_32] = nullio_exec_write_verify,
	[SUBCODE_WRITE_SAME_32] = vdisk_exec_write_same,
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
	[VARIABLE_LENGTH_CMD] = nullio_exec_var_len_cmd,
	[VERIFY] = nullio_exec_verify,
	[VERIFY_12] = nullio_exec_verify,
	[VERIFY_16] = nullio_exec_verify,
	SHARED_OPS
};

static int __init init_scst_vdisk_driver(void)
{
	int res;

	spin_lock_init(&vdev_err_lock);

	init_ops(fileio_ops, ARRAY_SIZE(fileio_ops));
	init_ops(blockio_ops, ARRAY_SIZE(blockio_ops));
	init_ops(nullio_ops, ARRAY_SIZE(nullio_ops));

	res = vdev_check_mode_pages_path();
	if (res != 0)
		goto out;

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
MODULE_IMPORT_NS(SCST);
