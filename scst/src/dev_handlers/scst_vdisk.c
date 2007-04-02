/*
 *  scst_vdisk.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
 *            (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 *            (C) 2007 Ross Walker <rswwalker at hotmail dot com>
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

#include <asm/uaccess.h>  
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/uio.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/ctype.h>
#include <linux/writeback.h>
#include <linux/vmalloc.h>
#include <asm/atomic.h>
#include <linux/kthread.h>

#define LOG_PREFIX			"dev_vdisk"

#include "scsi_tgt.h"

#define TRACE_ORDER	0x80000000

static struct scst_proc_log vdisk_proc_local_trace_tbl[] =
{
    { TRACE_ORDER,		"order" },
    { 0,			NULL }
};
#define trace_log_tbl	vdisk_proc_local_trace_tbl

#include "scst_dev_handler.h"

#if defined(DEBUG) && defined(CONFIG_DEBUG_SLAB)
#define VDISK_SLAB_FLAGS ( SLAB_RED_ZONE | SLAB_POISON )
#else
#define VDISK_SLAB_FLAGS 0L
#endif

/* 8 byte ASCII Vendor */
#define SCST_FIO_VENDOR			"SCST_FIO"
#define SCST_BIO_VENDOR			"SCST_BIO"
/* 4 byte ASCII Product Revision Level - left aligned */
#define SCST_FIO_REV			" 096"

#define READ_CAP_LEN			8
#define READ_CAP16_LEN			12

#define MAX_USN_LEN			20

#define BYTCHK				0x02

#define INQ_BUF_SZ			128
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
#define	DEF_DISK_BLOCKSIZE		512
#define	DEF_DISK_BLOCKSIZE_SHIFT	9
#define	DEF_CDROM_BLOCKSIZE		2048
#define	DEF_CDROM_BLOCKSIZE_SHIFT	11
#define	DEF_SECTORS_PER			63
#define LEN_MEM				(32 * 1024)
#define VDISK_NAME			"vdisk"
#define VCDROM_NAME			"vcdrom"

#define VDISK_PROC_HELP			"help"

struct scst_vdisk_dev {
	uint32_t block_size;
	uint64_t nblocks;
	int block_shift;
	loff_t file_size;	/* in bytes */
	spinlock_t flags_lock;
	/*
	 * Below flags are protected by flags_lock or suspended activity
	 * with scst_vdisk_mutex.
	 */
	unsigned int rd_only_flag:1;
	unsigned int wt_flag:1;
	unsigned int nv_cache:1;
	unsigned int o_direct_flag:1;
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int blockio:1;
	unsigned int cdrom_empty:1;
	int virt_id;
	char name[16+1];	/* Name of virtual device,
				   must be <= SCSI Model + 1 */
	char *file_name;	/* File name */
	char *usn;
	struct scst_device *dev;
	struct list_head vdisk_dev_list_entry;
};

struct scst_vdisk_tgt_dev {
	enum scst_cmd_queue_type last_write_cmd_queue_type;
};

struct scst_vdisk_thr {
	struct scst_thr_data_hdr hdr;
	struct file *fd;
	struct block_device *bdev;
	struct iovec *iv;
	int iv_count;
	struct scst_vdisk_dev *virt_dev;
};

static struct kmem_cache *vdisk_thr_cachep;

static int vdisk_attach(struct scst_device *dev);
static void vdisk_detach(struct scst_device *dev);
static int vdisk_attach_tgt(struct scst_tgt_dev *tgt_dev);
static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev);
static int vdisk_parse(struct scst_cmd *, const struct scst_info_cdb *info_cdb);
static int vdisk_do_job(struct scst_cmd *cmd);
static int vcdrom_parse(struct scst_cmd *, const struct scst_info_cdb *info_cdb);
static int vcdrom_exec(struct scst_cmd *cmd);
static void vdisk_exec_read(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void vdisk_exec_write(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void blockio_exec_rw(struct scst_cmd *cmd, struct scst_vdisk_thr *thr,
	u64 lba_start, int write);
static void vdisk_exec_verify(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void vdisk_exec_read_capacity(struct scst_cmd *cmd);
static void vdisk_exec_read_capacity16(struct scst_cmd *cmd);
static void vdisk_exec_inquiry(struct scst_cmd *cmd);
static void vdisk_exec_mode_sense(struct scst_cmd *cmd);
static void vdisk_exec_mode_select(struct scst_cmd *cmd);
static void vdisk_exec_read_toc(struct scst_cmd *cmd);
static void vdisk_exec_prevent_allow_medium_removal(struct scst_cmd *cmd);
static int vdisk_fsync(struct scst_vdisk_thr *thr,
	loff_t loff, loff_t len, struct scst_cmd *cmd);
static int vdisk_read_proc(struct seq_file *seq, struct scst_dev_type *dev_type);
static int vdisk_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type);
static int vcdrom_read_proc(struct seq_file *seq, struct scst_dev_type *dev_type);
static int vcdrom_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type);

#define VDISK_TYPE {			\
  name:         VDISK_NAME,		\
  type:         TYPE_DISK,		\
  parse_atomic: 1,			\
  exec_atomic:  0,			\
  dev_done_atomic: 1,			\
  dedicated_thread: 1,			\
  attach:       vdisk_attach,		\
  detach:       vdisk_detach,		\
  attach_tgt:   vdisk_attach_tgt,	\
  detach_tgt:   vdisk_detach_tgt,	\
  parse:        vdisk_parse,		\
  exec:         vdisk_do_job,		\
  read_proc:    vdisk_read_proc,	\
  write_proc:   vdisk_write_proc,	\
}

#define VCDROM_TYPE {			\
  name:         VCDROM_NAME,		\
  type:         TYPE_ROM,		\
  parse_atomic: 1,			\
  exec_atomic:  0,			\
  dev_done_atomic: 1,			\
  dedicated_thread: 1,			\
  attach:       vdisk_attach,		\
  detach:       vdisk_detach,		\
  attach_tgt:   vdisk_attach_tgt,	\
  detach_tgt:   vdisk_detach_tgt,	\
  parse:        vcdrom_parse,		\
  exec:         vcdrom_exec,		\
  read_proc:    vcdrom_read_proc,	\
  write_proc:   vcdrom_write_proc,	\
}

static DECLARE_MUTEX(scst_vdisk_mutex);
static LIST_HEAD(vdisk_dev_list);
static LIST_HEAD(vcdrom_dev_list);

static struct scst_dev_type vdisk_devtype = VDISK_TYPE;
static struct scst_dev_type vcdrom_devtype = VCDROM_TYPE;

static char *vdisk_proc_help_string =
	"echo \"open|close NAME [FILE_NAME [BLOCK_SIZE] [WRITE_THROUGH "
	"READ_ONLY O_DIRECT NULLIO NV_CACHE BLOCKIO]]\" >/proc/scsi_tgt/" 
	VDISK_NAME "/" VDISK_NAME "\n";

static char *vcdrom_proc_help_string =
	"echo \"open|change|close NAME [FILE_NAME]\" "
	">/proc/scsi_tgt/" VCDROM_NAME "/" VCDROM_NAME "\n";

/**************************************************************
 *  Function:  vdisk_open
 *
 *  Argument:  
 *
 *  Returns :  fd, use IS_ERR(fd) to get error status
 *
 *  Description:  
 *************************************************************/
static struct file *vdisk_open(const struct scst_vdisk_dev *virt_dev)
{
	int open_flags = 0;
	struct file *fd;

	TRACE_ENTRY();

	if (virt_dev->rd_only_flag)
		open_flags |= O_RDONLY;
	else
		open_flags |= O_RDWR;
	if (virt_dev->o_direct_flag)
		open_flags |= O_DIRECT;
	if (virt_dev->wt_flag)
		open_flags |= O_SYNC;
	TRACE_DBG("Opening file %s, flags 0x%x", virt_dev->file_name, open_flags);
	fd = filp_open(virt_dev->file_name, O_LARGEFILE | open_flags, 0600);

	TRACE_EXIT();
	return fd;
}

/**************************************************************
 *  Function:  vdisk_attach
 *
 *  Argument:  
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:  
 *************************************************************/
static int vdisk_attach(struct scst_device *dev)
{
	int res = 0;
	loff_t err;
	struct file *fd;
	struct scst_vdisk_dev *virt_dev = NULL, *vv;
	struct list_head *vd;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d (%s)", dev->virt_id, dev->virt_name);

	if (dev->virt_id == 0) {
		PRINT_ERROR_PR("%s", "Not a virtual device");
		res = -EINVAL;
		goto out;
	}

	vd = (dev->handler->type == TYPE_DISK) ? 
				&vdisk_dev_list :
				&vcdrom_dev_list;

	/* 
	 * scst_vdisk_mutex must be already taken before 
	 * scst_register_virtual_device()
	 */
	list_for_each_entry(vv, vd, vdisk_dev_list_entry) {
		if (strcmp(vv->name, dev->virt_name) == 0) {
			virt_dev = vv;
			break;
		}
	}
	
	if (virt_dev == NULL) {
		PRINT_ERROR_PR("Device %s not found", dev->virt_name);
		res = -EINVAL;
		goto out;
	}

	virt_dev->dev = dev;

	if (dev->handler->type == TYPE_ROM)
		virt_dev->rd_only_flag = 1;

	if (!virt_dev->cdrom_empty) {
		if (virt_dev->nullio)
			err = 3LL*1024*1024*1024*1024/2;
		else {
			struct inode *inode;

			fd = vdisk_open(virt_dev);
			if (IS_ERR(fd)) {
				res = PTR_ERR(fd);
				PRINT_ERROR_PR("filp_open(%s) returned an error %d",
				       virt_dev->file_name, res);
				goto out;
			}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
			if ((fd->f_op == NULL) || (fd->f_op->readv == NULL) || 
			    (fd->f_op->writev == NULL))
#else
			if ((fd->f_op == NULL) || (fd->f_op->aio_read == NULL) || 
			    (fd->f_op->aio_write == NULL))
#endif
			{
				PRINT_ERROR_PR("%s", "Wrong f_op or FS doesn't have "
					"required capabilities");
					res = -EINVAL;
				filp_close(fd, NULL);
				goto out;
			}
		
			inode = fd->f_dentry->d_inode;

			if (virt_dev->blockio && !S_ISBLK(inode->i_mode)) {
				PRINT_ERROR_PR("File %s is NOT a block device",
					virt_dev->file_name);
				res = -EINVAL;
				filp_close(fd, NULL);
				goto out;
			}

			if (S_ISREG(inode->i_mode))
				;
			else if (S_ISBLK(inode->i_mode))
				inode = inode->i_bdev->bd_inode;
			else {
				res = -EINVAL;
				filp_close(fd, NULL);
				goto out;
 			}
			err = inode->i_size;
 
			filp_close(fd, NULL);
		}
		virt_dev->file_size = err;
		TRACE_DBG("size of file: %Ld", (uint64_t)err);
	} else
		virt_dev->file_size = 0;

	if (dev->handler->type == TYPE_DISK) {
		virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;
	} else {
		virt_dev->block_size = DEF_CDROM_BLOCKSIZE;
		virt_dev->block_shift = DEF_CDROM_BLOCKSIZE_SHIFT;
		virt_dev->nblocks = virt_dev->file_size >> DEF_CDROM_BLOCKSIZE_SHIFT;
	}

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO_PR("Attached SCSI target virtual %s %s "
		      "(file=\"%s\", fs=%LdMB, bs=%d, nblocks=%Ld, cyln=%Ld%s)",
		      (dev->handler->type == TYPE_DISK) ? "disk" : "cdrom",
		      virt_dev->name, virt_dev->file_name,
		      virt_dev->file_size >> 20, virt_dev->block_size,
		      virt_dev->nblocks, virt_dev->nblocks/64/32,
		      virt_dev->nblocks < 64*32 ? " !WARNING! cyln less than 1" : "");
	} else {
		PRINT_INFO_PR("Attached empty SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	dev->dh_priv = virt_dev;

out:
	TRACE_EXIT();
	return res;
}

/************************************************************
 *  Function:  vdisk_detach
 *
 *  Argument: 
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
static void vdisk_detach(struct scst_device *dev)
{
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)dev->dh_priv;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d", dev->virt_id);

	PRINT_INFO_PR("Detached SCSI target virtual device %s (\"%s\")",
		      virt_dev->name, virt_dev->file_name);

	/* virt_dev will be freed by the caller */
	dev->dh_priv = NULL;
	
	TRACE_EXIT();
	return;
}

static void vdisk_free_thr_data(struct scst_thr_data_hdr *d)
{
	struct scst_vdisk_thr *thr = container_of(d, struct scst_vdisk_thr,
						hdr);

	TRACE_ENTRY();

	if (thr->fd)
		filp_close(thr->fd, NULL);

	if (thr->iv != NULL)
		kfree(thr->iv);

	kmem_cache_free(vdisk_thr_cachep, thr);

	TRACE_EXIT();
	return;
}

static struct scst_vdisk_thr *vdisk_init_thr_data(
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_thr *res;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)tgt_dev->dev->dh_priv;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
	res = kmem_cache_alloc(vdisk_thr_cachep, GFP_KERNEL);
	if (res != NULL)
		memset(thr, 0, sizeof(*thr));
#else
	res = kmem_cache_zalloc(vdisk_thr_cachep, GFP_KERNEL);
#endif
	if (res == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Unable to allocate struct "
			"scst_vdisk_thr");
		goto out;
	}

	res->virt_dev = virt_dev;

	if (!virt_dev->cdrom_empty && !virt_dev->nullio) {
		res->fd = vdisk_open(virt_dev);
		if (IS_ERR(res->fd)) {
			PRINT_ERROR_PR("filp_open(%s) returned an error %ld",
				virt_dev->file_name, PTR_ERR(res->fd));
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
	struct scst_vdisk_tgt_dev *ftgt_dev;
	int res = 0;

	TRACE_ENTRY();

	ftgt_dev = kzalloc(sizeof(*ftgt_dev), GFP_KERNEL);
	if (ftgt_dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of per-session "
			"virtual device failed");
		res = -ENOMEM;
		goto out;
	}

	tgt_dev->dh_priv = ftgt_dev;
	
out:
	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_tgt_dev *ftgt_dev = 
		(struct scst_vdisk_tgt_dev *)tgt_dev->dh_priv;

	TRACE_ENTRY();

	scst_del_all_thr_data(tgt_dev);

	kfree(ftgt_dev);
	tgt_dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static inline int vdisk_sync_queue_type(enum scst_cmd_queue_type qt)
{
	switch(qt) {
		case SCST_CMD_QUEUE_ORDERED:
		case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
			return 1;
		default:
			return 0;
	}
}

static inline int vdisk_need_pre_sync(enum scst_cmd_queue_type cur,
	enum scst_cmd_queue_type last)
{
	if (vdisk_sync_queue_type(cur))
		if (!vdisk_sync_queue_type(last))
			return 1;
	return 0;
}

static int vdisk_do_job(struct scst_cmd *cmd)
{
	uint64_t lba_start = 0;
	loff_t data_len = 0;
	uint8_t *cdb = cmd->cdb;
	int opcode = cdb[0];
	loff_t loff;
	struct scst_device *dev = cmd->dev;
	struct scst_vdisk_dev *virt_dev =
		(struct scst_vdisk_dev *)dev->dh_priv;
	struct scst_thr_data_hdr *d;
	struct scst_vdisk_thr *thr = NULL;
	int fua = 0;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Flag ABORTED set for "
		      "cmd %p (tag %d), skipping", cmd, cmd->tag);
		goto done_uncompl;
	}

	d = scst_find_thr_data(cmd->tgt_dev);
	if (unlikely(d == NULL)) {
		thr = vdisk_init_thr_data(cmd->tgt_dev);
		if (thr == NULL) {
			scst_set_busy(cmd);
			goto done;
		}
		scst_thr_data_get(&thr->hdr);
	} else
		thr = container_of(d, struct scst_vdisk_thr, hdr);

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
	case READ_16:
	case WRITE_16:
	case WRITE_VERIFY_16:
	case VERIFY_16:
		lba_start |= ((u64)cdb[2]) << 56;
		lba_start |= ((u64)cdb[3]) << 48;
		lba_start |= ((u64)cdb[4]) << 40;
		lba_start |= ((u64)cdb[5]) << 32;
		lba_start |= ((u64)cdb[6]) << 16;
		lba_start |= ((u64)cdb[7]) << 8;
		lba_start |= ((u64)cdb[8]);
		data_len = cmd->bufflen;
		break;
	}

	loff = (loff_t)lba_start << virt_dev->block_shift;
	TRACE_DBG("cmd %p, lba_start %Ld, loff %Ld, data_len %Ld", cmd,
		lba_start, (uint64_t)loff, (uint64_t)data_len);
	if (unlikely(loff < 0) || unlikely(data_len < 0) ||
	    unlikely((loff + data_len) > virt_dev->file_size)) {
	    	PRINT_INFO_PR("Access beyond the end of the device "
			"(%lld of %lld, len %Ld)", (uint64_t)loff, 
			(uint64_t)virt_dev->file_size, (uint64_t)data_len);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
					scst_sense_block_out_range_error));
		goto done;
	}

	switch (opcode) {
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		fua = (cdb[1] & 0x8);
		if (cdb[1] & 0x8) {
			TRACE(TRACE_ORDER, "FUA(%d): loff=%Ld, "
				"data_len=%Ld", fua, (uint64_t)loff,
				(uint64_t)data_len);
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
			goto out;
		} else
			vdisk_exec_read(cmd, thr, loff);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		if (likely(!virt_dev->rd_only_flag)) {
			int do_fsync = vdisk_sync_queue_type(cmd->queue_type);
			struct scst_vdisk_tgt_dev *ftgt_dev =
				(struct scst_vdisk_tgt_dev*)
					cmd->tgt_dev->dh_priv;
			enum scst_cmd_queue_type last_queue_type =
				ftgt_dev->last_write_cmd_queue_type;
			ftgt_dev->last_write_cmd_queue_type = cmd->queue_type;
			if (vdisk_need_pre_sync(cmd->queue_type, last_queue_type)) {
			    	TRACE(TRACE_ORDER, "ORDERED "
			    		"WRITE(%d): loff=%Ld, data_len=%Ld",
			    		cmd->queue_type, (uint64_t)loff,
			    		(uint64_t)data_len);
			    	do_fsync = 1;
				if (vdisk_fsync(thr, 0, 0, cmd) != 0)
					goto done;
			}
			if (virt_dev->blockio) {
				blockio_exec_rw(cmd, thr, lba_start, 1);
				goto out;
			} else
				vdisk_exec_write(cmd, thr, loff);
			/* O_SYNC flag is used for WT devices */
			if (do_fsync || fua)
				vdisk_fsync(thr, loff, data_len, cmd);
		} else {
			TRACE(TRACE_MINOR, "Attempt to write to read-only "
				"device %s", virt_dev->name);
			scst_set_cmd_error(cmd,
		    		SCST_LOAD_SENSE(scst_sense_data_protect));
		}
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		if (likely(!virt_dev->rd_only_flag)) {
			int do_fsync = vdisk_sync_queue_type(cmd->queue_type);
			struct scst_vdisk_tgt_dev *ftgt_dev =
				(struct scst_vdisk_tgt_dev*)
					cmd->tgt_dev->dh_priv;
			enum scst_cmd_queue_type last_queue_type =
				ftgt_dev->last_write_cmd_queue_type;
			ftgt_dev->last_write_cmd_queue_type = cmd->queue_type;
			if (vdisk_need_pre_sync(cmd->queue_type, last_queue_type)) {
			    	TRACE(TRACE_ORDER, "ORDERED "
			    		"WRITE_VERIFY(%d): loff=%Ld, data_len=%Ld",
			    		cmd->queue_type, (uint64_t)loff,
			    		(uint64_t)data_len);
			    	do_fsync = 1;
				if (vdisk_fsync(thr, 0, 0, cmd) != 0)
					goto done;
			}
			/* ToDo: BLOCKIO VERIFY */
			vdisk_exec_write(cmd, thr, loff);
			/* O_SYNC flag is used for WT devices */
			if (cmd->status == 0)
				vdisk_exec_verify(cmd, thr, loff);
			else if (do_fsync)
				vdisk_fsync(thr, loff, data_len, cmd);
		} else {
			TRACE(TRACE_MINOR, "Attempt to write to read-only "
				"device %s", virt_dev->name);
			scst_set_cmd_error(cmd,
		    		SCST_LOAD_SENSE(scst_sense_data_protect));
		}
		break;
	case SYNCHRONIZE_CACHE:
	{
		int immed = cdb[1] & 0x2;
		TRACE(TRACE_ORDER, "SYNCHRONIZE_CACHE: "
			"loff=%Ld, data_len=%Ld, immed=%d", (uint64_t)loff,
			(uint64_t)data_len, immed);
		if (immed) {
			scst_get();
			cmd->completed = 1;
			cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
			/* cmd is dead here */
			vdisk_fsync(thr, loff, data_len, NULL);
			/* ToDo: vdisk_fsync() error processing */
			scst_put();
			goto out;
		} else {
			vdisk_fsync(thr, loff, data_len, cmd);
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
	case ALLOW_MEDIUM_REMOVAL:
		vdisk_exec_prevent_allow_medium_removal(cmd);
		break;
	case READ_TOC:
		vdisk_exec_read_toc(cmd);
		break;
	case START_STOP:
		vdisk_fsync(thr, 0, virt_dev->file_size, cmd);
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
	case READ_CAPACITY:
		vdisk_exec_read_capacity(cmd);
		break;
        case SERVICE_ACTION_IN:
		if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
			vdisk_exec_read_capacity16(cmd);
			break;
		}
		/* else go through */
	case REPORT_LUNS:
	default:
		TRACE_DBG("Invalid opcode %d", opcode);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	}

done:
	cmd->completed = 1;

done_uncompl:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);

out:
	if (likely(thr != NULL))
		scst_thr_data_put(&thr->hdr);

	TRACE_EXIT();
	return SCST_EXEC_COMPLETED;
}

/********************************************************************
 *  Function:  vdisk_parse
 *
 *  Argument:  
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int vdisk_parse(struct scst_cmd *cmd,
	const struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;
	int fixed;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;

	TRACE_ENTRY();
	
	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen
	 * based on info_cdb, therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      info_cdb->op_name,
	      info_cdb->direction, info_cdb->flags, info_cdb->transfer_len);

	fixed = info_cdb->flags & SCST_TRANSFER_LEN_TYPE_FIXED;
	switch (cmd->cdb[0]) {
	case READ_CAPACITY:
		cmd->bufflen = READ_CAP_LEN;
		cmd->data_direction = SCST_DATA_READ;
		break;
	case SERVICE_ACTION_IN:
		if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
			cmd->bufflen = READ_CAP16_LEN;
			cmd->data_direction = SCST_DATA_READ;
		}
		break;
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = 
			    info_cdb->transfer_len << virt_dev->block_shift;
			cmd->bufflen = 0;
			cmd->data_direction = SCST_DATA_NONE;
			fixed = 0;
		} else
			cmd->data_len = 0;
		break;
	default:
		/* It's all good */
		break;
	}

	if (fixed) {
		/* 
		 * No need for locks here, since *_detach() can not be
		 * called, when there are existing commands.
		 */
		cmd->bufflen = info_cdb->transfer_len << virt_dev->block_shift;
	}

	TRACE_DBG("res %d, bufflen %zd, data_len %zd, direct %d",
	      res, cmd->bufflen, cmd->data_len, cmd->data_direction);

	TRACE_EXIT();
	return res;
}

/********************************************************************
 *  Function:  vcdrom_parse
 *
 *  Argument:  
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int vcdrom_parse(struct scst_cmd *cmd,
	const struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;
	int fixed;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;

	TRACE_ENTRY();
	
	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen
	 * based on info_cdb, therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      info_cdb->op_name,
	      info_cdb->direction, info_cdb->flags, info_cdb->transfer_len);

	fixed = info_cdb->flags & SCST_TRANSFER_LEN_TYPE_FIXED;
	switch (cmd->cdb[0]) {
	case READ_CAPACITY:
		cmd->bufflen = READ_CAP_LEN;
		cmd->data_direction = SCST_DATA_READ;
		break;
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = 
			    info_cdb->transfer_len << virt_dev->block_shift;
			cmd->bufflen = 0;
			cmd->data_direction = SCST_DATA_NONE;
			fixed = 0;
		} else
			cmd->data_len = 0;
		break;
	default:
		/* It's all good */
		break;
	}

	if (fixed) {
		/* 
		 * No need for locks here, since *_detach() can not be
		 * called, when there are existing commands.
		 */
		cmd->bufflen = info_cdb->transfer_len << virt_dev->block_shift;
	}

	TRACE_DBG("res %d, bufflen %zd, data_len %zd, direct %d",
	      res, cmd->bufflen, cmd->data_len, cmd->data_direction);

	TRACE_EXIT_HRES(res);
	return res;
}

/********************************************************************
 *  Function:  vcdrom_exec
 *
 *  Argument:  
 *
 *  Returns :  
 *
 *  Description:  
 ********************************************************************/
static int vcdrom_exec(struct scst_cmd *cmd)
{
	int opcode = cmd->cdb[0];
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (virt_dev->cdrom_empty && (opcode != INQUIRY)) {
		TRACE_DBG("%s", "CDROM empty");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_not_ready));
		goto out_complete;
	}

	if (virt_dev->media_changed && (cmd->cdb[0] != INQUIRY) && 
	    (cmd->cdb[0] != REQUEST_SENSE) && (cmd->cdb[0] != REPORT_LUNS)) {
		spin_lock(&virt_dev->flags_lock);
		if (virt_dev->media_changed) {
			virt_dev->media_changed = 0;
			TRACE_DBG("%s", "Reporting media changed");
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_medium_changed_UA));
			spin_unlock(&virt_dev->flags_lock);
			goto out_complete;
		}
		spin_unlock(&virt_dev->flags_lock);
	}

	vdisk_do_job(cmd);

out:
	TRACE_EXIT();
	return SCST_EXEC_COMPLETED;

out_complete:
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;
}

static void vdisk_exec_inquiry(struct scst_cmd *cmd)
{
	int32_t length, len, i, resp_len = 0;
	uint8_t *address;
	uint8_t *buf;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;

	/* ToDo: Performance Boost:
	 * 1. remove kzalloc, buf
	 * 2. do all checks before touching *address
	 * 3. zero *address
	 * 4. write directly to *address
	 */

	TRACE_ENTRY();

	buf = kzalloc(INQ_BUF_SZ, 
		scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	length = scst_get_buf_first(cmd, &address);
	TRACE_DBG("length %d", length);
	if (unlikely(length <= 0)) {
		PRINT_ERROR_PR("scst_get_buf_first() failed: %d", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_free;
	}

	/* 
	 * ToDo: write through/back flags as well as read only one.
	 */

	if (cmd->cdb[1] & CMDDT) {
		TRACE_DBG("%s", "INQUIRY: CMDDT is unsupported");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	memset(buf, 0, sizeof(buf));
	buf[0] = cmd->dev->handler->type;      /* type dev */
	if (buf[0] == TYPE_ROM)
		buf[1] = 0x80;      /* removable */
	/* Vital Product */
	if (cmd->cdb[1] & EVPD) {
		int dev_id_num;
		char dev_id_str[6];
		
		for (dev_id_num = 0, i = 0; i < strlen(virt_dev->name); i++) {
			dev_id_num += virt_dev->name[i];
		}
		len = scnprintf(dev_id_str, 6, "%d", dev_id_num);
		TRACE_DBG("num %d, str <%s>, len %d",
			   dev_id_num, dev_id_str, len);
		if (0 == cmd->cdb[2]) { /* supported vital product data pages */
			buf[3] = 3;
			buf[4] = 0x0; /* this page */
			buf[5] = 0x80; /* unit serial number */
			buf[6] = 0x83; /* device identification */
			resp_len = buf[3] + 4;
		} else if (0x80 == cmd->cdb[2]) { /* unit serial number */
			buf[1] = 0x80;
			if (virt_dev->usn == NULL) {
				buf[3] = MAX_USN_LEN;
				memset(&buf[4], 0x20, MAX_USN_LEN);
			} else {
				int usn_len;

				if (strlen(virt_dev->usn) > MAX_USN_LEN)
					usn_len = MAX_USN_LEN;
				else
					usn_len = len;
				buf[3] = usn_len;
				strncpy(&buf[4], virt_dev->usn, usn_len);
			}
			resp_len = buf[3] + 4;
		} else if (0x83 == cmd->cdb[2]) { /* device identification */
			int num = 4;

			buf[1] = 0x83;
			/* Two identification descriptors: */
			/* T10 vendor identifier field format (faked) */
			buf[num + 0] = 0x2;	/* ASCII */
			buf[num + 1] = 0x1;
			buf[num + 2] = 0x0;
			if (virt_dev->blockio)
				memcpy(&buf[num + 4], SCST_BIO_VENDOR, 8);
			else
				memcpy(&buf[num + 4], SCST_FIO_VENDOR, 8);
			memset(&buf[num + 12], ' ', 16);
			i = strlen(virt_dev->name);
			i = i < 16 ? i : 16;
			memcpy(&buf[num + 12], virt_dev->name, len);
			memcpy(&buf[num + 28], dev_id_str, len);
			buf[num + 3] = 8 + 16 + len;
			num += buf[num + 3] + 4;
			/* NAA IEEE registered identifier (faked) */
			buf[num] = 0x1;	/* binary */
			buf[num + 1] = 0x3;
			buf[num + 2] = 0x0;
			buf[num + 3] = 0x8;
			buf[num + 4] = 0x51;	/* ieee company id=0x123456 (faked) */
			buf[num + 5] = 0x23;
			buf[num + 6] = 0x45;
			buf[num + 7] = 0x60;
			buf[num + 8] = (dev_id_num >> 24);
			buf[num + 9] = (dev_id_num >> 16) & 0xff;
			buf[num + 10] = (dev_id_num >> 8) & 0xff;
			buf[num + 11] = dev_id_num & 0xff;

			resp_len = num + 12 - 4;
			buf[2] = (resp_len >> 8) & 0xFF;
			buf[3] = resp_len & 0xFF;
			resp_len += 4;
		} else {
			TRACE_DBG("INQUIRY: Unsupported EVPD page %x",
				cmd->cdb[2]);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out_put;
		}
	} else {
		if (cmd->cdb[2] != 0) {
			TRACE_DBG("INQUIRY: Unsupported page %x", cmd->cdb[2]);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out_put;
		}

		buf[2] = 4;		/* Device complies to this standard - SPC-2  */
		buf[3] = 2;		/* data in format specified in this standard */
		buf[4] = 31;		/* n - 4 = 35 - 4 = 31 for full 36 byte data */
		buf[6] = 0; buf[7] = 2; /* BQue = 0, CMDQUE = 1 commands queuing supported */

		/* 8 byte ASCII Vendor Identification of the target - left aligned */
		if (virt_dev->blockio)
			memcpy(&buf[8], SCST_BIO_VENDOR, 8);
		else
			memcpy(&buf[8], SCST_FIO_VENDOR, 8);

		/* 16 byte ASCII Product Identification of the target - left aligned */
		memset(&buf[16], ' ', 16);
		len = strlen(virt_dev->name);
		len = len < 16 ? len : 16;
		memcpy(&buf[16], virt_dev->name, len);

		/* 4 byte ASCII Product Revision Level of the target - left aligned */
		memcpy(&buf[32], SCST_FIO_REV, 4);
		resp_len = buf[4] + 5;
	}

	sBUG_ON(resp_len >= INQ_BUF_SZ);
	if (length > resp_len)
		length = resp_len;
	memcpy(address, buf, length);

out_put:
	scst_put_buf(cmd, address);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_free:
	kfree(buf);

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
{ 	/* Disconnect-Reconnect page for mode_sense */
	const unsigned char disconnect_pg[] = {0x2, 0xe, 128, 128, 0, 10, 0, 0,
					       0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(p, disconnect_pg, sizeof(disconnect_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(disconnect_pg) - 2);
	return sizeof(disconnect_pg);
}

static int vdisk_format_pg(unsigned char *p, int pcontrol,
			    struct scst_vdisk_dev *virt_dev)
{       /* Format device page for mode_sense */
	const unsigned char format_pg[] = {0x3, 0x16, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0x40, 0, 0, 0};

        memcpy(p, format_pg, sizeof(format_pg));
        p[10] = (DEF_SECTORS_PER >> 8) & 0xff;
        p[11] = DEF_SECTORS_PER & 0xff;
        p[12] = (virt_dev->block_size >> 8) & 0xff;
        p[13] = virt_dev->block_size & 0xff;
        if (1 == pcontrol)
                memset(p + 2, 0, sizeof(format_pg) - 2);
        return sizeof(format_pg);
}

static int vdisk_caching_pg(unsigned char *p, int pcontrol,
			     struct scst_vdisk_dev *virt_dev)
{ 	/* Caching page for mode_sense */
	const unsigned char caching_pg[] = {0x8, 18, 0x10, 0, 0xff, 0xff, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0, 0, 0, 0, 0, 0};

	memcpy(p, caching_pg, sizeof(caching_pg));
	p[2] |= !(virt_dev->wt_flag) ? WCE : 0;
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(caching_pg) - 2);
	return sizeof(caching_pg);
}

static int vdisk_ctrl_m_pg(unsigned char *p, int pcontrol,
			    struct scst_vdisk_dev *virt_dev)
{ 	/* Control mode page for mode_sense */
	const unsigned char ctrl_m_pg[] = {0xa, 0xa, 0x20, 0, 0, 0x40, 0, 0,
					   0, 0, 0x2, 0x4b};

	memcpy(p, ctrl_m_pg, sizeof(ctrl_m_pg));
	if (!virt_dev->wt_flag && !virt_dev->nv_cache)
		p[3] |= 0x10; /* Enable unrestricted reordering */
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(ctrl_m_pg) - 2);
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

	buf = kzalloc(MSENSE_BUF_SZ,
		scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks;
	
	type = cmd->dev->handler->type;    /* type dev */
	dbd = cmd->cdb[1] & DBD;
	pcontrol = (cmd->cdb[2] & 0xc0) >> 6;
	pcode = cmd->cdb[2] & 0x3f;
	subpcode = cmd->cdb[3];
	msense_6 = (MODE_SENSE == cmd->cdb[0]);
	dev_spec = (virt_dev->rd_only_flag ? WP : 0) | DPOFUA;

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		PRINT_ERROR_PR("scst_get_buf_first() failed: %d", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_free;
	}

	memset(buf, 0, sizeof(buf));
	
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

	if (0 != subpcode) { /* TODO: Control Extension page */
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
			buf[offset + 0] = (nblocks >> (BYTE * 3)) & 0xFF;/* num blks */
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
		offset += len;
		break;
	case 0x2:	/* Disconnect-Reconnect page, all devices */
		len = vdisk_disconnect_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
        case 0x3:       /* Format device page, direct access */
                len = vdisk_format_pg(bp, pcontrol, virt_dev);
                offset += len;
                break;
	case 0x8:	/* Caching page, direct access */
		len = vdisk_caching_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
	case 0xa:	/* Control Mode page, all devices */
		len = vdisk_ctrl_m_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
	case 0x1c:	/* Informational Exceptions Mode page, all devices */
		len = vdisk_iec_m_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
	case 0x3f:	/* Read all Mode pages */
		len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
		len += vdisk_disconnect_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_format_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_caching_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_ctrl_m_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_iec_m_pg(bp + len, pcontrol, virt_dev);
		offset += len;
		break;
	default:
		TRACE_DBG("MODE SENSE: Unsupported page %x", pcode);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}
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
	scst_put_buf(cmd, address);
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

	if ((virt_dev->wt_flag == wt) || virt_dev->nullio)
		goto out;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->wt_flag = wt;
	spin_unlock(&virt_dev->flags_lock);

	scst_dev_del_all_thr_data(virt_dev->dev);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_exec_mode_select(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	int mselect_6, offset;

	TRACE_ENTRY();

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	mselect_6 = (MODE_SELECT == cmd->cdb[0]);

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		PRINT_ERROR_PR("scst_get_buf_first() failed: %d", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	if (!(cmd->cdb[1] & PF) || (cmd->cdb[1] & SP)) {
		PRINT_ERROR_PR("MODE SELECT: PF and/or SP are wrongly set "
			"(cdb[1]=%x)", cmd->cdb[1]);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	if (mselect_6) {
		offset = 4;
	} else {
		offset = 8;
	}

	if (address[offset - 1] == 8) {
		offset += 8;
	} else if (address[offset - 1] != 0) {
		PRINT_ERROR_PR("%s", "MODE SELECT: Wrong parameters list "
			"lenght");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out_put;
	}

	while (length > offset + 2) {
		if (address[offset] & PS) {
			PRINT_ERROR_PR("%s", "MODE SELECT: Illegal PS bit");
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
			    	scst_sense_invalid_field_in_parm_list));
			goto out_put;
		}
		if ((address[offset] & 0x3f) == 0x8) {	/* Caching page */
			if (address[offset + 1] != 18) {
				PRINT_ERROR_PR("%s", "MODE SELECT: Invalid "
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
		}
		offset += address[offset + 1];
	}

out_put:
	scst_put_buf(cmd, address);

out:
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
	uint8_t buffer[READ_CAP_LEN];

	TRACE_ENTRY();

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks;

	/* last block on the virt_dev is (nblocks-1) */
	memset(buffer, 0, sizeof(buffer));
	if (nblocks >> 32) {
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
	
	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		PRINT_ERROR_PR("scst_get_buf_first() failed: %d", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	if (length > READ_CAP_LEN)
		length = READ_CAP_LEN;
	memcpy(address, buffer, length);

	scst_put_buf(cmd, address);

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
	uint8_t buffer[READ_CAP16_LEN];

	TRACE_ENTRY();

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks - 1;

	memset(buffer, 0, sizeof(buffer));
	buffer[0] = nblocks >> 56;
	buffer[1] = (nblocks >> 48) & 0xFF;
	buffer[2] = (nblocks >> 40) & 0xFF;
	buffer[3] = (nblocks >> 32) & 0xFF;
	buffer[4] = (nblocks >> 24) & 0xFF;
	buffer[5] = (nblocks >> 16) & 0xFF;
	buffer[6] = (nblocks >> 8) & 0xFF;
	buffer[7] = nblocks& 0xFF;

	buffer[8] = (blocksize >> (BYTE * 3)) & 0xFF;
	buffer[9] = (blocksize >> (BYTE * 2)) & 0xFF;
	buffer[10] = (blocksize >> (BYTE * 1)) & 0xFF;
	buffer[11] = (blocksize >> (BYTE * 0)) & 0xFF;

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		PRINT_ERROR_PR("scst_get_buf_first() failed: %d", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	if (length > READ_CAP16_LEN)
		length = READ_CAP16_LEN;
	memcpy(address, buffer, length);

	scst_put_buf(cmd, address);

	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

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

	if (cmd->dev->handler->type != TYPE_ROM) {
		PRINT_ERROR_PR("%s", "READ TOC for non-CDROM device");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out;
	}

	if (cmd->cdb[2] & 0x0e/*Format*/) {
		PRINT_ERROR_PR("%s", "READ TOC: invalid requested data format");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	if ((cmd->cdb[6] != 0 && (cmd->cdb[2] & 0x01)) ||
	    (cmd->cdb[6] > 1 && cmd->cdb[6] != 0xAA)) {
		PRINT_ERROR_PR("READ TOC: invalid requested track number %x",
			cmd->cdb[6]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		PRINT_ERROR_PR("scst_get_buf_first() failed: %d", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	/* FIXME when you have > 8TB ROM device. */
	nblocks = (uint32_t)virt_dev->nblocks;

	/* Header */
	memset(buffer, 0, sizeof(buffer));
	buffer[2] = 0x01;    /* First Track/Session */
	buffer[3] = 0x01;    /* Last Track/Session */
	off = 4;
	if (cmd->cdb[6] <= 1)
        {
		/* Fistr TOC Track Descriptor */
		buffer[off+1] = 0x14; /* ADDR    0x10 - Q Sub-channel encodes current position data
					 CONTROL 0x04 - Data track, recoreded uninterrupted */
		buffer[off+2] = 0x01; /* Track Number */
		off += 8;
        }
	if (!(cmd->cdb[2] & 0x01))
        {
		/* Lead-out area TOC Track Descriptor */
		buffer[off+1] = 0x14;
		buffer[off+2] = 0xAA;     /* Track Number */
		buffer[off+4] = (nblocks >> (BYTE * 3)) & 0xFF; /* Track Start Address */
		buffer[off+5] = (nblocks >> (BYTE * 2)) & 0xFF;
		buffer[off+6] = (nblocks >> (BYTE * 1)) & 0xFF;
		buffer[off+7] = (nblocks >> (BYTE * 0)) & 0xFF;
		off += 8;
        }

	buffer[1] = off - 2;    /* Data  Length */

	if (off > length)
		off = length;
	memcpy(address, buffer, off);

	scst_put_buf(cmd, address);

	if (off < cmd->resp_data_len)
                scst_set_resp_data_len(cmd, off);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_prevent_allow_medium_removal(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev =
		(struct scst_vdisk_dev *)cmd->dev->dh_priv;

	TRACE_DBG("PERSIST/PREVENT 0x%02x", cmd->cdb[4]);

	spin_lock(&virt_dev->flags_lock);
	if (cmd->dev->handler->type == TYPE_ROM)
		virt_dev->prevent_allow_medium_removal = 
			cmd->cdb[4] & 0x01 ? 1 : 0;
	else {
		PRINT_ERROR_PR("%s", "Prevent allow medium removal for "
			"non-CDROM device");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	}
	spin_unlock(&virt_dev->flags_lock);

	return;
}

static int vdisk_fsync(struct scst_vdisk_thr *thr,
	loff_t loff, loff_t len, struct scst_cmd *cmd)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev = thr->virt_dev;
	struct file *file = thr->fd;
	struct inode *inode = file->f_dentry->d_inode;
	struct address_space *mapping = file->f_mapping;

	TRACE_ENTRY();

	/* Hopefully, the compiler will generate the single comparison */
	if (virt_dev->nv_cache || virt_dev->blockio || virt_dev->wt_flag ||
	    virt_dev->rd_only_flag || virt_dev->o_direct_flag ||
	    virt_dev->nullio)
		goto out;

	res = sync_page_range(inode, mapping, loff, len);
	if (unlikely(res != 0)) {
		PRINT_ERROR_PR("sync_page_range() failed (%d)", res);
		if (cmd != NULL) {
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		}
	}

	/* ToDo: flush the device cache, if needed */

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct iovec *vdisk_alloc_iv(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr)
{
	int iv_count;
	
	iv_count = scst_get_buf_count(cmd);
	if (iv_count > thr->iv_count) {
		if (thr->iv != NULL)
			kfree(thr->iv);
		thr->iv = kmalloc(sizeof(*thr->iv) * iv_count, GFP_KERNEL);
		if (thr->iv == NULL) {
			PRINT_ERROR_PR("Unable to allocate iv (%d)", iv_count);
			scst_set_busy(cmd);
			goto out;
		}
		thr->iv_count = iv_count;
	}

out:
	return thr->iv;
}

/*
 * copied from <ksrc>/fs/read_write.*
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
static void wait_on_retry_sync_kiocb(struct kiocb *iocb)
{
	set_current_state(TASK_UNINTERRUPTIBLE);
	if (!kiocbIsKicked(iocb))
		schedule();
	else
		kiocbClearKicked(iocb);
	__set_current_state(TASK_RUNNING);
}

typedef ssize_t (*iov_fn_t)(struct kiocb *, const struct iovec *,
				unsigned long, loff_t);

ssize_t do_sync_readv_writev(struct file *filp, const struct iovec *iov,
		unsigned long nr_segs, size_t len, loff_t *ppos, iov_fn_t fn)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	kiocb.ki_left = len;
	kiocb.ki_nbytes = len;

	for (;;) {
		ret = fn(&kiocb, iov, nr_segs, kiocb.ki_pos);
		if (ret != -EIOCBRETRY)
			break;
		wait_on_retry_sync_kiocb(&kiocb);
	}

	if (ret == -EIOCBQUEUED)
		ret = wait_on_sync_kiocb(&kiocb);
	*ppos = kiocb.ki_pos;
	return ret;
}
#endif

static void vdisk_exec_read(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	struct iovec *iv;
	int iv_count, i;

	TRACE_ENTRY();
	
	iv = vdisk_alloc_iv(cmd, thr);
	if (iv == NULL)
		goto out;
	
	iv_count = 0;
	full_len = 0;
	i = -1;
	length = scst_get_buf_first(cmd, &address);
	while (length > 0) {
		full_len += length;
		i++;
		iv_count++;
		iv[i].iov_base = address;
		iv[i].iov_len = length;
		length = scst_get_buf_next(cmd, &address);
	}
	if (unlikely(length < 0)) {
		PRINT_ERROR_PR("scst_get_buf_() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_put;
	}

	old_fs = get_fs();
	set_fs(get_ds());

	TRACE_DBG("reading(iv_count %d, full_len %zd)", iv_count, full_len);
	if (virt_dev->nullio)
		err = full_len;
	else {
		/* SEEK */	
		if (fd->f_op->llseek) {
			err = fd->f_op->llseek(fd, loff, 0/*SEEK_SET*/);
		} else {
			err = default_llseek(fd, loff, 0/*SEEK_SET*/);
		}
		if (err != loff) {
			PRINT_ERROR_PR("lseek trouble %Ld != %Ld", (uint64_t)err, 
				(uint64_t)loff);
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}
		/* READ */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		err = fd->f_op->readv(fd, iv, iv_count, &fd->f_pos);
#else
		err = do_sync_readv_writev(fd, iv, iv_count, full_len, &fd->f_pos, fd->f_op->aio_read);
#endif
	}

	if ((err < 0) || (err < full_len)) {
		PRINT_ERROR_PR("readv() returned %Ld from %zd", (uint64_t)err, 
			full_len);
		if (err == -EAGAIN)
			scst_set_busy(cmd);
		else {
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_read_error));
		}
		goto out_set_fs;
	}

out_set_fs:
	set_fs(old_fs);
	
out_put:	
	for(; i >= 0; i--)
		scst_put_buf(cmd, iv[i].iov_base);
	
out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_write(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	struct iovec *iv, *eiv;
	int iv_count, eiv_count;

	TRACE_ENTRY();

	iv = vdisk_alloc_iv(cmd, thr);
	if (iv == NULL)
		goto out;
	
	iv_count = 0;
	full_len = 0;
	length = scst_get_buf_first(cmd, &address);
	while (length > 0) {
		full_len += length;
		iv[iv_count].iov_base = address;
		iv[iv_count].iov_len = length;
		iv_count++;
		length = scst_get_buf_next(cmd, &address);
	}
	if (unlikely(length < 0)) {
		PRINT_ERROR_PR("scst_get_buf_() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_put;
	}

	old_fs = get_fs();
	set_fs(get_ds());

	eiv = iv;
	eiv_count = iv_count;
restart:
	TRACE_DBG("writing(eiv_count %d, full_len %zd)", eiv_count, full_len);

	if (virt_dev->nullio)
		err = full_len;
	else {
		/* SEEK */
		if (fd->f_op->llseek) {
			err = fd->f_op->llseek(fd, loff, 0 /*SEEK_SET */ );
		} else {
			err = default_llseek(fd, loff, 0 /*SEEK_SET */ );
		}
		if (err != loff) {
			PRINT_ERROR_PR("lseek trouble %Ld != %Ld", (uint64_t)err, 
				(uint64_t)loff);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}

		/* WRITE */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		err = fd->f_op->writev(fd, eiv, eiv_count, &fd->f_pos);
#else
		err = do_sync_readv_writev(fd, iv, iv_count, full_len, &fd->f_pos, 
									fd->f_op->aio_write);
#endif
	}

	if (err < 0) {
		PRINT_ERROR_PR("write() returned %Ld from %zd", 
			(uint64_t)err, full_len);
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
		int i, e = eiv_count;
		TRACE_MGMT_DBG("write() returned %d from %zd "
			"(iv_count=%d)", (int)err, full_len,
			eiv_count);
		if (err == 0) {
			PRINT_INFO_PR("Suspicious: write() returned 0 from "
				"%zd (iv_count=%d)", full_len, eiv_count);
		}
		full_len -= err;
		for(i = 0; i < e; i++) {
			if (eiv->iov_len < err) {
				err -= eiv->iov_len;
				eiv++;
				eiv_count--;
			} else {
				eiv->iov_base = 
					(uint8_t*)eiv->iov_base + err;
				eiv->iov_len -= err;
				break;
			}
		}
		goto restart;
	}

out_set_fs:
	set_fs(old_fs);

out_put:	
	while (iv_count > 0) {
		scst_put_buf(cmd, iv[iv_count-1].iov_base);
		iv_count--;
	}

out:
	TRACE_EXIT();
	return;
}

struct blockio_work {
	atomic_t bios_inflight;
	struct scst_cmd *cmd;
};

static int blockio_endio(struct bio *bio, unsigned int bytes_done, int error)
{
	struct blockio_work *blockio_work = bio->bi_private;

	if (bio->bi_size)
		return 1;

	error = test_bit(BIO_UPTODATE, &bio->bi_flags) ? error : -EIO;

	if (unlikely(error != 0)) {
		PRINT_ERROR_PR("cmd %p returned error %d", blockio_work->cmd,
			error);
		/* 
		 * The race with other such bio's doesn't matter, since all
		 * scst_set_cmd_error() calls do the same local to this cmd
		 * operations.
		 */
		if (bio->bi_rw & WRITE)
			scst_set_cmd_error(blockio_work->cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		else
			scst_set_cmd_error(blockio_work->cmd,
				SCST_LOAD_SENSE(scst_sense_read_error));
	}

	/* Decrement the bios in processing, and if zero signal completion */
	if (atomic_dec_and_test(&blockio_work->bios_inflight)) {
		blockio_work->cmd->completed = 1;
		blockio_work->cmd->scst_cmd_done(blockio_work->cmd,
			SCST_CMD_STATE_DEFAULT);
		kfree(blockio_work);
	}

	bio_put(bio);
	return 0;
}

static void blockio_exec_rw(struct scst_cmd *cmd, struct scst_vdisk_thr *thr,
	u64 lba_start, int write)
{
	struct scst_vdisk_dev *virt_dev = thr->virt_dev;
	struct block_device *bdev = thr->bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	int j, max_nr_vecs = 0;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	int need_new_bio;
	struct scatterlist *sgl = cmd->sg;
	struct blockio_work *blockio_work;
	int bios = 0;

	TRACE_ENTRY();

	if (virt_dev->nullio)
		goto out;

	/* Allocate and initialize blockio_work struct */
	blockio_work = kmalloc(sizeof (*blockio_work), GFP_KERNEL);
	if (blockio_work == NULL)
		goto out_no_mem;
	
	blockio_work->cmd = cmd;

	if (q)
		max_nr_vecs = min(bio_get_nr_vecs(bdev), BIO_MAX_PAGES);
	else
		max_nr_vecs = 1;

	need_new_bio = 1;
	for (j = 0; j < cmd->sg_cnt; ++j) {
		unsigned int len, bytes, off, thislen;
		struct page *page;

		page = sgl[j].page;
		off = sgl[j].offset;
		len = sgl[j].length;
		thislen = 0;

		while (len > 0) {
			if (need_new_bio) {
				bio = bio_alloc(GFP_KERNEL, max_nr_vecs);
				if (!bio) {
					PRINT_ERROR_PR("Failed to create bio "
						       "for data segment= %d "
						       "cmd %p", j, cmd);
					goto out_no_bio;
				}

				bios++;
				need_new_bio = 0;
				bio->bi_end_io = blockio_endio;
				bio->bi_sector = lba_start << 
					(virt_dev->block_shift - 9);
				bio->bi_bdev = bdev;
				bio->bi_private = blockio_work;
#if 0 /* It could be win, but could be not, so a performance study is needed */
				bio->bi_rw |= 1 << BIO_RW_SYNC;
#endif
		 		if (!hbio)
				 	hbio = tbio = bio;
				 else
		 			tbio = tbio->bi_next = bio;
			}

			bytes = min_t(unsigned int, len, PAGE_SIZE - off);

			if (bio_add_page(bio, page, bytes, off) < bytes) {
				need_new_bio = 1;
				lba_start += thislen >> virt_dev->block_shift;
				thislen = 0;
				continue;
			}

			page++;
			thislen += bytes;
			len -= bytes;
			off = 0;
		}

		lba_start += sgl[j].length >> virt_dev->block_shift;
	}
	atomic_set(&blockio_work->bios_inflight, bios);

	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		submit_bio(write, bio);
	}

	if (q && q->unplug_fn)
		q->unplug_fn(q);

out:
	TRACE_EXIT();
	return;

out_no_bio:
	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio_put(bio);
	}
	kfree(blockio_work);

out_no_mem:
	scst_set_busy(cmd);
	goto out;
}

static void vdisk_exec_verify(struct scst_cmd *cmd, 
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, len_mem = 0;
	uint8_t *address_sav, *address;
	int compare;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	uint8_t *mem_verify = NULL;

	TRACE_ENTRY();

	if (vdisk_fsync(thr, loff, cmd->bufflen, cmd) != 0)
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
		if (fd->f_op->llseek) {
			err = fd->f_op->llseek(fd, loff, 0/*SEEK_SET*/);
		} else {
			err = default_llseek(fd, loff, 0/*SEEK_SET*/);
		}
		if (err != loff) {
			PRINT_ERROR_PR("lseek trouble %Ld != %Ld", (uint64_t)err, 
				(uint64_t)loff);
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}
	}

	mem_verify = vmalloc(LEN_MEM);
	if (mem_verify == NULL) {
		PRINT_ERROR_PR("Unable to allocate memory %d for verify",
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
		len_mem = length > LEN_MEM ? LEN_MEM : length;
		TRACE_DBG("Verify: length %zd - len_mem %zd", length, len_mem);

		if (!virt_dev->nullio)
			err = fd->f_op->read(fd, (char*)mem_verify, len_mem, &fd->f_pos);
		else
			err = len_mem;
		if ((err < 0) || (err < len_mem)) {
			PRINT_ERROR_PR("verify() returned %Ld from %zd",
				(uint64_t)err, len_mem);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			scst_put_buf(cmd, address_sav);
			goto out_set_fs;
		}
		if (compare && memcmp(address, mem_verify, len_mem) != 0)
		{
			TRACE_DBG("Verify: error memcmp length %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_miscompare_error));
			scst_put_buf(cmd, address_sav);
			goto out_set_fs;
		}
		length -= len_mem;
		address += len_mem;
		if (compare && length <= 0)
		{
			scst_put_buf(cmd, address_sav);
			length = scst_get_buf_next(cmd, &address);
			address_sav = address;
		}
	}

	if (length < 0) {
		PRINT_ERROR_PR("scst_get_buf_() failed: %zd", length);
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

static inline struct scst_vdisk_dev *vdisk_alloc_dev(void)
{
	struct scst_vdisk_dev *dev;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of virtual "
			"device failed");
		goto out;
	}
	spin_lock_init(&dev->flags_lock);
out:
	return dev;
}

/* 
 * Called when a file in the /proc/VDISK_NAME/VDISK_NAME is read
 */
static int vdisk_read_proc(struct seq_file *seq, struct scst_dev_type *dev_type)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();
	
	if (down_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}
	
	seq_printf(seq, "%-17s %-11s %-11s %-15s %s\n",
			   "Name", "Size(MB)", "Block size", "Options", "File name");

	list_for_each_entry(virt_dev, &vdisk_dev_list, vdisk_dev_list_entry) {
		int c;
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
		if (virt_dev->rd_only_flag) {
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
		while (c < 16) {
			seq_printf(seq, " ");
			c++;
		}
		seq_printf(seq, "%s\n", virt_dev->file_name);
	}
	up(&scst_vdisk_mutex);
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
	char *p, *name, *file_name;
	struct scst_vdisk_dev *virt_dev, *vv;
	uint32_t block_size = DEF_DISK_BLOCKSIZE;
	int block_shift = DEF_DISK_BLOCKSIZE_SHIFT;
	size_t len;

	TRACE_ENTRY();
	
	/* VERY UGLY code. You can rewrite it if you want */

	if (buffer[0] == '\0')
		goto out;
	
	if (down_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	p = buffer;
	if (p[strlen(p) - 1] == '\n') {
		p[strlen(p) - 1] = '\0';
	}
	if (!strncmp("close ", p, 6)) {
		p += 6;
		action = 0;
	} else if (!strncmp("open ", p, 5)) {
		p += 5;
		action = 2;
	} else {
		PRINT_ERROR_PR("Unknown action \"%s\"", p);
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
		PRINT_ERROR_PR("%s", "Name required");
		res = -EINVAL;
		goto out_up;
	} else if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR_PR("Name is too long (max %zd "
			"characters)", sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_up;
	}

	if (action) {                      /* open */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdisk_dev_list,
					vdisk_dev_list_entry)
		{
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev) {
			PRINT_ERROR_PR("Virtual device with name "
				   "%s already exist", name);
			res = -EINVAL;
			goto out_up;
		}

		while (isspace(*p) && *p != '\0')
			p++;
		file_name = p;
		while (!isspace(*p) && *p != '\0')
			p++;
		*p++ = '\0';
		if (*file_name == '\0') {
			PRINT_ERROR_PR("%s", "File name required");
			res = -EINVAL;
			goto out_up;
		}

		virt_dev = vdisk_alloc_dev();
		if (virt_dev == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
				  "Allocation of virt_dev failed");
			res = -ENOMEM;
			goto out_up;
		}

		while (isspace(*p) && *p != '\0')
			p++;

		if (isdigit(*p)) {
			char *pp;
			uint32_t t;
			block_size = simple_strtoul(p, &pp, 0);
			p = pp;
			if ((*p != '\0') && !isspace(*p)) {
				PRINT_ERROR_PR("Parse error: \"%s\"", p);
				res = -EINVAL;
				goto out_free_vdev;
			}
			while (isspace(*p) && *p != '\0')
				p++;

			t = block_size;
			block_shift = 0;
			while(1) {
				if ((t & 1) != 0)
					break;
				t >>= 1;
				block_shift++;
			}
			if (block_shift < 9) {
				PRINT_ERROR_PR("Wrong block size %d",
					block_size);
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
				virt_dev->rd_only_flag = 1;
				TRACE_DBG("%s", "READ_ONLY");
			} else if (!strncmp("O_DIRECT", p, 8)) {
				p += 8;
		#if 0
				
				virt_dev->o_direct_flag = 1;
				TRACE_DBG("%s", "O_DIRECT");
		#else
				PRINT_INFO_PR("%s flag doesn't currently"
					" work, ignoring it", "O_DIRECT");
		#endif
			} else if (!strncmp("NULLIO", p, 6)) {
				p += 6;
				virt_dev->nullio = 1;
				TRACE_DBG("%s", "NULLIO");
			} else if (!strncmp("BLOCKIO", p, 7)) {
				p += 7;
				virt_dev->blockio = 1;
				TRACE_DBG("%s", "BLOCKIO");
			} else {
				PRINT_ERROR_PR("Unknown flag \"%s\"", p);
				res = -EINVAL;
				goto out_free_vdev;
			}
			while (isspace(*p) && *p != '\0')
				p++;
		}

		if (!virt_dev->nullio && (*file_name != '/')) {
			PRINT_ERROR_PR("File path \"%s\" is not "
				"absolute", file_name);
			res = -EINVAL;
			goto out_up;
		}

		strcpy(virt_dev->name, name);

		len = strlen(file_name) + 1;
		virt_dev->file_name = kmalloc(len, GFP_KERNEL);
		if (virt_dev->file_name == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
				  "Allocation of file_name failed");
			res = -ENOMEM;
			goto out_free_vdev;
		}
		strncpy(virt_dev->file_name, file_name, len);

		list_add_tail(&virt_dev->vdisk_dev_list_entry,
				  &vdisk_dev_list);

		virt_dev->virt_id =
			scst_register_virtual_device(&vdisk_devtype,
						 virt_dev->name);
		if (virt_dev->virt_id < 0) {
			res = virt_dev->virt_id;
			goto out_free_vpath;
		}
		TRACE_DBG("Added virt_dev (name %s, file name %s, "
			"id %d, block size %d) to "
			"vdisk_dev_list", virt_dev->name,
			virt_dev->file_name, virt_dev->virt_id,
			virt_dev->block_size);
	} else {                           /* close */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdisk_dev_list,
					vdisk_dev_list_entry)
		{
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev == NULL) {
			PRINT_ERROR_PR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}
		scst_unregister_virtual_device(virt_dev->virt_id);
		PRINT_INFO_PR("Virtual device %s unregistered", 
			virt_dev->name);
		TRACE_DBG("virt_id %d unregister", virt_dev->virt_id);

		list_del(&virt_dev->vdisk_dev_list_entry);

		kfree(virt_dev->file_name);
		kfree(virt_dev);
	}
	res = length;

out_up:
	up(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_vpath:
	list_del(&virt_dev->vdisk_dev_list_entry);
	kfree(virt_dev->file_name);

out_free_vdev:
	kfree(virt_dev);
	goto out_up;
}

/* scst_vdisk_mutex supposed to be held */
static int vcdrom_open(char *p, char *name)
{
	struct scst_vdisk_dev *virt_dev, *vv;
	char *file_name;
	int len;
	int res = 0;
	int cdrom_empty;

	virt_dev = NULL;
	list_for_each_entry(vv, &vcdrom_dev_list, vdisk_dev_list_entry)
	{
		if (strcmp(vv->name, name) == 0) {
			virt_dev = vv;
			break;
		}
	}
	if (virt_dev) {
		PRINT_ERROR_PR("Virtual device with name "
		       "%s already exist", name);
		res = -EINVAL;
		goto out;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	file_name = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*file_name == '\0') {
		cdrom_empty = 1;
		TRACE_DBG("%s", "No media");
	} else if (*file_name != '/') {
		PRINT_ERROR_PR("File path \"%s\" is not "
			"absolute", file_name);
		res = -EINVAL;
		goto out;
	} else
		cdrom_empty = 0;

	virt_dev = vdisk_alloc_dev();
	if (virt_dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of virt_dev failed");
		res = -ENOMEM;
		goto out;
	}
	virt_dev->cdrom_empty = cdrom_empty;

	strcpy(virt_dev->name, name);

	if (!virt_dev->cdrom_empty) {
		len = strlen(file_name) + 1;
		virt_dev->file_name = kmalloc(len, GFP_KERNEL);
		if (virt_dev->file_name == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
			      "Allocation of file_name failed");
			res = -ENOMEM;
			goto out_free_vdev;
		}
		strncpy(virt_dev->file_name, file_name, len);
	}

	list_add_tail(&virt_dev->vdisk_dev_list_entry,
		      &vcdrom_dev_list);

	virt_dev->virt_id =
	    scst_register_virtual_device(&vcdrom_devtype,
					 virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_free_vpath;
	}
	TRACE_DBG("Added virt_dev (name %s file_name %s id %d) "
		  "to vcdrom_dev_list", virt_dev->name,
		  virt_dev->file_name, virt_dev->virt_id);

out:
	return res;

out_free_vpath:
	list_del(&virt_dev->vdisk_dev_list_entry);
	kfree(virt_dev->file_name);

out_free_vdev:
	kfree(virt_dev);
	goto out;
}

/* scst_vdisk_mutex supposed to be held */
static int vcdrom_close(char *name)
{
	struct scst_vdisk_dev *virt_dev, *vv;
	int res = 0;

	virt_dev = NULL;
	list_for_each_entry(vv, &vcdrom_dev_list,
			    vdisk_dev_list_entry)
	{
		if (strcmp(vv->name, name) == 0) {
			virt_dev = vv;
			break;
		}
	}
	if (virt_dev == NULL) {
		PRINT_ERROR_PR("Virtual device with name "
		       "%s not found", name);
		res = -EINVAL;
		goto out;
	}
	scst_unregister_virtual_device(virt_dev->virt_id);
	PRINT_INFO_PR("Virtual device %s unregistered", 
		virt_dev->name);
	TRACE_DBG("virt_id %d unregister", virt_dev->virt_id);

	list_del(&virt_dev->vdisk_dev_list_entry);

	if (virt_dev->file_name)
		kfree(virt_dev->file_name);
	kfree(virt_dev);

out:
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static int vcdrom_change(char *p, char *name)
{
	struct file *fd;
	loff_t err;
	mm_segment_t old_fs;
	struct scst_vdisk_dev *virt_dev, *vv;
	char *file_name, *fn, *old_fn;
	int len;
	int res = 0;

	virt_dev = NULL;
	list_for_each_entry(vv, &vcdrom_dev_list,
			    vdisk_dev_list_entry)
	{
		if (strcmp(vv->name, name) == 0) {
			virt_dev = vv;
			break;
		}
	}
	if (virt_dev == NULL) {
		PRINT_ERROR_PR("Virtual device with name "
		       "%s not found", name);
		res = -EINVAL;
		goto out;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	file_name = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*file_name == '\0') {
		virt_dev->cdrom_empty = 1;
		TRACE_DBG("%s", "No media");
	} else if (*file_name != '/') {
		PRINT_ERROR_PR("File path \"%s\" is not "
			"absolute", file_name);
		res = -EINVAL;
		goto out;
	} else
		virt_dev->cdrom_empty = 0;

	old_fn = virt_dev->file_name;

	if (!virt_dev->cdrom_empty && !virt_dev->nullio) {
		len = strlen(file_name) + 1;
		fn = kmalloc(len, GFP_KERNEL);
		if (fn == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
				"Allocation of file_name failed");
			res = -ENOMEM;
			goto out;
		}

		strncpy(fn, file_name, len);
		virt_dev->file_name = fn;

		fd = vdisk_open(virt_dev);
		if (IS_ERR(fd)) {
			res = PTR_ERR(fd);
			PRINT_ERROR_PR("filp_open(%s) returned an error %d",
				       virt_dev->file_name, res);
			goto out_free;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		if ((fd->f_op == NULL) || (fd->f_op->readv == NULL)) {
#else
		if ((fd->f_op == NULL) || (fd->f_op->aio_read == NULL)) {
#endif
			PRINT_ERROR_PR("%s", "Wrong f_op or FS doesn't "
				"have required capabilities");
			res = -EINVAL;
			filp_close(fd, NULL);
			goto out_free;
		}
		/* seek to end */
		old_fs = get_fs();
		set_fs(get_ds());
		if (fd->f_op->llseek) {
			err = fd->f_op->llseek(fd, 0, 2/*SEEK_END*/);
		} else {
			err = default_llseek(fd, 0, 2/*SEEK_END*/);
		}
		set_fs(old_fs);
		filp_close(fd, NULL);
		if (err < 0) {
			res = err;
			PRINT_ERROR_PR("llseek %s returned an error %d",
				       virt_dev->file_name, res);
			goto out_free;
		}
	} else {
		len = 0;
		err = 0;
		fn = NULL;
		virt_dev->file_name = fn;
	}

	scst_suspend_activity();

	if (virt_dev->prevent_allow_medium_removal) {
		PRINT_ERROR_PR("Prevent medium removal for "
			"virtual device with name %s", name);
		res = -EINVAL;
		goto out_free_resume;
	}

	virt_dev->file_size = err;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;
	if (!virt_dev->cdrom_empty)
		virt_dev->media_changed = 1;

	scst_dev_del_all_thr_data(virt_dev->dev);

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO_PR("Changed SCSI target virtual cdrom %s "
			"(file=\"%s\", fs=%LdMB, bs=%d, nblocks=%Ld, cyln=%Ld%s)",
			virt_dev->name, virt_dev->file_name,
			virt_dev->file_size >> 20, virt_dev->block_size,
			virt_dev->nblocks, virt_dev->nblocks/64/32,
			virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
							"than 1" : "");
	} else {
		PRINT_INFO_PR("Removed media from SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	if (old_fn)
		kfree(old_fn);

out_resume:
	scst_resume_activity();

out:
	return res;

out_free:
	virt_dev->file_name = old_fn;
	kfree(fn);
	goto out;

out_free_resume:
	virt_dev->file_name = old_fn;
	kfree(fn);
	goto out_resume;
}

/* 
 * Called when a file in the /proc/VCDROM_NAME/VCDROM_NAME is read
 */
static int vcdrom_read_proc(struct seq_file *seq, struct scst_dev_type *dev_type)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if (down_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}
	
	seq_printf(seq, "%-17s %-9s %s\n", "Name", "Size(MB)", "File name");

	list_for_each_entry(virt_dev, &vcdrom_dev_list, 
		vdisk_dev_list_entry) {
		seq_printf(seq, "%-17s %-9d %s\n", virt_dev->name,
			(uint32_t)(virt_dev->file_size >> 20),
			virt_dev->file_name);
	}

	up(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* 
 * Called when a file in the /proc/VCDROM_NAME/VCDROM_NAME is written 
 */
static int vcdrom_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type)
{
	int res = 0, action;
	char *p, *name;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if (down_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}
	
	p = buffer;
	if (p[strlen(p) - 1] == '\n') {
		p[strlen(p) - 1] = '\0';
	}
	if (!strncmp("close ", p, 6)) {
		p += 6;
		action = 0;
	} else if (!strncmp("change ", p, 5)) {
		p += 7;
		action = 1;
	} else if (!strncmp("open ", p, 5)) {
		p += 5;
		action = 2;
	} else {
		PRINT_ERROR_PR("Unknown action \"%s\"", p);
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
		PRINT_ERROR_PR("%s", "Name required");
		res = -EINVAL;
		goto out_up;
	} else if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR_PR("Name is too long (max %zd "
			"characters)", sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_up;
	}

	if (action == 2) {                      /* open */
		res = vcdrom_open(p, name);
		if (res != 0)
			goto out_up;
	} else if (action == 1) {          /* change */
		res = vcdrom_change(p, name);
		if (res != 0)
			goto out_up;
	} else {                           /* close */
		res = vcdrom_close(name);
		if (res != 0)
			goto out_up;
	}
	res = length;

out_up:
	up(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_help_info_show(struct seq_file *seq, void *v)
{
	char *s = (char*)seq->private;

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
	p = scst_create_proc_entry(root, VDISK_PROC_HELP, &vdisk_help_proc_data);
	if (p == NULL) {
		PRINT_ERROR_PR("Not enough memory to register dev "
		     "handler %s entry %s in /proc",
		      dev_type->name, VDISK_PROC_HELP);
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

static int __init init_scst_vdisk(struct scst_dev_type *devtype)
{
	int res = 0;

	TRACE_ENTRY();

	devtype->module = THIS_MODULE;

	res = scst_register_virtual_dev_driver(devtype);
	if (res < 0)
		goto out;

	res = scst_dev_handler_build_std_proc(devtype);
	if (res < 0)
		goto out_unreg;

	res = vdisk_proc_help_build(devtype);
	if (res < 0) {
		goto out_destroy_proc;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_destroy_proc:
	scst_dev_handler_destroy_std_proc(devtype);

out_unreg:
	scst_unregister_virtual_dev_driver(devtype);
	goto out;
}

static void __exit exit_scst_vdisk(struct scst_dev_type *devtype,
	struct list_head *vdisk_dev_list)
{
	TRACE_ENTRY();

	down(&scst_vdisk_mutex);
	while (1) {
		struct scst_vdisk_dev *virt_dev;

		if (list_empty(vdisk_dev_list))
			break;
		
		virt_dev = list_entry(vdisk_dev_list->next, typeof(*virt_dev),
				vdisk_dev_list_entry);

		scst_unregister_virtual_device(virt_dev->virt_id);

		list_del(&virt_dev->vdisk_dev_list_entry);

		PRINT_INFO_PR("Virtual device %s unregistered", virt_dev->name);
		TRACE_DBG("virt_id %d", virt_dev->virt_id);
		kfree(virt_dev->file_name);
		kfree(virt_dev);
	}
	up(&scst_vdisk_mutex);

	vdisk_proc_help_destroy(devtype);
	scst_dev_handler_destroy_std_proc(devtype);

	scst_unregister_virtual_dev_driver(devtype);

	TRACE_EXIT();
	return;
}

static int __init init_scst_vdisk_driver(void)
{
	int res;

	vdisk_thr_cachep = kmem_cache_create("vdisk_thr_data",
		sizeof(struct scst_vdisk_thr), 0, VDISK_SLAB_FLAGS, NULL,
		NULL);
	if (vdisk_thr_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = init_scst_vdisk(&vdisk_devtype);
	if (res != 0)
		goto out_free_slab;

	res = init_scst_vdisk(&vcdrom_devtype);
	if (res != 0)
		goto out_err;

out:
	return res;

out_err:
	exit_scst_vdisk(&vdisk_devtype, &vdisk_dev_list);

out_free_slab:
	kmem_cache_destroy(vdisk_thr_cachep);
	goto out;
}

static void __exit exit_scst_vdisk_driver(void)
{
	exit_scst_vdisk(&vdisk_devtype, &vdisk_dev_list);
	exit_scst_vdisk(&vcdrom_devtype, &vcdrom_dev_list);
	kmem_cache_destroy(vdisk_thr_cachep);
}

module_init(init_scst_vdisk_driver);
module_exit(exit_scst_vdisk_driver);

MODULE_LICENSE("GPL");
