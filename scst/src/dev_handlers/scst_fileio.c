/*
 *  scst_fileio.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
 *
 *  SCSI disk (type 0) and CDROM (type 5) dev handler using files 
 *  on file systems (FILEIO)
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
#include <asm/atomic.h>

#define LOG_PREFIX			"dev_fileio"
#include "scst_debug.h"
#include "scsi_tgt.h"
#include "scst_dev_handler.h"

#include "scst_debug.c"

/* 8 byte ASCII Vendor of the FILE IO target */
#define SCST_FIO_VENDOR			"SCST_FIO"
/* 4 byte ASCII Product Revision Level of the FILE IO target - left aligned */
#define SCST_FIO_REV			" 095"

#define READ_CAP_LEN			8
#define READ_CAP16_LEN			32

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
#define DISK_FILEIO_NAME		"disk_fileio"
#define CDROM_FILEIO_NAME		"cdrom_fileio"

#define FILEIO_PROC_HELP		"help"

#if defined(DEBUG) || defined(TRACING)
unsigned long trace_flag = SCST_DEFAULT_DEV_LOG_FLAGS;
#endif

struct scst_fileio_dev {
	uint32_t block_size;
	uint64_t nblocks;
	int block_shift;
	loff_t file_size;	/* in bytes */
	unsigned int rd_only_flag:1;
	unsigned int wt_flag:1;
	unsigned int nv_cache:1;
	unsigned int o_direct_flag:1;
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int cdrom_empty:1;
	int virt_id;
	char name[16+1];	/* Name of virtual device,
				   must be <= SCSI Model + 1 */
	char *file_name;	/* File name */
	struct list_head fileio_dev_list_entry;
	struct list_head ftgt_list;
	struct semaphore ftgt_list_mutex;
};

struct scst_fileio_tgt_dev {
	spinlock_t fdev_lock;
	enum scst_cmd_queue_type last_write_cmd_queue_type;
	int shutdown;
	struct file *fd;
	struct iovec *iv;
	int iv_count;
	struct list_head fdev_cmd_list;
	wait_queue_head_t fdev_waitQ;
	struct scst_fileio_dev *virt_dev;
	atomic_t threads_count;
	struct semaphore shutdown_mutex;
	struct list_head ftgt_list_entry;
};

static int fileio_attach(struct scst_device *dev);
static void fileio_detach(struct scst_device *dev);
static int fileio_attach_tgt(struct scst_tgt_dev *tgt_dev);
static void fileio_detach_tgt(struct scst_tgt_dev *tgt_dev);
static int disk_fileio_parse(struct scst_cmd *, const struct scst_info_cdb *info_cdb);
static int disk_fileio_exec(struct scst_cmd *cmd);
static int cdrom_fileio_parse(struct scst_cmd *, const struct scst_info_cdb *info_cdb);
static int cdrom_fileio_exec(struct scst_cmd *cmd);
static void fileio_exec_read(struct scst_cmd *cmd, loff_t loff);
static void fileio_exec_write(struct scst_cmd *cmd, loff_t loff);
static void fileio_exec_verify(struct scst_cmd *cmd, loff_t loff);
static int fileio_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev);
static void fileio_exec_read_capacity(struct scst_cmd *cmd);
static void fileio_exec_read_capacity16(struct scst_cmd *cmd);
static void fileio_exec_inquiry(struct scst_cmd *cmd);
static void fileio_exec_mode_sense(struct scst_cmd *cmd);
static void fileio_exec_mode_select(struct scst_cmd *cmd);
static void fileio_exec_read_toc(struct scst_cmd *cmd);
static void fileio_exec_prevent_allow_medium_removal(struct scst_cmd *cmd);
static int fileio_fsync(struct scst_fileio_tgt_dev *ftgt_dev,
	loff_t loff, loff_t len, struct scst_cmd *cmd);
static int disk_fileio_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type, int inout);
static int cdrom_fileio_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type, int inout);
static int fileio_proc_help_read(char *buffer, char **start,off_t offset,
	int length, int *eof, void *data);

#define DISK_TYPE_FILEIO {		\
  name:         DISK_FILEIO_NAME,	\
  type:         TYPE_DISK,		\
  parse_atomic: 1,			\
  exec_atomic:  1,			\
  dev_done_atomic: 1,			\
  attach:       fileio_attach,		\
  detach:       fileio_detach,		\
  attach_tgt:   fileio_attach_tgt,	\
  detach_tgt:   fileio_detach_tgt,	\
  parse:        disk_fileio_parse,	\
  exec:         disk_fileio_exec,	\
  task_mgmt_fn: fileio_task_mgmt_fn,	\
  proc_info:    disk_fileio_proc,	\
}

#define CDROM_TYPE_FILEIO {		\
  name:         CDROM_FILEIO_NAME,	\
  type:         TYPE_ROM,		\
  parse_atomic: 1,			\
  exec_atomic:  1,			\
  dev_done_atomic: 1,			\
  attach:       fileio_attach,		\
  detach:       fileio_detach,		\
  attach_tgt:   fileio_attach_tgt,	\
  detach_tgt:   fileio_detach_tgt,	\
  parse:        cdrom_fileio_parse,	\
  exec:         cdrom_fileio_exec,	\
  task_mgmt_fn: fileio_task_mgmt_fn,	\
  proc_info:    cdrom_fileio_proc,	\
}

DECLARE_MUTEX(scst_fileio_mutex);
static LIST_HEAD(disk_fileio_dev_list);
static LIST_HEAD(cdrom_fileio_dev_list);

static struct scst_dev_type disk_devtype_fileio = DISK_TYPE_FILEIO;
static struct scst_dev_type cdrom_devtype_fileio = CDROM_TYPE_FILEIO;

static char *disk_fileio_proc_help_string =
	"echo \"open|close NAME [FILE_NAME [BLOCK_SIZE] [WRITE_THROUGH "
	"READ_ONLY O_DIRECT NULLIO NV_CACHE]]\" >/proc/scsi_tgt/" 
	DISK_FILEIO_NAME "/" DISK_FILEIO_NAME "\n";

static char *cdrom_fileio_proc_help_string =
	"echo \"open|change|close NAME [FILE_NAME]\" "
	">/proc/scsi_tgt/" CDROM_FILEIO_NAME "/" CDROM_FILEIO_NAME "\n";

#define FILEIO_THREAD_FLAGS                    CLONE_KERNEL

/**************************************************************
 *  Function:  fileio_open
 *
 *  Argument:  
 *
 *  Returns :  fd, use IS_ERR(fd) to get error status
 *
 *  Description:  
 *************************************************************/
static struct file *fileio_open(const struct scst_fileio_dev *virt_dev)
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
 *  Function:  fileio_attach
 *
 *  Argument:  
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:  
 *************************************************************/
static int fileio_attach(struct scst_device *dev)
{
	int res = 0;
	loff_t err;
	mm_segment_t old_fs;
	struct file *fd;
	struct scst_fileio_dev *virt_dev = NULL, *vv;
	struct list_head *fileio_dev_list;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d (%s)", dev->virt_id, dev->virt_name);

	if (dev->virt_id == 0) {
		PRINT_ERROR_PR("%s", "Not a virtual device");
		res = -EINVAL;
		goto out;
	}

	fileio_dev_list = (dev->handler->type == TYPE_DISK) ? 
				&disk_fileio_dev_list :
				&cdrom_fileio_dev_list;

	/* 
	 * scst_fileio_mutex must be already taken before 
	 * scst_register_virtual_device()
	 */
	list_for_each_entry(vv, fileio_dev_list, fileio_dev_list_entry)
	{
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
	
	if (dev->handler->type == TYPE_ROM)
		virt_dev->rd_only_flag = 1;

	if (!virt_dev->cdrom_empty) {
		fd = fileio_open(virt_dev);
		if (IS_ERR(fd)) {
			res = PTR_ERR(fd);
			PRINT_ERROR_PR("filp_open(%s) returned an error %d",
				       virt_dev->file_name, res);
			goto out;
		}

		if ((fd->f_op == NULL) || (fd->f_op->readv == NULL) || 
		    (fd->f_op->writev == NULL))
		{
			PRINT_ERROR_PR("%s", "Wrong f_op or FS doesn't have "
				"required capabilities");
				res = -EINVAL;
			goto out_close_file;
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
		if (err < 0) {
			res = err;
			PRINT_ERROR_PR("llseek %s returned an error %d",
				       virt_dev->file_name, res);
			goto out_close_file;
		}
		virt_dev->file_size = err;
		TRACE_DBG("size of file: %Ld", (uint64_t)err);

		filp_close(fd, NULL);
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

out_close_file:
	filp_close(fd, NULL);
	goto out;
}

/************************************************************
 *  Function:  fileio_detach
 *
 *  Argument: 
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
static void fileio_detach(struct scst_device *dev)
{
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)dev->dh_priv;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d", dev->virt_id);

	PRINT_INFO_PR("Detached SCSI target virtual device %s (\"%s\")",
		      virt_dev->name, virt_dev->file_name);

	/* virt_dev will be freed by the caller */
	dev->dh_priv = NULL;
	
	TRACE_EXIT();
	return;
}

static inline int fileio_sync_queue_type(enum scst_cmd_queue_type qt)
{
	switch(qt) {
		case SCST_CMD_QUEUE_ORDERED:
		case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
			return 1;
		default:
			return 0;
	}
}

static inline int fileio_need_pre_sync(enum scst_cmd_queue_type cwqt,
	enum scst_cmd_queue_type lwqt)
{
	if (fileio_sync_queue_type(cwqt))
		if (!fileio_sync_queue_type(lwqt))
			return 1;
	return 0;
}

static void fileio_do_job(struct scst_cmd *cmd)
{
	uint64_t lba_start;
	loff_t data_len;
	int opcode = cmd->cdb[0];
	loff_t loff;
	struct scst_device *dev = cmd->dev;
	struct scst_fileio_dev *virt_dev =
		(struct scst_fileio_dev *)dev->dh_priv;
	int fua = 0;

	TRACE_ENTRY();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Flag ABORTED set for "
		      "cmd %p (tag %d), skipping", cmd, cmd->tag);
		goto done_uncompl;
	}
	

	switch (opcode) {
	case READ_6:
	case WRITE_6:
	case VERIFY_6:
		lba_start = (((cmd->cdb[1] & 0x1f) << (BYTE * 2)) +
			     (cmd->cdb[2] << (BYTE * 1)) +
			     (cmd->cdb[3] << (BYTE * 0)));
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
		lba_start = be32_to_cpu(*(u32 *)&cmd->cdb[2]);
		data_len = cmd->bufflen;
		break;
	case SYNCHRONIZE_CACHE:
		lba_start = be32_to_cpu(*(u32 *)&cmd->cdb[2]);
		data_len = ((cmd->cdb[7] << (BYTE * 1)) +
			(cmd->cdb[8] << (BYTE * 0))) << virt_dev->block_shift;
		if (data_len == 0)
			data_len = virt_dev->file_size - 
				((loff_t)lba_start << virt_dev->block_shift);
		break;
	case READ_16:
	case WRITE_16:
	case WRITE_VERIFY_16:
	case VERIFY_16:
		lba_start = be64_to_cpu(*(u64*)&cmd->cdb[2]);
		data_len = cmd->bufflen;
		break;
	default:
		lba_start = 0;
		data_len = 0;
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
		fua = (cmd->cdb[1] & 0x8) && !virt_dev->wt_flag;
		if (cmd->cdb[1] & 0x8) {
			TRACE(TRACE_SCSI, "FUA(%d): loff=%Ld, "
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
		fileio_exec_read(cmd, loff);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		if (likely(!virt_dev->rd_only_flag)) {
			int do_fsync = 0;
			struct scst_fileio_tgt_dev *ftgt_dev =
				(struct scst_fileio_tgt_dev*)
					cmd->tgt_dev->dh_priv;
			enum scst_cmd_queue_type last_queue_type =
				ftgt_dev->last_write_cmd_queue_type;
			ftgt_dev->last_write_cmd_queue_type = cmd->queue_type;
			if (fileio_need_pre_sync(cmd->queue_type, last_queue_type) &&
			    !virt_dev->wt_flag) {
			    	TRACE(TRACE_SCSI/*|TRACE_SPECIAL*/, "ORDERED "
			    		"WRITE(%d): loff=%Ld, data_len=%Ld",
			    		cmd->queue_type, (uint64_t)loff,
			    		(uint64_t)data_len);
			    	do_fsync = 1;
				if (fileio_fsync(ftgt_dev, 0, 0, cmd) != 0)
					goto done;
			}
			fileio_exec_write(cmd, loff);
			/* O_SYNC flag is used for wt_flag devices */
			if (do_fsync || fua)
				fileio_fsync(ftgt_dev, loff, data_len, cmd);
		} else {
			TRACE_DBG("%s", "Attempt to write to read-only device");
			scst_set_cmd_error(cmd,
		    		SCST_LOAD_SENSE(scst_sense_data_protect));
		}
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		if (likely(!virt_dev->rd_only_flag)) {
			int do_fsync = 0;
			struct scst_fileio_tgt_dev *ftgt_dev =
				(struct scst_fileio_tgt_dev*)
					cmd->tgt_dev->dh_priv;
			enum scst_cmd_queue_type last_queue_type =
				ftgt_dev->last_write_cmd_queue_type;
			ftgt_dev->last_write_cmd_queue_type = cmd->queue_type;
			if (fileio_need_pre_sync(cmd->queue_type, last_queue_type) && 
			    !virt_dev->wt_flag) {
			    	TRACE(TRACE_SCSI/*|TRACE_SPECIAL*/, "ORDERED "
			    		"WRITE_VERIFY(%d): loff=%Ld, data_len=%Ld",
			    		cmd->queue_type, (uint64_t)loff,
			    		(uint64_t)data_len);
			    	do_fsync = 1;
				if (fileio_fsync(ftgt_dev, 0, 0, cmd) != 0)
					goto done;
			}
			fileio_exec_write(cmd, loff);
			/* O_SYNC flag is used for wt_flag devices */
			if (cmd->status == 0)
				fileio_exec_verify(cmd, loff);
			else if (do_fsync)
				fileio_fsync(ftgt_dev, loff, data_len, cmd);
		} else {
			TRACE_DBG("%s", "Attempt to write to read-only device");
			scst_set_cmd_error(cmd,
		    		SCST_LOAD_SENSE(scst_sense_data_protect));
		}
		break;
	case SYNCHRONIZE_CACHE:
	{
		int immed = cmd->cdb[1] & 0x2;
		struct scst_fileio_tgt_dev *ftgt_dev = 
			(struct scst_fileio_tgt_dev*)
				cmd->tgt_dev->dh_priv;
		TRACE(TRACE_SCSI, "SYNCHRONIZE_CACHE: "
			"loff=%Ld, data_len=%Ld, immed=%d", (uint64_t)loff,
			(uint64_t)data_len, immed);
		if (immed) {
			scst_get();
			cmd->completed = 1;
			cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
			/* cmd is dead here */
			fileio_fsync(ftgt_dev, loff, data_len, NULL);
			/* ToDo: fileio_fsync() error processing */
			scst_put();
			goto out;
		} else {
			fileio_fsync(ftgt_dev, loff, data_len, cmd);
			break;
		}
	}
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		fileio_exec_verify(cmd, loff);
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		fileio_exec_mode_sense(cmd);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		fileio_exec_mode_select(cmd);
		break;
	case ALLOW_MEDIUM_REMOVAL:
		fileio_exec_prevent_allow_medium_removal(cmd);
		break;
	case READ_TOC:
		fileio_exec_read_toc(cmd);
		break;
	case START_STOP:
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
		break;
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
	TRACE_EXIT();
	return;
}

static inline int test_cmd_list(struct scst_fileio_tgt_dev *ftgt_dev)
{
	int res = !list_empty(&ftgt_dev->fdev_cmd_list) ||
		  unlikely(ftgt_dev->shutdown);
	return res;
}

static int fileio_cmd_thread(void *arg)
{
	struct scst_fileio_tgt_dev *ftgt_dev = (struct scst_fileio_tgt_dev*)arg;

	TRACE_ENTRY();

	daemonize("scst_fileio");
	recalc_sigpending();
	set_user_nice(current, 10);
	current->flags |= PF_NOFREEZE;

	spin_lock_bh(&ftgt_dev->fdev_lock);
	while (1) {
		wait_queue_t wait;
		struct scst_cmd *cmd;
		init_waitqueue_entry(&wait, current);

		if (!test_cmd_list(ftgt_dev)) {
			add_wait_queue_exclusive(&ftgt_dev->fdev_waitQ, &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_cmd_list(ftgt_dev))
					break;
				spin_unlock_bh(&ftgt_dev->fdev_lock);
				schedule();
				spin_lock_bh(&ftgt_dev->fdev_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&ftgt_dev->fdev_waitQ, &wait);
		}

		while (!list_empty(&ftgt_dev->fdev_cmd_list)) {
			cmd = list_entry(ftgt_dev->fdev_cmd_list.next, 
				typeof(*cmd), fileio_cmd_list_entry);
			cmd->fileio_in_list = 0;
			list_del(&cmd->fileio_cmd_list_entry);
			spin_unlock_bh(&ftgt_dev->fdev_lock);
			fileio_do_job(cmd);
			spin_lock_bh(&ftgt_dev->fdev_lock);
			if (unlikely(ftgt_dev->shutdown))
				break;
		}

		if (unlikely(ftgt_dev->shutdown))
			break;
	}
	spin_unlock_bh(&ftgt_dev->fdev_lock);

	if (atomic_dec_and_test(&ftgt_dev->threads_count)) {
		smp_mb__after_atomic_dec();
		TRACE_DBG("%s", "Releasing shutdown_mutex");
		up(&ftgt_dev->shutdown_mutex);
	}

	TRACE_EXIT();
	return 0;
}

static int fileio_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)tgt_dev->acg_dev->dev->dh_priv;
	struct scst_fileio_tgt_dev *ftgt_dev;
	int res = 0;

	TRACE_ENTRY();

	ftgt_dev = kzalloc(sizeof(*ftgt_dev), GFP_KERNEL);
	if (ftgt_dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of per-session "
			"virtual device failed");
		res = -ENOMEM;
		goto out;
	}

	spin_lock_init(&ftgt_dev->fdev_lock);
	INIT_LIST_HEAD(&ftgt_dev->fdev_cmd_list);
	init_waitqueue_head(&ftgt_dev->fdev_waitQ);
	atomic_set(&ftgt_dev->threads_count, 0);
	init_MUTEX_LOCKED(&ftgt_dev->shutdown_mutex);
	ftgt_dev->virt_dev = virt_dev;

	if (!virt_dev->cdrom_empty) {
		ftgt_dev->fd = fileio_open(virt_dev);
		if (IS_ERR(ftgt_dev->fd)) {
			res = PTR_ERR(ftgt_dev->fd);
			PRINT_ERROR_PR("filp_open(%s) returned an error %d",
				       virt_dev->file_name, res);
			goto out_free;
		}
	} else
		ftgt_dev->fd = NULL;

	/* 
	 * Only ONE thread must be run here, otherwise the commands could
	 * be executed out of order !!
	 */
	res = kernel_thread(fileio_cmd_thread, ftgt_dev, FILEIO_THREAD_FLAGS);
	if (res < 0) {
		PRINT_ERROR_PR("kernel_thread() failed: %d", res);
		goto out_free_close;
	}
	res = 0;
	atomic_inc(&ftgt_dev->threads_count);

	tgt_dev->dh_priv = ftgt_dev;

	down(&virt_dev->ftgt_list_mutex);
	list_add_tail(&ftgt_dev->ftgt_list_entry, 
		&virt_dev->ftgt_list);
	up(&virt_dev->ftgt_list_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_close:
	if (ftgt_dev->fd)
		filp_close(ftgt_dev->fd, NULL);

out_free:
	kfree(ftgt_dev);
	goto out;
}

static void fileio_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_fileio_tgt_dev *ftgt_dev = 
		(struct scst_fileio_tgt_dev *)tgt_dev->dh_priv;
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)tgt_dev->acg_dev->dev->dh_priv;

	TRACE_ENTRY();

	down(&virt_dev->ftgt_list_mutex);
	list_del(&ftgt_dev->ftgt_list_entry);
	up(&virt_dev->ftgt_list_mutex);

	ftgt_dev->shutdown = 1;
	wake_up_all(&ftgt_dev->fdev_waitQ);
	down(&ftgt_dev->shutdown_mutex);

	if (ftgt_dev->fd)
		filp_close(ftgt_dev->fd, NULL);

	if (ftgt_dev->iv != NULL)
		kfree(ftgt_dev->iv);

	kfree(ftgt_dev);

	tgt_dev->dh_priv = NULL;

	TRACE_EXIT();
}

/********************************************************************
 *  Function:  disk_fileio_parse
 *
 *  Argument:  
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int disk_fileio_parse(struct scst_cmd *cmd,
	const struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;
	int fixed;
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)cmd->dev->dh_priv;

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

static inline void fileio_queue_cmd(struct scst_cmd *cmd)
{
	struct scst_fileio_tgt_dev *ftgt_dev =
		(struct scst_fileio_tgt_dev *)cmd->tgt_dev->dh_priv;
	spin_lock_bh(&ftgt_dev->fdev_lock);
	TRACE_DBG("Pushing cmd %p to IO thread", cmd);
	list_add_tail(&cmd->fileio_cmd_list_entry, 
		&ftgt_dev->fdev_cmd_list);
	cmd->fileio_in_list = 1;
	spin_unlock_bh(&ftgt_dev->fdev_lock);
	wake_up(&ftgt_dev->fdev_waitQ);
}


/********************************************************************
 *  Function:  disk_fileio_exec
 *
 *  Argument:  
 *
 *  Returns : always SCST_EXEC_COMPLETED, real status is in error condition
 *  in command
 *
 *  Description:  
 ********************************************************************/
static int disk_fileio_exec(struct scst_cmd *cmd)
{
	int delayed = 0;
	int opcode = cmd->cdb[0];

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->masked_status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	/* 
	 * !!
	 * Only commands that unsensible to the execution order could be 
	 * performed here, in place. Other ones must be passed to the
	 * thread.
	 * !!
	 */
	switch (opcode) {
	case INQUIRY:
		fileio_exec_inquiry(cmd);
		break;
	case READ_CAPACITY:
		fileio_exec_read_capacity(cmd);
		break;
        case SERVICE_ACTION_IN:
		if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16)
			fileio_exec_read_capacity16(cmd);
		else
			goto def;
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
	    /* fall through */
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	    /* could move READ ONLY check up to here (currenlty in do_job()) */
	    /* fall through */
	case MODE_SENSE:
	case MODE_SENSE_10:
	case MODE_SELECT:
	case MODE_SELECT_10:
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case SYNCHRONIZE_CACHE:
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
	case START_STOP:
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
		fileio_queue_cmd(cmd);
		delayed = 1;
		break;
	case TEST_UNIT_READY:
		break;
	case REPORT_LUNS:
def:
	default:
		TRACE_DBG("Invalid opcode 0x%02x", opcode);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	}

	if (!delayed) {
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
	}

	TRACE_EXIT();
	return SCST_EXEC_COMPLETED;
}

/********************************************************************
 *  Function:  cdrom_fileio_parse
 *
 *  Argument:  
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int cdrom_fileio_parse(struct scst_cmd *cmd,
	const struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;
	int fixed;
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)cmd->dev->dh_priv;

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
 *  Function:  cdrom_fileio_exec
 *
 *  Argument:  
 *
 *  Returns :  
 *
 *  Description:  
 ********************************************************************/
static int cdrom_fileio_exec(struct scst_cmd *cmd)
{
	int delayed = 0;
	int opcode = cmd->cdb[0];
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)cmd->dev->dh_priv;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->masked_status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (virt_dev->cdrom_empty && (opcode != INQUIRY)) {
		TRACE_DBG("%s", "CDROM empty");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_not_ready));
		goto out;
	}

	/* 
	 * No protection is necessary, because media_changed set only
	 * in suspended state and exec() is serialized
	 */
	if (virt_dev->media_changed && (cmd->cdb[0] != INQUIRY) && 
	    (cmd->cdb[0] != REQUEST_SENSE) && (cmd->cdb[0] != REPORT_LUNS)) {
		virt_dev->media_changed = 0;
		TRACE_DBG("%s", "Reporting media changed");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_medium_changed_UA));
		goto out;
	}

	/* 
	 * !!
	 * Only commands that unsensible to the execution order could be 
	 * performed here, in place. Other ones must be passed to the
	 * thread.
	 * !!
	 */

	switch (opcode) {
	case INQUIRY:
		fileio_exec_inquiry(cmd);
		break;
	case READ_CAPACITY:
		fileio_exec_read_capacity(cmd);
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
	    /* fall through */
	case MODE_SENSE:
	case MODE_SENSE_10:
	case MODE_SELECT:
	case MODE_SELECT_10:
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
	case START_STOP:
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
	case ALLOW_MEDIUM_REMOVAL:
	case READ_TOC:
		fileio_queue_cmd(cmd);
		delayed = 1;
		break;
	case TEST_UNIT_READY:
		break;
	case REPORT_LUNS:
	default:
		TRACE_DBG("Invalid opcode 0x%02x", opcode);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	}

out:
	if (!delayed) {
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
	}

	TRACE_EXIT();
	return SCST_EXEC_COMPLETED;
}

static void fileio_exec_inquiry(struct scst_cmd *cmd)
{
	int32_t length, len, i;
	uint8_t *address;
	uint8_t *buf;
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)cmd->dev->dh_priv;

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
	 * Also task queue size should be set on some value.
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
			   dev_id_num,dev_id_str, len);
		if (0 == cmd->cdb[2]) { /* supported vital product data pages */
			buf[3] = 3;
			buf[4] = 0x0; /* this page */
			buf[5] = 0x80; /* unit serial number */
			buf[6] = 0x83; /* device identification */
		} else if (0x80 == cmd->cdb[2]) { /* unit serial number */
			buf[1] = 0x80;
			buf[3] = len;
			memcpy(&buf[4], dev_id_str, len);
		} else if (0x83 == cmd->cdb[2]) { /* device identification */
			int num = 4;

			buf[1] = 0x83;
			/* Two identification descriptors: */
			/* T10 vendor identifier field format (faked) */
			buf[num + 0] = 0x2;	/* ASCII */
			buf[num + 1] = 0x1;
			buf[num + 2] = 0x0;
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

			buf[3] = num + 12 - 4;
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
		memcpy(&buf[8], SCST_FIO_VENDOR, 8);

		/* 16 byte ASCII Product Identification of the target - left aligned */
		memset(&buf[16], ' ', 16);
		len = strlen(virt_dev->name);
		len = len < 16 ? len : 16;
		memcpy(&buf[16], virt_dev->name, len);

		/* 4 byte ASCII Product Revision Level of the target - left aligned */
		memcpy(&buf[32], SCST_FIO_REV, 4);
	}

	memcpy(address, buf, length < INQ_BUF_SZ ? length : INQ_BUF_SZ);
	
out_put:
	scst_put_buf(cmd, address);

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

static int fileio_err_recov_pg(unsigned char *p, int pcontrol,
			       struct scst_fileio_dev *virt_dev)
{	/* Read-Write Error Recovery page for mode_sense */
	const unsigned char err_recov_pg[] = {0x1, 0xa, 0xc0, 11, 240, 0, 0, 0,
					      5, 0, 0xff, 0xff};

	memcpy(p, err_recov_pg, sizeof(err_recov_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(err_recov_pg) - 2);
	return sizeof(err_recov_pg);
}

static int fileio_disconnect_pg(unsigned char *p, int pcontrol,
				struct scst_fileio_dev *virt_dev)
{ 	/* Disconnect-Reconnect page for mode_sense */
	const unsigned char disconnect_pg[] = {0x2, 0xe, 128, 128, 0, 10, 0, 0,
					       0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(p, disconnect_pg, sizeof(disconnect_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(disconnect_pg) - 2);
	return sizeof(disconnect_pg);
}

static int fileio_format_pg(unsigned char *p, int pcontrol,
			    struct scst_fileio_dev *virt_dev)
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

static int fileio_caching_pg(unsigned char *p, int pcontrol,
			     struct scst_fileio_dev *virt_dev)
{ 	/* Caching page for mode_sense */
	const unsigned char caching_pg[] = {0x8, 18, 0x10, 0, 0xff, 0xff, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0, 0, 0, 0, 0, 0};

	memcpy(p, caching_pg, sizeof(caching_pg));
	p[2] |= !(virt_dev->wt_flag) ? WCE : 0;
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(caching_pg) - 2);
	return sizeof(caching_pg);
}

static int fileio_ctrl_m_pg(unsigned char *p, int pcontrol,
			    struct scst_fileio_dev *virt_dev)
{ 	/* Control mode page for mode_sense */
	const unsigned char ctrl_m_pg[] = {0xa, 0xa, 0x22, 0, 0, 0x40, 0, 0,
					   0, 0, 0x2, 0x4b};

	memcpy(p, ctrl_m_pg, sizeof(ctrl_m_pg));
	if (!virt_dev->wt_flag)
		p[3] |= 0x10; /* Enable unrestricted reordering */
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(ctrl_m_pg) - 2);
	return sizeof(ctrl_m_pg);
}

static int fileio_iec_m_pg(unsigned char *p, int pcontrol,
			   struct scst_fileio_dev *virt_dev)
{	/* Informational Exceptions control mode page for mode_sense */
	const unsigned char iec_m_pg[] = {0x1c, 0xa, 0x08, 0, 0, 0, 0, 0,
				          0, 0, 0x0, 0x0};
	memcpy(p, iec_m_pg, sizeof(iec_m_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(iec_m_pg) - 2);
	return sizeof(iec_m_pg);
}

static void fileio_exec_mode_sense(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	uint8_t *buf;
	struct scst_fileio_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	unsigned char dbd, type;
	int pcontrol, pcode, subpcode;
	unsigned char dev_spec;
	int msense_6, offset, len;
	unsigned char *bp;

	TRACE_ENTRY();

	buf = kzalloc(MSENSE_BUF_SZ,
		scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	virt_dev = (struct scst_fileio_dev *)cmd->dev->dh_priv;
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
		len = fileio_err_recov_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
	case 0x2:	/* Disconnect-Reconnect page, all devices */
		len = fileio_disconnect_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
        case 0x3:       /* Format device page, direct access */
                len = fileio_format_pg(bp, pcontrol, virt_dev);
                offset += len;
                break;
	case 0x8:	/* Caching page, direct access */
		len = fileio_caching_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
	case 0xa:	/* Control Mode page, all devices */
		len = fileio_ctrl_m_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
	case 0x1c:	/* Informational Exceptions Mode page, all devices */
		len = fileio_iec_m_pg(bp, pcontrol, virt_dev);
		offset += len;
		break;
	case 0x3f:	/* Read all Mode pages */
		len = fileio_err_recov_pg(bp, pcontrol, virt_dev);
		len += fileio_disconnect_pg(bp + len, pcontrol, virt_dev);
		len += fileio_format_pg(bp + len, pcontrol, virt_dev);
		len += fileio_caching_pg(bp + len, pcontrol, virt_dev);
		len += fileio_ctrl_m_pg(bp + len, pcontrol, virt_dev);
		len += fileio_iec_m_pg(bp + len, pcontrol, virt_dev);
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

	memcpy(address, buf, min(length, offset));
	
out_put:
	scst_put_buf(cmd, address);

out_free:
	kfree(buf);

out:
	TRACE_EXIT();
	return;
}

static int fileio_set_wt(struct scst_fileio_dev *virt_dev, int wt)
{
	int res = 0;
	struct scst_fileio_tgt_dev *ftgt_dev;
	struct file *fd;

	TRACE_ENTRY();

	if (virt_dev->wt_flag == wt)
		goto out;

	virt_dev->wt_flag = wt;

	scst_suspend_activity();

	down(&virt_dev->ftgt_list_mutex);
	list_for_each_entry(ftgt_dev, &virt_dev->ftgt_list, 
		ftgt_list_entry) 
	{
		fd = fileio_open(virt_dev);
		if (IS_ERR(fd)) {
			res = PTR_ERR(fd);
			PRINT_ERROR_PR("filp_open(%s) returned an error %d, "
				"unable to change the cache mode",
				virt_dev->file_name, res);
			up(&virt_dev->ftgt_list_mutex);
			res = 0; /* ?? ToDo */
			goto out_resume;
		}
		if (ftgt_dev->fd)
			filp_close(ftgt_dev->fd, NULL);
		ftgt_dev->fd = fd;
	}
	up(&virt_dev->ftgt_list_mutex);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void fileio_exec_mode_select(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_fileio_dev *virt_dev;
	int mselect_6, offset;

	TRACE_ENTRY();

	virt_dev = (struct scst_fileio_dev *)cmd->dev->dh_priv;
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
			if (fileio_set_wt(virt_dev,
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

static void fileio_exec_read_capacity(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_fileio_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[READ_CAP_LEN];

	TRACE_ENTRY();

	virt_dev = (struct scst_fileio_dev *)cmd->dev->dh_priv;
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

	memcpy(address, buffer, length < READ_CAP_LEN ? length : READ_CAP_LEN);
	
	scst_put_buf(cmd, address);

out:
	TRACE_EXIT();
	return;
}

static void fileio_exec_read_capacity16(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_fileio_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[READ_CAP16_LEN];
	uint64_t *data64;

	TRACE_ENTRY();

	virt_dev = (struct scst_fileio_dev *)cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks;

	memset(buffer, 0, sizeof(buffer));
	data64 = (uint64_t*)buffer;
	data64[0] = cpu_to_be64(nblocks - 1);
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

	memcpy(address, buffer, length < READ_CAP16_LEN ? 
					length : READ_CAP16_LEN);
	
	scst_put_buf(cmd, address);

out:
	TRACE_EXIT();
	return;
}

static void fileio_exec_read_toc(struct scst_cmd *cmd)
{
	int32_t length, off = 0;
	uint8_t *address;
	struct scst_fileio_dev *virt_dev;
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

	virt_dev = (struct scst_fileio_dev *)cmd->dev->dh_priv;
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

	memcpy(address, buffer, (length < off) ? length : off);
	
	scst_put_buf(cmd, address);

out:
	TRACE_EXIT();
	return;
}

static void fileio_exec_prevent_allow_medium_removal(struct scst_cmd *cmd)
{
	struct scst_fileio_dev *virt_dev =
		(struct scst_fileio_dev *)cmd->dev->dh_priv;

	TRACE_DBG("PERSIST/PREVENT 0x%02x", cmd->cdb[4]);

	/* 
	 * No protection here, because in cdrom_fileio_change() the
	 * activity is suspended and exec() is serialized
	 */
	if (cmd->dev->handler->type == TYPE_ROM)
		virt_dev->prevent_allow_medium_removal = 
			cmd->cdb[4] & 0x01 ? 1 : 0;
	else {
		PRINT_ERROR_PR("%s", "Prevent allow medium removal for "
			"non-CDROM device");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	}

	return;
}

static int fileio_fsync(struct scst_fileio_tgt_dev *ftgt_dev,
	loff_t loff, loff_t len, struct scst_cmd *cmd)
{
	int res = 0;
	struct file *file = ftgt_dev->fd;
	struct inode *inode = file->f_dentry->d_inode;
	struct address_space *mapping = file->f_mapping;

	TRACE_ENTRY();

	if (ftgt_dev->virt_dev->nv_cache)
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

static struct iovec *fileio_alloc_iv(struct scst_cmd *cmd,
	struct scst_fileio_tgt_dev *ftgt_dev)
{
	int iv_count;
	
	iv_count = scst_get_buf_count(cmd);
	if (iv_count > ftgt_dev->iv_count) {
		if (ftgt_dev->iv != NULL)
			kfree(ftgt_dev->iv);
		ftgt_dev->iv = kmalloc(sizeof(*ftgt_dev->iv) * iv_count, GFP_KERNEL);
		if (ftgt_dev->iv == NULL) {
			PRINT_ERROR_PR("Unable to allocate iv (%d)", iv_count);
			scst_set_busy(cmd);
			goto out;
		}
		ftgt_dev->iv_count = iv_count;
	}

out:
	return ftgt_dev->iv;
}

static void fileio_exec_read(struct scst_cmd *cmd, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)cmd->dev->dh_priv;
	struct scst_fileio_tgt_dev *ftgt_dev = 
		(struct scst_fileio_tgt_dev *)cmd->tgt_dev->dh_priv;
	struct file *fd = ftgt_dev->fd;
	struct iovec *iv;
	int iv_count, i;

	TRACE_ENTRY();
	
	iv = fileio_alloc_iv(cmd, ftgt_dev);
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
	TRACE_DBG("reading(iv_count %d, full_len %zd)", iv_count, full_len);
	if (virt_dev->nullio)
		err = full_len;
	else
		err = fd->f_op->readv(fd, iv, iv_count, &fd->f_pos);
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

static void fileio_exec_write(struct scst_cmd *cmd, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len;
	uint8_t *address;
	struct scst_fileio_dev *virt_dev =
	    (struct scst_fileio_dev *)cmd->dev->dh_priv;
	struct scst_fileio_tgt_dev *ftgt_dev = 
		(struct scst_fileio_tgt_dev *)cmd->tgt_dev->dh_priv;
	struct file *fd = ftgt_dev->fd;
	struct iovec *iv, *eiv;
	int iv_count, eiv_count;

	TRACE_ENTRY();

	iv = fileio_alloc_iv(cmd, ftgt_dev);
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
	eiv = iv;
	eiv_count = iv_count;
restart:
	TRACE_DBG("writing(eiv_count %d, full_len %zd)", eiv_count, full_len);

	if (virt_dev->nullio)
		err = full_len;
	else
		err = fd->f_op->writev(fd, eiv, eiv_count, &fd->f_pos);
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

static void fileio_exec_verify(struct scst_cmd *cmd, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, len_mem = 0;
	uint8_t *address_sav, *address;
	int compare;
	struct scst_fileio_tgt_dev *ftgt_dev = 
		(struct scst_fileio_tgt_dev *)cmd->tgt_dev->dh_priv;
	struct file *fd = ftgt_dev->fd;
	uint8_t *mem_verify = NULL;

	TRACE_ENTRY();

	if (fileio_fsync(ftgt_dev, loff, cmd->bufflen, cmd) != 0)
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

		err = fd->f_op->read(fd, (char*)mem_verify, len_mem, &fd->f_pos);
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

/* Called with BH off. Might be called under lock and IRQ off */
static int fileio_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	int res = SCST_DEV_TM_COMPLETED_SUCCESS;

	TRACE_ENTRY();

	if (mcmd->fn == SCST_ABORT_TASK) {
		struct scst_cmd *cmd_to_abort = mcmd->cmd_to_abort;
		struct scst_fileio_tgt_dev *ftgt_dev = 
		  (struct scst_fileio_tgt_dev *)cmd_to_abort->tgt_dev->dh_priv;

		/*
		 * It is safe relating to scst_list_lock despite of lockdep's
		 * warning. Just don't know how to tell it to lockdep.
		 */
		/* BH already off */
		spin_lock(&ftgt_dev->fdev_lock);
		if (cmd_to_abort->fileio_in_list) {
			TRACE(TRACE_MGMT, "Aborting cmd %p and moving it to "
				"the queue head", cmd_to_abort);
			list_del(&cmd_to_abort->fileio_cmd_list_entry);
			list_add(&cmd_to_abort->fileio_cmd_list_entry,
				&ftgt_dev->fdev_cmd_list);
			wake_up(&ftgt_dev->fdev_waitQ);
		}
		spin_unlock(&ftgt_dev->fdev_lock);
	}

	TRACE_EXIT_RES(res);
	return res;
}

static inline struct scst_fileio_dev *fileio_alloc_dev(void)
{
	struct scst_fileio_dev *dev;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of virtual "
			"device failed");
		goto out;
	}
	INIT_LIST_HEAD(&dev->ftgt_list);
	init_MUTEX(&dev->ftgt_list_mutex);
out:
	return dev;
}

struct fileio_proc_update_struct {
	int len, plen, pplen;
	off_t begin, pbegin, ppbegin;
	off_t pos;
};

static int fileio_proc_update_size(int size, off_t offset, int length,
	struct fileio_proc_update_struct *p, int is_start)
{
	int res = 0;
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
	if (is_start) {
		p->ppbegin = p->pbegin;
		p->pplen = p->plen;
		p->pbegin = p->begin;
		p->plen = p->len;
	}
out:
	return res;
}

/* 
 * Called when a file in the /proc/DISK_FILEIO_NAME/DISK_FILEIO_NAME is read
 * or written 
 */
static int disk_fileio_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type, int inout)
{
	int res = 0, action;
	char *p, *name, *file_name;
	struct scst_fileio_dev *virt_dev, *vv;
	int size;
	struct fileio_proc_update_struct pu;

	TRACE_ENTRY();

	memset(&pu, 0, sizeof(pu));
	
	/* VERY UGLY code. You can rewrite it if you want */
	
	if (down_interruptible(&scst_fileio_mutex) != 0) {
		res = -EINTR;
		goto out;
	}
	
	if (inout == 0) { /* read */
		size = scnprintf(buffer, length, "%-17s %-11s %-11s %-15s %s\n",
			       "Name", "Size(MB)", "Block size", "Options", "File name");
		if (fileio_proc_update_size(size, offset, length, &pu, 1))
			goto stop_output;

		list_for_each_entry(virt_dev, &disk_fileio_dev_list, 
			fileio_dev_list_entry)
		{
			int c;
			size = scnprintf(buffer + pu.len, length - pu.len, 
				"%-17s %-11d %-12d", virt_dev->name,
				(uint32_t)(virt_dev->file_size >> 20),
				virt_dev->block_size);
			if (fileio_proc_update_size(size, offset, length, &pu,
					1)) {
				goto stop_output;
			}
			c = 0;
			if (virt_dev->wt_flag) {
				size = scnprintf(buffer + pu.len, length - pu.len, "WT");
				c += size;
				if (fileio_proc_update_size(size, offset,
						length, &pu, 0)) {
					goto stop_output;
				}
			}
			if (virt_dev->nv_cache) {
				size = scnprintf(buffer + pu.len, length - pu.len,
					c ? ",NV" : "NV");
				c += size;
				if (fileio_proc_update_size(size, offset,
						length, &pu, 0)) {
					goto stop_output;
				}
			}
			if (virt_dev->rd_only_flag) {
				size = scnprintf(buffer + pu.len, length - pu.len, 
					c ? ",RO" : "RO");
				c += size;
				if (fileio_proc_update_size(size, offset,
						length, &pu, 0)) {
					goto stop_output;
				}
			}
			if (virt_dev->o_direct_flag) {
				size = scnprintf(buffer + pu.len, length - pu.len, 
					c ? ",DR" : "DR");
				c += size;
				if (fileio_proc_update_size(size, offset,
						length, &pu, 0)) {
					goto stop_output;
				}
			}
			if (virt_dev->nullio) {
				size = scnprintf(buffer + pu.len, length - pu.len, 
					c ? ",NIO" : "NIO");
				c += size;
				if (fileio_proc_update_size(size, offset,
						length, &pu, 0)) {
					goto stop_output;
				}
			}
			while (c < 16) {
				size = scnprintf(buffer + pu.len, length - pu.len, " ");
				if (fileio_proc_update_size(size, offset,
						length, &pu, 0)) {
					goto stop_output;
				}
				c++;
			}
			size = scnprintf(buffer + pu.len, length - pu.len, "%s\n",
					virt_dev->file_name);
			if (fileio_proc_update_size(size, offset, length, &pu,
					0)) {
				goto stop_output;
			}
		}
		*eof = 1;
		goto stop_output;
	} else {  /* write */
		uint32_t block_size = DEF_DISK_BLOCKSIZE;
		int block_shift = DEF_DISK_BLOCKSIZE_SHIFT;
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
			list_for_each_entry(vv, &disk_fileio_dev_list,
					    fileio_dev_list_entry)
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
			} else if (*file_name != '/') {
				PRINT_ERROR_PR("File path \"%s\" is not "
					"absolute", file_name);
				res = -EINVAL;
				goto out_up;
			}

			virt_dev = fileio_alloc_dev();
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
				} else {
					PRINT_ERROR_PR("Unknown flag \"%s\"", p);
					res = -EINVAL;
					goto out_free_vdev;
				}
				while (isspace(*p) && *p != '\0')
					p++;
			}
			
			strcpy(virt_dev->name, name);

			pu.len = strlen(file_name) + 1;
			virt_dev->file_name = kmalloc(pu.len, GFP_KERNEL);
			if (virt_dev->file_name == NULL) {
				TRACE(TRACE_OUT_OF_MEM, "%s",
				      "Allocation of file_name failed");
				res = -ENOMEM;
				goto out_free_vdev;
			}
			strncpy(virt_dev->file_name, file_name, pu.len);

			list_add_tail(&virt_dev->fileio_dev_list_entry,
				      &disk_fileio_dev_list);

			virt_dev->virt_id =
			    scst_register_virtual_device(&disk_devtype_fileio,
							 virt_dev->name);
			if (virt_dev->virt_id < 0) {
				res = virt_dev->virt_id;
				goto out_free_vpath;
			}
			TRACE_DBG("Added virt_dev (name %s, file name %s, "
				"id %d, block size %d) to "
				"disk_fileio_dev_list", virt_dev->name,
				virt_dev->file_name, virt_dev->virt_id,
				virt_dev->block_size);
		} else {                           /* close */
			virt_dev = NULL;
			list_for_each_entry(vv, &disk_fileio_dev_list,
					    fileio_dev_list_entry)
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

			list_del(&virt_dev->fileio_dev_list_entry);

			kfree(virt_dev->file_name);
			kfree(virt_dev);
		}
		res = length;
	}

out_up:
	up(&scst_fileio_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

stop_output:
	*start = buffer + (offset - pu.begin);
	pu.len -= (offset - pu.begin);
	if (pu.len > length)
		pu.len = length;
	res = max(0, pu.len);
	goto out_up;

out_free_vpath:
	list_del(&virt_dev->fileio_dev_list_entry);
	kfree(virt_dev->file_name);

out_free_vdev:
	kfree(virt_dev);
	goto out_up;
}

/* scst_fileio_mutex supposed to be held */
static int cdrom_fileio_open(char *p, char *name)
{
	struct scst_fileio_dev *virt_dev, *vv;
	char *file_name;
	int len;
	int res = 0;
	int cdrom_empty;

	virt_dev = NULL;
	list_for_each_entry(vv, &cdrom_fileio_dev_list,
			    fileio_dev_list_entry)
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

	virt_dev = fileio_alloc_dev();
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

	list_add_tail(&virt_dev->fileio_dev_list_entry,
		      &cdrom_fileio_dev_list);

	virt_dev->virt_id =
	    scst_register_virtual_device(&cdrom_devtype_fileio,
					 virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_free_vpath;
	}
	TRACE_DBG("Added virt_dev (name %s file_name %s id %d) "
		  "to cdrom_fileio_dev_list", virt_dev->name,
		  virt_dev->file_name, virt_dev->virt_id);

out:
	return res;

out_free_vpath:
	list_del(&virt_dev->fileio_dev_list_entry);
	kfree(virt_dev->file_name);

out_free_vdev:
	kfree(virt_dev);
	goto out;
}

/* scst_fileio_mutex supposed to be held */
static int cdrom_fileio_close(char *name)
{
	struct scst_fileio_dev *virt_dev, *vv;
	int res = 0;

	virt_dev = NULL;
	list_for_each_entry(vv, &cdrom_fileio_dev_list,
			    fileio_dev_list_entry)
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

	list_del(&virt_dev->fileio_dev_list_entry);

	if (virt_dev->file_name)
		kfree(virt_dev->file_name);
	kfree(virt_dev);

out:
	return res;
}

/* scst_fileio_mutex supposed to be held */
static int cdrom_fileio_change(char *p, char *name)
{
	struct file *fd;
	struct scst_fileio_tgt_dev *ftgt_dev;
	loff_t err;
	mm_segment_t old_fs;
	struct scst_fileio_dev *virt_dev, *vv;
	char *file_name, *fn, *old_fn;
	int len;
	int res = 0;

	virt_dev = NULL;
	list_for_each_entry(vv, &cdrom_fileio_dev_list,
			    fileio_dev_list_entry)
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

	if (!virt_dev->cdrom_empty) {
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

		fd = fileio_open(virt_dev);
		if (IS_ERR(fd)) {
			res = PTR_ERR(fd);
			PRINT_ERROR_PR("filp_open(%s) returned an error %d",
				       virt_dev->file_name, res);
			goto out_free;
		}
		if ((fd->f_op == NULL) || (fd->f_op->readv == NULL)) {
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

	down(&virt_dev->ftgt_list_mutex);
	list_for_each_entry(ftgt_dev, &virt_dev->ftgt_list, 
		ftgt_list_entry) 
	{
		if (!virt_dev->cdrom_empty) {
			fd = fileio_open(virt_dev);
			if (IS_ERR(fd)) {
				res = PTR_ERR(fd);
				PRINT_ERROR_PR("filp_open(%s) returned an error %d, "
					"closing the device", virt_dev->file_name, res);
				up(&virt_dev->ftgt_list_mutex);
				goto out_err_resume;
			}
		} else
			fd = NULL;
		if (ftgt_dev->fd)
			filp_close(ftgt_dev->fd, NULL);
		ftgt_dev->fd = fd;
	}
	up(&virt_dev->ftgt_list_mutex);

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

out_err_resume:
	virt_dev->file_name = old_fn;
	kfree(fn);
	scst_resume_activity();
	cdrom_fileio_close(name);
	goto out;
}

/* 
 * Called when a file in the /proc/CDROM_FILEIO_NAME/CDROM_FILEIO_NAME is read
 * or written 
 */
static int cdrom_fileio_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type, int inout)
{
	int res = 0, action;
	char *p, *name;
	struct scst_fileio_dev *virt_dev;
	int size;
	struct fileio_proc_update_struct pu;

	TRACE_ENTRY();

	memset(&pu, 0, sizeof(pu));

	if (down_interruptible(&scst_fileio_mutex) != 0) {
		res = -EINTR;
		goto out;
	}
	
	if (inout == 0) { /* read */
		size = scnprintf(buffer, length, "%-17s %-9s %s\n",
			       "Name", "Size(MB)", "File name");
		if (fileio_proc_update_size(size, offset, length, &pu, 1))
			goto stop_output;

		list_for_each_entry(virt_dev, &cdrom_fileio_dev_list, 
			fileio_dev_list_entry)
		{
			size = scnprintf(buffer + pu.len, length - pu.len, 
				"%-17s %-9d %s\n", virt_dev->name,
				(uint32_t)(virt_dev->file_size >> 20),
				virt_dev->file_name);
			if (fileio_proc_update_size(size, offset, length, &pu,
					1)) {
				goto stop_output;
			}
		}
		*eof = 1;
		goto stop_output;
	} else {  /* write */
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
			res = cdrom_fileio_open(p, name);
			if (res != 0)
				goto out_up;
		} else if (action == 1) {          /* change */
			res = cdrom_fileio_change(p, name);
			if (res != 0)
				goto out_up;
		} else {                           /* close */
			res = cdrom_fileio_close(name);
			if (res != 0)
				goto out_up;
		}
		res = length;
	}

out_up:
	up(&scst_fileio_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

stop_output:
	*start = buffer + (offset - pu.begin);
	pu.len -= (offset - pu.begin);
	if (pu.len > length)
		pu.len = length;
	res = pu.len;
	goto out_up;
}

static int fileio_proc_help_build(struct scst_dev_type *dev_type)
{
	int res = 0;
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	if (root) {
		p = create_proc_read_entry(FILEIO_PROC_HELP,
			S_IFREG | S_IRUGO, root,
			fileio_proc_help_read,
			(dev_type->type == TYPE_DISK) ? 
				disk_fileio_proc_help_string :
				cdrom_fileio_proc_help_string);
		if (p == NULL) {
			PRINT_ERROR_PR("Not enough memory to register dev "
			     "handler %s entry %s in /proc",
			      dev_type->name, FILEIO_PROC_HELP);
			res = -ENOMEM;
			goto out;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void fileio_proc_help_destroy(struct scst_dev_type *dev_type)
{
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	if (root)
		remove_proc_entry(FILEIO_PROC_HELP, root);

	TRACE_EXIT();
}

static int fileio_proc_help_read(char *buffer, char **start, off_t offset,
				      int length, int *eof, void *data)
{
	int res = 0;
	char *s = (char*)data;
	
	TRACE_ENTRY();
	
	if (offset < strlen(s))
		res = scnprintf(buffer, length, "%s", &s[offset]);
	
	TRACE_EXIT_RES(res);
	return res;
}

static int __init init_scst_fileio(struct scst_dev_type *devtype)
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

	res = fileio_proc_help_build(devtype);
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

static void __exit exit_scst_fileio(struct scst_dev_type *devtype,
	struct list_head *fileio_dev_list)
{
	TRACE_ENTRY();

	down(&scst_fileio_mutex);
	while (1) {
		struct scst_fileio_dev *virt_dev;

		if (list_empty(fileio_dev_list))
			break;
		
		virt_dev = list_entry(fileio_dev_list->next, typeof(*virt_dev),
				fileio_dev_list_entry);

		scst_unregister_virtual_device(virt_dev->virt_id);

		list_del(&virt_dev->fileio_dev_list_entry);

		PRINT_INFO_PR("Virtual device %s unregistered", virt_dev->name);
		TRACE_DBG("virt_id %d", virt_dev->virt_id);
		kfree(virt_dev->file_name);
		kfree(virt_dev);
	}
	up(&scst_fileio_mutex);

	fileio_proc_help_destroy(devtype);
	scst_dev_handler_destroy_std_proc(devtype);

	scst_unregister_virtual_dev_driver(devtype);

	TRACE_EXIT();
	return;
}

static int __init init_scst_fileio_driver(void)
{
	int res;
	res = init_scst_fileio(&disk_devtype_fileio);
	if (res != 0)
		goto out;

	res = init_scst_fileio(&cdrom_devtype_fileio);
	if (res != 0)
		goto out_err;

out:
	return res;

out_err:
	exit_scst_fileio(&disk_devtype_fileio, &disk_fileio_dev_list);
	goto out;
}

static void __exit exit_scst_fileio_driver(void)
{
	exit_scst_fileio(&disk_devtype_fileio, &disk_fileio_dev_list);
	exit_scst_fileio(&cdrom_devtype_fileio, &cdrom_fileio_dev_list);

	/* 
	 * Wait for one sec. to allow the thread(s) actually exit,
	 * otherwise we can get Oops. Any better way?
	 */
	{
		unsigned long t = jiffies;
		TRACE_DBG("%s", "Waiting 1 sec...");
		while ((jiffies - t) < HZ)
			schedule();
	}
}

module_init(init_scst_fileio_driver);
module_exit(exit_scst_fileio_driver);

MODULE_LICENSE("GPL");
