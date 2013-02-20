/*
 *  scst_disk.c
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  SCSI disk (type 0) dev handler
 *  &
 *  SCSI disk (type 0) "performance" device handler (skip all READ and WRITE
 *   operations).
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
#include <linux/blkdev.h>
#include <scsi/scsi_host.h>
#include <linux/slab.h>
#include <asm/unaligned.h>

#define LOG_PREFIX           "dev_disk"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_dev_handler.h"

# define DISK_NAME           "dev_disk"
# define DISK_PERF_NAME      "dev_disk_perf"

#define DISK_DEF_BLOCK_SHIFT	9

static int disk_attach(struct scst_device *dev);
static void disk_detach(struct scst_device *dev);
static int disk_parse(struct scst_cmd *cmd);
static int disk_perf_exec(struct scst_cmd *cmd);
static int disk_done(struct scst_cmd *cmd);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)
static int disk_exec(struct scst_cmd *cmd);
static bool disk_on_sg_tablesize_low(struct scst_cmd *cmd);
#endif

static struct scst_dev_type disk_devtype = {
	.name =			DISK_NAME,
	.type =			TYPE_DISK,
	.threads_num =		1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.attach =		disk_attach,
	.detach =		disk_detach,
	.parse =		disk_parse,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)
	.exec =			disk_exec,
	.on_sg_tablesize_low = disk_on_sg_tablesize_low,
#endif
	.dev_done =		disk_done,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags = SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags = &trace_flag,
#endif
};

static struct scst_dev_type disk_devtype_perf = {
	.name =			DISK_PERF_NAME,
	.type =			TYPE_DISK,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.attach =		disk_attach,
	.detach =		disk_detach,
	.parse =		disk_parse,
	.exec =			disk_perf_exec,
	.dev_done =		disk_done,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)
	.on_sg_tablesize_low = disk_on_sg_tablesize_low,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
#endif
};

static int __init init_scst_disk_driver(void)
{
	int res = 0;

	TRACE_ENTRY();

	disk_devtype.module = THIS_MODULE;

	res = scst_register_dev_driver(&disk_devtype);
	if (res < 0)
		goto out;

	disk_devtype_perf.module = THIS_MODULE;

	res = scst_register_dev_driver(&disk_devtype_perf);
	if (res < 0)
		goto out_unreg;

#ifdef CONFIG_SCST_PROC
	res = scst_dev_handler_build_std_proc(&disk_devtype);
	if (res != 0)
		goto out_unreg1;

	res = scst_dev_handler_build_std_proc(&disk_devtype_perf);
	if (res != 0)
		goto out_unreg2;
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

#ifdef CONFIG_SCST_PROC
out_unreg2:
	scst_dev_handler_destroy_std_proc(&disk_devtype);

out_unreg1:
	scst_unregister_dev_driver(&disk_devtype_perf);
#endif

out_unreg:
	scst_unregister_dev_driver(&disk_devtype);
	goto out;
}

static void __exit exit_scst_disk_driver(void)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_PROC
	scst_dev_handler_destroy_std_proc(&disk_devtype_perf);
	scst_dev_handler_destroy_std_proc(&disk_devtype);
#endif
	scst_unregister_dev_driver(&disk_devtype_perf);
	scst_unregister_dev_driver(&disk_devtype);

	TRACE_EXIT();
	return;
}

module_init(init_scst_disk_driver);
module_exit(exit_scst_disk_driver);

static int disk_attach(struct scst_device *dev)
{
	int res, rc;
	uint8_t cmd[10];
	const int buffer_size = 512;
	uint8_t *buffer = NULL;
	int retries;
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
	enum dma_data_direction data_dir;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->type) {
		PRINT_ERROR("%s", "SCSI device not define or illegal type");
		res = -ENODEV;
		goto out;
	}

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		PRINT_ERROR("Buffer memory allocation (size %d) failure",
			buffer_size);
		res = -ENOMEM;
		goto out;
	}

	/* Clear any existing UA's and get disk capacity (disk block size) */
	memset(cmd, 0, sizeof(cmd));
	cmd[0] = READ_CAPACITY;
	cmd[1] = (dev->scsi_dev->scsi_level <= SCSI_2) ?
	    ((dev->scsi_dev->lun << 5) & 0xe0) : 0;
	retries = SCST_DEV_RETRIES_ON_UA;
	while (1) {
		memset(buffer, 0, buffer_size);
		memset(sense_buffer, 0, sizeof(sense_buffer));
		data_dir = SCST_DATA_READ;

		TRACE_DBG("%s", "Doing READ_CAPACITY");
		rc = scsi_execute(dev->scsi_dev, cmd, data_dir, buffer,
				   buffer_size, sense_buffer,
				   SCST_GENERIC_DISK_REG_TIMEOUT, 3, 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
				   , NULL
#endif
				  );

		TRACE_DBG("READ_CAPACITY done: %x", rc);

		if ((rc == 0) ||
		    !scst_analyze_sense(sense_buffer,
				sizeof(sense_buffer), SCST_SENSE_KEY_VALID,
				UNIT_ATTENTION, 0, 0))
			break;
		if (!--retries) {
			PRINT_ERROR("UA not clear after %d retries",
				SCST_DEV_RETRIES_ON_UA);
			res = -ENODEV;
			goto out_free_buf;
		}
	}
	if (rc == 0) {
		uint32_t sector_size = get_unaligned_be32(&buffer[4]);
		if (sector_size == 0)
			dev->block_shift = DISK_DEF_BLOCK_SHIFT;
		else
			dev->block_shift = scst_calc_block_shift(sector_size);
	} else {
		dev->block_shift = DISK_DEF_BLOCK_SHIFT;
		TRACE(TRACE_MINOR, "Read capacity failed: %x, using default "
			"sector size %d", rc, dev->block_shift);
		PRINT_BUFF_FLAG(TRACE_MINOR, "Returned sense", sense_buffer,
			sizeof(sense_buffer));
	}
	dev->block_size = 1 << dev->block_shift;

	res = scst_obtain_device_parameters(dev, NULL);
	if (res != 0) {
		PRINT_ERROR("Failed to obtain control parameters for device "
			"%s", dev->virt_name);
		goto out_free_buf;
	}

out_free_buf:
	kfree(buffer);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void disk_detach(struct scst_device *dev)
{
	/* Nothing to do */
	return;
}

static int disk_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT, rc;

	rc = scst_sbc_generic_parse(cmd);
	if (rc != 0) {
		res = scst_get_cmd_abnormal_done_state(cmd);
		goto out;
	}

	cmd->retries = SCST_PASSTHROUGH_RETRIES;
out:
	return res;
}

static void disk_set_block_shift(struct scst_cmd *cmd, int block_shift)
{
	struct scst_device *dev = cmd->dev;
	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	if (block_shift != 0)
		dev->block_shift = block_shift;
	else
		dev->block_shift = DISK_DEF_BLOCK_SHIFT;
	dev->block_size = 1 << dev->block_shift;
	return;
}

static int disk_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	res = scst_block_generic_dev_done(cmd, disk_set_block_shift);

	TRACE_EXIT_RES(res);
	return res;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)

static bool disk_on_sg_tablesize_low(struct scst_cmd *cmd)
{
	bool res;

	TRACE_ENTRY();

	switch (cmd->cdb[0]) {
	case WRITE_6:
	case READ_6:
	case WRITE_10:
	case READ_10:
	case WRITE_VERIFY:
	case WRITE_12:
	case READ_12:
	case WRITE_VERIFY_12:
	case WRITE_16:
	case READ_16:
	case WRITE_VERIFY_16:
		res = true;
		/* See comment in disk_exec */
		cmd->inc_expected_sn_on_done = 1;
		break;
	default:
		res = false;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

struct disk_work {
	struct scst_cmd *cmd;
	struct completion disk_work_cmpl;
	int result;
	unsigned int left;
	int64_t save_lba;
	int save_len;
	struct scatterlist *save_sg;
	int save_sg_cnt;
};

static void disk_restore_sg(struct disk_work *work)
{
	scst_set_cdb_lba(work->cmd, work->save_lba);
	scst_set_cdb_transf_len(work->cmd, work->save_len);
	work->cmd->sg = work->save_sg;
	work->cmd->sg_cnt = work->save_sg_cnt;
	return;
}

static void disk_cmd_done(void *data, char *sense, int result, int resid)
{
	struct disk_work *work = data;

	TRACE_ENTRY();

	TRACE_DBG("work %p, cmd %p, left %d, result %d, sense %p, resid %d",
		work, work->cmd, work->left, result, sense, resid);

	if (result == SAM_STAT_GOOD)
		goto out_complete;

	work->result = result;

	disk_restore_sg(work);

	scst_pass_through_cmd_done(work->cmd, sense, result, resid + work->left);

out_complete:
	complete_all(&work->disk_work_cmpl);

	TRACE_EXIT();
	return;
}

/* Executes command and split CDB, if necessary */
static int disk_exec(struct scst_cmd *cmd)
{
	int res, rc;
	struct disk_work work;
	struct scst_device *dev = cmd->dev;
	unsigned int offset, cur_len; /* in blocks */
	struct scatterlist *sg, *start_sg;
	int cur_sg_cnt;
	int sg_tablesize = cmd->dev->scsi_dev->host->sg_tablesize;
	int max_sectors;
	int num, j, block_shift = dev->block_shift;

	TRACE_ENTRY();

	/*
	 * For PC requests we are going to submit max_hw_sectors used instead
	 * of max_sectors.
	 */
	max_sectors = queue_max_hw_sectors(dev->scsi_dev->request_queue);

	if (unlikely(((max_sectors << block_shift) & ~PAGE_MASK) != 0)) {
		int mlen = max_sectors << block_shift;
		int pg = ((mlen >> PAGE_SHIFT) + ((mlen & ~PAGE_MASK) != 0)) - 1;
		int adj_len = pg << PAGE_SHIFT;
		max_sectors = adj_len >> block_shift;
		if (max_sectors == 0) {
			PRINT_ERROR("Too low max sectors %d", max_sectors);
			goto out_error;
		}
	}

	if (unlikely((cmd->bufflen >> block_shift) > max_sectors)) {
		if ((cmd->out_bufflen >> block_shift) > max_sectors) {
			PRINT_ERROR("Too limited max_sectors %d for "
				"bidirectional cmd %x (out_bufflen %d)",
				max_sectors, cmd->cdb[0], cmd->out_bufflen);
			/* Let lower level handle it */
			res = SCST_EXEC_NOT_COMPLETED;
			goto out;
		}
		goto split;
	}

	if (cmd->sg_cnt <= sg_tablesize) {
		res = SCST_EXEC_NOT_COMPLETED;
		goto out;
	}

split:
	sBUG_ON(cmd->out_sg_cnt > sg_tablesize);
	sBUG_ON((cmd->out_bufflen >> block_shift) > max_sectors);

	/*
	 * We don't support changing BIDI CDBs (see disk_on_sg_tablesize_low()),
	 * so use only sg_cnt
	 */

	memset(&work, 0, sizeof(work));
	work.cmd = cmd;
	work.save_sg = cmd->sg;
	work.save_sg_cnt = cmd->sg_cnt;
	work.save_lba = cmd->lba;
	work.save_len = cmd->bufflen;

	EXTRACHECKS_BUG_ON(work.save_len < 0);

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	TRACE_DBG("cmd %p, save_sg %p, save_sg_cnt %d, save_lba %lld, "
		"save_len %d (sg_tablesize %d, max_sectors %d, block_shift %d, "
		"sizeof(*sg) 0x%zx)", cmd, work.save_sg, work.save_sg_cnt,
		(unsigned long long)work.save_lba, work.save_len,
		sg_tablesize, max_sectors, block_shift, sizeof(*sg));

	/*
	 * If we submit all chunks async'ly, it will be very not trivial what
	 * to do if several of them finish with sense or residual. So, let's
	 * do it synchronously.
	 */

	num = 1;
	j = 0;
	offset = 0;
	cur_len = 0;
	sg = work.save_sg;
	start_sg = sg;
	cur_sg_cnt = 0;
	while (1) {
		unsigned int l;

		if (unlikely(sg_is_chain(&sg[j]))) {
			bool reset_start_sg = (start_sg == &sg[j]);
			sg = sg_chain_ptr(&sg[j]);
			j = 0;
			if (reset_start_sg)
				start_sg = sg;
		}

		l = sg[j].length >> block_shift;
		cur_len += l;
		cur_sg_cnt++;

		TRACE_DBG("l %d, j %d, num %d, offset %d, cur_len %d, "
			"cur_sg_cnt %d, start_sg %p", l, j, num, offset,
			cur_len, cur_sg_cnt, start_sg);

		if (((num % sg_tablesize) == 0) ||
		     (num == work.save_sg_cnt) ||
		     (cur_len >= max_sectors)) {
			TRACE_DBG("%s", "Execing...");

			scst_set_cdb_lba(work.cmd, work.save_lba + offset);
			scst_set_cdb_transf_len(work.cmd, cur_len);
			cmd->sg = start_sg;
			cmd->sg_cnt = cur_sg_cnt;

			work.left = work.save_len - (offset + cur_len);
			init_completion(&work.disk_work_cmpl);

			rc = scst_scsi_exec_async(cmd, &work, disk_cmd_done);
			if (unlikely(rc != 0)) {
				PRINT_ERROR("scst_scsi_exec_async() failed: %d",
					rc);
				goto out_err_restore;
			}

			wait_for_completion(&work.disk_work_cmpl);

			if (work.result != SAM_STAT_GOOD) {
				/* cmd can be already dead */
				res = SCST_EXEC_COMPLETED;
				goto out;
			}

			offset += cur_len;
			cur_len = 0;
			cur_sg_cnt = 0;
			start_sg = &sg[j+1];

			if (num == work.save_sg_cnt)
				break;
		}
		num++;
		j++;
	}

	cmd->completed = 1;

out_restore:
	disk_restore_sg(&work);

out_done:
	res = SCST_EXEC_COMPLETED;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

out:
	TRACE_EXIT_RES(res);
	return res;

out_err_restore:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_restore;

out_error:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_done;
}

#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED) */

static int disk_perf_exec(struct scst_cmd *cmd)
{
	int res;
	int opcode = cmd->cdb[0];

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	switch (opcode) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		goto out_complete;
	}

	res = SCST_EXEC_NOT_COMPLETED;

out:
	TRACE_EXIT_RES(res);
	return res;

out_complete:
	cmd->completed = 1;
	res = SCST_EXEC_COMPLETED;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI disk (type 0) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);

