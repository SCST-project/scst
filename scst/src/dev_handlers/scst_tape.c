/*
 *  scst_tape.c
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  SCSI tape (type 1) dev handler
 *  &
 *  SCSI tape (type 1) "performance" device handler (skip all READ and WRITE
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
#include <scsi/scsi_host.h>
#include <linux/slab.h>
#include <asm/unaligned.h>

#define LOG_PREFIX           "dev_tape"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_dev_handler.h"

#define TAPE_NAME		"dev_tape"
#define TAPE_PERF_NAME		"dev_tape_perf"

#define TAPE_RETRIES		2

#define TAPE_DEF_BLOCK_SIZE	512

/* The fixed bit in READ/WRITE/VERIFY */
#define SILI_BIT		2

static int tape_attach(struct scst_device *);
static void tape_detach(struct scst_device *);
static int tape_parse(struct scst_cmd *);
static int tape_done(struct scst_cmd *);
static int tape_perf_exec(struct scst_cmd *);

static struct scst_dev_type tape_devtype = {
	.name =			TAPE_NAME,
	.type =			TYPE_TAPE,
	.threads_num =		1,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.attach =		tape_attach,
	.detach =		tape_detach,
	.parse =		tape_parse,
	.dev_done =		tape_done,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
#endif
};

static struct scst_dev_type tape_devtype_perf = {
	.name =			TAPE_PERF_NAME,
	.type =			TYPE_TAPE,
	.parse_atomic =		1,
	.dev_done_atomic =	1,
	.attach =		tape_attach,
	.detach =		tape_detach,
	.parse =		tape_parse,
	.dev_done =		tape_done,
	.exec =			tape_perf_exec,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
#endif
};

static int __init init_scst_tape_driver(void)
{
	int res = 0;

	TRACE_ENTRY();

	tape_devtype.module = THIS_MODULE;

	res = scst_register_dev_driver(&tape_devtype);
	if (res < 0)
		goto out;

	tape_devtype_perf.module = THIS_MODULE;

	res = scst_register_dev_driver(&tape_devtype_perf);
	if (res < 0)
		goto out_unreg;

#ifdef CONFIG_SCST_PROC
	res = scst_dev_handler_build_std_proc(&tape_devtype);
	if (res != 0)
		goto out_unreg1;

	res = scst_dev_handler_build_std_proc(&tape_devtype_perf);
	if (res != 0)
		goto out_unreg2;
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

#ifdef CONFIG_SCST_PROC
out_unreg2:
	scst_dev_handler_destroy_std_proc(&tape_devtype);

out_unreg1:
	scst_unregister_dev_driver(&tape_devtype_perf);
#endif

out_unreg:
	scst_unregister_dev_driver(&tape_devtype);
	goto out;
}

static void __exit exit_scst_tape_driver(void)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_PROC
	scst_dev_handler_destroy_std_proc(&tape_devtype_perf);
	scst_dev_handler_destroy_std_proc(&tape_devtype);
#endif
	scst_unregister_dev_driver(&tape_devtype_perf);
	scst_unregister_dev_driver(&tape_devtype);

	TRACE_EXIT();
	return;
}

module_init(init_scst_tape_driver);
module_exit(exit_scst_tape_driver);

static int tape_attach(struct scst_device *dev)
{
	int res, rc;
	int retries;
	struct scsi_mode_data data;
	const int buffer_size = 512;
	uint8_t *buffer = NULL;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->type) {
		PRINT_ERROR("%s", "SCSI device not define or illegal type");
		res = -ENODEV;
		goto out;
	}

	dev->block_size = TAPE_DEF_BLOCK_SIZE;
	dev->block_shift = -1; /* not used */

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		PRINT_ERROR("Buffer memory allocation (size %d) failure",
			buffer_size);
		res = -ENOMEM;
		goto out;
	}

	retries = SCST_DEV_RETRIES_ON_UA;
	do {
		TRACE_DBG("%s", "Doing TEST_UNIT_READY");
		rc = scsi_test_unit_ready(dev->scsi_dev,
			SCST_GENERIC_TAPE_SMALL_TIMEOUT, TAPE_RETRIES
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
					  );
#else
					  , NULL);
#endif
		TRACE_DBG("TEST_UNIT_READY done: %x", rc);
	} while ((--retries > 0) && rc);

	if (rc) {
		PRINT_WARNING("Unit not ready: %x", rc);
		/* Let's try not to be too smart and continue processing */
		goto obtain;
	}

	TRACE_DBG("%s", "Doing MODE_SENSE");
	rc = scsi_mode_sense(dev->scsi_dev,
			      ((dev->scsi_dev->scsi_level <= SCSI_2) ?
			       ((dev->scsi_dev->lun << 5) & 0xe0) : 0),
			      0 /* Mode Page 0 */,
			      buffer, buffer_size,
			      SCST_GENERIC_TAPE_SMALL_TIMEOUT, TAPE_RETRIES,
			      &data, NULL);
	TRACE_DBG("MODE_SENSE done: %x", rc);

	if (rc == 0) {
		int medium_type, mode, speed, density;
		if (buffer[3] == 8)
			dev->block_size = get_unaligned_be24(&buffer[9]);
		else
			dev->block_size = TAPE_DEF_BLOCK_SIZE;
		medium_type = buffer[1];
		mode = (buffer[2] & 0x70) >> 4;
		speed = buffer[2] & 0x0f;
		density = buffer[4];
		TRACE_DBG("Tape: lun %d. bs %d. type 0x%02x mode 0x%02x "
		      "speed 0x%02x dens 0x%02x", dev->scsi_dev->lun,
		      dev->block_size, medium_type, mode, speed, density);
	} else {
		PRINT_ERROR("MODE_SENSE failed: %x", rc);
		res = -ENODEV;
		goto out_free_buf;
	}
	dev->block_shift = -1; /* not used */

obtain:
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

static void tape_detach(struct scst_device *dev)
{
	/* Nothing to do */
	return;
}

static int tape_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT, rc;

	rc = scst_tape_generic_parse(cmd);
	if (rc != 0) {
		res = scst_get_cmd_abnormal_done_state(cmd);
		goto out;
	}

	cmd->retries = SCST_PASSTHROUGH_RETRIES;
out:
	return res;
}

static void tape_set_block_size(struct scst_cmd *cmd, int block_size)
{
	struct scst_device *dev = cmd->dev;
	/*
	 * No need for locks here, since *_detach() can not be called, when
	 * there are existing commands.
	 */
	dev->block_size = block_size;
	dev->block_shift = -1; /* not used */
	return;
}

static int tape_done(struct scst_cmd *cmd)
{
	int opcode = cmd->cdb[0];
	int status = cmd->status;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	if ((status == SAM_STAT_GOOD) || (status == SAM_STAT_CONDITION_MET))
		res = scst_tape_generic_dev_done(cmd, tape_set_block_size);
	else if ((status == SAM_STAT_CHECK_CONDITION) &&
		   scst_sense_valid(cmd->sense)) {
		TRACE_DBG("Extended sense %x", scst_sense_response_code(cmd->sense));

		if (scst_sense_response_code(cmd->sense) != 0x70) {
			PRINT_ERROR("Sense format 0x%x is not supported",
				scst_sense_response_code(cmd->sense));
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out;
		}

		if (opcode == READ_6 && !(cmd->cdb[1] & SILI_BIT) &&
		    (cmd->sense[2] & 0xe0)) {
			/* EOF, EOM, or ILI */
			unsigned int TransferLength, Residue = 0;
			if ((cmd->sense[2] & 0x0f) == BLANK_CHECK)
				/* No need for EOM in this case */
				cmd->sense[2] &= 0xcf;
			TransferLength = get_unaligned_be24(&cmd->cdb[2]);
			/* Compute the residual count */
			if ((cmd->sense[0] & 0x80) != 0)
				Residue = get_unaligned_be32(&cmd->sense[3]);
			TRACE_DBG("Checking the sense key "
				"sn[2]=%x cmd->cdb[0,1]=%x,%x TransLen/Resid"
				" %d/%d", (int)cmd->sense[2], cmd->cdb[0],
				cmd->cdb[1], TransferLength, Residue);
			if (TransferLength > Residue) {
				int resp_data_len = TransferLength - Residue;
				if (cmd->cdb[1] & 1) {
					/*
					 * No need for locks here, since
					 * *_detach() can not be called, when
					 * there are existing commands.
					 */
					resp_data_len *= cmd->dev->block_size;
				}
				scst_set_resp_data_len(cmd, resp_data_len);
			}
		}
	}

out:
	TRACE_DBG("cmd->is_send_status=%x, cmd->resp_data_len=%d, "
	      "res=%d", cmd->is_send_status, cmd->resp_data_len, res);

	TRACE_EXIT_RES(res);
	return res;
}

static int tape_perf_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
	int opcode = cmd->cdb[0];

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	switch (opcode) {
	case WRITE_6:
	case READ_6:
		cmd->completed = 1;
		goto out_done;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	res = SCST_EXEC_COMPLETED;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI tape (type 1) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
