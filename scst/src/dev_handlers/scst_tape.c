/*
 *  scst_tape.c
 *
 *  Copyright (C) 2004-2007 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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

#define LOG_PREFIX           "dev_tape"

#include "scst.h"
#include "scst_dev_handler.h"

# define TAPE_NAME           "dev_tape"
# define TAPE_PERF_NAME      "dev_tape_perf"

#define TAPE_TYPE {				\
	.name =			TAPE_NAME,	\
	.type =			TYPE_TAPE,	\
	.parse_atomic =		1,		\
	.dev_done_atomic =	1,		\
	.exec_atomic =		1,		\
	.attach =		tape_attach,	\
	.detach =		tape_detach,	\
	.parse =		tape_parse,	\
	.dev_done =		tape_done,	\
}

#define TAPE_PERF_TYPE {			\
	.name =			TAPE_PERF_NAME,	\
	.type =			TYPE_TAPE,	\
	.parse_atomic =		1,		\
	.dev_done_atomic =	1,		\
	.exec_atomic =		1,		\
	.attach =		tape_attach,	\
	.detach =		tape_detach,	\
	.parse =		tape_parse,	\
	.dev_done =		tape_done,	\
	.exec =			tape_exec,	\
}

#define TAPE_RETRIES        2

#define TAPE_SMALL_TIMEOUT  (3 * HZ)
#define TAPE_REG_TIMEOUT    (900 * HZ)
#define TAPE_LONG_TIMEOUT   (14000 * HZ)

#define TAPE_DEF_BLOCK_SIZE	512

/* The fixed bit in READ/WRITE/VERIFY */
#define SILI_BIT            2

struct tape_params
{
	int block_size;
};

int tape_attach(struct scst_device *);
void tape_detach(struct scst_device *);
int tape_parse(struct scst_cmd *);
int tape_done(struct scst_cmd *);
int tape_exec(struct scst_cmd *);

static struct scst_dev_type tape_devtype = TAPE_TYPE;
static struct scst_dev_type tape_devtype_perf = TAPE_PERF_TYPE;

static int __init init_scst_tape_driver(void)
{
	int res = 0;

	TRACE_ENTRY();

	tape_devtype.module = THIS_MODULE;

	res = scst_register_dev_driver(&tape_devtype);
	if (res < 0)
		goto out;

	res = scst_dev_handler_build_std_proc(&tape_devtype);
	if (res != 0)
		goto out_unreg1;

	tape_devtype_perf.module = THIS_MODULE;

	res = scst_register_dev_driver(&tape_devtype_perf);
	if (res < 0)
		goto out_unreg1_err1;

	res = scst_dev_handler_build_std_proc(&tape_devtype_perf);
	if (res != 0)
		goto out_unreg2;

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg2:
	scst_dev_handler_destroy_std_proc(&tape_devtype_perf);

out_unreg1_err1:
	scst_dev_handler_destroy_std_proc(&tape_devtype);

out_unreg1:
	scst_unregister_dev_driver(&tape_devtype);
	goto out;
}

static void __exit exit_scst_tape_driver(void)
{
	TRACE_ENTRY();
	scst_dev_handler_destroy_std_proc(&tape_devtype_perf);
	scst_unregister_dev_driver(&tape_devtype_perf);
	scst_dev_handler_destroy_std_proc(&tape_devtype);
	scst_unregister_dev_driver(&tape_devtype);
	TRACE_EXIT();
	return;
}

module_init(init_scst_tape_driver);
module_exit(exit_scst_tape_driver);

/**************************************************************
 *  Function:  tape_attach
 *
 *  Argument:
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:
 *************************************************************/
int tape_attach(struct scst_device *dev)
{
	int res = 0;
	int retries;
	struct scsi_mode_data data;
	const int buffer_size = 512;
	uint8_t *buffer = NULL;
	struct tape_params *params;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->handler->type) {
		PRINT_ERROR("%s", "SCSI device not define or illegal type");
		res = -ENODEV;
		goto out;
	}

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (params == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Unable to allocate struct tape_params");
		res = -ENOMEM;
		goto out;
	}

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Memory allocation failure");
		res = -ENOMEM;
		goto out_free_req;
	}

	retries = SCST_DEV_UA_RETRIES;
	do {
		TRACE_DBG("%s", "Doing TEST_UNIT_READY");
		res = scsi_test_unit_ready(dev->scsi_dev, TAPE_SMALL_TIMEOUT,
					   TAPE_RETRIES
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
					  );
#else
					  , NULL);
#endif
		TRACE_DBG("TEST_UNIT_READY done: %x", res);
	} while ((--retries > 0) && res);
	if (res) {
		res = -ENODEV;
		goto out;
	}

	TRACE_DBG("%s", "Doing MODE_SENSE");
	res = scsi_mode_sense(dev->scsi_dev,
			      ((dev->scsi_dev->scsi_level <= SCSI_2) ?
			       ((dev->scsi_dev->lun << 5) & 0xe0) : 0),
			      0 /* Mode Page 0 */,
			      buffer, buffer_size,
			      TAPE_SMALL_TIMEOUT, TAPE_RETRIES,
			      &data, NULL);
	TRACE_DBG("MODE_SENSE done: %x", res);

	if (res == 0) {
		int medium_type, mode, speed, density;
		if (buffer[3] == 8) {
			params->block_size = ((buffer[9] << 16) |
					    (buffer[10] << 8) |
					    (buffer[11] << 0));
		} else {
			params->block_size = TAPE_DEF_BLOCK_SIZE;
		}
		medium_type = buffer[1];
		mode = (buffer[2] & 0x70) >> 4;
		speed = buffer[2] & 0x0f;
		density = buffer[4];
		TRACE_DBG("Tape: lun %d. bs %d. type 0x%02x mode 0x%02x "
		      "speed 0x%02x dens 0x%02x", dev->scsi_dev->lun,
		      params->block_size, medium_type, mode, speed, density);
	} else {
		res = -ENODEV;
		goto out_free_buf;
	}

	res = scst_obtain_device_parameters(dev);
	if (res != 0) {
		PRINT_ERROR("Failed to obtain control parameters for device "
			"%d:%d:%d:%d", dev->scsi_dev->host->host_no,
			dev->scsi_dev->channel, dev->scsi_dev->id,
			dev->scsi_dev->lun);
		goto out_free_buf;
	}

out_free_buf:
	kfree(buffer);

out_free_req:
	if (res == 0)
		dev->dh_priv = params;
	else
		kfree(params);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/************************************************************
 *  Function:  tape_detach
 *
 *  Argument:
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
void tape_detach(struct scst_device *dev)
{
	struct tape_params *params =
		(struct tape_params *)dev->dh_priv;

	TRACE_ENTRY();

	kfree(params);
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static int tape_get_block_size(struct scst_cmd *cmd)
{
	struct tape_params *params = (struct tape_params *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be called,
	 * when there are existing commands.
	 */
	return params->block_size;
}

/********************************************************************
 *  Function:  tape_parse
 *
 *  Argument:
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
int tape_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	scst_tape_generic_parse(cmd, tape_get_block_size);

	cmd->retries = SCST_PASSTHROUGH_RETRIES;

	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = TAPE_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = TAPE_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = TAPE_LONG_TIMEOUT;

	return res;
}

static void tape_set_block_size(struct scst_cmd *cmd, int block_size)
{
	struct tape_params *params = (struct tape_params *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be called, when
	 * there are existing commands.
	 */
	params->block_size = block_size;
	return;
}

/********************************************************************
 *  Function:  tape_done
 *
 *  Argument:
 *
 *  Returns :
 *
 *  Description:  This is the completion routine for the command,
 *                it is used to extract any necessary information
 *                about a command.
 ********************************************************************/
int tape_done(struct scst_cmd *cmd)
{
	int opcode = cmd->cdb[0];
	int status = cmd->status;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	if ((status == SAM_STAT_GOOD) || (status == SAM_STAT_CONDITION_MET)) {
		res = scst_tape_generic_dev_done(cmd, tape_set_block_size);
	} else if ((status == SAM_STAT_CHECK_CONDITION) &&
		   SCST_SENSE_VALID(cmd->sense))
	{
		struct tape_params *params;
		TRACE_DBG("%s", "Extended sense");
		if (opcode == READ_6 && !(cmd->cdb[1] & SILI_BIT) &&
		    (cmd->sense[2] & 0xe0)) {	/* EOF, EOM, or ILI */
			int TransferLength, Residue = 0;
			if ((cmd->sense[2] & 0x0f) == BLANK_CHECK) {
				cmd->sense[2] &= 0xcf;	/* No need for EOM in this case */
			}
			TransferLength = ((cmd->cdb[2] << 16) |
					  (cmd->cdb[3] << 8) | cmd->cdb[4]);
			/* Compute the residual count */
			if ((cmd->sense[0] & 0x80) != 0) {
				Residue = ((cmd->sense[3] << 24) |
					   (cmd->sense[4] << 16) |
					   (cmd->sense[5] << 8) |
					   cmd->sense[6]);
			}
			TRACE_DBG("Checking the sense key "
			      "sn[2]=%x cmd->cdb[0,1]=%x,%x TransLen/Resid %d/%d",
			      (int) cmd->sense[2], cmd->cdb[0], cmd->cdb[1],
			      TransferLength, Residue);
			if (TransferLength > Residue) {
				int resp_data_len = TransferLength - Residue;
				if (cmd->cdb[1] & SCST_TRANSFER_LEN_TYPE_FIXED) {
					/*
					 * No need for locks here, since
					 * *_detach() can not be called, when
					 * there are existing commands.
					 */
					params = (struct tape_params *)cmd->dev->dh_priv;
					resp_data_len *= params->block_size;
				}
				scst_set_resp_data_len(cmd, resp_data_len);
			}
		}
	}

	TRACE_DBG("cmd->is_send_status=%x, cmd->resp_data_len=%d, "
	      "res=%d", cmd->is_send_status, cmd->resp_data_len, res);

	TRACE_EXIT_RES(res);
	return res;
}

/********************************************************************
 *  Function:  tape_exec
 *
 *  Argument:
 *
 *  Returns :
 *
 *  Description:  Make SCST do nothing for data READs and WRITES.
 *                Intended for raw line performance testing
 ********************************************************************/
int tape_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED, rc;
	int opcode = cmd->cdb[0];

	TRACE_ENTRY();

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

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
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;
}

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI tape (type 1) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
