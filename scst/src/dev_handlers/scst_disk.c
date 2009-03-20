/*
 *  scst_disk.c
 *
 *  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
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
#include <scsi/scsi_host.h>

#define LOG_PREFIX           "dev_disk"

#include "scst.h"
#include "scst_dev_handler.h"

# define DISK_NAME           "dev_disk"
# define DISK_PERF_NAME      "dev_disk_perf"

#define DISK_TYPE {          				\
	.name =			DISK_NAME,		\
	.type =			TYPE_DISK,		\
	.parse_atomic =		1,       		\
	.dev_done_atomic =	1,       		\
	.exec_atomic =		1,       		\
	.attach =		disk_attach,		\
	.detach =		disk_detach,		\
	.parse =		disk_parse,		\
	.dev_done =		disk_done,		\
}

#define DISK_PERF_TYPE {     				\
	.name =			DISK_PERF_NAME,		\
	.type =			TYPE_DISK,		\
	.parse_atomic =		1,       		\
	.dev_done_atomic =	1,       		\
	.exec_atomic =		1,       		\
	.attach =		disk_attach,		\
	.detach =		disk_detach,		\
	.parse =		disk_parse,		\
	.dev_done =		disk_done,		\
	.exec =			disk_exec,		\
}

#define DISK_DEF_BLOCK_SHIFT	9

struct disk_params {
	int block_shift;
};

static int disk_attach(struct scst_device *dev);
static void disk_detach(struct scst_device *dev);
static int disk_parse(struct scst_cmd *cmd);
static int disk_done(struct scst_cmd *cmd);
static int disk_exec(struct scst_cmd *cmd);

static struct scst_dev_type disk_devtype = DISK_TYPE;
static struct scst_dev_type disk_devtype_perf = DISK_PERF_TYPE;

static int __init init_scst_disk_driver(void)
{
	int res = 0;

	TRACE_ENTRY();

	disk_devtype.module = THIS_MODULE;

	res = scst_register_dev_driver(&disk_devtype);
	if (res < 0)
		goto out;

	res = scst_dev_handler_build_std_proc(&disk_devtype);
	if (res != 0)
		goto out_unreg1;

	disk_devtype_perf.module = THIS_MODULE;

	res = scst_register_dev_driver(&disk_devtype_perf);
	if (res < 0)
		goto out_unreg1_err1;

	res = scst_dev_handler_build_std_proc(&disk_devtype_perf);
	if (res != 0)
		goto out_unreg2;

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg2:
	scst_dev_handler_destroy_std_proc(&disk_devtype_perf);

out_unreg1_err1:
	scst_dev_handler_destroy_std_proc(&disk_devtype);

out_unreg1:
	scst_unregister_dev_driver(&disk_devtype);
	goto out;
}

static void __exit exit_scst_disk_driver(void)
{
	TRACE_ENTRY();
	scst_dev_handler_destroy_std_proc(&disk_devtype_perf);
	scst_unregister_dev_driver(&disk_devtype_perf);
	scst_dev_handler_destroy_std_proc(&disk_devtype);
	scst_unregister_dev_driver(&disk_devtype);
	TRACE_EXIT();
	return;
}

module_init(init_scst_disk_driver);
module_exit(exit_scst_disk_driver);

/**************************************************************
 *  Function:  disk_attach
 *
 *  Argument:
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:
 *************************************************************/
static int disk_attach(struct scst_device *dev)
{
	int res = 0;
	uint8_t cmd[10];
	const int buffer_size = 512;
	uint8_t *buffer = NULL;
	int retries;
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
	enum dma_data_direction data_dir;
	struct disk_params *params;

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
		      "Unable to allocate struct disk_params");
		res = -ENOMEM;
		goto out;
	}

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Memory allocation failure");
		res = -ENOMEM;
		goto out_free_params;
	}

	/* Clear any existing UA's and get disk capacity (disk block size) */
	memset(cmd, 0, sizeof(cmd));
	cmd[0] = READ_CAPACITY;
	cmd[1] = (dev->scsi_dev->scsi_level <= SCSI_2) ?
	    ((dev->scsi_dev->lun << 5) & 0xe0) : 0;
	retries = SCST_DEV_UA_RETRIES;
	while (1) {
		memset(buffer, 0, buffer_size);
		data_dir = SCST_DATA_READ;

		TRACE_DBG("%s", "Doing READ_CAPACITY");
		res = scsi_execute(dev->scsi_dev, cmd, data_dir, buffer,
				   buffer_size, sense_buffer,
				   SCST_GENERIC_DISK_REG_TIMEOUT, 3, 0);

		TRACE_DBG("READ_CAPACITY done: %x", res);

		if ((res == 0) || !scst_analyze_sense(sense_buffer,
				sizeof(sense_buffer), SCST_SENSE_ALL_VALID,
				SCST_LOAD_SENSE(scst_sense_medium_changed_UA)) ||
		    !scst_analyze_sense(sense_buffer, sizeof(sense_buffer),
		    		SCST_SENSE_KEY_VALID | SCST_SENSE_ASC_VALID,
				UNIT_ATTENTION, 0x29, 0))
			break;
		if (!--retries) {
			PRINT_ERROR("UA not clear after %d retries",
				SCST_DEV_UA_RETRIES);
			res = -ENODEV;
			goto out_free_buf;
		}
	}
	if (res == 0) {
		int sector_size = ((buffer[4] << 24) | (buffer[5] << 16) |
				     (buffer[6] << 8) | (buffer[7] << 0));
		if (sector_size == 0)
			params->block_shift = DISK_DEF_BLOCK_SHIFT;
		else
			params->block_shift =
				scst_calc_block_shift(sector_size);
	} else {
		TRACE_BUFFER("Sense set", sense_buffer, sizeof(sense_buffer));
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

out_free_params:
	if (res == 0)
		dev->dh_priv = params;
	else
		kfree(params);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/************************************************************
 *  Function:  disk_detach
 *
 *  Argument:
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
static void disk_detach(struct scst_device *dev)
{
	struct disk_params *params =
		(struct disk_params *)dev->dh_priv;

	TRACE_ENTRY();

	kfree(params);
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static int disk_get_block_shift(struct scst_cmd *cmd)
{
	struct disk_params *params = (struct disk_params *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	return params->block_shift;
}

/********************************************************************
 *  Function:  disk_parse
 *
 *  Argument:
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int disk_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	scst_sbc_generic_parse(cmd, disk_get_block_shift);

	cmd->retries = SCST_PASSTHROUGH_RETRIES;

	return res;
}

static void disk_set_block_shift(struct scst_cmd *cmd, int block_shift)
{
	struct disk_params *params = (struct disk_params *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	if (block_shift != 0)
		params->block_shift = block_shift;
	else
		params->block_shift = DISK_DEF_BLOCK_SHIFT;
	return;
}

/********************************************************************
 *  Function:  disk_done
 *
 *  Argument:
 *
 *  Returns :
 *
 *  Description:  This is the completion routine for the command,
 *                it is used to extract any necessary information
 *                about a command.
 ********************************************************************/
static int disk_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	res = scst_block_generic_dev_done(cmd, disk_set_block_shift);

	TRACE_EXIT_RES(res);
	return res;
}

/********************************************************************
 *  Function:  disk_exec
 *
 *  Argument:
 *
 *  Returns :
 *
 *  Description:  Make SCST do nothing for data READs and WRITES.
 *                Intended for raw line performance testing
 ********************************************************************/
static int disk_exec(struct scst_cmd *cmd)
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
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
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
MODULE_DESCRIPTION("SCSI disk (type 0) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
