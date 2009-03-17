/*
 *  scst_cdrom.c
 *
 *  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
 *
 *  SCSI CDROM (type 5) dev handler
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

#include <linux/cdrom.h>
#include <scsi/scsi_host.h>

#define LOG_PREFIX	"dev_cdrom"

#include "scst.h"
#include "scst_dev_handler.h"

#define CDROM_NAME	"dev_cdrom"

#define CDROM_TYPE {				\
	.name = 		CDROM_NAME,	\
	.type =			TYPE_ROM,	\
	.parse_atomic =		1,		\
	.dev_done_atomic = 	1,		\
	.attach = 		cdrom_attach,	\
	.detach = 		cdrom_detach,	\
	.parse = 		cdrom_parse,	\
	.dev_done = 		cdrom_done,	\
}

#define CDROM_DEF_BLOCK_SHIFT	11

struct cdrom_params {
	int block_shift;
};

static int cdrom_attach(struct scst_device *);
static void cdrom_detach(struct scst_device *);
static int cdrom_parse(struct scst_cmd *);
static int cdrom_done(struct scst_cmd *);

static struct scst_dev_type cdrom_devtype = CDROM_TYPE;

/**************************************************************
 *  Function:  cdrom_attach
 *
 *  Argument:
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:
 *************************************************************/
static int cdrom_attach(struct scst_device *dev)
{
	int res = 0;
	uint8_t cmd[10];
	const int buffer_size = 512;
	uint8_t *buffer = NULL;
	int retries;
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
	enum dma_data_direction data_dir;
	struct cdrom_params *params;

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
		      "Unable to allocate struct cdrom_params");
		res = -ENOMEM;
		goto out;
	}

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Memory allocation failure");
		res = -ENOMEM;
		goto out_free_params;
	}

	/* Clear any existing UA's and get cdrom capacity (cdrom block size) */
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
				   SCST_GENERIC_CDROM_REG_TIMEOUT, 3, 0);

		TRACE_DBG("READ_CAPACITY done: %x", res);

		if ((res == 0) || (sense_buffer[2] != UNIT_ATTENTION))
			break;

		if (!--retries) {
			PRINT_ERROR("UA not cleared after %d retries",
				SCST_DEV_UA_RETRIES);
			params->block_shift = CDROM_DEF_BLOCK_SHIFT;
			goto out_free_buf;
		}
	}

	if (res == 0) {
		int sector_size = ((buffer[4] << 24) | (buffer[5] << 16) |
				      (buffer[6] << 8) | (buffer[7] << 0));
		if (sector_size == 0)
			params->block_shift = CDROM_DEF_BLOCK_SHIFT;
		else
			params->block_shift =
				scst_calc_block_shift(sector_size);
		TRACE_DBG("Sector size is %i scsi_level %d(SCSI_2 %d)",
			sector_size, dev->scsi_dev->scsi_level, SCSI_2);
	} else {
		TRACE_BUFFER("Sense set", sense_buffer, sizeof(sense_buffer));
		params->block_shift = CDROM_DEF_BLOCK_SHIFT;
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
	TRACE_EXIT();
	return res;
}

/************************************************************
 *  Function:  cdrom_detach
 *
 *  Argument:
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
static void cdrom_detach(struct scst_device *dev)
{
	struct cdrom_params *params =
		(struct cdrom_params *)dev->dh_priv;

	TRACE_ENTRY();

	kfree(params);
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static int cdrom_get_block_shift(struct scst_cmd *cmd)
{
	struct cdrom_params *params = (struct cdrom_params *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	return params->block_shift;
}

/********************************************************************
 *  Function:  cdrom_parse
 *
 *  Argument:
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int cdrom_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	scst_cdrom_generic_parse(cmd, cdrom_get_block_shift);

	cmd->retries = SCST_PASSTHROUGH_RETRIES;

	return res;
}

static void cdrom_set_block_shift(struct scst_cmd *cmd, int block_shift)
{
	struct cdrom_params *params = (struct cdrom_params *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	if (block_shift != 0)
		params->block_shift = block_shift;
	else
		params->block_shift = CDROM_DEF_BLOCK_SHIFT;
	return;
}

/********************************************************************
 *  Function:  cdrom_done
 *
 *  Argument:
 *
 *  Returns :
 *
 *  Description:  This is the completion routine for the command,
 *                it is used to extract any necessary information
 *                about a command.
 ********************************************************************/
static int cdrom_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	res = scst_block_generic_dev_done(cmd, cdrom_set_block_shift);

	TRACE_EXIT_RES(res);
	return res;
}

static int __init cdrom_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	cdrom_devtype.module = THIS_MODULE;

	res = scst_register_dev_driver(&cdrom_devtype);
	if (res < 0)
		goto out;

	res = scst_dev_handler_build_std_proc(&cdrom_devtype);
	if (res != 0)
		goto out_err;

out:
	TRACE_EXIT();
	return res;

out_err:
	scst_unregister_dev_driver(&cdrom_devtype);
	goto out;
}

static void __exit cdrom_exit(void)
{
	TRACE_ENTRY();
	scst_dev_handler_destroy_std_proc(&cdrom_devtype);
	scst_unregister_dev_driver(&cdrom_devtype);
	TRACE_EXIT();
	return;
}

module_init(cdrom_init);
module_exit(cdrom_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_DESCRIPTION("SCSI CDROM (type 5) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
