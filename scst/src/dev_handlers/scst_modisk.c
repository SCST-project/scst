/*
 *  scst_modisk.c
 *  
 *  Copyright (C) 2004-2007 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
 *
 *  SCSI MO disk (type 7) dev handler
 *  &
 *  SCSI MO disk (type 7) "performance" device handler (skip all READ and WRITE
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

#define LOG_PREFIX             "dev_modisk"

#include "scsi_tgt.h"
#include "scst_dev_handler.h"

# define MODISK_NAME           "dev_modisk"
# define MODISK_PERF_NAME      "dev_modisk_perf"

#define MODISK_TYPE {          \
  name:     MODISK_NAME,       \
  type:     TYPE_MOD,          \
  parse_atomic:     1,         \
  dev_done_atomic:  1,         \
  exec_atomic:      1,         \
  attach:   modisk_attach,     \
  detach:   modisk_detach,     \
  parse:    modisk_parse,      \
  dev_done: modisk_done,       \
}

#define MODISK_PERF_TYPE {     \
  name:     MODISK_PERF_NAME,  \
  type:     TYPE_MOD,          \
  parse_atomic:     1,         \
  dev_done_atomic:  1,         \
  exec_atomic:      1,         \
  attach:   modisk_attach,     \
  detach:   modisk_detach,     \
  parse:    modisk_parse,      \
  dev_done: modisk_done,       \
  exec:     modisk_exec,       \
}

#define MODISK_SMALL_TIMEOUT  (3 * HZ)
#define MODISK_REG_TIMEOUT    (900 * HZ)
#define MODISK_LONG_TIMEOUT   (14000 * HZ)

#define MODISK_DEF_BLOCK_SHIFT    10

struct modisk_params
{
	int block_shift;
};

int modisk_attach(struct scst_device *);
void modisk_detach(struct scst_device *);
int modisk_parse(struct scst_cmd *, struct scst_info_cdb *);
int modisk_done(struct scst_cmd *);
int modisk_exec(struct scst_cmd *);

static struct scst_dev_type modisk_devtype = MODISK_TYPE;
static struct scst_dev_type modisk_devtype_perf = MODISK_PERF_TYPE;

static int __init init_scst_modisk_driver(void)
{
	int res = 0;

	TRACE_ENTRY();

	modisk_devtype.module = THIS_MODULE;
	if (scst_register_dev_driver(&modisk_devtype) < 0) {
		res = -ENODEV;
		goto out;
	}

	res = scst_dev_handler_build_std_proc(&modisk_devtype);
	if (res != 0)
		goto out_unreg1;

	modisk_devtype_perf.module = THIS_MODULE;         
	if (scst_register_dev_driver(&modisk_devtype_perf) < 0) {
		res = -ENODEV;
		goto out_unreg1_err1;
	}

	res = scst_dev_handler_build_std_proc(&modisk_devtype_perf);
	if (res != 0)
	goto out_unreg2;

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg2:
	scst_dev_handler_destroy_std_proc(&modisk_devtype_perf);

out_unreg1_err1:
	scst_dev_handler_destroy_std_proc(&modisk_devtype);

out_unreg1:
	scst_unregister_dev_driver(&modisk_devtype);
	goto out;	
}

static void __exit exit_scst_modisk_driver(void)
{
	TRACE_ENTRY();
	scst_dev_handler_destroy_std_proc(&modisk_devtype_perf);
	scst_unregister_dev_driver(&modisk_devtype_perf);
	scst_dev_handler_destroy_std_proc(&modisk_devtype);
	scst_unregister_dev_driver(&modisk_devtype);
	TRACE_EXIT();
	return;
}

module_init(init_scst_modisk_driver);
module_exit(exit_scst_modisk_driver);

/**************************************************************
 *  Function:  modisk_attach
 *
 *  Argument:  
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:  
 *************************************************************/
int modisk_attach(struct scst_device *dev)
{
	int res = 0;
	uint8_t cmd[10];
	const int buffer_size = 512;
	uint8_t *buffer = NULL;
	int retries;
	unsigned char sense_buffer[SCST_SENSE_BUFFERSIZE];
	enum dma_data_direction data_dir;
	unsigned char *sbuff;
	struct modisk_params *params;

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
		      "Unable to allocate struct modisk_params");
		res = -ENOMEM;
		goto out;
	}
	params->block_shift = MODISK_DEF_BLOCK_SHIFT;

	/*
	 * If the device is offline, don't try to read capacity or any
	 * of the other stuff
	 */
	if (dev->scsi_dev->sdev_state == SDEV_OFFLINE)
	{
		TRACE_DBG("%s", "Device is offline");
		res = -ENODEV;
		goto out_free_params;
	}

	buffer = kzalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Memory allocation failure");
		res = -ENOMEM;
		goto out_free_params;
	}

	/* Clear any existing UA's and get modisk capacity (modisk block size) */
	memset(cmd, 0, sizeof(cmd));
	cmd[0] = READ_CAPACITY;
	cmd[1] = (dev->scsi_dev->scsi_level <= SCSI_2) ?
	    ((dev->scsi_dev->lun << 5) & 0xe0) : 0;
	retries = SCST_DEV_UA_RETRIES;
	while (1) {
		memset(buffer, 0, buffer_size);
		data_dir = SCST_DATA_READ;
		sbuff = sense_buffer;

		TRACE_DBG("%s", "Doing READ_CAPACITY");
		res = scsi_execute(dev->scsi_dev, cmd, data_dir, buffer, 
				   buffer_size, sbuff, 
				   MODISK_REG_TIMEOUT, 3, 0);

		TRACE_DBG("READ_CAPACITY done: %x", res);

		if (!res || (sbuff[2] != UNIT_ATTENTION)) 
		{
			break;
		}
		if (!--retries) {
			PRINT_ERROR("UA not clear after %d retries",
				    SCST_DEV_UA_RETRIES);
			goto out_free_buf;
		}
	}
	if (res == 0) {
		int sector_size = ((buffer[4] << 24) | (buffer[5] << 16) |
				       (buffer[6] << 8) | (buffer[7] << 0));
		if (sector_size == 0)
			params->block_shift = MODISK_DEF_BLOCK_SHIFT;
		else
			params->block_shift = scst_calc_block_shift(sector_size);
		TRACE_DBG("Sector size is %i scsi_level %d(SCSI_2 %d)",
		      sector_size, dev->scsi_dev->scsi_level, SCSI_2);
	} else {
		TRACE_BUFFER("Sense set", sbuff, SCST_SENSE_BUFFERSIZE);
			     
		if (sbuff[2] != NOT_READY)
			res = -ENODEV;
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
 *  Function:  modisk_detach
 *
 *  Argument: 
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
void modisk_detach(struct scst_device *dev)
{
	struct modisk_params *params =
		(struct modisk_params *)dev->dh_priv;

	TRACE_ENTRY();

	kfree(params);
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static int modisk_get_block_shift(struct scst_cmd *cmd)
{
	struct modisk_params *params = (struct modisk_params *)cmd->dev->dh_priv;
	/* 
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	return params->block_shift;
}

/********************************************************************
 *  Function:  modisk_parse
 *
 *  Argument:  
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
int modisk_parse(struct scst_cmd *cmd, struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;

	scst_modisk_generic_parse(cmd, info_cdb, modisk_get_block_shift);

	cmd->retries = 1;

	if (info_cdb->flags & SCST_SMALL_TIMEOUT) {
		cmd->timeout = MODISK_SMALL_TIMEOUT;
	} else if (info_cdb->flags & SCST_LONG_TIMEOUT) {
		cmd->timeout = MODISK_LONG_TIMEOUT;
	} else {
		cmd->timeout = MODISK_REG_TIMEOUT;
	}
	return res;
}

static void modisk_set_block_shift(struct scst_cmd *cmd, int block_shift)
{
	struct modisk_params *params = (struct modisk_params *)cmd->dev->dh_priv;
	/* 
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	if (block_shift != 0)
		params->block_shift = block_shift;
	else
		params->block_shift = MODISK_DEF_BLOCK_SHIFT;
	return;
}

/********************************************************************
 *  Function:  modisk_done
 *
 *  Argument:  
 *
 *  Returns :  
 *
 *  Description:  This is the completion routine for the command,
 *                it is used to extract any necessary information
 *                about a command. 
 ********************************************************************/
int modisk_done(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	res = scst_block_generic_dev_done(cmd, modisk_set_block_shift);

	TRACE_EXIT_RES(res);
	return res;
}

/********************************************************************
 *  Function:  modisk_exec
 *
 *  Argument:  
 *
 *  Returns :  
 *
 *  Description:  Make SCST do nothing for data READs and WRITES.
 *                Intended for raw line performance testing
 ********************************************************************/
int modisk_exec(struct scst_cmd *cmd)
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
		break;
	}

out_done:
	res = SCST_EXEC_COMPLETED;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);

	TRACE_EXIT_RES(res);
	return res;
}

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI MO disk (type 7) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
