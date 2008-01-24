/*
 *  scst_processor.c
 *  
 *  Copyright (C) 2004-2007 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
 *
 *  SCSI medium processor (type 3) dev handler
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

#include <scsi/scsi_host.h>

#define LOG_PREFIX "dev_processor"

#include "scsi_tgt.h"
#include "scst_dev_handler.h"

#define PROCESSOR_NAME	"dev_processor"

#define PROCESSOR_TYPE {	\
  name:     PROCESSOR_NAME,   	\
  type:     TYPE_PROCESSOR,	\
  parse_atomic:     1,      	\
/*  dev_done_atomic:  1,*/		\
  attach:   processor_attach, 	\
/*  detach:   processor_detach,*/ \
  parse:    processor_parse,  	\
/*  dev_done: processor_done*/	\
}

#define PROCESSOR_RETRIES       2
#define PROCESSOR_TIMEOUT      (3 * HZ)
#define PROCESSOR_LONG_TIMEOUT (14000 * HZ)
#define READ_CAP_LEN          8

int processor_attach(struct scst_device *);
void processor_detach(struct scst_device *);
int processor_parse(struct scst_cmd *);
int processor_done(struct scst_cmd *);

static struct scst_dev_type processor_devtype = PROCESSOR_TYPE;

/**************************************************************
 *  Function:  processor_attach
 *
 *  Argument:  
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:  
 *************************************************************/
int processor_attach(struct scst_device *dev)
{
	int res = 0;
	int retries;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->handler->type) {
		PRINT_ERROR("%s", "SCSI device not define or illegal type");
		res = -ENODEV;
		goto out;
	}

	/*
	 * If the device is offline, don't try to read capacity or any
	 * of the other stuff
	 */
	if (dev->scsi_dev->sdev_state == SDEV_OFFLINE)
	{
		TRACE_DBG("%s", "Device is offline");
		res = -ENODEV;
		goto out;
	}

	retries = SCST_DEV_UA_RETRIES;
	do {
		TRACE_DBG("%s", "Doing TEST_UNIT_READY");
		res = scsi_test_unit_ready(dev->scsi_dev, PROCESSOR_TIMEOUT, 
					   PROCESSOR_RETRIES);
		TRACE_DBG("TEST_UNIT_READY done: %x", res);
	} while ((--retries > 0) && res);
	if (res) {
		res = -ENODEV;
		goto out;
	}

	res = scst_obtain_device_parameters(dev);
	if (res != 0) {
		PRINT_ERROR("Failed to obtain control parameters for device "
			"%d:%d:%d:%d", dev->scsi_dev->host->host_no,
			dev->scsi_dev->channel, dev->scsi_dev->id,
			dev->scsi_dev->lun);
		goto out;
	}

out:
	TRACE_EXIT();
	return res;
}

/************************************************************
 *  Function:  processor_detach
 *
 *  Argument: 
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
void processor_detach(struct scst_device *dev)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return;
}

/********************************************************************
 *  Function:  processor_parse
 *
 *  Argument:  
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
int processor_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	scst_processor_generic_parse(cmd, 0);

	cmd->retries = SCST_PASSTHROUGH_RETRIES;

	if (cmd->op_flags & SCST_LONG_TIMEOUT) {
		cmd->timeout = PROCESSOR_LONG_TIMEOUT;
	} else {
		cmd->timeout = PROCESSOR_TIMEOUT;
	}
	return res;
}

/********************************************************************
 *  Function:  processor_done
 *
 *  Argument:  
 *
 *  Returns :  
 *
 *  Description:  This is the completion routine for the command,
 *                it is used to extract any necessary information
 *                about a command. 
 ********************************************************************/
int processor_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->tgt_resp_flags and cmd->resp_data_len
	 * based on cmd->status and cmd->data_direction, therefore change
	 * them only if necessary
	 */

#if 0
	switch (cmd->cdb[0]) {
	default:
		/* It's all good */
		break;
	}
#endif

	TRACE_EXIT();
	return res;
}

static int __init processor_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	processor_devtype.module = THIS_MODULE;
	if (scst_register_dev_driver(&processor_devtype) < 0) {
		res = -ENODEV;
		goto out;
	}
	
	res = scst_dev_handler_build_std_proc(&processor_devtype);
	if (res != 0)
		goto out_err;

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	scst_unregister_dev_driver(&processor_devtype);
	goto out;
}

static void __exit processor_exit(void)
{
	TRACE_ENTRY();
	scst_dev_handler_destroy_std_proc(&processor_devtype);
	scst_unregister_dev_driver(&processor_devtype);
	TRACE_EXIT();
	return;
}

module_init(processor_init);
module_exit(processor_exit);

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI medium processor (type 3) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
