/*
 *  scst_raid.c
 *
 *  Copyright (C) 2004 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
 *
 *  SCSI raid(controller) (type 0xC) dev handler
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

#define LOG_PREFIX      "dev_raid"

#include <scsi/scsi_host.h>

#include "scst.h"
#include "scst_dev_handler.h"

#define RAID_NAME	"dev_raid"

#define RAID_TYPE {				\
	.name =			RAID_NAME,	\
	.type =			TYPE_RAID,	\
	.parse_atomic =		1,		\
/*	.dev_done_atomic =	1,*/		\
	.attach =		raid_attach,	\
/*	.detach =		raid_detach,*/	\
	.parse =		raid_parse,	\
/*	.dev_done =		raid_done*/	\
}

#define RAID_RETRIES       2
#define READ_CAP_LEN          8

static int raid_attach(struct scst_device *);
/* static void raid_detach(struct scst_device *); */
static int raid_parse(struct scst_cmd *);
/* static int raid_done(struct scst_cmd *); */

static struct scst_dev_type raid_devtype = RAID_TYPE;

/**************************************************************
 *  Function:  raid_attach
 *
 *  Argument:
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:
 *************************************************************/
static int raid_attach(struct scst_device *dev)
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
	if (dev->scsi_dev->sdev_state == SDEV_OFFLINE) {
		TRACE_DBG("%s", "Device is offline");
		res = -ENODEV;
		goto out;
	}

	retries = SCST_DEV_UA_RETRIES;
	do {
		TRACE_DBG("%s", "Doing TEST_UNIT_READY");
		res = scsi_test_unit_ready(dev->scsi_dev,
			SCST_GENERIC_RAID_TIMEOUT, RAID_RETRIES
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
 *  Function:  raid_detach
 *
 *  Argument:
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
#if 0
void raid_detach(struct scst_device *dev)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return;
}
#endif

/********************************************************************
 *  Function:  raid_parse
 *
 *  Argument:
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int raid_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	scst_raid_generic_parse(cmd, NULL);

	cmd->retries = SCST_PASSTHROUGH_RETRIES;

	return res;
}

/********************************************************************
 *  Function:  raid_done
 *
 *  Argument:
 *
 *  Returns :
 *
 *  Description:  This is the completion routine for the command,
 *                it is used to extract any necessary information
 *                about a command.
 ********************************************************************/
#if 0
int raid_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->is_send_status and
	 * cmd->resp_data_len based on cmd->status and cmd->data_direction,
	 * therefore change them only if necessary.
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
#endif

static int __init raid_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	raid_devtype.module = THIS_MODULE;

	res = scst_register_dev_driver(&raid_devtype);
	if (res < 0)
		goto out;

	res = scst_dev_handler_build_std_proc(&raid_devtype);
	if (res != 0)
		goto out_err;

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	scst_unregister_dev_driver(&raid_devtype);
	goto out;
}

static void __exit raid_exit(void)
{
	TRACE_ENTRY();
	scst_dev_handler_destroy_std_proc(&raid_devtype);
	scst_unregister_dev_driver(&raid_devtype);
	TRACE_EXIT();
	return;
}

module_init(raid_init);
module_exit(raid_exit);

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI raid(controller) (type 0xC) dev handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
