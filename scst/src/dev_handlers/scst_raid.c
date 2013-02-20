/*
 *  scst_raid.c
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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
#include <linux/slab.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_dev_handler.h"

#define RAID_NAME	"dev_raid"

#define RAID_RETRIES		2

static int raid_attach(struct scst_device *);
/* static void raid_detach(struct scst_device *); */
static int raid_parse(struct scst_cmd *);
/* static int raid_done(struct scst_cmd *); */

static struct scst_dev_type raid_devtype = {
	.name =			RAID_NAME,
	.type =			TYPE_RAID,
	.threads_num =		1,
	.parse_atomic =		1,
/*	.dev_done_atomic =	1,*/
	.attach =		raid_attach,
/*	.detach =		raid_detach,*/
	.parse =		raid_parse,
/*	.dev_done =		raid_done,*/
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
#endif
};

static int raid_attach(struct scst_device *dev)
{
	int res, rc;
	int retries;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->type) {
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

	retries = SCST_DEV_RETRIES_ON_UA;
	do {
		TRACE_DBG("%s", "Doing TEST_UNIT_READY");
		rc = scsi_test_unit_ready(dev->scsi_dev,
			SCST_GENERIC_RAID_TIMEOUT, RAID_RETRIES
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
	}

	res = scst_obtain_device_parameters(dev, NULL);
	if (res != 0) {
		PRINT_ERROR("Failed to obtain control parameters for device "
			"%s", dev->virt_name);
		goto out;
	}

out:
	TRACE_EXIT();
	return res;
}

#if 0
void raid_detach(struct scst_device *dev)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return;
}
#endif

static int raid_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT, rc;

	rc = scst_raid_generic_parse(cmd);
	if (rc != 0) {
		res = scst_get_cmd_abnormal_done_state(cmd);
		goto out;
	}

	cmd->retries = SCST_PASSTHROUGH_RETRIES;
out:
	return res;
}

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

#ifdef CONFIG_SCST_PROC
	res = scst_dev_handler_build_std_proc(&raid_devtype);
	if (res != 0)
		goto out_err;
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

#ifdef CONFIG_SCST_PROC
out_err:
	scst_unregister_dev_driver(&raid_devtype);
	goto out;
#endif
}

static void __exit raid_exit(void)
{
	TRACE_ENTRY();
#ifdef CONFIG_SCST_PROC
	scst_dev_handler_destroy_std_proc(&raid_devtype);
#endif
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
