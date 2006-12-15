/*
 *  scst_cdrom.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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

#define LOG_PREFIX	"dev_cdrom"

#include "scsi_tgt.h"
#include "scst_dev_handler.h"

#define CDROM_NAME	"dev_cdrom"

#define CDROM_TYPE {          \
  name:     CDROM_NAME,       \
  type:     TYPE_ROM,         \
  parse_atomic:     1,        \
  dev_done_atomic:  1,        \
  attach:   cdrom_attach,     \
  detach:   cdrom_detach,     \
  parse:    cdrom_parse,      \
  dev_done: cdrom_done,       \
}

#define CDROM_RETRIES  2
#define CDROM_SMALL_TIMEOUT  (3 * HZ)
#define CDROM_REG_TIMEOUT    (900 * HZ)
#define CDROM_LONG_TIMEOUT   (14000 * HZ)
#define READ_CAP_LEN   8

/* Flags */
#define BYTCHK         0x02

struct cdrom_params
{
	int sector_size;
};

int cdrom_attach(struct scst_device *);
void cdrom_detach(struct scst_device *);
int cdrom_parse(struct scst_cmd *, const struct scst_info_cdb *);
int cdrom_done(struct scst_cmd *);

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
int cdrom_attach(struct scst_device *dev)
{
	int res = 0;
	uint8_t cmd[10];
	const int buffer_size = 512;
	uint8_t *buffer = NULL;
	int retries;
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
	enum dma_data_direction data_dir;
	unsigned char *sbuff;
	struct cdrom_params *cdrom;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->handler->type) {
		PRINT_ERROR_PR("%s", "SCSI device not define or illegal type");
		res = -ENODEV;
		goto out;
	}

	cdrom = kzalloc(sizeof(*cdrom), GFP_KERNEL);
	if (cdrom == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Unable to allocate struct cdrom_params");
		res = -ENOMEM;
		goto out;
	}

	buffer = kzalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Memory allocation failure");
		res = -ENOMEM;
		goto out_free_cdrom;
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
		sbuff = sense_buffer;

		TRACE_DBG("%s", "Doing READ_CAPACITY");
		res = scsi_execute(dev->scsi_dev, cmd, data_dir, buffer, 
				   buffer_size, sbuff, 
				   CDROM_REG_TIMEOUT, CDROM_RETRIES, 0);

		TRACE_DBG("READ_CAPACITY done: %x", res);

		if (!res || (sbuff[12] != 0x28 && sbuff[12] != 0x29))
		{
			break;
		}
		if (!--retries) {
			PRINT_ERROR_PR("UA not clear after %d retries",
				SCST_DEV_UA_RETRIES);
			cdrom->sector_size = 2048;
//			res = -ENODEV;
			goto out_free_buf;
		}
	}
	if (res == 0) {
		cdrom->sector_size = ((buffer[4] << 24) | (buffer[5] << 16) |
				      (buffer[6] << 8) | (buffer[7] << 0));
		TRACE_DBG("Sector size is %i scsi_level %d(SCSI_2 %d)",
			cdrom->sector_size, dev->scsi_dev->scsi_level, SCSI_2);
		if (!cdrom->sector_size) {
			cdrom->sector_size = 2048;
		}
	} else {
		TRACE_BUFFER("Sense set", sbuff, SCSI_SENSE_BUFFERSIZE);
		cdrom->sector_size = 2048;
//		res = -ENODEV;
		goto out_free_buf;
	}

out_free_buf:
	kfree(buffer);

out_free_cdrom:
	if (res == 0)
		dev->dh_priv = cdrom;
	else
		kfree(cdrom);

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
void cdrom_detach(struct scst_device *dev)
{
	struct cdrom_params *cdrom = (struct cdrom_params *)dev->dh_priv;

	TRACE_ENTRY();

	kfree(cdrom);
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
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
int cdrom_parse(struct scst_cmd *cmd, const struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;
	struct cdrom_params *cdrom;
	int fixed;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen
	 * based on info_cdb, therefore change them only if necessary
	 */

	if (info_cdb->flags & SCST_SMALL_TIMEOUT) {
		cmd->timeout = CDROM_SMALL_TIMEOUT;
	} else if (info_cdb->flags & SCST_LONG_TIMEOUT) {
		cmd->timeout = CDROM_LONG_TIMEOUT;
	} else {
		cmd->timeout = CDROM_REG_TIMEOUT;
	}

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d lun %d(%d)",
	      info_cdb->op_name,
	      info_cdb->direction,
	      info_cdb->flags,
	      info_cdb->transfer_len, cmd->lun, (cmd->cdb[1] >> 5) & 7);

	cmd->cdb[1] &= 0x1f;

	fixed = info_cdb->flags & SCST_TRANSFER_LEN_TYPE_FIXED;
	switch (cmd->cdb[0]) {
	case READ_CAPACITY:
		cmd->bufflen = READ_CAP_LEN;
		cmd->data_direction = SCST_DATA_READ;
		break;
	case GPCMD_SET_STREAMING:
		cmd->bufflen = (((*(cmd->cdb + 9)) & 0xff) << 8) +
		    ((*(cmd->cdb + 10)) & 0xff);
		cmd->bufflen &= 0xffff;
		break;
	case GPCMD_READ_CD:
		cmd->bufflen = cmd->bufflen >> 8;
		break;
#if 0
	case SYNCHRONIZE_CACHE:
		cmd->underflow = 0;
		break;
#endif
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->bufflen = 0;
			cmd->data_direction = SCST_DATA_NONE;
			fixed = 0;
		}
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
		cdrom = (struct cdrom_params *)cmd->dev->dh_priv;
		cmd->bufflen = info_cdb->transfer_len * cdrom->sector_size;
	}

	TRACE_DBG("res %d bufflen %zd direct %d",
	      res, cmd->bufflen, cmd->data_direction);

	TRACE_EXIT();
	return res;
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
int cdrom_done(struct scst_cmd *cmd)
{
	int opcode = cmd->cdb[0];
	int masked_status = cmd->masked_status;
	struct cdrom_params *cdrom;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	if (unlikely(cmd->sg == NULL))
		goto out;

	/*
	 * SCST sets good defaults for cmd->tgt_resp_flags and cmd->resp_data_len
	 * based on cmd->masked_status and cmd->data_direction, therefore change
	 * them only if necessary
	 */

	if ((masked_status == GOOD) || (masked_status == CONDITION_GOOD)) {
		switch (opcode) {
		case READ_CAPACITY:
		{
			/* Always keep track of cdrom capacity */
			int buffer_size;
			/* 
			 * To force the compiler not to optimize it out to keep
			 * cdrom->sector_size access atomic
			 */
			volatile int sector_size; 
			uint8_t *buffer;
			buffer_size = scst_get_buf_first(cmd, &buffer);
			if (unlikely(buffer_size <= 0)) {
				PRINT_ERROR_PR("%s: Unable to get the buffer",
					__FUNCTION__);
				scst_set_busy(cmd);
				goto out;
			}

			/* 
			 * No need for locks here, since *_detach() can not be
			 * called, when there are existing commands.
			 */
			cdrom = (struct cdrom_params *)cmd->dev->dh_priv;
			sector_size =
			    ((buffer[4] << 24) | (buffer[5] << 16) |
			     (buffer[6] << 8) | (buffer[7] << 0));
			if (!sector_size)
				sector_size = 2048;
			cdrom->sector_size = sector_size;
			TRACE_DBG("Sector size is %i", cdrom->sector_size);

			scst_put_buf(cmd, buffer);
			break;
		}
		default:
			/* It's all good */
			break;
		}
	}

	TRACE_DBG("cmd->tgt_resp_flags=%x, cmd->resp_data_len=%d, "
	      "res=%d", cmd->tgt_resp_flags, cmd->resp_data_len, res);

out:
	TRACE_EXIT();
	return res;
}

static int __init cdrom_init(void)
{
	int res = 0;

	TRACE_ENTRY();
	
	cdrom_devtype.module = THIS_MODULE;
	if (scst_register_dev_driver(&cdrom_devtype) < 0) {
		res = -ENODEV;
		goto out;
	}

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
