/*
 *  scst_tape.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
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

#define LOG_PREFIX           "dev_tape"

#include "scsi_tgt.h"
#include "scst_dev_handler.h"

# define TAPE_NAME           "dev_tape"
# define TAPE_PERF_NAME      "dev_tape_perf"

#define TAPE_TYPE {         \
  name:     TAPE_NAME,	    \
  type:     TYPE_TAPE,      \
  parse_atomic:     1,      \
  dev_done_atomic:  1,      \
  exec_atomic:      1,      \
  attach:   tape_attach,    \
  detach:   tape_detach,    \
  parse:    tape_parse,     \
  dev_done: tape_done,      \
}

#define TAPE_PERF_TYPE {    \
  name:     TAPE_PERF_NAME, \
  type:     TYPE_TAPE,      \
  parse_atomic:     1,      \
  dev_done_atomic:  1,      \
  exec_atomic:      1,      \
  attach:   tape_attach,    \
  detach:   tape_detach,    \
  parse:    tape_parse,     \
  dev_done: tape_done,      \
  exec:     tape_exec,      \
}

#define TAPE_RETRIES        2

#define TAPE_SMALL_TIMEOUT  (3 * HZ)
#define TAPE_REG_TIMEOUT    (900 * HZ)
#define TAPE_LONG_TIMEOUT   (14000 * HZ)

/* The fixed bit in READ/WRITE/VERIFY */
#define SILI_BIT            2

/* Bits in the READ POSITION command */
#define TCLP_BIT            4
#define LONG_BIT            2
#define BT_BIT              1

#define POSITION_LEN_SHORT  20
#define POSITION_LEN_LONG   32

struct tape_params
{
	spinlock_t tp_lock;
	uint8_t density;
	uint8_t mode;
	uint8_t speed;
	uint8_t medium_type;
	int block_size;
};

int tape_attach(struct scst_device *);
void tape_detach(struct scst_device *);
int tape_parse(struct scst_cmd *, const struct scst_info_cdb *);
int tape_done(struct scst_cmd *);
int tape_exec(struct scst_cmd *);

static struct scst_dev_type tape_devtype = TAPE_TYPE;
static struct scst_dev_type tape_devtype_perf = TAPE_PERF_TYPE;

static int __init init_scst_tape_driver(void)
{
	int res = 0;

	TRACE_ENTRY();

	tape_devtype.module = THIS_MODULE;
	if (scst_register_dev_driver(&tape_devtype) < 0) {
		res = -ENODEV;
		goto out;
	}

	res = scst_dev_handler_build_std_proc(&tape_devtype);
	if (res != 0)
		goto out_unreg1;

	tape_devtype_perf.module = THIS_MODULE;
	if (scst_register_dev_driver(&tape_devtype_perf) < 0) {
		res = -ENODEV;
		goto out_unreg1_err1;
	}

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
	struct tape_params *tape;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->handler->type) {
		PRINT_ERROR_PR("%s", "SCSI device not define or illegal type");
		res = -ENODEV;
		goto out;
	}

	tape = kzalloc(sizeof(*tape), GFP_KERNEL);
	if (tape == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Unable to allocate struct tape_params");
		res = -ENOMEM;
		goto out;
	}
	spin_lock_init(&tape->tp_lock);

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
					   TAPE_RETRIES);
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
		if (buffer[3] == 8) {
			tape->block_size = ((buffer[9] << 16) |
					    (buffer[10] << 8) |
					    (buffer[11] << 0));
		} else {
			tape->block_size = 512;
		}
		tape->medium_type = buffer[1];
		tape->mode = (buffer[2] & 0x70) >> 4;
		tape->speed = buffer[2] & 0x0f;
		tape->density = buffer[4];
		TRACE_DBG("Tape: lun %d. bs %d. type 0x%02x mode 0x%02x "
		      "speed 0x%02x dens 0x%02x", dev->scsi_dev->lun,
		      tape->block_size, tape->medium_type,
		      tape->mode, tape->speed, tape->density);
	} else {
		res = -ENODEV;
		goto out_free_buf;
	}

out_free_buf:
	kfree(buffer);

out_free_req:
	if (res == 0)
		dev->dh_priv = tape;
	else
		kfree(tape);

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
	struct tape_params *tape = (struct tape_params *)dev->dh_priv;

	TRACE_ENTRY();

	kfree(tape);
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
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
int tape_parse(struct scst_cmd *cmd, const struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;
	struct tape_params *tape;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen
	 * based on info_cdb, therefore change them only if necessary
	 */

	cmd->retries = 1;

	if (info_cdb->flags & SCST_SMALL_TIMEOUT) {
		cmd->timeout = TAPE_SMALL_TIMEOUT;
	} else if (info_cdb->flags & SCST_LONG_TIMEOUT) {
		cmd->timeout = TAPE_LONG_TIMEOUT;
	} else {
		cmd->timeout = TAPE_REG_TIMEOUT;
	}

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      info_cdb->op_name,
	      info_cdb->direction, info_cdb->flags, info_cdb->transfer_len);

	if (cmd->cdb[0] == READ_POSITION) {
		int tclp = cmd->cdb[1] & TCLP_BIT;
		int long_bit = cmd->cdb[1] & LONG_BIT;
		int bt = cmd->cdb[1] & BT_BIT;

		if ((tclp == long_bit) && (!bt || !long_bit)) {
			cmd->bufflen =
			    tclp ? POSITION_LEN_LONG : POSITION_LEN_SHORT;
			cmd->data_direction = SCST_DATA_READ;
		} else {
			cmd->bufflen = 0;
			cmd->data_direction = SCST_DATA_NONE;
		}
	}

	if (info_cdb->flags & SCST_TRANSFER_LEN_TYPE_FIXED & cmd->cdb[1]) {
		/* 
		 * No need for locks here, since *_detach() can not be called,
		 * when there are existing commands.
		 */
		tape = (struct tape_params *)cmd->dev->dh_priv;
		cmd->bufflen = info_cdb->transfer_len * tape->block_size;
	}

	TRACE_EXIT_RES(res);
	return res;
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
	struct tape_params *tape;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	if (unlikely(cmd->sg == NULL))
		goto out;

	/*
	 * SCST sets good defaults for cmd->tgt_resp_flags and cmd->resp_data_len
	 * based on cmd->status and cmd->data_direction, therefore change
	 * them only if necessary
	 */

	if ((status == SAM_STAT_GOOD) || (status == SAM_STAT_CONDITION_MET)) {
		int buffer_size;
		uint8_t *buffer = NULL;
		
		switch (opcode) {
		case MODE_SENSE:
		case MODE_SELECT:
			buffer_size = scst_get_buf_first(cmd, &buffer);
			if (unlikely(buffer_size <= 0)) {
				PRINT_ERROR_PR("%s: Unable to get the buffer",
					__FUNCTION__);
				scst_set_busy(cmd);
				goto out;
			}
			break;
		}

		switch (opcode) {
		case MODE_SENSE:
			TRACE_DBG("%s", "MODE_SENSE");
			if ((cmd->cdb[2] & 0xC0) == 0) {
				/* 
				 * No need for locks here, since *_detach()
				 * can not be called, when there are 
				 * existing commands.
				 */
				tape = (struct tape_params *)cmd->dev->dh_priv;
				spin_lock_bh(&tape->tp_lock);
				if (buffer[3] == 8) {
					tape->block_size = (buffer[9] << 16) |
					    (buffer[10] << 8) | buffer[11];
				}
				tape->medium_type = buffer[1];
				tape->mode = (buffer[2] & 0x70) >> 4;
				tape->speed = buffer[2] & 0x0f;
				tape->density = buffer[4];
				spin_unlock_bh(&tape->tp_lock);
			}
			break;
		case MODE_SELECT:
			TRACE_DBG("%s", "MODE_SELECT");
			/* 
			 * No need for locks here, since *_detach() can not be
			 * called, when there are existing commands.
			 */
			tape = (struct tape_params *)cmd->dev->dh_priv;
			spin_lock_bh(&tape->tp_lock);
			if (buffer[3] == 8) {
				tape->block_size =
				    (buffer[9] << 16) | (buffer[10] << 8) |
				    (buffer[11]);
			}
			tape->medium_type = buffer[1];
			tape->mode = (buffer[2] & 0x70) >> 4;
			tape->speed = buffer[2] & 0x0f;
			if (buffer[4] != 0x7f)
				tape->density = buffer[4];
			spin_unlock_bh(&tape->tp_lock);
			break;
		default:
			/* It's all good */
			break;
		}
		
		switch (opcode) {
		case MODE_SENSE:
		case MODE_SELECT:
			scst_put_buf(cmd, buffer);
			break;
		}
	} 
	else if ((status == SAM_STAT_CHECK_CONDITION) && 
		   SCST_SENSE_VALID(cmd->sense_buffer)) 
	{
		TRACE_DBG("%s", "Extended sense");
		if (opcode == READ_6 && !(cmd->cdb[1] & SILI_BIT) &&
		    (cmd->sense_buffer[2] & 0xe0)) {	/* EOF, EOM, or ILI */
			int TransferLength, Residue = 0;
			if ((cmd->sense_buffer[2] & 0x0f) == BLANK_CHECK) {
				cmd->sense_buffer[2] &= 0xcf;	/* No need for EOM in this case */
			}
			TransferLength = ((cmd->cdb[2] << 16) |
					  (cmd->cdb[3] << 8) | cmd->cdb[4]);
			/* Compute the residual count */
			if ((cmd->sense_buffer[0] & 0x80) != 0) {
				Residue = ((cmd->sense_buffer[3] << 24) |
					   (cmd->sense_buffer[4] << 16) |
					   (cmd->sense_buffer[5] << 8) |
					   cmd->sense_buffer[6]);
			}
			TRACE_DBG("Checking the sense key "
			      "sn[2]=%x cmd->cdb[0,1]=%x,%x TransLen/Resid %d/%d",
			      (int) cmd->sense_buffer[2],
			      cmd->cdb[0], cmd->cdb[1], TransferLength,
			      Residue);
			if (TransferLength > Residue) {
				int resp_data_len = TransferLength - Residue;
				if (cmd->cdb[1] & SCST_TRANSFER_LEN_TYPE_FIXED) {
					/* 
					 * No need for locks here, since 
					 * *_detach() can not be called, when
					 * there are existing commands.
					 */
					tape = (struct tape_params *)cmd->dev->dh_priv;
					resp_data_len *= tape->block_size;
				}
				scst_set_resp_data_len(cmd, resp_data_len);
			}
		}
	}

	TRACE_DBG("cmd->tgt_resp_flags=%x, cmd->resp_data_len=%d, "
	      "res=%d", cmd->tgt_resp_flags, cmd->resp_data_len, res);

out:
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
	int res = SCST_EXEC_NOT_COMPLETED;
	int opcode = cmd->cdb[0];

	TRACE_ENTRY();

	switch (opcode) {
	case WRITE_6:
	case READ_6:
		res = SCST_EXEC_COMPLETED;
		cmd->status = 0;
		cmd->msg_status = 0;
		cmd->host_status = DID_OK;
		cmd->driver_status = 0;
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

MODULE_LICENSE("GPL");
