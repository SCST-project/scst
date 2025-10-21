/*
 *  scst_local_cmd.c
 *
 *  Copyright (C) 2004 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
 *  Copyright (C) 2008 - 2020 Bart Van Assche <bvanassche@acm.org>
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

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_local_cmd.h"
#include "scst_priv.h"
#include "scst_pres.h"

enum scst_exec_res scst_report_luns_local(struct scst_cmd *cmd)
{
	enum scst_exec_res res = SCST_EXEC_COMPLETED;
	int dev_cnt = 0;
	int buffer_size;
	int i;
	struct scst_tgt_dev *tgt_dev = NULL;
	uint8_t *buffer;
	int offs, overflow = 0;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (cmd->cdb[2] != 0 && cmd->cdb[2] != 2) {
		TRACE(TRACE_MINOR,
		      "Unsupported SELECT REPORT value %#x in REPORT LUNS command",
		      cmd->cdb[2]);
		scst_set_invalid_field_in_cdb(cmd, 2, 0);
		goto out_compl;
	}

	buffer_size = scst_get_buf_full_sense(cmd, &buffer);
	if (unlikely(buffer_size <= 0))
		goto out_compl;

	if (buffer_size < 16) {
		scst_set_invalid_field_in_cdb(cmd, 6, 0);
		goto out_put_err;
	}

	memset(buffer, 0, buffer_size);
	offs = 8;

	rcu_read_lock();
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &cmd->sess->sess_tgt_dev_list[i];

		list_for_each_entry_rcu(tgt_dev, head,
					sess_tgt_dev_list_entry) {
			struct scst_tgt_dev_UA *ua;

			if (!overflow) {
				if ((buffer_size - offs) < 8) {
					overflow = 1;
					goto inc_dev_cnt;
				}
				*(__force __be64 *)&buffer[offs] =
					scst_pack_lun(tgt_dev->lun, cmd->sess->acg->addr_method);
				offs += 8;
			}
inc_dev_cnt:
			dev_cnt++;

			/* Clear sense_reported_luns_data_changed UA. */
			spin_lock_bh(&tgt_dev->tgt_dev_lock);
			list_for_each_entry(ua, &tgt_dev->UA_list, UA_list_entry) {
				if (scst_analyze_sense(ua->UA_sense_buffer, ua->UA_valid_sense_len,
						       SCST_SENSE_ALL_VALID,
						       SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed))) {
					TRACE_DBG("Freeing not needed REPORTED LUNS DATA CHANGED UA %p",
						  ua);
					scst_tgt_dev_del_free_UA(tgt_dev, ua);
					break;
				}
			}
			spin_unlock_bh(&tgt_dev->tgt_dev_lock);
		}
	}
	rcu_read_unlock();

	/* Set the response header */
	dev_cnt *= 8;
	put_unaligned_be32(dev_cnt, buffer);

	scst_put_buf_full(cmd, buffer);

	dev_cnt += 8;
	if (dev_cnt < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, dev_cnt);

out_compl:
	cmd->completed = 1;

	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

	TRACE_EXIT_RES(res);
	return res;

out_put_err:
	scst_put_buf_full(cmd, buffer);
	goto out_compl;
}

enum scst_exec_res scst_request_sense_local(struct scst_cmd *cmd)
{
	enum scst_exec_res res = SCST_EXEC_COMPLETED;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	uint8_t *buffer;
	int buffer_size = 0, sl = 0;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	buffer_size = scst_get_buf_full_sense(cmd, &buffer);
	if (unlikely(buffer_size <= 0))
		goto out_compl;

	memset(buffer, 0, buffer_size);

	spin_lock_bh(&tgt_dev->tgt_dev_lock);

	if (tgt_dev->tgt_dev_valid_sense_len == 0) {
		if (test_bit(SCST_TGT_DEV_UA_PENDING, &cmd->tgt_dev->tgt_dev_flags)) {
			int rc, size = sizeof(tgt_dev->tgt_dev_sense);
			uint8_t *buf;

			spin_unlock_bh(&tgt_dev->tgt_dev_lock);

			buf = kzalloc(size, GFP_KERNEL);
			if (!buf)
				goto out_put_busy;

			rc = scst_set_pending_UA(cmd, buf, &size);

			spin_lock_bh(&tgt_dev->tgt_dev_lock);

			if (rc == 0) {
				if (tgt_dev->tgt_dev_valid_sense_len == 0) {
					tgt_dev->tgt_dev_valid_sense_len = size;
					memcpy(tgt_dev->tgt_dev_sense, buf, size);
				} else {
					/*
					 * Yes, we can loose some of UA data
					 * here, if UA size is bigger, than
					 * size, i.e. tgt_dev_sense.
					 */
					scst_requeue_ua(cmd, buf, size);
				}
			}

			kfree(buf);
		}
		if (tgt_dev->tgt_dev_valid_sense_len == 0)
			goto out_unlock_put_not_completed;
	}

	TRACE(TRACE_SCSI, "%s: Returning stored/UA sense", cmd->op_name);

	if (((scst_sense_response_code(tgt_dev->tgt_dev_sense) == 0x70) ||
	     (scst_sense_response_code(tgt_dev->tgt_dev_sense) == 0x71)) &&
	     (cmd->cdb[1] & 1)) {
		PRINT_WARNING("%s: Fixed format of the saved sense, but descriptor format requested. Conversion will truncated data",
			      cmd->op_name);
		PRINT_BUFFER("Original sense",
			     tgt_dev->tgt_dev_sense, tgt_dev->tgt_dev_valid_sense_len);

		buffer_size = min(SCST_STANDARD_SENSE_LEN, buffer_size);
		sl = scst_set_sense(buffer, buffer_size, true, tgt_dev->tgt_dev_sense[2],
				    tgt_dev->tgt_dev_sense[12], tgt_dev->tgt_dev_sense[13]);
	} else if (((scst_sense_response_code(tgt_dev->tgt_dev_sense) == 0x72) ||
		    (scst_sense_response_code(tgt_dev->tgt_dev_sense) == 0x73)) &&
		   !(cmd->cdb[1] & 1)) {
		PRINT_WARNING("%s: Descriptor format of the saved sense, but fixed format requested. Conversion will truncate data",
			      cmd->op_name);
		PRINT_BUFFER("Original sense",
			     tgt_dev->tgt_dev_sense, tgt_dev->tgt_dev_valid_sense_len);

		buffer_size = min(SCST_STANDARD_SENSE_LEN, buffer_size);
		sl = scst_set_sense(buffer, buffer_size, false, tgt_dev->tgt_dev_sense[1],
				    tgt_dev->tgt_dev_sense[2], tgt_dev->tgt_dev_sense[3]);
	} else {
		if (buffer_size >= tgt_dev->tgt_dev_valid_sense_len) {
			sl = tgt_dev->tgt_dev_valid_sense_len;
		} else {
			sl = buffer_size;
			TRACE(TRACE_SCSI | TRACE_MINOR,
			      "%s: Being returned sense truncated to size %d (needed %d)",
			      cmd->op_name, buffer_size, tgt_dev->tgt_dev_valid_sense_len);
		}
		memcpy(buffer, tgt_dev->tgt_dev_sense, sl);
	}

	tgt_dev->tgt_dev_valid_sense_len = 0;

	spin_unlock_bh(&tgt_dev->tgt_dev_lock);

	scst_put_buf_full(cmd, buffer);

	scst_set_resp_data_len(cmd, sl);

out_compl:
	cmd->completed = 1;

	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

out:
	TRACE_EXIT_RES(res);
	return res;

out_put_busy:
	scst_put_buf_full(cmd, buffer);
	scst_set_busy(cmd);
	goto out_compl;

out_unlock_put_not_completed:
	spin_unlock_bh(&tgt_dev->tgt_dev_lock);
	scst_put_buf_full(cmd, buffer);
	res = SCST_EXEC_NOT_COMPLETED;
	goto out;
}

/* SPC-4 REPORT TARGET PORT GROUPS command */
static enum scst_exec_res scst_report_tpgs(struct scst_cmd *cmd)
{
	struct scst_device *dev;
	uint8_t *address;
	void *buf;
	int32_t buf_len;
	uint32_t data_length, length;
	uint8_t data_format;
	int res;

	TRACE_ENTRY();

	buf_len = scst_get_buf_full_sense(cmd, &address);
	if (buf_len <= 0)
		goto out;

	dev = cmd->dev;
	data_format = cmd->cdb[1] >> 5;

	res = scst_tg_get_group_info(&buf, &data_length, dev, data_format);
	if (res == -ENOMEM) {
		scst_set_busy(cmd);
		goto out_put;
	} else if (res < 0) {
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	length = min_t(uint32_t, data_length, buf_len);
	memcpy(address, buf, length);
	kfree(buf);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_put:
	scst_put_buf_full(cmd, address);

out:
	cmd->completed = 1;

	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

	return SCST_EXEC_COMPLETED;
}

/* SPC-4 SET TARGET PORT GROUPS command */
static enum scst_exec_res scst_exec_set_tpgs(struct scst_cmd *cmd)
{
	struct scst_device *dev = cmd->dev;
	int rc;

	if (!dev->expl_alua) {
		PRINT_ERROR("SET TARGET PORT GROUPS: not explicit ALUA mode (dev %s)",
			    dev->virt_name);
		/* Invalid opcode, i.e. SA field */
		scst_set_invalid_field_in_cdb(cmd, 1, 0 | SCST_INVAL_FIELD_BIT_OFFS_VALID);
		goto out;
	}

	rc = scst_tg_set_group_info(cmd);
	if (rc == 0) {
		/* Running async */
		return SCST_CMD_STATE_RES_CONT_NEXT;
	}
	scst_stpg_del_unblock_next(cmd);

out:
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	return SCST_EXEC_COMPLETED;
}

static enum scst_exec_res scst_report_supported_tm_fns(struct scst_cmd *cmd)
{
	const enum scst_exec_res res = SCST_EXEC_COMPLETED;
	int length, resp_len = 0;
	uint8_t *address;
	uint8_t buf[16];

	TRACE_ENTRY();

	length = scst_get_buf_full_sense(cmd, &address);
	TRACE_DBG("length %d", length);
	if (unlikely(length <= 0))
		goto out_compl;

	memset(buf, 0, sizeof(buf));

	buf[0] = 0xF8; /* ATS, ATSS, CACAS, CTSS, LURS */
	buf[1] = 0;
	if ((cmd->cdb[2] & 0x80) == 0) {
		resp_len = 4;
	} else {
		buf[3] = 0x0C;
#if 1
		buf[4] = 1; /* TMFTMOV */
		buf[6] = 0xA0; /* ATTS, CACATS */
		put_unaligned_be32(300, &buf[8]); /* long timeout - 30 sec. */
		put_unaligned_be32(150, &buf[12]); /* short timeout - 15 sec. */
#endif
		resp_len = 16;
	}

	if (length > resp_len)
		length = resp_len;
	memcpy(address, buf, length);

	scst_put_buf_full(cmd, address);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_compl:
	cmd->completed = 1;

	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

	TRACE_EXIT_RES(res);
	return res;
}

static enum scst_exec_res scst_report_supported_opcodes(struct scst_cmd *cmd)
{
	const enum scst_exec_res res = SCST_EXEC_COMPLETED;
	int length, buf_len, i, offs;
	uint8_t *address;
	uint8_t *buf;
	bool inline_buf;
	bool rctd = cmd->cdb[2] >> 7;
	int options = cmd->cdb[2] & 7;
	int req_opcode = cmd->cdb[3];
	int req_sa = get_unaligned_be16(&cmd->cdb[4]);
	const struct scst_opcode_descriptor *op = NULL;
	const struct scst_opcode_descriptor **supp_opcodes = NULL;
	int supp_opcodes_cnt, rc;

	TRACE_ENTRY();

	/* get_cdb_info_min() ensures that get_supported_opcodes is not NULL here */

	rc = cmd->devt->get_supported_opcodes(cmd, &supp_opcodes, &supp_opcodes_cnt);
	if (rc != 0)
		goto out_compl;

	TRACE_DBG("cmd %p, options %d, req_opcode %x, req_sa %x, rctd %d",
		  cmd, options, req_opcode, req_sa, rctd);

	switch (options) {
	case 0: /* all */
		buf_len = 4;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			buf_len += 8;
			if (rctd)
				buf_len += 12;
		}
		break;
	case 1:
		buf_len = 0;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			if (req_opcode == supp_opcodes[i]->od_opcode) {
				op = supp_opcodes[i];
				if (op->od_serv_action_valid) {
					TRACE(TRACE_MINOR,
					      "Requested opcode %x ith unexpected service action (dev %s, initiator %s)",
					      req_opcode, cmd->dev->virt_name,
					      cmd->sess->initiator_name);
					scst_set_invalid_field_in_cdb(cmd, 2,
								      SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
					goto out_compl;
				}
				buf_len = 4 + op->od_cdb_size;
				if (rctd)
					buf_len += 12;
				break;
			}
		}
		if (!op) {
			TRACE(TRACE_MINOR,
			      "Requested opcode %x not found (dev %s, initiator %s)",
			      req_opcode, cmd->dev->virt_name, cmd->sess->initiator_name);
			buf_len = 4;
		}
		break;
	case 2:
		buf_len = 0;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			if (req_opcode == supp_opcodes[i]->od_opcode) {
				op = supp_opcodes[i];
				if (!op->od_serv_action_valid) {
					TRACE(TRACE_MINOR,
					      "Requested opcode %x without expected service action (dev %s, initiator %s)",
					      req_opcode, cmd->dev->virt_name,
					      cmd->sess->initiator_name);
					scst_set_invalid_field_in_cdb(cmd, 2,
								      SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
					goto out_compl;
				}
				if (req_sa != op->od_serv_action) {
					op = NULL; /* reset it */
					continue;
				}
				buf_len = 4 + op->od_cdb_size;
				if (rctd)
					buf_len += 12;
				break;
			}
		}
		if (!op) {
			TRACE(TRACE_MINOR,
			      "Requested opcode %x/%x not found (dev %s, initiator %s)",
			      req_opcode, req_sa, cmd->dev->virt_name, cmd->sess->initiator_name);
			buf_len = 4;
		}
		break;
	default:
		PRINT_ERROR("REPORT SUPPORTED OPERATION CODES: REPORTING OPTIONS %x not supported (dev %s, initiator %s)",
			    options, cmd->dev->virt_name, cmd->sess->initiator_name);
		scst_set_invalid_field_in_cdb(cmd, 2, SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out_compl;
	}

	length = scst_get_buf_full_sense(cmd, &address);
	TRACE_DBG("length %d, buf_len %d, op %p", length, buf_len, op);
	if (unlikely(length <= 0))
		goto out_compl;

	if (length >= buf_len) {
		buf = address;
		inline_buf = true;
	} else {
		buf = vmalloc(buf_len); /* it can be big */
		if (!buf) {
			PRINT_ERROR("Unable to allocate REPORT SUPPORTED OPERATION CODES buffer with size %d",
				    buf_len);
			scst_set_busy(cmd);
			goto out_err_put;
		}
		inline_buf = false;
	}

	memset(buf, 0, buf_len);

	switch (options) {
	case 0: /* all */
		put_unaligned_be32(buf_len - 4, &buf[0]);
		offs = 4;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			op = supp_opcodes[i];
			buf[offs] = op->od_opcode;
			if (op->od_serv_action_valid) {
				put_unaligned_be16(op->od_serv_action, &buf[offs + 2]);
				buf[offs + 5] |= 1;
			}
			put_unaligned_be16(op->od_cdb_size, &buf[offs + 6]);
			offs += 8;
			if (rctd) {
				buf[(offs - 8) + 5] |= 2;
				buf[offs + 1] = 0xA;
				buf[offs + 3] = op->od_comm_specific_timeout;
				put_unaligned_be32(op->od_nominal_timeout, &buf[offs + 4]);
				put_unaligned_be32(op->od_recommended_timeout, &buf[offs + 8]);
				offs += 12;
			}
		}
		break;
	case 1:
	case 2:
		if (op) {
			buf[1] |= op->od_support;
			put_unaligned_be16(op->od_cdb_size, &buf[2]);
			memcpy(&buf[4], op->od_cdb_usage_bits, op->od_cdb_size);
			if (rctd) {
				buf[1] |= 0x80;
				offs = 4 + op->od_cdb_size;
				buf[offs + 1] = 0xA;
				buf[offs + 3] = op->od_comm_specific_timeout;
				put_unaligned_be32(op->od_nominal_timeout, &buf[offs + 4]);
				put_unaligned_be32(op->od_recommended_timeout, &buf[offs + 8]);
			}
		}
		break;
	default:
		sBUG();
	}

	if (length > buf_len)
		length = buf_len;
	if (!inline_buf) {
		memcpy(address, buf, length);
		vfree(buf);
	}

	scst_put_buf_full(cmd, address);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_compl:
	if (supp_opcodes && cmd->devt->put_supported_opcodes)
		cmd->devt->put_supported_opcodes(cmd, supp_opcodes, supp_opcodes_cnt);

	cmd->completed = 1;

	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

	TRACE_EXIT_RES(res);
	return res;

out_err_put:
	scst_put_buf_full(cmd, address);
	goto out_compl;
}

enum scst_exec_res scst_maintenance_in(struct scst_cmd *cmd)
{
	enum scst_exec_res res;

	TRACE_ENTRY();

	switch (cmd->cdb[1] & 0x1f) {
	case MI_REPORT_TARGET_PGS:
		res = scst_report_tpgs(cmd);
		break;
	case MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS:
		res = scst_report_supported_tm_fns(cmd);
		break;
	case MI_REPORT_SUPPORTED_OPERATION_CODES:
		res = scst_report_supported_opcodes(cmd);
		break;
	default:
		res = SCST_EXEC_NOT_COMPLETED;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

enum scst_exec_res scst_maintenance_out(struct scst_cmd *cmd)
{
	enum scst_exec_res res;

	switch (cmd->cdb[1] & 0x1f) {
	case MO_SET_TARGET_PGS:
		res = scst_exec_set_tpgs(cmd);
		break;
	default:
		res = SCST_EXEC_NOT_COMPLETED;
		break;
	}

	return res;
}

enum scst_exec_res scst_reserve_local(struct scst_cmd *cmd)
{
	enum scst_exec_res res = SCST_EXEC_NOT_COMPLETED;
	struct scst_device *dev;
	struct scst_lksb pr_lksb;

	TRACE_ENTRY();

	if (cmd->sess->sess_mq) {
		PRINT_WARNING_ONCE("MQ session (%p) from initiator %s (tgt %s), reservations not supported",
				   cmd->sess, cmd->sess->initiator_name, cmd->sess->tgt->tgt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	if (cmd->cdb[0] == RESERVE_10 && (cmd->cdb[2] & SCST_RES_3RDPTY)) {
		PRINT_ERROR("RESERVE_10: 3rdPty RESERVE not implemented (lun=%lld)",
			    (unsigned long long)cmd->lun);
		scst_set_invalid_field_in_cdb(cmd, 2, SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
		goto out_done;
	}

	dev = cmd->dev;

	/*
	 * There's no need to block this device, even for
	 * SCST_TST_0_SINGLE_TASK_SET, or anyhow else protect reservations
	 * changes, because:
	 *
	 * 1. The reservation changes are (rather) atomic, i.e., in contrast
	 *    to persistent reservations, don't have any invalid intermediate
	 *    states during being changed.
	 *
	 * 2. It's a duty of initiators to ensure order of regular commands
	 *    around the reservation command either by ORDERED attribute, or by
	 *    queue draining, or etc. For case of SCST_TST_0_SINGLE_TASK_SET
	 *    there are no target drivers which can ensure even for ORDERED
	 *    commands order of their delivery, so, because initiators know
	 *    it, also there's no point to do any extra protection actions.
	 */

	if (!list_empty(&dev->dev_registrants_list)) {
		if (scst_pr_crh_case(cmd))
			goto out_completed;

		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_done;
	}

	scst_res_lock(dev, &pr_lksb);
	if (scst_is_not_reservation_holder(dev, cmd->sess)) {
		scst_res_unlock(dev, &pr_lksb);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_done;
	}
	scst_reserve_dev(dev, cmd->sess);
	scst_res_unlock(dev, &pr_lksb);

out:
	TRACE_EXIT_RES(res);
	return res;

out_completed:
	cmd->completed = 1;

out_done:
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	res = SCST_EXEC_COMPLETED;
	goto out;
}

enum scst_exec_res scst_release_local(struct scst_cmd *cmd)
{
	enum scst_exec_res res = SCST_EXEC_NOT_COMPLETED;
	struct scst_device *dev;
	struct scst_lksb pr_lksb;

	TRACE_ENTRY();

	if (cmd->sess->sess_mq) {
		PRINT_WARNING_ONCE("MQ session (%p) from initiator %s (tgt %s), reservations not supported",
				   cmd->sess, cmd->sess->initiator_name, cmd->sess->tgt->tgt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	dev = cmd->dev;

	/*
	 * See comment in scst_reserve_local() why no dev blocking or any
	 * other protection is needed here.
	 */

	if (!list_empty(&dev->dev_registrants_list)) {
		if (scst_pr_crh_case(cmd))
			goto out_completed;

		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_done;
	}

	scst_res_lock(dev, &pr_lksb);

	/*
	 * The device could be RELEASED behind us, if RESERVING session
	 * is closed (see scst_free_tgt_dev()), but this actually doesn't
	 * matter, so use lock and no retest for DEV_RESERVED bits again
	 */
	if (scst_is_not_reservation_holder(dev, cmd->sess)) {
		/*
		 * SPC-2 requires to report SCSI status GOOD if a RELEASE
		 * command fails because a reservation is held by another
		 * session.
		 */
		res = SCST_EXEC_COMPLETED;
		cmd->status = 0;
		cmd->msg_status = 0;
		cmd->host_status = DID_OK;
		cmd->driver_status = 0;
		cmd->completed = 1;
	} else {
		scst_clear_dev_reservation(dev);
	}

	scst_res_unlock(dev, &pr_lksb);

	if (res == SCST_EXEC_COMPLETED)
		goto out_done;

out:
	TRACE_EXIT_RES(res);
	return res;

out_completed:
	cmd->completed = 1;

out_done:
	res = SCST_EXEC_COMPLETED;
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

/* No locks, no IRQ or IRQ-disabled context allowed */
enum scst_exec_res scst_persistent_reserve_in_local(struct scst_cmd *cmd)
{
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_session *session;
	int action;
	uint8_t *buffer;
	int buffer_size;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(scst_cmd_atomic(cmd));

	dev = cmd->dev;
	tgt_dev = cmd->tgt_dev;
	session = cmd->sess;

	if (session->sess_mq) {
		PRINT_WARNING_ONCE("MQ session %p from initiator %s (tgt %s), persistent reservations not supported",
				   session, session->initiator_name, session->tgt->tgt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	if (unlikely(dev->not_pr_supporting_tgt_devs_num != 0)) {
		PRINT_WARNING("Persistent Reservation command %s refused for device %s, because the device has not supporting PR transports connected",
			      scst_get_opcode_name(cmd), dev->virt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	if (scst_dev_reserved(dev)) {
		TRACE_PR("PR command rejected, because device %s holds regular reservation",
			 dev->virt_name);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_done;
	}

	if (cmd->tgt->tgt_forward_src && dev->scsi_dev && !dev->cluster_mode) {
		PRINT_WARNING("PR commands for pass-through devices not supported (device %s)",
			      dev->virt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	buffer_size = scst_get_buf_full_sense(cmd, &buffer);
	if (unlikely(buffer_size <= 0))
		goto out_done;

	scst_pr_read_lock(dev);

	/* We can be aborted by another PR command while waiting for the lock */
	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_unlock;
	}

	action = cmd->cdb[1] & 0x1f;

	TRACE(TRACE_SCSI, "PR IN action %x for '%s' (LUN %llx) from '%s'",
	      action, dev->virt_name, tgt_dev->lun, session->initiator_name);

	switch (action) {
	case PR_READ_KEYS:
		scst_pr_read_keys(cmd, buffer, buffer_size);
		break;
	case PR_READ_RESERVATION:
		scst_pr_read_reservation(cmd, buffer, buffer_size);
		break;
	case PR_REPORT_CAPS:
		scst_pr_report_caps(cmd, buffer, buffer_size);
		break;
	case PR_READ_FULL_STATUS:
		scst_pr_read_full_status(cmd, buffer, buffer_size);
		break;
	default:
		PRINT_ERROR("Unsupported action %x", action);
		goto out_unsup_act;
	}

out_complete:
	cmd->completed = 1;

out_unlock:
	scst_pr_read_unlock(dev);

	scst_put_buf_full(cmd, buffer);

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

	TRACE_EXIT_RES(SCST_EXEC_COMPLETED);
	return SCST_EXEC_COMPLETED;

out_unsup_act:
	scst_set_invalid_field_in_cdb(cmd, 1, SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
	goto out_complete;
}

/* No locks, no IRQ or IRQ-disabled context allowed */
enum scst_exec_res scst_persistent_reserve_out_local(struct scst_cmd *cmd)
{
	enum scst_exec_res res = SCST_EXEC_COMPLETED;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_session *session;
	int action;
	uint8_t *buffer;
	int buffer_size;
	struct scst_lksb pr_lksb;
	bool aborted = false;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(scst_cmd_atomic(cmd));

	dev = cmd->dev;
	tgt_dev = cmd->tgt_dev;
	session = cmd->sess;

	if (session->sess_mq) {
		PRINT_WARNING_ONCE("MQ session (%p) from initiator %s (tgt %s), persistent reservations not supported",
				   session, session->initiator_name, session->tgt->tgt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	if (unlikely(dev->not_pr_supporting_tgt_devs_num != 0)) {
		PRINT_WARNING("Persistent Reservation command %s refused for device %s, because the device has not supporting PR transports connected",
			      scst_get_opcode_name(cmd), dev->virt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	action = cmd->cdb[1] & 0x1f;

	TRACE(TRACE_SCSI, "PR OUT action %x for '%s' (LUN %llx) from '%s'",
	      action, dev->virt_name, tgt_dev->lun, session->initiator_name);

	if (scst_dev_reserved(dev)) {
		TRACE_PR("PR command rejected, because device %s holds regular reservation",
			 dev->virt_name);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_done;
	}

	buffer_size = scst_get_buf_full_sense(cmd, &buffer);
	if (unlikely(buffer_size <= 0))
		goto out_done;

	dev->cl_ops->pr_write_lock(dev, &pr_lksb);

	/*
	 * Check if tgt_dev already registered. Also by this check we make
	 * sure that table "PERSISTENT RESERVE OUT service actions that are
	 * allowed in the presence of various reservations" is honored.
	 * REGISTER AND MOVE and RESERVE will be additionally checked for
	 * conflicts later.
	 */
	if (action != PR_REGISTER && action != PR_REGISTER_AND_IGNORE &&
	    !tgt_dev->registrant) {
		TRACE_PR("'%s' not registered", cmd->sess->initiator_name);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_unlock;
	}

	/* Check scope */
	if (action != PR_REGISTER && action != PR_REGISTER_AND_IGNORE &&
	    action != PR_CLEAR && (cmd->cdb[2] >> 4) != SCOPE_LU) {
		TRACE_PR("Scope must be SCOPE_LU for action %x", action);
		scst_set_invalid_field_in_cdb(cmd, 2, SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
		goto out_unlock;
	}

	/* Check SPEC_I_PT (PR_REGISTER_AND_MOVE has another format) */
	if (action != PR_REGISTER && action != PR_REGISTER_AND_MOVE &&
	    ((buffer[20] >> 3) & 0x01)) {
		TRACE_PR("SPEC_I_PT must be zero for action %x", action);
		scst_set_invalid_field_in_parm_list(cmd, 20, SCST_INVAL_FIELD_BIT_OFFS_VALID | 3);
		goto out_unlock;
	}

	/* Check ALL_TG_PT (PR_REGISTER_AND_MOVE has another format) */
	if (action != PR_REGISTER && action != PR_REGISTER_AND_IGNORE &&
	    action != PR_REGISTER_AND_MOVE && ((buffer[20] >> 2) & 0x01)) {
		TRACE_PR("ALL_TG_PT must be zero for action %x", action);
		scst_set_invalid_field_in_parm_list(cmd, 20, SCST_INVAL_FIELD_BIT_OFFS_VALID | 2);
		goto out_unlock;
	}

	/* We can be aborted by another PR command while waiting for the lock */
	aborted = test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
	if (unlikely(aborted)) {
		TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_unlock;
	}

	switch (action) {
	case PR_REGISTER:
		scst_pr_register(cmd, buffer, buffer_size);
		break;
	case PR_RESERVE:
		scst_pr_reserve(cmd, buffer, buffer_size);
		break;
	case PR_RELEASE:
		scst_pr_release(cmd, buffer, buffer_size);
		break;
	case PR_CLEAR:
		scst_pr_clear(cmd, buffer, buffer_size);
		break;
	case PR_PREEMPT:
		scst_pr_preempt(cmd, buffer, buffer_size);
		break;
	case PR_PREEMPT_AND_ABORT:
		scst_pr_preempt_and_abort(cmd, buffer, buffer_size);
		break;
	case PR_REGISTER_AND_IGNORE:
		scst_pr_register_and_ignore(cmd, buffer, buffer_size);
		break;
	case PR_REGISTER_AND_MOVE:
		scst_pr_register_and_move(cmd, buffer, buffer_size);
		break;
	default:
		scst_set_invalid_field_in_cdb(cmd, 1, SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out_unlock;
	}

	if (cmd->status == SAM_STAT_GOOD)
		scst_pr_sync_device_file(dev);

	/* sync file may change status */
	if (cmd->devt->pr_cmds_notifications && cmd->status == SAM_STAT_GOOD)
		res = SCST_EXEC_NOT_COMPLETED;

out_unlock:
	dev->cl_ops->pr_write_unlock(dev, &pr_lksb);

	scst_put_buf_full(cmd, buffer);

out_done:
	if (res == SCST_EXEC_COMPLETED) {
		if (!aborted)
			cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	}

	TRACE_EXIT_RES(res);
	return res;
}
