/*
 *  scst_targ.c
 *
 *  Copyright (C) 2004 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include "scst.h"
#include "scst_priv.h"

static void scst_cmd_set_sn(struct scst_cmd *cmd);
static int __scst_init_cmd(struct scst_cmd *cmd);
static void scst_finish_cmd_mgmt(struct scst_cmd *cmd);
static struct scst_cmd *__scst_find_cmd_by_tag(struct scst_session *sess,
	uint64_t tag);
static void scst_proccess_redirect_cmd(struct scst_cmd *cmd,
	enum scst_exec_context context, int check_retries);

static inline void scst_schedule_tasklet(struct scst_cmd *cmd)
{
	struct scst_tasklet *t = &scst_tasklets[smp_processor_id()];
	unsigned long flags;

	spin_lock_irqsave(&t->tasklet_lock, flags);
	TRACE_DBG("Adding cmd %p to tasklet %d cmd list", cmd,
		smp_processor_id());
	list_add_tail(&cmd->cmd_list_entry, &t->tasklet_cmd_list);
	spin_unlock_irqrestore(&t->tasklet_lock, flags);

	tasklet_schedule(&t->tasklet);
}

/*
 * Must not be called in parallel with scst_unregister_session() for the
 * same sess
 */
struct scst_cmd *scst_rx_cmd(struct scst_session *sess,
			     const uint8_t *lun, int lun_len,
			     const uint8_t *cdb, int cdb_len, int atomic)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(sess->shut_phase != SCST_SESS_SPH_READY)) {
		PRINT_CRIT_ERROR("%s",
			"New cmd while shutting down the session");
		sBUG();
	}
#endif

	cmd = scst_alloc_cmd(atomic ? GFP_ATOMIC : GFP_KERNEL);
	if (cmd == NULL)
		goto out;

	cmd->sess = sess;
	cmd->tgt = sess->tgt;
	cmd->tgtt = sess->tgt->tgtt;

	/*
	 * For both wrong lun and CDB defer the error reporting for
	 * scst_cmd_init_done()
	 */

	cmd->lun = scst_unpack_lun(lun, lun_len);

	if (cdb_len <= SCST_MAX_CDB_SIZE) {
		memcpy(cmd->cdb, cdb, cdb_len);
		cmd->cdb_len = cdb_len;
	}

	TRACE_DBG("cmd %p, sess %p", cmd, sess);
	scst_sess_get(sess);

out:
	TRACE_EXIT();
	return cmd;
}
EXPORT_SYMBOL(scst_rx_cmd);

/*
 * No locks, but might be on IRQ. Returns 0 on success, <0 if processing of
 * this command should be stopped.
 */
static int scst_init_cmd(struct scst_cmd *cmd, enum scst_exec_context *context)
{
	int rc, res = 0;

	TRACE_ENTRY();

	/* See the comment in scst_do_job_init() */
	if (unlikely(!list_empty(&scst_init_cmd_list))) {
		TRACE_MGMT_DBG("%s", "init cmd list busy");
		goto out_redirect;
	}
	/*
	 * Memory barrier isn't necessary here, because CPU appears to
	 * be self-consistent and we don't care about the race, described
	 * in comment in scst_do_job_init().
	 */

	rc = __scst_init_cmd(cmd);
	if (unlikely(rc > 0))
		goto out_redirect;
	else if (unlikely(rc != 0)) {
		res = 1;
		goto out;
	}

	/* Small context optimization */
	if (((*context == SCST_CONTEXT_TASKLET) ||
	     (*context == SCST_CONTEXT_DIRECT_ATOMIC) ||
	     ((*context == SCST_CONTEXT_SAME) && scst_cmd_atomic(cmd))) &&
	      scst_cmd_is_expected_set(cmd)) {
		if (cmd->expected_data_direction & SCST_DATA_WRITE) {
			if (!test_bit(SCST_TGT_DEV_AFTER_INIT_WR_ATOMIC,
					&cmd->tgt_dev->tgt_dev_flags))
				*context = SCST_CONTEXT_THREAD;
		} else {
			if (!test_bit(SCST_TGT_DEV_AFTER_INIT_OTH_ATOMIC,
					&cmd->tgt_dev->tgt_dev_flags))
				*context = SCST_CONTEXT_THREAD;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_redirect:
	if (cmd->preprocessing_only) {
		/*
		 * Poor man solution for single threaded targets, where
		 * blocking receiver at least sometimes means blocking all.
		 */
		sBUG_ON(*context != SCST_CONTEXT_DIRECT);
		scst_set_busy(cmd);
		scst_set_cmd_abnormal_done_state(cmd);
		res = 1;
		/* Keep initiator away from too many BUSY commands */
		msleep(50);
	} else {
		unsigned long flags;
		spin_lock_irqsave(&scst_init_lock, flags);
		TRACE_MGMT_DBG("Adding cmd %p to init cmd list (scst_cmd_count "
			"%d)", cmd, atomic_read(&scst_cmd_count));
		list_add_tail(&cmd->cmd_list_entry, &scst_init_cmd_list);
		if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
			scst_init_poll_cnt++;
		spin_unlock_irqrestore(&scst_init_lock, flags);
		wake_up(&scst_init_cmd_list_waitQ);
		res = -1;
	}
	goto out;
}

#ifdef CONFIG_SCST_MEASURE_LATENCY
static inline uint64_t scst_sec_to_nsec(time_t sec)
{
	return (uint64_t)sec * 1000000000;
}
#endif

void scst_cmd_init_done(struct scst_cmd *cmd,
	enum scst_exec_context pref_context)
{
	unsigned long flags;
	struct scst_session *sess = cmd->sess;
	int rc;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_MEASURE_LATENCY
	{
		struct timespec ts;
		getnstimeofday(&ts);
		cmd->start = scst_sec_to_nsec(ts.tv_sec) + ts.tv_nsec;
		TRACE_DBG("cmd %p (sess %p): start %lld (tv_sec %ld, "
			"tv_nsec %ld)", cmd, sess, cmd->start, ts.tv_sec,
			ts.tv_nsec);
	}
#endif

	TRACE_DBG("Preferred context: %d (cmd %p)", pref_context, cmd);
	TRACE(TRACE_SCSI, "tag=%llu, lun=%lld, CDB len=%d, queue_type=%x "
		"(cmd %p)", (long long unsigned int)cmd->tag,
		(long long unsigned int)cmd->lun, cmd->cdb_len,
		cmd->queue_type, cmd);
	PRINT_BUFF_FLAG(TRACE_SCSI|TRACE_RCV_BOT, "Recieving CDB",
		cmd->cdb, cmd->cdb_len);

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely((in_irq() || irqs_disabled())) &&
	    ((pref_context == SCST_CONTEXT_DIRECT) ||
	     (pref_context == SCST_CONTEXT_DIRECT_ATOMIC))) {
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_THREAD instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_THREAD;
	}
#endif

	atomic_inc(&sess->sess_cmd_count);

	spin_lock_irqsave(&sess->sess_list_lock, flags);

	if (unlikely(sess->init_phase != SCST_SESS_IPH_READY)) {
		/*
		 * We have to always keep command in the search list from the
		 * very beginning, because otherwise it can be missed during
		 * TM processing. This check is needed because there might be
		 * old, i.e. deferred, commands and new, i.e. just coming, ones.
		 */
		if (cmd->sess_cmd_list_entry.next == NULL)
			list_add_tail(&cmd->sess_cmd_list_entry,
				&sess->search_cmd_list);
		switch (sess->init_phase) {
		case SCST_SESS_IPH_SUCCESS:
			break;
		case SCST_SESS_IPH_INITING:
			TRACE_DBG("Adding cmd %p to init deferred cmd list",
				  cmd);
			list_add_tail(&cmd->cmd_list_entry,
				&sess->init_deferred_cmd_list);
			spin_unlock_irqrestore(&sess->sess_list_lock, flags);
			goto out;
		case SCST_SESS_IPH_FAILED:
			spin_unlock_irqrestore(&sess->sess_list_lock, flags);
			scst_set_busy(cmd);
			scst_set_cmd_abnormal_done_state(cmd);
			goto active;
		default:
			sBUG();
		}
	} else
		list_add_tail(&cmd->sess_cmd_list_entry,
			      &sess->search_cmd_list);

	spin_unlock_irqrestore(&sess->sess_list_lock, flags);

	if (unlikely(cmd->lun == NO_SUCH_LUN)) {
		PRINT_ERROR("Wrong LUN %d, finishing cmd", -1);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		scst_set_cmd_abnormal_done_state(cmd);
		goto active;
	}

	if (unlikely(cmd->cdb_len == 0)) {
		PRINT_ERROR("%s", "Wrong CDB len, finishing cmd");
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		scst_set_cmd_abnormal_done_state(cmd);
		goto active;
	}

	if (unlikely(cmd->queue_type >= SCST_CMD_QUEUE_ACA)) {
		PRINT_ERROR("Unsupported queue type %d", cmd->queue_type);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_message));
		scst_set_cmd_abnormal_done_state(cmd);
		goto active;
	}

	/*
	 * Cmd must be inited here to preserve the order. In case if cmd
	 * already preliminary completed by target driver we need to init
	 * cmd anyway to find out in which format we should return sense.
	 */
	cmd->state = SCST_CMD_STATE_INIT;
	rc = scst_init_cmd(cmd, &pref_context);
	if (unlikely(rc < 0))
		goto out;
	else if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION)) {
		if (rc == 0) {
			/* Target driver preliminary completed cmd */
			scst_set_cmd_abnormal_done_state(cmd);
		}
	}

active:
	/* Here cmd must not be in any cmd list, no locks */
	switch (pref_context) {
	case SCST_CONTEXT_TASKLET:
		scst_schedule_tasklet(cmd);
		break;

	case SCST_CONTEXT_DIRECT:
		scst_process_active_cmd(cmd, false);
		/* For *NEED_THREAD wake_up() is already done */
		break;

	case SCST_CONTEXT_DIRECT_ATOMIC:
		scst_process_active_cmd(cmd, true);
		/* For *NEED_THREAD wake_up() is already done */
		break;

	default:
		PRINT_ERROR("Context %x is undefined, using the thread one",
			pref_context);
		/* go through */
	case SCST_CONTEXT_THREAD:
		spin_lock_irqsave(&cmd->cmd_lists->cmd_list_lock, flags);
		TRACE_DBG("Adding cmd %p to active cmd list", cmd);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		wake_up(&cmd->cmd_lists->cmd_list_waitQ);
		spin_unlock_irqrestore(&cmd->cmd_lists->cmd_list_lock, flags);
		break;
	}

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_cmd_init_done);

static int scst_pre_parse(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	struct scst_device *dev = cmd->dev;
	int rc;

	TRACE_ENTRY();

	cmd->inc_expected_sn_on_done = dev->handler->exec_sync ||
	     (!dev->has_own_order_mgmt &&
	      (dev->queue_alg == SCST_CONTR_MODE_QUEUE_ALG_RESTRICTED_REORDER ||
	       cmd->queue_type == SCST_CMD_QUEUE_ORDERED));

	/*
	 * Expected transfer data supplied by the SCSI transport via the
	 * target driver are untrusted, so we prefer to fetch them from CDB.
	 * Additionally, not all transports support supplying the expected
	 * transfer data.
	 */

	rc = scst_get_cdb_info(cmd);
	if (unlikely(rc != 0)) {
		if (rc > 0) {
			PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
			goto out_xmit;
		}
		PRINT_ERROR("Unknown opcode 0x%02x for %s. "
			"Should you update scst_scsi_op_table?",
			cmd->cdb[0], dev->handler->name);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
		if (scst_cmd_is_expected_set(cmd)) {
			TRACE(TRACE_SCSI, "Using initiator supplied values: "
				"direction %d, transfer_len %d",
				cmd->expected_data_direction,
				cmd->expected_transfer_len);
			cmd->data_direction = cmd->expected_data_direction;

			cmd->bufflen = cmd->expected_transfer_len;
			/* Restore (possibly) lost CDB length */
			cmd->cdb_len = scst_get_cdb_len(cmd->cdb);
			if (cmd->cdb_len == -1) {
				PRINT_ERROR("Unable to get CDB length for "
					"opcode 0x%02x. Returning INVALID "
					"OPCODE", cmd->cdb[0]);
				scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
				goto out_xmit;
			}
		} else {
			PRINT_ERROR("Unknown opcode 0x%02x for %s and "
			     "target %s not supplied expected values",
			     cmd->cdb[0], dev->handler->name, cmd->tgtt->name);
			scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
			goto out_xmit;
		}
#else
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_xmit;
#endif
	} else {
		TRACE(TRACE_SCSI, "op_name <%s> (cmd %p), direction=%d "
			"(expected %d, set %s), transfer_len=%d (expected "
			"len %d), flags=%d", cmd->op_name, cmd,
			cmd->data_direction, cmd->expected_data_direction,
			scst_cmd_is_expected_set(cmd) ? "yes" : "no",
			cmd->bufflen, cmd->expected_transfer_len,
			cmd->op_flags);

		if (unlikely((cmd->op_flags & SCST_UNKNOWN_LENGTH) != 0)) {
			if (scst_cmd_is_expected_set(cmd)) {
				/*
				 * Command data length can't be easily
				 * determined from the CDB. ToDo, all such
				 * commands processing should be fixed. Until
				 * it's done, get the length from the supplied
				 * expected value, but limit it to some
				 * reasonable value (15MB).
				 */
				cmd->bufflen = min(cmd->expected_transfer_len,
							15*1024*1024);
				cmd->op_flags &= ~SCST_UNKNOWN_LENGTH;
			} else
				cmd->bufflen = 0;
		}
	}

	if (unlikely(cmd->cdb[cmd->cdb_len - 1] & CONTROL_BYTE_NACA_BIT)) {
		PRINT_ERROR("NACA bit in control byte CDB is not supported "
			    "(opcode 0x%02x)", cmd->cdb[0]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_xmit;
	}

	if (unlikely(cmd->cdb[cmd->cdb_len - 1] & CONTROL_BYTE_LINK_BIT)) {
		PRINT_ERROR("Linked commands are not supported "
			    "(opcode 0x%02x)", cmd->cdb[0]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_xmit;
	}

	cmd->state = SCST_CMD_STATE_DEV_PARSE;

out:
	TRACE_EXIT_RES(res);
	return res;

out_xmit:
	scst_set_cmd_abnormal_done_state(cmd);
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

#ifndef CONFIG_SCST_USE_EXPECTED_VALUES
static bool scst_is_allowed_to_mismatch_cmd(struct scst_cmd *cmd)
{
	bool res = false;

	switch (cmd->cdb[0]) {
	case TEST_UNIT_READY:
		/* Crazy VMware people sometimes do TUR with READ direction */
		res = true;
		break;
	case VERIFY:
	case VERIFY_6:
	case VERIFY_12:
	case VERIFY_16:
		/* VERIFY commands with BYTCHK unset shouldn't fail here */
		if ((cmd->op_flags & SCST_VERIFY_BYTCHK_MISMATCH_ALLOWED) &&
		    (cmd->cdb[1] & BYTCHK) == 0)
			res = true;
		break;
	}

	return res;
}
#endif

static int scst_parse_cmd(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int state;
	struct scst_device *dev = cmd->dev;
	int orig_bufflen = cmd->bufflen;

	TRACE_ENTRY();

	if (likely(!scst_is_cmd_local(cmd))) {
		if (unlikely(!dev->handler->parse_atomic &&
			     scst_cmd_atomic(cmd))) {
			/*
			 * It shouldn't be because of SCST_TGT_DEV_AFTER_*
			 * optimization.
			 */
			TRACE_DBG("Dev handler %s parse() needs thread "
				"context, rescheduling", dev->handler->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		TRACE_DBG("Calling dev handler %s parse(%p)",
		      dev->handler->name, cmd);
		TRACE_BUFF_FLAG(TRACE_SND_BOT, "Parsing: ",
				cmd->cdb, cmd->cdb_len);
		state = dev->handler->parse(cmd);
		/* Caution: cmd can be already dead here */
		TRACE_DBG("Dev handler %s parse() returned %d",
			dev->handler->name, state);

		switch (state) {
		case SCST_CMD_STATE_NEED_THREAD_CTX:
			TRACE_DBG("Dev handler %s parse() requested thread "
			      "context, rescheduling", dev->handler->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;

		case SCST_CMD_STATE_STOP:
			TRACE_DBG("Dev handler %s parse() requested stop "
				"processing", dev->handler->name);
			res = SCST_CMD_STATE_RES_CONT_NEXT;
			goto out;
		}

		if (state == SCST_CMD_STATE_DEFAULT)
			state = SCST_CMD_STATE_PREPARE_SPACE;
	} else
		state = SCST_CMD_STATE_PREPARE_SPACE;

	if (cmd->data_len == -1)
		cmd->data_len = cmd->bufflen;

	if (cmd->bufflen == 0) {
		/*
		 * According to SPC bufflen 0 for data transfer commands isn't
		 * an error, so we need to fix the transfer direction.
		 */
		cmd->data_direction = SCST_DATA_NONE;
	}

	if (cmd->dh_data_buf_alloced &&
	    unlikely((orig_bufflen > cmd->bufflen))) {
		PRINT_ERROR("Dev handler supplied data buffer (size %d), "
			"is less, than required (size %d)", cmd->bufflen,
			orig_bufflen);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_error;
	}

	if (unlikely(state == SCST_CMD_STATE_PRE_XMIT_RESP))
		goto set_res;

	if (unlikely((cmd->bufflen == 0) &&
		     (cmd->op_flags & SCST_UNKNOWN_LENGTH))) {
		PRINT_ERROR("Unknown data transfer length for opcode 0x%x "
			"(handler %s, target %s)", cmd->cdb[0],
			dev->handler->name, cmd->tgtt->name);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_error;
	}

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((cmd->bufflen != 0) &&
	    ((cmd->data_direction == SCST_DATA_NONE) ||
	     ((cmd->sg == NULL) && (state > SCST_CMD_STATE_PREPARE_SPACE)))) {
		PRINT_ERROR("Dev handler %s parse() returned "
			"invalid cmd data_direction %d, bufflen %d, state %d "
			"or sg %p (opcode 0x%x)", dev->handler->name,
			cmd->data_direction, cmd->bufflen, state, cmd->sg,
			cmd->cdb[0]);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_error;
	}
#endif

	if (scst_cmd_is_expected_set(cmd)) {
#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
#	ifdef CONFIG_SCST_EXTRACHECKS
		if ((cmd->data_direction != cmd->expected_data_direction) ||
		    (cmd->bufflen != cmd->expected_transfer_len)) {
			PRINT_WARNING("Expected values don't match decoded "
				"ones: data_direction %d, "
				"expected_data_direction %d, "
				"bufflen %d, expected_transfer_len %d",
				cmd->data_direction,
				cmd->expected_data_direction,
				cmd->bufflen, cmd->expected_transfer_len);
			PRINT_BUFFER("Suspicious CDB", cmd->cdb, cmd->cdb_len);
		}
#	endif
		cmd->data_direction = cmd->expected_data_direction;
		cmd->bufflen = cmd->expected_transfer_len;
#else
		if (unlikely(cmd->data_direction !=
				cmd->expected_data_direction)) {
			if (((cmd->expected_data_direction != SCST_DATA_NONE) ||
			     (cmd->bufflen != 0)) &&
			    !scst_is_allowed_to_mismatch_cmd(cmd)) {
				PRINT_ERROR("Expected data direction %d for "
					"opcode 0x%02x (handler %s, target %s) "
					"doesn't match "
					"decoded value %d",
					cmd->expected_data_direction,
					cmd->cdb[0], dev->handler->name,
					cmd->tgtt->name, cmd->data_direction);
				PRINT_BUFFER("Failed CDB",
					cmd->cdb, cmd->cdb_len);
				scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_message));
				goto out_dev_done;
			}
		}
		if (unlikely(cmd->bufflen != cmd->expected_transfer_len)) {
			TRACE(TRACE_MGMT_MINOR, "Warning: expected "
				"transfer length %d for opcode 0x%02x "
				"(handler %s, target %s) doesn't match "
				"decoded value %d. Faulty initiator "
				"(e.g. VMware is known to be such) or "
				"scst_scsi_op_table should be updated?",
				cmd->expected_transfer_len, cmd->cdb[0],
				dev->handler->name, cmd->tgtt->name,
				cmd->bufflen);
			PRINT_BUFF_FLAG(TRACE_MGMT_MINOR, "Suspicious CDB",
				cmd->cdb, cmd->cdb_len);
		}
#endif
	}

	if (unlikely(cmd->data_direction == SCST_DATA_UNKNOWN)) {
		PRINT_ERROR("Unknown data direction. Opcode 0x%x, handler %s, "
			"target %s", cmd->cdb[0], dev->handler->name,
			cmd->tgtt->name);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_error;
	}

set_res:
	switch (state) {
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_PRE_PARSE:
	case SCST_CMD_STATE_DEV_PARSE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_TGT_PRE_EXEC:
	case SCST_CMD_STATE_SEND_FOR_EXEC:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_PRE_XMIT_RESP:
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
	case SCST_CMD_STATE_FINISHED_INTERNAL:
		cmd->state = state;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		break;

	default:
		if (state >= 0) {
			PRINT_ERROR("Dev handler %s parse() returned "
			     "invalid cmd state %d (opcode %d)",
			     dev->handler->name, state, cmd->cdb[0]);
		} else {
			PRINT_ERROR("Dev handler %s parse() returned "
				"error %d (opcode %d)", dev->handler->name,
				state, cmd->cdb[0]);
		}
		goto out_error;
	}

	if (cmd->resp_data_len == -1) {
		if (cmd->data_direction & SCST_DATA_READ)
			cmd->resp_data_len = cmd->bufflen;
		else
			 cmd->resp_data_len = 0;
	}

out:
	TRACE_EXIT_HRES(res);
	return res;

out_error:
	/* dev_done() will be called as part of the regular cmd's finish */
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

#ifndef CONFIG_SCST_USE_EXPECTED_VALUES
out_dev_done:
#endif
	cmd->state = SCST_CMD_STATE_PRE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

static int scst_prepare_space(struct scst_cmd *cmd)
{
	int r = 0, res = SCST_CMD_STATE_RES_CONT_SAME;

	TRACE_ENTRY();

	if (cmd->data_direction == SCST_DATA_NONE)
		goto prep_done;

	if (cmd->tgt_need_alloc_data_buf) {
		int orig_bufflen = cmd->bufflen;

		TRACE_MEM("Custom tgt data buf allocation requested (cmd %p)",
			cmd);

		r = cmd->tgtt->alloc_data_buf(cmd);
		if (r > 0)
			goto alloc;
		else if (r == 0) {
			if (unlikely(cmd->bufflen == 0)) {
				/* See comment in scst_alloc_space() */
				if (cmd->sg == NULL)
					goto alloc;
			}

			cmd->tgt_data_buf_alloced = 1;

			if (unlikely(orig_bufflen < cmd->bufflen)) {
				PRINT_ERROR("Target driver allocated data "
					"buffer (size %d), is less, than "
					"required (size %d)", orig_bufflen,
					cmd->bufflen);
				goto out_error;
			}
			TRACE_MEM("tgt_data_buf_alloced (cmd %p)", cmd);
		} else
			goto check;
	}

alloc:
	if (!cmd->tgt_data_buf_alloced && !cmd->dh_data_buf_alloced) {
		r = scst_alloc_space(cmd);
	} else if (cmd->dh_data_buf_alloced && !cmd->tgt_data_buf_alloced) {
		TRACE_MEM("dh_data_buf_alloced set (cmd %p)", cmd);
		r = 0;
	} else if (cmd->tgt_data_buf_alloced && !cmd->dh_data_buf_alloced) {
		TRACE_MEM("tgt_data_buf_alloced set (cmd %p)", cmd);
		cmd->sg = cmd->tgt_sg;
		cmd->sg_cnt = cmd->tgt_sg_cnt;
		cmd->in_sg = cmd->tgt_in_sg;
		cmd->in_sg_cnt = cmd->tgt_in_sg_cnt;
		r = 0;
	} else {
		TRACE_MEM("Both *_data_buf_alloced set (cmd %p, sg %p, "
			"sg_cnt %d, tgt_sg %p, tgt_sg_cnt %d)", cmd, cmd->sg,
			cmd->sg_cnt, cmd->tgt_sg, cmd->tgt_sg_cnt);
		r = 0;
	}

check:
	if (r != 0) {
		if (scst_cmd_atomic(cmd)) {
			TRACE_MEM("%s", "Atomic memory allocation failed, "
			      "rescheduling to the thread");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		} else
			goto out_no_space;
	}

prep_done:
	if (cmd->preprocessing_only) {
		cmd->preprocessing_only = 0;

		if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
			TRACE_MGMT_DBG("ABORTED set, returning ABORTED for "
				"cmd %p", cmd);
			scst_set_cmd_abnormal_done_state(cmd);
			res = SCST_CMD_STATE_RES_CONT_SAME;
			goto out;
		}

		res = SCST_CMD_STATE_RES_CONT_NEXT;
		cmd->state = SCST_CMD_STATE_PREPROCESS_DONE;

		TRACE_DBG("Calling preprocessing_done(cmd %p)", cmd);
		cmd->tgtt->preprocessing_done(cmd);
		TRACE_DBG("%s", "preprocessing_done() returned");
		goto out;

	}

	if (cmd->data_direction & SCST_DATA_WRITE)
		cmd->state = SCST_CMD_STATE_RDY_TO_XFER;
	else
		cmd->state = SCST_CMD_STATE_TGT_PRE_EXEC;

out:
	TRACE_EXIT_HRES(res);
	return res;

out_no_space:
	TRACE(TRACE_OUT_OF_MEM, "Unable to allocate or build requested buffer "
		"(size %d), sending BUSY or QUEUE FULL status", cmd->bufflen);
	scst_set_busy(cmd);
	scst_set_cmd_abnormal_done_state(cmd);
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;

out_error:
	scst_set_cmd_error(cmd,	SCST_LOAD_SENSE(scst_sense_hardw_error));
	scst_set_cmd_abnormal_done_state(cmd);
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

void scst_restart_cmd(struct scst_cmd *cmd, int status,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d", pref_context);
	TRACE_DBG("tag=%llu, status=%#x",
		  (long long unsigned int)scst_cmd_get_tag(cmd),
		  status);

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((in_irq() || irqs_disabled()) &&
	    ((pref_context == SCST_CONTEXT_DIRECT) ||
	     (pref_context == SCST_CONTEXT_DIRECT_ATOMIC))) {
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_THREAD instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_THREAD;
	}
#endif

	switch (status) {
	case SCST_PREPROCESS_STATUS_SUCCESS:
		if (cmd->data_direction & SCST_DATA_WRITE)
			cmd->state = SCST_CMD_STATE_RDY_TO_XFER;
		else
			cmd->state = SCST_CMD_STATE_TGT_PRE_EXEC;
		if (cmd->set_sn_on_restart_cmd)
			scst_cmd_set_sn(cmd);
		/* Small context optimization */
		if ((pref_context == SCST_CONTEXT_TASKLET) ||
		    (pref_context == SCST_CONTEXT_DIRECT_ATOMIC) ||
		    ((pref_context == SCST_CONTEXT_SAME) &&
		     scst_cmd_atomic(cmd))) {
			if (cmd->data_direction & SCST_DATA_WRITE) {
				if (!test_bit(SCST_TGT_DEV_AFTER_RESTART_WR_ATOMIC,
						&cmd->tgt_dev->tgt_dev_flags))
					pref_context = SCST_CONTEXT_THREAD;
			} else {
				if (!test_bit(SCST_TGT_DEV_AFTER_RESTART_OTH_ATOMIC,
						&cmd->tgt_dev->tgt_dev_flags))
					pref_context = SCST_CONTEXT_THREAD;
			}
		}
		break;

	case SCST_PREPROCESS_STATUS_ERROR_SENSE_SET:
		scst_set_cmd_abnormal_done_state(cmd);
		break;

	case SCST_PREPROCESS_STATUS_ERROR_FATAL:
		set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
		/* go through */
	case SCST_PREPROCESS_STATUS_ERROR:
		if (cmd->sense != NULL)
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
		break;

	default:
		PRINT_ERROR("%s() received unknown status %x", __func__,
			status);
		scst_set_cmd_abnormal_done_state(cmd);
		break;
	}

	scst_proccess_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_restart_cmd);

static int scst_rdy_to_xfer(struct scst_cmd *cmd)
{
	int res, rc;
	struct scst_tgt_template *tgtt = cmd->tgtt;

	TRACE_ENTRY();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_dev_done;
	}

	if ((tgtt->rdy_to_xfer == NULL) || unlikely(cmd->internal)) {
		cmd->state = SCST_CMD_STATE_TGT_PRE_EXEC;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		goto out;
	}

	if (unlikely(!tgtt->rdy_to_xfer_atomic && scst_cmd_atomic(cmd))) {
		/*
		 * It shouldn't be because of SCST_TGT_DEV_AFTER_*
		 * optimization.
		 */
		TRACE_DBG("Target driver %s rdy_to_xfer() needs thread "
			      "context, rescheduling", tgtt->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	while (1) {
		int finished_cmds = atomic_read(&cmd->tgt->finished_cmds);

		res = SCST_CMD_STATE_RES_CONT_NEXT;
		cmd->state = SCST_CMD_STATE_DATA_WAIT;

		if (tgtt->on_hw_pending_cmd_timeout != NULL) {
			struct scst_session *sess = cmd->sess;
			cmd->hw_pending_start = jiffies;
			cmd->cmd_hw_pending = 1;
			if (!test_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED, &sess->sess_aflags)) {
				TRACE_DBG("Sched HW pending work for sess %p "
					"(max time %d)", sess,
					tgtt->max_hw_pending_time);
				set_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED,
					&sess->sess_aflags);
				schedule_delayed_work(&sess->hw_pending_work,
					tgtt->max_hw_pending_time * HZ);
			}
		}

		TRACE_DBG("Calling rdy_to_xfer(%p)", cmd);
#ifdef CONFIG_SCST_DEBUG_RETRY
		if (((scst_random() % 100) == 75))
			rc = SCST_TGT_RES_QUEUE_FULL;
		else
#endif
			rc = tgtt->rdy_to_xfer(cmd);
		TRACE_DBG("rdy_to_xfer() returned %d", rc);

		if (likely(rc == SCST_TGT_RES_SUCCESS))
			goto out;

		cmd->cmd_hw_pending = 0;

		/* Restore the previous state */
		cmd->state = SCST_CMD_STATE_RDY_TO_XFER;

		switch (rc) {
		case SCST_TGT_RES_QUEUE_FULL:
			if (scst_queue_retry_cmd(cmd, finished_cmds) == 0)
				break;
			else
				continue;

		case SCST_TGT_RES_NEED_THREAD_CTX:
			TRACE_DBG("Target driver %s "
			      "rdy_to_xfer() requested thread "
			      "context, rescheduling", tgtt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			break;

		default:
			goto out_error_rc;
		}
		break;
	}

out:
	TRACE_EXIT_HRES(res);
	return res;

out_error_rc:
	if (rc == SCST_TGT_RES_FATAL_ERROR) {
		PRINT_ERROR("Target driver %s rdy_to_xfer() returned "
		     "fatal error", tgtt->name);
	} else {
		PRINT_ERROR("Target driver %s rdy_to_xfer() returned invalid "
			    "value %d", tgtt->name, rc);
	}
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

out_dev_done:
	scst_set_cmd_abnormal_done_state(cmd);
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

/* No locks, but might be in IRQ */
static void scst_proccess_redirect_cmd(struct scst_cmd *cmd,
	enum scst_exec_context context, int check_retries)
{
	struct scst_tgt *tgt = cmd->tgt;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_DBG("Context: %x", context);

	if (context == SCST_CONTEXT_SAME)
		context = scst_cmd_atomic(cmd) ? SCST_CONTEXT_DIRECT_ATOMIC :
						 SCST_CONTEXT_DIRECT;

	switch (context) {
	case SCST_CONTEXT_DIRECT_ATOMIC:
		scst_process_active_cmd(cmd, true);
		break;

	case SCST_CONTEXT_DIRECT:
		if (check_retries)
			scst_check_retries(tgt);
		scst_process_active_cmd(cmd, false);
		break;

	default:
		PRINT_ERROR("Context %x is unknown, using the thread one",
			    context);
		/* go through */
	case SCST_CONTEXT_THREAD:
		if (check_retries)
			scst_check_retries(tgt);
		spin_lock_irqsave(&cmd->cmd_lists->cmd_list_lock, flags);
		TRACE_DBG("Adding cmd %p to active cmd list", cmd);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		wake_up(&cmd->cmd_lists->cmd_list_waitQ);
		spin_unlock_irqrestore(&cmd->cmd_lists->cmd_list_lock, flags);
		break;

	case SCST_CONTEXT_TASKLET:
		if (check_retries)
			scst_check_retries(tgt);
		scst_schedule_tasklet(cmd);
		break;
	}

	TRACE_EXIT();
	return;
}

void scst_rx_data(struct scst_cmd *cmd, int status,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d", pref_context);
	TRACE(TRACE_SCSI, "cmd %p, status %#x", cmd, status);

	cmd->cmd_hw_pending = 0;

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((in_irq() || irqs_disabled()) &&
	    ((pref_context == SCST_CONTEXT_DIRECT) ||
	     (pref_context == SCST_CONTEXT_DIRECT_ATOMIC))) {
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_THREAD instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_THREAD;
	}
#endif

	switch (status) {
	case SCST_RX_STATUS_SUCCESS:
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
		if (trace_flag & TRACE_RCV_BOT) {
			int i;
			struct scatterlist *sg;
			if (cmd->in_sg != NULL)
				sg = cmd->in_sg;
			else if (cmd->tgt_in_sg != NULL)
				sg = cmd->tgt_in_sg;
			else if (cmd->tgt_sg != NULL)
				sg = cmd->tgt_sg;
			else
				sg = cmd->sg;
			if (sg != NULL) {
				TRACE_RECV_BOT("RX data for cmd %p "
					"(sg_cnt %d, sg %p, sg[0].page %p)",
					cmd, cmd->tgt_sg_cnt, sg,
					(void *)sg_page(&sg[0]));
				for (i = 0; i < cmd->tgt_sg_cnt; ++i) {
					PRINT_BUFF_FLAG(TRACE_RCV_BOT, "RX sg",
						sg_virt(&sg[i]), sg[i].length);
				}
			}
		}
#endif
		cmd->state = SCST_CMD_STATE_TGT_PRE_EXEC;
		/* Small context optimization */
		if ((pref_context == SCST_CONTEXT_TASKLET) ||
		    (pref_context == SCST_CONTEXT_DIRECT_ATOMIC) ||
		    ((pref_context == SCST_CONTEXT_SAME) &&
		     scst_cmd_atomic(cmd))) {
			if (!test_bit(SCST_TGT_DEV_AFTER_RX_DATA_ATOMIC,
					&cmd->tgt_dev->tgt_dev_flags))
				pref_context = SCST_CONTEXT_THREAD;
		}
		break;

	case SCST_RX_STATUS_ERROR_SENSE_SET:
		scst_set_cmd_abnormal_done_state(cmd);
		break;

	case SCST_RX_STATUS_ERROR_FATAL:
		set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
		/* go through */
	case SCST_RX_STATUS_ERROR:
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
		break;

	default:
		PRINT_ERROR("scst_rx_data() received unknown status %x",
			status);
		scst_set_cmd_abnormal_done_state(cmd);
		break;
	}

	scst_proccess_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_rx_data);

static int scst_tgt_pre_exec(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME, rc;

	TRACE_ENTRY();

	cmd->state = SCST_CMD_STATE_SEND_FOR_EXEC;

	if ((cmd->tgtt->pre_exec == NULL) || unlikely(cmd->internal))
		goto out;

	TRACE_DBG("Calling pre_exec(%p)", cmd);
	rc = cmd->tgtt->pre_exec(cmd);
	TRACE_DBG("pre_exec() returned %d", rc);

	if (unlikely(rc != SCST_PREPROCESS_STATUS_SUCCESS)) {
		switch (rc) {
		case SCST_PREPROCESS_STATUS_ERROR_SENSE_SET:
			scst_set_cmd_abnormal_done_state(cmd);
			break;
		case SCST_PREPROCESS_STATUS_ERROR_FATAL:
			set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
			/* go through */
		case SCST_PREPROCESS_STATUS_ERROR:
			scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
			scst_set_cmd_abnormal_done_state(cmd);
			break;
		case SCST_PREPROCESS_STATUS_NEED_THREAD:
			TRACE_DBG("Target driver's %s pre_exec() requested "
				"thread context, rescheduling",
				cmd->tgtt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			cmd->state = SCST_CMD_STATE_TGT_PRE_EXEC;
			break;
		default:
			sBUG();
			break;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void scst_do_cmd_done(struct scst_cmd *cmd, int result,
	const uint8_t *rq_sense, int rq_sense_len, int resid)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_MEASURE_LATENCY
	{
		struct timespec ts;
		getnstimeofday(&ts);
		cmd->post_exec_start = scst_sec_to_nsec(ts.tv_sec) + ts.tv_nsec;
		TRACE_DBG("cmd %p (sess %p): post_exec_start %lld (tv_sec %ld, "
			"tv_nsec %ld)", cmd, cmd->sess, cmd->post_exec_start,
			ts.tv_sec, ts.tv_nsec);
	}
#endif

	cmd->status = result & 0xff;
	cmd->msg_status = msg_byte(result);
	cmd->host_status = host_byte(result);
	cmd->driver_status = driver_byte(result);
	if (unlikely(resid != 0)) {
#ifdef CONFIG_SCST_EXTRACHECKS
		if ((resid < 0) || (resid > cmd->resp_data_len)) {
			PRINT_ERROR("Wrong resid %d (cmd->resp_data_len=%d, "
				"op %x)", resid, cmd->resp_data_len,
				cmd->cdb[0]);
		} else
#endif
			scst_set_resp_data_len(cmd, cmd->resp_data_len - resid);
	}

	if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION)) {
		/* We might have double reset UA here */
		cmd->dbl_ua_orig_resp_data_len = cmd->resp_data_len;
		cmd->dbl_ua_orig_data_direction = cmd->data_direction;

		scst_alloc_set_sense(cmd, 1, rq_sense, rq_sense_len);
	}

	TRACE(TRACE_SCSI, "cmd %p, result=%x, cmd->status=%x, resid=%d, "
	      "cmd->msg_status=%x, cmd->host_status=%x, "
	      "cmd->driver_status=%x (cmd %p)", cmd, result, cmd->status, resid,
	      cmd->msg_status, cmd->host_status, cmd->driver_status, cmd);

	cmd->completed = 1;

	TRACE_EXIT();
	return;
}

/* For small context optimization */
static inline enum scst_exec_context scst_optimize_post_exec_context(
	struct scst_cmd *cmd, enum scst_exec_context context)
{
	if (((context == SCST_CONTEXT_SAME) && scst_cmd_atomic(cmd)) ||
	    (context == SCST_CONTEXT_TASKLET) ||
	    (context == SCST_CONTEXT_DIRECT_ATOMIC)) {
		if (!test_bit(SCST_TGT_DEV_AFTER_EXEC_ATOMIC,
				&cmd->tgt_dev->tgt_dev_flags))
			context = SCST_CONTEXT_THREAD;
	}
	return context;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
static inline struct scst_cmd *scst_get_cmd(struct scsi_cmnd *scsi_cmd,
					    struct scsi_request **req)
{
	struct scst_cmd *cmd = NULL;

	if (scsi_cmd && (*req = scsi_cmd->sc_request))
		cmd = (struct scst_cmd *)(*req)->upper_private_data;

	if (cmd == NULL) {
		PRINT_ERROR("%s", "Request with NULL cmd");
		if (*req)
			scsi_release_request(*req);
	}

	return cmd;
}

static void scst_cmd_done(struct scsi_cmnd *scsi_cmd)
{
	struct scsi_request *req = NULL;
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	cmd = scst_get_cmd(scsi_cmd, &req);
	if (cmd == NULL)
		goto out;

	scst_do_cmd_done(cmd, req->sr_result, req->sr_sense_buffer,
		sizeof(req->sr_sense_buffer), scsi_cmd->resid);

	/* Clear out request structure */
	req->sr_use_sg = 0;
	req->sr_sglist_len = 0;
	req->sr_bufflen = 0;
	req->sr_buffer = NULL;
	req->sr_underflow = 0;
	req->sr_request->rq_disk = NULL; /* disown request blk */

	scst_release_request(cmd);

	cmd->state = SCST_CMD_STATE_PRE_DEV_DONE;

	scst_proccess_redirect_cmd(cmd,
		scst_optimize_post_exec_context(cmd, scst_estimate_context()),
						0);

out:
	TRACE_EXIT();
	return;
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18) */
static void scst_cmd_done(void *data, char *sense, int result, int resid)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	cmd = (struct scst_cmd *)data;
	if (cmd == NULL)
		goto out;

	scst_do_cmd_done(cmd, result, sense, SCSI_SENSE_BUFFERSIZE, resid);

	cmd->state = SCST_CMD_STATE_PRE_DEV_DONE;

	scst_proccess_redirect_cmd(cmd,
	    scst_optimize_post_exec_context(cmd, scst_estimate_context()), 0);

out:
	TRACE_EXIT();
	return;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18) */

static void scst_cmd_done_local(struct scst_cmd *cmd, int next_state,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_MEASURE_LATENCY
	{
		struct timespec ts;
		getnstimeofday(&ts);
		cmd->post_exec_start = scst_sec_to_nsec(ts.tv_sec) + ts.tv_nsec;
		TRACE_DBG("cmd %p (sess %p): post_exec_start %lld (tv_sec %ld, "
			"tv_nsec %ld)", cmd, cmd->sess, cmd->post_exec_start,
			ts.tv_sec, ts.tv_nsec);
	}
#endif

	if (next_state == SCST_CMD_STATE_DEFAULT)
		next_state = SCST_CMD_STATE_PRE_DEV_DONE;

#if defined(CONFIG_SCST_DEBUG)
	if (next_state == SCST_CMD_STATE_PRE_DEV_DONE) {
		if ((trace_flag & TRACE_RCV_TOP) && (cmd->sg != NULL)) {
			int i;
			struct scatterlist *sg = cmd->sg;
			TRACE_RECV_TOP("Exec'd %d S/G(s) at %p sg[0].page at "
				"%p", cmd->sg_cnt, sg, (void *)sg_page(&sg[0]));
			for (i = 0; i < cmd->sg_cnt; ++i) {
				TRACE_BUFF_FLAG(TRACE_RCV_TOP,
					"Exec'd sg", sg_virt(&sg[i]),
					sg[i].length);
			}
		}
	}
#endif

	cmd->state = next_state;

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((next_state != SCST_CMD_STATE_PRE_DEV_DONE) &&
	    (next_state != SCST_CMD_STATE_PRE_XMIT_RESP) &&
	    (next_state != SCST_CMD_STATE_FINISHED) &&
	    (next_state != SCST_CMD_STATE_FINISHED_INTERNAL)) {
		PRINT_ERROR("%s() received invalid cmd state %d (opcode %d)",
			__func__, next_state, cmd->cdb[0]);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
	}
#endif
	pref_context = scst_optimize_post_exec_context(cmd, pref_context);
	scst_proccess_redirect_cmd(cmd, pref_context, 0);

	TRACE_EXIT();
	return;
}

static int scst_report_luns_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED, rc;
	int dev_cnt = 0;
	int buffer_size;
	int i;
	struct scst_tgt_dev *tgt_dev = NULL;
	uint8_t *buffer;
	int offs, overflow = 0;

	TRACE_ENTRY();

	if (scst_cmd_atomic(cmd)) {
		res = SCST_EXEC_NEED_THREAD;
		goto out;
	}

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if ((cmd->cdb[2] != 0) && (cmd->cdb[2] != 2)) {
		PRINT_ERROR("Unsupported SELECT REPORT value %x in REPORT "
			"LUNS command", cmd->cdb[2]);
		goto out_err;
	}

	buffer_size = scst_get_buf_first(cmd, &buffer);
	if (unlikely(buffer_size == 0))
		goto out_compl;
	else if (unlikely(buffer_size < 0))
		goto out_hw_err;

	if (buffer_size < 16)
		goto out_put_err;

	memset(buffer, 0, buffer_size);
	offs = 8;

	/*
	 * cmd won't allow to suspend activities, so we can access
	 * sess->sess_tgt_dev_list_hash without any additional protection.
	 */
	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&cmd->sess->sess_tgt_dev_list_hash[i];
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			if (!overflow) {
				if (offs >= buffer_size) {
					scst_put_buf(cmd, buffer);
					buffer_size = scst_get_buf_next(cmd,
								       &buffer);
					if (buffer_size > 0) {
						memset(buffer, 0, buffer_size);
						offs = 0;
					} else {
						overflow = 1;
						goto inc_dev_cnt;
					}
				}
				if ((buffer_size - offs) < 8) {
					PRINT_ERROR("Buffer allocated for "
						"REPORT LUNS command doesn't "
						"allow to fit 8 byte entry "
						"(buffer_size=%d)",
						buffer_size);
					goto out_put_hw_err;
				}
				buffer[offs] = (tgt_dev->lun >> 8) & 0xff;
				buffer[offs+1] = tgt_dev->lun & 0xff;
				offs += 8;
			}
inc_dev_cnt:
			dev_cnt++;
		}
	}
	if (!overflow)
		scst_put_buf(cmd, buffer);

	/* Set the response header */
	buffer_size = scst_get_buf_first(cmd, &buffer);
	if (unlikely(buffer_size == 0))
		goto out_compl;
	else if (unlikely(buffer_size < 0))
		goto out_hw_err;

	dev_cnt *= 8;
	buffer[0] = (dev_cnt >> 24) & 0xff;
	buffer[1] = (dev_cnt >> 16) & 0xff;
	buffer[2] = (dev_cnt >> 8) & 0xff;
	buffer[3] = dev_cnt & 0xff;

	scst_put_buf(cmd, buffer);

	dev_cnt += 8;
	if (dev_cnt < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, dev_cnt);

out_compl:
	cmd->completed = 1;

	/* Clear left sense_reported_luns_data_changed UA, if any. */

	/*
	 * cmd won't allow to suspend activities, so we can access
	 * sess->sess_tgt_dev_list_hash without any additional protection.
	 */
	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&cmd->sess->sess_tgt_dev_list_hash[i];

		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			struct scst_tgt_dev_UA *ua;

			spin_lock_bh(&tgt_dev->tgt_dev_lock);
			list_for_each_entry(ua, &tgt_dev->UA_list,
						UA_list_entry) {
				if (scst_analyze_sense(ua->UA_sense_buffer,
						sizeof(ua->UA_sense_buffer),
						SCST_SENSE_ALL_VALID,
						SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed))) {
					TRACE_MGMT_DBG("Freeing not needed "
						"REPORTED LUNS DATA CHANGED UA "
						"%p", ua);
					list_del(&ua->UA_list_entry);
					mempool_free(ua, scst_ua_mempool);
					break;
				}
			}
			spin_unlock_bh(&tgt_dev->tgt_dev_lock);
		}
	}

out_done:
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

out:
	TRACE_EXIT_RES(res);
	return res;

out_put_err:
	scst_put_buf(cmd, buffer);

out_err:
	scst_set_cmd_error(cmd,
		   SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	goto out_compl;

out_put_hw_err:
	scst_put_buf(cmd, buffer);

out_hw_err:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_compl;
}

static int scst_request_sense_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED, rc;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	uint8_t *buffer;
	int buffer_size = 0;

	TRACE_ENTRY();

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	spin_lock_bh(&tgt_dev->tgt_dev_lock);

	if (tgt_dev->tgt_dev_valid_sense_len == 0)
		goto out_not_completed;

	TRACE(TRACE_SCSI, "%s: Returning stored sense", cmd->op_name);

	buffer_size = scst_get_buf_first(cmd, &buffer);
	if (unlikely(buffer_size == 0))
		goto out_compl;
	else if (unlikely(buffer_size < 0))
		goto out_hw_err;

	memset(buffer, 0, buffer_size);

	if (((tgt_dev->tgt_dev_sense[0] == 0x70) ||
	     (tgt_dev->tgt_dev_sense[0] == 0x71)) && (cmd->cdb[1] & 1)) {
		PRINT_WARNING("%s: Fixed format of the saved sense, but "
			"descriptor format requested. Convertion will "
			"truncated data", cmd->op_name);
		PRINT_BUFFER("Original sense", tgt_dev->tgt_dev_sense,
			tgt_dev->tgt_dev_valid_sense_len);

		buffer_size = min(SCST_STANDARD_SENSE_LEN, buffer_size);
		scst_set_sense(buffer, buffer_size, true,
			tgt_dev->tgt_dev_sense[2], tgt_dev->tgt_dev_sense[12],
			tgt_dev->tgt_dev_sense[13]);
	} else if (((tgt_dev->tgt_dev_sense[0] == 0x72) ||
		    (tgt_dev->tgt_dev_sense[0] == 0x73)) && !(cmd->cdb[1] & 1)) {
		PRINT_WARNING("%s: Descriptor format of the "
			"saved sense, but fixed format requested. Convertion "
			"will truncated data", cmd->op_name);
		PRINT_BUFFER("Original sense", tgt_dev->tgt_dev_sense,
			tgt_dev->tgt_dev_valid_sense_len);

		buffer_size = min(SCST_STANDARD_SENSE_LEN, buffer_size);
		scst_set_sense(buffer, buffer_size, false,
			tgt_dev->tgt_dev_sense[1], tgt_dev->tgt_dev_sense[2],
			tgt_dev->tgt_dev_sense[3]);
	} else {
		if (buffer_size >= tgt_dev->tgt_dev_valid_sense_len)
			buffer_size = tgt_dev->tgt_dev_valid_sense_len;
		else {
			PRINT_WARNING("%s: Being returned sense truncated to "
				"size %d (needed %d)", cmd->op_name,
				buffer_size, tgt_dev->tgt_dev_valid_sense_len);
		}
		memcpy(buffer, tgt_dev->tgt_dev_sense, buffer_size);
	}

	scst_put_buf(cmd, buffer);

out_compl:
	tgt_dev->tgt_dev_valid_sense_len = 0;
	scst_set_resp_data_len(cmd, buffer_size);

	spin_unlock_bh(&tgt_dev->tgt_dev_lock);

	cmd->completed = 1;

out_done:
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

out:
	TRACE_EXIT_RES(res);
	return res;

out_hw_err:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_compl;

out_not_completed:
	spin_unlock_bh(&tgt_dev->tgt_dev_lock);
	res = SCST_EXEC_NOT_COMPLETED;
	goto out;
}

static int scst_pre_select(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;

	TRACE_ENTRY();

	if (scst_cmd_atomic(cmd)) {
		res = SCST_EXEC_NEED_THREAD;
		goto out;
	}

	scst_block_dev_cmd(cmd, 1);

	/* Check for local events will be done when cmd will be executed */

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_reserve_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED, rc;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev_tmp;

	TRACE_ENTRY();

	if (scst_cmd_atomic(cmd)) {
		res = SCST_EXEC_NEED_THREAD;
		goto out;
	}

	if ((cmd->cdb[0] == RESERVE_10) && (cmd->cdb[2] & SCST_RES_3RDPTY)) {
		PRINT_ERROR("RESERVE_10: 3rdPty RESERVE not implemented "
		     "(lun=%lld)", (long long unsigned int)cmd->lun);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_done;
	}

	dev = cmd->dev;

	if (dev->tst == SCST_CONTR_MODE_ONE_TASK_SET)
		scst_block_dev_cmd(cmd, 1);

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	spin_lock_bh(&dev->dev_lock);

	if (test_bit(SCST_TGT_DEV_RESERVED, &cmd->tgt_dev->tgt_dev_flags)) {
		spin_unlock_bh(&dev->dev_lock);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_done;
	}

	list_for_each_entry(tgt_dev_tmp, &dev->dev_tgt_dev_list,
			    dev_tgt_dev_list_entry) {
		if (cmd->tgt_dev != tgt_dev_tmp)
			set_bit(SCST_TGT_DEV_RESERVED,
				&tgt_dev_tmp->tgt_dev_flags);
	}
	dev->dev_reserved = 1;

	spin_unlock_bh(&dev->dev_lock);

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	res = SCST_EXEC_COMPLETED;
	goto out;
}

static int scst_release_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED, rc;
	struct scst_tgt_dev *tgt_dev_tmp;
	struct scst_device *dev;

	TRACE_ENTRY();

	if (scst_cmd_atomic(cmd)) {
		res = SCST_EXEC_NEED_THREAD;
		goto out;
	}

	dev = cmd->dev;

	if (dev->tst == SCST_CONTR_MODE_ONE_TASK_SET)
		scst_block_dev_cmd(cmd, 1);

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	spin_lock_bh(&dev->dev_lock);

	/*
	 * The device could be RELEASED behind us, if RESERVING session
	 * is closed (see scst_free_tgt_dev()), but this actually doesn't
	 * matter, so use lock and no retest for DEV_RESERVED bits again
	 */
	if (test_bit(SCST_TGT_DEV_RESERVED, &cmd->tgt_dev->tgt_dev_flags)) {
		res = SCST_EXEC_COMPLETED;
		cmd->status = 0;
		cmd->msg_status = 0;
		cmd->host_status = DID_OK;
		cmd->driver_status = 0;
		cmd->completed = 1;
	} else {
		list_for_each_entry(tgt_dev_tmp,
				    &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			clear_bit(SCST_TGT_DEV_RESERVED,
				&tgt_dev_tmp->tgt_dev_flags);
		}
		dev->dev_reserved = 0;
	}

	spin_unlock_bh(&dev->dev_lock);

	if (res == SCST_EXEC_COMPLETED)
		goto out_done;

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	res = SCST_EXEC_COMPLETED;
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

/* No locks, no IRQ or IRQ-disabled context allowed */
int scst_check_local_events(struct scst_cmd *cmd)
{
	int res, rc;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	/*
	 * There's no race here, because we need to trace commands sent
	 * *after* dev_double_ua_possible flag was set.
	 */
	if (unlikely(dev->dev_double_ua_possible))
		cmd->double_ua_possible = 1;

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_uncomplete;
	}

	/* Reserve check before Unit Attention */
	if (unlikely(test_bit(SCST_TGT_DEV_RESERVED,
			      &tgt_dev->tgt_dev_flags))) {
		if (cmd->cdb[0] != INQUIRY &&
		    cmd->cdb[0] != REPORT_LUNS &&
		    cmd->cdb[0] != RELEASE &&
		    cmd->cdb[0] != RELEASE_10 &&
		    cmd->cdb[0] != REPORT_DEVICE_IDENTIFIER &&
		    (cmd->cdb[0] != ALLOW_MEDIUM_REMOVAL ||
		     (cmd->cdb[4] & 3)) &&
		    cmd->cdb[0] != LOG_SENSE &&
		    cmd->cdb[0] != REQUEST_SENSE) {
			scst_set_cmd_error_status(cmd,
				SAM_STAT_RESERVATION_CONFLICT);
			goto out_complete;
		}
	}

	/* If we had internal bus reset, set the command error unit attention */
	if ((dev->scsi_dev != NULL) &&
	    unlikely(dev->scsi_dev->was_reset)) {
		if (scst_is_ua_command(cmd)) {
			int done = 0;
			/*
			 * Prevent more than 1 cmd to be triggered by
			 * was_reset.
			 */
			spin_lock_bh(&dev->dev_lock);
			if (dev->scsi_dev->was_reset) {
				TRACE(TRACE_MGMT, "was_reset is %d", 1);
				scst_set_cmd_error(cmd,
					  SCST_LOAD_SENSE(scst_sense_reset_UA));
				/*
				 * It looks like it is safe to clear was_reset
				 * here.
				 */
				dev->scsi_dev->was_reset = 0;
				done = 1;
			}
			spin_unlock_bh(&dev->dev_lock);

			if (done)
				goto out_complete;
		}
	}

	if (unlikely(test_bit(SCST_TGT_DEV_UA_PENDING,
			&cmd->tgt_dev->tgt_dev_flags))) {
		if (scst_is_ua_command(cmd)) {
			rc = scst_set_pending_UA(cmd);
			if (rc == 0)
				goto out_complete;
		}
	}

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_complete:
	res = 1;
	sBUG_ON(!cmd->completed);
	goto out;

out_uncomplete:
	res = -1;
	goto out;
}
EXPORT_SYMBOL(scst_check_local_events);

/* No locks */
void scst_inc_expected_sn(struct scst_tgt_dev *tgt_dev, atomic_t *slot)
{
	if (slot == NULL)
		goto inc;

	/* Optimized for lockless fast path */

	TRACE_SN("Slot %zd, *cur_sn_slot %d", slot - tgt_dev->sn_slots,
		atomic_read(slot));

	if (!atomic_dec_and_test(slot))
		goto out;

	TRACE_SN("Slot is 0 (num_free_sn_slots=%d)",
		tgt_dev->num_free_sn_slots);
	if (tgt_dev->num_free_sn_slots < (int)ARRAY_SIZE(tgt_dev->sn_slots)-1) {
		spin_lock_irq(&tgt_dev->sn_lock);
		if (likely(tgt_dev->num_free_sn_slots < (int)ARRAY_SIZE(tgt_dev->sn_slots)-1)) {
			if (tgt_dev->num_free_sn_slots < 0)
				tgt_dev->cur_sn_slot = slot;
			/*
			 * To be in-sync with SIMPLE case in scst_cmd_set_sn()
			 */
			smp_mb();
			tgt_dev->num_free_sn_slots++;
			TRACE_SN("Incremented num_free_sn_slots (%d)",
				tgt_dev->num_free_sn_slots);

		}
		spin_unlock_irq(&tgt_dev->sn_lock);
	}

inc:
	/*
	 * No protection of expected_sn is needed, because only one thread
	 * at time can be here (serialized by sn). Also it is supposed that
	 * there could not be half-incremented halves.
	 */
	tgt_dev->expected_sn++;
	/*
	 * Write must be before def_cmd_count read to be in sync. with
	 * scst_post_exec_sn(). See comment in scst_send_for_exec().
	 */
	smp_mb();
	TRACE_SN("Next expected_sn: %ld", tgt_dev->expected_sn);

out:
	return;
}

/* No locks */
static struct scst_cmd *scst_post_exec_sn(struct scst_cmd *cmd,
	bool make_active)
{
	/* For HQ commands SN is not set */
	bool inc_expected_sn = !cmd->inc_expected_sn_on_done &&
			       cmd->sn_set && !cmd->retry;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_cmd *res;

	TRACE_ENTRY();

	if (inc_expected_sn)
		scst_inc_expected_sn(tgt_dev, cmd->sn_slot);

	if (make_active) {
		scst_make_deferred_commands_active(tgt_dev);
		res = NULL;
	} else
		res = scst_check_deferred_commands(tgt_dev);

	TRACE_EXIT_HRES(res);
	return res;
}

/* cmd must be additionally referenced to not die inside */
static int scst_do_real_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
	int rc;
#endif
	bool atomic = scst_cmd_atomic(cmd);
	struct scst_device *dev = cmd->dev;
	struct scst_dev_type *handler = dev->handler;
	struct io_context *old_ctx = NULL;
	bool ctx_changed = false;

	TRACE_ENTRY();

	if (!atomic)
		ctx_changed = scst_set_io_context(cmd, &old_ctx);

	cmd->state = SCST_CMD_STATE_REAL_EXECUTING;

	if (handler->exec) {
		if (unlikely(!dev->handler->exec_atomic && atomic)) {
			/*
			 * It shouldn't be because of SCST_TGT_DEV_AFTER_*
			 * optimization.
			 */
			TRACE_DBG("Dev handler %s exec() needs thread "
				"context, rescheduling", dev->handler->name);
			res = SCST_EXEC_NEED_THREAD;
			goto out_restore;
		}

		TRACE_DBG("Calling dev handler %s exec(%p)",
		      handler->name, cmd);
		TRACE_BUFF_FLAG(TRACE_SND_TOP, "Execing: ", cmd->cdb,
			cmd->cdb_len);
		res = handler->exec(cmd);
		TRACE_DBG("Dev handler %s exec() returned %d",
		      handler->name, res);

		if (res == SCST_EXEC_COMPLETED)
			goto out_complete;
		else if (res == SCST_EXEC_NEED_THREAD)
			goto out_restore;

		sBUG_ON(res != SCST_EXEC_NOT_COMPLETED);
	}

	TRACE_DBG("Sending cmd %p to SCSI mid-level", cmd);

	if (unlikely(dev->scsi_dev == NULL)) {
		PRINT_ERROR("Command for virtual device must be "
			"processed by device handler (LUN %lld)!",
			(long long unsigned int)cmd->lun);
		goto out_error;
	}

	res = scst_check_local_events(cmd);
	if (unlikely(res != 0))
		goto out_done;

#ifndef CONFIG_SCST_ALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ
	if (unlikely(atomic)) {
		TRACE_DBG("Pass-through exec() can not be called in atomic "
			"context, rescheduling to the thread (handler %s)",
			handler->name);
		res = SCST_EXEC_NEED_THREAD;
		goto out_restore;
	}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
	if (unlikely(scst_alloc_request(cmd) != 0)) {
		if (atomic) {
			res = SCST_EXEC_NEED_THREAD;
			goto out_restore;
		} else {
			PRINT_INFO("%s", "Unable to allocate request, "
				"sending BUSY status");
			goto out_busy;
		}
	}

	scst_do_req(cmd->scsi_req, (void *)cmd->cdb,
		    (void *)cmd->scsi_req->sr_buffer,
		    cmd->scsi_req->sr_bufflen, scst_cmd_done, cmd->timeout,
		    cmd->retries);
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	rc = scst_exec_req(dev->scsi_dev, cmd->cdb, cmd->cdb_len,
			cmd->data_direction, cmd->sg, cmd->bufflen, cmd->sg_cnt,
			cmd->timeout, cmd->retries, cmd, scst_cmd_done,
			atomic ? GFP_ATOMIC : GFP_KERNEL);
#else
	rc = scsi_execute_async(dev->scsi_dev, cmd->cdb, cmd->cdb_len,
			cmd->data_direction, cmd->sg, cmd->sg_cnt,
			cmd->timeout, cmd->retries, cmd, scst_cmd_done,
			atomic ? GFP_ATOMIC : GFP_KERNEL,
			cmd->tgt_data_buf_alloced ? 0 :
				SCSI_ASYNC_EXEC_FLAG_HAS_TAIL_SPACE_FOR_PADDING);
#endif
	if (unlikely(rc != 0)) {
		if (atomic) {
			res = SCST_EXEC_NEED_THREAD;
			goto out_restore;
		} else {
			PRINT_ERROR("scst_exec_req() failed: %x", rc);
			goto out_error;
		}
	}
#endif

out_complete:
	res = SCST_EXEC_COMPLETED;

out_reset_ctx:
	if (ctx_changed)
		scst_reset_io_context(cmd->tgt_dev, old_ctx);

	TRACE_EXIT();
	return res;

out_restore:
	/* Restore the state */
	cmd->state = SCST_CMD_STATE_REAL_EXEC;
	goto out_reset_ctx;

out_error:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_done;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
out_busy:
	scst_set_busy(cmd);
	/* go through */
#endif

out_done:
	res = SCST_EXEC_COMPLETED;
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out_complete;
}

static inline int scst_real_exec(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_SAME != SCST_EXEC_NOT_COMPLETED);
	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_NEXT != SCST_EXEC_COMPLETED);
	BUILD_BUG_ON(SCST_CMD_STATE_RES_NEED_THREAD != SCST_EXEC_NEED_THREAD);

	__scst_cmd_get(cmd);

	res = scst_do_real_exec(cmd);

	if (likely(res == SCST_EXEC_COMPLETED)) {
		scst_post_exec_sn(cmd, true);
		if (cmd->dev->scsi_dev != NULL)
			generic_unplug_device(
				cmd->dev->scsi_dev->request_queue);
	} else
		sBUG_ON(res != SCST_EXEC_NEED_THREAD);

	__scst_cmd_put(cmd);

	/* SCST_EXEC_* match SCST_CMD_STATE_RES_* */

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_do_local_exec(struct scst_cmd *cmd)
{
	int res;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	/* Check READ_ONLY device status */
	if ((cmd->op_flags & SCST_WRITE_MEDIUM) &&
	    (tgt_dev->acg_dev->rd_only || cmd->dev->swp ||
	     cmd->dev->rd_only)) {
		PRINT_WARNING("Attempt of write access to read-only device: "
			"initiator %s, LUN %lld, op %x",
			cmd->sess->initiator_name, cmd->lun, cmd->cdb[0]);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_data_protect));
		goto out_done;
	}

	/*
	 * Adding new commands here don't forget to update
	 * scst_is_cmd_local() in scst.h, if necessary
	 */

	if (!(cmd->op_flags & SCST_LOCAL_EXEC_NEEDED)) {
		res = SCST_EXEC_NOT_COMPLETED;
		goto out;
	}

	switch (cmd->cdb[0]) {
	case MODE_SELECT:
	case MODE_SELECT_10:
	case LOG_SELECT:
		res = scst_pre_select(cmd);
		break;
	case RESERVE:
	case RESERVE_10:
		res = scst_reserve_local(cmd);
		break;
	case RELEASE:
	case RELEASE_10:
		res = scst_release_local(cmd);
		break;
	case REPORT_LUNS:
		res = scst_report_luns_local(cmd);
		break;
	case REQUEST_SENSE:
		res = scst_request_sense_local(cmd);
		break;
	default:
		res = SCST_EXEC_NOT_COMPLETED;
		break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	res = SCST_EXEC_COMPLETED;
	goto out;
}

static int scst_local_exec(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_SAME != SCST_EXEC_NOT_COMPLETED);
	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_NEXT != SCST_EXEC_COMPLETED);
	BUILD_BUG_ON(SCST_CMD_STATE_RES_NEED_THREAD != SCST_EXEC_NEED_THREAD);

	__scst_cmd_get(cmd);

	res = scst_do_local_exec(cmd);
	if (likely(res == SCST_EXEC_NOT_COMPLETED))
		cmd->state = SCST_CMD_STATE_REAL_EXEC;
	else if (res == SCST_EXEC_COMPLETED)
		scst_post_exec_sn(cmd, true);
	else
		sBUG_ON(res != SCST_EXEC_NEED_THREAD);

	__scst_cmd_put(cmd);

	/* SCST_EXEC_* match SCST_CMD_STATE_RES_* */
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_exec(struct scst_cmd **active_cmd)
{
	struct scst_cmd *cmd = *active_cmd;
	struct scst_cmd *ref_cmd;
	struct scst_device *dev = cmd->dev;
	int res = SCST_CMD_STATE_RES_CONT_NEXT, count;

	TRACE_ENTRY();

	if (unlikely(scst_inc_on_dev_cmd(cmd) != 0))
		goto out;

	/* To protect tgt_dev */
	ref_cmd = cmd;
	__scst_cmd_get(ref_cmd);

	count = 0;
	while (1) {
		int rc;

		cmd->sent_for_exec = 1;
		/*
		 * To sync with scst_abort_cmd(). The above assignment must
		 * be before SCST_CMD_ABORTED test, done later in
		 * scst_check_local_events(). It's far from here, so the order
		 * is virtually guaranteed, but let's have it just in case.
		 */
		smp_mb();

		cmd->scst_cmd_done = scst_cmd_done_local;
		cmd->state = SCST_CMD_STATE_LOCAL_EXEC;

		if (cmd->tgt_data_buf_alloced && cmd->dh_data_buf_alloced &&
		    (cmd->data_direction & SCST_DATA_WRITE))
			scst_copy_sg(cmd, SCST_SG_COPY_FROM_TARGET);

		rc = scst_do_local_exec(cmd);
		if (likely(rc == SCST_EXEC_NOT_COMPLETED))
			/* Nothing to do */;
		else if (rc == SCST_EXEC_NEED_THREAD) {
			TRACE_DBG("%s", "scst_do_local_exec() requested "
				"thread context, rescheduling");
			scst_dec_on_dev_cmd(cmd);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			break;
		} else {
			sBUG_ON(rc != SCST_EXEC_COMPLETED);
			goto done;
		}

		cmd->state = SCST_CMD_STATE_REAL_EXEC;

		rc = scst_do_real_exec(cmd);
		if (likely(rc == SCST_EXEC_COMPLETED))
			/* Nothing to do */;
		else if (rc == SCST_EXEC_NEED_THREAD) {
			TRACE_DBG("scst_real_exec() requested thread "
				"context, rescheduling (cmd %p)", cmd);
			scst_dec_on_dev_cmd(cmd);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			break;
		} else
			sBUG();

done:
		count++;

		cmd = scst_post_exec_sn(cmd, false);
		if (cmd == NULL)
			break;

		if (unlikely(scst_inc_on_dev_cmd(cmd) != 0))
			break;

		__scst_cmd_put(ref_cmd);
		ref_cmd = cmd;
		__scst_cmd_get(ref_cmd);
	}

	*active_cmd = cmd;

	if (count == 0)
		goto out_put;

	if (dev->scsi_dev != NULL)
		generic_unplug_device(dev->scsi_dev->request_queue);

out_put:
	__scst_cmd_put(ref_cmd);
	/* !! At this point sess, dev and tgt_dev can be already freed !! */

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_send_for_exec(struct scst_cmd **active_cmd)
{
	int res;
	struct scst_cmd *cmd = *active_cmd;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	typeof(tgt_dev->expected_sn) expected_sn;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_MEASURE_LATENCY
	if (cmd->pre_exec_finish == 0) {
		struct timespec ts;
		getnstimeofday(&ts);
		cmd->pre_exec_finish = scst_sec_to_nsec(ts.tv_sec) + ts.tv_nsec;
		TRACE_DBG("cmd %p (sess %p): pre_exec_finish %lld (tv_sec %ld, "
			"tv_nsec %ld)", cmd, cmd->sess, cmd->pre_exec_finish,
			ts.tv_sec, ts.tv_nsec);
	}
#endif

	if (unlikely(cmd->internal))
		goto exec;

	if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
		goto exec;

	sBUG_ON(!cmd->sn_set);

	expected_sn = tgt_dev->expected_sn;
	/* Optimized for lockless fast path */
	if ((cmd->sn != expected_sn) || (tgt_dev->hq_cmd_count > 0)) {
		spin_lock_irq(&tgt_dev->sn_lock);

		tgt_dev->def_cmd_count++;
		/*
		 * Memory barrier is needed here to implement lockless fast
		 * path. We need the exact order of read and write between
		 * def_cmd_count and expected_sn. Otherwise, we can miss case,
		 * when expected_sn was changed to be equal to cmd->sn while
		 * we are queuing cmd the deferred list after the expected_sn
		 * below. It will lead to a forever stuck command. But with
		 * the barrier in such case __scst_check_deferred_commands()
		 * will be called and it will take sn_lock, so we will be
		 * synchronized.
		 */
		smp_mb();

		expected_sn = tgt_dev->expected_sn;
		if ((cmd->sn != expected_sn) || (tgt_dev->hq_cmd_count > 0)) {
			if (unlikely(test_bit(SCST_CMD_ABORTED,
					      &cmd->cmd_flags))) {
				/* Necessary to allow aborting out of sn cmds */
				TRACE_MGMT_DBG("Aborting out of sn cmd %p "
					"(tag %llu, sn %lu)", cmd,
					(long long unsigned)cmd->tag, cmd->sn);
				tgt_dev->def_cmd_count--;
				scst_set_cmd_abnormal_done_state(cmd);
				res = SCST_CMD_STATE_RES_CONT_SAME;
			} else {
				TRACE_SN("Deferring cmd %p (sn=%ld, set %d, "
					"expected_sn=%ld)", cmd, cmd->sn,
					cmd->sn_set, expected_sn);
				list_add_tail(&cmd->sn_cmd_list_entry,
					      &tgt_dev->deferred_cmd_list);
				res = SCST_CMD_STATE_RES_CONT_NEXT;
			}
			spin_unlock_irq(&tgt_dev->sn_lock);
			goto out;
		} else {
			TRACE_SN("Somebody incremented expected_sn %ld, "
				"continuing", expected_sn);
			tgt_dev->def_cmd_count--;
			spin_unlock_irq(&tgt_dev->sn_lock);
		}
	}

exec:
	res = scst_exec(active_cmd);

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* No locks supposed to be held */
static int scst_check_sense(struct scst_cmd *cmd)
{
	int res = 0;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	if (unlikely(cmd->ua_ignore))
		goto out;

	/* If we had internal bus reset behind us, set the command error UA */
	if ((dev->scsi_dev != NULL) &&
	    unlikely(cmd->host_status == DID_RESET) &&
	    scst_is_ua_command(cmd)) {
		TRACE(TRACE_MGMT, "DID_RESET: was_reset=%d host_status=%x",
		      dev->scsi_dev->was_reset, cmd->host_status);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_reset_UA));
		/* It looks like it is safe to clear was_reset here */
		dev->scsi_dev->was_reset = 0;
	}

	if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION) &&
	    SCST_SENSE_VALID(cmd->sense)) {
		PRINT_BUFF_FLAG(TRACE_SCSI, "Sense", cmd->sense,
			cmd->sense_bufflen);

		/* Check Unit Attention Sense Key */
		if (scst_is_ua_sense(cmd->sense)) {
			if (scst_analyze_sense(cmd->sense, cmd->sense_bufflen,
					SCST_SENSE_ASC_VALID,
					0, SCST_SENSE_ASC_UA_RESET, 0)) {
				if (cmd->double_ua_possible) {
					TRACE(TRACE_MGMT_MINOR, "Double UA "
						"detected for device %p", dev);
					TRACE(TRACE_MGMT_MINOR, "Retrying cmd"
						" %p (tag %llu)", cmd,
						(long long unsigned)cmd->tag);

					cmd->status = 0;
					cmd->msg_status = 0;
					cmd->host_status = DID_OK;
					cmd->driver_status = 0;

					mempool_free(cmd->sense,
						     scst_sense_mempool);
					cmd->sense = NULL;

					scst_check_restore_sg_buff(cmd);

					sBUG_ON(cmd->dbl_ua_orig_resp_data_len < 0);
					cmd->data_direction =
						cmd->dbl_ua_orig_data_direction;
					cmd->resp_data_len =
						cmd->dbl_ua_orig_resp_data_len;

					cmd->state = SCST_CMD_STATE_REAL_EXEC;
					cmd->retry = 1;
					res = 1;
					goto out;
				}
			}
			scst_dev_check_set_UA(dev, cmd,	cmd->sense,
				cmd->sense_bufflen);
		}
	}

	if (unlikely(cmd->double_ua_possible)) {
		if (scst_is_ua_command(cmd)) {
			TRACE_MGMT_DBG("Clearing dbl_ua_possible flag (dev %p, "
				"cmd %p)", dev, cmd);
			/*
			 * Lock used to protect other flags in the bitfield
			 * (just in case, actually). Those flags can't be
			 * changed in parallel, because the device is
			 * serialized.
			 */
			spin_lock_bh(&dev->dev_lock);
			dev->dev_double_ua_possible = 0;
			spin_unlock_bh(&dev->dev_lock);
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_check_auto_sense(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION) &&
	    (!SCST_SENSE_VALID(cmd->sense) ||
	     SCST_NO_SENSE(cmd->sense))) {
		TRACE(TRACE_SCSI|TRACE_MINOR, "CHECK_CONDITION, but no sense: "
		      "cmd->status=%x, cmd->msg_status=%x, "
		      "cmd->host_status=%x, cmd->driver_status=%x (cmd %p)",
		      cmd->status, cmd->msg_status, cmd->host_status,
		      cmd->driver_status, cmd);
		res = 1;
	} else if (unlikely(cmd->host_status)) {
		if ((cmd->host_status == DID_REQUEUE) ||
		    (cmd->host_status == DID_IMM_RETRY) ||
		    (cmd->host_status == DID_SOFT_ERROR) ||
		    (cmd->host_status == DID_ABORT)) {
			scst_set_busy(cmd);
		} else {
			TRACE(TRACE_SCSI|TRACE_MINOR, "Host status %x "
				"received, returning HARDWARE ERROR instead "
				"(cmd %p)", cmd->host_status, cmd);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_pre_dev_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME, rc;

	TRACE_ENTRY();

	if (unlikely(scst_check_auto_sense(cmd))) {
		PRINT_INFO("Command finished with CHECK CONDITION, but "
			    "without sense data (opcode 0x%x), issuing "
			    "REQUEST SENSE", cmd->cdb[0]);
		rc = scst_prepare_request_sense(cmd);
		if (rc == 0)
			res = SCST_CMD_STATE_RES_CONT_NEXT;
		else {
			PRINT_ERROR("%s", "Unable to issue REQUEST SENSE, "
				    "returning HARDWARE ERROR");
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out;
	} else if (unlikely(scst_check_sense(cmd)))
		goto out;

	if (likely(scsi_status_is_good(cmd->status))) {
		unsigned char type = cmd->dev->type;
		if (unlikely((cmd->cdb[0] == MODE_SENSE ||
			      cmd->cdb[0] == MODE_SENSE_10)) &&
		    (cmd->tgt_dev->acg_dev->rd_only || cmd->dev->swp ||
		     cmd->dev->rd_only) &&
		    (type == TYPE_DISK ||
		     type == TYPE_WORM ||
		     type == TYPE_MOD ||
		     type == TYPE_TAPE)) {
			int32_t length;
			uint8_t *address;
			bool err = false;

			length = scst_get_buf_first(cmd, &address);
			if (length < 0) {
				PRINT_ERROR("%s", "Unable to get "
					"MODE_SENSE buffer");
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(
						scst_sense_hardw_error));
				err = true;
			} else if (length > 2 && cmd->cdb[0] == MODE_SENSE)
				address[2] |= 0x80;   /* Write Protect*/
			else if (length > 3 && cmd->cdb[0] == MODE_SENSE_10)
				address[3] |= 0x80;   /* Write Protect*/
			scst_put_buf(cmd, address);

			if (err)
				goto out;
		}

		/*
		 * Check and clear NormACA option for the device, if necessary,
		 * since we don't support ACA
		 */
		if (unlikely((cmd->cdb[0] == INQUIRY)) &&
		    /* Std INQUIRY data (no EVPD) */
		    !(cmd->cdb[1] & SCST_INQ_EVPD) &&
		    (cmd->resp_data_len > SCST_INQ_BYTE3)) {
			uint8_t *buffer;
			int buflen;
			bool err = false;

			/* ToDo: all pages ?? */
			buflen = scst_get_buf_first(cmd, &buffer);
			if (buflen > SCST_INQ_BYTE3) {
#ifdef CONFIG_SCST_EXTRACHECKS
				if (buffer[SCST_INQ_BYTE3] & SCST_INQ_NORMACA_BIT) {
					PRINT_INFO("NormACA set for device: "
					    "lun=%lld, type 0x%02x. Clear it, "
					    "since it's unsupported.",
					    (long long unsigned int)cmd->lun,
					    buffer[0]);
				}
#endif
				buffer[SCST_INQ_BYTE3] &= ~SCST_INQ_NORMACA_BIT;
			} else if (buflen != 0) {
				PRINT_ERROR("%s", "Unable to get INQUIRY "
				    "buffer");
				scst_set_cmd_error(cmd,
				       SCST_LOAD_SENSE(scst_sense_hardw_error));
				err = true;
			}
			if (buflen > 0)
				scst_put_buf(cmd, buffer);

			if (err)
				goto out;
		}

		if (unlikely((cmd->cdb[0] == MODE_SELECT) ||
		    (cmd->cdb[0] == MODE_SELECT_10) ||
		    (cmd->cdb[0] == LOG_SELECT))) {
			TRACE(TRACE_SCSI,
				"MODE/LOG SELECT succeeded (LUN %lld)",
				(long long unsigned int)cmd->lun);
			cmd->state = SCST_CMD_STATE_MODE_SELECT_CHECKS;
			goto out;
		}
	} else {
		if ((cmd->cdb[0] == RESERVE) || (cmd->cdb[0] == RESERVE_10)) {
			if (!test_bit(SCST_TGT_DEV_RESERVED,
					&cmd->tgt_dev->tgt_dev_flags)) {
				struct scst_tgt_dev *tgt_dev_tmp;
				struct scst_device *dev = cmd->dev;

				TRACE(TRACE_SCSI,
					"Real RESERVE failed lun=%lld, "
					"status=%x",
					(long long unsigned int)cmd->lun,
					cmd->status);
				PRINT_BUFF_FLAG(TRACE_SCSI, "Sense", cmd->sense,
					cmd->sense_bufflen);

				/* Clearing the reservation */
				spin_lock_bh(&dev->dev_lock);
				list_for_each_entry(tgt_dev_tmp,
						    &dev->dev_tgt_dev_list,
						    dev_tgt_dev_list_entry) {
					clear_bit(SCST_TGT_DEV_RESERVED,
						&tgt_dev_tmp->tgt_dev_flags);
				}
				dev->dev_reserved = 0;
				spin_unlock_bh(&dev->dev_lock);
			}
		}

		/* Check for MODE PARAMETERS CHANGED UA */
		if ((cmd->dev->scsi_dev != NULL) &&
		    (cmd->status == SAM_STAT_CHECK_CONDITION) &&
		    SCST_SENSE_VALID(cmd->sense) &&
		    scst_is_ua_sense(cmd->sense) &&
		    scst_analyze_sense(cmd->sense, cmd->sense_bufflen,
					SCST_SENSE_ASCx_VALID,
					0, 0x2a, 0x01)) {
			TRACE(TRACE_SCSI, "MODE PARAMETERS CHANGED UA (lun "
				"%lld)", (long long unsigned int)cmd->lun);
			cmd->state = SCST_CMD_STATE_MODE_SELECT_CHECKS;
			goto out;
		}
	}

	cmd->state = SCST_CMD_STATE_DEV_DONE;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_mode_select_checks(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	if (likely(scsi_status_is_good(cmd->status))) {
		if (unlikely((cmd->cdb[0] == MODE_SELECT) ||
		    (cmd->cdb[0] == MODE_SELECT_10) ||
		    (cmd->cdb[0] == LOG_SELECT))) {
			struct scst_device *dev = cmd->dev;
			uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];

			if (atomic && (dev->scsi_dev != NULL)) {
				TRACE_DBG("%s", "MODE/LOG SELECT: thread "
					"context required");
				res = SCST_CMD_STATE_RES_NEED_THREAD;
				goto out;
			}

			TRACE(TRACE_SCSI, "MODE/LOG SELECT succeeded, "
				"setting the SELECT UA (lun=%lld)",
				(long long unsigned int)cmd->lun);

			spin_lock_bh(&dev->dev_lock);
			if (cmd->cdb[0] == LOG_SELECT) {
				scst_set_sense(sense_buffer,
					sizeof(sense_buffer),
					dev->d_sense,
					UNIT_ATTENTION, 0x2a, 0x02);
			} else {
				scst_set_sense(sense_buffer,
					sizeof(sense_buffer),
					dev->d_sense,
					UNIT_ATTENTION, 0x2a, 0x01);
			}
			scst_dev_check_set_local_UA(dev, cmd, sense_buffer,
				sizeof(sense_buffer));
			spin_unlock_bh(&dev->dev_lock);

			if (dev->scsi_dev != NULL)
				scst_obtain_device_parameters(dev);
		}
	} else if ((cmd->status == SAM_STAT_CHECK_CONDITION) &&
		    SCST_SENSE_VALID(cmd->sense) &&
		    scst_is_ua_sense(cmd->sense) &&
		     /* mode parameters changed */
		    (scst_analyze_sense(cmd->sense, cmd->sense_bufflen,
					SCST_SENSE_ASCx_VALID,
					0, 0x2a, 0x01) ||
		     scst_analyze_sense(cmd->sense, cmd->sense_bufflen,
					SCST_SENSE_ASC_VALID,
					0, 0x29, 0) /* reset */ ||
		     scst_analyze_sense(cmd->sense, cmd->sense_bufflen,
					SCST_SENSE_ASC_VALID,
					0, 0x28, 0) /* medium changed */ ||
		     /* cleared by another ini (just in case) */
		     scst_analyze_sense(cmd->sense, cmd->sense_bufflen,
					SCST_SENSE_ASC_VALID,
					0, 0x2F, 0))) {
		if (atomic) {
			TRACE_DBG("Possible parameters changed UA %x: "
				"thread context required", cmd->sense[12]);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		TRACE(TRACE_SCSI, "Possible parameters changed UA %x "
			"(LUN %lld): getting new parameters", cmd->sense[12],
			(long long unsigned int)cmd->lun);

		scst_obtain_device_parameters(cmd->dev);
	} else
		sBUG();

	cmd->state = SCST_CMD_STATE_DEV_DONE;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

static void scst_inc_check_expected_sn(struct scst_cmd *cmd)
{
	if (likely(cmd->sn_set))
		scst_inc_expected_sn(cmd->tgt_dev, cmd->sn_slot);

	scst_make_deferred_commands_active(cmd->tgt_dev);
}

static int scst_dev_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int state;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	state = SCST_CMD_STATE_PRE_XMIT_RESP;

	if (likely(!scst_is_cmd_local(cmd)) &&
	    likely(dev->handler->dev_done != NULL)) {
		int rc;

		if (unlikely(!dev->handler->dev_done_atomic &&
			     scst_cmd_atomic(cmd))) {
			/*
			 * It shouldn't be because of SCST_TGT_DEV_AFTER_*
			 * optimization.
			 */
			TRACE_DBG("Dev handler %s dev_done() needs thread "
			      "context, rescheduling", dev->handler->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		TRACE_DBG("Calling dev handler %s dev_done(%p)",
		      dev->handler->name, cmd);
		rc = dev->handler->dev_done(cmd);
		TRACE_DBG("Dev handler %s dev_done() returned %d",
		      dev->handler->name, rc);
		if (rc != SCST_CMD_STATE_DEFAULT)
			state = rc;
	}

	switch (state) {
	case SCST_CMD_STATE_PRE_XMIT_RESP:
	case SCST_CMD_STATE_DEV_PARSE:
	case SCST_CMD_STATE_PRE_PARSE:
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_TGT_PRE_EXEC:
	case SCST_CMD_STATE_SEND_FOR_EXEC:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_MODE_SELECT_CHECKS:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
	case SCST_CMD_STATE_FINISHED_INTERNAL:
		cmd->state = state;
		break;

	case SCST_CMD_STATE_NEED_THREAD_CTX:
		TRACE_DBG("Dev handler %s dev_done() requested "
		      "thread context, rescheduling",
		      dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		break;

	default:
		if (state >= 0) {
			PRINT_ERROR("Dev handler %s dev_done() returned "
				"invalid cmd state %d",
				dev->handler->name, state);
		} else {
			PRINT_ERROR("Dev handler %s dev_done() returned "
				"error %d", dev->handler->name,
				state);
		}
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
		break;
	}

	if (cmd->needs_unblocking)
		scst_unblock_dev_cmd(cmd);

	if (likely(cmd->dec_on_dev_needed))
		scst_dec_on_dev_cmd(cmd);

	if (cmd->inc_expected_sn_on_done && cmd->sent_for_exec)
		scst_inc_check_expected_sn(cmd);

	if (unlikely(cmd->internal))
		cmd->state = SCST_CMD_STATE_FINISHED_INTERNAL;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

static int scst_pre_xmit_response(struct scst_cmd *cmd)
{
	int res;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->internal);

#ifdef CONFIG_SCST_DEBUG_TM
	if (cmd->tm_dbg_delayed &&
			!test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
		if (scst_cmd_atomic(cmd)) {
			TRACE_MGMT_DBG("%s",
				"DEBUG_TM delayed cmd needs a thread");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			return res;
		}
		TRACE_MGMT_DBG("Delaying cmd %p (tag %llu) for 1 second",
			cmd, cmd->tag);
		schedule_timeout_uninterruptible(HZ);
	}
#endif

	if (likely(cmd->tgt_dev != NULL)) {
		atomic_dec(&cmd->tgt_dev->tgt_dev_cmd_count);
		atomic_dec(&cmd->dev->dev_cmd_count);
		/* If expected values not set, expected direction is UNKNOWN */
		if (cmd->expected_data_direction & SCST_DATA_WRITE)
			atomic_dec(&cmd->dev->write_cmd_count);

		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			scst_on_hq_cmd_response(cmd);

		if (unlikely(!cmd->sent_for_exec)) {
			TRACE_SN("cmd %p was not sent to mid-lev"
				" (sn %ld, set %d)",
				cmd, cmd->sn, cmd->sn_set);
			scst_unblock_deferred(cmd->tgt_dev, cmd);
			cmd->sent_for_exec = 1;
		}
	}

	/*
	 * If we don't remove cmd from the search list here, before
	 * submitting it for transmittion, we will have a race, when for
	 * some reason cmd's release is delayed after transmittion and
	 * initiator sends cmd with the same tag => it is possible that
	 * a wrong cmd will be found by find() functions.
	 */
	spin_lock_irq(&sess->sess_list_lock);
	list_move_tail(&cmd->sess_cmd_list_entry,
		&sess->after_pre_xmit_cmd_list);
	spin_unlock_irq(&sess->sess_list_lock);

	cmd->done = 1;
	smp_mb(); /* to sync with scst_abort_cmd() */

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
		scst_xmit_process_aborted_cmd(cmd);
	else if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION))
		scst_store_sense(cmd);

	if (unlikely(test_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Flag NO_RESP set for cmd %p (tag %llu),"
				" skipping",
				cmd, (long long unsigned int)cmd->tag);
		cmd->state = SCST_CMD_STATE_FINISHED;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		goto out;
	}

	if (cmd->tgt_data_buf_alloced && cmd->dh_data_buf_alloced &&
	    (cmd->data_direction & SCST_DATA_READ))
		scst_copy_sg(cmd, SCST_SG_COPY_TO_TARGET);

	cmd->state = SCST_CMD_STATE_XMIT_RESP;
	res = SCST_CMD_STATE_RES_CONT_SAME;

out:
#ifdef CONFIG_SCST_MEASURE_LATENCY
	{
		struct timespec ts;
		uint64_t finish, scst_time, proc_time;

		getnstimeofday(&ts);
		finish = scst_sec_to_nsec(ts.tv_sec) + ts.tv_nsec;

		spin_lock_bh(&sess->meas_lock);

		scst_time = cmd->pre_exec_finish - cmd->start;
		scst_time += finish - cmd->post_exec_start;
		proc_time = finish - cmd->start;

		sess->scst_time += scst_time;
		sess->processing_time += proc_time;
		sess->processed_cmds++;

		spin_unlock_bh(&sess->meas_lock);

		TRACE_DBG("cmd %p (sess %p): finish %lld (tv_sec %ld, "
			"tv_nsec %ld), scst_time %lld, proc_time %lld",
			cmd, sess, finish, ts.tv_sec, ts.tv_nsec, scst_time,
			proc_time);
	}
#endif
	TRACE_EXIT_HRES(res);
	return res;
}

static int scst_xmit_response(struct scst_cmd *cmd)
{
	struct scst_tgt_template *tgtt = cmd->tgtt;
	int res, rc;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->internal);

	if (unlikely(!tgtt->xmit_response_atomic &&
		     scst_cmd_atomic(cmd))) {
		/*
		 * It shouldn't be because of SCST_TGT_DEV_AFTER_*
		 * optimization.
		 */
		TRACE_DBG("Target driver %s xmit_response() needs thread "
			      "context, rescheduling", tgtt->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	while (1) {
		int finished_cmds = atomic_read(&cmd->tgt->finished_cmds);

		res = SCST_CMD_STATE_RES_CONT_NEXT;
		cmd->state = SCST_CMD_STATE_XMIT_WAIT;

		TRACE_DBG("Calling xmit_response(%p)", cmd);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
		if (trace_flag & TRACE_SND_BOT) {
			int i;
			struct scatterlist *sg;
			if (cmd->tgt_sg != NULL)
				sg = cmd->tgt_sg;
			else
				sg = cmd->sg;
			if (sg != NULL) {
				TRACE(TRACE_SND_BOT, "Xmitting data for cmd %p "
					"(sg_cnt %d, sg %p, sg[0].page %p)",
					cmd, cmd->tgt_sg_cnt, sg,
					(void *)sg_page(&sg[0]));
				for (i = 0; i < cmd->tgt_sg_cnt; ++i) {
					PRINT_BUFF_FLAG(TRACE_SND_BOT,
						"Xmitting sg", sg_virt(&sg[i]),
						sg[i].length);
				}
			}
		}
#endif

		if (tgtt->on_hw_pending_cmd_timeout != NULL) {
			struct scst_session *sess = cmd->sess;
			cmd->hw_pending_start = jiffies;
			cmd->cmd_hw_pending = 1;
			if (!test_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED, &sess->sess_aflags)) {
				TRACE_DBG("Sched HW pending work for sess %p "
					"(max time %d)", sess,
					tgtt->max_hw_pending_time);
				set_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED,
					&sess->sess_aflags);
				schedule_delayed_work(&sess->hw_pending_work,
					tgtt->max_hw_pending_time * HZ);
			}
		}

#ifdef CONFIG_SCST_DEBUG_RETRY
		if (((scst_random() % 100) == 77))
			rc = SCST_TGT_RES_QUEUE_FULL;
		else
#endif
			rc = tgtt->xmit_response(cmd);
		TRACE_DBG("xmit_response() returned %d", rc);

		if (likely(rc == SCST_TGT_RES_SUCCESS))
			goto out;

		cmd->cmd_hw_pending = 0;

		/* Restore the previous state */
		cmd->state = SCST_CMD_STATE_XMIT_RESP;

		switch (rc) {
		case SCST_TGT_RES_QUEUE_FULL:
			if (scst_queue_retry_cmd(cmd, finished_cmds) == 0)
				break;
			else
				continue;

		case SCST_TGT_RES_NEED_THREAD_CTX:
			TRACE_DBG("Target driver %s xmit_response() "
			      "requested thread context, rescheduling",
			      tgtt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			break;

		default:
			goto out_error;
		}
		break;
	}

out:
	/* Caution: cmd can be already dead here */
	TRACE_EXIT_HRES(res);
	return res;

out_error:
	if (rc == SCST_TGT_RES_FATAL_ERROR) {
		PRINT_ERROR("Target driver %s xmit_response() returned "
			"fatal error", tgtt->name);
	} else {
		PRINT_ERROR("Target driver %s xmit_response() returned "
			"invalid value %d", tgtt->name, rc);
	}
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	cmd->state = SCST_CMD_STATE_FINISHED;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

void scst_tgt_cmd_done(struct scst_cmd *cmd,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

	sBUG_ON(cmd->state != SCST_CMD_STATE_XMIT_WAIT);

	cmd->cmd_hw_pending = 0;

	cmd->state = SCST_CMD_STATE_FINISHED;
	scst_proccess_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_tgt_cmd_done);

static int scst_finish_cmd(struct scst_cmd *cmd)
{
	int res;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	atomic_dec(&sess->sess_cmd_count);

	spin_lock_irq(&sess->sess_list_lock);
	list_del(&cmd->sess_cmd_list_entry);
	spin_unlock_irq(&sess->sess_list_lock);

	cmd->finished = 1;
	smp_mb(); /* to sync with scst_abort_cmd() */

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Aborted cmd %p finished (cmd_ref %d, "
			"scst_cmd_count %d)", cmd, atomic_read(&cmd->cmd_ref),
			atomic_read(&scst_cmd_count));

		scst_finish_cmd_mgmt(cmd);
	}

	if (unlikely(cmd->delivery_status != SCST_CMD_DELIVERY_SUCCESS)) {
		if ((cmd->tgt_dev != NULL) &&
		    scst_is_ua_sense(cmd->sense)) {
			/* This UA delivery failed, so requeue it */
			TRACE_MGMT_DBG("Requeuing UA for delivery failed cmd "
				"%p", cmd);
			scst_check_set_UA(cmd->tgt_dev, cmd->sense,
				cmd->sense_bufflen, SCST_SET_UA_FLAG_AT_HEAD);
		}
	}

	__scst_cmd_put(cmd);

	res = SCST_CMD_STATE_RES_CONT_NEXT;

	TRACE_EXIT_HRES(res);
	return res;
}

/*
 * No locks, but it must be externally serialized (see comment for
 * scst_cmd_init_done() in scst.h)
 */
static void scst_cmd_set_sn(struct scst_cmd *cmd)
{
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	unsigned long flags;

	TRACE_ENTRY();

	if (scst_is_implicit_hq(cmd)) {
		TRACE_SN("Implicit HQ cmd %p", cmd);
		cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	}

	EXTRACHECKS_BUG_ON(cmd->sn_set || cmd->hq_cmd_inced);

	/* Optimized for lockless fast path */

	scst_check_debug_sn(cmd);

	if (cmd->dev->queue_alg ==
			SCST_CONTR_MODE_QUEUE_ALG_RESTRICTED_REORDER) {
		/*
		 * Not the best way, but well enough until there will be a
		 * possibility to specify queue type during pass-through
		 * commands submission.
		 */
		cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
	}

	switch (cmd->queue_type) {
	case SCST_CMD_QUEUE_SIMPLE:
	case SCST_CMD_QUEUE_UNTAGGED:
#if 0 /* left for future performance investigations */
		if (scst_cmd_is_expected_set(cmd)) {
			if ((cmd->expected_data_direction == SCST_DATA_READ) &&
			    (atomic_read(&cmd->dev->write_cmd_count) == 0))
				goto ordered;
		} else
			goto ordered;
#endif
		if (likely(tgt_dev->num_free_sn_slots >= 0)) {
			/*
			 * atomic_inc_return() implies memory barrier to sync
			 * with scst_inc_expected_sn()
			 */
			if (atomic_inc_return(tgt_dev->cur_sn_slot) == 1) {
				tgt_dev->curr_sn++;
				TRACE_SN("Incremented curr_sn %ld",
					tgt_dev->curr_sn);
			}
			cmd->sn_slot = tgt_dev->cur_sn_slot;
			cmd->sn = tgt_dev->curr_sn;

			tgt_dev->prev_cmd_ordered = 0;
		} else {
			TRACE(TRACE_MINOR, "***WARNING*** Not enough SN slots "
				"%zd", ARRAY_SIZE(tgt_dev->sn_slots));
			goto ordered;
		}
		break;

	case SCST_CMD_QUEUE_ORDERED:
		TRACE_SN("ORDERED cmd %p (op %x)", cmd, cmd->cdb[0]);
ordered:
		if (!tgt_dev->prev_cmd_ordered) {
			spin_lock_irqsave(&tgt_dev->sn_lock, flags);
			if (tgt_dev->num_free_sn_slots >= 0) {
				tgt_dev->num_free_sn_slots--;
				if (tgt_dev->num_free_sn_slots >= 0) {
					int i = 0;
					/* Commands can finish in any order, so
					 * we don't know which slot is empty.
					 */
					while (1) {
						tgt_dev->cur_sn_slot++;
						if (tgt_dev->cur_sn_slot ==
						      tgt_dev->sn_slots + ARRAY_SIZE(tgt_dev->sn_slots))
							tgt_dev->cur_sn_slot = tgt_dev->sn_slots;

						if (atomic_read(tgt_dev->cur_sn_slot) == 0)
							break;

						i++;
						sBUG_ON(i == ARRAY_SIZE(tgt_dev->sn_slots));
					}
					TRACE_SN("New cur SN slot %zd",
						tgt_dev->cur_sn_slot -
						tgt_dev->sn_slots);
				}
			}
			spin_unlock_irqrestore(&tgt_dev->sn_lock, flags);
		}
		tgt_dev->prev_cmd_ordered = 1;
		tgt_dev->curr_sn++;
		cmd->sn = tgt_dev->curr_sn;
		break;

	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		TRACE_SN("HQ cmd %p (op %x)", cmd, cmd->cdb[0]);
		spin_lock_irqsave(&tgt_dev->sn_lock, flags);
		tgt_dev->hq_cmd_count++;
		spin_unlock_irqrestore(&tgt_dev->sn_lock, flags);
		cmd->hq_cmd_inced = 1;
		goto out;

	default:
		sBUG();
	}

	TRACE_SN("cmd(%p)->sn: %ld (tgt_dev %p, *cur_sn_slot %d, "
		"num_free_sn_slots %d, prev_cmd_ordered %ld, "
		"cur_sn_slot %zd)", cmd, cmd->sn, tgt_dev,
		atomic_read(tgt_dev->cur_sn_slot),
		tgt_dev->num_free_sn_slots, tgt_dev->prev_cmd_ordered,
		tgt_dev->cur_sn_slot-tgt_dev->sn_slots);

	cmd->sn_set = 1;

out:
	TRACE_EXIT();
	return;
}

/*
 * Returns 0 on success, > 0 when we need to wait for unblock,
 * < 0 if there is no device (lun) or device type handler.
 *
 * No locks, but might be on IRQ, protection is done by the
 * suspended activity.
 */
static int scst_translate_lun(struct scst_cmd *cmd)
{
	struct scst_tgt_dev *tgt_dev = NULL;
	int res;

	TRACE_ENTRY();

	/* See comment about smp_mb() in scst_suspend_activity() */
	__scst_get(1);

	if (likely(!test_bit(SCST_FLAG_SUSPENDED, &scst_flags))) {
		struct list_head *sess_tgt_dev_list_head =
			&cmd->sess->sess_tgt_dev_list_hash[HASH_VAL(cmd->lun)];
		TRACE_DBG("Finding tgt_dev for cmd %p (lun %lld)", cmd,
			(long long unsigned int)cmd->lun);
		res = -1;
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			if (tgt_dev->lun == cmd->lun) {
				TRACE_DBG("tgt_dev %p found", tgt_dev);

				if (unlikely(tgt_dev->dev->handler ==
						&scst_null_devtype)) {
					PRINT_INFO("Dev handler for device "
					  "%lld is NULL, the device will not "
					  "be visible remotely",
					   (long long unsigned int)cmd->lun);
					break;
				}

				cmd->cmd_lists = tgt_dev->dev->p_cmd_lists;
				cmd->tgt_dev = tgt_dev;
				cmd->dev = tgt_dev->dev;

				res = 0;
				break;
			}
		}
		if (res != 0) {
			TRACE(TRACE_MINOR,
				"tgt_dev for LUN %lld not found, command to "
				"unexisting LU?",
				(long long unsigned int)cmd->lun);
			__scst_put();
		}
	} else {
		TRACE_MGMT_DBG("%s", "FLAG SUSPENDED set, skipping");
		__scst_put();
		res = 1;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * No locks, but might be on IRQ
 *
 * Returns 0 on success, > 0 when we need to wait for unblock,
 * < 0 if there is no device (lun) or device type handler.
 */
static int __scst_init_cmd(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_translate_lun(cmd);
	if (likely(res == 0)) {
		int cnt;
		bool failure = false;

		cmd->state = SCST_CMD_STATE_PRE_PARSE;

		cnt = atomic_inc_return(&cmd->tgt_dev->tgt_dev_cmd_count);
		if (unlikely(cnt > SCST_MAX_TGT_DEV_COMMANDS)) {
			TRACE(TRACE_MGMT_MINOR,
				"Too many pending commands (%d) in "
				"session, returning BUSY to initiator \"%s\"",
				cnt, (cmd->sess->initiator_name[0] == '\0') ?
				  "Anonymous" : cmd->sess->initiator_name);
			failure = true;
		}

		cnt = atomic_inc_return(&cmd->dev->dev_cmd_count);
		if (unlikely(cnt > SCST_MAX_DEV_COMMANDS)) {
			if (!failure) {
				TRACE(TRACE_MGMT_MINOR,
					"Too many pending device "
					"commands (%d), returning BUSY to "
					"initiator \"%s\"", cnt,
					(cmd->sess->initiator_name[0] == '\0') ?
						"Anonymous" :
						cmd->sess->initiator_name);
				failure = true;
			}
		}

		/* If expected values not set, expected direction is UNKNOWN */
		if (cmd->expected_data_direction & SCST_DATA_WRITE)
			atomic_inc(&cmd->dev->write_cmd_count);

		if (unlikely(failure))
			goto out_busy;

		if (!cmd->set_sn_on_restart_cmd)
			scst_cmd_set_sn(cmd);
	} else if (res < 0) {
		TRACE_DBG("Finishing cmd %p", cmd);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		scst_set_cmd_abnormal_done_state(cmd);
	} else
		goto out;

out:
	TRACE_EXIT_RES(res);
	return res;

out_busy:
	scst_set_busy(cmd);
	scst_set_cmd_abnormal_done_state(cmd);
	goto out;
}

/* Called under scst_init_lock and IRQs disabled */
static void scst_do_job_init(void)
	__releases(&scst_init_lock)
	__acquires(&scst_init_lock)
{
	struct scst_cmd *cmd;
	int susp;

	TRACE_ENTRY();

restart:
	/*
	 * There is no need for read barrier here, because we don't care where
	 * this check will be done.
	 */
	susp = test_bit(SCST_FLAG_SUSPENDED, &scst_flags);
	if (scst_init_poll_cnt > 0)
		scst_init_poll_cnt--;

	list_for_each_entry(cmd, &scst_init_cmd_list, cmd_list_entry) {
		int rc;
		if (susp && !test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
			continue;
		if (!test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
			spin_unlock_irq(&scst_init_lock);
			rc = __scst_init_cmd(cmd);
			spin_lock_irq(&scst_init_lock);
			if (rc > 0) {
				TRACE_MGMT_DBG("%s",
					"FLAG SUSPENDED set, restarting");
				goto restart;
			}
		} else {
			TRACE_MGMT_DBG("Aborting not inited cmd %p (tag %llu)",
				       cmd, (long long unsigned int)cmd->tag);
			scst_set_cmd_abnormal_done_state(cmd);
		}

		/*
		 * Deleting cmd from init cmd list after __scst_init_cmd()
		 * is necessary to keep the check in scst_init_cmd() correct
		 * to preserve the commands order.
		 *
		 * We don't care about the race, when init cmd list is empty
		 * and one command detected that it just was not empty, so
		 * it's inserting to it, but another command at the same time
		 * seeing init cmd list empty and goes directly, because it
		 * could affect only commands from the same initiator to the
		 * same tgt_dev, but scst_cmd_init_done*() doesn't guarantee
		 * the order in case of simultaneous such calls anyway.
		 */
		TRACE_MGMT_DBG("Deleting cmd %p from init cmd list", cmd);
		smp_wmb(); /* enforce the required order */
		list_del(&cmd->cmd_list_entry);
		spin_unlock(&scst_init_lock);

		spin_lock(&cmd->cmd_lists->cmd_list_lock);
		TRACE_MGMT_DBG("Adding cmd %p to active cmd list", cmd);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		wake_up(&cmd->cmd_lists->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_lists->cmd_list_lock);

		spin_lock(&scst_init_lock);
		goto restart;
	}

	/* It isn't really needed, but let's keep it */
	if (susp != test_bit(SCST_FLAG_SUSPENDED, &scst_flags))
		goto restart;

	TRACE_EXIT();
	return;
}

static inline int test_init_cmd_list(void)
{
	int res = (!list_empty(&scst_init_cmd_list) &&
		   !test_bit(SCST_FLAG_SUSPENDED, &scst_flags)) ||
		  unlikely(kthread_should_stop()) ||
		  (scst_init_poll_cnt > 0);
	return res;
}

int scst_init_thread(void *arg)
{
	TRACE_ENTRY();

	PRINT_INFO("Init thread started, PID %d", current->pid);

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock_irq(&scst_init_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_init_cmd_list()) {
			add_wait_queue_exclusive(&scst_init_cmd_list_waitQ,
						 &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_init_cmd_list())
					break;
				spin_unlock_irq(&scst_init_lock);
				schedule();
				spin_lock_irq(&scst_init_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&scst_init_cmd_list_waitQ, &wait);
		}
		scst_do_job_init();
	}
	spin_unlock_irq(&scst_init_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so scst_init_cmd_list must be empty.
	 */
	sBUG_ON(!list_empty(&scst_init_cmd_list));

	PRINT_INFO("Init thread PID %d finished", current->pid);

	TRACE_EXIT();
	return 0;
}

/* Called with no locks held */
void scst_process_active_cmd(struct scst_cmd *cmd, bool atomic)
{
	int res;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(in_irq() || irqs_disabled());

	cmd->atomic = atomic;

	TRACE_DBG("cmd %p, atomic %d", cmd, atomic);

	do {
		switch (cmd->state) {
		case SCST_CMD_STATE_PRE_PARSE:
			res = scst_pre_parse(cmd);
			EXTRACHECKS_BUG_ON(res ==
				SCST_CMD_STATE_RES_NEED_THREAD);
			break;

		case SCST_CMD_STATE_DEV_PARSE:
			res = scst_parse_cmd(cmd);
			break;

		case SCST_CMD_STATE_PREPARE_SPACE:
			res = scst_prepare_space(cmd);
			break;

		case SCST_CMD_STATE_RDY_TO_XFER:
			res = scst_rdy_to_xfer(cmd);
			break;

		case SCST_CMD_STATE_TGT_PRE_EXEC:
			res = scst_tgt_pre_exec(cmd);
			break;

		case SCST_CMD_STATE_SEND_FOR_EXEC:
			if (tm_dbg_check_cmd(cmd) != 0) {
				res = SCST_CMD_STATE_RES_CONT_NEXT;
				TRACE_MGMT_DBG("Skipping cmd %p (tag %llu), "
					"because of TM DBG delay", cmd,
					(long long unsigned int)cmd->tag);
				break;
			}
			res = scst_send_for_exec(&cmd);
			/*
			 * !! At this point cmd, sess & tgt_dev can already be
			 * freed !!
			 */
			break;

		case SCST_CMD_STATE_LOCAL_EXEC:
			res = scst_local_exec(cmd);
			/*
			 * !! At this point cmd, sess & tgt_dev can already be
			 * freed !!
			 */
			break;

		case SCST_CMD_STATE_REAL_EXEC:
			res = scst_real_exec(cmd);
			/*
			 * !! At this point cmd, sess & tgt_dev can already be
			 * freed !!
			 */
			break;

		case SCST_CMD_STATE_PRE_DEV_DONE:
			res = scst_pre_dev_done(cmd);
			EXTRACHECKS_BUG_ON(res ==
				SCST_CMD_STATE_RES_NEED_THREAD);
			break;

		case SCST_CMD_STATE_MODE_SELECT_CHECKS:
			res = scst_mode_select_checks(cmd);
			break;

		case SCST_CMD_STATE_DEV_DONE:
			res = scst_dev_done(cmd);
			break;

		case SCST_CMD_STATE_PRE_XMIT_RESP:
			res = scst_pre_xmit_response(cmd);
			EXTRACHECKS_BUG_ON(res ==
				SCST_CMD_STATE_RES_NEED_THREAD);
			break;

		case SCST_CMD_STATE_XMIT_RESP:
			res = scst_xmit_response(cmd);
			break;

		case SCST_CMD_STATE_FINISHED:
			res = scst_finish_cmd(cmd);
			EXTRACHECKS_BUG_ON(res ==
				SCST_CMD_STATE_RES_NEED_THREAD);
			break;

		case SCST_CMD_STATE_FINISHED_INTERNAL:
			res = scst_finish_internal_cmd(cmd);
			EXTRACHECKS_BUG_ON(res ==
				SCST_CMD_STATE_RES_NEED_THREAD);
			break;

		default:
			PRINT_CRIT_ERROR("cmd (%p) in state %d, but shouldn't "
				"be", cmd, cmd->state);
			sBUG();
			res = SCST_CMD_STATE_RES_CONT_NEXT;
			break;
		}
	} while (res == SCST_CMD_STATE_RES_CONT_SAME);

	if (res == SCST_CMD_STATE_RES_CONT_NEXT) {
		/* None */
	} else if (res == SCST_CMD_STATE_RES_NEED_THREAD) {
		spin_lock_irq(&cmd->cmd_lists->cmd_list_lock);
		switch (cmd->state) {
		case SCST_CMD_STATE_PRE_PARSE:
		case SCST_CMD_STATE_DEV_PARSE:
		case SCST_CMD_STATE_PREPARE_SPACE:
		case SCST_CMD_STATE_RDY_TO_XFER:
		case SCST_CMD_STATE_TGT_PRE_EXEC:
		case SCST_CMD_STATE_SEND_FOR_EXEC:
		case SCST_CMD_STATE_LOCAL_EXEC:
		case SCST_CMD_STATE_REAL_EXEC:
		case SCST_CMD_STATE_PRE_DEV_DONE:
		case SCST_CMD_STATE_MODE_SELECT_CHECKS:
		case SCST_CMD_STATE_DEV_DONE:
		case SCST_CMD_STATE_PRE_XMIT_RESP:
		case SCST_CMD_STATE_XMIT_RESP:
		case SCST_CMD_STATE_FINISHED:
		case SCST_CMD_STATE_FINISHED_INTERNAL:
			TRACE_DBG("Adding cmd %p to head of active cmd list",
				  cmd);
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
			break;
#ifdef CONFIG_SCST_EXTRACHECKS
		/* not very valid commands */
		case SCST_CMD_STATE_DEFAULT:
		case SCST_CMD_STATE_NEED_THREAD_CTX:
			PRINT_CRIT_ERROR("cmd %p is in invalid state %d)", cmd,
				cmd->state);
			spin_unlock_irq(&cmd->cmd_lists->cmd_list_lock);
			sBUG();
			spin_lock_irq(&cmd->cmd_lists->cmd_list_lock);
			break;
#endif
		default:
			break;
		}
		wake_up(&cmd->cmd_lists->cmd_list_waitQ);
		spin_unlock_irq(&cmd->cmd_lists->cmd_list_lock);
	} else
		sBUG();

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_process_active_cmd);

/* Called under cmd_list_lock and IRQs disabled */
static void scst_do_job_active(struct list_head *cmd_list,
	spinlock_t *cmd_list_lock, bool atomic)
	__releases(cmd_list_lock)
	__acquires(cmd_list_lock)
{
	TRACE_ENTRY();

	while (!list_empty(cmd_list)) {
		struct scst_cmd *cmd = list_entry(cmd_list->next, typeof(*cmd),
					cmd_list_entry);
		TRACE_DBG("Deleting cmd %p from active cmd list", cmd);
		list_del(&cmd->cmd_list_entry);
		spin_unlock_irq(cmd_list_lock);
		scst_process_active_cmd(cmd, atomic);
		spin_lock_irq(cmd_list_lock);
	}

	TRACE_EXIT();
	return;
}

static inline int test_cmd_lists(struct scst_cmd_lists *p_cmd_lists)
{
	int res = !list_empty(&p_cmd_lists->active_cmd_list) ||
	    unlikely(kthread_should_stop()) ||
	    tm_dbg_is_release();
	return res;
}

int scst_cmd_thread(void *arg)
{
	struct scst_cmd_lists *p_cmd_lists = (struct scst_cmd_lists *)arg;

	TRACE_ENTRY();

	PRINT_INFO("Processing thread started, PID %d", current->pid);

#if 0
	set_user_nice(current, 10);
#endif
	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&p_cmd_lists->cmd_list_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_cmd_lists(p_cmd_lists)) {
			add_wait_queue_exclusive_head(
				&p_cmd_lists->cmd_list_waitQ,
				&wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_cmd_lists(p_cmd_lists))
					break;
				spin_unlock_irq(&p_cmd_lists->cmd_list_lock);
				schedule();
				spin_lock_irq(&p_cmd_lists->cmd_list_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&p_cmd_lists->cmd_list_waitQ, &wait);
		}

		if (tm_dbg_is_release()) {
			spin_unlock_irq(&p_cmd_lists->cmd_list_lock);
			tm_dbg_check_released_cmds();
			spin_lock_irq(&p_cmd_lists->cmd_list_lock);
		}

		scst_do_job_active(&p_cmd_lists->active_cmd_list,
			&p_cmd_lists->cmd_list_lock, false);
	}
	spin_unlock_irq(&p_cmd_lists->cmd_list_lock);

#ifdef CONFIG_SCST_EXTRACHECKS
	/*
	 * If kthread_should_stop() is true, we are guaranteed to be either
	 * on the module unload, or there must be at least one other thread to
	 * process the commands lists.
	 */
	if (p_cmd_lists == &scst_main_cmd_lists) {
		sBUG_ON((scst_nr_global_threads == 1) &&
			 !list_empty(&scst_main_cmd_lists.active_cmd_list));
	}
#endif

	PRINT_INFO("Processing thread PID %d finished", current->pid);

	TRACE_EXIT();
	return 0;
}

void scst_cmd_tasklet(long p)
{
	struct scst_tasklet *t = (struct scst_tasklet *)p;

	TRACE_ENTRY();

	spin_lock_irq(&t->tasklet_lock);
	scst_do_job_active(&t->tasklet_cmd_list, &t->tasklet_lock, true);
	spin_unlock_irq(&t->tasklet_lock);

	TRACE_EXIT();
	return;
}

/*
 * Returns 0 on success, < 0 if there is no device handler or
 * > 0 if SCST_FLAG_SUSPENDED set and SCST_FLAG_SUSPENDING - not.
 * No locks, protection is done by the suspended activity.
 */
static int scst_mgmt_translate_lun(struct scst_mgmt_cmd *mcmd)
{
	struct scst_tgt_dev *tgt_dev = NULL;
	struct list_head *sess_tgt_dev_list_head;
	int res = -1;

	TRACE_ENTRY();

	TRACE_DBG("Finding tgt_dev for mgmt cmd %p (lun %lld)", mcmd,
	      (long long unsigned int)mcmd->lun);

	/* See comment about smp_mb() in scst_suspend_activity() */
	__scst_get(1);

	if (unlikely(test_bit(SCST_FLAG_SUSPENDED, &scst_flags) &&
		     !test_bit(SCST_FLAG_SUSPENDING, &scst_flags))) {
		TRACE_MGMT_DBG("%s", "FLAG SUSPENDED set, skipping");
		__scst_put();
		res = 1;
		goto out;
	}

	sess_tgt_dev_list_head =
		&mcmd->sess->sess_tgt_dev_list_hash[HASH_VAL(mcmd->lun)];
	list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
			sess_tgt_dev_list_entry) {
		if (tgt_dev->lun == mcmd->lun) {
			TRACE_DBG("tgt_dev %p found", tgt_dev);
			mcmd->mcmd_tgt_dev = tgt_dev;
			res = 0;
			break;
		}
	}
	if (mcmd->mcmd_tgt_dev == NULL)
		__scst_put();

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* No locks */
void scst_done_cmd_mgmt(struct scst_cmd *cmd)
{
	struct scst_mgmt_cmd_stub *mstb;
	bool wake = 0;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("cmd %p done (tag %llu)",
		       cmd, (long long unsigned int)cmd->tag);

	spin_lock_irqsave(&scst_mcmd_lock, flags);

	if (!test_bit(SCST_CMD_DONE_COUNTED, &cmd->cmd_flags))
		goto out_unlock;

	list_for_each_entry(mstb, &cmd->mgmt_cmd_list,
			cmd_mgmt_cmd_list_entry) {
		struct scst_mgmt_cmd *mcmd = mstb->mcmd;

		TRACE_MGMT_DBG("mcmd %p, mcmd->cmd_done_wait_count %d",
			mcmd, mcmd->cmd_done_wait_count);

		mcmd->cmd_done_wait_count--;
		if (mcmd->cmd_done_wait_count > 0) {
			TRACE_MGMT_DBG("cmd_done_wait_count(%d) not 0, "
				"skipping", mcmd->cmd_done_wait_count);
			continue;
		}

		if (mcmd->completed) {
			sBUG_ON(mcmd->affected_cmds_done_called);
			mcmd->completed = 0;
			mcmd->state = SCST_MCMD_STATE_POST_AFFECTED_CMDS_DONE;
			TRACE_MGMT_DBG("Adding mgmt cmd %p to active mgmt cmd "
				"list", mcmd);
			list_add_tail(&mcmd->mgmt_cmd_list_entry,
				&scst_active_mgmt_cmd_list);
			wake = 1;
		}
	}

out_unlock:
	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	if (wake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	TRACE_EXIT();
	return;
}

/* Called under scst_mcmd_lock and IRQs disabled */
static int __scst_dec_finish_wait_count(struct scst_mgmt_cmd *mcmd, bool *wake)
{
	TRACE_ENTRY();

	mcmd->cmd_finish_wait_count--;
	if (mcmd->cmd_finish_wait_count > 0) {
		TRACE_MGMT_DBG("cmd_finish_wait_count(%d) not 0, "
			"skipping", mcmd->cmd_finish_wait_count);
		goto out;
	}

	if (mcmd->completed) {
		mcmd->state = SCST_MCMD_STATE_DONE;
		TRACE_MGMT_DBG("Adding mgmt cmd %p to active mgmt cmd "
			"list",	mcmd);
		list_add_tail(&mcmd->mgmt_cmd_list_entry,
			&scst_active_mgmt_cmd_list);
		*wake = true;
	}

out:
	TRACE_EXIT_RES(mcmd->cmd_finish_wait_count);
	return mcmd->cmd_finish_wait_count;
}

/* No locks */
void scst_prepare_async_mcmd(struct scst_mgmt_cmd *mcmd)
{
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Preparing mcmd %p for async execution "
		"(cmd_finish_wait_count %d)", mcmd,
		mcmd->cmd_finish_wait_count);

	spin_lock_irqsave(&scst_mcmd_lock, flags);
	mcmd->cmd_finish_wait_count++;
	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_prepare_async_mcmd);

/* No locks */
void scst_async_mcmd_completed(struct scst_mgmt_cmd *mcmd, int status)
{
	unsigned long flags;
	bool wake = false;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Async mcmd %p completed (status %d)", mcmd, status);

	spin_lock_irqsave(&scst_mcmd_lock, flags);

	if (status != SCST_MGMT_STATUS_SUCCESS)
		mcmd->status = status;

	__scst_dec_finish_wait_count(mcmd, &wake);

	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	if (wake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_async_mcmd_completed);

/* No locks */
static void scst_finish_cmd_mgmt(struct scst_cmd *cmd)
{
	struct scst_mgmt_cmd_stub *mstb, *t;
	bool wake = false;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("cmd %p finished (tag %llu)",
		       cmd, (long long unsigned int)cmd->tag);

	spin_lock_irqsave(&scst_mcmd_lock, flags);

	list_for_each_entry_safe(mstb, t, &cmd->mgmt_cmd_list,
			cmd_mgmt_cmd_list_entry) {
		struct scst_mgmt_cmd *mcmd = mstb->mcmd;

		TRACE_MGMT_DBG("mcmd %p, mcmd->cmd_finish_wait_count %d",
			mcmd, mcmd->cmd_finish_wait_count);

		list_del(&mstb->cmd_mgmt_cmd_list_entry);
		mempool_free(mstb, scst_mgmt_stub_mempool);

		if (cmd->completed)
			mcmd->completed_cmd_count++;

		if (__scst_dec_finish_wait_count(mcmd, &wake) > 0) {
			TRACE_MGMT_DBG("cmd_finish_wait_count(%d) not 0, "
				"skipping", mcmd->cmd_finish_wait_count);
			continue;
		}
	}

	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	if (wake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	TRACE_EXIT();
	return;
}

static int scst_call_dev_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev, int set_status)
{
	int res = SCST_DEV_TM_NOT_COMPLETED;
	struct scst_dev_type *h = tgt_dev->dev->handler;

	if (h->task_mgmt_fn) {
		TRACE_MGMT_DBG("Calling dev handler %s task_mgmt_fn(fn=%d)",
			h->name, mcmd->fn);
		EXTRACHECKS_BUG_ON(in_irq() || irqs_disabled());
		res = h->task_mgmt_fn(mcmd, tgt_dev);
		TRACE_MGMT_DBG("Dev handler %s task_mgmt_fn() returned %d",
		      h->name, res);
		if (set_status && (res != SCST_DEV_TM_NOT_COMPLETED))
			mcmd->status = res;
	}
	return res;
}

static inline int scst_is_strict_mgmt_fn(int mgmt_fn)
{
	switch (mgmt_fn) {
#ifdef CONFIG_SCST_ABORT_CONSIDER_FINISHED_TASKS_AS_NOT_EXISTING
	case SCST_ABORT_TASK:
#endif
#if 0
	case SCST_ABORT_TASK_SET:
	case SCST_CLEAR_TASK_SET:
#endif
		return 1;
	default:
		return 0;
	}
}

/* Might be called under sess_list_lock and IRQ off + BHs also off */
void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	int other_ini, int call_dev_task_mgmt_fn)
{
	unsigned long flags;
	static DEFINE_SPINLOCK(other_ini_lock);

	TRACE_ENTRY();

	TRACE((mcmd && mcmd->fn == SCST_ABORT_TASK)
		? TRACE_MGMT_MINOR : TRACE_MGMT,
		"Aborting cmd %p (tag %llu, op %x)",
		cmd, (long long unsigned int)cmd->tag, cmd->cdb[0]);

	/* To protect from concurrent aborts */
	spin_lock_irqsave(&other_ini_lock, flags);

	if (other_ini) {
		/* Might be necessary if command aborted several times */
		if (!test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
			set_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
	} else {
		/* Might be necessary if command aborted several times */
		clear_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
	}

	set_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);

	spin_unlock_irqrestore(&other_ini_lock, flags);

	/*
	 * To sync with cmd->finished/done set in
	 * scst_finish_cmd()/scst_pre_xmit_response()
	 */
	smp_mb__after_set_bit();

	if (cmd->tgt_dev == NULL) {
		spin_lock_irqsave(&scst_init_lock, flags);
		scst_init_poll_cnt++;
		spin_unlock_irqrestore(&scst_init_lock, flags);
		wake_up(&scst_init_cmd_list_waitQ);
	}

	if (call_dev_task_mgmt_fn && (cmd->tgt_dev != NULL)) {
		EXTRACHECKS_BUG_ON(irqs_disabled());
		scst_call_dev_task_mgmt_fn(mcmd, cmd->tgt_dev, 1);
	}

	spin_lock_irqsave(&scst_mcmd_lock, flags);
	if ((mcmd != NULL) && !cmd->finished) {
		struct scst_mgmt_cmd_stub *mstb;

		mstb = mempool_alloc(scst_mgmt_stub_mempool, GFP_ATOMIC);
		if (mstb == NULL) {
			PRINT_CRIT_ERROR("Allocation of management command "
				"stub failed (mcmd %p, cmd %p)", mcmd, cmd);
			goto unlock;
		}
		mstb->mcmd = mcmd;

		/*
		 * cmd can't die here or sess_list_lock already taken and
		 * cmd is in the search list
		 */
		list_add_tail(&mstb->cmd_mgmt_cmd_list_entry,
			&cmd->mgmt_cmd_list);

		/*
		 * Delay the response until the command's finish in order to
		 * guarantee that "no further responses from the task are sent
		 * to the SCSI initiator port" after response from the TM
		 * function is sent (SAM). Plus, we must wait here to be sure
		 * that we won't receive double commands with the same tag.
		 * Moreover, if we don't wait here, we might have a possibility
		 * for data corruption, when aborted and reported as completed
		 * command actually gets executed *after* new commands sent
		 * after this TM command completed.
		 */
		TRACE_MGMT_DBG("cmd %p (tag %llu, sn %lu) being "
			"executed/xmitted (state %d, op %x, proc time %ld "
			"sec., timeout %d sec.), deferring ABORT...", cmd,
			(long long unsigned int)cmd->tag, cmd->sn, cmd->state,
			cmd->cdb[0], (long)(jiffies - cmd->start_time) / HZ,
			cmd->timeout / HZ);

		mcmd->cmd_finish_wait_count++;

		if (cmd->sent_for_exec && !cmd->done) {
			TRACE_MGMT_DBG("cmd %p (tag %llu) is being executed "
				"and not done yet", cmd,
				(long long unsigned int)cmd->tag);
			set_bit(SCST_CMD_DONE_COUNTED, &cmd->cmd_flags);
			mcmd->cmd_done_wait_count++;
		}
	}
unlock:
	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	tm_dbg_release_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* No locks */
static int scst_set_mcmd_next_state(struct scst_mgmt_cmd *mcmd)
{
	int res;

	spin_lock_irq(&scst_mcmd_lock);

	if (mcmd->cmd_finish_wait_count == 0) {
		if (!mcmd->affected_cmds_done_called)
			mcmd->state = SCST_MCMD_STATE_POST_AFFECTED_CMDS_DONE;
		else
			mcmd->state = SCST_MCMD_STATE_DONE;
		res = 0;
	} else if ((mcmd->cmd_done_wait_count == 0) &&
		   (!mcmd->affected_cmds_done_called)) {
		mcmd->state = SCST_MCMD_STATE_POST_AFFECTED_CMDS_DONE;
		res = 0;
		goto out_unlock;
	} else {
		TRACE_MGMT_DBG("cmd_finish_wait_count(%d) not 0, preparing to "
			"wait", mcmd->cmd_finish_wait_count);
		mcmd->state = SCST_MCMD_STATE_EXECUTING;
		res = -1;
	}

	mcmd->completed = 1;

out_unlock:
	spin_unlock_irq(&scst_mcmd_lock);
	return res;
}

static bool __scst_check_unblock_aborted_cmd(struct scst_cmd *cmd,
	struct list_head *list_entry)
{
	bool res;
	if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
		list_del(list_entry);
		spin_lock(&cmd->cmd_lists->cmd_list_lock);
		list_add_tail(&cmd->cmd_list_entry,
			&cmd->cmd_lists->active_cmd_list);
		wake_up(&cmd->cmd_lists->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_lists->cmd_list_lock);
		res = 1;
	} else
		res = 0;
	return res;
}

static void scst_unblock_aborted_cmds(int scst_mutex_held)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	if (!scst_mutex_held)
		mutex_lock(&scst_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		struct scst_cmd *cmd, *tcmd;
		struct scst_tgt_dev *tgt_dev;
		spin_lock_bh(&dev->dev_lock);
		local_irq_disable();
		list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
					blocked_cmd_list_entry) {
			if (__scst_check_unblock_aborted_cmd(cmd,
					&cmd->blocked_cmd_list_entry)) {
				TRACE_MGMT_DBG("Unblock aborted blocked cmd %p",
					cmd);
			}
		}
		local_irq_enable();
		spin_unlock_bh(&dev->dev_lock);

		local_irq_disable();
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
					 dev_tgt_dev_list_entry) {
			spin_lock(&tgt_dev->sn_lock);
			list_for_each_entry_safe(cmd, tcmd,
					&tgt_dev->deferred_cmd_list,
					sn_cmd_list_entry) {
				if (__scst_check_unblock_aborted_cmd(cmd,
						&cmd->sn_cmd_list_entry)) {
					TRACE_MGMT_DBG("Unblocked aborted SN "
						"cmd %p (sn %lu)",
						cmd, cmd->sn);
					tgt_dev->def_cmd_count--;
				}
			}
			spin_unlock(&tgt_dev->sn_lock);
		}
		local_irq_enable();
	}

	if (!scst_mutex_held)
		mutex_unlock(&scst_mutex);

	TRACE_EXIT();
	return;
}

static void __scst_abort_task_set(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_cmd *cmd;
	struct scst_session *sess = tgt_dev->sess;

	TRACE_ENTRY();

	spin_lock_irq(&sess->sess_list_lock);

	TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
	list_for_each_entry(cmd, &sess->search_cmd_list,
			    sess_cmd_list_entry) {
		if ((cmd->tgt_dev == tgt_dev) ||
		    ((cmd->tgt_dev == NULL) &&
		     (cmd->lun == tgt_dev->lun))) {
			if (mcmd->cmd_sn_set) {
				sBUG_ON(!cmd->tgt_sn_set);
				if (scst_sn_before(mcmd->cmd_sn, cmd->tgt_sn) ||
				    (mcmd->cmd_sn == cmd->tgt_sn))
					continue;
			}
			scst_abort_cmd(cmd, mcmd, 0, 0);
		}
	}
	spin_unlock_irq(&sess->sess_list_lock);

	TRACE_EXIT();
	return;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_task_set(struct scst_mgmt_cmd *mcmd)
{
	int res;
	struct scst_tgt_dev *tgt_dev = mcmd->mcmd_tgt_dev;

	TRACE(TRACE_MGMT, "Aborting task set (lun=%lld, mcmd=%p)",
	      (long long unsigned int)tgt_dev->lun, mcmd);

	__scst_abort_task_set(mcmd, tgt_dev);

	tm_dbg_task_mgmt(mcmd->mcmd_tgt_dev->dev, "ABORT TASK SET", 0);

	scst_unblock_aborted_cmds(0);

	scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_is_cmd_belongs_to_dev(struct scst_cmd *cmd,
	struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev = NULL;
	struct list_head *sess_tgt_dev_list_head;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("Finding match for dev %p and cmd %p (lun %lld)", dev, cmd,
	      (long long unsigned int)cmd->lun);

	sess_tgt_dev_list_head =
		&cmd->sess->sess_tgt_dev_list_hash[HASH_VAL(cmd->lun)];
	list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
			sess_tgt_dev_list_entry) {
		if (tgt_dev->lun == cmd->lun) {
			TRACE_DBG("dev %p found", tgt_dev->dev);
			res = (tgt_dev->dev == dev);
			goto out;
		}
	}

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_clear_task_set(struct scst_mgmt_cmd *mcmd)
{
	int res;
	struct scst_device *dev = mcmd->mcmd_tgt_dev->dev;
	struct scst_tgt_dev *tgt_dev;
	LIST_HEAD(UA_tgt_devs);

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Clearing task set (lun=%lld, mcmd=%p)",
		(long long unsigned int)mcmd->lun, mcmd);

	__scst_abort_task_set(mcmd, mcmd->mcmd_tgt_dev);

	mutex_lock(&scst_mutex);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			dev_tgt_dev_list_entry) {
		struct scst_session *sess = tgt_dev->sess;
		struct scst_cmd *cmd;
		int aborted = 0;

		if (tgt_dev == mcmd->mcmd_tgt_dev)
			continue;

		spin_lock_irq(&sess->sess_list_lock);

		TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
		list_for_each_entry(cmd, &sess->search_cmd_list,
				    sess_cmd_list_entry) {
			if ((cmd->dev == dev) ||
			    ((cmd->dev == NULL) &&
			     scst_is_cmd_belongs_to_dev(cmd, dev))) {
				scst_abort_cmd(cmd, mcmd, 1, 0);
				aborted = 1;
			}
		}
		spin_unlock_irq(&sess->sess_list_lock);

		if (aborted)
			list_add_tail(&tgt_dev->extra_tgt_dev_list_entry,
					&UA_tgt_devs);
	}

	tm_dbg_task_mgmt(mcmd->mcmd_tgt_dev->dev, "CLEAR TASK SET", 0);

	scst_unblock_aborted_cmds(1);

	mutex_unlock(&scst_mutex);

	if (!dev->tas) {
		uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];

		scst_set_sense(sense_buffer, sizeof(sense_buffer), dev->d_sense,
			SCST_LOAD_SENSE(scst_sense_cleared_by_another_ini_UA));

		list_for_each_entry(tgt_dev, &UA_tgt_devs,
				extra_tgt_dev_list_entry) {
			scst_check_set_UA(tgt_dev, sense_buffer,
				sizeof(sense_buffer), 0);
		}
	}

	scst_call_dev_task_mgmt_fn(mcmd, mcmd->mcmd_tgt_dev, 0);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued,
 * >0, if it should be requeued, <0 otherwise */
static int scst_mgmt_cmd_init(struct scst_mgmt_cmd *mcmd)
{
	int res = 0, rc;

	TRACE_ENTRY();

	mcmd->state = SCST_MCMD_STATE_READY;

	switch (mcmd->fn) {
	case SCST_ABORT_TASK:
	{
		struct scst_session *sess = mcmd->sess;
		struct scst_cmd *cmd;

		spin_lock_irq(&sess->sess_list_lock);
		cmd = __scst_find_cmd_by_tag(sess, mcmd->tag);
		if (cmd == NULL) {
			TRACE(TRACE_MGMT_MINOR, "ABORT TASK failed: command "
			      "for tag %llu not found",
			      (long long unsigned int)mcmd->tag);
			mcmd->status = SCST_MGMT_STATUS_TASK_NOT_EXIST;
			mcmd->state = SCST_MCMD_STATE_DONE;
			spin_unlock_irq(&sess->sess_list_lock);
			goto out;
		}
		__scst_cmd_get(cmd);
		spin_unlock_irq(&sess->sess_list_lock);
		TRACE_MGMT_DBG("Cmd %p for tag %llu (sn %ld, set %d, "
			"queue_type %x) found, aborting it",
			cmd, (long long unsigned int)mcmd->tag,
			cmd->sn, cmd->sn_set, cmd->queue_type);
		mcmd->cmd_to_abort = cmd;
		if (mcmd->lun_set && (mcmd->lun != cmd->lun)) {
			PRINT_ERROR("ABORT TASK: LUN mismatch: mcmd LUN %llx, "
				"cmd LUN %llx, cmd tag %llu",
				(long long unsigned int)mcmd->lun,
				(long long unsigned int)cmd->lun,
				(long long unsigned int)mcmd->tag);
			mcmd->status = SCST_MGMT_STATUS_REJECTED;
		} else if (mcmd->cmd_sn_set &&
			   (scst_sn_before(mcmd->cmd_sn, cmd->tgt_sn) ||
			    (mcmd->cmd_sn == cmd->tgt_sn))) {
			PRINT_ERROR("ABORT TASK: SN mismatch: mcmd SN %x, "
				"cmd SN %x, cmd tag %llu", mcmd->cmd_sn,
				cmd->tgt_sn, (long long unsigned int)mcmd->tag);
			mcmd->status = SCST_MGMT_STATUS_REJECTED;
		} else {
			scst_abort_cmd(cmd, mcmd, 0, 1);
			scst_unblock_aborted_cmds(0);
		}
		res = scst_set_mcmd_next_state(mcmd);
		mcmd->cmd_to_abort = NULL; /* just in case */
		__scst_cmd_put(cmd);
		break;
	}

	case SCST_TARGET_RESET:
	case SCST_NEXUS_LOSS_SESS:
	case SCST_ABORT_ALL_TASKS_SESS:
	case SCST_NEXUS_LOSS:
	case SCST_ABORT_ALL_TASKS:
	case SCST_UNREG_SESS_TM:
		break;

	case SCST_ABORT_TASK_SET:
	case SCST_CLEAR_ACA:
	case SCST_CLEAR_TASK_SET:
	case SCST_LUN_RESET:
		rc = scst_mgmt_translate_lun(mcmd);
		if (rc < 0) {
			PRINT_ERROR("Corresponding device for LUN %lld not "
				"found", (long long unsigned int)mcmd->lun);
			mcmd->status = SCST_MGMT_STATUS_LUN_NOT_EXIST;
			mcmd->state = SCST_MCMD_STATE_DONE;
		} else if (rc != 0)
			res = rc;
		break;

	default:
		sBUG();
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_target_reset(struct scst_mgmt_cmd *mcmd)
{
	int res, rc;
	struct scst_device *dev;
	struct scst_acg *acg = mcmd->sess->acg;
	struct scst_acg_dev *acg_dev;
	int cont, c;
	LIST_HEAD(host_devs);

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Target reset (mcmd %p, cmd count %d)",
		mcmd, atomic_read(&mcmd->sess->sess_cmd_count));

	mcmd->needs_unblocking = 1;

	mutex_lock(&scst_mutex);

	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		struct scst_device *d;
		struct scst_tgt_dev *tgt_dev;
		int found = 0;

		dev = acg_dev->dev;

		spin_lock_bh(&dev->dev_lock);
		__scst_block_dev(dev);
		scst_process_reset(dev, mcmd->sess, NULL, mcmd, true);
		spin_unlock_bh(&dev->dev_lock);

		cont = 0;
		c = 0;
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			cont = 1;
			if (mcmd->sess == tgt_dev->sess) {
				rc = scst_call_dev_task_mgmt_fn(mcmd,
						tgt_dev, 0);
				if (rc == SCST_DEV_TM_NOT_COMPLETED)
					c = 1;
				else if ((rc < 0) &&
					 (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
					mcmd->status = rc;
				break;
			}
		}
		if (cont && !c)
			continue;

		if (dev->scsi_dev == NULL)
			continue;

		list_for_each_entry(d, &host_devs, tm_dev_list_entry) {
			if (dev->scsi_dev->host->host_no ==
				    d->scsi_dev->host->host_no) {
				found = 1;
				break;
			}
		}
		if (!found)
			list_add_tail(&dev->tm_dev_list_entry, &host_devs);

		tm_dbg_task_mgmt(dev, "TARGET RESET", 0);
	}

	scst_unblock_aborted_cmds(1);

	/*
	 * We suppose here that for all commands that already on devices
	 * on/after scsi_reset_provider() completion callbacks will be called.
	 */

	list_for_each_entry(dev, &host_devs, tm_dev_list_entry) {
		/* dev->scsi_dev must be non-NULL here */
		TRACE(TRACE_MGMT, "Resetting host %d bus ",
			dev->scsi_dev->host->host_no);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
		rc = scsi_reset_provider(dev->scsi_dev, SCSI_TRY_RESET_TARGET);
#else
		rc = scsi_reset_provider(dev->scsi_dev, SCSI_TRY_RESET_BUS);
#endif
		TRACE(TRACE_MGMT, "Result of host %d target reset: %s",
		      dev->scsi_dev->host->host_no,
		      (rc == SUCCESS) ? "SUCCESS" : "FAILED");
#if 0
		if ((rc != SUCCESS) &&
		    (mcmd->status == SCST_MGMT_STATUS_SUCCESS)) {
			/*
			 * SCSI_TRY_RESET_BUS is also done by
			 * scsi_reset_provider()
			 */
			mcmd->status = SCST_MGMT_STATUS_FAILED;
		}
#else
	/*
	 * scsi_reset_provider() returns very weird status, so let's
	 * always succeed
	 */
#endif
	}

	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		dev = acg_dev->dev;
		if (dev->scsi_dev != NULL)
			dev->scsi_dev->was_reset = 0;
	}

	mutex_unlock(&scst_mutex);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_lun_reset(struct scst_mgmt_cmd *mcmd)
{
	int res, rc;
	struct scst_tgt_dev *tgt_dev = mcmd->mcmd_tgt_dev;
	struct scst_device *dev = tgt_dev->dev;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Resetting LUN %lld (mcmd %p)",
	      (long long unsigned int)tgt_dev->lun, mcmd);

	mcmd->needs_unblocking = 1;

	spin_lock_bh(&dev->dev_lock);
	__scst_block_dev(dev);
	scst_process_reset(dev, mcmd->sess, NULL, mcmd, true);
	spin_unlock_bh(&dev->dev_lock);

	rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 1);
	if (rc != SCST_DEV_TM_NOT_COMPLETED)
		goto out_tm_dbg;

	if (dev->scsi_dev != NULL) {
		TRACE(TRACE_MGMT, "Resetting host %d bus ",
		      dev->scsi_dev->host->host_no);
		rc = scsi_reset_provider(dev->scsi_dev, SCSI_TRY_RESET_DEVICE);
#if 0
		if (rc != SUCCESS && mcmd->status == SCST_MGMT_STATUS_SUCCESS)
			mcmd->status = SCST_MGMT_STATUS_FAILED;
#else
		/*
		 * scsi_reset_provider() returns very weird status, so let's
		 * always succeed
		 */
#endif
		dev->scsi_dev->was_reset = 0;
	}

	scst_unblock_aborted_cmds(0);

out_tm_dbg:
	tm_dbg_task_mgmt(mcmd->mcmd_tgt_dev->dev, "LUN RESET", 0);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* scst_mutex supposed to be held */
static void scst_do_nexus_loss_sess(struct scst_mgmt_cmd *mcmd)
{
	int i;
	struct scst_session *sess = mcmd->sess;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&sess->sess_tgt_dev_list_hash[i];
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			scst_nexus_loss(tgt_dev,
				(mcmd->fn != SCST_UNREG_SESS_TM));
		}
	}

	TRACE_EXIT();
	return;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_all_nexus_loss_sess(struct scst_mgmt_cmd *mcmd,
	int nexus_loss)
{
	int res;
	int i;
	struct scst_session *sess = mcmd->sess;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	if (nexus_loss) {
		TRACE(TRACE_MGMT_MINOR, "Nexus loss for sess %p (mcmd %p)",
			sess, mcmd);
	} else {
		TRACE(TRACE_MGMT_MINOR, "Aborting all from sess %p (mcmd %p)",
			sess, mcmd);
	}

	mutex_lock(&scst_mutex);

	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&sess->sess_tgt_dev_list_hash[i];
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			int rc;

			__scst_abort_task_set(mcmd, tgt_dev);

			rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);
			if (rc < 0 && mcmd->status == SCST_MGMT_STATUS_SUCCESS)
				mcmd->status = rc;

			tm_dbg_task_mgmt(tgt_dev->dev, "NEXUS LOSS SESS or "
				"ABORT ALL SESS or UNREG SESS",
				(mcmd->fn == SCST_UNREG_SESS_TM));
		}
	}

	scst_unblock_aborted_cmds(1);

	mutex_unlock(&scst_mutex);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* scst_mutex supposed to be held */
static void scst_do_nexus_loss_tgt(struct scst_mgmt_cmd *mcmd)
{
	int i;
	struct scst_tgt *tgt = mcmd->sess->tgt;
	struct scst_session *sess;

	TRACE_ENTRY();

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
			struct list_head *sess_tgt_dev_list_head =
				&sess->sess_tgt_dev_list_hash[i];
			struct scst_tgt_dev *tgt_dev;
			list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
					sess_tgt_dev_list_entry) {
				scst_nexus_loss(tgt_dev, true);
			}
		}
	}

	TRACE_EXIT();
	return;
}

static int scst_abort_all_nexus_loss_tgt(struct scst_mgmt_cmd *mcmd,
	int nexus_loss)
{
	int res;
	int i;
	struct scst_tgt *tgt = mcmd->sess->tgt;
	struct scst_session *sess;

	TRACE_ENTRY();

	if (nexus_loss) {
		TRACE(TRACE_MGMT_MINOR, "I_T Nexus loss (tgt %p, mcmd %p)",
			tgt, mcmd);
	} else {
		TRACE(TRACE_MGMT_MINOR, "Aborting all from tgt %p (mcmd %p)",
			tgt, mcmd);
	}

	mutex_lock(&scst_mutex);

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
			struct list_head *sess_tgt_dev_list_head =
				&sess->sess_tgt_dev_list_hash[i];
			struct scst_tgt_dev *tgt_dev;
			list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
					sess_tgt_dev_list_entry) {
				int rc;

				__scst_abort_task_set(mcmd, tgt_dev);

				if (nexus_loss)
					scst_nexus_loss(tgt_dev, true);

				if (mcmd->sess == tgt_dev->sess) {
					rc = scst_call_dev_task_mgmt_fn(
						mcmd, tgt_dev, 0);
					if ((rc < 0) &&
					    (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
						mcmd->status = rc;
				}

				tm_dbg_task_mgmt(tgt_dev->dev, "NEXUS LOSS or "
					"ABORT ALL", 0);
			}
		}
	}

	scst_unblock_aborted_cmds(1);

	mutex_unlock(&scst_mutex);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_mgmt_cmd_exec(struct scst_mgmt_cmd *mcmd)
{
	int res = 0;

	TRACE_ENTRY();

	mcmd->status = SCST_MGMT_STATUS_SUCCESS;

	switch (mcmd->fn) {
	case SCST_ABORT_TASK_SET:
		res = scst_abort_task_set(mcmd);
		break;

	case SCST_CLEAR_TASK_SET:
		if (mcmd->mcmd_tgt_dev->dev->tst ==
				SCST_CONTR_MODE_SEP_TASK_SETS)
			res = scst_abort_task_set(mcmd);
		else
			res = scst_clear_task_set(mcmd);
		break;

	case SCST_LUN_RESET:
		res = scst_lun_reset(mcmd);
		break;

	case SCST_TARGET_RESET:
		res = scst_target_reset(mcmd);
		break;

	case SCST_ABORT_ALL_TASKS_SESS:
		res = scst_abort_all_nexus_loss_sess(mcmd, 0);
		break;

	case SCST_NEXUS_LOSS_SESS:
	case SCST_UNREG_SESS_TM:
		res = scst_abort_all_nexus_loss_sess(mcmd, 1);
		break;

	case SCST_ABORT_ALL_TASKS:
		res = scst_abort_all_nexus_loss_tgt(mcmd, 0);
		break;

	case SCST_NEXUS_LOSS:
		res = scst_abort_all_nexus_loss_tgt(mcmd, 1);
		break;

	case SCST_CLEAR_ACA:
		if (scst_call_dev_task_mgmt_fn(mcmd, mcmd->mcmd_tgt_dev, 1) ==
				SCST_DEV_TM_NOT_COMPLETED) {
			mcmd->status = SCST_MGMT_STATUS_FN_NOT_SUPPORTED;
			/* Nothing to do (yet) */
		}
		goto out_done;

	default:
		PRINT_ERROR("Unknown task management function %d", mcmd->fn);
		mcmd->status = SCST_MGMT_STATUS_REJECTED;
		goto out_done;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	mcmd->state = SCST_MCMD_STATE_DONE;
	goto out;
}

static void scst_call_task_mgmt_affected_cmds_done(struct scst_mgmt_cmd *mcmd)
{
	struct scst_session *sess = mcmd->sess;

	if ((sess->tgt->tgtt->task_mgmt_affected_cmds_done != NULL) &&
	    (mcmd->fn != SCST_UNREG_SESS_TM)) {
		TRACE_DBG("Calling target %s task_mgmt_affected_cmds_done(%p)",
			sess->tgt->tgtt->name, sess);
		sess->tgt->tgtt->task_mgmt_affected_cmds_done(mcmd);
		TRACE_MGMT_DBG("Target's %s task_mgmt_affected_cmds_done() "
			"returned", sess->tgt->tgtt->name);
	}
	return;
}

static int scst_mgmt_affected_cmds_done(struct scst_mgmt_cmd *mcmd)
{
	int res;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	switch (mcmd->fn) {
	case SCST_NEXUS_LOSS_SESS:
	case SCST_UNREG_SESS_TM:
		scst_do_nexus_loss_sess(mcmd);
		break;

	case SCST_NEXUS_LOSS:
		scst_do_nexus_loss_tgt(mcmd);
		break;
	}

	mutex_unlock(&scst_mutex);

	scst_call_task_mgmt_affected_cmds_done(mcmd);

	mcmd->affected_cmds_done_called = 1;

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_mgmt_cmd_send_done(struct scst_mgmt_cmd *mcmd)
{
	struct scst_device *dev;
	struct scst_session *sess = mcmd->sess;

	TRACE_ENTRY();

	mcmd->state = SCST_MCMD_STATE_FINISHED;
	if (scst_is_strict_mgmt_fn(mcmd->fn) && (mcmd->completed_cmd_count > 0))
		mcmd->status = SCST_MGMT_STATUS_TASK_NOT_EXIST;

	TRACE(TRACE_MGMT_MINOR, "TM command fn %d finished, status %x",
		mcmd->fn, mcmd->status);

	if (!mcmd->affected_cmds_done_called) {
		/* It might happen in case of errors */
		scst_call_task_mgmt_affected_cmds_done(mcmd);
	}

	if ((sess->tgt->tgtt->task_mgmt_fn_done != NULL) &&
	    (mcmd->fn != SCST_UNREG_SESS_TM)) {
		TRACE_DBG("Calling target %s task_mgmt_fn_done(%p)",
			sess->tgt->tgtt->name, sess);
		sess->tgt->tgtt->task_mgmt_fn_done(mcmd);
		TRACE_MGMT_DBG("Target's %s task_mgmt_fn_done() "
			"returned", sess->tgt->tgtt->name);
	}

	if (mcmd->needs_unblocking) {
		switch (mcmd->fn) {
		case SCST_LUN_RESET:
			scst_unblock_dev(mcmd->mcmd_tgt_dev->dev);
			break;

		case SCST_TARGET_RESET:
		{
			struct scst_acg *acg = mcmd->sess->acg;
			struct scst_acg_dev *acg_dev;

			mutex_lock(&scst_mutex);
			list_for_each_entry(acg_dev, &acg->acg_dev_list,
					acg_dev_list_entry) {
				dev = acg_dev->dev;
				scst_unblock_dev(dev);
			}
			mutex_unlock(&scst_mutex);
			break;
		}

		default:
			sBUG();
			break;
		}
	}

	mcmd->tgt_priv = NULL;

	TRACE_EXIT();
	return;
}

/* Returns >0, if cmd should be requeued */
static int scst_process_mgmt_cmd(struct scst_mgmt_cmd *mcmd)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("mcmd %p, state %d", mcmd, mcmd->state);

	while (1) {
		switch (mcmd->state) {
		case SCST_MCMD_STATE_INIT:
			res = scst_mgmt_cmd_init(mcmd);
			if (res)
				goto out;
			break;

		case SCST_MCMD_STATE_READY:
			if (scst_mgmt_cmd_exec(mcmd))
				goto out;
			break;

		case SCST_MCMD_STATE_POST_AFFECTED_CMDS_DONE:
			if (scst_mgmt_affected_cmds_done(mcmd))
				goto out;
			break;

		case SCST_MCMD_STATE_DONE:
			scst_mgmt_cmd_send_done(mcmd);
			break;

		default:
			PRINT_ERROR("Unknown state %d of management command",
				    mcmd->state);
			res = -1;
			/* go through */
		case SCST_MCMD_STATE_FINISHED:
			scst_free_mgmt_cmd(mcmd);
			goto out;

#ifdef CONFIG_SCST_EXTRACHECKS
		case SCST_MCMD_STATE_EXECUTING:
			sBUG();
#endif
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static inline int test_mgmt_cmd_list(void)
{
	int res = !list_empty(&scst_active_mgmt_cmd_list) ||
		  unlikely(kthread_should_stop());
	return res;
}

int scst_tm_thread(void *arg)
{
	TRACE_ENTRY();

	PRINT_INFO("Task management thread started, PID %d", current->pid);

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock_irq(&scst_mcmd_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_mgmt_cmd_list()) {
			add_wait_queue_exclusive(&scst_mgmt_cmd_list_waitQ,
						 &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_mgmt_cmd_list())
					break;
				spin_unlock_irq(&scst_mcmd_lock);
				schedule();
				spin_lock_irq(&scst_mcmd_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&scst_mgmt_cmd_list_waitQ, &wait);
		}

		while (!list_empty(&scst_active_mgmt_cmd_list)) {
			int rc;
			struct scst_mgmt_cmd *mcmd;
			mcmd = list_entry(scst_active_mgmt_cmd_list.next,
					  typeof(*mcmd), mgmt_cmd_list_entry);
			TRACE_MGMT_DBG("Deleting mgmt cmd %p from active cmd "
				"list", mcmd);
			list_del(&mcmd->mgmt_cmd_list_entry);
			spin_unlock_irq(&scst_mcmd_lock);
			rc = scst_process_mgmt_cmd(mcmd);
			spin_lock_irq(&scst_mcmd_lock);
			if (rc > 0) {
				if (test_bit(SCST_FLAG_SUSPENDED, &scst_flags) &&
				    !test_bit(SCST_FLAG_SUSPENDING,
						&scst_flags)) {
					TRACE_MGMT_DBG("Adding mgmt cmd %p to "
						"head of delayed mgmt cmd list",
						mcmd);
					list_add(&mcmd->mgmt_cmd_list_entry,
						&scst_delayed_mgmt_cmd_list);
				} else {
					TRACE_MGMT_DBG("Adding mgmt cmd %p to "
						"head of active mgmt cmd list",
						mcmd);
					list_add(&mcmd->mgmt_cmd_list_entry,
					       &scst_active_mgmt_cmd_list);
				}
			}
		}
	}
	spin_unlock_irq(&scst_mcmd_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so scst_active_mgmt_cmd_list must be empty.
	 */
	sBUG_ON(!list_empty(&scst_active_mgmt_cmd_list));

	PRINT_INFO("Task management thread PID %d finished", current->pid);

	TRACE_EXIT();
	return 0;
}

static struct scst_mgmt_cmd *scst_pre_rx_mgmt_cmd(struct scst_session
	*sess, int fn, int atomic, void *tgt_priv)
{
	struct scst_mgmt_cmd *mcmd = NULL;

	TRACE_ENTRY();

	if (unlikely(sess->tgt->tgtt->task_mgmt_fn_done == NULL)) {
		PRINT_ERROR("New mgmt cmd, but task_mgmt_fn_done() is NULL "
			    "(target %s)", sess->tgt->tgtt->name);
		goto out;
	}

	mcmd = scst_alloc_mgmt_cmd(atomic ? GFP_ATOMIC : GFP_KERNEL);
	if (mcmd == NULL) {
		PRINT_CRIT_ERROR("Lost TM fn %x, initiator %s", fn,
			sess->initiator_name);
		goto out;
	}

	mcmd->sess = sess;
	mcmd->fn = fn;
	mcmd->state = SCST_MCMD_STATE_INIT;
	mcmd->tgt_priv = tgt_priv;

out:
	TRACE_EXIT();
	return mcmd;
}

static int scst_post_rx_mgmt_cmd(struct scst_session *sess,
	struct scst_mgmt_cmd *mcmd)
{
	unsigned long flags;
	int res = 0;

	TRACE_ENTRY();

	scst_sess_get(sess);

	if (unlikely(sess->shut_phase != SCST_SESS_SPH_READY)) {
		PRINT_CRIT_ERROR("New mgmt cmd while shutting down the "
			"session %p shut_phase %ld", sess, sess->shut_phase);
		sBUG();
	}

	local_irq_save(flags);

	spin_lock(&sess->sess_list_lock);
	atomic_inc(&sess->sess_cmd_count);

	if (unlikely(sess->init_phase != SCST_SESS_IPH_READY)) {
		switch (sess->init_phase) {
		case SCST_SESS_IPH_INITING:
			TRACE_DBG("Adding mcmd %p to init deferred mcmd list",
				mcmd);
			list_add_tail(&mcmd->mgmt_cmd_list_entry,
				&sess->init_deferred_mcmd_list);
			goto out_unlock;
		case SCST_SESS_IPH_SUCCESS:
			break;
		case SCST_SESS_IPH_FAILED:
			res = -1;
			goto out_unlock;
		default:
			sBUG();
		}
	}

	spin_unlock(&sess->sess_list_lock);

	TRACE_MGMT_DBG("Adding mgmt cmd %p to active mgmt cmd list", mcmd);
	spin_lock(&scst_mcmd_lock);
	list_add_tail(&mcmd->mgmt_cmd_list_entry, &scst_active_mgmt_cmd_list);
	spin_unlock(&scst_mcmd_lock);

	local_irq_restore(flags);

	wake_up(&scst_mgmt_cmd_list_waitQ);

out:
	TRACE_EXIT();
	return res;

out_unlock:
	spin_unlock(&sess->sess_list_lock);
	local_irq_restore(flags);
	goto out;
}

/*
 * Must not be called in parallel with scst_unregister_session() for the
 * same sess
 */
int scst_rx_mgmt_fn(struct scst_session *sess,
	const struct scst_rx_mgmt_params *params)
{
	int res = -EFAULT;
	struct scst_mgmt_cmd *mcmd = NULL;

	TRACE_ENTRY();

	switch (params->fn) {
	case SCST_ABORT_TASK:
		sBUG_ON(!params->tag_set);
		break;
	case SCST_TARGET_RESET:
	case SCST_ABORT_ALL_TASKS:
	case SCST_NEXUS_LOSS:
		break;
	default:
		sBUG_ON(!params->lun_set);
	}

	mcmd = scst_pre_rx_mgmt_cmd(sess, params->fn, params->atomic,
		params->tgt_priv);
	if (mcmd == NULL)
		goto out;

	if (params->lun_set) {
		mcmd->lun = scst_unpack_lun(params->lun, params->lun_len);
		if (mcmd->lun == NO_SUCH_LUN)
			goto out_free;
		mcmd->lun_set = 1;
	}

	if (params->tag_set)
		mcmd->tag = params->tag;

	mcmd->cmd_sn_set = params->cmd_sn_set;
	mcmd->cmd_sn = params->cmd_sn;

	TRACE((params->fn == SCST_ABORT_TASK) ? TRACE_MGMT_MINOR : TRACE_MGMT,
		"TM fn %x", params->fn);

	TRACE_MGMT_DBG("sess=%p, tag_set %d, tag %lld, lun_set %d, "
		"lun=%lld, cmd_sn_set %d, cmd_sn %d, priv %p", sess,
		params->tag_set,
		(long long unsigned int)params->tag,
		params->lun_set,
		(long long unsigned int)mcmd->lun,
		params->cmd_sn_set,
		params->cmd_sn,
		params->tgt_priv);

	if (scst_post_rx_mgmt_cmd(sess, mcmd) != 0)
		goto out_free;

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	scst_free_mgmt_cmd(mcmd);
	mcmd = NULL;
	goto out;
}
EXPORT_SYMBOL(scst_rx_mgmt_fn);

/*
 * Returns true if string "string" matches pattern "wild", false otherwise.
 * Pattern is a regular DOS-type pattern, containing '*' and '?' symbols.
 * '*' means match all any symbols, '?' means match only any single symbol.
 *
 * For instance:
 * if (wildcmp("bl?h.*", "blah.jpg")) {
 *   // match
 *  } else {
 *   // no match
 *  }
 *
 * Written by Jack Handy - jakkhandy@hotmail.com
 * Taken by Gennadiy Nerubayev <parakie@gmail.com> from
 * http://www.codeproject.com/KB/string/wildcmp.aspx. No license attached
 * to it, and is posted on a free site; assumed to be free for use.
 */
static bool wildcmp(const char *wild, const char *string)
{
	const char *cp = NULL, *mp = NULL;

	while ((*string) && (*wild != '*')) {
		if ((*wild != *string) && (*wild != '?'))
			return false;

		wild++;
		string++;
	}

	while (*string) {
		if (*wild == '*') {
			if (!*++wild)
				return true;

			mp = wild;
			cp = string+1;
		} else if ((*wild == *string) || (*wild == '?')) {
			wild++;
			string++;
		} else {
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*')
		wild++;

	return !*wild;
}

/* scst_mutex supposed to be held */
static struct scst_acg *scst_find_acg(const char *initiator_name)
{
	struct scst_acg *acg, *res = NULL;
	struct scst_acn *n;

	TRACE_ENTRY();

	list_for_each_entry(acg, &scst_acg_list, scst_acg_list_entry) {
		list_for_each_entry(n, &acg->acn_list, acn_list_entry) {
			if (wildcmp(n->name, initiator_name)) {
				TRACE_DBG("Access control group %s found",
					acg->acg_name);
				res = acg;
				goto out;
			}
		}
	}

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* scst_mutex supposed to be held */
static struct scst_acg *scst_find_acg_by_name(const char *acg_name)
{
	struct scst_acg *acg, *res = NULL;

	TRACE_ENTRY();

	list_for_each_entry(acg, &scst_acg_list, scst_acg_list_entry) {
		if (strcmp(acg->acg_name, acg_name) == 0) {
			TRACE_DBG("Access control group %s found",
				acg->acg_name);
			res = acg;
			goto out;
		}
	}

out:
	TRACE_EXIT_HRES(res);
	return res;
}

static int scst_init_session(struct scst_session *sess)
{
	int res = 0;
	struct scst_acg *acg = NULL;
	struct scst_cmd *cmd;
	struct scst_mgmt_cmd *mcmd, *tm;
	int mwake = 0;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	if (sess->initiator_name)
		acg = scst_find_acg(sess->initiator_name);
	if ((acg == NULL) && (sess->tgt->default_group_name != NULL))
		acg = scst_find_acg_by_name(sess->tgt->default_group_name);
	if (acg == NULL)
		acg = scst_default_acg;

	PRINT_INFO("Using security group \"%s\" for initiator \"%s\"",
		acg->acg_name, sess->initiator_name);

	sess->acg = acg;
	TRACE_MGMT_DBG("Assigning session %p to acg %s", sess, acg->acg_name);
	list_add_tail(&sess->acg_sess_list_entry, &acg->acg_sess_list);

	TRACE_DBG("Adding sess %p to tgt->sess_list", sess);
	list_add_tail(&sess->sess_list_entry, &sess->tgt->sess_list);

	res = scst_sess_alloc_tgt_devs(sess);

	mutex_unlock(&scst_mutex);

	if (sess->init_result_fn) {
		TRACE_DBG("Calling init_result_fn(%p)", sess);
		sess->init_result_fn(sess, sess->reg_sess_data, res);
		TRACE_DBG("%s", "init_result_fn() returned");
	}

	spin_lock_irq(&sess->sess_list_lock);

	if (res == 0)
		sess->init_phase = SCST_SESS_IPH_SUCCESS;
	else
		sess->init_phase = SCST_SESS_IPH_FAILED;

restart:
	list_for_each_entry(cmd, &sess->init_deferred_cmd_list,
				cmd_list_entry) {
		TRACE_DBG("Deleting cmd %p from init deferred cmd list", cmd);
		list_del(&cmd->cmd_list_entry);
		atomic_dec(&sess->sess_cmd_count);
		spin_unlock_irq(&sess->sess_list_lock);
		scst_cmd_init_done(cmd, SCST_CONTEXT_THREAD);
		spin_lock_irq(&sess->sess_list_lock);
		goto restart;
	}

	spin_lock(&scst_mcmd_lock);
	list_for_each_entry_safe(mcmd, tm, &sess->init_deferred_mcmd_list,
				mgmt_cmd_list_entry) {
		TRACE_DBG("Moving mgmt command %p from init deferred mcmd list",
			mcmd);
		list_move_tail(&mcmd->mgmt_cmd_list_entry,
			&scst_active_mgmt_cmd_list);
		mwake = 1;
	}
	spin_unlock(&scst_mcmd_lock);
	sess->init_phase = SCST_SESS_IPH_READY;
	spin_unlock_irq(&sess->sess_list_lock);

	if (mwake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	scst_sess_put(sess);

	TRACE_EXIT();
	return res;
}

struct scst_session *scst_register_session(struct scst_tgt *tgt, int atomic,
	const char *initiator_name, void *data,
	void (*result_fn) (struct scst_session *sess, void *data, int result))
{
	struct scst_session *sess;
	int res;
	unsigned long flags;

	TRACE_ENTRY();

	sess = scst_alloc_session(tgt, atomic ? GFP_ATOMIC : GFP_KERNEL,
		initiator_name);
	if (sess == NULL)
		goto out;

	scst_sess_get(sess); /* one for registered session */
	scst_sess_get(sess); /* one held until sess is inited */

	if (atomic) {
		sess->reg_sess_data = data;
		sess->init_result_fn = result_fn;
		spin_lock_irqsave(&scst_mgmt_lock, flags);
		TRACE_DBG("Adding sess %p to scst_sess_init_list", sess);
		list_add_tail(&sess->sess_init_list_entry,
			      &scst_sess_init_list);
		spin_unlock_irqrestore(&scst_mgmt_lock, flags);
		wake_up(&scst_mgmt_waitQ);
	} else {
		res = scst_init_session(sess);
		if (res != 0)
			goto out_free;
	}

out:
	TRACE_EXIT();
	return sess;

out_free:
	scst_free_session(sess);
	sess = NULL;
	goto out;
}
EXPORT_SYMBOL(scst_register_session);

/*
 * Must not be called in parallel with scst_rx_cmd() or
 * scst_rx_mgmt_fn_*() for the same sess
 */
void scst_unregister_session(struct scst_session *sess, int wait,
	void (*unreg_done_fn) (struct scst_session *sess))
{
	unsigned long flags;
	DECLARE_COMPLETION_ONSTACK(c);
	int rc, lun;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Unregistering session %p (wait %d)", sess, wait);

	sess->unreg_done_fn = unreg_done_fn;

	/* Abort all outstanding commands and clear reservation, if necessary */
	lun = 0;
	rc = scst_rx_mgmt_fn_lun(sess, SCST_UNREG_SESS_TM,
		(uint8_t *)&lun, sizeof(lun), SCST_ATOMIC, NULL);
	if (rc != 0) {
		PRINT_ERROR("SCST_UNREG_SESS_TM failed %d (sess %p)",
			rc, sess);
	}

	sess->shut_phase = SCST_SESS_SPH_SHUTDOWN;

	spin_lock_irqsave(&scst_mgmt_lock, flags);

	if (wait)
		sess->shutdown_compl = &c;

	spin_unlock_irqrestore(&scst_mgmt_lock, flags);

	scst_sess_put(sess);

	if (wait) {
		TRACE_DBG("Waiting for session %p to complete", sess);
		wait_for_completion(&c);
	}

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_unregister_session);

static inline int test_mgmt_list(void)
{
	int res = !list_empty(&scst_sess_init_list) ||
		  !list_empty(&scst_sess_shut_list) ||
		  unlikely(kthread_should_stop());
	return res;
}

int scst_global_mgmt_thread(void *arg)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	PRINT_INFO("Management thread started, PID %d", current->pid);

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock_irq(&scst_mgmt_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_mgmt_list()) {
			add_wait_queue_exclusive(&scst_mgmt_waitQ, &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_mgmt_list())
					break;
				spin_unlock_irq(&scst_mgmt_lock);
				schedule();
				spin_lock_irq(&scst_mgmt_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&scst_mgmt_waitQ, &wait);
		}

		while (!list_empty(&scst_sess_init_list)) {
			sess = list_entry(scst_sess_init_list.next,
				typeof(*sess), sess_init_list_entry);
			TRACE_DBG("Removing sess %p from scst_sess_init_list",
				sess);
			list_del(&sess->sess_init_list_entry);
			spin_unlock_irq(&scst_mgmt_lock);

			if (sess->init_phase == SCST_SESS_IPH_INITING)
				scst_init_session(sess);
			else {
				PRINT_CRIT_ERROR("session %p is in "
					"scst_sess_init_list, but in unknown "
					"init phase %x", sess,
					sess->init_phase);
				sBUG();
			}

			spin_lock_irq(&scst_mgmt_lock);
		}

		while (!list_empty(&scst_sess_shut_list)) {
			sess = list_entry(scst_sess_shut_list.next,
				typeof(*sess), sess_shut_list_entry);
			TRACE_DBG("Removing sess %p from scst_sess_shut_list",
				sess);
			list_del(&sess->sess_shut_list_entry);
			spin_unlock_irq(&scst_mgmt_lock);

			switch (sess->shut_phase) {
			case SCST_SESS_SPH_SHUTDOWN:
				sBUG_ON(atomic_read(&sess->refcnt) != 0);
				scst_free_session_callback(sess);
				break;
			default:
				PRINT_CRIT_ERROR("session %p is in "
					"scst_sess_shut_list, but in unknown "
					"shut phase %lx", sess,
					sess->shut_phase);
				sBUG();
				break;
			}

			spin_lock_irq(&scst_mgmt_lock);
		}
	}
	spin_unlock_irq(&scst_mgmt_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so both lists must be empty.
	 */
	sBUG_ON(!list_empty(&scst_sess_init_list));
	sBUG_ON(!list_empty(&scst_sess_shut_list));

	PRINT_INFO("Management thread PID %d finished", current->pid);

	TRACE_EXIT();
	return 0;
}

/* Called under sess->sess_list_lock */
static struct scst_cmd *__scst_find_cmd_by_tag(struct scst_session *sess,
	uint64_t tag)
{
	struct scst_cmd *cmd = NULL;

	TRACE_ENTRY();

	/* ToDo: hash list */

	TRACE_DBG("%s (sess=%p, tag=%llu)", "Searching in search cmd list",
		  sess, (long long unsigned int)tag);
	list_for_each_entry(cmd, &sess->search_cmd_list,
			sess_cmd_list_entry) {
		if (cmd->tag == tag)
			goto out;
	}
	cmd = NULL;
out:
	TRACE_EXIT();
	return cmd;
}

struct scst_cmd *scst_find_cmd(struct scst_session *sess, void *data,
			       int (*cmp_fn) (struct scst_cmd *cmd,
					      void *data))
{
	struct scst_cmd *cmd = NULL;
	unsigned long flags = 0;

	TRACE_ENTRY();

	if (cmp_fn == NULL)
		goto out;

	spin_lock_irqsave(&sess->sess_list_lock, flags);

	TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
	list_for_each_entry(cmd, &sess->search_cmd_list,
			sess_cmd_list_entry) {
		if (cmp_fn(cmd, data))
			goto out_unlock;
	}

	cmd = NULL;

out_unlock:
	spin_unlock_irqrestore(&sess->sess_list_lock, flags);

out:
	TRACE_EXIT();
	return cmd;
}
EXPORT_SYMBOL(scst_find_cmd);

struct scst_cmd *scst_find_cmd_by_tag(struct scst_session *sess,
	uint64_t tag)
{
	unsigned long flags;
	struct scst_cmd *cmd;
	spin_lock_irqsave(&sess->sess_list_lock, flags);
	cmd = __scst_find_cmd_by_tag(sess, tag);
	spin_unlock_irqrestore(&sess->sess_list_lock, flags);
	return cmd;
}
EXPORT_SYMBOL(scst_find_cmd_by_tag);

void *scst_cmd_get_tgt_priv_lock(struct scst_cmd *cmd)
{
	void *res;
	unsigned long flags;
	spin_lock_irqsave(&scst_main_lock, flags);
	res = cmd->tgt_priv;
	spin_unlock_irqrestore(&scst_main_lock, flags);
	return res;
}
EXPORT_SYMBOL(scst_cmd_get_tgt_priv_lock);

void scst_cmd_set_tgt_priv_lock(struct scst_cmd *cmd, void *val)
{
	unsigned long flags;
	spin_lock_irqsave(&scst_main_lock, flags);
	cmd->tgt_priv = val;
	spin_unlock_irqrestore(&scst_main_lock, flags);
}
EXPORT_SYMBOL(scst_cmd_set_tgt_priv_lock);
