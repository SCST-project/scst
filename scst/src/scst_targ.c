/*
 *  scst_targ.c
 *  
 *  Copyright (C) 2004-2007 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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
#include <asm/unistd.h>
#include <asm/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include "scsi_tgt.h"
#include "scst_priv.h"

static void scst_cmd_set_sn(struct scst_cmd *cmd);
static int __scst_init_cmd(struct scst_cmd *cmd);

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

#ifdef EXTRACHECKS
	if (unlikely(sess->shut_phase != SCST_SESS_SPH_READY)) {
		PRINT_ERROR("%s", "New cmd while shutting down the session");
		sBUG();
	}
#endif

	cmd = scst_alloc_cmd(atomic ? GFP_ATOMIC : GFP_KERNEL);
	if (cmd == NULL)
		goto out;

	cmd->sess = sess;
	cmd->tgt = sess->tgt;
	cmd->tgtt = sess->tgt->tgtt;
	cmd->state = SCST_CMD_STATE_INIT_WAIT;

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

static int scst_init_cmd(struct scst_cmd *cmd, int context)
{
	int rc;

	TRACE_ENTRY();

	/* See the comment in scst_do_job_init() */
	if (unlikely(!list_empty(&scst_init_cmd_list))) {
		TRACE_MGMT_DBG("%s", "init cmd list busy");
		goto out_redirect;
	}
	smp_rmb();

	rc = __scst_init_cmd(cmd);
	if (unlikely(rc > 0))
		goto out_redirect;
	else if (unlikely(rc != 0))
		goto out;

	/* Small context optimization */
	if (((context == SCST_CONTEXT_TASKLET) ||
	     (context == SCST_CONTEXT_DIRECT_ATOMIC)) && 
	    scst_cmd_is_expected_set(cmd)) {
		if (cmd->expected_data_direction == SCST_DATA_WRITE) {
			if ( !test_bit(SCST_TGT_DEV_AFTER_INIT_WR_ATOMIC,
					&cmd->tgt_dev->tgt_dev_flags))
				context = SCST_CONTEXT_THREAD;
		} else {
			if ( !test_bit(SCST_TGT_DEV_AFTER_INIT_OTH_ATOMIC,
					&cmd->tgt_dev->tgt_dev_flags))
				context = SCST_CONTEXT_THREAD;
		}
	}

out:
	TRACE_EXIT_RES(context);
	return context;

out_redirect:
	if (cmd->preprocessing_only) {
		/*
		 * Poor man solution for single threaded targets, where 
		 * blocking receiver at least sometimes means blocking all.
		 */
		sBUG_ON(context != SCST_CONTEXT_DIRECT);
		scst_set_busy(cmd);
		cmd->state = SCST_CMD_STATE_XMIT_RESP;
		/* Keep initiator away from too many BUSY commands */
		if (!in_interrupt() && !in_atomic())
			msleep(50);
		else
			WARN_ON_ONCE(1);
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
		context = -1;
	}
	goto out;
}

void scst_cmd_init_done(struct scst_cmd *cmd, int pref_context)
{
	unsigned long flags;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d (cmd %p)", pref_context, cmd);
	TRACE(TRACE_SCSI, "tag=%llu, lun=%Ld, CDB len=%d", cmd->tag, 
		(uint64_t)cmd->lun, cmd->cdb_len);
	TRACE_BUFF_FLAG(TRACE_SCSI|TRACE_RECV_BOT, "Recieving CDB",
		cmd->cdb, cmd->cdb_len);

#ifdef EXTRACHECKS
	if (unlikely(in_irq()) && ((pref_context == SCST_CONTEXT_DIRECT) ||
			 (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)))
	{
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_TASKLET instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_TASKLET;
	}
#endif

	atomic_inc(&sess->sess_cmd_count);

	spin_lock_irqsave(&sess->sess_list_lock, flags);

	list_add_tail(&cmd->search_cmd_list_entry, &sess->search_cmd_list);

	if (unlikely(sess->init_phase != SCST_SESS_IPH_READY)) {
		switch(sess->init_phase) {
		case SCST_SESS_IPH_SUCCESS:
			break;
		case SCST_SESS_IPH_INITING:
			TRACE_DBG("Adding cmd %p to init deferred cmd list", cmd);
			list_add_tail(&cmd->cmd_list_entry, 
				&sess->init_deferred_cmd_list);
			spin_unlock_irqrestore(&sess->sess_list_lock, flags);
			goto out;
		case SCST_SESS_IPH_FAILED:
			spin_unlock_irqrestore(&sess->sess_list_lock, flags);
			scst_set_busy(cmd);
			cmd->state = SCST_CMD_STATE_XMIT_RESP;
			goto active;
		default:
			sBUG();
		}
	}

	spin_unlock_irqrestore(&sess->sess_list_lock, flags);

	if (unlikely(cmd->lun == (lun_t)-1)) {
		PRINT_ERROR("Wrong LUN %d, finishing cmd", -1);
		scst_set_cmd_error(cmd,
		   	SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		cmd->state = SCST_CMD_STATE_XMIT_RESP;
		goto active;
	}

	if (unlikely(cmd->cdb_len == 0)) {
		PRINT_ERROR("Wrong CDB len %d, finishing cmd", 0);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		cmd->state = SCST_CMD_STATE_XMIT_RESP;
		goto active;
	}

	cmd->state = SCST_CMD_STATE_INIT;
	/* cmd must be inited here to keep the order */
	pref_context = scst_init_cmd(cmd, pref_context);
	if (unlikely(pref_context < 0))
		goto out;

active:
	/* Here cmd must not be in any cmd list, no locks */
	switch (pref_context) {
	case SCST_CONTEXT_TASKLET:
		scst_schedule_tasklet(cmd);
		break;

	case SCST_CONTEXT_DIRECT:
	case SCST_CONTEXT_DIRECT_ATOMIC:
		scst_process_active_cmd(cmd, pref_context);
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

static int scst_parse_cmd(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int state;
	struct scst_device *dev = cmd->dev;
	struct scst_info_cdb cdb_info;
	int atomic = scst_cmd_atomic(cmd);
	int orig_bufflen;

	TRACE_ENTRY();

	if (atomic && !dev->handler->parse_atomic) {
		TRACE_DBG("Dev handler %s parse() can not be "
		      "called in atomic context, rescheduling to the thread",
		      dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	cmd->inc_expected_sn_on_done = dev->handler->inc_expected_sn_on_done;

	if (cmd->skip_parse || cmd->internal)
		goto call_parse;

	/*
	 * Expected transfer data supplied by the SCSI transport via the
	 * target driver are untrusted, so we prefer to fetch them from CDB.
	 * Additionally, not all transports support supplying the expected
	 * transfer data.
	 */

	if (unlikely(scst_get_cdb_info(cmd->cdb, dev->handler->type, 
			&cdb_info) != 0)) {
		PRINT_ERROR("Unknown opcode 0x%02x for %s. "
			"Should you update scst_scsi_op_table?",
			cmd->cdb[0], dev->handler->name);
#ifdef USE_EXPECTED_VALUES
		if (scst_cmd_is_expected_set(cmd)) {
			TRACE(TRACE_SCSI, "Using initiator supplied values: "
				"direction %d, transfer_len %d",
				cmd->expected_data_direction,
				cmd->expected_transfer_len);
			cmd->data_direction = cmd->expected_data_direction;
			
			cmd->bufflen = cmd->expected_transfer_len;
			/* Restore (likely) lost CDB length */
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
		TRACE(TRACE_SCSI, "op_name <%s>, direction=%d (expected %d, "
			"set %s), transfer_len=%d (expected len %d), flags=%d",
			cdb_info.op_name, cdb_info.direction,
			cmd->expected_data_direction,
			scst_cmd_is_expected_set(cmd) ? "yes" : "no",
			cdb_info.transfer_len, cmd->expected_transfer_len,
			cdb_info.flags);

		cmd->data_direction = cdb_info.direction;

		if (unlikely((cdb_info.flags & SCST_UNKNOWN_LENGTH) != 0)) {
			if (scst_cmd_is_expected_set(cmd)) {
				/*
				 * Command data length can't be easily
				 * determined from the CDB. Get it from
				 * the supplied expected value, but
				 * limit it to some reasonable value (50MB).
				 */
				cmd->bufflen = min(cmd->expected_transfer_len,
							50*1024*1024);
			} else
				cmd->bufflen = 0;
		} else
			cmd->bufflen = cdb_info.transfer_len;

		/* Restore (likely) lost CDB length */
		cmd->cdb_len = cdb_info.cdb_len;
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

call_parse:
	orig_bufflen = cmd->bufflen;

	if (likely(!scst_is_cmd_local(cmd))) {
		TRACE_DBG("Calling dev handler %s parse(%p)",
		      dev->handler->name, cmd);
		TRACE_BUFF_FLAG(TRACE_SEND_BOT, "Parsing: ", cmd->cdb, cmd->cdb_len);
		state = dev->handler->parse(cmd, &cdb_info);
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

	if (cmd->data_buf_alloced && unlikely((orig_bufflen > cmd->bufflen))) {
		PRINT_ERROR("Dev handler supplied data buffer (size %d), "
			"is less, than required (size %d)", cmd->bufflen,
			orig_bufflen);
		goto out_error;
	}

#ifdef EXTRACHECKS
	if ((state != SCST_CMD_STATE_XMIT_RESP) &&
	    (((cmd->data_direction == SCST_DATA_UNKNOWN) &&
	    	(state != SCST_CMD_STATE_DEV_PARSE)) ||
	    ((cmd->bufflen != 0) && 
	    	(cmd->data_direction == SCST_DATA_NONE) &&
	    	(cmd->status == 0)) ||
	    ((cmd->bufflen == 0) && 
	    	(cmd->data_direction != SCST_DATA_NONE)) ||
	    ((cmd->bufflen != 0) && (cmd->sg == NULL) &&
	    	(state > SCST_CMD_STATE_PREPARE_SPACE))))
	{
		PRINT_ERROR("Dev handler %s parse() returned "
			       "invalid cmd data_direction %d, "
			       "bufflen %d or state %d (opcode 0x%x)",
			       dev->handler->name, 
			       cmd->data_direction, cmd->bufflen,
			       state, cmd->cdb[0]);
		goto out_error;
	}
#endif

	if (scst_cmd_is_expected_set(cmd)) {
#ifdef USE_EXPECTED_VALUES
#	ifdef EXTRACHECKS
		if ((cmd->data_direction != cmd->expected_data_direction) ||
		    (cmd->bufflen != cmd->expected_transfer_len)) {
			PRINT_ERROR("Expected values don't match decoded ones: "
				"data_direction %d, expected_data_direction %d, "
				"bufflen %d, expected_transfer_len %d",
				cmd->data_direction, cmd->expected_data_direction,
				cmd->bufflen, cmd->expected_transfer_len);
		}
#	endif
		cmd->data_direction = cmd->expected_data_direction;
		cmd->bufflen = cmd->expected_transfer_len;
#else
		if (unlikely(cmd->data_direction != cdb_info.direction)) {
			PRINT_ERROR("Expected data direction %d for opcode "
				"0x%02x (handler %s, target %s) doesn't match "
				"decoded value %d", cmd->data_direction,
				cmd->cdb[0], dev->handler->name,
				cmd->tgtt->name, cdb_info.direction);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_invalid_message));
			goto out_dev_done;
		}
		if (unlikely(cmd->bufflen != cmd->expected_transfer_len)) {
			PRINT_INFO("Warning: expected transfer length %d for "
				"opcode 0x%02x (handler %s, target %s) doesn't "
				"match decoded value %d. Faulty initiator?",
				cmd->expected_transfer_len, cmd->cdb[0],
				dev->handler->name, cmd->tgtt->name,
				cmd->bufflen);
		}
#endif
	}

	switch (state) {
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_DEV_PARSE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_PRE_EXEC:
	case SCST_CMD_STATE_SEND_TO_MIDLEV:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
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
		if (cmd->data_direction == SCST_DATA_READ)
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

#ifndef USE_EXPECTED_VALUES
out_dev_done:
#endif
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;

out_xmit:
	cmd->state = SCST_CMD_STATE_XMIT_RESP;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

static int scst_prepare_space(struct scst_cmd *cmd)
{
	int r = 0, res = SCST_CMD_STATE_RES_CONT_SAME;

	TRACE_ENTRY();

	if (cmd->data_direction == SCST_DATA_NONE)
		goto prep_done;

	if (cmd->data_buf_tgt_alloc) {
		int orig_bufflen = cmd->bufflen;

		TRACE_MEM("%s", "Custom tgt data buf allocation requested");

		r = cmd->tgtt->alloc_data_buf(cmd);
		if (r > 0)
			goto alloc;
		else if (r == 0) {
			cmd->data_buf_alloced = 1;
			if (unlikely(orig_bufflen < cmd->bufflen)) {
				PRINT_ERROR("Target driver allocated data "
					"buffer (size %d), is less, than "
					"required (size %d)", orig_bufflen,
					cmd->bufflen);
				goto out_error;
			}
		} else
			goto check;
	}

alloc:
	if (!cmd->data_buf_alloced) {
		r = scst_alloc_space(cmd);
	} else {
		TRACE_MEM("%s", "data_buf_alloced set, returning");
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
		if (scst_cmd_atomic(cmd) && 
		    !cmd->tgtt->preprocessing_done_atomic) {
			TRACE_DBG("%s", "preprocessing_done() can not be "
			      "called in atomic context, rescheduling to "
			      "the thread");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
			TRACE_MGMT_DBG("ABORTED set, returning ABORTED for "
				"cmd %p", cmd);
			cmd->state = SCST_CMD_STATE_DEV_DONE;
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

	switch (cmd->data_direction) {
	case SCST_DATA_WRITE:
		cmd->state = SCST_CMD_STATE_RDY_TO_XFER;
		break;

	default:
		cmd->state = SCST_CMD_STATE_PRE_EXEC;
		break;
	}

out:
	TRACE_EXIT_HRES(res);
	return res;

out_no_space:
	TRACE(TRACE_OUT_OF_MEM, "Unable to allocate or build requested buffer "
		"(size %d), sending BUSY or QUEUE FULL status", cmd->bufflen);
	scst_set_busy(cmd);
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;

out_error:
	scst_set_cmd_error(cmd,	SCST_LOAD_SENSE(scst_sense_hardw_error));
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

void scst_restart_cmd(struct scst_cmd *cmd, int status, int pref_context)
{
	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d", pref_context);
	TRACE_DBG("tag=%llu, status=%#x", scst_cmd_get_tag(cmd), status);

#ifdef EXTRACHECKS
	if (in_irq() && ((pref_context == SCST_CONTEXT_DIRECT) ||
			 (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)))
	{
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_TASKLET instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_TASKLET;
	}
#endif

	switch (status) {
	case SCST_PREPROCESS_STATUS_SUCCESS:
		switch (cmd->data_direction) {
		case SCST_DATA_WRITE:
			cmd->state = SCST_CMD_STATE_RDY_TO_XFER;
			break;
		default:
			cmd->state = SCST_CMD_STATE_PRE_EXEC;
			break;
		}
		if (cmd->set_sn_on_restart_cmd)
			scst_cmd_set_sn(cmd);
		/* Small context optimization */
		if ((pref_context == SCST_CONTEXT_TASKLET) || 
		    (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)) {
		    	if (cmd->data_direction == SCST_DATA_WRITE) {
				if ( !test_bit(SCST_TGT_DEV_AFTER_RESTART_WR_ATOMIC,
						&cmd->tgt_dev->tgt_dev_flags))
					pref_context = SCST_CONTEXT_THREAD;
			} else {
				if ( !test_bit(SCST_TGT_DEV_AFTER_RESTART_OTH_ATOMIC,
						&cmd->tgt_dev->tgt_dev_flags))
					pref_context = SCST_CONTEXT_THREAD;
			}
		}
		break;

	case SCST_PREPROCESS_STATUS_ERROR_SENSE_SET:
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;

	case SCST_PREPROCESS_STATUS_ERROR_FATAL:
		set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
		/* go through */
	case SCST_PREPROCESS_STATUS_ERROR:
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_hardw_error));
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;

	default:
		PRINT_ERROR("%s() received unknown status %x", __func__,
			status);
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;
	}

	scst_proccess_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}

/* No locks */
static int scst_queue_retry_cmd(struct scst_cmd *cmd, int finished_cmds)
{
	struct scst_tgt *tgt = cmd->sess->tgt;
	int res = 0;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&tgt->tgt_lock, flags);
	tgt->retry_cmds++;
	smp_mb();
	TRACE(TRACE_RETRY, "TGT QUEUE FULL: incrementing retry_cmds %d",
	      tgt->retry_cmds);
	if (finished_cmds != atomic_read(&tgt->finished_cmds)) {
		/* At least one cmd finished, so try again */
		tgt->retry_cmds--;
		TRACE(TRACE_RETRY, "TGT QUEUE FULL, direct retry "
		      "(finished_cmds=%d, tgt->finished_cmds=%d, "
		      "retry_cmds=%d)", finished_cmds,
		      atomic_read(&tgt->finished_cmds), tgt->retry_cmds);
		res = -1;
		goto out_unlock_tgt;
	}

	TRACE(TRACE_RETRY, "Adding cmd %p to retry cmd list", cmd);
	list_add_tail(&cmd->cmd_list_entry, &tgt->retry_cmd_list);

	if (!tgt->retry_timer_active) {
		tgt->retry_timer.expires = jiffies + SCST_TGT_RETRY_TIMEOUT;
		add_timer(&tgt->retry_timer);
		tgt->retry_timer_active = 1;
	}

out_unlock_tgt:
	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_rdy_to_xfer(struct scst_cmd *cmd)
{
	int res, rc;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_dev_done;
	}

	if (cmd->tgtt->rdy_to_xfer == NULL) {
		cmd->state = SCST_CMD_STATE_PRE_EXEC;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		goto out;
	}

	if (atomic && !cmd->tgtt->rdy_to_xfer_atomic) {
		TRACE_DBG("%s", "rdy_to_xfer() can not be "
		      "called in atomic context, rescheduling to the thread");
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	while (1) {
		int finished_cmds = atomic_read(&cmd->sess->tgt->finished_cmds);

		res = SCST_CMD_STATE_RES_CONT_NEXT;
		cmd->state = SCST_CMD_STATE_DATA_WAIT;

		TRACE_DBG("Calling rdy_to_xfer(%p)", cmd);
#ifdef DEBUG_RETRY
		if (((scst_random() % 100) == 75))
			rc = SCST_TGT_RES_QUEUE_FULL;
		else
#endif
			rc = cmd->tgtt->rdy_to_xfer(cmd);
		TRACE_DBG("rdy_to_xfer() returned %d", rc);

		if (likely(rc == SCST_TGT_RES_SUCCESS))
			goto out;

		/* Restore the previous state */
		cmd->state = SCST_CMD_STATE_RDY_TO_XFER;

		switch (rc) {
		case SCST_TGT_RES_QUEUE_FULL:
		{
			if (scst_queue_retry_cmd(cmd, finished_cmds) == 0)
				break;
			else
				continue;
		}

		case SCST_TGT_RES_NEED_THREAD_CTX:
		{
			TRACE_DBG("Target driver %s "
			      "rdy_to_xfer() requested thread "
			      "context, rescheduling", cmd->tgtt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			break;
		}

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
		     "fatal error", cmd->tgtt->name);
	} else {
		PRINT_ERROR("Target driver %s rdy_to_xfer() returned invalid "
			    "value %d", cmd->tgtt->name, rc);
	}
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

out_dev_done:
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

/* No locks, but might be in IRQ */
void scst_proccess_redirect_cmd(struct scst_cmd *cmd, int context,
	int check_retries)
{
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_DBG("Context: %d", context);

	switch(context) {
	case SCST_CONTEXT_DIRECT:
	case SCST_CONTEXT_DIRECT_ATOMIC:
		if (check_retries)
			scst_check_retries(cmd->tgt);
		scst_process_active_cmd(cmd, context);
		break;

	default:
		PRINT_ERROR("Context %x is unknown, using the thread one",
			    context);
		/* go through */
	case SCST_CONTEXT_THREAD:
		if (check_retries)
			scst_check_retries(cmd->tgt);
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
			scst_check_retries(cmd->tgt);
		scst_schedule_tasklet(cmd);
		break;
	}

	TRACE_EXIT();
	return;
}

void scst_rx_data(struct scst_cmd *cmd, int status, int pref_context)
{
	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d", pref_context);
	TRACE(TRACE_SCSI, "tag=%llu status=%#x", scst_cmd_get_tag(cmd), status);

#ifdef EXTRACHECKS
	if (in_irq() && ((pref_context == SCST_CONTEXT_DIRECT) ||
			 (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)))
	{
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_TASKLET instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_TASKLET;
	}
#endif

	switch (status) {
	case SCST_RX_STATUS_SUCCESS:
		cmd->state = SCST_CMD_STATE_PRE_EXEC;
		/* Small context optimization */
		if ((pref_context == SCST_CONTEXT_TASKLET) || 
		    (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)) {
			if ( !test_bit(SCST_TGT_DEV_AFTER_RX_DATA_ATOMIC, 
					&cmd->tgt_dev->tgt_dev_flags))
				pref_context = SCST_CONTEXT_THREAD;
		}
		break;

	case SCST_RX_STATUS_ERROR_SENSE_SET:
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;

	case SCST_RX_STATUS_ERROR_FATAL:
		set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
		/* go through */
	case SCST_RX_STATUS_ERROR:
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_hardw_error));
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;

	default:
		PRINT_ERROR("scst_rx_data() received unknown status %x",
			status);
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;
	}

	scst_proccess_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}

static int scst_tgt_pre_exec(struct scst_cmd *cmd)
{
	int rc;

	TRACE_ENTRY();

	cmd->state = SCST_CMD_STATE_SEND_TO_MIDLEV;

	if (cmd->tgtt->pre_exec == NULL)
		goto out;

	TRACE_DBG("Calling pre_exec(%p)", cmd);
	rc = cmd->tgtt->pre_exec(cmd);
	TRACE_DBG("pre_exec() returned %d", rc);

	if (unlikely(rc != SCST_PREPROCESS_STATUS_SUCCESS)) {
		switch(rc) {
		case SCST_PREPROCESS_STATUS_ERROR_SENSE_SET:
			cmd->state = SCST_CMD_STATE_DEV_DONE;
			break;
		case SCST_PREPROCESS_STATUS_ERROR_FATAL:
			set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
			/* go through */
		case SCST_PREPROCESS_STATUS_ERROR:
			scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
			cmd->state = SCST_CMD_STATE_DEV_DONE;
			break;
		default:
			sBUG();
			break;
		}
	}

out:
	TRACE_EXIT();
	return SCST_CMD_STATE_RES_CONT_SAME;
}

static void scst_inc_check_expected_sn(struct scst_cmd *cmd)
{
	struct scst_cmd *c;

	if (likely(cmd->sn_set))
		scst_inc_expected_sn(cmd->tgt_dev, cmd->sn_slot);

	c = scst_check_deferred_commands(cmd->tgt_dev);
	if (c != NULL) {
		unsigned long flags;
		spin_lock_irqsave(&c->cmd_lists->cmd_list_lock, flags);
		TRACE_SN("Adding cmd %p to active cmd list", c);
		list_add_tail(&c->cmd_list_entry,
			&c->cmd_lists->active_cmd_list);
		wake_up(&c->cmd_lists->cmd_list_waitQ);
		spin_unlock_irqrestore(&c->cmd_lists->cmd_list_lock, flags);
	}
}

static void scst_do_cmd_done(struct scst_cmd *cmd, int result,
	const uint8_t *rq_sense, int rq_sense_len, int resid)
{
	unsigned char type;

	TRACE_ENTRY();

	if (cmd->inc_expected_sn_on_done)
		scst_inc_check_expected_sn(cmd);

	cmd->status = result & 0xff;
	cmd->msg_status = msg_byte(result);
	cmd->host_status = host_byte(result);
	cmd->driver_status = driver_byte(result);
	if (unlikely(resid != 0)) {
#ifdef EXTRACHECKS
		if ((resid < 0) || (resid > cmd->resp_data_len)) {
			PRINT_ERROR("Wrong resid %d (cmd->resp_data_len=%d)",
				resid, cmd->resp_data_len);
		} else
#endif
			scst_set_resp_data_len(cmd, cmd->resp_data_len - resid);
	}

	/* 
	 * We checked that rq_sense_len < sizeof(cmd->sense_buffer)
	 * in init_scst()
	 */
	memcpy(cmd->sense_buffer, rq_sense, rq_sense_len);
	memset(&cmd->sense_buffer[rq_sense_len], 0,
		sizeof(cmd->sense_buffer) - rq_sense_len);

	TRACE(TRACE_SCSI, "result=%x, cmd->status=%x, resid=%d, "
	      "cmd->msg_status=%x, cmd->host_status=%x, "
	      "cmd->driver_status=%x", result, cmd->status, resid,
	      cmd->msg_status, cmd->host_status, cmd->driver_status);

	cmd->completed = 1;

	if (likely(cmd->host_status != DID_RESET) &&
	    likely(!SCST_SENSE_VALID(cmd->sense_buffer)))
		scst_dec_on_dev_cmd(cmd);

	type = cmd->dev->handler->type;
	if ((cmd->cdb[0] == MODE_SENSE || cmd->cdb[0] == MODE_SENSE_10) &&
	    cmd->tgt_dev->acg_dev->rd_only_flag &&
	    (type == TYPE_DISK || type == TYPE_WORM || type == TYPE_MOD ||
	     type == TYPE_TAPE)) {
		int32_t length;
		uint8_t *address;

		length = scst_get_buf_first(cmd, &address);
		TRACE_DBG("length %d", length);
		if (unlikely(length <= 0)) {
			PRINT_ERROR("%s: scst_get_buf_first() failed",
				__func__);
			goto out;
		}
		if (length > 2 && cmd->cdb[0] == MODE_SENSE) {
			address[2] |= 0x80;   /* Write Protect*/
		}
		else if (length > 3 && cmd->cdb[0] == MODE_SENSE_10) {
			address[3] |= 0x80;   /* Write Protect*/
		}
		scst_put_buf(cmd, address);
	}

out:
	TRACE_EXIT();
	return;
}

/* For small context optimization */
static inline int scst_optimize_post_exec_context(struct scst_cmd *cmd,
	int context)
{
	if ((context == SCST_CONTEXT_TASKLET) || 
	    (context == SCST_CONTEXT_DIRECT_ATOMIC)) {
		if ( !test_bit(SCST_TGT_DEV_AFTER_EXEC_ATOMIC, 
				&cmd->tgt_dev->tgt_dev_flags))
			context = SCST_CONTEXT_THREAD;
	}
	return context;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
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

	cmd->state = SCST_CMD_STATE_DEV_DONE;

	scst_proccess_redirect_cmd(cmd,
		scst_optimize_post_exec_context(cmd, scst_get_context()), 0);

out:
	TRACE_EXIT();
	return;
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */
static void scst_cmd_done(void *data, char *sense, int result, int resid)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	cmd = (struct scst_cmd *)data;
	if (cmd == NULL)
		goto out;

	scst_do_cmd_done(cmd, result, sense, SCST_SENSE_BUFFERSIZE, resid);

	cmd->state = SCST_CMD_STATE_DEV_DONE;

	scst_proccess_redirect_cmd(cmd,
		scst_optimize_post_exec_context(cmd, scst_get_context()), 0);

out:
	TRACE_EXIT();
	return;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */

static void scst_cmd_done_local(struct scst_cmd *cmd, int next_state)
{
	TRACE_ENTRY();

	if (likely(!SCST_SENSE_VALID(cmd->sense_buffer)))
		scst_dec_on_dev_cmd(cmd);

	if (cmd->inc_expected_sn_on_done)
		scst_inc_check_expected_sn(cmd);

	if (next_state == SCST_CMD_STATE_DEFAULT)
		next_state = SCST_CMD_STATE_DEV_DONE;

#if defined(DEBUG) || defined(TRACING)
	if (next_state == SCST_CMD_STATE_DEV_DONE) {
		if (cmd->sg) {
			int i;
			struct scatterlist *sg = cmd->sg;
			TRACE(TRACE_RECV_TOP, 
			      "Exec'd %d S/G(s) at %p sg[0].page at %p",
			      cmd->sg_cnt, sg, (void*)sg[0].page);
			for(i = 0; i < cmd->sg_cnt; ++i) {
				TRACE_BUFF_FLAG(TRACE_RECV_TOP, 
					"Exec'd sg", page_address(sg[i].page),
					sg[i].length);
			}
		}
	}
#endif


#ifdef EXTRACHECKS
	if ((next_state != SCST_CMD_STATE_DEV_DONE) &&
	    (next_state != SCST_CMD_STATE_XMIT_RESP) &&
	    (next_state != SCST_CMD_STATE_FINISHED)) 
	{
		PRINT_ERROR("scst_cmd_done_local() received invalid cmd "
			    "state %d (opcode %d)", next_state, cmd->cdb[0]);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		next_state = SCST_CMD_STATE_DEV_DONE;
	}
#endif
	cmd->state = next_state;

	scst_proccess_redirect_cmd(cmd,
		scst_optimize_post_exec_context(cmd, scst_get_context()), 0);

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
	if (unlikely(buffer_size <= 0))
		goto out_err;

	if (buffer_size < 16)
		goto out_put_err;

	memset(buffer, 0, buffer_size);
	offs = 8;

	/* sess->sess_tgt_dev_list_hash is protected by suspended activity */
	for(i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&cmd->sess->sess_tgt_dev_list_hash[i];
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			if (!overflow) {
				if (offs >= buffer_size) {
					scst_put_buf(cmd, buffer);
					buffer_size = scst_get_buf_next(cmd, &buffer);
					if (buffer_size > 0) {
						memset(buffer, 0, buffer_size);
						offs = 0;
					} else {
						overflow = 1;
						goto inc_dev_cnt;
					}
				}
				if ((buffer_size - offs) < 8) {
					PRINT_ERROR("Buffer allocated for REPORT "
						"LUNS command doesn't allow to fit 8 "
						"byte entry (buffer_size=%d)",
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
	if (unlikely(buffer_size <= 0))
		goto out_err;
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

out_done:
	/* Report the result */
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);

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
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_compl;
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

static inline void scst_report_reserved(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
	cmd->completed = 1;
	/* Report the result */
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);

	TRACE_EXIT();
	return;
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
		     "(lun=%Ld)", (uint64_t)cmd->lun);
		scst_set_cmd_error(cmd,
		   	SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		cmd->completed = 1;
		res = SCST_EXEC_COMPLETED;
		goto out;
	}

	dev = cmd->dev;

	scst_block_dev_cmd(cmd, 1);

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	spin_lock_bh(&dev->dev_lock);

	if (test_bit(SCST_TGT_DEV_RESERVED, &cmd->tgt_dev->tgt_dev_flags)) {
		scst_report_reserved(cmd);
		/* !! At this point cmd, sess & tgt_dev can be already freed !! */
		res = SCST_EXEC_COMPLETED;
		goto out_unlock;
	}

	list_for_each_entry(tgt_dev_tmp, &dev->dev_tgt_dev_list,
			    dev_tgt_dev_list_entry) 
	{
		if (cmd->tgt_dev != tgt_dev_tmp)
			set_bit(SCST_TGT_DEV_RESERVED, 
				&tgt_dev_tmp->tgt_dev_flags);
	}
	dev->dev_reserved = 1;

out_unlock:
	spin_unlock_bh(&dev->dev_lock);
	
out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	res = SCST_EXEC_COMPLETED;
	/* Report the result */
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
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
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;
}

/* No locks, no IRQ or IRQ-safe context allowed */
int scst_check_local_events(struct scst_cmd *cmd)
{
	int res, rc;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_uncomplete;
	}

	/* Reserve check before Unit Attention */
	if (unlikely(test_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags))) {
		if ((cmd->cdb[0] != INQUIRY) && (cmd->cdb[0] != REPORT_LUNS) &&
		    (cmd->cdb[0] != RELEASE) && (cmd->cdb[0] != RELEASE_10) &&
		    (cmd->cdb[0] != REPORT_DEVICE_IDENTIFIER) &&
		    (cmd->cdb[0] != ALLOW_MEDIUM_REMOVAL || (cmd->cdb[4] & 3)) &&
		    (cmd->cdb[0] != LOG_SENSE) && (cmd->cdb[0] != REQUEST_SENSE))
		{
			scst_report_reserved(cmd);
			goto out_complete;
		}
	}

	/* If we had a internal bus reset, set the command error unit attention */
	if ((cmd->dev->scsi_dev != NULL) &&
	    unlikely(cmd->dev->scsi_dev->was_reset)) {
		if (scst_is_ua_command(cmd)) 
		{
			struct scst_device *dev = cmd->dev;
			int done = 0;
			/* Prevent more than 1 cmd to be triggered by was_reset */
			spin_lock_bh(&dev->dev_lock);
			barrier(); /* to reread was_reset */
			if (dev->scsi_dev->was_reset) {
				TRACE(TRACE_MGMT, "was_reset is %d", 1);
				scst_set_cmd_error(cmd,
					   SCST_LOAD_SENSE(scst_sense_reset_UA));
				/* It looks like it is safe to clear was_reset here */
				dev->scsi_dev->was_reset = 0;
				smp_mb();
				done = 1;
			}
			spin_unlock_bh(&dev->dev_lock);

			if (done)
				goto out_complete;
		}
	}

	if (unlikely(test_bit(SCST_TGT_DEV_UA_PENDING, 
			&cmd->tgt_dev->tgt_dev_flags))) {
		if (scst_is_ua_command(cmd)) 
		{
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
	cmd->completed = 1;
	goto out;

out_uncomplete:
	res = -1;
	goto out;
}

/* 
 * The result of cmd execution, if any, should be reported 
 * via scst_cmd_done_local() 
 */
static int scst_pre_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	/* Check READ_ONLY device status */
	if (tgt_dev->acg_dev->rd_only_flag &&
	    (cmd->cdb[0] == WRITE_6 ||  /* ToDo: full list of the modify cmds */
	     cmd->cdb[0] == WRITE_10 ||
	     cmd->cdb[0] == WRITE_12 ||
	     cmd->cdb[0] == WRITE_16 ||
	     cmd->cdb[0] == WRITE_VERIFY ||
	     cmd->cdb[0] == WRITE_VERIFY_12 ||
	     cmd->cdb[0] == WRITE_VERIFY_16 ||
	     (cmd->dev->handler->type == TYPE_TAPE &&
	      (cmd->cdb[0] == ERASE || cmd->cdb[0] == WRITE_FILEMARKS))))
	{
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_data_protect));
		goto out_done;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	res = SCST_EXEC_COMPLETED;
	cmd->completed = 1;
	/* Report the result */
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;
}

/* 
 * The result of cmd execution, if any, should be reported 
 * via scst_cmd_done_local() 
 */
static inline int scst_local_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;

	TRACE_ENTRY();

	/*
	 * Adding new commands here don't forget to update
	 * scst_is_cmd_local() in scsi_tgt.h, if necessary
	 */

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
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_do_send_to_midlev(struct scst_cmd *cmd)
{
	int rc = SCST_EXEC_NOT_COMPLETED;

	TRACE_ENTRY();

	/* Check here to let an out of SN cmd be queued w/o context switch */
	if (scst_cmd_atomic(cmd) && !cmd->dev->handler->exec_atomic) {
		TRACE_DBG("Dev handler %s exec() can not be "
		      "called in atomic context, rescheduling to the thread",
		      cmd->dev->handler->name);
		rc = SCST_EXEC_NEED_THREAD;
		goto out;
	}

	cmd->sent_to_midlev = 1;
	cmd->state = SCST_CMD_STATE_EXECUTING;
	cmd->scst_cmd_done = scst_cmd_done_local;

	set_bit(SCST_CMD_EXECUTING, &cmd->cmd_flags);
	smp_mb__after_set_bit();

	rc = scst_pre_exec(cmd);
	/* !! At this point cmd, sess & tgt_dev can be already freed !! */
	if (rc != SCST_EXEC_NOT_COMPLETED) {
		if (rc == SCST_EXEC_COMPLETED)
			goto out;
		else if (rc == SCST_EXEC_NEED_THREAD)
			goto out_clear;
		else
			goto out_rc_error;
	}

	rc = scst_local_exec(cmd);
	/* !! At this point cmd, sess & tgt_dev can be already freed !! */
	if (rc != SCST_EXEC_NOT_COMPLETED) {
		if (rc == SCST_EXEC_COMPLETED)
			goto out;
		else if (rc == SCST_EXEC_NEED_THREAD)
			goto out_clear;
		else
			goto out_rc_error;
	}

	if (cmd->dev->handler->exec) {
		struct scst_device *dev = cmd->dev;
		TRACE_DBG("Calling dev handler %s exec(%p)",
		      dev->handler->name, cmd);
		TRACE_BUFF_FLAG(TRACE_SEND_TOP, "Execing: ", cmd->cdb, cmd->cdb_len);
		cmd->scst_cmd_done = scst_cmd_done_local;
		rc = dev->handler->exec(cmd);
		/* !! At this point cmd, sess & tgt_dev can be already freed !! */
		TRACE_DBG("Dev handler %s exec() returned %d",
		      dev->handler->name, rc);
		if (rc == SCST_EXEC_COMPLETED)
			goto out;
		else if (rc == SCST_EXEC_NEED_THREAD)
			goto out_clear;
		else if (rc != SCST_EXEC_NOT_COMPLETED)
			goto out_rc_error;
	}

	TRACE_DBG("Sending cmd %p to SCSI mid-level", cmd);
	
	if (unlikely(cmd->dev->scsi_dev == NULL)) {
		PRINT_ERROR("Command for virtual device must be "
			"processed by device handler (lun %Ld)!",
			(uint64_t)cmd->lun);
		goto out_error;
	}

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)	
	if (unlikely(scst_alloc_request(cmd) != 0)) {
		if (scst_cmd_atomic(cmd)) {
			rc = SCST_EXEC_NEED_THREAD;
			goto out_clear;
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
	rc = scst_exec_req(cmd->dev->scsi_dev, cmd->cdb, cmd->cdb_len,
			cmd->data_direction, cmd->sg, cmd->bufflen, cmd->sg_cnt,
			cmd->timeout, cmd->retries, cmd, scst_cmd_done,
			scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
	if (unlikely(rc != 0)) {
		if (scst_cmd_atomic(cmd)) {
			rc = SCST_EXEC_NEED_THREAD;
			goto out_clear;
		} else {
			PRINT_INFO("scst_exec_req() failed: %d", rc);
			goto out_error;
		}
	}
#endif

	rc = SCST_EXEC_COMPLETED;

out:
	TRACE_EXIT();
	return rc;

out_clear:
	/* Restore the state */
	cmd->sent_to_midlev = 0;
	cmd->state = SCST_CMD_STATE_SEND_TO_MIDLEV;
	goto out;

out_rc_error:
	PRINT_ERROR("Dev handler %s exec() or scst_local_exec() returned "
		    "invalid code %d", cmd->dev->handler->name, rc);
	/* go through */

out_error:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)	
out_busy:
	scst_set_busy(cmd);
	cmd->completed = 1;
	/* go through */
#endif

out_done:
	rc = SCST_EXEC_COMPLETED;
	/* Report the result. The cmd is not completed */
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;
}

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
	if (tgt_dev->num_free_sn_slots != ARRAY_SIZE(tgt_dev->sn_slots)) {
		spin_lock_irq(&tgt_dev->sn_lock);
		if (tgt_dev->num_free_sn_slots != ARRAY_SIZE(tgt_dev->sn_slots)) {
			tgt_dev->num_free_sn_slots++;
			TRACE_SN("Incremented num_free_sn_slots (%d)",
				tgt_dev->num_free_sn_slots);
			if (tgt_dev->num_free_sn_slots == 0)
				tgt_dev->cur_sn_slot = slot;
		}
		spin_unlock_irq(&tgt_dev->sn_lock);
	}

inc:
	/*
	 * No locks is needed, because only one thread at time can 
	 * be here (serialized by sn). Also it is supposed that there
	 * could not be half-incremented halves.
	 */
	tgt_dev->expected_sn++;
	smp_mb(); /* write must be before def_cmd_count read */
	TRACE_SN("Next expected_sn: %ld", tgt_dev->expected_sn);

out:
	return;
}

static int scst_send_to_midlev(struct scst_cmd *cmd)
{
	int res, rc;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_device *dev = cmd->dev;
	typeof(tgt_dev->expected_sn) expected_sn;
	int count;

	TRACE_ENTRY();

	res = SCST_CMD_STATE_RES_CONT_NEXT;

	if (unlikely(scst_inc_on_dev_cmd(cmd) != 0))
		goto out;

	__scst_get(0); /* protect dev & tgt_dev */

	if (unlikely(cmd->internal || cmd->retry)) {
		rc = scst_do_send_to_midlev(cmd);
		/* !! At this point cmd, sess & tgt_dev can be already freed !! */
		if (rc == SCST_EXEC_NEED_THREAD) {
			TRACE_DBG("%s", "scst_do_send_to_midlev() requested "
			      "thread context, rescheduling");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			scst_dec_on_dev_cmd(cmd);
			goto out_put;
		} else {
			sBUG_ON(rc != SCST_EXEC_COMPLETED);
			goto out_unplug;
		}
	}

	if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
		goto exec;

	sBUG_ON(!cmd->sn_set);

	expected_sn = tgt_dev->expected_sn;
	/* Optimized for lockless fast path */
	if ((cmd->sn != expected_sn) || (tgt_dev->hq_cmd_count > 0)) {
		spin_lock_irq(&tgt_dev->sn_lock);
		tgt_dev->def_cmd_count++;
		smp_mb();
		barrier(); /* to reread expected_sn & hq_cmd_count */
		expected_sn = tgt_dev->expected_sn;
		if ((cmd->sn != expected_sn) || (tgt_dev->hq_cmd_count > 0)) {
			/* We are under IRQ lock, but dev->dev_lock is BH one */
			int cmd_blocking = scst_pre_dec_on_dev_cmd(cmd);
			if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
				/* Necessary to allow aborting out of sn cmds */
				TRACE_MGMT_DBG("Aborting out of sn cmd %p (tag %llu)",
					cmd, cmd->tag);
				tgt_dev->def_cmd_count--;
				cmd->state = SCST_CMD_STATE_DEV_DONE;
				res = SCST_CMD_STATE_RES_CONT_SAME;
			} else {
				TRACE_SN("Deferring cmd %p (sn=%ld, set %d, "
					"expected_sn=%ld)", cmd, cmd->sn,
					cmd->sn_set, expected_sn);
				list_add_tail(&cmd->sn_cmd_list_entry,
					      &tgt_dev->deferred_cmd_list);
			}
			spin_unlock_irq(&tgt_dev->sn_lock);
			/* !! At this point cmd can be already freed !! */
			__scst_dec_on_dev_cmd(dev, cmd_blocking);
			goto out_put;
		} else {
			TRACE_SN("Somebody incremented expected_sn %ld, "
				"continuing", expected_sn);
			tgt_dev->def_cmd_count--;
			spin_unlock_irq(&tgt_dev->sn_lock);
		}
	}

exec:
	count = 0;
	while(1) {
		atomic_t *slot = cmd->sn_slot;
		int inc_expected_sn = !cmd->inc_expected_sn_on_done &&
				      cmd->sn_set;
		rc = scst_do_send_to_midlev(cmd);
		if (rc == SCST_EXEC_NEED_THREAD) {
			TRACE_DBG("%s", "scst_do_send_to_midlev() requested "
			      "thread context, rescheduling");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			scst_dec_on_dev_cmd(cmd);
			if (count != 0)
				goto out_unplug;
			else
				goto out_put;
		}
		sBUG_ON(rc != SCST_EXEC_COMPLETED);
		/* !! At this point cmd can be already freed !! */
		count++;
		if (inc_expected_sn)
			scst_inc_expected_sn(tgt_dev, slot);
		cmd = scst_check_deferred_commands(tgt_dev);
		if (cmd == NULL)
			break;
		if (unlikely(scst_inc_on_dev_cmd(cmd) != 0))
			break;
	}

out_unplug:
	if (dev->scsi_dev != NULL)
		generic_unplug_device(dev->scsi_dev->request_queue);

out_put:
	__scst_put();
	/* !! At this point sess, dev and tgt_dev can be already freed !! */

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* No locks supposed to be held */
static int scst_check_sense(struct scst_cmd *cmd)
{
	int res = 0;
	int sense_valid;
	struct scst_device *dev = cmd->dev;
	int dbl_ua_possible, ua_sent = 0;

	TRACE_ENTRY();

	/* If we had a internal bus reset behind us, set the command error UA */
	if ((dev->scsi_dev != NULL) &&
	    unlikely(cmd->host_status == DID_RESET) &&
	    scst_is_ua_command(cmd))
	{
		TRACE(TRACE_MGMT, "DID_RESET: was_reset=%d host_status=%x",
		      dev->scsi_dev->was_reset, cmd->host_status);
		scst_set_cmd_error(cmd,
		   SCST_LOAD_SENSE(scst_sense_reset_UA));
		/* just in case */
		cmd->ua_ignore = 0;
		/* It looks like it is safe to clear was_reset here */
		dev->scsi_dev->was_reset = 0;
		smp_mb();
	}

	sense_valid = SCST_SENSE_VALID(cmd->sense_buffer);

	dbl_ua_possible = dev->dev_double_ua_possible;
	TRACE_DBG("cmd %p dbl_ua_possible %d", cmd, dbl_ua_possible);
	if (unlikely(dbl_ua_possible)) {
		spin_lock_bh(&dev->dev_lock);
		barrier(); /* to reread dev_double_ua_possible */
		dbl_ua_possible = dev->dev_double_ua_possible;
		if (dbl_ua_possible)
			ua_sent = dev->dev_reset_ua_sent;
		else
			spin_unlock_bh(&dev->dev_lock);
	}

	if (unlikely(sense_valid)) {
		TRACE_BUFF_FLAG(TRACE_SCSI, "Sense", cmd->sense_buffer,
			sizeof(cmd->sense_buffer));
		/* Check Unit Attention Sense Key */
		if (cmd->sense_buffer[2] == UNIT_ATTENTION) {
			if (cmd->sense_buffer[12] == SCST_SENSE_ASC_UA_RESET) {
				if (dbl_ua_possible) {
					if (ua_sent) {
						TRACE(TRACE_MGMT, "%s", 
							"Double UA detected");
						/* Do retry */
						TRACE(TRACE_MGMT, "Retrying cmd %p "
							"(tag %llu)", cmd, cmd->tag);
						cmd->status = 0;
						cmd->msg_status = 0;
						cmd->host_status = DID_OK;
						cmd->driver_status = 0;
						memset(cmd->sense_buffer, 0,
							sizeof(cmd->sense_buffer));
						cmd->retry = 1;
						cmd->state = SCST_CMD_STATE_SEND_TO_MIDLEV;
						res = 1;
						/* 
						 * Dev is still blocked by this cmd, so
						 * it's OK to clear SCST_DEV_SERIALIZED
						 * here.
						 */
						dev->dev_double_ua_possible = 0;
						dev->dev_serialized = 0;
						dev->dev_reset_ua_sent = 0;
						goto out_unlock;
					} else
						dev->dev_reset_ua_sent = 1;
				}
			}
			if (cmd->ua_ignore == 0) {
				if (unlikely(dbl_ua_possible)) {
					__scst_process_UA(dev, cmd,
						cmd->sense_buffer,
						sizeof(cmd->sense_buffer), 0);
				} else {
					scst_process_UA(dev, cmd,
						cmd->sense_buffer,
						sizeof(cmd->sense_buffer), 0);
				}
			}
		}
	}

	if (unlikely(dbl_ua_possible)) {
		if (ua_sent && scst_is_ua_command(cmd)) {
			TRACE_MGMT_DBG("%s", "Clearing dbl_ua_possible flag");
			dev->dev_double_ua_possible = 0;
			dev->dev_serialized = 0;
			dev->dev_reset_ua_sent = 0;
		}
		spin_unlock_bh(&dev->dev_lock);
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	spin_unlock_bh(&dev->dev_lock);
	goto out;
}

static int scst_check_auto_sense(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION) &&
	    (!SCST_SENSE_VALID(cmd->sense_buffer) ||
	     SCST_NO_SENSE(cmd->sense_buffer)))
	{
		TRACE(TRACE_SCSI|TRACE_MINOR, "CHECK_CONDITION, but no sense: "
		      "cmd->status=%x, cmd->msg_status=%x, "
		      "cmd->host_status=%x, cmd->driver_status=%x", cmd->status,
		      cmd->msg_status, cmd->host_status, cmd->driver_status);
		res = 1;
	} else if (unlikely(cmd->host_status)) {
		if ((cmd->host_status == DID_REQUEUE) ||
		    (cmd->host_status == DID_IMM_RETRY) ||
		    (cmd->host_status == DID_SOFT_ERROR)) {
			scst_set_busy(cmd);
		} else {
			TRACE(TRACE_SCSI|TRACE_MINOR, "Host status %x "
				"received, returning HARDWARE ERROR instead",
				cmd->host_status);
			scst_set_cmd_error(cmd,	SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_done_cmd_check(struct scst_cmd *cmd, int *pres)
{
	int res = 0, rc;
	unsigned char type;

	TRACE_ENTRY();

	if (unlikely(cmd->cdb[0] == REQUEST_SENSE)) {
		if (cmd->internal)
			cmd = scst_complete_request_sense(cmd);
	} else if (unlikely(scst_check_auto_sense(cmd))) {
		PRINT_INFO("Command finished with CHECK CONDITION, but "
			    "without sense data (opcode 0x%x), issuing "
			    "REQUEST SENSE", cmd->cdb[0]);
		rc = scst_prepare_request_sense(cmd);
		if (rc > 0) {
			*pres = rc;
			res = 1;
			goto out;
		} else {
			PRINT_ERROR("%s", "Unable to issue REQUEST SENSE, "
				    "returning HARDWARE ERROR");
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
	} else if (scst_check_sense(cmd)) {
		*pres = SCST_CMD_STATE_RES_CONT_SAME;
		res = 1;
		goto out;
	}

	type = cmd->dev->handler->type;
	if ((cmd->cdb[0] == MODE_SENSE || cmd->cdb[0] == MODE_SENSE_10) &&
	    cmd->tgt_dev->acg_dev->rd_only_flag &&
	    (type == TYPE_DISK || type == TYPE_WORM || type == TYPE_MOD ||
	     type == TYPE_TAPE))
	{
		int32_t length;
		uint8_t *address;

		length = scst_get_buf_first(cmd, &address);
		if (length <= 0)
			goto out;
		if (length > 2 && cmd->cdb[0] == MODE_SENSE)
			address[2] |= 0x80;   /* Write Protect*/
		else if (length > 3 && cmd->cdb[0] == MODE_SENSE_10)
			address[3] |= 0x80;   /* Write Protect*/
		scst_put_buf(cmd, address);
	}

	/* 
	 * Check and clear NormACA option for the device, if necessary,
	 * since we don't support ACA
	 */
	if ((cmd->cdb[0] == INQUIRY) &&
	    !(cmd->cdb[1] & SCST_INQ_EVPD/* Std INQUIRY data (no EVPD) */) &&
	    (cmd->resp_data_len > SCST_INQ_BYTE3))
	{
		uint8_t *buffer;
		int buflen;

		/* ToDo: all pages ?? */
		buflen = scst_get_buf_first(cmd, &buffer);
		if (buflen > 0) {
			if (buflen > SCST_INQ_BYTE3) {
#ifdef EXTRACHECKS
				if (buffer[SCST_INQ_BYTE3] & SCST_INQ_NORMACA_BIT) {
					PRINT_INFO("NormACA set for device: "
					    "lun=%Ld, type 0x%02x", 
					    (uint64_t)cmd->lun, buffer[0]);
				}
#endif
				buffer[SCST_INQ_BYTE3] &= ~SCST_INQ_NORMACA_BIT;
			} else
				scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));

			scst_put_buf(cmd, buffer);
		}
	}

	if (unlikely((cmd->cdb[0] == RESERVE) || (cmd->cdb[0] == RESERVE_10))) {
		if ((cmd->status != 0) && !test_bit(SCST_TGT_DEV_RESERVED,
					    	&cmd->tgt_dev->tgt_dev_flags)) {
			struct scst_tgt_dev *tgt_dev_tmp;
			TRACE(TRACE_SCSI, "Real RESERVE failed lun=%Ld, status=%x",
			      (uint64_t)cmd->lun, cmd->status);
			TRACE_BUFF_FLAG(TRACE_SCSI, "Sense", cmd->sense_buffer,
				     sizeof(cmd->sense_buffer));
			/* Clearing the reservation */
			list_for_each_entry(tgt_dev_tmp, &cmd->dev->dev_tgt_dev_list,
					    dev_tgt_dev_list_entry) {
				clear_bit(SCST_TGT_DEV_RESERVED, 
					&tgt_dev_tmp->tgt_dev_flags);
			}
			cmd->dev->dev_reserved = 0;
		}
	}
	
	if (unlikely((cmd->cdb[0] == MODE_SELECT) || 
		     (cmd->cdb[0] == MODE_SELECT_10) ||
		     (cmd->cdb[0] == LOG_SELECT)))
	{
		if (cmd->status == 0) {
			TRACE(TRACE_SCSI, "MODE/LOG SELECT succeeded, "
				"setting the SELECT UA (lun=%Ld)", 
				(uint64_t)cmd->lun);
			spin_lock_bh(&scst_temp_UA_lock);
			if (cmd->cdb[0] == LOG_SELECT) {
				scst_set_sense(scst_temp_UA,
					sizeof(scst_temp_UA),
					UNIT_ATTENTION, 0x2a, 0x02);
			} else {
				scst_set_sense(scst_temp_UA,
					sizeof(scst_temp_UA),
					UNIT_ATTENTION, 0x2a, 0x01);
			}
			scst_process_UA(cmd->dev, cmd, scst_temp_UA,
				sizeof(scst_temp_UA), 1);
			spin_unlock_bh(&scst_temp_UA_lock);
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_dev_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME, rc;
	int state;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	if (atomic && !cmd->dev->handler->dev_done_atomic) 
	{
		TRACE_DBG("Dev handler %s dev_done() can not be "
		      "called in atomic context, rescheduling to the thread",
		      cmd->dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	rc = scst_done_cmd_check(cmd, &res);

	if (cmd->needs_unblocking)
		scst_unblock_dev_cmd(cmd);

	if (unlikely(cmd->dec_on_dev_needed))
		scst_dec_on_dev_cmd(cmd);

	if (rc)
		goto out;

	state = SCST_CMD_STATE_XMIT_RESP;
	if (likely(!scst_is_cmd_local(cmd)) && 
	    likely(cmd->dev->handler->dev_done != NULL))
	{
		int rc;
		TRACE_DBG("Calling dev handler %s dev_done(%p)",
		      cmd->dev->handler->name, cmd);
		rc = cmd->dev->handler->dev_done(cmd);
		TRACE_DBG("Dev handler %s dev_done() returned %d",
		      cmd->dev->handler->name, rc);
		if (rc != SCST_CMD_STATE_DEFAULT)
			state = rc;
	}

	switch (state) {
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_DEV_PARSE:
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_PRE_EXEC:
	case SCST_CMD_STATE_SEND_TO_MIDLEV:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_FINISHED:
		cmd->state = state;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		break;

	case SCST_CMD_STATE_NEED_THREAD_CTX:
		TRACE_DBG("Dev handler %s dev_done() requested "
		      "thread context, rescheduling",
		      cmd->dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		break;

	default:
		if (state >= 0) {
			PRINT_ERROR("Dev handler %s dev_done() returned "
				"invalid cmd state %d", 
				cmd->dev->handler->name, state);
		} else {
			PRINT_ERROR("Dev handler %s dev_done() returned "
				"error %d", cmd->dev->handler->name, 
				state);
		}
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_hardw_error));
		cmd->state = SCST_CMD_STATE_XMIT_RESP;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		break;
	}

out:
	TRACE_EXIT_HRES(res);
	return res;
}

static int scst_xmit_response(struct scst_cmd *cmd)
{
	int res, rc;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	/*
	 * Check here also in order to avoid unnecessary delays of other
	 * commands.
	 */
	if (cmd->tgt_dev != NULL) {
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE)) {
			struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

			spin_lock_irq(&tgt_dev->sn_lock);
			tgt_dev->hq_cmd_count--;
			spin_unlock_irq(&tgt_dev->sn_lock);

			EXTRACHECKS_BUG_ON(tgt_dev->hq_cmd_count < 0);

			/*
			 * There is no problem in checking hq_cmd_count in the
			 * non-locked state. In the worst case we will only have
			 * unneeded run of the deferred commands.
			 */
			if (tgt_dev->hq_cmd_count == 0) {
				struct scst_cmd *c =
					scst_check_deferred_commands(tgt_dev);
				if (c != NULL) {
					spin_lock_irq(&c->cmd_lists->cmd_list_lock);
					TRACE_SN("Adding cmd %p to active cmd list", c);
					list_add_tail(&c->cmd_list_entry,
						&c->cmd_lists->active_cmd_list);
					wake_up(&c->cmd_lists->cmd_list_waitQ);
					spin_unlock_irq(&c->cmd_lists->cmd_list_lock);
				}
			}
		}

		if (unlikely(!cmd->sent_to_midlev)) {
			TRACE_SN("cmd %p was not sent to mid-lev (sn %ld, set %d)",
				cmd, cmd->sn, cmd->sn_set);
			scst_unblock_deferred(cmd->tgt_dev, cmd);
			cmd->sent_to_midlev = 1;
		}
	}

	if (atomic && !cmd->tgtt->xmit_response_atomic) {
		TRACE_DBG("%s", "xmit_response() can not be "
		      "called in atomic context, rescheduling to the thread");
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	/*
	 * If we don't remove cmd from the search list here, before
	 * submitting it for transmittion, we will have a race, when for
	 * some reason cmd's release is delayed after transmittion and
	 * initiator sends cmd with the same tag => it is possible that
	 * a wrong cmd will be found by find() functions.
	 */
	spin_lock_irq(&cmd->sess->sess_list_lock);
	list_del(&cmd->search_cmd_list_entry);
	spin_unlock_irq(&cmd->sess->sess_list_lock);

	set_bit(SCST_CMD_XMITTING, &cmd->cmd_flags);
	smp_mb__after_set_bit();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		if (test_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags)) {
			if (cmd->completed) {
				/* It's completed and it's OK to return its result */
				clear_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
				clear_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
			} else {
				TRACE_MGMT_DBG("Flag ABORTED OTHER set for cmd "
					"%p (tag %llu), returning TASK ABORTED",
					cmd, cmd->tag);
				scst_set_cmd_error_status(cmd, SAM_STAT_TASK_ABORTED);
			}
		}
	}

	if (unlikely(test_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Flag NO_RESP set for cmd %p (tag %llu), skipping",
			cmd, cmd->tag);
		cmd->state = SCST_CMD_STATE_FINISHED;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		goto out;
	}

#ifdef DEBUG_TM
	if (cmd->tm_dbg_delayed && !test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
		if (atomic && !cmd->tgtt->xmit_response_atomic) {
			TRACE_MGMT_DBG("%s", "DEBUG_TM delayed cmd needs a thread");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}
		TRACE_MGMT_DBG("Delaying cmd %p (tag %llu) for 1 second",
			cmd, cmd->tag);
		schedule_timeout_uninterruptible(HZ);
	}
#endif

	while (1) {
		int finished_cmds = atomic_read(&cmd->sess->tgt->finished_cmds);

		res = SCST_CMD_STATE_RES_CONT_NEXT;
		cmd->state = SCST_CMD_STATE_XMIT_WAIT;

		TRACE_DBG("Calling xmit_response(%p)", cmd);

#if defined(DEBUG) || defined(TRACING)
		if (cmd->sg) {
			int i;
			struct scatterlist *sg = cmd->sg;
			TRACE(TRACE_SEND_BOT,
			      "Xmitting %d S/G(s) at %p sg[0].page at %p",
			      cmd->sg_cnt, sg, (void*)sg[0].page);
			for(i = 0; i < cmd->sg_cnt; ++i) {
				TRACE_BUFF_FLAG(TRACE_SEND_BOT,
				    "Xmitting sg", page_address(sg[i].page),
				    sg[i].length);
			}
		}
#endif

#ifdef DEBUG_RETRY
		if (((scst_random() % 100) == 77))
			rc = SCST_TGT_RES_QUEUE_FULL;
		else
#endif
			rc = cmd->tgtt->xmit_response(cmd);
		TRACE_DBG("xmit_response() returned %d", rc);

		if (likely(rc == SCST_TGT_RES_SUCCESS))
			goto out;

		/* Restore the previous state */
		cmd->state = SCST_CMD_STATE_XMIT_RESP;

		switch (rc) {
		case SCST_TGT_RES_QUEUE_FULL:
		{
			if (scst_queue_retry_cmd(cmd, finished_cmds) == 0)
				break;
			else
				continue;
		}

		case SCST_TGT_RES_NEED_THREAD_CTX:
		{
			TRACE_DBG("Target driver %s xmit_response() "
			      "requested thread context, rescheduling",
			      cmd->tgtt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			break;
		}

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
			"fatal error", cmd->tgtt->name);
	} else {
		PRINT_ERROR("Target driver %s xmit_response() returned "
			"invalid value %d", cmd->tgtt->name, rc);
	}
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	cmd->state = SCST_CMD_STATE_FINISHED;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

void scst_tgt_cmd_done(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	sBUG_ON(cmd->state != SCST_CMD_STATE_XMIT_WAIT);

	cmd->state = SCST_CMD_STATE_FINISHED;
	scst_proccess_redirect_cmd(cmd, scst_get_context(), 1);

	TRACE_EXIT();
	return;
}

static int scst_finish_cmd(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	atomic_dec(&cmd->sess->sess_cmd_count);

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Aborted cmd %p finished (cmd_ref %d, "
			"scst_cmd_count %d)", cmd, atomic_read(&cmd->cmd_ref),
			atomic_read(&scst_cmd_count));
	}

	scst_cmd_put(cmd);

	res = SCST_CMD_STATE_RES_CONT_NEXT;

	TRACE_EXIT_HRES(res);
	return res;
}

/*
 * No locks, but it must be externally serialized (see comment for
 * scst_cmd_init_done() in scsi_tgt.h)
 */
static void scst_cmd_set_sn(struct scst_cmd *cmd)
{
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	unsigned long flags;

	if (scst_is_implicit_hq(cmd)) {
		TRACE(TRACE_SCSI|TRACE_SCSI_SERIALIZING, "Implicit HQ cmd %p", cmd);
		cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	}

	/* Optimized for lockless fast path */

	scst_check_debug_sn(cmd);

	switch(cmd->queue_type) {
	case SCST_CMD_QUEUE_SIMPLE:
	case SCST_CMD_QUEUE_UNTAGGED:
		if (likely(tgt_dev->num_free_sn_slots >= 0)) {
			if (atomic_inc_return(tgt_dev->cur_sn_slot) == 1) {
				tgt_dev->curr_sn++;
				TRACE_SN("Incremented curr_sn %ld",
					tgt_dev->curr_sn);
			}
			cmd->sn_slot = tgt_dev->cur_sn_slot;
			cmd->sn = tgt_dev->curr_sn;
			
			tgt_dev->prev_cmd_ordered = 0;
		} else {
			TRACE(TRACE_MINOR, "%s", "Not enough SN slots");
			goto ordered;
		}
		break;

	case SCST_CMD_QUEUE_ORDERED:
		TRACE(TRACE_SCSI|TRACE_SCSI_SERIALIZING, "ORDERED cmd %p "
			"(op %x)", cmd, cmd->cdb[0]);
ordered:
		if (!tgt_dev->prev_cmd_ordered) {
			spin_lock_irqsave(&tgt_dev->sn_lock, flags);
			tgt_dev->num_free_sn_slots--;
			smp_mb();
			if ((tgt_dev->num_free_sn_slots >= 0) &&
			    (atomic_read(tgt_dev->cur_sn_slot) > 0)) {
			    	do {
					tgt_dev->cur_sn_slot++;
					if (tgt_dev->cur_sn_slot == 
						tgt_dev->sn_slots +
						ARRAY_SIZE(tgt_dev->sn_slots))
					    tgt_dev->cur_sn_slot = tgt_dev->sn_slots;
				} while(atomic_read(tgt_dev->cur_sn_slot) != 0);
				TRACE_SN("New cur SN slot %zd",
					tgt_dev->cur_sn_slot-tgt_dev->sn_slots);
			} else
				tgt_dev->num_free_sn_slots++;
			spin_unlock_irqrestore(&tgt_dev->sn_lock, flags);
		}
		tgt_dev->prev_cmd_ordered = 1;
		tgt_dev->curr_sn++;
		cmd->sn = tgt_dev->curr_sn;
		break;

	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		TRACE(TRACE_SCSI|TRACE_SCSI_SERIALIZING, "HQ cmd %p "
			"(op %x)", cmd, cmd->cdb[0]);
		spin_lock_irqsave(&tgt_dev->sn_lock, flags);
		tgt_dev->hq_cmd_count++;
		spin_unlock_irqrestore(&tgt_dev->sn_lock, flags);
		goto out;

	default:
		PRINT_ERROR("Unsupported queue type %d, treating it as "
			"ORDERED", cmd->queue_type);
		cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
		goto ordered;
	}

	TRACE_SN("cmd(%p)->sn: %ld (tgt_dev %p, *cur_sn_slot %d, "
		"num_free_sn_slots %d, prev_cmd_ordered %ld, "
		"cur_sn_slot %zd)", cmd, cmd->sn, tgt_dev,
		atomic_read(tgt_dev->cur_sn_slot), 
		tgt_dev->num_free_sn_slots, tgt_dev->prev_cmd_ordered,
		tgt_dev->cur_sn_slot-tgt_dev->sn_slots);

	cmd->sn_set = 1;
out:
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

	__scst_get(1);

	if (likely(!test_bit(SCST_FLAG_SUSPENDED, &scst_flags))) {
		struct list_head *sess_tgt_dev_list_head =
			&cmd->sess->sess_tgt_dev_list_hash[HASH_VAL(cmd->lun)];
		TRACE_DBG("Finding tgt_dev for cmd %p (lun %Ld)", cmd,
			(uint64_t)cmd->lun);
		res = -1;
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			if (tgt_dev->lun == cmd->lun) {
				TRACE_DBG("tgt_dev %p found", tgt_dev);

				if (unlikely(tgt_dev->dev->handler == &scst_null_devtype)) {
					PRINT_INFO("Dev handler for device "
					  "%Ld is NULL, the device will not be "
					  "visible remotely", (uint64_t)cmd->lun);
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
			TRACE(TRACE_MINOR, "tgt_dev for lun %Ld not found, command to "
				"unexisting LU?", (uint64_t)cmd->lun);
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
		cmd->state = SCST_CMD_STATE_DEV_PARSE;
		cnt = atomic_inc_return(&cmd->tgt_dev->tgt_dev_cmd_count);
		if (unlikely(cnt > SCST_MAX_TGT_DEV_COMMANDS)) {
			TRACE(TRACE_RETRY, "Too many pending commands (%d) in "
				"session, returning BUSY to initiator \"%s\"",
				cnt, (cmd->sess->initiator_name[0] == '\0') ?
				  "Anonymous" : cmd->sess->initiator_name);
			goto out_busy;
		}
		cnt = atomic_inc_return(&cmd->dev->dev_cmd_count);
		if (unlikely(cnt > SCST_MAX_DEV_COMMANDS)) {
			TRACE(TRACE_RETRY, "Too many pending device commands "
				"(%d), returning BUSY to initiator \"%s\"",
				cnt, (cmd->sess->initiator_name[0] == '\0') ?
				  "Anonymous" : cmd->sess->initiator_name);
			goto out_busy;
		}
		if (!cmd->set_sn_on_restart_cmd)
			scst_cmd_set_sn(cmd);
	} else if (res < 0) {
		TRACE_DBG("Finishing cmd %p", cmd);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		cmd->state = SCST_CMD_STATE_XMIT_RESP;
	} else
		goto out;

out:
	TRACE_EXIT_RES(res);
	return res;

out_busy:
	scst_set_busy(cmd);
	cmd->state = SCST_CMD_STATE_XMIT_RESP;
	goto out;
}

/* Called under scst_init_lock and IRQs disabled */
static void scst_do_job_init(void)
{
	struct scst_cmd *cmd;
	int susp;

	TRACE_ENTRY();

restart:
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
				TRACE_MGMT_DBG("%s", "FLAG SUSPENDED set, restarting");
				goto restart;
			}
		} else {
			TRACE_MGMT_DBG("Aborting not inited cmd %p (tag %llu)",
				cmd, cmd->tag);
			cmd->state = SCST_CMD_STATE_XMIT_RESP;
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
		 * same tgt_dev, but init_cmd_done() doesn't guarantee the order
		 * in case of simultaneous such calls anyway.
		 */
		TRACE_MGMT_DBG("Deleting cmd %p from init cmd list", cmd);
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

int scst_init_cmd_thread(void *arg)
{
	TRACE_ENTRY();

	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&scst_init_lock);
	while(!kthread_should_stop()) {
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

	TRACE_EXIT();
	return 0;
}

/* Called with no locks held */
void scst_process_active_cmd(struct scst_cmd *cmd, int context)
{
	int res;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(in_irq());

	cmd->atomic = (context == SCST_CONTEXT_DIRECT_ATOMIC);

	do {
		switch (cmd->state) {
		case SCST_CMD_STATE_DEV_PARSE:
			res = scst_parse_cmd(cmd);
			if ((res != SCST_CMD_STATE_RES_CONT_SAME) ||
			    (cmd->state != SCST_CMD_STATE_PREPARE_SPACE))
				break;
			/* else go through */

		case SCST_CMD_STATE_PREPARE_SPACE:
			res = scst_prepare_space(cmd);
			break;

		case SCST_CMD_STATE_RDY_TO_XFER:
			res = scst_rdy_to_xfer(cmd);
			break;

		case SCST_CMD_STATE_PRE_EXEC:
			res = scst_tgt_pre_exec(cmd);
			if ((res != SCST_CMD_STATE_RES_CONT_SAME) ||
			    (cmd->state != SCST_CMD_STATE_SEND_TO_MIDLEV))
				break;
			/* else go through */

		case SCST_CMD_STATE_SEND_TO_MIDLEV:
			if (tm_dbg_check_cmd(cmd) != 0) {
				res = SCST_CMD_STATE_RES_CONT_NEXT;
				TRACE_MGMT_DBG("Skipping cmd %p (tag %llu), "
					"because of TM DBG delay", cmd,
					cmd->tag);
				break;
			}
			res = scst_send_to_midlev(cmd);
			/* !! At this point cmd, sess & tgt_dev can be already freed !! */
			break;

		case SCST_CMD_STATE_DEV_DONE:
			res = scst_dev_done(cmd);
			if ((res != SCST_CMD_STATE_RES_CONT_SAME) ||
			    (cmd->state != SCST_CMD_STATE_XMIT_RESP))
				break;
			/* else go through */
			break;

		case SCST_CMD_STATE_XMIT_RESP:
			res = scst_xmit_response(cmd);
			break;

		case SCST_CMD_STATE_FINISHED:
			res = scst_finish_cmd(cmd);
			break;

		default:
			PRINT_ERROR("cmd (%p) in state %d, but shouldn't be",
			       cmd, cmd->state);
			sBUG();
			res = SCST_CMD_STATE_RES_CONT_NEXT;
			break;
		}
	} while(res == SCST_CMD_STATE_RES_CONT_SAME);

	if (res == SCST_CMD_STATE_RES_CONT_NEXT) {
		/* None */
	} else if (res == SCST_CMD_STATE_RES_NEED_THREAD) {
		spin_lock_irq(&cmd->cmd_lists->cmd_list_lock);
		switch (cmd->state) {
		case SCST_CMD_STATE_DEV_PARSE:
		case SCST_CMD_STATE_PREPARE_SPACE:
		case SCST_CMD_STATE_RDY_TO_XFER:
		case SCST_CMD_STATE_PRE_EXEC:
		case SCST_CMD_STATE_SEND_TO_MIDLEV:
		case SCST_CMD_STATE_DEV_DONE:
		case SCST_CMD_STATE_XMIT_RESP:
		case SCST_CMD_STATE_FINISHED:
			TRACE_DBG("Adding cmd %p to head of active cmd list", cmd);
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
			break;
#ifdef EXTRACHECKS
		/* not very valid commands */
		case SCST_CMD_STATE_DEFAULT:
		case SCST_CMD_STATE_NEED_THREAD_CTX:
			PRINT_ERROR("cmd %p is in state %d, not putting on "
				"useful list (left on scst cmd list)", cmd, 
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

/* Called under cmd_list_lock and IRQs disabled */
static void scst_do_job_active(struct list_head *cmd_list,
	spinlock_t *cmd_list_lock, int context)
{
	TRACE_ENTRY();

#ifdef EXTRACHECKS
	WARN_ON((context != SCST_CONTEXT_DIRECT_ATOMIC) && 
		(context != SCST_CONTEXT_DIRECT));
#endif

	while (!list_empty(cmd_list)) {
		struct scst_cmd *cmd = list_entry(cmd_list->next, typeof(*cmd),
					cmd_list_entry);
		TRACE_DBG("Deleting cmd %p from active cmd list", cmd);
		list_del(&cmd->cmd_list_entry);
		spin_unlock_irq(cmd_list_lock);
		scst_process_active_cmd(cmd, context);
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
	struct scst_cmd_lists *p_cmd_lists = (struct scst_cmd_lists*)arg;

	TRACE_ENTRY();

#if 0
	set_user_nice(current, 10);
#endif
	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&p_cmd_lists->cmd_list_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_cmd_lists(p_cmd_lists)) {
			add_wait_queue_exclusive(&p_cmd_lists->cmd_list_waitQ,
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
			&p_cmd_lists->cmd_list_lock, SCST_CONTEXT_DIRECT);
	}
	spin_unlock_irq(&p_cmd_lists->cmd_list_lock);

#ifdef EXTRACHECKS
	/*
	 * If kthread_should_stop() is true, we are guaranteed to be either
	 * on the module unload, or there must be at least one other thread to
	 * process the commands lists.
	 */
	if (p_cmd_lists == &scst_main_cmd_lists) {
		sBUG_ON((scst_threads_info.nr_cmd_threads == 1) &&
			 !list_empty(&scst_main_cmd_lists.active_cmd_list));
	}
#endif

	TRACE_EXIT();
	return 0;
}

void scst_cmd_tasklet(long p)
{
	struct scst_tasklet *t = (struct scst_tasklet*)p;

	TRACE_ENTRY();

	spin_lock_irq(&t->tasklet_lock);
	scst_do_job_active(&t->tasklet_cmd_list, &t->tasklet_lock,
		SCST_CONTEXT_DIRECT_ATOMIC);
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

	TRACE_DBG("Finding tgt_dev for mgmt cmd %p (lun %Ld)", mcmd,
	      (uint64_t)mcmd->lun);

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
void scst_complete_cmd_mgmt(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd)
{
	TRACE_ENTRY();

	spin_lock_irq(&scst_mcmd_lock);

	TRACE_MGMT_DBG("cmd %p completed (tag %llu, mcmd %p, "
		"mcmd->cmd_wait_count %d)", cmd, cmd->tag, mcmd,
		mcmd->cmd_wait_count);

	cmd->mgmt_cmnd = NULL;

	if (cmd->completed)
		mcmd->completed_cmd_count++;

	mcmd->cmd_wait_count--;
	if (mcmd->cmd_wait_count > 0) {
		TRACE_MGMT_DBG("cmd_wait_count(%d) not 0, skipping",
			mcmd->cmd_wait_count);
		goto out_unlock;
	}

	mcmd->state = SCST_MGMT_CMD_STATE_DONE;

	if (mcmd->completed) {
		TRACE_MGMT_DBG("Adding mgmt cmd %p to active mgmt cmd list",
			mcmd);
		list_add_tail(&mcmd->mgmt_cmd_list_entry,
			&scst_active_mgmt_cmd_list);
	}

	spin_unlock_irq(&scst_mcmd_lock);

	wake_up(&scst_mgmt_cmd_list_waitQ);

out:
	TRACE_EXIT();
	return;

out_unlock:
	spin_unlock_irq(&scst_mcmd_lock);
	goto out;
}

static int scst_call_dev_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev, int set_status)
{
	int res = SCST_DEV_TM_NOT_COMPLETED;
	struct scst_dev_type *h = tgt_dev->dev->handler;

	if (h->task_mgmt_fn) {
		TRACE_MGMT_DBG("Calling dev handler %s task_mgmt_fn(fn=%d)",
			h->name, mcmd->fn);
		EXTRACHECKS_BUG_ON(in_irq());
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
	switch(mgmt_fn) {
		case SCST_ABORT_TASK:
		case SCST_ABORT_TASK_SET:
		case SCST_CLEAR_TASK_SET:
			return 1;
		default:
			return 0;
	}
}

/* 
 * Might be called under sess_list_lock and IRQ off + BHs also off
 * Returns -1 if command is being executed (ABORT failed), 0 otherwise
 */
void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	int other_ini, int call_dev_task_mgmt_fn)
{
	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Aborting cmd %p (tag %llu)", cmd, cmd->tag);

	if (other_ini) {
		set_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
		smp_mb__after_set_bit();
	}
	set_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
	smp_mb__after_set_bit();

	if (cmd->tgt_dev == NULL) {
		unsigned long flags;
		spin_lock_irqsave(&scst_init_lock, flags);
		scst_init_poll_cnt++;
		spin_unlock_irqrestore(&scst_init_lock, flags);
		wake_up(&scst_init_cmd_list_waitQ);
	}

	if (call_dev_task_mgmt_fn && (cmd->tgt_dev != NULL)) {
		EXTRACHECKS_BUG_ON(irqs_disabled());
		scst_call_dev_task_mgmt_fn(mcmd, cmd->tgt_dev, 1);
	}

	if (mcmd) {
		unsigned long flags;
		/*
		 * Delay the response until the command's finish in
		 * order to guarantee that "no further responses from
		 * the task are sent to the SCSI initiator port" after
		 * response from the TM function is sent (SAM). Plus,
		 * we must wait here to be sure that we won't receive
		 * double commands with the same tag.
		 */
		TRACE(TRACE_MGMT, "cmd %p (tag %llu) being executed/"
			"xmitted (state %d), deferring ABORT...", cmd,
			cmd->tag, cmd->state);
#ifdef EXTRACHECKS
		if (cmd->mgmt_cmnd) {
			printk(KERN_ALERT "cmd %p (tag %llu, state %d) "
				"has non-NULL mgmt_cmnd %p!!! Current "
				"mcmd %p\n", cmd, cmd->tag, cmd->state,
				cmd->mgmt_cmnd, mcmd);
		}
#endif
		sBUG_ON(cmd->mgmt_cmnd);
		spin_lock_irqsave(&scst_mcmd_lock, flags);
		mcmd->cmd_wait_count++;
		spin_unlock_irqrestore(&scst_mcmd_lock, flags);
		/* cmd can't die here or sess_list_lock already taken */
		cmd->mgmt_cmnd = mcmd;
	}

	tm_dbg_release_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* No locks */
static int scst_set_mcmd_next_state(struct scst_mgmt_cmd *mcmd)
{
	int res;
	spin_lock_irq(&scst_mcmd_lock);
	if (mcmd->cmd_wait_count != 0) {
		TRACE_MGMT_DBG("cmd_wait_count(%d) not 0, preparing to "
			"wait", mcmd->cmd_wait_count);
		mcmd->state = SCST_MGMT_CMD_STATE_EXECUTING;
		res = -1;
	} else {
		mcmd->state = SCST_MGMT_CMD_STATE_DONE;
		res = 0;
	}
	mcmd->completed = 1;
	spin_unlock_irq(&scst_mcmd_lock);
	return res;
}

static int __scst_check_unblock_aborted_cmd(struct scst_cmd *cmd)
{
	int res;
	if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
		TRACE_MGMT_DBG("Adding aborted blocked cmd %p to active cmd "
			"list", cmd);
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
			if (__scst_check_unblock_aborted_cmd(cmd))
				list_del(&cmd->blocked_cmd_list_entry);
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
				if (__scst_check_unblock_aborted_cmd(cmd)) {
					TRACE_MGMT_DBG("Deleting aborted SN "
						"cmd %p from SN list", cmd);
					tgt_dev->def_cmd_count--;
					list_del(&cmd->sn_cmd_list_entry);
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

/* Returns 0 if the command processing should be continued, <0 otherwise */
static void __scst_abort_task_set(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev, int other_ini, int scst_mutex_held)
{
	struct scst_cmd *cmd;
	struct scst_session *sess = tgt_dev->sess;

	TRACE_ENTRY();

	spin_lock_irq(&sess->sess_list_lock);

	TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
 	list_for_each_entry(cmd, &sess->search_cmd_list, 
 			search_cmd_list_entry) {
 		if ((cmd->tgt_dev == tgt_dev) ||
 		    ((cmd->tgt_dev == NULL) && 
		     (cmd->lun == tgt_dev->lun))) {
			if (mcmd->cmd_sn_set) {
				sBUG_ON(!cmd->tgt_sn_set);
				if (scst_sn_before(mcmd->cmd_sn, cmd->tgt_sn) ||
				    (mcmd->cmd_sn == cmd->tgt_sn))
					continue;
			}
			scst_abort_cmd(cmd, mcmd, other_ini, 0);
		}
	}
	spin_unlock_irq(&sess->sess_list_lock);

	scst_unblock_aborted_cmds(scst_mutex_held);

	TRACE_EXIT();
	return;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_task_set(struct scst_mgmt_cmd *mcmd)
{
	int res;
	struct scst_tgt_dev *tgt_dev = mcmd->mcmd_tgt_dev;
	struct scst_device *dev = tgt_dev->dev;

	TRACE(TRACE_MGMT, "Aborting task set (lun=%Ld, mcmd=%p)",
		tgt_dev->lun, mcmd);

	mcmd->needs_unblocking = 1;

	spin_lock_bh(&dev->dev_lock);
	__scst_block_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	__scst_abort_task_set(mcmd, tgt_dev, 0, 0);
	scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_check_delay_mgmt_cmd(struct scst_mgmt_cmd *mcmd)
{
	if (test_bit(SCST_FLAG_TM_ACTIVE, &scst_flags) && !mcmd->active) {
		TRACE_MGMT_DBG("Adding mgmt cmd %p to delayed mgmt cmd list",
			mcmd);
		spin_lock_irq(&scst_mcmd_lock);
		list_add_tail(&mcmd->mgmt_cmd_list_entry, 
			&scst_delayed_mgmt_cmd_list);
		spin_unlock_irq(&scst_mcmd_lock);
		return -1;
	} else {
		mcmd->active = 1;
		set_bit(SCST_FLAG_TM_ACTIVE, &scst_flags);
		return 0;
	}
}

/* Returns 0 if the command processing should be continued, 
 * >0, if it should be requeued, <0 otherwise */
static int scst_mgmt_cmd_init(struct scst_mgmt_cmd *mcmd)
{
	int res = 0, rc;

	TRACE_ENTRY();

	res = scst_check_delay_mgmt_cmd(mcmd);
	if (res != 0)
		goto out;

	mcmd->state = SCST_MGMT_CMD_STATE_READY;

	switch (mcmd->fn) {
	case SCST_ABORT_TASK:
	{
		struct scst_session *sess = mcmd->sess;
		struct scst_cmd *cmd;

		spin_lock_irq(&sess->sess_list_lock);
		cmd = __scst_find_cmd_by_tag(sess, mcmd->tag);
		if (cmd == NULL) {
			TRACE(TRACE_MGMT, "ABORT TASK failed: command for "
				"tag %llu not found", mcmd->tag);
			mcmd->status = SCST_MGMT_STATUS_TASK_NOT_EXIST;
			mcmd->state = SCST_MGMT_CMD_STATE_DONE;
			spin_unlock_irq(&sess->sess_list_lock);
			goto out;
		}
		scst_cmd_get(cmd);
		spin_unlock_irq(&sess->sess_list_lock);
		TRACE(TRACE_MGMT, "Cmd %p for tag %llu (sn %ld, set %d, "
			"queue_type %x) found, aborting it", cmd, mcmd->tag,
			cmd->sn, cmd->sn_set, cmd->queue_type);
		mcmd->cmd_to_abort = cmd;
		if (mcmd->lun_set && (mcmd->lun != cmd->lun)) {
			PRINT_ERROR("ABORT TASK: LUN mismatch: mcmd LUN %Lx, "
				"cmd LUN %Lx, cmd tag %Lu", mcmd->lun, cmd->lun,
				mcmd->tag);
			mcmd->status = SCST_MGMT_STATUS_REJECTED;
		} else if (mcmd->cmd_sn_set && 
		           (scst_sn_before(mcmd->cmd_sn, cmd->tgt_sn) ||
			    (mcmd->cmd_sn == cmd->tgt_sn))) {
			PRINT_ERROR("ABORT TASK: SN mismatch: mcmd SN %x, "
				"cmd SN %x, cmd tag %Lu", mcmd->cmd_sn,
				cmd->tgt_sn, mcmd->tag);
			mcmd->status = SCST_MGMT_STATUS_REJECTED;
		} else {
			scst_abort_cmd(cmd, mcmd, 0, 1);
			scst_unblock_aborted_cmds(0);
		}
		res = scst_set_mcmd_next_state(mcmd);
		mcmd->cmd_to_abort = NULL; /* just in case */
		scst_cmd_put(cmd);
		break;
	}

	case SCST_TARGET_RESET:
	case SCST_ABORT_ALL_TASKS:
	case SCST_NEXUS_LOSS:
		break;

	default:
		rc = scst_mgmt_translate_lun(mcmd);
		if (rc < 0) {
			PRINT_ERROR("Corresponding device for lun %Ld not "
				"found", (uint64_t)mcmd->lun);
			mcmd->status = SCST_MGMT_STATUS_LUN_NOT_EXIST;
			mcmd->state = SCST_MGMT_CMD_STATE_DONE;
		} else if (rc != 0)
			res = rc;
		break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_target_reset(struct scst_mgmt_cmd *mcmd)
{
	int res, rc;
	struct scst_device *dev, *d;
	struct scst_tgt_dev *tgt_dev;
	int cont, c;
	LIST_HEAD(host_devs);

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Target reset (mcmd %p, cmd count %d)",
		mcmd, atomic_read(&mcmd->sess->sess_cmd_count));

	mcmd->needs_unblocking = 1;

	mutex_lock(&scst_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		int found = 0;

		spin_lock_bh(&dev->dev_lock);
		__scst_block_dev(dev);
		scst_process_reset(dev, mcmd->sess, NULL, mcmd);
		spin_unlock_bh(&dev->dev_lock);

		cont = 0;
		c = 0;
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			dev_tgt_dev_list_entry) 
		{
			cont = 1;
			rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);
			if (rc == SCST_DEV_TM_NOT_COMPLETED) 
				c = 1;
			else if ((rc < 0) &&
				 (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
				mcmd->status = rc;
		}
		if (cont && !c)
			continue;
		
		if (dev->scsi_dev == NULL)
			continue;

		list_for_each_entry(d, &host_devs, reset_dev_list_entry) {
			if (dev->scsi_dev->host->host_no ==
				    d->scsi_dev->host->host_no) 
			{
				found = 1;
				break;
			}
		}
		if (!found)
			list_add_tail(&dev->reset_dev_list_entry, &host_devs);
	}

	/*
	 * We suppose here that for all commands that already on devices
	 * on/after scsi_reset_provider() completion callbacks will be called.
	 */

	list_for_each_entry(dev, &host_devs, reset_dev_list_entry) {
		/* dev->scsi_dev must be non-NULL here */
		TRACE(TRACE_MGMT, "Resetting host %d bus ",
		      dev->scsi_dev->host->host_no);
		rc = scsi_reset_provider(dev->scsi_dev, SCSI_TRY_RESET_BUS);
		TRACE(TRACE_MGMT, "Result of host %d bus reset: %s",
		      dev->scsi_dev->host->host_no,
		      (rc == SUCCESS) ? "SUCCESS" : "FAILED");
		if ((rc != SUCCESS) &&
		    (mcmd->status == SCST_MGMT_STATUS_SUCCESS)) {
			/* SCSI_TRY_RESET_BUS is also done by scsi_reset_provider() */
			mcmd->status = SCST_MGMT_STATUS_FAILED;
		}
	}

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		if (dev->scsi_dev != NULL)
			dev->scsi_dev->was_reset = 0;
	}

	mutex_unlock(&scst_mutex);

	tm_dbg_task_mgmt("TARGET RESET", 0);
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

	TRACE(TRACE_MGMT, "Resetting lun %Ld (mcmd %p)", tgt_dev->lun, mcmd);

	mcmd->needs_unblocking = 1;

	spin_lock_bh(&dev->dev_lock);
	__scst_block_dev(dev);
	scst_process_reset(dev, mcmd->sess, NULL, mcmd);
	spin_unlock_bh(&dev->dev_lock);

	rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 1);
	if (rc != SCST_DEV_TM_NOT_COMPLETED)
		goto out_tm_dbg;

	if (dev->scsi_dev != NULL) {
		TRACE(TRACE_MGMT, "Resetting host %d bus ",
		      dev->scsi_dev->host->host_no);
		rc = scsi_reset_provider(dev->scsi_dev, SCSI_TRY_RESET_DEVICE);
		if ((rc != SUCCESS) && (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
			mcmd->status = SCST_MGMT_STATUS_FAILED;
		dev->scsi_dev->was_reset = 0;
	}

out_tm_dbg:
	tm_dbg_task_mgmt("LUN RESET", 0);
	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
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
		TRACE(TRACE_MGMT, "Nexus loss for sess %p (mcmd %p)", sess,
			mcmd);
	} else {
		TRACE(TRACE_MGMT, "Aborting all from sess %p (mcmd %p)", sess,
			mcmd);
	}

	mcmd->needs_unblocking = 1;

	mutex_lock(&scst_mutex);
	for(i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&sess->sess_tgt_dev_list_hash[i];
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			struct scst_device *dev = tgt_dev->dev;
			int rc;
	
			spin_lock_bh(&dev->dev_lock);
			__scst_block_dev(dev);
			spin_unlock_bh(&dev->dev_lock);
	
			__scst_abort_task_set(mcmd, tgt_dev, !nexus_loss, 1);
			if (nexus_loss)
				scst_reset_tgt_dev(tgt_dev, 1);
	
			rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);
			if ((rc < 0) && (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
				mcmd->status = rc;		
		}
	}
	mutex_unlock(&scst_mutex);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_all_nexus_loss_tgt(struct scst_mgmt_cmd *mcmd,
	int nexus_loss)
{
	int res;
	int i;
	struct scst_tgt *tgt = mcmd->sess->tgt;
	struct scst_session *sess;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	if (nexus_loss) {
		TRACE(TRACE_MGMT, "I_T Nexus loss (tgt %p, mcmd %p)", tgt,
			mcmd);
	} else {
		TRACE(TRACE_MGMT, "Aborting all from tgt %p (mcmd %p)", tgt,
			mcmd);
	}

	mcmd->needs_unblocking = 1;

	mutex_lock(&scst_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		spin_lock_bh(&dev->dev_lock);
		__scst_block_dev(dev);
		spin_unlock_bh(&dev->dev_lock);
	}

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		for(i = 0; i < TGT_DEV_HASH_SIZE; i++) {
			struct list_head *sess_tgt_dev_list_head =
				&sess->sess_tgt_dev_list_hash[i];
			list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
					sess_tgt_dev_list_entry) {
				int rc;
	
				__scst_abort_task_set(mcmd, tgt_dev, !nexus_loss, 1);
				if (nexus_loss)
					scst_reset_tgt_dev(tgt_dev, 1);
	
				rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);
				if ((rc < 0) &&
				    (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
					mcmd->status = rc;
			}
		}
	}

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
	case SCST_CLEAR_TASK_SET:
		res = scst_abort_task_set(mcmd);
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
	mcmd->state = SCST_MGMT_CMD_STATE_DONE;
	goto out;
}

static void scst_mgmt_cmd_send_done(struct scst_mgmt_cmd *mcmd)
{
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	clear_bit(SCST_FLAG_TM_ACTIVE, &scst_flags);
	spin_lock_irq(&scst_mcmd_lock);
	if (!list_empty(&scst_delayed_mgmt_cmd_list)) {
		struct scst_mgmt_cmd *m;
		m = list_entry(scst_delayed_mgmt_cmd_list.next, typeof(*m),
				mgmt_cmd_list_entry);
		TRACE_MGMT_DBG("Moving delayed mgmt cmd %p to head of active "
			"mgmt cmd list", m);
		list_move(&m->mgmt_cmd_list_entry, &scst_active_mgmt_cmd_list);
	}
	spin_unlock_irq(&scst_mcmd_lock);

	mcmd->state = SCST_MGMT_CMD_STATE_FINISHED;
	if (scst_is_strict_mgmt_fn(mcmd->fn) && (mcmd->completed_cmd_count > 0))
		mcmd->status = SCST_MGMT_STATUS_TASK_NOT_EXIST;

	if (mcmd->sess->tgt->tgtt->task_mgmt_fn_done) {
		TRACE_DBG("Calling target %s task_mgmt_fn_done()",
		      mcmd->sess->tgt->tgtt->name);
		mcmd->sess->tgt->tgtt->task_mgmt_fn_done(mcmd);
		TRACE_MGMT_DBG("Target's %s task_mgmt_fn_done() returned",
		      mcmd->sess->tgt->tgtt->name);
	}

	if (mcmd->needs_unblocking) {
		switch (mcmd->fn) {
		case SCST_ABORT_TASK_SET:
		case SCST_CLEAR_TASK_SET:
		case SCST_LUN_RESET:
			scst_unblock_dev(mcmd->mcmd_tgt_dev->dev);
			break;

		case SCST_TARGET_RESET:
		case SCST_ABORT_ALL_TASKS:
		case SCST_NEXUS_LOSS:
			mutex_lock(&scst_mutex);
			list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
				scst_unblock_dev(dev);
			}
			mutex_unlock(&scst_mutex);
			break;

		case SCST_NEXUS_LOSS_SESS:
		case SCST_ABORT_ALL_TASKS_SESS:
		{
			int i;

			mutex_lock(&scst_mutex);
			for(i = 0; i < TGT_DEV_HASH_SIZE; i++) {
				struct list_head *sess_tgt_dev_list_head = 
					&mcmd->sess->sess_tgt_dev_list_hash[i];
				list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
						sess_tgt_dev_list_entry) {
					scst_unblock_dev(tgt_dev->dev);
				}
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
		case SCST_MGMT_CMD_STATE_INIT:
			res = scst_mgmt_cmd_init(mcmd);
			if (res)
				goto out;
			break;

		case SCST_MGMT_CMD_STATE_READY:
			if (scst_mgmt_cmd_exec(mcmd))
				goto out;
			break;

		case SCST_MGMT_CMD_STATE_DONE:
			scst_mgmt_cmd_send_done(mcmd);
			break;

		default:
			PRINT_ERROR("Unknown state %d of management command",
				    mcmd->state);
			res = -1;
			/* go through */
		case SCST_MGMT_CMD_STATE_FINISHED:
			scst_free_mgmt_cmd(mcmd);
			goto out;

#ifdef EXTRACHECKS
		case SCST_MGMT_CMD_STATE_EXECUTING:
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

int scst_mgmt_cmd_thread(void *arg)
{
	TRACE_ENTRY();

	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&scst_mcmd_lock);
	while(!kthread_should_stop()) {
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
				    !test_bit(SCST_FLAG_SUSPENDING, &scst_flags)) {
					TRACE_MGMT_DBG("Adding mgmt cmd %p to head "
						"of delayed mgmt cmd list", mcmd);
					list_add(&mcmd->mgmt_cmd_list_entry, 
						&scst_delayed_mgmt_cmd_list);
				} else {
					TRACE_MGMT_DBG("Adding mgmt cmd %p to head "
						"of active mgmt cmd list", mcmd);
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
	if (mcmd == NULL)
		goto out;

	mcmd->sess = sess;
	mcmd->fn = fn;
	mcmd->state = SCST_MGMT_CMD_STATE_INIT;
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

	local_irq_save(flags);

	spin_lock(&sess->sess_list_lock);
	atomic_inc(&sess->sess_cmd_count);

#ifdef EXTRACHECKS
	if (unlikely(sess->shut_phase != SCST_SESS_SPH_READY)) {
		PRINT_ERROR("%s",
			"New mgmt cmd while shutting down the session");
		sBUG();
	}
#endif

	if (unlikely(sess->init_phase != SCST_SESS_IPH_READY)) {
		switch(sess->init_phase) {
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
		if (mcmd->lun == (lun_t)-1)
			goto out_free;
		mcmd->lun_set = 1;
	}

	if (params->tag_set)
		mcmd->tag = params->tag;

	mcmd->cmd_sn_set = params->cmd_sn_set;
	mcmd->cmd_sn = params->cmd_sn;

	TRACE(TRACE_MGMT, "sess=%p, fn %x, tag_set %d, tag %Ld, lun_set %d, "
		"lun=%Ld, cmd_sn_set %d, cmd_sn %x", sess, params->fn,
		params->tag_set, params->tag, params->lun_set,
		(uint64_t)mcmd->lun, params->cmd_sn_set, params->cmd_sn);

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

/* scst_mutex supposed to be held */
static struct scst_acg *scst_find_acg(const char *initiator_name)
{
	struct scst_acg *acg, *res = NULL;
	struct scst_acn *n;

	TRACE_ENTRY();
	
	list_for_each_entry(acg, &scst_acg_list, scst_acg_list_entry) {
		list_for_each_entry(n, &acg->acn_list, 
			acn_list_entry) 
		{
			if (strcmp(n->name, initiator_name) == 0) {
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

	scst_suspend_activity();	
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
	scst_resume_activity();

	if (sess->init_result_fn) {
		TRACE_DBG("Calling init_result_fn(%p)", sess);
		sess->init_result_fn(sess, sess->reg_sess_data, res);
		TRACE_DBG("%s", "init_result_fn() returned");
	}

#ifdef CONFIG_LOCKDEP
	if (res == 0) {
		sess->shutdown_compl = kmalloc(sizeof(*sess->shutdown_compl),
			GFP_KERNEL);
		if (sess->shutdown_compl == NULL)
			res = -ENOMEM;
		else
			init_completion(sess->shutdown_compl);
	}
#endif

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
		list_del(&cmd->search_cmd_list_entry);
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

/* 
 * Must not be called in parallel with scst_rx_cmd() or 
 * scst_rx_mgmt_fn_*() for the same sess
 */
void scst_unregister_session(struct scst_session *sess, int wait,
	void (*unreg_done_fn) (struct scst_session *sess))
{
	unsigned long flags;
	struct completion *pc;
#ifndef CONFIG_LOCKDEP
	DECLARE_COMPLETION(c);
#endif

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Unregistering session %p (wait %d)", sess, wait);

#ifdef CONFIG_LOCKDEP
	pc = sess->shutdown_compl;
#else
	pc = &c;
#endif

	sess->shut_phase = SCST_SESS_SPH_PRE_UNREG;

	spin_lock_irqsave(&scst_mgmt_lock, flags);

	sess->unreg_done_fn = unreg_done_fn;
	if (wait) {
		sess->shutdown_compl = pc;
		smp_mb();
	}
#ifdef CONFIG_LOCKDEP
	else
		 sess->shutdown_compl = NULL;
#endif

	spin_unlock_irqrestore(&scst_mgmt_lock, flags);

	tm_dbg_task_mgmt("UNREGISTER SESSION", 1);

	scst_sess_put(sess);

	if (wait) {
		TRACE_DBG("Waiting for session %p to complete", sess);
		wait_for_completion(pc);
	}

#ifdef CONFIG_LOCKDEP
	kfree(pc);
#endif

	TRACE_EXIT();
	return;
}

static void scst_pre_unreg_sess(struct scst_session *sess)
{
	int i;
	struct scst_tgt_dev *tgt_dev;
	unsigned long flags;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);
	for(i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&sess->sess_tgt_dev_list_hash[i];
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			struct scst_dev_type *handler = tgt_dev->dev->handler;
			if (handler && handler->pre_unreg_sess) {
				TRACE_DBG("Calling dev handler's pre_unreg_sess(%p)",
				      tgt_dev);
				handler->pre_unreg_sess(tgt_dev);
				TRACE_DBG("%s", "Dev handler's pre_unreg_sess() "
					"returned");
			}
		}
	}
	mutex_unlock(&scst_mutex);

	sess->shut_phase = SCST_SESS_SPH_SHUTDOWN;

	spin_lock_irqsave(&scst_mgmt_lock, flags);
	TRACE_DBG("Adding sess %p to scst_sess_shut_list", sess);
	list_add_tail(&sess->sess_shut_list_entry, &scst_sess_shut_list);
	spin_unlock_irqrestore(&scst_mgmt_lock, flags);

	TRACE_EXIT();
	return;
}

static inline int test_mgmt_list(void)
{
	int res = !list_empty(&scst_sess_init_list) ||
		  !list_empty(&scst_sess_shut_list) ||
		  unlikely(kthread_should_stop());
	return res;
}

int scst_mgmt_thread(void *arg)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&scst_mgmt_lock);
	while(!kthread_should_stop()) {
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
				PRINT_ERROR("session %p is in "
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

			switch(sess->shut_phase) {
			case SCST_SESS_SPH_PRE_UNREG:
				scst_pre_unreg_sess(sess);
				break;
			case SCST_SESS_SPH_SHUTDOWN:
				sBUG_ON(atomic_read(&sess->refcnt) != 0);
				scst_free_session_callback(sess);
				break;
			default:
				PRINT_ERROR("session %p is in "
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

	TRACE_EXIT();
	return 0;
}

/* Called under sess->sess_list_lock */
struct scst_cmd *__scst_find_cmd_by_tag(struct scst_session *sess, uint64_t tag)
{
	struct scst_cmd *cmd = NULL;

	TRACE_ENTRY();

	/* ToDo: hash list */

	TRACE_DBG("%s (sess=%p, tag=%llu)", "Searching in search cmd list",
		sess, tag);
	list_for_each_entry(cmd, &sess->search_cmd_list, 
			search_cmd_list_entry) {
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
			search_cmd_list_entry) {
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

void *scst_cmd_get_tgt_priv_lock(struct scst_cmd *cmd)
{
	void *res;
	unsigned long flags;
	spin_lock_irqsave(&scst_main_lock, flags);
	res = cmd->tgt_priv;
	spin_unlock_irqrestore(&scst_main_lock, flags);
	return res;
}

void scst_cmd_set_tgt_priv_lock(struct scst_cmd *cmd, void *val)
{
	unsigned long flags;
	spin_lock_irqsave(&scst_main_lock, flags);
	cmd->tgt_priv = val;
	spin_unlock_irqrestore(&scst_main_lock, flags);
}
