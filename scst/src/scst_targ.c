/*
 *  scst_targ.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
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

#include "scsi_tgt.h"
#include "scst_priv.h"

static int scst_do_job_init(void);
static int scst_process_init_cmd(struct scst_cmd *cmd);

static int __scst_process_active_cmd(struct scst_cmd *cmd, int context,
	int left_locked);

static void scst_complete_cmd_mgmt(struct scst_cmd *cmd,
	struct scst_mgmt_cmd *mcmd);

/* scst_list_lock assumed to be held */
static inline int scst_process_active_cmd(struct scst_cmd *cmd, int context,
	unsigned long *pflags, int left_locked)
{
	int res;

	TRACE_ENTRY();

	TRACE_DBG("Moving cmd %p to cmd list", cmd);
	list_move_tail(&cmd->cmd_list_entry, &scst_cmd_list);

	/* This is an inline func., so unneeded code will be optimized out */
	if (pflags)
		spin_unlock_irqrestore(&scst_list_lock, *pflags);
	else
		spin_unlock_irq(&scst_list_lock);

	res = __scst_process_active_cmd(cmd, context, left_locked);

	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_list_lock and IRQs disabled */
static inline void scst_cmd_set_sn(struct scst_cmd *cmd)
{
	/* ToDo: cmd->queue_type */

	/* scst_list_lock is enough to protect that */
	cmd->sn = cmd->tgt_dev->next_sn;
	cmd->tgt_dev->next_sn++;
	cmd->no_sn = 0;

	TRACE(TRACE_DEBUG/*TRACE_SCSI_SERIALIZING*/, "cmd(%p)->sn: %d",
		cmd, cmd->sn);
}

static inline void scst_schedule_tasklet(void)
{
	struct tasklet_struct *t = &scst_tasklets[smp_processor_id()];

	tasklet_schedule(t);
}

/* 
 * Must not been called in parallel with scst_unregister_session() for the 
 * same sess
 */
struct scst_cmd *scst_rx_cmd(struct scst_session *sess,
			     const uint8_t *lun, int lun_len,
			     const uint8_t *cdb, int cdb_len, int atomic)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

#ifdef EXTRACHECKS
	if (unlikely(sess->shutting_down)) {
		PRINT_ERROR_PR("%s", "New cmd while shutting down the session");
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

	if (cdb_len <= MAX_COMMAND_SIZE) {
		memcpy(cmd->cdb, cdb, cdb_len);
		cmd->cdb_len = cdb_len;
	}

	TRACE_DBG("cmd %p, sess %p", cmd, sess);
	scst_sess_get(sess);

out:
	TRACE_EXIT();
	return cmd;
}

static void scst_setup_to_active(struct scst_cmd *cmd)
{
	cmd->state = SCST_CMD_STATE_XMIT_RESP;
	TRACE_DBG("Adding cmd %p to active cmd list", cmd);
	list_add_tail(&cmd->cmd_list_entry, &scst_active_cmd_list);
}

void scst_cmd_init_done(struct scst_cmd *cmd, int pref_context)
{
	int res = 0;
	unsigned long flags = 0;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d (cmd %p)", pref_context, cmd);
	TRACE(TRACE_SCSI, "tag=%d, lun=%Ld, CDB len=%d", cmd->tag, 
		(uint64_t)cmd->lun, cmd->cdb_len);
	TRACE_BUFF_FLAG(TRACE_SCSI|TRACE_RECV_BOT, "Recieving CDB",
		cmd->cdb, cmd->cdb_len);

#ifdef EXTRACHECKS
	if (unlikely(in_irq()) && ((pref_context == SCST_CONTEXT_DIRECT) ||
			 (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)))
	{
		PRINT_ERROR_PR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_TASKLET instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_TASKLET;
	}
#endif

	spin_lock_irqsave(&scst_list_lock, flags);

	/* Let's make it here, this will save us a lock or atomic */
	sess->sess_cmd_count++;

	list_add_tail(&cmd->search_cmd_list_entry, &sess->search_cmd_list);

	if (unlikely(sess->init_phase != SCST_SESS_IPH_READY)) {
		switch(sess->init_phase) {
		case SCST_SESS_IPH_SUCCESS:
			break;
		case SCST_SESS_IPH_INITING:
			TRACE_DBG("Adding cmd %p to init deferred cmd list", cmd);
			list_add_tail(&cmd->cmd_list_entry, 
				&sess->init_deferred_cmd_list);
			goto out_unlock_flags;
		case SCST_SESS_IPH_FAILED:
			scst_set_busy(cmd);
			scst_setup_to_active(cmd);
			goto active;
		default:
			sBUG();
		}
	}

	if (unlikely(cmd->lun == (lun_t)-1)) {
		PRINT_ERROR_PR("Wrong LUN %d, finishing cmd", -1);
		scst_set_cmd_error(cmd,
		   	SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		scst_setup_to_active(cmd);
		goto active;
	}

	if (unlikely(cmd->cdb_len == 0)) {
		PRINT_ERROR_PR("Wrong CDB len %d, finishing cmd", 0);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		scst_setup_to_active(cmd);
		goto active;
	}

	TRACE_DBG("Adding cmd %p to init cmd list", cmd);
	list_add_tail(&cmd->cmd_list_entry, &scst_init_cmd_list);

	cmd->state = SCST_CMD_STATE_INIT;

	switch (pref_context) {
	case SCST_CONTEXT_TASKLET:
		scst_schedule_tasklet();
		goto out_unlock_flags;

	case SCST_CONTEXT_DIRECT:
	case SCST_CONTEXT_DIRECT_ATOMIC:
		if (cmd->no_sn)
			res = scst_process_init_cmd(cmd);
		else
			res = scst_do_job_init();
		if (unlikely(res > 0))
			goto out_unlock_flags;
		break;

	case SCST_CONTEXT_THREAD:
		goto out_thread_unlock_flags;

	default:
		PRINT_ERROR_PR("Context %x is undefined, using the thread one",
			pref_context);
		goto out_thread_unlock_flags;
	}

active:
	/* Here cmd must be in active cmd list */
	switch (pref_context) {
	case SCST_CONTEXT_TASKLET:
		scst_schedule_tasklet();
		goto out_unlock_flags;

	case SCST_CONTEXT_DIRECT:
	case SCST_CONTEXT_DIRECT_ATOMIC:
		scst_process_active_cmd(cmd, pref_context, &flags, 0);
		/* For *NEED_THREAD wake_up() is already done */
		break;

	case SCST_CONTEXT_THREAD:
		goto out_thread_unlock_flags;

	default:
		PRINT_ERROR_PR("Context %x is undefined, using the thread one",
			pref_context);
		goto out_thread_unlock_flags;
	}

out:
	TRACE_EXIT();
	return;

out_unlock_flags:
	spin_unlock_irqrestore(&scst_list_lock, flags);
	goto out;

out_thread_unlock_flags:
	cmd->non_atomic_only = 1;
	spin_unlock_irqrestore(&scst_list_lock, flags);
	wake_up(&scst_list_waitQ);
	goto out;
}

static int scst_parse_cmd(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int state;
	struct scst_tgt_dev *tgt_dev_saved = cmd->tgt_dev;
	struct scst_device *dev = cmd->dev;
	struct scst_info_cdb cdb_info;
	int atomic = scst_cmd_atomic(cmd);
	int orig_bufflen = cmd->bufflen;
	int set_dir = 1;

	TRACE_ENTRY();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_DBG("ABORTED set, returning ABORTED "
			"for cmd %p", cmd);
		goto out_xmit;
	}

	if (atomic && !dev->handler->parse_atomic) {
		TRACE_DBG("Dev handler %s parse() can not be "
		      "called in atomic context, rescheduling to the thread",
		      dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	/*
	 * Expected transfer data supplied by the SCSI transport via the
	 * target driver are untrusted, so we prefer to fetch them from CDB.
	 * Additionally, not all transports support supplying the expected
	 * transfer data.
	 */

	if (unlikely(scst_get_cdb_info(cmd->cdb, dev->handler->type, 
			&cdb_info) != 0)) 
	{
		static int t;
		if (t < 10) {
			t++;
			PRINT_INFO_PR("Unknown opcode 0x%02x for %s. "
				"Should you update scst_scsi_op_table?",
				cmd->cdb[0], dev->handler->name);
		}
		if (scst_cmd_is_expected_set(cmd)) {
			TRACE(TRACE_SCSI, "Using initiator supplied values: "
				"direction %d, transfer_len %d",
				cmd->expected_data_direction,
				cmd->expected_transfer_len);
			cmd->data_direction = cmd->expected_data_direction;
			cmd->bufflen = cmd->expected_transfer_len;
			/* Restore (most probably) lost CDB length */
			cmd->cdb_len = scst_get_cdb_len(cmd->cdb);
			if (cmd->cdb_len == -1) {
				PRINT_ERROR_PR("Unable to get CDB length for "
					"opcode 0x%02x. Returning INVALID "
					"OPCODE", cmd->cdb[0]);
				scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
				goto out_xmit;
			}
		}
		else {
			PRINT_ERROR_PR("Unknown opcode 0x%02x for %s and "
			     "target %s not supplied expected values. "
			     "Returning INVALID OPCODE.", cmd->cdb[0], 
			     dev->handler->name, cmd->tgtt->name);
			scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
			goto out_xmit;
		}
	} else {
		TRACE(TRACE_SCSI, "op_name <%s>, direction=%d (expected %d, "
			"set %s), transfer_len=%d (expected len %d), flags=%d",
			cdb_info.op_name, cdb_info.direction,
			cmd->expected_data_direction,
			scst_cmd_is_expected_set(cmd) ? "yes" : "no",
			cdb_info.transfer_len, cmd->expected_transfer_len,
			cdb_info.flags);

		/* Restore (most probably) lost CDB length */
		cmd->cdb_len = cdb_info.cdb_len;

		cmd->data_direction = cdb_info.direction;
		if (!(cdb_info.flags & SCST_UNKNOWN_LENGTH))
			cmd->bufflen = cdb_info.transfer_len;
		/* else cmd->bufflen remained as it was inited in 0 */
	}

	if (unlikely(cmd->cdb[cmd->cdb_len - 1] & CONTROL_BYTE_NACA_BIT)) {
		PRINT_ERROR_PR("NACA bit in control byte CDB is not supported "
			    "(opcode 0x%02x)", cmd->cdb[0]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_xmit;
	}

	if (unlikely(cmd->cdb[cmd->cdb_len - 1] & CONTROL_BYTE_LINK_BIT)) {
		PRINT_ERROR_PR("Linked commands are not supported "
			    "(opcode 0x%02x)", cmd->cdb[0]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_xmit;
	}

	if (likely(!scst_is_cmd_local(cmd))) {
		TRACE_DBG("Calling dev handler %s parse(%p)",
		      dev->handler->name, cmd);
		TRACE_BUFF_FLAG(TRACE_SEND_BOT, "Parsing: ", cmd->cdb, cmd->cdb_len);
		state = dev->handler->parse(cmd, &cdb_info);
		TRACE_DBG("Dev handler %s parse() returned %d",
			dev->handler->name, state);

		if (state == SCST_CMD_STATE_DEFAULT)
			state = SCST_CMD_STATE_PREPARE_SPACE;
	}
	else
		state = SCST_CMD_STATE_PREPARE_SPACE;

	if (scst_cmd_is_expected_set(cmd)) {
		if (cmd->expected_transfer_len < cmd->bufflen) {
			TRACE(TRACE_SCSI, "cmd->expected_transfer_len(%d) < "
				"cmd->bufflen(%zd), using expected_transfer_len "
				"instead", cmd->expected_transfer_len,
				cmd->bufflen);
			cmd->bufflen = cmd->expected_transfer_len;
		}
	}

	if (cmd->data_len == -1)
		cmd->data_len = cmd->bufflen;

	if (cmd->data_buf_alloced && (orig_bufflen < cmd->bufflen)) {
		PRINT_ERROR_PR("Target driver supplied data buffer (size %d), "
			"is less, than required (size %d)", orig_bufflen,
			cmd->bufflen);
		goto out_error;
	}

#ifdef EXTRACHECKS
	if (state != SCST_CMD_STATE_NEED_THREAD_CTX) {
		if (((cmd->data_direction == SCST_DATA_UNKNOWN) &&
		    	(state != SCST_CMD_STATE_DEV_PARSE)) ||
		    ((cmd->bufflen != 0) && 
		    	(cmd->data_direction == SCST_DATA_NONE)) ||
		    ((cmd->bufflen == 0) && 
		    	(cmd->data_direction != SCST_DATA_NONE)) ||
		    ((cmd->bufflen != 0) && (cmd->sg == NULL) &&
		    	(state > SCST_CMD_STATE_PREPARE_SPACE))) 
		{
			PRINT_ERROR_PR("Dev handler %s parse() returned "
				       "invalid cmd data_direction %d, "
				       "bufflen %zd or state %d (opcode 0x%x)",
				       dev->handler->name, 
				       cmd->data_direction, cmd->bufflen,
				       state, cmd->cdb[0]);
			goto out_error;
		}
	}
#endif

	switch (state) {
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_DEV_PARSE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_SEND_TO_MIDLEV:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
		cmd->state = state;
		res = SCST_CMD_STATE_RES_CONT_SAME;
		break;


	case SCST_CMD_STATE_NEED_THREAD_CTX:
		TRACE_DBG("Dev handler %s parse() requested thread "
		      "context, rescheduling", dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		set_dir = 0;
		break;

	case SCST_CMD_STATE_REINIT:
		cmd->tgt_dev_saved = tgt_dev_saved;
		cmd->state = state;
		res = SCST_CMD_STATE_RES_RESTART;
		set_dir = 0;
		break;

	default:
		if (state >= 0) {
			PRINT_ERROR_PR("Dev handler %s parse() returned "
			     "invalid cmd state %d (opcode %d)", 
			     dev->handler->name, state, cmd->cdb[0]);
		} else {
			PRINT_ERROR_PR("Dev handler %s parse() returned "
				"error %d (opcode %d)", dev->handler->name, 
				state, cmd->cdb[0]);
		}
		goto out_error;
	}

	if ((cmd->resp_data_len == -1) && set_dir) {
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
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;

out_xmit:
	cmd->state = SCST_CMD_STATE_XMIT_RESP;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
void scst_cmd_mem_work_fn(void *p)
#else
void scst_cmd_mem_work_fn(struct work_struct *work)
#endif
{
	TRACE_ENTRY();

	spin_lock_bh(&scst_cmd_mem_lock);

	scst_cur_max_cmd_mem += (scst_cur_max_cmd_mem >> 3);
	if (scst_cur_max_cmd_mem < scst_max_cmd_mem) {
		TRACE_MGMT_DBG("%s", "Schedule cmd_mem_work");
		schedule_delayed_work(&scst_cmd_mem_work, SCST_CMD_MEM_TIMEOUT);
	} else {
		scst_cur_max_cmd_mem = scst_max_cmd_mem;
		clear_bit(SCST_FLAG_CMD_MEM_WORK_SCHEDULED, &scst_flags);
	}
	TRACE_MGMT_DBG("New max cmd mem %ld Mb", scst_cur_max_cmd_mem >> 20);

	spin_unlock_bh(&scst_cmd_mem_lock);

	TRACE_EXIT();
	return;
}

int scst_check_mem(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	if (cmd->mem_checked)
		goto out;

	spin_lock_bh(&scst_cmd_mem_lock);

	scst_cur_cmd_mem += cmd->bufflen;
	cmd->mem_checked = 1;
	if (likely(scst_cur_cmd_mem <= scst_cur_max_cmd_mem))
		goto out_unlock;

	TRACE(TRACE_OUT_OF_MEM, "Total memory allocated by commands (%ld Kb) "
		"is too big, returning QUEUE FULL to initiator \"%s\" (maximum "
		"allowed %ld Kb)", scst_cur_cmd_mem >> 10,
		(cmd->sess->initiator_name[0] == '\0') ?
		  "Anonymous" : cmd->sess->initiator_name,
		scst_cur_max_cmd_mem >> 10);

	scst_cur_cmd_mem -= cmd->bufflen;
	cmd->mem_checked = 0;
	scst_set_busy(cmd);
	cmd->state = SCST_CMD_STATE_XMIT_RESP;
	res = 1;

out_unlock:
	spin_unlock_bh(&scst_cmd_mem_lock);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void scst_low_cur_max_cmd_mem(void)
{
	TRACE_ENTRY();

	if (test_bit(SCST_FLAG_CMD_MEM_WORK_SCHEDULED, &scst_flags)) {
		cancel_delayed_work(&scst_cmd_mem_work);
		flush_scheduled_work();
		clear_bit(SCST_FLAG_CMD_MEM_WORK_SCHEDULED, &scst_flags);
	}

	spin_lock_bh(&scst_cmd_mem_lock);

	scst_cur_max_cmd_mem = (scst_cur_cmd_mem >> 1) + 
				(scst_cur_cmd_mem >> 2);
	if (scst_cur_max_cmd_mem < 16*1024*1024)
		scst_cur_max_cmd_mem = 16*1024*1024;

	if (!test_bit(SCST_FLAG_CMD_MEM_WORK_SCHEDULED, &scst_flags)) {
		TRACE_MGMT_DBG("%s", "Schedule cmd_mem_work");
		schedule_delayed_work(&scst_cmd_mem_work, SCST_CMD_MEM_TIMEOUT);
		set_bit(SCST_FLAG_CMD_MEM_WORK_SCHEDULED, &scst_flags);
	}

	spin_unlock_bh(&scst_cmd_mem_lock);

	TRACE_MGMT_DBG("New max cmd mem %ld Mb", scst_cur_max_cmd_mem >> 20);

	TRACE_EXIT();
	return;
}

static int scst_prepare_space(struct scst_cmd *cmd)
{
	int r, res = SCST_CMD_STATE_RES_CONT_SAME;

	TRACE_ENTRY();

	if (cmd->data_direction == SCST_DATA_NONE)
		goto prep_done;

	r = scst_check_mem(cmd);
	if (unlikely(r != 0))
		goto out;

	if (cmd->data_buf_tgt_alloc) {
		int orig_bufflen = cmd->bufflen;
		TRACE_MEM("%s", "Custom tgt data buf allocation requested");
		r = cmd->tgtt->alloc_data_buf(cmd);
		if (r > 0)
			r = scst_alloc_space(cmd);
		else if (r == 0) {
			cmd->data_buf_alloced = 1;
			if (unlikely(orig_bufflen < cmd->bufflen)) {
				PRINT_ERROR_PR("Target driver allocated data "
					"buffer (size %d), is less, than "
					"required (size %d)", orig_bufflen,
					cmd->bufflen);
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(scst_sense_hardw_error));
				cmd->state = SCST_CMD_STATE_DEV_DONE;
				res = SCST_CMD_STATE_RES_CONT_SAME;
				goto out;
			}
		}
	} else
		r = scst_alloc_space(cmd);

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
		cmd->state = SCST_CMD_STATE_SEND_TO_MIDLEV;
		break;
	}

out:
	TRACE_EXIT_HRES(res);
	return res;

out_no_space:
	TRACE(TRACE_OUT_OF_MEM, "Unable to allocate or build requested buffer "
		"(size %zd), sending BUSY or QUEUE FULL status", cmd->bufflen);
	scst_low_cur_max_cmd_mem();
	scst_set_busy(cmd);
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

void scst_restart_cmd(struct scst_cmd *cmd, int status, int pref_context)
{
	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d", pref_context);
	TRACE_DBG("tag=%d, status=%#x", scst_cmd_get_tag(cmd), status);
	cmd->non_atomic_only = 0;

#ifdef EXTRACHECKS
	if (in_irq() && ((pref_context == SCST_CONTEXT_DIRECT) ||
			 (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)))
	{
		PRINT_ERROR_PR("Wrong context %d in IRQ from target %s, use "
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
			cmd->state = SCST_CMD_STATE_SEND_TO_MIDLEV;
			break;
		}
		if (cmd->no_sn) {
			unsigned long flags;
			int rc;
			spin_lock_irqsave(&scst_list_lock, flags);
			/* Necessary to keep the command's order */
			rc = scst_do_job_init();
			if (unlikely(rc > 0)) {
				TRACE_DBG("Adding cmd %p to init cmd list",
					cmd);
				list_add_tail(&cmd->cmd_list_entry,
					&scst_init_cmd_list);
				spin_unlock_irqrestore(&scst_list_lock, flags);
				goto out;
			}
			scst_cmd_set_sn(cmd);
			spin_unlock_irqrestore(&scst_list_lock, flags);
		}
		if (tm_dbg_check_cmd(cmd) != 0)
			goto out;
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
		PRINT_ERROR_PR("scst_rx_data() received unknown status %x",
			status);
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;
	}

	scst_proccess_redirect_cmd(cmd, pref_context, 1);

out:
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

	TRACE(TRACE_RETRY, "Moving cmd %p to retry cmd list", cmd);
	/* IRQ already off */
	spin_lock(&scst_list_lock);
	list_move_tail(&cmd->cmd_list_entry, &tgt->retry_cmd_list);
	spin_unlock(&scst_list_lock);

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

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
	{
		TRACE_DBG("ABORTED set, returning ABORTED for "
			"cmd %p", cmd);
		goto out_dev_done;
	}

	if (cmd->tgtt->rdy_to_xfer == NULL) {
		cmd->state = SCST_CMD_STATE_SEND_TO_MIDLEV;
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
		PRINT_ERROR_PR("Target driver %s rdy_to_xfer() returned "
		     "fatal error", cmd->tgtt->name);
	} else {
		PRINT_ERROR_PR("Target driver %s rdy_to_xfer() returned invalid "
			    "value %d", cmd->tgtt->name, rc);
	}
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

out_dev_done:
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

void scst_proccess_redirect_cmd(struct scst_cmd *cmd, int context,
	int check_retries)
{
	unsigned long flags;
	int rc;

	TRACE_ENTRY();

	TRACE_DBG("Context: %d", context);

	switch(context) {
	case SCST_CONTEXT_DIRECT:
	case SCST_CONTEXT_DIRECT_ATOMIC:
		if (check_retries)
			scst_check_retries(cmd->tgt, 0);
		cmd->non_atomic_only = 0;
		rc = __scst_process_active_cmd(cmd, context, 0);
		if (rc == SCST_CMD_STATE_RES_NEED_THREAD)
			goto out_thread;
		break;

	default:
		PRINT_ERROR_PR("Context %x is unknown, using the thread one",
			    context);
		/* go through */
	case SCST_CONTEXT_THREAD:
		if (check_retries)
			scst_check_retries(cmd->tgt, 1);
		goto out_thread;

	case SCST_CONTEXT_TASKLET:
		if (check_retries)
			scst_check_retries(cmd->tgt, 1);
		cmd->non_atomic_only = 0;
		spin_lock_irqsave(&scst_list_lock, flags);
		TRACE_DBG("Moving cmd %p to active cmd list", cmd);
		list_move_tail(&cmd->cmd_list_entry, &scst_active_cmd_list);
		spin_unlock_irqrestore(&scst_list_lock, flags);
		scst_schedule_tasklet();
		break;
	}
out:
	TRACE_EXIT();
	return;

out_thread:
	cmd->non_atomic_only = 1;
	spin_lock_irqsave(&scst_list_lock, flags);
	TRACE_DBG("Moving cmd %p to active cmd list", cmd);
	list_move_tail(&cmd->cmd_list_entry, &scst_active_cmd_list);
	spin_unlock_irqrestore(&scst_list_lock, flags);
	wake_up(&scst_list_waitQ);
	goto out;
}

void scst_rx_data(struct scst_cmd *cmd, int status, int pref_context)
{
	TRACE_ENTRY();

	TRACE_DBG("Preferred context: %d", pref_context);
	TRACE(TRACE_SCSI, "tag=%d status=%#x", scst_cmd_get_tag(cmd), status);
	cmd->non_atomic_only = 0;

#ifdef EXTRACHECKS
	if (in_irq() && ((pref_context == SCST_CONTEXT_DIRECT) ||
			 (pref_context == SCST_CONTEXT_DIRECT_ATOMIC)))
	{
		PRINT_ERROR_PR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_TASKLET instead\n", pref_context,
			cmd->tgtt->name);
		pref_context = SCST_CONTEXT_TASKLET;
	}
#endif

	switch (status) {
	case SCST_RX_STATUS_SUCCESS:
		cmd->state = SCST_CMD_STATE_SEND_TO_MIDLEV;
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
		PRINT_ERROR_PR("scst_rx_data() received unknown status %x",
			status);
		cmd->state = SCST_CMD_STATE_DEV_DONE;
		break;
	}

	scst_proccess_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}

/* No locks supposed to be held */
static void scst_check_sense(struct scst_cmd *cmd, const uint8_t *rq_sense,
	int rq_sense_len, int *next_state)
{
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

	if (rq_sense != NULL) {
		sense_valid = SCST_SENSE_VALID(rq_sense);
		if (sense_valid) {
			/* 
			 * We checked that rq_sense_len < sizeof(cmd->sense_buffer)
			 * in init_scst()
			 */
			memcpy(cmd->sense_buffer, rq_sense, rq_sense_len);
			memset(&cmd->sense_buffer[rq_sense_len], 0,
				sizeof(cmd->sense_buffer) - rq_sense_len);
		}
	} else
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

	if (sense_valid) {
		TRACE_BUFF_FLAG(TRACE_SCSI, "Sense", cmd->sense_buffer,
			     sizeof(cmd->sense_buffer));
		/* Check Unit Attention Sense Key */
		if (cmd->sense_buffer[2] == UNIT_ATTENTION) {
			if (cmd->sense_buffer[12] == SCST_SENSE_ASC_UA_RESET) {
				if (dbl_ua_possible) 
				{
					if (ua_sent) {
						TRACE(TRACE_MGMT, "%s", 
							"Double UA detected");
						/* Do retry */
						TRACE(TRACE_MGMT, "Retrying cmd %p "
							"(tag %d)", cmd, cmd->tag);
						cmd->status = 0;
						cmd->msg_status = 0;
						cmd->host_status = DID_OK;
						cmd->driver_status = 0;
						memset(cmd->sense_buffer, 0,
							sizeof(cmd->sense_buffer));
						cmd->retry = 1;
						*next_state = SCST_CMD_STATE_SEND_TO_MIDLEV;
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
	TRACE_EXIT();
	return;

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

static void scst_do_cmd_done(struct scst_cmd *cmd, int result,
	const uint8_t *rq_sense, int rq_sense_len, int resid,
	int *next_state)
{
	unsigned char type;

	TRACE_ENTRY();

	cmd->status = result & 0xff;
	cmd->msg_status = msg_byte(result);
	cmd->host_status = host_byte(result);
	cmd->driver_status = driver_byte(result);
	if (unlikely(resid != 0)) {
#ifdef EXTRACHECKS
		if ((resid < 0) || (resid >= cmd->resp_data_len)) {
			PRINT_ERROR_PR("Wrong resid %d (cmd->resp_data_len=%d)",
				resid, cmd->resp_data_len);
		} else
#endif
			scst_set_resp_data_len(cmd, cmd->resp_data_len - resid);
	}

	TRACE(TRACE_SCSI, "result=%x, cmd->status=%x, resid=%d, "
	      "cmd->msg_status=%x, cmd->host_status=%x, "
	      "cmd->driver_status=%x", result, cmd->status, resid,
	      cmd->msg_status, cmd->host_status, cmd->driver_status);

	cmd->completed = 1;

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
			PRINT_ERROR_PR("%s: scst_get_buf_first() failed",
				__func__);
			goto next;
		}
		if (length > 2 && cmd->cdb[0] == MODE_SENSE) {
			address[2] |= 0x80;   /* Write Protect*/
		}
		else if (length > 3 && cmd->cdb[0] == MODE_SENSE_10) {
			address[3] |= 0x80;   /* Write Protect*/
		}
		scst_put_buf(cmd, address);
	}

next:
	scst_check_sense(cmd, rq_sense, rq_sense_len, next_state);

	TRACE_EXIT();
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
static inline struct scst_cmd *scst_get_cmd(struct scsi_cmnd *scsi_cmd,
					    struct scsi_request **req)
{
	struct scst_cmd *cmd = NULL;

	if (scsi_cmd && (*req = scsi_cmd->sc_request))
		cmd = (struct scst_cmd *)(*req)->upper_private_data;

	if (cmd == NULL) {
		PRINT_ERROR_PR("%s", "Request with NULL cmd");
		if (*req)
			scsi_release_request(*req);
	}

	return cmd;
}

static void scst_cmd_done(struct scsi_cmnd *scsi_cmd)
{
	struct scsi_request *req = NULL;
	struct scst_cmd *cmd;
	int next_state;

	TRACE_ENTRY();

	WARN_ON(in_irq());

	cmd = scst_get_cmd(scsi_cmd, &req);
	if (cmd == NULL)
		goto out;

	next_state = SCST_CMD_STATE_DEV_DONE;
	scst_do_cmd_done(cmd, req->sr_result, req->sr_sense_buffer,
		sizeof(req->sr_sense_buffer), scsi_cmd->resid, &next_state);

	/* Clear out request structure */
	req->sr_use_sg = 0;
	req->sr_sglist_len = 0;
	req->sr_bufflen = 0;
	req->sr_buffer = NULL;
	req->sr_underflow = 0;
	req->sr_request->rq_disk = NULL; /* disown request blk */

	scst_release_request(cmd);

	cmd->state = next_state;
	cmd->non_atomic_only = 0;

	scst_proccess_redirect_cmd(cmd, scst_get_context(), 0);

out:
	TRACE_EXIT();
	return;
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */
static void scst_cmd_done(void *data, char *sense, int result, int resid)
{
	struct scst_cmd *cmd;
	int next_state;

	TRACE_ENTRY();

	WARN_ON(in_irq());

	cmd = (struct scst_cmd *)data;
	if (cmd == NULL)
		goto out;

	next_state = SCST_CMD_STATE_DEV_DONE;
	scst_do_cmd_done(cmd, result, sense, SCSI_SENSE_BUFFERSIZE, resid,
		&next_state);

	cmd->state = next_state;
	cmd->non_atomic_only = 0;

	scst_proccess_redirect_cmd(cmd, scst_get_context(), 0);

out:
	TRACE_EXIT();
	return;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */

static void scst_cmd_done_local(struct scst_cmd *cmd, int next_state)
{
	TRACE_ENTRY();

	sBUG_ON(in_irq());

	scst_dec_on_dev_cmd(cmd);

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
		PRINT_ERROR_PR("scst_cmd_done_local() received invalid cmd "
			    "state %d (opcode %d)", next_state, cmd->cdb[0]);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		next_state = SCST_CMD_STATE_DEV_DONE;
	}

	if (scst_check_auto_sense(cmd)) {
		PRINT_ERROR_PR("CHECK_CONDITION, but no valid sense for "
			"opcode %d", cmd->cdb[0]);
	}
#endif

	scst_check_sense(cmd, NULL, 0, &next_state);

	cmd->state = next_state;
	cmd->non_atomic_only = 0;

	scst_proccess_redirect_cmd(cmd, scst_get_context(), 0);

	TRACE_EXIT();
	return;
}

static int scst_report_luns_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
	int dev_cnt = 0;
	int buffer_size;
	struct scst_tgt_dev *tgt_dev = NULL;
	uint8_t *buffer;
	int offs, overflow = 0;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if ((cmd->cdb[2] != 0) && (cmd->cdb[2] != 2)) {
		PRINT_ERROR_PR("Unsupported SELECT REPORT value %x in REPORT "
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

	/* sess->sess_tgt_dev_list is protected by suspended activity */
	list_for_each_entry(tgt_dev, &cmd->sess->sess_tgt_dev_list,
			    sess_tgt_dev_list_entry) 
	{
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
				PRINT_ERROR_PR("Buffer allocated for REPORT "
					"LUNS command doesn't allow to fit 8 "
					"byte entry (buffer_size=%d)",
					buffer_size);
				goto out_put_hw_err;
			}
			buffer[offs] = (tgt_dev->acg_dev->lun >> 8) & 0xff;
			buffer[offs+1] = tgt_dev->acg_dev->lun & 0xff;
			offs += 8;
		}
inc_dev_cnt:
		dev_cnt++;
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

out_done:
	cmd->completed = 1;

	/* Report the result */
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);

	TRACE_EXIT_RES(res);
	return res;
	
out_put_err:
	scst_put_buf(cmd, buffer);

out_err:
	scst_set_cmd_error(cmd,
		   SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	goto out_done;

out_put_hw_err:
	scst_put_buf(cmd, buffer);
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_done;
}

static int scst_pre_select(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;

	TRACE_ENTRY();

	if (scst_cmd_atomic(cmd)) {
		res = SCST_EXEC_NEED_THREAD;
		goto out;
	}

	scst_block_dev(cmd->dev, 1);
	/* Device will be unblocked in scst_done_cmd_check() */

	if (test_bit(SCST_TGT_DEV_UA_PENDING, &cmd->tgt_dev->tgt_dev_flags)) {
		int rc = scst_set_pending_UA(cmd);
		if (rc == 0) {
			res = SCST_EXEC_COMPLETED;
			cmd->completed = 1;
			/* Report the result */
			scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
			goto out;
		}
	}

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
	int res = SCST_EXEC_NOT_COMPLETED;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev_tmp;

	TRACE_ENTRY();

	if (scst_cmd_atomic(cmd)) {
		res = SCST_EXEC_NEED_THREAD;
		goto out;
	}

	if ((cmd->cdb[0] == RESERVE_10) && (cmd->cdb[2] & SCST_RES_3RDPTY)) {
		PRINT_ERROR_PR("RESERVE_10: 3rdPty RESERVE not implemented "
		     "(lun=%Ld)", (uint64_t)cmd->lun);
		scst_set_cmd_error(cmd,
		   	SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		cmd->completed = 1;
		res = SCST_EXEC_COMPLETED;
		goto out;
	}

	dev = cmd->dev;
	scst_block_dev(dev, 1);
	/* Device will be unblocked in scst_done_cmd_check() */

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
}

static int scst_release_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
	struct scst_tgt_dev *tgt_dev_tmp;
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = cmd->dev;

	scst_block_dev(dev, 1);
	cmd->blocking = 1;
	TRACE_MGMT_DBG("Blocking cmd %p (tag %d)", cmd, cmd->tag);

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
				    dev_tgt_dev_list_entry) 
		{
			clear_bit(SCST_TGT_DEV_RESERVED, 
				&tgt_dev_tmp->tgt_dev_flags);
		}
		dev->dev_reserved = 0;
	}

	spin_unlock_bh(&dev->dev_lock);

	if (res == SCST_EXEC_COMPLETED) {
		cmd->completed = 1;
		/* Report the result */
		scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* 
 * The result of cmd execution, if any, should be reported 
 * via scst_cmd_done_local() 
 */
static int scst_pre_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED, rc;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	/* Reserve check before Unit Attention */
	if (unlikely(test_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags))) {
		if ((cmd->cdb[0] != INQUIRY) && (cmd->cdb[0] != REPORT_LUNS) &&
		    (cmd->cdb[0] != RELEASE) && (cmd->cdb[0] != RELEASE_10) &&
		    (cmd->cdb[0] != REPORT_DEVICE_IDENTIFIER) &&
		    (cmd->cdb[0] != ALLOW_MEDIUM_REMOVAL || (cmd->cdb[4] & 3)) &&
		    (cmd->cdb[0] != LOG_SENSE) && (cmd->cdb[0] != REQUEST_SENSE))
		{
			scst_report_reserved(cmd);
			res = SCST_EXEC_COMPLETED;
			goto out;
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
				goto out_done;
		}
	}

	if (unlikely(test_bit(SCST_TGT_DEV_UA_PENDING, 
			&cmd->tgt_dev->tgt_dev_flags))) {
		if (scst_is_ua_command(cmd)) 
		{
			rc = scst_set_pending_UA(cmd);
			if (rc == 0)
				goto out_done;
		}
	}

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

	cmd->sent_to_midlev = 1;
	cmd->state = SCST_CMD_STATE_EXECUTING;
	cmd->scst_cmd_done = scst_cmd_done_local;

	set_bit(SCST_CMD_EXECUTING, &cmd->cmd_flags);
	smp_mb__after_set_bit();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_aborted;
	}

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
		PRINT_ERROR_PR("Command for virtual device must be "
			"processed by device handler (lun %Ld)!",
			(uint64_t)cmd->lun);
		goto out_error;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)	
	if (unlikely(scst_alloc_request(cmd) != 0)) {
		if (scst_cmd_atomic(cmd)) {
			rc = SCST_EXEC_NEED_THREAD;
			goto out_clear;
		} else {
			PRINT_INFO_PR("%s", "Unable to allocate request, "
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
			PRINT_INFO_PR("scst_exec_req() failed: %d", rc);
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
	PRINT_ERROR_PR("Dev handler %s exec() or scst_local_exec() returned "
		    "invalid code %d", cmd->dev->handler->name, rc);
	/* go through */

out_error:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	cmd->completed = 1;
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	rc = SCST_EXEC_COMPLETED;
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)	
out_busy:
	scst_set_busy(cmd);
	cmd->completed = 1;
	cmd->state = SCST_CMD_STATE_DEV_DONE;
	rc = SCST_EXEC_COMPLETED;
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;
#endif

out_aborted:
	rc = SCST_EXEC_COMPLETED;
	/* Report the result. The cmd is not completed */
	scst_cmd_done_local(cmd, SCST_CMD_STATE_DEFAULT);
	goto out;
}

static int scst_send_to_midlev(struct scst_cmd *cmd)
{
	int res, rc;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_device *dev = cmd->dev;
	int expected_sn;
	int count;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	res = SCST_CMD_STATE_RES_CONT_NEXT;

	if (atomic && dev->handler->exec && !dev->handler->exec_atomic) {
		TRACE_DBG("Dev handler %s exec() can not be "
		      "called in atomic context, rescheduling to the thread",
		      dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	if (unlikely(scst_inc_on_dev_cmd(cmd) != 0))
		goto out;

	scst_inc_cmd_count(); /* protect dev & tgt_dev */

	if (unlikely(cmd->internal) || unlikely(cmd->retry)) {
		rc = scst_do_send_to_midlev(cmd);
		/* !! At this point cmd, sess & tgt_dev can be already freed !! */
		if (rc == SCST_EXEC_NEED_THREAD) {
			TRACE_DBG("%s", "scst_do_send_to_midlev() requested "
			      "thread context, rescheduling");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			scst_dec_on_dev_cmd(cmd);
			goto out_dec_cmd_count;
		} else {
			sBUG_ON(rc != SCST_EXEC_COMPLETED);
			goto out_unplug;
		}
	}

	EXTRACHECKS_BUG_ON(cmd->no_sn);

	expected_sn = tgt_dev->expected_sn;
	if (cmd->sn != expected_sn) {
		spin_lock_bh(&tgt_dev->sn_lock);
		tgt_dev->def_cmd_count++;
		smp_mb();
		barrier(); /* to reread expected_sn */
		expected_sn = tgt_dev->expected_sn;
		if (cmd->sn != expected_sn) {
			scst_dec_on_dev_cmd(cmd);
			TRACE(TRACE_SCSI_SERIALIZING, "Delaying cmd %p (sn=%d, "
			      "expected_sn=%d)", cmd, cmd->sn, expected_sn);
			list_add_tail(&cmd->sn_cmd_list_entry,
				      &tgt_dev->deferred_cmd_list);
			spin_unlock_bh(&tgt_dev->sn_lock);
			/* !! At this point cmd can be already freed !! */
			goto out_dec_cmd_count;
		} else {
			TRACE(TRACE_SCSI_SERIALIZING, "Somebody incremented "
			      "expected_sn %d, continuing", expected_sn);
			tgt_dev->def_cmd_count--;
			spin_unlock_bh(&tgt_dev->sn_lock);
		}
	}

	count = 0;
	while(1) {
		rc = scst_do_send_to_midlev(cmd);
		if (rc == SCST_EXEC_NEED_THREAD) {
			TRACE_DBG("%s", "scst_do_send_to_midlev() requested "
			      "thread context, rescheduling");
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			scst_dec_on_dev_cmd(cmd);
			if (count != 0)
				goto out_unplug;
			else
				goto out_dec_cmd_count;
		}
		sBUG_ON(rc != SCST_EXEC_COMPLETED);
		/* !! At this point cmd can be already freed !! */
		count++;
		expected_sn = __scst_inc_expected_sn(tgt_dev);
		cmd = scst_check_deferred_commands(tgt_dev, expected_sn);
		if (cmd == NULL)
			break;
		if (unlikely(scst_inc_on_dev_cmd(cmd) != 0))
			break;
	}

out_unplug:
	if (dev->scsi_dev != NULL)
		generic_unplug_device(dev->scsi_dev->request_queue);

out_dec_cmd_count:
	scst_dec_cmd_count();
	/* !! At this point sess, dev and tgt_dev can be already freed !! */

out:
	TRACE_EXIT_HRES(res);
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
		PRINT_INFO_PR("Command finished with CHECK CONDITION, but "
			    "without sense data (opcode 0x%x), issuing "
			    "REQUEST SENSE", cmd->cdb[0]);
		rc = scst_prepare_request_sense(cmd);
		if (res > 0) {
			*pres = rc;
			res = 1;
			goto out;
		} else {
			PRINT_ERROR_PR("%s", "Unable to issue REQUEST SENSE, "
				    "returning HARDWARE ERROR");
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
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
					PRINT_INFO_PR("NormACA set for device: "
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
		scst_unblock_dev(cmd->dev);
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
		scst_unblock_dev(cmd->dev);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_dev_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int state;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	if (atomic && !cmd->dev->handler->dev_done_atomic &&
	    cmd->dev->handler->dev_done) 
	{
		TRACE_DBG("Dev handler %s dev_done() can not be "
		      "called in atomic context, rescheduling to the thread",
		      cmd->dev->handler->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	if (scst_done_cmd_check(cmd, &res))
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
	case SCST_CMD_STATE_REINIT:
		cmd->state = state;
		res = SCST_CMD_STATE_RES_RESTART;
		break;

	case SCST_CMD_STATE_DEV_PARSE:
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_SEND_TO_MIDLEV:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_XMIT_RESP:
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
			PRINT_ERROR_PR("Dev handler %s dev_done() returned "
				"invalid cmd state %d", 
				cmd->dev->handler->name, state);
		} else {
			PRINT_ERROR_PR("Dev handler %s dev_done() returned "
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
	if (unlikely(cmd->sent_to_midlev == 0) &&
	    (cmd->tgt_dev != NULL))
	{
		TRACE(TRACE_SCSI_SERIALIZING,
		      "cmd %p was not sent to mid-lev (sn %d)", cmd, cmd->sn);
		scst_inc_expected_sn_unblock(cmd->tgt_dev, cmd, 0);
		cmd->sent_to_midlev = 1;
	}

	if (atomic && !cmd->tgtt->xmit_response_atomic) {
		TRACE_DBG("%s", "xmit_response() can not be "
		      "called in atomic context, rescheduling to the thread");
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	set_bit(SCST_CMD_XMITTING, &cmd->cmd_flags);
	smp_mb__after_set_bit();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		if (test_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags)) {
			TRACE_MGMT_DBG("Flag ABORTED OTHER set for cmd %p "
				"(tag %d), returning TASK ABORTED", cmd, cmd->tag);
			scst_set_cmd_error_status(cmd, SAM_STAT_TASK_ABORTED);
		}
	}

	if (unlikely(test_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Flag NO_RESP set for cmd %p (tag %d), skipping",
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
		TRACE_MGMT_DBG("Delaying cmd %p (tag %d) for 1 second",
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
		PRINT_ERROR_PR("Target driver %s xmit_response() returned "
			"fatal error", cmd->tgtt->name);
	} else {
		PRINT_ERROR_PR("Target driver %s xmit_response() returned "
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

	if (cmd->mem_checked) {
		spin_lock_bh(&scst_cmd_mem_lock);
		scst_cur_cmd_mem -= cmd->bufflen;
		spin_unlock_bh(&scst_cmd_mem_lock);
	}

	spin_lock_irq(&scst_list_lock);

	TRACE_DBG("Deleting cmd %p from cmd list", cmd);
	list_del(&cmd->cmd_list_entry);

	if (cmd->mgmt_cmnd)
		scst_complete_cmd_mgmt(cmd, cmd->mgmt_cmnd);

	if (likely(cmd->tgt_dev != NULL))
		cmd->tgt_dev->cmd_count--;

	cmd->sess->sess_cmd_count--;

	list_del(&cmd->search_cmd_list_entry);

	spin_unlock_irq(&scst_list_lock);

	scst_free_cmd(cmd);

	res = SCST_CMD_STATE_RES_CONT_NEXT;

	TRACE_EXIT_HRES(res);
	return res;
}

/*
 * Returns 0 on success, > 0 when we need to wait for unblock,
 * < 0 if there is no device (lun) or device type handler.
 * Called under scst_list_lock and IRQs disabled
 */
static int scst_translate_lun(struct scst_cmd *cmd)
{
	struct scst_tgt_dev *tgt_dev = NULL;
	int res;

	TRACE_ENTRY();

	scst_inc_cmd_count();	

	if (likely(!test_bit(SCST_FLAG_SUSPENDED, &scst_flags))) {
		res = -1;
		TRACE_DBG("Finding tgt_dev for cmd %p (lun %Ld)", cmd,
		      (uint64_t)cmd->lun);
		list_for_each_entry(tgt_dev, &cmd->sess->sess_tgt_dev_list,
				    sess_tgt_dev_list_entry) 
		{
			if (tgt_dev->acg_dev->lun == cmd->lun) {
				TRACE_DBG("tgt_dev %p found", tgt_dev);

				if (unlikely(tgt_dev->acg_dev->dev->handler == NULL)) {
					PRINT_INFO_PR("Dev handler for device "
					  "%Ld is NULL, the device will not be "
					  "visible remotely", (uint64_t)cmd->lun);
					break;
				}
				
				if (cmd->state == SCST_CMD_STATE_REINIT) {
					cmd->tgt_dev_saved->cmd_count--;
					TRACE(TRACE_SCSI_SERIALIZING,
					      "SCST_CMD_STATE_REINIT: "
					      "incrementing expected_sn on tgt_dev_saved %p",
					      cmd->tgt_dev_saved);
					scst_inc_expected_sn_unblock(
						cmd->tgt_dev_saved, cmd, 1);
				}
				cmd->tgt_dev = tgt_dev;
				tgt_dev->cmd_count++;
				cmd->dev = tgt_dev->acg_dev->dev;

				res = 0;
				break;
			}
		}
		if (res != 0) {
			TRACE_DBG("tgt_dev for lun %Ld not found, command to "
				"unexisting LU?", (uint64_t)cmd->lun);
			scst_dec_cmd_count();
		}
	} else {
		if ( !cmd->sess->waiting) {
			TRACE_DBG("Adding session %p to scst_dev_wait_sess_list",
			      cmd->sess);
			list_add_tail(&cmd->sess->dev_wait_sess_list_entry,
				      &scst_dev_wait_sess_list);
			cmd->sess->waiting = 1;
		}
		scst_dec_cmd_count();
		res = 1;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_list_lock and IRQs disabled */
static int scst_process_init_cmd(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	if (unlikely(cmd->tgt_dev)) {
		scst_cmd_set_sn(cmd);
		goto out_move;
	}

	res = scst_translate_lun(cmd);
	if (likely(res == 0)) {
		cmd->state = SCST_CMD_STATE_DEV_PARSE;
		if (cmd->tgt_dev->cmd_count > SCST_MAX_DEVICE_COMMANDS)	{
			TRACE(TRACE_RETRY, "Too many pending commands in "
				"session, returning BUSY to initiator \"%s\"",
				(cmd->sess->initiator_name[0] == '\0') ?
				  "Anonymous" : cmd->sess->initiator_name);
			scst_set_busy(cmd);
			cmd->state = SCST_CMD_STATE_XMIT_RESP;
		} else if (!cmd->no_sn)
			scst_cmd_set_sn(cmd);
	} else if (res < 0) {
		TRACE_DBG("Finishing cmd %p", cmd);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		cmd->state = SCST_CMD_STATE_XMIT_RESP;
	} else
		goto out;

out_move:
	TRACE_DBG("Moving cmd %p to active cmd list", cmd);
	list_move_tail(&cmd->cmd_list_entry, &scst_active_cmd_list);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* 
 * Called under scst_list_lock and IRQs disabled
 * We don't drop it anywhere inside, because command execution
 * have to be serialized, i.e. commands must be executed in order
 * of their arrival, and we set this order inside scst_translate_lun().
 */
static int scst_do_job_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	if (likely(!test_bit(SCST_FLAG_SUSPENDED, &scst_flags))) {
		while (!list_empty(&scst_init_cmd_list)) {
			struct scst_cmd *cmd = list_entry(
				scst_init_cmd_list.next, typeof(*cmd),
							  cmd_list_entry);
			res = scst_process_init_cmd(cmd);
			if (res > 0)
				break;
			/* For DIRECT context the cmd is always the last */
		}
	} else
		res = 1;

	TRACE_EXIT_RES(res);
	return res;
}

/* Called with no locks held */
static int __scst_process_active_cmd(struct scst_cmd *cmd, int context,
	int left_locked)
{
	int res;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(in_irq());

	cmd->atomic = ((context & ~SCST_PROCESSIBLE_ENV) == 
			SCST_CONTEXT_DIRECT_ATOMIC);
	cmd->processible_env = (context & SCST_PROCESSIBLE_ENV) != 0;

	do {
		switch (cmd->state) {
		case SCST_CMD_STATE_DEV_PARSE:
			res = scst_parse_cmd(cmd);
			break;

		case SCST_CMD_STATE_PREPARE_SPACE:
			res = scst_prepare_space(cmd);
			break;

		case SCST_CMD_STATE_RDY_TO_XFER:
			res = scst_rdy_to_xfer(cmd);
			break;

		case SCST_CMD_STATE_SEND_TO_MIDLEV:
			res = scst_send_to_midlev(cmd);
			/* !! At this point cmd, sess & tgt_dev can be already freed !! */
			break;

		case SCST_CMD_STATE_DEV_DONE:
			res = scst_dev_done(cmd);
			break;

		case SCST_CMD_STATE_XMIT_RESP:
			res = scst_xmit_response(cmd);
			break;

		case SCST_CMD_STATE_FINISHED:
			res = scst_finish_cmd(cmd);
			break;

		default:
			PRINT_ERROR_PR("cmd (%p) in state %d, but shouldn't be",
			       cmd, cmd->state);
			sBUG();
			res = SCST_CMD_STATE_RES_CONT_NEXT;
			break;
		}
	} while(res == SCST_CMD_STATE_RES_CONT_SAME);

	if (res == SCST_CMD_STATE_RES_CONT_NEXT) {
		if (left_locked)
			spin_lock_irq(&scst_list_lock);
	} else if (res == SCST_CMD_STATE_RES_NEED_THREAD) {
		spin_lock_irq(&scst_list_lock);

		switch (cmd->state) {
		case SCST_CMD_STATE_DEV_PARSE:
		case SCST_CMD_STATE_PREPARE_SPACE:
		case SCST_CMD_STATE_RDY_TO_XFER:
		case SCST_CMD_STATE_SEND_TO_MIDLEV:
		case SCST_CMD_STATE_DEV_DONE:
		case SCST_CMD_STATE_XMIT_RESP:
		case SCST_CMD_STATE_FINISHED:
			TRACE_DBG("Moving cmd %p to active cmd list", cmd);
			list_move(&cmd->cmd_list_entry, &scst_active_cmd_list);
			break;
#ifdef EXTRACHECKS
		/* not very valid commands */
		case SCST_CMD_STATE_DEFAULT:
		case SCST_CMD_STATE_NEED_THREAD_CTX:
			PRINT_ERROR_PR("cmd %p is in state %d, not putting on "
				"useful list (left on scst cmd list)", cmd, 
				cmd->state);
			spin_unlock_irq(&scst_list_lock);
			sBUG();
			spin_lock_irq(&scst_list_lock);
			break;
#endif
		default:
			break;
		}
		cmd->non_atomic_only = 1;
		if (!left_locked)
			spin_unlock_irq(&scst_list_lock);
		wake_up(&scst_list_waitQ);
	} else if (res == SCST_CMD_STATE_RES_RESTART) {
		if (cmd->state == SCST_CMD_STATE_REINIT) {
			spin_lock_irq(&scst_list_lock);
			TRACE_DBG("Moving cmd %p to head of init cmd list", cmd);
			list_move(&cmd->cmd_list_entry, &scst_init_cmd_list);
			if (!left_locked)
				spin_unlock_irq(&scst_list_lock);
		} else
			sBUG();
	} else
		sBUG();

	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_list_lock and IRQs disabled */
static void scst_do_job_active(int context)
{
	int res;
	struct scst_cmd *cmd;
	int atomic = ((context & ~SCST_PROCESSIBLE_ENV) == 
			SCST_CONTEXT_DIRECT_ATOMIC);

	TRACE_ENTRY();

#ifdef EXTRACHECKS
	{
		int c = (context & ~SCST_PROCESSIBLE_ENV);
		WARN_ON((c != SCST_CONTEXT_DIRECT_ATOMIC) && 
			(c != SCST_CONTEXT_DIRECT));
	}
#endif

	tm_dbg_check_released_cmds();

restart:
	list_for_each_entry(cmd, &scst_active_cmd_list, cmd_list_entry) {
		if (atomic && cmd->non_atomic_only) {
			TRACE(TRACE_DEBUG, "Skipping non-atomic cmd %p", cmd);
			continue;
		}
		if (tm_dbg_check_cmd(cmd) != 0)
			goto restart;
		res = scst_process_active_cmd(cmd, context, NULL, 1);
		if (res == SCST_CMD_STATE_RES_CONT_NEXT) {
			goto restart;
		} else if (res == SCST_CMD_STATE_RES_NEED_THREAD) {
			goto restart;
		} else if (res == SCST_CMD_STATE_RES_RESTART) {
			break;
		} else
			sBUG();
	}

	TRACE_EXIT();
	return;
}

static inline int test_cmd_lists(void)
{
	int res = !list_empty(&scst_active_cmd_list) ||
	    (!list_empty(&scst_init_cmd_list) &&
	     !test_bit(SCST_FLAG_SUSPENDED, &scst_flags)) ||
	    unlikely(kthread_should_stop()) ||
	    tm_dbg_is_release();
	return res;
}

int scst_cmd_thread(void *arg)
{
	TRACE_ENTRY();

	set_user_nice(current, 10);
	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&scst_list_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_cmd_lists()) {
			add_wait_queue_exclusive(&scst_list_waitQ, &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_cmd_lists())
					break;
				spin_unlock_irq(&scst_list_lock);
				schedule();
				spin_lock_irq(&scst_list_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&scst_list_waitQ, &wait);
		}

		scst_do_job_init();
		scst_do_job_active(SCST_CONTEXT_DIRECT|SCST_PROCESSIBLE_ENV);
	}
	spin_unlock_irq(&scst_list_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be either
	 * on the module unload, or there must be at least one other thread to
	 * process the commands lists.
	 */
	sBUG_ON((scst_threads_info.nr_cmd_threads == 1) &&
			(!list_empty(&scst_cmd_list) ||
			 !list_empty(&scst_active_cmd_list) ||
			 !list_empty(&scst_init_cmd_list)));

	TRACE_EXIT();
	return 0;
}

void scst_cmd_tasklet(long p)
{
	TRACE_ENTRY();

	spin_lock_irq(&scst_list_lock);

	scst_do_job_init();
	scst_do_job_active(SCST_CONTEXT_DIRECT_ATOMIC|SCST_PROCESSIBLE_ENV);

	spin_unlock_irq(&scst_list_lock);

	TRACE_EXIT();
	return;
}

/*
 * Returns 0 on success, < 0 if there is no device handler or
 * > 0 if SCST_FLAG_SUSPENDED set.
 */
static int scst_mgmt_translate_lun(struct scst_mgmt_cmd *mcmd)
{
	struct scst_tgt_dev *tgt_dev = NULL;
	int res = -1;

	TRACE_ENTRY();

	TRACE_DBG("Finding tgt_dev for mgmt cmd %p (lun %Ld)", mcmd,
	      (uint64_t)mcmd->lun);

	spin_lock_irq(&scst_list_lock);
	scst_inc_cmd_count();	
	if (likely(!test_bit(SCST_FLAG_SUSPENDED, &scst_flags))) {
		list_for_each_entry(tgt_dev, &mcmd->sess->sess_tgt_dev_list,
				    sess_tgt_dev_list_entry) 
		{
			if (tgt_dev->acg_dev->lun == mcmd->lun) {
				TRACE_DBG("tgt_dev %p found", tgt_dev);
				mcmd->mcmd_tgt_dev = tgt_dev;
				res = 0;
				break;
			}
		}
		if (mcmd->mcmd_tgt_dev == NULL)
			scst_dec_cmd_count();
	} else {
		if ( !mcmd->sess->waiting) {
			TRACE_DBG("Adding session %p to scst_dev_wait_sess_list",
			      mcmd->sess);
			list_add_tail(&mcmd->sess->dev_wait_sess_list_entry,
				      &scst_dev_wait_sess_list);
			mcmd->sess->waiting = 1;
		}
		scst_dec_cmd_count();
		res = 1;
	}
	spin_unlock_irq(&scst_list_lock);

	TRACE_EXIT_HRES(res);
	return res;
}

/* Called under scst_list_lock and IRQ off */
static void scst_complete_cmd_mgmt(struct scst_cmd *cmd,
	struct scst_mgmt_cmd *mcmd)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("cmd %p completed (tag %d, mcmd %p, "
		"mcmd->cmd_wait_count %d)", cmd, cmd->tag, mcmd,
		mcmd->cmd_wait_count);

	cmd->mgmt_cmnd = NULL;

	if (cmd->completed)
		mcmd->completed_cmd_count++;

	mcmd->cmd_wait_count--;
	if (mcmd->cmd_wait_count > 0) {
		TRACE_MGMT_DBG("cmd_wait_count(%d) not 0, skipping",
			mcmd->cmd_wait_count);
		goto out;
	}

	mcmd->state = SCST_MGMT_CMD_STATE_DONE;

	if (mcmd->completed) {
		TRACE_MGMT_DBG("Moving mgmt cmd %p to active mgmt cmd list",
			mcmd);
		list_move_tail(&mcmd->mgmt_cmd_list_entry,
			&scst_active_mgmt_cmd_list);
	}

	wake_up(&scst_mgmt_cmd_list_waitQ);

out:
	TRACE_EXIT();
	return;
}

static int scst_call_dev_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev, int set_status)
{
	int res = SCST_DEV_TM_NOT_COMPLETED;
	if (tgt_dev->acg_dev->dev->handler->task_mgmt_fn) {
		int irq = irqs_disabled();
		TRACE_MGMT_DBG("Calling dev handler %s task_mgmt_fn(fn=%d)",
			tgt_dev->acg_dev->dev->handler->name, mcmd->fn);
		EXTRACHECKS_BUG_ON(in_irq());
		if (!irq)
			local_bh_disable();
		res = tgt_dev->acg_dev->dev->handler->task_mgmt_fn(mcmd, 
			tgt_dev);
		if (!irq)
			local_bh_enable();
		TRACE_MGMT_DBG("Dev handler %s task_mgmt_fn() returned %d",
		      tgt_dev->acg_dev->dev->handler->name, res);
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
 * Called under scst_list_lock and IRQ off (to protect cmd
 * from being destroyed) + BHs also off
 * Returns -1 if command is being executed (ABORT failed), 0 otherwise
 */
void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	int other_ini, int call_dev_task_mgmt_fn)
{
	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Aborting cmd %p (tag %d)", cmd, cmd->tag);

	if (other_ini) {
		set_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
		smp_mb__after_set_bit();
	}
	set_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
	smp_mb__after_set_bit();

	if (call_dev_task_mgmt_fn && cmd->tgt_dev)
		scst_call_dev_task_mgmt_fn(mcmd, cmd->tgt_dev, 1);

	if (mcmd) {
		int defer;
		if (cmd->tgtt->tm_sync_reply)
			defer = 1;
		else {
			if (scst_is_strict_mgmt_fn(mcmd->fn))
				defer = test_bit(SCST_CMD_EXECUTING,
					&cmd->cmd_flags);
			else
				defer = test_bit(SCST_CMD_XMITTING,
					&cmd->cmd_flags);
		}

		if (defer) {
			/*
			 * Delay the response until the command's finish in
			 * order to guarantee that "no further responses from
			 * the task are sent to the SCSI initiator port" after
			 * response from the TM function is sent (SAM)
			 */
			TRACE(TRACE_MGMT, "cmd %p (tag %d) being executed/"
				"xmitted (state %d), deferring ABORT...", cmd,
				cmd->tag, cmd->state);
#ifdef EXTRACHECKS
			if (cmd->mgmt_cmnd) {
				printk(KERN_ALERT "cmd %p (tag %d, state %d) "
					"has non-NULL mgmt_cmnd %p!!! Current "
					"mcmd %p\n", cmd, cmd->tag, cmd->state,
					cmd->mgmt_cmnd, mcmd);
			}
#endif
			sBUG_ON(cmd->mgmt_cmnd);
			mcmd->cmd_wait_count++;
			cmd->mgmt_cmnd = mcmd;
		}
	}

	tm_dbg_release_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* Called under scst_list_lock and IRQ off */
static int scst_set_mcmd_next_state(struct scst_mgmt_cmd *mcmd)
{
	int res;
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
	return res;
}

static void scst_unblock_aborted_cmds(int scst_mutex_held)
{
	struct scst_device *dev;
	int wake = 0;

	TRACE_ENTRY();

	if (!scst_mutex_held)
		down(&scst_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		struct scst_cmd *cmd, *tcmd;
		spin_lock_bh(&dev->dev_lock);
		list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
					blocked_cmd_list_entry) {
			if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
				list_del(&cmd->blocked_cmd_list_entry);
				TRACE_MGMT_DBG("Moving aborted blocked cmd %p "
					"to active cmd list", cmd);
				spin_lock_irq(&scst_list_lock);
				list_move_tail(&cmd->cmd_list_entry,
					&scst_active_cmd_list);
				spin_unlock_irq(&scst_list_lock);
				wake = 1;
			}
		}
		spin_unlock_bh(&dev->dev_lock);
	}

	if (!scst_mutex_held)
		up(&scst_mutex);

	if (wake)
		wake_up(&scst_list_waitQ);

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

	local_bh_disable();
	spin_lock_irq(&scst_list_lock);

	TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
 	list_for_each_entry(cmd, &sess->search_cmd_list, 
 			search_cmd_list_entry) {
		if ((cmd->tgt_dev == NULL) && 
		    (cmd->lun == tgt_dev->acg_dev->lun))
		    	continue;
		if (cmd->tgt_dev != tgt_dev)
			continue;
		scst_abort_cmd(cmd, mcmd, other_ini, 0);
	}
	spin_unlock_irq(&scst_list_lock);
	local_bh_enable();

	scst_unblock_aborted_cmds(scst_mutex_held);

	TRACE_EXIT();
	return;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_task_set(struct scst_mgmt_cmd *mcmd)
{
	int res;
	struct scst_tgt_dev *tgt_dev = mcmd->mcmd_tgt_dev;
	struct scst_device *dev = tgt_dev->acg_dev->dev;

	TRACE(TRACE_MGMT, "Aborting task set (lun=%d, mcmd=%p)",
		tgt_dev->acg_dev->lun, mcmd);

	spin_lock_bh(&dev->dev_lock);
	__scst_block_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	__scst_abort_task_set(mcmd, tgt_dev, 0, 0);
	scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_check_delay_mgmt_cmd(struct scst_mgmt_cmd *mcmd, int locked)
{
	/*
	 * No need for special protection for SCST_FLAG_TM_ACTIVE, since
	 * we could be called from the only thread.
	 */
	if (test_bit(SCST_FLAG_TM_ACTIVE, &scst_flags)) {
		TRACE_MGMT_DBG("Moving mgmt cmd %p to delayed mgmt cmd list",
			mcmd);
		if (!locked)
			spin_lock_irq(&scst_list_lock);
		list_move_tail(&mcmd->mgmt_cmd_list_entry, 
			&scst_delayed_mgmt_cmd_list);
		if (!locked)
			spin_unlock_irq(&scst_list_lock);
		return -1;
	} else {
		set_bit(SCST_FLAG_TM_ACTIVE, &scst_flags);
		return 0;
	}
}

/* Returns 0 if the command processing should be continued, 
 * >0, if it should be requeued, <0 otherwise */
static int scst_mgmt_cmd_init(struct scst_mgmt_cmd *mcmd)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_check_delay_mgmt_cmd(mcmd, 1);
	if (res != 0)
		goto out;

	if (mcmd->fn == SCST_ABORT_TASK) {
		struct scst_session *sess = mcmd->sess;
		struct scst_cmd *cmd;

		local_bh_disable();
		spin_lock_irq(&scst_list_lock);
		cmd = __scst_find_cmd_by_tag(sess, mcmd->tag);
		if (cmd == NULL) {
			TRACE(TRACE_MGMT, "ABORT TASK failed: command for "
				"tag %d not found", mcmd->tag);
			mcmd->status = SCST_MGMT_STATUS_TASK_NOT_EXIST;
			mcmd->state = SCST_MGMT_CMD_STATE_DONE;
		} else {
			TRACE(TRACE_MGMT, "Cmd %p for tag %d (sn %d) found, "
				"aborting it", cmd, mcmd->tag, cmd->sn);
			mcmd->cmd_to_abort = cmd;
			scst_abort_cmd(cmd, mcmd, 0, 1);
			res = scst_set_mcmd_next_state(mcmd);
			mcmd->cmd_to_abort = NULL; /* just in case */
		}
		spin_unlock_irq(&scst_list_lock);
		local_bh_enable();
	} else {
		int rc;
		rc = scst_mgmt_translate_lun(mcmd);
		if (rc < 0) {
			PRINT_ERROR_PR("Corresponding device for lun %Ld not "
				"found", (uint64_t)mcmd->lun);
			mcmd->status = SCST_MGMT_STATUS_LUN_NOT_EXIST;
			mcmd->state = SCST_MGMT_CMD_STATE_DONE;
		} else if (rc == 0)
			mcmd->state = SCST_MGMT_CMD_STATE_READY;
		else
			res = rc;
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
		mcmd, mcmd->sess->sess_cmd_count);

	down(&scst_mutex);

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

	up(&scst_mutex);

	spin_lock_irq(&scst_list_lock);
	tm_dbg_task_mgmt("TARGET RESET");
	res = scst_set_mcmd_next_state(mcmd);
	spin_unlock_irq(&scst_list_lock);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_lun_reset(struct scst_mgmt_cmd *mcmd)
{
	int res, rc;
	struct scst_tgt_dev *tgt_dev = mcmd->mcmd_tgt_dev;
	struct scst_device *dev = tgt_dev->acg_dev->dev;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Resetting lun %d (mcmd %p)", tgt_dev->acg_dev->lun,
		mcmd);

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
	spin_lock_irq(&scst_list_lock);
	tm_dbg_task_mgmt("LUN RESET");
	res = scst_set_mcmd_next_state(mcmd);
	spin_unlock_irq(&scst_list_lock);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_all_nexus_loss_sess(struct scst_mgmt_cmd *mcmd,
	int nexus_loss)
{
	int res;
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

	down(&scst_mutex);
	list_for_each_entry(tgt_dev, &sess->sess_tgt_dev_list,
		sess_tgt_dev_list_entry) 
	{
		struct scst_device *dev = tgt_dev->acg_dev->dev;
		int rc;

		spin_lock_bh(&dev->dev_lock);
		__scst_block_dev(dev);
		spin_unlock_bh(&dev->dev_lock);

		rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);
		if ((rc < 0) && (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
			mcmd->status = rc;

		__scst_abort_task_set(mcmd, tgt_dev, !nexus_loss, 1);
		if (nexus_loss)
			scst_reset_tgt_dev(tgt_dev, 1);
	}
	up(&scst_mutex);

	spin_lock_irq(&scst_list_lock);
	res = scst_set_mcmd_next_state(mcmd);
	spin_unlock_irq(&scst_list_lock);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_all_nexus_loss_tgt(struct scst_mgmt_cmd *mcmd,
	int nexus_loss)
{
	int res;
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

	down(&scst_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		spin_lock_bh(&dev->dev_lock);
		__scst_block_dev(dev);
		spin_unlock_bh(&dev->dev_lock);
	}

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		list_for_each_entry(tgt_dev, &sess->sess_tgt_dev_list,
			sess_tgt_dev_list_entry) 
		{
			int rc;

			rc = scst_call_dev_task_mgmt_fn(mcmd, tgt_dev, 0);
			if ((rc < 0) &&
			    (mcmd->status == SCST_MGMT_STATUS_SUCCESS))
				mcmd->status = rc;

			__scst_abort_task_set(mcmd, tgt_dev, !nexus_loss, 1);
			if (nexus_loss)
				scst_reset_tgt_dev(tgt_dev, 1);
		}
	}

	up(&scst_mutex);

	spin_lock_irq(&scst_list_lock);
	res = scst_set_mcmd_next_state(mcmd);
	spin_unlock_irq(&scst_list_lock);

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
		break;

	default:
		PRINT_ERROR_PR("Unknown task management function %d", mcmd->fn);
		mcmd->status = SCST_MGMT_STATUS_REJECTED;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_mgmt_cmd_send_done(struct scst_mgmt_cmd *mcmd)
{
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	clear_bit(SCST_FLAG_TM_ACTIVE, &scst_flags);
	if (!list_empty(&scst_delayed_mgmt_cmd_list)) {
		struct scst_mgmt_cmd *m;
		spin_lock_irq(&scst_list_lock);
		m = list_entry(scst_delayed_mgmt_cmd_list.next, typeof(*m),
				mgmt_cmd_list_entry);
		TRACE_MGMT_DBG("Moving delayed mgmt cmd %p to active mgmt "
			"cmd list", m);
		list_move(&m->mgmt_cmd_list_entry, &scst_active_mgmt_cmd_list);
		spin_unlock_irq(&scst_list_lock);
	}

	mcmd->state = SCST_MGMT_CMD_STATE_FINISHED;
	if (scst_is_strict_mgmt_fn(mcmd->fn) && (mcmd->completed_cmd_count > 0))
		mcmd->status = SCST_MGMT_STATUS_TASK_NOT_EXIST;

	if (mcmd->sess->tgt->tgtt->task_mgmt_fn_done) {
		TRACE_DBG("Calling target %s task_mgmt_fn_done()",
		      mcmd->sess->tgt->tgtt->name);
		mcmd->sess->tgt->tgtt->task_mgmt_fn_done(mcmd);
		TRACE_MGMT_DBG("Dev handler %s task_mgmt_fn_done() returned",
		      mcmd->sess->tgt->tgtt->name);
	}

	switch (mcmd->fn) {
	case SCST_ABORT_TASK_SET:
	case SCST_CLEAR_TASK_SET:
	case SCST_LUN_RESET:
		scst_unblock_dev(mcmd->mcmd_tgt_dev->acg_dev->dev);
		break;

	case SCST_TARGET_RESET:
	case SCST_ABORT_ALL_TASKS:
	case SCST_NEXUS_LOSS:
		down(&scst_mutex);
		list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
			scst_unblock_dev(dev);
		}
		up(&scst_mutex);
		break;

	case SCST_NEXUS_LOSS_SESS:
	case SCST_ABORT_ALL_TASKS_SESS:
		down(&scst_mutex);
		list_for_each_entry(tgt_dev, &mcmd->sess->sess_tgt_dev_list,
				sess_tgt_dev_list_entry) {
			scst_unblock_dev(tgt_dev->acg_dev->dev);
		}
		up(&scst_mutex);
		break;

	case SCST_CLEAR_ACA:
	default:
		break;
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

		case SCST_MGMT_CMD_STATE_FINISHED:
			goto out_free;

#ifdef EXTRACHECKS
		case SCST_MGMT_CMD_STATE_EXECUTING:
			sBUG();
#endif

		default:
			PRINT_ERROR_PR("Unknown state %d of management command",
				    mcmd->state);
			res = -1;
			goto out_free;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	scst_free_mgmt_cmd(mcmd, 1);
	goto out;
}

static inline int test_mgmt_cmd_list(void)
{
	int res = (!list_empty(&scst_active_mgmt_cmd_list) &&
		   !test_bit(SCST_FLAG_SUSPENDED, &scst_flags)) ||
		  unlikely(kthread_should_stop());
	return res;
}

int scst_mgmt_cmd_thread(void *arg)
{
	struct scst_mgmt_cmd *mcmd;

	TRACE_ENTRY();

	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&scst_list_lock);
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
				spin_unlock_irq(&scst_list_lock);
				schedule();
				spin_lock_irq(&scst_list_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&scst_mgmt_cmd_list_waitQ, &wait);
		}

		while (!list_empty(&scst_active_mgmt_cmd_list) &&
		       !test_bit(SCST_FLAG_SUSPENDED, &scst_flags))
		{
			int rc;
			mcmd = list_entry(scst_active_mgmt_cmd_list.next,
					  typeof(*mcmd), mgmt_cmd_list_entry);
			TRACE_MGMT_DBG("Moving mgmt cmd %p to mgmt cmd list",
			      mcmd);
			list_move_tail(&mcmd->mgmt_cmd_list_entry,
				       &scst_mgmt_cmd_list);
			spin_unlock_irq(&scst_list_lock);
			rc = scst_process_mgmt_cmd(mcmd);
			spin_lock_irq(&scst_list_lock);
			if (rc > 0) {
				TRACE_MGMT_DBG("Moving mgmt cmd %p to head "
					"of active mgmt cmd list", mcmd);
				list_move(&mcmd->mgmt_cmd_list_entry,
				       &scst_active_mgmt_cmd_list);
			}
		}
	}
	spin_unlock_irq(&scst_list_lock);

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
		PRINT_ERROR_PR("New mgmt cmd, but task_mgmt_fn_done() is NULL "
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

	spin_lock_irqsave(&scst_list_lock, flags);

	sess->sess_cmd_count++;

#ifdef EXTRACHECKS
	if (unlikely(sess->shutting_down)) {
		PRINT_ERROR_PR("%s",
			"New mgmt cmd while shutting down the session");
		sBUG();
	}
#endif

	if (unlikely(sess->init_phase != SCST_SESS_IPH_READY)) {
		switch(sess->init_phase) {
		case SCST_SESS_IPH_INITING:
			TRACE_DBG("Moving mcmd %p to init deferred mcmd list",
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

	TRACE_MGMT_DBG("Adding mgmt cmd %p to active mgmt cmd list", mcmd);
	list_add_tail(&mcmd->mgmt_cmd_list_entry, &scst_active_mgmt_cmd_list);

	spin_unlock_irqrestore(&scst_list_lock, flags);

	wake_up(&scst_mgmt_cmd_list_waitQ);

out:
	TRACE_EXIT();
	return res;

out_unlock:
	spin_unlock_irqrestore(&scst_list_lock, flags);
	goto out;
}

/* 
 * Must not been called in parallel with scst_unregister_session() for the 
 * same sess
 */
int scst_rx_mgmt_fn_lun(struct scst_session *sess, int fn,
			const uint8_t *lun, int lun_len, int atomic,
			void *tgt_priv)
{
	int res = -EFAULT;
	struct scst_mgmt_cmd *mcmd = NULL;

	TRACE_ENTRY();

	if (unlikely(fn == SCST_ABORT_TASK)) {
		PRINT_ERROR_PR("%s() for ABORT TASK called", __FUNCTION__);
		res = -EINVAL;
		goto out;
	}

	mcmd = scst_pre_rx_mgmt_cmd(sess, fn, atomic, tgt_priv);
	if (mcmd == NULL)
		goto out;

	mcmd->lun = scst_unpack_lun(lun, lun_len);
	if (mcmd->lun == (lun_t)-1)
		goto out_free;

	TRACE(TRACE_MGMT, "sess=%p, lun=%Ld", sess, (uint64_t)mcmd->lun);

	if (scst_post_rx_mgmt_cmd(sess, mcmd) != 0)
		goto out_free;

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	scst_free_mgmt_cmd(mcmd, 0);
	mcmd = NULL;
	goto out;
}

/* 
 * Must not been called in parallel with scst_unregister_session() for the 
 * same sess
 */
int scst_rx_mgmt_fn_tag(struct scst_session *sess, int fn, uint32_t tag,
		       int atomic, void *tgt_priv)
{
	int res = -EFAULT;
	struct scst_mgmt_cmd *mcmd = NULL;

	TRACE_ENTRY();

	if (unlikely(fn != SCST_ABORT_TASK)) {
		PRINT_ERROR_PR("%s(%d) called", __FUNCTION__, fn);
		res = -EINVAL;
		goto out;
	}

	mcmd = scst_pre_rx_mgmt_cmd(sess, fn, atomic, tgt_priv);
	if (mcmd == NULL)
		goto out;

	mcmd->tag = tag;

	TRACE(TRACE_MGMT, "sess=%p, tag=%d", sess, mcmd->tag);

	if (scst_post_rx_mgmt_cmd(sess, mcmd) != 0)
		goto out_free;

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	scst_free_mgmt_cmd(mcmd, 0);
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

static int scst_init_session(struct scst_session *sess)
{
	int res = 0;
	struct scst_acg *acg;
	struct scst_cmd *cmd;
	struct scst_mgmt_cmd *mcmd, *tm;
	int mwake = 0;

	TRACE_ENTRY();
	
	down(&scst_mutex);

	if (sess->initiator_name) {
		acg = scst_find_acg(sess->initiator_name);
		if (acg == NULL) {
			PRINT_INFO_PR("Name %s not found, using default group",
				sess->initiator_name);
			acg = scst_default_acg;
		}
	}
	else
		acg = scst_default_acg;

	sess->acg = acg;
	TRACE_DBG("Assigning session %p to acg %s", sess, acg->acg_name);
	list_add_tail(&sess->acg_sess_list_entry, &acg->acg_sess_list);

	TRACE_DBG("Adding sess %p to tgt->sess_list", sess);
	list_add_tail(&sess->sess_list_entry, &sess->tgt->sess_list);

	res = scst_sess_alloc_tgt_devs(sess);

	up(&scst_mutex);
	
	if (sess->init_result_fn) {
		TRACE_DBG("Calling init_result_fn(%p)", sess);
		sess->init_result_fn(sess, sess->reg_sess_data, res);
		TRACE_DBG("%s", "init_result_fn() returned");
	}

	spin_lock_irq(&scst_list_lock);

	if (res == 0)
		sess->init_phase = SCST_SESS_IPH_SUCCESS;
	else
		sess->init_phase = SCST_SESS_IPH_FAILED;

restart:
	list_for_each_entry(cmd, &sess->init_deferred_cmd_list,
				cmd_list_entry)
	{
		TRACE_DBG("Deleting cmd %p from init deferred cmd list", cmd);
		list_del(&cmd->cmd_list_entry);
		sess->sess_cmd_count--;
		list_del(&cmd->search_cmd_list_entry);
		spin_unlock_irq(&scst_list_lock);
		scst_cmd_init_done(cmd, SCST_CONTEXT_THREAD);
		spin_lock_irq(&scst_list_lock);
		goto restart;
	}

	list_for_each_entry_safe(mcmd, tm, &sess->init_deferred_mcmd_list,
				mgmt_cmd_list_entry)
	{
		TRACE_DBG("Moving mgmt command %p from init deferred mcmd list",
			mcmd);
		list_move_tail(&mcmd->mgmt_cmd_list_entry,
			&scst_active_mgmt_cmd_list);
		mwake = 1;
	}
	sess->init_phase = SCST_SESS_IPH_READY;
	spin_unlock_irq(&scst_list_lock);

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
		TRACE_DBG("Adding sess %p to scst_sess_mgmt_list", sess);
		list_add_tail(&sess->sess_mgmt_list_entry,
			      &scst_sess_mgmt_list);
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
 * Must not been called in parallel with scst_rx_cmd() or 
 * scst_rx_mgmt_fn_*() for the same sess
 */
void scst_unregister_session(struct scst_session *sess, int wait,
	void (*unreg_done_fn) (struct scst_session *sess))
{
	unsigned long flags;
	DECLARE_COMPLETION(c);

	TRACE_ENTRY();

	spin_lock_irqsave(&scst_mgmt_lock, flags);

	sess->shutting_down = 1;
	sess->unreg_done_fn = unreg_done_fn;
	if (wait) {
		sess->shutdown_compl = &c;
		smp_mb();
	}

	spin_unlock_irqrestore(&scst_mgmt_lock, flags);

	scst_sess_put(sess);

	if (wait) {
		TRACE_DBG("Waiting for session %p to complete", sess);
		wait_for_completion(&c);
	}

	TRACE_EXIT();
	return;
}

static inline int test_mgmt_list(void)
{
	int res = !list_empty(&scst_sess_mgmt_list) ||
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

restart:
		list_for_each_entry(sess, &scst_sess_mgmt_list,
			sess_mgmt_list_entry)
		{
			TRACE_DBG("Removing sess %p from scst_sess_mgmt_list",
				sess);
			list_del(&sess->sess_mgmt_list_entry);
			spin_unlock_irq(&scst_mgmt_lock);
			if (sess->init_phase == SCST_SESS_IPH_INITING) {
				scst_init_session(sess);
			} else if (sess->shutting_down) {
				sBUG_ON(atomic_read(&sess->refcnt) != 0);
				scst_free_session_callback(sess);
			} else {
				PRINT_ERROR_PR("session %p is in "
					"scst_sess_mgmt_list, but in unknown "
					"phase %x", sess, sess->init_phase);
				sBUG();
			}
			spin_lock_irq(&scst_mgmt_lock);
			goto restart;
		}
	}
	spin_unlock_irq(&scst_mgmt_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so scst_sess_mgmt_list must be empty.
	 */
	sBUG_ON(!list_empty(&scst_sess_mgmt_list));

	TRACE_EXIT();
	return 0;
}

/* Called under scst_list_lock */
struct scst_cmd *__scst_find_cmd_by_tag(struct scst_session *sess, uint32_t tag)
{
	struct scst_cmd *cmd = NULL;

	TRACE_ENTRY();

	/* ToDo: hash list */

	TRACE_DBG("%s (sess=%p, tag=%d)", "Searching in search cmd list",
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

	spin_lock_irqsave(&scst_list_lock, flags);

	TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
	list_for_each_entry(cmd, &sess->search_cmd_list, 
			search_cmd_list_entry) {
		if (cmp_fn(cmd, data))
			goto out_unlock;
	}

	cmd = NULL;

out_unlock:
	spin_unlock_irqrestore(&scst_list_lock, flags);

out:
	TRACE_EXIT();
	return cmd;
}

struct scst_cmd *scst_find_cmd_by_tag(struct scst_session *sess,
	uint32_t tag)
{
	unsigned long flags;
	struct scst_cmd *cmd;
	spin_lock_irqsave(&scst_list_lock, flags);
	cmd = __scst_find_cmd_by_tag(sess, tag);
	spin_unlock_irqrestore(&scst_list_lock, flags);
	return cmd;
}

void *scst_cmd_get_tgt_priv_lock(struct scst_cmd *cmd)
{
	void *res;
	unsigned long flags;
	spin_lock_irqsave(&scst_list_lock, flags);
	res = cmd->tgt_priv;
	spin_unlock_irqrestore(&scst_list_lock, flags);
	return res;
}

void scst_cmd_set_tgt_priv_lock(struct scst_cmd *cmd, void *val)
{
	unsigned long flags;
	spin_lock_irqsave(&scst_list_lock, flags);
	cmd->tgt_priv = val;
	spin_unlock_irqrestore(&scst_list_lock, flags);
}
