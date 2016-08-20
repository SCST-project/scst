/*
 *  scst_targ.c
 *
 *  Copyright (C) 2004 - 2016 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2016 SanDisk Corporation
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
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/vmalloc.h>
#include <scsi/sg.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_priv.h"
#include "scst_pres.h"

static void scst_cmd_set_sn(struct scst_cmd *cmd);
static int __scst_init_cmd(struct scst_cmd *cmd);
static struct scst_cmd *__scst_find_cmd_by_tag(struct scst_session *sess,
	uint64_t tag, bool to_abort);
static void scst_process_redirect_cmd(struct scst_cmd *cmd,
	enum scst_exec_context context, int check_retries);

/**
 * scst_post_parse() - do post parse actions
 *
 * This function must be called by dev handler after its parse() callback
 * returned SCST_CMD_STATE_STOP before calling scst_process_active_cmd().
 */
void scst_post_parse(struct scst_cmd *cmd)
{
	scst_set_parse_time(cmd);
}
EXPORT_SYMBOL_GPL(scst_post_parse);

/**
 * scst_post_alloc_data_buf() - do post dev_alloc_data_buf actions
 *
 * This function must be called by dev handler after its dev_alloc_data_buf()
 * callback returned SCST_CMD_STATE_STOP before calling
 * scst_process_active_cmd().
 */
void scst_post_alloc_data_buf(struct scst_cmd *cmd)
{
	scst_set_alloc_buf_time(cmd);
}
EXPORT_SYMBOL_GPL(scst_post_alloc_data_buf);

static inline void scst_schedule_tasklet(struct scst_cmd *cmd)
{
	struct scst_percpu_info *i;
	unsigned long flags;

	preempt_disable();

	i = &scst_percpu_infos[smp_processor_id()];

	if (atomic_read(&i->cpu_cmd_count) <= scst_max_tasklet_cmd) {
		spin_lock_irqsave(&i->tasklet_lock, flags);
		TRACE_DBG("Adding cmd %p to tasklet %d cmd list", cmd,
			smp_processor_id());
		list_add_tail(&cmd->cmd_list_entry, &i->tasklet_cmd_list);
		spin_unlock_irqrestore(&i->tasklet_lock, flags);

		tasklet_schedule(&i->tasklet);
	} else {
		spin_lock_irqsave(&cmd->cmd_threads->cmd_list_lock, flags);
		TRACE_DBG("Too many tasklet commands (%d), adding cmd %p to "
			"active cmd list", atomic_read(&i->cpu_cmd_count), cmd);
		list_add_tail(&cmd->cmd_list_entry,
			&cmd->cmd_threads->active_cmd_list);
		wake_up(&cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock_irqrestore(&cmd->cmd_threads->cmd_list_lock, flags);
	}

	preempt_enable();
	return;
}

static bool scst_unmap_overlap(struct scst_cmd *cmd, int64_t lba2,
	int64_t lba2_blocks)
{
	bool res = false;
	struct scst_data_descriptor *pd = cmd->cmd_data_descriptors;
	int i;

	TRACE_ENTRY();

	if (pd == NULL)
		goto out;

	for (i = 0; pd[i].sdd_blocks != 0; i++) {
		struct scst_data_descriptor *d = &pd[i];

		TRACE_DBG("i %d, lba %lld, blocks %lld", i,
			(long long)d->sdd_lba, (long long)d->sdd_blocks);
		res = scst_lba1_inside_lba2(d->sdd_lba, lba2, lba2_blocks);
		if (res)
			goto out;
		res = scst_lba1_inside_lba2(lba2, d->sdd_lba, d->sdd_blocks);
		if (res)
			goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static bool scst_cmd_overlap_cwr(struct scst_cmd *cwr_cmd, struct scst_cmd *cmd)
{
	bool res;

	TRACE_ENTRY();

	TRACE_DBG("cwr_cmd %p, cmd %p (op %s, LBA valid %d, lba %lld, "
		"len %lld)", cwr_cmd, cmd, scst_get_opcode_name(cmd),
		(cmd->op_flags & SCST_LBA_NOT_VALID) == 0,
		(long long)cmd->lba, (long long)cmd->data_len);

	EXTRACHECKS_BUG_ON(cwr_cmd->cdb[0] != COMPARE_AND_WRITE);

	/*
	 * In addition to requirements listed in "Model for uninterrupted
	 * sequences on LBA ranges" (SBC) VMware wants that COMPARE AND WRITE
	 * be atomic against RESERVEs, as well as RESERVEs be atomic against
	 * all COMPARE AND WRITE commands and only against them.
	 */

	if (cmd->op_flags & SCST_LBA_NOT_VALID) {
		switch (cmd->cdb[0]) {
		case RESERVE:
		case RESERVE_10:
			res = true;
			break;
		case UNMAP:
			res = scst_unmap_overlap(cmd, cwr_cmd->lba,
				cwr_cmd->data_len);
			break;
		case EXTENDED_COPY:
			res = scst_cm_ec_cmd_overlap(cmd, cwr_cmd);
			break;
		default:
			res = false;
			break;
		}
		goto out;
	}

	/* If LBA valid, block_shift must be valid */
	EXTRACHECKS_BUG_ON(cmd->dev->block_shift <= 0);

	res = scst_lba1_inside_lba2(cwr_cmd->lba, cmd->lba,
		cmd->data_len >> cmd->dev->block_shift);
	if (res)
		goto out;

	res = scst_lba1_inside_lba2(cmd->lba, cwr_cmd->lba,
		cwr_cmd->data_len >> cwr_cmd->dev->block_shift);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static bool scst_cmd_overlap_reserve(struct scst_cmd *reserve_cmd,
	struct scst_cmd *cmd)
{
	bool res;

	TRACE_ENTRY();

	TRACE_DBG("reserve_cmd %p, cmd %p (op %s, LBA valid %d, lba %lld, "
		"len %lld)", reserve_cmd, cmd, scst_get_opcode_name(cmd),
		(cmd->op_flags & SCST_LBA_NOT_VALID) == 0,
		(long long)cmd->lba, (long long)cmd->data_len);

	EXTRACHECKS_BUG_ON((reserve_cmd->cdb[0] != RESERVE) &&
			   (reserve_cmd->cdb[0] != RESERVE_10));

	/*
	 * In addition to requirements listed in "Model for uninterrupted
	 * sequences on LBA ranges" (SBC) VMware wants that COMPARE AND WRITE
	 * be atomic against RESERVEs, as well as RESERVEs be atomic against
	 * all COMPARE AND WRITE commands and only against them.
	 */

	if (cmd->cdb[0] == COMPARE_AND_WRITE)
		res = true;
	else
		res = false;

	TRACE_EXIT_RES(res);
	return res;
}

static bool scst_cmd_overlap_atomic(struct scst_cmd *atomic_cmd, struct scst_cmd *cmd)
{
	bool res;

	TRACE_ENTRY();

	TRACE_DBG("atomic_cmd %p (op %s), cmd %p (op %s)", atomic_cmd,
		scst_get_opcode_name(atomic_cmd), cmd, scst_get_opcode_name(cmd));

	EXTRACHECKS_BUG_ON((atomic_cmd->op_flags & SCST_SCSI_ATOMIC) == 0);

	switch (atomic_cmd->cdb[0]) {
	case COMPARE_AND_WRITE:
		res = scst_cmd_overlap_cwr(atomic_cmd, cmd);
		break;
	case RESERVE:
	case RESERVE_10:
		res = scst_cmd_overlap_reserve(atomic_cmd, cmd);
		break;
	default:
		res = false;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static bool scst_cmd_overlap(struct scst_cmd *chk_cmd, struct scst_cmd *cmd)
{
	bool res = false;

	TRACE_ENTRY();

	TRACE_DBG("chk_cmd %p, cmd %p", chk_cmd, cmd);

	if ((chk_cmd->op_flags & SCST_SCSI_ATOMIC) != 0)
		res = scst_cmd_overlap_atomic(chk_cmd, cmd);
	else if ((cmd->op_flags & SCST_SCSI_ATOMIC) != 0)
		res = scst_cmd_overlap_atomic(cmd, chk_cmd);
	else
		res = false;

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * dev_lock supposed to be held and BH disabled. Returns true if cmd blocked,
 * hence stop processing it and go to the next command.
 */
static bool scst_check_scsi_atomicity(struct scst_cmd *chk_cmd)
{
	bool res = false;
	struct scst_device *dev = chk_cmd->dev;
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	/*
	 * chk_cmd isn't necessary SCSI atomic! For instance, if another SCSI
	 * atomic cmd is waiting blocked.
	 */

	TRACE_DBG("chk_cmd %p (op %s, internal %d, lba %lld, len %lld)",
		chk_cmd, scst_get_opcode_name(chk_cmd), chk_cmd->internal,
		(long long)chk_cmd->lba, (long long)chk_cmd->data_len);

	list_for_each_entry(cmd, &dev->dev_exec_cmd_list, dev_exec_cmd_list_entry) {
		if (chk_cmd == cmd)
			continue;
		if (scst_cmd_overlap(chk_cmd, cmd)) {
			struct scst_cmd **p = cmd->scsi_atomic_blocked_cmds;

			/*
			 * kmalloc() allocates by at least 32 bytes increments,
			 * hence krealloc() on 8 bytes increments, if not all
			 * that space is used, does nothing.
			 */
			p = krealloc(p, sizeof(*p) * (cmd->scsi_atomic_blocked_cmds_count + 1),
				GFP_ATOMIC);
			if (p == NULL)
				goto out_busy_undo;
			p[cmd->scsi_atomic_blocked_cmds_count] = chk_cmd;
			cmd->scsi_atomic_blocked_cmds = p;
			cmd->scsi_atomic_blocked_cmds_count++;

			chk_cmd->scsi_atomic_blockers++;

			TRACE_BLOCK("Delaying cmd %p (op %s, lba %lld, "
				"len %lld, blockers %d) due to overlap with "
				"cmd %p (op %s, lba %lld, len %lld, blocked "
				"cmds %d)", chk_cmd, scst_get_opcode_name(chk_cmd),
				(long long)chk_cmd->lba,
				(long long)chk_cmd->data_len,
				chk_cmd->scsi_atomic_blockers, cmd,
				scst_get_opcode_name(cmd), (long long)cmd->lba,
				(long long)cmd->data_len,
				cmd->scsi_atomic_blocked_cmds_count);
			res = true;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_busy_undo:
	list_for_each_entry(cmd, &dev->dev_exec_cmd_list, dev_exec_cmd_list_entry) {
		struct scst_cmd **p = cmd->scsi_atomic_blocked_cmds;

		if ((p != NULL) && (p[cmd->scsi_atomic_blocked_cmds_count-1] == chk_cmd)) {
			cmd->scsi_atomic_blocked_cmds_count--;
			chk_cmd->scsi_atomic_blockers--;
		}
	}
	sBUG_ON(chk_cmd->scsi_atomic_blockers != 0);

	scst_set_busy(chk_cmd);
	scst_set_cmd_abnormal_done_state(chk_cmd);

	spin_lock_irq(&chk_cmd->cmd_threads->cmd_list_lock);
	TRACE_MGMT_DBG("Adding on error chk_cmd %p back to head of active cmd "
		"list", chk_cmd);
	list_add(&chk_cmd->cmd_list_entry, &chk_cmd->cmd_threads->active_cmd_list);
	wake_up(&chk_cmd->cmd_threads->cmd_list_waitQ);
	spin_unlock_irq(&chk_cmd->cmd_threads->cmd_list_lock);

	res = false;
	goto out;
}

/*
 * dev_lock supposed to be BH locked. Returns true if cmd blocked, hence stop
 * processing it and go to the next command.
 */
bool scst_do_check_blocked_dev(struct scst_cmd *cmd)
{
	bool res;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	/*
	 * We want to have fairness between just unblocked previously blocked
	 * SCSI atomic cmds and new cmds came after them. Otherwise, the new
	 * cmds can bypass the SCSI atomic cmds and make them unfairly wait
	 * again. So, we need to always, from the beginning, have blocked SCSI
	 * atomic cmds on the exec list, even if they blocked, as well
	 * as dev's SCSI atomic cmds counter incremented.
	 */

	if (likely(!cmd->on_dev_exec_list)) {
		list_add_tail(&cmd->dev_exec_cmd_list_entry, &dev->dev_exec_cmd_list);
		cmd->on_dev_exec_list = 1;
	}

	/*
	 * After a cmd passed SCSI atomicy check, there's no need to recheck SCSI
	 * atomicity for this cmd in future entrances here, because then all
	 * future overlapping with this cmd cmds will be blocked on it.
	 */

	if (unlikely(((cmd->op_flags & SCST_SCSI_ATOMIC) != 0) ||
		     (dev->dev_scsi_atomic_cmd_active != 0)) &&
	    !cmd->scsi_atomicity_checked) {
		cmd->scsi_atomicity_checked = 1;
		if ((cmd->op_flags & SCST_SCSI_ATOMIC) != 0) {
			dev->dev_scsi_atomic_cmd_active++;
			TRACE_DBG("cmd %p (dev %p), scsi atomic_cmd_active %d",
				cmd, dev, dev->dev_scsi_atomic_cmd_active);
		}

		res = scst_check_scsi_atomicity(cmd);
		if (res) {
			EXTRACHECKS_BUG_ON(dev->dev_scsi_atomic_cmd_active == 0);
			goto out;
		}
	}

	dev->on_dev_cmd_count++;
	cmd->dec_on_dev_needed = 1;
	TRACE_DBG("New inc on_dev_count %d (cmd %p)", dev->on_dev_cmd_count, cmd);

	if (unlikely(dev->block_count > 0) ||
	    unlikely(dev->dev_double_ua_possible) ||
	    unlikely((cmd->op_flags & SCST_SERIALIZED) != 0))
		res = __scst_check_blocked_dev(cmd);
	else
		res = false;

	if (unlikely(res)) {
		/* Undo increments */
		dev->on_dev_cmd_count--;
		cmd->dec_on_dev_needed = 0;
		TRACE_DBG("New dec on_dev_count %d (cmd %p)",
			dev->on_dev_cmd_count, cmd);
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * No locks. Returns true if cmd blocked, hence stop processing it and go to
 * the next command.
 */
static bool scst_check_blocked_dev(struct scst_cmd *cmd)
{
	bool res;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	if (unlikely((cmd->op_flags & SCST_CAN_GEN_3PARTY_COMMANDS) != 0)) {
		EXTRACHECKS_BUG_ON(cmd->cdb[0] != EXTENDED_COPY);
		res = scst_cm_check_block_all_devs(cmd);
		goto out;
	}

	if (unlikely(cmd->internal || cmd->bypass_blocking)) {
		/*
		 * The original command can already block the device and must
		 * hold reference to it, so internal command should always pass.
		 */

		/* Copy Manager can send internal INQUIRYs, so don't BUG on them */
		sBUG_ON((dev->on_dev_cmd_count == 0) && (cmd->cdb[0] != INQUIRY));

		res = false;
		goto out;
	}

	spin_lock_bh(&dev->dev_lock);
	res = scst_do_check_blocked_dev(cmd);
	spin_unlock_bh(&dev->dev_lock);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* dev_lock supposed to be held and BH disabled */
static void scst_check_unblock_scsi_atomic_cmds(struct scst_cmd *cmd)
{
	int i;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->scsi_atomic_blocked_cmds_count == 0);

	for (i = 0; i < cmd->scsi_atomic_blocked_cmds_count; i++) {
		struct scst_cmd *acmd = cmd->scsi_atomic_blocked_cmds[i];

		acmd->scsi_atomic_blockers--;
		if (acmd->scsi_atomic_blockers == 0) {
			TRACE_BLOCK("Unblocking blocked acmd %p (blocker "
				"cmd %p)", acmd, cmd);
			spin_lock_irq(&acmd->cmd_threads->cmd_list_lock);
			if (acmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE)
				list_add(&acmd->cmd_list_entry,
					&acmd->cmd_threads->active_cmd_list);
			else
				list_add_tail(&acmd->cmd_list_entry,
					&acmd->cmd_threads->active_cmd_list);
			wake_up(&acmd->cmd_threads->cmd_list_waitQ);
			spin_unlock_irq(&acmd->cmd_threads->cmd_list_lock);
		}
	}

	kfree(cmd->scsi_atomic_blocked_cmds);
	cmd->scsi_atomic_blocked_cmds = NULL;
	cmd->scsi_atomic_blocked_cmds_count = 0;

	TRACE_EXIT();
	return;
}

/* dev_lock supposed to be BH locked */
void __scst_check_unblock_dev(struct scst_cmd *cmd)
{
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	/*
	 * We might be called here as part of Copy Manager's check blocking
	 * undo, so restore all flags in the previous state to allow
	 * restart of this cmd.
	 */

	if (likely(cmd->on_dev_exec_list)) {
		list_del(&cmd->dev_exec_cmd_list_entry);
		cmd->on_dev_exec_list = 0;
	}

	if (unlikely((cmd->op_flags & SCST_SCSI_ATOMIC) != 0)) {
		if (likely(cmd->scsi_atomicity_checked)) {
			dev->dev_scsi_atomic_cmd_active--;
			TRACE_DBG("cmd %p, scsi atomic_cmd_active %d",
				cmd, dev->dev_scsi_atomic_cmd_active);
			cmd->scsi_atomicity_checked = 0;
		}
	}

	if (likely(cmd->dec_on_dev_needed)) {
		dev->on_dev_cmd_count--;
		cmd->dec_on_dev_needed = 0;
		TRACE_DBG("New dec on_dev_count %d (cmd %p)",
			dev->on_dev_cmd_count, cmd);
	}

	if (unlikely(cmd->scsi_atomic_blocked_cmds != NULL))
		scst_check_unblock_scsi_atomic_cmds(cmd);

	if (unlikely(cmd->unblock_dev)) {
		TRACE_BLOCK("cmd %p (tag %llu): unblocking dev %s", cmd,
			(unsigned long long int)cmd->tag, dev->virt_name);
		cmd->unblock_dev = 0;
		scst_unblock_dev(dev);
	} else if (unlikely(dev->strictly_serialized_cmd_waiting)) {
		if (dev->on_dev_cmd_count == 0) {
			TRACE_BLOCK("Strictly serialized cmd waiting: "
				"unblocking dev %s", dev->virt_name);
			scst_unblock_dev(dev);
			dev->strictly_serialized_cmd_waiting = 0;
		}
	}

	if (unlikely(dev->ext_blocking_pending)) {
		if (dev->on_dev_cmd_count == 0) {
			TRACE_MGMT_DBG("Releasing pending dev %s extended "
				"blocks", dev->virt_name);
			scst_ext_blocking_done(dev);
		}
	}

	TRACE_EXIT();
	return;
}

/* No locks */
void scst_check_unblock_dev(struct scst_cmd *cmd)
{
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	spin_lock_bh(&dev->dev_lock);
	__scst_check_unblock_dev(cmd);
	spin_unlock_bh(&dev->dev_lock);

	TRACE_EXIT();
	return;
}

static void __scst_rx_cmd(struct scst_cmd *cmd, struct scst_session *sess,
	const uint8_t *lun, int lun_len, gfp_t gfp_mask)
{
	TRACE_ENTRY();

	cmd->sess = sess;
	scst_sess_get(sess);

	cmd->tgt = sess->tgt;
	cmd->tgtt = sess->tgt->tgtt;

	cmd->lun = scst_unpack_lun(lun, lun_len);
	if (unlikely(cmd->lun == NO_SUCH_LUN))
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_lun_not_supported));

	TRACE_DBG("cmd %p, sess %p", cmd, sess);

	TRACE_EXIT();
	return;
}

/**
 * scst_rx_cmd_prealloced() - notify SCST that new command received
 * @cmd:	new cmd to initialized
 * @sess:	SCST session
 * @lun:	LUN for the command
 * @lun_len:	length of the LUN in bytes
 * @cdb:	CDB of the command
 * @cdb_len:	length of the CDB in bytes
 * @atomic:	true, if current context is atomic
 *
 * Description:
 *    Initializes new prealloced SCST command. Returns 0 on success or
 *    negative error code otherwise.
 *
 *    Must not be called in parallel with scst_unregister_session() for the
 *    same session.
 *
 *    Cmd supposed to be zeroed!
 */
int scst_rx_cmd_prealloced(struct scst_cmd *cmd, struct scst_session *sess,
	const uint8_t *lun, int lun_len, const uint8_t *cdb,
	unsigned int cdb_len, bool atomic)
{
	int res;
	gfp_t gfp_mask = atomic ? GFP_ATOMIC : cmd->cmd_gfp_mask;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(sess->shut_phase != SCST_SESS_SPH_READY)) {
		PRINT_CRIT_ERROR("%s",
			"New cmd while shutting down the session");
		sBUG();
	}
#endif

	res = scst_pre_init_cmd(cmd, cdb, cdb_len, gfp_mask);
	if (unlikely(res != 0))
		goto out;

	__scst_rx_cmd(cmd, sess, lun, lun_len, gfp_mask);

	cmd->pre_alloced = 1;

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_rx_cmd_prealloced);

/**
 * scst_rx_cmd() - create new command
 * @sess:	SCST session
 * @lun:	LUN for the command
 * @lun_len:	length of the LUN in bytes
 * @cdb:	CDB of the command
 * @cdb_len:	length of the CDB in bytes
 * @atomic:	true, if current context is atomic
 *
 * Description:
 *    Creates new SCST command. Returns new command on success or
 *    NULL otherwise.
 *
 *    Must not be called in parallel with scst_unregister_session() for the
 *    same session.
 */
struct scst_cmd *scst_rx_cmd(struct scst_session *sess,
	const uint8_t *lun, int lun_len, const uint8_t *cdb,
	unsigned int cdb_len, bool atomic)
{
	struct scst_cmd *cmd;
	gfp_t gfp_mask = atomic ? GFP_ATOMIC : GFP_NOIO;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(sess->shut_phase != SCST_SESS_SPH_READY)) {
		PRINT_CRIT_ERROR("%s",
			"New cmd while shutting down the session");
		sBUG();
	}
#endif

	cmd = scst_alloc_cmd(cdb, cdb_len, gfp_mask);
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of scst_cmd failed");
		goto out;
	}

	__scst_rx_cmd(cmd, sess, lun, lun_len,  gfp_mask);

	cmd->pre_alloced = 0;

out:
	TRACE_EXIT();
	return cmd;
}
EXPORT_SYMBOL(scst_rx_cmd);

/*
 * No locks, but might be on IRQ. Returns:
 * -  < 0 if the caller must not perform any further processing of @cmd;
 * - >= 0 if the caller must continue processing @cmd.
 */
static int scst_init_cmd(struct scst_cmd *cmd, enum scst_exec_context *context)
{
	int rc, res = 0;

	TRACE_ENTRY();

	/* See the comment in scst_do_job_init() */
	if (unlikely(!list_empty(&scst_init_cmd_list))) {
		TRACE_DBG("%s", "init cmd list busy");
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

	EXTRACHECKS_BUG_ON(*context == SCST_CONTEXT_SAME);

#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
	if (cmd->op_flags & SCST_TEST_IO_IN_SIRQ_ALLOWED)
		goto out;
#endif

	/* Small context optimization */
	if ((*context == SCST_CONTEXT_TASKLET) ||
	    (*context == SCST_CONTEXT_DIRECT_ATOMIC)) {
		/*
		 * If any data_direction not set, it's SCST_DATA_UNKNOWN,
		 * which is 0, so we can safely | them
		 */
		BUILD_BUG_ON(SCST_DATA_UNKNOWN != 0);
		if ((cmd->data_direction | cmd->expected_data_direction) & SCST_DATA_WRITE) {
			if (!cmd->tgt_dev->tgt_dev_after_init_wr_atomic)
				*context = SCST_CONTEXT_THREAD;
		} else
			*context = SCST_CONTEXT_THREAD;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_redirect:
	if (cmd->preprocessing_only) {
		/*
		 * Poor man solution for single threaded targets, where
		 * blocking receiver at least sometimes means blocking all.
		 * For instance, iSCSI target won't be able to receive
		 * Data-Out PDUs.
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
		TRACE_DBG("Adding cmd %p to init cmd list", cmd);
		list_add_tail(&cmd->cmd_list_entry, &scst_init_cmd_list);
		if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
			scst_init_poll_cnt++;
		spin_unlock_irqrestore(&scst_init_lock, flags);
		wake_up(&scst_init_cmd_list_waitQ);
		res = -1;
	}
	goto out;
}

/**
 * scst_cmd_init_done() - the command's initialization done
 * @cmd:	SCST command
 * @pref_context: preferred command execution context
 *
 * Description:
 *    Notifies SCST that the driver finished its part of the command
 *    initialization, and the command is ready for execution.
 *    The second argument sets preferred command execution context.
 *    See SCST_CONTEXT_* constants for details.
 *
 *    !!IMPORTANT!!
 *
 *    If cmd->set_sn_on_restart_cmd not set, this function, as well as
 *    scst_cmd_init_stage1_done() and scst_restart_cmd(), must not be
 *    called simultaneously for the same session (more precisely,
 *    for the same session/LUN, i.e. tgt_dev), i.e. they must be
 *    somehow externally serialized. This is needed to have lock free fast
 *    path in scst_cmd_set_sn(). For majority of targets those functions are
 *    naturally serialized by the single source of commands. Only some, like
 *    iSCSI immediate commands with multiple connections per session or
 *    scst_local, are exceptions. For it, some mutex/lock must be used for
 *    the serialization. Or, alternatively, multithreaded_init_done can
 *    be set in the target's template.
 */
void scst_cmd_init_done(struct scst_cmd *cmd,
	enum scst_exec_context pref_context)
{
	unsigned long flags;
	struct scst_session *sess = cmd->sess;
	int rc;

	TRACE_ENTRY();

	scst_set_start_time(cmd);

	TRACE_DBG("Preferred context: %d (cmd %p)", pref_context, cmd);
	TRACE(TRACE_SCSI, "NEW CDB: len %d, lun %lld, initiator %s, "
		"target %s, queue_type %x, tag %llu (cmd %p, sess %p)",
		cmd->cdb_len, (unsigned long long int)cmd->lun,
		cmd->sess->initiator_name, cmd->tgt->tgt_name, cmd->queue_type,
		(unsigned long long int)cmd->tag, cmd, sess);
	PRINT_BUFF_FLAG(TRACE_SCSI, "CDB", cmd->cdb, cmd->cdb_len);

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely((in_irq() || irqs_disabled())) &&
	    ((pref_context == SCST_CONTEXT_DIRECT) ||
	     (pref_context == SCST_CONTEXT_DIRECT_ATOMIC))) {
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_THREAD instead", pref_context,
			cmd->tgtt->name);
		dump_stack();
		pref_context = SCST_CONTEXT_THREAD;
	}
#endif

	atomic_inc(&sess->sess_cmd_count);

	spin_lock_irqsave(&sess->sess_list_lock, flags);

	if (unlikely(sess->init_phase != SCST_SESS_IPH_READY)) {
		/*
		 * We must always keep commands in the sess list from the
		 * very beginning, because otherwise they can be missed during
		 * TM processing. This check is needed because there might be
		 * old, i.e. deferred, commands and new, i.e. just coming, ones.
		 */
		if (cmd->sess_cmd_list_entry.next == NULL)
			list_add_tail(&cmd->sess_cmd_list_entry,
				&sess->sess_cmd_list);
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
			goto set_state;
		default:
			sBUG();
		}
	} else
		list_add_tail(&cmd->sess_cmd_list_entry,
			      &sess->sess_cmd_list);

	spin_unlock_irqrestore(&sess->sess_list_lock, flags);

	if (unlikely(cmd->queue_type >= SCST_CMD_QUEUE_ACA)) {
		PRINT_ERROR("Unsupported queue type %d", cmd->queue_type);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_message));
	}

set_state:
	if (unlikely(cmd->status != SAM_STAT_GOOD)) {
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

active:
	/* Here cmd must not be in any cmd list, no locks */
	switch (pref_context) {
	case SCST_CONTEXT_TASKLET:
		scst_schedule_tasklet(cmd);
		break;

	default:
		PRINT_ERROR("Context %x is undefined, using the thread one",
			pref_context);
		/* go through */
	case SCST_CONTEXT_THREAD:
		spin_lock_irqsave(&cmd->cmd_threads->cmd_list_lock, flags);
		TRACE_DBG("Adding cmd %p to active cmd list", cmd);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
		wake_up(&cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock_irqrestore(&cmd->cmd_threads->cmd_list_lock, flags);
		break;

	case SCST_CONTEXT_DIRECT:
		scst_process_active_cmd(cmd, false);
		break;

	case SCST_CONTEXT_DIRECT_ATOMIC:
		scst_process_active_cmd(cmd, true);
		break;
	}

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_cmd_init_done);

int scst_pre_parse(struct scst_cmd *cmd)
{
	int res;
#ifndef CONFIG_SCST_STRICT_SERIALIZING
	struct scst_device *dev = cmd->dev;
#endif
	struct scst_dev_type *devt = cmd->devt;
	int rc;

	TRACE_ENTRY();

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
			goto out_err;
		}

		EXTRACHECKS_BUG_ON(cmd->op_flags & SCST_INFO_VALID);

		TRACE(TRACE_MINOR, "Unknown opcode 0x%02x for %s. "
			"Should you update scst_scsi_op_table?",
			cmd->cdb[0], devt->name);
		PRINT_BUFF_FLAG(TRACE_MINOR, "Failed CDB", cmd->cdb,
			cmd->cdb_len);
	} else
		EXTRACHECKS_BUG_ON(!(cmd->op_flags & SCST_INFO_VALID));

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	cmd->inc_expected_sn_on_done = 1;
#else
	cmd->inc_expected_sn_on_done = devt->exec_sync ||
		(!dev->has_own_order_mgmt &&
		 (dev->queue_alg == SCST_QUEUE_ALG_0_RESTRICTED_REORDER ||
		  cmd->queue_type == SCST_CMD_QUEUE_ORDERED));
#endif

	TRACE_DBG("op_name <%s> (cmd %p), direction=%d "
		"(expected %d, set %s), lba %lld, bufflen=%d, data_len %lld, "
		"out_bufflen=%d (expected len data %d, expected len DIF %d, "
		"out expected len %d), flags=0x%x, , naca %d",
		cmd->op_name, cmd, cmd->data_direction,
		cmd->expected_data_direction,
		scst_cmd_is_expected_set(cmd) ? "yes" : "no",
		(long long)cmd->lba, cmd->bufflen, (long long)cmd->data_len,
		cmd->out_bufflen, scst_cmd_get_expected_transfer_len_data(cmd),
		scst_cmd_get_expected_transfer_len_dif(cmd),
		cmd->expected_out_transfer_len, cmd->op_flags, cmd->cmd_naca);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	scst_set_cmd_abnormal_done_state(cmd);
	res = -1;
	goto out;
}

#ifndef CONFIG_SCST_USE_EXPECTED_VALUES
static bool scst_is_allowed_to_mismatch_cmd(struct scst_cmd *cmd)
{
	bool res = false;

	switch (cmd->cdb[0]) {
	case TEST_UNIT_READY:
		/* Crazy VMware people sometimes do TUR with READ direction */
		if ((cmd->expected_data_direction == SCST_DATA_READ) ||
		    (cmd->expected_data_direction == SCST_DATA_NONE))
			res = true;
		break;
	}

	return res;
}
#endif

static bool scst_bufflen_eq_expecten_len(struct scst_cmd *cmd)
{
	int b = cmd->bufflen;

	if (cmd->tgt_dif_data_expected)
		b += (b >> cmd->dev->block_shift) << SCST_DIF_TAG_SHIFT;

	return b == cmd->expected_transfer_len_full;
}

static int scst_parse_cmd(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int state;
	struct scst_dev_type *devt = cmd->devt;
	int orig_bufflen = cmd->bufflen;

	TRACE_ENTRY();

	if (likely((cmd->op_flags & SCST_FULLY_LOCAL_CMD) == 0)) {
		if (unlikely(!devt->parse_atomic &&
			     scst_cmd_atomic(cmd))) {
			/*
			 * It shouldn't be because of the SCST_TGT_DEV_AFTER_*
			 * optimization.
			 */
			TRACE_MGMT_DBG("Dev handler %s parse() needs thread "
				"context, rescheduling", devt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		TRACE_DBG("Calling dev handler %s parse(%p)",
		      devt->name, cmd);
		scst_set_cur_start(cmd);
		state = devt->parse(cmd);
		/* Caution: cmd can be already dead here */
		TRACE_DBG("Dev handler %s parse() returned %d",
			devt->name, state);

		switch (state) {
		case SCST_CMD_STATE_NEED_THREAD_CTX:
			scst_set_parse_time(cmd);
			TRACE_DBG("Dev handler %s parse() requested thread "
			      "context, rescheduling", devt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;

		case SCST_CMD_STATE_STOP:
			/*
			 * !! cmd can be dead now!
			 */
			TRACE_DBG("Dev handler %s parse() requested stop "
				"processing", devt->name);
			res = SCST_CMD_STATE_RES_CONT_NEXT;
			goto out;
		}

		scst_set_parse_time(cmd);
	} else
		state = scst_do_internal_parsing(cmd);

	if (state == SCST_CMD_STATE_DEFAULT)
		state = SCST_CMD_STATE_PREPARE_SPACE;

	if (unlikely(cmd->status != 0))
		goto set_res;

	if (unlikely(!(cmd->op_flags & SCST_INFO_VALID))) {
#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
		if (scst_cmd_is_expected_set(cmd)) {
			TRACE(TRACE_MINOR, "Using initiator supplied values: "
				"direction %d, transfer_len %d/%d/%d",
				cmd->expected_data_direction,
				scst_cmd_get_expected_transfer_len_data(cmd),
				scst_cmd_get_expected_transfer_len_dif(cmd),
				cmd->expected_out_transfer_len);
			cmd->data_direction = cmd->expected_data_direction;
			cmd->bufflen = scst_cmd_get_expected_transfer_len_data(cmd);
			cmd->data_len = cmd->bufflen;
			cmd->out_bufflen = cmd->expected_out_transfer_len;
		} else {
			PRINT_WARNING("Unknown opcode 0x%02x for %s and "
			     "target %s not supplied expected values",
			     cmd->cdb[0], devt->name, cmd->tgtt->name);
			scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
			goto out_done;
		}
#else
		PRINT_WARNING("Refusing unknown opcode %x", cmd->cdb[0]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
#endif
	}

	if (unlikely(cmd->cdb_len == 0)) {
		PRINT_ERROR("Unable to get CDB length for "
			"opcode %s. Returning INVALID "
			"OPCODE", scst_get_opcode_name(cmd));
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

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
			cmd->bufflen = min(scst_cmd_get_expected_transfer_len_data(cmd),
						15*1024*1024);
			cmd->data_len = cmd->bufflen;
			if (cmd->data_direction == SCST_DATA_BIDI)
				cmd->out_bufflen = min(cmd->expected_out_transfer_len,
							15*1024*1024);
		} else {
			if (cmd->bufflen == 0) {
				PRINT_ERROR("Unknown data transfer length for opcode "
					"%s (handler %s, target %s)",
					scst_get_opcode_name(cmd), devt->name,
					cmd->tgtt->name);
				PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(scst_sense_invalid_message));
				goto out_done;
			} /* else we have a guess, so proceed further */
		}
		cmd->op_flags &= ~SCST_UNKNOWN_LENGTH;
	}

	if (unlikely(cmd->cmd_naca)) {
		PRINT_ERROR("NACA bit in control byte CDB is not supported "
			    "(opcode 0x%02x)", cmd->cdb[0]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_message));
		goto out_done;
	}

	if (unlikely(cmd->cmd_linked)) {
		PRINT_ERROR("Linked commands are not supported "
			    "(opcode %s)", scst_get_opcode_name(cmd));
		scst_set_invalid_field_in_cdb(cmd, cmd->cdb_len-1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out_done;
	}

	if (cmd->dh_data_buf_alloced &&
	    unlikely((orig_bufflen > cmd->bufflen))) {
		PRINT_ERROR("Dev handler supplied data buffer (size %d), "
			"is less, than required (size %d)", cmd->bufflen,
			orig_bufflen);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_hw_error;
	}

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((cmd->bufflen != 0) &&
	    ((cmd->data_direction == SCST_DATA_NONE) ||
	     ((cmd->sg == NULL) && (state > SCST_CMD_STATE_PREPARE_SPACE)))) {
		PRINT_ERROR("Dev handler %s parse() returned "
			"invalid cmd data_direction %d, bufflen %d, state %d "
			"or sg %p (opcode %s)", devt->name,
			cmd->data_direction, cmd->bufflen, state, cmd->sg,
			scst_get_opcode_name(cmd));
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_hw_error;
	}
#endif

	if (scst_cmd_is_expected_set(cmd)) {
#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
		if (unlikely((cmd->data_direction != cmd->expected_data_direction) ||
			     !scst_bufflen_eq_expecten_len(cmd) ||
			     (cmd->out_bufflen != cmd->expected_out_transfer_len))) {
			TRACE(TRACE_MINOR, "Expected values don't match "
				"decoded ones: data_direction %d, "
				"expected_data_direction %d, "
				"bufflen %d, expected len data %d, expected len "
				"DIF %d, out_bufflen %d, expected_out_transfer_len %d",
				cmd->data_direction,
				cmd->expected_data_direction,
				cmd->bufflen, scst_cmd_get_expected_transfer_len_data(cmd),
				scst_cmd_get_expected_transfer_len_dif(cmd),
				cmd->out_bufflen, cmd->expected_out_transfer_len);
			PRINT_BUFF_FLAG(TRACE_MINOR, "Suspicious CDB",
				cmd->cdb, cmd->cdb_len);
			cmd->data_direction = cmd->expected_data_direction;
			cmd->bufflen = scst_cmd_get_expected_transfer_len_data(cmd);
			cmd->data_len = cmd->bufflen;
			cmd->out_bufflen = cmd->expected_out_transfer_len;
			cmd->resid_possible = 1;
		}
#else
		if (unlikely(cmd->data_direction !=
				cmd->expected_data_direction)) {
			if (((cmd->expected_data_direction != SCST_DATA_NONE) ||
			     (cmd->bufflen != 0)) &&
			    !scst_is_allowed_to_mismatch_cmd(cmd)) {
				PRINT_ERROR("Expected data direction %d for "
					"opcode %s (handler %s, target %s) "
					"doesn't match decoded value %d",
					cmd->expected_data_direction,
					scst_get_opcode_name(cmd), devt->name,
					cmd->tgtt->name, cmd->data_direction);
				PRINT_BUFFER("Failed CDB", cmd->cdb,
					cmd->cdb_len);
				scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_message));
				goto out_done;
			}
		}
		if (unlikely(!scst_bufflen_eq_expecten_len(cmd))) {
			TRACE(TRACE_MINOR, "Warning: expected "
				"transfer length %d (DIF %d) for opcode %s "
				"(handler %s, target %s) doesn't match "
				"decoded value %d",
				scst_cmd_get_expected_transfer_len_data(cmd),
				scst_cmd_get_expected_transfer_len_dif(cmd),
				scst_get_opcode_name(cmd), devt->name,
				cmd->tgtt->name, cmd->bufflen);
			PRINT_BUFF_FLAG(TRACE_MINOR, "Suspicious CDB",
				cmd->cdb, cmd->cdb_len);
			if ((cmd->expected_data_direction & SCST_DATA_READ) ||
			    (cmd->expected_data_direction & SCST_DATA_WRITE))
				cmd->resid_possible = 1;
		}
		if (unlikely(cmd->out_bufflen != cmd->expected_out_transfer_len)) {
			TRACE(TRACE_MINOR, "Warning: expected bidirectional OUT "
				"transfer length %d for opcode %s "
				"(handler %s, target %s) doesn't match "
				"decoded value %d",
				cmd->expected_out_transfer_len,
				scst_get_opcode_name(cmd), devt->name,
				cmd->tgtt->name, cmd->out_bufflen);
			PRINT_BUFF_FLAG(TRACE_MINOR, "Suspicious CDB",
				cmd->cdb, cmd->cdb_len);
			cmd->resid_possible = 1;
		}
#endif
	}

	if (unlikely(cmd->data_direction == SCST_DATA_UNKNOWN)) {
		PRINT_ERROR("Unknown data direction (opcode %s, handler %s, "
			"target %s)", scst_get_opcode_name(cmd), devt->name,
			cmd->tgtt->name);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_hw_error;
	}

	if (unlikely(cmd->op_flags & SCST_UNKNOWN_LBA)) {
		PRINT_ERROR("Unknown LBA (opcode %s, handler %s, "
			"target %s)", scst_get_opcode_name(cmd), devt->name,
			cmd->tgtt->name);
		PRINT_BUFFER("Failed CDB", cmd->cdb, cmd->cdb_len);
		goto out_hw_error;
	}

set_res:
	if (cmd->bufflen == 0) {
		/*
		 * According to SPC bufflen 0 for data transfer commands isn't
		 * an error, so we need to fix the transfer direction.
		 */
		cmd->data_direction = SCST_DATA_NONE;
	}

	TRACE(TRACE_SCSI, "op_name <%s> (cmd %p), direction=%d "
		"(expected %d, set %s), lba=%lld, bufflen=%d, data len %lld, "
		"out_bufflen=%d, (expected len data %d, expected len DIF %d, "
		"out expected len %d), flags=0x%x, internal %d, naca %d",
		cmd->op_name, cmd, cmd->data_direction, cmd->expected_data_direction,
		scst_cmd_is_expected_set(cmd) ? "yes" : "no",
		(unsigned long long)cmd->lba,
		cmd->bufflen, (long long)cmd->data_len, cmd->out_bufflen,
		scst_cmd_get_expected_transfer_len_data(cmd),
		scst_cmd_get_expected_transfer_len_dif(cmd),
		cmd->expected_out_transfer_len, cmd->op_flags, cmd->internal,
		cmd->cmd_naca);

#ifdef CONFIG_SCST_EXTRACHECKS
	switch (state) {
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_PARSE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_PREPROCESSING_DONE:
	case SCST_CMD_STATE_TGT_PRE_EXEC:
	case SCST_CMD_STATE_EXEC_CHECK_SN:
	case SCST_CMD_STATE_EXEC_CHECK_BLOCKING:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_PRE_XMIT_RESP1:
	case SCST_CMD_STATE_PRE_XMIT_RESP2:
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
	case SCST_CMD_STATE_FINISHED_INTERNAL:
#endif
		cmd->state = state;
		res = SCST_CMD_STATE_RES_CONT_SAME;
#ifdef CONFIG_SCST_EXTRACHECKS
		break;

	default:
		if (state >= 0) {
			PRINT_ERROR("Dev handler %s parse() returned "
			     "invalid cmd state %d (opcode %s)",
			     devt->name, state, scst_get_opcode_name(cmd));
		} else {
			PRINT_ERROR("Dev handler %s parse() returned "
				"error %d (opcode %s)", devt->name,
				state, scst_get_opcode_name(cmd));
		}
		goto out_hw_error;
	}
#endif

	if (cmd->resp_data_len == -1) {
		if (cmd->data_direction & SCST_DATA_READ)
			cmd->resp_data_len = cmd->bufflen;
		else
			 cmd->resp_data_len = 0;
	}

#ifndef CONFIG_SCST_TEST_IO_IN_SIRQ
	/*
	 * We can't allow atomic command on the exec stages. It shouldn't
	 * be because of the SCST_TGT_DEV_AFTER_* optimization, but during
	 * parsing data_direction can change, so we need to recheck.
	 */
	if (unlikely(scst_cmd_atomic(cmd) &&
		     !(cmd->data_direction & SCST_DATA_WRITE))) {
		TRACE_DBG_FLAG(TRACE_DEBUG|TRACE_MINOR, "Atomic context and "
			"non-WRITE data direction, rescheduling (cmd %p)", cmd);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		/* go through */
	}
#endif

out_check_compl:
#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(cmd->completed)) {
		/* Command completed with error */
		bool valid_state = (cmd->state == SCST_CMD_STATE_PREPROCESSING_DONE) ||
				   ((cmd->state >= SCST_CMD_STATE_PRE_XMIT_RESP) &&
				    (cmd->state < SCST_CMD_STATE_LAST_ACTIVE));

		if (!valid_state) {
			PRINT_CRIT_ERROR("Bad state for completed cmd "
				"(cmd %p, state %d)", cmd, cmd->state);
			sBUG();
		}
	} else if (cmd->state != SCST_CMD_STATE_PARSE) {
		/*
		 * Ready to execute. At this point both lba and data_len must
		 * be initialized or marked non-applicable.
		 */
		bool bad_lba = (cmd->lba == SCST_DEF_LBA_DATA_LEN) &&
			       !(cmd->op_flags & SCST_LBA_NOT_VALID);
		bool bad_data_len = (cmd->data_len == SCST_DEF_LBA_DATA_LEN);

		if (unlikely(bad_lba || bad_data_len)) {
			PRINT_CRIT_ERROR("Uninitialized lba or data_len for "
				"ready-to-execute command (cmd %p, lba %lld, "
				"data_len %lld, state %d)", cmd,
				(long long)cmd->lba, (long long)cmd->data_len,
				cmd->state);
			sBUG();
		}
	}
#endif

	if (unlikely(test_bit(SCST_TGT_DEV_BLACK_HOLE, &cmd->tgt_dev->tgt_dev_flags))) {
		struct scst_session *sess = cmd->sess;
		bool abort = false;

		switch (sess->acg->acg_black_hole_type) {
		case SCST_ACG_BLACK_HOLE_CMD:
		case SCST_ACG_BLACK_HOLE_ALL:
			abort = true;
			break;
		case SCST_ACG_BLACK_HOLE_DATA_CMD:
		case SCST_ACG_BLACK_HOLE_DATA_MCMD:
			if (cmd->data_direction != SCST_DATA_NONE)
				abort = true;
			break;
		default:
			break;
		}
		if (abort) {
			TRACE_MGMT_DBG("Black hole: aborting cmd %p (op %s, "
				"initiator %s)", cmd, scst_get_opcode_name(cmd),
				sess->initiator_name);
			scst_abort_cmd(cmd, NULL, false, false);
		}
	}

out:
	TRACE_EXIT_HRES(res);
	return res;

out_hw_error:
	/* dev_done() will be called as part of the regular cmd's finish */
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

out_done:
	scst_set_cmd_abnormal_done_state(cmd);
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out_check_compl;
}

static void scst_set_write_len(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(!(cmd->data_direction & SCST_DATA_WRITE));

	if (cmd->data_direction & SCST_DATA_READ) {
		cmd->write_len = cmd->out_bufflen;
		cmd->write_sg = &cmd->out_sg;
		cmd->write_sg_cnt = &cmd->out_sg_cnt;
	} else {
		cmd->write_len = cmd->bufflen;
		/* write_sg and write_sg_cnt already initialized correctly */
	}

	TRACE_MEM("cmd %p, write_len %d, write_sg %p, write_sg_cnt %d, "
		"resid_possible %d", cmd, cmd->write_len, *cmd->write_sg,
		*cmd->write_sg_cnt, cmd->resid_possible);

	if (unlikely(cmd->resid_possible)) {
		if (cmd->data_direction & SCST_DATA_READ) {
			cmd->write_len = min(cmd->out_bufflen,
				cmd->expected_out_transfer_len);
			if (cmd->write_len == cmd->out_bufflen)
				goto out;
		} else {
			cmd->write_len = min(cmd->bufflen,
				scst_cmd_get_expected_transfer_len_data(cmd));
			if (cmd->write_len == cmd->bufflen)
				goto out;
		}
		scst_limit_sg_write_len(cmd);
	}

out:
	TRACE_EXIT();
	return;
}

static int scst_prepare_space(struct scst_cmd *cmd)
{
	int r = 0, res = SCST_CMD_STATE_RES_CONT_SAME;
	struct scst_dev_type *devt = cmd->devt;

	TRACE_ENTRY();

	if (cmd->data_direction == SCST_DATA_NONE)
		goto done;

	if (likely((cmd->op_flags & SCST_FULLY_LOCAL_CMD) == 0) &&
	    (devt->dev_alloc_data_buf != NULL)) {
		int state;

		if (unlikely(!devt->dev_alloc_data_buf_atomic &&
			     scst_cmd_atomic(cmd))) {
			/*
			 * It shouldn't be because of the SCST_TGT_DEV_AFTER_*
			 * optimization.
			 */
			TRACE_MGMT_DBG("Dev handler %s dev_alloc_data_buf() "
				"needs thread context, rescheduling",
				devt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		TRACE_DBG("Calling dev handler's %s dev_alloc_data_buf(%p)",
		      devt->name, cmd);
		scst_set_cur_start(cmd);
		state = devt->dev_alloc_data_buf(cmd);
		/*
		 * Caution: cmd can be already dead here
		 */

		/* cmd can be already dead here, so we can't dereference devt */
		TRACE_DBG("Dev handler %p dev_alloc_data_buf() returned %d",
			devt, state);

		switch (state) {
		case SCST_CMD_STATE_NEED_THREAD_CTX:
			scst_set_alloc_buf_time(cmd);
			TRACE_DBG("Dev handler %s dev_alloc_data_buf() requested "
				"thread context, rescheduling", devt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;

		case SCST_CMD_STATE_STOP:
			/* cmd can be already dead here, so we can't deref devt */
			TRACE_DBG("Dev handler %p dev_alloc_data_buf() "
				"requested stop processing", devt);
			res = SCST_CMD_STATE_RES_CONT_NEXT;
			goto out;
		}

		scst_set_alloc_buf_time(cmd);

		if (unlikely(state != SCST_CMD_STATE_DEFAULT)) {
			cmd->state = state;
			goto out;
		}
	}

	if (cmd->tgt_need_alloc_data_buf) {
		int orig_bufflen = cmd->bufflen;

		TRACE_MEM("Calling tgt %s tgt_alloc_data_buf(cmd %p)",
			cmd->tgt->tgt_name, cmd);

		scst_set_cur_start(cmd);
		r = cmd->tgtt->tgt_alloc_data_buf(cmd);
		scst_set_alloc_buf_time(cmd);

		if (r > 0)
			goto alloc;
		else if (r == 0) {
			if (unlikely(cmd->bufflen == 0)) {
				/* See comment in scst_alloc_space() */
				if (cmd->sg == NULL)
					goto alloc;
			}

			cmd->tgt_i_data_buf_alloced = 1;

			if (unlikely(orig_bufflen < cmd->bufflen)) {
				PRINT_ERROR("Target driver allocated data "
					"buffer (size %d), is less, than "
					"required (size %d)", orig_bufflen,
					cmd->bufflen);
				goto out_error;
			}
			TRACE_MEM("tgt_i_data_buf_alloced (cmd %p)", cmd);
		} else
			goto check;
	}

alloc:
	if (!cmd->tgt_i_data_buf_alloced && !cmd->dh_data_buf_alloced) {
		r = scst_alloc_space(cmd);
	} else if (cmd->dh_data_buf_alloced && !cmd->tgt_i_data_buf_alloced) {
		TRACE_MEM("dh_data_buf_alloced set (cmd %p)", cmd);
		r = 0;
	} else if (cmd->tgt_i_data_buf_alloced && !cmd->dh_data_buf_alloced) {
		TRACE_MEM("tgt_i_data_buf_alloced set (cmd %p)", cmd);
		cmd->sg = cmd->tgt_i_sg;
		cmd->sg_cnt = cmd->tgt_i_sg_cnt;
		cmd->dif_sg = cmd->tgt_i_dif_sg;
		cmd->dif_sg_cnt = cmd->tgt_i_dif_sg_cnt;
		cmd->out_sg = cmd->tgt_out_sg;
		cmd->out_sg_cnt = cmd->tgt_out_sg_cnt;
		r = 0;
	} else {
		TRACE_MEM("Both *_data_buf_alloced set (cmd %p, sg %p, "
			"sg_cnt %d, dif_sg %p, dif_sg_cnt %d, tgt_i_sg %p, "
			"tgt_i_sg_cnt %d, tgt_i_dif_sg %p, tgt_i_dif_sg_cnt %d)",
			cmd, cmd->sg, cmd->sg_cnt, cmd->dif_sg, cmd->dif_sg_cnt,
			cmd->tgt_i_sg, cmd->tgt_i_sg_cnt, cmd->tgt_i_dif_sg,
			cmd->tgt_i_dif_sg_cnt);
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

done:
	if (cmd->preprocessing_only) {
		cmd->state = SCST_CMD_STATE_PREPROCESSING_DONE;
		if (cmd->data_direction & SCST_DATA_WRITE)
			scst_set_write_len(cmd);
	} else if (cmd->data_direction & SCST_DATA_WRITE) {
		cmd->state = SCST_CMD_STATE_RDY_TO_XFER;
		scst_set_write_len(cmd);
	} else
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
	if (cmd->data_direction & SCST_DATA_WRITE)
		scst_set_cmd_error(cmd,	SCST_LOAD_SENSE(scst_sense_write_error));
	else
		scst_set_cmd_error(cmd,	SCST_LOAD_SENSE(scst_sense_read_error));
	scst_set_cmd_abnormal_done_state(cmd);
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

static int scst_preprocessing_done(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(!cmd->preprocessing_only);

	cmd->preprocessing_only = 0;

	res = SCST_CMD_STATE_RES_CONT_NEXT;
	cmd->state = SCST_CMD_STATE_PREPROCESSING_DONE_CALLED;

	TRACE_DBG("Calling preprocessing_done(cmd %p)", cmd);
	scst_set_cur_start(cmd);
	cmd->tgtt->preprocessing_done(cmd);
	TRACE_DBG("%s", "preprocessing_done() returned");

	TRACE_EXIT_HRES(res);
	return res;
}

/**
 * scst_restart_cmd() - restart execution of the command
 * @cmd:	SCST commands
 * @status:	completion status
 * @pref_context: preferred command execution context
 *
 * Description:
 *    Notifies SCST that the driver finished its part of the command's
 *    preprocessing and it is ready for further processing.
 *
 *    The second argument sets completion status
 *    (see SCST_PREPROCESS_STATUS_* constants for details)
 *
 *    See also comment for scst_cmd_init_done() for the serialization
 *    requirements.
 */
void scst_restart_cmd(struct scst_cmd *cmd, int status,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

	scst_set_restart_waiting_time(cmd);

	TRACE_DBG("Preferred context: %d", pref_context);
	TRACE_DBG("tag=%llu, status=%#x",
		  (unsigned long long int)scst_cmd_get_tag(cmd),
		  status);

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((in_irq() || irqs_disabled()) &&
	    ((pref_context == SCST_CONTEXT_DIRECT) ||
	     (pref_context == SCST_CONTEXT_DIRECT_ATOMIC))) {
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_THREAD instead", pref_context,
			cmd->tgtt->name);
		dump_stack();
		pref_context = SCST_CONTEXT_THREAD;
	}
#endif

	switch (status) {
	case SCST_PREPROCESS_STATUS_SUCCESS:
		if (unlikely(cmd->tgt_dev == NULL)) {
			cmd->state = SCST_CMD_STATE_PRE_XMIT_RESP;
			pref_context = SCST_CONTEXT_THREAD;
			break;
		} else if (cmd->data_direction & SCST_DATA_WRITE)
			cmd->state = SCST_CMD_STATE_RDY_TO_XFER;
		else
			cmd->state = SCST_CMD_STATE_TGT_PRE_EXEC;
		if (cmd->set_sn_on_restart_cmd) {
			EXTRACHECKS_BUG_ON(cmd->tgtt->multithreaded_init_done);
			scst_cmd_set_sn(cmd);
		}
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
		if (cmd->op_flags & SCST_TEST_IO_IN_SIRQ_ALLOWED)
			break;
#endif
		/* Small context optimization */
		if ((pref_context == SCST_CONTEXT_TASKLET) ||
		    (pref_context == SCST_CONTEXT_DIRECT_ATOMIC) ||
		    ((pref_context == SCST_CONTEXT_SAME) &&
		     scst_cmd_atomic(cmd)))
			pref_context = SCST_CONTEXT_THREAD;
		break;

	case SCST_PREPROCESS_STATUS_ERROR_SENSE_SET:
		scst_set_cmd_abnormal_done_state(cmd);
		pref_context = SCST_CONTEXT_THREAD;
		break;

	case SCST_PREPROCESS_STATUS_ERROR_FATAL:
		set_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
		set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
		cmd->delivery_status = SCST_CMD_DELIVERY_FAILED;
		/* go through */
	case SCST_PREPROCESS_STATUS_ERROR:
		if (cmd->sense != NULL)
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
		pref_context = SCST_CONTEXT_THREAD;
		break;

	default:
		PRINT_ERROR("%s() received unknown status %x", __func__,
			status);
		scst_set_cmd_abnormal_done_state(cmd);
		pref_context = SCST_CONTEXT_THREAD;
		break;
	}

	scst_process_redirect_cmd(cmd, pref_context, 1);

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
#ifndef CONFIG_SCST_TEST_IO_IN_SIRQ
		/* We can't allow atomic command on the exec stages */
		if (scst_cmd_atomic(cmd)) {
			TRACE_DBG("NULL rdy_to_xfer() and atomic context, "
				"rescheduling (cmd %p)", cmd);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
		} else
#endif
			res = SCST_CMD_STATE_RES_CONT_SAME;
		goto out;
	}

	if (unlikely(!tgtt->rdy_to_xfer_atomic && scst_cmd_atomic(cmd))) {
		/*
		 * It shouldn't be because of the SCST_TGT_DEV_AFTER_*
		 * optimization.
		 */
		TRACE_MGMT_DBG("Target driver %s rdy_to_xfer() needs thread "
			"context, rescheduling", tgtt->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

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

	scst_set_cur_start(cmd);

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

	scst_set_rdy_to_xfer_time(cmd);

	cmd->cmd_hw_pending = 0;

	/* Restore the previous state */
	cmd->state = SCST_CMD_STATE_RDY_TO_XFER;

	switch (rc) {
	case SCST_TGT_RES_QUEUE_FULL:
		scst_queue_retry_cmd(cmd);
		goto out;

	case SCST_TGT_RES_NEED_THREAD_CTX:
		TRACE_DBG("Target driver %s "
		      "rdy_to_xfer() requested thread "
		      "context, rescheduling", tgtt->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;

	default:
		goto out_error_rc;
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
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_write_error));

out_dev_done:
	scst_set_cmd_abnormal_done_state(cmd);
	res = SCST_CMD_STATE_RES_CONT_SAME;
	goto out;
}

/* No locks, but might be in IRQ */
static void scst_process_redirect_cmd(struct scst_cmd *cmd,
	enum scst_exec_context context, int check_retries)
{
	struct scst_tgt *tgt = cmd->tgt;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_DBG("Context: %x", context);

	if (check_retries)
		scst_check_retries(tgt);

	if (context == SCST_CONTEXT_SAME)
		context = scst_cmd_atomic(cmd) ? SCST_CONTEXT_DIRECT_ATOMIC :
						 SCST_CONTEXT_DIRECT;

	switch (context) {
	case SCST_CONTEXT_DIRECT_ATOMIC:
		scst_process_active_cmd(cmd, true);
		break;

	case SCST_CONTEXT_DIRECT:
		scst_process_active_cmd(cmd, false);
		break;

	case SCST_CONTEXT_TASKLET:
		scst_schedule_tasklet(cmd);
		break;

	default:
		PRINT_ERROR("Context %x is unknown, using the thread one",
			    context);
		/* go through */
	case SCST_CONTEXT_THREAD:
	{
		struct list_head *active_cmd_list;
		if (cmd->cmd_thr != NULL) {
			TRACE_DBG("Using assigned thread %p for cmd %p",
				cmd->cmd_thr, cmd);
			active_cmd_list = &cmd->cmd_thr->thr_active_cmd_list;
			spin_lock_irqsave(&cmd->cmd_thr->thr_cmd_list_lock, flags);
		} else {
			active_cmd_list = &cmd->cmd_threads->active_cmd_list;
			spin_lock_irqsave(&cmd->cmd_threads->cmd_list_lock, flags);
		}
		TRACE_DBG("Adding cmd %p to active cmd list", cmd);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry, active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry, active_cmd_list);
		if (cmd->cmd_thr != NULL) {
			wake_up_process(cmd->cmd_thr->cmd_thread);
			spin_unlock_irqrestore(&cmd->cmd_thr->thr_cmd_list_lock, flags);
		} else {
			wake_up(&cmd->cmd_threads->cmd_list_waitQ);
			spin_unlock_irqrestore(&cmd->cmd_threads->cmd_list_lock, flags);
		}
		break;
	}
	}

	TRACE_EXIT();
	return;
}

/**
 * scst_rx_data() - the command's data received
 * @cmd:	SCST commands
 * @status:	data receiving completion status
 * @pref_context: preferred command execution context
 *
 * Description:
 *    Notifies SCST that the driver received all the necessary data
 *    and the command is ready for further processing.
 *
 *    The second argument sets data receiving completion status
 *    (see SCST_RX_STATUS_* constants for details)
 */
void scst_rx_data(struct scst_cmd *cmd, int status,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

	scst_set_rdy_to_xfer_time(cmd);

	TRACE_DBG("Preferred context: %d", pref_context);

	cmd->cmd_hw_pending = 0;

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((in_irq() || irqs_disabled()) &&
	    ((pref_context == SCST_CONTEXT_DIRECT) ||
	     (pref_context == SCST_CONTEXT_DIRECT_ATOMIC))) {
		PRINT_ERROR("Wrong context %d in IRQ from target %s, use "
			"SCST_CONTEXT_THREAD instead", pref_context,
			cmd->tgtt->name);
		dump_stack();
		pref_context = SCST_CONTEXT_THREAD;
	}
#endif

	switch (status) {
	case SCST_RX_STATUS_SUCCESS:
		cmd->state = SCST_CMD_STATE_TGT_PRE_EXEC;

#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
		if (cmd->op_flags & SCST_TEST_IO_IN_SIRQ_ALLOWED)
			break;
#endif

		/*
		 * Make sure that the exec phase runs in thread context since
		 * invoking I/O functions from atomic context is not allowed.
		 */
		if ((pref_context == SCST_CONTEXT_TASKLET) ||
		    (pref_context == SCST_CONTEXT_DIRECT_ATOMIC) ||
		    ((pref_context == SCST_CONTEXT_SAME) &&
		     scst_cmd_atomic(cmd)))
			pref_context = SCST_CONTEXT_THREAD;
		break;

	case SCST_RX_STATUS_ERROR_SENSE_SET:
		TRACE(TRACE_SCSI, "cmd %p, RX data error status %#x", cmd, status);
		if (!cmd->write_not_received_set)
			scst_cmd_set_write_no_data_received(cmd);
		scst_set_cmd_abnormal_done_state(cmd);
		pref_context = SCST_CONTEXT_THREAD;
		break;

	case SCST_RX_STATUS_ERROR_FATAL:
		set_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
		set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
		cmd->delivery_status = SCST_CMD_DELIVERY_FAILED;
		/* go through */
	case SCST_RX_STATUS_ERROR:
		TRACE(TRACE_SCSI, "cmd %p, RX data error status %#x", cmd, status);
		if (!cmd->write_not_received_set)
			scst_cmd_set_write_no_data_received(cmd);
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
		pref_context = SCST_CONTEXT_THREAD;
		break;

	default:
		PRINT_ERROR("scst_rx_data() received unknown status %x",
			status);
		if (!cmd->write_not_received_set)
			scst_cmd_set_write_no_data_received(cmd);
		scst_set_cmd_abnormal_done_state(cmd);
		pref_context = SCST_CONTEXT_THREAD;
		break;
	}

	scst_process_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_rx_data);

static int scst_tgt_pre_exec(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME, rc;

	TRACE_ENTRY();

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (unlikely(trace_flag & TRACE_DATA_RECEIVED) &&
	    (cmd->data_direction & SCST_DATA_WRITE)) {
		int i, sg_cnt;
		struct scatterlist *sg, *sgi;

		if (cmd->out_sg != NULL) {
			sg = cmd->out_sg;
			sg_cnt = cmd->out_sg_cnt;
		} else if (cmd->tgt_out_sg != NULL) {
			sg = cmd->tgt_out_sg;
			sg_cnt = cmd->tgt_out_sg_cnt;
		} else if (cmd->tgt_i_sg != NULL) {
			sg = cmd->tgt_i_sg;
			sg_cnt = cmd->tgt_i_sg_cnt;
		} else {
			sg = cmd->sg;
			sg_cnt = cmd->sg_cnt;
		}
		if (sg != NULL) {
			PRINT_INFO("Received data for cmd %p (sg_cnt %d, "
				"sg %p, sg[0].page %p)", cmd, sg_cnt, sg,
				(void *)sg_page(&sg[0]));
			for_each_sg(sg, sgi, sg_cnt, i) {
				PRINT_INFO("sg %d", i);
				PRINT_BUFFER("data", sg_virt(sgi), sgi->length);
			}
		}
	}
#endif

	if (unlikely(cmd->resid_possible)) {
		if (cmd->data_direction & SCST_DATA_WRITE) {
			bool remainder = false;

			if (cmd->data_direction & SCST_DATA_READ) {
				if (cmd->write_len != cmd->out_bufflen)
					remainder = true;
			} else {
				if (cmd->write_len != cmd->bufflen)
					remainder = true;
			}
			if (remainder) {
				if (!(cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED) ||
				    (cmd->write_len & ((1 << cmd->dev->block_shift) - 1)) == 0) {
#if 0 /* dangerous, because can override valid data by zeros */
					scst_check_restore_sg_buff(cmd);
					scst_zero_write_rest(cmd);
#else
					/* do nothing */
#endif
				} else {
					/*
					 * Looks like it's safer in this case to
					 * return error instead of zeroing
					 * the rest to prevent initiators lost
					 * in 4K and 512 bytes blocks, i.e.
					 * sending commands on 4K blocks devices
					 * thinking that they have 512 bytes
					 * blocks, from corrupting data.
					 */
					scst_set_cmd_error(cmd,
						SCST_LOAD_SENSE(scst_sense_invalid_field_in_command_information_unit));
					scst_set_cmd_abnormal_done_state(cmd);
					goto out;
				}
			}
		}
	}

	cmd->state = SCST_CMD_STATE_EXEC_CHECK_SN;

	if (unlikely(cmd->internal)) {
		if (cmd->dh_data_buf_alloced && cmd->tgt_i_data_buf_alloced &&
		    (scst_cmd_get_data_direction(cmd) & SCST_DATA_WRITE)) {
			TRACE_DBG("Internal WRITE cmd %p with DH alloced data",
				cmd);
			scst_copy_sg(cmd, SCST_SG_COPY_FROM_TARGET);
		}
		goto out_descr;
	}

	if (cmd->tgtt->pre_exec == NULL)
		goto out_descr;

	TRACE_DBG("Calling pre_exec(%p)", cmd);
	scst_set_cur_start(cmd);
	rc = cmd->tgtt->pre_exec(cmd);
	scst_set_pre_exec_time(cmd);
	TRACE_DBG("pre_exec() returned %d", rc);

	if (unlikely(rc != SCST_PREPROCESS_STATUS_SUCCESS)) {
		switch (rc) {
		case SCST_PREPROCESS_STATUS_ERROR_SENSE_SET:
			scst_set_cmd_abnormal_done_state(cmd);
			goto out;
		case SCST_PREPROCESS_STATUS_ERROR_FATAL:
			set_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
			set_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags);
			cmd->delivery_status = SCST_CMD_DELIVERY_FAILED;
			/* go through */
		case SCST_PREPROCESS_STATUS_ERROR:
			scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
			scst_set_cmd_abnormal_done_state(cmd);
			goto out;
		default:
			sBUG();
		}
	}

out_descr:
	if (unlikely(cmd->op_flags & SCST_DESCRIPTORS_BASED)) {
		int r = scst_parse_descriptors(cmd);

		if (unlikely(r != 0))
			goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void scst_do_cmd_done(struct scst_cmd *cmd, int result,
	const uint8_t *rq_sense, int rq_sense_len, int resid)
{
	TRACE_ENTRY();

	scst_set_exec_time(cmd);

	cmd->status = result & 0xff;
	cmd->msg_status = msg_byte(result);
	cmd->host_status = host_byte(result);
	cmd->driver_status = driver_byte(result);
	if (unlikely(resid != 0)) {
		if ((cmd->data_direction & SCST_DATA_READ) &&
		    (resid > 0) && (resid < cmd->resp_data_len))
			scst_set_resp_data_len(cmd, cmd->resp_data_len - resid);
		/*
		 * We ignore write direction residue, because from the
		 * initiator's POV we have already transferred all the data.
		 */
	}

	if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION)) {
		/* We might have double reset UA here */
		cmd->dbl_ua_orig_resp_data_len = cmd->resp_data_len;
		cmd->dbl_ua_orig_data_direction = cmd->data_direction;

		scst_alloc_set_sense(cmd, 1, rq_sense, rq_sense_len);
	}

	TRACE(TRACE_SCSI, "cmd %p, result %x, cmd->status %x, resid %d, "
	      "cmd->msg_status %x, cmd->host_status %x, "
	      "cmd->driver_status %x", cmd, result, cmd->status, resid,
	      cmd->msg_status, cmd->host_status, cmd->driver_status);

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
		if (!cmd->tgt_dev->tgt_dev_after_exec_atomic)
			context = SCST_CONTEXT_THREAD;
	}
	return context;
}

/**
 * scst_pass_through_cmd_done - done callback for pass-through commands
 * @data:	private opaque data
 * @sense:	pointer to the sense data, if any
 * @result:	command's execution result
 * @resid:	residual, if any
 */
void scst_pass_through_cmd_done(void *data, char *sense, int result, int resid)
{
	struct scst_cmd *cmd = data;

	TRACE_ENTRY();

	if (cmd == NULL)
		goto out;

	TRACE_DBG("cmd %p; CDB[0/%d] %#x: result %d; resid %d", cmd,
		  cmd->cdb_len, cmd->cdb[0], result, resid);

	scst_do_cmd_done(cmd, result, sense, SCSI_SENSE_BUFFERSIZE, resid);

	cmd->state = SCST_CMD_STATE_PRE_DEV_DONE;

	scst_process_redirect_cmd(cmd,
	    scst_optimize_post_exec_context(cmd, scst_estimate_context()), 0);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_pass_through_cmd_done);

static void scst_cmd_done_local(struct scst_cmd *cmd, int next_state,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

	scst_set_exec_time(cmd);

	TRACE(TRACE_SCSI, "cmd %p, status %x, msg_status %x, host_status %x, "
	      "driver_status %x, resp_data_len %d", cmd, cmd->status,
	      cmd->msg_status, cmd->host_status, cmd->driver_status,
	      cmd->resp_data_len);

	if (next_state == SCST_CMD_STATE_DEFAULT)
		next_state = SCST_CMD_STATE_PRE_DEV_DONE;

	cmd->state = next_state;

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((next_state != SCST_CMD_STATE_PRE_DEV_DONE) &&
	    (next_state != SCST_CMD_STATE_PRE_XMIT_RESP1) &&
	    (next_state != SCST_CMD_STATE_PRE_XMIT_RESP2) &&
	    (next_state != SCST_CMD_STATE_FINISHED) &&
	    (next_state != SCST_CMD_STATE_FINISHED_INTERNAL)) {
		PRINT_ERROR("%s() received invalid cmd state %d (opcode %s)",
			__func__, next_state, scst_get_opcode_name(cmd));
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
	}
#endif
	pref_context = scst_optimize_post_exec_context(cmd, pref_context);
	scst_process_redirect_cmd(cmd, pref_context, 0);

	TRACE_EXIT();
	return;
}

static int scst_report_luns_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
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

	if ((cmd->cdb[2] != 0) && (cmd->cdb[2] != 2)) {
		TRACE(TRACE_MINOR, "Unsupported SELECT REPORT value %#x in "
			"REPORT LUNS command", cmd->cdb[2]);
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

	/*
	 * cmd won't allow to suspend activities, so we can access
	 * sess->sess_tgt_dev_list without any additional protection.
	 */
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &cmd->sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			if (!overflow) {
				if ((buffer_size - offs) < 8) {
					overflow = 1;
					goto inc_dev_cnt;
				}
				*(__force __be64 *)&buffer[offs]
					= scst_pack_lun(tgt_dev->lun,
						cmd->sess->acg->addr_method);
				offs += 8;
			}
inc_dev_cnt:
			dev_cnt++;
		}
	}

	/* Set the response header */
	dev_cnt *= 8;
	put_unaligned_be32(dev_cnt, buffer);

	scst_put_buf_full(cmd, buffer);

	dev_cnt += 8;
	if (dev_cnt < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, dev_cnt);

out_compl:
	cmd->completed = 1;

	/* Clear left sense_reported_luns_data_changed UA, if any. */

	/*
	 * cmd won't allow to suspend activities, so we can access
	 * sess->sess_tgt_dev_list without any additional protection.
	 */
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &cmd->sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			struct scst_tgt_dev_UA *ua;

			spin_lock_bh(&tgt_dev->tgt_dev_lock);
			list_for_each_entry(ua, &tgt_dev->UA_list,
						UA_list_entry) {
				if (scst_analyze_sense(ua->UA_sense_buffer,
						ua->UA_valid_sense_len,
						SCST_SENSE_ALL_VALID,
						SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed))) {
					TRACE_DBG("Freeing not needed "
						"REPORTED LUNS DATA CHANGED UA "
						"%p", ua);
					scst_tgt_dev_del_free_UA(tgt_dev, ua);
					break;
				}
			}
			spin_unlock_bh(&tgt_dev->tgt_dev_lock);
		}
	}

	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

	TRACE_EXIT_RES(res);
	return res;

out_put_err:
	scst_put_buf_full(cmd, buffer);
	goto out_compl;
}

static int scst_request_sense_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
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
			if (buf == NULL)
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
		PRINT_WARNING("%s: Fixed format of the saved sense, but "
			"descriptor format requested. Conversion will "
			"truncated data", cmd->op_name);
		PRINT_BUFFER("Original sense", tgt_dev->tgt_dev_sense,
			tgt_dev->tgt_dev_valid_sense_len);

		buffer_size = min(SCST_STANDARD_SENSE_LEN, buffer_size);
		sl = scst_set_sense(buffer, buffer_size, true,
			tgt_dev->tgt_dev_sense[2], tgt_dev->tgt_dev_sense[12],
			tgt_dev->tgt_dev_sense[13]);
	} else if (((scst_sense_response_code(tgt_dev->tgt_dev_sense) == 0x72) ||
		    (scst_sense_response_code(tgt_dev->tgt_dev_sense) == 0x73)) &&
		   !(cmd->cdb[1] & 1)) {
		PRINT_WARNING("%s: Descriptor format of the "
			"saved sense, but fixed format requested. Conversion "
			"will truncate data", cmd->op_name);
		PRINT_BUFFER("Original sense", tgt_dev->tgt_dev_sense,
			tgt_dev->tgt_dev_valid_sense_len);

		buffer_size = min(SCST_STANDARD_SENSE_LEN, buffer_size);
		sl = scst_set_sense(buffer, buffer_size, false,
			tgt_dev->tgt_dev_sense[1], tgt_dev->tgt_dev_sense[2],
			tgt_dev->tgt_dev_sense[3]);
	} else {
		if (buffer_size >= tgt_dev->tgt_dev_valid_sense_len)
			sl = tgt_dev->tgt_dev_valid_sense_len;
		else {
			sl = buffer_size;
			TRACE(TRACE_SCSI|TRACE_MINOR, "%s: Being returned sense "
				"truncated to size %d (needed %d)", cmd->op_name,
				buffer_size, tgt_dev->tgt_dev_valid_sense_len);
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

static int scst_report_supported_tm_fns(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
	int length, resp_len = 0;
	uint8_t *address;
	uint8_t buf[16];

	TRACE_ENTRY();

	length = scst_get_buf_full_sense(cmd, &address);
	TRACE_DBG("length %d", length);
	if (unlikely(length <= 0))
		goto out_compl;

	memset(buf, 0, sizeof(buf));

	buf[0] = 0xD8; /* ATS, ATSS, CTSS, LURS */
	buf[1] = 0;
	if ((cmd->cdb[2] & 0x80) == 0)
		resp_len = 4;
	else {
		buf[3] = 0x0C;
#if 1
		buf[4] = 1; /* TMFTMOV */
		buf[6] = 0x80; /* ATTS */
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

static int scst_report_supported_opcodes(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
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
					TRACE(TRACE_MINOR, "Requested opcode %x "
						"with unexpected service action "
						"(dev %s, initiator %s)",
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
		if (op == NULL) {
			TRACE(TRACE_MINOR, "Requested opcode %x not found "
				"(dev %s, initiator %s)", req_opcode,
				cmd->dev->virt_name, cmd->sess->initiator_name);
			buf_len = 4;
		}
		break;
	case 2:
		buf_len = 0;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			if (req_opcode == supp_opcodes[i]->od_opcode) {
				op = supp_opcodes[i];
				if (!op->od_serv_action_valid) {
					TRACE(TRACE_MINOR, "Requested opcode %x "
						"without expected service action "
						"(dev %s, initiator %s)",
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
		if (op == NULL) {
			TRACE(TRACE_MINOR, "Requested opcode %x/%x not found "
				"(dev %s, initiator %s)", req_opcode, req_sa,
				cmd->dev->virt_name, cmd->sess->initiator_name);
			buf_len = 4;
		}
		break;
	default:
		PRINT_ERROR("REPORT SUPPORTED OPERATION CODES: REPORTING OPTIONS "
			"%x not supported (dev %s, initiator %s)", options,
			cmd->dev->virt_name, cmd->sess->initiator_name);
		scst_set_invalid_field_in_cdb(cmd, 2,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
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
		if (buf == NULL) {
			PRINT_ERROR("Unable to allocate REPORT SUPPORTED "
				"OPERATION CODES buffer with size %d", buf_len);
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
		if (op != NULL) {
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
	if ((supp_opcodes != NULL) && (cmd->devt->put_supported_opcodes != NULL))
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

static int scst_maintenance_in(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	switch (cmd->cdb[1] & 0x1f) {
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

static int scst_reserve_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
	struct scst_device *dev;
	struct scst_lksb pr_lksb;

	TRACE_ENTRY();

	if ((cmd->cdb[0] == RESERVE_10) && (cmd->cdb[2] & SCST_RES_3RDPTY)) {
		PRINT_ERROR("RESERVE_10: 3rdPty RESERVE not implemented "
		     "(lun=%lld)", (unsigned long long int)cmd->lun);
		scst_set_invalid_field_in_cdb(cmd, 2,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
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
		else {
			scst_set_cmd_error_status(cmd,
				SAM_STAT_RESERVATION_CONFLICT);
			goto out_done;
		}
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

static int scst_release_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
	struct scst_device *dev;
	struct scst_lksb pr_lksb;

	TRACE_ENTRY();

	dev = cmd->dev;

	/*
	 * See comment in scst_reserve_local() why no dev blocking or any
	 * other protection is needed here.
	 */

	if (!list_empty(&dev->dev_registrants_list)) {
		if (scst_pr_crh_case(cmd))
			goto out_completed;
		else {
			scst_set_cmd_error_status(cmd,
				SAM_STAT_RESERVATION_CONFLICT);
			goto out_done;
		}
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
static int scst_persistent_reserve_in_local(struct scst_cmd *cmd)
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

	if (unlikely(dev->not_pr_supporting_tgt_devs_num != 0)) {
		PRINT_WARNING("Persistent Reservation command %s refused for "
			"device %s, because the device has not supporting PR "
			"transports connected", scst_get_opcode_name(cmd),
			dev->virt_name);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	if (scst_dev_reserved(dev)) {
		TRACE_PR("PR command rejected, because device %s holds regular "
			"reservation", dev->virt_name);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_done;
	}

#ifndef CONFIG_SCST_FORWARD_MODE_PASS_THROUGH
	if (dev->scsi_dev != NULL) {
		PRINT_WARNING("PR commands for pass-through devices not "
			"supported (device %s)", dev->virt_name);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}
#endif

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
	scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
	goto out_complete;
}

/* No locks, no IRQ or IRQ-disabled context allowed */
static int scst_persistent_reserve_out_local(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
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

	if (unlikely(dev->not_pr_supporting_tgt_devs_num != 0)) {
		PRINT_WARNING("Persistent Reservation command %s refused for "
			"device %s, because the device has not supporting PR "
			"transports connected", scst_get_opcode_name(cmd),
			dev->virt_name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out_done;
	}

	action = cmd->cdb[1] & 0x1f;

	TRACE(TRACE_SCSI, "PR OUT action %x for '%s' (LUN %llx) from '%s'",
		action, dev->virt_name, tgt_dev->lun, session->initiator_name);

	if (scst_dev_reserved(dev)) {
		TRACE_PR("PR command rejected, because device %s holds regular "
			"reservation", dev->virt_name);
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
	if ((action != PR_REGISTER) && (action != PR_REGISTER_AND_IGNORE) &&
	    (tgt_dev->registrant == NULL)) {
		TRACE_PR("'%s' not registered", cmd->sess->initiator_name);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out_unlock;
	}

	/* Check scope */
	if ((action != PR_REGISTER) && (action != PR_REGISTER_AND_IGNORE) &&
	    (action != PR_CLEAR) && (cmd->cdb[2] >> 4) != SCOPE_LU) {
		TRACE_PR("Scope must be SCOPE_LU for action %x", action);
		scst_set_invalid_field_in_cdb(cmd, 2,
				SCST_INVAL_FIELD_BIT_OFFS_VALID | 4);
		goto out_unlock;
	}

	/* Check SPEC_I_PT (PR_REGISTER_AND_MOVE has another format) */
	if ((action != PR_REGISTER) && (action != PR_REGISTER_AND_MOVE) &&
	    ((buffer[20] >> 3) & 0x01)) {
		TRACE_PR("SPEC_I_PT must be zero for action %x", action);
		scst_set_invalid_field_in_parm_list(cmd, 20,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 3);
		goto out_unlock;
	}

	/* Check ALL_TG_PT (PR_REGISTER_AND_MOVE has another format) */
	if ((action != PR_REGISTER) && (action != PR_REGISTER_AND_IGNORE) &&
	    (action != PR_REGISTER_AND_MOVE) && ((buffer[20] >> 2) & 0x01)) {
		TRACE_PR("ALL_TG_PT must be zero for action %x", action);
		scst_set_invalid_field_in_parm_list(cmd, 20,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 2);
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
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out_unlock;
	}

#ifndef CONFIG_SCST_PROC
	if (cmd->status == SAM_STAT_GOOD)
		scst_pr_sync_device_file(dev);
#endif

	if ((cmd->devt->pr_cmds_notifications) &&
	    (cmd->status == SAM_STAT_GOOD)) /* sync file may change status */
		res = SCST_EXEC_NOT_COMPLETED;

out_unlock:
	dev->cl_ops->pr_write_unlock(dev, &pr_lksb);

	scst_put_buf_full(cmd, buffer);

out_done:
	if (res == SCST_EXEC_COMPLETED) {
		if (!aborted)
			cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
				SCST_CONTEXT_SAME);
	}

	TRACE_EXIT_RES(res);
	return res;
}

/**
 * __scst_check_local_events() - check if there are any local SCSI events
 *
 * Description:
 *    Checks if the command can be executed or there are local events,
 *    like reservations, pending UAs, etc. Returns < 0 if command must be
 *    aborted, > 0 if there is an event and command should be immediately
 *    completed, or 0 otherwise.
 *
 * On call no locks, no IRQ or IRQ-disabled context allowed.
 */
int __scst_check_local_events(struct scst_cmd *cmd, bool preempt_tests_only)
{
	int res, rc;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	if (unlikely(cmd->internal && !cmd->internal_check_local_events)) {
		if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
			TRACE_MGMT_DBG("ABORTED set, aborting internal "
				"cmd %p", cmd);
			goto out_uncomplete;
		}
		/*
		 * The original command passed all checks and not finished yet
		 */
		res = 0;
		goto out;
	}

	if (unlikely(test_bit(SCST_TGT_DEV_FORWARDING, &cmd->tgt_dev->tgt_dev_flags))) {
		/*
		 * All the checks are supposed to be done on the
		 * forwarding requester's side.
		 */
		res = 0;
		goto out;
	}

	/*
	 * There's no race here, because we need to trace commands sent
	 * *after* dev_double_ua_possible flag was set.
	 */
	if (unlikely(dev->dev_double_ua_possible))
		cmd->double_ua_possible = 1;

	/* Reserve check before Unit Attention */
	if (unlikely(scst_is_not_reservation_holder(dev, tgt_dev->sess))) {
		if ((cmd->op_flags & SCST_REG_RESERVE_ALLOWED) == 0) {
			scst_set_cmd_error_status(cmd,
				SAM_STAT_RESERVATION_CONFLICT);
			goto out_complete;
		}
	}

	if (!preempt_tests_only) {
		if (dev->cl_ops->pr_is_set(dev)) {
			if (unlikely(!scst_pr_is_cmd_allowed(cmd))) {
				scst_set_cmd_error_status(cmd,
					SAM_STAT_RESERVATION_CONFLICT);
				goto out_complete;
			}
		}
	}

	/*
	 * Let's check for ABORTED after scst_pr_is_cmd_allowed(), because
	 * we might sleep for a while there.
	 */
	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("ABORTED set, aborting cmd %p", cmd);
		goto out_uncomplete;
	}

	/* If we had internal bus reset, set the command error unit attention */
	if ((dev->scsi_dev != NULL) &&
	    unlikely(dev->scsi_dev->was_reset)) {
		if ((cmd->op_flags & SCST_SKIP_UA) == 0) {
			int done = 0;
			/*
			 * Prevent more than 1 cmd to be triggered by was_reset
			 */
			spin_lock_bh(&dev->dev_lock);
			if (dev->scsi_dev->was_reset) {
				TRACE(TRACE_MGMT, "was_reset is %d", 1);
				scst_set_cmd_error(cmd,
					  SCST_LOAD_SENSE(scst_sense_reset_UA));
				/*
				 * It looks like it is safe to clear was_reset
				 * here
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
		if ((cmd->op_flags & SCST_SKIP_UA) == 0) {
			rc = scst_set_pending_UA(cmd, NULL, NULL);
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
EXPORT_SYMBOL_GPL(__scst_check_local_events);

/*
 * No locks. Returns true, if expected_sn was incremented.
 *
 * !! At this point cmd can be processed in parallel by some other thread!
 * !! As consecuence, no pointer in cmd, except cur_order_data and
 * !! sn_slot, can be touched here! The same is for assignments to cmd's
 * !! fields. As protection cmd declared as const.
 *
 * Overall, cmd is passed here only for extra correctness checking.
 */
bool scst_inc_expected_sn(const struct scst_cmd *cmd)
{
	bool res = false;
	struct scst_order_data *order_data = cmd->cur_order_data;
	atomic_t *slot = cmd->sn_slot;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(!cmd->sn_set);

#ifdef CONFIG_SCST_EXTRACHECKS
	sBUG_ON(test_bit(SCST_CMD_INC_EXPECTED_SN_PASSED, &cmd->cmd_flags));
	set_bit(SCST_CMD_INC_EXPECTED_SN_PASSED, &((struct scst_cmd *)cmd)->cmd_flags);
#endif

	/* Optimized for lockless fast path of sequence of SIMPLE commands */

	if (slot == NULL)
		goto ordered;

	TRACE_SN("Slot %zd, value %d", slot - order_data->sn_slots,
		atomic_read(slot));

	if (!atomic_dec_and_test(slot))
		goto out;

	/*
	 * atomic_dec_and_test() implies memory barrier to sync with
	 * scst_inc_cur_sn() for pending_simple_inc_expected_sn
	 */

	if (likely(order_data->pending_simple_inc_expected_sn == 0))
		goto out;

	spin_lock_irq(&order_data->sn_lock);

	if (unlikely(order_data->pending_simple_inc_expected_sn == 0))
		goto out_unlock;

	order_data->pending_simple_inc_expected_sn--;
	TRACE_SN("New dec pending_simple_inc_expected_sn: %d",
		order_data->pending_simple_inc_expected_sn);
	EXTRACHECKS_BUG_ON(order_data->pending_simple_inc_expected_sn < 0);

inc_expected_sn_locked:
	order_data->expected_sn++;
	/*
	 * Write must be before def_cmd_count read to be in
	 * sync with scst_post_exec_sn(). See comment in
	 * scst_exec_check_sn(). Just in case if spin_unlock() isn't
	 * memory a barrier. Although, checking of def_cmd_count
	 * is far from here, but who knows, let's be safer.
	 */
	smp_mb();
	TRACE_SN("New expected_sn: %d", order_data->expected_sn);
	res = true;

out_unlock:
	spin_unlock_irq(&order_data->sn_lock);

out:
	TRACE_EXIT_RES(res);
	return res;

ordered:
	/* SIMPLE command can have slot NULL as well, if there were no free slots */
	EXTRACHECKS_BUG_ON((cmd->queue_type != SCST_CMD_QUEUE_SIMPLE) &&
			   (cmd->queue_type != SCST_CMD_QUEUE_ORDERED));
	spin_lock_irq(&order_data->sn_lock);
	goto inc_expected_sn_locked;
}

/* No locks */
static struct scst_cmd *scst_post_exec_sn(struct scst_cmd *cmd,
	bool make_active)
{
	/* For HQ commands SN is not set */
	bool inc_expected_sn = !cmd->inc_expected_sn_on_done &&
			       cmd->sn_set && !cmd->retry;
	struct scst_cmd *res = NULL;

	TRACE_ENTRY();

	if (inc_expected_sn) {
		bool rc = scst_inc_expected_sn(cmd);

		if (!rc)
			goto out;
		if (make_active)
			scst_make_deferred_commands_active(cmd->cur_order_data);
		else
			res = scst_check_deferred_commands(cmd->cur_order_data, true);
	}

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* cmd must be additionally referenced to not die inside */
static int scst_do_real_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
	int rc;
	struct scst_device *dev = cmd->dev;
	struct scst_dev_type *devt = cmd->devt;
	struct io_context *old_ctx = NULL;
	bool ctx_changed = false;
	struct scsi_device *scsi_dev;

	TRACE_ENTRY();

	ctx_changed = scst_set_io_context(cmd, &old_ctx);

	cmd->state = SCST_CMD_STATE_EXEC_WAIT;

	if (devt->exec) {
		TRACE_DBG("Calling dev handler %s exec(%p)",
		      devt->name, cmd);
		scst_set_exec_start(cmd);
		res = devt->exec(cmd);
		TRACE_DBG("Dev handler %s exec() returned %d",
		      devt->name, res);

		if (res == SCST_EXEC_COMPLETED)
			goto out_complete;

		scst_set_exec_time(cmd);

		sBUG_ON(res != SCST_EXEC_NOT_COMPLETED);
	}

	scsi_dev = dev->scsi_dev;

	if (unlikely(scsi_dev == NULL)) {
		PRINT_ERROR("Command for virtual device must be "
			"processed by device handler (LUN %lld)!",
			(unsigned long long int)cmd->lun);
		goto out_error;
	}

	TRACE_DBG("Sending cmd %p to SCSI mid-level dev %d:%d:%d:%lld", cmd,
		  scsi_dev->host->host_no, scsi_dev->channel, scsi_dev->id,
		  (u64)scsi_dev->lun);

	scst_set_exec_start(cmd);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	rc = scst_exec_req(scsi_dev, cmd->cdb, cmd->cdb_len,
			cmd->data_direction, cmd->sg, cmd->bufflen,
			cmd->sg_cnt, cmd->timeout, cmd->retries, cmd,
			scst_pass_through_cmd_done, cmd->cmd_gfp_mask);
#else
	rc = scst_scsi_exec_async(cmd, cmd, scst_pass_through_cmd_done);
#endif
	if (unlikely(rc != 0)) {
		PRINT_ERROR("scst pass-through exec failed: %d", rc);
		/* "Sectors" are hardcoded as 512 bytes in the kernel */
		if (rc == -EINVAL &&
		    (cmd->bufflen >> 9) > queue_max_hw_sectors(scsi_dev->request_queue))
			PRINT_ERROR("Too low max_hw_sectors %d sectors on %s "
				"to serve command %s with bufflen %d bytes."
				"See README for more details.",
				queue_max_hw_sectors(scsi_dev->request_queue),
				dev->virt_name, scst_get_opcode_name(cmd),
				cmd->bufflen);
		goto out_error;
	}

out_complete:
	res = SCST_EXEC_COMPLETED;

	if (ctx_changed)
		scst_reset_io_context(cmd->tgt_dev, old_ctx);

	TRACE_EXIT_RES(res);
	return res;

out_error:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

	res = SCST_EXEC_COMPLETED;
	/* Report the result */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out_complete;
}

static inline int scst_real_exec(struct scst_cmd *cmd)
{
	int res, rc;

	TRACE_ENTRY();

	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_SAME != SCST_EXEC_NOT_COMPLETED);
	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_NEXT != SCST_EXEC_COMPLETED);

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	__scst_cmd_get(cmd);

	res = scst_do_real_exec(cmd);
	if (likely(res == SCST_EXEC_COMPLETED)) {
		scst_post_exec_sn(cmd, true);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
		if (cmd->dev->scsi_dev != NULL)
			generic_unplug_device(
				cmd->dev->scsi_dev->request_queue);
#endif
	} else
		sBUG();

	__scst_cmd_put(cmd);

	/* SCST_EXEC_* match SCST_CMD_STATE_RES_* */

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	res = SCST_CMD_STATE_RES_CONT_NEXT;
	goto out;
}

typedef int (*scst_local_exec_fn)(struct scst_cmd *cmd);

static scst_local_exec_fn scst_local_fns[256] = {
	[RESERVE] = scst_reserve_local,
	[RESERVE_10] = scst_reserve_local,
	[RELEASE] = scst_release_local,
	[RELEASE_10] = scst_release_local,
	[PERSISTENT_RESERVE_IN] = scst_persistent_reserve_in_local,
	[PERSISTENT_RESERVE_OUT] = scst_persistent_reserve_out_local,
	[REPORT_LUNS] = scst_report_luns_local,
	[REQUEST_SENSE] = scst_request_sense_local,
	[COMPARE_AND_WRITE] = scst_cmp_wr_local,
	[EXTENDED_COPY] = scst_cm_ext_copy_exec,
	[RECEIVE_COPY_RESULTS] = scst_cm_rcv_copy_res_exec,
	[MAINTENANCE_IN] = scst_maintenance_in,
};

static int scst_do_local_exec(struct scst_cmd *cmd)
{
	int res;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	/* Check READ_ONLY device status */
	if ((cmd->op_flags & SCST_WRITE_MEDIUM) &&
	    (tgt_dev->tgt_dev_rd_only || cmd->dev->swp)) {
		PRINT_WARNING("Attempt of write access to read-only device: "
			"initiator %s, LUN %lld, op %s",
			cmd->sess->initiator_name, cmd->lun,
			scst_get_opcode_name(cmd));
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_data_protect));
		goto out_done;
	}

	if ((cmd->op_flags & SCST_LOCAL_CMD) == 0) {
		res = SCST_EXEC_NOT_COMPLETED;
		goto out;
	}

	res = scst_local_fns[cmd->cdb[0]](cmd);

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
	int res, rc;

	TRACE_ENTRY();

	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_SAME != SCST_EXEC_NOT_COMPLETED);
	BUILD_BUG_ON(SCST_CMD_STATE_RES_CONT_NEXT != SCST_EXEC_COMPLETED);

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	__scst_cmd_get(cmd);

	res = scst_do_local_exec(cmd);
	if (likely(res == SCST_EXEC_NOT_COMPLETED))
		cmd->state = SCST_CMD_STATE_REAL_EXEC;
	else if (res == SCST_EXEC_COMPLETED)
		scst_post_exec_sn(cmd, true);
	else
		sBUG();

	__scst_cmd_put(cmd);

	/* SCST_EXEC_* match SCST_CMD_STATE_RES_* */

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	res = SCST_CMD_STATE_RES_CONT_NEXT;
	goto out;
}

static int scst_pre_exec_checks(struct scst_cmd *cmd)
{
	int res, rc;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->lba == SCST_DEF_LBA_DATA_LEN);
	EXTRACHECKS_BUG_ON(cmd->data_len == SCST_DEF_LBA_DATA_LEN);

	rc = __scst_check_local_events(cmd, false);
	if (unlikely(rc != 0))
		goto out_done;

	res = SCST_CMD_STATE_RES_CONT_SAME;

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	res = SCST_CMD_STATE_RES_CONT_NEXT;
	goto out;
}

static inline bool scst_check_alua(struct scst_cmd *cmd, int *out_res)
{
	int (*alua_filter)(struct scst_cmd *cmd);
	bool res = false;

	alua_filter = ACCESS_ONCE(cmd->tgt_dev->alua_filter);
	if (unlikely(alua_filter)) {
		int ac = alua_filter(cmd);

		if (ac != SCST_ALUA_CHECK_OK) {
			if (ac != SCST_ALUA_CHECK_DELAYED) {
				EXTRACHECKS_BUG_ON(cmd->status == 0);
				scst_set_cmd_abnormal_done_state(cmd);
				*out_res = SCST_CMD_STATE_RES_CONT_SAME;
			}
			res = true;
		}
	}

	return res;
}

static int scst_exec_check_blocking(struct scst_cmd **active_cmd)
{
	struct scst_cmd *cmd = *active_cmd;
	struct scst_cmd *ref_cmd;
	int res = SCST_CMD_STATE_RES_CONT_NEXT;

	TRACE_ENTRY();

	cmd->state = SCST_CMD_STATE_EXEC_CHECK_BLOCKING;

	if (unlikely(scst_check_alua(cmd, &res)))
		goto out;

	if (unlikely(scst_check_blocked_dev(cmd)))
		goto out;

	/* To protect tgt_dev */
	ref_cmd = cmd;
	__scst_cmd_get(ref_cmd);

	while (1) {
		int rc;

#ifdef CONFIG_SCST_DEBUG_SN
		if ((scst_random() % 120) == 7) {
			int t = scst_random() % 200;

			TRACE_SN("Delaying IO on %d ms", t);
			msleep(t);
		}
#endif
		/*
		 * After sent_for_exec set, scst_post_exec_sn() must be called
		 * before exiting this function!
		 */
		cmd->sent_for_exec = 1;
		/*
		 * To sync with scst_abort_cmd(). The above assignment must
		 * be before SCST_CMD_ABORTED test, done later in
		 * __scst_check_local_events(). It's far from here, so the order
		 * is virtually guaranteed, but let's have it just in case.
		 */
		smp_mb();

		cmd->scst_cmd_done = scst_cmd_done_local;

		rc = scst_pre_exec_checks(cmd);
		if (unlikely(rc != SCST_CMD_STATE_RES_CONT_SAME)) {
			EXTRACHECKS_BUG_ON(rc != SCST_CMD_STATE_RES_CONT_NEXT);
			EXTRACHECKS_BUG_ON(cmd->state == SCST_CMD_STATE_EXEC_CHECK_BLOCKING);
			goto done;
		}

		cmd->state = SCST_CMD_STATE_LOCAL_EXEC;

		rc = scst_do_local_exec(cmd);
		if (likely(rc == SCST_EXEC_NOT_COMPLETED)) {
			/* Nothing to do */
		} else {
			sBUG_ON(rc != SCST_EXEC_COMPLETED);
			goto done;
		}

		cmd->state = SCST_CMD_STATE_REAL_EXEC;

		rc = scst_do_real_exec(cmd);
		sBUG_ON(rc != SCST_EXEC_COMPLETED);

done:
		cmd = scst_post_exec_sn(cmd, false);
		if (cmd == NULL)
			break;

		EXTRACHECKS_BUG_ON(cmd->state != SCST_CMD_STATE_EXEC_CHECK_SN);

		cmd->state = SCST_CMD_STATE_EXEC_CHECK_BLOCKING;

		if (unlikely(scst_check_alua(cmd, &res)))
			goto out;

		if (unlikely(scst_check_blocked_dev(cmd)))
			break;

		__scst_cmd_put(ref_cmd);
		ref_cmd = cmd;
		__scst_cmd_get(ref_cmd);
	}

	*active_cmd = cmd;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
	if (ref_cmd->dev->scsi_dev != NULL)
		generic_unplug_device(ref_cmd->dev->scsi_dev->request_queue);
#endif

	__scst_cmd_put(ref_cmd);
	/* !! At this point sess, dev and tgt_dev can be already freed !! */

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_exec_check_sn(struct scst_cmd **active_cmd)
{
	int res;
	struct scst_cmd *cmd = *active_cmd;
	struct scst_order_data *order_data = cmd->cur_order_data;
	typeof(order_data->expected_sn) expected_sn;

	TRACE_ENTRY();

	if (unlikely(cmd->internal))
		goto exec;

	if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
		goto exec;

	EXTRACHECKS_BUG_ON(!cmd->sn_set);

	expected_sn = ACCESS_ONCE(order_data->expected_sn);
	/* Optimized for lockless fast path */
	if ((cmd->sn != expected_sn) || (order_data->hq_cmd_count > 0)) {
		spin_lock_irq(&order_data->sn_lock);

		order_data->def_cmd_count++;
		/*
		 * Memory barrier is needed here to implement lockless fast
		 * path. We need the exact order of reads and writes between
		 * def_cmd_count and expected_sn. Otherwise, we can miss case,
		 * when expected_sn was changed to be equal to cmd->sn while
		 * we are queueing cmd into the deferred list after expected_sn
		 * read below. It will lead to a forever stuck command. But with
		 * the barrier in such case __scst_check_deferred_commands()
		 * will be called and it will take sn_lock, so we will be
		 * synchronized.
		 */
		smp_mb();

		expected_sn = order_data->expected_sn;
		if ((cmd->sn != expected_sn) || (order_data->hq_cmd_count > 0)) {
			if (unlikely(test_bit(SCST_CMD_ABORTED,
					      &cmd->cmd_flags))) {
				/* Necessary to allow aborting out of sn cmds */
				TRACE_MGMT_DBG("Aborting out of sn cmd %p "
					"(tag %llu, sn %u)", cmd,
					(unsigned long long)cmd->tag, cmd->sn);
				order_data->def_cmd_count--;
				scst_set_cmd_abnormal_done_state(cmd);
				res = SCST_CMD_STATE_RES_CONT_SAME;
			} else {
				TRACE_SN("Deferring cmd %p (sn=%d, set %d, "
					"expected_sn=%d)", cmd, cmd->sn,
					cmd->sn_set, expected_sn);
				list_add_tail(&cmd->deferred_cmd_list_entry,
					      &order_data->deferred_cmd_list);
				res = SCST_CMD_STATE_RES_CONT_NEXT;
			}
			spin_unlock_irq(&order_data->sn_lock);
			goto out;
		} else {
			TRACE_SN("Somebody incremented expected_sn %d, "
				"continuing", expected_sn);
			order_data->def_cmd_count--;
			spin_unlock_irq(&order_data->sn_lock);
		}
	}

exec:
	res = scst_exec_check_blocking(active_cmd);

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

	if (unlikely(cmd->ua_ignore)) {
		PRINT_BUFF_FLAG(TRACE_SCSI, "Local UA sense", cmd->sense,
			cmd->sense_valid_len);
		goto out;
	}

	/* If we had internal bus reset behind us, set the command error UA */
	if ((dev->scsi_dev != NULL) &&
	    unlikely(cmd->host_status == DID_RESET)) {
		if ((cmd->op_flags & SCST_SKIP_UA) == 0) {
			TRACE(TRACE_MGMT, "DID_RESET: was_reset=%d host_status=%x",
			      dev->scsi_dev->was_reset, cmd->host_status);
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_reset_UA));
		} else {
			int sl;
			uint8_t sense[SCST_STANDARD_SENSE_LEN];

			TRACE(TRACE_MGMT, "DID_RESET received for device %s, "
				"triggering reset UA", dev->virt_name);
			sl = scst_set_sense(sense, sizeof(sense), dev->d_sense,
				SCST_LOAD_SENSE(scst_sense_reset_UA));
			scst_dev_check_set_UA(dev, NULL, sense, sl);
			scst_abort_cmd(cmd, NULL, false, false);
		}
		/* It looks like it is safe to clear was_reset here */
		dev->scsi_dev->was_reset = 0;
	}

	if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION) &&
	    scst_sense_valid(cmd->sense)) {
		TRACE(TRACE_SCSI, "cmd %p with valid sense received", cmd);
		PRINT_BUFF_FLAG(TRACE_SCSI, "Sense", cmd->sense,
			cmd->sense_valid_len);

		/* Check Unit Attention Sense Key */
		if (scst_is_ua_sense(cmd->sense, cmd->sense_valid_len)) {
			if (scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
					SCST_SENSE_ASC_VALID,
					0, SCST_SENSE_ASC_UA_RESET, 0)) {
				if (cmd->double_ua_possible) {
					TRACE_DBG("Double UA "
						"detected for device %p", dev);
					TRACE_DBG("Retrying cmd"
						" %p (tag %llu)", cmd,
						(unsigned long long)cmd->tag);

					cmd->status = 0;
					cmd->msg_status = 0;
					cmd->host_status = DID_OK;
					cmd->driver_status = 0;
					cmd->completed = 0;

					mempool_free(cmd->sense,
						     scst_sense_mempool);
					cmd->sense = NULL;

					scst_check_restore_sg_buff(cmd);
					if (cmd->data_direction & SCST_DATA_WRITE)
						scst_set_write_len(cmd);

					sBUG_ON(cmd->dbl_ua_orig_resp_data_len < 0);
					cmd->data_direction =
						cmd->dbl_ua_orig_data_direction;
					cmd->resp_data_len =
						cmd->dbl_ua_orig_resp_data_len;

					cmd->state = SCST_CMD_STATE_LOCAL_EXEC;
					cmd->retry = 1;
					res = 1;
					goto out;
				}
			}
			scst_dev_check_set_UA(dev, cmd,	cmd->sense,
				cmd->sense_valid_len);
		}
	}

	if (unlikely(cmd->double_ua_possible)) {
		if ((cmd->op_flags & SCST_SKIP_UA) == 0) {
			TRACE_DBG("Clearing dbl_ua_possible flag (dev %p, "
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

static bool scst_check_auto_sense(struct scst_cmd *cmd)
{
	bool res = false;

	TRACE_ENTRY();

	if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION) &&
	    !scst_sense_valid(cmd->sense)) {
		if (!test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
			TRACE(TRACE_SCSI|TRACE_MINOR_AND_MGMT_DBG,
				"CHECK_CONDITION, but no sense: cmd->status=%x, "
				"cmd->msg_status=%x, cmd->host_status=%x, "
				"cmd->driver_status=%x (cmd %p)",
				cmd->status, cmd->msg_status, cmd->host_status,
				cmd->driver_status, cmd);
		}
		res = true;
	} else if (unlikely(cmd->host_status)) {
		if ((cmd->host_status == DID_REQUEUE) ||
		    (cmd->host_status == DID_IMM_RETRY) ||
		    (cmd->host_status == DID_SOFT_ERROR) ||
		    (cmd->host_status == DID_BUS_BUSY) ||
		    (cmd->host_status == DID_TRANSPORT_DISRUPTED) ||
		    (cmd->host_status == DID_TRANSPORT_FAILFAST) ||
		    (cmd->host_status == DID_ALLOC_FAILURE)) {
			scst_set_busy(cmd);
		} else if (cmd->host_status == DID_RESET) {
			/* Postpone handling to scst_check_sense() */
		} else if ((cmd->host_status == DID_ABORT) ||
			   (cmd->host_status == DID_NO_CONNECT) ||
			   (cmd->host_status == DID_TIME_OUT) ||
			   (cmd->host_status == DID_NEXUS_FAILURE)) {
			scst_abort_cmd(cmd, NULL, false, false);
		} else if (cmd->host_status == DID_MEDIUM_ERROR) {
			if (cmd->data_direction & SCST_DATA_WRITE)
				scst_set_cmd_error(cmd,	SCST_LOAD_SENSE(scst_sense_write_error));
			else
				scst_set_cmd_error(cmd,	SCST_LOAD_SENSE(scst_sense_read_error));
		} else if ((cmd->host_status == DID_TARGET_FAILURE) && (cmd->status != 0)) {
			/* It's OK, normal workflow, ignore */
		} else {
			TRACE(TRACE_SCSI|TRACE_MINOR_AND_MGMT_DBG, "Host "
				"status 0x%x received, returning HARDWARE ERROR "
				"instead (cmd %p, op %s, target %s, device "
				"%s)", cmd->host_status, cmd, scst_get_opcode_name(cmd),
				cmd->tgt->tgt_name, cmd->dev->virt_name);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_internal_failure));
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_pre_dev_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME, rc;

	TRACE_ENTRY();

again:
	rc = scst_check_auto_sense(cmd);
	if (unlikely(rc)) {
		if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
			goto next;
		PRINT_INFO("Command finished with CHECK CONDITION, but "
			"without sense data (opcode %s), issuing "
			"REQUEST SENSE", scst_get_opcode_name(cmd));
		rc = scst_prepare_request_sense(cmd);
		if (rc == 0)
			res = SCST_CMD_STATE_RES_CONT_NEXT;
		else {
			PRINT_ERROR("%s", "Unable to issue REQUEST SENSE, "
				    "returning HARDWARE ERROR");
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_internal_failure));
		}
		goto out;
	}

next:
	rc = scst_check_sense(cmd);
	if (unlikely(rc)) {
		/*
		 * We can't allow atomic command on the exec stages, so
		 * restart to the thread
		 */
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	if (likely(scst_cmd_completed_good(cmd))) {
		if (cmd->deferred_dif_read_check) {
			int rc = scst_dif_process_read(cmd);

			if (unlikely(rc != 0)) {
				cmd->deferred_dif_read_check = 0;
				goto again;
			}
		}

		if (unlikely((cmd->cdb[0] == MODE_SENSE ||
			      cmd->cdb[0] == MODE_SENSE_10)) &&
		    (cmd->tgt_dev->tgt_dev_rd_only || cmd->dev->swp) &&
		    (cmd->dev->type == TYPE_DISK ||
		     cmd->dev->type == TYPE_WORM ||
		     cmd->dev->type == TYPE_MOD ||
		     cmd->dev->type == TYPE_TAPE)) {
			int32_t length;
			uint8_t *address;
			bool err = false;

			length = scst_get_buf_full(cmd, &address);
			if (length < 0) {
				PRINT_ERROR("%s", "Unable to get "
					"MODE_SENSE buffer");
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(
						scst_sense_internal_failure));
				err = true;
			} else if (length > 2 && cmd->cdb[0] == MODE_SENSE)
				address[2] |= 0x80;   /* Write Protect*/
			else if (length > 3 && cmd->cdb[0] == MODE_SENSE_10)
				address[3] |= 0x80;   /* Write Protect*/

			if (err)
				goto out;
			else
				scst_put_buf_full(cmd, address);
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

			buflen = scst_get_buf_full(cmd, &buffer);
			if (buflen > SCST_INQ_BYTE3 && !cmd->tgtt->fake_aca) {
#ifdef CONFIG_SCST_EXTRACHECKS
				if (buffer[SCST_INQ_BYTE3] & SCST_INQ_NORMACA_BIT) {
					PRINT_INFO("NormACA set for device: "
						"lun=%lld, type 0x%02x. Clear it, "
						"since it's unsupported.",
						(unsigned long long int)cmd->lun,
						buffer[0]);
				}
#endif
				buffer[SCST_INQ_BYTE3] &= ~SCST_INQ_NORMACA_BIT;
			} else if (buflen <= SCST_INQ_BYTE3 && buflen != 0) {
				PRINT_ERROR("%s", "Unable to get INQUIRY "
				    "buffer");
				scst_set_cmd_error(cmd,
				       SCST_LOAD_SENSE(scst_sense_internal_failure));
				err = true;
			}
			if (buflen > 0)
				scst_put_buf_full(cmd, buffer);

			if (err)
				goto out;
		}

		if (unlikely((cmd->cdb[0] == MODE_SELECT) ||
		    (cmd->cdb[0] == MODE_SELECT_10) ||
		    (cmd->cdb[0] == LOG_SELECT))) {
			TRACE(TRACE_SCSI, "MODE/LOG SELECT succeeded (LUN %lld)",
				(unsigned long long int)cmd->lun);
			cmd->state = SCST_CMD_STATE_MODE_SELECT_CHECKS;
			goto out;
		}
	} else {
		/* Check for MODE PARAMETERS CHANGED UA */
		if ((cmd->dev->scsi_dev != NULL) &&
		    (cmd->status == SAM_STAT_CHECK_CONDITION) &&
		    scst_is_ua_sense(cmd->sense, cmd->sense_valid_len) &&
		    scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
					SCST_SENSE_ASCx_VALID,
					0, 0x2a, 0x01)) {
			TRACE(TRACE_SCSI, "MODE PARAMETERS CHANGED UA (lun "
				"%lld)", (unsigned long long int)cmd->lun);
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

	TRACE_ENTRY();

	if (likely(scsi_status_is_good(cmd->status))) {
		int atomic = scst_cmd_atomic(cmd);

		if (unlikely((cmd->cdb[0] == MODE_SELECT) ||
		    (cmd->cdb[0] == MODE_SELECT_10) ||
		    (cmd->cdb[0] == LOG_SELECT))) {
			struct scst_device *dev = cmd->dev;
			int sl;
			uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];

			if (atomic && (dev->scsi_dev != NULL)) {
				TRACE_DBG("%s", "MODE/LOG SELECT: thread "
					"context required");
				res = SCST_CMD_STATE_RES_NEED_THREAD;
				goto out;
			}

			TRACE(TRACE_SCSI, "MODE/LOG SELECT succeeded, "
				"setting the SELECT UA (lun=%lld)",
				(unsigned long long int)cmd->lun);

			spin_lock_bh(&dev->dev_lock);
			if (cmd->cdb[0] == LOG_SELECT) {
				sl = scst_set_sense(sense_buffer,
					sizeof(sense_buffer),
					dev->d_sense,
					UNIT_ATTENTION, 0x2a, 0x02);
			} else {
				sl = scst_set_sense(sense_buffer,
					sizeof(sense_buffer),
					dev->d_sense,
					UNIT_ATTENTION, 0x2a, 0x01);
			}
			scst_dev_check_set_local_UA(dev, cmd, sense_buffer, sl);
			spin_unlock_bh(&dev->dev_lock);

			if (dev->scsi_dev != NULL)
				scst_obtain_device_parameters(dev, cmd->cdb);
		}
	} else if ((cmd->status == SAM_STAT_CHECK_CONDITION) &&
		    scst_is_ua_sense(cmd->sense, cmd->sense_valid_len) &&
		     /* mode parameters changed */
		    (scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
					SCST_SENSE_ASCx_VALID,
					0, 0x2a, 0x01) ||
		     scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
					SCST_SENSE_ASC_VALID,
					0, 0x29, 0) /* reset */ ||
		     scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
					SCST_SENSE_ASC_VALID,
					0, 0x28, 0) /* medium changed */ ||
		     /* cleared by another ini (just in case) */
		     scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
					SCST_SENSE_ASC_VALID,
					0, 0x2F, 0))) {
		int atomic = scst_cmd_atomic(cmd);

		if (atomic) {
			TRACE_DBG("Possible parameters changed UA %x: "
				"thread context required", cmd->sense[12]);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		TRACE(TRACE_SCSI, "Possible parameters changed UA %x "
			"(LUN %lld): getting new parameters", cmd->sense[12],
			(unsigned long long int)cmd->lun);

		scst_obtain_device_parameters(cmd->dev, NULL);
	} else
		sBUG();

	cmd->state = SCST_CMD_STATE_DEV_DONE;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

static int scst_dev_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_RES_CONT_SAME;
	int state;
	struct scst_dev_type *devt = cmd->devt;

	TRACE_ENTRY();

	state = SCST_CMD_STATE_PRE_XMIT_RESP1;

	if (likely((cmd->op_flags & SCST_FULLY_LOCAL_CMD) == 0) &&
	    likely(devt->dev_done != NULL)) {
		int rc;

		if (unlikely(!devt->dev_done_atomic &&
			     scst_cmd_atomic(cmd))) {
			/*
			 * It shouldn't be because of the SCST_TGT_DEV_AFTER_*
			 * optimization.
			 */
			TRACE_MGMT_DBG("Dev handler %s dev_done() needs thread "
				"context, rescheduling", devt->name);
			res = SCST_CMD_STATE_RES_NEED_THREAD;
			goto out;
		}

		TRACE_DBG("Calling dev handler %s dev_done(%p)",
			devt->name, cmd);
		scst_set_cur_start(cmd);
		rc = devt->dev_done(cmd);
		scst_set_dev_done_time(cmd);
		TRACE_DBG("Dev handler %s dev_done() returned %d",
		      devt->name, rc);
		if (rc != SCST_CMD_STATE_DEFAULT)
			state = rc;
	}

	switch (state) {
#ifdef CONFIG_SCST_EXTRACHECKS
	case SCST_CMD_STATE_PRE_XMIT_RESP1:
	case SCST_CMD_STATE_PRE_XMIT_RESP2:
	case SCST_CMD_STATE_PARSE:
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_TGT_PRE_EXEC:
	case SCST_CMD_STATE_EXEC_CHECK_SN:
	case SCST_CMD_STATE_EXEC_CHECK_BLOCKING:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_MODE_SELECT_CHECKS:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
	case SCST_CMD_STATE_FINISHED_INTERNAL:
#else
	default:
#endif
		cmd->state = state;
		break;
	case SCST_CMD_STATE_NEED_THREAD_CTX:
		TRACE_DBG("Dev handler %s dev_done() requested "
		      "thread context, rescheduling",
		      devt->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
#ifdef CONFIG_SCST_EXTRACHECKS
	default:
		if (state >= 0) {
			PRINT_ERROR("Dev handler %s dev_done() returned "
				"invalid cmd state %d",
				devt->name, state);
		} else {
			PRINT_ERROR("Dev handler %s dev_done() returned "
				"error %d", devt->name, state);
		}
		scst_set_cmd_error(cmd,
			   SCST_LOAD_SENSE(scst_sense_hardw_error));
		scst_set_cmd_abnormal_done_state(cmd);
		break;
#endif
	}

	scst_check_unblock_dev(cmd);

	if (cmd->inc_expected_sn_on_done && cmd->sent_for_exec && cmd->sn_set) {
		bool rc = scst_inc_expected_sn(cmd);

		if (rc)
			scst_make_deferred_commands_active(cmd->cur_order_data);
	}

	if (unlikely(cmd->internal))
		cmd->state = SCST_CMD_STATE_FINISHED_INTERNAL;

#ifndef CONFIG_SCST_TEST_IO_IN_SIRQ
#ifdef CONFIG_SCST_EXTRACHECKS
	if (cmd->state != SCST_CMD_STATE_PRE_XMIT_RESP1) {
		/* We can't allow atomic command on the exec stages */
		if (scst_cmd_atomic(cmd)) {
			switch (state) {
			case SCST_CMD_STATE_TGT_PRE_EXEC:
			case SCST_CMD_STATE_EXEC_CHECK_SN:
			case SCST_CMD_STATE_EXEC_CHECK_BLOCKING:
			case SCST_CMD_STATE_LOCAL_EXEC:
			case SCST_CMD_STATE_REAL_EXEC:
				TRACE_DBG("Atomic context and redirect, "
					"rescheduling (cmd %p)", cmd);
				res = SCST_CMD_STATE_RES_NEED_THREAD;
				break;
			}
		}
	}
#endif
#endif

out:
	TRACE_EXIT_HRES(res);
	return res;
}

static int scst_pre_xmit_response2(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

again:
	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
		scst_xmit_process_aborted_cmd(cmd);
	else if (unlikely(cmd->status == SAM_STAT_CHECK_CONDITION)) {
		if (cmd->tgt_dev != NULL) {
			int rc = scst_process_check_condition(cmd);
			/* !! At this point cmd can be already dead !! */
			if (rc == -1) {
				res = SCST_CMD_STATE_RES_CONT_NEXT;
				goto out;
			} else if (rc == 1)
				goto again;
		}
	}

	if (unlikely(test_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags))) {
		EXTRACHECKS_BUG_ON(!test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags));
		TRACE_MGMT_DBG("Flag NO_RESP set for cmd %p (tag %llu), "
			"skipping", cmd, (unsigned long long int)cmd->tag);
		cmd->state = SCST_CMD_STATE_FINISHED;
		goto out_same;
	}

	if (unlikely(cmd->resid_possible))
		scst_adjust_resp_data_len(cmd);
	else
		cmd->adjusted_resp_data_len = cmd->resp_data_len;

	cmd->state = SCST_CMD_STATE_XMIT_RESP;

out_same:
	res = SCST_CMD_STATE_RES_CONT_SAME;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_pre_xmit_response1(struct scst_cmd *cmd)
{
	int res;

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
		/*
		 * Those counters protect from not getting too long processing
		 * latency, so we should decrement them after cmd completed.
		 */
		atomic_dec(&cmd->tgt_dev->tgt_dev_cmd_count);
#ifdef CONFIG_SCST_PER_DEVICE_CMD_COUNT_LIMIT
		atomic_dec(&cmd->dev->dev_cmd_count);
#endif
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			scst_on_hq_cmd_response(cmd);
		else if (unlikely(!cmd->sent_for_exec)) {
			/*
			 * scst_post_exec_sn() can't be called in parallel
			 * due to the sent_for_exec contract obligation
			 */
			TRACE_SN("cmd %p was not sent for exec (sn %d, "
				"set %d)", cmd, cmd->sn, cmd->sn_set);
			scst_unblock_deferred(cmd->cur_order_data, cmd);
		}
	}

	cmd->done = 1;
	smp_mb(); /* to sync with scst_abort_cmd() */

	cmd->state = SCST_CMD_STATE_PRE_XMIT_RESP2;
	res = scst_pre_xmit_response2(cmd);

	TRACE_EXIT_RES(res);
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
		 * It shouldn't be because of the SCST_TGT_DEV_AFTER_*
		 * optimization.
		 */
		TRACE_MGMT_DBG("Target driver %s xmit_response() needs thread "
			"context, rescheduling", tgtt->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	res = SCST_CMD_STATE_RES_CONT_NEXT;
	cmd->state = SCST_CMD_STATE_XMIT_WAIT;

	TRACE_DBG("Calling xmit_response(%p)", cmd);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (unlikely(trace_flag & TRACE_DATA_SEND) &&
	    (cmd->data_direction & SCST_DATA_READ)) {
		int i, sg_cnt;
		struct scatterlist *sg, *sgi;

		if (cmd->tgt_i_sg != NULL) {
			sg = cmd->tgt_i_sg;
			sg_cnt = cmd->tgt_i_sg_cnt;
		} else {
			sg = cmd->sg;
			sg_cnt = cmd->sg_cnt;
		}
		if (sg != NULL) {
			PRINT_INFO("Xmitting data for cmd %p "
				"(sg_cnt %d, sg %p, sg[0].page %p, buf %p, "
				"resp len %d)", cmd, sg_cnt, sg,
				(void *)sg_page(&sg[0]), sg_virt(sg),
				cmd->resp_data_len);
			for_each_sg(sg, sgi, sg_cnt, i) {
				PRINT_INFO("sg %d", i);
				PRINT_BUFFER("data", sg_virt(sgi),
					     sgi->length);
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

	scst_set_cur_start(cmd);

#ifdef CONFIG_SCST_DEBUG_RETRY
	if (((scst_random() % 100) == 77))
		rc = SCST_TGT_RES_QUEUE_FULL;
	else
#endif
		rc = tgtt->xmit_response(cmd);
	TRACE_DBG("xmit_response() returned %d", rc);

	if (likely(rc == SCST_TGT_RES_SUCCESS))
		goto out;

	scst_set_xmit_time(cmd);

	cmd->cmd_hw_pending = 0;

	/* Restore the previous state */
	cmd->state = SCST_CMD_STATE_XMIT_RESP;

	switch (rc) {
	case SCST_TGT_RES_QUEUE_FULL:
		scst_queue_retry_cmd(cmd);
		goto out;

	case SCST_TGT_RES_NEED_THREAD_CTX:
		TRACE_DBG("Target driver %s xmit_response() "
		      "requested thread context, rescheduling",
		      tgtt->name);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;

	default:
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

out:
	/* Caution: cmd can be already dead here */
	TRACE_EXIT_HRES(res);
	return res;
}

/**
 * scst_tgt_cmd_done() - the command's processing done
 * @cmd:	SCST command
 * @pref_context: preferred command execution context
 *
 * Description:
 *    Notifies SCST that the driver sent the response and the command
 *    can be freed now. Don't forget to set the delivery status, if it
 *    isn't success, using scst_set_delivery_status() before calling
 *    this function. The third argument sets preferred command execution
 *    context (see SCST_CONTEXT_* constants for details)
 */
void scst_tgt_cmd_done(struct scst_cmd *cmd,
	enum scst_exec_context pref_context)
{
	TRACE_ENTRY();

	sBUG_ON(cmd->state != SCST_CMD_STATE_XMIT_WAIT);

	scst_set_xmit_time(cmd);

	cmd->cmd_hw_pending = 0;

	if (unlikely(cmd->tgt_dev == NULL))
		pref_context = SCST_CONTEXT_THREAD;

	cmd->state = SCST_CMD_STATE_FINISHED;

	scst_process_redirect_cmd(cmd, pref_context, 1);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_tgt_cmd_done);

static int scst_finish_cmd(struct scst_cmd *cmd)
{
	int res;
	struct scst_session *sess = cmd->sess;
	struct scst_io_stat_entry *stat;
	int block_shift, align_len;

	TRACE_ENTRY();

	scst_update_lat_stats(cmd);

	if (unlikely(cmd->delivery_status != SCST_CMD_DELIVERY_SUCCESS)) {
		if ((cmd->tgt_dev != NULL) &&
		    (cmd->status == SAM_STAT_CHECK_CONDITION) &&
		    scst_is_ua_sense(cmd->sense, cmd->sense_valid_len)) {
			/* This UA delivery failed, so we need to requeue it */
			if (scst_cmd_atomic(cmd) &&
			    scst_is_ua_global(cmd->sense, cmd->sense_valid_len)) {
				TRACE_MGMT_DBG("Requeuing of global UA for "
					"failed cmd %p needs a thread", cmd);
				res = SCST_CMD_STATE_RES_NEED_THREAD;
				goto out;
			}
			scst_requeue_ua(cmd, NULL, 0);
		}
	}

	atomic_dec(&sess->sess_cmd_count);

	spin_lock_irq(&sess->sess_list_lock);

	stat = &sess->io_stats[cmd->data_direction];
	stat->cmd_count++;
	stat->io_byte_count += cmd->bufflen + cmd->out_bufflen;
	if (likely(cmd->dev != NULL)) {
		block_shift = cmd->dev->block_shift;
		/* Let's track only 4K unaligned cmds at the moment */
		align_len = (block_shift != 0) ? 4095 : 0;
	} else {
		block_shift = 0;
		align_len = 0;
	}

	if (unlikely(((cmd->lba << block_shift) & align_len) != 0) ||
	    unlikely(((cmd->bufflen + cmd->out_bufflen) & align_len) != 0))
		stat->unaligned_cmd_count++;

	list_del(&cmd->sess_cmd_list_entry);

	/*
	 * Done under sess_list_lock to sync with scst_abort_cmd() without
	 * using extra barrier.
	 */
	cmd->finished = 1;

	spin_unlock_irq(&sess->sess_list_lock);

	if (unlikely(cmd->cmd_on_global_stpg_list)) {
		TRACE_DBG("Unlisting being freed STPG cmd %p", cmd);
		EXTRACHECKS_BUG_ON(cmd->cmd_global_stpg_blocked);
		scst_stpg_del_unblock_next(cmd);
	}

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
		scst_finish_cmd_mgmt(cmd);

	__scst_cmd_put(cmd);

	res = SCST_CMD_STATE_RES_CONT_NEXT;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* Must be called under sn_lock with IRQs off */
static inline void scst_inc_expected_sn_idle(struct scst_order_data *order_data)
{
	order_data->expected_sn++;
	/*
	 * Write must be before def_cmd_count read to be in
	 * sync with scst_post_exec_sn(). See comment in
	 * scst_exec_check_sn(). Just in case if spin_unlock() isn't
	 * memory a barrier. Although, checking of def_cmd_count
	 * is far from here, but who knows, let's be safer.
	 */
	smp_mb();
	TRACE_SN("New expected_sn: %d", order_data->expected_sn);

	scst_make_deferred_commands_active_locked(order_data);
	return;
}

/**
 * scst_cmd_set_sn - Assign SN and a slot number to a command.
 *
 * Commands that may be executed concurrently are assigned the same slot
 * number. A command that must be executed after previously received commands
 * is assigned a new and higher slot number.
 *
 * No locks expected.
 *
 * Note: This approach in full compliance with SAM may result in the reordering
 * of conflicting SIMPLE READ and/or WRITE commands (commands with at least
 * partially overlapping data ranges and of which at least one of them is a
 * WRITE command). An initiator is not allowed to submit such conflicting
 * commands. After having modified data, an initiator must wait for the result
 * of that operation before rereading or rewriting the modified data range or
 * use ORDERED subsequent conflicting command(s). See also comments about the
 * command identifier in SAM-5 or comments about task tags and command
 * reordering in previous SAM revisions.
 */
static void scst_cmd_set_sn(struct scst_cmd *cmd)
{
	struct scst_order_data *order_data = cmd->cur_order_data;
	unsigned long flags;

	TRACE_ENTRY();

	if (((cmd->op_flags & SCST_IMPLICIT_HQ) != 0) &&
	    likely(cmd->queue_type == SCST_CMD_QUEUE_SIMPLE)) {
		TRACE_SN("Implicit HQ cmd %p", cmd);
		cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	}

	EXTRACHECKS_BUG_ON(cmd->sn_set || cmd->hq_cmd_inced);

	/* Optimized for lockless fast path of sequence of SIMPLE commands */

	scst_check_debug_sn(cmd);

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	if (likely(cmd->queue_type != SCST_CMD_QUEUE_HEAD_OF_QUEUE))
		cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
#endif

	if (cmd->dev->queue_alg == SCST_QUEUE_ALG_0_RESTRICTED_REORDER) {
		if (likely(cmd->queue_type != SCST_CMD_QUEUE_HEAD_OF_QUEUE)) {
			/*
			 * Not the best way, but good enough until there is a
			 * possibility to specify queue type during pass-through
			 * commands submission.
			 */
			TRACE_SN("Restricted reorder dev %s (cmd %p)",
				cmd->dev->virt_name, cmd);
			cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
		}
	}

again:
	switch (cmd->queue_type) {
	case SCST_CMD_QUEUE_SIMPLE:
		if (order_data->prev_cmd_ordered) {
			if (atomic_read(order_data->cur_sn_slot) != 0) {
				order_data->cur_sn_slot++;
				if (order_data->cur_sn_slot == order_data->sn_slots +
								ARRAY_SIZE(order_data->sn_slots))
					order_data->cur_sn_slot = order_data->sn_slots;
				if (unlikely(atomic_read(order_data->cur_sn_slot) != 0)) {
					static int q;

					if (q++ < 10)
						PRINT_WARNING("Not enough SN slots "
							"(dev %s)", cmd->dev->virt_name);
					goto ordered;
				}
				TRACE_SN("New cur SN slot %zd",
					order_data->cur_sn_slot - order_data->sn_slots);
			}

			order_data->curr_sn++;
			TRACE_SN("Incremented curr_sn %d", order_data->curr_sn);

			order_data->prev_cmd_ordered = 0;
			/*
			 * expected_sn will be/was incremented by the
			 * previous ORDERED cmd
			 */
		}

		cmd->sn_slot = order_data->cur_sn_slot;
		atomic_inc(cmd->sn_slot);
		cmd->sn = order_data->curr_sn;
		cmd->sn_set = 1;
		break;

	case SCST_CMD_QUEUE_UNTAGGED: /* put here with goto for better SIMPLE fast path */
		/* It is processed further as SIMPLE */
		cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
		goto again;

	case SCST_CMD_QUEUE_ORDERED:
		TRACE_SN("ORDERED cmd %p (op %s)", cmd, scst_get_opcode_name(cmd));
ordered:
		order_data->curr_sn++;
		TRACE_SN("Incremented curr_sn %d", order_data->curr_sn);

		if (order_data->prev_cmd_ordered) {
			TRACE_SN("Prev cmd ordered set");
			/*
			 * expected_sn will be/was incremented by the
			 * previous ORDERED cmd
			 */
		} else {
			order_data->prev_cmd_ordered = 1;

			spin_lock_irqsave(&order_data->sn_lock, flags);

			/*
			 * If no commands are going to reach
			 * scst_inc_expected_sn(), inc expected_sn here.
			 */
			if (atomic_read(order_data->cur_sn_slot) == 0)
				scst_inc_expected_sn_idle(order_data);
			else {
				order_data->pending_simple_inc_expected_sn++;
				TRACE_SN("New inc pending_simple_inc_expected_sn: %d",
					order_data->pending_simple_inc_expected_sn);
				smp_mb(); /* to sync with scst_inc_expected_sn() */
				if (unlikely(atomic_read(order_data->cur_sn_slot) == 0)) {
					order_data->pending_simple_inc_expected_sn--;
					TRACE_SN("New dec pending_simple_inc_expected_sn: %d",
						order_data->pending_simple_inc_expected_sn);
					EXTRACHECKS_BUG_ON(order_data->pending_simple_inc_expected_sn < 0);
					scst_inc_expected_sn_idle(order_data);
				}
			}
			spin_unlock_irqrestore(&order_data->sn_lock, flags);
		}

		cmd->sn = order_data->curr_sn;
		cmd->sn_set = 1;
		break;

	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		TRACE_SN("HQ cmd %p (op %s)", cmd, scst_get_opcode_name(cmd));
		spin_lock_irqsave(&order_data->sn_lock, flags);
		order_data->hq_cmd_count++;
		spin_unlock_irqrestore(&order_data->sn_lock, flags);
		cmd->hq_cmd_inced = 1;
		goto out;

	default:
		sBUG();
	}

	TRACE_SN("cmd(%p)->sn: %d (order_data %p, *cur_sn_slot %d, "
		"prev_cmd_ordered %d, cur_sn_slot %zd)", cmd,
		cmd->sn, order_data, atomic_read(order_data->cur_sn_slot),
		order_data->prev_cmd_ordered,
		order_data->cur_sn_slot - order_data->sn_slots);

out:
	TRACE_EXIT();
	return;
}

struct scst_tgt_dev *scst_lookup_tgt_dev(struct scst_session *sess, u64 lun)
{
	struct list_head *head;
	struct scst_tgt_dev *tgt_dev;

#ifdef CONFIG_SCST_EXTRACHECKS
	if (scst_get_cmd_counter() == 0)
		lockdep_assert_held(&scst_mutex);
#endif

	head = &sess->sess_tgt_dev_list[SESS_TGT_DEV_LIST_HASH_FN(lun)];
	list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
		if (tgt_dev->lun == lun)
			return tgt_dev;
	}

	return NULL;
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
	bool nul_dev = false;

	TRACE_ENTRY();

	cmd->cpu_cmd_counter = scst_get();

	if (likely(!test_bit(SCST_FLAG_SUSPENDED, &scst_flags))) {
		TRACE_DBG("Finding tgt_dev for cmd %p (lun %lld)", cmd,
			(unsigned long long int)cmd->lun);
		res = -1;
		tgt_dev = scst_lookup_tgt_dev(cmd->sess, cmd->lun);
		if (tgt_dev) {
			TRACE_DBG("tgt_dev %p found", tgt_dev);

			if (likely(tgt_dev->dev->handler != &scst_null_devtype)) {
				cmd->cmd_threads = tgt_dev->active_cmd_threads;
				cmd->tgt_dev = tgt_dev;
				cmd->cur_order_data = tgt_dev->curr_order_data;
				cmd->dev = tgt_dev->dev;
				cmd->devt = tgt_dev->dev->handler;

				res = 0;
			} else {
				PRINT_INFO("Dev handler for device %lld is NULL, "
					"the device will not be visible remotely",
					(unsigned long long int)cmd->lun);
				nul_dev = true;
			}
		}
		if (unlikely(res != 0)) {
			if (!nul_dev) {
				TRACE(TRACE_MINOR,
					"tgt_dev for LUN %lld not found, command to "
					"unexisting LU (initiator %s, target %s)?",
					(unsigned long long int)cmd->lun,
					cmd->sess->initiator_name, cmd->tgt->tgt_name);
				scst_event_queue_lun_not_found(cmd);
			}
			scst_put(cmd->cpu_cmd_counter);
		}
	} else {
		scst_put(cmd->cpu_cmd_counter);
		TRACE_MGMT_DBG("%s", "FLAG SUSPENDED set, skipping");
		res = 1;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * No locks, but might be on IRQ.
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

		cmd->state = SCST_CMD_STATE_PARSE;

		cnt = atomic_inc_return(&cmd->tgt_dev->tgt_dev_cmd_count);
		if (unlikely(cnt > SCST_MAX_TGT_DEV_COMMANDS)) {
			TRACE(TRACE_FLOW_CONTROL,
				"Too many pending commands (%d) in "
				"session, returning BUSY to initiator \"%s\"",
				cnt, (cmd->sess->initiator_name[0] == '\0') ?
				  "Anonymous" : cmd->sess->initiator_name);
			failure = true;
		}

#ifdef CONFIG_SCST_PER_DEVICE_CMD_COUNT_LIMIT
		cnt = atomic_inc_return(&cmd->dev->dev_cmd_count);
		if (unlikely(cnt > SCST_MAX_DEV_COMMANDS)) {
			if (!failure) {
				TRACE(TRACE_FLOW_CONTROL,
					"Too many pending device "
					"commands (%d), returning BUSY to "
					"initiator \"%s\"", cnt,
					(cmd->sess->initiator_name[0] == '\0') ?
						"Anonymous" :
						cmd->sess->initiator_name);
				failure = true;
			}
		}
#endif

		if (unlikely(failure))
			goto out_busy;

		/*
		 * SCST_IMPLICIT_HQ for unknown commands not implemented for
		 * case when set_sn_on_restart_cmd not set, because custom parse
		 * can reorder commands due to multithreaded processing. To
		 * implement it we need to implement all unknown commands as
		 * ORDERED in the beginning and post parse reprocess of
		 * queue_type to change it if needed. ToDo.
		 */
		scst_pre_parse(cmd);

		if (!cmd->set_sn_on_restart_cmd) {
			if (!cmd->tgtt->multithreaded_init_done)
				scst_cmd_set_sn(cmd);
			else {
				struct scst_order_data *order_data = cmd->cur_order_data;
				unsigned long flags;

				spin_lock_irqsave(&order_data->init_done_lock, flags);
				scst_cmd_set_sn(cmd);
				spin_unlock_irqrestore(&order_data->init_done_lock, flags);
			}
		}
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
				       cmd, (unsigned long long int)cmd->tag);
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
		TRACE_DBG("Deleting cmd %p from init cmd list", cmd);
		smp_wmb(); /* enforce the required order */
		list_del(&cmd->cmd_list_entry);
		spin_unlock(&scst_init_lock);

		spin_lock(&cmd->cmd_threads->cmd_list_lock);
		TRACE_DBG("Adding cmd %p to active cmd list", cmd);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
		wake_up(&cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_threads->cmd_list_lock);

		spin_lock(&scst_init_lock);
		goto restart;
	}

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

	PRINT_INFO("Init thread started");

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock_irq(&scst_init_lock);
	while (!kthread_should_stop()) {
		wait_event_locked(scst_init_cmd_list_waitQ,
				  test_init_cmd_list(),
				  lock_irq, scst_init_lock);
		scst_do_job_init();
	}
	spin_unlock_irq(&scst_init_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so scst_init_cmd_list must be empty.
	 */
	sBUG_ON(!list_empty(&scst_init_cmd_list));

	PRINT_INFO("Init thread finished");

	TRACE_EXIT();
	return 0;
}

/**
 * scst_ioctx_get() - Associate an I/O context with a thread.
 *
 * Associate an I/O context with a thread in such a way that all threads in an
 * SCST thread pool share the same I/O context. This greatly improves thread
 * pool I/O performance with at least the CFQ scheduler.
 *
 * Note: A more elegant approach would be to allocate the I/O context in
 * scst_init_threads() instead of this function. That approach is only possible
 * though after exporting alloc_io_context(). A previous discussion of this
 * topic can be found here: http://lkml.org/lkml/2008/12/11/282.
 */
static void scst_ioctx_get(struct scst_cmd_threads *p_cmd_threads)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	mutex_lock(&p_cmd_threads->io_context_mutex);

	WARN_ON(current->io_context);

	if (p_cmd_threads != &scst_main_cmd_threads) {
		/*
		 * For linked IO contexts io_context might be not NULL while
		 * io_context 0.
		 */
		if (p_cmd_threads->io_context == NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
			p_cmd_threads->io_context = get_task_io_context(current,
						GFP_KERNEL, NUMA_NO_NODE);
#else
			p_cmd_threads->io_context = get_io_context(GFP_KERNEL, -1);
#endif
			TRACE_DBG("Alloced new IO context %p "
				"(p_cmd_threads %p)", p_cmd_threads->io_context,
				       p_cmd_threads);
			/*
			 * Put the extra reference created by get_io_context()
			 * because we don't need it.
			 */
			put_io_context(p_cmd_threads->io_context);
		} else {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && (LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)))
#warning IO context sharing functionality disabled on 3.5 kernels due to bug in them. \
See "http://lkml.org/lkml/2012/7/17/515" for more details.
			static int q;

			if (q == 0) {
				q++;
				PRINT_WARNING("IO context sharing functionality "
					"disabled on 3.5 kernels due to bug in "
					"them. See http://lkml.org/lkml/2012/7/17/515 "
					"for more details.");
			}
#else
			ioc_task_link(p_cmd_threads->io_context);
			current->io_context = p_cmd_threads->io_context;
			TRACE_DBG("Linked IO context %p "
				"(p_cmd_threads %p)", p_cmd_threads->io_context,
				p_cmd_threads);
#endif
		}
		p_cmd_threads->io_context_refcnt++;
	}

	mutex_unlock(&p_cmd_threads->io_context_mutex);
#endif

	smp_wmb();
	p_cmd_threads->io_context_ready = true;
	return;
}

/**
 * scst_ioctx_put() - Free I/O context allocated by scst_ioctx_get().
 */
static void scst_ioctx_put(struct scst_cmd_threads *p_cmd_threads)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	if (p_cmd_threads != &scst_main_cmd_threads) {
		mutex_lock(&p_cmd_threads->io_context_mutex);
		if (--p_cmd_threads->io_context_refcnt == 0)
			p_cmd_threads->io_context = NULL;
		mutex_unlock(&p_cmd_threads->io_context_mutex);
	}
#endif
	return;
}

/**
 * scst_process_active_cmd() - process active command
 *
 * Description:
 *    Main SCST commands processing routing. Must be used only by dev handlers.
 *
 *    Argument atomic is true, if function called in atomic context.
 *
 *    Must be called with no locks held.
 */
void scst_process_active_cmd(struct scst_cmd *cmd, bool atomic)
{
	int res;

	TRACE_ENTRY();

	/*
	 * Checkpatch will complain on the use of in_atomic() below. You
	 * can safely ignore this warning since in_atomic() is used here only
	 * for debugging purposes.
	 */
	EXTRACHECKS_BUG_ON(in_irq() || irqs_disabled());
	EXTRACHECKS_WARN_ON((in_atomic() || in_interrupt()) && !atomic);

	cmd->atomic = atomic;

	TRACE_DBG("cmd %p, atomic %d", cmd, atomic);

	do {
		switch (cmd->state) {
		case SCST_CMD_STATE_PARSE:
			res = scst_parse_cmd(cmd);
			break;

		case SCST_CMD_STATE_PREPARE_SPACE:
			res = scst_prepare_space(cmd);
			break;

		case SCST_CMD_STATE_PREPROCESSING_DONE:
			res = scst_preprocessing_done(cmd);
			break;

		case SCST_CMD_STATE_RDY_TO_XFER:
			res = scst_rdy_to_xfer(cmd);
			break;

		case SCST_CMD_STATE_TGT_PRE_EXEC:
			res = scst_tgt_pre_exec(cmd);
			break;

		case SCST_CMD_STATE_EXEC_CHECK_SN:
			if (tm_dbg_check_cmd(cmd) != 0) {
				res = SCST_CMD_STATE_RES_CONT_NEXT;
				TRACE_MGMT_DBG("Skipping cmd %p (tag %llu), "
					"because of TM DBG delay", cmd,
					(unsigned long long int)cmd->tag);
				break;
			}
			res = scst_exec_check_sn(&cmd);
			EXTRACHECKS_BUG_ON(res == SCST_CMD_STATE_RES_NEED_THREAD);
			/*
			 * !! At this point cmd, sess & tgt_dev can already be
			 * freed !!
			 */
			break;

		case SCST_CMD_STATE_EXEC_CHECK_BLOCKING:
			res = scst_exec_check_blocking(&cmd);
			EXTRACHECKS_BUG_ON(res == SCST_CMD_STATE_RES_NEED_THREAD);
			/*
			 * !! At this point cmd, sess & tgt_dev can already be
			 * freed !!
			 */
			break;

		case SCST_CMD_STATE_LOCAL_EXEC:
			res = scst_local_exec(cmd);
			EXTRACHECKS_BUG_ON(res == SCST_CMD_STATE_RES_NEED_THREAD);
			/*
			 * !! At this point cmd, sess & tgt_dev can already be
			 * freed !!
			 */
			break;

		case SCST_CMD_STATE_REAL_EXEC:
			res = scst_real_exec(cmd);
			EXTRACHECKS_BUG_ON(res == SCST_CMD_STATE_RES_NEED_THREAD);
			/*
			 * !! At this point cmd, sess & tgt_dev can already be
			 * freed !!
			 */
			break;

		case SCST_CMD_STATE_PRE_DEV_DONE:
			res = scst_pre_dev_done(cmd);
			EXTRACHECKS_BUG_ON((res == SCST_CMD_STATE_RES_NEED_THREAD) &&
				(cmd->state == SCST_CMD_STATE_PRE_DEV_DONE));
			break;

		case SCST_CMD_STATE_MODE_SELECT_CHECKS:
			res = scst_mode_select_checks(cmd);
			break;

		case SCST_CMD_STATE_DEV_DONE:
			res = scst_dev_done(cmd);
			break;

		case SCST_CMD_STATE_PRE_XMIT_RESP1:
			res = scst_pre_xmit_response1(cmd);
			EXTRACHECKS_BUG_ON(res == SCST_CMD_STATE_RES_NEED_THREAD);
			break;

		case SCST_CMD_STATE_PRE_XMIT_RESP2:
			res = scst_pre_xmit_response2(cmd);
			EXTRACHECKS_BUG_ON(res == SCST_CMD_STATE_RES_NEED_THREAD);
			break;

		case SCST_CMD_STATE_XMIT_RESP:
			res = scst_xmit_response(cmd);
			break;

		case SCST_CMD_STATE_FINISHED:
			res = scst_finish_cmd(cmd);
			break;

		case SCST_CMD_STATE_FINISHED_INTERNAL:
			res = scst_finish_internal_cmd(cmd);
			break;

		default:
			PRINT_CRIT_ERROR("cmd (%p) in state %d, but shouldn't "
				"be", cmd, cmd->state);
			sBUG();
#if defined(RHEL_MAJOR) && RHEL_MAJOR -0 < 6
			/* For suppressing a gcc compiler warning */
			res = SCST_CMD_STATE_RES_CONT_NEXT;
			break;
#endif
		}
	} while (res == SCST_CMD_STATE_RES_CONT_SAME);

	if (res == SCST_CMD_STATE_RES_CONT_NEXT) {
		/* None */
	} else if (res == SCST_CMD_STATE_RES_NEED_THREAD) {
#ifdef CONFIG_SCST_EXTRACHECKS
		switch (cmd->state) {
		case SCST_CMD_STATE_PARSE:
		case SCST_CMD_STATE_PREPARE_SPACE:
		case SCST_CMD_STATE_RDY_TO_XFER:
		case SCST_CMD_STATE_TGT_PRE_EXEC:
		case SCST_CMD_STATE_EXEC_CHECK_SN:
		case SCST_CMD_STATE_EXEC_CHECK_BLOCKING:
		case SCST_CMD_STATE_LOCAL_EXEC:
		case SCST_CMD_STATE_REAL_EXEC:
		case SCST_CMD_STATE_DEV_DONE:
		case SCST_CMD_STATE_XMIT_RESP:
			break;
		default:
			PRINT_CRIT_ERROR("cmd %p is in invalid state %d)", cmd,
				cmd->state);
			sBUG();
		}
#endif
		TRACE_DBG("Adding cmd %p to head of active cmd list", cmd);

		spin_lock_irq(&cmd->cmd_threads->cmd_list_lock);
		list_add(&cmd->cmd_list_entry,
			 &cmd->cmd_threads->active_cmd_list);
		wake_up(&cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock_irq(&cmd->cmd_threads->cmd_list_lock);
	} else
		sBUG();

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_process_active_cmd);

/* Called under cmd_list_lock and IRQs disabled */
static void scst_do_job_active(struct list_head *cmd_list,
	spinlock_t *cmd_list_lock, bool atomic)
	__releases(cmd_list_lock)
	__acquires(cmd_list_lock)
{
	TRACE_ENTRY();

	while (!list_empty(cmd_list)) {
		struct scst_cmd *cmd = list_first_entry(cmd_list, typeof(*cmd),
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

static inline int test_cmd_threads(struct scst_cmd_thread_t *thr)
{
	int res = !list_empty(&thr->thr_active_cmd_list) ||
		  !list_empty(&thr->thr_cmd_threads->active_cmd_list) ||
		  unlikely(kthread_should_stop()) ||
		  tm_dbg_is_release();
	return res;
}

int scst_cmd_thread(void *arg)
{
	struct scst_cmd_thread_t *thr = arg;
	struct scst_cmd_threads *p_cmd_threads = thr->thr_cmd_threads;
	bool someth_done, p_locked, thr_locked;

	TRACE_ENTRY();

	TRACE(TRACE_MINOR, "Processing thread %s started", current->comm);

#if 0
	set_user_nice(current, 10);
#endif
	current->flags |= PF_NOFREEZE;

	scst_ioctx_get(p_cmd_threads);

	wake_up_all(&p_cmd_threads->ioctx_wq);

	spin_lock_irq(&p_cmd_threads->cmd_list_lock);
	spin_lock(&thr->thr_cmd_list_lock);
	while (!kthread_should_stop()) {
		if (!test_cmd_threads(thr)) {
			DEFINE_WAIT(wait);
			do {
				prepare_to_wait_exclusive_head(
					&p_cmd_threads->cmd_list_waitQ,
					&wait, TASK_INTERRUPTIBLE);
				if (test_cmd_threads(thr))
					break;
				spin_unlock(&thr->thr_cmd_list_lock);
				spin_unlock_irq(&p_cmd_threads->cmd_list_lock);
				schedule();
				spin_lock_irq(&p_cmd_threads->cmd_list_lock);
				spin_lock(&thr->thr_cmd_list_lock);
			} while (!test_cmd_threads(thr));
			finish_wait(&p_cmd_threads->cmd_list_waitQ, &wait);
		}

		if (tm_dbg_is_release()) {
			spin_unlock_irq(&p_cmd_threads->cmd_list_lock);
			tm_dbg_check_released_cmds();
			spin_lock_irq(&p_cmd_threads->cmd_list_lock);
		}

		/*
		 * Idea of this code is to have local queue be more prioritized
		 * comparing to the more global queue as 2:1, as well as the
		 * local processing not touching the more global data for writes
		 * during its iterations when the more global queue is empty.
		 * Why 2:1? 2 is average number of intermediate commands states
		 * reaching this point here.
		 */

		p_locked = true;
		thr_locked = true;
		do {
			int thr_cnt;

			someth_done = false;
again:
			if (!list_empty(&p_cmd_threads->active_cmd_list)) {
				struct scst_cmd *cmd;

				if (!p_locked) {
					if (thr_locked) {
						spin_unlock_irq(&thr->thr_cmd_list_lock);
						thr_locked = false;
					}
					spin_lock_irq(&p_cmd_threads->cmd_list_lock);
					p_locked = true;
					goto again;
				}

				cmd = list_first_entry(&p_cmd_threads->active_cmd_list,
							typeof(*cmd), cmd_list_entry);

				TRACE_DBG("Deleting cmd %p from active cmd list", cmd);
				list_del(&cmd->cmd_list_entry);

				if (thr_locked) {
					spin_unlock(&thr->thr_cmd_list_lock);
					thr_locked = false;
				}
				spin_unlock_irq(&p_cmd_threads->cmd_list_lock);
				p_locked = false;

				if (cmd->cmd_thr == NULL) {
					TRACE_DBG("Assigning thread %p on cmd %p",
						thr, cmd);
					cmd->cmd_thr = thr;
				}

				scst_process_active_cmd(cmd, false);
				someth_done = true;
			}

			if (thr_locked && p_locked) {
				/* We need to maintain order of locks and unlocks */
				spin_unlock(&thr->thr_cmd_list_lock);
				spin_unlock(&p_cmd_threads->cmd_list_lock);
				spin_lock(&thr->thr_cmd_list_lock);
				p_locked = false;
			} else if (!thr_locked) {
				if (p_locked) {
					spin_unlock_irq(&p_cmd_threads->cmd_list_lock);
					p_locked = false;
				}
				spin_lock_irq(&thr->thr_cmd_list_lock);
				thr_locked = true;
			}

			thr_cnt = 0;
			while (!list_empty(&thr->thr_active_cmd_list)) {
				struct scst_cmd *cmd = list_first_entry(
							&thr->thr_active_cmd_list,
							typeof(*cmd), cmd_list_entry);

				TRACE_DBG("Deleting cmd %p from thr active cmd list", cmd);
				list_del(&cmd->cmd_list_entry);

				spin_unlock_irq(&thr->thr_cmd_list_lock);
				thr_locked = false;

				scst_process_active_cmd(cmd, false);

				someth_done = true;

				if (++thr_cnt == 2)
					break;
				else {
					spin_lock_irq(&thr->thr_cmd_list_lock);
					thr_locked = true;
				}
			}
		} while (someth_done);

		EXTRACHECKS_BUG_ON(p_locked);

		if (thr_locked) {
			spin_unlock_irq(&thr->thr_cmd_list_lock);
			thr_locked = false;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
		if (scst_poll_ns > 0) {
			struct timespec ts;
			ktime_t end, kt;
			int rc;

			rc = __getnstimeofday(&ts);
			if (unlikely(rc != 0)) {
				WARN_ON_ONCE(rc);
				goto go;
			}

			end = timespec_to_ktime(ts);
			end = ktime_add_ns(end, scst_poll_ns);

			do {
				barrier();
				if (!list_empty(&p_cmd_threads->active_cmd_list) ||
				    !list_empty(&thr->thr_active_cmd_list)) {
					TRACE_DBG("Poll successful");
					goto again;
				}
				cpu_relax();
				rc = __getnstimeofday(&ts);
				if (unlikely(rc != 0)) {
					WARN_ON_ONCE(rc);
					goto go;
				}
				kt = timespec_to_ktime(ts);
			} while (ktime_before(kt, end));
		}

go:
#endif
		spin_lock_irq(&p_cmd_threads->cmd_list_lock);
		spin_lock(&thr->thr_cmd_list_lock);
	}
	spin_unlock(&thr->thr_cmd_list_lock);
	spin_unlock_irq(&p_cmd_threads->cmd_list_lock);

	scst_ioctx_put(p_cmd_threads);

	TRACE(TRACE_MINOR, "Processing thread %s finished", current->comm);

	TRACE_EXIT();
	return 0;
}

void scst_cmd_tasklet(long p)
{
	struct scst_percpu_info *i = (struct scst_percpu_info *)p;

	TRACE_ENTRY();

	spin_lock_irq(&i->tasklet_lock);
	scst_do_job_active(&i->tasklet_cmd_list, &i->tasklet_lock, true);
	spin_unlock_irq(&i->tasklet_lock);

	TRACE_EXIT();
	return;
}

/*
 * Returns 0 on success, or > 0 if SCST_FLAG_SUSPENDED set and
 * SCST_FLAG_SUSPENDING - not. No locks, protection is done by the
 * suspended activity.
 */
static int scst_get_mgmt(struct scst_mgmt_cmd *mcmd)
{
	int res = 0;

	TRACE_ENTRY();

	mcmd->cpu_cmd_counter = scst_get();

	if (unlikely(test_bit(SCST_FLAG_SUSPENDED, &scst_flags) &&
		     !test_bit(SCST_FLAG_SUSPENDING, &scst_flags))) {
		scst_put(mcmd->cpu_cmd_counter);
		TRACE_MGMT_DBG("%s", "FLAG SUSPENDED set, skipping");
		res = 1;
		goto out;
	}

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/*
 * Returns 0 on success, < 0 if there is no device handler or
 * > 0 if SCST_FLAG_SUSPENDED set and SCST_FLAG_SUSPENDING - not.
 * No locks, protection is done by the suspended activity.
 */
static int scst_mgmt_translate_lun(struct scst_mgmt_cmd *mcmd)
{
	struct scst_tgt_dev *tgt_dev;
	int res;

	TRACE_ENTRY();

	TRACE_DBG("Finding tgt_dev for mgmt cmd %p (lun %lld)", mcmd,
	      (unsigned long long int)mcmd->lun);

	res = scst_get_mgmt(mcmd);
	if (unlikely(res != 0))
		goto out;

	tgt_dev = scst_lookup_tgt_dev(mcmd->sess, mcmd->lun);
	if (tgt_dev) {
		TRACE_DBG("tgt_dev %p found", tgt_dev);
		mcmd->mcmd_tgt_dev = tgt_dev;
		res = 0;
	} else {
		scst_put(mcmd->cpu_cmd_counter);
		res = -1;
	}

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* No locks */
void scst_done_cmd_mgmt(struct scst_cmd *cmd)
{
	struct scst_mgmt_cmd_stub *mstb, *t;
	bool wake = 0;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("cmd %p done (tag %llu)",
		       cmd, (unsigned long long int)cmd->tag);

	spin_lock_irqsave(&scst_mcmd_lock, flags);

	list_for_each_entry_safe(mstb, t, &cmd->mgmt_cmd_list,
			cmd_mgmt_cmd_list_entry) {
		struct scst_mgmt_cmd *mcmd;

		if (!mstb->done_counted)
			continue;

		mcmd = mstb->mcmd;
		TRACE_MGMT_DBG("mcmd %p, mcmd->cmd_done_wait_count %d",
			mcmd, mcmd->cmd_done_wait_count);

		mcmd->cmd_done_wait_count--;

		sBUG_ON(mcmd->cmd_done_wait_count < 0);

		if (mcmd->cmd_done_wait_count > 0) {
			TRACE_MGMT_DBG("cmd_done_wait_count(%d) not 0, "
				"skipping", mcmd->cmd_done_wait_count);
			goto check_free;
		}

		if (mcmd->state == SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_DONE) {
			mcmd->state = SCST_MCMD_STATE_AFFECTED_CMDS_DONE;
			TRACE_MGMT_DBG("Adding mgmt cmd %p to active mgmt cmd "
				"list", mcmd);
			list_add_tail(&mcmd->mgmt_cmd_list_entry,
				&scst_active_mgmt_cmd_list);
			wake = 1;
		}

check_free:
		if (!mstb->finish_counted) {
			TRACE_DBG("Releasing mstb %p", mstb);
			list_del(&mstb->cmd_mgmt_cmd_list_entry);
			mempool_free(mstb, scst_mgmt_stub_mempool);
		}
	}

	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	if (wake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	TRACE_EXIT();
	return;
}

/* Called under scst_mcmd_lock and IRQs disabled */
static void __scst_dec_finish_wait_count(struct scst_mgmt_cmd *mcmd, bool *wake)
{
	TRACE_ENTRY();

	mcmd->cmd_finish_wait_count--;

	sBUG_ON(mcmd->cmd_finish_wait_count < 0);

	if (mcmd->cmd_finish_wait_count > 0) {
		TRACE_MGMT_DBG("cmd_finish_wait_count(%d) not 0, "
			"skipping", mcmd->cmd_finish_wait_count);
		goto out;
	}

	if (mcmd->cmd_done_wait_count > 0) {
		TRACE_MGMT_DBG("cmd_done_wait_count(%d) not 0, "
			"skipping", mcmd->cmd_done_wait_count);
		goto out;
	}

	if (mcmd->state == SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_FINISHED) {
		mcmd->state = SCST_MCMD_STATE_DONE;
		TRACE_MGMT_DBG("Adding mgmt cmd %p to active mgmt cmd "
			"list",	mcmd);
		list_add_tail(&mcmd->mgmt_cmd_list_entry,
			&scst_active_mgmt_cmd_list);
		*wake = true;
	}

out:
	TRACE_EXIT();
	return;
}

/**
 * scst_prepare_async_mcmd() - prepare async management command
 *
 * Notifies SCST that management command is going to be async, i.e.
 * will be completed in another context.
 *
 * No SCST locks supposed to be held on entrance.
 */
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
EXPORT_SYMBOL_GPL(scst_prepare_async_mcmd);

/**
 * scst_async_mcmd_completed() - async management command completed
 *
 * Notifies SCST that async management command, prepared by
 * scst_prepare_async_mcmd(), completed.
 *
 * No SCST locks supposed to be held on entrance.
 */
void scst_async_mcmd_completed(struct scst_mgmt_cmd *mcmd, int status)
{
	unsigned long flags;
	bool wake = false;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Async mcmd %p completed (status %d)", mcmd, status);

	spin_lock_irqsave(&scst_mcmd_lock, flags);

	scst_mgmt_cmd_set_status(mcmd, status);

	__scst_dec_finish_wait_count(mcmd, &wake);

	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	if (wake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_async_mcmd_completed);

/* No locks */
void scst_finish_cmd_mgmt(struct scst_cmd *cmd)
{
	struct scst_mgmt_cmd_stub *mstb, *t;
	bool wake = false;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Aborted cmd %p finished (tag %llu, ref %d)", cmd,
		(unsigned long long int)cmd->tag, atomic_read(&cmd->cmd_ref));

	spin_lock_irqsave(&scst_mcmd_lock, flags);

	list_for_each_entry_safe(mstb, t, &cmd->mgmt_cmd_list,
			cmd_mgmt_cmd_list_entry) {
		struct scst_mgmt_cmd *mcmd = mstb->mcmd;

		TRACE_MGMT_DBG("mcmd %p, mcmd->cmd_finish_wait_count %d", mcmd,
			mcmd->cmd_finish_wait_count);

		sBUG_ON(!mstb->finish_counted);

		if (cmd->completed)
			mcmd->completed_cmd_count++;

		__scst_dec_finish_wait_count(mcmd, &wake);

		TRACE_DBG("Releasing mstb %p", mstb);
		list_del(&mstb->cmd_mgmt_cmd_list_entry);
		mempool_free(mstb, scst_mgmt_stub_mempool);
	}

	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	if (wake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	TRACE_EXIT();
	return;
}

static void scst_call_dev_task_mgmt_fn_received(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_dev_type *h = tgt_dev->dev->handler;

	mcmd->task_mgmt_fn_received_called = 1;

	if (h->task_mgmt_fn_received) {
		TRACE_MGMT_DBG("Calling dev handler %s task_mgmt_fn_received(fn=%d)",
			h->name, mcmd->fn);
		h->task_mgmt_fn_received(mcmd, tgt_dev);
		TRACE_MGMT_DBG("Dev handler %s task_mgmt_fn_received() returned",
		      h->name);
	}
	return;
}

static void scst_call_dev_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_dev_type *h = tgt_dev->dev->handler;

	if (h->task_mgmt_fn_done) {
		TRACE_MGMT_DBG("Calling dev handler %s task_mgmt_fn_done(fn=%d)",
			h->name, mcmd->fn);
		h->task_mgmt_fn_done(mcmd, tgt_dev);
		TRACE_MGMT_DBG("Dev handler %s task_mgmt_fn_done() returned",
		      h->name);
	}
	return;
}

static inline int scst_is_strict_mgmt_fn(int mgmt_fn)
{
	switch (mgmt_fn) {
#ifdef CONFIG_SCST_ABORT_CONSIDER_FINISHED_TASKS_AS_NOT_EXISTING
	case SCST_ABORT_TASK:
		return 1;
#endif
#if 0
	case SCST_ABORT_TASK_SET:
	case SCST_CLEAR_TASK_SET:
		return 1;
#endif
	default:
		return 0;
	}
}

/*
 * If mcmd != NULL, must be called under sess_list_lock to sync with "finished"
 * flag assignment in scst_finish_cmd()
 */
void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	bool other_ini, bool call_dev_task_mgmt_fn_received)
{
	unsigned long flags;
	static DEFINE_SPINLOCK(other_ini_lock);

	TRACE_ENTRY();

	/* Fantom EC commands must not leak here */
	sBUG_ON((cmd->cdb[0] == EXTENDED_COPY) && cmd->internal);

	/*
	 * Help Coverity recognize that mcmd != NULL if
	 * call_dev_task_mgmt_fn_received == true.
	 */
	if (call_dev_task_mgmt_fn_received)
		EXTRACHECKS_BUG_ON(!mcmd);

	TRACE(TRACE_SCSI|TRACE_MGMT_DEBUG, "Aborting cmd %p (tag %llu, op %s)",
		cmd, (unsigned long long int)cmd->tag, scst_get_opcode_name(cmd));

	/* To protect from concurrent aborts */
	spin_lock_irqsave(&other_ini_lock, flags);

	if (other_ini) {
		struct scst_device *dev = NULL;

		/* Might be necessary if command aborted several times */
		if (!test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
			set_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);

		/* Necessary for scst_xmit_process_aborted_cmd */
		if (cmd->dev != NULL)
			dev = cmd->dev;
		else if ((mcmd != NULL) && (mcmd->mcmd_tgt_dev != NULL))
			dev = mcmd->mcmd_tgt_dev->dev;

		if (dev != NULL) {
			if (dev->tas)
				set_bit(SCST_CMD_DEVICE_TAS, &cmd->cmd_flags);
		} else
			PRINT_WARNING("Abort cmd %p from other initiator, but "
				"neither cmd, nor mcmd %p have tgt_dev set, so "
				"TAS information can be lost", cmd, mcmd);
	} else {
		/* Might be necessary if command aborted several times */
		clear_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
	}

	set_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);

	spin_unlock_irqrestore(&other_ini_lock, flags);

	/*
	 * To sync with setting cmd->done in scst_pre_xmit_response() (with
	 * scst_finish_cmd() we synced by using sess_list_lock) and with
	 * setting UA for aborted cmd in scst_set_pending_UA().
	 */
	smp_mb__after_set_bit();

	if (cmd->cdb[0] == EXTENDED_COPY)
		scst_cm_abort_ec_cmd(cmd);

	if (cmd->tgt_dev == NULL) {
		spin_lock_irqsave(&scst_init_lock, flags);
		scst_init_poll_cnt++;
		spin_unlock_irqrestore(&scst_init_lock, flags);
		wake_up(&scst_init_cmd_list_waitQ);
	}

	if (!cmd->finished && call_dev_task_mgmt_fn_received &&
	    (cmd->tgt_dev != NULL))
		scst_call_dev_task_mgmt_fn_received(mcmd, cmd->tgt_dev);

	spin_lock_irqsave(&scst_mcmd_lock, flags);
	if ((mcmd != NULL) && !cmd->finished) {
		struct scst_mgmt_cmd_stub *mstb;

		mstb = mempool_alloc(scst_mgmt_stub_mempool, GFP_ATOMIC);
		if (mstb == NULL) {
			PRINT_CRIT_ERROR("Allocation of management command "
				"stub failed (mcmd %p, cmd %p)", mcmd, cmd);
			goto unlock;
		}
		memset(mstb, 0, sizeof(*mstb));

		TRACE_DBG("mstb %p, mcmd %p", mstb, mcmd);

		mstb->mcmd = mcmd;

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

		if (cmd->sent_for_exec && !cmd->done) {
			TRACE_MGMT_DBG("cmd %p (tag %llu) is being executed",
				cmd, (unsigned long long int)cmd->tag);
			mstb->done_counted = 1;
			mcmd->cmd_done_wait_count++;
		}

		/*
		 * We don't have to wait the command's status delivery finish
		 * to other initiators + it can affect MPIO failover.
		 */
		if (!other_ini) {
			mstb->finish_counted = 1;
			mcmd->cmd_finish_wait_count++;
		}

		if (mstb->done_counted || mstb->finish_counted) {
			unsigned long t;
			char state_name[32];

			if (mcmd->fn != SCST_PR_ABORT_ALL)
				t = TRACE_MGMT;
			else
				t = TRACE_MGMT_DEBUG;
			TRACE(t, "cmd %p (tag %llu, "
				"sn %u) being executed/xmitted (state %s, "
				"op %s, proc time %ld sec., timeout %d sec.), "
				"deferring ABORT (cmd_done_wait_count %d, "
				"cmd_finish_wait_count %d, internal %d, mcmd "
				"fn %d (mcmd %p), initiator %s, target %s)",
				cmd, (unsigned long long int)cmd->tag,
				cmd->sn, scst_get_cmd_state_name(state_name,
					sizeof(state_name), cmd->state),
				scst_get_opcode_name(cmd),
				(long)(jiffies - cmd->start_time) / HZ,
				cmd->timeout / HZ, mcmd->cmd_done_wait_count,
				mcmd->cmd_finish_wait_count, cmd->internal,
				mcmd->fn, mcmd, mcmd->sess->initiator_name,
				mcmd->sess->tgt->tgt_name);
			/*
			 * cmd can't die here or sess_list_lock already taken
			 * and cmd is in the sess list
			 */
			list_add_tail(&mstb->cmd_mgmt_cmd_list_entry,
				&cmd->mgmt_cmd_list);
		} else {
			/* We don't need to wait for this cmd */
			mempool_free(mstb, scst_mgmt_stub_mempool);
		}

		if (!cmd->internal && cmd->tgtt->on_abort_cmd)
			cmd->tgtt->on_abort_cmd(cmd);
	}

unlock:
	spin_unlock_irqrestore(&scst_mcmd_lock, flags);

	tm_dbg_release_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* No locks. Returns 0, if mcmd should be processed further. */
static int scst_set_mcmd_next_state(struct scst_mgmt_cmd *mcmd)
{
	int res;

	spin_lock_irq(&scst_mcmd_lock);

	switch (mcmd->state) {
	case SCST_MCMD_STATE_INIT:
	case SCST_MCMD_STATE_EXEC:
		if (mcmd->cmd_done_wait_count == 0) {
			mcmd->state = SCST_MCMD_STATE_AFFECTED_CMDS_DONE;
			res = 0;
		} else {
			TRACE(TRACE_SCSI|TRACE_MGMT_DEBUG,
				"cmd_done_wait_count(%d) not 0, "
				"preparing to wait", mcmd->cmd_done_wait_count);
			mcmd->state = SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_DONE;
			res = -1;
		}
		break;

	case SCST_MCMD_STATE_AFFECTED_CMDS_DONE:
		if (mcmd->cmd_finish_wait_count == 0) {
			mcmd->state = SCST_MCMD_STATE_DONE;
			res = 0;
		} else {
			TRACE(TRACE_SCSI|TRACE_MGMT_DEBUG,
				"cmd_finish_wait_count(%d) not 0, "
				"preparing to wait",
				mcmd->cmd_finish_wait_count);
			mcmd->state = SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_FINISHED;
			res = -1;
		}
		break;

	case SCST_MCMD_STATE_DONE:
		mcmd->state = SCST_MCMD_STATE_FINISHED;
		res = 0;
		break;

	default:
	{
		char fn_name[16], state_name[32];

		PRINT_CRIT_ERROR("Wrong mcmd %p state %s (fn %s, "
			"cmd_finish_wait_count %d, cmd_done_wait_count %d)",
			mcmd, scst_get_mcmd_state_name(state_name,
					sizeof(state_name), mcmd->state),
			scst_get_tm_fn_name(fn_name, sizeof(fn_name), mcmd->fn),
			mcmd->cmd_finish_wait_count, mcmd->cmd_done_wait_count);
#if !defined(__CHECKER__)
		spin_unlock_irq(&scst_mcmd_lock);
#endif
		res = -1;
		sBUG();
	}
	}

	spin_unlock_irq(&scst_mcmd_lock);

	return res;
}

/* IRQs supposed to be disabled */
static bool __scst_check_unblock_aborted_cmd(struct scst_cmd *cmd,
	struct list_head *list_entry, bool blocked)
{
	bool res;

	if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
		list_del(list_entry);
		if (blocked)
			cmd->cmd_global_stpg_blocked = 0;
		spin_lock(&cmd->cmd_threads->cmd_list_lock);
		list_add_tail(&cmd->cmd_list_entry,
			&cmd->cmd_threads->active_cmd_list);
		wake_up(&cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_threads->cmd_list_lock);
		res = 1;
	} else
		res = 0;
	return res;
}

void scst_unblock_aborted_cmds(const struct scst_tgt *tgt,
	const struct scst_session *sess, const struct scst_device *device,
	bool scst_mutex_held)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	if (!scst_mutex_held)
		mutex_lock(&scst_mutex);
	else
		lockdep_assert_held(&scst_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		struct scst_cmd *cmd, *tcmd;
		struct scst_tgt_dev *tgt_dev;

		if ((device != NULL) && (device != dev))
			continue;

		spin_lock_bh(&dev->dev_lock);
		local_irq_disable_nort();
		list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
					blocked_cmd_list_entry) {

			if ((tgt != NULL) && (tgt != cmd->tgt))
				continue;
			if ((sess != NULL) && (sess != cmd->sess))
				continue;

			if (__scst_check_unblock_aborted_cmd(cmd,
					&cmd->blocked_cmd_list_entry, true)) {
				TRACE_MGMT_DBG("Unblock aborted blocked cmd %p", cmd);
			}
		}
		local_irq_enable_nort();
		spin_unlock_bh(&dev->dev_lock);

		local_irq_disable_nort();
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
					dev_tgt_dev_list_entry) {
			struct scst_order_data *order_data = tgt_dev->curr_order_data;

			spin_lock(&order_data->sn_lock);
			list_for_each_entry_safe(cmd, tcmd,
					&order_data->deferred_cmd_list,
					deferred_cmd_list_entry) {

				if ((tgt != NULL) && (tgt != cmd->tgt))
					continue;
				if ((sess != NULL) && (sess != cmd->sess))
					continue;

				if (__scst_check_unblock_aborted_cmd(cmd,
						&cmd->deferred_cmd_list_entry, false)) {
					TRACE_MGMT_DBG("Unblocked aborted SN "
						"cmd %p (sn %u)", cmd, cmd->sn);
					order_data->def_cmd_count--;
				}
			}
			spin_unlock(&order_data->sn_lock);
		}
		local_irq_enable_nort();
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
	bool other_ini;

	TRACE_ENTRY();

	if ((mcmd->fn == SCST_PR_ABORT_ALL) &&
	    (mcmd->origin_pr_cmd->sess != sess))
		other_ini = true;
	else
		other_ini = false;

	spin_lock_irq(&sess->sess_list_lock);

	TRACE_DBG("Searching in sess cmd list (sess=%p)", sess);
	list_for_each_entry(cmd, &sess->sess_cmd_list,
			    sess_cmd_list_entry) {
		if ((mcmd->fn == SCST_PR_ABORT_ALL) &&
		    (mcmd->origin_pr_cmd == cmd))
			continue;
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

	TRACE_EXIT();
	return;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_task_set(struct scst_mgmt_cmd *mcmd)
{
	int res;
	struct scst_tgt_dev *tgt_dev = mcmd->mcmd_tgt_dev;

	TRACE(TRACE_MGMT, "Aborting task set (lun=%lld, mcmd=%p)",
	      (unsigned long long int)tgt_dev->lun, mcmd);

	__scst_abort_task_set(mcmd, tgt_dev);

	if (mcmd->fn == SCST_PR_ABORT_ALL) {
		struct scst_pr_abort_all_pending_mgmt_cmds_counter *pr_cnt =
			mcmd->origin_pr_cmd->pr_abort_counter;
		if (atomic_dec_and_test(&pr_cnt->pr_aborting_cnt))
			complete_all(&pr_cnt->pr_aborting_cmpl);
	}

	tm_dbg_task_mgmt(mcmd->mcmd_tgt_dev->dev, "ABORT TASK SET/PR ABORT", 0);

	scst_unblock_aborted_cmds(tgt_dev->sess->tgt, tgt_dev->sess, tgt_dev->dev, false);

	scst_call_dev_task_mgmt_fn_received(mcmd, tgt_dev);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

static bool scst_is_cmd_belongs_to_dev(struct scst_cmd *cmd,
				       struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;
	bool res;

	TRACE_ENTRY();

	TRACE_DBG("Finding match for dev %s and cmd %p (lun %lld)",
		  dev->virt_name, cmd, (unsigned long long int)cmd->lun);

	tgt_dev = scst_lookup_tgt_dev(cmd->sess, cmd->lun);
	res = tgt_dev && tgt_dev->dev == dev;

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
		(unsigned long long int)mcmd->lun, mcmd);

#if 0 /* we are SAM-3 */
	/*
	 * When a logical unit is aborting one or more tasks from a SCSI
	 * initiator port with the TASK ABORTED status it should complete all
	 * of those tasks before entering additional tasks from that SCSI
	 * initiator port into the task set - SAM2
	 */
	mcmd->needs_unblocking = 1;
	spin_lock_bh(&dev->dev_lock);
	scst_block_dev(dev);
	spin_unlock_bh(&dev->dev_lock);
#endif

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

		TRACE_DBG("Searching in sess cmd list (sess=%p)", sess);
		list_for_each_entry(cmd, &sess->sess_cmd_list,
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

	scst_unblock_aborted_cmds(NULL, NULL, dev, true);

	if (!dev->tas) {
		uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
		int sl;

		sl = scst_set_sense(sense_buffer, sizeof(sense_buffer),
			dev->d_sense,
			SCST_LOAD_SENSE(scst_sense_cleared_by_another_ini_UA));

		list_for_each_entry(tgt_dev, &UA_tgt_devs,
				extra_tgt_dev_list_entry) {
			/*
			 * Potentially, setting UA here, when the aborted
			 * commands are still running, can lead to a situation
			 * that one of them could take it, then that would be
			 * detected and the UA requeued. But, meanwhile, one or
			 * more subsequent, i.e. not aborted, commands can
			 * "leak" executed normally. So, as result, the
			 * UA would be delivered one or more commands "later".
			 * However, that should be OK, because, if multiple
			 * commands are being executed in parallel, you can't
			 * control exact order of UA delivery anyway.
			 */
			scst_check_set_UA(tgt_dev, sense_buffer, sl, 0);
		}
	}

	mutex_unlock(&scst_mutex);

	scst_call_dev_task_mgmt_fn_received(mcmd, mcmd->mcmd_tgt_dev);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Returns 0 if the command processing should be continued,
 * >0, if it should be requeued, <0 otherwise.
 */
static int scst_mgmt_cmd_init(struct scst_mgmt_cmd *mcmd)
{
	int res = 0, rc, t;

	TRACE_ENTRY();

	t = mcmd->sess->acg->acg_black_hole_type;
	if (unlikely((t == SCST_ACG_BLACK_HOLE_ALL) ||
		     (t == SCST_ACG_BLACK_HOLE_DATA_MCMD))) {
		TRACE_MGMT_DBG("Dropping mcmd %p (fn %d, initiator %s)", mcmd,
			mcmd->fn, mcmd->sess->initiator_name);
		mcmd->mcmd_dropped = 1;
	}

	switch (mcmd->fn) {
	case SCST_ABORT_TASK:
	{
		struct scst_session *sess = mcmd->sess;
		struct scst_cmd *cmd;
		struct scst_tgt_dev *tgt_dev;

		spin_lock_irq(&sess->sess_list_lock);
		cmd = __scst_find_cmd_by_tag(sess, mcmd->tag, true);
		if (cmd == NULL) {
			TRACE_MGMT_DBG("ABORT TASK: command "
			      "for tag %llu not found",
			      (unsigned long long int)mcmd->tag);
			scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_TASK_NOT_EXIST);
			spin_unlock_irq(&sess->sess_list_lock);
			res = scst_set_mcmd_next_state(mcmd);
			goto out;
		}
		__scst_cmd_get(cmd);
		tgt_dev = cmd->tgt_dev;
		if (tgt_dev != NULL)
			mcmd->cpu_cmd_counter = scst_get();
		spin_unlock_irq(&sess->sess_list_lock);
		TRACE_DBG("Cmd to abort %p for tag %llu found (tgt_dev %p)",
			cmd, (unsigned long long int)mcmd->tag, tgt_dev);
		mcmd->cmd_to_abort = cmd;
		sBUG_ON(mcmd->mcmd_tgt_dev != NULL);
		mcmd->mcmd_tgt_dev = tgt_dev;
		mcmd->state = SCST_MCMD_STATE_EXEC;
		break;
	}

	case SCST_TARGET_RESET:
		/*
		 * Needed to protect against race, when a device added after
		 * blocking, so unblocking then will make dev->block_count
		 * of the new device negative.
		 */
		rc = scst_get_mgmt(mcmd);
		if (rc == 0) {
			mcmd->state = SCST_MCMD_STATE_EXEC;
			mcmd->scst_get_called = 1;
		} else {
			EXTRACHECKS_BUG_ON(rc < 0);
			res = rc;
		}
		break;

	case SCST_NEXUS_LOSS_SESS:
	case SCST_ABORT_ALL_TASKS_SESS:
	case SCST_NEXUS_LOSS:
	case SCST_ABORT_ALL_TASKS:
	case SCST_UNREG_SESS_TM:
		mcmd->state = SCST_MCMD_STATE_EXEC;
		break;

	case SCST_ABORT_TASK_SET:
	case SCST_CLEAR_ACA:
	case SCST_CLEAR_TASK_SET:
	case SCST_LUN_RESET:
	case SCST_PR_ABORT_ALL:
		rc = scst_mgmt_translate_lun(mcmd);
		if (rc == 0)
			mcmd->state = SCST_MCMD_STATE_EXEC;
		else if (rc < 0) {
			PRINT_ERROR("Corresponding device for LUN %lld not "
				"found", (unsigned long long int)mcmd->lun);
			scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_LUN_NOT_EXIST);
			res = scst_set_mcmd_next_state(mcmd);
		} else
			res = rc;
		break;

	default:
		sBUG();
	}

out:
	scst_event_queue_tm_fn_received(mcmd);

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
	LIST_HEAD(host_devs);

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Target reset (mcmd %p, cmd count %d)",
		mcmd, atomic_read(&mcmd->sess->sess_cmd_count));

	mcmd->needs_unblocking = 1;

	mutex_lock(&scst_mutex);

	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		struct scst_device *d;
		struct scst_tgt_dev *tgt_dev;
		struct scst_lksb pr_lksb;
		int found = 0;

		dev = acg_dev->dev;

		scst_res_lock(dev, &pr_lksb);
		scst_block_dev(dev);
		scst_process_reset(dev, mcmd->sess, NULL, mcmd, true);
		scst_res_unlock(dev, &pr_lksb);

		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			if (mcmd->sess == tgt_dev->sess) {
				scst_call_dev_task_mgmt_fn_received(mcmd, tgt_dev);
				break;
			}
		}

		tm_dbg_task_mgmt(dev, "TARGET RESET", 0);

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
	}

	scst_unblock_aborted_cmds(NULL, NULL, NULL, true);

	/*
	 * We suppose here that for all commands that already on devices
	 * on/after scsi_reset_provider() completion callbacks will be called.
	 */

	list_for_each_entry(dev, &host_devs, tm_dev_list_entry) {
		/* dev->scsi_dev must be non-NULL here */
		TRACE(TRACE_MGMT, "Resetting host %d bus ",
			dev->scsi_dev->host->host_no);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
		{
			int arg = SG_SCSI_RESET_TARGET;

			rc = scsi_ioctl_reset(dev->scsi_dev,
					      (__force __user int *)&arg);
		}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
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
			scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_FAILED);
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
	struct scst_lksb pr_lksb;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Resetting LUN %lld (mcmd %p)",
	      (unsigned long long int)tgt_dev->lun, mcmd);

	mcmd->needs_unblocking = 1;

	scst_res_lock(dev, &pr_lksb);
	scst_block_dev(dev);
	scst_process_reset(dev, mcmd->sess, NULL, mcmd, true);
	scst_res_unlock(dev, &pr_lksb);

	scst_call_dev_task_mgmt_fn_received(mcmd, tgt_dev);

	if (dev->scsi_dev != NULL) {
		TRACE(TRACE_MGMT, "Resetting host %d bus ",
		      dev->scsi_dev->host->host_no);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
		{
			int arg = SG_SCSI_RESET_DEVICE;

			rc = scsi_ioctl_reset(dev->scsi_dev,
					      (__force __user int *)&arg);
		}
#else
		rc = scsi_reset_provider(dev->scsi_dev, SCSI_TRY_RESET_DEVICE);
#endif
		TRACE(TRACE_MGMT, "scsi_reset_provider(%s) returned %d",
		      dev->virt_name, rc);
#if 0
		if (rc != SUCCESS && mcmd->status == SCST_MGMT_STATUS_SUCCESS)
			scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_FAILED);
#else
		/*
		 * scsi_reset_provider() returns very weird status, so let's
		 * always succeed
		 */
#endif
		dev->scsi_dev->was_reset = 0;
	}

	scst_unblock_aborted_cmds(NULL, NULL, dev, false);

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

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			scst_nexus_loss(tgt_dev,
				(mcmd->fn != SCST_UNREG_SESS_TM));
		}
	}

	TRACE_EXIT();
	return;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_abort_all_nexus_loss_sess(struct scst_mgmt_cmd *mcmd,
	int nexus_loss_unreg_sess)
{
	int res;
	int i;
	struct scst_session *sess = mcmd->sess;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	if (nexus_loss_unreg_sess) {
		TRACE_MGMT_DBG("Nexus loss or UNREG SESS for sess %p (mcmd %p)",
			sess, mcmd);
	} else {
		TRACE_MGMT_DBG("Aborting all from sess %p (mcmd %p)",
			sess, mcmd);
	}

	mutex_lock(&scst_mutex);

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			__scst_abort_task_set(mcmd, tgt_dev);

			scst_call_dev_task_mgmt_fn_received(mcmd, tgt_dev);

			tm_dbg_task_mgmt(tgt_dev->dev, "NEXUS LOSS SESS or "
				"ABORT ALL SESS or UNREG SESS",
				(mcmd->fn == SCST_UNREG_SESS_TM));
		}
	}

	scst_unblock_aborted_cmds(NULL, sess, NULL, true);

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
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry(tgt_dev, head,
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
		TRACE_MGMT_DBG("I_T Nexus loss (tgt %p, mcmd %p)",
			tgt, mcmd);
	} else {
		TRACE_MGMT_DBG("Aborting all from tgt %p (mcmd %p)",
			tgt, mcmd);
	}

	mutex_lock(&scst_mutex);

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry(tgt_dev, head,
					sess_tgt_dev_list_entry) {
				__scst_abort_task_set(mcmd, tgt_dev);

				if (mcmd->sess == tgt_dev->sess)
					scst_call_dev_task_mgmt_fn_received(
						mcmd, tgt_dev);

				tm_dbg_task_mgmt(tgt_dev->dev, "NEXUS LOSS or "
					"ABORT ALL", 0);
			}
		}
	}

	scst_unblock_aborted_cmds(tgt, NULL, NULL, true);

	mutex_unlock(&scst_mutex);

	res = scst_set_mcmd_next_state(mcmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_abort_task(struct scst_mgmt_cmd *mcmd)
{
	int res;
	struct scst_cmd *cmd = mcmd->cmd_to_abort;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Aborting task (cmd %p, sn %d, set %d, tag %llu, "
		"queue_type %x)", cmd, cmd->sn, cmd->sn_set,
		(unsigned long long int)mcmd->tag, cmd->queue_type);

	if (mcmd->lun_set && (mcmd->lun != cmd->lun)) {
		PRINT_ERROR("ABORT TASK: LUN mismatch: mcmd LUN %llx, "
			"cmd LUN %llx, cmd tag %llu",
			(unsigned long long int)mcmd->lun,
			(unsigned long long int)cmd->lun,
			(unsigned long long int)mcmd->tag);
		scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_REJECTED);
	} else if (mcmd->cmd_sn_set &&
		   (scst_sn_before(mcmd->cmd_sn, cmd->tgt_sn) ||
		    (mcmd->cmd_sn == cmd->tgt_sn))) {
		PRINT_ERROR("ABORT TASK: SN mismatch: mcmd SN %x, "
			"cmd SN %x, cmd tag %llu", mcmd->cmd_sn,
			cmd->tgt_sn, (unsigned long long int)mcmd->tag);
		scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_REJECTED);
	} else {
		spin_lock_irq(&cmd->sess->sess_list_lock);
		scst_abort_cmd(cmd, mcmd, 0, 1);
		spin_unlock_irq(&cmd->sess->sess_list_lock);

		scst_unblock_aborted_cmds(cmd->tgt, cmd->sess, cmd->dev, false);
	}

	res = scst_set_mcmd_next_state(mcmd);

	mcmd->cmd_to_abort = NULL; /* just in case */

	__scst_cmd_put(cmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 if the command processing should be continued, <0 otherwise */
static int scst_mgmt_cmd_exec(struct scst_mgmt_cmd *mcmd)
{
	int res = 0;

	TRACE_ENTRY();

	switch (mcmd->fn) {
	case SCST_ABORT_TASK:
		res = scst_abort_task(mcmd);
		break;

	case SCST_ABORT_TASK_SET:
	case SCST_PR_ABORT_ALL:
		res = scst_abort_task_set(mcmd);
		break;

	case SCST_CLEAR_TASK_SET:
		if (mcmd->mcmd_tgt_dev->dev->tst == SCST_TST_1_SEP_TASK_SETS)
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
		/* Nothing to do (yet) */
		scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_FN_NOT_SUPPORTED);
		goto out_done;

	default:
		PRINT_ERROR("Unknown task management function %d", mcmd->fn);
		scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_REJECTED);
		goto out_done;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	res = scst_set_mcmd_next_state(mcmd);
	goto out;
}

static void scst_call_task_mgmt_affected_cmds_done(struct scst_mgmt_cmd *mcmd)
{
	struct scst_session *sess = mcmd->sess;

	if ((sess->tgt->tgtt->task_mgmt_affected_cmds_done != NULL) &&
	    (mcmd->fn != SCST_UNREG_SESS_TM) &&
	    (mcmd->fn != SCST_PR_ABORT_ALL)) {
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
	int res, i;
	struct scst_session *sess = mcmd->sess;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;

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

	if (!mcmd->task_mgmt_fn_received_called)
		goto tgt_done;

	switch (mcmd->fn) {
	case SCST_ABORT_TASK:
	case SCST_ABORT_TASK_SET:
	case SCST_CLEAR_TASK_SET:
	case SCST_PR_ABORT_ALL:
	case SCST_LUN_RESET:
		scst_call_dev_task_mgmt_fn_done(mcmd, mcmd->mcmd_tgt_dev);
		break;

	case SCST_TARGET_RESET:
	{
		struct scst_acg *acg = sess->acg;
		struct scst_acg_dev *acg_dev;

		mutex_lock(&scst_mutex);
		list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
			dev = acg_dev->dev;
			list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
					dev_tgt_dev_list_entry) {
				if (mcmd->sess == tgt_dev->sess) {
					scst_call_dev_task_mgmt_fn_done(mcmd, tgt_dev);
					break;
				}
			}
		}
		mutex_unlock(&scst_mutex);
		break;
	}

	case SCST_ABORT_ALL_TASKS_SESS:
	case SCST_NEXUS_LOSS_SESS:
	case SCST_UNREG_SESS_TM:
		mutex_lock(&scst_mutex);
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];

			list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
				scst_call_dev_task_mgmt_fn_done(mcmd, tgt_dev);
			}
		}
		mutex_unlock(&scst_mutex);
		break;

	case SCST_ABORT_ALL_TASKS:
	case SCST_NEXUS_LOSS:
	{
		struct scst_session *s;
		struct scst_tgt *tgt = sess->tgt;

		mutex_lock(&scst_mutex);
		list_for_each_entry(s, &tgt->sess_list, sess_list_entry) {
			for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
				struct list_head *head = &s->sess_tgt_dev_list[i];
				struct scst_tgt_dev *tgt_dev;

				list_for_each_entry(tgt_dev, head,
						sess_tgt_dev_list_entry) {
					if (mcmd->sess == tgt_dev->sess)
						scst_call_dev_task_mgmt_fn_done(
							mcmd, tgt_dev);
				}
			}
		}
		mutex_unlock(&scst_mutex);
		break;
	}

	default:
		PRINT_ERROR("Wrong task management function %d on "
			"task_mgmt_fn_done() stage", mcmd->fn);
		break;
	}

tgt_done:
	scst_call_task_mgmt_affected_cmds_done(mcmd);

	switch (mcmd->fn) {
	case SCST_LUN_RESET:
	case SCST_TARGET_RESET:
	case SCST_NEXUS_LOSS_SESS:
	case SCST_NEXUS_LOSS:
	case SCST_UNREG_SESS_TM:
		scst_cm_free_pending_list_ids(sess);
		break;
	}

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
		scst_mgmt_cmd_set_status(mcmd, SCST_MGMT_STATUS_TASK_NOT_EXIST);

	if (mcmd->fn < SCST_UNREG_SESS_TM)
		TRACE(TRACE_MGMT, "TM fn %d (mcmd %p) finished, "
			"status %d", mcmd->fn, mcmd, mcmd->status);
	else
		TRACE_MGMT_DBG("TM fn %d (mcmd %p) finished, "
			"status %d", mcmd->fn, mcmd, mcmd->status);

	if (mcmd->fn == SCST_PR_ABORT_ALL) {
		mcmd->origin_pr_cmd->scst_cmd_done(mcmd->origin_pr_cmd,
					SCST_CMD_STATE_DEFAULT,
					SCST_CONTEXT_THREAD);
	} else if ((sess->tgt->tgtt->task_mgmt_fn_done != NULL) &&
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
		case SCST_CLEAR_TASK_SET:
			dev = mcmd->mcmd_tgt_dev->dev;
			spin_lock_bh(&dev->dev_lock);
			scst_unblock_dev(dev);
			spin_unlock_bh(&dev->dev_lock);
			break;

		case SCST_TARGET_RESET:
		{
			struct scst_acg *acg = mcmd->sess->acg;
			struct scst_acg_dev *acg_dev;

			mutex_lock(&scst_mutex);
			list_for_each_entry(acg_dev, &acg->acg_dev_list,
					acg_dev_list_entry) {
				dev = acg_dev->dev;
				spin_lock_bh(&dev->dev_lock);
				scst_unblock_dev(dev);
				spin_unlock_bh(&dev->dev_lock);
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

	/*
	 * We are in the TM thread and mcmd->state guaranteed to not be
	 * changed behind us.
	 */

	TRACE_DBG("mcmd %p, state %d", mcmd, mcmd->state);

	while (1) {
		switch (mcmd->state) {
		case SCST_MCMD_STATE_INIT:
			res = scst_mgmt_cmd_init(mcmd);
			if (res != 0)
				goto out;
			break;

		case SCST_MCMD_STATE_EXEC:
			if (scst_mgmt_cmd_exec(mcmd))
				goto out;
			break;

		case SCST_MCMD_STATE_AFFECTED_CMDS_DONE:
			if (scst_mgmt_affected_cmds_done(mcmd))
				goto out;
			break;

		case SCST_MCMD_STATE_DONE:
			scst_mgmt_cmd_send_done(mcmd);
			break;

		case SCST_MCMD_STATE_FINISHED:
			scst_free_mgmt_cmd(mcmd);
			/* mcmd is dead */
			goto out;

		default:
		{
			char fn_name[16], state_name[32];

			PRINT_CRIT_ERROR("Wrong mcmd %p state %s (fn %s, "
				"cmd_finish_wait_count %d, cmd_done_wait_count "
				"%d)", mcmd, scst_get_mcmd_state_name(state_name,
					sizeof(state_name), mcmd->state),
				scst_get_tm_fn_name(fn_name, sizeof(fn_name), mcmd->fn),
				mcmd->cmd_finish_wait_count,
				mcmd->cmd_done_wait_count);
			sBUG();
		}
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

	PRINT_INFO("Task management thread started");

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock_irq(&scst_mcmd_lock);
	while (!kthread_should_stop()) {
		wait_event_locked(scst_mgmt_cmd_list_waitQ,
				  test_mgmt_cmd_list(), lock_irq,
				  scst_mcmd_lock);

		while (!list_empty(&scst_active_mgmt_cmd_list)) {
			int rc;
			struct scst_mgmt_cmd *mcmd;

			mcmd = list_first_entry(&scst_active_mgmt_cmd_list,
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

	PRINT_INFO("Task management thread finished");

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
		PRINT_CRIT_ERROR("Lost TM fn %d, initiator %s", fn,
			sess->initiator_name);
		goto out;
	}

	mcmd->sess = sess;
	scst_sess_get(sess);

	atomic_inc(&sess->sess_cmd_count);

	mcmd->fn = fn;
	mcmd->state = SCST_MCMD_STATE_INIT;
	mcmd->tgt_priv = tgt_priv;

	if (fn == SCST_PR_ABORT_ALL) {
		atomic_inc(&mcmd->origin_pr_cmd->pr_abort_counter->pr_abort_pending_cnt);
		atomic_inc(&mcmd->origin_pr_cmd->pr_abort_counter->pr_aborting_cnt);
	}

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

	if (unlikely(sess->shut_phase != SCST_SESS_SPH_READY)) {
		PRINT_CRIT_ERROR("New mgmt cmd while shutting down the "
			"session %p shut_phase %ld", sess, sess->shut_phase);
		sBUG();
	}

	local_irq_save_nort(flags);

	spin_lock(&sess->sess_list_lock);

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

	local_irq_restore_nort(flags);

	wake_up(&scst_mgmt_cmd_list_waitQ);

out:
	TRACE_EXIT();
	return res;

out_unlock:
	spin_unlock(&sess->sess_list_lock);
	local_irq_restore_nort(flags);
	goto out;
}

/**
 * scst_rx_mgmt_fn() - create new management command and send it for execution
 *
 * Description:
 *    Creates new management command and sends it for execution.
 *
 *    Returns 0 for success, error code otherwise.
 *
 *    Must not be called in parallel with scst_unregister_session() for the
 *    same sess.
 */
int scst_rx_mgmt_fn(struct scst_session *sess,
	const struct scst_rx_mgmt_params *params)
{
	int res = -EFAULT;
	struct scst_mgmt_cmd *mcmd = NULL;
	char state_name[32];

	TRACE_ENTRY();

	switch (params->fn) {
	case SCST_ABORT_TASK:
		sBUG_ON(!params->tag_set);
		break;
	case SCST_TARGET_RESET:
	case SCST_ABORT_ALL_TASKS:
	case SCST_NEXUS_LOSS:
	case SCST_UNREG_SESS_TM:
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

	if (params->fn < SCST_UNREG_SESS_TM)
		TRACE(TRACE_MGMT, "TM fn %s/%d (mcmd %p, initiator %s, target %s)",
			scst_get_tm_fn_name(state_name, sizeof(state_name), params->fn),
			params->fn, mcmd, sess->initiator_name, sess->tgt->tgt_name);
	else
		TRACE_MGMT_DBG("TM fn %s/%d (mcmd %p)",
			scst_get_tm_fn_name(state_name, sizeof(state_name), params->fn),
			params->fn, mcmd);

	TRACE_MGMT_DBG("sess=%p, tag_set %d, tag %lld, lun_set %d, "
		"lun=%lld, cmd_sn_set %d, cmd_sn %d, priv %p", sess,
		params->tag_set,
		(unsigned long long int)params->tag,
		params->lun_set,
		(unsigned long long int)mcmd->lun,
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
 * Written by Jack Handy - jakkhandy@hotmail.com
 * Taken by Gennadiy Nerubayev <parakie@gmail.com> from
 * http://www.codeproject.com/KB/string/wildcmp.aspx. No license attached
 * to it, and it's posted on a free site; assumed to be free for use.
 *
 * Added the negative sign support - VLNB
 *
 * Also see comment for wildcmp().
 *
 * User space part of iSCSI-SCST also has a copy of this code, so fixing a bug
 * here, don't forget to fix the copy too!
 */
static bool __wildcmp(const char *wild, const char *string, int recursion_level)
{
	const char *cp = NULL, *mp = NULL;

	while ((*string) && (*wild != '*')) {
		if ((*wild == '!') && (recursion_level == 0))
			return !__wildcmp(++wild, string, ++recursion_level);

		if ((tolower(*wild) != tolower(*string)) && (*wild != '?'))
			return false;

		wild++;
		string++;
	}

	while (*string) {
		if ((*wild == '!') && (recursion_level == 0))
			return !__wildcmp(++wild, string, ++recursion_level);

		if (*wild == '*') {
			if (!*++wild)
				return true;

			mp = wild;
			cp = string+1;
		} else if ((tolower(*wild) == tolower(*string)) || (*wild == '?')) {
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
 * Also it supports boolean inversion sign '!', which does boolean inversion of
 * the value of the rest of the string. Only one '!' allowed in the pattern,
 * other '!' are treated as regular symbols. For instance:
 * if (wildcmp("bl!?h.*", "blah.jpg")) {
 *   // no match
 *  } else {
 *   // match
 *  }
 *
 * Also see comment for __wildcmp().
 */
static bool wildcmp(const char *wild, const char *string)
{
	return __wildcmp(wild, string, 0);
}

#ifdef CONFIG_SCST_PROC

/* scst_mutex supposed to be held */
static struct scst_acg *scst_find_acg_by_name_wild(const char *initiator_name)
{
	struct scst_acg *acg, *res = NULL;
	struct scst_acn *n;

	TRACE_ENTRY();

	list_for_each_entry(acg, &scst_acg_list, acg_list_entry) {
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

	list_for_each_entry(acg, &scst_acg_list, acg_list_entry) {
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

#else /* CONFIG_SCST_PROC */

/* scst_mutex supposed to be held */
static struct scst_acg *scst_find_tgt_acg_by_name_wild(struct scst_tgt *tgt,
	const char *initiator_name)
{
	struct scst_acg *acg, *res = NULL;
	struct scst_acn *n;

	TRACE_ENTRY();

	if (initiator_name == NULL)
		goto out;

	list_for_each_entry(acg, &tgt->tgt_acg_list, acg_list_entry) {
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

#endif /* CONFIG_SCST_PROC */

/* Must be called under scst_mutex */
static struct scst_acg *__scst_find_acg(struct scst_tgt *tgt,
	const char *initiator_name)
{
	struct scst_acg *acg = NULL;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_PROC
	if (initiator_name)
		acg = scst_find_acg_by_name_wild(initiator_name);
	if ((acg == NULL) && (tgt->default_group_name != NULL))
		acg = scst_find_acg_by_name(tgt->default_group_name);
	if (acg == NULL)
		acg = scst_default_acg;
#else
	acg = scst_find_tgt_acg_by_name_wild(tgt, initiator_name);
	if (acg == NULL)
		acg = tgt->default_acg;
#endif

	TRACE_EXIT_HRES((unsigned long)acg);
	return acg;
}

/* Must be called under scst_mutex */
struct scst_acg *scst_find_acg(const struct scst_session *sess)
{
	return __scst_find_acg(sess->tgt, sess->initiator_name);
}

/**
 * scst_initiator_has_luns() - check if this initiator will see any LUNs
 *
 * Checks if this initiator will see any LUNs upon connect to this target.
 * Returns true if yes and false otherwise.
 */
bool scst_initiator_has_luns(struct scst_tgt *tgt, const char *initiator_name)
{
	bool res;
	struct scst_acg *acg;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	acg = __scst_find_acg(tgt, initiator_name);

	res = !list_empty(&acg->acg_dev_list);

	if (!res)
		scst_event_queue_negative_luns_inquiry(tgt, initiator_name);

	mutex_unlock(&scst_mutex);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_initiator_has_luns);

/* Supposed to be called under scst_mutex */
static char *scst_get_unique_sess_name(struct list_head *sysfs_sess_list,
				       const char *initiator_name)
{
	char *name = (char *)initiator_name;
	struct scst_session *s;
	int len = 0, n = 1;

	BUG_ON(!initiator_name);
	lockdep_assert_held(&scst_mutex);

restart:
	list_for_each_entry(s, sysfs_sess_list, sysfs_sess_list_entry) {
		BUG_ON(!s->sess_name);
		if (strcmp(name, s->sess_name) == 0) {
			TRACE_DBG("Duplicated session from the same initiator "
				"%s found", name);

			if (name == initiator_name) {
				len = strlen(initiator_name) + 20;
				name = kmalloc(len, GFP_KERNEL);
				if (name == NULL) {
					PRINT_ERROR("Unable to allocate a "
						"replacement name (size %d)",
						len);
					break;
				}
			}

			snprintf(name, len, "%s_%d", initiator_name, n);
			n++;
			goto restart;
		}
	}
	return name;
}

static int scst_init_session(struct scst_session *sess)
{
	int res = 0;
	struct scst_cmd *cmd, *cmd_tmp;
	struct scst_mgmt_cmd *mcmd, *tm;
	int mwake = 0;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	sess->acg = scst_find_acg(sess);

	PRINT_INFO("Using security group \"%s\" for initiator \"%s\" "
		"(target %s)", sess->acg->acg_name, sess->initiator_name,
		sess->tgt->tgt_name);

	scst_get_acg(sess->acg);
	list_add_tail(&sess->acg_sess_list_entry, &sess->acg->acg_sess_list);

	TRACE_DBG("Adding sess %p to tgt->sess_list", sess);
	list_add_tail(&sess->sess_list_entry, &sess->tgt->sess_list);

	INIT_LIST_HEAD(&sess->sysfs_sess_list_entry);

	if (sess->tgt->tgtt->get_initiator_port_transport_id != NULL) {
		res = sess->tgt->tgtt->get_initiator_port_transport_id(
					sess->tgt, sess, &sess->transport_id);
		if (res != 0) {
			PRINT_ERROR("Unable to make initiator %s port "
				"transport id", sess->initiator_name);
			goto failed;
		}
		TRACE_PR("sess %p (ini %s), transport id %s/%d", sess,
			sess->initiator_name,
			debug_transport_id_to_initiator_name(
				sess->transport_id), sess->tgt->rel_tgt_id);
	}

	res = -ENOMEM;
	sess->sess_name = scst_get_unique_sess_name(&sess->tgt->sysfs_sess_list,
					       sess->initiator_name);
	if (!sess->sess_name)
		goto failed;

	res = scst_sess_sysfs_create(sess);
	if (res != 0)
		goto failed;

	list_add_tail(&sess->sysfs_sess_list_entry,
		      &sess->tgt->sysfs_sess_list);

	/*
	 * scst_sess_alloc_tgt_devs() must be called after session added in the
	 * sess_list to not race with scst_check_reassign_sess()!
	 */
	res = scst_sess_alloc_tgt_devs(sess);

failed:
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

	list_for_each_entry_safe(cmd, cmd_tmp, &sess->init_deferred_cmd_list,
				 cmd_list_entry) {
		TRACE_DBG("Deleting cmd %p from init deferred cmd list", cmd);
		list_del(&cmd->cmd_list_entry);
		atomic_dec(&sess->sess_cmd_count);
		spin_unlock_irq(&sess->sess_list_lock);
		scst_cmd_init_done(cmd, SCST_CONTEXT_THREAD);
		spin_lock_irq(&sess->sess_list_lock);
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
	/*
	 * In case of an error at this point the caller target driver supposed
	 * to already call this sess's unregistration.
	 */
	sess->init_phase = SCST_SESS_IPH_READY;
	spin_unlock_irq(&sess->sess_list_lock);

	if (mwake)
		wake_up(&scst_mgmt_cmd_list_waitQ);

	scst_sess_put(sess);

	TRACE_EXIT();
	return res;
}

/**
 * scst_register_session() - register session
 * @tgt:	target
 * @atomic:	true, if the function called in the atomic context. If false,
 *		 this function will block until the session registration is
 *		 completed.
 * @initiator_name: remote initiator's name, any NULL-terminated string,
 *		    e.g. iSCSI name, which used as the key to found appropriate
 *		    access control group. Could be NULL, then the default
 *		    target's LUNs are used.
 * @tgt_priv:	pointer to target driver's private data
 * @result_fn_data: any target driver supplied data
 * @result_fn:	pointer to the function that will be asynchronously called
 *		 when session initialization finishes.
 *		 Can be NULL. Parameters:
 *		    - sess - session
 *		    - data - target driver supplied to scst_register_session()
 *			     data
 *		    - result - session initialization result, 0 on success or
 *			      appropriate error code otherwise
 *
 * Description:
 *    Registers new session. Returns new session on success or NULL otherwise.
 *
 *    Note: A session creation and initialization is a complex task,
 *    which requires sleeping state, so it can't be fully done
 *    in interrupt context. Therefore the "bottom half" of it, if
 *    scst_register_session() is called from atomic context, will be
 *    done in SCST thread context. In this case scst_register_session()
 *    will return not completely initialized session, but the target
 *    driver can supply commands to this session via scst_rx_cmd().
 *    Those commands processing will be delayed inside SCST until
 *    the session initialization is finished, then their processing
 *    will be restarted. The target driver will be notified about
 *    finish of the session initialization by function result_fn().
 *    On success the target driver could do nothing, but if the
 *    initialization fails, the target driver must ensure that
 *    no more new commands being sent or will be sent to SCST after
 *    result_fn() returns. All already sent to SCST commands for
 *    failed session will be returned in xmit_response() with BUSY status.
 *    In case of failure the driver shall call scst_unregister_session()
 *    inside result_fn(), it will NOT be called automatically.
 */
struct scst_session *scst_register_session(struct scst_tgt *tgt, int atomic,
	const char *initiator_name, void *tgt_priv, void *result_fn_data,
	void (*result_fn)(struct scst_session *sess, void *data, int result))
{
	struct scst_session *sess;
	int res;
	unsigned long flags;

	TRACE_ENTRY();

	sess = scst_alloc_session(tgt, atomic ? GFP_ATOMIC : GFP_KERNEL,
		initiator_name);
	if (sess == NULL)
		goto out;

	scst_sess_set_tgt_priv(sess, tgt_priv);

	scst_sess_get(sess); /* one for registered session */
	scst_sess_get(sess); /* one held until sess is inited */

	if (atomic) {
		sess->reg_sess_data = result_fn_data;
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
EXPORT_SYMBOL_GPL(scst_register_session);

/**
 * scst_register_session_non_gpl() - register session (non-GPL version)
 * @tgt:	target
 * @initiator_name: remote initiator's name, any NULL-terminated string,
 *		    e.g. iSCSI name, which used as the key to found appropriate
 *		    access control group. Could be NULL, then the default
 *		    target's LUNs are used.
 * @tgt_priv:	pointer to target driver's private data
 *
 * Description:
 *    Registers new session. Returns new session on success or NULL otherwise.
 */
struct scst_session *scst_register_session_non_gpl(struct scst_tgt *tgt,
	const char *initiator_name, void *tgt_priv)
{
	return scst_register_session(tgt, 0, initiator_name, tgt_priv,
			NULL, NULL);
}
EXPORT_SYMBOL(scst_register_session_non_gpl);

/**
 * scst_unregister_session() - unregister session
 * @sess:	session to be unregistered
 * @wait:	if true, instructs to wait until all commands, which
 *		currently is being executed and belonged to the session,
 *		finished. Otherwise, target driver should be prepared to
 *		receive xmit_response() for the session's command after
 *		scst_unregister_session() returns.
 * @unreg_done_fn: pointer to the function that will be asynchronously called
 *		   when the last session's command finishes and
 *		   the session is about to be completely freed. Can be NULL.
 *		   Parameter:
 *			- sess - session
 *
 * Unregisters session.
 *
 * Notes:
 * - All outstanding commands will be finished regularly. After
 *   scst_unregister_session() returned, no new commands must be sent to
 *   SCST via scst_rx_cmd().
 *
 * - The caller must ensure that no scst_rx_cmd() or scst_rx_mgmt_fn_*() is
 *   called in parallel with scst_unregister_session().
 *
 * - Can be called before result_fn() of scst_register_session() called,
 *   i.e. during the session registration/initialization.
 *
 * - It is highly recommended to call scst_unregister_session() as soon as it
 *   gets clear that session will be unregistered and not to wait until all
 *   related commands finished. This function provides the wait functionality,
 *   but it also starts recovering stuck commands, if there are any.
 *   Otherwise, your target driver could wait for those commands forever.
 */
void scst_unregister_session(struct scst_session *sess, int wait,
	void (*unreg_done_fn)(struct scst_session *sess))
{
	unsigned long flags;
	DECLARE_COMPLETION_ONSTACK(c);
	int rc;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Unregistering session %p (wait %d)", sess, wait);

	sess->unreg_done_fn = unreg_done_fn;

	/* Abort all outstanding commands and clear reservation, if necessary */
	rc = scst_rx_mgmt_fn_lun(sess, SCST_UNREG_SESS_TM,
				 NULL, 0, SCST_ATOMIC, NULL);
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
EXPORT_SYMBOL_GPL(scst_unregister_session);

/**
 * scst_unregister_session_non_gpl() - unregister session, non-GPL version
 * @sess:	session to be unregistered
 *
 * Unregisters session.
 *
 * See notes for scst_unregister_session() above.
 */
void scst_unregister_session_non_gpl(struct scst_session *sess)
{
	TRACE_ENTRY();

	scst_unregister_session(sess, 1, NULL);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_unregister_session_non_gpl);

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

	PRINT_INFO("Management thread started");

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock_irq(&scst_mgmt_lock);
	while (!kthread_should_stop()) {
		wait_event_locked(scst_mgmt_waitQ, test_mgmt_list(), lock_irq,
				  scst_mgmt_lock);

		while (!list_empty(&scst_sess_init_list)) {
			sess = list_first_entry(&scst_sess_init_list,
				typeof(*sess), sess_init_list_entry);
			TRACE_DBG("Removing sess %p from scst_sess_init_list",
				sess);
			list_del(&sess->sess_init_list_entry);
			spin_unlock_irq(&scst_mgmt_lock);

			if (sess->init_phase == SCST_SESS_IPH_INITING) {
				/*
				 * Note: it's not necessary to free the session
				 * here if initialization fails. See also the
				 * comment block above scst_register_session().
				 */
				scst_init_session(sess);
			} else {
				PRINT_CRIT_ERROR("session %p is in "
					"scst_sess_init_list, but in unknown "
					"init phase %x", sess,
					sess->init_phase);
				sBUG();
			}

			spin_lock_irq(&scst_mgmt_lock);
		}

		while (!list_empty(&scst_sess_shut_list)) {
			sess = list_first_entry(&scst_sess_shut_list,
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

	PRINT_INFO("Management thread finished");

	TRACE_EXIT();
	return 0;
}

/* Called under sess->sess_list_lock */
static struct scst_cmd *__scst_find_cmd_by_tag(struct scst_session *sess,
	uint64_t tag, bool to_abort)
{
	struct scst_cmd *cmd, *res = NULL;

	TRACE_ENTRY();

	/* ToDo: hash list */

	TRACE_DBG("%s (sess=%p, tag=%llu)", "Searching in sess cmd list",
		  sess, (unsigned long long int)tag);

	list_for_each_entry(cmd, &sess->sess_cmd_list,
			sess_cmd_list_entry) {
		if ((cmd->tag == tag) && likely(!cmd->internal)) {
			/*
			 * We must not count done commands, because
			 * they were submitted for transmission.
			 * Otherwise we can have a race, when for
			 * some reason cmd's release delayed
			 * after transmission and initiator sends
			 * cmd with the same tag => it can be possible
			 * that a wrong cmd will be returned.
			 */
			if (cmd->done) {
				if (to_abort) {
					/*
					 * We should return the latest not
					 * aborted cmd with this tag.
					 */
					if (res == NULL)
						res = cmd;
					else {
						if (test_bit(SCST_CMD_ABORTED,
								&res->cmd_flags)) {
							res = cmd;
						} else if (!test_bit(SCST_CMD_ABORTED,
								&cmd->cmd_flags))
							res = cmd;
					}
				}
				continue;
			} else {
				res = cmd;
				break;
			}
		}
	}

	TRACE_EXIT();
	return res;
}

/**
 * scst_find_cmd() - find command by custom comparison function
 *
 * Finds a command based on user supplied data and comparison
 * callback function, that should return true, if the command is found.
 * Returns the command on success or NULL otherwise.
 */
struct scst_cmd *scst_find_cmd(struct scst_session *sess, void *data,
			       int (*cmp_fn)(struct scst_cmd *cmd,
					     void *data))
{
	struct scst_cmd *cmd = NULL;
	unsigned long flags = 0;

	TRACE_ENTRY();

	if (cmp_fn == NULL)
		goto out;

	spin_lock_irqsave(&sess->sess_list_lock, flags);

	TRACE_DBG("Searching in sess cmd list (sess=%p)", sess);
	list_for_each_entry(cmd, &sess->sess_cmd_list, sess_cmd_list_entry) {
		/*
		 * We must not count done commands, because they were
		 * submitted for transmission. Otherwise we can have a race,
		 * when for some reason cmd's release delayed after
		 * transmission and initiator sends cmd with the same tag =>
		 * it can be possible that a wrong cmd will be returned.
		 */
		if (cmd->done)
			continue;
		if (cmp_fn(cmd, data) && likely(!cmd->internal))
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

/**
 * scst_find_cmd_by_tag() - find command by tag
 *
 * Finds a command based on the supplied tag comparing it with one
 * that previously set by scst_cmd_set_tag(). Returns the found command on
 * success or NULL otherwise.
 */
struct scst_cmd *scst_find_cmd_by_tag(struct scst_session *sess,
	uint64_t tag)
{
	unsigned long flags;
	struct scst_cmd *cmd;

	spin_lock_irqsave(&sess->sess_list_lock, flags);
	cmd = __scst_find_cmd_by_tag(sess, tag, false);
	spin_unlock_irqrestore(&sess->sess_list_lock, flags);
	return cmd;
}
EXPORT_SYMBOL(scst_find_cmd_by_tag);
