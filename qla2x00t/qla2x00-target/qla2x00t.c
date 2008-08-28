/*
 *  qla2x00t.c
 *
 *  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *
 *  QLogic 2x00 SCSI target driver.
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
#include <linux/types.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/list.h>

#include <scst.h>

#include "qla2x00t.h"

#if !defined(CONFIG_SCSI_QLA2XXX_TARGET)
#error "CONFIG_SCSI_QLA2XXX_TARGET is NOT DEFINED"
#endif

#ifdef CONFIG_SCST_DEBUG
#define Q2T_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_MINOR | \
	TRACE_MGMT_DEBUG | TRACE_MINOR | TRACE_SPECIAL)
#else
# ifdef CONFIG_SCST_TRACING
#define Q2T_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MINOR | \
	TRACE_SPECIAL)
# endif
#endif

static int q2t_target_detect(struct scst_tgt_template *templ);
static int q2t_target_release(struct scst_tgt *scst_tgt);
static int q2t_xmit_response(struct scst_cmd *scst_cmd);
static int q2t_rdy_to_xfer(struct scst_cmd *scst_cmd);
static void q2t_on_free_cmd(struct scst_cmd *scst_cmd);
static void q2t_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd);

/* Predefs for callbacks handed to qla2xxx(target) */
static void q2t_response_pkt(scsi_qla_host_t *ha, sts_entry_t *pkt);
static void q2t_async_event(uint16_t code, scsi_qla_host_t *ha,
	uint16_t *mailbox);
static void q2t_ctio_completion(scsi_qla_host_t *ha, uint32_t handle);
static void q2t_host_action(scsi_qla_host_t *ha,
	qla2x_tgt_host_action_t action);
static void q2t_send_term_exchange(scsi_qla_host_t *ha, struct q2t_cmd *cmd,
	atio_entry_t *atio, int ha_locked);

/*
 * Global Variables
 */

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag q2t_trace_flag
unsigned long q2t_trace_flag = Q2T_DEFAULT_LOG_FLAGS;
#endif

struct scst_tgt_template tgt_template = {
	name: "qla2x00tgt",
	sg_tablesize: 0,
	use_clustering: 1,
#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	xmit_response_atomic: 0,
	rdy_to_xfer_atomic: 0,
#else
	xmit_response_atomic: 1,
	rdy_to_xfer_atomic: 1,
#endif
	detect: q2t_target_detect,
	release: q2t_target_release,
	xmit_response: q2t_xmit_response,
	rdy_to_xfer: q2t_rdy_to_xfer,
	on_free_cmd: q2t_on_free_cmd,
	task_mgmt_fn_done: q2t_task_mgmt_fn_done,
};

struct kmem_cache *q2t_cmd_cachep = NULL;
static struct qla2x_tgt_target tgt_data;

/*
 * Functions
 */

static inline int test_tgt_sess_count(struct q2t_tgt *tgt, scsi_qla_host_t *ha)
{
	unsigned long flags;
	int res;

	/*
	 * We need to protect against race, when tgt is freed before or
	 * inside wake_up()
	 */
	spin_lock_irqsave(&tgt->ha->hardware_lock, flags);
	TRACE_DBG("tgt %p, empty(sess_list)=%d sess_count=%d",
	      tgt, list_empty(&tgt->sess_list), tgt->sess_count);
	res = (tgt->sess_count == 0);
	spin_unlock_irqrestore(&tgt->ha->hardware_lock, flags);

	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static inline void q2t_exec_queue(scsi_qla_host_t *ha)
{
	tgt_data.isp_cmd(ha);
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_modify_command_count(scsi_qla_host_t *ha, int cmd_count,
	int imm_count)
{
	modify_lun_entry_t *pkt;

	TRACE_ENTRY();

	TRACE_DBG("Sending MODIFY_LUN ha %p, cmd %d, imm %d",
		  ha, cmd_count, imm_count);

	pkt = (modify_lun_entry_t *)tgt_data.req_pkt(ha);
	ha->tgt->modify_lun_expected++;

	pkt->entry_type = MODIFY_LUN_TYPE;
	pkt->entry_count = 1;
	if (cmd_count < 0) {
		pkt->operators = MODIFY_LUN_CMD_SUB;	/* Subtract from command count */
		pkt->command_count = -cmd_count;
	} else if (cmd_count > 0){
		pkt->operators = MODIFY_LUN_CMD_ADD;	/* Add to command count */
		pkt->command_count = cmd_count;
	}

	if (imm_count < 0) {
		pkt->operators |= MODIFY_LUN_IMM_SUB;
		pkt->immed_notify_count = -imm_count;
	} else if (imm_count > 0) {
		pkt->operators |= MODIFY_LUN_IMM_ADD;
		pkt->immed_notify_count = imm_count;
	}

	pkt->timeout = 0;	/* Use default */
	q2t_exec_queue(ha);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void __q2t_send_notify_ack(scsi_qla_host_t *ha,
	 uint16_t target_id, uint16_t status, uint16_t task_flags,
	 uint16_t seq_id, uint32_t add_flags, uint16_t resp_code,
	 int resp_code_valid, uint16_t ox_id)
{
	nack_entry_t *ntfy;

	TRACE_ENTRY();

	/* Send marker if required */
	if (tgt_data.issue_marker(ha) != QLA_SUCCESS) {
		PRINT_ERROR("qla2x00tgt(%ld): __QLA2X00_MARKER() "
			    "failed", ha->instance);
		goto out;
	}

	ntfy = (nack_entry_t *)tgt_data.req_pkt(ha);

	if (ha->tgt != NULL)
		ha->tgt->notify_ack_expected++;

	memset(ntfy, 0, sizeof(*ntfy));
	ntfy->entry_type = NOTIFY_ACK_TYPE;
	ntfy->entry_count = 1;
	SET_TARGET_ID(ha, ntfy->target, target_id);
	ntfy->status = status;
	ntfy->task_flags = task_flags;
	ntfy->seq_id = seq_id;
	/* Do not increment here, the chip isn't decrementing */
	/* ntfy->flags = __constant_cpu_to_le16(NOTIFY_ACK_RES_COUNT); */
	ntfy->flags |= cpu_to_le16(add_flags);
	ntfy->ox_id = ox_id;

	if (resp_code_valid) {
		ntfy->resp_code = cpu_to_le16(resp_code);
		ntfy->flags |=
			__constant_cpu_to_le16(NOTIFY_ACK_TM_RESP_CODE_VALID);
	}

	TRACE(TRACE_SCSI, "Sending Notify Ack Seq %#x -> I %#x St %#x RC %#x",
	      le16_to_cpu(seq_id), target_id, le16_to_cpu(status),
	      le16_to_cpu(ntfy->resp_code));

	q2t_exec_queue(ha);

out:
	TRACE_EXIT();
	return;
}
/* ha->hardware_lock supposed to be held on entry */
static inline void q2t_send_notify_ack(scsi_qla_host_t *ha,
	notify_entry_t *iocb, uint32_t add_flags, uint16_t resp_code,
	int resp_code_valid)
{
	__q2t_send_notify_ack(ha,  GET_TARGET_ID(ha, iocb), iocb->status,
	      iocb->task_flags, iocb->seq_id, add_flags, resp_code,
	      resp_code_valid, iocb->ox_id);
}

/*
 * register with initiator driver (but target mode isn't enabled till
 * it's turned on via sysfs)
 */
static int q2t_target_detect(struct scst_tgt_template *templ)
{
	int res;
	struct qla2x_tgt_initiator itd = {
		magic:QLA2X_TARGET_MAGIC,
		tgt_response_pkt:q2t_response_pkt,
		tgt_ctio_completion:q2t_ctio_completion,
		tgt_async_event:q2t_async_event,
		tgt_host_action:q2t_host_action,
	};

	TRACE_ENTRY();

	res = qla2xxx_tgt_register_driver(&itd, &tgt_data);
	if (res != 0) {
		PRINT_ERROR("Unable to register driver: %d", res);
		goto out;
	}

        if (tgt_data.magic != QLA2X_INITIATOR_MAGIC) {
                PRINT_ERROR("Wrong version of the initiator driver: %d",
			    tgt_data.magic);
                res = -EINVAL;
        }

out:
	TRACE_EXIT();
	return res;
}

/* no lock held */
static void q2t_free_session_done(struct scst_session *scst_sess)
{
	struct q2t_sess *sess;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *ha;
	unsigned long flags;

	TRACE_ENTRY();

	sBUG_ON(scst_sess == NULL);
	sess = (struct q2t_sess *)scst_sess_get_tgt_priv(scst_sess);
	sBUG_ON(sess == NULL);
	tgt = sess->tgt;

	kfree(sess);

	if (tgt == NULL)
		goto out;

	TRACE_MGMT_DBG("tgt %p, empty(sess_list) %d, sess_count %d",
	      tgt, list_empty(&tgt->sess_list), tgt->sess_count);

	ha = tgt->ha;

	/*
	 * We need to protect against race, when tgt is freed before or
	 * inside wake_up()
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	tgt->sess_count--;
	if (tgt->sess_count == 0)
		wake_up_all(&tgt->waitQ);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_unreg_sess(struct q2t_sess *sess)
{
	TRACE_ENTRY();

	if (sess == NULL)
		goto out;

	list_del(&sess->list);

	PRINT_INFO("qla2x00tgt(%ld): session for loop_id %d deleted",
		sess->tgt->ha->instance, sess->loop_id);

	/*
	 * Any commands for this session will be finished regularly,
	 * because we must not drop SCSI commands on transport level,
	 * at least without any response to the initiator.
	 */

	scst_unregister_session(sess->scst_sess, 0, q2t_free_session_done);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_port_logout(scsi_qla_host_t *ha, int loop_id)
{
	struct q2t_sess *sess = q2t_find_sess_by_lid(ha->tgt, loop_id);

	TRACE_MGMT_DBG("scsi(%ld) Unregistering session %p loop_id=%d",
	      ha->host_no, sess, loop_id);

	q2t_unreg_sess(sess);
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_clear_tgt_db(struct q2t_tgt *tgt)
{
	struct q2t_sess *sess, *sess_tmp;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Clearing targets DB %p", tgt);

	list_for_each_entry_safe(sess, sess_tmp, &tgt->sess_list, list) {
		q2t_unreg_sess(sess);
	}

	/* At this point tgt could be already dead */

	TRACE_MGMT_DBG("Finished clearing Target DB %p", tgt);

	TRACE_EXIT();
	return;
}

/* should be called w/out hardware_lock, but tgt should be
 * unfindable at this point */
static int q2t_target_release(struct scst_tgt *scst_tgt)
{
	int res = 0;
	struct q2t_tgt *tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *ha = tgt->ha;
	unsigned long flags = 0;

	TRACE_ENTRY();

	spin_lock_irqsave(&ha->hardware_lock, flags);
	tgt->tgt_shutdown = 1;
	q2t_clear_tgt_db(tgt);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	wait_event(tgt->waitQ, test_tgt_sess_count(tgt, ha));

	/* big hammer */
	if(!ha->flags.host_shutting_down)
		tgt_data.disable_lun(ha);

	/* wait for sessions to clear out (just in case) */
	wait_event(tgt->waitQ, test_tgt_sess_count(tgt, ha));

	TRACE_MGMT_DBG("Finished waiting for tgt %p: empty(sess_list)=%d "
		"sess_count=%d", tgt, list_empty(&tgt->sess_list),
		tgt->sess_count);

	/* The lock is needed, because we still can get an incoming packet */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	scst_tgt_set_tgt_priv(scst_tgt, NULL);
	ha->tgt = NULL;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	kfree(tgt);

	TRACE_EXIT_RES(res);
	return res;
}

static int q2t_pci_map_calc_cnt(struct q2t_prm *prm)
{
	int res = 0;

	sBUG_ON(prm->sg_cnt == 0);

	/* 32 bit S/G Data Transfer */
	prm->seg_cnt = pci_map_sg(prm->tgt->ha->pdev, prm->sg, prm->sg_cnt,
			       scst_to_tgt_dma_dir(prm->data_direction));
	if (unlikely(prm->seg_cnt == 0))
		goto out_err;
	/*
	 * If greater than four sg entries then we need to allocate
	 * the continuation entries
	 */
	if (prm->seg_cnt > prm->tgt->datasegs_per_cmd) {
		prm->req_cnt += (uint16_t)(prm->seg_cnt -
				prm->tgt->datasegs_per_cmd) /
				prm->tgt->datasegs_per_cont;
		if (((uint16_t)(prm->seg_cnt - prm->tgt->datasegs_per_cmd)) %
		                        prm->tgt->datasegs_per_cont)
		{
			prm->req_cnt++;
		}
	}

out:
	TRACE_DBG("seg_cnt=%d, req_cnt=%d, res=%d", prm->seg_cnt,
		prm->req_cnt, res);
	return res;

out_err:
	PRINT_ERROR("qla2x00tgt(%ld): PCI mapping failed: sg_cnt=%d",
		prm->tgt->ha->instance, prm->sg_cnt);
	res = -1;
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static inline uint32_t q2t_make_handle(scsi_qla_host_t *ha)
{
	uint32_t h;

	h = ha->current_cmd;
	/* always increment cmd handle */
	do {
		++h;
		if (h > MAX_OUTSTANDING_COMMANDS) {
			h = 0;
		}
		if (h == ha->current_cmd) {
			TRACE(TRACE_OUT_OF_MEM, "Ran out of empty cmd slots "
				"in ha %p", ha);
			h = Q2T_NULL_HANDLE;
			break;
		}
	} while ((h == Q2T_NULL_HANDLE) ||
		 (h == Q2T_BUSY_HANDLE) ||
		 (h == Q2T_SKIP_HANDLE) ||
		 (ha->cmds[h] != NULL));

	if (h != Q2T_NULL_HANDLE)
		ha->current_cmd = h;

	return h;
}

/* ha->hardware_lock supposed to be held on entry */
/*
 * NOTE: About CTIO_COMPLETION_HANDLE
 *  This is checked for in qla2x00_process_response_queue() to see
 *  if a handle coming back in a multi-complete should come to the tgt driver
 *  or be handled there by qla2xxx
 */
static void q2t_build_ctio_pkt(struct q2t_prm *prm)
{
	uint16_t timeout;
	uint32_t h;

	prm->pkt = (ctio_common_entry_t *)tgt_data.req_pkt(prm->tgt->ha);

	if (prm->tgt->tgt_enable_64bit_addr)
		prm->pkt->entry_type = CTIO_A64_TYPE;
	else
		prm->pkt->entry_type = CONTINUE_TGT_IO_TYPE;

	prm->pkt->entry_count = (uint8_t) prm->req_cnt;

	h = q2t_make_handle(prm->tgt->ha);
	if (h != Q2T_NULL_HANDLE) {
		prm->tgt->ha->cmds[h] = prm->cmd;
	}
	prm->pkt->handle = h | CTIO_COMPLETION_HANDLE_MARK;

	timeout = Q2T_TIMEOUT;
	prm->pkt->timeout = cpu_to_le16(timeout);

	/* Set initiator ID */
	h = GET_TARGET_ID(prm->tgt->ha, &prm->cmd->atio);
	SET_TARGET_ID(prm->tgt->ha, prm->pkt->target, h);

	prm->pkt->exchange_id = prm->cmd->atio.exchange_id;

	TRACE(TRACE_DEBUG|TRACE_SCSI,
	      "handle(scst_cmd) -> %08x, timeout %d L %#x -> I %#x E %#x",
	      prm->pkt->handle, timeout, le16_to_cpu(prm->cmd->atio.lun),
	      GET_TARGET_ID(prm->tgt->ha, prm->pkt),
	      le16_to_cpu(prm->pkt->exchange_id));

}

static void q2t_load_data_segments(struct q2t_prm *prm)
{
	uint32_t cnt;
	uint32_t *dword_ptr;
	int enable_64bit_addressing = prm->tgt->tgt_enable_64bit_addr;

	TRACE_DBG("iocb->scsi_status=%x, iocb->flags=%x",
	      le16_to_cpu(prm->pkt->scsi_status), le16_to_cpu(prm->pkt->flags));

	prm->pkt->transfer_length = cpu_to_le32(prm->bufflen);

	/* Setup packet address segment pointer */
	dword_ptr = prm->pkt->dseg_0_address;

	if (prm->seg_cnt == 0) {
		/* No data transfer */
		*dword_ptr++ = 0;
		*dword_ptr = 0;

		TRACE_BUFFER("No data, CTIO packet data",
			     prm->pkt, REQUEST_ENTRY_SIZE);
		goto out;
	}

	/* Set total data segment count */
	prm->pkt->dseg_count = cpu_to_le16(prm->seg_cnt);

	/* If scatter gather */
	TRACE_SG("%s", "Building S/G data segments...");
	/* Load command entry data segments */
	for (cnt = 0;
	     (cnt < prm->tgt->datasegs_per_cmd) && prm->seg_cnt;
	     cnt++, prm->seg_cnt--)
	{
		*dword_ptr++ =
		    cpu_to_le32(pci_dma_lo32(sg_dma_address(prm->sg)));
		if (enable_64bit_addressing) {
			*dword_ptr++ =
			    cpu_to_le32(pci_dma_hi32
					(sg_dma_address(prm->sg)));
		}
		*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

		TRACE_SG("S/G Segment phys_addr=%llx:%llx, len=%d",
		      (long long unsigned int)pci_dma_hi32(sg_dma_address(prm->sg)),
		      (long long unsigned int)pci_dma_lo32(sg_dma_address(prm->sg)),
		      (int)sg_dma_len(prm->sg));

		prm->sg++;
	}

	TRACE_BUFFER("Scatter/gather, CTIO packet data",
		     prm->pkt, REQUEST_ENTRY_SIZE);

	/* Build continuation packets */
	while (prm->seg_cnt > 0) {
		cont_a64_entry_t *cont_pkt64 =
			(cont_a64_entry_t *)tgt_data.req_cont_pkt(prm->tgt->ha);

		/*
		 * Make sure that from cont_pkt64 none of
		 * 64-bit specific fields used for 32-bit
		 * addressing. Cast to (cont_entry_t*) for
		 * that.
		 */

		memset(cont_pkt64, 0, sizeof(*cont_pkt64));

		cont_pkt64->entry_count = 1;
		cont_pkt64->sys_define = 0;

		if (enable_64bit_addressing) {
			cont_pkt64->entry_type = CONTINUE_A64_TYPE;
			dword_ptr =
			    (uint32_t*)&cont_pkt64->dseg_0_address;
		} else {
			cont_pkt64->entry_type = CONTINUE_TYPE;
			dword_ptr =
			    (uint32_t*)&((cont_entry_t *)
					    cont_pkt64)->dseg_0_address;
		}

		/* Load continuation entry data segments */
		for (cnt = 0;
		     cnt < prm->tgt->datasegs_per_cont && prm->seg_cnt;
		     cnt++, prm->seg_cnt--)
		{
			*dword_ptr++ =
			    cpu_to_le32(pci_dma_lo32
					(sg_dma_address(prm->sg)));
			if (enable_64bit_addressing) {
				*dword_ptr++ =
				    cpu_to_le32(pci_dma_hi32
						(sg_dma_address
						 (prm->sg)));
			}
			*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

			TRACE_SG("S/G Segment Cont. phys_addr=%llx:%llx, len=%d",
			      (long long unsigned int)pci_dma_hi32(sg_dma_address(prm->sg)),
			      (long long unsigned int)pci_dma_lo32(sg_dma_address(prm->sg)),
			      (int)sg_dma_len(prm->sg));

			prm->sg++;
		}

		TRACE_BUFFER("Continuation packet data",
			     cont_pkt64, REQUEST_ENTRY_SIZE);
	}

out:
	return;
}

static void q2t_init_ctio_ret_entry(ctio_ret_entry_t *ctio_m1,
	struct q2t_prm *prm)
{
	TRACE_ENTRY();

	prm->sense_buffer_len = min((uint32_t)prm->sense_buffer_len,
				    (uint32_t)sizeof(ctio_m1->sense_data));

	ctio_m1->flags = __constant_cpu_to_le16(OF_SSTS | OF_FAST_POST |
						OF_NO_DATA | OF_SS_MODE_1);
	ctio_m1->flags |= __constant_cpu_to_le16(OF_INC_RC);
	ctio_m1->scsi_status = cpu_to_le16(prm->rq_result);
	ctio_m1->residual = cpu_to_le32(prm->residual);
	if (SCST_SENSE_VALID(prm->sense_buffer)) {
		ctio_m1->scsi_status |=
				__constant_cpu_to_le16(SS_SENSE_LEN_VALID);
		ctio_m1->sense_length = cpu_to_le16(prm->sense_buffer_len);
		memcpy(ctio_m1->sense_data, prm->sense_buffer,
		       prm->sense_buffer_len);
	} else {
		memset(ctio_m1->sense_data, 0, sizeof(ctio_m1->sense_data));
		ctio_m1->sense_length = 0;
	}

	TRACE_BUFFER("CTIO returned packet data", ctio_m1, REQUEST_ENTRY_SIZE);

	/* Sense with len > 26, is it possible ??? */

	TRACE_EXIT();
	return;
}

static inline int q2t_has_data(struct scst_cmd *scst_cmd)
{
	return scst_cmd_get_resp_data_len(scst_cmd) > 0;
}

static int q2t_xmit_response(struct scst_cmd *scst_cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	struct q2t_sess *sess;
	int is_send_status;
	unsigned long flags = 0;
	struct q2t_prm prm;
	int data_sense_flag = 0;
	uint16_t full_req_cnt;

	TRACE_ENTRY();
	TRACE(TRACE_SCSI, "tag=%Ld", scst_cmd_get_tag(scst_cmd));

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	if (scst_cmd_atomic(scst_cmd))
		return SCST_TGT_RES_NEED_THREAD_CTX;
#endif

	memset(&prm, 0, sizeof(prm));

	prm.cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	sess = (struct q2t_sess *)
		scst_sess_get_tgt_priv(scst_cmd_get_session(scst_cmd));

	if (unlikely(scst_cmd_aborted(scst_cmd))) {
		scsi_qla_host_t *ha = sess->tgt->ha;

		TRACE(TRACE_MGMT_MINOR, "qla2x00tgt(%ld): terminating exchange "
			"for aborted scst_cmd=%p (tag=%Ld)",
			ha->instance, scst_cmd, scst_cmd_get_tag(scst_cmd));

		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);

		prm.cmd->state = Q2T_STATE_ABORTED;

		q2t_send_term_exchange(ha, prm.cmd, &prm.cmd->atio, 0);
		/* !! At this point cmd could be already freed !! */
		goto out;
	}

	prm.sg = scst_cmd_get_sg(scst_cmd);
	prm.bufflen = scst_cmd_get_resp_data_len(scst_cmd);
	prm.sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	prm.data_direction = scst_cmd_get_data_direction(scst_cmd);
	prm.rq_result = scst_cmd_get_status(scst_cmd);
	prm.sense_buffer = scst_cmd_get_sense_buffer(scst_cmd);
	prm.sense_buffer_len = scst_cmd_get_sense_buffer_len(scst_cmd);
	prm.tgt = sess->tgt;
	prm.seg_cnt = 0;
	prm.req_cnt = 1;
	is_send_status = scst_cmd_get_is_send_status(scst_cmd);

	TRACE_DBG("rq_result=%x, is_send_status=%x", prm.rq_result,
		is_send_status);

	if (prm.rq_result != 0)
		TRACE_BUFFER("Sense", prm.sense_buffer, prm.sense_buffer_len);

	if (!is_send_status) {
		/* ToDo, after it's done in SCST */
		PRINT_ERROR("qla2x00tgt(%ld): is_send_status not set: "
		     "feature not implemented", prm.tgt->ha->instance);
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&prm.tgt->ha->hardware_lock, flags);

	/* Send marker if required */
	if (tgt_data.issue_marker(prm.tgt->ha) != QLA_SUCCESS) {
		PRINT_ERROR("qla2x00tgt(%ld): __QLA2X00_MARKER() "
			    "failed", prm.tgt->ha->instance);
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out_unlock;
	}

	TRACE_DBG("CTIO start: ha(%d)", (int) prm.tgt->ha->instance);

	if (q2t_has_data(scst_cmd)) {
		if (q2t_pci_map_calc_cnt(&prm) != 0) {
			res = SCST_TGT_RES_QUEUE_FULL;
			goto out_unlock;
		}
		full_req_cnt = prm.req_cnt;
		if (SCST_SENSE_VALID(prm.sense_buffer)) {
			data_sense_flag = 1;
			full_req_cnt++;
		}
	} else
		full_req_cnt = prm.req_cnt;

	q2t_build_ctio_pkt(&prm);

	if (prm.data_direction != SCST_DATA_WRITE) {
		prm.residual =
		    le32_to_cpu(prm.cmd->atio.data_length) - prm.bufflen;
		if (prm.residual > 0) {
			TRACE_DBG("Residual underflow: %d", prm.residual);
			prm.rq_result |= SS_RESIDUAL_UNDER;
		} else if (prm.residual < 0) {
			TRACE_DBG("Residual overflow: %d", prm.residual);
			prm.rq_result |= SS_RESIDUAL_OVER;
			prm.residual = -prm.residual;
		}

		if (q2t_has_data(scst_cmd)) {
			prm.pkt->flags |= __constant_cpu_to_le16(
				OF_FAST_POST | OF_INC_RC | OF_DATA_IN);

			q2t_load_data_segments(&prm);

			if (data_sense_flag == 0) {
				prm.pkt->scsi_status = cpu_to_le16(
					prm.rq_result);
				prm.pkt->residual = cpu_to_le32(prm.residual);
				prm.pkt->flags |=
					__constant_cpu_to_le16(OF_SSTS);
			} else {
				ctio_ret_entry_t *ctio_m1 =
					(ctio_ret_entry_t *)
					tgt_data.req_cont_pkt(prm.tgt->ha);

				TRACE_DBG("%s", "Building additional status "
					"packet");

				memcpy(ctio_m1, prm.pkt, sizeof(*ctio_m1));
				ctio_m1->entry_count = 1;

				/* Real finish is ctio_m1's finish */
				prm.pkt->handle = Q2T_SKIP_HANDLE |
						CTIO_COMPLETION_HANDLE_MARK;

				prm.pkt->flags &= ~__constant_cpu_to_le16(OF_INC_RC);

				q2t_init_ctio_ret_entry(ctio_m1, &prm);
				TRACE_BUFFER("Status CTIO packet data", ctio_m1,
					REQUEST_ENTRY_SIZE);
			}
		} else
			q2t_init_ctio_ret_entry((ctio_ret_entry_t *)prm.pkt, &prm);
	} else {
		q2t_init_ctio_ret_entry((ctio_ret_entry_t *)prm.pkt, &prm);
	}

	prm.cmd->state = Q2T_STATE_PROCESSED;	/* Mid-level is done processing */

	TRACE_BUFFER("Xmitting", prm.pkt, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(prm.tgt->ha);

out_unlock:
	/* Release ring specific lock */
	spin_unlock_irqrestore(&prm.tgt->ha->hardware_lock, flags);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int q2t_rdy_to_xfer(struct scst_cmd *scst_cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	struct q2t_sess *sess;
	unsigned long flags = 0;
	struct q2t_prm prm;

	TRACE_ENTRY();
	TRACE(TRACE_SCSI, "tag=%Ld", scst_cmd_get_tag(scst_cmd));

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	if (scst_cmd_atomic(scst_cmd))
		return SCST_TGT_RES_NEED_THREAD_CTX;
#endif

	memset(&prm, 0, sizeof(prm));

	prm.cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	sess = (struct q2t_sess *)
		scst_sess_get_tgt_priv(scst_cmd_get_session(scst_cmd));

	prm.sg = scst_cmd_get_sg(scst_cmd);
	prm.bufflen = scst_cmd_get_bufflen(scst_cmd);
	prm.sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	prm.data_direction = scst_cmd_get_data_direction(scst_cmd);
	prm.tgt = sess->tgt;
	prm.req_cnt = 1;

	/* Acquire ring specific lock */
	spin_lock_irqsave(&prm.tgt->ha->hardware_lock, flags);

	/* Send marker if required */
	if (tgt_data.issue_marker(prm.tgt->ha) != QLA_SUCCESS) {
		PRINT_ERROR("qla2x00tgt(%ld): __QLA2X00_MARKER() "
			    "failed", prm.tgt->ha->instance);
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out_unlock;
	}

	TRACE_DBG("CTIO_start: ha(%d)", (int) prm.tgt->ha->instance);

	/* Calculate number of entries and segments required */
	if (q2t_pci_map_calc_cnt(&prm) != 0) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto out_unlock;
	}

	prm.cmd->iocb_cnt = prm.req_cnt;

	q2t_build_ctio_pkt(&prm);

	prm.pkt->flags = __constant_cpu_to_le16(OF_FAST_POST | OF_DATA_OUT);

	q2t_load_data_segments(&prm);

	prm.cmd->state = Q2T_STATE_NEED_DATA;

	TRACE_BUFFER("Xfering", prm.pkt, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(prm.tgt->ha);

out_unlock:
	/* Release ring specific lock */
	spin_unlock_irqrestore(&prm.tgt->ha->hardware_lock, flags);

	TRACE_EXIT_RES(res);
	return res;
}

static void q2t_send_term_exchange(scsi_qla_host_t *ha, struct q2t_cmd *cmd,
	atio_entry_t *atio, int ha_locked)
{
	ctio_ret_entry_t *ctio;
	unsigned long flags = 0;
	int do_tgt_cmd_done = 0;

	TRACE_ENTRY();

	TRACE_DBG("Sending TERM EXCH CTIO (ha=%p)", ha);

	if (!ha_locked)
		spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Send marker if required */
	if (tgt_data.issue_marker(ha) != QLA_SUCCESS) {
		PRINT_ERROR("qla2x00tgt(%ld): __QLA2X00_MARKER() "
			    "failed", ha->instance);
		goto out_unlock;
	}

	ctio = (ctio_ret_entry_t *)tgt_data.req_pkt(ha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00tgt(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out_unlock;
	}

	ctio->entry_type = CTIO_RET_TYPE;
	ctio->entry_count = 1;

	if (cmd != NULL) {
		ctio->handle = q2t_make_handle(ha);
		if (ctio->handle != Q2T_NULL_HANDLE) {
			ha->cmds[ctio->handle] = cmd;
		} else {
			ctio->handle = Q2T_SKIP_HANDLE;
			do_tgt_cmd_done = 1;
		}
	} else
		ctio->handle = Q2T_SKIP_HANDLE;

	ctio->handle |= CTIO_COMPLETION_HANDLE_MARK;

	SET_TARGET_ID(ha, ctio->target, GET_TARGET_ID(ha, atio));
	ctio->exchange_id = atio->exchange_id;

	/* Most likely, it isn't needed */
	ctio->residual = atio->data_length;
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	ctio->flags = __constant_cpu_to_le16(OF_FAST_POST | OF_TERM_EXCH |
			OF_NO_DATA | OF_SS_MODE_1);
	ctio->flags |= __constant_cpu_to_le16(OF_INC_RC);

	TRACE_BUFFER("CTIO TERM EXCH packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out_unlock:
	if (!ha_locked)
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (do_tgt_cmd_done) {
		if (!in_interrupt())
			msleep(250);
		scst_tgt_cmd_done(cmd->scst_cmd);
		/* !! At this point cmd could be already freed !! */
	}

	TRACE_EXIT();
	return;
}

static inline void q2t_free_cmd(struct q2t_cmd *cmd)
{
	kmem_cache_free(q2t_cmd_cachep, cmd);
}

static void q2t_on_free_cmd(struct scst_cmd *scst_cmd)
{
	struct q2t_cmd *cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);

	TRACE_ENTRY();
	TRACE(TRACE_SCSI, "END Command tag %Ld", scst_cmd_get_tag(scst_cmd));

	scst_cmd_set_tgt_priv(scst_cmd, NULL);

	q2t_free_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static inline struct scst_cmd *q2t_get_cmd(scsi_qla_host_t *ha, uint32_t handle)
{
	if (ha->cmds[handle] != NULL) {
		struct scst_cmd *cmd = ha->cmds[handle]->scst_cmd;
		ha->cmds[handle] = NULL;
		return cmd;
	} else
		return NULL;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_do_ctio_completion(scsi_qla_host_t *ha,
				   uint32_t handle,
				   uint16_t status,
				   ctio_common_entry_t *ctio)
{
	struct scst_cmd *scst_cmd;
	struct q2t_cmd *cmd;
	uint16_t loop_id = -1;
	int err = 0;

	TRACE_ENTRY();

	if (ctio != NULL)
		loop_id = GET_TARGET_ID(ha, ctio);

	TRACE(TRACE_DEBUG|TRACE_SCSI, "handle(ctio %p status %#x) <- %08x I %x",
	      ctio, status, handle, loop_id);

	/* Clear out CTIO_COMPLETION_HANDLE_MARK */
	handle &= ~CTIO_COMPLETION_HANDLE_MARK;

	if (status != CTIO_SUCCESS) {
		err = 1;
		switch (status) {
		case CTIO_LIP_RESET:
		case CTIO_TARGET_RESET:
		case CTIO_ABORTED:
		case CTIO_TIMEOUT:
		case CTIO_INVALID_RX_ID:
			/* they are OK */
			TRACE(TRACE_MGMT_MINOR, "qla2x00tgt(%ld): CTIO with "
				"status %#x received (LIP_RESET=e, ABORTED=2, "
				"TARGET_RESET=17, TIMEOUT=b, "
				"INVALID_RX_ID=8)", ha->instance, status);
			break;

		case CTIO_PORT_LOGGED_OUT:
		case CTIO_PORT_UNAVAILABLE:
			PRINT_INFO("qla2x00tgt(%ld): CTIO with PORT LOGGED "
				"OUT (29) or PORT UNAVAILABLE (28) status %x "
				"received", ha->instance, status);
			break;

		default:
			PRINT_ERROR("qla2x00tgt(%ld): CTIO with error status "
				    "0x%x received", ha->instance, status);
			break;
		}
		q2t_modify_command_count(ha, 1, 0);
	}

	if (handle != Q2T_NULL_HANDLE) {
		if (unlikely(handle == Q2T_SKIP_HANDLE)) {
			goto out;
		}
		if (unlikely(handle == Q2T_BUSY_HANDLE)) {
			goto out;
		}
		scst_cmd = q2t_get_cmd(ha, handle);
		if (unlikely(scst_cmd == NULL)) {
			PRINT_INFO("qla2x00tgt(%ld): Suspicious: unable to "
				   "find the command with handle %x",
				   ha->instance, handle);
			goto out;
		}
		if (unlikely(err)) {
			TRACE_MGMT_DBG("Found by handle failed CTIO scst_cmd "
				"%p (op %x)", scst_cmd, scst_cmd->cdb[0]);
		}
	} else if (ctio != NULL) {
		uint32_t tag = le16_to_cpu(ctio->exchange_id);
		struct q2t_sess *sess = q2t_find_sess_by_lid(ha->tgt, loop_id);

		if (sess == NULL) {
			PRINT_INFO("qla2x00tgt(%ld): Suspicious: "
				   "ctio_completion for non-existing session "
				   "(loop_id %d, tag %d)",
				   ha->instance, loop_id, tag);
			goto out;
		}

		scst_cmd = scst_find_cmd_by_tag(sess->scst_sess, tag);
		if (scst_cmd == NULL) {
			PRINT_INFO("qla2x00tgt(%ld): Suspicious: unable to "
			     "find the command with tag %d (loop_id %d)",
			     ha->instance, tag, loop_id);
			goto out;
		}
		if (unlikely(err)) {
			TRACE_MGMT_DBG("Found by ctio failed CTIO scst_cmd %p "
				"(op %x)", scst_cmd, scst_cmd->cdb[0]);
		}

		TRACE_DBG("Found scst_cmd %p", scst_cmd);
	} else
		goto out;

	cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	if (unlikely(err)) {
		TRACE(TRACE_MGMT_MINOR, "Failed CTIO state %d (err %x)",
			cmd->state, status);
	}

	if (cmd->state == Q2T_STATE_PROCESSED) {
		TRACE_DBG("Command %p finished", cmd);
		if (q2t_has_data(scst_cmd)) {
			pci_unmap_sg(ha->pdev, scst_cmd_get_sg(scst_cmd),
				scst_cmd_get_sg_cnt(scst_cmd),
				scst_to_tgt_dma_dir(
					scst_cmd_get_data_direction(scst_cmd)));
		}
		goto out_free;
	} else if (cmd->state == Q2T_STATE_NEED_DATA) {
		int context = SCST_CONTEXT_TASKLET;
		int rx_status = SCST_RX_STATUS_SUCCESS;

		cmd->state = Q2T_STATE_DATA_IN;

		if (status != CTIO_SUCCESS)
			rx_status = SCST_RX_STATUS_ERROR;

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
		context = SCST_CONTEXT_THREAD;
#endif

		TRACE_DBG("Data received, context %x, rx_status %d",
		      context, rx_status);

		pci_unmap_sg(ha->pdev, scst_cmd_get_sg(scst_cmd),
			scst_cmd_get_sg_cnt(scst_cmd),
			scst_to_tgt_dma_dir(
				scst_cmd_get_data_direction(scst_cmd)));

		scst_rx_data(scst_cmd, rx_status, context);
	} else if (cmd->state == Q2T_STATE_ABORTED) {
		TRACE_MGMT_DBG("Aborted command %p finished", cmd);
		goto out_free;
	} else {
		PRINT_ERROR("qla2x00tgt(%ld): A command in state (%d) should "
			"not return a CTIO complete", ha->instance, cmd->state);
		goto out_free;
	}

out:
	TRACE_EXIT();
	return;

out_free:
	if (unlikely(err)) {
		TRACE_MGMT_DBG("%s", "Finishing failed CTIO");
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
	}
	scst_tgt_cmd_done(scst_cmd);
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q2t_ctio_completion(scsi_qla_host_t *ha, uint32_t handle)
{
	TRACE_ENTRY();
	sBUG_ON(ha == NULL);

	if (ha->tgt != NULL) {
		q2t_do_ctio_completion(ha, handle,
				       CTIO_SUCCESS, NULL);
	} else {
		TRACE_DBG("CTIO, but target mode not enabled. ha %p handle %#x",
			  ha, handle);
	}
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_send_busy(scsi_qla_host_t *ha, atio_entry_t *atio)
{
	ctio_ret_entry_t *ctio;

	TRACE_ENTRY();

	ctio = (ctio_ret_entry_t *)tgt_data.req_pkt(ha);
	ctio->entry_type = CTIO_RET_TYPE;
	ctio->entry_count = 1;
	ctio->handle = Q2T_BUSY_HANDLE | CTIO_COMPLETION_HANDLE_MARK;
	ctio->scsi_status = __constant_cpu_to_le16(BUSY << 1);
	ctio->residual = atio->data_length;
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	/* Set IDs */
	SET_TARGET_ID(ha, ctio->target, GET_TARGET_ID(ha, atio));
	ctio->exchange_id = atio->exchange_id;

	ctio->flags = __constant_cpu_to_le16(OF_SSTS | OF_FAST_POST |
					     OF_NO_DATA | OF_SS_MODE_1);
	ctio->flags |= __constant_cpu_to_le16(OF_INC_RC);

	TRACE_BUFFER("CTIO BUSY packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock is supposed to be held on entry */
static int q2t_do_send_cmd_to_scst(scsi_qla_host_t *ha, struct q2t_cmd *cmd)
{
	int res = 0;
	struct q2t_sess *sess = cmd->sess;
	uint16_t lun;
	scst_data_direction dir = SCST_DATA_NONE;
	int context;

	TRACE_ENTRY();

	/* make it be in network byte order */
	lun = swab16(cmd->atio.lun);
	cmd->scst_cmd = scst_rx_cmd(sess->scst_sess, (uint8_t *)&lun,
				    sizeof(lun), cmd->atio.cdb, Q2T_MAX_CDB_LEN,
				    SCST_ATOMIC);

	if (cmd->scst_cmd == NULL) {
		PRINT_ERROR("qla2x00tgt(%ld): scst_rx_cmd() failed for "
		     "host %ld(%p)", ha->instance, ha->host_no, ha);
		res = -EFAULT;
		goto out;
	}

	scst_cmd_set_tag(cmd->scst_cmd, le16_to_cpu(cmd->atio.exchange_id));
	scst_cmd_set_tgt_priv(cmd->scst_cmd, cmd);

	if (cmd->atio.execution_codes & ATIO_EXEC_READ)
		dir = SCST_DATA_READ;
	else if (cmd->atio.execution_codes & ATIO_EXEC_WRITE)
		dir = SCST_DATA_WRITE;
	scst_cmd_set_expected(cmd->scst_cmd, dir,
		le32_to_cpu(cmd->atio.data_length));

	switch (cmd->atio.task_codes) {
	case ATIO_SIMPLE_QUEUE:
		cmd->scst_cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
		break;
	case ATIO_HEAD_OF_QUEUE:
		cmd->scst_cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
		break;
	case ATIO_ORDERED_QUEUE:
		cmd->scst_cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
		break;
	case ATIO_ACA_QUEUE:
		cmd->scst_cmd->queue_type = SCST_CMD_QUEUE_ACA;
		break;
	case ATIO_UNTAGGED:
		cmd->scst_cmd->queue_type = SCST_CMD_QUEUE_UNTAGGED;
		break;
	default:
		PRINT_ERROR("qla2x00tgt(%ld): Unknown task code %x, use "
			"ORDERED instead", ha->instance, cmd->atio.task_codes);
		cmd->scst_cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
		break;
	}

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif

	TRACE_DBG("Context %x", context);
	TRACE(TRACE_SCSI, "START Command (tag %Ld)", scst_cmd_get_tag(cmd->scst_cmd));
	scst_cmd_init_done(cmd->scst_cmd, context);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called in SCST's thread context */
static void q2t_alloc_session_done(struct scst_session *scst_sess,
				   void *data, int result)
{
	TRACE_ENTRY();

	if (result != 0) {
		struct q2t_sess *sess = (struct q2t_sess *)data;
		struct q2t_tgt *tgt = sess->tgt;
		scsi_qla_host_t *ha = tgt->ha;
		unsigned long flags;

		PRINT_INFO("qla2x00tgt(%ld): Session initialization failed",
			   ha->instance);

		spin_lock_irqsave(&ha->hardware_lock, flags);
		q2t_unreg_sess(sess);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}

	TRACE_EXIT();
	return;
}

static char *q2t_find_name(scsi_qla_host_t *ha, int loop_id)
{
	int wwn_found = 0;
	char *wwn_str;
	fc_port_t *fcl;

	wwn_str = kmalloc(2*WWN_SIZE, GFP_ATOMIC);
	if (wwn_str == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of wwn_str failed");
		goto out;
	}

	/* Find the WWN in the port db given the loop_id */
	list_for_each_entry_rcu(fcl, &ha->fcports, list) {
	    if (loop_id == (fcl->loop_id & 0xFF)) {
		sprintf(wwn_str, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			fcl->port_name[0], fcl->port_name[1],
			fcl->port_name[2], fcl->port_name[3],
			fcl->port_name[4], fcl->port_name[5],
			fcl->port_name[6], fcl->port_name[7]);
		TRACE_DBG("found wwn: %s for loop_id: %d", wwn_str, loop_id);
		wwn_found = 1;
		break;
	    }
	}

	if (wwn_found == 0) {
		TRACE_MGMT_DBG("qla2x00tgt(%ld): Unable to find wwn login for "
			"loop id %d", ha->instance, loop_id);
		kfree(wwn_str);
		wwn_str = NULL;
	}

out:
	return wwn_str;
}

static char *q2t_make_name(scsi_qla_host_t *ha, const uint8_t *name)
{
	char *wwn_str;

	wwn_str = kmalloc(3*WWN_SIZE, GFP_ATOMIC);
	if (wwn_str == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of wwn_str failed");
		goto out;
	}
	sprintf(wwn_str, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		name[1], name[0], name[3], name[2], name[5], name[4],
		name[7], name[6]);

out:
	return wwn_str;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_send_cmd_to_scst(scsi_qla_host_t *ha, atio_entry_t *atio)
{
	int res = 0;
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;
	struct q2t_cmd *cmd;
	uint16_t *pn;
	int loop_id;

	TRACE_ENTRY();

	tgt = ha->tgt;
	loop_id = GET_TARGET_ID(ha, atio);

	pn = (uint16_t *)(((char *)atio)+0x2a);
	TRACE_DBG("To SCST instance=%ld l_id=%d tag=%d wwpn=%04x%04x%04x%04x",
		  ha->instance, loop_id, le16_to_cpu(atio->exchange_id),
		  le16_to_cpu(pn[0]),
		  le16_to_cpu(pn[1]),
		  le16_to_cpu(pn[2]),
		  le16_to_cpu(pn[3]));
	/*	  le64_to_cpu(*(uint64_t *)(((char *)atio)+0x2c))); */
	/*le32_to_cpu(*(uint32_t *)atio->initiator_port_name)); */

	if (tgt->tgt_shutdown) {
		TRACE_MGMT_DBG("New command while device %p is shutting "
			"down", tgt);
		res = -EFAULT;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	cmd =  kmem_cache_alloc(q2t_cmd_cachep, GFP_ATOMIC);
#else
	cmd =  kmem_cache_zalloc(q2t_cmd_cachep, GFP_ATOMIC);
#endif
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of cmd failed");
		res = -ENOMEM;
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	memset(cmd, 0, sizeof(*cmd));
#endif

	TRACE_BUFFER("ATIO Coming Up", atio, sizeof(*atio));
	memcpy(&cmd->atio, atio, sizeof(*atio));
	cmd->state = Q2T_STATE_NEW;

	sess = q2t_find_sess_by_lid(tgt, loop_id);
	if (unlikely(sess == NULL)) {
		sess = kzalloc(sizeof(*sess), GFP_ATOMIC);
		if (sess == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
			      "Allocation of sess failed");
			res = -ENOMEM;
			goto out_free_cmd;
		}

		sess->tgt = tgt;
		sess->loop_id = loop_id;
		INIT_LIST_HEAD(&sess->list);

		/* register session (remote initiator) */
		{
			char *name;
			if (IS_QLA2200(ha))
				name = q2t_find_name(ha, loop_id);
			else {
				name = q2t_make_name(ha,
					atio->initiator_port_name);
			}
			if (name == NULL) {
				res = -ESRCH;
				goto out_free_sess;
			}

			sess->scst_sess = scst_register_session(
				tgt->scst_tgt, 1, name, sess,
				q2t_alloc_session_done);
			kfree(name);
		}

		if (sess->scst_sess == NULL) {
			PRINT_ERROR("qla2x00tgt(%ld): scst_register_session() failed "
			     "for host %ld(%p)", ha->instance, ha->host_no, ha);
			res = -EFAULT;
			goto out_free_sess;
		}
		scst_sess_set_tgt_priv(sess->scst_sess, sess);

		/* add session data to host data structure */
		list_add(&sess->list, &tgt->sess_list);
		tgt->sess_count++;
	}

	cmd->sess = sess;
	res = q2t_do_send_cmd_to_scst(ha, cmd);
	if (res != 0)
		goto out_free_cmd;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_sess:
	kfree(sess);
	tgt->sess_count--;
	if (tgt->sess_count == 0)
		wake_up_all(&tgt->waitQ);
	/* go through */

out_free_cmd:
	q2t_free_cmd(cmd);
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_handle_task_mgmt(scsi_qla_host_t *ha, notify_entry_t *iocb)
{
	int res = 0, rc = -1;
	struct q2t_mgmt_cmd *mcmd;
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;
	int loop_id;
	uint16_t lun;

	TRACE_ENTRY();

	tgt = ha->tgt;
	loop_id = GET_TARGET_ID(ha, iocb);

	/* Make it be in network byte order */
	lun = swab16(iocb->lun);

	sess = q2t_find_sess_by_lid(tgt, loop_id);
	if (sess == NULL) {
		TRACE(TRACE_MGMT, "qla2x00tgt(%ld): task mgmt fn 0x%x for "
		      "non-existant session", ha->instance, iocb->task_flags);
		res = -EFAULT;
		goto out;
	}

	mcmd = kzalloc(sizeof(*mcmd), GFP_ATOMIC);
	if (mcmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of mgmt cmd failed");
		res = -ENOMEM;
		goto out;
	}

	mcmd->sess = sess;
	mcmd->notify_entry = *iocb;

	switch (iocb->task_flags) {
	case IMM_NTFY_CLEAR_ACA:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_CLEAR_ACA received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_ACA,
					 (uint8_t *)&lun, sizeof(lun),
					 SCST_ATOMIC, mcmd);
		break;

	case IMM_NTFY_TARGET_RESET:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_TARGET_RESET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_TARGET_RESET,
					 (uint8_t *)&lun, sizeof(lun),
					 SCST_ATOMIC, mcmd);
		break;

	case IMM_NTFY_LUN_RESET:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_LUN_RESET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_LUN_RESET,
					 (uint8_t *)&lun, sizeof(lun),
					 SCST_ATOMIC, mcmd);
		break;

	case IMM_NTFY_CLEAR_TS:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_CLEAR_TS received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_TASK_SET,
					 (uint8_t *)&lun, sizeof(lun),
					 SCST_ATOMIC, mcmd);
		break;

	case IMM_NTFY_ABORT_TS:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_ABORT_TS received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_ABORT_TASK_SET,
					 (uint8_t *)&lun, sizeof(lun),
					 SCST_ATOMIC, mcmd);
		break;

	default:
		PRINT_ERROR("qla2x00tgt(%ld): Unknown task mgmt fn 0x%x",
			    ha->instance, iocb->task_flags);
		break;
	}

	if (rc != 0) {
		PRINT_ERROR("qla2x00tgt(%ld): scst_rx_mgmt_fn_lun() failed: %d",
			    ha->instance, rc);
		res = -EFAULT;
		goto out_free;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(mcmd);
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_abort_task(scsi_qla_host_t *ha, notify_entry_t *iocb)
{
	int res = 0, rc;
	struct q2t_mgmt_cmd *mcmd;
	struct q2t_sess *sess;
	int loop_id;
	uint32_t tag;

	TRACE_ENTRY();

	loop_id = GET_TARGET_ID(ha, iocb);
	tag = le16_to_cpu(iocb->seq_id);

	sess = q2t_find_sess_by_lid(ha->tgt, loop_id);
	if (sess == NULL) {
		TRACE(TRACE_MGMT, "qla2x00tgt(%ld): task abort for unexisting "
			"session", ha->instance);
		res = -EFAULT;
		goto out;
	}

	mcmd = kzalloc(sizeof(*mcmd), GFP_ATOMIC);
	if (mcmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of mgmt cmd failed");
		res = -ENOMEM;
		goto out;
	}

	mcmd->sess = sess;
	mcmd->notify_entry = *iocb;

	rc = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK, tag,
		SCST_ATOMIC, mcmd);
	if (rc != 0) {
		PRINT_ERROR("qla2x00tgt(%ld): scst_rx_mgmt_fn_tag() failed: %d",
			    ha->instance, rc);
		res = -EFAULT;
		goto out_free;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(mcmd);
	goto out;
}

/* SCST Callback */
static void q2t_task_mgmt_fn_done(struct scst_mgmt_cmd *scst_mcmd)
{
	struct q2t_mgmt_cmd *mcmd;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("scst_mcmd (%p) status %#x state %#x", scst_mcmd,
		scst_mcmd->status, scst_mcmd->state);

	mcmd = scst_mgmt_cmd_get_tgt_priv(scst_mcmd);
	if (unlikely(mcmd == NULL)) {
		PRINT_ERROR("scst_mcmd %p tgt_spec is NULL", mcmd);
		goto out;
	}

	spin_lock_irqsave(&mcmd->sess->tgt->ha->hardware_lock, flags);
	q2t_send_notify_ack(mcmd->sess->tgt->ha, &mcmd->notify_entry, 0,
		(scst_mgmt_cmd_get_status(scst_mcmd) == SCST_MGMT_STATUS_SUCCESS)
			 ? 0 : FC_TM_FAILED, 1);
	spin_unlock_irqrestore(&mcmd->sess->tgt->ha->hardware_lock, flags);

	/* scst_mgmt_cmd_set_tgt_priv(scst_mcmd, NULL); */
	scst_mcmd->tgt_priv = NULL;
	kfree(mcmd);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_handle_imm_notify(scsi_qla_host_t *ha, notify_entry_t *iocb)
{
	uint16_t status;
	int loop_id;
	uint32_t add_flags = 0;
	int send_notify_ack = 1;

	TRACE_ENTRY();

	status = le16_to_cpu(iocb->status);
	loop_id = GET_TARGET_ID(ha, iocb);

	if (!ha->flags.enable_target_mode || ha->tgt == NULL) {
		TRACE(TRACE_MGMT_DEBUG|TRACE_SCSI|TRACE_DEBUG,
		      "Acking %04x S %04x I %#x -> L %#x", status,
		      le16_to_cpu(iocb->seq_id), loop_id,
		      le16_to_cpu(iocb->lun));
		goto out;
	}

	TRACE_BUFFER("IMMED Notify Coming Up", iocb, sizeof(*iocb));

	switch (status) {
	case IMM_NTFY_LIP_RESET:
		TRACE(TRACE_MGMT, "LIP reset (I %#x)", loop_id);
		/*
		 * ToDo: doing so we reset all holding RESERVE'ations,
		 * which could be unexpected, so be more carefull here
		 */
		q2t_clear_tgt_db(ha->tgt);
		/* set the Clear LIP reset event flag */
		add_flags |= NOTIFY_ACK_CLEAR_LIP_RESET;
		break;

	case IMM_NTFY_IOCB_OVERFLOW:
		PRINT_ERROR("qla2x00tgt(%ld): Cannot provide requested "
			"capability (IOCB overflow)", ha->instance);
		break;

	case IMM_NTFY_ABORT_TASK:
		TRACE(TRACE_MGMT_MINOR, "Abort Task (S %04x I %#x -> L %#x)",
		      le16_to_cpu(iocb->seq_id), loop_id,
		      le16_to_cpu(iocb->lun));
		if (q2t_abort_task(ha, iocb) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_PORT_LOGOUT:
		TRACE(TRACE_MGMT, "Port logout (S %04x I %#x -> L %#x)",
		      le16_to_cpu(iocb->seq_id), loop_id,
		      le16_to_cpu(iocb->lun));
		/*
		 * ToDo: doing so we reset all holding RESERVE'ations,
		 * which could be unexpected, so be more carefull here
		 */
		q2t_port_logout(ha, loop_id);
		break;

	case IMM_NTFY_PORT_CONFIG:
	case IMM_NTFY_GLBL_TPRLO:
	case IMM_NTFY_GLBL_LOGO:
		/* ToDo: ports DB changes handling ?? */
		TRACE(TRACE_MGMT, "Port config changed, Global TPRLO or "
		      "Global LOGO (%d)", status);
		/*
		 * ToDo: doing so we reset all holding RESERVE'ations,
		 * which could be unexpected, so be more carefull here
		 */
		q2t_clear_tgt_db(ha->tgt);
		break;

	case IMM_NTFY_RESOURCE:
		PRINT_ERROR("qla2x00tgt(%ld): Out of resources, host %ld",
			    ha->instance, ha->host_no);
		break;

	case IMM_NTFY_MSG_RX:
		TRACE(TRACE_MGMT, "Immediate notify task %x", iocb->task_flags);
		if (q2t_handle_task_mgmt(ha, iocb) == 0)
			send_notify_ack = 0;
		break;

	default:
		PRINT_ERROR("qla2x00tgt(%ld): Received unknown immediate "
			"notify status %x", ha->instance, status);
		break;
	}


out:
	if (send_notify_ack)
		q2t_send_notify_ack(ha, iocb, add_flags, 0, 0);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q2t_response_pkt(scsi_qla_host_t *ha, sts_entry_t *pkt)
{
	atio_entry_t *atio;

	TRACE_ENTRY();

	TRACE(TRACE_SCSI, "pkt %p: T %02x C %02x S %02x handle %#x",
	      pkt, pkt->entry_type, pkt->entry_count, pkt->entry_status,
	      pkt->handle);

	if (unlikely(ha->tgt == NULL)) {
		TRACE_DBG("response pkt, but no tgt. ha %p tgt_flag %d",
			ha, ha->flags.enable_target_mode);
		goto out;
	}

	if (pkt->entry_status != 0) {
		PRINT_ERROR("qla2x00tgt(%ld): Received response packet %x "
		     "with error status %x", ha->instance, pkt->entry_type,
		     pkt->entry_status);
		goto out;
	}

	switch (pkt->entry_type) {
	case ACCEPT_TGT_IO_TYPE:
		if (ha->flags.enable_target_mode && ha->tgt != NULL) {
			int rc;
			atio = (atio_entry_t *)pkt;
			TRACE_DBG("ACCEPT_TGT_IO instance %ld status %04x "
				  "lun %04x read/write %d data_length %08x "
				  "target_id %02x exchange_id %04x ",
				  ha->instance, le16_to_cpu(atio->status),
				  le16_to_cpu(atio->lun),
				  atio->execution_codes,
				  le32_to_cpu(atio->data_length),
				  GET_TARGET_ID(ha, atio),
				  le16_to_cpu(atio->exchange_id));
			if (atio->status !=
				__constant_cpu_to_le16(ATIO_CDB_VALID)) {
				PRINT_ERROR("qla2x00tgt(%ld): ATIO with error "
					    "status %x received", ha->instance,
					    le16_to_cpu(atio->status));
				break;
			}
			PRINT_BUFF_FLAG(TRACE_SCSI, "CDB", atio->cdb,
					sizeof(atio->cdb));
			rc = q2t_send_cmd_to_scst(ha, atio);
			if (unlikely(rc != 0)) {
				if (rc == -ESRCH) {
#if 1 /* With TERM EXCHANGE some FC cards refuse to boot */
					q2t_send_busy(ha, atio);
#else
					q2t_send_term_exchange(ha, NULL, atio, 1);
#endif
				} else {
					if (!ha->tgt->tgt_shutdown) {
						PRINT_INFO("qla2x00tgt(%ld): Unable to "
						    "send the command to SCSI target "
						    "mid-level, sending BUSY status",
						    ha->instance);
					}
					q2t_send_busy(ha, atio);
				}
			}
		} else if (!ha->tgt->tgt_shutdown) {
			PRINT_ERROR("qla2x00tgt(%ld): ATIO, but target mode "
				"disabled", ha->instance);
		}
		break;

	case CONTINUE_TGT_IO_TYPE:
		if (ha->flags.enable_target_mode && ha->tgt != NULL) {
			ctio_common_entry_t *entry = (ctio_common_entry_t *)pkt;
			TRACE_DBG("CONTINUE_TGT_IO: instance %ld",
				  ha->instance);
			q2t_do_ctio_completion(ha, entry->handle,
					       le16_to_cpu(entry->status),
					       entry);
		} else if (!ha->tgt->tgt_shutdown) {
			PRINT_ERROR("qla2x00tgt(%ld): CTIO, but target mode "
				"disabled", ha->instance);
		}
		break;

	case CTIO_A64_TYPE:
		if (ha->flags.enable_target_mode && ha->tgt != NULL) {
			ctio_common_entry_t *entry = (ctio_common_entry_t *)pkt;
			TRACE_DBG("CTIO_A64: instance %ld", ha->instance);
			q2t_do_ctio_completion(ha, entry->handle,
					       le16_to_cpu(entry->status),
					       entry);
		} else if (!ha->tgt->tgt_shutdown) {
			PRINT_ERROR("qla2x00tgt(%ld): CTIO_A64, but target "
				"mode disabled", ha->instance);
		}
		break;

	case IMMED_NOTIFY_TYPE:
		TRACE_DBG("%s", "IMMED_NOTIFY");
		q2t_handle_imm_notify(ha, (notify_entry_t *)pkt);
		break;

	case NOTIFY_ACK_TYPE:
		if (ha->tgt == NULL) {
			PRINT_ERROR("qla2x00tgt(%ld): NOTIFY_ACK recieved "
				"with NULL tgt", ha->instance);
		} else if (ha->tgt->notify_ack_expected > 0) {
			nack_entry_t *entry = (nack_entry_t *)pkt;
			TRACE_DBG("NOTIFY_ACK seq %04x status %x",
				  le16_to_cpu(entry->seq_id),
				  le16_to_cpu(entry->status));
			ha->tgt->notify_ack_expected--;
			if (entry->status !=
				__constant_cpu_to_le16(NOTIFY_ACK_SUCCESS)) {
				PRINT_ERROR("qla2x00tgt(%ld): NOTIFY_ACK "
					    "failed %x", ha->instance,
					    le16_to_cpu(entry->status));
			}
		} else {
			PRINT_ERROR("qla2x00tgt(%ld): Unexpected NOTIFY_ACK "
				    "received", ha->instance);
		}
		break;

	case MODIFY_LUN_TYPE:
		if ((ha->tgt != NULL) && (ha->tgt->modify_lun_expected > 0)) {
			struct q2t_tgt *tgt = ha->tgt;
			modify_lun_entry_t *entry = (modify_lun_entry_t *)pkt;
			TRACE_DBG("MODIFY_LUN %x, imm %c%d, cmd %c%d",
				  entry->status,
				  (entry->operators & MODIFY_LUN_IMM_ADD) ?'+'
				  :(entry->operators & MODIFY_LUN_IMM_SUB) ?'-'
				  :' ',
				  entry->immed_notify_count,
				  (entry->operators & MODIFY_LUN_CMD_ADD) ?'+'
				  :(entry->operators & MODIFY_LUN_CMD_SUB) ?'-'
				  :' ',
				  entry->command_count);
			tgt->modify_lun_expected--;
			if (entry->status != MODIFY_LUN_SUCCESS) {
				PRINT_ERROR("qla2x00tgt(%ld): MODIFY_LUN "
					    "failed %x", ha->instance,
					    entry->status);
			}
			tgt->disable_lun_status = entry->status;
		} else {
			PRINT_ERROR("qla2x00tgt(%ld): Unexpected MODIFY_LUN "
				    "received", (ha != NULL) ?ha->instance :-1);
		}
		break;

	case ENABLE_LUN_TYPE:
		if (ha->tgt != NULL) {
			struct q2t_tgt *tgt = ha->tgt;
			elun_entry_t *entry = (elun_entry_t *)pkt;
			TRACE_DBG("ENABLE_LUN %x imm %u cmd %u ",
				  entry->status, entry->immed_notify_count,
				  entry->command_count);
			if ((ha->flags.enable_target_mode) &&
			    (entry->status == ENABLE_LUN_ALREADY_ENABLED)) {
				TRACE_DBG("LUN is already enabled: %#x",
					  entry->status);
				entry->status = ENABLE_LUN_SUCCESS;
			} else if (entry->status == ENABLE_LUN_RC_NONZERO) {
				TRACE_DBG("ENABLE_LUN succeeded, but with "
					"error: %#x", entry->status);
				entry->status = ENABLE_LUN_SUCCESS;
			} else if (entry->status != ENABLE_LUN_SUCCESS) {
				PRINT_ERROR("qla2x00tgt(%ld): ENABLE_LUN "
					    "failed %x",
					    ha->instance, entry->status);
				ha->flags.enable_target_mode =
					~ha->flags.enable_target_mode;
			} /* else success */
			tgt->disable_lun_status = entry->status;
		}
		break;

	default:
		PRINT_INFO("qla2x00tgt(%ld): Received unknown response pkt "
		     "type %x", ha->instance, pkt->entry_type);
		break;
	}

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q2t_async_event(uint16_t code, scsi_qla_host_t *ha, uint16_t *mailbox)
{
	TRACE_ENTRY();

	sBUG_ON(ha == NULL);

	if (unlikely(ha->tgt == NULL)) {
		TRACE(TRACE_DEBUG|TRACE_MGMT,
		      "ASYNC EVENT %#x, but no tgt. ha %p tgt_flag %d",
		      code, ha, ha->flags.enable_target_mode);
		goto out;
	}

	switch (code) {
	case MBA_RESET:			/* Reset */
	case MBA_SYSTEM_ERR:		/* System Error */
	case MBA_REQ_TRANSFER_ERR:	/* Request Transfer Error */
	case MBA_RSP_TRANSFER_ERR:	/* Response Transfer Error */
	case MBA_LOOP_DOWN:
	case MBA_LIP_OCCURRED:		/* Loop Initialization Procedure */
	case MBA_LIP_RESET:		/* LIP reset occurred */
	case MBA_POINT_TO_POINT:	/* Point to point mode. */
	case MBA_CHG_IN_CONNECTION:	/* Change in connection mode. */
		TRACE_MGMT_DBG("Async event %#x occured: clear tgt_db", code);
#if 0
		/*
		 * ToDo: doing so we reset all holding RESERVE'ations,
		 * which could be unexpected, so be more carefull here
		 */
		q2t_clear_tgt_db(ha->tgt);
#endif
		break;
	case MBA_RSCN_UPDATE:
		TRACE_MGMT_DBG("RSCN Update (%x) N_Port %#06x (fmt %x)", code,
			((mailbox[1] & 0xFF) << 16) | le16_to_cpu(mailbox[2]),
			(mailbox[1] & 0xFF00) >> 8);
		break;

	case MBA_PORT_UPDATE:		/* Port database update occurred */
		TRACE_MGMT_DBG("Port DB Chng: L_ID %#4x did %d: ignore",
		      le16_to_cpu(mailbox[1]), le16_to_cpu(mailbox[2]));
		break;

	case MBA_LOOP_UP:
	default:
		TRACE_MGMT_DBG("Async event %#x occured: ignore", code);
		/* just don't DO anything */
		break;
	}

out:
	TRACE_EXIT();
	return;
}

static int q2t_get_target_name(scsi_qla_host_t *ha, char **wwn)
{
	const int wwn_len = 3*WWN_SIZE+2;
	int res = 0;
	char *name;

	name = kmalloc(wwn_len, GFP_KERNEL);
	if (name == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of tgt name failed");
		res = -ENOMEM;
		goto out;
	}

	sprintf(name, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		ha->port_name[0], ha->port_name[1],
		ha->port_name[2], ha->port_name[3],
		ha->port_name[4], ha->port_name[5],
		ha->port_name[6], ha->port_name[7]);

	*wwn = name;

out:
	return res;
}

/* no lock held on entry */
/* called via callback from qla2xxx */
static void q2t_host_action(scsi_qla_host_t *ha,
			    qla2x_tgt_host_action_t action)
{
	struct q2t_tgt *tgt = NULL;
	unsigned long flags = 0;


	TRACE_ENTRY();

	sBUG_ON(ha == NULL);

	switch (action) {
	case ENABLE_TARGET_MODE:
	{
		char *wwn;
		int sg_tablesize;

		tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
		if (tgt == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
			      "Allocation of tgt failed");
			goto out;
		}

		tgt->ha = ha;
		tgt->disable_lun_status = Q2T_DISABLE_LUN_STATUS_NOT_SET;
		INIT_LIST_HEAD(&tgt->sess_list);
		init_waitqueue_head(&tgt->waitQ);

		if (ha->flags.enable_64bit_addressing) {
			PRINT_INFO("qla2x00tgt(%ld): 64 Bit PCI "
				   "Addressing Enabled", ha->instance);
			tgt->tgt_enable_64bit_addr = 1;
			/* 3 is reserved */
			sg_tablesize =
				QLA_MAX_SG64(ha->request_q_length - 3);
			tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND64;
			tgt->datasegs_per_cont = DATASEGS_PER_CONT64;
		} else {
			PRINT_INFO("qla2x00tgt(%ld): Using 32 Bit "
				   "PCI Addressing", ha->instance);
			sg_tablesize =
				QLA_MAX_SG32(ha->request_q_length - 3);
			tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND32;
			tgt->datasegs_per_cont = DATASEGS_PER_CONT32;
		}

		if (q2t_get_target_name(ha, &wwn) != 0) {
			kfree(tgt);
			goto out;
		}

		tgt->scst_tgt = scst_register(&tgt_template, wwn);
		kfree(wwn);
		if (!tgt->scst_tgt) {
			PRINT_ERROR("qla2x00tgt(%ld): scst_register() "
				    "failed for host %ld(%p)", ha->instance,
				    ha->host_no, ha);
			kfree(tgt);
			goto out;
		}

		scst_tgt_set_sg_tablesize(tgt->scst_tgt, sg_tablesize);
		scst_tgt_set_tgt_priv(tgt->scst_tgt, tgt);

		spin_lock_irqsave(&ha->hardware_lock, flags);
		ha->tgt = tgt;
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		TRACE_DBG("Enable lun for host %ld(%ld,%p)",
			  ha->host_no, ha->instance, ha);
		tgt_data.enable_lun(ha);

		break;
	}
	case DISABLE_TARGET_MODE:
		spin_lock_irqsave(&ha->hardware_lock, flags);
		if (ha->tgt == NULL) {
			/* ensure target mode is marked as off */
			ha->flags.enable_target_mode = 0;
			spin_unlock_irqrestore(&ha->hardware_lock, flags);

			if(!ha->flags.host_shutting_down)
				tgt_data.disable_lun(ha);

			goto out;
		}

		tgt = ha->tgt;
		ha->tgt = NULL; /* ensure no one gets in behind us */
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		TRACE_DBG("Shutting down host %ld(%ld,%p)",
			  ha->host_no, ha->instance, ha);
		scst_unregister(tgt->scst_tgt);
		/*
		 * Free of tgt happens via callback q2t_target_release
		 * called from scst_unregister, so we shouldn't touch it again
		 */
		tgt = NULL;
		break;

	default:
		PRINT_ERROR("Unknown action %d", action);
		break;
	}

out:
	TRACE_EXIT();
	return;
}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define Q2T_PROC_LOG_ENTRY_NAME     "trace_level"

#include <linux/proc_fs.h>

static int q2t_log_info_show(struct seq_file *seq, void *v)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_read(seq, trace_flag, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t q2t_proc_log_entry_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, &trace_flag,
		Q2T_DEFAULT_LOG_FLAGS, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data q2t_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(q2t_proc_log_entry_write)
	.show = q2t_log_info_show,
};
#endif

static int q2t_proc_log_entry_build(struct scst_tgt_template *templ)
{
	int res = 0;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
		/* create the proc file entry for the device */
		q2t_log_proc_data.data = (void *)templ->name;
		p = scst_create_proc_entry(root, Q2T_PROC_LOG_ENTRY_NAME,
					&q2t_log_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register "
			     "target driver %s entry %s in /proc",
			      templ->name, Q2T_PROC_LOG_ENTRY_NAME);
			res = -ENOMEM;
			goto out;
		}
	}

out:

	TRACE_EXIT_RES(res);
#endif
	return res;
}

static void q2t_proc_log_entry_clean(struct scst_tgt_template *templ)
{
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
		remove_proc_entry(Q2T_PROC_LOG_ENTRY_NAME, root);
	}

	TRACE_EXIT();
#endif
	return;
}

static int __init q2t_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	PRINT_INFO("Initializing QLogic Fibre Channel HBA Driver target mode "
		"addon version %s", Q2T_VERSION_STRING);

	q2t_cmd_cachep = KMEM_CACHE(q2t_cmd, SCST_SLAB_FLAGS);
	if (q2t_cmd_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = scst_register_target_template(&tgt_template);
	if (res < 0)
		goto out_free_kmem;

	/*
	 * qla2xxx_tgt_register_driver() happens in q2t_target_detect
	 * called via scst_register_target_template()
	 */

	res = q2t_proc_log_entry_build(&tgt_template);
	if (res < 0)
		goto out_unreg_target;

out:
	TRACE_EXIT();
	return res;

out_unreg_target:
	scst_unregister_target_template(&tgt_template);

out_free_kmem:
	kmem_cache_destroy(q2t_cmd_cachep);

	qla2xxx_tgt_unregister_driver();
	goto out;
}

static void __exit q2t_exit(void)
{
	TRACE_ENTRY();

	q2t_proc_log_entry_clean(&tgt_template);

	scst_unregister_target_template(&tgt_template);

	qla2xxx_tgt_unregister_driver();

	kmem_cache_destroy(q2t_cmd_cachep);

	TRACE_EXIT();
	return;
}

module_init(q2t_init);
module_exit(q2t_exit);

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar & Nathaniel Clark");
MODULE_DESCRIPTION("Target mode logic for qla2xxx");
MODULE_LICENSE("GPL");
MODULE_VERSION(Q2T_VERSION_STRING);
