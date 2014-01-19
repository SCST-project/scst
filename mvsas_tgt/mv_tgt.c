/*
 * Marvell 88SE64xx/88SE94xx main function
 *
 * Copyright 2007 Red Hat, Inc.
 * Copyright 2008 Marvell. <kewei@marvell.com>
 *
 * This file is licensed under GPLv2.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
*/

#ifdef SUPPORT_TARGET
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
#include <linux/kthread.h>
#include <asm/byteorder.h>
#include <scst.h>
#include <scst_debug.h>
#include "mv_sas.h"
#include "mv_defs.h"
#include "mv_64xx.h"
#include "mv_chips.h"

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
unsigned long mvst_trace_flag = MVST_DEFAULT_LOG_FLAGS;
#endif

#ifndef SUPPORT_TARGET
#error "SUPPORT_TARGET is NOT DEFINED"
#endif

static int mvst_target_detect(struct scst_tgt_template *templ);
static int mvst_target_release(struct scst_tgt *scst_tgt);
static int mvst_xmit_response(struct scst_cmd *scst_cmd);
static int mvst_rdy_to_xfer(struct scst_cmd *scst_cmd);
static void mvst_on_free_cmd(struct scst_cmd *scst_cmd);
static void mvst_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd);
static int mvst_report_event(struct scst_aen *aen);
/* Predefs for callbacks handed to mvst(target) */
static u8 mvst_response_ssp_command(struct mvs_info *mvi, u32 rx_desc);
static void mvst_cmd_completion(struct mvs_info *mvi, u32 rx_desc);
static void mvst_host_action(struct mvs_info *mvi,
	enum mvst_tgt_host_action_t action, u8 phyid);
static int mvst_start_sas_target(struct mvs_info *mvi, u8 id);
static int mvst_restart_free_list(struct mvs_info *mvi, u8 slot_id);
static uint16_t mvst_get_scsi_transport_version(struct scst_tgt *scst_tgt);

static struct kmem_cache *mvst_cmd_cachep;

static struct scst_tgt_template tgt_template = {
	.name = MVST_NAME,
	.sg_tablesize = 0,
	.use_clustering = 1,
#ifdef DEBUG_WORK_IN_THREAD
	.xmit_response_atomic = 0,
	.rdy_to_xfer_atomic = 0,
#else
	.xmit_response_atomic = 1,
	.rdy_to_xfer_atomic = 1,
#endif
	.detect = mvst_target_detect,
	.release = mvst_target_release,
	.xmit_response = mvst_xmit_response,
	.rdy_to_xfer = mvst_rdy_to_xfer,
	.on_free_cmd = mvst_on_free_cmd,
	.task_mgmt_fn_done = mvst_task_mgmt_fn_done,
	.report_aen = mvst_report_event,
	.get_scsi_transport_version = mvst_get_scsi_transport_version,
};

/*
 * Functions
 */

static uint16_t mvst_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	return 0x0BE0; /* SAS */
}

static u64 mvst_get_be_sas_addr(u8 *sas_addr)
{
	u64 lo = cpu_to_be32((u32)(*(u32 *)&sas_addr[0]));
	u64 hi = cpu_to_be32((u32)(*(u32 *)&sas_addr[4]));
	return  (hi << 32) | lo;
}

static u64 mvst_get_le_sas_addr(u8 *sas_addr)
{
	u64 lo = ((u32)(*(u32 *)&sas_addr[4]));
	u64 hi = ((u32)(*(u32 *)&sas_addr[0]));
	return  (hi << 32) | lo;
}

/* FIXME
 *
 * use_sg can not bigger than MAX_SG_COUNT
 *
 */
static inline void
mvst_prep_prd(struct mvst_prm *prm, struct mvs_prd *buf_prd)
{
	struct mvs_info *mvi = prm->tgt->mvi;

	TRACE_ENTRY();
	TRACE_DBG("bufflen 0x%x, %p", prm->bufflen, prm->sg);
	sBUG_ON(prm->sg_cnt == 0);
	prm->seg_cnt = pci_map_sg(prm->tgt->mvi->pdev, prm->sg, prm->sg_cnt,
				   scst_to_tgt_dma_dir(prm->data_direction));
	MVS_CHIP_DISP->make_prd(prm->sg, prm->sg_cnt, buf_prd);
}


static inline int test_tgt_sess_count(struct mvst_tgt *tgt,
				struct mvs_info *mvi)
{
	unsigned long flags;
	int res;

	/*
	 * We need to protect against race, when tgt is freed before or
	 * inside wake_up()
	 */
	spin_lock_irqsave(&tgt->mvi->lock, flags);
	TRACE_DBG("tgt %p, empty(sess_list)=%d sess_count=%d",
	      tgt, list_empty(&tgt->sess_list), tgt->sess_count);
	res = (tgt->sess_count == 0);
	spin_unlock_irqrestore(&tgt->mvi->lock, flags);

	return res;
}

/* mvi->lock supposed to be held on entry */
static inline void mvst_exec_queue(struct mvs_info *mvi)
{
	void __iomem *regs = mvi->regs;
	mw32(MVS_TX_PROD_IDX, (mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));
}

/*
 * register with initiator driver (but target mode isn't enabled till
 * it's turned on via sysfs)
 */
static int mvst_target_detect(struct scst_tgt_template *templ)
{
	int res;
	struct mvs_tgt_initiator itd = {
		.magic = MVST_TARGET_MAGIC,
		.tgt_rsp_ssp_cmd = mvst_response_ssp_command,
		.tgt_cmd_cmpl = mvst_cmd_completion,
		.tgt_host_action = mvst_host_action,
	};

	TRACE_ENTRY();

	res = mvs_tgt_register_driver(&itd);
	if (res != 0) {
		PRINT_ERROR("Unable to register driver: %d", res);
		goto out;
	}

out:
	TRACE_EXIT();
	return res;
}

/* no lock held */
static void mvst_free_session_done(struct scst_session *scst_sess)
{
	struct mvst_sess *sess;
	struct mvst_tgt *tgt;
	struct mvs_info *mvi;
	unsigned long flags;

	TRACE_ENTRY();

	sBUG_ON(scst_sess == NULL);
	sess = (struct mvst_sess *)scst_sess_get_tgt_priv(scst_sess);
	sBUG_ON(sess == NULL);
	tgt = sess->tgt;
	kfree(sess);
	if (tgt == NULL)
		goto out;

	TRACE_MGMT_DBG("tgt %p, empty(sess_list) %d, sess_count %d",
	      tgt, list_empty(&tgt->sess_list), tgt->sess_count);

	mvi = tgt->mvi;

	/*
	 * We need to protect against race, when tgt is freed before or
	 * inside wake_up()
	 */
	spin_lock_irqsave(&mvi->lock, flags);
	tgt->sess_count--;
	if (tgt->sess_count == 0)
		wake_up_all(&tgt->waitQ);
	spin_unlock_irqrestore(&mvi->lock, flags);

out:
	TRACE_EXIT();
	return;
}

/* mvi->lock supposed to be held on entry */
static void mvst_unreg_sess(struct mvst_sess *sess)
{
	TRACE_ENTRY();

	if (sess == NULL)
		goto out;

	list_del(&sess->sess_entry);

	TRACE_DBG("mvst tgt(%ld): session for initiator %016llx deleted",
		sess->tgt->mvi->instance,
		mvst_get_le_sas_addr((u8 *)&sess->initiator_sas_addr));

	/*
	 * Any commands for this session will be finished regularly,
	 * because we must not drop SCSI commands on transport level,
	 * at least without any response to the initiator.
	 */

	scst_unregister_session(sess->scst_sess, 0, mvst_free_session_done);

out:
	TRACE_EXIT();
	return;
}

/* mvi->lock supposed to be held on entry */
static void mvst_clear_tgt_db(struct mvst_tgt *tgt)
{
	struct mvst_sess *sess, *sess_tmp;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Clearing targets DB %p", tgt);

	list_for_each_entry_safe(sess, sess_tmp, &tgt->sess_list, sess_entry)
		mvst_unreg_sess(sess);

	/* At this point tgt could be already dead */

	TRACE_MGMT_DBG("Finished clearing Target DB %p", tgt);

	TRACE_EXIT();
	return;
}

/* should be called w/out lock, but tgt should be
 * unfindable at this point */
static int mvst_target_release(struct scst_tgt *scst_tgt)
{
	int res = 0;
	struct mvst_tgt *tgt =
		(struct mvst_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	struct mvs_info *mvi = tgt->mvi;
	unsigned long flags = 0;

	TRACE_ENTRY();

	spin_lock_irqsave(&mvi->lock, flags);
	tgt->tgt_shutdown = 1;
	mvst_clear_tgt_db(tgt);
	spin_unlock_irqrestore(&mvi->lock, flags);

	wait_event(tgt->waitQ, test_tgt_sess_count(tgt, mvi));

	/* big hammer */
	if (!(mvi->flags & MVF_HOST_SHUTTING_DOWN))
		mvi->flags |= MVF_TARGET_MODE_ENABLE;

	/* wait for sessions to clear out (just in case) */
	wait_event(tgt->waitQ, test_tgt_sess_count(tgt, mvi));

	TRACE_MGMT_DBG("Finished waiting for tgt %p: empty(sess_list)=%d "
		"sess_count=%d", tgt, list_empty(&tgt->sess_list),
		tgt->sess_count);

	/* The lock is needed, because we still can get an incoming packet */
	spin_lock_irqsave(&mvi->lock, flags);
	scst_tgt_set_tgt_priv(scst_tgt, NULL);
	mvi->tgt = NULL;
	spin_unlock_irqrestore(&mvi->lock, flags);
	kfree(tgt);

	TRACE_EXIT_RES(res);
	return res;
}

static inline int mvst_has_data(struct scst_cmd *scst_cmd)
{
	return scst_cmd_get_resp_data_len(scst_cmd) > 0;
}


static void
mvst_put_slot(struct mvs_info *mvi, struct mvs_slot_info *slot)
{
	u32 slot_idx = slot->target_cmd_tag;
	/* reset field used by target driver */
	slot->target_cmd_tag = 0xdeadbeef;
	slot->tx = 0xdeadbeef;
	slot->slot_scst_cmd = NULL;
	slot->slot_scst_mgmt_cmd = NULL;
	slot->response = NULL;
	slot->open_frame = NULL;
	slot->slot_tgt_port = NULL;
	list_del(&slot->entry);
	mvs_tag_clear(mvi, slot_idx);
}


static struct mvs_slot_info*
mvst_get_slot(struct mvs_info *mvi, struct mvst_port *tgt_port)
{
	u8 rc = 0;
	u32 tag;
	struct mvs_slot_info *slot = NULL;
	rc = mvs_tag_alloc(mvi, &tag);
	if (rc)
		return	NULL;
	slot = &mvi->slot_info[tag];
	memset(slot->buf, 0, MVS_SLOT_BUF_SZ);
	/* used by initiator driver, reserved  for target driver */
	slot->n_elem = 0;
	slot->task = NULL;
	slot->port = NULL;

	/* save free tag */
	slot->target_cmd_tag = tag;
	slot->slot_tgt_port = tgt_port;
	slot->slot_scst_cmd = NULL;
	slot->slot_scst_mgmt_cmd = NULL;
	slot->open_frame = NULL;
	slot->tx = mvi->tx_prod;
	list_add_tail(&slot->entry, &slot->slot_tgt_port->slot_list);
	return	slot;
}

static int mvst_prep_resp_frame(struct mvst_prm *prm,
			struct mvs_slot_info *slot, u8 datapres)
{
	u16 tag;
	void *buf_tmp;
	dma_addr_t buf_tmp_dma;
	u32 resp_len = 0, req_len = 0, prd_len = 0;
	const u32 max_resp_len = SB_RFB_MAX;
	struct mvs_info *mvi = prm->tgt->mvi;
	struct mvst_cmd *cmd = prm->cmd;
	struct mvs_cmd_header *cmd_hdr;
	struct mvs_delivery_queue *delivery_q;
	struct mvs_prd *buf_prd;
	struct open_address_frame *open_frame;
	struct mv_ssp_response_iu *response_iu;

	TRACE_ENTRY();
	tag = slot->target_cmd_tag;
	cmd_hdr = (struct mvs_cmd_header *)&mvi->slot[tag];
	/* get free delivery queue */
	delivery_q = (struct mvs_delivery_queue *)&mvi->tx[mvi->tx_prod];

	/* SSP protocol, Target mode, Normal priority */
	delivery_q->cmd = TXQ_CMD_SSP;
	delivery_q->mode = TXQ_MODE_TARGET;
	delivery_q->priority = TXQ_PRI_NORMAL;
	delivery_q->sata_reg_set = 0;
	delivery_q->phy = cmd->cmd_tgt_port->wide_port_phymap;
	delivery_q->slot_nm = tag;

	cmd_hdr->ssp_frame_type = MCH_SSP_FR_RESP;
	cmd_hdr->ssp_passthru = MCH_SSP_MODE_NORMAL;

	/* command header dword 1 */
	/* configure in below */

	/* command header dword 2 */
	/* copy the tag from received command frame */
	cmd_hdr->target_tag = cpu_to_le16(tag);
	cmd_hdr->tag = be16_to_cpu(prm->cmd->ssp_hdr->tag);

	/*
	 * arrange MVS_SLOT_BUF_SZ-sized DMA buffer according to our needs
	 */
	/* command header dword 4 -5 */
	/* region 1: command table area (MVS_SSP_CMD_SZ bytes) ******* */
	buf_tmp = slot->buf;
	buf_tmp_dma = slot->buf_dma;
	cmd_hdr->cmd_tbl = cpu_to_le64(buf_tmp_dma);

	req_len += sizeof(struct ssp_frame_header);
	req_len += 24;
	if (datapres == SENSE_DATA) {
		if (scst_sense_valid(prm->sense_buffer))
			req_len += prm->sense_buffer_len;
		else
			datapres = 0;
	} else if (datapres == RESPONSE_DATA)
		req_len += 4;
	/* fill in response frame IU */
	response_iu = (struct mv_ssp_response_iu *)(buf_tmp
		+ sizeof(struct ssp_frame_header));
	response_iu->status = prm->rq_result;
	response_iu->datapres = datapres;
	if (datapres == RESPONSE_DATA) {
		response_iu->response_data_len =
			cpu_to_be32(prm->sense_buffer_len);
	} else if (datapres == SENSE_DATA) {
		response_iu->response_data_len =
			cpu_to_be32(prm->sense_buffer_len);
	}
	memcpy(response_iu->data,
		prm->sense_buffer, prm->sense_buffer_len);

	/* command header dword 6 -7 */
	buf_tmp += req_len;
	buf_tmp_dma += req_len;
	/* region 2: open address frame area (MVS_OAF_SZ bytes) ********* */
	slot->open_frame = buf_tmp;
	cmd_hdr->open_frame = cpu_to_le64(buf_tmp_dma);

	/* command header dword 10 -11 */
	buf_tmp += MVS_OAF_SZ;
	buf_tmp_dma += MVS_OAF_SZ;
	/* region 3: PRD table ******************************* */
	buf_prd = buf_tmp;
	cmd_hdr->prd_tbl = 0;

	/* command header dword 8 -9 */
	/* region 4: status buffer (larger the PRD, smaller this buf) ****** */
	slot->response = buf_tmp;
	cmd_hdr->status_buf = cpu_to_le64(buf_tmp_dma);

	/* command header dword 1 */
	resp_len = MVS_SLOT_BUF_SZ - req_len - MVS_OAF_SZ -
	    sizeof(struct mvs_err_info) - prd_len;
	resp_len = min(resp_len, max_resp_len);

	cmd_hdr->max_rsp_frame_len = resp_len / 4;
	cmd_hdr->frame_len =
		req_len / 4 < MVS_MAX_SSP_FRAME ? req_len/4 : MVS_MAX_SSP_FRAME;

	/* generate open address frame hdr (first 12 bytes) */
	open_frame = (struct open_address_frame *)slot->open_frame;
	open_frame->initiator = 0;	/* target mode */
	open_frame->protocol = PROTOCOL_SSP;
	open_frame->frame_type = ADDRESS_OPEN_FRAME;
	open_frame->connect_rate = (prm->cmd->open_frame->received_rate);
	open_frame->connect_tag =
		be16_to_cpu(prm->cmd->open_frame->received_tag);
	open_frame->dest_sas_addr =
		mvst_get_be_sas_addr((u8 *)&prm->cmd->open_frame->src_sas_addr);
	/*  for passthru mode */
	/* fill in SSP frame header (Command Table.SSP frame header) */
	if (cmd_hdr->ssp_passthru == MCH_SSP_MODE_PASSTHRU) {
		struct ssp_frame_header *ssp_hdr;
		/* command table */
		ssp_hdr = (struct ssp_frame_header *)slot->buf;
		ssp_hdr->frame_type = SSP_RESPONSE;
		memcpy(ssp_hdr->hashed_dest_sas_addr,
			prm->cmd->ssp_hdr->hashed_src_sas_addr,
			HASHED_SAS_ADDR_SIZE);
		memcpy(ssp_hdr->hashed_src_sas_addr,
		       prm->cmd->ssp_hdr->hashed_dest_sas_addr,
		       HASHED_SAS_ADDR_SIZE);
		/* copy the tag from received command frame */
		ssp_hdr->tag = be16_to_cpu(prm->cmd->ssp_hdr->tag);
	}

	TRACE_EXIT();
	return 0;
}

static int
mvst_send_resp(struct mvs_info *mvi, struct mvst_cmd *cmd)
{
	struct mvst_prm prm = { NULL };
	struct scst_cmd *scst_cmd = cmd->scst_cmd;
	u16 pass = 0;
	struct mvs_slot_info *slot;
	u32 res = SCST_TGT_RES_SUCCESS;

	TRACE_ENTRY();

	prm.cmd = (struct mvst_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	prm.sg = scst_cmd_get_sg(scst_cmd);
	prm.bufflen = scst_cmd_get_resp_data_len(scst_cmd);
	prm.sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	prm.data_direction = scst_cmd_get_data_direction(scst_cmd);
	prm.rq_result = scst_cmd_get_status(scst_cmd);
	prm.sense_buffer = scst_cmd_get_sense_buffer(scst_cmd);
	prm.sense_buffer_len = scst_cmd_get_sense_buffer_len(scst_cmd);
	prm.tgt = mvi->tgt;
	prm.seg_cnt = 0;
	prm.req_cnt = 1;

	{
		/* prepare response frame */
		slot = mvst_get_slot(mvi, cmd->cmd_tgt_port);
		if (!slot) {
			res = SCST_TGT_RES_QUEUE_FULL;
			goto err_out;
		}
		/* save scst cmd */
		slot->slot_scst_cmd = scst_cmd;
		mvst_prep_resp_frame(&prm, slot, SENSE_DATA);

		pass++;
		mvi->tx_prod = (mvi->tx_prod + 1) & (MVS_CHIP_SLOT_SZ - 1);

	}
	/* Mid-level is done processing */
	cmd->cmd_state = MVST_STATE_PROCESSED;
	goto out_done;

err_out:
	TRACE_DBG("send_resp failed[%d]!\n", res);
out_done:
	if (pass)
		MVS_CHIP_DISP->start_delivery(mvi,
			(mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));
	TRACE_EXIT_RES(res);
	return res;
}


static int  mvst_prep_data_frame(struct mvst_prm *prm,
			struct mvs_slot_info *slot, u8 datapres)
{
	u16 tag;
	u8 *buf_tmp;
	dma_addr_t buf_tmp_dma;
	u32 resp_len, prd_len = 0;
	const u32 max_resp_len = SB_RFB_MAX;
	u16 cmd_tbl_len = MVS_MAX_SSP_FRAME * 4;
	struct mvs_info *mvi = prm->tgt->mvi;
	struct mvs_cmd_header *cmd_hdr;
	struct mvs_delivery_queue *delivery_q;
	struct mvs_prd *buf_prd;
	struct open_address_frame *open_frame;
	struct mv_ssp_response_iu *response_iu;

	TRACE_ENTRY();

	tag = slot->target_cmd_tag;
	cmd_hdr = (struct mvs_cmd_header *)&mvi->slot[tag];
	/* get free delivery queue */
	delivery_q = (struct mvs_delivery_queue *)&mvi->tx[mvi->tx_prod];

	/* SSP protocol, Target mode, Normal priority */
	delivery_q->cmd = TXQ_CMD_SSP;
	delivery_q->mode = TXQ_MODE_TARGET;
	delivery_q->priority = TXQ_PRI_NORMAL;
	delivery_q->sata_reg_set = 0;
	delivery_q->phy = prm->cmd->cmd_tgt_port->wide_port_phymap;
	delivery_q->slot_nm = tag;

	if (datapres == SENSE_DATA) {
		if (scst_sense_valid(prm->sense_buffer))
			datapres = SENSE_DATA;
		else
			datapres = 0;
	}

	/* command header dword 0 */
	cmd_hdr->prd_entry_count = prm->sg_cnt;
	cmd_hdr->ssp_frame_type = MCH_SSP_FR_READ_RESP;
	cmd_hdr->ssp_passthru = MCH_SSP_MODE_NORMAL;

	/* command header dword 1 */
	/* configure in below */

	/* command header dword 2 */
	cmd_hdr->target_tag = cpu_to_le16(tag);

	/* copy the tag from received command frame */
	cmd_hdr->tag = be16_to_cpu(prm->cmd->ssp_hdr->tag);

	/* command header dword 3 */
	cmd_hdr->data_len = cpu_to_le32(prm->bufflen);

	/*
	 * arrange MVS_SLOT_BUF_SZ-sized DMA buffer according to our needs
	 */

	/* command header dword 4 -5 */
	/* region 1: command table area (MVS_SSP_CMD_SZ bytes) ************** */
	buf_tmp  = slot->buf;
	buf_tmp_dma = slot->buf_dma;
	cmd_hdr->cmd_tbl = cpu_to_le64(buf_tmp_dma);

	/* prepare response frame following data */
	buf_tmp += sizeof(struct ssp_frame_header);
	response_iu = (struct mv_ssp_response_iu *)buf_tmp;
	response_iu->datapres = datapres;
	response_iu->status = prm->rq_result;
	if (datapres) {
		response_iu->sense_data_len =
			cpu_to_le32(prm->sense_buffer_len);
		memcpy(response_iu->data,
			prm->sense_buffer, prm->sense_buffer_len);
	}
	buf_tmp -= sizeof(struct ssp_frame_header);

	/* command header dword 6 -7 */
	buf_tmp += cmd_tbl_len;
	buf_tmp_dma += cmd_tbl_len;
	/* region 2: open address frame area (MVS_OAF_SZ bytes) ********* */
	slot->open_frame = buf_tmp;
	cmd_hdr->open_frame = cpu_to_le64(buf_tmp_dma);

	/* command header dword 10 -11 */
	buf_tmp += MVS_OAF_SZ;
	buf_tmp_dma += MVS_OAF_SZ;

	/* region 3: PRD table *********************************** */
	buf_prd = (struct mvs_prd *)buf_tmp;
	if (prm->sg_cnt != 0)
		cmd_hdr->prd_tbl = cpu_to_le64(buf_tmp_dma);
	else
		cmd_hdr->prd_tbl = 0;

	prd_len = MVS_CHIP_DISP->prd_size() * prm->sg_cnt;
	buf_tmp += prd_len;
	buf_tmp_dma += prd_len;

	/* command header dword 8 -9 */
	/* region 4: status buffer (larger the PRD, smaller this buf) ****** */
	slot->response = buf_tmp;
	cmd_hdr->status_buf = cpu_to_le64(buf_tmp_dma);

	/* command header dword 1 */
	resp_len = MVS_SLOT_BUF_SZ - cmd_tbl_len - MVS_OAF_SZ -
	    sizeof(struct mvs_err_info) - prd_len;
	resp_len = min(resp_len, max_resp_len);

	cmd_hdr->max_rsp_frame_len = resp_len / 4;
	cmd_hdr->frame_len = cmd_tbl_len;

	/* generate open address frame hdr (first 12 bytes) */
	open_frame = (struct open_address_frame *)slot->open_frame;
	open_frame->initiator = 0;	/* target mode */
	open_frame->protocol = PROTOCOL_SSP;
	open_frame->frame_type = ADDRESS_OPEN_FRAME;
	open_frame->connect_rate = (prm->cmd->open_frame->received_rate);
	open_frame->connect_tag =
		be16_to_cpu(prm->cmd->open_frame->received_tag);
	open_frame->dest_sas_addr =
		mvst_get_be_sas_addr((u8 *)&prm->cmd->open_frame->src_sas_addr);

	/*  for passthru mode */
	/* fill in SSP frame header (Command Table.SSP frame header) */
	if (cmd_hdr->ssp_passthru == MCH_SSP_MODE_PASSTHRU) {
		struct ssp_frame_header *ssp_hdr;
		/* command table */
		ssp_hdr = (struct ssp_frame_header *)slot->buf;
		ssp_hdr->frame_type = SSP_DATA;
		memcpy(ssp_hdr->hashed_dest_sas_addr,
			prm->cmd->ssp_hdr->hashed_src_sas_addr,
			HASHED_SAS_ADDR_SIZE);
		memcpy(ssp_hdr->hashed_src_sas_addr,
		       prm->cmd->ssp_hdr->hashed_dest_sas_addr,
		       HASHED_SAS_ADDR_SIZE);
		/* copy the tag from received command frame */
		ssp_hdr->tag = be16_to_cpu(prm->cmd->ssp_hdr->tag);
	}

	/* fill in PRD (scatter/gather) table, if any */
	mvst_prep_prd(prm, buf_prd);
	TRACE_EXIT();
	return 0;
}

static int
mvst_send_data_resp(struct mvs_info *mvi,
				struct mvst_prm *prm)
{
	u16 pass = 0;
	struct mvs_slot_info *slot;
	u32 res = SCST_TGT_RES_SUCCESS;
	struct mvst_cmd *cmd = prm->cmd;
	TRACE_ENTRY();
	/* prepare response frame */
	slot = mvst_get_slot(mvi, cmd->cmd_tgt_port);
	if (!slot) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto err_out;
	}
	/* save scst cmd */
	slot->slot_scst_cmd = cmd->scst_cmd;
	mvst_prep_data_frame(prm, slot, SENSE_DATA);
	pass++;
	mvi->tx_prod = (mvi->tx_prod + 1) & (MVS_CHIP_SLOT_SZ - 1);
	/* Mid-level is done processing */
	cmd->cmd_state = MVST_STATE_PROCESSED;
	goto out_done;
err_out:
	TRACE_DBG("send_data_frame failed[%d]!\n", res);
out_done:
	if (pass) {
		MVS_CHIP_DISP->start_delivery(mvi,
			(mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));
	}
	TRACE_EXIT_RES(res);
	return res;
}

static int mvst_xmit_response(struct scst_cmd *scst_cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	struct mvst_sess *sess;
	int is_send_status;
	unsigned long flags = 0;
	struct mvst_prm prm = { NULL };
	struct mvs_info	*mvi;

	TRACE_ENTRY();

	TRACE(TRACE_SCSI, "xmit_respons scmd[0x%p] tag=%lld, sg_cnt=%d",
		scst_cmd, scst_cmd_get_tag(scst_cmd), scst_cmd->sg_cnt);

#ifdef DEBUG_WORK_IN_THREAD
	if (scst_cmd_atomic(scst_cmd))
		return SCST_TGT_RES_NEED_THREAD_CTX;
#endif
	memset(&prm, 0, sizeof(struct mvst_prm));
	prm.cmd = (struct mvst_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	TRACE_DBG("xmit_response cmd[0x%p]", prm.cmd);
	sess = (struct mvst_sess *)
		scst_sess_get_tgt_priv(scst_cmd_get_session(scst_cmd));

	if (unlikely(scst_cmd_aborted_on_xmit(scst_cmd))) {
		TRACE_MGMT_DBG("mvst tgt: terminating exchange "
			"for aborted scst_cmd=%p (tag=%lld)",
			scst_cmd, scst_cmd_get_tag(scst_cmd));

		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);

		prm.cmd->cmd_state = MVST_STATE_ABORTED;

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

	TRACE_DBG("rq_result=%x, is_send_status=%x,"
		"bufflen=0x%x, sense_buffer_len=0x%x", prm.rq_result,
		is_send_status, prm.bufflen, prm.sense_buffer_len);

	mvi = prm.tgt->mvi;

	if (prm.rq_result != 0)
		TRACE_BUFFER("Sense", prm.sense_buffer, prm.sense_buffer_len);

	if (!is_send_status) {
		/* ToDo, after it's done in SCST */
		PRINT_ERROR("mvst tgt(%ld): is_send_status not set: "
		     "feature not implemented", prm.tgt->mvi->instance);
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out_tgt_free;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&prm.tgt->mvi->lock, flags);

	/*
	 * We need send read left data/response frame to HBA in later,
	 * so save the cmd to mvi->data_cmd_list.
	 */
	list_add_tail(&prm.cmd->cmd_entry, &mvi->data_cmd_list);
	if (mvst_has_data(scst_cmd)) {
		/* prepare send data frame */
		res = mvst_send_data_resp(mvi, &prm);
		if (res)
			TRACE_DBG("xmit_response"
			"mvst_send_data failed[%d]!\n",
			res);
		goto out_done;
	} else {
		/* prepare response frame */
		res = mvst_send_resp(mvi, prm.cmd);
		if (res)
			TRACE_DBG("xmit_response"
			"mvst_send_resp failed[%d]!\n",
			res);
	}

out_done:
	/* Release ring specific lock */
	spin_unlock_irqrestore(&prm.tgt->mvi->lock, flags);

out:
	TRACE_EXIT_RES(res);
	return res;

out_tgt_free:

	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_TASKLET);
	/* !! At this point cmd could be already freed !! */
	goto out;
}



static int mvst_prep_xfer_frame(struct mvst_prm *prm,
			struct mvs_slot_info *slot, u8 first_xfer)
{
	u16 tag;
	void *buf_tmp, *buf_cmd;
	dma_addr_t buf_tmp_dma;
	u32 resp_len, req_len, prd_len;
	const u32 max_resp_len = SB_RFB_MAX;
	struct mvs_info *mvi = prm->tgt->mvi;
	struct mvs_cmd_header *cmd_hdr;
	struct mvs_delivery_queue *delivery_q;
	struct mvs_prd *buf_prd;
	struct open_address_frame *open_frame;
	struct ssp_xfrd_iu *xfrd_iu;

	TRACE_ENTRY();

	tag = slot->target_cmd_tag;
	cmd_hdr = (struct mvs_cmd_header *)&mvi->slot[tag];
	/* get free delivery queue */
	delivery_q = (struct mvs_delivery_queue *)&mvi->tx[mvi->tx_prod];
	req_len = sizeof(struct ssp_frame_header) + sizeof(struct ssp_xfrd_iu);

	/* SSP protocol, Target mode, Normal priority */
	delivery_q->cmd = TXQ_CMD_SSP;
	delivery_q->mode = TXQ_MODE_TARGET;
	delivery_q->priority = TXQ_PRI_NORMAL;
	delivery_q->sata_reg_set = 0;
	delivery_q->phy = prm->cmd->cmd_tgt_port->wide_port_phymap;
	delivery_q->slot_nm = tag;

	TRACE_DBG("delivery_q=0x%x.\n", mvi->tx[mvi->tx_prod]);
	/* command header dword 0 */
	cmd_hdr->prd_entry_count = prm->sg_cnt;
	cmd_hdr->ssp_frame_type = MCH_SSP_FR_XFER_RDY;
	cmd_hdr->ssp_passthru = MCH_SSP_MODE_NORMAL;

	/* command header dword 1 */
	/* configure in below */

	/* command header dword 2 */
	/* copy the tag from received command frame */
	cmd_hdr->target_tag = cpu_to_le16(tag);
	cmd_hdr->tag = be16_to_cpu(prm->cmd->ssp_hdr->tag);

	/* command header dword 3 */
	cmd_hdr->data_len = cpu_to_le32(prm->bufflen);

	/*
	 * arrange MVS_SLOT_BUF_SZ-sized DMA buffer according to our needs
	 */
	/* command header dword 4 -5 */
	/* region 1: command table area (MVS_SSP_CMD_SZ bytes) ***** */
	buf_tmp = buf_cmd = slot->buf;
	buf_tmp_dma = slot->buf_dma;
	cmd_hdr->cmd_tbl = cpu_to_le64(buf_tmp_dma);

	/* command header dword 6 -7 */
	buf_tmp += req_len;
	buf_tmp_dma += req_len;
	/* region 2: open address frame area (MVS_OAF_SZ bytes) ***** */
	slot->open_frame = buf_tmp;
	cmd_hdr->open_frame = cpu_to_le64(buf_tmp_dma);

	/* command header dword 10 -11 */
	buf_tmp += MVS_OAF_SZ;
	buf_tmp_dma += MVS_OAF_SZ;
	/* region 3: PRD table ************************ */
	buf_prd = buf_tmp;
	if (prm->sg_cnt)
		cmd_hdr->prd_tbl = cpu_to_le64(buf_tmp_dma);
	else
		cmd_hdr->prd_tbl = 0;

	prd_len = sizeof(struct mvs_prd) * prm->sg_cnt;
	buf_tmp += prd_len;
	buf_tmp_dma += prd_len;

	/* command header dword 8 -9 */
	/* region 4: status buffer (larger the PRD, smaller this buf) ****** */
	slot->response = buf_tmp;
	cmd_hdr->status_buf = cpu_to_le64(buf_tmp_dma);

	/* command header dword 1 */
	resp_len = MVS_SLOT_BUF_SZ - req_len - MVS_OAF_SZ -
	    sizeof(struct mvs_err_info) - prd_len;
	resp_len = min(resp_len, max_resp_len);

	cmd_hdr->max_rsp_frame_len = resp_len / 4;
	cmd_hdr->frame_len =
		req_len / 4 < MVS_MAX_SSP_FRAME ?
		req_len/4 : MVS_MAX_SSP_FRAME;

	TRACE_BUFFER("command header:", cmd_hdr, sizeof(*cmd_hdr));
	/* generate open address frame hdr (first 12 bytes) */
	open_frame = (struct open_address_frame *)slot->open_frame;
	/* target mode */
	open_frame->initiator = 0;
	open_frame->protocol = PROTOCOL_SSP;
	open_frame->frame_type = ADDRESS_OPEN_FRAME;
	open_frame->connect_rate = (prm->cmd->open_frame->received_rate);
	open_frame->connect_tag =
		be16_to_cpu(prm->cmd->open_frame->received_tag);
	open_frame->dest_sas_addr =
		mvst_get_be_sas_addr((u8 *)&prm->cmd->open_frame->src_sas_addr);

	TRACE_BUFFER("open frame:", open_frame, sizeof(*open_frame));
/*  for passthru mode */
	/* fill in SSP frame header (Command Table.SSP frame header) */
	if (cmd_hdr->ssp_passthru == MCH_SSP_MODE_PASSTHRU) {
		struct ssp_frame_header *ssp_hdr;
		ssp_hdr = (struct ssp_frame_header *)slot->buf;
		ssp_hdr->frame_type = SSP_XFER_RDY;
		memcpy(ssp_hdr->hashed_dest_sas_addr,
			prm->cmd->ssp_hdr->hashed_src_sas_addr,
		       HASHED_SAS_ADDR_SIZE);
		memcpy(ssp_hdr->hashed_src_sas_addr,
		       prm->cmd->ssp_hdr->hashed_dest_sas_addr,
		       HASHED_SAS_ADDR_SIZE);
		/* copy the tag from received command frame */
		ssp_hdr->tag = be16_to_cpu(prm->cmd->ssp_hdr->tag);
	}

	/* fill in xfer ready frame IU */
	buf_cmd += sizeof(struct ssp_frame_header);
	xfrd_iu = (struct ssp_xfrd_iu *)buf_cmd;
	xfrd_iu->data_len = cpu_to_be32(prm->bufflen);
	if ((!prm->cmd->command_iu->first_burst) ||
		(!prm->cmd->open_frame->first_burst_size))
		xfrd_iu->requested_offset = 0;
	else
		xfrd_iu->requested_offset =
			prm->cmd->open_frame->first_burst_size;
	TRACE_BUFFER("xfrd_iu:", xfrd_iu, sizeof(*xfrd_iu));

	/* fill in PRD (scatter/gather) table, if any */
	mvst_prep_prd(prm, buf_prd);

	TRACE_EXIT();
	return 0;
}

static int mvst_pci_map_calc_cnt(struct mvst_prm *prm)
{
	struct mvs_info *mvi = prm->tgt->mvi;
	int res = 0;

	sBUG_ON(prm->sg_cnt == 0);

	/* 32 bit S/G Data Transfer */
	prm->seg_cnt = pci_map_sg(prm->tgt->mvi->pdev, prm->sg, prm->sg_cnt,
			       scst_to_tgt_dma_dir(prm->data_direction));
	if (unlikely(prm->seg_cnt == 0))
		goto out_err;
	/*
	 * If greater than four sg entries then we need to allocate
	 * the continuation entries, but bug on now
	 */

	sBUG_ON(prm->seg_cnt > MVS_MAX_SG);
out:
	TRACE_DBG("seg_cnt=%d, req_cnt=%d, res=%d", prm->seg_cnt,
		prm->req_cnt, res);
	return res;

out_err:
	PRINT_ERROR("mvs_tgt PCI mapping failed: sg_cnt=%d", prm->sg_cnt);
	res = -1;
	goto out;
}

static int mvst_rdy_to_xfer(struct scst_cmd *scst_cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	struct mvst_sess *sess;
	unsigned long flags = 0;
	struct mvst_prm prm = { NULL };
	struct mvs_slot_info *slot;
	u32 rc = 0, pass = 0;
	struct mvs_info *mvi;
	TRACE_ENTRY();
	TRACE(TRACE_SCSI, "tag=%lld", scst_cmd_get_tag(scst_cmd));

#ifdef DEBUG_WORK_IN_THREAD
	if (scst_cmd_atomic(scst_cmd))
		return SCST_TGT_RES_NEED_THREAD_CTX;
#endif
	prm.cmd = (struct mvst_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	sess = (struct mvst_sess *)
		scst_sess_get_tgt_priv(scst_cmd_get_session(scst_cmd));
	prm.sg = scst_cmd_get_sg(scst_cmd);
	prm.bufflen = scst_cmd_get_bufflen(scst_cmd);
	prm.sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	prm.data_direction = scst_cmd_get_data_direction(scst_cmd);
	prm.tgt = sess->tgt;
	prm.req_cnt = 1;
	prm.cmd->cmd_state = MVST_STATE_NEED_DATA;

	mvi = prm.tgt->mvi;

	/* Acquire ring specific lock */
	spin_lock_irqsave(&mvi->lock, flags);

	/* Calculate number of entries and segments required */
	if (mvst_pci_map_calc_cnt(&prm) != 0) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto err_out;
	}

	slot = mvst_get_slot(mvi, prm.cmd->cmd_tgt_port);
	if (!slot) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto err_out;
	}
	slot->slot_scst_cmd = scst_cmd;

	TRACE_DBG("start rdy_to_xfer: mvi(%d)", (int) prm.tgt->mvi->instance);

	rc = mvst_prep_xfer_frame(&prm, slot, 1);
	if (rc) {
		res = SCST_TGT_RES_FATAL_ERROR;
		goto err_out_tag;
	}
	++pass;
	mvi->tx_prod = (mvi->tx_prod + 1) & (MVS_CHIP_SLOT_SZ - 1);

	goto out_done;

err_out_tag:
	PRINT_ERROR("%s:prepare xfer frame failed.", __func__);
	mvst_put_slot(mvi, slot);
err_out:
	PRINT_ERROR("%s:No sufficient tag for xfer frame", __func__);
out_done:
	if (pass)
		MVS_CHIP_DISP->start_delivery(mvi,
			(mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));

	/* Release ring specific lock */
	spin_unlock_irqrestore(&mvi->lock, flags);

	TRACE_EXIT_RES(res);
	return res;
}

static inline void mvst_free_cmd(struct mvst_cmd *cmd)
{
	kmem_cache_free(mvst_cmd_cachep, cmd);
}

static void mvst_on_free_cmd(struct scst_cmd *scst_cmd)
{
	struct mvst_cmd *cmd =
		(struct mvst_cmd *)scst_cmd_get_tgt_priv(scst_cmd);

	TRACE_ENTRY();
	TRACE(TRACE_SCSI, "END Command tag %lld", scst_cmd_get_tag(scst_cmd));
	scst_cmd_set_tgt_priv(scst_cmd, NULL);
	memset(cmd->ssp_hdr, 0, sizeof(*cmd->ssp_hdr));
	memset(cmd->command_iu, 0, sizeof(*cmd->command_iu));
	memset(cmd->open_frame, 0, sizeof(*cmd->open_frame));
	memset(cmd, 0, sizeof(*cmd));

	mvst_free_cmd(cmd);

	TRACE_EXIT();
	return;
}


static int mvst_slot_tgt_err(struct mvs_info *mvi,	 u32 slot_idx)
{
	struct mvs_slot_info *slot = &mvi->slot_info[slot_idx];
	u32 err_dw0 = le32_to_cpu(*(u32 *) (slot->response));
	u32 err_dw1 = le32_to_cpu(*(u32 *) (slot->response + 4));
	int stat = 0;
	TRACE_ENTRY();
	if (err_dw0 & CMD_ISS_STPD)
		mv_dprintk("slot[%d] command issue stopped.\n", slot_idx);

	if (err_dw1 & SLOT_BSY_ERR)
		mv_dprintk("slot[%d] busy error.\n", slot_idx);
	mv_dprintk("slot[%d] get error Dw0:0x%x, Dw1:0x%x\n",
		slot_idx, err_dw0, err_dw1);
	TRACE_BUFFER("status buffer:", (u8 *) slot->response, 16);
	TRACE_EXIT_HRES(stat);
	return stat;
}

/* mvi->lock supposed to be held on entry */
static void mvst_do_cmd_completion(struct mvs_info *mvi,
				  uint32_t rx_desc)
{
	u32 slot_idx = rx_desc & RXQ_SLOT_MASK;
	struct mvs_slot_info *slot =
		(struct mvs_slot_info *)&mvi->slot_info[slot_idx];
	struct mvs_cmd_header  *cmd_hdr =
		(struct mvs_cmd_header  *)&mvi->slot[slot_idx];
	struct scst_cmd *scst_cmd;
	struct mvst_cmd *cmd;
	int err = 0;
	u8 frame_type;
	u64 dest_sas_addr;
	TRACE_ENTRY();

	frame_type = cmd_hdr->ssp_frame_type;
	TRACE(TRACE_DEBUG|TRACE_SCSI, "frame[0x%x] complete, rx_desc=0x%x",
	      frame_type, rx_desc);

	/* error info record present */
	if (unlikely((rx_desc & RXQ_ERR) && (slot->response))) {
		mvst_slot_tgt_err(mvi, slot_idx);
		TRACE_DBG("Found by failed  frame_type[0x%x]", frame_type);
		err = 1;
	}

	 if (slot->slot_scst_cmd) {
		if (!slot->open_frame) {
			TRACE_DBG("Found recevied command[%p]"
				"but no open frame.", slot->slot_scst_cmd);
			sBUG_ON(!slot->open_frame);
			goto out;
		}
	 }

	 if (slot->slot_scst_cmd) {
		struct open_address_frame *open_frame =
			(struct open_address_frame *)slot->open_frame;
		struct ssp_frame_header *ssp_hdr;
		struct mvst_sess *sess;
		TRACE_BUFFER("SSP open_frame", open_frame, sizeof(*open_frame));
		dest_sas_addr = (open_frame->dest_sas_addr);
		sess = mvst_find_sess_by_lid(mvi->tgt,
			mvst_get_le_sas_addr((u8 *)&dest_sas_addr));
		TRACE(TRACE_DEBUG, "dest_sas_addr=%016llx", dest_sas_addr);
		if (sess == NULL) {
			ssp_hdr = (struct ssp_frame_header *)slot->buf;
			TRACE_DBG("mvst tgt(%ld): Suspicious: "
				   "command completion for non-existing"
				   "session " "(sas addr[%016llx], tag %d)",
				   mvi->instance,
				   mvst_get_le_sas_addr((u8 *)&dest_sas_addr),
				   be16_to_cpu(ssp_hdr->tag));
			goto out;
		}
		scst_cmd = slot->slot_scst_cmd;
		TRACE_DBG("Found scst_cmd %p", scst_cmd);

		cmd = (struct mvst_cmd *)scst_cmd_get_tgt_priv(scst_cmd);

		if (cmd->cmd_state == MVST_STATE_PROCESSED) {
			TRACE_DBG("Command %p finished", cmd);
			if (mvst_has_data(scst_cmd)) {
				pci_unmap_sg(mvi->pdev,
					scst_cmd_get_sg(scst_cmd),
					scst_cmd_get_sg_cnt(scst_cmd),
					scst_to_tgt_dma_dir(
					scst_cmd_get_data_direction(scst_cmd)));
			}
			if (err)
				goto out;
			list_del(&cmd->cmd_entry);
			goto out_free;
		} else if (cmd->cmd_state == MVST_STATE_NEED_DATA) {
			int context = SCST_CONTEXT_TASKLET;
			int rx_status = SCST_RX_STATUS_SUCCESS;

			cmd->cmd_state = MVST_STATE_DATA_IN;

			if (err)
				rx_status = SCST_RX_STATUS_ERROR;

#ifdef DEBUG_WORK_IN_THREAD
			context = SCST_CONTEXT_THREAD;
#endif

			TRACE_DBG("Data received, context %x, rx_status %d",
			      context, rx_status);

			pci_unmap_sg(mvi->pdev, scst_cmd_get_sg(scst_cmd),
				scst_cmd_get_sg_cnt(scst_cmd),
				scst_to_tgt_dma_dir(
				scst_cmd_get_data_direction(scst_cmd)));

			scst_rx_data(scst_cmd, rx_status, context);
		} else if (cmd->cmd_state == MVST_STATE_SEND_DATA) {
			TRACE_DBG("Read data command %p finished", cmd);
			if (err) {
				cmd->cmd_state = MVST_STATE_SEND_DATA_RETRY;
				sBUG_ON(1);
			}
			goto out;
		} else if (cmd->cmd_state == MVST_STATE_ABORTED) {
			TRACE_DBG("Aborted command %p finished", cmd);
			goto out_free;
		} else {
			PRINT_ERROR("mvst tgt(%ld): A command in state"
				"(%d) should " "not return a complete",
				mvi->instance, cmd->cmd_state);
			goto out_free;
		}
	} else if (slot->slot_scst_mgmt_cmd) {
		TRACE_DBG("Found tmf frame[0x%x] complete",
			cmd_hdr->ssp_frame_type);
		cmd = scst_mgmt_cmd_get_tgt_priv(slot->slot_scst_mgmt_cmd);
		kfree(cmd);
		goto out;
	} else {
		TRACE_DBG("Found internal target frame[0x%x] complete",
			cmd_hdr->ssp_frame_type);
		goto out;
	}
out:
	mvst_put_slot(mvi, slot);
	TRACE_EXIT();
	return;

out_free:
	if (unlikely(err)) {
		TRACE_MGMT_DBG("%s", "Finishing failed CTIO");
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
	}

	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_TASKLET);
	goto out;
}

/* mvi->lock supposed to be held on entry */
/* called via callback from mvst */
static void mvst_cmd_completion(struct mvs_info *mvi, uint32_t rx_desc)
{
	u32 slot_idx = rx_desc & RXQ_SLOT_MASK;
	struct mvs_cmd_header  *cmd_hdr = NULL;

	TRACE_ENTRY();

	sBUG_ON(mvi == NULL);

	if ((mvi->tgt != NULL) && MVST_IN_TARGET_MODE(mvi))
		mvst_do_cmd_completion(mvi, rx_desc);
	else {
		cmd_hdr = (struct mvs_cmd_header  *)&mvi->slot[slot_idx];
		TRACE_DBG("command complete, but target mode not enabled."
			"mvi %p complete frame 0x%x",
			mvi, cmd_hdr->ssp_frame_type);
	}
	TRACE_EXIT();
	return;
}



/* mvi->lock is supposed to be held on entry */
static int mvst_do_send_cmd_to_scst(struct mvs_info *mvi, struct mvst_cmd *cmd)
{
	int res = 0;
	struct mvst_sess *sess = cmd->sess;
	u8 lun[8];
	scst_data_direction dir = SCST_DATA_NONE;
	int context;

	TRACE_ENTRY();

	memcpy(lun, cmd->command_iu->lun, 8);
	cmd->scst_cmd = scst_rx_cmd(sess->scst_sess, (uint8_t *)&lun,
				    sizeof(lun), cmd->command_iu->cdb,
				    MVST_MAX_CDB_LEN,
				    SCST_ATOMIC);

	if (cmd->scst_cmd == NULL) {
		PRINT_ERROR("mvst tgt(%ld): scst_rx_cmd() failed for "
		     "host %ld(%p)", mvi->instance, mvi->host_no, mvi);
		res = -EFAULT;
		goto out;
	}

	TRACE_DBG("Get new scst_cmd %p", cmd->scst_cmd);
	TRACE_BUFFER("Get command header:",
		cmd->ssp_hdr, sizeof(struct ssp_frame_header));
	TRACE_BUFFER("Get command open frame:",
		cmd->open_frame, sizeof(struct open_address_frame));
	scst_cmd_set_tag(cmd->scst_cmd, be16_to_cpu(cmd->ssp_hdr->tag));
	scst_cmd_set_tgt_priv(cmd->scst_cmd, cmd);
	if (cmd->command_iu->cdb[0] & MVST_EXEC_READ)
		dir = SCST_DATA_READ;
	else if (cmd->command_iu->cdb[0] & MVST_EXEC_WRITE)
		dir = SCST_DATA_WRITE;

	switch (cmd->command_iu->task_attr) {
	case TASK_ATTR_SIMPLE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case TASK_ATTR_HOQ:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case TASK_ATTR_ORDERED:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case TASK_ATTR_ACA:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ACA);
		break;
	default:
		PRINT_ERROR("mvst tgt(%ld): Unknown task code %x, use "
			"ORDERED instead", mvi->instance,
			cmd->command_iu->task_attr);
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

#ifdef DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif
	TRACE_DBG("Context %x", context);
	TRACE(TRACE_SCSI, "START Command (tag %lld)",
		scst_cmd_get_tag(cmd->scst_cmd));
	scst_cmd_init_done(cmd->scst_cmd, context);
out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called in SCST's thread context */
static void mvst_alloc_session_done(struct scst_session *scst_sess,
				   void *data, int result)
{
	TRACE_ENTRY();

	if (result != 0) {
		struct mvst_sess *sess = (struct mvst_sess *)data;
		struct mvst_tgt *tgt = sess->tgt;
		struct mvs_info *mvi = tgt->mvi;
		unsigned long flags;

		TRACE_DBG("mvst tgt(%ld): Session initialization failed",
			   mvi->instance);

		spin_lock_irqsave(&mvi->lock, flags);
		mvst_unreg_sess(sess);
		spin_unlock_irqrestore(&mvi->lock, flags);
	}

	TRACE_EXIT();
	return;
}



static char *mvst_make_name(struct mvs_info *mvi)
{
	char *wwn_str;
	u8 name[16];
	strcpy(name,  MVST_NAME);

	wwn_str = kmalloc(3*SAS_ADDR_SIZE, GFP_ATOMIC);
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

static struct mvst_port *mvst_get_port_by_sasaddr(struct mvs_info *mvi,
						  u64 dst_sas_addr,
						  u64 src_sas_addr)
{
	int n = 0;
	for (n = 0; n < mvi->chip->n_phy; n++) {
		if ((SAS_ADDR(&mvi->phy[n].dev_sas_addr) == dst_sas_addr)
			&& mvi->tgt_port[n].port_attached)
			break;
	}
#if 0
	/*check if direct initiator cmd*/
	if (n == mvi->chip->n_phy) {
		for (n = 0; n < mvi->chip->n_phy; n++) {
			if ((mvi->tgt_port[n].sas_addr == dst_sas_addr)
				&& mvi->tgt_port[n].port_attached)
				break;
		}
		if (n == mvi->chip->n_phy)
			return NULL;
	} else {
		for (n = 0; n < mvi->chip->n_phy; n++) {
			if ((mvi->tgt_port[n].att_sas_addr == src_sas_addr)
				&& mvi->tgt_port[n].port_attached)
				break;
		}
		if (n == mvi->chip->n_phy)
			mv_dprintk("Port attatch sas address error\n");
	}
#endif

	if (n == mvi->chip->n_phy) {
		mv_dprintk("Port attatch sas address error\n");
		return NULL;
	}

	return &mvi->tgt_port[n];
}

static int mvst_build_cmd(struct mvs_info *mvi, struct mvs_slot_info *slot,
			  struct mvst_cmd **pcmd, int cmd_type)
{
	int res = 0;
	u64 src_sas_addr, dst_sas_addr;
	struct mvst_cmd *cmd = NULL;
	struct open_address_frame *open_frame =
		(struct open_address_frame *)slot->open_frame;
	struct ssp_frame_header *ssp_hdr =
		(struct ssp_frame_header *)((u8 *)slot->response+8);
	struct ssp_command_iu *ssp_cmd_iu =
		(struct ssp_command_iu *)((u8 *)ssp_hdr +
		sizeof(struct ssp_frame_header));
	struct ssp_task_iu *ssp_task_iu =
		(struct ssp_task_iu *)((u8 *)ssp_hdr +
		sizeof(struct ssp_frame_header));
	struct mvst_port	*tgt_port;

	TRACE_ENTRY();

	dst_sas_addr = mvst_get_le_sas_addr((u8 *)&open_frame->dest_sas_addr);
	src_sas_addr = mvst_get_le_sas_addr((u8 *)&open_frame->src_sas_addr);

	tgt_port = mvst_get_port_by_sasaddr(mvi, dst_sas_addr, src_sas_addr);
	if (tgt_port == NULL) {
		res = -EFAULT;
		mv_dprintk("can not find tgt port for dst sas:%016llx,"
			"src sas:%016llx\n",
			dst_sas_addr, src_sas_addr);
		goto out;
	}

	if (mvi->tgt->tgt_shutdown) {
		TRACE_DBG("New command while device %p is shutting "
			"down", tgt_port);
		res = -EFAULT;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	cmd =  kmem_cache_alloc(mvst_cmd_cachep, GFP_ATOMIC);
#else
	cmd =  kmem_cache_zalloc(mvst_cmd_cachep, GFP_ATOMIC);
#endif
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of cmd failed");
		res = -ENOMEM;
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	memset(cmd, 0, sizeof(*cmd));
#endif
	/* set cmd private data for later use */
	if (!cmd_type)
		memcpy(&cmd->save_command_iu,
			ssp_cmd_iu, sizeof(*ssp_cmd_iu));
	else
		memcpy(&cmd->save_task_iu,
			ssp_task_iu, sizeof(*ssp_task_iu));
	memcpy(&cmd->save_open_frame, open_frame, sizeof(*open_frame));
	memcpy(&cmd->save_ssp_hdr, ssp_hdr, sizeof(*ssp_hdr));
	if (!cmd_type)
		cmd->command_iu = &cmd->save_command_iu;
	else
		cmd->task_iu = &cmd->save_task_iu;
	cmd->open_frame = &cmd->save_open_frame;
	cmd->ssp_hdr = &cmd->save_ssp_hdr;
	cmd->cmd_tgt_port = tgt_port;	/* save  SSP Target port */
	cmd->cmd_state = MVST_STATE_NEW;
	cmd->transfer_len = 0;
	cmd->finished_len = 0;
	cmd->transfer_buf = NULL;
out:
	*pcmd = cmd;
	TRACE_EXIT();
	return res;
}


/* mvi->lock supposed to be held on entry */
static int mvst_send_cmd_to_scst(struct mvs_info *mvi,
				 struct mvs_slot_info *slot)
{
	int res = 0;
	u64 initiator_sas_addr;
	struct mvst_tgt *tgt;
	struct mvst_sess *sess;
	struct mvst_cmd *cmd = NULL;
	struct open_address_frame *open_frame =
		(struct open_address_frame *)slot->open_frame;

	TRACE_ENTRY();

	tgt = mvi->tgt;
	initiator_sas_addr = be64_to_cpu(open_frame->src_sas_addr);

	res = mvst_build_cmd(mvi, slot, &cmd, MVST_CMD);
	if (res)
		goto out;

	sess = mvst_find_sess_by_lid(tgt, initiator_sas_addr);
	if (unlikely(sess == NULL)) {
		sess = kzalloc(sizeof(*sess), GFP_ATOMIC);
		if (sess == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
			      "Allocation of sess failed");
			res = -ENOMEM;
			goto out_free_cmd;
		}

		sess->tgt = tgt;
		sess->initiator_sas_addr = initiator_sas_addr;
		INIT_LIST_HEAD(&sess->sess_entry);

		/* register session (remote initiator) */
		{
			char *name;
			name = mvst_make_name(mvi);
			if (name == NULL) {
				PRINT_ERROR("can not make name for"
					"session, cmd[0x%p]",
					cmd);
				res = -ESRCH;
				goto out_free_sess;
			}

			sess->scst_sess = scst_register_session(
				tgt->scst_tgt, SCST_ATOMIC, name, sess, sess,
				mvst_alloc_session_done);
			kfree(name);
		}

		if (sess->scst_sess == NULL) {
			PRINT_ERROR("mvst tgt(%ld): scst_register_session()"
				"failed for host %ld(%p)",
				mvi->instance,
				mvi->host_no, mvi);
			res = -EFAULT;
			goto out_free_sess;
		}

		/* add session data to host data structure */
		list_add(&sess->sess_entry, &tgt->sess_list);
		tgt->sess_count++;
	}
	cmd->sess = sess;
	res = mvst_do_send_cmd_to_scst(mvi, cmd);
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
	mvst_free_cmd(cmd);
	goto out;
}

/* mvi->lock supposed to be held on entry */
static int mvst_handle_task_mgmt(struct mvs_info *mvi,
			struct mvs_slot_info *slot)
{
	int res = 0, rc = -1;
	u64 initiator_sas_addr;
	u8 lun[8];
	u16 tag;
	struct mvst_cmd *cmd = NULL;
	struct mvst_tgt *tgt;
	struct mvst_sess *sess;
	struct open_address_frame *open_frame =
		(struct open_address_frame *)slot->open_frame;
	struct ssp_frame_header *ssp_hdr =
		(struct ssp_frame_header *)((u8 *)slot->response+8);
	struct ssp_task_iu *ssp_task_iu =
		(struct ssp_task_iu *)((u8 *)ssp_hdr +
		sizeof(struct ssp_frame_header));

	TRACE_ENTRY();

	tgt = mvi->tgt;
	memcpy(lun,  ssp_task_iu->lun, 8);
	tag = be16_to_cpu(ssp_task_iu->tag);
	initiator_sas_addr = be64_to_cpu(open_frame->src_sas_addr);

	if (mvst_build_cmd(mvi, slot, &cmd, MVST_TMF))
		goto out;

	sess = mvst_find_sess_by_lid(tgt, initiator_sas_addr);
	if (sess == NULL) {
		TRACE(TRACE_MGMT, "mvsttgt(%ld): task mgmt fn 0x%x for "
		      "non-existant session", mvi->instance,
		      cmd->save_task_iu.task_fun);
		res = -EFAULT;
		goto out;
	}

	cmd->sess = sess;

	switch (cmd->save_task_iu.task_fun) {
	case TMF_CLEAR_ACA:
		TRACE(TRACE_MGMT, "%s", "TMF_CLEAR_ACA received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_ACA,
					 &lun, sizeof(lun), SCST_ATOMIC, cmd);
		break;

	case TMF_LU_RESET:
		TRACE(TRACE_MGMT, "%s", "TMF_LU_RESET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_LUN_RESET,
					 &lun, sizeof(lun), SCST_ATOMIC, cmd);
		break;

	case TMF_CLEAR_TASK_SET:
		TRACE(TRACE_MGMT, "%s", "TMF_CLEAR_TASK_SET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_TASK_SET,
					 &lun, sizeof(lun), SCST_ATOMIC, cmd);
		break;

	case TMF_ABORT_TASK_SET:
		TRACE(TRACE_MGMT, "%s", "TMF_ABORT_TASK_SET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_ABORT_TASK_SET,
					 &lun, sizeof(lun), SCST_ATOMIC, cmd);
		break;

	case TMF_ABORT_TASK:
		TRACE(TRACE_MGMT, "%s", "TMF_ABORT_TASK received");
		rc = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK, tag,
			SCST_ATOMIC, cmd);
		break;

	default:
		PRINT_ERROR("mvsttgt(%ld): Unknown task mgmt fn 0x%x",
			    mvi->instance, cmd->save_task_iu.task_fun);
		break;
	}

	if (rc != 0) {
		PRINT_ERROR("mvst tgt(%ld): scst_rx_mgmt_fn_lun() failed: %d",
			    mvi->instance, rc);
		res = -EFAULT;
		goto out_free;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(cmd);
	goto out;
}

static int mvst_notify_attach_chg(void)
{
	u8 i, j;
	int res = SCST_AEN_RES_SUCCESS;
	struct mvs_info *mvi = ((struct mvs_info **)tgt_mvi)[0];

	TRACE_ENTRY();
	if (!mvi)
		return SCST_AEN_RES_FAILED;
#if	0
	for (i = 0; i < mvi->chip->n_phy; i++) {
		struct mvs_phy *phy = &mvi->phy[i];
		struct asd_sas_phy *sas_phy = &phy->sas_phy;
		if (mvi->tgt_port[i].port_attr & MVST_TGT_PORT)
			sas_phy->tproto = SAS_PROTOCOL_SSP;

		if (mvi->tgt_port[i].port_attached) {
			for (j = 0; j < mvi->chip->n_phy; j++) {
				if (mvi->tgt_port[i].wide_port_phymap & (1<<j))
					MVS_CHIP_DISP->phy_disable(mvi, j);
			}
			msleep(500);
			for (j = 0; j < mvi->chip->n_phy; j++) {
				if (mvi->tgt_port[i].wide_port_phymap &
					(1<<j)) {
					MVS_CHIP_DISP->phy_enable(mvi, j);
				}
			}
		}
	}
#endif
	for (i = 0; i < mvi->chip->n_host; i++) {
		mvi = ((struct mvs_info **)tgt_mvi)[i];
		if (!mvi || !(mvi->flags & MVF_TARGET_MODE_ENABLE))
			continue;
		for (j = 0; j < mvi->chip->n_phy; j++) {
			if (mvi->phy[j].phy_mode)
				MVS_CHIP_DISP->phy_disable(mvi, j);
		}
		msleep(2000);
		for (j = 0; j < mvi->chip->n_phy; j++) {
			if (mvi->phy[j].phy_mode) {
				/* enable phy */
				mv_printk("Reset phy[%d] to notify iniator\n",
				j+mvi->chip->n_phy*i);
				MVS_CHIP_DISP->phy_enable(mvi, j);
			}
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int mvst_notify_unit_attention(struct scst_aen *aen)
{
	int res = SCST_AEN_RES_SUCCESS, key, asc, ascq;

	TRACE_ENTRY();

	if (scst_sense_response_code(aen->aen_sense) == 0x72) {
		key = aen->aen_sense[1];	/* Sense Key	*/
		asc = aen->aen_sense[2]; /* ASC		*/
		ascq = aen->aen_sense[3]; /* ASCQ */
	} else if (scst_sense_response_code(aen->aen_sense) == 0x70) {
		key = aen->aen_sense[2];	/* Sense Key	*/
		asc = aen->aen_sense[12]; /* ASC		*/
		ascq = aen->aen_sense[13]; /* ASCQ */
	} else
		return res;

	switch (key) {
	case UNIT_ATTENTION:
		if (asc == 0x3F && ascq == 0xE)
			mvst_notify_attach_chg();
		break;
		/*
		.to support more
		.
		*/
	default:
		res = SCST_AEN_RES_NOT_SUPPORTED;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int mvst_report_event(struct scst_aen *aen)
{
	int res = 0;
	int event_fn = scst_aen_get_event_fn(aen);

	TRACE_ENTRY();
	switch (event_fn) {
	case SCST_AEN_SCSI:
		res = mvst_notify_unit_attention(aen);
		break;
	default:
		TRACE_MGMT_DBG("Unsupported AEN %d", event_fn);
		res = SCST_AEN_RES_NOT_SUPPORTED;
		break;
	}
	scst_aen_done(aen);
	return res;
}

static u8 mvst_get_mgmt_status(int status)
{
	u8 resp = 0;
	switch (status) {
	case SCST_MGMT_STATUS_SUCCESS:
		resp = MVST_TM_COMPL;
		break;
	case SCST_MGMT_STATUS_LUN_NOT_EXIST:
		resp = MVST_TM_INCRT_LUN;
		break;
	case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
		resp = MVST_TM_NOT_SUPPORT;
		break;
	case SCST_MGMT_STATUS_TASK_NOT_EXIST:
	case SCST_MGMT_STATUS_REJECTED:
	case SCST_MGMT_STATUS_FAILED:
	default:
		resp = MVST_TM_FAILED;
		break;
	}
	return resp;
}

/* mvi->lock supposed to be held on entry */
static inline int mvst_send_notify_ack(struct mvst_cmd *cmd, int status)
{
	int res = 0;
	u8 buf[4] = {0, 0, 0, 0};
	struct mvs_slot_info *resp_slot;
	struct mvst_prm prm = { NULL };
	struct mvs_info *mvi = cmd->sess->tgt->mvi;

	TRACE_ENTRY();

	/* prepare response frame */
	resp_slot = mvst_get_slot(mvi, cmd->cmd_tgt_port);
	if (!resp_slot) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	}

	resp_slot->slot_scst_mgmt_cmd = cmd->scst_mcmd;
	prm.rq_result = SAM_STAT_GOOD;
	prm.tgt = mvi->tgt;
	prm.seg_cnt = 0;
	prm.req_cnt = 1;
	prm.sense_buffer_len = 4;
	prm.sense_buffer = buf;
	prm.cmd = cmd;

	buf[3] = mvst_get_mgmt_status(status);
	mvst_prep_resp_frame(&prm, resp_slot, RESPONSE_DATA);
	/* Mid-level is done processing */
	cmd->cmd_state = MVST_STATE_SEND_STATUS;

	mvi->tx_prod = (mvi->tx_prod + 1) & (MVS_CHIP_SLOT_SZ - 1);
	MVS_CHIP_DISP->start_delivery(mvi,
		(mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));
out:
	TRACE_EXIT();
	return res;
}

/* SCST Callback */
static void mvst_task_mgmt_fn_done(struct scst_mgmt_cmd *scst_mcmd)
{
	struct mvst_cmd *cmd;
	unsigned long flags;
	int status, res = 0;
	TRACE_ENTRY();

	cmd = scst_mgmt_cmd_get_tgt_priv(scst_mcmd);
	if (unlikely(cmd == NULL)) {
		PRINT_ERROR("scst_mcmd %p tgt_spec is NULL", cmd);
		goto out;
	}

	cmd->scst_mcmd = scst_mcmd;
	status = scst_mgmt_cmd_get_status(scst_mcmd);
	spin_lock_irqsave(&cmd->sess->tgt->mvi->lock, flags);
	res = mvst_send_notify_ack(cmd, status);
	spin_unlock_irqrestore(&cmd->sess->tgt->mvi->lock, flags);

	scst_mgmt_cmd_set_tgt_priv(scst_mcmd, NULL);
	if (res)
		kfree(cmd);
out:
	TRACE_EXIT();
	return;
}

static int mvst_send_busy(struct mvs_info *mvi, struct mvs_slot_info *slot)
{
	int res = 0;
	struct mvs_slot_info *resp_slot;
	struct mvst_cmd *cmd = NULL;
	struct mvst_prm prm = { NULL };

	TRACE_ENTRY();

	if (mvst_build_cmd(mvi, slot, &cmd, MVST_CMD)) {
		mv_printk("failed to build cmd from slot %p\n", slot);
		goto out;
	}

	/* prepare response frame */
	resp_slot = mvst_get_slot(mvi, cmd->cmd_tgt_port);
	if (!resp_slot) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto err_out;
	}

	prm.cmd = cmd;
	prm.rq_result = SAM_STAT_BUSY;
	prm.tgt = mvi->tgt;
	prm.seg_cnt = 0;
	prm.req_cnt = 1;

	mvst_prep_resp_frame(&prm, resp_slot, NO_DATA);
	/* Mid-level is done processing */
	cmd->cmd_state = MVST_STATE_SEND_STATUS;

	mvi->tx_prod = (mvi->tx_prod + 1) & (MVS_CHIP_SLOT_SZ - 1);
	MVS_CHIP_DISP->start_delivery(mvi,
		(mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));
out:
	TRACE_EXIT();
	return res;
err_out:
	mvst_free_cmd(cmd);
	goto out;
}

/* mvi->lock supposed to be held on entry */
/* called via callback from mvst */
/* DO NOT call mvst_put_slot in the function, the running slots
    are used to receive initiator command */
static u8 mvst_response_ssp_command(struct mvs_info *mvi, uint32_t rx_desc)
{
	int rc = 0;
	u32 slot_idx = rx_desc & RXQ_SLOT_MASK;
	struct mvs_slot_info *slot = &mvi->slot_info[slot_idx];
	struct ssp_frame_header *ssp_hdr =
		(struct ssp_frame_header *)((u8 *)slot->response+8);

	TRACE_ENTRY();
	if (unlikely((mvi->tgt == NULL) || !MVST_IN_TARGET_MODE(mvi))) {
		TRACE_DBG("receive command, but no tgt. mvi %p tgt_flag %ld",
			mvi, MVST_IN_TARGET_MODE(mvi));
		rc = -1;
		goto out;
	}

	if (!slot->open_frame) {
		TRACE_DBG("Found recevied command[%p] but no open frame.",
			slot->slot_scst_cmd);
		rc = -1;
		goto out;
	}

	if (!slot->slot_tgt_port) {
		mv_printk("Found recevied command[%p]"
			"but no related tgt port.\n",
			slot->slot_scst_cmd);
		rc = -1;
		goto out;

	}
	/*
	 else if (slot->slot_tgt_port->port_attr == MVST_INIT_PORT) {
		mv_dprintk("Found recevied command[%p] but not set
		as tgt port[0x%x].\n", slot->slot_scst_cmd,
		slot->slot_tgt_port->port_attr);
		rc = -1;
		goto out;
	}
	*/

	if ((ssp_hdr->frame_type != SSP_COMMAND) &&
		(ssp_hdr->frame_type != SSP_TASK) &&
		(ssp_hdr->frame_type != SSP_DATA) /* do we need ? */) {
		PRINT_ERROR("mvst tgt(%ld): Received command 0x%x "
		     "is not intiator command",  mvi->instance,
		     ssp_hdr->frame_type);
		rc = -1;
		goto out;
	}

	switch (ssp_hdr->frame_type) {
	case SSP_COMMAND:
		{
		struct ssp_command_iu *ssp_cmd_iu = NULL;
		ssp_cmd_iu = (struct ssp_command_iu *)((u8 *)ssp_hdr
			+ sizeof(struct ssp_frame_header));

		TRACE_DBG("COMMAND FRAME:lun[0-7]=%016llx.\n",
			(u64)(*(u64 *)&ssp_cmd_iu->lun[0]));
		TRACE_DBG("COMMAND FRAME:cdb[0-7]=%016llx,cdb[8-15]=%016llx.\n",
			(u64)(*(u64 *)&ssp_cmd_iu->cdb[0]),
			(u64)(*(u64 *)&ssp_cmd_iu->cdb[8]));
		}

		rc = mvst_send_cmd_to_scst(mvi, slot);
		if (unlikely(rc != 0)) {
			if (rc == -ESRCH)
				mvst_send_busy(mvi, slot);
			else {
				if (!mvi->tgt->tgt_shutdown) {
					mv_dprintk("mvst tgt(%ld): Unable to "
					    "send the command to SCSI target "
					    "mid-level, sending BUSY status.\n",
					    mvi->instance);
				}
				mvst_send_busy(mvi, slot);
			}
		}
		break;

	case SSP_TASK:
		rc = mvst_handle_task_mgmt(mvi, slot);
		if (unlikely(rc != 0)) {
			if (rc == -ESRCH)
				mvst_send_busy(mvi, slot);
			else {
				if (!mvi->tgt->tgt_shutdown) {
					mv_dprintk("mvsttgt(%ld): Unable to "
					"send the task manage to SCSI"
					"target " "mid-level, sending BUSY"
					"status.\n", mvi->instance);
				}
				mvst_send_busy(mvi, slot);
			}
		}
		break;

	default:
		mv_printk("mvst tgt(%ld): Received unknown frame "
		     "type %x.\n", mvi->instance, ssp_hdr->frame_type);
		break;

	}

	mvst_restart_free_list(mvi, slot_idx);

out:
	TRACE_EXIT();
	return rc;
}

static void mvst_register_tgt_handler(struct mvs_info *mvi)
{
	struct mvst_tgt *tgt = NULL;
	unsigned long flags = 0;

	tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
	if (tgt == NULL)
		return;

	tgt->mvi = mvi;
	INIT_LIST_HEAD(&tgt->sess_list);
	init_waitqueue_head(&tgt->waitQ);

	tgt->scst_tgt = scst_register_target(&tgt_template, MVST_NAME);
	if (!tgt->scst_tgt) {
		PRINT_ERROR("mvst tgt(%ld): scst_register_target() "
			    "failed for host %ld(%p)", mvi->instance,
			    mvi->host_no, mvi);
		kfree(tgt);
		return;
	}

	scst_tgt_set_sg_tablesize(tgt->scst_tgt, MVS_MAX_SG);
	scst_tgt_set_tgt_priv(tgt->scst_tgt, tgt);

	spin_lock_irqsave(&mvi->lock, flags);
	mvi->tgt = tgt;
	spin_unlock_irqrestore(&mvi->lock, flags);

	TRACE_DBG("Enable lun for host %ld(%ld,%p)",
		  mvi->host_no, mvi->instance, mvi);
	mvi->flags |= MVF_TARGET_MODE_ENABLE;
}

static void mvst_unregister_tgt_handler(struct mvs_info *mvi)
{
	struct mvst_tgt *tgt = NULL;
	tgt = mvi->tgt;
	mvi->tgt = NULL; /* ensure no one gets in behind us */

	TRACE_DBG("Shutting down host %ld(%ld,%p)",
		  mvi->host_no, mvi->instance, mvi);
	scst_unregister_target(tgt->scst_tgt);
	mvi->flags &= ~MVF_TARGET_MODE_ENABLE;
	/*
	 * Free of tgt happens via callback mvst_target_release
	 * called from scst_unregister_target, so we shouldn't touch it again
	 */
	tgt = NULL;
}
static void mvst_enable_tgt_port(struct mvs_info *mvi, u8 phyid)
{
	struct mvs_phy *phy;
	struct asd_sas_phy *sas_phy;
	u8 id = 0;

#if 0
	u8 j = 0, i = 0
	/*enable all the phy within the same port*/
	for (id = 0, j = 0; id < mvi->chip->n_phy; id++) {
		if (mvi->tgt_port[id].wide_port_phymap & (1<<phyid)) {
			mv_printk("port %x phymap %x\n",
				id, mvi->tgt_port[id].wide_port_phymap);
			break;
		}
	}

	if (id == mvi->chip->n_phy) {
		mvst_start_sas_target(mvi, phyid);
		msleep(100);
		MVS_CHIP_DISP->enable_target_mode(mvi, phyid);
		phy = &mvi->phy[phyid];
		phy->phy_mode = 1;
		sas_phy = &phy->sas_phy;
		sas_phy->tproto = SAS_PROTOCOL_SSP;
	} else {
		for_each_phy(mvi->tgt_port[id].wide_port_phymap, j, i) {
			if (j & 1) {
				mvst_start_sas_target(mvi, i);
				msleep(100);
				mv_printk("set phy %x to target mode\n", i);
				MVS_CHIP_DISP->enable_target_mode(mvi, i);
				phy = &mvi->phy[i];
				phy->phy_mode = 1;
				sas_phy = &phy->sas_phy;
				sas_phy->tproto = SAS_PROTOCOL_SSP;
			}
		}
	}
#else
	phy = &mvi->phy[phyid];
	for (id = 0; id < mvi->chip->n_phy; id++) {
		if (mvi->phy[id].dev_sas_addr == phy->dev_sas_addr) {
			mvst_start_sas_target(mvi, id);
			msleep(100);
			mv_printk("set phy %x to target mode\n", id);
			MVS_CHIP_DISP->enable_target_mode(mvi, id);
			mvi->phy[id].phy_mode = 1;
			sas_phy = &phy->sas_phy;
			sas_phy->tproto = SAS_PROTOCOL_SSP;
		}
	}
#endif
}

static void mvst_disable_tgt_port(struct mvs_info *mvi, u8 phyid)
{
	struct mvs_phy *phy;
	struct asd_sas_phy *sas_phy;
	u8 id = 0;
#if	0
	u8 j = 0, i = 0
	for (id = 0, j = 0; id < mvi->chip->n_phy; id++) {
		if (mvi->tgt_port[id].wide_port_phymap & (1<<phyid)) {
			mv_printk("port %x phymap %x\n", phyid,
				mvi->tgt_port[id].wide_port_phymap);
			break;
		}
	}
	if (id == mvi->chip->n_phy) {
		MVS_CHIP_DISP->disable_target_mode(mvi, phyid);
		msleep(100);
		mv_printk("reset PHY[%d] to notify iniator\n", phyid);
		MVS_CHIP_DISP->phy_reset(mvi, phyid, 0);
		phy = &mvi->phy[phyid];
		phy->phy_mode = 0;
		sas_phy = &phy->sas_phy;
		sas_phy->tproto = 0;
	} else {
		mv_printk("get port %x\n", id);
		for_each_phy(mvi->tgt_port[id].wide_port_phymap, j, i) {
			mv_printk("phy map %x get phy %x\n",
				mvi->tgt_port[id].wide_port_phymap, i);
			if (j & 1) {
				MVS_CHIP_DISP->disable_target_mode(mvi, i);
				msleep(100);
				MVS_CHIP_DISP->phy_reset(mvi, i, 0);
				phy = &mvi->phy[i];
				phy->phy_mode = 0;
				sas_phy = &phy->sas_phy;
				sas_phy->tproto = 0;
			}
		}
	}
#else
	phy = &mvi->phy[phyid];
	for (id = 0; id < mvi->chip->n_phy; id++) {
		if (mvi->phy[id].dev_sas_addr == phy->dev_sas_addr) {
			MVS_CHIP_DISP->disable_target_mode(mvi, id);
			msleep(100);
			mv_printk("reset PHY[%d] to notify iniator\n", id);
			MVS_CHIP_DISP->phy_reset(mvi, id, 0);
			phy = &mvi->phy[id];
			phy->phy_mode = 0;
			sas_phy = &phy->sas_phy;
			sas_phy->tproto = 0;
		}
	}
#endif
}

/* no lock held on entry */
/* called via callback from mvst */
static void mvst_host_action(struct mvs_info *mvi,
			    enum mvst_tgt_host_action_t action, u8 phyid)
{
	struct mvs_phy *phy;
	struct asd_sas_phy *sas_phy;
	struct mvst_tgt *tgt = NULL;
	int phy_id = 0, target_port = 0;

	TRACE_ENTRY();

	sBUG_ON(mvi == NULL);

	switch (action) {
	case ENABLE_TARGET_MODE:
		if (mvi->phy[phyid].phy_mode == 1)
			break;
		if (!MVST_IN_TARGET_MODE(mvi))
			mvst_register_tgt_handler(mvi);

		target_port++;
		mv_dprintk("initiator attaching %016llx,map %x on port[%d]\n",
			(mvi->tgt_port[target_port].sas_addr),
			mvi->tgt_port[target_port].wide_port_phymap,
			target_port);
		if (target_port * (MVS_CHIP_SLOT_SZ/mvi->chip->n_phy)
			> MVS_CHIP_SLOT_SZ) {
			mv_dprintk("Warning: No sufficient slots"
				"for target port[%d].\n", target_port);
			break;
		}

		mvst_enable_tgt_port(mvi, phyid);
		mvst_notify_attach_chg();

		mv_dprintk("Enable target mode......\n");
		break;

	case DISABLE_TARGET_MODE:
		if (mvi->phy[phyid].phy_mode == 0)
			break;
		if (mvi->flags & MVF_TARGET_MODE_ENABLE) {
			mvst_disable_tgt_port(mvi, phyid);
			for (phy_id = 0; phy_id < mvi->chip->n_phy; phy_id++) {
				if (mvi->phy[phy_id].dev_info
					& PORT_DEV_SSP_TRGT)
					break;
			}
			if (phy_id == mvi->chip->n_phy) {
				if (mvi->tgt == NULL)
					goto out;
				mvst_unregister_tgt_handler(mvi);
			}
		}
		mv_dprintk("Disable target mode.....\n");
		break;

	case EXIT_TARGET_MODE:
		for (phy_id = 0; phy_id < mvi->chip->n_phy; phy_id++) {
			if (mvi->phy[phy_id].dev_info & PORT_DEV_SSP_TRGT) {
				MVS_CHIP_DISP->disable_target_mode(mvi, phy_id);
				msleep(100);
				mv_dprintk("reset phy%d to notify init\n",
					phy_id);
				MVS_CHIP_DISP->phy_reset(mvi, phy_id, 0);
				phy = &mvi->phy[phy_id];
				phy->phy_mode = 0;
				sas_phy = &phy->sas_phy;
				sas_phy->tproto = 0;
			}
		}
		if (mvi->tgt == NULL)
			goto out;

		tgt = mvi->tgt;
		mvi->tgt = NULL; /* ensure no one gets in behind us */

		TRACE_DBG("Shutting down host %ld(%ld,%p)",
			  mvi->host_no, mvi->instance, mvi);
		scst_unregister_target(tgt->scst_tgt);
		mvi->flags &= ~MVF_TARGET_MODE_ENABLE;
		/*
		 * Free of tgt happens via callback mvst_target_release
		 * called from scst_unregister_target, so we shouldn't touch
		 * it again
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

#define MVST_PROC_LOG_ENTRY_NAME     "trace_level"

#include <linux/proc_fs.h>

static int mvst_log_info_show(struct seq_file *seq, void *v)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_read(seq, trace_flag, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t mvst_proc_log_entry_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, &trace_flag,
		MVST_DEFAULT_LOG_FLAGS, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data mvst_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(mvst_proc_log_entry_write)
	.show = mvst_log_info_show,
};
#endif

static int mvs_prep_sspt_frame(struct mvs_info *mvi,
				struct mvs_slot_info *slot)
{
	struct mvs_cmd_header *cmd_hdr;
	struct mvst_port *port = slot->slot_tgt_port;
	void *buf_tmp;
	dma_addr_t buf_tmp_dma;
	u32  tag = slot->target_cmd_tag;
	struct mvs_delivery_queue *delivery_q;

	/* get free command header */
	cmd_hdr = (struct mvs_cmd_header *)&mvi->slot[tag];
	/* get free delivery queue */
	delivery_q = (struct mvs_delivery_queue *)&mvi->tx[mvi->tx_prod];

	/* target mode, SSP target free list */
	delivery_q->cmd = TXQ_CMD_SSP_FREE_LIST;
	delivery_q->mode = TXQ_MODE_TARGET;
	delivery_q->priority = TXQ_PRI_NORMAL;
	delivery_q->sata_reg_set = 0;
	delivery_q->phy = port->wide_port_phymap;
	delivery_q->slot_nm = tag;

	/* command header dword 2 */
	/* copy the tag from received command frame */
	cmd_hdr->target_tag = tag;
	cmd_hdr->tag =  0;

	/* command header dword 3 */
	cmd_hdr->data_len = 0;

	/* region 1: open address frame area (MVS_OAF_SZ bytes)  */
	buf_tmp  = slot->open_frame = slot->buf;
	buf_tmp_dma = slot->buf_dma;
	cmd_hdr->open_frame = cpu_to_le64(buf_tmp_dma);

	buf_tmp += MVS_OAF_SZ;
	buf_tmp_dma += MVS_OAF_SZ;

	/* region 2: status buffer (lMVS_SLOT_BUF_SZ -  MVS_OAF_SZ) */
	slot->response = buf_tmp;
	cmd_hdr->status_buf = cpu_to_le64(buf_tmp_dma);

	/* command header dword 1 */
	cmd_hdr->max_rsp_frame_len =
		(min(SB_RFB_MAX, MVS_SLOT_BUF_SZ - MVS_OAF_SZ)) >> 2;
	cmd_hdr->frame_len =  0;
	return 0;
}


static int
mvst_restart_free_list(struct mvs_info *mvi, u8 slot_id)
{
	struct mvs_slot_info *slot;
	u32 rc = 0, tag = 0;
	u32 pass = 0;

	tag = slot_id;
	mvs_tag_set(mvi, tag);
	slot = &mvi->slot_info[tag];
	memset(slot->buf, 0, MVS_SLOT_BUF_SZ);
	/* save free tag */
	slot->slot_scst_cmd = NULL;
	slot->open_frame = NULL;
	slot->tx = mvi->tx_prod;
	rc = mvs_prep_sspt_frame(mvi, slot);
	if (rc)
		goto err_out_tag;

	++pass;
	mvi->tx_prod = (mvi->tx_prod + 1) & (MVS_CHIP_SLOT_SZ - 1);
	goto out_done;

err_out_tag:
	PRINT_ERROR("prepare SSPT[%d] failed.", slot_id);
	mvst_put_slot(mvi, slot);

out_done:
	if (pass)
		MVS_CHIP_DISP->start_delivery(mvi,
				(mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));
	return rc;
}

static int
mvst_start_sas_target(struct mvs_info *mvi, u8 id)
{
	struct mvs_slot_info *slot;
	struct mvst_port *tgt_port = &mvi->tgt_port[id];
	u32 rc = 0;
	unsigned long flags;
	u32 pass = 0;
	u32 slot_id = 0;

	spin_lock_irqsave(&mvi->lock, flags);
	do {
		slot = mvst_get_slot(mvi, tgt_port);
		if (!slot)
			goto err_out;
		slot->slot_scst_cmd = NULL;
		rc = mvs_prep_sspt_frame(mvi, slot);
		if (rc)
			goto err_out_tag;
		++pass;
		mvi->tx_prod = (mvi->tx_prod + 1) & (MVS_CHIP_SLOT_SZ - 1);
	} while (++slot_id < MVS_TARGET_QUEUE);
	rc = 0;
	goto out_done;

err_out_tag:
	PRINT_ERROR("prepare SSPT[%d] failed.", slot_id);
	mvst_put_slot(mvi, slot);
err_out:
	PRINT_ERROR("No sufficient tag for SSPT, current slot=%d", slot_id);

out_done:
	if (pass)
		MVS_CHIP_DISP->start_delivery(mvi,
			(mvi->tx_prod - 1) & (MVS_CHIP_SLOT_SZ - 1));

	spin_unlock_irqrestore(&mvi->lock, flags);
	return rc;
}

void mvst_init_port(struct mvs_info *mvi)
{
	int i;
	for (i = 0; i < mvi->chip->n_phy; i++) {
		mvi->tgt_port[i].port_id = i;
		mvi->tgt_port[i].wide_port_phymap = 1<<i;
		mvi->tgt_port[i].port_attached = 0;
		mvi->tgt_port[i].mvi = mvi;
		mvi->tgt_port[i].phy = &mvi->phy[i];
		INIT_LIST_HEAD(&mvi->tgt_port[i].slot_list);
	}
}

void mvst_update_wideport(struct mvs_info *mvi, int phy_no)
{
	u8 i, j, member = 0;
	u32 wide_port;

	for (i = 0; i < mvi->chip->n_phy; i++) {
		if (phy_no == i)
			continue;

		if ((mvi->phy[phy_no].att_dev_sas_addr ==
			mvi->tgt_port[i].att_sas_addr) &&
			(mvi->phy[phy_no].dev_sas_addr ==
			mvi->tgt_port[i].sas_addr)) {
			mvi->tgt_port[i].wide_port_phymap |= (1U << phy_no);
			mvi->tgt_port[phy_no].wide_port_phymap = 0;
			mvi->tgt_port[phy_no].port_attached = 0;
			mvi->tgt_port[phy_no].sas_addr = 0;
			member = 1;
		}
	}
	if (!member) {
		mvi->tgt_port[phy_no].wide_port_phymap |= (1U << phy_no);
		mvi->tgt_port[phy_no].port_attached = 1;
		mvi->tgt_port[phy_no].sas_addr = mvi->phy[phy_no].dev_sas_addr;
		mvi->tgt_port[phy_no].att_sas_addr =
			mvi->phy[phy_no].att_dev_sas_addr;
	}

	/* config wideport */
	for (i = 0; i < mvi->chip->n_phy; i++) {
		wide_port = mvi->tgt_port[i].wide_port_phymap;
		if (wide_port == 0)
			continue;
		for (j = i+1; j < mvi->chip->n_phy; j++) {
			wide_port = wide_port >> j;
			if (wide_port & 1) {
				MVS_CHIP_DISP->write_port_cfg_addr(mvi, j,
					PHYR_WIDE_PORT);
				MVS_CHIP_DISP->write_port_cfg_data(mvi, j,
					mvi->tgt_port[i].wide_port_phymap);
			} else {
				MVS_CHIP_DISP->write_port_cfg_addr(mvi, j,
					PHYR_WIDE_PORT);
				MVS_CHIP_DISP->write_port_cfg_data(mvi, j,
					0);
			}
		}
	}

}


void mvst_int_port(struct mvs_info *mvi, u32 id)
{
	struct mvst_port *tgt_port = &mvi->tgt_port[id];
	struct mvs_phy *phy = &mvi->phy[id];

	phy->irq_status = mvs_read_port_irq_stat(mvi, id);
	/* clean status */
	mvs_write_port_irq_stat(mvi, id, phy->irq_status);

	/*
	* events is port event now ,
	* we need check the interrupt status which belongs to per port.
	*/
	if (phy->irq_status & PHYEV_RDY_CH) {
		u32 tmp;
		mv_dprintk("Port %d phy change!!\n", id);
		tmp = mvs_read_phy_ctl(mvi, id);
		if (tmp & PHY_READY_MASK) {
			PRINT_INFO("Find port %d phy ready.\n", id);
			tgt_port->port_attached = 1;
			mvs_update_phyinfo(mvi, id, 0);
		} else
			PRINT_INFO("Port %d Unplug Notice!!\n", id);
	}

	if (phy->irq_status &  PHYEV_DEC_ERR)
		mv_dprintk("Port %d phy decoding error!!\n", id);
	else if (phy->irq_status & PHYEV_COMWAKE)
		mv_dprintk("Port %d COMWAKE received.\n", id);
	else if (phy->irq_status & PHYEV_SIG_FIS)
		mv_dprintk("Port %d Signature FIS received.\n", id);
	else
		mv_dprintk("Port %d unknown error[0x%x]"
		"received.\n", id, phy->irq_status);
}

u32 mvst_check_port(struct mvs_info *mvi, u8 phy_id)
{
	u32 att_dev_info;
	u32 port_attr;
	att_dev_info = mvi->phy[phy_id].att_dev_info;

	if ((att_dev_info & PORT_SSP_INIT_MASK ||
		att_dev_info & PORT_DEV_SMP_TRGT ||
		att_dev_info & PORT_DEV_SMP_INIT) &&
		!(att_dev_info & PORT_SSP_TRGT_MASK))
		port_attr = MVST_TGT_PORT;
	else if ((att_dev_info & PORT_SSP_INIT_MASK ||
		 att_dev_info & PORT_DEV_SMP_TRGT ||
		 att_dev_info & PORT_DEV_SMP_INIT) &&
		 (att_dev_info & PORT_SSP_TRGT_MASK))
		port_attr =  MVST_INIT_TGT_PORT;
	else
		port_attr =  MVST_INIT_PORT;

	return	port_attr;
}

static int mvst_proc_log_entry_build(struct scst_tgt_template *templ)
{
	int res = 0;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
		/* create the proc file entry for the device */
		mvst_log_proc_data.data = (void *)templ->name;
		p = scst_create_proc_entry(root, MVST_PROC_LOG_ENTRY_NAME,
					&mvst_log_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register "
			     "target driver %s entry %s in /proc",
			      templ->name, MVST_PROC_LOG_ENTRY_NAME);
			res = -ENOMEM;
			goto out;
		}
	}

out:

	TRACE_EXIT_RES(res);
#endif
	return res;
}

static void mvst_proc_log_entry_clean(struct scst_tgt_template *templ)
{
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root)
		remove_proc_entry(MVST_PROC_LOG_ENTRY_NAME, root);

	TRACE_EXIT();
#endif
	return;
}

int mvs_tgt_register_driver(struct mvs_tgt_initiator *tgt_data)
{
	int res = 0;

	ENTER(__func__);

	if ((tgt_data == NULL) || (tgt_data->magic != MVST_TARGET_MAGIC)) {
		mv_dprintk("***ERROR*** Wrong version of"
			"the target driver: %d\n", tgt_data->magic);
		res = -EINVAL;
		goto out;
	}
	memcpy(&mvs_tgt, tgt_data, sizeof(mvs_tgt));
out:
	LEAVE(__func__);
	return res;
}

static void mvs_tgt_unregister_driver(void)
{
	ENTER(__func__);
	memset(&mvs_tgt, 0, sizeof(mvs_tgt));
	LEAVE(__func__);
	return;
}

void mvst_init_tgt_port(struct mvs_info *mvi)
{
	INIT_LIST_HEAD(&mvi->data_cmd_list);
	mvst_init_port(mvi);
}

int  mvst_init(void)
{
	int res = 0;
	TRACE_ENTRY();
	mvst_cmd_cachep = KMEM_CACHE(mvst_cmd, SCST_SLAB_FLAGS);
	if (mvst_cmd_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = scst_register_target_template(&tgt_template);
	if (res < 0)
		goto out_free_kmem;

	/*
	 * mvst_tgt_register_driver() happens in mv_target_detect
	 * called via scst_register_target_template()
	 */

	res = mvst_proc_log_entry_build(&tgt_template);
	if (res < 0)
		goto out_unreg_target;

out:
	TRACE_EXIT();
	return res;

out_unreg_target:
	scst_unregister_target_template(&tgt_template);

out_free_kmem:
	kmem_cache_destroy(mvst_cmd_cachep);

	mvs_tgt_unregister_driver();
	goto out;
}

void  mvst_exit(void)
{
	TRACE_ENTRY();

	/*mvst_shutdown_queue(&tgt_msg_queue);*/
	mvst_proc_log_entry_clean(&tgt_template);
	scst_unregister_target_template(&tgt_template);
	mvs_tgt_unregister_driver();
	kmem_cache_destroy(mvst_cmd_cachep);

	TRACE_EXIT();
	return;
}

#endif
