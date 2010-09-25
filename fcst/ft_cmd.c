/*
 * Copyright (c) 2010 Cisco Systems, Inc.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <scsi/libfc.h>
#include <scsi/fc_encode.h>
#include "fcst.h"

/*
 * Append string to buffer safely.
 * Also prepends a space if there's already something the buf.
 */
static void ft_cmd_flag(char *buf, size_t len, const char *desc)
{
	if (buf[0])
		strlcat(buf, " ", len);
	strlcat(buf, desc, len);
}

/*
 * Debug: dump command.
 */
void ft_cmd_dump(struct scst_cmd *cmd, const char *caller)
{
	static atomic_t serial;
	struct ft_cmd *fcmd;
	struct fc_exch *ep;
	char prefix[30];
	char buf[150];

	if (!(ft_debug_logging & FT_DEBUG_IO))
		return;

	fcmd = scst_cmd_get_tgt_priv(cmd);
	ep = fc_seq_exch(fcmd->seq);
	snprintf(prefix, sizeof(prefix), FT_MODULE ": cmd %2x",
		atomic_inc_return(&serial) & 0xff);

	printk(KERN_INFO "%s %s oid %x oxid %x resp_len %u\n",
		prefix, caller, ep->oid, ep->oxid,
		scst_cmd_get_resp_data_len(cmd));
	printk(KERN_INFO "%s scst_cmd %p wlen %u rlen %u\n",
		prefix, cmd, fcmd->write_data_len, fcmd->read_data_len);
	printk(KERN_INFO "%s exp_dir %x exp_xfer_len %d exp_in_len %d\n",
		prefix, cmd->expected_data_direction,
		cmd->expected_transfer_len, cmd->expected_out_transfer_len);
	printk(KERN_INFO "%s dir %x data_len %d bufflen %d out_bufflen %d\n",
		prefix, cmd->data_direction, cmd->data_len,
		cmd->bufflen, cmd->out_bufflen);
	printk(KERN_INFO "%s sg_cnt reg %d in %d tgt %d tgt_in %d\n",
		prefix, cmd->sg_cnt, cmd->out_sg_cnt,
		cmd->tgt_sg_cnt, cmd->tgt_out_sg_cnt);

	buf[0] = '\0';
	if (cmd->sent_for_exec)
		ft_cmd_flag(buf, sizeof(buf), "sent");
	if (cmd->completed)
		ft_cmd_flag(buf, sizeof(buf), "comp");
	if (cmd->ua_ignore)
		ft_cmd_flag(buf, sizeof(buf), "ua_ign");
	if (cmd->atomic)
		ft_cmd_flag(buf, sizeof(buf), "atom");
	if (cmd->double_ua_possible)
		ft_cmd_flag(buf, sizeof(buf), "dbl_ua_poss");
	if (cmd->is_send_status)
		ft_cmd_flag(buf, sizeof(buf), "send_stat");
	if (cmd->retry)
		ft_cmd_flag(buf, sizeof(buf), "retry");
	if (cmd->internal)
		ft_cmd_flag(buf, sizeof(buf), "internal");
	if (cmd->unblock_dev)
		ft_cmd_flag(buf, sizeof(buf), "unblock_dev");
	if (cmd->cmd_hw_pending)
		ft_cmd_flag(buf, sizeof(buf), "hw_pend");
	if (cmd->tgt_need_alloc_data_buf)
		ft_cmd_flag(buf, sizeof(buf), "tgt_need_alloc");
	if (cmd->tgt_data_buf_alloced)
		ft_cmd_flag(buf, sizeof(buf), "tgt_alloced");
	if (cmd->dh_data_buf_alloced)
		ft_cmd_flag(buf, sizeof(buf), "dh_alloced");
	if (cmd->expected_values_set)
		ft_cmd_flag(buf, sizeof(buf), "exp_val");
	if (cmd->sg_buff_modified)
		ft_cmd_flag(buf, sizeof(buf), "sg_buf_mod");
	if (cmd->preprocessing_only)
		ft_cmd_flag(buf, sizeof(buf), "pre_only");
	if (cmd->sn_set)
		ft_cmd_flag(buf, sizeof(buf), "sn_set");
	if (cmd->hq_cmd_inced)
		ft_cmd_flag(buf, sizeof(buf), "hq_cmd_inc");
	if (cmd->set_sn_on_restart_cmd)
		ft_cmd_flag(buf, sizeof(buf), "set_sn_on_restart");
	if (cmd->no_sgv)
		ft_cmd_flag(buf, sizeof(buf), "no_sgv");
	if (cmd->may_need_dma_sync)
		ft_cmd_flag(buf, sizeof(buf), "dma_sync");
	if (cmd->out_of_sn)
		ft_cmd_flag(buf, sizeof(buf), "oo_sn");
	if (cmd->inc_expected_sn_on_done)
		ft_cmd_flag(buf, sizeof(buf), "inc_sn_exp");
	if (cmd->done)
		ft_cmd_flag(buf, sizeof(buf), "done");
	if (cmd->finished)
		ft_cmd_flag(buf, sizeof(buf), "fin");

	printk(KERN_INFO "%s flags %s\n", prefix, buf);
	printk(KERN_INFO "%s lun %lld sn %d tag %lld cmd_flags %lx\n",
		prefix, cmd->lun, cmd->sn, cmd->tag, cmd->cmd_flags);
	printk(KERN_INFO "%s tgt_sn %d op_flags %x op %s\n",
		prefix, cmd->tgt_sn, cmd->op_flags, cmd->op_name);
	printk(KERN_INFO "%s status %x msg_status %x "
		"host_status %x driver_status %x\n",
		prefix, cmd->status, cmd->msg_status,
		cmd->host_status, cmd->driver_status);
	printk(KERN_INFO "%s cdb_len %d ext_cdb_len %u\n",
		prefix, cmd->cdb_len, cmd->ext_cdb_len);
	snprintf(buf, sizeof(buf), "%s cdb ", prefix);
	print_hex_dump(KERN_INFO, buf, DUMP_PREFIX_NONE,
		16, 4, cmd->cdb, SCST_MAX_CDB_SIZE, 0);
}

/*
 * Debug: dump mgmt command.
 */
static void ft_cmd_tm_dump(struct scst_mgmt_cmd *mcmd, const char *caller)
{
	struct ft_cmd *fcmd;
	struct fc_exch *ep;
	char prefix[30];
	char buf[150];

	if (!(ft_debug_logging & FT_DEBUG_IO))
		return;
	fcmd = scst_mgmt_cmd_get_tgt_priv(mcmd);
	ep = fc_seq_exch(fcmd->seq);

	snprintf(prefix, sizeof(prefix), FT_MODULE ": mcmd");

	printk(KERN_INFO "%s %s oid %x oxid %x lun %lld\n",
		prefix, caller, ep->oid, ep->oxid,
		(unsigned long long)mcmd->lun);
	printk(KERN_INFO "%s state %d fn %d fin_wait %d done_wait %d comp %d\n",
		prefix, mcmd->state, mcmd->fn,
		mcmd->cmd_finish_wait_count, mcmd->cmd_done_wait_count,
		mcmd->completed_cmd_count);
	buf[0] = '\0';
	if (mcmd->needs_unblocking)
		ft_cmd_flag(buf, sizeof(buf), "needs_unblock");
	if (mcmd->lun_set)
		ft_cmd_flag(buf, sizeof(buf), "lun_set");
	if (mcmd->cmd_sn_set)
		ft_cmd_flag(buf, sizeof(buf), "cmd_sn_set");
	printk(KERN_INFO "%s flags %s\n", prefix, buf);
	if (mcmd->cmd_to_abort)
		ft_cmd_dump(mcmd->cmd_to_abort, caller);
}

/*
 * Free command.
 */
void ft_cmd_free(struct scst_cmd *cmd)
{
	struct ft_cmd *fcmd;

	fcmd = scst_cmd_get_tgt_priv(cmd);
	if (fcmd) {
		scst_cmd_set_tgt_priv(cmd, NULL);
		fc_frame_free(fcmd->req_frame);
		kfree(fcmd);
	}
}

/*
 * Send response, after data if applicable.
 */
int ft_send_response(struct scst_cmd *cmd)
{
	struct ft_cmd *fcmd;
	struct fc_frame *fp;
	struct fcp_resp_with_ext *fcp;
	struct fc_lport *lport;
	struct fc_exch *ep;
	unsigned int slen;
	size_t len;
	int resid = 0;
	int bi_resid = 0;
	int error;
	int dir;
	u32 status;

	ft_cmd_dump(cmd, __func__);
	fcmd = scst_cmd_get_tgt_priv(cmd);
	ep = fc_seq_exch(fcmd->seq);
	lport = ep->lp;

	if (scst_cmd_aborted(cmd)) {
		FT_IO_DBG("cmd aborted did %x oxid %x\n", ep->did, ep->oxid);
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_ABORTED);
		goto done;
	}

	if (!scst_cmd_get_is_send_status(cmd)) {
		FT_IO_DBG("send status not set.  feature not implemented\n");
		return SCST_TGT_RES_FATAL_ERROR;
	}

	status = scst_cmd_get_status(cmd);
	dir = scst_cmd_get_data_direction(cmd);

	slen = scst_cmd_get_sense_buffer_len(cmd);
	len = sizeof(*fcp) + slen;

	/*
	 * Send read data and set underflow/overflow residual count.
	 * For bi-directional comands, the bi_resid is for the read direction.
	 */
	if (dir & SCST_DATA_WRITE)
		resid = (signed)scst_cmd_get_bufflen(cmd) -
			fcmd->write_data_len;
	if (dir & SCST_DATA_READ) {
		error = ft_send_read_data(cmd);
		if (error) {
			FT_ERR("ft_send_read_data returned %d\n", error);
			return error;
		}

		if (dir == SCST_DATA_BIDI) {
			bi_resid = (signed)scst_cmd_get_out_bufflen(cmd) -
				   scst_cmd_get_resp_data_len(cmd);
			if (bi_resid)
				len += sizeof(__be32);
		} else
			resid = (signed)scst_cmd_get_bufflen(cmd) -
				scst_cmd_get_resp_data_len(cmd);
	}

	fp = fc_frame_alloc(lport, len);
	if (!fp)
		return SCST_TGT_RES_QUEUE_FULL;

	fcp = fc_frame_payload_get(fp, len);
	memset(fcp, 0, sizeof(*fcp));
	fcp->resp.fr_status = status;

	if (slen) {
		fcp->resp.fr_flags |= FCP_SNS_LEN_VAL;
		fcp->ext.fr_sns_len = htonl(slen);
		memcpy(fcp + 1, scst_cmd_get_sense_buffer(cmd), slen);
	}
	if (bi_resid) {
		if (bi_resid < 0) {
			fcp->resp.fr_flags |= FCP_BIDI_READ_OVER;
			bi_resid = -bi_resid;
		} else
			fcp->resp.fr_flags |= FCP_BIDI_READ_UNDER;
		*(__be32 *)((u8 *)(fcp + 1) + slen) = htonl(bi_resid);
	}
	if (resid) {
		if (resid < 0) {
			resid = -resid;
			fcp->resp.fr_flags |= FCP_RESID_OVER;
		} else
			fcp->resp.fr_flags |= FCP_RESID_UNDER;
		fcp->ext.fr_resid = htonl(resid);
	}
	FT_IO_DBG("response did %x oxid %x\n", ep->did, ep->oxid);

	/*
	 * Send response.
	 */
	fcmd->seq = lport->tt.seq_start_next(fcmd->seq);
	fc_fill_fc_hdr(fp, FC_RCTL_DD_CMD_STATUS, ep->did, ep->sid, FC_TYPE_FCP,
		       FC_FC_EX_CTX | FC_FC_LAST_SEQ | FC_FC_END_SEQ, 0);

	lport->tt.seq_send(lport, fcmd->seq, fp);
done:
	lport->tt.exch_done(fcmd->seq);
	scst_tgt_cmd_done(cmd, SCST_CONTEXT_SAME);
	return SCST_TGT_RES_SUCCESS;
}

/*
 * FC sequence response handler for follow-on sequences (data) and aborts.
 */
static void ft_recv_seq(struct fc_seq *sp, struct fc_frame *fp, void *arg)
{
	struct scst_cmd *cmd = arg;
	struct fc_frame_header *fh;

	/*
	 * If an error is being reported, it must be FC_EX_CLOSED.
	 * Timeouts don't occur on incoming requests, and there are
	 * currently no other errors.
	 * The PRLO handler will be also called by libfc to delete
	 * the session and all pending commands, so we ignore this response.
	 */
	if (IS_ERR(fp)) {
		FT_IO_DBG("exchange error %ld - not handled\n", -PTR_ERR(fp));
		return;
	}

	fh = fc_frame_header_get(fp);
	switch (fh->fh_r_ctl) {
	case FC_RCTL_DD_SOL_DATA:	/* write data */
		ft_recv_write_data(cmd, fp);
		break;
	case FC_RCTL_DD_UNSOL_CTL:	/* command */
	case FC_RCTL_DD_SOL_CTL:	/* transfer ready */
	case FC_RCTL_DD_DATA_DESC:	/* transfer ready */
	default:
		printk(KERN_INFO "%s: unhandled frame r_ctl %x\n",
		       __func__, fh->fh_r_ctl);
		fc_frame_free(fp);
		break;
	}
}

/*
 * Command timeout.
 * SCST calls this when the command has taken too long in the device handler.
 */
void ft_cmd_timeout(struct scst_cmd *cmd)
{
	FT_IO_DBG("timeout not implemented\n");	/* XXX TBD */
}

/*
 * Send TX_RDY (transfer ready).
 */
static int ft_send_xfer_rdy_off(struct scst_cmd *cmd, u32 offset, u32 len)
{
	struct ft_cmd *fcmd;
	struct fc_frame *fp;
	struct fcp_txrdy *txrdy;
	struct fc_lport *lport;
	struct fc_exch *ep;

	fcmd = scst_cmd_get_tgt_priv(cmd);
	if (fcmd->xfer_rdy_len < len + offset)
		fcmd->xfer_rdy_len = len + offset;

	ep = fc_seq_exch(fcmd->seq);
	lport = ep->lp;
	fp = fc_frame_alloc(lport, sizeof(*txrdy));
	if (!fp)
		return SCST_TGT_RES_QUEUE_FULL;

	txrdy = fc_frame_payload_get(fp, sizeof(*txrdy));
	memset(txrdy, 0, sizeof(*txrdy));
	txrdy->ft_data_ro = htonl(offset);
	txrdy->ft_burst_len = htonl(len);

	fcmd->seq = lport->tt.seq_start_next(fcmd->seq);
	fc_fill_fc_hdr(fp, FC_RCTL_DD_DATA_DESC, ep->did, ep->sid, FC_TYPE_FCP,
		       FC_FC_EX_CTX | FC_FC_END_SEQ | FC_FC_SEQ_INIT, 0);
	lport->tt.seq_send(lport, fcmd->seq, fp);
	return SCST_TGT_RES_SUCCESS;
}

/*
 * Send TX_RDY (transfer ready).
 */
int ft_send_xfer_rdy(struct scst_cmd *cmd)
{
	return ft_send_xfer_rdy_off(cmd, 0, scst_cmd_get_bufflen(cmd));
}

/*
 * Send a FCP response including SCSI status and optional FCP rsp_code.
 * status is SAM_STAT_GOOD (zero) if code is valid.
 * This is used in error cases, such as allocation failures.
 */
static void ft_send_resp_status(struct fc_seq *sp, u32 status,
				enum fcp_resp_rsp_codes code)
{
	struct fc_frame *fp;
	size_t len;
	struct fcp_resp_with_ext *fcp;
	struct fcp_resp_rsp_info *info;
	struct fc_lport *lport;
	struct fc_exch *ep;

	ep = fc_seq_exch(sp);

	FT_IO_DBG("FCP error response: did %x oxid %x status %x code %x\n",
		  ep->did, ep->oxid, status, code);
	lport = ep->lp;
	len = sizeof(*fcp);
	if (status == SAM_STAT_GOOD)
		len += sizeof(*info);
	fp = fc_frame_alloc(lport, len);
	if (!fp)
		goto out;
	fcp = fc_frame_payload_get(fp, len);
	memset(fcp, 0, len);
	fcp->resp.fr_status = status;
	if (status == SAM_STAT_GOOD) {
		fcp->ext.fr_rsp_len = htonl(sizeof(*info));
		fcp->resp.fr_flags |= FCP_RSP_LEN_VAL;
		info = (struct fcp_resp_rsp_info *)(fcp + 1);
		info->rsp_code = code;
	}

	sp = lport->tt.seq_start_next(sp);
	fc_fill_fc_hdr(fp, FC_RCTL_DD_CMD_STATUS, ep->did, ep->sid, FC_TYPE_FCP,
		       FC_FC_EX_CTX | FC_FC_LAST_SEQ | FC_FC_END_SEQ, 0);

	lport->tt.seq_send(lport, sp, fp);
out:
	lport->tt.exch_done(sp);
}

/*
 * Send error or task management response.
 * Always frees the fcmd and associated state.
 */
static void ft_send_resp_code(struct ft_cmd *fcmd, enum fcp_resp_rsp_codes code)
{
	ft_send_resp_status(fcmd->seq, SAM_STAT_GOOD, code);
	fc_frame_free(fcmd->req_frame);
	kfree(fcmd);
}

void ft_cmd_tm_done(struct scst_mgmt_cmd *mcmd)
{
	struct ft_cmd *fcmd;
	enum fcp_resp_rsp_codes code;

	ft_cmd_tm_dump(mcmd, __func__);
	fcmd = scst_mgmt_cmd_get_tgt_priv(mcmd);
	switch (scst_mgmt_cmd_get_status(mcmd)) {
	case SCST_MGMT_STATUS_SUCCESS:
		code = FCP_TMF_CMPL;
		break;
	case SCST_MGMT_STATUS_REJECTED:
		code = FCP_TMF_REJECTED;
		break;
	case SCST_MGMT_STATUS_LUN_NOT_EXIST:
		code = FCP_TMF_INVALID_LUN;
		break;
	case SCST_MGMT_STATUS_TASK_NOT_EXIST:
	case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
	case SCST_MGMT_STATUS_FAILED:
	default:
		code = FCP_TMF_FAILED;
		break;
	}
	FT_IO_DBG("tm cmd done fn %d code %d\n", mcmd->fn, code);
	ft_send_resp_code(fcmd, code);
}

/*
 * Handle an incoming FCP task management command frame.
 * Note that this may be called directly from the softirq context.
 */
static void ft_recv_tm(struct scst_session *scst_sess,
		       struct ft_cmd *fcmd, struct fcp_cmnd *fcp)
{
	struct scst_rx_mgmt_params params;
	int ret;

	memset(&params, 0, sizeof(params));
	params.lun = fcp->fc_lun;
	params.lun_len = sizeof(fcp->fc_lun);
	params.lun_set = 1;
	params.atomic = SCST_ATOMIC;
	params.tgt_priv = fcmd;

	switch (fcp->fc_tm_flags) {
	case FCP_TMF_LUN_RESET:
		params.fn = SCST_LUN_RESET;
		break;
	case FCP_TMF_TGT_RESET:
		params.fn = SCST_TARGET_RESET;
		params.lun_set = 0;
		break;
	case FCP_TMF_CLR_TASK_SET:
		params.fn = SCST_CLEAR_TASK_SET;
		break;
	case FCP_TMF_ABT_TASK_SET:
		params.fn = SCST_ABORT_TASK_SET;
		break;
	case FCP_TMF_CLR_ACA:
		params.fn = SCST_CLEAR_ACA;
		break;
	default:
		/*
		 * FCP4r01 indicates having a combination of
		 * tm_flags set is invalid.
		 */
		FT_IO_DBG("invalid FCP tm_flags %x\n", fcp->fc_tm_flags);
		ft_send_resp_code(fcmd, FCP_CMND_FIELDS_INVALID);
		return;
	}
	FT_IO_DBG("submit tm cmd fn %d\n", params.fn);
	ret = scst_rx_mgmt_fn(scst_sess, &params);
	FT_IO_DBG("scst_rx_mgmt_fn ret %d\n", ret);
	if (ret)
		ft_send_resp_code(fcmd, FCP_TMF_FAILED);
}

/*
 * Handle an incoming FCP command frame.
 * Note that this may be called directly from the softirq context.
 */
static void ft_recv_cmd(struct ft_sess *sess, struct fc_seq *sp,
			struct fc_frame *fp)
{
	static atomic_t serial;
	struct scst_cmd *cmd;
	struct ft_cmd *fcmd;
	struct fcp_cmnd *fcp;
	struct fc_lport *lport;
	int data_dir;
	u32 data_len;
	int cdb_len;

	lport = fc_seq_exch(sp)->lp;
	fcmd = kzalloc(sizeof(*fcmd), GFP_ATOMIC);
	if (!fcmd)
		goto busy;
	fcmd->serial = atomic_inc_return(&serial);	/* debug only */
	fcmd->seq = sp;
	fcmd->max_payload = sess->max_payload;
	fcmd->max_lso_payload = sess->max_lso_payload;
	fcmd->req_frame = fp;

	fcp = fc_frame_payload_get(fp, sizeof(*fcp));
	if (!fcp)
		goto err;
	if (fcp->fc_tm_flags) {
		ft_recv_tm(sess->scst_sess, fcmd, fcp);
		return;
	}

	/*
	 * re-check length including specified CDB length.
	 * data_len is just after the CDB.
	 */
	cdb_len = fcp->fc_flags & FCP_CFL_LEN_MASK;
	fcp = fc_frame_payload_get(fp, sizeof(*fcp) + cdb_len);
	if (!fcp)
		goto err;
	cdb_len += sizeof(fcp->fc_cdb);
	data_len = ntohl(*(__be32 *)(fcp->fc_cdb + cdb_len));

	cmd = scst_rx_cmd(sess->scst_sess, fcp->fc_lun, sizeof(fcp->fc_lun),
			  fcp->fc_cdb, cdb_len, SCST_ATOMIC);
	if (!cmd) {
		kfree(fcmd);
		goto busy;
	}
	fcmd->scst_cmd = cmd;
	scst_cmd_set_tgt_priv(cmd, fcmd);

	switch (fcp->fc_flags & (FCP_CFL_RDDATA | FCP_CFL_WRDATA)) {
	case 0:
		data_dir = SCST_DATA_NONE;
		break;
	case FCP_CFL_RDDATA:
		data_dir = SCST_DATA_READ;
		break;
	case FCP_CFL_WRDATA:
		data_dir = SCST_DATA_WRITE;
		break;
	case FCP_CFL_RDDATA | FCP_CFL_WRDATA:
		data_dir = SCST_DATA_BIDI;
		break;
	}
	scst_cmd_set_expected(cmd, data_dir, data_len);

	switch (fcp->fc_pri_ta & FCP_PTA_MASK) {
	case FCP_PTA_SIMPLE:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case FCP_PTA_HEADQ:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case FCP_PTA_ACA:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_ACA);
		break;
	case FCP_PTA_ORDERED:
	default:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

	lport->tt.seq_set_resp(sp, ft_recv_seq, cmd);
	scst_cmd_init_done(cmd, SCST_CONTEXT_THREAD);
	return;

err:
	ft_send_resp_code(fcmd, FCP_CMND_FIELDS_INVALID);
	return;

busy:
	FT_IO_DBG("cmd allocation failure - sending BUSY\n");
	ft_send_resp_status(sp, SAM_STAT_BUSY, 0);
	fc_frame_free(fp);
}

/*
 * Send FCP ELS-4 Reject.
 */
static void ft_cmd_ls_rjt(struct fc_seq *sp, enum fc_els_rjt_reason reason,
			  enum fc_els_rjt_explan explan)
{
	struct fc_frame *fp;
	struct fc_els_ls_rjt *rjt;
	struct fc_lport *lport;
	struct fc_exch *ep;

	ep = fc_seq_exch(sp);
	lport = ep->lp;
	fp = fc_frame_alloc(lport, sizeof(*rjt));
	if (!fp)
		return;

	rjt = fc_frame_payload_get(fp, sizeof(*rjt));
	memset(rjt, 0, sizeof(*rjt));
	rjt->er_cmd = ELS_LS_RJT;
	rjt->er_reason = reason;
	rjt->er_explan = explan;

	sp = lport->tt.seq_start_next(sp);
	fc_fill_fc_hdr(fp, FC_RCTL_ELS_REP, ep->did, ep->sid, FC_TYPE_FCP,
		       FC_FC_EX_CTX | FC_FC_END_SEQ | FC_FC_LAST_SEQ, 0);
	lport->tt.seq_send(lport, sp, fp);
}

/*
 * Handle an incoming FCP ELS-4 command frame.
 * Note that this may be called directly from the softirq context.
 */
static void ft_recv_els4(struct ft_sess *sess, struct fc_seq *sp,
			 struct fc_frame *fp)
{
	u8 op = fc_frame_payload_op(fp);

	switch (op) {
	case ELS_SRR:			/* TBD */
	default:
		FT_IO_DBG("unsupported ELS-4 op %x\n", op);
		ft_cmd_ls_rjt(sp, ELS_RJT_INVAL, ELS_EXPL_NONE);
		fc_frame_free(fp);
		break;
	}
}

/*
 * Handle an incoming FCP frame.
 * Note that this may be called directly from the softirq context.
 */
void ft_recv_req(struct ft_sess *sess, struct fc_seq *sp, struct fc_frame *fp)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);

	switch (fh->fh_r_ctl) {
	case FC_RCTL_DD_UNSOL_CMD:
		ft_recv_cmd(sess, sp, fp);
		break;
	case FC_RCTL_ELS4_REQ:
		ft_recv_els4(sess, sp, fp);
		break;
	default:
		printk(KERN_INFO "%s: unhandled frame r_ctl %x\n",
		       __func__, fh->fh_r_ctl);
		fc_frame_free(fp);
		sess->tport->lport->tt.exch_done(sp);
		break;
	}
}
