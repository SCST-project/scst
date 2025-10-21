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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <scsi/libfc.h>
/*
 * See also upstream commit e31ac898ac29 ("scsi: libfc: Move scsi/fc_encode.h
 * to libfc"). That commit moved fc_fill_fc_hdr() from <scsi/fc_encode.h> into
 * <scsi/fc_frame.h>.
 */
#if defined(FC_FILL_FC_HDR_IN_SCSI_FC_ENCODE_H)
#include <scsi/fc_encode.h>
#else
#include <scsi/fc_frame.h>
#endif
#include "fcst.h"

/*
 * ft_set_cmd_state() - set the state of a command
 */
static enum ft_cmd_state ft_set_cmd_state(struct ft_cmd *fcmd,
					  enum ft_cmd_state new)
{
	enum ft_cmd_state previous;

	spin_lock(&fcmd->lock);
	previous = fcmd->state;
	if (previous != FT_STATE_DONE)
		fcmd->state = new;
	spin_unlock(&fcmd->lock);

	return previous;
}

/*
 * ft_test_and_set_cmd_state() - test and set the state of a command
 *
 * Returns true if and only if the previous command state was equal to 'old'.
 */
bool ft_test_and_set_cmd_state(struct ft_cmd *fcmd, enum ft_cmd_state old,
			       enum ft_cmd_state new)
{
	enum ft_cmd_state previous;

	WARN_ON(old == FT_STATE_DONE);
	WARN_ON(new == FT_STATE_NEW);

	spin_lock(&fcmd->lock);
	previous = fcmd->state;
	if (previous == old)
		fcmd->state = new;
	spin_unlock(&fcmd->lock);

	return previous == old;
}

static void ft_abort_cmd(struct scst_cmd *cmd)
{
	struct ft_cmd *fcmd = scst_cmd_get_tgt_priv(cmd);
	struct fc_seq *sp = fcmd->seq;
	struct fc_exch *ep = fc_seq_exch(sp);

	pr_err("%s: cmd %p ox_id %#x rx_id %#x state %d\n", __func__, cmd,
	       ep->oxid, ep->rxid, fcmd->state);

	spin_lock(&fcmd->lock);
	switch (fcmd->state) {
	case FT_STATE_NEW:
	case FT_STATE_DATA_IN:
	case FT_STATE_MGMT:
		/*
		 * Do nothing - defer abort processing until
		 * srpt_xmit_response() is invoked.
		 */
		break;
	case FT_STATE_NEED_DATA:
		/* SCST_DATA_WRITE */
		fcmd->state = FT_STATE_DATA_IN;
		scst_rx_data(cmd, SCST_RX_STATUS_ERROR_FATAL,
			     SCST_CONTEXT_THREAD);
		break;
	case FT_STATE_CMD_RSP_SENT:
		/*
		 * ft_send_response() is either in progress or has finished.
		 * Wait until the SCST core has invoked ft_cmd_done().
		 */
		break;
	case FT_STATE_MGMT_RSP_SENT:
	default:
		pr_info("Unexpected command state %d\n", fcmd->state);
		__WARN();
		fcmd->state = FT_STATE_DONE;
		break;
	}
	spin_unlock(&fcmd->lock);
}

/*
 * Free command and associated frame.
 */
static void ft_cmd_done(struct ft_cmd *fcmd)
{
	struct fc_frame *fp = fcmd->req_frame;
	struct fc_seq *sp = fcmd->seq;
#ifndef NEW_LIBFC_API
	struct fc_lport *lport = fr_dev(fp);
#endif

	if (sp)
#ifdef NEW_LIBFC_API
		fc_exch_done(sp);
#else
		lport->tt.exch_done(sp);
#endif

	if (fr_seq(fp))
#ifdef NEW_LIBFC_API
		fc_seq_release(fr_seq(fp));
#else
		lport->tt.seq_release(fr_seq(fp));
#endif

	fc_frame_free(fp);
	kfree(fcmd);
}

/*
 * Free command - callback from SCST.
 */
void ft_cmd_free(struct scst_cmd *cmd)
{
	struct ft_cmd *fcmd = scst_cmd_get_tgt_priv(cmd);

	ft_cmd_done(fcmd);
}

/*
 * Send response.
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
	enum ft_cmd_state prev_state;
	int resid = 0;
	int bi_resid = 0;
	int error;
	int dir;
	u32 status;

	fcmd = scst_cmd_get_tgt_priv(cmd);
	ep = fc_seq_exch(fcmd->seq);
	lport = ep->lp;

	WARN_ON(fcmd->state != FT_STATE_NEW && fcmd->state != FT_STATE_DATA_IN);
	prev_state = ft_set_cmd_state(fcmd, FT_STATE_CMD_RSP_SENT);

	if (scst_cmd_aborted_on_xmit(cmd)) {
		FT_IO_DBG("cmd aborted did %x oxid %x\n", ep->did, ep->oxid);
		ft_abort_cmd(cmd);
		goto done;
	}

	if (!scst_cmd_get_is_send_status(cmd)) {
		FT_IO_DBG("send status not set.  feature not implemented\n");
		error = SCST_TGT_RES_FATAL_ERROR;
		goto err;
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
		resid = (signed int)scst_cmd_get_bufflen(cmd) -
			fcmd->write_data_len;
	if (dir & SCST_DATA_READ) {
		error = ft_send_read_data(cmd);
		if (error) {
			FT_ERR("ft_send_read_data returned %d\n", error);
			goto err;
		}

		if (dir == SCST_DATA_BIDI) {
			bi_resid = (signed int)scst_cmd_get_out_bufflen(cmd) -
				   scst_cmd_get_resp_data_len(cmd);
			if (bi_resid)
				len += sizeof(__be32);
		} else {
			resid = (signed int)scst_cmd_get_bufflen(cmd) -
				scst_cmd_get_resp_data_len(cmd);
		}
	}

	fp = fc_frame_alloc(lport, len);
	if (!fp) {
		error = SCST_TGT_RES_QUEUE_FULL;
		goto err;
	}

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
		} else {
			fcp->resp.fr_flags |= FCP_BIDI_READ_UNDER;
		}
		*(__be32 *)((u8 *)(fcp + 1) + slen) = htonl(bi_resid);
	}
	if (resid) {
		if (resid < 0) {
			resid = -resid;
			fcp->resp.fr_flags |= FCP_RESID_OVER;
		} else {
			fcp->resp.fr_flags |= FCP_RESID_UNDER;
		}
		fcp->ext.fr_resid = htonl(resid);
	}
	FT_IO_DBG("response did %x oxid %x\n", ep->did, ep->oxid);

	/*
	 * Send response.
	 */
#ifdef NEW_LIBFC_API
	fcmd->seq = fc_seq_start_next(fcmd->seq);
#else
	fcmd->seq = lport->tt.seq_start_next(fcmd->seq);
#endif
	fc_fill_fc_hdr(fp, FC_RCTL_DD_CMD_STATUS, ep->did, ep->sid, FC_TYPE_FCP,
		       FC_FC_EX_CTX | FC_FC_LAST_SEQ | FC_FC_END_SEQ, 0);

#ifdef NEW_LIBFC_API
	error = FCST_INJ_SEND_ERR(fc_seq_send(lport, fcmd->seq, fp));
#else
	error = FCST_INJ_SEND_ERR(lport->tt.seq_send(lport, fcmd->seq, fp));
#endif
	if (error < 0) {
		pr_err("Sending response for exchange with OX_ID %#x and RX_ID %#x failed: %d\n",
		       ep->oxid, ep->rxid, error);
		error = error == -ENOMEM ? SCST_TGT_RES_QUEUE_FULL :
			SCST_TGT_RES_FATAL_ERROR;
		goto err;
	}
done:
	scst_tgt_cmd_done(cmd, SCST_CONTEXT_SAME);
	return SCST_TGT_RES_SUCCESS;

err:
	ft_set_cmd_state(fcmd, prev_state);
	WARN_ONCE(error != SCST_TGT_RES_QUEUE_FULL &&
		  error != SCST_TGT_RES_FATAL_ERROR,
		  "%s: invalid error code %d\n",
		  __func__, error);
	return error;
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
		pr_err("exchange error %ld - aborting cmd %p / tag %lld\n",
		       -PTR_ERR(fp), cmd, cmd->tag);
		ft_abort_cmd(cmd);
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
		pr_info("%s: unhandled frame r_ctl %x\n", __func__,
			fh->fh_r_ctl);
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
	FT_IO_DBG("%p: timeout\n", cmd);
	ft_abort_cmd(cmd);
}

/*
 * Send TX_RDY (transfer ready).
 */
int ft_send_xfer_rdy(struct scst_cmd *cmd)
{
	struct ft_cmd *fcmd;
	struct fc_frame *fp;
	struct fcp_txrdy *txrdy;
	struct fc_lport *lport;
	struct fc_exch *ep;
	int error;

	fcmd = scst_cmd_get_tgt_priv(cmd);

	ep = fc_seq_exch(fcmd->seq);
	lport = ep->lp;
	fp = fc_frame_alloc(lport, sizeof(*txrdy));
	if (!fp)
		return SCST_TGT_RES_QUEUE_FULL;

	WARN_ON(!ft_test_and_set_cmd_state(fcmd, FT_STATE_NEW,
					   FT_STATE_NEED_DATA));

	txrdy = fc_frame_payload_get(fp, sizeof(*txrdy));
	memset(txrdy, 0, sizeof(*txrdy));
	txrdy->ft_data_ro = 0;
	txrdy->ft_burst_len = htonl(scst_cmd_get_bufflen(cmd));

#ifdef NEW_LIBFC_API
	fcmd->seq = fc_seq_start_next(fcmd->seq);
#else
	fcmd->seq = lport->tt.seq_start_next(fcmd->seq);
#endif
	fc_fill_fc_hdr(fp, FC_RCTL_DD_DATA_DESC, ep->did, ep->sid, FC_TYPE_FCP,
		       FC_FC_EX_CTX | FC_FC_END_SEQ | FC_FC_SEQ_INIT, 0);
#ifdef NEW_LIBFC_API
	error = FCST_INJ_SEND_ERR(fc_seq_send(lport, fcmd->seq, fp));
#else
	error = FCST_INJ_SEND_ERR(lport->tt.seq_send(lport, fcmd->seq, fp));
#endif
	switch (error) {
	case 0:
		return SCST_TGT_RES_SUCCESS;
	case -ENOMEM:
		ft_set_cmd_state(fcmd, FT_STATE_NEW);
		return SCST_TGT_RES_QUEUE_FULL;
	default:
		ft_set_cmd_state(fcmd, FT_STATE_NEW);
		return SCST_TGT_RES_FATAL_ERROR;
	}
}

/*
 * Send a FCP response including SCSI status and optional FCP rsp_code.
 * status is SAM_STAT_GOOD (zero) if code is valid.
 * This is used in error cases, such as allocation failures.
 */
static void ft_send_resp_status(struct fc_frame *rx_fp, u32 status,
				enum fcp_resp_rsp_codes code)
{
	struct fc_frame *fp;
	struct fc_seq *sp;
	const struct fc_frame_header *fh;
	size_t len;
	struct fcp_resp_with_ext *fcp;
	struct fcp_resp_rsp_info *info;
	struct fc_lport *lport;

	fh = fc_frame_header_get(rx_fp);
	FT_IO_DBG("FCP error response: did %x oxid %x status %x code %x\n",
		  ntoh24(fh->fh_s_id), ntohs(fh->fh_ox_id), status, code);
	lport = fr_dev(rx_fp);
	len = sizeof(*fcp);
	if (status == SAM_STAT_GOOD)
		len += sizeof(*info);
	fp = fc_frame_alloc(lport, len);
	if (!fp)
		return;

	fcp = fc_frame_payload_get(fp, len);
	memset(fcp, 0, len);
	fcp->resp.fr_status = status;
	if (status == SAM_STAT_GOOD) {
		fcp->ext.fr_rsp_len = htonl(sizeof(*info));
		fcp->resp.fr_flags |= FCP_RSP_LEN_VAL;
		info = (struct fcp_resp_rsp_info *)(fcp + 1);
		info->rsp_code = code;
	}

	fc_fill_reply_hdr(fp, rx_fp, FC_RCTL_DD_CMD_STATUS, 0);
	sp = fr_seq(fp);
	if (sp)
#ifdef NEW_LIBFC_API
		fc_seq_send(lport, sp, fp);
#else
		lport->tt.seq_send(lport, sp, fp);
#endif
	else
		lport->tt.frame_send(lport, fp);
}

/*
 * Send error or task management response.
 * Always frees the cmd and associated state.
 */
static void ft_send_resp_code(struct ft_cmd *fcmd, enum fcp_resp_rsp_codes code)
{
	ft_send_resp_status(fcmd->req_frame, SAM_STAT_GOOD, code);
	ft_cmd_done(fcmd);
}

void ft_cmd_tm_done(struct scst_mgmt_cmd *mcmd)
{
	struct ft_cmd *fcmd;
	enum fcp_resp_rsp_codes code;

	fcmd = scst_mgmt_cmd_get_tgt_priv(mcmd);
	if (!fcmd)
		return;

	ft_set_cmd_state(fcmd, FT_STATE_MGMT_RSP_SENT);

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

	ft_set_cmd_state(fcmd, FT_STATE_MGMT);

	scst_rx_mgmt_params_init(&params);

	params.lun = fcp->fc_lun.scsi_lun;
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
static void ft_recv_cmd(struct ft_sess *sess, struct fc_frame *fp)
{
	struct fc_seq *sp;
	struct scst_cmd *cmd;
	struct ft_cmd *fcmd = NULL;
	struct fcp_cmnd *fcp;
	struct fc_lport *lport;
	int data_dir;
	u32 data_len;
	int cdb_len;

	lport = sess->tport->lport;

#ifdef NEW_LIBFC_API
	sp = fc_seq_assign(lport, fp);
#else
	sp = lport->tt.seq_assign(lport, fp);
#endif
	if (!sp)
		goto busy;

	fcmd = kzalloc(sizeof(*fcmd), GFP_ATOMIC);
	if (!fcmd)
		goto busy;
	fcmd->max_payload = sess->max_payload;
	fcmd->max_lso_payload = sess->max_lso_payload;
	fcmd->req_frame = fp;
	spin_lock_init(&fcmd->lock);

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

	cmd = scst_rx_cmd(sess->scst_sess, fcp->fc_lun.scsi_lun,
			  sizeof(fcp->fc_lun), fcp->fc_cdb, cdb_len,
			  SCST_ATOMIC);
	if (!cmd)
		goto busy;
	fcmd->scst_cmd = cmd;
	scst_cmd_set_tgt_priv(cmd, fcmd);
	fcmd->state = FT_STATE_NEW;

	fcmd->seq = sp;
#ifdef NEW_LIBFC_API
	fc_seq_set_resp(sp, ft_recv_seq, cmd);
#else
	lport->tt.seq_set_resp(sp, ft_recv_seq, cmd);
#endif

	switch (fcp->fc_flags & (FCP_CFL_RDDATA | FCP_CFL_WRDATA)) {
	case 0:
	default:
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

	scst_cmd_set_tag(cmd, fc_seq_exch(sp)->rxid);
	scst_cmd_init_done(cmd, SCST_CONTEXT_THREAD);
	return;

err:
	ft_send_resp_code(fcmd, FCP_CMND_FIELDS_INVALID);
	return;

busy:
	FT_IO_DBG("cmd allocation failure - sending BUSY\n");
	ft_send_resp_status(fp, SAM_STAT_BUSY, 0);
	if (fcmd)
		ft_cmd_done(fcmd);
	else if (sp)
#ifdef NEW_LIBFC_API
		fc_exch_done(sp);
#else
		lport->tt.exch_done(sp);
#endif
}

/*
 * Send FCP ELS-4 Reject.
 */
static void ft_cmd_ls_rjt(struct fc_frame *rx_fp, enum fc_els_rjt_reason reason,
			  enum fc_els_rjt_explan explan)
{
	struct fc_seq_els_data rjt_data;

	rjt_data.reason = reason;
	rjt_data.explan = explan;
#ifdef NEW_LIBFC_API
	fc_seq_els_rsp_send(rx_fp, ELS_LS_RJT, &rjt_data);
#else
	fr_dev(rx_fp)->tt.seq_els_rsp_send(rx_fp, ELS_LS_RJT, &rjt_data);
#endif
}

/*
 * Handle an incoming FCP ELS-4 command frame.
 * Note that this may be called directly from the softirq context.
 */
static void ft_recv_els4(struct ft_sess *sess, struct fc_frame *fp)
{
	u8 op = fc_frame_payload_op(fp);

	switch (op) {
	case ELS_SRR:			/* TBD */
	default:
		FT_IO_DBG("unsupported ELS-4 op %x\n", op);
		ft_cmd_ls_rjt(fp, ELS_RJT_INVAL, ELS_EXPL_NONE);
		fc_frame_free(fp);
		break;
	}
}

/*
 * Handle an incoming FCP frame.
 * Note that this may be called directly from the softirq context.
 */
void ft_recv_req(struct ft_sess *sess, struct fc_frame *fp)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);

	switch (fh->fh_r_ctl) {
	case FC_RCTL_DD_UNSOL_CMD:
		ft_recv_cmd(sess, fp);
		break;
	case FC_RCTL_ELS4_REQ:
		ft_recv_els4(sess, fp);
		break;
	default:
		pr_info("%s: unhandled frame r_ctl %x\n", __func__,
			fh->fh_r_ctl);
		fc_frame_free(fp);
		break;
	}
}
