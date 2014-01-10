/*
 * Copyright (c) 2010 Cisco Systems, Inc.
 *
 * Portions based on drivers/scsi/libfc/fc_fcp.c and subject to the following:
 *
 * Copyright (c) 2007 Intel Corporation. All rights reserved.
 * Copyright (c) 2008 Red Hat, Inc.  All rights reserved.
 * Copyright (c) 2008 Mike Christie
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <scsi/libfc.h>
#include <scsi/fc_encode.h>
#include "fcst.h"

/*
 * Send read data back to initiator.
 */
int ft_send_read_data(struct scst_cmd *cmd)
{
	struct ft_cmd *fcmd;
	struct fc_frame *fp = NULL;
	struct fc_exch *ep;
	struct fc_lport *lport;
	size_t remaining;
	u32 fh_off = 0;
	u32 frame_off;
	size_t frame_len = 0;
	size_t mem_len;
	u32 mem_off;
	size_t tlen;
	struct page *page;
	int use_sg;
	int error;
	void *to = NULL;
	u8 *from = NULL;
	int loop_limit = 10000;

	fcmd = scst_cmd_get_tgt_priv(cmd);
	ep = fc_seq_exch(fcmd->seq);
	lport = ep->lp;

	frame_off = fcmd->read_data_len;
	tlen = scst_cmd_get_resp_data_len(cmd);
	FT_IO_DBG("oid %x oxid %x resp_len %zd frame_off %u\n",
		  ep->oid, ep->oxid, tlen, frame_off);
	if (tlen <= frame_off)
		return SCST_TGT_RES_SUCCESS;
	remaining = tlen - frame_off;
	if (remaining > UINT_MAX)
		FT_ERR("oid %x oxid %x resp_len %zd frame_off %u\n",
		       ep->oid, ep->oxid, tlen, frame_off);

	mem_len = scst_get_buf_first(cmd, &from);
	mem_off = 0;
	if (!mem_len) {
		FT_IO_DBG("mem_len 0\n");
		return SCST_TGT_RES_SUCCESS;
	}
	FT_IO_DBG("sid %x oxid %x mem_len %zd frame_off %u remaining %zd\n",
		 ep->sid, ep->oxid, mem_len, frame_off, remaining);

	/*
	 * If we've already transferred some of the data, skip through
	 * the buffer over the data already sent and continue with the
	 * same sequence.  Otherwise, get a new sequence for the data.
	 */
	if (frame_off) {
		tlen = frame_off;
		while (mem_len <= tlen) {
			tlen -= mem_len;
			scst_put_buf(cmd, from);
			mem_len = scst_get_buf_next(cmd, &from);
			if (!mem_len)
				return SCST_TGT_RES_SUCCESS;
		}
		mem_len -= tlen;
		mem_off = tlen;
	} else
		fcmd->seq = lport->tt.seq_start_next(fcmd->seq);

	/* no scatter/gather in skb for odd word length due to fc_seq_send() */
	use_sg = !(remaining % 4) && lport->sg_supp;
	/*
	 * Note: since libfc_function_template.seq_send() sends frames
	 * asynchronously and since the SCST data buffer is freed as soon as
	 * scst_tgt_cmd_done() has been invoked, data has to be copied into
	 * the skb instead of only copying a pointer to the data. To do: defer
	 * invocation of scst_tgt_cmd_done() until sending the data frames
	 * finished once the paged fragment destructor or an equivalent is
	 * upstream.
	 */
	use_sg = false;

	while (remaining) {
		if (!loop_limit) {
			FT_ERR("hit loop limit.  remaining %zx mem_len %zx "
			       "frame_len %zx tlen %zx\n",
			       remaining, mem_len, frame_len, tlen);
			break;
		}
		loop_limit--;
		if (!mem_len) {
			scst_put_buf(cmd, from);
			mem_len = scst_get_buf_next(cmd, &from);
			mem_off = 0;
			if (!mem_len) {
				FT_ERR("mem_len 0 from get_buf_next\n");
				break;
			}
		}
		if (!frame_len) {
			frame_len = fcmd->max_lso_payload;
			frame_len = min(frame_len, remaining);
			fp = fc_frame_alloc(lport, use_sg ? 0 : frame_len);
			if (!fp) {
				FT_IO_DBG("frame_alloc failed. "
					  "use_sg %d frame_len %zd\n",
					  use_sg, frame_len);
				break;
			}
			fr_max_payload(fp) = fcmd->max_payload;
			to = fc_frame_payload_get(fp, 0);
			fh_off = frame_off;
		}
		tlen = min(mem_len, frame_len);
		BUG_ON(!tlen);
		BUG_ON(tlen > remaining);
		BUG_ON(tlen > mem_len);
		BUG_ON(tlen > frame_len);

		if (use_sg) {
			page = virt_to_page(from + mem_off);
			get_page(page);
			tlen = min_t(size_t, tlen,
				     PAGE_SIZE - (mem_off & ~PAGE_MASK));
			skb_fill_page_desc(fp_skb(fp),
					   skb_shinfo(fp_skb(fp))->nr_frags,
					   page, offset_in_page(from + mem_off),
					   tlen);
			fr_len(fp) += tlen;
			fp_skb(fp)->data_len += tlen;
			fp_skb(fp)->truesize +=
					PAGE_SIZE << compound_order(page);
			frame_len -= tlen;
			if (skb_shinfo(fp_skb(fp))->nr_frags >= FC_FRAME_SG_LEN)
				frame_len = 0;
		} else {
			memcpy(to, from + mem_off, tlen);
			to += tlen;
			frame_len -= tlen;
		}

		mem_off += tlen;
		mem_len -= tlen;
		frame_off += tlen;
		remaining -= tlen;

		if (frame_len)
			continue;
		fc_fill_fc_hdr(fp, FC_RCTL_DD_SOL_DATA, ep->did, ep->sid,
			       FC_TYPE_FCP,
			       remaining ? (FC_FC_EX_CTX | FC_FC_REL_OFF) :
			       (FC_FC_EX_CTX | FC_FC_REL_OFF | FC_FC_END_SEQ),
			       fh_off);
		error = lport->tt.seq_send(lport, fcmd->seq, fp);
		if (error) {
			WARN_ON(1);
			/* XXX For now, initiator will retry */
		} else
			fcmd->read_data_len = frame_off;
	}
	if (mem_len)
		scst_put_buf(cmd, from);
	if (remaining) {
		FT_IO_DBG("remaining read data %zd\n", remaining);
		return SCST_TGT_RES_QUEUE_FULL;
	}
	return SCST_TGT_RES_SUCCESS;
}

/*
 * Receive write data frame.
 */
void ft_recv_write_data(struct scst_cmd *cmd, struct fc_frame *fp)
{
	struct ft_cmd *fcmd;
	struct fc_frame_header *fh;
	unsigned int bufflen;
	u32 rel_off;
	size_t frame_len;
	size_t mem_len;
	size_t tlen;
	void *from;
	void *to;
	int dir;
	u8 *buf;

	dir = scst_cmd_get_data_direction(cmd);
	if (dir == SCST_DATA_BIDI) {
		mem_len = scst_get_out_buf_first(cmd, &buf);
		bufflen = scst_cmd_get_out_bufflen(cmd);
	} else {
		mem_len = scst_get_buf_first(cmd, &buf);
		bufflen = scst_cmd_get_bufflen(cmd);
	}
	to = buf;

	fcmd = scst_cmd_get_tgt_priv(cmd);
	fh = fc_frame_header_get(fp);

	if (!(ntoh24(fh->fh_f_ctl) & FC_FC_REL_OFF))
		goto drop;
	rel_off = ntohl(fh->fh_parm_offset);
	frame_len = fr_len(fp);
	if (frame_len <= sizeof(*fh))
		goto drop;
	frame_len -= sizeof(*fh);
	from = fc_frame_payload_get(fp, 0);

	if (rel_off >= bufflen)
		goto drop;
	if (frame_len + rel_off > bufflen)
		frame_len = bufflen - rel_off;

	while (frame_len) {
		if (!mem_len) {
			if (dir == SCST_DATA_BIDI) {
				scst_put_out_buf(cmd, buf);
				mem_len = scst_get_out_buf_next(cmd, &buf);
			} else {
				scst_put_buf(cmd, buf);
				mem_len = scst_get_buf_next(cmd, &buf);
			}
			to = buf;
			if (!mem_len)
				break;
		}
		if (rel_off) {
			if (rel_off >= mem_len) {
				rel_off -= mem_len;
				mem_len = 0;
				continue;
			}
			mem_len -= rel_off;
			to += rel_off;
			rel_off = 0;
		}

		tlen = min(mem_len, frame_len);
		memcpy(to, from, tlen);

		from += tlen;
		frame_len -= tlen;
		mem_len -= tlen;
		to += tlen;
		fcmd->write_data_len += tlen;
	}
	if (mem_len) {
		if (dir == SCST_DATA_BIDI)
			scst_put_out_buf(cmd, buf);
		else
			scst_put_buf(cmd, buf);
	}
	if (fcmd->write_data_len == bufflen) {
		spin_lock(&fcmd->lock);
		if (fcmd->state == FT_STATE_NEED_DATA) {
			fcmd->state = FT_STATE_DATA_IN;
			scst_rx_data(cmd, SCST_RX_STATUS_SUCCESS,
				     SCST_CONTEXT_THREAD);
		}
		spin_unlock(&fcmd->lock);
	}
drop:
	fc_frame_free(fp);
}
