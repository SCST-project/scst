/*
 *  iSCSI digest handling.
 *
 *  Copyright (C) 2004 - 2006 Xiranet Communications GmbH
 *                            <arne.redlich@xiranet.com>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/types.h>
#include <linux/scatterlist.h>

#include "iscsi.h"
#include "digest.h"
#include <linux/crc32c.h>

void digest_alg_available(int *val)
{
#if defined(CONFIG_LIBCRC32C_MODULE) || defined(CONFIG_LIBCRC32C)
	int crc32c = 1;
#else
	int crc32c = 0;
#endif

	if ((*val & DIGEST_CRC32C) && !crc32c) {
		PRINT_ERROR("%s", "CRC32C digest algorithm not available "
			"in kernel");
		*val |= ~DIGEST_CRC32C;
	}
}

/**
 * initialize support for digest calculation.
 *
 * digest_init -
 * @conn: ptr to connection to make use of digests
 *
 * @return: 0 on success, < 0 on error
 */
int digest_init(struct iscsi_conn *conn)
{
	if (!(conn->hdigest_type & DIGEST_ALL))
		conn->hdigest_type = DIGEST_NONE;

	if (!(conn->ddigest_type & DIGEST_ALL))
		conn->ddigest_type = DIGEST_NONE;

	return 0;
}

static __be32 evaluate_crc32_from_sg(struct scatterlist *sg, int nbytes,
	uint32_t padding)
{
	u32 crc = ~0;
	int pad_bytes = ((nbytes + 3) & -4) - nbytes;

#ifdef CONFIG_SCST_ISCSI_DEBUG_DIGEST_FAILURES
	if (((scst_random() % 100000) == 752)) {
		PRINT_INFO("%s", "Simulating digest failure");
		return 0;
	}
#endif

#if defined(CONFIG_LIBCRC32C_MODULE) || defined(CONFIG_LIBCRC32C)
	while (nbytes > 0) {
		int d = min(nbytes, (int)(sg->length));
		crc = crc32c(crc, sg_virt(sg), d);
		nbytes -= d;
		sg++;
	}

	if (pad_bytes)
		crc = crc32c(crc, (u8 *)&padding, pad_bytes);
#endif

	return (__force __be32)~cpu_to_le32(crc);
}

static __be32 digest_header(struct iscsi_pdu *pdu)
{
	struct scatterlist sg[2];
	unsigned int nbytes = sizeof(struct iscsi_hdr);
	int asize = (pdu->ahssize + 3) & -4;

	sg_init_table(sg, 2);

	sg_set_buf(&sg[0], &pdu->bhs, nbytes);
	if (pdu->ahssize) {
		sg_set_buf(&sg[1], pdu->ahs, asize);
		nbytes += asize;
	}
	EXTRACHECKS_BUG_ON((nbytes & 3) != 0);
	return evaluate_crc32_from_sg(sg, nbytes, 0);
}

static __be32 digest_data(struct iscsi_cmnd *cmd, u32 size, u32 offset,
	uint32_t padding)
{
	struct scatterlist *sg = cmd->sg;
	int idx, count;
	struct scatterlist saved_sg;
	__be32 crc;

	offset += sg[0].offset;
	idx = offset >> PAGE_SHIFT;
	offset &= ~PAGE_MASK;

	count = get_pgcnt(size, offset);

	TRACE_DBG("req %p, idx %d, count %d, sg_cnt %d, size %d, "
		"offset %d", cmd, idx, count, cmd->sg_cnt, size, offset);
	sBUG_ON(idx + count > cmd->sg_cnt);

	saved_sg = sg[idx];
	sg[idx].offset = offset;
	sg[idx].length -= offset - saved_sg.offset;

	crc = evaluate_crc32_from_sg(sg + idx, size, padding);

	sg[idx] = saved_sg;
	return crc;
}

int digest_rx_header(struct iscsi_cmnd *cmnd)
{
	__be32 crc;

	crc = digest_header(&cmnd->pdu);
	if (unlikely(crc != cmnd->hdigest)) {
		PRINT_ERROR("%s", "RX header digest failed");
		return -EIO;
	} else
		TRACE_DBG("RX header digest OK for cmd %p", cmnd);

	return 0;
}

void digest_tx_header(struct iscsi_cmnd *cmnd)
{
	cmnd->hdigest = digest_header(&cmnd->pdu);
	TRACE_DBG("TX header digest for cmd %p: %x", cmnd, cmnd->hdigest);
}

int digest_rx_data(struct iscsi_cmnd *cmnd)
{
	struct iscsi_cmnd *req;
	struct iscsi_data_out_hdr *req_hdr;
	u32 offset;
	__be32 crc;
	int res = 0;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_DATA_OUT:
		req = cmnd->cmd_req;
		if (unlikely(req == NULL)) {
			/* It can be for prelim completed commands */
			req = cmnd;
			goto out;
		}
		req_hdr = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
		offset = be32_to_cpu(req_hdr->buffer_offset);
		break;

	default:
		req = cmnd;
		offset = 0;
	}

	/*
	 * We need to skip the digest check for prelim completed commands,
	 * because we use shared data buffer for them, so, most likely, the
	 * check will fail. Plus, for such commands we sometimes don't have
	 * sg_cnt set correctly (cmnd_prepare_get_rejected_cmd_data() doesn't
	 * do it).
	 */
	if (unlikely(req->prelim_compl_flags != 0))
		goto out;

	/*
	 * Temporary to not crash with write residual overflows. ToDo. Until
	 * that let's always have succeeded data digests for such overflows.
	 * In ideal, we should allocate additional one or more sg's for the
	 * overflowed data and free them here or on req release. It's quite
	 * not trivial for such virtually never used case, so let's do it,
	 * when it gets needed.
	 */
	if (unlikely(offset + cmnd->pdu.datasize > req->bufflen)) {
		PRINT_WARNING("Skipping RX data digest check for residual "
			"overflow command op %x (data size %d, buffer size %d)",
			cmnd_hdr(req)->scb[0], offset + cmnd->pdu.datasize,
			req->bufflen);
		goto out;
	}

	crc = digest_data(req, cmnd->pdu.datasize, offset,
			cmnd->conn->rpadding);

	if (unlikely(crc != cmnd->ddigest)) {
		TRACE(TRACE_MINOR|TRACE_MGMT_DEBUG, "%s", "RX data digest "
			"failed");
		TRACE_MGMT_DBG("Calculated crc %x, ddigest %x, offset %d", crc,
			cmnd->ddigest, offset);
		iscsi_dump_pdu(&cmnd->pdu);
		res = -EIO;
	} else
		TRACE_DBG("RX data digest OK for cmd %p", cmnd);

out:
	return res;
}

void digest_tx_data(struct iscsi_cmnd *cmnd)
{
	struct iscsi_data_in_hdr *hdr;
	u32 offset;

	TRACE_DBG("%s:%d req %p, own_sg %d, sg %p, sgcnt %d cmnd %p, "
		"own_sg %d, sg %p, sgcnt %d", __func__, __LINE__,
		cmnd->parent_req, cmnd->parent_req->own_sg,
		cmnd->parent_req->sg, cmnd->parent_req->sg_cnt,
		cmnd, cmnd->own_sg, cmnd->sg, cmnd->sg_cnt);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_DATA_IN:
		hdr = (struct iscsi_data_in_hdr *)&cmnd->pdu.bhs;
		offset = be32_to_cpu(hdr->buffer_offset);
		break;
	default:
		offset = 0;
	}

	cmnd->ddigest = digest_data(cmnd, cmnd->pdu.datasize, offset, 0);
	TRACE_DBG("TX data digest for cmd %p: %x (offset %d, opcode %x)", cmnd,
		cmnd->ddigest, offset, cmnd_opcode(cmnd));
}
