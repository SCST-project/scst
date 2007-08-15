/*
 * iSCSI digest handling.
 * (C) 2004 - 2006 Xiranet Communications GmbH <arne.redlich@xiranet.com>
 * This code is licensed under the GPL.
 */
 
#include <asm/types.h>
#include <asm/scatterlist.h>

#include "iscsi.h"
#include "digest.h"
#include <linux/crc32c.h>

void digest_alg_available(unsigned int *val)
{
#if CONFIG_LIBCRC32C_MODULE || CONFIG_LIBCRC32C
	int crc32c = 1;
#else
	int crc32c = 0;
#endif

	if ((*val & DIGEST_CRC32C) && !crc32c) {
		PRINT_ERROR_PR("%s", "CRC32C digest algorithm not available "
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

/* Copied from linux-iscsi initiator and slightly adjusted */
#define SETSG(sg, p, l) do {					\
	(sg).page = virt_to_page((p));				\
	(sg).offset = ((unsigned long)(p) & ~PAGE_MASK);	\
	(sg).length = (l);					\
} while (0)

static u32 evaluate_crc32_from_sg(struct scatterlist *sg, int total,
	int pad_bytes)
{
	u32 crc = ~0;

#ifdef DEBUG_DIGEST_FAILURES
	if (((scst_random() % 100000) == 752)) {
		PRINT_INFO_PR("%s", "Simulating digest failure");
		return 0;
	}
#endif

#if CONFIG_LIBCRC32C_MODULE || CONFIG_LIBCRC32C
	while (total > 0) {
		int d = min(min(total, (int)(sg->length)),
			(int)(PAGE_SIZE - sg->offset));

		crc = crc32c(crc, page_address(sg->page) + sg->offset, d);
		total -= d;
		sg++;
	}

	if (pad_bytes) {
		u32 padding = 0;
		/*
		 * Digest includes also padding for aligned pdu length, hopefully
		 * it is always filled with 0s in pdu (according to crypto/crc32c.c
		 */
		crc = crc32c(crc, (u8 *)&padding, pad_bytes);
	}
#endif

	return ~cpu_to_le32(crc);
}

static u32 digest_header(struct iscsi_pdu *pdu)
{
	struct scatterlist sg[2];
	unsigned int nbytes = sizeof(struct iscsi_hdr);

	SETSG(sg[0], &pdu->bhs, nbytes);
	if (pdu->ahssize) {
		SETSG(sg[1], pdu->ahs, pdu->ahssize);
		nbytes += pdu->ahssize;
	}
	return evaluate_crc32_from_sg(sg, nbytes, 0);
}

static u32 digest_data(struct iscsi_cmnd *req, u32 osize, u32 offset)
{
	struct scatterlist *sg = req->sg;
	int idx, count;
	struct scatterlist saved_sg;
	u32 size = (osize + 3) & ~3;
	u32 crc;

	offset += sg[0].offset;
	idx = offset >> PAGE_SHIFT;
	offset &= ~PAGE_MASK;
	
	count = get_pgcnt(size, offset);
	sBUG_ON(idx + count > get_pgcnt(req->bufflen, 0));
	sBUG_ON(count > ISCSI_CONN_IOV_MAX);

	saved_sg = sg[idx];
	sg[idx].offset = offset;
	sg[idx].length -= offset - saved_sg.offset;

	crc = evaluate_crc32_from_sg(sg + idx, osize, size - osize);

	sg[idx] = saved_sg;
	return crc;
}

int digest_rx_header(struct iscsi_cmnd *cmnd)
{
	u32 crc;

	crc = digest_header(&cmnd->pdu);
	if (crc != cmnd->hdigest) {
		PRINT_ERROR_PR("%s", "RX header digest failed");
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
	u32 offset, crc;
	int res = 0;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_DATA_OUT:
		req = cmnd->cmd_req;
		req_hdr = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
		offset = be32_to_cpu(req_hdr->buffer_offset);
		break;

	case ISCSI_OP_SCSI_REJECT:
	case ISCSI_OP_PDU_REJECT:
	case ISCSI_OP_DATA_REJECT:
		goto out;

	default:
		req = cmnd;
		offset = 0;
	}

	crc = digest_data(req, cmnd->pdu.datasize, offset);

	if (crc != cmnd->ddigest) {
		PRINT_ERROR_PR("%s", "RX data digest failed");
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
		"own_sg %d, sg %p, sgcnt %d", __FUNCTION__, __LINE__,
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

	/* 
	 * cmnd is used here regardless of its sg comes from parent or was
	 * allocated for this cmnd only, see cmnd_send_pdu()
	 */
	cmnd->ddigest = digest_data(cmnd, cmnd->pdu.datasize, offset);
	TRACE_DBG("TX data digest for cmd %p: %x (offset %d, opcode %x)", cmnd,
		cmnd->ddigest, offset, cmnd_opcode(cmnd));
}
