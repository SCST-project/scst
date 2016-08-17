/*
* isert_rdma.c
* This file is part of iser target kernel module.
*
* Copyright (c) 2013 - 2014 Mellanox Technologies. All rights reserved.
* Copyright (c) 2013 - 2014 Yan Burman (yanb@mellanox.com)
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* OpenIB.org BSD license below:
*
*     Redistribution and use in source and binary forms, with or
*     without modification, are permitted provided that the following
*     conditions are met:
*
*            - Redistributions of source code must retain the above
*              copyright notice, this list of conditions and the following
*              disclaimer.
*
*            - Redistributions in binary form must reproduce the above
*              copyright notice, this list of conditions and the following
*              disclaimer in the documentation and/or other materials
*              provided with the distribution.
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
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/in.h>
#include <linux/in6.h>

#include "isert_dbg.h"
#include "iser.h"
#include "isert.h"
#include "iser_datamover.h"

#define ISER_CQ_ENTRIES		(128 * 1024)
#define ISER_LISTEN_BACKLOG	8

static DEFINE_MUTEX(dev_list_mutex);

static void isert_portal_free(struct isert_portal *portal);

static int isert_num_recv_posted_on_err(struct ib_recv_wr *first_ib_wr,
					struct ib_recv_wr *bad_wr)
{
	struct ib_recv_wr *wr;
	int num_posted = 0;

	for (wr = first_ib_wr; wr != NULL && wr != bad_wr; wr = wr->next)
		num_posted++;

	return num_posted;
}

int isert_post_recv(struct isert_connection *isert_conn,
		    struct isert_wr *first_wr,
		    int num_wr)
{
	struct ib_recv_wr *first_ib_wr = &first_wr->recv_wr;
	struct ib_recv_wr *bad_wr;
	int num_posted;
	int err;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (test_bit(ISERT_DRAIN_POSTED, &isert_conn->flags)) {
		PRINT_ERROR("conn:%p post recv after drain", isert_conn);
		BUG();
	}
#endif

	err = ib_post_recv(isert_conn->qp, first_ib_wr, &bad_wr);
	if (unlikely(err)) {
		num_posted = isert_num_recv_posted_on_err(first_ib_wr, bad_wr);

		PRINT_ERROR("conn:%p recv posted:%d/%d 1st wr_id:0x%llx sz:%d err:%d",
			    isert_conn, num_posted, num_wr, first_ib_wr->wr_id,
			    first_ib_wr->sg_list->length, err);
	}

	TRACE_EXIT_RES(err);
	return err;
}

static int isert_num_send_posted_on_err(struct ib_send_wr *first_ib_wr,
					struct ib_send_wr *bad_wr)
{
	struct ib_send_wr *wr;
	int num_posted = 0;

	for (wr = first_ib_wr; wr != NULL && wr != bad_wr; wr = wr->next)
		num_posted++;

	return num_posted;
}

int isert_post_send(struct isert_connection *isert_conn,
		    struct isert_wr *first_wr,
		    int num_wr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	struct ib_send_wr *first_ib_wr = &first_wr->send_wr;
#else
	struct ib_send_wr *first_ib_wr = &first_wr->send_wr.wr;
#endif
	struct ib_send_wr *bad_wr;
	int num_posted;
	int err;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (test_bit(ISERT_DRAIN_POSTED, &isert_conn->flags)) {
		PRINT_ERROR("conn:%p post send after drain", isert_conn);
		BUG();
	}
#endif

	err = ib_post_send(isert_conn->qp, first_ib_wr, &bad_wr);
	if (unlikely(err)) {
		num_posted = isert_num_send_posted_on_err(first_ib_wr, bad_wr);

		PRINT_ERROR("conn:%p send posted:%d/%d bad wr_id:0x%llx sz:%d num_sge: %d err:%d",
			    isert_conn, num_posted, num_wr, bad_wr->wr_id,
			    bad_wr->sg_list->length, bad_wr->num_sge, err);
	}

	TRACE_EXIT_RES(err);
	return err;
}

void isert_post_drain(struct isert_connection *isert_conn)
{
	if (!test_and_set_bit(ISERT_DRAIN_POSTED, &isert_conn->flags)) {
		struct ib_send_wr *bad_wr;
		int err;

		isert_wr_set_fields(&isert_conn->drain_wr, isert_conn, NULL);
		isert_conn->drain_wr.wr_op = ISER_WR_SEND;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		isert_conn->drain_wr.send_wr.wr_id =
			_ptr_to_u64(&isert_conn->drain_wr);
		isert_conn->drain_wr.send_wr.opcode = IB_WR_SEND;
		err = ib_post_send(isert_conn->qp,
				   &isert_conn->drain_wr.send_wr, &bad_wr);
#else
		isert_conn->drain_wr.send_wr.wr.wr_id =
			_ptr_to_u64(&isert_conn->drain_wr);
		isert_conn->drain_wr.send_wr.wr.opcode = IB_WR_SEND;
		err = ib_post_send(isert_conn->qp,
				   &isert_conn->drain_wr.send_wr.wr, &bad_wr);
#endif
		if (unlikely(err)) {
			PRINT_ERROR("Failed to post drain wr, err:%d", err);
			/*
			 * We need to decrement iser_conn->kref in order to be
			 * able to cleanup the connection.
			 */
			set_bit(ISERT_DRAIN_FAILED, &isert_conn->flags);
			isert_conn_free(isert_conn);
		}
	}
}

void isert_conn_disconnect(struct isert_connection *isert_conn)
{
	int err;

	if (isert_conn->state != ISER_CONN_CLOSING) {
		isert_conn->state = ISER_CONN_CLOSING;

		err = rdma_disconnect(isert_conn->cm_id);

		if (unlikely(err))
			PRINT_ERROR("Failed to rdma disconnect, err:%d", err);
	}
}

static int isert_pdu_handle_hello_req(struct isert_cmnd *pdu)
{
	PRINT_INFO("iSER Hello not supported");
	return -EINVAL; /* meanwhile disconnect immediately */
}

static int isert_pdu_handle_login_req(struct isert_cmnd *isert_pdu)
{
	return isert_login_req_rx(&isert_pdu->iscsi);
}

static int isert_pdu_handle_text(struct isert_cmnd *pdu)
{
	struct iscsi_cmnd *iscsi_cmnd = &pdu->iscsi;

	iscsi_cmnd->sg_cnt = pdu->buf.sg_cnt;
	iscsi_cmnd->sg = pdu->buf.sg;
	return isert_login_req_rx(iscsi_cmnd);
}

static int isert_pdu_handle_nop_out(struct isert_cmnd *pdu)
{
	return isert_pdu_rx(&pdu->iscsi);
}

static int isert_pdu_handle_scsi_cmd(struct isert_cmnd *pdu)
{
	return isert_pdu_rx(&pdu->iscsi);
}

static int isert_pdu_handle_tm_func(struct isert_cmnd *pdu)
{
	return isert_pdu_rx(&pdu->iscsi);
}

static int isert_pdu_handle_data_out(struct isert_cmnd *pdu)
{
	PRINT_INFO("iser iscsi data out not supported");
	return -EINVAL; /* meanwhile disconnect immediately */
}

static int isert_pdu_handle_logout(struct isert_cmnd *pdu)
{
	return isert_pdu_rx(&pdu->iscsi);
}

static int isert_pdu_handle_snack(struct isert_cmnd *pdu)
{
	PRINT_INFO("iser iscsi SNACK not supported");
	return -EINVAL; /* meanwhile disconnect immediately */
}

static void isert_rx_pdu_parse_headers(struct isert_cmnd *isert_pdu)
{
	struct iscsi_cmnd *iscsi_cmnd = &isert_pdu->iscsi;
	struct isert_buf *isert_buf = &isert_pdu->buf;
	u8 *addr = isert_buf->addr;
	struct isert_hdr *isert_hdr = (struct isert_hdr *)addr;
	struct iscsi_hdr *bhs = (struct iscsi_hdr *)(addr + sizeof(*isert_hdr));
	unsigned int data_offset = ISER_HDRS_SZ;
	unsigned int ahssize;

	TRACE_ENTRY();

	isert_pdu->isert_hdr = isert_hdr;
	isert_pdu->isert_opcode = isert_hdr->flags & 0xf0;
	isert_pdu->is_rstag_valid = isert_hdr->flags & ISER_RSV ? 1 : 0;
	isert_pdu->is_wstag_valid = isert_hdr->flags & ISER_WSV ? 1 : 0;

	if (isert_pdu->is_rstag_valid) {
		isert_pdu->rem_read_stag = be32_to_cpu(isert_hdr->read_stag);
		isert_pdu->rem_read_va = be64_to_cpu(isert_hdr->read_va);
	}

	if (isert_pdu->is_wstag_valid) {
		isert_pdu->rem_write_stag = be32_to_cpu(isert_hdr->write_stag);
		isert_pdu->rem_write_va = be64_to_cpu(isert_hdr->write_va);
	}

	isert_pdu->bhs = bhs;
	isert_pdu->iscsi_opcode = bhs->opcode & ISCSI_OPCODE_MASK;

	memcpy(&iscsi_cmnd->pdu.bhs, bhs, sizeof(iscsi_cmnd->pdu.bhs));
	iscsi_cmnd_get_length(&iscsi_cmnd->pdu); /* get ahssize and datasize */

	ahssize = isert_pdu->iscsi.pdu.ahssize;
	if (likely(!ahssize)) {
		isert_pdu->ahs = NULL;
	} else {
		isert_pdu->ahs = addr + ISER_HDRS_SZ;
		data_offset += ahssize;
	}
	iscsi_cmnd->pdu.ahs = isert_pdu->ahs;

	iscsi_cmnd->bufflen = iscsi_cmnd->pdu.datasize;
	iscsi_cmnd->bufflen = (iscsi_cmnd->bufflen + 3) & ~3;
	if (iscsi_cmnd->bufflen) {
		iscsi_cmnd->sg_cnt = isert_pdu->buf.sg_cnt;
		iscsi_cmnd->sg = isert_pdu->buf.sg;
	} else {
		iscsi_cmnd->sg = NULL;
	}

	TRACE_EXIT();
}

static void isert_dma_sync_data_for_cpu(struct ib_device *ib_dev,
					struct ib_sge *sge, size_t size)
{
	size_t to_sync = size > (PAGE_SIZE - ISER_HDRS_SZ) ?
			 (PAGE_SIZE - ISER_HDRS_SZ) : size;
	ib_dma_sync_single_for_cpu(ib_dev, sge->addr + ISER_HDRS_SZ,
				   to_sync,
				   DMA_FROM_DEVICE);

	size -= to_sync;
	while (size) {
		++sge;
		to_sync = size > PAGE_SIZE ? PAGE_SIZE : size;
		ib_dma_sync_single_for_cpu(ib_dev, sge->addr,
					   to_sync,
					   DMA_FROM_DEVICE);

		size -= to_sync;
	}
}

static void isert_recv_completion_handler(struct isert_wr *wr)
{
	struct isert_cmnd *pdu = wr->pdu;
	struct ib_sge *sge = wr->sge_list;
	struct ib_device *ib_dev = wr->isert_dev->ib_dev;
	int err;

	TRACE_ENTRY();

	ib_dma_sync_single_for_cpu(ib_dev, sge->addr,
				   ISER_HDRS_SZ,
				   DMA_FROM_DEVICE);
	isert_rx_pdu_parse_headers(pdu);
	isert_dma_sync_data_for_cpu(ib_dev, sge,
				    pdu->iscsi.pdu.datasize + pdu->iscsi.pdu.ahssize);

	switch (pdu->isert_opcode) {
	case ISER_ISCSI_CTRL:
		switch (pdu->iscsi_opcode) {
		case ISCSI_OP_NOP_OUT:
			err = isert_pdu_handle_nop_out(pdu);
			break;
		case ISCSI_OP_SCSI_CMD:
			err = isert_pdu_handle_scsi_cmd(pdu);
			break;
		case ISCSI_OP_SCSI_TASK_MGT_MSG:
			err = isert_pdu_handle_tm_func(pdu);
			break;
		case ISCSI_OP_LOGIN_CMD:
			err = isert_pdu_handle_login_req(pdu);
			break;
		case ISCSI_OP_TEXT_CMD:
			err = isert_pdu_handle_text(pdu);
			break;
		case ISCSI_OP_SCSI_DATA_OUT:
			err = isert_pdu_handle_data_out(pdu);
			break;
		case ISCSI_OP_LOGOUT_CMD:
			err = isert_pdu_handle_logout(pdu);
			break;
		case ISCSI_OP_SNACK_CMD:
			err = isert_pdu_handle_snack(pdu);
			break;
		default:
			PRINT_ERROR("Unexpected iscsi opcode:0x%x",
				    pdu->iscsi_opcode);
			err = -EINVAL;
			break;
		}
		break;
	case ISER_HELLO:
		err = isert_pdu_handle_hello_req(pdu);
		break;
	default:
		PRINT_ERROR("malformed isert_hdr, iser op:%x flags 0x%02x",
			    pdu->isert_opcode, pdu->isert_hdr->flags);
		err = -EINVAL;
		break;
	}

	if (unlikely(err)) {
		PRINT_ERROR("err:%d while handling iser pdu", err);
		isert_conn_disconnect(wr->conn);
	}

	TRACE_EXIT();
}

static void isert_send_completion_handler(struct isert_wr *wr)
{
	struct isert_cmnd *isert_pdu = wr->pdu;
	struct iscsi_cmnd *iscsi_pdu = &isert_pdu->iscsi;
	struct iscsi_cmnd *iscsi_req_pdu = iscsi_pdu->parent_req;
	struct isert_cmnd *isert_req_pdu = container_of(iscsi_req_pdu,
						    struct isert_cmnd, iscsi);


	TRACE_ENTRY();

	if (iscsi_req_pdu && iscsi_req_pdu->bufflen &&
	    isert_req_pdu->is_rstag_valid)
		isert_data_in_sent(iscsi_req_pdu);

	isert_pdu_sent(iscsi_pdu);

	TRACE_EXIT();
}

static void isert_rdma_rd_completion_handler(struct isert_wr *wr)
{
	struct isert_buf *isert_buf = wr->buf;
	struct isert_device *isert_dev = wr->isert_dev;
	struct ib_device *ib_dev = isert_dev->ib_dev;

	ib_dma_unmap_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt,
			isert_buf->dma_dir);
	isert_buf->sg_cnt = 0;

	isert_data_out_ready(&wr->pdu->iscsi);
}

static void isert_rdma_wr_completion_handler(struct isert_wr *wr)
{
	struct isert_buf *isert_buf = wr->buf;
	struct isert_device *isert_dev = wr->isert_dev;
	struct ib_device *ib_dev = isert_dev->ib_dev;

	ib_dma_unmap_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt,
			isert_buf->dma_dir);
	isert_buf->sg_cnt = 0;

	isert_data_in_sent(&wr->pdu->iscsi);
}

static void isert_handle_wc(struct ib_wc *wc)
{
	struct isert_wr *wr = _u64_to_ptr(wc->wr_id);
	struct isert_connection *isert_conn;

	TRACE_ENTRY();

	switch (wr->wr_op) {
	case ISER_WR_RECV:
		isert_conn = wr->conn;
		if (unlikely(isert_conn->state == ISER_CONN_HANDSHAKE)) {
			isert_conn->state = ISER_CONN_ACTIVE;
			isert_conn->saved_wr = wr;
			PRINT_INFO("iser rx pdu before conn established, pdu saved");
			break;
		}
		isert_recv_completion_handler(wr);
		break;
	case ISER_WR_SEND:
		isert_send_completion_handler(wr);
		break;
	case ISER_WR_RDMA_WRITE:
		isert_rdma_wr_completion_handler(wr);
		break;
	case ISER_WR_RDMA_READ:
		isert_rdma_rd_completion_handler(wr);
		break;
	default:
		isert_conn = wr->conn;
		PRINT_ERROR("unexpected work req op:%d, wc op:%d, wc:%p wr_id:%p conn:%p",
			    wr->wr_op, wc->opcode, wc, wr, isert_conn);
		if (isert_conn)
			isert_conn_disconnect(isert_conn);
		break;
	}

	TRACE_EXIT();
}

static const char *wr_status_str(enum ib_wc_status status)
{
	switch (status) {
	case IB_WC_SUCCESS:
		return "WC_SUCCESS";

	case IB_WC_LOC_LEN_ERR:
		return "WC_LOC_LEN_ERR";

	case IB_WC_LOC_QP_OP_ERR:
		return "WC_LOC_QP_OP_ERR";

	case IB_WC_LOC_EEC_OP_ERR:
		return "WC_LOC_EEC_OP_ERR";

	case IB_WC_LOC_PROT_ERR:
		return "WC_LOC_PROT_ERR";

	case IB_WC_WR_FLUSH_ERR:
		return "WC_WR_FLUSH_ERR";

	case IB_WC_MW_BIND_ERR:
		return "WC_MW_BIND_ERR";

	case IB_WC_BAD_RESP_ERR:
		return "WC_BAD_RESP_ERR";

	case IB_WC_LOC_ACCESS_ERR:
		return "WC_LOC_ACCESS_ERR";

	case IB_WC_REM_INV_REQ_ERR:
		return "WC_REM_INV_REQ_ERR";

	case IB_WC_REM_ACCESS_ERR:
		return "WC_REM_ACCESS_ERR";

	case IB_WC_REM_OP_ERR:
		return "WC_REM_OP_ERR";

	case IB_WC_RETRY_EXC_ERR:
		return "WC_RETRY_EXC_ERR";

	case IB_WC_RNR_RETRY_EXC_ERR:
		return "WC_RNR_RETRY_EXC_ERR";

	case IB_WC_LOC_RDD_VIOL_ERR:
		return "WC_LOC_RDD_VIOL_ERR";

	case IB_WC_REM_INV_RD_REQ_ERR:
		return "WC_REM_INV_RD_REQ_ERR";

	case IB_WC_REM_ABORT_ERR:
		return "WC_REM_ABORT_ERR";

	case IB_WC_INV_EECN_ERR:
		return "WC_INV_EECN_ERR";

	case IB_WC_INV_EEC_STATE_ERR:
		return "WC_INV_EEC_STATE_ERR";

	case IB_WC_FATAL_ERR:
		return "WC_FATAL_ERR";

	case IB_WC_RESP_TIMEOUT_ERR:
		return "WC_RESP_TIMEOUT_ERR";

	case IB_WC_GENERAL_ERR:
		return "WC_GENERAL_ERR";

	default:
		return "UNKNOWN";
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void isert_discon_do_work(void *ctx)
#else
static void isert_discon_do_work(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct isert_connection *isert_conn = ctx;
#else
	struct isert_connection *isert_conn =
		container_of(work, struct isert_connection, discon_work);
#endif

	/* notify upper layer */
	isert_connection_closed(&isert_conn->iscsi);
}

static void isert_sched_discon(struct isert_connection *isert_conn)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&isert_conn->discon_work, isert_discon_do_work, isert_conn);
#else
	INIT_WORK(&isert_conn->discon_work, isert_discon_do_work);
#endif
	isert_conn_queue_work(&isert_conn->discon_work);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void isert_conn_drained_do_work(void *ctx)
#else
static void isert_conn_drained_do_work(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct isert_connection *isert_conn = ctx;
#else
	struct isert_connection *isert_conn =
		container_of(work, struct isert_connection, drain_work);
#endif

	isert_conn_free(isert_conn);
}

static void isert_sched_conn_drained(struct isert_connection *isert_conn)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&isert_conn->drain_work, isert_conn_drained_do_work, isert_conn);
#else
	INIT_WORK(&isert_conn->drain_work, isert_conn_drained_do_work);
#endif
	isert_conn_queue_work(&isert_conn->drain_work);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void isert_conn_closed_do_work(void *ctx)
#else
static void isert_conn_closed_do_work(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct isert_connection *isert_conn = ctx;
#else
	struct isert_connection *isert_conn =
		container_of(work, struct isert_connection, close_work);
#endif

	if (!test_bit(ISERT_CONNECTION_ABORTED, &isert_conn->flags))
		isert_connection_abort(&isert_conn->iscsi);

	/* if connection established we have another refcount */
	if (test_bit(ISERT_CONNECTION_EST, &isert_conn->flags)) {
		isert_conn_free(isert_conn);
	}
}

static void isert_sched_conn_closed(struct isert_connection *isert_conn)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&isert_conn->close_work, isert_conn_closed_do_work,
		  isert_conn);
#else
	INIT_WORK(&isert_conn->close_work, isert_conn_closed_do_work);
#endif
	isert_conn_queue_work(&isert_conn->close_work);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void isert_conn_free_do_work(void *ctx)
#else
static void isert_conn_free_do_work(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct isert_connection *isert_conn = ctx;
#else
	struct isert_connection *isert_conn =
		container_of(work, struct isert_connection, free_work);
#endif

	isert_conn_free(isert_conn);
}

void isert_sched_conn_free(struct isert_connection *isert_conn)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&isert_conn->free_work, isert_conn_free_do_work,
		  isert_conn);
#else
	INIT_WORK(&isert_conn->free_work, isert_conn_free_do_work);
#endif
	isert_conn_queue_work(&isert_conn->free_work);
}

static void isert_handle_wc_error(struct ib_wc *wc)
{
	struct isert_wr *wr = _u64_to_ptr(wc->wr_id);
	struct isert_cmnd *isert_pdu = wr->pdu;
	struct isert_connection *isert_conn = wr->conn;
	struct isert_buf *isert_buf = wr->buf;
	struct isert_device *isert_dev = wr->isert_dev;
	struct ib_device *ib_dev = isert_dev->ib_dev;
	u32 num_sge;

	TRACE_ENTRY();

	if (wc->status != IB_WC_WR_FLUSH_ERR)
		PRINT_ERROR("conn:%p wr_id:0x%p status:%s vendor_err:0x%0x",
			    isert_conn, wr, wr_status_str(wc->status),
			    wc->vendor_err);

	if (!test_bit(ISERT_CONNECTION_ABORTED, &isert_conn->flags))
		if (!test_and_set_bit(ISERT_DISCON_CALLED, &isert_conn->flags))
			isert_sched_discon(isert_conn);

	switch (wr->wr_op) {
	case ISER_WR_SEND:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		num_sge = wr->send_wr.num_sge;
#else
		num_sge = wr->send_wr.wr.num_sge;
#endif
		if (unlikely(num_sge == 0)) /* Drain WR */
			isert_sched_conn_drained(isert_conn);
		else if (!isert_pdu->is_fake_rx)
			isert_pdu_err(&isert_pdu->iscsi);
		break;
	case ISER_WR_RDMA_READ:
		if (isert_buf->sg_cnt != 0) {
			ib_dma_unmap_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt,
				isert_buf->dma_dir);
			isert_buf->sg_cnt = 0;
		}
		if (!isert_pdu->is_fake_rx)
			isert_pdu_err(&isert_pdu->iscsi);
		break;
	case ISER_WR_RECV:
		/* this should be the Flush, no task has been created yet */
		break;
	case ISER_WR_RDMA_WRITE:
		if (isert_buf->sg_cnt != 0) {
			ib_dma_unmap_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt,
				isert_buf->dma_dir);
			isert_buf->sg_cnt = 0;
		}
		/*
		 * RDMA-WR and SEND response of a READ task
		 * are sent together, so when receiving RDMA-WR error,
		 * wait until SEND error arrives to complete the task.
		 */
		break;
	default:
		PRINT_ERROR("unexpected opcode %d, wc:%p wr_id:%p conn:%p",
			    wr->wr_op, wc, wr, isert_conn);
		break;
	}

	TRACE_EXIT();
}

static int isert_poll_cq(struct isert_cq *cq)
{
	int err;
	struct ib_wc *wc, *last_wc;

	TRACE_ENTRY();

	do {
		err = ib_poll_cq(cq->cq, ARRAY_SIZE(cq->wc), cq->wc);
		last_wc = &cq->wc[err];
		for (wc = cq->wc; wc < last_wc; ++wc) {
			if (likely(wc->status == IB_WC_SUCCESS))
				isert_handle_wc(wc);
			else
				isert_handle_wc_error(wc);
		}

	} while (err > 0);

	TRACE_EXIT_RES(err);
	return err;
}

/* callback function for isert_dev->[cq]->cq_comp_work */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
/* A vanilla 2.6.19 or older kernel without backported OFED kernel headers. */
static void isert_cq_comp_work_cb(void *ctx)
{
	struct isert_cq *cq_desc = ctx;
#else
static void isert_cq_comp_work_cb(struct work_struct *work)
{
	struct isert_cq *cq_desc =
		container_of(work, struct isert_cq, cq_comp_work);
#endif
	int ret;

	TRACE_ENTRY();

	ret = isert_poll_cq(cq_desc);
	if (unlikely(ret < 0)) { /* poll error */
		PRINT_ERROR("ib_poll_cq failed");
		goto out;
	}

	ib_req_notify_cq(cq_desc->cq,
			 IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
	/*
	 * not all HCAs support IB_CQ_REPORT_MISSED_EVENTS,
	 * so we need to make sure we don't miss any events between
	 * last call to ib_poll_cq() and ib_req_notify_cq()
	 */
	isert_poll_cq(cq_desc);

out:
	TRACE_EXIT();
	return;
}

static void isert_cq_comp_handler(struct ib_cq *cq, void *context)
{
	struct isert_cq *cq_desc = context;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	queue_work(cq_desc->cq_workqueue, &cq_desc->cq_comp_work);
#else
	queue_work_on(smp_processor_id(), cq_desc->cq_workqueue,
		      &cq_desc->cq_comp_work);
#endif
}

static const char *ib_event_type_str(enum ib_event_type ev_type)
{
	switch (ev_type) {
	case IB_EVENT_COMM_EST:
		return "COMM_EST";
	case IB_EVENT_QP_FATAL:
		return "QP_FATAL";
	case IB_EVENT_QP_REQ_ERR:
		return "QP_REQ_ERR";
	case IB_EVENT_QP_ACCESS_ERR:
		return "QP_ACCESS_ERR";
	case IB_EVENT_SQ_DRAINED:
		return "SQ_DRAINED";
	case IB_EVENT_PATH_MIG:
		return "PATH_MIG";
	case IB_EVENT_PATH_MIG_ERR:
		return "PATH_MIG_ERR";
	case IB_EVENT_QP_LAST_WQE_REACHED:
		return "QP_LAST_WQE_REACHED";
	case IB_EVENT_CQ_ERR:
		return "CQ_ERR";
	case IB_EVENT_SRQ_ERR:
		return "SRQ_ERR";
	case IB_EVENT_SRQ_LIMIT_REACHED:
		return "SRQ_LIMIT_REACHED";
	case IB_EVENT_PORT_ACTIVE:
		return "PORT_ACTIVE";
	case IB_EVENT_PORT_ERR:
		return "PORT_ERR";
	case IB_EVENT_LID_CHANGE:
		return "LID_CHANGE";
	case IB_EVENT_PKEY_CHANGE:
		return "PKEY_CHANGE";
	case IB_EVENT_SM_CHANGE:
		return "SM_CHANGE";
	case IB_EVENT_CLIENT_REREGISTER:
		return "CLIENT_REREGISTER";
	case IB_EVENT_DEVICE_FATAL:
		return "DEVICE_FATAL";
	default:
		return "UNKNOWN";
	}
}

static void isert_async_evt_handler(struct ib_event *async_ev, void *context)
{
	struct isert_cq *cq = context;
	struct isert_device *isert_dev = cq->dev;
	struct ib_device *ib_dev = isert_dev->ib_dev;
	char *dev_name = ib_dev->name;
	enum ib_event_type ev_type = async_ev->event;
	struct isert_connection *isert_conn;

	TRACE_ENTRY();

	switch (ev_type) {
	case IB_EVENT_COMM_EST:
		isert_conn = async_ev->element.qp->qp_context;
		PRINT_INFO("conn:0x%p cm_id:0x%p dev:%s, QP evt: %s",
			   isert_conn, isert_conn->cm_id, dev_name,
			   ib_event_type_str(IB_EVENT_COMM_EST));
		/* force "connection established" event */
		rdma_notify(isert_conn->cm_id, IB_EVENT_COMM_EST);
		break;

	/* rest of QP-related events */
	case IB_EVENT_QP_FATAL:
	case IB_EVENT_QP_REQ_ERR:
	case IB_EVENT_QP_ACCESS_ERR:
	case IB_EVENT_SQ_DRAINED:
	case IB_EVENT_PATH_MIG:
	case IB_EVENT_PATH_MIG_ERR:
	case IB_EVENT_QP_LAST_WQE_REACHED:
		isert_conn = async_ev->element.qp->qp_context;
		PRINT_ERROR("conn:0x%p cm_id:0x%p dev:%s, QP evt: %s",
			    isert_conn, isert_conn->cm_id, dev_name,
			    ib_event_type_str(ev_type));
		break;

	/* CQ-related events */
	case IB_EVENT_CQ_ERR:
		PRINT_ERROR("dev:%s CQ evt: %s", dev_name,
			    ib_event_type_str(ev_type));
		break;

	/* SRQ events */
	case IB_EVENT_SRQ_ERR:
	case IB_EVENT_SRQ_LIMIT_REACHED:
		PRINT_ERROR("dev:%s SRQ evt: %s", dev_name,
			    ib_event_type_str(ev_type));
		break;

	/* Port events */
	case IB_EVENT_PORT_ACTIVE:
	case IB_EVENT_PORT_ERR:
	case IB_EVENT_LID_CHANGE:
	case IB_EVENT_PKEY_CHANGE:
	case IB_EVENT_SM_CHANGE:
	case IB_EVENT_CLIENT_REREGISTER:
		PRINT_ERROR("dev:%s port:%d evt: %s",
			    dev_name, async_ev->element.port_num,
			    ib_event_type_str(ev_type));
		break;

	/* HCA events */
	case IB_EVENT_DEVICE_FATAL:
		PRINT_ERROR("dev:%s HCA evt: %s", dev_name,
			    ib_event_type_str(ev_type));
		break;

	default:
		PRINT_ERROR("dev:%s evt: %s", dev_name,
			    ib_event_type_str(ev_type));
		break;
	}

	TRACE_EXIT();
}

static struct isert_device *isert_device_create(struct ib_device *ib_dev)
{
	struct isert_device *isert_dev;
	int cqe_num, err;
	struct ib_pd *pd;
	struct ib_mr *mr;
	struct ib_cq *cq;
	char wq_name[64];
	int i, j;

	TRACE_ENTRY();

	isert_dev = kzalloc(sizeof(*isert_dev), GFP_KERNEL);
	if (unlikely(isert_dev == NULL)) {
		PRINT_ERROR("Failed to allocate iser dev");
		err = -ENOMEM;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	err = ib_query_device(ib_dev, &isert_dev->device_attr);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to query device, err: %d", err);
		goto free_isert_dev;
	}
#else
	isert_dev->device_attr = ib_dev->attrs;
#endif

	isert_dev->num_cqs = min_t(int, num_online_cpus(),
				   ib_dev->num_comp_vectors);

	isert_dev->cq_qps = kcalloc(isert_dev->num_cqs,
				    sizeof(*isert_dev->cq_qps),
				    GFP_KERNEL);
	if (unlikely(isert_dev->cq_qps == NULL)) {
		PRINT_ERROR("Failed to allocate iser cq_qps");
		err = -ENOMEM;
		goto free_isert_dev;
	}

	isert_dev->cq_desc = vmalloc(sizeof(*isert_dev->cq_desc) * isert_dev->num_cqs);
	if (unlikely(isert_dev->cq_desc == NULL)) {
		PRINT_ERROR("Failed to allocate %ld bytes for iser cq_desc",
			    sizeof(*isert_dev->cq_desc) * isert_dev->num_cqs);
		err = -ENOMEM;
		goto fail_alloc_cq_desc;
	}

	pd = ib_alloc_pd(ib_dev);
	if (unlikely(IS_ERR(pd))) {
		err = PTR_ERR(pd);
		PRINT_ERROR("Failed to alloc iser dev pd, err:%d", err);
		goto fail_pd;
	}

	mr = ib_get_dma_mr(pd, IB_ACCESS_LOCAL_WRITE);
	if (unlikely(IS_ERR(mr))) {
		err = PTR_ERR(mr);
		PRINT_ERROR("Failed to get dma mr, err: %d", err);
		goto fail_mr;
	}

	cqe_num = min(isert_dev->device_attr.max_cqe, ISER_CQ_ENTRIES);
	cqe_num = cqe_num / isert_dev->num_cqs;

#ifdef CONFIG_SCST_EXTRACHECKS
	if (isert_dev->device_attr.max_cqe == 0)
		PRINT_ERROR("Zero max_cqe encountered: you may have a compilation problem");
#endif

	for (i = 0; i < isert_dev->num_cqs; ++i) {
		struct isert_cq *cq_desc = &isert_dev->cq_desc[i];

		cq_desc->dev = isert_dev;
		cq_desc->idx = i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
		INIT_WORK(&cq_desc->cq_comp_work, isert_cq_comp_work_cb, NULL);
#else
		INIT_WORK(&cq_desc->cq_comp_work, isert_cq_comp_work_cb);
#endif

		snprintf(wq_name, sizeof(wq_name), "isert_cq_%p", cq_desc);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		cq_desc->cq_workqueue = create_singlethread_workqueue(wq_name);
#else
#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 36)
		cq_desc->cq_workqueue = alloc_workqueue(wq_name,
							WQ_CPU_INTENSIVE|
							WQ_RESCUER, 1);
#else
		cq_desc->cq_workqueue = alloc_workqueue(wq_name,
							WQ_CPU_INTENSIVE|
							WQ_MEM_RECLAIM, 1);
#endif
#endif
		if (unlikely(!cq_desc->cq_workqueue)) {
			PRINT_ERROR("Failed to alloc iser cq work queue for dev:%s",
				    ib_dev->name);
			err = -ENOMEM;
			goto fail_cq;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0) && \
	!defined(IB_CREATE_CQ_HAS_INIT_ATTR)
		cq = ib_create_cq(ib_dev,
				  isert_cq_comp_handler,
				  isert_async_evt_handler,
				  cq_desc, /* context */
				  cqe_num,
				  i); /* completion vector */
#else
		{
		struct ib_cq_init_attr ia = {
			.cqe		 = cqe_num,
			.comp_vector	 = i,
		};
		cq = ib_create_cq(ib_dev,
				  isert_cq_comp_handler,
				  isert_async_evt_handler,
				  cq_desc, /* context */
				  &ia);
		}
#endif
		if (unlikely(IS_ERR(cq))) {
			cq_desc->cq = NULL;
			err = PTR_ERR(cq);
			PRINT_ERROR("Failed to create iser dev cq, err:%d", err);
			goto fail_cq;
		}

		cq_desc->cq = cq;
		err = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
		if (unlikely(err)) {
			PRINT_ERROR("Failed to request notify cq, err: %d", err);
			goto fail_cq;
		}
	}

	isert_dev->ib_dev = ib_dev;
	isert_dev->pd = pd;
	isert_dev->mr = mr;

	INIT_LIST_HEAD(&isert_dev->conn_list);

	lockdep_assert_held(&dev_list_mutex);

	isert_dev_list_add(isert_dev);

	PRINT_INFO("iser created device:%p", isert_dev);
	return isert_dev;

fail_cq:
	for (j = 0; j <= i; ++j) {
		if (isert_dev->cq_desc[j].cq)
			ib_destroy_cq(isert_dev->cq_desc[j].cq);
		if (isert_dev->cq_desc[j].cq_workqueue)
			destroy_workqueue(isert_dev->cq_desc[j].cq_workqueue);
	}
	ib_dereg_mr(mr);
fail_mr:
	ib_dealloc_pd(pd);
fail_pd:
	vfree(isert_dev->cq_desc);
fail_alloc_cq_desc:
	kfree(isert_dev->cq_qps);
free_isert_dev:
	kfree(isert_dev);
out:
	TRACE_EXIT_RES(err);
	return ERR_PTR(err);
}

static void isert_device_release(struct isert_device *isert_dev)
{
	int err, i;

	TRACE_ENTRY();

	lockdep_assert_held(&dev_list_mutex);

	isert_dev_list_remove(isert_dev); /* remove from global list */

	for (i = 0; i < isert_dev->num_cqs; ++i) {
		struct isert_cq *cq_desc = &isert_dev->cq_desc[i];

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
		/*
		 * cancel_work_sync() was introduced in 2.6.22. We can
		 * only wait until all scheduled work is done.
		 */
		flush_workqueue(cq_desc->cq_workqueue);
#else
		cancel_work_sync(&cq_desc->cq_comp_work);
#endif

		err = ib_destroy_cq(cq_desc->cq);
		if (unlikely(err))
			PRINT_ERROR("Failed to destroy cq, err:%d", err);

		destroy_workqueue(cq_desc->cq_workqueue);
	}

	err = ib_dereg_mr(isert_dev->mr);
	if (unlikely(err))
		PRINT_ERROR("Failed to destroy mr, err:%d", err);
	ib_dealloc_pd(isert_dev->pd);

	vfree(isert_dev->cq_desc);
	isert_dev->cq_desc = NULL;

	kfree(isert_dev->cq_qps);
	isert_dev->cq_qps = NULL;

	kfree(isert_dev);

	TRACE_EXIT();
}

static int isert_get_cq_idx(struct isert_device *isert_dev)
{
	int i, min_idx;

	min_idx = 0;
	mutex_lock(&dev_list_mutex);
	for (i = 0; i < isert_dev->num_cqs; ++i)
		if (isert_dev->cq_qps[i] < isert_dev->cq_qps[min_idx])
			min_idx = i;
	isert_dev->cq_qps[min_idx]++;
	mutex_unlock(&dev_list_mutex);

	return min_idx;
}

static int isert_conn_qp_create(struct isert_connection *isert_conn)
{
	struct rdma_cm_id *cm_id = isert_conn->cm_id;
	struct isert_device *isert_dev = isert_conn->isert_dev;
	struct ib_qp_init_attr qp_attr;
	int err;
	int cq_idx;
	int max_wr = ISER_MAX_WCE;

	TRACE_ENTRY();

	cq_idx = isert_get_cq_idx(isert_dev);

	memset(&qp_attr, 0, sizeof(qp_attr));

	qp_attr.event_handler = isert_async_evt_handler;
	qp_attr.qp_context = isert_conn;
	qp_attr.send_cq = isert_dev->cq_desc[cq_idx].cq;
	qp_attr.recv_cq = isert_dev->cq_desc[cq_idx].cq;

	isert_conn->cq_desc = &isert_dev->cq_desc[cq_idx];

	qp_attr.cap.max_send_sge = isert_conn->max_sge;
	qp_attr.cap.max_recv_sge = 3;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;

	do {
		if (max_wr < ISER_MIN_SQ_SIZE) {
			PRINT_ERROR("Failed to create qp, not enough memory");
			goto fail_create_qp;
		}

		qp_attr.cap.max_send_wr = max_wr;
		qp_attr.cap.max_recv_wr = max_wr;

		err = rdma_create_qp(cm_id, isert_dev->pd, &qp_attr);
		if (err && err != -ENOMEM) {
			PRINT_ERROR("Failed to create qp, err:%d", err);
			goto fail_create_qp;
		}

		max_wr /= 2;
	} while (err == -ENOMEM);

	isert_conn->qp = cm_id->qp;

	PRINT_INFO("iser created cm_id:%p qp:0x%X", cm_id, cm_id->qp->qp_num);

out:
	TRACE_EXIT_RES(err);
	return err;

fail_create_qp:
	mutex_lock(&dev_list_mutex);
	isert_dev->cq_qps[cq_idx]--;
	mutex_unlock(&dev_list_mutex);
	goto out;
}

static struct isert_connection *isert_conn_create(struct rdma_cm_id *cm_id,
						  struct isert_device *isert_dev)
{
	struct isert_connection *isert_conn;
	int err;
	struct isert_cq *cq;

	TRACE_ENTRY();

	isert_conn = isert_conn_zalloc();
	if (unlikely(!isert_conn)) {
		PRINT_ERROR("Unable to allocate iser conn, cm_id:%p", cm_id);
		err = -ENOMEM;
		goto fail_alloc;
	}
	isert_conn->state = ISER_CONN_INIT;
	isert_conn->cm_id = cm_id;
	isert_conn->isert_dev = isert_dev;

	/*
	 * A quote from the OFED 1.5.3.1 release notes
	 * (docs/release_notes/mthca_release_notes.txt), section "Known Issues":
	 * In mem-free devices, RC QPs can be created with a maximum of
	 * (max_sge - 1) entries only; UD QPs can be created with a maximum of
	 * (max_sge - 3) entries.
	 * A quote from the OFED 1.2.5 release notes
	 * (docs/mthca_release_notes.txt), section "Known Issues":
	 * In mem-free devices, RC QPs can be created with a maximum of
	 * (max_sge - 3) entries only.
	 */
	isert_conn->max_sge = isert_dev->device_attr.max_sge - 3;

	WARN_ON(isert_conn->max_sge < 1);

	INIT_LIST_HEAD(&isert_conn->rx_buf_list);
	INIT_LIST_HEAD(&isert_conn->tx_free_list);
	INIT_LIST_HEAD(&isert_conn->tx_busy_list);
	spin_lock_init(&isert_conn->tx_lock);
	spin_lock_init(&isert_conn->post_recv_lock);

	isert_conn->login_req_pdu = isert_rx_pdu_alloc(isert_conn,
						       ISER_MAX_LOGIN_RDSL);
	if (unlikely(!isert_conn->login_req_pdu)) {
		PRINT_ERROR("Failed to init login req rx pdu");
		err = -ENOMEM;
		goto fail_login_req_pdu;
	}

	isert_conn->login_rsp_pdu = isert_tx_pdu_alloc(isert_conn,
						       ISER_MAX_LOGIN_RDSL);
	if (unlikely(!isert_conn->login_rsp_pdu)) {
		PRINT_ERROR("Failed to init login rsp tx pdu");
		err = -ENOMEM;
		goto fail_login_rsp_pdu;
	}

	err = isert_conn_qp_create(isert_conn);
	if (unlikely(err))
		goto fail_qp;

	err = isert_post_recv(isert_conn, &isert_conn->login_req_pdu->wr[0], 1);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to post recv login req rx buf, err:%d", err);
		goto fail_post_recv;
	}

	kref_init(&isert_conn->kref);

	TRACE_EXIT();
	return isert_conn;

fail_post_recv:
	cq = isert_conn->qp->recv_cq->cq_context;
	mutex_lock(&dev_list_mutex);
	isert_dev->cq_qps[cq->idx]--;
	mutex_unlock(&dev_list_mutex);
	rdma_destroy_qp(isert_conn->cm_id);
fail_qp:
	isert_pdu_free(isert_conn->login_rsp_pdu);
fail_login_rsp_pdu:
	isert_pdu_free(isert_conn->login_req_pdu);
fail_login_req_pdu:
	isert_conn_kfree(isert_conn);
fail_alloc:
	module_put(THIS_MODULE);
	TRACE_EXIT_RES(err);
	return ERR_PTR(err);
}

static void isert_deref_device(struct isert_device *isert_dev)
{
	isert_dev->refcnt--;
	if (isert_dev->refcnt == 0)
		isert_device_release(isert_dev);
}

static void isert_kref_free(struct kref *kref)
{
	struct isert_conn_dev *dev;
	struct isert_connection *isert_conn = container_of(kref,
							   struct isert_connection,
							   kref);
	struct isert_device *isert_dev = isert_conn->isert_dev;
	struct isert_cq *cq = isert_conn->qp->recv_cq->cq_context;

	TRACE_ENTRY();

	PRINT_INFO("free conn:%p", isert_conn);

	isert_free_conn_resources(isert_conn);

	rdma_destroy_id(isert_conn->cm_id);
	isert_conn->cm_id = NULL;

	dev = isert_get_priv(&isert_conn->iscsi);
	if (dev) {
		isert_del_timer(dev);
		set_bit(ISERT_CONN_PASSED, &dev->flags);
		dev->conn = NULL;
		dev->state = CS_DISCONNECTED;
	}

	ib_destroy_qp(isert_conn->qp);
	isert_conn->qp = NULL;

	mutex_lock(&dev_list_mutex);
	isert_dev->cq_qps[cq->idx]--;
	list_del(&isert_conn->portal_node);
	isert_deref_device(isert_dev);
	if (unlikely(isert_conn->portal->state == ISERT_PORTAL_INACTIVE))
		isert_portal_free(isert_conn->portal);
	mutex_unlock(&dev_list_mutex);

	isert_conn_kfree(isert_conn);

	module_put(THIS_MODULE);

	TRACE_EXIT();
}

void isert_conn_free(struct isert_connection *isert_conn)
{
	sBUG_ON(atomic_read(&isert_conn->kref.refcount) == 0);
	kref_put(&isert_conn->kref, isert_kref_free);
}

static int isert_cm_timewait_exit_handler(struct rdma_cm_id *cm_id,
					  struct rdma_cm_event *event)
{
	struct isert_connection *isert_conn = cm_id->qp->qp_context;

	isert_sched_conn_closed(isert_conn);
	return 0;
}

static int isert_cm_conn_req_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *event)
{
	/* passed in rdma_create_id */
	struct isert_portal *portal = cm_id->context;
	struct ib_device *ib_dev = cm_id->device;
	struct isert_device *isert_dev;
	struct isert_connection *isert_conn;
	struct rdma_conn_param *ini_conn_param;
	struct rdma_conn_param tgt_conn_param;
	struct isert_cm_hdr cm_hdr = { 0 };
	int err;

	TRACE_ENTRY();

	if (unlikely(!try_module_get(THIS_MODULE))) {
		err = -EINVAL;
		goto fail_get;
	}

	mutex_lock(&dev_list_mutex);
	isert_dev = isert_device_find(ib_dev);
	if (!isert_dev) {
		isert_dev = isert_device_create(ib_dev);
		if (unlikely(IS_ERR(isert_dev))) {
			err = PTR_ERR(isert_dev);
			mutex_unlock(&dev_list_mutex);
			goto fail_dev_create;
		}
	}
	isert_dev->refcnt++;
	mutex_unlock(&dev_list_mutex);

	isert_conn = isert_conn_create(cm_id, isert_dev);
	if (unlikely(IS_ERR(isert_conn))) {
		err = PTR_ERR(isert_conn);
		goto fail_conn_create;
	}

	isert_conn->state = ISER_CONN_HANDSHAKE;
	isert_conn->portal = portal;

	mutex_lock(&dev_list_mutex);
	list_add_tail(&isert_conn->portal_node, &portal->conn_list);
	mutex_unlock(&dev_list_mutex);

	/* initiator is dst, target is src */
	memcpy(&isert_conn->peer_addr, &cm_id->route.addr.dst_addr,
	       sizeof(isert_conn->peer_addr));
	memcpy(&isert_conn->self_addr, &cm_id->route.addr.src_addr,
	       sizeof(isert_conn->self_addr));

	ini_conn_param = &event->param.conn;
	memset(&tgt_conn_param, 0, sizeof(tgt_conn_param));
	tgt_conn_param.flow_control =
		ini_conn_param->flow_control;
	tgt_conn_param.rnr_retry_count =
		ini_conn_param->rnr_retry_count;

	tgt_conn_param.initiator_depth = isert_dev->device_attr.max_qp_init_rd_atom;
	if (tgt_conn_param.initiator_depth > ini_conn_param->initiator_depth)
		tgt_conn_param.initiator_depth = ini_conn_param->initiator_depth;

	tgt_conn_param.private_data_len = sizeof(cm_hdr);
	tgt_conn_param.private_data = &cm_hdr;
	cm_hdr.flags = ISER_ZBVA_NOT_SUPPORTED | ISER_SEND_W_INV_NOT_SUPPORTED;

	kref_get(&isert_conn->kref);

	err = rdma_accept(cm_id, &tgt_conn_param);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to accept conn request, err:%d", err);
		goto fail_accept;
	}

	switch (isert_conn->peer_addr.ss_family) {
	case AF_INET:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		PRINT_INFO("iser accepted connection cm_id:%p "
			   NIPQUAD_FMT "->" NIPQUAD_FMT, cm_id,
			   NIPQUAD(((struct sockaddr_in *)&isert_conn->peer_addr)->sin_addr.s_addr),
			   NIPQUAD(((struct sockaddr_in *)&isert_conn->self_addr)->sin_addr.s_addr));
#else
		PRINT_INFO("iser accepted connection cm_id:%p "
			   "%pI4->%pI4", cm_id,
			   &((struct sockaddr_in *)&isert_conn->peer_addr)->sin_addr.s_addr,
			   &((struct sockaddr_in *)&isert_conn->self_addr)->sin_addr.s_addr);
#endif
		break;
	case AF_INET6:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		PRINT_INFO("iser accepted connection cm_id:%p "
			   NIP6_FMT "->" NIP6_FMT, cm_id,
			   NIP6(((struct sockaddr_in6 *)&isert_conn->peer_addr)->sin6_addr),
			   NIP6(((struct sockaddr_in6 *)&isert_conn->self_addr)->sin6_addr));
#else
		PRINT_INFO("iser accepted connection cm_id:%p "
			   "%pI6->%pI6", cm_id,
			   &((struct sockaddr_in6 *)&isert_conn->peer_addr)->sin6_addr,
			   &((struct sockaddr_in6 *)&isert_conn->self_addr)->sin6_addr);
#endif
		break;
	default:
		PRINT_INFO("iser accepted connection cm_id:%p", cm_id);
	}

out:
	TRACE_EXIT_RES(err);
	return err;

fail_accept:
	set_bit(ISERT_CONNECTION_ABORTED, &isert_conn->flags);
	isert_conn_free(isert_conn);
	isert_sched_conn_free(isert_conn);
	err = 0;
	goto out;

fail_conn_create:
	mutex_lock(&dev_list_mutex);
	isert_deref_device(isert_dev);
	mutex_unlock(&dev_list_mutex);
fail_dev_create:
	rdma_reject(cm_id, NULL, 0);
fail_get:
	module_put(THIS_MODULE);
	goto out;
}

static int isert_cm_connect_handler(struct rdma_cm_id *cm_id,
				    struct rdma_cm_event *event)
{
	struct isert_connection *isert_conn = cm_id->qp->qp_context;
	int push_saved_pdu = 0;
	int ret;

	TRACE_ENTRY();

	if (isert_conn->state == ISER_CONN_HANDSHAKE)
		isert_conn->state = ISER_CONN_ACTIVE;
	else if (isert_conn->state == ISER_CONN_ACTIVE)
		push_saved_pdu = 1;

	ret = isert_get_addr_size((struct sockaddr *)&isert_conn->peer_addr,
				  &isert_conn->peer_addrsz);
	if (unlikely(ret))
		goto out;

	/* check if already started teardown */
	if (!unlikely(kref_get_unless_zero(&isert_conn->kref)))
		goto out;

	/* notify upper layer */
	ret = isert_conn_established(&isert_conn->iscsi,
				     (struct sockaddr *)&isert_conn->peer_addr,
				     isert_conn->peer_addrsz);
	if (unlikely(ret)) {
		set_bit(ISERT_CONNECTION_ABORTED, &isert_conn->flags);
		isert_post_drain(isert_conn);
		isert_conn_free(isert_conn);
		goto out;
	}

	set_bit(ISERT_CONNECTION_EST, &isert_conn->flags);

	if (push_saved_pdu) {
		PRINT_INFO("iser push saved rx pdu");
		isert_recv_completion_handler(isert_conn->saved_wr);
		isert_conn->saved_wr = NULL;
	}

out:
	TRACE_EXIT_RES(ret);
	return ret;
}

static int isert_cm_disconnect_handler(struct rdma_cm_id *cm_id,
				       struct rdma_cm_event *event)
{
	struct isert_connection *isert_conn = cm_id->qp->qp_context;

	isert_conn_disconnect(isert_conn);

	return 0;
}

static const char *cm_event_type_str(enum rdma_cm_event_type ev_type)
{
	switch (ev_type) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		return "ADDRESS_RESOLVED";
	case RDMA_CM_EVENT_ADDR_ERROR:
		return "ADDESS_ERROR";
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		return "ROUTE_RESOLVED";
	case RDMA_CM_EVENT_ROUTE_ERROR:
		return "ROUTE_ERROR";
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		return "CONNECT_REQUEST";
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		return "CONNECT_RESPONSE";
	case RDMA_CM_EVENT_CONNECT_ERROR:
		return "CONNECT_ERROR";
	case RDMA_CM_EVENT_UNREACHABLE:
		return "UNREACHABLE";
	case RDMA_CM_EVENT_REJECTED:
		return "REJECTED";
	case RDMA_CM_EVENT_ESTABLISHED:
		return "ESTABLISHED";
	case RDMA_CM_EVENT_DISCONNECTED:
		return "DISCONNECTED";
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		return "DEVICE_REMOVAL";
	case RDMA_CM_EVENT_MULTICAST_JOIN:
		return "MULTICAST_JOIN";
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		return "MULTICAST_ERROR";
	case RDMA_CM_EVENT_ADDR_CHANGE:
		return "ADDR_CHANGE";
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		return "TIMEWAIT_EXIT";
	default:
		return "UNKNOWN";
	}
}

static int isert_handle_failure(struct isert_connection *conn)
{
	isert_conn_disconnect(conn);
	return 0;
}

static int isert_cm_evt_listener_handler(struct rdma_cm_id *cm_id,
					 struct rdma_cm_event *cm_ev)
{
	enum rdma_cm_event_type ev_type;
	struct isert_portal *portal;
	int err = 0;

	ev_type = cm_ev->event;
	portal = cm_id->context;

	switch (ev_type) {
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		portal->cm_id = NULL;
		err = -EINVAL;
		break;

	default:
		PRINT_INFO("Listener event:%s(%d), ignored",
			   cm_event_type_str(ev_type), ev_type);
		break;
	}

	return err;
}

static int isert_cm_evt_handler(struct rdma_cm_id *cm_id,
				struct rdma_cm_event *cm_ev)
{
	enum rdma_cm_event_type ev_type;
	struct isert_portal *portal;
	int err = -EINVAL;

	TRACE_ENTRY();

	ev_type = cm_ev->event;
	portal = cm_id->context;
	PRINT_INFO("isert_cm_evt:%s(%d) status:%d portal:%p cm_id:%p",
		   cm_event_type_str(ev_type), ev_type, cm_ev->status,
		   portal, cm_id);

	if (portal->cm_id == cm_id) {
		err = isert_cm_evt_listener_handler(cm_id, cm_ev);
		goto out;
	}

	switch (ev_type) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		err = isert_cm_conn_req_handler(cm_id, cm_ev);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		err = isert_cm_connect_handler(cm_id, cm_ev);
		if (unlikely(err))
			err = isert_handle_failure(cm_id->qp->qp_context);
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_REJECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_DISCONNECTED:
		err = isert_cm_disconnect_handler(cm_id, cm_ev);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		isert_cm_disconnect_handler(cm_id, cm_ev);
		err = isert_cm_timewait_exit_handler(cm_id, cm_ev);
		break;

	case RDMA_CM_EVENT_MULTICAST_JOIN:
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		PRINT_ERROR("UD-related event:%d, ignored", ev_type);
		break;

	case RDMA_CM_EVENT_ADDR_RESOLVED:
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		PRINT_ERROR("Active side event:%d, ignored", ev_type);
		break;

	/* We can receive this instead of RDMA_CM_EVENT_ESTABLISHED */
	case RDMA_CM_EVENT_UNREACHABLE:
		{
			struct isert_connection *isert_conn;

			isert_conn = cm_id->qp->qp_context;
			set_bit(ISERT_CONNECTION_ABORTED, &isert_conn->flags);
			/*
			 * reaching here must be with the isert_conn refcount of 2,
			 * one from the init and one from the connect request,
			 * thus it is safe to deref directly before the sched_conn_free.
			*/
			isert_conn_free(isert_conn);
			isert_sched_conn_free(isert_conn);
			err = 0;
		}
		break;

	default:
		PRINT_ERROR("Illegal event:%d, ignored", ev_type);
		break;
	}

	if (unlikely(err))
		PRINT_ERROR("Failed to handle rdma cm evt:%d, err:%d",
			    ev_type, err);

out:
	TRACE_EXIT_RES(err);
	return err;
}

/* create a portal, after listening starts all events
 * are received in isert_cm_evt_handler()
 */
struct isert_portal *isert_portal_create(void)
{
	struct isert_portal *portal;
	struct rdma_cm_id *cm_id;
	int err;

	if (unlikely(!try_module_get(THIS_MODULE))) {
		PRINT_ERROR("Unable increment module reference");
		portal = ERR_PTR(-EINVAL);
		goto out;
	}

	portal = kzalloc(sizeof(*portal), GFP_KERNEL);
	if (unlikely(!portal)) {
		PRINT_ERROR("Unable to allocate struct portal");
		portal = ERR_PTR(-ENOMEM);
		goto err_alloc;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 <= 5)
	cm_id = rdma_create_id(isert_cm_evt_handler, portal, RDMA_PS_TCP);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	cm_id = rdma_create_id(isert_cm_evt_handler, portal, RDMA_PS_TCP,
			       IB_QPT_RC);
#else
	cm_id = rdma_create_id(&init_net, isert_cm_evt_handler, portal,
			       RDMA_PS_TCP, IB_QPT_RC);
#endif
	if (unlikely(IS_ERR(cm_id))) {
		err = PTR_ERR(cm_id);
		PRINT_ERROR("Failed to create rdma id, err:%d", err);
		goto create_id_err;
	}
	portal->cm_id = cm_id;

	INIT_LIST_HEAD(&portal->conn_list);
	isert_portal_list_add(portal);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	rdma_set_afonly(cm_id, 1);
#endif

	PRINT_INFO("Created iser portal cm_id:%p", cm_id);
out:
	return portal;

create_id_err:
	kfree(portal);
	portal = ERR_PTR(err);
err_alloc:
	module_put(THIS_MODULE);
	goto out;
}

int isert_portal_listen(struct isert_portal *portal,
			struct sockaddr *sa,
			size_t addr_len)
{
	int err;

	TRACE_ENTRY();
	err = rdma_bind_addr(portal->cm_id, sa);
	if (err) {
		PRINT_WARNING("Failed to bind rdma addr, err:%d", err);
		goto out;
	}
	err = rdma_listen(portal->cm_id, ISER_LISTEN_BACKLOG);
	if (err) {
		PRINT_ERROR("Failed rdma listen, err:%d", err);
		goto out;
	}
	memcpy(&portal->addr, sa, addr_len);

	switch (sa->sa_family) {
	case AF_INET:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		PRINT_INFO("iser portal cm_id:%p listens on: "
			   NIPQUAD_FMT ":%d", portal->cm_id,
			   NIPQUAD(((struct sockaddr_in *)sa)->sin_addr.s_addr),
			   (int)ntohs(((struct sockaddr_in *)sa)->sin_port));
#else
		PRINT_INFO("iser portal cm_id:%p listens on: "
			   "%pI4:%d", portal->cm_id,
			   &((struct sockaddr_in *)sa)->sin_addr.s_addr,
			   (int)ntohs(((struct sockaddr_in *)sa)->sin_port));
#endif
		break;
	case AF_INET6:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		PRINT_INFO("iser portal cm_id:%p listens on: "
			   NIP6_FMT " %d",
			   portal->cm_id,
			   NIP6(((struct sockaddr_in6 *)sa)->sin6_addr),
			   (int)ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
#else
		PRINT_INFO("iser portal cm_id:%p listens on: "
			   "%pI6 %d", portal->cm_id,
			   &((struct sockaddr_in6 *)sa)->sin6_addr,
			   (int)ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
#endif
		break;
	default:
		PRINT_ERROR("Unknown address family");
		err = -EINVAL;
		goto out;
	}

out:
	TRACE_EXIT_RES(err);
	return err;
}

static void isert_portal_free(struct isert_portal *portal)
{
	lockdep_assert_held(&dev_list_mutex);

	if (!list_empty(&portal->conn_list))
		return;

	kfree(portal);
	module_put(THIS_MODULE);
}

void isert_portal_release(struct isert_portal *portal)
{
	struct isert_connection *conn;

	PRINT_INFO("iser portal cm_id:%p releasing", portal->cm_id);

	if (portal->cm_id) {
		rdma_destroy_id(portal->cm_id);
		portal->cm_id = NULL;
	}

	isert_portal_list_remove(portal);

	mutex_lock(&dev_list_mutex);
	list_for_each_entry(conn, &portal->conn_list, portal_node)
		isert_conn_disconnect(conn);
	portal->state = ISERT_PORTAL_INACTIVE;
	isert_portal_free(portal);
	mutex_unlock(&dev_list_mutex);
}

struct isert_portal *isert_portal_start(struct sockaddr *sa, size_t addr_len)
{
	struct isert_portal *portal;
	int err;

	portal = isert_portal_create();
	if (unlikely(IS_ERR(portal)))
		return portal;

	err = isert_portal_listen(portal, sa, addr_len);
	if (err) {
		isert_portal_release(portal);
		portal = ERR_PTR(err);
	}
	return portal;
}
