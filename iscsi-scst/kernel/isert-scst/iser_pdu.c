/*
* isert_pdu.c
*
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

#include "isert_dbg.h"
#include "iser.h"
#include "../iscsi.h"
#include "iser_datamover.h"

static inline int isert_pdu_rx_buf_init(struct isert_cmnd *isert_pdu,
				 struct isert_connection *isert_conn)
{
	struct isert_buf *isert_buf = &isert_pdu->buf;

	return isert_wr_init(&isert_pdu->wr[0], ISER_WR_RECV, isert_buf,
			   isert_conn, isert_pdu, isert_pdu->sg_pool,
			   0, isert_buf->sg_cnt, 0);
}

static inline int isert_pdu_tx_buf_init(struct isert_cmnd *isert_pdu,
				 struct isert_connection *isert_conn)
{
	struct isert_buf *isert_buf = &isert_pdu->buf;

	return isert_wr_init(&isert_pdu->wr[0], ISER_WR_SEND, isert_buf,
			   isert_conn, isert_pdu, isert_pdu->sg_pool,
			   0, isert_buf->sg_cnt, 0);
}

static inline void isert_pdu_set_hdr_plain(struct isert_cmnd *isert_pdu)
{
	struct isert_hdr *isert_hdr = isert_pdu->isert_hdr;

	isert_hdr->flags = ISER_ISCSI_CTRL;
	isert_hdr->write_stag = 0;
	isert_hdr->write_va = 0;
	isert_hdr->read_stag = 0;
	isert_hdr->read_va = 0;
}

/* rx pdu should be initialized to get the posted buffer and
 * the associated pointers right; after a pdu is received
 * it should be parsed to setup isert_cmnd + iscsi_cmnd in full
 */
static int isert_rx_pdu_init(struct isert_cmnd *isert_pdu,
			     struct isert_connection *isert_conn)
{
	struct iscsi_cmnd *iscsi_cmnd = &isert_pdu->iscsi;
	int err = isert_pdu_rx_buf_init(isert_pdu, isert_conn);

	if (unlikely(err < 0))
		return err;
	iscsi_cmnd->conn = &isert_conn->iscsi;
	return 0;
}

void isert_tx_pdu_init_iscsi(struct isert_cmnd *isert_pdu)
{
	struct iscsi_cmnd *iscsi_cmnd = &isert_pdu->iscsi;
	struct isert_buf *isert_buf = &isert_pdu->buf;

	memset(iscsi_cmnd, 0, sizeof(*iscsi_cmnd));

	iscsi_cmnd->sg_cnt = isert_buf->sg_cnt;
	iscsi_cmnd->sg = isert_buf->sg;
	iscsi_cmnd->bufflen = isert_buf->size;
}

/* tx pdu should set most of the pointers to enable filling out
 * of the iscsi pdu struct
 */
void isert_tx_pdu_init(struct isert_cmnd *isert_pdu,
		       struct isert_connection *isert_conn)
{
	struct iscsi_cmnd *iscsi_cmnd = &isert_pdu->iscsi;
	struct isert_buf *isert_buf = &isert_pdu->buf;
	void *addr = isert_buf->addr;
	struct iscsi_hdr *bhs = (struct iscsi_hdr *)(addr + sizeof(struct isert_hdr));

	isert_pdu->isert_hdr = (struct isert_hdr *)addr;
	isert_pdu->bhs = bhs;
	isert_pdu->ahs = NULL;

	isert_tx_pdu_init_iscsi(isert_pdu);
	iscsi_cmnd->conn = &isert_conn->iscsi;
}

void isert_tx_pdu_convert_from_iscsi(struct isert_cmnd *isert_cmnd,
				     struct iscsi_cmnd *iscsi_cmnd)
{
	struct iscsi_pdu *iscsi_pdu = &iscsi_cmnd->pdu;

	TRACE_ENTRY();

	memcpy(isert_cmnd->bhs, &iscsi_pdu->bhs, sizeof(*isert_cmnd->bhs));
	if (unlikely(iscsi_pdu->ahssize)) {
		isert_cmnd->ahs = isert_cmnd->bhs + 1;
		memcpy(isert_cmnd->ahs, iscsi_pdu->ahs, iscsi_pdu->ahssize);
	}

#ifdef CONFIG_SCST_EXTRACHECKS
	if (iscsi_cmnd->bufflen)
		EXTRACHECKS_BUG_ON(!iscsi_cmnd->sg);
#endif

	TRACE_EXIT();
	return;
}

static inline int isert_pdu_prepare_send(struct isert_connection *isert_conn,
					  struct isert_cmnd *tx_pdu)
{
	struct isert_device *isert_dev = isert_conn->isert_dev;
	struct ib_sge *sge = tx_pdu->wr[0].sge_list;
	size_t to_sync, size;
	int sg_cnt = 0;

	size = ISER_HDRS_SZ + tx_pdu->iscsi.pdu.ahssize +
		tx_pdu->iscsi.pdu.datasize;
	while (size) {
		to_sync = size > PAGE_SIZE ? PAGE_SIZE : size;
		ib_dma_sync_single_for_device(isert_dev->ib_dev, sge->addr,
					      to_sync,
					      DMA_TO_DEVICE);

		sge->length = to_sync;
		size -= to_sync;
		++sge;
		++sg_cnt;
	}

	return sg_cnt;
}

static int isert_alloc_for_rdma(struct isert_cmnd *pdu, int sge_cnt,
				struct isert_connection *isert_conn)
{
	struct isert_wr *wr;
	struct ib_sge *sg_pool;
	int i, ret = 0;
	int wr_cnt;

	sg_pool = kmalloc_array(sge_cnt, sizeof(*sg_pool), GFP_KERNEL);
	if (unlikely(sg_pool == NULL)) {
		ret = -ENOMEM;
		goto out;
	}

	wr_cnt = DIV_ROUND_UP(sge_cnt, isert_conn->max_sge);
	wr = kmalloc_array(wr_cnt, sizeof(*wr), GFP_KERNEL);
	if (unlikely(wr == NULL)) {
		ret = -ENOMEM;
		goto out_free_sg_pool;
	}

	kfree(pdu->wr);
	pdu->wr = wr;

	kfree(pdu->sg_pool);
	pdu->sg_pool = sg_pool;

	pdu->n_wr = wr_cnt;
	pdu->n_sge = sge_cnt;

	for (i = 0; i < wr_cnt; ++i)
		isert_wr_set_fields(&pdu->wr[i], isert_conn, pdu);

	for (i = 0; i < sge_cnt; ++i)
		pdu->sg_pool[i].lkey = isert_conn->isert_dev->lkey;

	goto out;

out_free_sg_pool:
	kfree(sg_pool);
out:
	return ret;
}

static inline void isert_link_send_wrs(struct isert_wr *from_wr,
				       struct isert_wr *to_wr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
	from_wr->send_wr.next = &to_wr->send_wr;
#else
	from_wr->send_wr.wr.next = &to_wr->send_wr.wr;
#endif
}

static inline void isert_link_send_pdu_wrs(struct isert_cmnd *from_pdu,
					   struct isert_cmnd *to_pdu,
					   int wr_cnt)
{
	isert_link_send_wrs(&from_pdu->wr[wr_cnt - 1], &to_pdu->wr[0]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
	to_pdu->wr[0].send_wr.next = NULL;
#else
	to_pdu->wr[0].send_wr.wr.next = NULL;
#endif
}

int isert_prepare_rdma(struct isert_cmnd *isert_pdu,
		       struct isert_connection *isert_conn,
		       enum isert_wr_op op)
{
	struct isert_buf *isert_buf = &isert_pdu->rdma_buf;
	struct isert_device *isert_dev = isert_conn->isert_dev;
	struct ib_device *ib_dev = isert_dev->ib_dev;
	int err;
	int buff_offset;
	int sg_offset, sg_cnt;
	int wr_cnt, i;

	isert_buf_init_sg(isert_buf, isert_pdu->iscsi.sg,
			  isert_pdu->iscsi.sg_cnt,
			  isert_pdu->iscsi.bufflen);

	if (op == ISER_WR_RDMA_WRITE)
		isert_buf->dma_dir = DMA_TO_DEVICE;
	else
		isert_buf->dma_dir = DMA_FROM_DEVICE;

	if (unlikely(isert_buf->sg_cnt > isert_pdu->n_sge)) {
		wr_cnt = isert_alloc_for_rdma(isert_pdu, isert_buf->sg_cnt, isert_conn);
		if (unlikely(wr_cnt))
			goto out;
	}

	err = ib_dma_map_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt,
			    isert_buf->dma_dir);
	if (unlikely(!err)) {
		PRINT_ERROR("Failed to DMA map iser sg:%p len:%d",
			    isert_buf->sg, isert_buf->sg_cnt);
		wr_cnt = -EFAULT;
		goto out;
	}

	buff_offset = 0;
	sg_cnt = 0;
	for (wr_cnt = 0, sg_offset = 0; sg_offset < isert_buf->sg_cnt; ++wr_cnt) {
		sg_cnt = min((int)isert_conn->max_sge,
			     isert_buf->sg_cnt - sg_offset);
		err = isert_wr_init(&isert_pdu->wr[wr_cnt], op, isert_buf,
				    isert_conn, isert_pdu, isert_pdu->sg_pool,
				    sg_offset, sg_cnt, buff_offset);
		if (unlikely(err < 0)) {
			wr_cnt = err;
			goto out;
		}
		buff_offset = err;
		sg_offset += sg_cnt;
	}

	for (i = 1; i < wr_cnt; ++i)
		isert_link_send_wrs(&isert_pdu->wr[i - 1], &isert_pdu->wr[i]);

	if (op == ISER_WR_RDMA_READ) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
		isert_pdu->wr[wr_cnt - 1].send_wr.send_flags = IB_SEND_SIGNALED;
		isert_pdu->wr[wr_cnt - 1].send_wr.next = NULL;
#else
		isert_pdu->wr[wr_cnt - 1].send_wr.wr.send_flags =
			IB_SEND_SIGNALED;
		isert_pdu->wr[wr_cnt - 1].send_wr.wr.next = NULL;
#endif
	}

out:
	TRACE_EXIT_RES(wr_cnt);
	return wr_cnt;
}

void isert_pdu_free(struct isert_cmnd *pdu)
{
	int i;

	list_del(&pdu->pool_node);
	for (i = 0; i < pdu->n_wr; ++i)
		isert_wr_release(&pdu->wr[i]);

	kfree(pdu->wr);
	pdu->wr = NULL;

	kfree(pdu->sg_pool);
	pdu->sg_pool = NULL;

	isert_pdu_kfree(pdu);
}

struct isert_cmnd *isert_rx_pdu_alloc(struct isert_connection *isert_conn,
				      size_t size)
{
	struct isert_cmnd *pdu = NULL;
	int err;

	TRACE_ENTRY();

	pdu = isert_pdu_alloc();
	if (unlikely(!pdu)) {
		PRINT_ERROR("Failed to alloc pdu");
		goto out;
	}

	err = isert_alloc_for_rdma(pdu, 4, isert_conn);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to alloc sge and wr for rx pdu");
		goto out;
	}

	err = isert_buf_alloc_data_buf(isert_conn->isert_dev->ib_dev,
				       &pdu->buf, size, DMA_FROM_DEVICE);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to alloc rx pdu buf sz:%zd", size);
		goto buf_alloc_failed;
	}

	err = isert_rx_pdu_init(pdu, isert_conn);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to init rx pdu wr:%p size:%zd err:%d",
			    &pdu->wr, size, err);
		goto pdu_init_failed;
	}

	list_add_tail(&pdu->pool_node, &isert_conn->rx_buf_list);

	goto out;

pdu_init_failed:
	isert_buf_release(&pdu->buf);
buf_alloc_failed:
	isert_pdu_kfree(pdu);
	pdu = NULL;
out:
	TRACE_EXIT();
	return pdu;
}

struct isert_cmnd *isert_tx_pdu_alloc(struct isert_connection *isert_conn,
				      size_t size)
{
	struct isert_cmnd *pdu = NULL;
	int err;

	TRACE_ENTRY();

	pdu = isert_pdu_alloc();
	if (unlikely(!pdu)) {
		PRINT_ERROR("Failed to alloc pdu");
		goto out;
	}

	err = isert_alloc_for_rdma(pdu, 4, isert_conn);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to alloc sge and wr for tx pdu");
		goto out;
	}

	err = isert_buf_alloc_data_buf(isert_conn->isert_dev->ib_dev,
				       &pdu->buf, size, DMA_TO_DEVICE);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to alloc tx pdu buf sz:%zd", size);
		goto buf_alloc_failed;
	}

	err = isert_pdu_tx_buf_init(pdu, isert_conn);
	if (unlikely(err < 0)) {
		PRINT_ERROR("Failed to init tx pdu wr:%p size:%zd err:%d",
			    &pdu->wr, size, err);
		goto buf_init_failed;
	}

	isert_tx_pdu_init(pdu, isert_conn);

	isert_pdu_set_hdr_plain(pdu);

	list_add_tail(&pdu->pool_node, &isert_conn->tx_free_list);

	goto out;

buf_init_failed:
	isert_buf_release(&pdu->buf);
buf_alloc_failed:
	isert_pdu_kfree(pdu);
	pdu = NULL;
out:
	TRACE_EXIT();
	return pdu;
}

static inline void isert_link_recv_wrs(struct isert_wr *from_wr,
				       struct isert_wr *to_wr)
{
	from_wr->recv_wr.next = &to_wr->recv_wr;

	to_wr->recv_wr.next = NULL;
}

static inline void isert_link_recv_pdu_wrs(struct isert_cmnd *from_pdu,
					   struct isert_cmnd *to_pdu)
{
	isert_link_recv_wrs(&from_pdu->wr[0], &to_pdu->wr[0]);
}

int isert_alloc_conn_resources(struct isert_connection *isert_conn)
{
	struct isert_cmnd *pdu, *prev_pdu = NULL, *first_pdu = NULL;
	int t_datasz = 512; /* RFC states that minimum receive data size is 512 */
	int i_datasz = ISER_HDRS_SZ + SCST_SENSE_BUFFERSIZE;
	int i, err = 0;
	int to_alloc;

	TRACE_ENTRY();

	isert_conn->repost_threshold = 32;
	to_alloc = isert_conn->queue_depth * 2 + isert_conn->repost_threshold;

	if (unlikely(to_alloc > ISER_MAX_WCE)) {
		PRINT_ERROR("QueuedCommands larger than %d not supported",
			    (ISER_MAX_WCE - isert_conn->repost_threshold) / 2);
		err = -EINVAL;
		goto out;
	}

	for (i = 0; i < to_alloc; i++) {
		pdu = isert_rx_pdu_alloc(isert_conn, t_datasz);
		if (unlikely(!pdu)) {
			err = -ENOMEM;
			goto clean_pdus;
		}

		if (unlikely(first_pdu == NULL))
			first_pdu = pdu;
		else
			isert_link_recv_pdu_wrs(prev_pdu, pdu);

		prev_pdu = pdu;

		pdu = isert_tx_pdu_alloc(isert_conn, i_datasz);
		if (unlikely(!pdu)) {
			err = -ENOMEM;
			goto clean_pdus;
		}
	}

	err = isert_post_recv(isert_conn, &first_pdu->wr[0], to_alloc);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to post recv err:%d", err);
		goto clean_pdus;
	}

out:
	TRACE_EXIT_RES(err);
	return err;

clean_pdus:
	isert_free_conn_resources(isert_conn);
	goto out;
}

static int isert_reinit_rx_pdu(struct isert_cmnd *pdu)
{
	struct isert_connection *isert_conn = container_of(pdu->iscsi.conn,
						struct isert_connection, iscsi);

	pdu->is_rstag_valid = 0;
	pdu->is_wstag_valid = 0;

	memset(&pdu->iscsi, 0, sizeof(pdu->iscsi));

	return isert_rx_pdu_init(pdu, isert_conn);
}

int isert_rx_pdu_done(struct isert_cmnd *pdu)
{
	int err;
	struct isert_connection *isert_conn = container_of(pdu->iscsi.conn,
						struct isert_connection, iscsi);

	TRACE_ENTRY();

	err = isert_reinit_rx_pdu(pdu);
	if (unlikely(err))
		goto out;

	spin_lock(&isert_conn->post_recv_lock);
	if (unlikely(isert_conn->to_post_recv == 0))
		isert_conn->post_recv_first = &pdu->wr[0];
	else
		isert_link_recv_wrs(isert_conn->post_recv_curr, &pdu->wr[0]);

	isert_conn->post_recv_curr = &pdu->wr[0];

	if (++isert_conn->to_post_recv > isert_conn->repost_threshold) {
		err = isert_post_recv(isert_conn, isert_conn->post_recv_first,
				     isert_conn->to_post_recv);
		isert_conn->to_post_recv = 0;
	}
	spin_unlock(&isert_conn->post_recv_lock);

out:
	TRACE_EXIT_RES(err);
	return err;
}

void isert_free_conn_resources(struct isert_connection *isert_conn)
{
	struct isert_cmnd *pdu;

	TRACE_ENTRY();

	if (isert_conn->login_rsp_pdu) {
		isert_pdu_free(isert_conn->login_rsp_pdu);
		isert_conn->login_rsp_pdu = NULL;
	}
	if (isert_conn->login_req_pdu) {
		isert_pdu_free(isert_conn->login_req_pdu);
		isert_conn->login_req_pdu = NULL;
	}

	while (!list_empty(&isert_conn->rx_buf_list)) {
		pdu = list_first_entry(&isert_conn->rx_buf_list,
				       struct isert_cmnd, pool_node);
		isert_pdu_free(pdu); /* releases buffer as well */
	}

	spin_lock(&isert_conn->tx_lock);
	while (!list_empty(&isert_conn->tx_free_list)) {
		pdu = list_first_entry(&isert_conn->tx_free_list,
				       struct isert_cmnd, pool_node);
		isert_pdu_free(pdu); /* releases buffer as well */
	}

	while (!list_empty(&isert_conn->tx_busy_list)) {
		pdu = list_first_entry(&isert_conn->tx_busy_list,
				       struct isert_cmnd, pool_node);
		isert_pdu_free(pdu); /* releases buffer as well */
	}
	spin_unlock(&isert_conn->tx_lock);

	TRACE_EXIT();
}

int isert_pdu_send(struct isert_connection *isert_conn,
		   struct isert_cmnd *tx_pdu)
{
	int err;
	struct isert_wr *wr;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	EXTRACHECKS_BUG_ON(!isert_conn);
	EXTRACHECKS_BUG_ON(!tx_pdu);
#endif

	wr = &tx_pdu->wr[0];
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
	wr->send_wr.num_sge = isert_pdu_prepare_send(isert_conn, tx_pdu);
#else
	wr->send_wr.wr.num_sge = isert_pdu_prepare_send(isert_conn, tx_pdu);
#endif

	err = isert_post_send(isert_conn, wr, 1);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to send pdu conn:%p pdu:%p err:%d",
			    isert_conn, tx_pdu, err);
	}

	TRACE_EXIT_RES(err);
	return err;
}

int isert_pdu_post_rdma_write(struct isert_connection *isert_conn,
			      struct isert_cmnd *isert_cmd,
			      struct isert_cmnd *isert_rsp,
			      int wr_cnt)
{
	int err;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
	isert_rsp->wr[0].send_wr.num_sge = isert_pdu_prepare_send(isert_conn,
								  isert_rsp);
#else
	isert_rsp->wr[0].send_wr.wr.num_sge = isert_pdu_prepare_send(isert_conn,
								     isert_rsp);
#endif
	isert_link_send_pdu_wrs(isert_cmd, isert_rsp, wr_cnt);
	err = isert_post_send(isert_conn, &isert_cmd->wr[0], wr_cnt + 1);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to send pdu conn:%p pdu:%p err:%d",
			    isert_conn, isert_cmd, err);
	}

	TRACE_EXIT_RES(err);
	return err;
}

int isert_pdu_post_rdma_read(struct isert_connection *isert_conn,
			     struct isert_cmnd *isert_cmd, int wr_cnt)
{
	int err;

	TRACE_ENTRY();

	err = isert_post_send(isert_conn, &isert_cmd->wr[0], wr_cnt);
	if (unlikely(err)) {
		PRINT_ERROR("Failed to send pdu conn:%p pdu:%p err:%d",
			    isert_conn, isert_cmd, err);
	}

	TRACE_EXIT_RES(err);
	return err;
}

