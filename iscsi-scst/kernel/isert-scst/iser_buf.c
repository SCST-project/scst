/*
* isert_buf.c
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

static int isert_buf_alloc_pg(struct ib_device *ib_dev,
			      struct isert_buf *isert_buf, size_t size,
			      enum dma_data_direction dma_dir)
{
	int res = 0;
	int i;
	struct page *page;

	isert_buf->sg_cnt = DIV_ROUND_UP(size, PAGE_SIZE);
	isert_buf->sg = kmalloc_array(isert_buf->sg_cnt, sizeof(*isert_buf->sg),
				      GFP_KERNEL);
	if (unlikely(!isert_buf->sg)) {
		PRINT_ERROR("Failed to allocate buffer SG");
		res = -ENOMEM;
		goto out;
	}

	sg_init_table(isert_buf->sg, isert_buf->sg_cnt);
	for (i = 0; i < isert_buf->sg_cnt; ++i) {
		size_t page_len = min_t(size_t, size, PAGE_SIZE);

		page = alloc_page(GFP_KERNEL);
		if (unlikely(!page)) {
			PRINT_ERROR("Failed to allocate page");
			res = -ENOMEM;
			goto out_map_failed;
		}
		sg_set_page(&isert_buf->sg[i], page, page_len, 0);
		size -= page_len;
	}

	res = ib_dma_map_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt, dma_dir);
	if (unlikely(!res)) {
		--i; /* do not overrun isert_buf->sg */
		PRINT_ERROR("Failed to DMA map iser sg:%p len:%d",
			    isert_buf->sg, isert_buf->sg_cnt);
		res = -ENOMEM;
		goto out_map_failed;
	}

	isert_buf->addr = sg_virt(&isert_buf->sg[0]);

	res = 0;
	goto out;

out_map_failed:
	for (; i >= 0; --i)
		__free_page(sg_page(&isert_buf->sg[i]));
	kfree(isert_buf->sg);
	isert_buf->sg = NULL;
out:
	return res;
}

static void isert_buf_release_pg(struct isert_buf *isert_buf)
{
	int i;

	for (i = 0; i < isert_buf->sg_cnt; ++i)
		__free_page(sg_page(&isert_buf->sg[i]));
}

static int isert_buf_malloc(struct ib_device *ib_dev,
			    struct isert_buf *isert_buf, size_t size,
			    enum dma_data_direction dma_dir)
{
	int res = 0;

	isert_buf->sg_cnt = 1;
	isert_buf->sg = kmalloc(sizeof(isert_buf->sg[0]), GFP_KERNEL);
	if (unlikely(!isert_buf->sg)) {
		PRINT_ERROR("Failed to allocate buffer SG");
		res = -ENOMEM;
		goto out;
	}

	isert_buf->addr = kmalloc(size, GFP_KERNEL);
	if (unlikely(!isert_buf->addr)) {
		PRINT_ERROR("Failed to allocate data buffer");
		res = -ENOMEM;
		goto data_malloc_failed;
	}

	sg_init_one(&isert_buf->sg[0], isert_buf->addr, size);

	res = ib_dma_map_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt, dma_dir);
	if (unlikely(!res)) {
		PRINT_ERROR("Failed to DMA map iser sg:%p len:%d",
			    isert_buf->sg, isert_buf->sg_cnt);
		res = -ENOMEM;
		goto out_map_failed;
	}

	res = 0;
	goto out;

out_map_failed:
	kfree(isert_buf->addr);
	isert_buf->addr = NULL;
data_malloc_failed:
	kfree(isert_buf->addr);
	isert_buf->addr = NULL;
out:
	return res;
}

static void isert_buf_release_kmalloc(struct isert_buf *isert_buf)
{
	kfree(isert_buf->addr);
	isert_buf->addr = NULL;
}

int isert_buf_alloc_data_buf(struct ib_device *ib_dev,
			     struct isert_buf *isert_buf, size_t size,
			     enum dma_data_direction dma_dir)
{
	int res = 0;

	isert_buf->is_alloced = 0;
	if (size >= PAGE_SIZE) {
		res = isert_buf_alloc_pg(ib_dev, isert_buf, size, dma_dir);
		if (unlikely(res))
			goto out;
		isert_buf->is_pgalloced = 1;
		isert_buf->is_malloced = 0;
		isert_buf->is_alloced = 1;
	} else if (size) {
		res = isert_buf_malloc(ib_dev, isert_buf, size, dma_dir);
		if (unlikely(res))
			goto out;
		isert_buf->is_pgalloced = 0;
		isert_buf->is_malloced = 1;
		isert_buf->is_alloced = 1;
	}

	isert_buf->size = size;
	isert_buf->dma_dir = dma_dir;
out:
	return res;
}

void isert_buf_release(struct isert_buf *isert_buf)
{
	if (isert_buf->is_alloced) {
		if (isert_buf->is_pgalloced)
			isert_buf_release_pg(isert_buf);

		if (isert_buf->is_malloced)
			isert_buf_release_kmalloc(isert_buf);

		isert_buf->is_alloced = 0;
		kfree(isert_buf->sg);
		isert_buf->sg = NULL;
	}
}

void isert_wr_set_fields(struct isert_wr *wr,
			 struct isert_connection *isert_conn,
			 struct isert_cmnd *pdu)
{
	struct isert_device *isert_dev = isert_conn->isert_dev;

	wr->conn = isert_conn;
	wr->pdu = pdu;
	wr->isert_dev = isert_dev;
}

int isert_wr_init(struct isert_wr *wr,
		  enum isert_wr_op wr_op,
		  struct isert_buf *isert_buf,
		  struct isert_connection *isert_conn,
		  struct isert_cmnd *pdu,
		  struct ib_sge *sge,
		  int sg_offset,
		  int sg_cnt,
		  int buff_offset)
{
	enum ib_wr_opcode send_wr_op = IB_WR_SEND;
	struct scatterlist *sg_tmp;
	int i;
	u32 send_flags = 0;

	TRACE_ENTRY();

	switch (wr_op) {
	case ISER_WR_RECV:
		break;
	case ISER_WR_SEND:
		send_flags = IB_SEND_SIGNALED;
		break;
	case ISER_WR_RDMA_READ:
		send_wr_op = IB_WR_RDMA_READ;
		if (unlikely(!pdu->is_wstag_valid)) {
			PRINT_ERROR("No write tag/va specified for RDMA op");
			isert_buf_release(isert_buf);
			buff_offset = -EFAULT;
			goto out;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
		wr->send_wr.wr.rdma.remote_addr = pdu->rem_write_va +
						  buff_offset;
		wr->send_wr.wr.rdma.rkey = pdu->rem_write_stag;
#else
		wr->send_wr.remote_addr = pdu->rem_write_va + buff_offset;
		wr->send_wr.rkey = pdu->rem_write_stag;
#endif
		break;
	case ISER_WR_RDMA_WRITE:
		send_wr_op = IB_WR_RDMA_WRITE;
		if (unlikely(!pdu->is_rstag_valid)) {
			PRINT_ERROR("No read tag/va specified for RDMA op");
			isert_buf_release(isert_buf);
			buff_offset = -EFAULT;
			goto out;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
		wr->send_wr.wr.rdma.remote_addr = pdu->rem_read_va +
						  buff_offset;
		wr->send_wr.wr.rdma.rkey = pdu->rem_read_stag;
#else
		wr->send_wr.remote_addr = pdu->rem_read_va + buff_offset;
		wr->send_wr.rkey = pdu->rem_read_stag;
#endif
		break;
	default:
		BUG();
	}

	EXTRACHECKS_BUG_ON(isert_buf->sg_cnt == 0);

	wr->wr_op = wr_op;
	wr->buf = isert_buf;

	wr->sge_list = sge + sg_offset;

	sg_tmp = &isert_buf->sg[sg_offset];
	for (i = 0; i < sg_cnt; i++, sg_tmp++) {
		wr->sge_list[i].addr = sg_dma_address(sg_tmp);
		wr->sge_list[i].length = sg_dma_len(sg_tmp);
		buff_offset += wr->sge_list[i].length;
	}

	if (wr_op == ISER_WR_RECV) {
		wr->recv_wr.next = NULL;
		wr->recv_wr.wr_id = _ptr_to_u64(wr);
		wr->recv_wr.sg_list = wr->sge_list;
		wr->recv_wr.num_sge = sg_cnt;
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
		wr->send_wr.next = NULL;
		wr->send_wr.wr_id = _ptr_to_u64(wr);
		wr->send_wr.sg_list = wr->sge_list;
		wr->send_wr.num_sge = sg_cnt;
		wr->send_wr.opcode = send_wr_op;
		wr->send_wr.send_flags = send_flags;
#else
		wr->send_wr.wr.next = NULL;
		wr->send_wr.wr.wr_id = _ptr_to_u64(wr);
		wr->send_wr.wr.sg_list = wr->sge_list;
		wr->send_wr.wr.num_sge = sg_cnt;
		wr->send_wr.wr.opcode = send_wr_op;
		wr->send_wr.wr.send_flags = send_flags;
#endif
	}

out:
	TRACE_EXIT_RES(buff_offset);
	return buff_offset;
}

void isert_wr_release(struct isert_wr *wr)
{
	struct isert_buf *isert_buf = wr->buf;

	if (isert_buf && isert_buf->is_alloced) {
		struct isert_device *isert_dev = wr->isert_dev;
		struct ib_device *ib_dev;

		if (isert_buf->sg_cnt) {
			ib_dev = isert_dev->ib_dev;
			ib_dma_unmap_sg(ib_dev, isert_buf->sg, isert_buf->sg_cnt,
					isert_buf->dma_dir);
		}
		isert_buf_release(isert_buf);
	}
	memset(wr, 0, sizeof(*wr));
}

