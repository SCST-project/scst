/*
 * SCSI RDMA Protocol lib functions
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2010 Bart Van Assche <bvanassche@acm.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#ifdef INSIDE_KERNEL_TREE
#include <scsi/srp.h>
#include <scsi/libsrp.h>
#else
#include "srpnew.h"
#include "libsrpnew.h"
#endif

/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	printk(KERN_ERR "%s(%d) " fmt, __func__, __LINE__, ##args); \
} while (0)
/* #define dprintk eprintk */
#define dprintk(fmt, args...)

static int srp_iu_pool_alloc(struct srp_queue *q, size_t max,
			     struct srp_buf **ring)
{
	int i;
	struct iu_entry *iue;

	q->pool = kcalloc(max, sizeof(struct iu_entry *), GFP_KERNEL);
	if (!q->pool)
		return -ENOMEM;
	q->items = kcalloc(max, sizeof(struct iu_entry), GFP_KERNEL);
	if (!q->items)
		goto free_pool;

	spin_lock_init(&q->lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	q->queue = kfifo_init((void *) q->pool, max * sizeof(void *),
			      GFP_KERNEL, &q->lock);
	if (IS_ERR(q->queue))
		goto free_item;
#else
	kfifo_init(&q->queue, (void *) q->pool, max * sizeof(void *));
#endif

	for (i = 0, iue = q->items; i < max; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		__kfifo_put(q->queue, (void *) &iue, sizeof(void *));
#else
		kfifo_in(&q->queue, (void *) &iue, sizeof(void *));
#endif
		iue->sbuf = ring[i];
		iue++;
	}
	return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
free_item:
#endif
	kfree(q->items);
free_pool:
	kfree(q->pool);
	return -ENOMEM;
}

static void srp_iu_pool_free(struct srp_queue *q)
{
	kfree(q->items);
	kfree(q->pool);
}

static struct srp_buf **srp_ring_alloc(struct device *dev,
				       size_t max, size_t size)
{
	int i;
	struct srp_buf **ring;

	ring = kcalloc(max, sizeof(struct srp_buf *), GFP_KERNEL);
	if (!ring)
		return NULL;

	for (i = 0; i < max; i++) {
		ring[i] = kzalloc(sizeof(struct srp_buf), GFP_KERNEL);
		if (!ring[i])
			goto out;
		ring[i]->buf = dma_alloc_coherent(dev, size, &ring[i]->dma,
						  GFP_KERNEL);
		if (!ring[i]->buf)
			goto out;
	}
	return ring;

out:
	for (i = 0; i < max && ring[i]; i++) {
		if (ring[i]->buf)
			dma_free_coherent(dev, size, ring[i]->buf, ring[i]->dma);
		kfree(ring[i]);
	}
	kfree(ring);

	return NULL;
}

static void srp_ring_free(struct device *dev, struct srp_buf **ring, size_t max,
			  size_t size)
{
	int i;

	for (i = 0; i < max; i++) {
		dma_free_coherent(dev, size, ring[i]->buf, ring[i]->dma);
		kfree(ring[i]);
	}
	kfree(ring);
}

int srp_target_alloc(struct srp_target *target, struct device *dev,
		     size_t nr, size_t iu_size)
{
	int err;

	spin_lock_init(&target->lock);

	target->dev = dev;

	target->srp_iu_size = iu_size;
	target->rx_ring_size = nr;
	target->rx_ring = srp_ring_alloc(target->dev, nr, iu_size);
	if (!target->rx_ring)
		return -ENOMEM;
	err = srp_iu_pool_alloc(&target->iu_queue, nr, target->rx_ring);
	if (err)
		goto free_ring;
	dev_set_drvdata(target->dev, target);

	return 0;

free_ring:
	srp_ring_free(target->dev, target->rx_ring, nr, iu_size);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(srp_target_alloc);

void srp_target_free(struct srp_target *target)
{
	dev_set_drvdata(target->dev, NULL);
	srp_ring_free(target->dev, target->rx_ring, target->rx_ring_size,
		      target->srp_iu_size);
	srp_iu_pool_free(&target->iu_queue);
}
EXPORT_SYMBOL_GPL(srp_target_free);

struct iu_entry *srp_iu_get(struct srp_target *target)
{
	struct iu_entry *iue = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	kfifo_get(target->iu_queue.queue, (void *) &iue, sizeof(void *));
#else
	if (kfifo_out_locked(&target->iu_queue.queue, (void *) &iue,
		sizeof(void *), &target->iu_queue.lock) != sizeof(void *)) {
			WARN_ONCE(1, "unexpected fifo state");
			return NULL;
	}
#endif
	if (!iue)
		return iue;
	iue->target = target;
	iue->flags = 0;
	return iue;
}
EXPORT_SYMBOL_GPL(srp_iu_get);

void srp_iu_put(struct iu_entry *iue)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	kfifo_put(iue->target->iu_queue.queue, (void *) &iue, sizeof(void *));
#else
	kfifo_in_locked(&iue->target->iu_queue.queue, (void *) &iue,
			sizeof(void *), &iue->target->iu_queue.lock);
#endif
}
EXPORT_SYMBOL_GPL(srp_iu_put);

static int srp_direct_data(struct scst_cmd *sc, struct srp_direct_buf *md,
			   enum dma_data_direction dir, srp_rdma_t rdma_io,
			   int dma_map)
{
	struct iu_entry *iue = NULL;
	struct scatterlist *sg = NULL;
	int err, nsg = 0, len, sg_cnt;
	u32 tsize;
	enum dma_data_direction dma_dir;

	iue = scst_cmd_get_tgt_priv(sc);
	if (dir == DMA_TO_DEVICE) {
		scst_cmd_get_write_fields(sc, &sg, &sg_cnt);
		tsize = scst_cmd_get_bufflen(sc);
		dma_dir = DMA_FROM_DEVICE;
	} else {
		sg = scst_cmd_get_sg(sc);
		sg_cnt = scst_cmd_get_sg_cnt(sc);
		tsize = scst_cmd_get_adjusted_resp_data_len(sc);
		dma_dir = DMA_TO_DEVICE;
	}

	dprintk("%p %u %u %d\n", iue, tsize, be32_to_cpu(md->len), sg_cnt);

	len = min(tsize, be32_to_cpu(md->len));

	if (dma_map) {
		nsg = dma_map_sg(iue->target->dev, sg, sg_cnt, dma_dir);
		if (!nsg) {
			eprintk(KERN_ERR "fail to map %p %d\n", iue, sg_cnt);
			return -ENOMEM;
		}
	}

	err = rdma_io(sc, sg, nsg, md, 1, dir, len);

	if (dma_map)
		dma_unmap_sg(iue->target->dev, sg, nsg, dma_dir);

	return err;
}

static int srp_indirect_data(struct scst_cmd *sc, struct srp_cmd *cmd,
			     struct srp_indirect_buf *id,
			     enum dma_data_direction dir, srp_rdma_t rdma_io,
			     int dma_map, int ext_desc)
{
	struct iu_entry *iue = NULL;
	struct srp_direct_buf *md = NULL;
	struct scatterlist dummy, *sg = NULL;
	dma_addr_t token = 0;
	int err = 0;
	int nmd, nsg = 0, len, sg_cnt = 0;
	u32 tsize = 0;
	enum dma_data_direction dma_dir;

	iue = scst_cmd_get_tgt_priv(sc);
	if (dir == DMA_TO_DEVICE) {
		scst_cmd_get_write_fields(sc, &sg, &sg_cnt);
		tsize = scst_cmd_get_bufflen(sc);
		dma_dir = DMA_FROM_DEVICE;
	} else {
		sg = scst_cmd_get_sg(sc);
		sg_cnt = scst_cmd_get_sg_cnt(sc);
		tsize = scst_cmd_get_adjusted_resp_data_len(sc);
		dma_dir = DMA_TO_DEVICE;
	}

	dprintk("%p %u %u %d %d\n", iue, tsize, be32_to_cpu(id->len),
		be32_to_cpu(cmd->data_in_desc_cnt),
		be32_to_cpu(cmd->data_out_desc_cnt));

	len = min(tsize, be32_to_cpu(id->len));

	nmd = be32_to_cpu(id->table_desc.len) / sizeof(struct srp_direct_buf);

	if ((dir == DMA_FROM_DEVICE && nmd == cmd->data_in_desc_cnt) ||
	    (dir == DMA_TO_DEVICE && nmd == cmd->data_out_desc_cnt)) {
		md = &id->desc_list[0];
		goto rdma;
	}

	if (ext_desc && dma_map) {
		md = dma_alloc_coherent(iue->target->dev,
					be32_to_cpu(id->table_desc.len),
					&token, GFP_KERNEL);
		if (!md) {
			eprintk("Can't get dma memory %u\n", id->table_desc.len);
			return -ENOMEM;
		}

		sg_init_one(&dummy, md, be32_to_cpu(id->table_desc.len));
		sg_dma_address(&dummy) = token;
		sg_dma_len(&dummy) = be32_to_cpu(id->table_desc.len);
		err = rdma_io(sc, &dummy, 1, &id->table_desc, 1, DMA_TO_DEVICE,
			      be32_to_cpu(id->table_desc.len));
		if (err) {
			eprintk("Error copying indirect table %d\n", err);
			goto free_mem;
		}
	} else {
		eprintk("This command uses external indirect buffer\n");
		return -EINVAL;
	}

rdma:
	if (dma_map) {
		nsg = dma_map_sg(iue->target->dev, sg, sg_cnt, dma_dir);
		if (!nsg) {
			eprintk("fail to map %p %d\n", iue, sg_cnt);
			err = -ENOMEM;
			goto free_mem;
		}
	}

	err = rdma_io(sc, sg, nsg, md, nmd, dir, len);

	if (dma_map)
		dma_unmap_sg(iue->target->dev, sg, nsg, dma_dir);

free_mem:
	if (token && dma_map)
		dma_free_coherent(iue->target->dev,
				  be32_to_cpu(id->table_desc.len), md, token);

	return err;
}

static int data_out_desc_size(struct srp_cmd *cmd)
{
	int size = 0;
	u8 fmt = cmd->buf_fmt >> 4;

	switch (fmt) {
	case SRP_NO_DATA_DESC:
		break;
	case SRP_DATA_DESC_DIRECT:
		size = sizeof(struct srp_direct_buf);
		break;
	case SRP_DATA_DESC_INDIRECT:
		size = sizeof(struct srp_indirect_buf) +
			sizeof(struct srp_direct_buf) * cmd->data_out_desc_cnt;
		break;
	default:
		eprintk("client error. Invalid data_out_format %x\n", fmt);
		break;
	}
	return size;
}

int srp_transfer_data(struct scst_cmd *sc, struct srp_cmd *cmd,
		      srp_rdma_t rdma_io, int dma_map, int ext_desc)
{
	struct srp_direct_buf *md;
	struct srp_indirect_buf *id;
	enum dma_data_direction dir;
	int offset, err = 0;
	u8 format;

	offset = cmd->add_cdb_len & ~3;

	dir = srp_cmd_direction(cmd);
	if (dir == DMA_FROM_DEVICE)
		offset += data_out_desc_size(cmd);

	if (dir == DMA_TO_DEVICE)
		format = cmd->buf_fmt >> 4;
	else
		format = cmd->buf_fmt & ((1U << 4) - 1);

	switch (format) {
	case SRP_NO_DATA_DESC:
		break;
	case SRP_DATA_DESC_DIRECT:
		md = (struct srp_direct_buf *)
			(cmd->add_data + offset);
		err = srp_direct_data(sc, md, dir, rdma_io, dma_map);
		break;
	case SRP_DATA_DESC_INDIRECT:
		id = (struct srp_indirect_buf *)
			(cmd->add_data + offset);
		err = srp_indirect_data(sc, cmd, id, dir, rdma_io, dma_map,
					ext_desc);
		break;
	default:
		eprintk("Unknown format %d %x\n", dir, format);
		err = -EINVAL;
	}

	return err;
}
EXPORT_SYMBOL_GPL(srp_transfer_data);

int srp_data_length(struct srp_cmd *cmd, enum dma_data_direction dir)
{
	struct srp_direct_buf *md;
	struct srp_indirect_buf *id;
	int len = 0, offset = cmd->add_cdb_len & ~3;
	u8 fmt;

	if (dir == DMA_TO_DEVICE)
		fmt = cmd->buf_fmt >> 4;
	else {
		fmt = cmd->buf_fmt & ((1U << 4) - 1);
		offset += data_out_desc_size(cmd);
	}

	switch (fmt) {
	case SRP_NO_DATA_DESC:
		break;
	case SRP_DATA_DESC_DIRECT:
		md = (struct srp_direct_buf *) (cmd->add_data + offset);
		len = be32_to_cpu(md->len);
		break;
	case SRP_DATA_DESC_INDIRECT:
		id = (struct srp_indirect_buf *) (cmd->add_data + offset);
		len = be32_to_cpu(id->len);
		break;
	default:
		eprintk("invalid data format %x\n", fmt);
		break;
	}
	return len;
}
EXPORT_SYMBOL_GPL(srp_data_length);

int srp_cmd_queue(struct scst_session *sess, struct srp_cmd *cmd, void *info,
		  int atomic)
{
	enum dma_data_direction dir;
	struct scst_cmd *sc;
	int tag, len;

	switch (cmd->task_attr) {
	case SRP_SIMPLE_TASK:
		tag = SCST_CMD_QUEUE_SIMPLE;
		break;
	case SRP_ORDERED_TASK:
		tag = SCST_CMD_QUEUE_ORDERED;
		break;
	case SRP_HEAD_TASK:
		tag = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
		break;
	case SRP_ACA_TASK:
		tag = SCST_CMD_QUEUE_ACA;
		break;
	default:
		eprintk("Task attribute %d not supported\n", cmd->task_attr);
		tag = SCST_CMD_QUEUE_ORDERED;
	}

	dir = srp_cmd_direction(cmd);
	len = srp_data_length(cmd, dir);

	dprintk("%p %x %lx %d %d %d %llx\n", info, cmd->cdb[0],
		cmd->lun, dir, len, tag, (unsigned long long) cmd->tag);

	sc = scst_rx_cmd(sess, (u8 *) &cmd->lun, sizeof(cmd->lun),
			 cmd->cdb, sizeof(cmd->cdb), atomic);
	if (!sc)
		return -ENOMEM;

	scst_cmd_set_queue_type(sc, tag);
	scst_cmd_set_tag(sc, cmd->tag);
	scst_cmd_set_tgt_priv(sc, info);
	scst_cmd_set_expected(sc, dir == DMA_TO_DEVICE
			      ? SCST_DATA_WRITE : SCST_DATA_READ, len);
	scst_cmd_init_done(sc, SCST_CONTEXT_THREAD);

	return 0;
}
EXPORT_SYMBOL_GPL(srp_cmd_queue);

MODULE_DESCRIPTION("SCSI RDMA Protocol lib functions");
MODULE_AUTHOR("FUJITA Tomonori");
MODULE_LICENSE("GPL");
