#ifndef __LIBSRP_H__
#define __LIBSRP_H__

#include <linux/list.h>
#include <linux/kfifo.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include <scsi/srp.h>

struct srp_buf {
	dma_addr_t dma;
	void *buf;
};

struct srp_queue {
	void *pool;
	void *items;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	struct kfifo *queue;
#else
	struct kfifo queue;
#endif
	spinlock_t lock;
};

struct srp_target {
	struct scst_tgt *tgt;
	struct device *dev;

	spinlock_t lock;

	size_t srp_iu_size;
	struct srp_queue iu_queue;
	size_t rx_ring_size;
	struct srp_buf **rx_ring;

	void *ldata;
};

struct iu_entry {
	struct srp_target *target;

	dma_addr_t remote_token;
	unsigned long flags;

	struct srp_buf *sbuf;
};

typedef int (srp_rdma_t)(struct scst_cmd *, struct scatterlist *, int,
			 struct srp_direct_buf *, int,
			 enum dma_data_direction, unsigned int);
extern int srp_target_alloc(struct srp_target *, struct device *, size_t, size_t);
extern void srp_target_free(struct srp_target *);

extern struct iu_entry *srp_iu_get(struct srp_target *);
extern void srp_iu_put(struct iu_entry *);

extern int srp_data_length(struct srp_cmd *, enum dma_data_direction);
extern int srp_cmd_queue(struct scst_session *, struct srp_cmd *, void *, int);
extern int srp_transfer_data(struct scst_cmd *, struct srp_cmd *,
			     srp_rdma_t, int, int);


static inline int srp_cmd_direction(struct srp_cmd *cmd)
{
	return (cmd->buf_fmt >> 4) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
}

#endif
