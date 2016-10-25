/*
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

#ifndef __ISER_H__
#define __ISER_H__

#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <rdma/ib_verbs.h>
#if defined(RHEL_MAJOR) && RHEL_MAJOR -0 == 5
static inline u16 vlan_dev_vlan_id(const void *dev)
{
	BUG();
	return 0;
}
#endif
#include <rdma/rdma_cm.h>

#include "iser_hdr.h"

enum isert_portal_state {
	ISERT_PORTAL_ACTIVE,
	ISERT_PORTAL_INACTIVE
};

struct isert_portal {
	struct rdma_cm_id	*cm_id;
	struct sockaddr_storage	addr;
	struct list_head	list_node; /* in portals list */
	/* protected by dev_list_mutex */
	struct list_head	conn_list; /* head of conns list */
	enum isert_portal_state	state;
	int			refcnt;
};

struct isert_buf {
	int			sg_cnt ____cacheline_aligned;
	struct scatterlist	*sg;
	u8			*addr;
	size_t			size;
	enum dma_data_direction	dma_dir;
	unsigned int		is_alloced:1;
	unsigned int		is_pgalloced:1;
	unsigned int		is_malloced:1;
};

enum isert_wr_op {
	ISER_WR_RECV,
	ISER_WR_SEND,
	ISER_WR_RDMA_WRITE,
	ISER_WR_RDMA_READ,
};

struct isert_device;
struct isert_connection;

struct isert_wr {
	enum isert_wr_op	wr_op;
	struct isert_buf	*buf;

	struct isert_connection	*conn;
	struct isert_cmnd	*pdu;

	struct isert_device	*isert_dev;

	struct ib_sge		*sge_list;
	union {
		struct ib_recv_wr recv_wr;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || defined(MOFED_MAJOR)
		struct ib_send_wr send_wr;
#else
		struct ib_rdma_wr send_wr;
#endif
	};
} ____cacheline_aligned;

#define ISER_SQ_SIZE		128
#define ISER_MAX_WCE		2048

#define ISER_MIN_SQ_SIZE	16

struct isert_cmnd {
	struct iscsi_cmnd	iscsi ____cacheline_aligned;

	struct isert_buf	buf;
	struct isert_buf	rdma_buf;
	struct isert_wr		*wr;
	struct ib_sge		*sg_pool;
	int			n_wr;
	int			n_sge;

	struct isert_hdr	*isert_hdr ____cacheline_aligned;
	struct iscsi_hdr	*bhs;
	void			*ahs;
	void			*data;

	u8			isert_opcode;
	u8			iscsi_opcode;
	u8			is_rstag_valid;
	u8			is_wstag_valid;

	u32			rem_write_stag; /* write rkey */
	u64			rem_write_va;
	u32			rem_read_stag;  /* read rkey */
	u64			rem_read_va;

	int			is_fake_rx;
	struct list_head	pool_node; /* pool list */
};

enum isert_conn_state {
	ISER_CONN_INIT = 0,
	ISER_CONN_HANDSHAKE,
	ISER_CONN_ACTIVE,
	ISER_CONN_CLOSING,
};

struct isert_cq {
	struct ib_cq		*cq ____cacheline_aligned;
	struct ib_wc		wc[ISER_SQ_SIZE];
	struct isert_device	*dev;
	struct workqueue_struct	*cq_workqueue;
	struct work_struct	cq_comp_work;
	int			idx;
};

#define ISERT_CONNECTION_ABORTED	0
#define ISERT_DRAIN_POSTED		1
#define ISERT_DISCON_CALLED		2
#define ISERT_DRAINED_RQ		3
#define ISERT_DRAINED_SQ		4
#define ISERT_CONNECTION_CLOSE		5
#define ISERT_IN_PORTAL_LIST		6

struct isert_connection {
	struct iscsi_conn	iscsi ____cacheline_aligned;

	int			repost_threshold ____cacheline_aligned;
	/* access to the following 3 fields is guarded by post_recv_lock */
	int			to_post_recv;
	struct isert_wr		*post_recv_first;
	struct isert_wr		*post_recv_curr;

	spinlock_t		post_recv_lock;


	spinlock_t		tx_lock ____cacheline_aligned;

	/* Following two protected by tx_lock */
	struct list_head	tx_free_list;
	struct list_head	tx_busy_list;

	struct rdma_cm_id	*cm_id;
	struct isert_device	*isert_dev;
	struct ib_qp		*qp;
	struct isert_cq		*cq_desc;

	enum isert_conn_state	state;
	struct mutex		state_mutex;

	u32			responder_resources;
	u32			initiator_depth;
	u32			max_sge;

	/*
	 * Unprotected. Accessed only before login response is sent and when
	 * freeing connection
	 */
	struct list_head	rx_buf_list;

	struct isert_cmnd	*login_req_pdu;
	struct isert_cmnd	*login_rsp_pdu;
	struct isert_wr		*saved_wr;

	int			queue_depth;
	int			immediate_data;
	unsigned int		target_recv_data_length;
	int			initiator_recv_data_length;
	int			initial_r2t;
	unsigned int		first_burst_length;
	struct sockaddr_storage	peer_addr;
	size_t			peer_addrsz;
	struct sockaddr_storage	self_addr;

	struct list_head	portal_node;

	unsigned long		flags;
	struct work_struct	close_work;
	struct work_struct	drain_work;
	struct work_struct	discon_work;
	struct work_struct	free_work;
	struct isert_wr		drain_wr_sq;
	struct isert_wr		drain_wr_rq;
	struct kref		kref;

	struct isert_portal	*portal;
	void			*priv_data; /* for connection tracking */
};

struct isert_device {
	struct ib_device	*ib_dev;
	struct ib_pd		*pd;
	struct ib_mr		*mr;
	u32			lkey;

	struct list_head	devs_node;
	/* conn_list and refcnt protected by dev_list_mutex */
	struct list_head	conn_list;
	int			refcnt;
	struct ib_device_attr	device_attr;

	int			num_cqs;
	int			*cq_qps;
	struct isert_cq		*cq_desc;
};

struct isert_global {
	spinlock_t		portal_lock;
	/* protected by portal_lock */
	struct list_head	portal_list;
	/* protected by dev_list_mutex */
	struct list_head	dev_list;
	struct workqueue_struct	*conn_wq;
};

#define _ptr_to_u64(p)		(u64)(unsigned long)(p)
#define _u64_to_ptr(v)		(void *)(unsigned long)(v)

/* global iser scope */
int isert_global_init(void);
int isert_datamover_cleanup(void);

void isert_portal_list_add(struct isert_portal *portal);
void isert_portal_list_remove(struct isert_portal *portal);

void isert_dev_list_add(struct isert_device *isert_dev);
void isert_dev_list_remove(struct isert_device *isert_dev);
struct isert_device *isert_device_find(struct ib_device *ib_dev);

void isert_conn_queue_work(struct work_struct *w);

extern struct kmem_cache *isert_cmnd_cache;
extern struct kmem_cache *isert_conn_cache;

/* iser portal */
struct isert_portal *isert_portal_create(void);
int isert_portal_listen(struct isert_portal *portal,
			struct sockaddr *sa,
			size_t addr_len);
void isert_portal_release(struct isert_portal *portal);
void isert_portal_list_release_all(void);
struct isert_portal *isert_portal_start(struct sockaddr *sa, size_t addr_len);

/* iser connection */
int isert_post_recv(struct isert_connection *isert_conn,
		    struct isert_wr *first_wr, int num_wr);
int isert_post_send(struct isert_connection *isert_conn,
		    struct isert_wr *first_wr, int num_wr);

int isert_alloc_conn_resources(struct isert_connection *isert_conn);
void isert_free_conn_resources(struct isert_connection *isert_conn);
void isert_conn_free(struct isert_connection *isert_conn);
void isert_conn_disconnect(struct isert_connection *isert_conn);
void isert_post_drain(struct isert_connection *isert_conn);
void isert_sched_conn_free(struct isert_connection *isert_conn);

static inline struct isert_connection *isert_conn_zalloc(void)
{
	return kmem_cache_zalloc(isert_conn_cache, GFP_KERNEL);
}

static inline void isert_conn_kfree(struct isert_connection *isert_conn)
{
	kmem_cache_free(isert_conn_cache, isert_conn);
}

/* iser buf */
int isert_buf_alloc_data_buf(struct ib_device *ib_dev,
			     struct isert_buf *isert_buf, size_t size,
			     enum dma_data_direction dma_dir);
void isert_wr_set_fields(struct isert_wr *wr,
			 struct isert_connection *isert_conn,
			 struct isert_cmnd *pdu);
int isert_wr_init(struct isert_wr *wr,
		  enum isert_wr_op wr_op,
		  struct isert_buf *isert_buf,
		  struct isert_connection *isert_conn,
		  struct isert_cmnd *pdu,
		  struct ib_sge *sge,
		  int sg_offset,
		  int sg_cnt,
		  int buff_offset);
void isert_wr_release(struct isert_wr *wr);

void isert_buf_release(struct isert_buf *isert_buf);

static inline void isert_buf_init_sg(struct isert_buf *isert_buf,
				     struct scatterlist *sg,
				     int sg_cnt, size_t size)
{
	isert_buf->sg_cnt = sg_cnt;
	isert_buf->sg = sg;
	isert_buf->size = size;
}

/* iser pdu */
static inline struct isert_cmnd *isert_pdu_alloc(void)
{
	return kmem_cache_zalloc(isert_cmnd_cache, GFP_KERNEL);
}

static inline void isert_pdu_kfree(struct isert_cmnd *cmnd)
{
	kmem_cache_free(isert_cmnd_cache, cmnd);
}

struct isert_cmnd *isert_rx_pdu_alloc(struct isert_connection *isert_conn,
				      size_t size);
struct isert_cmnd *isert_tx_pdu_alloc(struct isert_connection *isert_conn,
				      size_t size);
void isert_tx_pdu_init(struct isert_cmnd *isert_pdu,
		       struct isert_connection *isert_conn);
int isert_pdu_send(struct isert_connection *isert_conn,
		   struct isert_cmnd *tx_pdu);

int isert_prepare_rdma(struct isert_cmnd *isert_pdu,
		       struct isert_connection *isert_conn,
		       enum isert_wr_op op);
int isert_pdu_post_rdma_write(struct isert_connection *isert_conn,
			      struct isert_cmnd *isert_cmd,
			      struct isert_cmnd *isert_rsp,
			      int wr_cnt);
int isert_pdu_post_rdma_read(struct isert_connection *isert_conn,
			     struct isert_cmnd *isert_cmd,
			     int wr_cnt);

void isert_pdu_free(struct isert_cmnd *pdu);
int isert_rx_pdu_done(struct isert_cmnd *pdu);

void isert_tx_pdu_convert_from_iscsi(struct isert_cmnd *isert_cmnd,
				     struct iscsi_cmnd *iscsi_cmnd);

void isert_tx_pdu_init_iscsi(struct isert_cmnd *isert_pdu);

/* global */
void isert_global_cleanup(void);
int isert_get_addr_size(struct sockaddr *sa, size_t *size);

#endif
