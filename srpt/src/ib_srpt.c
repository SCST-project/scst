/*
 * Copyright (c) 2006 Mellanox Technology Inc.  All rights reserved.
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
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/kthread.h>

#include <asm/atomic.h>

#include "ib_srpt.h"

#define DRV_NAME		"ib_srpt"
#define PFX			DRV_NAME ": "
#define DRV_VERSION		"0.1"
#define DRV_RELDATE		"January 10, 2007"

#define MELLANOX_SRPT_ID_STRING	"Mellanox OFED SRP target"

MODULE_AUTHOR("Vu Pham");
MODULE_DESCRIPTION("InfiniBand SCSI RDMA Protocol target "
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

struct srpt_thread {
	spinlock_t thread_lock;
	struct list_head thread_ioctx_list;
	struct task_struct *thread;
};

static u64 mellanox_ioc_guid = 0;
static struct list_head srpt_devices;
static int thread = 1;
static struct srpt_thread srpt_thread;
DECLARE_WAIT_QUEUE_HEAD(ioctx_list_waitQ);

module_param(thread, int, 0444);
MODULE_PARM_DESC(thread,
		 "Executing ioctx in thread context. Default thread = 1");

static void srpt_add_one(struct ib_device *device);
static void srpt_remove_one(struct ib_device *device);
static int srpt_disconnect_channel(struct srpt_rdma_ch *ch, int dreq);

static struct ib_client srpt_client = {
	.name = DRV_NAME,
	.add = srpt_add_one,
	.remove = srpt_remove_one
};

static void srpt_event_handler(struct ib_event_handler *handler,
			       struct ib_event *event)
{
	struct srpt_device *sdev =
	    ib_get_client_data(event->device, &srpt_client);
	struct srpt_port *sport;

	if (!sdev || sdev->device != event->device)
		return;

	printk(KERN_WARNING PFX "ASYNC event= %d on device= %s\n",
		event->event, sdev->device->name);

	switch (event->event) {
	case IB_EVENT_PORT_ERR:
		if (event->element.port_num <= sdev->device->phys_port_cnt) {
			sport = &sdev->port[event->element.port_num - 1];
			sport->lid = 0;
			sport->sm_lid = 0;
		}
		break;
	case IB_EVENT_PORT_ACTIVE:
	case IB_EVENT_LID_CHANGE:
	case IB_EVENT_PKEY_CHANGE:
	case IB_EVENT_SM_CHANGE:
	case IB_EVENT_CLIENT_REREGISTER:
		if (event->element.port_num <= sdev->device->phys_port_cnt) {
			sport = &sdev->port[event->element.port_num - 1];
			if (!sport->lid && !sport->sm_lid)
				schedule_work(&sport->work);
		}
		break;
	default:
		break;
	}

}

static void srpt_srq_event(struct ib_event *event, void *ctx)
{
	printk(KERN_WARNING PFX "SRQ event %d\n", event->event);
}

static void srpt_qp_event(struct ib_event *event, void *ctx)
{
	struct srpt_rdma_ch *ch = ctx;

	printk(KERN_WARNING PFX "QP event %d on cm_id= %p sess_name= %s state= %d\n",
	       event->event, ch->cm_id, ch->sess_name, ch->state);

	switch (event->event) {
	case IB_EVENT_COMM_EST:
		ib_cm_notify(ch->cm_id, event->event);
		break;
	case IB_EVENT_QP_LAST_WQE_REACHED:
		if (ch->state == RDMA_CHANNEL_LIVE) {
			printk(KERN_WARNING PFX "Schedule CM_DISCONNECT_WORK\n");
			srpt_disconnect_channel(ch, 1);
		}
		break;
	default:
		break;
	}
}

static void srpt_set_ioc(u8 * c_list, u32 slot, u8 value)
{
	u16 id;
	u8 tmp;

	id = (slot - 1) / 2;
	if (slot & 0x1) {
		tmp = c_list[id] & 0xf;
		c_list[id] = (value << 4) | tmp;
	} else {
		tmp = c_list[id] & 0xf0;
		c_list[id] = (value & 0xf) | tmp;
	}
}

static void srpt_get_class_port_info(struct ib_dm_mad *mad)
{
	struct ib_class_port_info *cif;

	cif = (struct ib_class_port_info *)mad->data;
	memset(cif, 0, sizeof *cif);
	cif->base_version = 1;
	cif->class_version = 1;
	cif->resp_time_value = 20;

	mad->mad_hdr.status = 0;
}

static void srpt_get_iou(struct ib_dm_mad *mad)
{
	struct ib_dm_iou_info *ioui;
	u8 slot;
	int i;

	ioui = (struct ib_dm_iou_info *)mad->data;
	ioui->change_id = 1;
	ioui->max_controllers = 16;

	/* set present for slot 1 and empty for the rest */
	srpt_set_ioc(ioui->controller_list, 1, 1);
	for (i = 1, slot = 2; i < 16; i++, slot++)
		srpt_set_ioc(ioui->controller_list, slot, 0);

	mad->mad_hdr.status = 0;
}

static void srpt_get_ioc(struct srpt_device *sdev, u32 slot,
			 struct ib_dm_mad *mad)
{
	struct ib_dm_ioc_profile *iocp;

	iocp = (struct ib_dm_ioc_profile *)mad->data;

	if (!slot || slot > 16) {
		mad->mad_hdr.status = cpu_to_be16(DM_MAD_STATUS_INVALID_FIELD);
		return;
	}

	if (slot > 2) {
		mad->mad_hdr.status = cpu_to_be16(DM_MAD_STATUS_NO_IOC);
		return;
	}

	memset(iocp, 0, sizeof *iocp);
	strcpy(iocp->id_string, MELLANOX_SRPT_ID_STRING);
	iocp->guid = cpu_to_be64(mellanox_ioc_guid);
	iocp->vendor_id = cpu_to_be32(sdev->dev_attr.vendor_id);
	iocp->device_id = cpu_to_be32(sdev->dev_attr.vendor_part_id);
	iocp->device_version = cpu_to_be16(sdev->dev_attr.hw_ver);
	iocp->subsys_vendor_id = cpu_to_be32(sdev->dev_attr.vendor_id);
	iocp->subsys_device_id = 0x0;
	iocp->io_class = cpu_to_be16(SRP_REV16A_IB_IO_CLASS);
	iocp->io_subclass = cpu_to_be16(SRP_IO_SUBCLASS);
	iocp->protocol = cpu_to_be16(SRP_PROTOCOL);
	iocp->protocol_version = cpu_to_be16(SRP_PROTOCOL_VERSION);
	iocp->send_queue_depth = cpu_to_be16(SRPT_SRQ_SIZE);
	iocp->rdma_read_depth = 4;
	iocp->send_size = cpu_to_be32(MAX_MESSAGE_SIZE);
	iocp->rdma_size = cpu_to_be32(MAX_RDMA_SIZE);
	iocp->num_svc_entries = 1;
	iocp->op_cap_mask = SRP_SEND_TO_IOC | SRP_SEND_FROM_IOC |
	    SRP_RDMA_READ_FROM_IOC | SRP_RDMA_WRITE_FROM_IOC;

	mad->mad_hdr.status = 0;
}

static void srpt_get_svc_entries(u16 slot, u8 hi, u8 lo, struct ib_dm_mad *mad)
{
	struct ib_dm_svc_entries *svc_entries;

	if (!slot || slot > 16) {
		mad->mad_hdr.status = cpu_to_be16(DM_MAD_STATUS_INVALID_FIELD);
		return;
	}

	if (slot > 2 || lo > hi || hi > 1) {
		mad->mad_hdr.status = cpu_to_be16(DM_MAD_STATUS_NO_IOC);
		return;
	}

	svc_entries = (struct ib_dm_svc_entries *)mad->data;
	memset(svc_entries, 0, sizeof *svc_entries);
	svc_entries->service_entries[0].id = cpu_to_be64(mellanox_ioc_guid);
	sprintf(svc_entries->service_entries[0].name, "%s%016llx",
		SRP_SERVICE_NAME_PREFIX, (unsigned long long)mellanox_ioc_guid);

	mad->mad_hdr.status = 0;
}

static void srpt_mgmt_method_get(struct srpt_port *sp, struct ib_mad *rq_mad,
				 struct ib_dm_mad *rsp_mad)
{
	u16 attr_id;
	u32 slot;
	u8 hi, lo;

	attr_id = be16_to_cpu(rq_mad->mad_hdr.attr_id);
	switch (attr_id) {
	case DM_ATTR_CLASS_PORT_INFO:
		srpt_get_class_port_info(rsp_mad);
		break;
	case DM_ATTR_IOU_INFO:
		srpt_get_iou(rsp_mad);
		break;
	case DM_ATTR_IOC_PROFILE:
		slot = be32_to_cpu(rq_mad->mad_hdr.attr_mod);
		srpt_get_ioc(sp->sdev, slot, rsp_mad);
		break;
	case DM_ATTR_SVC_ENTRIES:
		slot = be32_to_cpu(rq_mad->mad_hdr.attr_mod);
		hi = (u8) ((slot >> 8) & 0xff);
		lo = (u8) (slot & 0xff);
		slot = (u16) ((slot >> 16) & 0xffff);
		srpt_get_svc_entries(slot, hi, lo, rsp_mad);
		break;
	default:
		rsp_mad->mad_hdr.status =
		    cpu_to_be16(DM_MAD_STATUS_UNSUP_METHOD_ATTR);
		break;
	}
}

static void srpt_mad_send_handler(struct ib_mad_agent *mad_agent,
				  struct ib_mad_send_wc *mad_wc)
{
	ib_destroy_ah(mad_wc->send_buf->ah);
	ib_free_send_mad(mad_wc->send_buf);
}

static void srpt_mad_recv_handler(struct ib_mad_agent *mad_agent,
				  struct ib_mad_recv_wc *mad_wc)
{
	struct srpt_port *sport = (struct srpt_port *)mad_agent->context;
	struct ib_ah *ah;
	struct ib_mad_send_buf *rsp;
	struct ib_dm_mad *dm_mad;

	if (!mad_wc || !mad_wc->recv_buf.mad)
		return;

	ah = ib_create_ah_from_wc(mad_agent->qp->pd, mad_wc->wc,
				  mad_wc->recv_buf.grh, mad_agent->port_num);
	if (IS_ERR(ah))
		goto err;

	rsp = ib_create_send_mad(mad_agent, mad_wc->wc->src_qp,
				 mad_wc->wc->pkey_index, 0,
				 IB_MGMT_DEVICE_HDR, IB_MGMT_DEVICE_DATA,
				 GFP_KERNEL);
	if (IS_ERR(rsp))
		goto err_rsp;

	rsp->ah = ah;

	dm_mad = rsp->mad;
	memcpy(dm_mad, mad_wc->recv_buf.mad, sizeof *dm_mad);
	dm_mad->mad_hdr.method = IB_MGMT_METHOD_GET_RESP;
	dm_mad->mad_hdr.status = 0;

	switch (mad_wc->recv_buf.mad->mad_hdr.method) {
	case IB_MGMT_METHOD_GET:
		srpt_mgmt_method_get(sport, mad_wc->recv_buf.mad, dm_mad);
		break;
	case IB_MGMT_METHOD_SET:
		dm_mad->mad_hdr.status =
		    cpu_to_be16(DM_MAD_STATUS_UNSUP_METHOD_ATTR);
		break;
	default:
		dm_mad->mad_hdr.status =
		    cpu_to_be16(DM_MAD_STATUS_UNSUP_METHOD);
		break;
	}

	if (!ib_post_send_mad(rsp, NULL)) {
		ib_free_recv_mad(mad_wc);
		/* will destroy_ah & free_send_mad in send completion */
		return;
	}

	ib_free_send_mad(rsp);

err_rsp:
	ib_destroy_ah(ah);
err:
	ib_free_recv_mad(mad_wc);
}

static int srpt_refresh_port(struct srpt_port *sport)
{
	struct ib_mad_reg_req reg_req;
	struct ib_port_modify port_modify;
	struct ib_port_attr port_attr;
	int ret;

	memset(&port_modify, 0, sizeof port_modify);
	port_modify.set_port_cap_mask = IB_PORT_DEVICE_MGMT_SUP;
	port_modify.clr_port_cap_mask = 0;

	ret = ib_modify_port(sport->sdev->device, sport->port, 0, &port_modify);
	if (ret)
		goto err_mod_port;

	ret = ib_query_port(sport->sdev->device, sport->port, &port_attr);
	if (ret)
		goto err_query_port;

	sport->sm_lid = port_attr.sm_lid;
	sport->lid = port_attr.lid;

	ret = ib_query_gid(sport->sdev->device, sport->port, 0, &sport->gid);
	if (ret)
		goto err_query_port;

	if (!sport->mad_agent) {
		memset(&reg_req, 0, sizeof reg_req);
		reg_req.mgmt_class = IB_MGMT_CLASS_DEVICE_MGMT;
		reg_req.mgmt_class_version = IB_MGMT_BASE_VERSION;
		set_bit(IB_MGMT_METHOD_GET, reg_req.method_mask);
		set_bit(IB_MGMT_METHOD_SET, reg_req.method_mask);

		sport->mad_agent = ib_register_mad_agent(sport->sdev->device,
							 sport->port,
							 IB_QPT_GSI,
							 &reg_req, 0,
							 srpt_mad_send_handler,
							 srpt_mad_recv_handler,
							 sport);
		if (IS_ERR(sport->mad_agent))
			goto err_query_port;
	}

	return 0;

err_query_port:

	port_modify.set_port_cap_mask = 0;
	port_modify.clr_port_cap_mask = IB_PORT_DEVICE_MGMT_SUP;
	ib_modify_port(sport->sdev->device, sport->port, 0, &port_modify);

err_mod_port:

	return ret;
}

static struct srpt_ioctx *srpt_alloc_ioctx(struct srpt_device *sdev)
{
	struct srpt_ioctx *ioctx;

	ioctx = kmalloc(sizeof *ioctx, GFP_KERNEL);
	if (!ioctx)
		goto out;

	ioctx->buf = kzalloc(MAX_MESSAGE_SIZE, GFP_KERNEL);
	if (!ioctx->buf)
		goto out_free_ioctx;

	ioctx->dma = dma_map_single(sdev->device->dma_device, ioctx->buf,
				    MAX_MESSAGE_SIZE, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(ioctx->dma))
		goto out_free_buf;

	return ioctx;

out_free_buf:
	kfree(ioctx->buf);
out_free_ioctx:
	kfree(ioctx);
out:
	return NULL;
}

static void srpt_free_ioctx(struct srpt_device *sdev, struct srpt_ioctx *ioctx)
{
	if (!ioctx)
		return;

	dma_unmap_single(sdev->device->dma_device, ioctx->dma,
			 MAX_MESSAGE_SIZE, DMA_BIDIRECTIONAL);
	kfree(ioctx->buf);
	kfree(ioctx);
}

static int srpt_alloc_ioctx_ring(struct srpt_device *sdev)
{
	int i;

	for (i = 0; i < SRPT_SRQ_SIZE; ++i) {
		sdev->ioctx_ring[i] = srpt_alloc_ioctx(sdev);

		if (!sdev->ioctx_ring[i])
			goto err;

		sdev->ioctx_ring[i]->index = i;
	}

	return 0;

err:
	while (--i > 0) {
		srpt_free_ioctx(sdev, sdev->ioctx_ring[i]);
		sdev->ioctx_ring[i] = NULL;
	}
	return -ENOMEM;
}

static int srpt_post_recv(struct srpt_device *sdev, struct srpt_ioctx *ioctx)
{
	struct ib_sge list;
	struct ib_recv_wr wr, *bad_wr;

	wr.wr_id = ioctx->index | SRPT_OP_RECV;

	list.addr = ioctx->dma;
	list.length = MAX_MESSAGE_SIZE;
	list.lkey = sdev->mr->lkey;

	wr.next = NULL;
	wr.sg_list = &list;
	wr.num_sge = 1;

	return ib_post_srq_recv(sdev->srq, &wr, &bad_wr);
}

static int srpt_post_send(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx,
			  int len)
{
	struct ib_sge list;
	struct ib_send_wr wr, *bad_wr;
	struct srpt_device *sdev = ch->sport->sdev;

	dma_sync_single_for_device(sdev->device->dma_device, ioctx->dma,
				   MAX_MESSAGE_SIZE, DMA_TO_DEVICE);

	list.addr = ioctx->dma;
	list.length = len;
	list.lkey = sdev->mr->lkey;

	wr.next = NULL;
	wr.wr_id = ioctx->index;
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(ch->qp, &wr, &bad_wr);
}

static int srpt_get_desc_tbl(struct srpt_ioctx *ioctx, struct srp_cmd *srp_cmd,
			     int *ind)
{
	struct srp_indirect_buf *idb;
	struct srp_direct_buf *db;

	*ind = 0;
	if (((srp_cmd->buf_fmt & 0xf) == SRP_DATA_DESC_DIRECT) ||
	    ((srp_cmd->buf_fmt >> 4) == SRP_DATA_DESC_DIRECT)) {
		ioctx->n_rbuf = 1;
		ioctx->rbufs = &ioctx->single_rbuf;

		db = (void *)srp_cmd->add_data;
		memcpy(ioctx->rbufs, db, sizeof *db);
		ioctx->data_len = be32_to_cpu(db->len);
	} else {
		idb = (void *)srp_cmd->add_data;

		ioctx->n_rbuf = be32_to_cpu(idb->table_desc.len) / sizeof *db;

		if (ioctx->n_rbuf >
		    (srp_cmd->data_out_desc_cnt + srp_cmd->data_in_desc_cnt)) {
			*ind = 1;
			ioctx->n_rbuf = 0;
			goto out;
		}

		if (ioctx->n_rbuf == 1)
			ioctx->rbufs = &ioctx->single_rbuf;
		else
			ioctx->rbufs = kmalloc(ioctx->n_rbuf * sizeof *db, GFP_ATOMIC);
		if (!ioctx->rbufs) {
			ioctx->n_rbuf = 0;
			return -ENOMEM;
		}

		db = idb->desc_list;
		memcpy(ioctx->rbufs, db, ioctx->n_rbuf * sizeof *db);
		ioctx->data_len = be32_to_cpu(idb->len);
	}
out:
	return 0;
}

static int srpt_init_ch_qp(struct srpt_rdma_ch *ch, struct ib_qp *qp)
{
	struct ib_qp_attr *attr;
	int ret;

	attr = kzalloc(sizeof *attr, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_INIT;
	attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ |
	    IB_ACCESS_REMOTE_WRITE;
	attr->port_num = ch->sport->port;
	attr->pkey_index = 0;

	ret = ib_modify_qp(qp, attr,
			   IB_QP_STATE | IB_QP_ACCESS_FLAGS | IB_QP_PORT |
			   IB_QP_PKEY_INDEX);

	kfree(attr);
	return ret;
}

static int srpt_ch_qp_rtr_rts(struct srpt_rdma_ch *ch, struct ib_qp *qp,
			      enum ib_qp_state qp_state)
{
	struct ib_qp_attr *qp_attr;
	int attr_mask;
	int ret;

	qp_attr = kmalloc(sizeof *qp_attr, GFP_KERNEL);
	if (!qp_attr)
		return -ENOMEM;

	qp_attr->qp_state = qp_state;
	ret = ib_cm_init_qp_attr(ch->cm_id, qp_attr, &attr_mask);
	if (ret)
		goto out;

	if (qp_state == IB_QPS_RTR)
		qp_attr->max_dest_rd_atomic = 4;
	else
		qp_attr->max_rd_atomic = 4;

	ret = ib_modify_qp(qp, qp_attr, attr_mask);

out:
	kfree(qp_attr);
	return ret;
}

static void srpt_reset_ioctx(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx)
{
	int i;

	if (ioctx->n_rdma_ius > 0 && ioctx->rdma_ius) {
		struct rdma_iu *riu = ioctx->rdma_ius;

		for (i = 0; i < ioctx->n_rdma_ius; ++i, ++riu) {
			if (riu->sge)
				kfree(riu->sge);
		}
		kfree(ioctx->rdma_ius);
	}

	if (ioctx->n_rbuf > 1 && ioctx->rbufs)
		kfree(ioctx->rbufs);

	if (srpt_post_recv(ch->sport->sdev, ioctx))
		printk(KERN_ERR PFX "SRQ post_recv failed - this is serious\n");
		/* we should queue it back to free_ioctx queue */
	else
		atomic_inc(&ch->req_lim_delta);
}

static void srpt_handle_err_comp(struct srpt_rdma_ch *ch, struct ib_wc *wc)
{
	struct srpt_ioctx *ioctx;
	struct srpt_device *sdev = ch->sport->sdev;
	scst_data_direction dir = SCST_DATA_NONE;

	if (wc->wr_id & SRPT_OP_RECV) {
		ioctx = sdev->ioctx_ring[wc->wr_id & ~SRPT_OP_RECV];
		printk(KERN_ERR PFX "This is serious - SRQ is in bad state\n");
	} else {
		ioctx = sdev->ioctx_ring[wc->wr_id];

		if (ioctx->scmnd) {
			struct scst_cmd *scmnd = ioctx->scmnd;

			dir = scst_cmd_get_data_direction(scmnd);

			if (dir == SCST_DATA_NONE)
				scst_tgt_cmd_done(scmnd);
			else {
				dma_unmap_sg(sdev->device->dma_device,
					     scst_cmd_get_sg(scmnd),
					     scst_cmd_get_sg_cnt(scmnd),
					     scst_to_tgt_dma_dir(dir));

				if (scmnd->data_buf_tgt_alloc &&
				    scmnd->data_buf_alloced) {
					kfree(scmnd->sg);
					scmnd->sg = NULL;
					scmnd->sg_cnt = 0;
				}

				if (scmnd->state == SCST_CMD_STATE_RDY_TO_XFER)
					scst_rx_data(scmnd,
						     SCST_RX_STATUS_ERROR,
						     SCST_CONTEXT_THREAD);
				else if (scmnd->state == SCST_CMD_STATE_XMIT_WAIT)
					scst_tgt_cmd_done(scmnd);
			}
		} else
			srpt_reset_ioctx(ch, ioctx);
	}

}

static void srpt_handle_send_comp(struct srpt_rdma_ch *ch,
				  struct srpt_ioctx *ioctx)
{
	if (ioctx->scmnd) {
		scst_data_direction dir = scst_cmd_get_data_direction(ioctx->scmnd);

		if (dir != SCST_DATA_NONE)
			dma_unmap_sg(ch->sport->sdev->device->dma_device,
				     scst_cmd_get_sg(ioctx->scmnd),
				     scst_cmd_get_sg_cnt(ioctx->scmnd),
				     scst_to_tgt_dma_dir(dir));

		if (ioctx->scmnd->data_buf_tgt_alloc &&
		    ioctx->scmnd->data_buf_alloced) {
			kfree(ioctx->scmnd->sg);
			ioctx->scmnd->sg = NULL;
			ioctx->scmnd->sg_cnt = 0;
		}

		scst_tgt_cmd_done(ioctx->scmnd);
	} else
		srpt_reset_ioctx(ch, ioctx);
}

static void srpt_handle_rdma_comp(struct srpt_rdma_ch *ch,
				  struct srpt_ioctx *ioctx)
{
	if (!ioctx->scmnd) {
		srpt_reset_ioctx(ch, ioctx);
		return;
	}

	if (scst_cmd_get_data_direction(ioctx->scmnd) == SCST_DATA_WRITE)
		scst_rx_data(ioctx->scmnd, SCST_RX_STATUS_SUCCESS,
			     SCST_CONTEXT_THREAD);
}

static void srpt_build_cmd_rsp(struct srpt_rdma_ch *ch,
			       struct srpt_ioctx *ioctx, u8 s_key, u8 s_code,
			       u64 tag)
{
	struct srp_rsp *srp_rsp;
	struct sense_data *sense;
	int limit_delta;

	srp_rsp = ioctx->buf;
	memset(srp_rsp, 0, sizeof *srp_rsp);

	limit_delta = atomic_read(&ch->req_lim_delta);
	atomic_sub(limit_delta, &ch->req_lim_delta);

	srp_rsp->opcode = SRP_RSP;
	srp_rsp->req_lim_delta = cpu_to_be32(limit_delta);
	srp_rsp->tag = tag;

	if (s_key != NO_SENSE) {
		srp_rsp->flags |= SRP_RSP_FLAG_SNSVALID;
		srp_rsp->status = SAM_STAT_CHECK_CONDITION;
		srp_rsp->sense_data_len =
		    cpu_to_be32(sizeof *sense + (sizeof *sense % 4));

		sense = (struct sense_data *)(srp_rsp + 1);
		sense->err_code = 0x70;
		sense->key = s_key;
		sense->asc_ascq = s_code;
	}
}

static void srpt_build_tskmgmt_rsp(struct srpt_rdma_ch *ch,
				   struct srpt_ioctx *ioctx, u8 rsp_code,
				   u64 tag)
{
	struct srp_rsp *srp_rsp;
	int limit_delta;

	dma_sync_single_for_cpu(ch->sport->sdev->device->dma_device, ioctx->dma,
				MAX_MESSAGE_SIZE, DMA_TO_DEVICE);

	srp_rsp = ioctx->buf;
	memset(srp_rsp, 0, sizeof *srp_rsp);

	limit_delta = atomic_read(&ch->req_lim_delta);
	atomic_sub(limit_delta, &ch->req_lim_delta);

	srp_rsp->opcode = SRP_RSP;
	srp_rsp->req_lim_delta = cpu_to_be32(limit_delta);
	srp_rsp->tag = tag;

	if (rsp_code != SRP_TSK_MGMT_SUCCESS) {
		srp_rsp->flags |= SRP_RSP_FLAG_RSPVALID;
		srp_rsp->resp_data_len = cpu_to_be32(4);
		srp_rsp->data[3] = rsp_code;
	}
}

static void srpt_handle_new_iu(struct srpt_rdma_ch *ch,
			       struct srpt_ioctx *ioctx)
{
	struct scst_cmd *scmnd = NULL;
	struct srp_cmd *srp_cmd = NULL;
	struct srp_tsk_mgmt *srp_tsk = NULL;
	struct srpt_mgmt_ioctx *mgmt_ioctx;
	scst_data_direction dir = SCST_DATA_NONE;
	int indirect_desc = 0;
	u8 op;
	int ret;

	if (ch->state != RDMA_CHANNEL_LIVE) {
		if (ch->state == RDMA_CHANNEL_CONNECTING) {
			spin_lock_irq(&ch->spinlock);
			list_add_tail(&ioctx->wait_list, &ch->cmd_wait_list);
			spin_unlock_irq(&ch->spinlock);
		} else
			srpt_reset_ioctx(ch, ioctx);

		return;
	}

	dma_sync_single_for_cpu(ch->sport->sdev->device->dma_device, ioctx->dma,
				MAX_MESSAGE_SIZE, DMA_FROM_DEVICE);

	ioctx->data_len = 0;
	ioctx->n_rbuf = 0;
	ioctx->rbufs = NULL;
	ioctx->n_rdma = 0;
	ioctx->n_rdma_ius = 0;
	ioctx->rdma_ius = NULL;
	ioctx->scmnd = NULL;

	op = *(u8 *) ioctx->buf;
	switch (op) {
	case SRP_CMD:
		srp_cmd = ioctx->buf;

		if (srp_cmd->buf_fmt) {
			ret = srpt_get_desc_tbl(ioctx, srp_cmd, &indirect_desc);
			if (ret) {
				srpt_build_cmd_rsp(ch, ioctx, NO_SENSE,
						   NO_ADD_SENSE, srp_cmd->tag);
				((struct srp_rsp*)ioctx->buf)->status =
					SAM_STAT_TASK_SET_FULL;
				goto send_rsp;
			}

			if (indirect_desc) {
				srpt_build_cmd_rsp(ch, ioctx, NO_SENSE,
						   NO_ADD_SENSE, srp_cmd->tag);
				((struct srp_rsp*)ioctx->buf)->status =
					SAM_STAT_TASK_SET_FULL;
				goto send_rsp;
			}

			if (srp_cmd->buf_fmt & 0xf)
				dir = SCST_DATA_READ;
			else if (srp_cmd->buf_fmt >> 4)
				dir = SCST_DATA_WRITE;
			else
				dir = SCST_DATA_NONE;
		} else
			dir = SCST_DATA_NONE;

		scmnd = scst_rx_cmd(ch->scst_sess, (u8 *) & srp_cmd->lun,
				    sizeof srp_cmd->lun, srp_cmd->cdb, 16,
				    thread ? SCST_NON_ATOMIC : SCST_ATOMIC);
		if (!scmnd) {
			srpt_build_cmd_rsp(ch, ioctx, NO_SENSE,
					   NO_ADD_SENSE, srp_cmd->tag);
			((struct srp_rsp*)ioctx->buf)->status =
				SAM_STAT_TASK_SET_FULL;
			goto send_rsp;
		}

		ioctx->scmnd = scmnd;

		switch (srp_cmd->task_attr) {
		case SRP_CMD_HEAD_OF_Q:
			scmnd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
			break;
		case SRP_CMD_ORDERED_Q:
			scmnd->queue_type = SCST_CMD_QUEUE_ORDERED;
			break;
		case SRP_CMD_SIMPLE_Q:
			scmnd->queue_type = SCST_CMD_QUEUE_SIMPLE;
			break;
		case SRP_CMD_ACA:
			scmnd->queue_type = SCST_CMD_QUEUE_ACA;
			break;
		default:
			scmnd->queue_type = SCST_CMD_QUEUE_ORDERED;
			break;
		}

		scst_cmd_set_tag(scmnd, srp_cmd->tag);
		scst_cmd_set_tgt_priv(scmnd, ioctx);
		scst_cmd_set_expected(scmnd, dir, ioctx->data_len);

		spin_lock_irq(&ch->spinlock);
		list_add_tail(&ioctx->scmnd_list, &ch->active_scmnd_list);
		ch->active_scmnd_cnt++;
		scst_cmd_init_done(scmnd, SCST_CONTEXT_THREAD);
		spin_unlock_irq(&ch->spinlock);

		break;

	case SRP_TSK_MGMT:
		srp_tsk = ioctx->buf;

		printk(KERN_WARNING PFX
		       "recv_tsk_mgmt= %d for task_tag= %lld"
		       " using tag= %lld cm_id= %p sess= %p\n",
		       srp_tsk->tsk_mgmt_func,
		       (unsigned long long) srp_tsk->task_tag,
		       (unsigned long long) srp_tsk->tag,
		       ch->cm_id, ch->scst_sess);

		mgmt_ioctx = kmalloc(sizeof *mgmt_ioctx, GFP_ATOMIC);
		if (!mgmt_ioctx) {
			srpt_build_tskmgmt_rsp(ch, ioctx, SRP_TSK_MGMT_FAILED,
					       srp_tsk->tag);
			goto send_rsp;
		}

		mgmt_ioctx->ioctx = ioctx;
		mgmt_ioctx->ch = ch;
		mgmt_ioctx->tag = srp_tsk->tag;

		switch (srp_tsk->tsk_mgmt_func) {
		case SRP_TSK_ABORT_TASK:
			ret = scst_rx_mgmt_fn_tag(ch->scst_sess,
						  SCST_ABORT_TASK,
						  srp_tsk->task_tag,
						  thread ? SCST_NON_ATOMIC : SCST_ATOMIC,
						  mgmt_ioctx);
			break;
		case SRP_TSK_ABORT_TASK_SET:
			ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
						  SCST_ABORT_TASK_SET,
						  (u8 *) & srp_tsk->lun,
						  sizeof srp_tsk->lun,
						  thread ? SCST_NON_ATOMIC : SCST_ATOMIC,
						  mgmt_ioctx);
			break;
		case SRP_TSK_CLEAR_TASK_SET:
			ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
						  SCST_CLEAR_TASK_SET,
						  (u8 *) & srp_tsk->lun,
						  sizeof srp_tsk->lun,
						  thread ? SCST_NON_ATOMIC : SCST_ATOMIC,
						  mgmt_ioctx);
			break;
#if 0
		case SRP_TSK_LUN_RESET:
			ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
						  SCST_LUN_RESET,
						  (u8 *) & srp_tsk->lun,
						  sizeof srp_tsk->lun,
						  thread ? SCST_NON_ATOMIC : SCST_ATOMIC,
						  mgmt_ioctx);
			break;
#endif
		case SRP_TSK_CLEAR_ACA:
			ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
						  SCST_CLEAR_ACA,
						  (u8 *) & srp_tsk->lun,
						  sizeof srp_tsk->lun,
						  thread ? SCST_NON_ATOMIC : SCST_ATOMIC,
						  mgmt_ioctx);
			break;
		default:
			srpt_build_tskmgmt_rsp(ch, ioctx,
					       SRP_TSK_MGMT_FUNC_NOT_SUPP,
					       srp_tsk->tag);
			goto send_rsp;
		}

		break;
	case SRP_I_LOGOUT:
	case SRP_AER_REQ:
	default:
		srpt_build_cmd_rsp(ch, ioctx, ILLEGAL_REQUEST, INVALID_CDB,
				   ((struct srp_cmd *)ioctx->buf)->tag);

		goto send_rsp;
	}

	dma_sync_single_for_device(ch->sport->sdev->device->dma_device,
				   ioctx->dma, MAX_MESSAGE_SIZE,
				   DMA_FROM_DEVICE);

	return;

send_rsp:
	if (ch->state != RDMA_CHANNEL_LIVE ||
	    srpt_post_send(ch, ioctx,
			   sizeof(struct srp_rsp) +
			   be32_to_cpu(((struct srp_rsp *)ioctx->buf)->
				       sense_data_len)))
		srpt_reset_ioctx(ch, ioctx);
}

static inline int srpt_test_ioctx_list(void)
{
	int res = (!list_empty(&srpt_thread.thread_ioctx_list) ||
		   unlikely(kthread_should_stop()));
	return res;
}

static inline void srpt_schedule_thread(struct srpt_ioctx *ioctx)
{
	unsigned long flags;

	spin_lock_irqsave(&srpt_thread.thread_lock, flags);
	list_add_tail(&ioctx->comp_list, &srpt_thread.thread_ioctx_list);
	spin_unlock_irqrestore(&srpt_thread.thread_lock, flags);
	wake_up(&ioctx_list_waitQ);
}

static void srpt_completion(struct ib_cq *cq, void *ctx)
{
	struct srpt_rdma_ch *ch = ctx;
	struct srpt_device *sdev = ch->sport->sdev;
	struct ib_wc wc;
	struct srpt_ioctx *ioctx;

	ib_req_notify_cq(ch->cq, IB_CQ_NEXT_COMP);
	while (ib_poll_cq(ch->cq, 1, &wc) > 0) {
		if (wc.status) {
			printk(KERN_ERR PFX "failed %s status= %d\n",
			       wc.wr_id & SRPT_OP_RECV ? "receive" : "send",
			       wc.status);
			srpt_handle_err_comp(ch, &wc);
			break;
		}

		if (wc.wr_id & SRPT_OP_RECV) {
			ioctx = sdev->ioctx_ring[wc.wr_id & ~SRPT_OP_RECV];
			if (thread) {
				ioctx->ch = ch;
				ioctx->op = IB_WC_RECV;
				srpt_schedule_thread(ioctx);
			} else
				srpt_handle_new_iu(ch, ioctx);
			continue;
		} else
			ioctx = sdev->ioctx_ring[wc.wr_id];

		if (thread) {
			ioctx->ch = ch;
			ioctx->op = wc.opcode;
			srpt_schedule_thread(ioctx);
		} else {
			switch (wc.opcode) {
			case IB_WC_SEND:
				srpt_handle_send_comp(ch, ioctx);
				break;
			case IB_WC_RDMA_WRITE:
			case IB_WC_RDMA_READ:
				srpt_handle_rdma_comp(ch, ioctx);
				break;
			default:
				break;
			}
		}
	}
}

static int srpt_create_ch_ib(struct srpt_rdma_ch *ch)
{
	struct ib_qp_init_attr *qp_init;
	struct srpt_device *sdev = ch->sport->sdev;
	int cqe;
	int ret;

	qp_init = kzalloc(sizeof *qp_init, GFP_KERNEL);
	if (!qp_init)
		return -ENOMEM;

	cqe = SRPT_RQ_SIZE + SRPT_SQ_SIZE - 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch, cqe);
#else
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch, cqe, 0);
#endif
	if (IS_ERR(ch->cq)) {
		ret = PTR_ERR(ch->cq);
		printk(KERN_ERR PFX "failed to create_cq cqe= %d ret= %d\n",
			cqe, ret);
		goto out;
	}

	ib_req_notify_cq(ch->cq, IB_CQ_NEXT_COMP);

	qp_init->qp_context = (void *)ch;
	qp_init->event_handler = srpt_qp_event;
	qp_init->send_cq = ch->cq;
	qp_init->recv_cq = ch->cq;
	qp_init->srq = sdev->srq;
	qp_init->sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_init->qp_type = IB_QPT_RC;
	qp_init->cap.max_send_wr = SRPT_SQ_SIZE;
	qp_init->cap.max_send_sge = SRPT_DEF_SG_PER_WQE;

	ch->qp = ib_create_qp(sdev->pd, qp_init);
	if (IS_ERR(ch->qp)) {
		ret = PTR_ERR(ch->qp);
		ib_destroy_cq(ch->cq);
		printk(KERN_ERR PFX "failed to create_qp ret= %d\n", ret);
		goto out;
	}

	printk(KERN_DEBUG PFX "%s[%d] max_cqe= %d max_sge= %d cm_id= %p\n",
	       __FUNCTION__, __LINE__, ch->cq->cqe, qp_init->cap.max_send_sge,
	       ch->cm_id);

	ret = srpt_init_ch_qp(ch, ch->qp);
	if (ret) {
		ib_destroy_qp(ch->qp);
		ib_destroy_cq(ch->cq);
		goto out;
	}

	atomic_set(&ch->req_lim_delta, SRPT_RQ_SIZE);
out:
	kfree(qp_init);
	return ret;
}

static struct srpt_rdma_ch *srpt_find_channel(struct ib_cm_id *cm_id)
{
	struct srpt_device *sdev = cm_id->context;
	struct srpt_rdma_ch *ch, *tmp_ch;

	spin_lock_irq(&sdev->spinlock);
	list_for_each_entry_safe(ch, tmp_ch, &sdev->rch_list, list) {
		if (ch->cm_id == cm_id) {
			spin_unlock_irq(&sdev->spinlock);
			return ch;
		}
	}

	spin_unlock_irq(&sdev->spinlock);

	return NULL;
}

static int srpt_release_channel(struct srpt_rdma_ch *ch, int destroy_cmid)
{
	spin_lock_irq(&ch->sport->sdev->spinlock);
	list_del(&ch->list);
	spin_unlock_irq(&ch->sport->sdev->spinlock);

	if (ch->cm_id && destroy_cmid) {
		printk(KERN_WARNING PFX
		       "%s Destroy cm_id= %p\n", __FUNCTION__, ch->cm_id);
		ib_destroy_cm_id(ch->cm_id);
		ch->cm_id = NULL;
	}

	ib_destroy_qp(ch->qp);
	ib_destroy_cq(ch->cq);

	if (ch->scst_sess) {
		struct srpt_ioctx *ioctx, *ioctx_tmp;

		printk(KERN_WARNING PFX
		       "%s: Release sess= %p sess_name= %s active_cmd= %d\n",
		       __FUNCTION__, ch->scst_sess, ch->sess_name,
		       ch->active_scmnd_cnt);

		list_for_each_entry_safe(ioctx, ioctx_tmp,
					 &ch->active_scmnd_list, scmnd_list) {
			list_del(&ioctx->scmnd_list);
			ch->active_scmnd_cnt--;
		}

		scst_unregister_session(ch->scst_sess, 0, NULL);
		ch->scst_sess = NULL;
	}

	kfree(ch);

	return (destroy_cmid ? 0 : 1);
}

static void srpt_register_channel_done(struct scst_session *scst_sess,
				       void *data, int status)
{
	struct srpt_rdma_ch *ch = data;

	BUG_ON(!ch);

	if (status) {
		if (ch->scst_sess) {
			scst_unregister_session(ch->scst_sess, 0, NULL);
			ch->scst_sess = NULL;
		}
		printk(KERN_ERR PFX
		       "%s[%d] Failed to establish sess= %p status= %d\n",
		       __FUNCTION__, __LINE__, scst_sess, status);
	}

	complete(&ch->scst_sess_done);
}

static int srpt_disconnect_channel(struct srpt_rdma_ch *ch, int dreq)
{
	spin_lock_irq(&ch->spinlock);
	ch->state = RDMA_CHANNEL_DISCONNECTING;
	spin_unlock_irq(&ch->spinlock);

	if (dreq)
		ib_send_cm_dreq(ch->cm_id, NULL, 0);
	else
		ib_send_cm_drep(ch->cm_id, NULL, 0);

	return 0;
}

static int srpt_cm_req_recv(struct ib_cm_id *cm_id,
			    struct ib_cm_req_event_param *param,
			    void *private_data)
{
	struct srpt_device *sdev = cm_id->context;
	struct srp_login_req *req;
	struct srp_login_rsp *rsp;
	struct srp_login_rej *rej;
	struct ib_cm_rep_param *rep_param;
	struct srpt_rdma_ch *ch, *tmp_ch;
	u32 it_iu_len;
	int ret = 0;

	if (!sdev || !private_data)
		return -EINVAL;

	rsp = kzalloc(sizeof *rsp, GFP_KERNEL);
	rej = kzalloc(sizeof *rej, GFP_KERNEL);
	rep_param = kzalloc(sizeof *rep_param, GFP_KERNEL);

	if (!rsp || !rej || !rep_param) {
		ret = -ENOMEM;
		goto out;
	}

	req = (struct srp_login_req *)private_data;

	it_iu_len = be32_to_cpu(req->req_it_iu_len);

	printk(KERN_ERR PFX
	       "Host login i_port_id=0x%llx:0x%llx t_port_id=0x%llx:0x%llx"
	       " it_iu_len=%d\n",
	       (unsigned long long)be64_to_cpu(*(u64 *)&req->initiator_port_id[0]),
	       (unsigned long long)be64_to_cpu(*(u64 *)&req->initiator_port_id[8]),
	       (unsigned long long)be64_to_cpu(*(u64 *)&req->target_port_id[0]),
	       (unsigned long long)be64_to_cpu(*(u64 *)&req->target_port_id[8]), it_iu_len);

	if (it_iu_len > MAX_MESSAGE_SIZE || it_iu_len < 64) {
		rej->reason =
		    cpu_to_be32(SRP_LOGIN_REJ_REQ_IT_IU_LENGTH_TOO_LARGE);
		ret = -EINVAL;
		printk(KERN_WARNING PFX
		       "Reject invalid it_iu_len=%d\n", it_iu_len);
		goto reject;
	}

	if ((req->req_flags & 0x3) == SRP_MULTICHAN_SINGLE) {
		rsp->rsp_flags = SRP_LOGIN_RSP_MULTICHAN_NO_CHAN;

		spin_lock_irq(&sdev->spinlock);

		list_for_each_entry_safe(ch, tmp_ch, &sdev->rch_list, list) {
			if (!memcmp(ch->i_port_id, req->initiator_port_id, 16)
			    && !memcmp(ch->t_port_id, req->target_port_id, 16)
			    && param->port == ch->sport->port
			    && param->listen_id == ch->sport->sdev->cm_id
			    && ch->cm_id) {
				/* found an existing channel */
				printk(KERN_WARNING PFX
				       "Found existing channel name= %s"
				       " cm_id= %p state= %d\n",
				       ch->sess_name, ch->cm_id, ch->state);

				spin_unlock_irq(&sdev->spinlock);

				rsp->rsp_flags =
				    SRP_LOGIN_RSP_MULTICHAN_TERMINATED;

				if (ch->state == RDMA_CHANNEL_LIVE)
					srpt_disconnect_channel(ch, 1);
				else if (ch->state == RDMA_CHANNEL_CONNECTING) {
					ib_send_cm_rej(ch->cm_id,
						       IB_CM_REJ_NO_RESOURCES,
						       NULL, 0, NULL, 0);
					srpt_release_channel(ch, 1);
				}

				spin_lock_irq(&sdev->spinlock);
			}
		}

		spin_unlock_irq(&sdev->spinlock);

	} else
		rsp->rsp_flags = SRP_LOGIN_RSP_MULTICHAN_MAINTAINED;

	if (((u64) (*(u64 *) req->target_port_id) !=
	     cpu_to_be64(mellanox_ioc_guid)) ||
	    ((u64) (*(u64 *) (req->target_port_id + 8)) !=
	     cpu_to_be64(mellanox_ioc_guid))) {
		rej->reason =
		    cpu_to_be32(SRP_LOGIN_REJ_UNABLE_ASSOCIATE_CHANNEL);
		ret = -ENOMEM;
		printk(KERN_WARNING PFX "Reject invalid target_port_id\n");
		goto reject;
	}

	ch = kzalloc(sizeof *ch, GFP_KERNEL);
	if (!ch) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		printk(KERN_WARNING PFX "Reject failed allocate rdma_ch\n");
		ret = -ENOMEM;
		goto reject;
	}

	spin_lock_init(&ch->spinlock);
	memcpy(ch->i_port_id, req->initiator_port_id, 16);
	memcpy(ch->t_port_id, req->target_port_id, 16);
	ch->sport = &sdev->port[param->port - 1];
	ch->cm_id = cm_id;
	ch->state = RDMA_CHANNEL_CONNECTING;
	INIT_LIST_HEAD(&ch->cmd_wait_list);
	INIT_LIST_HEAD(&ch->active_scmnd_list);

	ret = srpt_create_ch_ib(ch);
	if (ret) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		printk(KERN_WARNING PFX "Reject failed to create rdma_ch\n");
		goto free_ch;
	}

	ret = srpt_ch_qp_rtr_rts(ch, ch->qp, IB_QPS_RTR);
	if (ret) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		printk(KERN_WARNING PFX "Reject failed qp to rtr/rts ret=%d\n", ret);
		goto destroy_ib;
	}

	init_completion(&ch->scst_sess_done);
	sprintf(ch->sess_name, "0x%016llx%016llx",
		(unsigned long long)be64_to_cpu(*(u64 *)ch->i_port_id),
		(unsigned long long)be64_to_cpu(*(u64 *)(ch->i_port_id + 8)));
	ch->scst_sess =
	    scst_register_session(sdev->scst_tgt, 1, ch->sess_name,
				  ch, srpt_register_channel_done);

	wait_for_completion(&ch->scst_sess_done);

	if (!ch->scst_sess) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		printk(KERN_WARNING PFX "Reject failed to create scst sess");
		goto destroy_ib;
	}

	spin_lock_irq(&sdev->spinlock);
	list_add_tail(&ch->list, &sdev->rch_list);
	spin_unlock_irq(&sdev->spinlock);

	printk(KERN_DEBUG PFX "Establish connection sess= %p name= %s cm_id= %p\n",
	       ch->scst_sess, ch->sess_name, ch->cm_id);

	scst_sess_set_tgt_priv(ch->scst_sess, ch);

	/* create srp_login_response */
	rsp->opcode = SRP_LOGIN_RSP;
	rsp->tag = req->tag;
	rsp->max_it_iu_len = req->req_it_iu_len;
	rsp->max_ti_iu_len = req->req_it_iu_len;
	rsp->buf_fmt =
	    cpu_to_be16(SRP_BUF_FORMAT_DIRECT | SRP_BUF_FORMAT_INDIRECT);
	rsp->req_lim_delta = cpu_to_be32(SRPT_RQ_SIZE);
	atomic_set(&ch->req_lim_delta, 0);

	/* create cm reply */
	rep_param->qp_num = ch->qp->qp_num;
	rep_param->private_data = (void *)rsp;
	rep_param->private_data_len = sizeof *rsp;
	rep_param->rnr_retry_count = 7;
	rep_param->flow_control = 1;
	rep_param->failover_accepted = 0;
	rep_param->srq = 1;
	rep_param->responder_resources = 4;
	rep_param->initiator_depth = 4;

	ret = ib_send_cm_rep(cm_id, rep_param);
	if (ret)
		srpt_release_channel(ch, 0);

	goto out;

destroy_ib:
	ib_destroy_qp(ch->qp);
	ib_destroy_cq(ch->cq);

free_ch:
	kfree(ch);

reject:
	rej->opcode = SRP_LOGIN_REJ;
	rej->tag = req->tag;
	rej->buf_fmt =
	    cpu_to_be16(SRP_BUF_FORMAT_DIRECT | SRP_BUF_FORMAT_INDIRECT);

	ret = ib_send_cm_rej(cm_id, IB_CM_REJ_CONSUMER_DEFINED, NULL, 0,
			     (void *)rej, sizeof *rej);

out:
	kfree(rep_param);
	kfree(rsp);
	kfree(rej);

	return ret;
}

static int srpt_find_and_release_channel(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch;

	ch = srpt_find_channel(cm_id);
	if (!ch)
		return -EINVAL;

	return srpt_release_channel(ch, 0);
}

static int srpt_cm_rej_recv(struct ib_cm_id *cm_id)
{
	printk(KERN_DEBUG PFX "%s[%d] cm_id= %p\n",
	       __FUNCTION__, __LINE__, cm_id);
	return srpt_find_and_release_channel(cm_id);
}

static int srpt_cm_rtu_recv(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch;
	int ret;

	ch = srpt_find_channel(cm_id);
	if (!ch)
		return -EINVAL;

	if (ch->state == RDMA_CHANNEL_CONNECTING) {
		struct srpt_ioctx *ioctx, *ioctx_tmp;

		spin_lock_irq(&ch->spinlock);
		ch->state = RDMA_CHANNEL_LIVE;
		spin_unlock_irq(&ch->spinlock);
		ret = srpt_ch_qp_rtr_rts(ch, ch->qp, IB_QPS_RTS);

		list_for_each_entry_safe(ioctx, ioctx_tmp, &ch->cmd_wait_list,
					 wait_list) {
			list_del(&ioctx->wait_list);
			srpt_handle_new_iu(ch, ioctx);
		}
	} else if (ch->state == RDMA_CHANNEL_DISCONNECTING)
		ret = -EAGAIN;
	else
		ret = 0;

	if (ret) {
		printk(KERN_ERR PFX "%s[%d] cm_id= %p sess_name= %s state= %d\n",
		       __FUNCTION__, __LINE__, cm_id, ch->sess_name, ch->state);
		srpt_disconnect_channel(ch, 1);
	}

	return ret;
}

static int srpt_cm_timewait_exit(struct ib_cm_id *cm_id)
{
	printk(KERN_DEBUG PFX "%s[%d] cm_id= %p\n",
	       __FUNCTION__, __LINE__, cm_id);
	return srpt_find_and_release_channel(cm_id);
}

static int srpt_cm_rep_error(struct ib_cm_id *cm_id)
{
	printk(KERN_DEBUG PFX "%s[%d] cm_id= %p\n",
	       __FUNCTION__, __LINE__, cm_id);
	return srpt_find_and_release_channel(cm_id);
}

static int srpt_cm_dreq_recv(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch;
	int ret = 0;

	ch = srpt_find_channel(cm_id);

	if (!ch)
		return -EINVAL;

	printk(KERN_DEBUG PFX "%s[%d] cm_id= %p ch->state= %d\n",
		 __FUNCTION__, __LINE__, cm_id, ch->state);

	switch (ch->state) {
	case RDMA_CHANNEL_LIVE:
	case RDMA_CHANNEL_CONNECTING:
		ret = srpt_disconnect_channel(ch, 0);
		break;
	case RDMA_CHANNEL_DISCONNECTING:
	default:
		break;
	}

	return ret;
}

static int srpt_cm_drep_recv(struct ib_cm_id *cm_id)
{
	printk(KERN_DEBUG PFX "%s[%d] cm_id= %p\n",
		 __FUNCTION__, __LINE__, cm_id);
	return srpt_find_and_release_channel(cm_id);
}

static int srpt_cm_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	int ret = 0;

	switch (event->event) {
	case IB_CM_REQ_RECEIVED:
		ret = srpt_cm_req_recv(cm_id, &event->param.req_rcvd,
				       event->private_data);
		break;
	case IB_CM_REJ_RECEIVED:
		ret = srpt_cm_rej_recv(cm_id);
		break;
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		ret = srpt_cm_rtu_recv(cm_id);
		break;
	case IB_CM_DREQ_RECEIVED:
		ret = srpt_cm_dreq_recv(cm_id);
		break;
	case IB_CM_DREP_RECEIVED:
		ret = srpt_cm_drep_recv(cm_id);
		break;
	case IB_CM_TIMEWAIT_EXIT:
		ret = srpt_cm_timewait_exit(cm_id);
		break;
	case IB_CM_REP_ERROR:
		ret = srpt_cm_rep_error(cm_id);
		break;
	default:
		break;
	}

	return ret;
}

static int srpt_map_sg_to_ib_sge(struct srpt_rdma_ch *ch,
				 struct srpt_ioctx *ioctx,
				 struct scst_cmd *scmnd)
{
	struct scatterlist *scat;
	scst_data_direction dir;
	struct rdma_iu *riu;
	struct srp_direct_buf *db;
	dma_addr_t dma_addr;
	struct ib_sge *sge;
	u64 raddr;
	u32 rsize;
	u32 tsize;
	u32 dma_len;
	int count, nrdma;
	int i, j, k;

	scat = scst_cmd_get_sg(scmnd);
	dir = scst_cmd_get_data_direction(scmnd);
	count = dma_map_sg(ch->sport->sdev->device->dma_device, scat,
			   scst_cmd_get_sg_cnt(scmnd),
			   scst_to_tgt_dma_dir(dir));
	if (unlikely(!count))
		return -EBUSY;

	if (ioctx->rdma_ius && ioctx->n_rdma_ius)
		nrdma = ioctx->n_rdma_ius;
	else {
		nrdma = count / SRPT_DEF_SG_PER_WQE + ioctx->n_rbuf;

		ioctx->rdma_ius = kzalloc(nrdma * sizeof *riu,
					  scst_cmd_atomic(scmnd)
					  ? GFP_ATOMIC : GFP_KERNEL);
		if (!ioctx->rdma_ius) {
			dma_unmap_sg(ch->sport->sdev->device->dma_device,
				     scat, scst_cmd_get_sg_cnt(scmnd),
				     scst_to_tgt_dma_dir(dir));
			return -ENOMEM;
		}

		ioctx->n_rdma_ius = nrdma;
	}

	db = ioctx->rbufs;
	tsize = (dir == SCST_DATA_READ) ?
		scst_cmd_get_resp_data_len(scmnd) : scst_cmd_get_bufflen(scmnd);
	dma_len = sg_dma_len(&scat[0]);
	riu = ioctx->rdma_ius;

	/*
	 * For each remote desc - calculate the #ib_sge.
	 * If #ib_sge < SRPT_DEF_SG_PER_WQE per rdma operation then
	 *      each remote desc rdma_iu is required a rdma wr;
	 * else
	 *      we need to allocate extra rdma_iu to carry extra #ib_sge in
	 *      another rdma wr
	 */
	for (i = 0, j = 0;
	     j < count && i < ioctx->n_rbuf && tsize > 0; ++i, ++riu, ++db) {
		rsize = be32_to_cpu(db->len);
		raddr = be64_to_cpu(db->va);
		riu->raddr = raddr;
		riu->rkey = be32_to_cpu(db->key);
		riu->sge_cnt = 0;

		/* calculate how many sge required for this remote_buf */
		while (rsize > 0 && tsize > 0) {

			if (rsize >= dma_len) {
				tsize -= dma_len;
				rsize -= dma_len;
				raddr += dma_len;

				if (tsize > 0) {
					++j;
					if (j < count)
						dma_len = sg_dma_len(&scat[j]);
				}
			} else {
				tsize -= rsize;
				dma_len -= rsize;
				rsize = 0;
			}

			++riu->sge_cnt;

			if (rsize > 0 && riu->sge_cnt == SRPT_DEF_SG_PER_WQE) {
				riu->sge =
				    kmalloc(riu->sge_cnt * sizeof *riu->sge,
					    scst_cmd_atomic(scmnd)
					    ? GFP_ATOMIC : GFP_KERNEL);
				if (!riu->sge)
					goto free_mem;

				++ioctx->n_rdma;
				++riu;
				riu->sge_cnt = 0;
				riu->raddr = raddr;
				riu->rkey = be32_to_cpu(db->key);
			}
		}

		riu->sge = kmalloc(riu->sge_cnt * sizeof *riu->sge,
				   scst_cmd_atomic(scmnd)
				   ? GFP_ATOMIC : GFP_KERNEL);

		if (!riu->sge)
			goto free_mem;

		++ioctx->n_rdma;
	}

	db = ioctx->rbufs;
	scat = scst_cmd_get_sg(scmnd);
	tsize = (dir == SCST_DATA_READ) ?
		scst_cmd_get_resp_data_len(scmnd) : scst_cmd_get_bufflen(scmnd);
	riu = ioctx->rdma_ius;
	dma_len = sg_dma_len(&scat[0]);
	dma_addr = sg_dma_address(&scat[0]);

	/* this second loop is really mapped sg_addres to rdma_iu->ib_sge */
	for (i = 0, j = 0;
	     j < count && i < ioctx->n_rbuf && tsize > 0; ++i, ++riu, ++db) {
		rsize = be32_to_cpu(db->len);
		sge = riu->sge;
		k = 0;

		while (rsize > 0 && tsize > 0) {
			sge->addr = dma_addr;
			sge->lkey = ch->sport->sdev->mr->lkey;

			if (rsize >= dma_len) {
				sge->length = (tsize < dma_len) ? tsize : dma_len;
				tsize -= dma_len;
				rsize -= dma_len;

				if (tsize > 0) {
					++j;
					if (j < count) {
						dma_len = sg_dma_len(&scat[j]);
						dma_addr = sg_dma_address(&scat[j]);
					}
				}
			} else {
				sge->length = (tsize < rsize) ? tsize : rsize;
				tsize -= rsize;
				dma_len -= rsize;
				dma_addr += rsize;
				rsize = 0;
			}

			++k;
			if (k == riu->sge_cnt && rsize > 0) {
				++riu;
				sge = riu->sge;
				k = 0;
			} else if (rsize > 0)
				++sge;
		}
	}

	return 0;

free_mem:
	while (ioctx->n_rdma)
		kfree(ioctx->rdma_ius[ioctx->n_rdma--].sge);

	kfree(ioctx->rdma_ius);

	dma_unmap_sg(ch->sport->sdev->device->dma_device,
		     scat, scst_cmd_get_sg_cnt(scmnd),
		     scst_to_tgt_dma_dir(dir));

	return -ENOMEM;
}

static int srpt_perform_rdmas(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx,
			      scst_data_direction dir)
{
	struct ib_send_wr wr;
	struct ib_send_wr *bad_wr;
	struct rdma_iu *riu;
	int i;
	int ret = 0;

	riu = ioctx->rdma_ius;
	memset(&wr, 0, sizeof wr);

	for (i = 0; i < ioctx->n_rdma; ++i, ++riu) {
		wr.opcode = (dir == SCST_DATA_READ) ?
		    IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
		wr.next = NULL;
		wr.wr_id = ioctx->index;
		wr.wr.rdma.remote_addr = riu->raddr;
		wr.wr.rdma.rkey = riu->rkey;
		wr.num_sge = riu->sge_cnt;
		wr.sg_list = riu->sge;

		/* only get completion event for the last rdma wr */
		if (i == (ioctx->n_rdma - 1) && dir == SCST_DATA_WRITE)
			wr.send_flags = IB_SEND_SIGNALED;

		ret = ib_post_send(ch->qp, &wr, &bad_wr);
		if (ret)
			break;
	}

	return ret;
}

static int srpt_xfer_data(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx,
			  struct scst_cmd *scmnd)
{
	int ret;

	ret = srpt_map_sg_to_ib_sge(ch, ioctx, scmnd);
	if (ret) {
		printk(KERN_ERR PFX "%s[%d] ret= %d\n", __FUNCTION__, __LINE__,
		       ret);
		ret = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	}

	ret = srpt_perform_rdmas(ch, ioctx, scst_cmd_get_data_direction(scmnd));
	if (ret) {
		printk(KERN_ERR PFX "%s[%d] ret= %d\n",
		       __FUNCTION__, __LINE__, ret);
		if (ret == -EAGAIN || ret == -ENOMEM)
			ret = SCST_TGT_RES_QUEUE_FULL;
		else
			ret = SCST_TGT_RES_FATAL_ERROR;
		goto out;
	}

	ret = SCST_TGT_RES_SUCCESS;

out:
	return ret;
}

static int srpt_rdy_to_xfer(struct scst_cmd *scmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_ioctx *ioctx;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);

	ch = scst_sess_get_tgt_priv(scst_cmd_get_session(scmnd));
	BUG_ON(!ch);

	if (ch->state == RDMA_CHANNEL_DISCONNECTING)
		return SCST_TGT_RES_FATAL_ERROR;
	else if (ch->state == RDMA_CHANNEL_CONNECTING)
		return SCST_TGT_RES_QUEUE_FULL;

	return srpt_xfer_data(ch, ioctx, scmnd);
}

static int srpt_xmit_response(struct scst_cmd *scmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_ioctx *ioctx;
	struct srp_rsp *srp_rsp;
	u64 tag;
	int ret = SCST_TGT_RES_SUCCESS;
	int dir;
	int status;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);

	ch = scst_sess_get_tgt_priv(scst_cmd_get_session(scmnd));
	BUG_ON(!ch);

	tag = scst_cmd_get_tag(scmnd);

	if (ch->state != RDMA_CHANNEL_LIVE) {
		printk(KERN_ERR PFX
		       "%s[%d] tag= %lld channel in bad state %d\n",
		       __FUNCTION__, __LINE__, (unsigned long long)tag, ch->state);

		if (ch->state == RDMA_CHANNEL_DISCONNECTING)
			ret = SCST_TGT_RES_FATAL_ERROR;
		else if (ch->state == RDMA_CHANNEL_CONNECTING)
			ret = SCST_TGT_RES_QUEUE_FULL;

		if (unlikely(scst_cmd_aborted(scmnd))) {
			scst_set_delivery_status(scmnd, SCST_CMD_DELIVERY_ABORTED);
			ret = SCST_TGT_RES_SUCCESS;
		}

		goto out;
	}

	dma_sync_single_for_cpu(ch->sport->sdev->device->dma_device, ioctx->dma,
				MAX_MESSAGE_SIZE, DMA_TO_DEVICE);

	srp_rsp = ioctx->buf;

	if (unlikely(scst_cmd_aborted(scmnd))) {
		printk(KERN_ERR PFX
		       "%s[%d] tag= %lld already get aborted\n",
		       __FUNCTION__, __LINE__, (unsigned long long)tag);
		scst_set_delivery_status(ioctx->scmnd, SCST_CMD_DELIVERY_ABORTED);
		scst_tgt_cmd_done(ioctx->scmnd);
		goto out;
	}

	dir = scst_cmd_get_data_direction(scmnd);
	status = scst_cmd_get_status(scmnd) & 0xff;

	srpt_build_cmd_rsp(ch, ioctx, NO_SENSE, NO_ADD_SENSE, tag);

	if (SCST_SENSE_VALID(scst_cmd_get_sense_buffer(scmnd))) {
		srp_rsp->sense_data_len = scst_cmd_get_sense_buffer_len(scmnd);
		if (srp_rsp->sense_data_len >
		    (MAX_MESSAGE_SIZE - sizeof *srp_rsp))
			srp_rsp->sense_data_len =
			    MAX_MESSAGE_SIZE - sizeof *srp_rsp;

		memcpy((u8 *) (srp_rsp + 1), scst_cmd_get_sense_buffer(scmnd),
		       srp_rsp->sense_data_len);

		srp_rsp->sense_data_len = cpu_to_be32(srp_rsp->sense_data_len);
		srp_rsp->flags |= SRP_RSP_FLAG_SNSVALID;

		if (!status)
			status = SAM_STAT_CHECK_CONDITION;
	}

	srp_rsp->status = status;

	/* transfer read data if any */
	if (dir == SCST_DATA_READ && scst_cmd_get_resp_data_len(scmnd)) {
		ret = srpt_xfer_data(ch, ioctx, scmnd);
		if (ret != SCST_TGT_RES_SUCCESS) {
			printk(KERN_ERR PFX
			       "%s[%d] tag= %lld xfer_data failed\n",
			       __FUNCTION__, __LINE__, (unsigned long long)tag);
			goto out;
		}
	}

	if (srpt_post_send(ch, ioctx,
			   sizeof *srp_rsp +
			   be32_to_cpu(srp_rsp->sense_data_len))) {
		printk(KERN_ERR PFX "%s[%d] ch->state= %d tag= %lld\n",
		       __FUNCTION__, __LINE__, ch->state,
		       (unsigned long long)tag);
		ret = SCST_TGT_RES_FATAL_ERROR;
	}

out:
	return ret;
}

static void srpt_tsk_mgmt_done(struct scst_mgmt_cmd *mcmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_mgmt_ioctx *mgmt_ioctx;
	struct srpt_ioctx *ioctx;

	mgmt_ioctx = scst_mgmt_cmd_get_tgt_priv(mcmnd);
	BUG_ON(!mgmt_ioctx);

	ch = mgmt_ioctx->ch;
	BUG_ON(!ch);

	ioctx = mgmt_ioctx->ioctx;
	BUG_ON(!ioctx);

	printk(KERN_WARNING PFX
	       "%s[%d] tsk_mgmt_done for tag= %lld status=%d\n",
	       __FUNCTION__, __LINE__,(unsigned long long)mgmt_ioctx->tag,
	       scst_mgmt_cmd_get_status(mcmnd));

	srpt_build_tskmgmt_rsp(ch, ioctx,
			       (scst_mgmt_cmd_get_status(mcmnd) ==
				SCST_MGMT_STATUS_SUCCESS) ? SRP_TSK_MGMT_SUCCESS
			       : SRP_TSK_MGMT_FAILED, mgmt_ioctx->tag);
	srpt_post_send(ch, ioctx, sizeof(struct srp_rsp) + 4);

	scst_mgmt_cmd_set_tgt_priv(mcmnd, NULL);

	kfree(mgmt_ioctx);
}

static void srpt_on_free_cmd(struct scst_cmd *scmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_ioctx *ioctx;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);

	ch = scst_sess_get_tgt_priv(scst_cmd_get_session(scmnd));
	BUG_ON(!ch);

	spin_lock_irq(&ch->spinlock);
	list_del(&ioctx->scmnd_list);
	ch->active_scmnd_cnt--;
	spin_unlock_irq(&ch->spinlock);

	srpt_reset_ioctx(ch, ioctx);
	scst_cmd_set_tgt_priv(scmnd, NULL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void srpt_refresh_port_work(void *ctx)
#else
static void srpt_refresh_port_work(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	struct srpt_port *sport = (struct srpt_port *)ctx;
#else
	struct srpt_port *sport = container_of(work, struct srpt_port, work);
#endif

	srpt_refresh_port(sport);
}

static int srpt_detect(struct scst_tgt_template *tp)
{
	struct srpt_device *sdev;
	struct srpt_port *sport;
	int i;
	int count = 0;

	list_for_each_entry(sdev, &srpt_devices, list) {

		sdev->scst_tgt = scst_register(tp, NULL);
		if (!sdev->scst_tgt)
			goto out;

		scst_tgt_set_tgt_priv(sdev->scst_tgt, sdev);

		for (i = 1; i <= sdev->device->phys_port_cnt; i++) {
			sport = &sdev->port[i - 1];
			sport->sdev = sdev;
			sport->port = i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
			INIT_WORK(&sport->work, srpt_refresh_port_work, sport);
#else
			INIT_WORK(&sport->work, srpt_refresh_port_work);
#endif

			if (srpt_refresh_port(sport)) {
				scst_unregister(sdev->scst_tgt);
				goto out;
			}
		}

		++count;
	}
out:
	return count;
}

static int srpt_release(struct scst_tgt *scst_tgt)
{
	struct srpt_device *sdev = scst_tgt_get_tgt_priv(scst_tgt);
	struct srpt_port *sport;
	struct srpt_rdma_ch *ch, *tmp_ch;
	struct ib_port_modify port_modify = {
		.clr_port_cap_mask = IB_PORT_DEVICE_MGMT_SUP
	};
	int i;

	list_for_each_entry_safe(ch, tmp_ch, &sdev->rch_list, list)
	    srpt_release_channel(ch, 1);

	for (i = 1; i <= sdev->device->phys_port_cnt; i++) {
		sport = &sdev->port[i - 1];
		ib_modify_port(sdev->device, sport->port, 0, &port_modify);
		ib_unregister_mad_agent(sport->mad_agent);
	}

	scst_tgt_set_tgt_priv(scst_tgt, NULL);

	complete(&sdev->scst_released);

	return 0;
}

int srpt_ioctx_thread(void *arg)
{
	struct srpt_ioctx *ioctx;

	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&srpt_thread.thread_lock);
	while(!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if(!srpt_test_ioctx_list()) {
			add_wait_queue_exclusive(&ioctx_list_waitQ, &wait);

			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (srpt_test_ioctx_list())
					break;
				spin_unlock_irq(&srpt_thread.thread_lock);
				schedule();
				spin_lock_irq(&srpt_thread.thread_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&ioctx_list_waitQ, &wait);
		}

		while(!list_empty(&srpt_thread.thread_ioctx_list)) {
			ioctx = list_entry(srpt_thread.thread_ioctx_list.next,
					   struct srpt_ioctx, comp_list);

			list_del(&ioctx->comp_list);

			spin_unlock_irq(&srpt_thread.thread_lock);
			switch (ioctx->op) {
			case IB_WC_SEND:
				srpt_handle_send_comp(ioctx->ch, ioctx);
				break;
			case IB_WC_RDMA_WRITE:
			case IB_WC_RDMA_READ:
				srpt_handle_rdma_comp(ioctx->ch, ioctx);
				break;
			case IB_WC_RECV:
				srpt_handle_new_iu(ioctx->ch, ioctx);
				break;
			default:
				break;
			}
			spin_lock_irq(&srpt_thread.thread_lock);
		}
	}
	spin_unlock_irq(&srpt_thread.thread_lock);

	return 0;
}

struct scst_tgt_template srpt_template = {
	.name = DRV_NAME,
	.sg_tablesize = SRPT_DEF_SG_TABLESIZE,
	.xmit_response_atomic = 1,
	.rdy_to_xfer_atomic = 1,
	.no_proc_entry = 1,
	.detect = srpt_detect,
	.release = srpt_release,
	.xmit_response = srpt_xmit_response,
	.rdy_to_xfer = srpt_rdy_to_xfer,
	.on_free_cmd = srpt_on_free_cmd,
	.task_mgmt_fn_done = srpt_tsk_mgmt_done
};

static void srpt_release_class_dev(struct class_device *class_dev)
{
}

static struct class srpt_class = {
	.name = "infiniband_srpt",
	.release = srpt_release_class_dev
};

static ssize_t show_login_info(struct class_device *class_dev, char *buf)
{
	struct srpt_device *sdev =
		container_of(class_dev, struct srpt_device, class_dev);
	struct srpt_port *sport;
	int i;
	int len = 0;

	for (i = 0; i < sdev->device->phys_port_cnt; i++) {
		sport = &sdev->port[i];

		len += sprintf(buf,
			       "tid_ext=%016llx,ioc_guid=%016llx,pkey=ffff,"
			       "dgid=%04x%04x%04x%04x%04x%04x%04x%04x,service_id=%016llx\n",
			       (unsigned long long) mellanox_ioc_guid,
			       (unsigned long long) mellanox_ioc_guid,
			       be16_to_cpu(((__be16 *) sport->gid.raw)[0]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[1]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[2]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[3]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[4]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[5]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[6]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[7]),
			       (unsigned long long) mellanox_ioc_guid);
		buf += len;
	}

	return len;
}

static CLASS_DEVICE_ATTR(login_info, S_IRUGO, show_login_info, NULL);

static void srpt_add_one(struct ib_device *device)
{
	struct srpt_device *sdev;
	struct ib_srq_init_attr srq_attr;
	int i;

	sdev = kzalloc(sizeof *sdev, GFP_KERNEL);
	if (!sdev)
		return;

	sdev->device = device;
	init_completion(&sdev->scst_released);

	sdev->class_dev.class = &srpt_class;
	sdev->class_dev.dev = device->dma_device;
	snprintf(sdev->class_dev.class_id, BUS_ID_SIZE, "srpt-%s", device->name);

	if (class_device_register(&sdev->class_dev))
		goto free_dev;
	if (class_device_create_file(&sdev->class_dev, &class_device_attr_login_info))
		goto err_class;

	if (ib_query_device(device, &sdev->dev_attr))
		goto err_class;

	sdev->pd = ib_alloc_pd(device);
	if (IS_ERR(sdev->pd))
		goto err_class;

	sdev->mr = ib_get_dma_mr(sdev->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(sdev->mr))
		goto err_pd;

	srq_attr.event_handler = srpt_srq_event;
	srq_attr.srq_context = (void *)sdev;
	srq_attr.attr.max_wr = min(SRPT_SRQ_SIZE, sdev->dev_attr.max_srq_wr);
	srq_attr.attr.max_sge = 1;
	srq_attr.attr.srq_limit = 0;

	sdev->srq = ib_create_srq(sdev->pd, &srq_attr);
	if (IS_ERR(sdev->srq))
		goto err_mr;

	printk(KERN_DEBUG PFX "%s[%d] create SRQ #wr= %d max_allow=%d dev= %s\n",
	       __FUNCTION__, __LINE__, srq_attr.attr.max_wr,
	      sdev->dev_attr.max_srq_wr,device->name);

	if (!mellanox_ioc_guid)
		mellanox_ioc_guid = be64_to_cpu(device->node_guid);

	sdev->cm_id = ib_create_cm_id(device, srpt_cm_handler, sdev);
	if (IS_ERR(sdev->cm_id))
		goto err_srq;

	/* print out target login information */
	printk("Target login info: "
		"id_ext=%016llx,ioc_guid=%016llx,pkey=ffff,service_id=%016llx\n",
		(unsigned long long) mellanox_ioc_guid,
		(unsigned long long) mellanox_ioc_guid,
		(unsigned long long) mellanox_ioc_guid);

	/*
	 * We do not have a consistent service_id (ie. also id_ext of target_id)
	 * to identify this target. We currently use the guid of the first HCA
	 * in the system as service_id; therefore, the target_id will change
	 * if this HCA is gone bad and replaced by different HCA
	 */
	if (ib_cm_listen(sdev->cm_id, cpu_to_be64(mellanox_ioc_guid), 0, NULL))
		goto err_cm;

	INIT_IB_EVENT_HANDLER(&sdev->event_handler, sdev->device,
			      srpt_event_handler);
	if (ib_register_event_handler(&sdev->event_handler))
		goto err_cm;

	if (srpt_alloc_ioctx_ring(sdev))
		goto err_event;

	INIT_LIST_HEAD(&sdev->rch_list);
	spin_lock_init(&sdev->spinlock);

	for (i = 0; i < SRPT_SRQ_SIZE; ++i)
		srpt_post_recv(sdev, sdev->ioctx_ring[i]);

	list_add_tail(&sdev->list, &srpt_devices);

	ib_set_client_data(device, &srpt_client, sdev);

	return;

err_event:
	ib_unregister_event_handler(&sdev->event_handler);
err_cm:
	ib_destroy_cm_id(sdev->cm_id);
err_srq:
	ib_destroy_srq(sdev->srq);
err_mr:
	ib_dereg_mr(sdev->mr);
err_pd:
	ib_dealloc_pd(sdev->pd);
err_class:
	class_device_unregister(&sdev->class_dev);
free_dev:
	kfree(sdev);
}

static void srpt_remove_one(struct ib_device *device)
{
	struct srpt_device *sdev;
	int i;

	sdev = ib_get_client_data(device, &srpt_client);
	if (!sdev)
		return;

	wait_for_completion(&sdev->scst_released);

	ib_unregister_event_handler(&sdev->event_handler);
	ib_destroy_cm_id(sdev->cm_id);
	ib_destroy_srq(sdev->srq);
	ib_dereg_mr(sdev->mr);
	ib_dealloc_pd(sdev->pd);
	class_device_unregister(&sdev->class_dev);

	for (i = 0; i < SRPT_SRQ_SIZE; ++i)
		srpt_free_ioctx(sdev, sdev->ioctx_ring[i]);

	list_del(&sdev->list);
	kfree(sdev);
}

static int __init srpt_init_module(void)
{
	int ret;

	INIT_LIST_HEAD(&srpt_devices);

	ret = class_register(&srpt_class);
	if (ret) {
		printk(KERN_ERR PFX "couldn't register class ib_srpt\n");
		return ret;
	}

	ret = ib_register_client(&srpt_client);
	if (ret) {
		printk(KERN_ERR PFX "couldn't register IB client\n");
		goto mem_out;
	}

	ret = scst_register_target_template(&srpt_template);
	if (ret < 0) {
		printk(KERN_ERR PFX "couldn't register with scst\n");
		ret = -ENODEV;
		goto ib_out;
	}

	if (thread) {
		spin_lock_init(&srpt_thread.thread_lock);
		INIT_LIST_HEAD(&srpt_thread.thread_ioctx_list);
		srpt_thread.thread = kthread_run(srpt_ioctx_thread,
						 NULL, "srpt_thread");
		if (IS_ERR(srpt_thread.thread)) {
			srpt_thread.thread = NULL;
			thread = 0;
		}
	}

	return 0;

ib_out:
	ib_unregister_client(&srpt_client);
mem_out:
	class_unregister(&srpt_class);
	return ret;
}

static void __exit srpt_cleanup_module(void)
{
	if (srpt_thread.thread)
		kthread_stop(srpt_thread.thread);
	scst_unregister_target_template(&srpt_template);
	ib_unregister_client(&srpt_client);
	class_unregister(&srpt_class);
}

module_init(srpt_init_module);
module_exit(srpt_cleanup_module);
