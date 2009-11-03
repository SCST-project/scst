/*
 * Copyright (c) 2006 - 2009 Mellanox Technology Inc.  All rights reserved.
 * Copyright (C) 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 * Copyright (C) 2008 - 2009 Bart Van Assche <bart.vanassche@gmail.com>
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
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/atomic.h>
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif
#include "ib_srpt.h"
#include "scst_debug.h"

#define CONFIG_SCST_PROC

/* Name of this kernel module. */
#define DRV_NAME		"ib_srpt"
/* Prefix for printk() kernel messages. */
#define LOG_PFX			DRV_NAME ": "
#define DRV_VERSION		"1.0.1"
#define DRV_RELDATE		"July 10, 2008"
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
/* Flags to be used in SCST debug tracing statements. */
#define DEFAULT_SRPT_TRACE_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR \
				  | TRACE_MGMT | TRACE_SPECIAL)
/* Name of the entry that will be created under /proc/scsi_tgt/ib_srpt. */
#define SRPT_PROC_TRACE_LEVEL_NAME	"trace_level"
#endif

#define MELLANOX_SRPT_ID_STRING	"SCST SRP target"

MODULE_AUTHOR("Vu Pham");
MODULE_DESCRIPTION("InfiniBand SCSI RDMA Protocol target "
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

struct srpt_thread {
	/* Protects thread_ioctx_list. */
	spinlock_t thread_lock;
	/* I/O contexts to be processed by the kernel thread. */
	struct list_head thread_ioctx_list;
	/* SRPT kernel thread. */
	struct task_struct *thread;
};

/*
 * Global Variables
 */

static u64 srpt_service_guid;
/* List of srpt_device structures. */
static atomic_t srpt_device_count;
static int use_port_guid_in_session_name;
static int thread;
static struct srpt_thread srpt_thread;
static DECLARE_WAIT_QUEUE_HEAD(ioctx_list_waitQ);
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static unsigned long trace_flag = DEFAULT_SRPT_TRACE_FLAGS;
module_param(trace_flag, long, 0644);
MODULE_PARM_DESC(trace_flag,
		 "Trace flags for the ib_srpt kernel module.");
#endif
#if defined(CONFIG_SCST_DEBUG)
static unsigned long interrupt_processing_delay_in_us;
module_param(interrupt_processing_delay_in_us, long, 0744);
MODULE_PARM_DESC(interrupt_processing_delay_in_us,
		 "CQ completion handler interrupt delay in microseconds.");
static unsigned long thread_processing_delay_in_us;
module_param(thread_processing_delay_in_us, long, 0744);
MODULE_PARM_DESC(thread_processing_delay_in_us,
		 "SRP thread processing delay in microseconds.");
#endif

module_param(thread, int, 0444);
MODULE_PARM_DESC(thread,
		 "Executing ioctx in thread context. Default 0, i.e. soft IRQ, "
		 "where possible");

static unsigned int srp_max_rdma_size = 65536;
module_param(srp_max_rdma_size, int, 0744);
MODULE_PARM_DESC(thread,
		 "Maximum size of SRP RDMA transfers for new connections");

module_param(use_port_guid_in_session_name, bool, 0444);
MODULE_PARM_DESC(use_port_guid_in_session_name,
		 "Use target port ID in the SCST session name such that"
		 " redundant paths between multiport systems can be masked.");

static void srpt_add_one(struct ib_device *device);
static void srpt_remove_one(struct ib_device *device);
static void srpt_unregister_mad_agent(struct srpt_device *sdev);
#ifdef CONFIG_SCST_PROC
static void srpt_unregister_procfs_entry(struct scst_tgt_template *tgt);
#endif /*CONFIG_SCST_PROC*/

static struct ib_client srpt_client = {
	.name = DRV_NAME,
	.add = srpt_add_one,
	.remove = srpt_remove_one
};

/**
 * Atomically test and set the channel state.
 * @ch: RDMA channel.
 * @old: channel state to compare with.
 * @new: state to change the channel state to if the current state matches the
 *       argument 'old'.
 *
 * Returns true if the channel state matched old upon entry of this function,
 * and false otherwise.
 */
static bool srpt_test_and_set_channel_state(struct srpt_rdma_ch *ch,
					    enum rdma_ch_state old,
					    enum rdma_ch_state new)
{
	unsigned long flags;
	enum rdma_ch_state cur;

	spin_lock_irqsave(&ch->spinlock, flags);
	cur = ch->state;
	if (cur == old)
		ch->state = new;
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return cur == old;
}

/*
 * Callback function called by the InfiniBand core when an asynchronous IB
 * event occurs. This callback may occur in interrupt context. See also
 * section 11.5.2, Set Asynchronous Event Handler in the InfiniBand
 * Architecture Specification.
 */
static void srpt_event_handler(struct ib_event_handler *handler,
			       struct ib_event *event)
{
	struct srpt_device *sdev;
	struct srpt_port *sport;

	TRACE_ENTRY();

	sdev = ib_get_client_data(event->device, &srpt_client);
	if (!sdev || sdev->device != event->device)
		return;

	TRACE_DBG("ASYNC event= %d on device= %s",
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
		/*
		 * Refresh port data asynchronously. Note: it is safe to call
		 * schedule_work() even if &sport->work is already on the
		 * global workqueue because schedule_work() tests for the
		 * work_pending() condition before adding &sport->work to the
		 * global work queue.
		 */
		if (event->element.port_num <= sdev->device->phys_port_cnt) {
			sport = &sdev->port[event->element.port_num - 1];
			if (!sport->lid && !sport->sm_lid)
				schedule_work(&sport->work);
		}
		break;
	default:
		break;
	}

	TRACE_EXIT();
}

/*
 * Callback function called by the InfiniBand core for SRQ (shared receive
 * queue) events.
 */
static void srpt_srq_event(struct ib_event *event, void *ctx)
{
	TRACE_ENTRY();

	TRACE_DBG("SRQ event %d", event->event);

	TRACE_EXIT();
}

/*
 * Callback function called by the InfiniBand core for QP (queue pair) events.
 */
static void srpt_qp_event(struct ib_event *event, void *ctx)
{
	struct srpt_rdma_ch *ch = ctx;

	TRACE_DBG("QP event %d on cm_id=%p sess_name=%s state=%d",
		  event->event, ch->cm_id, ch->sess_name, ch->state);

	switch (event->event) {
	case IB_EVENT_COMM_EST:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20) || defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
		ib_cm_notify(ch->cm_id, event->event);
#else
		/* Vanilla 2.6.19 kernel (or before) without OFED. */
		PRINT_ERROR("%s", "how to perform ib_cm_notify() on a"
			    " vanilla 2.6.18 kernel ???");
#endif
		break;
	case IB_EVENT_QP_LAST_WQE_REACHED:
		if (srpt_test_and_set_channel_state(ch, RDMA_CHANNEL_LIVE,
					RDMA_CHANNEL_DISCONNECTING)) {
			PRINT_INFO("disconnected session %s.", ch->sess_name);
			ib_send_cm_dreq(ch->cm_id, NULL, 0);
		}
		break;
	default:
		break;
	}
}

/*
 * Helper function for filling in an InfiniBand IOUnitInfo structure. Copies
 * the lowest four bits of value in element slot of the array of four bit
 * elements called c_list (controller list). The index slot is one-based.
 *
 * @pre 1 <= slot && 0 <= value && value < 16
 */
static void srpt_set_ioc(u8 *c_list, u32 slot, u8 value)
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

/*
 * Write InfiniBand ClassPortInfo to mad. See also section 16.3.3.1
 * ClassPortInfo in the InfiniBand Architecture Specification.
 */
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

/*
 * Write IOUnitInfo to mad. See also section 16.3.3.3 IOUnitInfo in the
 * InfiniBand Architecture Specification. See also section B.7,
 * table B.6 in the T10 SRP r16a document.
 */
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

/*
 * Write IOControllerprofile to mad for I/O controller (sdev, slot). See also
 * section 16.3.3.4 IOControllerProfile in the InfiniBand Architecture
 * Specification. See also section B.7, table B.7 in the T10 SRP r16a
 * document.
 */
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
	iocp->guid = cpu_to_be64(srpt_service_guid);
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
	iocp->rdma_size = cpu_to_be32(min(max(srp_max_rdma_size, 256U),
					  1U << 24));
	iocp->num_svc_entries = 1;
	iocp->op_cap_mask = SRP_SEND_TO_IOC | SRP_SEND_FROM_IOC |
		SRP_RDMA_READ_FROM_IOC | SRP_RDMA_WRITE_FROM_IOC;

	mad->mad_hdr.status = 0;
}

/*
 * Device management: write ServiceEntries to mad for the given slot. See also
 * section 16.3.3.5 ServiceEntries in the InfiniBand Architecture
 * Specification. See also section B.7, table B.8 in the T10 SRP r16a document.
 */
static void srpt_get_svc_entries(u64 ioc_guid,
				 u16 slot, u8 hi, u8 lo, struct ib_dm_mad *mad)
{
	struct ib_dm_svc_entries *svc_entries;

	WARN_ON(!ioc_guid);

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
	svc_entries->service_entries[0].id = cpu_to_be64(ioc_guid);
	snprintf(svc_entries->service_entries[0].name,
		 sizeof(svc_entries->service_entries[0].name),
		 "%s%016llx",
		 SRP_SERVICE_NAME_PREFIX,
		 (unsigned long long)ioc_guid);

	mad->mad_hdr.status = 0;
}

/*
 * Actual processing of a received MAD *rq_mad received through source port *sp
 * (MAD = InfiniBand management datagram). The response to be sent back is
 * written to *rsp_mad.
 */
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
		srpt_get_svc_entries(srpt_service_guid,
				     slot, hi, lo, rsp_mad);
		break;
	default:
		rsp_mad->mad_hdr.status =
		    cpu_to_be16(DM_MAD_STATUS_UNSUP_METHOD_ATTR);
		break;
	}
}

/*
 * Callback function that is called by the InfiniBand core after transmission of
 * a MAD. (MAD = management datagram; AH = address handle.)
 */
static void srpt_mad_send_handler(struct ib_mad_agent *mad_agent,
				  struct ib_mad_send_wc *mad_wc)
{
	ib_destroy_ah(mad_wc->send_buf->ah);
	ib_free_send_mad(mad_wc->send_buf);
}

/*
 * Callback function that is called by the InfiniBand core after reception of
 * a MAD (management datagram).
 */
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

	BUILD_BUG_ON(offsetof(struct ib_dm_mad, data) != IB_MGMT_DEVICE_HDR);

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

/*
 * Enable InfiniBand management datagram processing, update the cached sm_lid,
 * lid and gid values, and register a callback function for processing MADs
 * on the specified port. It is safe to call this function more than once for
 * the same port.
 */
static int srpt_refresh_port(struct srpt_port *sport)
{
	struct ib_mad_reg_req reg_req;
	struct ib_port_modify port_modify;
	struct ib_port_attr port_attr;
	int ret;

	TRACE_ENTRY();

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
		if (IS_ERR(sport->mad_agent)) {
			ret = PTR_ERR(sport->mad_agent);
			sport->mad_agent = NULL;
			goto err_query_port;
		}
	}

	TRACE_EXIT_RES(0);

	return 0;

err_query_port:

	port_modify.set_port_cap_mask = 0;
	port_modify.clr_port_cap_mask = IB_PORT_DEVICE_MGMT_SUP;
	ib_modify_port(sport->sdev->device, sport->port, 0, &port_modify);

err_mod_port:

	TRACE_EXIT_RES(ret);

	return ret;
}

/*
 * Unregister the callback function for processing MADs and disable MAD
 * processing for all ports of the specified device. It is safe to call this
 * function more than once for the same device.
 */
static void srpt_unregister_mad_agent(struct srpt_device *sdev)
{
	struct ib_port_modify port_modify = {
		.clr_port_cap_mask = IB_PORT_DEVICE_MGMT_SUP,
	};
	struct srpt_port *sport;
	int i;

	for (i = 1; i <= sdev->device->phys_port_cnt; i++) {
		sport = &sdev->port[i - 1];
		WARN_ON(sport->port != i);
		if (ib_modify_port(sdev->device, i, 0, &port_modify) < 0)
			PRINT_ERROR("%s", "disabling MAD processing failed.");
		if (sport->mad_agent) {
			ib_unregister_mad_agent(sport->mad_agent);
			sport->mad_agent = NULL;
		}
	}
}

/*
 * Allocate and initialize an SRPT I/O context structure.
 */
static struct srpt_ioctx *srpt_alloc_ioctx(struct srpt_device *sdev)
{
	struct srpt_ioctx *ioctx;

	ioctx = kmalloc(sizeof *ioctx, GFP_KERNEL);
	if (!ioctx)
		goto out;

	ioctx->buf = kzalloc(MAX_MESSAGE_SIZE, GFP_KERNEL);
	if (!ioctx->buf)
		goto out_free_ioctx;

	ioctx->dma = ib_dma_map_single(sdev->device, ioctx->buf,
				       MAX_MESSAGE_SIZE, DMA_BIDIRECTIONAL);
	if (ib_dma_mapping_error(sdev->device, ioctx->dma))
		goto out_free_buf;

	return ioctx;

out_free_buf:
	kfree(ioctx->buf);
out_free_ioctx:
	kfree(ioctx);
out:
	return NULL;
}

/*
 * Deallocate an SRPT I/O context structure.
 */
static void srpt_free_ioctx(struct srpt_device *sdev, struct srpt_ioctx *ioctx)
{
	if (!ioctx)
		return;

	ib_dma_unmap_single(sdev->device, ioctx->dma,
			    MAX_MESSAGE_SIZE, DMA_BIDIRECTIONAL);
	kfree(ioctx->buf);
	kfree(ioctx);
}

/*
 * Associate a ring of SRPT I/O context structures with the specified device.
 */
static int srpt_alloc_ioctx_ring(struct srpt_device *sdev)
{
	int i;

	TRACE_ENTRY();

	for (i = 0; i < SRPT_SRQ_SIZE; ++i) {
		sdev->ioctx_ring[i] = srpt_alloc_ioctx(sdev);

		if (!sdev->ioctx_ring[i])
			goto err;

		sdev->ioctx_ring[i]->index = i;
	}

	TRACE_EXIT_RES(0);

	return 0;

err:
	while (--i > 0) {
		srpt_free_ioctx(sdev, sdev->ioctx_ring[i]);
		sdev->ioctx_ring[i] = NULL;
	}
	TRACE_EXIT_RES(-ENOMEM);
	return -ENOMEM;
}

/* Free the ring of SRPT I/O context structures. */
static void srpt_free_ioctx_ring(struct srpt_device *sdev)
{
	int i;

	for (i = 0; i < SRPT_SRQ_SIZE; ++i) {
		srpt_free_ioctx(sdev, sdev->ioctx_ring[i]);
		sdev->ioctx_ring[i] = NULL;
	}
}

/** Atomically get the state of a command. */
static enum srpt_command_state srpt_get_cmd_state(struct srpt_ioctx *ioctx)
{
	barrier();
	return atomic_read(&ioctx->state);
}

/**
 * Atomically set the state of a command.
 * @new: New state to be set.
 *
 * Does not modify the state of aborted commands.
 *
 * Returns the previous command state.
 */
static enum srpt_command_state srpt_set_cmd_state(struct srpt_ioctx *ioctx,
						  enum srpt_command_state new)
{
	enum srpt_command_state previous;

	WARN_ON(new == SRPT_STATE_NEW);

	do {
		barrier();
		previous = atomic_read(&ioctx->state);
	} while (previous != SRPT_STATE_ABORTED
		 && atomic_cmpxchg(&ioctx->state, previous, new) != previous);
	barrier();

	return previous;
}

/**
 * Atomically test and set the state of a command.
 * @expected: State to compare against.
 * @new:      New state to be set if the current state matches 'expected'.
 *
 * Returns the previous command state.
 */
static enum srpt_command_state
srpt_test_and_set_cmd_state(struct srpt_ioctx *ioctx,
			    enum srpt_command_state expected,
			    enum srpt_command_state new)
{
	enum srpt_command_state previous;

	WARN_ON(expected == SRPT_STATE_ABORTED);
	WARN_ON(new == SRPT_STATE_NEW);

	do {
		barrier();
		previous = atomic_read(&ioctx->state);
	} while (previous != SRPT_STATE_ABORTED
		 && previous == expected
		 && atomic_cmpxchg(&ioctx->state, previous, new) != previous);
	barrier();

	return previous;
}

/*
 * Post a receive request on the work queue of InfiniBand device 'sdev'.
 */
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

/*
 * Post an IB send request.
 * @ch: RDMA channel to post the send request on.
 * @ioctx: I/O context of the send request.
 * @len: length of the request to be sent in bytes.
 *
 * Returns zero upon success and a non-zero value upon failure.
 */
static int srpt_post_send(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx,
			  int len)
{
	struct ib_sge list;
	struct ib_send_wr wr, *bad_wr;
	struct srpt_device *sdev = ch->sport->sdev;

	ib_dma_sync_single_for_device(sdev->device, ioctx->dma,
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
			ioctx->rbufs =
				kmalloc(ioctx->n_rbuf * sizeof *db, GFP_ATOMIC);
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

/*
 * Modify the attributes of queue pair 'qp': allow local write, remote read,
 * and remote write. Also transition 'qp' to state IB_QPS_INIT.
 */
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

/**
 * Change the state of a channel to 'ready to receive' (RTR).
 * @ch: channel of the queue pair.
 * @qp: queue pair to change the state of.
 *
 * Returns zero upon success and a negative value upon failure.
 *
 * Note: currently a struct ib_qp_attr takes 136 bytes on a 64-bit system.
 * If this structure ever becomes larger, it might be necessary to allocate
 * it dynamically instead of on the stack.
 */
static int srpt_ch_qp_rtr(struct srpt_rdma_ch *ch, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int attr_mask;
	int ret;

	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_cm_init_qp_attr(ch->cm_id, &qp_attr, &attr_mask);
	if (ret)
		goto out;

	qp_attr.max_dest_rd_atomic = 4;

	ret = ib_modify_qp(qp, &qp_attr, attr_mask);

out:
	return ret;
}

/**
 * Change the state of a channel to 'ready to send' (RTS).
 * @ch: channel of the queue pair.
 * @qp: queue pair to change the state of.
 *
 * Returns zero upon success and a negative value upon failure.
 *
 * Note: currently a struct ib_qp_attr takes 136 bytes on a 64-bit system.
 * If this structure ever becomes larger, it might be necessary to allocate
 * it dynamically instead of on the stack.
 */
static int srpt_ch_qp_rts(struct srpt_rdma_ch *ch, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int attr_mask;
	int ret;

	qp_attr.qp_state = IB_QPS_RTS;
	ret = ib_cm_init_qp_attr(ch->cm_id, &qp_attr, &attr_mask);
	if (ret)
		goto out;

	qp_attr.max_rd_atomic = 4;

	ret = ib_modify_qp(qp, &qp_attr, attr_mask);

out:
	return ret;
}

static void srpt_reset_ioctx(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx)
{
	int i;

	if (ioctx->n_rdma_ius > 0 && ioctx->rdma_ius) {
		struct rdma_iu *riu = ioctx->rdma_ius;

		for (i = 0; i < ioctx->n_rdma_ius; ++i, ++riu)
			kfree(riu->sge);
		kfree(ioctx->rdma_ius);
	}

	if (ioctx->n_rbuf > 1)
		kfree(ioctx->rbufs);

	/* If ch == NULL this means that the command has been aborted. */
	if (!ch)
		return;

	if (srpt_post_recv(ch->sport->sdev, ioctx))
		PRINT_ERROR("%s", "SRQ post_recv failed - this is serious.");
		/* we should queue it back to free_ioctx queue */
	else
		atomic_inc(&ch->req_lim_delta);
}

static void srpt_abort_scst_cmd(struct srpt_device *sdev,
				struct scst_cmd *scmnd,
				bool tell_initiator)
{
	struct srpt_ioctx *ioctx;
	scst_data_direction dir;
	struct srpt_rdma_ch *ch;
	enum srpt_command_state previous_state;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);
	dir = scst_cmd_get_data_direction(scmnd);
	if (dir != SCST_DATA_NONE && scst_cmd_get_sg(scmnd))
		ib_dma_unmap_sg(sdev->device,
				scst_cmd_get_sg(scmnd),
				scst_cmd_get_sg_cnt(scmnd),
				scst_to_tgt_dma_dir(dir));

	previous_state = srpt_set_cmd_state(ioctx, SRPT_STATE_ABORTED);
	TRACE_DBG("Aborting cmd with state %d and tag %lld",
		  previous_state, scst_cmd_get_tag(scmnd));
	switch (previous_state) {
	case SRPT_STATE_NEW:
		/*
		 * Do not try to abort the SCST command here but wait until
		 * the SCST core has called srpt_rdy_to_xfer() or
		 * srpt_xmit_response(). Since srpt_release_channel() will
		 * finish before srpt_on_free_cmd() is called, set the channel
		 * pointer inside the SCST command to NULL such that
		 * srpt_on_free_cmd() will not dereference a dangling pointer.
		 */
		ch = ioctx->ch;
		ioctx->ch = NULL;
		BUG_ON(!ch);
		spin_lock_irq(&ch->spinlock);
		list_del(&ioctx->scmnd_list);
		ch->active_scmnd_cnt--;
		spin_unlock_irq(&ch->spinlock);
		break;
	case SRPT_STATE_NEED_DATA:
		WARN_ON(scst_cmd_get_data_direction(ioctx->scmnd)
			== SCST_DATA_READ);
		scst_rx_data(scmnd,
			     tell_initiator ? SCST_RX_STATUS_ERROR
			     : SCST_RX_STATUS_ERROR_FATAL,
			     SCST_CONTEXT_THREAD);
		break;
	case SRPT_STATE_PROCESSED:
		scst_set_delivery_status(scmnd, SCST_CMD_DELIVERY_FAILED);
		WARN_ON(scmnd->state != SCST_CMD_STATE_XMIT_WAIT);
		scst_tgt_cmd_done(scmnd, scst_estimate_context());
		break;
	default:
		TRACE_DBG("Aborting cmd with state %d", previous_state);
		WARN_ON("ERROR: unexpected command state");
	}
}

static void srpt_handle_err_comp(struct srpt_rdma_ch *ch, struct ib_wc *wc)
{
	struct srpt_ioctx *ioctx;
	struct srpt_device *sdev = ch->sport->sdev;

	if (wc->wr_id & SRPT_OP_RECV) {
		ioctx = sdev->ioctx_ring[wc->wr_id & ~SRPT_OP_RECV];
		PRINT_ERROR("%s", "This is serious - SRQ is in bad state.");
	} else {
		ioctx = sdev->ioctx_ring[wc->wr_id];

		if (ioctx->scmnd)
			srpt_abort_scst_cmd(sdev, ioctx->scmnd, true);
		else
			srpt_reset_ioctx(ch, ioctx);
	}
}

static void srpt_handle_send_comp(struct srpt_rdma_ch *ch,
				  struct srpt_ioctx *ioctx,
				  enum scst_exec_context context)
{
	if (ioctx->scmnd) {
		scst_data_direction dir =
			scst_cmd_get_data_direction(ioctx->scmnd);

		if (dir != SCST_DATA_NONE && scst_cmd_get_sg(ioctx->scmnd))
			ib_dma_unmap_sg(ch->sport->sdev->device,
					scst_cmd_get_sg(ioctx->scmnd),
					scst_cmd_get_sg_cnt(ioctx->scmnd),
					scst_to_tgt_dma_dir(dir));

		WARN_ON(ioctx->scmnd->state != SCST_CMD_STATE_XMIT_WAIT);
		scst_tgt_cmd_done(ioctx->scmnd, context);
	} else
		srpt_reset_ioctx(ch, ioctx);
}

/** Process an RDMA completion notification. */
static void srpt_handle_rdma_comp(struct srpt_rdma_ch *ch,
				  struct srpt_ioctx *ioctx)
{
	if (!ioctx->scmnd) {
		WARN_ON("ERROR: ioctx->scmnd == NULL");
		srpt_reset_ioctx(ch, ioctx);
		return;
	}

	/*
	 * If an RDMA completion notification has been received for a write
	 * command, tell SCST that processing can continue by calling
	 * scst_rx_data().
	 */
	if (srpt_test_and_set_cmd_state(ioctx, SRPT_STATE_NEED_DATA,
				SRPT_STATE_DATA_IN) == SRPT_STATE_NEED_DATA) {
		WARN_ON(scst_cmd_get_data_direction(ioctx->scmnd)
			== SCST_DATA_READ);
		scst_rx_data(ioctx->scmnd, SCST_RX_STATUS_SUCCESS,
			     scst_estimate_context());
	}
}

/**
 * Build an SRP_RSP response.
 * @ch: RDMA channel through which the request has been received.
 * @ioctx: I/O context in which the SRP_RSP response will be built.
 * @s_key: sense key that will be stored in the response.
 * @s_code: value that will be stored in the asc_ascq field of the sense data.
 * @tag: tag of the request for which this response is being generated.
 *
 * Returns the size in bytes of the SRP_RSP response.
 *
 * An SRP_RSP response contains a SCSI status or service response. See also
 * section 6.9 in the T10 SRP r16a document for the format of an SRP_RSP
 * response. See also SPC-2 for more information about sense data.
 */
static int srpt_build_cmd_rsp(struct srpt_rdma_ch *ch,
			      struct srpt_ioctx *ioctx, u8 s_key, u8 s_code,
			      u64 tag)
{
	struct srp_rsp *srp_rsp;
	struct sense_data *sense;
	int limit_delta;
	int sense_data_len = 0;

	srp_rsp = ioctx->buf;
	memset(srp_rsp, 0, sizeof *srp_rsp);

	limit_delta = atomic_read(&ch->req_lim_delta);
	atomic_sub(limit_delta, &ch->req_lim_delta);

	srp_rsp->opcode = SRP_RSP;
	srp_rsp->req_lim_delta = cpu_to_be32(limit_delta);
	srp_rsp->tag = tag;

	if (s_key != NO_SENSE) {
		sense_data_len = sizeof *sense + (sizeof *sense % 4);
		srp_rsp->flags |= SRP_RSP_FLAG_SNSVALID;
		srp_rsp->status = SAM_STAT_CHECK_CONDITION;
		srp_rsp->sense_data_len = cpu_to_be32(sense_data_len);

		sense = (struct sense_data *)(srp_rsp + 1);
		sense->err_code = 0x70;
		sense->key = s_key;
		sense->asc_ascq = s_code;
	}

	return sizeof(*srp_rsp) + sense_data_len;
}

/**
 * Build a task management response, which is a specific SRP_RSP response.
 * @ch: RDMA channel through which the request has been received.
 * @ioctx: I/O context in which the SRP_RSP response will be built.
 * @rsp_code: RSP_CODE that will be stored in the response.
 * @tag: tag of the request for which this response is being generated.
 *
 * Returns the size in bytes of the SRP_RSP response.
 *
 * An SRP_RSP response contains a SCSI status or service response. See also
 * section 6.9 in the T10 SRP r16a document for the format of an SRP_RSP
 * response.
 */
static int srpt_build_tskmgmt_rsp(struct srpt_rdma_ch *ch,
				  struct srpt_ioctx *ioctx, u8 rsp_code,
				  u64 tag)
{
	struct srp_rsp *srp_rsp;
	int limit_delta;
	int resp_data_len = 0;

	ib_dma_sync_single_for_cpu(ch->sport->sdev->device, ioctx->dma,
				   MAX_MESSAGE_SIZE, DMA_TO_DEVICE);

	srp_rsp = ioctx->buf;
	memset(srp_rsp, 0, sizeof *srp_rsp);

	limit_delta = atomic_read(&ch->req_lim_delta);
	atomic_sub(limit_delta, &ch->req_lim_delta);

	srp_rsp->opcode = SRP_RSP;
	srp_rsp->req_lim_delta = cpu_to_be32(limit_delta);
	srp_rsp->tag = tag;

	if (rsp_code != SRP_TSK_MGMT_SUCCESS) {
		resp_data_len = 4;
		srp_rsp->flags |= SRP_RSP_FLAG_RSPVALID;
		srp_rsp->resp_data_len = cpu_to_be32(resp_data_len);
		srp_rsp->data[3] = rsp_code;
	}

	return sizeof(*srp_rsp) + resp_data_len;
}

/*
 * Process SRP_CMD.
 */
static int srpt_handle_cmd(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx)
{
	struct scst_cmd *scmnd;
	struct srp_cmd *srp_cmd;
	struct srp_rsp *srp_rsp;
	scst_data_direction dir;
	int indirect_desc = 0;
	int ret;
	unsigned long flags;

	srp_cmd = ioctx->buf;
	srp_rsp = ioctx->buf;

	dir = SCST_DATA_NONE;
	if (srp_cmd->buf_fmt) {
		ret = srpt_get_desc_tbl(ioctx, srp_cmd, &indirect_desc);
		if (ret) {
			srpt_build_cmd_rsp(ch, ioctx, NO_SENSE,
					   NO_ADD_SENSE, srp_cmd->tag);
			srp_rsp->status = SAM_STAT_TASK_SET_FULL;
			goto err;
		}

		if (indirect_desc) {
			srpt_build_cmd_rsp(ch, ioctx, NO_SENSE,
					   NO_ADD_SENSE, srp_cmd->tag);
			srp_rsp->status = SAM_STAT_TASK_SET_FULL;
			goto err;
		}

		/*
		 * The lower four bits of the buffer format field contain the
		 * DATA-IN buffer descriptor format, and the highest four bits
		 * contain the DATA-OUT buffer descriptor format.
		 */
		if (srp_cmd->buf_fmt & 0xf)
			/* DATA-IN: transfer data from target to initiator. */
			dir = SCST_DATA_READ;
		else if (srp_cmd->buf_fmt >> 4)
			/* DATA-OUT: transfer data from initiator to target. */
			dir = SCST_DATA_WRITE;
	}

	scmnd = scst_rx_cmd(ch->scst_sess, (u8 *) &srp_cmd->lun,
			    sizeof srp_cmd->lun, srp_cmd->cdb, 16,
			    thread ? SCST_NON_ATOMIC : SCST_ATOMIC);
	if (!scmnd) {
		srpt_build_cmd_rsp(ch, ioctx, NO_SENSE,
				   NO_ADD_SENSE, srp_cmd->tag);
		srp_rsp->status = SAM_STAT_TASK_SET_FULL;
		goto err;
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

	spin_lock_irqsave(&ch->spinlock, flags);
	list_add_tail(&ioctx->scmnd_list, &ch->active_scmnd_list);
	ch->active_scmnd_cnt++;
	spin_unlock_irqrestore(&ch->spinlock, flags);

	scst_cmd_init_done(scmnd, scst_estimate_context());

	return 0;

err:
	WARN_ON(srp_rsp->opcode != SRP_RSP);

	return -1;
}

/*
 * Process an SRP_TSK_MGMT request.
 *
 * Returns 0 upon success and -1 upon failure.
 *
 * Each task management function is performed by calling one of the
 * scst_rx_mgmt_fn*() functions. These functions will either report failure
 * or process the task management function asynchronously. The function
 * srpt_tsk_mgmt_done() will be called by the SCST core upon completion of the
 * task management function. When srpt_handle_tsk_mgmt() reports failure
 * (i.e. returns -1) a response will have been built in ioctx->buf. This
 * information unit has to be sent back by the caller.
 *
 * For more information about SRP_TSK_MGMT information units, see also section
 * 6.7 in the T10 SRP r16a document.
 */
static int srpt_handle_tsk_mgmt(struct srpt_rdma_ch *ch,
				struct srpt_ioctx *ioctx)
{
	struct srp_tsk_mgmt *srp_tsk;
	struct srpt_mgmt_ioctx *mgmt_ioctx;
	int ret;

	srp_tsk = ioctx->buf;

	TRACE_DBG("recv_tsk_mgmt= %d for task_tag= %lld"
		  " using tag= %lld cm_id= %p sess= %p",
		  srp_tsk->tsk_mgmt_func,
		  (unsigned long long) srp_tsk->task_tag,
		  (unsigned long long) srp_tsk->tag,
		  ch->cm_id, ch->scst_sess);

	mgmt_ioctx = kmalloc(sizeof *mgmt_ioctx, GFP_ATOMIC);
	if (!mgmt_ioctx) {
		srpt_build_tskmgmt_rsp(ch, ioctx, SRP_TSK_MGMT_FAILED,
				       srp_tsk->tag);
		goto err;
	}

	mgmt_ioctx->ioctx = ioctx;
	mgmt_ioctx->ch = ch;
	mgmt_ioctx->tag = srp_tsk->tag;

	switch (srp_tsk->tsk_mgmt_func) {
	case SRP_TSK_ABORT_TASK:
		TRACE_DBG("%s", "Processing SRP_TSK_ABORT_TASK");
		ret = scst_rx_mgmt_fn_tag(ch->scst_sess,
					  SCST_ABORT_TASK,
					  srp_tsk->task_tag,
					  thread ?
					  SCST_NON_ATOMIC : SCST_ATOMIC,
					  mgmt_ioctx);
		break;
	case SRP_TSK_ABORT_TASK_SET:
		TRACE_DBG("%s", "Processing SRP_TSK_ABORT_TASK_SET");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
					  SCST_ABORT_TASK_SET,
					  (u8 *) &srp_tsk->lun,
					  sizeof srp_tsk->lun,
					  thread ?
					  SCST_NON_ATOMIC : SCST_ATOMIC,
					  mgmt_ioctx);
		break;
	case SRP_TSK_CLEAR_TASK_SET:
		TRACE_DBG("%s", "Processing SRP_TSK_CLEAR_TASK_SET");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
					  SCST_CLEAR_TASK_SET,
					  (u8 *) &srp_tsk->lun,
					  sizeof srp_tsk->lun,
					  thread ?
					  SCST_NON_ATOMIC : SCST_ATOMIC,
					  mgmt_ioctx);
		break;
	case SRP_TSK_LUN_RESET:
		TRACE_DBG("%s", "Processing SRP_TSK_LUN_RESET");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
					  SCST_LUN_RESET,
					  (u8 *) &srp_tsk->lun,
					  sizeof srp_tsk->lun,
					  thread ?
					  SCST_NON_ATOMIC : SCST_ATOMIC,
					  mgmt_ioctx);
		break;
	case SRP_TSK_CLEAR_ACA:
		TRACE_DBG("%s", "Processing SRP_TSK_CLEAR_ACA");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess,
					  SCST_CLEAR_ACA,
					  (u8 *) &srp_tsk->lun,
					  sizeof srp_tsk->lun,
					  thread ?
					  SCST_NON_ATOMIC : SCST_ATOMIC,
					  mgmt_ioctx);
		break;
	default:
		TRACE_DBG("%s", "Unsupported task management function.");
		srpt_build_tskmgmt_rsp(ch, ioctx,
				       SRP_TSK_MGMT_FUNC_NOT_SUPP,
				       srp_tsk->tag);
		goto err;
	}

	if (ret) {
		TRACE_DBG("%s", "Processing task management function failed.");
		srpt_build_tskmgmt_rsp(ch, ioctx, SRP_TSK_MGMT_FAILED,
				       srp_tsk->tag);
		goto err;
	}

	WARN_ON(srp_tsk->opcode == SRP_RSP);

	return 0;

err:
	WARN_ON(srp_tsk->opcode != SRP_RSP);

	kfree(mgmt_ioctx);
	return -1;
}

/**
 * Process a receive completion event.
 * @ch: RDMA channel for which the completion event has been received.
 * @ioctx: SRPT I/O context for which the completion event has been received.
 */
static void srpt_handle_new_iu(struct srpt_rdma_ch *ch,
			       struct srpt_ioctx *ioctx)
{
	struct srp_cmd *srp_cmd;
	struct srp_rsp *srp_rsp;
	unsigned long flags;
	int len;

	spin_lock_irqsave(&ch->spinlock, flags);
	if (ch->state != RDMA_CHANNEL_LIVE) {
		if (ch->state == RDMA_CHANNEL_CONNECTING) {
			list_add_tail(&ioctx->wait_list, &ch->cmd_wait_list);
			spin_unlock_irqrestore(&ch->spinlock, flags);
			return;
		} else {
			spin_unlock_irqrestore(&ch->spinlock, flags);
			srpt_reset_ioctx(ch, ioctx);
			return;
		}
	}
	spin_unlock_irqrestore(&ch->spinlock, flags);

	ib_dma_sync_single_for_cpu(ch->sport->sdev->device, ioctx->dma,
				   MAX_MESSAGE_SIZE, DMA_FROM_DEVICE);

	ioctx->data_len = 0;
	ioctx->n_rbuf = 0;
	ioctx->rbufs = NULL;
	ioctx->n_rdma = 0;
	ioctx->n_rdma_ius = 0;
	ioctx->rdma_ius = NULL;
	ioctx->scmnd = NULL;
	ioctx->ch = ch;
	atomic_set(&ioctx->state, SRPT_STATE_NEW);

	srp_cmd = ioctx->buf;
	srp_rsp = ioctx->buf;

	switch (srp_cmd->opcode) {
	case SRP_CMD:
		if (srpt_handle_cmd(ch, ioctx) < 0)
			goto err;
		break;

	case SRP_TSK_MGMT:
		if (srpt_handle_tsk_mgmt(ch, ioctx) < 0)
			goto err;
		break;

	case SRP_I_LOGOUT:
	case SRP_AER_REQ:
	default:
		srpt_build_cmd_rsp(ch, ioctx, ILLEGAL_REQUEST, INVALID_CDB,
				   srp_cmd->tag);
		goto err;
	}

	ib_dma_sync_single_for_device(ch->sport->sdev->device,
				   ioctx->dma, MAX_MESSAGE_SIZE,
				   DMA_FROM_DEVICE);

	return;

err:
	WARN_ON(srp_rsp->opcode != SRP_RSP);
	len = (sizeof *srp_rsp) + be32_to_cpu(srp_rsp->sense_data_len);

	if (ch->state != RDMA_CHANNEL_LIVE) {
		/* Give up if another thread modified the channel state. */
		PRINT_ERROR("%s: channel is in state %d", __func__, ch->state);
		srpt_reset_ioctx(ch, ioctx);
	} else if (srpt_post_send(ch, ioctx, len)) {
		PRINT_ERROR("%s: sending SRP_RSP response failed", __func__);
		srpt_reset_ioctx(ch, ioctx);
	}
}

/*
 * Returns true if the ioctx list is non-empty or if the ib_srpt kernel thread
 * should stop.
 * @pre thread != 0
 */
static inline int srpt_test_ioctx_list(void)
{
	int res = (!list_empty(&srpt_thread.thread_ioctx_list) ||
		   unlikely(kthread_should_stop()));
	return res;
}

/*
 * Add 'ioctx' to the tail of the ioctx list and wake up the kernel thread.
 *
 * @pre thread != 0
 */
static inline void srpt_schedule_thread(struct srpt_ioctx *ioctx)
{
	unsigned long flags;

	spin_lock_irqsave(&srpt_thread.thread_lock, flags);
	list_add_tail(&ioctx->comp_list, &srpt_thread.thread_ioctx_list);
	spin_unlock_irqrestore(&srpt_thread.thread_lock, flags);
	wake_up(&ioctx_list_waitQ);
}

/**
 * InfiniBand completion queue callback function.
 * @cq: completion queue.
 * @ctx: completion queue context, which was passed as the fourth argument of
 *       the function ib_create_cq().
 */
static void srpt_completion(struct ib_cq *cq, void *ctx)
{
	struct srpt_rdma_ch *ch = ctx;
	struct srpt_device *sdev = ch->sport->sdev;
	struct ib_wc wc;
	struct srpt_ioctx *ioctx;

	ib_req_notify_cq(ch->cq, IB_CQ_NEXT_COMP);
	while (ib_poll_cq(ch->cq, 1, &wc) > 0) {
		if (wc.status) {
			PRINT_ERROR("failed %s status= %d",
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
				srpt_handle_send_comp(ch, ioctx,
					scst_estimate_context());
				break;
			case IB_WC_RDMA_WRITE:
			case IB_WC_RDMA_READ:
				srpt_handle_rdma_comp(ch, ioctx);
				break;
			default:
				break;
			}
		}

#if defined(CONFIG_SCST_DEBUG)
		if (interrupt_processing_delay_in_us <= MAX_UDELAY_MS * 1000)
			udelay(interrupt_processing_delay_in_us);
#endif
	}
}

/*
 * Create a completion queue on the specified device.
 */
static int srpt_create_ch_ib(struct srpt_rdma_ch *ch)
{
	struct ib_qp_init_attr *qp_init;
	struct srpt_device *sdev = ch->sport->sdev;
	int cqe;
	int ret;

	qp_init = kzalloc(sizeof *qp_init, GFP_KERNEL);
	if (!qp_init)
		return -ENOMEM;

	/* Create a completion queue (CQ). */

	cqe = SRPT_RQ_SIZE + SRPT_SQ_SIZE - 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && ! defined(RHEL_RELEASE_CODE)
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch, cqe);
#else
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch, cqe, 0);
#endif
	if (IS_ERR(ch->cq)) {
		ret = PTR_ERR(ch->cq);
		PRINT_ERROR("failed to create_cq cqe= %d ret= %d", cqe, ret);
		goto out;
	}

	/* Request completion notification. */

	ib_req_notify_cq(ch->cq, IB_CQ_NEXT_COMP);

	/* Create a queue pair (QP). */

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
		PRINT_ERROR("failed to create_qp ret= %d", ret);
		goto out;
	}

	TRACE_DBG("%s: max_cqe= %d max_sge= %d cm_id= %p",
	       __func__, ch->cq->cqe, qp_init->cap.max_send_sge,
	       ch->cm_id);

	/* Modify the attributes and the state of queue pair ch->qp. */

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

/**
 * Look up the RDMA channel that corresponds to the specified cm_id.
 *
 * Return NULL if no matching RDMA channel has been found.
 */
static struct srpt_rdma_ch *srpt_find_channel(struct ib_cm_id *cm_id, bool del)
{
	struct srpt_device *sdev = cm_id->context;
	struct srpt_rdma_ch *ch;

	spin_lock_irq(&sdev->spinlock);
	list_for_each_entry(ch, &sdev->rch_list, list) {
		if (ch->cm_id == cm_id) {
			if (del)
				list_del(&ch->list);
			spin_unlock_irq(&sdev->spinlock);
			return ch;
		}
	}

	spin_unlock_irq(&sdev->spinlock);

	return NULL;
}

/**
 * Release all resources associated with the specified RDMA channel.
 *
 * Note: the caller must have removed the channel from the channel list
 * before calling this function.
 */
static void srpt_release_channel(struct srpt_rdma_ch *ch, int destroy_cmid)
{
	TRACE_ENTRY();

	WARN_ON(srpt_find_channel(ch->cm_id, false) == ch);

	if (ch->cm_id && destroy_cmid) {
		TRACE_DBG("%s: destroy cm_id= %p", __func__, ch->cm_id);
		ib_destroy_cm_id(ch->cm_id);
		ch->cm_id = NULL;
	}

	ib_destroy_qp(ch->qp);
	ib_destroy_cq(ch->cq);

	if (ch->scst_sess) {
		struct srpt_ioctx *ioctx, *ioctx_tmp;

		if (ch->active_scmnd_cnt)
			PRINT_INFO("Releasing session %s which still has %d"
				   " active commands",
				   ch->sess_name, ch->active_scmnd_cnt);
		else
			PRINT_INFO("Releasing session %s", ch->sess_name);

		spin_lock_irq(&ch->spinlock);
		list_for_each_entry_safe(ioctx, ioctx_tmp,
					 &ch->active_scmnd_list, scmnd_list) {
			spin_unlock_irq(&ch->spinlock);

			if (ioctx->scmnd)
				srpt_abort_scst_cmd(ch->sport->sdev,
						    ioctx->scmnd, true);

			spin_lock_irq(&ch->spinlock);
		}
		WARN_ON(!list_empty(&ch->active_scmnd_list));
		WARN_ON(ch->active_scmnd_cnt != 0);
		spin_unlock_irq(&ch->spinlock);

		scst_unregister_session(ch->scst_sess, 0, NULL);
		ch->scst_sess = NULL;
	}

	kfree(ch);

	TRACE_EXIT();
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

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
	WARN_ON(!sdev || !private_data);
	if (!sdev || !private_data)
		return -EINVAL;
#else
	if (WARN_ON(!sdev || !private_data))
		return -EINVAL;
#endif

	req = (struct srp_login_req *)private_data;

	it_iu_len = be32_to_cpu(req->req_it_iu_len);

	PRINT_INFO("Received SRP_LOGIN_REQ with"
	    " i_port_id 0x%llx:0x%llx, t_port_id 0x%llx:0x%llx and length %d"
	    " on port %d (guid=0x%llx:0x%llx)",
	    (unsigned long long)be64_to_cpu(*(u64 *)&req->initiator_port_id[0]),
	    (unsigned long long)be64_to_cpu(*(u64 *)&req->initiator_port_id[8]),
	    (unsigned long long)be64_to_cpu(*(u64 *)&req->target_port_id[0]),
	    (unsigned long long)be64_to_cpu(*(u64 *)&req->target_port_id[8]),
	    it_iu_len,
	    param->port,
	    (unsigned long long)be64_to_cpu(*(u64 *)
				&sdev->port[param->port - 1].gid.raw[0]),
	    (unsigned long long)be64_to_cpu(*(u64 *)
				&sdev->port[param->port - 1].gid.raw[8]));

	rsp = kzalloc(sizeof *rsp, GFP_KERNEL);
	rej = kzalloc(sizeof *rej, GFP_KERNEL);
	rep_param = kzalloc(sizeof *rep_param, GFP_KERNEL);

	if (!rsp || !rej || !rep_param) {
		ret = -ENOMEM;
		goto out;
	}

	if (it_iu_len > MAX_MESSAGE_SIZE || it_iu_len < 64) {
		rej->reason =
		    cpu_to_be32(SRP_LOGIN_REJ_REQ_IT_IU_LENGTH_TOO_LARGE);
		ret = -EINVAL;
		PRINT_ERROR("rejected SRP_LOGIN_REQ because its"
			    " length (%d bytes) is invalid", it_iu_len);
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
				enum rdma_ch_state prev_state;

				/* found an existing channel */
				TRACE_DBG("Found existing channel name= %s"
					  " cm_id= %p state= %d",
					  ch->sess_name, ch->cm_id, ch->state);

				prev_state = ch->state;
				if (ch->state == RDMA_CHANNEL_LIVE)
					ch->state = RDMA_CHANNEL_DISCONNECTING;
				else if (ch->state == RDMA_CHANNEL_CONNECTING)
					list_del(&ch->list);

				spin_unlock_irq(&sdev->spinlock);

				rsp->rsp_flags =
					SRP_LOGIN_RSP_MULTICHAN_TERMINATED;

				if (prev_state == RDMA_CHANNEL_LIVE) {
					ib_send_cm_dreq(ch->cm_id, NULL, 0);
					PRINT_INFO("disconnected"
					  " session %s because a new"
					  " SRP_LOGIN_REQ has been received.",
					  ch->sess_name);
				} else if (prev_state ==
					 RDMA_CHANNEL_CONNECTING) {
					PRINT_ERROR("%s", "rejected"
					  " SRP_LOGIN_REQ because another login"
					  " request is being processed.");
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
	     cpu_to_be64(srpt_service_guid)) ||
	    ((u64) (*(u64 *) (req->target_port_id + 8)) !=
	     cpu_to_be64(srpt_service_guid))) {
		rej->reason =
		    cpu_to_be32(SRP_LOGIN_REJ_UNABLE_ASSOCIATE_CHANNEL);
		ret = -ENOMEM;
		PRINT_ERROR("%s", "rejected SRP_LOGIN_REQ because it"
		       " has an invalid target port identifier.");
		goto reject;
	}

	ch = kzalloc(sizeof *ch, GFP_KERNEL);
	if (!ch) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_ERROR("%s",
			    "rejected SRP_LOGIN_REQ because out of memory.");
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
		PRINT_ERROR("%s", "rejected SRP_LOGIN_REQ because creating"
			    " a new RDMA channel failed.");
		goto free_ch;
	}

	ret = srpt_ch_qp_rtr(ch, ch->qp);
	if (ret) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_ERROR("rejected SRP_LOGIN_REQ because enabling"
		       " RTR failed (error code = %d)", ret);
		goto destroy_ib;
	}

	if (use_port_guid_in_session_name) {
		/*
		 * If the kernel module parameter use_port_guid_in_session_name
		 * has been specified, use a combination of the target port
		 * GUID and the initiator port ID as the session name. This
		 * was the original behavior of the SRP target implementation
		 * (i.e. before the SRPT was included in OFED 1.3).
		 */
		snprintf(ch->sess_name, sizeof(ch->sess_name),
			 "0x%016llx%016llx",
			 (unsigned long long)be64_to_cpu(*(u64 *)
				&sdev->port[param->port - 1].gid.raw[8]),
			 (unsigned long long)be64_to_cpu(*(u64 *)
				(ch->i_port_id + 8)));
	} else {
		/*
		 * Default behavior: use the initator port identifier as the
		 * session name.
		 */
		snprintf(ch->sess_name, sizeof(ch->sess_name),
			 "0x%016llx%016llx",
			 (unsigned long long)be64_to_cpu(*(u64 *)ch->i_port_id),
			 (unsigned long long)be64_to_cpu(*(u64 *)
				 (ch->i_port_id + 8)));
	}

	TRACE_DBG("registering session %s", ch->sess_name);

	BUG_ON(!sdev->scst_tgt);
	ch->scst_sess = scst_register_session(sdev->scst_tgt, 0, ch->sess_name,
					      NULL, NULL);
	if (!ch->scst_sess) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		TRACE_DBG("%s", "Failed to create scst sess");
		goto destroy_ib;
	}

	TRACE_DBG("Establish connection sess=%p name=%s cm_id=%p",
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
	if (ret) {
		PRINT_ERROR("sending SRP_LOGIN_REQ response failed"
			    " (error code = %d)", ret);
		goto release_channel;
	}

	spin_lock_irq(&sdev->spinlock);
	list_add_tail(&ch->list, &sdev->rch_list);
	spin_unlock_irq(&sdev->spinlock);

	goto out;

release_channel:
	scst_unregister_session(ch->scst_sess, 0, NULL);
	ch->scst_sess = NULL;

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

	ib_send_cm_rej(cm_id, IB_CM_REJ_CONSUMER_DEFINED, NULL, 0,
			     (void *)rej, sizeof *rej);

out:
	kfree(rep_param);
	kfree(rsp);
	kfree(rej);

	return ret;
}

/**
 * Release the channel with the specified cm_id.
 *
 * Returns one to indicate that the caller of srpt_cm_handler() should destroy
 * the cm_id.
 */
static void srpt_find_and_release_channel(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch;

	ch = srpt_find_channel(cm_id, true);
	if (ch)
		srpt_release_channel(ch, 0);
}

static void srpt_cm_rej_recv(struct ib_cm_id *cm_id)
{
	PRINT_INFO("%s", "Received InfiniBand REJ packet.");
	srpt_find_and_release_channel(cm_id);
}

/**
 * Process an IB_CM_RTU_RECEIVED or IB_CM_USER_ESTABLISHED event.
 *
 * An IB_CM_RTU_RECEIVED message indicates that the connection is established
 * and that the recipient may begin transmitting (RTU = ready to use).
 */
static int srpt_cm_rtu_recv(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch;
	int ret;

	ch = srpt_find_channel(cm_id, false);
	if (!ch)
		return -EINVAL;

	if (srpt_test_and_set_channel_state(ch, RDMA_CHANNEL_CONNECTING,
					    RDMA_CHANNEL_LIVE)) {
		struct srpt_ioctx *ioctx, *ioctx_tmp;

		ret = srpt_ch_qp_rts(ch, ch->qp);

		list_for_each_entry_safe(ioctx, ioctx_tmp, &ch->cmd_wait_list,
					 wait_list) {
			list_del(&ioctx->wait_list);
			srpt_handle_new_iu(ch, ioctx);
		}
		if (ret && srpt_test_and_set_channel_state(ch,
					RDMA_CHANNEL_LIVE,
					RDMA_CHANNEL_DISCONNECTING)) {
			TRACE_DBG("cm_id=%p sess_name=%s state=%d",
				  cm_id, ch->sess_name, ch->state);
			ib_send_cm_dreq(ch->cm_id, NULL, 0);
		}
	} else if (ch->state == RDMA_CHANNEL_DISCONNECTING) {
		TRACE_DBG("cm_id=%p sess_name=%s state=%d",
			  cm_id, ch->sess_name, ch->state);
		ib_send_cm_dreq(ch->cm_id, NULL, 0);
		ret = -EAGAIN;
	} else
		ret = 0;

	return ret;
}

static void srpt_cm_timewait_exit(struct ib_cm_id *cm_id)
{
	PRINT_INFO("%s", "Received InfiniBand TimeWait exit.");
	srpt_find_and_release_channel(cm_id);
}

static void srpt_cm_rep_error(struct ib_cm_id *cm_id)
{
	PRINT_INFO("%s", "Received InfiniBand REP error.");
	srpt_find_and_release_channel(cm_id);
}

static int srpt_cm_dreq_recv(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch;

	ch = srpt_find_channel(cm_id, false);
	if (!ch)
		return -EINVAL;

	TRACE_DBG("%s: cm_id= %p ch->state= %d",
		 __func__, cm_id, ch->state);

	switch (ch->state) {
	case RDMA_CHANNEL_LIVE:
	case RDMA_CHANNEL_CONNECTING:
		ib_send_cm_drep(ch->cm_id, NULL, 0);
		PRINT_INFO("Received DREQ and sent DREP for session %s.",
			   ch->sess_name);
		break;
	case RDMA_CHANNEL_DISCONNECTING:
	default:
		break;
	}

	return 0;
}

static void srpt_cm_drep_recv(struct ib_cm_id *cm_id)
{
	PRINT_INFO("%s", "Received InfiniBand DREP message.");
	srpt_find_and_release_channel(cm_id);
}

/**
 * IB connection manager callback function.
 *
 * A non-zero return value will make the caller destroy the CM ID.
 *
 * Note: srpt_add_one passes a struct srpt_device* as the third argument to
 * the ib_create_cm_id() call.
 */
static int srpt_cm_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	int ret = 0;

	switch (event->event) {
	case IB_CM_REQ_RECEIVED:
		ret = srpt_cm_req_recv(cm_id, &event->param.req_rcvd,
				       event->private_data);
		break;
	case IB_CM_REJ_RECEIVED:
		srpt_cm_rej_recv(cm_id);
		ret = -EINVAL;
		break;
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		ret = srpt_cm_rtu_recv(cm_id);
		break;
	case IB_CM_DREQ_RECEIVED:
		ret = srpt_cm_dreq_recv(cm_id);
		break;
	case IB_CM_DREP_RECEIVED:
		srpt_cm_drep_recv(cm_id);
		ret = -EINVAL;
		break;
	case IB_CM_TIMEWAIT_EXIT:
		srpt_cm_timewait_exit(cm_id);
		ret = -EINVAL;
		break;
	case IB_CM_REP_ERROR:
		srpt_cm_rep_error(cm_id);
		ret = -EINVAL;
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
	WARN_ON(scat == NULL);
	count = ib_dma_map_sg(ch->sport->sdev->device, scat,
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
			WARN_ON(scat == NULL);
			ib_dma_unmap_sg(ch->sport->sdev->device,
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
				sge->length =
					(tsize < dma_len) ? tsize : dma_len;
				tsize -= dma_len;
				rsize -= dma_len;

				if (tsize > 0) {
					++j;
					if (j < count) {
						dma_len = sg_dma_len(&scat[j]);
						dma_addr =
						    sg_dma_address(&scat[j]);
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

	WARN_ON(scat == NULL);
	ib_dma_unmap_sg(ch->sport->sdev->device,
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

/*
 * Start data transfer between initiator and target. Must not block.
 */
static int srpt_xfer_data(struct srpt_rdma_ch *ch, struct srpt_ioctx *ioctx,
			  struct scst_cmd *scmnd)
{
	int ret;

	ret = srpt_map_sg_to_ib_sge(ch, ioctx, scmnd);
	if (ret) {
		PRINT_ERROR("%s[%d] ret=%d", __func__, __LINE__, ret);
		ret = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	}

	ret = srpt_perform_rdmas(ch, ioctx, scst_cmd_get_data_direction(scmnd));
	if (ret) {
		PRINT_ERROR("%s[%d] ret=%d", __func__, __LINE__, ret);
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

/*
 * Called by the SCST core to inform ib_srpt that data reception from the
 * initiator should start (SCST_DATA_WRITE). Must not block.
 */
static int srpt_rdy_to_xfer(struct scst_cmd *scmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_ioctx *ioctx;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);

	if (srpt_get_cmd_state(ioctx) == SRPT_STATE_ABORTED) {
		TRACE_DBG("cmd with tag %lld has been aborted",
			  scst_cmd_get_tag(scmnd));
		return SCST_TGT_RES_FATAL_ERROR;
	}

	ch = ioctx->ch;
	WARN_ON(ch != scst_sess_get_tgt_priv(scst_cmd_get_session(scmnd)));
	BUG_ON(!ch);

	if (ch->state == RDMA_CHANNEL_DISCONNECTING) {
		TRACE_DBG("cmd with tag %lld: channel disconnecting",
			  scst_cmd_get_tag(scmnd));
		return SCST_TGT_RES_FATAL_ERROR;
	} else if (ch->state == RDMA_CHANNEL_CONNECTING)
		return SCST_TGT_RES_QUEUE_FULL;

	srpt_set_cmd_state(ioctx, SRPT_STATE_NEED_DATA);

	return srpt_xfer_data(ch, ioctx, scmnd);
}

/*
 * Called by the SCST core. Transmits the response buffer and status held in
 * 'scmnd'. Must not block.
 */
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

	if (srpt_get_cmd_state(ioctx) == SRPT_STATE_ABORTED) {
		TRACE_DBG("cmd with tag %lld has been aborted",
			  scst_cmd_get_tag(scmnd));
		ret = SCST_TGT_RES_FATAL_ERROR;
		goto out;
	}

	ch = scst_sess_get_tgt_priv(scst_cmd_get_session(scmnd));
	BUG_ON(!ch);

	tag = scst_cmd_get_tag(scmnd);

	srpt_set_cmd_state(ioctx, SRPT_STATE_PROCESSED);

	if (ch->state != RDMA_CHANNEL_LIVE) {
		PRINT_ERROR("%s: tag= %lld channel in bad state %d",
		       __func__, (unsigned long long)tag, ch->state);

		if (ch->state == RDMA_CHANNEL_DISCONNECTING) {
			TRACE_DBG("cmd with tag %lld: channel disconnecting",
				  (unsigned long long)tag);
			ret = SCST_TGT_RES_FATAL_ERROR;
		} else if (ch->state == RDMA_CHANNEL_CONNECTING)
			ret = SCST_TGT_RES_QUEUE_FULL;

		if (unlikely(scst_cmd_aborted(scmnd)))
			goto out_aborted;

		goto out;
	}

	ib_dma_sync_single_for_cpu(ch->sport->sdev->device, ioctx->dma,
				   MAX_MESSAGE_SIZE, DMA_TO_DEVICE);

	srp_rsp = ioctx->buf;

	if (unlikely(scst_cmd_aborted(scmnd))) {
		TRACE_MGMT_DBG("%s: tag= %lld already got aborted",
			       __func__, (unsigned long long)tag);
		goto out_aborted;
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

	/* For read commands, transfer the data to the initiator. */
	if (dir == SCST_DATA_READ && scst_cmd_get_resp_data_len(scmnd)) {
		ret = srpt_xfer_data(ch, ioctx, scmnd);
		if (ret != SCST_TGT_RES_SUCCESS) {
			PRINT_ERROR("%s: tag= %lld xfer_data failed",
				    __func__, (unsigned long long)tag);
			goto out;
		}
	}

	if (srpt_post_send(ch, ioctx,
			   sizeof *srp_rsp +
			   be32_to_cpu(srp_rsp->sense_data_len))) {
		PRINT_ERROR("%s: ch->state= %d tag= %lld",
			    __func__, ch->state,
			    (unsigned long long)tag);
		ret = SCST_TGT_RES_FATAL_ERROR;
	}

out:
	return ret;

out_aborted:
	ret = SCST_TGT_RES_SUCCESS;
	scst_set_delivery_status(scmnd, SCST_CMD_DELIVERY_ABORTED);
	srpt_set_cmd_state(ioctx, SRPT_STATE_ABORTED);
	WARN_ON(scmnd->state != SCST_CMD_STATE_XMIT_WAIT);
	scst_tgt_cmd_done(scmnd, SCST_CONTEXT_SAME);
	goto out;
}

/*
 * Called by the SCST core to inform ib_srpt that a received task management
 * function has been completed. Must not block.
 */
static void srpt_tsk_mgmt_done(struct scst_mgmt_cmd *mcmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_mgmt_ioctx *mgmt_ioctx;
	struct srpt_ioctx *ioctx;
	int rsp_len;

	mgmt_ioctx = scst_mgmt_cmd_get_tgt_priv(mcmnd);
	BUG_ON(!mgmt_ioctx);

	ch = mgmt_ioctx->ch;
	BUG_ON(!ch);

	ioctx = mgmt_ioctx->ioctx;
	BUG_ON(!ioctx);

	TRACE_DBG("%s: tsk_mgmt_done for tag= %lld status=%d",
		  __func__, (unsigned long long)mgmt_ioctx->tag,
		  scst_mgmt_cmd_get_status(mcmnd));

	srpt_set_cmd_state(ioctx, SRPT_STATE_PROCESSED);

	rsp_len = srpt_build_tskmgmt_rsp(ch, ioctx,
					 (scst_mgmt_cmd_get_status(mcmnd) ==
					  SCST_MGMT_STATUS_SUCCESS) ?
					 SRP_TSK_MGMT_SUCCESS :
					 SRP_TSK_MGMT_FAILED,
					 mgmt_ioctx->tag);
	srpt_post_send(ch, ioctx, rsp_len);

	scst_mgmt_cmd_set_tgt_priv(mcmnd, NULL);

	kfree(mgmt_ioctx);
}

/*
 * Called by the SCST core to inform ib_srpt that the command 'scmnd' is about
 * to be freed. May be called in IRQ context.
 */
static void srpt_on_free_cmd(struct scst_cmd *scmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_ioctx *ioctx;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);

	ch = ioctx->ch;
	if (ch) {
		spin_lock_irq(&ch->spinlock);
		list_del(&ioctx->scmnd_list);
		ch->active_scmnd_cnt--;
		spin_unlock_irq(&ch->spinlock);
		ioctx->ch = NULL;
	}

	srpt_reset_ioctx(ch, ioctx);
	scst_cmd_set_tgt_priv(scmnd, NULL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && ! defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
/* A vanilla 2.6.19 or older kernel without backported OFED kernel headers. */
static void srpt_refresh_port_work(void *ctx)
#else
static void srpt_refresh_port_work(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && ! defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
	struct srpt_port *sport = (struct srpt_port *)ctx;
#else
	struct srpt_port *sport = container_of(work, struct srpt_port, work);
#endif

	srpt_refresh_port(sport);
}

/*
 * Called by the SCST core to detect target adapters. Returns the number of
 * detected target adapters.
 */
static int srpt_detect(struct scst_tgt_template *tp)
{
	int device_count;

	TRACE_ENTRY();

	device_count = atomic_read(&srpt_device_count);

	TRACE_EXIT_RES(device_count);

	return device_count;
}

/*
 * Callback function called by the SCST core from scst_unregister() to free up
 * the resources associated with device scst_tgt.
 */
static int srpt_release(struct scst_tgt *scst_tgt)
{
	struct srpt_device *sdev = scst_tgt_get_tgt_priv(scst_tgt);
	struct srpt_rdma_ch *ch, *tmp_ch;

	TRACE_ENTRY();

	BUG_ON(!scst_tgt);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
	WARN_ON(!sdev);
	if (!sdev)
		return -ENODEV;
#else
	if (WARN_ON(!sdev))
		return -ENODEV;
#endif

#ifdef CONFIG_SCST_PROC
	srpt_unregister_procfs_entry(scst_tgt->tgtt);
#endif /*CONFIG_SCST_PROC*/

	spin_lock_irq(&sdev->spinlock);
	list_for_each_entry_safe(ch, tmp_ch, &sdev->rch_list, list) {
		list_del(&ch->list);
		spin_unlock_irq(&sdev->spinlock);
		srpt_release_channel(ch, 1);
		spin_lock_irq(&sdev->spinlock);
	}
	spin_unlock_irq(&sdev->spinlock);

	srpt_unregister_mad_agent(sdev);

	scst_tgt_set_tgt_priv(scst_tgt, NULL);

	TRACE_EXIT();

	return 0;
}

/*
 * Entry point for ib_srpt's kernel thread. This kernel thread is only created
 * when the module parameter 'thread' is not zero (the default is zero).
 * This thread processes the ioctx list srpt_thread.thread_ioctx_list.
 *
 * @pre thread != 0
 */
static int srpt_ioctx_thread(void *arg)
{
	struct srpt_ioctx *ioctx;

	/* Hibernation / freezing of the SRPT kernel thread is not supported. */
	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&srpt_thread.thread_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!srpt_test_ioctx_list()) {
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

		while (!list_empty(&srpt_thread.thread_ioctx_list)) {
			ioctx = list_entry(srpt_thread.thread_ioctx_list.next,
					   struct srpt_ioctx, comp_list);

			list_del(&ioctx->comp_list);

			spin_unlock_irq(&srpt_thread.thread_lock);
			switch (ioctx->op) {
			case IB_WC_SEND:
				srpt_handle_send_comp(ioctx->ch, ioctx,
					SCST_CONTEXT_DIRECT);
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
#if defined(CONFIG_SCST_DEBUG)
			if (thread_processing_delay_in_us
			    <= MAX_UDELAY_MS * 1000)
				udelay(thread_processing_delay_in_us);
#endif
			spin_lock_irq(&srpt_thread.thread_lock);
		}
	}
	spin_unlock_irq(&srpt_thread.thread_lock);

	return 0;
}

/* SCST target template for the SRP target implementation. */
static struct scst_tgt_template srpt_template = {
	.name = DRV_NAME,
	.sg_tablesize = SRPT_DEF_SG_TABLESIZE,
	.xmit_response_atomic = 1,
	.rdy_to_xfer_atomic = 1,
	.detect = srpt_detect,
	.release = srpt_release,
	.xmit_response = srpt_xmit_response,
	.rdy_to_xfer = srpt_rdy_to_xfer,
	.on_free_cmd = srpt_on_free_cmd,
	.task_mgmt_fn_done = srpt_tsk_mgmt_done
};

/*
 * The callback function srpt_release_class_dev() is called whenever a
 * device is removed from the /sys/class/infiniband_srpt device class.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static void srpt_release_class_dev(struct class_device *class_dev)
#else
static void srpt_release_class_dev(struct device *dev)
#endif
{
}

#ifdef CONFIG_SCST_PROC

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static int srpt_trace_level_show(struct seq_file *seq, void *v)
{
	return scst_proc_log_entry_read(seq, trace_flag, NULL);
}

static ssize_t srpt_proc_trace_level_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	return scst_proc_log_entry_write(file, buf, length, &trace_flag,
		DEFAULT_SRPT_TRACE_FLAGS, NULL);
}

static struct scst_proc_data srpt_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(srpt_proc_trace_level_write)
	.show = srpt_trace_level_show,
};
#endif

#endif /* CONFIG_SCST_PROC */

static struct class_attribute srpt_class_attrs[] = {
	__ATTR_NULL,
};

static struct class srpt_class = {
	.name = "infiniband_srpt",
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	.release = srpt_release_class_dev,
#else
	.dev_release = srpt_release_class_dev,
#endif
	.class_attrs = srpt_class_attrs,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static ssize_t show_login_info(struct class_device *class_dev, char *buf)
#else
static ssize_t show_login_info(struct device *dev,
			       struct device_attribute *attr, char *buf)
#endif
{
	struct srpt_device *sdev =
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
		container_of(class_dev, struct srpt_device, class_dev);
#else
		container_of(dev, struct srpt_device, dev);
#endif
	struct srpt_port *sport;
	int i;
	int len = 0;

	for (i = 0; i < sdev->device->phys_port_cnt; i++) {
		sport = &sdev->port[i];

		len += sprintf(buf + len,
			       "tid_ext=%016llx,ioc_guid=%016llx,pkey=ffff,"
			       "dgid=%04x%04x%04x%04x%04x%04x%04x%04x,"
			       "service_id=%016llx\n",
			       (unsigned long long) srpt_service_guid,
			       (unsigned long long) srpt_service_guid,
			       be16_to_cpu(((__be16 *) sport->gid.raw)[0]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[1]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[2]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[3]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[4]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[5]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[6]),
			       be16_to_cpu(((__be16 *) sport->gid.raw)[7]),
			       (unsigned long long) srpt_service_guid);
	}

	return len;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static CLASS_DEVICE_ATTR(login_info, S_IRUGO, show_login_info, NULL);
#else
static DEVICE_ATTR(login_info, S_IRUGO, show_login_info, NULL);
#endif

/*
 * Callback function called by the InfiniBand core when either an InfiniBand
 * device has been added or during the ib_register_client() call for each
 * registered InfiniBand device.
 */
static void srpt_add_one(struct ib_device *device)
{
	struct srpt_device *sdev;
	struct srpt_port *sport;
	struct ib_srq_init_attr srq_attr;
	int i;

	TRACE_ENTRY();

	TRACE_DBG("device = %p, device->dma_ops = %p", device, device->dma_ops);

	sdev = kzalloc(sizeof *sdev, GFP_KERNEL);
	if (!sdev)
		return;

	sdev->device = device;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	sdev->class_dev.class = &srpt_class;
	sdev->class_dev.dev = device->dma_device;
	snprintf(sdev->class_dev.class_id, BUS_ID_SIZE,
		 "srpt-%s", device->name);
#else
	sdev->dev.class = &srpt_class;
	sdev->dev.parent = device->dma_device;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	snprintf(sdev->dev.bus_id, BUS_ID_SIZE, "srpt-%s", device->name);
#else
	dev_set_name(&sdev->dev, "srpt-%s", device->name);
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	if (class_device_register(&sdev->class_dev))
		goto free_dev;
	if (class_device_create_file(&sdev->class_dev,
				     &class_device_attr_login_info))
		goto err_dev;
#else
	if (device_register(&sdev->dev))
		goto free_dev;
	if (device_create_file(&sdev->dev, &dev_attr_login_info))
		goto err_dev;
#endif

	if (ib_query_device(device, &sdev->dev_attr))
		goto err_dev;

	sdev->pd = ib_alloc_pd(device);
	if (IS_ERR(sdev->pd))
		goto err_dev;

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

	TRACE_DBG("%s: create SRQ #wr= %d max_allow=%d dev= %s",
	       __func__, srq_attr.attr.max_wr,
	      sdev->dev_attr.max_srq_wr, device->name);

	if (!srpt_service_guid)
		srpt_service_guid = be64_to_cpu(device->node_guid);

	sdev->cm_id = ib_create_cm_id(device, srpt_cm_handler, sdev);
	if (IS_ERR(sdev->cm_id))
		goto err_srq;

	/* print out target login information */
	TRACE_DBG("Target login info: id_ext=%016llx,"
		  "ioc_guid=%016llx,pkey=ffff,service_id=%016llx",
		  (unsigned long long) srpt_service_guid,
		  (unsigned long long) srpt_service_guid,
		  (unsigned long long) srpt_service_guid);

	/*
	 * We do not have a consistent service_id (ie. also id_ext of target_id)
	 * to identify this target. We currently use the guid of the first HCA
	 * in the system as service_id; therefore, the target_id will change
	 * if this HCA is gone bad and replaced by different HCA
	 */
	if (ib_cm_listen(sdev->cm_id, cpu_to_be64(srpt_service_guid), 0, NULL))
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

	ib_set_client_data(device, &srpt_client, sdev);

	sdev->scst_tgt = scst_register(&srpt_template, NULL);
	if (!sdev->scst_tgt) {
		PRINT_ERROR("SCST registration failed for %s.",
			    sdev->device->name);
		goto err_ring;
	}

	scst_tgt_set_tgt_priv(sdev->scst_tgt, sdev);

	WARN_ON(sdev->device->phys_port_cnt
		> sizeof(sdev->port)/sizeof(sdev->port[0]));

	for (i = 1; i <= sdev->device->phys_port_cnt; i++) {
		sport = &sdev->port[i - 1];
		sport->sdev = sdev;
		sport->port = i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && ! defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
		/*
		 * A vanilla 2.6.19 or older kernel without backported OFED
		 * kernel headers.
		 */
		INIT_WORK(&sport->work, srpt_refresh_port_work, sport);
#else
		INIT_WORK(&sport->work, srpt_refresh_port_work);
#endif
		if (srpt_refresh_port(sport)) {
			PRINT_ERROR("MAD registration failed for %s-%d.",
				    sdev->device->name, i);
			goto err_refresh_port;
		}
	}

	atomic_inc(&srpt_device_count);

	TRACE_EXIT();

	return;

err_refresh_port:
	scst_unregister(sdev->scst_tgt);
err_ring:
	ib_set_client_data(device, &srpt_client, NULL);
	srpt_free_ioctx_ring(sdev);
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
err_dev:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	class_device_unregister(&sdev->class_dev);
#else
	device_unregister(&sdev->dev);
#endif
free_dev:
	kfree(sdev);

	TRACE_EXIT();
}

/*
 * Callback function called by the InfiniBand core when either an InfiniBand
 * device has been removed or during the ib_unregister_client() call for each
 * registered InfiniBand device.
 */
static void srpt_remove_one(struct ib_device *device)
{
	int i;
	struct srpt_device *sdev;

	TRACE_ENTRY();

	sdev = ib_get_client_data(device, &srpt_client);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
	WARN_ON(!sdev);
	if (!sdev)
		return;
#else
	if (WARN_ON(!sdev))
		return;
#endif

	/*
	 * Cancel the work if it is queued. Wait until srpt_refresh_port_work()
	 * finished if it is running.
	 */
	for (i = 0; i < sdev->device->phys_port_cnt; i++)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
		cancel_work_sync(&sdev->port[i].work);
#else
		/*
		 * cancel_work_sync() was introduced in kernel 2.6.22. Older
		 * kernels do not have a facility to cancel scheduled work.
		 */
		PRINT_ERROR("%s",
		       "your kernel does not provide cancel_work_sync().");
#endif

	scst_unregister(sdev->scst_tgt);
	sdev->scst_tgt = NULL;

	ib_unregister_event_handler(&sdev->event_handler);
	ib_destroy_cm_id(sdev->cm_id);
	ib_destroy_srq(sdev->srq);
	ib_dereg_mr(sdev->mr);
	ib_dealloc_pd(sdev->pd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	class_device_unregister(&sdev->class_dev);
#else
	device_unregister(&sdev->dev);
#endif

	srpt_free_ioctx_ring(sdev);
	kfree(sdev);

	TRACE_EXIT();
}

#ifdef CONFIG_SCST_PROC

/**
 * Create procfs entries for srpt. Currently the only procfs entry created
 * by this function is the "trace_level" entry.
 */
static int srpt_register_procfs_entry(struct scst_tgt_template *tgt)
{
	int res = 0;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *p, *root;

	root = scst_proc_get_tgt_root(tgt);
	WARN_ON(!root);
	if (root) {
		/*
		 * Fill in the scst_proc_data::data pointer, which is used in
		 * a printk(KERN_INFO ...) statement in
		 * scst_proc_log_entry_write() in scst_proc.c.
		 */
		srpt_log_proc_data.data = (char *)tgt->name;
		p = scst_create_proc_entry(root, SRPT_PROC_TRACE_LEVEL_NAME,
					   &srpt_log_proc_data);
		if (!p)
			res = -ENOMEM;
	} else
		res = -ENOMEM;

#endif
	return res;
}

static void srpt_unregister_procfs_entry(struct scst_tgt_template *tgt)
{
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *root;

	root = scst_proc_get_tgt_root(tgt);
	WARN_ON(!root);
	if (root)
		remove_proc_entry(SRPT_PROC_TRACE_LEVEL_NAME, root);
#endif
}

#endif /*CONFIG_SCST_PROC*/

/*
 * Module initialization.
 *
 * Note: since ib_register_client() registers callback functions, and since at
 * least one of these callback functions (srpt_add_one()) calls SCST functions,
 * the SCST target template must be registered before ib_register_client() is
 * called.
 */
static int __init srpt_init_module(void)
{
	int ret;

	ret = class_register(&srpt_class);
	if (ret) {
		PRINT_ERROR("%s", "couldn't register class ib_srpt");
		goto out;
	}

	ret = scst_register_target_template(&srpt_template);
	if (ret < 0) {
		PRINT_ERROR("%s", "couldn't register with scst");
		ret = -ENODEV;
		goto out_unregister_class;
	}

#ifdef CONFIG_SCST_PROC
	ret = srpt_register_procfs_entry(&srpt_template);
	if (ret) {
		PRINT_ERROR("%s", "couldn't register procfs entry");
		goto out_unregister_target;
	}
#endif /*CONFIG_SCST_PROC*/

	ret = ib_register_client(&srpt_client);
	if (ret) {
		PRINT_ERROR("%s", "couldn't register IB client");
		goto out_unregister_target;
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

out_unregister_target:
#ifdef CONFIG_SCST_PROC
	/*
	 * Note: the procfs entry is unregistered in srpt_release(), which is
	 * called by scst_unregister_target_template().
	 */
#endif /*CONFIG_SCST_PROC*/
	scst_unregister_target_template(&srpt_template);
out_unregister_class:
	class_unregister(&srpt_class);
out:
	return ret;
}

static void __exit srpt_cleanup_module(void)
{
	TRACE_ENTRY();

	if (srpt_thread.thread)
		kthread_stop(srpt_thread.thread);
	ib_unregister_client(&srpt_client);
	scst_unregister_target_template(&srpt_template);
	class_unregister(&srpt_class);

	TRACE_EXIT();
}

module_init(srpt_init_module);
module_exit(srpt_cleanup_module);
