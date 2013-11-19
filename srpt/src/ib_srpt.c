/*
 * Copyright (c) 2006 - 2009 Mellanox Technology Inc.  All rights reserved.
 * Copyright (C) 2008 - 2013 Bart Van Assche <bvanassche@acm.org>.
 * Copyright (C) 2008 Vladislav Bolkhovitin <vst@vlnb.net>
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
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <asm/atomic.h>
#if defined(CONFIG_SCST_PROC)
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif
#endif
#include "ib_srpt.h"
#define LOG_PREFIX "ib_srpt" /* Prefix for SCST tracing macros. */
#if defined(INSIDE_KERNEL_TREE)
#include <scst/scst_debug.h>
#else
#include "scst_debug.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27) && !defined(WARN)
/* See also commit a8f18b909c0a3f22630846207035c8b84bb252b8 */
#define WARN(condition, format...) do {		\
	if (unlikely(condition)) {		\
		printk(KERN_WARNING format);	\
		WARN_ON(true);			\
	}					\
} while(0);
#endif

/* Name of this kernel module. */
#define DRV_NAME		"ib_srpt"
#define DRV_VERSION		"3.0.0-pre"
#define DRV_RELDATE		"(not yet released)"
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
/* Flags to be used in SCST debug tracing statements. */
#define DEFAULT_SRPT_TRACE_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR \
				  | TRACE_MGMT | TRACE_SPECIAL)
/* Name of the entry that will be created under /proc/scsi_tgt/ib_srpt. */
#define SRPT_PROC_TRACE_LEVEL_NAME	"trace_level"
#endif

#define SRPT_ID_STRING	"SCST SRP target"

MODULE_AUTHOR("Vu Pham and Bart Van Assche");
MODULE_DESCRIPTION("InfiniBand SCSI RDMA Protocol target "
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

/*
 * Global Variables
 */

static u64 srpt_service_guid;
/* List of srpt_device structures. */
static atomic_t srpt_device_count;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static unsigned long trace_flag = DEFAULT_SRPT_TRACE_FLAGS;
module_param(trace_flag, long, 0644);
MODULE_PARM_DESC(trace_flag, "SCST trace flags.");
#endif

static unsigned srp_max_rdma_size = DEFAULT_MAX_RDMA_SIZE;
module_param(srp_max_rdma_size, int, 0644);
MODULE_PARM_DESC(srp_max_rdma_size,
		 "Maximum size of SRP RDMA transfers for new connections.");

static unsigned srp_max_req_size = DEFAULT_MAX_REQ_SIZE;
module_param(srp_max_req_size, int, 0444);
MODULE_PARM_DESC(srp_max_req_size,
		 "Maximum size of SRP request messages in bytes.");

static unsigned int srp_max_rsp_size = DEFAULT_MAX_RSP_SIZE;
module_param(srp_max_rsp_size, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(srp_max_rsp_size,
		 "Maximum size of SRP response messages in bytes.");

static int srpt_srq_size = DEFAULT_SRPT_SRQ_SIZE;
module_param(srpt_srq_size, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(srpt_srq_size,
		 "Shared receive queue (SRQ) size.");

static int srpt_sq_size = DEF_SRPT_SQ_SIZE;
module_param(srpt_sq_size, int, 0444);
MODULE_PARM_DESC(srpt_sq_size,
		 "Per-channel send queue (SQ) size.");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31) \
    || defined(RHEL_MAJOR) && RHEL_MAJOR -0 <= 5
static int use_port_guid_in_session_name;
#else
static bool use_port_guid_in_session_name;
#endif
module_param(use_port_guid_in_session_name, bool, 0444);
MODULE_PARM_DESC(use_port_guid_in_session_name,
		 "Use target port ID in the session name such that"
		 " redundant paths between multiport systems can be masked.");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31) \
    || defined(RHEL_MAJOR) && RHEL_MAJOR -0 <= 5
static int use_node_guid_in_target_name;
#else
static bool use_node_guid_in_target_name;
#endif
module_param(use_node_guid_in_target_name, bool, 0444);
MODULE_PARM_DESC(use_node_guid_in_target_name,
		 "Use HCA node GUID as SCST target name.");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31) \
    || defined(RHEL_MAJOR) && RHEL_MAJOR -0 <= 5
static int one_target_per_port;
#else
static bool one_target_per_port;
#endif
module_param(one_target_per_port, bool, 0444);
MODULE_PARM_DESC(one_target_per_port,
		 "One SCST target per HCA port instead of one per HCA.");

static int srpt_get_u64_x(char *buffer, struct kernel_param *kp)
{
	return sprintf(buffer, "0x%016llx", *(u64 *)kp->arg);
}
module_param_call(srpt_service_guid, NULL, srpt_get_u64_x, &srpt_service_guid,
		  0444);
MODULE_PARM_DESC(srpt_service_guid,
		 "Using this value for ioc_guid, id_ext, and cm_listen_id"
		 " instead of using the node_guid of the first HCA.");

/*
 * Note: changing any of the two constants below into SCST_CONTEXT_DIRECT is
 * dangerous because it might cause IB completions to be processed too late
 * ("IB completion for idx <n> has not been received in time").
 */
static const enum scst_exec_context srpt_new_iu_context = SCST_CONTEXT_THREAD;
static const enum scst_exec_context srpt_xmt_rsp_context = SCST_CONTEXT_THREAD;
static const enum scst_exec_context srpt_send_context = SCST_CONTEXT_DIRECT;

static struct ib_client srpt_client;
static struct scst_tgt_template srpt_template;
static void srpt_unregister_mad_agent(struct srpt_device *sdev);
#ifdef CONFIG_SCST_PROC
static void srpt_unregister_procfs_entry(struct scst_tgt_template *tgt);
#endif /*CONFIG_SCST_PROC*/
static void srpt_unmap_sg_to_ib_sge(struct srpt_rdma_ch *ch,
				    struct srpt_send_ioctx *ioctx);
static void srpt_drain_channel(struct ib_cm_id *cm_id);
static void srpt_destroy_ch_ib(struct srpt_rdma_ch *ch);

static enum rdma_ch_state srpt_set_ch_state_to_disc(struct srpt_rdma_ch *ch)
{
	unsigned long flags;
	enum rdma_ch_state prev;
	bool changed = false;

	spin_lock_irqsave(&ch->spinlock, flags);
	prev = ch->state;
	switch (prev) {
	case CH_CONNECTING:
	case CH_LIVE:
		ch->state = CH_DISCONNECTING;
		wake_up_process(ch->thread);
		changed = true;
		break;
	default:
		break;
	}
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return prev;
}

static bool srpt_set_ch_state_to_draining(struct srpt_rdma_ch *ch)
{
	unsigned long flags;
	bool changed = false;

	spin_lock_irqsave(&ch->spinlock, flags);
	switch (ch->state) {
	case CH_CONNECTING:
	case CH_LIVE:
	case CH_DISCONNECTING:
		ch->state = CH_DRAINING;
		wake_up_process(ch->thread);
		changed = true;
		break;
	default:
		break;
	}
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return changed;
}

/**
 * srpt_test_and_set_ch_state() - Test and set the channel state.
 *
 * Returns true if and only if the channel state has been set to the new state.
 */
static bool srpt_test_and_set_ch_state(struct srpt_rdma_ch *ch,
				       enum rdma_ch_state old,
				       enum rdma_ch_state new)
{
	unsigned long flags;
	bool changed = false;

	spin_lock_irqsave(&ch->spinlock, flags);
	if (ch->state == old) {
		ch->state = new;
		wake_up_process(ch->thread);
		changed = true;
	}
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return changed;
}

/**
 * srpt_adjust_req_lim() - Adjust ch->req_lim and ch->req_lim_delta atomically.
 *
 * Returns the new value of ch->req_lim.
 */
static int srpt_adjust_req_lim(struct srpt_rdma_ch *ch, int req_lim_change,
			       int req_lim_delta_change)
{
	int req_lim;
	unsigned long flags;

	spin_lock_irqsave(&ch->spinlock, flags);
	ch->req_lim += req_lim_change;
	req_lim = ch->req_lim;
	ch->req_lim_delta += req_lim_delta_change;
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return req_lim;
}

/**
 * srpt_inc_req_lim() - Increase ch->req_lim and decrease ch->req_lim_delta.
 *
 * Returns one more than the previous value of ch->req_lim_delta.
 */
static int srpt_inc_req_lim(struct srpt_rdma_ch *ch)
{
	int req_lim_delta;
	unsigned long flags;

	spin_lock_irqsave(&ch->spinlock, flags);
	req_lim_delta = ch->req_lim_delta + 1;
	ch->req_lim += req_lim_delta;
	ch->req_lim_delta = 0;
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return req_lim_delta;
}

/**
 * srpt_undo_inc_req_lim() - Undo the effect of srpt_inc_req_lim.
 */
static int srpt_undo_inc_req_lim(struct srpt_rdma_ch *ch, int req_lim_delta)
{
	return srpt_adjust_req_lim(ch, -req_lim_delta, req_lim_delta - 1);
}

/**
 * srpt_event_handler() - Asynchronous IB event callback function.
 *
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
	u8 port_num;

	TRACE_ENTRY();

	sdev = ib_get_client_data(event->device, &srpt_client);
	if (!sdev || sdev->device != event->device)
		return;

	TRACE_DBG("ASYNC event= %d on device= %s",
		  event->event, sdev->device->name);

	switch (event->event) {
	case IB_EVENT_PORT_ERR:
		port_num = event->element.port_num - 1;
		if (port_num < sdev->device->phys_port_cnt) {
			sport = &sdev->port[port_num];
			sport->lid = 0;
			sport->sm_lid = 0;
		} else {
			WARN(true, "event %d: port_num %d out of range 1..%d\n",
			     event->event, port_num + 1,
			     sdev->device->phys_port_cnt);
		}
		break;
	case IB_EVENT_PORT_ACTIVE:
	case IB_EVENT_LID_CHANGE:
	case IB_EVENT_PKEY_CHANGE:
	case IB_EVENT_SM_CHANGE:
	case IB_EVENT_CLIENT_REREGISTER:
		/* Refresh port data asynchronously. */
		port_num = event->element.port_num - 1;
		if (port_num < sdev->device->phys_port_cnt) {
			sport = &sdev->port[port_num];
			if (!sport->lid && !sport->sm_lid)
				schedule_work(&sport->work);
		} else {
			WARN(true, "event %d: port_num %d out of range 1..%d\n",
			     event->event, port_num + 1,
			     sdev->device->phys_port_cnt);
		}
		break;
	default:
		PRINT_ERROR("received unrecognized IB event %d", event->event);
		break;
	}

	TRACE_EXIT();
}

/**
 * srpt_srq_event() - IB SRQ event callback function.
 */
static void srpt_srq_event(struct ib_event *event, void *ctx)
{
	TRACE_DBG("SRQ event %d", event->event);
}

static const char *get_ch_state_name(enum rdma_ch_state s)
{
	switch (s) {
	case CH_CONNECTING:
		return "connecting";
	case CH_LIVE:
		return "live";
	case CH_DISCONNECTING:
		return "disconnecting";
	case CH_DRAINING:
		return "draining";
	}
	return "???";
}

/**
 * srpt_qp_event() - IB QP event callback function.
 */
static void srpt_qp_event(struct ib_event *event, struct srpt_rdma_ch *ch)
{
	unsigned long flags;

	TRACE_DBG("QP event %d on cm_id=%p sess_name=%s state=%s",
		  event->event, ch->cm_id, ch->sess_name,
		  get_ch_state_name(ch->state));

	switch (event->event) {
	case IB_EVENT_COMM_EST:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20) || defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
		ib_cm_notify(ch->cm_id, event->event);
#else
		/* Vanilla 2.6.19 kernel (or before) without OFED. */
		PRINT_ERROR("how to perform ib_cm_notify() on a"
			    " vanilla 2.6.18 kernel ???");
#endif
		break;
	case IB_EVENT_QP_LAST_WQE_REACHED:
		TRACE_DBG("%s, state %s: received Last WQE event.",
			  ch->sess_name, get_ch_state_name(ch->state));
		BUG_ON(!ch->thread);
		spin_lock_irqsave(&ch->spinlock, flags);
		ch->last_wqe_received = true;
		wake_up_process(ch->thread);
		spin_unlock_irqrestore(&ch->spinlock, flags);
		break;
	default:
		PRINT_ERROR("received unrecognized IB QP event %d",
			    event->event);
		break;
	}
}

/**
 * srpt_set_ioc() - Helper function for initializing an IOUnitInfo structure.
 *
 * @slot: one-based slot number.
 * @value: four-bit value.
 *
 * Copies the lowest four bits of value in element slot of the array of four
 * bit elements called c_list (controller list). The index slot is one-based.
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

/**
 * srpt_get_class_port_info() - Copy ClassPortInfo to a management datagram.
 *
 * See also section 16.3.3.1 ClassPortInfo in the InfiniBand Architecture
 * Specification.
 */
static void srpt_get_class_port_info(struct ib_dm_mad *mad)
{
	struct ib_class_port_info *cif;

	cif = (struct ib_class_port_info *)mad->data;
	memset(cif, 0, sizeof(*cif));
	cif->base_version = 1;
	cif->class_version = 1;
	cif->resp_time_value = 20;

	mad->mad_hdr.status = 0;
}

/**
 * srpt_get_iou() - Write IOUnitInfo to a management datagram.
 *
 * See also section 16.3.3.3 IOUnitInfo in the InfiniBand Architecture
 * Specification. See also section B.7, table B.6 in the SRP r16a document.
 */
static void srpt_get_iou(struct ib_dm_mad *mad)
{
	struct ib_dm_iou_info *ioui;
	u8 slot;
	int i;

	ioui = (struct ib_dm_iou_info *)mad->data;
	ioui->change_id = cpu_to_be16(1);
	ioui->max_controllers = 16;

	/* set present for slot 1 and empty for the rest */
	srpt_set_ioc(ioui->controller_list, 1, 1);
	for (i = 1, slot = 2; i < 16; i++, slot++)
		srpt_set_ioc(ioui->controller_list, slot, 0);

	mad->mad_hdr.status = 0;
}

/**
 * srpt_get_ioc() - Write IOControllerprofile to a management datagram.
 *
 * See also section 16.3.3.4 IOControllerProfile in the InfiniBand
 * Architecture Specification. See also section B.7, table B.7 in the SRP
 * r16a document.
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

	memset(iocp, 0, sizeof(*iocp));
	strcpy(iocp->id_string, SRPT_ID_STRING);
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
	iocp->send_queue_depth = cpu_to_be16(sdev->srq_size);
	iocp->rdma_read_depth = 4;
	iocp->send_size = cpu_to_be32(srp_max_req_size);
	iocp->rdma_size = cpu_to_be32(min(max(srp_max_rdma_size, 256U),
					  1U << 24));
	iocp->num_svc_entries = 1;
	iocp->op_cap_mask = SRP_SEND_TO_IOC | SRP_SEND_FROM_IOC |
		SRP_RDMA_READ_FROM_IOC | SRP_RDMA_WRITE_FROM_IOC;

	mad->mad_hdr.status = 0;
}

/**
 * srpt_get_svc_entries() - Write ServiceEntries to a management datagram.
 *
 * See also section 16.3.3.5 ServiceEntries in the InfiniBand Architecture
 * Specification. See also section B.7, table B.8 in the SRP r16a document.
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
	memset(svc_entries, 0, sizeof(*svc_entries));
	svc_entries->service_entries[0].id = cpu_to_be64(ioc_guid);
	snprintf(svc_entries->service_entries[0].name,
		 sizeof(svc_entries->service_entries[0].name),
		 "%s%016llx",
		 SRP_SERVICE_NAME_PREFIX,
		 ioc_guid);

	mad->mad_hdr.status = 0;
}

/**
 * srpt_mgmt_method_get() - Process a received management datagram.
 * @sp:      source port through which the MAD has been received.
 * @rq_mad:  received MAD.
 * @rsp_mad: response MAD.
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

/**
 * srpt_mad_send_handler() - Post MAD-send callback function.
 */
static void srpt_mad_send_handler(struct ib_mad_agent *mad_agent,
				  struct ib_mad_send_wc *mad_wc)
{
	ib_destroy_ah(mad_wc->send_buf->ah);
	ib_free_send_mad(mad_wc->send_buf);
}

/**
 * srpt_mad_recv_handler() - MAD reception callback function.
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
	memcpy(dm_mad, mad_wc->recv_buf.mad, sizeof(*dm_mad));
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

/**
 * srpt_refresh_port() - Configure a HCA port.
 *
 * Enable InfiniBand management datagram processing, update the cached sm_lid,
 * lid and gid values, and register a callback function for processing MADs
 * on the specified port.
 *
 * Note: It is safe to call this function more than once for the same port.
 */
static int srpt_refresh_port(struct srpt_port *sport)
{
	struct ib_mad_reg_req reg_req;
	struct ib_port_modify port_modify;
	struct ib_port_attr port_attr;
	int ret;
	char tgt_name[40];

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37) /* commit a3f5adaf4 */
	switch (rdma_port_get_link_layer(sport->sdev->device, sport->port)) {
	case IB_LINK_LAYER_UNSPECIFIED:
	case IB_LINK_LAYER_INFINIBAND:
		break;
	case IB_LINK_LAYER_ETHERNET:
	default:
		return 0;
	}
#endif

	memset(&port_modify, 0, sizeof(port_modify));
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
		memset(&reg_req, 0, sizeof(reg_req));
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

	if (one_target_per_port && !sport->srpt_tgt.scst_tgt) {
		snprintf(tgt_name, sizeof(tgt_name),
			 "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			 be16_to_cpu(((__be16 *) sport->gid.raw)[0]),
			 be16_to_cpu(((__be16 *) sport->gid.raw)[1]),
			 be16_to_cpu(((__be16 *) sport->gid.raw)[2]),
			 be16_to_cpu(((__be16 *) sport->gid.raw)[3]),
			 be16_to_cpu(((__be16 *) sport->gid.raw)[4]),
			 be16_to_cpu(((__be16 *) sport->gid.raw)[5]),
			 be16_to_cpu(((__be16 *) sport->gid.raw)[6]),
			 be16_to_cpu(((__be16 *) sport->gid.raw)[7]));
		sport->srpt_tgt.scst_tgt = scst_register_target(&srpt_template,
						       tgt_name);
		if (sport->srpt_tgt.scst_tgt)
			scst_tgt_set_tgt_priv(sport->srpt_tgt.scst_tgt, sport);
		else
			PRINT_ERROR("Registration of target %s failed.",
				    tgt_name);
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

/**
 * srpt_unregister_mad_agent() - Unregister MAD callback functions.
 *
 * Note: It is safe to call this function more than once for the same device.
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
			PRINT_ERROR("disabling MAD processing failed.");
		if (sport->mad_agent) {
			ib_unregister_mad_agent(sport->mad_agent);
			sport->mad_agent = NULL;
		}
	}
}

/**
 * srpt_alloc_ioctx() - Allocate an SRPT I/O context structure.
 */
static struct srpt_ioctx *srpt_alloc_ioctx(struct srpt_device *sdev,
					   int ioctx_size, int dma_size,
					   enum dma_data_direction dir)
{
	struct srpt_ioctx *ioctx;

	ioctx = kmalloc(ioctx_size, GFP_KERNEL);
	if (!ioctx)
		goto err;

	ioctx->buf = kmalloc(dma_size, GFP_KERNEL);
	if (!ioctx->buf)
		goto err_free_ioctx;

	ioctx->dma = ib_dma_map_single(sdev->device, ioctx->buf, dma_size, dir);
	if (ib_dma_mapping_error(sdev->device, ioctx->dma))
		goto err_free_buf;

	return ioctx;

err_free_buf:
	kfree(ioctx->buf);
err_free_ioctx:
	kfree(ioctx);
err:
	return NULL;
}

/**
 * srpt_free_ioctx() - Free an SRPT I/O context structure.
 */
static void srpt_free_ioctx(struct srpt_device *sdev, struct srpt_ioctx *ioctx,
			    int dma_size, enum dma_data_direction dir)
{
	if (!ioctx)
		return;

	ib_dma_unmap_single(sdev->device, ioctx->dma, dma_size, dir);
	kfree(ioctx->buf);
	kfree(ioctx);
}

/**
 * srpt_alloc_ioctx_ring() - Allocate a ring of SRPT I/O context structures.
 * @sdev:       Device to allocate the I/O context ring for.
 * @ring_size:  Number of elements in the I/O context ring.
 * @ioctx_size: I/O context size.
 * @dma_size:   DMA buffer size.
 * @dir:        DMA data direction.
 */
static struct srpt_ioctx **srpt_alloc_ioctx_ring(struct srpt_device *sdev,
				int ring_size, int ioctx_size,
				int dma_size, enum dma_data_direction dir)
{
	struct srpt_ioctx **ring;
	int i;

	TRACE_ENTRY();

	WARN_ON(ioctx_size != sizeof(struct srpt_recv_ioctx) &&
		ioctx_size != sizeof(struct srpt_send_ioctx));

	ring = kmalloc(ring_size * sizeof(ring[0]), GFP_KERNEL);
	if (!ring)
		goto out;
	for (i = 0; i < ring_size; ++i) {
		ring[i] = srpt_alloc_ioctx(sdev, ioctx_size, dma_size, dir);
		if (!ring[i])
			goto err;
		ring[i]->index = i;
	}
	goto out;

err:
	while (--i >= 0)
		srpt_free_ioctx(sdev, ring[i], dma_size, dir);
	kfree(ring);
	ring = NULL;
out:
	TRACE_EXIT_HRES(ring);
	return ring;
}

/**
 * srpt_free_ioctx_ring() - Free the ring of SRPT I/O context structures.
 */
static void srpt_free_ioctx_ring(struct srpt_ioctx **ioctx_ring,
				 struct srpt_device *sdev, int ring_size,
				 int dma_size, enum dma_data_direction dir)
{
	int i;

	for (i = 0; i < ring_size; ++i)
		srpt_free_ioctx(sdev, ioctx_ring[i], dma_size, dir);
	kfree(ioctx_ring);
}

/**
 * srpt_set_cmd_state() - Set the state of a SCSI command.
 * @new: New state.
 *
 * Does not modify the state of aborted commands. Returns the previous command
 * state.
 */
static enum srpt_command_state srpt_set_cmd_state(struct srpt_send_ioctx *ioctx,
						  enum srpt_command_state new)
{
	enum srpt_command_state previous;

	BUG_ON(!ioctx);

	spin_lock(&ioctx->spinlock);
	previous = ioctx->state;
	if (previous != SRPT_STATE_DONE)
		ioctx->state = new;
	spin_unlock(&ioctx->spinlock);

	return previous;
}

/**
 * srpt_test_and_set_cmd_state() - Test and set the state of a command.
 *
 * Returns true if and only if the previous command state was equal to 'old'.
 */
static bool srpt_test_and_set_cmd_state(struct srpt_send_ioctx *ioctx,
					enum srpt_command_state old,
					enum srpt_command_state new)
{
	enum srpt_command_state previous;

	WARN_ON(!ioctx);
	WARN_ON(old == SRPT_STATE_DONE);
	WARN_ON(new == SRPT_STATE_NEW);

	spin_lock(&ioctx->spinlock);
	previous = ioctx->state;
	if (previous == old)
		ioctx->state = new;
	spin_unlock(&ioctx->spinlock);

	return previous == old;
}

/**
 * srpt_post_recv() - Post an IB receive request.
 */
static int srpt_post_recv(struct srpt_device *sdev,
			  struct srpt_recv_ioctx *ioctx)
{
	struct ib_sge list;
	struct ib_recv_wr wr, *bad_wr;

	BUG_ON(!sdev);
	wr.wr_id = encode_wr_id(SRPT_RECV, ioctx->ioctx.index);

	list.addr = ioctx->ioctx.dma;
	list.length = srp_max_req_size;
	list.lkey = sdev->mr->lkey;

	wr.next = NULL;
	wr.sg_list = &list;
	wr.num_sge = 1;

	return ib_post_srq_recv(sdev->srq, &wr, &bad_wr);
}

static int srpt_adjust_srq_wr_avail(struct srpt_rdma_ch *ch, int delta)
{
	int res;
	unsigned long flags;

	spin_lock_irqsave(&ch->spinlock, flags);
	ch->sq_wr_avail += delta;
	res = ch->sq_wr_avail;
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return res;
}

/**
 * srpt_post_send() - Post an IB send request.
 *
 * Returns zero upon success and a non-zero value upon failure.
 */
static int srpt_post_send(struct srpt_rdma_ch *ch,
			  struct srpt_send_ioctx *ioctx, int len)
{
	struct ib_sge list;
	struct ib_send_wr wr, *bad_wr;
	struct srpt_device *sdev = ch->sport->sdev;
	int ret;

	ret = -ENOMEM;
	if (srpt_adjust_srq_wr_avail(ch, -1) < 0) {
		PRINT_WARNING("IB send queue full (needed 1)");
		goto out;
	}

	ib_dma_sync_single_for_device(sdev->device, ioctx->ioctx.dma, len,
				      DMA_TO_DEVICE);

	list.addr = ioctx->ioctx.dma;
	list.length = len;
	list.lkey = sdev->mr->lkey;

	wr.next = NULL;
	wr.wr_id = encode_wr_id(SRPT_SEND, ioctx->ioctx.index);
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	ret = ib_post_send(ch->qp, &wr, &bad_wr);

out:
	if (ret < 0)
		srpt_adjust_srq_wr_avail(ch, 1);
	return ret;
}

/**
 * srpt_get_desc_tbl() - Parse the data descriptors of an SRP_CMD request.
 * @ioctx: Pointer to the I/O context associated with the request.
 * @srp_cmd: Pointer to the SRP_CMD request data.
 * @dir: Pointer to the variable to which the transfer direction will be
 *   written.
 * @data_len: Pointer to the variable to which the total data length of all
 *   descriptors in the SRP_CMD request will be written.
 *
 * This function initializes ioctx->nrbuf and ioctx->r_bufs.
 *
 * Returns -EINVAL when the SRP_CMD request contains inconsistent descriptors;
 * -ENOMEM when memory allocation fails and zero upon success.
 */
static int srpt_get_desc_tbl(struct srpt_send_ioctx *ioctx,
			     struct srp_cmd *srp_cmd,
			     scst_data_direction *dir, u64 *data_len)
{
	struct srp_indirect_buf *idb;
	struct srp_direct_buf *db;
	unsigned add_cdb_offset;
	int ret;

	/*
	 * The pointer computations below will only be compiled correctly
	 * if srp_cmd::add_data is declared as s8*, u8*, s8[] or u8[], so check
	 * whether srp_cmd::add_data has been declared as a byte pointer.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	BUILD_BUG_ON(!__same_type(srp_cmd->add_data[0], (s8)0)
		     && !__same_type(srp_cmd->add_data[0], (u8)0));
#else
	/* Note: the __same_type() macro has been introduced in kernel 2.6.31.*/
#endif

	BUG_ON(!dir);
	BUG_ON(!data_len);

	ret = 0;
	*data_len = 0;

	/*
	 * The lower four bits of the buffer format field contain the DATA-IN
	 * buffer descriptor format, and the highest four bits contain the
	 * DATA-OUT buffer descriptor format.
	 */
	*dir = SCST_DATA_NONE;
	if (srp_cmd->buf_fmt & 0xf)
		/* DATA-IN: transfer data from target to initiator (read). */
		*dir = SCST_DATA_READ;
	else if (srp_cmd->buf_fmt >> 4)
		/* DATA-OUT: transfer data from initiator to target (write). */
		*dir = SCST_DATA_WRITE;

	/*
	 * According to the SRP spec, the lower two bits of the 'ADDITIONAL
	 * CDB LENGTH' field are reserved and the size in bytes of this field
	 * is four times the value specified in bits 3..7. Hence the "& ~3".
	 */
	add_cdb_offset = srp_cmd->add_cdb_len & ~3;
	if (((srp_cmd->buf_fmt & 0xf) == SRP_DATA_DESC_DIRECT) ||
	    ((srp_cmd->buf_fmt >> 4) == SRP_DATA_DESC_DIRECT)) {
		ioctx->n_rbuf = 1;
		ioctx->rbufs = &ioctx->single_rbuf;

		db = (struct srp_direct_buf *)(srp_cmd->add_data
					       + add_cdb_offset);
		memcpy(ioctx->rbufs, db, sizeof(*db));
		*data_len = be32_to_cpu(db->len);
	} else if (((srp_cmd->buf_fmt & 0xf) == SRP_DATA_DESC_INDIRECT) ||
		   ((srp_cmd->buf_fmt >> 4) == SRP_DATA_DESC_INDIRECT)) {
		idb = (struct srp_indirect_buf *)(srp_cmd->add_data
						  + add_cdb_offset);

		ioctx->n_rbuf = be32_to_cpu(idb->table_desc.len) / sizeof(*db);

		if (ioctx->n_rbuf >
		    (srp_cmd->data_out_desc_cnt + srp_cmd->data_in_desc_cnt)) {
			PRINT_ERROR("received unsupported SRP_CMD request type"
				    " (%u out + %u in != %u / %zu)",
				    srp_cmd->data_out_desc_cnt,
				    srp_cmd->data_in_desc_cnt,
				    be32_to_cpu(idb->table_desc.len),
				    sizeof(*db));
			ioctx->n_rbuf = 0;
			ret = -EINVAL;
			goto out;
		}

		if (ioctx->n_rbuf == 1)
			ioctx->rbufs = &ioctx->single_rbuf;
		else {
			ioctx->rbufs =
				kmalloc(ioctx->n_rbuf * sizeof(*db), GFP_ATOMIC);
			if (!ioctx->rbufs) {
				ioctx->n_rbuf = 0;
				ret = -ENOMEM;
				goto out;
			}
		}

		db = idb->desc_list;
		memcpy(ioctx->rbufs, db, ioctx->n_rbuf * sizeof(*db));
		*data_len = be32_to_cpu(idb->len);
	}
out:
	return ret;
}

/**
 * srpt_init_ch_qp() - Initialize queue pair attributes.
 *
 * Initialized the attributes of queue pair 'qp' by allowing local write,
 * remote read and remote write. Also transitions 'qp' to state IB_QPS_INIT.
 */
static int srpt_init_ch_qp(struct srpt_rdma_ch *ch, struct ib_qp *qp)
{
	struct ib_qp_attr *attr;
	int ret;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_INIT;
	attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ |
	    IB_ACCESS_REMOTE_WRITE;
	attr->port_num = ch->sport->port;
	attr->pkey_index = ch->pkey_index;

	ret = ib_modify_qp(qp, attr,
			   IB_QP_STATE | IB_QP_ACCESS_FLAGS | IB_QP_PORT |
			   IB_QP_PKEY_INDEX);

	kfree(attr);
	return ret;
}

/**
 * srpt_ch_qp_rtr() - Change the state of a channel to 'ready to receive' (RTR).
 * @ch: channel of the queue pair.
 * @qp: queue pair to change the state of.
 *
 * Returns zero upon success and a negative value upon failure.
 */
static int srpt_ch_qp_rtr(struct srpt_rdma_ch *ch, struct ib_qp *qp)
{
	struct ib_qp_attr *attr;
	int attr_mask;
	int ret;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_RTR;
	ret = ib_cm_init_qp_attr(ch->cm_id, attr, &attr_mask);
	if (ret)
		goto out;

	attr->max_dest_rd_atomic = 4;

	ret = ib_modify_qp(qp, attr, attr_mask);

out:
	kfree(attr);
	return ret;
}

/**
 * srpt_ch_qp_rts() - Change the state of a channel to 'ready to send' (RTS).
 * @ch: channel of the queue pair.
 * @qp: queue pair to change the state of.
 *
 * Returns zero upon success and a negative value upon failure.
 */
static int srpt_ch_qp_rts(struct srpt_rdma_ch *ch, struct ib_qp *qp)
{
	struct ib_qp_attr *attr;
	int attr_mask;
	int ret;
	uint64_t T_tr_ns, max_compl_time_ms;
	uint32_t T_tr_ms;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_RTS;
	ret = ib_cm_init_qp_attr(ch->cm_id, attr, &attr_mask);
	if (ret)
		goto out;

	attr->max_rd_atomic = 4;

	/*
	 * From IBTA C9-140: Transport Timer timeout interval
	 * T_tr = 4.096 us * 2**(local ACK timeout) where the local ACK timeout
	 * is a five-bit value, with zero meaning that the timer is disabled.
	 */
	WARN_ON(attr->timeout >= (1 << 5));
	if (attr->timeout) {
		T_tr_ns = 1ULL << (12 + attr->timeout);
		max_compl_time_ms = attr->retry_cnt * 4 * T_tr_ns;
		do_div(max_compl_time_ms, 1000000);
		T_tr_ms = T_tr_ns;
		do_div(T_tr_ms, 1000000);
		TRACE_DBG("Session %s: QP local ack timeout = %d or T_tr ="
			  " %u ms; retry_cnt = %d; max compl. time = %d ms",
			  ch->sess_name, attr->timeout, T_tr_ms,
			  attr->retry_cnt, (unsigned)max_compl_time_ms);

		if (max_compl_time_ms >= RDMA_COMPL_TIMEOUT_S * 1000) {
			PRINT_ERROR("Maximum RDMA completion time (%d ms)"
				    " exceeds ib_srpt timeout (%d ms)",
				    (unsigned)max_compl_time_ms,
				    1000 * RDMA_COMPL_TIMEOUT_S);
		}
	}

	ret = ib_modify_qp(qp, attr, attr_mask);

out:
	kfree(attr);
	return ret;
}

/**
 * srpt_ch_qp_err() - Set the channel queue pair state to 'error'.
 */
static int srpt_ch_qp_err(struct srpt_rdma_ch *ch)
{
	struct ib_qp_attr *attr;
	int ret;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_ERR;
	ret = ib_modify_qp(ch->qp, attr, IB_QP_STATE);
	kfree(attr);
	return ret;
}

/**
 * srpt_get_send_ioctx() - Obtain an I/O context for sending to the initiator.
 */
static struct srpt_send_ioctx *srpt_get_send_ioctx(struct srpt_rdma_ch *ch)
{
	struct srpt_send_ioctx *ioctx;
	unsigned long flags;

	BUG_ON(!ch);

	ioctx = NULL;
	spin_lock_irqsave(&ch->spinlock, flags);
	if (!list_empty(&ch->free_list)) {
		ioctx = list_first_entry(&ch->free_list,
					 struct srpt_send_ioctx, free_list);
		list_del(&ioctx->free_list);
	}
	spin_unlock_irqrestore(&ch->spinlock, flags);

	if (!ioctx)
		return ioctx;

	BUG_ON(ioctx->ch != ch);
	spin_lock_init(&ioctx->spinlock);
	ioctx->state = SRPT_STATE_NEW;
	ioctx->n_rbuf = 0;
	ioctx->rbufs = NULL;
	ioctx->n_rdma = 0;
	ioctx->n_rdma_ius = 0;
	ioctx->rdma_ius = NULL;
	ioctx->mapped_sg_count = 0;
	memset(&ioctx->scmnd, 0, sizeof(ioctx->scmnd));

	return ioctx;
}

/**
 * srpt_put_send_ioctx() - Free up resources.
 */
static void srpt_put_send_ioctx(struct srpt_send_ioctx *ioctx)
{
	struct srpt_rdma_ch *ch;
	unsigned long flags;

	BUG_ON(!ioctx);
	ch = ioctx->ch;
	BUG_ON(!ch);

	/*
	 * If the WARN_ON() below gets triggered this means that
	 * srpt_unmap_sg_to_ib_sge() has not been called before
	 * scst_tgt_cmd_done().
	 */
	WARN_ON(ioctx->mapped_sg_count);

	if (ioctx->n_rbuf > 1) {
		kfree(ioctx->rbufs);
		ioctx->rbufs = NULL;
		ioctx->n_rbuf = 0;
	}

	spin_lock_irqsave(&ch->spinlock, flags);
	list_add(&ioctx->free_list, &ch->free_list);
	spin_unlock_irqrestore(&ch->spinlock, flags);
}

/**
 * srpt_abort_cmd() - Make SCST stop processing a SCSI command.
 * @ioctx:   I/O context associated with the SCSI command.
 * @context: Preferred execution context.
 */
static void srpt_abort_cmd(struct srpt_send_ioctx *ioctx,
			   enum scst_exec_context context)
{
	struct scst_cmd *scmnd;
	enum srpt_command_state state;

	TRACE_ENTRY();

	BUG_ON(!ioctx);

	/*
	 * If the command is in a state where the target core is waiting for
	 * the ib_srpt driver, change the state to the next state. Changing
	 * the state of the command from SRPT_STATE_NEED_DATA to
	 * SRPT_STATE_DATA_IN ensures that srpt_xmit_response() will call this
	 * function a second time.
	 */
	spin_lock(&ioctx->spinlock);
	state = ioctx->state;
	switch (state) {
	case SRPT_STATE_NEED_DATA:
		ioctx->state = SRPT_STATE_DATA_IN;
		break;
	case SRPT_STATE_DATA_IN:
	case SRPT_STATE_CMD_RSP_SENT:
	case SRPT_STATE_MGMT_RSP_SENT:
		ioctx->state = SRPT_STATE_DONE;
		break;
	default:
		break;
	}
	spin_unlock(&ioctx->spinlock);

	if (state == SRPT_STATE_DONE)
		goto out;

	scmnd = &ioctx->scmnd;

	WARN_ON(ioctx != scst_cmd_get_tgt_priv(scmnd));

	TRACE_DBG("Aborting cmd with state %d and tag %lld",
		  state, scst_cmd_get_tag(scmnd));

	switch (state) {
	case SRPT_STATE_NEW:
	case SRPT_STATE_DATA_IN:
	case SRPT_STATE_MGMT:
		/*
		 * Do nothing - defer abort processing until
		 * srpt_xmit_response() is invoked.
		 */
		WARN_ON(!scst_cmd_aborted_on_xmit(scmnd));
		break;
	case SRPT_STATE_NEED_DATA:
		/* SCST_DATA_WRITE - RDMA read error or RDMA read timeout. */
		scst_set_cmd_error(scmnd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		scst_rx_data(scmnd, SCST_RX_STATUS_ERROR_SENSE_SET, context);
		break;
	case SRPT_STATE_CMD_RSP_SENT:
		/*
		 * SRP_RSP sending failed or the SRP_RSP send completion has
		 * not been received in time.
		 */
		srpt_unmap_sg_to_ib_sge(ioctx->ch, ioctx);
		scst_set_delivery_status(scmnd, SCST_CMD_DELIVERY_ABORTED);
		scst_tgt_cmd_done(scmnd, context);
		break;
	case SRPT_STATE_MGMT_RSP_SENT:
		/*
		 * Management command response sending failed. This state is
		 * never reached since there is no scmnd associated with
		 * management commands. Note: the SCST core frees these
		 * commands immediately after srpt_tsk_mgmt_done() returned.
		 */
		WARN(true, "Unexpected command state %d", state);
		break;
	default:
		WARN(true, "Unexpected command state %d", state);
		break;
	}

out:
	;

	TRACE_EXIT();
}

/**
 * srpt_handle_send_err_comp() - Process an IB_WC_SEND error completion.
 */
static void srpt_handle_send_err_comp(struct srpt_rdma_ch *ch, u64 wr_id,
				      enum scst_exec_context context)
{
	struct srpt_send_ioctx *ioctx;
	enum srpt_command_state state;
	struct scst_cmd *scmnd;
	u32 index;

	srpt_adjust_srq_wr_avail(ch, 1);

	index = idx_from_wr_id(wr_id);
	ioctx = ch->ioctx_ring[index];
	state = ioctx->state;
	scmnd = &ioctx->scmnd;

	EXTRACHECKS_WARN_ON(state != SRPT_STATE_CMD_RSP_SENT
			    && state != SRPT_STATE_MGMT_RSP_SENT
			    && state != SRPT_STATE_NEED_DATA
			    && state != SRPT_STATE_DONE);

	/*
	 * If SRP_RSP sending failed, undo the ch->req_lim and ch->req_lim_delta
	 * changes.
	 */
	if (state == SRPT_STATE_CMD_RSP_SENT
	    || state == SRPT_STATE_MGMT_RSP_SENT)
		srpt_undo_inc_req_lim(ch, ioctx->req_lim_delta);
	switch (state) {
	default:
		srpt_abort_cmd(ioctx, context);
		break;
	case SRPT_STATE_MGMT_RSP_SENT:
		srpt_put_send_ioctx(ioctx);
		break;
	case SRPT_STATE_DONE:
		PRINT_ERROR("Received more than one IB error completion"
			    " for wr_id = %u.", (unsigned)index);
		break;
	}
}

/**
 * srpt_handle_send_comp() - Process an IB send completion notification.
 */
static void srpt_handle_send_comp(struct srpt_rdma_ch *ch,
				  struct srpt_send_ioctx *ioctx,
				  enum scst_exec_context context)
{
	srpt_adjust_srq_wr_avail(ch, 1);

	switch (srpt_set_cmd_state(ioctx, SRPT_STATE_DONE)) {
	case SRPT_STATE_CMD_RSP_SENT:
		srpt_unmap_sg_to_ib_sge(ch, ioctx);
		scst_tgt_cmd_done(&ioctx->scmnd, context);
		break;
	case SRPT_STATE_MGMT_RSP_SENT:
		srpt_put_send_ioctx(ioctx);
		break;
	case SRPT_STATE_DONE:
		PRINT_ERROR("IB completion has been received too late for"
			    " wr_id = %u.", ioctx->ioctx.index);
		break;
	default:
		EXTRACHECKS_WARN_ON(true);
	}
}

/**
 * srpt_handle_rdma_comp() - Process an IB RDMA completion notification.
 */
static void srpt_handle_rdma_comp(struct srpt_rdma_ch *ch,
				  struct srpt_send_ioctx *ioctx,
				  enum srpt_opcode opcode,
				  enum scst_exec_context context)
{
	struct scst_cmd *scmnd;

	EXTRACHECKS_WARN_ON(ioctx->n_rdma <= 0);
	srpt_adjust_srq_wr_avail(ch, ioctx->n_rdma);

	scmnd = &ioctx->scmnd;
	if (opcode == SRPT_RDMA_READ_LAST && scmnd) {
		if (srpt_test_and_set_cmd_state(ioctx, SRPT_STATE_NEED_DATA,
						SRPT_STATE_DATA_IN))
			scst_rx_data(scmnd, SCST_RX_STATUS_SUCCESS, context);
		else
			PRINT_ERROR("%s[%d]: wrong state = %d", __func__,
				    __LINE__, ioctx->state);
	} else if (opcode == SRPT_RDMA_ABORT) {
		ioctx->rdma_aborted = true;
	} else {
		WARN(true, "scmnd == NULL (opcode %d)", opcode);
	}
}

/**
 * srpt_handle_rdma_err_comp() - Process an IB RDMA error completion.
 */
static void srpt_handle_rdma_err_comp(struct srpt_rdma_ch *ch,
				      struct srpt_send_ioctx *ioctx,
				      enum srpt_opcode opcode,
				      enum scst_exec_context context)
{
	struct scst_cmd *scmnd;
	enum srpt_command_state state;

	scmnd = &ioctx->scmnd;
	state = ioctx->state;
	switch (opcode) {
	case SRPT_RDMA_READ_LAST:
		if (ioctx->n_rdma <= 0) {
			PRINT_ERROR("Received invalid RDMA read error"
				    " completion with idx %d",
				    ioctx->ioctx.index);
			break;
		}
		srpt_adjust_srq_wr_avail(ch, ioctx->n_rdma);
		if (state == SRPT_STATE_NEED_DATA)
			srpt_abort_cmd(ioctx, context);
		else
			PRINT_ERROR("%s[%d]: wrong state = %d", __func__,
				    __LINE__, state);
		break;
	case SRPT_RDMA_WRITE_LAST:
		scst_set_delivery_status(scmnd, SCST_CMD_DELIVERY_ABORTED);
		break;
	default:
		PRINT_ERROR("%s[%d]: opcode = %u", __func__, __LINE__, opcode);
		break;
	}
}

/**
 * srpt_build_cmd_rsp() - Build an SRP_RSP response.
 * @ch: RDMA channel through which the request has been received.
 * @ioctx: I/O context associated with the SRP_CMD request. The response will
 *   be built in the buffer ioctx->buf points at and hence this function will
 *   overwrite the request data.
 * @tag: tag of the request for which this response is being generated.
 * @status: value for the STATUS field of the SRP_RSP information unit.
 * @sense_data: pointer to sense data to be included in the response.
 * @sense_data_len: length in bytes of the sense data.
 *
 * Returns the size in bytes of the SRP_RSP response.
 *
 * An SRP_RSP response contains a SCSI status or service response. See also
 * section 6.9 in the SRP r16a document for the format of an SRP_RSP
 * response. See also SPC-2 for more information about sense data.
 */
static int srpt_build_cmd_rsp(struct srpt_rdma_ch *ch,
			      struct srpt_send_ioctx *ioctx, u64 tag,
			      int status, const u8 *sense_data,
			      int sense_data_len)
{
	struct srp_rsp *srp_rsp;
	int max_sense_len;

	/*
	 * The lowest bit of all SAM-3 status codes is zero (see also
	 * paragraph 5.3 in SAM-3).
	 */
	EXTRACHECKS_WARN_ON(status & 1);

	srp_rsp = ioctx->ioctx.buf;
	BUG_ON(!srp_rsp);
	memset(srp_rsp, 0, sizeof(*srp_rsp));

	srp_rsp->opcode = SRP_RSP;
	srp_rsp->req_lim_delta = cpu_to_be32(ioctx->req_lim_delta);
	srp_rsp->tag = tag;
	srp_rsp->status = status;

	if (!scst_sense_valid(sense_data))
		sense_data_len = 0;
	else {
		BUILD_BUG_ON(MIN_MAX_RSP_SIZE <= sizeof(*srp_rsp));
		max_sense_len = ch->max_ti_iu_len - sizeof(*srp_rsp);
		if (sense_data_len > max_sense_len) {
			PRINT_WARNING("truncated sense data from %d to %d"
				" bytes", sense_data_len, max_sense_len);
			sense_data_len = max_sense_len;
		}

		srp_rsp->flags |= SRP_RSP_FLAG_SNSVALID;
		srp_rsp->sense_data_len = cpu_to_be32(sense_data_len);
		memcpy(srp_rsp + 1, sense_data, sense_data_len);
	}

	return sizeof(*srp_rsp) + sense_data_len;
}

/**
 * srpt_build_tskmgmt_rsp() - Build a task management response.
 * @ch:       RDMA channel through which the request has been received.
 * @ioctx:    I/O context in which the SRP_RSP response will be built.
 * @rsp_code: RSP_CODE that will be stored in the response.
 * @tag:      Tag of the request for which this response is being generated.
 *
 * Returns the size in bytes of the SRP_RSP response.
 *
 * An SRP_RSP response contains a SCSI status or service response. See also
 * section 6.9 in the SRP r16a document for the format of an SRP_RSP
 * response.
 */
static int srpt_build_tskmgmt_rsp(struct srpt_rdma_ch *ch,
				  struct srpt_send_ioctx *ioctx,
				  u8 rsp_code, u64 tag)
{
	struct srp_rsp *srp_rsp;
	int resp_data_len;
	int resp_len;

	resp_data_len = 4;
	resp_len = sizeof(*srp_rsp) + resp_data_len;

	srp_rsp = ioctx->ioctx.buf;
	BUG_ON(!srp_rsp);
	memset(srp_rsp, 0, sizeof(*srp_rsp));

	srp_rsp->opcode = SRP_RSP;
	srp_rsp->req_lim_delta = cpu_to_be32(ioctx->req_lim_delta);
	srp_rsp->tag = tag;

	srp_rsp->flags |= SRP_RSP_FLAG_RSPVALID;
	srp_rsp->resp_data_len = cpu_to_be32(resp_data_len);
	srp_rsp->data[3] = rsp_code;

	return resp_len;
}

/**
 * srpt_handle_cmd() - Process SRP_CMD.
 */
static int srpt_handle_cmd(struct srpt_rdma_ch *ch,
			   struct srpt_recv_ioctx *recv_ioctx,
			   struct srpt_send_ioctx *send_ioctx,
			   enum scst_exec_context context)
{
	struct scst_cmd *scmnd;
	struct srp_cmd *srp_cmd;
	scst_data_direction dir;
	u64 data_len;
	int ret;
	int atomic;

	BUG_ON(!send_ioctx);

	srp_cmd = recv_ioctx->ioctx.buf;

	atomic = context == SCST_CONTEXT_TASKLET ? SCST_ATOMIC
		 : SCST_NON_ATOMIC;
	scmnd = &send_ioctx->scmnd;
	ret = scst_rx_cmd_prealloced(scmnd, ch->scst_sess, (u8 *) &srp_cmd->lun,
				     sizeof(srp_cmd->lun), srp_cmd->cdb,
				     sizeof(srp_cmd->cdb), atomic);
	if (ret) {
		PRINT_ERROR("tag 0x%llx: SCST command initialization failed",
			    srp_cmd->tag);
		goto err;
	}

	ret = srpt_get_desc_tbl(send_ioctx, srp_cmd, &dir, &data_len);
	if (ret) {
		PRINT_ERROR("0x%llx: parsing SRP descriptor table failed.",
			    srp_cmd->tag);
		scst_set_cmd_error(scmnd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	}

	switch (srp_cmd->task_attr) {
	case SRP_CMD_HEAD_OF_Q:
		scst_cmd_set_queue_type(scmnd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case SRP_CMD_ORDERED_Q:
		scst_cmd_set_queue_type(scmnd, SCST_CMD_QUEUE_ORDERED);
		break;
	case SRP_CMD_SIMPLE_Q:
		scst_cmd_set_queue_type(scmnd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case SRP_CMD_ACA:
		scst_cmd_set_queue_type(scmnd, SCST_CMD_QUEUE_ACA);
		break;
	default:
		scst_cmd_set_queue_type(scmnd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

	scst_cmd_set_tag(scmnd, srp_cmd->tag);
	scst_cmd_set_tgt_priv(scmnd, send_ioctx);
	scst_cmd_set_expected(scmnd, dir, data_len);
	scst_cmd_init_done(scmnd, context);

	return 0;

err:
	srpt_put_send_ioctx(send_ioctx);
	return -1;
}

/**
 * srpt_handle_tsk_mgmt() - Process an SRP_TSK_MGMT information unit.
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
 * 6.7 in the SRP r16a document.
 */
static void srpt_handle_tsk_mgmt(struct srpt_rdma_ch *ch,
				 struct srpt_recv_ioctx *recv_ioctx,
				 struct srpt_send_ioctx *send_ioctx)
{
	struct srp_tsk_mgmt *srp_tsk;
	int ret;

	ret = -EOPNOTSUPP;

	BUG_ON(!send_ioctx);
	BUG_ON(send_ioctx->ch != ch);

	srpt_set_cmd_state(send_ioctx, SRPT_STATE_MGMT);

	srp_tsk = recv_ioctx->ioctx.buf;

	TRACE_DBG("recv_tsk_mgmt= %d for task_tag= %lld"
		  " using tag= %lld cm_id= %p sess= %p",
		  srp_tsk->tsk_mgmt_func, srp_tsk->task_tag, srp_tsk->tag,
		  ch->cm_id, ch->scst_sess);

	send_ioctx->tsk_mgmt.tag = srp_tsk->tag;

	switch (srp_tsk->tsk_mgmt_func) {
	case SRP_TSK_ABORT_TASK:
		TRACE_DBG("Processing SRP_TSK_ABORT_TASK");
		ret = scst_rx_mgmt_fn_tag(ch->scst_sess, SCST_ABORT_TASK,
					  srp_tsk->task_tag,
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_ABORT_TASK_SET:
		TRACE_DBG("Processing SRP_TSK_ABORT_TASK_SET");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess, SCST_ABORT_TASK_SET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_CLEAR_TASK_SET:
		TRACE_DBG("Processing SRP_TSK_CLEAR_TASK_SET");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess, SCST_CLEAR_TASK_SET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_LUN_RESET:
		TRACE_DBG("Processing SRP_TSK_LUN_RESET");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess, SCST_LUN_RESET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_CLEAR_ACA:
		TRACE_DBG("Processing SRP_TSK_CLEAR_ACA");
		ret = scst_rx_mgmt_fn_lun(ch->scst_sess, SCST_CLEAR_ACA,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	default:
		TRACE_DBG("Unsupported task management function.");
	}

	if (ret != 0) {
		PRINT_ERROR("Processing task management function %d failed: %d",
			    srp_tsk->tsk_mgmt_func, ret);
		srpt_put_send_ioctx(send_ioctx);
	}
}

static u8 scst_to_srp_tsk_mgmt_status(const int scst_mgmt_status)
{
	switch (scst_mgmt_status) {
	case SCST_MGMT_STATUS_SUCCESS:
		return SRP_TSK_MGMT_SUCCESS;
	case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
		return SRP_TSK_MGMT_FUNC_NOT_SUPP;
	case SCST_MGMT_STATUS_TASK_NOT_EXIST:
	case SCST_MGMT_STATUS_LUN_NOT_EXIST:
	case SCST_MGMT_STATUS_REJECTED:
	case SCST_MGMT_STATUS_FAILED:
	default:
		break;
	}
	return SRP_TSK_MGMT_FAILED;
}

/**
 * srpt_handle_new_iu() - Process a newly received information unit.
 * @ch:    RDMA channel through which the information unit has been received.
 * @ioctx: SRPT I/O context associated with the information unit.
 */
static void srpt_handle_new_iu(struct srpt_rdma_ch *ch,
			       struct srpt_recv_ioctx *recv_ioctx,
			       struct srpt_send_ioctx *send_ioctx,
			       enum scst_exec_context context)
{
	struct srp_cmd *srp_cmd;

	BUG_ON(!ch);
	BUG_ON(!recv_ioctx);

	ib_dma_sync_single_for_cpu(ch->sport->sdev->device,
				   recv_ioctx->ioctx.dma, srp_max_req_size,
				   DMA_FROM_DEVICE);

	srp_cmd = recv_ioctx->ioctx.buf;
	if (unlikely(ch->state == CH_CONNECTING)) {
		list_add_tail(&recv_ioctx->wait_list, &ch->cmd_wait_list);
		goto out;
	}

	if (srp_cmd->opcode == SRP_CMD || srp_cmd->opcode == SRP_TSK_MGMT) {
		if (!send_ioctx)
			send_ioctx = srpt_get_send_ioctx(ch);
		if (unlikely(!send_ioctx)) {
			list_add_tail(&recv_ioctx->wait_list,
				      &ch->cmd_wait_list);
			goto out;
		}
	}

	switch (srp_cmd->opcode) {
	case SRP_CMD:
		srpt_handle_cmd(ch, recv_ioctx, send_ioctx, context);
		break;
	case SRP_TSK_MGMT:
		srpt_handle_tsk_mgmt(ch, recv_ioctx, send_ioctx);
		break;
	case SRP_I_LOGOUT:
		PRINT_ERROR("Not yet implemented: SRP_I_LOGOUT");
		break;
	case SRP_CRED_RSP:
		TRACE_DBG("received SRP_CRED_RSP");
		break;
	case SRP_AER_RSP:
		TRACE_DBG("received SRP_AER_RSP");
		break;
	case SRP_RSP:
		PRINT_ERROR("Received SRP_RSP");
		break;
	default:
		PRINT_ERROR("received IU with unknown opcode 0x%x",
			    srp_cmd->opcode);
		break;
	}

	srpt_post_recv(ch->sport->sdev, recv_ioctx);
out:
	return;
}

static void srpt_process_rcv_completion(struct ib_cq *cq,
					struct srpt_rdma_ch *ch,
					struct ib_wc *wc)
{
	struct srpt_device *sdev = ch->sport->sdev;
	struct srpt_recv_ioctx *ioctx;
	u32 index;

	index = idx_from_wr_id(wc->wr_id);
	if (wc->status == IB_WC_SUCCESS) {
		int req_lim;

		req_lim = srpt_adjust_req_lim(ch, -1, 0);
		if (unlikely(req_lim < 0))
			PRINT_ERROR("req_lim = %d < 0", req_lim);
		ioctx = sdev->ioctx_ring[index];
		srpt_handle_new_iu(ch, ioctx, NULL, srpt_new_iu_context);
	} else {
		PRINT_INFO("receiving failed for idx %u with status %d",
			   index, wc->status);
	}
}

static void srpt_process_wait_list(struct srpt_rdma_ch *ch)
{
	struct srpt_recv_ioctx *recv_ioctx, *tmp;
	struct srpt_send_ioctx *send_ioctx;

	list_for_each_entry_safe(recv_ioctx, tmp, &ch->cmd_wait_list,
				 wait_list) {
		send_ioctx = srpt_get_send_ioctx(ch);
		if (!send_ioctx)
			break;
		list_del(&recv_ioctx->wait_list);
		srpt_handle_new_iu(ch, recv_ioctx, send_ioctx,
				   srpt_new_iu_context);
	}
}

/**
 * srpt_process_send_completion() - Process an IB send completion.
 *
 * Note: Although this has not yet been observed during tests, at least in
 * theory it is possible that the srpt_get_send_ioctx() call invoked by
 * srpt_handle_new_iu() fails. This is possible because the req_lim_delta
 * value in each response is set to at least one, and it is possible that this
 * response makes the initiator send a new request before the send completion
 * for that response has been processed. This could e.g. happen if the call to
 * srpt_put_send_iotcx() is delayed because of a higher priority interrupt or
 * if IB retransmission causes generation of the send completion to be
 * delayed. Incoming information units for which srpt_get_send_ioctx() fails
 * are queued on cmd_wait_list. The code below processes these delayed
 * requests one at a time.
 */
static void srpt_process_send_completion(struct ib_cq *cq,
					 struct srpt_rdma_ch *ch,
					 struct ib_wc *wc)
{
	uint32_t index;
	enum srpt_opcode opcode;

	index = idx_from_wr_id(wc->wr_id);
	opcode = opcode_from_wr_id(wc->wr_id);
	if (wc->status == IB_WC_SUCCESS) {
		if (opcode == SRPT_SEND) {
			srpt_handle_send_comp(ch, ch->ioctx_ring[index],
					      srpt_send_context);
		} else if (opcode == SRPT_RDMA_READ_LAST ||
			   opcode == SRPT_RDMA_ABORT) {
			srpt_handle_rdma_comp(ch, ch->ioctx_ring[index], opcode,
					      srpt_xmt_rsp_context);
		} else {
			WARN(true, "unexpected opcode %d", opcode);
		}
	} else {
		if (opcode == SRPT_SEND) {
			PRINT_INFO("sending response for idx %u failed with"
				   " status %d", index, wc->status);
			srpt_handle_send_err_comp(ch, wc->wr_id,
						  srpt_send_context);
		} else if (opcode == SRPT_RDMA_READ_LAST ||
			   opcode == SRPT_RDMA_WRITE_LAST) {
			PRINT_INFO("RDMA t %d for idx %u failed with status %d",
				   opcode, index, wc->status);
			srpt_handle_rdma_err_comp(ch, ch->ioctx_ring[index],
						  opcode, srpt_xmt_rsp_context);
		} else if (opcode != SRPT_RDMA_MID) {
			WARN(true, "unexpected opcode %d", opcode);
		}
	}

	if (unlikely(!list_empty(&ch->cmd_wait_list) &&
		     ch->state != CH_CONNECTING))
		srpt_process_wait_list(ch);
}

static void srpt_poll(struct srpt_rdma_ch *ch)
{
	struct ib_cq *const cq = ch->cq;
	struct ib_wc *const wc = ch->wc;
	int i, n;

	while ((n = ib_poll_cq(cq, ARRAY_SIZE(ch->wc), wc)) > 0) {
		for (i = 0; i < n; i++) {
			if (opcode_from_wr_id(wc[i].wr_id) == SRPT_RECV)
				srpt_process_rcv_completion(cq, ch, &wc[i]);
			else
				srpt_process_send_completion(cq, ch, &wc[i]);
		}
	}
}

static void srpt_process_completion(struct srpt_rdma_ch *ch)
{
	struct ib_cq *const cq = ch->cq;

	do {
		srpt_poll(ch);
	} while (ib_req_notify_cq(cq, IB_CQ_NEXT_COMP |
				      IB_CQ_REPORT_MISSED_EVENTS) > 0);
}

/**
 * srpt_completion() - IB completion queue callback function.
 */
static void srpt_completion(struct ib_cq *cq, void *ctx)
{
	struct srpt_rdma_ch *ch = ctx;

	BUG_ON(!ch->thread);
	wake_up_process(ch->thread);
}

static void srpt_free_ch(struct kref *kref)
{
	struct srpt_rdma_ch *ch = container_of(kref, struct srpt_rdma_ch, kref);

	/*
	 * The function call below will wait for the completion handler
	 * callback to finish and hence ensures that wake_up_process() won't
	 * be invoked anymore from that callback for the current thread.
	 */
	srpt_destroy_ch_ib(ch);

	kfree(ch);
}

static void srpt_unreg_sess(struct scst_session *scst_sess)
{
	struct srpt_rdma_ch *ch = scst_sess_get_tgt_priv(scst_sess);
	struct srpt_device *sdev = ch->sport->sdev;
	struct srpt_tgt *srpt_tgt = ch->srpt_tgt;

	kthread_stop(ch->thread);

	srpt_free_ioctx_ring((struct srpt_ioctx **)ch->ioctx_ring,
			     sdev, ch->rq_size,
			     ch->max_rsp_size, DMA_TO_DEVICE);

	/*
	 * Note: if a DREQ is received after ch->dreq_received has been read,
	 * ib_destroy_cm_id() will send a DREP.
	 *
	 */
	if (ch->dreq_received) {
		if (ib_send_cm_drep(ch->cm_id, NULL, 0) >= 0)
			PRINT_INFO("Received DREQ and sent DREP for session %s",
				   ch->sess_name);
		else
			PRINT_ERROR("Sending DREP failed");
	}

	/*
	 * If the connection is still established, ib_destroy_cm_id() will
	 * send a DREQ.
	 */
	ib_destroy_cm_id(ch->cm_id);

	/*
	 * Invoke wake_up() inside the lock to avoid that srpt_tgt disappears
	 * after list_del() and before wake_up() has been invoked.
	 */
	spin_lock_irq(&srpt_tgt->spinlock);
	list_del(&ch->list);
	wake_up(&srpt_tgt->ch_releaseQ);
	spin_unlock_irq(&srpt_tgt->spinlock);

	kref_put(&ch->kref, srpt_free_ch);
}

static int srpt_compl_thread(void *arg)
{
	struct srpt_rdma_ch *ch;

	/* Hibernation / freezing of the SRPT kernel thread is not supported. */
	current->flags |= PF_NOFREEZE;

	ch = arg;
	BUG_ON(!ch);

	set_current_state(TASK_INTERRUPTIBLE);
#if defined(__GNUC__)
#if (__GNUC__ * 100 + __GNUC_MINOR__) <= 406
	/* See also http://gcc.gnu.org/bugzilla/show_bug.cgi?id=52925. */
	barrier();
#endif
#endif
	while (!ch->last_wqe_received && ch->state <= CH_LIVE) {
		srpt_process_completion(ch);
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	set_current_state(TASK_RUNNING);

	/*
	 * Process all IB (error) completions before invoking
	 * scst_unregister_session().
	 */
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		srpt_process_completion(ch);
		if (atomic_read(&ch->scst_sess->sess_cmd_count) == 0)
			break;
		schedule_timeout(HZ / 10);
	}
	set_current_state(TASK_RUNNING);

	TRACE_DBG("ch %s: about to invoke scst_unregister_session()",
		  ch->sess_name);
	scst_unregister_session(ch->scst_sess, false, srpt_unreg_sess);

	while (!kthread_should_stop())
		schedule_timeout(DIV_ROUND_UP(HZ, 10));

	return 0;
}

/**
 * srpt_create_ch_ib() - Create receive and send completion queues.
 */
static int srpt_create_ch_ib(struct srpt_rdma_ch *ch)
{
	struct ib_qp_init_attr *qp_init;
	struct srpt_device *sdev = ch->sport->sdev;
	int ret;

	EXTRACHECKS_WARN_ON(ch->rq_size < 1);

	ret = -ENOMEM;
	qp_init = kzalloc(sizeof(*qp_init), GFP_KERNEL);
	if (!qp_init)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) \
    && !defined(RHEL_RELEASE_CODE)
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch,
			      ch->rq_size + srpt_sq_size);
#else
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch,
			      ch->rq_size + srpt_sq_size, 0);
#endif
	if (IS_ERR(ch->cq)) {
		ret = PTR_ERR(ch->cq);
		PRINT_ERROR("failed to create CQ cqe= %d ret= %d",
			    ch->rq_size + srpt_sq_size, ret);
		goto out;
	}

	qp_init->qp_context = (void *)ch;
	qp_init->event_handler
		= (void(*)(struct ib_event *, void*))srpt_qp_event;
	qp_init->send_cq = ch->cq;
	qp_init->recv_cq = ch->cq;
	qp_init->srq = sdev->srq;
	qp_init->sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_init->qp_type = IB_QPT_RC;
	qp_init->cap.max_send_wr = srpt_sq_size;
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
	ch->max_sge = sdev->dev_attr.max_sge - 3;
	WARN_ON(ch->max_sge < 1);
	qp_init->cap.max_send_sge = ch->max_sge;

	ch->qp = ib_create_qp(sdev->pd, qp_init);
	if (IS_ERR(ch->qp)) {
		ret = PTR_ERR(ch->qp);
		PRINT_ERROR("failed to create_qp ret= %d", ret);
		goto err_destroy_cq;
	}

	TRACE_DBG("qp_num = %#x", ch->qp->qp_num);

	ch->sq_wr_avail = qp_init->cap.max_send_wr;

	TRACE_DBG("%s: max_cqe= %d max_sge= %d sq_size = %d"
		  " cm_id= %p", __func__, ch->cq->cqe,
		  qp_init->cap.max_send_sge, qp_init->cap.max_send_wr,
		  ch->cm_id);

	ret = srpt_init_ch_qp(ch, ch->qp);
	if (ret) {
		PRINT_ERROR("srpt_init_ch_qp(%#x) failed (%d)", ch->qp->qp_num,
			    ret);
		goto err_destroy_qp;
	}

out:
	kfree(qp_init);
	return ret;

err_destroy_qp:
	ib_destroy_qp(ch->qp);
err_destroy_cq:
	ib_destroy_cq(ch->cq);
	goto out;
}

static void srpt_destroy_ch_ib(struct srpt_rdma_ch *ch)
{
	TRACE_ENTRY();

	while (ib_poll_cq(ch->cq, ARRAY_SIZE(ch->wc), ch->wc) > 0)
		;

	ib_destroy_qp(ch->qp);
	ib_destroy_cq(ch->cq);

	TRACE_EXIT();
}

/**
 * __srpt_close_ch() - Close an RDMA channel.
 *
 * Make sure all resources associated with the channel will be deallocated at
 * an appropriate time.
 *
 * Returns true if and only if the channel state has been modified from
 * CH_CONNECTING or CH_LIVE into CH_DISCONNECTING.
 */
static bool __srpt_close_ch(struct srpt_rdma_ch *ch)
	__releases(&ch->srpt_tgt->spinlock)
	__acquires(&ch->srpt_tgt->spinlock)
{
	struct srpt_tgt *srpt_tgt = ch->srpt_tgt;
	enum rdma_ch_state prev_state;
	int ret;
	bool was_live;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&srpt_tgt->spinlock);
#endif

	was_live = false;

	prev_state = srpt_set_ch_state_to_disc(ch);

	switch (prev_state) {
	case CH_CONNECTING:
	case CH_LIVE:
		was_live = true;
		break;
	case CH_DISCONNECTING:
	case CH_DRAINING:
		break;
	}

	if (was_live) {
		kref_get(&ch->kref);
		spin_unlock_irq(&srpt_tgt->spinlock);

		ret = srpt_ch_qp_err(ch);
		if (ret < 0)
			PRINT_ERROR("Setting queue pair in error state"
			       " failed: %d", ret);
		kref_put(&ch->kref, srpt_free_ch);

		spin_lock_irq(&srpt_tgt->spinlock);
	}

	return was_live;
}

/**
 * srpt_close_ch() - Close an RDMA channel.
 */
static void srpt_close_ch(struct srpt_rdma_ch *ch)
{
	struct srpt_tgt *srpt_tgt = ch->srpt_tgt;

	spin_lock_irq(&srpt_tgt->spinlock);
	__srpt_close_ch(ch);
	spin_unlock_irq(&srpt_tgt->spinlock);
}

/**
 * srpt_drain_channel() - Drain a channel by resetting the IB queue pair.
 * @cm_id: Pointer to the CM ID of the channel to be drained.
 *
 * Note: Must be called from inside srpt_cm_handler to avoid a race between
 * accessing sdev->spinlock and the call to kfree(sdev) in srpt_remove_one()
 * (the caller of srpt_cm_handler holds the cm_id spinlock; srpt_remove_one()
 * waits until all target sessions for the associated IB device have been
 * unregistered and target session registration involves a call to
 * ib_destroy_cm_id(), which locks the cm_id spinlock and hence waits until
 * this function has finished).
 */
static void srpt_drain_channel(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch;
	int ret;

	WARN_ON_ONCE(irqs_disabled());

	ch = cm_id->context;
	if (srpt_set_ch_state_to_draining(ch)) {
		ret = srpt_ch_qp_err(ch);
		if (ret < 0)
			PRINT_ERROR("Setting queue pair in error state"
			       " failed: %d", ret);
	}
}

static void __srpt_close_all_ch(struct srpt_tgt *srpt_tgt)
{
	struct srpt_rdma_ch *ch, *next_ch;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&srpt_tgt->spinlock);
#endif

	list_for_each_entry_safe(ch, next_ch, &srpt_tgt->rch_list, list) {
		PRINT_INFO("Closing channel %s because target %s has been"
			   " disabled", ch->sess_name,
			   srpt_tgt->scst_tgt->tgt_name);
		__srpt_close_ch(ch);
	}
}

static struct srpt_tgt *srpt_convert_scst_tgt(struct scst_tgt *scst_tgt)
{
	struct srpt_device *sdev;
	struct srpt_port *sport;
	struct srpt_tgt *srpt_tgt;

	if (one_target_per_port) {
		sport = scst_tgt_get_tgt_priv(scst_tgt);
		srpt_tgt = sport ? &sport->srpt_tgt : NULL;
	} else {
		sdev = scst_tgt_get_tgt_priv(scst_tgt);
		srpt_tgt = sdev ? &sdev->srpt_tgt : NULL;
	}
	return srpt_tgt;
}

#if !defined(CONFIG_SCST_PROC)
/**
 * srpt_enable_target - Set the "enabled" status of a target.
 */
static int srpt_enable_target(struct scst_tgt *scst_tgt, bool enable)
{
	struct srpt_tgt *srpt_tgt = srpt_convert_scst_tgt(scst_tgt);
	int res = -E_TGT_PRIV_NOT_YET_SET;

	EXTRACHECKS_WARN_ON_ONCE(irqs_disabled());

	if (!srpt_tgt)
		goto out;

	TRACE_DBG("%s target %s", enable ? "Enabling" : "Disabling",
		  scst_tgt->tgt_name);

	spin_lock_irq(&srpt_tgt->spinlock);
	srpt_tgt->enabled = enable;
	if (!enable)
		__srpt_close_all_ch(srpt_tgt);
	spin_unlock_irq(&srpt_tgt->spinlock);

	res = 0;

out:
	return res;
}

/**
 * srpt_is_target_enabled - Report whether a target is enabled.
 */
static bool srpt_is_target_enabled(struct scst_tgt *scst_tgt)
{
	struct srpt_tgt *srpt_tgt = srpt_convert_scst_tgt(scst_tgt);

	return srpt_tgt && srpt_tgt->enabled;
}
#endif

/**
 * srpt_cm_req_recv() - Process the event IB_CM_REQ_RECEIVED.
 *
 * Ownership of the cm_id is transferred to the SCST session if this function
 * returns zero. Otherwise the caller remains the owner of cm_id.
 */
static int srpt_cm_req_recv(struct ib_cm_id *cm_id,
			    struct ib_cm_req_event_param *param,
			    void *private_data)
{
	struct srpt_device *const sdev = cm_id->context;
	struct srpt_port *const sport = &sdev->port[param->port - 1];
	struct srpt_tgt *const srpt_tgt = one_target_per_port ?
					  &sport->srpt_tgt : &sdev->srpt_tgt;
	struct srp_login_req *req;
	struct srp_login_rsp *rsp;
	struct srp_login_rej *rej;
	struct ib_cm_rep_param *rep_param;
	struct srpt_rdma_ch *ch = NULL;
	struct task_struct *thread;
	u32 it_iu_len;
	int i;
	int ret;

	EXTRACHECKS_WARN_ON_ONCE(irqs_disabled());

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

	PRINT_INFO("Received SRP_LOGIN_REQ with i_port_id"
		   " %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x,"
		   " t_port_id %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x and"
		   " it_iu_len %d on port %d"
		   " (guid=%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x)",
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[0]),
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[2]),
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[4]),
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[6]),
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[8]),
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[10]),
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[12]),
	    be16_to_cpu(*(__be16 *)&req->initiator_port_id[14]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[0]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[2]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[4]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[6]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[8]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[10]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[12]),
	    be16_to_cpu(*(__be16 *)&req->target_port_id[14]),
	    it_iu_len,
	    param->port,
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[0]),
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[2]),
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[4]),
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[6]),
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[8]),
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[10]),
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[12]),
	    be16_to_cpu(*(__be16 *)&sdev->port[param->port - 1].gid.raw[14]));

	ret = -ENOMEM;
	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	rej = kzalloc(sizeof(*rej), GFP_KERNEL);
	rep_param = kzalloc(sizeof(*rep_param), GFP_KERNEL);
	if (!rsp || !rej || !rep_param)
		goto out;

	ret = -EINVAL;
	if (it_iu_len > srp_max_req_size || it_iu_len < 64) {
		rej->reason = cpu_to_be32(
				SRP_LOGIN_REJ_REQ_IT_IU_LENGTH_TOO_LARGE);
		PRINT_ERROR("rejected SRP_LOGIN_REQ because its"
			    " length (%d bytes) is out of range (%d .. %d)",
			    it_iu_len, 64, srp_max_req_size);
		goto reject;
	}

	if (!srpt_tgt->enabled) {
		rej->reason = cpu_to_be32(
				SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_INFO("rejected SRP_LOGIN_REQ because target %s is not"
			   " enabled", srpt_tgt->scst_tgt->tgt_name);
		goto reject;
	}

	if (*(__be64 *)req->target_port_id != cpu_to_be64(srpt_service_guid)
	    || *(__be64 *)(req->target_port_id + 8) !=
	       cpu_to_be64(srpt_service_guid)) {
		rej->reason = cpu_to_be32(
				SRP_LOGIN_REJ_UNABLE_ASSOCIATE_CHANNEL);
		PRINT_ERROR("rejected SRP_LOGIN_REQ because it"
		       " has an invalid target port identifier.");
		goto reject;
	}

	ret = -ENOMEM;
	ch = kzalloc(sizeof(*ch), GFP_KERNEL);
	if (!ch) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_ERROR("rejected SRP_LOGIN_REQ because out of memory.");
		goto reject;
	}

	kref_init(&ch->kref);
	ret = ib_find_pkey(sdev->device, sport->port,
			   be16_to_cpu(param->primary_path->pkey),
			   &ch->pkey_index);
	if (ret < 0) {
		ch->pkey_index = 0;
		PRINT_ERROR("Translating pkey %#x failed (%d) - using index 0",
			    be16_to_cpu(param->primary_path->pkey), ret);
	}
	memcpy(ch->i_port_id, req->initiator_port_id, 16);
	memcpy(ch->t_port_id, req->target_port_id, 16);
	ch->sport = sport;
	ch->srpt_tgt = srpt_tgt;
	ch->cm_id = cm_id;
	cm_id->context = ch;
	/*
	 * Avoid QUEUE_FULL conditions by limiting the number of buffers used
	 * for the SRP protocol to the SCST SCSI command queue size.
	 */
	ch->rq_size = min(SRPT_RQ_SIZE, scst_get_max_lun_commands(NULL, 0));
	spin_lock_init(&ch->spinlock);
	ch->state = CH_CONNECTING;
	INIT_LIST_HEAD(&ch->cmd_wait_list);
	ch->max_rsp_size = max_t(uint32_t, srp_max_rsp_size, MIN_MAX_RSP_SIZE);
	ch->ioctx_ring = (struct srpt_send_ioctx **)
		srpt_alloc_ioctx_ring(ch->sport->sdev, ch->rq_size,
				      sizeof(*ch->ioctx_ring[0]),
				      ch->max_rsp_size, DMA_TO_DEVICE);
	if (!ch->ioctx_ring) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		goto free_ch;
	}

	INIT_LIST_HEAD(&ch->free_list);
	for (i = 0; i < ch->rq_size; i++) {
		ch->ioctx_ring[i]->ch = ch;
		list_add_tail(&ch->ioctx_ring[i]->free_list, &ch->free_list);
	}

	ret = srpt_create_ch_ib(ch);
	if (ret) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_ERROR("rejected SRP_LOGIN_REQ because creating"
			    " a new RDMA channel failed.");
		goto free_ring;
	}

	if (one_target_per_port) {
		__be16 *const raw_gid = (__be16 *)param->primary_path->dgid.raw;

		snprintf(ch->sess_name, sizeof(ch->sess_name),
			 "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			 be16_to_cpu(raw_gid[0]),
			 be16_to_cpu(raw_gid[1]),
			 be16_to_cpu(raw_gid[2]),
			 be16_to_cpu(raw_gid[3]),
			 be16_to_cpu(raw_gid[4]),
			 be16_to_cpu(raw_gid[5]),
			 be16_to_cpu(raw_gid[6]),
			 be16_to_cpu(raw_gid[7]));
	} else if (use_port_guid_in_session_name) {
		/*
		 * If the kernel module parameter use_port_guid_in_session_name
		 * has been specified, use a combination of the target port
		 * GUID and the initiator port ID as the session name. This
		 * was the original behavior of the SRP target implementation
		 * (i.e. before the SRPT was included in OFED 1.3).
		 */
		snprintf(ch->sess_name, sizeof(ch->sess_name),
			 "0x%016llx%016llx",
			 be64_to_cpu(*(__be64 *)
				&sdev->port[param->port - 1].gid.raw[8]),
			 be64_to_cpu(*(__be64 *)(ch->i_port_id + 8)));
	} else {
		/*
		 * Default behavior: use the initiator port identifier as the
		 * session name.
		 */
		snprintf(ch->sess_name, sizeof(ch->sess_name),
			 "0x%016llx%016llx",
			 be64_to_cpu(*(__be64 *)ch->i_port_id),
			 be64_to_cpu(*(__be64 *)(ch->i_port_id + 8)));
	}

	TRACE_DBG("registering session %s", ch->sess_name);

	BUG_ON(!srpt_tgt->scst_tgt);
	ret = -ENOMEM;
	ch->scst_sess = scst_register_session(srpt_tgt->scst_tgt, 0, ch->sess_name,
					      ch, NULL, NULL);
	if (!ch->scst_sess) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		TRACE_DBG("Failed to create SCST session");
		goto destroy_ib;
	}

	thread = kthread_run(srpt_compl_thread, ch, "srpt_%s-%d",
			     ch->sport->sdev->device->name, ch->sport->port);
	if (IS_ERR(thread)) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		ret = PTR_ERR(thread);
		PRINT_ERROR("failed to create kernel thread: %d", ret);
		goto unreg_ch;
	}

	spin_lock_irq(&srpt_tgt->spinlock);

	if ((req->req_flags & SRP_MTCH_ACTION) == SRP_MULTICHAN_SINGLE) {
		struct srpt_rdma_ch *ch2;

		rsp->rsp_flags = SRP_LOGIN_RSP_MULTICHAN_NO_CHAN;
restart:
		list_for_each_entry(ch2, &srpt_tgt->rch_list, list) {
			if (!memcmp(ch2->i_port_id, req->initiator_port_id, 16)
			    && param->port == ch2->sport->port
			    && param->listen_id == ch2->sport->sdev->cm_id) {
				if (!__srpt_close_ch(ch2))
					continue;

				PRINT_INFO("Relogin - closed existing channel"
					   " %s; cm_id = %p", ch2->sess_name,
					   ch2->cm_id);

				rsp->rsp_flags =
					SRP_LOGIN_RSP_MULTICHAN_TERMINATED;

				goto restart;
			}
		}
	} else {
		rsp->rsp_flags = SRP_LOGIN_RSP_MULTICHAN_MAINTAINED;
	}

	list_add_tail(&ch->list, &srpt_tgt->rch_list);
	ch->thread = thread;

	if (!srpt_tgt->enabled) {
		rej->reason = cpu_to_be32(
				SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_INFO("rejected SRP_LOGIN_REQ because the target %s (%s)"
			   " is not enabled",
			   srpt_tgt->scst_tgt->tgt_name, sdev->device->name);
		spin_unlock_irq(&srpt_tgt->spinlock);
		goto reject;
	}

	spin_unlock_irq(&srpt_tgt->spinlock);

	ret = srpt_ch_qp_rtr(ch, ch->qp);
	if (ret) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_ERROR("rejected SRP_LOGIN_REQ because enabling"
		       " RTR failed (error code = %d)", ret);
		goto reject;
	}

	TRACE_DBG("Establish connection sess=%p name=%s cm_id=%p",
		  ch->scst_sess, ch->sess_name, ch->cm_id);

	/* create srp_login_response */
	rsp->opcode = SRP_LOGIN_RSP;
	rsp->tag = req->tag;
	rsp->max_it_iu_len = req->req_it_iu_len;
	rsp->max_ti_iu_len = req->req_it_iu_len;
	ch->max_ti_iu_len = it_iu_len;
	rsp->buf_fmt = cpu_to_be16(SRP_BUF_FORMAT_DIRECT |
				   SRP_BUF_FORMAT_INDIRECT);
	rsp->req_lim_delta = cpu_to_be32(ch->rq_size);
	ch->req_lim = ch->rq_size;
	ch->req_lim_delta = 0;

	/* create cm reply */
	rep_param->qp_num = ch->qp->qp_num;
	rep_param->private_data = (void *)rsp;
	rep_param->private_data_len = sizeof(*rsp);
	rep_param->rnr_retry_count = 7;
	rep_param->flow_control = 1;
	rep_param->failover_accepted = 0;
	rep_param->srq = 1;
	rep_param->responder_resources = 4;
	rep_param->initiator_depth = 4;

	spin_lock_irq(&srpt_tgt->spinlock);
	if (ch->state == CH_CONNECTING)
		ret = ib_send_cm_rep(cm_id, rep_param);
	else
		ret = -ECONNABORTED;
	spin_unlock_irq(&srpt_tgt->spinlock);

	switch (ret) {
	case 0:
		break;
	case -ECONNABORTED:
		goto reject;
	default:
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_ERROR("sending SRP_LOGIN_REQ response failed"
			    " (error code = %d)", ret);
		goto reject;
	}

	goto out;

unreg_ch:
	scst_unregister_session(ch->scst_sess, true, NULL);

destroy_ib:
	srpt_destroy_ch_ib(ch);

free_ring:
	srpt_free_ioctx_ring((struct srpt_ioctx **)ch->ioctx_ring,
			     ch->sport->sdev, ch->rq_size,
			     ch->max_rsp_size, DMA_TO_DEVICE);

free_ch:
	cm_id->context = NULL;
	kfree(ch);
	ch = NULL;

	BUG_ON(ret == 0);

reject:
	PRINT_INFO("Rejecting login with reason %#x", be32_to_cpu(rej->reason));
	rej->opcode = SRP_LOGIN_REJ;
	rej->tag = req->tag;
	rej->buf_fmt = cpu_to_be16(SRP_BUF_FORMAT_DIRECT |
				   SRP_BUF_FORMAT_INDIRECT);
	ib_send_cm_rej(cm_id, IB_CM_REJ_CONSUMER_DEFINED, NULL, 0, rej,
		       sizeof(*rej));

	if (ch && ch->thread) {
		srpt_close_ch(ch);
		/*
		 * Tell the caller not to free cm_id since
		 * srpt_compl_thread() will do that.
		 */
		ret = 0;
	}

out:
	kfree(rep_param);
	kfree(rsp);
	kfree(rej);

	return ret;
}

static void srpt_cm_rej_recv(struct ib_cm_id *cm_id)
{
	PRINT_INFO("Received InfiniBand REJ packet for cm_id %p.", cm_id);
	srpt_drain_channel(cm_id);
}

/**
 * srpt_cm_rtu_recv() - Process IB CM RTU_RECEIVED and USER_ESTABLISHED events.
 *
 * An IB_CM_RTU_RECEIVED message indicates that the connection is established
 * and that the recipient may begin transmitting (RTU = ready to use).
 */
static void srpt_cm_rtu_recv(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch = cm_id->context;
	int ret;

	ret = srpt_ch_qp_rts(ch, ch->qp);
	if (ret == 0 && srpt_test_and_set_ch_state(ch, CH_CONNECTING,
						   CH_LIVE)) {
		wake_up_process(ch->thread);
	} else {
		srpt_close_ch(ch);
	}
}

static void srpt_cm_timewait_exit(struct ib_cm_id *cm_id)
{
	PRINT_INFO("Received InfiniBand TimeWait exit for cm_id %p.", cm_id);
	srpt_drain_channel(cm_id);
}

static void srpt_cm_rep_error(struct ib_cm_id *cm_id)
{
	PRINT_INFO("Received InfiniBand REP error for cm_id %p.", cm_id);
	srpt_drain_channel(cm_id);
}

/**
 * srpt_cm_dreq_recv() - Process reception of a DREQ message.
 */
static void srpt_cm_dreq_recv(struct ib_cm_id *cm_id)
{
	struct srpt_rdma_ch *ch = cm_id->context;

	ch->dreq_received = true;
	srpt_set_ch_state_to_disc(ch);
}

/**
 * srpt_cm_drep_recv() - Process reception of a DREP message.
 */
static void srpt_cm_drep_recv(struct ib_cm_id *cm_id)
{
	PRINT_INFO("Received InfiniBand DREP message for cm_id %p.", cm_id);
	srpt_drain_channel(cm_id);
}

/**
 * srpt_cm_handler() - IB connection manager callback function.
 *
 * A non-zero return value will cause the caller destroy the CM ID.
 *
 * Note: srpt_cm_handler() must only return a non-zero value when transferring
 * ownership of the cm_id to a channel if srpt_cm_req_recv() failed. Returning
 * a non-zero value in any other case will trigger a race with the
 * ib_destroy_cm_id() call in srpt_compl_thread().
 */
static int srpt_cm_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	int ret;

	BUG_ON(!cm_id->context);

	ret = 0;
	switch (event->event) {
	case IB_CM_REQ_RECEIVED:
		ret = srpt_cm_req_recv(cm_id, &event->param.req_rcvd,
				       event->private_data);
		break;
	case IB_CM_REJ_RECEIVED:
		srpt_cm_rej_recv(cm_id);
		break;
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		srpt_cm_rtu_recv(cm_id);
		break;
	case IB_CM_DREQ_RECEIVED:
		srpt_cm_dreq_recv(cm_id);
		break;
	case IB_CM_DREP_RECEIVED:
		srpt_cm_drep_recv(cm_id);
		break;
	case IB_CM_TIMEWAIT_EXIT:
		srpt_cm_timewait_exit(cm_id);
		break;
	case IB_CM_REP_ERROR:
		srpt_cm_rep_error(cm_id);
		break;
	case IB_CM_DREQ_ERROR:
		PRINT_INFO("Received IB DREQ ERROR event.");
		break;
	case IB_CM_MRA_RECEIVED:
		PRINT_INFO("Received IB MRA event");
		break;
	default:
		PRINT_ERROR("received unrecognized IB CM event %d",
			    event->event);
		break;
	}

	return ret;
}

/**
 * srpt_map_sg_to_ib_sge() - Map an SG list to an IB SGE list.
 */
static int srpt_map_sg_to_ib_sge(struct srpt_rdma_ch *ch,
				 struct srpt_send_ioctx *ioctx,
				 struct scst_cmd *scmnd)
{
	struct ib_device *dev;
	struct scatterlist *sg, *cur_sg;
	int sg_cnt;
	scst_data_direction dir;
	struct rdma_iu *riu;
	struct srp_direct_buf *db;
	dma_addr_t dma_addr;
	struct ib_sge *sge_array, *sge;
	u64 raddr;
	u32 rsize;
	u32 tsize;
	u32 dma_len;
	int count;
	int i, j, k;
	int max_sge, nsge;

	BUG_ON(!ch);
	BUG_ON(!ioctx);
	BUG_ON(!scmnd);
	dev = ch->sport->sdev->device;
	max_sge = ch->max_sge;
	dir = scst_cmd_get_data_direction(scmnd);
	BUG_ON(dir == SCST_DATA_NONE);
	/*
	 * Cache 'dir' because it is needed in srpt_unmap_sg_to_ib_sge()
	 * and because scst_set_cmd_error_status() resets scmnd->data_direction.
	 */
	ioctx->dir = dir;
	if (dir == SCST_DATA_WRITE) {
		scst_cmd_get_write_fields(scmnd, &sg, &sg_cnt);
		WARN_ON(!sg);
	} else {
		sg = scst_cmd_get_sg(scmnd);
		sg_cnt = scst_cmd_get_sg_cnt(scmnd);
		WARN_ON(!sg);
	}
	ioctx->sg = sg;
	ioctx->sg_cnt = sg_cnt;
	count = ib_dma_map_sg(ch->sport->sdev->device, sg, sg_cnt,
			      scst_to_tgt_dma_dir(dir));
	if (unlikely(!count))
		return -EBUSY;

	ioctx->mapped_sg_count = count;

	{
		int size, nrdma;

		nrdma = (count + max_sge - 1) / max_sge + ioctx->n_rbuf;
		nsge = count + ioctx->n_rbuf;
		size = nrdma * sizeof(*riu) + nsge * sizeof(*sge);
		ioctx->rdma_ius = size <= sizeof(ioctx->rdma_ius_buf) ?
			ioctx->rdma_ius_buf : kmalloc(size,
			scst_cmd_atomic(scmnd) ? GFP_ATOMIC : GFP_KERNEL);
		if (!ioctx->rdma_ius)
			goto free_mem;

		ioctx->n_rdma_ius = nrdma;
		sge_array = (struct ib_sge *)(ioctx->rdma_ius + nrdma);
	}

	db = ioctx->rbufs;
	tsize = (dir == SCST_DATA_READ)
		? scst_cmd_get_adjusted_resp_data_len(scmnd)
		: scst_cmd_get_bufflen(scmnd);
	dma_len = ib_sg_dma_len(dev, &sg[0]);
	riu = ioctx->rdma_ius;
	sge = sge_array;

	/*
	 * For each remote desc - calculate the #ib_sge.
	 * If #ib_sge < SRPT_DEF_SG_PER_WQE per rdma operation then
	 *      each remote desc rdma_iu is required a rdma wr;
	 * else
	 *      we need to allocate extra rdma_iu to carry extra #ib_sge in
	 *      another rdma wr
	 */
	for (i = 0, j = 0, cur_sg = sg;
	     j < count && i < ioctx->n_rbuf && tsize > 0; ++i, ++riu, ++db) {
		rsize = be32_to_cpu(db->len);
		raddr = be64_to_cpu(db->va);
		riu->raddr = raddr;
		riu->rkey = be32_to_cpu(db->key);
		riu->sge_cnt = 0;
		riu->sge = sge;

		/* calculate how many sge required for this remote_buf */
		while (rsize > 0 && tsize > 0) {

			if (rsize >= dma_len) {
				tsize -= dma_len;
				rsize -= dma_len;
				raddr += dma_len;

				if (tsize > 0) {
					++j;
					if (j < count) {
						cur_sg = __sg_next_inline(cur_sg);
						dma_len = ib_sg_dma_len(dev, cur_sg);
					}
				}
			} else {
				tsize -= rsize;
				dma_len -= rsize;
				rsize = 0;
			}

			++riu->sge_cnt;
			++sge;

			if (rsize > 0 && riu->sge_cnt == max_sge) {
				++riu;
				riu->raddr = raddr;
				riu->rkey = be32_to_cpu(db->key);
				riu->sge_cnt = 0;
				riu->sge = sge;
			}
		}
	}

	ioctx->n_rdma = riu - ioctx->rdma_ius;
	EXTRACHECKS_WARN_ON(ioctx->n_rdma > ioctx->n_rdma_ius);
	EXTRACHECKS_WARN_ON(sge - sge_array > nsge);

	db = ioctx->rbufs;
	tsize = (dir == SCST_DATA_READ)
		? scst_cmd_get_adjusted_resp_data_len(scmnd)
		: scst_cmd_get_bufflen(scmnd);
	riu = ioctx->rdma_ius;
	dma_len = ib_sg_dma_len(dev, &sg[0]);
	dma_addr = ib_sg_dma_address(dev, &sg[0]);

	/* this second loop is really mapped sg_addres to rdma_iu->ib_sge */
	for (i = 0, j = 0, cur_sg = sg;
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
						cur_sg = __sg_next_inline(cur_sg);
						dma_len = ib_sg_dma_len(dev, cur_sg);
						dma_addr =
						    ib_sg_dma_address(dev, cur_sg);
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
			if (k == riu->sge_cnt && rsize > 0 && tsize > 0) {
				++riu;
				sge = riu->sge;
				k = 0;
			} else if (rsize > 0 && tsize > 0)
				++sge;
		}
	}

	EXTRACHECKS_WARN_ON(riu - ioctx->rdma_ius != ioctx->n_rdma);

	return 0;

free_mem:
	srpt_unmap_sg_to_ib_sge(ch, ioctx);

	return -ENOMEM;
}

/**
 * srpt_unmap_sg_to_ib_sge() - Unmap an IB SGE list.
 */
static void srpt_unmap_sg_to_ib_sge(struct srpt_rdma_ch *ch,
				    struct srpt_send_ioctx *ioctx)
{
	struct scatterlist *sg;
	scst_data_direction dir;

	EXTRACHECKS_BUG_ON(!ch);
	EXTRACHECKS_BUG_ON(!ioctx);
	EXTRACHECKS_BUG_ON(ioctx->n_rdma && !ioctx->rdma_ius);

	if (ioctx->rdma_ius != (void *)ioctx->rdma_ius_buf)
		kfree(ioctx->rdma_ius);
	ioctx->rdma_ius = NULL;
	ioctx->n_rdma = 0;

	if (ioctx->mapped_sg_count) {
		EXTRACHECKS_WARN_ON(ioctx
				    != scst_cmd_get_tgt_priv(&ioctx->scmnd));
		sg = ioctx->sg;
		EXTRACHECKS_WARN_ON(!sg);
		dir = ioctx->dir;
		EXTRACHECKS_BUG_ON(dir == SCST_DATA_NONE);
		ib_dma_unmap_sg(ch->sport->sdev->device, sg, ioctx->sg_cnt,
				scst_to_tgt_dma_dir(dir));
		ioctx->mapped_sg_count = 0;
	}
}

/**
 * srpt_perform_rdmas() - Perform IB RDMA.
 *
 * Returns zero upon success or a negative number upon failure.
 */
static int srpt_perform_rdmas(struct srpt_rdma_ch *ch,
			      struct srpt_send_ioctx *ioctx,
			      scst_data_direction dir)
{
	struct ib_send_wr wr;
	struct ib_send_wr *bad_wr;
	struct rdma_iu *riu;
	int i;
	int ret;
	int sq_wr_avail;
	const int n_rdma = ioctx->n_rdma;

	if (dir == SCST_DATA_WRITE) {
		ret = -ENOMEM;
		sq_wr_avail = srpt_adjust_srq_wr_avail(ch, -n_rdma);
		if (sq_wr_avail < 0) {
			PRINT_WARNING("IB send queue full (needed %d)",
				      n_rdma);
			goto out;
		}
	}

	ioctx->rdma_aborted = false;
	ret = 0;
	riu = ioctx->rdma_ius;
	memset(&wr, 0, sizeof(wr));

	for (i = 0; i < n_rdma; ++i, ++riu) {
		if (dir == SCST_DATA_READ) {
			wr.opcode = IB_WR_RDMA_WRITE;
			wr.wr_id = encode_wr_id(i == n_rdma - 1 ?
						SRPT_RDMA_WRITE_LAST :
						SRPT_RDMA_MID,
						ioctx->ioctx.index);
		} else {
			wr.opcode = IB_WR_RDMA_READ;
			wr.wr_id = encode_wr_id(i == n_rdma - 1 ?
						SRPT_RDMA_READ_LAST :
						SRPT_RDMA_MID,
						ioctx->ioctx.index);
		}
		wr.next = NULL;
		wr.wr.rdma.remote_addr = riu->raddr;
		wr.wr.rdma.rkey = riu->rkey;
		wr.num_sge = riu->sge_cnt;
		wr.sg_list = riu->sge;

		/* only get completion event for the last rdma wr */
		if (i == (n_rdma - 1) && dir == SCST_DATA_WRITE)
			wr.send_flags = IB_SEND_SIGNALED;

		ret = ib_post_send(ch->qp, &wr, &bad_wr);
		if (ret)
			break;
	}

	if (ret)
		PRINT_ERROR("%s[%d]: ib_post_send() returned %d for %d/%d",
			    __func__, __LINE__, ret, i, n_rdma);
	if (ret && i > 0) {
		wr.num_sge = 0;
		wr.wr_id = encode_wr_id(SRPT_RDMA_ABORT, ioctx->ioctx.index);
		wr.send_flags = IB_SEND_SIGNALED;
		while (ch->state == CH_LIVE &&
		       ib_post_send(ch->qp, &wr, &bad_wr) != 0) {
			PRINT_INFO("Trying to abort failed RDMA transfer [%d]",
				   ioctx->ioctx.index);
			msleep(1000);
		}
		while (ch->state != CH_DRAINING && !ioctx->rdma_aborted) {
			PRINT_INFO("Waiting until RDMA abort finished [%d]",
				   ioctx->ioctx.index);
			msleep(1000);
		}
		PRINT_INFO("%s[%d]: done", __func__, __LINE__);
	}

out:
	if (unlikely(dir == SCST_DATA_WRITE && ret < 0))
		srpt_adjust_srq_wr_avail(ch, n_rdma);
	return ret;
}

/**
 * srpt_xfer_data() - Start data transfer from initiator to target.
 *
 * Returns an SCST_TGT_RES_... status code.
 *
 * Note: Must not block.
 */
static int srpt_xfer_data(struct srpt_rdma_ch *ch,
			  struct srpt_send_ioctx *ioctx,
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
		if (ret == -EAGAIN || ret == -ENOMEM) {
			PRINT_INFO("%s[%d] queue full -- ret=%d",
				   __func__, __LINE__, ret);
			ret = SCST_TGT_RES_QUEUE_FULL;
		} else {
			PRINT_ERROR("%s[%d] fatal error -- ret=%d",
				    __func__, __LINE__, ret);
			ret = SCST_TGT_RES_FATAL_ERROR;
		}
		goto out_unmap;
	}

	ret = SCST_TGT_RES_SUCCESS;

out:
	return ret;
out_unmap:
	srpt_unmap_sg_to_ib_sge(ch, ioctx);
	goto out;
}

/**
 * srpt_pending_cmd_timeout() - SCST command HCA processing timeout callback.
 *
 * Called by the SCST core if no IB completion notification has been received
 * within RDMA_COMPL_TIMEOUT_S seconds.
 */
static void srpt_pending_cmd_timeout(struct scst_cmd *scmnd)
{
	struct srpt_send_ioctx *ioctx;
	enum srpt_command_state state;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);

	state = ioctx->state;
	switch (state) {
	case SRPT_STATE_NEW:
	case SRPT_STATE_DATA_IN:
	case SRPT_STATE_DONE:
		/*
		 * srpt_pending_cmd_timeout() should never be invoked for
		 * commands in this state.
		 */
		PRINT_ERROR("Processing SCST command %p (SRPT state %d) took"
			    " too long -- aborting", scmnd, state);
		break;
	case SRPT_STATE_NEED_DATA:
	case SRPT_STATE_CMD_RSP_SENT:
	case SRPT_STATE_MGMT_RSP_SENT:
	default:
		PRINT_ERROR("Command %p: IB completion for idx %u has not"
			    " been received in time (SRPT command state %d)",
			    scmnd, ioctx->ioctx.index, state);
		break;
	}

	srpt_abort_cmd(ioctx, SCST_CONTEXT_SAME);
}

/**
 * srpt_rdy_to_xfer() - Transfers data from initiator to target.
 *
 * Called by the SCST core to transfer data from the initiator to the target
 * (SCST_DATA_WRITE). Must not block.
 */
static int srpt_rdy_to_xfer(struct scst_cmd *scmnd)
{
	struct srpt_send_ioctx *ioctx;
	enum srpt_command_state prev_cmd_state;
	int ret;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	prev_cmd_state = srpt_set_cmd_state(ioctx, SRPT_STATE_NEED_DATA);
	ret = srpt_xfer_data(ioctx->ch, ioctx, scmnd);
	if (unlikely(ret != SCST_TGT_RES_SUCCESS))
		srpt_set_cmd_state(ioctx, prev_cmd_state);

	return ret;
}

/**
 * srpt_xmit_response() - Transmits the response to a SCSI command.
 *
 * Callback function called by the SCST core. Must not block. Must ensure that
 * scst_tgt_cmd_done() will get invoked when returning SCST_TGT_RES_SUCCESS.
 */
static int srpt_xmit_response(struct scst_cmd *scmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_send_ioctx *ioctx;
	enum srpt_command_state state;
	int ret;
	scst_data_direction dir;
	int resp_len;

	ret = SCST_TGT_RES_SUCCESS;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	BUG_ON(!ioctx);

	ch = scst_sess_get_tgt_priv(scst_cmd_get_session(scmnd));
	BUG_ON(!ch);

	spin_lock(&ioctx->spinlock);
	state = ioctx->state;
	switch (state) {
	case SRPT_STATE_NEW:
	case SRPT_STATE_DATA_IN:
		ioctx->state = SRPT_STATE_CMD_RSP_SENT;
		break;
	default:
		WARN(true, "Unexpected command state %d", state);
		break;
	}
	spin_unlock(&ioctx->spinlock);

	if (unlikely(scst_cmd_aborted_on_xmit(scmnd))) {
		srpt_adjust_req_lim(ch, 0, 1);
		srpt_abort_cmd(ioctx, SCST_CONTEXT_SAME);
		goto out;
	}

	EXTRACHECKS_BUG_ON(scst_cmd_atomic(scmnd));

	dir = scst_cmd_get_data_direction(scmnd);

	/* For read commands, transfer the data to the initiator. */
	if (dir == SCST_DATA_READ
	    && scst_cmd_get_adjusted_resp_data_len(scmnd)) {
		ret = srpt_xfer_data(ch, ioctx, scmnd);
		if (unlikely(ret != SCST_TGT_RES_SUCCESS)) {
			srpt_set_cmd_state(ioctx, state);
			PRINT_WARNING("xfer_data failed for tag %llu"
				      " - %s", scst_cmd_get_tag(scmnd),
				      ret == SCST_TGT_RES_QUEUE_FULL ?
				      "retrying" : "failing");
			goto out;
		}
	}

	ioctx->req_lim_delta = srpt_inc_req_lim(ch);
	resp_len = srpt_build_cmd_rsp(ch, ioctx,
				      scst_cmd_get_tag(scmnd),
				      scst_cmd_get_status(scmnd),
				      scst_cmd_get_sense_buffer(scmnd),
				      scst_cmd_get_sense_buffer_len(scmnd));

	if (srpt_post_send(ch, ioctx, resp_len)) {
		srpt_unmap_sg_to_ib_sge(ch, ioctx);
		srpt_set_cmd_state(ioctx, state);
		srpt_undo_inc_req_lim(ch, ioctx->req_lim_delta);
		PRINT_WARNING("sending response failed for tag %llu - retrying",
			      scst_cmd_get_tag(scmnd));
		ret = SCST_TGT_RES_QUEUE_FULL;
	}

out:
	return ret;
}

/**
 * srpt_tsk_mgmt_done() - SCST callback function that sends back the response
 * for a task management request.
 *
 * Must not block.
 */
static void srpt_tsk_mgmt_done(struct scst_mgmt_cmd *mcmnd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_send_ioctx *ioctx;
	int rsp_len;

	ioctx = scst_mgmt_cmd_get_tgt_priv(mcmnd);
	BUG_ON(!ioctx);

	ch = ioctx->ch;
	BUG_ON(!ch);

	TRACE_DBG("%s: tsk_mgmt_done for tag= %lld status=%d",
		  __func__, ioctx->tsk_mgmt.tag,
		  scst_mgmt_cmd_get_status(mcmnd));

	WARN_ON(in_irq());

	srpt_set_cmd_state(ioctx, SRPT_STATE_MGMT_RSP_SENT);
	WARN_ON(ioctx->state == SRPT_STATE_DONE);

	ioctx->req_lim_delta = srpt_inc_req_lim(ch);
	rsp_len = srpt_build_tskmgmt_rsp(ch, ioctx,
					 scst_to_srp_tsk_mgmt_status(
					 scst_mgmt_cmd_get_status(mcmnd)),
					 ioctx->tsk_mgmt.tag);
	/*
	 * Note: the srpt_post_send() call below sends the task management
	 * response asynchronously. It is possible that the SCST core has
	 * already freed the struct scst_mgmt_cmd structure before the
	 * response is sent. This is fine however.
	 */
	if (srpt_post_send(ch, ioctx, rsp_len)) {
		PRINT_ERROR("Sending SRP_RSP response failed.");
		srpt_put_send_ioctx(ioctx);
		srpt_undo_inc_req_lim(ch, ioctx->req_lim_delta);
	}
}

/**
 * srpt_get_initiator_port_transport_id() - SCST TransportID callback function.
 *
 * See also SPC-3, section 7.5.4.5, TransportID for initiator ports using SRP.
 */
static int srpt_get_initiator_port_transport_id(struct scst_tgt *tgt,
	struct scst_session *scst_sess,	uint8_t **transport_id)
{
	struct srpt_rdma_ch *ch;
	struct spc_rdma_transport_id {
		uint8_t protocol_identifier;
		uint8_t reserved[7];
		uint8_t i_port_id[16];
	};
	struct spc_rdma_transport_id *tr_id;
	int res;

	TRACE_ENTRY();

	if (!scst_sess) {
		res = SCSI_TRANSPORTID_PROTOCOLID_SRP;
		goto out;
	}

	ch = scst_sess_get_tgt_priv(scst_sess);
	BUG_ON(!ch);

	BUILD_BUG_ON(sizeof(*tr_id) != 24);

	tr_id = kzalloc(sizeof(struct spc_rdma_transport_id), GFP_KERNEL);
	if (!tr_id) {
		PRINT_ERROR("Allocation of TransportID failed");
		res = -ENOMEM;
		goto out;
	}

	res = 0;
	tr_id->protocol_identifier = SCSI_TRANSPORTID_PROTOCOLID_SRP;
	memcpy(tr_id->i_port_id, ch->i_port_id, sizeof(ch->i_port_id));

	*transport_id = (uint8_t *)tr_id;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/**
 * srpt_on_free_cmd() - Free command-private data.
 *
 * Called by the SCST core. May be called in IRQ context.
 */
static void srpt_on_free_cmd(struct scst_cmd *scmnd)
{
	struct srpt_send_ioctx *ioctx;

	ioctx = scst_cmd_get_tgt_priv(scmnd);
	srpt_put_send_ioctx(ioctx);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
/* A vanilla 2.6.19 or older kernel without backported OFED kernel headers. */
static void srpt_refresh_port_work(void *ctx)
#else
static void srpt_refresh_port_work(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
	struct srpt_port *sport = ctx;
#else
	struct srpt_port *sport = container_of(work, struct srpt_port, work);
#endif

	srpt_refresh_port(sport);
}

/**
 * srpt_detect() - Returns the number of target adapters.
 *
 * Callback function called by the SCST core.
 */
static int srpt_detect(struct scst_tgt_template *tp)
{
	int device_count;

	TRACE_ENTRY();

	device_count = atomic_read(&srpt_device_count);

	TRACE_EXIT_RES(device_count);

	return device_count;
}

static int srpt_close_session(struct scst_session *sess)
{
	struct srpt_rdma_ch *ch = scst_sess_get_tgt_priv(sess);

	srpt_close_ch(ch);
	return 0;
}

static int srpt_ch_list_empty(struct srpt_tgt *srpt_tgt)
{
	int res;

	spin_lock_irq(&srpt_tgt->spinlock);
	res = list_empty(&srpt_tgt->rch_list);
	spin_unlock_irq(&srpt_tgt->spinlock);

	return res;
}

/**
 * srpt_release_sport() - Free channel resources associated with a target.
 */
static int srpt_release_sport(struct srpt_tgt *srpt_tgt)
{
	struct srpt_rdma_ch *ch;

	TRACE_ENTRY();

	WARN_ON_ONCE(irqs_disabled());
	BUG_ON(!srpt_tgt);

	/* Disallow new logins and close all active sessions. */
	spin_lock_irq(&srpt_tgt->spinlock);
	srpt_tgt->enabled = false;
	__srpt_close_all_ch(srpt_tgt);
	spin_unlock_irq(&srpt_tgt->spinlock);

	while (wait_event_timeout(srpt_tgt->ch_releaseQ,
				  srpt_ch_list_empty(srpt_tgt), 5 * HZ) <= 0) {
		PRINT_INFO("%s: waiting for session unregistration ...",
			   srpt_tgt->scst_tgt->tgt_name);
		spin_lock_irq(&srpt_tgt->spinlock);
		list_for_each_entry(ch, &srpt_tgt->rch_list, list) {
			PRINT_INFO("%s: state %s; %d commands in progress",
				   ch->sess_name, get_ch_state_name(ch->state),
				   atomic_read(&ch->scst_sess->sess_cmd_count));
		}
		spin_unlock_irq(&srpt_tgt->spinlock);
	}

	TRACE_EXIT();
	return 0;
}

/**
 * srpt_release() - Free the resources associated with an SCST target.
 *
 * Callback function called by the SCST core from scst_unregister_target().
 */
static int srpt_release(struct scst_tgt *scst_tgt)
{
	struct srpt_tgt *srpt_tgt = srpt_convert_scst_tgt(scst_tgt);

	TRACE_ENTRY();

	EXTRACHECKS_WARN_ON_ONCE(irqs_disabled());

	BUG_ON(!scst_tgt);
	BUG_ON(!srpt_tgt);

	srpt_release_sport(srpt_tgt);

	scst_tgt_set_tgt_priv(scst_tgt, NULL);

	TRACE_EXIT();

	return 0;
}

/**
 * srpt_get_scsi_transport_version() - Returns the SCSI transport version.
 * This function is called from scst_pres.c, the code that implements
 * persistent reservation support.
 */
static uint16_t srpt_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	return 0x0940; /* SRP */
}

#if !defined(CONFIG_SCST_PROC)
static ssize_t srpt_show_device(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_tgt *srpt_tgt = srpt_convert_scst_tgt(scst_tgt);
	struct srpt_device *sdev;
	int res = -E_TGT_PRIV_NOT_YET_SET;

	if (!srpt_tgt)
		goto out;

	if (one_target_per_port) {
		struct srpt_port *sport;

		sport = container_of(srpt_tgt, struct srpt_port, srpt_tgt);
		sdev = sport->sdev;
	} else {
		sdev = container_of(srpt_tgt, struct srpt_device, srpt_tgt);
	}
	res = sprintf(buf, "%s\n", sdev->device->name);

out:
	return res;
}

static struct kobj_attribute srpt_device_attr =
	__ATTR(device, S_IRUGO, srpt_show_device, NULL);

static ssize_t show_login_info(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_tgt *srpt_tgt = srpt_convert_scst_tgt(scst_tgt);
	struct srpt_port *sport;
	int i, res = -E_TGT_PRIV_NOT_YET_SET;

	if (!srpt_tgt)
		goto out;

	if (one_target_per_port) {
		sport = container_of(srpt_tgt, struct srpt_port, srpt_tgt);
		res = sprintf(buf,
			      "tid_ext=%016llx,ioc_guid=%016llx,pkey=ffff,"
			      "dgid=%04x%04x%04x%04x%04x%04x%04x%04x,"
			      "service_id=%016llx\n",
			      srpt_service_guid, srpt_service_guid,
			      be16_to_cpu(((__be16 *) sport->gid.raw)[0]),
			      be16_to_cpu(((__be16 *) sport->gid.raw)[1]),
			      be16_to_cpu(((__be16 *) sport->gid.raw)[2]),
			      be16_to_cpu(((__be16 *) sport->gid.raw)[3]),
			      be16_to_cpu(((__be16 *) sport->gid.raw)[4]),
			      be16_to_cpu(((__be16 *) sport->gid.raw)[5]),
			      be16_to_cpu(((__be16 *) sport->gid.raw)[6]),
			      be16_to_cpu(((__be16 *) sport->gid.raw)[7]),
			      srpt_service_guid);
	} else {
		struct srpt_device *sdev;

		sdev = container_of(srpt_tgt, struct srpt_device, srpt_tgt);
		res = 0;
		for (i = 0; i < sdev->device->phys_port_cnt; i++) {
			sport = &sdev->port[i];

			res += sprintf(buf + res,
				   "tid_ext=%016llx,ioc_guid=%016llx,pkey=ffff,"
				   "dgid=%04x%04x%04x%04x%04x%04x%04x%04x,"
				   "service_id=%016llx\n",
				   srpt_service_guid,
				   srpt_service_guid,
				   be16_to_cpu(((__be16 *) sport->gid.raw)[0]),
				   be16_to_cpu(((__be16 *) sport->gid.raw)[1]),
				   be16_to_cpu(((__be16 *) sport->gid.raw)[2]),
				   be16_to_cpu(((__be16 *) sport->gid.raw)[3]),
				   be16_to_cpu(((__be16 *) sport->gid.raw)[4]),
				   be16_to_cpu(((__be16 *) sport->gid.raw)[5]),
				   be16_to_cpu(((__be16 *) sport->gid.raw)[6]),
				   be16_to_cpu(((__be16 *) sport->gid.raw)[7]),
				   srpt_service_guid);
		}
	}

out:
	return res;
}

static struct kobj_attribute srpt_show_login_info_attr =
	__ATTR(login_info, S_IRUGO, show_login_info, NULL);

static const struct attribute *srpt_tgt_attrs[] = {
	&srpt_device_attr.attr,
	&srpt_show_login_info_attr.attr,
	NULL
};

static ssize_t show_req_lim(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct scst_session *scst_sess;
	struct srpt_rdma_ch *ch;

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	ch = scst_sess_get_tgt_priv(scst_sess);
	if (!ch)
		return -ENOENT;
	return sprintf(buf, "%d\n", ch->req_lim);
}

static ssize_t show_req_lim_delta(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct scst_session *scst_sess;
	struct srpt_rdma_ch *ch;

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	ch = scst_sess_get_tgt_priv(scst_sess);
	if (!ch)
		return -ENOENT;
	return sprintf(buf, "%d\n", ch->req_lim_delta);
}

static ssize_t show_ch_state(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct scst_session *scst_sess;
	struct srpt_rdma_ch *ch;

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	ch = scst_sess_get_tgt_priv(scst_sess);
	if (!ch)
		return -ENOENT;
	return sprintf(buf, "%s\n", get_ch_state_name(ch->state));
}

static const struct kobj_attribute srpt_req_lim_attr =
	__ATTR(req_lim,       S_IRUGO, show_req_lim,       NULL);
static const struct kobj_attribute srpt_req_lim_delta_attr =
	__ATTR(req_lim_delta, S_IRUGO, show_req_lim_delta, NULL);
static const struct kobj_attribute srpt_ch_state_attr =
	__ATTR(ch_state, S_IRUGO, show_ch_state, NULL);

static const struct attribute *srpt_sess_attrs[] = {
	&srpt_req_lim_attr.attr,
	&srpt_req_lim_delta_attr.attr,
	&srpt_ch_state_attr.attr,
	NULL
};
#endif

/* SCST target template for the SRP target implementation. */
static struct scst_tgt_template srpt_template = {
	.name				 = DRV_NAME,
	.sg_tablesize			 = SRPT_DEF_SG_TABLESIZE,
	.max_hw_pending_time		 = RDMA_COMPL_TIMEOUT_S,
#if !defined(CONFIG_SCST_PROC)
	.enable_target			 = srpt_enable_target,
	.is_target_enabled		 = srpt_is_target_enabled,
	.tgt_attrs			 = srpt_tgt_attrs,
	.sess_attrs			 = srpt_sess_attrs,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags		 = DEFAULT_SRPT_TRACE_FLAGS,
	.trace_flags			 = &trace_flag,
#endif
	.detect				 = srpt_detect,
	.release			 = srpt_release,
	.close_session			 = srpt_close_session,
	.xmit_response			 = srpt_xmit_response,
	.rdy_to_xfer			 = srpt_rdy_to_xfer,
	.on_hw_pending_cmd_timeout	 = srpt_pending_cmd_timeout,
	.on_free_cmd			 = srpt_on_free_cmd,
	.task_mgmt_fn_done		 = srpt_tsk_mgmt_done,
	.get_initiator_port_transport_id = srpt_get_initiator_port_transport_id,
	.get_scsi_transport_version	 = srpt_get_scsi_transport_version,
};

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

#endif /*CONFIG_SCST_PROC*/

/* Note: the caller must have zero-initialized *@srpt_tgt. */
static void srpt_init_tgt(struct srpt_tgt *srpt_tgt)
{
	INIT_LIST_HEAD(&srpt_tgt->rch_list);
	init_waitqueue_head(&srpt_tgt->ch_releaseQ);
	spin_lock_init(&srpt_tgt->spinlock);
}

/**
 * srpt_add_one() - Infiniband device addition callback function.
 */
static void srpt_add_one(struct ib_device *device)
{
	struct srpt_device *sdev;
	struct srpt_port *sport;
	struct srpt_tgt *srpt_tgt;
	struct ib_srq_init_attr srq_attr;
	char tgt_name[24];
	int i, ret;

	TRACE_ENTRY();

	TRACE_DBG("device = %p, device->dma_ops = %p", device, device->dma_ops);

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev)
		goto err;

	sdev->device = device;

	if (!one_target_per_port) {
		srpt_tgt = &sdev->srpt_tgt;
		srpt_init_tgt(srpt_tgt);

		if (use_node_guid_in_target_name) {
			snprintf(tgt_name, sizeof(tgt_name),
				 "%04x:%04x:%04x:%04x",
				 be16_to_cpu(((__be16 *)&device->node_guid)[0]),
				 be16_to_cpu(((__be16 *)&device->node_guid)[1]),
				 be16_to_cpu(((__be16 *)&device->node_guid)[2]),
				 be16_to_cpu(((__be16 *)&device->node_guid)[3]));
			srpt_tgt->scst_tgt =
				scst_register_target(&srpt_template, tgt_name);
		} else {
			srpt_tgt->scst_tgt =
				scst_register_target(&srpt_template, NULL);
		}
		if (!srpt_tgt->scst_tgt) {
			PRINT_ERROR("SCST registration failed for %s.",
				    sdev->device->name);
			goto free_dev;
		}

		scst_tgt_set_tgt_priv(srpt_tgt->scst_tgt, sdev);
	}

	ret = ib_query_device(device, &sdev->dev_attr);
	if (ret) {
		PRINT_ERROR("ib_query_device() failed: %d", ret);
		goto unregister_tgt;
	}

	sdev->pd = ib_alloc_pd(device);
	if (IS_ERR(sdev->pd)) {
		PRINT_ERROR("ib_alloc_pd() failed: %ld", PTR_ERR(sdev->pd));
		goto unregister_tgt;
	}

	sdev->mr = ib_get_dma_mr(sdev->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(sdev->mr)) {
		PRINT_ERROR("ib_get_dma_mr() failed: %ld", PTR_ERR(sdev->mr));
		goto err_pd;
	}

	sdev->srq_size = min(max(srpt_srq_size, MIN_SRPT_SRQ_SIZE),
			     sdev->dev_attr.max_srq_wr);

	memset(&srq_attr, 0, sizeof(srq_attr));
	srq_attr.event_handler = srpt_srq_event;
	srq_attr.srq_context = (void *)sdev;
	srq_attr.attr.max_wr = sdev->srq_size;
	srq_attr.attr.max_sge = 1;
	srq_attr.attr.srq_limit = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	srq_attr.srq_type = IB_SRQT_BASIC;
#endif

	sdev->srq = ib_create_srq(sdev->pd, &srq_attr);
	if (IS_ERR(sdev->srq)) {
		PRINT_ERROR("ib_create_srq() failed: %ld", PTR_ERR(sdev->srq));
		goto err_mr;
	}

	TRACE_DBG("%s: create SRQ #wr= %d max_allow=%d dev= %s", __func__,
		  sdev->srq_size, sdev->dev_attr.max_srq_wr, device->name);

	if (!srpt_service_guid)
		srpt_service_guid = be64_to_cpu(device->node_guid) &
			~be64_to_cpu(IB_SERVICE_ID_AGN_MASK);

	sdev->cm_id = ib_create_cm_id(device, srpt_cm_handler, sdev);
	if (IS_ERR(sdev->cm_id)) {
		PRINT_ERROR("ib_create_cm_id() failed: %ld",
			    PTR_ERR(sdev->cm_id));
		goto err_srq;
	}

	/* print out target login information */
	TRACE_DBG("Target login info: id_ext=%016llx,"
		  "ioc_guid=%016llx,pkey=ffff,service_id=%016llx",
		  srpt_service_guid, srpt_service_guid, srpt_service_guid);

	/*
	 * We do not have a consistent service_id (ie. also id_ext of target_id)
	 * to identify this target. We currently use the guid of the first HCA
	 * in the system as service_id; therefore, the target_id will change
	 * if this HCA is gone bad and replaced by different HCA
	 */
	ret = ib_cm_listen(sdev->cm_id, cpu_to_be64(srpt_service_guid), 0,
			   NULL);
	if (ret) {
		PRINT_ERROR("ib_cm_listen() failed: %d (cm_id state = %d)",
			    ret, sdev->cm_id->state);
		goto err_cm;
	}

	INIT_IB_EVENT_HANDLER(&sdev->event_handler, sdev->device,
			      srpt_event_handler);
	ret = ib_register_event_handler(&sdev->event_handler);
	if (ret) {
		PRINT_ERROR("ib_register_event_handler() failed: %d", ret);
		goto err_cm;
	}

	sdev->ioctx_ring = (struct srpt_recv_ioctx **)
		srpt_alloc_ioctx_ring(sdev, sdev->srq_size,
				      sizeof(*sdev->ioctx_ring[0]),
				      srp_max_req_size, DMA_FROM_DEVICE);
	if (!sdev->ioctx_ring) {
		PRINT_ERROR("srpt_alloc_ioctx_ring() failed");
		goto err_event;
	}

	for (i = 0; i < sdev->srq_size; ++i)
		srpt_post_recv(sdev, sdev->ioctx_ring[i]);

	WARN_ON(sdev->device->phys_port_cnt > ARRAY_SIZE(sdev->port));

	for (i = 1; i <= sdev->device->phys_port_cnt; i++) {
		sport = &sdev->port[i - 1];
		sport->sdev = sdev;
		sport->port = i;
		if (one_target_per_port)
			srpt_init_tgt(&sport->srpt_tgt);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
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
			goto err_ring;
		}
	}

	atomic_inc(&srpt_device_count);
out:
	ib_set_client_data(device, &srpt_client, sdev);

	TRACE_EXIT();
	return;

err_ring:
	srpt_free_ioctx_ring((struct srpt_ioctx **)sdev->ioctx_ring, sdev,
			     sdev->srq_size, srp_max_req_size,
			     DMA_FROM_DEVICE);
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
unregister_tgt:
	if (!one_target_per_port)
		scst_unregister_target(sdev->srpt_tgt.scst_tgt);
free_dev:
	kfree(sdev);
err:
	sdev = NULL;
	PRINT_INFO("%s(%s) failed.", __func__, device->name);
	goto out;
}

/**
 * srpt_remove_one() - InfiniBand device removal callback function.
 */
static void srpt_remove_one(struct ib_device *device)
{
	int i;
	struct srpt_device *sdev;

	TRACE_ENTRY();

	sdev = ib_get_client_data(device, &srpt_client);
	if (!sdev) {
		PRINT_INFO("%s(%s): nothing to do.", __func__, device->name);
		return;
	}

	srpt_unregister_mad_agent(sdev);

	ib_unregister_event_handler(&sdev->event_handler);

	/* Cancel any work queued by the just unregistered IB event handler. */
	for (i = 0; i < sdev->device->phys_port_cnt; i++)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
		cancel_work_sync(&sdev->port[i].work);
#else
		/*
		 * cancel_work_sync() was introduced in kernel 2.6.22. Older
		 * kernels do not have a facility to cancel scheduled work, so
		 * wait until the scheduled work finished.
		 */
		flush_scheduled_work();
#endif

	ib_destroy_cm_id(sdev->cm_id);

	/*
	 * SCST target unregistration must happen after destroying sdev->cm_id
	 * such that no new SRP_LOGIN_REQ information units can arrive while
	 * unregistering the SCST target.
	 */
	if (one_target_per_port) {
		for (i = 0; i < sdev->device->phys_port_cnt; i++) {
			struct srpt_tgt *tgt = &sdev->port[i].srpt_tgt;

			if (tgt->scst_tgt) {
				scst_unregister_target(tgt->scst_tgt);
				tgt->scst_tgt = NULL;
			}
		}
	} else {
		scst_unregister_target(sdev->srpt_tgt.scst_tgt);
		sdev->srpt_tgt.scst_tgt = NULL;
	}

	ib_destroy_srq(sdev->srq);
	ib_dereg_mr(sdev->mr);
	ib_dealloc_pd(sdev->pd);

	srpt_free_ioctx_ring((struct srpt_ioctx **)sdev->ioctx_ring, sdev,
			     sdev->srq_size, srp_max_req_size, DMA_FROM_DEVICE);
	sdev->ioctx_ring = NULL;
	kfree(sdev);

	TRACE_EXIT();
}

static struct ib_client srpt_client = {
	.name = DRV_NAME,
	.add = srpt_add_one,
	.remove = srpt_remove_one
};

#ifdef CONFIG_SCST_PROC

/**
 * srpt_register_procfs_entry() - Create SRPT procfs entries.
 *
 * Currently the only procfs entry created by this function is the
 * "trace_level" entry.
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

/**
 * srpt_unregister_procfs_entry() - Unregister SRPT procfs entries.
 */
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

/**
 * srpt_init_module() - Kernel module initialization.
 *
 * Note: Since ib_register_client() registers callback functions, and since at
 * least one of these callback functions (srpt_add_one()) calls SCST functions,
 * the SCST target template must be registered before ib_register_client() is
 * called.
 */
static int __init srpt_init_module(void)
{
	int ret;

	ret = -EINVAL;
	if (srp_max_req_size < MIN_MAX_REQ_SIZE) {
		PRINT_ERROR("invalid value %d for kernel module parameter"
			    " srp_max_req_size -- must be at least %d.",
			    srp_max_req_size,
			    MIN_MAX_REQ_SIZE);
		goto out;
	}

	if (srp_max_rsp_size < MIN_MAX_RSP_SIZE) {
		PRINT_ERROR("invalid value %d for kernel module parameter"
			    " srp_max_rsp_size -- must be at least %d.",
			    srp_max_rsp_size,
			    MIN_MAX_RSP_SIZE);
		goto out;
	}

	if (srpt_srq_size < MIN_SRPT_SRQ_SIZE
	    || srpt_srq_size > MAX_SRPT_SRQ_SIZE) {
		PRINT_ERROR("invalid value %d for kernel module parameter"
			    " srpt_srq_size -- must be in the range [%d..%d].",
			    srpt_srq_size, MIN_SRPT_SRQ_SIZE,
			    MAX_SRPT_SRQ_SIZE);
		goto out;
	}

	if (srpt_sq_size < MIN_SRPT_SQ_SIZE) {
		PRINT_ERROR("invalid value %d for kernel module parameter"
			    " srpt_sq_size -- must be at least %d.",
			    srpt_srq_size, MIN_SRPT_SQ_SIZE);
		goto out;
	}

	if (!one_target_per_port)
		PRINT_WARNING("%s%s", !use_node_guid_in_target_name ?
			      "Using one target per HCA " :
			      "Using autogenerated target names ",
			      "is deprecated and will be removed in one of the "
			      "next versions. It is strongly recommended to "
			      "set the one_target_per_port parameter to true "
			      "and to update your SCST config file.");

	ret = scst_register_target_template(&srpt_template);
	if (ret < 0) {
		PRINT_ERROR("couldn't register with scst");
		ret = -ENODEV;
		goto out;
	}

	ret = ib_register_client(&srpt_client);
	if (ret) {
		PRINT_ERROR("couldn't register IB client");
		goto out_unregister_target;
	}

#ifdef CONFIG_SCST_PROC
	ret = srpt_register_procfs_entry(&srpt_template);
	if (ret) {
		PRINT_ERROR("couldn't register procfs entry");
		goto out_unregister_client;
	}
#endif /*CONFIG_SCST_PROC*/

	return 0;

#ifdef CONFIG_SCST_PROC
out_unregister_client:
	ib_unregister_client(&srpt_client);
#endif /*CONFIG_SCST_PROC*/
out_unregister_target:
	scst_unregister_target_template(&srpt_template);
out:
	return ret;
}

static void __exit srpt_cleanup_module(void)
{
	TRACE_ENTRY();

	ib_unregister_client(&srpt_client);
#ifdef CONFIG_SCST_PROC
	srpt_unregister_procfs_entry(&srpt_template);
#endif /*CONFIG_SCST_PROC*/
	scst_unregister_target_template(&srpt_template);

	TRACE_EXIT();
}

module_init(srpt_init_module);
module_exit(srpt_cleanup_module);

/*
 * Local variables:
 * c-basic-offset:   8
 * indent-tabs-mode: t
 * End:
 */
