/*
 * Copyright (c) 2006 - 2009 Mellanox Technology Inc.  All rights reserved.
 * Copyright (C) 2008 - 2018 Bart Van Assche <bvanassche@acm.org>.
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

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/delay.h>
#if !defined(INSIDE_KERNEL_TREE)
#include <linux/version.h>
#endif
#include <linux/atomic.h>
#include <rdma/ib_cache.h>
#include "ib_srpt.h"
#define LOG_PREFIX "ib_srpt" /* Prefix for SCST tracing macros. */
#if defined(INSIDE_KERNEL_TREE)
#include <scst/scst_debug.h>
#else
#include "scst_debug.h"
#endif

/* Name of this kernel module. */
#define DRV_NAME		"ib_srpt"
#define DRV_VERSION		"3.10.0-pre" "#" __stringify(OFED_FLAVOR)
#define DRV_RELDATE		"28 December 2024"
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
/* Flags to be used in SCST debug tracing statements. */
#define DEFAULT_SRPT_TRACE_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR \
				  | TRACE_MGMT | TRACE_SPECIAL)
/* Name of the entry that will be created under /proc/scsi_tgt/ib_srpt. */
#define SRPT_PROC_TRACE_LEVEL_NAME	"trace_level"
#endif

#define DEFAULT_SRPT_ID_STRING	"SCST SRP target"

MODULE_AUTHOR("Vu Pham and Bart Van Assche");
MODULE_DESCRIPTION("SCSI RDMA Protocol target driver "
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_IMPORT_NS(SCST_NAMESPACE);

/*
 * Global Variables
 */

static u64 srpt_service_guid;
static atomic_t srpt_device_count;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static unsigned long trace_flag = DEFAULT_SRPT_TRACE_FLAGS;
module_param(trace_flag, long, 0644);
MODULE_PARM_DESC(trace_flag, "SCST trace flags.");
#endif

static u16 rdma_cm_port;
module_param(rdma_cm_port, short, 0444);
MODULE_PARM_DESC(rdma_cm_port, "Port number RDMA/CM will bind to.");

static unsigned int srp_max_rdma_size = DEFAULT_MAX_RDMA_SIZE;
module_param(srp_max_rdma_size, int, 0644);
MODULE_PARM_DESC(srp_max_rdma_size,
		 "Maximum size of SRP RDMA transfers for new connections.");

static unsigned int srp_max_req_size = DEFAULT_MAX_REQ_SIZE;
module_param(srp_max_req_size, int, 0444);
MODULE_PARM_DESC(srp_max_req_size,
		 "Maximum size of SRP request messages in bytes.");

static unsigned int srp_max_rsp_size = DEFAULT_MAX_RSP_SIZE;
module_param(srp_max_rsp_size, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(srp_max_rsp_size,
		 "Maximum size of SRP response messages in bytes.");

static bool use_srq;
module_param(use_srq, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(use_srq, "Whether or not to use SRQ");

static int srpt_srq_size = DEFAULT_SRPT_SRQ_SIZE;
module_param(srpt_srq_size, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(srpt_srq_size,
		 "Shared receive queue (SRQ) size.");

static int srpt_sq_size = DEF_SRPT_SQ_SIZE;
module_param(srpt_sq_size, int, 0444);
MODULE_PARM_DESC(srpt_sq_size, "Per-channel send queue (SQ) size.");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
static int srpt_get_u64_x(char *buffer, struct kernel_param *kp)
#else
static int srpt_get_u64_x(char *buffer, const struct kernel_param *kp)
#endif
{
	return sprintf(buffer, "0x%016llx", *(u64 *)kp->arg);
}
module_param_call(srpt_service_guid, NULL, srpt_get_u64_x, &srpt_service_guid,
		  0444);
MODULE_PARM_DESC(srpt_service_guid,
		 "Using this value for ioc_guid, id_ext, and cm_listen_id instead of using the node_guid of the first HCA.");

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
static struct workqueue_struct *srpt_wq;
static struct net *srpt_net_ns;
static struct rdma_cm_id *rdma_cm_id;

static void srpt_unmap_sg_to_ib_sge(struct srpt_rdma_ch *ch,
				    struct srpt_send_ioctx *ioctx);
static void srpt_destroy_ch_ib(struct srpt_rdma_ch *ch);
static void srpt_unregister_ch(struct srpt_rdma_ch *ch);

/*
 * The only allowed channel state changes are those that change the channel
 * state into a state with a higher numerical value. Hence the new > prev test.
 */
static bool srpt_set_ch_state(struct srpt_rdma_ch *ch, enum rdma_ch_state new)
{
	unsigned long flags;
	enum rdma_ch_state prev;
	bool changed = false;

	spin_lock_irqsave(&ch->spinlock, flags);
	prev = ch->state;
	if (new > prev) {
		ch->state = new;
		changed = true;
	}
	spin_unlock_irqrestore(&ch->spinlock, flags);

	return changed;
}

/*
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

/*
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

/*
 * srpt_undo_inc_req_lim() - Undo the effect of srpt_inc_req_lim.
 */
static int srpt_undo_inc_req_lim(struct srpt_rdma_ch *ch, int req_lim_delta)
{
	return srpt_adjust_req_lim(ch, -req_lim_delta, req_lim_delta - 1);
}

/**
 * srpt_event_handler - asynchronous IB event callback function
 * @handler: IB event handler registered by ib_register_event_handler().
 * @event: Description of the event that occurred.
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

	sdev = ib_get_client_data(event->device, &srpt_client);
	if (!sdev || sdev->device != event->device)
		return;

	pr_debug("ASYNC event= %d on device= %s\n", event->event,
		 dev_name(&sdev->device->dev));

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
	case IB_EVENT_GID_CHANGE:
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
		pr_err("received unrecognized IB event %d\n", event->event);
		break;
	}
}

/**
 * srpt_srq_event - SRQ event callback function
 * @event: Description of the event that occurred.
 * @ctx: Context pointer specified at SRQ creation time.
 */
static void srpt_srq_event(struct ib_event *event, void *ctx)
{
	pr_debug("SRQ event %d\n", event->event);
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
	case CH_DISCONNECTED:
		return "disconnected";
	}
	return "???";
}

/**
 * srpt_qp_event - QP event callback function
 * @event: Description of the event that occurred.
 * @ch: SRPT RDMA channel.
 */
static void srpt_qp_event(struct ib_event *event, struct srpt_rdma_ch *ch)
{
	pr_debug("QP event %d on ch=%p sess_name=%s-%d state=%s\n",
		 event->event, ch, ch->sess_name, ch->qp->qp_num,
		 get_ch_state_name(ch->state));

	switch (event->event) {
	case IB_EVENT_COMM_EST:
		if (ch->using_rdma_cm)
			rdma_notify(ch->rdma_cm.cm_id, event->event);
		else
			ib_cm_notify(ch->ib_cm.cm_id, event->event);
		break;
	case IB_EVENT_QP_LAST_WQE_REACHED:
		pr_debug("%s-%d, state %s: received Last WQE event.\n",
			 ch->sess_name, ch->qp->qp_num,
			 get_ch_state_name(ch->state));
		break;
	default:
		pr_err("received unrecognized IB QP event %d\n", event->event);
		break;
	}
}

/**
 * srpt_set_ioc - initialize a IOUnitInfo structure
 * @c_list: controller list.
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
 * srpt_get_class_port_info - copy ClassPortInfo to a management datagram
 * @mad: Datagram that will be sent as response to DM_ATTR_CLASS_PORT_INFO.
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
#ifndef HAVE_IB_SET_CPI_RESP_TIME
	cif->resp_time_value = 20;
#else
	ib_set_cpi_resp_time(cif, 20);
#endif

	mad->mad_hdr.status = 0;
}

/**
 * srpt_get_iou - write IOUnitInfo to a management datagram
 * @mad: Datagram that will be sent as response to DM_ATTR_IOU_INFO.
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
 * srpt_get_ioc - write IOControllerprofile to a management datagram
 * @sport: HCA port through which the MAD has been received.
 * @slot: Slot number specified in DM_ATTR_IOC_PROFILE query.
 * @mad: Datagram that will be sent as response to DM_ATTR_IOC_PROFILE.
 *
 * See also section 16.3.3.4 IOControllerProfile in the InfiniBand
 * Architecture Specification. See also section B.7, table B.7 in the SRP
 * r16a document.
 */
static void srpt_get_ioc(struct srpt_port *sport, u32 slot,
			 struct ib_dm_mad *mad)
{
	struct srpt_device *sdev = sport->sdev;
	struct ib_dm_ioc_profile *iocp;
	int send_queue_depth;

	iocp = (struct ib_dm_ioc_profile *)mad->data;

	if (!slot || slot > 16) {
		mad->mad_hdr.status
			= cpu_to_be16(DM_MAD_STATUS_INVALID_FIELD);
		return;
	}

	if (slot > 2) {
		mad->mad_hdr.status
			= cpu_to_be16(DM_MAD_STATUS_NO_IOC);
		return;
	}

	if (sdev->use_srq)
		send_queue_depth = sdev->srq_size;
	else
		send_queue_depth = min(MAX_SRPT_RQ_SIZE,
				       sdev->dev_attr.max_qp_wr);

	memset(iocp, 0, sizeof(*iocp));
	mutex_lock(&sport->mutex);
	strscpy(iocp->id_string, sport->port_id, sizeof(iocp->id_string));
	mutex_unlock(&sport->mutex);
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
	iocp->send_queue_depth = cpu_to_be16(send_queue_depth);

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
 * srpt_get_svc_entries - write ServiceEntries to a management datagram
 * @ioc_guid: I/O controller GUID to use in reply.
 * @slot: I/O controller number.
 * @hi: End of the range of service entries to be specified in the reply.
 * @lo: Start of the range of service entries to be specified in the reply..
 * @mad: Datagram that will be sent as response to DM_ATTR_SVC_ENTRIES.
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
		mad->mad_hdr.status
			= cpu_to_be16(DM_MAD_STATUS_INVALID_FIELD);
		return;
	}

	if (slot > 2 || lo > hi || hi > 1) {
		mad->mad_hdr.status
			= cpu_to_be16(DM_MAD_STATUS_NO_IOC);
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
 * srpt_mgmt_method_get - process a received management datagram
 * @sp:      HCA port through which the MAD has been received.
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
		srpt_get_ioc(sp, slot, rsp_mad);
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
 * srpt_mad_send_handler - MAD send completion callback
 * @mad_agent: Return value of ib_register_mad_agent().
 * @mad_wc: Work completion reporting that the MAD has been sent.
 */
static void srpt_mad_send_handler(struct ib_mad_agent *mad_agent,
				  struct ib_mad_send_wc *mad_wc)
{
#if HAVE_RDMA_DESTROY_AH_WITH_FLAGS
	rdma_destroy_ah(mad_wc->send_buf->ah, RDMA_DESTROY_AH_SLEEPABLE);
#elif HAVE_RDMA_DESTROY_AH
	rdma_destroy_ah(mad_wc->send_buf->ah);
#else
	ib_destroy_ah(mad_wc->send_buf->ah);
#endif
	ib_free_send_mad(mad_wc->send_buf);
}

/**
 * srpt_mad_recv_handler - MAD reception callback function
 * @mad_agent: Return value of ib_register_mad_agent().
 * @send_buf: Not used.
 * @mad_wc: Work completion reporting that a MAD has been received.
 */
static void srpt_mad_recv_handler(struct ib_mad_agent *mad_agent,
#ifdef MAD_HANDLER_TAKES_SEND_BUF
				  struct ib_mad_send_buf *send_buf,
#endif
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
				 mad_wc->wc->pkey_index,
#ifdef CREATE_SEND_MAD_HAS_AH_ARG
				 NULL,
#endif
				 0, IB_MGMT_DEVICE_HDR, IB_MGMT_DEVICE_DATA,
				 GFP_KERNEL
#ifdef CREATE_SEND_MAD_HAS_BASE_ARG
				 , IB_MGMT_BASE_VERSION
#endif
				 );
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
#if HAVE_RDMA_DESTROY_AH_WITH_FLAGS
	rdma_destroy_ah(ah, RDMA_DESTROY_AH_SLEEPABLE);
#elif HAVE_RDMA_DESTROY_AH
	rdma_destroy_ah(ah);
#else
	ib_destroy_ah(ah);
#endif

err:
	ib_free_recv_mad(mad_wc);
}

/**
 * srpt_refresh_port - configure a HCA port
 * @sport: SRPT HCA port.
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

	ret = ib_query_port(sport->sdev->device, sport->port, &port_attr);
	if (ret)
		return ret;

	sport->sm_lid = port_attr.sm_lid;
	sport->lid = port_attr.lid;

#if HAVE_RDMA_QUERY_GID
	ret = rdma_query_gid(sport->sdev->device, sport->port, 0, &sport->gid);
#else
	ret = ib_query_gid(sport->sdev->device, sport->port, 0, &sport->gid
#ifdef IB_QUERY_GID_HAS_ATTR_ARG
			   , NULL
#endif
			   );
#endif
	if (ret)
		return ret;

	memset(&port_modify, 0, sizeof(port_modify));
	port_modify.set_port_cap_mask = IB_PORT_DEVICE_MGMT_SUP;
	port_modify.clr_port_cap_mask = 0;

	ret = ib_modify_port(sport->sdev->device, sport->port, 0, &port_modify);
	if (ret) {
		pr_warn("%s-%d: enabling device management failed (%d). Note: this is expected if SR-IOV is enabled.\n",
			dev_name(&sport->sdev->device->dev), sport->port, ret);
		goto register_tgt;
	}

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
							 sport
#ifdef REGISTER_MAD_AGENT_HAS_FLAGS_ARG
							 , 0
#endif
							 );
		if (IS_ERR(sport->mad_agent)) {
			pr_err("%s-%d: MAD agent registration failed (%ld). Note: this is expected if SR-IOV is enabled.\n",
			       dev_name(&sport->sdev->device->dev), sport->port,
			       PTR_ERR(sport->mad_agent));
			sport->mad_agent = NULL;
		}
	}

register_tgt:
	if (!sport->scst_tgt) {
		snprintf(tgt_name, sizeof(tgt_name), "%pI6", &sport->gid);
		sport->scst_tgt = scst_register_target(&srpt_template,
						       tgt_name);
		if (sport->scst_tgt)
			scst_tgt_set_tgt_priv(sport->scst_tgt, sport);
		else
			pr_err("Registration of target %s failed.\n", tgt_name);
	}

	return 0;
}

/**
 * srpt_unregister_mad_agent - unregister MAD callback functions
 * @sdev: SRPT HCA pointer.
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
			pr_err("disabling MAD processing failed.\n");
		if (sport->mad_agent) {
			ib_unregister_mad_agent(sport->mad_agent);
			sport->mad_agent = NULL;
		}
	}
}

/**
 * srpt_alloc_ioctx - allocate a SRPT I/O context structure
 * @sdev: SRPT HCA pointer.
 * @ioctx_size: I/O context size.
 * @buf_cache: I/O buffer cache.
 * @dir: DMA data direction.
 */
static struct srpt_ioctx *srpt_alloc_ioctx(struct srpt_device *sdev,
					   int ioctx_size,
					   struct kmem_cache *buf_cache,
					   enum dma_data_direction dir)
{
	struct srpt_ioctx *ioctx;

	ioctx = kzalloc(ioctx_size, GFP_KERNEL);
	if (!ioctx)
		goto err;

	ioctx->buf = kmem_cache_alloc(buf_cache, GFP_KERNEL);
	if (!ioctx->buf)
		goto err_free_ioctx;

	ioctx->dma = ib_dma_map_single(sdev->device, ioctx->buf,
				       kmem_cache_size(buf_cache), dir);
	if (ib_dma_mapping_error(sdev->device, ioctx->dma))
		goto err_free_buf;

	return ioctx;

err_free_buf:
	kmem_cache_free(buf_cache, ioctx->buf);
err_free_ioctx:
	kfree(ioctx);
err:
	return NULL;
}

/**
 * srpt_free_ioctx - free a SRPT I/O context structure
 * @sdev: SRPT HCA pointer.
 * @ioctx: I/O context pointer.
 * @buf_cache: I/O buffer cache.
 * @dir: DMA data direction.
 */
static void srpt_free_ioctx(struct srpt_device *sdev, struct srpt_ioctx *ioctx,
			    struct kmem_cache *buf_cache,
			    enum dma_data_direction dir)
{
	if (!ioctx)
		return;

	ib_dma_unmap_single(sdev->device, ioctx->dma,
			    kmem_cache_size(buf_cache), dir);
	kmem_cache_free(buf_cache, ioctx->buf);
	kfree(ioctx);
}

/**
 * srpt_alloc_ioctx_ring - allocate a ring of SRPT I/O context structures
 * @sdev:       Device to allocate the I/O context ring for.
 * @ring_size:  Number of elements in the I/O context ring.
 * @ioctx_size: I/O context size.
 * @buf_cache:  I/O buffer cache.
 * @alignment_offset: Offset in each ring buffer at which the SRP information
 *		unit starts.
 * @dir:        DMA data direction.
 */
static struct srpt_ioctx **srpt_alloc_ioctx_ring(struct srpt_device *sdev,
				int ring_size, int ioctx_size,
				struct kmem_cache *buf_cache,
				int alignment_offset,
				enum dma_data_direction dir)
{
	struct srpt_ioctx **ring;
	int i;

	WARN_ON(ioctx_size != sizeof(struct srpt_recv_ioctx) &&
		ioctx_size != sizeof(struct srpt_send_ioctx));

	ring = kvmalloc_array(ring_size, sizeof(ring[0]), GFP_KERNEL);
	if (!ring)
		goto out;
	for (i = 0; i < ring_size; ++i) {
		ring[i] = srpt_alloc_ioctx(sdev, ioctx_size, buf_cache, dir);
		if (!ring[i])
			goto err;
		ring[i]->index = i;
		ring[i]->offset = alignment_offset;
	}
	goto out;

err:
	while (--i >= 0)
		srpt_free_ioctx(sdev, ring[i], buf_cache, dir);
	kvfree(ring);
	ring = NULL;
out:
	return ring;
}

/**
 * srpt_free_ioctx_ring - free the ring of SRPT I/O context structures
 * @ioctx_ring: I/O context ring to be freed.
 * @sdev: SRPT HCA pointer.
 * @ring_size: Number of ring elements.
 * @buf_cache: I/O buffer cache.
 * @dir: DMA data direction.
 */
static void srpt_free_ioctx_ring(struct srpt_ioctx **ioctx_ring,
				 struct srpt_device *sdev, int ring_size,
				 struct kmem_cache *buf_cache,
				 enum dma_data_direction dir)
{
	int i;

	if (!ioctx_ring)
		return;

	for (i = 0; i < ring_size; ++i)
		srpt_free_ioctx(sdev, ioctx_ring[i], buf_cache, dir);
	kvfree(ioctx_ring);
}

/**
 * srpt_set_cmd_state - set the state of a SCSI command
 * @ioctx: Send I/O context.
 * @new: New I/O context state.
 *
 * Does not modify the state of aborted commands. Returns the previous command
 * state.
 */
static enum srpt_command_state srpt_set_cmd_state(struct srpt_send_ioctx *ioctx,
						  enum srpt_command_state new)
{
	enum srpt_command_state previous;

	previous = ioctx->state;
	if (previous != SRPT_STATE_DONE)
		ioctx->state = new;

	return previous;
}

/**
 * srpt_test_and_set_cmd_state - test and set the state of a command
 * @ioctx: Send I/O context.
 * @old: Current I/O context state.
 * @new: New I/O context state.
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

	previous = ioctx->state;
	if (previous == old)
		ioctx->state = new;

	return previous == old;
}

/**
 * srpt_post_recv - post an IB receive request
 * @sdev: SRPT HCA pointer.
 * @ch: SRPT RDMA channel.
 * @ioctx: Receive I/O context pointer.
 */
static int srpt_post_recv(struct srpt_device *sdev, struct srpt_rdma_ch *ch,
			  struct srpt_recv_ioctx *ioctx)
{
	struct ib_sge list;
	struct ib_recv_wr wr;
	BAD_WR_MODIFIER struct ib_recv_wr *bad_wr;

	BUG_ON(!sdev);
	wr.wr_id = encode_wr_id(SRPT_RECV, ioctx->ioctx.index);

	list.addr = ioctx->ioctx.dma + ioctx->ioctx.offset;
	list.length = srp_max_req_size;
	list.lkey = sdev->lkey;

	wr.next = NULL;
	wr.sg_list = &list;
	wr.num_sge = 1;

	if (sdev->use_srq)
		return ib_post_srq_recv(sdev->srq, &wr, &bad_wr);
	else
		return ib_post_recv(ch->qp, &wr, &bad_wr);
}

static int srpt_adjust_sq_wr_avail(struct srpt_rdma_ch *ch, int delta)
{
	return atomic_add_return(delta, &ch->sq_wr_avail);
}

/**
 * srpt_post_send - post an IB send request
 * @ch: SRPT RDMA channel.
 * @ioctx: I/O context.
 * @len: Length in bytes of request to send.
 *
 * Returns zero upon success and a non-zero value upon failure.
 */
static int srpt_post_send(struct srpt_rdma_ch *ch,
			  struct srpt_send_ioctx *ioctx, int len)
{
	struct ib_sge list;
	struct ib_send_wr wr;
	BAD_WR_MODIFIER struct ib_send_wr *bad_wr;
	struct srpt_device *sdev = ch->sport->sdev;
	int ret;

	ret = -ENOMEM;
	if (srpt_adjust_sq_wr_avail(ch, -1) < 0) {
		pr_warn("ch %s-%d send queue full (needed 1)\n", ch->sess_name,
			ch->qp->qp_num);
		goto out;
	}

	ib_dma_sync_single_for_device(sdev->device, ioctx->ioctx.dma, len,
				      DMA_TO_DEVICE);

	list.addr = ioctx->ioctx.dma;
	list.length = len;
	list.lkey = sdev->lkey;

	wr.next = NULL;
	wr.wr_id = encode_wr_id(SRPT_SEND, ioctx->ioctx.index);
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	ret = ib_post_send(ch->qp, &wr, &bad_wr);

out:
	if (ret < 0)
		srpt_adjust_sq_wr_avail(ch, 1);
	return ret;
}

/**
 * srpt_zerolength_write - perform a zero-length RDMA write
 * @ch: SRPT RDMA channel.
 *
 * A quote from the InfiniBand specification: C9-88: For an HCA responder
 * using Reliable Connection service, for each zero-length RDMA READ or WRITE
 * request, the R_Key shall not be validated, even if the request includes
 * Immediate data.
 */
static int srpt_zerolength_write(struct srpt_rdma_ch *ch)
{
#ifdef USE_PRE_440_WR_STRUCTURE
	struct ib_send_wr wr;
#else
	struct ib_rdma_wr wr;
#endif
	BAD_WR_MODIFIER struct ib_send_wr *bad_wr;

	memset(&wr, 0, sizeof(wr));
#ifdef USE_PRE_440_WR_STRUCTURE
	wr.opcode = IB_WR_RDMA_WRITE;
	wr.wr_id = encode_wr_id(SRPT_RDMA_ZEROLENGTH_WRITE, 0xffffffffUL);
	wr.send_flags = IB_SEND_SIGNALED;
	return ib_post_send(ch->qp, &wr, &bad_wr);
#else
	wr.wr.opcode = IB_WR_RDMA_WRITE;
	wr.wr.wr_id = encode_wr_id(SRPT_RDMA_ZEROLENGTH_WRITE, 0xffffffffUL);
	wr.wr.send_flags = IB_SEND_SIGNALED;
	return ib_post_send(ch->qp, &wr.wr, &bad_wr);
#endif
}

static inline void *srpt_get_desc_buf(struct srp_cmd *srp_cmd)
{
	/*
	 * The pointer computations below will only be compiled correctly
	 * if srp_cmd::add_data is declared as s8*, u8*, s8[] or u8[], so check
	 * whether srp_cmd::add_data has been declared as a byte pointer.
	 */
	BUILD_BUG_ON(!__same_type(srp_cmd->add_data[0], (s8)0) &&
		     !__same_type(srp_cmd->add_data[0], (u8)0));

	/*
	 * According to the SRP spec, the lower two bits of the 'ADDITIONAL
	 * CDB LENGTH' field are reserved and the size in bytes of this field
	 * is four times the value specified in bits 3..7. Hence the "& ~3".
	 */
	return srp_cmd->add_data + (srp_cmd->add_cdb_len & ~3);
}

/**
 * srpt_get_desc_tbl - parse the data descriptors of a SRP_CMD request
 * @recv_ioctx: I/O context associated with the received command @srp_cmd.
 * @ioctx: I/O context that will be used for responding to the initiator.
 * @srp_cmd: Pointer to the SRP_CMD request data.
 * @dir: Pointer to the variable to which the transfer direction will be
 *   written.
 * @data_len: Pointer to the variable to which the total data length of all
 *   descriptors in the SRP_CMD request will be written.
 * @imm_data_offset: [in] Offset in SRP_CMD requests at which immediate data
 *   starts.
 *
 * This function initializes ioctx->nrbuf and ioctx->r_bufs.
 *
 * Returns -EINVAL when the SRP_CMD request contains inconsistent descriptors;
 * -ENOMEM when memory allocation fails and zero upon success.
 */
static int srpt_get_desc_tbl(struct srpt_recv_ioctx *recv_ioctx,
			     struct srpt_send_ioctx *ioctx,
			     struct srp_cmd *srp_cmd,
			     scst_data_direction *dir, u64 *data_len,
			     u16 imm_data_offset)
{
	u8 fmt;

	BUG_ON(!dir);
	BUG_ON(!data_len);

	*data_len = 0;

	/*
	 * The lower four bits of the buffer format field contain the DATA-IN
	 * buffer descriptor format, and the highest four bits contain the
	 * DATA-OUT buffer descriptor format.
	 */
	fmt = srp_cmd->buf_fmt;
	if (fmt & 0xf) {
		/* DATA-IN: transfer data from target to initiator (read). */
		*dir = SCST_DATA_READ;
		fmt = fmt & 0xf;
	} else if (fmt >> 4) {
		/* DATA-OUT: transfer data from initiator to target (write). */
		*dir = SCST_DATA_WRITE;
		fmt = fmt >> 4;
	} else {
		*dir = SCST_DATA_NONE;
	}

	if (fmt == SRP_DATA_DESC_DIRECT) {
		struct srp_direct_buf *db = srpt_get_desc_buf(srp_cmd);

		ioctx->n_rbuf = 1;
		ioctx->rbufs = &ioctx->single_rbuf;

		memcpy(ioctx->rbufs, db, sizeof(*db));
		*data_len = be32_to_cpu(db->len);
		return 0;
	} else if (fmt == SRP_DATA_DESC_INDIRECT) {
		struct srp_indirect_buf *idb = srpt_get_desc_buf(srp_cmd);
		struct srp_direct_buf *db;

		ioctx->n_rbuf = be32_to_cpu(idb->table_desc.len) / sizeof(*db);

		if (ioctx->n_rbuf >
		    (srp_cmd->data_out_desc_cnt + srp_cmd->data_in_desc_cnt)) {
			pr_err("received unsupported SRP_CMD request type (%u out + %u in != %u / %zu)\n",
			       srp_cmd->data_out_desc_cnt,
			       srp_cmd->data_in_desc_cnt,
			       be32_to_cpu(idb->table_desc.len),
			       sizeof(struct srp_direct_buf));
			ioctx->n_rbuf = 0;
			return -EINVAL;
		}

		if (ioctx->n_rbuf == 1)
			ioctx->rbufs = &ioctx->single_rbuf;
		else {
			ioctx->rbufs = kmalloc_array(ioctx->n_rbuf,
						     sizeof(*db), GFP_ATOMIC);
			if (!ioctx->rbufs) {
				ioctx->n_rbuf = 0;
				return -ENOMEM;
			}
		}

		db = idb->desc_list;
		memcpy(ioctx->rbufs, db, ioctx->n_rbuf * sizeof(*db));
		*data_len = be32_to_cpu(idb->len);
		return 0;
	} else if (fmt == SRP_DATA_DESC_IMM) {
		struct srp_imm_buf *imm_buf = srpt_get_desc_buf(srp_cmd);
		void *data = (void *)srp_cmd + imm_data_offset;
		uint32_t len = be32_to_cpu(imm_buf->len);
		uint32_t req_size = imm_data_offset + len;

		if (req_size > srp_max_req_size) {
			pr_err("Immediate data (length %d + %d) exceeds request size %d\n",
			       imm_data_offset, len, srp_max_req_size);
			return -EINVAL;
		}
		if (recv_ioctx->byte_len < req_size) {
			pr_err("Received too few data - %d < %d\n",
			       recv_ioctx->byte_len, req_size);
			return -EIO;
		}
		/*
		 * The immediate data buffer descriptor must occur before the
		 * immediate data itself.
		 */
		if ((void *)(imm_buf + 1) > (void *)data) {
			pr_err("Received invalid write request\n");
			return -EINVAL;
		}
		*data_len = len;
		ioctx->recv_ioctx = recv_ioctx;
		if ((uintptr_t)data & 511) {
			pr_warn_once("Internal error - the receive buffers are not aligned properly.\n");
			return -EINVAL;
		}
		/* Note: this sg entry may span more than one physical page. */
		sg_init_one(&ioctx->imm_sg, data, len);
		scst_cmd_set_tgt_sg(&ioctx->cmd, &ioctx->imm_sg, 1);
		return 0;
	} else if (fmt != 0) {
		pr_err("Unsupported data format %d\n\n", fmt);
		return -EINVAL;
	} else {
		*data_len = 0;
		return 0;
	}
}

/**
 * srpt_init_ch_qp - initialize queue pair attributes
 * @ch: SRPT RDMA channel.
 * @qp: Queue pair pointer.
 *
 * Initialized the attributes of queue pair 'qp' by allowing local write,
 * remote read and remote write. Also transitions 'qp' to state IB_QPS_INIT.
 */
static int srpt_init_ch_qp(struct srpt_rdma_ch *ch, struct ib_qp *qp)
{
	struct ib_qp_attr *attr;
	int ret;

	WARN_ON_ONCE(ch->using_rdma_cm);

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_INIT;
	attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE;
	attr->port_num = ch->sport->port;

	ret = ib_find_cached_pkey(ch->sport->sdev->device, ch->sport->port,
				  ch->pkey, &attr->pkey_index);
	if (ret < 0)
		pr_err("Translating pkey %#x failed (%d) - using index 0\n",
		       ch->pkey, ret);

	ret = ib_modify_qp(qp, attr,
			   IB_QP_STATE | IB_QP_ACCESS_FLAGS | IB_QP_PORT |
			   IB_QP_PKEY_INDEX);

	kfree(attr);
	return ret;
}

/**
 * srpt_ch_qp_rtr - change the state of a channel to 'ready to receive' (RTR)
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

	WARN_ON_ONCE(ch->using_rdma_cm);

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_RTR;
	ret = ib_cm_init_qp_attr(ch->ib_cm.cm_id, attr, &attr_mask);
	if (ret)
		goto out;

	attr->max_dest_rd_atomic = 4;

	ret = ib_modify_qp(qp, attr, attr_mask);

out:
	kfree(attr);
	return ret;
}

/**
 * srpt_ch_qp_rts - change the state of a channel to 'ready to send' (RTS)
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

	WARN_ON_ONCE(ch->using_rdma_cm);

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->qp_state = IB_QPS_RTS;
	ret = ib_cm_init_qp_attr(ch->ib_cm.cm_id, attr, &attr_mask);
	if (ret)
		goto out;

	attr->max_rd_atomic = 4;

	ret = ib_modify_qp(qp, attr, attr_mask);

out:
	kfree(attr);
	return ret;
}

/**
 * srpt_ch_qp_err - set the channel queue pair state to 'error'
 * @ch: SRPT RDMA channel.
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
 * srpt_get_send_ioctx - obtain an I/O context for sending to the initiator
 * @ch: SRPT RDMA channel.
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
	ioctx->state = SRPT_STATE_NEW;
	EXTRACHECKS_WARN_ON(ioctx->recv_ioctx);
	ioctx->n_rbuf = 0;
	ioctx->rbufs = NULL;
	ioctx->n_rdma = 0;
	ioctx->n_rdma_ius = 0;
	ioctx->rdma_ius = NULL;
	ioctx->mapped_sg_count = 0;
	memset(&ioctx->cmd, 0, sizeof(ioctx->cmd));

	return ioctx;
}

/**
 * srpt_put_send_ioctx() - free up resources
 * @ioctx: I/O context to free.
 */
static void srpt_put_send_ioctx(struct srpt_send_ioctx *ioctx)
{
	struct srpt_rdma_ch *ch = ioctx->ch;
	struct srpt_recv_ioctx *recv_ioctx = ioctx->recv_ioctx;
	unsigned long flags;

	if (recv_ioctx) {
		EXTRACHECKS_WARN_ON(!list_empty(&recv_ioctx->wait_list));
		ioctx->recv_ioctx = NULL;
		srpt_post_recv(ch->sport->sdev, ch, recv_ioctx);
	}

	/*
	 * If the WARN_ON() below gets triggered this means that
	 * srpt_unmap_sg_to_ib_sge() has not been called.
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
 * srpt_abort_cmd - abort a SCSI command
 * @ioctx:   I/O context associated with the SCSI command.
 * @context: Preferred execution context.
 *
 * Must only be called when the I/O context is in a state where it is waiting
 * for the HCA.
 */
static void srpt_abort_cmd(struct srpt_send_ioctx *ioctx,
			   enum scst_exec_context context)
{
	struct scst_cmd *cmd = &ioctx->cmd;
	enum srpt_command_state state = ioctx->state;

	switch (state) {
	case SRPT_STATE_NEED_DATA:
		ioctx->state = SRPT_STATE_DATA_IN;
		break;
	case SRPT_STATE_CMD_RSP_SENT:
	case SRPT_STATE_MGMT_RSP_SENT:
		ioctx->state = SRPT_STATE_DONE;
		break;
	default:
		WARN_ONCE(true, "%s: unexpected I/O context state %d\n",
			  __func__, state);
		break;
	}

	WARN_ON(ioctx != scst_cmd_get_tgt_priv(cmd));

	pr_debug("Aborting cmd with state %d -> %d and tag %lld\n", state,
		 ioctx->state, scst_cmd_get_tag(cmd));

	switch (state) {
	case SRPT_STATE_NEW:
	case SRPT_STATE_DATA_IN:
	case SRPT_STATE_MGMT:
	case SRPT_STATE_DONE:
		/*
		 * Do nothing - defer abort processing until
		 * srpt_queue_response() is invoked.
		 */
		break;
	case SRPT_STATE_NEED_DATA:
		pr_debug("tag %#llx: RDMA read error\n", ioctx->cmd.tag);
		scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		scst_rx_data(cmd, SCST_RX_STATUS_ERROR_SENSE_SET, context);
		break;
	case SRPT_STATE_CMD_RSP_SENT:
		/*
		 * SRP_RSP sending failed or the SRP_RSP send completion has
		 * not been received in time.
		 */
		srpt_unmap_sg_to_ib_sge(ioctx->ch, ioctx);
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_ABORTED);
		scst_tgt_cmd_done(cmd, context);
		break;
	case SRPT_STATE_MGMT_RSP_SENT:
		/*
		 * Management command response sending failed. This state is
		 * never reached since there is no cmd associated with
		 * management commands. Note: the SCST core frees these
		 * commands immediately after srpt_tsk_mgmt_done() returned.
		 */
		WARN(true, "Unexpected command state %d\n", state);
		break;
	}
}

/*
 * srpt_handle_send_err_comp() - Process an IB_WC_SEND error completion.
 */
static void srpt_handle_send_err_comp(struct srpt_rdma_ch *ch, u64 wr_id,
				      enum scst_exec_context context)
{
	u32 index = idx_from_wr_id(wr_id);
	struct srpt_send_ioctx *ioctx = ch->ioctx_ring[index];
	struct scst_cmd *cmd = &ioctx->cmd;
	enum srpt_command_state state = ioctx->state;
	int wr_avail_delta = 1;

	switch (state) {
	case SRPT_STATE_NEED_DATA:
		srpt_abort_cmd(ioctx, context);
		break;
	case SRPT_STATE_CMD_RSP_SENT:
		if (scst_cmd_get_data_direction(cmd) == SCST_DATA_READ) {
			/*
			 * IB_SEND_SIGNALED is not set for RDMA writes so
			 * process the wr_avail delta when the response
			 * send completion has been received.
			 */
			EXTRACHECKS_WARN_ON(ioctx->n_rdma <= 0);
			wr_avail_delta += ioctx->n_rdma;
		}
		srpt_undo_inc_req_lim(ch, ioctx->req_lim_delta);
		srpt_abort_cmd(ioctx, context);
		break;
	case SRPT_STATE_MGMT_RSP_SENT:
		srpt_undo_inc_req_lim(ch, ioctx->req_lim_delta);
		srpt_put_send_ioctx(ioctx);
		break;
	case SRPT_STATE_DONE:
		pr_err("Received more than one IB error completion for wr_id = %u.\n",
		       index);
		break;
	default:
		EXTRACHECKS_WARN_ON(true);
		break;
	}

	srpt_adjust_sq_wr_avail(ch, wr_avail_delta);
}

/*
 * srpt_handle_send_comp() - Process an IB send completion notification.
 */
static void srpt_handle_send_comp(struct srpt_rdma_ch *ch,
				  struct srpt_send_ioctx *ioctx,
				  enum scst_exec_context context)
{
	struct scst_cmd *cmd = &ioctx->cmd;
	int wr_avail_delta = 1;

	switch (srpt_set_cmd_state(ioctx, SRPT_STATE_DONE)) {
	case SRPT_STATE_CMD_RSP_SENT:
		if (scst_cmd_get_data_direction(cmd) == SCST_DATA_READ) {
			/*
			 * IB_SEND_SIGNALED is not set for RDMA writes so
			 * process the wr_avail delta when the response
			 * send completion has been received.
			 */
			EXTRACHECKS_WARN_ON(ioctx->n_rdma <= 0);
			wr_avail_delta += ioctx->n_rdma;
		}
		srpt_unmap_sg_to_ib_sge(ch, ioctx);
		scst_tgt_cmd_done(&ioctx->cmd, context);
		break;
	case SRPT_STATE_MGMT_RSP_SENT:
		srpt_put_send_ioctx(ioctx);
		break;
	case SRPT_STATE_DONE:
		pr_err("IB completion has been received too late for wr_id = %u.\n",
		       ioctx->ioctx.index);
		break;
	default:
		EXTRACHECKS_WARN_ON(true);
	}

	srpt_adjust_sq_wr_avail(ch, wr_avail_delta);
}

/*
 * srpt_handle_rdma_comp() - Process an IB RDMA completion notification.
 */
static void srpt_handle_rdma_comp(struct srpt_rdma_ch *ch,
				  struct srpt_send_ioctx *ioctx,
				  enum srpt_opcode opcode,
				  enum scst_exec_context context)
{
	struct scst_cmd *cmd = &ioctx->cmd;

	if (opcode == SRPT_RDMA_READ_LAST) {
		EXTRACHECKS_WARN_ON(ioctx->n_rdma <= 0);
		srpt_adjust_sq_wr_avail(ch, ioctx->n_rdma);
		if (srpt_test_and_set_cmd_state(ioctx, SRPT_STATE_NEED_DATA,
						SRPT_STATE_DATA_IN))
			scst_rx_data(cmd, SCST_RX_STATUS_SUCCESS, context);
		else
			pr_err("%s: wrong ioctx state %d\n", __func__,
			       ioctx->state);
	} else if (opcode == SRPT_RDMA_ABORT) {
		ioctx->rdma_aborted = true;
	} else {
		WARN(true, "Unexpected RDMA opcode %d\n", opcode);
	}
}

/*
 * srpt_handle_rdma_err_comp() - Process an IB RDMA error completion.
 */
static void srpt_handle_rdma_err_comp(struct srpt_rdma_ch *ch,
				      struct srpt_send_ioctx *ioctx,
				      enum srpt_opcode opcode,
				      enum scst_exec_context context)
{
	struct scst_cmd *cmd = &ioctx->cmd;
	enum srpt_command_state state = ioctx->state;

	switch (opcode) {
	case SRPT_RDMA_READ_LAST:
		if (ioctx->n_rdma <= 0) {
			pr_err("Received invalid RDMA read error completion with idx %d\n",
			       ioctx->ioctx.index);
			break;
		}
		srpt_adjust_sq_wr_avail(ch, ioctx->n_rdma);
		if (state == SRPT_STATE_NEED_DATA)
			srpt_abort_cmd(ioctx, context);
		else
			pr_err("%s: wrong ioctx state %d\n", __func__, state);
		break;
	case SRPT_RDMA_WRITE_LAST:
		/*
		 * Note: if an RDMA write error completion is received that
		 * means that a SEND also has been posted. Defer further
		 * processing of the associated command until the send error
		 * completion has been received.
		 */
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_ABORTED);
		break;
	default:
		pr_err("%s: opcode %u\n", __func__, opcode);
		break;
	}
}

/**
 * srpt_build_cmd_rsp - build a SRP_RSP response
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
	struct scst_cmd *cmd = &ioctx->cmd;
	struct srp_rsp *srp_rsp;
	int resid, max_sense_len;

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

	if (unlikely(scst_get_resid(cmd, &resid, NULL) && resid != 0)) {
		if (scst_cmd_get_data_direction(cmd) & SCST_DATA_READ) {
			if (resid > 0)
				srp_rsp->flags |= SRP_RSP_FLAG_DIUNDER;
			else if (resid < 0)
				srp_rsp->flags |= SRP_RSP_FLAG_DIOVER;
			srp_rsp->data_in_res_cnt = cpu_to_be32(abs(resid));
		}
		if (scst_cmd_get_data_direction(cmd) & SCST_DATA_WRITE) {
			if (resid > 0)
				srp_rsp->flags |= SRP_RSP_FLAG_DOUNDER;
			else if (resid < 0)
				srp_rsp->flags |= SRP_RSP_FLAG_DOOVER;
			srp_rsp->data_out_res_cnt = cpu_to_be32(abs(resid));
		}
	}

	if (!scst_sense_valid(sense_data)) {
		sense_data_len = 0;
	} else {
		BUILD_BUG_ON(sizeof(*srp_rsp) >= MIN_MAX_RSP_SIZE);
		max_sense_len = ch->max_ti_iu_len - sizeof(*srp_rsp);
		if (sense_data_len > max_sense_len) {
			pr_warn("truncated sense data from %d to %d bytes\n",
				sense_data_len, max_sense_len);
			sense_data_len = max_sense_len;
		}

		srp_rsp->flags |= SRP_RSP_FLAG_SNSVALID;
		srp_rsp->sense_data_len = cpu_to_be32(sense_data_len);
		memcpy(srp_rsp + 1, sense_data, sense_data_len);
	}

	return sizeof(*srp_rsp) + sense_data_len;
}

/**
 * srpt_build_tskmgmt_rsp - build a task management response
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
 * srpt_handle_cmd - process a SRP_CMD information unit
 * @ch: SRPT RDMA channel.
 * @recv_ioctx: Receive I/O context.
 * @send_ioctx: Send I/O context.
 * @context: SCST command processing context.
 */
static int srpt_handle_cmd(struct srpt_rdma_ch *ch,
			   struct srpt_recv_ioctx *recv_ioctx,
			   struct srpt_send_ioctx *send_ioctx,
			   enum scst_exec_context context)
{
	struct scst_cmd *cmd;
	struct srp_cmd *srp_cmd;
	scst_data_direction dir;
	u64 data_len;
	int ret;

	BUG_ON(!send_ioctx);

	srp_cmd = recv_ioctx->ioctx.buf + recv_ioctx->ioctx.offset;

	cmd = &send_ioctx->cmd;
	ret = scst_rx_cmd_prealloced(cmd, ch->sess, (u8 *) &srp_cmd->lun,
				     sizeof(srp_cmd->lun), srp_cmd->cdb,
				     sizeof(srp_cmd->cdb), in_interrupt());
	if (ret) {
		pr_err("tag 0x%llx: SCST command initialization failed\n",
		       srp_cmd->tag);
		goto err;
	}

	ret = srpt_get_desc_tbl(recv_ioctx, send_ioctx, srp_cmd, &dir,
				&data_len, ch->imm_data_offset);
	if (ret) {
		pr_err("0x%llx: parsing SRP descriptor table failed.\n",
		       srp_cmd->tag);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	}

	switch (srp_cmd->task_attr) {
	case SRP_CMD_HEAD_OF_Q:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case SRP_CMD_ORDERED_Q:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case SRP_CMD_SIMPLE_Q:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case SRP_CMD_ACA:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_ACA);
		break;
	default:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

	scst_cmd_set_tag(cmd, srp_cmd->tag);
	scst_cmd_set_tgt_priv(cmd, send_ioctx);
	scst_cmd_set_expected(cmd, dir, data_len);
	scst_cmd_init_done(cmd, context);

	return 0;

err:
	srpt_put_send_ioctx(send_ioctx);
	return -1;
}

/**
 * srpt_handle_tsk_mgmt - process a SRP_TSK_MGMT information unit
 * @ch: SRPT RDMA channel.
 * @recv_ioctx: Receive I/O context.
 * @send_ioctx: Send I/O context.
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

	srp_tsk = recv_ioctx->ioctx.buf + recv_ioctx->ioctx.offset;

	pr_debug("recv_tsk_mgmt= %d for task_tag= %lld using tag= %lld ch= %p sess= %p\n",
		 srp_tsk->tsk_mgmt_func, srp_tsk->task_tag, srp_tsk->tag,
		 ch, ch->sess);

	send_ioctx->tsk_mgmt.tag = srp_tsk->tag;

	switch (srp_tsk->tsk_mgmt_func) {
	case SRP_TSK_ABORT_TASK:
		pr_debug("Processing SRP_TSK_ABORT_TASK\n");
		ret = scst_rx_mgmt_fn_tag(ch->sess, SCST_ABORT_TASK,
					  srp_tsk->task_tag,
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_ABORT_TASK_SET:
		pr_debug("Processing SRP_TSK_ABORT_TASK_SET\n");
		ret = scst_rx_mgmt_fn_lun(ch->sess, SCST_ABORT_TASK_SET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_CLEAR_TASK_SET:
		pr_debug("Processing SRP_TSK_CLEAR_TASK_SET\n");
		ret = scst_rx_mgmt_fn_lun(ch->sess, SCST_CLEAR_TASK_SET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_LUN_RESET:
		pr_debug("Processing SRP_TSK_LUN_RESET\n");
		ret = scst_rx_mgmt_fn_lun(ch->sess, SCST_LUN_RESET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	case SRP_TSK_CLEAR_ACA:
		pr_debug("Processing SRP_TSK_CLEAR_ACA\n");
		ret = scst_rx_mgmt_fn_lun(ch->sess, SCST_CLEAR_ACA,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  in_interrupt(), send_ioctx);
		break;
	default:
		pr_debug("Unsupported task management function.\n");
	}

	if (ret != 0) {
		pr_err("Processing task management function %d failed: %d\n",
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
 * srpt_handle_new_iu - process a newly received information unit
 * @ch:    RDMA channel through which the information unit has been received.
 * @recv_ioctx: Receive I/O context associated with the information unit.
 * @context: SCST command processing context.
 */
static struct srpt_send_ioctx *
srpt_handle_new_iu(struct srpt_rdma_ch *ch,
		   struct srpt_recv_ioctx *recv_ioctx,
		   enum scst_exec_context context)
{
	struct srpt_send_ioctx *send_ioctx = NULL;
	struct srp_cmd *srp_cmd;
	u8 opcode;

	BUG_ON(!ch);
	BUG_ON(!recv_ioctx);

	if (unlikely(ch->state == CH_CONNECTING))
		goto push;

	ib_dma_sync_single_for_cpu(ch->sport->sdev->device,
				   recv_ioctx->ioctx.dma,
				   recv_ioctx->ioctx.offset + srp_max_req_size,
				   DMA_FROM_DEVICE);

	srp_cmd = recv_ioctx->ioctx.buf + recv_ioctx->ioctx.offset;
	opcode = srp_cmd->opcode;
	if (opcode == SRP_CMD || opcode == SRP_TSK_MGMT) {
		send_ioctx = srpt_get_send_ioctx(ch);
		if (unlikely(!send_ioctx))
			goto push;
	}

	if (!list_empty(&recv_ioctx->wait_list)) {
		WARN_ON_ONCE(!ch->processing_wait_list);
		list_del_init(&recv_ioctx->wait_list);
	}

	switch (opcode) {
	case SRP_CMD:
		srpt_handle_cmd(ch, recv_ioctx, send_ioctx, context);
		break;
	case SRP_TSK_MGMT:
		srpt_handle_tsk_mgmt(ch, recv_ioctx, send_ioctx);
		break;
	case SRP_I_LOGOUT:
		pr_err("Not yet implemented: SRP_I_LOGOUT\n");
		break;
	case SRP_CRED_RSP:
		pr_debug("received SRP_CRED_RSP\n");
		break;
	case SRP_AER_RSP:
		pr_debug("received SRP_AER_RSP\n");
		break;
	case SRP_RSP:
		pr_err("Received SRP_RSP\n");
		break;
	default:
		pr_err("received IU with unknown opcode 0x%x\n", opcode);
		break;
	}

	if (!send_ioctx || !send_ioctx->recv_ioctx)
		srpt_post_recv(ch->sport->sdev, ch, recv_ioctx);

out:
	return send_ioctx;

push:
	if (list_empty(&recv_ioctx->wait_list)) {
		WARN_ON_ONCE(ch->processing_wait_list);
		list_add_tail(&recv_ioctx->wait_list, &ch->cmd_wait_list);
	}
	goto out;
}

static void srpt_process_rcv_completion(struct ib_cq *cq,
					struct srpt_rdma_ch *ch,
					struct ib_wc *wc)
{
	struct srpt_recv_ioctx *ioctx;
	u32 index;

	index = idx_from_wr_id(wc->wr_id);
	if (wc->status == IB_WC_SUCCESS) {
		int req_lim;

		req_lim = srpt_adjust_req_lim(ch, -1, 0);
		if (unlikely(req_lim < 0))
			pr_err("req_lim = %d < 0\n", req_lim);
		if (ch->sport->sdev->use_srq)
			ioctx = ch->sport->sdev->ioctx_ring[index];
		else
			ioctx = ch->ioctx_recv_ring[index];
		ioctx->byte_len = wc->byte_len;
		srpt_handle_new_iu(ch, ioctx, srpt_new_iu_context);
	} else if (ch->state <= CH_LIVE) {
		pr_info("receiving failed for idx %u with status %d\n", index,
			wc->status);
	}
}

/*
 * This function must be called from the context in which RDMA completions are
 * processed because it accesses the wait list without protection against
 * access from other threads.
 */
static void srpt_process_wait_list(struct srpt_rdma_ch *ch)
{
	struct srpt_recv_ioctx *recv_ioctx, *tmp;

	WARN_ON_ONCE(ch->state == CH_CONNECTING);

	if (list_empty(&ch->cmd_wait_list))
		return;

	WARN_ON_ONCE(ch->processing_wait_list);
	ch->processing_wait_list = true;
	list_for_each_entry_safe(recv_ioctx, tmp, &ch->cmd_wait_list,
				 wait_list) {
		if (!srpt_handle_new_iu(ch, recv_ioctx, srpt_new_iu_context))
			break;
	}
	ch->processing_wait_list = false;
}

/*
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
		} else if (opcode == SRPT_RDMA_ZEROLENGTH_WRITE) {
			WARN_ONCE(ch->state != CH_LIVE,
				  "%s-%d: QP not in 'live' state\n",
				  ch->sess_name, ch->qp->qp_num);
			srpt_process_wait_list(ch);
		} else {
			WARN(true, "unexpected opcode %d\n", opcode);
		}
	} else {
		if (opcode == SRPT_SEND) {
			pr_info("sending response for idx %u failed with status %d\n",
				index, wc->status);
			srpt_handle_send_err_comp(ch, wc->wr_id,
						  srpt_send_context);
		} else if (opcode == SRPT_RDMA_READ_LAST ||
			   opcode == SRPT_RDMA_WRITE_LAST) {
			pr_info("RDMA t %d for idx %u failed with status %d.%s\n",
				opcode, index, wc->status,
				wc->status == IB_WC_RETRY_EXC_ERR ?
				" If this has not been triggered by a cable pull, please consider to increase the subnet timeout parameter on the IB switch." :
				wc->status == IB_WC_WR_FLUSH_ERR ?
				" If this has not been triggered by a cable pull, please check the involved IB HCA's and cables." :
				"");
			srpt_handle_rdma_err_comp(ch, ch->ioctx_ring[index],
						  opcode, srpt_xmt_rsp_context);
		} else if (opcode == SRPT_RDMA_ZEROLENGTH_WRITE) {
			srpt_unregister_ch(ch);
		} else if (opcode != SRPT_RDMA_MID) {
			WARN(true, "unexpected opcode %d\n", opcode);
		}
	}

	if (unlikely(!list_empty(&ch->cmd_wait_list) &&
		     ch->state != CH_CONNECTING &&
		     !ch->processing_wait_list))
		srpt_process_wait_list(ch);
}

static void srpt_process_one_compl(struct srpt_rdma_ch *ch, struct ib_wc *wc)
{
	struct ib_cq *const cq = ch->cq;

	if (opcode_from_wr_id(wc->wr_id) == SRPT_RECV)
		srpt_process_rcv_completion(cq, ch, wc);
	else
		srpt_process_send_completion(cq, ch, wc);
}

static int srpt_poll(struct srpt_rdma_ch *ch, int budget)
{
	struct ib_cq *const cq = ch->cq;
	struct ib_wc *const wc = ch->wc;
	int i, n, processed = 0;

	while ((n = ib_poll_cq(cq, min_t(int, ARRAY_SIZE(ch->wc), budget),
			       wc)) > 0) {
		for (i = 0; i < n; i++)
			srpt_process_one_compl(ch, &wc[i]);
		budget -= n;
		processed += n;
	}

	return processed;
}

static int srpt_process_completion(struct srpt_rdma_ch *ch, int budget)
{
	struct ib_cq *const cq = ch->cq;
	int processed = 0, n = budget;

	do {
		processed += srpt_poll(ch, n);
		n = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP |
				     IB_CQ_REPORT_MISSED_EVENTS);
	} while (n > 0);

	return processed;
}

/*
 * srpt_completion() - IB completion queue callback function.
 */
static void srpt_completion(struct ib_cq *cq, void *ctx)
{
	struct srpt_rdma_ch *ch = ctx;

	queue_work_on(raw_smp_processor_id(), srpt_wq, &ch->compl);
}

static void srpt_free_ch(struct kref *kref)
{
	struct srpt_rdma_ch *ch = container_of(kref, struct srpt_rdma_ch, kref);

	srpt_destroy_ch_ib(ch);

	kfree_rcu(ch, rcu);
}

/*
 * Called indirectly by scst_unregister_session() after the last command
 * associated with a session has finished.
 */
static void srpt_unreg_ch(struct srpt_rdma_ch *ch)
{
	struct srpt_port *sport = ch->sport;
	struct srpt_device *sdev = sport->sdev;

	WARN_ON_ONCE(ch->state != CH_DISCONNECTED);
	flush_work(&ch->compl);

	srpt_free_ioctx_ring((struct srpt_ioctx **)ch->ioctx_recv_ring,
			     sdev, ch->rq_size,
			     ch->req_buf_cache, DMA_FROM_DEVICE);

	srpt_free_ioctx_ring((struct srpt_ioctx **)ch->ioctx_ring,
			     sdev, ch->rq_size,
			     ch->rsp_buf_cache, DMA_TO_DEVICE);

	/* Wait until CM callbacks have finished and prevent new callbacks. */
	if (ch->using_rdma_cm)
		rdma_destroy_id(ch->rdma_cm.cm_id);
	else
		ib_destroy_cm_id(ch->ib_cm.cm_id);

	/*
	 * Invoke wake_up() inside the lock to avoid that sport disappears
	 * after list_del() and before wake_up() has been invoked.
	 */
	mutex_lock(&sport->mutex);
	list_del_rcu(&ch->list);
	wake_up(&sport->ch_releaseQ);
	mutex_unlock(&sport->mutex);

	kref_put(&ch->kref, srpt_free_ch);
}

/*
 * Called by scst_unregister_session() after the last command associated with
 * a session has finished.
 */
static void srpt_unreg_sess(struct scst_session *sess)
{
	srpt_unreg_ch(scst_sess_get_tgt_priv(sess));
}

static void srpt_unregister_ch(struct srpt_rdma_ch *ch)
{
	WARN_ON_ONCE(!srpt_set_ch_state(ch, CH_DISCONNECTED));
	pr_debug("%s-%d: about to unregister this session\n", ch->sess_name,
		 ch->qp->qp_num);
	scst_unregister_session(ch->sess, false, srpt_unreg_sess);
}

static void srpt_do_compl_work(struct work_struct *work)
{
	struct srpt_rdma_ch *ch = container_of(work, typeof(*ch), compl);
	enum { poll_budget = 256 };
	int n;

	n = srpt_process_completion(ch, poll_budget);
	if (n >= poll_budget)
		schedule_work(work);
}

/**
 * srpt_create_ch_ib - create receive and send completion queues
 * @ch: SRPT RDMA channel.
 */
static int srpt_create_ch_ib(struct srpt_rdma_ch *ch)
{
	struct ib_qp_init_attr *qp_init;
	struct srpt_device *sdev = ch->sport->sdev;
	int sq_size = srpt_sq_size, i, ret;

	EXTRACHECKS_WARN_ON(ch->rq_size < 1);

	ret = -ENOMEM;
	qp_init = kzalloc(sizeof(*qp_init), GFP_KERNEL);
	if (!qp_init)
		goto out;

retry:
#if !defined(IB_CREATE_CQ_HAS_INIT_ATTR)
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch,
			      ch->rq_size + sq_size, ch->comp_vector);
#else
	{
	struct ib_cq_init_attr ia = { };

	ia.cqe = ch->rq_size + sq_size;
	ia.comp_vector = ch->comp_vector;
	ch->cq = ib_create_cq(sdev->device, srpt_completion, NULL, ch, &ia);
	}
#endif
	if (IS_ERR(ch->cq)) {
		ret = PTR_ERR(ch->cq);
		pr_err("failed to create CQ: cqe %d; c.v. %d; ret %d\n",
		       ch->rq_size + sq_size, ch->comp_vector, ret);
		goto out;
	}

	ib_req_notify_cq(ch->cq, IB_CQ_NEXT_COMP);

	qp_init->qp_context = (void *)ch;
	qp_init->event_handler
		= (void(*)(struct ib_event *, void*))srpt_qp_event;
	qp_init->send_cq = ch->cq;
	qp_init->recv_cq = ch->cq;
	qp_init->sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_init->qp_type = IB_QPT_RC;
	qp_init->cap.max_send_wr = sq_size;
#if HAVE_DEV_ATTR_MAX_SEND_SGE
	ch->max_send_sge = sdev->dev_attr.max_send_sge;
#else
	ch->max_send_sge = sdev->dev_attr.max_sge;
#endif
	qp_init->cap.max_send_sge = ch->max_send_sge;
	qp_init->cap.max_recv_sge = 1;
	if (sdev->use_srq) {
		qp_init->srq = sdev->srq;
	} else {
		qp_init->cap.max_recv_wr = ch->rq_size;
	}

	if (ch->using_rdma_cm) {
		ret = rdma_create_qp(ch->rdma_cm.cm_id, sdev->pd, qp_init);
		ch->qp = ch->rdma_cm.cm_id->qp;
	} else {
		ch->qp = ib_create_qp(sdev->pd, qp_init);
		if (!IS_ERR(ch->qp)) {
			ret = srpt_init_ch_qp(ch, ch->qp);
			if (ret)
				ib_destroy_qp(ch->qp);
		} else {
			ret = PTR_ERR(ch->qp);
		}
	}
	if (ret) {
		bool retry = sq_size > MIN_SRPT_SQ_SIZE;

		if (retry) {
			pr_debug("failed to create queue pair with sq_size = %d (%d) - retrying\n",
				 sq_size, ret);
			ib_destroy_cq(ch->cq);
			sq_size = max(sq_size / 2, MIN_SRPT_SQ_SIZE);
			goto retry;
		} else {
			pr_err("failed to create queue pair with sq_size = %d (%d)\n",
			       sq_size, ret);
			goto err_destroy_cq;
		}
	}

	pr_debug("qp_num = %#x\n", ch->qp->qp_num);

	if (!sdev->use_srq)
		for (i = 0; i < ch->rq_size; i++)
			srpt_post_recv(sdev, ch, ch->ioctx_recv_ring[i]);

	atomic_set(&ch->sq_wr_avail, qp_init->cap.max_send_wr);

	pr_debug("%s: max_cqe= %d max_sge= %d sq_size = %d ch= %p\n", __func__,
		  ch->cq->cqe, qp_init->cap.max_send_sge,
		  qp_init->cap.max_send_wr, ch);

out:
	kfree(qp_init);
	return ret;

err_destroy_cq:
	ch->qp = NULL;
	ib_destroy_cq(ch->cq);
	goto out;
}

static void srpt_destroy_ch_ib(struct srpt_rdma_ch *ch)
{
	ib_destroy_qp(ch->qp);
	ib_destroy_cq(ch->cq);
}

/**
 * srpt_close_ch - close a RDMA channel
 * @ch: SRPT RDMA channel.
 *
 * Make sure all resources associated with the channel will be deallocated at
 * an appropriate time.
 *
 * Returns true if and only if the channel state has been modified into
 * CH_DRAINING.
 */
static bool srpt_close_ch(struct srpt_rdma_ch *ch)
{
	int ret;

	if (!srpt_set_ch_state(ch, CH_DRAINING)) {
		pr_debug("%s: already closed\n", ch->sess_name);
		return false;
	}

	kref_get(&ch->kref);

	ret = srpt_ch_qp_err(ch);
	if (ret < 0)
		pr_err("%s-%d: changing queue pair into error state failed: %d\n",
		       ch->sess_name, ch->qp->qp_num, ret);

	ret = srpt_zerolength_write(ch);
	if (ret < 0) {
		pr_err("%s-%d: queuing zero-length write failed: %d\n",
		       ch->sess_name, ch->qp->qp_num, ret);
		srpt_unregister_ch(ch);
	}

	kref_put(&ch->kref, srpt_free_ch);

	return true;
}

/*
 * Change the channel state into CH_DISCONNECTING. If a channel has not yet
 * reached the connected state, close it. If a channel is in the connected
 * state, send a DREQ. If a DREQ has been received, send a DREP. Note: it is
 * the responsibility of the caller to ensure that this function is not
 * invoked concurrently with the code that accepts a connection. This means
 * that this function must either be invoked from inside a CM callback
 * function or that it must be invoked with the srpt_port.mutex held.
 */
static int srpt_disconnect_ch(struct srpt_rdma_ch *ch)
{
	int ret;

	if (!srpt_set_ch_state(ch, CH_DISCONNECTING))
		return -ENOTCONN;

	if (ch->using_rdma_cm) {
		ret = rdma_disconnect(ch->rdma_cm.cm_id);
	} else {
		ret = ib_send_cm_dreq(ch->ib_cm.cm_id, NULL, 0);
		if (ret < 0)
			ret = ib_send_cm_drep(ch->ib_cm.cm_id, NULL, 0);
	}

	if (ret < 0 && srpt_close_ch(ch))
		ret = 0;

	return ret;
}

static void __srpt_close_all_ch(struct srpt_port *sport)
{
	struct srpt_nexus *nexus;
	struct srpt_rdma_ch *ch;

	lockdep_assert_held(&sport->mutex);

	list_for_each_entry(nexus, &sport->nexus_list, entry) {
		list_for_each_entry(ch, &nexus->ch_list, list) {
			if (srpt_disconnect_ch(ch) >= 0)
				pr_info("Closing channel %s-%d because target %s has been disabled\n",
					ch->sess_name, ch->qp->qp_num,
					sport->scst_tgt->tgt_name);
			srpt_close_ch(ch);
		}
	}
}

/*
 * Look up (i_port_id, t_port_id) in sport->nexus_list. Create an entry if
 * it does not yet exist.
 */
static struct srpt_nexus *srpt_get_nexus(struct srpt_port *sport,
					 const u8 i_port_id[16],
					 const u8 t_port_id[16])
{
	struct srpt_nexus *nexus = NULL, *tmp_nexus = NULL, *n;

	for (;;) {
		mutex_lock(&sport->mutex);
		list_for_each_entry(n, &sport->nexus_list, entry) {
			if (memcmp(n->i_port_id, i_port_id, 16) == 0 &&
			    memcmp(n->t_port_id, t_port_id, 16) == 0) {
				nexus = n;
				break;
			}
		}
		if (!nexus && tmp_nexus) {
			list_add_tail_rcu(&tmp_nexus->entry,
					  &sport->nexus_list);
			swap(nexus, tmp_nexus);
		}
		mutex_unlock(&sport->mutex);

		if (nexus)
			break;
		tmp_nexus = kzalloc(sizeof(*nexus), GFP_KERNEL);
		if (!tmp_nexus) {
			nexus = ERR_PTR(-ENOMEM);
			break;
		}
		INIT_LIST_HEAD(&tmp_nexus->ch_list);
		memcpy(tmp_nexus->i_port_id, i_port_id, 16);
		memcpy(tmp_nexus->t_port_id, t_port_id, 16);
	}

	kfree(tmp_nexus);

	return nexus;
}

/*
 * srpt_enable_target - Set the "enabled" status of a target.
 */
static int srpt_enable_target(struct scst_tgt *scst_tgt, bool enable)
{
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	int res = -E_TGT_PRIV_NOT_YET_SET;

	EXTRACHECKS_WARN_ON_ONCE(irqs_disabled());

	if (!sport)
		goto out;

	pr_info("%s target %s\n", enable ? "Enabling" : "Disabling",
		scst_tgt->tgt_name);

	mutex_lock(&sport->mutex);
	sport->enabled = enable;
	if (!enable)
		__srpt_close_all_ch(sport);
	mutex_unlock(&sport->mutex);

	res = 0;

out:
	return res;
}

/*
 * srpt_is_target_enabled - Report whether a target is enabled.
 */
static bool srpt_is_target_enabled(struct scst_tgt *scst_tgt)
{
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);

	return sport && sport->enabled;
}

/*
 * srpt_next_comp_vector() - Next completion vector >= sport->comp_vector
 */
static u16 srpt_next_comp_vector(struct srpt_port *sport)
{
	u16 comp_vector;

	mutex_lock(&sport->mutex);
	comp_vector = cpumask_next(sport->comp_vector, &sport->comp_v_mask);
	if (comp_vector >= nr_cpu_ids)
		comp_vector = cpumask_next(-1, &sport->comp_v_mask);
	sBUG_ON(comp_vector >= nr_cpu_ids);
	sport->comp_vector = comp_vector;
	mutex_unlock(&sport->mutex);

	return comp_vector;
}

/**
 * srpt_cm_req_recv - process the event IB_CM_REQ_RECEIVED
 * @sdev: HCA through which the login request was received.
 * @ib_cm_id: IB/CM connection identifier in case of IB/CM.
 * @rdma_cm_id: RDMA/CM connection identifier in case of RDMA/CM.
 * @port_num: Port through which the REQ message was received.
 * @pkey: P_Key of the incoming connection.
 * @req: SRP login request.
 * @src_addr: GID (IB/CM) or IP address (RDMA/CM) of the port that submitted
 * the login request.
 *
 * Ownership of the cm_id is transferred to the target session if this
 * function returns zero. Otherwise the caller remains the owner of cm_id.
 */
static int srpt_cm_req_recv(struct srpt_device *const sdev,
			    struct ib_cm_id *ib_cm_id,
			    struct rdma_cm_id *rdma_cm_id,
			    u8 port_num, __be16 pkey,
			    const struct srp_login_req *req,
			    const char *src_addr)
{
	struct srpt_port *const sport = &sdev->port[port_num - 1];
	struct srpt_nexus *nexus;
	struct srp_login_rsp *rsp = NULL;
	struct srp_login_rej *rej = NULL;
	union {
		struct rdma_conn_param rdma_cm;
		struct ib_cm_rep_param ib_cm;
	} *rep_param = NULL;
	struct srpt_rdma_ch *ch = NULL;
	u32 it_iu_len;
	int i, ret;

	WARN_ON_ONCE(irqs_disabled());

	if (WARN_ON(!sdev || !req))
		return -EINVAL;

	it_iu_len = be32_to_cpu(req->req_it_iu_len);

	pr_info("Received SRP_LOGIN_REQ with i_port_id %pI6, t_port_id %pI6 and it_iu_len %d on port %d (guid=%pI6); pkey %#04x\n",
		req->initiator_port_id, req->target_port_id, it_iu_len,
		port_num, &sport->gid, be16_to_cpu(pkey));

	nexus = srpt_get_nexus(sport, req->initiator_port_id,
			       req->target_port_id);
	if (IS_ERR(nexus)) {
		ret = PTR_ERR(nexus);
		goto out;
	}

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
		pr_err("rejected SRP_LOGIN_REQ because its length (%d bytes) is out of range (%d .. %d)\n",
		       it_iu_len, 64, srp_max_req_size);
		goto reject;
	}

	if (!sport->enabled) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		pr_info("rejected SRP_LOGIN_REQ because target port %s has not yet been enabled\n",
			sport->scst_tgt->tgt_name);
		goto reject;
	}

	if (*(__be64 *)req->target_port_id != cpu_to_be64(srpt_service_guid)
	    || *(__be64 *)(req->target_port_id + 8) !=
	       cpu_to_be64(srpt_service_guid)) {
		rej->reason = cpu_to_be32(
				SRP_LOGIN_REJ_UNABLE_ASSOCIATE_CHANNEL);
		pr_err("rejected SRP_LOGIN_REQ because it has an invalid target port identifier.\n");
		goto reject;
	}

	ret = -ENOMEM;
	ch = kzalloc(sizeof(*ch), GFP_KERNEL);
	if (!ch) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		pr_err("rejected SRP_LOGIN_REQ because out of memory.\n");
		goto reject;
	}

	kref_init(&ch->kref);
	ch->pkey = be16_to_cpu(pkey);
	ch->nexus = nexus;
	ch->sport = sport;
	if (ib_cm_id) {
		ch->ib_cm.cm_id = ib_cm_id;
		ib_cm_id->context = ch;
	} else {
		ch->using_rdma_cm = true;
		ch->rdma_cm.cm_id = rdma_cm_id;
		rdma_cm_id->context = ch;
	}
	/*
	 * ch->rq_size should be at least as large as the initiator queue
	 * depth to avoid that the initiator driver has to report QUEUE_FULL
	 * to the SCSI mid-layer.
	 */
	ch->rq_size = min(MAX_SRPT_RQ_SIZE, scst_get_max_lun_commands(NULL, 0));
	spin_lock_init(&ch->spinlock);
	ch->state = CH_CONNECTING;
	INIT_WORK(&ch->compl, srpt_do_compl_work);
	INIT_LIST_HEAD(&ch->cmd_wait_list);
	ch->max_rsp_size = max_t(uint32_t, srp_max_rsp_size, MIN_MAX_RSP_SIZE);

	ch->rsp_buf_cache = kmem_cache_create("srpt-rsp-buf", ch->max_rsp_size,
					      512, 0, NULL);
	if (!ch->rsp_buf_cache)
		goto free_ch;

	ch->ioctx_ring = (struct srpt_send_ioctx **)
		srpt_alloc_ioctx_ring(ch->sport->sdev, ch->rq_size,
				      sizeof(*ch->ioctx_ring[0]),
				      ch->rsp_buf_cache, 0, DMA_TO_DEVICE);
	if (!ch->ioctx_ring) {
		pr_err("rejected SRP_LOGIN_REQ because creating a new QP SQ ring failed.\n");
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		goto free_rsp_cache;
	}

	INIT_LIST_HEAD(&ch->free_list);
	for (i = 0; i < ch->rq_size; i++) {
		ch->ioctx_ring[i]->ch = ch;
		list_add_tail(&ch->ioctx_ring[i]->free_list, &ch->free_list);
	}
	if (!sdev->use_srq) {
		u16 imm_data_offset = req->req_flags & SRP_IMMED_REQUESTED ?
			be16_to_cpu(req->imm_data_offset) : 0;
		u16 alignment_offset;
		u32 req_sz;

		if (req->req_flags & SRP_IMMED_REQUESTED)
			pr_debug("imm_data_offset = %d\n",
				 be16_to_cpu(req->imm_data_offset));
		if (imm_data_offset >= sizeof(struct srp_cmd)) {
			ch->imm_data_offset = imm_data_offset;
			rsp->rsp_flags |= SRP_LOGIN_RSP_IMMED_SUPP;
		} else {
			ch->imm_data_offset = 0;
		}
		alignment_offset = round_up(imm_data_offset, 512) -
			imm_data_offset;
		req_sz = alignment_offset + imm_data_offset + srp_max_req_size;
		ch->req_buf_cache = kmem_cache_create("srpt-req-buf", req_sz,
						      512, 0, NULL);
		if (!ch->req_buf_cache)
			goto free_rsp_ring;

		ch->ioctx_recv_ring = (struct srpt_recv_ioctx **)
			srpt_alloc_ioctx_ring(ch->sport->sdev, ch->rq_size,
					      sizeof(*ch->ioctx_recv_ring[0]),
					      ch->req_buf_cache,
					      alignment_offset,
					      DMA_FROM_DEVICE);
		if (!ch->ioctx_recv_ring) {
			pr_err("rejected SRP_LOGIN_REQ because creating a new QP RQ ring failed.\n");
			rej->reason =
			    cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
			goto free_recv_cache;
		}
		for (i = 0; i < ch->rq_size; i++)
			INIT_LIST_HEAD(&ch->ioctx_recv_ring[i]->wait_list);
	}

	ch->comp_vector = srpt_next_comp_vector(sport);

	ret = srpt_create_ch_ib(ch);
	if (ret) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		pr_err("rejected SRP_LOGIN_REQ because creating a new RDMA channel failed.\n");
		goto free_recv_ring;
	}

	strscpy(ch->sess_name, src_addr, sizeof(ch->sess_name));
	pr_debug("registering session %s\n", ch->sess_name);

	BUG_ON(!sport->scst_tgt);
	ret = -ENOMEM;
	ch->sess = scst_register_session(sport->scst_tgt, 0,
					 ch->sess_name, ch, NULL, NULL);
	if (!ch->sess) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		pr_debug("Failed to create SCST session\n");
		goto destroy_ib;
	}

	mutex_lock(&sport->mutex);

	if ((req->req_flags & SRP_MTCH_ACTION) == SRP_MULTICHAN_SINGLE) {
		struct srpt_rdma_ch *ch2;

		list_for_each_entry(ch2, &nexus->ch_list, list) {
			if (srpt_disconnect_ch(ch2) < 0)
				continue;
			pr_info("Relogin - closed existing channel %s\n",
				ch2->sess_name);
			rsp->rsp_flags |= SRP_LOGIN_RSP_MULTICHAN_TERMINATED;
		}
	} else {
		rsp->rsp_flags |= SRP_LOGIN_RSP_MULTICHAN_MAINTAINED;
	}

	list_add_tail_rcu(&ch->list, &nexus->ch_list);

	if (!sport->enabled) {
		rej->reason = cpu_to_be32(
				SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		pr_info("rejected SRP_LOGIN_REQ because the target %s (%s) is not enabled\n",
			sport->scst_tgt->tgt_name,
			dev_name(&sdev->device->dev));
		mutex_unlock(&sport->mutex);
		goto reject;
	}

	mutex_unlock(&sport->mutex);

	ret = ch->using_rdma_cm ? 0 : srpt_ch_qp_rtr(ch, ch->qp);
	if (ret) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		pr_err("rejected SRP_LOGIN_REQ because enabling RTR failed (error code = %d)\n",
		       ret);
		goto reject;
	}

	pr_debug("Establish connection sess=%p name=%s ch=%p\n", ch->sess,
		 ch->sess_name, ch);

	/* create srp_login_response */
	rsp->opcode = SRP_LOGIN_RSP;
	rsp->tag = req->tag;
	rsp->max_it_iu_len = cpu_to_be32(srp_max_req_size);
	rsp->max_ti_iu_len = req->req_it_iu_len;
	ch->max_ti_iu_len = it_iu_len;
	rsp->buf_fmt = cpu_to_be16(SRP_BUF_FORMAT_DIRECT |
				   SRP_BUF_FORMAT_INDIRECT);
	rsp->req_lim_delta = cpu_to_be32(ch->rq_size);
	ch->req_lim = ch->rq_size;
	ch->req_lim_delta = 0;

	/* create cm reply */
	if (ch->using_rdma_cm) {
		rep_param->rdma_cm.private_data = (void *)rsp;
		rep_param->rdma_cm.private_data_len = sizeof(*rsp);
		rep_param->rdma_cm.rnr_retry_count = 7;
		rep_param->rdma_cm.flow_control = 1;
		rep_param->rdma_cm.responder_resources = 4;
		rep_param->rdma_cm.initiator_depth = 4;
	} else {
		rep_param->ib_cm.qp_num = ch->qp->qp_num;
		rep_param->ib_cm.private_data = (void *)rsp;
		rep_param->ib_cm.private_data_len = sizeof(*rsp);
		rep_param->ib_cm.rnr_retry_count = 7;
		rep_param->ib_cm.flow_control = 1;
		rep_param->ib_cm.failover_accepted = 0;
		rep_param->ib_cm.srq = 1;
		rep_param->ib_cm.responder_resources = 4;
		rep_param->ib_cm.initiator_depth = 4;
	}

	/*
	 * Hold the sport mutex while accepting a connection to avoid that
	 * srpt_disconnect_ch() is invoked concurrently with this code.
	 */
	mutex_lock(&sport->mutex);
	if (sport->enabled && ch->state == CH_CONNECTING) {
		if (ch->using_rdma_cm)
			ret = rdma_accept(rdma_cm_id, &rep_param->rdma_cm);
		else
			ret = ib_send_cm_rep(ib_cm_id, &rep_param->ib_cm);
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&sport->mutex);

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		goto reject;
	default:
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		pr_err("sending SRP_LOGIN_REQ response failed (error code = %d)\n",
		       ret);
		goto reject;
	}

	goto out;

destroy_ib:
	srpt_destroy_ch_ib(ch);

free_recv_ring:
	srpt_free_ioctx_ring((struct srpt_ioctx **)ch->ioctx_recv_ring,
			     ch->sport->sdev, ch->rq_size,
			     ch->req_buf_cache, DMA_FROM_DEVICE);

free_recv_cache:
	kmem_cache_destroy(ch->req_buf_cache);

free_rsp_ring:
	srpt_free_ioctx_ring((struct srpt_ioctx **)ch->ioctx_ring,
			     ch->sport->sdev, ch->rq_size,
			     ch->rsp_buf_cache, DMA_TO_DEVICE);

free_rsp_cache:
	kmem_cache_destroy(ch->rsp_buf_cache);

free_ch:
	if (rdma_cm_id)
		rdma_cm_id->context = NULL;
	else
		ib_cm_id->context = NULL;
	kfree(ch);
	ch = NULL;

	WARN_ON_ONCE(ret == 0);

reject:
	pr_info("Rejecting login with reason %#x\n", be32_to_cpu(rej->reason));
	rej->opcode = SRP_LOGIN_REJ;
	rej->tag = req->tag;
	rej->buf_fmt = cpu_to_be16(SRP_BUF_FORMAT_DIRECT |
				   SRP_BUF_FORMAT_INDIRECT);

	if (rdma_cm_id)
		rdma_reject(rdma_cm_id, rej, sizeof(*rej)
#if RDMA_REJECT_HAS_FOUR_ARGS
			    , IB_CM_REJ_CONSUMER_DEFINED
#endif
			    );
	else
		ib_send_cm_rej(ib_cm_id, IB_CM_REJ_CONSUMER_DEFINED, NULL, 0,
			       rej, sizeof(*rej));

	if (ch && ch->qp) {
		srpt_close_ch(ch);
		/*
		 * Tell the caller not to free cm_id since srpt_do_compl_work()
		 * will do that.
		 */
		ret = 0;
	}

out:
	kfree(rep_param);
	kfree(rsp);
	kfree(rej);

	return ret;
}

static int srpt_ib_cm_req_recv(struct ib_cm_id *cm_id,
			       const struct ib_cm_req_event_param *param,
			       void *private_data)
{
	char sgid[40];

	snprintf(sgid, sizeof(sgid), "%pI6", &param->primary_path->dgid);

	return srpt_cm_req_recv(cm_id->context, cm_id, NULL, param->port,
				param->primary_path->pkey,
				private_data, sgid);
}

static const char *inet_ntop(const void *sa, char *dst, unsigned int size)
{
	switch (((struct sockaddr *)sa)->sa_family) {
	case AF_INET:
		snprintf(dst, size, "%pI4",
			 &((struct sockaddr_in *)sa)->sin_addr);
		break;
	case AF_INET6:
		snprintf(dst, size, "%pI6",
			 &((struct sockaddr_in6 *)sa)->sin6_addr);
		break;
	default:
		snprintf(dst, size, "???");
		break;
	}
	return dst;
}

static int srpt_rdma_cm_req_recv(struct rdma_cm_id *cm_id,
				 const struct rdma_cm_event *event)
{
	struct srpt_device *sdev;
	struct srp_login_req req;
	const struct srp_login_req_rdma *req_rdma;
	/*
	 * See also commit c2f8fc4ec440 ("IB/SA: Rename ib_sa_path_rec to
	 * sa_path_rec") # v4.12.
	 */
	typeof(cm_id->route.path_rec) path_rec = cm_id->route.path_rec;
	char src_addr[40];

	sdev = ib_get_client_data(cm_id->device, &srpt_client);
	if (!sdev)
		return -ECONNREFUSED;

	if (event->param.conn.private_data_len < sizeof(*req_rdma))
		return -EINVAL;

	/* Transform srp_login_req_rdma into srp_login_req. */
	req_rdma = event->param.conn.private_data;
	memset(&req, 0, sizeof(req));
	req.opcode		= req_rdma->opcode;
	req.tag			= req_rdma->tag;
	req.req_it_iu_len	= req_rdma->req_it_iu_len;
	req.req_buf_fmt		= req_rdma->req_buf_fmt;
	req.req_flags		= req_rdma->req_flags;
	memcpy(req.initiator_port_id, req_rdma->initiator_port_id, 16);
	memcpy(req.target_port_id, req_rdma->target_port_id, 16);
	req.imm_data_offset	= req_rdma->imm_data_offset;

	inet_ntop(&cm_id->route.addr.src_addr, src_addr, sizeof(src_addr));

	return srpt_cm_req_recv(sdev, NULL, cm_id, cm_id->port_num,
				path_rec ? path_rec->pkey : 0, &req, src_addr);
}

static void srpt_cm_rej_recv(struct srpt_rdma_ch *ch,
			     enum ib_cm_rej_reason reason,
			     const u8 *private_data,
			     u8 private_data_len)
{
	char *priv = NULL;
	int i;

	if (private_data_len && (priv = kmalloc(private_data_len * 3 + 1,
						GFP_KERNEL))) {
		for (i = 0; i < private_data_len; i++)
			sprintf(priv + 3 * i, " %02x", private_data[i]);
	}
	pr_info("Received CM REJ for ch %s-%d; reason %d%s%s.\n",
		ch->sess_name, ch->qp->qp_num, reason, private_data_len ?
		"; private data" : "", priv ? priv : " (?)");
	kfree(priv);
}

static void srpt_check_timeout(struct srpt_rdma_ch *ch)
{
	struct ib_qp_attr attr;
	struct ib_qp_init_attr iattr;
	uint64_t T_tr_ns, max_compl_time_ms;
	uint64_t T_tr_ms;

	if (ib_query_qp(ch->qp, &attr, IB_QP_TIMEOUT, &iattr) < 0) {
		pr_err("Querying QP attributes failed\n");
		return;
	}

	/*
	 * From IBTA C9-140: Transport Timer timeout interval
	 * T_tr = 4.096 us * 2**(local ACK timeout) where the local ACK timeout
	 * is a five-bit value, with zero meaning that the timer is disabled.
	 */
	WARN_ON(attr.timeout >= (1 << 5));
	if (attr.timeout) {
		T_tr_ns = 1ULL << (12 + attr.timeout);
		max_compl_time_ms = attr.retry_cnt * 4 * T_tr_ns;
		do_div(max_compl_time_ms, 1000000);
		T_tr_ms = T_tr_ns;
		do_div(T_tr_ms, 1000000);
		pr_debug("%s-%d: QP local ack timeout = %d or T_tr = %llu ms; retry_cnt = %d; max compl. time = %d ms\n",
			  ch->sess_name, ch->qp->qp_num, attr.timeout, T_tr_ms,
			  attr.retry_cnt, (unsigned int)max_compl_time_ms);

		if (max_compl_time_ms >= RDMA_COMPL_TIMEOUT_S * 1000) {
			pr_err("Maximum RDMA completion time (%lld ms) exceeds ib_srpt timeout (%d ms)\n",
			       max_compl_time_ms, 1000 * RDMA_COMPL_TIMEOUT_S);
		}
	}
}

/**
 * srpt_cm_rtu_recv - process an IB_CM_RTU_RECEIVED or USER_ESTABLISHED event
 * @ch: SRPT RDMA channel.
 *
 * An RTU (ready to use) message indicates that the connection has been
 * established and that the recipient may begin transmitting.
 */
static void srpt_cm_rtu_recv(struct srpt_rdma_ch *ch)
{
	int ret;

	ret = ch->using_rdma_cm ? 0 : srpt_ch_qp_rts(ch, ch->qp);
	if (ret < 0) {
		pr_err("%s-%d: QP transition to RTS failed\n", ch->sess_name,
		       ch->qp->qp_num);
		srpt_close_ch(ch);
		return;
	}

	srpt_check_timeout(ch);

	/*
	 * Note: calling srpt_close_ch() if the transition to the LIVE state
	 * fails is not necessary since that means that that function has
	 * already been invoked from another thread.
	 */
	if (!srpt_set_ch_state(ch, CH_LIVE))
		pr_err("%s-%d: channel transition to LIVE state failed\n",
		       ch->sess_name, ch->qp->qp_num);

	/* Trigger wait list processing. */
	ret = srpt_zerolength_write(ch);
	WARN_ONCE(ret < 0, "%d\n", ret);
}

/**
 * srpt_cm_handler - IB connection manager callback function
 * @cm_id: IB/CM connection identifier.
 * @event: IB/CM event.
 *
 * A non-zero return value will cause the caller destroy the CM ID.
 *
 * Note: srpt_cm_handler() must only return a non-zero value when transferring
 * ownership of the cm_id to a channel by srpt_cm_req_recv() failed. Returning
 * a non-zero value in any other case will trigger a race with the
 * ib_destroy_cm_id() call triggered indirectly by srpt_do_compl_work().
 */
static int srpt_cm_handler(struct ib_cm_id *cm_id,
			   CM_HANDLER_EVENT_MODIFIER struct ib_cm_event *event)
{
	struct srpt_rdma_ch *ch = cm_id->context;
	int ret;

	ret = 0;
	switch (event->event) {
	case IB_CM_REQ_RECEIVED:
		ret = srpt_ib_cm_req_recv(cm_id, &event->param.req_rcvd,
					  event->private_data);
		break;
	case IB_CM_REJ_RECEIVED:
		srpt_cm_rej_recv(ch, event->param.rej_rcvd.reason,
				 event->private_data,
				 IB_CM_REJ_PRIVATE_DATA_SIZE);
		break;
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		srpt_cm_rtu_recv(ch);
		break;
	case IB_CM_DREQ_RECEIVED:
		srpt_disconnect_ch(ch);
		break;
	case IB_CM_DREP_RECEIVED:
		pr_info("Received CM DREP message for ch %s-%d.\n",
			ch->sess_name, ch->qp->qp_num);
		srpt_close_ch(ch);
		break;
	case IB_CM_TIMEWAIT_EXIT:
		pr_info("Received CM TimeWait exit for ch %s-%d.\n",
			ch->sess_name, ch->qp->qp_num);
		srpt_close_ch(ch);
		break;
	case IB_CM_REP_ERROR:
		pr_info("Received CM REP error for ch %s-%d.\n", ch->sess_name,
			ch->qp->qp_num);
		break;
	case IB_CM_DREQ_ERROR:
		pr_info("Received CM DREQ ERROR event.\n");
		break;
	case IB_CM_MRA_RECEIVED:
		pr_info("Received CM MRA event\n");
		break;
	default:
		pr_err("received unrecognized CM event %d\n", event->event);
		break;
	}

	return ret;
}

static int srpt_rdma_cm_handler(struct rdma_cm_id *cm_id,
				struct rdma_cm_event *event)
{
	struct srpt_rdma_ch *ch = cm_id->context;
	int ret = 0;

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = srpt_rdma_cm_req_recv(cm_id, event);
		break;
	case RDMA_CM_EVENT_REJECTED:
		srpt_cm_rej_recv(ch, event->status,
				 event->param.conn.private_data,
				 event->param.conn.private_data_len);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		srpt_cm_rtu_recv(ch);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		if (ch->state < CH_DISCONNECTING)
			srpt_disconnect_ch(ch);
		else
			srpt_close_ch(ch);
		break;
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		srpt_close_ch(ch);
		break;
	case RDMA_CM_EVENT_UNREACHABLE:
		pr_info("Received CM REP error for ch %s-%d.\n", ch->sess_name,
			ch->qp->qp_num);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
	case RDMA_CM_EVENT_ADDR_CHANGE:
		break;
	default:
		pr_err("received unrecognized RDMA CM event %d\n",
		       event->event);
		break;
	}

	return ret;
}

/*
 * srpt_map_sg_to_ib_sge() - Map an SG list to an IB SGE list.
 */
static int srpt_map_sg_to_ib_sge(struct srpt_rdma_ch *ch,
				 struct srpt_send_ioctx *ioctx,
				 struct scst_cmd *cmd)
{
	struct srpt_device *sdev = ch->sport->sdev;
	struct ib_device *dev __maybe_unused = sdev->device;
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

	max_sge = ch->max_send_sge;
	dir = scst_cmd_get_data_direction(cmd);
	BUG_ON(dir == SCST_DATA_NONE);
	/*
	 * Cache 'dir' because it is needed in srpt_unmap_sg_to_ib_sge()
	 * and because scst_set_cmd_error_status() resets cmd->data_direction.
	 */
	ioctx->dir = dir;
	if (dir == SCST_DATA_WRITE) {
		scst_cmd_get_write_fields(cmd, &sg, &sg_cnt);
		WARN_ON(!sg);
		max_sge = min(max_sge, ch->sport->sdev->dev_attr.max_sge_rd);
	} else {
		sg = scst_cmd_get_sg(cmd);
		sg_cnt = scst_cmd_get_sg_cnt(cmd);
		WARN_ON(!sg);
	}
	ioctx->sg = sg;
	ioctx->sg_cnt = sg_cnt;
	count = ib_dma_map_sg(sdev->device, sg, sg_cnt,
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
			scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
		if (!ioctx->rdma_ius)
			goto free_mem;

		ioctx->n_rdma_ius = nrdma;
		sge_array = (struct ib_sge *)(ioctx->rdma_ius + nrdma);
	}

	db = ioctx->rbufs;
	tsize = (dir == SCST_DATA_READ)
		? scst_cmd_get_adjusted_resp_data_len(cmd)
		: scst_cmd_get_bufflen(cmd);
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
		? scst_cmd_get_adjusted_resp_data_len(cmd)
		: scst_cmd_get_bufflen(cmd);
	riu = ioctx->rdma_ius;
	dma_len = ib_sg_dma_len(dev, &sg[0]);
	dma_addr = ib_sg_dma_address(dev, &sg[0]);

	/* this second loop is really mapped sg_address to rdma_iu->ib_sge */
	for (i = 0, j = 0, cur_sg = sg;
	     j < count && i < ioctx->n_rbuf && tsize > 0; ++i, ++riu, ++db) {
		rsize = be32_to_cpu(db->len);
		sge = riu->sge;
		k = 0;

		while (rsize > 0 && tsize > 0) {
			sge->addr = dma_addr;
			sge->lkey = sdev->lkey;

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

/*
 * srpt_unmap_sg_to_ib_sge() - Unmap an IB SGE list.
 */
static void srpt_unmap_sg_to_ib_sge(struct srpt_rdma_ch *ch,
				    struct srpt_send_ioctx *ioctx)
{
	struct scatterlist *sg;
	scst_data_direction dir;

	EXTRACHECKS_BUG_ON(!ch);
	EXTRACHECKS_BUG_ON(!ioctx);

	if (scst_cmd_get_tgt_sg(&ioctx->cmd) == &ioctx->imm_sg)
		return;

	EXTRACHECKS_BUG_ON(ioctx->n_rdma && !ioctx->rdma_ius);

	if (ioctx->rdma_ius != (void *)ioctx->rdma_ius_buf)
		kfree(ioctx->rdma_ius);
	ioctx->rdma_ius = NULL;
	ioctx->n_rdma = 0;

	if (ioctx->mapped_sg_count) {
		EXTRACHECKS_WARN_ON(ioctx
				    != scst_cmd_get_tgt_priv(&ioctx->cmd));
		sg = ioctx->sg;
		EXTRACHECKS_WARN_ON(!sg);
		dir = ioctx->dir;
		EXTRACHECKS_BUG_ON(dir == SCST_DATA_NONE);
		ib_dma_unmap_sg(ch->sport->sdev->device, sg, ioctx->sg_cnt,
				scst_to_tgt_dma_dir(dir));
		ioctx->mapped_sg_count = 0;
	}
}

/*
 * srpt_perform_rdmas() - Perform IB RDMA.
 *
 * Returns zero upon success or a negative number upon failure.
 */
static int srpt_perform_rdmas(struct srpt_rdma_ch *ch,
			      struct srpt_send_ioctx *ioctx,
			      scst_data_direction dir)
{
#ifdef USE_PRE_440_WR_STRUCTURE
	struct ib_send_wr wr;
#else
	struct ib_rdma_wr wr;
#endif
	BAD_WR_MODIFIER struct ib_send_wr *bad_wr;
	struct rdma_iu *riu;
	int i;
	int ret = -ENOMEM;
	int sq_wr_avail;
	const int n_rdma = ioctx->n_rdma;

	sq_wr_avail = srpt_adjust_sq_wr_avail(ch, -n_rdma);
	if (sq_wr_avail < 0) {
		pr_warn("ch %s-%d send queue full (needed %d)\n",
			ch->sess_name, ch->qp->qp_num, n_rdma);
		goto out;
	}

	ioctx->rdma_aborted = false;
	ret = 0;
	riu = ioctx->rdma_ius;
	memset(&wr, 0, sizeof(wr));

	for (i = 0; i < n_rdma; ++i, ++riu) {
#ifdef USE_PRE_440_WR_STRUCTURE
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
#else
		if (dir == SCST_DATA_READ) {
			wr.wr.opcode = IB_WR_RDMA_WRITE;
			wr.wr.wr_id = encode_wr_id(i == n_rdma - 1 ?
						SRPT_RDMA_WRITE_LAST :
						SRPT_RDMA_MID,
						ioctx->ioctx.index);
		} else {
			wr.wr.opcode = IB_WR_RDMA_READ;
			wr.wr.wr_id = encode_wr_id(i == n_rdma - 1 ?
						SRPT_RDMA_READ_LAST :
						SRPT_RDMA_MID,
						ioctx->ioctx.index);
		}
		wr.wr.next = NULL;
		wr.remote_addr = riu->raddr;
		wr.rkey = riu->rkey;
		wr.wr.num_sge = riu->sge_cnt;
		wr.wr.sg_list = riu->sge;

		/* only get completion event for the last rdma wr */
		if (i == (n_rdma - 1) && dir == SCST_DATA_WRITE)
			wr.wr.send_flags = IB_SEND_SIGNALED;

		ret = ib_post_send(ch->qp, &wr.wr, &bad_wr);
#endif
		if (ret)
			break;
	}

	if (ret)
		pr_err("%s: ib_post_send() returned %d for %d/%d\n", __func__,
		       ret, i, n_rdma);
	if (ret && i > 0) {
#ifdef USE_PRE_440_WR_STRUCTURE
		wr.num_sge = 0;
		wr.wr_id = encode_wr_id(SRPT_RDMA_ABORT, ioctx->ioctx.index);
		wr.send_flags = IB_SEND_SIGNALED;
		pr_info("Trying to abort failed RDMA transfer [%d]\n",
			ioctx->ioctx.index);
		while (ch->state == CH_LIVE &&
		       ib_post_send(ch->qp, &wr, &bad_wr) != 0) {
			pr_info("Trying to abort failed RDMA transfer [%d]\n",
				ioctx->ioctx.index);
			msleep(1000);
		}
#else
		wr.wr.num_sge = 0;
		wr.wr.wr_id = encode_wr_id(SRPT_RDMA_ABORT, ioctx->ioctx.index);
		wr.wr.send_flags = IB_SEND_SIGNALED;
		pr_info("Trying to abort failed RDMA transfer [%d]\n",
			ioctx->ioctx.index);
		while (ch->state == CH_LIVE &&
		       ib_post_send(ch->qp, &wr.wr, &bad_wr) != 0) {
			pr_info("Trying to abort failed RDMA transfer [%d]\n",
				ioctx->ioctx.index);
			msleep(1000);
		}
#endif
		pr_info("Waiting until RDMA abort finished [%d]\n",
			ioctx->ioctx.index);
#ifdef USE_PRE_440_WR_STRUCTURE
		while (ch->state < CH_DISCONNECTED && !ioctx->rdma_aborted) {
			pr_info("Waiting until RDMA abort finished [%d]\n",
				ioctx->ioctx.index);
			msleep(1000);
		}
#else
		while (ch->state < CH_DISCONNECTED && !ioctx->rdma_aborted) {
			pr_info("Waiting until RDMA abort finished [%d]\n",
				ioctx->ioctx.index);
			msleep(1000);
		}
#endif
		pr_info("%s[%d]: done\n", __func__, __LINE__);
	}

out:
	if (unlikely(ret < 0))
		srpt_adjust_sq_wr_avail(ch, n_rdma);
	return ret;
}

/*
 * srpt_xfer_data() - Start data transfer from initiator to target.
 *
 * Returns 0, -EAGAIN or -EIO.
 *
 * Note: Must not block.
 */
static int srpt_xfer_data(struct srpt_rdma_ch *ch,
			  struct srpt_send_ioctx *ioctx)
{
	struct scst_cmd *cmd = &ioctx->cmd;
	int ret;

	if (scst_cmd_get_tgt_sg(&ioctx->cmd) == &ioctx->imm_sg) {
		bool res;

		res = srpt_test_and_set_cmd_state(ioctx, SRPT_STATE_NEED_DATA,
						  SRPT_STATE_DATA_IN);
		BUG_ON(!res);
		WARN_ON_ONCE(!scst_cmd_get_tgt_data_buff_alloced(cmd));
		if (cmd->tgt_i_data_buf_alloced && cmd->dh_data_buf_alloced &&
		    scst_cmd_get_data_direction(cmd) & SCST_DATA_WRITE) {
			scst_copy_sg(cmd, SCST_SG_COPY_FROM_TARGET);
		}
		scst_rx_data(cmd, SCST_RX_STATUS_SUCCESS,
			     in_irq() ? SCST_CONTEXT_TASKLET :
			     in_softirq() ? SCST_CONTEXT_DIRECT_ATOMIC :
			     SCST_CONTEXT_DIRECT);
		ret = 0;
		goto out;
	}

	ret = srpt_map_sg_to_ib_sge(ch, ioctx, cmd);
	if (ret) {
		pr_err("%s srpt_map_sg_to_ib_sge() ret=%d\n", __func__, ret);
		ret = -EAGAIN;
		goto out;
	}

	ret = srpt_perform_rdmas(ch, ioctx, scst_cmd_get_data_direction(cmd));
	if (ret) {
		if (ret == -EAGAIN || ret == -ENOMEM) {
			pr_info("%s: queue full -- ret=%d\n", __func__, ret);
			ret = -EAGAIN;
		} else {
			pr_err("%s: fatal error -- ret=%d\n", __func__, ret);
			ret = -EIO;
		}
		goto out_unmap;
	}

	ret = 0;

out:
	return ret;
out_unmap:
	srpt_unmap_sg_to_ib_sge(ch, ioctx);
	goto out;
}

/*
 * srpt_pending_cmd_timeout() - SCST command HCA processing timeout callback.
 *
 * Called by the SCST core if no IB completion notification has been received
 * within RDMA_COMPL_TIMEOUT_S seconds.
 */
static void srpt_pending_cmd_timeout(struct scst_cmd *cmd)
{
	struct srpt_send_ioctx *ioctx;
	enum srpt_command_state state;

	ioctx = scst_cmd_get_tgt_priv(cmd);
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
		pr_err("Processing SCST command %p (SRPT state %d) took too long -- aborting\n",
		       cmd, state);
		break;
	case SRPT_STATE_NEED_DATA:
	case SRPT_STATE_CMD_RSP_SENT:
	case SRPT_STATE_MGMT_RSP_SENT:
	default:
		pr_err("Command %p: IB completion for idx %u has not been received in time (SRPT command state %d)\n",
		       cmd, ioctx->ioctx.index, state);
		break;
	}

	srpt_abort_cmd(ioctx, SCST_CONTEXT_SAME);
}

/*
 * srpt_rdy_to_xfer() - Transfers data from initiator to target.
 *
 * Called by the SCST core to transfer data from the initiator to the target
 * (SCST_DATA_WRITE). Must not block.
 */
static int srpt_rdy_to_xfer(struct scst_cmd *cmd)
{
	struct srpt_send_ioctx *ioctx = scst_cmd_get_tgt_priv(cmd);
	enum srpt_command_state prev_cmd_state;
	int ret;

	prev_cmd_state = srpt_set_cmd_state(ioctx, SRPT_STATE_NEED_DATA);
	ret = srpt_xfer_data(ioctx->ch, ioctx);

	switch (ret) {
	case 0:
		return SCST_TGT_RES_SUCCESS;
	case -EAGAIN:
		srpt_set_cmd_state(ioctx, prev_cmd_state);
		return SCST_TGT_RES_QUEUE_FULL;
	default:
		srpt_set_cmd_state(ioctx, prev_cmd_state);
		return SCST_TGT_RES_FATAL_ERROR;
	}
}

/*
 * srpt_xmit_response() - Transmits the response to a SCSI command.
 *
 * Callback function called by the SCST core. Must not block. Must ensure that
 * scst_tgt_cmd_done() will get invoked when returning SCST_TGT_RES_SUCCESS.
 */
static int srpt_xmit_response(struct scst_cmd *cmd)
{
	struct srpt_rdma_ch *ch;
	struct srpt_send_ioctx *ioctx;
	enum srpt_command_state state;
	int ret;
	scst_data_direction dir;
	int resp_len;

	ret = SCST_TGT_RES_SUCCESS;

	ioctx = scst_cmd_get_tgt_priv(cmd);
	BUG_ON(!ioctx);

	ch = scst_sess_get_tgt_priv(scst_cmd_get_session(cmd));
	BUG_ON(!ch);

	state = ioctx->state;
	switch (state) {
	case SRPT_STATE_NEW:
	case SRPT_STATE_DATA_IN:
		ioctx->state = SRPT_STATE_CMD_RSP_SENT;
		break;
	default:
		WARN(true, "Unexpected command state %d\n", state);
		break;
	}

	if (unlikely(scst_cmd_aborted_on_xmit(cmd))) {
		srpt_adjust_req_lim(ch, 0, 1);
		srpt_abort_cmd(ioctx, SCST_CONTEXT_SAME);
		goto out;
	}

	EXTRACHECKS_BUG_ON(scst_cmd_atomic(cmd));

	dir = scst_cmd_get_data_direction(cmd);

	if (cmd->tgt_i_data_buf_alloced && cmd->dh_data_buf_alloced &&
	    dir & SCST_DATA_READ)
		scst_copy_sg(cmd, SCST_SG_COPY_TO_TARGET);

	/* For read commands, transfer the data to the initiator. */
	if (dir == SCST_DATA_READ
	    && scst_cmd_get_adjusted_resp_data_len(cmd)) {
		ret = srpt_xfer_data(ch, ioctx);
		if (unlikely(ret != 0)) {
			srpt_set_cmd_state(ioctx, state);
			pr_warn("xfer_data failed for tag %llu - %s\n",
				scst_cmd_get_tag(cmd),
				ret == -EAGAIN ? "retrying" :
				"failing");
			switch (ret) {
			case -EAGAIN:
				ret = SCST_TGT_RES_QUEUE_FULL;
				break;
			default:
				WARN_ONCE(true,
					  "srpt_xfer_data() returned %d\n",
					  ret);
				fallthrough;
			case -EIO:
				ret = SCST_TGT_RES_FATAL_ERROR;
				break;
			}
			goto out;
		}
	}

	ioctx->req_lim_delta = srpt_inc_req_lim(ch);
	resp_len = srpt_build_cmd_rsp(ch, ioctx,
				      scst_cmd_get_tag(cmd),
				      scst_cmd_get_status(cmd),
				      scst_cmd_get_sense_buffer(cmd),
				      scst_cmd_get_sense_buffer_len(cmd));

	if (srpt_post_send(ch, ioctx, resp_len)) {
		srpt_unmap_sg_to_ib_sge(ch, ioctx);
		srpt_set_cmd_state(ioctx, state);
		srpt_undo_inc_req_lim(ch, ioctx->req_lim_delta);
		pr_warn("sending response failed for tag %llu - retrying\n",
			scst_cmd_get_tag(cmd));
		ret = SCST_TGT_RES_QUEUE_FULL;
	}

out:
	return ret;
}

/*
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

	pr_debug("tsk_mgmt_done for tag= %lld status=%d\n", ioctx->tsk_mgmt.tag,
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
		pr_err("Sending SRP_RSP response failed.\n");
		srpt_put_send_ioctx(ioctx);
		srpt_undo_inc_req_lim(ch, ioctx->req_lim_delta);
	}
}

/*
 * srpt_get_initiator_port_transport_id() - SCST TransportID callback function.
 *
 * See also SPC-3, section 7.5.4.5, TransportID for initiator ports using SRP.
 */
static int srpt_get_initiator_port_transport_id(struct scst_tgt *tgt,
	struct scst_session *sess, uint8_t **transport_id)
{
	struct srpt_rdma_ch *ch;
	struct spc_rdma_transport_id {
		uint8_t protocol_identifier;
		uint8_t reserved[7];
		uint8_t i_port_id[16];
	};
	struct spc_rdma_transport_id *tr_id;
	int res = SCSI_TRANSPORTID_PROTOCOLID_SRP;

	if (!sess)
		goto out;

	ch = scst_sess_get_tgt_priv(sess);
	BUG_ON(!ch);

	BUILD_BUG_ON(sizeof(*tr_id) != 24);

	res = -ENOMEM;
	tr_id = kzalloc(sizeof(struct spc_rdma_transport_id), GFP_KERNEL);
	if (!tr_id)
		goto out;

	res = 0;
	tr_id->protocol_identifier = SCSI_TRANSPORTID_PROTOCOLID_SRP;
	memcpy(tr_id->i_port_id, ch->nexus->i_port_id,
	       sizeof(tr_id->i_port_id));

	*transport_id = (uint8_t *)tr_id;

out:
	return res;
}

/*
 * srpt_on_free_cmd() - Free command-private data.
 *
 * Called by the SCST core. May be called in IRQ context.
 */
static void srpt_on_free_cmd(struct scst_cmd *cmd)
{
	struct srpt_send_ioctx *ioctx;

	ioctx = scst_cmd_get_tgt_priv(cmd);
	srpt_put_send_ioctx(ioctx);
}

static void srpt_refresh_port_work(struct work_struct *work)
{
	struct srpt_port *sport = container_of(work, struct srpt_port, work);

	srpt_refresh_port(sport);
}

static int srpt_close_session(struct scst_session *sess)
{
	struct srpt_rdma_ch *ch = scst_sess_get_tgt_priv(sess);
	struct srpt_port *sport = ch->sport;

	mutex_lock(&sport->mutex);
	srpt_disconnect_ch(ch);
	mutex_unlock(&sport->mutex);

	return 0;
}

static bool srpt_ch_list_empty(struct srpt_port *sport)
{
	struct srpt_nexus *nexus;
	bool res = true;

	rcu_read_lock();
	list_for_each_entry_rcu(nexus, &sport->nexus_list, entry)
		if (!list_empty(&nexus->ch_list))
			res = false;
	rcu_read_unlock();

	return res;
}

/**
 * srpt_release_sport - disable login and wait for associated channels
 * @sport: SRPT HCA port.
 */
static int srpt_release_sport(struct srpt_port *sport)
{
	struct srpt_nexus *nexus, *next_n;
	struct srpt_rdma_ch *ch;

	WARN_ON_ONCE(irqs_disabled());

	/* Disallow new logins and close all active sessions. */
	mutex_lock(&sport->mutex);
	sport->enabled = false;
	__srpt_close_all_ch(sport);
	mutex_unlock(&sport->mutex);

	while (wait_event_timeout(sport->ch_releaseQ,
				  srpt_ch_list_empty(sport), 5 * HZ) <= 0) {
		pr_info("%s: waiting for session unregistration ...\n",
			sport->scst_tgt->tgt_name);
		rcu_read_lock();
		list_for_each_entry_rcu(nexus, &sport->nexus_list, entry) {
			list_for_each_entry(ch, &nexus->ch_list, list) {
				pr_info("%s-%d: state %s; %d commands in progress\n",
					ch->sess_name, ch->qp->qp_num,
					get_ch_state_name(ch->state),
					atomic_read(&ch->sess->sess_cmd_count));
			}
		}
		rcu_read_unlock();
	}

	mutex_lock(&sport->mutex);
	list_for_each_entry_safe(nexus, next_n, &sport->nexus_list, entry) {
		list_del_rcu(&nexus->entry);
		kfree_rcu(nexus, rcu);
	}
	mutex_unlock(&sport->mutex);

	return 0;
}

/*
 * srpt_release() - Free the resources associated with an SCST target.
 *
 * Callback function called by the SCST core from scst_unregister_target().
 */
static int srpt_release(struct scst_tgt *scst_tgt)
{
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);

	EXTRACHECKS_WARN_ON_ONCE(irqs_disabled());

	BUG_ON(!scst_tgt);
	BUG_ON(!sport);

	srpt_release_sport(sport);

	scst_tgt_set_tgt_priv(scst_tgt, NULL);

	return 0;
}

/*
 * srpt_get_scsi_transport_version() - Returns the SCSI transport version.
 * This function is called from scst_pres.c, the code that implements
 * persistent reservation support.
 */
static uint16_t srpt_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	return 0x0940; /* SRP */
}

static ssize_t show_comp_v_mask(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	int res = -E_TGT_PRIV_NOT_YET_SET;

	if (!sport)
		goto out;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	res = cpumask_scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, &sport->comp_v_mask);
#else
	res = sysfs_emit(buf, "%*pb",
			 cpumask_pr_args(&sport->comp_v_mask));
#endif
	res += sysfs_emit_at(buf, res, "\n%s\n", SCST_SYSFS_KEY_MARK);

out:
	return res;
}

static ssize_t store_comp_v_mask(struct kobject *kobj,
				 struct kobj_attribute *attr, const char *buf,
				 size_t count)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	struct srpt_device *sdev;
	int res = -E_TGT_PRIV_NOT_YET_SET;
	cpumask_var_t mask;
	unsigned int i1, i2;

	if (!sport)
		goto out;
	sdev = sport->sdev;
	res = -ENOMEM;
	if (!alloc_cpumask_var(&mask, GFP_KERNEL))
		goto out;
	res = cpumask_parse(buf, mask);
	if (res)
		goto free_mask;
	res = -EINVAL;
	i1 = cpumask_next(-1, mask);
	i2 = cpumask_next(sdev->device->num_comp_vectors - 1, mask);
	if (i1 >= nr_cpu_ids ||
	    (i2 >= sdev->device->num_comp_vectors && i2 < nr_cpu_ids))
		goto free_mask;
	cpumask_copy(&sport->comp_v_mask, mask);
	res = count;

free_mask:
	free_cpumask_var(mask);
out:
	return res;
}

static struct kobj_attribute srpt_show_comp_v_mask_attr =
	__ATTR(comp_v_mask, S_IRUGO | S_IWUSR, show_comp_v_mask,
	       store_comp_v_mask);

static ssize_t srpt_show_device(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	struct srpt_device *sdev;
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	if (!sport)
		goto out;

	sdev = sport->sdev;
	res = sysfs_emit(buf, "%s\n", dev_name(&sdev->device->dev));

out:
	return res;
}

static struct kobj_attribute srpt_device_attr =
	__ATTR(device, S_IRUGO, srpt_show_device, NULL);

/*
 * The link layer names in this function match those used by the IB core.
 * See also link_layer_show() in drivers/infiniband/core/sysfs.c
 */
static ssize_t srpt_show_link_layer(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	const char *lln = "Unknown";
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	if (!sport)
		goto out;

	switch (rdma_port_get_link_layer(sport->sdev->device, sport->port)) {
	case IB_LINK_LAYER_INFINIBAND:
		lln = "InfiniBand";
		break;
	case IB_LINK_LAYER_ETHERNET:
		lln = "Ethernet";
		break;
	case IB_LINK_LAYER_UNSPECIFIED:
	default:
		break;
	}
	res = sysfs_emit(buf, "%s\n", lln);

out:
	return res;
}

static struct kobj_attribute srpt_link_layer_attr =
	__ATTR(link_layer, S_IRUGO, srpt_show_link_layer, NULL);

static ssize_t show_port_id(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	if (!sport)
		goto out;

	mutex_lock(&sport->mutex);

	res = sysfs_emit(buf, "%s\n", sport->port_id);

	if (strcmp(sport->port_id, DEFAULT_SRPT_ID_STRING))
		res += sysfs_emit_at(buf, res, "%s\n", SCST_SYSFS_KEY_MARK);

	mutex_unlock(&sport->mutex);

out:
	return res;
}

static ssize_t store_port_id(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	const char *end;
	int res = -E_TGT_PRIV_NOT_YET_SET;

	if (!sport)
		goto out;

	end = buf + count;
	while (end > buf && isspace(((unsigned char *)end)[-1]))
		--end;
	res = -E2BIG;
	if (end - buf >= sizeof(sport->port_id))
		goto out;

	mutex_lock(&sport->mutex);
	sprintf(sport->port_id, "%.*s", (int)(end - buf), buf);
	mutex_unlock(&sport->mutex);

	res = count;

out:
	return res;
}

static struct kobj_attribute srpt_port_id_attr =
	__ATTR(port_id, S_IRUGO | S_IWUSR, show_port_id, store_port_id);

static ssize_t show_login_info(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt = container_of(kobj, struct scst_tgt,
						 tgt_kobj);
	struct srpt_port *sport = scst_tgt_get_tgt_priv(scst_tgt);
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	if (!sport)
		goto out;

	res = sysfs_emit(buf,
			 "tid_ext=%016llx,ioc_guid=%016llx,pkey=ffff,dgid=%04x%04x%04x%04x%04x%04x%04x%04x,service_id=%016llx\n",
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

out:
	return res;
}

static struct kobj_attribute srpt_show_login_info_attr =
	__ATTR(login_info, S_IRUGO, show_login_info, NULL);

static const struct attribute *srpt_tgt_attrs[] = {
	&srpt_show_comp_v_mask_attr.attr,
	&srpt_device_attr.attr,
	&srpt_link_layer_attr.attr,
	&srpt_port_id_attr.attr,
	&srpt_show_login_info_attr.attr,
	NULL
};

static ssize_t show_req_lim(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;
	struct srpt_rdma_ch *ch;

	sess = container_of(kobj, struct scst_session, sess_kobj);
	ch = scst_sess_get_tgt_priv(sess);
	if (!ch)
		return -ENOENT;

	return sysfs_emit(buf, "%d\n", ch->req_lim);
}

static ssize_t show_req_lim_delta(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;
	struct srpt_rdma_ch *ch;

	sess = container_of(kobj, struct scst_session, sess_kobj);
	ch = scst_sess_get_tgt_priv(sess);
	if (!ch)
		return -ENOENT;

	return sysfs_emit(buf, "%d\n", ch->req_lim_delta);
}

static ssize_t show_ch_state(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct scst_session *sess;
	struct srpt_rdma_ch *ch;

	sess = container_of(kobj, struct scst_session, sess_kobj);
	ch = scst_sess_get_tgt_priv(sess);
	if (!ch)
		return -ENOENT;

	return sysfs_emit(buf, "%s\n", get_ch_state_name(ch->state));
}

static ssize_t show_comp_vector(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;
	struct srpt_rdma_ch *ch;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	ch = scst_sess_get_tgt_priv(sess);
	if (!ch)
		return -ENOENT;

	return sysfs_emit(buf, "%u\n", ch->comp_vector);
}

static const struct kobj_attribute srpt_req_lim_attr =
	__ATTR(req_lim,       S_IRUGO, show_req_lim,       NULL);
static const struct kobj_attribute srpt_req_lim_delta_attr =
	__ATTR(req_lim_delta, S_IRUGO, show_req_lim_delta, NULL);
static const struct kobj_attribute srpt_ch_state_attr =
	__ATTR(ch_state, S_IRUGO, show_ch_state, NULL);
static const struct kobj_attribute srpt_comp_vector_attr =
	__ATTR(comp_vector, S_IRUGO, show_comp_vector, NULL);

static const struct attribute *srpt_sess_attrs[] = {
	&srpt_req_lim_attr.attr,
	&srpt_req_lim_delta_attr.attr,
	&srpt_ch_state_attr.attr,
	&srpt_comp_vector_attr.attr,
	NULL
};

/* SCST target template for the SRP target implementation. */
static struct scst_tgt_template srpt_template = {
	.name				 = DRV_NAME,
	.sg_tablesize			 = 1 << 16,
	.use_clustering			 = true,
	.max_hw_pending_time		 = RDMA_COMPL_TIMEOUT_S,
	.enable_target			 = srpt_enable_target,
	.is_target_enabled		 = srpt_is_target_enabled,
	.tgt_attrs			 = srpt_tgt_attrs,
	.sess_attrs			 = srpt_sess_attrs,
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


/* Note: the caller must have zero-initialized *@sport. */
static void srpt_init_sport(struct srpt_port *sport, struct ib_device *ib_dev)
{
	int i;

	INIT_LIST_HEAD(&sport->nexus_list);
	init_waitqueue_head(&sport->ch_releaseQ);
	mutex_init(&sport->mutex);
	strscpy(sport->port_id, DEFAULT_SRPT_ID_STRING,
		sizeof(sport->port_id));
	for (i = 0; i < ib_dev->num_comp_vectors; i++)
		cpumask_set_cpu(i, &sport->comp_v_mask);
}

/*
 * srpt_add_one() - Infiniband device addition callback function.
 */
static int srpt_add_one(struct ib_device *device)
{
	struct ib_cm_id *cm_id;
	struct srpt_device *sdev;
	struct srpt_port *sport;
	struct ib_srq_init_attr srq_attr;
	int i, ret;

	pr_debug("device = %p\n", device);

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev) {
		ret = -ENOMEM;
		goto err;
	}

	sdev->device = device;

#ifdef HAVE_IB_QUERY_DEVICE
	ret = ib_query_device(device, &sdev->dev_attr);
	if (ret) {
		pr_err("ib_query_device() failed: %d\n", ret);
		goto free_dev;
	}
#else
	sdev->dev_attr = device->attrs;
#endif

	sdev->pd = ib_alloc_pd(device, 0);
	if (IS_ERR(sdev->pd)) {
		ret = PTR_ERR(sdev->pd);
		pr_err("ib_alloc_pd() failed: %d\n", ret);
		goto free_dev;
	}

#ifndef IB_PD_HAS_LOCAL_DMA_LKEY
	sdev->mr = ib_get_dma_mr(sdev->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(sdev->mr)) {
		ret = PTR_ERR(sdev->mr);
		pr_err("ib_get_dma_mr() failed: %ld\n", PTR_ERR(sdev->mr));
		goto err_pd;
	}
	sdev->lkey = sdev->mr->lkey;
#else
	sdev->lkey = sdev->pd->local_dma_lkey;
#endif

	sdev->srq_size = min(max(srpt_srq_size, MIN_SRPT_SRQ_SIZE),
			     sdev->dev_attr.max_srq_wr);

	memset(&srq_attr, 0, sizeof(srq_attr));
	srq_attr.event_handler = srpt_srq_event;
	srq_attr.srq_context = (void *)sdev;
	srq_attr.attr.max_wr = sdev->srq_size;
	srq_attr.attr.max_sge = 1;
	srq_attr.attr.srq_limit = 0;
	srq_attr.srq_type = IB_SRQT_BASIC;

	sdev->srq = use_srq ? ib_create_srq(sdev->pd, &srq_attr) :
		ERR_PTR(-EOPNOTSUPP);
	if (IS_ERR(sdev->srq)) {
		if (use_srq)
			pr_debug("ib_create_srq() failed: %ld\n",
				 PTR_ERR(sdev->srq));

		/* SRQ disabled or not supported. */
		sdev->use_srq = false;
	} else {
		pr_debug("create SRQ #wr= %d max_allow=%d dev= %s\n",
			 sdev->srq_size, sdev->dev_attr.max_srq_wr,
			 device->name);

		sdev->req_buf_cache = kmem_cache_create("srpt-srq-req-buf",
						srp_max_req_size, 0, 0, NULL);
		if (!sdev->req_buf_cache) {
			ret = -ENOMEM;
			goto free_srq;
		}

		sdev->ioctx_ring = (struct srpt_recv_ioctx **)
			srpt_alloc_ioctx_ring(sdev, sdev->srq_size,
					      sizeof(*sdev->ioctx_ring[0]),
					      sdev->req_buf_cache,
					      0, DMA_FROM_DEVICE);
		if (!sdev->ioctx_ring) {
			ret = -ENOMEM;
			pr_err("srpt_alloc_ioctx_ring() failed\n");
			goto free_cache;
		}

		sdev->use_srq = true;

		for (i = 0; i < sdev->srq_size; ++i) {
			INIT_LIST_HEAD(&sdev->ioctx_ring[i]->wait_list);
			srpt_post_recv(sdev, NULL, sdev->ioctx_ring[i]);
		}
	}

	WARN_ON(sdev->device->phys_port_cnt > ARRAY_SIZE(sdev->port));

	for (i = 1; i <= sdev->device->phys_port_cnt; i++) {
		sport = &sdev->port[i - 1];
		sport->sdev = sdev;
		sport->port = i;
		srpt_init_sport(sport, sdev->device);
		INIT_WORK(&sport->work, srpt_refresh_port_work);
		ret = srpt_refresh_port(sport);
		if (ret) {
			pr_err("MAD registration failed for %s-%d.\n",
			       dev_name(&sdev->device->dev), i);
			goto err_ring;
		}
	}

	if (!srpt_service_guid)
		srpt_service_guid = be64_to_cpu(device->node_guid) &
			~be64_to_cpu(IB_SERVICE_ID_AGN_MASK);

	cm_id = ib_create_cm_id(device, srpt_cm_handler, sdev);
	if (IS_ERR(cm_id)) {
		ret = PTR_ERR(cm_id);
		pr_err("ib_create_cm_id() failed: %d\n", ret);
		goto err_ring;
	}
	sdev->cm_id = cm_id;

	/* print out target login information */
	pr_debug("Target login info: id_ext=%016llx,ioc_guid=%016llx,pkey=ffff,service_id=%016llx\n",
		 srpt_service_guid, srpt_service_guid, srpt_service_guid);

	/*
	 * We do not have a consistent service_id (ie. also id_ext of target_id)
	 * to identify this target. We currently use the guid of the first HCA
	 * in the system as service_id; therefore, the target_id will change
	 * if this HCA is gone bad and replaced by different HCA
	 */
	ret = ib_cm_listen(sdev->cm_id, cpu_to_be64(srpt_service_guid)
#ifdef IB_CM_LISTEN_TAKES_FOURTH_ARG
			   , 0
			   , NULL
#elif defined(IB_CM_LISTEN_TAKES_THIRD_ARG)
			   , 0
#endif
			   );
	if (ret) {
		pr_err("ib_cm_listen() failed: %d (cm_id state = %d)\n", ret,
		       sdev->cm_id->state);
		goto err_cm;
	}

	INIT_IB_EVENT_HANDLER(&sdev->event_handler, sdev->device,
			      srpt_event_handler);
	ib_register_event_handler(&sdev->event_handler);
	atomic_inc(&srpt_device_count);
	ret = 0;
out:
	ib_set_client_data(device, &srpt_client, sdev);

	return ret;

err_cm:
	ib_destroy_cm_id(sdev->cm_id);
err_ring:
	srpt_free_ioctx_ring((struct srpt_ioctx **)sdev->ioctx_ring, sdev,
			     sdev->srq_size, sdev->req_buf_cache,
			     DMA_FROM_DEVICE);
free_cache:
	kmem_cache_destroy(sdev->req_buf_cache);

free_srq:
	if (sdev->use_srq)
		ib_destroy_srq(sdev->srq);

#ifndef IB_PD_HAS_LOCAL_DMA_LKEY
	ib_dereg_mr(sdev->mr);
err_pd:
#endif
	ib_dealloc_pd(sdev->pd);
free_dev:
	kfree(sdev);
err:
	sdev = NULL;
	pr_info("%s(%s) failed.\n", __func__, device->name);
	goto out;
}

#if !IB_CLIENT_ADD_ONE_RETURNS_INT
static void srpt_add_one_void(struct ib_device *device)
{
	srpt_add_one(device);
}
#endif

/*
 * srpt_remove_one() - InfiniBand device removal callback function.
 */
#ifndef IB_CLIENT_REMOVE_TAKES_TWO_ARGS
static void srpt_remove_one(struct ib_device *device)
{
	void *client_data = ib_get_client_data(device, &srpt_client);
#else
static void srpt_remove_one(struct ib_device *device, void *client_data)
{
#endif
	struct srpt_device *sdev;
	int i;

	sdev = client_data;
	if (!sdev) {
		pr_info("%s(%s): nothing to do.\n", __func__, device->name);
		return;
	}

	srpt_unregister_mad_agent(sdev);

	ib_unregister_event_handler(&sdev->event_handler);

	/* Cancel any work queued by the just unregistered IB event handler. */
	for (i = 0; i < sdev->device->phys_port_cnt; i++)
		cancel_work_sync(&sdev->port[i].work);

	ib_destroy_cm_id(sdev->cm_id);

	ib_set_client_data(device, &srpt_client, NULL);

	/*
	 * SCST target unregistration must happen after sdev->cm_id has been
	 * destroyed and after the client data has been reset such that no new
	 * SRP_LOGIN_REQ information units can arrive while unregistering the
	 * SCST target.
	 */
	for (i = 0; i < sdev->device->phys_port_cnt; i++) {
		struct srpt_port *sport = &sdev->port[i];

		if (sport->scst_tgt) {
			scst_unregister_target(sport->scst_tgt);
			sport->scst_tgt = NULL;
		}
	}

	if (sdev->use_srq)
		ib_destroy_srq(sdev->srq);
	srpt_free_ioctx_ring((struct srpt_ioctx **)sdev->ioctx_ring, sdev,
			     sdev->srq_size, sdev->req_buf_cache,
			     DMA_FROM_DEVICE);
	kmem_cache_destroy(sdev->req_buf_cache);
#ifndef IB_PD_HAS_LOCAL_DMA_LKEY
	ib_dereg_mr(sdev->mr);
#endif
	ib_dealloc_pd(sdev->pd);

	kfree(sdev);
}

static struct ib_client srpt_client = {
	.name = DRV_NAME,
#if IB_CLIENT_ADD_ONE_RETURNS_INT
	.add = srpt_add_one,
#else
	.add = srpt_add_one_void,
#endif
	.remove = srpt_remove_one
};


/**
 * srpt_init_module - kernel module initialization
 *
 * Note: Since ib_register_client() registers callback functions, and since at
 * least one of these callback functions (srpt_add_one()) calls target core
 * functions, this driver must be registered with the target core before
 * ib_register_client() is called.
 */
static int __init srpt_init_module(void)
{
	int ret;

	ret = -EINVAL;
	if (srp_max_req_size < MIN_MAX_REQ_SIZE) {
		pr_err("invalid value %d for kernel module parameter srp_max_req_size -- must be at least %d.\n",
		       srp_max_req_size, MIN_MAX_REQ_SIZE);
		goto out;
	}

	if (srp_max_rsp_size < MIN_MAX_RSP_SIZE) {
		pr_err("invalid value %d for kernel module parameter srp_max_rsp_size -- must be at least %d.\n",
		       srp_max_rsp_size, MIN_MAX_RSP_SIZE);
		goto out;
	}

	if (srpt_srq_size < MIN_SRPT_SRQ_SIZE
	    || srpt_srq_size > MAX_SRPT_SRQ_SIZE) {
		pr_err("invalid value %d for kernel module parameter srpt_srq_size -- must be in the range [%d..%d].\n",
		       srpt_srq_size, MIN_SRPT_SRQ_SIZE, MAX_SRPT_SRQ_SIZE);
		goto out;
	}

	if (srpt_sq_size < MIN_SRPT_SQ_SIZE) {
		pr_err("invalid value %d for kernel module parameter srpt_sq_size -- must be at least %d.\n",
		       srpt_sq_size, MIN_SRPT_SQ_SIZE);
		goto out;
	}

	ret = scst_register_target_template(&srpt_template);
	if (ret < 0) {
		pr_err("couldn't register target template\n");
		ret = -ENODEV;
		goto out;
	}

	srpt_wq = alloc_workqueue("srpt", WQ_SYSFS, 0);
	if (!srpt_wq) {
		pr_err("Couldn't allocate the ib_srpt workqueue\n");
		ret = -ENOMEM;
		goto out_unregister_target;
	}

	ret = ib_register_client(&srpt_client);
	if (ret) {
		pr_err("couldn't register IB client\n");
		goto destroy_wq;
	}

	srpt_net_ns = kobj_ns_grab_current(KOBJ_NS_TYPE_NET);

	if (rdma_cm_port) {
		struct sockaddr_in addr;

#if !RDMA_CREATE_ID_TAKES_NET_ARG
		rdma_cm_id = rdma_create_id(srpt_rdma_cm_handler, NULL,
					    RDMA_PS_TCP, IB_QPT_RC);
#else
		rdma_cm_id = rdma_create_id(srpt_net_ns, srpt_rdma_cm_handler,
					    NULL, RDMA_PS_TCP, IB_QPT_RC);
#endif
		if (IS_ERR(rdma_cm_id)) {
			ret = PTR_ERR(rdma_cm_id);
			rdma_cm_id = NULL;
			pr_err("RDMA/CM ID creation failed\n");
			goto drop_ns;
		}

		/* We will listen on any RDMA device. */
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = cpu_to_be16(rdma_cm_port);
		ret = rdma_bind_addr(rdma_cm_id, (void *)&addr);
		if (ret) {
			pr_err("Binding RDMA/CM ID to port %u failed\n",
			       rdma_cm_port);
			goto destroy_id;
		}

		ret = rdma_listen(rdma_cm_id, 128);
		if (ret) {
			pr_err("rdma_listen() failed\n");
			goto destroy_id;
		}
	}

	return 0;

destroy_id:
	if (rdma_cm_id)
		rdma_destroy_id(rdma_cm_id);

drop_ns:
	kobj_ns_drop(KOBJ_NS_TYPE_NET, srpt_net_ns);
	srpt_net_ns = NULL;
	ib_unregister_client(&srpt_client);

destroy_wq:
	destroy_workqueue(srpt_wq);

out_unregister_target:
	scst_unregister_target_template(&srpt_template);

out:
	return ret;
}

static void __exit srpt_cleanup_module(void)
{
	if (rdma_cm_id)
		rdma_destroy_id(rdma_cm_id);

	kobj_ns_drop(KOBJ_NS_TYPE_NET, srpt_net_ns);
	srpt_net_ns = NULL;

	ib_unregister_client(&srpt_client);

	destroy_workqueue(srpt_wq);

	rcu_barrier();

	scst_unregister_target_template(&srpt_template);
}

module_init(srpt_init_module);
module_exit(srpt_cleanup_module);
