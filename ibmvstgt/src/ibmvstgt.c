/*
 * IBM eServer i/pSeries Virtual SCSI Target Driver
 * Copyright (C) 2003-2005 Dave Boutcher (boutcher@us.ibm.com) IBM Corp.
 *			   Santiago Leon (santil@us.ibm.com) IBM Corp.
 *			   Linda Xie (lxie@us.ibm.com) IBM Corp.
 *
 * Copyright (C) 2005-2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2010 Bart Van Assche <bvanassche@acm.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/slab.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_debug.h>
#else
#include "scst.h"
#include "scst_debug.h"
#endif
#if defined(INSIDE_KERNEL_TREE)
#include <scsi/libsrp.h>
#else
#include "libsrpnew.h"
#endif
#if defined(INSIDE_KERNEL_TREE) || defined(__powerpc__)
#include <asm/hvcall.h>
#endif
#if defined(INSIDE_KERNEL_TREE) || defined(__powerpc__)
#include <asm/iommu.h>
#include <asm/prom.h>
#include <asm/vio.h>
#else
#include <linux/mod_devicetable.h>
#endif
#if defined(INSIDE_KERNEL_TREE) || defined(__powerpc__)
#if !defined(RHEL_MAJOR)
#include <linux/of.h>
#endif
#else
#include "dummy_powerpc_defs.h"
#endif

#include "ibmvscsi.h"

#define	VSCSI_REQ_LIM		16
#define	MAD_REQ_LIM		1
#define	SRP_REQ_LIM		(VSCSI_REQ_LIM - MAD_REQ_LIM)
/* Minimal trfr size that must be supported by a PAPR-compliant hypervisor. */
#define	MAX_H_COPY_RDMA		(128*1024)

#define	TGT_NAME	"ibmvstgt"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
/* Force a compilation error if a constant expression is not a power of 2 */
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#endif
/*
 * Hypervisor calls.
 */
#define h_send_crq(ua, l, h) \
			plpar_hcall_norets(H_SEND_CRQ, ua, l, h)
#define h_reg_crq(ua, tok, sz)\
			plpar_hcall_norets(H_REG_CRQ, ua, tok, sz);
#define h_free_crq(ua) \
			plpar_hcall_norets(H_FREE_CRQ, ua);

/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	pr_err("%s(%d) " fmt, __func__, __LINE__, ##args);	\
} while (0)
/* #define dprintk eprintk */
#define dprintk(fmt, args...)

/* iu_entry.flags */
enum iue_flags {
	V_DIOVER,
	V_WRITE,
	V_LINKED,
};

struct vio_port {
	struct vio_dev *dma_dev;

	struct crq_queue crq_queue;
	struct work_struct crq_work;

	atomic_t req_lim_delta;
	unsigned long liobn;
	unsigned long riobn;
	struct srp_target *target;

	struct scst_session *sess;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	struct class_device dev;
#else
	struct device dev;
#endif
	bool releasing;
	bool enabled;
};

static atomic_t ibmvstgt_device_count;
static struct workqueue_struct *vtgtd;
static unsigned max_vdma_size = MAX_H_COPY_RDMA;
static struct scst_tgt_template ibmvstgt_template;

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define DEFAULT_IBMVSTGT_TRACE_FLAGS \
	(TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_MGMT | TRACE_SPECIAL)
static unsigned long trace_flag = DEFAULT_IBMVSTGT_TRACE_FLAGS;
module_param(trace_flag, long, 0644);
MODULE_PARM_DESC(trace_flag, "SCST trace flags.");
#endif

/*
 * These are fixed for the system and come from the Open Firmware device tree.
 * We just store them here to save getting them every time.
 */
static char system_id[64] = "";
static char partition_name[97] = "UNKNOWN";
static unsigned int partition_number = -1;

static long h_copy_rdma(u64 length, unsigned long siobn, dma_addr_t saddr,
			unsigned long diobn, dma_addr_t daddr)
{
	u64 bytes_copied = 0;
	long rc;

	while (bytes_copied < length) {
		u64 bytes_to_copy;

		bytes_to_copy = min_t(u64, length - bytes_copied,
				      max_vdma_size);
		rc = plpar_hcall_norets(H_COPY_RDMA, bytes_to_copy, siobn,
					saddr, diobn, daddr);
		if (rc != H_SUCCESS)
			return rc;

		bytes_copied += bytes_to_copy;
		saddr += bytes_to_copy;
		daddr += bytes_to_copy;
	}
	return H_SUCCESS;
}

static struct vio_port *target_to_port(struct srp_target *target)
{
	return (struct vio_port *) target->ldata;
}

static inline union viosrp_iu *vio_iu(struct iu_entry *iue)
{
	return (union viosrp_iu *) (iue->sbuf->buf);
}

static int send_iu(struct iu_entry *iue, uint64_t length, uint8_t format)
{
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	long rc, rc1;
	union {
		struct viosrp_crq cooked;
		uint64_t raw[2];
	} crq;

	/* First copy the SRP */
	rc = h_copy_rdma(length, vport->liobn, iue->sbuf->dma,
			 vport->riobn, iue->remote_token);

	if (rc)
		eprintk("Error %ld transferring data\n", rc);

	crq.cooked.valid = 0x80;
	crq.cooked.format = format;
	crq.cooked.reserved = 0x00;
	crq.cooked.timeout = 0x00;
	crq.cooked.IU_length = length;
	crq.cooked.IU_data_ptr = vio_iu(iue)->srp.rsp.tag;

	if (rc == 0)
		crq.cooked.status = 0x99;	/* Just needs to be non-zero */
	else
		crq.cooked.status = 0x00;

	srp_iu_put(iue);

	rc1 = h_send_crq(vport->dma_dev->unit_address, crq.raw[0], crq.raw[1]);

	if (rc1) {
		eprintk("%ld sending response\n", rc1);
		return rc1;
	}

	return rc;
}

#define SRP_RSP_SENSE_DATA_LEN	18

static int send_rsp(struct iu_entry *iue, struct scst_cmd *sc,
		    unsigned char status, unsigned char asc)
{
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	union viosrp_iu *iu = vio_iu(iue);
	uint64_t tag = iu->srp.rsp.tag;

	/* If the linked bit is on and status is good */
	if (test_bit(V_LINKED, &iue->flags) && (status == NO_SENSE))
		status = 0x10;

	memset(iu, 0, sizeof(struct srp_rsp));
	iu->srp.rsp.opcode = SRP_RSP;
	iu->srp.rsp.req_lim_delta = cpu_to_be32(1
				    + atomic_xchg(&vport->req_lim_delta, 0));
	iu->srp.rsp.tag = tag;

	if (test_bit(V_DIOVER, &iue->flags))
		iu->srp.rsp.flags |= SRP_RSP_FLAG_DIOVER;

	iu->srp.rsp.data_in_res_cnt = 0;
	iu->srp.rsp.data_out_res_cnt = 0;

	iu->srp.rsp.flags &= ~SRP_RSP_FLAG_RSPVALID;

	iu->srp.rsp.resp_data_len = 0;
	iu->srp.rsp.status = status;
	if (status) {
		uint8_t *sense = iu->srp.rsp.data;

		if (sc) {
			uint8_t *sc_sense;
			int sense_data_len;

			sc_sense = scst_cmd_get_sense_buffer(sc);
			if (scst_sense_valid(sc_sense)) {
				sense_data_len
					= min(scst_cmd_get_sense_buffer_len(sc),
					      SRP_RSP_SENSE_DATA_LEN);
				iu->srp.rsp.flags |= SRP_RSP_FLAG_SNSVALID;
				iu->srp.rsp.sense_data_len
					= cpu_to_be32(sense_data_len);
				memcpy(sense, sc_sense, sense_data_len);
			}
		} else {
			iu->srp.rsp.status = SAM_STAT_CHECK_CONDITION;
			iu->srp.rsp.flags |= SRP_RSP_FLAG_SNSVALID;
			iu->srp.rsp.sense_data_len
			      = cpu_to_be32(SRP_RSP_SENSE_DATA_LEN);

			/* Valid bit and 'current errors' */
			sense[0] = (0x1 << 7 | 0x70);
			/* Sense key */
			sense[2] = status;
			/* Additional sense length */
			sense[7] = 0xa;	/* 10 bytes */
			/* Additional sense code */
			sense[12] = asc;
		}
	}

	send_iu(iue, sizeof(iu->srp.rsp) + SRP_RSP_SENSE_DATA_LEN,
		VIOSRP_SRP_FORMAT);

	return 0;
}

static int ibmvstgt_rdma(struct scst_cmd *sc, struct scatterlist *sg, int nsg,
			 struct srp_direct_buf *md, int nmd,
			 enum dma_data_direction dir, unsigned int rest)
{
	struct iu_entry *iue = scst_cmd_get_tgt_priv(sc);
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	dma_addr_t token;
	long err;
	int i, sidx, soff;

	sidx = soff = 0;
	token = sg_dma_address(sg + sidx);

	for (i = 0; i < nmd && rest; i++) {
		unsigned int mdone, mlen;

		mlen = min(rest, be32_to_cpu(md[i].len));
		for (mdone = 0; mlen;) {
			int slen = min(sg_dma_len(sg + sidx) - soff, mlen);

			if (dir == DMA_TO_DEVICE)
				err = h_copy_rdma(slen,
						vport->riobn,
						be64_to_cpu(md[i].va) + mdone,
						vport->liobn,
						token + soff);
			else
				err = h_copy_rdma(slen,
						vport->liobn,
						token + soff,
						vport->riobn,
						be64_to_cpu(md[i].va) + mdone);

			if (err != H_SUCCESS) {
				eprintk("rdma error %d %d %ld\n", dir, slen, err);
				return -EIO;
			}

			mlen -= slen;
			mdone += slen;
			soff += slen;

			if (soff == sg_dma_len(sg + sidx)) {
				sidx++;
				soff = 0;
				token = sg_dma_address(sg + sidx);

				if (sidx > nsg) {
					eprintk("out of sg %p %d %d\n",
						iue, sidx, nsg);
					return -EIO;
				}
			}
		}

		rest -= mlen;
	}
	return 0;
}

#if !defined(CONFIG_SCST_PROC)
/**
 * ibmvstgt_enable_target() - Allows to enable a target via sysfs.
 */
static int ibmvstgt_enable_target(struct scst_tgt *scst_tgt, bool enable)
{
	struct srp_target *target = scst_tgt_get_tgt_priv(scst_tgt);
	struct vio_port *vport;
	unsigned long flags;

	if (!target)
		return -ENOENT;

	vport = target_to_port(target);
	TRACE_DBG("%s target %d", enable ? "Enabling" : "Disabling",
		  vport->dma_dev->unit_address);

	spin_lock_irqsave(&target->lock, flags);
	vport->enabled = enable;
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;
}

/**
 * ibmvstgt_is_target_enabled() - Allows to query a targets status via sysfs.
 */
static bool ibmvstgt_is_target_enabled(struct scst_tgt *scst_tgt)
{
	struct srp_target *target = scst_tgt_get_tgt_priv(scst_tgt);
	struct vio_port *vport;
	unsigned long flags;
	bool res;

	if (!target)
		return false;

	vport = target_to_port(target);
	spin_lock_irqsave(&target->lock, flags);
	res = vport->enabled;
	spin_unlock_irqrestore(&target->lock, flags);
	return res;
}
#else
static bool ibmvstgt_is_target_enabled(struct scst_tgt *scst_tgt)
{
	return true;
}
#endif

/**
 * ibmvstgt_detect() - Returns the number of target adapters.
 *
 * Callback function called by the SCST core.
 */
static int ibmvstgt_detect(struct scst_tgt_template *tp)
{
	return atomic_read(&ibmvstgt_device_count);
}

/**
 * ibmvstgt_release() - Free the resources associated with an SCST target.
 *
 * Callback function called by the SCST core from scst_unregister_target().
 */
static int ibmvstgt_release(struct scst_tgt *scst_tgt)
{
	unsigned long flags;
	struct srp_target *target = scst_tgt_get_tgt_priv(scst_tgt);
	struct vio_port *vport = target_to_port(target);
	struct scst_session *sess = vport->sess;

	spin_lock_irqsave(&target->lock, flags);
	vport->releasing = true;
	spin_unlock_irqrestore(&target->lock, flags);

	if (sess)
		scst_unregister_session(sess, 0, NULL);

	return 0;
}

/**
 * ibmvstgt_xmit_response() - Transmits the response to a SCSI command.
 *
 * Callback function called by the SCST core. Must not block. Must ensure that
 * scst_tgt_cmd_done() will get invoked when returning SCST_TGT_RES_SUCCESS.
 */
static int ibmvstgt_xmit_response(struct scst_cmd *sc)
{
	struct iu_entry *iue = scst_cmd_get_tgt_priv(sc);
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	struct srp_cmd *srp_cmd;
	int ret;
	enum dma_data_direction dir;

	if (unlikely(scst_cmd_aborted_on_xmit(sc))) {
		scst_set_delivery_status(sc, SCST_CMD_DELIVERY_ABORTED);
		atomic_inc(&vport->req_lim_delta);
		srp_iu_put(iue);
		goto out;
	}

	srp_cmd = &vio_iu(iue)->srp.cmd;
	dir = srp_cmd_direction(srp_cmd);
	WARN_ON(dir != DMA_FROM_DEVICE && dir != DMA_TO_DEVICE);

	/* For read commands, transfer the data to the initiator. */
	if (dir == DMA_FROM_DEVICE && scst_cmd_get_adjusted_resp_data_len(sc)) {
		ret = srp_transfer_data(sc, srp_cmd, ibmvstgt_rdma, true, true);
		if (ret == -ENOMEM)
			return SCST_TGT_RES_QUEUE_FULL;
		else if (ret) {
			PRINT_ERROR("%s: tag= %llu xmit_response failed",
				    __func__, (long long unsigned)
				    scst_cmd_get_tag(sc));
			scst_set_delivery_status(sc, SCST_CMD_DELIVERY_FAILED);
		}
	}

	send_rsp(iue, sc, scst_cmd_get_status(sc), 0);

out:
	scst_tgt_cmd_done(sc, SCST_CONTEXT_SAME);

	return SCST_TGT_RES_SUCCESS;
}

/**
 * ibmvstgt_rdy_to_xfer() - Transfers data from initiator to target.
 *
 * Called by the SCST core to transfer data from the initiator to the target
 * (SCST_DATA_WRITE / DMA_TO_DEVICE). Must not block.
 */
static int ibmvstgt_rdy_to_xfer(struct scst_cmd *sc)
{
	struct iu_entry *iue = scst_cmd_get_tgt_priv(sc);
	struct srp_cmd *srp_cmd = &vio_iu(iue)->srp.cmd;
	int ret;

	WARN_ON(srp_cmd_direction(srp_cmd) != DMA_TO_DEVICE);

	/* Transfer the data from the initiator to the target. */
	ret = srp_transfer_data(sc, srp_cmd, ibmvstgt_rdma, true, true);
	if (ret == 0)
		scst_rx_data(sc, SCST_RX_STATUS_SUCCESS, SCST_CONTEXT_SAME);
	else if (ret == -ENOMEM)
		return SCST_TGT_RES_QUEUE_FULL;
	else {
		PRINT_ERROR("%s: tag= %llu xfer_data failed", __func__,
			(long long unsigned)scst_cmd_get_tag(sc));
		scst_rx_data(sc, SCST_RX_STATUS_ERROR, SCST_CONTEXT_SAME);
	}

	return SCST_TGT_RES_SUCCESS;
}

/**
 * ibmvstgt_on_free_cmd() - Free command-private data.
 *
 * Called by the SCST core. May be called in IRQ context.
 */
static void ibmvstgt_on_free_cmd(struct scst_cmd *sc)
{
}

static int send_adapter_info(struct iu_entry *iue,
		      dma_addr_t remote_buffer, uint16_t length)
{
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	dma_addr_t data_token;
	struct mad_adapter_info_data *info;
	int err;

	info = dma_alloc_coherent(target->dev, sizeof(*info), &data_token,
				  GFP_KERNEL);
	if (!info) {
		eprintk("bad dma_alloc_coherent %p\n", target);
		return 1;
	}

	/* Get remote info */
	err = h_copy_rdma(sizeof(*info), vport->riobn, remote_buffer,
			  vport->liobn, data_token);
	if (err == H_SUCCESS) {
		dprintk("Client connect: %s (%d)\n",
			info->partition_name, info->partition_number);
	}

	memset(info, 0, sizeof(*info));

	strcpy(info->srp_version, "16.a");
	strncpy(info->partition_name, partition_name,
		sizeof(info->partition_name));
	info->partition_number = partition_number;
	info->mad_version = 1;
	info->os_type = 2;
	info->port_max_txu[0] = ibmvstgt_template.sg_tablesize * PAGE_SIZE;

	/* Send our info to remote */
	err = h_copy_rdma(sizeof(*info), vport->liobn, data_token,
			  vport->riobn, remote_buffer);

	dma_free_coherent(target->dev, sizeof(*info), info, data_token);

	if (err != H_SUCCESS) {
		eprintk("Error sending adapter info %d\n", err);
		return 1;
	}

	return 0;
}

static void process_login(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct srp_login_rsp *rsp = &iu->srp.login_rsp;
	struct srp_login_rej *rej = &iu->srp.login_rej;
	uint64_t tag = iu->srp.rsp.tag;
	struct scst_session *sess;
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	char name[16];

	BUG_ON(!target);
	BUG_ON(!target->tgt);
	BUG_ON(!vport);

	memset(iu, 0, max(sizeof(*rsp), sizeof(*rej)));

	snprintf(name, sizeof(name), "%x", vport->dma_dev->unit_address);

	if (!ibmvstgt_is_target_enabled(target->tgt)) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		PRINT_ERROR("rejected SRP_LOGIN_REQ because the target %s"
			    " has not yet been enabled", name);
		goto reject;
	}

	if (vport->sess) {
		PRINT_INFO("Closing session %s (%p) because a new login request"
			" has been received", name, vport->sess);
		scst_unregister_session(vport->sess, 0, NULL);
		vport->sess = NULL;
	}

	sess = scst_register_session(target->tgt, 0, name, vport, NULL, NULL);
	if (!sess) {
		rej->reason = cpu_to_be32(SRP_LOGIN_REJ_INSUFFICIENT_RESOURCES);
		TRACE_DBG("%s", "Failed to create SCST session");
		goto reject;
	}

	vport->sess = sess;

	/* TODO handle case that requested size is wrong and
	 * buffer format is wrong
	 */
	rsp->opcode = SRP_LOGIN_RSP;
	/*
	 * Avoid BUSY conditions by limiting the number of buffers used
	 * for the SRP protocol to the SCST SCSI command queue size.
	 */
	rsp->req_lim_delta = cpu_to_be32(min(SRP_REQ_LIM,
					   scst_get_max_lun_commands(NULL, 0)));
	rsp->tag = tag;
	rsp->max_it_iu_len = cpu_to_be32(sizeof(union srp_iu));
	rsp->max_ti_iu_len = cpu_to_be32(sizeof(union srp_iu));
	/* direct and indirect */
	rsp->buf_fmt = cpu_to_be16(SRP_BUF_FORMAT_DIRECT
				   | SRP_BUF_FORMAT_INDIRECT);

	send_iu(iue, sizeof(*rsp), VIOSRP_SRP_FORMAT);

	return;

reject:
	rej->opcode = SRP_LOGIN_REJ;
	rej->tag = tag;
	rej->buf_fmt = cpu_to_be16(SRP_BUF_FORMAT_DIRECT
				   | SRP_BUF_FORMAT_INDIRECT);

	send_iu(iue, sizeof(*rsp), VIOSRP_SRP_FORMAT);
}

/**
 * struct mgmt_ctx - management command context information.
 * @iue:  VIO SRP information unit associated with the management command.
 * @sess: SCST session via which the management command has been received.
 * @tag:  SCSI tag of the management command.
 */
struct mgmt_ctx {
	struct iu_entry *iue;
	struct scst_session *sess;
};

static int process_tsk_mgmt(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	struct scst_session *sess = vport->sess;
	struct srp_tsk_mgmt *srp_tsk;
	struct mgmt_ctx *mgmt_ctx;
	int ret = 0;

	srp_tsk = &iu->srp.tsk_mgmt;

	dprintk("%p %u\n", iue, srp_tsk->tsk_mgmt_func);

	ret = SCST_MGMT_STATUS_FAILED;
	mgmt_ctx = kmalloc(sizeof(*mgmt_ctx), GFP_ATOMIC);
	if (!mgmt_ctx)
		goto err;

	mgmt_ctx->iue = iue;
	mgmt_ctx->sess = sess;
	iu->srp.rsp.tag = srp_tsk->tag;

	switch (srp_tsk->tsk_mgmt_func) {
	case SRP_TSK_ABORT_TASK:
		ret = scst_rx_mgmt_fn_tag(sess, SCST_ABORT_TASK,
					  srp_tsk->task_tag,
					  SCST_ATOMIC, mgmt_ctx);
		break;
	case SRP_TSK_ABORT_TASK_SET:
		ret = scst_rx_mgmt_fn_lun(sess, SCST_ABORT_TASK_SET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  SCST_ATOMIC, mgmt_ctx);
		break;
	case SRP_TSK_CLEAR_TASK_SET:
		ret = scst_rx_mgmt_fn_lun(sess, SCST_CLEAR_TASK_SET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  SCST_ATOMIC, mgmt_ctx);
		break;
	case SRP_TSK_LUN_RESET:
		ret = scst_rx_mgmt_fn_lun(sess, SCST_LUN_RESET,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  SCST_ATOMIC, mgmt_ctx);
		break;
	case SRP_TSK_CLEAR_ACA:
		ret = scst_rx_mgmt_fn_lun(sess, SCST_CLEAR_ACA,
					  &srp_tsk->lun, sizeof(srp_tsk->lun),
					  SCST_ATOMIC, mgmt_ctx);
		break;
	default:
		ret = SCST_MGMT_STATUS_FN_NOT_SUPPORTED;
	}

	if (ret != SCST_MGMT_STATUS_SUCCESS)
		goto err;
	return ret;

err:
	kfree(mgmt_ctx);
	srp_iu_put(iue);
	return ret;
}

enum {
	/* See also table 24 in the T10 r16a document. */
	SRP_TSK_MGMT_SUCCESS = 0x00,
	SRP_TSK_MGMT_FUNC_NOT_SUPP = 0x04,
	SRP_TSK_MGMT_FAILED = 0x05,
};

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

static void ibmvstgt_tsk_mgmt_done(struct scst_mgmt_cmd *mcmnd)
{
	struct mgmt_ctx *mgmt_ctx;
	struct scst_session *sess;
	struct iu_entry *iue;
	union viosrp_iu *iu;

	mgmt_ctx = scst_mgmt_cmd_get_tgt_priv(mcmnd);
	BUG_ON(!mgmt_ctx);

	sess = mgmt_ctx->sess;
	BUG_ON(!sess);

	iue = mgmt_ctx->iue;
	BUG_ON(!iue);

	iu = vio_iu(iue);

	TRACE_DBG("%s: tag %lld status %d",
		  __func__, (long long unsigned)iu->srp.rsp.tag,
		  scst_mgmt_cmd_get_status(mcmnd));

	send_rsp(iue, NULL,
		 scst_to_srp_tsk_mgmt_status(scst_mgmt_cmd_get_status(mcmnd)),
		 0/*asc*/);

	kfree(mgmt_ctx);
}

static void process_mad_iu(struct iu_entry *iue)
{
	union viosrp_iu *iu = vio_iu(iue);
	struct viosrp_adapter_info *info;
	struct viosrp_host_config *conf;

	switch (iu->mad.empty_iu.common.type) {
	case VIOSRP_EMPTY_IU_TYPE:
		eprintk("%s\n", "Unsupported EMPTY MAD IU");
		srp_iu_put(iue);
		break;
	case VIOSRP_ERROR_LOG_TYPE:
		eprintk("%s\n", "Unsupported ERROR LOG MAD IU");
		iu->mad.error_log.common.status = 1;
		send_iu(iue, sizeof(iu->mad.error_log),	VIOSRP_MAD_FORMAT);
		break;
	case VIOSRP_ADAPTER_INFO_TYPE:
		info = &iu->mad.adapter_info;
		info->common.status = send_adapter_info(iue, info->buffer,
							info->common.length);
		send_iu(iue, sizeof(*info), VIOSRP_MAD_FORMAT);
		break;
	case VIOSRP_HOST_CONFIG_TYPE:
		conf = &iu->mad.host_config;
		conf->common.status = 1;
		send_iu(iue, sizeof(*conf), VIOSRP_MAD_FORMAT);
		break;
	default:
		eprintk("Unknown type %u\n", iu->srp.rsp.opcode);
		srp_iu_put(iue);
	}
}

static void process_srp_iu(struct iu_entry *iue)
{
	unsigned long flags;
	union viosrp_iu *iu = vio_iu(iue);
	struct srp_target *target = iue->target;
	struct vio_port *vport = target_to_port(target);
	int err;
	u8 opcode = iu->srp.rsp.opcode;

	spin_lock_irqsave(&target->lock, flags);
	if (vport->releasing) {
		spin_unlock_irqrestore(&target->lock, flags);
		srp_iu_put(iue);
		return;
	}
	spin_unlock_irqrestore(&target->lock, flags);

	switch (opcode) {
	case SRP_LOGIN_REQ:
		process_login(iue);
		break;
	case SRP_TSK_MGMT:
		process_tsk_mgmt(iue);
		break;
	case SRP_CMD:
		err = srp_cmd_queue(vport->sess, &iu->srp.cmd, iue,
				    SCST_NON_ATOMIC);
		if (err) {
			eprintk("cannot queue cmd %p %d\n", &iu->srp.cmd, err);
			srp_iu_put(iue);
		}
		break;
	case SRP_LOGIN_RSP:
	case SRP_I_LOGOUT:
	case SRP_T_LOGOUT:
	case SRP_RSP:
	case SRP_CRED_REQ:
	case SRP_CRED_RSP:
	case SRP_AER_REQ:
	case SRP_AER_RSP:
		eprintk("Unsupported type %u\n", opcode);
		srp_iu_put(iue);
		break;
	default:
		eprintk("Unknown type %u\n", opcode);
		srp_iu_put(iue);
	}
}

static void process_iu(struct viosrp_crq *crq, struct srp_target *target)
{
	struct vio_port *vport = target_to_port(target);
	struct iu_entry *iue;
	long err;

	iue = srp_iu_get(target);
	if (!iue) {
		eprintk("Error getting IU from pool, %p\n", target);
		return;
	}

	iue->remote_token = crq->IU_data_ptr;

	err = h_copy_rdma(crq->IU_length, vport->riobn,
			  iue->remote_token, vport->liobn, iue->sbuf->dma);

	if (err != H_SUCCESS) {
		eprintk("%ld transferring data error %p\n", err, iue);
		srp_iu_put(iue);
	}

	if (crq->format == VIOSRP_MAD_FORMAT)
		process_mad_iu(iue);
	else
		process_srp_iu(iue);
}

#ifdef RHEL_MAJOR
static irqreturn_t ibmvstgt_interrupt(int dummy, void *data, struct pt_regs *p)
#else
static irqreturn_t ibmvstgt_interrupt(int dummy, void *data)
#endif
{
	struct srp_target *target = data;
	struct vio_port *vport = target_to_port(target);

	vio_disable_interrupts(vport->dma_dev);
	queue_work(vtgtd, &vport->crq_work);

	return IRQ_HANDLED;
}

static int crq_queue_create(struct crq_queue *queue, struct srp_target *target)
{
	int err;
	struct vio_port *vport = target_to_port(target);

	queue->msgs = (struct viosrp_crq *) get_zeroed_page(GFP_KERNEL);
	if (!queue->msgs)
		goto malloc_failed;
	queue->size = PAGE_SIZE / sizeof(*queue->msgs);

	queue->msg_token = dma_map_single(target->dev, queue->msgs,
					  queue->size * sizeof(*queue->msgs),
					  DMA_BIDIRECTIONAL);

#ifdef RHEL_MAJOR
	if (dma_mapping_error(queue->msg_token))
#else
	if (dma_mapping_error(target->dev, queue->msg_token))
#endif
		goto map_failed;

	err = h_reg_crq(vport->dma_dev->unit_address, queue->msg_token,
			PAGE_SIZE);

	/* If the adapter was left active for some reason (like kexec)
	 * try freeing and re-registering
	 */
	if (err == H_RESOURCE) {
	    do {
		err = h_free_crq(vport->dma_dev->unit_address);
	    } while (err == H_BUSY || H_IS_LONG_BUSY(err));

	    err = h_reg_crq(vport->dma_dev->unit_address, queue->msg_token,
			    PAGE_SIZE);
	}

	if (err != H_SUCCESS && err != 2) {
		eprintk("Error 0x%x opening virtual adapter\n", err);
		goto reg_crq_failed;
	}

	err = request_irq(vport->dma_dev->irq, &ibmvstgt_interrupt,
			  IRQF_DISABLED, "ibmvstgt", target);
	if (err)
		goto req_irq_failed;

	vio_enable_interrupts(vport->dma_dev);

	h_send_crq(vport->dma_dev->unit_address, 0xC001000000000000ULL, 0);

	queue->cur = 0;
	spin_lock_init(&queue->lock);

	return 0;

req_irq_failed:
	do {
		err = h_free_crq(vport->dma_dev->unit_address);
	} while (err == H_BUSY || H_IS_LONG_BUSY(err));

reg_crq_failed:
	dma_unmap_single(target->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);
map_failed:
	free_page((unsigned long) queue->msgs);

malloc_failed:
	return -ENOMEM;
}

static void crq_queue_destroy(struct srp_target *target)
{
	struct vio_port *vport = target_to_port(target);
	struct crq_queue *queue = &vport->crq_queue;
	int err;

	free_irq(vport->dma_dev->irq, target);
	do {
		err = h_free_crq(vport->dma_dev->unit_address);
	} while (err == H_BUSY || H_IS_LONG_BUSY(err));

	dma_unmap_single(target->dev, queue->msg_token,
			 queue->size * sizeof(*queue->msgs), DMA_BIDIRECTIONAL);

	free_page((unsigned long) queue->msgs);
}

static void process_crq(struct viosrp_crq *crq,	struct srp_target *target)
{
	struct vio_port *vport = target_to_port(target);
	dprintk("%x %x\n", crq->valid, crq->format);

	switch (crq->valid) {
	case 0xC0:
		/* initialization */
		switch (crq->format) {
		case 0x01:
			h_send_crq(vport->dma_dev->unit_address,
				   0xC002000000000000ULL, 0);
			break;
		case 0x02:
			break;
		default:
			eprintk("Unknown format %u\n", crq->format);
		}
		break;
	case 0xFF:
		/* transport event */
		break;
	case 0x80:
		/* real payload */
		switch (crq->format) {
		case VIOSRP_SRP_FORMAT:
		case VIOSRP_MAD_FORMAT:
			process_iu(crq, target);
			break;
		case VIOSRP_OS400_FORMAT:
		case VIOSRP_AIX_FORMAT:
		case VIOSRP_LINUX_FORMAT:
		case VIOSRP_INLINE_FORMAT:
			eprintk("Unsupported format %u\n", crq->format);
			break;
		default:
			eprintk("Unknown format %u\n", crq->format);
		}
		break;
	default:
		eprintk("unknown message type 0x%02x!?\n", crq->valid);
	}
}

static inline struct viosrp_crq *next_crq(struct crq_queue *queue)
{
	struct viosrp_crq *crq;
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	crq = &queue->msgs[queue->cur];
	if (crq->valid & 0x80) {
		if (++queue->cur == queue->size)
			queue->cur = 0;
	} else
		crq = NULL;
	spin_unlock_irqrestore(&queue->lock, flags);

	return crq;
}

/**
 * handle_crq() - Process the command/response queue.
 *
 * Note: Although this function is not thread-safe because of how it is
 * scheduled it is guaranteed that this function will never run concurrently
 * with itself.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
static void handle_crq(void *ctx)
#else
static void handle_crq(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
	struct vio_port *vport = (struct vio_port *)ctx;
#else
	struct vio_port *vport = container_of(work, struct vio_port, crq_work);
#endif
	struct srp_target *target = vport->target;
	struct viosrp_crq *crq;
	int done = 0;

	while (!done) {
		while ((crq = next_crq(&vport->crq_queue)) != NULL) {
			process_crq(crq, target);
			crq->valid = 0x00;
		}

		vio_enable_interrupts(vport->dma_dev);

		crq = next_crq(&vport->crq_queue);
		if (crq) {
			vio_disable_interrupts(vport->dma_dev);
			process_crq(crq, target);
			crq->valid = 0x00;
		} else
			done = 1;
	}
}

static void ibmvstgt_get_product_id(const struct scst_tgt_dev *tgt_dev,
				    char *buf, const int size)
{
	WARN_ON(size != 16);

	/*
	 * AIX uses hardcoded device names. The AIX SCSI initiator even won't
	 * work unless we use the names VDASD and VOPTA.
	 */
	switch (tgt_dev->dev->type) {
	case TYPE_DISK:
		memcpy(buf, "VDASD blkdev    ", 16);
		break;
	case TYPE_ROM:
		memcpy(buf, "VOPTA blkdev    ", 16);
		break;
	default:
		snprintf(buf, size, "(devtype %d)     ", tgt_dev->dev->type);
		break;
	}
}

/*
 * Extract target, bus and LUN information from a 64-bit LUN in CPU-order.
 */
#define GETTARGET(x) ((((uint16_t)(x) >> 8) & 0x003f))
#define GETBUS(x)    ((((uint16_t)(x) >> 5) & 0x0007))
#define GETLUN(x)    ((((uint16_t)(x) >> 0) & 0x001f))

static int ibmvstgt_get_serial(const struct scst_tgt_dev *tgt_dev, char *buf,
			       int size)
{
	struct scst_session *sess = tgt_dev->sess;
	struct vio_port *vport = scst_sess_get_tgt_priv(sess);
	uint64_t lun = tgt_dev->lun;

	return snprintf(buf, size,
			"IBM-VSCSI-%s-P%d-%x-%d-%d-%d\n",
			system_id, partition_number,
			vport->dma_dev->unit_address,
			GETBUS(lun), GETTARGET(lun), GETLUN(lun));
}

/**
 * ibmvstgt_get_transportid() - SCST TransportID callback function.
 *
 * See also SPC-3, section 7.5.4.5, TransportID for initiator ports using SRP.
 */
static int ibmvstgt_get_transportid(struct scst_tgt *tgt,
	struct scst_session *sess, uint8_t **transport_id)
{
	struct vio_port *vport;
	struct spc_rdma_transport_id {
		uint8_t protocol_identifier;
		uint8_t reserved[7];
		union {
			uint8_t id8[16];
			__be32  id32[4];
		} i_port_id;
	};
	struct spc_rdma_transport_id *tr_id;
	int res;

	if (!sess) {
		res = SCSI_TRANSPORTID_PROTOCOLID_SRP;
		goto out;
	}

	vport = scst_sess_get_tgt_priv(sess);
	BUG_ON(!vport);

	BUILD_BUG_ON(sizeof(*tr_id) != 24);

	res = -ENOMEM;
	tr_id = kzalloc(sizeof(struct spc_rdma_transport_id), GFP_KERNEL);
	if (!tr_id) {
		PRINT_ERROR("%s", "Allocation of TransportID failed");
		goto out;
	}

	res = 0;
	tr_id->protocol_identifier = SCSI_TRANSPORTID_PROTOCOLID_SRP;
	memset(&tr_id->i_port_id, 0, sizeof(tr_id->i_port_id));
	tr_id->i_port_id.id32[3] = cpu_to_be32(vport->dma_dev->unit_address);

	*transport_id = (uint8_t *)tr_id;

out:
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static ssize_t system_id_show(struct class_device *dev, char *buf)
#else
static ssize_t system_id_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
#endif
{
	return snprintf(buf, PAGE_SIZE, "%s\n", system_id);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static ssize_t partition_number_show(struct class_device *dev, char *buf)
#else
static ssize_t partition_number_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
#endif
{
	return snprintf(buf, PAGE_SIZE, "%x\n", partition_number);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static ssize_t unit_address_show(struct class_device *dev, char *buf)
#else
static ssize_t unit_address_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
#endif
{
	struct vio_port *vport = container_of(dev, struct vio_port, dev);
	return snprintf(buf, PAGE_SIZE, "%x\n", vport->dma_dev->unit_address);
}

static struct class_attribute ibmvstgt_class_attrs[] = {
	__ATTR_NULL,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static struct class_device_attribute ibmvstgt_attrs[] = {
#else
static struct device_attribute ibmvstgt_attrs[] = {
#endif
	__ATTR(system_id, S_IRUGO, system_id_show, NULL),
	__ATTR(partition_number, S_IRUGO, partition_number_show, NULL),
	__ATTR(unit_address, S_IRUGO, unit_address_show, NULL),
	__ATTR_NULL,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static void ibmvstgt_dev_release(struct class_device *dev)
#else
static void ibmvstgt_dev_release(struct device *dev)
#endif
{ }

static struct class ibmvstgt_class = {
	.name		= "ibmvstgt",
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	.release	= ibmvstgt_dev_release,
#else
	.dev_release	= ibmvstgt_dev_release,
#endif
	.class_attrs	= ibmvstgt_class_attrs,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	.class_dev_attrs= ibmvstgt_attrs,
#else
	.dev_attrs	= ibmvstgt_attrs,
#endif
};

static struct scst_tgt_template ibmvstgt_template = {
	.name			= TGT_NAME,
	.preferred_addr_method	= SCST_LUN_ADDR_METHOD_LUN,
#ifdef RHEL_MAJOR
	.sg_tablesize		= 1024,
#else
	.sg_tablesize		= SCSI_MAX_SG_SEGMENTS,
#endif
	.vendor			= "IBM     ",
	.revision		= "0001",
	.fake_aca		= true,
	.get_product_id		= ibmvstgt_get_product_id,
	.get_serial		= ibmvstgt_get_serial,
	.get_vend_specific	= ibmvstgt_get_serial,

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags	= DEFAULT_IBMVSTGT_TRACE_FLAGS,
	.trace_flags		= &trace_flag,
#endif
#if !defined(CONFIG_SCST_PROC)
	.enable_target		= ibmvstgt_enable_target,
	.is_target_enabled	= ibmvstgt_is_target_enabled,
#endif
	.detect			= ibmvstgt_detect,
	.release		= ibmvstgt_release,
	.xmit_response		= ibmvstgt_xmit_response,
	.rdy_to_xfer		= ibmvstgt_rdy_to_xfer,
	.on_free_cmd		= ibmvstgt_on_free_cmd,
	.task_mgmt_fn_done	= ibmvstgt_tsk_mgmt_done,
	.get_initiator_port_transport_id = ibmvstgt_get_transportid,
};

static int ibmvstgt_probe(struct vio_dev *dev, const struct vio_device_id *id)
{
	struct scst_tgt *scst_tgt;
	struct srp_target *target;
	struct vio_port *vport;
	const unsigned int *dma;
	unsigned dma_size;
	int err = -ENOMEM;

	vport = kzalloc(sizeof(struct vio_port), GFP_KERNEL);
	if (!vport)
		return err;

	target = kzalloc(sizeof(struct srp_target), GFP_KERNEL);
	if (!target)
		goto free_vport;

	scst_tgt = scst_register_target(&ibmvstgt_template, NULL);
	if (!scst_tgt)
		goto free_target;

	scst_tgt_set_tgt_priv(scst_tgt, target);
	target->tgt = scst_tgt;
	vport->dma_dev = dev;
	target->ldata = vport;
	vport->target = target;
	BUILD_BUG_ON_NOT_POWER_OF_2(VSCSI_REQ_LIM);
	err = srp_target_alloc(target, &dev->dev, VSCSI_REQ_LIM,
			       SRP_MAX_IU_LEN);
	if (err)
		goto unregister_target;

	dma = vio_get_attribute(dev, "ibm,my-dma-window", &dma_size);
	if (!dma || dma_size != 40) {
		eprintk("Couldn't get window property %d\n", dma_size);
		err = -EIO;
		goto free_srp_target;
	}
	vport->liobn = dma[0];
	vport->riobn = dma[5];

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
	INIT_WORK(&vport->crq_work, handle_crq, vport);
#else
	INIT_WORK(&vport->crq_work, handle_crq);
#endif

	err = crq_queue_create(&vport->crq_queue, target);
	if (err)
		goto free_srp_target;

	vport->dev.class = &ibmvstgt_class;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	vport->dev.dev = &dev->dev;
#else
	vport->dev.parent = &dev->dev;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	snprintf(vport->dev.class_id, BUS_ID_SIZE, "ibmvstgt-%d",
		     vport->dma_dev->unit_address);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	snprintf(vport->dev.bus_id, BUS_ID_SIZE, "ibmvstgt-%d",
		     vport->dma_dev->unit_address);
#else
	dev_set_name(&vport->dev, "ibmvstgt-%d",
		     vport->dma_dev->unit_address);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	if (class_device_register(&vport->dev))
#else
	if (device_register(&vport->dev))
#endif
		goto destroy_crq_queue;

	atomic_inc(&ibmvstgt_device_count);

	return 0;

destroy_crq_queue:
	crq_queue_destroy(target);
free_srp_target:
	srp_target_free(target);
unregister_target:
	scst_unregister_target(scst_tgt);
free_target:
	kfree(target);
free_vport:
	kfree(vport);
	return err;
}

static int ibmvstgt_remove(struct vio_dev *dev)
{
	struct srp_target *target;
	struct vio_port *vport;

	target = dev_get_drvdata(&dev->dev);
	if (!target)
		return 0;

	atomic_dec(&ibmvstgt_device_count);

	vport = target->ldata;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	class_device_unregister(&vport->dev);
#else
	device_unregister(&vport->dev);
#endif
	crq_queue_destroy(target);
	srp_target_free(target);
	scst_unregister_target(target->tgt);
	kfree(target);
	kfree(vport);
	return 0;
}

#ifdef CONFIG_SCST_PROC
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static int ibmvstgt_trace_level_show(struct seq_file *seq, void *v)
{
	return scst_proc_log_entry_read(seq, trace_flag, NULL);
}

static ssize_t ibmvstgt_proc_trace_level_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	return scst_proc_log_entry_write(file, buf, length, &trace_flag,
		DEFAULT_IBMVSTGT_TRACE_FLAGS, NULL);
}

static struct scst_proc_data ibmvstgt_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(ibmvstgt_proc_trace_level_write)
	.show = ibmvstgt_trace_level_show,
};
#endif

static int ibmvstgt_register_procfs_entry(struct scst_tgt_template *tgt)
{
	int res = -ENOMEM;
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *p, *root;

	root = scst_proc_get_tgt_root(tgt);
	if (!root)
		goto out;
	/*
	 * Fill in the scst_proc_data::data pointer, which is used in
	 * a printk(KERN_INFO ...) statement in
	 * scst_proc_log_entry_write() in scst_proc.c.
	 */
	ibmvstgt_log_proc_data.data = (char *)tgt->name;
	p = scst_create_proc_entry(root, "trace_level",
				   &ibmvstgt_log_proc_data);
	if (p)
		res = 0;
#endif
out:
	return res;
}

static void ibmvstgt_unregister_procfs_entry(struct scst_tgt_template *tgt)
{
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *root;

	root = scst_proc_get_tgt_root(tgt);
	if (!root)
		goto out;
	remove_proc_entry("trace_level", root);
out:
	;
#endif
}
#endif /*CONFIG_SCST_PROC*/

static struct vio_device_id ibmvstgt_device_table[] = {
	{"v-scsi-host", "IBM,v-scsi-host"},
	{"",""}
};

MODULE_DEVICE_TABLE(vio, ibmvstgt_device_table);

static struct vio_driver ibmvstgt_driver = {
	.id_table	= ibmvstgt_device_table,
	.probe		= ibmvstgt_probe,
	.remove		= ibmvstgt_remove,
	.driver = {
		.name = "ibmvscsis",
		.owner = THIS_MODULE,
	}
};

static int get_system_info(void)
{
	struct device_node *rootdn, *vdevdn;
	const char *id, *model, *name;
	const unsigned int *num;

	rootdn = of_find_node_by_path("/");
	if (!rootdn)
		return -ENOENT;

	model = of_get_property(rootdn, "model", NULL);
	id = of_get_property(rootdn, "system-id", NULL);
	if (model && id)
		snprintf(system_id, sizeof(system_id), "%s-%s", model, id);

	name = of_get_property(rootdn, "ibm,partition-name", NULL);
	if (name)
		strncpy(partition_name, name, sizeof(partition_name));

	num = of_get_property(rootdn, "ibm,partition-no", NULL);
	if (num)
		partition_number = *num;

	of_node_put(rootdn);

	vdevdn = of_find_node_by_path("/vdevice");
	if (vdevdn) {
		const unsigned *mvds;

		mvds = of_get_property(vdevdn, "ibm,max-virtual-dma-size",
				       NULL);
		if (mvds)
			max_vdma_size = *mvds;
		of_node_put(vdevdn);
	}

	return 0;
}

/**
 * ibmvstgt_init() - Kernel module initialization.
 *
 * Note: Since vio_register_driver() registers callback functions, and since
 * at least one of these callback functions (ibmvstgt_probe()) calls SCST
 * functions, the SCST target template must be registered before
 * vio_register_driver() is called.
 */
static int __init ibmvstgt_init(void)
{
	int err = -ENOMEM;

	pr_info("IBM eServer i/pSeries Virtual SCSI Target Driver\n");

	err = get_system_info();
	if (err)
		goto out;

	err = class_register(&ibmvstgt_class);
	if (err)
		goto out;

	err = scst_register_target_template(&ibmvstgt_template);
	if (err)
		goto unregister_class;

	vtgtd = create_workqueue("ibmvtgtd");
	if (!vtgtd)
		goto unregister_tgt;

	err = vio_register_driver(&ibmvstgt_driver);
	if (err)
		goto destroy_wq;

#ifdef CONFIG_SCST_PROC
	err = ibmvstgt_register_procfs_entry(&ibmvstgt_template);
	if (err)
		goto unregister_driver;
#endif

	return 0;

#ifdef CONFIG_SCST_PROC
unregister_driver:
	vio_unregister_driver(&ibmvstgt_driver);
#endif
destroy_wq:
	destroy_workqueue(vtgtd);
unregister_tgt:
	scst_unregister_target_template(&ibmvstgt_template);
unregister_class:
	class_unregister(&ibmvstgt_class);
out:
	return err;
}

static void __exit ibmvstgt_exit(void)
{
	pr_info("Unregister IBM virtual SCSI driver\n");

#ifdef CONFIG_SCST_PROC
	ibmvstgt_unregister_procfs_entry(&ibmvstgt_template);
#endif
	vio_unregister_driver(&ibmvstgt_driver);
	destroy_workqueue(vtgtd);
	scst_unregister_target_template(&ibmvstgt_template);
	class_unregister(&ibmvstgt_class);
}

MODULE_DESCRIPTION("IBM Virtual SCSI Target");
MODULE_AUTHOR("Santiago Leon");
MODULE_LICENSE("GPL");

module_init(ibmvstgt_init);
module_exit(ibmvstgt_exit);
