/*
 *  qla2x00t.c
 *
 *  Copyright (C) 2004 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
 *
 *  QLogic 22xx/23xx/24xx/25xx FC target driver.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/workqueue.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include <scst.h>
#endif

#include "qla2x00t.h"

/*
 * This driver calls qla2x00_req_pkt() and qla2x00_issue_marker(), which
 * must be called under HW lock and could unlock/lock it inside.
 * It isn't an issue, since in the current implementation on the time when
 * those functions are called:
 *
 *   - Either context is IRQ and only IRQ handler can modify HW data,
 *     including rings related fields,
 *
 *   - Or access to target mode variables from struct q2t_tgt doesn't
 *     cross those functions boundaries, except tgt_stop, which
 *     additionally protected by irq_cmd_count.
 */

#ifndef CONFIG_SCSI_QLA2XXX_TARGET
#error "CONFIG_SCSI_QLA2XXX_TARGET is NOT DEFINED"
#endif

#ifdef CONFIG_SCST_DEBUG
#define Q2T_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_LINE | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL)
#else
# ifdef CONFIG_SCST_TRACING
#define Q2T_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_PID | \
	TRACE_SPECIAL)
# endif
#endif

static int q2t_target_release(struct scst_tgt *scst_tgt);
static int q2x_xmit_response(struct scst_cmd *scst_cmd);
static int __q24_xmit_response(struct q2t_cmd *cmd, int xmit_type);
static int q2t_rdy_to_xfer(struct scst_cmd *scst_cmd);
static void q2t_on_free_cmd(struct scst_cmd *scst_cmd);
static void q2t_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd);
static int q2t_get_initiator_port_transport_id(struct scst_tgt *tgt,
	struct scst_session *scst_sess, uint8_t **transport_id);

/* Predefs for callbacks handed to qla2xxx(target) */
static void q24_atio_pkt(scsi_qla_host_t *vha, atio7_entry_t *pkt);
static void q2t_response_pkt(scsi_qla_host_t *vha, response_t *pkt);
static void q2t_async_event(uint16_t code, scsi_qla_host_t *vha,
	uint16_t *mailbox);
static void q2x_ctio_completion(scsi_qla_host_t *vha, uint32_t handle);
static int q2t_host_action(scsi_qla_host_t *vha,
	qla2x_tgt_host_action_t action);
static void q2t_fc_port_added(scsi_qla_host_t *vha, fc_port_t *fcport);
static void q2t_fc_port_deleted(scsi_qla_host_t *vha, fc_port_t *fcport);
static int q2t_issue_task_mgmt(struct q2t_sess *sess, uint8_t *lun,
	int lun_size, int fn, void *iocb, int flags);
static void q2x_send_term_exchange(scsi_qla_host_t *vha, struct q2t_cmd *cmd,
	atio_entry_t *atio, int ha_locked);
static void q24_send_term_exchange(scsi_qla_host_t *vha, struct q2t_cmd *cmd,
	atio7_entry_t *atio, int ha_locked);
static void q2t_reject_free_srr_imm(scsi_qla_host_t *vha, struct srr_imm *imm,
	int ha_lock);
static int q2t_cut_cmd_data_head(struct q2t_cmd *cmd, unsigned int offset);
static void q2t_schedule_sess_for_deletion(struct q2t_sess *sess);
static void q2t_clear_tgt_db(struct q2t_tgt *tgt, bool immediately);
static void q2t_on_hw_pending_cmd_timeout(struct scst_cmd *scst_cmd);
static void q2t_unreg_sess(struct q2t_sess *sess);
static int q2t_close_session(struct scst_session *scst_sess);
static uint16_t q2t_get_scsi_transport_version(struct scst_tgt *scst_tgt);
static uint16_t q2t_get_phys_transport_version(struct scst_tgt *scst_tgt);


/** SYSFS **/

static ssize_t q2t_version_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);


static struct kobj_attribute q2t_version_attr =
	__ATTR(version, S_IRUGO, q2t_version_show, NULL);

static const struct attribute *q2tt_attrs[] = {
	&q2t_version_attr.attr,
	NULL,
};

static ssize_t q2t_show_expl_conf_enabled(struct kobject *kobj,
	struct kobj_attribute *attr, char *buffer);
static ssize_t q2t_store_expl_conf_enabled(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size);

static struct kobj_attribute q2t_expl_conf_attr =
	__ATTR(explicit_confirmation, S_IRUGO|S_IWUSR,
	       q2t_show_expl_conf_enabled, q2t_store_expl_conf_enabled);

static ssize_t q2t_abort_isp_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size);

static struct kobj_attribute q2t_abort_isp_attr =
	__ATTR(abort_isp, S_IWUSR, NULL, q2t_abort_isp_store);

static ssize_t q2t_hw_target_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);

static struct kobj_attribute q2t_hw_target_attr =
	__ATTR(hw_target, S_IRUGO, q2t_hw_target_show, NULL);

static ssize_t q2t_node_name_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t q2t_node_name_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size);

static struct kobj_attribute q2t_vp_node_name_attr =
	__ATTR(node_name, S_IRUGO, q2t_node_name_show, NULL);

static struct kobj_attribute q2t_hw_node_name_attr =
	__ATTR(node_name, S_IRUGO|S_IWUSR, q2t_node_name_show,
		q2t_node_name_store);

static ssize_t q2t_port_name_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);

static struct kobj_attribute q2t_vp_port_name_attr =
	__ATTR(port_name, S_IRUGO, q2t_port_name_show, NULL);

static ssize_t q2t_port_name_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size);

static struct kobj_attribute q2t_hw_port_name_attr =
	__ATTR(port_name, S_IRUGO|S_IWUSR, q2t_port_name_show,
		q2t_port_name_store);

static ssize_t q2t_vp_parent_host_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);

static struct kobj_attribute q2t_vp_parent_host_attr =
	__ATTR(parent_host, S_IRUGO, q2t_vp_parent_host_show, NULL);

static const struct attribute *q2t_hw_tgt_attrs[] = {
	&q2t_hw_target_attr.attr,
	&q2t_expl_conf_attr.attr,
	&q2t_abort_isp_attr.attr,
	&q2t_hw_node_name_attr.attr,
	&q2t_hw_port_name_attr.attr,
	NULL,
};

static const struct attribute *q2t_npiv_tgt_attrs[] = {
	&q2t_vp_node_name_attr.attr,
	&q2t_vp_parent_host_attr.attr,
	&q2t_vp_port_name_attr.attr,
	NULL,
};


static int q2t_enable_tgt(struct scst_tgt *tgt, bool enable);
static bool q2t_is_tgt_enabled(struct scst_tgt *tgt);

#define ENABLE_NPIV 0 /* NPIV does not work */

#if ENABLE_NPIV
static ssize_t q2t_add_vtarget(const char *target_name, char *params);
static ssize_t q2t_del_vtarget(const char *target_name);
#endif /* ENABLE_NPIV */

/*
 * Global Variables
 */

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag q2t_trace_flag
static unsigned long q2t_trace_flag = Q2T_DEFAULT_LOG_FLAGS;
#endif

static struct scst_tgt_template tgt2x_template = {
	.name = "qla2x00t",
	.sg_tablesize = 0,
	.use_clustering = 1,
#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	.xmit_response_atomic = 0,
	.rdy_to_xfer_atomic = 0,
#else
	.xmit_response_atomic = 1,
	.rdy_to_xfer_atomic = 1,
#endif
	.max_hw_pending_time = Q2T_MAX_HW_PENDING_TIME,
	.release = q2t_target_release,
	.xmit_response = q2x_xmit_response,
	.rdy_to_xfer = q2t_rdy_to_xfer,
	.on_free_cmd = q2t_on_free_cmd,
	.task_mgmt_fn_done = q2t_task_mgmt_fn_done,
	.close_session = q2t_close_session,
	.get_initiator_port_transport_id = q2t_get_initiator_port_transport_id,
	.get_scsi_transport_version = q2t_get_scsi_transport_version,
	.get_phys_transport_version = q2t_get_phys_transport_version,
	.on_hw_pending_cmd_timeout = q2t_on_hw_pending_cmd_timeout,
	.enable_target = q2t_enable_tgt,
	.is_target_enabled = q2t_is_tgt_enabled,
#if ENABLE_NPIV
	.add_target = q2t_add_vtarget,
	.del_target = q2t_del_vtarget,
	.add_target_parameters = "node_name, parent_host",
#endif
	.tgtt_attrs = q2tt_attrs,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags = Q2T_DEFAULT_LOG_FLAGS,
	.trace_flags = &trace_flag,
#endif
};

static struct kmem_cache *q2t_cmd_cachep;
static struct kmem_cache *q2t_sess_cachep;
static struct kmem_cache *q2t_tgt_cachep;
static struct kmem_cache *q2t_mgmt_cmd_cachep;
static mempool_t *q2t_mgmt_cmd_mempool;

static DECLARE_RWSEM(q2t_unreg_rwsem);

/* It's not yet supported */
static inline int scst_cmd_get_ppl_offset(struct scst_cmd *scst_cmd)
{
	return 0;
}

/*
 * ha->hardware_lock supposed to be held on entry.
 *
 * !! If you are calling it after finding sess in tgt->sess_list, make sure
 * !! that the lock is not dropped between find and this function call!
 */
static inline void q2t_sess_get(struct q2t_sess *sess)
{
	sess->sess_ref++;
	TRACE_DBG("sess %p, new sess_ref %d", sess, sess->sess_ref);
}

/* ha->hardware_lock supposed to be held on entry */
static inline void q2t_sess_put(struct q2t_sess *sess)
{
	TRACE_DBG("sess %p, new sess_ref %d", sess, sess->sess_ref-1);
	sBUG_ON(sess->sess_ref == 0);

	sess->sess_ref--;
	if (sess->sess_ref == 0)
		q2t_unreg_sess(sess);
}

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_loop_id(struct q2t_tgt *tgt,
	uint16_t loop_id)
{
	struct q2t_sess *sess;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if (loop_id == sess->loop_id) {
			EXTRACHECKS_BUG_ON(sess->deleted);
			return sess;
		}
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_s_id_include_deleted(
	struct q2t_tgt *tgt, const uint8_t *s_id)
{
	struct q2t_sess *sess;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->s_id.b.al_pa == s_id[2]) &&
		    (sess->s_id.b.area == s_id[1]) &&
		    (sess->s_id.b.domain == s_id[0])) {
			EXTRACHECKS_BUG_ON(sess->deleted);
			return sess;
		}
	}
	list_for_each_entry(sess, &tgt->del_sess_list, sess_list_entry) {
		if ((sess->s_id.b.al_pa == s_id[2]) &&
		    (sess->s_id.b.area == s_id[1]) &&
		    (sess->s_id.b.domain == s_id[0])) {
			EXTRACHECKS_BUG_ON(!sess->deleted);
			return sess;
		}
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_s_id(struct q2t_tgt *tgt,
	const uint8_t *s_id)
{
	struct q2t_sess *sess;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->s_id.b.al_pa == s_id[2]) &&
		    (sess->s_id.b.area == s_id[1]) &&
		    (sess->s_id.b.domain == s_id[0])) {
			EXTRACHECKS_BUG_ON(sess->deleted);
			return sess;
		}
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_s_id_le(struct q2t_tgt *tgt,
	const uint8_t *s_id)
{
	struct q2t_sess *sess;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->s_id.b.al_pa == s_id[0]) &&
		    (sess->s_id.b.area == s_id[1]) &&
		    (sess->s_id.b.domain == s_id[2])) {
			EXTRACHECKS_BUG_ON(sess->deleted);
			return sess;
		}
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_port_name(struct q2t_tgt *tgt,
	const uint8_t *port_name)
{
	struct q2t_sess *sess;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->port_name[0] == port_name[0]) &&
		    (sess->port_name[1] == port_name[1]) &&
		    (sess->port_name[2] == port_name[2]) &&
		    (sess->port_name[3] == port_name[3]) &&
		    (sess->port_name[4] == port_name[4]) &&
		    (sess->port_name[5] == port_name[5]) &&
		    (sess->port_name[6] == port_name[6]) &&
		    (sess->port_name[7] == port_name[7])) {
			EXTRACHECKS_BUG_ON(sess->deleted);
			return sess;
		}
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry */
static inline struct q2t_sess *q2t_find_sess_by_port_name_include_deleted(
	struct q2t_tgt *tgt, const uint8_t *port_name)
{
	struct q2t_sess *sess;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->port_name[0] == port_name[0]) &&
		    (sess->port_name[1] == port_name[1]) &&
		    (sess->port_name[2] == port_name[2]) &&
		    (sess->port_name[3] == port_name[3]) &&
		    (sess->port_name[4] == port_name[4]) &&
		    (sess->port_name[5] == port_name[5]) &&
		    (sess->port_name[6] == port_name[6]) &&
		    (sess->port_name[7] == port_name[7])) {
			EXTRACHECKS_BUG_ON(sess->deleted);
			return sess;
		}
	}
	list_for_each_entry(sess, &tgt->del_sess_list, sess_list_entry) {
		if ((sess->port_name[0] == port_name[0]) &&
		    (sess->port_name[1] == port_name[1]) &&
		    (sess->port_name[2] == port_name[2]) &&
		    (sess->port_name[3] == port_name[3]) &&
		    (sess->port_name[4] == port_name[4]) &&
		    (sess->port_name[5] == port_name[5]) &&
		    (sess->port_name[6] == port_name[6]) &&
		    (sess->port_name[7] == port_name[7])) {
			EXTRACHECKS_BUG_ON(!sess->deleted);
			return sess;
		}
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry */
static inline void q2t_exec_queue(scsi_qla_host_t *vha)
{
	qla2x00_start_iocbs(vha, vha->req);
}

/* ha->hardware_lock supposed to be held on entry */
static inline request_t *q2t_req_pkt(scsi_qla_host_t *vha)
{
	return qla2x00_req_pkt(vha);
}

/* Might release hw lock, then reacquire!! */
static inline int q2t_issue_marker(scsi_qla_host_t *vha, int vha_locked)
{
	/* Send marker if required */
	if (unlikely(vha->marker_needed != 0)) {
		int rc = qla2x00_issue_marker(vha, vha_locked);

		if (rc != QLA_SUCCESS) {
			PRINT_ERROR("qla2x00t(%ld): issue_marker() "
				"failed", vha->host_no);
		}
		return rc;
	}
	return QLA_SUCCESS;
}

static inline scsi_qla_host_t *q2t_find_host_by_d_id(scsi_qla_host_t *vha,
	uint8_t *d_id)
{
	struct qla_hw_data *ha = vha->hw;

	if ((vha->d_id.b.area != d_id[1]) || (vha->d_id.b.domain != d_id[0]))
		return NULL;

	if (vha->d_id.b.al_pa == d_id[2])
		return vha;

	if (IS_FWI2_CAPABLE(ha)) {
		uint8_t vp_idx;

		sBUG_ON(ha->tgt_vp_map == NULL);
		vp_idx = ha->tgt_vp_map[d_id[2]].idx;
		if (likely(test_bit(vp_idx, ha->vp_idx_map)))
			return ha->tgt_vp_map[vp_idx].vha;
	}

	return NULL;
}

static inline scsi_qla_host_t *q2t_find_host_by_vp_idx(scsi_qla_host_t *vha,
	uint16_t vp_idx)
{
	struct qla_hw_data *ha = vha->hw;

	if (vha->vp_idx == vp_idx)
		return vha;

	if (IS_FWI2_CAPABLE(ha)) {
		sBUG_ON(ha->tgt_vp_map == NULL);
		if (likely(test_bit(vp_idx, ha->vp_idx_map)))
			return ha->tgt_vp_map[vp_idx].vha;
	}

	return NULL;
}

/* ha->hardware_lock supposed to be held on entry */
static void q24_queue_unknown_atio(scsi_qla_host_t *vha, atio7_entry_t *atio)
{
	struct q2t_unknown_atio *u;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	if ((vha->tgt != NULL) && vha->tgt->tgt_stop) {
		TRACE_MGMT_DBG("qla2x00t(%ld): dropping unknown ATIO_TYPE7, "
			"because tgt is being stopped", vha->host_no);
		goto out_term;
	}

	u = kzalloc(sizeof(*u), GFP_ATOMIC);
	if (u == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Alloc of struct unknown_atio "
			"(size %zd) failed", sizeof(*u));
		/* It should be harmless and on the next retry should work well */
		goto out_term;
	}

	TRACE_MGMT_DBG("qla2x00t(%ld): Received ATIO_TYPE7 "
		"with unknown d_id %x:%x:%x, queuing unknown entry %p",
		vha->host_no, atio->fcp_hdr.d_id[0], atio->fcp_hdr.d_id[1],
		atio->fcp_hdr.d_id[2], u);

	u->vha = vha;
	memcpy(&u->atio7, atio, sizeof(u->atio7));

	list_add_tail(&u->unknown_atio_list_entry, &ha->unknown_atio_list);

	schedule_delayed_work(&ha->unknown_atio_work, 1);

out:
	TRACE_EXIT();
	return;

out_term:
	q24_send_term_exchange(vha, NULL, atio, 1);
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static void q24_try_to_dequeue_unknown_atios(struct qla_hw_data *ha)
{
	struct q2t_unknown_atio *u, *t;

	TRACE_ENTRY();

	list_for_each_entry_safe(u, t, &ha->unknown_atio_list,
				 unknown_atio_list_entry) {
		scsi_qla_host_t *host, *vha = u->vha;

		sBUG_ON(vha->hw != ha);
		host = q2t_find_host_by_d_id(vha, u->atio7.fcp_hdr.d_id);
		if (host != NULL) {
			TRACE_MGMT_DBG("qla2x00t(%ld): Requeuing unknown "
				"ATIO_TYPE7 %p", vha->host_no, u);
			q24_atio_pkt(host, &u->atio7);
		} else if ((vha->tgt != NULL) && vha->tgt->tgt_stop) {
			TRACE_MGMT_DBG("qla2x00t(%ld): Freeing unknown "
				"ATIO_TYPE7 %p, because tgt is being stopped",
				 vha->host_no, u);
			q24_send_term_exchange(vha, NULL, &u->atio7, 1);
		} else {
			TRACE_DBG("u %p, vha %p, host %p, sched again..", u,
				vha, host);
			schedule_delayed_work(&ha->unknown_atio_work, 1);
			continue;
		}

		list_del(&u->unknown_atio_list_entry);
		kfree(u);
	}

	TRACE_EXIT();
	return;
}

static void q2t_try_to_dequeue_unknown_atios(struct qla_hw_data *ha)
{
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_DBG("qla2x00t(%ld): Trying to requeue unknown ATIOs",
		((scsi_qla_host_t *)(pci_get_drvdata(ha->pdev)))->host_no);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	q24_try_to_dequeue_unknown_atios(ha);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	TRACE_EXIT();
	return;
}

static void __q2t_try_to_dequeue_unknown_atios(struct qla_hw_data *ha)
{
	TRACE_ENTRY();
	q2t_try_to_dequeue_unknown_atios(ha);
	TRACE_EXIT();
	return;
}

static void q24_atio_pkt_all_vps(scsi_qla_host_t *vha, atio7_entry_t *atio)
{
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	sBUG_ON(vha == NULL);

	switch (atio->entry_type) {
	case ATIO_TYPE7:
	{
		scsi_qla_host_t *host = q2t_find_host_by_d_id(vha, atio->fcp_hdr.d_id);

		if (unlikely(host == NULL)) {
			/*
			 * It might happen, because there is a small gap between
			 * requesting the DPC thread to update loop and actual
			 * update.
			 */
			q24_queue_unknown_atio(vha, atio);
			break;
		}
		if (unlikely(!list_empty(&ha->unknown_atio_list)))
			q24_try_to_dequeue_unknown_atios(ha);
		q24_atio_pkt(host, atio);
		break;
	}

	case IMMED_NOTIFY_TYPE:
	{
		scsi_qla_host_t *host = vha;

		if (IS_FWI2_CAPABLE(ha)) {
			notify24xx_entry_t *entry = (notify24xx_entry_t *)atio;

			if ((entry->vp_index != 0xFF) &&
			    (entry->nport_handle != 0xFFFF)) {
				host = q2t_find_host_by_vp_idx(vha,
						entry->vp_index);
				if (unlikely(!host)) {
					PRINT_ERROR("qla2x00t(%ld): Received "
						"ATIO (IMMED_NOTIFY_TYPE) "
						"with unknown vp_index %d",
						vha->host_no, entry->vp_index);
					break;
				}
			}
		}
		q24_atio_pkt(host, atio);
		break;
	}

	default:
		PRINT_ERROR("qla2x00t(%ld): Received unknown ATIO atio "
		     "type %x", vha->host_no, atio->entry_type);
		break;
	}

	TRACE_EXIT();
	return;
}

static void q2t_response_pkt_all_vps(scsi_qla_host_t *vha, response_t *pkt)
{
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	sBUG_ON(vha == NULL);

	switch (pkt->entry_type) {
	case CTIO_TYPE7:
	{
		ctio7_fw_entry_t *entry = (ctio7_fw_entry_t *)pkt;
		scsi_qla_host_t *host = q2t_find_host_by_vp_idx(vha,
						entry->vp_index);

		if (unlikely(!host)) {
			PRINT_ERROR("qla2x00t(%ld): Response pkt (CTIO_TYPE7) "
				"received, with unknown vp_index %d",
				vha->host_no, entry->vp_index);
			break;
		}
		q2t_response_pkt(host, pkt);
		break;
	}

	case IMMED_NOTIFY_TYPE:
	{
		scsi_qla_host_t *host = vha;

		if (IS_FWI2_CAPABLE(ha)) {
			notify24xx_entry_t *entry = (notify24xx_entry_t *)pkt;

			host = q2t_find_host_by_vp_idx(vha, entry->vp_index);
			if (unlikely(!host)) {
				PRINT_ERROR("qla2x00t(%ld): Response pkt "
					"(IMMED_NOTIFY_TYPE) received, "
					"with unknown vp_index %d",
					vha->host_no, entry->vp_index);
				break;
			}
		}
		q2t_response_pkt(host, pkt);
		break;
	}

	case NOTIFY_ACK_TYPE:
	{
		scsi_qla_host_t *host = vha;

		if (IS_FWI2_CAPABLE(ha)) {
			nack24xx_entry_t *entry = (nack24xx_entry_t *)pkt;

			if (entry->vp_index != 0xFF) {
				host = q2t_find_host_by_vp_idx(vha,
						entry->vp_index);
				if (unlikely(!host)) {
					PRINT_ERROR("qla2x00t(%ld): Response "
						"pkt (NOTIFY_ACK_TYPE) "
						"received, with unknown "
						"vp_index %d", vha->host_no,
						entry->vp_index);
					break;
				}
			}
		}
		q2t_response_pkt(host, pkt);
		break;
	}

	case ABTS_RECV_24XX:
	{
		abts24_recv_entry_t *entry = (abts24_recv_entry_t *)pkt;
		scsi_qla_host_t *host = q2t_find_host_by_vp_idx(vha,
						entry->vp_index);

		if (unlikely(!host)) {
			PRINT_ERROR("qla2x00t(%ld): Response pkt "
				"(ABTS_RECV_24XX) received, with unknown "
				"vp_index %d", vha->host_no, entry->vp_index);
			break;
		}
		q2t_response_pkt(host, pkt);
		break;
	}

	case ABTS_RESP_24XX:
	{
		abts24_resp_entry_t *entry = (abts24_resp_entry_t *)pkt;
		scsi_qla_host_t *host = q2t_find_host_by_vp_idx(vha,
						entry->vp_index);

		if (unlikely(!host)) {
			PRINT_ERROR("qla2x00t(%ld): Response pkt "
				"(ABTS_RECV_24XX) received, with unknown "
				"vp_index %d", vha->host_no, entry->vp_index);
			break;
		}
		q2t_response_pkt(host, pkt);
		break;
	}

	default:
		q2t_response_pkt(vha, pkt);
		break;
	}

	TRACE_EXIT();
	return;
}
/*
 * Registers with initiator driver (but target mode isn't enabled till
 * it's turned on via sysfs)
 */
static int q2t_target_driver_reg(struct scst_tgt_template *tgtt)
{
	int res, rc;
	struct qla_tgt_data t = {
		.magic = QLA2X_TARGET_MAGIC,
		.tgt24_atio_pkt = q24_atio_pkt_all_vps,
		.tgt_response_pkt = q2t_response_pkt_all_vps,
		.tgt2x_ctio_completion = q2x_ctio_completion,
		.tgt_async_event = q2t_async_event,
		.tgt_try_to_dequeue_unknown_atios = __q2t_try_to_dequeue_unknown_atios,
		.tgt_host_action = q2t_host_action,
		.tgt_fc_port_added = q2t_fc_port_added,
		.tgt_fc_port_deleted = q2t_fc_port_deleted,
	};

	TRACE_ENTRY();

	rc = qla2xxx_tgt_register_driver(&t);
	if (rc < 0) {
		res = rc;
		PRINT_ERROR("qla2x00t: Unable to register driver: %d", res);
		goto out;
	}

	if (rc != QLA2X_INITIATOR_MAGIC) {
		PRINT_ERROR("qla2x00t: Wrong version of the initiator part: "
			"%d", rc);
		res = -EINVAL;
		goto out;
	}

	res = 0;

	PRINT_INFO("qla2x00t: %s", "Target mode driver for QLogic 2x00 controller "
		"registered successfully");

out:
	TRACE_EXIT();
	return res;
}

static void q2t_free_session_done(struct scst_session *scst_sess)
{
	struct q2t_sess *sess;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha;
	unsigned long flags;

	TRACE_ENTRY();

	sBUG_ON(scst_sess == NULL);
	sess = (struct q2t_sess *)scst_sess_get_tgt_priv(scst_sess);
	sBUG_ON(sess == NULL);
	tgt = sess->tgt;

	TRACE_MGMT_DBG("Unregistration of sess %p finished", sess);

	kmem_cache_free(q2t_sess_cachep, sess);

	if (tgt == NULL)
		goto out;

	TRACE_DBG("empty(sess_list) %d sess_count %d",
	      list_empty(&tgt->sess_list), tgt->sess_count);

	vha = tgt->vha;
	ha = vha->hw;

	/*
	 * We need to protect against race, when tgt is freed before or
	 * inside wake_up()
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	tgt->sess_count--;
	if (tgt->sess_count == 0)
		wake_up_all(&tgt->waitQ);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_unreg_sess(struct q2t_sess *sess)
{
	TRACE_ENTRY();

	sBUG_ON(sess == NULL);
	sBUG_ON(sess->sess_ref != 0);

	TRACE_MGMT_DBG("Unregistering sess %p (tgt %p)", sess, sess->tgt);

	sBUG_ON(list_entry_in_list(&sess->sess_list_entry));

	PRINT_INFO("qla2x00t(%ld): %ssession for loop_id %d deleted",
		sess->tgt->vha->host_no, sess->local ? "local " : "",
		sess->loop_id);

	scst_unregister_session(sess->scst_sess, 0, q2t_free_session_done);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_reset(scsi_qla_host_t *vha, void *iocb, int mcmd)
{
	struct q2t_sess *sess;
	int loop_id;
	uint16_t lun = 0;
	int res = 0;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	if (IS_FWI2_CAPABLE(ha)) {
		notify24xx_entry_t *n = (notify24xx_entry_t *)iocb;

		if ((le16_to_cpu(n->status) == IMM_NTFY_ELS) &&
		    ((n->status_subcode == ELS_TPRLO) ||
		     (n->status_subcode == ELS_LOGO))) {
			if ((n->status_subcode == ELS_TPRLO) &&
			    (n->flags & cpu_to_le16(BIT_1))) {
				/* Global flag set */
				loop_id = 0xFFFF;
			} else
				loop_id = le16_to_cpu(n->els_nport_handle);
		} else
			loop_id = le16_to_cpu(n->nport_handle);
	} else
		loop_id = GET_TARGET_ID(ha, (notify_entry_t *)iocb);

	if (loop_id == 0xFFFF) {
		/* Global event */
		atomic_inc(&vha->tgt->tgt_global_resets_count);
		q2t_clear_tgt_db(vha->tgt, false);
		if (!list_empty(&vha->tgt->sess_list)) {
			sess = list_entry(vha->tgt->sess_list.next,
					typeof(*sess), sess_list_entry);
			switch (mcmd) {
			case Q2T_NEXUS_LOSS_SESS:
				mcmd = Q2T_NEXUS_LOSS;
				break;

			case Q2T_ABORT_ALL_SESS:
				mcmd = Q2T_ABORT_ALL;
				break;

			case Q2T_NEXUS_LOSS:
			case Q2T_ABORT_ALL:
				break;

			default:
				PRINT_ERROR("qla2x00t(%ld): Not allowed "
					"command %x in %s", vha->host_no,
					mcmd, __func__);
				sess = NULL;
				break;
			}
		} else
			sess = NULL;
	} else
		sess = q2t_find_sess_by_loop_id(vha->tgt, loop_id);

	if (sess == NULL) {
		if (loop_id != 0xFFFF)
			TRACE_MGMT_DBG("sess for loop_id 0x%x not found", loop_id);
		res = -ESRCH;
		vha->tgt->tm_to_unknown = 1;
		goto del;
	}

	TRACE_MGMT_DBG("scsi(%ld): resetting (session %p from port "
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
		"mcmd %x, loop_id %d)", vha->host_no, sess,
		sess->port_name[0], sess->port_name[1],
		sess->port_name[2], sess->port_name[3],
		sess->port_name[4], sess->port_name[5],
		sess->port_name[6], sess->port_name[7],
		mcmd, loop_id);

	res = q2t_issue_task_mgmt(sess, (uint8_t *)&lun, sizeof(lun),
			mcmd, iocb, Q24_MGMT_SEND_NACK);

del:
	switch (mcmd) {
	case Q2T_NEXUS_LOSS_SESS:
		if (sess != NULL)
			q2t_schedule_sess_for_deletion(sess);
		break;
	case Q2T_NEXUS_LOSS:
		if (loop_id != 0xFFFF)
			q2t_clear_tgt_db(vha->tgt, false);
	default:
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_sess_del(struct q2t_sess *sess)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("Deleting sess %p", sess);

	sBUG_ON(!list_entry_in_list(&sess->sess_list_entry));
	list_del_init(&sess->sess_list_entry);
	q2t_sess_put(sess);

	TRACE_EXIT();
	return;
}

/* pha->hardware_lock supposed to be held on entry */
static void q2t_schedule_sess_for_deletion(struct q2t_sess *sess)
{
	struct q2t_tgt *tgt = sess->tgt;
	uint32_t dev_loss_tmo = tgt->vha->hw->port_down_retry_count + 5;
	bool schedule;

	TRACE_ENTRY();

	if (sess->deleted)
		goto out;

	if (tgt->tgt_stop) {
		TRACE_DBG("tgt %p stopped, deleting sess %p immediately",
			tgt, sess);
		q2t_sess_del(sess);
		goto out;
	}

	/*
	 * If the list is empty, then, most likely, the work isn't
	 * scheduled.
	 */
	schedule = list_empty(&tgt->del_sess_list);

	TRACE_MGMT_DBG("Scheduling sess %p for deletion (schedule %d)", sess,
		schedule);
	list_move_tail(&sess->sess_list_entry, &tgt->del_sess_list);
	sess->deleted = 1;
	sess->expires = jiffies + dev_loss_tmo * HZ;

	PRINT_INFO("qla2x00t(%ld): session for port %02x:%02x:%02x:"
		"%02x:%02x:%02x:%02x:%02x (loop_id %d) scheduled for "
		"deletion in %d secs", tgt->vha->host_no,
		sess->port_name[0], sess->port_name[1],
		sess->port_name[2], sess->port_name[3],
		sess->port_name[4], sess->port_name[5],
		sess->port_name[6], sess->port_name[7],
		sess->loop_id, dev_loss_tmo);

	if (schedule)
		schedule_delayed_work(&tgt->sess_del_work,
				max_t(long, sess->expires - jiffies, 0));

out:
	TRACE_EXIT();
	return;
}

static int q2t_close_session(struct scst_session *scst_sess)
{
	struct q2t_sess *sess = scst_sess_get_tgt_priv(scst_sess);
	struct q2t_tgt *tgt = sess->tgt;
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;
	unsigned long flags;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (list_entry_in_list(&sess->sess_list_entry)) {
		TRACE_MGMT_DBG("Force closing sess %p", sess);
		q2t_sess_del(sess);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return 0;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_clear_tgt_db(struct q2t_tgt *tgt, bool immediately)
{
	struct q2t_sess *sess, *sess_tmp;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("qla2x00t: Clearing targets DB for target %p", tgt);

	list_for_each_entry_safe(sess, sess_tmp, &tgt->sess_list,
					sess_list_entry) {
		sBUG_ON(sess->deleted);

		if (immediately)
			q2t_sess_del(sess);
		else
			q2t_schedule_sess_for_deletion(sess);
	}

	if (immediately) {
		/* Delete also scheduled to del sessions */
		list_for_each_entry_safe(sess, sess_tmp, &tgt->del_sess_list,
						sess_list_entry) {
			sBUG_ON(!sess->deleted);
			q2t_sess_del(sess);
		}
	}

	/* At this point tgt could be already dead */

	TRACE_MGMT_DBG("Finished clearing tgt %p DB", tgt);

	TRACE_EXIT();
	return;
}

/* Called in a thread context */
static void q2t_alloc_session_done(struct scst_session *scst_sess,
				   void *data, int result)
{
	struct q2t_sess *sess = (struct q2t_sess *)data;
	struct q2t_tgt *tgt = sess->tgt;
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&ha->hardware_lock, flags);

	if (result != 0) {
		PRINT_INFO("qla2x00t(%ld): Session initialization failed",
			   vha->host_no);
		if (list_entry_in_list(&sess->sess_list_entry))
			q2t_sess_del(sess);
	}

	q2t_sess_put(sess);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	TRACE_EXIT();
	return;
}

static int q24_get_loop_id(scsi_qla_host_t *vha, const uint8_t *s_id,
	uint16_t *loop_id)
{
	dma_addr_t gid_list_dma;
	struct gid_list_info *gid_list;
	char *id_iter;
	int res, rc, i, retries = 0;
	uint16_t entries;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	gid_list = dma_alloc_coherent(&ha->pdev->dev, qla2x00_gid_list_size(ha),
			&gid_list_dma, GFP_KERNEL);
	if (gid_list == NULL) {
		PRINT_ERROR("qla2x00t(%ld): DMA Alloc failed of %d",
			vha->host_no, qla2x00_gid_list_size(ha));
		res = -ENOMEM;
		goto out;
	}

	/* Get list of logged in devices */
retry:
	rc = qla2x00_get_id_list(vha, gid_list, gid_list_dma, &entries);
	if (rc != QLA_SUCCESS) {
		if (rc == QLA_FW_NOT_READY) {
			retries++;
			if (retries < 3) {
				msleep(1000);
				goto retry;
			}
		}
		TRACE_MGMT_DBG("qla2x00t(%ld): get_id_list() failed: %x",
			vha->host_no, rc);
		res = -rc;
		goto out_free_id_list;
	}

	id_iter = (char *)gid_list;
	res = -1;
	for (i = 0; i < entries; i++) {
		struct gid_list_info *gid = (struct gid_list_info *)id_iter;

		if ((gid->al_pa == s_id[2]) &&
		    (gid->area == s_id[1]) &&
		    (gid->domain == s_id[0])) {
			*loop_id = le16_to_cpu(gid->loop_id);
			res = 0;
			break;
		}
		id_iter += ha->gid_list_info_size;
	}

out_free_id_list:
	dma_free_coherent(&ha->pdev->dev, qla2x00_gid_list_size(ha), gid_list, gid_list_dma);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static bool q2t_check_fcport_exist(scsi_qla_host_t *vha, struct q2t_sess *sess)
{
	struct qla_hw_data *ha = vha->hw;
	bool res, found = false;
	int rc, i;
	uint16_t loop_id = 0xFFFF; /* to eliminate compiler's warning */
	uint16_t entries;
	void *pmap;
	int pmap_len;
	fc_port_t *fcport;
	int global_resets;

	TRACE_ENTRY();

retry:
	global_resets = atomic_read(&vha->tgt->tgt_global_resets_count);

	rc = qla2x00_get_node_name_list(vha, true, &pmap, &pmap_len);
	if (rc != QLA_SUCCESS) {
		res = false;
		goto out;
	}

	if (IS_FWI2_CAPABLE(ha)) {
		struct qla_port24_data *pmap24 = pmap;

		entries = pmap_len/sizeof(*pmap24);

		for (i = 0; i < entries; ++i) {
			if ((sess->port_name[0] == pmap24[i].port_name[7]) &&
			    (sess->port_name[1] == pmap24[i].port_name[6]) &&
			    (sess->port_name[2] == pmap24[i].port_name[5]) &&
			    (sess->port_name[3] == pmap24[i].port_name[4]) &&
			    (sess->port_name[4] == pmap24[i].port_name[3]) &&
			    (sess->port_name[5] == pmap24[i].port_name[2]) &&
			    (sess->port_name[6] == pmap24[i].port_name[1]) &&
			    (sess->port_name[7] == pmap24[i].port_name[0])) {
				loop_id = le16_to_cpu(pmap24[i].loop_id);
				found = true;
				break;
			}
		}
	} else {
		struct qla_port23_data *pmap2x = pmap;

		entries = pmap_len/sizeof(*pmap2x);

		for (i = 0; i < entries; ++i) {
			if ((sess->port_name[0] == pmap2x[i].port_name[7]) &&
			    (sess->port_name[1] == pmap2x[i].port_name[6]) &&
			    (sess->port_name[2] == pmap2x[i].port_name[5]) &&
			    (sess->port_name[3] == pmap2x[i].port_name[4]) &&
			    (sess->port_name[4] == pmap2x[i].port_name[3]) &&
			    (sess->port_name[5] == pmap2x[i].port_name[2]) &&
			    (sess->port_name[6] == pmap2x[i].port_name[1]) &&
			    (sess->port_name[7] == pmap2x[i].port_name[0])) {
				loop_id = le16_to_cpu(pmap2x[i].loop_id);
				found = true;
				break;
			}
		}
	}

	vfree(pmap);

	if (!found) {
		res = false;
		goto out;
	}

	TRACE_DBG("loop_id 0x%x", loop_id);

	fcport = kzalloc(sizeof(*fcport), GFP_KERNEL);
	if (fcport == NULL) {
		PRINT_ERROR("qla2x00t(%ld): Allocation of tmp FC port failed",
			vha->host_no);
		res = false;
		goto out;
	}

	/*
	 * Mask that bit off, because the driver/fw does not use
	 * it for internal loop_id lookups.
	 *
	 * From 3.47 in the Qlogic 2500 fw spec:
	 *
	 * Internet protocol (IP) sets bit 15 of the N_Port handle to
	 * indicate that the device completed port login, but not
	 * process login. The bit setting allows the host to see the
	 * device as an IP candidate.
	 */
	fcport->loop_id = loop_id & 0x7FFF;

	rc = qla2x00_get_port_database(vha, fcport, 0);
	if (rc != QLA_SUCCESS) {
		PRINT_ERROR("qla2x00t(%ld): Failed to retrieve fcport "
			"information -- get_port_database() returned %x "
			"(loop_id=0x%04x)", vha->host_no, rc, loop_id);
		res = false;
		goto out_free_fcport;
	}

	if (global_resets != atomic_read(&vha->tgt->tgt_global_resets_count)) {
		TRACE_MGMT_DBG("qla2x00t(%ld): global reset during session "
			"discovery (counter was %d, new %d), retrying",
			vha->host_no, global_resets,
			atomic_read(&vha->tgt->tgt_global_resets_count));
		goto retry;
	}

	TRACE_MGMT_DBG("Updating sess %p s_id %x:%x:%x, "
		"loop_id %d) to d_id %x:%x:%x, loop_id %d", sess,
		sess->s_id.b.domain, sess->s_id.b.area,
		sess->s_id.b.al_pa, sess->loop_id, fcport->d_id.b.domain,
		fcport->d_id.b.area, fcport->d_id.b.al_pa, fcport->loop_id);

	sess->s_id = fcport->d_id;
	sess->loop_id = fcport->loop_id;
	sess->conf_compl_supported = fcport->conf_compl_supported;

	res = true;

out_free_fcport:
	kfree(fcport);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_undelete_sess(struct q2t_sess *sess)
{
	TRACE_ENTRY();

	sBUG_ON(!sess->deleted);
	sBUG_ON(!list_entry_in_list(&sess->sess_list_entry));

	TRACE_MGMT_DBG("Undeleting sess %p", sess);
	list_move(&sess->sess_list_entry, &sess->tgt->sess_list);
	sess->deleted = 0;

	TRACE_EXIT();
	return;
}

static void q2t_del_sess_work_fn(struct work_struct *work)
{
	struct q2t_tgt *tgt = container_of(work, struct q2t_tgt,
					   sess_del_work.work);
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;
	struct q2t_sess *sess;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&ha->hardware_lock, flags);
	while (!list_empty(&tgt->del_sess_list)) {
		sess = list_first_entry(&tgt->del_sess_list, typeof(*sess),
				sess_list_entry);
		if (time_after_eq(jiffies, sess->expires)) {
			bool cancel;

			/*
			 * We need to take extra reference, because we are
			 * going to drop hardware_lock. Otherwise, we are racing
			 * with other possible callers of q2t_sess_put() for
			 * the same sess.
			 */
			q2t_sess_get(sess);

			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			cancel = q2t_check_fcport_exist(vha, sess);
			spin_lock_irqsave(&ha->hardware_lock, flags);

			if (!sess->deleted ||
			    !list_entry_in_list(&sess->sess_list_entry)) {
				/*
				 * session has been undeleted or got ready to
				 * be destroyed while we were entering here
				 */
				goto put_continue;
			}

			if (cancel) {
				q2t_undelete_sess(sess);

				TRACE(TRACE_MINOR, "qla2x00t(%ld): cancel deletion of "
					"session for port %02x:%02x:%02x:"
					"%02x:%02x:%02x:%02x:%02x (loop_id %d), "
					"because it isn't deleted by firmware",
					vha->host_no,
					sess->port_name[0], sess->port_name[1],
					sess->port_name[2], sess->port_name[3],
					sess->port_name[4], sess->port_name[5],
					sess->port_name[6], sess->port_name[7],
					sess->loop_id);
			} else {
				TRACE_MGMT_DBG("Timeout for sess %p", sess);
				q2t_sess_del(sess);
			}
put_continue:
			q2t_sess_put(sess);
		} else {
			schedule_delayed_work(&tgt->sess_del_work,
				max_t(long, sess->expires - jiffies, 0));
			break;
		}
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	TRACE_EXIT();
	return;
}

/*
 * Must be called under tgt_mutex.
 *
 * Adds an extra ref to allow to drop hw lock after adding sess to the list.
 * Caller must put it.
 */
static struct q2t_sess *q2t_create_sess(scsi_qla_host_t *vha, fc_port_t *fcport,
	bool local)
{
	char *wwn_str;
	struct q2t_tgt *tgt = vha->tgt;
	struct q2t_sess *sess;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	/* Check to avoid double sessions */
	spin_lock_irq(&ha->hardware_lock);
	sess = q2t_find_sess_by_port_name_include_deleted(tgt, fcport->port_name);
	if (sess != NULL) {
		TRACE_MGMT_DBG("Double sess %p found (s_id %x:%x:%x, "
			"loop_id %d), updating to d_id %x:%x:%x, "
			"loop_id %d", sess, sess->s_id.b.domain,
			sess->s_id.b.area, sess->s_id.b.al_pa,
			sess->loop_id, fcport->d_id.b.domain,
			fcport->d_id.b.area, fcport->d_id.b.al_pa,
			fcport->loop_id);

		if (sess->deleted)
			q2t_undelete_sess(sess);

		q2t_sess_get(sess);
		sess->s_id = fcport->d_id;
		sess->loop_id = fcport->loop_id;
		sess->conf_compl_supported = fcport->conf_compl_supported;
		if (sess->local && !local)
			sess->local = 0;
		spin_unlock_irq(&ha->hardware_lock);
		goto out;
	}
	spin_unlock_irq(&ha->hardware_lock);

	/* We are under tgt_mutex, so a new sess can't be added behind us */

	sess = kmem_cache_zalloc(q2t_sess_cachep, GFP_KERNEL);
	if (sess == NULL) {
		PRINT_ERROR("qla2x00t(%ld): session allocation failed, "
			"all commands from port %02x:%02x:%02x:%02x:"
			"%02x:%02x:%02x:%02x will be refused", vha->host_no,
			fcport->port_name[0], fcport->port_name[1],
			fcport->port_name[2], fcport->port_name[3],
			fcport->port_name[4], fcport->port_name[5],
			fcport->port_name[6], fcport->port_name[7]);
		goto out;
	}

	/* +1 for q2t_alloc_session_done(), +1 extra ref, see above */
	sess->sess_ref = 3;
	sess->tgt = vha->tgt;
	sess->s_id = fcport->d_id;
	sess->loop_id = fcport->loop_id;
	sess->conf_compl_supported = fcport->conf_compl_supported;
	sess->local = local;
	BUILD_BUG_ON(sizeof(sess->port_name) != sizeof(fcport->port_name));
	memcpy(sess->port_name, fcport->port_name, sizeof(sess->port_name));

	wwn_str = kasprintf(GFP_KERNEL,
			    "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7]);
	if (wwn_str == NULL) {
		PRINT_ERROR("qla2x00t(%ld): Allocation of wwn_str failed. "
			"All commands from port %02x:%02x:%02x:%02x:%02x:%02x:"
			"%02x:%02x will be refused", vha->host_no,
			fcport->port_name[0], fcport->port_name[1],
			fcport->port_name[2], fcport->port_name[3],
			fcport->port_name[4], fcport->port_name[5],
			fcport->port_name[6], fcport->port_name[7]);
		goto out_free_sess;
	}

	/* Lock here to eliminate creating sessions for being stopped target */
	spin_lock_irq(&ha->hardware_lock);

	if (tgt->tgt_stop)
		goto out_free_sess_wwn;

	sess->scst_sess = scst_register_session(tgt->scst_tgt, 1, wwn_str,
				sess, sess, q2t_alloc_session_done);
	if (sess->scst_sess == NULL) {
		PRINT_ERROR("qla2x00t(%ld): scst_register_session() "
			"failed for (wwn %s, loop_id %d), all "
			"commands from it will be refused", vha->host_no,
			wwn_str, fcport->loop_id);
		goto out_free_sess_wwn;
	}

	TRACE_MGMT_DBG("Adding sess %p to tgt %p", sess, tgt);
	list_add_tail(&sess->sess_list_entry, &tgt->sess_list);
	tgt->sess_count++;

	spin_unlock_irq(&ha->hardware_lock);

	PRINT_INFO("qla2x00t(%ld): %ssession for wwn %s (loop_id %d, "
		"s_id %x:%x:%x, confirmed completion %ssupported) added",
		vha->host_no, local ? "local " : "", wwn_str, fcport->loop_id,
		sess->s_id.b.domain, sess->s_id.b.area, sess->s_id.b.al_pa,
		sess->conf_compl_supported ? "" : "not ");

	kfree(wwn_str);

out:
	TRACE_EXIT_HRES(sess);
	return sess;

out_free_sess_wwn:
	spin_unlock_irq(&ha->hardware_lock);

	kfree(wwn_str);
	/* fall through */

out_free_sess:
	kmem_cache_free(q2t_sess_cachep, sess);
	sess = NULL;
	goto out;
}

static void q2t_fc_port_added(scsi_qla_host_t *vha, fc_port_t *fcport)
{
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	mutex_lock(&vha->tgt_mutex);

	tgt = vha->tgt;

	if ((tgt == NULL) || (fcport->port_type != FCT_INITIATOR))
		goto out_unlock;

	if (tgt->tgt_stop)
		goto out_unlock;

	spin_lock_irq(&ha->hardware_lock);

	sess = q2t_find_sess_by_port_name_include_deleted(tgt, fcport->port_name);
	if (sess == NULL) {
		spin_unlock_irq(&ha->hardware_lock);
		sess = q2t_create_sess(vha, fcport, false);
		spin_lock_irq(&ha->hardware_lock);
		if (sess != NULL)
			q2t_sess_put(sess); /* put the extra creation ref */
	} else {
		if (sess->deleted) {
			q2t_undelete_sess(sess);

			PRINT_INFO("qla2x00t(%ld): %ssession for port %02x:"
				"%02x:%02x:%02x:%02x:%02x:%02x:%02x (loop_id %d) "
				"reappeared", sess->tgt->vha->host_no,
				sess->local ? "local " : "", sess->port_name[0],
				sess->port_name[1], sess->port_name[2],
				sess->port_name[3], sess->port_name[4],
				sess->port_name[5], sess->port_name[6],
				sess->port_name[7], sess->loop_id);

			TRACE_MGMT_DBG("Reappeared sess %p", sess);
		}
		sess->s_id = fcport->d_id;
		sess->loop_id = fcport->loop_id;
		sess->conf_compl_supported = fcport->conf_compl_supported;
	}

	if (sess && sess->local) {
		TRACE(TRACE_MGMT, "qla2x00t(%ld): local session for "
			"port %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
			"(loop_id %d) became global", vha->host_no,
			fcport->port_name[0], fcport->port_name[1],
			fcport->port_name[2], fcport->port_name[3],
			fcport->port_name[4], fcport->port_name[5],
			fcport->port_name[6], fcport->port_name[7],
			sess->loop_id);
		sess->local = 0;
	}

	spin_unlock_irq(&ha->hardware_lock);

out_unlock:
	mutex_unlock(&vha->tgt_mutex);

	TRACE_EXIT();
	return;
}

static void q2t_fc_port_deleted(scsi_qla_host_t *vha, fc_port_t *fcport)
{
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	mutex_lock(&vha->tgt_mutex);

	tgt = vha->tgt;

	if ((tgt == NULL) || (fcport->port_type != FCT_INITIATOR))
		goto out_unlock;

	if (tgt->tgt_stop)
		goto out_unlock;

	spin_lock_irq(&ha->hardware_lock);

	sess = q2t_find_sess_by_port_name(tgt, fcport->port_name);
	if (sess == NULL)
		goto out_unlock_ha;

	TRACE_MGMT_DBG("sess %p", sess);

	sess->local = 1;
	q2t_schedule_sess_for_deletion(sess);

out_unlock_ha:
	spin_unlock_irq(&ha->hardware_lock);

out_unlock:
	mutex_unlock(&vha->tgt_mutex);

	TRACE_EXIT();
	return;
}

static inline int test_tgt_sess_count(struct q2t_tgt *tgt)
{
	unsigned long flags;
	int res;
	struct qla_hw_data *ha = tgt->vha->hw;

	/*
	 * We need to protect against race, when tgt is freed before or
	 * inside wake_up()
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	TRACE_DBG("tgt %p, empty(sess_list)=%d sess_count=%d",
	      tgt, list_empty(&tgt->sess_list), tgt->sess_count);
	res = (tgt->sess_count == 0);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return res;
}

/* Must be called under tgt_host_action_mutex or q2t_unreg_rwsem write locked */
static void q2t_target_stop(struct scst_tgt *scst_tgt)
{
	struct q2t_tgt *tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_DBG("Stopping target for host %ld(%p)", vha->host_no, ha);

	/*
	 * Mutex needed to sync with q2t_fc_port_[added,deleted].
	 * Lock is needed, because we still can get an incoming packet.
	 */

	mutex_lock(&vha->tgt_mutex);
	spin_lock_irq(&ha->hardware_lock);
	tgt->tgt_stop = 1;
	q2t_clear_tgt_db(tgt, true);
	spin_unlock_irq(&ha->hardware_lock);
	mutex_unlock(&vha->tgt_mutex);

	cancel_delayed_work_sync(&ha->unknown_atio_work);
	cancel_delayed_work_sync(&tgt->sess_del_work);

	/*
	 * Just in case, if unknown_atio_work was canceled before clearing
	 * the unknown ATIOs
	 */
	q2t_try_to_dequeue_unknown_atios(ha);

	TRACE_MGMT_DBG("Waiting for sess works (tgt %p)", tgt);
	spin_lock_irq(&tgt->sess_work_lock);
	while (!list_empty(&tgt->sess_works_list)) {
		spin_unlock_irq(&tgt->sess_work_lock);
		flush_work(&tgt->sess_work);
		spin_lock_irq(&tgt->sess_work_lock);
	}
	spin_unlock_irq(&tgt->sess_work_lock);

	TRACE_MGMT_DBG("Waiting for tgt %p: list_empty(sess_list)=%d "
		"sess_count=%d", tgt, list_empty(&tgt->sess_list),
		tgt->sess_count);

	wait_event(tgt->waitQ, test_tgt_sess_count(tgt));

	if (!vha->hw->host_shutting_down && qla_tgt_mode_enabled(vha))
		qla2x00_disable_tgt_mode(vha);

	/* Wait for sessions to clear out (just in case) */
	wait_event(tgt->waitQ, test_tgt_sess_count(tgt));

	TRACE_MGMT_DBG("Waiting for %d IRQ commands to complete (tgt %p)",
		tgt->irq_cmd_count, tgt);

	mutex_lock(&vha->tgt_mutex);
	spin_lock_irq(&ha->hardware_lock);
	while (tgt->irq_cmd_count != 0) {
		spin_unlock_irq(&ha->hardware_lock);
		udelay(2);
		spin_lock_irq(&ha->hardware_lock);
	}
	vha->tgt = NULL;
	spin_unlock_irq(&ha->hardware_lock);
	mutex_unlock(&vha->tgt_mutex);

	TRACE_MGMT_DBG("Stop of tgt %p finished", tgt);

	TRACE_EXIT();
	return;
}

/* Must be called under tgt_host_action_mutex or q2t_unreg_rwsem write locked */
static int q2t_target_release(struct scst_tgt *scst_tgt)
{
	struct q2t_tgt *tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *vha = tgt->vha;

	TRACE_ENTRY();

	q2t_target_stop(scst_tgt);

	cancel_work_sync(&tgt->rscn_reg_work);

	vha->q2t_tgt = NULL;
	scst_tgt_set_tgt_priv(scst_tgt, NULL);

	TRACE_MGMT_DBG("Release of tgt %p finished", tgt);

	kmem_cache_free(q2t_tgt_cachep, tgt);

	TRACE_EXIT();
	return 0;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_sched_sess_work(struct q2t_tgt *tgt, int type,
	const void *param, unsigned int param_size)
{
	int res;
	struct q2t_sess_work_param *prm;
	unsigned long flags;

	TRACE_ENTRY();

	prm = kzalloc(sizeof(*prm), GFP_ATOMIC);
	if (prm == NULL) {
		PRINT_ERROR("qla2x00t(%ld): Unable to create session "
			"work, command will be refused", tgt->vha->host_no);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MGMT_DBG("Scheduling work (type %d, prm %p) to find session for "
		"param %p (size %d, tgt %p)", type, prm, param, param_size, tgt);

	sBUG_ON(param_size > (sizeof(*prm) -
		offsetof(struct q2t_sess_work_param, cmd)));

	prm->type = type;
	memcpy(&prm->cmd, param, param_size);

	spin_lock_irqsave(&tgt->sess_work_lock, flags);
	if (!tgt->sess_works_pending)
		tgt->tm_to_unknown = 0;
	list_add_tail(&prm->sess_works_list_entry, &tgt->sess_works_list);
	tgt->sess_works_pending = 1;
	spin_unlock_irqrestore(&tgt->sess_work_lock, flags);

	schedule_work(&tgt->sess_work);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q2x_modify_command_count(scsi_qla_host_t *vha, int cmd_count,
	int imm_count)
{
	modify_lun_entry_t *pkt;

	TRACE_ENTRY();

	TRACE_DBG("Sending MODIFY_LUN (vha=%p, cmd=%d, imm=%d)",
		  vha, cmd_count, imm_count);

	/* Sending marker isn't necessary, since we called from ISR */

	pkt = (modify_lun_entry_t *)q2t_req_pkt(vha);
	if (pkt == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	vha->tgt->modify_lun_expected++;

	pkt->entry_type = MODIFY_LUN_TYPE;
	pkt->entry_count = 1;
	if (cmd_count < 0) {
		pkt->operators = MODIFY_LUN_CMD_SUB;	/* Subtract from command count */
		pkt->command_count = -cmd_count;
	} else if (cmd_count > 0) {
		pkt->operators = MODIFY_LUN_CMD_ADD;	/* Add to command count */
		pkt->command_count = cmd_count;
	}

	if (imm_count < 0) {
		pkt->operators |= MODIFY_LUN_IMM_SUB;
		pkt->immed_notify_count = -imm_count;
	} else if (imm_count > 0) {
		pkt->operators |= MODIFY_LUN_IMM_ADD;
		pkt->immed_notify_count = imm_count;
	}

	pkt->timeout = 0;	/* Use default */

	TRACE_BUFFER("MODIFY LUN packet data", pkt, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q2x_send_notify_ack(scsi_qla_host_t *vha, notify_entry_t *iocb,
	uint32_t add_flags, uint16_t resp_code, int resp_code_valid,
	uint16_t srr_flags, uint16_t srr_reject_code, uint8_t srr_explan)
{
	nack_entry_t *ntfy;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_DBG("Sending NOTIFY_ACK (vha=%p)", vha);

	/* Send marker if required */
	if (q2t_issue_marker(vha, 1) != QLA_SUCCESS)
		goto out;

	ntfy = (nack_entry_t *)q2t_req_pkt(vha);
	if (ntfy == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	if (vha->tgt != NULL)
		vha->tgt->notify_ack_expected++;

	ntfy->entry_type = NOTIFY_ACK_TYPE;
	ntfy->entry_count = 1;
	SET_TARGET_ID(ha, ntfy->target, GET_TARGET_ID(ha, iocb));
	ntfy->status = iocb->status;
	ntfy->task_flags = iocb->task_flags;
	ntfy->seq_id = iocb->seq_id;
	/* Do not increment here, the chip isn't decrementing */
	/* ntfy->flags = cpu_to_le16(NOTIFY_ACK_RES_COUNT); */
	ntfy->flags |= cpu_to_le16(add_flags);
	ntfy->srr_rx_id = iocb->srr_rx_id;
	ntfy->srr_rel_offs = iocb->srr_rel_offs;
	ntfy->srr_ui = iocb->srr_ui;
	ntfy->srr_flags = cpu_to_le16(srr_flags);
	ntfy->srr_reject_code = cpu_to_le16(srr_reject_code);
	ntfy->srr_reject_code_expl = srr_explan;
	ntfy->ox_id = iocb->ox_id;

	if (resp_code_valid) {
		ntfy->resp_code = cpu_to_le16(resp_code);
		ntfy->flags |= cpu_to_le16(NOTIFY_ACK_TM_RESP_CODE_VALID);
	}

	TRACE(TRACE_SCSI, "qla2x00t(%ld): Sending Notify Ack Seq %#x -> I %#x "
		"St %#x RC %#x", vha->host_no,
		le16_to_cpu(iocb->seq_id), GET_TARGET_ID(ha, iocb),
		le16_to_cpu(iocb->status), le16_to_cpu(ntfy->resp_code));
	TRACE_BUFFER("Notify Ack packet data", ntfy, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q24_send_abts_resp(scsi_qla_host_t *vha,
	const abts24_recv_entry_t *abts, uint32_t status, bool ids_reversed)
{
	abts24_resp_entry_t *resp;
	uint32_t f_ctl;
	uint8_t *p;

	TRACE_ENTRY();

	TRACE_DBG("Sending task mgmt ABTS response (vha=%p, atio=%p, "
		"status=%x", vha, abts, status);

	/* Send marker if required */
	if (q2t_issue_marker(vha, 1) != QLA_SUCCESS)
		goto out;

	resp = (abts24_resp_entry_t *)q2t_req_pkt(vha);
	if (resp == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	resp->entry_type = ABTS_RESP_24XX;
	resp->entry_count = 1;
	resp->nport_handle = abts->nport_handle;
	resp->vp_index = vha->vp_idx;
	resp->sof_type = abts->sof_type;
	resp->exchange_address = abts->exchange_address;
	resp->fcp_hdr_le = abts->fcp_hdr_le;
	f_ctl = cpu_to_le32(F_CTL_EXCH_CONTEXT_RESP |
			F_CTL_LAST_SEQ | F_CTL_END_SEQ |
			F_CTL_SEQ_INITIATIVE);
	p = (uint8_t *)&f_ctl;
	resp->fcp_hdr_le.f_ctl[0] = *p++;
	resp->fcp_hdr_le.f_ctl[1] = *p++;
	resp->fcp_hdr_le.f_ctl[2] = *p;
	if (ids_reversed) {
		resp->fcp_hdr_le.d_id[0] = abts->fcp_hdr_le.d_id[0];
		resp->fcp_hdr_le.d_id[1] = abts->fcp_hdr_le.d_id[1];
		resp->fcp_hdr_le.d_id[2] = abts->fcp_hdr_le.d_id[2];
		resp->fcp_hdr_le.s_id[0] = abts->fcp_hdr_le.s_id[0];
		resp->fcp_hdr_le.s_id[1] = abts->fcp_hdr_le.s_id[1];
		resp->fcp_hdr_le.s_id[2] = abts->fcp_hdr_le.s_id[2];
	} else {
		resp->fcp_hdr_le.d_id[0] = abts->fcp_hdr_le.s_id[0];
		resp->fcp_hdr_le.d_id[1] = abts->fcp_hdr_le.s_id[1];
		resp->fcp_hdr_le.d_id[2] = abts->fcp_hdr_le.s_id[2];
		resp->fcp_hdr_le.s_id[0] = abts->fcp_hdr_le.d_id[0];
		resp->fcp_hdr_le.s_id[1] = abts->fcp_hdr_le.d_id[1];
		resp->fcp_hdr_le.s_id[2] = abts->fcp_hdr_le.d_id[2];
	}
	resp->exchange_addr_to_abort = abts->exchange_addr_to_abort;
	if (status == SCST_MGMT_STATUS_SUCCESS) {
		resp->fcp_hdr_le.r_ctl = R_CTL_BASIC_LINK_SERV | R_CTL_B_ACC;
		resp->payload.ba_acct.seq_id_valid = SEQ_ID_INVALID;
		resp->payload.ba_acct.low_seq_cnt = 0x0000;
		resp->payload.ba_acct.high_seq_cnt = 0xFFFF;
		resp->payload.ba_acct.ox_id = abts->fcp_hdr_le.ox_id;
		resp->payload.ba_acct.rx_id = abts->fcp_hdr_le.rx_id;
	} else {
		resp->fcp_hdr_le.r_ctl = R_CTL_BASIC_LINK_SERV | R_CTL_B_RJT;
		resp->payload.ba_rjt.reason_code =
			BA_RJT_REASON_CODE_UNABLE_TO_PERFORM;
		/* Other bytes are zero */
	}

	TRACE_BUFFER("ABTS RESP packet data", resp, REQUEST_ENTRY_SIZE);

	vha->tgt->abts_resp_expected++;

	q2t_exec_queue(vha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q24_retry_term_exchange(scsi_qla_host_t *vha,
	abts24_resp_fw_entry_t *entry)
{
	ctio7_status1_entry_t *ctio;

	TRACE_ENTRY();

	TRACE_DBG("Sending retry TERM EXCH CTIO7 (vha=%p)", vha);

	/* Send marker if required */
	if (q2t_issue_marker(vha, 1) != QLA_SUCCESS)
		goto out;

	ctio = (ctio7_status1_entry_t *)q2t_req_pkt(vha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	/*
	 * We've got on entrance firmware's response on by us generated
	 * ABTS response. So, in it ID fields are reversed.
	 */

	ctio->common.entry_type = CTIO_TYPE7;
	ctio->common.entry_count = 1;
	ctio->common.nport_handle = entry->nport_handle;
	ctio->common.handle = Q2T_SKIP_HANDLE |	CTIO_COMPLETION_HANDLE_MARK;
	ctio->common.timeout = cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.vp_index = vha->vp_idx;
	ctio->common.initiator_id[0] = entry->fcp_hdr_le.d_id[0];
	ctio->common.initiator_id[1] = entry->fcp_hdr_le.d_id[1];
	ctio->common.initiator_id[2] = entry->fcp_hdr_le.d_id[2];
	ctio->common.exchange_addr = entry->exchange_addr_to_abort;
	ctio->flags = cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_TERMINATE);
	ctio->ox_id = entry->fcp_hdr_le.ox_id;

	TRACE_BUFFER("CTIO7 retry TERM EXCH packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

	q24_send_abts_resp(vha, (abts24_recv_entry_t *)entry,
		SCST_MGMT_STATUS_SUCCESS, true);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static int __q24_handle_abts(scsi_qla_host_t *vha, abts24_recv_entry_t *abts,
	struct q2t_sess *sess)
{
	int res;
	uint32_t tag = abts->exchange_addr_to_abort;
	struct q2t_mgmt_cmd *mcmd;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("qla2x00t(%ld): task abort (tag=%d)", vha->host_no, tag);

	/*
	 * Clearing all unknown ATIOs, because the aborted one can be
	 * among them. Let's be simpler and don't implement search of
	 * the aborted command in the unknown list. It should be harmless
	 * and on the next retry work well.
	 */
	while (!list_empty(&ha->unknown_atio_list)) {
		struct q2t_unknown_atio *u;

		u = list_first_entry(&ha->unknown_atio_list,
			struct q2t_unknown_atio, unknown_atio_list_entry);
		TRACE_MGMT_DBG("qla2x00t(%ld): Clearing unknown "
			"ATIO_TYPE7 %p", vha->host_no, u);
		q24_send_term_exchange(vha, NULL, &u->atio7, 1);
		list_del(&u->unknown_atio_list_entry);
		kfree(u);
	}

	mcmd = mempool_alloc(q2t_mgmt_cmd_mempool, GFP_ATOMIC);
	if (mcmd == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s: Allocation of ABORT cmd failed",
			vha->host_no, __func__);
		res = -ENOMEM;
		goto out;
	}
	memset(mcmd, 0, sizeof(*mcmd));

	mcmd->sess = sess;
	memcpy(&mcmd->orig_iocb.abts, abts, sizeof(mcmd->orig_iocb.abts));

	res = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK, tag,
		SCST_ATOMIC, mcmd);
	if (res != 0) {
		PRINT_ERROR("qla2x00t(%ld): scst_rx_mgmt_fn_tag() failed: %d",
			    vha->host_no, res);
		goto out_free;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	mempool_free(mcmd, q2t_mgmt_cmd_mempool);
	goto out;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q24_handle_abts(scsi_qla_host_t *vha, abts24_recv_entry_t *abts)
{
	int rc;
	uint32_t tag = abts->exchange_addr_to_abort;
	struct q2t_sess *sess;

	TRACE_ENTRY();

	if (le32_to_cpu(abts->fcp_hdr_le.parameter) & ABTS_PARAM_ABORT_SEQ) {
		PRINT_ERROR("qla2x00t(%ld): ABTS: Abort Sequence not "
			"supported", vha->host_no);
		goto out_err;
	}

	if (tag == ATIO_EXCHANGE_ADDRESS_UNKNOWN) {
		TRACE_MGMT_DBG("qla2x00t(%ld): ABTS: Unknown Exchange "
			"Address received", vha->host_no);
		goto out_err;
	}

	TRACE(TRACE_MGMT, "qla2x00t(%ld): task abort (s_id=%x:%x:%x, "
		"tag=%d, param=%x)", vha->host_no, abts->fcp_hdr_le.s_id[2],
		abts->fcp_hdr_le.s_id[1], abts->fcp_hdr_le.s_id[0], tag,
		le32_to_cpu(abts->fcp_hdr_le.parameter));

	sess = q2t_find_sess_by_s_id_le(vha->tgt, abts->fcp_hdr_le.s_id);
	if (sess == NULL) {
		TRACE_MGMT_DBG("qla2x00t(%ld): task abort for unexisting "
			"session", vha->host_no);
		rc = q2t_sched_sess_work(vha->tgt, Q2T_SESS_WORK_ABORT, abts,
			sizeof(*abts));
		if (rc != 0) {
			vha->tgt->tm_to_unknown = 1;
			goto out_err;
		}
		goto out;
	}

	rc = __q24_handle_abts(vha, abts, sess);
	if (rc != 0) {
		PRINT_ERROR("qla2x00t(%ld): scst_rx_mgmt_fn_tag() failed: %d",
			    vha->host_no, rc);
		goto out_err;
	}

out:
	TRACE_EXIT();
	return;

out_err:
	q24_send_abts_resp(vha, abts, SCST_MGMT_STATUS_REJECTED, false);
	goto out;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q24_send_task_mgmt_ctio(scsi_qla_host_t *vha,
	struct q2t_mgmt_cmd *mcmd, uint32_t resp_code)
{
	const atio7_entry_t *atio = &mcmd->orig_iocb.atio7;
	ctio7_status1_entry_t *ctio;

	TRACE_ENTRY();

	TRACE_DBG("Sending task mgmt CTIO7 (vha=%p, atio=%p, resp_code=%x",
		  vha, atio, resp_code);

	/* Send marker if required */
	if (q2t_issue_marker(vha, 1) != QLA_SUCCESS)
		goto out;

	ctio = (ctio7_status1_entry_t *)q2t_req_pkt(vha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	ctio->common.entry_type = CTIO_TYPE7;
	ctio->common.entry_count = 1;
	ctio->common.handle = Q2T_SKIP_HANDLE | CTIO_COMPLETION_HANDLE_MARK;
	ctio->common.nport_handle = mcmd->sess->loop_id;
	ctio->common.timeout = cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.vp_index = vha->vp_idx;
	ctio->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	ctio->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	ctio->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	ctio->common.exchange_addr = atio->exchange_addr;
	ctio->flags = (atio->attr << 9) | cpu_to_le16(
		CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_SEND_STATUS);
	ctio->ox_id = swab16(atio->fcp_hdr.ox_id);
	ctio->scsi_status = cpu_to_le16(SS_RESPONSE_INFO_LEN_VALID);
	ctio->response_len = cpu_to_le16(8);
	((uint32_t *)ctio->sense_data)[0] = cpu_to_le32(resp_code);

	TRACE_BUFFER("CTIO7 TASK MGMT packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q24_send_notify_ack(scsi_qla_host_t *vha,
	notify24xx_entry_t *iocb, uint16_t srr_flags,
	uint8_t srr_reject_code, uint8_t srr_explan)
{
	nack24xx_entry_t *nack;

	TRACE_ENTRY();

	TRACE_DBG("Sending NOTIFY_ACK24 (vha=%p)", vha);

	/* Send marker if required */
	if (q2t_issue_marker(vha, 1) != QLA_SUCCESS)
		goto out;

	if (vha->tgt != NULL)
		vha->tgt->notify_ack_expected++;

	nack = (nack24xx_entry_t *)q2t_req_pkt(vha);
	if (nack == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	nack->entry_type = NOTIFY_ACK_TYPE;
	nack->entry_count = 1;
	nack->nport_handle = iocb->nport_handle;
	if (le16_to_cpu(iocb->status) == IMM_NTFY_ELS) {
		nack->flags = iocb->flags &
			cpu_to_le32(NOTIFY24XX_FLAGS_PUREX_IOCB);
	}
	nack->srr_rx_id = iocb->srr_rx_id;
	nack->status = iocb->status;
	nack->status_subcode = iocb->status_subcode;
	nack->fw_handle = iocb->fw_handle;
	nack->exchange_address = iocb->exchange_address;
	nack->srr_rel_offs = iocb->srr_rel_offs;
	nack->srr_ui = iocb->srr_ui;
	nack->srr_flags = cpu_to_le16(srr_flags);
	nack->srr_reject_code = srr_reject_code;
	nack->srr_reject_code_expl = srr_explan;
	nack->ox_id = iocb->ox_id;
	nack->vp_index = iocb->vp_index;

	TRACE(TRACE_SCSI, "qla2x00t(%ld): Sending 24xx Notify Ack %d",
		vha->host_no, nack->status);
	TRACE_BUFFER("24xx Notify Ack packet data", nack, sizeof(*nack));

	q2t_exec_queue(vha);

out:
	TRACE_EXIT();
	return;
}

static uint32_t q2t_convert_to_fc_tm_status(int scst_mstatus)
{
	uint32_t res;

	switch (scst_mstatus) {
	case SCST_MGMT_STATUS_SUCCESS:
		res = FC_TM_SUCCESS;
		break;
	case SCST_MGMT_STATUS_TASK_NOT_EXIST:
		res = FC_TM_BAD_CMD;
		break;
	case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
	case SCST_MGMT_STATUS_REJECTED:
		res = FC_TM_REJECT;
		break;
	case SCST_MGMT_STATUS_LUN_NOT_EXIST:
	case SCST_MGMT_STATUS_FAILED:
	default:
		res = FC_TM_FAILED;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* SCST Callback */
static void q2t_task_mgmt_fn_done(struct scst_mgmt_cmd *scst_mcmd)
{
	struct q2t_mgmt_cmd *mcmd;
	unsigned long flags;
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("scst_mcmd (%p) status %#x state %#x", scst_mcmd,
		scst_mcmd->status, scst_mcmd->state);

	mcmd = scst_mgmt_cmd_get_tgt_priv(scst_mcmd);
	if (unlikely(mcmd == NULL)) {
		PRINT_ERROR("qla2x00t: scst_mcmd %p tgt_spec is NULL", mcmd);
		goto out;
	}

	vha = mcmd->sess->tgt->vha;
	ha = vha->hw;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (IS_FWI2_CAPABLE(ha)) {
		if (mcmd->flags == Q24_MGMT_SEND_NACK) {
			q24_send_notify_ack(vha,
				&mcmd->orig_iocb.notify_entry24, 0, 0, 0);
		} else {
			if (scst_mcmd->fn == SCST_ABORT_TASK)
				q24_send_abts_resp(vha, &mcmd->orig_iocb.abts,
					scst_mgmt_cmd_get_status(scst_mcmd),
					false);
			else
				q24_send_task_mgmt_ctio(vha, mcmd,
					q2t_convert_to_fc_tm_status(
						scst_mgmt_cmd_get_status(scst_mcmd)));
		}
	} else {
		uint32_t resp_code = q2t_convert_to_fc_tm_status(
					scst_mgmt_cmd_get_status(scst_mcmd));
		q2x_send_notify_ack(vha, &mcmd->orig_iocb.notify_entry, 0,
			resp_code, 1, 0, 0, 0);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	scst_mgmt_cmd_set_tgt_priv(scst_mcmd, NULL);
	mempool_free(mcmd, q2t_mgmt_cmd_mempool);

out:
	TRACE_EXIT();
	return;
}

/* No locks */
static int q2t_pci_map_calc_cnt(struct q2t_prm *prm)
{
	int res = 0;

	sBUG_ON(prm->cmd->sg_cnt == 0);

	prm->sg = prm->cmd->sg;
	prm->seg_cnt = dma_map_sg(&prm->tgt->vha->hw->pdev->dev, prm->cmd->sg,
		prm->cmd->sg_cnt, prm->cmd->dma_data_direction);
	if (unlikely(prm->seg_cnt == 0))
		goto out_err;

	prm->cmd->sg_mapped = 1;

	/*
	 * If greater than four sg entries then we need to allocate
	 * the continuation entries
	 */
	if (prm->seg_cnt > prm->tgt->datasegs_per_cmd)
		prm->req_cnt += DIV_ROUND_UP(prm->seg_cnt - prm->tgt->datasegs_per_cmd,
					     prm->tgt->datasegs_per_cont);

out:
	TRACE_DBG("seg_cnt=%d, req_cnt=%d, res=%d", prm->seg_cnt,
		prm->req_cnt, res);
	return res;

out_err:
	PRINT_ERROR("qla2x00t(%ld): PCI mapping failed: sg_cnt=%d",
		prm->tgt->vha->host_no, prm->cmd->sg_cnt);
	res = -1;
	goto out;
}

static inline void q2t_unmap_sg(scsi_qla_host_t *vha, struct q2t_cmd *cmd)
{
	EXTRACHECKS_BUG_ON(!cmd->sg_mapped);
	dma_unmap_sg(&vha->hw->pdev->dev, cmd->sg, cmd->sg_cnt,
	    cmd->dma_data_direction);
	cmd->sg_mapped = 0;
}

static int q2t_check_reserve_free_req(scsi_qla_host_t *vha, uint32_t req_cnt)
{
	int res = SCST_TGT_RES_SUCCESS;
	struct qla_hw_data *ha = vha->hw;
	device_reg_t __iomem *reg = ha->iobase;
	uint32_t cnt;

	TRACE_ENTRY();

	if (vha->req->cnt < (req_cnt + 2)) {
		if (IS_FWI2_CAPABLE(ha))
			cnt = (uint16_t)RD_REG_DWORD(&reg->isp24.req_q_out);
		else
			cnt = qla2x00_debounce_register(
				    ISP_REQ_Q_OUT(ha, &reg->isp));

		TRACE_DBG("Request ring circled: cnt=%d, vha->->ring_index=%d, "
		    "vha->req->cnt=%d, req_cnt=%d\n", cnt,
		    vha->req->ring_index, vha->req->cnt, req_cnt);
		if  (vha->req->ring_index < cnt)
			vha->req->cnt = cnt - vha->req->ring_index;
		else
			vha->req->cnt = vha->req->length -
			    (vha->req->ring_index - cnt);

		if (unlikely(vha->req->cnt < (req_cnt + 2))) {
			TRACE(TRACE_OUT_OF_MEM,
			    "qla_target(%d): There is no room in the "
			    "request ring: vha->req->ring_index=%d, "
			    "vha->req->cnt=%d, req_cnt=%d\n", vha->vp_idx,
			    vha->req->ring_index, vha->req->cnt, req_cnt);
			res = SCST_TGT_RES_QUEUE_FULL;
			goto out;
		}
	}

	vha->req->cnt -= req_cnt;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static inline void *q2t_get_req_pkt(scsi_qla_host_t *vha)
{
	/* Adjust ring index. */
	vha->req->ring_index++;
	if (vha->req->ring_index == vha->req->length) {
		vha->req->ring_index = 0;
		vha->req->ring_ptr = vha->req->ring;
	} else {
		vha->req->ring_ptr++;
	}
	return (cont_entry_t *)vha->req->ring_ptr;
}

/* ha->hardware_lock supposed to be held on entry */
static inline uint32_t q2t_make_handle(scsi_qla_host_t *vha)
{
	uint32_t h;
	struct qla_hw_data *ha = vha->hw;

	h = vha->current_handle;
	/* always increment cmd handle */
	do {
		++h;
		if (h > MAX_OUTSTANDING_COMMANDS)
			h = 1; /* 0 is Q2T_NULL_HANDLE */
		if (h == vha->current_handle) {
			TRACE(TRACE_OUT_OF_MEM, "qla2x00t(%ld): Ran out of "
				"empty cmd slots in ha %p", vha->host_no, ha);
			h = Q2T_NULL_HANDLE;
			break;
		}
	} while ((h == Q2T_NULL_HANDLE) ||
		 (h == Q2T_SKIP_HANDLE) ||
		 (vha->cmds[h-1] != NULL));

	if (h != Q2T_NULL_HANDLE)
		vha->current_handle = h;

	return h;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2x_build_ctio_pkt(struct q2t_prm *prm)
{
	uint32_t h;
	ctio_entry_t *pkt;
	scsi_qla_host_t *vha = prm->tgt->vha;
	struct qla_hw_data *ha = vha->hw;

	pkt = (ctio_entry_t *)vha->req->ring_ptr;
	prm->pkt = pkt;
	memset(pkt, 0, sizeof(*pkt));

	if (ha->enable_64bit_addressing)
		pkt->common.entry_type = CTIO_A64_TYPE;
	else
		pkt->common.entry_type = CONTINUE_TGT_IO_TYPE;

	pkt->common.entry_count = (uint8_t)prm->req_cnt;

	h = q2t_make_handle(vha);
	if (h != Q2T_NULL_HANDLE)
		vha->cmds[h-1] = prm->cmd;

	pkt->common.handle = h | CTIO_COMPLETION_HANDLE_MARK;
	pkt->common.timeout = cpu_to_le16(Q2T_TIMEOUT);

	/* Set initiator ID */
	h = GET_TARGET_ID(ha, &prm->cmd->atio.atio2x);
	SET_TARGET_ID(ha, pkt->common.target, h);

	pkt->common.rx_id = prm->cmd->atio.atio2x.rx_id;
	pkt->common.relative_offset = cpu_to_le32(prm->cmd->offset);

	TRACE(TRACE_DEBUG|TRACE_SCSI, "qla2x00t(%ld): handle(scst_cmd) -> %08x, "
		"timeout %d L %#x -> I %#x E %#x", vha->host_no,
		pkt->common.handle, Q2T_TIMEOUT,
		le16_to_cpu(prm->cmd->atio.atio2x.lun),
		GET_TARGET_ID(ha, &pkt->common), pkt->common.rx_id);
}

/* ha->hardware_lock supposed to be held on entry */
static int q24_build_ctio_pkt(struct q2t_prm *prm)
{
	uint32_t h;
	ctio7_status0_entry_t *pkt;
	scsi_qla_host_t *vha = prm->tgt->vha;
	atio7_entry_t *atio = &prm->cmd->atio.atio7;
	int res = SCST_TGT_RES_SUCCESS;

	TRACE_ENTRY();

	pkt = (ctio7_status0_entry_t *)vha->req->ring_ptr;
	prm->pkt = pkt;
	memset(pkt, 0, sizeof(*pkt));

	pkt->common.entry_type = CTIO_TYPE7;
	pkt->common.entry_count = (uint8_t)prm->req_cnt;
	pkt->common.vp_index = vha->vp_idx;

	h = q2t_make_handle(vha);
	if (unlikely(h == Q2T_NULL_HANDLE)) {
		/*
		 * CTIO type 7 from the firmware doesn't provide a way to
		 * know the initiator's lood id, hence we can't find
		 * the session and, so, the command.
		 */
		res = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	} else
		vha->cmds[h-1] = prm->cmd;

	pkt->common.handle = h | CTIO_COMPLETION_HANDLE_MARK;
	pkt->common.nport_handle = cpu_to_le16(prm->cmd->loop_id);
	pkt->common.timeout = cpu_to_le16(Q2T_TIMEOUT);
	pkt->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	pkt->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	pkt->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	pkt->common.exchange_addr = atio->exchange_addr;
	pkt->flags |= (atio->attr << 9);
	pkt->ox_id = swab16(atio->fcp_hdr.ox_id);
	pkt->relative_offset = cpu_to_le32(prm->cmd->offset);

out:
	TRACE(TRACE_DEBUG|TRACE_SCSI, "qla2x00t(%ld): handle(scst_cmd) -> %08x, "
		"timeout %d, ox_id %#x", vha->host_no, pkt->common.handle,
		Q2T_TIMEOUT, le16_to_cpu(pkt->ox_id));
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * ha->hardware_lock supposed to be held on entry. We have already made sure
 * that there is sufficient amount of request entries to not drop it.
 */
static void q2t_load_cont_data_segments(struct q2t_prm *prm)
{
	int cnt;
	uint32_t *dword_ptr;
	int enable_64bit_addressing = prm->tgt->vha->hw->enable_64bit_addressing;

	TRACE_ENTRY();

	/* Build continuation packets */
	while (prm->seg_cnt > 0) {
		cont_a64_entry_t *cont_pkt64 =
			(cont_a64_entry_t *)q2t_get_req_pkt(prm->tgt->vha);

		/*
		 * Make sure that from cont_pkt64 none of
		 * 64-bit specific fields used for 32-bit
		 * addressing. Cast to (cont_entry_t *) for
		 * that.
		 */

		memset(cont_pkt64, 0, sizeof(*cont_pkt64));

		cont_pkt64->entry_count = 1;
		cont_pkt64->sys_define = 0;

		if (enable_64bit_addressing) {
			cont_pkt64->entry_type = CONTINUE_A64_TYPE;
			dword_ptr =
			    (uint32_t *)&cont_pkt64->dseg_0_address;
		} else {
			cont_pkt64->entry_type = CONTINUE_TYPE;
			dword_ptr =
			    (uint32_t *)&((cont_entry_t *)
					    cont_pkt64)->dseg_0_address;
		}

		/* Load continuation entry data segments */
		for (cnt = 0;
		     cnt < prm->tgt->datasegs_per_cont && prm->seg_cnt;
		     cnt++, prm->seg_cnt--) {
			dma_addr_t dma_addr = sg_dma_address(prm->sg);

			*dword_ptr++ = cpu_to_le32(pci_dma_lo32(dma_addr));
			if (enable_64bit_addressing)
				*dword_ptr++ = cpu_to_le32(pci_dma_hi32(dma_addr));
			*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

			TRACE_SG("S/G Segment Cont. phys_addr=%llx:%llx, len=%d",
			      (unsigned long long)pci_dma_hi32(dma_addr),
			      (unsigned long long)pci_dma_lo32(dma_addr),
			      (int)sg_dma_len(prm->sg));

			/* prm->sg might be last here */
			prm->sg = sg_next_inline(prm->sg);
		}

		TRACE_BUFFER("Continuation packet data",
			     cont_pkt64, REQUEST_ENTRY_SIZE);
	}

	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. We have already made sure
 * that there is sufficient amount of request entries to not drop it.
 */
static void q2x_load_data_segments(struct q2t_prm *prm)
{
	int cnt;
	uint32_t *dword_ptr;
	int enable_64bit_addressing = prm->tgt->vha->hw->enable_64bit_addressing;
	ctio_common_entry_t *pkt = (ctio_common_entry_t *)prm->pkt;

	TRACE_DBG("iocb->scsi_status=%x, iocb->flags=%x",
	      le16_to_cpu(pkt->scsi_status), le16_to_cpu(pkt->flags));

	pkt->transfer_length = cpu_to_le32(prm->cmd->bufflen);

	/* Setup packet address segment pointer */
	dword_ptr = pkt->dseg_0_address;

	if (prm->seg_cnt == 0) {
		/* No data transfer */
		*dword_ptr++ = 0;
		*dword_ptr = 0;

		TRACE_BUFFER("No data, CTIO packet data", pkt,
			REQUEST_ENTRY_SIZE);
		goto out;
	}

	/* Set total data segment count */
	pkt->dseg_count = cpu_to_le16(prm->seg_cnt);

	/* If scatter gather */
	TRACE_SG("%s", "Building S/G data segments...");
	/* Load command entry data segments */
	for (cnt = 0;
	     (cnt < prm->tgt->datasegs_per_cmd) && prm->seg_cnt;
	     cnt++, prm->seg_cnt--) {
		dma_addr_t dma_addr = sg_dma_address(prm->sg);

		*dword_ptr++ = cpu_to_le32(pci_dma_lo32(dma_addr));
		if (enable_64bit_addressing)
			*dword_ptr++ = cpu_to_le32(pci_dma_hi32(dma_addr));
		*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

		TRACE_SG("S/G Segment phys_addr=%llx:%llx, len=%d",
		      (unsigned long long)pci_dma_hi32(dma_addr),
		      (unsigned long long)pci_dma_lo32(dma_addr),
		      (int)sg_dma_len(prm->sg));

		/* prm->sg might be last here */
		prm->sg = sg_next_inline(prm->sg);
	}

	TRACE_BUFFER("Scatter/gather, CTIO packet data", pkt,
		REQUEST_ENTRY_SIZE);

	q2t_load_cont_data_segments(prm);

out:
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. We have already made sure
 * that there is sufficient amount of request entries to not drop it.
 */
static void q24_load_data_segments(struct q2t_prm *prm)
{
	int cnt;
	uint32_t *dword_ptr;
	int enable_64bit_addressing = prm->tgt->vha->hw->enable_64bit_addressing;
	ctio7_status0_entry_t *pkt = (ctio7_status0_entry_t *)prm->pkt;

	TRACE_DBG("iocb->scsi_status=%x, iocb->flags=%x",
	      le16_to_cpu(pkt->scsi_status), le16_to_cpu(pkt->flags));

	pkt->transfer_length = cpu_to_le32(prm->cmd->bufflen);

	/* Setup packet address segment pointer */
	dword_ptr = pkt->dseg_0_address;

	if (prm->seg_cnt == 0) {
		/* No data transfer */
		*dword_ptr++ = 0;
		*dword_ptr = 0;

		TRACE_BUFFER("No data, CTIO7 packet data", pkt,
			REQUEST_ENTRY_SIZE);
		goto out;
	}

	/* Set total data segment count */
	pkt->common.dseg_count = cpu_to_le16(prm->seg_cnt);

	/* If scatter gather */
	TRACE_SG("%s", "Building S/G data segments...");
	/* Load command entry data segments */
	for (cnt = 0; (cnt < prm->tgt->datasegs_per_cmd) && prm->seg_cnt;
					cnt++, prm->seg_cnt--) {
		dma_addr_t dma_addr = sg_dma_address(prm->sg);

		*dword_ptr++ = cpu_to_le32(pci_dma_lo32(dma_addr));
		if (enable_64bit_addressing)
			*dword_ptr++ = cpu_to_le32(pci_dma_hi32(dma_addr));
		*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

		TRACE_SG("S/G Segment phys_addr=%llx:%llx, len=%d",
		      (unsigned long long)pci_dma_hi32(dma_addr),
		      (unsigned long long)pci_dma_lo32(dma_addr),
		      (int)sg_dma_len(prm->sg));

		/* prm->sg might be last here */
		prm->sg = sg_next_inline(prm->sg);
	}

	q2t_load_cont_data_segments(prm);

out:
	return;
}

static inline int q2t_has_data(struct q2t_cmd *cmd)
{
	return cmd->bufflen > 0;
}

/*
 * Acquires ha->hardware lock and returns with the lock held when
 * the result == SCST_TGT_RES_SUCCESS. The lock is unlocked if an
 * error is returned.
 */
static int q2t_pre_xmit_response(struct q2t_cmd *cmd,
	struct q2t_prm *prm, int xmit_type, unsigned long *flags)
{
	int res;
	struct q2t_tgt *tgt = cmd->tgt;
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;
	uint16_t full_req_cnt;
	struct scst_cmd *scst_cmd = &cmd->scst_cmd;

	TRACE_ENTRY();

	if (unlikely(cmd->aborted)) {
		TRACE_MGMT_DBG("qla2x00t(%ld): terminating exchange "
			"for aborted cmd=%p (scst_cmd=%p, tag=%d)",
			vha->host_no, cmd, scst_cmd, cmd->tag);

		cmd->state = Q2T_STATE_ABORTED;
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);

		if (IS_FWI2_CAPABLE(ha))
			q24_send_term_exchange(vha, cmd, &cmd->atio.atio7, 0);
		else
			q2x_send_term_exchange(vha, cmd, &cmd->atio.atio2x, 0);
		/* !! At this point cmd could be already freed !! */
		res = Q2T_PRE_XMIT_RESP_CMD_ABORTED;
		goto out;
	}

	TRACE(TRACE_SCSI, "qla2x00t(%ld): tag=%lld", vha->host_no,
		scst_cmd_get_tag(scst_cmd));

	prm->cmd = cmd;
	prm->tgt = tgt;
	prm->rq_result = scst_cmd_get_status(scst_cmd);
	prm->sense_buffer = scst_cmd_get_sense_buffer(scst_cmd);
	prm->sense_buffer_len = scst_cmd_get_sense_buffer_len(scst_cmd);
	prm->sg = NULL;
	prm->seg_cnt = -1;
	prm->req_cnt = 1;
	prm->add_status_pkt = 0;

	TRACE_DBG("rq_result=%x, xmit_type=%x", prm->rq_result, xmit_type);
	if (prm->rq_result != 0)
		TRACE_BUFFER("Sense", prm->sense_buffer, prm->sense_buffer_len);

	/* Send marker if required */
	if (q2t_issue_marker(vha, 0) != QLA_SUCCESS) {
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out;
	}

	TRACE_DBG("CTIO start: vha(%d)", (int)vha->host_no);

	if ((xmit_type & Q2T_XMIT_DATA) && q2t_has_data(cmd)) {
		if  (q2t_pci_map_calc_cnt(prm) != 0) {
			res = SCST_TGT_RES_QUEUE_FULL;
			goto out;
		}
	}

	full_req_cnt = prm->req_cnt;

	if (xmit_type & Q2T_XMIT_STATUS) {
		/* Bidirectional transfers not supported (yet) */
		if (unlikely(scst_get_resid(scst_cmd, &prm->residual, NULL))) {
			if (prm->residual > 0) {
				TRACE_DBG("Residual underflow: %d (tag %lld, "
					"op %s, bufflen %d, rq_result %x)",
					prm->residual, scst_cmd->tag,
					scst_get_opcode_name(scst_cmd), cmd->bufflen,
					prm->rq_result);
				prm->rq_result |= SS_RESIDUAL_UNDER;
			} else if (prm->residual < 0) {
				TRACE_DBG("Residual overflow: %d (tag %lld, "
					"op %s, bufflen %d, rq_result %x)",
					prm->residual, scst_cmd->tag,
					scst_get_opcode_name(scst_cmd), cmd->bufflen,
					prm->rq_result);
				prm->rq_result |= SS_RESIDUAL_OVER;
				prm->residual = -prm->residual;
			}
		}

		/*
		 * If Q2T_XMIT_DATA is not set, add_status_pkt will be ignored
		 * in *xmit_response() below
		 */
		if (q2t_has_data(cmd)) {
			if (scst_sense_valid(prm->sense_buffer) ||
			    (IS_FWI2_CAPABLE(ha) &&
			     (prm->rq_result != 0))) {
				prm->add_status_pkt = 1;
				full_req_cnt++;
			}
		}
	}

	TRACE_DBG("req_cnt=%d, full_req_cnt=%d, add_status_pkt=%d",
		prm->req_cnt, full_req_cnt, prm->add_status_pkt);

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hardware_lock, *flags);

	/* Does F/W have an IOCBs for this request */
	res = q2t_check_reserve_free_req(vha, full_req_cnt);

	/* The following check must match the callers' assumptions */
	if (unlikely(res != SCST_TGT_RES_SUCCESS))
		goto out_unlock_free_unmap;

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock_free_unmap:
	if (cmd->sg_mapped)
		q2t_unmap_sg(vha, cmd);

	/* Release ring specific lock */
	spin_unlock_irqrestore(&ha->hardware_lock, *flags);
	goto out;
}

/*
 * Convert sense buffer (byte array) to little endian format as required by
 * qla24xx firmware.
 */
static void q24_copy_sense_buffer_to_ctio(ctio7_status1_entry_t *ctio,
	uint8_t *sense_buf, unsigned int sense_buf_len)
{
	uint32_t *src = (void *)sense_buf;
	uint32_t *end = (void *)sense_buf + sense_buf_len;
	uint8_t *p;
	__be32 *dst = (void *)ctio->sense_data;

	/*
	 * The sense buffer allocated by scst_alloc_sense() is zero-filled and
	 * has a length that is a multiple of four. This means that it is safe
	 * to access the bytes after the end of the sense buffer up to a
	 * boundary that is a multiple of four.
	 */
	for (p = (uint8_t *)end; ((uintptr_t)p & 3) != 0; p++)
		WARN_ONCE(*p != 0, "sense_buf[%zd] = %d\n", p - sense_buf, *p);

	for ( ; src < end; src++)
		*dst++ = cpu_to_be32(*src);
}

static inline int q2t_need_explicit_conf(scsi_qla_host_t *vha,
	struct q2t_cmd *cmd, int sending_sense)
{
	struct qla_hw_data *ha = vha->hw;

	if (ha->enable_class_2)
		return 0;

	if (sending_sense)
		return cmd->conf_compl_supported;
	else
		return vha->hw->enable_explicit_conf && cmd->conf_compl_supported;
}

static void q2x_init_ctio_ret_entry(ctio_ret_entry_t *ctio_m1,
	struct q2t_prm *prm)
{
	TRACE_ENTRY();

	prm->sense_buffer_len = min_t(uint32_t, prm->sense_buffer_len,
				      sizeof(ctio_m1->sense_data));

	ctio_m1->flags = cpu_to_le16(OF_SSTS | OF_FAST_POST |
				     OF_NO_DATA | OF_SS_MODE_1);
	ctio_m1->flags |= cpu_to_le16(OF_INC_RC);
	if (q2t_need_explicit_conf(prm->tgt->vha, prm->cmd, 0))
		ctio_m1->flags |= cpu_to_le16(OF_EXPL_CONF | OF_CONF_REQ);

	ctio_m1->scsi_status = cpu_to_le16(prm->rq_result);
	ctio_m1->residual = cpu_to_le32(prm->residual);
	if (scst_sense_valid(prm->sense_buffer)) {
		if (q2t_need_explicit_conf(prm->tgt->vha, prm->cmd, 1))
			ctio_m1->flags |= cpu_to_le16(OF_EXPL_CONF | OF_CONF_REQ);
		ctio_m1->scsi_status |= cpu_to_le16(SS_SENSE_LEN_VALID);
		ctio_m1->sense_length = cpu_to_le16(prm->sense_buffer_len);
		memcpy(ctio_m1->sense_data, prm->sense_buffer,
		       prm->sense_buffer_len);
	} else {
		memset(ctio_m1->sense_data, 0, sizeof(ctio_m1->sense_data));
		ctio_m1->sense_length = 0;
	}

	/* Sense with len > 26, is it possible ??? */

	TRACE_EXIT();
	return;
}

static int __q2x_xmit_response(struct q2t_cmd *cmd, int xmit_type)
{
	int res;
	unsigned long flags;
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha;
	struct q2t_prm prm;
	ctio_common_entry_t *pkt;

	TRACE_ENTRY();

	memset(&prm, 0, sizeof(prm));

	res = q2t_pre_xmit_response(cmd, &prm, xmit_type, &flags);
	if (unlikely(res != SCST_TGT_RES_SUCCESS)) {
		if (res == Q2T_PRE_XMIT_RESP_CMD_ABORTED)
			res = SCST_TGT_RES_SUCCESS;
		goto out;
	}

	/* Here ha->hardware_lock already locked */

	vha = prm.tgt->vha;
	ha = vha->hw;

	q2x_build_ctio_pkt(&prm);
	pkt = (ctio_common_entry_t *)prm.pkt;

	if (q2t_has_data(cmd) && (xmit_type & Q2T_XMIT_DATA)) {
		pkt->flags |= cpu_to_le16(OF_FAST_POST | OF_DATA_IN);
		pkt->flags |= cpu_to_le16(OF_INC_RC);

		q2x_load_data_segments(&prm);

		if (prm.add_status_pkt == 0) {
			if (xmit_type & Q2T_XMIT_STATUS) {
				pkt->scsi_status = cpu_to_le16(prm.rq_result);
				pkt->residual = cpu_to_le32(prm.residual);
				pkt->flags |= cpu_to_le16(OF_SSTS);
				if (q2t_need_explicit_conf(vha, cmd, 0)) {
					pkt->flags |= cpu_to_le16(
							OF_EXPL_CONF |
							OF_CONF_REQ);
				}
			}
		} else {
			/*
			 * We have already made sure that there is sufficient
			 * amount of request entries to not drop HW lock in
			 * req_pkt().
			 */
			ctio_ret_entry_t *ctio_m1 =
				(ctio_ret_entry_t *)q2t_get_req_pkt(vha);

			TRACE_DBG("%s", "Building additional status packet");

			memcpy(ctio_m1, pkt, sizeof(*ctio_m1));
			ctio_m1->entry_count = 1;
			ctio_m1->dseg_count = 0;

			/* Real finish is ctio_m1's finish */
			pkt->handle |= CTIO_INTERMEDIATE_HANDLE_MARK;
			pkt->flags &= ~cpu_to_le16(OF_INC_RC);

			q2x_init_ctio_ret_entry(ctio_m1, &prm);
			TRACE_BUFFER("Status CTIO packet data", ctio_m1,
				REQUEST_ENTRY_SIZE);
		}
	} else
		q2x_init_ctio_ret_entry((ctio_ret_entry_t *)pkt, &prm);

	cmd->state = Q2T_STATE_PROCESSED;	/* Mid-level is done processing */

	TRACE_BUFFER("Xmitting", pkt, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

	/* Release ring specific lock */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#ifdef CONFIG_QLA_TGT_DEBUG_SRR
static void q2t_check_srr_debug(struct q2t_cmd *cmd, int *xmit_type)
{
#if 0 /* This is not a real status packets lost, so it won't lead to SRR */
	if ((*xmit_type & Q2T_XMIT_STATUS) && (scst_random() % 200) == 50) {
		*xmit_type &= ~Q2T_XMIT_STATUS;
		TRACE_MGMT_DBG("Dropping cmd %p (tag %d) status", cmd,
			cmd->tag);
	}
#endif

	if (q2t_has_data(cmd) && (cmd->sg_cnt > 1) &&
	    ((scst_random() % 100) == 20)) {
		int i, leave = 0;
		unsigned int tot_len = 0;

		while (leave == 0)
			leave = scst_random() % cmd->sg_cnt;

		for (i = 0; i < leave; i++)
			tot_len += cmd->sg[i].length;

		TRACE_MGMT_DBG("Cutting cmd %p (tag %d) buffer tail to len %d, "
			"sg_cnt %d (cmd->bufflen %d, cmd->sg_cnt %d)", cmd,
			cmd->tag, tot_len, leave, cmd->bufflen, cmd->sg_cnt);

		cmd->bufflen = tot_len;
		cmd->sg_cnt = leave;
	}

	if (q2t_has_data(cmd) && ((scst_random() % 100) == 70)) {
		unsigned int offset = scst_random() % cmd->bufflen;

		TRACE_MGMT_DBG("Cutting cmd %p (tag %d) buffer head "
			"to offset %d (cmd->bufflen %d)", cmd, cmd->tag,
			offset, cmd->bufflen);
		if (offset == 0)
			*xmit_type &= ~Q2T_XMIT_DATA;
		else if (q2t_cut_cmd_data_head(cmd, offset)) {
			TRACE_MGMT_DBG("q2t_cut_cmd_data_head() failed (tag %d)",
				cmd->tag);
		}
	}
}
#else
static inline void q2t_check_srr_debug(struct q2t_cmd *cmd, int *xmit_type) {}
#endif

static int q2x_xmit_response(struct scst_cmd *scst_cmd)
{
	int xmit_type = Q2T_XMIT_DATA, res;
	int is_send_status = scst_cmd_get_is_send_status(scst_cmd);
	struct q2t_cmd *cmd = container_of(scst_cmd, struct q2t_cmd, scst_cmd);

#ifdef CONFIG_SCST_EXTRACHECKS
	sBUG_ON(!q2t_has_data(cmd) && !is_send_status);
#endif

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	EXTRACHECKS_BUG_ON(scst_cmd_atomic(scst_cmd));
#endif

	if (is_send_status)
		xmit_type |= Q2T_XMIT_STATUS;

	cmd->bufflen = scst_cmd_get_adjusted_resp_data_len(scst_cmd);
	cmd->sg = scst_cmd_get_sg(scst_cmd);
	cmd->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	cmd->data_direction = scst_cmd_get_data_direction(scst_cmd);
	cmd->dma_data_direction = scst_to_tgt_dma_dir(cmd->data_direction);
	cmd->offset = scst_cmd_get_ppl_offset(scst_cmd);
	cmd->aborted = scst_cmd_aborted_on_xmit(scst_cmd);

	q2t_check_srr_debug(cmd, &xmit_type);

	TRACE_DBG("is_send_status=%x, cmd->bufflen=%d, cmd->sg_cnt=%d, "
		"cmd->data_direction=%d", is_send_status, cmd->bufflen,
		cmd->sg_cnt, cmd->data_direction);

	if (IS_FWI2_CAPABLE(cmd->tgt->vha->hw))
		res = __q24_xmit_response(cmd, xmit_type);
	else
		res = __q2x_xmit_response(cmd, xmit_type);

	return res;
}

static void q24_init_ctio_ret_entry(ctio7_status0_entry_t *ctio,
	struct q2t_prm *prm)
{
	ctio7_status1_entry_t *ctio1;

	TRACE_ENTRY();

	prm->sense_buffer_len = min_t(uint32_t, prm->sense_buffer_len,
				      sizeof(ctio1->sense_data));
	ctio->flags |= cpu_to_le16(CTIO7_FLAGS_SEND_STATUS);
	if (q2t_need_explicit_conf(prm->tgt->vha, prm->cmd, 0)) {
		ctio->flags |= cpu_to_le16(CTIO7_FLAGS_EXPLICIT_CONFORM |
					   CTIO7_FLAGS_CONFORM_REQ);
	}
	ctio->residual = cpu_to_le32(prm->residual);
	ctio->scsi_status = cpu_to_le16(prm->rq_result);
	if (scst_sense_valid(prm->sense_buffer)) {
		ctio1 = (ctio7_status1_entry_t *)ctio;
		if (q2t_need_explicit_conf(prm->tgt->vha, prm->cmd, 1)) {
			ctio1->flags |= cpu_to_le16(
				CTIO7_FLAGS_EXPLICIT_CONFORM |
				CTIO7_FLAGS_CONFORM_REQ);
		}
		ctio1->flags &= ~cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_0);
		ctio1->flags |= cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_1);
		ctio1->scsi_status |= cpu_to_le16(SS_SENSE_LEN_VALID);
		ctio1->sense_length = cpu_to_le16(prm->sense_buffer_len);
		q24_copy_sense_buffer_to_ctio(ctio1, prm->sense_buffer,
					      prm->sense_buffer_len);
	} else {
		ctio1 = (ctio7_status1_entry_t *)ctio;
		ctio1->flags &= ~cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_0);
		ctio1->flags |= cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_1);
		ctio1->sense_length = 0;
		memset(ctio1->sense_data, 0, sizeof(ctio1->sense_data));
	}

	/* Sense with len > 24, is it possible ??? */

	TRACE_EXIT();
	return;
}

static int __q24_xmit_response(struct q2t_cmd *cmd, int xmit_type)
{
	int res;
	unsigned long flags;
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha;
	struct q2t_prm prm;
	ctio7_status0_entry_t *pkt;

	TRACE_ENTRY();

	memset(&prm, 0, sizeof(prm));

	res = q2t_pre_xmit_response(cmd, &prm, xmit_type, &flags);
	if (unlikely(res != SCST_TGT_RES_SUCCESS)) {
		if (res == Q2T_PRE_XMIT_RESP_CMD_ABORTED)
			res = SCST_TGT_RES_SUCCESS;
		goto out;
	}

	/* Here ha->hardware_lock already locked */

	vha = prm.tgt->vha;
	ha = vha->hw;

	res = q24_build_ctio_pkt(&prm);
	if (unlikely(res != SCST_TGT_RES_SUCCESS))
		goto out_unmap_unlock;

	pkt = (ctio7_status0_entry_t *)prm.pkt;

	if (q2t_has_data(cmd) && (xmit_type & Q2T_XMIT_DATA)) {
		pkt->flags |= cpu_to_le16(CTIO7_FLAGS_DATA_IN |
					CTIO7_FLAGS_STATUS_MODE_0);

		q24_load_data_segments(&prm);

		if (prm.add_status_pkt == 0) {
			if (xmit_type & Q2T_XMIT_STATUS) {
				pkt->scsi_status = cpu_to_le16(prm.rq_result);
				pkt->residual = cpu_to_le32(prm.residual);
				pkt->flags |= cpu_to_le16(
						CTIO7_FLAGS_SEND_STATUS);
				if (q2t_need_explicit_conf(vha, cmd, 0)) {
					pkt->flags |= cpu_to_le16(
						CTIO7_FLAGS_EXPLICIT_CONFORM |
						CTIO7_FLAGS_CONFORM_REQ);
				}
			}
		} else {
			/*
			 * We have already made sure that there is sufficient
			 * amount of request entries to not drop HW lock in
			 * req_pkt().
			 */
			ctio7_status1_entry_t *ctio =
				(ctio7_status1_entry_t *)q2t_get_req_pkt(vha);

			TRACE_DBG("%s", "Building additional status packet");

			memcpy(ctio, pkt, sizeof(*ctio));
			ctio->common.entry_count = 1;
			ctio->common.dseg_count = 0;
			ctio->flags &= ~cpu_to_le16(CTIO7_FLAGS_DATA_IN);

			/* Real finish is ctio_m1's finish */
			pkt->common.handle |= CTIO_INTERMEDIATE_HANDLE_MARK;
			pkt->flags |= cpu_to_le16(CTIO7_FLAGS_DONT_RET_CTIO);
			q24_init_ctio_ret_entry((ctio7_status0_entry_t *)ctio,
							&prm);
			TRACE_BUFFER("Status CTIO7", ctio, REQUEST_ENTRY_SIZE);
		}
	} else
		q24_init_ctio_ret_entry(pkt, &prm);

	cmd->state = Q2T_STATE_PROCESSED;	/* Mid-level is done processing */

	TRACE_BUFFER("Xmitting CTIO7", pkt, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out_unlock:
	/* Release ring specific lock */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unmap_unlock:
	if (cmd->sg_mapped)
		q2t_unmap_sg(vha, cmd);
	goto out_unlock;
}

static int __q2t_rdy_to_xfer(struct q2t_cmd *cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	unsigned long flags;
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha;
	struct q2t_tgt *tgt = cmd->tgt;
	struct q2t_prm prm;
	void *p;

	TRACE_ENTRY();

	memset(&prm, 0, sizeof(prm));
	prm.cmd = cmd;
	prm.tgt = tgt;
	prm.sg = NULL;
	prm.req_cnt = 1;
	vha = tgt->vha;
	ha = vha->hw;

	/* Send marker if required */
	if (q2t_issue_marker(vha, 0) != QLA_SUCCESS) {
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out;
	}

	TRACE_DBG("CTIO_start: vha(%d)", (int)vha->host_no);

	/* Calculate number of entries and segments required */
	if (q2t_pci_map_calc_cnt(&prm) != 0) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Does F/W have an IOCBs for this request */
	res = q2t_check_reserve_free_req(vha, prm.req_cnt);
	if (res != SCST_TGT_RES_SUCCESS)
		goto out_unlock_free_unmap;

	if (IS_FWI2_CAPABLE(ha)) {
		ctio7_status0_entry_t *pkt;

		res = q24_build_ctio_pkt(&prm);
		if (unlikely(res != SCST_TGT_RES_SUCCESS))
			goto out_unlock_free_unmap;
		pkt = (ctio7_status0_entry_t *)prm.pkt;
		pkt->flags |= cpu_to_le16(CTIO7_FLAGS_DATA_OUT |
				CTIO7_FLAGS_STATUS_MODE_0);
		q24_load_data_segments(&prm);
		p = pkt;
	} else {
		ctio_common_entry_t *pkt;

		q2x_build_ctio_pkt(&prm);
		pkt = (ctio_common_entry_t *)prm.pkt;
		pkt->flags = cpu_to_le16(OF_FAST_POST | OF_DATA_OUT);
		q2x_load_data_segments(&prm);
		p = pkt;
	}

	cmd->state = Q2T_STATE_NEED_DATA;

	TRACE_BUFFER("Xfering", p, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out_unlock:
	/* Release ring specific lock */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock_free_unmap:
	if (cmd->sg_mapped)
		q2t_unmap_sg(vha, cmd);
	goto out_unlock;
}

static int q2t_rdy_to_xfer(struct scst_cmd *scst_cmd)
{
	int res;
	struct q2t_cmd *cmd;

	TRACE_ENTRY();

	TRACE(TRACE_SCSI, "qla2x00t: tag=%lld", scst_cmd_get_tag(scst_cmd));

	cmd = container_of(scst_cmd, struct q2t_cmd, scst_cmd);
	cmd->bufflen = scst_cmd_get_write_fields(scst_cmd, &cmd->sg,
		&cmd->sg_cnt);
	cmd->data_direction = scst_cmd_get_data_direction(scst_cmd);
	cmd->dma_data_direction = scst_to_tgt_dma_dir(cmd->data_direction);

	res = __q2t_rdy_to_xfer(cmd);

	TRACE_EXIT();
	return res;
}

/* If hardware_lock held on entry, might drop it, then reacquire */
static void q2x_send_term_exchange(scsi_qla_host_t *vha, struct q2t_cmd *cmd,
	atio_entry_t *atio, int ha_locked)
{
	ctio_ret_entry_t *ctio;
	unsigned long flags = 0; /* to stop compiler's warning */
	int do_tgt_cmd_done = 0;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_DBG("Sending TERM EXCH CTIO (vha=%p)", vha);

	/* Send marker if required */
	if (q2t_issue_marker(vha, ha_locked) != QLA_SUCCESS)
		goto out;

	if (!ha_locked)
		spin_lock_irqsave(&ha->hardware_lock, flags);

	ctio = (ctio_ret_entry_t *)q2t_req_pkt(vha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out_unlock;
	}

	ctio->entry_type = CTIO_RET_TYPE;
	ctio->entry_count = 1;
	if (cmd != NULL) {
		if (cmd->state < Q2T_STATE_PROCESSED) {
			PRINT_ERROR("qla2x00t(%ld): Terminating cmd %p with "
				"incorrect state %d", vha->host_no, cmd,
				cmd->state);
		} else
			do_tgt_cmd_done = 1;
	}
	ctio->handle = Q2T_SKIP_HANDLE | CTIO_COMPLETION_HANDLE_MARK;

	/* Set IDs */
	SET_TARGET_ID(ha, ctio->target, GET_TARGET_ID(ha, atio));
	ctio->rx_id = atio->rx_id;

	/* Most likely, it isn't needed */
	ctio->residual = atio->data_length;
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	ctio->flags = cpu_to_le16(OF_FAST_POST | OF_TERM_EXCH |
					     OF_NO_DATA | OF_SS_MODE_1);
	ctio->flags |= cpu_to_le16(OF_INC_RC);

	TRACE_BUFFER("CTIO TERM EXCH packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out_unlock:
	if (!ha_locked)
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (do_tgt_cmd_done) {
		scst_tgt_cmd_done(&cmd->scst_cmd, SCST_CONTEXT_THREAD);
		/* !! At this point cmd could be already freed !! */
	}

out:
	TRACE_EXIT();
	return;
}

/* If hardware_lock held on entry, might drop it, then reacquire */
static void q24_send_term_exchange(scsi_qla_host_t *vha, struct q2t_cmd *cmd,
	atio7_entry_t *atio, int ha_locked)
{
	ctio7_status1_entry_t *ctio;
	unsigned long flags = 0; /* to stop compiler's warning */
	int do_tgt_cmd_done = 0;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_DBG("Sending TERM EXCH CTIO7 (vha=%p)", vha);

	/* Send marker if required */
	if (q2t_issue_marker(vha, ha_locked) != QLA_SUCCESS)
		goto out;

	if (!ha_locked)
		spin_lock_irqsave(&ha->hardware_lock, flags);

	ctio = (ctio7_status1_entry_t *)q2t_req_pkt(vha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out_unlock;
	}

	ctio->common.entry_type = CTIO_TYPE7;
	ctio->common.entry_count = 1;
	if (cmd != NULL) {
		ctio->common.nport_handle = cmd->loop_id;
		if (cmd->state < Q2T_STATE_PROCESSED) {
			PRINT_ERROR("qla2x00t(%ld): Terminating cmd %p with "
				"incorrect state %d", vha->host_no, cmd,
				 cmd->state);
		} else
			do_tgt_cmd_done = 1;
	} else
		ctio->common.nport_handle = CTIO7_NHANDLE_UNRECOGNIZED;
	ctio->common.handle = Q2T_SKIP_HANDLE |	CTIO_COMPLETION_HANDLE_MARK;
	ctio->common.timeout = cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.vp_index = vha->vp_idx;
	ctio->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	ctio->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	ctio->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	ctio->common.exchange_addr = atio->exchange_addr;
	ctio->flags = (atio->attr << 9) | cpu_to_le16(
		CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_TERMINATE);
	ctio->ox_id = swab16(atio->fcp_hdr.ox_id);

	/* Most likely, it isn't needed */
	ctio->residual = get_unaligned((uint32_t *)
			&atio->fcp_cmnd.add_cdb[atio->fcp_cmnd.add_cdb_len]);
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	TRACE_BUFFER("CTIO7 TERM EXCH packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out_unlock:
	if (!ha_locked)
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (do_tgt_cmd_done) {
		scst_tgt_cmd_done(&cmd->scst_cmd, SCST_CONTEXT_THREAD);
		/* !! At this point cmd could be already freed !! */
	}

out:
	TRACE_EXIT();
	return;
}

static inline void q2t_free_cmd(struct q2t_cmd *cmd)
{
	EXTRACHECKS_BUG_ON(cmd->sg_mapped);

	if (unlikely(cmd->free_sg))
		kfree(cmd->sg);
	kmem_cache_free(q2t_cmd_cachep, cmd);
}

static void q2t_on_free_cmd(struct scst_cmd *scst_cmd)
{
	struct q2t_cmd *cmd;

	TRACE_ENTRY();

	TRACE(TRACE_SCSI, "qla2x00t: Freeing command %p, tag %lld",
		scst_cmd, scst_cmd_get_tag(scst_cmd));

	cmd = container_of(scst_cmd, struct q2t_cmd, scst_cmd);

	q2t_free_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_prepare_srr_ctio(scsi_qla_host_t *vha, struct q2t_cmd *cmd,
	void *ctio)
{
	struct srr_ctio *sc;
	struct q2t_tgt *tgt = vha->tgt;
	int res = 0;
	struct srr_imm *imm;

	tgt->ctio_srr_id++;

	TRACE_MGMT_DBG("qla2x00t(%ld): CTIO with SRR "
		"status received", vha->host_no);

	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): SRR CTIO, "
			"but ctio is NULL", vha->host_no);
		res = -EINVAL;
		goto out;
	}

	scst_update_hw_pending_start(&cmd->scst_cmd);

	sc = kzalloc(sizeof(*sc), GFP_ATOMIC);
	if (sc != NULL) {
		sc->cmd = cmd;
		/* IRQ is already OFF */
		spin_lock(&tgt->srr_lock);
		sc->srr_id = tgt->ctio_srr_id;
		list_add_tail(&sc->srr_list_entry,
			&tgt->srr_ctio_list);
		TRACE_MGMT_DBG("CTIO SRR %p added (id %d)",
			sc, sc->srr_id);
		if (tgt->imm_srr_id == tgt->ctio_srr_id) {
			int found = 0;

			list_for_each_entry(imm, &tgt->srr_imm_list,
					srr_list_entry) {
				if (imm->srr_id == sc->srr_id) {
					found = 1;
					break;
				}
			}
			if (found) {
				TRACE_MGMT_DBG("%s", "Scheduling srr work");
				schedule_work(&tgt->srr_work);
			} else {
				PRINT_ERROR("qla2x00t(%ld): imm_srr_id "
					"== ctio_srr_id (%d), but there is no "
					"corresponding SRR IMM, deleting CTIO "
					"SRR %p", vha->host_no,	tgt->ctio_srr_id,
					sc);
				list_del(&sc->srr_list_entry);
				spin_unlock(&tgt->srr_lock);

				kfree(sc);
				res = -EINVAL;
				goto out;
			}
		}
		spin_unlock(&tgt->srr_lock);
	} else {
		struct srr_imm *ti;

		PRINT_ERROR("qla2x00t(%ld): Unable to allocate SRR CTIO entry",
			vha->host_no);
		spin_lock(&tgt->srr_lock);
		list_for_each_entry_safe(imm, ti, &tgt->srr_imm_list,
					srr_list_entry) {
			if (imm->srr_id == tgt->ctio_srr_id) {
				TRACE_MGMT_DBG("IMM SRR %p deleted "
					"(id %d)", imm, imm->srr_id);
				list_del(&imm->srr_list_entry);
				q2t_reject_free_srr_imm(vha, imm, 1);
			}
		}
		spin_unlock(&tgt->srr_lock);
		res = -ENOMEM;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static bool q2t_term_ctio_exchange(scsi_qla_host_t *vha, void *ctio,
	struct q2t_cmd *cmd, uint32_t status)
{
	bool term = false;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	if (IS_FWI2_CAPABLE(ha)) {
		if (cmd == NULL) {
			/*
			 * We can't get loop id from CTIO7 and
			 * ATIO7 from NULL cmd.
			 */
			goto out;
		}
		if (ctio != NULL) {
			ctio7_fw_entry_t *c = (ctio7_fw_entry_t *)ctio;

			term = !(c->flags & cpu_to_le16(OF_TERM_EXCH));
		} else
			term = true;
		if (term)
			q24_send_term_exchange(vha, cmd, &cmd->atio.atio7, 1);
	} else {
		if (status != CTIO_SUCCESS)
			q2x_modify_command_count(vha, 1, 0);
#if 0 /* Seems, it isn't needed. If enable it, add support for NULL cmd! */
		if (ctio != NULL) {
			ctio_common_entry_t *c = (ctio_common_entry_t *)ctio;

			term = !(c->flags & cpu_to_le16(CTIO7_FLAGS_TERMINATE));
		} else
			term = true;
		if (term)
			q2x_send_term_exchange(ha, cmd, &cmd->atio.atio2x, 1);
#endif
	}

out:
	TRACE_EXIT_RES(term);
	return term;
}

/* ha->hardware_lock supposed to be held on entry */
static inline struct q2t_cmd *q2t_get_cmd(scsi_qla_host_t *vha, uint32_t handle)
{
	handle--;
	if (vha->cmds[handle] != NULL) {
		struct q2t_cmd *cmd = vha->cmds[handle];

		vha->cmds[handle] = NULL;
		return cmd;
	} else
		return NULL;
}

/* ha->hardware_lock supposed to be held on entry */
static struct q2t_cmd *q2t_ctio_to_cmd(scsi_qla_host_t *vha, uint32_t handle,
	void *ctio)
{
	struct q2t_cmd *cmd = NULL;
	struct qla_hw_data *ha = vha->hw;

	/* Clear out internal marks */
	handle &= ~(CTIO_COMPLETION_HANDLE_MARK | CTIO_INTERMEDIATE_HANDLE_MARK);

	if (handle != Q2T_NULL_HANDLE) {
#ifndef __COVERITY__
		/*
		 * Although the code below is never reached we want to keep it.
		 * The #ifndef __COVERITY__ construct avoids that Coveritiy
		 * reports that the code below is dead.
		 */
		if (unlikely(handle == Q2T_SKIP_HANDLE)) {
			TRACE_DBG("%s", "SKIP_HANDLE CTIO");
			goto out;
		}
#endif
		/* handle-1 is actually used */
		if (unlikely(handle > MAX_OUTSTANDING_COMMANDS)) {
			PRINT_ERROR("qla2x00t(%ld): Wrong handle %x "
				"received", vha->host_no, handle);
			goto out;
		}
		cmd = q2t_get_cmd(vha, handle);
		if (unlikely(cmd == NULL)) {
			PRINT_WARNING("qla2x00t(%ld): Suspicious: unable to "
				   "find the command with handle %x",
				   vha->host_no, handle);
			goto out;
		}
	} else if (ctio != NULL) {
		uint16_t loop_id;
		int tag;
		struct q2t_sess *sess;
		struct scst_cmd *scst_cmd;

		if (IS_FWI2_CAPABLE(ha)) {
			/* We can't get loop id from CTIO7 */
			PRINT_ERROR("qla2x00t(%ld): Wrong CTIO received: "
				"QLA24xx doesn't support NULL handles",
				vha->host_no);
			goto out;
		} else {
			ctio_common_entry_t *c = (ctio_common_entry_t *)ctio;

			loop_id = GET_TARGET_ID(ha, c);
			tag = c->rx_id;
		}

		sess = q2t_find_sess_by_loop_id(vha->tgt, loop_id);
		if (sess == NULL) {
			PRINT_WARNING("qla2x00t(%ld): Suspicious: "
				   "ctio_completion for non-existing session "
				   "(loop_id %d, tag %d)",
				   vha->host_no, loop_id, tag);
			goto out;
		}

		scst_cmd = scst_find_cmd_by_tag(sess->scst_sess, tag);
		if (scst_cmd == NULL) {
			PRINT_WARNING("qla2x00t(%ld): Suspicious: unable to "
			     "find the command with tag %d (loop_id %d)",
			     vha->host_no, tag, loop_id);
			goto out;
		}

		cmd = container_of(scst_cmd, struct q2t_cmd, scst_cmd);
		TRACE_DBG("Found q2t_cmd %p (tag %d)", cmd, tag);
	}

out:
	return cmd;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q2t_do_ctio_completion(scsi_qla_host_t *vha, uint32_t handle,
	uint32_t status, void *ctio)
{
	struct scst_cmd *scst_cmd;
	struct q2t_cmd *cmd;
	enum scst_exec_context context;

	TRACE_ENTRY();

#if 1	/*
	 * We can't do anything better, because DLM PR sync code calls
	 * mutex_lock() on this path
	 */
	context = SCST_CONTEXT_THREAD;
#else
#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif
#endif

	TRACE(TRACE_DEBUG|TRACE_SCSI, "qla2x00t(%ld): handle(ctio %p "
		"status %#x) <- %08x", vha->host_no, ctio, status, handle);

	if (handle & CTIO_INTERMEDIATE_HANDLE_MARK) {
		/* That could happen only in case of an error/reset/abort */
		if (status != CTIO_SUCCESS) {
			TRACE_MGMT_DBG("Intermediate CTIO received (status %x)",
				status);
		}
		goto out;
	}

	cmd = q2t_ctio_to_cmd(vha, handle, ctio);
	if (cmd == NULL) {
		if (status != CTIO_SUCCESS)
			q2t_term_ctio_exchange(vha, ctio, NULL, status);
		goto out;
	}

	scst_cmd = &cmd->scst_cmd;

	if (cmd->sg_mapped)
		q2t_unmap_sg(vha, cmd);

	if (unlikely(status != CTIO_SUCCESS)) {
		switch (status & 0xFFFF) {
		case CTIO_LIP_RESET:
		case CTIO_TARGET_RESET:
		case CTIO_ABORTED:
		case CTIO_TIMEOUT:
		case CTIO_INVALID_RX_ID:
			/* They are OK */
			TRACE(TRACE_MINOR_AND_MGMT_DBG,
				"qla2x00t(%ld): CTIO with "
				"status %#x received, state %x, scst_cmd %p, "
				"op %s (LIP_RESET=e, ABORTED=2, TARGET_RESET=17, "
				"TIMEOUT=b, INVALID_RX_ID=8)", vha->host_no,
				status, cmd->state, scst_cmd, scst_get_opcode_name(scst_cmd));
			break;

		case CTIO_PORT_LOGGED_OUT:
		case CTIO_PORT_UNAVAILABLE:
			PRINT_INFO("qla2x00t(%ld): CTIO with PORT LOGGED "
				"OUT (29) or PORT UNAVAILABLE (28) status %x "
				"received (state %x, scst_cmd %p, op %s)",
				vha->host_no, status, cmd->state, scst_cmd,
				scst_get_opcode_name(scst_cmd));
			break;

		case CTIO_SRR_RECEIVED:
			if (q2t_prepare_srr_ctio(vha, cmd, ctio) != 0)
				break;
			else
				goto out;

		default:
			PRINT_ERROR("qla2x00t(%ld): CTIO with error status "
				"0x%x received (state %x, scst_cmd %p, op %s)",
				vha->host_no, status, cmd->state, scst_cmd,
				scst_get_opcode_name(scst_cmd));
			break;
		}

		if (cmd->state != Q2T_STATE_NEED_DATA)
			if (q2t_term_ctio_exchange(vha, ctio, cmd, status))
				goto out;
	}

	if (cmd->state == Q2T_STATE_PROCESSED) {
		TRACE_DBG("Command %p finished", cmd);
	} else if (cmd->state == Q2T_STATE_NEED_DATA) {
		int rx_status = SCST_RX_STATUS_SUCCESS;

		cmd->state = Q2T_STATE_DATA_IN;

		if (unlikely(status != CTIO_SUCCESS)) {
			scst_set_cmd_error(&cmd->scst_cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
			rx_status = SCST_RX_STATUS_ERROR_SENSE_SET;
		} else
			cmd->write_data_transferred = 1;

		TRACE_DBG("Data received, context %x, rx_status %d",
		      context, rx_status);

		scst_rx_data(scst_cmd, rx_status, context);
		goto out;
	} else if (cmd->state == Q2T_STATE_ABORTED) {
		TRACE_MGMT_DBG("Aborted command %p (tag %d) finished", cmd,
			cmd->tag);
	} else {
		PRINT_ERROR("qla2x00t(%ld): A command in state (%d) should "
			"not return a CTIO complete", vha->host_no, cmd->state);
	}

	if (unlikely(status != CTIO_SUCCESS)) {
		TRACE_MGMT_DBG("%s", "Finishing failed CTIO");
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
	}

	scst_tgt_cmd_done(scst_cmd, context);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q2x_ctio_completion(scsi_qla_host_t *vha, uint32_t handle)
{
	struct q2t_tgt *tgt = vha->tgt;

	TRACE_ENTRY();

	if (likely(tgt != NULL)) {
		tgt->irq_cmd_count++;
		q2t_do_ctio_completion(vha, handle, CTIO_SUCCESS, NULL);
		tgt->irq_cmd_count--;
	} else {
		TRACE_DBG("CTIO, but target mode not enabled (vha %p handle "
			"%#x)", vha, handle);
	}

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2x_do_send_cmd_to_scst(struct q2t_cmd *cmd)
{
	int res;
	struct q2t_sess *sess = cmd->sess;
	uint16_t lun;
	atio_entry_t *atio = &cmd->atio.atio2x;
	scst_data_direction dir;
	int context;

	TRACE_ENTRY();

	/* make it be in network byte order */
	lun = swab16(le16_to_cpu(atio->lun));
	res = scst_rx_cmd_prealloced(&cmd->scst_cmd, sess->scst_sess,
				(uint8_t *)&lun, sizeof(lun), atio->cdb,
				Q2T_MAX_CDB_LEN, SCST_ATOMIC);
	if (res != 0)
		goto out;

	cmd->tag = atio->rx_id;
	scst_cmd_set_tag(&cmd->scst_cmd, cmd->tag);

	if ((atio->execution_codes & (ATIO_EXEC_READ | ATIO_EXEC_WRITE)) ==
				(ATIO_EXEC_READ | ATIO_EXEC_WRITE))
		dir = SCST_DATA_BIDI;
	else if (atio->execution_codes & ATIO_EXEC_READ)
		dir = SCST_DATA_READ;
	else if (atio->execution_codes & ATIO_EXEC_WRITE)
		dir = SCST_DATA_WRITE;
	else
		dir = SCST_DATA_NONE;
	scst_cmd_set_expected(&cmd->scst_cmd, dir,
		le32_to_cpu(atio->data_length));

	switch (atio->task_codes) {
	case ATIO_SIMPLE_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case ATIO_HEAD_OF_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case ATIO_ORDERED_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case ATIO_ACA_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_ACA);
		break;
	case ATIO_UNTAGGED:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	default:
		PRINT_WARNING("qla2x00t: unknown task code %x, use "
			"ORDERED instead", atio->task_codes);
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif

	TRACE_DBG("Context %x", context);
	TRACE(TRACE_SCSI, "qla2x00t: START Command (tag %d, queue_type %d)",
		cmd->tag, scst_cmd_get_queue_type(&cmd->scst_cmd));
	scst_cmd_init_done(&cmd->scst_cmd, context);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static int q24_do_send_cmd_to_scst(struct q2t_cmd *cmd)
{
	int res;
	struct q2t_sess *sess = cmd->sess;
	atio7_entry_t *atio = &cmd->atio.atio7;
	scst_data_direction dir;
	int context;

	TRACE_ENTRY();

	res = scst_rx_cmd_prealloced(&cmd->scst_cmd, sess->scst_sess,
		(uint8_t *)&atio->fcp_cmnd.lun, sizeof(atio->fcp_cmnd.lun),
		atio->fcp_cmnd.cdb, sizeof(atio->fcp_cmnd.cdb) +
			atio->fcp_cmnd.add_cdb_len, SCST_ATOMIC);
	if (res != 0)
		goto out;

	cmd->tag = atio->exchange_addr;
	scst_cmd_set_tag(&cmd->scst_cmd, cmd->tag);

	if (atio->fcp_cmnd.rddata && atio->fcp_cmnd.wrdata)
		dir = SCST_DATA_BIDI;
	else if (atio->fcp_cmnd.rddata)
		dir = SCST_DATA_READ;
	else if (atio->fcp_cmnd.wrdata)
		dir = SCST_DATA_WRITE;
	else
		dir = SCST_DATA_NONE;
	scst_cmd_set_expected(&cmd->scst_cmd, dir,
		be32_to_cpu(get_unaligned((uint32_t *)&atio->fcp_cmnd.add_cdb[
					atio->fcp_cmnd.add_cdb_len])));

	switch (atio->fcp_cmnd.task_attr) {
	case ATIO_SIMPLE_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case ATIO_HEAD_OF_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case ATIO_ORDERED_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case ATIO_ACA_QUEUE:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_ACA);
		break;
	case ATIO_UNTAGGED:
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	default:
		PRINT_WARNING("qla2x00t: unknown task code %x, use "
			"ORDERED instead", atio->fcp_cmnd.task_attr);
		scst_cmd_set_queue_type(&cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif

	TRACE_DBG("Context %x", context);
	TRACE(TRACE_SCSI, "qla2x00t: START Command %p (tag %d, queue type %x)",
		cmd, cmd->tag, scst_cmd_get_queue_type(&cmd->scst_cmd));
	scst_cmd_init_done(&cmd->scst_cmd, context);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_do_send_cmd_to_scst(scsi_qla_host_t *vha,
	struct q2t_cmd *cmd, struct q2t_sess *sess)
{
	int res;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	cmd->sess = sess;
	cmd->loop_id = sess->loop_id;
	cmd->conf_compl_supported = sess->conf_compl_supported;

	if (IS_FWI2_CAPABLE(ha))
		res = q24_do_send_cmd_to_scst(cmd);
	else
		res = q2x_do_send_cmd_to_scst(cmd);

	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_send_cmd_to_scst(scsi_qla_host_t *vha, atio_t *atio)
{
	int res = 0;
	struct q2t_tgt *tgt = vha->tgt;
	struct q2t_sess *sess;
	struct q2t_cmd *cmd;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	if (unlikely(tgt->tgt_stop)) {
		TRACE_MGMT_DBG("New command while device %p is shutting "
			"down", tgt);
		res = -EFAULT;
		goto out;
	}

	cmd = kmem_cache_zalloc(q2t_cmd_cachep, GFP_ATOMIC);
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "qla2x00t(%ld): Allocation of cmd "
			"failed", vha->host_no);
		res = -ENOMEM;
		goto out;
	}

	memcpy(&cmd->atio.atio2x, atio, sizeof(*atio));
	cmd->state = Q2T_STATE_NEW;
	cmd->tgt = vha->tgt;

	if (IS_FWI2_CAPABLE(ha)) {
		atio7_entry_t *a = (atio7_entry_t *)atio;

		sess = q2t_find_sess_by_s_id(tgt, a->fcp_hdr.s_id);
		if (unlikely(sess == NULL)) {
			TRACE_MGMT_DBG("qla2x00t(%ld): Unable to find "
				"wwn login (s_id %x:%x:%x), trying to create "
				"it manually", vha->host_no,
				a->fcp_hdr.s_id[0], a->fcp_hdr.s_id[1],
				a->fcp_hdr.s_id[2]);
			goto out_sched;
		}
	} else {
		sess = q2t_find_sess_by_loop_id(tgt,
			GET_TARGET_ID(ha, (atio_entry_t *)atio));
		if (unlikely(sess == NULL)) {
			TRACE_MGMT_DBG("qla2x00t(%ld): Unable to find "
				"wwn login (loop_id=%d), trying to create it "
				"manually", vha->host_no,
				GET_TARGET_ID(ha, (atio_entry_t *)atio));
			goto out_sched;
		}
	}

	res = q2t_do_send_cmd_to_scst(vha, cmd, sess);
	if (unlikely(res != 0))
		goto out_free_cmd;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_cmd:
	q2t_free_cmd(cmd);
	goto out;

out_sched:
	if (atio->entry_count > 1) {
		TRACE_MGMT_DBG("Dropping multy entry cmd %p", cmd);
		res = -EBUSY;
		goto out_free_cmd;
	}
	res = q2t_sched_sess_work(tgt, Q2T_SESS_WORK_CMD, &cmd, sizeof(cmd));
	if (res != 0)
		goto out_free_cmd;
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_issue_task_mgmt(struct q2t_sess *sess, uint8_t *lun,
	int lun_size, int fn, void *iocb, int flags)
{
	int res = 0, rc = -1;
	struct q2t_mgmt_cmd *mcmd;
	struct qla_hw_data *ha = sess->tgt->vha->hw;

	TRACE_ENTRY();

	/*
	 * Clearing all unknown ATIOs, because the aborted ones can be
	 * among them. Let's be simpler and don't implement search of
	 * the aborted commands in the unknown list. It should be harmless
	 * and on the next retry work well.
	 */
	while (!list_empty(&ha->unknown_atio_list)) {
		struct q2t_unknown_atio *u;

		u = list_first_entry(&ha->unknown_atio_list,
			struct q2t_unknown_atio, unknown_atio_list_entry);
		TRACE_MGMT_DBG("qla2x00t(%ld): Clearing unknown "
			"ATIO_TYPE7 %p", u->vha->host_no, u);
		WARN_ON(!IS_FWI2_CAPABLE(u->vha->hw));
		BUG_ON(u->vha->hw != ha);
		q24_send_term_exchange(u->vha, NULL, &u->atio7, 1);
		list_del(&u->unknown_atio_list_entry);
		kfree(u);
	}

	mcmd = mempool_alloc(q2t_mgmt_cmd_mempool, GFP_ATOMIC);
	if (mcmd == NULL) {
		PRINT_CRIT_ERROR("qla2x00t(%ld): Allocation of management "
			"command failed, some commands and their data could "
			"leak", sess->tgt->vha->host_no);
		res = -ENOMEM;
		goto out;
	}
	memset(mcmd, 0, sizeof(*mcmd));

	mcmd->sess = sess;
	if (iocb) {
		memcpy(&mcmd->orig_iocb.notify_entry, iocb,
			sizeof(mcmd->orig_iocb.notify_entry));
	}
	mcmd->flags = flags;

	switch (fn) {
	case Q2T_CLEAR_ACA:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): CLEAR_ACA received",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_ACA,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_TARGET_RESET:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): TARGET_RESET received",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_TARGET_RESET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_LUN_RESET:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): LUN_RESET received",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_LUN_RESET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_CLEAR_TS:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): CLEAR_TS received",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_TASK_SET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_ABORT_TS:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): ABORT_TS received",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_ABORT_TASK_SET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_ABORT_ALL:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Doing ABORT_ALL_TASKS",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess,
					 SCST_ABORT_ALL_TASKS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_ABORT_ALL_SESS:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Doing ABORT_ALL_TASKS_SESS",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess,
					 SCST_ABORT_ALL_TASKS_SESS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_NEXUS_LOSS_SESS:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Doing NEXUS_LOSS_SESS",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_NEXUS_LOSS_SESS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_NEXUS_LOSS:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Doing NEXUS_LOSS",
			sess->tgt->vha->host_no);
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_NEXUS_LOSS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	default:
		PRINT_ERROR("qla2x00t(%ld): Unknown task mgmt fn 0x%x",
			    sess->tgt->vha->host_no, fn);
		rc = -1;
		break;
	}

	if (rc != 0) {
		PRINT_ERROR("qla2x00t(%ld): scst_rx_mgmt_fn_lun() failed: %d",
			    sess->tgt->vha->host_no, rc);
		res = -EFAULT;
		goto out_free;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	mempool_free(mcmd, q2t_mgmt_cmd_mempool);
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_handle_task_mgmt(scsi_qla_host_t *vha, void *iocb)
{
	int res = 0;
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;
	uint8_t *lun;
	uint16_t lun_data;
	int lun_size;
	int fn;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	tgt = vha->tgt;
	if (IS_FWI2_CAPABLE(ha)) {
		atio7_entry_t *a = (atio7_entry_t *)iocb;

		lun = (uint8_t *)&a->fcp_cmnd.lun;
		lun_size = sizeof(a->fcp_cmnd.lun);
		fn = a->fcp_cmnd.task_mgmt_flags;
		sess = q2t_find_sess_by_s_id(tgt, a->fcp_hdr.s_id);
	} else {
		notify_entry_t *n = (notify_entry_t *)iocb;

		/* make it be in network byte order */
		lun_data = swab16(le16_to_cpu(n->lun));
		lun = (uint8_t *)&lun_data;
		lun_size = sizeof(lun_data);
		fn = n->task_flags >> IMM_NTFY_TASK_MGMT_SHIFT;
		sess = q2t_find_sess_by_loop_id(tgt, GET_TARGET_ID(ha, n));
	}

	if (sess == NULL) {
		TRACE_MGMT_DBG("qla2x00t(%ld): task mgmt fn 0x%x for "
			"non-existent session", vha->host_no, fn);
		res = q2t_sched_sess_work(tgt, Q2T_SESS_WORK_TM, iocb,
			IS_FWI2_CAPABLE(ha) ? sizeof(atio7_entry_t) :
					      sizeof(notify_entry_t));
		if (res != 0)
			tgt->tm_to_unknown = 1;
		goto out;
	}

	res = q2t_issue_task_mgmt(sess, lun, lun_size, fn, iocb, 0);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static int __q2t_abort_task(scsi_qla_host_t *vha, notify_entry_t *iocb,
	struct q2t_sess *sess)
{
	int res, rc;
	struct q2t_mgmt_cmd *mcmd;

	TRACE_ENTRY();

	mcmd = mempool_alloc(q2t_mgmt_cmd_mempool, GFP_ATOMIC);
	if (mcmd == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s: Allocation of ABORT cmd failed",
			vha->host_no, __func__);
		res = -ENOMEM;
		goto out;
	}
	memset(mcmd, 0, sizeof(*mcmd));

	mcmd->sess = sess;
	memcpy(&mcmd->orig_iocb.notify_entry, iocb,
		sizeof(mcmd->orig_iocb.notify_entry));

	rc = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK,
		le16_to_cpu(iocb->seq_id), SCST_ATOMIC, mcmd);
	if (rc != 0) {
		PRINT_ERROR("qla2x00t(%ld): scst_rx_mgmt_fn_tag() failed: %d",
			    vha->host_no, rc);
		res = -EFAULT;
		goto out_free;
	}

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	mempool_free(mcmd, q2t_mgmt_cmd_mempool);
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_abort_task(scsi_qla_host_t *vha, notify_entry_t *iocb)
{
	int res;
	struct q2t_sess *sess;
	int loop_id;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	loop_id = GET_TARGET_ID(ha, iocb);

	sess = q2t_find_sess_by_loop_id(vha->tgt, loop_id);
	if (sess == NULL) {
		TRACE_MGMT_DBG("qla2x00t(%ld): task abort for unexisting "
			"session", vha->host_no);
		res = q2t_sched_sess_work(vha->tgt, Q2T_SESS_WORK_ABORT, iocb,
			sizeof(*iocb));
		if (res != 0)
			vha->tgt->tm_to_unknown = 1;
		goto out;
	}

	res = __q2t_abort_task(vha, iocb, sess);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void q2t_rscn_reg_work(struct work_struct *work)
{
	struct q2t_tgt *tgt = container_of(work, struct q2t_tgt, rscn_reg_work);
	scsi_qla_host_t *vha = tgt->vha;
	int ret;

	TRACE_ENTRY();

	if ((vha->host->active_mode & MODE_INITIATOR) == 0) {
		/*
		 * The QLogic firmware and qla2xxx do not register for RSCNs in
		 * target-only mode, so do that explicitly.
		 */
		ret = qla2x00_send_change_request(vha, 0x3, vha->vp_idx);
		if (ret != QLA_SUCCESS) {
			PRINT_INFO("qla2x00t(%ld): RSCN registration failed: "
				"%#x (OK for non-fabric setups)",
				vha->host_no, ret);
		} else
			TRACE_MGMT_DBG("qla2x00t(%ld): RSCN registration succeeded",
				vha->host_no);
	}

	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static int q24_handle_els(scsi_qla_host_t *vha, notify24xx_entry_t *iocb)
{
	struct q2t_tgt *tgt = vha->tgt;
	int res = 1; /* send notify ack */

	TRACE_ENTRY();

	TRACE_MGMT_DBG("qla2x00t(%ld): ELS opcode %x", vha->host_no,
		iocb->status_subcode);

	switch (iocb->status_subcode) {
	case ELS_PLOGI:
		/*
		 * HACK. Let's do it on PLOGI, because seems there is no other
		 * simple place, from where it can be called. In the worst
		 * case, we will just reinstall RSCNs once again, it's harmless.
		 */
		schedule_work(&tgt->rscn_reg_work);
		break;

	case ELS_FLOGI:
	case ELS_PRLI:
		break;

	case ELS_LOGO:
	case ELS_PRLO:
	case ELS_TPRLO:
		res = q2t_reset(vha, iocb, Q2T_NEXUS_LOSS_SESS);
		break;

	case ELS_PDISC:
	case ELS_ADISC:
	{
		struct q2t_tgt *tgt = vha->tgt;

		if (tgt->link_reinit_iocb_pending) {
			q24_send_notify_ack(vha, &tgt->link_reinit_iocb, 0, 0, 0);
			tgt->link_reinit_iocb_pending = 0;
		}
		break;
	}

	default:
		PRINT_ERROR("qla2x00t(%ld): Unsupported ELS command %x "
			"received", vha->host_no, iocb->status_subcode);
#if 0
		res = q2t_reset(vha, iocb, Q2T_NEXUS_LOSS_SESS);
#endif
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int q2t_cut_cmd_data_head(struct q2t_cmd *cmd, unsigned int offset)
{
	int res = 0;
	int cnt, first_sg, first_page = 0, first_page_offs = 0, i;
	unsigned int l;
	int cur_dst, cur_src;
	struct scatterlist *sg;
	size_t bufflen = 0;

	TRACE_ENTRY();

	first_sg = -1;
	cnt = 0;
	l = 0;
	for (i = 0; i < cmd->sg_cnt; i++) {
		l += cmd->sg[i].length;
		if (l > offset) {
			int sg_offs = l - cmd->sg[i].length;

			first_sg = i;
			if (cmd->sg[i].offset == 0) {
				first_page_offs = offset % PAGE_SIZE;
				first_page = (offset - sg_offs) >> PAGE_SHIFT;
			} else {
				TRACE_SG("i=%d, sg[i].offset=%d, "
					"sg_offs=%d", i, cmd->sg[i].offset, sg_offs);
				if ((cmd->sg[i].offset + sg_offs) > offset) {
					first_page_offs = offset - sg_offs;
					first_page = 0;
				} else {
					int sec_page_offs = sg_offs +
						(PAGE_SIZE - cmd->sg[i].offset);
					first_page_offs = sec_page_offs % PAGE_SIZE;
					first_page = 1 +
						((offset - sec_page_offs) >>
							PAGE_SHIFT);
				}
			}
			cnt = cmd->sg_cnt - i + (first_page_offs != 0);
			break;
		}
	}
	if (first_sg == -1) {
		PRINT_ERROR("qla2x00t(%ld): Wrong offset %d, buf length %d",
			cmd->tgt->vha->host_no, offset, cmd->bufflen);
		res = -EINVAL;
		goto out;
	}

	TRACE_SG("offset=%d, first_sg=%d, first_page=%d, "
		"first_page_offs=%d, cmd->bufflen=%d, cmd->sg_cnt=%d", offset,
		first_sg, first_page, first_page_offs, cmd->bufflen,
		cmd->sg_cnt);

	sg = kmalloc_array(cnt, sizeof(sg[0]), GFP_KERNEL);
	if (sg == NULL) {
		PRINT_ERROR("qla2x00t(%ld): Unable to allocate cut "
			"SG (len %zd)", cmd->tgt->vha->host_no,
			cnt * sizeof(sg[0]));
		res = -ENOMEM;
		goto out;
	}
	sg_init_table(sg, cnt);

	cur_dst = 0;
	cur_src = first_sg;
	if (first_page_offs != 0) {
		int fpgs;

		sg_set_page(&sg[cur_dst], &sg_page(&cmd->sg[cur_src])[first_page],
			PAGE_SIZE - first_page_offs, first_page_offs);
		bufflen += sg[cur_dst].length;
		TRACE_SG("cur_dst=%d, cur_src=%d, sg[].page=%p, "
			"sg[].offset=%d, sg[].length=%d, bufflen=%zu",
			cur_dst, cur_src, sg_page(&sg[cur_dst]), sg[cur_dst].offset,
			sg[cur_dst].length, bufflen);
		cur_dst++;

		fpgs = (cmd->sg[cur_src].length >> PAGE_SHIFT) +
			((cmd->sg[cur_src].length & ~PAGE_MASK) != 0);
		first_page++;
		if (fpgs > first_page) {
			sg_set_page(&sg[cur_dst],
				&sg_page(&cmd->sg[cur_src])[first_page],
				cmd->sg[cur_src].length - PAGE_SIZE*first_page,
				0);
			TRACE_SG("fpgs=%d, cur_dst=%d, cur_src=%d, "
				"sg[].page=%p, sg[].length=%d, bufflen=%zu",
				fpgs, cur_dst, cur_src, sg_page(&sg[cur_dst]),
				sg[cur_dst].length, bufflen);
			bufflen += sg[cur_dst].length;
			cur_dst++;
		}
		cur_src++;
	}

	while (cur_src < cmd->sg_cnt) {
		sg_set_page(&sg[cur_dst], sg_page(&cmd->sg[cur_src]),
			cmd->sg[cur_src].length, cmd->sg[cur_src].offset);
		TRACE_SG("cur_dst=%d, cur_src=%d, "
			"sg[].page=%p, sg[].length=%d, sg[].offset=%d, "
			"bufflen=%zu", cur_dst, cur_src, sg_page(&sg[cur_dst]),
			sg[cur_dst].length, sg[cur_dst].offset, bufflen);
		bufflen += sg[cur_dst].length;
		cur_dst++;
		cur_src++;
	}

	if (cmd->free_sg)
		kfree(cmd->sg);

	cmd->sg = sg;
	cmd->free_sg = 1;
	cmd->sg_cnt = cur_dst;
	cmd->bufflen = bufflen;
	cmd->offset += offset;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static inline int q2t_srr_adjust_data(struct q2t_cmd *cmd,
	uint32_t srr_rel_offs, int *xmit_type)
{
	int res = 0;
	int rel_offs;

	rel_offs = srr_rel_offs - cmd->offset;
	TRACE_MGMT_DBG("srr_rel_offs=%d, rel_offs=%d", srr_rel_offs, rel_offs);

	*xmit_type = Q2T_XMIT_ALL;

	if (rel_offs < 0) {
		PRINT_ERROR("qla2x00t(%ld): SRR rel_offs (%d) < 0",
			cmd->tgt->vha->host_no, rel_offs);
		res = -1;
	} else if (rel_offs == cmd->bufflen)
		*xmit_type = Q2T_XMIT_STATUS;
	else if (rel_offs > 0)
		res = q2t_cut_cmd_data_head(cmd, rel_offs);

	return res;
}

/* No locks, thread context */
static void q24_handle_srr(scsi_qla_host_t *vha, struct srr_ctio *sctio,
	struct srr_imm *imm)
{
	notify24xx_entry_t *ntfy = &imm->imm.notify_entry24;
	struct q2t_cmd *cmd = sctio->cmd;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("SRR cmd %p, srr_ui %x", cmd, ntfy->srr_ui);

	switch (ntfy->srr_ui) {
	case SRR_IU_STATUS:
		spin_lock_irq(&ha->hardware_lock);
		q24_send_notify_ack(vha, ntfy,
			NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
		spin_unlock_irq(&ha->hardware_lock);
		__q24_xmit_response(cmd, Q2T_XMIT_STATUS);
		break;
	case SRR_IU_DATA_IN:
		cmd->bufflen = scst_cmd_get_adjusted_resp_data_len(&cmd->scst_cmd);
		if (q2t_has_data(cmd) &&
		    (scst_cmd_get_data_direction(&cmd->scst_cmd) & SCST_DATA_READ)) {
			uint32_t offset;
			int xmit_type;

			offset = le32_to_cpu(imm->imm.notify_entry24.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q24_send_notify_ack(vha, ntfy,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			__q24_xmit_response(cmd, xmit_type);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for in data for cmd "
				"without them (tag %d, SCSI status %d, dir %d),"
				" reject", vha->host_no, cmd->tag,
				scst_cmd_get_status(&cmd->scst_cmd),
				scst_cmd_get_data_direction(&cmd->scst_cmd));
			goto out_reject;
		}
		break;
	case SRR_IU_DATA_OUT:
		cmd->bufflen = scst_cmd_get_write_fields(&cmd->scst_cmd,
					&cmd->sg, &cmd->sg_cnt);
		if (q2t_has_data(cmd) &&
		    (scst_cmd_get_data_direction(&cmd->scst_cmd) & SCST_DATA_WRITE)) {
			uint32_t offset;
			int xmit_type;

			offset = le32_to_cpu(imm->imm.notify_entry24.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q24_send_notify_ack(vha, ntfy,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			if (xmit_type & Q2T_XMIT_DATA)
				__q2t_rdy_to_xfer(cmd);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for out data for cmd "
				"without them (tag %d, SCSI status %d, dir %d),"
				" reject", vha->host_no, cmd->tag,
				scst_cmd_get_status(&cmd->scst_cmd),
				scst_cmd_get_data_direction(&cmd->scst_cmd));
			goto out_reject;
		}
		break;
	default:
		PRINT_ERROR("qla2x00t(%ld): Unknown srr_ui value %x",
			vha->host_no, ntfy->srr_ui);
		goto out_reject;
	}

out:
	TRACE_EXIT();
	return;

out_reject:
	spin_lock_irq(&ha->hardware_lock);
	q24_send_notify_ack(vha, ntfy, NOTIFY_ACK_SRR_FLAGS_REJECT,
		NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
		NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	if (cmd->state == Q2T_STATE_NEED_DATA) {
		cmd->state = Q2T_STATE_DATA_IN;
		scst_set_cmd_error(&cmd->scst_cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		scst_rx_data(&cmd->scst_cmd, SCST_RX_STATUS_ERROR_SENSE_SET,
			SCST_CONTEXT_THREAD);
	} else
		q24_send_term_exchange(vha, cmd, &cmd->atio.atio7, 1);
	spin_unlock_irq(&ha->hardware_lock);
	goto out;
}

/* No locks, thread context */
static void q2x_handle_srr(scsi_qla_host_t *vha, struct srr_ctio *sctio,
	struct srr_imm *imm)
{
	notify_entry_t *ntfy = &imm->imm.notify_entry;
	struct q2t_cmd *cmd = sctio->cmd;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("SRR cmd %p, srr_ui %x", cmd, ntfy->srr_ui);

	switch (ntfy->srr_ui) {
	case SRR_IU_STATUS:
		spin_lock_irq(&ha->hardware_lock);
		q2x_send_notify_ack(vha, ntfy, 0, 0, 0,
			NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
		spin_unlock_irq(&ha->hardware_lock);
		__q2x_xmit_response(cmd, Q2T_XMIT_STATUS);
		break;
	case SRR_IU_DATA_IN:
		cmd->bufflen = scst_cmd_get_adjusted_resp_data_len(&cmd->scst_cmd);
		if (q2t_has_data(cmd)) {
			uint32_t offset;
			int xmit_type;

			offset = le32_to_cpu(imm->imm.notify_entry.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q2x_send_notify_ack(vha, ntfy, 0, 0, 0,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			__q2x_xmit_response(cmd, xmit_type);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for in data for cmd "
				"without them (tag %d, SCSI status %d), "
				"reject", vha->host_no, cmd->tag,
				scst_cmd_get_status(&cmd->scst_cmd));
			goto out_reject;
		}
		break;
	case SRR_IU_DATA_OUT:
		cmd->bufflen = scst_cmd_get_write_fields(&cmd->scst_cmd,
					&cmd->sg, &cmd->sg_cnt);
		if (q2t_has_data(cmd)) {
			uint32_t offset;
			int xmit_type;

			offset = le32_to_cpu(imm->imm.notify_entry.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q2x_send_notify_ack(vha, ntfy, 0, 0, 0,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			if (xmit_type & Q2T_XMIT_DATA)
				__q2t_rdy_to_xfer(cmd);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for out data for cmd "
				"without them (tag %d, SCSI status %d), "
				"reject", vha->host_no, cmd->tag,
				scst_cmd_get_status(&cmd->scst_cmd));
			goto out_reject;
		}
		break;
	default:
		PRINT_ERROR("qla2x00t(%ld): Unknown srr_ui value %x",
			vha->host_no, ntfy->srr_ui);
		goto out_reject;
	}

out:
	TRACE_EXIT();
	return;

out_reject:
	spin_lock_irq(&ha->hardware_lock);
	q2x_send_notify_ack(vha, ntfy, 0, 0, 0, NOTIFY_ACK_SRR_FLAGS_REJECT,
		NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
		NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	if (cmd->state == Q2T_STATE_NEED_DATA) {
		cmd->state = Q2T_STATE_DATA_IN;
		scst_set_cmd_error(&cmd->scst_cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		scst_rx_data(&cmd->scst_cmd, SCST_RX_STATUS_ERROR_SENSE_SET,
			SCST_CONTEXT_THREAD);
	} else
		q2x_send_term_exchange(vha, cmd, &cmd->atio.atio2x, 1);
	spin_unlock_irq(&ha->hardware_lock);
	goto out;
}

static void q2t_reject_free_srr_imm(scsi_qla_host_t *vha, struct srr_imm *imm,
	int ha_locked)
{
	struct qla_hw_data *ha = vha->hw;

	if (!ha_locked)
		spin_lock_irq(&ha->hardware_lock);

	if (IS_FWI2_CAPABLE(ha)) {
		q24_send_notify_ack(vha, &imm->imm.notify_entry24,
			NOTIFY_ACK_SRR_FLAGS_REJECT,
			NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
			NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	} else {
		q2x_send_notify_ack(vha, &imm->imm.notify_entry,
			0, 0, 0, NOTIFY_ACK_SRR_FLAGS_REJECT,
			NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
			NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	}

	if (!ha_locked)
		spin_unlock_irq(&ha->hardware_lock);

	kfree(imm);
	return;
}

static void q2t_handle_srr_work(struct work_struct *work)
{
	struct q2t_tgt *tgt = container_of(work, struct q2t_tgt, srr_work);
	scsi_qla_host_t *vha = tgt->vha;
	struct srr_ctio *sctio;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("SRR work (tgt %p)", tgt);

restart:
	spin_lock_irq(&tgt->srr_lock);
	list_for_each_entry(sctio, &tgt->srr_ctio_list, srr_list_entry) {
		struct srr_imm *imm;
		struct q2t_cmd *cmd;
		struct srr_imm *i, *ti;

		imm = NULL;
		list_for_each_entry_safe(i, ti, &tgt->srr_imm_list,
						srr_list_entry) {
			if (i->srr_id == sctio->srr_id) {
				list_del(&i->srr_list_entry);
				if (imm) {
					PRINT_ERROR("qla2x00t(%ld): There must "
					  "be only one IMM SRR per CTIO SRR "
					  "(IMM SRR %p, id %d, CTIO %p",
					  vha->host_no, i, i->srr_id, sctio);
					q2t_reject_free_srr_imm(vha, i, 0);
				} else
					imm = i;
			}
		}

		TRACE_MGMT_DBG("IMM SRR %p, CTIO SRR %p (id %d)", imm, sctio,
			sctio->srr_id);

		if (imm == NULL) {
			TRACE_MGMT_DBG("Not found matching IMM for SRR CTIO "
				"(id %d)", sctio->srr_id);
			continue;
		} else
			list_del(&sctio->srr_list_entry);

		spin_unlock_irq(&tgt->srr_lock);

		cmd = sctio->cmd;

		/* Restore the originals, except bufflen */
		cmd->offset = scst_cmd_get_ppl_offset(&cmd->scst_cmd);
		if (cmd->free_sg) {
			kfree(cmd->sg);
			cmd->free_sg = 0;
		}
		cmd->sg = scst_cmd_get_sg(&cmd->scst_cmd);
		cmd->sg_cnt = scst_cmd_get_sg_cnt(&cmd->scst_cmd);

		TRACE_MGMT_DBG("SRR cmd %p (scst_cmd %p, tag %d, op %s), "
			"sg_cnt=%d, offset=%d", cmd, &cmd->scst_cmd,
			cmd->tag, scst_get_opcode_name(&cmd->scst_cmd),
			cmd->sg_cnt, cmd->offset);

		if (IS_FWI2_CAPABLE(ha))
			q24_handle_srr(vha, sctio, imm);
		else
			q2x_handle_srr(vha, sctio, imm);

		kfree(imm);
		kfree(sctio);
		goto restart;
	}
	spin_unlock_irq(&tgt->srr_lock);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_prepare_srr_imm(scsi_qla_host_t *vha, void *iocb)
{
	struct srr_imm *imm;
	struct q2t_tgt *tgt = vha->tgt;
	notify_entry_t *iocb2x = (notify_entry_t *)iocb;
	notify24xx_entry_t *iocb24 = (notify24xx_entry_t *)iocb;
	struct srr_ctio *sctio;
	struct qla_hw_data *ha = vha->hw;

	tgt->imm_srr_id++;

	TRACE(TRACE_MGMT, "qla2x00t(%ld): SRR received", vha->host_no);

	imm = kzalloc(sizeof(*imm), GFP_ATOMIC);
	if (imm != NULL) {
		memcpy(&imm->imm.notify_entry, iocb,
			sizeof(imm->imm.notify_entry));

		/* IRQ is already OFF */
		spin_lock(&tgt->srr_lock);
		imm->srr_id = tgt->imm_srr_id;
		list_add_tail(&imm->srr_list_entry,
			&tgt->srr_imm_list);
		TRACE_MGMT_DBG("IMM NTFY SRR %p added (id %d, ui %x)", imm,
			imm->srr_id, iocb24->srr_ui);
		if (tgt->imm_srr_id == tgt->ctio_srr_id) {
			int found = 0;

			list_for_each_entry(sctio, &tgt->srr_ctio_list,
					srr_list_entry) {
				if (sctio->srr_id == imm->srr_id) {
					found = 1;
					break;
				}
			}
			if (found) {
				TRACE_MGMT_DBG("%s", "Scheduling srr work");
				schedule_work(&tgt->srr_work);
			} else {
				TRACE(TRACE_MGMT, "qla2x00t(%ld): imm_srr_id "
					"== ctio_srr_id (%d), but there is no "
					"corresponding SRR CTIO, deleting IMM "
					"SRR %p", vha->host_no,	tgt->ctio_srr_id,
					imm);
				list_del(&imm->srr_list_entry);

				kfree(imm);

				spin_unlock(&tgt->srr_lock);
				goto out_reject;
			}
		}
		spin_unlock(&tgt->srr_lock);
	} else {
		struct srr_ctio *ts;

		PRINT_ERROR("qla2x00t(%ld): Unable to allocate SRR IMM "
			"entry, SRR request will be rejected", vha->host_no);

		/* IRQ is already OFF */
		spin_lock(&tgt->srr_lock);
		list_for_each_entry_safe(sctio, ts, &tgt->srr_ctio_list,
					srr_list_entry) {
			if (sctio->srr_id == tgt->imm_srr_id) {
				TRACE_MGMT_DBG("CTIO SRR %p deleted "
					"(id %d)", sctio, sctio->srr_id);
				list_del(&sctio->srr_list_entry);
				if (IS_FWI2_CAPABLE(ha)) {
					q24_send_term_exchange(vha, sctio->cmd,
						&sctio->cmd->atio.atio7, 1);
				} else {
					q2x_send_term_exchange(vha, sctio->cmd,
						&sctio->cmd->atio.atio2x, 1);
				}
				kfree(sctio);
			}
		}
		spin_unlock(&tgt->srr_lock);
		goto out_reject;
	}

out:
	return;

out_reject:
	if (IS_FWI2_CAPABLE(ha)) {
		q24_send_notify_ack(vha, iocb24,
			NOTIFY_ACK_SRR_FLAGS_REJECT,
			NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
			NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	} else {
		q2x_send_notify_ack(vha, iocb2x,
			0, 0, 0, NOTIFY_ACK_SRR_FLAGS_REJECT,
			NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
			NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	}
	goto out;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q2t_handle_imm_notify(scsi_qla_host_t *vha, void *iocb)
{
	uint16_t status;
	uint32_t add_flags = 0;
	int send_notify_ack = 1;
	notify_entry_t *iocb2x = (notify_entry_t *)iocb;
	notify24xx_entry_t *iocb24 = (notify24xx_entry_t *)iocb;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	status = le16_to_cpu(iocb2x->status);

	TRACE_BUFF_FLAG(TRACE_BUFF, "IMMED Notify Coming Up",
		iocb, sizeof(*iocb2x));

	switch (status) {
	case IMM_NTFY_LIP_RESET:
	{
		if (IS_FWI2_CAPABLE(ha)) {
			TRACE(TRACE_MGMT, "qla2x00t(%ld): LIP reset (loop %#x), "
				"subcode %x", vha->host_no,
				le16_to_cpu(iocb24->nport_handle),
				iocb24->status_subcode);
		} else {
			TRACE(TRACE_MGMT, "qla2x00t(%ld): LIP reset (I %#x)",
				vha->host_no, GET_TARGET_ID(ha, iocb2x));
			/* set the Clear LIP reset event flag */
			add_flags |= NOTIFY_ACK_CLEAR_LIP_RESET;
		}
		/*
		 * No additional resets or aborts are needed, because firmware
		 * will as required by FCP either generate TARGET RESET or
		 * reject all affected commands with LIP_RESET status.
		 */
		break;
	}

	case IMM_NTFY_LIP_LINK_REINIT:
	{
		struct q2t_tgt *tgt = vha->tgt;

		TRACE(TRACE_MGMT, "qla2x00t(%ld): LINK REINIT (loop %#x, "
			"subcode %x)", vha->host_no,
			le16_to_cpu(iocb24->nport_handle),
			iocb24->status_subcode);
		if (tgt->link_reinit_iocb_pending)
			q24_send_notify_ack(vha, &tgt->link_reinit_iocb, 0, 0, 0);
		memcpy(&tgt->link_reinit_iocb, iocb24, sizeof(*iocb24));
		tgt->link_reinit_iocb_pending = 1;
		/*
		 * QLogic requires to wait after LINK REINIT for possible
		 * PDISC or ADISC ELS commands
		 */
		send_notify_ack = 0;
		break;
	}

	case IMM_NTFY_PORT_LOGOUT:
		if (IS_FWI2_CAPABLE(ha)) {
			TRACE(TRACE_MGMT, "qla2x00t(%ld): Port logout (loop "
				"%#x, subcode %x)", vha->host_no,
				le16_to_cpu(iocb24->nport_handle),
				iocb24->status_subcode);
		} else {
			TRACE(TRACE_MGMT, "qla2x00t(%ld): Port logout (S "
				"%08x -> L %#x)", vha->host_no,
				le16_to_cpu(iocb2x->seq_id),
				le16_to_cpu(iocb2x->lun));
		}
		if (q2t_reset(vha, iocb, Q2T_NEXUS_LOSS_SESS) == 0)
			send_notify_ack = 0;
		/* The sessions will be cleared in the callback, if needed */
		break;

	case IMM_NTFY_GLBL_TPRLO:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Global TPRLO (%x)",
			vha->host_no, status);
		if (q2t_reset(vha, iocb, Q2T_NEXUS_LOSS) == 0)
			send_notify_ack = 0;
		/* The sessions will be cleared in the callback, if needed */
		break;

	case IMM_NTFY_PORT_CONFIG:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Port config changed (%x)",
			vha->host_no, status);
		break;

	case IMM_NTFY_LINK_FAILURE:
		if (IS_FWI2_CAPABLE(ha))
			TRACE(TRACE_MGMT, "qla2x00t(%ld): Link failure detected",
				vha->host_no);
		else
			TRACE(TRACE_MGMT, "qla2x00t(%ld): Global LOGO received",
				vha->host_no);
		/* I_T nexus loss */
		if (q2t_reset(vha, iocb, Q2T_NEXUS_LOSS) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_IOCB_OVERFLOW:
		PRINT_ERROR("qla2x00t(%ld): Cannot provide requested "
			"capability (IOCB overflowed the immediate notify "
			"resource count)", vha->host_no);
		break;

	case IMM_NTFY_ABORT_TASK:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Abort Task (S %08x I %#x -> "
			"L %#x)", vha->host_no, le16_to_cpu(iocb2x->seq_id),
			GET_TARGET_ID(ha, iocb2x), le16_to_cpu(iocb2x->lun));
		if (q2t_abort_task(vha, iocb2x) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_RESOURCE:
		PRINT_ERROR("qla2x00t(%ld): Out of resources", vha->host_no);
		break;

	case IMM_NTFY_MSG_RX:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Immediate notify task %x",
			vha->host_no, iocb2x->task_flags);
		if (q2t_handle_task_mgmt(vha, iocb2x) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_ELS:
		if (q24_handle_els(vha, iocb24) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_SRR:
		q2t_prepare_srr_imm(vha, iocb);
		send_notify_ack = 0;
		break;

	default:
		PRINT_ERROR("qla2x00t(%ld): Received unknown immediate "
			"notify status %x", vha->host_no, status);
		break;
	}

	if (send_notify_ack) {
		if (IS_FWI2_CAPABLE(ha))
			q24_send_notify_ack(vha, iocb24, 0, 0, 0);
		else
			q2x_send_notify_ack(vha, iocb2x, add_flags, 0, 0, 0,
				0, 0);
	}

	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q2x_send_busy(scsi_qla_host_t *vha, atio_entry_t *atio)
{
	ctio_ret_entry_t *ctio;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	/* Sending marker isn't necessary, since we called from ISR */

	ctio = (ctio_ret_entry_t *)q2t_req_pkt(vha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	ctio->entry_type = CTIO_RET_TYPE;
	ctio->entry_count = 1;
	ctio->handle = Q2T_SKIP_HANDLE | CTIO_COMPLETION_HANDLE_MARK;
	ctio->scsi_status = cpu_to_le16(SAM_STAT_BUSY);
	ctio->residual = atio->data_length;
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	/* Set IDs */
	SET_TARGET_ID(ha, ctio->target, GET_TARGET_ID(ha, atio));
	ctio->rx_id = atio->rx_id;

	ctio->flags = cpu_to_le16(OF_SSTS | OF_FAST_POST |
				  OF_NO_DATA | OF_SS_MODE_1);
	ctio->flags |= cpu_to_le16(OF_INC_RC);
	/*
	 * CTIO from fw w/o scst_cmd doesn't provide enough info to retry it,
	 * if the explicit confirmation is used.
	 */

	TRACE_BUFFER("CTIO BUSY packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q24_send_busy(scsi_qla_host_t *vha, atio7_entry_t *atio,
	uint16_t status)
{
	ctio7_status1_entry_t *ctio;
	struct q2t_sess *sess;
	uint16_t loop_id;

	TRACE_ENTRY();

	/*
	 * In some cases, for instance for ATIO_EXCHANGE_ADDRESS_UNKNOWN, the
	 * spec requires to issue queue full SCSI status. So, let's search among
	 * being deleted sessions as well and use CTIO7_NHANDLE_UNRECOGNIZED,
	 * if we can't find sess.
	 */
	sess = q2t_find_sess_by_s_id_include_deleted(vha->tgt,
					atio->fcp_hdr.s_id);
	if (sess != NULL)
		loop_id = sess->loop_id;
	else
		loop_id = CTIO7_NHANDLE_UNRECOGNIZED;

	/* Sending marker isn't necessary, since we called from ISR */

	ctio = (ctio7_status1_entry_t *)q2t_req_pkt(vha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", vha->host_no, __func__);
		goto out;
	}

	ctio->common.entry_type = CTIO_TYPE7;
	ctio->common.entry_count = 1;
	ctio->common.handle = Q2T_SKIP_HANDLE | CTIO_COMPLETION_HANDLE_MARK;
	ctio->common.nport_handle = loop_id;
	ctio->common.timeout = cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.vp_index = vha->vp_idx;
	ctio->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	ctio->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	ctio->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	ctio->common.exchange_addr = atio->exchange_addr;
	ctio->flags = (atio->attr << 9) | cpu_to_le16(
		CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_SEND_STATUS |
		CTIO7_FLAGS_DONT_RET_CTIO);
	/*
	 * CTIO from fw w/o scst_cmd doesn't provide enough info to retry it,
	 * if the explicit confirmation is used.
	 */
	ctio->ox_id = swab16(atio->fcp_hdr.ox_id);
	ctio->scsi_status = cpu_to_le16(status);
	ctio->residual = get_unaligned((uint32_t *)
			&atio->fcp_cmnd.add_cdb[atio->fcp_cmnd.add_cdb_len]);
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	TRACE_BUFFER("CTIO7 BUSY packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(vha);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q24_atio_pkt(scsi_qla_host_t *vha, atio7_entry_t *atio)
{
	int rc;
	struct q2t_tgt *tgt = vha->tgt;

	TRACE_ENTRY();

	if (unlikely(tgt == NULL)) {
		TRACE_MGMT_DBG("ATIO pkt, but no tgt (vha %p)", vha);
		goto out;
	}

	TRACE(TRACE_SCSI, "qla2x00t(%ld): ATIO pkt %p: type %02x count %02x",
	      vha->host_no, atio, atio->entry_type, atio->entry_count);

	/*
	 * In tgt_stop mode we also should allow all requests to pass.
	 * Otherwise, some commands can stuck.
	 */

	tgt->irq_cmd_count++;

	switch (atio->entry_type) {
	case ATIO_TYPE7:
		TRACE_DBG("ATIO_TYPE7 instance %ld, lun %llx, read/write %d/%d, "
			"add_cdb_len %d, data_length %04x, s_id %x:%x:%x",
			vha->host_no, atio->fcp_cmnd.lun, atio->fcp_cmnd.rddata,
			atio->fcp_cmnd.wrdata, atio->fcp_cmnd.add_cdb_len,
			be32_to_cpu(get_unaligned((uint32_t *)
				&atio->fcp_cmnd.add_cdb[atio->fcp_cmnd.add_cdb_len])),
			atio->fcp_hdr.s_id[0], atio->fcp_hdr.s_id[1],
			atio->fcp_hdr.s_id[2]);
		TRACE_BUFFER("Incoming ATIO7 packet data", atio,
			REQUEST_ENTRY_SIZE);
		PRINT_BUFF_FLAG(TRACE_SCSI, "FCP CDB", atio->fcp_cmnd.cdb,
				sizeof(atio->fcp_cmnd.cdb));
		if (unlikely(atio->exchange_addr ==
				ATIO_EXCHANGE_ADDRESS_UNKNOWN)) {
			TRACE(TRACE_OUT_OF_MEM, "qla2x00t(%ld): ATIO_TYPE7 "
				"received with UNKNOWN exchange address, "
				"sending QUEUE_FULL", vha->host_no);
			q24_send_busy(vha, atio, SAM_STAT_TASK_SET_FULL);
			break;
		}
		if (likely(atio->fcp_cmnd.task_mgmt_flags == 0))
			rc = q2t_send_cmd_to_scst(vha, (atio_t *)atio);
		else
			rc = q2t_handle_task_mgmt(vha, atio);
		if (unlikely(rc != 0)) {
			if (rc == -ESRCH) {
#if 1 /* With TERM EXCHANGE some FC cards refuse to boot */
				q24_send_busy(vha, atio, SAM_STAT_BUSY);
#else
				q24_send_term_exchange(vha, NULL, atio, 1);
#endif
			} else {
				PRINT_INFO("qla2x00t(%ld): Unable to send "
				   "command to SCST, sending BUSY status",
				   vha->host_no);
				q24_send_busy(vha, atio, SAM_STAT_BUSY);
			}
		}
		break;

	case IMMED_NOTIFY_TYPE:
	{
		notify_entry_t *pkt = (notify_entry_t *)atio;

		if (unlikely(pkt->entry_status != 0)) {
			PRINT_ERROR("qla2x00t(%ld): Received ATIO packet %x "
				"with error status %x", vha->host_no,
				pkt->entry_type, pkt->entry_status);
			break;
		}
		TRACE_DBG("%s", "IMMED_NOTIFY ATIO");
		q2t_handle_imm_notify(vha, pkt);
		break;
	}

	default:
		PRINT_ERROR("qla2x00t(%ld): Received unknown ATIO atio "
		     "type %x", vha->host_no, atio->entry_type);
		break;
	}

	tgt->irq_cmd_count--;

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q2t_response_pkt(scsi_qla_host_t *vha, response_t *pkt)
{
	struct q2t_tgt *tgt = vha->tgt;

	TRACE_ENTRY();

	if (unlikely(tgt == NULL)) {
		PRINT_ERROR("qla2x00t(%ld): Response pkt %x received, but no "
			"tgt (vha %p)", vha->host_no, pkt->entry_type, vha);
		goto out;
	}

	TRACE(TRACE_SCSI, "qla2x00t(%ld): pkt %p: T %02x C %02x S %02x "
		"handle %#x", vha->host_no, pkt, pkt->entry_type,
		pkt->entry_count, pkt->entry_status, pkt->handle);

	/*
	 * In tgt_stop mode we also should allow all requests to pass.
	 * Otherwise, some commands can stuck.
	 */

	if (unlikely(pkt->entry_status != 0)) {
		PRINT_ERROR("qla2x00t(%ld): Received response packet %x "
		     "with error status %x", vha->host_no, pkt->entry_type,
		     pkt->entry_status);
		switch (pkt->entry_type) {
		case ACCEPT_TGT_IO_TYPE:
		case IMMED_NOTIFY_TYPE:
		case ABTS_RECV_24XX:
			goto out;
		default:
			break;
		}
	}

	tgt->irq_cmd_count++;

	switch (pkt->entry_type) {
	case CTIO_TYPE7:
	{
		ctio7_fw_entry_t *entry = (ctio7_fw_entry_t *)pkt;

		TRACE_DBG("CTIO_TYPE7: instance %ld",
			  vha->host_no);
		TRACE_BUFFER("Incoming CTIO7 packet data", entry,
			REQUEST_ENTRY_SIZE);
		q2t_do_ctio_completion(vha, entry->handle,
			le16_to_cpu(entry->status)|(pkt->entry_status << 16),
			entry);
		break;
	}

	case ACCEPT_TGT_IO_TYPE:
	{
		atio_entry_t *atio;
		int rc;

		atio = (atio_entry_t *)pkt;
		TRACE_DBG("ACCEPT_TGT_IO instance %ld status %04x "
			  "lun %04x read/write %d data_length %04x "
			  "target_id %02x rx_id %04x ",
			  vha->host_no, le16_to_cpu(atio->status),
			  le16_to_cpu(atio->lun),
			  atio->execution_codes,
			  le32_to_cpu(atio->data_length),
			  GET_TARGET_ID(vha->hw, atio), atio->rx_id);
		TRACE_BUFFER("Incoming ATIO packet data", atio,
			REQUEST_ENTRY_SIZE);
		if (atio->status != cpu_to_le16(ATIO_CDB_VALID)) {
			PRINT_ERROR("qla2x00t(%ld): ATIO with error "
				    "status %x received", vha->host_no,
				    le16_to_cpu(atio->status));
			break;
		}
		TRACE_BUFFER("Incoming ATIO packet data", atio, REQUEST_ENTRY_SIZE);
		PRINT_BUFF_FLAG(TRACE_SCSI, "FCP CDB", atio->cdb,
				sizeof(atio->cdb));
		rc = q2t_send_cmd_to_scst(vha, (atio_t *)atio);
		if (unlikely(rc != 0)) {
			if (rc == -ESRCH) {
#if 1 /* With TERM EXCHANGE some FC cards refuse to boot */
				q2x_send_busy(vha, atio);
#else
				q2x_send_term_exchange(vha, NULL, atio, 1);
#endif
			} else {
				PRINT_INFO("qla2x00t(%ld): Unable to send "
					"command to SCST, sending BUSY status",
					vha->host_no);
				q2x_send_busy(vha, atio);
			}
		}
	}
	break;

	case CONTINUE_TGT_IO_TYPE:
	{
		ctio_common_entry_t *entry = (ctio_common_entry_t *)pkt;

		TRACE_DBG("CONTINUE_TGT_IO: instance %ld", vha->host_no);
		TRACE_BUFFER("Incoming CTIO packet data", entry,
			REQUEST_ENTRY_SIZE);
		q2t_do_ctio_completion(vha, entry->handle,
			le16_to_cpu(entry->status)|(pkt->entry_status << 16),
			entry);
		break;
	}

	case CTIO_A64_TYPE:
	{
		ctio_common_entry_t *entry = (ctio_common_entry_t *)pkt;

		TRACE_DBG("CTIO_A64: instance %ld", vha->host_no);
		TRACE_BUFFER("Incoming CTIO_A64 packet data", entry,
			REQUEST_ENTRY_SIZE);
		q2t_do_ctio_completion(vha, entry->handle,
			le16_to_cpu(entry->status)|(pkt->entry_status << 16),
			entry);
		break;
	}

	case IMMED_NOTIFY_TYPE:
		TRACE_DBG("%s", "IMMED_NOTIFY");
		q2t_handle_imm_notify(vha, (notify_entry_t *)pkt);
		break;

	case NOTIFY_ACK_TYPE:
		if (tgt->notify_ack_expected > 0) {
			nack_entry_t *entry = (nack_entry_t *)pkt;

			TRACE_DBG("NOTIFY_ACK seq %08x status %x",
				  le16_to_cpu(entry->seq_id),
				  le16_to_cpu(entry->status));
			TRACE_BUFFER("Incoming NOTIFY_ACK packet data", pkt,
				RESPONSE_ENTRY_SIZE);
			tgt->notify_ack_expected--;
			if (entry->status != cpu_to_le16(NOTIFY_ACK_SUCCESS)) {
				PRINT_ERROR("qla2x00t(%ld): NOTIFY_ACK "
					    "failed %x", vha->host_no,
					    le16_to_cpu(entry->status));
			}
		} else {
			PRINT_ERROR("qla2x00t(%ld): Unexpected NOTIFY_ACK "
				    "received", vha->host_no);
		}
		break;

	case ABTS_RECV_24XX:
		TRACE_DBG("ABTS_RECV_24XX: instance %ld", vha->host_no);
		TRACE_BUFF_FLAG(TRACE_BUFF, "Incoming ABTS_RECV "
			"packet data", pkt, REQUEST_ENTRY_SIZE);
		q24_handle_abts(vha, (abts24_recv_entry_t *)pkt);
		break;

	case ABTS_RESP_24XX:
		if (tgt->abts_resp_expected > 0) {
			abts24_resp_fw_entry_t *entry =
				(abts24_resp_fw_entry_t *)pkt;

			TRACE_DBG("ABTS_RESP_24XX: compl_status %x",
				entry->compl_status);
			TRACE_BUFF_FLAG(TRACE_BUFF, "Incoming ABTS_RESP "
				"packet data", pkt, REQUEST_ENTRY_SIZE);
			tgt->abts_resp_expected--;
			if (le16_to_cpu(entry->compl_status) != ABTS_RESP_COMPL_SUCCESS) {
				if ((entry->error_subcode1 == 0x1E) &&
				    (entry->error_subcode2 == 0)) {
					/*
					 * We've got a race here: aborted exchange not
					 * terminated, i.e. response for the aborted
					 * command was sent between the abort request
					 * was received and processed. Unfortunately,
					 * the firmware has a silly requirement that
					 * all aborted exchanges must be explicitly
					 * terminated, otherwise it refuses to send
					 * responses for the abort requests. So, we
					 * have to (re)terminate the exchange and
					 * retry the abort response.
					 */
					q24_retry_term_exchange(vha, entry);
				} else
					PRINT_WARNING("qla2x00t(%ld): ABTS_RESP_24XX "
					    "failed %x (subcode %x:%x)", vha->host_no,
					    entry->compl_status, entry->error_subcode1,
					    entry->error_subcode2);
			}
		} else {
			PRINT_ERROR("qla2x00t(%ld): Unexpected ABTS_RESP_24XX "
				    "received", vha->host_no);
		}
		break;

	case MODIFY_LUN_TYPE:
		if (tgt->modify_lun_expected > 0) {
			modify_lun_entry_t *entry = (modify_lun_entry_t *)pkt;

			TRACE_DBG("MODIFY_LUN %x, imm %c%d, cmd %c%d",
				  entry->status,
				  (entry->operators & MODIFY_LUN_IMM_ADD) ? '+'
				  : (entry->operators & MODIFY_LUN_IMM_SUB) ? '-'
				  : ' ',
				  entry->immed_notify_count,
				  (entry->operators & MODIFY_LUN_CMD_ADD) ? '+'
				  : (entry->operators & MODIFY_LUN_CMD_SUB) ? '-'
				  : ' ',
				  entry->command_count);
			tgt->modify_lun_expected--;
			if (entry->status != MODIFY_LUN_SUCCESS) {
				PRINT_ERROR("qla2x00t(%ld): MODIFY_LUN "
					    "failed %x", vha->host_no,
					    entry->status);
			}
		} else {
			PRINT_ERROR("qla2x00t(%ld): Unexpected MODIFY_LUN "
			    "received", (vha != NULL) ? (long)vha->host_no : -1);
		}
		break;

	case ENABLE_LUN_TYPE:
	{
		elun_entry_t *entry = (elun_entry_t *)pkt;

		TRACE_DBG("ENABLE_LUN %x imm %u cmd %u ",
			  entry->status, entry->immed_notify_count,
			  entry->command_count);
		if (entry->status == ENABLE_LUN_ALREADY_ENABLED) {
			TRACE_DBG("LUN is already enabled: %#x",
				  entry->status);
			entry->status = ENABLE_LUN_SUCCESS;
		} else if (entry->status == ENABLE_LUN_RC_NONZERO) {
			TRACE_DBG("ENABLE_LUN succeeded, but with "
				"error: %#x", entry->status);
			entry->status = ENABLE_LUN_SUCCESS;
		} else if (entry->status != ENABLE_LUN_SUCCESS) {
			PRINT_ERROR("qla2x00t(%ld): ENABLE_LUN "
				"failed %x", vha->host_no, entry->status);
			qla_clear_tgt_mode(vha);
		} /* else success */
		break;
	}

	default:
		PRINT_ERROR("qla2x00t(%ld): Received unknown response pkt "
		     "type %x", vha->host_no, pkt->entry_type);
		break;
	}

	tgt->irq_cmd_count--;

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reacquire
 */
static void q2t_async_event(uint16_t code, scsi_qla_host_t *vha,
	uint16_t *mailbox)
{
	struct q2t_tgt *tgt = vha->tgt;

	TRACE_ENTRY();

	if (unlikely(tgt == NULL)) {
		TRACE_DBG("ASYNC EVENT %#x, but no tgt (vha %p)", code, vha);
		goto out;
	}

	/*
	 * In tgt_stop mode we also should allow all requests to pass.
	 * Otherwise, some commands can stuck.
	 */

	tgt->irq_cmd_count++;

	switch (code) {
	case MBA_RESET:			/* Reset */
	case MBA_SYSTEM_ERR:		/* System Error */
	case MBA_REQ_TRANSFER_ERR:	/* Request Transfer Error */
	case MBA_RSP_TRANSFER_ERR:	/* Response Transfer Error */
	case MBA_ATIO_TRANSFER_ERR:	/* ATIO Queue Transfer Error */
		TRACE(TRACE_MGMT, "qla2x00t(%ld): System error async event %#x "
			"occurred", vha->host_no, code);
		break;

	case MBA_LOOP_UP:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Loop up occurred",
			vha->host_no);
		if (tgt->link_reinit_iocb_pending) {
			q24_send_notify_ack(vha, &tgt->link_reinit_iocb, 0, 0, 0);
			tgt->link_reinit_iocb_pending = 0;
		}
		break;

	case MBA_LIP_OCCURRED:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): LIP occurred", vha->host_no);
		break;

	case MBA_LOOP_DOWN:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Loop down occurred",
			vha->host_no);
		break;

	case MBA_LIP_RESET:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): LIP reset occurred",
			vha->host_no);
		break;

	case MBA_PORT_UPDATE:
	case MBA_RSCN_UPDATE:
		TRACE_MGMT_DBG("qla2x00t(%ld): Port update async event %#x "
			"occurred", vha->host_no, code);
		q2t_clear_tgt_db(tgt, false);
		break;

	default:
		TRACE(TRACE_MGMT, "qla2x00t(%ld): Async event %#x occurred: "
			"ignoring (m[0]=%x, m[1]=%x, m[2]=%x, m[3]=%x)",
			vha->host_no, code,
			le16_to_cpu(mailbox[0]), le16_to_cpu(mailbox[1]),
			le16_to_cpu(mailbox[2]), le16_to_cpu(mailbox[3]));
		break;
	}

	tgt->irq_cmd_count--;

out:
	TRACE_EXIT();
	return;
}

static int q2t_get_target_name(uint8_t *wwn, char **ppwwn_name)
{
	const int wwn_len = 3*WWN_SIZE+2;
	int res = 0;
	char *name;

	name = kmalloc(wwn_len, GFP_KERNEL);
	if (name == NULL) {
		PRINT_ERROR("qla2x00t: Allocation of tgt wwn name (size %d) "
			"failed", wwn_len);
		res = -ENOMEM;
		goto out;
	}

	sprintf(name, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		wwn[0], wwn[1], wwn[2], wwn[3],
		wwn[4], wwn[5], wwn[6], wwn[7]);

	*ppwwn_name = name;

out:
	return res;
}

/* Must be called under tgt_mutex */
static struct q2t_sess *q2t_make_local_sess(scsi_qla_host_t *vha,
	const uint8_t *s_id, uint16_t loop_id)
{
	struct q2t_sess *sess = NULL;
	fc_port_t *fcport = NULL;
	int rc, global_resets;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

retry:
	global_resets = atomic_read(&vha->tgt->tgt_global_resets_count);

	if (IS_FWI2_CAPABLE(ha)) {
		sBUG_ON(s_id == NULL);

		/* Just after LIP it can take a while, e.g. 30 seconds */
		rc = q24_get_loop_id(vha, s_id, &loop_id);
		if (rc != 0) {
			if ((s_id[0] == 0xFF) &&
			    (s_id[1] == 0xFC)) {
				/*
				 * This is Domain Controller, so it should be
				 * OK to drop SCSI commands from it.
				 */
				TRACE_MGMT_DBG("Unable to find initiator with "
					"S_ID %x:%x:%x", s_id[0], s_id[1],
					s_id[2]);
			} else
				PRINT_WARNING("qla2x00t(%ld): Unable to find "
					"initiator with S_ID %x:%x:%x",
					vha->host_no, s_id[0], s_id[1],
					s_id[2]);
			goto out;
		}
	}

	fcport = kzalloc(sizeof(*fcport), GFP_KERNEL);
	if (fcport == NULL) {
		PRINT_ERROR("qla2x00t(%ld): Allocation of tmp FC port failed",
			vha->host_no);
		goto out;
	}

	TRACE_MGMT_DBG("loop_id %d", loop_id);

	fcport->loop_id = loop_id;

	rc = qla2x00_get_port_database(vha, fcport, 0);
	if (rc != QLA_SUCCESS) {
		TRACE_MGMT_DBG("qla2x00t(%ld): Failed to retrieve fcport "
			"information -- get_port_database() returned %x "
			"(loop_id=0x%04x)", vha->host_no, rc, loop_id);
		goto out_free_fcport;
	}

	if (global_resets != atomic_read(&vha->tgt->tgt_global_resets_count)) {
		TRACE_MGMT_DBG("qla2x00t(%ld): global reset during session "
			"discovery (counter was %d, new %d), retrying",
			vha->host_no, global_resets,
			atomic_read(&vha->tgt->tgt_global_resets_count));
		kfree(fcport);
		fcport = NULL;
		goto retry;
	}

	sess = q2t_create_sess(vha, fcport, true);

out_free_fcport:
	kfree(fcport);

out:
	TRACE_EXIT_HRES(sess);
	return sess;
}

static void q2t_exec_sess_work(struct q2t_tgt *tgt,
	struct q2t_sess_work_param *prm)
{
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;
	int rc;
	struct q2t_sess *sess = NULL;
	uint8_t *s_id = NULL; /* to hide compiler warnings */
	uint8_t local_s_id[3];
	int loop_id = -1; /* to hide compiler warnings */

	TRACE_ENTRY();

	TRACE_MGMT_DBG("prm %p", prm);

	mutex_lock(&vha->tgt_mutex);
	spin_lock_irq(&ha->hardware_lock);

	if (tgt->tgt_stop)
		goto send;

	switch (prm->type) {
	case Q2T_SESS_WORK_CMD:
	{
		struct q2t_cmd *cmd = prm->cmd;

		if (IS_FWI2_CAPABLE(ha)) {
			atio7_entry_t *a = (atio7_entry_t *)&cmd->atio;

			s_id = a->fcp_hdr.s_id;
		} else
			loop_id = GET_TARGET_ID(ha, (atio_entry_t *)&cmd->atio);
		break;
	}
	case Q2T_SESS_WORK_ABORT:
		if (IS_FWI2_CAPABLE(ha)) {
			sess = q2t_find_sess_by_s_id_le(tgt,
				prm->abts.fcp_hdr_le.s_id);
			if (sess == NULL) {
				s_id = local_s_id;
				s_id[0] = prm->abts.fcp_hdr_le.s_id[2];
				s_id[1] = prm->abts.fcp_hdr_le.s_id[1];
				s_id[2] = prm->abts.fcp_hdr_le.s_id[0];
			}
			goto after_find;
		} else
			loop_id = GET_TARGET_ID(ha, &prm->tm_iocb);
		break;
	case Q2T_SESS_WORK_TM:
		if (IS_FWI2_CAPABLE(ha))
			s_id = prm->tm_iocb2.fcp_hdr.s_id;
		else
			loop_id = GET_TARGET_ID(ha, &prm->tm_iocb);
		break;
	default:
		sBUG();
		break;
	}

	if (IS_FWI2_CAPABLE(ha)) {
		sBUG_ON(s_id == NULL);
		sess = q2t_find_sess_by_s_id(tgt, s_id);
	} else
		sess = q2t_find_sess_by_loop_id(tgt, loop_id);

after_find:
	if (sess != NULL) {
		TRACE_MGMT_DBG("sess %p found", sess);
		q2t_sess_get(sess);
	} else {
		/*
		 * We are under tgt_mutex, so a new sess can't be added
		 * behind us.
		 */
		spin_unlock_irq(&ha->hardware_lock);
		sess = q2t_make_local_sess(vha, s_id, loop_id);
		spin_lock_irq(&ha->hardware_lock);
		/* sess has got an extra creation ref */
	}

send:
	if ((sess == NULL) || tgt->tgt_stop)
		goto out_term;

	switch (prm->type) {
	case Q2T_SESS_WORK_CMD:
	{
		struct q2t_cmd *cmd = prm->cmd;

		if (tgt->tm_to_unknown) {
			/*
			 * Cmd might be already aborted behind us, so be safe
			 * and abort it. It should be OK, initiator will retry
			 * it.
			 */
			goto out_term;
		}
		TRACE_MGMT_DBG("Sending work cmd %p to SCST", cmd);
		rc = q2t_do_send_cmd_to_scst(vha, cmd, sess);
		break;
	}
	case Q2T_SESS_WORK_ABORT:
		if (IS_FWI2_CAPABLE(ha))
			rc = __q24_handle_abts(vha, &prm->abts, sess);
		else
			rc = __q2t_abort_task(vha, &prm->tm_iocb, sess);
		break;
	case Q2T_SESS_WORK_TM:
	{
		uint8_t *lun;
		uint16_t lun_data;
		int lun_size, fn;
		void *iocb;

		if (IS_FWI2_CAPABLE(ha)) {
			atio7_entry_t *a = &prm->tm_iocb2;

			iocb = a;
			lun = (uint8_t *)&a->fcp_cmnd.lun;
			lun_size = sizeof(a->fcp_cmnd.lun);
			fn = a->fcp_cmnd.task_mgmt_flags;
		} else {
			notify_entry_t *n = &prm->tm_iocb;

			iocb = n;
			/* make it be in network byte order */
			lun_data = swab16(le16_to_cpu(n->lun));
			lun = (uint8_t *)&lun_data;
			lun_size = sizeof(lun_data);
			fn = n->task_flags >> IMM_NTFY_TASK_MGMT_SHIFT;
		}
		rc = q2t_issue_task_mgmt(sess, lun, lun_size, fn, iocb, 0);
		break;
	}
	default:
		sBUG();
		break;
	}

	if (rc != 0)
		goto out_term;

out_put:
	if (sess != NULL)
		q2t_sess_put(sess);

	spin_unlock_irq(&ha->hardware_lock);
	mutex_unlock(&vha->tgt_mutex);

	TRACE_EXIT();
	return;

out_term:
	switch (prm->type) {
	case Q2T_SESS_WORK_CMD:
	{
		struct q2t_cmd *cmd = prm->cmd;

		TRACE_MGMT_DBG("Terminating work cmd %p", cmd);
		/*
		 * cmd has not sent to SCST yet, so pass NULL as the second
		 * argument
		 */
		if (IS_FWI2_CAPABLE(ha))
			q24_send_term_exchange(vha, NULL, &cmd->atio.atio7, 1);
		else
			q2x_send_term_exchange(vha, NULL, &cmd->atio.atio2x, 1);
		q2t_free_cmd(cmd);
		break;
	}
	case Q2T_SESS_WORK_ABORT:
		if (IS_FWI2_CAPABLE(ha))
			q24_send_abts_resp(vha, &prm->abts,
				SCST_MGMT_STATUS_REJECTED, false);
		else
			q2x_send_notify_ack(vha, &prm->tm_iocb, 0,
				0, 0, 0, 0, 0);
		break;
	case Q2T_SESS_WORK_TM:
		if (IS_FWI2_CAPABLE(ha))
			q24_send_term_exchange(vha, NULL, &prm->tm_iocb2, 1);
		else
			q2x_send_notify_ack(vha, &prm->tm_iocb, 0,
				0, 0, 0, 0, 0);
		break;
	default:
		sBUG();
		break;
	}
	goto out_put;
}

static void q2t_sess_work_fn(struct work_struct *work)
{
	struct q2t_tgt *tgt = container_of(work, struct q2t_tgt, sess_work);
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Sess work (tgt %p)", tgt);

	spin_lock_irq(&tgt->sess_work_lock);
	while (!list_empty(&tgt->sess_works_list)) {
		struct q2t_sess_work_param *prm = list_entry(
			tgt->sess_works_list.next, typeof(*prm),
			sess_works_list_entry);

		/*
		 * This work can be scheduled on several CPUs at time, so we
		 * must delete the entry to eliminate double processing
		 */
		list_del(&prm->sess_works_list_entry);

		spin_unlock_irq(&tgt->sess_work_lock);

		q2t_exec_sess_work(tgt, prm);

		spin_lock_irq(&tgt->sess_work_lock);

		kfree(prm);
	}
	spin_unlock_irq(&tgt->sess_work_lock);

	spin_lock_irq(&ha->hardware_lock);
	spin_lock(&tgt->sess_work_lock);
	if (list_empty(&tgt->sess_works_list)) {
		tgt->sess_works_pending = 0;
		tgt->tm_to_unknown = 0;
	}
	spin_unlock(&tgt->sess_work_lock);
	spin_unlock_irq(&ha->hardware_lock);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held and IRQs off */
static void q2t_cleanup_hw_pending_cmd(scsi_qla_host_t *vha, struct q2t_cmd *cmd)
{
	uint32_t h;

	for (h = 0; h < MAX_OUTSTANDING_COMMANDS; h++) {
		if (vha->cmds[h] == cmd) {
			TRACE_DBG("Clearing handle %d for cmd %p", h, cmd);
			vha->cmds[h] = NULL;
			break;
		}
	}
	return;
}

static void q2t_on_hw_pending_cmd_timeout(struct scst_cmd *scst_cmd)
{
	struct q2t_cmd *cmd = container_of(scst_cmd, struct q2t_cmd, scst_cmd);
	struct q2t_tgt *tgt = cmd->tgt;
	scsi_qla_host_t *vha = tgt->vha;
	struct qla_hw_data *ha = vha->hw;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Cmd %p HW pending for too long (state %x)", cmd,
		cmd->state);

	spin_lock_irqsave(&ha->hardware_lock, flags);

	if (cmd->sg_mapped)
		q2t_unmap_sg(vha, cmd);

	if (cmd->state == Q2T_STATE_PROCESSED) {
		TRACE_MGMT_DBG("Force finishing cmd %p", cmd);
	} else if (cmd->state == Q2T_STATE_NEED_DATA) {
		TRACE_MGMT_DBG("Force rx_data cmd %p", cmd);

		q2t_cleanup_hw_pending_cmd(vha, cmd);

		/* It might be sporadic, hence retriable */
		scst_set_cmd_error(scst_cmd,
				SCST_LOAD_SENSE(scst_sense_internal_failure));
		scst_rx_data(scst_cmd, SCST_RX_STATUS_ERROR_SENSE_SET, SCST_CONTEXT_THREAD);
		goto out_unlock;
	} else if (cmd->state == Q2T_STATE_ABORTED) {
		TRACE_MGMT_DBG("Force finishing aborted cmd %p (tag %d)",
			cmd, cmd->tag);
	} else {
		PRINT_ERROR("qla2x00t(%ld): A command in state (%d) should "
			"not be HW pending", vha->host_no, cmd->state);
		goto out_unlock;
	}

	q2t_cleanup_hw_pending_cmd(vha, cmd);

	scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_THREAD);

out_unlock:
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	TRACE_EXIT();
	return;
}

/* Must be called under tgt_host_action_mutex */
static int q2t_add_target(scsi_qla_host_t *vha)
{
	int res;
	int rc;
	char *wwn;
	int sg_tablesize;
	struct q2t_tgt *tgt;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	TRACE_DBG("Registering target for host %ld(%p)", vha->host_no, vha);

	sBUG_ON((vha->q2t_tgt != NULL) || (vha->tgt != NULL));

	tgt = kmem_cache_zalloc(q2t_tgt_cachep, GFP_KERNEL);
	if (tgt == NULL) {
		PRINT_ERROR("qla2x00t: %s", "Allocation of tgt failed");
		res = -ENOMEM;
		goto out;
	}

	tgt->vha = vha;
	init_waitqueue_head(&tgt->waitQ);
	INIT_WORK(&tgt->rscn_reg_work, q2t_rscn_reg_work);
	INIT_LIST_HEAD(&tgt->sess_list);
	INIT_LIST_HEAD(&tgt->del_sess_list);
	INIT_DELAYED_WORK(&tgt->sess_del_work, q2t_del_sess_work_fn);
	spin_lock_init(&tgt->sess_work_lock);
	INIT_WORK(&tgt->sess_work, q2t_sess_work_fn);
	INIT_LIST_HEAD(&tgt->sess_works_list);
	spin_lock_init(&tgt->srr_lock);
	INIT_LIST_HEAD(&tgt->srr_ctio_list);
	INIT_LIST_HEAD(&tgt->srr_imm_list);
	INIT_WORK(&tgt->srr_work, q2t_handle_srr_work);
	atomic_set(&tgt->tgt_global_resets_count, 0);

	vha->q2t_tgt = tgt;

	res = q2t_get_target_name(((vha->vp_idx == 0) && vha->port_name_set) ?
					vha->hw->orig_hw_port_name :
					vha->port_name, &wwn);
	if (res != 0)
		goto out_free;

	tgt->scst_tgt = scst_register_target(&tgt2x_template, wwn);

	kfree(wwn);

	if (!tgt->scst_tgt) {
		PRINT_ERROR("qla2x00t(%ld): scst_register_target() "
			    "failed for host %ld(%p)", vha->host_no,
			    vha->host_no, vha);
		res = -ENOMEM;
		goto out_free;
	}

	if (IS_FWI2_CAPABLE(ha)) {
		/* 3 is reserved */
		sg_tablesize = QLA_MAX_SG_24XX(ha->req_q_map[0]->length - 3);
		tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND_24XX;
		tgt->datasegs_per_cont = DATASEGS_PER_CONT_24XX;
	} else {
		if (ha->enable_64bit_addressing) {
			/* 3 is reserved */
			sg_tablesize = QLA_MAX_SG64(ha->req_q_map[0]->length - 3);
			tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND64;
			tgt->datasegs_per_cont = DATASEGS_PER_CONT64;
		} else {
			PRINT_INFO("qla2x00t(%ld): Using 32 Bit "
				   "PCI addressing", vha->host_no);
			sg_tablesize = QLA_MAX_SG32(ha->req_q_map[0]->length - 3);
			tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND32;
			tgt->datasegs_per_cont = DATASEGS_PER_CONT32;
		}
	}

	rc = sysfs_create_link(scst_sysfs_get_tgt_kobj(tgt->scst_tgt),
		&vha->host->shost_dev.kobj, "host");
	if (rc != 0)
		PRINT_ERROR("qla2x00t(%ld): Unable to create \"host\" link for "
			"target %s", vha->host_no,
			scst_get_tgt_name(tgt->scst_tgt));
	if (vha->vp_idx == 0) {
		int i = 0;

		while (1) {
			const struct attribute *a = q2t_hw_tgt_attrs[i];

			if (a == NULL)
				break;
			rc = sysfs_create_file(scst_sysfs_get_tgt_kobj(tgt->scst_tgt), a);
			if (rc != 0)
				PRINT_ERROR("qla2x00t(%ld): Unable to create "
					"\"%s\" file for target %s",
					vha->host_no, a->name,
					scst_get_tgt_name(tgt->scst_tgt));
			i++;
		}
	} else {
		int i = 0;

		while (1) {
			const struct attribute *a = q2t_npiv_tgt_attrs[i];

			if (a == NULL)
				break;
			rc = sysfs_create_file(scst_sysfs_get_tgt_kobj(tgt->scst_tgt), a);
			if (rc != 0)
				PRINT_ERROR("qla2x00t(%ld): Unable to create "
					"\"%s\" file for target %s",
					vha->host_no, a->name,
					scst_get_tgt_name(tgt->scst_tgt));
			i++;
		}
	}

	scst_tgt_set_sg_tablesize(tgt->scst_tgt, sg_tablesize);
	scst_tgt_set_tgt_priv(tgt->scst_tgt, tgt);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	vha->q2t_tgt = NULL;
	kmem_cache_free(q2t_tgt_cachep, tgt);
	goto out;
}

/* Must be called under tgt_host_action_mutex */
static int q2t_remove_target(scsi_qla_host_t *vha)
{
	TRACE_ENTRY();

	TRACE_DBG("Unregistering target for host %ld(%p)", vha->host_no, vha);
	scst_unregister_target(vha->q2t_tgt->scst_tgt);
	/*
	 * Free of tgt happens via callback q2t_target_release
	 * called from scst_unregister_target, so we shouldn't touch
	 * it again.
	 */

	TRACE_EXIT();
	return 0;
}

static int q2t_host_action(scsi_qla_host_t *vha,
	qla2x_tgt_host_action_t action)
{
	int res = 0;
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	sBUG_ON(vha == NULL);

	/* To sync with q2t_exit() */
	if (down_read_trylock(&q2t_unreg_rwsem) == 0)
		goto out;

	mutex_lock(&vha->tgt_host_action_mutex);

	switch (action) {
	case ADD_TARGET:
		res = q2t_add_target(vha);
		break;
	case REMOVE_TARGET:
		res = q2t_remove_target(vha);
		break;
	case ENABLE_TARGET_MODE:
	{
		fc_port_t *fcport;

		if (qla_tgt_mode_enabled(vha)) {
			PRINT_INFO("qla2x00t(%ld): Target mode already "
				"enabled", vha->host_no);
			break;
		}

		if ((vha->q2t_tgt == NULL) ||
		    (vha->tgt != NULL)) {
			PRINT_ERROR("qla2x00t(%ld): Can't enable target mode "
				"for not existing target", vha->host_no);
			break;
		}

		PRINT_INFO("qla2x00t(%ld): Enabling target mode",
			vha->host_no);

		spin_lock_irq(&ha->hardware_lock);
		vha->tgt = vha->q2t_tgt;
		vha->tgt->tgt_stop = 0;
		spin_unlock_irq(&ha->hardware_lock);
		list_for_each_entry_rcu(fcport, &vha->vp_fcports, list) {
			q2t_fc_port_added(vha, fcport);
		}
		TRACE_DBG("Enable tgt mode for host %ld(%p)",
			  vha->host_no, vha);
		qla2x00_enable_tgt_mode(vha);
		break;
	}

	case DISABLE_TARGET_MODE:
		if (!qla_tgt_mode_enabled(vha)) {
			PRINT_INFO("qla2x00t(%ld): Target mode already "
				"disabled", vha->host_no);
			break;
		}

		PRINT_INFO("qla2x00t(%ld): Disabling target mode",
			vha->host_no);

		sBUG_ON(vha->tgt == NULL);

		q2t_target_stop(vha->tgt->scst_tgt);
		break;

	default:
		PRINT_ERROR("qla2x00t(%ld): %s: unsupported action %d",
			vha->host_no, __func__, action);
		res = -EINVAL;
		break;
	}

	mutex_unlock(&vha->tgt_host_action_mutex);

	up_read(&q2t_unreg_rwsem);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int q2t_enable_tgt(struct scst_tgt *scst_tgt, bool enable)
{
	struct q2t_tgt *tgt = scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *vha;
	int res = -E_TGT_PRIV_NOT_YET_SET;

	if (tgt == NULL)
		goto out;

	vha = tgt->vha;

	if (enable)
		res = q2t_host_action(vha, ENABLE_TARGET_MODE);
	else
		res = q2t_host_action(vha, DISABLE_TARGET_MODE);

out:
	return res;
}

static bool q2t_is_tgt_enabled(struct scst_tgt *scst_tgt)
{
	struct q2t_tgt *tgt = scst_tgt_get_tgt_priv(scst_tgt);

	if (tgt == NULL)
		return false;

	return qla_tgt_mode_enabled(tgt->vha);
}

static int q2t_parse_wwn(const char *ns, u64 *nm)
{
	unsigned int i, j;
	u8 wwn[8];

	/* validate we have enough characters for WWPN */
	if (strnlen(ns, 23) != 23)
		return -EINVAL;

	memset(wwn, 0, sizeof(wwn));

	/* Validate and store the new name */
	for (i = 0, j = 0; i < 16; i++) {
		if ((*ns >= 'a') && (*ns <= 'f'))
			j = ((j << 4) | ((*ns++ - 'a') + 10));
		else if ((*ns >= 'A') && (*ns <= 'F'))
			j = ((j << 4) | ((*ns++ - 'A') + 10));
		else if ((*ns >= '0') && (*ns <= '9'))
			j = ((j << 4) | (*ns++ - '0'));
		else
			return -EINVAL;
		if (i % 2) {
			wwn[i/2] = j & 0xff;
			j = 0;
			if ((i < 15) && (':' != *ns++))
				return -EINVAL;
		}
	}

	*nm = wwn_to_u64(wwn);

	return 0;
}

#if ENABLE_NPIV
static ssize_t q2t_add_vtarget(const char *target_name, char *params)
{
	int res;
	char *param, *p, *pp;
	u64 port_name, node_name;
	u64 parent_host;
	bool parent_host_set = false, node_name_set = false;

	TRACE_ENTRY();

	res = q2t_parse_wwn(target_name, &port_name);
	if (res) {
		PRINT_ERROR("qla2x00t: Syntax error at target name %s",
			target_name);
		goto out;
	}

	while (1) {
		param = scst_get_next_token_str(&params);
		if (param == NULL)
			break;

		p = scst_get_next_lexem(&param);
		if (*p == '\0') {
			PRINT_ERROR("qla2x00t: Syntax error at %s (target %s)",
				param, target_name);
			res = -EINVAL;
			goto out;
		}

		pp = scst_get_next_lexem(&param);
		if (*pp == '\0') {
			PRINT_ERROR("qla2x00t: Parameter %s value missed for "
				"target %s", p, target_name);
			res = -EINVAL;
			goto out;
		}

		if (scst_get_next_lexem(&param)[0] != '\0') {
			PRINT_ERROR("qla2x00t: Too many parameter's %s values "
				"(target %s)", p, target_name);
			res = -EINVAL;
			goto out;
		}

		if (!strcasecmp("node_name", p)) {
			res = q2t_parse_wwn(pp, &node_name);
			if (res) {
				PRINT_ERROR("qla2x00t: Illegal node_name %s "
					"(target %s)", pp, target_name);
				res = -EINVAL;
				goto out;
			}
			node_name_set = true;
			continue;
		}

		if (!strcasecmp("parent_host", p)) {
			res = q2t_parse_wwn(pp, &parent_host);
			if (res != 0) {
				PRINT_ERROR("qla2x00t: Illegal parent_host %s"
					" (target %s)", pp, target_name);
				goto out;
			}
			parent_host_set = true;
			continue;
		}

		PRINT_ERROR("qla2x00t: Unknown parameter %s (target %s)", p,
			target_name);
		res = -EINVAL;
		goto out;
	}

	if (!node_name_set)
		node_name = port_name;

	if (!parent_host_set) {
		PRINT_ERROR("qla2x00t: Missing parameter parent_host "
			"(target %s)", target_name);
		res = -EINVAL;
		goto out;
	}

	res = qla2xxx_add_vtarget(port_name, node_name, parent_host);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t q2t_del_vtarget(const char *target_name)
{
	int res;
	u64 port_name;

	TRACE_ENTRY();

	res = q2t_parse_wwn(target_name, &port_name);
	if (res) {
		PRINT_ERROR("qla2x00t: Syntax error at target name %s",
			target_name);
		goto out;
	}

	res = qla2xxx_del_vtarget(port_name);

out:
	TRACE_EXIT_RES(res);
	return res;
}
#endif /* ENABLE_NPIV */

static int q2t_get_initiator_port_transport_id(struct scst_tgt *tgt,
	struct scst_session *scst_sess, uint8_t **transport_id)
{
	struct q2t_sess *sess;
	int res = 0;
	int tr_id_size;
	uint8_t *tr_id;

	TRACE_ENTRY();

	if (scst_sess == NULL) {
		res = SCSI_TRANSPORTID_PROTOCOLID_FCP2;
		goto out;
	}

	sess = (struct q2t_sess *)scst_sess_get_tgt_priv(scst_sess);

	tr_id_size = 24;

	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (tr_id == NULL) {
		PRINT_ERROR("qla2x00t: Allocation of TransportID (size %d) "
			"failed", tr_id_size);
		res = -ENOMEM;
		goto out;
	}

	tr_id[0] = SCSI_TRANSPORTID_PROTOCOLID_FCP2;

	BUILD_BUG_ON(sizeof(sess->port_name) != 8);
	memcpy(&tr_id[8], sess->port_name, 8);

	*transport_id = tr_id;

	TRACE_BUFF_FLAG(TRACE_DEBUG, "Created tid", tr_id, tr_id_size);

out:
	TRACE_EXIT_RES(res);
	return res;
}


static ssize_t q2t_show_expl_conf_enabled(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buffer)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;

	vha = tgt->vha;

	res = sysfs_emit(buffer, "%d\n", vha->hw->enable_explicit_conf);

	if (vha->hw->enable_explicit_conf)
		res += sysfs_emit_at(buffer, res, "%s\n", SCST_SYSFS_KEY_MARK);

out:
	return res;
}

static ssize_t q2t_store_expl_conf_enabled(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha;
	int res = -E_TGT_PRIV_NOT_YET_SET, old;
	unsigned long flags;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;
	vha = tgt->vha;
	ha = vha->hw;

	/* Only hw port allowed here */
	sBUG_ON(vha->vp_idx != 0);

	old = ha->enable_explicit_conf;

	spin_lock_irqsave(&ha->hardware_lock, flags);

	switch (buffer[0]) {
	case '0':
		ha->enable_explicit_conf = 0;
		PRINT_INFO("qla2x00t(%ld): explicit confirmations disabled",
			vha->host_no);
		break;
	case '1':
		ha->enable_explicit_conf = 1;
		PRINT_INFO("qla2x00t(%ld): explicit confirmations enabled",
			vha->host_no);
		break;
	default:
		PRINT_ERROR("%s: qla2x00t(%ld): Requested action not "
			"understood: %s", __func__, vha->host_no, buffer);
		break;
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (ha->enable_explicit_conf != old) {
		set_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
		qla2x00_wait_for_hba_online(vha);
	}

	res = size;

out:
	return res;
}

static ssize_t q2t_abort_isp_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	int res = -E_TGT_PRIV_NOT_YET_SET;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;
	vha = tgt->vha;

	/* Only hw port allowed here */
	sBUG_ON(vha->vp_idx != 0);

	PRINT_INFO("qla2x00t(%ld): Aborting ISP", vha->host_no);

	set_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
	qla2x00_wait_for_hba_online(vha);

	res = size;

out:
	return res;
}

static ssize_t q2t_version_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	size_t ret = 0;

	ret += sysfs_emit_at(buf, ret, "%s\n", Q2T_VERSION_STRING);

#ifdef CONFIG_SCST_EXTRACHECKS
	ret += sysfs_emit_at(buf, ret, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_SCST_TRACING
	ret += sysfs_emit_at(buf, ret, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	ret += sysfs_emit_at(buf, ret, "DEBUG\n");
#endif

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	ret += sysfs_emit_at(buf, ret, "QLA_TGT_DEBUG_WORK_IN_THREAD\n");
#endif

	TRACE_EXIT();
	return ret;
}

static ssize_t q2t_hw_target_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", 1);
}

static ssize_t q2t_node_name_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;
	char *wwn;
	uint8_t *node_name;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;
	vha = tgt->vha;

	node_name = vha->node_name;

	res = q2t_get_target_name(node_name, &wwn);
	if (res != 0)
		goto out;

	res = sysfs_emit(buf, "%s\n", wwn);

	/* For virtual ports it's always key */
	if (vha->node_name_set || (vha->vp_idx != 0))
		res += sysfs_emit_at(buf, res, "%s\n", SCST_SYSFS_KEY_MARK);

	kfree(wwn);

out:
	return res;
}

static ssize_t q2t_node_name_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	u64 node_name, old_node_name;
	int res = -E_TGT_PRIV_NOT_YET_SET;

	TRACE_ENTRY();

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;
	vha = tgt->vha;

	/* Only hw port allowed to dynamically set node name */
	sBUG_ON(vha->vp_idx != 0);

	if (size == 0)
		goto out_default;

	res = q2t_parse_wwn(buffer, &node_name);
	if (res != 0) {
		if ((buffer[0] == '\0') || (buffer[0] == '\n'))
			goto out_default;
		PRINT_ERROR("qla2x00t(%ld): Wrong node name", vha->host_no);
		goto out;
	}

	old_node_name = wwn_to_u64(vha->node_name);
	if (old_node_name == node_name)
		goto out_success;

	if (vha->node_name_set)
		vha->node_name_set = (node_name != wwn_to_u64(vha->hw->orig_hw_node_name));
	else {
		BUILD_BUG_ON(sizeof(vha->node_name) != sizeof(vha->hw->orig_hw_node_name));
		memcpy(vha->hw->orig_hw_node_name, vha->node_name,
			sizeof(vha->node_name));
		vha->node_name_set = 1;
	}

	u64_to_wwn(node_name, vha->node_name);

abort:
	if (qla_tgt_mode_enabled(vha)) {
		set_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
		qla2x00_wait_for_hba_online(vha);
	}

out_success:
	res = size;

out:
	TRACE_EXIT_RES(res);
	return res;

out_default:
	if (vha->node_name_set)
		memcpy(vha->node_name, vha->hw->orig_hw_node_name,
			sizeof(vha->node_name));
	vha->node_name_set = 0;
	goto abort;
}

static ssize_t q2t_port_name_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	char *wwn;
	uint8_t *port_name;
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	/* Can be called for both HW and V ports */

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;
	vha = tgt->vha;

	port_name = vha->port_name;

	res = q2t_get_target_name(port_name, &wwn);
	if (res != 0)
		goto out;

	res = sysfs_emit(buf, "%s\n", wwn);

	/* For virtual ports it's always key */
	if ((vha->vp_idx != 0) || vha->port_name_set)
		res += sysfs_emit_at(buf, res, "%s\n", SCST_SYSFS_KEY_MARK);

	kfree(wwn);

out:
	return res;
}

static ssize_t q2t_port_name_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *vha;
	u64 port_name, old_port_name;
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	TRACE_ENTRY();

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;
	vha = tgt->vha;

	sBUG_ON(vha->vp_idx != 0);

	if (size == 0)
		goto out_default;

	res = q2t_parse_wwn(buffer, &port_name);
	if (res != 0) {
		if ((buffer[0] == '\0') || (buffer[0] == '\n'))
			goto out_default;
		PRINT_ERROR("qla2x00t(%ld): Wrong port name", vha->host_no);
		goto out;
	}

	old_port_name = wwn_to_u64(vha->port_name);
	if (old_port_name == port_name)
		goto out_success;

	if (vha->port_name_set)
		vha->port_name_set = (port_name != wwn_to_u64(vha->hw->orig_hw_port_name));
	else {
		BUILD_BUG_ON(sizeof(vha->port_name) != sizeof(vha->hw->orig_hw_port_name));
		memcpy(vha->hw->orig_hw_port_name, vha->port_name,
			sizeof(vha->port_name));
		vha->port_name_set = 1;
	}

	u64_to_wwn(port_name, vha->port_name);

abort:
	if (qla_tgt_mode_enabled(vha)) {
		set_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
		qla2x00_wait_for_hba_online(vha);
	}

out_success:
	res = size;

out:
	TRACE_EXIT_RES(res);
	return res;

out_default:
	if (vha->port_name_set)
		memcpy(vha->port_name, vha->hw->orig_hw_port_name,
			sizeof(vha->port_name));
	vha->port_name_set = 0;
	goto abort;
}

static ssize_t q2t_vp_parent_host_show(struct kobject *kobj, struct kobj_attribute *attr,
				       char *buf)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *base_vha;
	char *wwn;
	ssize_t res = -E_TGT_PRIV_NOT_YET_SET;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out;
	base_vha = pci_get_drvdata(tgt->vha->hw->pdev);

	res = q2t_get_target_name(base_vha->port_name, &wwn);
	if (res != 0)
		goto out;

	res = sysfs_emit(buf, "%s\n%s\n", wwn, SCST_SYSFS_KEY_MARK);

	kfree(wwn);

out:
	return res;
}


static uint16_t q2t_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	/* FCP-2 */
	return 0x0900;
}

static uint16_t q2t_get_phys_transport_version(struct scst_tgt *scst_tgt)
{
	return 0x0DA0; /* FC-FS */
}

static int __init q2t_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	BUILD_BUG_ON(sizeof(atio7_entry_t) != sizeof(atio_entry_t));

	PRINT_INFO("qla2x00t: Initializing QLogic Fibre Channel HBA Driver "
		"target mode addon version %s", Q2T_VERSION_STRING);

	q2t_cmd_cachep = KMEM_CACHE(q2t_cmd, SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (q2t_cmd_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	/* it's read-mostly */
	q2t_sess_cachep = KMEM_CACHE(q2t_sess, SCST_SLAB_FLAGS);
	if (q2t_sess_cachep == NULL) {
		res = -ENOMEM;
		goto out_cmd_free;
	}

	/* it's read-mostly */
	q2t_tgt_cachep = KMEM_CACHE(q2t_tgt, SCST_SLAB_FLAGS);
	if (q2t_tgt_cachep == NULL) {
		res = -ENOMEM;
		goto out_sess_free;
	}

	q2t_mgmt_cmd_cachep = KMEM_CACHE(q2t_mgmt_cmd, SCST_SLAB_FLAGS);
	if (q2t_mgmt_cmd_cachep == NULL) {
		res = -ENOMEM;
		goto out_tgt_free;
	}

	q2t_mgmt_cmd_mempool = mempool_create(25, mempool_alloc_slab,
		mempool_free_slab, q2t_mgmt_cmd_cachep);
	if (q2t_mgmt_cmd_mempool == NULL) {
		res = -ENOMEM;
		goto out_kmem_free;
	}

	q2t_target_driver_reg(&tgt2x_template);

	res = scst_register_target_template(&tgt2x_template);
	if (res < 0)
		goto out_mempool_free;

	qla2xxx_add_targets();


out:
	TRACE_EXIT_RES(res);
	return res;


out_mempool_free:
	mempool_destroy(q2t_mgmt_cmd_mempool);

out_kmem_free:
	kmem_cache_destroy(q2t_mgmt_cmd_cachep);

out_tgt_free:
	kmem_cache_destroy(q2t_tgt_cachep);

out_sess_free:
	kmem_cache_destroy(q2t_sess_cachep);

out_cmd_free:
	kmem_cache_destroy(q2t_cmd_cachep);
	goto out;
}

static void __exit q2t_exit(void)
{
	TRACE_ENTRY();

	PRINT_INFO("qla2x00t: %s", "Unloading QLogic Fibre Channel HBA Driver "
		"target mode addon driver");

	/* To sync with q2t_host_action() */
	down_write(&q2t_unreg_rwsem);


	scst_unregister_target_template(&tgt2x_template);

	/*
	 * Now we have everywhere target mode disabled and no possibilities
	 * to call us through sysfs, so we can safely remove all the references
	 * to our functions.
	 */
	qla2xxx_tgt_unregister_driver();

	mempool_destroy(q2t_mgmt_cmd_mempool);
	kmem_cache_destroy(q2t_mgmt_cmd_cachep);
	kmem_cache_destroy(q2t_tgt_cachep);
	kmem_cache_destroy(q2t_sess_cachep);
	kmem_cache_destroy(q2t_cmd_cachep);

	/* Let's make lockdep happy */
	up_write(&q2t_unreg_rwsem);

	TRACE_EXIT();
	return;
}

module_init(q2t_init);
module_exit(q2t_exit);

MODULE_AUTHOR("Vladislav Bolkhovitin and others");
MODULE_DESCRIPTION("Target mode addon for qla2[2,3,4,5+]xx");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(SCST_NAMESPACE);
MODULE_IMPORT_NS(SCST_QLA16_NAMESPACE);
MODULE_VERSION(Q2T_VERSION_STRING);
