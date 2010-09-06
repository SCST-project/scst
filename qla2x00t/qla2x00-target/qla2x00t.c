/*
 *  qla2x00t.c
 *
 *  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *  Copyright (C) 2006 - 2010 ID7 Ltd.
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
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/list.h>

#include <scst.h>

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
#define Q2T_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_SPECIAL)
# endif
#endif

static int q2t_target_detect(struct scst_tgt_template *templ);
static int q2t_target_release(struct scst_tgt *scst_tgt);
static int q2x_xmit_response(struct scst_cmd *scst_cmd);
static int __q24_xmit_response(struct q2t_cmd *cmd, int xmit_type);
static int q2t_rdy_to_xfer(struct scst_cmd *scst_cmd);
static void q2t_on_free_cmd(struct scst_cmd *scst_cmd);
static void q2t_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd);
static int q2t_get_initiator_port_transport_id(struct scst_session *scst_sess,
	uint8_t **transport_id);

/* Predefs for callbacks handed to qla2xxx(target) */
static void q24_atio_pkt(scsi_qla_host_t *ha, atio7_entry_t *pkt);
static void q2t_response_pkt(scsi_qla_host_t *ha, response_t *pkt);
static void q2t_async_event(uint16_t code, scsi_qla_host_t *ha,
	uint16_t *mailbox);
static void q2x_ctio_completion(scsi_qla_host_t *ha, uint32_t handle);
static int q2t_host_action(scsi_qla_host_t *ha,
	qla2x_tgt_host_action_t action);
static void q2t_fc_port_added(scsi_qla_host_t *ha, fc_port_t *fcport);
static void q2t_fc_port_deleted(scsi_qla_host_t *ha, fc_port_t *fcport);
static int q2t_issue_task_mgmt(struct q2t_sess *sess, uint8_t *lun,
	int lun_size, int fn, void *iocb, int flags);
static void q2x_send_term_exchange(scsi_qla_host_t *ha, struct q2t_cmd *cmd,
	atio_entry_t *atio, int ha_locked);
static void q24_send_term_exchange(scsi_qla_host_t *ha, struct q2t_cmd *cmd,
	atio7_entry_t *atio, int ha_locked);
static void q2t_reject_free_srr_imm(scsi_qla_host_t *ha, struct srr_imm *imm,
	int ha_lock);
static int q2t_cut_cmd_data_head(struct q2t_cmd *cmd, unsigned int offset);
static void q2t_clear_tgt_db(struct q2t_tgt *tgt, bool local_only);
static void q2t_on_hw_pending_cmd_timeout(struct scst_cmd *scst_cmd);
static int q2t_unreg_sess(struct q2t_sess *sess);
static uint16_t q2t_get_scsi_transport_version(struct scst_tgt *scst_tgt);
static uint16_t q2t_get_phys_transport_version(struct scst_tgt *scst_tgt);

#ifndef CONFIG_SCST_PROC

/** SYSFS **/

static ssize_t q2t_version_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);

struct kobj_attribute q2t_version_attr =
	__ATTR(version, S_IRUGO, q2t_version_show, NULL);

static const struct attribute *q2t_attrs[] = {
	&q2t_version_attr.attr,
	NULL,
};

static ssize_t q2t_show_expl_conf_enabled(struct kobject *kobj,
	struct kobj_attribute *attr, char *buffer);
static ssize_t q2t_store_expl_conf_enabled(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size);

struct kobj_attribute q2t_expl_conf_attr =
	__ATTR(explicit_confirmation, S_IRUGO|S_IWUSR,
	       q2t_show_expl_conf_enabled, q2t_store_expl_conf_enabled);

static ssize_t q2t_abort_isp_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size);

struct kobj_attribute q2t_abort_isp_attr =
	__ATTR(abort_isp, S_IWUSR, NULL, q2t_abort_isp_store);

static const struct attribute *q2t_tgt_attrs[] = {
	&q2t_expl_conf_attr.attr,
	&q2t_abort_isp_attr.attr,
	NULL,
};

#endif /* CONFIG_SCST_PROC */

static int q2t_enable_tgt(struct scst_tgt *tgt, bool enable);
static bool q2t_is_tgt_enabled(struct scst_tgt *tgt);

/*
 * Global Variables
 */

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag q2t_trace_flag
static unsigned long q2t_trace_flag = Q2T_DEFAULT_LOG_FLAGS;
#endif

static struct scst_tgt_template tgt2x_template = {
#ifdef CONFIG_SCST_PROC
	.name = "qla2x00tgt",
#else
	.name = "qla2x00t",
#endif
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
	.detect = q2t_target_detect,
	.release = q2t_target_release,
	.xmit_response = q2x_xmit_response,
	.rdy_to_xfer = q2t_rdy_to_xfer,
	.on_free_cmd = q2t_on_free_cmd,
	.task_mgmt_fn_done = q2t_task_mgmt_fn_done,
	.get_initiator_port_transport_id = q2t_get_initiator_port_transport_id,
	.get_scsi_transport_version = q2t_get_scsi_transport_version,
	.get_phys_transport_version = q2t_get_phys_transport_version,
	.on_hw_pending_cmd_timeout = q2t_on_hw_pending_cmd_timeout,
	.enable_target = q2t_enable_tgt,
	.is_target_enabled = q2t_is_tgt_enabled,
#ifndef CONFIG_SCST_PROC
	.tgtt_attrs = q2t_attrs,
	.tgt_attrs = q2t_tgt_attrs,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags = Q2T_DEFAULT_LOG_FLAGS,
	.trace_flags = &trace_flag,
#endif
};

static struct kmem_cache *q2t_cmd_cachep;
static struct kmem_cache *q2t_mgmt_cmd_cachep;
static mempool_t *q2t_mgmt_cmd_mempool;

static DECLARE_RWSEM(q2t_unreg_rwsem);

/* It's not yet supported */
static inline int scst_cmd_get_ppl_offset(struct scst_cmd *scst_cmd)
{
	return 0;
}

/* ha->hardware_lock supposed to be held on entry */
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
	uint16_t lid)
{
	struct q2t_sess *sess;
	sBUG_ON(tgt == NULL);
	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if (lid == (sess->loop_id))
			return sess;
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_s_id(struct q2t_tgt *tgt,
	const uint8_t *s_id)
{
	struct q2t_sess *sess;
	sBUG_ON(tgt == NULL);
	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->s_id.b.al_pa == s_id[2]) &&
		    (sess->s_id.b.area == s_id[1]) &&
		    (sess->s_id.b.domain == s_id[0]))
			return sess;
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_s_id_le(struct q2t_tgt *tgt,
	const uint8_t *s_id)
{
	struct q2t_sess *sess;
	sBUG_ON(tgt == NULL);
	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->s_id.b.al_pa == s_id[0]) &&
		    (sess->s_id.b.area == s_id[1]) &&
		    (sess->s_id.b.domain == s_id[2]))
			return sess;
	}
	return NULL;
}

/* ha->hardware_lock supposed to be held on entry */
static inline void q2t_exec_queue(scsi_qla_host_t *ha)
{
	qla2x00_isp_cmd(ha);
}

/* Might release hw lock, then reaquire!! */
static inline int q2t_issue_marker(scsi_qla_host_t *ha, int ha_locked)
{
	/* Send marker if required */
	if (unlikely(ha->marker_needed != 0)) {
		int rc = qla2x00_issue_marker(ha, ha_locked);
		if (rc != QLA_SUCCESS) {
			PRINT_ERROR("qla2x00t(%ld): issue_marker() "
				"failed", ha->instance);
		}
		return rc;
	}
	return QLA_SUCCESS;
}

/*
 * Registers with initiator driver (but target mode isn't enabled till
 * it's turned on via sysfs)
 */
static int q2t_target_detect(struct scst_tgt_template *tgtt)
{
	int res, rc;
	struct qla_tgt_data t = {
		.magic = QLA2X_TARGET_MAGIC,
		.tgt24_atio_pkt = q24_atio_pkt,
		.tgt_response_pkt = q2t_response_pkt,
		.tgt2x_ctio_completion = q2x_ctio_completion,
		.tgt_async_event = q2t_async_event,
		.tgt_host_action = q2t_host_action,
		.tgt_fc_port_added = q2t_fc_port_added,
		.tgt_fc_port_deleted = q2t_fc_port_deleted,
	};

	TRACE_ENTRY();

	rc = qla2xxx_tgt_register_driver(&t);
	if (rc < 0) {
		res = rc;
		PRINT_ERROR("Unable to register driver: %d", res);
		goto out;
	}

	if (rc != QLA2X_INITIATOR_MAGIC) {
		PRINT_ERROR("Wrong version of the initiator part: %d", rc);
		res = -EINVAL;
		goto out;
	}

	qla2xxx_add_targets();

	res = 0;

	PRINT_INFO("%s", "Target mode driver for QLogic 2x00 controller "
		"registered successfully");

out:
	TRACE_EXIT();
	return res;
}

static void q2t_free_session_done(struct scst_session *scst_sess)
{
	struct q2t_sess *sess;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *ha;
	unsigned long flags;

	TRACE_ENTRY();

	sBUG_ON(scst_sess == NULL);
	sess = (struct q2t_sess *)scst_sess_get_tgt_priv(scst_sess);
	sBUG_ON(sess == NULL);
	tgt = sess->tgt;

	TRACE_MGMT_DBG("Unregistration of sess %p finished", sess);

	kfree(sess);

	if (tgt == NULL)
		goto out;

	TRACE_DBG("empty(sess_list) %d sess_count %d",
	      list_empty(&tgt->sess_list), tgt->sess_count);

	ha = tgt->ha;

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
static int q2t_unreg_sess(struct q2t_sess *sess)
{
	int res = 1;

	TRACE_ENTRY();

	sBUG_ON(sess == NULL);
	sBUG_ON(sess->sess_ref != 0);

	TRACE_MGMT_DBG("Deleting sess %p from tgt %p", sess, sess->tgt);
	list_del(&sess->sess_list_entry);

	if (sess->deleted)
		list_del(&sess->del_list_entry);

	PRINT_INFO("qla2x00t(%ld): %ssession for loop_id %d deleted",
		sess->tgt->ha->instance, sess->local ? "local " : "",
		sess->loop_id);

	scst_unregister_session(sess->scst_sess, 0, q2t_free_session_done);

	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_reset(scsi_qla_host_t *ha, void *iocb, int mcmd)
{
	struct q2t_sess *sess;
	int loop_id;
	uint16_t lun = 0;
	int res = 0;

	TRACE_ENTRY();

	if (IS_FWI2_CAPABLE(ha)) {
		notify24xx_entry_t *n = (notify24xx_entry_t *)iocb;
		loop_id = le16_to_cpu(n->nport_handle);
	} else
		loop_id = GET_TARGET_ID(ha, (notify_entry_t *)iocb);

	if (loop_id == 0xFFFF) {
		/* Global event */
		q2t_clear_tgt_db(ha->tgt, 1);
		if (!list_empty(&ha->tgt->sess_list)) {
			sess = list_entry(ha->tgt->sess_list.next,
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
					"command %x in %s", ha->instance,
					mcmd, __func__);
				sess = NULL;
				break;
			}
		} else
			sess = NULL;
	} else
		sess = q2t_find_sess_by_loop_id(ha->tgt, loop_id);

	if (sess == NULL) {
		res = -ESRCH;
		ha->tgt->tm_to_unknown = 1;
		goto out;
	}

	TRACE_MGMT_DBG("scsi(%ld): resetting (session %p from port "
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
		"mcmd %x, loop_id %d)", ha->host_no, sess,
		sess->port_name[0], sess->port_name[1],
		sess->port_name[2], sess->port_name[3],
		sess->port_name[4], sess->port_name[5],
		sess->port_name[6], sess->port_name[7],
		mcmd, loop_id);

	res = q2t_issue_task_mgmt(sess, (uint8_t *)&lun, sizeof(lun),
			mcmd, iocb, Q24_MGMT_SEND_NACK);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_clear_tgt_db(struct q2t_tgt *tgt, bool local_only)
{
	struct q2t_sess *sess, *sess_tmp;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Clearing targets DB %p", tgt);

	list_for_each_entry_safe(sess, sess_tmp, &tgt->sess_list,
					sess_list_entry) {
		if (local_only && !sess->local)
			continue;
		if (local_only && sess->local)
			TRACE_MGMT_DBG("Putting local session %p from port "
				"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
				sess,
				sess->port_name[0], sess->port_name[1],
				sess->port_name[2], sess->port_name[3],
				sess->port_name[4], sess->port_name[5],
				sess->port_name[6], sess->port_name[7]);
		q2t_sess_put(sess);
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
	TRACE_ENTRY();

	if (result != 0) {
		struct q2t_sess *sess = (struct q2t_sess *)data;
		struct q2t_tgt *tgt = sess->tgt;
		scsi_qla_host_t *ha = tgt->ha;
		unsigned long flags;

		PRINT_INFO("qla2x00t(%ld): Session initialization failed",
			   ha->instance);

		spin_lock_irqsave(&ha->hardware_lock, flags);
		q2t_sess_put(sess);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}

	TRACE_EXIT();
	return;
}

static void q2t_del_sess_timer_fn(unsigned long arg)
{
	struct q2t_tgt *tgt = (struct q2t_tgt *)arg;
	scsi_qla_host_t *ha = tgt->ha;
	struct q2t_sess *sess;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&ha->hardware_lock, flags);
	while (!list_empty(&tgt->del_sess_list)) {
		sess = list_entry(tgt->del_sess_list.next, typeof(*sess),
				del_list_entry);
		if (time_after_eq(jiffies, sess->expires)) {
			/*
			 * sess will be deleted from del_sess_list in
			 * q2t_unreg_sess()
			 */
			TRACE_MGMT_DBG("Timeout: sess %p about to be deleted",
				sess);
			q2t_sess_put(sess);
		} else {
			tgt->sess_del_timer.expires = sess->expires;
			add_timer(&tgt->sess_del_timer);
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
static struct q2t_sess *q2t_create_sess(scsi_qla_host_t *ha, fc_port_t *fcport,
	bool local)
{
	char *wwn_str;
	const int wwn_str_len = 3*WWN_SIZE+2;
	struct q2t_tgt *tgt = ha->tgt;
	struct q2t_sess *sess;

	TRACE_ENTRY();

	/* Check to avoid double sessions */
	spin_lock_irq(&ha->hardware_lock);
	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		if ((sess->port_name[0] == fcport->port_name[0]) &&
		    (sess->port_name[1] == fcport->port_name[1]) &&
		    (sess->port_name[2] == fcport->port_name[2]) &&
		    (sess->port_name[3] == fcport->port_name[3]) &&
		    (sess->port_name[4] == fcport->port_name[4]) &&
		    (sess->port_name[5] == fcport->port_name[5]) &&
		    (sess->port_name[6] == fcport->port_name[6]) &&
		    (sess->port_name[7] == fcport->port_name[7])) {
			TRACE_MGMT_DBG("Double sess %p found (s_id %x:%x:%x, "
				"loop_id %d), updating to d_id %x:%x:%x, "
				"loop_id %d", sess, sess->s_id.b.al_pa,
				sess->s_id.b.area, sess->s_id.b.domain,
				sess->loop_id, fcport->d_id.b.al_pa,
				fcport->d_id.b.area, fcport->d_id.b.domain,
				fcport->loop_id);

			if (sess->deleted) {
				list_del(&sess->del_list_entry);
				sess->deleted = 0;
			}

			q2t_sess_get(sess);
			sess->s_id = fcport->d_id;
			sess->loop_id = fcport->loop_id;
			sess->conf_compl_supported = fcport->conf_compl_supported;
			if (sess->local && !local)
				sess->local = false;
			spin_unlock_irq(&ha->hardware_lock);
			goto out;
		}
	}
	spin_unlock_irq(&ha->hardware_lock);

	/* We are under tgt_mutex, so a new sess can't be added behind us */

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (sess == NULL) {
		PRINT_ERROR("qla2x00t(%ld): session allocation failed, "
			"all commands from port %02x:%02x:%02x:%02x:"
			"%02x:%02x:%02x:%02x will be refused", ha->instance,
			fcport->port_name[0], fcport->port_name[1],
			fcport->port_name[2], fcport->port_name[3],
			fcport->port_name[4], fcport->port_name[5],
			fcport->port_name[6], fcport->port_name[7]);
		goto out;
	}

	sess->sess_ref = 2; /* plus 1 extra ref, see above */
	sess->tgt = ha->tgt;
	sess->s_id = fcport->d_id;
	sess->loop_id = fcport->loop_id;
	sess->conf_compl_supported = fcport->conf_compl_supported;
	sess->local = local;
	BUILD_BUG_ON(sizeof(sess->port_name) != sizeof(fcport->port_name));
	memcpy(sess->port_name, fcport->port_name, sizeof(sess->port_name));

	wwn_str = kmalloc(wwn_str_len, GFP_KERNEL);
	if (wwn_str == NULL) {
		PRINT_ERROR("qla2x00t(%ld): Allocation of wwn_str failed. "
			"All commands from port %02x:%02x:%02x:%02x:%02x:%02x:"
			"%02x:%02x will be refused", ha->instance,
			fcport->port_name[0], fcport->port_name[1],
			fcport->port_name[2], fcport->port_name[3],
			fcport->port_name[4], fcport->port_name[5],
			fcport->port_name[6], fcport->port_name[7]);
		goto out_free_sess;
	}

	sprintf(wwn_str, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		fcport->port_name[0], fcport->port_name[1],
		fcport->port_name[2], fcport->port_name[3],
		fcport->port_name[4], fcport->port_name[5],
		fcport->port_name[6], fcport->port_name[7]);

	/* Let's do the session creation async'ly */
	sess->scst_sess = scst_register_session(tgt->scst_tgt, 1, wwn_str,
				sess, sess, q2t_alloc_session_done);
	if (sess->scst_sess == NULL) {
		PRINT_CRIT_ERROR("qla2x00t(%ld): scst_register_session() "
			"failed for host %ld (wwn %s, loop_id %d), all "
			"commands from it will be refused", ha->instance,
			ha->host_no, wwn_str, fcport->loop_id);
		goto out_free_sess_wwn;
	}

	spin_lock_irq(&ha->hardware_lock);
	TRACE_MGMT_DBG("Adding sess %p to tgt %p", sess, tgt);
	list_add_tail(&sess->sess_list_entry, &tgt->sess_list);
	tgt->sess_count++;
	spin_unlock_irq(&ha->hardware_lock);

	PRINT_INFO("qla2x00t(%ld): %ssession for wwn %s (loop_id %d, "
		"s_id %x:%x:%x, confirmed completion %ssupported) added",
		ha->instance, local ? "local " : "", wwn_str, fcport->loop_id,
		sess->s_id.b.al_pa, sess->s_id.b.area, sess->s_id.b.domain,
		sess->conf_compl_supported ? "" : "not ");

	kfree(wwn_str);

out:
	TRACE_EXIT_HRES(sess);
	return sess;

out_free_sess_wwn:
	kfree(wwn_str);
	/* go through */

out_free_sess:
	kfree(sess);
	sess = NULL;
	goto out;
}

static void q2t_fc_port_added(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;

	TRACE_ENTRY();

	mutex_lock(&ha->tgt_mutex);

	tgt = ha->tgt;

	if ((tgt == NULL) || (fcport->port_type != FCT_INITIATOR))
		goto out_unlock;

	if (tgt->tgt_stop)
		goto out_unlock;

	spin_lock_irq(&ha->hardware_lock);

	sess = q2t_find_sess_by_loop_id(tgt, fcport->loop_id);
	if (sess == NULL) {
		spin_unlock_irq(&ha->hardware_lock);
		sess = q2t_create_sess(ha, fcport, false);
		spin_lock_irq(&ha->hardware_lock);
		if (sess != NULL)
			q2t_sess_put(sess); /* put the extra creation ref */
	} else {
		if (sess->deleted) {
			list_del(&sess->del_list_entry);
			sess->deleted = 0;

			PRINT_INFO("qla2x00t(%ld): session for port %02x:"
				"%02x:%02x:%02x:%02x:%02x:%02x:%02x (loop ID %d) "
				"reappeared", ha->instance, fcport->port_name[0],
				fcport->port_name[1], fcport->port_name[2],
				fcport->port_name[3], fcport->port_name[4],
				fcport->port_name[5], fcport->port_name[6],
				fcport->port_name[7], sess->loop_id);
			TRACE_MGMT_DBG("Appeared sess %p", sess);
		} else if (sess->local) {
			TRACE(TRACE_MGMT, "qla2x00t(%ld): local session for "
				"port %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
				"(loop ID %d) became global", ha->instance,
				fcport->port_name[0], fcport->port_name[1],
				fcport->port_name[2], fcport->port_name[3],
				fcport->port_name[4], fcport->port_name[5],
				fcport->port_name[6], fcport->port_name[7],
				sess->loop_id);
		}
		sess->local = 0;
	}

	spin_unlock_irq(&ha->hardware_lock);

out_unlock:
	mutex_unlock(&ha->tgt_mutex);

	TRACE_EXIT();
	return;
}

static void q2t_fc_port_deleted(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;
	uint32_t dev_loss_tmo;

	TRACE_ENTRY();

	mutex_lock(&ha->tgt_mutex);

	tgt = ha->tgt;

	if ((tgt == NULL) || (fcport->port_type != FCT_INITIATOR))
		goto out_unlock;

	dev_loss_tmo = ha->port_down_retry_count + 5;

	if (tgt->tgt_stop)
		goto out_unlock;

	spin_lock_irq(&ha->hardware_lock);

	sess = q2t_find_sess_by_loop_id(tgt, fcport->loop_id);
	if (sess == NULL)
		goto out_unlock_ha;

	if (!sess->deleted) {
		int add_tmr;

		add_tmr = list_empty(&tgt->del_sess_list);

		TRACE_MGMT_DBG("Scheduling sess %p to deletion", sess);
		list_add_tail(&sess->del_list_entry, &tgt->del_sess_list);
		sess->deleted = 1;

		PRINT_INFO("qla2x00t(%ld): %ssession for port %02x:%02x:%02x:"
			"%02x:%02x:%02x:%02x:%02x (loop ID %d) scheduled for "
			"deletion in %d secs", ha->instance,
			sess->local ? "local " : "",
			fcport->port_name[0], fcport->port_name[1],
			fcport->port_name[2], fcport->port_name[3],
			fcport->port_name[4], fcport->port_name[5],
			fcport->port_name[6], fcport->port_name[7],
			sess->loop_id, dev_loss_tmo);

		sess->expires = jiffies + dev_loss_tmo * HZ;
		if (add_tmr)
			mod_timer(&tgt->sess_del_timer, sess->expires);
	}

out_unlock_ha:
	spin_unlock_irq(&ha->hardware_lock);

out_unlock:
	mutex_unlock(&ha->tgt_mutex);

	TRACE_EXIT();
	return;
}

static inline int test_tgt_sess_count(struct q2t_tgt *tgt)
{
	unsigned long flags;
	int res;

	/*
	 * We need to protect against race, when tgt is freed before or
	 * inside wake_up()
	 */
	spin_lock_irqsave(&tgt->ha->hardware_lock, flags);
	TRACE_DBG("tgt %p, empty(sess_list)=%d sess_count=%d",
	      tgt, list_empty(&tgt->sess_list), tgt->sess_count);
	res = (tgt->sess_count == 0);
	spin_unlock_irqrestore(&tgt->ha->hardware_lock, flags);

	return res;
}

/* Must be called under tgt_host_action_mutex or q2t_unreg_rwsem write locked */
static void q2t_target_stop(struct scst_tgt *scst_tgt)
{
	struct q2t_tgt *tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *ha = tgt->ha;

	TRACE_ENTRY();

	TRACE_DBG("Stopping target for host %ld(%p)", ha->host_no, ha);

	/*
	 * Mutex needed to sync with q2t_fc_port_[added,deleted].
	 * Lock is needed, because we still can get an incoming packet.
	 */

	mutex_lock(&ha->tgt_mutex);
	spin_lock_irq(&ha->hardware_lock);
	tgt->tgt_stop = 1;
	q2t_clear_tgt_db(tgt, false);
	spin_unlock_irq(&ha->hardware_lock);
	mutex_unlock(&ha->tgt_mutex);

	del_timer_sync(&tgt->sess_del_timer);

	TRACE_MGMT_DBG("Waiting for sess works (tgt %p)", tgt);
	spin_lock_irq(&tgt->sess_work_lock);
	while (!list_empty(&tgt->sess_works_list)) {
		spin_unlock_irq(&tgt->sess_work_lock);
		flush_scheduled_work();
		spin_lock_irq(&tgt->sess_work_lock);
	}
	spin_unlock_irq(&tgt->sess_work_lock);

	TRACE_MGMT_DBG("Waiting for tgt %p: list_empty(sess_list)=%d "
		"sess_count=%d", tgt, list_empty(&tgt->sess_list),
		tgt->sess_count);

	wait_event(tgt->waitQ, test_tgt_sess_count(tgt));

	/* Big hammer */
	if (!ha->host_shutting_down && qla_tgt_mode_enabled(ha))
		qla2x00_disable_tgt_mode(ha);

	/* Wait for sessions to clear out (just in case) */
	wait_event(tgt->waitQ, test_tgt_sess_count(tgt));

	TRACE_MGMT_DBG("Waiting for %d IRQ commands to complete (tgt %p)",
		tgt->irq_cmd_count, tgt);

	mutex_lock(&ha->tgt_mutex);
	spin_lock_irq(&ha->hardware_lock);
	while (tgt->irq_cmd_count != 0) {
		spin_unlock_irq(&ha->hardware_lock);
		udelay(2);
		spin_lock_irq(&ha->hardware_lock);
	}
	ha->tgt = NULL;
	spin_unlock_irq(&ha->hardware_lock);
	mutex_unlock(&ha->tgt_mutex);

	TRACE_MGMT_DBG("Stop of tgt %p finished", tgt);

	TRACE_EXIT();
	return;
}

/* Must be called under tgt_host_action_mutex or q2t_unreg_rwsem write locked */
static int q2t_target_release(struct scst_tgt *scst_tgt)
{
	struct q2t_tgt *tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *ha = tgt->ha;

	TRACE_ENTRY();

	q2t_target_stop(scst_tgt);

	ha->q2t_tgt = NULL;
	scst_tgt_set_tgt_priv(scst_tgt, NULL);

	TRACE_MGMT_DBG("Release of tgt %p finished", tgt);

	kfree(tgt);

	TRACE_EXIT();
	return 0;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q2x_modify_command_count(scsi_qla_host_t *ha, int cmd_count,
	int imm_count)
{
	modify_lun_entry_t *pkt;

	TRACE_ENTRY();

	TRACE_DBG("Sending MODIFY_LUN (ha=%p, cmd=%d, imm=%d)",
		  ha, cmd_count, imm_count);

	/* Sending marker isn't necessary, since we called from ISR */

	pkt = (modify_lun_entry_t *)qla2x00_req_pkt(ha);
	if (pkt == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out;
	}

	ha->tgt->modify_lun_expected++;

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

	q2t_exec_queue(ha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q2x_send_notify_ack(scsi_qla_host_t *ha, notify_entry_t *iocb,
	uint32_t add_flags, uint16_t resp_code, int resp_code_valid,
	uint16_t srr_flags, uint16_t srr_reject_code, uint8_t srr_explan)
{
	nack_entry_t *ntfy;

	TRACE_ENTRY();

	TRACE_DBG("Sending NOTIFY_ACK (ha=%p)", ha);

	/* Send marker if required */
	if (q2t_issue_marker(ha, 1) != QLA_SUCCESS)
		goto out;

	ntfy = (nack_entry_t *)qla2x00_req_pkt(ha);
	if (ntfy == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out;
	}

	if (ha->tgt != NULL)
		ha->tgt->notify_ack_expected++;

	ntfy->entry_type = NOTIFY_ACK_TYPE;
	ntfy->entry_count = 1;
	SET_TARGET_ID(ha, ntfy->target, GET_TARGET_ID(ha, iocb));
	ntfy->status = iocb->status;
	ntfy->task_flags = iocb->task_flags;
	ntfy->seq_id = iocb->seq_id;
	/* Do not increment here, the chip isn't decrementing */
	/* ntfy->flags = __constant_cpu_to_le16(NOTIFY_ACK_RES_COUNT); */
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
		ntfy->flags |= __constant_cpu_to_le16(
			NOTIFY_ACK_TM_RESP_CODE_VALID);
	}

	TRACE(TRACE_SCSI, "Sending Notify Ack Seq %#x -> I %#x St %#x RC %#x",
	      le16_to_cpu(iocb->seq_id), GET_TARGET_ID(ha, iocb),
	      le16_to_cpu(iocb->status), le16_to_cpu(ntfy->resp_code));
	TRACE_BUFFER("Notify Ack packet data", ntfy, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q24_send_abts_resp(scsi_qla_host_t *ha,
	const abts24_recv_entry_t *abts, uint32_t status, bool ids_reversed)
{
	abts24_resp_entry_t *resp;
	uint32_t f_ctl;
	uint8_t *p;

	TRACE_ENTRY();

	TRACE_DBG("Sending task mgmt ABTS response (ha=%p, atio=%p, "
		"status=%x", ha, abts, status);

	/* Send marker if required */
	if (q2t_issue_marker(ha, 1) != QLA_SUCCESS)
		goto out;

	resp = (abts24_resp_entry_t *)qla2x00_req_pkt(ha);
	if (resp == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out;
	}

	resp->entry_type = ABTS_RESP_24XX;
	resp->entry_count = 1;
	resp->nport_handle = abts->nport_handle;
	resp->sof_type = abts->sof_type;
	resp->exchange_address = abts->exchange_address;
	resp->fcp_hdr_le = abts->fcp_hdr_le;
	f_ctl = __constant_cpu_to_le32(F_CTL_EXCH_CONTEXT_RESP |
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

	ha->tgt->abts_resp_expected++;

	q2t_exec_queue(ha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q24_retry_term_exchange(scsi_qla_host_t *ha,
	abts24_resp_fw_entry_t *entry)
{
	ctio7_status1_entry_t *ctio;

	TRACE_ENTRY();

	TRACE_DBG("Sending retry TERM EXCH CTIO7 (ha=%p)", ha);

	/* Send marker if required */
	if (q2t_issue_marker(ha, 1) != QLA_SUCCESS)
		goto out;

	ctio = (ctio7_status1_entry_t *)qla2x00_req_pkt(ha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
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
	ctio->common.timeout = __constant_cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.initiator_id[0] = entry->fcp_hdr_le.d_id[0];
	ctio->common.initiator_id[1] = entry->fcp_hdr_le.d_id[1];
	ctio->common.initiator_id[2] = entry->fcp_hdr_le.d_id[2];
	ctio->common.exchange_addr = entry->exchange_addr_to_abort;
	ctio->flags = __constant_cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_TERMINATE);
	ctio->ox_id = entry->fcp_hdr_le.ox_id;

	TRACE_BUFFER("CTIO7 retry TERM EXCH packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

	q24_send_abts_resp(ha, (abts24_recv_entry_t *)entry,
		SCST_MGMT_STATUS_SUCCESS, true);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q24_handle_abts(scsi_qla_host_t *ha, abts24_recv_entry_t *abts)
{
	uint32_t tag;
	int rc;
	struct q2t_mgmt_cmd *mcmd;
	struct q2t_sess *sess;

	TRACE_ENTRY();

	if (le32_to_cpu(abts->fcp_hdr_le.parameter) & ABTS_PARAM_ABORT_SEQ) {
		PRINT_ERROR("qla2x00t(%ld): ABTS: Abort Sequence not "
			"supported", ha->instance);
		goto out_err;
	}

	tag = abts->exchange_addr_to_abort;

	if (tag == ATIO_EXCHANGE_ADDRESS_UNKNOWN) {
		TRACE_MGMT_DBG("qla2x00t(%ld): ABTS: Unknown Exchange "
			"Address received", ha->instance);
		goto out_err;
	}

	TRACE(TRACE_MGMT, "qla2x00t(%ld): task abort (s_id=%x:%x:%x, "
		"tag=%d, param=%x)", ha->instance, abts->fcp_hdr_le.s_id[0],
		abts->fcp_hdr_le.s_id[1], abts->fcp_hdr_le.s_id[2], tag,
		le32_to_cpu(abts->fcp_hdr_le.parameter));

	sess = q2t_find_sess_by_s_id_le(ha->tgt, abts->fcp_hdr_le.s_id);
	if (sess == NULL) {
		TRACE(TRACE_MGMT, "qla2x00t(%ld): task abort for unexisting "
			"session", ha->instance);
		ha->tgt->tm_to_unknown = 1;
		goto out_err;
	}

	mcmd = mempool_alloc(q2t_mgmt_cmd_mempool, GFP_ATOMIC);
	if (mcmd == NULL) {
		PRINT_ERROR("%s: Allocation of ABORT cmd failed", __func__);
		goto out_err;
	}
	memset(mcmd, 0, sizeof(*mcmd));

	mcmd->sess = sess;
	memcpy(&mcmd->orig_iocb.abts, abts, sizeof(mcmd->orig_iocb.abts));

	rc = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK, tag,
		SCST_ATOMIC, mcmd);
	if (rc != 0) {
		PRINT_ERROR("qla2x00t(%ld): scst_rx_mgmt_fn_tag() failed: %d",
			    ha->instance, rc);
		goto out_err_free;
	}

out:
	TRACE_EXIT();
	return;

out_err_free:
	mempool_free(mcmd, q2t_mgmt_cmd_mempool);

out_err:
	q24_send_abts_resp(ha, abts, SCST_MGMT_STATUS_REJECTED, false);
	goto out;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q24_send_task_mgmt_ctio(scsi_qla_host_t *ha,
	struct q2t_mgmt_cmd *mcmd, uint32_t resp_code)
{
	const atio7_entry_t *atio = &mcmd->orig_iocb.atio7;
	ctio7_status1_entry_t *ctio;

	TRACE_ENTRY();

	TRACE_DBG("Sending task mgmt CTIO7 (ha=%p, atio=%p, resp_code=%x",
		  ha, atio, resp_code);

	/* Send marker if required */
	if (q2t_issue_marker(ha, 1) != QLA_SUCCESS)
		goto out;

	ctio = (ctio7_status1_entry_t *)qla2x00_req_pkt(ha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out;
	}

	ctio->common.entry_type = CTIO_TYPE7;
	ctio->common.entry_count = 1;
	ctio->common.handle = Q2T_SKIP_HANDLE | CTIO_COMPLETION_HANDLE_MARK;
	ctio->common.nport_handle = mcmd->sess->loop_id;
	ctio->common.timeout = __constant_cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	ctio->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	ctio->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	ctio->common.exchange_addr = atio->exchange_addr;
	ctio->flags = (atio->attr << 9) | __constant_cpu_to_le16(
		CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_SEND_STATUS);
	ctio->ox_id = swab16(atio->fcp_hdr.ox_id);
	ctio->scsi_status = __constant_cpu_to_le16(SS_RESPONSE_INFO_LEN_VALID);
	ctio->response_len = __constant_cpu_to_le16(8);
	((uint32_t *)ctio->sense_data)[0] = cpu_to_be32(resp_code);

	TRACE_BUFFER("CTIO7 TASK MGMT packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q24_send_notify_ack(scsi_qla_host_t *ha,
	notify24xx_entry_t *iocb, uint16_t srr_flags,
	uint8_t srr_reject_code, uint8_t srr_explan)
{
	nack24xx_entry_t *nack;

	TRACE_ENTRY();

	TRACE_DBG("Sending NOTIFY_ACK24 (ha=%p)", ha);

	/* Send marker if required */
	if (q2t_issue_marker(ha, 1) != QLA_SUCCESS)
		goto out;

	if (ha->tgt != NULL)
		ha->tgt->notify_ack_expected++;

	nack = (nack24xx_entry_t *)qla2x00_req_pkt(ha);
	if (nack == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out;
	}

	nack->entry_type = NOTIFY_ACK_TYPE;
	nack->entry_count = 1;
	nack->nport_handle = iocb->nport_handle;
	if (le16_to_cpu(iocb->status) == IMM_NTFY_ELS) {
		nack->flags = iocb->flags &
			__constant_cpu_to_le32(NOTIFY24XX_FLAGS_PUREX_IOCB);
	}
	nack->srr_rx_id = iocb->srr_rx_id;
	nack->status = iocb->status;
	nack->status_subcode = iocb->status_subcode;
	nack->exchange_address = iocb->exchange_address;
	nack->srr_rel_offs = iocb->srr_rel_offs;
	nack->srr_ui = iocb->srr_ui;
	nack->srr_flags = cpu_to_le16(srr_flags);
	nack->srr_reject_code = srr_reject_code;
	nack->srr_reject_code_expl = srr_explan;
	nack->ox_id = iocb->ox_id;

	TRACE(TRACE_SCSI, "Sending 24xx Notify Ack %d", nack->status);
	TRACE_BUFFER("24xx Notify Ack packet data", nack, sizeof(*nack));

	q2t_exec_queue(ha);

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
	scsi_qla_host_t *ha;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("scst_mcmd (%p) status %#x state %#x", scst_mcmd,
		scst_mcmd->status, scst_mcmd->state);

	mcmd = scst_mgmt_cmd_get_tgt_priv(scst_mcmd);
	if (unlikely(mcmd == NULL)) {
		PRINT_ERROR("scst_mcmd %p tgt_spec is NULL", mcmd);
		goto out;
	}

	ha = mcmd->sess->tgt->ha;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (IS_FWI2_CAPABLE(ha)) {
		if (mcmd->flags == Q24_MGMT_SEND_NACK) {
			q24_send_notify_ack(ha,
				&mcmd->orig_iocb.notify_entry24, 0, 0, 0);
		} else {
			if (scst_mcmd->fn == SCST_ABORT_TASK)
				q24_send_abts_resp(ha, &mcmd->orig_iocb.abts,
					scst_mgmt_cmd_get_status(scst_mcmd),
					false);
			else
				q24_send_task_mgmt_ctio(ha, mcmd,
					q2t_convert_to_fc_tm_status(
						scst_mgmt_cmd_get_status(scst_mcmd)));
		}
	} else {
		uint32_t resp_code = q2t_convert_to_fc_tm_status(
					scst_mgmt_cmd_get_status(scst_mcmd));
		q2x_send_notify_ack(ha, &mcmd->orig_iocb.notify_entry, 0,
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

	prm->sg = (struct scatterlist *)prm->cmd->sg;
	prm->seg_cnt = pci_map_sg(prm->tgt->ha->pdev, prm->cmd->sg,
		prm->cmd->sg_cnt, prm->cmd->dma_data_direction);
	if (unlikely(prm->seg_cnt == 0))
		goto out_err;
	/*
	 * If greater than four sg entries then we need to allocate
	 * the continuation entries
	 */
	if (prm->seg_cnt > prm->tgt->datasegs_per_cmd) {
		prm->req_cnt += (uint16_t)(prm->seg_cnt -
				prm->tgt->datasegs_per_cmd) /
				prm->tgt->datasegs_per_cont;
		if (((uint16_t)(prm->seg_cnt - prm->tgt->datasegs_per_cmd)) %
		    prm->tgt->datasegs_per_cont)
			prm->req_cnt++;
	}

out:
	TRACE_DBG("seg_cnt=%d, req_cnt=%d, res=%d", prm->seg_cnt,
		prm->req_cnt, res);
	return res;

out_err:
	PRINT_ERROR("qla2x00t(%ld): PCI mapping failed: sg_cnt=%d",
		prm->tgt->ha->instance, prm->cmd->sg_cnt);
	res = -1;
	goto out;
}

static int q2t_check_reserve_free_req(scsi_qla_host_t *ha, uint32_t req_cnt)
{
	int res = SCST_TGT_RES_SUCCESS;
	device_reg_t __iomem *reg = ha->iobase;
	uint32_t cnt;

	TRACE_ENTRY();

	if (ha->req_q_cnt < (req_cnt + 2)) {
		if (IS_FWI2_CAPABLE(ha))
			cnt = (uint16_t)RD_REG_DWORD(
				    &reg->isp24.req_q_out);
		else
			cnt = qla2x00_debounce_register(
				    ISP_REQ_Q_OUT(ha, &reg->isp));
		TRACE_DBG("Request ring circled: cnt=%d, "
			"ha->req_ring_index=%d, ha->req_q_cnt=%d, req_cnt=%d",
			cnt, ha->req_ring_index, ha->req_q_cnt, req_cnt);
		if  (ha->req_ring_index < cnt)
			ha->req_q_cnt = cnt - ha->req_ring_index;
		else
			ha->req_q_cnt = ha->request_q_length -
			    (ha->req_ring_index - cnt);
	}

	if (unlikely(ha->req_q_cnt < (req_cnt + 2))) {
		TRACE(TRACE_OUT_OF_MEM, "There is no room in the request ring: "
			"ha->req_ring_index=%d, ha->req_q_cnt=%d, req_cnt=%d",
			ha->req_ring_index, ha->req_q_cnt, req_cnt);
		res = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	}

	ha->req_q_cnt -= req_cnt;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static inline void *q2t_get_req_pkt(scsi_qla_host_t *ha)
{
	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else {
		ha->request_ring_ptr++;
	}
	return (cont_entry_t *)ha->request_ring_ptr;
}

/* ha->hardware_lock supposed to be held on entry */
static inline uint32_t q2t_make_handle(scsi_qla_host_t *ha)
{
	uint32_t h;

	h = ha->current_handle;
	/* always increment cmd handle */
	do {
		++h;
		if (h > MAX_OUTSTANDING_COMMANDS)
			h = 1; /* 0 is Q2T_NULL_HANDLE */
		if (h == ha->current_handle) {
			TRACE(TRACE_OUT_OF_MEM,
			      "Ran out of empty cmd slots in ha %p", ha);
			h = Q2T_NULL_HANDLE;
			break;
		}
	} while ((h == Q2T_NULL_HANDLE) ||
		 (h == Q2T_SKIP_HANDLE) ||
		 (ha->cmds[h-1] != NULL));

	if (h != Q2T_NULL_HANDLE)
		ha->current_handle = h;

	return h;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2x_build_ctio_pkt(struct q2t_prm *prm)
{
	uint32_t h;
	ctio_entry_t *pkt;
	scsi_qla_host_t *ha = prm->tgt->ha;

	pkt = (ctio_entry_t *)ha->request_ring_ptr;
	prm->pkt = pkt;
	memset(pkt, 0, sizeof(*pkt));

	if (prm->tgt->tgt_enable_64bit_addr)
		pkt->common.entry_type = CTIO_A64_TYPE;
	else
		pkt->common.entry_type = CONTINUE_TGT_IO_TYPE;

	pkt->common.entry_count = (uint8_t)prm->req_cnt;

	h = q2t_make_handle(ha);
	if (h != Q2T_NULL_HANDLE)
		ha->cmds[h-1] = prm->cmd;

	pkt->common.handle = h | CTIO_COMPLETION_HANDLE_MARK;
	pkt->common.timeout = __constant_cpu_to_le16(Q2T_TIMEOUT);

	/* Set initiator ID */
	h = GET_TARGET_ID(ha, &prm->cmd->atio.atio2x);
	SET_TARGET_ID(ha, pkt->common.target, h);

	pkt->common.rx_id = prm->cmd->atio.atio2x.rx_id;
	pkt->common.relative_offset = cpu_to_le32(prm->cmd->offset);

	TRACE(TRACE_DEBUG|TRACE_SCSI,
	      "handle(scst_cmd) -> %08x, timeout %d L %#x -> I %#x E %#x",
	      pkt->common.handle, Q2T_TIMEOUT,
	      le16_to_cpu(prm->cmd->atio.atio2x.lun),
	      GET_TARGET_ID(ha, &pkt->common), pkt->common.rx_id);
}

/* ha->hardware_lock supposed to be held on entry */
static int q24_build_ctio_pkt(struct q2t_prm *prm)
{
	uint32_t h;
	ctio7_status0_entry_t *pkt;
	scsi_qla_host_t *ha = prm->tgt->ha;
	atio7_entry_t *atio = &prm->cmd->atio.atio7;
	int res = SCST_TGT_RES_SUCCESS;

	TRACE_ENTRY();

	pkt = (ctio7_status0_entry_t *)ha->request_ring_ptr;
	prm->pkt = pkt;
	memset(pkt, 0, sizeof(*pkt));

	pkt->common.entry_type = CTIO_TYPE7;
	pkt->common.entry_count = (uint8_t)prm->req_cnt;

	h = q2t_make_handle(ha);
	if (unlikely(h == Q2T_NULL_HANDLE)) {
		/*
		 * CTIO type 7 from the firmware doesn't provide a way to
		 * know the initiator's LOOP ID, hence we can't find
		 * the session and, so, the command.
		 */
		res = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	} else
		ha->cmds[h-1] = prm->cmd;

	pkt->common.handle = h | CTIO_COMPLETION_HANDLE_MARK;
	pkt->common.nport_handle = prm->cmd->loop_id;
	pkt->common.timeout = __constant_cpu_to_le16(Q2T_TIMEOUT);
	pkt->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	pkt->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	pkt->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	pkt->common.exchange_addr = atio->exchange_addr;
	pkt->flags |= (atio->attr << 9);
	pkt->ox_id = swab16(atio->fcp_hdr.ox_id);
	pkt->relative_offset = cpu_to_le32(prm->cmd->offset);

out:
	TRACE(TRACE_DEBUG|TRACE_SCSI, "handle(scst_cmd) -> %08x, timeout %d "
		"ox_id %#x", pkt->common.handle, Q2T_TIMEOUT,
		le16_to_cpu(pkt->ox_id));
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
	int enable_64bit_addressing = prm->tgt->tgt_enable_64bit_addr;

	TRACE_ENTRY();

	/* Build continuation packets */
	while (prm->seg_cnt > 0) {
		cont_a64_entry_t *cont_pkt64 =
			(cont_a64_entry_t *)q2t_get_req_pkt(prm->tgt->ha);

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
			*dword_ptr++ =
			    cpu_to_le32(pci_dma_lo32
					(sg_dma_address(prm->sg)));
			if (enable_64bit_addressing) {
				*dword_ptr++ =
				    cpu_to_le32(pci_dma_hi32
						(sg_dma_address
						 (prm->sg)));
			}
			*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

			TRACE_SG("S/G Segment Cont. phys_addr=%llx:%llx, len=%d",
			      (long long unsigned int)pci_dma_hi32(sg_dma_address(prm->sg)),
			      (long long unsigned int)pci_dma_lo32(sg_dma_address(prm->sg)),
			      (int)sg_dma_len(prm->sg));

			prm->sg++;
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
	int enable_64bit_addressing = prm->tgt->tgt_enable_64bit_addr;
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
		*dword_ptr++ =
		    cpu_to_le32(pci_dma_lo32(sg_dma_address(prm->sg)));
		if (enable_64bit_addressing) {
			*dword_ptr++ =
			    cpu_to_le32(pci_dma_hi32
					(sg_dma_address(prm->sg)));
		}
		*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

		TRACE_SG("S/G Segment phys_addr=%llx:%llx, len=%d",
		      (long long unsigned int)pci_dma_hi32(sg_dma_address(prm->sg)),
		      (long long unsigned int)pci_dma_lo32(sg_dma_address(prm->sg)),
		      (int)sg_dma_len(prm->sg));

		prm->sg++;
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
	int enable_64bit_addressing = prm->tgt->tgt_enable_64bit_addr;
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
	for (cnt = 0;
	     (cnt < prm->tgt->datasegs_per_cmd) && prm->seg_cnt;
	     cnt++, prm->seg_cnt--) {
		*dword_ptr++ =
		    cpu_to_le32(pci_dma_lo32(sg_dma_address(prm->sg)));
		if (enable_64bit_addressing) {
			*dword_ptr++ =
			    cpu_to_le32(pci_dma_hi32(
					sg_dma_address(prm->sg)));
		}
		*dword_ptr++ = cpu_to_le32(sg_dma_len(prm->sg));

		TRACE_SG("S/G Segment phys_addr=%llx:%llx, len=%d",
		      (long long unsigned int)pci_dma_hi32(sg_dma_address(
								prm->sg)),
		      (long long unsigned int)pci_dma_lo32(sg_dma_address(
								prm->sg)),
		      (int)sg_dma_len(prm->sg));

		prm->sg++;
	}

	q2t_load_cont_data_segments(prm);

out:
	return;
}

static inline int q2t_has_data(struct q2t_cmd *cmd)
{
	return cmd->bufflen > 0;
}

static int q2t_pre_xmit_response(struct q2t_cmd *cmd,
	struct q2t_prm *prm, int xmit_type, unsigned long *flags)
{
	int res;
	struct q2t_tgt *tgt = cmd->tgt;
	scsi_qla_host_t *ha = tgt->ha;
	uint16_t full_req_cnt;
	struct scst_cmd *scst_cmd = cmd->scst_cmd;

	TRACE_ENTRY();

	if (unlikely(cmd->aborted)) {
		TRACE_MGMT_DBG("qla2x00t(%ld): terminating exchange "
			"for aborted cmd=%p (scst_cmd=%p, tag=%d)",
			ha->instance, cmd, scst_cmd, cmd->tag);

		cmd->state = Q2T_STATE_ABORTED;
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);

		if (IS_FWI2_CAPABLE(ha))
			q24_send_term_exchange(ha, cmd, &cmd->atio.atio7, 0);
		else
			q2x_send_term_exchange(ha, cmd, &cmd->atio.atio2x, 0);
		/* !! At this point cmd could be already freed !! */
		res = Q2T_PRE_XMIT_RESP_CMD_ABORTED;
		goto out;
	}

	TRACE(TRACE_SCSI, "tag=%lld", scst_cmd_get_tag(scst_cmd));

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
	if (q2t_issue_marker(ha, 0) != QLA_SUCCESS) {
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out;
	}

	TRACE_DBG("CTIO start: ha(%d)", (int)ha->instance);

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
					"op %x, bufflen %d, rq_result %x)",
					prm->residual, scst_cmd->tag,
					scst_cmd->cdb[0], cmd->bufflen,
					prm->rq_result);
				prm->rq_result |= SS_RESIDUAL_UNDER;
			} else if (prm->residual < 0) {
				TRACE_DBG("Residual overflow: %d (tag %lld, "
					"op %x, bufflen %d, rq_result %x)",
					prm->residual, scst_cmd->tag,
					scst_cmd->cdb[0], cmd->bufflen,
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
			if (SCST_SENSE_VALID(prm->sense_buffer) ||
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
	res = q2t_check_reserve_free_req(ha, full_req_cnt);
	if (unlikely(res != SCST_TGT_RES_SUCCESS) &&
	    (xmit_type & Q2T_XMIT_DATA))
		goto out_unlock_free_unmap;

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock_free_unmap:
	if (q2t_has_data(cmd))
		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
		     cmd->dma_data_direction);

	/* Release ring specific lock */
	spin_unlock_irqrestore(&ha->hardware_lock, *flags);
	goto out;
}

static inline int q2t_need_explicit_conf(scsi_qla_host_t *ha,
	struct q2t_cmd *cmd, int sending_sense)
{
	if (ha->enable_class_2)
		return 0;

	if (sending_sense)
		return cmd->conf_compl_supported;
	else
		return ha->enable_explicit_conf && cmd->conf_compl_supported;
}

static void q2x_init_ctio_ret_entry(ctio_ret_entry_t *ctio_m1,
	struct q2t_prm *prm)
{
	TRACE_ENTRY();

	prm->sense_buffer_len = min((uint32_t)prm->sense_buffer_len,
				    (uint32_t)sizeof(ctio_m1->sense_data));

	ctio_m1->flags = __constant_cpu_to_le16(OF_SSTS | OF_FAST_POST |
				     OF_NO_DATA | OF_SS_MODE_1);
	ctio_m1->flags |= __constant_cpu_to_le16(OF_INC_RC);
	if (q2t_need_explicit_conf(prm->tgt->ha, prm->cmd, 0)) {
		ctio_m1->flags |= __constant_cpu_to_le16(OF_EXPL_CONF |
					OF_CONF_REQ);
	}
	ctio_m1->scsi_status = cpu_to_le16(prm->rq_result);
	ctio_m1->residual = cpu_to_le32(prm->residual);
	if (SCST_SENSE_VALID(prm->sense_buffer)) {
		if (q2t_need_explicit_conf(prm->tgt->ha, prm->cmd, 1)) {
			ctio_m1->flags |= __constant_cpu_to_le16(OF_EXPL_CONF |
						OF_CONF_REQ);
		}
		ctio_m1->scsi_status |= __constant_cpu_to_le16(
						SS_SENSE_LEN_VALID);
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
	scsi_qla_host_t *ha;
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

	ha = prm.tgt->ha;

	q2x_build_ctio_pkt(&prm);
	pkt = (ctio_common_entry_t *)prm.pkt;

	if (q2t_has_data(cmd) && (xmit_type & Q2T_XMIT_DATA)) {
		pkt->flags |= __constant_cpu_to_le16(OF_FAST_POST | OF_DATA_IN);
		pkt->flags |= __constant_cpu_to_le16(OF_INC_RC);

		q2x_load_data_segments(&prm);

		if (prm.add_status_pkt == 0) {
			if (xmit_type & Q2T_XMIT_STATUS) {
				pkt->scsi_status = cpu_to_le16(prm.rq_result);
				pkt->residual = cpu_to_le32(prm.residual);
				pkt->flags |= __constant_cpu_to_le16(OF_SSTS);
				if (q2t_need_explicit_conf(ha, cmd, 0)) {
					pkt->flags |= __constant_cpu_to_le16(
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
				(ctio_ret_entry_t *)q2t_get_req_pkt(ha);

			TRACE_DBG("%s", "Building additional status packet");

			memcpy(ctio_m1, pkt, sizeof(*ctio_m1));
			ctio_m1->entry_count = 1;
			ctio_m1->dseg_count = 0;

			/* Real finish is ctio_m1's finish */
			pkt->handle |= CTIO_INTERMEDIATE_HANDLE_MARK;
			pkt->flags &= ~__constant_cpu_to_le16(OF_INC_RC);

			q2x_init_ctio_ret_entry(ctio_m1, &prm);
			TRACE_BUFFER("Status CTIO packet data", ctio_m1,
				REQUEST_ENTRY_SIZE);
		}
	} else
		q2x_init_ctio_ret_entry((ctio_ret_entry_t *)pkt, &prm);

	cmd->state = Q2T_STATE_PROCESSED;	/* Mid-level is done processing */

	TRACE_BUFFER("Xmitting", pkt, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

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
	struct q2t_cmd *cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);

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
	cmd->aborted = scst_cmd_aborted(scst_cmd);

	q2t_check_srr_debug(cmd, &xmit_type);

	TRACE_DBG("is_send_status=%x, cmd->bufflen=%d, cmd->sg_cnt=%d, "
		"cmd->data_direction=%d", is_send_status, cmd->bufflen,
		cmd->sg_cnt, cmd->data_direction);

	if (IS_FWI2_CAPABLE(cmd->tgt->ha))
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

	prm->sense_buffer_len = min((uint32_t)prm->sense_buffer_len,
				    (uint32_t)sizeof(ctio1->sense_data));
	ctio->flags |= __constant_cpu_to_le16(CTIO7_FLAGS_SEND_STATUS);
	if (q2t_need_explicit_conf(prm->tgt->ha, prm->cmd, 0)) {
		ctio->flags |= __constant_cpu_to_le16(
				CTIO7_FLAGS_EXPLICIT_CONFORM |
				CTIO7_FLAGS_CONFORM_REQ);
	}
	ctio->residual = cpu_to_le32(prm->residual);
	ctio->scsi_status = cpu_to_le16(prm->rq_result);
	if (SCST_SENSE_VALID(prm->sense_buffer)) {
		int i;
		ctio1 = (ctio7_status1_entry_t *)ctio;
		if (q2t_need_explicit_conf(prm->tgt->ha, prm->cmd, 1)) {
			ctio1->flags |= __constant_cpu_to_le16(
				CTIO7_FLAGS_EXPLICIT_CONFORM |
				CTIO7_FLAGS_CONFORM_REQ);
		}
		ctio1->flags &= ~__constant_cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_0);
		ctio1->flags |= __constant_cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_1);
		ctio1->scsi_status |= __constant_cpu_to_le16(SS_SENSE_LEN_VALID);
		ctio1->sense_length = cpu_to_le16(prm->sense_buffer_len);
		for (i = 0; i < prm->sense_buffer_len/4; i++)
			((uint32_t *)ctio1->sense_data)[i] =
				cpu_to_be32(((uint32_t *)prm->sense_buffer)[i]);
#if 0
		if (unlikely((prm->sense_buffer_len % 4) != 0)) {
			static int q;
			if (q < 10) {
				PRINT_INFO("qla2x00t(%ld): %d bytes of sense "
					"lost", prm->tgt->ha->instance,
					prm->sense_buffer_len % 4);
				q++;
			}
		}
#endif
	} else {
		ctio1 = (ctio7_status1_entry_t *)ctio;
		ctio1->flags &= ~__constant_cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_0);
		ctio1->flags |= __constant_cpu_to_le16(CTIO7_FLAGS_STATUS_MODE_1);
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
	scsi_qla_host_t *ha;
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

	ha = prm.tgt->ha;

	res = q24_build_ctio_pkt(&prm);
	if (unlikely(res != SCST_TGT_RES_SUCCESS))
		goto out_unmap_unlock;

	pkt = (ctio7_status0_entry_t *)prm.pkt;

	if (q2t_has_data(cmd) && (xmit_type & Q2T_XMIT_DATA)) {
		pkt->flags |= __constant_cpu_to_le16(CTIO7_FLAGS_DATA_IN |
				CTIO7_FLAGS_STATUS_MODE_0);

		q24_load_data_segments(&prm);

		if (prm.add_status_pkt == 0) {
			if (xmit_type & Q2T_XMIT_STATUS) {
				pkt->scsi_status = cpu_to_le16(prm.rq_result);
				pkt->residual = cpu_to_le32(prm.residual);
				pkt->flags |= __constant_cpu_to_le16(
						CTIO7_FLAGS_SEND_STATUS);
				if (q2t_need_explicit_conf(ha, cmd, 0)) {
					pkt->flags |= __constant_cpu_to_le16(
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
				(ctio7_status1_entry_t *)q2t_get_req_pkt(ha);

			TRACE_DBG("%s", "Building additional status packet");

			memcpy(ctio, pkt, sizeof(*ctio));
			ctio->common.entry_count = 1;
			ctio->common.dseg_count = 0;
			ctio->flags &= ~__constant_cpu_to_le16(
						CTIO7_FLAGS_DATA_IN);

			/* Real finish is ctio_m1's finish */
			pkt->common.handle |= CTIO_INTERMEDIATE_HANDLE_MARK;
			pkt->flags |= __constant_cpu_to_le16(
					CTIO7_FLAGS_DONT_RET_CTIO);
			q24_init_ctio_ret_entry((ctio7_status0_entry_t *)ctio,
							&prm);
			TRACE_BUFFER("Status CTIO7", ctio, REQUEST_ENTRY_SIZE);
		}
	} else
		q24_init_ctio_ret_entry(pkt, &prm);

	cmd->state = Q2T_STATE_PROCESSED;	/* Mid-level is done processing */

	TRACE_BUFFER("Xmitting CTIO7", pkt, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out_unlock:
	/* Release ring specific lock */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unmap_unlock:
	if (q2t_has_data(cmd))
		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
			cmd->dma_data_direction);
	goto out_unlock;
}

static int __q2t_rdy_to_xfer(struct q2t_cmd *cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	unsigned long flags;
	scsi_qla_host_t *ha;
	struct q2t_tgt *tgt = cmd->tgt;
	struct q2t_prm prm;
	void *p;

	TRACE_ENTRY();

	memset(&prm, 0, sizeof(prm));
	prm.cmd = cmd;
	prm.tgt = tgt;
	prm.sg = NULL;
	prm.req_cnt = 1;
	ha = tgt->ha;

	/* Send marker if required */
	if (q2t_issue_marker(ha, 0) != QLA_SUCCESS) {
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out;
	}

	TRACE_DBG("CTIO_start: ha(%d)", (int)ha->instance);

	/* Calculate number of entries and segments required */
	if (q2t_pci_map_calc_cnt(&prm) != 0) {
		res = SCST_TGT_RES_QUEUE_FULL;
		goto out;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Does F/W have an IOCBs for this request */
	res = q2t_check_reserve_free_req(ha, prm.req_cnt);
	if (res != SCST_TGT_RES_SUCCESS)
		goto out_unlock_free_unmap;

	if (IS_FWI2_CAPABLE(ha)) {
		ctio7_status0_entry_t *pkt;
		res = q24_build_ctio_pkt(&prm);
		if (unlikely(res != SCST_TGT_RES_SUCCESS))
			goto out_unlock_free_unmap;
		pkt = (ctio7_status0_entry_t *)prm.pkt;
		pkt->flags |= __constant_cpu_to_le16(CTIO7_FLAGS_DATA_OUT |
				CTIO7_FLAGS_STATUS_MODE_0);
		q24_load_data_segments(&prm);
		p = pkt;
	} else {
		ctio_common_entry_t *pkt;
		q2x_build_ctio_pkt(&prm);
		pkt = (ctio_common_entry_t *)prm.pkt;
		pkt->flags = __constant_cpu_to_le16(OF_FAST_POST | OF_DATA_OUT);
		q2x_load_data_segments(&prm);
		p = pkt;
	}

	cmd->state = Q2T_STATE_NEED_DATA;

	TRACE_BUFFER("Xfering", p, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out_unlock:
	/* Release ring specific lock */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock_free_unmap:
	if (q2t_has_data(cmd)) {
		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
		     cmd->dma_data_direction);
	}
	goto out_unlock;
}

static int q2t_rdy_to_xfer(struct scst_cmd *scst_cmd)
{
	int res;
	struct q2t_cmd *cmd;

	TRACE_ENTRY();

	TRACE(TRACE_SCSI, "tag=%lld", scst_cmd_get_tag(scst_cmd));

	cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	cmd->bufflen = scst_cmd_get_write_fields(scst_cmd, &cmd->sg,
		&cmd->sg_cnt);
	cmd->data_direction = scst_cmd_get_data_direction(scst_cmd);
	cmd->dma_data_direction = scst_to_tgt_dma_dir(cmd->data_direction);

	res = __q2t_rdy_to_xfer(cmd);

	TRACE_EXIT();
	return res;
}

/* If hardware_lock held on entry, might drop it, then reaquire */
static void q2x_send_term_exchange(scsi_qla_host_t *ha, struct q2t_cmd *cmd,
	atio_entry_t *atio, int ha_locked)
{
	ctio_ret_entry_t *ctio;
	unsigned long flags = 0; /* to stop compiler's warning */
	int do_tgt_cmd_done = 0;

	TRACE_ENTRY();

	TRACE_DBG("Sending TERM EXCH CTIO (ha=%p)", ha);

	/* Send marker if required */
	if (q2t_issue_marker(ha, ha_locked) != QLA_SUCCESS)
		goto out;

	if (!ha_locked)
		spin_lock_irqsave(&ha->hardware_lock, flags);

	ctio = (ctio_ret_entry_t *)qla2x00_req_pkt(ha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out_unlock;
	}

	ctio->entry_type = CTIO_RET_TYPE;
	ctio->entry_count = 1;
	if (cmd != NULL) {
		if (cmd->state < Q2T_STATE_PROCESSED) {
			PRINT_ERROR("qla2x00t(%ld): Terminating cmd %p with "
				"incorrect state %d", ha->instance, cmd,
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

	ctio->flags = __constant_cpu_to_le16(OF_FAST_POST | OF_TERM_EXCH |
			OF_NO_DATA | OF_SS_MODE_1);
	ctio->flags |= __constant_cpu_to_le16(OF_INC_RC);

	TRACE_BUFFER("CTIO TERM EXCH packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out_unlock:
	if (!ha_locked)
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (do_tgt_cmd_done) {
		if (!ha_locked && !in_interrupt()) {
			msleep(250); /* just in case */
			scst_tgt_cmd_done(cmd->scst_cmd, SCST_CONTEXT_DIRECT);
		} else
			scst_tgt_cmd_done(cmd->scst_cmd, SCST_CONTEXT_TASKLET);
		/* !! At this point cmd could be already freed !! */
	}

out:
	TRACE_EXIT();
	return;
}

/* If hardware_lock held on entry, might drop it, then reaquire */
static void q24_send_term_exchange(scsi_qla_host_t *ha, struct q2t_cmd *cmd,
	atio7_entry_t *atio, int ha_locked)
{
	ctio7_status1_entry_t *ctio;
	unsigned long flags = 0; /* to stop compiler's warning */
	int do_tgt_cmd_done = 0;

	TRACE_ENTRY();

	TRACE_DBG("Sending TERM EXCH CTIO7 (ha=%p)", ha);

	/* Send marker if required */
	if (q2t_issue_marker(ha, ha_locked) != QLA_SUCCESS)
		goto out;

	if (!ha_locked)
		spin_lock_irqsave(&ha->hardware_lock, flags);

	ctio = (ctio7_status1_entry_t *)qla2x00_req_pkt(ha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out_unlock;
	}

	ctio->common.entry_type = CTIO_TYPE7;
	ctio->common.entry_count = 1;
	if (cmd != NULL) {
		ctio->common.nport_handle = cmd->loop_id;
		if (cmd->state < Q2T_STATE_PROCESSED) {
			PRINT_ERROR("qla2x00t(%ld): Terminating cmd %p with "
				"incorrect state %d", ha->instance, cmd,
				 cmd->state);
		} else
			do_tgt_cmd_done = 1;
	} else
		ctio->common.nport_handle = CTIO7_NHANDLE_UNRECOGNIZED;
	ctio->common.handle = Q2T_SKIP_HANDLE |	CTIO_COMPLETION_HANDLE_MARK;
	ctio->common.timeout = __constant_cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	ctio->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	ctio->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	ctio->common.exchange_addr = atio->exchange_addr;
	ctio->flags = (atio->attr << 9) | __constant_cpu_to_le16(
		CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_TERMINATE);
	ctio->ox_id = swab16(atio->fcp_hdr.ox_id);

	/* Most likely, it isn't needed */
	ctio->residual = atio->fcp_cmnd.data_length;
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	TRACE_BUFFER("CTIO7 TERM EXCH packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out_unlock:
	if (!ha_locked)
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (do_tgt_cmd_done) {
		if (!ha_locked && !in_interrupt()) {
			msleep(250); /* just in case */
			scst_tgt_cmd_done(cmd->scst_cmd, SCST_CONTEXT_DIRECT);
		} else
			scst_tgt_cmd_done(cmd->scst_cmd, SCST_CONTEXT_TASKLET);
		/* !! At this point cmd could be already freed !! */
	}

out:
	TRACE_EXIT();
	return;
}

static inline void q2t_free_cmd(struct q2t_cmd *cmd)
{
	if (unlikely(cmd->free_sg))
		kfree(cmd->sg);
	kmem_cache_free(q2t_cmd_cachep, cmd);
}

static void q2t_on_free_cmd(struct scst_cmd *scst_cmd)
{
	struct q2t_cmd *cmd;

	TRACE_ENTRY();

	TRACE(TRACE_SCSI, "Freeing command %p, tag %lld", scst_cmd,
		scst_cmd_get_tag(scst_cmd));

	cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	scst_cmd_set_tgt_priv(scst_cmd, NULL);

	q2t_free_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_prepare_srr_ctio(scsi_qla_host_t *ha, struct q2t_cmd *cmd,
	void *ctio)
{
	struct srr_ctio *sc;
	struct q2t_tgt *tgt = ha->tgt;
	int res = 0;
	struct srr_imm *imm;

	tgt->ctio_srr_id++;

	TRACE_MGMT_DBG("qla2x00t(%ld): CTIO with SRR "
		"status received", ha->instance);

	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): SRR CTIO, "
			"but ctio is NULL", ha->instance);
		res = -EINVAL;
		goto out;
	}

	if (cmd->scst_cmd != NULL)
		scst_update_hw_pending_start(cmd->scst_cmd);

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
					"SRR %p", ha->instance,	tgt->ctio_srr_id,
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
		PRINT_CRIT_ERROR("qla2x00t(%ld): Unable to "
		    "allocate SRR CTIO entry", ha->instance);
		spin_lock(&tgt->srr_lock);
		list_for_each_entry_safe(imm, ti, &tgt->srr_imm_list,
					srr_list_entry) {
			if (imm->srr_id == tgt->ctio_srr_id) {
				TRACE_MGMT_DBG("IMM SRR %p deleted "
					"(id %d)", imm, imm->srr_id);
				list_del(&imm->srr_list_entry);
				q2t_reject_free_srr_imm(ha, imm, 1);
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
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static int q2t_term_ctio_exchange(scsi_qla_host_t *ha, void *ctio,
	struct q2t_cmd *cmd, uint32_t status)
{
	int term = 0;

	if (IS_FWI2_CAPABLE(ha)) {
		if (ctio != NULL) {
			ctio7_fw_entry_t *c = (ctio7_fw_entry_t *)ctio;
			term = !(c->flags &
				__constant_cpu_to_le16(OF_TERM_EXCH));
		} else
			term = 1;
		if (term) {
			q24_send_term_exchange(ha, cmd,
				&cmd->atio.atio7, 1);
		}
	} else {
		if (status != CTIO_SUCCESS)
			q2x_modify_command_count(ha, 1, 0);
#if 0 /* seems, it isn't needed */
		if (ctio != NULL) {
			ctio_common_entry_t *c = (ctio_common_entry_t *)ctio;
			term = !(c->flags &
				__constant_cpu_to_le16(
					CTIO7_FLAGS_TERMINATE));
		} else
			term = 1;
		if (term) {
			q2x_send_term_exchange(ha, cmd,
				&cmd->atio.atio2x, 1);
		}
#endif
	}
	return term;
}

/* ha->hardware_lock supposed to be held on entry */
static inline struct q2t_cmd *q2t_get_cmd(scsi_qla_host_t *ha, uint32_t handle)
{
	handle--;
	if (ha->cmds[handle] != NULL) {
		struct q2t_cmd *cmd = ha->cmds[handle];
		ha->cmds[handle] = NULL;
		return cmd;
	} else
		return NULL;
}

/* ha->hardware_lock supposed to be held on entry */
static struct q2t_cmd *q2t_ctio_to_cmd(scsi_qla_host_t *ha, uint32_t handle,
	void *ctio)
{
	struct q2t_cmd *cmd = NULL;

	/* Clear out internal marks */
	handle &= ~(CTIO_COMPLETION_HANDLE_MARK | CTIO_INTERMEDIATE_HANDLE_MARK);

	if (handle != Q2T_NULL_HANDLE) {
		if (unlikely(handle == Q2T_SKIP_HANDLE)) {
			TRACE_DBG("%s", "SKIP_HANDLE CTIO");
			goto out;
		}
		/* handle-1 is actually used */
		if (unlikely(handle > MAX_OUTSTANDING_COMMANDS)) {
			PRINT_ERROR("qla2x00t(%ld): Wrong handle %x "
				"received", ha->instance, handle);
			goto out;
		}
		cmd = q2t_get_cmd(ha, handle);
		if (unlikely(cmd == NULL)) {
			PRINT_WARNING("qla2x00t(%ld): Suspicious: unable to "
				   "find the command with handle %x",
				   ha->instance, handle);
			goto out;
		}
	} else if (ctio != NULL) {
		uint16_t loop_id;
		int tag;
		struct q2t_sess *sess;
		struct scst_cmd *scst_cmd;

		if (IS_FWI2_CAPABLE(ha)) {
			/* We can't get loop ID from CTIO7 */
			PRINT_ERROR("qla2x00t(%ld): Wrong CTIO received: "
				"QLA24xx doesn't support NULL handles",
				ha->instance);
			goto out;
		} else {
			ctio_common_entry_t *c = (ctio_common_entry_t *)ctio;
			loop_id = GET_TARGET_ID(ha, c);
			tag = c->rx_id;
		}

		sess = q2t_find_sess_by_loop_id(ha->tgt, loop_id);
		if (sess == NULL) {
			PRINT_WARNING("qla2x00t(%ld): Suspicious: "
				   "ctio_completion for non-existing session "
				   "(loop_id %d, tag %d)",
				   ha->instance, loop_id, tag);
			goto out;
		}

		scst_cmd = scst_find_cmd_by_tag(sess->scst_sess, tag);
		if (scst_cmd == NULL) {
			PRINT_WARNING("qla2x00t(%ld): Suspicious: unable to "
			     "find the command with tag %d (loop_id %d)",
			     ha->instance, tag, loop_id);
			goto out;
		}

		cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
		TRACE_DBG("Found q2t_cmd %p (tag %d)", cmd, tag);
	}

out:
	return cmd;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q2t_do_ctio_completion(scsi_qla_host_t *ha, uint32_t handle,
	uint32_t status, void *ctio)
{
	struct scst_cmd *scst_cmd;
	struct q2t_cmd *cmd;
	enum scst_exec_context context;

	TRACE_ENTRY();

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif

	TRACE(TRACE_DEBUG|TRACE_SCSI, "handle(ctio %p status %#x) <- %08x",
	      ctio, status, handle);

	if (handle & CTIO_INTERMEDIATE_HANDLE_MARK) {
		/* That could happen only in case of an error/reset/abort */
		if (status != CTIO_SUCCESS) {
			TRACE_MGMT_DBG("Intermediate CTIO received (status %x)",
				status);
		}
		goto out;
	}

	cmd = q2t_ctio_to_cmd(ha, handle, ctio);
	if (cmd == NULL) {
		if (status != CTIO_SUCCESS)
			q2t_term_ctio_exchange(ha, ctio, NULL, status);
		goto out;
	}

	scst_cmd = cmd->scst_cmd;

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
				"op %x (LIP_RESET=e, ABORTED=2, TARGET_RESET=17, "
				"TIMEOUT=b, INVALID_RX_ID=8)", ha->instance,
				status, cmd->state, scst_cmd, scst_cmd->cdb[0]);
			break;

		case CTIO_PORT_LOGGED_OUT:
		case CTIO_PORT_UNAVAILABLE:
			PRINT_INFO("qla2x00t(%ld): CTIO with PORT LOGGED "
				"OUT (29) or PORT UNAVAILABLE (28) status %x "
				"received (state %x, scst_cmd %p, op %x)",
				ha->instance, status, cmd->state, scst_cmd,
				scst_cmd->cdb[0]);
			break;

		case CTIO_SRR_RECEIVED:
			if (q2t_prepare_srr_ctio(ha, cmd, ctio) != 0)
				break;
			else
				goto out;

		default:
			PRINT_ERROR("qla2x00t(%ld): CTIO with error status "
				"0x%x received (state %x, scst_cmd %p, op %x)",
				ha->instance, status, cmd->state, scst_cmd,
				scst_cmd->cdb[0]);
			break;
		}

		if (cmd->state != Q2T_STATE_NEED_DATA)
			if (q2t_term_ctio_exchange(ha, ctio, cmd, status))
				goto out;
	}

	if (cmd->state == Q2T_STATE_PROCESSED) {
		TRACE_DBG("Command %p finished", cmd);
		if (q2t_has_data(cmd)) {
			pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);
		}
	} else if (cmd->state == Q2T_STATE_NEED_DATA) {
		int rx_status = SCST_RX_STATUS_SUCCESS;

		cmd->state = Q2T_STATE_DATA_IN;

		if (unlikely(status != CTIO_SUCCESS))
			rx_status = SCST_RX_STATUS_ERROR;
		else
			cmd->write_data_transferred = 1;

		TRACE_DBG("Data received, context %x, rx_status %d",
		      context, rx_status);

		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);

		scst_rx_data(scst_cmd, rx_status, context);
		goto out;
	} else if (cmd->state == Q2T_STATE_ABORTED) {
		TRACE_MGMT_DBG("Aborted command %p (tag %d) finished", cmd,
			cmd->tag);
	} else {
		PRINT_ERROR("qla2x00t(%ld): A command in state (%d) should "
			"not return a CTIO complete", ha->instance, cmd->state);
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
static void q2x_ctio_completion(scsi_qla_host_t *ha, uint32_t handle)
{
	struct q2t_tgt *tgt = ha->tgt;

	TRACE_ENTRY();

	if (likely(tgt != NULL)) {
		tgt->irq_cmd_count++;
		q2t_do_ctio_completion(ha, handle, CTIO_SUCCESS, NULL);
		tgt->irq_cmd_count--;
	} else {
		TRACE_DBG("CTIO, but target mode not enabled (ha %p handle "
			"%#x)", ha, handle);
	}

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock is supposed to be held on entry */
static int q2x_do_send_cmd_to_scst(struct q2t_cmd *cmd)
{
	int res = 0;
	struct q2t_sess *sess = cmd->sess;
	uint16_t lun;
	atio_entry_t *atio = &cmd->atio.atio2x;
	scst_data_direction dir;
	int context;

	TRACE_ENTRY();

	/* make it be in network byte order */
	lun = swab16(le16_to_cpu(atio->lun));
	cmd->scst_cmd = scst_rx_cmd(sess->scst_sess, (uint8_t *)&lun,
				    sizeof(lun), atio->cdb, Q2T_MAX_CDB_LEN,
				    SCST_ATOMIC);

	if (cmd->scst_cmd == NULL) {
		PRINT_ERROR("%s", "qla2x00t: scst_rx_cmd() failed");
		res = -EFAULT;
		goto out;
	}

	cmd->tag = atio->rx_id;
	scst_cmd_set_tag(cmd->scst_cmd, cmd->tag);
	scst_cmd_set_tgt_priv(cmd->scst_cmd, cmd);

	if ((atio->execution_codes & (ATIO_EXEC_READ | ATIO_EXEC_WRITE)) ==
				(ATIO_EXEC_READ | ATIO_EXEC_WRITE))
		dir = SCST_DATA_BIDI;
	else if (atio->execution_codes & ATIO_EXEC_READ)
		dir = SCST_DATA_READ;
	else if (atio->execution_codes & ATIO_EXEC_WRITE)
		dir = SCST_DATA_WRITE;
	else
		dir = SCST_DATA_NONE;
	scst_cmd_set_expected(cmd->scst_cmd, dir,
		le32_to_cpu(atio->data_length));

	switch (atio->task_codes) {
	case ATIO_SIMPLE_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case ATIO_HEAD_OF_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case ATIO_ORDERED_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case ATIO_ACA_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ACA);
		break;
	case ATIO_UNTAGGED:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	default:
		PRINT_ERROR("qla2x00t: unknown task code %x, use "
			"ORDERED instead", atio->task_codes);
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif

	TRACE_DBG("Context %x", context);
	TRACE(TRACE_SCSI, "START Command (tag %d, queue_type %d)",
		cmd->tag, scst_cmd_get_queue_type(cmd->scst_cmd));
	scst_cmd_init_done(cmd->scst_cmd, context);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock is supposed to be held on entry */
static int q24_do_send_cmd_to_scst(struct q2t_cmd *cmd)
{
	int res = 0;
	struct q2t_sess *sess = cmd->sess;
	atio7_entry_t *atio = &cmd->atio.atio7;
	scst_data_direction dir;
	int context;

	TRACE_ENTRY();

	cmd->scst_cmd = scst_rx_cmd(sess->scst_sess,
		(uint8_t *)&atio->fcp_cmnd.lun, sizeof(atio->fcp_cmnd.lun),
		atio->fcp_cmnd.cdb, Q2T_MAX_CDB_LEN, SCST_ATOMIC);

	if (cmd->scst_cmd == NULL) {
		PRINT_ERROR("%s", "qla2x00t: scst_rx_cmd() failed");
		res = -EFAULT;
		goto out;
	}

	cmd->tag = atio->exchange_addr;
	scst_cmd_set_tag(cmd->scst_cmd, cmd->tag);
	scst_cmd_set_tgt_priv(cmd->scst_cmd, cmd);

	if (atio->fcp_cmnd.rddata && atio->fcp_cmnd.wrdata)
		dir = SCST_DATA_BIDI;
	else if (atio->fcp_cmnd.rddata)
		dir = SCST_DATA_READ;
	else if (atio->fcp_cmnd.wrdata)
		dir = SCST_DATA_WRITE;
	else
		dir = SCST_DATA_NONE;
	scst_cmd_set_expected(cmd->scst_cmd, dir,
		be32_to_cpu(atio->fcp_cmnd.data_length));

	switch (atio->fcp_cmnd.task_attr) {
	case ATIO_SIMPLE_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case ATIO_HEAD_OF_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case ATIO_ORDERED_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case ATIO_ACA_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ACA);
		break;
	case ATIO_UNTAGGED:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	default:
		PRINT_ERROR("qla2x00t: unknown task code %x, use "
			"ORDERED instead", atio->fcp_cmnd.task_attr);
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	}

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif

	TRACE_DBG("Context %x", context);
	TRACE(TRACE_SCSI, "START Command %p (tag %d, queue type %x)", cmd,
		cmd->tag, scst_cmd_get_queue_type(cmd->scst_cmd));
	scst_cmd_init_done(cmd->scst_cmd, context);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_do_send_cmd_to_scst(scsi_qla_host_t *ha,
	struct q2t_cmd *cmd, struct q2t_sess *sess)
{
	int res;

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
static int q2t_send_cmd_to_scst(scsi_qla_host_t *ha, atio_t *atio)
{
	int res = 0;
	struct q2t_tgt *tgt = ha->tgt;
	struct q2t_sess *sess;
	struct q2t_cmd *cmd;

	TRACE_ENTRY();

	if (unlikely(tgt->tgt_stop)) {
		TRACE_MGMT_DBG("New command while device %p is shutting "
			"down", tgt);
		res = -EFAULT;
		goto out;
	}

	cmd = kmem_cache_zalloc(q2t_cmd_cachep, GFP_ATOMIC);
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of cmd failed");
		res = -ENOMEM;
		goto out;
	}

	memcpy(&cmd->atio.atio2x, atio, sizeof(*atio));
	cmd->state = Q2T_STATE_NEW;
	cmd->tgt = ha->tgt;

	if (IS_FWI2_CAPABLE(ha)) {
		atio7_entry_t *a = (atio7_entry_t *)atio;
		sess = q2t_find_sess_by_s_id(tgt, a->fcp_hdr.s_id);
		if (unlikely(sess == NULL)) {
			TRACE_MGMT_DBG("qla2x00t(%ld): Unable to find "
				"wwn login (s_id %x:%x:%x), trying to create "
				"it manually", ha->instance,
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
				"manually", ha->instance,
				GET_TARGET_ID(ha, (atio_entry_t *)atio));
			goto out_sched;
		}
	}

	res = q2t_do_send_cmd_to_scst(ha, cmd, sess);
	if (unlikely(res != 0))
		goto out_free_cmd;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_cmd:
	q2t_free_cmd(cmd);
	goto out;

out_sched:
	{
		struct q2t_sess_work_param *prm;
		unsigned long flags;

		prm = kzalloc(sizeof(*prm), GFP_ATOMIC);
		if (prm == NULL) {
			PRINT_ERROR("%s", "Unable to create session work, "
				"command will be refused");
			res = -1;
			goto out_free_cmd;
		}

		TRACE_MGMT_DBG("Scheduling work to find session for cmd %p",
			cmd);

		prm->cmd = cmd;

		spin_lock_irqsave(&tgt->sess_work_lock, flags);
		if (!tgt->sess_works_pending)
			tgt->tm_to_unknown = 0;
		list_add_tail(&prm->sess_works_list_entry, &tgt->sess_works_list);
		tgt->sess_works_pending = 1;
		spin_unlock_irqrestore(&tgt->sess_work_lock, flags);

		schedule_work(&tgt->sess_work);
	}
	goto out;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_issue_task_mgmt(struct q2t_sess *sess, uint8_t *lun,
	int lun_size, int fn, void *iocb, int flags)
{
	int res = 0, rc = -1;
	struct q2t_mgmt_cmd *mcmd;

	TRACE_ENTRY();

	mcmd = mempool_alloc(q2t_mgmt_cmd_mempool, GFP_ATOMIC);
	if (mcmd == NULL) {
		PRINT_CRIT_ERROR("qla2x00t(%ld): Allocation of management "
			"command failed, some commands and their data could "
			"leak", sess->tgt->ha->instance);
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
		TRACE(TRACE_MGMT, "%s", "CLEAR_ACA received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_ACA,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_TARGET_RESET:
		TRACE(TRACE_MGMT, "%s", "TARGET_RESET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_TARGET_RESET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_LUN_RESET:
		TRACE(TRACE_MGMT, "%s", "LUN_RESET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_LUN_RESET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_CLEAR_TS:
		TRACE(TRACE_MGMT, "%s", "CLEAR_TS received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_TASK_SET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_ABORT_TS:
		TRACE(TRACE_MGMT, "%s", "ABORT_TS received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_ABORT_TASK_SET,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_ABORT_ALL:
		TRACE(TRACE_MGMT, "%s", "Doing ABORT_ALL_TASKS");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess,
					 SCST_ABORT_ALL_TASKS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_ABORT_ALL_SESS:
		TRACE(TRACE_MGMT, "%s", "Doing ABORT_ALL_TASKS_SESS");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess,
					 SCST_ABORT_ALL_TASKS_SESS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_NEXUS_LOSS_SESS:
		TRACE(TRACE_MGMT, "%s", "Doing NEXUS_LOSS_SESS");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_NEXUS_LOSS_SESS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	case Q2T_NEXUS_LOSS:
		TRACE(TRACE_MGMT, "%s", "Doing NEXUS_LOSS");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_NEXUS_LOSS,
					 lun, lun_size, SCST_ATOMIC, mcmd);
		break;

	default:
		PRINT_ERROR("qla2x00t(%ld): Unknown task mgmt fn 0x%x",
			    sess->tgt->ha->instance, fn);
		rc = -1;
		break;
	}

	if (rc != 0) {
		PRINT_ERROR("qla2x00t(%ld): scst_rx_mgmt_fn_lun() failed: %d",
			    sess->tgt->ha->instance, rc);
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
static int q2t_handle_task_mgmt(scsi_qla_host_t *ha, void *iocb)
{
	int res = 0;
	struct q2t_tgt *tgt;
	struct q2t_sess *sess;
	uint8_t *lun;
	uint16_t lun_data;
	int lun_size;
	int fn;

	TRACE_ENTRY();

	tgt = ha->tgt;
	if (IS_FWI2_CAPABLE(ha)) {
		atio7_entry_t *a = (atio7_entry_t *)iocb;
		lun = (uint8_t *)&a->fcp_cmnd.lun;
		lun_size = sizeof(a->fcp_cmnd.lun);
		fn = a->fcp_cmnd.task_mgmt_flags;
		sess = q2t_find_sess_by_s_id(tgt, a->fcp_hdr.s_id);
		if (sess != NULL) {
			sess->s_id.b.al_pa = a->fcp_hdr.s_id[2];
			sess->s_id.b.area = a->fcp_hdr.s_id[1];
			sess->s_id.b.domain = a->fcp_hdr.s_id[0];
		}
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
		TRACE(TRACE_MGMT, "qla2x00t(%ld): task mgmt fn 0x%x for "
			"non-existant session", ha->instance, fn);
		tgt->tm_to_unknown = 1;
		res = -ESRCH;
		goto out;
	}

	res = q2t_issue_task_mgmt(sess, lun, lun_size, fn, iocb, 0);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* ha->hardware_lock supposed to be held on entry */
static int q2t_abort_task(scsi_qla_host_t *ha, notify_entry_t *iocb)
{
	int res = 0, rc;
	struct q2t_mgmt_cmd *mcmd;
	struct q2t_sess *sess;
	int loop_id;
	uint32_t tag;

	TRACE_ENTRY();

	loop_id = GET_TARGET_ID(ha, iocb);
	tag = le16_to_cpu(iocb->seq_id);

	sess = q2t_find_sess_by_loop_id(ha->tgt, loop_id);
	if (sess == NULL) {
		TRACE(TRACE_MGMT, "qla2x00t(%ld): task abort for unexisting "
			"session", ha->instance);
		ha->tgt->tm_to_unknown = 1;
		res = -EFAULT;
		goto out;
	}

	mcmd = mempool_alloc(q2t_mgmt_cmd_mempool, GFP_ATOMIC);
	if (mcmd == NULL) {
		PRINT_ERROR("%s: Allocation of ABORT cmd failed", __func__);
		res = -ENOMEM;
		goto out;
	}
	memset(mcmd, 0, sizeof(*mcmd));

	mcmd->sess = sess;
	memcpy(&mcmd->orig_iocb.notify_entry, iocb,
		sizeof(mcmd->orig_iocb.notify_entry));

	rc = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK, tag,
		SCST_ATOMIC, mcmd);
	if (rc != 0) {
		PRINT_ERROR("qla2x00t(%ld): scst_rx_mgmt_fn_tag() failed: %d",
			    ha->instance, rc);
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

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static int q24_handle_els(scsi_qla_host_t *ha, notify24xx_entry_t *iocb)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "ELS opcode %x", iocb->status_subcode);

	switch (iocb->status_subcode) {
	case ELS_PLOGI:
	case ELS_FLOGI:
	case ELS_PRLI:
	case ELS_LOGO:
	case ELS_PRLO:
		res = q2t_reset(ha, iocb, Q2T_NEXUS_LOSS_SESS);
		break;

	case ELS_PDISC:
	case ELS_ADISC:
	{
		struct q2t_tgt *tgt = ha->tgt;
		if (tgt->link_reinit_iocb_pending) {
			q24_send_notify_ack(ha, &tgt->link_reinit_iocb, 0, 0, 0);
			tgt->link_reinit_iocb_pending = 0;
		}
		res = 1; /* send notify ack */
		break;
	}

	default:
		PRINT_ERROR("qla2x00t(%ld): Unsupported ELS command %x "
			"received", ha->instance, iocb->status_subcode);
		res = q2t_reset(ha, iocb, Q2T_NEXUS_LOSS_SESS);
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
			cmd->tgt->ha->instance, offset, cmd->bufflen);
		res = -EINVAL;
		goto out;
	}

	TRACE_SG("offset=%d, first_sg=%d, first_page=%d, "
		"first_page_offs=%d, cmd->bufflen=%d, cmd->sg_cnt=%d", offset,
		first_sg, first_page, first_page_offs, cmd->bufflen,
		cmd->sg_cnt);

	sg = kmalloc(cnt * sizeof(sg[0]), GFP_KERNEL);
	if (sg == NULL) {
		PRINT_CRIT_ERROR("qla2x00t(%ld): Unable to allocate cut "
			"SG (len %zd)", cmd->tgt->ha->instance,
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
		PRINT_ERROR("qla2x00t(%ld): SRR rel_offs (%d) "
			"< 0", cmd->tgt->ha->instance, rel_offs);
		res = -1;
	} else if (rel_offs == cmd->bufflen)
		*xmit_type = Q2T_XMIT_STATUS;
	else if (rel_offs > 0)
		res = q2t_cut_cmd_data_head(cmd, rel_offs);

	return res;
}

/* No locks, thread context */
static void q24_handle_srr(scsi_qla_host_t *ha, struct srr_ctio *sctio,
	struct srr_imm *imm)
{
	notify24xx_entry_t *ntfy = &imm->imm.notify_entry24;
	struct q2t_cmd *cmd = sctio->cmd;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("SRR cmd %p, srr_ui %x", cmd, ntfy->srr_ui);

	switch (ntfy->srr_ui) {
	case SRR_IU_STATUS:
		spin_lock_irq(&ha->hardware_lock);
		q24_send_notify_ack(ha, ntfy,
			NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
		spin_unlock_irq(&ha->hardware_lock);
		__q24_xmit_response(cmd, Q2T_XMIT_STATUS);
		break;
	case SRR_IU_DATA_IN:
		cmd->bufflen = scst_cmd_get_adjusted_resp_data_len(cmd->scst_cmd);
		if (q2t_has_data(cmd)) {
			uint32_t offset;
			int xmit_type;
			pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);
			offset = le32_to_cpu(imm->imm.notify_entry24.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q24_send_notify_ack(ha, ntfy,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			__q24_xmit_response(cmd, xmit_type);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for in data for cmd "
				"without them (tag %d, SCSI status %d), "
				"reject", ha->instance, cmd->tag,
				scst_cmd_get_status(cmd->scst_cmd));
			goto out_reject;
		}
		break;
	case SRR_IU_DATA_OUT:
		cmd->bufflen = scst_cmd_get_write_fields(cmd->scst_cmd,
					&cmd->sg, &cmd->sg_cnt);
		if (q2t_has_data(cmd)) {
			uint32_t offset;
			int xmit_type;
			pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);
			offset = le32_to_cpu(imm->imm.notify_entry24.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q24_send_notify_ack(ha, ntfy,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			__q2t_rdy_to_xfer(cmd);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for out data for cmd "
				"without them (tag %d, SCSI status %d), "
				"reject", ha->instance, cmd->tag,
				scst_cmd_get_status(cmd->scst_cmd));
			goto out_reject;
		}
		break;
	default:
		PRINT_ERROR("qla2x00t(%ld): Unknown srr_ui value %x",
			ha->instance, ntfy->srr_ui);
		goto out_unmap_reject;
	}

out:
	TRACE_EXIT();
	return;

out_unmap_reject:
	if (q2t_has_data(sctio->cmd)) {
		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
			cmd->dma_data_direction);
	}

out_reject:
	spin_lock_irq(&ha->hardware_lock);
	q24_send_notify_ack(ha, ntfy, NOTIFY_ACK_SRR_FLAGS_REJECT,
		NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
		NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	if (cmd->state == Q2T_STATE_NEED_DATA) {
		cmd->state = Q2T_STATE_DATA_IN;

		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);

		scst_rx_data(cmd->scst_cmd, SCST_RX_STATUS_ERROR,
			SCST_CONTEXT_THREAD);
	} else
		q24_send_term_exchange(ha, cmd, &cmd->atio.atio7, 1);
	spin_unlock_irq(&ha->hardware_lock);
	goto out;
}

/* No locks, thread context */
static void q2x_handle_srr(scsi_qla_host_t *ha, struct srr_ctio *sctio,
	struct srr_imm *imm)
{
	notify_entry_t *ntfy = &imm->imm.notify_entry;
	struct q2t_cmd *cmd = sctio->cmd;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("SRR cmd %p, srr_ui %x", cmd, ntfy->srr_ui);

	switch (ntfy->srr_ui) {
	case SRR_IU_STATUS:
		spin_lock_irq(&ha->hardware_lock);
		q2x_send_notify_ack(ha, ntfy, 0, 0, 0,
			NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
		spin_unlock_irq(&ha->hardware_lock);
		__q2x_xmit_response(cmd, Q2T_XMIT_STATUS);
		break;
	case SRR_IU_DATA_IN:
		cmd->bufflen = scst_cmd_get_adjusted_resp_data_len(cmd->scst_cmd);
		if (q2t_has_data(cmd)) {
			uint32_t offset;
			int xmit_type;
			pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);
			offset = le32_to_cpu(imm->imm.notify_entry.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q2x_send_notify_ack(ha, ntfy, 0, 0, 0,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			__q2x_xmit_response(cmd, xmit_type);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for in data for cmd "
				"without them (tag %d, SCSI status %d), "
				"reject", ha->instance, cmd->tag,
				scst_cmd_get_status(cmd->scst_cmd));
			goto out_reject;
		}
		break;
	case SRR_IU_DATA_OUT:
		cmd->bufflen = scst_cmd_get_write_fields(cmd->scst_cmd,
					&cmd->sg, &cmd->sg_cnt);
		if (q2t_has_data(cmd)) {
			uint32_t offset;
			int xmit_type;
			pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);
			offset = le32_to_cpu(imm->imm.notify_entry.srr_rel_offs);
			if (q2t_srr_adjust_data(cmd, offset, &xmit_type) != 0)
				goto out_reject;
			spin_lock_irq(&ha->hardware_lock);
			q2x_send_notify_ack(ha, ntfy, 0, 0, 0,
				NOTIFY_ACK_SRR_FLAGS_ACCEPT, 0, 0);
			spin_unlock_irq(&ha->hardware_lock);
			__q2t_rdy_to_xfer(cmd);
		} else {
			PRINT_ERROR("qla2x00t(%ld): SRR for out data for cmd "
				"without them (tag %d, SCSI status %d), "
				"reject", ha->instance, cmd->tag,
				scst_cmd_get_status(cmd->scst_cmd));
			goto out_reject;
		}
		break;
	default:
		PRINT_ERROR("qla2x00t(%ld): Unknown srr_ui value %x",
			ha->instance, ntfy->srr_ui);
		goto out_unmap_reject;
	}

out:
	TRACE_EXIT();
	return;

out_unmap_reject:
	if (q2t_has_data(sctio->cmd)) {
		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
			cmd->dma_data_direction);
	}

out_reject:
	spin_lock_irq(&ha->hardware_lock);
	q2x_send_notify_ack(ha, ntfy, 0, 0, 0, NOTIFY_ACK_SRR_FLAGS_REJECT,
		NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
		NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	if (cmd->state == Q2T_STATE_NEED_DATA) {
		cmd->state = Q2T_STATE_DATA_IN;

		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);

		scst_rx_data(cmd->scst_cmd, SCST_RX_STATUS_ERROR,
			SCST_CONTEXT_THREAD);
	} else
		q2x_send_term_exchange(ha, cmd, &cmd->atio.atio2x, 1);
	spin_unlock_irq(&ha->hardware_lock);
	goto out;
}

static void q2t_reject_free_srr_imm(scsi_qla_host_t *ha, struct srr_imm *imm,
	int ha_locked)
{
	if (!ha_locked)
		spin_lock_irq(&ha->hardware_lock);

	if (IS_FWI2_CAPABLE(ha)) {
		q24_send_notify_ack(ha, &imm->imm.notify_entry24,
			NOTIFY_ACK_SRR_FLAGS_REJECT,
			NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
			NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	} else {
		q2x_send_notify_ack(ha, &imm->imm.notify_entry,
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
	scsi_qla_host_t *ha = tgt->ha;
	struct srr_ctio *sctio;

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
					  ha->instance, i, i->srr_id, sctio);
					q2t_reject_free_srr_imm(ha, i, 0);
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
		cmd->offset = scst_cmd_get_ppl_offset(cmd->scst_cmd);
		if (cmd->free_sg) {
			kfree(cmd->sg);
			cmd->free_sg = 0;
		}
		cmd->sg = scst_cmd_get_sg(cmd->scst_cmd);
		cmd->sg_cnt = scst_cmd_get_sg_cnt(cmd->scst_cmd);

		TRACE_MGMT_DBG("SRR cmd %p (scst_cmd %p, tag %d, op %x), "
			"sg_cnt=%d, offset=%d", cmd, cmd->scst_cmd,
			cmd->tag, cmd->scst_cmd->cdb[0], cmd->sg_cnt,
			cmd->offset);

		if (IS_FWI2_CAPABLE(ha))
			q24_handle_srr(ha, sctio, imm);
		else
			q2x_handle_srr(ha, sctio, imm);

		kfree(imm);
		kfree(sctio);
		goto restart;
	}
	spin_unlock_irq(&tgt->srr_lock);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
static void q2t_prepare_srr_imm(scsi_qla_host_t *ha, void *iocb)
{
	struct srr_imm *imm;
	struct q2t_tgt *tgt = ha->tgt;
	notify_entry_t *iocb2x = (notify_entry_t *)iocb;
	notify24xx_entry_t *iocb24 = (notify24xx_entry_t *)iocb;
	struct srr_ctio *sctio;

	tgt->imm_srr_id++;

	TRACE(TRACE_MGMT, "qla2x00t(%ld): SRR received", ha->instance);

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
					"SRR %p", ha->instance,	tgt->ctio_srr_id,
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

		PRINT_CRIT_ERROR("qla2x00t(%ld): Unable to allocate SRR IMM "
			"entry, SRR request will be rejected", ha->instance);

		/* IRQ is already OFF */
		spin_lock(&tgt->srr_lock);
		list_for_each_entry_safe(sctio, ts, &tgt->srr_ctio_list,
					srr_list_entry) {
			if (sctio->srr_id == tgt->imm_srr_id) {
				TRACE_MGMT_DBG("CTIO SRR %p deleted "
					"(id %d)", sctio, sctio->srr_id);
				list_del(&sctio->srr_list_entry);
				if (IS_FWI2_CAPABLE(ha)) {
					q24_send_term_exchange(ha, sctio->cmd,
						&sctio->cmd->atio.atio7, 1);
				} else {
					q2x_send_term_exchange(ha, sctio->cmd,
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
		q24_send_notify_ack(ha, iocb24,
			NOTIFY_ACK_SRR_FLAGS_REJECT,
			NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
			NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	} else {
		q2x_send_notify_ack(ha, iocb2x,
			0, 0, 0, NOTIFY_ACK_SRR_FLAGS_REJECT,
			NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM,
			NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL);
	}
	goto out;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q2t_handle_imm_notify(scsi_qla_host_t *ha, void *iocb)
{
	uint16_t status;
	uint32_t add_flags = 0;
	int send_notify_ack = 1;
	notify_entry_t *iocb2x = (notify_entry_t *)iocb;
	notify24xx_entry_t *iocb24 = (notify24xx_entry_t *)iocb;

	TRACE_ENTRY();

	status = le16_to_cpu(iocb2x->status);

	TRACE_BUFF_FLAG(TRACE_BUFF, "IMMED Notify Coming Up",
		iocb, sizeof(*iocb2x));

	switch (status) {
	case IMM_NTFY_LIP_RESET:
	{
		if (IS_FWI2_CAPABLE(ha)) {
			TRACE(TRACE_MGMT, "LIP reset (loop %#x), subcode %x",
				le16_to_cpu(iocb24->nport_handle),
				iocb24->status_subcode);
		} else {
			TRACE(TRACE_MGMT, "LIP reset (I %#x)",
				GET_TARGET_ID(ha, iocb2x));
			/* set the Clear LIP reset event flag */
			add_flags |= NOTIFY_ACK_CLEAR_LIP_RESET;
		}
		if (q2t_reset(ha, iocb, Q2T_ABORT_ALL) == 0)
			send_notify_ack = 0;
		break;
	}

	case IMM_NTFY_LIP_LINK_REINIT:
	{
		struct q2t_tgt *tgt = ha->tgt;
		TRACE(TRACE_MGMT, "LINK REINIT (loop %#x, subcode %x)",
			le16_to_cpu(iocb24->nport_handle),
			iocb24->status_subcode);
		if (tgt->link_reinit_iocb_pending)
			q24_send_notify_ack(ha, &tgt->link_reinit_iocb, 0, 0, 0);
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
			TRACE(TRACE_MGMT, "Port logout (loop %#x, subcode %x)",
				le16_to_cpu(iocb24->nport_handle),
				iocb24->status_subcode);
		} else {
			TRACE(TRACE_MGMT, "Port logout (S %08x -> L %#x)",
				le16_to_cpu(iocb2x->seq_id),
				le16_to_cpu(iocb2x->lun));
		}
		if (q2t_reset(ha, iocb, Q2T_NEXUS_LOSS_SESS) == 0)
			send_notify_ack = 0;
		/* The sessions will be cleared in the callback, if needed */
		break;

	case IMM_NTFY_GLBL_TPRLO:
		TRACE(TRACE_MGMT, "Global TPRLO (%x)", status);
		if (q2t_reset(ha, iocb, Q2T_NEXUS_LOSS) == 0)
			send_notify_ack = 0;
		/* The sessions will be cleared in the callback, if needed */
		break;

	case IMM_NTFY_PORT_CONFIG:
		TRACE(TRACE_MGMT, "Port config changed (%x)", status);
		if (q2t_reset(ha, iocb, Q2T_ABORT_ALL) == 0)
			send_notify_ack = 0;
		/* The sessions will be cleared in the callback, if needed */
		break;

	case IMM_NTFY_GLBL_LOGO:
		PRINT_ERROR("qla2x00t(%ld): Link failure detected",
			ha->instance);
		/* I_T nexus loss */
		if (q2t_reset(ha, iocb, Q2T_NEXUS_LOSS) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_IOCB_OVERFLOW:
		PRINT_ERROR("qla2x00t(%ld): Cannot provide requested "
			"capability (IOCB overflowed the immediate notify "
			"resource count)", ha->instance);
		break;

	case IMM_NTFY_ABORT_TASK:
		TRACE(TRACE_MGMT, "Abort Task (S %08x I %#x -> L %#x)",
		      le16_to_cpu(iocb2x->seq_id), GET_TARGET_ID(ha, iocb2x),
		      le16_to_cpu(iocb2x->lun));
		if (q2t_abort_task(ha, iocb2x) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_RESOURCE:
		PRINT_ERROR("qla2x00t(%ld): Out of resources, host %ld",
			    ha->instance, ha->host_no);
		break;

	case IMM_NTFY_MSG_RX:
		TRACE(TRACE_MGMT, "Immediate notify task %x", iocb2x->task_flags);
		if (q2t_handle_task_mgmt(ha, iocb2x) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_ELS:
		if (q24_handle_els(ha, iocb24) == 0)
			send_notify_ack = 0;
		break;

	case IMM_NTFY_SRR:
		q2t_prepare_srr_imm(ha, iocb);
		send_notify_ack = 0;
		break;

	default:
		PRINT_ERROR("qla2x00t(%ld): Received unknown immediate "
			"notify status %x", ha->instance, status);
		break;
	}

	if (send_notify_ack) {
		if (IS_FWI2_CAPABLE(ha))
			q24_send_notify_ack(ha, iocb24, 0, 0, 0);
		else
			q2x_send_notify_ack(ha, iocb2x, add_flags, 0, 0, 0,
				0, 0);
	}

	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q2x_send_busy(scsi_qla_host_t *ha, atio_entry_t *atio)
{
	ctio_ret_entry_t *ctio;

	TRACE_ENTRY();

	/* Sending marker isn't necessary, since we called from ISR */

	ctio = (ctio_ret_entry_t *)qla2x00_req_pkt(ha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out;
	}

	ctio->entry_type = CTIO_RET_TYPE;
	ctio->entry_count = 1;
	ctio->handle = Q2T_SKIP_HANDLE | CTIO_COMPLETION_HANDLE_MARK;
	ctio->scsi_status = __constant_cpu_to_le16(SAM_STAT_BUSY);
	ctio->residual = atio->data_length;
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	/* Set IDs */
	SET_TARGET_ID(ha, ctio->target, GET_TARGET_ID(ha, atio));
	ctio->rx_id = atio->rx_id;

	ctio->flags = __constant_cpu_to_le16(OF_SSTS | OF_FAST_POST |
				  OF_NO_DATA | OF_SS_MODE_1);
	ctio->flags |= __constant_cpu_to_le16(OF_INC_RC);
	/*
	 * CTIO from fw w/o scst_cmd doesn't provide enough info to retry it,
	 * if the explicit conformation is used.
	 */

	TRACE_BUFFER("CTIO BUSY packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q24_send_busy(scsi_qla_host_t *ha, atio7_entry_t *atio,
	uint16_t status)
{
	ctio7_status1_entry_t *ctio;
	struct q2t_sess *sess;

	TRACE_ENTRY();

	sess = q2t_find_sess_by_s_id(ha->tgt, atio->fcp_hdr.s_id);
	if (sess == NULL) {
		q24_send_term_exchange(ha, NULL, atio, 1);
		goto out;
	}

	/* Sending marker isn't necessary, since we called from ISR */

	ctio = (ctio7_status1_entry_t *)qla2x00_req_pkt(ha);
	if (ctio == NULL) {
		PRINT_ERROR("qla2x00t(%ld): %s failed: unable to allocate "
			"request packet", ha->instance, __func__);
		goto out;
	}

	ctio->common.entry_type = CTIO_TYPE7;
	ctio->common.entry_count = 1;
	ctio->common.handle = Q2T_SKIP_HANDLE | CTIO_COMPLETION_HANDLE_MARK;
	ctio->common.nport_handle = sess->loop_id;
	ctio->common.timeout = __constant_cpu_to_le16(Q2T_TIMEOUT);
	ctio->common.initiator_id[0] = atio->fcp_hdr.s_id[2];
	ctio->common.initiator_id[1] = atio->fcp_hdr.s_id[1];
	ctio->common.initiator_id[2] = atio->fcp_hdr.s_id[0];
	ctio->common.exchange_addr = atio->exchange_addr;
	ctio->flags = (atio->attr << 9) | __constant_cpu_to_le16(
		CTIO7_FLAGS_STATUS_MODE_1 | CTIO7_FLAGS_SEND_STATUS |
		CTIO7_FLAGS_DONT_RET_CTIO);
	/*
	 * CTIO from fw w/o scst_cmd doesn't provide enough info to retry it,
	 * if the explicit conformation is used.
	 */
	ctio->ox_id = swab16(atio->fcp_hdr.ox_id);
	ctio->scsi_status = cpu_to_le16(status);
	ctio->residual = atio->fcp_cmnd.data_length;
	if (ctio->residual != 0)
		ctio->scsi_status |= SS_RESIDUAL_UNDER;

	TRACE_BUFFER("CTIO7 BUSY packet data", ctio, REQUEST_ENTRY_SIZE);

	q2t_exec_queue(ha);

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q24_atio_pkt(scsi_qla_host_t *ha, atio7_entry_t *atio)
{
	int rc;
	struct q2t_tgt *tgt = ha->tgt;

	TRACE_ENTRY();

	if (unlikely(tgt == NULL)) {
		TRACE_MGMT_DBG("ATIO pkt, but no tgt (ha %p)", ha);
		goto out;
	}

	TRACE(TRACE_SCSI, "ATIO pkt %p: type %02x count %02x",
	      atio, atio->entry_type, atio->entry_count);

	/*
	 * In tgt_stop mode we also should allow all requests to pass.
	 * Otherwise, some commands can stuck.
	 */

	tgt->irq_cmd_count++;

	switch (atio->entry_type) {
	case ATIO_TYPE7:
		if (unlikely(atio->entry_count > 1) ||
		    unlikely(atio->fcp_cmnd.add_cdb_len != 0)) {
			PRINT_ERROR("qla2x00t(%ld): Multi entry ATIO7 IOCBs "
				"(%d), ie with CDBs>16 bytes (%d), are not "
				"supported", ha->instance, atio->entry_count,
				atio->fcp_cmnd.add_cdb_len);
			break;
		}
		TRACE_DBG("ATIO_TYPE7 instance %ld "
			  "lun %Lx read/write %d/%d data_length %04x "
			  "s_id %x:%x:%x",
			  ha->instance, atio->fcp_cmnd.lun,
			  atio->fcp_cmnd.rddata, atio->fcp_cmnd.wrdata,
			  be32_to_cpu(atio->fcp_cmnd.data_length),
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
				"sending QUEUE_FULL", ha->instance);
			q24_send_busy(ha, atio, SAM_STAT_TASK_SET_FULL);
			break;
		}
		if (likely(atio->fcp_cmnd.task_mgmt_flags == 0))
			rc = q2t_send_cmd_to_scst(ha, (atio_t *)atio);
		else
			rc = q2t_handle_task_mgmt(ha, atio);
		if (unlikely(rc != 0)) {
			if (rc == -ESRCH) {
#if 1 /* With TERM EXCHANGE some FC cards refuse to boot */
				q24_send_busy(ha, atio, SAM_STAT_BUSY);
#else
				q24_send_term_exchange(ha, NULL, atio, 1);
#endif
			} else {
				PRINT_INFO("qla2x00t(%ld): Unable to send "
				   "command to SCST, sending BUSY status",
				   ha->instance);
				q24_send_busy(ha, atio, SAM_STAT_BUSY);
			}
		}
		break;

	case IMMED_NOTIFY_TYPE:
	{
		notify_entry_t *pkt = (notify_entry_t *)atio;
		if (unlikely(pkt->entry_status != 0)) {
			PRINT_ERROR("qla2x00t(%ld): Received ATIO packet %x "
				"with error status %x", ha->instance,
				pkt->entry_type, pkt->entry_status);
			break;
		}
		TRACE_DBG("%s", "IMMED_NOTIFY ATIO");
		q2t_handle_imm_notify(ha, pkt);
		break;
	}

	default:
		PRINT_ERROR("qla2x00t(%ld): Received unknown ATIO atio "
		     "type %x", ha->instance, atio->entry_type);
		break;
	}

	tgt->irq_cmd_count--;

out:
	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held on entry */
/* called via callback from qla2xxx */
static void q2t_response_pkt(scsi_qla_host_t *ha, response_t *pkt)
{
	struct q2t_tgt *tgt = ha->tgt;

	TRACE_ENTRY();

	if (unlikely(tgt == NULL)) {
		PRINT_ERROR("Response pkt %x received, but no tgt (ha %p)",
			pkt->entry_type, ha);
		goto out;
	}

	TRACE(TRACE_SCSI, "pkt %p: T %02x C %02x S %02x handle %#x",
	      pkt, pkt->entry_type, pkt->entry_count, pkt->entry_status,
	      pkt->handle);

	/*
	 * In tgt_stop mode we also should allow all requests to pass.
	 * Otherwise, some commands can stuck.
	 */

	if (unlikely(pkt->entry_status != 0)) {
		PRINT_ERROR("qla2x00t(%ld): Received response packet %x "
		     "with error status %x", ha->instance, pkt->entry_type,
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
			  ha->instance);
		TRACE_BUFFER("Incoming CTIO7 packet data", entry,
			REQUEST_ENTRY_SIZE);
		q2t_do_ctio_completion(ha, entry->handle,
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
			  ha->instance, le16_to_cpu(atio->status),
			  le16_to_cpu(atio->lun),
			  atio->execution_codes,
			  le32_to_cpu(atio->data_length),
			  GET_TARGET_ID(ha, atio), atio->rx_id);
		TRACE_BUFFER("Incoming ATIO packet data", atio,
			REQUEST_ENTRY_SIZE);
		if (atio->status != __constant_cpu_to_le16(ATIO_CDB_VALID)) {
			PRINT_ERROR("qla2x00t(%ld): ATIO with error "
				    "status %x received", ha->instance,
				    le16_to_cpu(atio->status));
			break;
		}
		TRACE_BUFFER("Incoming ATIO packet data", atio, REQUEST_ENTRY_SIZE);
		PRINT_BUFF_FLAG(TRACE_SCSI, "FCP CDB", atio->cdb,
				sizeof(atio->cdb));
		rc = q2t_send_cmd_to_scst(ha, (atio_t *)atio);
		if (unlikely(rc != 0)) {
			if (rc == -ESRCH) {
#if 1 /* With TERM EXCHANGE some FC cards refuse to boot */
				q2x_send_busy(ha, atio);
#else
				q2x_send_term_exchange(ha, NULL, atio, 1);
#endif
			} else {
				PRINT_INFO("qla2x00t(%ld): Unable to send "
					"command to SCST, sending BUSY status",
					ha->instance);
				q2x_send_busy(ha, atio);
			}
		}
	}
	break;

	case CONTINUE_TGT_IO_TYPE:
	{
		ctio_common_entry_t *entry = (ctio_common_entry_t *)pkt;
		TRACE_DBG("CONTINUE_TGT_IO: instance %ld", ha->instance);
		TRACE_BUFFER("Incoming CTIO packet data", entry,
			REQUEST_ENTRY_SIZE);
		q2t_do_ctio_completion(ha, entry->handle,
			le16_to_cpu(entry->status)|(pkt->entry_status << 16),
			entry);
		break;
	}

	case CTIO_A64_TYPE:
	{
		ctio_common_entry_t *entry = (ctio_common_entry_t *)pkt;
		TRACE_DBG("CTIO_A64: instance %ld", ha->instance);
		TRACE_BUFFER("Incoming CTIO_A64 packet data", entry,
			REQUEST_ENTRY_SIZE);
		q2t_do_ctio_completion(ha, entry->handle,
			le16_to_cpu(entry->status)|(pkt->entry_status << 16),
			entry);
		break;
	}

	case IMMED_NOTIFY_TYPE:
		TRACE_DBG("%s", "IMMED_NOTIFY");
		q2t_handle_imm_notify(ha, (notify_entry_t *)pkt);
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
			if (entry->status != __constant_cpu_to_le16(NOTIFY_ACK_SUCCESS)) {
				PRINT_ERROR("qla2x00t(%ld): NOTIFY_ACK "
					    "failed %x", ha->instance,
					    le16_to_cpu(entry->status));
			}
		} else {
			PRINT_ERROR("qla2x00t(%ld): Unexpected NOTIFY_ACK "
				    "received", ha->instance);
		}
		break;

	case ABTS_RECV_24XX:
		TRACE_DBG("ABTS_RECV_24XX: instance %ld", ha->instance);
		TRACE_BUFF_FLAG(TRACE_BUFF, "Incoming ABTS_RECV "
			"packet data", pkt, REQUEST_ENTRY_SIZE);
		q24_handle_abts(ha, (abts24_recv_entry_t *)pkt);
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
					 * all aborted exchanges must be explicitely
					 * terminated, otherwise it refuses to send
					 * responses for the abort requests. So, we
					 * have to (re)terminate the exchange and
					 * retry the abort response.
					 */
					q24_retry_term_exchange(ha, entry);
				} else
					PRINT_ERROR("qla2x00t(%ld): ABTS_RESP_24XX "
					    "failed %x (subcode %x:%x)", ha->instance,
					    entry->compl_status, entry->error_subcode1,
					    entry->error_subcode2);
			}
		} else {
			PRINT_ERROR("qla2x00t(%ld): Unexpected ABTS_RESP_24XX "
				    "received", ha->instance);
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
					    "failed %x", ha->instance,
					    entry->status);
			}
		} else {
			PRINT_ERROR("qla2x00t(%ld): Unexpected MODIFY_LUN "
			    "received", (ha != NULL) ? (long)ha->instance : -1);
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
				"failed %x", ha->instance, entry->status);
			qla_clear_tgt_mode(ha);
		} /* else success */
		break;
	}

	default:
		PRINT_ERROR("qla2x00t(%ld): Received unknown response pkt "
		     "type %x", ha->instance, pkt->entry_type);
		break;
	}

	tgt->irq_cmd_count--;

out:
	TRACE_EXIT();
	return;
}

/*
 * ha->hardware_lock supposed to be held on entry. Might drop it, then reaquire
 */
static void q2t_async_event(uint16_t code, scsi_qla_host_t *ha,
	uint16_t *mailbox)
{
	struct q2t_tgt *tgt = ha->tgt;

	TRACE_ENTRY();

	if (unlikely(tgt == NULL)) {
		TRACE_DBG("ASYNC EVENT %#x, but no tgt (ha %p)", code, ha);
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
		TRACE(TRACE_MGMT, "System error async event %#x occured", code);
		break;

	case MBA_LOOP_UP:
	{
		TRACE(TRACE_MGMT, "Async LOOP_UP occured (m[1]=%x, m[2]=%x, "
			"m[3]=%x, m[4]=%x)", le16_to_cpu(mailbox[1]),
			le16_to_cpu(mailbox[2]), le16_to_cpu(mailbox[3]),
			le16_to_cpu(mailbox[4]));
		if (tgt->link_reinit_iocb_pending) {
			q24_send_notify_ack(ha, &tgt->link_reinit_iocb, 0, 0, 0);
			tgt->link_reinit_iocb_pending = 0;
		}
		break;
	}

	case MBA_LIP_OCCURRED:
	case MBA_LOOP_DOWN:
	case MBA_LIP_RESET:
		TRACE(TRACE_MGMT, "Async event %#x occured (m[1]=%x, m[2]=%x, "
			"m[3]=%x, m[4]=%x)", code,
			le16_to_cpu(mailbox[1]), le16_to_cpu(mailbox[2]),
			le16_to_cpu(mailbox[3]), le16_to_cpu(mailbox[4]));
		break;

	case MBA_PORT_UPDATE:
	case MBA_RSCN_UPDATE:
		TRACE(TRACE_MGMT, "Port update async event %#x occured: "
			"updating the ports database (m[1]=%x, m[2]=%x, "
			"m[3]=%x, m[4]=%x)", code,
			le16_to_cpu(mailbox[1]), le16_to_cpu(mailbox[2]),
			le16_to_cpu(mailbox[3]), le16_to_cpu(mailbox[4]));
		/* .mark_all_devices_lost() is handled by the initiator driver */
		break;

	default:
		TRACE(TRACE_MGMT, "Async event %#x occured: ignore (m[1]=%x, "
			"m[2]=%x, m[3]=%x, m[4]=%x)", code,
			le16_to_cpu(mailbox[1]), le16_to_cpu(mailbox[2]),
			le16_to_cpu(mailbox[3]), le16_to_cpu(mailbox[4]));
		break;
	}

	tgt->irq_cmd_count--;

out:
	TRACE_EXIT();
	return;
}

static int q2t_get_target_name(scsi_qla_host_t *ha, char **wwn)
{
	const int wwn_len = 3*WWN_SIZE+2;
	int res = 0;
	char *name;

	name = kmalloc(wwn_len, GFP_KERNEL);
	if (name == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of tgt name failed");
		res = -ENOMEM;
		goto out;
	}

	sprintf(name, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		ha->port_name[0], ha->port_name[1],
		ha->port_name[2], ha->port_name[3],
		ha->port_name[4], ha->port_name[5],
		ha->port_name[6], ha->port_name[7]);

	*wwn = name;

out:
	return res;
}

static int q24_get_loop_id(scsi_qla_host_t *ha, atio7_entry_t *atio7,
	uint16_t *loop_id)
{
	dma_addr_t gid_list_dma;
	struct gid_list_info *gid_list;
	char *id_iter;
	int res, rc, i;
	uint16_t entries;

	TRACE_ENTRY();

	gid_list = dma_alloc_coherent(&ha->pdev->dev, GID_LIST_SIZE,
			&gid_list_dma, GFP_KERNEL);
	if (gid_list == NULL) {
		PRINT_ERROR("DMA Alloc failed of %zd", GID_LIST_SIZE);
		res = -ENOMEM;
		goto out;
	}

	/* Get list of logged in devices */
	rc = qla2x00_get_id_list(ha, gid_list, gid_list_dma, &entries);
	if (rc != QLA_SUCCESS) {
		PRINT_ERROR("get_id_list() failed: %x", rc);
		res = -1;
		goto out_free_id_list;
	}

	id_iter = (char *)gid_list;
	res = -1;
	for (i = 0; i < entries; i++) {
		struct gid_list_info *gid = (struct gid_list_info *)id_iter;
		if ((gid->al_pa == atio7->fcp_hdr.s_id[2]) &&
		    (gid->area == atio7->fcp_hdr.s_id[1]) &&
		    (gid->domain == atio7->fcp_hdr.s_id[0])) {
			*loop_id = le16_to_cpu(gid->loop_id);
			res = 0;
			break;
		}
		id_iter += ha->gid_list_info_size;
	}

	if (res != 0) {
		PRINT_ERROR("Unable to find initiator with S_ID %x:%x:%x",
			atio7->fcp_hdr.s_id[2], atio7->fcp_hdr.s_id[1],
			atio7->fcp_hdr.s_id[0]);
	}

out_free_id_list:
	dma_free_coherent(&ha->pdev->dev, GID_LIST_SIZE, gid_list, gid_list_dma);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Must be called under tgt_mutex */
static struct q2t_sess *q2t_make_local_sess(scsi_qla_host_t *ha, atio_t *atio)
{
	struct q2t_sess *sess = NULL;
	fc_port_t *fcport = NULL;
	uint16_t loop_id = 0xFFFF; /* to remove warning */
	int rc;

	TRACE_ENTRY();

	if (IS_FWI2_CAPABLE(ha)) {
		rc = q24_get_loop_id(ha, (atio7_entry_t *)atio, &loop_id);
		if (rc != 0)
			goto out;
	} else
		loop_id = GET_TARGET_ID(ha, (atio_entry_t *)atio);

	fcport = kzalloc(sizeof(*fcport), GFP_KERNEL);
	if (fcport == NULL) {
		PRINT_ERROR("%s", "Allocation of tmp FC port failed");
		goto out;
	}

	TRACE_MGMT_DBG("loop_id %d", loop_id);

	fcport->loop_id = loop_id;

	rc = qla2x00_get_port_database(ha, fcport, 0);
	if (rc != QLA_SUCCESS) {
		PRINT_ERROR("Failed to retrieve fcport information "
			"-- get_port_database() returned %x "
			"(loop_id=0x%04x)", rc, loop_id);
		goto out_free_fcport;
	}

	sess = q2t_create_sess(ha, fcport, true);

out_free_fcport:
	kfree(fcport);

out:
	TRACE_EXIT_HRES((unsigned long)sess);
	return sess;
}

static int q2t_exec_sess_work(struct q2t_tgt *tgt,
	struct q2t_sess_work_param *prm)
{
	scsi_qla_host_t *ha = tgt->ha;
	int res = 0;
	struct q2t_sess *sess = NULL;
	struct q2t_cmd *cmd = prm->cmd;
	atio_t *atio = (atio_t *)&cmd->atio;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("cmd %p", cmd);

	mutex_lock(&ha->tgt_mutex);
	spin_lock_irq(&ha->hardware_lock);

	if (tgt->tgt_stop)
		goto send;

	if (IS_FWI2_CAPABLE(ha)) {
		atio7_entry_t *a = (atio7_entry_t *)atio;
		sess = q2t_find_sess_by_s_id(tgt, a->fcp_hdr.s_id);
	} else
		sess = q2t_find_sess_by_loop_id(tgt,
			GET_TARGET_ID(ha, (atio_entry_t *)atio));

	if (sess != NULL) {
		TRACE_MGMT_DBG("sess %p found", sess);
		q2t_sess_get(sess);
	} else {
		/*
		 * We are under tgt_mutex, so a new sess can't be added
		 * behind us.
		 */
		spin_unlock_irq(&ha->hardware_lock);
		sess = q2t_make_local_sess(ha, atio);
		spin_lock_irq(&ha->hardware_lock);
		/* sess has got an extra creation ref */
	}

send:
	if (!tgt->tm_to_unknown && !tgt->tgt_stop && (sess != NULL)) {
		TRACE_MGMT_DBG("Sending work cmd %p to SCST", cmd);
		res = q2t_do_send_cmd_to_scst(ha, cmd, sess);
	} else {
		/*
		 * Cmd might be already aborted behind us, so be safe and
		 * abort it. It was not sent to SCST yet, so pass NULL as
		 * the second argument.
		 */
		TRACE_MGMT_DBG("Terminating work cmd %p", cmd);
		if (IS_FWI2_CAPABLE(ha))
			q24_send_term_exchange(ha, NULL , &cmd->atio.atio7, 1);
		else
			q2x_send_term_exchange(ha, NULL, &cmd->atio.atio2x, 1);
		q2t_free_cmd(cmd);
	}

	if (sess != NULL)
		q2t_sess_put(sess);

	spin_unlock_irq(&ha->hardware_lock);
	mutex_unlock(&ha->tgt_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

static void q2t_sess_work_fn(struct work_struct *work)
{
	struct q2t_tgt *tgt = container_of(work, struct q2t_tgt, sess_work);

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Sess work (tgt %p)", tgt);

	spin_lock_irq(&tgt->sess_work_lock);
	while (!list_empty(&tgt->sess_works_list)) {
		int rc;
		struct q2t_sess_work_param *prm = list_entry(
			tgt->sess_works_list.next, typeof(*prm),
			sess_works_list_entry);

		/*
		 * This work can be scheduled on several CPUs at time, so we
		 * must delete the entry to eliminate double processing
		 */
		list_del(&prm->sess_works_list_entry);

		spin_unlock_irq(&tgt->sess_work_lock);

		rc = q2t_exec_sess_work(tgt, prm);

		spin_lock_irq(&tgt->sess_work_lock);

		if (rc != 0) {
			PRINT_CRIT_ERROR("%s", "Unable to complete sess work");
			q2t_free_cmd(prm->cmd);
		}

		kfree(prm);
	}
	spin_unlock_irq(&tgt->sess_work_lock);

	spin_lock_irq(&tgt->ha->hardware_lock);
	spin_lock(&tgt->sess_work_lock);
	if (list_empty(&tgt->sess_works_list)) {
		tgt->sess_works_pending = 0;
		tgt->tm_to_unknown = 0;
	}
	spin_unlock(&tgt->sess_work_lock);
	spin_unlock_irq(&tgt->ha->hardware_lock);

	TRACE_EXIT();
	return;
}

/* ha->hardware_lock supposed to be held and IRQs off */
static void q2t_cleanup_hw_pending_cmd(scsi_qla_host_t *ha, struct q2t_cmd *cmd)
{
	uint32_t h;

	for (h = 0; h < MAX_OUTSTANDING_COMMANDS; h++) {
		if (ha->cmds[h] == cmd) {
			TRACE_DBG("Clearing handle %d for cmd %p", h, cmd);
			ha->cmds[h] = NULL;
			break;
		}
	}
	return;
}

static void q2t_on_hw_pending_cmd_timeout(struct scst_cmd *scst_cmd)
{
	struct q2t_cmd *cmd = (struct q2t_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	struct q2t_tgt *tgt = cmd->tgt;
	scsi_qla_host_t *ha = tgt->ha;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Cmd %p HW pending for too long (state %x)", cmd,
		cmd->state);

	spin_lock_irqsave(&ha->hardware_lock, flags);

	if (cmd->state == Q2T_STATE_PROCESSED) {
		TRACE_MGMT_DBG("Force finishing cmd %p", cmd);
		if (q2t_has_data(cmd)) {
			pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
				cmd->dma_data_direction);
		}
	} else if (cmd->state == Q2T_STATE_NEED_DATA) {
		TRACE_MGMT_DBG("Force rx_data cmd %p", cmd);

		q2t_cleanup_hw_pending_cmd(ha, cmd);

		pci_unmap_sg(ha->pdev, cmd->sg, cmd->sg_cnt,
			cmd->dma_data_direction);

		scst_rx_data(scst_cmd, SCST_RX_STATUS_ERROR_FATAL,
				SCST_CONTEXT_THREAD);
		goto out_unlock;
	} else if (cmd->state == Q2T_STATE_ABORTED) {
		TRACE_MGMT_DBG("Force finishing aborted cmd %p (tag %d)",
			cmd, cmd->tag);
	} else {
		PRINT_ERROR("qla2x00t(%ld): A command in state (%d) should "
			"not be HW pending", ha->instance, cmd->state);
		goto out_unlock;
	}

	q2t_cleanup_hw_pending_cmd(ha, cmd);

	scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_THREAD);

out_unlock:
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	TRACE_EXIT();
	return;
}

/* Must be called under tgt_host_action_mutex */
static int q2t_add_target(scsi_qla_host_t *ha)
{
	int res, rc;
	char *wwn;
	int sg_tablesize;
	struct q2t_tgt *tgt;

	TRACE_ENTRY();

	TRACE_DBG("Registering target for host %ld(%p)", ha->host_no, ha);

	sBUG_ON((ha->q2t_tgt != NULL) || (ha->tgt != NULL));

	tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
	if (tgt == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of tgt "
			"failed");
		res = -ENOMEM;
		goto out;
	}

	tgt->ha = ha;
	init_waitqueue_head(&tgt->waitQ);
	INIT_LIST_HEAD(&tgt->sess_list);
	INIT_LIST_HEAD(&tgt->del_sess_list);
	init_timer(&tgt->sess_del_timer);
	tgt->sess_del_timer.data = (unsigned long)tgt;
	tgt->sess_del_timer.function = q2t_del_sess_timer_fn;
	spin_lock_init(&tgt->sess_work_lock);
	INIT_WORK(&tgt->sess_work, q2t_sess_work_fn);
	INIT_LIST_HEAD(&tgt->sess_works_list);
	spin_lock_init(&tgt->srr_lock);
	INIT_LIST_HEAD(&tgt->srr_ctio_list);
	INIT_LIST_HEAD(&tgt->srr_imm_list);
	INIT_WORK(&tgt->srr_work, q2t_handle_srr_work);

	ha->q2t_tgt = tgt;

	if (q2t_get_target_name(ha, &wwn) != 0)
		goto out_free;

	tgt->scst_tgt = scst_register_target(&tgt2x_template, wwn);

	kfree(wwn);

	if (!tgt->scst_tgt) {
		PRINT_ERROR("qla2x00t(%ld): scst_register_target() "
			    "failed for host %ld(%p)", ha->instance,
			    ha->host_no, ha);
		res = -ENOMEM;
		goto out_free;
	}

	if (IS_FWI2_CAPABLE(ha)) {
		PRINT_INFO("qla2400tgt(%ld): using 64 Bit PCI "
			   "addressing", ha->instance);
			tgt->tgt_enable_64bit_addr = 1;
			/* 3 is reserved */
			sg_tablesize =
			    QLA_MAX_SG_24XX(ha->request_q_length - 3);
			tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND_24XX;
			tgt->datasegs_per_cont = DATASEGS_PER_CONT_24XX;
	} else {
		if (ha->flags.enable_64bit_addressing) {
			PRINT_INFO("qla2x00t(%ld): 64 Bit PCI "
				   "addressing enabled", ha->instance);
			tgt->tgt_enable_64bit_addr = 1;
			/* 3 is reserved */
			sg_tablesize =
				QLA_MAX_SG64(ha->request_q_length - 3);
			tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND64;
			tgt->datasegs_per_cont = DATASEGS_PER_CONT64;
		} else {
			PRINT_INFO("qla2x00t(%ld): Using 32 Bit "
				   "PCI addressing", ha->instance);
			sg_tablesize =
				QLA_MAX_SG32(ha->request_q_length - 3);
			tgt->datasegs_per_cmd = DATASEGS_PER_COMMAND32;
			tgt->datasegs_per_cont = DATASEGS_PER_CONT32;
		}
	}

#ifndef CONFIG_SCST_PROC
	rc = sysfs_create_link(scst_sysfs_get_tgt_kobj(tgt->scst_tgt),
		&ha->host->shost_dev.kobj, "host");
	if (rc != 0)
		PRINT_ERROR("Unable to create \"host\" link for target "
			"%s", scst_get_tgt_name(tgt->scst_tgt));
#endif

	scst_tgt_set_sg_tablesize(tgt->scst_tgt, sg_tablesize);
	scst_tgt_set_tgt_priv(tgt->scst_tgt, tgt);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	ha->q2t_tgt = NULL;
	kfree(tgt);
	goto out;
}

/* Must be called under tgt_host_action_mutex */
static int q2t_remove_target(scsi_qla_host_t *ha)
{
	TRACE_ENTRY();

	if ((ha->q2t_tgt == NULL) || (ha->tgt != NULL)) {
		PRINT_ERROR("qla2x00t(%ld): Can't remove "
			"existing target", ha->instance);
	}

	TRACE_DBG("Unregistering target for host %ld(%p)", ha->host_no, ha);
	scst_unregister_target(ha->tgt->scst_tgt);
	/*
	 * Free of tgt happens via callback q2t_target_release
	 * called from scst_unregister_target, so we shouldn't touch
	 * it again.
	 */

	TRACE_EXIT();
	return 0;
}

static int q2t_host_action(scsi_qla_host_t *ha,
	qla2x_tgt_host_action_t action)
{
	int res = 0;

	TRACE_ENTRY();

	sBUG_ON(ha == NULL);

	/* To sync with q2t_exit() */
	if (down_read_trylock(&q2t_unreg_rwsem) == 0)
		goto out;

	mutex_lock(&ha->tgt_host_action_mutex);

	switch (action) {
	case ADD_TARGET:
		res = q2t_add_target(ha);
		break;
	case REMOVE_TARGET:
		res = q2t_remove_target(ha);
		break;
	case ENABLE_TARGET_MODE:
	{
		fc_port_t *fcport;

		if (qla_tgt_mode_enabled(ha)) {
			PRINT_INFO("qla2x00t(%ld): Target mode already "
				"enabled", ha->instance);
			break;
		}

		if ((ha->q2t_tgt == NULL) || (ha->tgt != NULL)) {
			PRINT_ERROR("qla2x00t(%ld): Can't enable target mode "
				"for not existing target", ha->instance);
			break;
		}

		PRINT_INFO("qla2x00t(%ld): Enabling target mode",
			ha->instance);

		spin_lock_irq(&ha->hardware_lock);
		ha->tgt = ha->q2t_tgt;
		ha->tgt->tgt_stop = 0;
		spin_unlock_irq(&ha->hardware_lock);
		list_for_each_entry_rcu(fcport, &ha->fcports, list) {
			q2t_fc_port_added(ha, fcport);
		}
		TRACE_DBG("Enable tgt mode for host %ld(%ld,%p)",
			  ha->host_no, ha->instance, ha);
		qla2x00_enable_tgt_mode(ha);
		break;
	}

	case DISABLE_TARGET_MODE:
		if (!qla_tgt_mode_enabled(ha)) {
			PRINT_INFO("qla2x00t(%ld): Target mode already "
				"disabled", ha->instance);
			break;
		}

		PRINT_INFO("qla2x00t(%ld): Disabling target mode",
			ha->instance);

		sBUG_ON(ha->tgt == NULL);

		q2t_target_stop(ha->tgt->scst_tgt);
		break;

	default:
		PRINT_ERROR("qla2x00t(%ld): %s: unsupported action %d",
			ha->instance, __func__, action);
		res = -EINVAL;
		break;
	}

	mutex_unlock(&ha->tgt_host_action_mutex);

	up_read(&q2t_unreg_rwsem);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int q2t_enable_tgt(struct scst_tgt *scst_tgt, bool enable)
{
	struct q2t_tgt *tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *ha = tgt->ha;
	int res;

	if (enable)
		res = q2t_host_action(ha, ENABLE_TARGET_MODE);
	else
		res = q2t_host_action(ha, DISABLE_TARGET_MODE);

	return res;
}

static bool q2t_is_tgt_enabled(struct scst_tgt *scst_tgt)
{
	struct q2t_tgt *tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	scsi_qla_host_t *ha = tgt->ha;

	return qla_tgt_mode_enabled(ha);
}

static int q2t_get_initiator_port_transport_id(struct scst_session *scst_sess,
	uint8_t **transport_id)
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
		PRINT_ERROR("Allocation of TransportID (size %d) failed",
			tr_id_size);
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

#ifndef CONFIG_SCST_PROC

static ssize_t q2t_show_expl_conf_enabled(struct kobject *kobj,
	struct kobj_attribute *attr, char *buffer)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *ha;
	ssize_t size;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	ha = tgt->ha;

	size = scnprintf(buffer, PAGE_SIZE, "%d\n%s", ha->enable_explicit_conf,
		ha->enable_explicit_conf ? SCST_SYSFS_KEY_MARK "\n" : "");

	return size;
}

static ssize_t q2t_store_expl_conf_enabled(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *ha;
	unsigned long flags;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	ha = tgt->ha;

	spin_lock_irqsave(&ha->hardware_lock, flags);

	switch (buffer[0]) {
	case '0':
		ha->enable_explicit_conf = 0;
		PRINT_INFO("qla2xxx(%ld): explicit conformations disabled",
			ha->instance);
		break;
	case '1':
		ha->enable_explicit_conf = 1;
		PRINT_INFO("qla2xxx(%ld): explicit conformations enabled",
			ha->instance);
		break;
	default:
#if defined(QL_DEBUG_LEVEL_9) || defined(QL_DEBUG_LEVEL_11)
		PRINT_INFO("%s: Requested action not understood: %s",
		       __func__, buffer);
#endif
		break;
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return size;
}

static ssize_t q2t_abort_isp_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct q2t_tgt *tgt;
	scsi_qla_host_t *ha;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct q2t_tgt *)scst_tgt_get_tgt_priv(scst_tgt);
	ha = tgt->ha;

	PRINT_INFO("qla2xxx(%ld): Aborting ISP", ha->instance);

	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	qla2x00_wait_for_hba_online(ha);

	return size;
}

static ssize_t q2t_version_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	sprintf(buf, "%s\n", Q2T_VERSION_STRING);

#ifdef CONFIG_SCST_EXTRACHECKS
	strcat(buf, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_SCST_TRACING
	strcat(buf, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	strcat(buf, "DEBUG\n");
#endif

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	strcat(buf, "QLA_TGT_DEBUG_WORK_IN_THREAD\n");
#endif

	TRACE_EXIT();
	return strlen(buf);
}

#else /* CONFIG_SCST_PROC */

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define Q2T_PROC_LOG_ENTRY_NAME     "trace_level"

#include <linux/proc_fs.h>

static int q2t_log_info_show(struct seq_file *seq, void *v)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_read(seq, trace_flag, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t q2t_proc_log_entry_write(struct file *file,
	const char __user *buf, size_t length, loff_t *off)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, &trace_flag,
		Q2T_DEFAULT_LOG_FLAGS, NULL);

	TRACE_EXIT_RES(res);
	return res;
}
#endif

static int q2t_version_info_show(struct seq_file *seq, void *v)
{
	TRACE_ENTRY();

	seq_printf(seq, "%s\n", Q2T_VERSION_STRING);

#ifdef CONFIG_SCST_EXTRACHECKS
	seq_printf(seq, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	seq_printf(seq, "DEBUG_WORK_IN_THREAD\n");
#endif

#ifdef CONFIG_SCST_TRACING
	seq_printf(seq, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	seq_printf(seq, "DEBUG\n");
#endif

#ifdef CONFIG_QLA_TGT_DEBUG_SRR
	seq_printf(seq, "DEBUG_SRR\n");
#endif

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data q2t_version_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = q2t_version_info_show,
};

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static struct scst_proc_data q2t_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(q2t_proc_log_entry_write)
	.show = q2t_log_info_show,
};
#endif

static __init int q2t_proc_log_entry_build(struct scst_tgt_template *templ)
{
	int res = 0;
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
		p = scst_create_proc_entry(root, Q2T_PROC_VERSION_NAME,
					 &q2t_version_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register "
			     "target driver %s entry %s in /proc",
			      templ->name, Q2T_PROC_VERSION_NAME);
			res = -ENOMEM;
			goto out;
		}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
		/* create the proc file entry for the device */
		q2t_log_proc_data.data = (void *)templ->name;
		p = scst_create_proc_entry(root, Q2T_PROC_LOG_ENTRY_NAME,
					&q2t_log_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register "
			     "target driver %s entry %s in /proc",
			      templ->name, Q2T_PROC_LOG_ENTRY_NAME);
			res = -ENOMEM;
			goto out_remove_ver;
		}
#endif
	}

out:
	TRACE_EXIT_RES(res);
	return res;

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
out_remove_ver:
	remove_proc_entry(Q2T_PROC_VERSION_NAME, root);
	goto out;
#endif
}

static void q2t_proc_log_entry_clean(struct scst_tgt_template *templ)
{
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
		remove_proc_entry(Q2T_PROC_LOG_ENTRY_NAME, root);
#endif
		remove_proc_entry(Q2T_PROC_VERSION_NAME, root);
	}

	TRACE_EXIT();
	return;
}

#endif /* CONFIG_SCST_PROC */

static uint16_t q2t_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	/* FCP-2 (speculative, there's no info what FW supports) */
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

	PRINT_INFO("Initializing QLogic Fibre Channel HBA Driver target mode "
		"addon version %s", Q2T_VERSION_STRING);

	q2t_cmd_cachep = KMEM_CACHE(q2t_cmd, SCST_SLAB_FLAGS);
	if (q2t_cmd_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	q2t_mgmt_cmd_cachep = KMEM_CACHE(q2t_mgmt_cmd, SCST_SLAB_FLAGS);
	if (q2t_mgmt_cmd_cachep == NULL) {
		res = -ENOMEM;
		goto out_cmd_free;
	}

	q2t_mgmt_cmd_mempool = mempool_create(25, mempool_alloc_slab,
		mempool_free_slab, q2t_mgmt_cmd_cachep);
	if (q2t_mgmt_cmd_mempool == NULL) {
		res = -ENOMEM;
		goto out_kmem_free;
	}

	res = scst_register_target_template(&tgt2x_template);
	if (res < 0)
		goto out_mempool_free;

	/*
	 * qla2xxx_tgt_register_driver() happens in q2t_target_detect
	 * called via scst_register_target_template()
	 */

#ifdef CONFIG_SCST_PROC
	res = q2t_proc_log_entry_build(&tgt2x_template);
	if (res < 0)
		goto out_unreg_target2x;
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

#ifdef CONFIG_SCST_PROC
out_unreg_target2x:
#endif
	scst_unregister_target_template(&tgt2x_template);
	qla2xxx_tgt_unregister_driver();

out_mempool_free:
	mempool_destroy(q2t_mgmt_cmd_mempool);

out_kmem_free:
	kmem_cache_destroy(q2t_mgmt_cmd_cachep);

out_cmd_free:
	kmem_cache_destroy(q2t_cmd_cachep);
	goto out;
}

static void __exit q2t_exit(void)
{
	TRACE_ENTRY();

	PRINT_INFO("%s", "Unloading QLogic Fibre Channel HBA Driver target "
		"mode addon driver");

	/* To sync with q2t_host_action() */
	down_write(&q2t_unreg_rwsem);

#ifdef CONFIG_SCST_PROC
	q2t_proc_log_entry_clean(&tgt2x_template);
#endif

	scst_unregister_target_template(&tgt2x_template);

	/*
	 * Now we have everywhere target mode disabled and no possibilities
	 * to call us through sysfs, so we can safely remove all the references
	 * to our functions.
	 */
	qla2xxx_tgt_unregister_driver();

	mempool_destroy(q2t_mgmt_cmd_mempool);
	kmem_cache_destroy(q2t_mgmt_cmd_cachep);
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
MODULE_VERSION(Q2T_VERSION_STRING);
