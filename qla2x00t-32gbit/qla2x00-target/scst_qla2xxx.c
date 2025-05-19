/*
 *  scst_qla2xxx.c
 *
 *  SCST Cavium Adapter target interface driver.
 *
 *  Based on initial work by:
 *  Copyright (C) 2004 - 2012 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *  Copyright (C) 2006 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2012 SCST Ltd.
 *
 *  Port to Cavium in-kernel target driver by:
 *  Copyright (C) 2013 Dr. Greg Wettstein, Enjellic Systems Development, LLC
 *  Copyright (C) 2017 Cavium Inc
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

/*
 * This driver is an interface between the SCST core and the Cavium target
 * code (qla_target.c). It uses the LIO se_session and se_cmd data structures
 * to exchange information between this interface driver and the qla2xxx
 * driver.
 *
 * This interface driver relies heavily upon hardware and mutex locking
 * supplied by the qla2xxx driver.  The primary exception to this is the
 * statically scoped sqa_mutex locks which provides exclusion locking between
 * target registration and module unload.
 */

#define EXCLUDED 0

#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_debug.h>
#else
#include "scst.h"
#include "scst_debug.h"
#endif

#include "qla_def.h"
#include "qla_target.h"
#include "scst_qla2xxx.h"

#define SQA_VERSION	QLA2XXX_VERSION

#define SQA_MAX_HW_PENDING_TIME	    60 /* in seconds */


#ifdef CONFIG_SCST_DEBUG
#define SQA_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_LINE | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL)
#else
#ifdef CONFIG_SCST_TRACING
#define SQA_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_SPECIAL)
#endif
#endif

static LIST_HEAD(sqa_tgt_glist);

/* Function definitions for callbacks from the SCST target core. */

static int sqa_target_release(struct scst_tgt *scst_tgt);
static int sqa_xmit_response(struct scst_cmd *scst_cmd);
static int sqa_rdy_to_xfer(struct scst_cmd *scst_cmd);
static void sqa_on_free_cmd(struct scst_cmd *scst_cmd);
static void sqa_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd);
static int sqa_get_initiator_port_transport_id(struct scst_tgt *tgt,
					       struct scst_session *scst_sess,
					       uint8_t **transport_id);
static void sqa_on_hw_pending_cmd_timeout(struct scst_cmd *scst_cmd);
static uint16_t sqa_get_scsi_transport_version(struct scst_tgt *scst_tgt);
static uint16_t sqa_get_phys_transport_version(struct scst_tgt *scst_tgt);
static int sqa_enable_tgt(struct scst_tgt *tgt, bool enable);
static bool sqa_is_tgt_enabled(struct scst_tgt *tgt);
static ssize_t sqa_add_vtarget(const char *target_name, char *params);
static ssize_t sqa_del_vtarget(const char *target_name);

/* Definitions for helper functions. */
static int sqa_get_target_name(uint8_t *wwn, char **ppwwn_name);
static int sqa_parse_wwn(const char *ns, u64 *nm);

/* Variables and function definitions for sysfs control plane. */
static ssize_t sqa_version_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf);

static struct kobj_attribute sqa_version_attr =
	__ATTR(version, S_IRUGO, sqa_version_show, NULL);

static const struct attribute *sqa_attrs[] = {
	&sqa_version_attr.attr,
	NULL,
};

static ssize_t sqa_show_expl_conf_enabled(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buffer);
static ssize_t sqa_store_expl_conf_enabled(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buffer, size_t size);

static struct kobj_attribute sqa_expl_conf_attr =
	__ATTR(explicit_confirmation, S_IRUGO|S_IWUSR,
	       sqa_show_expl_conf_enabled, sqa_store_expl_conf_enabled);

static ssize_t sqa_abort_isp_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buffer, size_t size);

static struct kobj_attribute sqa_abort_isp_attr =
	__ATTR(abort_isp, S_IWUSR, NULL, sqa_abort_isp_store);

static ssize_t sqa_hw_target_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf);

static struct kobj_attribute sqa_hw_target_attr =
	__ATTR(hw_target, S_IRUGO, sqa_hw_target_show, NULL);

static ssize_t sqa_node_name_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf);

#if EXCLUDED
static struct kobj_attribute sqa_vp_node_name_attr =
	__ATTR(node_name, S_IRUGO, sqa_node_name_show, NULL);
#endif

static ssize_t sqa_node_name_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buffer, size_t size);

static struct kobj_attribute sqa_hw_node_name_attr =
	__ATTR(node_name, S_IRUGO|S_IWUSR, sqa_node_name_show,
	       sqa_node_name_store);

#if EXCLUDED
static ssize_t sqa_vp_parent_host_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf);

static struct kobj_attribute sqa_vp_parent_host_attr =
	__ATTR(parent_host, S_IRUGO, sqa_vp_parent_host_show, NULL);
#endif

static const struct attribute *sqa_tgt_attrs[] = {
	&sqa_expl_conf_attr.attr,
	&sqa_abort_isp_attr.attr,
	NULL,
};

/*
 * Statically scoped variables.
 */
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag sqa_trace_flag
static unsigned long sqa_trace_flag = SQA_DEFAULT_LOG_FLAGS;
#endif

//#define CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
static enum scst_exec_context scst_work_context = SCST_CONTEXT_THREAD;
#else
static enum scst_exec_context scst_work_context = SCST_CONTEXT_TASKLET;
#endif


static struct cmd_state_name {
	uint8_t state;
	char *str;
} cmd_str[] = {
	{0xff, "unknown"},
	{QLA_TGT_STATE_NEW, "new"},
	{QLA_TGT_STATE_NEED_DATA, "NeedData"},
	{QLA_TGT_STATE_DATA_IN, "DataIn"},
	{QLA_TGT_STATE_PROCESSED, "Processed"},
};

static char *cmdstate_to_str(uint8_t state)
{
	int i;
	struct cmd_state_name *e;

	for (i = 1; i < ARRAY_SIZE(cmd_str); i++) {
		e = cmd_str + i;
		if (state == e->state)
			return e->str;
	}
	return cmd_str[0].str; /* unknown */
}

#if QLA_ENABLE_PI

static const int qla_tgt_supported_dif_block_size[] = {
	512,
	0,			/* null terminated */
};

static inline void qla_tgt_set_cmd_prot_op(struct qla_tgt_cmd *cmd,
					   uint8_t xmit_rsp)
{
	struct scst_cmd *scst_cmd = cmd->scst_cmd;
	int dir = scst_cmd_get_data_direction(scst_cmd);
	int action = scst_get_dif_action(
		scst_get_tgt_dif_actions(scst_cmd->cmd_dif_actions));

	if (action == SCST_DIF_ACTION_NONE) {
		cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
		return;
	}

	if (scst_cmd->status && (dir == SCST_DATA_NONE)) {
		/* scst_set_cmd_error() will over ride the data direction
		 * in the error case at the back end.  Need to figure out
		 * the
		 */
		dir = scst_cmd_get_expected_data_direction(scst_cmd);
	}

	switch (action) {
	case SCST_DIF_ACTION_STRIP:
		switch (dir) {
		case SCST_DATA_READ:
			cmd->se_cmd.prot_op = TARGET_PROT_DOUT_STRIP;
			break;
		case SCST_DATA_WRITE:
			cmd->se_cmd.prot_op = TARGET_PROT_DIN_STRIP;
			break;
		case SCST_DATA_BIDI:
			if (xmit_rsp)
				cmd->se_cmd.prot_op = TARGET_PROT_DOUT_STRIP;
			else
				cmd->se_cmd.prot_op = TARGET_PROT_DIN_STRIP;
			break;
		case SCST_DATA_NONE:
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		default:
			EXTRACHECKS_BUG_ON(dir);
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		}
		break;


	case SCST_DIF_ACTION_INSERT:
		switch (dir) {
		case SCST_DATA_READ:
			cmd->se_cmd.prot_op = TARGET_PROT_DOUT_INSERT;
			break;
		case SCST_DATA_WRITE:
			cmd->se_cmd.prot_op = TARGET_PROT_DIN_INSERT;
			break;
		case SCST_DATA_BIDI:
			if (xmit_rsp)
				cmd->se_cmd.prot_op = TARGET_PROT_DOUT_INSERT;
			else
				cmd->se_cmd.prot_op = TARGET_PROT_DIN_INSERT;
			break;
		case SCST_DATA_NONE:
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		default:
			EXTRACHECKS_BUG_ON(dir);
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		}
		break;


	case SCST_DIF_ACTION_PASS_CHECK:
		switch (dir) {
		case SCST_DATA_READ:
			cmd->se_cmd.prot_op = TARGET_PROT_DOUT_PASS;
			break;
		case SCST_DATA_WRITE:
			cmd->se_cmd.prot_op = TARGET_PROT_DIN_PASS;
			break;
		case SCST_DATA_BIDI:
			if (xmit_rsp) {
				cmd->se_cmd.prot_op = TARGET_PROT_DOUT_PASS;
			} else {
				cmd->se_cmd.prot_op = TARGET_PROT_DIN_PASS;
			}
			break;
		case SCST_DATA_NONE:
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		default:
			EXTRACHECKS_BUG_ON(dir);
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		}
		break;


	case SCST_DIF_ACTION_PASS: // nocheck
		switch (dir) {
		case SCST_DATA_READ:
		case SCST_DATA_WRITE:
		case SCST_DATA_BIDI:
			//cmd->prot_op = TARGET_PROT_PASS_NOCHECK; TODO
			//cmd->se_cmd.prot_op = TARGET_PROT_PASS_NOCHECK; TODO
			break;
		case SCST_DATA_NONE:
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		default:
			EXTRACHECKS_BUG_ON(dir);
			cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
			break;
		}
		break;


	default:
		cmd->se_cmd.prot_op = TARGET_PROT_NORMAL;
		EXTRACHECKS_BUG_ON(action);
		break;
	}
}

#endif	/* QLA_ENABLE_PI */

static void sqa_qla2xxx_rel_cmd(struct qla_tgt_cmd *cmd)
{
	struct fc_port *sess = cmd->sess;
	struct sqa_scst_tgt *sqa_tgt = sess->vha->vha_tgt.target_lport_ptr;

#if QLT_USE_PERCPU_IDA
	percpu_ida_free(&sqa_tgt->tgt_tag_pool, cmd->se_cmd.map_tag);
#elif QLT_USE_SBITMAP
	sbitmap_queue_clear(&sqa_tgt->tgt_tag_pool, cmd->se_cmd.map_tag,
			    cmd->se_cmd.map_cpu);
#else
	clear_bit(cmd->map_tag, sqa_tgt->tgt_tag_pool);
#endif
}

static struct qla_tgt_cmd *sqa_qla2xxx_get_cmd(struct fc_port *sess)
{
	struct sqa_scst_tgt *sqa_tgt =
		(struct sqa_scst_tgt *)sess->vha->vha_tgt.target_lport_ptr;
	struct qla_tgt_cmd *cmd;
	int tag = -ENOENT;

#if QLT_USE_PERCPU_IDA
	tag = percpu_ida_alloc(&sqa_tgt->tgt_tag_pool, TASK_RUNNING);
#elif QLT_USE_SBITMAP
	int cpu;

	tag = sbitmap_queue_get(&sqa_tgt->tgt_tag_pool, &cpu);
#else
	for (;;) {
		tag = find_first_zero_bit(sqa_tgt->tgt_tag_pool,
					  sqa_tgt->tag_num);
		if (test_and_set_bit(tag, sqa_tgt->tgt_tag_pool) == 0)
			break;
		if (tag >= sqa_tgt->tag_num) {
			tag = -ENOENT;
			break;
		}
	}
#endif
	if (tag < 0)
		return NULL;

	cmd = &((struct qla_tgt_cmd *)sqa_tgt->tgt_cmd_map)[tag];
	memset(cmd, 0, sizeof(struct qla_tgt_cmd));
#if QLT_USE_PERCPU_IDA || QLT_USE_SBITMAP
	cmd->se_cmd.map_tag = tag;
#else
	cmd->map_tag = tag;
#endif
#if QLT_USE_SBITMAP
	cmd->se_cmd.map_cpu = cpu;
#endif
	cmd->sess = sess;
	cmd->vha = sess->vha;
	return cmd;
}

static DEFINE_MUTEX(sqa_mutex);


/* Stub function for unimplemented functionality. */
static inline int scst_cmd_get_ppl_offset(struct scst_cmd *scst_cmd)
{
	return 0;
}

static int sqa_qla2xxx_handle_cmd(scsi_qla_host_t *vha,
	struct qla_tgt_cmd *cmd, unsigned char *cdb,
	uint32_t data_length, int task_codes,
	int data_dir, int bidi)
{
	int res = 0;
	struct fc_port *sess = cmd->sess;
	struct scst_session *scst_sess = (struct scst_session *)
		sess->se_sess->fabric_sess_ptr;
	struct atio_from_isp *atio = &cmd->atio;
	scst_data_direction dir;

	TRACE_ENTRY();
	TRACE_DBG("sqatgt(%ld/%d): Handling command: length=%d, fcp_task_attr=%d, direction=%d, bidirectional=%d lun=%llx cdb=%x tag=%d cmd %p ulpcmd %p\n",
		vha->host_no, vha->vp_idx, data_length, task_codes,
		data_dir, bidi, cmd->unpacked_lun,
		atio->u.isp24.fcp_cmnd.cdb[0],
		atio->u.isp24.exchange_addr, cmd, cmd->scst_cmd);


	cmd->scst_cmd = scst_rx_cmd(scst_sess,
		(uint8_t *)&atio->u.isp24.fcp_cmnd.lun,
		sizeof(atio->u.isp24.fcp_cmnd.lun),
		atio->u.isp24.fcp_cmnd.cdb,
		sizeof(atio->u.isp24.fcp_cmnd.cdb) +
		(atio->u.isp24.fcp_cmnd.add_cdb_len * 4),
		SCST_ATOMIC);

	if (cmd->scst_cmd == NULL) {
		PRINT_ERROR("sqatgt(%ld/%d): scst_rx_cmd function failed.",
			vha->host_no, vha->vp_idx);
		res = -EFAULT;
		goto out;
	}

	scst_cmd_set_tag(cmd->scst_cmd,
			 le32_to_cpu(atio->u.isp24.exchange_addr));
	scst_cmd_set_tgt_priv(cmd->scst_cmd, cmd);

	if (atio->u.isp24.fcp_cmnd.rddata && atio->u.isp24.fcp_cmnd.wrdata)
		dir = SCST_DATA_BIDI;
	else if (atio->u.isp24.fcp_cmnd.rddata)
		dir = SCST_DATA_READ;
	else if (atio->u.isp24.fcp_cmnd.wrdata)
		dir = SCST_DATA_WRITE;
	else
		dir = SCST_DATA_NONE;
	scst_cmd_set_expected(cmd->scst_cmd, dir, data_length);

	/* task_code fr arg list is based on TCM #define. */
	switch (atio->u.isp24.fcp_cmnd.task_attr) {
	case ATIO_SIMPLE_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case ATIO_HEAD_OF_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd,
			SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case ATIO_ORDERED_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd,
			SCST_CMD_QUEUE_ORDERED);
		break;
	case ATIO_ACA_QUEUE:
		scst_cmd_set_queue_type(cmd->scst_cmd,
			SCST_CMD_QUEUE_ACA);
		break;
	case ATIO_UNTAGGED:
		scst_cmd_set_queue_type(cmd->scst_cmd,
			SCST_CMD_QUEUE_UNTAGGED);
		break;
	default:
		PRINT_ERROR("sqatgt(%ld/%d): unknown task code %x, use ORDERED instead.",
			    vha->host_no, vha->vp_idx,
			    atio->u.isp24.fcp_cmnd.task_attr);
		scst_cmd_set_queue_type(cmd->scst_cmd,
			SCST_CMD_QUEUE_ORDERED);
		break;
	}

	TRACE(TRACE_SCSI,
	      "sqatgt(%ld/%d): START Command=%p tag=%d, queue type=%x",
	      vha->host_no, vha->vp_idx, cmd, cmd->atio.u.isp24.exchange_addr,
	      scst_cmd_get_queue_type(cmd->scst_cmd));

	scst_cmd_init_done(cmd->scst_cmd, scst_work_context);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void sqa_qla2xxx_handle_data(struct qla_tgt_cmd *cmd)
{
	struct scst_cmd *scst_cmd = cmd->scst_cmd;
	int rx_status;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&cmd->cmd_lock, flags);
	if (cmd->aborted) {
		spin_unlock_irqrestore(&cmd->cmd_lock, flags);

		scst_set_cmd_error(scst_cmd,
			SCST_LOAD_SENSE(scst_sense_internal_failure));
		scst_rx_data(scst_cmd, SCST_RX_STATUS_ERROR_SENSE_SET,
			SCST_CONTEXT_THREAD);
		return;
	}
	spin_unlock_irqrestore(&cmd->cmd_lock, flags);

	if (cmd->write_data_transferred) {
		rx_status = SCST_RX_STATUS_SUCCESS;
	} else {
		rx_status = SCST_RX_STATUS_ERROR_SENSE_SET;
		switch (cmd->dif_err_code) {
		case DIF_ERR_GRD:
			scst_dif_acc_guard_check_failed_tgt(scst_cmd);
			scst_set_cmd_error(scst_cmd,
				SCST_LOAD_SENSE(scst_logical_block_guard_check_failed));
			break;
		case DIF_ERR_REF:
			scst_dif_acc_ref_check_failed_tgt(scst_cmd);
			scst_set_cmd_error(scst_cmd,
				SCST_LOAD_SENSE(scst_logical_block_ref_tag_check_failed));
			break;
		case DIF_ERR_APP:
			scst_dif_acc_app_check_failed_tgt(scst_cmd);
			scst_set_cmd_error(scst_cmd,
				SCST_LOAD_SENSE(scst_logical_block_app_tag_check_failed));
			break;
		case DIF_ERR_NONE:
		default:
			scst_set_cmd_error(scst_cmd,
				SCST_LOAD_SENSE(scst_sense_aborted_command));
			break;
		}
	}

	/* Avoid using SCST_CONTEXT_DIRECT, the caller might hold qpair
	 * lock.  scst_rx_data(scst_context_direct) might call qlt_xmit_respond
	 * which will "re-grab" the qpair lock, creating a deadlock.
	 */
	scst_rx_data(scst_cmd, rx_status, scst_work_context);

	TRACE_EXIT();
}

static int sqa_qla2xxx_handle_tmr(struct qla_tgt_mgmt_cmd *mcmd, u64 lun,
				  uint16_t tmr_func, uint32_t tag)
{
	int res = 0, rc = -1, lun_size = sizeof(lun);
	struct fc_port *sess = mcmd->sess;
	struct scst_session *scst_sess = (struct scst_session *)
		sess->se_sess->fabric_sess_ptr;
	struct scsi_lun sl;

	TRACE_ENTRY();
	TRACE(TRACE_MGMT,
	      "sqatgt(%ld/%d): Received task management cmd: lun=%llu, type=%d, tag=%d\n",
	      sess->vha->host_no, sess->vha->vp_idx, lun, tmr_func, tag);

	mcmd->tmr_func = tmr_func;
	memset(&sl, 0, sizeof(sl));
	int_to_scsilun(lun, &sl);

	/*
	 * Call into SCST target core based on task management function
	 * type.
	 */
	switch (tmr_func) {
	case QLA_TGT_CLEAR_ACA: //TMR_CLEAR_ACA:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d) CLEAR_ACA received.",
		      sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_CLEAR_ACA,
					 &sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_TARGET_RESET: //TMR_TARGET_WARM_RESET:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d) TARGET_RESET received.",
		      sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_TARGET_RESET,
					 &sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_LUN_RESET: //TMR_LUN_RESET:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d) LUN_RESET received.",
			sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_LUN_RESET,
					 &sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_CLEAR_TS: //TMR_CLEAR_TASK_SET:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d) CLEAR_TS received.",
			sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_CLEAR_TASK_SET,
					 &sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_2G_ABORT_TASK:// TMR_ABORT_TASK:
	case QLA_TGT_ABTS:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d): TMR_ABORT_TASK received.",
			sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_tag(scst_sess, SCST_ABORT_TASK, tag,
					 SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_ABORT_TS:// TMR_ABORT_TASK_SET:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d) ABORT_TS received.",
			sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_ABORT_TASK_SET,
					 &sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_ABORT_ALL: // TMR_TARGET_COLD_RESET:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d): ABORT_ALL_TASKS received.",
			  sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_ABORT_ALL_TASKS,
			&sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_ABORT_ALL_SESS: //TMR_TARGET_ABORT_ALL:
		TRACE(TRACE_MGMT,
		      "sqatgt(%ld/%d): ABORT_ALL_TASKS_SESS received.",
		      sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_ABORT_ALL_TASKS_SESS,
			&sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_NEXUS_LOSS_SESS: //TMR_NEXUS_LOSS_SESSION:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d): NEXUS_LOSS_SESS received.",
		      sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_NEXUS_LOSS_SESS,
			&sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	case QLA_TGT_NEXUS_LOSS: //TMR_NEXUS_LOSS:
		TRACE(TRACE_MGMT, "sqatgt(%ld/%d): NEXUS_LOSS received.",
			sess->tgt->vha->host_no, sess->tgt->vha->vp_idx);
		rc = scst_rx_mgmt_fn_lun(scst_sess, SCST_NEXUS_LOSS,
			&sl, lun_size, SCST_ATOMIC, mcmd);
		break;

	default:
		PRINT_ERROR("sqatgt(%ld/%d): Unknown task mgmt fn=0x%x",
			    sess->tgt->vha->host_no, sess->tgt->vha->vp_idx,
			    tmr_func);
		res = -EFAULT;
		goto done;
	}

	if (rc != 0) {
		PRINT_ERROR("sqatgt(%ld/%d) scst_rx_mgmt_fn_lun() failed: tmf=%d, lun=%llu, code=%d",
			    sess->tgt->vha->host_no, sess->tgt->vha->vp_idx,
			    tmr_func, lun, rc);
		res = -EFAULT;
	}

done:
	TRACE_EXIT_RES(res);
	return res;
}

static struct qla_tgt_cmd *
sqa_qla2xxx_find_cmd_by_tag(struct fc_port *fcport, uint64_t tag)
{
	struct scst_session *sess = fcport->se_sess->fabric_sess_ptr;
	struct qla_tgt_cmd *qla_cmd = NULL;
	struct scst_cmd *cmd;
	unsigned long flags;

	spin_lock_irqsave(&sess->sess_list_lock, flags);
	list_for_each_entry(cmd, &sess->sess_cmd_list, sess_cmd_list_entry) {
		if (cmd->tag == tag) {
			qla_cmd = scst_cmd_get_tgt_priv(cmd);
			break;
		}
	}
	spin_unlock_irqrestore(&sess->sess_list_lock, flags);

	return qla_cmd;
}

static void sqa_qla2xxx_free_cmd(struct qla_tgt_cmd *cmd)
{
	struct scst_cmd *scst_cmd = cmd->scst_cmd;

	TRACE_ENTRY();

	cmd->trc_flags |= TRC_CMD_DONE;
	scst_tgt_cmd_done(scst_cmd, scst_work_context);

	TRACE_EXIT();
}


static void sqa_qla2xxx_free_mcmd(struct qla_tgt_mgmt_cmd *mcmd)
{
	TRACE_ENTRY();
	qlt_free_mcmd(mcmd);
	TRACE_EXIT();
}

static void sqa_free_session_done(struct scst_session *scst_sess)
{
	struct fc_port *fcport = scst_sess_get_tgt_priv(scst_sess);

	if (fcport->unreg_done)
		complete(fcport->unreg_done);
}

static void sqa_qla2xxx_free_session(struct fc_port *fcport)
{
	struct scsi_qla_host *vha = fcport->vha;
	struct se_session *se_sess = fcport->se_sess;
	struct scst_session *scst_sess = se_sess->fabric_sess_ptr;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("sqatgt(%ld/%d):	Deleting session %8phC fcid=%3phC\n",
		vha->host_no, vha->vp_idx, fcport->port_name, &fcport->d_id);

	{
		DECLARE_COMPLETION_ONSTACK(c);

		fcport->unreg_done = &c;
		scst_unregister_session(scst_sess, 1, sqa_free_session_done);
		wait_for_completion(&c);
	}

	TRACE_MGMT_DBG("sqatgt(%ld/%d):	Unregister completed %8phC done\n",
		vha->host_no, vha->vp_idx, fcport->port_name);

	kfree(se_sess);

	TRACE_EXIT();
}

static void sqa_qla2xxx_update_sess(struct fc_port *sess, port_id_t s_id,
	uint16_t loop_id, bool conf_compl_supported)
{
	TRACE_ENTRY();
	TRACE_EXIT();
}

static int sqa_qla2xxx_check_initiator_node_acl(scsi_qla_host_t *vha,
	unsigned char *fc_wwpn, struct fc_port *fcport)
{
	int res = -ENOMEM;
	char *ini_name;
	struct se_session *se_sess;
	struct scst_session *scst_sess;
	unsigned long flags;
	struct sqa_scst_tgt *sqa_tgt;

	TRACE_ENTRY();

	PRINT_INFO("sqatgt(%ld/%d): Registering initiator: pwwn=%8phC",
		   vha->host_no, vha->vp_idx, fc_wwpn);

	se_sess = kzalloc(sizeof(*se_sess), GFP_KERNEL);
	if (!se_sess)
		return res;

	/* Create the SCST session. */
	ini_name = kasprintf(GFP_KERNEL, "%8phC", fc_wwpn);
	if (!ini_name)
		goto free_sess;

	memcpy(fcport->port_name, fc_wwpn, sizeof(fcport->port_name));
	sqa_tgt = vha->vha_tgt.target_lport_ptr;

	res = -ESRCH;
	scst_sess = scst_register_session(sqa_tgt->scst_tgt, 0,
	    ini_name, fcport, NULL, NULL);
	if (scst_sess == NULL) {
		PRINT_ERROR("sqatgt(%ld/%d): SCST session registration failed, all commands will be refused: pwwn=%s",
			    vha->host_no, vha->vp_idx, ini_name);
		goto free_sess;
	}

	res = 0;

	spin_lock_irqsave(&vha->hw->tgt.sess_lock, flags);
	se_sess->fabric_sess_ptr = scst_sess;
	fcport->se_sess = se_sess;
	spin_unlock_irqrestore(&vha->hw->tgt.sess_lock, flags);

out:
	kfree(ini_name);

	TRACE_EXIT_RES(res);
	return res;

free_sess:
	kfree(se_sess);
	goto out;
}

static struct fc_port *sqa_qla2xxx_find_sess_by_s_id(scsi_qla_host_t *vha,
						     be_id_t s_id)
{
	struct fc_port *sess;

	TRACE_ENTRY();
#if 0
	TRACE_DBG("sqatgt(%ld/%d): Looking up session for fcid: 0x%02x%02x%02x\n",
		  vha->host_no, vha->vp_idx, s_id[0], s_id[1], s_id[2]);
#endif
	list_for_each_entry(sess, &vha->vp_fcports, list) {
		if (sess->d_id.b.al_pa == s_id.al_pa &&
		    sess->d_id.b.area == s_id.area &&
		    sess->d_id.b.domain == s_id.domain &&
		    !sess->deleted && sess->se_sess)
			return sess;
	}

	TRACE_EXIT();
	return NULL;
}

static struct fc_port *sqa_qla2xxx_find_sess_by_loop_id(scsi_qla_host_t *vha,
							const uint16_t loop_id)
{
	struct fc_port *sess;

	TRACE_ENTRY();
	TRACE_DBG("sqatgt(%ld/%d): Looking up session for loop id: 0x%04x\n",
		  vha->host_no, vha->vp_idx, loop_id);

	list_for_each_entry(sess, &vha->vp_fcports, list) {
		if (loop_id == sess->loop_id && !sess->deleted && sess->se_sess)
			return sess;
	}

	TRACE_EXIT();
	return NULL;
}

static void sqa_qla2xxx_clear_nacl_from_fcport_map(struct fc_port *sess)
{
	TRACE_ENTRY();

	TRACE_EXIT();
}

static void sqa_qla2xxx_release_sess(struct kref *kref)
{
	struct fc_port *fcport = container_of(kref, struct fc_port, sess_kref);

	qlt_unreg_sess(fcport);
}

static void sqa_qla2xxx_put_sess(struct fc_port *sess)
{
	TRACE_ENTRY();

	kref_put(&sess->sess_kref, sqa_qla2xxx_release_sess);

	TRACE_EXIT();
}

static int sqa_close_session(struct scst_session *scst_sess)
{
	struct fc_port *fcport = scst_sess_get_tgt_priv(scst_sess);
	unsigned long flags;
	struct qla_hw_data *ha = fcport->vha->hw;

	fcport->explicit_logout = 1;

	spin_lock_irqsave(&ha->tgt.sess_lock, flags);
	sqa_qla2xxx_put_sess(fcport);
	spin_unlock_irqrestore(&ha->tgt.sess_lock, flags);
	return 0;
}


static void sqa_qla2xxx_shutdown_sess(struct fc_port *sess)
{
	TRACE_ENTRY();
	TRACE_EXIT();
}


/*
 * sysfs functions from here forward.
 */

static ssize_t sqa_version_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	ssize_t ret = 0;

	ret += sysfs_emit_at(buf, ret, "INTERFACE=%s\nSCST=%s\nQLOGIC=%s\n",
			     SQA_VERSION, SCST_VERSION_NAME, QLA2XXX_VERSION);

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

#ifdef CONFIG_QLA_TGT_DEBUG_SRR
	ret += sysfs_emit_at(buf, ret, "DEBUG_SRR\n");
#endif

	TRACE_EXIT();
	return ret;
}

static ssize_t sqa_hw_target_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);

	tgt = sqa_tgt->qla_tgt;

	return sysfs_emit(buf, "%d\n", tgt->vha->vp_idx == 0 ? 1 : 0);
}

static ssize_t sqa_node_name_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;
	struct qla_hw_data *ha;
	ssize_t res = -ENOMEM;
	char *wwn;
	uint8_t *node_name;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);

	mutex_lock(&sqa_mutex);
	if (!sqa_tgt || !sqa_tgt->qla_tgt) {
		mutex_unlock(&sqa_mutex);
		goto out;
	}
	mutex_unlock(&sqa_mutex);

	tgt = sqa_tgt->qla_tgt;
	ha = tgt->ha;

	if (qla_tgt_mode_enabled(tgt->vha) || qla_dual_mode_enabled(tgt->vha) ||
		!ha->tgt.node_name_set)
		node_name = tgt->vha->node_name;
	else
		node_name = ha->tgt.tgt_node_name;

	res = sqa_get_target_name(node_name, &wwn);
	if (res != 0)
		goto out;

	res = sysfs_emit(buf, "%s\n", wwn);

	if (ha->tgt.node_name_set)
		res += sysfs_emit_at(buf, res, "%s\n", SCST_SYSFS_KEY_MARK);

	kfree(wwn);

out:
	return res;
}

static ssize_t sqa_node_name_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;
	struct qla_hw_data *ha;
	u64 node_name, old_node_name;
	int res;

	TRACE_ENTRY();

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;
	ha = tgt->ha;

	if (size == 0)
		goto out_default;

	res = sqa_parse_wwn(buffer, &node_name);
	if (res != 0) {
		if ((buffer[0] == '\0') || (buffer[0] == '\n'))
			goto out_default;
		PRINT_ERROR("sqatgt(%ld/%d) Wrong node name",
			    tgt->vha->host_no, tgt->vha->vp_idx);
		goto out;
	}

	old_node_name = wwn_to_u64(tgt->vha->node_name);
	if (old_node_name == node_name)
		goto out_success;

	u64_to_wwn(node_name, ha->tgt.tgt_node_name);
	ha->tgt.node_name_set = 1;

abort:
	/*
	 * A substitute is needed for the following code sequence which
	 * was previously used within the following conditional:
	 *
	 *	set_bit(ISP_ABORT_NEEDED, &tgt->vha->dpc_flags);
	 *	qla2x00_wait_for_hba_online(tgt->vha);
	 *
	 * The substitute used will be to gracefully shutdown the
	 * target with subsequent restart.
	 */
	if (qla_tgt_mode_enabled(tgt->vha) ||
		qla_dual_mode_enabled(tgt->vha)) {
		qlt_stop_phase1(tgt);
		qlt_stop_phase2(tgt);
		qlt_enable_vha(tgt->vha);
	}

out_success:
	res = size;

out:
	TRACE_EXIT_RES(res);
	return res;

out_default:
	ha->tgt.node_name_set = 0;
	goto abort;
}

#if EXCLUDED
static ssize_t sqa_vp_parent_host_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;
	struct qla_hw_data *ha;
	ssize_t res;
	char *wwn;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;
	ha = tgt->ha;

	res = sqa_get_target_name(tgt->vha->port_name, &wwn);
	if (res != 0)
		goto out;

	res = sysfs_emit(buf, "%s\n%s\n", wwn, SCST_SYSFS_KEY_MARK);

	kfree(wwn);

out:
	return res;
}
#endif

static ssize_t sqa_show_expl_conf_enabled(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buffer)
{
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;
	struct qla_hw_data *ha;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;
	ha = tgt->ha;

	return sysfs_emit(buffer, "%d\n%s",
			  ha->base_qpair->enable_explicit_conf,
			  ha->base_qpair->enable_explicit_conf ?
			  SCST_SYSFS_KEY_MARK "\n" : "");
}

static ssize_t sqa_store_expl_conf_enabled(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;
	struct qla_hw_data *ha;
	struct scsi_qla_host *vha;
	unsigned long flags;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;
	ha = tgt->ha;
	vha = tgt->vha;

	spin_lock_irqsave(&ha->hardware_lock, flags);

	switch (buffer[0]) {
	case '0':
		QLA_DIS_CONF(ha);
		PRINT_INFO("sqatgt(%ld/%d) explicit conformations disabled",
			vha->host_no, vha->vp_idx);
		break;
	case '1':
		QLA_ENA_CONF(ha)
		PRINT_INFO("sqatgt(%ld/%d) explicit conformations enabled",
			vha->host_no, vha->vp_idx);
		break;
	default:
		PRINT_ERROR("sqatgt(%ld/%d): Requested action not understood: %s",
			    vha->host_no, vha->vp_idx, buffer);
		break;
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return size;
}

static ssize_t sqa_abort_isp_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buffer, size_t size)
{
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;

	TRACE_ENTRY();

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;

	PRINT_INFO("sqatgt(%ld/%d) ISP abort not implemented.",
		   tgt->vha->host_no, tgt->vha->vp_idx);

	TRACE_EXIT();
	return -ENOSYS;

#if EXCLUDED
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;
	struct qla_hw_data *ha;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;
	ha = tgt->ha;

	PRINT_INFO("sqatgt(%ld/%d) Aborting ISP.", tgt->vha->host_no,
		   tgt->vha->vp_idx);

	set_bit(ISP_ABORT_NEEDED, &tgt->vha->dpc_flags);
	WARN_ON_ONCE(qla2x00_wait_for_hba_online(tgt->vha) != QLA_SUCCESS);

	return size;
#endif
}

static int sqa_get_target_name(uint8_t *wwn, char **ppwwn_name)
{
	*ppwwn_name = kasprintf(GFP_KERNEL,
				"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
				wwn[0], wwn[1], wwn[2], wwn[3],
				wwn[4], wwn[5], wwn[6], wwn[7]);

	return *ppwwn_name ? 0 : -ENOMEM;
}

static int sqa_parse_wwn(const char *ns, u64 *nm)
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

/*
 * The following structure definition provides descriptive parameeters
 * and callbacks which will be used by the SCST target core to
 * communicate with this target interface driver.
 */
static struct scst_tgt_template sqa_scst_template = {
	.name			= "qla2x00t",
	.sg_tablesize			= 0,
	.use_clustering			= 1,
#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	.xmit_response_atomic		= 0,
	.rdy_to_xfer_atomic		= 0,
#else
	.xmit_response_atomic		= 1,
	.rdy_to_xfer_atomic		= 1,
#endif

#if QLA_ENABLE_PI
/* diff cap for individual adapter is set during sqa_qla2xxx_add_target */
	.dif_supported			 = 0,
	.hw_dif_type1_supported		 = 0,
	.hw_dif_type2_supported		 = 0,
	.hw_dif_type3_supported		 = 0,
	.hw_dif_ip_supported		 = 0,
	.hw_dif_same_sg_layout_required	 = 0,
#endif

	.max_hw_pending_time		 = SQA_MAX_HW_PENDING_TIME,
	.release			 = sqa_target_release,

	.xmit_response			 = sqa_xmit_response,
	.rdy_to_xfer			 = sqa_rdy_to_xfer,

	.on_free_cmd			 = sqa_on_free_cmd,
	.task_mgmt_fn_done		 = sqa_task_mgmt_fn_done,
	.close_session			 = sqa_close_session,

	.get_initiator_port_transport_id = sqa_get_initiator_port_transport_id,
	.get_scsi_transport_version	 = sqa_get_scsi_transport_version,
	.get_phys_transport_version	 = sqa_get_phys_transport_version,
	.on_hw_pending_cmd_timeout	 = sqa_on_hw_pending_cmd_timeout,
	.enable_target			 = sqa_enable_tgt,
	.is_target_enabled		 = sqa_is_tgt_enabled,
	.add_target			 = sqa_add_vtarget,
	.del_target			 = sqa_del_vtarget,
	.add_target_parameters		 = "node_name, parent_host",
	.tgtt_attrs			 = sqa_attrs,
	.tgt_attrs			 = sqa_tgt_attrs,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags		 = SQA_DEFAULT_LOG_FLAGS,
	.trace_flags			 = &trace_flag,
#endif
};

/* call must hold sqa_mutex */
static int sqa_init_scst_tgt(struct scsi_qla_host *vha)
{
	char *pwwn = NULL;
	int res;
	struct scst_tgt *scst_tgt;
	struct sqa_scst_tgt *sqa_tgt;
	uint tag_num = vha->hw->orig_fw_xcb_count ? vha->hw->orig_fw_xcb_count :
		SQA_DEFAULT_TAGS;
	u16 tag_size = sizeof(struct qla_tgt_cmd);

	TRACE_ENTRY();

	res = sqa_get_target_name(vha->port_name, &pwwn);
	if (res)
		goto done;

	sqa_tgt = kzalloc(sizeof(*sqa_tgt), GFP_KERNEL);
	if (!sqa_tgt) {
		PRINT_ERROR("sqatgt(%ld/%d): alloc sqa_tgt failed",
		    vha->host_no, vha->vp_idx);
		res = -ENOMEM;
		goto done;
	}

	sqa_tgt->tgt_cmd_map = kvcalloc(tag_num, tag_size, GFP_KERNEL);
	if (!sqa_tgt->tgt_cmd_map) {
		PRINT_ERROR("sqatgt(%ld/%d): alloc tgt_cmd_map failed",
			    vha->host_no, vha->vp_idx);
		kfree(sqa_tgt);
		res = -ENOMEM;
		goto done;
	}

#if QLT_USE_PERCPU_IDA
	res = percpu_ida_init(&sqa_tgt->tgt_tag_pool, tag_num);
#elif QLT_USE_SBITMAP
	res = sbitmap_queue_init_node(&sqa_tgt->tgt_tag_pool, tag_num, -1,
				      false, GFP_KERNEL, NUMA_NO_NODE);
#else
	sqa_tgt->tag_num = tag_num;
	sqa_tgt->tgt_tag_pool = kzalloc(BITS_TO_LONGS(tag_num), GFP_KERNEL);
	res = PTR_ERR_OR_ZERO(sqa_tgt->tgt_tag_pool);
#endif
	if (res < 0) {
		pr_err("Unable to init se_sess->tgt_tag_pool, tag_num: %u\n",
		       tag_num);
		kvfree(sqa_tgt->tgt_cmd_map);
		kfree(sqa_tgt);
		goto done;
	}

	PRINT_INFO("sqatgt(%ld/%d): Registering target pwwn=%s",
		   vha->host_no, vha->vp_idx, pwwn);

	scst_tgt = scst_register_target(&sqa_scst_template, pwwn);
	if (!scst_tgt) {
		PRINT_ERROR("sqatgt(%ld/%d): SCST target registration failed.",
			    vha->host_no, vha->vp_idx);
		res = -ENOMEM;
		kfree(sqa_tgt);
		goto done;
	}

#if QLA_ENABLE_PI
	if (IS_T10_PI_CAPABLE(vha->hw)) {
		scst_tgt_set_supported_dif_block_sizes(scst_tgt,
					qla_tgt_supported_dif_block_size);
		scst_tgt_set_dif_supported(scst_tgt, true);
		scst_tgt_set_hw_dif_type1_supported(scst_tgt, true);
		scst_tgt_set_hw_dif_type3_supported(scst_tgt, true);
	}
#endif
	INIT_LIST_HEAD(&sqa_tgt->list);
	sqa_tgt->scst_tgt = scst_tgt;
	sqa_tgt->qla_tgt = vha->vha_tgt.qla_tgt;

	scst_tgt_set_tgt_priv(scst_tgt, sqa_tgt);
	scst_tgt_set_sg_tablesize(scst_tgt,
				  vha->vha_tgt.qla_tgt->sg_tablesize);

	res = sysfs_create_link(scst_sysfs_get_tgt_kobj(scst_tgt),
				&vha->host->shost_dev.kobj, "host");
	if (res != 0)
		PRINT_ERROR("sqatgt(%ld/%d) Unable to create \"host\" link for, target=%s",
			    vha->host_no, vha->vp_idx,
			    scst_get_tgt_name(scst_tgt));

	res = sysfs_create_file(scst_sysfs_get_tgt_kobj(scst_tgt),
				&sqa_hw_target_attr.attr);
	if (res != 0)
		PRINT_ERROR("sqatgt(%ld/%dd) Unable to create \"hw_target\" file, target=%s",
			    vha->host_no, vha->vp_idx,
			    scst_get_tgt_name(scst_tgt));

	res = sysfs_create_file(scst_sysfs_get_tgt_kobj(scst_tgt),
				&sqa_hw_node_name_attr.attr);
	if (res != 0)
		PRINT_ERROR("sqatgt(%ld/%d) Unable to create \"node_name\" file for HW target %s",
			    vha->host_no, vha->vp_idx,
			    scst_get_tgt_name(scst_tgt));

	list_add_tail(&sqa_tgt->list, &sqa_tgt_glist);
	TRACE(TRACE_MGMT, "sqatgt(%ld/%d): Registering target pwwn=%s scst_tgt %p sqa_tgt %p",
	    vha->host_no, vha->vp_idx, pwwn, scst_tgt, sqa_tgt);
done:
	kfree(pwwn);
	return res;
}

static void sqa_get_target_list(void)
{
	struct qla_tgt *tgt;
	struct scsi_qla_host *vha;

	mutex_lock(&sqa_mutex);
	list_for_each_entry(tgt, &qla_tgt_glist, tgt_list_entry) {
		vha = tgt->vha;
		sqa_init_scst_tgt(vha);
	}
	mutex_unlock(&sqa_mutex);
}


static void sqa_qla2xxx_add_target(struct scsi_qla_host *vha)
{
	if (!vha) {
		dump_stack();
		return;
	}

	TRACE_ENTRY();

	PRINT_INFO("sqatgt: add target %8phC", vha->port_name);

	if (!vha->vha_tgt.target_lport_ptr) {
		mutex_lock(&sqa_mutex);
		sqa_init_scst_tgt(vha);
		mutex_unlock(&sqa_mutex);
	}

	TRACE_EXIT();
}

static void sqa_qla2xxx_remove_target(struct scsi_qla_host *vha)
{
	struct sqa_scst_tgt *sqa_tgt =
		(struct sqa_scst_tgt *)vha->vha_tgt.target_lport_ptr;

	TRACE_ENTRY();
	TRACE(TRACE_MGMT, "Unregistering target for host %ld(%p)",
	    vha->host_no, vha);
	scst_unregister_target(sqa_tgt->scst_tgt);
	TRACE_EXIT();
}

static void sqa_qla2xxx_drop_lport(struct qla_tgt *tgt)
{
	struct scsi_qla_host *vha = tgt->vha;

	TRACE_ENTRY();

	if (vha->vha_tgt.qla_tgt->tgt_stop &&
			!vha->vha_tgt.qla_tgt->tgt_stopped) {
		PRINT_INFO("sqatgt(%ld/%d): calling qlt_stop_phase2.\n",
				vha->host_no, vha->vp_idx);
		qlt_stop_phase2(vha->vha_tgt.qla_tgt);
	}

	qlt_lport_deregister(vha);

	TRACE_EXIT();
}

static void sqa_qla2xxx_npiv_drop_lport(struct qla_tgt *tgt)
{
	struct scsi_qla_host *npiv_vha = tgt->vha;
	struct qla_hw_data *ha = npiv_vha->hw;
	scsi_qla_host_t *base_vha = pci_get_drvdata(ha->pdev);

	TRACE_ENTRY();

	scsi_host_put(npiv_vha->host);
	scsi_host_put(base_vha->host);

	TRACE_EXIT();
}

/*
 * Must be called under tgt_host_action_mutex or sqa_unreg_rwsem write
 * locked.
 */
static int sqa_target_release(struct scst_tgt *scst_tgt)
{
	struct sqa_scst_tgt *sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	struct qla_tgt *tgt = sqa_tgt->qla_tgt;
	struct scsi_qla_host *vha = tgt->vha;

	TRACE_ENTRY();

	if (vha->vha_tgt.target_lport_ptr) {

		if (!vha->vha_tgt.qla_tgt->tgt_stop &&
				!vha->vha_tgt.qla_tgt->tgt_stopped) {
			PRINT_INFO("sqatgt(%ld:%d: calling qlt_stop_phase1.\n",
					vha->host_no, vha->vp_idx);
			qlt_stop_phase1(vha->vha_tgt.qla_tgt);
		}

		if (vha->vp_idx)
			sqa_qla2xxx_npiv_drop_lport(tgt);
		else
			sqa_qla2xxx_drop_lport(tgt);
	}

	scst_tgt_set_tgt_priv(scst_tgt, NULL);

	mutex_lock(&sqa_mutex);
	sqa_tgt->qla_tgt = NULL;
	list_del(&sqa_tgt->list);
	mutex_unlock(&sqa_mutex);

	TRACE(TRACE_MGMT, "sqatgt(%ld/%d): Target release finished sqa_tgt %p",
	    vha->host_no, vha->vp_idx, sqa_tgt);

	kfree(sqa_tgt);

	TRACE_EXIT();
	return 0;
}

static int sqa_xmit_response(struct scst_cmd *scst_cmd)
{
	int xmit_type = QLA_TGT_XMIT_DATA, res, residual = 0;
	int is_send_status = scst_cmd_get_is_send_status(scst_cmd);
	struct qla_tgt_cmd *cmd;

	TRACE_ENTRY();
	cmd = scst_cmd_get_tgt_priv(scst_cmd);

	if (scst_cmd_aborted_on_xmit(scst_cmd)) {
		TRACE_MGMT_DBG("sqatgt(%ld/%d): CMD_ABORTED cmd[%p]",
			cmd->vha->host_no, cmd->vha->vp_idx,
			cmd);
		qlt_abort_cmd(cmd);
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);
		scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_DIRECT);
		return SCST_TGT_RES_SUCCESS;
	}

#ifdef CONFIG_SCST_EXTRACHECKS
	BUG_ON(cmd->bufflen > 0 && !is_send_status);
#endif
#ifdef CONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
	EXTRACHECKS_BUG_ON(scst_cmd_atomic(scst_cmd));
#endif
	if (is_send_status) {
		const u8 *const sense_buf = scst_cmd_get_sense_buffer(scst_cmd);
		u16 len = scst_cmd_get_sense_buffer_len(scst_cmd);

		xmit_type |= QLA_TGT_XMIT_STATUS;
		if (QLA_TGT_SENSE_VALID(sense_buf)) {
			if (len > TRANSPORT_SENSE_BUFFER || len == 0)
				len = TRANSPORT_SENSE_BUFFER;
			memcpy(cmd->sense_buffer, sense_buf, len);
		}
	}

	cmd->bufflen = scst_cmd_get_adjusted_resp_data_len(scst_cmd);
	cmd->sg = scst_cmd_get_sg(scst_cmd);
	cmd->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	cmd->dma_data_direction =
		scst_to_tgt_dma_dir(scst_cmd_get_data_direction(scst_cmd));
	cmd->offset = scst_cmd_get_ppl_offset(scst_cmd);
	cmd->scsi_status = scst_cmd_get_status(scst_cmd);
	cmd->cdb = (unsigned char *) scst_cmd_get_cdb(scst_cmd);
	cmd->lba = scst_cmd_get_lba(scst_cmd);
	cmd->trc_flags |= TRC_XMIT_STATUS;

#if QLA_ENABLE_PI
	if (scst_get_tgt_dif_actions(scst_cmd->cmd_dif_actions)) {
		cmd->blk_sz = scst_cmd_get_block_size(scst_cmd);
		cmd->prot_sg_cnt = scst_cmd->dif_sg_cnt;
		cmd->prot_sg = scst_cmd->dif_sg;
		cmd->se_cmd.prot_type = scst_cmd_get_dif_prot_type(scst_cmd);

		qla_tgt_set_cmd_prot_op(cmd, true);

		TRACE_DBG("cmd[%p] ulpcmd[%p] dif_actions=0x%x, cdb=0x%x, prot_sg[%p] prot_sg_cnt[%x], prot_type[%x] prot_op[%x]",
			  cmd, cmd->scst_cmd, scst_cmd->cmd_dif_actions,
			  scst_cmd->cdb_buf[0], cmd->prot_sg, cmd->prot_sg_cnt,
			  cmd->se_cmd.prot_type, cmd->se_cmd.prot_op);

		if ((cmd->se_cmd.prot_op == TARGET_PROT_DIN_INSERT) &&
			(!cmd->prot_sg_cnt || !cmd->prot_sg)) {
			PRINT_ERROR("qla2x00t(%ld): %s: DIN Insert w/out DIF buf[%p:%d]",
				    cmd->vha->host_no, __func__, cmd->prot_sg,
				    cmd->prot_sg_cnt);
		}
	}
#endif

	/* SCST residual is opposite of qla
	 * scst : + = under, - = over
	 */
	if (scst_get_resid(scst_cmd, &residual, NULL)) {
		TRACE_DBG("sqatgt(%ld/%d): Have residual, count=%d",
				  cmd->vha->host_no, cmd->vha->vp_idx, residual);
		if (residual > 0)
			cmd->se_cmd.se_cmd_flags |= SCF_UNDERFLOW_BIT;
		if (residual < 0) {
			cmd->se_cmd.se_cmd_flags |= SCF_OVERFLOW_BIT;
			residual = -residual;
		}
		cmd->se_cmd.residual_count = residual;
	}


	TRACE_DBG("sqatgt(%ld/%d): is_send_status=%x, bufflen=%d, sg_cnt=%d, flipped dma_direction=%d resid=%d",
		  cmd->vha->host_no, cmd->vha->vp_idx, is_send_status,
		  cmd->bufflen, cmd->sg_cnt, cmd->dma_data_direction,
		  cmd->se_cmd.residual_count);

	res = qlt_xmit_response(cmd, xmit_type, scst_cmd_get_status(scst_cmd));

	switch (res) {
	case 0:
		res = SCST_TGT_RES_SUCCESS;
		break;

	case -EAGAIN:
		res = SCST_TGT_RES_QUEUE_FULL;
		break;
	default:
		res = SCST_TGT_RES_FATAL_ERROR;
		break;
	}

	TRACE_EXIT();
	return res;
}

static int sqa_rdy_to_xfer(struct scst_cmd *scst_cmd)
{
	int res;
	struct qla_tgt_cmd *cmd;

	TRACE_ENTRY();
	cmd = scst_cmd_get_tgt_priv(scst_cmd);

	TRACE(TRACE_SCSI, "sqatgt(%ld/%d): tag=%lld", cmd->vha->host_no,
	      cmd->vha->vp_idx, scst_cmd_get_tag(scst_cmd));

	cmd->bufflen = scst_cmd_get_write_fields(scst_cmd, &cmd->sg,
						 &cmd->sg_cnt);
	cmd->dma_data_direction =
		scst_to_tgt_dma_dir(scst_cmd_get_data_direction(scst_cmd));

	cmd->cdb = scst_cmd_get_cdb(scst_cmd);
	cmd->sg = scst_cmd_get_sg(scst_cmd);
	cmd->sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
	cmd->scsi_status = scst_cmd_get_status(scst_cmd);
	cmd->trc_flags |= TRC_XFR_RDY;

#if QLA_ENABLE_PI
	if (scst_get_tgt_dif_actions(scst_cmd->cmd_dif_actions)) {
		cmd->blk_sz    = scst_cmd_get_block_size(scst_cmd);
		cmd->se_cmd.prot_type = scst_cmd_get_dif_prot_type(scst_cmd);
		cmd->prot_sg_cnt = scst_cmd->dif_sg_cnt;
		cmd->prot_sg = scst_cmd->dif_sg;
		/* translate dif_actions to prot_op */
		qla_tgt_set_cmd_prot_op(cmd, false);

		TRACE_DBG("%s: cmd[%p] ulpcmd[%p] dif_actions=0x%x, cdb=0x%x, prot_sg_cnt[%x], prot_type[%x] prot_op[%x], bufflen[%x]",
			  __func__, cmd, cmd->scst_cmd,
			  scst_cmd->cmd_dif_actions, scst_cmd->cdb_buf[0],
			  cmd->prot_sg_cnt, cmd->se_cmd.prot_type,
			  cmd->se_cmd.prot_op, cmd->bufflen);
}
#endif
	/*
	 * Call the destination function in the low-level-driver and
	 * translate the return code into a value which can be
	 * interpreted by the SCST target core.
	 */
	res = qlt_rdy_to_xfer(cmd);
	switch (res) {
	case 0:
		res = SCST_TGT_RES_SUCCESS;
		break;
	case -EAGAIN:
		res = SCST_TGT_RES_QUEUE_FULL;
		break;
	default:
		res = SCST_TGT_RES_FATAL_ERROR;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}


static void sqa_on_free_cmd(struct scst_cmd *scst_cmd)
{
	struct qla_tgt_cmd *cmd = scst_cmd_get_tgt_priv(scst_cmd);

	TRACE_ENTRY();

	TRACE(TRACE_SCSI, "sqatgt(%ld/%d): Freeing command %p: tag=%lld",
		cmd->vha->host_no, cmd->vha->vp_idx, scst_cmd,
		scst_cmd_get_tag(scst_cmd));
	cmd->trc_flags |= TRC_CMD_FREE;

	/* free resource below. */
	qlt_free_cmd(cmd);

	TRACE_EXIT();
}

static uint32_t sqa_convert_to_fc_tm_status(int scst_mstatus)
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
static void sqa_task_mgmt_fn_done(struct scst_mgmt_cmd *scst_mcmd)
{
	struct qla_tgt_mgmt_cmd *mcmd;
	struct scsi_qla_host *vha;

	TRACE_ENTRY();

	mcmd = scst_mgmt_cmd_get_tgt_priv(scst_mcmd);
	if (unlikely(mcmd == NULL)) {
		PRINT_ERROR("sqatgt: Null target pointer for SCST task management, command=%p",
			    scst_mcmd);
		goto out;
	}

	vha = mcmd->sess->vha;
	TRACE_MGMT_DBG("sqatgt(%ld/%d):	scst_mcmd %p status %#x state %#x; mcmd %p flags %x\n",
		       vha->host_no, vha->vp_idx, scst_mcmd, scst_mcmd->status,
		       scst_mcmd->state, mcmd, mcmd->flags);

	TRACE_MGMT_DBG("sqatgt(%ld/%d): scst_mcmd (%p) status %#x state %#x",
		       vha->host_no, vha->vp_idx, scst_mcmd,
		       scst_mcmd->status, scst_mcmd->state);

	mcmd->fc_tm_rsp = sqa_convert_to_fc_tm_status(
				scst_mgmt_cmd_get_status(scst_mcmd));
	qlt_xmit_tm_rsp(mcmd);

out:
	TRACE_EXIT();
}

static int sqa_get_initiator_port_transport_id(struct scst_tgt *tgt,
					       struct scst_session *scst_sess,
					       uint8_t **transport_id)
{
	struct fc_port *sess;
	int res = 0;
	int tr_id_size;
	uint8_t *tr_id;

	TRACE_ENTRY();

	if (scst_sess == NULL) {
		res = SCSI_TRANSPORTID_PROTOCOLID_FCP2;
		goto out;
	}

	sess = scst_sess_get_tgt_priv(scst_sess);
	if (sess == NULL) {
		res = SCSI_TRANSPORTID_PROTOCOLID_FCP2;
		goto out;
	}

	TRACE_DBG("sqatgt(%ld/%d): Creating transport id: target session=%p, initiator=%8phC, fcid=%3phC, loop=0x%04x",
		sess->vha->host_no, sess->vha->vp_idx, sess,
		sess->port_name, &sess->d_id.b, sess->loop_id);

	tr_id_size = 24;
	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (tr_id == NULL) {
		PRINT_ERROR("sqatgt(%ld/%d): Allocation of TransportID size=%d failed.",
			    sess->vha->host_no, sess->vha->vp_idx, tr_id_size);
		res = -ENOMEM;
		goto out;
	}

	tr_id[0] = SCSI_TRANSPORTID_PROTOCOLID_FCP2;

	BUILD_BUG_ON(sizeof(sess->port_name) != 8);
	memcpy(&tr_id[8], sess->port_name, 8);
	*transport_id = tr_id;
	TRACE_DBG("sqatgt(%ld/%d): Created tid.", sess->vha->host_no,
		  sess->vha->vp_idx);
	TRACE_BUFF_FLAG(TRACE_DEBUG, "tid buffer", tr_id, tr_id_size);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static uint16_t sqa_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	/* FCP-2 */
	return 0x0900;
}

static uint16_t sqa_get_phys_transport_version(struct scst_tgt *scst_tgt)
{
	/* FC-FS */
	return 0x0DA0;
}

static int sqa_qla2xxx_chk_dif_tags(uint32_t tag)
{
	return tag & SCST_DIF_CHECK_REF_TAG;
}

static int sqa_qla2xxx_dif_tags(struct qla_tgt_cmd *cmd,
				uint16_t *pfw_prot_opts)
{
	struct scst_cmd *scst_cmd = cmd->scst_cmd;
	uint32_t t32 = 0;

	t32 = scst_get_dif_checks(scst_cmd->cmd_dif_actions);
	if (!(t32 & SCST_DIF_CHECK_GUARD_TAG))
		*pfw_prot_opts |= PO_DISABLE_GUARD_CHECK;

	if (!(t32 & SCST_DIF_CHECK_APP_TAG))
		*pfw_prot_opts |= PO_DIS_APP_TAG_VALD;

	return t32;
}

static void sqa_cleanup_hw_pending_cmd(scsi_qla_host_t *vha,
	struct qla_tgt_cmd *cmd)
{
	uint32_t h;
	struct qla_qpair *qpair = cmd->qpair;

	for (h = 1; h < qpair->req->num_outstanding_cmds; h++) {
		if (qpair->req->outstanding_cmds[h] == (srb_t *)cmd) {
			printk(KERN_INFO "Clearing handle %d for cmd %p", h,
			       cmd);
			//TRACE_DBG("Clearing handle %d for cmd %p", h, cmd);
			qpair->req->outstanding_cmds[h] = NULL;
			break;
		}
	}
}

static void sqa_on_hw_pending_cmd_timeout(struct scst_cmd *scst_cmd)
{
	struct qla_tgt_cmd *cmd = scst_cmd_get_tgt_priv(scst_cmd);
	struct scsi_qla_host *vha = cmd->vha;
	struct qla_qpair *qpair = cmd->qpair;
	uint8_t aborted = cmd->aborted;
	unsigned long flags;

	TRACE_ENTRY();
	TRACE_MGMT_DBG("sqatgt(%ld/%d): Cmd %p HW pending for too long (state %s) %s; %s;",
		       vha->host_no, vha->vp_idx, cmd,
		       cmdstate_to_str((uint8_t)cmd->state),
		       cmd->cmd_sent_to_fw ? "sent to fw" : "not sent to fw",
		       aborted ? "aborted" : "not aborted");


	qlt_abort_cmd(cmd);

	spin_lock_irqsave(qpair->qp_lock_ptr, flags);
	switch (cmd->state) {
	case QLA_TGT_STATE_NEW:
	case QLA_TGT_STATE_DATA_IN:
		PRINT_ERROR("sqa(%ld): A command in state (%s) should not be HW pending. %s",
			vha->host_no, cmdstate_to_str((uint8_t)cmd->state),
			aborted ? "aborted" : "not aborted");
		break;

	case QLA_TGT_STATE_NEED_DATA:
		/* the abort will nudge it out of FW */
		TRACE_MGMT_DBG("Force rx_data cmd %p", cmd);
		sqa_cleanup_hw_pending_cmd(vha, cmd);
		scst_set_cmd_error(scst_cmd,
		    SCST_LOAD_SENSE(scst_sense_internal_failure));
		scst_rx_data(scst_cmd, SCST_RX_STATUS_ERROR_SENSE_SET,
		    SCST_CONTEXT_THREAD);
		break;
	case QLA_TGT_STATE_PROCESSED:
		if (!cmd->cmd_sent_to_fw)
			PRINT_ERROR("sqa(%ld): command should not be in HW pending. It's already processed. ",
				    vha->host_no);
		else
			TRACE_MGMT_DBG("Force finishing cmd %p", cmd);
		sqa_cleanup_hw_pending_cmd(vha, cmd);
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
		scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_THREAD);
		break;
	}
	spin_unlock_irqrestore(qpair->qp_lock_ptr, flags);

	TRACE_EXIT();
}

/*
 * The following structure defines the callbacks which will be executed
 * from functions in the qla_target.c file back to this interface
 * driver.
 */
static struct qla_tgt_func_tmpl sqa_qla2xxx_template = {
	.handle_cmd		    = sqa_qla2xxx_handle_cmd,
	.handle_data		    = sqa_qla2xxx_handle_data,
	.handle_tmr		    = sqa_qla2xxx_handle_tmr,
	.find_cmd_by_tag	    = sqa_qla2xxx_find_cmd_by_tag,
	.get_cmd		    = sqa_qla2xxx_get_cmd,
	.rel_cmd		    = sqa_qla2xxx_rel_cmd,
	.free_cmd		    = sqa_qla2xxx_free_cmd,
	.free_mcmd		    = sqa_qla2xxx_free_mcmd,
	.free_session		    = sqa_qla2xxx_free_session,
	.update_sess		    = sqa_qla2xxx_update_sess,
	.check_initiator_node_acl   = sqa_qla2xxx_check_initiator_node_acl,
	.find_sess_by_s_id	    = sqa_qla2xxx_find_sess_by_s_id,
	.find_sess_by_loop_id	    = sqa_qla2xxx_find_sess_by_loop_id,
	.clear_nacl_from_fcport_map = sqa_qla2xxx_clear_nacl_from_fcport_map,
	.put_sess		    = sqa_qla2xxx_put_sess,
	.shutdown_sess		    = sqa_qla2xxx_shutdown_sess,
	.get_dif_tags		    = sqa_qla2xxx_dif_tags,
	.chk_dif_tags		    = sqa_qla2xxx_chk_dif_tags,
	.add_target		    = sqa_qla2xxx_add_target,
	.remove_target		    = sqa_qla2xxx_remove_target,
};

static int sqa_lport_callback(struct scsi_qla_host *vha,
	void *target_lport_ptr, u64 npiv_wwpn, u64 npiv_wwnn)

{
	struct qla_hw_data *ha = vha->hw;

	TRACE_ENTRY();

	ha->tgt.tgt_ops = &sqa_qla2xxx_template;
	vha->vha_tgt.target_lport_ptr = target_lport_ptr;

	TRACE_EXIT();
	return 0;
}

static int sqa_enable_tgt(struct scst_tgt *scst_tgt, bool enable)
{
	struct sqa_scst_tgt *sqa_tgt;
	struct qla_tgt *tgt;
	struct scsi_qla_host *vha;
	int rc;

	TRACE_ENTRY();

	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;
	vha = tgt->vha;
	if (enable && (qla_tgt_mode_enabled(tgt->vha) ||
		qla_dual_mode_enabled(tgt->vha))) {
		PRINT_INFO("sqatgt(%ld/%d): Target already enabled.",
			   vha->host_no, vha->vp_idx);
		return -EINVAL;
	}
	if (!enable && (!qla_tgt_mode_enabled(vha) &&
		!qla_dual_mode_enabled(vha))) {
		PRINT_INFO("sqatgt(%ld/%d): Target already disabled.",
			   vha->host_no, vha->vp_idx);
		return -EINVAL;
	}

	PRINT_INFO("sqatgt(%ld/%d): %s target pwwn=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		   vha->host_no, vha->vp_idx, enable ? "Enabling" : "Disabling",
		   vha->port_name[0], vha->port_name[1],
		   vha->port_name[2], vha->port_name[3],
		   vha->port_name[4], vha->port_name[5],
		   vha->port_name[6], vha->port_name[7]);

	if (enable) {
		qlt_lport_register(sqa_tgt, wwn_to_u64(vha->port_name),
		    0, 0, sqa_lport_callback);
		qlt_enable_vha(vha);
	} else {
		rc = qlt_stop_phase1(tgt);
		if (!rc)
			qlt_stop_phase2(tgt);
	}

	TRACE_EXIT();
	return 0;
}

static bool sqa_is_tgt_enabled(struct scst_tgt *scst_tgt)
{
	int res;
	struct qla_tgt *tgt;
	struct sqa_scst_tgt *sqa_tgt;

	TRACE_ENTRY();
	sqa_tgt = scst_tgt_get_tgt_priv(scst_tgt);
	tgt = sqa_tgt->qla_tgt;
	res = qla_tgt_mode_enabled(tgt->vha) || qla_dual_mode_enabled(tgt->vha);

	TRACE_EXIT();
	return res;
}

static ssize_t sqa_add_vtarget(const char *target_name, char *params)
{
	int res;
	char *param, *p, *pp;
	u64 port_name, node_name;
	u64 parent_host;
	u64 pnode_name = 0, pparent_host = 0;

	TRACE_ENTRY();

	res = sqa_parse_wwn(target_name, &port_name);
	if (res) {
		PRINT_ERROR("sqatgt: Syntax error at target name %s",
			target_name);
		goto out;
	}

	while (1) {
		param = scst_get_next_token_str(&params);
		if (param == NULL)
			break;

		p = scst_get_next_lexem(&param);
		if (*p == '\0') {
			PRINT_ERROR("sqatgt: Syntax error at %s (target %s)",
				param, target_name);
			res = -EINVAL;
			goto out;
		}

		pp = scst_get_next_lexem(&param);
		if (*pp == '\0') {
			PRINT_ERROR("sqatgt: Parameter %s value missed for target %s",
				    p, target_name);
			res = -EINVAL;
			goto out;
		}

		if (scst_get_next_lexem(&param)[0] != '\0') {
			PRINT_ERROR("sqatgt: Too many parameter's %s values (target %s)",
				    p, target_name);
			res = -EINVAL;
			goto out;
		}

		if (!strcasecmp("node_name", p)) {
			res = sqa_parse_wwn(pp, &node_name);
			if (res) {
				PRINT_ERROR("sqatgt: Illegal node_name %s (target %s)",
					    pp, target_name);
				res = -EINVAL;
				goto out;
			}
			pnode_name = node_name;
			continue;
		}

		if (!strcasecmp("parent_host", p)) {
			res = sqa_parse_wwn(pp, &parent_host);
			if (res != 0) {
				PRINT_ERROR("sqatgt: Illegal parent_host %s (target %s)",
					    pp, target_name);
				goto out;
			}
			pparent_host = parent_host;
			continue;
		}

		PRINT_ERROR("sqatgt: Unknown parameter %s (target %s)", p,
			target_name);
		res = -EINVAL;
		goto out;
	}

	if (!pnode_name) {
		PRINT_ERROR("sqatgt: Missing parameter node_name (target %s)",
			target_name);
		res = -EINVAL;
		goto out;
	}

	if (!pparent_host) {
		PRINT_ERROR("sqatgt: Missing parameter parent_host (target %s)",
			    target_name);
		res = -EINVAL;
		goto out;
	}

	res = qlt_add_vtarget(port_name, pnode_name, pparent_host);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t sqa_del_vtarget(const char *target_name)
{
	int res;
	u64 port_name;

	TRACE_ENTRY();

	res = sqa_parse_wwn(target_name, &port_name);
	if (res) {
		PRINT_ERROR("sqatgt: Syntax error at target name %s",
			target_name);
		goto out;
	}

	res = qlt_del_vtarget(port_name);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int __init sqa_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	PRINT_INFO("sqatgt: Initializing SCST Cavium adapter target driver interface - driver version=%s, SCST version=%s, Cavium version=%s",
		   SQA_VERSION, SCST_VERSION_NAME, QLA2XXX_VERSION);

	res = scst_register_target_template(&sqa_scst_template);

	if (res) {
		PRINT_ERROR("sqatgt: fail to register template.");
		goto out;
	}

	sqa_get_target_list();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void __exit sqa_exit(void)
{
	struct sqa_scst_tgt *sqa_tgt, *t;
	struct scsi_qla_host *vha;

	TRACE_ENTRY();
	PRINT_INFO("sqatgt: Unloading SCST Cavium adapter target driver interface.");

	list_for_each_entry_safe(sqa_tgt, t, &sqa_tgt_glist, list) {
		vha = sqa_tgt->qla_tgt->vha;
		if (vha->vp_idx) {
			/* qla driver will not allow a physical host
			 * to be stopped if there's an Npiv host still
			 * active. If the NPIV host is not taken down,
			 * the scst_unregister_target_template call will
			 * hang.  It assumes various cleanup has already
			 * taken place.
			 */
			PRINT_INFO("sqatgt: Stopping NPIV host%ld.\n",
				vha->host_no);

			qlt_stop_phase1(sqa_tgt->qla_tgt);
			qlt_del_vtarget(wwn_to_u64(vha->port_name));
		}
	}

	list_for_each_entry_safe(sqa_tgt, t, &sqa_tgt_glist, list) {
		vha = sqa_tgt->qla_tgt->vha;
		if (!vha->vp_idx) {
			PRINT_INFO("sqatgt: Stopping host%ld.\n",
				vha->host_no);

			qlt_stop_phase1(sqa_tgt->qla_tgt);
			scst_unregister_target(sqa_tgt->scst_tgt);
		}
	}

	scst_unregister_target_template(&sqa_scst_template);

	TRACE_EXIT();
}

#ifdef MODULE
module_init(sqa_init);
module_exit(sqa_exit);
#else
late_initcall(sqa_init);
#endif

MODULE_DESCRIPTION("SCST Cavium adapter target interface driver.");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(SCST_NAMESPACE);
MODULE_IMPORT_NS(SCST_QLA32_NAMESPACE);
MODULE_VERSION(SQA_VERSION);
