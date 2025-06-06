/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2011 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"
#include "qla_gbl.h"

#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
#include <linux/list.h>

#include <scsi/scsi_tcq.h>
#include <scsi/scsicam.h>
#include <linux/delay.h>

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
#include "qla2x_tgt.h"
#endif

#undef DEFAULT_SYMBOL_NAMESPACE
#define DEFAULT_SYMBOL_NAMESPACE	SCST_QLA16_NAMESPACE

void
qla2x00_vp_stop_timer(scsi_qla_host_t *vha)
{
	if (vha->vp_idx && vha->timer_active) {
		timer_delete_sync(&vha->timer);
		vha->timer_active = 0;
	}
}

static uint32_t
qla24xx_allocate_vp_id(scsi_qla_host_t *vha)
{
	uint32_t vp_id;
	struct qla_hw_data *ha = vha->hw;
	unsigned long flags;

	/* Find an empty slot and assign an vp_id */
	mutex_lock(&ha->vport_lock);
	vp_id = find_first_zero_bit(ha->vp_idx_map, ha->max_npiv_vports + 1);
	if (vp_id > ha->max_npiv_vports) {
		ql_dbg(ql_dbg_vport, vha, 0xa000,
		    "vp_id %d is bigger than max-supported %d.\n",
		    vp_id, ha->max_npiv_vports);
		mutex_unlock(&ha->vport_lock);
		return vp_id;
	}

	set_bit(vp_id, ha->vp_idx_map);
	ha->num_vhosts++;
	vha->vp_idx = vp_id;

	spin_lock_irqsave(&ha->vport_slock, flags);
	list_add_tail(&vha->list, &ha->vp_list);
	spin_unlock_irqrestore(&ha->vport_slock, flags);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	ha->tgt_vp_map[vp_id].vha = vha;
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */
	mutex_unlock(&ha->vport_lock);
	return vp_id;
}

void
qla24xx_deallocate_vp_id(scsi_qla_host_t *vha)
{
	uint16_t vp_id;
	struct qla_hw_data *ha = vha->hw;
	unsigned long flags = 0;

	mutex_lock(&ha->vport_lock);
	/*
	 * Wait for all pending activities to finish before removing vport from
	 * the list.
	 * Lock needs to be held for safe removal from the list (it
	 * ensures no active vp_list traversal while the vport is removed
	 * from the queue)
	 */
	spin_lock_irqsave(&ha->vport_slock, flags);
	while (atomic_read(&vha->vref_count)) {
		spin_unlock_irqrestore(&ha->vport_slock, flags);

		msleep(500);

		spin_lock_irqsave(&ha->vport_slock, flags);
	}
	list_del(&vha->list);
	spin_unlock_irqrestore(&ha->vport_slock, flags);

	vp_id = vha->vp_idx;
	ha->num_vhosts--;
	clear_bit(vp_id, ha->vp_idx_map);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	ha->tgt_vp_map[vp_id].vha = NULL;
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */
	mutex_unlock(&ha->vport_lock);
}

static scsi_qla_host_t *
qla24xx_find_vhost_by_name(struct qla_hw_data *ha, uint8_t *port_name)
{
	scsi_qla_host_t *vha;
	struct scsi_qla_host *tvha;
	unsigned long flags;

	spin_lock_irqsave(&ha->vport_slock, flags);
	/* Locate matching device in database. */
	list_for_each_entry_safe(vha, tvha, &ha->vp_list, list) {
		if (!memcmp(port_name, vha->port_name, WWN_SIZE)) {
			spin_unlock_irqrestore(&ha->vport_slock, flags);
			return vha;
		}
	}
	spin_unlock_irqrestore(&ha->vport_slock, flags);
	return NULL;
}

/*
 * qla2x00_mark_vp_devices_dead
 *	Updates fcport state when device goes offline.
 *
 * Input:
 *	ha = adapter block pointer.
 *	fcport = port structure pointer.
 *
 * Return:
 *	None.
 *
 * Context:
 */
static void
qla2x00_mark_vp_devices_dead(scsi_qla_host_t *vha)
{
	/*
	 * !!! NOTE !!!
	 * This function, if called in contexts other than vp create, disable
	 * or delete, please make sure this is synchronized with the
	 * delete thread.
	 */
	fc_port_t *fcport;

	list_for_each_entry_rcu(fcport, &vha->vp_fcports, list) {
		ql_dbg(ql_dbg_vport, vha, 0xa001,
		    "Marking port dead, loop_id=0x%04x : %x.\n",
		    fcport->loop_id, fcport->vha->vp_idx);

		qla2x00_mark_device_lost(vha, fcport, 0, 0);
		qla2x00_set_fcport_state(fcport, FCS_UNCONFIGURED);
	}
}

static int
__qla24xx_init_vp(scsi_qla_host_t *vha, int status)
{
	atomic_set(&vha->loop_state, LOOP_DOWN);
	atomic_set(&vha->loop_down_timer, LOOP_DOWN_TIME);
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	/* Remove port id from vp target map */
	vha->hw->tgt_vp_map[vha->d_id.b.al_pa].idx = 0;
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

	/* Delete all vp's fcports from parent's list */
	qla2x00_mark_vp_devices_dead(vha);
	atomic_set(&vha->vp_state, VP_FAILED);
	vha->flags.management_server_logged_in = 0;
	if (status == QLA_SUCCESS) {
		fc_vport_set_state(vha->fc_vport, FC_VPORT_DISABLED);
	} else {
		fc_vport_set_state(vha->fc_vport, FC_VPORT_FAILED);
		return -1;
	}
	return 0;
}

int
qla24xx_init_vp(scsi_qla_host_t *vha)
{
	struct qla_hw_data *ha = vha->hw;
	struct scsi_qla_host *base_vha = pci_get_drvdata(ha->pdev);
	/*
	 * When we are initing a virtual initiator port, it's a good idea to
	 * disable it at first to clean up all possible residues from another
	 * life of this virtual port on another physical port. But for virtual
	 * target port it's a pretty bad idea, because it can make initiators
	 * think that this port gone, hence disable it and fail all running IO.
	 *
	 * But this virtual port can be new in this place, so we might be not
	 * able to know if it's going to be initiator or target port. So,
	 * let's ask its parent as well, because good targets don't have
	 * initiator mode enabled anywhere.
	 */
	if (qla_ini_mode_enabled(base_vha))
		return qla24xx_disable_vp(vha);
	else
		return __qla24xx_init_vp(vha, QLA_SUCCESS);
}

int
qla24xx_disable_vp(scsi_qla_host_t *vha)
{
	int ret;

	ret = qla24xx_control_vp(vha, VCE_COMMAND_DISABLE_VPS_LOGO_ALL);
	__qla24xx_init_vp(vha, ret);
	if (ret != QLA_SUCCESS)
		return -1;
	else
		return 0;
}
EXPORT_SYMBOL(qla24xx_disable_vp);

int
qla24xx_enable_vp(scsi_qla_host_t *vha)
{
	int ret;
	struct qla_hw_data *ha = vha->hw;
	scsi_qla_host_t *base_vha = pci_get_drvdata(ha->pdev);

	/* Check if physical ha port is Up */
	if (atomic_read(&base_vha->loop_state) == LOOP_DOWN  ||
		atomic_read(&base_vha->loop_state) == LOOP_DEAD ||
		!(ha->current_topology & ISP_CFG_F)) {
		vha->vp_err_state = VP_ERR_PORTDWN;
		fc_vport_set_state(vha->fc_vport, FC_VPORT_LINKDOWN);
		goto enable_failed;
	}

	/* Initialize the new vport unless it is a persistent port */
	mutex_lock(&ha->vport_lock);
	ret = qla24xx_modify_vp_config(vha);
	mutex_unlock(&ha->vport_lock);

	if (ret != QLA_SUCCESS) {
		fc_vport_set_state(vha->fc_vport, FC_VPORT_FAILED);
		goto enable_failed;
	}

	ql_dbg(ql_dbg_taskm, vha, 0x801a,
	    "Virtual port with id: %d - Enabled.\n", vha->vp_idx);
	return 0;

enable_failed:
	ql_dbg(ql_dbg_taskm, vha, 0x801b,
	    "Virtual port with id: %d - Disabled.\n", vha->vp_idx);
	return 1;
}
EXPORT_SYMBOL(qla24xx_enable_vp);

static void
qla24xx_configure_vp(scsi_qla_host_t *vha)
{
	struct fc_vport *fc_vport;
	int ret;

	fc_vport = vha->fc_vport;

	/* Target mode has own handling */
	if (qla_ini_mode_enabled(vha)) {
		ql_dbg(ql_dbg_vport, vha, 0xa002,
		    "%s: change request #3.\n", __func__);
		ret = qla2x00_send_change_request(vha, 0x3, vha->vp_idx);
		if (ret != QLA_SUCCESS) {
			ql_dbg(ql_dbg_vport, vha, 0xa003, "Failed to enable "
			    "receiving of RSCN requests: 0x%x.\n", ret);
			return;
		} else {
			/* Corresponds to SCR enabled */
			clear_bit(VP_SCR_NEEDED, &vha->vp_flags);
		}
	}

	vha->flags.online = 1;
	if (qla24xx_configure_vhba(vha))
		return;

	atomic_set(&vha->vp_state, VP_ACTIVE);
	fc_vport_set_state(fc_vport, FC_VPORT_ACTIVE);
}

void
qla2x00_alert_all_vps(struct rsp_que *rsp, uint16_t *mb)
{
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha = rsp->hw;
	int i = 0;
	unsigned long flags;

	spin_lock_irqsave(&ha->vport_slock, flags);
	list_for_each_entry(vha, &ha->vp_list, list) {
		if (vha->vp_idx) {
			atomic_inc(&vha->vref_count);
			spin_unlock_irqrestore(&ha->vport_slock, flags);

			switch (mb[0]) {
			case MBA_LIP_OCCURRED:
			case MBA_LOOP_UP:
			case MBA_LOOP_DOWN:
			case MBA_LIP_RESET:
			case MBA_POINT_TO_POINT:
			case MBA_CHG_IN_CONNECTION:
			case MBA_PORT_UPDATE:
			case MBA_RSCN_UPDATE:
				ql_dbg(ql_dbg_async, vha, 0x5024,
				    "Async_event for VP[%d], mb=0x%x vha=%p.\n",
				    i, *mb, vha);
				qla2x00_async_event(vha, rsp, mb);
				break;
			}

			spin_lock_irqsave(&ha->vport_slock, flags);
			atomic_dec(&vha->vref_count);
		}
		i++;
	}
	spin_unlock_irqrestore(&ha->vport_slock, flags);
}

int
qla2x00_vp_abort_isp(scsi_qla_host_t *vha)
{
	int ret;
	struct qla_hw_data *ha = vha->hw;
	struct scsi_qla_host *base_vha = pci_get_drvdata(ha->pdev);
	/*
	 * Physical port will do most of the abort and recovery work. We can
	 * just treat it as a loop down
	 */
	if (atomic_read(&vha->loop_state) != LOOP_DOWN) {
		atomic_set(&vha->loop_state, LOOP_DOWN);
		qla2x00_mark_all_devices_lost(vha, 0);
	} else {
		if (!atomic_read(&vha->loop_down_timer))
			atomic_set(&vha->loop_down_timer, LOOP_DOWN_TIME);
	}

	/*
	 * To exclusively reset vport, we need to log it out first.  Note: this
	 * control_vp can fail if ISP reset is already issued, this is
	 * expected, as the vp would be already logged out due to ISP reset.
	 */
	if (!test_bit(ABORT_ISP_ACTIVE, &vha->dpc_flags))
		qla24xx_control_vp(vha, VCE_COMMAND_DISABLE_VPS_LOGO_ALL);

	/* See comment in qla24xx_init_vp() */
	if (qla_ini_mode_enabled(base_vha)) {
		ql_dbg(ql_dbg_taskm, vha, 0x801d,
		    "Scheduling enable of Vport %d.\n", vha->vp_idx);
		ret = qla24xx_enable_vp(vha);
	} else
		ret = QLA_SUCCESS;
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	/* Enable target response to SCSI bus. */
	if (qla_tgt_mode_enabled(vha))
		qla2x00_send_enable_lun(vha, true);
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */
	return ret;
}

static int
qla2x00_do_dpc_vp(scsi_qla_host_t *vha)
{
	ql_dbg(ql_dbg_dpc + ql_dbg_verbose, vha, 0x4012,
	    "Entering %s vp_flags: 0x%lx.\n", __func__, vha->vp_flags);

	qla2x00_do_work(vha);

	if (test_and_clear_bit(VP_IDX_ACQUIRED, &vha->vp_flags)) {
		/* VP acquired. complete port configuration */
		ql_dbg(ql_dbg_dpc, vha, 0x4014,
		    "Configure VP scheduled.\n");
		qla24xx_configure_vp(vha);
		ql_dbg(ql_dbg_dpc, vha, 0x4015,
		    "Configure VP end.\n");
		return 0;
	}

	if (test_bit(FCPORT_UPDATE_NEEDED, &vha->dpc_flags)) {
		ql_dbg(ql_dbg_dpc, vha, 0x4016,
		    "FCPort update scheduled.\n");
		qla2x00_update_fcports(vha);
		clear_bit(FCPORT_UPDATE_NEEDED, &vha->dpc_flags);
		ql_dbg(ql_dbg_dpc, vha, 0x4017,
		    "FCPort update end.\n");
	}

	if ((test_and_clear_bit(RELOGIN_NEEDED, &vha->dpc_flags)) &&
		!test_bit(LOOP_RESYNC_NEEDED, &vha->dpc_flags) &&
		atomic_read(&vha->loop_state) != LOOP_DOWN) {

		ql_dbg(ql_dbg_dpc, vha, 0x4018,
		    "Relogin needed scheduled.\n");
		qla2x00_relogin(vha);
		ql_dbg(ql_dbg_dpc, vha, 0x4019,
		    "Relogin needed end.\n");
	}

	if (test_and_clear_bit(RESET_MARKER_NEEDED, &vha->dpc_flags) &&
	    (!(test_and_set_bit(RESET_ACTIVE, &vha->dpc_flags)))) {
		clear_bit(RESET_ACTIVE, &vha->dpc_flags);
	}

	if (test_and_clear_bit(LOOP_RESYNC_NEEDED, &vha->dpc_flags)) {
		if (!(test_and_set_bit(LOOP_RESYNC_ACTIVE, &vha->dpc_flags))) {
			ql_dbg(ql_dbg_dpc, vha, 0x401a,
			    "Loop resync scheduled.\n");
			qla2x00_loop_resync(vha);
			clear_bit(LOOP_RESYNC_ACTIVE, &vha->dpc_flags);
			ql_dbg(ql_dbg_dpc, vha, 0x401b,
			    "Loop resync end.\n");
		}
	}

	ql_dbg(ql_dbg_dpc + ql_dbg_verbose, vha, 0x401c,
	    "Exiting %s.\n", __func__);
	return 0;
}

void
qla2x00_do_dpc_all_vps(scsi_qla_host_t *vha)
{
	struct qla_hw_data *ha = vha->hw;
	scsi_qla_host_t *vp;
	unsigned long flags = 0;

	if (vha->vp_idx)
		return;
	if (list_empty(&ha->vp_list))
		return;

	clear_bit(VP_DPC_NEEDED, &vha->dpc_flags);

	if (!(ha->current_topology & ISP_CFG_F))
		return;

	spin_lock_irqsave(&ha->vport_slock, flags);
	list_for_each_entry(vp, &ha->vp_list, list) {
		if (vp->vp_idx) {
			atomic_inc(&vp->vref_count);
			spin_unlock_irqrestore(&ha->vport_slock, flags);

			qla2x00_do_dpc_vp(vp);

			spin_lock_irqsave(&ha->vport_slock, flags);
			atomic_dec(&vp->vref_count);
		}
	}
	spin_unlock_irqrestore(&ha->vport_slock, flags);
}

int
qla24xx_vport_create_req_sanity_check(struct fc_vport *fc_vport)
{
	scsi_qla_host_t *base_vha = shost_priv(fc_vport->shost);
	struct qla_hw_data *ha = base_vha->hw;
	scsi_qla_host_t *vha;
	uint8_t port_name[WWN_SIZE];

#ifndef CONFIG_SCSI_QLA2XXX_TARGET
	if (fc_vport->roles != FC_PORT_ROLE_FCP_INITIATOR)
		return VPCERR_UNSUPPORTED;
#endif

	/* Check up the F/W and H/W support NPIV */
	if (!ha->flags.npiv_supported)
		return VPCERR_UNSUPPORTED;

#if 0 /* we might not configured it yet */
	/* Check up whether npiv supported switch presented */
	if (!(ha->switch_cap & FLOGI_MID_SUPPORT))
		return VPCERR_NO_FABRIC_SUPP;
#endif

	/* Check up unique WWPN */
	u64_to_wwn(fc_vport->port_name, port_name);
	if (!memcmp(port_name, base_vha->port_name, WWN_SIZE))
		return VPCERR_BAD_WWN;
	vha = qla24xx_find_vhost_by_name(ha, port_name);
	if (vha)
		return VPCERR_BAD_WWN;

	/* Check up max-npiv-supports */
	if (ha->num_vhosts > ha->max_npiv_vports) {
		printk("scsi(%ld): num_vhosts %ud is bigger "
		    "than max_npiv_vports %ud.\n", base_vha->host_no,
		    ha->num_vhosts, ha->max_npiv_vports);
		return VPCERR_UNSUPPORTED;
	}
	return 0;
}

scsi_qla_host_t *
qla24xx_create_vhost(struct fc_vport *fc_vport)
{
	scsi_qla_host_t *base_vha = shost_priv(fc_vport->shost);
	struct qla_hw_data *ha = base_vha->hw;
	scsi_qla_host_t *vha;
	const struct scsi_host_template *sht = &qla2xxx_driver_template;
	struct Scsi_Host *host;

	vha = qla2x00_create_host(sht, ha);
	if (!vha) {
		ql_log(ql_log_warn, vha, 0xa005,
		    "scsi_host_alloc() failed for vport.\n");
		return NULL;
	}

	host = vha->host;
	fc_vport->dd_data = vha;
	/* New host info */
	u64_to_wwn(fc_vport->node_name, vha->node_name);
	u64_to_wwn(fc_vport->port_name, vha->port_name);

	vha->fc_vport = fc_vport;
	vha->device_flags = 0;
	vha->vp_idx = qla24xx_allocate_vp_id(vha);
	if (vha->vp_idx > ha->max_npiv_vports) {
		ql_dbg(ql_dbg_vport, vha, 0xa006,
		    "Couldn't allocate vp_id.\n");
		goto create_vhost_failed;
	}
	vha->mgmt_svr_loop_id = 10 + vha->vp_idx;

	vha->dpc_flags = 0L;

	/*
	 * To fix the issue of processing a parent's RSCN for the vport before
	 * its SCR is complete.
	 */
	set_bit(VP_SCR_NEEDED, &vha->vp_flags);
	atomic_set(&vha->loop_state, LOOP_DOWN);
	atomic_set(&vha->loop_down_timer, LOOP_DOWN_TIME);

	qla2x00_start_timer(vha, qla2x00_timer, WATCH_INTERVAL);

	vha->req = base_vha->req;
	host->can_queue = base_vha->req->length + 128;
	host->this_id = 255;
	host->cmd_per_lun = 3;
	if (IS_T10_PI_CAPABLE(ha) && ql2xenabledif)
		host->max_cmd_len = 32;
	else
		host->max_cmd_len = MAX_CMDSZ;
	host->max_channel = MAX_BUSES - 1;
	host->max_lun = ql2xmaxlun;
	host->unique_id = host->host_no;
	host->max_id = ha->max_fibre_devices;
	host->transportt = qla2xxx_transport_vport_template;

	ql_dbg(ql_dbg_vport, vha, 0xa007,
	    "Detect vport hba %ld at address = %p.\n",
	    vha->host_no, vha);

	vha->flags.init_done = 1;

	mutex_lock(&ha->vport_lock);
	set_bit(vha->vp_idx, ha->vp_idx_map);
	ha->cur_vport_count++;
	mutex_unlock(&ha->vport_lock);

	return vha;

create_vhost_failed:
	return NULL;
}

static void
qla25xx_free_req_que(struct scsi_qla_host *vha, struct req_que *req)
{
	struct qla_hw_data *ha = vha->hw;
	uint16_t que_id = req->id;

	dma_free_coherent(&ha->pdev->dev, (req->length + 1) *
		sizeof(request_t), req->ring, req->dma);
	req->ring = NULL;
	req->dma = 0;
	if (que_id) {
		ha->req_q_map[que_id] = NULL;
		mutex_lock(&ha->vport_lock);
		clear_bit(que_id, ha->req_qid_map);
		mutex_unlock(&ha->vport_lock);
	}
	kfree(req);
	req = NULL;
}

static void
qla25xx_free_rsp_que(struct scsi_qla_host *vha, struct rsp_que *rsp)
{
	struct qla_hw_data *ha = vha->hw;
	uint16_t que_id = rsp->id;

	if (rsp->msix && rsp->msix->have_irq) {
		free_irq(rsp->msix->vector, rsp);
		rsp->msix->have_irq = 0;
		rsp->msix->rsp = NULL;
	}
	dma_free_coherent(&ha->pdev->dev, (rsp->length + 1) *
		sizeof(response_t), rsp->ring, rsp->dma);
	rsp->ring = NULL;
	rsp->dma = 0;
	if (que_id) {
		ha->rsp_q_map[que_id] = NULL;
		mutex_lock(&ha->vport_lock);
		clear_bit(que_id, ha->rsp_qid_map);
		mutex_unlock(&ha->vport_lock);
	}
	kfree(rsp);
	rsp = NULL;
}

int
qla25xx_delete_req_que(struct scsi_qla_host *vha, struct req_que *req)
{
	int ret = -1;

	if (req) {
		req->options |= BIT_0;
		ret = qla25xx_init_req_que(vha, req);
	}
	if (ret == QLA_SUCCESS)
		qla25xx_free_req_que(vha, req);

	return ret;
}

static int
qla25xx_delete_rsp_que(struct scsi_qla_host *vha, struct rsp_que *rsp)
{
	int ret = -1;

	if (rsp) {
		rsp->options |= BIT_0;
		ret = qla25xx_init_rsp_que(vha, rsp);
	}
	if (ret == QLA_SUCCESS)
		qla25xx_free_rsp_que(vha, rsp);

	return ret;
}

/* Delete all queues for a given vhost */
int
qla25xx_delete_queues(struct scsi_qla_host *vha)
{
	int cnt, ret = 0;
	struct req_que *req = NULL;
	struct rsp_que *rsp = NULL;
	struct qla_hw_data *ha = vha->hw;

	/* Delete request queues */
	for (cnt = 1; cnt < ha->max_req_queues; cnt++) {
		req = ha->req_q_map[cnt];
		if (req) {
			ret = qla25xx_delete_req_que(vha, req);
			if (ret != QLA_SUCCESS) {
				ql_log(ql_log_warn, vha, 0x00ea,
				    "Couldn't delete req que %d.\n",
				    req->id);
				return ret;
			}
		}
	}

	/* Delete response queues */
	for (cnt = 1; cnt < ha->max_rsp_queues; cnt++) {
		rsp = ha->rsp_q_map[cnt];
		if (rsp) {
			ret = qla25xx_delete_rsp_que(vha, rsp);
			if (ret != QLA_SUCCESS) {
				ql_log(ql_log_warn, vha, 0x00eb,
				    "Couldn't delete rsp que %d.\n",
				    rsp->id);
				return ret;
			}
		}
	}
	return ret;
}

int
qla25xx_create_req_que(struct qla_hw_data *ha, uint16_t options,
	uint8_t vp_idx, uint16_t rid, int rsp_que, uint8_t qos)
{
	int ret = 0;
	struct req_que *req = NULL;
	struct scsi_qla_host *base_vha = pci_get_drvdata(ha->pdev);
	uint16_t que_id = 0;
	uint32_t cnt;

	req = kzalloc(sizeof(struct req_que), GFP_KERNEL);
	if (req == NULL) {
		ql_log(ql_log_fatal, base_vha, 0x00d9,
		    "Failed to allocate memory for request queue.\n");
		goto failed;
	}

	req->length = REQUEST_ENTRY_CNT_24XX;
	req->ring = dma_alloc_coherent(&ha->pdev->dev,
			(req->length + 1) * sizeof(request_t),
			&req->dma, GFP_KERNEL);
	if (req->ring == NULL) {
		ql_log(ql_log_fatal, base_vha, 0x00da,
		    "Failed to allocate memory for request_ring.\n");
		goto que_failed;
	}

	mutex_lock(&ha->vport_lock);
	que_id = find_first_zero_bit(ha->req_qid_map, ha->max_req_queues);
	if (que_id >= ha->max_req_queues) {
		mutex_unlock(&ha->vport_lock);
		ql_log(ql_log_warn, base_vha, 0x00db,
		    "No resources to create additional request queue.\n");
		goto que_failed;
	}
	set_bit(que_id, ha->req_qid_map);
	ha->req_q_map[que_id] = req;
	req->rid = rid;
	req->vp_idx = vp_idx;
	req->qos = qos;

	ql_dbg(ql_dbg_multiq, base_vha, 0xc002,
	    "queue_id=%d rid=%d vp_idx=%d qos=%d.\n",
	    que_id, req->rid, req->vp_idx, req->qos);
	ql_dbg(ql_dbg_init, base_vha, 0x00dc,
	    "queue_id=%d rid=%d vp_idx=%d qos=%d.\n",
	    que_id, req->rid, req->vp_idx, req->qos);
	if (rsp_que < 0)
		req->rsp = NULL;
	else
		req->rsp = ha->rsp_q_map[rsp_que];
	/* Use alternate PCI bus number */
	if (MSB(req->rid))
		options |= BIT_4;
	/* Use alternate PCI devfn */
	if (LSB(req->rid))
		options |= BIT_5;
	req->options = options;

	ql_dbg(ql_dbg_multiq, base_vha, 0xc003,
	    "options=0x%x.\n", req->options);
	ql_dbg(ql_dbg_init, base_vha, 0x00dd,
	    "options=0x%x.\n", req->options);
	for (cnt = 1; cnt < MAX_OUTSTANDING_COMMANDS; cnt++)
		req->outstanding_cmds[cnt] = NULL;
	req->current_outstanding_cmd = 1;

	req->ring_ptr = req->ring;
	req->ring_index = 0;
	req->cnt = req->length;
	req->id = que_id;
	req->max_q_depth = ha->req_q_map[0]->max_q_depth;
	mutex_unlock(&ha->vport_lock);
	ql_dbg(ql_dbg_multiq, base_vha, 0xc004,
	    "ring_ptr=%p ring_index=%d, "
	    "cnt=%d id=%d max_q_depth=%d.\n",
	    req->ring_ptr, req->ring_index,
	    req->cnt, req->id, req->max_q_depth);
	ql_dbg(ql_dbg_init, base_vha, 0x00de,
	    "ring_ptr=%p ring_index=%d, "
	    "cnt=%d id=%d max_q_depth=%d.\n",
	    req->ring_ptr, req->ring_index, req->cnt,
	    req->id, req->max_q_depth);

	ret = qla25xx_init_req_que(base_vha, req);
	if (ret != QLA_SUCCESS) {
		ql_log(ql_log_fatal, base_vha, 0x00df,
		    "%s failed.\n", __func__);
		mutex_lock(&ha->vport_lock);
		clear_bit(que_id, ha->req_qid_map);
		mutex_unlock(&ha->vport_lock);
		goto que_failed;
	}

	return req->id;

que_failed:
	qla25xx_free_req_que(base_vha, req);
failed:
	return 0;
}

static void qla_do_work(struct work_struct *work)
{
	unsigned long flags;
	struct rsp_que *rsp = container_of(work, struct rsp_que, q_work);
	struct scsi_qla_host *vha;
	struct qla_hw_data *ha = rsp->hw;

	spin_lock_irqsave(&rsp->hw->hardware_lock, flags);
	vha = pci_get_drvdata(ha->pdev);
	qla24xx_process_response_queue(vha, rsp);
	spin_unlock_irqrestore(&rsp->hw->hardware_lock, flags);
}

/* create response queue */
int
qla25xx_create_rsp_que(struct qla_hw_data *ha, uint16_t options,
	uint8_t vp_idx, uint16_t rid, int req)
{
	int ret = 0;
	struct rsp_que *rsp = NULL;
	struct scsi_qla_host *base_vha = pci_get_drvdata(ha->pdev);
	uint16_t que_id = 0;
	device_reg_t __iomem *reg;

	rsp = kzalloc(sizeof(struct rsp_que), GFP_KERNEL);
	if (rsp == NULL) {
		ql_log(ql_log_warn, base_vha, 0x0066,
		    "Failed to allocate memory for response queue.\n");
		goto failed;
	}

	rsp->length = RESPONSE_ENTRY_CNT_MQ;
	rsp->ring = dma_alloc_coherent(&ha->pdev->dev,
			(rsp->length + 1) * sizeof(response_t),
			&rsp->dma, GFP_KERNEL);
	if (rsp->ring == NULL) {
		ql_log(ql_log_warn, base_vha, 0x00e1,
		    "Failed to allocate memory for response ring.\n");
		goto que_failed;
	}

	mutex_lock(&ha->vport_lock);
	que_id = find_first_zero_bit(ha->rsp_qid_map, ha->max_rsp_queues);
	if (que_id >= ha->max_rsp_queues) {
		mutex_unlock(&ha->vport_lock);
		ql_log(ql_log_warn, base_vha, 0x00e2,
		    "No resources to create additional request queue.\n");
		goto que_failed;
	}
	set_bit(que_id, ha->rsp_qid_map);

	if (ha->flags.msix_enabled)
		rsp->msix = &ha->msix_entries[que_id + 1];
	else
		ql_log(ql_log_warn, base_vha, 0x00e3,
		    "MSIX not enalbled.\n");

	ha->rsp_q_map[que_id] = rsp;
	rsp->rid = rid;
	rsp->vp_idx = vp_idx;
	rsp->hw = ha;
	ql_dbg(ql_dbg_init, base_vha, 0x00e4,
	    "queue_id=%d rid=%d vp_idx=%d hw=%p.\n",
	    que_id, rsp->rid, rsp->vp_idx, rsp->hw);
	/* Use alternate PCI bus number */
	if (MSB(rsp->rid))
		options |= BIT_4;
	/* Use alternate PCI devfn */
	if (LSB(rsp->rid))
		options |= BIT_5;
	/* Enable MSIX handshake mode on for uncapable adapters */
	if (!IS_MSIX_NACK_CAPABLE(ha))
		options |= BIT_6;

	rsp->options = options;
	rsp->id = que_id;
	reg = ISP_QUE_REG(ha, que_id);
	rsp->rsp_q_in = &reg->isp25mq.rsp_q_in;
	rsp->rsp_q_out = &reg->isp25mq.rsp_q_out;
	mutex_unlock(&ha->vport_lock);
	ql_dbg(ql_dbg_multiq, base_vha, 0xc00b,
	    "options=%x id=%d rsp_q_in=%p rsp_q_out=%p",
	    rsp->options, rsp->id, rsp->rsp_q_in,
	    rsp->rsp_q_out);
	ql_dbg(ql_dbg_init, base_vha, 0x00e5,
	    "options=%x id=%d rsp_q_in=%p rsp_q_out=%p",
	    rsp->options, rsp->id, rsp->rsp_q_in,
	    rsp->rsp_q_out);

	ret = qla25xx_request_irq(rsp);
	if (ret)
		goto que_failed;

	ret = qla25xx_init_rsp_que(base_vha, rsp);
	if (ret != QLA_SUCCESS) {
		ql_log(ql_log_fatal, base_vha, 0x00e7,
		    "%s failed.\n", __func__);
		mutex_lock(&ha->vport_lock);
		clear_bit(que_id, ha->rsp_qid_map);
		mutex_unlock(&ha->vport_lock);
		goto que_failed;
	}
	if (req >= 0)
		rsp->req = ha->req_q_map[req];
	else
		rsp->req = NULL;

	qla2x00_init_response_q_entries(rsp);
	if (rsp->hw->wq)
		INIT_WORK(&rsp->q_work, qla_do_work);
	return rsp->id;

que_failed:
	qla25xx_free_rsp_que(base_vha, rsp);
failed:
	return 0;
}
