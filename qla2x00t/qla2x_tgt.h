/*
 *  qla2x_tgt.h
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  Additional file for the target driver support.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */
/*
 * This should be included only from within qla2xxx module.
 */


#ifndef __QLA2X_TGT_H
#define __QLA2X_TGT_H

#include <linux/version.h>

extern request_t *qla2x00_req_pkt(scsi_qla_host_t *ha);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET

#include "qla2x_tgt_def.h"

extern struct qla_tgt_data qla_target;

void qla_set_tgt_mode(scsi_qla_host_t *ha);
void qla_clear_tgt_mode(scsi_qla_host_t *ha);

static inline bool qla_tgt_mode_enabled(scsi_qla_host_t *ha)
{
	return ha->host->active_mode & MODE_TARGET;
}

static inline bool qla_ini_mode_enabled(scsi_qla_host_t *ha)
{
	return ha->host->active_mode & MODE_INITIATOR;
}

static inline void qla_reverse_ini_mode(scsi_qla_host_t *ha)
{
	if (ha->host->active_mode & MODE_INITIATOR)
		ha->host->active_mode &= ~MODE_INITIATOR;
	else
		ha->host->active_mode |= MODE_INITIATOR;
}

/********************************************************************\
 * ISP Queue types left out of new QLogic driver (from old version)
\********************************************************************/

/*
 * qla2x00_do_en_dis_lun
 *	Issue enable or disable LUN entry IOCB.
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Caller MUST have hardware lock held. This function might release it,
 * then reacquire.
 */
static inline void
__qla2x00_send_enable_lun(scsi_qla_host_t *ha, int enable)
{
	elun_entry_t *pkt;

	BUG_ON(IS_FWI2_CAPABLE(ha));

	pkt = (elun_entry_t *)qla2x00_req_pkt(ha);
	if (pkt != NULL) {
		pkt->entry_type = ENABLE_LUN_TYPE;
		if (enable) {
			pkt->command_count = QLA2X00_COMMAND_COUNT_INIT;
			pkt->immed_notify_count = QLA2X00_IMMED_NOTIFY_COUNT_INIT;
			pkt->timeout = 0xffff;
		} else {
			pkt->command_count = 0;
			pkt->immed_notify_count = 0;
			pkt->timeout = 0;
		}
		DEBUG2(printk(KERN_DEBUG
			      "scsi%lu:ENABLE_LUN IOCB imm %u cmd %u timeout %u\n",
			      ha->host_no, pkt->immed_notify_count,
			      pkt->command_count, pkt->timeout));

		/* Issue command to ISP */
		qla2x00_isp_cmd(ha);

	} else
		qla_clear_tgt_mode(ha);
#if defined(QL_DEBUG_LEVEL_2) || defined(QL_DEBUG_LEVEL_3)
	if (!pkt)
		pr_err("%s: **** FAILED ****\n", __func__);
#endif

	return;
}

/*
 * qla2x00_send_enable_lun
 *      Issue enable LUN entry IOCB.
 *
 * Input:
 *      ha = adapter block pointer.
 *	enable = enable/disable flag.
 */
static inline void
qla2x00_send_enable_lun(scsi_qla_host_t *ha, bool enable)
{
	if (!IS_FWI2_CAPABLE(ha)) {
		unsigned long flags;
		scsi_qla_host_t *pha = to_qla_parent(ha);
		spin_lock_irqsave(&pha->hardware_lock, flags);
		__qla2x00_send_enable_lun(ha, enable);
		spin_unlock_irqrestore(&pha->hardware_lock, flags);
	}
}

extern void qla2xxx_add_targets(void);
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)) || \
     defined(FC_VPORT_CREATE_DEFINED))
extern size_t
qla2xxx_add_vtarget(u64 *port_name, u64 *node_name, u64 *parent_host);
extern size_t qla2xxx_del_vtarget(u64 *port_name);
#endif /*((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)) || \
	  defined(FC_VPORT_CREATE_DEFINED))*/

#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

#endif /* __QLA2X_TGT_H */
