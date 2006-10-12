/*
 *  qla2x_tgt.h
 *  
 *  Copyright (C) 2004-2005 Vladislav Bolkhovitin <vst@vlnb.net>
 *		   and Leonid Stoljar
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

#ifndef FC_TARGET_SUPPORT
#error __FILE__ " included without FC_TARGET_SUPPORT"
#endif

#include "qla2x_tgt_def.h"

extern struct qla2x_tgt_initiator qla_target;

/* declare here because it doesn't appear in any .h file just in qla_iocb.c */
extern request_t *qla2x00_req_pkt(scsi_qla_host_t *ha);

/********************************************************************\
 * ISP Queue types left out of new QLogic driver (from old version)
\********************************************************************/

/*
 * qla2x00_do_en_dis_lun
 *	Issue enable or disable LUN entry IOCB.
 *	Also set enable_target_mode in ha
 *
 * Input:
 *	ha = adapter block pointer.
 */
/* Caller MUST have hardware lock held */
static inline void
__qla2x00_en_dis_lun(scsi_qla_host_t *ha, int enable) 
{
	elun_entry_t *pkt;

	if ((pkt = (elun_entry_t *)qla2x00_req_pkt(ha)) != NULL) {
		pkt->entry_type = ENABLE_LUN_TYPE;
		if (enable) {
			pkt->command_count = QLA2X00_COMMAND_COUNT_INIT;
			pkt->immed_notify_count = QLA2X00_IMMED_NOTIFY_COUNT_INIT;
			pkt->timeout = 0xffff;
		}
		else
		{
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
		ha->flags.enable_target_mode = enable;
	}
#if defined(QL_DEBUG_LEVEL_2) || defined(QL_DEBUG_LEVEL_3)
	if (!pkt)
		printk("qla2100_en_dis_lun: **** FAILED ****\n");
#endif
}
/* get-lock version */
static inline void
qla2x00_en_dis_lun(scsi_qla_host_t *ha, int enable)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	__qla2x00_en_dis_lun(ha, enable);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}


/*
 * qla2x00_enable_lun
 *      Issue enable LUN entry IOCB.
 *
 * Input:
 *      ha = adapter block pointer.
 */
static inline void
qla2x00_enable_lun(scsi_qla_host_t *ha)
{
	qla2x00_en_dis_lun(ha, 1);
}

/*
 * qla2x00_disable_lun
 *	Issue enable LUN entry IOCB (command_count = 0).
 *
 * Input:
 *	ha = adapter block pointer.
 */
static inline void
qla2x00_disable_lun(scsi_qla_host_t *ha)
{
	qla2x00_en_dis_lun(ha, 0);
}

#endif /* __QLA2X_TGT_H */
