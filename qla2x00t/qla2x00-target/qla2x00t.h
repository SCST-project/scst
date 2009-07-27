/*
 *  qla2x00t.h
 *
 *  Copyright (C) 2004 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *
 *  QLogic 2x00 SCSI target driver.
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

#ifndef __QLA2X00T_H
#define __QLA2X00T_H

/* Sneaky hack to skip redefinitions from qla_dbg.h */
#define __QLA_DBG_H
#include <qla_def.h>
#include "qla2x_tgt_def.h"

#include <scst_debug.h>

/* Version numbers, the same as for the kernel */
#define Q2T_VERSION(a, b, c, d) (((a) << 030) + ((b) << 020) + (c) << 010 + (d))
#define Q2T_VERSION_CODE Q2T_VERSION(1, 0, 2, 0)
#define Q2T_VERSION_STRING "1.0.2"

#define Q2T_MAX_CDB_LEN             16
#define Q2T_TIMEOUT                 10	/* in seconds */
#define Q2T_MAX_HW_PENDING_TIME	    60 /* in seconds */

/* Immediate notify status constants */
#define IMM_NTFY_LIP_RESET          0x000E
#define IMM_NTFY_IOCB_OVERFLOW      0x0016
#define IMM_NTFY_ABORT_TASK         0x0020
#define IMM_NTFY_PORT_LOGOUT        0x0029
#define IMM_NTFY_PORT_CONFIG        0x002A
#define IMM_NTFY_GLBL_TPRLO         0x002D
#define IMM_NTFY_GLBL_LOGO          0x002E
#define IMM_NTFY_RESOURCE           0x0034
#define IMM_NTFY_MSG_RX             0x0036

/* Immediate notify task flags */
#define IMM_NTFY_CLEAR_ACA          0x4000
#define IMM_NTFY_TARGET_RESET       0x2000
#define IMM_NTFY_LUN_RESET          0x1000
#define IMM_NTFY_CLEAR_TS           0x0400
#define IMM_NTFY_ABORT_TS           0x0200

/* Notify Acknowledge flags */
#define NOTIFY_ACK_RES_COUNT        BIT_8
#define NOTIFY_ACK_CLEAR_LIP_RESET  BIT_5
#define NOTIFY_ACK_TM_RESP_CODE_VALID BIT_4

/* Command's states */
#define Q2T_STATE_NEW               0	/* New command and SCST processing it */
#define Q2T_STATE_PROCESSED         1	/* SCST done processing */
#define Q2T_STATE_NEED_DATA         2	/* SCST needs data to continue */
#define Q2T_STATE_DATA_IN           3	/* Data arrived and SCST processing */
					/* them */
#define Q2T_STATE_ABORTED           4	/* Command aborted */

/* Misc */
#define Q2T_NULL_HANDLE             0
#define Q2T_SKIP_HANDLE             (0xFFFFFFFE & ~CTIO_COMPLETION_HANDLE_MARK)
#define Q2T_BUSY_HANDLE             (0xFFFFFFFF & ~CTIO_COMPLETION_HANDLE_MARK)

/* ATIO task_codes fields */
#define ATIO_SIMPLE_QUEUE           0
#define ATIO_HEAD_OF_QUEUE          1
#define ATIO_ORDERED_QUEUE          2
#define ATIO_ACA_QUEUE              4
#define ATIO_UNTAGGED               5

/* TM failed response code, see FCP */
#define FC_TM_FAILED                0x5

#if (BITS_PER_LONG > 32) || defined(CONFIG_HIGHMEM64G)
#define pci_dma_lo32(a) (a & 0xffffffff)
#define pci_dma_hi32(a) ((((a) >> 16)>>16) & 0xffffffff)
#else
#define pci_dma_lo32(a) (a & 0xffffffff)
#define pci_dma_hi32(a) 0
#endif

/*
 * Equivilant to IT Nexus (Initiator-Target)
 */
struct q2t_sess {
	struct list_head list;
	struct scst_session *scst_sess;
	struct q2t_tgt *tgt;
	int loop_id;
};

struct q2t_cmd {
	struct q2t_sess *sess;
	struct scst_cmd *scst_cmd;
	int state;
	struct atio_entry atio;
	dma_addr_t dma_handle;
	uint32_t iocb_cnt;
};

struct q2t_tgt {
	struct scst_tgt *scst_tgt;
	scsi_qla_host_t *ha;
	int datasegs_per_cmd, datasegs_per_cont;
	/* Target's flags, serialized by ha->hardware_lock */
	unsigned int tgt_shutdown:1;	/* The driver is being released */
	unsigned int tgt_enable_64bit_addr:1; /* 64bit PCI addressing enabled */
	wait_queue_head_t waitQ;
	int notify_ack_expected;
	int modify_lun_expected;
	/* Count of sessions refering q2t_tgt, protected by hardware_lock */
	int sess_count;
	struct list_head sess_list;
};

struct q2t_mgmt_cmd {
	struct q2t_sess *sess;
	struct notify_entry notify_entry;
};

struct q2t_prm {
	struct q2t_tgt *tgt;
	uint16_t req_cnt;
	uint16_t seg_cnt;
	int sg_cnt;
	struct scatterlist *sg;
	int bufflen;
	scst_data_direction data_direction;
	uint16_t rq_result;
	uint16_t scsi_status;
	unsigned char *sense_buffer;
	unsigned int sense_buffer_len;
	int residual;
	struct q2t_cmd *cmd;
	struct ctio_common_entry *pkt;
};

/* ha->hardware_lock supposed to be held on entry (to protect tgt->sess_list) */
static inline struct q2t_sess *q2t_find_sess_by_lid(struct q2t_tgt *tgt,
						    uint16_t lid)
{
	struct q2t_sess *sess;
	sBUG_ON(tgt == NULL);
	list_for_each_entry(sess, &tgt->sess_list, list) {
		if (lid == sess->loop_id)
			return sess;
	}

	return NULL;
}

#endif /* __QLA2X00T_H */
