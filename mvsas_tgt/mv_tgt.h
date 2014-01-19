/*
 * Marvell 88SE64xx/88SE94xx main function
 *
 * Copyright 2007 Red Hat, Inc.
 * Copyright 2008 Marvell. <kewei@marvell.com>
 *
 * This file is licensed under GPLv2.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
*/

#ifdef SUPPORT_TARGET
#ifndef _MVSAST_H
#define _MVSAST_H
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_debug.h>
#else
#include "scst.h"
#include "scst_debug.h"
#endif
#include "mv_sas.h"

struct mvs_info;
#ifdef MV_DEBUG
#ifdef CONFIG_SCST_DEBUG
#define MVST_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL | TRACE_SCSI | TRACE_DEBUG)
#else
# ifdef CONFIG_SCST_TRACING
#define MVST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | \
				TRACE_MGMT | TRACE_SPECIAL)
# endif
#endif
#else
#define MVST_DEFAULT_LOG_FLAGS  0
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag mvst_trace_flag
extern unsigned long mvst_trace_flag;
#endif

#define MVST_NAME "mvst_scst"

/*
* Macros use for debugging the driver.
*/
#undef ENTER_TRACE
#if defined(ENTER_TRACE)
#define ENTER(x)	printk(KERN_NOTICE "mvsas : Entering %s()\n", x)
#define LEAVE(x)	printk(KERN_NOTICE "mvsas : Leaving %s()\n", x)
#define ENTER_INTR(x)	printk(KERN_NOTICE "mvsas : Entering %s()\n", x)
#define LEAVE_INTR(x)	printk(KERN_NOTICE "mvsas : Leaving %s()\n", x)
#else
#define ENTER(x)	do {} while (0)
#define LEAVE(x)	do {} while (0)
#define ENTER_INTR(x)	do {} while (0)
#define LEAVE_INTR(x)   do {} while (0)
#endif

#ifdef MV_DEBUG
#define DEBUG(x)	(x)
#else
#define DEBUG(x)	do {} while (0)
#endif

#define BUFFER_PACKED		__packed
#define MVST_TARGET_MAGIC	0xFFF1
#define MVST_INITIATOR_MAGIC   0xFFF2

#define MV_FRAME_SIZE	1024

/* Protocol */
#define PROTOCOL_SMP      0x0
#define PROTOCOL_SSP      0x1
#define PROTOCOL_STP      0x2

/* cmd type for build cmd */
#define MVST_CMD	0x0
#define MVST_TMF	0x1

/* defines for address frame types */
#define ADDRESS_IDENTIFY_FRAME	0x00
#define ADDRESS_OPEN_FRAME	0x01

/* defines for target mode action */
#define MVSAS_ENABLE_TGT	0x01
#define MVSAS_DISABLE_TGT	0x02
/********************************************************************\
 * Type Definitions used by initiator & target halves
\********************************************************************/
#define to_mvi_host(x)		((struct mvs_info *) (x)->hostdata)

/* Command's states */
#define MVST_STATE_NEW     0 /* New command and SCST processing it */
#define MVST_STATE_PROCESSED     1    /* SCST done processing */
#define MVST_STATE_NEED_DATA         2   /* SCST needs data to continue */
#define MVST_STATE_DATA_IN      3    /* Data arrived and SCST processing them */
#define MVST_STATE_ABORTED      4    /* Command aborted */
#define MVST_STATE_SEND_DATA     5  /*Target sending DATA out */
#define MVST_STATE_SEND_STATUS      6  /*Target sending status */
#define MVST_STATE_SEND_DATA_RETRY  7  /*Command failed,retry sending data */

/* TM failed */
#define MVST_TM_COMPL		0x00
#define MVST_TM_INVALID_FR	0x02
#define MVST_TM_NOT_SUPPORT	0x04
#define MVST_TM_FAILED		0x05
#define MVST_TM_SUCCEED	0x08
#define MVST_TM_INCRT_LUN	0x09
#define MVST_TM_OVLAP_TAG	0x0a

#define MVST_MAX_CDB_LEN             16
#define MVST_TIMEOUT                 10	/* in seconds */


#define MVST_EXEC_READ          0x1
#define MVST_EXEC_WRITE         0x2

enum mvst_msg_state {
	MSG_QUEUE_IDLE = 0,
	MSG_QUEUE_PROC,
	MSG_QUEUE_NO_START
};

enum module_event {
	EVENT_DEVICE_ARRIVAL,
	EVENT_DEVICE_REMOVAL,
	EVENT_LOG_GENERATED,
};

struct mvst_msg {
	struct  list_head msg_entry;
	void *data;
	u32   msg;
	u64   param;
};

#define MSG_QUEUE_DEPTH (MVS_MAX_PHYS)

#define MVST_TGT_PORT			1
#define MVST_INIT_PORT			2
#define MVST_INIT_TGT_PORT		3

struct mvst_msg_queue {
	u8 msg_state;
	struct task_struct *msg_task;
	spinlock_t msg_lock;
	struct list_head free;
	struct list_head tasks;
	struct mvst_msg msgs[MSG_QUEUE_DEPTH];
};

struct mvs_cmd_header {
#if defined(__BIG_ENDIAN_BITFIELD)
/* DWORD 0 */
	u32   prd_entry_count:16;
	u32   ssp_frame_type:3;

	/*
	  * SSP only, 0-frame type set by HW,
	  * 1-frame type given by SSP_SSPFrameType
	  */
	u32   ssp_passthru:1;

	/* SSP only, generate Burst without waiting for XFER-RDY */
	u32   first_burst:1;

	/* SSP only, verify Data length */
	u32   verify_data_len:1;

	/* SSP only, set if enabling SSP transport layer retry */
	u32   ssp_retry:1;

	/* SSP only, set if protection information record present */
	u32   protect_info_record:1;

	/* SATA only, set if it is for device reset */
	u32   reset:1;

	/* SATA only, set if it is a first party DMA command */
	u32   first_dma:1;

	/* SATA only, set if it is a ATAPI PIO */
	u32   atapi:1;

	/* SATA only, set if it is a BIST FIS */
	u32   bist:1;
	u32   pm_port:4;   /* Port Multiplier field in command FIS */

	/* DWORD 1 */
	u32   reserved2:7;

	/*
	  * max response frame length in DW,
	  * HW will put in status buffer structure
	  */
	u32   max_rsp_frame_len:9;
	u32   reserved1:6;

	/* command frame length in DW,
	  *including frame length, excluding CRC
	  */
	u32   frame_len:10;

	/* DWORD 2 */
	/*
	  * Target Port Transfer Tag,
	  * for target to tag multiple XFER_RDY
	  */
	u32   target_tag:16;
	u32   tag:16;   /* command tag */
#else /*  __BIG_ENDIAN_BITFIELD */
	/* DWORD 0 */
	/* Port Multiplier field in command FIS */
	u32   pm_port:4;
	/* SATA only, set if it is a BIST FIS */
	u32   bist:1;
	/* SATA only, set if it is a ATAPI PIO */
	u32   atapi:1;
	/* SATA only, set if it is a first party DMA command */
	u32   first_dma:1;
	/* SATA only, set if it is for device reset */
	u32   reset:1;
	/* SSP only, set if protection information record present */
	u32   protect_info_record:1;
	/* SSP only, set if enabling SSP transport layer retry */
	u32   ssp_retry:1;
	 /* SSP only, verify Data length */
	u32   verify_data_len:1;
	 /* SSP only, generate Burst without waiting for XFER-RDY */
	u32   first_burst:1;
	/*
	* SSP only, 0-frame type set by HW, 1-frame type given
	* by SSP_SSPFrameType
	*/
	u32   ssp_passthru:1;
	u32   ssp_frame_type:3;
	u32   prd_entry_count:16;

	/* DWORD 1 */
	/* command frame length in DW, including
	  * frame length, excluding CRC
	  */
	u32   frame_len:10;
	u32   reserved1:6;

	/* max response frame length in DW,
	 * HW will put in status buffer structure */
	u32   max_rsp_frame_len:9;
	u32   reserved2:7;

	/* DWORD 2 */
	/* command tag */
	u32   tag:16;
	/* Target Port Transfer Tag, for target to tag multiple XFER_RDY */
	u32   target_tag:16;
#endif /* __BIG_ENDIAN_BITFIELD */
/* DWORD 3 */
	__le32	data_len;	/* data xfer len  in bytes  */
/* DWORD 4 - 5 */
	__le64	cmd_tbl;	/* command table address */
/* DWORD 6 -7  */
	__le64	open_frame;	/* open addr frame address */
/* DWORD 8 - 9 */
	__le64	status_buf;	/* status buffer address */
/* DWORD 10 - 11 */
	__le64	prd_tbl;		/* PRD tbl address */
/* DWORD 12-15 */
	__le32	reserved[4];
} BUFFER_PACKED;

/* for command table */
/* SSP frame header */
struct ssp_frame_header {
	u8   frame_type;
	u8   hashed_dest_sas_addr[3];
	u8   reseved1;
	u8   hashed_src_sas_addr[3];
	u8   reseved2[2];
#if defined(__BIG_ENDIAN_BITFIELD)
	u8   reserved3:3;
	u8   tlr_control:2;
/* set in XFER_RDY to allow ReTx Data frames */
	u8   retry_data:1;
 /* set in TASK/XFER_RDY/RESPONSE frames indicating this is a re-txed */
	u8   retransmit:1;
 /* Change Data Pointer */
	u8   change_data_point:1;

	u8   reserved4:6;
	u8   num_of_fill_bytes:2;
#else /* __BIG_ENDIAN_BITFIELD */
 /* Change Data Pointer */
	u8   change_data_point:1;
/* set in TASK/XFER_RDY/RESPONSE frames indicating this is a re-txed */
	u8   retransmit:1;
/* set in XFER_RDY to allow ReTx Data frames */
	u8   retry_data:1;
	u8   tlr_control:2;
	u8   reserved3:3;

	u8   num_of_fill_bytes:2;
	u8   reserved4:6;
#endif /* __BIG_ENDIAN_BITFIELD */
	u8   reserved5[4];
/* command tag */
	__be16   tag;
/* Target Port Transfer Tag, for target to tag multiple XFER_RDY */
	__be16   target_tag;
	__be32   data_offset;
} BUFFER_PACKED;

/* SSP Command UI */
struct ssp_command_iu {
	u8   lun[8];
	u8   reserved1;
#ifdef __BIG_ENDIAN_BITFIELD
	u8   add_cdb_len:6;      /* in DW */
	u8   reserved4:2;
	u8   reserved3;
	u8   first_burst:1;
	u8   task_priority:4;
	u8   task_attr:3;
#else
	u8   task_attr:3;
	u8   task_priority:4;
	u8   first_burst:1;
	u8   reserved3;
	u8   reserved4:2;
	u8   add_cdb_len:6;      /* in DW */
#endif /* __BIG_ENDIAN_BITFIELD */
	u8   cdb[MVST_MAX_CDB_LEN];
} BUFFER_PACKED;

/* SSP TASK UI */
struct ssp_task_iu {
	u8   lun[8];
	u8   reserved1[2];
	u8   task_fun;
	u8   reserved2;
	__be16   tag;
	u8   reserved3[14];
} BUFFER_PACKED;


/* SSP XFER_RDY UI */
struct ssp_xfrd_iu {
	__be32   requested_offset;
	__be32   data_len;
	u8   reserved3[4];
} BUFFER_PACKED;

struct mv_ssp_response_iu {
	u8     _r_a[8];
	__be16 rdt;
#ifdef __BIG_ENDIAN_BITFIELD
	u8     _r_b:6;
	u8     datapres:2;
#else
	u8     datapres:2;
	u8     _r_b:6;
#endif
	u8     status;

	u32    _r_c;

	__be32 sense_data_len;
	__be32 response_data_len;

	u8     data[0];
} BUFFER_PACKED;

#define NO_DATA				0
#define RESPONSE_DATA			1
#define SENSE_DATA			2

#define TASK_MANAGE_COMP				0x00
#define INVALID_FRAME					0x02
#define TASK_MANAGE_UNSUPPORT		0x04
#define TASK_MANAGE_FAILED				0x05
#define TASK_MANAGE_SUCCESS			0x08
#define INCORRECT_LOGICAL_UNIT		0x09
#define OVERLAPPED_TAG					0x0a


/* SSP Command Table */
struct ssp_command_tbl {
	struct ssp_frame_header frame_header;
	union {
		struct ssp_command_iu command;
		struct ssp_task_iu task;
		struct ssp_xfrd_iu xfer_rdy;
		struct ssp_response_iu response;
	} data;
};

/* Delivery Queue Entry */
struct mvs_delivery_queue {
#ifdef __BIG_ENDIAN_BITFIELD
	u32 cmd:3;
	u32 mode:1;
	u32 priority:1;
	u32 sata_reg_set:7;
	u32 phy:8;
	u32 slot_nm:12;
#else
	u32 slot_nm:12;
	u32 phy:8;
	u32 sata_reg_set:7;
	u32 priority:1;
	u32 mode:1;
	u32 cmd:3;
#endif /* __BIG_ENDIAN_BITFIELD */
} BUFFER_PACKED;

#define TXQ_MODE_TARGET		0
#define TXQ_MODE_INITIATOR	1

#define TXQ_PRI_NORMAL		0
#define TXQ_PRI_HIGH			1

/* Completion Queue Entry */
struct mvs_compl_queue {
#ifdef __BIG_ENDIAN_BITFIELD
	u32 reserved2:9;
	u32 rspns_good:1;
	u32 slot_rst_cmpl:1;
	u32 cmd_rcvd:1;        /* target mode */
	u32 attention:1;
	u32 rspns_xfrd:1;
	u32 err_rcrd_xfrd:1;
	u32 cmd_cmpl:1;
	u32 reserved1:4;
	u32 slot_nm:12;
#else
	u32 slot_nm:12;
	u32 reserved1:4;
	u32 cmd_cmpl:1;
	u32 err_rcrd_xfrd:1;
	u32 rspns_xfrd:1;
	u32 attention:1;
	u32 cmd_rcvd:1; /* target mode */
	u32 slot_rst_cmpl:1;
	u32 rspns_good:1;
	u32 reserved2:9;
#endif /* __BIG_ENDIAN_BITFIELD */
} BUFFER_PACKED;


enum mvst_tgt_host_action_t {
	DISABLE_TARGET_MODE = 0,
	ENABLE_TARGET_MODE = 1,
	EXIT_TARGET_MODE = 0xff
};

struct mvs_tgt_initiator {
	int magic;

	/* Callbacks */
	u8 (*tgt_rsp_ssp_cmd)(struct mvs_info *mvi, u32 rx_desc);
	void (*tgt_cmd_cmpl)(struct mvs_info *mvi, u32 rx_desc);
	void (*tgt_host_action)(struct mvs_info *mvi,
		enum mvst_tgt_host_action_t action, u8 phyid);
};

/*
 * Equivilant to IT Nexus (Initiator-Target)
 */
struct mvst_sess {
	struct list_head sess_entry;
	struct scst_session *scst_sess;
	struct mvst_tgt *tgt;
	u64 initiator_sas_addr;
};

/* Open Address Frame */
struct open_address_frame {
	union {
		struct {
#if defined(__BIG_ENDIAN_BITFIELD)
			u8   initiator:1;
			u8   protocol:3;
			u8   frame_type:4;

			u8   feature:4;
			u8   connect_rate:4;
#else /* __BIG_ENDIAN_BITFIELD */
			u8   frame_type:4;
			u8   protocol:3;
			u8   initiator:1;

			u8   connect_rate:4;
			u8   feature:4;
#endif /* __BIG_ENDIAN_BITFIELD */
		__be16   connect_tag;
		};
		struct {
		__be16 received_tag;
		__be16 received_rate;
		};
	};

	u64   dest_sas_addr;
/* HW will generate Byte 12 after... */
	u64   src_sas_addr;
	u8   src_zone_group;
	u8   blocked_count;
	__be16   awt;
	u8   cmp_features2[4];
	u32   first_burst_size;      /* for hardware use*/
} BUFFER_PACKED;

struct mvst_cmd {
	struct list_head	cmd_entry;
	struct mvst_sess *sess;
	struct scst_cmd *scst_cmd;
	struct scst_mgmt_cmd *scst_mcmd;
	int cmd_state;
	struct ssp_frame_header *ssp_hdr;
	union {
		struct ssp_command_iu *command_iu;
		struct ssp_task_iu *task_iu;
	};

	struct open_address_frame *open_frame;
	struct ssp_frame_header save_ssp_hdr;
	union {
		struct ssp_command_iu save_command_iu;
		struct ssp_task_iu save_task_iu;
	};
	struct open_address_frame save_open_frame;
	dma_addr_t dma_handle;
	struct mvst_port	*cmd_tgt_port;
	u32	transfer_len;
	u32	finished_len;
	void *transfer_buf;
	void *org_transfer_buf;
};

struct mvst_tgt {
	struct scst_tgt *scst_tgt;
	struct mvs_info *mvi;
	unsigned int tgt_shutdown:1;
	unsigned int tgt_enable_64bit_addr:1;
	wait_queue_head_t waitQ;
	int notify_ack_expected;
	/* Count of sessions refering q2t_tgt, protected by hardware_lock */
	int sess_count;
	struct list_head sess_list;
};

struct mvst_prm {
	struct mvst_tgt *tgt;
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
	struct mvst_cmd *cmd;
};

/* mvi->hardware_lock supposed to be
 * held on entry (to protect tgt->sess_list)
 */
static inline struct mvst_sess *mvst_find_sess_by_lid(struct mvst_tgt *tgt,
						    u64 sas_addr)
{
	struct mvst_sess *sess;
	BUG_ON(tgt == NULL);
	list_for_each_entry(sess, &tgt->sess_list, sess_entry) {
		if (sas_addr == sess->initiator_sas_addr)
			return sess;
	}

	return NULL;
}

struct mvst_port {
	int	port_id;
	u8	port_attached;
	u8	wide_port_phymap;	/* save phy id */
	u8	port_attr;
	u64  sas_addr;
	u64  att_sas_addr;
	struct list_head	slot_list;
	struct mvs_info *mvi;
	int              num_phys;
	struct mvs_phy *phy;
};
struct pci_dev *mvs_get_pdev(void);
int mvs_tgt_register_driver(struct mvs_tgt_initiator *tgt_data);
void mvst_update_wideport(struct mvs_info *mvi, int phy_no);
void mvst_init_port(struct mvs_info *mvi);
void mvst_exit(void);
int  mvst_init(void);
void mvst_int_port(struct mvs_info *mvi, u32 id);
u32 mvst_check_port(struct mvs_info *mvi, u8 phy_id);
void mvst_init_tgt_port(struct mvs_info *mvi);
#define MVST_IN_TARGET_MODE(mvi)	((mvi)->flags & MVF_TARGET_MODE_ENABLE)
#define PHY_IN_TARGET_MODE(dev)		(((dev) & PORT_DEV_SSP_TRGT) ? 1 : 0)

#endif	/* #ifdef _MVSAST_H */
#endif	/*SUPPORT_TARGET*/


