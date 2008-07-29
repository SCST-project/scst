/*
 *  qla2x_tgt_def.h
 *
 *  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *
 *  Additional file for the target driver support. Intended to define
 *  for 2200 and 2300 thier own exported symbols with unique names.
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
 * This is the global def file that is useful for including from the
 * target portion.
 */

#ifndef __QLA2X_TGT_DEF_H
#define __QLA2X_TGT_DEF_H

#include "qla_def.h"

#ifndef CONFIG_SCSI_QLA2XXX_TARGET
#error __FILE__ " included without CONFIG_SCSI_QLA2XXX_TARGET"
#endif

#ifndef ENTER
#define ENTER(a)
#endif

#ifndef LEAVE
#define LEAVE(a)
#endif

#define QLA2X_TARGET_MAGIC	153
#define QLA2X_INITIATOR_MAGIC   54207

#define QLA2X00_COMMAND_COUNT_INIT	250
#define QLA2X00_IMMED_NOTIFY_COUNT_INIT 250

#define QLA_EXTENDED_LUN 1

/*
 * Used to mark which completion handles (for RIO Status's) are for CTIO's
 * vs. regular (non-target) info.
 */
#define CTIO_COMPLETION_HANDLE_MARK	BIT_15
#if (CTIO_COMPLETION_HANDLE_MARK <= MAX_OUTSTANDING_COMMANDS)
#error "Hackish CTIO_COMPLETION_HANDLE_MARK no longer larger than MAX_OUTSTANDING_COMMANDS"
#endif
#define HANDLE_IS_CTIO_COMP(h) (h & CTIO_COMPLETION_HANDLE_MARK)

#ifndef OF_SS_MODE_0
/*
 * ISP target entries - Flags bit definitions.
 */
#define OF_SS_MODE_0        0
#define OF_SS_MODE_1        1
#define OF_SS_MODE_2        2
#define OF_SS_MODE_3        3

#define OF_RESET            BIT_5       /* Reset LIP flag */
#define OF_DATA_IN          BIT_6       /* Data in to initiator */
                                        /*  (data from target to initiator) */
#define OF_DATA_OUT         BIT_7       /* Data out from initiator */
                                        /*  (data from initiator to target) */
#define OF_NO_DATA          (BIT_7 | BIT_6)
#define OF_INC_RC           BIT_8       /* Increment command resource count */
#define OF_FAST_POST        BIT_9       /* Enable mailbox fast posting. */
#define OF_TERM_EXCH        BIT_14      /* Terminate exchange */
#define OF_SSTS             BIT_15      /* Send SCSI status */
#endif

#ifndef DATASEGS_PER_COMMAND32
#define DATASEGS_PER_COMMAND32    3
#define DATASEGS_PER_CONT32       7
#define QLA_MAX_SG32(ql) \
   (DATASEGS_PER_COMMAND32 + (((ql) > 0) ? DATASEGS_PER_CONT32*((ql) - 1) : 0))

#define DATASEGS_PER_COMMAND64    2
#define DATASEGS_PER_CONT64       5
#define QLA_MAX_SG64(ql) \
   (DATASEGS_PER_COMMAND64 + (((ql) > 0) ? DATASEGS_PER_CONT64*((ql) - 1) : 0))
#endif

/********************************************************************\
 * ISP Queue types left out of new QLogic driver (from old version)
\********************************************************************/

#ifndef ENABLE_LUN_TYPE
#define ENABLE_LUN_TYPE 0x0B		/* Enable LUN entry. */
/*!
 * ISP queue - enable LUN entry structure definition.
 */
typedef struct
{
	uint8_t	 entry_type;		/* Entry type. */
	uint8_t	 entry_count;		/* Entry count. */
	uint8_t	 sys_define;		/* System defined. */
	uint8_t	 entry_status;		/* Entry Status. */
	uint32_t sys_define_2;		/* System defined. */
	uint8_t	 reserved_8;
	uint8_t	 reserved_1;
	uint16_t reserved_2;
	uint32_t reserved_3;
	uint8_t	 status;
	uint8_t	 reserved_4;
	uint8_t	 command_count;		/* Number of ATIOs allocated. */
	uint8_t	 immed_notify_count;	/* Number of Immediate Notify entries allocated. */
	uint16_t reserved_5;
	uint16_t timeout;		/* 0 = 30 seconds, 0xFFFF = disable */
	uint16_t reserved_6[20];
} elun_entry_t;
#define ENABLE_LUN_SUCCESS          0x01
#define ENABLE_LUN_RC_NONZERO       0x04
#define ENABLE_LUN_INVALID_REQUEST  0x06
#define ENABLE_LUN_ALREADY_ENABLED  0x3E
#endif

#ifndef MODIFY_LUN_TYPE
#define MODIFY_LUN_TYPE 0x0C	  //!< Modify LUN entry.
/*
 * ISP queue - modify LUN entry structure definition.
 */
typedef struct
{
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t sys_define_2;		    /* System defined. */
	uint8_t	 reserved_8;
	uint8_t	 reserved_1;
	uint8_t	 operators;
	uint8_t	 reserved_2;
	uint32_t reserved_3;
	uint8_t	 status;
	uint8_t	 reserved_4;
	uint8_t	 command_count;		    /* Number of ATIOs allocated. */
	uint8_t	 immed_notify_count;	    /* Number of Immediate Notify */
	/* entries allocated. */
	uint16_t reserved_5;
	uint16_t timeout;		    /* 0 = 30 seconds, 0xFFFF = disable */
	uint16_t reserved_7[20];
}modify_lun_entry_t;
#define MODIFY_LUN_SUCCESS	0x01
#define MODIFY_LUN_CMD_ADD BIT_0
#define MODIFY_LUN_CMD_SUB BIT_1
#define MODIFY_LUN_IMM_ADD BIT_2
#define MODIFY_LUN_IMM_SUB BIT_3
#endif


#define GET_TARGET_ID(ha, iocb) ((HAS_EXTENDED_IDS(ha))			\
				 ? le16_to_cpu((iocb)->target.extended)	\
				 : (uint16_t)(iocb)->target.id.standard)

#ifndef IMMED_NOTIFY_TYPE
#define IMMED_NOTIFY_TYPE 0x0D/* Immediate notify entry. */
/*
 * ISP queue - immediate notify entry structure definition.
 */
typedef struct
{
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t sys_define_2;		    /* System defined. */
	target_id_t target;
	uint16_t lun;
	uint32_t reserved_2;
	uint16_t status;
	uint16_t task_flags;
	uint16_t seq_id;
	uint16_t reserved_5[11];
	uint16_t scsi_status;
	uint8_t	 sense_data[16];
	uint16_t ox_id;
}notify_entry_t;
#endif

#ifndef NOTIFY_ACK_TYPE
#define NOTIFY_ACK_TYPE 0x0E	  /* Notify acknowledge entry. */
/*
 * ISP queue - notify acknowledge entry structure definition.
 */
typedef struct
{
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t sys_define_2;		    /* System defined. */
	target_id_t target;
	uint8_t	 reserved_1;
	uint8_t	 target_id;
	uint16_t flags;
	uint16_t resp_code;
	uint16_t status;
	uint16_t task_flags;
	uint16_t seq_id;
	uint16_t reserved_3[20];
	uint16_t ox_id;
}nack_entry_t;
#define NOTIFY_ACK_SUCCESS      0x01
#endif

#ifndef ACCEPT_TGT_IO_TYPE
#define ACCEPT_TGT_IO_TYPE 0x16 /* Accept target I/O entry. */
/*
 * ISP queue - Accept Target I/O (ATIO) entry structure definition.
 */
typedef struct
{
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t sys_define_2;		    /* System defined. */
	target_id_t target;
	uint16_t exchange_id;
	uint16_t flags;
	uint16_t status;
	uint8_t	 command_ref;
	uint8_t	 task_codes;
	uint8_t	 task_flags;
	uint8_t	 execution_codes;
	uint8_t	 cdb[MAX_CMDSZ];
	uint32_t data_length;
	uint16_t lun;
	uint8_t  initiator_port_name[WWN_SIZE]; /* on qla23xx */
	uint8_t  reserved2[12];
	uint16_t ox_id;
}atio_entry_t;
#endif

#ifndef CONTINUE_TGT_IO_TYPE
#define CONTINUE_TGT_IO_TYPE 0x17
/*
 * ISP queue - Continue Target I/O (CTIO) entry for status mode 0
 *	       structure definition.
 */
typedef struct
{
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;		    /* System defined handle */
	target_id_t target;
	uint16_t exchange_id;
	uint16_t flags;
	uint16_t status;
	uint16_t timeout;		    /* 0 = 30 seconds, 0xFFFF = disable */
	uint16_t dseg_count;		    /* Data segment count. */
	uint32_t relative_offset;
	uint32_t residual;
	uint16_t reserved_1[3];
	uint16_t scsi_status;
	uint32_t transfer_length;
	uint32_t dseg_0_address[0];
}ctio_common_entry_t;
#define ATIO_PATH_INVALID       0x07
#define ATIO_CANT_PROV_CAP      0x16
#define ATIO_CDB_VALID          0x3D

#define ATIO_EXEC_READ          BIT_1
#define ATIO_EXEC_WRITE         BIT_0
#endif

#ifndef CTIO_A64_TYPE
#define CTIO_A64_TYPE 0x1F
typedef struct
{
	ctio_common_entry_t common;
	uint32_t dseg_0_address;	    /* Data segment 0 address. */
	uint32_t dseg_0_length;		    /* Data segment 0 length. */
	uint32_t dseg_1_address;	    /* Data segment 1 address. */
	uint32_t dseg_1_length;		    /* Data segment 1 length. */
	uint32_t dseg_2_address;	    /* Data segment 2 address. */
	uint32_t dseg_2_length;		    /* Data segment 2 length. */
}ctio_entry_t;
#define CTIO_SUCCESS			0x01
#define CTIO_ABORTED			0x02
#define CTIO_INVALID_RX_ID		0x08
#define CTIO_TIMEOUT			0x0B
#define CTIO_LIP_RESET			0x0E
#define CTIO_TARGET_RESET		0x17
#define CTIO_PORT_UNAVAILABLE		0x28
#define CTIO_PORT_LOGGED_OUT		0x29
#endif

#ifndef CTIO_RET_TYPE
#define CTIO_RET_TYPE	0x17		/* CTIO return entry */
/*
 * ISP queue - CTIO returned entry structure definition.
 */
typedef struct
{
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;		    /* System defined handle. */
	target_id_t target;
	uint16_t exchange_id;
	uint16_t flags;
	uint16_t status;
	uint16_t timeout;	    /* 0 = 30 seconds, 0xFFFF = disable */
	uint16_t dseg_count;	    /* Data segment count. */
	uint32_t relative_offset;
	uint32_t residual;
	uint16_t reserved_1[2];
	uint16_t sense_length;
	uint16_t scsi_status;
	uint16_t response_length;
	uint8_t	 sense_data[26];
}ctio_ret_entry_t;
#endif

/********************************************************************\
 * Type Definitions used by initiator & target halves
\********************************************************************/

typedef enum {
	DISABLE_TARGET_MODE = 0,
	ENABLE_TARGET_MODE = 1
} qla2x_tgt_host_action_t;

struct qla2x_tgt_initiator
{
	int magic;

	/* Callbacks */
	void (*tgt_response_pkt)(scsi_qla_host_t *ha, sts_entry_t *pkt);
	void (*tgt_ctio_completion)(scsi_qla_host_t *ha, uint32_t handle);
	void (*tgt_async_event)(uint16_t code, scsi_qla_host_t *ha, uint16_t *mailbox);
	void (*tgt_host_action)(scsi_qla_host_t *ha, qla2x_tgt_host_action_t action);
};

struct qla2x_tgt_target
{
	int magic;

	/* Callbacks - H/W lock MUST be held while calling any */
	request_t *(*req_pkt)(scsi_qla_host_t *ha);
	void (*isp_cmd)(scsi_qla_host_t *ha);
	void (*enable_lun)(scsi_qla_host_t *ha);
	void (*disable_lun)(scsi_qla_host_t *ha);
	int (*issue_marker)(scsi_qla_host_t *ha);
	cont_entry_t *(*req_cont_pkt)(scsi_qla_host_t *ha);
	int (*get_counts)(scsi_qla_host_t *ha, uint8_t *cmd, uint8_t *imm);
};

int qla2xxx_tgt_register_driver(/* IN */  struct qla2x_tgt_initiator *tgt,
				/* OUT */ struct qla2x_tgt_target *init);

void qla2xxx_tgt_unregister_driver(void);

#endif
