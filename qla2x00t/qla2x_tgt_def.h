/*
 *  qla2x_tgt_def.h
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

/*
 * Must be changed on any change in any initiator visible interfaces or
 * data in the target add-on
 */
#define QLA2X_TARGET_MAGIC	270

/*
 * Must be changed on any change in any target visible interfaces or
 * data in the initiator
 */
#define QLA2X_INITIATOR_MAGIC   57225

#define QLA2X_INI_MODE_STR_EXCLUSIVE	"exclusive"
#define QLA2X_INI_MODE_STR_DISABLED	"disabled"
#define QLA2X_INI_MODE_STR_ENABLED	"enabled"

#define QLA2X_INI_MODE_EXCLUSIVE	0
#define QLA2X_INI_MODE_DISABLED		1
#define QLA2X_INI_MODE_ENABLED		2

#define QLA2X00_COMMAND_COUNT_INIT	250
#define QLA2X00_IMMED_NOTIFY_COUNT_INIT 250

/*
 * Used to mark which completion handles (for RIO Status's) are for CTIO's
 * vs. regular (non-target) info. This is checked for in
 * qla2x00_process_response_queue() to see if a handle coming back in a
 * multi-complete should come to the tgt driver or be handled there by qla2xxx
 */
#define CTIO_COMPLETION_HANDLE_MARK	BIT_29
#if (CTIO_COMPLETION_HANDLE_MARK <= MAX_OUTSTANDING_COMMANDS)
#error "Hackish CTIO_COMPLETION_HANDLE_MARK no longer larger than MAX_OUTSTANDING_COMMANDS"
#endif
#define HANDLE_IS_CTIO_COMP(h) (h & CTIO_COMPLETION_HANDLE_MARK)

/* Used to mark CTIO as intermediate */
#define CTIO_INTERMEDIATE_HANDLE_MARK	BIT_30

#ifndef OF_SS_MODE_0
/*
 * ISP target entries - Flags bit definitions.
 */
#define OF_SS_MODE_0        0
#define OF_SS_MODE_1        1
#define OF_SS_MODE_2        2
#define OF_SS_MODE_3        3

#define OF_EXPL_CONF        BIT_5       /* Explicit Confirmation Requested */
#define OF_DATA_IN          BIT_6       /* Data in to initiator */
					/*  (data from target to initiator) */
#define OF_DATA_OUT         BIT_7       /* Data out from initiator */
					/*  (data from initiator to target) */
#define OF_NO_DATA          (BIT_7 | BIT_6)
#define OF_INC_RC           BIT_8       /* Increment command resource count */
#define OF_FAST_POST        BIT_9       /* Enable mailbox fast posting. */
#define OF_CONF_REQ         BIT_13      /* Confirmation Requested */
#define OF_TERM_EXCH        BIT_14      /* Terminate exchange */
#define OF_SSTS             BIT_15      /* Send SCSI status */
#endif

#ifndef DATASEGS_PER_COMMAND32
#define DATASEGS_PER_COMMAND32    3
#define DATASEGS_PER_CONT32       7
#define QLA_MAX_SG32(ql)						  \
	(((ql) > 0) ?							  \
	 (DATASEGS_PER_COMMAND32 + DATASEGS_PER_CONT32 * ((ql) - 1)) : 0)

#define DATASEGS_PER_COMMAND64    2
#define DATASEGS_PER_CONT64       5
#define QLA_MAX_SG64(ql)						  \
	(((ql) > 0) ?							  \
	 (DATASEGS_PER_COMMAND64 + DATASEGS_PER_CONT64 * ((ql) - 1)) : 0)
#endif

#ifndef DATASEGS_PER_COMMAND_24XX
#define DATASEGS_PER_COMMAND_24XX 1
#define DATASEGS_PER_CONT_24XX    5
#define QLA_MAX_SG_24XX(ql)						\
	(min(1270, ((ql) > 0) ?						\
	 (DATASEGS_PER_COMMAND_24XX + DATASEGS_PER_CONT_24XX * ((ql) - 1)) : 0))
#endif

/********************************************************************\
 * ISP Queue types left out of new QLogic driver (from old version)
\********************************************************************/

#ifndef ENABLE_LUN_TYPE
#define ENABLE_LUN_TYPE 0x0B		/* Enable LUN entry. */
/*
 * ISP queue - enable LUN entry structure definition.
 */
typedef struct {
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
} __packed elun_entry_t;
#define ENABLE_LUN_SUCCESS          0x01
#define ENABLE_LUN_RC_NONZERO       0x04
#define ENABLE_LUN_INVALID_REQUEST  0x06
#define ENABLE_LUN_ALREADY_ENABLED  0x3E
#endif

#ifndef MODIFY_LUN_TYPE
#define MODIFY_LUN_TYPE 0x0C	  /* Modify LUN entry. */
/*
 * ISP queue - modify LUN entry structure definition.
 */
typedef struct {
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
} __packed modify_lun_entry_t;
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
#define IMMED_NOTIFY_TYPE 0x0D		/* Immediate notify entry. */
/*
 * ISP queue - immediate notify entry structure definition.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t sys_define_2;		    /* System defined. */
	target_id_t target;
	uint16_t lun;
	uint8_t  target_id;
	uint8_t  reserved_1;
	uint16_t status_modifier;
	uint16_t status;
	uint16_t task_flags;
	uint16_t seq_id;
	uint16_t srr_rx_id;
	uint32_t srr_rel_offs;
	uint16_t srr_ui;
#define SRR_IU_DATA_IN		0x1
#define SRR_IU_DATA_OUT		0x5
#define SRR_IU_STATUS		0x7
	uint16_t srr_ox_id;
	uint8_t reserved_2[30];
	uint16_t ox_id;
} __packed notify_entry_t;
#endif

#ifndef NOTIFY_ACK_TYPE
#define NOTIFY_ACK_TYPE 0x0E	  /* Notify acknowledge entry. */
/*
 * ISP queue - notify acknowledge entry structure definition.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t sys_define_2;		    /* System defined. */
	target_id_t target;
	uint8_t	 target_id;
	uint8_t	 reserved_1;
	uint16_t flags;
	uint16_t resp_code;
	uint16_t status;
	uint16_t task_flags;
	uint16_t seq_id;
	uint16_t srr_rx_id;
	uint32_t srr_rel_offs;
	uint16_t srr_ui;
	uint16_t srr_flags;
	uint16_t srr_reject_code;
	uint8_t  srr_reject_vendor_uniq;
	uint8_t  srr_reject_code_expl;
	uint8_t  reserved_2[26];
	uint16_t ox_id;
} __packed nack_entry_t;
#define NOTIFY_ACK_SRR_FLAGS_ACCEPT	0
#define NOTIFY_ACK_SRR_FLAGS_REJECT	1

#define NOTIFY_ACK_SRR_REJECT_REASON_UNABLE_TO_PERFORM	0x9

#define NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_NO_EXPL		0
#define NOTIFY_ACK_SRR_FLAGS_REJECT_EXPL_UNABLE_TO_SUPPLY_DATA	0x2a

#define NOTIFY_ACK_SUCCESS      0x01
#endif

#ifndef ACCEPT_TGT_IO_TYPE
#define ACCEPT_TGT_IO_TYPE 0x16 /* Accept target I/O entry. */
/*
 * ISP queue - Accept Target I/O (ATIO) entry structure definition.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t sys_define_2;		    /* System defined. */
	target_id_t target;
	uint16_t rx_id;
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
	uint16_t reserved_32[6];
	uint16_t ox_id;
} __packed atio_entry_t;
#endif

#ifndef CONTINUE_TGT_IO_TYPE
#define CONTINUE_TGT_IO_TYPE 0x17
/*
 * ISP queue - Continue Target I/O (CTIO) entry for status mode 0
 *	       structure definition.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;		    /* System defined handle */
	target_id_t target;
	uint16_t rx_id;
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
} __packed ctio_common_entry_t;
#define ATIO_PATH_INVALID       0x07
#define ATIO_CANT_PROV_CAP      0x16
#define ATIO_CDB_VALID          0x3D

#define ATIO_EXEC_READ          BIT_1
#define ATIO_EXEC_WRITE         BIT_0
#endif

#ifndef CTIO_A64_TYPE
#define CTIO_A64_TYPE 0x1F
typedef struct {
	ctio_common_entry_t common;
	uint32_t dseg_0_address;	    /* Data segment 0 address. */
	uint32_t dseg_0_length;		    /* Data segment 0 length. */
	uint32_t dseg_1_address;	    /* Data segment 1 address. */
	uint32_t dseg_1_length;		    /* Data segment 1 length. */
	uint32_t dseg_2_address;	    /* Data segment 2 address. */
	uint32_t dseg_2_length;		    /* Data segment 2 length. */
} __packed ctio_entry_t;
#define CTIO_SUCCESS			0x01
#define CTIO_ABORTED			0x02
#define CTIO_INVALID_RX_ID		0x08
#define CTIO_TIMEOUT			0x0B
#define CTIO_LIP_RESET			0x0E
#define CTIO_TARGET_RESET		0x17
#define CTIO_PORT_UNAVAILABLE		0x28
#define CTIO_PORT_LOGGED_OUT		0x29
#define CTIO_PORT_CONF_CHANGED		0x2A
#define CTIO_SRR_RECEIVED		0x45

#endif

#ifndef CTIO_RET_TYPE
#define CTIO_RET_TYPE	0x17		/* CTIO return entry */
/*
 * ISP queue - CTIO returned entry structure definition.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;		    /* System defined handle. */
	target_id_t target;
	uint16_t rx_id;
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
} __packed ctio_ret_entry_t;
#endif

#define ATIO_TYPE7 0x06 /* Accept target I/O entry for 24xx */

typedef struct {
	uint8_t  r_ctl;
	uint8_t  d_id[3];
	uint8_t  cs_ctl;
	uint8_t  s_id[3];
	uint8_t  type;
	uint8_t  f_ctl[3];
	uint8_t  seq_id;
	uint8_t  df_ctl;
	uint16_t seq_cnt;
	uint16_t ox_id;
	uint16_t rx_id;
	uint32_t parameter;
} __packed fcp_hdr_t;

typedef struct {
	uint8_t  d_id[3];
	uint8_t  r_ctl;
	uint8_t  s_id[3];
	uint8_t  cs_ctl;
	uint8_t  f_ctl[3];
	uint8_t  type;
	uint16_t seq_cnt;
	uint8_t  df_ctl;
	uint8_t  seq_id;
	uint16_t rx_id;
	uint16_t ox_id;
	uint32_t parameter;
} __packed fcp_hdr_le_t;

#define F_CTL_EXCH_CONTEXT_RESP	BIT_23
#define F_CTL_SEQ_CONTEXT_RESIP	BIT_22
#define F_CTL_LAST_SEQ		BIT_20
#define F_CTL_END_SEQ		BIT_19
#define F_CTL_SEQ_INITIATIVE	BIT_16

#define R_CTL_BASIC_LINK_SERV	0x80
#define R_CTL_B_ACC		0x4
#define R_CTL_B_RJT		0x5

typedef struct {
	uint64_t lun;
	uint8_t  cmnd_ref;
#ifdef __LITTLE_ENDIAN
	uint8_t  task_attr:3;
	uint8_t  reserved:5;
#else
	uint8_t  reserved:5;
	uint8_t  task_attr:3;
#endif
	uint8_t  task_mgmt_flags;
#define FCP_CMND_TASK_MGMT_CLEAR_ACA		6
#define FCP_CMND_TASK_MGMT_TARGET_RESET		5
#define FCP_CMND_TASK_MGMT_LU_RESET		4
#define FCP_CMND_TASK_MGMT_CLEAR_TASK_SET	2
#define FCP_CMND_TASK_MGMT_ABORT_TASK_SET	1
#ifdef __LITTLE_ENDIAN
	uint8_t  wrdata:1;
	uint8_t  rddata:1;
	uint8_t  add_cdb_len:6;
#else
	uint8_t  add_cdb_len:6;
	uint8_t  rddata:1;
	uint8_t  wrdata:1;
#endif
	uint8_t  cdb[16];
	/*
	 * add_cdb is optional and can absent from fcp_cmnd_t. Size 4 only to
	 * make sizeof(fcp_cmnd_t) be as expected by BUILD_BUG_ON() in
	 * q2t_init().
	 */
	uint8_t  add_cdb[4];
	/* uint32_t data_length; */
} __packed fcp_cmnd_t;

/*
 * ISP queue - Accept Target I/O (ATIO) type 7 entry for 24xx structure
 * definition.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t  fcp_cmnd_len_low;
#ifdef __LITTLE_ENDIAN
	uint8_t  fcp_cmnd_len_high:4;
	uint8_t  attr:4;
#else
	uint8_t  attr:4;
	uint8_t  fcp_cmnd_len_high:4;
#endif
	uint32_t exchange_addr;
#define ATIO_EXCHANGE_ADDRESS_UNKNOWN		0xFFFFFFFF
	fcp_hdr_t fcp_hdr;
	fcp_cmnd_t fcp_cmnd;
} __packed atio7_entry_t;

#define CTIO_TYPE7 0x12 /* Continue target I/O entry (for 24xx) */

/*
 * ISP queue - Continue Target I/O (ATIO) type 7 entry (for 24xx) structure
 * definition.
 */

typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;		    /* System defined handle */
	uint16_t nport_handle;
#define CTIO7_NHANDLE_UNRECOGNIZED	0xFFFF
	uint16_t timeout;
	uint16_t dseg_count;		    /* Data segment count. */
	uint8_t  vp_index;
	uint8_t  add_flags;
	uint8_t  initiator_id[3];
	uint8_t  reserved;
	uint32_t exchange_addr;
} __packed ctio7_common_entry_t;

typedef struct {
	ctio7_common_entry_t common;
	uint16_t reserved1;
	uint16_t flags;
	uint32_t residual;
	uint16_t ox_id;
	uint16_t scsi_status;
	uint32_t relative_offset;
	uint32_t reserved2;
	uint32_t transfer_length;
	uint32_t reserved3;
	uint32_t dseg_0_address[2];	    /* Data segment 0 address. */
	uint32_t dseg_0_length;		    /* Data segment 0 length. */
} __packed ctio7_status0_entry_t;

typedef struct {
	ctio7_common_entry_t common;
	uint16_t sense_length;
	uint16_t flags;
	uint32_t residual;
	uint16_t ox_id;
	uint16_t scsi_status;
	uint16_t response_len;
	uint16_t reserved;
	uint8_t sense_data[24];
} __packed ctio7_status1_entry_t;

typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;		    /* System defined handle */
	uint16_t status;
	uint16_t timeout;
	uint16_t dseg_count;		    /* Data segment count. */
	uint8_t  vp_index;
	uint8_t  reserved1[5];
	uint32_t exchange_address;
	uint16_t reserved2;
	uint16_t flags;
	uint32_t residual;
	uint16_t ox_id;
	uint16_t reserved3;
	uint32_t relative_offset;
	uint8_t  reserved4[24];
} __packed ctio7_fw_entry_t;

/* CTIO7 flags values */
#define CTIO7_FLAGS_SEND_STATUS		BIT_15
#define CTIO7_FLAGS_TERMINATE		BIT_14
#define CTIO7_FLAGS_CONFORM_REQ		BIT_13
#define CTIO7_FLAGS_DONT_RET_CTIO	BIT_8
#define CTIO7_FLAGS_STATUS_MODE_0	0
#define CTIO7_FLAGS_STATUS_MODE_1	BIT_6
#define CTIO7_FLAGS_EXPLICIT_CONFORM	BIT_5
#define CTIO7_FLAGS_CONFIRM_SATISF	BIT_4
#define CTIO7_FLAGS_DSD_PTR		BIT_2
#define CTIO7_FLAGS_DATA_IN		BIT_1
#define CTIO7_FLAGS_DATA_OUT		BIT_0

/*
 * ISP queue - immediate notify entry structure definition for 24xx.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t reserved;
	uint16_t nport_handle;
	uint16_t reserved_2;
	uint16_t flags;
#define NOTIFY24XX_FLAGS_GLOBAL_TPRLO	BIT_1
#define NOTIFY24XX_FLAGS_PUREX_IOCB	BIT_0
	uint16_t srr_rx_id;
	uint16_t status;
	uint8_t  status_subcode;
	uint8_t  reserved_3;
	uint32_t exchange_address;
	uint32_t srr_rel_offs;
	uint16_t srr_ui;
	uint16_t srr_ox_id;
	uint8_t  reserved_4[19];
	uint8_t  vp_index;
	uint32_t reserved_5;
	uint8_t  port_id[3];
	uint8_t  reserved_6;
	uint16_t reserved_7;
	uint16_t ox_id;
} __packed notify24xx_entry_t;

#define ELS_PLOGI			0x3
#define ELS_FLOGI			0x4
#define ELS_LOGO			0x5
#define ELS_PRLI			0x20
#define ELS_PRLO			0x21
#define ELS_TPRLO			0x24
#define ELS_PDISC			0x50
#define ELS_ADISC			0x52

/*
 * ISP queue - notify acknowledge entry structure definition for 24xx.
 */
typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;
	uint16_t nport_handle;
	uint16_t reserved_1;
	uint16_t flags;
	uint16_t srr_rx_id;
	uint16_t status;
	uint8_t  status_subcode;
	uint8_t  reserved_3;
	uint32_t exchange_address;
	uint32_t srr_rel_offs;
	uint16_t srr_ui;
	uint16_t srr_flags;
	uint8_t  reserved_4[19];
	uint8_t  vp_index;
	uint8_t  srr_reject_vendor_uniq;
	uint8_t  srr_reject_code_expl;
	uint8_t  srr_reject_code;
	uint8_t  reserved_5[7];
	uint16_t ox_id;
} __packed nack24xx_entry_t;

/*
 * ISP queue - ABTS received/response entries structure definition for 24xx.
 */
#define ABTS_RECV_24XX		0x54 /* ABTS received (for 24xx) */
#define ABTS_RESP_24XX		0x55 /* ABTS responce (for 24xx) */

typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint8_t  reserved_1[6];
	uint16_t nport_handle;
	uint8_t  reserved_2[2];
	uint8_t  vp_index;
#ifdef __LITTLE_ENDIAN
	uint8_t  reserved_3:4;
	uint8_t  sof_type:4;
#else
	uint8_t  sof_type:4;
	uint8_t  reserved_3:4;
#endif
	uint32_t exchange_address;
	fcp_hdr_le_t fcp_hdr_le;
	uint8_t  reserved_4[16];
	uint32_t exchange_addr_to_abort;
} __packed abts24_recv_entry_t;

#define ABTS_PARAM_ABORT_SEQ		BIT_0

typedef struct {
	uint16_t reserved;
	uint8_t  seq_id_last;
	uint8_t  seq_id_valid;
#define SEQ_ID_VALID	0x80
#define SEQ_ID_INVALID	0x00
	uint16_t rx_id;
	uint16_t ox_id;
	uint16_t high_seq_cnt;
	uint16_t low_seq_cnt;
} __packed ba_acc_le_t;

typedef struct {
	uint8_t vendor_uniq;
	uint8_t reason_expl;
	uint8_t reason_code;
#define BA_RJT_REASON_CODE_INVALID_COMMAND	0x1
#define BA_RJT_REASON_CODE_UNABLE_TO_PERFORM	0x9
	uint8_t reserved;
} __packed ba_rjt_le_t;

typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;
	uint16_t reserved_1;
	uint16_t nport_handle;
	uint16_t control_flags;
#define ABTS_CONTR_FLG_TERM_EXCHG	BIT_0
	uint8_t  vp_index;
#ifdef __LITTLE_ENDIAN
	uint8_t  reserved_3:4;
	uint8_t  sof_type:4;
#else
	uint8_t  sof_type:4;
	uint8_t  reserved_3:4;
#endif
	uint32_t exchange_address;
	fcp_hdr_le_t fcp_hdr_le;
	union {
		ba_acc_le_t ba_acct;
		ba_rjt_le_t ba_rjt;
	} __packed payload;
	uint32_t reserved_4;
	uint32_t exchange_addr_to_abort;
} __packed abts24_resp_entry_t;

typedef struct {
	uint8_t	 entry_type;		    /* Entry type. */
	uint8_t	 entry_count;		    /* Entry count. */
	uint8_t	 sys_define;		    /* System defined. */
	uint8_t	 entry_status;		    /* Entry Status. */
	uint32_t handle;
	uint16_t compl_status;
#define ABTS_RESP_COMPL_SUCCESS		0
#define ABTS_RESP_COMPL_SUBCODE_ERROR	0x31
	uint16_t nport_handle;
	uint16_t reserved_1;
	uint8_t  reserved_2;
#ifdef __LITTLE_ENDIAN
	uint8_t  reserved_3:4;
	uint8_t  sof_type:4;
#else
	uint8_t  sof_type:4;
	uint8_t  reserved_3:4;
#endif
	uint32_t exchange_address;
	fcp_hdr_le_t fcp_hdr_le;
	uint8_t reserved_4[8];
	uint32_t error_subcode1;
#define ABTS_RESP_SUBCODE_ERR_ABORTED_EXCH_NOT_TERM	0x1E
	uint32_t error_subcode2;
	uint32_t exchange_addr_to_abort;
} __packed abts24_resp_fw_entry_t;

/********************************************************************\
 * Type Definitions used by initiator & target halves
\********************************************************************/

typedef enum {
	ADD_TARGET = 0,
	REMOVE_TARGET,
	DISABLE_TARGET_MODE,
	ENABLE_TARGET_MODE,
} qla2x_tgt_host_action_t;

/* Changing it don't forget to change QLA2X_TARGET_MAGIC! */
struct qla_tgt_data {
	int magic;

	/* Callbacks */
	void (*tgt24_atio_pkt)(scsi_qla_host_t *ha, atio7_entry_t *pkt);
	void (*tgt_response_pkt)(scsi_qla_host_t *ha, response_t *pkt);
	void (*tgt2x_ctio_completion)(scsi_qla_host_t *ha, uint32_t handle);
	void (*tgt_async_event)(uint16_t code, scsi_qla_host_t *ha,
		uint16_t *mailbox);
	int (*tgt_host_action)(scsi_qla_host_t *ha, qla2x_tgt_host_action_t
							action);
	void (*tgt_fc_port_added)(scsi_qla_host_t *ha, fc_port_t *fcport);
	void (*tgt_fc_port_deleted)(scsi_qla_host_t *ha, fc_port_t *fcport);
};

int qla2xxx_tgt_register_driver(struct qla_tgt_data *tgt);

void qla2xxx_tgt_unregister_driver(void);

int qla2x00_wait_for_loop_ready(scsi_qla_host_t *ha);
int qla2x00_wait_for_hba_online(scsi_qla_host_t *ha);

#endif /* __QLA2X_TGT_DEF_H */
