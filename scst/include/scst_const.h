/*
 *  include/scst_const.h
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  Contains common SCST constants. This file supposed to be included
 *  from both kernel and user spaces.
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

#ifndef __SCST_CONST_H
#define __SCST_CONST_H

#ifndef GENERATING_UPSTREAM_PATCH
/*
 * Include <linux/version.h> only when not converting this header file into
 * a patch for upstream review because only then the symbol LINUX_VERSION_CODE
 * is needed.
 */
#include <linux/version.h>
#endif
#include <scsi/scsi.h>

#ifndef __KERNEL__
#include <errno.h>
#endif

/*
 * Version numbers, the same as for the kernel.
 *
 * Changing it don't forget to change SCST_FIO_REV in scst_vdisk.c
 * and FIO_REV in usr/fileio/common.h as well.
 */
#define SCST_VERSION(a, b, c, d)    (((a) << 24) + ((b) << 16) + ((c) << 8) + d)
#define SCST_VERSION_CODE	    SCST_VERSION(3, 0, 0, 0)
#ifdef CONFIG_SCST_PROC
#define SCST_VERSION_STRING_SUFFIX  "-procfs"
#else
#define SCST_VERSION_STRING_SUFFIX
#endif
#define SCST_VERSION_NAME	    "3.0.0-pre2"
#define SCST_VERSION_STRING	    SCST_VERSION_NAME SCST_VERSION_STRING_SUFFIX

#define SCST_CONST_VERSION "$Revision$"

/*** Shared constants between user and kernel spaces ***/

/* Max size of CDB */
#define SCST_MAX_CDB_SIZE            16

/* Max size of long CDB */
#define SCST_MAX_LONG_CDB_SIZE	     65536

/* Max size of various names */
#define SCST_MAX_NAME		     50

/* Max size of external names, like initiator name */
#define SCST_MAX_EXTERNAL_NAME	     256

/* Max LUN. 2 bits are used for addressing method. */
#define SCST_MAX_LUN		     ((1 << (16-2)) - 1)

/*
 * Size of sense sufficient to carry standard sense data.
 * Warning! It's allocated on stack!
 */
#define SCST_STANDARD_SENSE_LEN      18

/* Max size of sense */
#define SCST_SENSE_BUFFERSIZE        252

/*************************************************************
 ** Allowed delivery statuses for cmd's delivery_status
 *************************************************************/

#define SCST_CMD_DELIVERY_SUCCESS	0
#define SCST_CMD_DELIVERY_FAILED	-1
#define SCST_CMD_DELIVERY_ABORTED	-2

/*************************************************************
 ** Values for task management functions
 *************************************************************/
#define SCST_ABORT_TASK			0
#define SCST_ABORT_TASK_SET		1
#define SCST_CLEAR_ACA			2
#define SCST_CLEAR_TASK_SET		3
#define SCST_LUN_RESET			4
#define SCST_TARGET_RESET		5

/**
 ** SCST extensions
 **
 ** !! Adding new extensions don't forget to update
 ** !! scst_tm_fn_name as well!
 **/

/*
 * Notifies about I_T nexus loss event in the corresponding session.
 * Aborts all tasks there and sets up the I_T Nexus loss UA.
 */
#define SCST_NEXUS_LOSS_SESS		6

/* Aborts all tasks in the corresponding session */
#define SCST_ABORT_ALL_TASKS_SESS	7

/*
 * Notifies about I_T nexus loss event. Aborts all tasks in all sessions
 * of the tgt, and sets up in them the I_T Nexus loss UA.
 */
#define SCST_NEXUS_LOSS			8

/* Aborts all tasks in all sessions of the tgt */
#define SCST_ABORT_ALL_TASKS		9

/*
 * Internal TM command issued by SCST in scst_unregister_session(). It is the
 * same as SCST_NEXUS_LOSS_SESS, except:
 *  - it doesn't call task_mgmt_affected_cmds_done()
 *  - it doesn't call task_mgmt_fn_done()
 *  - it doesn't queue NEXUS LOSS UA.
 *
 * Target drivers must NEVER use it!!
 */
#define SCST_UNREG_SESS_TM		10

/*
 * Internal TM command issued by SCST in scst_pr_abort_reg(). It aborts all
 * tasks from mcmd->origin_pr_cmd->tgt_dev, except mcmd->origin_pr_cmd.
 * Additionally:
 *  - it signals pr_aborting_cmpl completion when all affected
 *    commands marked as aborted.
 *  - it doesn't call task_mgmt_affected_cmds_done()
 *  - it doesn't call task_mgmt_fn_done()
 *  - it calls mcmd->origin_pr_cmd->scst_cmd_done() when all affected
 *    commands aborted.
 *
 * Target drivers must NEVER use it!!
 */
#define SCST_PR_ABORT_ALL		11

/*************************************************************
 ** Values for mgmt cmd's status field. Codes taken from iSCSI
 *************************************************************/
#define SCST_MGMT_STATUS_SUCCESS		0
#define SCST_MGMT_STATUS_TASK_NOT_EXIST		-1
#define SCST_MGMT_STATUS_LUN_NOT_EXIST		-2
#define SCST_MGMT_STATUS_FN_NOT_SUPPORTED	-5
#define SCST_MGMT_STATUS_REJECTED		-255
#define SCST_MGMT_STATUS_FAILED			-129

/* Extra status meaning that the received stage completed, not done */
#define SCST_MGMT_STATUS_RECEIVED_STAGE_COMPLETED 200

/*************************************************************
 ** SCSI LUN addressing methods. See also SAM-2 and the
 ** section about eight byte LUNs.
 *************************************************************/
enum scst_lun_addr_method {
	SCST_LUN_ADDR_METHOD_PERIPHERAL	  = 0,
	SCST_LUN_ADDR_METHOD_FLAT	  = 1,
	SCST_LUN_ADDR_METHOD_LUN	  = 2,
	SCST_LUN_ADDR_METHOD_EXTENDED_LUN = 3,
};

/*************************************************************
 ** SCSI task attribute queue types
 *************************************************************/
enum scst_cmd_queue_type {
	SCST_CMD_QUEUE_UNTAGGED = 0,
	SCST_CMD_QUEUE_SIMPLE,
	SCST_CMD_QUEUE_ORDERED,
	SCST_CMD_QUEUE_HEAD_OF_QUEUE,
	SCST_CMD_QUEUE_ACA
};

/***************************************************************
 ** CDB flags. All must be single bit fit in int32. Bit fields
 ** approach (unsigned int x:1) was not used, because those
 ** flags supposed to be passed to the user space where another
 ** compiler with another bitfields layout can be used.
 ***************************************************************/
enum scst_cdb_flags {
	/*
	 * !! Both timeouts must be the lowest bits to match
	 * !! scst_generic_parse() expectations!
	 */
	SCST_SMALL_TIMEOUT =			0x0001,
	SCST_LONG_TIMEOUT =			0x0002,
#define	SCST_BOTH_TIMEOUTS	(SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)
	SCST_TRANSFER_LEN_TYPE_FIXED =		0x0004,
	SCST_UNKNOWN_LBA =			0x0008,
	SCST_UNKNOWN_LENGTH =			0x0010,
	SCST_INFO_VALID =			0x0020,

	/*
	 * Set if LBA not defined for this CDB. The "NOT" approach
	 * was used to make sure that all dev handlers either init
	 * cmd->lba or set this flag (for backward compatibility)
	 */
	SCST_LBA_NOT_VALID =			0x0040,

	SCST_IMPLICIT_HQ =			0x0080,
	SCST_SKIP_UA =				0x0100,
	SCST_WRITE_MEDIUM =			0x0200,
	SCST_LOCAL_CMD =			0x0400,

	/*
	 * Set if CDB is fully locally handled by SCST. Dev handlers
	 * parse() and dev_done() not called for such commands
	 */
	SCST_FULLY_LOCAL_CMD =			0x0800,

	SCST_REG_RESERVE_ALLOWED =		0x1000,
	SCST_WRITE_EXCL_ALLOWED =		0x2000,
	SCST_EXCL_ACCESS_ALLOWED =		0x4000,
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
	SCST_TEST_IO_IN_SIRQ_ALLOWED =		0x8000,
#endif
	SCST_SERIALIZED =		       0x10000,
	SCST_STRICTLY_SERIALIZED =	       0x20000|SCST_SERIALIZED,
	SCST_DESCRIPTORS_BASED =	       0x40000,
};

/*************************************************************
 ** Data direction aliases. Changing it don't forget to change
 ** scst_to_tgt_dma_dir and SCST_DATA_DIR_MAX as well!!
 *************************************************************/
#define SCST_DATA_UNKNOWN		0
#define SCST_DATA_WRITE			1
#define SCST_DATA_READ			2
#define SCST_DATA_BIDI			(SCST_DATA_WRITE | SCST_DATA_READ)
#define SCST_DATA_NONE			4

#define SCST_DATA_DIR_MAX		(SCST_DATA_NONE+1)

#ifdef CONFIG_SCST_PROC

/*************************************************************
 ** Name of the "Default" security group
 *************************************************************/
#define SCST_DEFAULT_ACG_NAME			"Default"

#endif

/*************************************************************
 ** Default suffix for targets with NULL names
 *************************************************************/
#define SCST_DEFAULT_TGT_NAME_SUFFIX		"_target_"

/*************************************************************
 ** Sense manipulation and examination
 *************************************************************/
#define SCST_LOAD_SENSE(key_asc_ascq) key_asc_ascq

static inline int scst_sense_valid(const uint8_t *sense)
{
	return ((sense != NULL) && ((sense[0] & 0x70) == 0x70));
}

static inline int scst_no_sense(const uint8_t *sense)
{
	return ((sense != NULL) && (sense[2] == 0));
}

static inline int scst_sense_response_code(const uint8_t *sense)
{
	return sense[0] & 0x7F;
}

/*************************************************************
 ** Sense data for the appropriate errors. Can be used with
 ** scst_set_cmd_error(). Column order: key, ASC, ASCQ. See
 ** also http://www.t10.org/lists/asc-num.htm.
 *************************************************************/

/* NO_SENSE is 0 */
#define scst_sense_no_sense			NO_SENSE,        0x00, 0

/* NOT_READY is 2 */
#define scst_sense_format_in_progress		NOT_READY,       0x04, 0x04
#define scst_sense_tp_transitioning		NOT_READY,	 0x04, 0x0A
#define scst_sense_tp_unav			NOT_READY,	 0x04, 0x0C
#define scst_sense_not_ready			NOT_READY,       0x04, 0x10
#define scst_sense_no_medium			NOT_READY,       0x3a, 0

/* MEDIUM_ERROR is 3 */
#define scst_sense_write_error			MEDIUM_ERROR,    0x03, 0
#define scst_sense_read_error			MEDIUM_ERROR,    0x11, 0

/* HARDWARE_ERROR is 4 */
#define scst_sense_hardw_error			HARDWARE_ERROR,  0x44, 0

/* ILLEGAL_REQUEST is 5 */
#define scst_sense_invalid_opcode		ILLEGAL_REQUEST, 0x20, 0
#define scst_sense_block_out_range_error	ILLEGAL_REQUEST, 0x21, 0
/* Don't use it directly, use scst_set_invalid_field_in_cdb() instead! */
#define scst_sense_invalid_field_in_cdb		ILLEGAL_REQUEST, 0x24, 0
#define scst_sense_lun_not_supported		ILLEGAL_REQUEST, 0x25, 0
/* Don't use it directly, use scst_set_invalid_field_in_parm_list() instead! */
#define scst_sense_invalid_field_in_parm_list	ILLEGAL_REQUEST, 0x26, 0
#define scst_sense_parameter_value_invalid	ILLEGAL_REQUEST, 0x26, 2
#define scst_sense_invalid_release		ILLEGAL_REQUEST, 0x26, 4
#define scst_sense_saving_params_unsup		ILLEGAL_REQUEST, 0x39, 0
#define scst_sense_invalid_message		ILLEGAL_REQUEST, 0x49, 0
#define scst_sense_parameter_list_length_invalid ILLEGAL_REQUEST, 0x1A, 0
#define scst_sense_invalid_field_in_command_information_unit ILLEGAL_REQUEST, 0xE, 0x3

/* UNIT_ATTENTION is 6 */
#define scst_sense_medium_changed_UA		UNIT_ATTENTION,  0x28, 0
#define scst_sense_reset_UA			UNIT_ATTENTION,  0x29, 0
#define scst_sense_nexus_loss_UA		UNIT_ATTENTION,  0x29, 0x7
#define scst_sense_reservation_preempted	UNIT_ATTENTION,  0x2A, 0x03
#define scst_sense_reservation_released		UNIT_ATTENTION,  0x2A, 0x04
#define scst_sense_registrations_preempted	UNIT_ATTENTION,  0x2A, 0x05
#define scst_sense_asym_access_state_changed	UNIT_ATTENTION,  0x2A, 0x06
#define scst_sense_capacity_data_changed	UNIT_ATTENTION,  0x2A, 0x9
#define scst_sense_cleared_by_another_ini_UA	UNIT_ATTENTION,  0x2F, 0
#define scst_sense_inquiry_data_changed		UNIT_ATTENTION,  0x3F, 0x3
#define scst_sense_reported_luns_data_changed	UNIT_ATTENTION,  0x3F, 0xE

/* DATA_PROTECT is 7 */
#define scst_sense_data_protect			DATA_PROTECT,    0x00, 0

/* ABORTED_COMMAND is 0xb */
#define scst_sense_aborted_command		ABORTED_COMMAND, 0x00, 0

/* MISCOMPARE is 0xe */
#define scst_sense_miscompare_error		MISCOMPARE,      0x1D, 0


/*************************************************************
 * SCSI opcodes not listed anywhere else
 *************************************************************/
#define INIT_ELEMENT_STATUS         0x07
#define INIT_ELEMENT_STATUS_RANGE   0x37
#define PREVENT_ALLOW_MEDIUM        0x1E
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) \
	&& (!defined(RHEL_MAJOR) || RHEL_MAJOR -0 <= 5)
#define READ_ATTRIBUTE              0x8C
#endif
#define REQUEST_VOLUME_ADDRESS      0xB5
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) \
	&& (!defined(RHEL_MAJOR) || RHEL_MAJOR -0 <= 5)
#define WRITE_ATTRIBUTE             0x8D
#endif
#define WRITE_VERIFY_16             0x8E
#define VERIFY_6                    0x13
#ifndef VERIFY_12
#define VERIFY_12                   0xAF
#endif
#if !defined(GENERATING_UPSTREAM_PATCH) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
/*
 * The constants below have been defined in the kernel header <scsi/scsi.h>
 * and hence are not needed when this header file is included in kernel code.
 * The definitions below are only used when this header file is included during
 * compilation of SCST's user space components.
 */
#ifndef GET_EVENT_STATUS_NOTIFICATION
/* Upstream commit 93aae17a (v2.6.38) */
#define GET_EVENT_STATUS_NOTIFICATION 0x4a
#endif
#ifndef READ_16
#define READ_16               0x88
#endif
#ifndef WRITE_16
#define WRITE_16              0x8a
#endif
#ifndef VERIFY_16
#define VERIFY_16	      0x8f
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
#ifndef MI_REPORT_IDENTIFYING_INFORMATION
#define MI_REPORT_IDENTIFYING_INFORMATION 0x05
#endif
#ifndef MI_REPORT_SUPPORTED_OPERATION_CODES
#define MI_REPORT_SUPPORTED_OPERATION_CODES 0x0c
#endif
#ifndef MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS
#define MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS 0x0d
#endif
#endif
#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN     0x9e
#endif
#ifndef SAI_READ_CAPACITY_16
/* values for service action in */
#define	SAI_READ_CAPACITY_16  0x10
#endif
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#ifndef SAI_GET_LBA_STATUS
#define SAI_GET_LBA_STATUS    0x12
#endif
#endif
#ifndef GENERATING_UPSTREAM_PATCH
#ifndef REPORT_LUNS
#define REPORT_LUNS           0xa0
#endif
#endif

#ifndef WRITE_SAME_16
#define WRITE_SAME_16	      0x93
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
/*
 * From <scsi/scsi.h>. See also commit
 * f57e4502cea471c69782d4790c71d8414ab49a9d.
 */
#define UNMAP 0x42
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
/*
 * From <linux/fs.h>. See also commit
 * d30a2605be9d5132d95944916e8f578fcfe4f976.
 */
#define BLKDISCARD _IO(0x12,119)
#endif


/*************************************************************
 **  SCSI Architecture Model (SAM) Status codes. Taken from SAM-3 draft
 **  T10/1561-D Revision 4 Draft dated 7th November 2002.
 *************************************************************/
#define SAM_STAT_GOOD            0x00
#define SAM_STAT_CHECK_CONDITION 0x02
#define SAM_STAT_CONDITION_MET   0x04
#define SAM_STAT_BUSY            0x08
#define SAM_STAT_INTERMEDIATE    0x10
#define SAM_STAT_INTERMEDIATE_CONDITION_MET 0x14
#define SAM_STAT_RESERVATION_CONFLICT 0x18
#define SAM_STAT_COMMAND_TERMINATED 0x22	/* obsolete in SAM-3 */
#define SAM_STAT_TASK_SET_FULL   0x28
#define SAM_STAT_ACA_ACTIVE      0x30
#define SAM_STAT_TASK_ABORTED    0x40

/*************************************************************
 ** Control byte field in CDB
 *************************************************************/
#define CONTROL_BYTE_LINK_BIT       0x01
#define CONTROL_BYTE_NACA_BIT       0x04

/*************************************************************
 ** Byte 1 in INQUIRY CDB
 *************************************************************/
#define SCST_INQ_EVPD                0x01

/*************************************************************
 ** Byte 3 in Standard INQUIRY data
 *************************************************************/
#define SCST_INQ_BYTE3               3

#define SCST_INQ_NORMACA_BIT         0x20

/*************************************************************
 ** TPGS field in byte 5 of the INQUIRY response (SPC-4).
 *************************************************************/
enum {
	SCST_INQ_TPGS_MODE_IMPLICIT = 0x10,
	SCST_INQ_TPGS_MODE_EXPLICIT = 0x20,
};

/*************************************************************
 ** Byte 2 in RESERVE_10 CDB
 *************************************************************/
#define SCST_RES_3RDPTY              0x10
#define SCST_RES_LONGID              0x02

/*************************************************************
 ** Values for the control mode page TST field
 *************************************************************/
#define SCST_CONTR_MODE_ONE_TASK_SET  0
#define SCST_CONTR_MODE_SEP_TASK_SETS 1

/*******************************************************************
 ** Values for the control mode page QUEUE ALGORITHM MODIFIER field
 *******************************************************************/
#define SCST_CONTR_MODE_QUEUE_ALG_RESTRICTED_REORDER   0
#define SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER 1

/*************************************************************
 ** Values for the control mode page D_SENSE field
 *************************************************************/
#define SCST_CONTR_MODE_FIXED_SENSE  0
#define SCST_CONTR_MODE_DESCR_SENSE 1

/*************************************************************
 ** TransportID protocol identifiers
 *************************************************************/

#define SCSI_TRANSPORTID_PROTOCOLID_FCP2	0
#define SCSI_TRANSPORTID_PROTOCOLID_SPI5	1
#define SCSI_TRANSPORTID_PROTOCOLID_SRP		4
#define SCSI_TRANSPORTID_PROTOCOLID_ISCSI	5
#define SCSI_TRANSPORTID_PROTOCOLID_SAS		6

/**
 * enum scst_tg_state - SCSI target port group asymmetric access state.
 *
 * See also the documentation of the REPORT TARGET PORT GROUPS command in SPC-4.
 */
enum scst_tg_state {
	SCST_TG_STATE_UNDEFINED         =  -1,
	SCST_TG_STATE_OPTIMIZED		= 0x0,
	SCST_TG_STATE_NONOPTIMIZED	= 0x1,
	SCST_TG_STATE_STANDBY		= 0x2,
	SCST_TG_STATE_UNAVAILABLE	= 0x3,
	SCST_TG_STATE_LBA_DEPENDENT	= 0x4,
	SCST_TG_STATE_OFFLINE		= 0xe,
	SCST_TG_STATE_TRANSITIONING	= 0xf,
};

/**
 * Target port group preferred bit.
 *
 * See also the documentation of the REPORT TARGET PORT GROUPS command in SPC-4.
 */
enum {
	SCST_TG_PREFERRED = 0x80,
};

/**
 * enum scst_tg_sup - Supported SCSI target port group states.
 *
 * See also the documentation of the REPORT TARGET PORT GROUPS command in SPC-4.
 */
enum scst_tg_sup {
	SCST_TG_SUP_OPTIMIZED		= 0x01,
	SCST_TG_SUP_NONOPTIMIZED	= 0x02,
	SCST_TG_SUP_STANDBY		= 0x04,
	SCST_TG_SUP_UNAVAILABLE		= 0x08,
	SCST_TG_SUP_LBA_DEPENDENT	= 0x10,
	SCST_TG_SUP_OFFLINE		= 0x40,
	SCST_TG_SUP_TRANSITION		= 0x80,
};

/*************************************************************
 ** Misc SCSI constants
 *************************************************************/
#define SCST_SENSE_ASC_UA_RESET      0x29
#define BYTCHK			     0x02
#define POSITION_LEN_SHORT           20
#define POSITION_LEN_LONG            32

/*************************************************************
 ** Various timeouts
 *************************************************************/
#define SCST_DEFAULT_TIMEOUT			(30 * HZ)

#define SCST_GENERIC_CHANGER_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_CHANGER_LONG_TIMEOUT	(14000 * HZ)

#define SCST_GENERIC_PROCESSOR_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_PROCESSOR_LONG_TIMEOUT	(14000 * HZ)

#define SCST_GENERIC_TAPE_SMALL_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_TAPE_REG_TIMEOUT		(900 * HZ)
#define SCST_GENERIC_TAPE_LONG_TIMEOUT		(14000 * HZ)

#define SCST_GENERIC_MODISK_SMALL_TIMEOUT	(3 * HZ)
#define SCST_GENERIC_MODISK_REG_TIMEOUT		(900 * HZ)
#define SCST_GENERIC_MODISK_LONG_TIMEOUT	(14000 * HZ)

#define SCST_GENERIC_DISK_SMALL_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_DISK_REG_TIMEOUT		(30 * HZ)
#define SCST_GENERIC_DISK_LONG_TIMEOUT		(3600 * HZ)

#define SCST_GENERIC_RAID_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_RAID_LONG_TIMEOUT		(14000 * HZ)

#define SCST_GENERIC_CDROM_SMALL_TIMEOUT	(3 * HZ)
#define SCST_GENERIC_CDROM_REG_TIMEOUT		(900 * HZ)
#define SCST_GENERIC_CDROM_LONG_TIMEOUT		(14000 * HZ)

#define SCST_MAX_OTHER_TIMEOUT			(14000 * HZ)

/*************************************************************
 ** I/O grouping attribute string values. Must match constants
 ** w/o '_STR' suffix!
 *************************************************************/
#define SCST_IO_GROUPING_AUTO_STR		"auto"
#define SCST_IO_GROUPING_THIS_GROUP_ONLY_STR	"this_group_only"
#define SCST_IO_GROUPING_NEVER_STR		"never"

/*************************************************************
 ** Threads pool type attribute string values.
 ** Must match scst_dev_type_threads_pool_type!
 *************************************************************/
#define SCST_THREADS_POOL_PER_INITIATOR_STR	"per_initiator"
#define SCST_THREADS_POOL_SHARED_STR		"shared"

/*************************************************************
 ** Misc constants
 *************************************************************/
#define SCST_SYSFS_BLOCK_SIZE			PAGE_SIZE

#define SCST_PR_DIR				"/var/lib/scst/pr"

#define TID_COMMON_SIZE				24

#define SCST_SYSFS_KEY_MARK			"[key]"

#define SCST_MIN_REL_TGT_ID			1
#define SCST_MAX_REL_TGT_ID			65535

/*
 * Error code returned by target attribute sysfs methods if invoked after
 * scst_register_target() finished but before before scst_tgt_set_tgt_priv()
 * has been invoked.
 */
enum {
	E_TGT_PRIV_NOT_YET_SET = EBUSY
};

#endif /* __SCST_CONST_H */
