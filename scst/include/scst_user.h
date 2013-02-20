/*
 *  include/scst_user.h
 *
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  Contains constants and data structures for scst_user module.
 *  See http://scst.sourceforge.net/doc/scst_user_spec.txt or
 *  scst_user_spec.txt for description.
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

#ifndef __SCST_USER_H
#define __SCST_USER_H

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_const.h>
#else
#include <scst_const.h>
#endif

#define DEV_USER_NAME			"scst_user"
#define DEV_USER_PATH			"/dev/"
#define DEV_USER_VERSION_NAME		SCST_VERSION_NAME
#define DEV_USER_VERSION		\
	DEV_USER_VERSION_NAME "$Revision$" SCST_CONST_VERSION

#define SCST_USER_PARSE_STANDARD	0
#define SCST_USER_PARSE_CALL		1
#define SCST_USER_PARSE_EXCEPTION	2
#define SCST_USER_MAX_PARSE_OPT		SCST_USER_PARSE_EXCEPTION

#define SCST_USER_ON_FREE_CMD_CALL	0
#define SCST_USER_ON_FREE_CMD_IGNORE	1
#define SCST_USER_MAX_ON_FREE_CMD_OPT	SCST_USER_ON_FREE_CMD_IGNORE

#define SCST_USER_MEM_NO_REUSE		0
#define SCST_USER_MEM_REUSE_READ	1
#define SCST_USER_MEM_REUSE_WRITE	2
#define SCST_USER_MEM_REUSE_ALL		3
#define SCST_USER_MAX_MEM_REUSE_OPT	SCST_USER_MEM_REUSE_ALL

#define SCST_USER_PARTIAL_TRANSFERS_NOT_SUPPORTED	0
#define SCST_USER_PARTIAL_TRANSFERS_SUPPORTED_ORDERED	1
#define SCST_USER_PARTIAL_TRANSFERS_SUPPORTED		2
#define SCST_USER_MAX_PARTIAL_TRANSFERS_OPT		\
		SCST_USER_PARTIAL_TRANSFERS_SUPPORTED

#ifndef __KERNEL__
#define aligned_u64 uint64_t __attribute__((aligned(8)))
#endif

#ifndef aligned_i64
#define aligned_i64 int64_t __attribute__((aligned(8)))
#endif

/*************************************************************
 ** Private ucmd states
 *************************************************************/
#define UCMD_STATE_NEW			0
#define UCMD_STATE_PARSING		1
#define UCMD_STATE_BUF_ALLOCING		2
#define UCMD_STATE_EXECING		3
#define UCMD_STATE_ON_FREEING		4
#define UCMD_STATE_ON_FREE_SKIPPED	5
#define UCMD_STATE_ON_CACHE_FREEING	6
#define UCMD_STATE_TM_RECEIVED_EXECING	7
#define UCMD_STATE_TM_DONE_EXECING	8

#define UCMD_STATE_ATTACH_SESS		0x20
#define UCMD_STATE_DETACH_SESS		0x21

struct scst_user_opt {
	uint8_t parse_type;
	uint8_t on_free_cmd_type;
	uint8_t memory_reuse_type;
	uint8_t partial_transfers_type;
	int32_t partial_len;

	/* SCSI control mode page parameters, see SPC */
	uint8_t tst;
	uint8_t queue_alg;
	uint8_t tas;
	uint8_t swp;
	uint8_t d_sense;

	uint8_t has_own_order_mgmt;
};

struct scst_user_dev_desc {
	aligned_u64 version_str;
	aligned_u64 license_str;
	uint8_t type;
	uint8_t sgv_shared;
	uint8_t sgv_disable_clustered_pool;
	int32_t sgv_single_alloc_pages;
	int32_t sgv_purge_interval;
	struct scst_user_opt opt;
	uint32_t block_size;
	uint8_t enable_pr_cmds_notifications;
	char name[SCST_MAX_NAME];
	char sgv_name[SCST_MAX_NAME];
};

struct scst_user_sess {
	aligned_u64 sess_h;
	aligned_u64 lun;
	uint16_t threads_num;
	uint8_t rd_only;
	uint16_t scsi_transport_version;
	uint16_t phys_transport_version;
	char initiator_name[SCST_MAX_EXTERNAL_NAME];
	char target_name[SCST_MAX_EXTERNAL_NAME];
};

struct scst_user_scsi_cmd_parse {
	aligned_u64 sess_h;

	uint8_t cdb[SCST_MAX_CDB_SIZE];
	uint16_t cdb_len;

	aligned_i64 lba;

	aligned_i64 data_len;
	int32_t bufflen;
	int32_t out_bufflen;
	int32_t timeout;

	uint32_t op_flags;

	uint8_t queue_type;
	uint8_t data_direction;

	uint8_t expected_values_set;
	uint8_t expected_data_direction;
	int32_t expected_transfer_len;
	int32_t expected_out_transfer_len;

	uint32_t sn;
};

struct scst_user_scsi_cmd_alloc_mem {
	aligned_u64 sess_h;

	uint8_t cdb[SCST_MAX_CDB_SIZE];
	uint16_t cdb_len;

	int32_t alloc_len;

	uint8_t queue_type;
	uint8_t data_direction;

	uint32_t sn;
};

struct scst_user_scsi_cmd_exec {
	aligned_u64 sess_h;

	uint8_t cdb[SCST_MAX_CDB_SIZE];
	uint16_t cdb_len;

	aligned_i64 lba;

	aligned_i64 data_len;
	int32_t bufflen;
	int32_t alloc_len;
	aligned_u64 pbuf;
	uint8_t queue_type;
	uint8_t data_direction;
	uint8_t partial;
	int32_t timeout;

	aligned_u64 p_out_buf;
	int32_t out_bufflen;

	uint32_t sn;

	uint32_t parent_cmd_h;
	int32_t parent_cmd_data_len;
	uint32_t partial_offset;
};

struct scst_user_scsi_on_free_cmd {
	aligned_u64 pbuf;
	int32_t resp_data_len;
	uint8_t buffer_cached;
	uint8_t aborted;
	uint8_t status;
	uint8_t delivery_status;
};

struct scst_user_on_cached_mem_free {
	aligned_u64 pbuf;
};

struct scst_user_tm {
	aligned_u64 sess_h;
	uint32_t fn;
	uint32_t cmd_h_to_abort;
	uint32_t cmd_sn;
	uint8_t cmd_sn_set;
};

struct scst_user_get_cmd {
	uint32_t cmd_h;
	uint32_t subcode;
	union {
		aligned_u64 preply;
		struct scst_user_sess sess;
		struct scst_user_scsi_cmd_parse parse_cmd;
		struct scst_user_scsi_cmd_alloc_mem alloc_cmd;
		struct scst_user_scsi_cmd_exec exec_cmd;
		struct scst_user_scsi_on_free_cmd on_free_cmd;
		struct scst_user_on_cached_mem_free on_cached_mem_free;
		struct scst_user_tm tm_cmd;
	};
};

/* Be careful adding new members here, this structure is allocated on stack! */
struct scst_user_scsi_cmd_reply_parse {
	uint8_t status;
	union {
		struct {
			uint8_t queue_type;
			uint8_t data_direction;
			uint16_t cdb_len;
			aligned_i64 lba;
			aligned_i64 data_len;
			int32_t bufflen;
			uint32_t op_flags;
			int32_t out_bufflen;
		};
		struct {
			uint8_t sense_len;
			aligned_u64 psense_buffer;
		};
	};
};

/* Be careful adding new members here, this structure is allocated on stack! */
struct scst_user_scsi_cmd_reply_alloc_mem {
	aligned_u64 pbuf;
};

/* Be careful adding new members here, this structure is allocated on stack! */
struct scst_user_scsi_cmd_reply_exec {
	int32_t resp_data_len;
	aligned_u64 pbuf;

#define SCST_EXEC_REPLY_BACKGROUND	0
#define SCST_EXEC_REPLY_COMPLETED	1
	uint8_t reply_type;

	uint8_t status;
	uint8_t sense_len;
	aligned_u64 psense_buffer;
};

/* Be careful adding new members here, this structure is allocated on stack! */
struct scst_user_reply_cmd {
	uint32_t cmd_h;
	uint32_t subcode;
	union {
		int32_t result;
		struct scst_user_scsi_cmd_reply_parse parse_reply;
		struct scst_user_scsi_cmd_reply_alloc_mem alloc_reply;
		struct scst_user_scsi_cmd_reply_exec exec_reply;
	};
};

/* Be careful adding new members here, this structure is allocated on stack! */
struct scst_user_get_ext_cdb {
	uint32_t cmd_h;
	aligned_u64 ext_cdb_buffer;
};

/* Be careful adding new members here, this structure is allocated on stack! */
struct scst_user_prealloc_buffer_in {
	aligned_u64 pbuf;
	uint32_t bufflen;
	uint8_t for_clust_pool;
};

/* Be careful adding new members here, this structure is allocated on stack! */
struct scst_user_prealloc_buffer_out {
	uint32_t cmd_h;
};

/* Be careful adding new members here, this structure is allocated on stack! */
union scst_user_prealloc_buffer {
	struct scst_user_prealloc_buffer_in in;
	struct scst_user_prealloc_buffer_out out;
};

#define SCST_USER_REGISTER_DEVICE	_IOW('u', 1, struct scst_user_dev_desc)
#define SCST_USER_UNREGISTER_DEVICE	_IO('u', 2)
#define SCST_USER_SET_OPTIONS		_IOW('u', 3, struct scst_user_opt)
#define SCST_USER_GET_OPTIONS		_IOR('u', 4, struct scst_user_opt)
#define SCST_USER_REPLY_AND_GET_CMD	_IOWR('u', 5, struct scst_user_get_cmd)
#define SCST_USER_REPLY_CMD		_IOW('u', 6, struct scst_user_reply_cmd)
#define SCST_USER_FLUSH_CACHE		_IO('u', 7)
#define SCST_USER_DEVICE_CAPACITY_CHANGED _IO('u', 8)
#define SCST_USER_GET_EXTENDED_CDB	_IOWR('u', 9, struct scst_user_get_ext_cdb)
#define SCST_USER_PREALLOC_BUFFER	_IOWR('u', 10, union scst_user_prealloc_buffer)

/* Values for scst_user_get_cmd.subcode */
#define SCST_USER_ATTACH_SESS		\
	_IOR('s', UCMD_STATE_ATTACH_SESS, struct scst_user_sess)
#define SCST_USER_DETACH_SESS		\
	_IOR('s', UCMD_STATE_DETACH_SESS, struct scst_user_sess)
#define SCST_USER_PARSE			\
	_IOWR('s', UCMD_STATE_PARSING, struct scst_user_scsi_cmd_parse)
#define SCST_USER_ALLOC_MEM		\
	_IOWR('s', UCMD_STATE_BUF_ALLOCING, struct scst_user_scsi_cmd_alloc_mem)
#define SCST_USER_EXEC			\
	_IOWR('s', UCMD_STATE_EXECING, struct scst_user_scsi_cmd_exec)
#define SCST_USER_ON_FREE_CMD		\
	_IOR('s', UCMD_STATE_ON_FREEING, struct scst_user_scsi_on_free_cmd)
#define SCST_USER_ON_CACHED_MEM_FREE            \
	_IOR('s', UCMD_STATE_ON_CACHE_FREEING,  \
	struct scst_user_on_cached_mem_free)
#define SCST_USER_TASK_MGMT_RECEIVED		\
	_IOWR('s', UCMD_STATE_TM_RECEIVED_EXECING, struct scst_user_tm)
#define SCST_USER_TASK_MGMT_DONE		\
	_IOWR('s', UCMD_STATE_TM_DONE_EXECING, struct scst_user_tm)

#endif /* __SCST_USER_H */
