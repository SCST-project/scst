/*
 *  Copyright (C) 2007 Vladislav Bolkhovitin
 *  Copyright (C) 2007 CMS Distribution Limited
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

#ifndef _ISCSI_U_H
#define _ISCSI_U_H

#ifndef __KERNEL__
#include <sys/uio.h>
#endif

#define ISCSI_VERSION_STRING	"0.9.6/0.4.15r147"

/* The maximum length of 223 bytes in the RFC. */
#define ISCSI_NAME_LEN	256

#define ISCSI_LISTEN_PORT	3260

#define SCSI_ID_LEN	24

#ifndef aligned_u64
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#endif

struct target_info {
	u32 tid;
	char name[ISCSI_NAME_LEN];
};

struct session_info {
	u32 tid;

	aligned_u64 sid;
	char initiator_name[ISCSI_NAME_LEN];
	char user_name[ISCSI_NAME_LEN];
	u32 exp_cmd_sn;
};

#define DIGEST_ALL	(DIGEST_NONE | DIGEST_CRC32C)
#define DIGEST_NONE		(1 << 0)
#define DIGEST_CRC32C           (1 << 1)

struct conn_info {
	u32 tid;
	aligned_u64 sid;

	u32 cid;
	u32 stat_sn;
	u32 exp_stat_sn;
	int header_digest;
	int data_digest;
	int fd;
};

enum {
	key_initial_r2t,
	key_immediate_data,
	key_max_connections,
	key_max_recv_data_length,
	key_max_xmit_data_length,
	key_max_burst_length,
	key_first_burst_length,
	key_default_wait_time,
	key_default_retain_time,
	key_max_outstanding_r2t,
	key_data_pdu_inorder,
	key_data_sequence_inorder,
	key_error_recovery_level,
	key_header_digest,
	key_data_digest,
	key_ofmarker,
	key_ifmarker,
	key_ofmarkint,
	key_ifmarkint,
	session_key_last,
};

enum {
	key_queued_cmnds,
	target_key_last,
};

enum {
	key_session,
	key_target,
};

struct iscsi_param_info {
	u32 tid;
	aligned_u64 sid;

	u32 param_type;
	u32 partial;

	u32 session_param[session_key_last];
	u32 target_param[target_key_last];
};

enum iscsi_event_state {
	E_CONN_CLOSE,
};

struct iscsi_event {
	u32 tid;
	aligned_u64 sid;
	u32 cid;
	u32 state;
};

#define	DEFAULT_NR_QUEUED_CMNDS	32
#define	MIN_NR_QUEUED_CMNDS	1
#define	MAX_NR_QUEUED_CMNDS	256

#define MAX_DATA_SEG_LEN	(4096/sizeof(struct iovec)*4096)

#define NETLINK_ISCSI_SCST	25

#define ADD_TARGET _IOW('i', 0, struct target_info)
#define DEL_TARGET _IOW('i', 1, struct target_info)
#define ADD_SESSION _IOW('i', 2, struct session_info)
#define DEL_SESSION _IOW('i', 3, struct session_info)
#define GET_SESSION_INFO _IOWR('i', 4, struct session_info)
#define ADD_CONN _IOW('i', 5, struct conn_info)
#define DEL_CONN _IOW('i', 6, struct conn_info)
#define GET_CONN_INFO _IOWR('i', 7, struct conn_info)
#define ISCSI_PARAM_SET _IOW('i', 8, struct iscsi_param_info)
#define ISCSI_PARAM_GET _IOWR('i', 9, struct iscsi_param_info)

static inline int iscsi_is_key_declarative(int key)
{
	switch(key)
	{
	case key_max_xmit_data_length:
		return 1;
	default:
		return 0;
	}
}

#endif
