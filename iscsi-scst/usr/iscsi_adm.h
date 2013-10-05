/*
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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

#ifndef _ISCSI_ADM_H
#define _ISCSI_ADM_H

#define ISCSI_ADM_NAMESPACE "ISCSI_SCST_ADM"

struct msg_trgt {
	char name[ISCSI_NAME_LEN];
	char alias[ISCSI_NAME_LEN];

	u32 type;
	u32 session_partial;
	u32 target_partial;
	struct iscsi_param session_params[session_key_last];
	struct iscsi_param target_params[target_key_last];
};

struct msg_acnt {
	u32 auth_dir;
	union {
		struct {
			char name[ISCSI_NAME_LEN];
			char pass[ISCSI_NAME_LEN];
		} user;
		struct {
			u32 alloc_len;
			u32 count;
			u32 overflow;
		} list;
	} u;
};

enum iscsi_adm_cmnd {
	C_TRGT_NEW,
	C_TRGT_DEL,
	C_TRGT_UPDATE,
	C_TRGT_SHOW,

	C_SESS_NEW,
	C_SESS_DEL,
	C_SESS_UPDATE,
	C_SESS_SHOW,

	C_CONN_NEW,
	C_CONN_DEL,
	C_CONN_UPDATE,
	C_CONN_SHOW,

	C_ACCT_NEW,
	C_ACCT_DEL,
	C_ACCT_UPDATE,
	C_ACCT_SHOW,

	C_ACCT_LIST,
};

struct iscsi_adm_req {
	enum iscsi_adm_cmnd rcmnd;

	u32 tid;
	u64 sid;
	u32 cid;
	u32 lun;

	union {
		struct msg_trgt trgt;
		struct msg_acnt acnt;
	} u;
};

struct iscsi_adm_rsp {
	int err;
};

#endif
