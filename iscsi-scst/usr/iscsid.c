/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2010 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "iscsid.h"

int iscsi_enabled;

static u32 ttt;

static u32 get_next_ttt(struct connection *conn __attribute__((unused)))
{
	ttt += 1;
	return (ttt == ISCSI_RESERVED_TAG) ? ++ttt : ttt;
}

static struct iscsi_key login_keys[] = {
	{"InitiatorName",},
	{"InitiatorAlias",},
	{"SessionType",},
	{"TargetName",},
	{NULL,},
};

char *text_key_find(struct connection *conn, char *searchKey)
{
	char *data, *key, *value;
	int keylen, datasize;

	keylen = strlen(searchKey);
	data = conn->req.data;
	datasize = conn->req.datasize;

	while (1) {
		for (key = data; datasize > 0 && *data != '='; data++, datasize--)
			;
		if (!datasize)
			return NULL;
		data++;
		datasize--;

		for (value = data; datasize > 0 && *data != 0; data++, datasize--)
			;
		if (!datasize)
			return NULL;
		data++;
		datasize--;

		if (keylen == value - key - 1
		     && !strncasecmp(key, searchKey, keylen))
			return value;
	}
}

static char *next_key(char **data, int *datasize, char **value)
{
	char *key, *p, *q;
	int size = *datasize;

	key = p = *data;
	for (; size > 0 && *p != '='; p++, size--)
		;
	if (!size)
		return NULL;
	*p++ = 0;
	size--;

	for (q = p; size > 0 && *p != 0; p++, size--)
		;
	if (!size)
		return NULL;
	p++;
	size--;

	*data = p;
	*value = q;
	*datasize = size;

	return key;
}

static struct buf_segment *conn_alloc_buf_segment(struct connection *conn,
						   size_t sz)
{
	struct buf_segment *seg = malloc(sizeof *seg + sz);

	if (seg) {
		seg->len = 0;
		memset(seg->data, 0x0, sz);
		list_add_tail(&seg->entry, &conn->rsp_buf_list);
		log_debug(2, "alloc'ed new buf_segment");
	}

	return seg;
}

void text_key_add(struct connection *conn, char *key, const char *value)
{
	struct buf_segment *seg;
	int keylen = strlen(key);
	int valuelen = strlen(value);
	int len = keylen + valuelen + 2;
	int off = 0;
	int sz = 0;
	int stage = 0;
	size_t data_sz;

	data_sz = (conn->state == STATE_FULL) ?
		conn->session_params[key_max_xmit_data_length].val :
		INCOMING_BUFSIZE;

	seg = list_empty(&conn->rsp_buf_list) ? NULL :
		list_entry(conn->rsp_buf_list.q_back, struct buf_segment,
			   entry);

	while (len) {
		if (!seg || seg->len == data_sz) {
			seg = conn_alloc_buf_segment(conn, data_sz);
			if (!seg) {
				log_error("Failed to alloc text buf segment\n");
				conn_free_rsp_buf_list(conn);
				break;
			}
		}
		switch (stage) {
		case 0:
			sz = min_t(int, data_sz - seg->len, keylen - off);
			strncpy(seg->data + seg->len, key + off, sz);
			if (sz == data_sz - seg->len) {
				off += sz;
				if (keylen - off == 0) {
					off = 0;
					stage++;
				}
			} else {
				off = 0;
				stage++;
			}
			break;
		case 1:
			seg->data[seg->len] = '=';
			off = 0;
			sz = 1;
			stage++;
			break;
		case 2:
			sz = min_t(int, data_sz - seg->len, valuelen - off);
			strncpy(seg->data + seg->len, value + off, sz);
			off += sz;
			if (valuelen - off == 0) {
				off = 0;
				stage++;
			}
			break;
		case 3:
			seg->data[seg->len] = 0;
			sz = 1;
			break;
		}

		log_debug(2, "wrote: %s", seg->data + seg->len);

		seg->len += sz;
		len -= sz;
	}
}

static void text_key_add_reject(struct connection *conn, char *key)
{
	text_key_add(conn, key, "Reject");
}

static void text_scan_security(struct connection *conn)
{
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;
	char *key, *value, *data, *nextValue;
	int datasize;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while ((key = next_key(&data, &datasize, &value))) {
		if (!(params_index_by_name(key, login_keys) < 0))
			;
		else if (!strcmp(key, "AuthMethod")) {
			do {
				nextValue = strchr(value, ',');
				if (nextValue)
					*nextValue++ = 0;

				if (!strcmp(value, "None")) {
					if (!accounts_empty(conn->tid, ISCSI_USER_DIR_INCOMING))
						continue;
					conn->auth_method = AUTH_NONE;
					text_key_add(conn, key, "None");
					break;
				} else if (!strcmp(value, "CHAP")) {
					if (accounts_empty(conn->tid, ISCSI_USER_DIR_INCOMING))
						continue;
					conn->auth_method = AUTH_CHAP;
					text_key_add(conn, key, "CHAP");
					break;
				}
			} while ((value = nextValue));

			if (conn->auth_method == AUTH_UNKNOWN)
				text_key_add_reject(conn, key);
		} else
			text_key_add(conn, key, "NotUnderstood");
	}
	if (conn->auth_method == AUTH_UNKNOWN) {
		rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_STATUS_AUTH_FAILED;
		conn->state = STATE_EXIT;
	}
	return;
}

#define ISCSI_SESS_REINSTATEMENT	1
#define ISCSI_CONN_REINSTATEMENT	2

/*
 * Returns above ISCSI_*_REINSTATEMENT for session reinstatement,
 * <0 for error, 0 otherwise.
 */
static int login_check_reinstatement(struct connection *conn)
{
	struct iscsi_login_req_hdr *req = (struct iscsi_login_req_hdr *)&conn->req.bhs;
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;
	struct session *session;
	int res = 0;

	/*
	 * We only check here to catch errors earlier. Actual session/connection
	 * reinstatement, if necessary, will be done in the kernel.
	 */

	sBUG_ON(conn->sess != NULL);

	session = session_find_name(conn->tid, conn->initiator, req->sid);
	if (session != NULL) {
		if (req->sid.id.tsih == 0) {
			/* Kernel will do session reinstatement */
			log_debug(1, "Session sid %#" PRIx64 " reinstatement "
				"detected (tid %d, initiator %s)", req->sid.id64,
				conn->tid, conn->initiator);
			res = ISCSI_SESS_REINSTATEMENT;
		} else if (req->sid.id.tsih != session->sid.id.tsih) {
			log_error("TSIH for existing session sid %#" PRIx64
				") doesn't match (tid %d, initiator %s, sid requested "
				"%#" PRIx64, session->sid.id64, conn->tid,
				conn->initiator, req->sid.id64);
			/* Fail the login */
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_SESSION_NOT_FOUND;
			conn->state = STATE_EXIT;
			res = -1;
			goto out;
		} else {
			struct connection *c = conn_find(session, conn->cid);
			if (c != NULL) {
				/* Kernel will do connection reinstatement */
				log_debug(1, "Conn %x reinstatement "
					"detected (tid %d, sid %#" PRIx64
					"initiator %s)", conn->cid, conn->tid,
					req->sid.id64, conn->initiator);
				conn->sess = session;
				list_add_tail(&conn->clist, &session->conn_list);
				res = ISCSI_CONN_REINSTATEMENT;
			} else {
				log_error("Only a single connection supported "
					"(initiator %s)", conn->initiator);
				/* Fail the login */
				rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
				rsp->status_detail = ISCSI_STATUS_TOO_MANY_CONN;
				conn->state = STATE_EXIT;
				res = -1;
				goto out;
			}
		}
	} else {
		if (req->sid.id.tsih != 0) {
			log_error("Requested TSIH not 0 (TSIH %d, tid %d, "
				"initiator %s, sid requisted %#" PRIx64 ")",
				req->sid.id.tsih, conn->tid, conn->initiator,
				req->sid.id64);
			/* Fail the login */
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_SESSION_NOT_FOUND;
			conn->state = STATE_EXIT;
			res = -1;
			goto out;
		} else
			log_debug(1, "New session sid %#" PRIx64 "(tid %d, "
				"initiator %s)", req->sid.id64,
				conn->tid, conn->initiator);
	}

out:
	return res;
}

static void text_scan_login(struct connection *conn)
{
	char *key, *value, *data;
	int datasize, idx;
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while ((key = next_key(&data, &datasize, &value))) {
		if (!(params_index_by_name(key, login_keys) < 0))
			;
		else if (!strcmp(key, "AuthMethod"))
			;
		else if (!((idx = params_index_by_name(key, session_keys)) < 0)) {
			unsigned int val;
			char buf[32];

			if (idx == key_max_xmit_data_length) {
				text_key_add(conn, key, "NotUnderstood");
				continue;
			}
			if (idx == key_max_recv_data_length) {
				conn->session_params[idx].key_state = KEY_STATE_DONE;
				idx = key_max_xmit_data_length;
			};

			if (params_str_to_val(session_keys, idx, value, &val) < 0) {
				if (conn->session_params[idx].key_state == KEY_STATE_START) {
					text_key_add_reject(conn, key);
					continue;
				} else {
					rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
					rsp->status_detail = ISCSI_STATUS_INIT_ERR;
					conn->state = STATE_EXIT;
					goto out;
				}
			}

			params_check_val(session_keys, idx, &val);
			params_set_val(session_keys, conn->session_params, idx, &val);

			switch (conn->session_params[idx].key_state) {
			case KEY_STATE_START:
				if (iscsi_is_key_internal(idx)) {
					conn->session_params[idx].key_state = KEY_STATE_DONE;
					break;
				}
				memset(buf, 0, sizeof(buf));
				params_val_to_str(session_keys, idx, val, buf, sizeof(buf));
				text_key_add(conn, key, buf);
				conn->session_params[idx].key_state = KEY_STATE_DONE_ADDED;
				break;
			case KEY_STATE_REQUEST:
				if (val != conn->session_params[idx].val) {
					rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
					rsp->status_detail = ISCSI_STATUS_INIT_ERR;
					conn->state = STATE_EXIT;
					log_warning("%s %u %u\n", key,
						val, conn->session_params[idx].val);
					goto out;
				}
				conn->session_params[idx].key_state = KEY_STATE_DONE;
				break;
			case KEY_STATE_DONE_ADDED:
			case KEY_STATE_DONE:
				break;
			}
		} else
			text_key_add(conn, key, "NotUnderstood");
	}

out:
	return;
}

static int text_check_params(struct connection *conn)
{
	struct iscsi_param *p = conn->session_params;
	char buf[32];
	int i, cnt;

	for (i = 0, cnt = 0; session_keys[i].name; i++) {
		if (p[i].val != session_keys[i].rfc_def) {
			if (p[i].key_state == KEY_STATE_START) {
				log_debug(1, "Key %s was not negotiated, use RFC "
					"defined default %d",  session_keys[i].name,
					session_keys[i].rfc_def);
				p[i].val = session_keys[i].rfc_def;
				continue;
			} else if (p[i].key_state == KEY_STATE_DONE_ADDED) {
				log_debug(1, "Key %s was already added, val %d",
					session_keys[i].name, p[i].val);
				continue;
			}
			switch (conn->state) {
			case STATE_LOGIN_FULL:
			case STATE_SECURITY_FULL:
				if (iscsi_is_key_internal(i)) {
					p[i].key_state = KEY_STATE_DONE;
					continue;
				}
				break;
			case STATE_LOGIN:
				if (iscsi_is_key_internal(i))
					continue;
				memset(buf, 0, sizeof(buf));
				params_val_to_str(session_keys, i, p[i].val, buf, sizeof(buf));
				text_key_add(conn, session_keys[i].name, buf);
				if (i == key_max_recv_data_length) {
					p[i].key_state = KEY_STATE_DONE;
					continue;
				}
				p[i].key_state = KEY_STATE_REQUEST;
				break;
			default:
				if (iscsi_is_key_internal(i))
					continue;
			}
			cnt++;
		}
	}

	return cnt;
}

static int init_conn_session_params(struct connection *conn)
{
	int res = 0, i;
	struct target *target;

	target = target_find_by_id(conn->tid);
	if (target == NULL) {
		log_error("target %d not found", conn->tid);
		res = -EINVAL;
		goto out;
	}

	for (i = 0; i < session_key_last; i++)
		conn->session_params[i].val = target->session_params[i];

out:
	return res;
}

static void login_start(struct connection *conn)
{
	struct iscsi_login_req_hdr *req = (struct iscsi_login_req_hdr *)&conn->req.bhs;
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;
	char *name, *alias, *session_type, *target_name;

	conn->cid = be16_to_cpu(req->cid);
	conn->sid.id64 = req->sid.id64;

	name = text_key_find(conn, "InitiatorName");
	if (!name) {
		rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_STATUS_MISSING_FIELDS;
		conn->state = STATE_EXIT;
		return;
	}

	conn->initiator = strdup(name);
	if (conn->initiator == NULL) {
		log_error("Unable to duplicate initiator's name %s", name);
		rsp->status_class = ISCSI_STATUS_TARGET_ERR;
		rsp->status_detail = ISCSI_STATUS_NO_RESOURCES;
		conn->state = STATE_EXIT;
		return;
	}

	alias = text_key_find(conn, "InitiatorAlias");
	session_type = text_key_find(conn, "SessionType");
	target_name = text_key_find(conn, "TargetName");

	conn->auth_method = -1;
	conn->session_type = SESSION_NORMAL;

	if (session_type) {
		if (!strcmp(session_type, "Discovery")) {
			conn->session_type = SESSION_DISCOVERY;
		} else if (strcmp(session_type, "Normal")) {
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_INV_SESSION_TYPE;
			conn->state = STATE_EXIT;
			return;
		}
	}

	if (conn->session_type == SESSION_NORMAL) {
		struct target *target;
		int err, rc;

		if (!target_name) {
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_MISSING_FIELDS;
			conn->state = STATE_EXIT;
			return;
		}

		target = target_find_by_name(target_name);
		if (target == NULL) {
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_TGT_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		}

		if (!target->tgt_enabled) {
			log_info("Connect from %s to disabled target %s refused",
				name, target_name);
			rsp->status_class = ISCSI_STATUS_TARGET_ERR;
			conn->state = STATE_CLOSE;
			return;
		}

		conn->tid = target->tid;
		if (config_initiator_access(conn->tid, conn->fd) ||
		    isns_scn_access(conn->tid, conn->fd, name)) {
			log_info("Initiator %s not allowed to connect to "
				"target %s", name, target_name);
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_TGT_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		}

		err = init_conn_session_params(conn);
		if (err != 0) {
			log_error("Can't get session params for session 0x%" PRIu64
				" (err %d): %s\n", conn->sid.id64, err,
				strerror(-err));
			rsp->status_class = ISCSI_STATUS_TARGET_ERR;
			rsp->status_detail = ISCSI_STATUS_TARGET_ERROR;
			conn->state = STATE_EXIT;
			return;
		}

		rc = login_check_reinstatement(conn);
		if (rc < 0)
			return;
		else if (rc == ISCSI_SESS_REINSTATEMENT)
			target->sessions_count++;
		else if (rc != ISCSI_CONN_REINSTATEMENT) {
			if ((target->target_params[key_max_sessions] == 0) ||
			    (target->sessions_count < target->target_params[key_max_sessions]))
				target->sessions_count++;
			else {
				log_warning("Initiator %s not allowed to connect to "
					"target %s - max sessions limit "
					"reached (%d)",	name, target_name,
					target->target_params[key_max_sessions]);
				rsp->status_class = ISCSI_STATUS_TARGET_ERR;
				rsp->status_detail = ISCSI_STATUS_NO_RESOURCES;
				conn->state = STATE_CLOSE;
				return;
			}
		}
		log_debug(1, "target %s, sessions_count %d", target_name,
			target->sessions_count);
	}

	conn->exp_cmd_sn = be32_to_cpu(req->cmd_sn);
	log_debug(1, "exp_cmd_sn %u, cmd_sn %u", conn->exp_cmd_sn, req->cmd_sn);
	text_key_add(conn, "TargetPortalGroupTag", "1");
	return;
}

static int login_finish(struct connection *conn)
{
	int res = 0;

	switch (conn->session_type) {
	case SESSION_NORMAL:
		if (!conn->sess)
			res = session_create(conn);
		if (res == 0)
			conn->sid = conn->sess->sid;
		break;
	case SESSION_DISCOVERY:
		/* set a dummy tsih value */
		conn->sid.id.tsih = 1;
		break;
	}

	return res;
}

static void cmnd_reject(struct connection *conn, u8 reason)
{
	struct iscsi_reject_hdr *rej =
		(struct iscsi_reject_hdr *)&conn->rsp.bhs;
	size_t data_sz = sizeof(struct iscsi_hdr);
	struct buf_segment *seg;

	conn_free_rsp_buf_list(conn);
	seg = conn_alloc_buf_segment(conn, data_sz);

	memset(rej, 0x0, sizeof *rej);
	rej->opcode = ISCSI_OP_REJECT_MSG;
	rej->reason = reason;
	rej->ffffffff = ISCSI_RESERVED_TAG;
	rej->flags |= ISCSI_FLG_FINAL;

	rej->stat_sn = cpu_to_be32(conn->stat_sn++);
	rej->exp_cmd_sn = cpu_to_be32(conn->exp_cmd_sn);
	rej->max_cmd_sn = cpu_to_be32(conn->exp_cmd_sn + 1);

	if (!seg) {
		log_error("Failed to alloc data segment for Reject PDU\n");
		return;
	}

	memcpy(seg->data, &conn->req.bhs, data_sz);
	seg->len = data_sz;
}

static int cmnd_exec_auth(struct connection *conn)
{
       int res;

        switch (conn->auth_method) {
        case AUTH_CHAP:
                res = cmnd_exec_auth_chap(conn);
                break;
        case AUTH_NONE:
                res = 0;
                break;
        default:
                log_error("Unknown auth. method %d", conn->auth_method);
                res = -3;
        }

        return res;
}

static void cmnd_exec_login(struct connection *conn)
{
	struct iscsi_login_req_hdr *req = (struct iscsi_login_req_hdr *)&conn->req.bhs;
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;
	int stay = 0, nsg_disagree = 0;

	memset(rsp, 0, BHS_SIZE);
	if ((req->opcode & ISCSI_OPCODE_MASK) != ISCSI_OP_LOGIN_CMD ||
	    !(req->opcode & ISCSI_OP_IMMEDIATE)) {
		cmnd_reject(conn, ISCSI_REASON_PROTOCOL_ERROR);
		return;
	}

	rsp->opcode = ISCSI_OP_LOGIN_RSP;
	rsp->max_version = ISCSI_VERSION;
	rsp->active_version = ISCSI_VERSION;
	rsp->itt = req->itt;

	if (/*req->max_version < ISCSI_VERSION ||*/
	    req->min_version > ISCSI_VERSION) {
		rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_STATUS_NO_VERSION;
		conn->state = STATE_EXIT;
		return;
	}

	switch (req->flags & ISCSI_FLG_CSG_MASK) {
	case ISCSI_FLG_CSG_SECURITY:
		log_debug(1, "Login request (security negotiation): %d", conn->state);
		rsp->flags = ISCSI_FLG_CSG_SECURITY;

		switch (conn->state) {
		case STATE_FREE:
			conn->state = STATE_SECURITY;
			login_start(conn);
			if (rsp->status_class)
				return;
			//else fall through
		case STATE_SECURITY:
			text_scan_security(conn);
			if (rsp->status_class)
				return;
			if (conn->auth_method != AUTH_NONE) {
				conn->state = STATE_SECURITY_AUTH;
				conn->auth_state = AUTH_STATE_START;
			}
			break;
		case STATE_SECURITY_AUTH:
			switch (cmnd_exec_auth(conn)) {
			case 0:
				break;
			default:
			case -1:
				goto init_err;
			case -2:
				goto auth_err;
			}
			break;
		default:
			goto init_err;
		}

		break;
	case ISCSI_FLG_CSG_LOGIN:
		log_debug(1, "Login request (operational negotiation): %d", conn->state);
		rsp->flags = ISCSI_FLG_CSG_LOGIN;

		switch (conn->state) {
		case STATE_FREE:
			conn->state = STATE_LOGIN;

			login_start(conn);
			if (rsp->status_class)
				return;
			if (!accounts_empty(conn->tid, ISCSI_USER_DIR_INCOMING))
				goto auth_err;
			if (rsp->status_class)
				return;
			text_scan_login(conn);
			if (rsp->status_class)
				return;
			stay = text_check_params(conn);
			break;
		case STATE_LOGIN:
			text_scan_login(conn);
			if (rsp->status_class)
				return;
			stay = text_check_params(conn);
			break;
		default:
			goto init_err;
		}
		break;
	default:
		goto init_err;
	}

	if (rsp->status_class)
		return;
	if (conn->state != STATE_SECURITY_AUTH && req->flags & ISCSI_FLG_TRANSIT) {
		int nsg = req->flags & ISCSI_FLG_NSG_MASK;

		switch (nsg) {
		case ISCSI_FLG_NSG_LOGIN:
			switch (conn->state) {
			case STATE_SECURITY:
			case STATE_SECURITY_DONE:
				conn->state = STATE_SECURITY_LOGIN;
				break;
			default:
				goto init_err;
			}
			break;
		case ISCSI_FLG_NSG_FULL_FEATURE:
			switch (conn->state) {
			case STATE_SECURITY:
			case STATE_SECURITY_DONE:
				if ((nsg_disagree = text_check_params(conn))) {
					conn->state = STATE_LOGIN;
					nsg = ISCSI_FLG_NSG_LOGIN;
					break;
				}
				conn->state = STATE_SECURITY_FULL;
				break;
			case STATE_LOGIN:
				if (stay)
					nsg = ISCSI_FLG_NSG_LOGIN;
				else
					conn->state = STATE_LOGIN_FULL;
				break;
			default:
				goto init_err;
			}
			if (!stay && !nsg_disagree) {
				int err;
				text_check_params(conn);
				err = login_finish(conn);
				if (err != 0) {
					log_debug(1, "login_finish() failed: %d", err);
					/* Make initiator retry later */
					goto tgt_no_mem;
				}
			}
			break;
		default:
			goto init_err;
		}
		rsp->flags |= nsg | (stay ? 0 : ISCSI_FLG_TRANSIT);
	}

	/*
	 * TODO: support Logical Text Data Segments > INCOMING_BUFSIZE (i.e.
	 * key=value pairs spanning several PDUs) during login phase
	 */
	if (!list_empty(&conn->rsp_buf_list) &&
	    !list_length_is_one(&conn->rsp_buf_list)) {
		log_error("Target error: \'key=value\' pairs spanning several "
			  "Login PDUs are not implemented, yet\n");
		goto target_err;
	}

	rsp->sid = conn->sid;
	rsp->stat_sn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmd_sn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmd_sn = cpu_to_be32(conn->exp_cmd_sn + 1);
	return;

init_err:
	log_error("Initiator %s error", conn->initiator);
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
	rsp->status_detail = ISCSI_STATUS_INIT_ERR;
	conn->state = STATE_EXIT;
	return;

auth_err:
	log_error("Authentication of initiator %s failed", conn->initiator);
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
	rsp->status_detail = ISCSI_STATUS_AUTH_FAILED;
	conn->state = STATE_EXIT;
	return;

target_err:
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_TARGET_ERR;
	rsp->status_detail = ISCSI_STATUS_TARGET_ERROR;
	conn->state = STATE_EXIT;
	return;

tgt_no_mem:
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_TARGET_ERR;
	rsp->status_detail = ISCSI_STATUS_NO_RESOURCES;
	conn->state = STATE_EXIT;
	return;
}

static void text_scan_text(struct connection *conn)
{
	char *key, *value, *data;
	int datasize;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while ((key = next_key(&data, &datasize, &value))) {
		if (!strcmp(key, "SendTargets")) {
			struct sockaddr_storage ss;
			socklen_t slen, blen;
			char *p, *addr, buf[NI_MAXHOST + 128];
			int suppress_ip6 = 0;

			if (value[0] == 0)
				continue;

			p = addr = buf + 1;
			buf[0] = '[';
			blen = sizeof(buf) - 1;

			slen = sizeof(ss);

			getpeername(conn->fd, (struct sockaddr *) &ss, &slen);
			if (ss.ss_family == AF_INET)
				suppress_ip6 = 1;
			else {
				getnameinfo((struct sockaddr *) &ss, slen, p,
					    blen, NULL, 0, NI_NUMERICHOST);

				if (strstr(p, "::ffff:") == p)
					suppress_ip6 = 1;	// ipv4-mapped ipv6 ?
			}

			getsockname(conn->fd, (struct sockaddr *) &ss, &slen);
			slen = sizeof(ss);

			getnameinfo((struct sockaddr *) &ss, slen, p, blen,
				    NULL, 0, NI_NUMERICHOST);

			if (ss.ss_family == AF_INET6 && suppress_ip6) {
				if (strstr(p, "::ffff:") != p) {
					log_error("%s, %s:%d.", __FILE__,
						  __func__, __LINE__);
					suppress_ip6 = 0;
				} else
					addr += 7;
			}

			p += strlen(p);

			if (ss.ss_family == AF_INET6 && !suppress_ip6) {
				*p++ = ']';
				addr = buf;
			}

			sprintf(p, ":%d,1", server_port);
			target_list_build(conn, addr,
					  strcmp(value, "All") ? value : NULL);
		} else
			text_key_add(conn, key, "NotUnderstood");
	}
}

static void cmnd_exec_text(struct connection *conn)
{
	struct iscsi_text_req_hdr *req = (struct iscsi_text_req_hdr *)&conn->req.bhs;
	struct iscsi_text_rsp_hdr *rsp = (struct iscsi_text_rsp_hdr *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);

	rsp->opcode = ISCSI_OP_TEXT_RSP;
	rsp->itt = req->itt;
	conn->exp_cmd_sn = be32_to_cpu(req->cmd_sn);
	if (!(req->opcode & ISCSI_OP_IMMEDIATE))
		conn->exp_cmd_sn++;

	log_debug(1, "Text request: %d", conn->state);

	if (req->ttt == ISCSI_RESERVED_TAG) {
		conn_free_rsp_buf_list(conn);
		text_scan_text(conn);
		if (!list_empty(&conn->rsp_buf_list) &&
		    !list_length_is_one(&conn->rsp_buf_list))
			conn->ttt = get_next_ttt(conn);
		else
			conn->ttt = ISCSI_RESERVED_TAG;
	} else if (list_empty(&conn->rsp_buf_list) || conn->ttt != req->ttt) {
		log_error("Rejecting unexpected text request. TTT recv %#x, "
			  "expected %#x; %stext segments queued\n",
			  req->ttt, conn->ttt, list_empty(&conn->rsp_buf_list) ?
			  "no " : "");
		cmnd_reject(conn, ISCSI_REASON_INVALID_PDU_FIELD);
		return;
	}

	if (list_length_is_one(&conn->rsp_buf_list))
		rsp->flags = ISCSI_FLG_FINAL;
	rsp->ttt = conn->ttt;

	rsp->stat_sn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmd_sn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmd_sn = cpu_to_be32(conn->exp_cmd_sn + 1);
}

static void cmnd_exec_logout(struct connection *conn)
{
	struct iscsi_logout_req_hdr *req = (struct iscsi_logout_req_hdr *)&conn->req.bhs;
	struct iscsi_logout_rsp_hdr *rsp = (struct iscsi_logout_rsp_hdr *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);
	rsp->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp->flags = ISCSI_FLG_FINAL;
	rsp->itt = req->itt;
	conn->exp_cmd_sn = be32_to_cpu(req->cmd_sn);
	if (!(req->opcode & ISCSI_OP_IMMEDIATE))
		conn->exp_cmd_sn++;

	rsp->stat_sn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmd_sn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmd_sn = cpu_to_be32(conn->exp_cmd_sn + 1);
}

int cmnd_execute(struct connection *conn)
{
	int res = 1;
	struct buf_segment *seg;
	struct iscsi_login_rsp_hdr *login_rsp;

	switch (conn->req.bhs.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_LOGIN_CMD:
		if (conn->state == STATE_FULL) {
			cmnd_reject(conn, ISCSI_REASON_PROTOCOL_ERROR);
			break;
		}
		cmnd_exec_login(conn);
		login_rsp = (struct iscsi_login_rsp_hdr *) &conn->rsp.bhs;
		if (login_rsp->status_class)
			conn_free_rsp_buf_list(conn);
		break;
	case ISCSI_OP_TEXT_CMD:
		if (conn->state != STATE_FULL)
			cmnd_reject(conn, ISCSI_REASON_PROTOCOL_ERROR);
		else
			cmnd_exec_text(conn);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		if (conn->state != STATE_FULL)
			cmnd_reject(conn, ISCSI_REASON_PROTOCOL_ERROR);
		else
			cmnd_exec_logout(conn);
		break;
	default:
		cmnd_reject(conn, ISCSI_REASON_UNSUPPORTED_COMMAND);
		res = 0;
		goto out;
	}

	if (!list_empty(&conn->rsp_buf_list)) {
		seg = list_entry(conn->rsp_buf_list.q_forw,
				 struct buf_segment, entry);
		list_del_init(&seg->entry);
		conn->rsp.datasize = seg->len;
		conn->rsp.data = seg->data;
	} else {
		conn->rsp.datasize = 0;
		conn->rsp.data = NULL;
	}

	conn->rsp.bhs.ahslength = conn->rsp.ahssize / 4;
	conn->rsp.bhs.datalength[0] = conn->rsp.datasize >> 16;
	conn->rsp.bhs.datalength[1] = conn->rsp.datasize >> 8;
	conn->rsp.bhs.datalength[2] = conn->rsp.datasize;
	log_pdu(2, &conn->rsp);

out:
	return res;
}

void cmnd_finish(struct connection *conn)
{
	struct buf_segment *seg;

	if (conn->rsp.data) {
		seg = container_of(conn->rsp.data, struct buf_segment, data);
		list_del(&seg->entry);
		free(seg);
		conn->rsp.data = NULL;
	}

	switch (conn->state) {
	case STATE_EXIT:
		conn->state = STATE_CLOSE;
		break;
	case STATE_SECURITY_LOGIN:
		conn->state = STATE_LOGIN;
		break;
	case STATE_SECURITY_FULL:
		//fall through
	case STATE_LOGIN_FULL:
		if (conn->session_type == SESSION_NORMAL)
			conn->state = STATE_KERNEL;
		else
			conn->state = STATE_FULL;
		break;
	}
}
