/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2009 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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

#ifndef ISCSID_H
#define ISCSID_H

#include <search.h>
#include <sys/types.h>
#include <assert.h>

#include "types.h"
#include "iscsi_hdr.h"
#include "iscsi_scst.h"
#include "param.h"
#include "misc.h"

#define sBUG() assert(0)
#define sBUG_ON(p) assert(!(p))

struct buf_segment {
	struct __qelem entry;

	unsigned int len;
	char data[0];
};

struct PDU {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	void *data;
	unsigned int datasize;
};

#define KEY_STATE_START		0
#define KEY_STATE_REQUEST	1
#define KEY_STATE_DONE_ADDED	2
#define KEY_STATE_DONE		3

struct session {
	struct __qelem slist;

	char *initiator;
	struct target *target;
	union iscsi_sid sid;

	struct __qelem conn_list;
};

struct connection {
	int state;
	int iostate;
	int fd;

	struct session *sess;

	u32 tid;
	struct iscsi_param session_param[session_key_last];

	char *initiator;
	char *user;
	union iscsi_sid sid;
	u16 cid;

	int session_type;
	int auth_method;

	u32 stat_sn;
	u32 exp_stat_sn;

	u32 cmd_sn;
	u32 exp_cmd_sn;
	u32 ttt;

	struct PDU req;
	void *req_buffer;
	struct PDU rsp;
	struct __qelem rsp_buf_list;
	unsigned char *buffer;
	int rwsize;

	int auth_state;
	union {
		struct {
			int digest_alg;
			int id;
			int challenge_size;
			unsigned char *challenge;
		} chap;
	} auth;

	struct __qelem clist;
};

#define IOSTATE_FREE		0
#define IOSTATE_READ_BHS	1
#define IOSTATE_READ_AHS_DATA	2
#define IOSTATE_WRITE_BHS	3
#define IOSTATE_WRITE_AHS	4
#define IOSTATE_WRITE_DATA	5

#define STATE_FREE		0
#define STATE_SECURITY		1
#define STATE_SECURITY_AUTH	2
#define STATE_SECURITY_DONE	3
#define STATE_SECURITY_LOGIN	4
#define STATE_SECURITY_FULL	5
#define STATE_LOGIN		6
#define STATE_LOGIN_FULL	7
#define STATE_FULL		8
#define STATE_KERNEL		9
#define STATE_CLOSE		10
#define STATE_EXIT		11

#define AUTH_STATE_START	0
#define AUTH_STATE_CHALLENGE	1

/* don't touch these */
#define AUTH_DIR_INCOMING       0
#define AUTH_DIR_OUTGOING       1

#define SESSION_NORMAL		0
#define SESSION_DISCOVERY	1
#define AUTH_UNKNOWN		-1
#define AUTH_NONE		0
#define AUTH_CHAP		1
#define DIGEST_UNKNOWN		-1

#define BHS_SIZE		48

/*
 * Must be 8192, since it used as MaxRecvDataSegmentLength during Login phase,
 * because iSCSI RFC requires: "The default MaxRecvDataSegmentLength is used
 * during Login".
 */
#define INCOMING_BUFSIZE	8192

struct target {
	struct __qelem tlist;

	struct __qelem sessions_list;

	u32 tid;
	char name[ISCSI_NAME_LEN];
	char *alias;

	struct __qelem isns_head;
};

extern int ctrl_fd;
extern int conn_blocked;

/* chap.c */
extern int cmnd_exec_auth_chap(struct connection *conn);

/* conn.c */
extern struct connection *conn_alloc(void);
extern void conn_free(struct connection *conn);
extern void conn_pass_to_kern(struct connection *conn, int fd);
extern void conn_read_pdu(struct connection *conn);
extern void conn_write_pdu(struct connection *conn);
extern void conn_free_pdu(struct connection *conn);
extern void conn_free_rsp_buf_list(struct connection *conn);

/* iscsi_scstd.c */
extern uint16_t server_port;
extern void isns_set_fd(int isns, int scn_listen, int scn);
extern void wait_4_iscsi_event(int timeout);

/* iscsid.c */
extern int iscsi_debug;

extern int cmnd_execute(struct connection *conn);
extern void cmnd_finish(struct connection *conn);
extern char *text_key_find(struct connection *conn, char *searchKey);
extern void text_key_add(struct connection *conn, char *key, char *value);

/* log.c */
extern int log_daemon;
extern int log_level;

extern void log_init(void);
extern void __log_info(const char *func, int line, const char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void __log_warning(const char *func, int line, const char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void __log_error(const char *func, int line, const char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void __log_debug(const char *func, int line, int level, const char *fmt, ...)
	__attribute__ ((format (printf, 4, 5)));
extern void __log_pdu(const char *func, int line, int level, struct PDU *pdu);

#define log_info(args...)	__log_info(__func__, __LINE__, ## args)
#define log_warning(args...)	__log_warning(__func__, __LINE__, ## args)
#define log_error(args...)	__log_error(__func__, __LINE__, ## args)
#define log_debug(args...)	__log_debug(__func__, __LINE__, ## args)
#define log_pdu(args...)	__log_pdu(__func__, __LINE__, ## args)

/* session.c */
extern struct session *session_find_name(u32 tid, const char *iname, union iscsi_sid sid);
extern struct session *session_find_id(u32 tid, u64 sid);
extern int session_create(struct connection *conn);
extern void session_free(struct session *session);
extern struct connection *conn_find(struct session *session, u16 cid);

/* target.c */
extern struct __qelem targets_list;
extern int target_add(u32 *, char *);
extern int target_del(u32);
extern u32 target_find_id_by_name(const char *name);
extern struct target *target_find_by_name(const char *name);
struct target *target_find_by_id(u32);
extern void target_list_build(struct connection *, char *, char *);

/* message.c */
extern int iscsi_adm_request_listen(void);
extern int iscsi_adm_request_handle(int accept_fd);

/* ctldev.c */
extern int kernel_open(int *max_data_seg_len);
extern int kernel_param_get(u32 tid, u64 sid, int type, struct iscsi_param *param);
extern int kernel_param_set(u32 tid, u64 sid, int type, u32 partial,
	struct iscsi_param *param);
extern int kernel_target_create(u32 *tid, char *name);
extern int kernel_target_destroy(u32 tid);
extern int kernel_session_create(u32 tid, u64 sid, u32 exp_cmd_sn,
	char *name, char *user);
extern int kernel_session_destroy(u32 tid, u64 sid);
extern int kernel_conn_create(u32 tid, u64 sid, u32 cid, u32 stat_sn, u32 exp_stat_sn,
	int fd, u32 hdigest, u32 ddigest);
extern int kernel_conn_destroy(u32 tid, u64 sid, u32 cid);	

/* event.c */
extern void handle_iscsi_events(int fd);
extern int nl_open(void);

/* param.c */
extern int param_index_by_name(char *name, struct iscsi_key *keys);

/* config.c */
extern int config_isns_load(char *params, char **isns, int *isns_ac);
extern int config_load(char *params);
extern int config_target_create(u32 *tid, char *name);
extern int config_target_destroy(u32 tid);
int config_account_add(u32 tid, int dir, char *name, char *pass);
extern int config_account_query(u32 tid, int dir, char *name, char *pass);
extern int config_account_list(u32 tid, int dir, u32 *cnt, u32 *overflow,
	char *buf, size_t buf_sz);
extern int config_account_del(u32 tid, int dir, char *name);
extern int config_param_set(u32 tid, u64 sid, int type, u32 partial,
	struct iscsi_param *param);
extern int config_initiator_access(u32 tid, int fd);

/* isns.c */
extern int isns_init(char *addr, int isns_ac);
extern int isns_handle(int is_timeout, int *timeout);
extern int isns_scn_handle(int accept);
extern int isns_scn_access(u32 tid, int fd, char *name);
extern int isns_target_register(char *name);
extern int isns_target_deregister(char *name);
extern void isns_exit(void);

#endif	/* ISCSID_H */
