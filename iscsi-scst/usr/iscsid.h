/*
 *  Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
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

#ifndef ISCSID_H
#define ISCSID_H

#include <search.h>
#include <sys/types.h>

#include "types.h"
#include "iscsi_hdr.h"
#include "iscsi_scst.h"
#include "param.h"
#include "config.h"
#include "misc.h"

#define PROC_SESSION	"/proc/scsi_tgt/iscsi/session"

struct PDU {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	void *data;
	unsigned int datasize;
};

#define KEY_STATE_START		0
#define KEY_STATE_REQUEST	1
#define KEY_STATE_DONE		2

struct session {
	struct qelem slist;

	char *initiator;
	struct target *target;
	union iscsi_sid sid;

	int conn_cnt;
};

struct connection {
	int state;
	int iostate;
	int fd;

	struct session *session;

	u32 tid;
	struct iscsi_param session_param[session_key_last];

	char *initiator;
	char *user;
	union iscsi_sid sid;
	u16 cid;
	u16 pad;
	int session_type;
	int auth_method;

	u32 stat_sn;
	u32 exp_stat_sn;

	u32 cmd_sn;
	u32 exp_cmd_sn;

	struct PDU req;
	void *req_buffer;
	struct PDU rsp;
	void *rsp_buffer;
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

#define INCOMING_BUFSIZE	8192

struct target {
	struct qelem tlist;

	struct qelem sessions_list;

	u32 tid;
	char name[ISCSI_NAME_LEN];
	char *alias;

	int max_nr_sessions;
	int nr_sessions;

	struct qelem isns_head;
};

extern struct config_operations plain_ops;
extern int ctrl_fd;
extern int conn_blocked;

/* chap.c */
extern int cmnd_exec_auth_chap(struct connection *conn);

/* conn.c */
extern struct connection *conn_alloc(void);
extern void conn_free(struct connection *conn);
extern int conn_test(struct connection *conn);
extern void conn_take_fd(struct connection *conn, int fd);
extern void conn_read_pdu(struct connection *conn);
extern void conn_write_pdu(struct connection *conn);
extern void conn_free_pdu(struct connection *conn);

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
extern void log_info(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_warning(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_error(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_debug(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern void log_pdu(int level, struct PDU *pdu);

/* session.c */
extern struct session *session_find_name(u32 tid, const char *iname, union iscsi_sid sid);
extern struct session *session_find_id(u32 tid, u64 sid);
extern void session_create(struct connection *conn);
extern void session_remove(struct session *session);

/* target.c */
extern struct qelem targets_list;
extern int target_add(u32 *, char *);
extern int target_del(u32);
extern u32 target_find_by_name(const char *name);
struct target * target_find_by_id(u32);
extern void target_list_build(struct connection *, char *, char *);

/* message.c */
extern int iscsi_adm_request_listen(void);
extern int iscsi_adm_request_handle(int accept_fd);

/* ctldev.c */
struct iscsi_kernel_interface {
	int (*ctldev_open) (void);
	int (*param_get) (u32, u64, int, struct iscsi_param *, int);
	int (*param_set) (u32, u64, int, u32, struct iscsi_param *, int);
	int (*target_create) (u32 *, char *);
	int (*target_destroy) (u32);
	int (*session_create) (u32, u64, u32, char *, char *);
	int (*session_destroy) (u32, u64);
	int (*conn_create) (u32, u64, u32, u32, u32, int, u32, u32);
	int (*conn_destroy) (u32 tid, u64 sid, u32 cid);
};

extern struct iscsi_kernel_interface *ki;

/* the following functions should be killed */
extern int session_conns_close(u32 tid, u64 sid);
extern int server_stop(void);
extern int target_destroy(u32 tid);

/* event.c */
extern void handle_iscsi_events(int fd);
extern int nl_open(void);

/* param.c */
extern int param_index_by_name(char *name, struct iscsi_key *keys);

/* isns.c */
extern int isns_init(char *addr, int isns_ac);
extern int isns_handle(int is_timeout, int *timeout);
extern int isns_scn_handle(int accept);
extern int isns_scn_access(u32 tid, int fd, char *name);
extern int isns_target_register(char *name);
extern int isns_target_deregister(char *name);
extern void isns_exit(void);

#endif	/* ISCSID_H */
