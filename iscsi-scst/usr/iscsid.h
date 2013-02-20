/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
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

#ifndef ISCSID_H
#define ISCSID_H

#include <search.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <assert.h>
#include <netdb.h>
#include <syslog.h>

#include "types.h"
#ifdef INSIDE_KERNEL_TREE
#include <scst/iscsi_scst.h>
#else
#include "iscsi_scst.h"
#endif
#include "iscsi_hdr.h"
#include "param.h"
#include "misc.h"

#ifndef bool
typedef enum {false = 0, true} bool;
#endif

#define sBUG() assert(0)
#define sBUG_ON(p) assert(!(p))

struct iscsi_init_params {
	int max_data_seg_len;
	int max_queued_cmds;
};

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

	unsigned int passed_to_kern:1;
	unsigned int sessions_count_incremented:1;

	struct target *target;
	struct session *sess;

	u32 tid;

	/* Put here, because negotiations is done before session created */
	struct iscsi_param session_params[session_key_last];

	char *initiator;
	char *target_portal;
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
#define STATE_DROP		12

#define AUTH_STATE_START	0
#define AUTH_STATE_CHALLENGE	1

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

#define ISCSI_USER_DIR_INCOMING	0
#define ISCSI_USER_DIR_OUTGOING	1

#define ISCSI_USER_NAME(attr)	(attr)->attr_key
#define ISCSI_USER_PASS(attr)	(attr)->attr_value

struct iscsi_attr {
	struct __qelem ulist;
	const char *attr_key;
	const char *attr_value;
	u32 sysfs_mode;
	char sysfs_name[64];
};

struct target {
	struct __qelem tlist;

	struct __qelem sessions_list;

	unsigned int tgt_enabled:1;
	unsigned int per_portal_acl:1;

	unsigned int target_params[target_key_last];
	unsigned int session_params[session_key_last];

	u32 tid;
	char name[ISCSI_NAME_LEN];
	char *alias;
	unsigned int sessions_count;

	struct redirect_addr {
		char addr[NI_MAXHOST + 1];
		int port;
		u8 type; /* one of ISCSI_STATUS_TGT_MOVED_* constants */
	} redirect;

	struct __qelem target_in_accounts;
	struct __qelem target_out_accounts;

	struct __qelem allowed_portals;

	struct __qelem isns_head;
};

extern int ctrl_fd;
extern int conn_blocked;

#define LISTEN_MAX		8
#define INCOMING_MAX		256

enum {
	POLL_LISTEN,
	POLL_IPC = POLL_LISTEN + LISTEN_MAX,
	POLL_NL,
	POLL_ISNS,
	POLL_SCN_LISTEN,
	POLL_SCN,
	POLL_INCOMING,
	POLL_MAX = POLL_INCOMING + INCOMING_MAX,
};

extern struct pollfd poll_array[POLL_MAX];

extern int nl_fd;

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
extern struct iscsi_init_params iscsi_init_params;
extern void isns_set_fd(int isns, int scn_listen, int scn);
extern const char *get_error_str(int error);

/* iscsid.c */
extern int iscsi_enabled;

extern int cmnd_execute(struct connection *conn);
extern void cmnd_finish(struct connection *conn);
extern char *text_key_find(struct connection *conn, char *searchKey);
extern void text_key_add(struct connection *conn, char *key, const char *value);

/* log.c */
extern int log_daemon;
extern int log_level;

extern void log_init(void);
extern void __log(const char *func, int line, int prio, int level, const char *fmt, ...)
	__attribute__ ((format (printf, 5, 6)));
extern void __log_pdu(const char *func, int line, int level, struct PDU *pdu);

#define log_info(args...)		__log(__func__, __LINE__, LOG_INFO, 0, ## args)
#define log_warning(args...)		__log(__func__, __LINE__, LOG_WARNING, 0, ## args)
#define log_error(args...)		__log(__func__, __LINE__, LOG_ERR, 0, ## args)
#define log_debug(level, args...)	__log(__func__, __LINE__, LOG_DEBUG, level, ## args)
#define log_pdu(level, args...)		__log_pdu(__func__, __LINE__, level, ## args)

/* Conditional versions of log_* functions. Useful when log priority depends
 * on some parameter, say recurrence of some event. In these cases the first
 * occurence could be logged as log_info while the latter ones may be logged
 * with log_debug. So, if level != 0 then log_debug is called.
 */
#define log_info_cond(level, args...)		\
	__log(__func__, __LINE__, LOG_INFO, level, ## args)
#define log_warning_cond(level, args...)	\
	__log(__func__, __LINE__, LOG_WARNING, level, ## args)
#define log_error_cond(level, args...)		\
	__log(__func__, __LINE__, LOG_ERR, level, ## args)

/* session.c */
extern struct session *session_find_name(u32 tid, const char *iname, union iscsi_sid sid);
extern struct session *session_find_id(u32 tid, u64 sid);
extern int session_create(struct connection *conn);
extern void session_free(struct session *session);
extern struct connection *conn_find(struct session *session, u16 cid);

/* target.c */
extern struct __qelem targets_list;
extern int target_create(const char *name, struct target **out_target);
extern void target_free(struct target *target);
extern int target_add(struct target *target, u32 *tid, u32 cookie);
extern int target_del(u32 tid, u32 cookie);
extern u32 target_find_id_by_name(const char *name);
extern struct target *target_find_by_name(const char *name);
extern struct target *target_find_by_id(u32);
extern void target_list_build(struct connection *, char *);
extern int target_portal_allowed(struct target *target,
	const char *target_portal, const char *initiator_name);
extern const char *iscsi_make_full_initiator_name(int per_portal_acl,
	const char *initiator_name, const char *target_portal,
	char *buf, int size);
extern bool target_redirected(struct target *target, struct connection *conn);

/* message.c */
extern int iscsi_adm_request_listen(void);
extern int iscsi_adm_request_handle(int accept_fd);

/* ctldev.c */
extern int kernel_open(void);
extern int kernel_params_get(u32 tid, u64 sid, int type, struct iscsi_param *params);
extern int kernel_params_set(u32 tid, u64 sid, int type, u32 partial,
	const struct iscsi_param *params);
extern int kernel_target_create(struct target *target, u32 *tid, u32 cookie);
extern int kernel_target_destroy(u32 tid, u32 cookie);
#ifndef CONFIG_SCST_PROC
extern int kernel_user_add(struct target *target, struct iscsi_attr *attr,
		u32 cookie);
extern int kernel_user_del(struct target *target, struct iscsi_attr *attr,
		u32 cookie);
extern int kernel_attr_add(struct target *target, const char *name,
	u32 mode, u32 cookie);
extern int kernel_attr_del(struct target *target, const char *name, u32 cookie);
#endif
extern int kernel_initiator_allowed(u32 tid, const char *initiator_name);
extern int kernel_session_create(struct connection *conn);
extern int kernel_session_destroy(u32 tid, u64 sid);
extern int kernel_conn_create(u32 tid, u64 sid, u32 cid, u32 stat_sn, u32 exp_stat_sn,
	int fd);
extern int kernel_conn_destroy(u32 tid, u64 sid, u32 cid);

/* event.c */
extern int handle_iscsi_events(int fd, bool wait);
extern int nl_open(void);

/* config.c */
extern char *config_sep_string(char **pp);
extern int config_parse_main(const char *data, u32 cookie);
extern int config_load(const char *config_name);
extern int config_target_create(u32 *tid, char *name);
extern int config_target_destroy(u32 tid);
extern int config_account_add(u32 tid, int dir, char *name, char *pass,
	char *sysfs_name, u32 cookie);
extern int __config_account_add(struct target *target, int dir, char *name,
	char *pass, char *sysfs_name, int send_to_kern, u32 cookie);
extern int config_account_query(u32 tid, int dir, const char *name, char *pass);
extern int config_account_list(u32 tid, int dir, u32 *cnt, u32 *overflow,
	char *buf, size_t buf_sz);
extern int config_account_del(u32 tid, int dir, char *name, u32 cookie);
extern int config_params_get(u32 tid, u64 sid, int type, struct iscsi_param *params);
extern int config_params_set(u32 tid, u64 sid, int type, u32 partial,
	struct iscsi_param *params);
extern int config_initiator_access_allowed(u32 tid, int fd);
extern int accounts_empty(u32 tid, int dir);
extern struct iscsi_attr *account_get_first(u32 tid, int dir);
extern struct iscsi_attr *account_lookup_by_sysfs_name(struct target *target,
	int dir, const char *sysfs_name);
extern int account_replace(struct target *target, int direction,
	const char *sysfs_name, char *value);
extern void accounts_free(struct __qelem *accounts_list);
extern struct iscsi_attr *iscsi_attr_lookup_by_sysfs_name(
	struct __qelem *attrs_list, const char *sysfs_name);
extern struct iscsi_attr *iscsi_attr_lookup_by_key(
	struct __qelem *attrs_list, const char *key);
extern void iscsi_attrs_free(struct __qelem *attrs_list);
extern int iscsi_attr_create(int attr_size, struct __qelem *attrs_list,
	const char *sysfs_name_tmpl, const char *key, const char *val,
	u32 mode, struct iscsi_attr **res_attr);
extern void iscsi_attr_destroy(struct iscsi_attr *attr);
extern int iscsi_attr_replace(struct __qelem *attrs_list, const char *sysfs_name,
	char *raw_value);

/* isns.c */
extern char *isns_server;
extern int isns_access_control;
extern char isns_entity_target_name[ISCSI_NAME_LEN];
extern int isns_timeout;
extern int isns_init(void);
extern int isns_handle(int is_timeout);
extern int isns_scn_handle(int accept);
extern int isns_scn_access_allowed(u32 tid, char *name);
extern int isns_target_register(char *name);
extern int isns_target_deregister(char *name);
extern void isns_exit(void);

#endif	/* ISCSID_H */
