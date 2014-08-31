
#ifndef __ISCSI_TRANSPORT_H__
#define __ISCSI_TRANSPORT_H__

#include <linux/module.h>
#include <linux/list.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include <scst.h>
#endif

/* Forward declarations */
struct iscsi_session;
struct iscsi_kern_conn_info;
struct iscsi_conn;

enum iscsit_transport_type {
	ISCSI_TCP,
	ISCSI_RDMA,
};

struct iscsit_transport {
	struct iscsi_cmnd* (*iscsit_alloc_cmd)(struct iscsi_conn *conn,
					       struct iscsi_cmnd *parent);
	void (*iscsit_preprocessing_done)(struct iscsi_cmnd *cmnd);
	void (*iscsit_send_data_rsp)(struct iscsi_cmnd *req, u8 *sense,
				     int sense_len, u8 status,
				     int send_status);
	int (*iscsit_send_locally)(struct iscsi_cmnd *cmnd,
				   unsigned int cmd_count);
	void (*iscsit_set_sense_data)(struct iscsi_cmnd *rsp,
				      const u8 *sense_buf, int sense_len);
	int (*iscsit_receive_cmnd_data)(struct iscsi_cmnd *cmnd);
	void (*iscsit_make_conn_wr_active)(struct iscsi_conn *conn);
	void (*iscsit_free_cmd)(struct iscsi_cmnd *cmnd);

	void (*iscsit_set_req_data)(struct iscsi_cmnd *req,
				    struct iscsi_cmnd *rsp);

	int (*iscsit_conn_alloc)(struct iscsi_session *session,
				 struct iscsi_kern_conn_info *info,
				 struct iscsi_conn **new_conn,
				 struct iscsit_transport *transport);
	int (*iscsit_conn_activate)(struct iscsi_conn *conn);
	void (*iscsit_conn_free)(struct iscsi_conn *conn);
	void (*iscsit_conn_close)(struct iscsi_conn *conn, int flags);
	void (*iscsit_mark_conn_closed)(struct iscsi_conn *conn, int flags);

	ssize_t (*iscsit_get_initiator_ip)(struct iscsi_conn *conn, char *buf,
					   int size);

	void (*iscsit_close_all_portals)(void);

#if !defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	unsigned int need_alloc_write_buf:1;
#endif

	struct module *owner;
	const char name[SCST_MAX_NAME];
	enum iscsit_transport_type transport_type;
	struct list_head transport_list_entry;
} ____cacheline_aligned;

extern int iscsit_reg_transport(struct iscsit_transport *t);
extern void iscsit_unreg_transport(struct iscsit_transport *t);
extern struct iscsit_transport *iscsit_get_transport(enum iscsit_transport_type type);

#endif /* __ISCSI_TRANSPORT_H__ */

