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

#ifndef __ISCSI_H__
#define __ISCSI_H__

#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <net/sock.h>

#include <scsi_tgt.h>

#include "iscsi_hdr.h"
#include "iscsi_u.h"

#include "iscsi_dbg.h"

#define iscsi_sense_crc_error		ABORTED_COMMAND, 0x47, 0x5

struct iscsi_sess_param {
	int initial_r2t;
	int immediate_data;
	int max_connections;
	int max_recv_data_length;
	int max_xmit_data_length;
	int max_burst_length;
	int first_burst_length;
	int default_wait_time;
	int default_retain_time;
	int max_outstanding_r2t;
	int data_pdu_inorder;
	int data_sequence_inorder;
	int error_recovery_level;
	int header_digest;
	int data_digest;
	int ofmarker;
	int ifmarker;
	int ofmarkint;
	int ifmarkint;
};

struct iscsi_trgt_param {
	int queued_cmnds;
};

struct network_thread_info {
	struct task_struct *task;
	unsigned int ready;
};

struct iscsi_cmnd;

struct iscsi_target {
	struct scst_tgt *scst_tgt;

	struct mutex target_mutex;

	struct list_head session_list; /* protected by target_mutex */

	/* Both protected by target_mutex */
	struct iscsi_sess_param trgt_sess_param;
	struct iscsi_trgt_param trgt_param;

	struct list_head target_list_entry;
	u32 tid;
	char name[ISCSI_NAME_LEN];
};

#define ISCSI_HASH_ORDER	8
#define	cmnd_hashfn(itt)	hash_long((itt), ISCSI_HASH_ORDER)

struct iscsi_session {
	struct iscsi_target *target;
	struct scst_session *scst_sess;

	/* All 2 unprotected, since accessed only from a single read thread */
	struct list_head pending_list;
	u32 next_ttt;

	u32 max_queued_cmnds; /* unprotected, since read-only */
	atomic_t active_cmds;

	spinlock_t sn_lock;
	u32 exp_cmd_sn; /* protected by sn_lock */

	struct iscsi_cmnd *tm_rsp;

	/* read only, if there are connection(s) */
	struct iscsi_sess_param sess_param;

	spinlock_t cmnd_hash_lock;
	struct list_head cmnd_hash[1 << ISCSI_HASH_ORDER];

	struct list_head conn_list; /* protected by target_mutex */

	struct list_head session_list_entry;

	/* Bot don't need any protection */
	char *initiator_name;
	u64 sid;
};

#define ISCSI_CONN_IOV_MAX			(PAGE_SIZE/sizeof(struct iovec))

#define ISCSI_CONN_RD_STATE_IDLE		0
#define ISCSI_CONN_RD_STATE_IN_LIST		1		
#define ISCSI_CONN_RD_STATE_PROCESSING		2

#define ISCSI_CONN_WR_STATE_IDLE		0
#define ISCSI_CONN_WR_STATE_IN_LIST		1
#define ISCSI_CONN_WR_STATE_SPACE_WAIT		2
#define ISCSI_CONN_WR_STATE_PROCESSING		3

struct iscsi_conn {
	struct iscsi_session *session; /* owning session */

	/* Both protected by session->sn_lock */
	u32 stat_sn;
	u32 exp_stat_sn;	

	spinlock_t cmd_list_lock; /* BH lock */

	/*
	 * IMPORTANT! If you find a cmd in cmd_list and immediately get_cmnd()
	 * it, it still can be destroyed immediately after you drop
	 * cmd_list_lock no matter how big is its ref_cnt!
	 */

	/* Protected by cmd_list_lock */
	struct list_head cmd_list; /* in/outcoming pdus */

	atomic_t conn_ref_cnt;

	spinlock_t write_list_lock;
	/* List of data pdus to be sent, protected by write_list_lock */
	struct list_head write_list; 

	/* All 2 protected by iscsi_wr_lock */
	unsigned short wr_state;
	unsigned short wr_space_ready:1;

	struct list_head wr_list_entry;

#ifdef EXTRACHECKS
	struct task_struct *wr_task;
#endif

	/* All are unprotected, since accessed only from a single write thread */
	struct iscsi_cmnd *write_cmnd;
	struct iovec *write_iop;
	int write_iop_used;
	struct iovec write_iov[2];
	u32 write_size;
	u32 write_offset;
	int write_state;

	/* Both don't need any protection */
	struct file *file;
	struct socket *sock;

	void (*old_state_change)(struct sock *);
	void (*old_data_ready)(struct sock *, int);
	void (*old_write_space)(struct sock *);

	/* Both read only */
	int hdigest_type;
	int ddigest_type;

	/* All 4 protected by iscsi_rd_lock */
	unsigned short rd_state;
	unsigned short rd_data_ready:1;
	unsigned short closing:1; /* Let's save some cache footprint by putting it here */

	struct list_head rd_list_entry;

#ifdef EXTRACHECKS
	struct task_struct *rd_task;
#endif

	/* All are unprotected, since accessed only from a single read thread */
	struct iscsi_cmnd *read_cmnd;
	struct msghdr read_msg;
	u32 read_size;
	int read_state;
	struct iovec *read_iov;

	struct iscsi_target *target;

	struct list_head conn_list_entry;	/* list entry in session conn_list */

	/* Doesn't need any protection */
	u16 cid;
};

struct iscsi_pdu {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	unsigned int datasize;
};

typedef void (iscsi_show_info_t)(struct seq_file *seq, struct iscsi_target *target);

/* Command's states */
#define ISCSI_CMD_STATE_NEW               0	/* New command and SCST processes it */
#define ISCSI_CMD_STATE_RX_CMD            1	/* SCST processes cmd after scst_rx_cmd() */
#define ISCSI_CMD_STATE_AFTER_PREPROC     2	/* The command returned from preprocessing_done() */
#define ISCSI_CMD_STATE_RESTARTED         3	/* scst_restart_cmd() called and SCST processing it */
#define ISCSI_CMD_STATE_PROCESSED         4	/* SCST done processing */

/* 
 * Most of the fields don't need any protection, since accessed from only a
 * single thread, except where noted.
 */
struct iscsi_cmnd {
	struct iscsi_conn *conn;

	/* Some flags protected by conn->write_list_lock */
	unsigned int hashed:1;
	unsigned int should_close_conn:1;
	unsigned int pending:1;
	unsigned int own_sg:1;
	unsigned int on_write_list:1;
	unsigned int write_processing_started:1;
	unsigned int data_waiting:1;
	unsigned int force_cleanup_done:1;
	unsigned int dec_active_cmnds:1;
#ifdef EXTRACHECKS
	unsigned int release_called:1;
#endif

	unsigned long tmfabort; /* it's async. with the above flags */

	struct list_head hash_list_entry;

	spinlock_t rsp_cmd_lock; /* BH lock */

	/* Unions are for readability and grepability */

	/*
	 * IMPORTANT! If you find a cmd in rsp_cmd_list and immediately
	 * get_cmnd() it, it still can be destroyed immediately after you drop
	 * rsp_cmd_lock no matter how big is its ref_cnt!
	 */

	union {
		/* Protected by rsp_cmd_lock */
		struct list_head rsp_cmd_list;
		struct list_head rsp_cmd_list_entry;
	};

	union {
		struct list_head pending_list_entry;
		struct list_head write_list_entry;
	};

	/*
	 * Unprotected, since could be accessed from only a single 
	 * thread at time
	 */
	struct list_head rx_ddigest_cmd_list;
	struct list_head rx_ddigest_cmd_list_entry;

	struct iscsi_cmnd *parent_req;
	struct iscsi_cmnd *cmd_req;

	struct iscsi_target *target;

	wait_queue_head_t scst_waitQ;
	int scst_state;
	struct scst_cmd *scst_cmd;
	atomic_t ref_cnt;
#ifdef NET_PAGE_CALLBACKS_DEFINED
	atomic_t net_ref_cnt;
#endif

	struct iscsi_pdu pdu;

	struct scatterlist *sg;
	int bufflen;
	u32 r2t_sn;
	u32 r2t_length;
	u32 is_unsolicited_data;
	u32 target_task_tag;
	u32 outstanding_r2t;

	u32 hdigest;
	u32 ddigest;

	int sg_cnt; /* valid only if own_sg is 1 */
	struct list_head cmd_list_entry;
};

#define ISCSI_OP_SCSI_REJECT	ISCSI_OP_VENDOR1_CMD
#define ISCSI_OP_PDU_REJECT	ISCSI_OP_VENDOR2_CMD
#define ISCSI_OP_DATA_REJECT	ISCSI_OP_VENDOR3_CMD

/* Flags for req_cmnd_release_force() */
#define ISCSI_FORCE_RELEASE_WRITE	1

extern struct mutex target_mgmt_mutex;

extern struct file_operations ctr_fops;

extern spinlock_t iscsi_rd_lock;
extern struct list_head iscsi_rd_list;
extern wait_queue_head_t iscsi_rd_waitQ;

extern spinlock_t iscsi_wr_lock;
extern struct list_head iscsi_wr_list;
extern wait_queue_head_t iscsi_wr_waitQ;

/* iscsi.c */
extern struct iscsi_cmnd *cmnd_alloc(struct iscsi_conn *,
	struct iscsi_cmnd *parent);
extern int cmnd_rx_start(struct iscsi_cmnd *);
extern void cmnd_rx_end(struct iscsi_cmnd *);
extern void cmnd_tx_start(struct iscsi_cmnd *);
extern void cmnd_tx_end(struct iscsi_cmnd *);
extern void req_cmnd_release(struct iscsi_cmnd *req);
extern void req_cmnd_release_force(struct iscsi_cmnd *req, int flags);
extern void rsp_cmnd_release(struct iscsi_cmnd *);
extern void cmnd_done(struct iscsi_cmnd *cmnd);
extern void conn_abort(struct iscsi_conn *conn);

/* conn.c */
extern struct iscsi_conn *conn_lookup(struct iscsi_session *, u16);
extern int conn_add(struct iscsi_session *, struct conn_info *);
extern int conn_del(struct iscsi_session *, struct conn_info *);
extern int conn_free(struct iscsi_conn *);
extern void mark_conn_closed(struct iscsi_conn *);
extern void iscsi_make_conn_wr_active(struct iscsi_conn *);
extern void conn_info_show(struct seq_file *, struct iscsi_session *);

/* nthread.c */
extern int iscsi_send(struct iscsi_conn *conn);
#ifdef NET_PAGE_CALLBACKS_DEFINED
extern void iscsi_get_page_callback(struct page *page);
extern void iscsi_put_page_callback(struct page *page);
#endif
extern int istrd(void *arg);
extern int istwr(void *arg);

/* target.c */
struct iscsi_target *target_lookup_by_id(u32);
extern int target_add(struct target_info *);
extern int target_del(u32 id);
extern void target_del_all(void);

/* config.c */
extern int iscsi_procfs_init(void);
extern void iscsi_procfs_exit(void);
extern int iscsi_info_show(struct seq_file *, iscsi_show_info_t *);

/* session.c */
extern struct file_operations session_seq_fops;
extern struct iscsi_session *session_lookup(struct iscsi_target *, u64);
extern int session_add(struct iscsi_target *, struct session_info *);
extern int session_del(struct iscsi_target *, u64);
extern int session_free(struct iscsi_session *session);

/* params.c */
extern int iscsi_param_set(struct iscsi_target *, struct iscsi_param_info *, int);

/* event.c */
extern int event_send(u32, u64, u32, u32, int);
extern int event_init(void);
extern void event_exit(void);

#define get_pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_MASK)) + PAGE_SIZE - 1) >> PAGE_SHIFT)

static inline void iscsi_cmnd_get_length(struct iscsi_pdu *pdu)
{
#if defined(__BIG_ENDIAN)
	pdu->ahssize = pdu->bhs.length.ahslength * 4;
	pdu->datasize = pdu->bhs.length.datalength;
#elif defined(__LITTLE_ENDIAN)
	pdu->ahssize = (pdu->bhs.length & 0xff) * 4;
	pdu->datasize = be32_to_cpu(pdu->bhs.length & ~0xff);
#else
#error
#endif
}

static inline void iscsi_cmnd_set_length(struct iscsi_pdu *pdu)
{
#if defined(__BIG_ENDIAN)
	pdu->bhs.length.ahslength = pdu->ahssize / 4;
	pdu->bhs.length.datalength = pdu->datasize;
#elif defined(__LITTLE_ENDIAN)
	pdu->bhs.length = cpu_to_be32(pdu->datasize) | (pdu->ahssize / 4);
#else
#error
#endif
}

extern struct scst_tgt_template iscsi_template;

static inline void cmnd_get(struct iscsi_cmnd *cmnd)
{
	atomic_inc(&cmnd->ref_cnt);
	TRACE_DBG("cmnd %p, new cmnd->ref_cnt %d", cmnd,
		atomic_read(&cmnd->ref_cnt));
}

static inline void cmnd_get_ordered(struct iscsi_cmnd *cmnd)
{
	cmnd_get(cmnd);
	smp_mb__after_atomic_inc();
}

static inline void cmnd_put(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("cmnd %p, new cmnd->ref_cnt %d", cmnd,
		atomic_read(&cmnd->ref_cnt)-1);
	sBUG_ON(atomic_read(&cmnd->ref_cnt) == 0);
	if (atomic_dec_and_test(&cmnd->ref_cnt))
		cmnd_done(cmnd);
}

/* conn->write_list_lock supposed to be locked */
static inline void cmd_add_on_write_list(struct iscsi_conn *conn,
	struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);
	list_add_tail(&cmnd->write_list_entry, &conn->write_list);
	cmnd->on_write_list = 1;
}

/* conn->write_list_lock supposed to be locked */
static inline void cmd_del_from_write_list(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);
	list_del(&cmnd->write_list_entry);
	cmnd->on_write_list = 0;
}

static inline int test_write_ready(struct iscsi_conn *conn)
{
	/*
	 * No need for write_list protection, in the worst case we will be
	 * restarted again.
	 */
	return (!list_empty(&conn->write_list) || conn->write_cmnd);
}

static inline void conn_get(struct iscsi_conn *conn)
{
	atomic_inc(&conn->conn_ref_cnt);
	TRACE_DBG("conn %p, new conn_ref_cnt %d", conn,
		atomic_read(&conn->conn_ref_cnt));
}

static inline void conn_get_ordered(struct iscsi_conn *conn)
{
	conn_get(conn);
	smp_mb__after_atomic_inc();
}

static inline void conn_put(struct iscsi_conn *conn)
{
	TRACE_DBG("conn %p, new conn_ref_cnt %d", conn,
		atomic_read(&conn->conn_ref_cnt)-1);
	sBUG_ON(atomic_read(&conn->conn_ref_cnt) == 0);

	/* 
	 * It always ordered to protect from undesired side effects like
	 * accessing just destroyed obeject because of this *_dec() reordering.
	 */
	smp_mb__before_atomic_dec();
	atomic_dec(&conn->conn_ref_cnt);
}

#ifdef EXTRACHECKS
#define iscsi_extracheck_is_rd_thread(conn) sBUG_ON(current != (conn)->rd_task)
#define iscsi_extracheck_is_wr_thread(conn) sBUG_ON(current != (conn)->wr_task)
#else
static inline void iscsi_extracheck_is_rd_thread(struct iscsi_conn *conn) {}
static inline void iscsi_extracheck_is_wr_thread(struct iscsi_conn *conn) {}
#endif

#endif	/* __ISCSI_H__ */
