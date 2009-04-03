/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2008 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
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

#include <scst.h>

#include "iscsi_hdr.h"
#include "iscsi_scst.h"

#include "iscsi_dbg.h"

#define iscsi_sense_crc_error		ABORTED_COMMAND, 0x47, 0x5

struct iscsi_sess_param {
	int initial_r2t;
	int immediate_data;
	int max_connections;
	unsigned int max_recv_data_length;
	unsigned int max_xmit_data_length;
	unsigned int max_burst_length;
	unsigned int first_burst_length;
	int default_wait_time;
	int default_retain_time;
	unsigned int max_outstanding_r2t;
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

	/* Both protected by target_mgmt_mutex */
	struct iscsi_trgt_param trgt_param;
	/*
	 * Put here to have uniform parameters checking and assigning
	 * from various places, including iscsi-scst-adm.
	 */
	struct iscsi_sess_param trgt_sess_param;

	struct list_head target_list_entry;
	u32 tid;
	char name[ISCSI_NAME_LEN];
};

#define ISCSI_HASH_ORDER	8
#define	cmnd_hashfn(itt)	hash_long((itt), ISCSI_HASH_ORDER)

struct iscsi_session {
	struct iscsi_target *target;
	struct scst_session *scst_sess;

	struct list_head pending_list; /* protected by sn_lock */

	/* Unprotected, since accessed only from a single read thread */
	u32 next_ttt;

	u32 max_queued_cmnds; /* unprotected, since read-only */
	atomic_t active_cmds;

	spinlock_t sn_lock;
	u32 exp_cmd_sn; /* protected by sn_lock */

	/* All 3 protected by sn_lock */
	int tm_active;
	u32 tm_sn;
	struct iscsi_cmnd *tm_rsp;

	/* Read only, if there are connection(s) */
	struct iscsi_sess_param sess_param;

	spinlock_t cmnd_hash_lock;
	struct list_head cmnd_hash[1 << ISCSI_HASH_ORDER];

	struct list_head conn_list; /* protected by target_mutex */

	struct list_head session_list_entry;

	/* All protected by target_mutex, where necessary */
	struct iscsi_session *sess_reinst_successor;
	unsigned int sess_reinstating:1;
	unsigned int sess_shutting_down:1;
	unsigned int deleted_from_session_list:1;

	/* All don't need any protection */
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

	/* Protected by cmd_list_lock */
	struct list_head cmd_list; /* in/outcoming pdus */

	atomic_t conn_ref_cnt;

	spinlock_t write_list_lock;
	/* List of data pdus to be sent, protected by write_list_lock */
	struct list_head write_list;
	/* List of data pdus being sent, protected by write_list_lock */
	struct list_head written_list;

	struct timer_list rsp_timer;

	/* All 2 protected by iscsi_wr_lock */
	unsigned short wr_state;
	unsigned short wr_space_ready:1;

	struct list_head wr_list_entry;

#ifdef CONFIG_SCST_EXTRACHECKS
	struct task_struct *wr_task;
#endif

	/*
	 * All are unprotected, since accessed only from a single write
	 * thread.
	 */
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

	/* All 5 protected by iscsi_rd_lock */
	unsigned short rd_state;
	unsigned short rd_data_ready:1;
	/* Let's save some cache footprint by putting them here */
	unsigned short closing:1;
	unsigned short active_close:1;
	unsigned short deleting:1;

	struct list_head rd_list_entry;

#ifdef CONFIG_SCST_EXTRACHECKS
	struct task_struct *rd_task;
#endif

	/*
	 * All are unprotected, since accessed only from a single read
	 * thread.
	 */
	struct iscsi_cmnd *read_cmnd;
	struct msghdr read_msg;
	u32 read_size;
	int read_state;
	struct iovec *read_iov;
	uint32_t rpadding;

	struct iscsi_target *target;

	struct list_head conn_list_entry; /* list entry in session conn_list */

	/* All protected by target_mutex, where necessary */
	struct iscsi_conn *conn_reinst_successor;
	unsigned int conn_reinstating:1;
	unsigned int conn_shutting_down:1;

	struct completion ready_to_free;

	/* Doesn't need any protection */
	u16 cid;
};

struct iscsi_pdu {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	unsigned int datasize;
};

typedef void (iscsi_show_info_t)(struct seq_file *seq,
				 struct iscsi_target *target);

/** Command's states **/

/* New command and SCST processes it */
#define ISCSI_CMD_STATE_NEW               0

/* SCST processes cmd after scst_rx_cmd() */
#define ISCSI_CMD_STATE_RX_CMD            1

/* The command returned from preprocessing_done() */
#define ISCSI_CMD_STATE_AFTER_PREPROC     2

/* scst_restart_cmd() called and SCST processing it */
#define ISCSI_CMD_STATE_RESTARTED         3

/* SCST done processing */
#define ISCSI_CMD_STATE_PROCESSED         4

/* AEN processing */
#define ISCSI_CMD_STATE_AEN               5

/** Command's reject reasons **/
#define ISCSI_REJECT_SCSI_CMD             1
#define ISCSI_REJECT_CMD                  2
#define ISCSI_REJECT_DATA                 3

/*
 * Most of the fields don't need any protection, since accessed from only a
 * single thread, except where noted.
 */
struct iscsi_cmnd {
	struct iscsi_conn *conn;

	/*
	 * Some flags protected by conn->write_list_lock, but all modified only
	 * from single read thread or when there are no references to cmd.
	 */
	unsigned int hashed:1;
	unsigned int should_close_conn:1;
	unsigned int should_close_all_conn:1;
	unsigned int pending:1;
	unsigned int own_sg:1;
	unsigned int on_write_list:1;
	unsigned int write_processing_started:1;
	unsigned int data_waiting:1;
	unsigned int force_cleanup_done:1;
	unsigned int dec_active_cmnds:1;
	unsigned int ddigest_checked:1;
	unsigned int rejected:1;
	unsigned int reject_reason:2;
#ifdef CONFIG_SCST_EXTRACHECKS
	unsigned int on_rx_digest_list:1;
	unsigned int release_called:1;
#endif

	/* It's async. with the above flags */
	volatile unsigned int tm_aborted;

	struct list_head hash_list_entry;

	spinlock_t rsp_cmd_lock; /* BH lock */

	/*
	 * Unions are for readability and grepability and to save some
	 * cache footprint.
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

	/* Both modified only from single write thread */
	unsigned int on_written_list:1;
	unsigned long write_timeout;

	/*
	 * All unprotected, since could be accessed from only a single
	 * thread at time
	 */
	struct iscsi_cmnd *parent_req;
	struct iscsi_cmnd *cmd_req;

	/*
	 * All unprotected, since could be accessed from only a single
	 * thread at time
	 */
	union {
		/* Request only fields */
		struct {
			struct list_head rx_ddigest_cmd_list;
			struct list_head rx_ddigest_cmd_list_entry;

			wait_queue_head_t scst_waitQ;
			int scst_state;
			union {
				struct scst_cmd *scst_cmd;
				struct scst_aen *scst_aen;
			};
		};

		/* Response only fields */
		struct {
			struct scatterlist rsp_sg[2];
			struct iscsi_sense_data sense_hdr;
		};
	};

	atomic_t ref_cnt;
#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
	atomic_t net_ref_cnt;
#endif

	struct iscsi_pdu pdu;

	struct scatterlist *sg;
	int sg_cnt;
	unsigned int bufflen;
	u32 r2t_sn;
	u32 r2t_length;
	u32 is_unsolicited_data;
	u32 target_task_tag;
	u32 outstanding_r2t;

	u32 hdigest;
	u32 ddigest;

	struct list_head cmd_list_entry;
};

/* Flags for req_cmnd_release_force() */
#define ISCSI_FORCE_RELEASE_WRITE	1

#define ISCSI_RSP_TIMEOUT		(30 * HZ)

extern struct mutex target_mgmt_mutex;

extern const struct file_operations ctr_fops;

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
extern void req_cmnd_release_force(struct iscsi_cmnd *req, int flags);
extern void rsp_cmnd_release(struct iscsi_cmnd *);
extern void cmnd_done(struct iscsi_cmnd *cmnd);
extern void conn_abort(struct iscsi_conn *conn);

/* conn.c */
extern struct iscsi_conn *conn_lookup(struct iscsi_session *, u16);
extern void __iscsi_socket_bind(struct iscsi_conn *);
extern int conn_add(struct iscsi_session *, struct iscsi_kern_conn_info *);
extern int conn_del(struct iscsi_session *, struct iscsi_kern_conn_info *);
extern int conn_free(struct iscsi_conn *);

#define ISCSI_CONN_ACTIVE_CLOSE		1
#define ISCSI_CONN_DELETING		2
extern void __mark_conn_closed(struct iscsi_conn *, int);

extern void mark_conn_closed(struct iscsi_conn *);
extern void iscsi_make_conn_wr_active(struct iscsi_conn *);
extern void conn_info_show(struct seq_file *, struct iscsi_session *);

/* nthread.c */
extern int iscsi_send(struct iscsi_conn *conn);
#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
extern void iscsi_get_page_callback(struct page *page);
extern void iscsi_put_page_callback(struct page *page);
#endif
extern int istrd(void *arg);
extern int istwr(void *arg);
extern void iscsi_task_mgmt_affected_cmds_done(struct scst_mgmt_cmd *scst_mcmd);

/* target.c */
struct iscsi_target *target_lookup_by_id(u32);
extern int target_add(struct iscsi_kern_target_info *);
extern int target_del(u32 id);
extern void target_del_session(struct iscsi_target *target,
	struct iscsi_session *session, int flags);
extern void target_del_all_sess(struct iscsi_target *target, int flags);
extern void target_del_all(void);

extern const struct seq_operations iscsi_seq_op;

/* config.c */
extern int iscsi_procfs_init(void);
extern void iscsi_procfs_exit(void);

/* session.c */
extern const struct file_operations session_seq_fops;
extern struct iscsi_session *session_lookup(struct iscsi_target *, u64);
extern void sess_enable_reinstated_sess(struct iscsi_session *);
extern int session_add(struct iscsi_target *, struct iscsi_kern_session_info *);
extern int session_del(struct iscsi_target *, u64);
extern int session_free(struct iscsi_session *session);

/* params.c */
extern int iscsi_param_set(struct iscsi_target *,
	struct iscsi_kern_param_info *, int);

/* event.c */
extern int event_send(u32, u64, u32, u32, int);
extern int event_init(void);
extern void event_exit(void);

#define get_pgcnt(size, offset)	\
	((((size) + ((offset) & ~PAGE_MASK)) + PAGE_SIZE - 1) >> PAGE_SHIFT)

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

/*
 * Skip this command if result is not 0. Must be called under
 * corresponding lock.
 */
static inline bool cmnd_get_check(struct iscsi_cmnd *cmnd)
{
	int r = atomic_inc_return(&cmnd->ref_cnt);
	int res;
	if (unlikely(r == 1)) {
		TRACE_DBG("cmnd %p is being destroyed", cmnd);
		atomic_dec(&cmnd->ref_cnt);
		res = 1;
		/* Necessary code is serialized by locks in cmnd_done() */
	} else {
		TRACE_DBG("cmnd %p, new ref_cnt %d", cmnd,
			atomic_read(&cmnd->ref_cnt));
		res = 0;
	}
	return res;
}

static inline void cmnd_get(struct iscsi_cmnd *cmnd)
{
	atomic_inc(&cmnd->ref_cnt);
	TRACE_DBG("cmnd %p, new cmnd->ref_cnt %d", cmnd,
		atomic_read(&cmnd->ref_cnt));
}

static inline void cmnd_get_ordered(struct iscsi_cmnd *cmnd)
{
	cmnd_get(cmnd);
	/* See comments for each cmnd_get_ordered() use */
	smp_mb__after_atomic_inc();
}

static inline void cmnd_put(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("cmnd %p, new ref_cnt %d", cmnd,
		atomic_read(&cmnd->ref_cnt)-1);

	EXTRACHECKS_BUG_ON(atomic_read(&cmnd->ref_cnt) == 0);

	if (atomic_dec_and_test(&cmnd->ref_cnt))
		cmnd_done(cmnd);
}

/* conn->write_list_lock supposed to be locked and BHs off */
static inline void cmd_add_on_write_list(struct iscsi_conn *conn,
	struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);
	list_add_tail(&cmnd->write_list_entry, &conn->write_list);
	cmnd->on_write_list = 1;
}

/* conn->write_list_lock supposed to be locked and BHs off */
static inline void cmd_del_from_write_list(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("%p", cmnd);
	list_del(&cmnd->write_list_entry);
	cmnd->on_write_list = 0;
}

static inline void cmd_add_on_rx_ddigest_list(struct iscsi_cmnd *req,
	struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("Adding RX ddigest cmd %p to digest list "
			"of req %p", cmnd, req);
	list_add_tail(&cmnd->rx_ddigest_cmd_list_entry,
			&req->rx_ddigest_cmd_list);
#ifdef CONFIG_SCST_EXTRACHECKS
	cmnd->on_rx_digest_list = 1;
#endif
}

static inline void cmd_del_from_rx_ddigest_list(struct iscsi_cmnd *cmnd)
{
	TRACE_DBG("Deleting RX digest cmd %p from digest list", cmnd);
	list_del(&cmnd->rx_ddigest_cmd_list_entry);
#ifdef CONFIG_SCST_EXTRACHECKS
	cmnd->on_rx_digest_list = 0;
#endif
}

static inline int test_write_ready(struct iscsi_conn *conn)
{
	/*
	 * No need for write_list protection, in the worst case we will be
	 * restarted again.
	 */
	return !list_empty(&conn->write_list) || conn->write_cmnd;
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
	/* See comments for each conn_get_ordered() use */
	smp_mb__after_atomic_inc();
}

static inline void conn_put(struct iscsi_conn *conn)
{
	TRACE_DBG("conn %p, new conn_ref_cnt %d", conn,
		atomic_read(&conn->conn_ref_cnt)-1);
	sBUG_ON(atomic_read(&conn->conn_ref_cnt) == 0);

	/*
	 * Make it always ordered to protect from undesired side effects like
	 * accessing just destroyed by close_conn() conn caused by reordering
	 * of this atomic_dec().
	 */
	smp_mb__before_atomic_dec();
	atomic_dec(&conn->conn_ref_cnt);
}

#ifdef CONFIG_SCST_EXTRACHECKS
extern void iscsi_extracheck_is_rd_thread(struct iscsi_conn *conn);
extern void iscsi_extracheck_is_wr_thread(struct iscsi_conn *conn);
#else
static inline void iscsi_extracheck_is_rd_thread(struct iscsi_conn *conn) {}
static inline void iscsi_extracheck_is_wr_thread(struct iscsi_conn *conn) {}
#endif

#endif	/* __ISCSI_H__ */
