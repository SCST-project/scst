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

#ifndef __ISCSI_H__
#define __ISCSI_H__

#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/sock.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/iscsi_scst.h>
#else
#include <scst.h>
#include "iscsi_scst.h"
#endif
#include "iscsi_hdr.h"
#include "iscsi_dbg.h"

#define iscsi_sense_crc_error			ABORTED_COMMAND, 0x47, 0x05
#define iscsi_sense_unexpected_unsolicited_data	ABORTED_COMMAND, 0x0C, 0x0C
#define iscsi_sense_incorrect_amount_of_data	ABORTED_COMMAND, 0x0C, 0x0D

struct iscsi_sess_params {
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

struct iscsi_tgt_params {
	int queued_cmnds;
	unsigned int rsp_timeout;
	unsigned int nop_in_interval;
	unsigned int nop_in_timeout;
};

struct iscsi_thread {
	struct task_struct *thr;
	struct list_head threads_list_entry;
};

struct iscsi_thread_pool {
	spinlock_t rd_lock;
	struct list_head rd_list;
	wait_queue_head_t rd_waitQ;

	/* It's used by another thread, hence aligned */
	spinlock_t wr_lock ____cacheline_aligned_in_smp;
	struct list_head wr_list;
	wait_queue_head_t wr_waitQ;

	cpumask_t cpu_mask;

	int thread_pool_ref;

	struct list_head threads_list;

	struct list_head thread_pools_list_entry;
};


struct iscsi_target;
struct iscsi_cmnd;

#ifndef CONFIG_SCST_PROC
struct iscsi_attr {
	struct list_head attrs_list_entry;
	struct kobj_attribute attr;
	struct iscsi_target *target;
	const char *name;
};
#endif

struct iscsi_target {
	struct scst_tgt *scst_tgt;

	struct mutex target_mutex;

	struct list_head session_list; /* protected by target_mutex */

	struct list_head target_list_entry;
	u32 tid;

	unsigned int tgt_enabled:1;

#ifndef CONFIG_SCST_PROC
	/* Protected by target_mutex */
	struct list_head attrs_list;
#endif

	char name[ISCSI_NAME_LEN];
};

#define ISCSI_HASH_ORDER	8
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
#define	cmnd_hashfn(itt)	hash_32(itt, ISCSI_HASH_ORDER)
#else
#define	cmnd_hashfn(itt)	hash_long(itt, ISCSI_HASH_ORDER)
#endif

struct iscsi_session {
	struct iscsi_target *target;
	struct scst_session *scst_sess;

	struct list_head pending_list; /* protected by sn_lock */

	/* Unprotected, since accessed only from a single read thread */
	u32 next_ttt;

	/* Read only, if there are connection(s) */
	struct iscsi_tgt_params tgt_params;
	atomic_t active_cmds;

	spinlock_t sn_lock;
	u32 exp_cmd_sn; /* protected by sn_lock */

	/* All 3 protected by sn_lock */
	int tm_active;
	u32 tm_sn;
	struct iscsi_cmnd *tm_rsp;

	/* Read only, if there are connection(s) */
	struct iscsi_sess_params sess_params;

	/*
	 * In some corner cases commands can be deleted from the hash
	 * not from the corresponding read thread. So, let's simplify
	 * errors recovery and have this lock.
	 */
	spinlock_t cmnd_data_wait_hash_lock;
	struct list_head cmnd_data_wait_hash[1 << ISCSI_HASH_ORDER];

	struct list_head conn_list; /* protected by target_mutex */

	struct list_head session_list_entry;

	/* All protected by target_mutex, where necessary */
	struct iscsi_session *sess_reinst_successor;
	unsigned int sess_reinstating:1;
	unsigned int sess_shutting_down:1;

	struct iscsi_thread_pool *sess_thr_pool;

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

#define ISCSI_CONN_REINSTATING	1
#define ISCSI_CONN_SHUTTINGDOWN	2
	unsigned long conn_aflags;

	spinlock_t cmd_list_lock; /* BH lock */

	/* Protected by cmd_list_lock */
	struct list_head cmd_list; /* in/outcoming pdus */

	atomic_t conn_ref_cnt;

	spinlock_t write_list_lock;
	/* List of data pdus to be sent. Protected by write_list_lock */
	struct list_head write_list;
	/* List of data pdus being sent. Protected by write_list_lock */
	struct list_head write_timeout_list;

	/* Protected by write_list_lock */
	struct timer_list rsp_timer;
	unsigned int data_rsp_timeout; /* in jiffies */

	/*
	 * All 2 protected by wr_lock. Modified independently to the
	 * above field, hence the alignment.
	 */
	unsigned short wr_state __aligned(sizeof(long));
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

	/* Both read only. Stay here for better CPU cache locality. */
	int hdigest_type;
	int ddigest_type;

	struct iscsi_thread_pool *conn_thr_pool;

	/* All 6 protected by rd_lock */
	unsigned short rd_state;
	unsigned short rd_data_ready:1;
	/* Let's save some cache footprint by putting them here */
	unsigned short closing:1;
	unsigned short active_close:1;
	unsigned short deleting:1;
	unsigned short conn_tm_active:1;

	struct list_head rd_list_entry;

#ifdef CONFIG_SCST_EXTRACHECKS
	struct task_struct *rd_task;
#endif

	unsigned long last_rcv_time;

	/*
	 * All are unprotected, since accessed only from a single read
	 * thread.
	 */
	struct iscsi_cmnd *read_cmnd;
	struct msghdr read_msg;
	u32 read_size;
	int read_state;
	struct iovec *read_iov;
	struct task_struct *rx_task;
	uint32_t rpadding;

	struct iscsi_target *target;

	struct list_head conn_list_entry; /* list entry in session conn_list */

	/* All protected by target_mutex, where necessary */
	struct iscsi_conn *conn_reinst_successor;
	struct list_head reinst_pending_cmd_list;

	wait_queue_head_t read_state_waitQ;
	struct completion ready_to_free;

	/* Doesn't need any protection */
	u16 cid;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
	struct delayed_work nop_in_delayed_work;
#else
	struct work_struct nop_in_delayed_work;
#endif
	unsigned int nop_in_interval; /* in jiffies */
	unsigned int nop_in_timeout; /* in jiffies */
	struct list_head nop_req_list;
	spinlock_t nop_req_list_lock;
	u32 nop_in_ttt;

#ifndef CONFIG_SCST_PROC
	/* Don't need any protection */
	struct kobject conn_kobj;
	struct completion *conn_kobj_release_cmpl;
#endif /* CONFIG_SCST_PROC */
};

struct iscsi_pdu {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	unsigned int datasize;
};

typedef void (iscsi_show_info_t)(struct seq_file *seq,
				 struct iscsi_target *target);

/** Commands' states **/

/* New command and SCST processes it */
#define ISCSI_CMD_STATE_NEW		0

/* SCST processes cmd after scst_rx_cmd() */
#define ISCSI_CMD_STATE_RX_CMD		1

/* The command returned from preprocessing_done() */
#define ISCSI_CMD_STATE_AFTER_PREPROC	2

/* The command is waiting for session or connection reinstatement finished */
#define ISCSI_CMD_STATE_REINST_PENDING	3

/* scst_restart_cmd() called and SCST processing it */
#define ISCSI_CMD_STATE_RESTARTED	4

/* SCST done processing */
#define ISCSI_CMD_STATE_PROCESSED	5

/* AEN processing */
#define ISCSI_CMD_STATE_AEN		6

/* Out of SCST core preliminary completed */
#define ISCSI_CMD_STATE_OUT_OF_SCST_PRELIM_COMPL 7

/*
 * Most of the fields don't need any protection, since accessed from only a
 * single thread, except where noted.
 *
 * ToDo: Eventually divide request and response structures in 2 separate
 * structures and stop this IET-derived garbage.
 */
struct iscsi_cmnd {
	struct iscsi_conn *conn;

	/*
	 * Some flags used under conn->write_list_lock, but all modified only
	 * from single read thread or when there are no references to cmd.
	 */
	unsigned int hashed:1;
	unsigned int should_close_conn:1;
	unsigned int should_close_all_conn:1;
	unsigned int pending:1;
	unsigned int own_sg:1;
	unsigned int on_write_list:1;
	unsigned int write_processing_started:1;
	unsigned int force_cleanup_done:1;
	unsigned int dec_active_cmds:1;
	unsigned int ddigest_checked:1;
	/*
	 * Used to prevent release of original req while its related DATA OUT
	 * cmd is receiving data, i.e. stays between data_out_start() and
	 * data_out_end(). Ref counting can't be used for that, because
	 * req_cmnd_release() supposed to be called only once.
	 */
	unsigned int data_out_in_data_receiving:1;
	unsigned int force_release_done:1;
#ifdef CONFIG_SCST_EXTRACHECKS
	unsigned int on_rx_digest_list:1;
	unsigned int release_called:1;
#endif

	/*
	 * We suppose that preliminary commands completion is tested by
	 * comparing prelim_compl_flags with 0. Otherwise, because of the
	 * gap between setting different flags a race is possible,
	 * like sending command in SCST core as PRELIM_COMPLETED, while it
	 * wasn't aborted in it yet and have as the result a wrong success
	 * status sent to the initiator.
	 */
#define ISCSI_CMD_ABORTED		0
#define ISCSI_CMD_PRELIM_COMPLETED	1
	unsigned long prelim_compl_flags;

	struct list_head hash_list_entry;

	/*
	 * Unions are for readability and grepability and to save some
	 * cache footprint.
	 */

	union {
		/*
		 * Used only to abort not yet sent responses. Usage in
		 * cmnd_done() is only a side effect to have a lockless
		 * accesss to this list from always only a single thread
		 * at any time. So, all responses live in the parent
		 * until it has the last reference put.
		 */
		struct list_head rsp_cmd_list;
		struct list_head rsp_cmd_list_entry;
	};

	union {
		struct list_head pending_list_entry;
		struct list_head reinst_pending_cmd_list_entry;
	};

	union {
		struct list_head write_list_entry;
		struct list_head write_timeout_list_entry;
	};

	/* Both protected by conn->write_list_lock */
	unsigned int on_write_timeout_list:1;
	unsigned long write_start;

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

			int scst_state;
			union {
				struct scst_cmd *scst_cmd;
				struct scst_aen *scst_aen;
			};

			struct iscsi_cmnd *main_rsp;

			/*
			 * Protected on modify by conn->write_list_lock, hence
			 * modified independently to the above field, hence the
			 * alignment.
			 */
			int not_processed_rsp_cnt __aligned(sizeof(long));
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
	unsigned int r2t_len_to_receive;
	unsigned int r2t_len_to_send;
	unsigned int outstanding_r2t;
	u32 target_task_tag;
	__be32 hdigest;
	__be32 ddigest;

	struct list_head cmd_list_entry;
	struct list_head nop_req_list_entry;

	unsigned int not_received_data_len;
};

/* Max time to wait for our response satisfied for aborted commands */
#define ISCSI_TM_DATA_WAIT_TIMEOUT	(10 * HZ)

/*
 * Needed addition to all timeouts to complete a burst of commands at once.
 * Otherwise, a part of the burst can be timeouted only in double timeout time.
 */
#define ISCSI_ADD_SCHED_TIME		HZ

#define ISCSI_CTR_OPEN_STATE_CLOSED	0
#define ISCSI_CTR_OPEN_STATE_OPEN	1
#define ISCSI_CTR_OPEN_STATE_CLOSING	2

extern struct mutex target_mgmt_mutex;

extern int ctr_open_state;
extern const struct file_operations ctr_fops;

extern struct kmem_cache *iscsi_conn_cache;
extern struct kmem_cache *iscsi_sess_cache;

/* iscsi.c */
extern struct iscsi_cmnd *cmnd_alloc(struct iscsi_conn *,
	struct iscsi_cmnd *parent);
extern int cmnd_rx_start(struct iscsi_cmnd *);
extern int cmnd_rx_continue(struct iscsi_cmnd *req);
extern void cmnd_rx_end(struct iscsi_cmnd *);
extern void cmnd_tx_start(struct iscsi_cmnd *);
extern void cmnd_tx_end(struct iscsi_cmnd *);
extern void req_cmnd_release_force(struct iscsi_cmnd *req);
extern void rsp_cmnd_release(struct iscsi_cmnd *);
extern void cmnd_done(struct iscsi_cmnd *cmnd);
extern void conn_abort(struct iscsi_conn *conn);
extern void iscsi_restart_cmnd(struct iscsi_cmnd *cmnd);
extern void iscsi_fail_data_waiting_cmnd(struct iscsi_cmnd *cmnd);
extern void iscsi_send_nop_in(struct iscsi_conn *conn);
extern int iscsi_preliminary_complete(struct iscsi_cmnd *req,
	struct iscsi_cmnd *orig_req, bool get_data);
extern int set_scst_preliminary_status_rsp(struct iscsi_cmnd *req,
	bool get_data, int key, int asc, int ascq);
extern int iscsi_threads_pool_get(const cpumask_t *cpu_mask,
	struct iscsi_thread_pool **out_pool);
extern void iscsi_threads_pool_put(struct iscsi_thread_pool *p);

/* conn.c */
#ifndef CONFIG_SCST_PROC
extern struct kobj_type iscsi_conn_ktype;
#endif
extern struct iscsi_conn *conn_lookup(struct iscsi_session *, u16);
extern void conn_reinst_finished(struct iscsi_conn *);
extern int __add_conn(struct iscsi_session *, struct iscsi_kern_conn_info *);
extern int __del_conn(struct iscsi_session *, struct iscsi_kern_conn_info *);
extern int conn_free(struct iscsi_conn *);
extern void iscsi_make_conn_rd_active(struct iscsi_conn *conn);
#define ISCSI_CONN_ACTIVE_CLOSE		1
#define ISCSI_CONN_DELETING		2
extern void __mark_conn_closed(struct iscsi_conn *, int);
extern void mark_conn_closed(struct iscsi_conn *);
extern void iscsi_make_conn_wr_active(struct iscsi_conn *);
#ifdef CONFIG_SCST_PROC
extern void conn_info_show(struct seq_file *, struct iscsi_session *);
#endif
extern void iscsi_check_tm_data_wait_timeouts(struct iscsi_conn *conn,
	bool force);
extern void __iscsi_write_space_ready(struct iscsi_conn *conn);

/* nthread.c */
extern int iscsi_send(struct iscsi_conn *conn);
#if defined(CONFIG_TCP_ZERO_COPY_TRANSFER_COMPLETION_NOTIFICATION)
extern void iscsi_get_page_callback(struct page *page);
extern void iscsi_put_page_callback(struct page *page);
#endif
extern int istrd(void *arg);
extern int istwr(void *arg);
extern void iscsi_task_mgmt_affected_cmds_done(struct scst_mgmt_cmd *scst_mcmd);
extern void req_add_to_write_timeout_list(struct iscsi_cmnd *req);

/* target.c */
#ifdef CONFIG_SCST_PROC
extern const struct seq_operations iscsi_seq_op;
#else
extern const struct attribute *iscsi_tgt_attrs[];
extern int iscsi_enable_target(struct scst_tgt *scst_tgt, bool enable);
extern bool iscsi_is_target_enabled(struct scst_tgt *scst_tgt);
extern ssize_t iscsi_sysfs_send_event(uint32_t tid,
	enum iscsi_kern_event_code code,
	const char *param1, const char *param2, void **data);
#endif
extern struct iscsi_target *target_lookup_by_id(u32);
extern int __add_target(struct iscsi_kern_target_info *);
extern int __del_target(u32 id);
extern ssize_t iscsi_sysfs_add_target(const char *target_name, char *params);
extern ssize_t iscsi_sysfs_del_target(const char *target_name);
extern ssize_t iscsi_sysfs_mgmt_cmd(char *cmd);
extern void target_del_session(struct iscsi_target *target,
	struct iscsi_session *session, int flags);
extern void target_del_all_sess(struct iscsi_target *target, int flags);
extern void target_del_all(void);

/* config.c */
#ifdef CONFIG_SCST_PROC
extern int iscsi_procfs_init(void);
extern void iscsi_procfs_exit(void);
#else
extern const struct attribute *iscsi_attrs[];
extern int iscsi_add_attr(struct iscsi_target *target,
	const struct iscsi_kern_attr *user_info);
extern void __iscsi_del_attr(struct iscsi_target *target,
	struct iscsi_attr *tgt_attr);
#endif

/* session.c */
#ifndef CONFIG_SCST_PROC
extern const struct attribute *iscsi_sess_attrs[];
#endif
extern const struct file_operations session_seq_fops;
extern struct iscsi_session *session_lookup(struct iscsi_target *, u64);
extern void sess_reinst_finished(struct iscsi_session *);
extern int __add_session(struct iscsi_target *,
	struct iscsi_kern_session_info *);
extern int __del_session(struct iscsi_target *, u64);
extern int session_free(struct iscsi_session *session, bool del);
extern void iscsi_sess_force_close(struct iscsi_session *sess);

/* params.c */
extern const char *iscsi_get_digest_name(int val, char *res);
extern const char *iscsi_get_bool_value(int val);
extern int iscsi_params_set(struct iscsi_target *,
	struct iscsi_kern_params_info *, int);

/* event.c */
extern int event_send(u32, u64, u32, u32, enum iscsi_kern_event_code,
	const char *param1, const char *param2);
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
	pdu->ahssize = ((__force __u32)pdu->bhs.length & 0xff) * 4;
	pdu->datasize = be32_to_cpu((__force __be32)((__force __u32)pdu->bhs.length & ~0xff));
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
	pdu->bhs.length = cpu_to_be32(pdu->datasize) | (__force __be32)(pdu->ahssize / 4);
#else
#error
#endif
}

extern struct scst_tgt_template iscsi_template;

/*
 * Skip this command if result is true. Must be called under
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
	/*
	 * For the same reason as in kref_get(). Let's be safe and
	 * always do it.
	 */
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
	struct iscsi_cmnd *parent = cmnd->parent_req;

	TRACE_DBG("cmnd %p", cmnd);
	/* See comment in iscsi_restart_cmnd() */
	EXTRACHECKS_BUG_ON(cmnd->parent_req->hashed &&
		(cmnd_opcode(cmnd) != ISCSI_OP_R2T));
	list_add_tail(&cmnd->write_list_entry, &conn->write_list);
	cmnd->on_write_list = 1;

	parent->not_processed_rsp_cnt++;
	TRACE_DBG("not processed rsp cnt %d (parent %p)",
		parent->not_processed_rsp_cnt, parent);
}

/* conn->write_list_lock supposed to be locked and BHs off */
static inline void cmd_del_from_write_list(struct iscsi_cmnd *cmnd)
{
	struct iscsi_cmnd *parent = cmnd->parent_req;

	TRACE_DBG("%p", cmnd);
	list_del(&cmnd->write_list_entry);
	cmnd->on_write_list = 0;

	parent->not_processed_rsp_cnt--;
	TRACE_DBG("not processed rsp cnt %d (parent %p)",
		parent->not_processed_rsp_cnt, parent);
	EXTRACHECKS_BUG_ON(parent->not_processed_rsp_cnt < 0);
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

static inline unsigned long iscsi_get_timeout(struct iscsi_cmnd *req)
{
	unsigned long res;

	res = (cmnd_opcode(req) == ISCSI_OP_NOP_OUT) ?
			req->conn->nop_in_timeout : req->conn->data_rsp_timeout;

	if (unlikely(test_bit(ISCSI_CMD_ABORTED, &req->prelim_compl_flags)))
		res = min_t(unsigned long, res, ISCSI_TM_DATA_WAIT_TIMEOUT);

	return res;
}

static inline unsigned long iscsi_get_timeout_time(struct iscsi_cmnd *req)
{
	return req->write_start + iscsi_get_timeout(req);
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
	/*
	 * For the same reason as in kref_get(). Let's be safe and
	 * always do it.
	 */
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
