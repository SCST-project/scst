/*
 *  scst_priv.h
 *
 *  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
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

#ifndef __SCST_PRIV_H
#define __SCST_PRIV_H

#include <linux/types.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
#include <scsi/scsi_request.h>
#endif

#define LOG_PREFIX "scst"

#include "scst_debug.h"

#define SCST_MAJOR              177

#define TRACE_RTRY              0x80000000
#define TRACE_SCSI_SERIALIZING  0x40000000
/** top being the edge away from the interupt */
#define TRACE_SND_TOP		0x20000000
#define TRACE_RCV_TOP		0x01000000
/** bottom being the edge toward the interupt */
#define TRACE_SND_BOT		0x08000000
#define TRACE_RCV_BOT		0x04000000

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag scst_trace_flag
extern unsigned long scst_trace_flag;
#endif

#ifdef CONFIG_SCST_DEBUG

/* TRACE_MGMT_MINOR disabled to not confuse regular users */
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_PID | \
	TRACE_LINE | TRACE_FUNCTION | TRACE_SPECIAL | TRACE_MGMT | \
	/*TRACE_MGMT_MINOR |*/ TRACE_MGMT_DEBUG | TRACE_RTRY)

#define TRACE_RETRY(args...)		__TRACE(TRACE_RTRY, args)
#define TRACE_SN(args...)		__TRACE(TRACE_SCSI_SERIALIZING, args)
#define TRACE_SEND_TOP(args...)		__TRACE(TRACE_SND_TOP, args)
#define TRACE_RECV_TOP(args...)		__TRACE(TRACE_RCV_TOP, args)
#define TRACE_SEND_BOT(args...)		__TRACE(TRACE_SND_BOT, args)
#define TRACE_RECV_BOT(args...)		__TRACE(TRACE_RCV_BOT, args)

#else /* CONFIG_SCST_DEBUG */

# ifdef CONFIG_SCST_TRACING
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_MGMT | \
	TRACE_SPECIAL)
# else
#define SCST_DEFAULT_LOG_FLAGS 0
# endif

#define TRACE_RETRY(args...)
#define TRACE_SN(args...)
#define TRACE_SEND_TOP(args...)
#define TRACE_RECV_TOP(args...)
#define TRACE_SEND_BOT(args...)
#define TRACE_RECV_BOT(args...)

#endif

/**
 ** Bits for scst_flags
 **/

/*
 * Set if new commands initialization is being suspended for a while.
 * Used to let TM commands execute while preparing the suspend, since
 * RESET or ABORT could be necessary to free SCSI commands.
 */
#define SCST_FLAG_SUSPENDING		     0

/* Set if new commands initialization is suspended for a while */
#define SCST_FLAG_SUSPENDED		     1

/**
 ** Return codes for cmd state process functions. Codes are the same as
 ** for SCST_EXEC_* to avoid translation to them and, hence, have better code.
 **/
#define SCST_CMD_STATE_RES_CONT_NEXT         SCST_EXEC_COMPLETED
#define SCST_CMD_STATE_RES_CONT_SAME         SCST_EXEC_NOT_COMPLETED
#define SCST_CMD_STATE_RES_NEED_THREAD       SCST_EXEC_NEED_THREAD

/**
 ** Maximum count of uncompleted commands that an initiator could
 ** queue on any device. Then it will start getting TASK QUEUE FULL status.
 **/
#define SCST_MAX_TGT_DEV_COMMANDS            48

/**
 ** Maximum count of uncompleted commands that could be queued on any device.
 ** Then initiators sending commands to this device will start getting
 ** TASK QUEUE FULL status.
 **/
#define SCST_MAX_DEV_COMMANDS                256

#define SCST_TGT_RETRY_TIMEOUT               (3/2*HZ)

extern unsigned int scst_max_dev_cmd_mem;

extern mempool_t *scst_mgmt_mempool;
extern mempool_t *scst_mgmt_stub_mempool;
extern mempool_t *scst_ua_mempool;
extern mempool_t *scst_sense_mempool;

extern struct kmem_cache *scst_cmd_cachep;
extern struct kmem_cache *scst_sess_cachep;
extern struct kmem_cache *scst_tgtd_cachep;
extern struct kmem_cache *scst_acgd_cachep;

extern spinlock_t scst_main_lock;

extern struct scst_sgv_pools scst_sgv;

extern unsigned long scst_flags;
extern struct mutex scst_mutex;
extern atomic_t scst_cmd_count;
extern struct list_head scst_dev_list;
extern struct list_head scst_dev_type_list;
extern wait_queue_head_t scst_dev_cmd_waitQ;

extern struct list_head scst_acg_list;
extern struct scst_acg *scst_default_acg;

extern spinlock_t scst_init_lock;
extern struct list_head scst_init_cmd_list;
extern wait_queue_head_t scst_init_cmd_list_waitQ;
extern unsigned int scst_init_poll_cnt;

extern struct scst_cmd_lists scst_main_cmd_lists;

extern spinlock_t scst_mcmd_lock;
/* The following lists protected by scst_mcmd_lock */
extern struct list_head scst_active_mgmt_cmd_list;
extern struct list_head scst_delayed_mgmt_cmd_list;
extern wait_queue_head_t scst_mgmt_cmd_list_waitQ;

struct scst_tasklet {
	spinlock_t tasklet_lock;
	struct list_head tasklet_cmd_list;
	struct tasklet_struct tasklet;
};
extern struct scst_tasklet scst_tasklets[NR_CPUS];

extern wait_queue_head_t scst_mgmt_waitQ;
extern spinlock_t scst_mgmt_lock;
extern struct list_head scst_sess_init_list;
extern struct list_head scst_sess_shut_list;

struct scst_cmd_thread_t {
	struct task_struct *cmd_thread;
	struct list_head thread_list_entry;
};

struct scst_threads_info_t {
	struct mutex cmd_threads_mutex;
	u32 nr_cmd_threads;
	struct list_head cmd_threads_list;
	struct task_struct *init_cmd_thread;
	struct task_struct *mgmt_thread;
	struct task_struct *mgmt_cmd_thread;
};

extern struct scst_threads_info_t scst_threads_info;
extern int scst_cmd_threads_count(void);
extern int __scst_add_cmd_threads(int num);
extern void __scst_del_cmd_threads(int num);

extern spinlock_t scst_temp_UA_lock;
extern uint8_t scst_temp_UA[SCST_SENSE_BUFFERSIZE];

extern struct scst_dev_type scst_null_devtype;

extern struct scst_cmd *__scst_check_deferred_commands(
	struct scst_tgt_dev *tgt_dev);

/* Used to save the function call on the fast path */
static inline struct scst_cmd *scst_check_deferred_commands(
	struct scst_tgt_dev *tgt_dev)
{
	if (tgt_dev->def_cmd_count == 0)
		return NULL;
	else
		return __scst_check_deferred_commands(tgt_dev);
}

static inline void scst_make_deferred_commands_active(
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_cmd *c;

	c = __scst_check_deferred_commands(tgt_dev);
	if (c != NULL) {
		TRACE_SN("Adding cmd %p to active cmd list", c);
		spin_lock_irq(&c->cmd_lists->cmd_list_lock);
		list_add_tail(&c->cmd_list_entry,
			&c->cmd_lists->active_cmd_list);
		wake_up(&c->cmd_lists->cmd_list_waitQ);
		spin_unlock_irq(&c->cmd_lists->cmd_list_lock);
	}

	return;
}

void scst_inc_expected_sn(struct scst_tgt_dev *tgt_dev, atomic_t *slot);
int scst_check_hq_cmd(struct scst_cmd *cmd);

void scst_unblock_deferred(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *cmd_sn);

void scst_on_hq_cmd_response(struct scst_cmd *cmd);
void scst_xmit_process_aborted_cmd(struct scst_cmd *cmd);

int scst_cmd_thread(void *arg);
void scst_cmd_tasklet(long p);
int scst_init_cmd_thread(void *arg);
int scst_mgmt_cmd_thread(void *arg);
int scst_mgmt_thread(void *arg);

int scst_add_dev_threads(struct scst_device *dev, int num);
void scst_del_dev_threads(struct scst_device *dev, int num);

int scst_alloc_device(gfp_t gfp_mask, struct scst_device **out_dev);
void scst_free_device(struct scst_device *dev);

struct scst_acg *scst_alloc_add_acg(const char *acg_name);
int scst_destroy_acg(struct scst_acg *acg);

int scst_sess_alloc_tgt_devs(struct scst_session *sess);
void scst_nexus_loss(struct scst_tgt_dev *tgt_dev);

int scst_acg_add_dev(struct scst_acg *acg, struct scst_device *dev,
		     uint64_t lun, int read_only);
int scst_acg_remove_dev(struct scst_acg *acg, struct scst_device *dev);

int scst_acg_add_name(struct scst_acg *acg, const char *name);
int scst_acg_remove_name(struct scst_acg *acg, const char *name);

int scst_prepare_request_sense(struct scst_cmd *orig_cmd);
struct scst_cmd *scst_complete_request_sense(struct scst_cmd *cmd);

int scst_assign_dev_handler(struct scst_device *dev,
	struct scst_dev_type *handler);

struct scst_session *scst_alloc_session(struct scst_tgt *tgt, gfp_t gfp_mask,
	const char *initiator_name);
void scst_free_session(struct scst_session *sess);
void scst_free_session_callback(struct scst_session *sess);

struct scst_cmd *scst_alloc_cmd(gfp_t gfp_mask);
void scst_free_cmd(struct scst_cmd *cmd);
static inline void scst_destroy_cmd(struct scst_cmd *cmd)
{
	kmem_cache_free(scst_cmd_cachep, cmd);
	return;
}

void scst_check_retries(struct scst_tgt *tgt);
void scst_tgt_retry_timer_fn(unsigned long arg);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
int scst_alloc_request(struct scst_cmd *cmd);
void scst_release_request(struct scst_cmd *cmd);

static inline void scst_do_req(struct scsi_request *sreq,
	const void *cmnd, void *buffer, unsigned bufflen,
	void (*done)(struct scsi_cmnd *), int timeout, int retries)
{
#ifdef CONFIG_SCST_STRICT_SERIALIZING
	scsi_do_req(sreq, cmnd, buffer, bufflen, done, timeout, retries);
#elif !defined(SCSI_EXEC_REQ_FIFO_DEFINED)
	sBUG();
#else
	scsi_do_req_fifo(sreq, cmnd, buffer, bufflen, done, timeout, retries);
#endif
}
#else
static inline int scst_exec_req(struct scsi_device *sdev,
	const unsigned char *cmd, int cmd_len, int data_direction,
	void *buffer, unsigned bufflen,	int use_sg, int timeout, int retries,
	void *privdata, void (*done)(void *, char *, int, int), gfp_t gfp)
{
#ifdef CONFIG_SCST_STRICT_SERIALIZING
	return scsi_execute_async(sdev, cmd, cmd_len, data_direction, buffer,
		    bufflen, use_sg, timeout, retries, privdata, done, gfp);
#elif !defined(SCSI_EXEC_REQ_FIFO_DEFINED)
	sBUG();
	return -1;
#else
	return scsi_execute_async_fifo(sdev, cmd, cmd_len, data_direction,
	    buffer, bufflen, use_sg, timeout, retries, privdata, done, gfp);
#endif
}
#endif

int scst_alloc_space(struct scst_cmd *cmd);
void scst_scsi_op_list_init(void);

enum scst_sg_copy_dir {
	SCST_SG_COPY_FROM_TARGET,
	SCST_SG_COPY_TO_TARGET
};
void scst_copy_sg(struct scst_cmd *cmd, enum scst_sg_copy_dir);

uint64_t scst_unpack_lun(const uint8_t *lun, int len);

struct scst_mgmt_cmd *scst_alloc_mgmt_cmd(gfp_t gfp_mask);
void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd);
void scst_done_cmd_mgmt(struct scst_cmd *cmd);

/* /proc support */
int scst_proc_init_module(void);
void scst_proc_cleanup_module(void);
int scst_build_proc_target_dir_entries(struct scst_tgt_template *vtt);
void scst_cleanup_proc_target_dir_entries(struct scst_tgt_template *vtt);
int scst_build_proc_target_entries(struct scst_tgt *vtt);
void scst_cleanup_proc_target_entries(struct scst_tgt *vtt);
int scst_build_proc_dev_handler_dir_entries(struct scst_dev_type *dev_type);
void scst_cleanup_proc_dev_handler_dir_entries(struct scst_dev_type *dev_type);

int scst_get_cdb_len(const uint8_t *cdb);

void __scst_dev_check_set_UA(struct scst_device *dev, struct scst_cmd *exclude,
	const uint8_t *sense, int sense_len);
static inline void scst_dev_check_set_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len)
{
	spin_lock_bh(&dev->dev_lock);
	__scst_dev_check_set_UA(dev, exclude, sense, sense_len);
	spin_unlock_bh(&dev->dev_lock);
	return;
}
void scst_dev_check_set_local_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len);

void scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int head);
int scst_set_pending_UA(struct scst_cmd *cmd);

void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	int other_ini, int call_dev_task_mgmt_fn);
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd, bool setUA);

static inline int scst_is_ua_command(struct scst_cmd *cmd)
{
	return cmd->cdb[0] != INQUIRY
	       && cmd->cdb[0] != REQUEST_SENSE
	       && cmd->cdb[0] != REPORT_LUNS;
}

static inline int scst_is_implicit_hq(struct scst_cmd *cmd)
{
	return cmd->cdb[0] == INQUIRY
	       || cmd->cdb[0] == REPORT_LUNS
	       || (cmd->dev->type == TYPE_DISK
		   && (cmd->cdb[0] == READ_CAPACITY
		       || (cmd->cdb[0] == SERVICE_ACTION_IN
			   && (cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16)));
}

/*
 * Some notes on devices "blocking". Blocking means that no
 * commands will go from SCST to underlying SCSI device until it
 * is unblocked. But we don't care about all commands that
 * already on the device.
 */

extern int scst_inc_on_dev_cmd(struct scst_cmd *cmd);

extern void __scst_block_dev(struct scst_device *dev);
extern void scst_block_dev_cmd(struct scst_cmd *cmd, int outstanding);
extern void scst_unblock_dev(struct scst_device *dev);
extern void scst_unblock_dev_cmd(struct scst_cmd *cmd);

/* No locks */
static inline void scst_dec_on_dev_cmd(struct scst_cmd *cmd)
{
	struct scst_device *dev = cmd->dev;
	bool unblock_dev = cmd->inc_blocking;

	if (cmd->inc_blocking) {
		TRACE_MGMT_DBG("cmd %p (tag %llu): unblocking dev %p", cmd,
			       (long long unsigned int)cmd->tag, cmd->dev);
		cmd->inc_blocking = 0;
	}
	cmd->dec_on_dev_needed = 0;

	if (unblock_dev)
		scst_unblock_dev(dev);

	atomic_dec(&dev->on_dev_count);
	/* See comment in scst_block_dev() */
	smp_mb__after_atomic_dec();

	TRACE_DBG("New on_dev_count %d", atomic_read(&dev->on_dev_count));

	sBUG_ON(atomic_read(&dev->on_dev_count) < 0);

	if (unlikely(dev->block_count != 0))
		wake_up_all(&dev->on_dev_waitQ);

	return;
}

static inline void __scst_get(int barrier)
{
	atomic_inc(&scst_cmd_count);
	TRACE_DBG("Incrementing scst_cmd_count(%d)",
		atomic_read(&scst_cmd_count));

	/* See comment about smp_mb() in scst_suspend_activity() */
	if (barrier)
		smp_mb__after_atomic_inc();
}

static inline void __scst_put(void)
{
	int f;
	f = atomic_dec_and_test(&scst_cmd_count);
	/* See comment about smp_mb() in scst_suspend_activity() */
	if (f && unlikely(test_bit(SCST_FLAG_SUSPENDED, &scst_flags))) {
		TRACE_MGMT_DBG("%s", "Waking up scst_dev_cmd_waitQ");
		wake_up_all(&scst_dev_cmd_waitQ);
	}
	TRACE_DBG("Decrementing scst_cmd_count(%d)",
	      atomic_read(&scst_cmd_count));
}

void scst_sched_session_free(struct scst_session *sess);

static inline void scst_sess_get(struct scst_session *sess)
{
	atomic_inc(&sess->refcnt);
}

static inline void scst_sess_put(struct scst_session *sess)
{
	if (atomic_dec_and_test(&sess->refcnt))
		scst_sched_session_free(sess);
}

static inline void __scst_cmd_get(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->cmd_ref);
}

static inline void __scst_cmd_put(struct scst_cmd *cmd)
{
	if (atomic_dec_and_test(&cmd->cmd_ref))
		scst_free_cmd(cmd);
}

extern void scst_throttle_cmd(struct scst_cmd *cmd);
extern void scst_unthrottle_cmd(struct scst_cmd *cmd);

static inline void scst_check_restore_sg_buff(struct scst_cmd *cmd)
{
	if (cmd->sg_buff_modified) {
		TRACE_MEM("cmd %p, sg %p, orig_sg_entry %d, "
			"orig_entry_len %d, orig_sg_cnt %d", cmd, cmd->sg,
			cmd->orig_sg_entry, cmd->orig_entry_len,
			cmd->orig_sg_cnt);
		cmd->sg[cmd->orig_sg_entry].length = cmd->orig_entry_len;
		cmd->sg_cnt = cmd->orig_sg_cnt;
		cmd->sg_buff_modified = 0;
	}
}

#ifdef CONFIG_SCST_DEBUG_TM
extern void tm_dbg_check_released_cmds(void);
extern int tm_dbg_check_cmd(struct scst_cmd *cmd);
extern void tm_dbg_release_cmd(struct scst_cmd *cmd);
extern void tm_dbg_task_mgmt(struct scst_device *dev, const char *fn,
	int force);
extern int tm_dbg_is_release(void);
#else
static inline void tm_dbg_check_released_cmds(void) {}
static inline int tm_dbg_check_cmd(struct scst_cmd *cmd)
{
	return 0;
}
static inline void tm_dbg_release_cmd(struct scst_cmd *cmd) {}
static inline void tm_dbg_task_mgmt(struct scst_device *dev, const char *fn,
	int force) {}
static inline int tm_dbg_is_release(void)
{
	return 0;
}
#endif /* CONFIG_SCST_DEBUG_TM */

#ifdef CONFIG_SCST_DEBUG_SN
void scst_check_debug_sn(struct scst_cmd *cmd);
#else
static inline void scst_check_debug_sn(struct scst_cmd *cmd) {}
#endif

/*
 * It deals with comparing 32 bit unsigned ints and worry about wraparound
 * (automatic with unsigned arithmetic). Borrowed from net/tcp.h.
 */
static inline int scst_sn_before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1-seq2) < 0;
}

#endif /* __SCST_PRIV_H */
