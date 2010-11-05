/*
 *  scst_priv.h
 *
 *  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
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

#ifndef __SCST_PRIV_H
#define __SCST_PRIV_H

#include <linux/types.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#define LOG_PREFIX "scst"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_debug.h>
#else
#include "scst_debug.h"
#endif

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

#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_PID | \
	TRACE_LINE | TRACE_FUNCTION | TRACE_SPECIAL | TRACE_MGMT | \
	TRACE_MGMT_DEBUG | TRACE_RTRY)

#define TRACE_RETRY(args...)	TRACE_DBG_FLAG(TRACE_RTRY, args)
#define TRACE_SN(args...)	TRACE_DBG_FLAG(TRACE_SCSI_SERIALIZING, args)
#define TRACE_SEND_TOP(args...)	TRACE_DBG_FLAG(TRACE_SND_TOP, args)
#define TRACE_RECV_TOP(args...)	TRACE_DBG_FLAG(TRACE_RCV_TOP, args)
#define TRACE_SEND_BOT(args...)	TRACE_DBG_FLAG(TRACE_SND_BOT, args)
#define TRACE_RECV_BOT(args...)	TRACE_DBG_FLAG(TRACE_RCV_BOT, args)

#else /* CONFIG_SCST_DEBUG */

# ifdef CONFIG_SCST_TRACING
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
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
#define SCST_CMD_STATE_RES_NEED_THREAD       (SCST_EXEC_NOT_COMPLETED+1)

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

/* Definitions of symbolic constants for LUN addressing method */
#define SCST_LUN_ADDR_METHOD_PERIPHERAL	0
#define SCST_LUN_ADDR_METHOD_FLAT	1

/* Activities suspending timeout */
#define SCST_SUSPENDING_TIMEOUT			(90 * HZ)

extern struct mutex scst_mutex2;

extern int scst_threads;

extern unsigned int scst_max_dev_cmd_mem;

extern mempool_t *scst_mgmt_mempool;
extern mempool_t *scst_mgmt_stub_mempool;
extern mempool_t *scst_ua_mempool;
extern mempool_t *scst_sense_mempool;
extern mempool_t *scst_aen_mempool;

extern struct kmem_cache *scst_cmd_cachep;
extern struct kmem_cache *scst_sess_cachep;
extern struct kmem_cache *scst_tgtd_cachep;
extern struct kmem_cache *scst_acgd_cachep;

extern spinlock_t scst_main_lock;

extern struct scst_sgv_pools scst_sgv;

extern unsigned long scst_flags;
extern atomic_t scst_cmd_count;
extern struct list_head scst_template_list;
extern struct list_head scst_dev_list;
extern struct list_head scst_dev_type_list;
extern struct list_head scst_virtual_dev_type_list;
extern wait_queue_head_t scst_dev_cmd_waitQ;

#ifdef CONFIG_SCST_PROC
extern struct list_head scst_acg_list;
extern struct scst_acg *scst_default_acg;
#else
extern unsigned int scst_setup_id;
#endif

extern spinlock_t scst_init_lock;
extern struct list_head scst_init_cmd_list;
extern wait_queue_head_t scst_init_cmd_list_waitQ;
extern unsigned int scst_init_poll_cnt;

extern struct scst_cmd_threads scst_main_cmd_threads;

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

extern cpumask_t default_cpu_mask;

struct scst_cmd_thread_t {
	struct task_struct *cmd_thread;
	struct list_head thread_list_entry;
};

static inline bool scst_set_io_context(struct scst_cmd *cmd,
	struct io_context **old)
{
	bool res;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	return false;
#endif

#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
	return false;
#endif

	if (cmd->cmd_threads == &scst_main_cmd_threads) {
		EXTRACHECKS_BUG_ON(in_interrupt());
		/*
		 * No need for any ref counting action, because io_context
		 * supposed to be cleared in the end of the caller function.
		 */
		current->io_context = cmd->tgt_dev->async_io_context;
		res = true;
		TRACE_DBG("io_context %p (tgt_dev %p)", current->io_context,
			cmd->tgt_dev);
		EXTRACHECKS_BUG_ON(current->io_context == NULL);
	} else
		res = false;

	return res;
}

static inline void scst_reset_io_context(struct scst_tgt_dev *tgt_dev,
	struct io_context *old)
{
	current->io_context = old;
	TRACE_DBG("io_context %p reset", current->io_context);
	return;
}

/*
 * Converts string presentation of threads pool type to enum.
 * Returns SCST_THREADS_POOL_TYPE_INVALID if the string is invalid.
 */
extern enum scst_dev_type_threads_pool_type scst_parse_threads_pool_type(
	const char *p, int len);

extern int scst_add_threads(struct scst_cmd_threads *cmd_threads,
	struct scst_device *dev, struct scst_tgt_dev *tgt_dev, int num);
extern void scst_del_threads(struct scst_cmd_threads *cmd_threads, int num);

extern int scst_create_dev_threads(struct scst_device *dev);
extern void scst_stop_dev_threads(struct scst_device *dev);

extern int scst_tgt_dev_setup_threads(struct scst_tgt_dev *tgt_dev);
extern void scst_tgt_dev_stop_threads(struct scst_tgt_dev *tgt_dev);

extern bool scst_del_thr_data(struct scst_tgt_dev *tgt_dev,
	struct task_struct *tsk);

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
		spin_lock_irq(&c->cmd_threads->cmd_list_lock);
		list_add_tail(&c->cmd_list_entry,
			&c->cmd_threads->active_cmd_list);
		wake_up(&c->cmd_threads->cmd_list_waitQ);
		spin_unlock_irq(&c->cmd_threads->cmd_list_lock);
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
int scst_init_thread(void *arg);
int scst_tm_thread(void *arg);
int scst_global_mgmt_thread(void *arg);

void scst_zero_write_rest(struct scst_cmd *cmd);
void scst_limit_sg_write_len(struct scst_cmd *cmd);
void scst_adjust_resp_data_len(struct scst_cmd *cmd);

int scst_queue_retry_cmd(struct scst_cmd *cmd, int finished_cmds);

int scst_alloc_tgt(struct scst_tgt_template *tgtt, struct scst_tgt **tgt);
void scst_free_tgt(struct scst_tgt *tgt);

int scst_alloc_device(gfp_t gfp_mask, struct scst_device **out_dev);
void scst_free_device(struct scst_device *dev);

struct scst_acg *scst_alloc_add_acg(struct scst_tgt *tgt,
	const char *acg_name, bool tgt_acg);
void scst_del_free_acg(struct scst_acg *acg);

struct scst_acg *scst_tgt_find_acg(struct scst_tgt *tgt, const char *name);
struct scst_acg *scst_find_acg(const struct scst_session *sess);

void scst_check_reassign_sessions(void);

int scst_sess_alloc_tgt_devs(struct scst_session *sess);
void scst_sess_free_tgt_devs(struct scst_session *sess);
void scst_nexus_loss(struct scst_tgt_dev *tgt_dev, bool queue_UA);

int scst_acg_add_lun(struct scst_acg *acg, struct kobject *parent,
	struct scst_device *dev, uint64_t lun, int read_only,
	bool gen_scst_report_luns_changed, struct scst_acg_dev **out_acg_dev);
int scst_acg_del_lun(struct scst_acg *acg, uint64_t lun,
	bool gen_scst_report_luns_changed);

int scst_acg_add_acn(struct scst_acg *acg, const char *name);
#ifdef CONFIG_SCST_PROC
int scst_acg_remove_name(struct scst_acg *acg, const char *name, bool reassign);
#endif
void scst_del_free_acn(struct scst_acn *acn, bool reassign);
struct scst_acn *scst_find_acn(struct scst_acg *acg, const char *name);

/* The activity supposed to be suspended and scst_mutex held */
static inline bool scst_acg_sess_is_empty(struct scst_acg *acg)
{
	return list_empty(&acg->acg_sess_list);
}

int scst_prepare_request_sense(struct scst_cmd *orig_cmd);
int scst_finish_internal_cmd(struct scst_cmd *cmd);

void scst_store_sense(struct scst_cmd *cmd);

int scst_assign_dev_handler(struct scst_device *dev,
	struct scst_dev_type *handler);

struct scst_session *scst_alloc_session(struct scst_tgt *tgt, gfp_t gfp_mask,
	const char *initiator_name);
void scst_free_session(struct scst_session *sess);
void scst_free_session_callback(struct scst_session *sess);

struct scst_cmd *scst_alloc_cmd(const uint8_t *cdb,
	unsigned int cdb_len, gfp_t gfp_mask);
void scst_free_cmd(struct scst_cmd *cmd);
static inline void scst_destroy_cmd(struct scst_cmd *cmd)
{
	kmem_cache_free(scst_cmd_cachep, cmd);
	return;
}

void scst_check_retries(struct scst_tgt *tgt);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
static inline int scst_exec_req(struct scsi_device *sdev,
	const unsigned char *cmd, int cmd_len, int data_direction,
	struct scatterlist *sgl, unsigned bufflen, unsigned nents,
	int timeout, int retries, void *privdata,
	void (*done)(void *, char *, int, int), gfp_t gfp)
{
#if defined(CONFIG_SCST_STRICT_SERIALIZING)
	return scsi_execute_async(sdev, cmd, cmd_len, data_direction, (void *)sgl,
		    bufflen, nents, timeout, retries, privdata, done, gfp);
#elif !defined(SCSI_EXEC_REQ_FIFO_DEFINED)
	WARN_ON(1);
	return -1;
#else
	return scsi_execute_async_fifo(sdev, cmd, cmd_len, data_direction,
	    (void *)sgl, bufflen, nents, timeout, retries, privdata, done, gfp);
#endif
}
#else /* i.e. LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30) */
#if !defined(SCSI_EXEC_REQ_FIFO_DEFINED)
static inline int scst_scsi_exec_async(struct scst_cmd *cmd, void *data,
	void (*done)(void *data, char *sense, int result, int resid))
{
	WARN_ON_ONCE(1);
	return -1;
}
#endif
#endif

int scst_alloc_space(struct scst_cmd *cmd);

int scst_lib_init(void);
void scst_lib_exit(void);

__be64 scst_pack_lun(const uint64_t lun, unsigned int addr_method);
uint64_t scst_unpack_lun(const uint8_t *lun, int len);

struct scst_mgmt_cmd *scst_alloc_mgmt_cmd(gfp_t gfp_mask);
void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd);
void scst_done_cmd_mgmt(struct scst_cmd *cmd);

static inline void scst_devt_cleanup(struct scst_dev_type *devt) { }

#ifdef CONFIG_SCST_PROC

int scst_proc_init_module(void);
void scst_proc_cleanup_module(void);
int scst_build_proc_target_dir_entries(struct scst_tgt_template *vtt);
void scst_cleanup_proc_target_dir_entries(struct scst_tgt_template *vtt);
int scst_build_proc_target_entries(struct scst_tgt *vtt);
void scst_cleanup_proc_target_entries(struct scst_tgt *vtt);
int scst_build_proc_dev_handler_dir_entries(struct scst_dev_type *dev_type);
void scst_cleanup_proc_dev_handler_dir_entries(struct scst_dev_type *dev_type);

static inline int scst_sysfs_init(void)
{
	return 0;
}
static inline void scst_sysfs_cleanup(void) { }

static inline int scst_devt_dev_sysfs_create(struct scst_device *dev)
{
	return 0;
}
static inline void scst_devt_dev_sysfs_del(struct scst_device *dev) { }

static inline void scst_dev_sysfs_del(struct scst_device *dev) { }

static inline int scst_tgt_dev_sysfs_create(struct scst_tgt_dev *tgt_dev)
{
	return 0;
}
static inline void scst_tgt_dev_sysfs_del(struct scst_tgt_dev *tgt_dev) { }

static inline int scst_sess_sysfs_create(struct scst_session *sess)
{
	return 0;
}

static inline int scst_acg_dev_sysfs_create(struct scst_acg_dev *acg_dev,
	struct kobject *parent)
{
	return 0;
}

static inline void scst_acg_dev_sysfs_del(struct scst_acg_dev *acg_dev) { }

static inline int scst_acn_sysfs_create(struct scst_acn *acn)
{
	return 0;
}
static inline void scst_acn_sysfs_del(struct scst_acn *acn) { }

static inline int scst_sgv_sysfs_create(struct sgv_pool *pool)
{
	return 0;
}
static inline void scst_sgv_sysfs_del(struct sgv_pool *pool) { }

#else /* CONFIG_SCST_PROC */

int scst_sysfs_init(void);
void scst_sysfs_cleanup(void);
int scst_tgtt_sysfs_create(struct scst_tgt_template *tgtt);
void scst_tgtt_sysfs_del(struct scst_tgt_template *tgtt);
int scst_tgt_sysfs_create(struct scst_tgt *tgt);
void scst_tgt_sysfs_prepare_put(struct scst_tgt *tgt);
void scst_tgt_sysfs_del(struct scst_tgt *tgt);
int scst_sess_sysfs_create(struct scst_session *sess);
void scst_sess_sysfs_del(struct scst_session *sess);
int scst_recreate_sess_luns_link(struct scst_session *sess);
int scst_sgv_sysfs_create(struct sgv_pool *pool);
void scst_sgv_sysfs_del(struct sgv_pool *pool);
int scst_devt_sysfs_create(struct scst_dev_type *devt);
void scst_devt_sysfs_del(struct scst_dev_type *devt);
int scst_dev_sysfs_create(struct scst_device *dev);
void scst_dev_sysfs_del(struct scst_device *dev);
int scst_tgt_dev_sysfs_create(struct scst_tgt_dev *tgt_dev);
void scst_tgt_dev_sysfs_del(struct scst_tgt_dev *tgt_dev);
int scst_devt_dev_sysfs_create(struct scst_device *dev);
void scst_devt_dev_sysfs_del(struct scst_device *dev);
int scst_acg_sysfs_create(struct scst_tgt *tgt,
	struct scst_acg *acg);
void scst_acg_sysfs_del(struct scst_acg *acg);
int scst_acg_dev_sysfs_create(struct scst_acg_dev *acg_dev,
	struct kobject *parent);
void scst_acg_dev_sysfs_del(struct scst_acg_dev *acg_dev);
int scst_acn_sysfs_create(struct scst_acn *acn);
void scst_acn_sysfs_del(struct scst_acn *acn);

#endif /* CONFIG_SCST_PROC */

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

#define SCST_SET_UA_FLAG_AT_HEAD	1
#define SCST_SET_UA_FLAG_GLOBAL		2

void scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags);
int scst_set_pending_UA(struct scst_cmd *cmd);

void scst_report_luns_changed(struct scst_acg *acg);

void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	bool other_ini, bool call_dev_task_mgmt_fn);
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd, bool setUA);

bool scst_is_ua_global(const uint8_t *sense, int len);
void scst_requeue_ua(struct scst_cmd *cmd);

struct scst_aen *scst_alloc_aen(struct scst_session *sess,
	uint64_t unpacked_lun);
void scst_free_aen(struct scst_aen *aen);

void scst_gen_aen_or_ua(struct scst_tgt_dev *tgt_dev,
	int key, int asc, int ascq);

static inline bool scst_is_implicit_hq(struct scst_cmd *cmd)
{
	return (cmd->op_flags & SCST_IMPLICIT_HQ) != 0;
}

/*
 * Some notes on devices "blocking". Blocking means that no
 * commands will go from SCST to underlying SCSI device until it
 * is unblocked. But we don't care about all commands that
 * already on the device.
 */

extern void scst_block_dev(struct scst_device *dev);
extern void scst_unblock_dev(struct scst_device *dev);

extern bool __scst_check_blocked_dev(struct scst_cmd *cmd);

static inline bool scst_check_blocked_dev(struct scst_cmd *cmd)
{
	if (unlikely(cmd->dev->block_count > 0) ||
	    unlikely(cmd->dev->dev_double_ua_possible))
		return __scst_check_blocked_dev(cmd);
	else
		return false;
}

/* No locks */
static inline void scst_check_unblock_dev(struct scst_cmd *cmd)
{
	if (unlikely(cmd->unblock_dev)) {
		TRACE_MGMT_DBG("cmd %p (tag %llu): unblocking dev %p", cmd,
			       (long long unsigned int)cmd->tag, cmd->dev);
		cmd->unblock_dev = 0;
		scst_unblock_dev(cmd->dev);
	}
	return;
}

static inline void __scst_get(void)
{
	atomic_inc(&scst_cmd_count);
	TRACE_DBG("Incrementing scst_cmd_count(new value %d)",
		atomic_read(&scst_cmd_count));
	/* See comment about smp_mb() in scst_suspend_activity() */
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
	TRACE_DBG("Decrementing scst_cmd_count(new value %d)",
	      atomic_read(&scst_cmd_count));
}

void scst_sched_session_free(struct scst_session *sess);

static inline void scst_sess_get(struct scst_session *sess)
{
	atomic_inc(&sess->refcnt);
	TRACE_DBG("Incrementing sess %p refcnt (new value %d)",
		sess, atomic_read(&sess->refcnt));
}

static inline void scst_sess_put(struct scst_session *sess)
{
	TRACE_DBG("Decrementing sess %p refcnt (new value %d)",
		sess, atomic_read(&sess->refcnt)-1);
	if (atomic_dec_and_test(&sess->refcnt))
		scst_sched_session_free(sess);
}

static inline void __scst_cmd_get(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->cmd_ref);
	TRACE_DBG("Incrementing cmd %p ref (new value %d)",
		cmd, atomic_read(&cmd->cmd_ref));
}

static inline void __scst_cmd_put(struct scst_cmd *cmd)
{
	TRACE_DBG("Decrementing cmd %p ref (new value %d)",
		cmd, atomic_read(&cmd->cmd_ref)-1);
	if (atomic_dec_and_test(&cmd->cmd_ref))
		scst_free_cmd(cmd);
}

extern void scst_throttle_cmd(struct scst_cmd *cmd);
extern void scst_unthrottle_cmd(struct scst_cmd *cmd);

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

static inline int scst_sn_before(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq1-seq2) < 0;
}

int gen_relative_target_port_id(uint16_t *id);
bool scst_is_relative_target_port_id_unique(uint16_t id,
	const struct scst_tgt *t);

#ifdef CONFIG_SCST_MEASURE_LATENCY

void scst_set_start_time(struct scst_cmd *cmd);
void scst_set_cur_start(struct scst_cmd *cmd);
void scst_set_parse_time(struct scst_cmd *cmd);
void scst_set_alloc_buf_time(struct scst_cmd *cmd);
void scst_set_restart_waiting_time(struct scst_cmd *cmd);
void scst_set_rdy_to_xfer_time(struct scst_cmd *cmd);
void scst_set_pre_exec_time(struct scst_cmd *cmd);
void scst_set_exec_time(struct scst_cmd *cmd);
void scst_set_dev_done_time(struct scst_cmd *cmd);
void scst_set_xmit_time(struct scst_cmd *cmd);
void scst_set_tgt_on_free_time(struct scst_cmd *cmd);
void scst_set_dev_on_free_time(struct scst_cmd *cmd);
void scst_update_lat_stats(struct scst_cmd *cmd);

#else

static inline void scst_set_start_time(struct scst_cmd *cmd) {}
static inline void scst_set_cur_start(struct scst_cmd *cmd) {}
static inline void scst_set_parse_time(struct scst_cmd *cmd) {}
static inline void scst_set_alloc_buf_time(struct scst_cmd *cmd) {}
static inline void scst_set_restart_waiting_time(struct scst_cmd *cmd) {}
static inline void scst_set_rdy_to_xfer_time(struct scst_cmd *cmd) {}
static inline void scst_set_pre_exec_time(struct scst_cmd *cmd) {}
static inline void scst_set_exec_time(struct scst_cmd *cmd) {}
static inline void scst_set_dev_done_time(struct scst_cmd *cmd) {}
static inline void scst_set_xmit_time(struct scst_cmd *cmd) {}
static inline void scst_set_tgt_on_free_time(struct scst_cmd *cmd) {}
static inline void scst_set_dev_on_free_time(struct scst_cmd *cmd) {}
static inline void scst_update_lat_stats(struct scst_cmd *cmd) {}

#endif /* CONFIG_SCST_MEASURE_LATENCY */

#endif /* __SCST_PRIV_H */
