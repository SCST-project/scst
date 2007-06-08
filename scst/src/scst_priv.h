/*
 *  scst_priv.h
 *  
 *  Copyright (C) 2004-2007 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#include <scsi/scsi_request.h>
#endif

#include "scst_debug.h"

#define SCST_MAJOR              177

#define TRACE_RETRY             0x80000000
#define TRACE_SCSI_SERIALIZING  0x40000000
#define TRACE_SEND_TOP		0x20000000 /** top being the edge away from the interupt */
#define TRACE_RECV_TOP		0x01000000 
#define TRACE_SEND_BOT		0x08000000 /** bottom being the edge toward the interupt */
#define TRACE_RECV_BOT		0x04000000

#define LOG_PREFIX "scst"

#if defined(DEBUG) || defined(TRACING)
#define trace_flag scst_trace_flag
extern unsigned long scst_trace_flag;
#endif

#ifdef DEBUG
/*#define SCST_DEFAULT_LOG_FLAGS (TRACE_ALL & ~TRACE_MEMORY & ~TRACE_BUFF \
	 & ~TRACE_FUNCTION)
#define SCST_DEFAULT_LOG_FLAGS (TRACE_ALL & ~TRACE_MEMORY & ~TRACE_BUFF & \
	~TRACE_SCSI & ~TRACE_SCSI_SERIALIZING & ~TRACE_DEBUG)
*/
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_PID | \
	TRACE_LINE | TRACE_FUNCTION | TRACE_SPECIAL | TRACE_MGMT | \
	TRACE_MGMT_DEBUG | TRACE_RETRY)

#define TRACE_SN(args...)	TRACE(TRACE_SCSI_SERIALIZING, args)

#else /* DEBUG */

# ifdef TRACING
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_PID | \
	TRACE_SPECIAL)
# else
#define SCST_DEFAULT_LOG_FLAGS 0
# endif

#define TRACE_SN(args...)

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

/* Set if a TM command is being performed */
#define SCST_FLAG_TM_ACTIVE                  2

/* Set if scst_cmd_mem_work is scheduled */
#define SCST_FLAG_CMD_MEM_WORK_SCHEDULED     3

/** 
 ** Return codes for cmd state process functions 
 **/
#define SCST_CMD_STATE_RES_CONT_SAME         0
#define SCST_CMD_STATE_RES_CONT_NEXT         1
#define SCST_CMD_STATE_RES_NEED_THREAD       2

/** Name of the "default" security group **/
#define SCST_DEFAULT_ACG_NAME                "Default"

/**
 ** Maximum count of uncompleted commands that an initiator could 
 ** queue on any device. Then it will take TASK QUEUE FULL status.
 **/
#define SCST_MAX_DEVICE_COMMANDS           128

#define SCST_TGT_RETRY_TIMEOUT             (3/2*HZ)
#define SCST_CMD_MEM_TIMEOUT               (120*HZ)

static inline int scst_get_context(void) {
	if (in_irq())
		return SCST_CONTEXT_TASKLET;
	if (irqs_disabled())
		return SCST_CONTEXT_THREAD;
	if (in_softirq() || in_atomic())
		return SCST_CONTEXT_DIRECT_ATOMIC;
	return SCST_CONTEXT_DIRECT;
}

#define SCST_MGMT_CMD_CACHE_STRING "scst_mgmt_cmd"
extern struct kmem_cache *scst_mgmt_cachep;
extern mempool_t *scst_mgmt_mempool;

#define SCST_UA_CACHE_STRING "scst_ua"
extern struct kmem_cache *scst_ua_cachep;
extern mempool_t *scst_ua_mempool;

#define SCST_CMD_CACHE_STRING "scst_cmd"
extern struct kmem_cache *scst_cmd_cachep;

#define SCST_SESSION_CACHE_STRING "scst_session"
extern struct kmem_cache *scst_sess_cachep;

#define SCST_TGT_DEV_CACHE_STRING "scst_tgt_dev"
extern struct kmem_cache *scst_tgtd_cachep;

#define SCST_ACG_DEV_CACHE_STRING "scst_acg_dev"
extern struct kmem_cache *scst_acgd_cachep;

extern spinlock_t scst_main_lock;

extern struct scst_sgv_pools scst_sgv;

extern unsigned long scst_flags;
extern struct semaphore scst_mutex;
extern atomic_t scst_cmd_count;
extern struct list_head scst_template_list; /* protected by scst_mutex */
extern struct list_head scst_dev_list; /* protected by scst_mutex */
extern struct list_head scst_dev_type_list; /* protected by scst_mutex */
extern wait_queue_head_t scst_dev_cmd_waitQ;

extern struct semaphore scst_suspend_mutex;
extern struct list_head scst_cmd_lists_list; /* protected by scst_suspend_mutex */

extern struct list_head scst_acg_list;
extern struct scst_acg *scst_default_acg;

extern spinlock_t scst_init_lock;
extern struct list_head scst_init_cmd_list;
extern wait_queue_head_t scst_init_cmd_list_waitQ;
extern unsigned int scst_init_poll_cnt;

extern struct scst_cmd_lists scst_main_cmd_lists;

extern spinlock_t scst_cmd_mem_lock;
extern unsigned long scst_max_cmd_mem, scst_cur_max_cmd_mem, scst_cur_cmd_mem;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
extern struct work_struct scst_cmd_mem_work;
#else
extern struct delayed_work scst_cmd_mem_work;
#endif

extern spinlock_t scst_mcmd_lock;
/* The following lists protected by scst_mcmd_lock */
extern struct list_head scst_active_mgmt_cmd_list;
extern struct list_head scst_delayed_mgmt_cmd_list;
extern wait_queue_head_t scst_mgmt_cmd_list_waitQ;

struct scst_tasklet
{
	spinlock_t tasklet_lock;
	struct list_head tasklet_cmd_list;
	struct tasklet_struct tasklet;
};
extern struct scst_tasklet scst_tasklets[NR_CPUS];

extern wait_queue_head_t scst_mgmt_waitQ;
extern spinlock_t scst_mgmt_lock;
extern struct list_head scst_sess_mgmt_list;

struct scst_cmd_thread_t {
	struct task_struct *cmd_thread;
	struct list_head thread_list_entry;
};

struct scst_threads_info_t {
	struct semaphore cmd_threads_mutex;
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

extern struct scst_cmd *__scst_check_deferred_commands(
	struct scst_tgt_dev *tgt_dev);

/* Used to save the function call on the fast path */
static inline struct scst_cmd *scst_check_deferred_commands(
	struct scst_tgt_dev *tgt_dev)
{
	if ((tgt_dev->def_cmd_count == 0) && 
	    likely(!test_bit(SCST_TGT_DEV_HQ_ACTIVE, &tgt_dev->tgt_dev_flags)))
		return NULL;
	else
		return __scst_check_deferred_commands(tgt_dev);
}

void scst_inc_expected_sn(struct scst_tgt_dev *tgt_dev, atomic_t *slot);
int scst_check_hq_cmd(struct scst_cmd *cmd);

void scst_unblock_deferred(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *cmd_sn);

int scst_cmd_thread(void *arg);
void scst_cmd_tasklet(long p);
int scst_init_cmd_thread(void *arg);
int scst_mgmt_cmd_thread(void *arg);
int scst_mgmt_thread(void *arg);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
void scst_cmd_mem_work_fn(void *p);
#else
void scst_cmd_mem_work_fn(struct work_struct *work);
#endif

int scst_add_dev_threads(struct scst_device *dev, int num);
void scst_del_dev_threads(struct scst_device *dev, int num);

int scst_alloc_device(int gfp_mask, struct scst_device **out_dev);
void scst_free_device(struct scst_device *tgt_dev);

struct scst_acg *scst_alloc_add_acg(const char *acg_name);
int scst_destroy_acg(struct scst_acg *acg);
int scst_proc_group_add_tree(struct scst_acg *acg, const char *name);
void scst_proc_del_acg_tree(struct proc_dir_entry *acg_proc_root,
	const char *name);

int scst_sess_alloc_tgt_devs(struct scst_session *sess);
void scst_sess_free_tgt_devs(struct scst_session *sess);
void scst_reset_tgt_dev(struct scst_tgt_dev *tgt_dev, int nexus_loss);

int scst_acg_add_dev(struct scst_acg *acg, struct scst_device *dev, lun_t lun,
	int read_only);
int scst_acg_remove_dev(struct scst_acg *acg, struct scst_device *dev);

int scst_acg_add_name(struct scst_acg *acg, const char *name);
int scst_acg_remove_name(struct scst_acg *acg, const char *name);

struct scst_cmd *scst_create_prepare_internal_cmd(
	struct scst_cmd *orig_cmd, int bufsize);
void scst_free_internal_cmd(struct scst_cmd *cmd);
int scst_prepare_request_sense(struct scst_cmd *orig_cmd);
struct scst_cmd *scst_complete_request_sense(struct scst_cmd *cmd);

int scst_assign_dev_handler(struct scst_device *dev, 
	struct scst_dev_type *handler);

struct scst_session *scst_alloc_session(struct scst_tgt *tgt, int gfp_mask,
	const char *initiator_name);
void scst_free_session(struct scst_session *sess);
void scst_free_session_callback(struct scst_session *sess);

struct scst_cmd *scst_alloc_cmd(int gfp_mask);
void scst_free_cmd(struct scst_cmd *cmd);
static inline void scst_destroy_cmd(struct scst_cmd *cmd)
{
	kmem_cache_free(scst_cmd_cachep, cmd);
	return;
}

void scst_proccess_redirect_cmd(struct scst_cmd *cmd, int context,
	int check_retries);
void scst_check_retries(struct scst_tgt *tgt);
void scst_tgt_retry_timer_fn(unsigned long arg);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
int scst_alloc_request(struct scst_cmd *cmd);
void scst_release_request(struct scst_cmd *cmd);

static inline void scst_do_req(struct scsi_request *sreq, 
	const void *cmnd, void *buffer, unsigned bufflen, 
	void (*done)(struct scsi_cmnd *), int timeout, int retries)
{
    #ifdef STRICT_SERIALIZING
	scsi_do_req(sreq, cmnd, buffer, bufflen, done, timeout, retries);
    #elif defined(VDISK_ONLY)
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
    #ifdef STRICT_SERIALIZING
	return scsi_execute_async(sdev, cmd, cmd_len, data_direction, buffer,
		bufflen, use_sg, timeout, retries, privdata, done, gfp);
    #elif defined(VDISK_ONLY)
    	sBUG();
    	return -1;
    #else
    	return scsi_execute_async_fifo(sdev, cmd, cmd_len, data_direction,
    		buffer,	bufflen, use_sg, timeout, retries, privdata, done, gfp);
    #endif
}
#endif

int scst_alloc_space(struct scst_cmd *cmd);
void scst_release_space(struct scst_cmd *cmd);
void scst_scsi_op_list_init(void);

lun_t scst_unpack_lun(const uint8_t *lun, int len);

struct scst_cmd *__scst_find_cmd_by_tag(struct scst_session *sess, 
	uint32_t tag);

struct scst_mgmt_cmd *scst_alloc_mgmt_cmd(int gfp_mask);
void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd);
void scst_complete_cmd_mgmt(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd);

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

void __scst_process_UA(struct scst_device *dev, struct scst_cmd *exclude,
	const uint8_t *sense, int sense_len, int internal);
static inline void scst_process_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len,
	int internal)
{
	spin_lock_bh(&dev->dev_lock);
	__scst_process_UA(dev, exclude, sense, sense_len, internal);
	spin_unlock_bh(&dev->dev_lock);
	return;
}
void scst_alloc_set_UA(struct scst_tgt_dev *tgt_dev, const uint8_t *sense,
	int sense_len);
void scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len);
int scst_set_pending_UA(struct scst_cmd *cmd);
void scst_free_all_UA(struct scst_tgt_dev *tgt_dev);

void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	int other_ini, int call_dev_task_mgmt_fn);
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd);

static inline int scst_is_ua_command(struct scst_cmd *cmd)
{
	return ((cmd->cdb[0] != INQUIRY) && 
		(cmd->cdb[0] != REQUEST_SENSE) &&
		(cmd->cdb[0] != REPORT_LUNS));
}

static inline int scst_is_implicit_hq(struct scst_cmd *cmd)
{
	return ((cmd->cdb[0] == INQUIRY) ||
		(cmd->cdb[0] == REPORT_LUNS) ||
		((cmd->dev->type == TYPE_DISK) &&
		   ((cmd->cdb[0] == READ_CAPACITY) ||
		    ((cmd->cdb[0] == SERVICE_ACTION_IN) &&
		       ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16)))));
}

/*
 * Some notes on devices "blocking". Blocking means that no
 * commands will go from SCST to underlying SCSI device until it 
 * is unblocked. But we don't care about all commands that 
 * already on the device.
 */

extern int scst_inc_on_dev_cmd(struct scst_cmd *cmd);
extern void scst_unblock_cmds(struct scst_device *dev);

static inline void __scst_block_dev(struct scst_device *dev)
{
	dev->block_count++;
	smp_mb();
	TRACE_MGMT_DBG("Device BLOCK(%d), dev %p", dev->block_count, dev);
}

static inline void scst_block_dev(struct scst_device *dev, 
	int outstanding)
{
	spin_lock_bh(&dev->dev_lock);
	__scst_block_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	TRACE_MGMT_DBG("Waiting during blocking outstanding %d (on_dev_count "
		"%d)", outstanding, atomic_read(&dev->on_dev_count));
	wait_event(dev->on_dev_waitQ, 
		atomic_read(&dev->on_dev_count) <= outstanding);
	TRACE_MGMT_DBG("%s", "wait_event() returned");
}

static inline void scst_unblock_dev(struct scst_device *dev)
{
	spin_lock_bh(&dev->dev_lock);
	TRACE_MGMT_DBG("Device UNBLOCK(%d), dev %p",
		dev->block_count-1, dev);
	if (--dev->block_count == 0)
		scst_unblock_cmds(dev);
	spin_unlock_bh(&dev->dev_lock);
}

static inline void __scst_dec_on_dev_cmd(struct scst_device *dev,
	int cmd_blocking)
{
	if (cmd_blocking)
		scst_unblock_dev(dev);
	atomic_dec(&dev->on_dev_count);
	smp_mb__after_atomic_dec();
	if (unlikely(dev->block_count != 0))
		wake_up_all(&dev->on_dev_waitQ);
}

static inline int scst_dec_on_dev_cmd(struct scst_cmd *cmd, int defer)
{
	int cmd_blocking = cmd->blocking;
	if (cmd_blocking) {
		TRACE_MGMT_DBG("cmd %p (tag %d): unblocking dev %p", cmd,
			cmd->tag, cmd->dev);
		cmd->blocking = 0;
	}
	if (!defer)
		__scst_dec_on_dev_cmd(cmd->dev, cmd_blocking);
	return cmd_blocking;
}

static inline void __scst_get(int barrier)
{
	atomic_inc(&scst_cmd_count);
	TRACE_DBG("Incrementing scst_cmd_count(%d)",
		atomic_read(&scst_cmd_count));

	if (barrier)
		smp_mb__after_atomic_inc();
}

static inline void __scst_put(void)
{
	int f;
	f = atomic_dec_and_test(&scst_cmd_count);
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

static inline void scst_cmd_get(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->cmd_ref);
}

static inline void scst_cmd_put(struct scst_cmd *cmd)
{
	if (atomic_dec_and_test(&cmd->cmd_ref))
		scst_free_cmd(cmd);
}

extern void scst_throttle_cmd(struct scst_cmd *cmd);
extern void scst_unthrottle_cmd(struct scst_cmd *cmd);

static inline void scst_set_sense(uint8_t *buffer, int len, int key,
	int asc, int ascq)
{
	memset(buffer, 0, len);
	buffer[0] = 0x70;	/* Error Code			*/
	buffer[2] = key;	/* Sense Key			*/
	buffer[7] = 0x0a;	/* Additional Sense Length	*/
	buffer[12] = asc;	/* ASC				*/
	buffer[13] = ascq;	/* ASCQ				*/
	TRACE_BUFFER("Sense set", buffer, len);
	return;
}

static inline void scst_check_restore_sg_buff(struct scst_cmd *cmd)
{
	if (cmd->sg_buff_modified) {
		TRACE_MEM("cmd %p, sg %p, orig_sg_entry %d, "
			"orig_entry_len %d, orig_sg_cnt %d", cmd, cmd->sg,
			cmd->orig_sg_entry, cmd->orig_entry_len,
			cmd->orig_sg_cnt);
		cmd->sg[cmd->orig_sg_entry].length = cmd->orig_entry_len;
		cmd->sg_cnt = cmd->orig_sg_cnt;
	}
}

#ifdef DEBUG_TM
extern void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev,
	struct scst_acg_dev *acg_dev);
extern void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev);
extern void tm_dbg_check_released_cmds(void);
extern int tm_dbg_check_cmd(struct scst_cmd *cmd);
extern void tm_dbg_release_cmd(struct scst_cmd *cmd);
extern void tm_dbg_task_mgmt(const char *fn, int force);
extern int tm_dbg_is_release(void);
#else
static inline void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev,
	struct scst_acg_dev *acg_dev) {}
static inline void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev) {}
static inline void tm_dbg_check_released_cmds(void) {}
static inline int tm_dbg_check_cmd(struct scst_cmd *cmd)
{
	return 0;
}
static inline void tm_dbg_release_cmd(struct scst_cmd *cmd) {}
static inline void tm_dbg_task_mgmt(const char *fn, int force) {}
static inline int tm_dbg_is_release(void)
{
	return 0;
}
#endif /* DEBUG_TM */

#ifdef DEBUG_SN
void scst_check_debug_sn(struct scst_cmd *cmd);
#else
static inline void scst_check_debug_sn(struct scst_cmd *cmd) {}
#endif

#endif /* __SCST_PRIV_H */
