/*
 *  scst_priv.h
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
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

#define SCST_MAJOR              177

#define TRACE_RETRY             0x80000000
#define TRACE_SCSI_SERIALIZING  0x40000000
#define TRACE_SEND_TOP		0x20000000 /** top being the edge away from the interupt */
#define TRACE_RECV_TOP		0x01000000 
#define TRACE_SEND_BOT		0x08000000 /** bottom being the edge toward the interupt */
#define TRACE_RECV_BOT		0x04000000

#define LOG_PREFIX "scst"

#ifdef DEBUG
/*#define SCST_DEFAULT_LOG_FLAGS (TRACE_ALL & ~TRACE_MEMORY & ~TRACE_BUFF \
	 & ~TRACE_FUNCTION)
#define SCST_DEFAULT_LOG_FLAGS (TRACE_ALL & ~TRACE_MEMORY & ~TRACE_BUFF & \
	~TRACE_SCSI & ~TRACE_SCSI_SERIALIZING & ~TRACE_DEBUG)
*/
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_PID | \
	TRACE_FUNCTION | TRACE_SPECIAL | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_RETRY)
#else
# ifdef TRACING
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_PID | \
	TRACE_SPECIAL)
# else
#define SCST_DEFAULT_LOG_FLAGS 0
# endif
#endif

/**
 ** Bits for scst_flags 
 **/

/* Set if new commands initialization should be suspended for a while */
#define SCST_FLAG_SUSPENDED		     0

/*
 * If set, SCST's threads exit immediately not performing any
 * sessions' shutdown tasks, therefore at this point all the sessions
 * must be already down.
 */
#define SCST_FLAG_SHUTDOWN		     1

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
#define SCST_CMD_STATE_RES_RESTART           3

/** Name of the "default" security group **/
#define SCST_DEFAULT_ACG_NAME                "Default"

/**
 ** Maximum count of uncompleted commands that an initiator could 
 ** queue on any device. Then it will take TASK QUEUE FULL status.
 **/
#define SCST_MAX_DEVICE_COMMANDS           128

#define SCST_THREAD_FLAGS                  CLONE_KERNEL

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
extern kmem_cache_t *scst_mgmt_cachep;
extern mempool_t *scst_mgmt_mempool;

#define SCST_UA_CACHE_STRING "scst_ua"
extern kmem_cache_t *scst_ua_cachep;
extern mempool_t *scst_ua_mempool;

#define SCST_CMD_CACHE_STRING "scst_cmd"
extern kmem_cache_t *scst_cmd_cachep;

#define SCST_SESSION_CACHE_STRING "scst_session"
extern kmem_cache_t *scst_sess_cachep;

#define SCST_TGT_DEV_CACHE_STRING "scst_tgt_dev"
extern kmem_cache_t *scst_tgtd_cachep;

#define SCST_ACG_DEV_CACHE_STRING "scst_acg_dev"
extern kmem_cache_t *scst_acgd_cachep;

extern struct scst_sgv_pools scst_sgv;

extern int scst_num_cpus;
extern unsigned long scst_flags;
extern struct semaphore scst_mutex;
extern atomic_t scst_cmd_count;
extern spinlock_t scst_list_lock;
extern struct list_head scst_dev_wait_sess_list; /* protected by scst_list_lock */
extern struct list_head scst_template_list; /* protected by scst_mutex */
extern struct list_head scst_dev_list; /* protected by scst_mutex */
extern struct list_head scst_dev_type_list; /* protected by scst_mutex */
extern wait_queue_head_t scst_dev_cmd_waitQ;

extern struct list_head scst_acg_list;
extern struct scst_acg *scst_default_acg;

/* The following lists protected by scst_list_lock */
extern struct list_head scst_active_cmd_list;
extern struct list_head scst_init_cmd_list;
extern struct list_head scst_cmd_list;

extern spinlock_t scst_cmd_mem_lock;
extern unsigned long scst_max_cmd_mem, scst_cur_max_cmd_mem, scst_cur_cmd_mem;
extern struct work_struct scst_cmd_mem_work;

/* The following lists protected by scst_list_lock as well */
extern struct list_head scst_mgmt_cmd_list;
extern struct list_head scst_active_mgmt_cmd_list;
extern struct list_head scst_delayed_mgmt_cmd_list;

extern struct tasklet_struct scst_tasklets[NR_CPUS];
extern wait_queue_head_t scst_list_waitQ;

extern wait_queue_head_t scst_mgmt_cmd_list_waitQ;

extern wait_queue_head_t scst_mgmt_waitQ;
extern spinlock_t scst_mgmt_lock;
extern struct list_head scst_sess_mgmt_list;

extern int scst_threads;
extern int scst_shut_threads_count;
extern atomic_t scst_threads_count;
extern int scst_thread_num;

extern struct semaphore *scst_shutdown_mutex;

extern spinlock_t scst_temp_UA_lock;
extern uint8_t scst_temp_UA[SCSI_SENSE_BUFFERSIZE];

extern struct scst_cmd *__scst_check_deferred_commands(
	struct scst_tgt_dev *tgt_dev, int expected_sn);

/* Used to save the function call on th fast path */
static inline struct scst_cmd *scst_check_deferred_commands(
	struct scst_tgt_dev *tgt_dev, int expected_sn)
{
	if (tgt_dev->def_cmd_count == 0)
		return NULL;
	else
		return __scst_check_deferred_commands(tgt_dev, expected_sn);
}

static inline int __scst_inc_expected_sn(struct scst_tgt_dev *tgt_dev)
{
	/*
	 * No locks is needed, because only one thread at time can 
	 * call it (serialized by sn). Also it is supposed that there
	 * could not be half-incremented halves.
	 */

	typeof(tgt_dev->expected_sn) e;

	e = tgt_dev->expected_sn;
	tgt_dev->expected_sn++;
	smp_mb(); /* write must be before def_cmd_count read */
	e++;
	TRACE(TRACE_DEBUG/*TRACE_SCSI_SERIALIZING*/, "Next expected_sn: %d", e);
	return e;
}

void scst_inc_expected_sn_unblock(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *cmd_sn, int locked);

int scst_cmd_thread(void *arg);
void scst_cmd_tasklet(long p);
int scst_mgmt_cmd_thread(void *arg);
int scst_mgmt_thread(void *arg);
void scst_cmd_mem_work_fn(void *p);

struct scst_device *scst_alloc_device(int gfp_mask);
void scst_free_device(struct scst_device *tgt_dev);

struct scst_acg *scst_alloc_add_acg(const char *acg_name);
int scst_destroy_acg(struct scst_acg *acg);

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
void scst_check_retries(struct scst_tgt *tgt, int processible_env);
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
    #elif defined(FILEIO_ONLY)
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
    #elif defined(FILEIO_ONLY)
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
void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd, int del);

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

/*
 * Returns 1, if cmd's CDB is locally handled by SCST and 0 otherwise.
 * Dev handlers parse() and dev_done() not called for such commands.
 */
static inline int scst_is_cmd_local(struct scst_cmd *cmd)
{
	int res = 0;
	switch (cmd->cdb[0]) {
	case REPORT_LUNS:
		res = 1;
	}
	return res;
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
	unsigned int outstanding)
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

static inline void scst_dec_on_dev_cmd(struct scst_cmd *cmd)
{
	if (cmd->blocking) {
		TRACE_MGMT_DBG("cmd %p (tag %d): unblocking dev %p", cmd,
			cmd->tag, cmd->dev);
		cmd->blocking = 0;
		scst_unblock_dev(cmd->dev);
	}
	atomic_dec(&cmd->dev->on_dev_count);
	smp_mb__after_atomic_dec();
	if (unlikely(cmd->dev->block_count != 0))
		wake_up_all(&cmd->dev->on_dev_waitQ);
}

static inline void scst_inc_cmd_count(void)
{
	atomic_inc(&scst_cmd_count);
	smp_mb__after_atomic_inc();
	TRACE_DBG("Incrementing scst_cmd_count(%d)",
	      atomic_read(&scst_cmd_count));
}

static inline void scst_dec_cmd_count(void)
{
	int f;
	f = atomic_dec_and_test(&scst_cmd_count);
	smp_mb__after_atomic_dec();
	if (f && unlikely(test_bit(SCST_FLAG_SUSPENDED, &scst_flags)))
		wake_up_all(&scst_dev_cmd_waitQ);
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
	smp_mb__before_atomic_dec();
	if (atomic_dec_and_test(&sess->refcnt)) {
		smp_mb__after_atomic_dec();
		scst_sched_session_free(sess);
	}
}

void __scst_suspend_activity(void);
void __scst_resume_activity(void);

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
extern void tm_dbg_task_mgmt(const char *fn);
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
static inline void tm_dbg_task_mgmt(const char *fn) {}
static inline int tm_dbg_is_release(void)
{
	return 0;
}
#endif /* DEBUG_TM */

#endif /* __SCST_PRIV_H */
