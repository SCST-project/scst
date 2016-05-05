/*
 *  scst_priv.h
 *
 *  Copyright (C) 2004 - 2016 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2016 SanDisk Corporation
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
#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
#include <linux/export.h>
#endif
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
#define TRACE_DATA_SEND		0x20000000
#define TRACE_DATA_RECEIVED	0x01000000

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
#define TRACE_SN_SPECIAL(args...) TRACE_DBG_FLAG(TRACE_SCSI_SERIALIZING|TRACE_SPECIAL, args)

#else /* CONFIG_SCST_DEBUG */

# ifdef CONFIG_SCST_TRACING
#define SCST_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_PID | \
	TRACE_SPECIAL)
# else
#define SCST_DEFAULT_LOG_FLAGS 0
# endif

#define TRACE_RETRY(args...)
#define TRACE_SN(args...)
#define TRACE_SN_SPECIAL(args...)

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
#define SCST_MAX_TGT_DEV_COMMANDS            64

#ifdef CONFIG_SCST_PER_DEVICE_CMD_COUNT_LIMIT
/**
 ** Maximum count of uncompleted commands that could be queued on any device.
 ** Then initiators sending commands to this device will start getting
 ** TASK QUEUE FULL status.
 **/
#define SCST_MAX_DEV_COMMANDS                256
#endif

#define SCST_TGT_RETRY_TIMEOUT               1 /* 1 jiffy */

#define SCST_DEF_LBA_DATA_LEN		     -1

/* Used to prevent overflow of int cmd->bufflen. Assumes max blocksize is 4K */
#define SCST_MAX_VALID_BUFFLEN_MASK	     (~((1 << (32 - 12)) - 1))

#define SCST_MAX_EACH_INTERNAL_IO_SIZE	     (128*1024)
#define SCST_MAX_IN_FLIGHT_INTERNAL_COMMANDS 32

/*
 * Compatibility with real-time (CONFIG_PREEMPT_RT_FULL) kernels.
 * In such kernels:
 * - Interrupt handlers run in kernel thread context (see e.g.
 *   http://lwn.net/Articles/302043/).
 * - spin_lock() calls can sleep (see e.g. http://lwn.net/Articles/271817/).
 * - local_irq functions manipulate preemptibility, not HW interruptibility
 *   (see also http://lwn.net/Articles/146861).
 * For the upstream kernels up to at least kernel 3.14 _nort functions are
 * only defined if a CONFIG PREEMPT RT patch has been applied to the kernel.
 * See https://rt.wiki.kernel.org/index.php/CONFIG_PREEMPT_RT_Patch.
 */
#ifndef local_irq_enable_nort
/* Kernel does not have CONFIG_PREEMPT_RT patch */
#define local_irq_enable_nort()		local_irq_enable()
#define local_irq_disable_nort()	local_irq_disable()
#define local_irq_save_nort(flags)	local_irq_save(flags)
#define local_irq_restore_nort(flags)	local_irq_restore(flags)
#endif

typedef void (*scst_i_finish_fn_t) (struct scst_cmd *cmd);

extern struct mutex scst_mutex2;

extern int scst_threads;

extern unsigned int scst_max_dev_cmd_mem;

extern int scst_forcibly_close_sessions;

extern mempool_t *scst_mgmt_mempool;
extern mempool_t *scst_mgmt_stub_mempool;
extern mempool_t *scst_ua_mempool;
extern mempool_t *scst_sense_mempool;
extern mempool_t *scst_aen_mempool;

extern struct kmem_cache *scst_cmd_cachep;
extern struct kmem_cache *scst_sess_cachep;
extern struct kmem_cache *scst_dev_cachep;
extern struct kmem_cache *scst_tgt_cachep;
extern struct kmem_cache *scst_tgtd_cachep;
extern struct kmem_cache *scst_acgd_cachep;

extern unsigned long scst_flags;
extern struct list_head scst_template_list;
extern struct list_head scst_dev_list;
extern struct list_head scst_dev_type_list;
extern struct list_head scst_virtual_dev_type_list;
extern wait_queue_head_t scst_dev_cmd_waitQ;

extern const struct scst_cl_ops scst_no_dlm_cl_ops;
extern const struct scst_cl_ops scst_dlm_cl_ops;

#ifdef CONFIG_SCST_PROC
extern struct list_head scst_acg_list;
extern struct scst_acg *scst_default_acg;
#else
extern unsigned int scst_setup_id;
#endif

#define SCST_DEF_MAX_TASKLET_CMD 10
extern int scst_max_tasklet_cmd;

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

struct scst_percpu_info {
	atomic_t cpu_cmd_count;
	spinlock_t tasklet_lock;
	struct list_head tasklet_cmd_list;
	struct tasklet_struct tasklet;
} ____cacheline_aligned_in_smp;
extern struct scst_percpu_info scst_percpu_infos[NR_CPUS];

extern wait_queue_head_t scst_mgmt_waitQ;
extern spinlock_t scst_mgmt_lock;
extern struct list_head scst_sess_init_list;
extern struct list_head scst_sess_shut_list;

extern cpumask_t default_cpu_mask;

struct scst_cmd_thread_t {
	struct task_struct *cmd_thread;
	struct list_head thread_list_entry;
	bool		 being_stopped;
};

static inline bool scst_set_io_context(struct scst_cmd *cmd,
	struct io_context **old)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	return false;
#else
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
	return false;
#else
	bool res;

	EXTRACHECKS_BUG_ON(old == NULL);

	if (cmd->cmd_threads == &scst_main_cmd_threads) {
		EXTRACHECKS_BUG_ON(in_interrupt());
		/*
		 * No need for any ref counting action, because io_context
		 * supposed to be cleared in the end of the caller function.
		 */
		*old = current->io_context;
		current->io_context = cmd->tgt_dev->async_io_context;
		res = true;
		TRACE_DBG("io_context %p (tgt_dev %p)", current->io_context,
			cmd->tgt_dev);
		EXTRACHECKS_BUG_ON(current->io_context == NULL);
	} else
		res = false;

	return res;
#endif
#endif
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

extern struct scst_dev_type scst_null_devtype;

char *scst_get_cmd_state_name(char *name, int len, unsigned int state);
char *scst_get_mcmd_state_name(char *name, int len, unsigned int state);
char *scst_get_tm_fn_name(char *name, int len, unsigned int fn);

extern struct scst_cmd *__scst_check_deferred_commands_locked(
	struct scst_order_data *order_data, bool return_first);
extern struct scst_cmd *__scst_check_deferred_commands(
	struct scst_order_data *order_data, bool return_first);

/* Used to save the function call on the fast path */
static inline struct scst_cmd *scst_check_deferred_commands(
	struct scst_order_data *order_data, bool return_first)
{
	if (order_data->def_cmd_count == 0)
		return NULL;
	else
		return __scst_check_deferred_commands(order_data, return_first);
}

static inline void scst_make_deferred_commands_active(
	struct scst_order_data *order_data)
{
	scst_check_deferred_commands(order_data, false);
	return;
}

/*
 * sn_lock supposed to be locked and IRQs off. Might drop then reacquire
 * it inside.
 */
static inline void scst_make_deferred_commands_active_locked(
	struct scst_order_data *order_data)
{
	if (order_data->def_cmd_count != 0)
		__scst_check_deferred_commands_locked(order_data, false);
	return;
}

bool scst_inc_expected_sn(const struct scst_cmd *cmd);
int scst_check_hq_cmd(struct scst_cmd *cmd);

void scst_unblock_deferred(struct scst_order_data *order_data,
	struct scst_cmd *cmd_sn);

void scst_on_hq_cmd_response(struct scst_cmd *cmd);
void scst_xmit_process_aborted_cmd(struct scst_cmd *cmd);

int scst_pre_parse(struct scst_cmd *cmd);

int scst_cmd_thread(void *arg);
void scst_cmd_tasklet(long p);
int scst_init_thread(void *arg);
int scst_tm_thread(void *arg);
int scst_global_mgmt_thread(void *arg);

void scst_cmd_set_write_no_data_received(struct scst_cmd *cmd);

void scst_zero_write_rest(struct scst_cmd *cmd);
void scst_limit_sg_write_len(struct scst_cmd *cmd);
void scst_adjust_resp_data_len(struct scst_cmd *cmd);

void scst_queue_retry_cmd(struct scst_cmd *cmd);

int scst_alloc_tgt(struct scst_tgt_template *tgtt, struct scst_tgt **tgt);
void scst_free_tgt(struct scst_tgt *tgt);

int scst_alloc_device(gfp_t gfp_mask, struct scst_device **out_dev);
void scst_free_device(struct scst_device *dev);
bool scst_device_is_exported(struct scst_device *dev);

int scst_alloc_add_acg(struct scst_tgt *tgt, const char *acg_name,
	bool tgt_acg, struct scst_acg **out_acg);
int scst_del_free_acg(struct scst_acg *acg, bool close_sessions);
void scst_get_acg(struct scst_acg *acg);
void scst_put_acg(struct scst_acg *acg);

struct scst_acg *scst_tgt_find_acg(struct scst_tgt *tgt, const char *name);
struct scst_acg *scst_find_acg(const struct scst_session *sess);

void scst_check_reassign_sessions(void);

int scst_sess_alloc_tgt_devs(struct scst_session *sess);
void scst_sess_free_tgt_devs(struct scst_session *sess);
struct scst_tgt_dev *scst_lookup_tgt_dev(struct scst_session *sess, u64 lun);
void scst_nexus_loss(struct scst_tgt_dev *tgt_dev, bool queue_UA);

#define SCST_ADD_LUN_READ_ONLY	1
#define SCST_ADD_LUN_GEN_UA	2
#define SCST_ADD_LUN_CM		4
#define SCST_REPL_LUN_GEN_UA	8

int scst_acg_add_lun(struct scst_acg *acg, struct kobject *parent,
	struct scst_device *dev, uint64_t lun, unsigned int flags,
	struct scst_acg_dev **out_acg_dev);
int scst_acg_del_lun(struct scst_acg *acg, uint64_t lun,
	bool gen_report_luns_changed);
int scst_acg_repl_lun(struct scst_acg *acg, struct kobject *parent,
		      struct scst_device *dev, uint64_t lun,
		      unsigned int flags);

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

int scst_set_cmd_error_sense(struct scst_cmd *cmd, uint8_t *sense,
	unsigned int len);
void scst_store_sense(struct scst_cmd *cmd);

int scst_process_check_condition(struct scst_cmd *cmd);

int scst_assign_dev_handler(struct scst_device *dev,
	struct scst_dev_type *handler);

struct scst_session *scst_alloc_session(struct scst_tgt *tgt, gfp_t gfp_mask,
	const char *initiator_name);
void scst_free_session(struct scst_session *sess);
void scst_free_session_callback(struct scst_session *sess);

void scst_check_retries(struct scst_tgt *tgt);

static inline int scst_dlm_new_lockspace(const char *name, int namelen,
					 dlm_lockspace_t **lockspace,
					 uint32_t flags,
					 int lvblen)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	return dlm_new_lockspace((char *)name, namelen, lockspace, flags,
				 lvblen);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	return dlm_new_lockspace(name, namelen, lockspace, flags, lvblen);
#else
	return dlm_new_lockspace(name, NULL, flags, lvblen, NULL, NULL, NULL,
				 lockspace);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
static inline int scst_exec_req(struct scsi_device *sdev,
	const unsigned char *cmd, int cmd_len, int data_direction,
	struct scatterlist *sgl, unsigned int bufflen, unsigned int nents,
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
#endif

int scst_alloc_space(struct scst_cmd *cmd);

int scst_lib_init(void);
void scst_lib_exit(void);

struct scst_mgmt_cmd *scst_alloc_mgmt_cmd(gfp_t gfp_mask);
void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd);
void scst_done_cmd_mgmt(struct scst_cmd *cmd);
void scst_finish_cmd_mgmt(struct scst_cmd *cmd);

static inline void scst_devt_cleanup(struct scst_dev_type *devt) { }

void scst_tg_init(void);
void scst_tg_cleanup(void);
int scst_dg_add(struct kobject *parent, const char *name);
int scst_dg_remove(const char *name);
struct scst_dev_group *scst_lookup_dg_by_kobj(struct kobject *kobj);
int scst_dg_dev_add(struct scst_dev_group *dg, const char *name);
int scst_dg_dev_remove_by_name(struct scst_dev_group *dg, const char *name);
int scst_dg_dev_remove_by_dev(struct scst_device *dev);
enum scst_tg_state scst_alua_name_to_state(const char *n);
int scst_tg_add(struct scst_dev_group *dg, const char *name);
int scst_tg_remove_by_name(struct scst_dev_group *dg, const char *name);
void scst_tg_init_tgt_dev(struct scst_tgt_dev *tgt_dev);
int scst_tg_set_state(struct scst_target_group *tg, enum scst_tg_state state);
int scst_tg_set_preferred(struct scst_target_group *tg, bool preferred);
int scst_tg_tgt_add(struct scst_target_group *tg, const char *name);
int scst_tg_tgt_remove_by_name(struct scst_target_group *tg, const char *name);
void scst_tg_tgt_remove_by_tgt(struct scst_tgt *tgt);
#ifndef CONFIG_SCST_PROC
int scst_dg_sysfs_add(struct kobject *parent, struct scst_dev_group *dg);
void scst_dg_sysfs_del(struct scst_dev_group *dg);
void scst_tgt_sysfs_put(struct scst_tgt *tgt);
int scst_dg_dev_sysfs_add(struct scst_dev_group *dg, struct scst_dg_dev *dgdev);
void scst_dg_dev_sysfs_del(struct scst_dev_group *dg,
			   struct scst_dg_dev *dgdev);
int scst_tg_sysfs_add(struct scst_dev_group *dg,
			 struct scst_target_group *tg);
void scst_tg_sysfs_del(struct scst_target_group *tg);
int scst_tg_tgt_sysfs_add(struct scst_target_group *tg,
			  struct scst_tg_tgt *tg_tgt);
void scst_tg_tgt_sysfs_del(struct scst_target_group *tg,
			   struct scst_tg_tgt *tg_tgt);
#else
static inline int scst_dg_sysfs_add(struct kobject *parent,
				    struct scst_dev_group *dg)
{
	return 0;
}
static inline void scst_dg_sysfs_del(struct scst_dev_group *dg)
{
}
static inline int scst_dg_dev_sysfs_add(struct scst_dev_group *dg,
					struct scst_dg_dev *dgdev)
{
	return 0;
}
static inline void scst_dg_dev_sysfs_del(struct scst_dev_group *dg,
					 struct scst_dg_dev *dgdev)
{
}
static inline int scst_tg_sysfs_add(struct scst_dev_group *dg,
					struct scst_target_group *tg)
{
	return 0;
}
static inline void scst_tg_sysfs_del(struct scst_target_group *tg)
{
}
static inline int scst_tg_tgt_sysfs_add(struct scst_target_group *tg,
					struct scst_tg_tgt *tg_tgt)
{
	return 0;
}
static inline void scst_tg_tgt_sysfs_del(struct scst_target_group *tg,
					 struct scst_tg_tgt *tg_tgt)
{
}
#endif

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

static inline int scst_dev_sysfs_dif_create(struct scst_device *dev)
{
	return 0;
}

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

#else /* CONFIG_SCST_PROC */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
extern const struct sysfs_ops scst_sysfs_ops;
#else
extern struct sysfs_ops scst_sysfs_ops;
#endif
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
int scst_add_sgv_kobj(struct kobject *parent, const char *name);
void scst_del_put_sgv_kobj(void);
int scst_devt_sysfs_create(struct scst_dev_type *devt);
void scst_devt_sysfs_del(struct scst_dev_type *devt);
int scst_dev_sysfs_create(struct scst_device *dev);
void scst_dev_sysfs_del(struct scst_device *dev);
int scst_dev_sysfs_dif_create(struct scst_device *dev);
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

/*
 * Check SPC-2 reservation state.
 * Must not be called from atomic context.
 */
static inline bool scst_dev_reserved(struct scst_device *dev)
{
	return dev->cl_ops->reserved(dev);
}


/* Protect SPC-2 reservation state against concurrent modifications. */
static inline void scst_res_lock(struct scst_device *dev,
				 struct scst_lksb *pr_lksb)
	__acquires(&dev->dev_lock)
{
	dev->cl_ops->res_lock(dev, pr_lksb);
}

static inline void scst_res_unlock(struct scst_device *dev,
				   struct scst_lksb *pr_lksb)
	__releases(&dev->dev_lock)
{
	dev->cl_ops->res_unlock(dev, pr_lksb);
}

/*
 * Whether @sess holds a reservation on @dev.
 * The caller may but does not have to hold dev->dev_lock.
 */
static inline bool scst_is_reservation_holder(struct scst_device *dev,
					      struct scst_session *sess)
{
	EXTRACHECKS_BUG_ON(sess == NULL);
	return dev->cl_ops->is_rsv_holder(dev, sess);
}

/*
 * Whether another session than @sess holds a reservation on @dev.
 * The caller may but does not have to hold dev->dev_lock.
 */
static inline bool scst_is_not_reservation_holder(struct scst_device *dev,
						  struct scst_session *sess)
{
	EXTRACHECKS_BUG_ON(sess == NULL);
	return dev->cl_ops->is_not_rsv_holder(dev, sess);
}

static inline void scst_reserve_dev(struct scst_device *dev,
				    struct scst_session *sess)
{
	lockdep_assert_held(&dev->dev_lock);
	EXTRACHECKS_BUG_ON(sess == NULL);
	dev->cl_ops->reserve(dev, sess);
}

static inline void scst_clear_dev_reservation(struct scst_device *dev)
{
	lockdep_assert_held(&dev->dev_lock);
	dev->cl_ops->reserve(dev, NULL);
}

void scst_tgt_dev_del_free_UA(struct scst_tgt_dev *tgt_dev,
			      struct scst_tgt_dev_UA *ua);
void scst_dev_check_set_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len);
void scst_dev_check_set_local_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len);

#define SCST_SET_UA_FLAG_AT_HEAD	1
#define SCST_SET_UA_FLAG_GLOBAL		2

void scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags);
int scst_set_pending_UA(struct scst_cmd *cmd, uint8_t *buf, int *size);

void scst_report_luns_changed(struct scst_acg *acg);

void scst_abort_cmd(struct scst_cmd *cmd, struct scst_mgmt_cmd *mcmd,
	bool other_ini, bool call_dev_task_mgmt_fn);
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd, bool setUA);
void scst_unblock_aborted_cmds(const struct scst_tgt *tgt,
	const struct scst_session *sess, const struct scst_device *device,
	bool scst_mutex_held);

bool scst_is_ua_global(const uint8_t *sense, int len);
void scst_requeue_ua(struct scst_cmd *cmd, const uint8_t *buf, int size);

struct scst_aen *scst_alloc_aen(struct scst_session *sess,
	uint64_t unpacked_lun);
void scst_free_aen(struct scst_aen *aen);

void scst_gen_aen_or_ua(struct scst_tgt_dev *tgt_dev,
	int key, int asc, int ascq);

/*
 * Some notes on devices "blocking". Blocking means that no
 * commands will go from SCST to underlying SCSI device until it
 * is unblocked. But, except for strictly serialized commands,
 * we don't care about all commands that already on the device.
 */

void scst_block_dev(struct scst_device *dev);
void scst_unblock_dev(struct scst_device *dev);
bool scst_do_check_blocked_dev(struct scst_cmd *cmd);
bool __scst_check_blocked_dev(struct scst_cmd *cmd);
void __scst_check_unblock_dev(struct scst_cmd *cmd);
void scst_check_unblock_dev(struct scst_cmd *cmd);

#define SCST_EXT_BLOCK_SYNC	1
#define SCST_EXT_BLOCK_STPG	2
int scst_ext_block_dev(struct scst_device *dev, ext_blocker_done_fn_t done_fn,
	const uint8_t *priv, int priv_len, int flags);
void scst_ext_unblock_dev(struct scst_device *dev, bool stpg);
void __scst_ext_blocking_done(struct scst_device *dev);
void scst_ext_blocking_done(struct scst_device *dev);

int scst_get_suspend_count(void);

/*
 * Increases global SCST ref counters which prevent from entering into suspended
 * activities stage, so protects from any global management operations.
 */
static inline atomic_t *scst_get(void)
{
	atomic_t *a;
	/*
	 * We don't mind if we because of preemption inc counter from another
	 * CPU as soon in the majority cases we will the correct one.
	 */
	a = &scst_percpu_infos[raw_smp_processor_id()].cpu_cmd_count;
	atomic_inc(a);
	TRACE_DBG("Incrementing cpu_cmd_count %p (new value %d)",
		a, atomic_read(a));
	/* See comment about smp_mb() in scst_suspend_activity() */
	smp_mb__after_atomic_inc();

	return a;
}

/*
 * Decreases global SCST ref counters which prevent from entering into suspended
 * activities stage, so protects from any global management operations. On
 * all them zero, if suspending activities is waiting, it will be proceed.
 */
static inline void scst_put(atomic_t *a)
{
	int f;

	f = atomic_dec_and_test(a);
	/* See comment about smp_mb() in scst_suspend_activity() */
	if (unlikely(test_bit(SCST_FLAG_SUSPENDED, &scst_flags)) && f) {
		TRACE_MGMT_DBG("%s", "Waking up scst_dev_cmd_waitQ");
		wake_up_all(&scst_dev_cmd_waitQ);
	}
	TRACE_DBG("Decrementing cpu_cmd_count %p (new value %d)",
	      a, atomic_read(a));
}

int scst_get_cmd_counter(void);

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

struct scst_cmd *scst_alloc_cmd(const uint8_t *cdb,
	unsigned int cdb_len, gfp_t gfp_mask);
int scst_pre_init_cmd(struct scst_cmd *cmd, const uint8_t *cdb,
	unsigned int cdb_len, gfp_t gfp_mask);
void scst_free_cmd(struct scst_cmd *cmd);

static inline void __scst_cmd_get(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->cmd_ref);
	smp_mb__after_atomic_inc();
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

void scst_throttle_cmd(struct scst_cmd *cmd);
void scst_unthrottle_cmd(struct scst_cmd *cmd);

int scst_do_internal_parsing(struct scst_cmd *cmd);
int scst_parse_descriptors(struct scst_cmd *cmd);

int scst_cmp_wr_local(struct scst_cmd *cmd);

int scst_pr_init(struct scst_device *dev);
void scst_pr_cleanup(struct scst_device *dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
void scst_vfs_unlink_and_put(struct nameidata *nd);
#else
void scst_vfs_unlink_and_put(struct path *path);
#endif

int scst_copy_file(const char *src, const char *dest);

struct scst_cmd *__scst_create_prepare_internal_cmd(const uint8_t *cdb,
	unsigned int cdb_len, enum scst_cmd_queue_type queue_type,
	struct scst_tgt_dev *tgt_dev, gfp_t gfp_mask, bool fantom);

static inline bool scst_lba1_inside_lba2(int64_t lba1,
	int64_t lba2, int64_t lba2_blocks)
{
	bool res;

	TRACE_DBG("lba1 %lld, lba2 %lld, lba2_blocks %lld", (long long)lba1,
		(long long)lba2, (long long)lba2_blocks);

	if ((lba1 >= lba2) && (lba1 < (lba2 + lba2_blocks)))
		res = true;
	else
		res = false;

	TRACE_EXIT_RES(res);
	return res;
}

#ifndef CONFIG_SCST_PROC

void scst_cm_update_dev(struct scst_device *dev);
int scst_cm_on_dev_register(struct scst_device *dev);
void scst_cm_on_dev_unregister(struct scst_device *dev);

int scst_cm_on_add_acg(struct scst_acg *acg);
void scst_cm_on_del_acg(struct scst_acg *acg);
int scst_cm_on_add_lun(struct scst_acg_dev *acg_dev, uint64_t lun,
	unsigned int *flags);
bool scst_cm_on_del_lun(struct scst_acg_dev *acg_dev,
	bool gen_report_luns_changed);

int scst_cm_parse_descriptors(struct scst_cmd *cmd);
void scst_cm_free_descriptors(struct scst_cmd *cmd);

int scst_cm_ext_copy_exec(struct scst_cmd *cmd);
int scst_cm_rcv_copy_res_exec(struct scst_cmd *cmd);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
void sess_cm_list_id_cleanup_work_fn(void *p);
#else
void sess_cm_list_id_cleanup_work_fn(struct work_struct *work);
#endif
void scst_cm_free_pending_list_ids(struct scst_session *sess);

bool scst_cm_check_block_all_devs(struct scst_cmd *cmd);
void scst_cm_abort_ec_cmd(struct scst_cmd *ec_cmd);

bool scst_cm_ec_cmd_overlap(struct scst_cmd *ec_cmd, struct scst_cmd *cmd);

int scst_cm_init(void);
void scst_cm_exit(void);

#else /* #ifndef CONFIG_SCST_PROC */

static inline void scst_cm_update_dev(struct scst_device *dev) {}
static inline int scst_cm_on_dev_register(struct scst_device *dev) { return 0; }
static inline void scst_cm_on_dev_unregister(struct scst_device *dev) {}

static inline int scst_cm_on_add_acg(struct scst_acg *acg)
{
	return 0;
}

static inline void scst_cm_on_del_acg(struct scst_acg *acg)
{
}

static inline int scst_cm_on_add_lun(struct scst_acg_dev *acg_dev, uint64_t lun,
				     unsigned int *flags)
{
	return 0;
}

static inline bool scst_cm_on_del_lun(struct scst_acg_dev *acg_dev,
				      bool gen_report_luns_changed)
{
	return gen_report_luns_changed;
}

static inline int scst_cm_parse_descriptors(struct scst_cmd *cmd)
{
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	scst_set_cmd_abnormal_done_state(cmd);
	return -1;
}
static inline void scst_cm_free_descriptors(struct scst_cmd *cmd) {}

static inline int scst_cm_ext_copy_exec(struct scst_cmd *cmd)
{
	return SCST_EXEC_NOT_COMPLETED;
}
static inline int scst_cm_rcv_copy_res_exec(struct scst_cmd *cmd)
{
	return SCST_EXEC_NOT_COMPLETED;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static inline void sess_cm_list_id_cleanup_work_fn(void *p) {}
#else
static inline void sess_cm_list_id_cleanup_work_fn(struct work_struct *work) {}
#endif
static inline void scst_cm_free_pending_list_ids(struct scst_session *sess) {}

static inline bool scst_cm_check_block_all_devs(struct scst_cmd *cmd) { return false; }
static inline void scst_cm_abort_ec_cmd(struct scst_cmd *ec_cmd) {}

static inline bool scst_cm_ec_cmd_overlap(struct scst_cmd *ec_cmd, struct scst_cmd *cmd)
{
	return false;
}

static inline int scst_cm_init(void) { return 0; }
static inline void scst_cm_exit(void) {}

#endif /* #ifndef CONFIG_SCST_PROC */

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

int scst_event_init(void);
void scst_event_exit(void);

int scst_event_queue_lun_not_found(const struct scst_cmd *cmd);
int scst_event_queue_negative_luns_inquiry(const struct scst_tgt *tgt,
	const char *initiator_name);
int scst_event_queue_ext_blocking_done(struct scst_device *dev, void *data, int len);
int scst_event_queue_tm_fn_received(struct scst_mgmt_cmd *mcmd);

typedef void __printf(2, 3) (*scst_show_fn)(void *arg, const char *fmt, ...);
void scst_trace_cmds(scst_show_fn show, void *arg);
void scst_trace_mcmds(scst_show_fn show, void *arg);

#ifdef CONFIG_SCST_MEASURE_LATENCY

void scst_set_start_time(struct scst_cmd *cmd);
void scst_set_cur_start(struct scst_cmd *cmd);
void scst_set_parse_time(struct scst_cmd *cmd);
void scst_set_alloc_buf_time(struct scst_cmd *cmd);
void scst_set_restart_waiting_time(struct scst_cmd *cmd);
void scst_set_rdy_to_xfer_time(struct scst_cmd *cmd);
void scst_set_pre_exec_time(struct scst_cmd *cmd);
void scst_set_exec_start(struct scst_cmd *cmd);
void scst_set_exec_time(struct scst_cmd *cmd);
void scst_set_dev_done_time(struct scst_cmd *cmd);
void scst_set_xmit_time(struct scst_cmd *cmd);
void scst_update_lat_stats(struct scst_cmd *cmd);

#else

static inline void scst_set_start_time(struct scst_cmd *cmd) {}
static inline void scst_set_cur_start(struct scst_cmd *cmd) {}
static inline void scst_set_parse_time(struct scst_cmd *cmd) {}
static inline void scst_set_alloc_buf_time(struct scst_cmd *cmd) {}
static inline void scst_set_restart_waiting_time(struct scst_cmd *cmd) {}
static inline void scst_set_rdy_to_xfer_time(struct scst_cmd *cmd) {}
static inline void scst_set_pre_exec_time(struct scst_cmd *cmd) {}
static inline void scst_set_exec_start(struct scst_cmd *cmd) {}
static inline void scst_set_exec_time(struct scst_cmd *cmd) {}
static inline void scst_set_dev_done_time(struct scst_cmd *cmd) {}
static inline void scst_set_xmit_time(struct scst_cmd *cmd) {}
static inline void scst_update_lat_stats(struct scst_cmd *cmd) {}

#endif /* CONFIG_SCST_MEASURE_LATENCY */

#endif /* __SCST_PRIV_H */
