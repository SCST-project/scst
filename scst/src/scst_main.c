/*
 *  scst_main.c
 *
 *  Copyright (C) 2004 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
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

#include <linux/module.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/lockdep.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_priv.h"
#include "scst_mem.h"
#include "scst_pres.h"

#undef DEFAULT_SYMBOL_NAMESPACE
#define DEFAULT_SYMBOL_NAMESPACE	SCST_NAMESPACE

#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
#warning HIGHMEM kernel configurations are fully supported, but not \
recommended for performance reasons. Consider changing VMSPLIT \
option or use a 64-bit configuration instead. See README file for \
details.
#endif

/*
 ** SCST global variables. They are all uninitialized to have their layout in
 ** memory be exactly as specified. Otherwise compiler puts zero-initialized
 ** variable separately from nonzero-initialized ones.
 **/

/*
 * Main SCST mutex. All targets, devices and dev_types management is done
 * under this mutex.
 */
struct mutex scst_mutex;
EXPORT_SYMBOL_GPL(scst_mutex);

/*
 * Second level main mutex, inner to scst_mutex and dev_pr_mutex. Needed for
 * __scst_pr_register_all_tg_pt(), since we can't use scst_mutex there,
 * because its caller already holds dev_pr_mutex, hence circular locking
 * dependency is possible.
 */
struct mutex scst_mutex2;

/* Both protected by scst_mutex or scst_mutex2 on read and both on write */
struct list_head scst_template_list;
struct list_head scst_dev_list;

/* Protected by scst_mutex */
struct list_head scst_dev_type_list;
struct list_head scst_virtual_dev_type_list;

static struct kmem_cache *scst_mgmt_cachep;
mempool_t *scst_mgmt_mempool;
static struct kmem_cache *scst_mgmt_stub_cachep;
mempool_t *scst_mgmt_stub_mempool;
static struct kmem_cache *scst_ua_cachep;
mempool_t *scst_ua_mempool;
static struct kmem_cache *scst_sense_cachep;
mempool_t *scst_sense_mempool;
static struct kmem_cache *scst_aen_cachep;
mempool_t *scst_aen_mempool;
struct kmem_cache *scst_tgt_cachep;
struct kmem_cache *scst_dev_cachep;
struct kmem_cache *scst_tgtd_cachep;
struct kmem_cache *scst_sess_cachep;
struct kmem_cache *scst_acgd_cachep;
static struct kmem_cache *scst_thr_cachep;

char *scst_cluster_name;

unsigned int scst_setup_id;

spinlock_t scst_init_lock;
wait_queue_head_t scst_init_cmd_list_waitQ;
struct list_head scst_init_cmd_list;
unsigned int scst_init_poll_cnt;

struct kmem_cache *scst_cmd_cachep;

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
unsigned long scst_trace_flag;
#endif

unsigned long scst_poll_ns = SCST_DEF_POLL_NS;

int scst_max_tasklet_cmd = SCST_DEF_MAX_TASKLET_CMD;

struct scst_cmd_threads scst_main_cmd_threads;

static bool percpu_ref_killed;
struct percpu_ref scst_cmd_count;
struct percpu_ref scst_mcmd_count;
struct scst_percpu_info scst_percpu_infos[NR_CPUS];

spinlock_t scst_mcmd_lock;
struct list_head scst_active_mgmt_cmd_list;
struct list_head scst_delayed_mgmt_cmd_list;
wait_queue_head_t scst_mgmt_cmd_list_waitQ;

wait_queue_head_t scst_mgmt_waitQ;
spinlock_t scst_mgmt_lock;
struct list_head scst_sess_init_list;
struct list_head scst_sess_shut_list;

static wait_queue_head_t scst_dev_cmd_waitQ;
static struct completion scst_confirm_done;

static struct mutex scst_cmd_threads_mutex;
/* protected by scst_cmd_threads_mutex */
static struct list_head scst_cmd_threads_list;

static struct task_struct *scst_init_cmd_thread;
static struct task_struct *scst_mgmt_thread;
static struct task_struct *scst_mgmt_cmd_thread;

/*
 * Protects global suspending and resuming from being initiated from
 * several threads simultaneously.
 */
static struct mutex scst_suspend_mutex;
#ifdef CONFIG_LOCKDEP
static struct lock_class_key scst_suspend_key;
struct lockdep_map scst_suspend_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_suspend_activity", &scst_suspend_key);
#endif

/* Protected by scst_suspend_mutex */
static int suspend_count;

static int scst_virt_dev_last_id; /* protected by scst_mutex */

cpumask_t default_cpu_mask;

spinlock_t scst_measure_latency_lock;
atomic_t scst_measure_latency;

int scst_threads;
module_param_named(scst_threads, scst_threads, int, 0444);
MODULE_PARM_DESC(scst_threads, "SCSI target threads count");

static unsigned int scst_max_cmd_mem;
module_param_named(scst_max_cmd_mem, scst_max_cmd_mem, int, 0444);
MODULE_PARM_DESC(scst_max_cmd_mem,
		 "Maximum memory allowed to be consumed by all SCSI commands of all devices at any given time in MB");

unsigned int scst_max_dev_cmd_mem;
module_param_named(scst_max_dev_cmd_mem, scst_max_dev_cmd_mem, int, 0444);
MODULE_PARM_DESC(scst_max_dev_cmd_mem,
		 "Maximum memory allowed to be consumed by all SCSI commands of a device at any given time in MB");

bool scst_forcibly_close_sessions;
module_param_named(forcibly_close_sessions, scst_forcibly_close_sessions, bool, 0644);
MODULE_PARM_DESC(forcibly_close_sessions,
		 "If enabled, close the sessions associated with an access control group (ACG) when an ACG is deleted via sysfs instead of returning -EBUSY. (default: false)");

bool scst_auto_cm_assignment = true;
module_param_named(auto_cm_assignment, scst_auto_cm_assignment, bool, 0644);
MODULE_PARM_DESC(auto_cm_assignment,
		 "Enables the copy managers auto registration. (default: true)");

struct scst_dev_type scst_null_devtype = {
	.name = "none",
	.threads_num = -1,
};

static void __scst_resume_activity(void);

/**
 * __scst_register_target_template() - register target template.
 * @vtt:	target template
 * @version:	SCST_INTERFACE_VERSION version string to ensure that
 *		SCST core and the target driver use the same version of
 *		the SCST interface
 *
 * Description:
 *    Registers a target template and returns 0 on success or appropriate
 *    error code otherwise.
 *
 *    Target drivers supposed to behave sanely and not call register()
 *    and unregister() randomly simultaneously.
 */
int __scst_register_target_template(struct scst_tgt_template *vtt, const char *version)
{
	int res = 0;
	struct scst_tgt_template *t;

	TRACE_ENTRY();

	INIT_LIST_HEAD(&vtt->tgt_list);

	if (strcmp(version, SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of target %s", vtt->name);
		res = -EINVAL;
		goto out;
	}

	if (!vtt->release) {
		PRINT_ERROR("Target driver %s must have release() method.",
			    vtt->name);
		res = -EINVAL;
		goto out;
	}

	if (!vtt->xmit_response) {
		PRINT_ERROR("Target driver %s must have xmit_response() method.",
			    vtt->name);
		res = -EINVAL;
		goto out;
	}

	if (!vtt->get_initiator_port_transport_id)
		PRINT_WARNING("Target driver %s doesn't support Persistent Reservations",
			      vtt->name);

	if (vtt->threads_num < 0) {
		PRINT_ERROR("Wrong threads_num value %d for target \"%s\"",
			    vtt->threads_num, vtt->name);
		res = -EINVAL;
		goto out;
	}

	if ((!vtt->enable_target || !vtt->is_target_enabled) &&
	    !vtt->enabled_attr_not_needed)
		PRINT_WARNING("Target driver %s doesn't have enable_target() and/or is_target_enabled() method(s). This is unsafe and can lead that initiators connected on the initialization time can see an unexpected set of devices or no devices at all!",
			      vtt->name);

	if ((vtt->add_target && !vtt->del_target) || (!vtt->add_target && vtt->del_target)) {
		PRINT_ERROR("Target driver %s must either define both add_target() and del_target(), or none.",
			    vtt->name);
		res = -EINVAL;
		goto out;
	}

	if (!vtt->rdy_to_xfer)
		vtt->rdy_to_xfer_atomic = 1;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;
	list_for_each_entry(t, &scst_template_list, scst_template_list_entry) {
		if (strcmp(t->name, vtt->name) == 0) {
			PRINT_ERROR("Target driver %s already registered",
				    vtt->name);
			goto out_unlock;
		}
	}
	mutex_unlock(&scst_mutex);

	res = scst_tgtt_sysfs_create(vtt);
	if (res != 0)
		goto out;

	mutex_lock(&scst_mutex);
	mutex_lock(&scst_mutex2);
	list_add_tail(&vtt->scst_template_list_entry, &scst_template_list);
	mutex_unlock(&scst_mutex2);
	mutex_unlock(&scst_mutex);

	PRINT_INFO("Target template %s registered successfully", vtt->name);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	mutex_unlock(&scst_mutex);
	goto out;
}
EXPORT_SYMBOL_GPL(__scst_register_target_template);

static int scst_check_non_gpl_target_template(struct scst_tgt_template *vtt)
{
	int res;

	TRACE_ENTRY();

	if (vtt->task_mgmt_affected_cmds_done || vtt->threads_num ||
	    vtt->on_hw_pending_cmd_timeout) {
		PRINT_ERROR("Not allowed functionality in non-GPL version for target template %s",
			    vtt->name);
		res = -EPERM;
		goto out;
	}

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/**
 * __scst_register_target_template_non_gpl() - register target template,
 *					      non-GPL version
 * @vtt:	target template
 * @version:	SCST_INTERFACE_VERSION version string to ensure that
 *		SCST core and the target driver use the same version of
 *		the SCST interface
 *
 * Description:
 *    Registers a target template and returns 0 on success or appropriate
 *    error code otherwise.
 *
 *    Note: *vtt must be static!
 */
int __scst_register_target_template_non_gpl(struct scst_tgt_template *vtt, const char *version)
{
	int res;

	TRACE_ENTRY();

	res = scst_check_non_gpl_target_template(vtt);
	if (res != 0)
		goto out;

	res = __scst_register_target_template(vtt, version);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(__scst_register_target_template_non_gpl);

/*
 * scst_unregister_target_template() - unregister target template
 *
 * Target drivers supposed to behave sanely and not call register()
 * and unregister() randomly simultaneously. Also it is supposed that
 * no attempts to create new targets for this vtt will be done in a race
 * with this function.
 */
void scst_unregister_target_template(struct scst_tgt_template *vtt)
{
	struct scst_tgt *tgt;
	struct scst_tgt_template *t;
	int found = 0;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	list_for_each_entry(t, &scst_template_list, scst_template_list_entry) {
		if (strcmp(t->name, vtt->name) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		PRINT_ERROR("Target driver %s isn't registered", vtt->name);
		goto out_err_up;
	}

	mutex_lock(&scst_mutex2);
	list_del(&vtt->scst_template_list_entry);
	mutex_unlock(&scst_mutex2);

	/* Wait for outstanding sysfs mgmt calls completed */
	while (vtt->tgtt_active_sysfs_works_count > 0) {
		mutex_unlock(&scst_mutex);
		msleep(100);
		mutex_lock(&scst_mutex);
	}

	while (!list_empty(&vtt->tgt_list)) {
		tgt = list_first_entry(&vtt->tgt_list, typeof(*tgt),
				       tgt_list_entry);
		mutex_unlock(&scst_mutex);
		scst_unregister_target(tgt);
		mutex_lock(&scst_mutex);
	}

	mutex_unlock(&scst_mutex);

	scst_tgtt_sysfs_del(vtt);

	PRINT_INFO("Target template %s unregistered successfully", vtt->name);

out:
	TRACE_EXIT();
	return;

out_err_up:
	mutex_unlock(&scst_mutex);
	goto out;
}
EXPORT_SYMBOL(scst_unregister_target_template);

/*
 * scst_register_target() - register target
 *
 * Registers a target for template vtt and returns new target structure on
 * success or NULL otherwise.
 */
struct scst_tgt *scst_register_target(struct scst_tgt_template *vtt, const char *target_name)
{
	struct scst_tgt *tgt, *t;
	int rc = 0;

	TRACE_ENTRY();

	BUG_ON(!target_name);

	rc = scst_alloc_tgt(vtt, &tgt);
	if (rc != 0)
		goto out;

	tgt->tgt_name = kstrdup(target_name, GFP_KERNEL);
	if (!tgt->tgt_name) {
		PRINT_ERROR("Allocation of tgt name %s failed",
			    target_name);
		rc = -ENOMEM;
		goto out_free_tgt;
	}

	rc = mutex_lock_interruptible(&scst_mutex);
	if (rc != 0)
		goto out_free_tgt;

	list_for_each_entry(t, &vtt->tgt_list, tgt_list_entry) {
		if (strcmp(t->tgt_name, tgt->tgt_name) == 0) {
			PRINT_ERROR("target %s already exists", tgt->tgt_name);
			rc = -EEXIST;
			goto out_unlock;
		}
	}

	rc = scst_tgt_sysfs_create(tgt);
	if (rc < 0)
		goto out_unlock;

	rc = scst_alloc_add_acg(tgt, tgt->tgt_name, false, &tgt->default_acg);
	if (rc != 0)
		goto out_sysfs_del;

	mutex_lock(&scst_mutex2);
	list_add_tail(&tgt->tgt_list_entry, &vtt->tgt_list);
	mutex_unlock(&scst_mutex2);

	mutex_unlock(&scst_mutex);

	PRINT_INFO("Target %s for template %s registered successfully",
		   tgt->tgt_name, vtt->name);

	TRACE_DBG("tgt %p", tgt);

out:
	TRACE_EXIT();
	return tgt;

out_sysfs_del:
	mutex_unlock(&scst_mutex);
	scst_tgt_sysfs_del(tgt);
	goto out_free_tgt;

out_unlock:
	mutex_unlock(&scst_mutex);

out_free_tgt:
	/* In case of error tgt_name will be freed in scst_free_tgt() */
	scst_free_tgt(tgt);
	tgt = NULL;
	goto out;
}
EXPORT_SYMBOL(scst_register_target);

/**
 * scst_unregister_target() - unregister a target
 * @tgt: Target to be unregistered.
 *
 * The caller is responsible for unregistration of all sessions associated
 * with @tgt. Additionally, the caller must guarantee that no new sessions
 * will be associated with @tgt while this function is in progress.
 */
void scst_unregister_target(struct scst_tgt *tgt)
{
	struct scst_tgt_template *vtt = tgt->tgtt;
	struct scst_acg *acg, *acg_tmp;
	int res;

	TRACE_ENTRY();

	/*
	 * Remove the sysfs attributes of a target before invoking
	 * tgt->tgtt->release(tgt) such that the "enabled" attribute can't be
	 * accessed during or after the tgt->tgtt->release(tgt) call.
	 */
	scst_tgt_sysfs_del(tgt);

	TRACE_DBG("Calling target driver's release()");
	tgt->tgtt->release(tgt);
	TRACE_DBG("Target driver's release() returned");

	/*
	 * Testing tgt->sysfs_sess_list below without holding scst_mutex
	 * is safe, because:
	 *
	 * - On the init path no attempts to create new sessions for this
	 * target can be done in a race with this function (see above)
	 *
	 * - On the shutdown path 'tgt' won't disappear until scst_free_tgt()
	 * is called below and because the mutex_lock(&scst_mutex) call below
	 * waits until scst_free_session() has finished accessing the 'tgt'
	 * object.
	 */
	TRACE_DBG("Waiting for sessions shutdown");
	while (!wait_event_timeout(tgt->unreg_waitQ, list_empty(&tgt->sysfs_sess_list), 60 * HZ)) {
		struct scst_session *sess;

		mutex_lock(&scst_mutex);
		list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
			PRINT_INFO("Still waiting for session %s/%s; state %ld; refcnt %#lx",
				   tgt->tgt_name, sess->sess_name,
				   sess->shut_phase,
				   percpu_ref_read(&sess->refcnt));
		}
		mutex_unlock(&scst_mutex);
	}
	TRACE_DBG("wait_event() returned");

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_UNLIMITED);
	WARN_ON_ONCE(res);

	mutex_lock(&scst_mutex);

	mutex_lock(&scst_mutex2);
	list_del(&tgt->tgt_list_entry);
	mutex_unlock(&scst_mutex2);

	timer_delete_sync(&tgt->retry_timer);

	scst_tg_tgt_remove_by_tgt(tgt);

	scst_del_free_acg(tgt->default_acg, false);

	list_for_each_entry_safe(acg, acg_tmp, &tgt->tgt_acg_list, acg_list_entry)
		scst_del_free_acg(acg, false);

	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	scst_tgt_sysfs_put(tgt);

	PRINT_INFO("Target %s for template %s unregistered successfully",
		   tgt->tgt_name, vtt->name);

	scst_free_tgt(tgt);

	TRACE_DBG("Unregistering tgt %p finished", tgt);

	TRACE_EXIT();
}
EXPORT_SYMBOL(scst_unregister_target);

static const char *const scst_cmd_state_name[] = {
	[SCST_CMD_STATE_PARSE]				= "PARSE",
	[SCST_CMD_STATE_PREPARE_SPACE]			= "PREPARE_SPACE",
	[SCST_CMD_STATE_PREPROCESSING_DONE]		= "PREP_DONE",
	[SCST_CMD_STATE_RDY_TO_XFER]			= "RDY_TO_XFER",
	[SCST_CMD_STATE_TGT_PRE_EXEC]			= "TGT_PRE_EXEC",
	[SCST_CMD_STATE_EXEC_CHECK_SN]			= "EXEC_CHECK_SN",
	[SCST_CMD_STATE_PRE_DEV_DONE]			= "PRE_DEV_DONE",
	[SCST_CMD_STATE_MODE_SELECT_CHECKS]		= "MODE_SELECT_CHECKS",
	[SCST_CMD_STATE_DEV_DONE]			= "DEV_DONE",
	[SCST_CMD_STATE_PRE_XMIT_RESP]			= "PRE_XMIT_RESP",
	[SCST_CMD_STATE_PRE_XMIT_RESP1]			= "PRE_XMIT_RESP1",
	[SCST_CMD_STATE_CSW2]				= "CSW2",
	[SCST_CMD_STATE_PRE_XMIT_RESP2]			= "PRE_XMIT_RESP2",
	[SCST_CMD_STATE_XMIT_RESP]			= "XMIT_RESP",
	[SCST_CMD_STATE_FINISHED]			= "FINISHED",
	[SCST_CMD_STATE_FINISHED_INTERNAL]		= "FINISHED_INTERNAL",
	[SCST_CMD_STATE_INIT_WAIT]			= "INIT_WAIT",
	[SCST_CMD_STATE_INIT]				= "INIT",
	[SCST_CMD_STATE_CSW1]				= "CSW1",
	[SCST_CMD_STATE_PREPROCESSING_DONE_CALLED]	= "PREP_DONE_CALLED",
	[SCST_CMD_STATE_DATA_WAIT]			= "DATA_WAIT",
	[SCST_CMD_STATE_EXEC_CHECK_BLOCKING]		= "EXEC_CHECK_BLOCKING",
	[SCST_CMD_STATE_LOCAL_EXEC]			= "LOCAL_EXEC",
	[SCST_CMD_STATE_REAL_EXEC]			= "REAL_EXEC",
	[SCST_CMD_STATE_EXEC_WAIT]			= "EXEC_WAIT",
	[SCST_CMD_STATE_XMIT_WAIT]			= "XMIT_WAIT",
};

char *scst_get_cmd_state_name(char *name, int len, unsigned int state)
{
	if (state < ARRAY_SIZE(scst_cmd_state_name) &&
	    scst_cmd_state_name[state])
		strscpy(name, scst_cmd_state_name[state], len);
	else
		snprintf(name, len, "%d", state);
	return name;
}

static char *scst_dump_cdb(char *buf, int buf_len, struct scst_cmd *cmd)
{
	char *p = buf, *end = buf + buf_len;
	int i;

	for (i = 0; i < cmd->cdb_len && p < end; i++)
		p += scnprintf(p, end - p, "%s%02x", i ? " " : "", cmd->cdb[i]);

	return buf;
}

void scst_trace_cmds(scst_show_fn show, void *arg)
{
	struct scst_tgt_template *t;
	struct scst_tgt *tgt;
	struct scst_session *sess;
	struct scst_cmd *cmd;
	struct scst_tgt_dev *tgt_dev;
	char state_name[32];
	char cdb[64];

	mutex_lock(&scst_mutex);
	list_for_each_entry(t, &scst_template_list, scst_template_list_entry) {
		list_for_each_entry(tgt, &t->tgt_list, tgt_list_entry) {
			list_for_each_entry(sess, &tgt->sess_list,
					    sess_list_entry) {
				spin_lock_irq(&sess->sess_list_lock);
				list_for_each_entry(cmd, &sess->sess_cmd_list,
						    sess_cmd_list_entry) {
					tgt_dev = cmd->tgt_dev;
					scst_dump_cdb(cdb, sizeof(cdb), cmd);
					scst_get_cmd_state_name(state_name, sizeof(state_name),
								cmd->state);
					show(arg,
					     "cmd %p: state %s; op %s; proc time %ld sec; tgtt %s; tgt %s; session %s; grp %s; LUN %lld; ini %s; cdb %s\n",
					     cmd, state_name, scst_get_opcode_name(cmd),
					     (long)(jiffies - cmd->start_time) / HZ,
					     t->name, tgt->tgt_name, sess->sess_name,
					     tgt_dev ? (tgt_dev->acg_dev->acg->acg_name ?: "(default)") : "?",
					     cmd->lun, sess->initiator_name, cdb);
				}
				spin_unlock_irq(&sess->sess_list_lock);
			}
		}
	}
	mutex_unlock(&scst_mutex);
}

static const char *const scst_tm_fn_name[] = {
	[SCST_ABORT_TASK]		= "ABORT_TASK",
	[SCST_ABORT_TASK_SET]		= "ABORT_TASK_SET",
	[SCST_CLEAR_ACA]		= "CLEAR_ACA",
	[SCST_CLEAR_TASK_SET]		= "CLEAR_TASK_SET",
	[SCST_LUN_RESET]		= "LUN_RESET",
	[SCST_TARGET_RESET]		= "TARGET_RESET",
	[SCST_NEXUS_LOSS_SESS]		= "NEXUS_LOSS_SESS",
	[SCST_ABORT_ALL_TASKS_SESS]	= "ABORT_ALL_TASKS_SESS",
	[SCST_NEXUS_LOSS]		= "NEXUS_LOSS",
	[SCST_ABORT_ALL_TASKS]		= "ABORT_ALL_TASKS",
	[SCST_UNREG_SESS_TM]		= "UNREG_SESS_TM",
	[SCST_PR_ABORT_ALL]		= "PR_ABORT_ALL",
};

char *scst_get_tm_fn_name(char *name, int len, unsigned int fn)
{
	if (fn < ARRAY_SIZE(scst_tm_fn_name) && scst_tm_fn_name[fn])
		strscpy(name, scst_tm_fn_name[fn], len);
	else
		snprintf(name, len, "%d", fn);
	return name;
}

static const char *const scst_mcmd_state_name[] = {
	[SCST_MCMD_STATE_INIT]					= "INIT",
	[SCST_MCMD_STATE_EXEC]					= "EXEC",
	[SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_DONE]		= "WAITING_AFFECTED_CMDS_DONE",
	[SCST_MCMD_STATE_AFFECTED_CMDS_DONE]			= "AFFECTED_CMDS_DONE",
	[SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_FINISHED]	= "WAITING_AFFECTED_CMDS_FINISHED",
	[SCST_MCMD_STATE_DONE]					= "DONE",
	[SCST_MCMD_STATE_FINISHED]				= "FINISHED",
};

char *scst_get_mcmd_state_name(char *name, int len, unsigned int state)
{
	if (state < ARRAY_SIZE(scst_mcmd_state_name) &&
	    scst_mcmd_state_name[state])
		strscpy(name, scst_mcmd_state_name[state], len);
	else
		snprintf(name, len, "%d", state);
	return name;
}

void scst_trace_mcmds(scst_show_fn show, void *arg)
{
	struct scst_mgmt_cmd *mcmd;
	char fn_name[16], state_name[32];

	spin_lock_irq(&scst_mcmd_lock);
	list_for_each_entry(mcmd, &scst_active_mgmt_cmd_list, mgmt_cmd_list_entry) {
		scst_get_tm_fn_name(fn_name, sizeof(fn_name), mcmd->fn);
		scst_get_mcmd_state_name(state_name, sizeof(state_name), mcmd->state);
		show(arg,
		     "mcmd %p: state %s; tgtt %s; tgt %s; session %s; fn %s; LUN %lld; tag %lld; cmd_done_wait_count %d\n",
		     mcmd, state_name, mcmd->sess->tgt->tgtt->name,
		     mcmd->sess->tgt->tgt_name, mcmd->sess->sess_name, fn_name,
		     mcmd->lun, mcmd->tag, mcmd->cmd_done_wait_count);
	}
	spin_unlock_irq(&scst_mcmd_lock);
}

static void __printf(2, 3) scst_to_syslog(void *arg, const char *fmt, ...)
{
	bool *header_printed = arg;
	va_list args;

	if (!*header_printed) {
		PRINT_INFO("Pending commands:");
		*header_printed = true;
	}

	va_start(args, fmt);
	pr_info("    ");
	vprintk(fmt, args);
	va_end(args);
}

/*
 * Number of SCST non-management commands, management commands and activities
 * that are in progress. Must only be called if both scst_cmd_count and
 * scst_mcmd_count are in atomic mode.
 */
int scst_get_cmd_counter(void)
{
	return percpu_ref_read(&scst_cmd_count) +
		percpu_ref_read(&scst_mcmd_count);
}

static int scst_susp_wait(unsigned long timeout)
{
	int res;
	unsigned long t;
	bool hp = false;
#define SCST_SUSP_WAIT_REPORT_TIMEOUT (5UL * HZ)

	TRACE_ENTRY();

	if (timeout == SCST_SUSPEND_TIMEOUT_UNLIMITED)
		t = SCST_SUSP_WAIT_REPORT_TIMEOUT;
	else
		t = min(timeout, SCST_SUSP_WAIT_REPORT_TIMEOUT);

	res = wait_event_interruptible_timeout(scst_dev_cmd_waitQ,
					       percpu_ref_killed, t);
	if (res > 0) {
		res = 0;
		goto out;
	}
	if (res < 0 && timeout != SCST_SUSPEND_TIMEOUT_UNLIMITED)
		goto out;

	if (res == 0) {
		PRINT_INFO("%d active commands to still not completed. See README for possible reasons.",
			   scst_get_cmd_counter());
		scst_trace_cmds(scst_to_syslog, &hp);
		scst_trace_mcmds(scst_to_syslog, &hp);
	}

	if (timeout != SCST_SUSPEND_TIMEOUT_UNLIMITED) {
		res = wait_event_interruptible_timeout(scst_dev_cmd_waitQ,
						       percpu_ref_killed, timeout - t);
		if (res == 0)
			res = -EBUSY;
		else if (res > 0)
			res = 0;
	} else {
		wait_event(scst_dev_cmd_waitQ, percpu_ref_killed);
		res = 0;
	}

out:
	TRACE_MGMT_DBG("wait_event() returned %d", res);

	TRACE_EXIT_RES(res);
	return res;
#undef SCST_SUSP_WAIT_REPORT_TIMEOUT
}

static void scst_suspend_counter_confirm(struct percpu_ref *ref)
{
	complete(&scst_confirm_done);
}

/*
 * scst_suspend_activity() - globally suspend activity
 *
 * Description:
 *    Globally suspends SCSI command and SCSI management command processing and
 *    waits until all active commands have finished (state after
 *    SCST_CMD_STATE_INIT). The timeout parameter defines the maximum time this
 *    function will wait until activity has been suspended. If this function is
 *    interrupted by a signal, it returns a negative value. If the timeout value
 *    is SCST_SUSPEND_TIMEOUT_UNLIMITED, then it will wait virtually forever.
 *    Returns 0 upon success.
 *
 *    Newly arriving commands remain in the suspended state until
 *    scst_resume_activity() is called.
 */
int scst_suspend_activity(unsigned long timeout)
{
	int res = 0;
	bool rep = false;
	unsigned long cur_time = jiffies, wait_time;

	TRACE_ENTRY();

	rwlock_acquire_read(&scst_suspend_dep_map, 0, 0, _RET_IP_);

	if (timeout != SCST_SUSPEND_TIMEOUT_UNLIMITED) {
		res = mutex_lock_interruptible(&scst_suspend_mutex);
		if (res != 0)
			goto out;
	} else {
		mutex_lock(&scst_suspend_mutex);
	}

	TRACE_MGMT_DBG("suspend_count %d", suspend_count);
	suspend_count++;
	if (suspend_count > 1)
		goto out_up;

	/* Cause scst_get_cmd() to fail. */
	init_completion(&scst_confirm_done);

	percpu_ref_killed = false;
	percpu_ref_kill_and_confirm(&scst_cmd_count, scst_suspend_counter_confirm);

	wait_for_completion(&scst_confirm_done);

	/*
	 * See comment in scst_user.c::dev_user_task_mgmt_fn() for more
	 * information about scst_user behavior.
	 *
	 * ToDo: make the global suspending unneeded (switch to per-device
	 * reference counting? That would mean to switch off from lockless
	 * implementation of scst_translate_lun().. )
	 */

	if (scst_get_cmd_counter() != 0) {
		PRINT_INFO("Waiting for %d active commands to complete...",
			   scst_get_cmd_counter());
		rep = true;

		lock_contended(&scst_suspend_dep_map, _RET_IP_);
	}

	res = scst_susp_wait(timeout);

	/* Cause scst_get_mcmd() to fail. */
	init_completion(&scst_confirm_done);

	percpu_ref_killed = false;
	percpu_ref_kill_and_confirm(&scst_mcmd_count, scst_suspend_counter_confirm);

	wait_for_completion(&scst_confirm_done);

	if (res != 0)
		goto out_resume;

	if (scst_get_cmd_counter() != 0)
		TRACE_MGMT_DBG("Waiting for %d active commands finally to complete",
			       scst_get_cmd_counter());

	if (timeout != SCST_SUSPEND_TIMEOUT_UNLIMITED) {
		wait_time = jiffies - cur_time;
		/* just in case */
		if (wait_time >= timeout) {
			res = -EBUSY;
			goto out_resume;
		}
		wait_time = timeout - wait_time;
	} else {
		wait_time = SCST_SUSPEND_TIMEOUT_UNLIMITED;
	}

	res = scst_susp_wait(wait_time);
	if (res != 0)
		goto out_resume;

	if (rep)
		PRINT_INFO("All active commands completed");

out_up:
	mutex_unlock(&scst_suspend_mutex);

out:
	if (res == 0)
		lock_acquired(&scst_suspend_dep_map, _RET_IP_);
	else
		rwlock_release(&scst_suspend_dep_map, _RET_IP_);

	TRACE_EXIT_RES(res);
	return res;

out_resume:
	__scst_resume_activity();
	EXTRACHECKS_BUG_ON(suspend_count != 0);
	goto out_up;
}
EXPORT_SYMBOL_GPL(scst_suspend_activity);

/* scst_suspend_mutex supposed to be locked */
static void __scst_resume_activity(void)
{
	struct scst_cmd_threads *l;
	struct scst_mgmt_cmd *m;

	TRACE_ENTRY();

	if (suspend_count == 0) {
		PRINT_WARNING("Resume without suspend");
		goto out;
	}

	suspend_count--;
	TRACE_MGMT_DBG("suspend_count %d left", suspend_count);
	if (suspend_count > 0)
		goto out;

	percpu_ref_resurrect(&scst_mcmd_count);
	percpu_ref_resurrect(&scst_cmd_count);

	mutex_lock(&scst_cmd_threads_mutex);
	list_for_each_entry(l, &scst_cmd_threads_list, lists_list_entry) {
		wake_up_all(&l->cmd_list_waitQ);
	}
	mutex_unlock(&scst_cmd_threads_mutex);

	/*
	 * Wait until scst_init_thread() either is waiting or has reexamined
	 * scst_cmd_count.
	 */
	spin_lock_irq(&scst_init_lock);
	spin_unlock_irq(&scst_init_lock);

	wake_up_all(&scst_init_cmd_list_waitQ);

	spin_lock_irq(&scst_mcmd_lock);
	list_for_each_entry(m, &scst_delayed_mgmt_cmd_list, mgmt_cmd_list_entry)
		TRACE_MGMT_DBG("Moving delayed mgmt cmd %p to head of active mgmt cmd list",
			       m);
	list_splice_init(&scst_delayed_mgmt_cmd_list,
			 &scst_active_mgmt_cmd_list);
	spin_unlock_irq(&scst_mcmd_lock);

	wake_up_all(&scst_mgmt_cmd_list_waitQ);

out:
	TRACE_EXIT();
}

/**
 * scst_resume_activity() - globally resume all activities
 *
 * Resumes suspended by scst_suspend_activity() activities.
 */
void scst_resume_activity(void)
{
	TRACE_ENTRY();

	rwlock_release(&scst_suspend_dep_map, _RET_IP_);

	mutex_lock(&scst_suspend_mutex);
	__scst_resume_activity();
	mutex_unlock(&scst_suspend_mutex);

	TRACE_EXIT();
}
EXPORT_SYMBOL_GPL(scst_resume_activity);

int scst_get_suspend_count(void)
{
	return suspend_count;
}

static int scst_register_device(struct scsi_device *scsidp)
{
	DECLARE_COMPLETION_ONSTACK(c);
	struct scst_device *dev, *d;
	int res;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	res = scst_alloc_device(GFP_KERNEL, NUMA_NO_NODE, &dev);
	if (res != 0)
		goto out_unlock;

	dev->type = scsidp->type;

	dev->virt_name = kasprintf(GFP_KERNEL, "%d:%d:%d:%lld",
				   scsidp->host->host_no, scsidp->channel,
				   scsidp->id, (u64)scsidp->lun);
	if (!dev->virt_name) {
		PRINT_ERROR("Unable to alloc device name");
		res = -ENOMEM;
		goto out_free_dev;
	}

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (strcmp(d->virt_name, dev->virt_name) == 0) {
			PRINT_ERROR("Device %s already exists", dev->virt_name);
			res = -EEXIST;
			goto out_free_dev;
		}
	}

	dev->scsi_dev = scsidp;

	/* For target ports that function as forwarding source. */
	res = scst_pr_set_file_name(dev, NULL, "%s/%s", SCST_PR_DIR,
				    dev->virt_name);
	if (res != 0)
		goto out_free_dev;

	res = scst_pr_init_dev(dev);
	if (res != 0)
		goto out_free_dev;

	list_add_tail(&dev->dev_list_entry, &scst_dev_list);

	mutex_unlock(&scst_mutex);

	res = scst_dev_sysfs_create(dev);
	if (res != 0)
		goto out_del_unlocked;

	percpu_ref_get(&dev->refcnt);

	PRINT_INFO("Attached to scsi%d, channel %d, id %d, lun %lld, type %d",
		   scsidp->host->host_no, scsidp->channel, scsidp->id,
		   (u64)scsidp->lun, scsidp->type);

out:
	TRACE_EXIT_RES(res);
	return res;

out_del_unlocked:
	mutex_lock(&scst_mutex);
	list_del_init(&dev->dev_list_entry);

	/* If used as a forwarding source (see also tgt_forward_src). */
	scst_pr_clear_dev(dev);

out_free_dev:
	dev->remove_completion = &c;
	percpu_ref_kill(&dev->refcnt);
	wait_for_completion(&c);
	scst_free_device(dev);

out_unlock:
	mutex_unlock(&scst_mutex);
	goto out;
}

static struct scst_device *__scst_lookup_device(struct scsi_device *scsidp)
{
	struct scst_device *d;

	lockdep_assert_held(&scst_mutex);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry)
		if (d->scsi_dev == scsidp)
			return d;

	return NULL;
}

static void scst_unregister_device(struct scsi_device *scsidp)
{
	struct scst_device *dev;
	struct scst_acg_dev *acg_dev, *aa;
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	dev = __scst_lookup_device(scsidp);
	if (!dev) {
		PRINT_ERROR("SCST device for SCSI device %d:%d:%d:%lld not found",
			    scsidp->host->host_no, scsidp->channel, scsidp->id,
			    (u64)scsidp->lun);
		goto out_unlock;
	}

	dev->dev_unregistering = 1;

	list_del_init(&dev->dev_list_entry);

	/* For forwarding sources (see also tgt_forward_src). */
	scst_pr_clear_dev(dev);

	scst_dg_dev_remove_by_dev(dev);

	list_for_each_entry_safe(acg_dev, aa, &dev->dev_acg_dev_list,
				 dev_acg_dev_list_entry) {
		scst_acg_del_lun(acg_dev->acg, acg_dev->lun, true);
	}

	dev->remove_completion = &c;

	mutex_unlock(&scst_mutex);

	PRINT_INFO("Detached from scsi%d, channel %d, id %d, lun %lld, type %d",
		   scsidp->host->host_no, scsidp->channel, scsidp->id,
		   (u64)scsidp->lun, scsidp->type);

	percpu_ref_kill(&dev->refcnt);
	percpu_ref_put(&dev->refcnt);

	wait_for_completion(&c);

	mutex_lock(&scst_mutex);
	scst_assign_dev_handler(dev, &scst_null_devtype);
	mutex_unlock(&scst_mutex);

	scst_dev_sysfs_del(dev);

	scst_free_device(dev);

out:
	TRACE_EXIT();
	return;

out_unlock:
	mutex_unlock(&scst_mutex);
	goto out;
}

static int scst_dev_handler_check(struct scst_dev_type *dev_handler)
{
	int res = 0;

	if (!dev_handler->parse) {
		PRINT_ERROR("scst dev handler %s must have parse() method.",
			    dev_handler->name);
		res = -EINVAL;
		goto out;
	}

	if ((dev_handler->add_device && !dev_handler->del_device) ||
	    (!dev_handler->add_device && dev_handler->del_device)) {
		PRINT_ERROR("Dev handler %s must either define both add_device() and del_device(), or none.",
			    dev_handler->name);
		res = -EINVAL;
		goto out;
	}

	if (!dev_handler->dev_alloc_data_buf)
		dev_handler->dev_alloc_data_buf_atomic = 1;

	if (!dev_handler->dev_done)
		dev_handler->dev_done_atomic = 1;

	if (dev_handler->max_tgt_dev_commands == 0)
		dev_handler->max_tgt_dev_commands = SCST_MAX_TGT_DEV_COMMANDS;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_check_device_name(const char *dev_name)
{
	int res = 0;

	if (strchr(dev_name, '/')) {
		PRINT_ERROR("Dev name %s contains illegal character '/'",
			    dev_name);
		res = -EINVAL;
		goto out;
	}

	/* To prevent collision with saved PR and mode pages backup files */
	if (strchr(dev_name, '.')) {
		PRINT_ERROR("Dev name %s contains illegal character '.'",
			    dev_name);
		res = -EINVAL;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/**
 * scst_register_virtual_device_node() - register a virtual device.
 * @dev_handler: the device's device handler
 * @dev_name:	the new device name, NULL-terminated string. Must be uniq
 *              among all virtual devices in the system.
 * @nodeid:	NUMA node id this device belongs to or NUMA_NO_NODE.
 *
 * Registers a virtual device and returns ID assigned to the device on
 * success, or negative value otherwise
 */
int scst_register_virtual_device_node(struct scst_dev_type *dev_handler, const char *dev_name,
				      int nodeid)
{
	DECLARE_COMPLETION_ONSTACK(c);
	struct scst_device *dev, *d;
	bool sysfs_del = false;
	int res;

	TRACE_ENTRY();

	if (!dev_handler) {
		PRINT_ERROR("%s: valid device handler must be supplied",
			    __func__);
		res = -EINVAL;
		goto out;
	}

	if (!dev_name) {
		PRINT_ERROR("%s: device name must be non-NULL", __func__);
		res = -EINVAL;
		goto out;
	}

	res = scst_check_device_name(dev_name);
	if (res != 0)
		goto out;

	res = scst_dev_handler_check(dev_handler);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	res = scst_alloc_device(GFP_KERNEL, nodeid, &dev);
	if (res != 0)
		goto out_unlock;

	dev->type = dev_handler->type;
	dev->scsi_dev = NULL;
	dev->virt_name = kstrdup(dev_name, GFP_KERNEL);
	if (!dev->virt_name) {
		PRINT_ERROR("Unable to allocate virt_name for dev %s",
			    dev_name);
		res = -ENOMEM;
		goto out_free_dev;
	}

	while (1) {
		dev->virt_id = scst_virt_dev_last_id++;
		if (dev->virt_id > 0)
			break;
		scst_virt_dev_last_id = 1;
	}

	res = scst_pr_set_file_name(dev, NULL, "%s/%s", SCST_PR_DIR,
				    dev->virt_name);
	if (res != 0)
		goto out_free_dev;

	res = scst_pr_init_dev(dev);
	if (res != 0)
		goto out_free_dev;

	/*
	 * We can drop scst_mutex, because we have not yet added the dev in
	 * scst_dev_list, so it "doesn't exist" yet.
	 */
	mutex_unlock(&scst_mutex);

	res = scst_dev_sysfs_create(dev);
	if (res != 0)
		goto out_lock_pr_clear_dev;

	mutex_lock(&scst_mutex);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (strcmp(d->virt_name, dev_name) == 0) {
			PRINT_ERROR("Device %s already exists", dev_name);
			res = -EEXIST;
			sysfs_del = true;
			goto out_pr_clear_dev;
		}
	}

	res = scst_assign_dev_handler(dev, dev_handler);
	if (res != 0) {
		sysfs_del = true;
		goto out_pr_clear_dev;
	}

	list_add_tail(&dev->dev_list_entry, &scst_dev_list);

	res = scst_cm_on_dev_register(dev);
	if (res != 0) {
		sysfs_del = true;
		goto out_unreg;
	}

	mutex_unlock(&scst_mutex);

	percpu_ref_get(&dev->refcnt);

	res = dev->virt_id;

	scst_event_queue_reg_vdev(dev_name);
	PRINT_INFO("Attached to virtual device %s (id %d)", dev_name, res);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg:
	dev->dev_unregistering = 1;
	list_del(&dev->dev_list_entry);
	scst_assign_dev_handler(dev, &scst_null_devtype);
	goto out_pr_clear_dev;

out_lock_pr_clear_dev:
	mutex_lock(&scst_mutex);

out_pr_clear_dev:
	scst_pr_clear_dev(dev);

out_free_dev:
	mutex_unlock(&scst_mutex);
	if (sysfs_del)
		scst_dev_sysfs_del(dev);
	dev->remove_completion = &c;
	percpu_ref_kill(&dev->refcnt);
	wait_for_completion(&c);
	scst_free_device(dev);
	goto out;

out_unlock:
	mutex_unlock(&scst_mutex);
	goto out;
}
EXPORT_SYMBOL_GPL(scst_register_virtual_device_node);

/*
 * scst_unregister_virtual_device() - unegister a virtual device.
 * @id:		the device's ID, returned by the registration function
 */
void scst_unregister_virtual_device(int id,
				    void (*on_free)(struct scst_device *dev,
						    void *arg),
				    void *arg)
{
	struct scst_device *d, *dev = NULL;
	struct scst_acg_dev *acg_dev, *aa;
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (d->virt_id == id) {
			dev = d;
			TRACE_DBG("Virtual device %p (id %d) found", dev, id);
			break;
		}
	}
	if (!dev) {
		PRINT_ERROR("Virtual device (id %d) not found", id);
		goto out_unlock;
	}

	dev->dev_unregistering = 1;

	scst_cm_on_dev_unregister(dev);

	list_del_init(&dev->dev_list_entry);

	scst_pr_clear_dev(dev);

	scst_dg_dev_remove_by_dev(dev);

	list_for_each_entry_safe(acg_dev, aa, &dev->dev_acg_dev_list,
				 dev_acg_dev_list_entry) {
		scst_acg_del_lun(acg_dev->acg, acg_dev->lun, true);
	}

	dev->remove_completion = &c;

	mutex_unlock(&scst_mutex);

	PRINT_INFO("Detached from virtual device %s (id %d)",
		   dev->virt_name, dev->virt_id);

	if (on_free)
		on_free(dev, arg);

	percpu_ref_kill(&dev->refcnt);
	percpu_ref_put(&dev->refcnt);

	wait_for_completion(&c);

	mutex_lock(&scst_mutex);
	scst_assign_dev_handler(dev, &scst_null_devtype);
	mutex_unlock(&scst_mutex);

	scst_dev_sysfs_del(dev);

	scst_free_device(dev);

out:
	TRACE_EXIT();
	return;

out_unlock:
	mutex_unlock(&scst_mutex);
	scst_resume_activity();
	goto out;
}
EXPORT_SYMBOL_GPL(scst_unregister_virtual_device);

/**
 * __scst_register_dev_driver() - register pass-through dev handler driver
 * @dev_type:	dev handler template
 * @version:	SCST_INTERFACE_VERSION version string to ensure that
 *		SCST core and the dev handler use the same version of
 *		the SCST interface
 *
 * Description:
 *    Registers a pass-through dev handler driver. Returns 0 on success
 *    or appropriate error code otherwise.
 */
int __scst_register_dev_driver(struct scst_dev_type *dev_type, const char *version)
{
	int res, exist;
	struct scst_dev_type *dt;

	TRACE_ENTRY();

	res = -EINVAL;
	if (strcmp(version, SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of dev handler %s",
			    dev_type->name);
		goto out;
	}

	res = scst_dev_handler_check(dev_type);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	exist = 0;
	list_for_each_entry(dt, &scst_dev_type_list, dev_type_list_entry) {
		if (strcmp(dt->name, dev_type->name) == 0) {
			PRINT_ERROR("Device type handler \"%s\" already exists",
				    dt->name);
			exist = 1;
			break;
		}
	}
	if (exist)
		goto out_unlock;

	list_add_tail(&dev_type->dev_type_list_entry, &scst_dev_type_list);

	mutex_unlock(&scst_mutex);

	res = scst_devt_sysfs_create(dev_type);
	if (res < 0)
		goto out;

	PRINT_INFO("Device handler \"%s\" for type %d registered successfully",
		   dev_type->name, dev_type->type);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	mutex_unlock(&scst_mutex);
	goto out;
}
EXPORT_SYMBOL_GPL(__scst_register_dev_driver);

/*
 * scst_unregister_dev_driver() - unregister pass-through dev handler driver
 */
void scst_unregister_dev_driver(struct scst_dev_type *dev_type)
{
	struct scst_device *dev;
	struct scst_dev_type *dt;
	int res, found = 0;

	TRACE_ENTRY();

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_UNLIMITED);
	WARN_ON_ONCE(res);

	mutex_lock(&scst_mutex);

	list_for_each_entry(dt, &scst_dev_type_list, dev_type_list_entry) {
		if (strcmp(dt->name, dev_type->name) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		PRINT_ERROR("Dev handler \"%s\" isn't registered",
			    dev_type->name);
		goto out_up;
	}

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		if (dev->handler == dev_type) {
			scst_assign_dev_handler(dev, &scst_null_devtype);
			TRACE_DBG("Dev handler removed from device %p", dev);
		}
	}

	list_del(&dev_type->dev_type_list_entry);

	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	scst_devt_sysfs_del(dev_type);

	PRINT_INFO("Device handler \"%s\" for type %d unloaded",
		   dev_type->name, dev_type->type);

out:
	TRACE_EXIT();
	return;

out_up:
	mutex_unlock(&scst_mutex);
	scst_resume_activity();
	goto out;
}
EXPORT_SYMBOL_GPL(scst_unregister_dev_driver);

/**
 * __scst_register_virtual_dev_driver() - register virtual dev handler driver
 * @dev_type:	dev handler template
 * @version:	SCST_INTERFACE_VERSION version string to ensure that
 *		SCST core and the dev handler use the same version of
 *		the SCST interface
 *
 * Description:
 *    Registers a virtual dev handler driver. Returns 0 on success or
 *    appropriate error code otherwise.
 */
int __scst_register_virtual_dev_driver(struct scst_dev_type *dev_type, const char *version)
{
	int res;

	TRACE_ENTRY();

	if (strcmp(version, SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of virtual dev handler %s",
			    dev_type->name);
		res = -EINVAL;
		goto out;
	}

	res = scst_dev_handler_check(dev_type);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;
	list_add_tail(&dev_type->dev_type_list_entry, &scst_virtual_dev_type_list);
	mutex_unlock(&scst_mutex);

	res = scst_devt_sysfs_create(dev_type);
	if (res < 0)
		goto out;

	if (dev_type->type != -1)
		PRINT_INFO("Virtual device handler %s for type %d registered successfully",
			   dev_type->name, dev_type->type);
	else
		PRINT_INFO("Virtual device handler \"%s\" registered successfully",
			   dev_type->name);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(__scst_register_virtual_dev_driver);

/*
 * scst_unregister_virtual_dev_driver() - unregister virtual dev driver
 */
void scst_unregister_virtual_dev_driver(struct scst_dev_type *dev_type)
{
	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	/* Disable sysfs mgmt calls (e.g. addition of new devices) */
	list_del(&dev_type->dev_type_list_entry);

	/* Wait for outstanding sysfs mgmt calls completed */
	while (dev_type->devt_active_sysfs_works_count > 0) {
		mutex_unlock(&scst_mutex);
		msleep(100);
		mutex_lock(&scst_mutex);
	}

	mutex_unlock(&scst_mutex);

	scst_devt_sysfs_del(dev_type);

	PRINT_INFO("Device handler \"%s\" unloaded", dev_type->name);

	TRACE_EXIT();
}
EXPORT_SYMBOL_GPL(scst_unregister_virtual_dev_driver);

int scst_add_threads(struct scst_cmd_threads *cmd_threads, struct scst_device *dev,
		     struct scst_tgt_dev *tgt_dev, int num)
{
	int res = 0, i;
	struct scst_cmd_thread_t *thr;
	int n = 0, tgt_dev_num = 0, nodeid = NUMA_NO_NODE;

	TRACE_ENTRY();

	if (num == 0) {
		res = 0;
		goto out;
	}

	spin_lock(&cmd_threads->thr_lock);
	n = cmd_threads->nr_threads;
	spin_unlock(&cmd_threads->thr_lock);

	TRACE_DBG("cmd_threads %p, dev %s, tgt_dev %p, num %d, n %d",
		  cmd_threads, dev ? dev->virt_name : "NULL", tgt_dev, num, n);

	if (tgt_dev) {
		struct scst_tgt_dev *t;

		list_for_each_entry(t, &tgt_dev->dev->dev_tgt_dev_list, dev_tgt_dev_list_entry) {
			if (t == tgt_dev)
				break;
			tgt_dev_num++;
		}
		tgt_dev->thread_index = tgt_dev_num;

		nodeid = tgt_dev->dev->dev_numa_node_id;
	} else if (dev) {
		nodeid = dev->dev_numa_node_id;
	}

	for (i = 0; i < num; i++) {
		thr = kmem_cache_alloc_node(scst_thr_cachep, GFP_KERNEL, nodeid);
		if (!thr) {
			res = -ENOMEM;
			PRINT_ERROR("Fail to allocate thr %d", res);
			goto out_wait;
		}
		memset(thr, 0, sizeof(*thr));
		INIT_LIST_HEAD(&thr->thr_active_cmd_list);
		spin_lock_init(&thr->thr_cmd_list_lock);
		thr->thr_cmd_threads = cmd_threads;

		if (dev) {
			thr->cmd_thread = kthread_create_on_node(scst_cmd_thread, thr, nodeid,
								 "%.13s%d", dev->virt_name, n++);
		} else if (tgt_dev) {
			thr->cmd_thread = kthread_create_on_node(scst_cmd_thread, thr, nodeid,
								 "%.10s%d_%d",
								 tgt_dev->dev->virt_name,
								 tgt_dev_num, n++);
		} else {
			thr->cmd_thread = kthread_create_on_node(scst_cmd_thread, thr, nodeid,
								 "scstd%d", n++);
		}

		if (IS_ERR(thr->cmd_thread)) {
			res = PTR_ERR(thr->cmd_thread);
			PRINT_ERROR("kthread_create() failed: %d", res);
			kfree(thr);
			goto out_wait;
		}

		if (tgt_dev) {
			int rc;
			/*
			 * sess->acg can be NULL here, if called from
			 * scst_check_reassign_sess()!
			 */
			rc = set_cpus_allowed_ptr(thr->cmd_thread,
						  &tgt_dev->acg_dev->acg->acg_cpu_mask);
			if (rc != 0)
				PRINT_ERROR("Setting CPU affinity failed: %d",
					    rc);
		}

		spin_lock(&cmd_threads->thr_lock);
		list_add(&thr->thread_list_entry, &cmd_threads->threads_list);
		cmd_threads->nr_threads++;
		spin_unlock(&cmd_threads->thr_lock);

		TRACE_DBG("Added thr %p to threads list (nr_threads %d, n %d)",
			  thr, cmd_threads->nr_threads, n);

		wake_up_process(thr->cmd_thread);
	}

out_wait:
	if (i > 0 && cmd_threads != &scst_main_cmd_threads) {
		/*
		 * Wait for io_context gets initialized to avoid possible races
		 * for it from the sharing it tgt_devs.
		 */
		wait_event(cmd_threads->ioctx_wq,
			   cmd_threads->io_context_ready);
		smp_rmb();
	}

	if (res != 0)
		scst_del_threads(cmd_threads, i);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * The being stopped threads must not have assigned commands, which usually
 * means suspended activities.
 */
void scst_del_threads(struct scst_cmd_threads *cmd_threads, int num)
{
	TRACE_ENTRY();

	for ( ; num != 0; num--) {
		struct scst_cmd_thread_t *ct = NULL, *ct2;
		int rc;

		spin_lock(&cmd_threads->thr_lock);
		list_for_each_entry_reverse(ct2, &cmd_threads->threads_list,
					    thread_list_entry) {
			if (!ct2->being_stopped) {
				ct = ct2;
				list_del(&ct->thread_list_entry);
				ct->being_stopped = true;
				cmd_threads->nr_threads--;
				break;
			}
		}
		spin_unlock(&cmd_threads->thr_lock);

		if (!ct)
			break;

		rc = kthread_stop(ct->cmd_thread);
		if (rc != 0 && rc != -EINTR)
			TRACE_MGMT_DBG("kthread_stop() failed: %d", rc);

		kmem_cache_free(scst_thr_cachep, ct);
	}

	EXTRACHECKS_BUG_ON((cmd_threads->nr_threads == 0) && cmd_threads->io_context);

	TRACE_EXIT();
}

/* scst_mutex supposed to be held */
int scst_set_thr_cpu_mask(struct scst_cmd_threads *cmd_threads,
			  cpumask_t *cpu_mask)
{
	struct scst_cmd_thread_t *thr;
	int rc = 0;

	spin_lock(&cmd_threads->thr_lock);
	list_for_each_entry(thr, &cmd_threads->threads_list,
			    thread_list_entry) {
		rc = set_cpus_allowed_ptr(thr->cmd_thread, cpu_mask);
		if (rc)
			break;
	}
	spin_unlock(&cmd_threads->thr_lock);

	return rc;
}
EXPORT_SYMBOL(scst_set_thr_cpu_mask);

/* The activity supposed to be suspended and scst_mutex held */
void scst_stop_dev_threads(struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list, dev_tgt_dev_list_entry)
		scst_tgt_dev_stop_threads(tgt_dev);

	if (dev->threads_num > 0 && dev->threads_pool_type == SCST_THREADS_POOL_SHARED)
		scst_del_threads(&dev->dev_cmd_threads, -1);

	TRACE_EXIT();
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_create_dev_threads(struct scst_device *dev)
{
	int res = 0;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list, dev_tgt_dev_list_entry) {
		res = scst_tgt_dev_setup_threads(tgt_dev);
		if (res != 0)
			goto out_err;
	}

	if (dev->threads_num > 0 && dev->threads_pool_type == SCST_THREADS_POOL_SHARED) {
		res = scst_add_threads(&dev->dev_cmd_threads, dev, NULL, dev->threads_num);
		if (res != 0)
			goto out_err;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	scst_stop_dev_threads(dev);
	goto out;
}

/*
 * The caller must hold scst_mutex. No commands must be in progress for @dev.
 * There are two ways to achieve this: either make sure no device handler is
 * assigned before this function is called or remove all associated LUNs and
 * wait until the commands associated with these LUNs have finished before this
 * function is called.
 */
int scst_assign_dev_handler(struct scst_device *dev, struct scst_dev_type *handler)
{
	int res = 0;
	struct scst_tgt_dev *tgt_dev;
	LIST_HEAD(attached_tgt_devs);

	TRACE_ENTRY();

	lockdep_assert_held(&scst_mutex);

	sBUG_ON(!handler);

	if (dev->handler == handler)
		goto out;

	if (!dev->handler)
		goto assign;

	if (dev->handler->detach_tgt) {
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list, dev_tgt_dev_list_entry) {
			TRACE_DBG("Calling dev handler's detach_tgt(%p)",
				  tgt_dev);
			dev->handler->detach_tgt(tgt_dev);
			TRACE_DBG("Dev handler's detach_tgt() returned");
		}
	}

	/*
	 * devt_dev sysfs must be created AFTER attach() and deleted BEFORE
	 * detach() to avoid calls from sysfs for not yet ready or already dead
	 * objects.
	 */
	scst_devt_dev_sysfs_del(dev);

	if (dev->handler->detach) {
		TRACE_DBG("Calling dev handler's detach()");
		dev->handler->detach(dev);
		TRACE_DBG("Old handler's detach() returned");
	}

	scst_stop_dev_threads(dev);

assign:
	dev->handler = handler;
	dev->threads_num = handler->threads_num;
	dev->threads_pool_type = handler->threads_pool_type;
	dev->max_tgt_dev_commands = handler->max_tgt_dev_commands;
	dev->max_write_same_len = 256 * 1024 * 1024; /* 256 MB */

	if (handler->attach) {
		TRACE_DBG("Calling new dev handler's attach(%p)", dev);
		res = handler->attach(dev);
		TRACE_DBG("New dev handler's attach() returned %d", res);
		if (res != 0) {
			PRINT_ERROR("New device handler's %s attach() failed: %d",
				    handler->name, res);
			goto out;
		}
	}

	res = scst_devt_dev_sysfs_create(dev);
	if (res != 0)
		goto out_detach;

	if (handler->attach_tgt) {
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list, dev_tgt_dev_list_entry) {
			TRACE_DBG("Calling dev handler's attach_tgt(%p)",
				  tgt_dev);
			res = handler->attach_tgt(tgt_dev);
			TRACE_DBG("Dev handler's attach_tgt() returned");
			if (res != 0) {
				PRINT_ERROR("Device handler's %s attach_tgt() failed: %d",
					    handler->name, res);
				goto out_err_detach_tgt;
			}
			list_add_tail(&tgt_dev->extra_tgt_dev_list_entry, &attached_tgt_devs);
		}
	}

	res = scst_create_dev_threads(dev);
	if (res != 0)
		goto out_err_detach_tgt;

out:
	TRACE_EXIT_RES(res);
	return res;

out_err_detach_tgt:
	if (handler->detach_tgt) {
		list_for_each_entry(tgt_dev, &attached_tgt_devs, extra_tgt_dev_list_entry) {
			TRACE_DBG("Calling handler's detach_tgt(%p)",
				  tgt_dev);
			handler->detach_tgt(tgt_dev);
			TRACE_DBG("Handler's detach_tgt() returned");
		}
	}

	scst_devt_dev_sysfs_del(dev);

out_detach:
	if (handler->detach) {
		TRACE_DBG("Calling handler's detach()");
		handler->detach(dev);
		TRACE_DBG("Handler's detach() returned");
	}

	dev->handler = &scst_null_devtype;
	dev->threads_num = scst_null_devtype.threads_num;
	dev->threads_pool_type = scst_null_devtype.threads_pool_type;
	goto out;
}

/*
 * scst_init_threads() - initialize SCST processing threads pool
 *
 * Initializes scst_cmd_threads structure
 */
void scst_init_threads(struct scst_cmd_threads *cmd_threads)
{
	TRACE_ENTRY();

	spin_lock_init(&cmd_threads->cmd_list_lock);
	INIT_LIST_HEAD(&cmd_threads->active_cmd_list);
	init_waitqueue_head(&cmd_threads->cmd_list_waitQ);
	init_waitqueue_head(&cmd_threads->ioctx_wq);
	INIT_LIST_HEAD(&cmd_threads->threads_list);
	mutex_init(&cmd_threads->io_context_mutex);
	spin_lock_init(&cmd_threads->thr_lock);

	mutex_lock(&scst_cmd_threads_mutex);
	list_add_tail(&cmd_threads->lists_list_entry, &scst_cmd_threads_list);
	mutex_unlock(&scst_cmd_threads_mutex);

	TRACE_EXIT();
}
EXPORT_SYMBOL_GPL(scst_init_threads);

/*
 * scst_deinit_threads() - deinitialize SCST processing threads pool
 *
 * Deinitializes scst_cmd_threads structure
 */
void scst_deinit_threads(struct scst_cmd_threads *cmd_threads)
{
	TRACE_ENTRY();

	mutex_lock(&scst_cmd_threads_mutex);
	list_del(&cmd_threads->lists_list_entry);
	mutex_unlock(&scst_cmd_threads_mutex);

	sBUG_ON(cmd_threads->io_context);

	TRACE_EXIT();
}
EXPORT_SYMBOL_GPL(scst_deinit_threads);

static void scst_stop_global_threads(void)
{
	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	scst_del_threads(&scst_main_cmd_threads, -1);

	if (scst_mgmt_cmd_thread)
		kthread_stop(scst_mgmt_cmd_thread);
	if (scst_mgmt_thread)
		kthread_stop(scst_mgmt_thread);
	if (scst_init_cmd_thread)
		kthread_stop(scst_init_cmd_thread);

	mutex_unlock(&scst_mutex);

	TRACE_EXIT();
}

/* It does NOT stop ran threads on error! */
static int scst_start_global_threads(int num)
{
	int res;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	res = scst_add_threads(&scst_main_cmd_threads, NULL, NULL, num);
	if (res < 0)
		goto out_unlock;

	scst_init_cmd_thread = kthread_run(scst_init_thread, NULL, "scst_initd");
	if (IS_ERR(scst_init_cmd_thread)) {
		res = PTR_ERR(scst_init_cmd_thread);
		PRINT_ERROR("kthread_create() for init cmd failed: %d", res);
		scst_init_cmd_thread = NULL;
		goto out_unlock;
	}

	scst_mgmt_cmd_thread = kthread_run(scst_tm_thread, NULL, "scsi_tm");
	if (IS_ERR(scst_mgmt_cmd_thread)) {
		res = PTR_ERR(scst_mgmt_cmd_thread);
		PRINT_ERROR("kthread_create() for TM failed: %d", res);
		scst_mgmt_cmd_thread = NULL;
		goto out_unlock;
	}

	scst_mgmt_thread = kthread_run(scst_global_mgmt_thread, NULL, "scst_mgmtd");
	if (IS_ERR(scst_mgmt_thread)) {
		res = PTR_ERR(scst_mgmt_thread);
		PRINT_ERROR("kthread_create() for mgmt failed: %d", res);
		scst_mgmt_thread = NULL;
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&scst_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

/**
 * scst_get_setup_id() - return SCST setup ID
 *
 * Returns SCST setup ID. This ID can be used for multiple
 * setups with the same configuration.
 */
unsigned int scst_get_setup_id(void)
{
	return scst_setup_id;
}
EXPORT_SYMBOL_GPL(scst_get_setup_id);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 4))
static int scst_add(struct device *cdev, struct class_interface *intf)
#else
static int scst_add(struct device *cdev)
#endif
{
	struct scsi_device *scsidp;
	int res = 0;

	TRACE_ENTRY();

	scsidp = to_scsi_device(cdev->parent);

	if (!scsidp->host->hostt->name ||
	    (strcmp(scsidp->host->hostt->name, SCST_LOCAL_NAME) != 0))
		res = scst_register_device(scsidp);

	TRACE_EXIT();
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 4))
static void scst_remove(struct device *cdev, struct class_interface *intf)
#else
static void scst_remove(struct device *cdev)
#endif
{
	struct scsi_device *scsidp;

	TRACE_ENTRY();

	scsidp = to_scsi_device(cdev->parent);

	if (!scsidp->host->hostt->name ||
	    (strcmp(scsidp->host->hostt->name, SCST_LOCAL_NAME) != 0))
		scst_unregister_device(scsidp);

	TRACE_EXIT();
}

static struct class_interface scst_interface = {
	.add_dev = scst_add,
	.remove_dev = scst_remove,
};

bool scst_dump_config(char *buf, size_t len)
{
	ssize_t ret, pos;

	ret = scnprintf(buf, len, "SCST config: ");
	pos = ret;

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	ret += scnprintf(buf + ret, len - ret, "%sSTRICT_SERIALIZING",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_EXTRACHECKS
	ret += scnprintf(buf + ret, len - ret, "%sEXTRACHECKS",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_TRACING
	ret += scnprintf(buf + ret, len - ret, "%sTRACING",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG
	ret += scnprintf(buf + ret, len - ret, "%sDEBUG",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_TM
	ret += scnprintf(buf + ret, len - ret, "%sDEBUG_TM",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_RETRY
	ret += scnprintf(buf + ret, len - ret, "%sDEBUG_RETRY",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_OOM
	ret += scnprintf(buf + ret, len - ret, "%sDEBUG_OOM",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_SN
	ret += scnprintf(buf + ret, len - ret, "%sDEBUG_SN",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
	ret += scnprintf(buf + ret, len - ret, "%sUSE_EXPECTED_VALUES",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
	ret += scnprintf(buf + ret, len - ret, "%sTEST_IO_IN_SIRQ",
			 ret == pos ? "" : ", ");
#endif

#ifdef CONFIG_SCST_STRICT_SECURITY
	ret += scnprintf(buf + ret, len - ret, "%sSTRICT_SECURITY",
			 ret == pos ? "" : ", ");
#endif

	return ret != pos;
}

static inline void __init scst_print_config(void)
{
	char config[SCST_CONFIG_BUF_SIZE] = {};

	if (scst_dump_config(config, sizeof(config)))
		PRINT_INFO("%s", config);
}

static void scst_suspended(struct percpu_ref *ref)
{
	WARN_ON_ONCE(ref != &scst_cmd_count && ref != &scst_mcmd_count);
	percpu_ref_killed = true;
	wake_up_all(&scst_dev_cmd_waitQ);
}

static int __init init_scst(void)
{
	int res, i;
	int scst_num_cpus;

	TRACE_ENTRY();

	{
		struct scsi_sense_hdr *shdr;
		struct scst_order_data *o;
		struct scst_cmd *c;

		BUILD_BUG_ON(sizeof(*shdr) > SCST_SENSE_BUFFERSIZE);
		BUILD_BUG_ON(sizeof(o->curr_sn) != sizeof(o->expected_sn));
		BUILD_BUG_ON(sizeof(c->sn) != sizeof(o->expected_sn));
	}

	mutex_init(&scst_mutex);
	mutex_init(&scst_mutex2);
	INIT_LIST_HEAD(&scst_template_list);
	INIT_LIST_HEAD(&scst_dev_list);
	INIT_LIST_HEAD(&scst_dev_type_list);
	INIT_LIST_HEAD(&scst_virtual_dev_type_list);
	spin_lock_init(&scst_init_lock);
	init_waitqueue_head(&scst_init_cmd_list_waitQ);
	INIT_LIST_HEAD(&scst_init_cmd_list);
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	scst_trace_flag = SCST_DEFAULT_LOG_FLAGS;
#endif
	spin_lock_init(&scst_mcmd_lock);
	INIT_LIST_HEAD(&scst_active_mgmt_cmd_list);
	INIT_LIST_HEAD(&scst_delayed_mgmt_cmd_list);
	init_waitqueue_head(&scst_mgmt_cmd_list_waitQ);
	init_waitqueue_head(&scst_mgmt_waitQ);
	spin_lock_init(&scst_mgmt_lock);
	INIT_LIST_HEAD(&scst_sess_init_list);
	INIT_LIST_HEAD(&scst_sess_shut_list);
	init_waitqueue_head(&scst_dev_cmd_waitQ);
	mutex_init(&scst_suspend_mutex);
	mutex_init(&scst_cmd_threads_mutex);
	INIT_LIST_HEAD(&scst_cmd_threads_list);
	cpumask_setall(&default_cpu_mask);
	spin_lock_init(&scst_measure_latency_lock);

	scst_init_threads(&scst_main_cmd_threads);

	res = scst_lib_init();
	if (res != 0)
		goto out_deinit_threads;

	scst_num_cpus = num_online_cpus();

	/* ToDo: register_cpu_notifier() */

	if (scst_threads == 0)
		scst_threads = scst_num_cpus;

	if (scst_threads < 1) {
		PRINT_ERROR("scst_threads can not be less than 1");
		scst_threads = scst_num_cpus;
	}

/* Used for rarely used or read-mostly on fast path structures */
#define INIT_CACHEP(p, s) ({						\
		(p) = KMEM_CACHE(s, SCST_SLAB_FLAGS);			\
		TRACE_MEM("Slab create: %s at %p size %zd", #s, (p),	\
			  sizeof(struct s));				\
		(p);							\
	})

#define INIT_CACHEP_USERCOPY(p, s, f) ({				\
		(p) = KMEM_CACHE_USERCOPY(s, SCST_SLAB_FLAGS, f);	\
		TRACE_MEM("Slab create: %s at %p size %zd", #s, (p),	\
			  sizeof(struct s));				\
		(p);							\
	})

/* Used for structures with fast path write access */
#define INIT_CACHEP_ALIGN(p, s) ({					\
		(p) = KMEM_CACHE(s,					\
				 SCST_SLAB_FLAGS | SLAB_HWCACHE_ALIGN);	\
		TRACE_MEM("Slab create: %s at %p size %zd", #s, (p),	\
			  sizeof(struct s));				\
		(p);							\
	})
#define INIT_CACHEP_ALIGN_USERCOPY(p, s, f) ({				\
		(p) = KMEM_CACHE_USERCOPY(s, SCST_SLAB_FLAGS |		\
					  SLAB_HWCACHE_ALIGN, f);	\
		TRACE_MEM("Slab create: %s at %p size %zd", #s, (p),	\
			  sizeof(struct s));				\
		(p);							\
	})

	res = -ENOMEM;
	if (!INIT_CACHEP(scst_mgmt_cachep, scst_mgmt_cmd))
		goto out_lib_exit;
	if (!INIT_CACHEP(scst_mgmt_stub_cachep, scst_mgmt_cmd_stub))
		goto out_destroy_mgmt_cache;
	if (!INIT_CACHEP(scst_ua_cachep, scst_tgt_dev_UA))
		goto out_destroy_mgmt_stub_cache;
	{
		struct scst_sense { uint8_t s[SCST_SENSE_BUFFERSIZE]; };
		if (!INIT_CACHEP_USERCOPY(scst_sense_cachep, scst_sense, s))
			goto out_destroy_ua_cache;
	}
	if (!INIT_CACHEP(scst_aen_cachep, scst_aen)) /* read-mostly */
		goto out_destroy_sense_cache;
	if (!INIT_CACHEP_ALIGN_USERCOPY(scst_cmd_cachep, scst_cmd, cdb_buf))
		goto out_destroy_aen_cache;
	/* Big enough with read-mostly head and tail */
	if (!INIT_CACHEP(scst_sess_cachep, scst_session))
		goto out_destroy_cmd_cache;
	if (!INIT_CACHEP(scst_dev_cachep, scst_device)) /* big enough */
		goto out_destroy_sess_cache;
	if (!INIT_CACHEP(scst_tgt_cachep, scst_tgt)) /* read-mostly */
		goto out_destroy_dev_cache;
	/* Big enough with read-mostly head and tail */
	if (!INIT_CACHEP(scst_tgtd_cachep, scst_tgt_dev)) /* big enough */
		goto out_destroy_tgt_cache;
	if (!INIT_CACHEP(scst_acgd_cachep, scst_acg_dev)) /* read-mostly */
		goto out_destroy_tgtd_cache;
	if (!INIT_CACHEP_ALIGN(scst_thr_cachep, scst_cmd_thread_t))
		goto out_destroy_acg_cache;

	scst_mgmt_mempool = mempool_create(64, mempool_alloc_slab, mempool_free_slab,
					   scst_mgmt_cachep);
	if (!scst_mgmt_mempool) {
		res = -ENOMEM;
		goto out_destroy_thr_cache;
	}

	/*
	 * All mgmt stubs, UAs and sense buffers are bursty and losing them
	 * may have fatal consequences, so let's have big pools for them.
	 */

	scst_mgmt_stub_mempool = mempool_create(1024, mempool_alloc_slab, mempool_free_slab,
						scst_mgmt_stub_cachep);
	if (!scst_mgmt_stub_mempool) {
		res = -ENOMEM;
		goto out_destroy_mgmt_mempool;
	}

	scst_ua_mempool = mempool_create(512, mempool_alloc_slab, mempool_free_slab,
					 scst_ua_cachep);
	if (!scst_ua_mempool) {
		res = -ENOMEM;
		goto out_destroy_mgmt_stub_mempool;
	}

	scst_sense_mempool = mempool_create(1024, mempool_alloc_slab, mempool_free_slab,
					    scst_sense_cachep);
	if (!scst_sense_mempool) {
		res = -ENOMEM;
		goto out_destroy_ua_mempool;
	}

	scst_aen_mempool = mempool_create(100, mempool_alloc_slab, mempool_free_slab,
					  scst_aen_cachep);
	if (!scst_aen_mempool) {
		res = -ENOMEM;
		goto out_destroy_sense_mempool;
	}

	res = scst_event_init();
	if (res != 0)
		goto out_destroy_aen_mempool;

	res = scst_sysfs_init();
	if (res != 0)
		goto out_event_exit;

	scst_tg_init();

	if (scst_max_cmd_mem == 0) {
		struct sysinfo si;

		si_meminfo(&si);
#if BITS_PER_LONG == 32
		scst_max_cmd_mem = min((((uint64_t)(si.totalram - si.totalhigh) << PAGE_SHIFT) >> 20) >> 2,
				       (uint64_t)1 << 30);
#else
		scst_max_cmd_mem = (((si.totalram - si.totalhigh) << PAGE_SHIFT) >> 20) >> 2;
#endif
	}

	if (scst_max_dev_cmd_mem != 0) {
		if (scst_max_dev_cmd_mem > scst_max_cmd_mem) {
			PRINT_ERROR("scst_max_dev_cmd_mem (%d) > scst_max_cmd_mem (%d)",
				    scst_max_dev_cmd_mem, scst_max_cmd_mem);
			scst_max_dev_cmd_mem = scst_max_cmd_mem;
		}
	} else {
		scst_max_dev_cmd_mem = scst_max_cmd_mem * 2 / 5;
	}

	res = scst_sgv_pools_init(((uint64_t)scst_max_cmd_mem << 10) >> (PAGE_SHIFT - 10), 0);
	if (res != 0)
		goto out_sysfs_cleanup;

	res = scsi_register_interface(&scst_interface);
	if (res != 0)
		goto out_destroy_sgv_pool;

	res = percpu_ref_init(&scst_cmd_count, scst_suspended,
			      PERCPU_REF_ALLOW_REINIT, GFP_KERNEL);
	if (res != 0)
		goto out_unreg_interface;

	res = percpu_ref_init(&scst_mcmd_count, scst_suspended,
			      PERCPU_REF_ALLOW_REINIT, GFP_KERNEL);
	if (res != 0)
		goto out_cmd_count;

	for (i = 0; i < ARRAY_SIZE(scst_percpu_infos); i++) {
		spin_lock_init(&scst_percpu_infos[i].tasklet_lock);
		INIT_LIST_HEAD(&scst_percpu_infos[i].tasklet_cmd_list);
		tasklet_init(&scst_percpu_infos[i].tasklet,
			     (void *)scst_cmd_tasklet,
			     (unsigned long)&scst_percpu_infos[i]);
	}

	TRACE_DBG("%d CPUs found, starting %d threads",
		  scst_num_cpus, scst_threads);

	res = scst_start_global_threads(scst_threads);
	if (res < 0)
		goto out_thread_free;

	res = scst_cm_init();
	if (res != 0)
		goto out_thread_free;

#ifdef CONFIG_SCST_NO_TOTAL_MEM_CHECKS
	PRINT_INFO("SCST loaded successfully (global max mem for commands ignored, per device %dMB)",
		   scst_max_dev_cmd_mem);
#else
	PRINT_INFO("SCST loaded successfully (max mem for commands %dMB, per device %dMB)",
		   scst_max_cmd_mem, scst_max_dev_cmd_mem);
#endif
	PRINT_INFO("SCST version: %s", SCST_VERSION_STRING);
	PRINT_INFO("SCST build date: %s", SCST_BUILD_DATE_STRING);
	PRINT_INFO("SCST build number: %s", SCST_BUILD_NUMBER_STRING);
	PRINT_INFO("SCST git commit sha1: %s", SCST_GIT_COMMIT_STRING);
	PRINT_INFO("SCST kver: %s", SCST_KVER_STRING);
	PRINT_INFO("SCST arch type: %s", SCST_ARCH_TYPE_STRING);
	scst_print_config();

out:
	TRACE_EXIT_RES(res);
	return res;

out_thread_free:
	scst_stop_global_threads();
	percpu_ref_exit(&scst_mcmd_count);

out_cmd_count:
	percpu_ref_exit(&scst_cmd_count);

out_unreg_interface:
	scsi_unregister_interface(&scst_interface);

out_destroy_sgv_pool:
	scst_sgv_pools_deinit();
	scst_tg_cleanup();

out_sysfs_cleanup:
	scst_sysfs_cleanup();

out_event_exit:
	scst_event_exit();

out_destroy_aen_mempool:
	mempool_destroy(scst_aen_mempool);

out_destroy_sense_mempool:
	mempool_destroy(scst_sense_mempool);

out_destroy_ua_mempool:
	mempool_destroy(scst_ua_mempool);

out_destroy_mgmt_stub_mempool:
	mempool_destroy(scst_mgmt_stub_mempool);

out_destroy_mgmt_mempool:
	mempool_destroy(scst_mgmt_mempool);

out_destroy_thr_cache:
	kmem_cache_destroy(scst_thr_cachep);

out_destroy_acg_cache:
	kmem_cache_destroy(scst_acgd_cachep);

out_destroy_tgtd_cache:
	kmem_cache_destroy(scst_tgtd_cachep);

out_destroy_tgt_cache:
	kmem_cache_destroy(scst_tgt_cachep);

out_destroy_dev_cache:
	kmem_cache_destroy(scst_dev_cachep);

out_destroy_sess_cache:
	kmem_cache_destroy(scst_sess_cachep);

out_destroy_cmd_cache:
	kmem_cache_destroy(scst_cmd_cachep);

out_destroy_aen_cache:
	kmem_cache_destroy(scst_aen_cachep);

out_destroy_sense_cache:
	kmem_cache_destroy(scst_sense_cachep);

out_destroy_ua_cache:
	kmem_cache_destroy(scst_ua_cachep);

out_destroy_mgmt_stub_cache:
	kmem_cache_destroy(scst_mgmt_stub_cachep);

out_destroy_mgmt_cache:
	kmem_cache_destroy(scst_mgmt_cachep);

out_lib_exit:
	scst_lib_exit();

out_deinit_threads:
	scst_deinit_threads(&scst_main_cmd_threads);
	goto out;
}

static void __exit exit_scst(void)
{
	TRACE_ENTRY();

	/* ToDo: unregister_cpu_notifier() */

	scst_cm_exit();

	scst_stop_global_threads();

	scst_deinit_threads(&scst_main_cmd_threads);

	percpu_ref_exit(&scst_mcmd_count);
	percpu_ref_exit(&scst_cmd_count);

	scsi_unregister_interface(&scst_interface);

	scst_sgv_pools_deinit();

	scst_tg_cleanup();

	scst_sysfs_cleanup();

	kfree(scst_cluster_name);

	scst_event_exit();

	rcu_barrier();

#define DEINIT_CACHEP(p) do {		\
		kmem_cache_destroy(p);	\
		p = NULL;		\
	} while (0)

	mempool_destroy(scst_mgmt_mempool);
	mempool_destroy(scst_mgmt_stub_mempool);
	mempool_destroy(scst_ua_mempool);
	mempool_destroy(scst_sense_mempool);
	mempool_destroy(scst_aen_mempool);

	DEINIT_CACHEP(scst_mgmt_cachep);
	DEINIT_CACHEP(scst_mgmt_stub_cachep);
	DEINIT_CACHEP(scst_ua_cachep);
	DEINIT_CACHEP(scst_sense_cachep);
	DEINIT_CACHEP(scst_aen_cachep);
	DEINIT_CACHEP(scst_cmd_cachep);
	DEINIT_CACHEP(scst_sess_cachep);
	DEINIT_CACHEP(scst_tgtd_cachep);
	DEINIT_CACHEP(scst_dev_cachep);
	DEINIT_CACHEP(scst_tgt_cachep);
	DEINIT_CACHEP(scst_acgd_cachep);
	DEINIT_CACHEP(scst_thr_cachep);

	scst_lib_exit();

	PRINT_INFO("SCST unloaded");

	TRACE_EXIT();
}

module_init(init_scst);
module_exit(exit_scst);

MODULE_AUTHOR("Vladislav Bolkhovitin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI target core");
MODULE_VERSION(SCST_VERSION_STRING);
MODULE_INFO(build_date, SCST_BUILD_DATE_STRING);
MODULE_INFO(build_number, SCST_BUILD_NUMBER_STRING);
MODULE_INFO(git_commit, SCST_GIT_COMMIT_STRING);
MODULE_INFO(kver, SCST_KVER_STRING);
MODULE_INFO(arch_type, SCST_ARCH_TYPE_STRING);
