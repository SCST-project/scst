/*
 *  scst_main.c
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

#include "scst.h"
#include "scst_priv.h"
#include "scst_mem.h"

#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
#warning "HIGHMEM kernel configurations are fully supported, but not \
	recommended for performance reasons. Consider change VMSPLIT \
	option or use 64-bit configuration instead. See README file for \
	details."
#endif

#ifdef CONFIG_SCST_HIGHMEM
#error "CONFIG_SCST_HIGHMEM configuration isn't supported and broken, because\
        there is no real point to support it, at least it definitely isn't   \
        worth the effort. Better use no-HIGHMEM kernel with VMSPLIT option   \
	or in 64-bit configuration instead. See README file for details."
#endif

#if !defined(SCSI_EXEC_REQ_FIFO_DEFINED) && !defined(CONFIG_SCST_STRICT_SERIALIZING)
#warning "Patch scst_exec_req_fifo-<kernel-version>.patch was not applied on \
	your kernel and CONFIG_SCST_STRICT_SERIALIZING isn't defined. Pass-through dev \
	handlers will not be supported."
#endif

/**
 ** SCST global variables. They are all uninitialized to have their layout in
 ** memory be exactly as specified. Otherwise compiler puts zero-initialized
 ** variable separately from nonzero-initialized ones.
 **/

/*
 * All targets, devices and dev_types management is done under this mutex.
 *
 * It must NOT be used in any works (schedule_work(), etc.), because
 * otherwise a deadlock (double lock, actually) is possible, e.g., with
 * scst_user detach_tgt(), which is called under scst_mutex and calls
 * flush_scheduled_work().
 */
struct mutex scst_mutex;

struct list_head scst_template_list;
struct list_head scst_dev_list;
struct list_head scst_dev_type_list;

spinlock_t scst_main_lock;

struct kmem_cache *scst_mgmt_cachep;
mempool_t *scst_mgmt_mempool;
struct kmem_cache *scst_mgmt_stub_cachep;
mempool_t *scst_mgmt_stub_mempool;
struct kmem_cache *scst_ua_cachep;
mempool_t *scst_ua_mempool;
struct kmem_cache *scst_sense_cachep;
mempool_t *scst_sense_mempool;
struct kmem_cache *scst_tgtd_cachep;
struct kmem_cache *scst_sess_cachep;
struct kmem_cache *scst_acgd_cachep;

struct list_head scst_acg_list;
struct scst_acg *scst_default_acg;

spinlock_t scst_init_lock;
wait_queue_head_t scst_init_cmd_list_waitQ;
struct list_head scst_init_cmd_list;
unsigned int scst_init_poll_cnt;

struct kmem_cache *scst_cmd_cachep;

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
unsigned long scst_trace_flag;
#endif

unsigned long scst_flags;
atomic_t scst_cmd_count;

struct scst_cmd_lists scst_main_cmd_lists;

struct scst_tasklet scst_tasklets[NR_CPUS];

spinlock_t scst_mcmd_lock;
struct list_head scst_active_mgmt_cmd_list;
struct list_head scst_delayed_mgmt_cmd_list;
wait_queue_head_t scst_mgmt_cmd_list_waitQ;

wait_queue_head_t scst_mgmt_waitQ;
spinlock_t scst_mgmt_lock;
struct list_head scst_sess_init_list;
struct list_head scst_sess_shut_list;

wait_queue_head_t scst_dev_cmd_waitQ;

struct mutex scst_suspend_mutex;
struct list_head scst_cmd_lists_list;

static int scst_threads;
struct scst_threads_info_t scst_threads_info;

static int suspend_count;

static int scst_virt_dev_last_id; /* protected by scst_mutex */

/*
 * This buffer and lock are intended to avoid memory allocation, which
 * could fail in improper places.
 */
spinlock_t scst_temp_UA_lock;
uint8_t scst_temp_UA[SCST_SENSE_BUFFERSIZE];

unsigned int scst_max_cmd_mem;
unsigned int scst_max_dev_cmd_mem;

module_param_named(scst_threads, scst_threads, int, 0);
MODULE_PARM_DESC(scst_threads, "SCSI target threads count");

module_param_named(scst_max_cmd_mem, scst_max_cmd_mem, int, 0);
MODULE_PARM_DESC(scst_max_cmd_mem, "Maximum memory allowed to be consumed by "
	"all SCSI commands of all devices at any given time in MB");

module_param_named(scst_max_dev_cmd_mem, scst_max_dev_cmd_mem, int, 0);
MODULE_PARM_DESC(scst_max_dev_cmd_mem, "Maximum memory allowed to be consumed "
	"by all SCSI commands of a device at any given time in MB");

struct scst_dev_type scst_null_devtype = {
	.name = "none",
};

static void __scst_resume_activity(void);

int __scst_register_target_template(struct scst_tgt_template *vtt,
	const char *version)
{
	int res = 0;
	struct scst_tgt_template *t;
	static DEFINE_MUTEX(m);

	TRACE_ENTRY();

	INIT_LIST_HEAD(&vtt->tgt_list);

	if (strcmp(version, SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of target %s", vtt->name);
		res = -EINVAL;
		goto out_err;
	}

	if (!vtt->detect) {
		PRINT_ERROR("Target driver %s doesn't have a "
			"detect() method.", vtt->name);
		res = -EINVAL;
		goto out_err;
	}

	if (!vtt->release) {
		PRINT_ERROR("Target driver %s doesn't have a "
			"release() method.", vtt->name);
		res = -EINVAL;
		goto out_err;
	}

	if (!vtt->xmit_response) {
		PRINT_ERROR("Target driver %s doesn't have a "
			"xmit_response() method.", vtt->name);
		res = -EINVAL;
		goto out_err;
	}

	if (vtt->threads_num < 0) {
		PRINT_ERROR("Wrong threads_num value %d for "
			"target \"%s\"", vtt->threads_num,
			vtt->name);
		res = -EINVAL;
		goto out_err;
	}

	if (!vtt->no_proc_entry) {
		res = scst_build_proc_target_dir_entries(vtt);
		if (res < 0)
			goto out_err;
	}

	if (mutex_lock_interruptible(&m) != 0)
		goto out_err;

	if (mutex_lock_interruptible(&scst_mutex) != 0)
		goto out_m_up;
	list_for_each_entry(t, &scst_template_list, scst_template_list_entry) {
		if (strcmp(t->name, vtt->name) == 0) {
			PRINT_ERROR("Target driver %s already registered",
				vtt->name);
			mutex_unlock(&scst_mutex);
			goto out_cleanup;
		}
	}
	mutex_unlock(&scst_mutex);

	TRACE_DBG("%s", "Calling target driver's detect()");
	res = vtt->detect(vtt);
	TRACE_DBG("Target driver's detect() returned %d", res);
	if (res < 0) {
		PRINT_ERROR("%s", "The detect() routine failed");
		res = -EINVAL;
		goto out_cleanup;
	}

	mutex_lock(&scst_mutex);
	list_add_tail(&vtt->scst_template_list_entry, &scst_template_list);
	mutex_unlock(&scst_mutex);

	res = 0;

	PRINT_INFO("Target template %s registered successfully", vtt->name);

	mutex_unlock(&m);

out:
	TRACE_EXIT_RES(res);
	return res;

out_cleanup:
	scst_cleanup_proc_target_dir_entries(vtt);

out_m_up:
	mutex_unlock(&m);

out_err:
	PRINT_ERROR("Failed to register target template %s", vtt->name);
	goto out;
}
EXPORT_SYMBOL(__scst_register_target_template);

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
		goto out_up;
	}

restart:
	list_for_each_entry(tgt, &vtt->tgt_list, tgt_list_entry) {
		mutex_unlock(&scst_mutex);
		scst_unregister(tgt);
		mutex_lock(&scst_mutex);
		goto restart;
	}
	list_del(&vtt->scst_template_list_entry);

	PRINT_INFO("Target template %s unregistered successfully", vtt->name);

out_up:
	mutex_unlock(&scst_mutex);

	scst_cleanup_proc_target_dir_entries(vtt);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_unregister_target_template);

struct scst_tgt *scst_register(struct scst_tgt_template *vtt,
	const char *target_name)
{
	struct scst_tgt *tgt;
	int rc = 0;

	TRACE_ENTRY();

	tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
	if (tgt == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of tgt failed");
		rc = -ENOMEM;
		goto out_err;
	}

	INIT_LIST_HEAD(&tgt->sess_list);
	init_waitqueue_head(&tgt->unreg_waitQ);
	tgt->tgtt = vtt;
	tgt->sg_tablesize = vtt->sg_tablesize;
	spin_lock_init(&tgt->tgt_lock);
	INIT_LIST_HEAD(&tgt->retry_cmd_list);
	atomic_set(&tgt->finished_cmds, 0);
	init_timer(&tgt->retry_timer);
	tgt->retry_timer.data = (unsigned long)tgt;
	tgt->retry_timer.function = scst_tgt_retry_timer_fn;

	rc = scst_suspend_activity(true);
	if (rc != 0)
		goto out_free_tgt_err;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		rc = -EINTR;
		goto out_resume_free;
	}

	if (target_name != NULL) {
		int len = strlen(target_name) + 1 +
			strlen(SCST_DEFAULT_ACG_NAME) + 1;

		tgt->default_group_name = kmalloc(len, GFP_KERNEL);
		if (tgt->default_group_name == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of default "
				"group name failed");
			rc = -ENOMEM;
			goto out_unlock_resume;
		}
		sprintf(tgt->default_group_name, "%s_%s", SCST_DEFAULT_ACG_NAME,
			target_name);
	}

	rc = scst_build_proc_target_entries(tgt);
	if (rc < 0)
		goto out_free_name;
	else
		list_add_tail(&tgt->tgt_list_entry, &vtt->tgt_list);

	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	PRINT_INFO("Target %s (%p) for template %s registered successfully",
		target_name, tgt, vtt->name);

out:
	TRACE_EXIT();
	return tgt;

out_free_name:
	kfree(tgt->default_group_name);

out_unlock_resume:
	mutex_unlock(&scst_mutex);

out_resume_free:
	scst_resume_activity();

out_free_tgt_err:
	kfree(tgt);
	tgt = NULL;

out_err:
	PRINT_ERROR("Failed to register target %s for template %s (error %d)",
		target_name, vtt->name, rc);
	goto out;
}
EXPORT_SYMBOL(scst_register);

static inline int test_sess_list(struct scst_tgt *tgt)
{
	int res;
	mutex_lock(&scst_mutex);
	res = list_empty(&tgt->sess_list);
	mutex_unlock(&scst_mutex);
	return res;
}

void scst_unregister(struct scst_tgt *tgt)
{
	struct scst_session *sess;
	struct scst_tgt_template *vtt = tgt->tgtt;

	TRACE_ENTRY();

	TRACE_DBG("%s", "Calling target driver's release()");
	tgt->tgtt->release(tgt);
	TRACE_DBG("%s", "Target driver's release() returned");

	mutex_lock(&scst_mutex);
	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		sBUG_ON(sess->shut_phase == SCST_SESS_SPH_READY);
	}
	mutex_unlock(&scst_mutex);

	TRACE_DBG("%s", "Waiting for sessions shutdown");
	wait_event(tgt->unreg_waitQ, test_sess_list(tgt));
	TRACE_DBG("%s", "wait_event() returned");

	scst_suspend_activity(false);
	mutex_lock(&scst_mutex);

	list_del(&tgt->tgt_list_entry);

	scst_cleanup_proc_target_entries(tgt);

	kfree(tgt->default_group_name);

	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	del_timer_sync(&tgt->retry_timer);

	PRINT_INFO("Target %p for template %s unregistered successfully",
		tgt, vtt->name);

	kfree(tgt);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_unregister);

static int scst_susp_wait(bool interruptible)
{
	int res = 0;

	TRACE_ENTRY();

	if (interruptible) {
		res = wait_event_interruptible_timeout(scst_dev_cmd_waitQ,
			(atomic_read(&scst_cmd_count) == 0),
			SCST_SUSPENDING_TIMEOUT);
		if (res <= 0) {
			__scst_resume_activity();
			if (res == 0)
				res = -EBUSY;
		} else
			res = 0;
	} else
		wait_event(scst_dev_cmd_waitQ, atomic_read(&scst_cmd_count) == 0);

	TRACE_MGMT_DBG("wait_event() returned %d", res);

	TRACE_EXIT_RES(res);
	return res;
}

int scst_suspend_activity(bool interruptible)
{
	int res = 0;
	bool rep = false;

	TRACE_ENTRY();

	if (interruptible) {
		if (mutex_lock_interruptible(&scst_suspend_mutex) != 0) {
			res = -EINTR;
			goto out;
		}
	} else
		mutex_lock(&scst_suspend_mutex);

	TRACE_MGMT_DBG("suspend_count %d", suspend_count);
	suspend_count++;
	if (suspend_count > 1)
		goto out_up;

	set_bit(SCST_FLAG_SUSPENDING, &scst_flags);
	set_bit(SCST_FLAG_SUSPENDED, &scst_flags);
	smp_mb__after_set_bit();

	/*
	 * See comment in scst_user.c::dev_user_task_mgmt_fn() for more
	 * information about scst_user behavior.
	 *
	 * ToDo: make the global suspending unneeded (Switch to per-device
	 * reference counting? That would mean to switch off from lockless
	 * implementation of scst_translate_lun().. )
	 */

	if (atomic_read(&scst_cmd_count) != 0) {
		PRINT_INFO("Waiting for %d active commands to complete... This "
			"might take few minutes for disks or few hours for "
			"tapes, if you use long executed commands, like "
			"REWIND or FORMAT. In case, if you have a hung user "
			"space device (i.e. made using scst_user module) not "
			"responding to any commands, if might take virtually "
			"forever until the corresponding user space "
			"program recovers and starts responding or gets "
			"killed.", atomic_read(&scst_cmd_count));
		rep = true;
	}

	res = scst_susp_wait(interruptible);
	if (res != 0)
		goto out_clear;

	clear_bit(SCST_FLAG_SUSPENDING, &scst_flags);
	smp_mb__after_clear_bit();

	TRACE_MGMT_DBG("Waiting for %d active commands finally to complete",
		atomic_read(&scst_cmd_count));

	res = scst_susp_wait(interruptible);
	if (res != 0)
		goto out_clear;

	if (rep)
		PRINT_INFO("%s", "All active commands completed");

out_up:
	mutex_unlock(&scst_suspend_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_clear:
	clear_bit(SCST_FLAG_SUSPENDING, &scst_flags);
	smp_mb__after_clear_bit();
	goto out_up;
}
EXPORT_SYMBOL(scst_suspend_activity);

static void __scst_resume_activity(void)
{
	struct scst_cmd_lists *l;

	TRACE_ENTRY();

	suspend_count--;
	TRACE_MGMT_DBG("suspend_count %d left", suspend_count);
	if (suspend_count > 0)
		goto out;

	clear_bit(SCST_FLAG_SUSPENDED, &scst_flags);
	smp_mb__after_clear_bit();

	list_for_each_entry(l, &scst_cmd_lists_list, lists_list_entry) {
		wake_up_all(&l->cmd_list_waitQ);
	}
	wake_up_all(&scst_init_cmd_list_waitQ);

	spin_lock_irq(&scst_mcmd_lock);
	if (!list_empty(&scst_delayed_mgmt_cmd_list)) {
		struct scst_mgmt_cmd *m;
		m = list_entry(scst_delayed_mgmt_cmd_list.next, typeof(*m),
				mgmt_cmd_list_entry);
		TRACE_MGMT_DBG("Moving delayed mgmt cmd %p to head of active "
			"mgmt cmd list", m);
		list_move(&m->mgmt_cmd_list_entry, &scst_active_mgmt_cmd_list);
	}
	spin_unlock_irq(&scst_mcmd_lock);
	wake_up_all(&scst_mgmt_cmd_list_waitQ);

out:
	TRACE_EXIT();
	return;
}

void scst_resume_activity(void)
{
	TRACE_ENTRY();

	mutex_lock(&scst_suspend_mutex);
	__scst_resume_activity();
	mutex_unlock(&scst_suspend_mutex);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_resume_activity);

static int scst_register_device(struct scsi_device *scsidp)
{
	int res = 0;
	struct scst_device *dev;
	struct scst_dev_type *dt;

	TRACE_ENTRY();

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out_err;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_resume;
	}

	res = scst_alloc_device(GFP_KERNEL, &dev);
	if (res != 0)
		goto out_up;

	dev->type = scsidp->type;

	dev->rq_disk = alloc_disk(1);
	if (dev->rq_disk == NULL) {
		res = -ENOMEM;
		goto out_free_dev;
	}
	dev->rq_disk->major = SCST_MAJOR;

	dev->scsi_dev = scsidp;

	list_add_tail(&dev->dev_list_entry, &scst_dev_list);

	list_for_each_entry(dt, &scst_dev_type_list, dev_type_list_entry) {
		if (dt->type == scsidp->type) {
			res = scst_assign_dev_handler(dev, dt);
			if (res != 0)
				goto out_free;
			break;
		}
	}

out_up:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out_err:
	if (res == 0) {
		PRINT_INFO("Attached SCSI target mid-level at "
		    "scsi%d, channel %d, id %d, lun %d, type %d",
		    scsidp->host->host_no, scsidp->channel, scsidp->id,
		    scsidp->lun, scsidp->type);
	} else {
		PRINT_ERROR("Failed to attach SCSI target mid-level "
		    "at scsi%d, channel %d, id %d, lun %d, type %d",
		    scsidp->host->host_no, scsidp->channel, scsidp->id,
		    scsidp->lun, scsidp->type);
	}

	TRACE_EXIT_RES(res);
	return res;

out_free:
	list_del(&dev->dev_list_entry);
	put_disk(dev->rq_disk);

out_free_dev:
	scst_free_device(dev);
	goto out_up;
}

static void scst_unregister_device(struct scsi_device *scsidp)
{
	struct scst_device *d, *dev = NULL;
	struct scst_acg_dev *acg_dev, *aa;

	TRACE_ENTRY();

	scst_suspend_activity(false);
	mutex_lock(&scst_mutex);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (d->scsi_dev == scsidp) {
			dev = d;
			TRACE_DBG("Target device %p found", dev);
			break;
		}
	}
	if (dev == NULL) {
		PRINT_ERROR("%s", "Target device not found");
		goto out_unblock;
	}

	list_del(&dev->dev_list_entry);

	list_for_each_entry_safe(acg_dev, aa, &dev->dev_acg_dev_list,
				 dev_acg_dev_list_entry)
	{
		scst_acg_remove_dev(acg_dev->acg, dev);
	}

	scst_assign_dev_handler(dev, &scst_null_devtype);

	put_disk(dev->rq_disk);
	scst_free_device(dev);

	PRINT_INFO("Detached SCSI target mid-level from scsi%d, channel %d, "
		"id %d, lun %d, type %d", scsidp->host->host_no,
		scsidp->channel, scsidp->id, scsidp->lun, scsidp->type);

out_unblock:
	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	TRACE_EXIT();
	return;
}

static int scst_dev_handler_check(struct scst_dev_type *dev_handler)
{
	int res = 0;

	if (dev_handler->parse == NULL) {
		PRINT_ERROR("scst dev_type driver %s doesn't have a "
			"parse() method.", dev_handler->name);
		res = -EINVAL;
		goto out;
	}

	if (dev_handler->exec == NULL) {
#ifdef CONFIG_SCST_ALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ
		dev_handler->exec_atomic = 1;
#else
		dev_handler->exec_atomic = 0;
#endif
	}

	if (dev_handler->dev_done == NULL)
		dev_handler->dev_done_atomic = 1;

out:
	TRACE_EXIT_RES(res);
	return res;
}

int scst_register_virtual_device(struct scst_dev_type *dev_handler,
	const char *dev_name)
{
	int res, rc;
	struct scst_device *dev = NULL;

	TRACE_ENTRY();

	if (dev_handler == NULL) {
		PRINT_ERROR("%s: valid device handler must be supplied",
			    __func__);
		res = -EINVAL;
		goto out;
	}

	if (dev_name == NULL) {
		PRINT_ERROR("%s: device name must be non-NULL", __func__);
		res = -EINVAL;
		goto out;
	}

	res = scst_dev_handler_check(dev_handler);
	if (res != 0)
		goto out;

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_resume;
	}

	res = scst_alloc_device(GFP_KERNEL, &dev);
	if (res != 0)
		goto out_up;

	dev->type = dev_handler->type;
	dev->scsi_dev = NULL;
	dev->virt_name = dev_name;
	dev->virt_id = scst_virt_dev_last_id++;

	list_add_tail(&dev->dev_list_entry, &scst_dev_list);

	res = dev->virt_id;

	rc = scst_assign_dev_handler(dev, dev_handler);
	if (rc != 0) {
		res = rc;
		goto out_free_del;
	}

out_up:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	if (res > 0) {
		PRINT_INFO("Attached SCSI target mid-level to virtual "
		    "device %s (id %d)", dev_name, dev->virt_id);
	} else {
		PRINT_INFO("Failed to attach SCSI target mid-level to "
		    "virtual device %s", dev_name);
	}

	TRACE_EXIT_RES(res);
	return res;

out_free_del:
	list_del(&dev->dev_list_entry);
	scst_free_device(dev);
	goto out_up;
}
EXPORT_SYMBOL(scst_register_virtual_device);

void scst_unregister_virtual_device(int id)
{
	struct scst_device *d, *dev = NULL;
	struct scst_acg_dev *acg_dev, *aa;

	TRACE_ENTRY();

	scst_suspend_activity(false);
	mutex_lock(&scst_mutex);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (d->virt_id == id) {
			dev = d;
			TRACE_DBG("Target device %p (id %d) found", dev, id);
			break;
		}
	}
	if (dev == NULL) {
		PRINT_ERROR("Target virtual device (id %d) not found", id);
		goto out_unblock;
	}

	list_del(&dev->dev_list_entry);

	list_for_each_entry_safe(acg_dev, aa, &dev->dev_acg_dev_list,
				 dev_acg_dev_list_entry)
	{
		scst_acg_remove_dev(acg_dev->acg, dev);
	}

	scst_assign_dev_handler(dev, &scst_null_devtype);

	PRINT_INFO("Detached SCSI target mid-level from virtual device %s "
		"(id %d)", dev->virt_name, dev->virt_id);

	scst_free_device(dev);

out_unblock:
	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_unregister_virtual_device);

int __scst_register_dev_driver(struct scst_dev_type *dev_type,
	const char *version)
{
	struct scst_dev_type *dt;
	struct scst_device *dev;
	int res;
	int exist;

	TRACE_ENTRY();

	if (strcmp(version, SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of dev handler %s",
			dev_type->name);
		res = -EINVAL;
		goto out_error;
	}

	res = scst_dev_handler_check(dev_type);
	if (res != 0)
		goto out_error;

#if !defined(SCSI_EXEC_REQ_FIFO_DEFINED) && !defined(CONFIG_SCST_STRICT_SERIALIZING)
	if (dev_type->exec == NULL) {
		PRINT_ERROR("Pass-through dev handlers (handler \"%s\") not "
			"supported. Consider applying on your kernel patch "
			"scst_exec_req_fifo-<kernel-version>.patch or define "
			"CONFIG_SCST_STRICT_SERIALIZING", dev_type->name);
		res = -EINVAL;
		goto out;
	}
#endif

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out_error;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_err_res;
	}

	exist = 0;
	list_for_each_entry(dt, &scst_dev_type_list, dev_type_list_entry) {
		if (strcmp(dt->name, dev_type->name) == 0) {
			PRINT_ERROR("Device type handler \"%s\" already "
				"exist", dt->name);
			exist = 1;
			break;
		}
	}
	if (exist)
		goto out_up;

	res = scst_build_proc_dev_handler_dir_entries(dev_type);
	if (res < 0)
		goto out_up;

	list_add_tail(&dev_type->dev_type_list_entry, &scst_dev_type_list);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		if ((dev->scsi_dev == NULL) || (dev->handler != &scst_null_devtype))
			continue;
		if (dev->scsi_dev->type == dev_type->type)
			scst_assign_dev_handler(dev, dev_type);
	}

	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	if (res == 0) {
		PRINT_INFO("Device handler \"%s\" for type %d registered "
			"successfully", dev_type->name, dev_type->type);
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_up:
	mutex_unlock(&scst_mutex);

out_err_res:
	scst_resume_activity();

out_error:
	PRINT_ERROR("Failed to register device handler \"%s\" for type %d",
		dev_type->name, dev_type->type);
	goto out;
}
EXPORT_SYMBOL(__scst_register_dev_driver);

void scst_unregister_dev_driver(struct scst_dev_type *dev_type)
{
	struct scst_device *dev;
	struct scst_dev_type *dt;
	int found = 0;

	TRACE_ENTRY();

	scst_suspend_activity(false);
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

	scst_cleanup_proc_dev_handler_dir_entries(dev_type);

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
EXPORT_SYMBOL(scst_unregister_dev_driver);

int __scst_register_virtual_dev_driver(struct scst_dev_type *dev_type,
	const char *version)
{
	int res;

	TRACE_ENTRY();

	if (strcmp(version, SCST_INTERFACE_VERSION) != 0) {
		PRINT_ERROR("Incorrect version of virtual dev handler %s",
			dev_type->name);
		res = -EINVAL;
		goto out_err;
	}

	res = scst_dev_handler_check(dev_type);
	if (res != 0)
		goto out_err;

	if (!dev_type->no_proc) {
		res = scst_build_proc_dev_handler_dir_entries(dev_type);
		if (res < 0)
			goto out_err;
	}

	if (dev_type->type != -1) {
		PRINT_INFO("Virtual device handler %s for type %d "
			"registered successfully", dev_type->name,
			dev_type->type);
	} else {
		PRINT_INFO("Virtual device handler \"%s\" registered "
			"successfully", dev_type->name);
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	PRINT_ERROR("Failed to register virtual device handler \"%s\"",
		dev_type->name);
	goto out;
}
EXPORT_SYMBOL(__scst_register_virtual_dev_driver);

void scst_unregister_virtual_dev_driver(struct scst_dev_type *dev_type)
{
	TRACE_ENTRY();

	if (!dev_type->no_proc)
		scst_cleanup_proc_dev_handler_dir_entries(dev_type);

	PRINT_INFO("Device handler \"%s\" unloaded", dev_type->name);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_unregister_virtual_dev_driver);

/* Called under scst_mutex */
int scst_add_dev_threads(struct scst_device *dev, int num)
{
	int i, res = 0;
	int n = 0;
	struct scst_cmd_thread_t *thr;
	char nm[12];

	TRACE_ENTRY();

	list_for_each_entry(thr, &dev->threads_list, thread_list_entry) {
		n++;
	}

	for (i = 0; i < num; i++) {
		thr = kmalloc(sizeof(*thr), GFP_KERNEL);
		if (!thr) {
			res = -ENOMEM;
			PRINT_ERROR("Failed to allocate thr %d", res);
			goto out;
		}
		strncpy(nm, dev->handler->name, ARRAY_SIZE(nm)-1);
		nm[ARRAY_SIZE(nm)-1] = '\0';
		thr->cmd_thread = kthread_run(scst_cmd_thread,
			&dev->cmd_lists, "%sd%d_%d", nm, dev->dev_num, n++);
		if (IS_ERR(thr->cmd_thread)) {
			res = PTR_ERR(thr->cmd_thread);
			PRINT_ERROR("kthread_create() failed: %d", res);
			kfree(thr);
			goto out;
		}
		list_add(&thr->thread_list_entry, &dev->threads_list);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_mutex and suspended activity */
static int scst_create_dev_threads(struct scst_device *dev)
{
	int res = 0;
	int threads_num;

	TRACE_ENTRY();

	if (dev->handler->threads_num <= 0)
		goto out;

	threads_num = dev->handler->threads_num;

	spin_lock_init(&dev->cmd_lists.cmd_list_lock);
	INIT_LIST_HEAD(&dev->cmd_lists.active_cmd_list);
	init_waitqueue_head(&dev->cmd_lists.cmd_list_waitQ);

	res = scst_add_dev_threads(dev, threads_num);
	if (res != 0)
		goto out;

	mutex_lock(&scst_suspend_mutex);
	list_add_tail(&dev->cmd_lists.lists_list_entry,
		&scst_cmd_lists_list);
	mutex_unlock(&scst_suspend_mutex);

	dev->p_cmd_lists = &dev->cmd_lists;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_mutex */
void scst_del_dev_threads(struct scst_device *dev, int num)
{
	struct scst_cmd_thread_t *ct, *tmp;
	int i = 0;

	TRACE_ENTRY();

	list_for_each_entry_safe(ct, tmp, &dev->threads_list,
				thread_list_entry) {
		int rc = kthread_stop(ct->cmd_thread);
		if (rc < 0)
			TRACE_MGMT_DBG("kthread_stop() failed: %d", rc);
		list_del(&ct->thread_list_entry);
		kfree(ct);
		if ((num > 0) && (++i >= num))
			break;
	}

	TRACE_EXIT();
	return;
}

/* Called under scst_mutex and suspended activity */
static void scst_stop_dev_threads(struct scst_device *dev)
{
	TRACE_ENTRY();

	if (list_empty(&dev->threads_list))
		goto out;

	scst_del_dev_threads(dev, -1);

	if (dev->p_cmd_lists == &dev->cmd_lists) {
		mutex_lock(&scst_suspend_mutex);
		list_del(&dev->cmd_lists.lists_list_entry);
		mutex_unlock(&scst_suspend_mutex);
	}

out:
	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_assign_dev_handler(struct scst_device *dev,
	struct scst_dev_type *handler)
{
	int res = 0;
	struct scst_tgt_dev *tgt_dev;
	LIST_HEAD(attached_tgt_devs);

	TRACE_ENTRY();

	sBUG_ON(handler == NULL);

	if (dev->handler == handler)
		goto out;

	if (dev->handler && dev->handler->detach_tgt) {
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			TRACE_DBG("Calling dev handler's detach_tgt(%p)",
				tgt_dev);
			dev->handler->detach_tgt(tgt_dev);
			TRACE_DBG("%s", "Dev handler's detach_tgt() returned");
		}
	}

	if (dev->handler && dev->handler->detach) {
		TRACE_DBG("%s", "Calling dev handler's detach()");
		dev->handler->detach(dev);
		TRACE_DBG("%s", "Old handler's detach() returned");
	}

	scst_stop_dev_threads(dev);

	dev->handler = handler;

	if (handler) {
		res = scst_create_dev_threads(dev);
		if (res != 0)
			goto out_null;
	}

	if (handler && handler->attach) {
		TRACE_DBG("Calling new dev handler's attach(%p)", dev);
		res = handler->attach(dev);
		TRACE_DBG("New dev handler's attach() returned %d", res);
		if (res != 0) {
			PRINT_ERROR("New device handler's %s attach() "
				"failed: %d", handler->name, res);
		}
		goto out_thr_null;
	}

	if (handler && handler->attach_tgt) {
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			TRACE_DBG("Calling dev handler's attach_tgt(%p)",
				tgt_dev);
			res = handler->attach_tgt(tgt_dev);
			TRACE_DBG("%s", "Dev handler's attach_tgt() returned");
			if (res != 0) {
				PRINT_ERROR("Device handler's %s attach_tgt() "
				    "failed: %d", handler->name, res);
				goto out_err_detach_tgt;
			}
			list_add_tail(&tgt_dev->extra_tgt_dev_list_entry,
				&attached_tgt_devs);
		}
	}

out_thr_null:
	if (res != 0)
		scst_stop_dev_threads(dev);

out_null:
	if (res != 0)
		dev->handler = &scst_null_devtype;

out:
	TRACE_EXIT_RES(res);
	return res;

out_err_detach_tgt:
	if (handler && handler->detach_tgt) {
		list_for_each_entry(tgt_dev, &attached_tgt_devs,
				 extra_tgt_dev_list_entry)
		{
			TRACE_DBG("Calling handler's detach_tgt(%p)",
				tgt_dev);
			handler->detach_tgt(tgt_dev);
			TRACE_DBG("%s", "Handler's detach_tgt() returned");
		}
	}
	if (handler && handler->detach) {
		TRACE_DBG("%s", "Calling handler's detach()");
		handler->detach(dev);
		TRACE_DBG("%s", "Handler's detach() returned");
	}
	goto out_null;
}

int scst_cmd_threads_count(void)
{
	int i;

	/* Just to lower the race window, when user can get just changed value */
	mutex_lock(&scst_threads_info.cmd_threads_mutex);
	i = scst_threads_info.nr_cmd_threads;
	mutex_unlock(&scst_threads_info.cmd_threads_mutex);
	return i;
}

static void scst_threads_info_init(void)
{
	memset(&scst_threads_info, 0, sizeof(scst_threads_info));
	mutex_init(&scst_threads_info.cmd_threads_mutex);
	INIT_LIST_HEAD(&scst_threads_info.cmd_threads_list);
}

/* scst_threads_info.cmd_threads_mutex supposed to be held */
void __scst_del_cmd_threads(int num)
{
	struct scst_cmd_thread_t *ct, *tmp;
	int i;

	TRACE_ENTRY();

	i = scst_threads_info.nr_cmd_threads;
	if (num <= 0 || num > i) {
		PRINT_ERROR("can not del %d cmd threads from %d", num, i);
		return;
	}

	list_for_each_entry_safe(ct, tmp, &scst_threads_info.cmd_threads_list,
				thread_list_entry) {
		int res;

		res = kthread_stop(ct->cmd_thread);
		if (res < 0)
			TRACE_MGMT_DBG("kthread_stop() failed: %d", res);
		list_del(&ct->thread_list_entry);
		kfree(ct);
		scst_threads_info.nr_cmd_threads--;
		--num;
		if (num == 0)
			break;
	}

	TRACE_EXIT();
	return;
}

/* scst_threads_info.cmd_threads_mutex supposed to be held */
int __scst_add_cmd_threads(int num)
{
	int res = 0, i;
	static int scst_thread_num;

	TRACE_ENTRY();

	for (i = 0; i < num; i++) {
		struct scst_cmd_thread_t *thr;

		thr = kmalloc(sizeof(*thr), GFP_KERNEL);
		if (!thr) {
			res = -ENOMEM;
			PRINT_ERROR("fail to allocate thr %d", res);
			goto out_error;
		}
		thr->cmd_thread = kthread_run(scst_cmd_thread,
			&scst_main_cmd_lists, "scsi_tgt%d",
			scst_thread_num++);
		if (IS_ERR(thr->cmd_thread)) {
			res = PTR_ERR(thr->cmd_thread);
			PRINT_ERROR("kthread_create() failed: %d", res);
			kfree(thr);
			goto out_error;
		}
		list_add(&thr->thread_list_entry,
			&scst_threads_info.cmd_threads_list);
		scst_threads_info.nr_cmd_threads++;
	}
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_error:
	if (i > 0)
		__scst_del_cmd_threads(i - 1);
	goto out;
}

int scst_add_cmd_threads(int num)
{
	int res;

	TRACE_ENTRY();

	mutex_lock(&scst_threads_info.cmd_threads_mutex);
	res = __scst_add_cmd_threads(num);
	mutex_unlock(&scst_threads_info.cmd_threads_mutex);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_add_cmd_threads);

void scst_del_cmd_threads(int num)
{
	TRACE_ENTRY();

	mutex_lock(&scst_threads_info.cmd_threads_mutex);
	__scst_del_cmd_threads(num);
	mutex_unlock(&scst_threads_info.cmd_threads_mutex);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_del_cmd_threads);

static void scst_stop_all_threads(void)
{
	TRACE_ENTRY();

	mutex_lock(&scst_threads_info.cmd_threads_mutex);
	__scst_del_cmd_threads(scst_threads_info.nr_cmd_threads);
	if (scst_threads_info.mgmt_cmd_thread)
		kthread_stop(scst_threads_info.mgmt_cmd_thread);
	if (scst_threads_info.mgmt_thread)
		kthread_stop(scst_threads_info.mgmt_thread);
	if (scst_threads_info.init_cmd_thread)
		kthread_stop(scst_threads_info.init_cmd_thread);
	mutex_unlock(&scst_threads_info.cmd_threads_mutex);

	TRACE_EXIT();
	return;
}

static int scst_start_all_threads(int num)
{
	int res;

	TRACE_ENTRY();

	mutex_lock(&scst_threads_info.cmd_threads_mutex);
	res = __scst_add_cmd_threads(num);
	if (res < 0)
		goto out;

	scst_threads_info.init_cmd_thread = kthread_run(scst_init_cmd_thread,
		NULL, "scsi_tgt_init");
	if (IS_ERR(scst_threads_info.init_cmd_thread)) {
		res = PTR_ERR(scst_threads_info.init_cmd_thread);
		PRINT_ERROR("kthread_create() for init cmd failed: %d", res);
		scst_threads_info.init_cmd_thread = NULL;
		goto out;
	}

	scst_threads_info.mgmt_cmd_thread = kthread_run(scst_mgmt_cmd_thread,
		NULL, "scsi_tgt_mc");
	if (IS_ERR(scst_threads_info.mgmt_cmd_thread)) {
		res = PTR_ERR(scst_threads_info.mgmt_cmd_thread);
		PRINT_ERROR("kthread_create() for mcmd failed: %d", res);
		scst_threads_info.mgmt_cmd_thread = NULL;
		goto out;
	}

	scst_threads_info.mgmt_thread = kthread_run(scst_mgmt_thread,
		NULL, "scsi_tgt_mgmt");
	if (IS_ERR(scst_threads_info.mgmt_thread)) {
		res = PTR_ERR(scst_threads_info.mgmt_thread);
		PRINT_ERROR("kthread_create() for mgmt failed: %d", res);
		scst_threads_info.mgmt_thread = NULL;
		goto out;
	}

out:
	mutex_unlock(&scst_threads_info.cmd_threads_mutex);
	TRACE_EXIT_RES(res);
	return res;
}

void scst_get(void)
{
	__scst_get(0);
}
EXPORT_SYMBOL(scst_get);

void scst_put(void)
{
	__scst_put();
}
EXPORT_SYMBOL(scst_put);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
static int scst_add(struct class_device *cdev)
#else
static int scst_add(struct class_device *cdev, struct class_interface *intf)
#endif
{
	struct scsi_device *scsidp;
	int res = 0;

	TRACE_ENTRY();

	scsidp = to_scsi_device(cdev->dev);
	res = scst_register_device(scsidp);

	TRACE_EXIT();
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
static void scst_remove(struct class_device *cdev)
#else
static void scst_remove(struct class_device *cdev, struct class_interface *intf)
#endif
{
	struct scsi_device *scsidp;

	TRACE_ENTRY();

	scsidp = to_scsi_device(cdev->dev);
	scst_unregister_device(scsidp);

	TRACE_EXIT();
	return;
}

static struct class_interface scst_interface = {
	.add = scst_add,
	.remove = scst_remove,
};

static void __init scst_print_config(void)
{
	char buf[128];
	int i, j;

	i = snprintf(buf, sizeof(buf), "Enabled features: ");
	j = i;

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	i += snprintf(&buf[i], sizeof(buf) - i, "Strict serializing");
#endif

#ifdef CONFIG_SCST_EXTRACHECKS
	i += snprintf(&buf[i], sizeof(buf) - i, "%sEXTRACHECKS",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_TRACING
	i += snprintf(&buf[i], sizeof(buf) - i, "%sTRACING",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG
	i += snprintf(&buf[i], sizeof(buf) - i, "%sDEBUG",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_TM
	i += snprintf(&buf[i], sizeof(buf) - i, "%sDEBUG_TM",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_RETRY
	i += snprintf(&buf[i], sizeof(buf) - i, "%sDEBUG_RETRY",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_OOM
	i += snprintf(&buf[i], sizeof(buf) - i, "%sDEBUG_OOM",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_DEBUG_SN
	i += snprintf(&buf[i], sizeof(buf) - i, "%sDEBUG_SN",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
	i += snprintf(&buf[i], sizeof(buf) - i, "%sUSE_EXPECTED_VALUES",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_ALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ
	i += snprintf(&buf[i], sizeof(buf) - i, "%sALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_STRICT_SECURITY
	i += snprintf(&buf[i], sizeof(buf) - i, "%sSCST_STRICT_SECURITY",
		(j == i) ? "" : ", ");
#endif

#ifdef CONFIG_SCST_HIGHMEM
	i += snprintf(&buf[i], sizeof(buf) - i, "%sSCST_HIGHMEM",
		(j == i) ? "" : ", ");
#endif

	if (j != i)
		PRINT_INFO("%s", buf);
}

static int __init init_scst(void)
{
	int res = 0, i;
	int scst_num_cpus;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
	{
		struct scsi_request *req;
		BUILD_BUG_ON(SCST_SENSE_BUFFERSIZE !=
			sizeof(req->sr_sense_buffer));
	}
#else
	{
		struct scsi_sense_hdr *shdr;
		BUILD_BUG_ON(SCST_SENSE_BUFFERSIZE < sizeof(*shdr));
	}
#endif
	{
		struct scst_tgt_dev *t;
		struct scst_cmd *c;
		BUILD_BUG_ON(sizeof(t->curr_sn) != sizeof(t->expected_sn));
		BUILD_BUG_ON(sizeof(c->sn) != sizeof(t->expected_sn));
	}

	BUILD_BUG_ON(SCST_DATA_UNKNOWN != DMA_BIDIRECTIONAL);
	BUILD_BUG_ON(SCST_DATA_WRITE != DMA_TO_DEVICE);
	BUILD_BUG_ON(SCST_DATA_READ != DMA_FROM_DEVICE);
	BUILD_BUG_ON(SCST_DATA_NONE != DMA_NONE);

	mutex_init(&scst_mutex);
	INIT_LIST_HEAD(&scst_template_list);
	INIT_LIST_HEAD(&scst_dev_list);
	INIT_LIST_HEAD(&scst_dev_type_list);
	spin_lock_init(&scst_main_lock);
	INIT_LIST_HEAD(&scst_acg_list);
	spin_lock_init(&scst_init_lock);
	init_waitqueue_head(&scst_init_cmd_list_waitQ);
	INIT_LIST_HEAD(&scst_init_cmd_list);
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	scst_trace_flag = SCST_DEFAULT_LOG_FLAGS;
#endif
	atomic_set(&scst_cmd_count, 0);
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
	INIT_LIST_HEAD(&scst_cmd_lists_list);
	scst_virt_dev_last_id = 1;
	spin_lock_init(&scst_temp_UA_lock);

	spin_lock_init(&scst_main_cmd_lists.cmd_list_lock);
	INIT_LIST_HEAD(&scst_main_cmd_lists.active_cmd_list);
	init_waitqueue_head(&scst_main_cmd_lists.cmd_list_waitQ);
	list_add_tail(&scst_main_cmd_lists.lists_list_entry,
		&scst_cmd_lists_list);

	scst_num_cpus = num_online_cpus();

	/* ToDo: register_cpu_notifier() */

	if (scst_threads == 0)
		scst_threads = scst_num_cpus;

	if (scst_threads < 1) {
		PRINT_ERROR("%s", "scst_threads can not be less than 1");
		scst_threads = scst_num_cpus;
	}

	scst_threads_info_init();

#define INIT_CACHEP(p, s, o) do {					\
		p = KMEM_CACHE(s, SCST_SLAB_FLAGS);			\
		TRACE_MEM("Slab create: %s at %p size %zd", #s, p,	\
			  sizeof(struct s));				\
		if (p == NULL) {					\
			res = -ENOMEM;					\
			goto o;						\
		}							\
	} while (0)

	INIT_CACHEP(scst_mgmt_cachep, scst_mgmt_cmd, out);
	INIT_CACHEP(scst_mgmt_stub_cachep, scst_mgmt_cmd_stub,
			out_destroy_mgmt_cache);
	INIT_CACHEP(scst_ua_cachep, scst_tgt_dev_UA,
			out_destroy_mgmt_stub_cache);
	{
		struct scst_sense { uint8_t s[SCST_SENSE_BUFFERSIZE]; };
		INIT_CACHEP(scst_sense_cachep, scst_sense, out_destroy_ua_cache);
	}
	INIT_CACHEP(scst_cmd_cachep, scst_cmd, out_destroy_sense_cache);
	INIT_CACHEP(scst_sess_cachep, scst_session, out_destroy_cmd_cache);
	INIT_CACHEP(scst_tgtd_cachep, scst_tgt_dev, out_destroy_sess_cache);
	INIT_CACHEP(scst_acgd_cachep, scst_acg_dev, out_destroy_tgt_cache);

	scst_mgmt_mempool = mempool_create(64, mempool_alloc_slab,
		mempool_free_slab, scst_mgmt_cachep);
	if (scst_mgmt_mempool == NULL) {
		res = -ENOMEM;
		goto out_destroy_acg_cache;
	}

	scst_mgmt_stub_mempool = mempool_create(1024, mempool_alloc_slab,
		mempool_free_slab, scst_mgmt_stub_cachep);
	if (scst_mgmt_stub_mempool == NULL) {
		res = -ENOMEM;
		goto out_destroy_mgmt_mempool;
	}

	scst_ua_mempool = mempool_create(64, mempool_alloc_slab,
		mempool_free_slab, scst_ua_cachep);
	if (scst_ua_mempool == NULL) {
		res = -ENOMEM;
		goto out_destroy_mgmt_stub_mempool;
	}

	/* Loosing sense may have fatal consequences, so let's have a big pool */
	scst_sense_mempool = mempool_create(128, mempool_alloc_slab,
		mempool_free_slab, scst_sense_cachep);
	if (scst_sense_mempool == NULL) {
		res = -ENOMEM;
		goto out_destroy_ua_mempool;
	}

	if (scst_max_cmd_mem == 0) {
		struct sysinfo si;
		si_meminfo(&si);
#if BITS_PER_LONG == 32
		scst_max_cmd_mem = min(
			(((uint64_t)si.totalram << PAGE_SHIFT) >> 20) >> 2,
			(uint64_t)1 << 30);
#else
		scst_max_cmd_mem = ((si.totalram << PAGE_SHIFT) >> 20) >> 2;
#endif
	}

	if (scst_max_dev_cmd_mem != 0) {
		if (scst_max_dev_cmd_mem > scst_max_cmd_mem) {
			PRINT_ERROR("scst_max_dev_cmd_mem (%d) > "
				"scst_max_cmd_mem (%d)",
				scst_max_dev_cmd_mem,
				scst_max_cmd_mem);
			scst_max_dev_cmd_mem = scst_max_cmd_mem;
		}
	} else
		scst_max_dev_cmd_mem = scst_max_cmd_mem * 2 / 5;

	res = scst_sgv_pools_init(
		((uint64_t)scst_max_cmd_mem << 10) >> (PAGE_SHIFT - 10), 0);
	if (res != 0)
		goto out_destroy_sense_mempool;

	scst_default_acg = scst_alloc_add_acg(SCST_DEFAULT_ACG_NAME);
	if (scst_default_acg == NULL) {
		res = -ENOMEM;
		goto out_destroy_sgv_pool;
	}

	res = scsi_register_interface(&scst_interface);
	if (res != 0)
		goto out_free_acg;

	scst_scsi_op_list_init();

	for (i = 0; i < (int)ARRAY_SIZE(scst_tasklets); i++) {
		spin_lock_init(&scst_tasklets[i].tasklet_lock);
		INIT_LIST_HEAD(&scst_tasklets[i].tasklet_cmd_list);
		tasklet_init(&scst_tasklets[i].tasklet, (void *)scst_cmd_tasklet,
			(unsigned long)&scst_tasklets[i]);
	}

	TRACE_DBG("%d CPUs found, starting %d threads", scst_num_cpus,
		scst_threads);

	res = scst_start_all_threads(scst_threads);
	if (res < 0)
		goto out_thread_free;

	res = scst_proc_init_module();
	if (res != 0)
		goto out_thread_free;


	PRINT_INFO("SCST version %s loaded successfully (max mem for "
		"commands %dMB, per device %dMB)", SCST_VERSION_STRING,
		scst_max_cmd_mem, scst_max_dev_cmd_mem);

	scst_print_config();

out:
	TRACE_EXIT_RES(res);
	return res;

out_thread_free:
	scst_stop_all_threads();

	scsi_unregister_interface(&scst_interface);

out_free_acg:
	scst_destroy_acg(scst_default_acg);

out_destroy_sgv_pool:
	scst_sgv_pools_deinit();

out_destroy_sense_mempool:
	mempool_destroy(scst_sense_mempool);

out_destroy_ua_mempool:
	mempool_destroy(scst_ua_mempool);

out_destroy_mgmt_stub_mempool:
	mempool_destroy(scst_mgmt_stub_mempool);

out_destroy_mgmt_mempool:
	mempool_destroy(scst_mgmt_mempool);

out_destroy_acg_cache:
	kmem_cache_destroy(scst_acgd_cachep);

out_destroy_tgt_cache:
	kmem_cache_destroy(scst_tgtd_cachep);

out_destroy_sess_cache:
	kmem_cache_destroy(scst_sess_cachep);

out_destroy_cmd_cache:
	kmem_cache_destroy(scst_cmd_cachep);

out_destroy_sense_cache:
	kmem_cache_destroy(scst_sense_cachep);

out_destroy_ua_cache:
	kmem_cache_destroy(scst_ua_cachep);

out_destroy_mgmt_stub_cache:
	kmem_cache_destroy(scst_mgmt_stub_cachep);

out_destroy_mgmt_cache:
	kmem_cache_destroy(scst_mgmt_cachep);
	goto out;
}

static void __exit exit_scst(void)
{
#ifdef CONFIG_LOCKDEP
	static /* To hide the lockdep's warning about non-static key */
#endif
	DECLARE_MUTEX_LOCKED(shm);

	TRACE_ENTRY();

	/* ToDo: unregister_cpu_notifier() */

	scst_proc_cleanup_module();

	scst_stop_all_threads();

	scsi_unregister_interface(&scst_interface);
	scst_destroy_acg(scst_default_acg);

	scst_sgv_pools_deinit();

#define DEINIT_CACHEP(p) do {		\
		kmem_cache_destroy(p);	\
		p = NULL;		\
	} while (0)

	mempool_destroy(scst_mgmt_mempool);
	mempool_destroy(scst_mgmt_stub_mempool);
	mempool_destroy(scst_ua_mempool);
	mempool_destroy(scst_sense_mempool);

	DEINIT_CACHEP(scst_mgmt_cachep);
	DEINIT_CACHEP(scst_mgmt_stub_cachep);
	DEINIT_CACHEP(scst_ua_cachep);
	DEINIT_CACHEP(scst_sense_cachep);
	DEINIT_CACHEP(scst_cmd_cachep);
	DEINIT_CACHEP(scst_sess_cachep);
	DEINIT_CACHEP(scst_tgtd_cachep);
	DEINIT_CACHEP(scst_acgd_cachep);

	PRINT_INFO("%s", "SCST unloaded");

	TRACE_EXIT();
	return;
}


module_init(init_scst);
module_exit(exit_scst);

MODULE_AUTHOR("Vladislav Bolkhovitin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI target core");
MODULE_VERSION(SCST_VERSION_STRING);
