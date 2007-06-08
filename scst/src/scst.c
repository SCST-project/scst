/*
 *  scst.c
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

#include <linux/module.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <asm/unistd.h>
#include <asm/string.h>
#include <linux/kthread.h>

#include "scsi_tgt.h"
#include "scst_priv.h"
#include "scst_mem.h"

#ifndef CONFIG_NOHIGHMEM
#warning HIGHMEM kernel configurations are supported, but not recommended. \
	Consider changing VMSPLIT option or using 64-bit configuration instead.
#endif

/*
 * All targets, devices and dev_types management is done under
 * this mutex.
 */
DECLARE_MUTEX(scst_mutex);

LIST_HEAD(scst_template_list);
LIST_HEAD(scst_dev_list);
LIST_HEAD(scst_dev_type_list);

spinlock_t scst_main_lock = SPIN_LOCK_UNLOCKED;

struct kmem_cache *scst_mgmt_cachep;
mempool_t *scst_mgmt_mempool;
struct kmem_cache *scst_ua_cachep;
mempool_t *scst_ua_mempool;
struct kmem_cache *scst_tgtd_cachep;
struct kmem_cache *scst_sess_cachep;
struct kmem_cache *scst_acgd_cachep;

LIST_HEAD(scst_acg_list);
struct scst_acg *scst_default_acg;

spinlock_t scst_init_lock = SPIN_LOCK_UNLOCKED;
DECLARE_WAIT_QUEUE_HEAD(scst_init_cmd_list_waitQ);
LIST_HEAD(scst_init_cmd_list);
unsigned int scst_init_poll_cnt;

struct kmem_cache *scst_cmd_cachep;

#if defined(DEBUG) || defined(TRACING)
unsigned long scst_trace_flag = SCST_DEFAULT_LOG_FLAGS;
#endif

unsigned long scst_flags;
atomic_t scst_cmd_count = ATOMIC_INIT(0);

spinlock_t scst_cmd_mem_lock = SPIN_LOCK_UNLOCKED;
unsigned long scst_cur_cmd_mem, scst_cur_max_cmd_mem;
unsigned long scst_max_cmd_mem;

struct scst_sgv_pools scst_sgv;

struct scst_cmd_lists scst_main_cmd_lists;

struct scst_tasklet scst_tasklets[NR_CPUS];

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
DECLARE_WORK(scst_cmd_mem_work, scst_cmd_mem_work_fn, 0);
#else
DECLARE_DELAYED_WORK(scst_cmd_mem_work, scst_cmd_mem_work_fn);
#endif

spinlock_t scst_mcmd_lock = SPIN_LOCK_UNLOCKED;
LIST_HEAD(scst_active_mgmt_cmd_list);
LIST_HEAD(scst_delayed_mgmt_cmd_list);
DECLARE_WAIT_QUEUE_HEAD(scst_mgmt_cmd_list_waitQ);

DECLARE_WAIT_QUEUE_HEAD(scst_mgmt_waitQ);
spinlock_t scst_mgmt_lock = SPIN_LOCK_UNLOCKED;
LIST_HEAD(scst_sess_mgmt_list);

DECLARE_WAIT_QUEUE_HEAD(scst_dev_cmd_waitQ);

DECLARE_MUTEX(scst_suspend_mutex);
LIST_HEAD(scst_cmd_lists_list); /* protected by scst_suspend_mutex */

static int scst_threads;
struct scst_threads_info_t scst_threads_info;

static int suspend_count;

int scst_virt_dev_last_id = 1; /* protected by scst_mutex */

/* 
 * This buffer and lock are intended to avoid memory allocation, which
 * could fail in improper places.
 */
spinlock_t scst_temp_UA_lock = SPIN_LOCK_UNLOCKED;
uint8_t scst_temp_UA[SCST_SENSE_BUFFERSIZE];

module_param_named(scst_threads, scst_threads, int, 0);
MODULE_PARM_DESC(scst_threads, "SCSI target threads count");

module_param_named(scst_max_cmd_mem, scst_max_cmd_mem, long, 0);
MODULE_PARM_DESC(scst_max_cmd_mem, "Maximum memory allowed to be consumed by "
	"the SCST commands at any given time in Mb");

int scst_register_target_template(struct scst_tgt_template *vtt)
{
	int res = 0;
	struct scst_tgt_template *t;
	static DECLARE_MUTEX(m);

	TRACE_ENTRY();

	INIT_LIST_HEAD(&vtt->tgt_list);

	if (!vtt->detect) {
		PRINT_ERROR_PR("Target driver %s doesn't have a "
			"detect() method.", vtt->name);
		res = -EINVAL;
		goto out_err;
	}
	
	if (!vtt->release) {
		PRINT_ERROR_PR("Target driver %s doesn't have a "
			"release() method.", vtt->name);
		res = -EINVAL;
		goto out_err;
	}

	if (!vtt->xmit_response) {
		PRINT_ERROR_PR("Target driver %s doesn't have a "
			"xmit_response() method.", vtt->name);
		res = -EINVAL;
		goto out_err;
	}

	if (vtt->threads_num < 0) {
		PRINT_ERROR_PR("Wrong threads_num value %d for "
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

	if (vtt->preprocessing_done == NULL)
		vtt->preprocessing_done_atomic = 1;

	if (down_interruptible(&m) != 0)
		goto out_err;

	if (down_interruptible(&scst_mutex) != 0)
		goto out_m_up;
	list_for_each_entry(t, &scst_template_list, scst_template_list_entry) {
		if (strcmp(t->name, vtt->name) == 0) {
			PRINT_ERROR_PR("Target driver %s already registered",
				vtt->name);
			up(&scst_mutex);
			goto out_cleanup;
		}
	}
	up(&scst_mutex);

	TRACE_DBG("%s", "Calling target driver's detect()");
	res = vtt->detect(vtt);
	TRACE_DBG("Target driver's detect() returned %d", res);
	if (res < 0) {
		PRINT_ERROR_PR("%s", "The detect() routine failed");
		res = -EINVAL;
		goto out_cleanup;
	}

	down(&scst_mutex);
	list_add_tail(&vtt->scst_template_list_entry, &scst_template_list);
	up(&scst_mutex);

	res = 0;

	PRINT_INFO_PR("Target template %s registered successfully", vtt->name);

	up(&m);

out:
	TRACE_EXIT_RES(res);
	return res;

out_m_up:
	up(&m);

out_cleanup:
	scst_cleanup_proc_target_dir_entries(vtt);

out_err:
	PRINT_ERROR_PR("Failed to register target template %s", vtt->name);
	goto out;
}

void scst_unregister_target_template(struct scst_tgt_template *vtt)
{
	struct scst_tgt *tgt;
	struct scst_tgt_template *t;
	int found = 0;

	TRACE_ENTRY();

	down(&scst_mutex);

	list_for_each_entry(t, &scst_template_list, scst_template_list_entry) {
		if (strcmp(t->name, vtt->name) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		PRINT_ERROR_PR("Target driver %s isn't registered", vtt->name);
		goto out_up;
	}

restart:
	list_for_each_entry(tgt, &vtt->tgt_list, tgt_list_entry) {
		up(&scst_mutex);
		scst_unregister(tgt);
		down(&scst_mutex);
		goto restart;
	}
	list_del(&vtt->scst_template_list_entry);

	PRINT_INFO_PR("Target template %s unregistered successfully", vtt->name);

out_up:
	up(&scst_mutex);

	scst_cleanup_proc_target_dir_entries(vtt);

	TRACE_EXIT();
	return;
}

struct scst_tgt *scst_register(struct scst_tgt_template *vtt,
	const char *target_name)
{
	struct scst_tgt *tgt;

	TRACE_ENTRY();

	tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
	if (tgt == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "kzalloc() failed");
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

	scst_suspend_activity();
	down(&scst_mutex);

	if (target_name != NULL) {
		int len = strlen(target_name) + 1 +
			strlen(SCST_DEFAULT_ACG_NAME) + 1;

		tgt->default_group_name = kmalloc(len, GFP_KERNEL);
		if (tgt->default_group_name == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of default "
				"group name failed");
			goto out_free_err;
		}
		sprintf(tgt->default_group_name, "%s_%s", SCST_DEFAULT_ACG_NAME,
			target_name);
	}

	if (scst_build_proc_target_entries(tgt) < 0)
		goto out_free_name;
	else
		list_add_tail(&tgt->tgt_list_entry, &vtt->tgt_list);

	up(&scst_mutex);
	scst_resume_activity();

	PRINT_INFO_PR("Target %s for template %s registered successfully",
		target_name, vtt->name);

out:
	TRACE_EXIT();
	return tgt;

out_free_name:
	if (tgt->default_group_name)
		kfree(tgt->default_group_name);

out_free_err:
	up(&scst_mutex);
	scst_resume_activity();

	kfree(tgt);
	tgt = NULL;

out_err:
	PRINT_ERROR_PR("Failed to register target for template %s", vtt->name);
	goto out;
}

static inline int test_sess_list(struct scst_tgt *tgt)
{
	int res;
	down(&scst_mutex);
	res = list_empty(&tgt->sess_list);
	up(&scst_mutex);
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

	down(&scst_mutex);
	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		sBUG_ON(!sess->shutting_down);
	}
	up(&scst_mutex);

	TRACE_DBG("%s", "Waiting for sessions shutdown");
	wait_event(tgt->unreg_waitQ, test_sess_list(tgt));
	TRACE_DBG("%s", "wait_event() returned");

	scst_suspend_activity();
	down(&scst_mutex);

	list_del(&tgt->tgt_list_entry);

	scst_cleanup_proc_target_entries(tgt);

	if (tgt->default_group_name)
		kfree(tgt->default_group_name);

	up(&scst_mutex);
	scst_resume_activity();

	del_timer_sync(&tgt->retry_timer);

	kfree(tgt);

	PRINT_INFO_PR("Target for template %s unregistered successfully",
		vtt->name);

	TRACE_EXIT();
	return;
}

void scst_suspend_activity(void)
{
	TRACE_ENTRY();

	down(&scst_suspend_mutex);

	TRACE_MGMT_DBG("suspend_count %d", suspend_count);
	suspend_count++;
	if (suspend_count > 1)
		goto out_up;

	set_bit(SCST_FLAG_SUSPENDING, &scst_flags);
	set_bit(SCST_FLAG_SUSPENDED, &scst_flags);
	smp_mb__after_set_bit();

	TRACE_MGMT_DBG("Waiting for %d active commands to complete",
	      atomic_read(&scst_cmd_count));
	wait_event(scst_dev_cmd_waitQ, atomic_read(&scst_cmd_count) == 0);
	TRACE_MGMT_DBG("%s", "wait_event() returned");

	clear_bit(SCST_FLAG_SUSPENDING, &scst_flags);
	smp_mb__after_clear_bit();

	TRACE_MGMT_DBG("Waiting for %d active commands finally to complete",
	      atomic_read(&scst_cmd_count));
	wait_event(scst_dev_cmd_waitQ, atomic_read(&scst_cmd_count) == 0);
	TRACE_MGMT_DBG("%s", "wait_event() returned");

out_up:
	up(&scst_suspend_mutex);

	TRACE_EXIT();
	return;
}

void scst_resume_activity(void)
{
	struct scst_cmd_lists *l;

	TRACE_ENTRY();

	down(&scst_suspend_mutex);

	TRACE_MGMT_DBG("suspend_count %d", suspend_count);
	suspend_count--;
	if (suspend_count > 0)
		goto out_up;

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

out_up:
	up(&scst_suspend_mutex);

	TRACE_EXIT();
	return;
}

static int scst_register_device(struct scsi_device *scsidp)
{
	int res = 0;
	struct scst_device *dev;
	struct scst_dev_type *dt;

	TRACE_ENTRY();

	scst_suspend_activity();
	down(&scst_mutex);

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
	up(&scst_mutex);
	scst_resume_activity();

	if (res == 0) {
		PRINT_INFO_PR("Attached SCSI target mid-level at "
		    "scsi%d, channel %d, id %d, lun %d, type %d", 
		    scsidp->host->host_no, scsidp->channel, scsidp->id, 
		    scsidp->lun, scsidp->type);
	} 
	else {
		PRINT_ERROR_PR("Failed to attach SCSI target mid-level "
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
	
	scst_suspend_activity();
	down(&scst_mutex);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (d->scsi_dev == scsidp) {
			dev = d;
			TRACE_DBG("Target device %p found", dev);
			break;
		}
	}
	if (dev == NULL) {
		PRINT_ERROR_PR("%s", "Target device not found");
		goto out_unblock;
	}

	list_del(&dev->dev_list_entry);
	
	list_for_each_entry_safe(acg_dev, aa, &dev->dev_acg_dev_list,
				 dev_acg_dev_list_entry) 
	{
		scst_acg_remove_dev(acg_dev->acg, dev);
	}

	scst_assign_dev_handler(dev, NULL);

	put_disk(dev->rq_disk);
	scst_free_device(dev);

	PRINT_INFO_PR("Detached SCSI target mid-level from scsi%d, channel %d, "
		"id %d, lun %d, type %d", scsidp->host->host_no,
		scsidp->channel, scsidp->id, scsidp->lun, scsidp->type);

out_unblock:
	up(&scst_mutex);
	scst_resume_activity();

	TRACE_EXIT();
	return;
}

static int scst_dev_handler_check(struct scst_dev_type *dev_handler)
{
	int res = 0;

	if (dev_handler->parse == NULL) {
		PRINT_ERROR_PR("scst dev_type driver %s doesn't have a "
			"parse() method.", dev_handler->name);
		res = -EINVAL;
		goto out;
	}

	if (dev_handler->exec == NULL)
		dev_handler->exec_atomic = 1;

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
		PRINT_ERROR_PR("%s: valid device handler must be supplied", 
			__FUNCTION__);
		res = -EINVAL;
		goto out;
	}
	
	if (dev_name == NULL) {
		PRINT_ERROR_PR("%s: device name must be non-NULL", __FUNCTION__);
		res = -EINVAL;
		goto out;
	}

	res = scst_dev_handler_check(dev_handler);
	if (res != 0)
		goto out;

	scst_suspend_activity();
	if (down_interruptible(&scst_mutex) != 0) {
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
	up(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	if (res > 0) {
		PRINT_INFO_PR("Attached SCSI target mid-level to virtual "
		    "device %s (id %d)", dev_name, dev->virt_id);
	} 
	else {
		PRINT_INFO_PR("Failed to attach SCSI target mid-level to "
		    "virtual device %s", dev_name);
	}

	TRACE_EXIT_RES(res);
	return res;

out_free_del:
	list_del(&dev->dev_list_entry);
	scst_free_device(dev);
	goto out_up;
}

void scst_unregister_virtual_device(int id)
{
	struct scst_device *d, *dev = NULL;
	struct scst_acg_dev *acg_dev, *aa;

	TRACE_ENTRY();

	scst_suspend_activity();
	down(&scst_mutex);

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (d->virt_id == id) {
			dev = d;
			TRACE_DBG("Target device %p found", dev);
			break;
		}
	}
	if (dev == NULL) {
		PRINT_ERROR_PR("%s", "Target device not found");
		goto out_unblock;
	}

	list_del(&dev->dev_list_entry);
	
	list_for_each_entry_safe(acg_dev, aa, &dev->dev_acg_dev_list,
				 dev_acg_dev_list_entry) 
	{
		scst_acg_remove_dev(acg_dev->acg, dev);
	}

	scst_assign_dev_handler(dev, NULL);

	PRINT_INFO_PR("Detached SCSI target mid-level from virtual device %s "
		"(id %d)", dev->virt_name, dev->virt_id);

	scst_free_device(dev);

out_unblock:
	up(&scst_mutex);
	scst_resume_activity();

	TRACE_EXIT();
	return;
}

int scst_register_dev_driver(struct scst_dev_type *dev_type)
{
	struct scst_dev_type *dt;
	struct scst_device *dev;
	int res;
	int exist;

	TRACE_ENTRY();

	res = scst_dev_handler_check(dev_type);
	if (res != 0)
		goto out_err;

#ifdef VDISK_ONLY
	if (dev_type->exec == NULL) {
		PRINT_ERROR_PR("Pass-through dev handlers (handler \"%s\") not "
			"supported. Recompile SCST with undefined VDISK_ONLY",
			dev_type->name);
		res = -EINVAL;
		goto out_err;
	}
#endif

	scst_suspend_activity();
	if (down_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_err;
	}

	exist = 0;
	list_for_each_entry(dt, &scst_dev_type_list, dev_type_list_entry) {
		if (strcmp(dt->name, dev_type->name) == 0) {
			PRINT_ERROR_PR("Device type handler \"%s\" already "
				"exist", dt->name);
			exist = 1;
			break;
		}
	}
	if (exist)
		goto out_up;

	res = scst_build_proc_dev_handler_dir_entries(dev_type);
	if (res < 0) {
		goto out_up;
	}

	list_add_tail(&dev_type->dev_type_list_entry, &scst_dev_type_list);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		if ((dev->scsi_dev == NULL) || (dev->handler != NULL))
			continue;
		if (dev->scsi_dev->type == dev_type->type)
			scst_assign_dev_handler(dev, dev_type);
	}

	up(&scst_mutex);
	scst_resume_activity();

	if (res == 0) {
		PRINT_INFO_PR("Device handler \"%s\" for type %d registered "
			"successfully", dev_type->name, dev_type->type);
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_up:
	up(&scst_mutex);

out_err:
	scst_resume_activity();
	PRINT_ERROR_PR("Failed to register device handler \"%s\" for type %d",
		dev_type->name, dev_type->type);
	goto out;
}

void scst_unregister_dev_driver(struct scst_dev_type *dev_type)
{
	struct scst_device *dev;
	struct scst_dev_type *dt;
	int found = 0;

	TRACE_ENTRY();

	scst_suspend_activity();
	down(&scst_mutex);

	list_for_each_entry(dt, &scst_dev_type_list, dev_type_list_entry) {
		if (strcmp(dt->name, dev_type->name) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		PRINT_ERROR_PR("Dev handler \"%s\" isn't registered",
			dev_type->name);
		goto out_up;
	}

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		if (dev->handler == dev_type) {
			scst_assign_dev_handler(dev, NULL);
			TRACE_DBG("Dev handler removed from device %p", dev);
		}
	}

	list_del(&dev_type->dev_type_list_entry);

	up(&scst_mutex);
	scst_resume_activity();

	scst_cleanup_proc_dev_handler_dir_entries(dev_type);

	PRINT_INFO_PR("Device handler \"%s\" for type %d unloaded",
		   dev_type->name, dev_type->type);

out:
	TRACE_EXIT();
	return;

out_up:
	up(&scst_mutex);
	scst_resume_activity();
	goto out;
}

int scst_register_virtual_dev_driver(struct scst_dev_type *dev_type)
{
	int res;

	TRACE_ENTRY();

	res = scst_dev_handler_check(dev_type);
	if (res != 0)
		goto out_err;

	if (!dev_type->no_proc) {
		res = scst_build_proc_dev_handler_dir_entries(dev_type);
		if (res < 0)
			goto out_err;
	}

	if (dev_type->type != -1) {
		PRINT_INFO_PR("Virtual device handler %s for type %d "
			"registered successfully", dev_type->name,
			dev_type->type);
	} else {
		PRINT_INFO_PR("Virtual device handler \"%s\" registered "
			"successfully", dev_type->name);
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	PRINT_ERROR_PR("Failed to register virtual device handler \"%s\"",
		dev_type->name);
	goto out;
}

void scst_unregister_virtual_dev_driver(struct scst_dev_type *dev_type)
{
	TRACE_ENTRY();

	if (!dev_type->no_proc)
		scst_cleanup_proc_dev_handler_dir_entries(dev_type);

	PRINT_INFO_PR("Device handler \"%s\" unloaded", dev_type->name);

	TRACE_EXIT();
	return;
}

/* Called under scst_mutex and suspended activity */
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
			PRINT_ERROR_PR("Failed to allocate thr %d", res);
			goto out;
		}
		strncpy(nm, dev->handler->name, ARRAY_SIZE(nm)-1);
		nm[ARRAY_SIZE(nm)-1] = '\0';
		thr->cmd_thread = kthread_run(scst_cmd_thread,
			&dev->cmd_lists, "%sd%d_%d", nm, dev->dev_num, n++);
		if (IS_ERR(thr->cmd_thread)) {
			res = PTR_ERR(thr->cmd_thread);
			PRINT_ERROR_PR("kthread_create() failed: %d", res);
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

	down(&scst_suspend_mutex);
	list_add_tail(&dev->cmd_lists.lists_list_entry,
		&scst_cmd_lists_list);
	up(&scst_suspend_mutex);

	dev->p_cmd_lists = &dev->cmd_lists;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_mutex and suspended activity */
void scst_del_dev_threads(struct scst_device *dev, int num)
{
	struct scst_cmd_thread_t *ct, *tmp;
	int i = 0;

	TRACE_ENTRY();

	list_for_each_entry_safe(ct, tmp, &dev->threads_list,
				thread_list_entry) {
		int rc = kthread_stop(ct->cmd_thread);
		if (rc < 0) {
			TRACE_MGMT_DBG("kthread_stop() failed: %d", rc);
		}
		list_del(&ct->thread_list_entry);
		kfree(ct);
		if ((num >0) && (++i >= num))
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
		down(&scst_suspend_mutex);
		list_del(&dev->cmd_lists.lists_list_entry);
		up(&scst_suspend_mutex);
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
			PRINT_ERROR_PR("New device handler's %s attach() "
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
				PRINT_ERROR_PR("Device handler's %s attach_tgt() "
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
		dev->handler = NULL;
	
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
	down(&scst_threads_info.cmd_threads_mutex);
	i = scst_threads_info.nr_cmd_threads;
	up(&scst_threads_info.cmd_threads_mutex);
	return i;
}

static void scst_threads_info_init(void)
{
	memset(&scst_threads_info, 0, sizeof(scst_threads_info));
	init_MUTEX(&scst_threads_info.cmd_threads_mutex);
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
		PRINT_ERROR_PR("can not del %d cmd threads from %d", num, i);
		return;
	}

	list_for_each_entry_safe(ct, tmp, &scst_threads_info.cmd_threads_list,
				thread_list_entry) {
		int res;

		res = kthread_stop(ct->cmd_thread);
		if (res < 0) {
			TRACE_MGMT_DBG("kthread_stop() failed: %d", res);
		}
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
	static int scst_thread_num = 0;
	
	TRACE_ENTRY();

	for (i = 0; i < num; i++) {
		struct scst_cmd_thread_t *thr;

		thr = kmalloc(sizeof(*thr), GFP_KERNEL);
		if (!thr) {
			res = -ENOMEM;
			PRINT_ERROR_PR("fail to allocate thr %d", res);
			goto out_error;
		}
		thr->cmd_thread = kthread_run(scst_cmd_thread,
			&scst_main_cmd_lists, "scsi_tgt%d",
			scst_thread_num++);
		if (IS_ERR(thr->cmd_thread)) {
			res = PTR_ERR(thr->cmd_thread);
			PRINT_ERROR_PR("kthread_create() failed: %d", res);
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

	down(&scst_threads_info.cmd_threads_mutex);
	res = __scst_add_cmd_threads(num);
	up(&scst_threads_info.cmd_threads_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

void scst_del_cmd_threads(int num)
{
	TRACE_ENTRY();

	down(&scst_threads_info.cmd_threads_mutex);
	__scst_del_cmd_threads(num);
	up(&scst_threads_info.cmd_threads_mutex);

	TRACE_EXIT();
	return;
}

static void scst_stop_all_threads(void)
{
	TRACE_ENTRY();

	down(&scst_threads_info.cmd_threads_mutex);
	__scst_del_cmd_threads(scst_threads_info.nr_cmd_threads);
	if (scst_threads_info.mgmt_cmd_thread)
		kthread_stop(scst_threads_info.mgmt_cmd_thread);
	if (scst_threads_info.mgmt_thread)
		kthread_stop(scst_threads_info.mgmt_thread);
	if (scst_threads_info.init_cmd_thread)
		kthread_stop(scst_threads_info.init_cmd_thread);
	up(&scst_threads_info.cmd_threads_mutex);

	TRACE_EXIT();
	return;
}

static int scst_start_all_threads(int num)
{
	int res;

	TRACE_ENTRY();

	down(&scst_threads_info.cmd_threads_mutex);		
        res = __scst_add_cmd_threads(num);
        if (res < 0)
                goto out;

	scst_threads_info.init_cmd_thread = kthread_run(scst_init_cmd_thread,
                NULL, "scsi_tgt_init");
        if (IS_ERR(scst_threads_info.init_cmd_thread)) {
		res = PTR_ERR(scst_threads_info.init_cmd_thread);
                PRINT_ERROR_PR("kthread_create() for init cmd failed: %d", res);
                scst_threads_info.init_cmd_thread = NULL;
                goto out;
        }

        scst_threads_info.mgmt_cmd_thread = kthread_run(scst_mgmt_cmd_thread,
                NULL, "scsi_tgt_mc");
        if (IS_ERR(scst_threads_info.mgmt_cmd_thread)) {
		res = PTR_ERR(scst_threads_info.mgmt_cmd_thread);
                PRINT_ERROR_PR("kthread_create() for mcmd failed: %d", res);
                scst_threads_info.mgmt_cmd_thread = NULL;
                goto out;
        }

        scst_threads_info.mgmt_thread = kthread_run(scst_mgmt_thread,
                NULL, "scsi_tgt_mgmt");
        if (IS_ERR(scst_threads_info.mgmt_thread)) {
		res = PTR_ERR(scst_threads_info.mgmt_thread);
                PRINT_ERROR_PR("kthread_create() for mgmt failed: %d", res);
                scst_threads_info.mgmt_thread = NULL;
                goto out;
        }

out:
	up(&scst_threads_info.cmd_threads_mutex);
	TRACE_EXIT_RES(res);
	return res;	
}

void scst_get(void)
{
	__scst_get(0);
}

void scst_put(void)
{
	__scst_put();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
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

static int __init init_scst(void)
{
	int res = 0, i;
	struct scst_cmd *cmd;
	int scst_num_cpus;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	{
		struct scsi_request *req;
		BUILD_BUG_ON(sizeof(cmd->sense_buffer) !=
			sizeof(req->sr_sense_buffer));
	}
#else
	{
		struct scsi_sense_hdr *shdr;
		BUILD_BUG_ON((sizeof(cmd->sense_buffer) < sizeof(*shdr)) &&
			(sizeof(cmd->sense_buffer) >= SCST_SENSE_BUFFERSIZE));
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

	spin_lock_init(&scst_main_cmd_lists.cmd_list_lock);
	INIT_LIST_HEAD(&scst_main_cmd_lists.active_cmd_list);
	init_waitqueue_head(&scst_main_cmd_lists.cmd_list_waitQ);
	list_add_tail(&scst_main_cmd_lists.lists_list_entry,
		&scst_cmd_lists_list);

	scst_num_cpus = num_online_cpus();

	/* ToDo: register_cpu_notifier() */
	
	if (scst_threads == 0)
		scst_threads = scst_num_cpus;
		
	if (scst_threads < scst_num_cpus) {
		PRINT_ERROR_PR("%s", "scst_threads can not be less than "
			"CPUs count");
		scst_threads = scst_num_cpus;
	}

	scst_threads_info_init();

#define INIT_CACHEP(p, s, t, o) do {					\
		p = kmem_cache_create(s, sizeof(struct t), 0,		\
				      SCST_SLAB_FLAGS, NULL, NULL);	\
		TRACE_MEM("Slab create: %s at %p size %zd", s, p,	\
			  sizeof(struct t));				\
		if (p == NULL) { res = -ENOMEM; goto o; }		\
	} while (0)
	  
	INIT_CACHEP(scst_mgmt_cachep, SCST_MGMT_CMD_CACHE_STRING, 
		    scst_mgmt_cmd, out);
	INIT_CACHEP(scst_ua_cachep, SCST_UA_CACHE_STRING, 
		    scst_tgt_dev_UA, out_destroy_mgmt_cache);
	INIT_CACHEP(scst_cmd_cachep,  SCST_CMD_CACHE_STRING, 
		    scst_cmd, out_destroy_ua_cache);
	INIT_CACHEP(scst_sess_cachep, SCST_SESSION_CACHE_STRING,
		    scst_session, out_destroy_cmd_cache);
	INIT_CACHEP(scst_tgtd_cachep, SCST_TGT_DEV_CACHE_STRING,
		    scst_tgt_dev, out_destroy_sess_cache);
	INIT_CACHEP(scst_acgd_cachep, SCST_ACG_DEV_CACHE_STRING,
		    scst_acg_dev, out_destroy_tgt_cache);

	scst_mgmt_mempool = mempool_create(10, mempool_alloc_slab,
		mempool_free_slab, scst_mgmt_cachep);
	if (scst_mgmt_mempool == NULL) {
		res = -ENOMEM;
		goto out_destroy_acg_cache;
	}

	scst_ua_mempool = mempool_create(25, mempool_alloc_slab,
		mempool_free_slab, scst_ua_cachep);
	if (scst_ua_mempool == NULL) {
		res = -ENOMEM;
		goto out_destroy_mgmt_mempool;
	}

	res = scst_sgv_pools_init(&scst_sgv);
	if (res != 0)
		goto out_destroy_ua_mempool;

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
		tasklet_init(&scst_tasklets[i].tasklet, (void*)scst_cmd_tasklet,
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

	if (scst_max_cmd_mem == 0) {
		struct sysinfo si;
		si_meminfo(&si);
#if BITS_PER_LONG == 32
		scst_max_cmd_mem = min(((uint64_t)si.totalram << PAGE_SHIFT) >> 2,
					(uint64_t)1 << 30);
#else
		scst_max_cmd_mem = (si.totalram << PAGE_SHIFT) >> 2;
#endif
	} else
		scst_max_cmd_mem <<= 20;

	scst_cur_max_cmd_mem = scst_max_cmd_mem;

	PRINT_INFO_PR("SCST version %s loaded successfully (max mem for "
		"commands %ld Mb)", SCST_VERSION_STRING, scst_max_cmd_mem >> 20);

out:
	TRACE_EXIT_RES(res);
	return res;

out_thread_free:
	scst_stop_all_threads();

	scsi_unregister_interface(&scst_interface);

out_free_acg:
	scst_destroy_acg(scst_default_acg);

out_destroy_sgv_pool:
	scst_sgv_pools_deinit(&scst_sgv);

out_destroy_ua_mempool:
	mempool_destroy(scst_ua_mempool);

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

out_destroy_ua_cache:
	kmem_cache_destroy(scst_ua_cachep);

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

	if (test_bit(SCST_FLAG_CMD_MEM_WORK_SCHEDULED, &scst_flags)) {
		cancel_delayed_work(&scst_cmd_mem_work);
		flush_scheduled_work();
	}

	scst_proc_cleanup_module();

	scst_stop_all_threads();

	scsi_unregister_interface(&scst_interface);
	scst_destroy_acg(scst_default_acg);

	scst_sgv_pools_deinit(&scst_sgv);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define DEINIT_CACHEP(p, s) do {			\
		if (kmem_cache_destroy(p)) {		\
			PRINT_INFO_PR("kmem_cache_destroy of %s returned an "\
				"error", s);		\
		}					\
		p = NULL;				\
	} while (0)
#else
#define DEINIT_CACHEP(p, s) do {			\
		kmem_cache_destroy(p);			\
                p = NULL;				\
	} while (0)
#endif

	mempool_destroy(scst_mgmt_mempool);
	mempool_destroy(scst_ua_mempool);

	DEINIT_CACHEP(scst_mgmt_cachep, SCST_MGMT_CMD_CACHE_STRING);
	DEINIT_CACHEP(scst_ua_cachep, SCST_UA_CACHE_STRING);
	DEINIT_CACHEP(scst_cmd_cachep, SCST_CMD_CACHE_STRING);
	DEINIT_CACHEP(scst_sess_cachep, SCST_SESSION_CACHE_STRING);
	DEINIT_CACHEP(scst_tgtd_cachep, SCST_TGT_DEV_CACHE_STRING);
	DEINIT_CACHEP(scst_acgd_cachep, SCST_ACG_DEV_CACHE_STRING);

	PRINT_INFO_PR("%s", "SCST unloaded");

	TRACE_EXIT();
	return;
}

/*
 * Device Handler Side (i.e. scst_vdisk)
 */
EXPORT_SYMBOL(scst_register_dev_driver);
EXPORT_SYMBOL(scst_unregister_dev_driver);
EXPORT_SYMBOL(scst_register);
EXPORT_SYMBOL(scst_unregister);

EXPORT_SYMBOL(scst_register_virtual_device);
EXPORT_SYMBOL(scst_unregister_virtual_device);
EXPORT_SYMBOL(scst_register_virtual_dev_driver);
EXPORT_SYMBOL(scst_unregister_virtual_dev_driver);

EXPORT_SYMBOL(scst_set_busy);
EXPORT_SYMBOL(scst_set_cmd_error_status);
EXPORT_SYMBOL(scst_set_cmd_error);
EXPORT_SYMBOL(scst_set_resp_data_len);

EXPORT_SYMBOL(scst_process_active_cmd);

/*
 * Target Driver Side (i.e. HBA)
 */
EXPORT_SYMBOL(scst_register_session);
EXPORT_SYMBOL(scst_unregister_session);

EXPORT_SYMBOL(scst_register_target_template);
EXPORT_SYMBOL(scst_unregister_target_template);

EXPORT_SYMBOL(scst_cmd_init_done);
EXPORT_SYMBOL(scst_tgt_cmd_done);
EXPORT_SYMBOL(scst_restart_cmd);
EXPORT_SYMBOL(scst_rx_cmd);
EXPORT_SYMBOL(scst_rx_data);
EXPORT_SYMBOL(scst_rx_mgmt_fn_tag);
EXPORT_SYMBOL(scst_rx_mgmt_fn_lun);

EXPORT_SYMBOL(scst_find_cmd);
EXPORT_SYMBOL(scst_find_cmd_by_tag);

/*
 * Global Commands
 */
EXPORT_SYMBOL(scst_suspend_activity);
EXPORT_SYMBOL(scst_resume_activity);

EXPORT_SYMBOL(scst_add_cmd_threads);
EXPORT_SYMBOL(scst_del_cmd_threads);

#if defined(DEBUG) || defined(TRACING)
EXPORT_SYMBOL(scst_proc_log_entry_read);
EXPORT_SYMBOL(scst_proc_log_entry_write);
#endif

EXPORT_SYMBOL(scst_create_proc_entry);
EXPORT_SYMBOL(scst_single_seq_open);

EXPORT_SYMBOL(__scst_get_buf);
EXPORT_SYMBOL(scst_check_mem);
EXPORT_SYMBOL(scst_get);
EXPORT_SYMBOL(scst_put);

EXPORT_SYMBOL(scst_alloc);
EXPORT_SYMBOL(scst_free);

/* Tgt_dev's threads local storage */
EXPORT_SYMBOL(scst_add_thr_data);
EXPORT_SYMBOL(scst_del_all_thr_data);
EXPORT_SYMBOL(scst_dev_del_all_thr_data);
EXPORT_SYMBOL(scst_find_thr_data);

/* SGV pool routines */
EXPORT_SYMBOL(sgv_pool_create);
EXPORT_SYMBOL(sgv_pool_destroy);
EXPORT_SYMBOL(sgv_pool_set_allocator);
EXPORT_SYMBOL(sgv_pool_alloc);
EXPORT_SYMBOL(sgv_pool_free);
EXPORT_SYMBOL(sgv_get_priv);

/* Generic parse() routines */
EXPORT_SYMBOL(scst_calc_block_shift);
EXPORT_SYMBOL(scst_sbc_generic_parse);
EXPORT_SYMBOL(scst_cdrom_generic_parse);
EXPORT_SYMBOL(scst_modisk_generic_parse);
EXPORT_SYMBOL(scst_tape_generic_parse);
EXPORT_SYMBOL(scst_changer_generic_parse);
EXPORT_SYMBOL(scst_processor_generic_parse);
EXPORT_SYMBOL(scst_raid_generic_parse);

/* Generic dev_done() routines */
EXPORT_SYMBOL(scst_block_generic_dev_done);
EXPORT_SYMBOL(scst_tape_generic_dev_done);

/*
 * Other Commands
 */
EXPORT_SYMBOL(scst_get_cdb_info);
EXPORT_SYMBOL(scst_cmd_get_tgt_priv_lock);
EXPORT_SYMBOL(scst_cmd_set_tgt_priv_lock);

#ifdef DEBUG
EXPORT_SYMBOL(scst_random);
#endif

module_init(init_scst);
module_exit(exit_scst);

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI target core");
MODULE_VERSION(SCST_VERSION_STRING);
