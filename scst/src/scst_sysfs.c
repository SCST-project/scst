/*
 *  scst_sysfs.c
 *
 *  Copyright (C) 2009 Daniel Henrique Debonzi <debonzi@linux.vnet.ibm.com>
 *  Copyright (C) 2009 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2009 - 2010 ID7 Ltd.
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

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/kthread.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_priv.h"
#include "scst_pres.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
#ifdef CONFIG_LOCKDEP
static struct lock_class_key scst_tgtt_key;
static struct lockdep_map scst_tgtt_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_tgtt_kref", &scst_tgtt_key);
static struct lock_class_key scst_tgt_key;
static struct lockdep_map scst_tgt_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_tgt_kref", &scst_tgt_key);
static struct lock_class_key scst_devt_key;
static struct lockdep_map scst_devt_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_devt_kref", &scst_devt_key);
static struct lock_class_key scst_dev_key;
struct lockdep_map scst_dev_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_dev_kref", &scst_dev_key);
EXPORT_SYMBOL(scst_dev_dep_map);
static struct lock_class_key scst_sess_key;
static struct lockdep_map scst_sess_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_sess_kref", &scst_sess_key);
static struct lock_class_key scst_acg_dev_key;
static struct lockdep_map scst_acg_dev_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_acg_dev_kref", &scst_acg_dev_key);
static struct lock_class_key scst_acg_key;
static struct lockdep_map scst_acg_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_acg_kref", &scst_acg_key);
static struct lock_class_key scst_tgt_dev_key;
static struct lockdep_map scst_tgt_dev_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_tgt_dev_kref", &scst_tgt_dev_key);
static struct lock_class_key scst_dg_key;
static struct lockdep_map scst_dg_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_dg_kref", &scst_dg_key);
static struct lock_class_key scst_tg_key;
static struct lockdep_map scst_tg_dep_map =
	STATIC_LOCKDEP_MAP_INIT("scst_tg_kref", &scst_tg_key);
#endif
#endif

static DECLARE_COMPLETION(scst_sysfs_root_release_completion);

static struct kobject *scst_targets_kobj;
static struct kobject *scst_devices_kobj;
static struct kobject *scst_handlers_kobj;
static struct kobject *scst_device_groups_kobj;

static const char *const scst_dev_handler_types[] = {
	"Direct-access device (e.g., magnetic disk)",
	"Sequential-access device (e.g., magnetic tape)",
	"Printer device",
	"Processor device",
	"Write-once device (e.g., some optical disks)",
	"CD-ROM device",
	"Scanner device (obsolete)",
	"Optical memory device (e.g., some optical disks)",
	"Medium changer device (e.g., jukeboxes)",
	"Communications device (obsolete)",
	"Defined by ASC IT8 (Graphic arts pre-press devices)",
	"Defined by ASC IT8 (Graphic arts pre-press devices)",
	"Storage array controller device (e.g., RAID)",
	"Enclosure services device",
	"Simplified direct-access device (e.g., magnetic disk)",
	"Optical card reader/writer device"
};

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static DEFINE_MUTEX(scst_log_mutex);

static struct scst_trace_log scst_trace_tbl[] = {
	{ TRACE_OUT_OF_MEM,	"out_of_mem"	},
	{ TRACE_MINOR,		"minor"		},
	{ TRACE_SG_OP,		"sg"		},
	{ TRACE_MEMORY,		"mem"		},
	{ TRACE_BUFF,		"buff"		},
#ifndef GENERATING_UPSTREAM_PATCH
	{ TRACE_ENTRYEXIT,	"entryexit"	},
#endif
	{ TRACE_PID,		"pid"		},
	{ TRACE_LINE,		"line"		},
	{ TRACE_FUNCTION,	"function"	},
	{ TRACE_DEBUG,		"debug"		},
	{ TRACE_SPECIAL,	"special"	},
	{ TRACE_SCSI,		"scsi"		},
	{ TRACE_MGMT,		"mgmt"		},
	{ TRACE_MGMT_DEBUG,	"mgmt_dbg"	},
	{ TRACE_FLOW_CONTROL,	"flow_control"	},
	{ TRACE_PRES,		"pr"		},
	{ 0,			NULL		}
};

static struct scst_trace_log scst_local_trace_tbl[] = {
	{ TRACE_RTRY,			"retry"			},
	{ TRACE_SCSI_SERIALIZING,	"scsi_serializing"	},
	{ TRACE_DATA_SEND,              "data_send"		},
	{ TRACE_DATA_RECEIVED,          "data_received"		},
	{ TRACE_BLOCKING,		"block"			},
	{ 0,				NULL			}
};

static void scst_read_trace_tbl(const struct scst_trace_log *tbl, char *buf,
	unsigned long log_level, int *pos)
{
	const struct scst_trace_log *t = tbl;

	if (t == NULL)
		goto out;

	while (t->token) {
		if (log_level & t->val) {
			*pos += sprintf(&buf[*pos], "%s%s",
					(*pos == 0) ? "" : " | ",
					t->token);
		}
		t++;
	}
out:
	return;
}

static ssize_t scst_trace_level_show(const struct scst_trace_log *local_tbl,
	unsigned long log_level, char *buf, const char *help)
{
	int pos = 0;

	scst_read_trace_tbl(scst_trace_tbl, buf, log_level, &pos);
	scst_read_trace_tbl(local_tbl, buf, log_level, &pos);

	pos += sprintf(&buf[pos], "\n\n\nUsage:\n"
		"	echo \"all|none|default\" >trace_level\n"
		"	echo \"value DEC|0xHEX|0OCT\" >trace_level\n"
		"	echo \"add|del TOKEN\" >trace_level\n"
		"\nwhere TOKEN is one of [debug, function, line, pid,\n"
#ifndef GENERATING_UPSTREAM_PATCH
		"		       entryexit, buff, mem, sg, out_of_mem,\n"
#else
		"		       buff, mem, sg, out_of_mem,\n"
#endif
		"		       special, scsi, mgmt, minor,\n"
		"		       mgmt_dbg, scsi_serializing,\n"
		"		       retry, recv_bot, send_bot, recv_top, pr,\n"
		"		       block, send_top%s]\n", help != NULL ? help : "");

	return pos;
}

static int scst_write_trace(const char *buf, size_t length,
	unsigned long *log_level, unsigned long default_level,
	const char *name, const struct scst_trace_log *tbl)
{
	int res;
	int action;
	unsigned long level = 0, oldlevel;
	char *buffer, *p, *pp;
	const struct scst_trace_log *t;
	enum {
		SCST_TRACE_ACTION_ALL	  = 1,
		SCST_TRACE_ACTION_NONE	  = 2,
		SCST_TRACE_ACTION_DEFAULT = 3,
		SCST_TRACE_ACTION_ADD	  = 4,
		SCST_TRACE_ACTION_DEL	  = 5,
		SCST_TRACE_ACTION_VALUE	  = 6,
	};

	TRACE_ENTRY();

	if ((buf == NULL) || (length == 0)) {
		res = -EINVAL;
		goto out;
	}

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)length, buf);
	if (buffer == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer (size %zd)",
			length+1);
		res = -ENOMEM;
		goto out;
	}

	TRACE_DBG("buffer %s", buffer);

	pp = buffer;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp("all", p) == 0) {
		action = SCST_TRACE_ACTION_ALL;
	} else if (strcasecmp("none", p) == 0 || strcasecmp("null", p) == 0) {
		action = SCST_TRACE_ACTION_NONE;
	} else if (strcasecmp("default", p) == 0) {
		action = SCST_TRACE_ACTION_DEFAULT;
	} else if (strcasecmp("add", p) == 0) {
		action = SCST_TRACE_ACTION_ADD;
	} else if (strcasecmp("del", p) == 0) {
		action = SCST_TRACE_ACTION_DEL;
	} else if (strcasecmp("value", p) == 0) {
		action = SCST_TRACE_ACTION_VALUE;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	p = scst_get_next_lexem(&pp);

	switch (action) {
	case SCST_TRACE_ACTION_ALL:
		level = TRACE_ALL;
		break;
	case SCST_TRACE_ACTION_DEFAULT:
		level = default_level;
		break;
	case SCST_TRACE_ACTION_NONE:
		level = TRACE_NULL;
		break;
	case SCST_TRACE_ACTION_ADD:
	case SCST_TRACE_ACTION_DEL:
		if (tbl) {
			t = tbl;
			while (t->token) {
				if (!strcasecmp(p, t->token)) {
					level = t->val;
					break;
				}
				t++;
			}
		}
		if (level == 0) {
			t = scst_trace_tbl;
			while (t->token) {
				if (!strcasecmp(p, t->token)) {
					level = t->val;
					break;
				}
				t++;
			}
		}
		if (level == 0) {
			PRINT_ERROR("Unknown token \"%s\"", p);
			res = -EINVAL;
			goto out_free;
		}
		break;
	case SCST_TRACE_ACTION_VALUE:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		res = kstrtoul(p, 0, &level);
#else
		res = strict_strtoul(p, 0, &level);
#endif
		if (res != 0) {
			PRINT_ERROR("Invalid trace value \"%s\"", p);
			res = -EINVAL;
			goto out_free;
		}
		break;
	}

	oldlevel = *log_level;

	switch (action) {
	case SCST_TRACE_ACTION_ADD:
		*log_level |= level;
		break;
	case SCST_TRACE_ACTION_DEL:
		*log_level &= ~level;
		break;
	default:
		*log_level = level;
		break;
	}

	PRINT_INFO("Changed trace level for \"%s\": old 0x%08lx, new 0x%08lx",
		name, oldlevel, *log_level);

	res = length;

out_free:
	kfree(buffer);
out:
	TRACE_EXIT_RES(res);
	return res;
}

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
/**
 ** Backported sysfs functions.
 **/

static int sysfs_create_files(struct kobject *kobj,
			      const struct attribute **ptr)
{
	int err = 0;
	int i;

	for (i = 0; ptr[i] && !err; i++)
		err = sysfs_create_file(kobj, ptr[i]);
	if (err)
		while (--i >= 0)
			sysfs_remove_file(kobj, ptr[i]);
	return err;
}

static void sysfs_remove_files(struct kobject *kobj,
			       const struct attribute **ptr)
{
	int i;

	for (i = 0; ptr[i]; i++)
		sysfs_remove_file(kobj, ptr[i]);
}
#endif

/**
 ** Sysfs work
 **/

static DEFINE_SPINLOCK(sysfs_work_lock);
static LIST_HEAD(sysfs_work_list);
static DECLARE_WAIT_QUEUE_HEAD(sysfs_work_waitQ);
static int active_sysfs_works;
static int last_sysfs_work_res;
static struct task_struct *sysfs_work_thread;

/**
 * scst_alloc_sysfs_work() - allocates a sysfs work
 */
int scst_alloc_sysfs_work(int (*sysfs_work_fn)(struct scst_sysfs_work_item *),
	bool read_only_action, struct scst_sysfs_work_item **res_work)
{
	int res = 0;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	if (sysfs_work_fn == NULL) {
		PRINT_ERROR("%s", "sysfs_work_fn is NULL");
		res = -EINVAL;
		goto out;
	}

	*res_work = NULL;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (work == NULL) {
		PRINT_ERROR("Unable to alloc sysfs work (size %zd)",
			sizeof(*work));
		res = -ENOMEM;
		goto out;
	}

	work->read_only_action = read_only_action;
	kref_init(&work->sysfs_work_kref);
	init_completion(&work->sysfs_work_done);
	work->sysfs_work_fn = sysfs_work_fn;

	*res_work = work;

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_alloc_sysfs_work);

static void scst_sysfs_work_release(struct kref *kref)
{
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	work = container_of(kref, struct scst_sysfs_work_item,
			sysfs_work_kref);

	TRACE_DBG("Freeing sysfs work %p (buf %p)", work, work->buf);

	kfree(work->buf);
	kfree(work->res_buf);
	kfree(work);

	TRACE_EXIT();
	return;
}

/**
 * scst_sysfs_work_get() - increases ref counter of the sysfs work
 */
void scst_sysfs_work_get(struct scst_sysfs_work_item *work)
{
	kref_get(&work->sysfs_work_kref);
}
EXPORT_SYMBOL(scst_sysfs_work_get);

/**
 * scst_sysfs_work_put() - decreases ref counter of the sysfs work
 */
void scst_sysfs_work_put(struct scst_sysfs_work_item *work)
{
	kref_put(&work->sysfs_work_kref, scst_sysfs_work_release);
}
EXPORT_SYMBOL(scst_sysfs_work_put);

/* Called under sysfs_work_lock and drops/reacquire it inside */
static void scst_process_sysfs_works(void)
	__releases(&sysfs_work_lock)
	__acquires(&sysfs_work_lock)
{
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	while (!list_empty(&sysfs_work_list)) {
		work = list_first_entry(&sysfs_work_list,
			struct scst_sysfs_work_item, sysfs_work_list_entry);
		list_del(&work->sysfs_work_list_entry);
		spin_unlock(&sysfs_work_lock);

		TRACE_DBG("Sysfs work %p", work);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
		if (work->dep_map) {
			mutex_acquire(work->dep_map, 0, 0, _RET_IP_);
			lock_acquired(work->dep_map, _RET_IP_);
		}
#endif

		work->work_res = work->sysfs_work_fn(work);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
		if (work->dep_map)
			mutex_release(work->dep_map, 0, _RET_IP_);
#endif

		spin_lock(&sysfs_work_lock);
		if (!work->read_only_action)
			last_sysfs_work_res = work->work_res;
		active_sysfs_works--;
		spin_unlock(&sysfs_work_lock);

		complete_all(&work->sysfs_work_done);
		kref_put(&work->sysfs_work_kref, scst_sysfs_work_release);

		spin_lock(&sysfs_work_lock);
	}

	TRACE_EXIT();
	return;
}

static inline int test_sysfs_work_list(void)
{
	int res = !list_empty(&sysfs_work_list) ||
		  unlikely(kthread_should_stop());
	return res;
}

static int sysfs_work_thread_fn(void *arg)
{
	bool one_time_only = (bool)arg;

	TRACE_ENTRY();

	if (!one_time_only)
		PRINT_INFO("User interface thread started, PID %d", current->pid);

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock(&sysfs_work_lock);
	while (!kthread_should_stop()) {
		if (one_time_only && !test_sysfs_work_list())
			break;
		wait_event_locked(sysfs_work_waitQ, test_sysfs_work_list(),
				  lock, sysfs_work_lock);
		scst_process_sysfs_works();
	}
	spin_unlock(&sysfs_work_lock);

	if (!one_time_only) {
		/*
		 * If kthread_should_stop() is true, we are guaranteed to be
		 * on the module unload, so both lists must be empty.
		 */
		sBUG_ON(!list_empty(&sysfs_work_list));

		PRINT_INFO("User interface thread PID %d finished", current->pid);
	}

	TRACE_EXIT();
	return 0;
}

/**
 * scst_sysfs_queue_wait_work() - waits for the work to complete
 *
 * Returns status of the completed work or -EAGAIN if the work not
 * completed before timeout. In the latter case a user should poll
 * last_sysfs_mgmt_res until it returns the result of the processing.
 */
int scst_sysfs_queue_wait_work(struct scst_sysfs_work_item *work)
{
	int res = 0, rc;
	unsigned long timeout = 15*HZ;
	struct task_struct *t;
	static atomic_t uid_thread_name = ATOMIC_INIT(0);

	TRACE_ENTRY();

	spin_lock(&sysfs_work_lock);

	TRACE_DBG("Adding sysfs work %p to the list", work);
	list_add_tail(&work->sysfs_work_list_entry, &sysfs_work_list);

	active_sysfs_works++;

	kref_get(&work->sysfs_work_kref);

	spin_unlock(&sysfs_work_lock);

	wake_up(&sysfs_work_waitQ);

	/*
	 * We can have a dead lock possibility like: the sysfs thread is waiting
	 * for the last put during some object unregistration and at the same
	 * time another queued work is having reference on that object taken and
	 * waiting for attention from the sysfs thread. Generally, all sysfs
	 * functions calling kobject_get() and then queuing sysfs thread job
	 * affected by this. This is especially dangerous in read only cases,
	 * like vdev_sysfs_filename_show().
	 *
	 * So, to eliminate that deadlock we will create an extra sysfs thread
	 * for each queued sysfs work. This thread will quit as soon as it will
	 * see that there is not more queued works to process.
	 */

	t = kthread_run(sysfs_work_thread_fn, (void *)true, "scst_uid%d",
		atomic_inc_return(&uid_thread_name));
	if (IS_ERR(t))
		PRINT_ERROR("kthread_run() for user interface thread %d "
			"failed: %d", atomic_read(&uid_thread_name),
			(int)PTR_ERR(t));

#ifdef CONFIG_SCST_DEBUG_SYSFS_EAGAIN
	{
		static int cnt;

		if (!work->read_only_action || cnt++ % 4 < 3) {
			/*
			 * Helps testing user space code that writes to or
			 * reads from SCST sysfs variables.
			 */
			timeout = 0;
			rc = 0;
			res = -EAGAIN;
			goto out_put;
		}
	}
#endif

	while (1) {
		rc = wait_for_completion_interruptible_timeout(
			&work->sysfs_work_done, timeout);
		if (rc == 0) {
			if (!mutex_is_locked(&scst_mutex)) {
				TRACE_DBG("scst_mutex not locked, continue "
					"waiting (work %p)", work);
				timeout = 5*HZ;
				continue;
			}
			TRACE_MGMT_DBG("Time out waiting for work %p", work);
			res = -EAGAIN;
			goto out_put;
		} else if (rc < 0) {
			res = rc;
			goto out_put;
		}
		break;
	}

	res = work->work_res;

out_put:
	kref_put(&work->sysfs_work_kref, scst_sysfs_work_release);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_sysfs_queue_wait_work);

/* No locks */
static int scst_check_grab_tgtt_ptr(struct scst_tgt_template *tgtt)
{
	int res = 0;
	struct scst_tgt_template *tt;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	list_for_each_entry(tt, &scst_template_list, scst_template_list_entry) {
		if (tt == tgtt) {
			tgtt->tgtt_active_sysfs_works_count++;
			goto out_unlock;
		}
	}

	TRACE_DBG("Tgtt %p not found", tgtt);
	res = -ENOENT;

out_unlock:
	mutex_unlock(&scst_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

/* No locks */
static void scst_ungrab_tgtt_ptr(struct scst_tgt_template *tgtt)
{
	TRACE_ENTRY();

	mutex_lock(&scst_mutex);
	tgtt->tgtt_active_sysfs_works_count--;
	mutex_unlock(&scst_mutex);

	TRACE_EXIT();
	return;
}

/* scst_mutex supposed to be locked */
static int scst_check_tgt_acg_ptrs(struct scst_tgt *tgt, struct scst_acg *acg)
{
	int res = 0;
	struct scst_tgt_template *tgtt;

	list_for_each_entry(tgtt, &scst_template_list, scst_template_list_entry) {
		struct scst_tgt *t;
		list_for_each_entry(t, &tgtt->tgt_list, tgt_list_entry) {
			if (t == tgt) {
				struct scst_acg *a;
				if (acg == NULL)
					goto out;
				if (acg == tgt->default_acg)
					goto out;
				list_for_each_entry(a, &tgt->tgt_acg_list,
							acg_list_entry) {
					if (a == acg)
						goto out;
				}
			}
		}
	}

	TRACE_DBG("Tgt %p/ACG %p not found", tgt, acg);
	res = -ENOENT;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_mutex supposed to be locked */
static int scst_check_devt_ptr(struct scst_dev_type *devt,
	struct list_head *list)
{
	int res = 0;
	struct scst_dev_type *dt;

	TRACE_ENTRY();

	list_for_each_entry(dt, list, dev_type_list_entry) {
		if (dt == devt)
			goto out;
	}

	TRACE_DBG("Devt %p not found", devt);
	res = -ENOENT;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_mutex supposed to be locked */
static int scst_check_dev_ptr(struct scst_device *dev)
{
	int res = 0;
	struct scst_device *d;

	TRACE_ENTRY();

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (d == dev)
			goto out;
	}

	TRACE_DBG("Dev %p not found", dev);
	res = -ENOENT;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* No locks */
static int scst_check_grab_devt_ptr(struct scst_dev_type *devt,
	struct list_head *list)
{
	int res = 0;
	struct scst_dev_type *dt;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	list_for_each_entry(dt, list, dev_type_list_entry) {
		if (dt == devt) {
			devt->devt_active_sysfs_works_count++;
			goto out_unlock;
		}
	}

	TRACE_DBG("Devt %p not found", devt);
	res = -ENOENT;

out_unlock:
	mutex_unlock(&scst_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

/* No locks */
static void scst_ungrab_devt_ptr(struct scst_dev_type *devt)
{
	TRACE_ENTRY();

	mutex_lock(&scst_mutex);
	devt->devt_active_sysfs_works_count--;
	mutex_unlock(&scst_mutex);

	TRACE_EXIT();
	return;
}

/**
 ** Regular SCST sysfs ops
 **/
static ssize_t scst_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct kobj_attribute *kobj_attr;
	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	return kobj_attr->show(kobj, kobj_attr, buf);
}

static ssize_t scst_store(struct kobject *kobj, struct attribute *attr,
			  const char *buf, size_t count)
{
	struct kobj_attribute *kobj_attr;
	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	if (kobj_attr->store)
		return kobj_attr->store(kobj, kobj_attr, buf, count);
	else
		return -EIO;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
const struct sysfs_ops scst_sysfs_ops = {
#else
struct sysfs_ops scst_sysfs_ops = {
#endif
	.show = scst_show,
	.store = scst_store,
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
const struct sysfs_ops *scst_sysfs_get_sysfs_ops(void)
#else
struct sysfs_ops *scst_sysfs_get_sysfs_ops(void)
#endif
{
	return &scst_sysfs_ops;
}
EXPORT_SYMBOL_GPL(scst_sysfs_get_sysfs_ops);

/**
 ** Target Template
 **/

static void scst_tgtt_release(struct kobject *kobj)
{
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);
	if (tgtt->tgtt_kobj_release_cmpl)
		complete_all(tgtt->tgtt_kobj_release_cmpl);

	TRACE_EXIT();
	return;
}

static struct kobj_type tgtt_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_tgtt_release,
};

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_tgtt_trace_level_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt_template *tgtt;

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	return scst_trace_level_show(tgtt->trace_tbl,
		tgtt->trace_flags ? *tgtt->trace_flags : 0, buf,
		tgtt->trace_tbl_help);
}

static ssize_t scst_tgtt_trace_level_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	res = mutex_lock_interruptible(&scst_log_mutex);
	if (res != 0)
		goto out;

	res = scst_write_trace(buf, count, tgtt->trace_flags,
		tgtt->default_trace_flags, tgtt->name, tgtt->trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute tgtt_trace_attr =
	__ATTR(trace_level, S_IRUGO | S_IWUSR,
	       scst_tgtt_trace_level_show, scst_tgtt_trace_level_store);

#endif /* #if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static ssize_t scst_tgtt_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add_target target_name [parameters]\" >mgmt\n"
		"       echo \"del_target target_name\" >mgmt\n"
		"%s%s"
		"%s"
		"\n"
		"where parameters are one or more "
		"param_name=value pairs separated by ';'\n\n"
		"%s%s%s%s%s%s%s%s\n";
	struct scst_tgt_template *tgtt;

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	return scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, help,
		(tgtt->tgtt_optional_attributes != NULL) ?
			"       echo \"add_attribute <attribute> <value>\" >mgmt\n"
			"       echo \"del_attribute <attribute> <value>\" >mgmt\n" : "",
		(tgtt->tgt_optional_attributes != NULL) ?
			"       echo \"add_target_attribute target_name <attribute> <value>\" >mgmt\n"
			"       echo \"del_target_attribute target_name <attribute> <value>\" >mgmt\n" : "",
		(tgtt->mgmt_cmd_help) ? tgtt->mgmt_cmd_help : "",
		(tgtt->add_target_parameters != NULL) ?
			"The following parameters available: " : "",
		(tgtt->add_target_parameters != NULL) ?
			tgtt->add_target_parameters : "",
		(tgtt->tgtt_optional_attributes != NULL) ?
			"The following target driver attributes available: " : "",
		(tgtt->tgtt_optional_attributes != NULL) ?
			tgtt->tgtt_optional_attributes : "",
		(tgtt->tgtt_optional_attributes != NULL) ? "\n" : "",
		(tgtt->tgt_optional_attributes != NULL) ?
			"The following target attributes available: " : "",
		(tgtt->tgt_optional_attributes != NULL) ?
			tgtt->tgt_optional_attributes : "",
		(tgtt->tgt_optional_attributes != NULL) ? "\n" : "");
}

static int scst_process_tgtt_mgmt_store(char *buffer,
	struct scst_tgt_template *tgtt)
{
	int res = 0;
	char *p, *pp, *target_name;

	TRACE_ENTRY();

	TRACE_DBG("buffer %s", buffer);

	/* Check if our pointer is still alive and, if yes, grab it */
	if (scst_check_grab_tgtt_ptr(tgtt) != 0)
		goto out;

	pp = buffer;
	p = scst_get_next_lexem(&pp);

	if (strcasecmp("add_target", p) == 0) {
		target_name = scst_get_next_lexem(&pp);
		if (*target_name == '\0') {
			PRINT_ERROR("%s", "Target name required");
			res = -EINVAL;
			goto out_ungrab;
		}
		res = tgtt->add_target(target_name, pp);
	} else if (strcasecmp("del_target", p) == 0) {
		target_name = scst_get_next_lexem(&pp);
		if (*target_name == '\0') {
			PRINT_ERROR("%s", "Target name required");
			res = -EINVAL;
			goto out_ungrab;
		}

		p = scst_get_next_lexem(&pp);
		if (*p != '\0')
			goto out_syntax_err;

		res = tgtt->del_target(target_name);
	} else if (tgtt->mgmt_cmd != NULL) {
		scst_restore_token_str(p, pp);
		res = tgtt->mgmt_cmd(buffer);
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_ungrab;
	}

out_ungrab:
	scst_ungrab_tgtt_ptr(tgtt);

out:
	TRACE_EXIT_RES(res);
	return res;

out_syntax_err:
	PRINT_ERROR("Syntax error on \"%s\"", p);
	res = -EINVAL;
	goto out_ungrab;
}

static int scst_tgtt_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_tgtt_mgmt_store(work->buf, work->tgtt);
}

static ssize_t scst_tgtt_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	char *buffer;
	struct scst_sysfs_work_item *work;
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = scst_alloc_sysfs_work(scst_tgtt_mgmt_store_work_fn, false, &work);
	if (res != 0)
		goto out_free;

	work->buf = buffer;
	work->tgtt = tgtt;

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(buffer);
	goto out;
}

static struct kobj_attribute scst_tgtt_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_tgtt_mgmt_show,
	       scst_tgtt_mgmt_store);

/*
 * Creates an attribute entry for target driver.
 */
int scst_create_tgtt_attr(struct scst_tgt_template *tgtt,
	struct kobj_attribute *attribute)
{
	int res;

	res = sysfs_create_file(&tgtt->tgtt_kobj, &attribute->attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for target driver %s",
			attribute->attr.name, tgtt->name);
		goto out;
	}

out:
	return res;
}
EXPORT_SYMBOL(scst_create_tgtt_attr);

int scst_tgtt_sysfs_create(struct scst_tgt_template *tgtt)
{
	int res = 0;

	TRACE_ENTRY();

	res = kobject_init_and_add(&tgtt->tgtt_kobj, &tgtt_ktype,
			scst_targets_kobj, tgtt->name);
	if (res != 0) {
		PRINT_ERROR("Can't add tgtt %s to sysfs", tgtt->name);
		goto out;
	}

	if (tgtt->add_target != NULL) {
		res = sysfs_create_file(&tgtt->tgtt_kobj,
				&scst_tgtt_mgmt.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add mgmt attr for target driver %s",
				tgtt->name);
			goto out_del;
		}
	}

	if (tgtt->tgtt_attrs) {
		res = sysfs_create_files(&tgtt->tgtt_kobj, tgtt->tgtt_attrs);
		if (res != 0) {
			PRINT_ERROR("Can't add attributes for target "
				    "driver %s", tgtt->name);
			goto out_del;
		}
	}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (tgtt->trace_flags != NULL) {
		res = sysfs_create_file(&tgtt->tgtt_kobj,
				&tgtt_trace_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add trace_flag for target "
				"driver %s", tgtt->name);
			goto out_del;
		}
	}
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	scst_tgtt_sysfs_del(tgtt);
	goto out;
}

void scst_kobject_put_and_wait(struct kobject *kobj, const char *category,
			       struct completion *c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29) && defined(CONFIG_LOCKDEP)
			       , struct lockdep_map *dep_map
#endif
			       )
{
	char *name;

	TRACE_ENTRY();

	name = kstrdup(kobject_name(kobj), GFP_KERNEL);

	kobject_put(kobj);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	mutex_acquire(dep_map, 0, 0, _RET_IP_);
#endif

	if (wait_for_completion_timeout(c, HZ) > 0)
		goto out_free;

	PRINT_INFO("Waiting for release of sysfs entry for %s %s (%d refs)",
		   category, name ? : "(?)", atomic_read(&kobj->kref.refcount));
	wait_for_completion(c);
	PRINT_INFO("Finished waiting for release of %s %s sysfs entry",
		   category, name ? : "(?)");

out_free:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	lock_acquired(dep_map, _RET_IP_);
	mutex_release(dep_map, 0, _RET_IP_);
#endif

	kfree(name);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_kobject_put_and_wait);

/*
 * Must not be called under scst_mutex, due to possible deadlock with
 * sysfs ref counting in sysfs works (it is waiting for the last put, but
 * the last ref counter holder is waiting for scst_mutex)
 */
void scst_tgtt_sysfs_del(struct scst_tgt_template *tgtt)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	tgtt->tgtt_kobj_release_cmpl = &c;

	kobject_del(&tgtt->tgtt_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&tgtt->tgtt_kobj, "target template", &c,
				  &scst_tgtt_dep_map);

	TRACE_EXIT();
	return;
}

/**
 ** Target directory implementation
 **/

static void scst_tgt_release(struct kobject *kobj)
{
	struct scst_tgt *tgt;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	if (tgt->tgt_kobj_release_cmpl)
		complete_all(tgt->tgt_kobj_release_cmpl);

	TRACE_EXIT();
	return;
}

static struct kobj_type tgt_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_tgt_release,
};

static int __scst_process_luns_mgmt_store(char *buffer,
	struct scst_tgt *tgt, struct scst_acg *acg, bool tgt_kobj)
{
	int res, read_only = 0, action;
	char *p, *pp, *e;
	unsigned long virt_lun;
	struct scst_acg_dev *acg_dev = NULL, *acg_dev_tmp;
	struct scst_device *d, *dev = NULL;
	enum {
		SCST_LUN_ACTION_ADD	= 1,
		SCST_LUN_ACTION_DEL	= 2,
		SCST_LUN_ACTION_REPLACE	= 3,
		SCST_LUN_ACTION_CLEAR	= 4,
	};

	TRACE_ENTRY();

	TRACE_DBG("buffer %s", buffer);

	pp = buffer;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp("add", p) == 0) {
		action = SCST_LUN_ACTION_ADD;
	} else if (strcasecmp("del", p) == 0) {
		action = SCST_LUN_ACTION_DEL;
	} else if (strcasecmp("replace", p) == 0) {
		action = SCST_LUN_ACTION_REPLACE;
	} else if (strcasecmp("clear", p) == 0) {
		action = SCST_LUN_ACTION_CLEAR;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out;
	}

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_resume;

	/* Check if tgt and acg not already freed while we were coming here */
	if (scst_check_tgt_acg_ptrs(tgt, acg) != 0)
		goto out_unlock;

	if ((action != SCST_LUN_ACTION_CLEAR) &&
	    (action != SCST_LUN_ACTION_DEL)) {
		p = scst_get_next_lexem(&pp);
		list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
			if (!strcmp(d->virt_name, p)) {
				dev = d;
				TRACE_DBG("Device %p (%s) found", dev, p);
				break;
			}
		}
		if (dev == NULL) {
			PRINT_ERROR("Device '%s' not found", p);
			res = -EINVAL;
			goto out_unlock;
		}
	}

	switch (action) {
	case SCST_LUN_ACTION_ADD:
	case SCST_LUN_ACTION_REPLACE:
	{
		bool dev_replaced = false;

		e = scst_get_next_lexem(&pp);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		res = kstrtoul(e, 0, &virt_lun);
#else
		res = strict_strtoul(e, 0, &virt_lun);
#endif
		if (res != 0) {
			PRINT_ERROR("Valid LUN required for dev %s (res %d)", p, res);
			goto out_unlock;
		} else if (virt_lun > SCST_MAX_LUN) {
			PRINT_ERROR("Too big LUN %ld (max %d)", virt_lun, SCST_MAX_LUN);
			goto out_unlock;
		}

		while (1) {
			unsigned long val;
			char *param = scst_get_next_token_str(&pp);
			char *pp;

			if (param == NULL)
				break;

			p = scst_get_next_lexem(&param);
			if (*p == '\0') {
				PRINT_ERROR("Syntax error at %s (device %s)",
					param, dev->virt_name);
				res = -EINVAL;
				goto out_unlock;
			}

			pp = scst_get_next_lexem(&param);
			if (*pp == '\0') {
				PRINT_ERROR("Parameter %s value missed for device %s",
					p, dev->virt_name);
				res = -EINVAL;
				goto out_unlock;
			}

			if (scst_get_next_lexem(&param)[0] != '\0') {
				PRINT_ERROR("Too many parameter's %s values (device %s)",
					p, dev->virt_name);
				res = -EINVAL;
				goto out_unlock;
			}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
			res = kstrtoul(pp, 0, &val);
#else
			res = strict_strtoul(pp, 0, &val);
#endif
			if (res != 0) {
				PRINT_ERROR("strict_strtoul() for %s failed: %d "
					"(device %s)", pp, res, dev->virt_name);
				goto out_unlock;
			}

			if (!strcasecmp("read_only", p)) {
				read_only = val;
				TRACE_DBG("READ ONLY %d", read_only);
			} else {
				PRINT_ERROR("Unknown parameter %s (device %s)",
					p, dev->virt_name);
				res = -EINVAL;
				goto out_unlock;
			}
		}

		acg_dev = NULL;
		list_for_each_entry(acg_dev_tmp, &acg->acg_dev_list,
				    acg_dev_list_entry) {
			if (acg_dev_tmp->lun == virt_lun) {
				acg_dev = acg_dev_tmp;
				break;
			}
		}

		if (acg_dev != NULL) {
			if (action == SCST_LUN_ACTION_ADD) {
				PRINT_ERROR("virt lun %ld already exists in "
					"group %s", virt_lun, acg->acg_name);
				res = -EEXIST;
				goto out_unlock;
			} else {
				/* Replace */
				res = scst_acg_del_lun(acg, acg_dev->lun,
						false);
				if (res != 0)
					goto out_unlock;

				dev_replaced = true;
			}
		}

		res = scst_acg_add_lun(acg,
			tgt_kobj ? tgt->tgt_luns_kobj : acg->luns_kobj,
			dev, virt_lun, read_only, !dev_replaced, NULL);
		if (res != 0)
			goto out_unlock;

		if (dev_replaced) {
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
				if ((tgt_dev->acg_dev->acg == acg) &&
				    (tgt_dev->lun == virt_lun)) {
					TRACE_MGMT_DBG("INQUIRY DATA HAS CHANGED"
						" on tgt_dev %p", tgt_dev);
					scst_gen_aen_or_ua(tgt_dev,
						SCST_LOAD_SENSE(scst_sense_inquiry_data_changed));
				}
			}
		}

		break;
	}
	case SCST_LUN_ACTION_DEL:
		p = scst_get_next_lexem(&pp);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		res = kstrtoul(p, 0, &virt_lun);
#else
		res = strict_strtoul(p, 0, &virt_lun);
#endif
		if (res != 0)
			goto out_unlock;

		if (scst_get_next_lexem(&pp)[0] != '\0') {
			PRINT_ERROR("Too many parameters for del LUN %ld: %s",
				    virt_lun, p);
			res = -EINVAL;
			goto out_unlock;
		}

		res = scst_acg_del_lun(acg, virt_lun, true);
		if (res != 0)
			goto out_unlock;
		break;
	case SCST_LUN_ACTION_CLEAR:
		if (scst_get_next_lexem(&pp)[0] != '\0') {
			PRINT_ERROR("Too many parameters for clear: %s", p);
			res = -EINVAL;
			goto out_unlock;
		}
		PRINT_INFO("Removed all devices from group %s",
			acg->acg_name);
		list_for_each_entry_safe(acg_dev, acg_dev_tmp,
					 &acg->acg_dev_list,
					 acg_dev_list_entry) {
			res = scst_acg_del_lun(acg, acg_dev->lun,
				list_is_last(&acg_dev->acg_dev_list_entry,
					     &acg->acg_dev_list));
			if (res != 0)
				goto out_unlock;
		}
		break;
	}

	res = 0;

out_unlock:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_luns_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return __scst_process_luns_mgmt_store(work->buf, work->tgt, work->acg,
			work->is_tgt_kobj);
}

static ssize_t __scst_acg_mgmt_store(struct scst_acg *acg,
	const char *buf, size_t count, bool is_tgt_kobj,
	int (*sysfs_work_fn)(struct scst_sysfs_work_item *))
{
	int res;
	char *buffer;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = scst_alloc_sysfs_work(sysfs_work_fn, false, &work);
	if (res != 0)
		goto out_free;

	work->buf = buffer;
	work->tgt = acg->tgt;
	work->acg = acg;
	work->is_tgt_kobj = is_tgt_kobj;

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(buffer);
	goto out;
}

static ssize_t __scst_luns_mgmt_store(struct scst_acg *acg,
	bool tgt_kobj, const char *buf, size_t count)
{
	return __scst_acg_mgmt_store(acg, buf, count, tgt_kobj,
			scst_luns_mgmt_store_work_fn);
}

static ssize_t scst_luns_mgmt_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	static const char help[] =
		"Usage: echo \"add H:C:I:L lun [parameters]\" >mgmt\n"
		"       echo \"add VNAME lun [parameters]\" >mgmt\n"
		"       echo \"del lun\" >mgmt\n"
		"       echo \"replace H:C:I:L lun [parameters]\" >mgmt\n"
		"       echo \"replace VNAME lun [parameters]\" >mgmt\n"
		"       echo \"clear\" >mgmt\n"
		"\n"
		"where parameters are one or more "
		"param_name=value pairs separated by ';'\n"
		"\nThe following parameters available: read_only.\n";

	return sprintf(buf, "%s", help);
}

static ssize_t scst_luns_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj->parent, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	res = __scst_luns_mgmt_store(acg, true, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_luns_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_luns_mgmt_show,
	       scst_luns_mgmt_store);

static ssize_t __scst_acg_addr_method_show(struct scst_acg *acg, char *buf)
{
	int res;

	switch (acg->addr_method) {
	case SCST_LUN_ADDR_METHOD_FLAT:
		res = sprintf(buf, "FLAT\n");
		break;
	case SCST_LUN_ADDR_METHOD_PERIPHERAL:
		res = sprintf(buf, "PERIPHERAL\n");
		break;
	case SCST_LUN_ADDR_METHOD_LUN:
		res = sprintf(buf, "LUN\n");
		break;
	default:
		res = sprintf(buf, "UNKNOWN\n");
		break;
	}

	if (acg->addr_method != acg->tgt->tgtt->preferred_addr_method)
		res += sprintf(&buf[res], "%s\n", SCST_SYSFS_KEY_MARK);

	return res;
}

static ssize_t __scst_acg_addr_method_store(struct scst_acg *acg,
	const char *buf, size_t count)
{
	int res = count;

	if (strncasecmp(buf, "FLAT", min_t(int, 4, count)) == 0)
		acg->addr_method = SCST_LUN_ADDR_METHOD_FLAT;
	else if (strncasecmp(buf, "PERIPHERAL", min_t(int, 10, count)) == 0)
		acg->addr_method = SCST_LUN_ADDR_METHOD_PERIPHERAL;
	else if (strncasecmp(buf, "LUN", min_t(int, 3, count)) == 0)
		acg->addr_method = SCST_LUN_ADDR_METHOD_LUN;
	else {
		PRINT_ERROR("Unknown address method %s", buf);
		res = -EINVAL;
	}

	TRACE_DBG("acg %p, addr_method %d", acg, acg->addr_method);

	return res;
}

static ssize_t scst_tgt_addr_method_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	return __scst_acg_addr_method_show(acg, buf);
}

static ssize_t scst_tgt_addr_method_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	res = __scst_acg_addr_method_store(acg, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_addr_method =
	__ATTR(addr_method, S_IRUGO | S_IWUSR, scst_tgt_addr_method_show,
	       scst_tgt_addr_method_store);

static ssize_t __scst_acg_io_grouping_type_show(struct scst_acg *acg, char *buf)
{
	int res;

	switch (acg->acg_io_grouping_type) {
	case SCST_IO_GROUPING_AUTO:
		res = sprintf(buf, "%s\n", SCST_IO_GROUPING_AUTO_STR);
		break;
	case SCST_IO_GROUPING_THIS_GROUP_ONLY:
		res = sprintf(buf, "%s\n%s\n",
			SCST_IO_GROUPING_THIS_GROUP_ONLY_STR,
			SCST_SYSFS_KEY_MARK);
		break;
	case SCST_IO_GROUPING_NEVER:
		res = sprintf(buf, "%s\n%s\n", SCST_IO_GROUPING_NEVER_STR,
			SCST_SYSFS_KEY_MARK);
		break;
	default:
		res = sprintf(buf, "%d\n%s\n", acg->acg_io_grouping_type,
			SCST_SYSFS_KEY_MARK);
		break;
	}

	return res;
}

static int __scst_acg_process_io_grouping_type_store(struct scst_tgt *tgt,
	struct scst_acg *acg, int io_grouping_type)
{
	int res = 0;
	struct scst_acg_dev *acg_dev;

	TRACE_DBG("tgt %p, acg %p, io_grouping_type %d", tgt, acg,
		io_grouping_type);

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_resume;

	/* Check if tgt and acg not already freed while we were coming here */
	if (scst_check_tgt_acg_ptrs(tgt, acg) != 0)
		goto out_unlock;

	acg->acg_io_grouping_type = io_grouping_type;

	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		int rc;

		scst_stop_dev_threads(acg_dev->dev);

		rc = scst_create_dev_threads(acg_dev->dev);
		if (rc != 0)
			res = rc;
	}

out_unlock:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	return res;
}

static int __scst_acg_io_grouping_type_store_work_fn(struct scst_sysfs_work_item *work)
{
	return __scst_acg_process_io_grouping_type_store(work->tgt, work->acg,
			work->io_grouping_type);
}

static ssize_t __scst_acg_io_grouping_type_store(struct scst_acg *acg,
	const char *buf, size_t count)
{
	int res = 0;
	int prev = acg->acg_io_grouping_type;
	long io_grouping_type;
	struct scst_sysfs_work_item *work;

	if (strncasecmp(buf, SCST_IO_GROUPING_AUTO_STR,
			min_t(int, strlen(SCST_IO_GROUPING_AUTO_STR), count)) == 0)
		io_grouping_type = SCST_IO_GROUPING_AUTO;
	else if (strncasecmp(buf, SCST_IO_GROUPING_THIS_GROUP_ONLY_STR,
			min_t(int, strlen(SCST_IO_GROUPING_THIS_GROUP_ONLY_STR), count)) == 0)
		io_grouping_type = SCST_IO_GROUPING_THIS_GROUP_ONLY;
	else if (strncasecmp(buf, SCST_IO_GROUPING_NEVER_STR,
			min_t(int, strlen(SCST_IO_GROUPING_NEVER_STR), count)) == 0)
		io_grouping_type = SCST_IO_GROUPING_NEVER;
	else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		res = kstrtol(buf, 0, &io_grouping_type);
#else
		res = strict_strtol(buf, 0, &io_grouping_type);
#endif
		if ((res != 0) || (io_grouping_type <= 0)) {
			PRINT_ERROR("Unknown or not allowed I/O grouping type "
				"%s", buf);
			res = -EINVAL;
			goto out;
		}
	}

	if (prev == io_grouping_type)
		goto out;

	res = scst_alloc_sysfs_work(__scst_acg_io_grouping_type_store_work_fn,
					false, &work);
	if (res != 0)
		goto out;

	work->tgt = acg->tgt;
	work->acg = acg;
	work->io_grouping_type = io_grouping_type;

	res = scst_sysfs_queue_wait_work(work);

out:
	return res;
}

static ssize_t scst_tgt_io_grouping_type_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	return __scst_acg_io_grouping_type_show(acg, buf);
}

static ssize_t scst_tgt_io_grouping_type_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	res = __scst_acg_io_grouping_type_store(acg, buf, count);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_io_grouping_type =
	__ATTR(io_grouping_type, S_IRUGO | S_IWUSR,
	       scst_tgt_io_grouping_type_show,
	       scst_tgt_io_grouping_type_store);

static ssize_t __scst_acg_cpu_mask_show(struct scst_acg *acg, char *buf)
{
	int res;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
	res = cpumask_scnprintf(buf, SCST_SYSFS_BLOCK_SIZE,
		acg->acg_cpu_mask);
#else
	res = cpumask_scnprintf(buf, SCST_SYSFS_BLOCK_SIZE,
		&acg->acg_cpu_mask);
#endif
	if (!cpus_equal(acg->acg_cpu_mask, default_cpu_mask))
		res += sprintf(&buf[res], "\n%s\n", SCST_SYSFS_KEY_MARK);

	return res;
}

static int __scst_acg_process_cpu_mask_store(struct scst_tgt *tgt,
	struct scst_acg *acg, cpumask_t *cpu_mask)
{
	int res = 0;
	struct scst_session *sess;

	TRACE_DBG("tgt %p, acg %p", tgt, acg);

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	/* Check if tgt and acg not already freed while we were coming here */
	if (scst_check_tgt_acg_ptrs(tgt, acg) != 0)
		goto out_unlock;

	cpumask_copy(&acg->acg_cpu_mask, cpu_mask);

	list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) {
		int i;
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct scst_tgt_dev *tgt_dev;
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			list_for_each_entry(tgt_dev, head,
						sess_tgt_dev_list_entry) {
				struct scst_cmd_thread_t *thr;
				if (tgt_dev->active_cmd_threads != &tgt_dev->tgt_dev_cmd_threads)
					continue;
				list_for_each_entry(thr,
						&tgt_dev->active_cmd_threads->threads_list,
						thread_list_entry) {
					int rc;
					rc = set_cpus_allowed_ptr(thr->cmd_thread, cpu_mask);
					if (rc != 0)
						PRINT_ERROR("Setting CPU "
							"affinity failed: %d", rc);
				}
			}
		}
		if (tgt->tgtt->report_aen != NULL) {
			struct scst_aen *aen;
			int rc;

			aen = scst_alloc_aen(sess, 0);
			if (aen == NULL) {
				PRINT_ERROR("Unable to notify target driver %s "
					"about cpu_mask change", tgt->tgt_name);
				continue;
			}

			aen->event_fn = SCST_AEN_CPU_MASK_CHANGED;

			TRACE_DBG("Calling target's %s report_aen(%p)",
				tgt->tgtt->name, aen);
			rc = tgt->tgtt->report_aen(aen);
			TRACE_DBG("Target's %s report_aen(%p) returned %d",
				tgt->tgtt->name, aen, rc);
			if (rc != SCST_AEN_RES_SUCCESS)
				scst_free_aen(aen);
		}
	}


out_unlock:
	mutex_unlock(&scst_mutex);

out:
	return res;
}

static int __scst_acg_cpu_mask_store_work_fn(struct scst_sysfs_work_item *work)
{
	return __scst_acg_process_cpu_mask_store(work->tgt, work->acg,
			&work->cpu_mask);
}

static ssize_t __scst_acg_cpu_mask_store(struct scst_acg *acg,
	const char *buf, size_t count)
{
	int res;
	struct scst_sysfs_work_item *work;

	/* cpumask might be too big for stack */

	res = scst_alloc_sysfs_work(__scst_acg_cpu_mask_store_work_fn,
					false, &work);
	if (res != 0)
		goto out;

	/*
	 * We can't use cpumask_parse_user() here, because it expects
	 * buffer in the user space.
	 */
	res = __bitmap_parse(buf, count, 0, cpumask_bits(&work->cpu_mask),
				nr_cpumask_bits);
	if (res != 0) {
		PRINT_ERROR("__bitmap_parse() failed: %d", res);
		goto out_release;
	}

	if (cpus_equal(acg->acg_cpu_mask, work->cpu_mask))
		goto out;

	work->tgt = acg->tgt;
	work->acg = acg;

	res = scst_sysfs_queue_wait_work(work);

out:
	return res;

out_release:
	scst_sysfs_work_release(&work->sysfs_work_kref);
	goto out;
}

static ssize_t scst_tgt_cpu_mask_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	return __scst_acg_cpu_mask_show(acg, buf);
}

static ssize_t scst_tgt_cpu_mask_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	res = __scst_acg_cpu_mask_store(acg, buf, count);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_cpu_mask =
	__ATTR(cpu_mask, S_IRUGO | S_IWUSR,
	       scst_tgt_cpu_mask_show,
	       scst_tgt_cpu_mask_store);

static ssize_t scst_ini_group_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"create GROUP_NAME\" >mgmt\n"
		"       echo \"del GROUP_NAME\" >mgmt\n";

	return sprintf(buf, "%s", help);
}

static int scst_process_ini_group_mgmt_store(char *buffer,
	struct scst_tgt *tgt)
{
	int res, action;
	char *p, *pp;
	struct scst_acg *acg;
	enum {
		SCST_INI_GROUP_ACTION_CREATE = 1,
		SCST_INI_GROUP_ACTION_DEL    = 2,
	};

	TRACE_ENTRY();

	TRACE_DBG("tgt %p, buffer %s", tgt, buffer);

	pp = buffer;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp("create", p) == 0) {
		action = SCST_INI_GROUP_ACTION_CREATE;
	} else if (strcasecmp("del", p) == 0) {
		action = SCST_INI_GROUP_ACTION_DEL;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out;
	}

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_resume;

	/* Check if our pointer is still alive */
	if (scst_check_tgt_acg_ptrs(tgt, NULL) != 0)
		goto out_unlock;

	p = scst_get_next_lexem(&pp);
	if (p[0] == '\0') {
		PRINT_ERROR("%s", "Group name required");
		res = -EINVAL;
		goto out_unlock;
	}

	acg = scst_tgt_find_acg(tgt, p);

	switch (action) {
	case SCST_INI_GROUP_ACTION_CREATE:
		TRACE_DBG("Creating group '%s'", p);
		if (acg != NULL) {
			PRINT_ERROR("acg name %s exist", p);
			res = -EINVAL;
			goto out_unlock;
		}
		acg = scst_alloc_add_acg(tgt, p, true);
		if (acg == NULL)
			goto out_unlock;
		break;
	case SCST_INI_GROUP_ACTION_DEL:
		TRACE_DBG("Deleting group '%s'", p);
		if (acg == NULL) {
			PRINT_ERROR("Group %s not found", p);
			res = -EINVAL;
			goto out_unlock;
		}
		if (!scst_acg_sess_is_empty(acg)) {
			PRINT_ERROR("Group %s is not empty", acg->acg_name);
			res = -EBUSY;
			goto out_unlock;
		}
		scst_del_free_acg(acg);
		break;
	}

	res = 0;

out_unlock:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_ini_group_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_ini_group_mgmt_store(work->buf, work->tgt);
}

static ssize_t scst_ini_group_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	char *buffer;
	struct scst_tgt *tgt;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	tgt = container_of(kobj->parent, struct scst_tgt, tgt_kobj);

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = scst_alloc_sysfs_work(scst_ini_group_mgmt_store_work_fn, false,
					&work);
	if (res != 0)
		goto out_free;

	work->buf = buffer;
	work->tgt = tgt;

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(buffer);
	goto out;
}

static struct kobj_attribute scst_ini_group_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_ini_group_mgmt_show,
	       scst_ini_group_mgmt_store);

static ssize_t scst_tgt_enable_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *tgt;
	int res;
	bool enabled;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	enabled = tgt->tgtt->is_target_enabled(tgt);

	res = sprintf(buf, "%d\n", enabled ? 1 : 0);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_process_tgt_enable_store(struct scst_tgt *tgt, bool enable)
{
	int res;

	TRACE_ENTRY();

	/* Tgt protected by kobject reference */

	TRACE_DBG("tgt %s, enable %d", tgt->tgt_name, enable);

	if (enable) {
		if (tgt->rel_tgt_id == 0) {
			res = gen_relative_target_port_id(&tgt->rel_tgt_id);
			if (res != 0)
				goto out_put;
			PRINT_INFO("Using autogenerated relative target id %d "
				"for target %s", tgt->rel_tgt_id, tgt->tgt_name);
		} else {
			if (!scst_is_relative_target_port_id_unique(
					    tgt->rel_tgt_id, tgt)) {
				PRINT_ERROR("Relative target id %d is not "
					"unique", tgt->rel_tgt_id);
				res = -EBADSLT;
				goto out_put;
			}
		}
	}

	res = tgt->tgtt->enable_target(tgt, enable);

out_put:
	kobject_put(&tgt->tgt_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_tgt_enable_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_tgt_enable_store(work->tgt, work->enable);
}

static ssize_t scst_tgt_enable_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_tgt *tgt;
	bool enable;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	if (buf == NULL) {
		PRINT_ERROR("%s: NULL buffer?", __func__);
		res = -EINVAL;
		goto out;
	}

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	switch (buf[0]) {
	case '0':
		enable = false;
		break;
	case '1':
		enable = true;
		break;
	default:
		PRINT_ERROR("%s: Requested action not understood: %s",
		       __func__, buf);
		res = -EINVAL;
		goto out;
	}

	res = scst_alloc_sysfs_work(scst_tgt_enable_store_work_fn, false,
					&work);
	if (res != 0)
		goto out;

	work->tgt = tgt;
	work->enable = enable;

	SCST_SET_DEP_MAP(work, &scst_tgt_dep_map);
	kobject_get(&tgt->tgt_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute tgt_enable_attr =
	__ATTR(enabled, S_IRUGO | S_IWUSR,
	       scst_tgt_enable_show, scst_tgt_enable_store);

static ssize_t scst_rel_tgt_id_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *tgt;
	int res;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	res = sprintf(buf, "%d\n%s", tgt->rel_tgt_id,
		(tgt->rel_tgt_id != 0) ? SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_process_rel_tgt_id_store(struct scst_sysfs_work_item *work)
{
	int res = 0;
	struct scst_tgt *tgt = work->tgt_r;
	unsigned long rel_tgt_id = work->rel_tgt_id;
	bool enabled;

	TRACE_ENTRY();

	/* tgt protected by kobject_get() */

	TRACE_DBG("Trying to set relative target port id %d",
		(uint16_t)rel_tgt_id);

	if (tgt->tgtt->is_target_enabled != NULL)
		enabled = tgt->tgtt->is_target_enabled(tgt);
	else
		enabled = true;

	if (enabled && rel_tgt_id != tgt->rel_tgt_id) {
		if (!scst_is_relative_target_port_id_unique(rel_tgt_id, tgt)) {
			PRINT_ERROR("Relative port id %d is not unique",
				(uint16_t)rel_tgt_id);
			res = -EBADSLT;
			goto out_put;
		}
	}

	if (rel_tgt_id < SCST_MIN_REL_TGT_ID ||
	    rel_tgt_id > SCST_MAX_REL_TGT_ID) {
		if ((rel_tgt_id == 0) && !enabled)
			goto set;

		PRINT_ERROR("Invalid relative port id %d",
			(uint16_t)rel_tgt_id);
		res = -EINVAL;
		goto out_put;
	}

set:
	tgt->rel_tgt_id = (uint16_t)rel_tgt_id;

out_put:
	kobject_put(&tgt->tgt_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_rel_tgt_id_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res = 0;
	struct scst_tgt *tgt;
	unsigned long rel_tgt_id;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	if (buf == NULL)
		goto out;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtoul(buf, 0, &rel_tgt_id);
#else
	res = strict_strtoul(buf, 0, &rel_tgt_id);
#endif
	if (res != 0) {
		PRINT_ERROR("%s", "Wrong rel_tgt_id");
		res = -EINVAL;
		goto out;
	}

	res = scst_alloc_sysfs_work(scst_process_rel_tgt_id_store, false,
					&work);
	if (res != 0)
		goto out;

	work->tgt_r = tgt;
	work->rel_tgt_id = rel_tgt_id;

	SCST_SET_DEP_MAP(work, &scst_tgt_dep_map);
	kobject_get(&tgt->tgt_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_rel_tgt_id =
	__ATTR(rel_tgt_id, S_IRUGO | S_IWUSR, scst_rel_tgt_id_show,
	       scst_rel_tgt_id_store);

static ssize_t scst_tgt_comment_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *tgt;
	int res;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	if (tgt->tgt_comment != NULL)
		res = sprintf(buf, "%s\n%s", tgt->tgt_comment,
			SCST_SYSFS_KEY_MARK "\n");
	else
		res = 0;

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_tgt_comment_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_tgt *tgt;
	char *p;
	int len;

	TRACE_ENTRY();

	if ((buf == NULL) || (count == 0)) {
		res = 0;
		goto out;
	}

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	len = strnlen(buf, count);
	if (buf[count-1] == '\n')
		len--;

	if (len == 0) {
		kfree(tgt->tgt_comment);
		tgt->tgt_comment = NULL;
		goto out_done;
	}

	p = kmalloc(len+1, GFP_KERNEL);
	if (p == NULL) {
		PRINT_ERROR("Unable to alloc tgt_comment string (len %d)",
			len+1);
		res = -ENOMEM;
		goto out;
	}

	memcpy(p, buf, len);
	p[len] = '\0';

	kfree(tgt->tgt_comment);

	tgt->tgt_comment = p;

out_done:
	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_comment =
	__ATTR(comment, S_IRUGO | S_IWUSR, scst_tgt_comment_show,
	       scst_tgt_comment_store);
/*
 * Creates an attribute entry for one target. Allows for target driver to
 * create an attribute that is not for every target.
 */
int scst_create_tgt_attr(struct scst_tgt *tgt, struct kobj_attribute *attribute)
{
	int res;

	res = sysfs_create_file(&tgt->tgt_kobj, &attribute->attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			attribute->attr.name, tgt->tgt_name);
		goto out;
	}

out:
	return res;
}
EXPORT_SYMBOL(scst_create_tgt_attr);

/*
 * Supposed to be called under scst_mutex. In case of error will drop,
 * then reacquire it.
 */
int scst_tgt_sysfs_create(struct scst_tgt *tgt)
{
	int res;

	TRACE_ENTRY();

	res = kobject_init_and_add(&tgt->tgt_kobj, &tgt_ktype,
			&tgt->tgtt->tgtt_kobj, tgt->tgt_name);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt %s to sysfs", tgt->tgt_name);
		goto out;
	}

	if ((tgt->tgtt->enable_target != NULL) &&
	    (tgt->tgtt->is_target_enabled != NULL)) {
		res = sysfs_create_file(&tgt->tgt_kobj,
				&tgt_enable_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add attr %s to sysfs",
				tgt_enable_attr.attr.name);
			goto out_err;
		}
	}

	tgt->tgt_sess_kobj = kobject_create_and_add("sessions", &tgt->tgt_kobj);
	if (tgt->tgt_sess_kobj == NULL) {
		PRINT_ERROR("Can't create sess kobj for tgt %s", tgt->tgt_name);
		goto out_nomem;
	}

	tgt->tgt_luns_kobj = kobject_create_and_add("luns", &tgt->tgt_kobj);
	if (tgt->tgt_luns_kobj == NULL) {
		PRINT_ERROR("Can't create luns kobj for tgt %s", tgt->tgt_name);
		goto out_nomem;
	}

	res = sysfs_create_file(tgt->tgt_luns_kobj, &scst_luns_mgmt.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_luns_mgmt.attr.name, tgt->tgt_name);
		goto out_err;
	}

	tgt->tgt_ini_grp_kobj = kobject_create_and_add("ini_groups",
					&tgt->tgt_kobj);
	if (tgt->tgt_ini_grp_kobj == NULL) {
		PRINT_ERROR("Can't create ini_grp kobj for tgt %s",
			tgt->tgt_name);
		goto out_nomem;
	}

	res = sysfs_create_file(tgt->tgt_ini_grp_kobj,
			&scst_ini_group_mgmt.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_ini_group_mgmt.attr.name, tgt->tgt_name);
		goto out_err;
	}

	res = sysfs_create_file(&tgt->tgt_kobj,
			&scst_rel_tgt_id.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_rel_tgt_id.attr.name, tgt->tgt_name);
		goto out_err;
	}

	res = sysfs_create_file(&tgt->tgt_kobj,
			&scst_tgt_comment.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_tgt_comment.attr.name, tgt->tgt_name);
		goto out_err;
	}

	res = sysfs_create_file(&tgt->tgt_kobj,
			&scst_tgt_addr_method.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_tgt_addr_method.attr.name, tgt->tgt_name);
		goto out_err;
	}

	res = sysfs_create_file(&tgt->tgt_kobj,
			&scst_tgt_io_grouping_type.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_tgt_io_grouping_type.attr.name, tgt->tgt_name);
		goto out_err;
	}

	res = sysfs_create_file(&tgt->tgt_kobj, &scst_tgt_cpu_mask.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_tgt_cpu_mask.attr.name, tgt->tgt_name);
		goto out_err;
	}

	if (tgt->tgtt->tgt_attrs) {
		res = sysfs_create_files(&tgt->tgt_kobj, tgt->tgtt->tgt_attrs);
		if (res != 0) {
			PRINT_ERROR("Can't add attributes for tgt %s",
				    tgt->tgt_name);
			goto out_err;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_nomem:
	res = -ENOMEM;

out_err:
	mutex_unlock(&scst_mutex);
	scst_tgt_sysfs_del(tgt);
	mutex_lock(&scst_mutex);
	goto out;
}

/*
 * Must not be called under scst_mutex, due to possible deadlock with
 * sysfs ref counting in sysfs works (it is waiting for the last put, but
 * the last ref counter holder is waiting for scst_mutex)
 */
void scst_tgt_sysfs_del(struct scst_tgt *tgt)
{
	TRACE_ENTRY();

	kobject_del(tgt->tgt_sess_kobj);
	kobject_del(tgt->tgt_luns_kobj);
	kobject_del(tgt->tgt_ini_grp_kobj);
	kobject_del(&tgt->tgt_kobj);

	kobject_put(tgt->tgt_sess_kobj);
	kobject_put(tgt->tgt_luns_kobj);
	kobject_put(tgt->tgt_ini_grp_kobj);

	TRACE_EXIT();
	return;
}

void scst_tgt_sysfs_put(struct scst_tgt *tgt)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	tgt->tgt_kobj_release_cmpl = &c;

	SCST_KOBJECT_PUT_AND_WAIT(&tgt->tgt_kobj, "target", &c,
				  &scst_tgt_dep_map);

	TRACE_EXIT();
	return;
}

/**
 ** Devices directory implementation
 **/

static ssize_t scst_dev_sysfs_type_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	int pos = 0;

	struct scst_device *dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);

	pos = scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%d - %s\n", dev->type,
		(unsigned)dev->type >= ARRAY_SIZE(scst_dev_handler_types) ?
		      "unknown" : scst_dev_handler_types[dev->type]);

	return pos;
}

static struct kobj_attribute dev_type_attr =
	__ATTR(type, S_IRUGO, scst_dev_sysfs_type_show, NULL);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_dev_sysfs_dump_prs(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	scst_pr_dump_prs(dev, true);

	TRACE_EXIT_RES(count);
	return count;
}

static struct kobj_attribute dev_dump_prs_attr =
	__ATTR(dump_prs, S_IWUSR, NULL, scst_dev_sysfs_dump_prs);

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static int scst_process_dev_sysfs_threads_data_store(
	struct scst_device *dev, int threads_num,
	enum scst_dev_type_threads_pool_type threads_pool_type)
{
	int res = 0;
	int oldtn = dev->threads_num;
	enum scst_dev_type_threads_pool_type oldtt = dev->threads_pool_type;

	TRACE_ENTRY();

	TRACE_DBG("dev %p, threads_num %d, threads_pool_type %d", dev,
		threads_num, threads_pool_type);

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_resume;

	/* Check if our pointer is still alive */
	if (scst_check_dev_ptr(dev) != 0)
		goto out_unlock;

	scst_stop_dev_threads(dev);

	dev->threads_num = threads_num;
	dev->threads_pool_type = threads_pool_type;

	res = scst_create_dev_threads(dev);
	if (res != 0)
		goto out_unlock;

	if (oldtn != dev->threads_num)
		PRINT_INFO("Changed cmd threads num to %d", dev->threads_num);
	else if (oldtt != dev->threads_pool_type)
		PRINT_INFO("Changed cmd threads pool type to %d",
			dev->threads_pool_type);

out_unlock:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_dev_sysfs_threads_data_store_work_fn(
	struct scst_sysfs_work_item *work)
{
	return scst_process_dev_sysfs_threads_data_store(work->dev,
		work->new_threads_num, work->new_threads_pool_type);
}

static ssize_t scst_dev_sysfs_check_threads_data(
	struct scst_device *dev, int threads_num,
	enum scst_dev_type_threads_pool_type threads_pool_type, bool *stop)
{
	int res = 0;

	TRACE_ENTRY();

	*stop = false;

	if (dev->threads_num < 0) {
		PRINT_ERROR("Threads pool disabled for device %s",
			dev->virt_name);
		res = -EPERM;
		goto out;
	}

	if ((threads_num == dev->threads_num) &&
	    (threads_pool_type == dev->threads_pool_type)) {
		*stop = true;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_dev_sysfs_threads_num_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	pos = sprintf(buf, "%d\n%s", dev->threads_num,
		(dev->threads_num != dev->handler->threads_num) ?
			SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t scst_dev_sysfs_threads_num_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	long newtn;
	bool stop;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtol(buf, 0, &newtn);
#else
	res = strict_strtol(buf, 0, &newtn);
#endif
	if (res != 0) {
		PRINT_ERROR("strict_strtol() for %s failed: %d ", buf, res);
		goto out;
	}
	if (newtn < 0) {
		PRINT_ERROR("Illegal threads num value %ld", newtn);
		res = -EINVAL;
		goto out;
	}

	res = scst_dev_sysfs_check_threads_data(dev, newtn,
		dev->threads_pool_type, &stop);
	if ((res != 0) || stop)
		goto out;

	res = scst_alloc_sysfs_work(scst_dev_sysfs_threads_data_store_work_fn,
					false, &work);
	if (res != 0)
		goto out;

	work->dev = dev;
	work->new_threads_num = newtn;
	work->new_threads_pool_type = dev->threads_pool_type;

	res = scst_sysfs_queue_wait_work(work);

out:
	if (res == 0)
		res = count;

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute dev_threads_num_attr =
	__ATTR(threads_num, S_IRUGO | S_IWUSR,
		scst_dev_sysfs_threads_num_show,
		scst_dev_sysfs_threads_num_store);

static ssize_t scst_dev_sysfs_threads_pool_type_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	if (dev->threads_num == 0) {
		pos = sprintf(buf, "Async\n");
		goto out;
	} else if (dev->threads_num < 0) {
		pos = sprintf(buf, "Not valid\n");
		goto out;
	}

	switch (dev->threads_pool_type) {
	case SCST_THREADS_POOL_PER_INITIATOR:
		pos = sprintf(buf, "%s\n%s", SCST_THREADS_POOL_PER_INITIATOR_STR,
			(dev->threads_pool_type != dev->handler->threads_pool_type) ?
				SCST_SYSFS_KEY_MARK "\n" : "");
		break;
	case SCST_THREADS_POOL_SHARED:
		pos = sprintf(buf, "%s\n%s", SCST_THREADS_POOL_SHARED_STR,
			(dev->threads_pool_type != dev->handler->threads_pool_type) ?
				SCST_SYSFS_KEY_MARK "\n" : "");
		break;
	default:
		pos = sprintf(buf, "Unknown\n");
		break;
	}

out:
	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t scst_dev_sysfs_threads_pool_type_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	enum scst_dev_type_threads_pool_type newtpt;
	struct scst_sysfs_work_item *work;
	bool stop;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	newtpt = scst_parse_threads_pool_type(buf, count);
	if (newtpt == SCST_THREADS_POOL_TYPE_INVALID) {
		PRINT_ERROR("Illegal threads pool type %s", buf);
		res = -EINVAL;
		goto out;
	}

	TRACE_DBG("buf %s, count %zd, newtpt %d", buf, count, newtpt);

	res = scst_dev_sysfs_check_threads_data(dev, dev->threads_num,
		newtpt, &stop);
	if ((res != 0) || stop)
		goto out;

	res = scst_alloc_sysfs_work(scst_dev_sysfs_threads_data_store_work_fn,
					false, &work);
	if (res != 0)
		goto out;

	work->dev = dev;
	work->new_threads_num = dev->threads_num;
	work->new_threads_pool_type = newtpt;

	res = scst_sysfs_queue_wait_work(work);

out:
	if (res == 0)
		res = count;

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute dev_threads_pool_type_attr =
	__ATTR(threads_pool_type, S_IRUGO | S_IWUSR,
		scst_dev_sysfs_threads_pool_type_show,
		scst_dev_sysfs_threads_pool_type_store);

static struct attribute *scst_dev_attrs[] = {
	&dev_type_attr.attr,
	NULL,
};

static void scst_sysfs_dev_release(struct kobject *kobj)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	if (dev->dev_kobj_release_cmpl)
		complete_all(dev->dev_kobj_release_cmpl);

	TRACE_EXIT();
	return;
}

/*
 * Creates an attribute entry for one SCST device. Allows for dev handlers to
 * create an attribute that is not for every device.
 */
int scst_create_dev_attr(struct scst_device *dev,
	struct kobj_attribute *attribute)
{
	int res;

	res = sysfs_create_file(&dev->dev_kobj, &attribute->attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for dev %s",
			attribute->attr.name, dev->virt_name);
		goto out;
	}

out:
	return res;
}
EXPORT_SYMBOL(scst_create_dev_attr);

int scst_devt_dev_sysfs_create(struct scst_device *dev)
{
	int res = 0;

	TRACE_ENTRY();

	if (dev->handler == &scst_null_devtype)
		goto out;

	res = sysfs_create_link(&dev->dev_kobj,
			&dev->handler->devt_kobj, "handler");
	if (res != 0) {
		PRINT_ERROR("Can't create handler link for dev %s",
			dev->virt_name);
		goto out;
	}

	res = sysfs_create_link(&dev->handler->devt_kobj,
			&dev->dev_kobj, dev->virt_name);
	if (res != 0) {
		PRINT_ERROR("Can't create handler link for dev %s",
			dev->virt_name);
		goto out_err;
	}

	if (dev->handler->threads_num >= 0) {
		res = sysfs_create_file(&dev->dev_kobj,
				&dev_threads_num_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add dev attr %s for dev %s",
				dev_threads_num_attr.attr.name,
				dev->virt_name);
			goto out_err;
		}
		res = sysfs_create_file(&dev->dev_kobj,
				&dev_threads_pool_type_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add dev attr %s for dev %s",
				dev_threads_pool_type_attr.attr.name,
				dev->virt_name);
			goto out_err;
		}
	}

	if (dev->handler->dev_attrs) {
		res = sysfs_create_files(&dev->dev_kobj,
					 dev->handler->dev_attrs);
		if (res != 0) {
			PRINT_ERROR("Can't add dev attributes for dev %s",
				    dev->virt_name);
			goto out_err;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	scst_devt_dev_sysfs_del(dev);
	goto out;
}

void scst_devt_dev_sysfs_del(struct scst_device *dev)
{
	TRACE_ENTRY();

	if (dev->handler == &scst_null_devtype)
		goto out;

	if (dev->handler->dev_attrs)
		sysfs_remove_files(&dev->dev_kobj, dev->handler->dev_attrs);

	sysfs_remove_link(&dev->dev_kobj, "handler");
	sysfs_remove_link(&dev->handler->devt_kobj, dev->virt_name);

	if (dev->handler->threads_num >= 0) {
		sysfs_remove_file(&dev->dev_kobj,
			&dev_threads_num_attr.attr);
		sysfs_remove_file(&dev->dev_kobj,
			&dev_threads_pool_type_attr.attr);
	}

out:
	TRACE_EXIT();
	return;
}

static struct kobj_type scst_dev_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_dev_release,
	.default_attrs = scst_dev_attrs,
};

/*
 * Must not be called under scst_mutex, because it can call
 * scst_dev_sysfs_del()
 */
int scst_dev_sysfs_create(struct scst_device *dev)
{
	int res = 0;

	TRACE_ENTRY();

	res = kobject_init_and_add(&dev->dev_kobj, &scst_dev_ktype,
				      scst_devices_kobj, dev->virt_name);
	if (res != 0) {
		PRINT_ERROR("Can't add device %s to sysfs", dev->virt_name);
		goto out;
	}

	dev->dev_exp_kobj = kobject_create_and_add("exported",
						   &dev->dev_kobj);
	if (dev->dev_exp_kobj == NULL) {
		PRINT_ERROR("Can't create exported link for device %s",
			dev->virt_name);
		res = -ENOMEM;
		goto out_del;
	}

	if (dev->scsi_dev != NULL) {
		res = sysfs_create_link(&dev->dev_kobj,
			&dev->scsi_dev->sdev_dev.kobj, "scsi_device");
		if (res != 0) {
			PRINT_ERROR("Can't create scsi_device link for dev %s",
				dev->virt_name);
			goto out_del;
		}
	}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (dev->scsi_dev == NULL) {
		res = sysfs_create_file(&dev->dev_kobj,
				&dev_dump_prs_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't create attr %s for dev %s",
				dev_dump_prs_attr.attr.name, dev->virt_name);
			goto out_del;
		}
	}
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	scst_dev_sysfs_del(dev);
	goto out;
}

/*
 * Must not be called under scst_mutex, due to possible deadlock with
 * sysfs ref counting in sysfs works (it is waiting for the last put, but
 * the last ref counter holder is waiting for scst_mutex)
 */
void scst_dev_sysfs_del(struct scst_device *dev)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	dev->dev_kobj_release_cmpl = &c;

	kobject_del(dev->dev_exp_kobj);
	kobject_del(&dev->dev_kobj);

	kobject_put(dev->dev_exp_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&dev->dev_kobj, "device", &c,
				  &scst_dev_dep_map);

	TRACE_EXIT();
	return;
}

/**
 ** Tgt_dev implementation
 **/

#ifdef CONFIG_SCST_MEASURE_LATENCY

static char *scst_io_size_names[] = {
	"<=8K  ",
	"<=32K ",
	"<=128K",
	"<=512K",
	">512K "
};

static ssize_t scst_tgt_dev_latency_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buffer)
{
	int res = 0, i;
	char buf[50];
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	tgt_dev = container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);

	for (i = 0; i < SCST_LATENCY_STATS_NUM; i++) {
		uint64_t scst_time_wr, tgt_time_wr, dev_time_wr;
		uint64_t processed_cmds_wr;
		uint64_t scst_time_rd, tgt_time_rd, dev_time_rd;
		uint64_t processed_cmds_rd;
		struct scst_ext_latency_stat *latency_stat;

		latency_stat = &tgt_dev->dev_latency_stat[i];
		scst_time_wr = latency_stat->scst_time_wr;
		scst_time_rd = latency_stat->scst_time_rd;
		tgt_time_wr = latency_stat->tgt_time_wr;
		tgt_time_rd = latency_stat->tgt_time_rd;
		dev_time_wr = latency_stat->dev_time_wr;
		dev_time_rd = latency_stat->dev_time_rd;
		processed_cmds_wr = latency_stat->processed_cmds_wr;
		processed_cmds_rd = latency_stat->processed_cmds_rd;

		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			 "%-5s %-9s %-15llu ", "Write", scst_io_size_names[i],
			processed_cmds_wr);

		scst_time_per_cmd(scst_time_wr, processed_cmds_wr);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_scst_time_wr,
			(unsigned long)scst_time_wr,
			(unsigned long)latency_stat->max_scst_time_wr,
			(unsigned long)latency_stat->scst_time_wr);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(tgt_time_wr, processed_cmds_wr);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_tgt_time_wr,
			(unsigned long)tgt_time_wr,
			(unsigned long)latency_stat->max_tgt_time_wr,
			(unsigned long)latency_stat->tgt_time_wr);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(dev_time_wr, processed_cmds_wr);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_dev_time_wr,
			(unsigned long)dev_time_wr,
			(unsigned long)latency_stat->max_dev_time_wr,
			(unsigned long)latency_stat->dev_time_wr);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s\n", buf);

		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-5s %-9s %-15llu ", "Read", scst_io_size_names[i],
			processed_cmds_rd);

		scst_time_per_cmd(scst_time_rd, processed_cmds_rd);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_scst_time_rd,
			(unsigned long)scst_time_rd,
			(unsigned long)latency_stat->max_scst_time_rd,
			(unsigned long)latency_stat->scst_time_rd);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(tgt_time_rd, processed_cmds_rd);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_tgt_time_rd,
			(unsigned long)tgt_time_rd,
			(unsigned long)latency_stat->max_tgt_time_rd,
			(unsigned long)latency_stat->tgt_time_rd);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(dev_time_rd, processed_cmds_rd);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_dev_time_rd,
			(unsigned long)dev_time_rd,
			(unsigned long)latency_stat->max_dev_time_rd,
			(unsigned long)latency_stat->dev_time_rd);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s\n", buf);
	}

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute tgt_dev_latency_attr =
	__ATTR(latency, S_IRUGO,
		scst_tgt_dev_latency_show, NULL);

#endif /* CONFIG_SCST_MEASURE_LATENCY */

static ssize_t scst_tgt_dev_active_commands_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_tgt_dev *tgt_dev;

	tgt_dev = container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);

	pos = sprintf(buf, "%d\n", atomic_read(&tgt_dev->tgt_dev_cmd_count));

	return pos;
}

static struct kobj_attribute tgt_dev_active_commands_attr =
	__ATTR(active_commands, S_IRUGO,
		scst_tgt_dev_active_commands_show, NULL);

static struct attribute *scst_tgt_dev_attrs[] = {
	&tgt_dev_active_commands_attr.attr,
#ifdef CONFIG_SCST_MEASURE_LATENCY
	&tgt_dev_latency_attr.attr,
#endif
	NULL,
};

static void scst_sysfs_tgt_dev_release(struct kobject *kobj)
{
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	tgt_dev = container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);
	if (tgt_dev->tgt_dev_kobj_release_cmpl)
		complete_all(tgt_dev->tgt_dev_kobj_release_cmpl);

	TRACE_EXIT();
	return;
}

static struct kobj_type scst_tgt_dev_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_tgt_dev_release,
	.default_attrs = scst_tgt_dev_attrs,
};

int scst_tgt_dev_sysfs_create(struct scst_tgt_dev *tgt_dev)
{
	int res = 0;

	TRACE_ENTRY();

	res = kobject_init_and_add(&tgt_dev->tgt_dev_kobj, &scst_tgt_dev_ktype,
			      &tgt_dev->sess->sess_kobj, "lun%lld",
			      (unsigned long long)tgt_dev->lun);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt_dev %lld to sysfs",
			(unsigned long long)tgt_dev->lun);
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Called with scst_mutex held.
 *
 * !! No sysfs works must use kobject_get() to protect tgt_dev, due to possible
 * !! deadlock with scst_mutex (it is waiting for the last put, but
 * !! the last ref counter holder is waiting for scst_mutex)
 */
void scst_tgt_dev_sysfs_del(struct scst_tgt_dev *tgt_dev)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	tgt_dev->tgt_dev_kobj_release_cmpl = &c;

	kobject_del(&tgt_dev->tgt_dev_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&tgt_dev->tgt_dev_kobj, "tgt_dev", &c,
				  &scst_tgt_dev_dep_map);

	TRACE_EXIT();
	return;
}

/**
 ** Sessions subdirectory implementation
 **/

#ifdef CONFIG_SCST_MEASURE_LATENCY

static ssize_t scst_sess_latency_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buffer)
{
	ssize_t res = 0;
	struct scst_session *sess;
	int i;
	char buf[50];
	uint64_t scst_time, tgt_time, dev_time;
	uint64_t processed_cmds;

	TRACE_ENTRY();

	sess = container_of(kobj, struct scst_session, sess_kobj);

	res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
		"%-15s %-15s %-46s %-46s %-46s\n",
		"T-L names", "Total commands", "SCST latency",
		"Target latency", "Dev latency (min/avg/max/all us)");

	spin_lock_bh(&sess->lat_lock);

	for (i = 0; i < SCST_LATENCY_STATS_NUM; i++) {
		uint64_t scst_time_wr, tgt_time_wr, dev_time_wr;
		uint64_t processed_cmds_wr;
		uint64_t scst_time_rd, tgt_time_rd, dev_time_rd;
		uint64_t processed_cmds_rd;
		struct scst_ext_latency_stat *latency_stat;

		latency_stat = &sess->sess_latency_stat[i];
		scst_time_wr = latency_stat->scst_time_wr;
		scst_time_rd = latency_stat->scst_time_rd;
		tgt_time_wr = latency_stat->tgt_time_wr;
		tgt_time_rd = latency_stat->tgt_time_rd;
		dev_time_wr = latency_stat->dev_time_wr;
		dev_time_rd = latency_stat->dev_time_rd;
		processed_cmds_wr = latency_stat->processed_cmds_wr;
		processed_cmds_rd = latency_stat->processed_cmds_rd;

		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-5s %-9s %-15llu ",
			"Write", scst_io_size_names[i],
			processed_cmds_wr);

		scst_time_per_cmd(scst_time_wr, processed_cmds_wr);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_scst_time_wr,
			(unsigned long)scst_time_wr,
			(unsigned long)latency_stat->max_scst_time_wr,
			(unsigned long)latency_stat->scst_time_wr);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(tgt_time_wr, processed_cmds_wr);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_tgt_time_wr,
			(unsigned long)tgt_time_wr,
			(unsigned long)latency_stat->max_tgt_time_wr,
			(unsigned long)latency_stat->tgt_time_wr);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(dev_time_wr, processed_cmds_wr);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_dev_time_wr,
			(unsigned long)dev_time_wr,
			(unsigned long)latency_stat->max_dev_time_wr,
			(unsigned long)latency_stat->dev_time_wr);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s\n", buf);

		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-5s %-9s %-15llu ",
			"Read", scst_io_size_names[i],
			processed_cmds_rd);

		scst_time_per_cmd(scst_time_rd, processed_cmds_rd);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_scst_time_rd,
			(unsigned long)scst_time_rd,
			(unsigned long)latency_stat->max_scst_time_rd,
			(unsigned long)latency_stat->scst_time_rd);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(tgt_time_rd, processed_cmds_rd);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_tgt_time_rd,
			(unsigned long)tgt_time_rd,
			(unsigned long)latency_stat->max_tgt_time_rd,
			(unsigned long)latency_stat->tgt_time_rd);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s ", buf);

		scst_time_per_cmd(dev_time_rd, processed_cmds_rd);
		snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
			(unsigned long)latency_stat->min_dev_time_rd,
			(unsigned long)dev_time_rd,
			(unsigned long)latency_stat->max_dev_time_rd,
			(unsigned long)latency_stat->dev_time_rd);
		res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
			"%-46s\n", buf);
	}

	scst_time = sess->scst_time;
	tgt_time = sess->tgt_time;
	dev_time = sess->dev_time;
	processed_cmds = sess->processed_cmds;

	res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
		"\n%-15s %-16llu", "Overall ", processed_cmds);

	scst_time_per_cmd(scst_time, processed_cmds);
	snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
		(unsigned long)sess->min_scst_time,
		(unsigned long)scst_time,
		(unsigned long)sess->max_scst_time,
		(unsigned long)sess->scst_time);
	res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
		"%-46s ", buf);

	scst_time_per_cmd(tgt_time, processed_cmds);
	snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
		(unsigned long)sess->min_tgt_time,
		(unsigned long)tgt_time,
		(unsigned long)sess->max_tgt_time,
		(unsigned long)sess->tgt_time);
	res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
		"%-46s ", buf);

	scst_time_per_cmd(dev_time, processed_cmds);
	snprintf(buf, sizeof(buf), "%lu/%lu/%lu/%lu",
		(unsigned long)sess->min_dev_time,
		(unsigned long)dev_time,
		(unsigned long)sess->max_dev_time,
		(unsigned long)sess->dev_time);
	res += scnprintf(&buffer[res], SCST_SYSFS_BLOCK_SIZE - res,
		"%-46s\n\n", buf);

	spin_unlock_bh(&sess->lat_lock);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_sess_zero_latency(struct scst_sysfs_work_item *work)
{
	int res = 0, t;
	struct scst_session *sess = work->sess;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_put;

	PRINT_INFO("Zeroing latency statistics for initiator "
		"%s", sess->initiator_name);

	spin_lock_bh(&sess->lat_lock);

	sess->scst_time = 0;
	sess->tgt_time = 0;
	sess->dev_time = 0;
	sess->min_scst_time = 0;
	sess->min_tgt_time = 0;
	sess->min_dev_time = 0;
	sess->max_scst_time = 0;
	sess->max_tgt_time = 0;
	sess->max_dev_time = 0;
	sess->processed_cmds = 0;
	memset(sess->sess_latency_stat, 0,
		sizeof(sess->sess_latency_stat));

	for (t = SESS_TGT_DEV_LIST_HASH_SIZE-1; t >= 0; t--) {
		struct list_head *head = &sess->sess_tgt_dev_list[t];
		struct scst_tgt_dev *tgt_dev;
		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			tgt_dev->scst_time = 0;
			tgt_dev->tgt_time = 0;
			tgt_dev->dev_time = 0;
			tgt_dev->processed_cmds = 0;
			memset(tgt_dev->dev_latency_stat, 0,
				sizeof(tgt_dev->dev_latency_stat));
		}
	}

	spin_unlock_bh(&sess->lat_lock);

	mutex_unlock(&scst_mutex);

out_put:
	kobject_put(&sess->sess_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_sess_latency_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_session *sess;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	sess = container_of(kobj, struct scst_session, sess_kobj);

	res = scst_alloc_sysfs_work(scst_sess_zero_latency, false, &work);
	if (res != 0)
		goto out;

	work->sess = sess;

	SCST_SET_DEP_MAP(work, &scst_sess_dep_map);
	kobject_get(&sess->sess_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute session_latency_attr =
	__ATTR(latency, S_IRUGO | S_IWUSR, scst_sess_latency_show,
	       scst_sess_latency_store);

#endif /* CONFIG_SCST_MEASURE_LATENCY */

static ssize_t scst_sess_sysfs_commands_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	return sprintf(buf, "%i\n", atomic_read(&sess->sess_cmd_count));
}

static struct kobj_attribute session_commands_attr =
	__ATTR(commands, S_IRUGO, scst_sess_sysfs_commands_show, NULL);

static int scst_sysfs_sess_get_active_commands(struct scst_session *sess)
{
	int res;
	int active_cmds = 0, t;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_put;

	for (t = SESS_TGT_DEV_LIST_HASH_SIZE-1; t >= 0; t--) {
		struct list_head *head = &sess->sess_tgt_dev_list[t];
		struct scst_tgt_dev *tgt_dev;
		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			active_cmds += atomic_read(&tgt_dev->tgt_dev_cmd_count);
		}
	}

	mutex_unlock(&scst_mutex);

	res = active_cmds;

out_put:
	kobject_put(&sess->sess_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_sysfs_sess_get_active_commands_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_sysfs_sess_get_active_commands(work->sess);
}

static ssize_t scst_sess_sysfs_active_commands_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	int res;
	struct scst_session *sess;
	struct scst_sysfs_work_item *work;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	res = scst_alloc_sysfs_work(scst_sysfs_sess_get_active_commands_work_fn,
			true, &work);
	if (res != 0)
		goto out;

	work->sess = sess;

	SCST_SET_DEP_MAP(work, &scst_sess_dep_map);
	kobject_get(&sess->sess_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res != -EAGAIN)
		res = sprintf(buf, "%i\n", res);

out:
	return res;
}

static struct kobj_attribute session_active_commands_attr =
	__ATTR(active_commands, S_IRUGO, scst_sess_sysfs_active_commands_show,
		NULL);

static ssize_t scst_sess_sysfs_initiator_name_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	return scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%s\n",
		sess->initiator_name);
}

static struct kobj_attribute session_initiator_name_attr =
	__ATTR(initiator_name, S_IRUGO, scst_sess_sysfs_initiator_name_show,
	       NULL);

#define SCST_SESS_SYSFS_STAT_ATTR(name, exported_name, dir, kb)		\
static ssize_t scst_sess_sysfs_##exported_name##_show(struct kobject *kobj,	\
	struct kobj_attribute *attr, char *buf)					\
{										\
	struct scst_session *sess;						\
	int res;								\
	uint64_t v;								\
										\
	BUILD_BUG_ON(SCST_DATA_UNKNOWN != 0);					\
	BUILD_BUG_ON(SCST_DATA_WRITE != 1);					\
	BUILD_BUG_ON(SCST_DATA_READ != 2);					\
	BUILD_BUG_ON(SCST_DATA_BIDI != 3);					\
	BUILD_BUG_ON(SCST_DATA_NONE != 4);					\
										\
	BUILD_BUG_ON(dir >= SCST_DATA_DIR_MAX);					\
										\
	sess = container_of(kobj, struct scst_session, sess_kobj);		\
	v = sess->io_stats[dir].name;						\
	if (kb)									\
		v >>= 10;							\
	res = sprintf(buf, "%llu\n", (unsigned long long)v);			\
	return res;								\
}										\
										\
static ssize_t scst_sess_sysfs_##exported_name##_store(struct kobject *kobj,	\
	struct kobj_attribute *attr, const char *buf, size_t count)		\
{										\
	struct scst_session *sess;						\
	sess = container_of(kobj, struct scst_session, sess_kobj);		\
	spin_lock_irq(&sess->sess_list_lock);					\
	BUILD_BUG_ON(dir >= SCST_DATA_DIR_MAX);					\
	sess->io_stats[dir].cmd_count = 0;					\
	sess->io_stats[dir].io_byte_count = 0;					\
	spin_unlock_irq(&sess->sess_list_lock);					\
	return count;								\
}										\
										\
static struct kobj_attribute session_##exported_name##_attr =			\
	__ATTR(exported_name, S_IRUGO | S_IWUSR,				\
		scst_sess_sysfs_##exported_name##_show,	\
		scst_sess_sysfs_##exported_name##_store);

SCST_SESS_SYSFS_STAT_ATTR(cmd_count, unknown_cmd_count, SCST_DATA_UNKNOWN, 0);
SCST_SESS_SYSFS_STAT_ATTR(cmd_count, write_cmd_count, SCST_DATA_WRITE, 0);
SCST_SESS_SYSFS_STAT_ATTR(io_byte_count, write_io_count_kb, SCST_DATA_WRITE, 1);
SCST_SESS_SYSFS_STAT_ATTR(cmd_count, read_cmd_count, SCST_DATA_READ, 0);
SCST_SESS_SYSFS_STAT_ATTR(io_byte_count, read_io_count_kb, SCST_DATA_READ, 1);
SCST_SESS_SYSFS_STAT_ATTR(cmd_count, bidi_cmd_count, SCST_DATA_BIDI, 0);
SCST_SESS_SYSFS_STAT_ATTR(io_byte_count, bidi_io_count_kb, SCST_DATA_BIDI, 1);
SCST_SESS_SYSFS_STAT_ATTR(cmd_count, none_cmd_count, SCST_DATA_NONE, 0);


static ssize_t scst_sess_force_close_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	struct scst_session *sess = container_of(kobj, struct scst_session,
						 sess_kobj);
	int res;

	res = sess->tgt->tgtt->close_session(sess);
	if (res < 0)
		goto out;
	res = count;

out:
	return res;
}

static struct kobj_attribute session_force_close_attr =
	__ATTR(force_close, S_IWUSR, NULL, scst_sess_force_close_store);


static struct attribute *scst_session_attrs[] = {
	&session_commands_attr.attr,
	&session_active_commands_attr.attr,
	&session_initiator_name_attr.attr,
	&session_unknown_cmd_count_attr.attr,
	&session_write_cmd_count_attr.attr,
	&session_write_io_count_kb_attr.attr,
	&session_read_cmd_count_attr.attr,
	&session_read_io_count_kb_attr.attr,
	&session_bidi_cmd_count_attr.attr,
	&session_bidi_io_count_kb_attr.attr,
	&session_none_cmd_count_attr.attr,
#ifdef CONFIG_SCST_MEASURE_LATENCY
	&session_latency_attr.attr,
#endif /* CONFIG_SCST_MEASURE_LATENCY */
	NULL,
};

static void scst_sysfs_session_release(struct kobject *kobj)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	sess = container_of(kobj, struct scst_session, sess_kobj);
	if (sess->sess_kobj_release_cmpl)
		complete_all(sess->sess_kobj_release_cmpl);

	TRACE_EXIT();
	return;
}

static struct kobj_type scst_session_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_session_release,
	.default_attrs = scst_session_attrs,
};

static int scst_create_sess_luns_link(struct scst_session *sess)
{
	int res;

	/*
	 * No locks are needed, because sess supposed to be in acg->acg_sess_list
	 * and tgt->sess_list, so blocking them from disappearing.
	 */

	if (sess->acg == sess->tgt->default_acg)
		res = sysfs_create_link(&sess->sess_kobj,
				sess->tgt->tgt_luns_kobj, "luns");
	else
		res = sysfs_create_link(&sess->sess_kobj,
				sess->acg->luns_kobj, "luns");

	if (res != 0)
		PRINT_ERROR("Can't create luns link for initiator %s",
			sess->initiator_name);

	return res;
}

int scst_recreate_sess_luns_link(struct scst_session *sess)
{
	sysfs_remove_link(&sess->sess_kobj, "luns");
	return scst_create_sess_luns_link(sess);
}

/* Supposed to be called under scst_mutex */
int scst_sess_sysfs_create(struct scst_session *sess)
{
	int res = 0;
	const char *name;

	TRACE_ENTRY();

	name = sess->sess_name;
	TRACE_DBG("Adding session %s to sysfs", name);

	res = kobject_init_and_add(&sess->sess_kobj, &scst_session_ktype,
			      sess->tgt->tgt_sess_kobj, name);
	if (res != 0) {
		PRINT_ERROR("Can't add session %s to sysfs", name);
		goto out;
	}

	sess->sess_kobj_ready = 1;

	if (sess->tgt->tgtt->close_session) {
		res = sysfs_create_file(&sess->sess_kobj,
					&session_force_close_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Adding force_close sysfs attribute to session %s failed (%d)",
				    name, res);
			goto out_del;
		}
	}

	if (sess->tgt->tgtt->sess_attrs) {
		res = sysfs_create_files(&sess->sess_kobj,
					 sess->tgt->tgtt->sess_attrs);
		if (res != 0) {
			PRINT_ERROR("Can't add attributes for session %s", name);
			goto out_del;
		}
	}

	res = scst_create_sess_luns_link(sess);
	if (res != 0) {
		PRINT_ERROR("Can't add LUN links for session %s", name);
		goto out_del;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	kobject_del(&sess->sess_kobj);
	kobject_put(&sess->sess_kobj);
	sess->sess_kobj_ready = 0;
	goto out;
}

/*
 * Must not be called under scst_mutex, due to possible deadlock with
 * sysfs ref counting in sysfs works (it is waiting for the last put, but
 * the last ref counter holder is waiting for scst_mutex)
 */
void scst_sess_sysfs_del(struct scst_session *sess)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	if (!sess->sess_kobj_ready)
		goto out;

	TRACE_DBG("Deleting session %s from sysfs",
		kobject_name(&sess->sess_kobj));

	sess->sess_kobj_release_cmpl = &c;

	kobject_del(&sess->sess_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&sess->sess_kobj, "session", &c,
				  &scst_sess_dep_map);

out:
	TRACE_EXIT();
	return;
}

/**
 ** Target luns directory implementation
 **/

static void scst_acg_dev_release(struct kobject *kobj)
{
	struct scst_acg_dev *acg_dev;

	TRACE_ENTRY();

	acg_dev = container_of(kobj, struct scst_acg_dev, acg_dev_kobj);
	if (acg_dev->acg_dev_kobj_release_cmpl)
		complete_all(acg_dev->acg_dev_kobj_release_cmpl);

	TRACE_EXIT();
	return;
}

static ssize_t scst_lun_rd_only_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	struct scst_acg_dev *acg_dev;

	acg_dev = container_of(kobj, struct scst_acg_dev, acg_dev_kobj);

	if (acg_dev->acg_dev_rd_only || acg_dev->dev->dev_rd_only)
		return sprintf(buf, "%d\n%s\n", 1, SCST_SYSFS_KEY_MARK);
	else
		return sprintf(buf, "%d\n", 0);
}

static struct kobj_attribute lun_options_attr =
	__ATTR(read_only, S_IRUGO, scst_lun_rd_only_show, NULL);

static struct attribute *lun_attrs[] = {
	&lun_options_attr.attr,
	NULL,
};

static struct kobj_type acg_dev_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_acg_dev_release,
	.default_attrs = lun_attrs,
};

/*
 * Called with scst_mutex held.
 *
 * !! No sysfs works must use kobject_get() to protect acg_dev, due to possible
 * !! deadlock with scst_mutex (it is waiting for the last put, but
 * !! the last ref counter holder is waiting for scst_mutex)
 */
void scst_acg_dev_sysfs_del(struct scst_acg_dev *acg_dev)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	acg_dev->acg_dev_kobj_release_cmpl = &c;

	if (acg_dev->dev != NULL) {
		sysfs_remove_link(acg_dev->dev->dev_exp_kobj,
			acg_dev->acg_dev_link_name);
		kobject_put(&acg_dev->dev->dev_kobj);
	}

	kobject_del(&acg_dev->acg_dev_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&acg_dev->acg_dev_kobj, "acg_dev", &c,
				  &scst_acg_dev_dep_map);

	TRACE_EXIT();
	return;
}

int scst_acg_dev_sysfs_create(struct scst_acg_dev *acg_dev,
	struct kobject *parent)
{
	int res;

	TRACE_ENTRY();

	res = kobject_init_and_add(&acg_dev->acg_dev_kobj, &acg_dev_ktype,
				      parent, "%llu", acg_dev->lun);
	if (res != 0) {
		PRINT_ERROR("Can't add acg_dev %p to sysfs", acg_dev);
		goto out;
	}

	kobject_get(&acg_dev->dev->dev_kobj);

	snprintf(acg_dev->acg_dev_link_name, sizeof(acg_dev->acg_dev_link_name),
		"export%u", acg_dev->dev->dev_exported_lun_num++);

	res = sysfs_create_link(acg_dev->dev->dev_exp_kobj,
			   &acg_dev->acg_dev_kobj, acg_dev->acg_dev_link_name);
	if (res != 0) {
		PRINT_ERROR("Can't create acg %s LUN link",
			acg_dev->acg->acg_name);
		goto out_del;
	}

	res = sysfs_create_link(&acg_dev->acg_dev_kobj,
			&acg_dev->dev->dev_kobj, "device");
	if (res != 0) {
		PRINT_ERROR("Can't create acg %s device link",
			acg_dev->acg->acg_name);
		goto out_del;
	}

out:
	return res;

out_del:
	scst_acg_dev_sysfs_del(acg_dev);
	goto out;
}

/**
 ** ini_groups directory implementation.
 **/

static void scst_acg_release(struct kobject *kobj)
{
	struct scst_acg *acg;

	TRACE_ENTRY();

	acg = container_of(kobj, struct scst_acg, acg_kobj);
	if (acg->acg_kobj_release_cmpl)
		complete_all(acg->acg_kobj_release_cmpl);

	TRACE_EXIT();
	return;
}

static struct kobj_type acg_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_acg_release,
};

static ssize_t scst_acg_ini_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add INITIATOR_NAME\" >mgmt\n"
		"       echo \"del INITIATOR_NAME\" >mgmt\n"
		"       echo \"move INITIATOR_NAME DEST_GROUP_NAME\" >mgmt\n"
		"       echo \"clear\" >mgmt\n";

	return sprintf(buf, "%s", help);
}

static int scst_process_acg_ini_mgmt_store(char *buffer,
	struct scst_tgt *tgt, struct scst_acg *acg)
{
	int res, action;
	char *p, *pp, *name, *group;
	struct scst_acg *acg_dest = NULL;
	struct scst_acn *acn = NULL, *acn_tmp;
	enum {
		SCST_ACG_ACTION_INI_ADD	  = 1,
		SCST_ACG_ACTION_INI_DEL	  = 2,
		SCST_ACG_ACTION_INI_CLEAR = 3,
		SCST_ACG_ACTION_INI_MOVE  = 4,
	};

	TRACE_ENTRY();

	TRACE_DBG("tgt %p, acg %p, buffer %s", tgt, acg, buffer);

	pp = buffer;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp("add", p) == 0) {
		action = SCST_ACG_ACTION_INI_ADD;
	} else if (strcasecmp("del", p) == 0) {
		action = SCST_ACG_ACTION_INI_DEL;
	} else if (strcasecmp("clear", p) == 0) {
		action = SCST_ACG_ACTION_INI_CLEAR;
	} else if (strcasecmp("move", p) == 0) {
		action = SCST_ACG_ACTION_INI_MOVE;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out;
	}

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_resume;

	/* Check if tgt and acg not already freed while we were coming here */
	if (scst_check_tgt_acg_ptrs(tgt, acg) != 0)
		goto out_unlock;

	switch (action) {
	case SCST_ACG_ACTION_INI_ADD:
		name = scst_get_next_lexem(&pp);
		if (name[0] == '\0') {
			PRINT_ERROR("%s", "Invalid initiator name");
			res = -EINVAL;
			goto out_unlock;
		}

		res = scst_acg_add_acn(acg, name);
		if (res != 0)
			goto out_unlock;
		break;
	case SCST_ACG_ACTION_INI_DEL:
		name = scst_get_next_lexem(&pp);
		if (name[0] == '\0') {
			PRINT_ERROR("%s", "Invalid initiator name");
			res = -EINVAL;
			goto out_unlock;
		}

		acn = scst_find_acn(acg, name);
		if (acn == NULL) {
			PRINT_ERROR("Unable to find "
				"initiator '%s' in group '%s'",
				name, acg->acg_name);
			res = -EINVAL;
			goto out_unlock;
		}
		scst_del_free_acn(acn, true);
		break;
	case SCST_ACG_ACTION_INI_CLEAR:
		list_for_each_entry_safe(acn, acn_tmp, &acg->acn_list,
				acn_list_entry) {
			scst_del_free_acn(acn, false);
		}
		scst_check_reassign_sessions();
		break;
	case SCST_ACG_ACTION_INI_MOVE:
		name = scst_get_next_lexem(&pp);
		if (name[0] == '\0') {
			PRINT_ERROR("%s", "Invalid initiator name");
			res = -EINVAL;
			goto out_unlock;
		}

		group = scst_get_next_lexem(&pp);
		if (group[0] == '\0') {
			PRINT_ERROR("%s", "Invalid group name");
			res = -EINVAL;
			goto out_unlock;
		}

		TRACE_DBG("Move initiator '%s' to group '%s'",
			name, group);

		acn = scst_find_acn(acg, name);
		if (acn == NULL) {
			PRINT_ERROR("Unable to find "
				"initiator '%s' in group '%s'",
				name, acg->acg_name);
			res = -EINVAL;
			goto out_unlock;
		}
		acg_dest = scst_tgt_find_acg(tgt, group);
		if (acg_dest == NULL) {
			PRINT_ERROR("Unable to find group '%s' in target '%s'",
				group, tgt->tgt_name);
			res = -EINVAL;
			goto out_unlock;
		}
		if (scst_find_acn(acg_dest, name) != NULL) {
			PRINT_ERROR("Initiator '%s' already exists in group '%s'",
				name, acg_dest->acg_name);
			res = -EEXIST;
			goto out_unlock;
		}
		scst_del_free_acn(acn, false);

		res = scst_acg_add_acn(acg_dest, name);
		if (res != 0)
			goto out_unlock;
		break;
	}

	res = 0;

out_unlock:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_acg_ini_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_acg_ini_mgmt_store(work->buf, work->tgt, work->acg);
}

static ssize_t scst_acg_ini_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_acg *acg;

	acg = container_of(kobj->parent, struct scst_acg, acg_kobj);

	return __scst_acg_mgmt_store(acg, buf, count, false,
		scst_acg_ini_mgmt_store_work_fn);
}

static struct kobj_attribute scst_acg_ini_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_acg_ini_mgmt_show,
	       scst_acg_ini_mgmt_store);

static ssize_t scst_acg_luns_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	acg = container_of(kobj->parent, struct scst_acg, acg_kobj);
	res = __scst_luns_mgmt_store(acg, false, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_acg_luns_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_luns_mgmt_show,
	       scst_acg_luns_mgmt_store);

static ssize_t scst_acg_addr_method_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	return __scst_acg_addr_method_show(acg, buf);
}

static ssize_t scst_acg_addr_method_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	res = __scst_acg_addr_method_store(acg, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_acg_addr_method =
	__ATTR(addr_method, S_IRUGO | S_IWUSR, scst_acg_addr_method_show,
		scst_acg_addr_method_store);

static ssize_t scst_acg_io_grouping_type_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	return __scst_acg_io_grouping_type_show(acg, buf);
}

static ssize_t scst_acg_io_grouping_type_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	res = __scst_acg_io_grouping_type_store(acg, buf, count);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_acg_io_grouping_type =
	__ATTR(io_grouping_type, S_IRUGO | S_IWUSR,
	       scst_acg_io_grouping_type_show,
	       scst_acg_io_grouping_type_store);

static ssize_t scst_acg_cpu_mask_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	return __scst_acg_cpu_mask_show(acg, buf);
}

static ssize_t scst_acg_cpu_mask_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	res = __scst_acg_cpu_mask_store(acg, buf, count);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_acg_cpu_mask =
	__ATTR(cpu_mask, S_IRUGO | S_IWUSR,
	       scst_acg_cpu_mask_show,
	       scst_acg_cpu_mask_store);

/*
 * Called with scst_mutex held.
 *
 * !! No sysfs works must use kobject_get() to protect acg, due to possible
 * !! deadlock with scst_mutex (it is waiting for the last put, but
 * !! the last ref counter holder is waiting for scst_mutex)
 */
void scst_acg_sysfs_del(struct scst_acg *acg)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	acg->acg_kobj_release_cmpl = &c;

	kobject_del(acg->luns_kobj);
	kobject_del(acg->initiators_kobj);
	kobject_del(&acg->acg_kobj);

	kobject_put(acg->luns_kobj);
	kobject_put(acg->initiators_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&acg->acg_kobj, "acg", &c,
				  &scst_acg_dep_map);

	TRACE_EXIT();
	return;
}

int scst_acg_sysfs_create(struct scst_tgt *tgt,
	struct scst_acg *acg)
{
	int res = 0;

	TRACE_ENTRY();

	res = kobject_init_and_add(&acg->acg_kobj, &acg_ktype,
		tgt->tgt_ini_grp_kobj, acg->acg_name);
	if (res != 0) {
		PRINT_ERROR("Can't add acg '%s' to sysfs", acg->acg_name);
		goto out;
	}

	acg->luns_kobj = kobject_create_and_add("luns", &acg->acg_kobj);
	if (acg->luns_kobj == NULL) {
		PRINT_ERROR("Can't create luns kobj for tgt %s",
			tgt->tgt_name);
		res = -ENOMEM;
		goto out_del;
	}

	res = sysfs_create_file(acg->luns_kobj, &scst_acg_luns_mgmt.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_luns_mgmt.attr.name, tgt->tgt_name);
		goto out_del;
	}

	acg->initiators_kobj = kobject_create_and_add("initiators",
					&acg->acg_kobj);
	if (acg->initiators_kobj == NULL) {
		PRINT_ERROR("Can't create initiators kobj for tgt %s",
			tgt->tgt_name);
		res = -ENOMEM;
		goto out_del;
	}

	res = sysfs_create_file(acg->initiators_kobj,
			&scst_acg_ini_mgmt.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_ini_mgmt.attr.name, tgt->tgt_name);
		goto out_del;
	}

	res = sysfs_create_file(&acg->acg_kobj, &scst_acg_addr_method.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_addr_method.attr.name, tgt->tgt_name);
		goto out_del;
	}

	res = sysfs_create_file(&acg->acg_kobj, &scst_acg_io_grouping_type.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_io_grouping_type.attr.name, tgt->tgt_name);
		goto out_del;
	}

	res = sysfs_create_file(&acg->acg_kobj, &scst_acg_cpu_mask.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_cpu_mask.attr.name, tgt->tgt_name);
		goto out_del;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	scst_acg_sysfs_del(acg);
	goto out;
}

/**
 ** acn
 **/

static ssize_t scst_acn_file_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%s\n",
		attr->attr.name);
}

int scst_acn_sysfs_create(struct scst_acn *acn)
{
	int res = 0;
	struct scst_acg *acg = acn->acg;
	struct kobj_attribute *attr = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	static struct lock_class_key __key;
#endif
#endif

	TRACE_ENTRY();

	acn->acn_attr = NULL;

	attr = kzalloc(sizeof(struct kobj_attribute), GFP_KERNEL);
	if (attr == NULL) {
		PRINT_ERROR("Unable to allocate attributes for initiator '%s'",
			acn->name);
		res = -ENOMEM;
		goto out;
	}

	attr->attr.name = kstrdup(acn->name, GFP_KERNEL);
	if (attr->attr.name == NULL) {
		PRINT_ERROR("Unable to allocate attributes for initiator '%s'",
			acn->name);
		res = -ENOMEM;
		goto out_free;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	attr->attr.owner = THIS_MODULE;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	attr->attr.key = &__key;
#endif
#endif

	attr->attr.mode = S_IRUGO;
	attr->show = scst_acn_file_show;
	attr->store = NULL;

	res = sysfs_create_file(acg->initiators_kobj, &attr->attr);
	if (res != 0) {
		PRINT_ERROR("Unable to create acn '%s' for group '%s'",
			acn->name, acg->acg_name);
		kfree(attr->attr.name);
		goto out_free;
	}

	acn->acn_attr = attr;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(attr);
	goto out;
}

void scst_acn_sysfs_del(struct scst_acn *acn)
{
	struct scst_acg *acg = acn->acg;

	TRACE_ENTRY();

	if (acn->acn_attr != NULL) {
		sysfs_remove_file(acg->initiators_kobj,
			&acn->acn_attr->attr);
		kfree(acn->acn_attr->attr.name);
		kfree(acn->acn_attr);
	}

	TRACE_EXIT();
	return;
}


/**
 ** Dev handlers
 **/

static void scst_devt_release(struct kobject *kobj)
{
	struct scst_dev_type *devt;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);
	if (devt->devt_kobj_release_compl)
		complete_all(devt->devt_kobj_release_compl);

	TRACE_EXIT();
	return;
}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_devt_trace_level_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_dev_type *devt;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	return scst_trace_level_show(devt->trace_tbl,
		devt->trace_flags ? *devt->trace_flags : 0, buf,
		devt->trace_tbl_help);
}

static ssize_t scst_devt_trace_level_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_dev_type *devt;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	res = mutex_lock_interruptible(&scst_log_mutex);
	if (res != 0)
		goto out;

	res = scst_write_trace(buf, count, devt->trace_flags,
		devt->default_trace_flags, devt->name, devt->trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute devt_trace_attr =
	__ATTR(trace_level, S_IRUGO | S_IWUSR,
	       scst_devt_trace_level_show, scst_devt_trace_level_store);

#endif /* #if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static ssize_t scst_devt_type_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos;
	struct scst_dev_type *devt;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	pos = sprintf(buf, "%d - %s\n", devt->type,
		(unsigned)devt->type >= ARRAY_SIZE(scst_dev_handler_types) ?
			"unknown" : scst_dev_handler_types[devt->type]);

	return pos;
}

static struct kobj_attribute scst_devt_type_attr =
	__ATTR(type, S_IRUGO, scst_devt_type_show, NULL);

static struct attribute *scst_devt_default_attrs[] = {
	&scst_devt_type_attr.attr,
	NULL,
};

static struct kobj_type scst_devt_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_devt_release,
	.default_attrs = scst_devt_default_attrs,
};

static ssize_t scst_devt_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add_device device_name [parameters]\" >mgmt\n"
		"       echo \"del_device device_name\" >mgmt\n"
		"%s%s"
		"%s"
		"\n"
		"where parameters are one or more "
		"param_name=value pairs separated by ';'\n\n"
		"%s%s%s%s%s%s%s%s\n";
	struct scst_dev_type *devt;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	return scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, help,
		(devt->devt_optional_attributes != NULL) ?
			"       echo \"add_attribute <attribute> <value>\" >mgmt\n"
			"       echo \"del_attribute <attribute> <value>\" >mgmt\n" : "",
		(devt->dev_optional_attributes != NULL) ?
			"       echo \"add_device_attribute device_name <attribute> <value>\" >mgmt"
			"       echo \"del_device_attribute device_name <attribute> <value>\" >mgmt\n" : "",
		(devt->mgmt_cmd_help) ? devt->mgmt_cmd_help : "",
		(devt->add_device_parameters != NULL) ?
			"The following parameters available: " : "",
		(devt->add_device_parameters != NULL) ?
			devt->add_device_parameters : "",
		(devt->devt_optional_attributes != NULL) ?
			"The following dev handler attributes available: " : "",
		(devt->devt_optional_attributes != NULL) ?
			devt->devt_optional_attributes : "",
		(devt->devt_optional_attributes != NULL) ? "\n" : "",
		(devt->dev_optional_attributes != NULL) ?
			"The following device attributes available: " : "",
		(devt->dev_optional_attributes != NULL) ?
			devt->dev_optional_attributes : "",
		(devt->dev_optional_attributes != NULL) ? "\n" : "");
}

static int scst_process_devt_mgmt_store(char *buffer,
	struct scst_dev_type *devt)
{
	int res = 0;
	char *p, *pp, *dev_name;

	TRACE_ENTRY();

	/* Check if our pointer is still alive and, if yes, grab it */
	if (scst_check_grab_devt_ptr(devt, &scst_virtual_dev_type_list) != 0)
		goto out;

	TRACE_DBG("devt %p, buffer %s", devt, buffer);

	pp = buffer;
	p = scst_get_next_lexem(&pp);

	if (strcasecmp("add_device", p) == 0) {
		dev_name = scst_get_next_lexem(&pp);
		if (*dev_name == '\0') {
			PRINT_ERROR("%s", "Device name required");
			res = -EINVAL;
			goto out_ungrab;
		}
		res = devt->add_device(dev_name, pp);
	} else if (strcasecmp("del_device", p) == 0) {
		dev_name = scst_get_next_lexem(&pp);
		if (*dev_name == '\0') {
			PRINT_ERROR("%s", "Device name required");
			res = -EINVAL;
			goto out_ungrab;
		}

		p = scst_get_next_lexem(&pp);
		if (*p != '\0')
			goto out_syntax_err;

		res = devt->del_device(dev_name);
	} else if (devt->mgmt_cmd != NULL) {
		scst_restore_token_str(p, pp);
		res = devt->mgmt_cmd(buffer);
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_ungrab;
	}

out_ungrab:
	scst_ungrab_devt_ptr(devt);

out:
	TRACE_EXIT_RES(res);
	return res;

out_syntax_err:
	PRINT_ERROR("Syntax error on \"%s\"", p);
	res = -EINVAL;
	goto out_ungrab;
}

static int scst_devt_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_devt_mgmt_store(work->buf, work->devt);
}

static ssize_t __scst_devt_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count,
	int (*sysfs_work_fn)(struct scst_sysfs_work_item *work))
{
	int res;
	char *buffer;
	struct scst_dev_type *devt;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = scst_alloc_sysfs_work(sysfs_work_fn, false, &work);
	if (res != 0)
		goto out_free;

	work->buf = buffer;
	work->devt = devt;

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(buffer);
	goto out;
}

static ssize_t scst_devt_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	return __scst_devt_mgmt_store(kobj, attr, buf, count,
		scst_devt_mgmt_store_work_fn);
}

static struct kobj_attribute scst_devt_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_devt_mgmt_show,
	       scst_devt_mgmt_store);

static ssize_t scst_devt_pass_through_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add_device H:C:I:L\" >mgmt\n"
		"       echo \"del_device H:C:I:L\" >mgmt\n";
	return sprintf(buf, "%s", help);
}

static int scst_process_devt_pass_through_mgmt_store(char *buffer,
	struct scst_dev_type *devt)
{
	int res = 0;
	char *pp, *action, *devstr;
	unsigned int host, channel, id, lun;
	struct scst_device *d, *dev = NULL;

	TRACE_ENTRY();

	TRACE_DBG("devt %p, buffer %s", devt, buffer);

	pp = buffer;
	action = scst_get_next_lexem(&pp);
	devstr = scst_get_next_lexem(&pp);
	if (*devstr == '\0') {
		PRINT_ERROR("%s", "Device required");
		res = -EINVAL;
		goto out;
	}

	if (*scst_get_next_lexem(&pp) != '\0') {
		PRINT_ERROR("%s", "Too many parameters");
		res = -EINVAL;
		goto out_syntax_err;
	}

	if (sscanf(devstr, "%u:%u:%u:%u", &host, &channel, &id, &lun) != 4)
		goto out_syntax_err;

	TRACE_DBG("Dev %d:%d:%d:%d", host, channel, id, lun);

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	/* Check if devt not be already freed while we were coming here */
	if (scst_check_devt_ptr(devt, &scst_dev_type_list) != 0)
		goto out_unlock;

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if ((d->virt_id == 0) &&
		    d->scsi_dev->host->host_no == host &&
		    d->scsi_dev->channel == channel &&
		    d->scsi_dev->id == id &&
		    d->scsi_dev->lun == lun) {
			dev = d;
			TRACE_DBG("Dev %p (%d:%d:%d:%d) found",
				  dev, host, channel, id, lun);
			break;
		}
	}
	if (dev == NULL) {
		PRINT_ERROR("Device %d:%d:%d:%d not found",
			       host, channel, id, lun);
		res = -EINVAL;
		goto out_unlock;
	}

	if (dev->scsi_dev->type != devt->type) {
		PRINT_ERROR("Type %d of device %s differs from type "
			"%d of dev handler %s", dev->type,
			dev->virt_name, devt->type, devt->name);
		res = -EINVAL;
		goto out_unlock;
	}

	if (strcasecmp("add_device", action) == 0) {
		res = scst_assign_dev_handler(dev, devt);
		if (res == 0)
			PRINT_INFO("Device %s assigned to dev handler %s",
				dev->virt_name, devt->name);
	} else if (strcasecmp("del_device", action) == 0) {
		if (dev->handler != devt) {
			PRINT_ERROR("Device %s is not assigned to handler %s",
				dev->virt_name, devt->name);
			res = -EINVAL;
			goto out_unlock;
		}
		res = scst_assign_dev_handler(dev, &scst_null_devtype);
		if (res == 0)
			PRINT_INFO("Device %s unassigned from dev handler %s",
				dev->virt_name, devt->name);
	} else {
		PRINT_ERROR("Unknown action \"%s\"", action);
		res = -EINVAL;
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_syntax_err:
	PRINT_ERROR("Syntax error on \"%s\"", buffer);
	res = -EINVAL;
	goto out;
}

static int scst_devt_pass_through_mgmt_store_work_fn(
	struct scst_sysfs_work_item *work)
{
	return scst_process_devt_pass_through_mgmt_store(work->buf, work->devt);
}

static ssize_t scst_devt_pass_through_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	return __scst_devt_mgmt_store(kobj, attr, buf, count,
		scst_devt_pass_through_mgmt_store_work_fn);
}

static struct kobj_attribute scst_devt_pass_through_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_devt_pass_through_mgmt_show,
	       scst_devt_pass_through_mgmt_store);

/*
 * Creates an attribute entry for dev handler.
 */
int scst_create_devt_attr(struct scst_dev_type *devt,
	struct kobj_attribute *attribute)
{
	int res;

	res = sysfs_create_file(&devt->devt_kobj, &attribute->attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for dev handler %s",
			attribute->attr.name, devt->name);
		goto out;
	}

out:
	return res;
}
EXPORT_SYMBOL(scst_create_devt_attr);

int scst_devt_sysfs_create(struct scst_dev_type *devt)
{
	int res;
	struct kobject *parent;

	TRACE_ENTRY();

	if (devt->parent != NULL)
		parent = &devt->parent->devt_kobj;
	else
		parent = scst_handlers_kobj;

	res = kobject_init_and_add(&devt->devt_kobj, &scst_devt_ktype,
			parent, devt->name);
	if (res != 0) {
		PRINT_ERROR("Can't add devt %s to sysfs", devt->name);
		goto out;
	}

	if (devt->add_device != NULL) {
		res = sysfs_create_file(&devt->devt_kobj,
				&scst_devt_mgmt.attr);
	} else {
		res = sysfs_create_file(&devt->devt_kobj,
				&scst_devt_pass_through_mgmt.attr);
	}
	if (res != 0) {
		PRINT_ERROR("Can't add mgmt attr for dev handler %s",
			devt->name);
		goto out_err;
	}

	if (devt->devt_attrs) {
		res = sysfs_create_files(&devt->devt_kobj, devt->devt_attrs);
		if (res != 0) {
			PRINT_ERROR("Can't add attributes for dev handler %s",
				    devt->name);
			goto out_err;
		}
	}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (devt->trace_flags != NULL) {
		res = sysfs_create_file(&devt->devt_kobj,
				&devt_trace_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add devt trace_flag for dev "
				"handler %s", devt->name);
			goto out_err;
		}
	}
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	scst_devt_sysfs_del(devt);
	goto out;
}

void scst_devt_sysfs_del(struct scst_dev_type *devt)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	devt->devt_kobj_release_compl = &c;

	kobject_del(&devt->devt_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&devt->devt_kobj, "dev handler template", &c,
				  &scst_devt_dep_map);

	TRACE_EXIT();
	return;
}

/**
 ** SCST sysfs device_groups/<dg>/devices/<dev> implementation.
 **/

int scst_dg_dev_sysfs_add(struct scst_dev_group *dg, struct scst_dg_dev *dgdev)
{
	int res;

	TRACE_ENTRY();
	res = sysfs_create_link(dg->dev_kobj, &dgdev->dev->dev_kobj,
				dgdev->dev->virt_name);
	TRACE_EXIT_RES(res);
	return res;
}

void scst_dg_dev_sysfs_del(struct scst_dev_group *dg, struct scst_dg_dev *dgdev)
{
	TRACE_ENTRY();
	sysfs_remove_link(dg->dev_kobj, dgdev->dev->virt_name);
	TRACE_EXIT();
}

/**
 ** SCST sysfs device_groups/<dg>/devices directory implementation.
 **/

static ssize_t scst_dg_devs_mgmt_show(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	static const char help[] =
		"Usage: echo \"add device\" >mgmt\n"
		"       echo \"del device\" >mgmt\n";

	return scnprintf(buf, PAGE_SIZE, help);
}

static int scst_dg_devs_mgmt_store_work_fn(struct scst_sysfs_work_item *w)
{
	struct scst_dev_group *dg;
	char *cmd, *p, *pp, *dev_name;
	int res;

	TRACE_ENTRY();

	cmd = w->buf;
	dg = scst_lookup_dg_by_kobj(w->kobj);
	WARN_ON(!dg);

	p = strchr(cmd, '\n');
	if (p)
		*p = '\0';

	res = -EINVAL;
	pp = cmd;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp(p, "add") == 0) {
		dev_name = scst_get_next_lexem(&pp);
		if (!*dev_name)
			goto out;
		res = scst_dg_dev_add(dg, dev_name);
	} else if (strcasecmp(p, "del") == 0) {
		dev_name = scst_get_next_lexem(&pp);
		if (!*dev_name)
			goto out;
		res = scst_dg_dev_remove_by_name(dg, dev_name);
	}
out:
	kobject_put(w->kobj);
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_dg_devs_mgmt_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	char *cmd;
	struct scst_sysfs_work_item *work;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	cmd = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!cmd)
		goto out;

	res = scst_alloc_sysfs_work(scst_dg_devs_mgmt_store_work_fn, false,
				    &work);
	if (res)
		goto out;

	swap(work->buf, cmd);
	work->kobj = kobj;
	SCST_SET_DEP_MAP(work, &scst_dg_dep_map);
	kobject_get(kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(cmd);
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_dg_devs_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_dg_devs_mgmt_show,
	       scst_dg_devs_mgmt_store);

static const struct attribute *scst_dg_devs_attrs[] = {
	&scst_dg_devs_mgmt.attr,
	NULL,
};

/**
 ** SCST sysfs device_groups/<dg>/target_groups/<tg>/<tgt> implementation.
 **/

static ssize_t scst_tg_tgt_rel_tgt_id_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct scst_tg_tgt *tg_tgt;

	tg_tgt = container_of(kobj, struct scst_tg_tgt, kobj);
	return scnprintf(buf, PAGE_SIZE, "%u\n" SCST_SYSFS_KEY_MARK "\n",
			 tg_tgt->rel_tgt_id);
}

static ssize_t scst_tg_tgt_rel_tgt_id_store(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf, size_t count)
{
	struct scst_tg_tgt *tg_tgt;
	unsigned long rel_tgt_id;
	char ch[8];
	int res;

	TRACE_ENTRY();
	tg_tgt = container_of(kobj, struct scst_tg_tgt, kobj);
	snprintf(ch, sizeof(ch), "%.*s", min_t(int, count, sizeof(ch)-1), buf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtoul(ch, 0, &rel_tgt_id);
#else
	res = strict_strtoul(ch, 0, &rel_tgt_id);
#endif
	if (res)
		goto out;
	res = -EINVAL;
	if (rel_tgt_id == 0 || rel_tgt_id > 0xffff)
		goto out;
	tg_tgt->rel_tgt_id = rel_tgt_id;
	res = count;
out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tg_tgt_rel_tgt_id =
	__ATTR(rel_tgt_id, S_IRUGO | S_IWUSR, scst_tg_tgt_rel_tgt_id_show,
	       scst_tg_tgt_rel_tgt_id_store);

static const struct attribute *scst_tg_tgt_attrs[] = {
	&scst_tg_tgt_rel_tgt_id.attr,
	NULL,
};

int scst_tg_tgt_sysfs_add(struct scst_target_group *tg,
			  struct scst_tg_tgt *tg_tgt)
{
	int res;

	TRACE_ENTRY();
	BUG_ON(!tg);
	BUG_ON(!tg_tgt);
	BUG_ON(!tg_tgt->name);
	if (tg_tgt->tgt)
		res = sysfs_create_link(&tg->kobj, &tg_tgt->tgt->tgt_kobj,
					tg_tgt->name);
	else {
		res = kobject_add(&tg_tgt->kobj, &tg->kobj, "%s", tg_tgt->name);
		if (res)
			goto err;
		res = sysfs_create_files(&tg_tgt->kobj, scst_tg_tgt_attrs);
		if (res)
			goto err;
	}
out:
	TRACE_EXIT_RES(res);
	return res;
err:
	scst_tg_tgt_sysfs_del(tg, tg_tgt);
	goto out;
}

void scst_tg_tgt_sysfs_del(struct scst_target_group *tg,
			   struct scst_tg_tgt *tg_tgt)
{
	TRACE_ENTRY();
	if (tg_tgt->tgt)
		sysfs_remove_link(&tg->kobj, tg_tgt->name);
	else {
		sysfs_remove_files(&tg_tgt->kobj, scst_tg_tgt_attrs);
		kobject_del(&tg_tgt->kobj);
	}
	TRACE_EXIT();
}

/**
 ** SCST sysfs device_groups/<dg>/target_groups/<tg> directory implementation.
 **/

static ssize_t scst_tg_group_id_show(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     char *buf)
{
	struct scst_target_group *tg;

	tg = container_of(kobj, struct scst_target_group, kobj);
	return scnprintf(buf, PAGE_SIZE, "%u\n" SCST_SYSFS_KEY_MARK "\n",
			 tg->group_id);
}

static ssize_t scst_tg_group_id_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	struct scst_target_group *tg;
	unsigned long group_id;
	char ch[8];
	int res;

	TRACE_ENTRY();
	tg = container_of(kobj, struct scst_target_group, kobj);
	snprintf(ch, sizeof(ch), "%.*s", min_t(int, count, sizeof(ch)-1), buf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtoul(ch, 0, &group_id);
#else
	res = strict_strtoul(ch, 0, &group_id);
#endif
	if (res)
		goto out;
	res = -EINVAL;
	if (group_id == 0 || group_id > 0xffff)
		goto out;
	tg->group_id = group_id;
	res = count;
out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tg_group_id =
	__ATTR(group_id, S_IRUGO | S_IWUSR, scst_tg_group_id_show,
	       scst_tg_group_id_store);

static ssize_t scst_tg_preferred_show(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      char *buf)
{
	struct scst_target_group *tg;

	tg = container_of(kobj, struct scst_target_group, kobj);
	return scnprintf(buf, PAGE_SIZE, "%u\n%s",
			 tg->preferred, SCST_SYSFS_KEY_MARK "\n");
}

static int scst_tg_preferred_store_work_fn(struct scst_sysfs_work_item *w)
{
	struct scst_target_group *tg;
	unsigned long preferred;
	char *cmd;
	int res;

	TRACE_ENTRY();
	cmd = w->buf;
	tg = container_of(w->kobj, struct scst_target_group, kobj);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtoul(cmd, 0, &preferred);
#else
	res = strict_strtoul(cmd, 0, &preferred);
#endif
	if (res)
		goto out;
	res = -EINVAL;
	if (preferred != 0 && preferred != 1)
		goto out;
	res = scst_tg_set_preferred(tg, preferred);

out:
	kobject_put(w->kobj);
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_tg_preferred_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	char *cmd;
	struct scst_sysfs_work_item *work;
	int res;

	res = -ENOMEM;
	cmd = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!cmd)
		goto out;

	res = scst_alloc_sysfs_work(scst_tg_preferred_store_work_fn, false,
				    &work);
	if (res)
		goto out;

	swap(work->buf, cmd);
	work->kobj = kobj;
	SCST_SET_DEP_MAP(work, &scst_tg_dep_map);
	kobject_get(kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(cmd);
	return res;
}

static struct kobj_attribute scst_tg_preferred =
	__ATTR(preferred, S_IRUGO | S_IWUSR, scst_tg_preferred_show,
	       scst_tg_preferred_store);

static ssize_t scst_tg_state_show(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf)
{
	struct scst_target_group *tg;
	const char *n;

	tg = container_of(kobj, struct scst_target_group, kobj);
	n = scst_alua_state_name(tg->state);

	return scnprintf(buf, PAGE_SIZE, "%s\n" SCST_SYSFS_KEY_MARK "\n",
			 n ? n : "???");
}

static int scst_tg_state_store_work_fn(struct scst_sysfs_work_item *w)
{
	struct scst_target_group *tg;
	char *cmd, *p;
	int res;
	enum scst_tg_state s;

	TRACE_ENTRY();

	cmd = w->buf;
	tg = container_of(w->kobj, struct scst_target_group, kobj);

	p = strchr(cmd, '\n');
	if (p)
		*p = '\0';

	s = scst_alua_name_to_state(cmd);

	res = -EINVAL;
	if (s == SCST_TG_STATE_UNDEFINED)
		goto out;
	res = scst_tg_set_state(tg, s);

out:
	kobject_put(w->kobj);
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_tg_state_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	char *cmd;
	struct scst_sysfs_work_item *work;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	cmd = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!cmd)
		goto out;

	res = scst_alloc_sysfs_work(scst_tg_state_store_work_fn, false,
				    &work);
	if (res)
		goto out;

	swap(work->buf, cmd);
	work->kobj = kobj;
	SCST_SET_DEP_MAP(work, &scst_tg_dep_map);
	kobject_get(kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(cmd);
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tg_state =
	__ATTR(state, S_IRUGO | S_IWUSR, scst_tg_state_show,
	       scst_tg_state_store);

static ssize_t scst_tg_mgmt_show(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	static const char help[] =
		"Usage: echo \"add target\" >mgmt\n"
		"       echo \"del target\" >mgmt\n";

	return scnprintf(buf, PAGE_SIZE, help);
}

static int scst_tg_mgmt_store_work_fn(struct scst_sysfs_work_item *w)
{
	struct scst_target_group *tg;
	char *cmd, *p, *pp, *target_name;
	int res;

	TRACE_ENTRY();

	cmd = w->buf;
	tg = container_of(w->kobj, struct scst_target_group, kobj);

	p = strchr(cmd, '\n');
	if (p)
		*p = '\0';

	res = -EINVAL;
	pp = cmd;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp(p, "add") == 0) {
		target_name = scst_get_next_lexem(&pp);
		if (!*target_name)
			goto out;
		res = scst_tg_tgt_add(tg, target_name);
	} else if (strcasecmp(p, "del") == 0) {
		target_name = scst_get_next_lexem(&pp);
		if (!*target_name)
			goto out;
		res = scst_tg_tgt_remove_by_name(tg, target_name);
	}
out:
	kobject_put(w->kobj);
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_tg_mgmt_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	char *cmd;
	struct scst_sysfs_work_item *work;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	cmd = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!cmd)
		goto out;

	res = scst_alloc_sysfs_work(scst_tg_mgmt_store_work_fn, false,
				    &work);
	if (res)
		goto out;

	swap(work->buf, cmd);
	work->kobj = kobj;
	SCST_SET_DEP_MAP(work, &scst_tg_dep_map);
	kobject_get(kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(cmd);
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tg_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_tg_mgmt_show,
	       scst_tg_mgmt_store);

static const struct attribute *scst_tg_attrs[] = {
	&scst_tg_mgmt.attr,
	&scst_tg_group_id.attr,
	&scst_tg_preferred.attr,
	&scst_tg_state.attr,
	NULL,
};

int scst_tg_sysfs_add(struct scst_dev_group *dg, struct scst_target_group *tg)
{
	int res;

	TRACE_ENTRY();
	res = kobject_add(&tg->kobj, dg->tg_kobj, "%s", tg->name);
	if (res)
		goto err;
	res = sysfs_create_files(&tg->kobj, scst_tg_attrs);
	if (res)
		goto err;
out:
	TRACE_EXIT_RES(res);
	return res;
err:
	scst_tg_sysfs_del(tg);
	goto out;
}

void scst_tg_sysfs_del(struct scst_target_group *tg)
{
	TRACE_ENTRY();
	sysfs_remove_files(&tg->kobj, scst_tg_attrs);
	kobject_del(&tg->kobj);
	TRACE_EXIT();
}

/**
 ** SCST sysfs device_groups/<dg>/target_groups directory implementation.
 **/

static ssize_t scst_dg_tgs_mgmt_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"create group_name\" >mgmt\n"
		"       echo \"del group_name\" >mgmt\n";

	return scnprintf(buf, PAGE_SIZE, help);
}

static int scst_dg_tgs_mgmt_store_work_fn(struct scst_sysfs_work_item *w)
{
	struct scst_dev_group *dg;
	char *cmd, *p, *pp, *dev_name;
	int res;

	TRACE_ENTRY();

	cmd = w->buf;
	dg = scst_lookup_dg_by_kobj(w->kobj);
	WARN_ON(!dg);

	p = strchr(cmd, '\n');
	if (p)
		*p = '\0';

	res = -EINVAL;
	pp = cmd;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp(p, "create") == 0 || strcasecmp(p, "add") == 0) {
		dev_name = scst_get_next_lexem(&pp);
		if (!*dev_name)
			goto out;
		res = scst_tg_add(dg, dev_name);
	} else if (strcasecmp(p, "del") == 0) {
		dev_name = scst_get_next_lexem(&pp);
		if (!*dev_name)
			goto out;
		res = scst_tg_remove_by_name(dg, dev_name);
	}
out:
	kobject_put(w->kobj);
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_dg_tgs_mgmt_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	char *cmd;
	struct scst_sysfs_work_item *work;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	cmd = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!cmd)
		goto out;

	res = scst_alloc_sysfs_work(scst_dg_tgs_mgmt_store_work_fn, false,
				    &work);
	if (res)
		goto out;

	swap(work->buf, cmd);
	work->kobj = kobj;
	SCST_SET_DEP_MAP(work, &scst_dg_dep_map);
	kobject_get(kobj);
	res = scst_sysfs_queue_wait_work(work);
	if (res)
		goto out;
	res = count;

out:
	kfree(cmd);
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_dg_tgs_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_dg_tgs_mgmt_show,
	       scst_dg_tgs_mgmt_store);

static const struct attribute *scst_dg_tgs_attrs[] = {
	&scst_dg_tgs_mgmt.attr,
	NULL,
};

/**
 ** SCST sysfs device_groups directory implementation.
 **/

int scst_dg_sysfs_add(struct kobject *parent, struct scst_dev_group *dg)
{
	int res;

	dg->dev_kobj = NULL;
	dg->tg_kobj = NULL;
	res = kobject_add(&dg->kobj, parent, "%s", dg->name);
	if (res)
		goto err;
	res = -EEXIST;
	dg->dev_kobj = kobject_create_and_add("devices", &dg->kobj);
	if (!dg->dev_kobj)
		goto err;
	res = sysfs_create_files(dg->dev_kobj, scst_dg_devs_attrs);
	if (res)
		goto err;
	dg->tg_kobj = kobject_create_and_add("target_groups", &dg->kobj);
	if (!dg->tg_kobj)
		goto err;
	res = sysfs_create_files(dg->tg_kobj, scst_dg_tgs_attrs);
	if (res)
		goto err;
out:
	return res;
err:
	scst_dg_sysfs_del(dg);
	goto out;
}

void scst_dg_sysfs_del(struct scst_dev_group *dg)
{
	if (dg->tg_kobj) {
		sysfs_remove_files(dg->tg_kobj, scst_dg_tgs_attrs);
		kobject_del(dg->tg_kobj);
		kobject_put(dg->tg_kobj);
		dg->tg_kobj = NULL;
	}
	if (dg->dev_kobj) {
		sysfs_remove_files(dg->dev_kobj, scst_dg_devs_attrs);
		kobject_del(dg->dev_kobj);
		kobject_put(dg->dev_kobj);
		dg->dev_kobj = NULL;
	}
	kobject_del(&dg->kobj);
}

static ssize_t scst_device_groups_mgmt_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	static const char help[] =
		"Usage: echo \"create group_name\" >mgmt\n"
		"       echo \"del group_name\" >mgmt\n";

	return scnprintf(buf, PAGE_SIZE, help);
}

static ssize_t scst_device_groups_mgmt_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	int res;
	char *p, *pp, *input, *group_name;

	TRACE_ENTRY();

	input = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	pp = input;
	p = strchr(input, '\n');
	if (p)
		*p = '\0';

	res = -EINVAL;
	p = scst_get_next_lexem(&pp);
	if (strcasecmp(p, "create") == 0 || strcasecmp(p, "add") == 0) {
		group_name = scst_get_next_lexem(&pp);
		if (!*group_name)
			goto out;
		res = scst_dg_add(scst_device_groups_kobj, group_name);
	} else if (strcasecmp(p, "del") == 0) {
		group_name = scst_get_next_lexem(&pp);
		if (!*group_name)
			goto out;
		res = scst_dg_remove(group_name);
	}
out:
	kfree(input);
	if (res == 0)
		res = count;
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_device_groups_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_device_groups_mgmt_show,
	       scst_device_groups_mgmt_store);

static const struct attribute *scst_device_groups_attrs[] = {
	&scst_device_groups_mgmt.attr,
	NULL,
};

/**
 ** SCST sysfs root directory implementation
 **/

static struct kobject scst_sysfs_root_kobj;

static ssize_t scst_threads_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int count;

	TRACE_ENTRY();

	count = sprintf(buf, "%d\n%s", scst_main_cmd_threads.nr_threads,
		(scst_main_cmd_threads.nr_threads != scst_threads) ?
			SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT();
	return count;
}

static int scst_process_threads_store(int newtn)
{
	int res;
	long oldtn, delta;

	TRACE_ENTRY();

	TRACE_DBG("newtn %d", newtn);

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	oldtn = scst_main_cmd_threads.nr_threads;

	delta = newtn - oldtn;
	if (delta < 0)
		scst_del_threads(&scst_main_cmd_threads, -delta);
	else {
		res = scst_add_threads(&scst_main_cmd_threads, NULL, NULL, delta);
		if (res != 0)
			goto out_up;
	}

	PRINT_INFO("Changed cmd threads num: old %ld, new %d", oldtn, newtn);

out_up:
	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_threads_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_threads_store(work->new_threads_num);
}

static ssize_t scst_threads_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	long newtn;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtol(buf, 0, &newtn);
#else
	res = strict_strtol(buf, 0, &newtn);
#endif
	if (res != 0) {
		PRINT_ERROR("strict_strtol() for %s failed: %d ", buf, res);
		goto out;
	}
	if (newtn <= 0) {
		PRINT_ERROR("Illegal threads num value %ld", newtn);
		res = -EINVAL;
		goto out;
	}

	res = scst_alloc_sysfs_work(scst_threads_store_work_fn, false, &work);
	if (res != 0)
		goto out;

	work->new_threads_num = newtn;

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_threads_attr =
	__ATTR(threads, S_IRUGO | S_IWUSR, scst_threads_show,
	       scst_threads_store);

static ssize_t scst_setup_id_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	int count;

	TRACE_ENTRY();

	count = sprintf(buf, "0x%x\n%s\n", scst_setup_id,
		(scst_setup_id == 0) ? "" : SCST_SYSFS_KEY_MARK);

	TRACE_EXIT();
	return count;
}

static ssize_t scst_setup_id_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	unsigned long val;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtoul(buf, 0, &val);
#else
	res = strict_strtoul(buf, 0, &val);
#endif
	if (res != 0) {
		PRINT_ERROR("strict_strtoul() for %s failed: %d ", buf, res);
		goto out;
	}

	scst_setup_id = val;
	PRINT_INFO("Changed scst_setup_id to %x", scst_setup_id);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_setup_id_attr =
	__ATTR(setup_id, S_IRUGO | S_IWUSR, scst_setup_id_show,
	       scst_setup_id_store);

static ssize_t scst_max_tasklet_cmd_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	int count;

	TRACE_ENTRY();

	count = sprintf(buf, "%d\n%s\n", scst_max_tasklet_cmd,
		(scst_max_tasklet_cmd == SCST_DEF_MAX_TASKLET_CMD)
			? "" : SCST_SYSFS_KEY_MARK);

	TRACE_EXIT();
	return count;
}

static ssize_t scst_max_tasklet_cmd_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	unsigned long val;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	res = kstrtoul(buf, 0, &val);
#else
	res = strict_strtoul(buf, 0, &val);
#endif
	if (res != 0) {
		PRINT_ERROR("strict_strtoul() for %s failed: %d ", buf, res);
		goto out;
	}

	scst_max_tasklet_cmd = val;
	PRINT_INFO("Changed scst_max_tasklet_cmd to %d", scst_max_tasklet_cmd);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_max_tasklet_cmd_attr =
	__ATTR(max_tasklet_cmd, S_IRUGO | S_IWUSR, scst_max_tasklet_cmd_show,
	       scst_max_tasklet_cmd_store);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_main_trace_level_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return scst_trace_level_show(scst_local_trace_tbl, trace_flag,
			buf, NULL);
}

static ssize_t scst_main_trace_level_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_log_mutex);
	if (res != 0)
		goto out;

	res = scst_write_trace(buf, count, &trace_flag,
		SCST_DEFAULT_LOG_FLAGS, "scst", scst_local_trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_main_trace_level_attr =
	__ATTR(trace_level, S_IRUGO | S_IWUSR, scst_main_trace_level_show,
	       scst_main_trace_level_store);

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static void __printf(2, 3) scst_append(void *arg, const char *fmt, ...)
{
	char *buf = arg;
	int len = strlen(buf);
	va_list args;

	va_start(args, fmt);
	vscnprintf(buf + len, SCST_SYSFS_BLOCK_SIZE - len, fmt, args);
	va_end(args);
}

static int scst_process_show_trace_cmds(struct scst_sysfs_work_item *work)
{
	int ret = -ENOMEM;

	work->res_buf = kmalloc(SCST_SYSFS_BLOCK_SIZE, GFP_KERNEL);
	if (!work->res_buf)
		goto put;
	work->res_buf[0] = '\0';
	scst_trace_cmds(scst_append, work->res_buf);
	ret = 0;

put:
	kobject_put(&scst_sysfs_root_kobj);
	return ret;
}

static ssize_t scst_show_trace_cmds(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct scst_sysfs_work_item *work;
	int res;

	res = scst_alloc_sysfs_work(scst_process_show_trace_cmds, true,
				    &work);
	if (res != 0)
		goto out;

	kobject_get(&scst_sysfs_root_kobj);
	scst_sysfs_work_get(work);
	res = scst_sysfs_queue_wait_work(work);
	if (res != 0)
		goto put;

	res = scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%s", work->res_buf);

put:
	scst_sysfs_work_put(work);

out:
	return res;

}

static struct kobj_attribute scst_trace_cmds_attr =
	__ATTR(trace_cmds, S_IRUGO, scst_show_trace_cmds, NULL);

static int scst_process_show_trace_mcmds(struct scst_sysfs_work_item *work)
{
	int ret = -ENOMEM;

	work->res_buf = kmalloc(SCST_SYSFS_BLOCK_SIZE, GFP_KERNEL);
	if (!work->res_buf)
		goto put;
	work->res_buf[0] = '\0';
	scst_trace_mcmds(scst_append, work->res_buf);
	ret = 0;

put:
	kobject_put(&scst_sysfs_root_kobj);
	return ret;
}

static ssize_t scst_show_trace_mcmds(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	struct scst_sysfs_work_item *work;
	int res;

	res = scst_alloc_sysfs_work(scst_process_show_trace_mcmds, true,
				    &work);
	if (res != 0)
		goto out;

	kobject_get(&scst_sysfs_root_kobj);
	scst_sysfs_work_get(work);
	res = scst_sysfs_queue_wait_work(work);
	if (res != 0)
		goto put;

	res = scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%s", work->res_buf);

put:
	scst_sysfs_work_put(work);

out:
	return res;

}

static struct kobj_attribute scst_trace_mcmds_attr =
	__ATTR(trace_mcmds, S_IRUGO, scst_show_trace_mcmds, NULL);

static ssize_t scst_version_show(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	TRACE_ENTRY();

	sprintf(buf, "%s\n", SCST_VERSION_STRING);

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	strcat(buf, "STRICT_SERIALIZING\n");
#endif

#ifdef CONFIG_SCST_EXTRACHECKS
	strcat(buf, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_SCST_TRACING
	strcat(buf, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	strcat(buf, "DEBUG\n");
#endif

#ifdef CONFIG_SCST_DEBUG_TM
	strcat(buf, "DEBUG_TM\n");
#endif

#ifdef CONFIG_SCST_DEBUG_RETRY
	strcat(buf, "DEBUG_RETRY\n");
#endif

#ifdef CONFIG_SCST_DEBUG_OOM
	strcat(buf, "DEBUG_OOM\n");
#endif

#ifdef CONFIG_SCST_DEBUG_SN
	strcat(buf, "DEBUG_SN\n");
#endif

#ifdef CONFIG_SCST_USE_EXPECTED_VALUES
	strcat(buf, "USE_EXPECTED_VALUES\n");
#endif

#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
	strcat(buf, "TEST_IO_IN_SIRQ\n");
#endif

#ifdef CONFIG_SCST_STRICT_SECURITY
	strcat(buf, "STRICT_SECURITY\n");
#endif

	TRACE_EXIT();
	return strlen(buf);
}

static struct kobj_attribute scst_version_attr =
	__ATTR(version, S_IRUGO, scst_version_show, NULL);

static ssize_t scst_last_sysfs_mgmt_res_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int res;

	TRACE_ENTRY();

	spin_lock(&sysfs_work_lock);
	TRACE_DBG("active_sysfs_works %d", active_sysfs_works);
	if (active_sysfs_works > 0)
		res = -EAGAIN;
	else
		res = sprintf(buf, "%d\n", last_sysfs_work_res);
	spin_unlock(&sysfs_work_lock);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_last_sysfs_mgmt_res_attr =
	__ATTR(last_sysfs_mgmt_res, S_IRUGO,
		scst_last_sysfs_mgmt_res_show, NULL);

static struct attribute *scst_sysfs_root_default_attrs[] = {
	&scst_threads_attr.attr,
	&scst_setup_id_attr.attr,
	&scst_max_tasklet_cmd_attr.attr,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	&scst_main_trace_level_attr.attr,
#endif
	&scst_trace_cmds_attr.attr,
	&scst_trace_mcmds_attr.attr,
	&scst_version_attr.attr,
	&scst_last_sysfs_mgmt_res_attr.attr,
	NULL,
};

static void scst_sysfs_root_release(struct kobject *kobj)
{
	complete_all(&scst_sysfs_root_release_completion);
}

static struct kobj_type scst_sysfs_root_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_root_release,
	.default_attrs = scst_sysfs_root_default_attrs,
};

/**
 ** Sysfs user info
 **/

static DEFINE_MUTEX(scst_sysfs_user_info_mutex);

/* All protected by scst_sysfs_user_info_mutex */
static LIST_HEAD(scst_sysfs_user_info_list);
static uint32_t scst_sysfs_info_cur_cookie;

/* scst_sysfs_user_info_mutex supposed to be held */
static struct scst_sysfs_user_info *scst_sysfs_user_find_info(uint32_t cookie)
{
	struct scst_sysfs_user_info *info, *res = NULL;

	TRACE_ENTRY();

	list_for_each_entry(info, &scst_sysfs_user_info_list,
			info_list_entry) {
		if (info->info_cookie == cookie) {
			res = info;
			break;
		}
	}

	TRACE_EXIT_HRES(res);
	return res;
}

/**
 * scst_sysfs_user_get_info() - get user_info
 *
 * Finds the user_info based on cookie and mark it as received the reply by
 * setting for it flag info_being_executed.
 *
 * Returns found entry or NULL.
 */
struct scst_sysfs_user_info *scst_sysfs_user_get_info(uint32_t cookie)
{
	struct scst_sysfs_user_info *res = NULL;

	TRACE_ENTRY();

	mutex_lock(&scst_sysfs_user_info_mutex);

	res = scst_sysfs_user_find_info(cookie);
	if (res != NULL) {
		if (!res->info_being_executed)
			res->info_being_executed = 1;
	}

	mutex_unlock(&scst_sysfs_user_info_mutex);

	TRACE_EXIT_HRES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_sysfs_user_get_info);

/**
 ** Helper functionality to help target drivers and dev handlers support
 ** sending events to user space and wait for their completion in a safe
 ** manner. See samples how to use it in iscsi-scst or scst_user.
 **/

/**
 * scst_sysfs_user_add_info() - create and add user_info in the global list
 *
 * Creates an info structure and adds it in the info_list.
 * Returns 0 and out_info on success, error code otherwise.
 */
int scst_sysfs_user_add_info(struct scst_sysfs_user_info **out_info)
{
	int res = 0;
	struct scst_sysfs_user_info *info;

	TRACE_ENTRY();

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL) {
		PRINT_ERROR("Unable to allocate sysfs user info (size %zd)",
			sizeof(*info));
		res = -ENOMEM;
		goto out;
	}

	mutex_lock(&scst_sysfs_user_info_mutex);

	while ((info->info_cookie == 0) ||
	       (scst_sysfs_user_find_info(info->info_cookie) != NULL))
		info->info_cookie = scst_sysfs_info_cur_cookie++;

	init_completion(&info->info_completion);

	list_add_tail(&info->info_list_entry, &scst_sysfs_user_info_list);
	info->info_in_list = 1;

	*out_info = info;

	mutex_unlock(&scst_sysfs_user_info_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_sysfs_user_add_info);

/**
 * scst_sysfs_user_del_info - delete and frees user_info
 */
void scst_sysfs_user_del_info(struct scst_sysfs_user_info *info)
{
	TRACE_ENTRY();

	mutex_lock(&scst_sysfs_user_info_mutex);

	if (info->info_in_list)
		list_del(&info->info_list_entry);

	mutex_unlock(&scst_sysfs_user_info_mutex);

	kfree(info);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_sysfs_user_del_info);

/*
 * Returns true if the reply received and being processed by another part of
 * the kernel, false otherwise. Also removes the user_info from the list to
 * fix for the user space that it missed the timeout.
 */
static bool scst_sysfs_user_info_executing(struct scst_sysfs_user_info *info)
{
	bool res;

	TRACE_ENTRY();

	mutex_lock(&scst_sysfs_user_info_mutex);

	res = info->info_being_executed;

	if (info->info_in_list) {
		list_del(&info->info_list_entry);
		info->info_in_list = 0;
	}

	mutex_unlock(&scst_sysfs_user_info_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

/**
 * scst_wait_info_completion() - wait an user space event's completion
 *
 * Waits for the info request been completed by user space at most timeout
 * jiffies. If the reply received before timeout and being processed by
 * another part of the kernel, i.e. scst_sysfs_user_info_executing()
 * returned true, waits for it to complete indefinitely.
 *
 * Returns status of the request completion.
 */
int scst_wait_info_completion(struct scst_sysfs_user_info *info,
	unsigned long timeout)
{
	int res, rc;

	TRACE_ENTRY();

	TRACE_DBG("Waiting for info %p completion", info);

	while (1) {
		rc = wait_for_completion_interruptible_timeout(
			&info->info_completion, timeout);
		if (rc > 0) {
			TRACE_DBG("Waiting for info %p finished with %d",
				info, rc);
			break;
		} else if (rc == 0) {
			if (!scst_sysfs_user_info_executing(info)) {
				PRINT_ERROR("Timeout waiting for user "
					"space event %p", info);
				res = -EBUSY;
				goto out;
			} else {
				/* Req is being executed in the kernel */
				TRACE_DBG("Keep waiting for info %p completion",
					info);
				wait_for_completion(&info->info_completion);
				break;
			}
		} else if (rc != -ERESTARTSYS) {
				res = rc;
				PRINT_ERROR("wait_for_completion() failed: %d",
					res);
				goto out;
		} else {
			TRACE_DBG("Waiting for info %p finished with %d, "
				"retrying", info, rc);
		}
	}

	TRACE_DBG("info %p, status %d", info, info->info_status);
	res = info->info_status;

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_wait_info_completion);

int __init scst_sysfs_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	sysfs_work_thread = kthread_run(sysfs_work_thread_fn,
		NULL, "scst_uid");
	if (IS_ERR(sysfs_work_thread)) {
		res = PTR_ERR(sysfs_work_thread);
		PRINT_ERROR("kthread_run() for user interface thread "
			"failed: %d", res);
		sysfs_work_thread = NULL;
		goto out;
	}

	res = kobject_init_and_add(&scst_sysfs_root_kobj,
			&scst_sysfs_root_ktype, kernel_kobj, "%s", "scst_tgt");
	if (res != 0)
		goto sysfs_root_add_error;

	scst_targets_kobj = kobject_create_and_add("targets",
				&scst_sysfs_root_kobj);
	if (scst_targets_kobj == NULL)
		goto targets_kobj_error;

	scst_devices_kobj = kobject_create_and_add("devices",
				&scst_sysfs_root_kobj);
	if (scst_devices_kobj == NULL)
		goto devices_kobj_error;

	res = scst_add_sgv_kobj(&scst_sysfs_root_kobj, "sgv");
	if (res != 0)
		goto sgv_kobj_error;

	scst_handlers_kobj = kobject_create_and_add("handlers",
					&scst_sysfs_root_kobj);
	if (scst_handlers_kobj == NULL)
		goto handlers_kobj_error;

	scst_device_groups_kobj = kobject_create_and_add("device_groups",
							 &scst_sysfs_root_kobj);
	if (scst_device_groups_kobj == NULL)
		goto device_groups_kobj_error;

	if (sysfs_create_files(scst_device_groups_kobj,
			       scst_device_groups_attrs))
		goto device_groups_attrs_error;

out:
	TRACE_EXIT_RES(res);
	return res;

device_groups_attrs_error:
	kobject_del(scst_device_groups_kobj);
	kobject_put(scst_device_groups_kobj);

device_groups_kobj_error:
	kobject_del(scst_handlers_kobj);
	kobject_put(scst_handlers_kobj);

handlers_kobj_error:
	scst_del_put_sgv_kobj();

sgv_kobj_error:
	kobject_del(scst_devices_kobj);
	kobject_put(scst_devices_kobj);

devices_kobj_error:
	kobject_del(scst_targets_kobj);
	kobject_put(scst_targets_kobj);

targets_kobj_error:
	kobject_del(&scst_sysfs_root_kobj);

sysfs_root_add_error:
	kobject_put(&scst_sysfs_root_kobj);

	kthread_stop(sysfs_work_thread);

	if (res == 0)
		res = -EINVAL;

	goto out;
}

void scst_sysfs_cleanup(void)
{
	TRACE_ENTRY();

	PRINT_INFO("%s", "Exiting SCST sysfs hierarchy...");

	scst_del_put_sgv_kobj();

	kobject_del(scst_devices_kobj);
	kobject_put(scst_devices_kobj);

	kobject_del(scst_targets_kobj);
	kobject_put(scst_targets_kobj);

	kobject_del(scst_handlers_kobj);
	kobject_put(scst_handlers_kobj);

	sysfs_remove_files(scst_device_groups_kobj, scst_device_groups_attrs);

	kobject_del(scst_device_groups_kobj);
	kobject_put(scst_device_groups_kobj);

	kobject_del(&scst_sysfs_root_kobj);
	kobject_put(&scst_sysfs_root_kobj);

	wait_for_completion(&scst_sysfs_root_release_completion);
	/*
	 * There is a race, when in the release() schedule happens just after
	 * calling complete(), so if we exit and unload scst module immediately,
	 * there will be oops there. So let's give it a chance to quit
	 * gracefully. Unfortunately, current kobjects implementation
	 * doesn't allow better ways to handle it.
	 */
	msleep(3000);

	if (sysfs_work_thread)
		kthread_stop(sysfs_work_thread);

	PRINT_INFO("%s", "Exiting SCST sysfs hierarchy done");

	TRACE_EXIT();
	return;
}
