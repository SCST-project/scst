/*
 *  scst_sysfs.c
 *
 *  Copyright (C) 2009 Daniel Henrique Debonzi <debonzi@linux.vnet.ibm.com>
 *  Copyright (C) 2009 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
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
#include "scst_mem.h"

#undef DEFAULT_SYMBOL_NAMESPACE
#define DEFAULT_SYMBOL_NAMESPACE	SCST_NAMESPACE

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

static ssize_t scst_read_trace_tbl(const struct scst_trace_log *tbl, char *buf,
				   unsigned long log_level, ssize_t ret)
{
	const struct scst_trace_log *t = tbl;

	if (!t)
		goto out;

	while (t->token) {
		if (log_level & t->val)
			ret += sysfs_emit_at(buf, ret, "%s%s",
					     ret == 0 ? "" : " | ", t->token);
		t++;
	}

out:
	return ret;
}

static ssize_t scst_trace_level_show(const struct scst_trace_log *local_tbl,
				     unsigned long log_level, char *buf, const char *help)
{
	ssize_t ret = 0;

	ret += scst_read_trace_tbl(scst_trace_tbl, buf, log_level, ret);
	ret += scst_read_trace_tbl(local_tbl, buf, log_level, ret);

	ret += sysfs_emit_at(buf, ret,
			     "\n\n\nUsage:\n"
			     "	echo \"all|none|default\" >trace_level\n"
			     "	echo \"value DEC|0xHEX|0OCT\" >trace_level\n"
			     "	echo \"add|del TOKEN\" >trace_level\n"
#ifdef CONFIG_SCST_DEBUG
			     "\nwhere TOKEN is one of [debug, function, line, pid,\n"
#ifndef GENERATING_UPSTREAM_PATCH
			     "		       entryexit, buff, mem, sg, out_of_mem,\n"
#else
			     "		       buff, mem, sg, out_of_mem,\n"
#endif
			     "		       special, scsi, mgmt, minor,\n"
			     "		       mgmt_dbg, scsi_serializing,\n"
			     "		       retry, pr, block%s]\n",
#else /* CONFIG_SCST_DEBUG */
			     "\nwhere TOKEN is one of [function, line, pid, out_of_mem, special, scsi, mgmt, minor, scsi_serializing, retry, pr%s]\n",

#endif /* CONFIG_SCST_DEBUG */
			     help ? help : "");

	return ret;
}

static int scst_write_trace(const char *buf, size_t length, unsigned long *log_level,
			    unsigned long default_level, const char *name,
			    const struct scst_trace_log *tbl)
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

	if (!buf || length == 0) {
		res = -EINVAL;
		goto out;
	}

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)length, buf);
	if (!buffer) {
		PRINT_ERROR("Unable to alloc intermediate buffer (size %zd)",
			    length + 1);
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
		res = kstrtoul(p, 0, &level);
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

/*
 ** Sysfs work
 **/

static DEFINE_SPINLOCK(sysfs_work_lock);
static LIST_HEAD(sysfs_work_list);
static DECLARE_WAIT_QUEUE_HEAD(sysfs_work_waitQ);
static int active_sysfs_works;
static int last_sysfs_work_res;
static struct task_struct *sysfs_work_thread;

/*
 * scst_alloc_sysfs_work() - allocates a sysfs work
 */
int scst_alloc_sysfs_work(int (*sysfs_work_fn)(struct scst_sysfs_work_item *),
			  bool read_only_action, struct scst_sysfs_work_item **res_work)
{
	int res = 0;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	if (!sysfs_work_fn) {
		PRINT_ERROR("sysfs_work_fn is NULL");
		res = -EINVAL;
		goto out;
	}

	*res_work = NULL;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
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

	work = container_of(kref, struct scst_sysfs_work_item, sysfs_work_kref);

	TRACE_DBG("Freeing sysfs work %p (buf %p)", work, work->buf);

	kfree(work->buf);
	kfree(work->res_buf);
	kfree(work);

	TRACE_EXIT();
}

/*
 * scst_sysfs_work_get() - increases ref counter of the sysfs work
 */
void scst_sysfs_work_get(struct scst_sysfs_work_item *work)
{
	kref_get(&work->sysfs_work_kref);
}
EXPORT_SYMBOL(scst_sysfs_work_get);

/*
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
		work = list_first_entry(&sysfs_work_list, struct scst_sysfs_work_item,
					sysfs_work_list_entry);
		list_del(&work->sysfs_work_list_entry);
		spin_unlock(&sysfs_work_lock);

		TRACE_DBG("Sysfs work %p", work);

		if (work->dep_map) {
			mutex_acquire(work->dep_map, 0, 0, _RET_IP_);
			lock_acquired(work->dep_map, _RET_IP_);
		}

		work->work_res = work->sysfs_work_fn(work);

		if (work->dep_map)
			mutex_release(work->dep_map, _RET_IP_);

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
		PRINT_INFO("User interface thread started");

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -10);

	spin_lock(&sysfs_work_lock);
	while (!kthread_should_stop()) {
		if (one_time_only && !test_sysfs_work_list())
			break;
		scst_wait_event_interruptible_lock(sysfs_work_waitQ, test_sysfs_work_list(),
						   sysfs_work_lock);
		scst_process_sysfs_works();
	}
	spin_unlock(&sysfs_work_lock);

	if (!one_time_only) {
		/*
		 * If kthread_should_stop() is true, we are guaranteed to be
		 * on the module unload, so both lists must be empty.
		 */
		sBUG_ON(!list_empty(&sysfs_work_list));

		PRINT_INFO("User interface thread finished");
	}

	TRACE_EXIT();
	return 0;
}

/*
 * scst_sysfs_queue_wait_work() - waits for the work to complete
 *
 * Returns status of the completed work or -EAGAIN if the work not
 * completed before timeout. In the latter case a user should poll
 * last_sysfs_mgmt_res until it returns the result of the processing.
 */
int scst_sysfs_queue_wait_work(struct scst_sysfs_work_item *work)
{
	int res = 0, rc;
	unsigned long timeout = 15 * HZ;
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
		PRINT_ERROR("kthread_run() for user interface thread %d failed: %d",
			    atomic_read(&uid_thread_name), (int)PTR_ERR(t));

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
		rc = wait_for_completion_interruptible_timeout(&work->sysfs_work_done, timeout);
		if (rc == 0) {
			if (!mutex_is_locked(&scst_mutex)) {
				TRACE_DBG("scst_mutex not locked, continue waiting (work %p)",
					  work);
				timeout = 5 * HZ;
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

				if (!acg)
					goto out;
				if (acg == tgt->default_acg)
					goto out;
				list_for_each_entry(a, &tgt->tgt_acg_list, acg_list_entry) {
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
static int scst_check_devt_ptr(struct scst_dev_type *devt, struct list_head *list)
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
static int scst_check_grab_devt_ptr(struct scst_dev_type *devt, struct list_head *list)
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
}

/*
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

const struct sysfs_ops scst_sysfs_ops = {
	.show = scst_show,
	.store = scst_store,
};

const struct sysfs_ops *scst_sysfs_get_sysfs_ops(void)
{
	return &scst_sysfs_ops;
}
EXPORT_SYMBOL_GPL(scst_sysfs_get_sysfs_ops);

/*
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
}

static struct kobj_type tgtt_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_tgtt_release,
};

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_tgtt_trace_level_show(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buf)
{
	struct scst_tgt_template *tgtt;

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	return scst_trace_level_show(tgtt->trace_tbl, tgtt->trace_flags ? *tgtt->trace_flags : 0,
				     buf, tgtt->trace_tbl_help);
}

static ssize_t scst_tgtt_trace_level_store(struct kobject *kobj, struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	int res;
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	res = mutex_lock_interruptible(&scst_log_mutex);
	if (res != 0)
		goto out;

	res = scst_write_trace(buf, count, tgtt->trace_flags, tgtt->default_trace_flags,
			       tgtt->name, tgtt->trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute tgtt_trace_attr =
	__ATTR(trace_level, 0644, scst_tgtt_trace_level_show, scst_tgtt_trace_level_store);

#endif /* #if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static ssize_t scst_tgtt_mgmt_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add_target target_name [parameters]\" >mgmt\n"
		"       echo \"del_target target_name\" >mgmt\n"
		"%s%s"
		"%s"
		"\n"
		"where parameters are one or more param_name=value pairs separated by ';'\n\n"
		"%s%s%s%s%s%s%s%s%s%s\n";
	struct scst_tgt_template *tgtt;

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	return sysfs_emit(buf, help,
			  tgtt->tgtt_optional_attributes ?
			  "       echo \"add_attribute <attribute> <value>\" >mgmt\n"
			  "       echo \"del_attribute <attribute> <value>\" >mgmt\n" : "",
			  tgtt->tgt_optional_attributes ?
			  "       echo \"add_target_attribute target_name <attribute> <value>\" >mgmt\n"
			  "       echo \"del_target_attribute target_name <attribute> <value>\" >mgmt\n" : "",
			  tgtt->mgmt_cmd_help ? tgtt->mgmt_cmd_help : "",
			  tgtt->mgmt_cmd_help ? "\n" : "",
			  tgtt->add_target_parameters ?
			  "The following parameters available: " : "",
			  tgtt->add_target_parameters ? tgtt->add_target_parameters : "",
			  tgtt->add_target_parameters ? "\n" : "",
			  tgtt->tgtt_optional_attributes ?
			  "The following target driver attributes available: " : "",
			  tgtt->tgtt_optional_attributes ? tgtt->tgtt_optional_attributes : "",
			  tgtt->tgtt_optional_attributes ? "\n" : "",
			  tgtt->tgt_optional_attributes ?
			  "The following target attributes available: " : "",
			  tgtt->tgt_optional_attributes ? tgtt->tgt_optional_attributes : "",
			  tgtt->tgt_optional_attributes ? "\n" : "");
}

static int scst_process_tgtt_mgmt_store(char *buffer, struct scst_tgt_template *tgtt)
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
			PRINT_ERROR("Target name required");
			res = -EINVAL;
			goto out_ungrab;
		}
		res = tgtt->add_target(target_name, pp);
	} else if (strcasecmp("del_target", p) == 0) {
		target_name = scst_get_next_lexem(&pp);
		if (*target_name == '\0') {
			PRINT_ERROR("Target name required");
			res = -EINVAL;
			goto out_ungrab;
		}

		p = scst_get_next_lexem(&pp);
		if (*p != '\0')
			goto out_syntax_err;

		res = tgtt->del_target(target_name);
	} else if (tgtt->mgmt_cmd) {
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

static ssize_t scst_tgtt_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res;
	char *buffer;
	struct scst_sysfs_work_item *work;
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!buffer) {
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
	__ATTR(mgmt, 0644, scst_tgtt_mgmt_show, scst_tgtt_mgmt_store);

static ssize_t scst_tgtt_dif_capable_show(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buf)
{
	struct scst_tgt_template *tgtt;
	ssize_t ret = 0;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	EXTRACHECKS_BUG_ON(!tgtt->dif_supported);

	ret += sysfs_emit_at(buf, ret, "dif_supported");

	if (tgtt->hw_dif_type1_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_type1_supported");

	if (tgtt->hw_dif_type2_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_type2_supported");

	if (tgtt->hw_dif_type3_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_type3_supported");

	if (tgtt->hw_dif_ip_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_ip_supported");

	if (tgtt->hw_dif_same_sg_layout_required)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_same_sg_layout_required");

	ret += sysfs_emit_at(buf, ret, "\n");

	if (tgtt->supported_dif_block_sizes) {
		const int *p = tgtt->supported_dif_block_sizes;
		ssize_t pos;

		ret += sysfs_emit_at(buf, ret, "Supported blocks: ");
		pos = ret;

		while (*p != 0) {
			ret += sysfs_emit_at(buf, ret, "%s%d",
					     ret == pos ? "" : ", ", *p);
			p++;
		}
	}

	TRACE_EXIT_RES(ret);
	return ret;
}

static struct kobj_attribute scst_tgtt_dif_capable_attr =
	__ATTR(dif_capabilities, 0444, scst_tgtt_dif_capable_show, NULL);

/*
 * Creates an attribute entry for target driver.
 */
int scst_create_tgtt_attr(struct scst_tgt_template *tgtt, struct kobj_attribute *attribute)
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

	res = kobject_init_and_add(&tgtt->tgtt_kobj, &tgtt_ktype, scst_targets_kobj, "%s",
				   tgtt->name);
	if (res != 0) {
		PRINT_ERROR("Can't add tgtt %s to sysfs", tgtt->name);
		goto out;
	}

	if (tgtt->add_target) {
		res = sysfs_create_file(&tgtt->tgtt_kobj, &scst_tgtt_mgmt.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add mgmt attr for target driver %s",
				    tgtt->name);
			goto out_del;
		}
	}

	if (tgtt->tgtt_attrs) {
		res = sysfs_create_files(&tgtt->tgtt_kobj, tgtt->tgtt_attrs);
		if (res != 0) {
			PRINT_ERROR("Can't add attributes for target driver %s",
				    tgtt->name);
			goto out_del;
		}
	}

	if (tgtt->dif_supported) {
		res = sysfs_create_file(&tgtt->tgtt_kobj, &scst_tgtt_dif_capable_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add attribute %s for target driver %s",
				    scst_tgtt_dif_capable_attr.attr.name, tgtt->name);
			goto out;
		}
	}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (tgtt->trace_flags) {
		res = sysfs_create_file(&tgtt->tgtt_kobj, &tgtt_trace_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add trace_flag for target driver %s",
				    tgtt->name);
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
#if defined(CONFIG_LOCKDEP)
			       , struct lockdep_map *dep_map
#endif
			       )
{
	char *name;

	TRACE_ENTRY();

	name = kstrdup(kobject_name(kobj), GFP_KERNEL);

	kobject_put(kobj);

	mutex_acquire(dep_map, 0, 0, _RET_IP_);

	if (wait_for_completion_timeout(c, HZ) > 0)
		goto out_free;

	PRINT_INFO("Waiting for release of sysfs entry for %s %s (%d refs)",
		   category, name ? : "(?)", kref_read(&kobj->kref));
	wait_for_completion(c);
	PRINT_INFO("Finished waiting for release of %s %s sysfs entry",
		   category, name ? : "(?)");

out_free:
	lock_acquired(dep_map, _RET_IP_);
	mutex_release(dep_map, _RET_IP_);

	kfree(name);

	TRACE_EXIT();
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
}

/*
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
}

static int scst_parse_add_repl_param(struct scst_acg *acg,
				     struct scst_device *dev, char *pp,
				     unsigned long *virt_lun,
				     bool *read_only)
{
	int res;
	char *e;

	*read_only = false;
	e = scst_get_next_lexem(&pp);
	res = kstrtoul(e, 0, virt_lun);
	if (res != 0) {
		PRINT_ERROR("Valid LUN required for dev %s (res %d)",
			    dev->virt_name, res);
		goto out;
	} else if (*virt_lun > SCST_MAX_LUN) {
		PRINT_ERROR("Too big LUN %ld (max %d)", *virt_lun, SCST_MAX_LUN);
		res = -EINVAL;
		goto out;
	}

	while (1) {
		unsigned long val;
		char *param = scst_get_next_token_str(&pp);
		char *p, *pp;

		if (!param)
			break;

		p = scst_get_next_lexem(&param);
		if (*p == '\0') {
			PRINT_ERROR("Syntax error at %s (device %s)", param,
				    dev->virt_name);
			res = -EINVAL;
			goto out;
		}

		pp = scst_get_next_lexem(&param);
		if (*pp == '\0') {
			PRINT_ERROR("Parameter %s value missed for device %s",
				    p, dev->virt_name);
			res = -EINVAL;
			goto out;
		}

		if (scst_get_next_lexem(&param)[0] != '\0') {
			PRINT_ERROR("Too many parameter %s values (device %s)",
				    p, dev->virt_name);
			res = -EINVAL;
			goto out;
		}

		res = kstrtoul(pp, 0, &val);
		if (res != 0) {
			PRINT_ERROR("kstrtoul() for %s failed: %d (device %s)",
				    pp, res, dev->virt_name);
			goto out;
		}

		if (strcasecmp("read_only", p) == 0) {
			*read_only = !!val;
			TRACE_DBG("READ ONLY %d", *read_only);
		} else {
			PRINT_ERROR("Unknown parameter %s (device %s)", p,
				    dev->virt_name);
			res = -EINVAL;
			goto out;
		}
	}

	res = 0;

out:
	return res;
}

static int __scst_process_luns_mgmt_store(char *buffer, struct scst_tgt *tgt, struct scst_acg *acg,
					  bool tgt_kobj)
{
	int res, action;
	bool read_only;
	char *p, *pp;
	unsigned long virt_lun;
	struct scst_acg_dev *acg_dev = NULL, *acg_dev_tmp;
	struct scst_device *d, *dev = NULL;
	enum {
		SCST_LUN_ACTION_ADD	= 1,
		SCST_LUN_ACTION_DEL	= 2,
		SCST_LUN_ACTION_REPLACE	= 3,
		SCST_LUN_ACTION_CLEAR	= 4,
	};
	bool replace_gen_ua = true;

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
		replace_gen_ua = true;
	} else if (strcasecmp("replace_no_ua", p) == 0) {
		action = SCST_LUN_ACTION_REPLACE;
		replace_gen_ua = false;
	} else if (strcasecmp("clear", p) == 0) {
		action = SCST_LUN_ACTION_CLEAR;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out;
	}

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	/* Check if tgt and acg not already freed while we were coming here */
	if (scst_check_tgt_acg_ptrs(tgt, acg) != 0)
		goto out_unlock;

	if (action != SCST_LUN_ACTION_CLEAR && action != SCST_LUN_ACTION_DEL) {
		p = scst_get_next_lexem(&pp);
		list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
			if (!strcmp(d->virt_name, p)) {
				dev = d;
				TRACE_DBG("Device %p (%s) found", dev, p);
				break;
			}
		}
		if (!dev) {
			PRINT_ERROR("Device '%s' not found", p);
			res = -EINVAL;
			goto out_unlock;
		}
	}

	switch (action) {
	case SCST_LUN_ACTION_ADD:
	{
		unsigned int flags = SCST_ADD_LUN_GEN_UA;

		res = scst_parse_add_repl_param(acg, dev, pp, &virt_lun,
						&read_only);
		if (res != 0)
			goto out_unlock;

		acg_dev = NULL;
		list_for_each_entry(acg_dev_tmp, &acg->acg_dev_list,
				    acg_dev_list_entry) {
			if (acg_dev_tmp->lun == virt_lun) {
				acg_dev = acg_dev_tmp;
				break;
			}
		}

		if (acg_dev) {
			PRINT_ERROR("virt lun %ld already exists in group %s",
				    virt_lun, acg->acg_name);
			res = -EEXIST;
			goto out_unlock;
		}

		if (read_only)
			flags |= SCST_ADD_LUN_READ_ONLY;
		res = scst_acg_add_lun(acg, tgt_kobj ? tgt->tgt_luns_kobj : acg->luns_kobj,
				       dev, virt_lun, flags, NULL);
		if (res != 0)
			goto out_unlock;
		break;
	}
	case SCST_LUN_ACTION_REPLACE:
	{
		unsigned int flags = replace_gen_ua ? SCST_REPL_LUN_GEN_UA : 0;

		res = scst_parse_add_repl_param(acg, dev, pp, &virt_lun,
						&read_only);
		if (res != 0)
			goto out_unlock;

		flags |= read_only ? SCST_ADD_LUN_READ_ONLY : 0;
		res = scst_acg_repl_lun(acg, tgt_kobj ? tgt->tgt_luns_kobj :
					acg->luns_kobj, dev, virt_lun,
					flags);
		if (res != 0)
			goto out_unlock;
		break;
	}
	case SCST_LUN_ACTION_DEL:
		p = scst_get_next_lexem(&pp);
		res = kstrtoul(p, 0, &virt_lun);
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

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_luns_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return __scst_process_luns_mgmt_store(work->buf, work->tgt, work->acg, work->is_tgt_kobj);
}

static ssize_t __scst_acg_mgmt_store(struct scst_acg *acg, const char *buf, size_t count,
				     bool is_tgt_kobj,
				     int (*sysfs_work_fn)(struct scst_sysfs_work_item *))
{
	int res;
	char *buffer;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!buffer) {
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

static ssize_t __scst_luns_mgmt_store(struct scst_acg *acg, bool tgt_kobj, const char *buf,
				      size_t count)
{
	return __scst_acg_mgmt_store(acg, buf, count, tgt_kobj, scst_luns_mgmt_store_work_fn);
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
		"       echo \"replace_no_ua H:C:I:L lun [parameters]\" >mgmt\n"
		"       echo \"replace_no_ua VNAME lun [parameters]\" >mgmt\n"
		"       echo \"clear\" >mgmt\n"
		"\n"
		"where parameters are one or more param_name=value pairs separated by ';'\n"
		"\nThe following parameters available: read_only";

	return sysfs_emit(buf, "%s\n", help);
}

static ssize_t scst_luns_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	TRACE_ENTRY();

	tgt = container_of(kobj->parent, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	res = __scst_luns_mgmt_store(acg, true, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_luns_mgmt =
	__ATTR(mgmt, 0644, scst_luns_mgmt_show, scst_luns_mgmt_store);

static ssize_t __scst_acg_addr_method_show(struct scst_acg *acg, char *buf)
{
	ssize_t ret;

	switch (acg->addr_method) {
	case SCST_LUN_ADDR_METHOD_FLAT:
		ret = sysfs_emit(buf, "FLAT\n");
		break;
	case SCST_LUN_ADDR_METHOD_PERIPHERAL:
		ret = sysfs_emit(buf, "PERIPHERAL\n");
		break;
	case SCST_LUN_ADDR_METHOD_LUN:
		ret = sysfs_emit(buf, "LUN\n");
		break;
	default:
		ret = sysfs_emit(buf, "UNKNOWN\n");
		break;
	}

	if (acg->addr_method != acg->tgt->tgtt->preferred_addr_method)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	return ret;
}

static ssize_t __scst_acg_addr_method_store(struct scst_acg *acg, const char *buf, size_t count)
{
	int res = count;

	if (strncasecmp(buf, "FLAT", min_t(int, 4, count)) == 0) {
		acg->addr_method = SCST_LUN_ADDR_METHOD_FLAT;
	} else if (strncasecmp(buf, "PERIPHERAL", min_t(int, 10, count)) == 0) {
		acg->addr_method = SCST_LUN_ADDR_METHOD_PERIPHERAL;
	} else if (strncasecmp(buf, "LUN", min_t(int, 3, count)) == 0) {
		acg->addr_method = SCST_LUN_ADDR_METHOD_LUN;
	} else {
		PRINT_ERROR("Unknown address method %s", buf);
		res = -EINVAL;
	}

	TRACE_DBG("acg %p, addr_method %d", acg, acg->addr_method);

	return res;
}

static ssize_t scst_tgt_addr_method_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	return __scst_acg_addr_method_show(acg, buf);
}

static ssize_t scst_tgt_addr_method_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	res = __scst_acg_addr_method_store(acg, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_addr_method =
	__ATTR(addr_method, 0644, scst_tgt_addr_method_show, scst_tgt_addr_method_store);

static ssize_t __scst_acg_io_grouping_type_show(struct scst_acg *acg, char *buf)
{
	ssize_t ret;

	switch (acg->acg_io_grouping_type) {
	case SCST_IO_GROUPING_AUTO:
		ret = sysfs_emit(buf, "%s\n", SCST_IO_GROUPING_AUTO_STR);
		break;
	case SCST_IO_GROUPING_THIS_GROUP_ONLY:
		ret = sysfs_emit(buf, "%s\n%s\n",
				 SCST_IO_GROUPING_THIS_GROUP_ONLY_STR, SCST_SYSFS_KEY_MARK);
		break;
	case SCST_IO_GROUPING_NEVER:
		ret = sysfs_emit(buf, "%s\n%s\n",
				 SCST_IO_GROUPING_NEVER_STR, SCST_SYSFS_KEY_MARK);
		break;
	default:
		ret = sysfs_emit(buf, "%d\n%s\n",
				 acg->acg_io_grouping_type, SCST_SYSFS_KEY_MARK);
		break;
	}

	return ret;
}

static int __scst_acg_process_io_grouping_type_store(struct scst_tgt *tgt, struct scst_acg *acg,
						     int io_grouping_type)
{
	int res = 0;
	struct scst_acg_dev *acg_dev;

	TRACE_DBG("tgt %p, acg %p, io_grouping_type %d",
		  tgt, acg, io_grouping_type);

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

static ssize_t __scst_acg_io_grouping_type_store(struct scst_acg *acg, const char *buf,
						 size_t count)
{
	int res = 0;
	int prev = acg->acg_io_grouping_type;
	long io_grouping_type;
	struct scst_sysfs_work_item *work;

	if (strncasecmp(buf, SCST_IO_GROUPING_AUTO_STR,
			min_t(int, strlen(SCST_IO_GROUPING_AUTO_STR), count)) == 0) {
		io_grouping_type = SCST_IO_GROUPING_AUTO;
	} else if (strncasecmp(buf, SCST_IO_GROUPING_THIS_GROUP_ONLY_STR,
			       min_t(int, strlen(SCST_IO_GROUPING_THIS_GROUP_ONLY_STR), count)) == 0) {
		io_grouping_type = SCST_IO_GROUPING_THIS_GROUP_ONLY;
	} else if (strncasecmp(buf, SCST_IO_GROUPING_NEVER_STR,
			       min_t(int, strlen(SCST_IO_GROUPING_NEVER_STR), count)) == 0) {
		io_grouping_type = SCST_IO_GROUPING_NEVER;
	} else {
		res = kstrtol(buf, 0, &io_grouping_type);
		if (res != 0 || io_grouping_type <= 0) {
			PRINT_ERROR("Unknown or not allowed I/O grouping type %s", buf);
			res = -EINVAL;
			goto out;
		}
	}

	if (prev == io_grouping_type)
		goto out;

	res = scst_alloc_sysfs_work(__scst_acg_io_grouping_type_store_work_fn, false, &work);
	if (res != 0)
		goto out;

	work->tgt = acg->tgt;
	work->acg = acg;
	work->io_grouping_type = io_grouping_type;

	res = scst_sysfs_queue_wait_work(work);

out:
	return res;
}

static ssize_t scst_tgt_io_grouping_type_show(struct kobject *kobj, struct kobj_attribute *attr,
					      char *buf)
{
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	return __scst_acg_io_grouping_type_show(acg, buf);
}

static ssize_t scst_tgt_io_grouping_type_store(struct kobject *kobj, struct kobj_attribute *attr,
					       const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	TRACE_ENTRY();

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
	__ATTR(io_grouping_type, 0644, scst_tgt_io_grouping_type_show,
	       scst_tgt_io_grouping_type_store);

static ssize_t __scst_acg_black_hole_show(struct scst_acg *acg, char *buf)
{
	int t = acg->acg_black_hole_type;

	return sysfs_emit(buf, "%d\n", t);
}

static ssize_t __scst_acg_black_hole_store(struct scst_acg *acg, const char *buf, size_t count)
{
	int res = 0;
	int prev, t;
	struct scst_session *sess;

	prev = acg->acg_black_hole_type;

	if (!buf || count == 0) {
		res = 0;
		goto out;
	}

	mutex_lock(&scst_mutex);

	BUILD_BUG_ON((SCST_ACG_BLACK_HOLE_NONE != 0) ||
		     (SCST_ACG_BLACK_HOLE_CMD != 1) ||
		     (SCST_ACG_BLACK_HOLE_ALL != 2) ||
		     (SCST_ACG_BLACK_HOLE_DATA_CMD != 3) ||
		     (SCST_ACG_BLACK_HOLE_DATA_MCMD != 4));
	switch (buf[0]) {
	case '0':
		acg->acg_black_hole_type = SCST_ACG_BLACK_HOLE_NONE;
		break;
	case '1':
		acg->acg_black_hole_type = SCST_ACG_BLACK_HOLE_CMD;
		break;
	case '2':
		acg->acg_black_hole_type = SCST_ACG_BLACK_HOLE_ALL;
		break;
	case '3':
		acg->acg_black_hole_type = SCST_ACG_BLACK_HOLE_DATA_CMD;
		break;
	case '4':
		acg->acg_black_hole_type = SCST_ACG_BLACK_HOLE_DATA_MCMD;
		break;
	default:
		PRINT_ERROR("%s: Requested action not understood: %s",
			    __func__, buf);
		res = -EINVAL;
		goto out_unlock;
	}

	t = acg->acg_black_hole_type;

	if (prev == t)
		goto out_unlock;

	list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) {
		int i;

		rcu_read_lock();
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry_rcu(tgt_dev, head,
						sess_tgt_dev_list_entry) {
				if (t != SCST_ACG_BLACK_HOLE_NONE)
					set_bit(SCST_TGT_DEV_BLACK_HOLE, &tgt_dev->tgt_dev_flags);
				else
					clear_bit(SCST_TGT_DEV_BLACK_HOLE, &tgt_dev->tgt_dev_flags);
			}
		}
		rcu_read_unlock();
	}

	PRINT_INFO("Black hole set to %d for ACG %s", t, acg->acg_name);

out_unlock:
	mutex_unlock(&scst_mutex);

out:
	return res;
}

static ssize_t scst_tgt_black_hole_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	return __scst_acg_black_hole_show(acg, buf);
}

static ssize_t scst_tgt_black_hole_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	res = __scst_acg_black_hole_store(acg, buf, count);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_black_hole =
	__ATTR(black_hole, 0644, scst_tgt_black_hole_show, scst_tgt_black_hole_store);

static ssize_t __scst_acg_cpu_mask_show(struct scst_acg *acg, char *buf)
{
	ssize_t ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	ret = cpumask_scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, &acg->acg_cpu_mask);
#else
	ret = sysfs_emit(buf, "%*pb", cpumask_pr_args(&acg->acg_cpu_mask));
#endif
	if (!cpumask_equal(&acg->acg_cpu_mask, &default_cpu_mask))
		ret += sysfs_emit_at(buf, ret, "\n%s\n", SCST_SYSFS_KEY_MARK);
	else
		ret += sysfs_emit_at(buf, ret, "\n");

	return ret;
}

static int __scst_acg_process_cpu_mask_store(struct scst_tgt *tgt, struct scst_acg *acg,
					     cpumask_t *cpu_mask)
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

		rcu_read_lock();
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct scst_tgt_dev *tgt_dev;
			struct list_head *head = &sess->sess_tgt_dev_list[i];

			list_for_each_entry_rcu(tgt_dev, head,
						sess_tgt_dev_list_entry) {
				int rc;

				if (tgt_dev->active_cmd_threads != &tgt_dev->tgt_dev_cmd_threads)
					continue;
				rc = scst_set_thr_cpu_mask(tgt_dev->active_cmd_threads, cpu_mask);
				if (rc != 0)
					PRINT_ERROR("Setting CPU affinity failed: %d", rc);
			}
		}
		rcu_read_unlock();

		if (tgt->tgtt->report_aen) {
			struct scst_aen *aen;
			int rc;

			aen = scst_alloc_aen(sess, 0);
			if (!aen) {
				PRINT_ERROR("Unable to notify target driver %s about cpu_mask change",
					    tgt->tgt_name);
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
	return __scst_acg_process_cpu_mask_store(work->tgt, work->acg, &work->cpu_mask);
}

static ssize_t __scst_acg_cpu_mask_store(struct scst_acg *acg, const char *buf, size_t count)
{
	int res;
	struct scst_sysfs_work_item *work;

	/* cpumask might be too big for stack */

	res = scst_alloc_sysfs_work(__scst_acg_cpu_mask_store_work_fn, false, &work);
	if (res != 0)
		goto out;

	/*
	 * We can't use cpumask_parse_user() here, because it expects
	 * buffer in the user space.
	 */
	res = bitmap_parse(buf, count, cpumask_bits(&work->cpu_mask),
			   nr_cpumask_bits);
	if (res != 0) {
		PRINT_ERROR("bitmap_parse() failed: %d", res);
		goto out_release;
	}

	if (cpumask_equal(&acg->acg_cpu_mask, &work->cpu_mask))
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

static ssize_t scst_tgt_cpu_mask_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	return __scst_acg_cpu_mask_show(acg, buf);
}

static ssize_t scst_tgt_cpu_mask_store(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;
	struct scst_tgt *tgt;

	TRACE_ENTRY();

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
	__ATTR(cpu_mask, 0644, scst_tgt_cpu_mask_show, scst_tgt_cpu_mask_store);

static ssize_t scst_ini_group_mgmt_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	static const char help[] =
		"Usage: echo \"create GROUP_NAME\" >mgmt\n"
		"       echo \"del GROUP_NAME\" >mgmt";

	return sysfs_emit(buf, "%s\n", help);
}

static int scst_process_ini_group_mgmt_store(char *buffer, struct scst_tgt *tgt)
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
		PRINT_ERROR("Group name required");
		res = -EINVAL;
		goto out_unlock;
	}

	acg = scst_tgt_find_acg(tgt, p);

	switch (action) {
	case SCST_INI_GROUP_ACTION_CREATE:
		TRACE_DBG("Creating group '%s'", p);
		if (acg) {
			PRINT_ERROR("acg name %s exist", p);
			res = -EEXIST;
			goto out_unlock;
		}
		res = scst_alloc_add_acg(tgt, p, true, &acg);
		if (res != 0)
			goto out_unlock;
		break;
	case SCST_INI_GROUP_ACTION_DEL:
		TRACE_DBG("Deleting group '%s'", p);
		if (!acg) {
			PRINT_ERROR("Group %s not found", p);
			res = -EINVAL;
			goto out_unlock;
		}
		res = scst_del_free_acg(acg, scst_forcibly_close_sessions);
		if (res) {
			if (scst_forcibly_close_sessions)
				PRINT_ERROR("Removing group %s failed",
					    acg->acg_name);
			else
				PRINT_ERROR("Group %s is not empty",
					    acg->acg_name);
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

static int scst_ini_group_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_ini_group_mgmt_store(work->buf, work->tgt);
}

static ssize_t scst_ini_group_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	int res;
	char *buffer;
	struct scst_tgt *tgt;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	tgt = container_of(kobj->parent, struct scst_tgt, tgt_kobj);

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!buffer) {
		res = -ENOMEM;
		goto out;
	}

	res = scst_alloc_sysfs_work(scst_ini_group_mgmt_store_work_fn, false, &work);
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
	__ATTR(mgmt, 0644, scst_ini_group_mgmt_show, scst_ini_group_mgmt_store);

static ssize_t scst_tgt_enable_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *tgt;
	bool enabled;
	ssize_t ret;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	enabled = tgt->tgtt->is_target_enabled(tgt);

	ret = sysfs_emit(buf, "%d\n", enabled ? 1 : 0);

	TRACE_EXIT_RES(ret);
	return ret;
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
			PRINT_INFO("Using autogenerated relative target id %d for target %s",
				   tgt->rel_tgt_id, tgt->tgt_name);
		} else {
			if (!scst_is_relative_target_port_id_unique(tgt->rel_tgt_id, tgt)) {
				PRINT_ERROR("Relative target id %d is not unique",
					    tgt->rel_tgt_id);
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

static ssize_t scst_tgt_enable_store(struct kobject *kobj, struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int res;
	struct scst_tgt *tgt;
	bool enable;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	if (!buf) {
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

	res = scst_alloc_sysfs_work(scst_tgt_enable_store_work_fn, false, &work);
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
	__ATTR(enabled, 0644, scst_tgt_enable_show, scst_tgt_enable_store);

static ssize_t scst_rel_tgt_id_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *tgt;
	ssize_t ret;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	ret = sysfs_emit(buf, "%d\n", tgt->rel_tgt_id);

	if (tgt->rel_tgt_id)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
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

	if (tgt->tgtt->is_target_enabled)
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

	if (rel_tgt_id < SCST_MIN_REL_TGT_ID || rel_tgt_id > SCST_MAX_REL_TGT_ID) {
		if (rel_tgt_id == 0 && !enabled)
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

static ssize_t scst_rel_tgt_id_store(struct kobject *kobj, struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int res = 0;
	struct scst_tgt *tgt;
	unsigned long rel_tgt_id;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	if (!buf)
		goto out;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	res = kstrtoul(buf, 0, &rel_tgt_id);
	if (res != 0) {
		PRINT_ERROR("Wrong rel_tgt_id");
		res = -EINVAL;
		goto out;
	}

	res = scst_alloc_sysfs_work(scst_process_rel_tgt_id_store, false, &work);
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
	__ATTR(rel_tgt_id, 0644, scst_rel_tgt_id_show, scst_rel_tgt_id_store);

static ssize_t scst_tgt_forward_src_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct scst_tgt *tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	ssize_t ret;

	ret = sysfs_emit(buf, "%d\n", tgt->tgt_forward_src);

	if (tgt->tgt_forward_src)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	return ret;
}

static ssize_t scst_tgt_forward_src_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct scst_tgt *tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	int res, old, new;

	res = kstrtoint(buf, 0, &new);
	if (res < 0)
		return res;
	if (new < 0 || new > 1)
		return -EINVAL;

	mutex_lock(&scst_mutex);
	old = tgt->tgt_forward_src;
	if (old != new) {
		tgt->tgt_forward_src = new;
		PRINT_INFO("%s target %s as forwarding source",
			   tgt->tgt_forward_src ? "Set" : "Clear",
			   tgt->tgt_name);
	}
	mutex_unlock(&scst_mutex);

	return count;
}

static struct kobj_attribute scst_tgt_forward_src =
	__ATTR(forward_src, 0644, scst_tgt_forward_src_show, scst_tgt_forward_src_store);

static ssize_t scst_tgt_forward_dst_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct scst_tgt *tgt;
	ssize_t ret;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	ret = sysfs_emit(buf, "%d\n", tgt->tgt_forward_dst);

	if (tgt->tgt_forward_dst)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
}

static ssize_t scst_tgt_forward_dst_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	int res = 0;
	struct scst_tgt *tgt;
	struct scst_session *sess;
	int old;

	TRACE_ENTRY();

	if (!buf || count == 0) {
		res = 0;
		goto out;
	}

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	mutex_lock(&scst_mutex);

	old = tgt->tgt_forward_dst;

	switch (buf[0]) {
	case '0':
		tgt->tgt_forward_dst = 0;
		break;
	case '1':
		tgt->tgt_forward_dst = 1;
		break;
	default:
		PRINT_ERROR("%s: Requested action not understood: %s",
			    __func__, buf);
		res = -EINVAL;
		goto out_unlock;
	}

	if (tgt->tgt_forward_dst == old)
		goto out_unlock;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		int i;

		rcu_read_lock();
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry_rcu(tgt_dev, head, sess_tgt_dev_list_entry) {
				if (tgt->tgt_forward_dst)
					set_bit(SCST_TGT_DEV_FORWARD_DST,
						&tgt_dev->tgt_dev_flags);
				else
					clear_bit(SCST_TGT_DEV_FORWARD_DST,
						  &tgt_dev->tgt_dev_flags);
			}
		}
		rcu_read_unlock();
	}

	if (tgt->tgt_forward_dst)
		PRINT_INFO("Set target %s as forwarding destination",
			   tgt->tgt_name);
	else
		PRINT_INFO("Clear target %s as forwarding destination",
			   tgt->tgt_name);

out_unlock:
	mutex_unlock(&scst_mutex);

	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_forward_dst =
	__ATTR(forward_dst, 0644, scst_tgt_forward_dst_show, scst_tgt_forward_dst_store);

// To do: remove the 'forwarding' sysfs attribute and keep 'forward_dst'.
static struct kobj_attribute scst_tgt_forwarding =
	__ATTR(forwarding, 0644, scst_tgt_forward_dst_show, scst_tgt_forward_dst_store);

static ssize_t scst_tgt_aen_disabled_show(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buf)
{
	struct scst_tgt *tgt;
	ssize_t ret;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	ret = sysfs_emit(buf, "%d\n", tgt->tgt_aen_disabled);

	if (tgt->tgt_aen_disabled)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
}

static ssize_t scst_tgt_aen_disabled_store(struct kobject *kobj, struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	int res = 0;
	struct scst_tgt *tgt;
	struct scst_session *sess;
	int old;

	TRACE_ENTRY();

	if (!buf || count == 0) {
		res = 0;
		goto out;
	}

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	mutex_lock(&scst_mutex);

	old = tgt->tgt_aen_disabled;

	switch (buf[0]) {
	case '0':
		tgt->tgt_aen_disabled = 0;
		break;
	case '1':
		tgt->tgt_aen_disabled = 1;
		break;
	default:
		PRINT_ERROR("%s: Requested action not understood: %s",
			    __func__, buf);
		res = -EINVAL;
		goto out_unlock;
	}

	if (tgt->tgt_aen_disabled == old)
		goto out_unlock;

	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry) {
		int i;

		rcu_read_lock();
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry_rcu(tgt_dev, head, sess_tgt_dev_list_entry) {
				if (tgt->tgt_aen_disabled)
					set_bit(SCST_TGT_DEV_AEN_DISABLED,
						&tgt_dev->tgt_dev_flags);
				else
					clear_bit(SCST_TGT_DEV_AEN_DISABLED,
						  &tgt_dev->tgt_dev_flags);
			}
		}
		rcu_read_unlock();
	}

	if (tgt->tgt_aen_disabled)
		PRINT_INFO("Set AEN disabled for target %s",
			   tgt->tgt_name);
	else
		PRINT_INFO("Clear AEN disabled for target %s",
			   tgt->tgt_name);

out_unlock:
	mutex_unlock(&scst_mutex);

	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_tgt_aen_disabled =
	__ATTR(aen_disabled, 0644, scst_tgt_aen_disabled_show,
	       scst_tgt_aen_disabled_store);

static ssize_t scst_tgt_comment_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *tgt;
	ssize_t ret;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	if (tgt->tgt_comment)
		ret = sysfs_emit(buf, "%s\n%s\n",
				 tgt->tgt_comment, SCST_SYSFS_KEY_MARK);
	else
		ret = 0;

	TRACE_EXIT_RES(ret);
	return ret;
}

static ssize_t scst_tgt_comment_store(struct kobject *kobj, struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	int res;
	struct scst_tgt *tgt;
	char *p;
	int len;

	TRACE_ENTRY();

	if (!buf || count == 0) {
		res = 0;
		goto out;
	}

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	len = strnlen(buf, count);
	if (buf[count - 1] == '\n')
		len--;

	if (len == 0) {
		kfree(tgt->tgt_comment);
		tgt->tgt_comment = NULL;
		goto out_done;
	}

	p = kmalloc(len + 1, GFP_KERNEL);
	if (!p) {
		PRINT_ERROR("Unable to alloc tgt_comment string (len %d)",
			    len + 1);
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
	__ATTR(comment, 0644, scst_tgt_comment_show, scst_tgt_comment_store);
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

static ssize_t scst_tgt_dif_capable_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct scst_tgt *tgt;
	ssize_t ret = 0;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	EXTRACHECKS_BUG_ON(!tgt->tgt_dif_supported);

	ret += sysfs_emit_at(buf, ret, "dif_supported");

	if (tgt->tgt_hw_dif_type1_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_type1_supported");

	if (tgt->tgt_hw_dif_type2_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_type2_supported");

	if (tgt->tgt_hw_dif_type3_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_type3_supported");

	if (tgt->tgt_hw_dif_ip_supported)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_ip_supported");

	if (tgt->tgt_hw_dif_same_sg_layout_required)
		ret += sysfs_emit_at(buf, ret, ", hw_dif_same_sg_layout_required");

	ret += sysfs_emit_at(buf, ret, "\n");

	if (tgt->tgt_supported_dif_block_sizes) {
		const int *p = tgt->tgt_supported_dif_block_sizes;
		ssize_t pos;

		ret += sysfs_emit_at(buf, ret, "Supported blocks: ");
		pos = ret;

		while (*p != 0) {
			ret += sysfs_emit_at(buf, ret, "%s%d", ret == pos ? "" : ", ", *p);
			p++;
		}
	}

	TRACE_EXIT_RES(ret);
	return ret;
}

static struct kobj_attribute scst_tgt_dif_capable_attr =
	__ATTR(dif_capabilities, 0444, scst_tgt_dif_capable_show, NULL);

static ssize_t scst_tgt_dif_checks_failed_show(struct kobject *kobj, struct kobj_attribute *attr,
					       char *buf)
{
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	return sysfs_emit(buf,
			  "\tapp\tref\tguard\ntgt\t%d\t%d\t%d\nscst\t%d\t%d\t%d\ndev\t%d\t%d\t%d\n",
			  atomic_read(&tgt->tgt_dif_app_failed_tgt),
			  atomic_read(&tgt->tgt_dif_ref_failed_tgt),
			  atomic_read(&tgt->tgt_dif_guard_failed_tgt),
			  atomic_read(&tgt->tgt_dif_app_failed_scst),
			  atomic_read(&tgt->tgt_dif_ref_failed_scst),
			  atomic_read(&tgt->tgt_dif_guard_failed_scst),
			  atomic_read(&tgt->tgt_dif_app_failed_dev),
			  atomic_read(&tgt->tgt_dif_ref_failed_dev),
			  atomic_read(&tgt->tgt_dif_guard_failed_dev));
}

static ssize_t scst_tgt_dif_checks_failed_store(struct kobject *kobj, struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	PRINT_INFO("Zeroing DIF failures statistics for target %s",
		   tgt->tgt_name);

	atomic_set(&tgt->tgt_dif_app_failed_tgt, 0);
	atomic_set(&tgt->tgt_dif_ref_failed_tgt, 0);
	atomic_set(&tgt->tgt_dif_guard_failed_tgt, 0);
	atomic_set(&tgt->tgt_dif_app_failed_scst, 0);
	atomic_set(&tgt->tgt_dif_ref_failed_scst, 0);
	atomic_set(&tgt->tgt_dif_guard_failed_scst, 0);
	atomic_set(&tgt->tgt_dif_app_failed_dev, 0);
	atomic_set(&tgt->tgt_dif_ref_failed_dev, 0);
	atomic_set(&tgt->tgt_dif_guard_failed_dev, 0);

	return count;
}

static struct kobj_attribute scst_tgt_dif_checks_failed_attr =
	__ATTR(dif_checks_failed, 0644, scst_tgt_dif_checks_failed_show,
	       scst_tgt_dif_checks_failed_store);

#define SCST_TGT_SYSFS_STAT_ATTR(member_name, attr, dir, result_op)			\
static int scst_tgt_sysfs_##attr##_show_work_fn(struct scst_sysfs_work_item *work)	\
{											\
	struct scst_tgt *tgt = work->tgt;						\
	struct scst_session *sess;							\
	int res;									\
	uint64_t c = 0;									\
											\
	BUILD_BUG_ON((unsigned int)(dir) >= ARRAY_SIZE(sess->io_stats));		\
											\
	res = mutex_lock_interruptible(&scst_mutex);					\
	if (res)									\
		goto out;								\
	list_for_each_entry(sess, &tgt->sess_list, sess_list_entry)			\
		c += sess->io_stats[(dir)].member_name;					\
	mutex_unlock(&scst_mutex);							\
											\
	work->res_buf = kasprintf(GFP_KERNEL, "%llu\n", c result_op);			\
	res = work->res_buf ? 0 : -ENOMEM;						\
											\
out:											\
	kobject_put(&tgt->tgt_kobj);							\
	return res;									\
}											\
											\
static ssize_t scst_tgt_sysfs_##attr##_show(struct kobject *kobj,			\
					    struct kobj_attribute *attr,		\
					    char *buf)					\
{											\
	struct scst_tgt *tgt =								\
		container_of(kobj, struct scst_tgt, tgt_kobj);				\
	struct scst_sysfs_work_item *work;						\
	ssize_t res;									\
											\
	res = scst_alloc_sysfs_work(scst_tgt_sysfs_##attr##_show_work_fn,		\
				    true, &work);					\
	if (res)									\
		goto out;								\
											\
	work->tgt = tgt;								\
	SCST_SET_DEP_MAP(work, &scst_tgt_dep_map);					\
	kobject_get(&tgt->tgt_kobj);							\
	scst_sysfs_work_get(work);							\
	res = scst_sysfs_queue_wait_work(work);						\
	if (res == 0)									\
		res = sysfs_emit(buf, "%s", work->res_buf);				\
	scst_sysfs_work_put(work);							\
											\
out:											\
	return res;									\
}											\
											\
static struct kobj_attribute scst_tgt_##attr##_attr =					\
	__ATTR(attr, 0444, scst_tgt_sysfs_##attr##_show, NULL)

SCST_TGT_SYSFS_STAT_ATTR(cmd_count, unknown_cmd_count, SCST_DATA_UNKNOWN, >> 0);
SCST_TGT_SYSFS_STAT_ATTR(cmd_count, write_cmd_count, SCST_DATA_WRITE, >> 0);
SCST_TGT_SYSFS_STAT_ATTR(io_byte_count, write_io_count_kb, SCST_DATA_WRITE, >> 10);
SCST_TGT_SYSFS_STAT_ATTR(unaligned_cmd_count, write_unaligned_cmd_count, SCST_DATA_WRITE, >> 0);
SCST_TGT_SYSFS_STAT_ATTR(cmd_count, read_cmd_count, SCST_DATA_READ, >> 0);
SCST_TGT_SYSFS_STAT_ATTR(io_byte_count, read_io_count_kb, SCST_DATA_READ, >> 10);
SCST_TGT_SYSFS_STAT_ATTR(unaligned_cmd_count, read_unaligned_cmd_count, SCST_DATA_READ, >> 0);
SCST_TGT_SYSFS_STAT_ATTR(cmd_count, bidi_cmd_count, SCST_DATA_BIDI, >> 0);
SCST_TGT_SYSFS_STAT_ATTR(io_byte_count, bidi_io_count_kb, SCST_DATA_BIDI, >> 10);
SCST_TGT_SYSFS_STAT_ATTR(unaligned_cmd_count, bidi_unaligned_cmd_count, SCST_DATA_BIDI, >> 0);
SCST_TGT_SYSFS_STAT_ATTR(cmd_count, none_cmd_count, SCST_DATA_NONE, >> 0);

static struct attribute *scst_tgt_attrs[] = {
	&scst_rel_tgt_id.attr,
	&scst_tgt_forward_src.attr,
	&scst_tgt_forward_dst.attr,
	&scst_tgt_aen_disabled.attr,
	&scst_tgt_forwarding.attr,
	&scst_tgt_comment.attr,
	&scst_tgt_addr_method.attr,
	&scst_tgt_io_grouping_type.attr,
	&scst_tgt_black_hole.attr,
	&scst_tgt_cpu_mask.attr,
	&scst_tgt_unknown_cmd_count_attr.attr,
	&scst_tgt_write_cmd_count_attr.attr,
	&scst_tgt_write_io_count_kb_attr.attr,
	&scst_tgt_write_unaligned_cmd_count_attr.attr,
	&scst_tgt_read_cmd_count_attr.attr,
	&scst_tgt_read_io_count_kb_attr.attr,
	&scst_tgt_read_unaligned_cmd_count_attr.attr,
	&scst_tgt_bidi_cmd_count_attr.attr,
	&scst_tgt_bidi_io_count_kb_attr.attr,
	&scst_tgt_bidi_unaligned_cmd_count_attr.attr,
	&scst_tgt_none_cmd_count_attr.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
ATTRIBUTE_GROUPS(scst_tgt);
#endif

static struct kobj_type tgt_ktype = {
	.sysfs_ops	= &scst_sysfs_ops,
	.release	= scst_tgt_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.default_groups = scst_tgt_groups,
#else
	.default_attrs  = scst_tgt_attrs,
#endif
};

/*
 * Supposed to be called under scst_mutex. In case of error will drop,
 * then reacquire it.
 */
int scst_tgt_sysfs_create(struct scst_tgt *tgt)
{
	int res;

	TRACE_ENTRY();

	res = kobject_init_and_add(&tgt->tgt_kobj, &tgt_ktype, &tgt->tgtt->tgtt_kobj, "%s",
				   tgt->tgt_name);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt %s to sysfs", tgt->tgt_name);
		goto out;
	}

	if (tgt->tgtt->enable_target && tgt->tgtt->is_target_enabled) {
		res = sysfs_create_file(&tgt->tgt_kobj, &tgt_enable_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add attr %s to sysfs",
				    tgt_enable_attr.attr.name);
			goto out_err;
		}
	}

	tgt->tgt_sess_kobj = kobject_create_and_add("sessions", &tgt->tgt_kobj);
	if (!tgt->tgt_sess_kobj) {
		PRINT_ERROR("Can't create sess kobj for tgt %s", tgt->tgt_name);
		goto out_nomem;
	}

	tgt->tgt_luns_kobj = kobject_create_and_add("luns", &tgt->tgt_kobj);
	if (!tgt->tgt_luns_kobj) {
		PRINT_ERROR("Can't create luns kobj for tgt %s", tgt->tgt_name);
		goto out_nomem;
	}

	res = sysfs_create_file(tgt->tgt_luns_kobj, &scst_luns_mgmt.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			    scst_luns_mgmt.attr.name, tgt->tgt_name);
		goto out_err;
	}

	tgt->tgt_ini_grp_kobj = kobject_create_and_add("ini_groups", &tgt->tgt_kobj);
	if (!tgt->tgt_ini_grp_kobj) {
		PRINT_ERROR("Can't create ini_grp kobj for tgt %s",
			    tgt->tgt_name);
		goto out_nomem;
	}

	res = sysfs_create_file(tgt->tgt_ini_grp_kobj, &scst_ini_group_mgmt.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			    scst_ini_group_mgmt.attr.name, tgt->tgt_name);
		goto out_err;
	}

	if (tgt->tgt_dif_supported) {
		res = sysfs_create_file(&tgt->tgt_kobj, &scst_tgt_dif_capable_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add attribute %s for tgt %s",
				    scst_tgt_dif_capable_attr.attr.name, tgt->tgt_name);
			goto out_err;
		}

		res = sysfs_create_file(&tgt->tgt_kobj,
					&scst_tgt_dif_checks_failed_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add attribute %s for tgt %s",
				    scst_tgt_dif_checks_failed_attr.attr.name, tgt->tgt_name);
			goto out_err;
		}
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
}

void scst_tgt_sysfs_put(struct scst_tgt *tgt)
{
	DECLARE_COMPLETION_ONSTACK(c);

	TRACE_ENTRY();

	tgt->tgt_kobj_release_cmpl = &c;

	SCST_KOBJECT_PUT_AND_WAIT(&tgt->tgt_kobj, "target", &c,
				  &scst_tgt_dep_map);

	TRACE_EXIT();
}

/*
 ** Devices directory implementation
 **/

static ssize_t scst_dev_sysfs_type_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	struct scst_device *dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);

	return sysfs_emit(buf, "%d - %s\n",
			  dev->type,
			  (unsigned int)dev->type >= ARRAY_SIZE(scst_dev_handler_types) ?
			  "unknown" : scst_dev_handler_types[dev->type]);
}

static struct kobj_attribute dev_type_attr =
	__ATTR(type, 0444, scst_dev_sysfs_type_show, NULL);

static ssize_t scst_dev_sysfs_pr_file_name_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct scst_device *dev;
	ssize_t res;

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = mutex_lock_interruptible(&dev->dev_pr_mutex);
	if (res != 0)
		goto out;

	res = sysfs_emit(buf, "%s\n", dev->pr_file_name ? : "");

	if (dev->pr_file_name_is_set)
		res += sysfs_emit_at(buf, res, "%s\n", SCST_SYSFS_KEY_MARK);

	mutex_unlock(&dev->dev_pr_mutex);

out:
	return res;
}

static int
scst_dev_sysfs_pr_file_name_process_store(struct scst_sysfs_work_item *work)
{
	struct scst_device *dev = work->dev;
	char *pr_file_name = work->buf, *prev = NULL;
	int res;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	res = -EBUSY;
	if (scst_device_is_exported(dev)) {
		PRINT_ERROR("%s: not changing pr_file_name because the device has already been exported",
			    dev->virt_name);
		goto unlock_scst;
	}

	res = mutex_lock_interruptible(&dev->dev_pr_mutex);
	if (res)
		goto unlock_scst;

	if (strcmp(dev->pr_file_name, pr_file_name) == 0)
		goto unlock_dev_pr;

	res = scst_pr_set_file_name(dev, &prev, "%s", pr_file_name);
	if (res != 0)
		goto unlock_dev_pr;

	res = scst_pr_init_dev(dev);
	if (res != 0) {
		PRINT_ERROR("%s: loading PR from %s failed (%d) - restoring %s",
			    dev->virt_name, dev->pr_file_name, res,
			    prev ? : "");
		scst_pr_set_file_name(dev, NULL, "%s", prev);
		scst_pr_init_dev(dev);
		goto unlock_dev_pr;
	}

	dev->pr_file_name_is_set = !work->default_val;

unlock_dev_pr:
	mutex_unlock(&dev->dev_pr_mutex);

unlock_scst:
	mutex_unlock(&scst_mutex);

out:
	kobject_put(&dev->dev_kobj);
	kfree(prev);

	return res;
}

static ssize_t scst_dev_sysfs_pr_file_name_store(struct kobject *kobj, struct kobj_attribute *attr,
						 const char *buf, size_t count)
{
	struct scst_sysfs_work_item *work;
	struct scst_device *dev;
	char *pr_file_name = NULL, *p;
	int res = -EPERM;
	bool def = false;

	dev = container_of(kobj, struct scst_device, dev_kobj);

	if (dev->cluster_mode)
		goto out;

	res = -ENOMEM;
	pr_file_name = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!pr_file_name) {
		PRINT_ERROR("Unable to kasprintf() PR file name");
		goto out;
	}
	p = pr_file_name;
	strsep(&p, "\n"); /* strip trailing whitespace */
	if (pr_file_name[0] == '\0') {
		kfree(pr_file_name);
		pr_file_name = kasprintf(GFP_KERNEL, "%s/%s", SCST_PR_DIR,
					 dev->virt_name);
		if (!pr_file_name) {
			PRINT_ERROR("Unable to kasprintf() PR file name");
			goto out;
		}
		def = true;
	}

	res = scst_alloc_sysfs_work(scst_dev_sysfs_pr_file_name_process_store,
				    false, &work);
	if (res != 0)
		goto out;
	kobject_get(&dev->dev_kobj);
	work->dev = dev;
	work->default_val = def;
	swap(work->buf, pr_file_name);

	res = scst_sysfs_queue_wait_work(work);
	if (res == 0)
		res = count;

out:
	kfree(pr_file_name);
	return res;
}

static struct kobj_attribute dev_pr_file_name_attr =
	__ATTR(pr_file_name, 0644, scst_dev_sysfs_pr_file_name_show,
	       scst_dev_sysfs_pr_file_name_store);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_dev_sysfs_dump_prs(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct scst_device *dev;
	int res;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = mutex_lock_interruptible(&dev->dev_pr_mutex);
	if (res != 0)
		goto out;
	scst_pr_dump_prs(dev, true);
	mutex_unlock(&dev->dev_pr_mutex);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute dev_dump_prs_attr =
	__ATTR(dump_prs, 0200, NULL, scst_dev_sysfs_dump_prs);

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static int scst_process_dev_sysfs_threads_data_store(struct scst_device *dev, int threads_num,
						     enum scst_dev_type_threads_pool_type threads_pool_type)
{
	int res = 0;
	int oldtn = dev->threads_num;
	enum scst_dev_type_threads_pool_type oldtt = dev->threads_pool_type;

	TRACE_ENTRY();

	TRACE_DBG("dev %p, threads_num %d, threads_pool_type %d",
		  dev, threads_num, threads_pool_type);

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

static int scst_dev_sysfs_threads_data_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_dev_sysfs_threads_data_store(work->dev, work->new_threads_num,
							 work->new_threads_pool_type);
}

static ssize_t scst_dev_sysfs_check_threads_data(struct scst_device *dev, int threads_num,
						 enum scst_dev_type_threads_pool_type threads_pool_type,
						 bool *stop)
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

	if (threads_num == dev->threads_num && threads_pool_type == dev->threads_pool_type) {
		*stop = true;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_dev_sysfs_threads_num_show(struct kobject *kobj, struct kobj_attribute *attr,
					       char *buf)
{
	struct scst_device *dev;
	ssize_t ret;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	ret = sysfs_emit(buf, "%d\n", dev->threads_num);

	if (dev->threads_num != dev->handler->threads_num)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
}

static ssize_t scst_dev_sysfs_threads_num_store(struct kobject *kobj, struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	long newtn;
	bool stop;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = kstrtol(buf, 0, &newtn);
	if (res != 0) {
		PRINT_ERROR("kstrtol() for %s failed: %d ", buf, res);
		goto out;
	}
	if (newtn < 0) {
		PRINT_ERROR("Illegal threads num value %ld", newtn);
		res = -EINVAL;
		goto out;
	}

	res = scst_dev_sysfs_check_threads_data(dev, newtn, dev->threads_pool_type, &stop);
	if (res != 0 || stop)
		goto out;

	res = scst_alloc_sysfs_work(scst_dev_sysfs_threads_data_store_work_fn, false, &work);
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
	__ATTR(threads_num, 0644, scst_dev_sysfs_threads_num_show,
	       scst_dev_sysfs_threads_num_store);

static ssize_t scst_dev_sysfs_threads_pool_type_show(struct kobject *kobj,
						     struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev;
	ssize_t ret;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	if (dev->threads_num == 0) {
		ret = sysfs_emit(buf, "Async\n");
		goto out;
	} else if (dev->threads_num < 0) {
		ret = sysfs_emit(buf, "Not valid\n");
		goto out;
	}

	switch (dev->threads_pool_type) {
	case SCST_THREADS_POOL_PER_INITIATOR:
		ret = sysfs_emit(buf, "%s\n", SCST_THREADS_POOL_PER_INITIATOR_STR);

		if (dev->threads_pool_type != dev->handler->threads_pool_type)
			ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);
		break;
	case SCST_THREADS_POOL_SHARED:
		ret = sysfs_emit(buf, "%s\n", SCST_THREADS_POOL_SHARED_STR);

		if (dev->threads_pool_type != dev->handler->threads_pool_type)
			ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);
		break;
	default:
		ret = sysfs_emit(buf, "Unknown\n");
		break;
	}

out:
	TRACE_EXIT_RES(ret);
	return ret;
}

static ssize_t scst_dev_sysfs_threads_pool_type_store(struct kobject *kobj,
						      struct kobj_attribute *attr, const char *buf,
						      size_t count)
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

	res = scst_dev_sysfs_check_threads_data(dev, dev->threads_num, newtpt, &stop);
	if (res != 0 || stop)
		goto out;

	res = scst_alloc_sysfs_work(scst_dev_sysfs_threads_data_store_work_fn, false, &work);
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
	__ATTR(threads_pool_type, 0644, scst_dev_sysfs_threads_pool_type_show,
	       scst_dev_sysfs_threads_pool_type_store);

static ssize_t scst_dev_sysfs_max_tgt_dev_commands_show(struct kobject *kobj,
							struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev;
	ssize_t ret;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	ret = sysfs_emit(buf, "%d\n", dev->max_tgt_dev_commands);

	if (dev->max_tgt_dev_commands != dev->handler->max_tgt_dev_commands)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
}

static ssize_t scst_dev_sysfs_max_tgt_dev_commands_store(struct kobject *kobj,
							 struct kobj_attribute *attr,
							 const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	long newtn;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = kstrtol(buf, 0, &newtn);
	if (res != 0) {
		PRINT_ERROR("kstrtol() for %s failed: %d ", buf, res);
		goto out;
	}
	if (newtn < 0) {
		PRINT_ERROR("Illegal max tgt dev value %ld", newtn);
		res = -EINVAL;
		goto out;
	}

	if (dev->max_tgt_dev_commands != newtn) {
		PRINT_INFO("Setting new queue depth %ld for device %s (old %d)",
			   newtn, dev->virt_name, dev->max_tgt_dev_commands);
		dev->max_tgt_dev_commands = newtn;
	}

out:
	if (res == 0)
		res = count;

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute dev_max_tgt_dev_commands_attr =
	__ATTR(max_tgt_dev_commands, 0644, scst_dev_sysfs_max_tgt_dev_commands_show,
	       scst_dev_sysfs_max_tgt_dev_commands_store);

static ssize_t scst_dev_numa_node_id_show(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buf)
{
	struct scst_device *dev;
	ssize_t ret;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	ret = sysfs_emit(buf, "%d\n", dev->dev_numa_node_id);

	if (dev->dev_numa_node_id != NUMA_NO_NODE)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
}

static ssize_t scst_dev_numa_node_id_store(struct kobject *kobj, struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	long newtn;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = kstrtol(buf, 0, &newtn);
	if (res != 0) {
		PRINT_ERROR("kstrtol() for %s failed: %d ", buf, res);
		goto out;
	}
	BUILD_BUG_ON(NUMA_NO_NODE != -1);
	if (newtn < NUMA_NO_NODE) {
		PRINT_ERROR("Illegal numa_node_id value %ld", newtn);
		res = -EINVAL;
		goto out;
	}

	if (dev->dev_numa_node_id != newtn) {
		PRINT_INFO("Setting new NUMA node id %ld for device %s (old %d)",
			   newtn, dev->virt_name, dev->dev_numa_node_id);
		dev->dev_numa_node_id = newtn;
	}

out:
	if (res == 0)
		res = count;

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute dev_numa_node_id_attr =
	__ATTR(numa_node_id, 0644, scst_dev_numa_node_id_show,
	       scst_dev_numa_node_id_store);

static ssize_t scst_dev_block_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev;
	ssize_t ret;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	ret = sysfs_emit(buf, "%d %d\n",
			 READ_ONCE(dev->ext_blocks_cnt), dev->ext_blocking_pending);

	TRACE_EXIT_RES(ret);
	return ret;
}

static void scst_sysfs_ext_blocking_done(struct scst_device *dev, uint8_t *data, int len)
{
	scst_event_queue_ext_blocking_done(dev, data, len);
}

static ssize_t scst_dev_block_store(struct kobject *kobj, struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res, data_len = 0, pos = 0;
	struct scst_device *dev;
	const char *p = buf, *data_start = NULL;
	bool sync;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	switch (*p) {
	case '0':
		p++;
		pos++;
		while ((pos < count) && isspace(*p) && (*p != '\0')) {
			p++;
			pos++;
		}
		if (pos != count && (*p != '\0')) {
			PRINT_ERROR("Parse error on %c", *p);
			res = -EINVAL;
			goto out;
		}

		TRACE_MGMT_DBG("Sysfs unblocking (dev %s)", dev->virt_name);

		scst_ext_unblock_dev(dev, false);
		res = 0;
		goto out;
	case '1':
		p++;
		pos++;
		while ((pos < count) && isspace(*p) && (*p != '\0')) {
			p++;
			pos++;
		}
		if (pos == count || (*p == '\0')) {
			data_len = sizeof(void *);
			sync = true;
			break;
		} else if (*p != '1') {
			PRINT_ERROR("Parse error on %c", *p);
			res = -EINVAL;
			goto out;
		}

		sync = false;

		p++;
		pos++;
		if (pos == count || (*p == '\0'))
			break;

		while ((pos < count) && isspace(*p) && (*p != '\0')) {
			p++;
			pos++;
		}
		if (pos == count || (*p == '\0'))
			break;

		data_start = p;
		while ((pos < count) && (*p != '\0')) {
			p++;
			pos++;
			data_len++;
		}
		/* Skip trailing spaces, if any */
		while (isspace(*(p - 1))) {
			p--;
			data_len--;
		}
		break;
	default:
		PRINT_ERROR("Illegal blocking value %c", *p);
		res = -EINVAL;
		goto out;
	}

	TRACE_MGMT_DBG("Sysfs blocking dev %s (sync %d, data_start %p, data_len %d)",
		       dev->virt_name, sync, data_start, data_len);

	if (sync)
		res = scst_sync_ext_block_dev(dev);
	else
		res = scst_ext_block_dev(dev, scst_sysfs_ext_blocking_done,
					 data_start, data_len, false);
	if (res != 0)
		goto out;

	res = 0;

out:
	if (res == 0)
		res = count;

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute dev_block_attr =
	__ATTR(block, 0644, scst_dev_block_show, scst_dev_block_store);

static struct attribute *scst_dev_attrs[] = {
	&dev_type_attr.attr,
	&dev_max_tgt_dev_commands_attr.attr,
	&dev_numa_node_id_attr.attr,
	&dev_block_attr.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
ATTRIBUTE_GROUPS(scst_dev);
#endif

static void scst_sysfs_dev_release(struct kobject *kobj)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	if (dev->dev_kobj_release_cmpl)
		complete_all(dev->dev_kobj_release_cmpl);

	TRACE_EXIT();
}

/*
 * Creates an attribute entry for one SCST device. Allows for dev handlers to
 * create an attribute that is not for every device.
 */
int scst_create_dev_attr(struct scst_device *dev, struct kobj_attribute *attribute)
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

	res = sysfs_create_link(&dev->dev_kobj, &dev->handler->devt_kobj, "handler");
	if (res != 0) {
		PRINT_ERROR("Can't create handler link for dev %s",
			    dev->virt_name);
		goto out;
	}

	res = sysfs_create_link(&dev->handler->devt_kobj, &dev->dev_kobj, dev->virt_name);
	if (res != 0) {
		PRINT_ERROR("Can't create handler link for dev %s",
			    dev->virt_name);
		goto out_err;
	}

	if (dev->handler->threads_num >= 0) {
		res = sysfs_create_file(&dev->dev_kobj, &dev_threads_num_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add dev attr %s for dev %s",
				    dev_threads_num_attr.attr.name, dev->virt_name);
			goto out_err;
		}
		res = sysfs_create_file(&dev->dev_kobj, &dev_threads_pool_type_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add dev attr %s for dev %s",
				    dev_threads_pool_type_attr.attr.name,
				    dev->virt_name);
			goto out_err;
		}
	}

	if (dev->handler->dev_attrs) {
		res = sysfs_create_files(&dev->dev_kobj, dev->handler->dev_attrs);
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
		sysfs_remove_file(&dev->dev_kobj, &dev_threads_num_attr.attr);
		sysfs_remove_file(&dev->dev_kobj, &dev_threads_pool_type_attr.attr);
	}

out:
	TRACE_EXIT();
}

static struct kobj_type scst_dev_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_dev_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.default_groups = scst_dev_groups,
#else
	.default_attrs = scst_dev_attrs,
#endif
};

/*
 * Must not be called under scst_mutex, because it can call
 * scst_dev_sysfs_del()
 */
int scst_dev_sysfs_create(struct scst_device *dev)
{
	int res = 0;

	TRACE_ENTRY();

	res = kobject_init_and_add(&dev->dev_kobj, &scst_dev_ktype, scst_devices_kobj, "%s",
				   dev->virt_name);
	if (res != 0) {
		PRINT_ERROR("Can't add device %s to sysfs", dev->virt_name);
		goto out;
	}

	dev->dev_exp_kobj = kobject_create_and_add("exported", &dev->dev_kobj);
	if (!dev->dev_exp_kobj) {
		PRINT_ERROR("Can't create exported link for device %s",
			    dev->virt_name);
		res = -ENOMEM;
		goto out_del;
	}

	if (dev->scsi_dev) {
		res = sysfs_create_link(&dev->dev_kobj, &dev->scsi_dev->sdev_dev.kobj,
					"scsi_device");
		if (res != 0) {
			PRINT_ERROR("Can't create scsi_device link for dev %s",
				    dev->virt_name);
			goto out_del;
		}
	}

	if (dev->pr_file_name) {
		res = sysfs_create_file(&dev->dev_kobj, &dev_pr_file_name_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't create attr %s for dev %s",
				    dev_pr_file_name_attr.attr.name,
				    dev->virt_name);
			goto out_del;
		}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
		res = sysfs_create_file(&dev->dev_kobj, &dev_dump_prs_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't create attr %s for dev %s",
				    dev_dump_prs_attr.attr.name, dev->virt_name);
			goto out_del;
		}
#endif
	}

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
}

static ssize_t scst_dev_dif_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev;
	ssize_t ret = 0;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	if (dev->dev_dif_mode == SCST_DIF_MODE_NONE) {
		ret = sysfs_emit(buf, "None\n");
	} else {
		ssize_t pos = ret;

		if (dev->dev_dif_mode & SCST_DIF_MODE_TGT)
			ret += sysfs_emit_at(buf, ret, "%s", SCST_DIF_MODE_TGT_STR);

		if (dev->dev_dif_mode & SCST_DIF_MODE_SCST)
			ret += sysfs_emit_at(buf, ret, "%s%s",
					     ret == pos ? "" : "|", SCST_DIF_MODE_SCST_STR);

		if (dev->dev_dif_mode & SCST_DIF_MODE_DEV_CHECK)
			ret += sysfs_emit_at(buf, ret, "%s%s",
					     ret == pos ? "" : "|", SCST_DIF_MODE_DEV_CHECK_STR);

		if (dev->dev_dif_mode & SCST_DIF_MODE_DEV_STORE)
			ret += sysfs_emit_at(buf, ret, "%s%s",
					     ret == pos ? "" : "|", SCST_DIF_MODE_DEV_STORE_STR);

		ret += sysfs_emit_at(buf, ret, "\n%s\n", SCST_SYSFS_KEY_MARK);
	}

	TRACE_EXIT_RES(ret);
	return ret;
}

static struct kobj_attribute scst_dev_dif_mode_attr =
	__ATTR(dif_mode, 0444, scst_dev_dif_mode_show, NULL);

static ssize_t scst_dev_dif_type_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev;
	ssize_t ret;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	ret = sysfs_emit(buf, "%d\n", dev->dev_dif_type);

	if (dev->dev_dif_type)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
}

static struct kobj_attribute scst_dev_dif_type_attr =
	__ATTR(dif_type, 0444, scst_dev_dif_type_show, NULL);

static ssize_t scst_dev_sysfs_dif_static_app_tag_store(struct kobject *kobj,
						       struct kobj_attribute *attr,
						       const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	unsigned long long val;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = kstrtoull(buf, 0, &val);
	if (res != 0) {
		PRINT_ERROR("strtoul() for %s failed: %d (device %s)",
			    buf, res, dev->virt_name);
		goto out;
	}

	scst_dev_set_dif_static_app_tag_combined(dev, cpu_to_be64(val));

	res = count;

	PRINT_INFO("APP TAG for device %s changed to %llx",
		   dev->virt_name,
		   (long long)be64_to_cpu(scst_dev_get_dif_static_app_tag_combined(dev)));

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_dev_sysfs_dif_static_app_tag_show(struct kobject *kobj,
						      struct kobj_attribute *attr, char *buf)
{
	struct scst_device *dev;
	__be64 a;
	ssize_t ret;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	a = scst_dev_get_dif_static_app_tag_combined(dev);

	ret = sysfs_emit(buf, "0x%llx\n", (unsigned long long)be64_to_cpu(a));

	if (a != SCST_DIF_NO_CHECK_APP_TAG)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(ret);
	return ret;
}

static struct kobj_attribute scst_dev_dif_static_app_tag_attr =
	__ATTR(dif_static_app_tag, 0644, scst_dev_sysfs_dif_static_app_tag_show,
	       scst_dev_sysfs_dif_static_app_tag_store);

int scst_dev_sysfs_dif_create(struct scst_device *dev)
{
	int res;

	TRACE_ENTRY();

	/*
	 * On errors the caller supposed to unregister this device, hence,
	 * perform the cleanup.
	 */

	res = sysfs_create_file(&dev->dev_kobj, &scst_dev_dif_mode_attr.attr);
	if (res != 0) {
		PRINT_ERROR("Can't create attr %s for dev %s",
			    scst_dev_dif_mode_attr.attr.name, dev->virt_name);
		goto out;
	}

	res = sysfs_create_file(&dev->dev_kobj, &scst_dev_dif_type_attr.attr);
	if (res != 0) {
		PRINT_ERROR("Can't create attr %s for dev %s",
			    scst_dev_dif_type_attr.attr.name, dev->virt_name);
		goto out;
	}

	res = sysfs_create_file(&dev->dev_kobj, &scst_dev_dif_static_app_tag_attr.attr);
	if (res != 0) {
		PRINT_ERROR("Can't create attr %s for dev %s",
			    scst_dev_dif_static_app_tag_attr.attr.name, dev->virt_name);
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 ** Tgt_dev implementation
 **/

static ssize_t scst_tgt_dev_thread_index_show(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      char *buffer)
{
	struct scst_tgt_dev *tgt_dev =
		container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);

	return sysfs_emit(buffer, "%d\n", tgt_dev->thread_index);
}

static struct kobj_attribute tgt_dev_thread_idx_attr =
	__ATTR(thread_index, 0444, scst_tgt_dev_thread_index_show, NULL);

static ssize_t scst_tgt_dev_thread_pid_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buffer)
{
	struct scst_tgt_dev *tgt_dev =
		container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);
	struct scst_cmd_threads *cmd_threads = tgt_dev->active_cmd_threads;
	struct scst_cmd_thread_t *t;
	ssize_t ret = 0;

	spin_lock(&cmd_threads->thr_lock);
	list_for_each_entry(t, &cmd_threads->threads_list, thread_list_entry)
		ret += sysfs_emit_at(buffer, ret, "%d%s",
				     task_pid_vnr(t->cmd_thread),
				     list_is_last(&t->thread_list_entry,
						  &cmd_threads->threads_list) ? "\n" : " ");
	spin_unlock(&cmd_threads->thr_lock);

	return ret;
}

static struct kobj_attribute tgt_dev_thread_pid_attr =
	__ATTR(thread_pid, 0444, scst_tgt_dev_thread_pid_show, NULL);

static ssize_t scst_tgt_dev_active_commands_show(struct kobject *kobj, struct kobj_attribute *attr,
						 char *buf)
{
	struct scst_tgt_dev *tgt_dev;

	tgt_dev = container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);

	return sysfs_emit(buf, "%d\n",
			  atomic_read(&tgt_dev->tgt_dev_cmd_count));
}

static struct kobj_attribute tgt_dev_active_commands_attr =
	__ATTR(active_commands, 0444, scst_tgt_dev_active_commands_show, NULL);

static ssize_t scst_tgt_dev_dif_checks_failed_show(struct kobject *kobj,
						   struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt_dev *tgt_dev;

	tgt_dev = container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);

	return sysfs_emit(buf,
			  "\tapp\tref\tguard\ntgt\t%d\t%d\t%d\nscst\t%d\t%d\t%d\ndev\t%d\t%d\t%d\n",
			  atomic_read(&tgt_dev->tgt_dev_dif_app_failed_tgt),
			  atomic_read(&tgt_dev->tgt_dev_dif_ref_failed_tgt),
			  atomic_read(&tgt_dev->tgt_dev_dif_guard_failed_tgt),
			  atomic_read(&tgt_dev->tgt_dev_dif_app_failed_scst),
			  atomic_read(&tgt_dev->tgt_dev_dif_ref_failed_scst),
			  atomic_read(&tgt_dev->tgt_dev_dif_guard_failed_scst),
			  atomic_read(&tgt_dev->tgt_dev_dif_app_failed_dev),
			  atomic_read(&tgt_dev->tgt_dev_dif_ref_failed_dev),
			  atomic_read(&tgt_dev->tgt_dev_dif_guard_failed_dev));
}

static ssize_t scst_tgt_dev_dif_checks_failed_store(struct kobject *kobj,
						    struct kobj_attribute *attr, const char *buf,
						    size_t count)
{
	struct scst_tgt_dev *tgt_dev;

	tgt_dev = container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);

	PRINT_INFO("Zeroing DIF failures statistics for initiator %s, target %s, LUN %lld",
		   tgt_dev->sess->initiator_name, tgt_dev->sess->tgt->tgt_name,
		   (unsigned long long)tgt_dev->lun);

	atomic_set(&tgt_dev->tgt_dev_dif_app_failed_tgt, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_ref_failed_tgt, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_guard_failed_tgt, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_app_failed_scst, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_ref_failed_scst, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_guard_failed_scst, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_app_failed_dev, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_ref_failed_dev, 0);
	atomic_set(&tgt_dev->tgt_dev_dif_guard_failed_dev, 0);

	return count;
}

static struct kobj_attribute tgt_dev_dif_checks_failed_attr =
	__ATTR(dif_checks_failed, 0644, scst_tgt_dev_dif_checks_failed_show,
	       scst_tgt_dev_dif_checks_failed_store);

static struct attribute *scst_tgt_dev_attrs[] = {
	&tgt_dev_thread_idx_attr.attr,
	&tgt_dev_thread_pid_attr.attr,
	&tgt_dev_active_commands_attr.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
ATTRIBUTE_GROUPS(scst_tgt_dev);
#endif

static void scst_sysfs_tgt_dev_release(struct kobject *kobj)
{
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	tgt_dev = container_of(kobj, struct scst_tgt_dev, tgt_dev_kobj);
	if (tgt_dev->tgt_dev_kobj_release_cmpl)
		complete_all(tgt_dev->tgt_dev_kobj_release_cmpl);

	TRACE_EXIT();
}

static struct kobj_type scst_tgt_dev_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_tgt_dev_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.default_groups = scst_tgt_dev_groups,
#else
	.default_attrs = scst_tgt_dev_attrs,
#endif
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

	if (tgt_dev->sess->tgt->tgt_dif_supported && tgt_dev->dev->dev_dif_type != 0) {
		res = sysfs_create_file(&tgt_dev->tgt_dev_kobj,
					&tgt_dev_dif_checks_failed_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Adding %s sysfs attribute to tgt_dev %lld failed (%d)",
				    tgt_dev_dif_checks_failed_attr.attr.name,
				    (unsigned long long)tgt_dev->lun, res);
			goto out_del;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	kobject_del(&tgt_dev->tgt_dev_kobj);
	kobject_put(&tgt_dev->tgt_dev_kobj);
	goto out;
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
}

/*
 ** Sessions subdirectory implementation
 **/

/* Calculate int_sqrt64((sumsq - sum * sum / count) / count) */
static u64 calc_stddev(u64 sumsq, u64 sum, u32 count)
{
	u64 d = sum * sum;

	do_div(d, count);
	d = sumsq - d;
	do_div(d, count);
	return int_sqrt64(d);
}

static ssize_t scst_sess_latency_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess =
		container_of(kobj->parent, struct scst_session, sess_kobj);
	int i, j, k;
	long sz;
	struct scst_lat_stat_entry *d;
	uint64_t avg, stddev;
#ifdef SCST_MEASURE_CLOCK_CYCLES
	uint64_t min, max, sumc = 0, sumsqc = 0;
#else
	uint64_t sum = 0, sumsq = 0;
#endif
	unsigned int count = 0, numst = 0;
	u64 d_min_div_10, d_max_div_10, avg_div_10, stddev_div_10;
	u32 d_min_mod_10, d_max_mod_10, avg_mod_10, stddev_mod_10;
	char state_name[32];
	ssize_t res;

	switch (attr->attr.name[0]) {
	case 'n':
		j = SCST_DATA_NONE & 3;
		break;
	case 'r':
		j = SCST_DATA_READ;
		break;
	case 'w':
		j = SCST_DATA_WRITE;
		break;
	case 'b':
		j = SCST_DATA_BIDI;
		break;
	default:
		return -EINVAL;
	}

	res = kstrtol(attr->attr.name + 1, 0, &sz);
	if (WARN_ON(res < 0))
		goto out;
	i = ilog2(sz) - SCST_STATS_LOG2_SZ_OFFSET;
	if (WARN_ON(i < 0 || i >= SCST_STATS_MAX_LOG2_SZ)) {
		res = -EINVAL;
		goto out;
	}

	res += sysfs_emit_at(buf, res, "state count min max avg stddev\n");

	spin_lock_irq(&sess->lat_stats_lock);
	for (k = 0; k < SCST_CMD_STATE_COUNT; k++) {
		struct scst_lat_stats *lat_stats = sess->lat_stats;

		if (!lat_stats || res >= SCST_SYSFS_BLOCK_SIZE)
			continue;
		d = &lat_stats->ls[i][j][k];
		if (d->count == 0)
			continue;
		scst_get_cmd_state_name(state_name, sizeof(state_name),
					k);
		avg = d->sum;
		do_div(avg, d->count);
		stddev = calc_stddev(d->sumsq, d->sum, d->count);
		d_min_div_10 = d->min;
		d_min_mod_10 = do_div(d_min_div_10, 10);
		d_max_div_10 = d->max;
		d_max_mod_10 = do_div(d_max_div_10, 10);
		avg_div_10 = avg;
		avg_mod_10 = do_div(avg_div_10, 10);
		stddev_div_10 = stddev;
		stddev_mod_10 = do_div(stddev_div_10, 10);
		res += sysfs_emit_at(buf, res,
				     "%s %d %lld.%01d %lld.%01d %lld.%01d %lld.%01d us\n",
				     state_name, d->count,
				     d_min_div_10, d_min_mod_10,
				     d_max_div_10, d_max_mod_10,
				     avg_div_10, avg_mod_10,
				     stddev_div_10, stddev_mod_10);
#ifdef SCST_MEASURE_CLOCK_CYCLES
		min = d->minc * 10000 / (tsc_khz / 100);
		max = d->maxc * 10000 / (tsc_khz / 100);
		avg = d->sumc * 10000 / (d->count * 1ull * tsc_khz / 100);
		stddev = calc_stddev(d->sumsqc, d->sumc, d->count) * 1000000 / tsc_khz;
		res += sysfs_emit_at(buf, res,
				     "%s %d %lld.%01lld %lld.%01lld %lld.%01lld %lld.%01lld cc -> us\n",
				     state_name, d->count,
				     min / 10, min % 10,
				     max / 10, max % 10,
				     avg / 10, avg % 10,
				     stddev / 10, stddev % 10);
		sumc += d->sumc;
		sumsqc += d->sumsqc;
#else
		sum += d->sum;
		sumsq += d->sumsq;
#endif
		count += d->count;
		numst++;
	}
	spin_unlock_irq(&sess->lat_stats_lock);

	if (count != 0) {
#ifdef SCST_MEASURE_CLOCK_CYCLES
		avg = numst * sumc / (count * 1ull * tsc_khz / 1000000);
		stddev = calc_stddev(sumsqc, sumc, count) * numst * 1000000 / tsc_khz;
		res += sysfs_emit_at(buf, res,
				     "total %d - - %lld.%01lld %lld.%01lld cc -> us\n",
				     count / numst, avg / 10, avg % 10, stddev / 10,
				     stddev % 10);
#else
		avg = numst * sum;
		do_div(avg, count);
		stddev = calc_stddev(sumsq, sum, count) * numst;
		avg_div_10 = avg;
		avg_mod_10 = do_div(avg_div_10, 10);
		stddev_div_10 = stddev;
		stddev_mod_10 = do_div(stddev_div_10, 10);
		res += sysfs_emit_at(buf, res,
				     "total %d - - %lld.%01d %lld.%01d us\n",
				     count / numst, avg_div_10, avg_mod_10,
				     stddev_div_10, stddev_mod_10);
#endif
	}

out:
	return res;
}

static ssize_t scst_sess_latency_store(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct scst_session *sess =
		container_of(kobj->parent, struct scst_session, sess_kobj);

	spin_lock_irq(&sess->lat_stats_lock);
	BUILD_BUG_ON(sizeof(*sess->lat_stats) != sizeof(struct scst_lat_stats));
	memset(sess->lat_stats, 0, sizeof(*sess->lat_stats));
	spin_unlock_irq(&sess->lat_stats_lock);

	return count;
}

static ssize_t scst_sess_sysfs_commands_show(struct kobject *kobj, struct kobj_attribute *attr,
					     char *buf)
{
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	return sysfs_emit(buf, "%d\n", atomic_read(&sess->sess_cmd_count));
}

static struct kobj_attribute session_commands_attr =
	__ATTR(commands, 0444, scst_sess_sysfs_commands_show, NULL);

static int scst_sysfs_sess_get_active_commands(struct scst_session *sess)
{
	int res;
	int active_cmds = 0, t;

	TRACE_ENTRY();

	rcu_read_lock();
	for (t = SESS_TGT_DEV_LIST_HASH_SIZE - 1; t >= 0; t--) {
		struct list_head *head = &sess->sess_tgt_dev_list[t];
		struct scst_tgt_dev *tgt_dev;

		list_for_each_entry_rcu(tgt_dev, head, sess_tgt_dev_list_entry)
			active_cmds += atomic_read(&tgt_dev->tgt_dev_cmd_count);
	}
	rcu_read_unlock();

	res = active_cmds;

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
	struct scst_session *sess;
	struct scst_sysfs_work_item *work;
	int res;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	res = scst_alloc_sysfs_work(scst_sysfs_sess_get_active_commands_work_fn, true, &work);
	if (res != 0)
		goto out;

	work->sess = sess;

	SCST_SET_DEP_MAP(work, &scst_sess_dep_map);
	kobject_get(&sess->sess_kobj);

	res = scst_sysfs_queue_wait_work(work);
	if (res != -EAGAIN)
		res = sysfs_emit(buf, "%d\n", res);

out:
	return res;
}

static struct kobj_attribute session_active_commands_attr =
	__ATTR(active_commands, 0444, scst_sess_sysfs_active_commands_show, NULL);

static int scst_sysfs_sess_get_dif_checks_failed_work_fn(struct scst_sysfs_work_item *work)
{
	int res, t;
	struct scst_session *sess = work->sess;
	int app_failed_tgt = 0, ref_failed_tgt = 0, guard_failed_tgt = 0;
	int app_failed_scst = 0, ref_failed_scst = 0, guard_failed_scst = 0;
	int app_failed_dev = 0, ref_failed_dev = 0, guard_failed_dev = 0;

	TRACE_ENTRY();

	rcu_read_lock();
	for (t = SESS_TGT_DEV_LIST_HASH_SIZE - 1; t >= 0; t--) {
		struct list_head *head = &sess->sess_tgt_dev_list[t];
		struct scst_tgt_dev *tgt_dev;

		list_for_each_entry_rcu(tgt_dev, head, sess_tgt_dev_list_entry) {
			app_failed_tgt += atomic_read(&tgt_dev->tgt_dev_dif_app_failed_tgt);
			ref_failed_tgt += atomic_read(&tgt_dev->tgt_dev_dif_ref_failed_tgt);
			guard_failed_tgt += atomic_read(&tgt_dev->tgt_dev_dif_guard_failed_tgt);
			app_failed_scst += atomic_read(&tgt_dev->tgt_dev_dif_app_failed_scst);
			ref_failed_scst += atomic_read(&tgt_dev->tgt_dev_dif_ref_failed_scst);
			guard_failed_scst += atomic_read(&tgt_dev->tgt_dev_dif_guard_failed_scst);
			app_failed_dev += atomic_read(&tgt_dev->tgt_dev_dif_app_failed_dev);
			ref_failed_dev += atomic_read(&tgt_dev->tgt_dev_dif_ref_failed_dev);
			guard_failed_dev += atomic_read(&tgt_dev->tgt_dev_dif_guard_failed_dev);
		}
	}
	rcu_read_unlock();

	work->res_buf = kasprintf(GFP_KERNEL, "\tapp\tref\tguard\n"
			  "tgt\t%d\t%d\t%d\nscst\t%d\t%d\t%d\ndev\t%d\t%d\t%d\n",
			  app_failed_tgt, ref_failed_tgt, guard_failed_tgt,
			  app_failed_scst, ref_failed_scst, guard_failed_scst,
			  app_failed_dev, ref_failed_dev, guard_failed_dev);
	res = work->res_buf ? 0 : -ENOMEM;

	kobject_put(&sess->sess_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_sess_sysfs_dif_checks_failed_show(struct kobject *kobj,
						      struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;
	struct scst_sysfs_work_item *work;
	ssize_t res;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	res = scst_alloc_sysfs_work(scst_sysfs_sess_get_dif_checks_failed_work_fn, true, &work);
	if (res != 0)
		goto out;

	work->sess = sess;

	SCST_SET_DEP_MAP(work, &scst_sess_dep_map);
	kobject_get(&sess->sess_kobj);

	scst_sysfs_work_get(work);

	res = scst_sysfs_queue_wait_work(work);
	if (res != 0)
		goto out_put;

	res = sysfs_emit(buf, "%s", work->res_buf);

out_put:
	scst_sysfs_work_put(work);

out:
	return res;
}

static int scst_sess_zero_dif_checks_failed(struct scst_sysfs_work_item *work)
{
	int res, t;
	struct scst_session *sess = work->sess;

	TRACE_ENTRY();

	PRINT_INFO("Zeroing DIF failures statistics for initiator %s, target %s",
		   sess->initiator_name, sess->tgt->tgt_name);

	rcu_read_lock();
	for (t = SESS_TGT_DEV_LIST_HASH_SIZE - 1; t >= 0; t--) {
		struct list_head *head = &sess->sess_tgt_dev_list[t];
		struct scst_tgt_dev *tgt_dev;

		list_for_each_entry_rcu(tgt_dev, head,
					sess_tgt_dev_list_entry) {
			atomic_set(&tgt_dev->tgt_dev_dif_app_failed_tgt, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_ref_failed_tgt, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_guard_failed_tgt, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_app_failed_scst, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_ref_failed_scst, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_guard_failed_scst, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_app_failed_dev, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_ref_failed_dev, 0);
			atomic_set(&tgt_dev->tgt_dev_dif_guard_failed_dev, 0);
		}
	}
	rcu_read_unlock();

	res = 0;

	kobject_put(&sess->sess_kobj);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_sess_sysfs_dif_checks_failed_store(struct kobject *kobj,
						       struct kobj_attribute *attr,
						       const char *buf, size_t count)
{
	int res;
	struct scst_session *sess;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	sess = container_of(kobj, struct scst_session, sess_kobj);

	res = scst_alloc_sysfs_work(scst_sess_zero_dif_checks_failed, false, &work);
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

static struct kobj_attribute session_dif_checks_failed_attr =
	__ATTR(dif_checks_failed, 0644, scst_sess_sysfs_dif_checks_failed_show,
	       scst_sess_sysfs_dif_checks_failed_store);

static ssize_t scst_sess_sysfs_initiator_name_show(struct kobject *kobj,
						   struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	return sysfs_emit(buf, "%s\n", sess->initiator_name);
}

static struct kobj_attribute session_initiator_name_attr =
	__ATTR(initiator_name, 0444, scst_sess_sysfs_initiator_name_show, NULL);

#define SCST_SESS_SYSFS_STAT_ATTR(name, exported_name, dir, kb)					\
static ssize_t scst_sess_sysfs_##exported_name##_show(struct kobject *kobj,			\
						      struct kobj_attribute *attr, char *buf)	\
{												\
	struct scst_session *sess;								\
	uint64_t v;										\
												\
	BUILD_BUG_ON(SCST_DATA_UNKNOWN != 0);							\
	BUILD_BUG_ON(SCST_DATA_WRITE != 1);							\
	BUILD_BUG_ON(SCST_DATA_READ != 2);							\
	BUILD_BUG_ON(SCST_DATA_BIDI != 3);							\
	BUILD_BUG_ON(SCST_DATA_NONE != 4);							\
												\
	BUILD_BUG_ON(dir >= SCST_DATA_DIR_MAX);							\
												\
	sess = container_of(kobj, struct scst_session, sess_kobj);				\
	v = sess->io_stats[dir].name;								\
	if (kb)											\
		v >>= 10;									\
	return sysfs_emit(buf, "%llu\n", (unsigned long long)v);				\
}												\
												\
static ssize_t scst_sess_sysfs_##exported_name##_store(struct kobject *kobj,			\
						       struct kobj_attribute *attr,		\
						       const char *buf, size_t count)		\
{												\
	struct scst_session *sess;								\
	sess = container_of(kobj, struct scst_session, sess_kobj);				\
	spin_lock_irq(&sess->sess_list_lock);							\
	BUILD_BUG_ON(dir >= SCST_DATA_DIR_MAX);							\
	sess->io_stats[dir].cmd_count = 0;							\
	sess->io_stats[dir].io_byte_count = 0;							\
	sess->io_stats[dir].unaligned_cmd_count = 0;						\
	spin_unlock_irq(&sess->sess_list_lock);							\
	return count;										\
}												\
												\
static struct kobj_attribute session_##exported_name##_attr =					\
	__ATTR(exported_name, 0644, scst_sess_sysfs_##exported_name##_show,			\
	       scst_sess_sysfs_##exported_name##_store)

SCST_SESS_SYSFS_STAT_ATTR(cmd_count, unknown_cmd_count, SCST_DATA_UNKNOWN, 0);
SCST_SESS_SYSFS_STAT_ATTR(cmd_count, write_cmd_count, SCST_DATA_WRITE, 0);
SCST_SESS_SYSFS_STAT_ATTR(io_byte_count, write_io_count_kb, SCST_DATA_WRITE, 1);
SCST_SESS_SYSFS_STAT_ATTR(unaligned_cmd_count, write_unaligned_cmd_count, SCST_DATA_WRITE, 0);
SCST_SESS_SYSFS_STAT_ATTR(cmd_count, read_cmd_count, SCST_DATA_READ, 0);
SCST_SESS_SYSFS_STAT_ATTR(io_byte_count, read_io_count_kb, SCST_DATA_READ, 1);
SCST_SESS_SYSFS_STAT_ATTR(unaligned_cmd_count, read_unaligned_cmd_count, SCST_DATA_READ, 0);
SCST_SESS_SYSFS_STAT_ATTR(cmd_count, bidi_cmd_count, SCST_DATA_BIDI, 0);
SCST_SESS_SYSFS_STAT_ATTR(io_byte_count, bidi_io_count_kb, SCST_DATA_BIDI, 1);
SCST_SESS_SYSFS_STAT_ATTR(unaligned_cmd_count, bidi_unaligned_cmd_count, SCST_DATA_BIDI, 0);
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
	__ATTR(force_close, 0200, NULL, scst_sess_force_close_store);

static struct attribute *scst_session_attrs[] = {
	&session_commands_attr.attr,
	&session_active_commands_attr.attr,
	&session_initiator_name_attr.attr,
	&session_unknown_cmd_count_attr.attr,
	&session_write_cmd_count_attr.attr,
	&session_write_io_count_kb_attr.attr,
	&session_write_unaligned_cmd_count_attr.attr,
	&session_read_cmd_count_attr.attr,
	&session_read_io_count_kb_attr.attr,
	&session_read_unaligned_cmd_count_attr.attr,
	&session_bidi_cmd_count_attr.attr,
	&session_bidi_io_count_kb_attr.attr,
	&session_bidi_unaligned_cmd_count_attr.attr,
	&session_none_cmd_count_attr.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
ATTRIBUTE_GROUPS(scst_session);
#endif

static void scst_sysfs_session_release(struct kobject *kobj)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	sess = container_of(kobj, struct scst_session, sess_kobj);
	if (sess->sess_kobj_release_cmpl)
		complete_all(sess->sess_kobj_release_cmpl);

	TRACE_EXIT();
}

static struct kobj_type scst_session_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_session_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.default_groups = scst_session_groups,
#else
	.default_attrs = scst_session_attrs,
#endif
};

#define SCST_LAT_ATTRS(size)		\
	&sess_lat_attr_n##size.attr,	\
	&sess_lat_attr_r##size.attr,	\
	&sess_lat_attr_w##size.attr,	\
	&sess_lat_attr_b##size.attr

#define SCST_LAT_ATTR(size)									\
	static struct kobj_attribute sess_lat_attr_n##size =					\
		__ATTR(n##size, 0644, scst_sess_latency_show, scst_sess_latency_store);		\
	static struct kobj_attribute sess_lat_attr_r##size =					\
		__ATTR(r##size, 0644, scst_sess_latency_show, scst_sess_latency_store);		\
	static struct kobj_attribute sess_lat_attr_w##size =					\
		__ATTR(w##size, 0644, scst_sess_latency_show, scst_sess_latency_store);		\
	static struct kobj_attribute sess_lat_attr_b##size =					\
		__ATTR(b##size, 0644, scst_sess_latency_show, scst_sess_latency_store)
SCST_LAT_ATTR(512);
SCST_LAT_ATTR(1024);
SCST_LAT_ATTR(2048);
SCST_LAT_ATTR(4096);
SCST_LAT_ATTR(8192);
SCST_LAT_ATTR(16384);
SCST_LAT_ATTR(32768);
SCST_LAT_ATTR(65536);
SCST_LAT_ATTR(131072);
SCST_LAT_ATTR(262144);
SCST_LAT_ATTR(524288);

static const struct attribute *scst_sess_lat_attr[] = {
	SCST_LAT_ATTRS(512),
	SCST_LAT_ATTRS(1024),
	SCST_LAT_ATTRS(2048),
	SCST_LAT_ATTRS(4096),
	SCST_LAT_ATTRS(8192),
	SCST_LAT_ATTRS(16384),
	SCST_LAT_ATTRS(32768),
	SCST_LAT_ATTRS(65536),
	SCST_LAT_ATTRS(131072),
	SCST_LAT_ATTRS(262144),
	SCST_LAT_ATTRS(524288),
	NULL,
};

static int scst_create_latency_attrs(struct scst_session *sess)
{
	int res;

	res = -ENOMEM;
	sess->lat_kobj = kobject_create_and_add("latency", &sess->sess_kobj);
	if (!sess->lat_kobj)
		goto out;

	res = sysfs_create_files(sess->lat_kobj, scst_sess_lat_attr);
	if (res < 0)
		goto out;

out:
	return res;
}

static void scst_remove_latency_attrs(struct scst_session *sess)
{
	kobject_del(sess->lat_kobj);
}

static int scst_create_sess_luns_link(struct scst_session *sess)
{
	int res;

	/*
	 * No locks are needed, because sess supposed to be in acg->acg_sess_list
	 * and tgt->sess_list, so blocking them from disappearing.
	 */

	if (sess->acg == sess->tgt->default_acg)
		res = sysfs_create_link(&sess->sess_kobj, sess->tgt->tgt_luns_kobj, "luns");
	else
		res = sysfs_create_link(&sess->sess_kobj, sess->acg->luns_kobj, "luns");

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

	res = kobject_init_and_add(&sess->sess_kobj, &scst_session_ktype, sess->tgt->tgt_sess_kobj,
				   "%s", name);
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

	if (sess->tgt->tgt_dif_supported) {
		res = sysfs_create_file(&sess->sess_kobj,
					&session_dif_checks_failed_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Adding %s sysfs attribute to session %s failed (%d)",
				    session_dif_checks_failed_attr.attr.name, name, res);
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

	res = scst_create_latency_attrs(sess);
	if (res != 0)
		goto out_del;

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

	scst_remove_latency_attrs(sess);
	kobject_del(&sess->sess_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&sess->sess_kobj, "session", &c,
				  &scst_sess_dep_map);

out:
	TRACE_EXIT();
}

/*
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
}

static ssize_t scst_lun_rd_only_show(struct kobject *kobj, struct kobj_attribute *attr,
				     char *buf)
{
	struct scst_acg_dev *acg_dev;

	acg_dev = container_of(kobj, struct scst_acg_dev, acg_dev_kobj);

	if (acg_dev->acg_dev_rd_only || acg_dev->dev->dev_rd_only)
		return sysfs_emit(buf, "%d\n%s\n", 1, SCST_SYSFS_KEY_MARK);
	else
		return sysfs_emit(buf, "%d\n", 0);
}

static struct kobj_attribute lun_options_attr =
	__ATTR(read_only, 0444, scst_lun_rd_only_show, NULL);

static struct attribute *acg_dev_attrs[] = {
	&lun_options_attr.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
ATTRIBUTE_GROUPS(acg_dev);
#endif

static struct kobj_type acg_dev_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_acg_dev_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.default_groups = acg_dev_groups,
#else
	.default_attrs = acg_dev_attrs,
#endif
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

	if (acg_dev->dev) {
		sysfs_remove_link(acg_dev->dev->dev_exp_kobj, acg_dev->acg_dev_link_name);
		kobject_put(&acg_dev->dev->dev_kobj);
	}

	kobject_del(&acg_dev->acg_dev_kobj);

	SCST_KOBJECT_PUT_AND_WAIT(&acg_dev->acg_dev_kobj, "acg_dev", &c,
				  &scst_acg_dev_dep_map);

	TRACE_EXIT();
}

int scst_acg_dev_sysfs_create(struct scst_acg_dev *acg_dev, struct kobject *parent)
{
	int res;

	TRACE_ENTRY();

	res = kobject_init_and_add(&acg_dev->acg_dev_kobj, &acg_dev_ktype, parent, "%llu",
				   acg_dev->lun);
	if (res != 0) {
		PRINT_ERROR("Can't add acg_dev %p to sysfs", acg_dev);
		goto out;
	}

	kobject_get(&acg_dev->dev->dev_kobj);

	snprintf(acg_dev->acg_dev_link_name, sizeof(acg_dev->acg_dev_link_name),
		 "export%u", acg_dev->dev->dev_exported_lun_num++);

	res = sysfs_create_link(acg_dev->dev->dev_exp_kobj, &acg_dev->acg_dev_kobj,
				acg_dev->acg_dev_link_name);
	if (res != 0) {
		PRINT_ERROR("Can't create acg %s LUN link",
			    acg_dev->acg->acg_name);
		goto out_del;
	}

	res = sysfs_create_link(&acg_dev->acg_dev_kobj, &acg_dev->dev->dev_kobj, "device");
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

/*
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
}

static struct kobj_type acg_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_acg_release,
};

static ssize_t scst_acg_ini_mgmt_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add INITIATOR_NAME\" >mgmt\n"
		"       echo \"del INITIATOR_NAME\" >mgmt\n"
		"       echo \"move INITIATOR_NAME DEST_GROUP_NAME\" >mgmt\n"
		"       echo \"clear\" >mgmt";

	return sysfs_emit(buf, "%s\n", help);
}

static int scst_process_acg_ini_mgmt_store(char *buffer, struct scst_tgt *tgt,
					   struct scst_acg *acg)
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
			PRINT_ERROR("Invalid initiator name");
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
			PRINT_ERROR("Invalid initiator name");
			res = -EINVAL;
			goto out_unlock;
		}

		acn = scst_find_acn(acg, name);
		if (!acn) {
			PRINT_ERROR("Unable to find initiator '%s' in group '%s'",
				    name, acg->acg_name);
			res = -EINVAL;
			goto out_unlock;
		}
		scst_del_free_acn(acn, true);
		break;
	case SCST_ACG_ACTION_INI_CLEAR:
		list_for_each_entry_safe(acn, acn_tmp, &acg->acn_list, acn_list_entry)
			scst_del_free_acn(acn, false);
		scst_check_reassign_sessions();
		break;
	case SCST_ACG_ACTION_INI_MOVE:
		name = scst_get_next_lexem(&pp);
		if (name[0] == '\0') {
			PRINT_ERROR("Invalid initiator name");
			res = -EINVAL;
			goto out_unlock;
		}

		group = scst_get_next_lexem(&pp);
		if (group[0] == '\0') {
			PRINT_ERROR("Invalid group name");
			res = -EINVAL;
			goto out_unlock;
		}

		TRACE_DBG("Move initiator '%s' to group '%s'",
			  name, group);

		acn = scst_find_acn(acg, name);
		if (!acn) {
			PRINT_ERROR("Unable to find initiator '%s' in group '%s'",
				    name, acg->acg_name);
			res = -EINVAL;
			goto out_unlock;
		}
		acg_dest = scst_tgt_find_acg(tgt, group);
		if (!acg_dest) {
			PRINT_ERROR("Unable to find group '%s' in target '%s'",
				    group, tgt->tgt_name);
			res = -EINVAL;
			goto out_unlock;
		}
		if (scst_find_acn(acg_dest, name)) {
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

static ssize_t scst_acg_ini_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct scst_acg *acg;

	acg = container_of(kobj->parent, struct scst_acg, acg_kobj);

	return __scst_acg_mgmt_store(acg, buf, count, false, scst_acg_ini_mgmt_store_work_fn);
}

static struct kobj_attribute scst_acg_ini_mgmt =
	__ATTR(mgmt, 0644, scst_acg_ini_mgmt_show, scst_acg_ini_mgmt_store);

static ssize_t scst_acg_luns_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
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
	__ATTR(mgmt, 0644, scst_luns_mgmt_show, scst_acg_luns_mgmt_store);

static ssize_t scst_acg_addr_method_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	return __scst_acg_addr_method_show(acg, buf);
}

static ssize_t scst_acg_addr_method_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	TRACE_ENTRY();

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	res = __scst_acg_addr_method_store(acg, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_acg_addr_method =
	__ATTR(addr_method, 0644, scst_acg_addr_method_show, scst_acg_addr_method_store);

static ssize_t scst_acg_io_grouping_type_show(struct kobject *kobj, struct kobj_attribute *attr,
					      char *buf)
{
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	return __scst_acg_io_grouping_type_show(acg, buf);
}

static ssize_t scst_acg_io_grouping_type_store(struct kobject *kobj, struct kobj_attribute *attr,
					       const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	TRACE_ENTRY();

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
	__ATTR(io_grouping_type, 0644, scst_acg_io_grouping_type_show,
	       scst_acg_io_grouping_type_store);

static ssize_t scst_acg_black_hole_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	return __scst_acg_black_hole_show(acg, buf);
}

static ssize_t scst_acg_black_hole_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	TRACE_ENTRY();

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	res = __scst_acg_black_hole_store(acg, buf, count);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_acg_black_hole =
	__ATTR(black_hole, 0644, scst_acg_black_hole_show, scst_acg_black_hole_store);

static ssize_t scst_acg_cpu_mask_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_acg *acg;

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	return __scst_acg_cpu_mask_show(acg, buf);
}

static ssize_t scst_acg_cpu_mask_store(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	TRACE_ENTRY();

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
	__ATTR(cpu_mask, 0644, scst_acg_cpu_mask_show, scst_acg_cpu_mask_store);

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

	SCST_KOBJECT_PUT_AND_WAIT(&acg->acg_kobj, "acg", &c, &scst_acg_dep_map);

	TRACE_EXIT();
}

int scst_acg_sysfs_create(struct scst_tgt *tgt, struct scst_acg *acg)
{
	int res = 0;

	TRACE_ENTRY();

	res = kobject_init_and_add(&acg->acg_kobj, &acg_ktype, tgt->tgt_ini_grp_kobj, "%s",
				   acg->acg_name);
	if (res != 0) {
		PRINT_ERROR("Can't add acg '%s' to sysfs", acg->acg_name);
		goto out;
	}

	acg->luns_kobj = kobject_create_and_add("luns", &acg->acg_kobj);
	if (!acg->luns_kobj) {
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

	acg->initiators_kobj = kobject_create_and_add("initiators", &acg->acg_kobj);
	if (!acg->initiators_kobj) {
		PRINT_ERROR("Can't create initiators kobj for tgt %s",
			    tgt->tgt_name);
		res = -ENOMEM;
		goto out_del;
	}

	res = sysfs_create_file(acg->initiators_kobj, &scst_acg_ini_mgmt.attr);
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

	res = sysfs_create_file(&acg->acg_kobj, &scst_acg_black_hole.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			    scst_acg_black_hole.attr.name, tgt->tgt_name);
		goto out_del;
	}

	res = sysfs_create_file(&acg->acg_kobj, &scst_acg_cpu_mask.attr);
	if (res != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			    scst_acg_cpu_mask.attr.name, tgt->tgt_name);
		goto out_del;
	}

	if (acg->tgt->tgtt->acg_attrs) {
		res = sysfs_create_files(&acg->acg_kobj, acg->tgt->tgtt->acg_attrs);
		if (res != 0) {
			PRINT_ERROR("Can't add attributes for acg %s",
				    acg->acg_name);
			goto out_del;
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	scst_acg_sysfs_del(acg);
	goto out;
}

/*
 ** acn
 **/

static ssize_t scst_acn_file_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", attr->attr.name);
}

int scst_acn_sysfs_create(struct scst_acn *acn)
{
	int res = 0;
	struct scst_acg *acg = acn->acg;
	struct kobj_attribute *attr = NULL;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	static struct lock_class_key __key;
#endif

	TRACE_ENTRY();

	acn->acn_attr = NULL;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		PRINT_ERROR("Unable to allocate attributes for initiator '%s'",
			    acn->name);
		res = -ENOMEM;
		goto out;
	}

	attr->attr.name = kstrdup(acn->name, GFP_KERNEL);
	if (!attr->attr.name) {
		PRINT_ERROR("Unable to allocate attributes for initiator '%s'",
			    acn->name);
		res = -ENOMEM;
		goto out_free;
	}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	attr->attr.key = &__key;
#endif

	attr->attr.mode = 0444;
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

	if (acn->acn_attr) {
		sysfs_remove_file(acg->initiators_kobj, &acn->acn_attr->attr);
		kfree(acn->acn_attr->attr.name);
		kfree(acn->acn_attr);
	}

	TRACE_EXIT();
}

/*
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
}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_devt_trace_level_show(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buf)
{
	struct scst_dev_type *devt;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	return scst_trace_level_show(devt->trace_tbl, devt->trace_flags ? *devt->trace_flags : 0,
				     buf, devt->trace_tbl_help);
}

static ssize_t scst_devt_trace_level_store(struct kobject *kobj, struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	int res;
	struct scst_dev_type *devt;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	res = mutex_lock_interruptible(&scst_log_mutex);
	if (res != 0)
		goto out;

	res = scst_write_trace(buf, count, devt->trace_flags, devt->default_trace_flags,
			       devt->name, devt->trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute devt_trace_attr =
	__ATTR(trace_level, 0644, scst_devt_trace_level_show, scst_devt_trace_level_store);

#endif /* #if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static ssize_t scst_devt_type_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_dev_type *devt;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	return sysfs_emit(buf, "%d - %s\n",
			  devt->type,
			  (unsigned int)devt->type >= ARRAY_SIZE(scst_dev_handler_types) ?
			  "unknown" : scst_dev_handler_types[devt->type]);
}

static struct kobj_attribute scst_devt_type_attr =
	__ATTR(type, 0444, scst_devt_type_show, NULL);

static struct attribute *scst_devt_def_attrs[] = {
	&scst_devt_type_attr.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
ATTRIBUTE_GROUPS(scst_devt_def);
#endif

static struct kobj_type scst_devt_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_devt_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.default_groups = scst_devt_def_groups,
#else
	.default_attrs = scst_devt_def_attrs,
#endif
};

static char *scst_dev_params(struct scst_dev_type *devt)
{
	char *p, *r;
	const char *const *q;
	bool comma = false;

	if (!devt->add_device_parameters)
		return NULL;
	p = kstrdup("The following parameters available: ", GFP_KERNEL);
	if (!p)
		return NULL;
	for (q = devt->add_device_parameters; *q; q++) {
		r = kasprintf(GFP_KERNEL, "%s%s%s", p, comma ? ", " : "", *q);
		kfree(p);
		if (!r)
			return NULL;
		p = r;
		comma = true;
	}
	return p;
}

static ssize_t scst_devt_mgmt_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add_device device_name [parameters]\" >mgmt\n"
		"       echo \"del_device device_name\" >mgmt\n"
		"%s%s"
		"%s"
		"\n"
		"where parameters are one or more param_name=value pairs separated by ';'\n\n"
		"%s%s%s%s%s%s%s%s%s\n";
	struct scst_dev_type *devt;
	char *p;
	int res;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);
	p = scst_dev_params(devt);
	res = sysfs_emit(buf, help,
			 devt->devt_optional_attributes ?
			 "       echo \"add_attribute <attribute> <value>\" >mgmt\n"
			 "       echo \"del_attribute <attribute> <value>\" >mgmt\n" : "",
			 devt->dev_optional_attributes ?
			 "       echo \"add_device_attribute device_name <attribute> <value>\" >mgmt\n"
			 "       echo \"del_device_attribute device_name <attribute> <value>\" >mgmt\n" : "",
			 devt->mgmt_cmd_help ? devt->mgmt_cmd_help : "",
			 devt->mgmt_cmd_help ? "\n" : "",
			 p ?: "",
			 devt->add_device_parameters ? "\n" : "",
			 devt->devt_optional_attributes ?
			 "The following dev handler attributes available: " : "",
			 devt->devt_optional_attributes ? devt->devt_optional_attributes : "",
			 devt->devt_optional_attributes ? "\n" : "",
			 devt->dev_optional_attributes ?
			 "The following device attributes available: " : "",
			 devt->dev_optional_attributes ? devt->dev_optional_attributes : "",
			 devt->dev_optional_attributes ? "\n" : "");
	kfree(p);
	return res;
}

static int scst_process_devt_mgmt_store(char *buffer, struct scst_dev_type *devt)
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
			PRINT_ERROR("Device name required");
			res = -EINVAL;
			goto out_ungrab;
		}
		res = devt->add_device(dev_name, pp);
	} else if (strcasecmp("del_device", p) == 0) {
		dev_name = scst_get_next_lexem(&pp);
		if (*dev_name == '\0') {
			PRINT_ERROR("Device name required");
			res = -EINVAL;
			goto out_ungrab;
		}

		p = scst_get_next_lexem(&pp);
		if (*p != '\0')
			goto out_syntax_err;

		res = devt->del_device(dev_name);
	} else if (devt->mgmt_cmd) {
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

static ssize_t __scst_devt_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
				      const char *buf, size_t count,
				      int (*sysfs_work_fn)(struct scst_sysfs_work_item *work))
{
	int res;
	char *buffer;
	struct scst_dev_type *devt;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	buffer = kasprintf(GFP_KERNEL, "%.*s", (int)count, buf);
	if (!buffer) {
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

static ssize_t scst_devt_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	return __scst_devt_mgmt_store(kobj, attr, buf, count, scst_devt_mgmt_store_work_fn);
}

static struct kobj_attribute scst_devt_mgmt =
	__ATTR(mgmt, 0644, scst_devt_mgmt_show, scst_devt_mgmt_store);

static ssize_t scst_devt_pass_through_mgmt_show(struct kobject *kobj, struct kobj_attribute *attr,
						char *buf)
{
	static const char help[] =
		"Usage: echo \"add_device H:C:I:L\" >mgmt\n"
		"       echo \"del_device H:C:I:L\" >mgmt";

	return sysfs_emit(buf, "%s\n", help);
}

static int scst_process_devt_pass_through_mgmt_store(char *buffer, struct scst_dev_type *devt)
{
	int res = 0;
	char *pp, *action, *devstr;
	unsigned int host, channel, id;
	u64 lun;
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

	if (sscanf(devstr, "%u:%u:%u:%llu", &host, &channel, &id, &lun) != 4)
		goto out_syntax_err;

	TRACE_DBG("Dev %d:%d:%d:%lld", host, channel, id, lun);

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	/* Check if devt not be already freed while we were coming here */
	if (scst_check_devt_ptr(devt, &scst_dev_type_list) != 0)
		goto out_unlock;

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (d->virt_id == 0 &&
		    d->scsi_dev->host->host_no == host &&
		    d->scsi_dev->channel == channel &&
		    d->scsi_dev->id == id &&
		    d->scsi_dev->lun == lun) {
			dev = d;
			TRACE_DBG("Dev %p (%d:%d:%d:%lld) found",
				  dev, host, channel, id, lun);
			break;
		}
	}
	if (!dev) {
		PRINT_ERROR("Device %d:%d:%d:%lld not found",
			    host, channel, id, lun);
		res = -EINVAL;
		goto out_unlock;
	}

	if (dev->scsi_dev->type != devt->type) {
		PRINT_ERROR("Type %d of device %s differs from type %d of dev handler %s",
			    dev->type, dev->virt_name, devt->type, devt->name);
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

static int scst_devt_pass_through_mgmt_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_devt_pass_through_mgmt_store(work->buf, work->devt);
}

static ssize_t scst_devt_pass_through_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
						 const char *buf, size_t count)
{
	return __scst_devt_mgmt_store(kobj, attr, buf, count,
				      scst_devt_pass_through_mgmt_store_work_fn);
}

static struct kobj_attribute scst_devt_pass_through_mgmt =
	__ATTR(mgmt, 0644, scst_devt_pass_through_mgmt_show, scst_devt_pass_through_mgmt_store);

/*
 * Creates an attribute entry for dev handler.
 */
int scst_create_devt_attr(struct scst_dev_type *devt, struct kobj_attribute *attribute)
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

	if (devt->parent)
		parent = &devt->parent->devt_kobj;
	else
		parent = scst_handlers_kobj;

	res = kobject_init_and_add(&devt->devt_kobj, &scst_devt_ktype, parent, "%s", devt->name);
	if (res != 0) {
		PRINT_ERROR("Can't add devt %s to sysfs", devt->name);
		goto out;
	}

	if (devt->add_device)
		res = sysfs_create_file(&devt->devt_kobj, &scst_devt_mgmt.attr);
	else if (!devt->no_mgmt)
		res = sysfs_create_file(&devt->devt_kobj, &scst_devt_pass_through_mgmt.attr);

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
	if (devt->trace_flags) {
		res = sysfs_create_file(&devt->devt_kobj, &devt_trace_attr.attr);
		if (res != 0) {
			PRINT_ERROR("Can't add devt trace_flag for dev handler %s",
				    devt->name);
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
}

/*
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

/*
 ** SCST sysfs device_groups/<dg>/devices directory implementation.
 **/

static ssize_t scst_dg_devs_mgmt_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	static const char help[] =
		"Usage: echo \"add device\" >mgmt\n"
		"       echo \"del device\" >mgmt\n";

	return sysfs_emit(buf, help);
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

static ssize_t scst_dg_devs_mgmt_store(struct kobject *kobj, struct kobj_attribute *attr,
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
	__ATTR(mgmt, 0644, scst_dg_devs_mgmt_show, scst_dg_devs_mgmt_store);

static const struct attribute *scst_dg_devs_attrs[] = {
	&scst_dg_devs_mgmt.attr,
	NULL,
};

/*
 ** SCST sysfs device_groups/<dg>/target_groups/<tg>/<tgt> implementation.
 **/

static ssize_t scst_tg_tgt_rel_tgt_id_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct scst_tg_tgt *tg_tgt;

	tg_tgt = container_of(kobj, struct scst_tg_tgt, kobj);
	return sysfs_emit(buf, "%u\n" SCST_SYSFS_KEY_MARK "\n",
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
	snprintf(ch, sizeof(ch), "%.*s", min_t(int, count, sizeof(ch) - 1), buf);
	res = kstrtoul(ch, 0, &rel_tgt_id);
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
	__ATTR(rel_tgt_id, 0644, scst_tg_tgt_rel_tgt_id_show, scst_tg_tgt_rel_tgt_id_store);

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
	if (tg_tgt->tgt) {
		res = sysfs_create_link(&tg->kobj, &tg_tgt->tgt->tgt_kobj,
					tg_tgt->name);
	} else {
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
	if (tg_tgt->tgt) {
		sysfs_remove_link(&tg->kobj, tg_tgt->name);
	} else {
		sysfs_remove_files(&tg_tgt->kobj, scst_tg_tgt_attrs);
		kobject_del(&tg_tgt->kobj);
	}
	TRACE_EXIT();
}

/*
 ** SCST sysfs device_groups/<dg>/target_groups/<tg> directory implementation.
 **/

static ssize_t scst_tg_group_id_show(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     char *buf)
{
	struct scst_target_group *tg;

	tg = container_of(kobj, struct scst_target_group, kobj);
	return sysfs_emit(buf, "%u\n" SCST_SYSFS_KEY_MARK "\n",
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
	snprintf(ch, sizeof(ch), "%.*s", min_t(int, count, sizeof(ch) - 1), buf);
	res = kstrtoul(ch, 0, &group_id);
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
	__ATTR(group_id, 0644, scst_tg_group_id_show, scst_tg_group_id_store);

static ssize_t scst_tg_preferred_show(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      char *buf)
{
	struct scst_target_group *tg = container_of(kobj, struct scst_target_group, kobj);
	ssize_t ret;

	ret = sysfs_emit(buf, "%u\n", tg->preferred);

	if (tg->preferred)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	return ret;
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
	res = kstrtoul(cmd, 0, &preferred);
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
	__ATTR(preferred, 0644, scst_tg_preferred_show, scst_tg_preferred_store);

static ssize_t scst_tg_state_show(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf)
{
	struct scst_target_group *tg;
	const char *n;

	tg = container_of(kobj, struct scst_target_group, kobj);
	n = scst_alua_state_name(tg->state);

	return sysfs_emit(buf, "%s\n" SCST_SYSFS_KEY_MARK "\n",
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

static ssize_t scst_tg_state_store(struct kobject *kobj, struct kobj_attribute *attr,
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
	__ATTR(state, 0644, scst_tg_state_show, scst_tg_state_store);

static ssize_t scst_tg_mgmt_show(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	static const char help[] =
		"Usage: echo \"add target\" >mgmt\n"
		"       echo \"del target\" >mgmt\n";

	return sysfs_emit(buf, help);
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
	__ATTR(mgmt, 0644, scst_tg_mgmt_show, scst_tg_mgmt_store);

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

/*
 ** SCST sysfs device_groups/<dg>/target_groups directory implementation.
 **/

static ssize_t scst_dg_tgs_mgmt_show(struct kobject *kobj, struct kobj_attribute *attr,
				     char *buf)
{
	static const char help[] =
		"Usage: echo \"create group_name\" >mgmt\n"
		"       echo \"del group_name\" >mgmt\n";

	return sysfs_emit(buf, help);
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
	__ATTR(mgmt, 0644, scst_dg_tgs_mgmt_show, scst_dg_tgs_mgmt_store);

static const struct attribute *scst_dg_tgs_attrs[] = {
	&scst_dg_tgs_mgmt.attr,
	NULL,
};

/*
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

	return sysfs_emit(buf, help);
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
	__ATTR(mgmt, 0644, scst_device_groups_mgmt_show, scst_device_groups_mgmt_store);

static const struct attribute *scst_device_groups_attrs[] = {
	&scst_device_groups_mgmt.attr,
	NULL,
};

/*
 ** SCST sysfs root directory implementation
 **/

static struct kobject scst_sysfs_root_kobj;

static ssize_t scst_measure_latency_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&scst_measure_latency));
}

static void scst_free_lat_stats_mem(void)
{
	struct scst_tgt_template *tt;
	struct scst_tgt *tgt;
	struct scst_session *sess;

	lockdep_assert_held(&scst_mutex);

	list_for_each_entry(tt, &scst_template_list, scst_template_list_entry) {
		list_for_each_entry(tgt, &tt->tgt_list, tgt_list_entry) {
			list_for_each_entry(sess, &tgt->sess_list,
					    sess_list_entry) {
				kvfree(sess->lat_stats);
				sess->lat_stats = NULL;
			}
		}
	}
}

static int scst_alloc_lat_stats_mem(void)
{
	struct scst_tgt_template *tt;
	struct scst_tgt *tgt;
	struct scst_session *sess;

	lockdep_assert_held(&scst_mutex);

	list_for_each_entry(tt, &scst_template_list, scst_template_list_entry) {
		list_for_each_entry(tgt, &tt->tgt_list, tgt_list_entry) {
			list_for_each_entry(sess, &tgt->sess_list,
					    sess_list_entry) {
				sess->lat_stats = vzalloc(sizeof(*sess->lat_stats));
				if (!sess->lat_stats) {
					scst_free_lat_stats_mem();
					return -ENOMEM;
				}
			}
		}
	}

	return 0;
}

static ssize_t scst_measure_latency_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	bool prev_val;
	long val;
	int res;

	res = kstrtol(buf, 0, &val);
	if (res < 0)
		goto out;

	val = !!val;

	res = scst_suspend_activity(10 * HZ);
	if (res)
		goto out;
	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out_resume;

	spin_lock(&scst_measure_latency_lock);
	prev_val = atomic_read(&scst_measure_latency);
	atomic_set(&scst_measure_latency, val);
	spin_unlock(&scst_measure_latency_lock);

	if (prev_val != val) {
		if (val) {
			res = scst_alloc_lat_stats_mem();
			if (res)
				goto out_unlock;
		} else {
			scst_free_lat_stats_mem();
		}
	}

	res = count;

out_unlock:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	return res;
}

static struct kobj_attribute scst_measure_latency_attr =
	__ATTR(measure_latency, 0644, scst_measure_latency_show, scst_measure_latency_store);

static ssize_t scst_threads_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	TRACE_ENTRY();

	ret = sysfs_emit(buf, "%d\n", scst_main_cmd_threads.nr_threads);

	if (scst_main_cmd_threads.nr_threads != scst_threads)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT();

	return ret;
}

static int scst_process_threads_store(int newtn)
{
	int res;
	long oldtn, delta;

	TRACE_ENTRY();

	TRACE_DBG("newtn %d", newtn);

	/*
	 * Some commands are taking scst_mutex on commands processing path,
	 * so we need to drain them, because otherwise we can fall into a
	 * deadlock with kthread_stop() in scst_del_threads() waiting for
	 * those commands to finish.
	 */
	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out_resume;

	oldtn = scst_main_cmd_threads.nr_threads;

	delta = newtn - oldtn;
	if (delta < 0) {
		scst_del_threads(&scst_main_cmd_threads, -delta);
	} else {
		res = scst_add_threads(&scst_main_cmd_threads, NULL, NULL, delta);
		if (res != 0)
			goto out_up;
	}

	PRINT_INFO("Changed cmd threads num: old %ld, new %d", oldtn, newtn);

out_up:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_threads_store_work_fn(struct scst_sysfs_work_item *work)
{
	return scst_process_threads_store(work->new_threads_num);
}

static ssize_t scst_threads_store(struct kobject *kobj, struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	int res;
	long newtn;
	struct scst_sysfs_work_item *work;

	TRACE_ENTRY();

	res = kstrtol(buf, 0, &newtn);
	if (res != 0) {
		PRINT_ERROR("kstrtol() for %s failed: %d ", buf, res);
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
	__ATTR(threads, 0644, scst_threads_show, scst_threads_store);

static ssize_t scst_setup_id_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	TRACE_ENTRY();

	ret = sysfs_emit(buf, "0x%x\n", scst_setup_id);

	if (scst_setup_id)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT();

	return ret;
}

static ssize_t scst_setup_id_store(struct kobject *kobj, struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int res;
	unsigned long val;

	TRACE_ENTRY();

	res = kstrtoul(buf, 0, &val);
	if (res != 0) {
		PRINT_ERROR("kstrtoul() for %s failed: %d ", buf, res);
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
	__ATTR(setup_id, 0644, scst_setup_id_show, scst_setup_id_store);

static ssize_t scst_max_tasklet_cmd_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	ssize_t ret;

	TRACE_ENTRY();

	ret = sysfs_emit(buf, "%d\n", scst_max_tasklet_cmd);

	if (scst_max_tasklet_cmd != SCST_DEF_MAX_TASKLET_CMD)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT();

	return ret;
}

static ssize_t scst_max_tasklet_cmd_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	int res;
	unsigned long val;

	TRACE_ENTRY();

	res = kstrtoul(buf, 0, &val);
	if (res != 0) {
		PRINT_ERROR("kstrtoul() for %s failed: %d ", buf, res);
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
	__ATTR(max_tasklet_cmd, 0644, scst_max_tasklet_cmd_show, scst_max_tasklet_cmd_store);

static ssize_t scst_poll_us_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	u64 t = scst_poll_ns;
	ssize_t ret;

	TRACE_ENTRY();

	do_div(t, 1000);

	ret = sysfs_emit(buf, "%lld\n", t);

	if (scst_poll_ns != SCST_DEF_POLL_NS)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	TRACE_EXIT();

	return ret;
}

static ssize_t scst_poll_us_store(struct kobject *kobj, struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	int res;
	unsigned long val;

	TRACE_ENTRY();

	res = kstrtoul(buf, 0, &val);
	if (res != 0) {
		PRINT_ERROR("kstrtoul() for %s failed: %d ", buf, res);
		goto out;
	}

	PRINT_INFO("Changed poll_us to %ld us", val);

	val *= 1000;
	scst_poll_ns = val;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_poll_us_attr =
	__ATTR(poll_us, 0644, scst_poll_us_show, scst_poll_us_store);

static ssize_t scst_suspend_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	TRACE_ENTRY();

	ret = sysfs_emit(buf, "%d\n", scst_get_suspend_count());

	TRACE_EXIT();

	return ret;
}

static ssize_t scst_suspend_store(struct kobject *kobj, struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	int res;
	long val;

	TRACE_ENTRY();

	res = kstrtol(buf, 0, &val);
	if (res != 0) {
		PRINT_ERROR("kstrtoul() for %s failed: %d ", buf, res);
		goto out;
	}

	if (val >= 0) {
		PRINT_INFO("SYSFS: suspending activities (timeout %ld)...", val);
		res = scst_suspend_activity(val * HZ);
		if (res == 0)
			PRINT_INFO("sysfs suspending done");
	} else {
		PRINT_INFO("SYSFS: resuming activities");
		scst_resume_activity();
	}

	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_suspend_attr =
	__ATTR(suspend, 0644, scst_suspend_show, scst_suspend_store);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static ssize_t scst_main_trace_level_show(struct kobject *kobj, struct kobj_attribute *attr,
					  char *buf)
{
	return scst_trace_level_show(scst_local_trace_tbl, trace_flag, buf, NULL);
}

static ssize_t scst_main_trace_level_store(struct kobject *kobj, struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	int res;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_log_mutex);
	if (res != 0)
		goto out;

	res = scst_write_trace(buf, count, &trace_flag, SCST_DEFAULT_LOG_FLAGS, "scst",
			       scst_local_trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_main_trace_level_attr =
	__ATTR(trace_level, 0644, scst_main_trace_level_show, scst_main_trace_level_store);

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static ssize_t scst_force_global_sgv_pool_show(struct kobject *kobj, struct kobj_attribute *attr,
					       char *buf)
{
	ssize_t ret;

	ret = sysfs_emit(buf, "%d\n", scst_force_global_sgv_pool);

	if (scst_force_global_sgv_pool)
		ret += sysfs_emit_at(buf, ret, "%s\n", SCST_SYSFS_KEY_MARK);

	return ret;
}

static ssize_t scst_force_global_sgv_pool_store(struct kobject *kobj, struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	int res;
	unsigned long v;

	TRACE_ENTRY();

	res = kstrtoul(buf, 0, &v);
	if (res)
		goto out;

	scst_force_global_sgv_pool = v;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_force_global_sgv_pool_attr =
	__ATTR(force_global_sgv_pool, 0644, scst_force_global_sgv_pool_show,
	       scst_force_global_sgv_pool_store);

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

	res = sysfs_emit(buf, "%s", work->res_buf);

put:
	scst_sysfs_work_put(work);

out:
	return res;
}

static struct kobj_attribute scst_trace_cmds_attr =
	__ATTR(trace_cmds, 0444, scst_show_trace_cmds, NULL);

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

static ssize_t scst_show_trace_mcmds(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_sysfs_work_item *work;
	ssize_t res;

	res = scst_alloc_sysfs_work(scst_process_show_trace_mcmds, true,
				    &work);
	if (res != 0)
		goto out;

	kobject_get(&scst_sysfs_root_kobj);
	scst_sysfs_work_get(work);
	res = scst_sysfs_queue_wait_work(work);
	if (res != 0)
		goto put;

	res = sysfs_emit(buf, "%s", work->res_buf);

put:
	scst_sysfs_work_put(work);

out:
	return res;
}

static struct kobj_attribute scst_trace_mcmds_attr =
	__ATTR(trace_mcmds, 0444, scst_show_trace_mcmds, NULL);

static ssize_t scst_version_show(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	char config[SCST_CONFIG_BUF_SIZE] = {};
	ssize_t ret = 0;

	TRACE_ENTRY();

	ret += sysfs_emit_at(buf, ret, "SCST version: %s\n", SCST_VERSION_STRING);
	ret += sysfs_emit_at(buf, ret, "SCST build date: %s\n", SCST_BUILD_DATE_STRING);
	ret += sysfs_emit_at(buf, ret, "SCST build number: %s\n", SCST_BUILD_NUMBER_STRING);
	ret += sysfs_emit_at(buf, ret, "SCST git commit sha1: %s\n", SCST_GIT_COMMIT_STRING);
	ret += sysfs_emit_at(buf, ret, "SCST kver: %s\n", SCST_KVER_STRING);
	ret += sysfs_emit_at(buf, ret, "SCST arch type: %s\n", SCST_ARCH_TYPE_STRING);

	if (scst_dump_config(config, sizeof(config)))
		ret += sysfs_emit_at(buf, ret, "%s\n", config);

	TRACE_EXIT();

	return ret;
}

static struct kobj_attribute scst_version_attr =
	__ATTR(version, 0444, scst_version_show, NULL);

static ssize_t scst_last_sysfs_mgmt_res_show(struct kobject *kobj, struct kobj_attribute *attr,
					     char *buf)
{
	ssize_t res;

	TRACE_ENTRY();

	spin_lock(&sysfs_work_lock);
	TRACE_DBG("active_sysfs_works %d", active_sysfs_works);
	if (active_sysfs_works > 0)
		res = -EAGAIN;
	else
		res = sysfs_emit(buf, "%d\n", last_sysfs_work_res);
	spin_unlock(&sysfs_work_lock);

	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_last_sysfs_mgmt_res_attr =
	__ATTR(last_sysfs_mgmt_res, 0444, scst_last_sysfs_mgmt_res_show, NULL);

static ssize_t scst_cluster_name_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t res = 0;

	TRACE_ENTRY();

	if (scst_cluster_name)
		res = sysfs_emit(buf, "%s\n%s\n", scst_cluster_name, SCST_SYSFS_KEY_MARK);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_cluster_name_store(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	int res = 0;
	int len;

	TRACE_ENTRY();

	if (!buf || count == 0)
		goto out;

	len = strnlen(buf, count);
	if (buf[count - 1] == '\n')
		len--;

	if (len == 0) {
		kfree(scst_cluster_name);
		scst_cluster_name = NULL;
		goto out_done;
	}

	if (len >= DLM_LOCKSPACE_LEN) {
		PRINT_ERROR("cluster_name string too long (len %d)", len);
		res = -EINVAL;
		goto out;
	}

	kfree(scst_cluster_name);
	scst_cluster_name = kstrndup(buf, len, GFP_KERNEL);
	if (!scst_cluster_name) {
		PRINT_ERROR("Unable to alloc cluster_name string (len %d)",
			    len + 1);
		res = -ENOMEM;
		goto out;
	}

out_done:
	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_cluster_name_attr =
	__ATTR(cluster_name, 0644, scst_cluster_name_show, scst_cluster_name_store);

static struct attribute *scst_sysfs_root_def_attrs[] = {
	&scst_measure_latency_attr.attr,
	&scst_threads_attr.attr,
	&scst_setup_id_attr.attr,
	&scst_max_tasklet_cmd_attr.attr,
	&scst_poll_us_attr.attr,
	&scst_suspend_attr.attr,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	&scst_main_trace_level_attr.attr,
#endif
	&scst_force_global_sgv_pool_attr.attr,
	&scst_trace_cmds_attr.attr,
	&scst_trace_mcmds_attr.attr,
	&scst_version_attr.attr,
	&scst_last_sysfs_mgmt_res_attr.attr,
	&scst_cluster_name_attr.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
ATTRIBUTE_GROUPS(scst_sysfs_root_def);
#endif

static void scst_sysfs_root_release(struct kobject *kobj)
{
	complete_all(&scst_sysfs_root_release_completion);
}

static struct kobj_type scst_sysfs_root_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_root_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.default_groups = scst_sysfs_root_def_groups,
#else
	.default_attrs = scst_sysfs_root_def_attrs,
#endif
};

/*
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

	list_for_each_entry(info, &scst_sysfs_user_info_list, info_list_entry) {
		if (info->info_cookie == cookie) {
			res = info;
			break;
		}
	}

	TRACE_EXIT_HRES(res);
	return res;
}

/*
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
	if (res) {
		if (!res->info_being_executed)
			res->info_being_executed = 1;
	}

	mutex_unlock(&scst_sysfs_user_info_mutex);

	TRACE_EXIT_HRES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_sysfs_user_get_info);

/*
 ** Helper functionality to help target drivers and dev handlers support
 ** sending events to user space and wait for their completion in a safe
 ** manner. See samples how to use it in iscsi-scst or scst_user.
 **/

/*
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
	if (!info) {
		PRINT_ERROR("Unable to allocate sysfs user info (size %zd)",
			    sizeof(*info));
		res = -ENOMEM;
		goto out;
	}

	mutex_lock(&scst_sysfs_user_info_mutex);

	while ((info->info_cookie == 0) ||
	       (scst_sysfs_user_find_info(info->info_cookie)))
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

/*
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

/*
 * scst_wait_info_completion() - wait for a user space event's completion
 *
 * Waits for the info request been completed by user space at most timeout
 * jiffies. If the reply received before timeout and being processed by
 * another part of the kernel, i.e. scst_sysfs_user_info_executing()
 * returned true, waits for it to complete indefinitely.
 *
 * Returns status of the request completion.
 */
int scst_wait_info_completion(struct scst_sysfs_user_info *info, unsigned long timeout)
{
	int res, rc;

	TRACE_ENTRY();

	TRACE_DBG("Waiting for info %p completion", info);

	while (1) {
		rc = wait_for_completion_interruptible_timeout(&info->info_completion, timeout);
		if (rc > 0) {
			TRACE_DBG("Waiting for info %p finished with %d",
				  info, rc);
			break;
		} else if (rc == 0) {
			if (!scst_sysfs_user_info_executing(info)) {
				PRINT_ERROR("Timeout waiting for user space event %p",
					    info);
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
			PRINT_ERROR("wait_for_completion() failed: %d", res);
			goto out;
		} else {
			TRACE_DBG("Waiting for info %p finished with %d, retrying",
				  info, rc);
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

	sysfs_work_thread = kthread_run(sysfs_work_thread_fn, NULL, "scst_uid");
	if (IS_ERR(sysfs_work_thread)) {
		res = PTR_ERR(sysfs_work_thread);
		PRINT_ERROR("kthread_run() for user interface thread failed: %d", res);
		sysfs_work_thread = NULL;
		goto out;
	}

	res = kobject_init_and_add(&scst_sysfs_root_kobj, &scst_sysfs_root_ktype, kernel_kobj,
				   "%s", "scst_tgt");
	if (res != 0)
		goto sysfs_root_add_error;

	scst_targets_kobj = kobject_create_and_add("targets", &scst_sysfs_root_kobj);
	if (!scst_targets_kobj)
		goto targets_kobj_error;

	scst_devices_kobj = kobject_create_and_add("devices", &scst_sysfs_root_kobj);
	if (!scst_devices_kobj)
		goto devices_kobj_error;

	res = scst_add_sgv_kobj(&scst_sysfs_root_kobj, "sgv");
	if (res != 0)
		goto sgv_kobj_error;

	scst_handlers_kobj = kobject_create_and_add("handlers", &scst_sysfs_root_kobj);
	if (!scst_handlers_kobj)
		goto handlers_kobj_error;

	scst_device_groups_kobj = kobject_create_and_add("device_groups", &scst_sysfs_root_kobj);
	if (!scst_device_groups_kobj)
		goto device_groups_kobj_error;

	if (sysfs_create_files(scst_device_groups_kobj, scst_device_groups_attrs))
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

	PRINT_INFO("Exiting SCST sysfs hierarchy...");

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

	PRINT_INFO("Exiting SCST sysfs hierarchy done");

	TRACE_EXIT();
}
