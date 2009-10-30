/*
 *  scst_sysfs.c
 *
 *  Copyright (C) 2009 Daniel Henrique Debonzi <debonzi@linux.vnet.ibm.com>
 *  Copyright (C) 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2009 ID7 Ltd.
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

#include "scst.h"
#include "scst_priv.h"
#include "scst_mem.h"

static DEFINE_MUTEX(scst_sysfs_mutex);

static DECLARE_COMPLETION(scst_sysfs_root_release_completion);

static struct kobject scst_sysfs_root_kobj;
static struct kobject *scst_targets_kobj;
static struct kobject *scst_devices_kobj;
static struct kobject *scst_sgv_kobj;
static struct kobject *scst_handlers_kobj;

struct sysfs_ops scst_sysfs_ops;
EXPORT_SYMBOL(scst_sysfs_ops);

static const char *scst_dev_handler_types[] =
{
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

static struct scst_trace_log scst_trace_tbl[] =
{
    { TRACE_OUT_OF_MEM,		"out_of_mem" },
    { TRACE_MINOR,		"minor" },
    { TRACE_SG_OP,		"sg" },
    { TRACE_MEMORY,		"mem" },
    { TRACE_BUFF,		"buff" },
#ifndef GENERATING_UPSTREAM_PATCH
    { TRACE_ENTRYEXIT,		"entryexit" },
#endif
    { TRACE_PID,		"pid" },
    { TRACE_LINE,		"line" },
    { TRACE_FUNCTION,		"function" },
    { TRACE_DEBUG,		"debug" },
    { TRACE_SPECIAL,		"special" },
    { TRACE_SCSI,		"scsi" },
    { TRACE_MGMT,		"mgmt" },
    { TRACE_MGMT_MINOR,		"mgmt_minor" },
    { TRACE_MGMT_DEBUG,		"mgmt_dbg" },
    { 0,			NULL }
};

static struct scst_trace_log scst_local_trace_tbl[] =
{
    { TRACE_RTRY,		"retry" },
    { TRACE_SCSI_SERIALIZING,	"scsi_serializing" },
    { TRACE_RCV_BOT,		"recv_bot" },
    { TRACE_SND_BOT,		"send_bot" },
    { TRACE_RCV_TOP,		"recv_top" },
    { TRACE_SND_TOP,		"send_top" },
    { 0,			NULL }
};

static ssize_t scst_trace_level_show(const struct scst_trace_log *local_tbl,
	unsigned long log_level, char *buf, const char *help);
static int scst_write_trace(const char *buf, size_t length,
	unsigned long *log_level, unsigned long default_level,
	const char *name, const struct scst_trace_log *tbl);

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static ssize_t scst_luns_mgmt_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_luns_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);

static void scst_sysfs_release(struct kobject *kobj)
{
	kfree(kobj);
}

/*
 * Target Template
 */

static void scst_tgtt_release(struct kobject *kobj)
{
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	complete_all(&tgtt->tgtt_kobj_release_cmpl);

	scst_tgtt_cleanup(tgtt);

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

	if (mutex_lock_interruptible(&scst_log_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

int scst_create_tgtt_sysfs(struct scst_tgt_template *tgtt)
{
	int retval = 0;
	const struct attribute **pattr;

	TRACE_ENTRY();

	init_completion(&tgtt->tgtt_kobj_release_cmpl);

	tgtt->tgtt_kobj_initialized = 1;

	retval = kobject_init_and_add(&tgtt->tgtt_kobj, &tgtt_ktype,
			scst_targets_kobj, tgtt->name);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgtt %s to sysfs", tgtt->name);
		goto out;
	}

	/*
	 * In case of errors there's no need for additional cleanup, because
	 * it will be done by the _put function() called by the caller.
	 */

	pattr = tgtt->tgtt_attrs;
	if (pattr != NULL) {
		while (*pattr != NULL) {
			TRACE_DBG("Creating attr %s for target driver %s",
				(*pattr)->name, tgtt->name);
			retval = sysfs_create_file(&tgtt->tgtt_kobj, *pattr);
			if (retval != 0) {
				PRINT_ERROR("Can't add attr %s for target "
					"driver %s", (*pattr)->name,
					tgtt->name);
				goto out;
			}
			pattr++;
		}
	}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (tgtt->trace_flags != NULL) {
		retval = sysfs_create_file(&tgtt->tgtt_kobj,
				&tgtt_trace_attr.attr);
		if (retval != 0) {
			PRINT_ERROR("Can't add trace_flag for target "
				"driver %s", tgtt->name);
			goto out;
		}
	}
#endif

out:
	TRACE_EXIT_RES(retval);
	return retval;
}

void scst_tgtt_sysfs_put(struct scst_tgt_template *tgtt)
{
	TRACE_ENTRY();

	if (tgtt->tgtt_kobj_initialized) {
		int rc;

		kobject_del(&tgtt->tgtt_kobj);
		kobject_put(&tgtt->tgtt_kobj);

		rc = wait_for_completion_timeout(&tgtt->tgtt_kobj_release_cmpl, HZ);
		if (rc == 0) {
			PRINT_INFO("Waiting for releasing sysfs entry "
				"for target template %s...", tgtt->name);
			wait_for_completion(&tgtt->tgtt_kobj_release_cmpl);
			PRINT_INFO("Done waiting for releasing sysfs "
				"entry for target template %s", tgtt->name);
		}
	} else
		scst_tgtt_cleanup(tgtt);

	TRACE_EXIT();
	return;
}

/*
 * Target directory implementation
 */

static void scst_tgt_release(struct kobject *kobj)
{
	struct scst_tgt *tgt;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	scst_free_tgt(tgt);

	TRACE_EXIT();
	return;
}

static struct kobj_type tgt_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_tgt_release,
};

static struct kobj_attribute scst_luns_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_luns_mgmt_show,
	       scst_luns_mgmt_store);

static ssize_t scst_tgt_enable_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *tgt;
	int res;
	bool enabled;

	TRACE_ENTRY();

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	enabled = tgt->tgtt->is_tgt_enabled(tgt);

	res = sprintf(buf, "%d\n", enabled ? 1 : 0);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_tgt_enable_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_tgt *tgt;

	TRACE_ENTRY();

	if (buf == NULL)
		goto out_err;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	res = tgt->tgtt->enable_tgt(tgt, buf, count);

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	PRINT_ERROR("%s: Requested action not understood: %s", __func__, buf);
	res = -EINVAL;
	goto out;
}

static struct kobj_attribute tgt_enable_attr =
	__ATTR(enabled, S_IRUGO | S_IWUSR,
	       scst_tgt_enable_show, scst_tgt_enable_store);

int scst_create_tgt_sysfs(struct scst_tgt *tgt)
{
	int retval;
	const struct attribute **pattr;

	TRACE_ENTRY();

	tgt->tgt_kobj_initialized = 1;

	retval = kobject_init_and_add(&tgt->tgt_kobj, &tgt_ktype,
			&tgt->tgtt->tgtt_kobj, tgt->tgt_name);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgt %s to sysfs", tgt->tgt_name);
		goto out;
	}

	/*
	 * In case of errors there's no need for additional cleanup, because
	 * it will be done by the _put function() called by the caller.
	 */

	if ((tgt->tgtt->enable_tgt != NULL) &&
	    (tgt->tgtt->is_tgt_enabled != NULL)) {
		retval = sysfs_create_file(&tgt->tgt_kobj,
				&tgt_enable_attr.attr);
		if (retval != 0) {
			PRINT_ERROR("Can't add attr %s to sysfs",
				tgt_enable_attr.attr.name);
			goto out;
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

	retval = sysfs_create_file(tgt->tgt_luns_kobj, &scst_luns_mgmt.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_luns_mgmt.attr.name, tgt->tgt_name);
		goto out;
	}

	tgt->tgt_ini_grp_kobj = kobject_create_and_add("ini_group",
					&tgt->tgt_kobj);
	if (tgt->tgt_ini_grp_kobj == NULL) {
		PRINT_ERROR("Can't create ini_grp kobj for tgt %s",
			tgt->tgt_name);
		goto out_nomem;
	}

	pattr = tgt->tgtt->tgt_attrs;
	if (pattr != NULL) {
		while (*pattr != NULL) {
			TRACE_DBG("Creating attr %s for tgt %s", (*pattr)->name,
				tgt->tgt_name);
			retval = sysfs_create_file(&tgt->tgt_kobj, *pattr);
			if (retval != 0) {
				PRINT_ERROR("Can't add tgt attr %s for tgt %s",
					(*pattr)->name, tgt->tgt_name);
				goto out;
			}
			pattr++;
		}
	}

out:
	TRACE_EXIT_RES(retval);
	return retval;

out_nomem:
	retval = -ENOMEM;
	goto out;
}

void scst_tgt_sysfs_put(struct scst_tgt *tgt)
{
	if (tgt->tgt_kobj_initialized) {
		kobject_del(tgt->tgt_sess_kobj);
		kobject_put(tgt->tgt_sess_kobj);

		sysfs_remove_file(tgt->tgt_luns_kobj, &scst_luns_mgmt.attr);

		kobject_del(tgt->tgt_luns_kobj);
		kobject_put(tgt->tgt_luns_kobj);

		kobject_del(tgt->tgt_ini_grp_kobj);
		kobject_put(tgt->tgt_ini_grp_kobj);

		kobject_del(&tgt->tgt_kobj);
		kobject_put(&tgt->tgt_kobj);
	} else
		scst_free_tgt(tgt);
	return;
}

/*
 * Devices directory implementation
 */

ssize_t scst_device_sysfs_type_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	int pos = 0;

	struct scst_device *dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);

	pos = sprintf(buf, "%d - %s\n", dev->type,
		(unsigned)dev->type > ARRAY_SIZE(scst_dev_handler_types) ?
		      "unknown" : scst_dev_handler_types[dev->type]);

	return pos;
}

static struct kobj_attribute device_type_attr =
	__ATTR(type, S_IRUGO, scst_device_sysfs_type_show, NULL);

static struct attribute *scst_device_attrs[] = {
	&device_type_attr.attr,
	NULL,
};

static void scst_sysfs_device_release(struct kobject *kobj)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	scst_free_device(dev);

	TRACE_EXIT();
	return;
}

int scst_create_devt_dev_sysfs(struct scst_device *dev)
{
	int retval = 0;
	const struct attribute **pattr;

	TRACE_ENTRY();

	if (dev->handler == &scst_null_devtype)
		goto out;

	sBUG_ON(!dev->handler->devt_kobj_initialized);

	/*
	 * In case of errors there's no need for additional cleanup, because
	 * it will be done by the _put function() called by the caller.
	 */

	retval = sysfs_create_link(&dev->dev_kobj,
			&dev->handler->devt_kobj, "handler");
	if (retval != 0) {
		PRINT_ERROR("Can't create handler link for dev %s",
			dev->virt_name);
		goto out;
	}

	pattr = dev->handler->dev_attrs;
	if (pattr != NULL) {
		while (*pattr != NULL) {
			retval = sysfs_create_file(&dev->dev_kobj, *pattr);
			if (retval != 0) {
				PRINT_ERROR("Can't add dev attr %s for dev %s",
					(*pattr)->name, dev->virt_name);
				goto out;
			}
			pattr++;
		}
	}

out:
	TRACE_EXIT_RES(retval);
	return retval;
}

void scst_devt_dev_sysfs_put(struct scst_device *dev)
{
	const struct attribute **pattr;

	TRACE_ENTRY();

	if (dev->handler == &scst_null_devtype)
		goto out;

	sBUG_ON(!dev->handler->devt_kobj_initialized);

	pattr = dev->handler->dev_attrs;
	if (pattr != NULL) {
		while (*pattr != NULL) {
			sysfs_remove_file(&dev->dev_kobj, *pattr);
			pattr++;
		}
	}

	sysfs_remove_link(&dev->dev_kobj, "handler");

out:
	TRACE_EXIT();
	return;
}

static struct kobj_type scst_device_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_device_release,
	.default_attrs = scst_device_attrs,
};

int scst_create_device_sysfs(struct scst_device *dev)
{
	int retval = 0;

	TRACE_ENTRY();

	dev->dev_kobj_initialized = 1;

	retval = kobject_init_and_add(&dev->dev_kobj, &scst_device_ktype,
				      scst_devices_kobj, dev->virt_name);
	if (retval != 0) {
		PRINT_ERROR("Can't add device %s to sysfs", dev->virt_name);
		goto out;
	}

	/*
	 * In case of errors there's no need for additional cleanup, because
	 * it will be done by the _put function() called by the caller.
	 */

	dev->dev_exp_kobj = kobject_create_and_add("exported",
						   &dev->dev_kobj);
	if (dev->dev_exp_kobj == NULL) {
		PRINT_ERROR("Can't create exported link for device %s",
			dev->virt_name);
		retval = -ENOMEM;
		goto out;
	}

	if (dev->scsi_dev != NULL) {
		retval = sysfs_create_link(&dev->dev_kobj,
			&dev->scsi_dev->sdev_dev.kobj, "scsi_device");
		if (retval != 0) {
			PRINT_ERROR("Can't create scsi_device link for dev %s",
				dev->virt_name);
			goto out;
		}
	}

out:
	TRACE_EXIT_RES(retval);
	return retval;
}

void scst_device_sysfs_put(struct scst_device *dev)
{
	TRACE_ENTRY();

	if (dev->dev_kobj_initialized) {
		if (dev->dev_exp_kobj != NULL) {
			kobject_del(dev->dev_exp_kobj);
			kobject_put(dev->dev_exp_kobj);
		}
		kobject_del(&dev->dev_kobj);
		kobject_put(&dev->dev_kobj);
	} else
		scst_free_device(dev);

	TRACE_EXIT();
	return;
}

/*
 * Target sessions directory implementation
 */

ssize_t scst_sess_sysfs_commands_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	return sprintf(buf, "%i\n", atomic_read(&sess->sess_cmd_count));
}

static struct kobj_attribute session_commands_attr =
	__ATTR(commands, S_IRUGO, scst_sess_sysfs_commands_show, NULL);

static struct attribute *scst_session_attrs[] = {
	&session_commands_attr.attr,
	NULL,
};

static void scst_sysfs_session_release(struct kobject *kobj)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	sess = container_of(kobj, struct scst_session, sess_kobj);

	scst_release_session(sess);

	TRACE_EXIT();
	return;
}

static struct kobj_type scst_session_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_session_release,
	.default_attrs = scst_session_attrs,
};

int scst_create_sess_sysfs(struct scst_session *sess)
{
	int retval = 0;
	const struct attribute **pattr;

	TRACE_ENTRY();

	sess->sess_kobj_initialized = 1;

	retval = kobject_init_and_add(&sess->sess_kobj, &scst_session_ktype,
			      sess->tgt->tgt_sess_kobj, sess->initiator_name);
	if (retval != 0) {
		PRINT_ERROR("Can't add session %s to sysfs",
			    sess->initiator_name);
		goto out;
	}

	/*
	 * In case of errors there's no need for additional cleanup, because
	 * it will be done by the _put function() called by the caller.
	 */

	pattr = sess->tgt->tgtt->sess_attrs;
	if (pattr != NULL) {
		while (*pattr != NULL) {
			retval = sysfs_create_file(&sess->sess_kobj, *pattr);
			if (retval != 0) {
				PRINT_ERROR("Can't add sess attr %s for sess "
					"for initiator %s", (*pattr)->name,
					sess->initiator_name);
				goto out;
			}
			pattr++;
		}
	}

out:
	TRACE_EXIT_RES(retval);
	return retval;
}

void scst_sess_sysfs_put(struct scst_session *sess)
{
	TRACE_ENTRY();

	if (sess->sess_kobj_initialized) {
		kobject_del(&sess->sess_kobj);
		kobject_put(&sess->sess_kobj);
	} else
		scst_release_session(sess);

	TRACE_EXIT();
	return;
}

/*
 * Target luns directory implementation
 */

static void scst_acg_dev_release(struct kobject *kobj)
{
	struct scst_acg_dev *acg_dev;

	TRACE_ENTRY();

	acg_dev = container_of(kobj, struct scst_acg_dev, acg_dev_kobj);

	scst_acg_dev_destroy(acg_dev);

	TRACE_EXIT();
	return;
}

static ssize_t scst_lun_rd_only_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	struct scst_acg_dev *acg_dev;

	acg_dev = container_of(kobj, struct scst_acg_dev, acg_dev_kobj);

	return sprintf(buf, "%d\n",
		(acg_dev->rd_only || acg_dev->dev->rd_only) ? 1 : 0);
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

int scst_create_acg_dev_sysfs(struct scst_acg *acg, unsigned int virt_lun,
	struct kobject *parent)
{
	int retval;
	struct scst_acg_dev *acg_dev = NULL, *acg_dev_tmp;
	char str[10];

	TRACE_ENTRY();

	list_for_each_entry(acg_dev_tmp, &acg->acg_dev_list,
			    acg_dev_list_entry) {
		if (acg_dev_tmp->lun == virt_lun) {
			acg_dev = acg_dev_tmp;
			break;
		}
	}
	if (acg_dev == NULL) {
		PRINT_ERROR("%s", "acg_dev lookup for kobject creation failed");
		retval = -EINVAL;
		goto out;
	}

	snprintf(str, sizeof(str), "%u", acg_dev->dev->dev_exported_lun_num++);

	acg_dev->acg_dev_kobj_initialized = 1;

	retval = kobject_init_and_add(&acg_dev->acg_dev_kobj, &acg_dev_ktype,
				      parent, "%u", virt_lun);
	if (retval != 0) {
		PRINT_ERROR("Can't add acg %s to sysfs", acg->acg_name);
		goto out;
	}

	/*
	 * In case of errors there's no need for additional cleanup, because
	 * it will be done by the _put function() called by the caller.
	 */

	retval = sysfs_create_link(acg_dev->dev->dev_exp_kobj,
				   &acg_dev->acg_dev_kobj, str);
	if (retval != 0) {
		PRINT_ERROR("Can't create acg %s LUN link", acg->acg_name);
		goto out;
	}

	retval = sysfs_create_link(&acg_dev->acg_dev_kobj,
			&acg_dev->dev->dev_kobj, "device");
	if (retval != 0) {
		PRINT_ERROR("Can't create acg %s device link", acg->acg_name);
		goto out;
	}

out:
	return retval;
}

static ssize_t scst_luns_mgmt_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	static char *help = "Usage: echo \"add|del H:C:I:L lun [READ_ONLY]\" "
					">mgmt\n"
			    "       echo \"add|del VNAME lun [READ_ONLY]\" "
					">mgmt\n";

	return sprintf(buf, help);
}

static ssize_t scst_luns_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res, virt = 0, read_only = 0, action;
	char *buffer, *p, *e = NULL;
	unsigned int host, channel = 0, id = 0, lun = 0, virt_lun;
	struct scst_acg *acg;
	struct scst_acg_dev *acg_dev = NULL, *acg_dev_tmp;
	struct scst_device *d, *dev = NULL;
	struct scst_tgt *tgt;

#define SCST_LUN_ACTION_ADD	1
#define SCST_LUN_ACTION_DEL	2
#define SCST_LUN_ACTION_REPLACE	3

	TRACE_ENTRY();

	tgt = container_of(kobj->parent, struct scst_tgt, tgt_kobj);
	acg = tgt->default_acg;

	buffer = kzalloc(count+1, GFP_KERNEL);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	memcpy(buffer, buf, count);
	buffer[count] = '\0';
	p = buffer;

	p = buffer;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (strncasecmp("add", p, 3) == 0) {
		p += 3;
		action = SCST_LUN_ACTION_ADD;
	} else if (strncasecmp("del", p, 3) == 0) {
		p += 3;
		action = SCST_LUN_ACTION_DEL;
	} else if (!strncasecmp("replace", p, 7)) {
		p += 7;
		action = SCST_LUN_ACTION_REPLACE;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	if (!isspace(*p)) {
		PRINT_ERROR("%s", "Syntax error");
		res = -EINVAL;
		goto out_free;
	}

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out_free;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_free_resume;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	e = p; /* save p */
	host = simple_strtoul(p, &p, 0);
	if (*p == ':') {
		channel = simple_strtoul(p + 1, &p, 0);
		id = simple_strtoul(p + 1, &p, 0);
		lun = simple_strtoul(p + 1, &p, 0);
		e = p;
	} else {
		virt++;
		p = e; /* restore p */
		while (!isspace(*e) && *e != '\0')
			e++;
		*e = '\0';
	}

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if (virt) {
			if (d->virt_id && !strcmp(d->virt_name, p)) {
				dev = d;
				TRACE_DBG("Virt device %p (%s) found",
					  dev, p);
				break;
			}
		} else {
			if (d->scsi_dev &&
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
	}
	if (dev == NULL) {
		if (virt) {
			PRINT_ERROR("Virt device %s not found", p);
		} else {
			PRINT_ERROR("Device %d:%d:%d:%d not found",
				    host, channel, id, lun);
		}
		res = -EINVAL;
		goto out_free_up;
	}

	switch (action) {
	case SCST_LUN_ACTION_ADD:
	case SCST_LUN_ACTION_REPLACE:
	{
		bool dev_replaced = false;

		e++;
		while (isspace(*e) && *e != '\0')
			e++;
		virt_lun = simple_strtoul(e, &e, 0);

		while (isspace(*e) && *e != '\0')
			e++;

		if (*e != '\0') {
			if ((strncasecmp("READ_ONLY", e, 9) == 0) &&
			    (isspace(e[9]) || (e[9] == '\0')))
				read_only = 1;
			else {
				PRINT_ERROR("Unknown option \"%s\"", e);
				res = -EINVAL;
				goto out_free_up;
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
				PRINT_ERROR("virt lun %d already exists in "
					"group %s", virt_lun, acg->acg_name);
				res = -EINVAL;
				goto out_free_up;
			} else {
				/* Replace */
				res = scst_acg_remove_dev(acg, acg_dev->dev,
						false);
				if (res != 0)
					goto out_free_up;

				dev_replaced = true;
			}
		}

		res = scst_acg_add_dev(acg, dev, virt_lun, read_only,
					!dev_replaced);
		if (res != 0)
			goto out_free_up;

		res = scst_create_acg_dev_sysfs(acg, virt_lun, kobj);
		if (res != 0) {
			PRINT_ERROR("%s", "Creation of acg_dev kobject failed");
			goto out_remove_acg_dev;
		}

		if (dev_replaced) {
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
					dev_tgt_dev_list_entry) {
				if ((tgt_dev->acg_dev->acg == acg) &&
				    (tgt_dev->lun == virt_lun)) {
					TRACE_MGMT_DBG("INQUIRY DATA HAS CHANGED"
						" on tgt_dev %p", tgt_dev);
					scst_gen_aen_or_ua(tgt_dev,
						SCST_LOAD_SENSE(scst_sense_inquery_data_changed));
				}
			}
		}

		break;
	}
	case SCST_LUN_ACTION_DEL:
		res = scst_acg_remove_dev(acg, dev, true);
		if (res != 0)
			goto out_free_up;
		break;
	}

	res = count;

out_free_up:
	mutex_unlock(&scst_mutex);

out_free_resume:
	scst_resume_activity();

out_free:
	kfree(buffer);

out:
	TRACE_EXIT_RES(res);
	return res;

out_remove_acg_dev:
	scst_acg_remove_dev(acg, dev, true);
	goto out_free_up;

#undef SCST_LUN_ACTION_ADD
#undef SCST_LUN_ACTION_DEL
#undef SCST_LUN_ACTION_REPLACE
}

/*
 * SGV directory implementation
 */

static struct kobj_attribute sgv_stat_attr =
	__ATTR(stats, S_IRUGO | S_IWUSR, sgv_sysfs_stat_show,
		sgv_sysfs_stat_reset);

static struct attribute *sgv_attrs[] = {
	&sgv_stat_attr.attr,
	NULL,
};

static void sgv_kobj_release(struct kobject *kobj)
{
	struct sgv_pool *pool;

	TRACE_ENTRY();

	pool = container_of(kobj, struct sgv_pool, sgv_kobj);

	sgv_pool_destroy(pool);

	TRACE_EXIT();
	return;
}

static struct kobj_type sgv_pool_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = sgv_kobj_release,
	.default_attrs = sgv_attrs,
};

int scst_create_sgv_sysfs(struct sgv_pool *pool)
{
	int retval;

	TRACE_ENTRY();

	pool->sgv_kobj_initialized = 1;

	retval = kobject_init_and_add(&pool->sgv_kobj, &sgv_pool_ktype,
			scst_sgv_kobj, pool->name);
	if (retval != 0) {
		PRINT_ERROR("Can't add sgv pool %s to sysfs", pool->name);
		goto out;
	}

out:
	TRACE_EXIT_RES(retval);
	return retval;
}

/* pool can be dead upon exit from this function! */
void scst_sgv_sysfs_put(struct sgv_pool *pool)
{
	if (pool->sgv_kobj_initialized) {
		kobject_del(&pool->sgv_kobj);
		kobject_put(&pool->sgv_kobj);
	} else
		sgv_pool_destroy(pool);
	return;
}

static struct kobj_attribute sgv_global_stat_attr =
	__ATTR(global_stats, S_IRUGO | S_IWUSR, sgv_sysfs_global_stat_show,
		sgv_sysfs_global_stat_reset);

static struct attribute *sgv_default_attrs[] = {
	&sgv_global_stat_attr.attr,
	NULL,
};

static struct kobj_type sgv_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_release,
	.default_attrs = sgv_default_attrs,
};

/*
 * SCST sysfs root directory implementation
 */

static ssize_t scst_threads_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int count;

	TRACE_ENTRY();

	count = sprintf(buf, "%d\n", scst_global_threads_count());

	TRACE_EXIT();
	return count;
}

static ssize_t scst_threads_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res = count;
	int oldtn, newtn, delta;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_sysfs_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	mutex_lock(&scst_global_threads_mutex);

	oldtn = scst_nr_global_threads;
	sscanf(buf, "%du", &newtn);

	if (newtn <= 0) {
		PRINT_ERROR("Illegal threads num value %d", newtn);
		res = -EINVAL;
		goto out_up_thr_free;
	}
	delta = newtn - oldtn;
	if (delta < 0)
		__scst_del_global_threads(-delta);
	else
		__scst_add_global_threads(delta);

	PRINT_INFO("Changed cmd threads num: old %d, new %d", oldtn, newtn);

out_up_thr_free:
	mutex_unlock(&scst_global_threads_mutex);

	mutex_unlock(&scst_sysfs_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

static void scst_read_trace_tlb(const struct scst_trace_log *tbl, char *buf,
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

	scst_read_trace_tlb(scst_trace_tbl, buf, log_level, &pos);
	scst_read_trace_tlb(local_tbl, buf, log_level, &pos);

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
		"		       mgmt_minor, mgmt_dbg, scsi_serializing,\n"
		"		       retry, recv_bot, send_bot, recv_top,\n"
		"		       send_top%s]", help != NULL ? help : "");

	return pos;
}

static ssize_t scst_main_trace_level_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return scst_trace_level_show(scst_local_trace_tbl, trace_flag,
			buf, NULL);
}

static int scst_write_trace(const char *buf, size_t length,
	unsigned long *log_level, unsigned long default_level,
	const char *name, const struct scst_trace_log *tbl)
{
	int res = length;
	int action;
	unsigned long level = 0, oldlevel;
	char *buffer, *p, *e;
	const struct scst_trace_log *t;

#define SCST_TRACE_ACTION_ALL		1
#define SCST_TRACE_ACTION_NONE		2
#define SCST_TRACE_ACTION_DEFAULT	3
#define SCST_TRACE_ACTION_ADD		4
#define SCST_TRACE_ACTION_DEL		5
#define SCST_TRACE_ACTION_VALUE		6

	TRACE_ENTRY();

	if ((buf == NULL) || (length == 0)) {
		res = -EINVAL;
		goto out;
	}

	buffer = kmalloc(length+1, GFP_KERNEL);
	if (buffer == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer (size %zd)",
			length+1);
		res = -ENOMEM;
		goto out;
	}
	memcpy(buffer, buf, length);
	buffer[length] = '\0';

	p = buffer;
	if (!strncasecmp("all", p, 3)) {
		action = SCST_TRACE_ACTION_ALL;
	} else if (!strncasecmp("none", p, 4) || !strncasecmp("null", p, 4)) {
		action = SCST_TRACE_ACTION_NONE;
	} else if (!strncasecmp("default", p, 7)) {
		action = SCST_TRACE_ACTION_DEFAULT;
	} else if (!strncasecmp("add", p, 3)) {
		p += 3;
		action = SCST_TRACE_ACTION_ADD;
	} else if (!strncasecmp("del", p, 3)) {
		p += 3;
		action = SCST_TRACE_ACTION_DEL;
	} else if (!strncasecmp("value", p, 5)) {
		p += 5;
		action = SCST_TRACE_ACTION_VALUE;
	} else {
		if (p[strlen(p) - 1] == '\n')
			p[strlen(p) - 1] = '\0';
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	switch (action) {
	case SCST_TRACE_ACTION_ADD:
	case SCST_TRACE_ACTION_DEL:
	case SCST_TRACE_ACTION_VALUE:
		if (!isspace(*p)) {
			PRINT_ERROR("%s", "Syntax error");
			res = -EINVAL;
			goto out_free;
		}
	}

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
		while (isspace(*p) && *p != '\0')
			p++;
		e = p;
		while (!isspace(*e) && *e != '\0')
			e++;
		*e = 0;
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
		while (isspace(*p) && *p != '\0')
			p++;
		res = strict_strtoul(p, 0, &level);
		if (res != 0) {
			PRINT_ERROR("Invalud trace value \"%s\"", p);
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

out_free:
	kfree(buffer);
out:
	TRACE_EXIT_RES(res);
	return res;

#undef SCST_TRACE_ACTION_ALL
#undef SCST_TRACE_ACTION_NONE
#undef SCST_TRACE_ACTION_DEFAULT
#undef SCST_TRACE_ACTION_ADD
#undef SCST_TRACE_ACTION_DEL
#undef SCST_TRACE_ACTION_VALUE
}

static ssize_t scst_main_trace_level_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_log_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	res = scst_write_trace(buf, count, &trace_flag,
		SCST_DEFAULT_LOG_FLAGS, "scst", scst_local_trace_tbl);

	mutex_unlock(&scst_log_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

static ssize_t scst_version_show(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	TRACE_ENTRY();

	sprintf(buf, "%s\n", SCST_VERSION_STRING);

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	strcat(buf, "Strict serializing enabled\n");
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

#ifdef CONFIG_SCST_ALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ
	strcat(buf, "ALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ\n");
#endif

#ifdef CONFIG_SCST_STRICT_SECURITY
	strcat(buf, "SCST_STRICT_SECURITY\n");
#endif

	TRACE_EXIT();
	return strlen(buf);
}

static struct kobj_attribute scst_threads_attr =
	__ATTR(threads, S_IRUGO | S_IWUSR, scst_threads_show,
	       scst_threads_store);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static struct kobj_attribute scst_trace_level_attr =
	__ATTR(trace_level, S_IRUGO | S_IWUSR, scst_main_trace_level_show,
	       scst_main_trace_level_store);
#endif

static struct kobj_attribute scst_version_attr =
	__ATTR(version, S_IRUGO, scst_version_show, NULL);

static struct attribute *scst_sysfs_root_default_attrs[] = {
	&scst_threads_attr.attr,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	&scst_trace_level_attr.attr,
#endif
	&scst_version_attr.attr,
	NULL,
};

static void scst_sysfs_root_release(struct kobject *kobj)
{
	complete_all(&scst_sysfs_root_release_completion);
}

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

	return kobj_attr->store(kobj, kobj_attr, buf, count);
}

struct sysfs_ops scst_sysfs_ops = {
	.show = scst_show,
	.store = scst_store,
};

static struct kobj_type scst_sysfs_root_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_sysfs_root_release,
	.default_attrs = scst_sysfs_root_default_attrs,
};

static void scst_devt_free(struct kobject *kobj)
{
	struct scst_dev_type *devt;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	complete_all(&devt->devt_kobj_release_compl);

	scst_devt_cleanup(devt);

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

	if (mutex_lock_interruptible(&scst_log_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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
		(unsigned)devt->type > ARRAY_SIZE(scst_dev_handler_types) ?
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
	.release = scst_devt_free,
	.default_attrs = scst_devt_default_attrs,
};

int scst_create_devt_sysfs(struct scst_dev_type *devt)
{
	int retval;
	struct kobject *parent;
	const struct attribute **pattr;

	TRACE_ENTRY();

	init_completion(&devt->devt_kobj_release_compl);

	if (devt->parent != NULL)
		parent = &devt->parent->devt_kobj;
	else
		parent = scst_handlers_kobj;

	devt->devt_kobj_initialized = 1;

	retval = kobject_init_and_add(&devt->devt_kobj, &scst_devt_ktype,
			parent, devt->name);
	if (retval != 0) {
		PRINT_ERROR("Can't add devt %s to sysfs", devt->name);
		goto out;
	}

	/*
	 * In case of errors there's no need for additional cleanup, because
	 * it will be done by the _put function() called by the caller.
	 */

	pattr = devt->devt_attrs;
	if (pattr != NULL) {
		while (*pattr != NULL) {
			retval = sysfs_create_file(&devt->devt_kobj, *pattr);
			if (retval != 0) {
				PRINT_ERROR("Can't add devt attr %s for dev "
					"handler %s", (*pattr)->name,
					devt->name);
				goto out;
			}
			pattr++;
		}
	}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	if (devt->trace_flags != NULL) {
		retval = sysfs_create_file(&devt->devt_kobj,
				&devt_trace_attr.attr);
		if (retval != 0) {
			PRINT_ERROR("Can't add devt trace_flag for dev "
				"handler %s", devt->name);
			goto out;
		}
	}
#endif

out:
	TRACE_EXIT_RES(retval);
	return retval;
}

void scst_devt_sysfs_put(struct scst_dev_type *devt)
{
	TRACE_ENTRY();

	if (devt->devt_kobj_initialized) {
		int rc;

		kobject_del(&devt->devt_kobj);
		kobject_put(&devt->devt_kobj);

		rc = wait_for_completion_timeout(&devt->devt_kobj_release_compl, HZ);
		if (rc == 0) {
			PRINT_INFO("Waiting for releasing sysfs entry "
				"for dev handler template %s...", devt->name);
			wait_for_completion(&devt->devt_kobj_release_compl);
			PRINT_INFO("Done waiting for releasing sysfs entry "
				"for dev handler template %s", devt->name);
		}
	} else
		scst_devt_cleanup(devt);

	TRACE_EXIT();
	return;
}

int __init scst_sysfs_init(void)
{
	int retval = 0;

	TRACE_ENTRY();

	retval = kobject_init_and_add(&scst_sysfs_root_kobj,
			&scst_sysfs_root_ktype, kernel_kobj, "%s", "scst_tgt");
	if (retval != 0)
		goto sysfs_root_add_error;

	scst_targets_kobj = kobject_create_and_add("targets",
				&scst_sysfs_root_kobj);
	if (scst_targets_kobj == NULL)
		goto targets_kobj_error;

	scst_devices_kobj = kobject_create_and_add("devices",
				&scst_sysfs_root_kobj);
	if (scst_devices_kobj == NULL)
		goto devices_kobj_error;

	scst_sgv_kobj = kzalloc(sizeof(*scst_sgv_kobj), GFP_KERNEL);
	if (scst_sgv_kobj == NULL)
		goto sgv_kobj_error;

	retval = kobject_init_and_add(scst_sgv_kobj, &sgv_ktype,
			&scst_sysfs_root_kobj, "%s", "sgv");
	if (retval != 0)
		goto sgv_kobj_add_error;

	scst_handlers_kobj = kobject_create_and_add("handlers",
					&scst_sysfs_root_kobj);
	if (scst_handlers_kobj == NULL)
		goto handlers_kobj_error;

out:
	TRACE_EXIT_RES(retval);
	return retval;

handlers_kobj_error:
	kobject_del(scst_sgv_kobj);

sgv_kobj_add_error:
	kobject_put(scst_sgv_kobj);

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

	if (retval == 0)
		retval = -EINVAL;
	goto out;
}

void __exit scst_sysfs_cleanup(void)
{
	TRACE_ENTRY();

	PRINT_INFO("%s", "Exiting SCST sysfs hierarchy...");

	kobject_del(scst_sgv_kobj);
	kobject_put(scst_sgv_kobj);

	kobject_del(scst_devices_kobj);
	kobject_put(scst_devices_kobj);

	kobject_del(scst_targets_kobj);
	kobject_put(scst_targets_kobj);

	kobject_del(scst_handlers_kobj);
	kobject_put(scst_handlers_kobj);

	kobject_del(&scst_sysfs_root_kobj);
	kobject_put(&scst_sysfs_root_kobj);

	wait_for_completion(&scst_sysfs_root_release_completion);

	PRINT_INFO("%s", "Exiting SCST sysfs hierarchy done");

	TRACE_EXIT();
	return;
}
