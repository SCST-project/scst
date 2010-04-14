/*
 *  scst_sysfs.c
 *
 *  Copyright (C) 2009 Daniel Henrique Debonzi <debonzi@linux.vnet.ibm.com>
 *  Copyright (C) 2009 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2009 - 2010 ID7 Ltd.
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

static DECLARE_COMPLETION(scst_sysfs_root_release_completion);

static struct kobject scst_sysfs_root_kobj;
static struct kobject *scst_targets_kobj;
static struct kobject *scst_devices_kobj;
static struct kobject *scst_sgv_kobj;
static struct kobject *scst_handlers_kobj;

/* Regular SCST sysfs operations */
struct sysfs_ops scst_sysfs_ops;
EXPORT_SYMBOL(scst_sysfs_ops);

static const char *scst_dev_handler_types[] = {
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
    { TRACE_MGMT_DEBUG,		"mgmt_dbg" },
    { TRACE_FLOW_CONTROL,	"flow_control" },
    { 0,			NULL }
};

static struct scst_trace_log scst_local_trace_tbl[] = {
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
static ssize_t scst_tgt_addr_method_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_tgt_addr_method_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_tgt_io_grouping_type_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_tgt_io_grouping_type_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_ini_group_mgmt_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_ini_group_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_rel_tgt_id_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_rel_tgt_id_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_acg_luns_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_acg_ini_mgmt_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_acg_ini_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_acg_addr_method_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_acg_addr_method_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_acg_io_grouping_type_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
static ssize_t scst_acg_io_grouping_type_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
static ssize_t scst_acn_file_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);

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

static ssize_t scst_tgtt_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	char *help = "Usage: echo \"add_target target_name [parameters]\" "
				">mgmt\n"
		     "       echo \"del_target target_name\" >mgmt\n"
		     "%s"
		     "\n"
		     "where parameters are one or more "
		     "param_name=value pairs separated by ';'\n"
		     "%s%s";
	struct scst_tgt_template *tgtt;

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	if (tgtt->add_target_parameters_help != NULL)
		return sprintf(buf, help,
			(tgtt->mgmt_cmd_help) ? tgtt->mgmt_cmd_help : "",
			"\nThe following parameters available: ",
			tgtt->add_target_parameters_help);
	else
		return sprintf(buf, help,
			(tgtt->mgmt_cmd_help) ? tgtt->mgmt_cmd_help : "",
			"", "");
}

static ssize_t scst_tgtt_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res;
	char *buffer, *p, *pp, *target_name;
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	tgtt = container_of(kobj, struct scst_tgt_template, tgtt_kobj);

	buffer = kzalloc(count+1, GFP_KERNEL);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	memcpy(buffer, buf, count);
	buffer[count] = '\0';

	pp = buffer;
	if (pp[strlen(pp) - 1] == '\n')
		pp[strlen(pp) - 1] = '\0';

	p = scst_get_next_lexem(&pp);

	if (strcasecmp("add_target", p) == 0) {
		target_name = scst_get_next_lexem(&pp);
		if (*target_name == '\0') {
			PRINT_ERROR("%s", "Target name required");
			res = -EINVAL;
			goto out_free;
		}
		res = tgtt->add_target(target_name, pp);
	} else if (strcasecmp("del_target", p) == 0) {
		target_name = scst_get_next_lexem(&pp);
		if (*target_name == '\0') {
			PRINT_ERROR("%s", "Target name required");
			res = -EINVAL;
			goto out_free;
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
		goto out_free;
	}

	if (res == 0)
		res = count;

out_free:
	kfree(buffer);

out:
	TRACE_EXIT_RES(res);
	return res;

out_syntax_err:
	PRINT_ERROR("Syntax error on \"%s\"", p);
	res = -EINVAL;
	goto out_free;
}

static struct kobj_attribute scst_tgtt_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_tgtt_mgmt_show,
	       scst_tgtt_mgmt_store);

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

	if (tgtt->add_target != NULL) {
		retval = sysfs_create_file(&tgtt->tgtt_kobj,
				&scst_tgtt_mgmt.attr);
		if (retval != 0) {
			PRINT_ERROR("Can't add mgmt attr for target driver %s",
				tgtt->name);
			goto out;
		}
	}

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

	/* Let's make lockdep happy */
	up_write(&tgt->tgt_attr_rwsem);

	scst_free_tgt(tgt);

	TRACE_EXIT();
	return;
}

static ssize_t scst_tgt_attr_show(struct kobject *kobj, struct attribute *attr,
	char *buf)
{
	int res;
	struct kobj_attribute *kobj_attr;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	if (down_read_trylock(&tgt->tgt_attr_rwsem) == 0) {
		res = -ENOENT;
		goto out;
	}

	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	res = kobj_attr->show(kobj, kobj_attr, buf);

	up_read(&tgt->tgt_attr_rwsem);

out:
	return res;
}

static ssize_t scst_tgt_attr_store(struct kobject *kobj,
	struct attribute *attr, const char *buf, size_t count)
{
	int res;
	struct kobj_attribute *kobj_attr;
	struct scst_tgt *tgt;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	if (down_read_trylock(&tgt->tgt_attr_rwsem) == 0) {
		res = -ENOENT;
		goto out;
	}

	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	if (kobj_attr->store)
		res = kobj_attr->store(kobj, kobj_attr, buf, count);
	else
		res = -EIO;

	up_read(&tgt->tgt_attr_rwsem);

out:
	return res;
}

static struct sysfs_ops scst_tgt_sysfs_ops = {
	.show = scst_tgt_attr_show,
	.store = scst_tgt_attr_store,
};

static struct kobj_type tgt_ktype = {
	.sysfs_ops = &scst_tgt_sysfs_ops,
	.release = scst_tgt_release,
};

static void scst_acg_release(struct kobject *kobj)
{
	struct scst_acg *acg;

	TRACE_ENTRY();

	acg = container_of(kobj, struct scst_acg, acg_kobj);

	scst_destroy_acg(acg);

	TRACE_EXIT();
	return;
}

static struct kobj_type acg_ktype = {
	.sysfs_ops = &scst_sysfs_ops,
	.release = scst_acg_release,
};

static struct kobj_attribute scst_luns_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_luns_mgmt_show,
	       scst_luns_mgmt_store);

static struct kobj_attribute scst_acg_luns_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_luns_mgmt_show,
	       scst_acg_luns_mgmt_store);

static struct kobj_attribute scst_acg_ini_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_acg_ini_mgmt_show,
	       scst_acg_ini_mgmt_store);

static struct kobj_attribute scst_ini_group_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_ini_group_mgmt_show,
	       scst_ini_group_mgmt_store);

static struct kobj_attribute scst_tgt_addr_method =
	__ATTR(addr_method, S_IRUGO | S_IWUSR, scst_tgt_addr_method_show,
	       scst_tgt_addr_method_store);

static struct kobj_attribute scst_tgt_io_grouping_type =
	__ATTR(io_grouping_type, S_IRUGO | S_IWUSR,
	       scst_tgt_io_grouping_type_show,
	       scst_tgt_io_grouping_type_store);

static struct kobj_attribute scst_rel_tgt_id =
	__ATTR(rel_tgt_id, S_IRUGO | S_IWUSR, scst_rel_tgt_id_show,
	       scst_rel_tgt_id_store);

static struct kobj_attribute scst_acg_addr_method =
	__ATTR(addr_method, S_IRUGO | S_IWUSR, scst_acg_addr_method_show,
		scst_acg_addr_method_store);

static struct kobj_attribute scst_acg_io_grouping_type =
	__ATTR(io_grouping_type, S_IRUGO | S_IWUSR,
	       scst_acg_io_grouping_type_show,
	       scst_acg_io_grouping_type_store);

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

static ssize_t scst_tgt_enable_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_tgt *tgt;
	bool enable;

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
		if (tgt->rel_tgt_id == 0) {
			res = gen_relative_target_port_id(&tgt->rel_tgt_id);
			if (res)
				goto out;
			PRINT_INFO("Using autogenerated rel ID %d for target "
				"%s", tgt->rel_tgt_id, tgt->tgt_name);
		} else {
			if (!scst_is_relative_target_port_id_unique(
			    tgt->rel_tgt_id, tgt)) {
				PRINT_ERROR("Relative port id %d is not unique",
					tgt->rel_tgt_id);
					res = -EBADSLT;
				goto out;
			}
		}
		enable = true;
		break;
	default:
		PRINT_ERROR("%s: Requested action not understood: %s",
		       __func__, buf);
		res = -EINVAL;
		goto out;
	}

	res = tgt->tgtt->enable_target(tgt, enable);
	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute tgt_enable_attr =
	__ATTR(enabled, S_IRUGO | S_IWUSR,
	       scst_tgt_enable_show, scst_tgt_enable_store);

int scst_create_tgt_sysfs(struct scst_tgt *tgt)
{
	int retval;
	const struct attribute **pattr;

	TRACE_ENTRY();

	init_rwsem(&tgt->tgt_attr_rwsem);

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

	if ((tgt->tgtt->enable_target != NULL) &&
	    (tgt->tgtt->is_target_enabled != NULL)) {
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

	tgt->tgt_ini_grp_kobj = kobject_create_and_add("ini_groups",
					&tgt->tgt_kobj);
	if (tgt->tgt_ini_grp_kobj == NULL) {
		PRINT_ERROR("Can't create ini_grp kobj for tgt %s",
			tgt->tgt_name);
		goto out_nomem;
	}

	retval = sysfs_create_file(tgt->tgt_ini_grp_kobj,
			&scst_ini_group_mgmt.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_ini_group_mgmt.attr.name, tgt->tgt_name);
		goto out;
	}

	retval = sysfs_create_file(&tgt->tgt_kobj,
			&scst_rel_tgt_id.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_rel_tgt_id.attr.name, tgt->tgt_name);
		goto out;
	}

	retval = sysfs_create_file(&tgt->tgt_kobj,
			&scst_tgt_addr_method.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_tgt_addr_method.attr.name, tgt->tgt_name);
		goto out;
	}

	retval = sysfs_create_file(&tgt->tgt_kobj,
			&scst_tgt_io_grouping_type.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add attribute %s for tgt %s",
			scst_tgt_io_grouping_type.attr.name, tgt->tgt_name);
		goto out;
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

/*
 * Must not be called under scst_mutex or there can be a deadlock with
 * tgt_attr_rwsem
 */
void scst_tgt_sysfs_prepare_put(struct scst_tgt *tgt)
{
	if (tgt->tgt_kobj_initialized) {
		down_write(&tgt->tgt_attr_rwsem);
		tgt->tgt_kobj_put_prepared = 1;
	}

	return;
}

/*
 * Must not be called under scst_mutex or there can be a deadlock with
 * tgt_attr_rwsem
 */
void scst_tgt_sysfs_put(struct scst_tgt *tgt)
{
	if (tgt->tgt_kobj_initialized) {
		kobject_del(tgt->tgt_sess_kobj);
		kobject_put(tgt->tgt_sess_kobj);

		kobject_del(tgt->tgt_luns_kobj);
		kobject_put(tgt->tgt_luns_kobj);

		kobject_del(tgt->tgt_ini_grp_kobj);
		kobject_put(tgt->tgt_ini_grp_kobj);

		kobject_del(&tgt->tgt_kobj);

		if (!tgt->tgt_kobj_put_prepared)
			down_write(&tgt->tgt_attr_rwsem);
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

static ssize_t scst_device_sysfs_threads_num_show(struct kobject *kobj,
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

static ssize_t scst_device_sysfs_threads_data_store(struct scst_device *dev,
	int threads_num, enum scst_dev_type_threads_pool_type threads_pool_type)
{
	int res = 0;

	TRACE_ENTRY();

	if (dev->threads_num < 0) {
		PRINT_ERROR("Threads pool disabled for device %s",
			dev->virt_name);
		res = -EPERM;
		goto out;
	}

	if ((threads_num == dev->threads_num) &&
	    (threads_pool_type == dev->threads_pool_type))
		goto out;

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_resume;
	}

	scst_stop_dev_threads(dev);

	dev->threads_num = threads_num;
	dev->threads_pool_type = threads_pool_type;

	res = scst_create_dev_threads(dev);
	if (res != 0)
		goto out_up;

out_up:
	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_device_sysfs_threads_num_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	long newtn;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	res = strict_strtoul(buf, 0, &newtn);
	if (res != 0) {
		PRINT_ERROR("strict_strtoul() for %s failed: %d ", buf, res);
		goto out;
	}

	if (newtn < 0) {
		PRINT_ERROR("Illegal threads num value %ld", newtn);
		res = -EINVAL;
		goto out;
	}

	res = scst_device_sysfs_threads_data_store(dev, newtn,
		dev->threads_pool_type);
	if (res != 0)
		goto out;

	PRINT_INFO("Changed cmd threads num to %ld", newtn);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute device_threads_num_attr =
	__ATTR(threads_num, S_IRUGO | S_IWUSR,
		scst_device_sysfs_threads_num_show,
		scst_device_sysfs_threads_num_store);

static ssize_t scst_device_sysfs_threads_pool_type_show(struct kobject *kobj,
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

static ssize_t scst_device_sysfs_threads_pool_type_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	enum scst_dev_type_threads_pool_type newtpt;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	newtpt = scst_parse_threads_pool_type(buf, count);
	if (newtpt == SCST_THREADS_POOL_TYPE_INVALID) {
		PRINT_ERROR("Illegal threads pool type %s", buf);
		res = -EINVAL;
		goto out;
	}

	TRACE_DBG("buf %s, count %zd, newtpt %d", buf, count, newtpt);

	res = scst_device_sysfs_threads_data_store(dev, dev->threads_num,
		newtpt);
	if (res != 0)
		goto out;

	PRINT_INFO("Changed cmd threads pool type to %d", newtpt);

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}


static struct kobj_attribute device_threads_pool_type_attr =
	__ATTR(threads_pool_type, S_IRUGO | S_IWUSR,
		scst_device_sysfs_threads_pool_type_show,
		scst_device_sysfs_threads_pool_type_store);

static struct attribute *scst_device_attrs[] = {
	&device_type_attr.attr,
	&device_threads_num_attr.attr,
	&device_threads_pool_type_attr.attr,
	NULL,
};

static void scst_sysfs_device_release(struct kobject *kobj)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);

	/* Let's make lockdep happy */
	up_write(&dev->dev_attr_rwsem);

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

	retval = sysfs_create_link(&dev->handler->devt_kobj,
			&dev->dev_kobj, dev->virt_name);
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
	sysfs_remove_link(&dev->handler->devt_kobj, dev->virt_name);

out:
	TRACE_EXIT();
	return;
}

static ssize_t scst_dev_attr_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	int res;
	struct kobj_attribute *kobj_attr;
	struct scst_device *dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);

	if (down_read_trylock(&dev->dev_attr_rwsem) == 0) {
		res = -ENOENT;
		goto out;
	}

	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	res = kobj_attr->show(kobj, kobj_attr, buf);

	up_read(&dev->dev_attr_rwsem);

out:
	return res;
}

static ssize_t scst_dev_attr_store(struct kobject *kobj, struct attribute *attr,
			  const char *buf, size_t count)
{
	int res;
	struct kobj_attribute *kobj_attr;
	struct scst_device *dev;

	dev = container_of(kobj, struct scst_device, dev_kobj);

	if (down_read_trylock(&dev->dev_attr_rwsem) == 0) {
		res = -ENOENT;
		goto out;
	}

	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	if (kobj_attr->store)
		res = kobj_attr->store(kobj, kobj_attr, buf, count);
	else
		res = -EIO;

	up_read(&dev->dev_attr_rwsem);

out:
	return res;
}

static struct sysfs_ops scst_dev_sysfs_ops = {
	.show = scst_dev_attr_show,
	.store = scst_dev_attr_store,
};

static struct kobj_type scst_device_ktype = {
	.sysfs_ops = &scst_dev_sysfs_ops,
	.release = scst_sysfs_device_release,
	.default_attrs = scst_device_attrs,
};

int scst_create_device_sysfs(struct scst_device *dev)
{
	int retval = 0;

	TRACE_ENTRY();

	init_rwsem(&dev->dev_attr_rwsem);

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

/*
 * Must not be called under scst_mutex or there can be a deadlock with
 * dev_attr_rwsem
 */
void scst_device_sysfs_put(struct scst_device *dev)
{
	TRACE_ENTRY();

	if (dev->dev_kobj_initialized) {
		kobject_del(dev->dev_exp_kobj);
		kobject_put(dev->dev_exp_kobj);

		kobject_del(&dev->dev_kobj);

		down_write(&dev->dev_attr_rwsem);
		kobject_put(&dev->dev_kobj);
	} else
		scst_free_device(dev);

	TRACE_EXIT();
	return;
}

/*
 * Target sessions directory implementation
 */

static ssize_t scst_sess_sysfs_commands_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	return sprintf(buf, "%i\n", atomic_read(&sess->sess_cmd_count));
}

static struct kobj_attribute session_commands_attr =
	__ATTR(commands, S_IRUGO, scst_sess_sysfs_commands_show, NULL);

static ssize_t scst_sess_sysfs_active_commands_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	int res;
	struct scst_session *sess;
	int active_cmds = 0, t;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	sess = container_of(kobj, struct scst_session, sess_kobj);

	for (t = TGT_DEV_HASH_SIZE-1; t >= 0; t--) {
		struct list_head *sess_tgt_dev_list_head =
			&sess->sess_tgt_dev_list_hash[t];
		struct scst_tgt_dev *tgt_dev;
		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			active_cmds += atomic_read(&tgt_dev->tgt_dev_cmd_count);
		}
	}

	mutex_unlock(&scst_mutex);

	res = sprintf(buf, "%i\n", active_cmds);

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
	__ATTR(initiator_name, S_IRUGO, scst_sess_sysfs_initiator_name_show, NULL);

static struct attribute *scst_session_attrs[] = {
	&session_commands_attr.attr,
	&session_active_commands_attr.attr,
	&session_initiator_name_attr.attr,
	NULL,
};

static void scst_sysfs_session_release(struct kobject *kobj)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	sess = container_of(kobj, struct scst_session, sess_kobj);

	/* Let's make lockdep happy */
	up_write(&sess->sess_attr_rwsem);

	scst_release_session(sess);

	TRACE_EXIT();
	return;
}

static ssize_t scst_sess_attr_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	int res;
	struct kobj_attribute *kobj_attr;
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	if (down_read_trylock(&sess->sess_attr_rwsem) == 0) {
		res = -ENOENT;
		goto out;
	}

	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	res = kobj_attr->show(kobj, kobj_attr, buf);

	up_read(&sess->sess_attr_rwsem);

out:
	return res;
}

static ssize_t scst_sess_attr_store(struct kobject *kobj, struct attribute *attr,
			  const char *buf, size_t count)
{
	int res;
	struct kobj_attribute *kobj_attr;
	struct scst_session *sess;

	sess = container_of(kobj, struct scst_session, sess_kobj);

	if (down_read_trylock(&sess->sess_attr_rwsem) == 0) {
		res = -ENOENT;
		goto out;
	}

	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	if (kobj_attr->store)
		res = kobj_attr->store(kobj, kobj_attr, buf, count);
	else
		res = -EIO;

	up_read(&sess->sess_attr_rwsem);

out:
	return res;
}

static struct sysfs_ops scst_sess_sysfs_ops = {
	.show = scst_sess_attr_show,
	.store = scst_sess_attr_store,
};

static struct kobj_type scst_session_ktype = {
	.sysfs_ops = &scst_sess_sysfs_ops,
	.release = scst_sysfs_session_release,
	.default_attrs = scst_session_attrs,
};

/* scst_mutex supposed to be locked */
int scst_create_sess_sysfs(struct scst_session *sess)
{
	int retval = 0;
	struct scst_session *s;
	const struct attribute **pattr;
	char *name = (char *)sess->initiator_name;
	int len = strlen(name) + 1, n = 1;

	TRACE_ENTRY();

restart:
	list_for_each_entry(s, &sess->tgt->sess_list, sess_list_entry) {
		if (!s->sess_kobj_initialized)
			continue;

		if (strcmp(name, kobject_name(&s->sess_kobj)) == 0) {
			if (s == sess)
				continue;

			TRACE_DBG("Dublicated session from the same initiator "
				"%s found", name);

			if (name == sess->initiator_name) {
				len = strlen(sess->initiator_name);
				len += 20;
				name = kmalloc(len, GFP_KERNEL);
				if (name == NULL) {
					PRINT_ERROR("Unable to allocate a "
						"replacement name (size %d)",
						len);
				}
			}

			snprintf(name, len, "%s_%d", sess->initiator_name, n);
			n++;
			goto restart;
		}
	}

	init_rwsem(&sess->sess_attr_rwsem);

	sess->sess_kobj_initialized = 1;

	retval = kobject_init_and_add(&sess->sess_kobj, &scst_session_ktype,
			      sess->tgt->tgt_sess_kobj, name);
	if (retval != 0) {
		PRINT_ERROR("Can't add session %s to sysfs", name);
		goto out_free;
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
					name);
				goto out_free;
			}
			pattr++;
		}
	}

	if (sess->acg == sess->tgt->default_acg)
		retval = sysfs_create_link(&sess->sess_kobj,
				sess->tgt->tgt_luns_kobj, "luns");
	else
		retval = sysfs_create_link(&sess->sess_kobj,
				sess->acg->luns_kobj, "luns");

out_free:
	if (name != sess->initiator_name)
		kfree(name);

	TRACE_EXIT_RES(retval);
	return retval;
}

/*
 * Must not be called under scst_mutex or there can be a deadlock with
 * sess_attr_rwsem
 */
void scst_sess_sysfs_put(struct scst_session *sess)
{
	TRACE_ENTRY();

	if (sess->sess_kobj_initialized) {
		kobject_del(&sess->sess_kobj);

		down_write(&sess->sess_attr_rwsem);
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

	if (acg_dev->rd_only || acg_dev->dev->rd_only)
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

int scst_create_acg_dev_sysfs(struct scst_acg *acg, unsigned int virt_lun,
	struct kobject *parent)
{
	int retval;
	struct scst_acg_dev *acg_dev = NULL, *acg_dev_tmp;
	char str[20];

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

	snprintf(str, sizeof(str), "export%u",
		acg_dev->dev->dev_exported_lun_num++);

	kobject_get(&acg_dev->dev->dev_kobj);

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

static ssize_t __scst_luns_mgmt_store(struct scst_acg *acg,
	struct kobject *kobj, const char *buf, size_t count)
{
	int res, virt = 0, read_only = 0, action;
	char *buffer, *p, *e = NULL;
	unsigned int host, channel = 0, id = 0, lun = 0, virt_lun;
	struct scst_acg_dev *acg_dev = NULL, *acg_dev_tmp;
	struct scst_device *d, *dev = NULL;

#define SCST_LUN_ACTION_ADD	1
#define SCST_LUN_ACTION_DEL	2
#define SCST_LUN_ACTION_REPLACE	3
#define SCST_LUN_ACTION_CLEAR	4

	TRACE_ENTRY();

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
	} else if (!strncasecmp("clear", p, 5)) {
		p += 5;
		action = SCST_LUN_ACTION_CLEAR;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
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

	if (action != SCST_LUN_ACTION_CLEAR) {
		if (!isspace(*p)) {
			PRINT_ERROR("%s", "Syntax error");
			res = -EINVAL;
			goto out_free_up;
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
				PRINT_ERROR("Virt device '%s' not found", p);
			} else {
				PRINT_ERROR("Device %d:%d:%d:%d not found",
					    host, channel, id, lun);
			}
			res = -EINVAL;
			goto out_free_up;
		}
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

		while (1) {
			char *pp;
			unsigned long val;
			char *param = scst_get_next_token_str(&e);
			if (param == NULL)
				break;

			p = scst_get_next_lexem(&param);
			if (*p == '\0') {
				PRINT_ERROR("Syntax error at %s (device %s)",
					param, dev->virt_name);
				res = -EINVAL;
				goto out_free_up;
			}

			pp = scst_get_next_lexem(&param);
			if (*pp == '\0') {
				PRINT_ERROR("Parameter %s value missed for device %s",
					p, dev->virt_name);
				res = -EINVAL;
				goto out_free_up;
			}

			if (scst_get_next_lexem(&param)[0] != '\0') {
				PRINT_ERROR("Too many parameter's %s values (device %s)",
					p, dev->virt_name);
				res = -EINVAL;
				goto out_free_up;
			}

			res = strict_strtoul(pp, 0, &val);
			if (res != 0) {
				PRINT_ERROR("strict_strtoul() for %s failed: %d "
					"(device %s)", pp, res, dev->virt_name);
				goto out_free_up;
			}

			if (!strcasecmp("read_only", p)) {
				read_only = val;
				TRACE_DBG("READ ONLY %d", read_only);
			} else {
				PRINT_ERROR("Unknown parameter %s (device %s)",
					p, dev->virt_name);
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
				res = -EEXIST;
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
	case SCST_LUN_ACTION_CLEAR:
		PRINT_INFO("Removed all devices from group %s",
			acg->acg_name);
		list_for_each_entry_safe(acg_dev, acg_dev_tmp,
					 &acg->acg_dev_list,
					 acg_dev_list_entry) {
			res = scst_acg_remove_dev(acg, acg_dev->dev,
				list_is_last(&acg_dev->acg_dev_list_entry,
					     &acg->acg_dev_list));
			if (res)
				goto out_free_up;
		}
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
#undef SCST_LUN_ACTION_CLEAR
}

static ssize_t scst_luns_mgmt_show(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	static char *help = "Usage: echo \"add|del H:C:I:L lun [parameters]\" "
					">mgmt\n"
			    "       echo \"add|del VNAME lun [parameters]\" "
					">mgmt\n"
			    "       echo \"replace H:C:I:L lun [parameters]\" "
					">mgmt\n"
			    "       echo \"replace VNAME lun [parameters]\" "
					">mgmt\n"
			    "       echo \"clear\" >mgmt\n"
			    "\n"
			    "where parameters are one or more "
			    "param_name=value pairs separated by ';'\n"
			    "\nThe following parameters available: read_only.";

	return sprintf(buf, help);
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

	res = __scst_luns_mgmt_store(acg, kobj, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t __scst_acg_addr_method_show(struct scst_acg *acg, char *buf)
{
	int res;

	switch (acg->addr_method) {
	case SCST_LUN_ADDR_METHOD_FLAT:
		res = sprintf(buf, "FLAT\n%s\n", SCST_SYSFS_KEY_MARK);
		break;
	case SCST_LUN_ADDR_METHOD_PERIPHERAL:
		res = sprintf(buf, "PERIPHERAL\n");
		break;
	default:
		res = sprintf(buf, "UNKNOWN\n");
		break;
	}

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
	else {
		PRINT_ERROR("Unknown address method %s", buf);
		res = -EINVAL;
	}
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

static ssize_t __scst_acg_io_grouping_type_store(struct scst_acg *acg,
	const char *buf, size_t count)
{
	int res = 0;
	int prev = acg->acg_io_grouping_type;
	struct scst_acg_dev *acg_dev;

	if (strncasecmp(buf, SCST_IO_GROUPING_AUTO_STR,
			min_t(int, strlen(SCST_IO_GROUPING_AUTO_STR), count)) == 0)
		acg->acg_io_grouping_type = SCST_IO_GROUPING_AUTO;
	else if (strncasecmp(buf, SCST_IO_GROUPING_THIS_GROUP_ONLY_STR,
			min_t(int, strlen(SCST_IO_GROUPING_THIS_GROUP_ONLY_STR), count)) == 0)
		acg->acg_io_grouping_type = SCST_IO_GROUPING_THIS_GROUP_ONLY;
	else if (strncasecmp(buf, SCST_IO_GROUPING_NEVER_STR,
			min_t(int, strlen(SCST_IO_GROUPING_NEVER_STR), count)) == 0)
		acg->acg_io_grouping_type = SCST_IO_GROUPING_NEVER;
	else {
		long io_grouping_type;
		res = strict_strtoul(buf, 0, &io_grouping_type);
		if ((res != 0) || (io_grouping_type <= 0)) {
			PRINT_ERROR("Unknown or not allowed I/O grouping type "
				"%s", buf);
			res = -EINVAL;
			goto out;
		}
		acg->acg_io_grouping_type = io_grouping_type;
	}

	if (prev == acg->acg_io_grouping_type)
		goto out;

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out;

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_resume;
	}

	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		int rc;

		scst_stop_dev_threads(acg_dev->dev);

		rc = scst_create_dev_threads(acg_dev->dev);
		if (rc != 0)
			res = rc;
	}

	mutex_unlock(&scst_mutex);

out_resume:
	scst_resume_activity();

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

static int scst_create_acg_sysfs(struct scst_tgt *tgt,
	struct scst_acg *acg)
{
	int retval = 0;

	TRACE_ENTRY();

	acg->acg_kobj_initialized = 1;

	retval = kobject_init_and_add(&acg->acg_kobj, &acg_ktype,
		tgt->tgt_ini_grp_kobj, acg->acg_name);
	if (retval != 0) {
		PRINT_ERROR("Can't add acg '%s' to sysfs", acg->acg_name);
		goto out;
	}

	acg->luns_kobj = kobject_create_and_add("luns", &acg->acg_kobj);
	if (acg->luns_kobj == NULL) {
		PRINT_ERROR("Can't create luns kobj for tgt %s",
			tgt->tgt_name);
		retval = -ENOMEM;
		goto out;
	}

	retval = sysfs_create_file(acg->luns_kobj, &scst_acg_luns_mgmt.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_luns_mgmt.attr.name, tgt->tgt_name);
		goto out;
	}

	acg->initiators_kobj = kobject_create_and_add("initiators",
		&acg->acg_kobj);
	if (acg->initiators_kobj == NULL) {
		PRINT_ERROR("Can't create initiators kobj for tgt %s",
			tgt->tgt_name);
		retval = -ENOMEM;
		goto out;
	}

	retval = sysfs_create_file(acg->initiators_kobj,
		&scst_acg_ini_mgmt.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_ini_mgmt.attr.name, tgt->tgt_name);
		goto out;
	}

	retval = sysfs_create_file(&acg->acg_kobj, &scst_acg_addr_method.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_addr_method.attr.name, tgt->tgt_name);
		goto out;
	}

	retval = sysfs_create_file(&acg->acg_kobj, &scst_acg_io_grouping_type.attr);
	if (retval != 0) {
		PRINT_ERROR("Can't add tgt attr %s for tgt %s",
			scst_acg_io_grouping_type.attr.name, tgt->tgt_name);
		goto out;
	}

out:
	TRACE_EXIT_RES(retval);
	return retval;
}

void scst_acg_sysfs_put(struct scst_acg *acg)
{
	TRACE_ENTRY();

	if (acg->acg_kobj_initialized) {
		scst_clear_acg(acg);

		kobject_del(acg->luns_kobj);
		kobject_put(acg->luns_kobj);

		kobject_del(acg->initiators_kobj);
		kobject_put(acg->initiators_kobj);

		kobject_del(&acg->acg_kobj);
		kobject_put(&acg->acg_kobj);
	} else
		scst_destroy_acg(acg);

	TRACE_EXIT();
	return;
}

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

static ssize_t scst_ini_group_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	static char *help = "Usage: echo \"create GROUP_NAME\" >mgmt\n"
			    "       echo \"del GROUP_NAME\" >mgmt\n";

	return sprintf(buf, help);
}

static ssize_t scst_ini_group_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res, action;
	int len;
	char *name;
	char *buffer, *p, *e = NULL;
	struct scst_acg *a, *acg = NULL;
	struct scst_tgt *tgt;

#define SCST_INI_GROUP_ACTION_CREATE	1
#define SCST_INI_GROUP_ACTION_DEL	2

	TRACE_ENTRY();

	tgt = container_of(kobj->parent, struct scst_tgt, tgt_kobj);

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
	if (strncasecmp("create ", p, 7) == 0) {
		p += 7;
		action = SCST_INI_GROUP_ACTION_CREATE;
	} else if (strncasecmp("del ", p, 4) == 0) {
		p += 4;
		action = SCST_INI_GROUP_ACTION_DEL;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
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
	e = p;
	while (!isspace(*e) && *e != '\0')
		e++;
	*e = '\0';

	if (p[0] == '\0') {
		PRINT_ERROR("%s", "Group name required");
		res = -EINVAL;
		goto out_free_up;
	}

	list_for_each_entry(a, &tgt->tgt_acg_list, acg_list_entry) {
		if (strcmp(a->acg_name, p) == 0) {
			TRACE_DBG("group (acg) %p %s found",
				  a, a->acg_name);
			acg = a;
			break;
		}
	}

	switch (action) {
	case SCST_INI_GROUP_ACTION_CREATE:
		TRACE_DBG("Creating group '%s'", p);
		if (acg != NULL) {
			PRINT_ERROR("acg name %s exist", p);
			res = -EINVAL;
			goto out_free_up;
		}

		len = strlen(p) + 1;
		name = kmalloc(len, GFP_KERNEL);
		if (name == NULL) {
			PRINT_ERROR("%s", "Allocation of name failed");
			res = -ENOMEM;
			goto out_free_up;
		}
		strlcpy(name, p, len);

		acg = scst_alloc_add_acg(tgt, name);
		kfree(name);
		if (acg == NULL)
			goto out_free_up;

		res = scst_create_acg_sysfs(tgt, acg);
		if (res != 0)
			goto out_free_acg;
		break;
	case SCST_INI_GROUP_ACTION_DEL:
		TRACE_DBG("Deleting group '%s'", p);
		if (acg == NULL) {
			PRINT_ERROR("Group %s not found", p);
			res = -EINVAL;
			goto out_free_up;
		}
		if (!scst_acg_sess_is_empty(acg)) {
			PRINT_ERROR("Group %s is not empty", acg->acg_name);
			res = -EBUSY;
			goto out_free_up;
		}
		scst_acg_sysfs_put(acg);
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

out_free_acg:
	scst_acg_sysfs_put(acg);
	goto out_free_up;

#undef SCST_LUN_ACTION_CREATE
#undef SCST_LUN_ACTION_DEL
}

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

static ssize_t scst_rel_tgt_id_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res = 0;
	struct scst_tgt *tgt;
	unsigned long rel_tgt_id;

	TRACE_ENTRY();

	if (buf == NULL)
		goto out_err;

	tgt = container_of(kobj, struct scst_tgt, tgt_kobj);

	res = strict_strtoul(buf, 0, &rel_tgt_id);
	if (res != 0)
		goto out_err;

	TRACE_DBG("Try to set relative target port id %d",
		(uint16_t)rel_tgt_id);

	if (rel_tgt_id < SCST_MIN_REL_TGT_ID ||
	    rel_tgt_id > SCST_MAX_REL_TGT_ID) {
		if ((rel_tgt_id == 0) && !tgt->tgtt->is_target_enabled(tgt))
			goto set;

		PRINT_ERROR("Invalid relative port id %d",
			(uint16_t)rel_tgt_id);
		res = -EINVAL;
		goto out;
	}

	if (tgt->tgtt->is_target_enabled(tgt) &&
	    rel_tgt_id != tgt->rel_tgt_id) {
		if (!scst_is_relative_target_port_id_unique(rel_tgt_id, tgt)) {
			PRINT_ERROR("Relative port id %d is not unique",
				(uint16_t)rel_tgt_id);
			res = -EBADSLT;
			goto out;
		}
	}

set:
	tgt->rel_tgt_id = (uint16_t)rel_tgt_id;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	PRINT_ERROR("%s: Requested action not understood: %s", __func__, buf);
	res = -EINVAL;
	goto out;
}

int scst_create_acn_sysfs(struct scst_acg *acg, struct scst_acn *acn)
{
	int retval = 0;
	int len;
	struct kobj_attribute *attr = NULL;

	TRACE_ENTRY();

	acn->acn_attr = NULL;

	attr = kzalloc(sizeof(struct kobj_attribute), GFP_KERNEL);
	if (attr == NULL) {
		PRINT_ERROR("Unable to allocate attributes for initiator '%s'",
			acn->name);
		retval = -ENOMEM;
		goto out;
	}

	len = strlen(acn->name) + 1;
	attr->attr.name = kzalloc(len, GFP_KERNEL);
	if (attr->attr.name == NULL) {
		PRINT_ERROR("Unable to allocate attributes for initiator '%s'",
			acn->name);
		retval = -ENOMEM;
		goto out_free;
	}
	strlcpy((char *)attr->attr.name, acn->name, len);

	attr->attr.owner = THIS_MODULE;
	attr->attr.mode = S_IRUGO;
	attr->show = scst_acn_file_show;
	attr->store = NULL;

	retval = sysfs_create_file(acg->initiators_kobj, &attr->attr);
	if (retval != 0) {
		PRINT_ERROR("Unable to create acn '%s' for group '%s'",
			acn->name, acg->acg_name);
		kfree(attr->attr.name);
		goto out_free;
	}

	acn->acn_attr = attr;

out:
	TRACE_EXIT_RES(retval);
	return retval;

out_free:
	kfree(attr);
	goto out;
}

void scst_acn_sysfs_del(struct scst_acg *acg, struct scst_acn *acn,
	bool reassign)
{
	TRACE_ENTRY();

	if (acn->acn_attr != NULL) {
		sysfs_remove_file(acg->initiators_kobj,
			&acn->acn_attr->attr);
		kfree(acn->acn_attr->attr.name);
		kfree(acn->acn_attr);
	}
	scst_acg_remove_acn(acn);
	if (reassign)
		scst_check_reassign_sessions();

	TRACE_EXIT();
	return;
}

static ssize_t scst_acn_file_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, "%s\n",
		attr->attr.name);
}

static ssize_t scst_acg_luns_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res;
	struct scst_acg *acg;

	acg = container_of(kobj->parent, struct scst_acg, acg_kobj);
	res = __scst_luns_mgmt_store(acg, kobj, buf, count);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_acg_ini_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	static char *help = "Usage: echo \"add INITIATOR_NAME\" "
					">mgmt\n"
			    "       echo \"del INITIATOR_NAME\" "
					">mgmt\n"
			    "       echo \"move INITIATOR_NAME DEST_GROUP_NAME\" "
					">mgmt\n"
			    "       echo \"clear\" "
					">mgmt\n";

	return sprintf(buf, help);
}

static ssize_t scst_acg_ini_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res, action;
	char *buffer, *p, *e = NULL;
	char *name = NULL, *group = NULL;
	struct scst_acg *acg = NULL, *acg_dest = NULL;
	struct scst_tgt *tgt = NULL;
	struct scst_acn *acn = NULL, *acn_tmp;

#define SCST_ACG_ACTION_INI_ADD		1
#define SCST_ACG_ACTION_INI_DEL		2
#define SCST_ACG_ACTION_INI_CLEAR	3
#define SCST_ACG_ACTION_INI_MOVE	4

	TRACE_ENTRY();

	acg = container_of(kobj->parent, struct scst_acg, acg_kobj);

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
		action = SCST_ACG_ACTION_INI_ADD;
	} else if (strncasecmp("del", p, 3) == 0) {
		p += 3;
		action = SCST_ACG_ACTION_INI_DEL;
	} else if (strncasecmp("clear", p, 5) == 0) {
		p += 5;
		action = SCST_ACG_ACTION_INI_CLEAR;
	} else if (strncasecmp("move", p, 4) == 0) {
		p += 4;
		action = SCST_ACG_ACTION_INI_MOVE;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	if (action != SCST_ACG_ACTION_INI_CLEAR)
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

	if (action != SCST_ACG_ACTION_INI_CLEAR)
		while (isspace(*p) && *p != '\0')
			p++;

	switch (action) {
	case SCST_ACG_ACTION_INI_ADD:
		e = p;
		while (!isspace(*e) && *e != '\0')
			e++;
		*e = '\0';
		name = p;

		if (name[0] == '\0') {
			PRINT_ERROR("%s", "Invalid initiator name");
			res = -EINVAL;
			goto out_free_up;
		}

		res = scst_acg_add_name(acg, name);
		if (res != 0)
			goto out_free_up;
		break;
	case SCST_ACG_ACTION_INI_DEL:
		e = p;
		while (!isspace(*e) && *e != '\0')
			e++;
		*e = '\0';
		name = p;

		if (name[0] == '\0') {
			PRINT_ERROR("%s", "Invalid initiator name");
			res = -EINVAL;
			goto out_free_up;
		}

		acn = scst_acg_find_name(acg, name);
		if (acn == NULL) {
			PRINT_ERROR("Unable to find "
				"initiator '%s' in group '%s'",
				name, acg->acg_name);
			res = -EINVAL;
			goto out_free_up;
		}
		scst_acn_sysfs_del(acg, acn, true);
		break;
	case SCST_ACG_ACTION_INI_CLEAR:
		list_for_each_entry_safe(acn, acn_tmp, &acg->acn_list,
				acn_list_entry) {
			scst_acn_sysfs_del(acg, acn, false);
		}
		scst_check_reassign_sessions();
		break;
	case SCST_ACG_ACTION_INI_MOVE:
		e = p;
		while (!isspace(*e) && *e != '\0')
			e++;
		if (*e == '\0') {
			PRINT_ERROR("%s", "Too few parameters");
			res = -EINVAL;
			goto out_free_up;
		}
		*e = '\0';
		name = p;

		if (name[0] == '\0') {
			PRINT_ERROR("%s", "Invalid initiator name");
			res = -EINVAL;
			goto out_free_up;
		}

		e++;
		p = e;
		while (!isspace(*e) && *e != '\0')
			e++;
		*e = '\0';
		group = p;

		if (group[0] == '\0') {
			PRINT_ERROR("%s", "Invalid group name");
			res = -EINVAL;
			goto out_free_up;
		}

		TRACE_DBG("Move initiator '%s' to group '%s'",
			name, group);

		/*
		 * Better get tgt from hierarchy tgt_kobj -> tgt_ini_grp_kobj ->
		 * acg_kobj -> initiators_kobj than have direct pointer to tgt
		 * in struct acg and have a headache to care about its possible
		 * wrong dereference on the destruction time.
		 */
		{
			struct kobject *k;

			/* acg_kobj */
			k = kobj->parent;
			if (k == NULL) {
				res = -EINVAL;
				goto out_free_up;
			}
			/* tgt_ini_grp_kobj */
			k = k->parent;
			if (k == NULL) {
				res = -EINVAL;
				goto out_free_up;
			}
			/* tgt_kobj */
			k = k->parent;
			if (k == NULL) {
				res = -EINVAL;
				goto out_free_up;
			}

			tgt = container_of(k, struct scst_tgt, tgt_kobj);
		}

		acn = scst_acg_find_name(acg, name);
		if (acn == NULL) {
			PRINT_ERROR("Unable to find "
				"initiator '%s' in group '%s'",
				name, acg->acg_name);
			res = -EINVAL;
			goto out_free_up;
		}
		acg_dest = scst_tgt_find_acg(tgt, group);
		if (acg_dest == NULL) {
			PRINT_ERROR("Unable to find group '%s' in target '%s'",
				group, tgt->tgt_name);
			res = -EINVAL;
			goto out_free_up;
		}
		if (scst_acg_find_name(acg_dest, name) != NULL) {
			PRINT_ERROR("Initiator '%s' already exists in group '%s'",
				name, acg_dest->acg_name);
			res = -EEXIST;
			goto out_free_up;
		}
		scst_acn_sysfs_del(acg, acn, false);

		res = scst_acg_add_name(acg_dest, name);
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

#undef SCST_ACG_ACTION_INI_ADD
#undef SCST_ACG_ACTION_INI_DEL
#undef SCST_ACG_ACTION_INI_CLEAR
#undef SCST_ACG_ACTION_INI_MOVE
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

	count = sprintf(buf, "%d\n%s", scst_main_cmd_threads.nr_threads,
		(scst_main_cmd_threads.nr_threads != scst_threads) ?
			SCST_SYSFS_KEY_MARK "\n" : "");

	TRACE_EXIT();
	return count;
}

static ssize_t scst_threads_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	long oldtn, newtn, delta;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	oldtn = scst_main_cmd_threads.nr_threads;

	res = strict_strtoul(buf, 0, &newtn);
	if (res != 0) {
		PRINT_ERROR("strict_strtoul() for %s failed: %d ", buf, res);
		goto out_up;
	}

	if (newtn <= 0) {
		PRINT_ERROR("Illegal threads num value %ld", newtn);
		res = -EINVAL;
		goto out_up;
	}

	delta = newtn - oldtn;
	if (delta < 0)
		scst_del_threads(&scst_main_cmd_threads, -delta);
	else {
		res = scst_add_threads(&scst_main_cmd_threads, NULL, NULL, delta);
		if (res != 0)
			goto out_up;
	}

	PRINT_INFO("Changed cmd threads num: old %ld, new %ld", oldtn, newtn);

	res = count;

out_up:
	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_setup_id_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int count;

	TRACE_ENTRY();

	count = sprintf(buf, "0x%x%s\n", scst_setup_id,
		(scst_setup_id == 0) ? "" : SCST_SYSFS_KEY_MARK "\n");

	TRACE_EXIT();
	return count;
}

static ssize_t scst_setup_id_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	unsigned long val;

	TRACE_ENTRY();

	res = strict_strtoul(buf, 0, &val);
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
		"		       mgmt_dbg, scsi_serializing,\n"
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

static struct kobj_attribute scst_setup_id_attr =
	__ATTR(setup_id, S_IRUGO | S_IWUSR, scst_setup_id_show,
	       scst_setup_id_store);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
static struct kobj_attribute scst_trace_level_attr =
	__ATTR(trace_level, S_IRUGO | S_IWUSR, scst_main_trace_level_show,
	       scst_main_trace_level_store);
#endif

static struct kobj_attribute scst_version_attr =
	__ATTR(version, S_IRUGO, scst_version_show, NULL);

static struct attribute *scst_sysfs_root_default_attrs[] = {
	&scst_threads_attr.attr,
	&scst_setup_id_attr.attr,
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

	if (kobj_attr->store)
		return kobj_attr->store(kobj, kobj_attr, buf, count);
	else
		return -EIO;
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

static ssize_t scst_devt_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	char *help = "Usage: echo \"add_device device_name [parameters]\" "
				">mgmt\n"
		     "       echo \"del_device device_name\" >mgmt\n"
		     "%s"
		     "\n"
		     "where parameters are one or more "
		     "param_name=value pairs separated by ';'\n"
		     "%s%s";
	struct scst_dev_type *devt;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	if (devt->add_device_parameters_help != NULL)
		return sprintf(buf, help,
			(devt->mgmt_cmd_help) ? devt->mgmt_cmd_help : "",
			"\nThe following parameters available: ",
			devt->add_device_parameters_help);
	else
		return sprintf(buf, help,
			(devt->mgmt_cmd_help) ? devt->mgmt_cmd_help : "",
			"", "");
}

static ssize_t scst_devt_mgmt_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int res;
	char *buffer, *p, *pp, *device_name;
	struct scst_dev_type *devt;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	buffer = kzalloc(count+1, GFP_KERNEL);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	memcpy(buffer, buf, count);
	buffer[count] = '\0';

	pp = buffer;
	if (pp[strlen(pp) - 1] == '\n')
		pp[strlen(pp) - 1] = '\0';

	p = scst_get_next_lexem(&pp);

	if (strcasecmp("add_device", p) == 0) {
		device_name = scst_get_next_lexem(&pp);
		if (*device_name == '\0') {
			PRINT_ERROR("%s", "Device name required");
			res = -EINVAL;
			goto out_free;
		}
		res = devt->add_device(device_name, pp);
	} else if (strcasecmp("del_device", p) == 0) {
		device_name = scst_get_next_lexem(&pp);
		if (*device_name == '\0') {
			PRINT_ERROR("%s", "Device name required");
			res = -EINVAL;
			goto out_free;
		}

		p = scst_get_next_lexem(&pp);
		if (*p != '\0')
			goto out_syntax_err;

		res = devt->del_device(device_name);
	} else if (devt->mgmt_cmd != NULL) {
		scst_restore_token_str(p, pp);
		res = devt->mgmt_cmd(buffer);
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_free;
	}

	if (res == 0)
		res = count;

out_free:
	kfree(buffer);

out:
	TRACE_EXIT_RES(res);
	return res;

out_syntax_err:
	PRINT_ERROR("Syntax error on \"%s\"", p);
	res = -EINVAL;
	goto out_free;
}

static struct kobj_attribute scst_devt_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_devt_mgmt_show,
	       scst_devt_mgmt_store);

static ssize_t scst_devt_pass_through_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "1");
}

static struct kobj_attribute scst_devt_pass_through =
	__ATTR(pass_through, S_IRUGO, scst_devt_pass_through_show, NULL);

static ssize_t scst_devt_pass_through_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	char *help = "Usage: echo \"assign H:C:I:L\" >mgmt\n"
		     "       echo \"unassign H:C:I:L\" >mgmt\n";
	return sprintf(buf, help);
}

static ssize_t scst_devt_pass_through_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	char *buffer, *p, *pp, *action;
	struct scst_dev_type *devt;
	unsigned long host, channel, id, lun;
	struct scst_device *d, *dev = NULL;

	TRACE_ENTRY();

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	buffer = kzalloc(count+1, GFP_KERNEL);
	if (buffer == NULL) {
		res = -ENOMEM;
		goto out;
	}

	memcpy(buffer, buf, count);
	buffer[count] = '\0';

	pp = buffer;
	if (pp[strlen(pp) - 1] == '\n')
		pp[strlen(pp) - 1] = '\0';

	action = scst_get_next_lexem(&pp);
	p = scst_get_next_lexem(&pp);
	if (*p == '\0') {
		PRINT_ERROR("%s", "Device required");
		res = -EINVAL;
		goto out_free;
	}

	;
	if (*scst_get_next_lexem(&pp) != '\0') {
		PRINT_ERROR("%s", "Too many parameters");
		res = -EINVAL;
		goto out_syntax_err;
	}

	host = simple_strtoul(p, &p, 0);
	if ((host == ULONG_MAX) || (*p != ':'))
		goto out_syntax_err;
	p++;
	channel = simple_strtoul(p, &p, 0);
	if ((channel == ULONG_MAX) || (*p != ':'))
		goto out_syntax_err;
	p++;
	id = simple_strtoul(p, &p, 0);
	if ((channel == ULONG_MAX) || (*p != ':'))
		goto out_syntax_err;
	p++;
	lun = simple_strtoul(p, &p, 0);
	if (lun == ULONG_MAX)
		goto out_syntax_err;

	TRACE_DBG("Dev %ld:%ld:%ld:%ld", host, channel, id, lun);

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	list_for_each_entry(d, &scst_dev_list, dev_list_entry) {
		if ((d->virt_id == 0) &&
		    d->scsi_dev->host->host_no == host &&
		    d->scsi_dev->channel == channel &&
		    d->scsi_dev->id == id &&
		    d->scsi_dev->lun == lun) {
			dev = d;
			TRACE_DBG("Dev %p (%ld:%ld:%ld:%ld) found",
				  dev, host, channel, id, lun);
			break;
		}
	}
	if (dev == NULL) {
		PRINT_ERROR("Device %ld:%ld:%ld:%ld not found",
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

	if (strcasecmp("assign", action) == 0)
		res = scst_assign_dev_handler(dev, devt);
	else if (strcasecmp("deassign", action) == 0) {
		if (dev->handler != devt) {
			PRINT_ERROR("Device %s is not assigned to handler %s",
				dev->virt_name, devt->name);
			res = -EINVAL;
			goto out_unlock;
		}
		res = scst_assign_dev_handler(dev, &scst_null_devtype);
	} else {
		PRINT_ERROR("Unknown action \"%s\"", action);
		res = -EINVAL;
		goto out_unlock;
	}

	if (res == 0)
		res = count;

out_unlock:
	mutex_unlock(&scst_mutex);

out_free:
	kfree(buffer);

out:
	TRACE_EXIT_RES(res);
	return res;

out_syntax_err:
	PRINT_ERROR("Syntax error on \"%s\"", p);
	res = -EINVAL;
	goto out_free;
}

static struct kobj_attribute scst_devt_pass_through_mgmt =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, scst_devt_pass_through_mgmt_show,
	       scst_devt_pass_through_mgmt_store);

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

	if (devt->add_device != NULL) {
		retval = sysfs_create_file(&devt->devt_kobj,
				&scst_devt_mgmt.attr);
		if (retval != 0) {
			PRINT_ERROR("Can't add mgmt attr for dev handler %s",
				devt->name);
			goto out;
		}
	} else if (devt->pass_through) {
		retval = sysfs_create_file(&devt->devt_kobj,
				&scst_devt_pass_through_mgmt.attr);
		if (retval != 0) {
			PRINT_ERROR("Can't add mgmt attr for dev handler %s",
				devt->name);
			goto out;
		}

		retval = sysfs_create_file(&devt->devt_kobj,
				&scst_devt_pass_through.attr);
		if (retval != 0) {
			PRINT_ERROR("Can't add pass_through attr for dev "
				"handler %s", devt->name);
			goto out;
		}
	}

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
EXPORT_SYMBOL(scst_sysfs_user_get_info);

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
EXPORT_SYMBOL(scst_sysfs_user_add_info);

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
EXPORT_SYMBOL(scst_sysfs_user_del_info);

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
EXPORT_SYMBOL(scst_wait_info_completion);

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

void scst_sysfs_cleanup(void)
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
	/*
	 * There is a race, when in the release() schedule happens just after
	 * calling complete(), so if we exit and unload scst module immediately,
	 * there will be oops there. So let's give it a chance to quit
	 * gracefully. Unfortunately, current kobjects implementation
	 * doesn't allow better ways to handle it.
	 */
	msleep(3000);

	PRINT_INFO("%s", "Exiting SCST sysfs hierarchy done");

	TRACE_EXIT();
	return;
}
