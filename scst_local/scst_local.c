/*
 * Copyright (C) 2008 - 2010 Richard Sharpe
 * Copyright (C) 1992 Eric Youngdale
 * Copyright (C) 2008 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
 *
 * Simulate a host adapter and an SCST target adapter back to back
 *
 * Based on the scsi_debug.c driver originally by Eric Youngdale and
 * others, including D Gilbert et al
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/spinlock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/blk-mq.h>
#else
#include <linux/blkdev.h>
static inline u32 blk_mq_unique_tag(struct request *rq)
{
	return rq->tag;
}
#endif
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>

#define LOG_PREFIX "scst_local"

/* SCST includes ... */
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_debug.h>
#else
#include <scst.h>
#include <scst_debug.h>
#endif

#ifndef INSIDE_KERNEL_TREE
#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
#warning HIGHMEM kernel configurations are not supported by this module, \
because nowadays it is not worth the effort. Consider changing \
VMSPLIT option or use a 64-bit configuration instead. See SCST core \
README file for details.
#endif
#endif

#ifdef CONFIG_SCST_DEBUG
#define SCST_LOCAL_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_PID | \
	TRACE_LINE | TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL)
#else
# ifdef CONFIG_SCST_TRACING
#define SCST_LOCAL_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_PID | \
	TRACE_SPECIAL)
# endif
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag scst_local_trace_flag
static unsigned long scst_local_trace_flag = SCST_LOCAL_DEFAULT_LOG_FLAGS;
#endif

#define SCST_LOCAL_VERSION "3.10.0-pre"
static const char *scst_local_version_date = "20110901";

/* Some statistics */
static atomic_t num_aborts = ATOMIC_INIT(0);
static atomic_t num_dev_resets = ATOMIC_INIT(0);
static atomic_t num_target_resets = ATOMIC_INIT(0);

static bool scst_local_add_default_tgt = true;
module_param_named(add_default_tgt, scst_local_add_default_tgt, bool, 0444);
MODULE_PARM_DESC(add_default_tgt,
		 "add (default) or not on start default target scst_local_tgt with default session scst_local_host");

static struct workqueue_struct *aen_workqueue;

struct scst_aen_work_item {
	struct list_head work_list_entry;
	struct scst_aen *aen;
};

struct scst_local_tgt {
	struct scst_tgt *scst_tgt;
	struct list_head sessions_list; /* protected by scst_local_mutex */
	struct list_head tgts_list_entry;

	/* SCSI version descriptors */
	uint16_t scsi_transport_version;
	uint16_t phys_transport_version;
};

struct scst_local_sess {
	struct scst_session *scst_sess;

	unsigned int unregistering:1;

	struct device dev;
	struct Scsi_Host *shost;
	struct scst_local_tgt *tgt;

	int number;

	struct mutex tr_id_mutex;
	uint8_t *transport_id;
	int transport_id_len;

	struct work_struct aen_work;
	spinlock_t aen_lock;
	struct list_head aen_work_list; /* protected by aen_lock */

	struct work_struct remove_work;

	struct list_head sessions_list_entry;
};

#define to_scst_lcl_sess(d) \
	container_of(d, struct scst_local_sess, dev)

static int __scst_local_add_adapter(struct scst_local_tgt *tgt, const char *initiator_name,
				    bool locked);
static int scst_local_add_adapter(struct scst_local_tgt *tgt, const char *initiator_name);
static void scst_local_close_session_impl(struct scst_local_sess *sess,
					  bool async);
static void scst_local_remove_adapter(struct scst_local_sess *sess);
static int scst_local_add_target(const char *target_name, struct scst_local_tgt **out_tgt);
static void __scst_local_remove_target(struct scst_local_tgt *tgt);
static void scst_local_remove_target(struct scst_local_tgt *tgt);

static atomic_t scst_local_sess_num = ATOMIC_INIT(0);

static LIST_HEAD(scst_local_tgts_list);
static DEFINE_MUTEX(scst_local_mutex);

static DECLARE_RWSEM(scst_local_exit_rwsem);

MODULE_AUTHOR("Richard Sharpe, Vladislav Bolkhovitin + ideas from SCSI_DEBUG");
MODULE_DESCRIPTION("SCSI+SCST local adapter driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(SCST_LOCAL_VERSION);
MODULE_IMPORT_NS(SCST);

static int scst_local_get_sas_transport_id(struct scst_local_sess *sess, uint8_t **transport_id,
					   int *len)
{
	int res = 0;
	int tr_id_size = 0;
	uint8_t *tr_id = NULL;

	TRACE_ENTRY();

	tr_id_size = 24;  /* A SAS TransportID */

	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (!tr_id) {
		PRINT_ERROR("Allocation of TransportID (size %d) failed",
			    tr_id_size);
		res = -ENOMEM;
		goto out;
	}

	tr_id[0] = 0x00 | SCSI_TRANSPORTID_PROTOCOLID_SAS;

	/*
	 * Assemble a valid SAS address = 0x5OOUUIIR12345678 ... Does SCST
	 * have one?
	 */

	tr_id[4]  = 0x5F;
	tr_id[5]  = 0xEE;
	tr_id[6]  = 0xDE;
	tr_id[7]  = 0x40 | ((sess->number >> 4) & 0x0F);
	tr_id[8]  = 0x0F | ((sess->number & 0x0F) << 4);
	tr_id[9]  = 0xAD;
	tr_id[10] = 0xE0;
	tr_id[11] = 0x50;

	*transport_id = tr_id;
	if (len)
		*len = tr_id_size;

	TRACE_DBG("Created tid '%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X'",
		  tr_id[4], tr_id[5], tr_id[6], tr_id[7],
		  tr_id[8], tr_id[9], tr_id[10], tr_id[11]);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_local_get_initiator_port_transport_id(struct scst_tgt *tgt,
						      struct scst_session *scst_sess,
						      uint8_t **transport_id)
{
	int res = 0;
	struct scst_local_sess *sess;

	TRACE_ENTRY();

	if (!scst_sess) {
		res = SCSI_TRANSPORTID_PROTOCOLID_SAS;
		goto out;
	}

	sess = scst_sess_get_tgt_priv(scst_sess);

	mutex_lock(&sess->tr_id_mutex);

	if (!sess->transport_id) {
		res = scst_local_get_sas_transport_id(sess, transport_id, NULL);
	} else {
		*transport_id = kmemdup(sess->transport_id,
					sess->transport_id_len,
					GFP_KERNEL);
		if (!*transport_id) {
			PRINT_ERROR("Allocation of TransportID (size %d) failed",
				    sess->transport_id_len);
			res = -ENOMEM;
		}
	}

	mutex_unlock(&sess->tr_id_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 ** Tgtt attributes
 **/

static ssize_t scst_local_version_show(struct kobject *kobj, struct kobj_attribute *attr,
				       char *buf)
{
	sprintf(buf, "%s/%s\n", SCST_LOCAL_VERSION, scst_local_version_date);

#ifdef CONFIG_SCST_EXTRACHECKS
	strcat(buf, "EXTRACHECKS\n");
#endif

#ifdef CONFIG_SCST_TRACING
	strcat(buf, "TRACING\n");
#endif

#ifdef CONFIG_SCST_DEBUG
	strcat(buf, "DEBUG\n");
#endif

	TRACE_EXIT();
	return strlen(buf);
}

static struct kobj_attribute scst_local_version_attr =
	__ATTR(version, 0444, scst_local_version_show, NULL);

static ssize_t scst_local_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf,
		       "Aborts: %d, Device Resets: %d, Target Resets: %d\n",
		       atomic_read(&num_aborts), atomic_read(&num_dev_resets),
		       atomic_read(&num_target_resets));
}

static struct kobj_attribute scst_local_stats_attr =
	__ATTR(stats, 0444, scst_local_stats_show, NULL);

static const struct attribute *scst_local_tgtt_attrs[] = {
	&scst_local_version_attr.attr,
	&scst_local_stats_attr.attr,
	NULL,
};

/*
 ** Tgt attributes
 **/

static ssize_t scst_local_scsi_transport_version_show(struct kobject *kobj,
						      struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	ssize_t res = -ENOENT;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		goto out;

	res = -E_TGT_PRIV_NOT_YET_SET;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out_up;

	if (tgt->scsi_transport_version != 0)
		res = sprintf(buf, "0x%x\n%s", tgt->scsi_transport_version,
			      SCST_SYSFS_KEY_MARK "\n");
	else
		res = sprintf(buf, "0x%x\n", 0x0BE0); /* SAS */

out_up:
	up_read(&scst_local_exit_rwsem);
out:
	return res;
}

static ssize_t scst_local_scsi_transport_version_store(struct kobject *kobj,
						       struct kobj_attribute *attr,
						       const char *buffer, size_t size)
{
	ssize_t res = -ENOENT;
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	unsigned long val;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		goto out;

	res = -E_TGT_PRIV_NOT_YET_SET;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out_up;

	res = kstrtoul(buffer, 0, &val);
	if (res != 0) {
		PRINT_ERROR("strtoul() for %s failed: %zd", buffer, res);
		goto out_up;
	}

	tgt->scsi_transport_version = val;

	res = size;

out_up:
	up_read(&scst_local_exit_rwsem);
out:
	return res;
}

static struct kobj_attribute scst_local_scsi_transport_version_attr =
	__ATTR(scsi_transport_version, 0644,
	       scst_local_scsi_transport_version_show,
	       scst_local_scsi_transport_version_store);

static ssize_t scst_local_phys_transport_version_show(struct kobject *kobj,
						      struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	ssize_t res = -ENOENT;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		goto out;

	res = -E_TGT_PRIV_NOT_YET_SET;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out_up;

	res = sprintf(buf, "0x%x\n%s", tgt->phys_transport_version,
		      tgt->phys_transport_version != 0 ? SCST_SYSFS_KEY_MARK "\n" : "");

out_up:
	up_read(&scst_local_exit_rwsem);
out:
	return res;
}

static ssize_t scst_local_phys_transport_version_store(struct kobject *kobj,
						       struct kobj_attribute *attr,
						       const char *buffer, size_t size)
{
	ssize_t res = -ENOENT;
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	unsigned long val;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		goto out;

	res = -E_TGT_PRIV_NOT_YET_SET;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = scst_tgt_get_tgt_priv(scst_tgt);
	if (!tgt)
		goto out_up;

	res = kstrtoul(buffer, 0, &val);
	if (res != 0) {
		PRINT_ERROR("strtoul() for %s failed: %zd", buffer, res);
		goto out_up;
	}

	tgt->phys_transport_version = val;

	res = size;

out_up:
	up_read(&scst_local_exit_rwsem);
out:
	return res;
}

static struct kobj_attribute scst_local_phys_transport_version_attr =
	__ATTR(phys_transport_version, 0644,
	       scst_local_phys_transport_version_show,
	       scst_local_phys_transport_version_store);

static const struct attribute *scst_local_tgt_attrs[] = {
	&scst_local_scsi_transport_version_attr.attr,
	&scst_local_phys_transport_version_attr.attr,
	NULL,
};

/*
 ** Session attributes
 **/

static ssize_t host_no_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct scst_session *scst_sess =
		container_of(kobj, struct scst_session, sess_kobj);
	struct scst_local_sess *sess = scst_sess_get_tgt_priv(scst_sess);
	struct Scsi_Host *host = sess->shost;

	return host ? snprintf(buf, PAGE_SIZE, "%u\n", host->host_no) : -EINVAL;
}

static struct kobj_attribute scst_local_host_no_attr = __ATTR_RO(host_no);

static ssize_t scst_local_transport_id_show(struct kobject *kobj, struct kobj_attribute *attr,
					    char *buf)
{
	ssize_t res;
	struct scst_session *scst_sess;
	struct scst_local_sess *sess;
	uint8_t *tr_id;
	int tr_id_len, i;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = scst_sess_get_tgt_priv(scst_sess);

	mutex_lock(&sess->tr_id_mutex);

	if (sess->transport_id) {
		tr_id = sess->transport_id;
		tr_id_len = sess->transport_id_len;
	} else {
		res = scst_local_get_sas_transport_id(sess, &tr_id, &tr_id_len);
		if (res != 0)
			goto out_unlock;
	}

	res = 0;
	for (i = 0; i < tr_id_len; i++)
		res += sprintf(&buf[res], "%c", tr_id[i]);

	if (!sess->transport_id)
		kfree(tr_id);

out_unlock:
	mutex_unlock(&sess->tr_id_mutex);
	up_read(&scst_local_exit_rwsem);
	return res;
}

static ssize_t scst_local_transport_id_store(struct kobject *kobj, struct kobj_attribute *attr,
					     const char *buffer, size_t size)
{
	ssize_t res;
	struct scst_session *scst_sess;
	struct scst_local_sess *sess;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = scst_sess_get_tgt_priv(scst_sess);

	mutex_lock(&sess->tr_id_mutex);

	kfree(sess->transport_id);
	sess->transport_id = NULL;
	sess->transport_id_len = 0;

	if (size == 0)
		goto out_res;

	sess->transport_id = kzalloc(size, GFP_KERNEL);
	if (!sess->transport_id) {
		PRINT_ERROR("Allocation of transport_id (size %zd) failed",
			    size);
		res = -ENOMEM;
		goto out_unlock;
	}

	sess->transport_id_len = size;

	memcpy(sess->transport_id, buffer, sess->transport_id_len);

out_res:
	res = size;

out_unlock:
	mutex_unlock(&sess->tr_id_mutex);
	up_read(&scst_local_exit_rwsem);
	return res;
}

static struct kobj_attribute scst_local_transport_id_attr =
	__ATTR(transport_id, 0644,
	       scst_local_transport_id_show,
	       scst_local_transport_id_store);

static const struct attribute *scst_local_sess_attrs[] = {
	&scst_local_host_no_attr.attr,
	&scst_local_transport_id_attr.attr,
	NULL,
};

static ssize_t scst_local_sysfs_add_target(const char *target_name, char *params)
{
	int res;
	struct scst_local_tgt *tgt;
	char *param, *p;

	TRACE_ENTRY();

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	res = scst_local_add_target(target_name, &tgt);
	if (res != 0)
		goto out_up;

	while (1) {
		param = scst_get_next_token_str(&params);
		if (!param)
			break;

		p = scst_get_next_lexem(&param);
		if (*p == '\0')
			break;

		if (strcasecmp("session_name", p) != 0) {
			PRINT_ERROR("Unknown parameter %s", p);
			res = -EINVAL;
			goto out_remove;
		}

		p = scst_get_next_lexem(&param);
		if (*p == '\0') {
			PRINT_ERROR("Wrong session name %s", p);
			res = -EINVAL;
			goto out_remove;
		}

		res = scst_local_add_adapter(tgt, p);
		if (res != 0)
			goto out_remove;
	}

out_up:
	up_read(&scst_local_exit_rwsem);

	TRACE_EXIT_RES(res);
	return res;

out_remove:
	scst_local_remove_target(tgt);
	goto out_up;
}

static ssize_t scst_local_sysfs_del_target(const char *target_name)
{
	int res;
	struct scst_local_tgt *tgt;
	bool deleted = false;

	TRACE_ENTRY();

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	mutex_lock(&scst_local_mutex);
	list_for_each_entry(tgt, &scst_local_tgts_list, tgts_list_entry) {
		if (strcmp(target_name, tgt->scst_tgt->tgt_name) == 0) {
			__scst_local_remove_target(tgt);
			deleted = true;
			break;
		}
	}
	mutex_unlock(&scst_local_mutex);

	if (!deleted) {
		PRINT_ERROR("Target %s not found", target_name);
		res = -ENOENT;
		goto out_up;
	}

	res = 0;

out_up:
	up_read(&scst_local_exit_rwsem);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_local_sysfs_mgmt_cmd(char *buf)
{
	ssize_t res = 0;
	char *command, *target_name, *session_name;
	struct scst_local_tgt *t, *tgt;

	TRACE_ENTRY();

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	command = scst_get_next_lexem(&buf);

	target_name = scst_get_next_lexem(&buf);
	if (*target_name == '\0') {
		PRINT_ERROR("Target name required");
		res = -EINVAL;
		goto out_up;
	}

	mutex_lock(&scst_local_mutex);

	tgt = NULL;
	list_for_each_entry(t, &scst_local_tgts_list, tgts_list_entry) {
		if (strcmp(t->scst_tgt->tgt_name, target_name) == 0) {
			tgt = t;
			break;
		}
	}
	if (!tgt) {
		PRINT_ERROR("Target %s not found", target_name);
		res = -EINVAL;
		goto out_unlock;
	}

	session_name = scst_get_next_lexem(&buf);
	if (*session_name == '\0') {
		PRINT_ERROR("Session name required");
		res = -EINVAL;
		goto out_unlock;
	}

	if (strcasecmp("add_session", command) == 0) {
		res = __scst_local_add_adapter(tgt, session_name, true);
	} else if (strcasecmp("del_session", command) == 0) {
		struct scst_local_sess *s, *sess = NULL;

		list_for_each_entry(s, &tgt->sessions_list, sessions_list_entry) {
			if (strcmp(s->scst_sess->initiator_name, session_name) == 0) {
				sess = s;
				break;
			}
		}
		if (!sess) {
			PRINT_ERROR("Session %s not found (target %s)",
				    session_name, target_name);
			res = -EINVAL;
			goto out_unlock;
		}
		scst_local_close_session_impl(sess, false);
	}

out_unlock:
	mutex_unlock(&scst_local_mutex);

out_up:
	up_read(&scst_local_exit_rwsem);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_local_abort(struct scsi_cmnd *scmd)
{
	struct scst_local_sess *sess;
	int ret;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(scsi_get_device(scmd->device->host));

	ret = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK,
				  blk_mq_unique_tag(scsi_cmd_to_rq(scmd)),
				  false, &dev_reset_completion);

	/* Now wait for the completion ... */
	wait_for_completion_interruptible(&dev_reset_completion);

	atomic_inc(&num_aborts);

	if (ret == 0)
		ret = SUCCESS;

	TRACE_EXIT_RES(ret);
	return ret;
}

static int scst_local_device_reset(struct scsi_cmnd *scmd)
{
	struct scst_local_sess *sess;
	struct scsi_lun lun;
	int ret;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(scsi_get_device(scmd->device->host));

	int_to_scsilun(scmd->device->lun, &lun);

	ret = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_LUN_RESET,
				  lun.scsi_lun, sizeof(lun), false,
				  &dev_reset_completion);

	/* Now wait for the completion ... */
	wait_for_completion_interruptible(&dev_reset_completion);

	atomic_inc(&num_dev_resets);

	if (ret == 0)
		ret = SUCCESS;

	TRACE_EXIT_RES(ret);
	return ret;
}

static int scst_local_target_reset(struct scsi_cmnd *scmd)
{
	struct scst_local_sess *sess;
	struct scsi_lun lun;
	int ret;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(scsi_get_device(scmd->device->host));

	int_to_scsilun(scmd->device->lun, &lun);

	ret = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_TARGET_RESET,
				  lun.scsi_lun, sizeof(lun), false,
				  &dev_reset_completion);

	/* Now wait for the completion ... */
	wait_for_completion_interruptible(&dev_reset_completion);

	atomic_inc(&num_target_resets);

	if (ret == 0)
		ret = SUCCESS;

	TRACE_EXIT_RES(ret);
	return ret;
}

static void scst_local_copy_sense(struct scsi_cmnd *cmnd, struct scst_cmd *scst_cmnd)
{
	int scst_cmnd_sense_len = scst_cmd_get_sense_buffer_len(scst_cmnd);

	TRACE_ENTRY();

	scst_cmnd_sense_len = min(scst_cmnd_sense_len, SCSI_SENSE_BUFFERSIZE);
	memcpy(cmnd->sense_buffer, scst_cmd_get_sense_buffer(scst_cmnd),
	       scst_cmnd_sense_len);

	TRACE_BUFFER("Sense set", cmnd->sense_buffer, scst_cmnd_sense_len);

	TRACE_EXIT();
}

/*
 * Utility function to handle processing of done and allow
 * easy insertion of error injection if desired
 */
static int scst_local_send_resp(struct scsi_cmnd *cmnd,
				struct scst_cmd *scst_cmnd,
				void (*done)(struct scsi_cmnd *),
				int scsi_result)
{
	int ret = 0;

	TRACE_ENTRY();

	if (scst_cmnd) {
		/* The buffer isn't ours, so let's be safe and restore it */
		scst_check_restore_sg_buff(scst_cmnd);

		/* Simulate autosense by this driver */
		if (unlikely(scst_sense_valid(scst_cmnd->sense)))
			scst_local_copy_sense(cmnd, scst_cmnd);
	}

	cmnd->result = scsi_result;

	done(cmnd);

	TRACE_EXIT_RES(ret);
	return ret;
}

/*
 * This does the heavy lifting ... we pass all the commands on to the
 * target driver and have it do its magic ...
 */
static int scst_local_queuecommand(struct Scsi_Host *host,
				   struct scsi_cmnd *scmd)
{
	struct scst_local_sess *sess;
	struct scatterlist *sgl = NULL;
	int sgl_count = 0;
	struct scsi_lun lun;
	struct scst_cmd *scst_cmd = NULL;
	scst_data_direction dir;

	TRACE_ENTRY();

	TRACE_DBG("lun %lld, cmd: 0x%02X", (u64)scmd->device->lun,
		  scmd->cmnd[0]);

	sess = to_scst_lcl_sess(scsi_get_device(scmd->device->host));

	if (sess->unregistering) {
		scmd->result = DID_BAD_TARGET << 16;
		scsi_done(scmd);
		return 0;
	}

	scsi_set_resid(scmd, 0);

	/*
	 * Tell the target that we have a command ... but first we need
	 * to get the LUN into a format that SCST understand
	 *
	 * NOTE! We need to call it with atomic parameter true to not
	 * get into mem alloc deadlock when mounting file systems over
	 * our devices.
	 */
	int_to_scsilun(scmd->device->lun, &lun);
	scst_cmd = scst_rx_cmd(sess->scst_sess, lun.scsi_lun, sizeof(lun),
			       scmd->cmnd, scmd->cmd_len, true);
	if (!scst_cmd) {
		PRINT_ERROR("scst_rx_cmd() failed");
		return SCSI_MLQUEUE_HOST_BUSY;
	}

	scst_cmd_set_tag(scst_cmd, blk_mq_unique_tag(scsi_cmd_to_rq(scmd)));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	if (scmd->device->tagged_supported && scmd->device->simple_tags)
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_SIMPLE);
	else
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
#else
	switch (scsi_get_tag_type(scmd->device)) {
	case MSG_SIMPLE_TAG:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case MSG_HEAD_TAG:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case MSG_ORDERED_TAG:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case SCSI_NO_TAG:
	default:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	}
#endif

	sgl = scsi_sglist(scmd);
	sgl_count = scsi_sg_count(scmd);

	if (scsi_bidi_cmnd(scmd)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(8, 3))
		/* Some of these symbols are only defined after 2.6.24 */
		dir = SCST_DATA_BIDI;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(scmd));
		scst_cmd_set_expected_out_transfer_len(scst_cmd, scsi_in(scmd)->length);
		scst_cmd_set_noio_mem_alloc(scst_cmd);
		scst_cmd_set_tgt_sg(scst_cmd, scsi_in(scmd)->table.sgl,
				    scsi_in(scmd)->table.nents);
		scst_cmd_set_tgt_out_sg(scst_cmd, sgl, sgl_count);
#endif
	} else if (scmd->sc_data_direction == DMA_TO_DEVICE) {
		dir = SCST_DATA_WRITE;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(scmd));
		scst_cmd_set_noio_mem_alloc(scst_cmd);
		scst_cmd_set_tgt_sg(scst_cmd, sgl, sgl_count);
	} else if (scmd->sc_data_direction == DMA_FROM_DEVICE) {
		dir = SCST_DATA_READ;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(scmd));
		scst_cmd_set_noio_mem_alloc(scst_cmd);
		scst_cmd_set_tgt_sg(scst_cmd, sgl, sgl_count);
	} else {
		dir = SCST_DATA_NONE;
		scst_cmd_set_expected(scst_cmd, dir, 0);
	}

	/* Save the correct thing below depending on version */
	scst_cmd_set_tgt_priv(scst_cmd, scmd);

	scst_cmd_init_done(scst_cmd, SCST_CONTEXT_THREAD);

	TRACE_EXIT();
	return 0;
}

static int scst_local_targ_pre_exec(struct scst_cmd *scst_cmd)
{
	int res = SCST_PREPROCESS_STATUS_SUCCESS;

	TRACE_ENTRY();

	if (scst_cmd_get_dh_data_buff_alloced(scst_cmd) &&
	    (scst_cmd_get_data_direction(scst_cmd) & SCST_DATA_WRITE))
		scst_copy_sg(scst_cmd, SCST_SG_COPY_FROM_TARGET);

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_local_get_max_queue_depth(struct scsi_device *sdev)
{
	int res;
	struct scst_local_sess *sess;
	struct scsi_lun lun;

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(scsi_get_device(sdev->host));
	int_to_scsilun(sdev->lun, &lun);
	res = scst_get_max_lun_commands(sess->scst_sess,
					scst_unpack_lun(lun.scsi_lun,
							sizeof(lun)));

	TRACE_EXIT_RES(res);
	return res;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)

static int scst_local_change_queue_depth(struct scsi_device *sdev, int depth)
{
	return scsi_change_queue_depth(sdev, depth);
}

#else

static int scst_local_change_queue_depth(struct scsi_device *sdev, int depth, int reason)
{
	int res, mqd;

	TRACE_ENTRY();

	switch (reason) {
	case SCSI_QDEPTH_DEFAULT:
		mqd = scst_local_get_max_queue_depth(sdev);
		if (mqd < depth) {
			PRINT_INFO("Requested queue depth %d is too big (possible max %d (sdev %p)",
				   depth, mqd, sdev);
			res = -EINVAL;
			goto out;
		}

		PRINT_INFO("Setting queue depth %d as default (sdev %p, current %d)",
			   depth, sdev, sdev->queue_depth);
		scsi_adjust_queue_depth(sdev, scsi_get_tag_type(sdev), depth);
		break;

	case SCSI_QDEPTH_QFULL:
		TRACE(TRACE_FLOW_CONTROL, "QUEUE FULL on sdev %p, setting qdepth %d (cur %d)",
		      sdev, depth, sdev->queue_depth);
		scsi_track_queue_full(sdev, depth);
		break;

	case SCSI_QDEPTH_RAMP_UP:
		TRACE(TRACE_FLOW_CONTROL, "Ramping up qdepth on sdev %p to %d (cur %d)",
		      sdev, depth, sdev->queue_depth);
		scsi_adjust_queue_depth(sdev, scsi_get_tag_type(sdev), depth);
		break;

	default:
		res = -EOPNOTSUPP;
		goto out;
	}

	res = sdev->queue_depth;

out:
	TRACE_EXIT_RES(res);
	return res;
}

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
static int scst_local_slave_alloc(struct scsi_device *sdev)
{
	struct request_queue *q = sdev->request_queue;

#ifdef QUEUE_FLAG_BIDI
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0) &&	\
	!defined(CONFIG_SUSE_KERNEL)
#if !defined(RHEL_MAJOR) || RHEL_MAJOR -0 >= 6
	queue_flag_set_unlocked(QUEUE_FLAG_BIDI, q);
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	blk_queue_flag_set(QUEUE_FLAG_BIDI, q);
#endif
#endif

	/*
	 * vdisk_blockio requires that data buffers have block_size alignment
	 * and supports block sizes from 512 up to 4096. See also
	 * https://github.com/sahlberg/libiscsi/issues/302.
	 */
	blk_queue_dma_alignment(q, (4096 - 1));

	return 0;
}
#endif

static int scst_local_slave_configure(struct scsi_device *sdev)
{
	int mqd;

	TRACE_ENTRY();

	mqd = scst_local_get_max_queue_depth(sdev);

	PRINT_INFO("Configuring queue depth %d on sdev %p (tagged supported %d)",
		   mqd, sdev, sdev->tagged_supported);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	if (sdev->tagged_supported)
		scsi_activate_tcq(sdev, mqd);
	else
		scsi_deactivate_tcq(sdev, mqd);
#endif

	TRACE_EXIT();
	return 0;
}

/* Must be called under sess->aen_lock. Drops then reacquires it inside. */
static void scst_process_aens(struct scst_local_sess *sess, bool cleanup_only)
	__releases(&sess->aen_lock)
	__acquires(&sess->aen_lock)
{
	struct scst_aen_work_item *work_item = NULL;
	struct Scsi_Host *shost;

	TRACE_ENTRY();

	TRACE_DBG("Target work sess %p", sess);

	while (!list_empty(&sess->aen_work_list)) {
		work_item = list_first_entry(&sess->aen_work_list, struct scst_aen_work_item,
					     work_list_entry);
		list_del(&work_item->work_list_entry);
		shost = sess->shost;
		if (shost && !scsi_host_get(shost))
			shost = NULL;
		spin_unlock(&sess->aen_lock);

		if (cleanup_only)
			goto done;

		sBUG_ON(work_item->aen->event_fn != SCST_AEN_SCSI);

		/* Let's always rescan */
		if (shost)
			scsi_scan_target(&shost->shost_gendev, 0, 0,
					 SCAN_WILD_CARD, 1);

done:
		scst_aen_done(work_item->aen);
		kfree(work_item);

		if (shost)
			scsi_host_put(shost);

		spin_lock(&sess->aen_lock);
	}

	TRACE_EXIT();
}

static void scst_aen_work_fn(struct work_struct *work)
{
	struct scst_local_sess *sess =
		container_of(work, struct scst_local_sess, aen_work);

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Target work %p)", sess);

	spin_lock(&sess->aen_lock);
	scst_process_aens(sess, false);
	spin_unlock(&sess->aen_lock);

	TRACE_EXIT();
}

static int scst_local_report_aen(struct scst_aen *aen)
{
	int res = 0;
	int event_fn = scst_aen_get_event_fn(aen);
	struct scst_local_sess *sess;
	struct scst_aen_work_item *work_item = NULL;

	TRACE_ENTRY();

	sess = scst_sess_get_tgt_priv(scst_aen_get_sess(aen));
	switch (event_fn) {
	case SCST_AEN_SCSI:
		/*
		 * Allocate a work item and place it on the queue
		 */
		work_item = kzalloc(sizeof(*work_item), GFP_KERNEL);
		if (!work_item) {
			PRINT_ERROR("Unable to allocate work item to handle AEN!");
			return -ENOMEM;
		}

		spin_lock(&sess->aen_lock);

		if (unlikely(sess->unregistering)) {
			spin_unlock(&sess->aen_lock);
			kfree(work_item);
			res = SCST_AEN_RES_NOT_SUPPORTED;
			goto out;
		}

		list_add_tail(&work_item->work_list_entry, &sess->aen_work_list);
		work_item->aen = aen;

		spin_unlock(&sess->aen_lock);

		/*
		 * We might queue the same item over and over, but that is OK
		 * It will be ignored by queue_work if it is already queued.
		 */
		queue_work(aen_workqueue, &sess->aen_work);
		break;

	default:
		TRACE_MGMT_DBG("Unsupported AEN %d", event_fn);
		res = SCST_AEN_RES_NOT_SUPPORTED;
		break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_local_targ_release(struct scst_tgt *tgt)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return 0;
}

static void scst_remove_work_fn(struct work_struct *work)
{
	struct scst_local_sess *sess =
		container_of(work, struct scst_local_sess, remove_work);

	scst_local_remove_adapter(sess);
}

static void scst_local_close_session_impl(struct scst_local_sess *sess,
					  bool async)
{
	bool unregistering;

	spin_lock(&sess->aen_lock);
	unregistering = sess->unregistering;
	sess->unregistering = 1;
	spin_unlock(&sess->aen_lock);

	if (!unregistering) {
		if (async)
			schedule_work(&sess->remove_work);
		else
			scst_local_remove_adapter(sess);
	}
}

/*
 * Perform removal from the context of another thread since the caller may
 * already hold an SCST mutex, since scst_local_remove_adapter() triggers a
 * call of device_unregister(), since device_unregister() invokes
 * device_del(), since device_del() locks the same mutex that is held while
 * invoking scst_add() from class_interface_register() and since scst_add()
 * also may lock an SCST mutex.
 */
static int scst_local_close_session(struct scst_session *scst_sess)
{
	struct scst_local_sess *sess = scst_sess_get_tgt_priv(scst_sess);

	scst_local_close_session_impl(sess, true);
	return 0;
}

static int scst_local_targ_xmit_response(struct scst_cmd *scst_cmd)
{
	struct scsi_cmnd *scmd = NULL;
	void (*done)(struct scsi_cmnd *scmd);

	TRACE_ENTRY();

	if (unlikely(scst_cmd_aborted_on_xmit(scst_cmd))) {
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);
		scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);
		return SCST_TGT_RES_SUCCESS;
	}

	if (scst_cmd_get_dh_data_buff_alloced(scst_cmd) &&
	    (scst_cmd_get_data_direction(scst_cmd) & SCST_DATA_READ))
		scst_copy_sg(scst_cmd, SCST_SG_COPY_TO_TARGET);

	scmd = scst_cmd_get_tgt_priv(scst_cmd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
	done = scmd->scsi_done;
#else
	done = scsi_done;
#endif

	/*
	 * This might have to change to use the two status flags
	 */
	if (scst_cmd_get_is_send_status(scst_cmd)) {
		int resid = 0, out_resid = 0;

		/* Calculate the residual ... */
		if (likely(!scst_get_resid(scst_cmd, &resid, &out_resid))) {
			TRACE_DBG("No residuals for request %p", scmd);
		} else {
			if (out_resid != 0)
				PRINT_ERROR("Unable to return OUT residual %d (op %02x)",
					    out_resid, scmd->cmnd[0]);
		}

		scsi_set_resid(scmd, resid);

		/*
		 * It seems like there is no way to set out_resid ...
		 */

		(void)scst_local_send_resp(scmd, scst_cmd, done,
					   scst_cmd_get_status(scst_cmd));
	}

	/* Now tell SCST that the command is done ... */
	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);

	TRACE_EXIT();
	return SCST_TGT_RES_SUCCESS;
}

static void scst_local_targ_task_mgmt_done(struct scst_mgmt_cmd *mgmt_cmd)
{
	struct completion *compl;

	TRACE_ENTRY();

	compl = scst_mgmt_cmd_get_tgt_priv(mgmt_cmd);
	if (compl)
		complete(compl);

	TRACE_EXIT();
}

static uint16_t scst_local_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	struct scst_local_tgt *tgt = scst_tgt_get_tgt_priv(scst_tgt);

	/*
	 * It's OK to not check tgt != NULL here, because new sessions
	 * can't create before its' set.
	 */

	if (tgt->scsi_transport_version == 0)
		return 0x0BE0; /* SAS */
	else
		return tgt->scsi_transport_version;
}

static uint16_t scst_local_get_phys_transport_version(struct scst_tgt *scst_tgt)
{
	struct scst_local_tgt *tgt = scst_tgt_get_tgt_priv(scst_tgt);

	/*
	 * It's OK to not check tgt != NULL here, because new sessions
	 * can't create before its' set.
	 */

	return tgt->phys_transport_version;
}

static struct scst_tgt_template scst_local_targ_tmpl = {
	.name			= "scst_local",
	.sg_tablesize		= 0xffff,
	.xmit_response_atomic	= 1,
	.multithreaded_init_done = 1,
	.enabled_attr_not_needed = 1,
	.tgtt_attrs		= scst_local_tgtt_attrs,
	.tgt_attrs		= scst_local_tgt_attrs,
	.sess_attrs		= scst_local_sess_attrs,
	.add_target		= scst_local_sysfs_add_target,
	.del_target		= scst_local_sysfs_del_target,
	.mgmt_cmd		= scst_local_sysfs_mgmt_cmd,
	.add_target_parameters	= "session_name",
	.mgmt_cmd_help		= "       echo \"add_session target_name session_name\" >mgmt\n"
				  "       echo \"del_session target_name session_name\" >mgmt\n",
	.release		= scst_local_targ_release,
	.close_session		= scst_local_close_session,
	.pre_exec		= scst_local_targ_pre_exec,
	.xmit_response		= scst_local_targ_xmit_response,
	.task_mgmt_fn_done	= scst_local_targ_task_mgmt_done,
	.report_aen		= scst_local_report_aen,
	.get_initiator_port_transport_id = scst_local_get_initiator_port_transport_id,
	.get_scsi_transport_version = scst_local_get_scsi_transport_version,
	.get_phys_transport_version = scst_local_get_phys_transport_version,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags = SCST_LOCAL_DEFAULT_LOG_FLAGS,
	.trace_flags = &trace_flag,
#endif
};

static const struct scsi_host_template scst_lcl_ini_driver_template = {
	.name				= SCST_LOCAL_NAME,
	.queuecommand			= scst_local_queuecommand,
	.change_queue_depth		= scst_local_change_queue_depth,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
	.slave_alloc			= scst_local_slave_alloc,
#else
	.dma_alignment			= (4096 - 1),
#endif
	.slave_configure		= scst_local_slave_configure,
	.eh_abort_handler		= scst_local_abort,
	.eh_device_reset_handler	= scst_local_device_reset,
	.eh_target_reset_handler	= scst_local_target_reset,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	.use_blk_tags			= true,
#endif
	.can_queue			= 2048,
	/*
	 * Set it low for the "Drop back to untagged" case in
	 * scsi_track_queue_full(). We are adjusting it to a better
	 * default in slave_configure()
	 */
	.cmd_per_lun			= 3,
	.this_id			= -1,
	.sg_tablesize			= 0xFFFF,
	.max_sectors			= 0xffff,
	/* Possible pass-through backend device may not support clustering */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 21, 0)
	.use_clustering			= DISABLE_CLUSTERING,
#else
	.dma_boundary			= PAGE_SIZE - 1,
	.max_segment_size		= PAGE_SIZE,
#endif
	.skip_settle_delay		= 1,
	.module				= THIS_MODULE,
};

/*
 * LLD Bus and functions
 */

static int scst_local_driver_probe(struct device *dev)
{
	int ret;
	struct scst_local_sess *sess;
	struct Scsi_Host *hpnt;

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(dev);

	TRACE_DBG("sess %p", sess);

	hpnt = scsi_host_alloc((struct scsi_host_template *)&scst_lcl_ini_driver_template,
			       sizeof(*sess));
	if (!hpnt) {
		PRINT_ERROR("scsi_register() failed");
		ret = -ENODEV;
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	hpnt->nr_hw_queues = num_possible_cpus();
#endif

	sess->shost = hpnt;

	hpnt->max_id = 1;        /* Don't want more than one id */
	hpnt->max_lun = SCST_MAX_LUN + 1;

	/*
	 * Because of a change in the size of this field at 2.6.26
	 * we use this check ... it allows us to work on earlier
	 * kernels. If we don't,  max_cmd_size gets set to 4 (and we get
	 * a compiler warning) so a scan never occurs.
	 */
	hpnt->max_cmd_len = 260;

	ret = scsi_add_host(hpnt, &sess->dev);
	if (ret) {
		PRINT_ERROR("scsi_add_host() failed");
		ret = -ENODEV;
		scsi_host_put(hpnt);
		goto out;
	}

out:
	TRACE_EXIT_RES(ret);
	return ret;
}

/*
 * See also commit fc7a6209d571 ("bus: Make remove callback return void")
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 2))
#define DRIVER_REMOVE_RET int
#else
#define DRIVER_REMOVE_RET void
#endif

static DRIVER_REMOVE_RET scst_local_driver_remove(struct device *dev)
{
	struct scst_local_sess *sess;
	struct Scsi_Host *shost = NULL;

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(dev);

	spin_lock(&sess->aen_lock);
	swap(sess->shost, shost);
	spin_unlock(&sess->aen_lock);

	scsi_remove_host(shost);
	scsi_host_put(shost);

	TRACE_EXIT();
	return (DRIVER_REMOVE_RET)0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0)
static int scst_local_bus_match(struct device *dev, struct device_driver *drv)
#else
static int scst_local_bus_match(struct device *dev, const struct device_driver *drv)
#endif
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return 1;
}

static struct bus_type scst_local_lld_bus = {
	.name   = "scst_local_bus",
	.match  = scst_local_bus_match,
	.probe  = scst_local_driver_probe,
	.remove = scst_local_driver_remove,
};

static struct device_driver scst_local_driver = {
	.name	= SCST_LOCAL_NAME,
	.bus	= &scst_local_lld_bus,
};

static struct device *scst_local_root;

static void scst_local_free_sess(struct scst_session *scst_sess)
{
	struct scst_local_sess *sess = scst_sess_get_tgt_priv(scst_sess);

	kfree(sess);
}

static void scst_local_release_adapter(struct device *dev)
{
	struct scst_local_sess *sess;

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(dev);

	/*
	 * At this point the SCSI device is almost gone because the SCSI
	 * Mid Layer calls us when the device is being unregistered. However,
	 * SCST might have queued some AENs to us that have not yet been
	 * processed when unregister_device started working.
	 *
	 * To prevent a race between us and AEN handling we must flush the
	 * workqueue before we clean up the AEN list (calling scst_process_aens
	 * with cleanup_only set to true) and then unregister the session.
	 *
	 * For kernels after 2.6.22 it is sufficient to cancel any outstanding
	 * work.
	 */

	cancel_work_sync(&sess->aen_work);

	spin_lock(&sess->aen_lock);
	WARN_ON_ONCE(!sess->unregistering);
	scst_process_aens(sess, true);
	spin_unlock(&sess->aen_lock);

	scst_unregister_session(sess->scst_sess, false, scst_local_free_sess);

	TRACE_EXIT();
}

static int __scst_local_add_adapter(struct scst_local_tgt *tgt, const char *initiator_name,
				    bool locked)
{
	int res;
	struct scst_local_sess *sess;

	TRACE_ENTRY();

	/* It's read-mostly, so cache alignment isn't needed */
	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		PRINT_ERROR("Unable to alloc scst_lcl_host (size %zu)",
			    sizeof(*sess));
		res = -ENOMEM;
		goto out;
	}

	sess->tgt = tgt;
	sess->number = atomic_inc_return(&scst_local_sess_num);
	mutex_init(&sess->tr_id_mutex);

	/*
	 * Init this stuff we need for scheduling AEN work
	 */
	INIT_WORK(&sess->aen_work, scst_aen_work_fn);
	INIT_WORK(&sess->remove_work, scst_remove_work_fn);
	spin_lock_init(&sess->aen_lock);
	INIT_LIST_HEAD(&sess->aen_work_list);

	sess->scst_sess = scst_register_session(tgt->scst_tgt, 0, initiator_name, sess, NULL,
						NULL);
	if (!sess->scst_sess) {
		PRINT_ERROR("scst_register_session failed");
		res = -EFAULT;
		goto out_free;
	}

	sess->dev.bus     = &scst_local_lld_bus;
	sess->dev.parent = scst_local_root;
	sess->dev.release = &scst_local_release_adapter;
	sess->dev.init_name = kobject_name(&sess->scst_sess->sess_kobj);

	res = device_register(&sess->dev);
	if (res != 0)
		goto unregister_session;

	res = sysfs_create_link(scst_sysfs_get_sess_kobj(sess->scst_sess),
				&sess->shost->shost_dev.kobj, "host");
	if (res != 0) {
		PRINT_ERROR("Unable to create \"host\" link for target %s",
			    scst_get_tgt_name(tgt->scst_tgt));
		goto unregister_dev;
	}

	if (!locked)
		mutex_lock(&scst_local_mutex);
	list_add_tail(&sess->sessions_list_entry, &tgt->sessions_list);
	if (!locked)
		mutex_unlock(&scst_local_mutex);

	if (scst_initiator_has_luns(tgt->scst_tgt, initiator_name))
		scsi_scan_target(&sess->shost->shost_gendev, 0, 0,
				 SCAN_WILD_CARD, 1);

out:
	TRACE_EXIT_RES(res);
	return res;

unregister_dev:
	device_unregister(&sess->dev);
	goto out;

unregister_session:
	scst_unregister_session(sess->scst_sess, true, NULL);

out_free:
	kfree(sess);
	goto out;
}

static int scst_local_add_adapter(struct scst_local_tgt *tgt, const char *initiator_name)
{
	return __scst_local_add_adapter(tgt, initiator_name, false);
}

/* Must be called under scst_local_mutex */
static void scst_local_remove_adapter(struct scst_local_sess *sess)
{
	TRACE_ENTRY();

	list_del(&sess->sessions_list_entry);

	device_unregister(&sess->dev);

	TRACE_EXIT();
}

static int scst_local_add_target(const char *target_name, struct scst_local_tgt **out_tgt)
{
	int res;
	struct scst_local_tgt *tgt;

	TRACE_ENTRY();

	tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
	if (!tgt) {
		PRINT_ERROR("Unable to alloc tgt (size %zu)", sizeof(*tgt));
		res = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&tgt->sessions_list);

	tgt->scst_tgt = scst_register_target(&scst_local_targ_tmpl, target_name);
	if (!tgt->scst_tgt) {
		res = -EFAULT;
		goto out_free;
	}

	scst_tgt_set_tgt_priv(tgt->scst_tgt, tgt);

	mutex_lock(&scst_local_mutex);
	list_add_tail(&tgt->tgts_list_entry, &scst_local_tgts_list);
	mutex_unlock(&scst_local_mutex);

	res = 0;

	if (out_tgt)
		*out_tgt = tgt;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(tgt);
	goto out;
}

/* Must be called under scst_local_mutex */
static void __scst_local_remove_target(struct scst_local_tgt *tgt)
{
	struct scst_local_sess *sess, *ts;

	TRACE_ENTRY();

	list_for_each_entry_safe(sess, ts, &tgt->sessions_list, sessions_list_entry)
		scst_local_close_session_impl(sess, false);

	list_del(&tgt->tgts_list_entry);

	scst_unregister_target(tgt->scst_tgt);

	kfree(tgt);

	TRACE_EXIT();
}

static void scst_local_remove_target(struct scst_local_tgt *tgt)
{
	TRACE_ENTRY();

	mutex_lock(&scst_local_mutex);
	__scst_local_remove_target(tgt);
	mutex_unlock(&scst_local_mutex);

	TRACE_EXIT();
}

static int __init scst_local_init(void)
{
	int ret;
	struct scst_local_tgt *tgt;

	TRACE_ENTRY();

#ifndef INSIDE_KERNEL_TREE
#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
	PRINT_ERROR("HIGHMEM kernel configurations are not supported. "
		    "Consider changing VMSPLIT option or use a 64-bit configuration instead. "
		    "See SCST core README file for details.");
	ret = -EINVAL;
	goto out;
#endif
#endif

	scst_local_root = root_device_register(SCST_LOCAL_NAME);
	if (IS_ERR(scst_local_root)) {
		ret = PTR_ERR(scst_local_root);
		goto out;
	}

	ret = bus_register(&scst_local_lld_bus);
	if (ret < 0) {
		PRINT_ERROR("bus_register() error: %d", ret);
		goto dev_unreg;
	}

	ret = driver_register(&scst_local_driver);
	if (ret < 0) {
		PRINT_ERROR("driver_register() error: %d", ret);
		goto bus_unreg;
	}

	ret = scst_register_target_template(&scst_local_targ_tmpl);
	if (ret != 0) {
		PRINT_ERROR("Unable to register target template: %d", ret);
		goto driver_unreg;
	}

	/*
	 * We don't expect much work on this queue, so only create a
	 * single thread workqueue rather than one on each core.
	 */
	aen_workqueue = alloc_ordered_workqueue("scstlclaen", WQ_MEM_RECLAIM);
	if (!aen_workqueue) {
		PRINT_ERROR("Unable to create scst_local workqueue");
		goto tgt_templ_unreg;
	}

	/* Don't add a default target unless we are told to do so. */
	if (!scst_local_add_default_tgt)
		goto out;

	ret = scst_local_add_target("scst_local_tgt", &tgt);
	if (ret != 0)
		goto workqueue_unreg;

	ret = scst_local_add_adapter(tgt, "scst_local_host");
	if (ret != 0)
		goto tgt_unreg;

out:
	TRACE_EXIT_RES(ret);
	return ret;

tgt_unreg:
	scst_local_remove_target(tgt);

workqueue_unreg:
	destroy_workqueue(aen_workqueue);

tgt_templ_unreg:
	scst_unregister_target_template(&scst_local_targ_tmpl);

driver_unreg:
	driver_unregister(&scst_local_driver);

bus_unreg:
	bus_unregister(&scst_local_lld_bus);

dev_unreg:
	root_device_unregister(scst_local_root);

	goto out;
}

static void __exit scst_local_exit(void)
{
	struct scst_local_tgt *tgt, *tt;

	TRACE_ENTRY();

	down_write(&scst_local_exit_rwsem);

	mutex_lock(&scst_local_mutex);
	list_for_each_entry_safe(tgt, tt, &scst_local_tgts_list,
				 tgts_list_entry) {
		__scst_local_remove_target(tgt);
	}
	mutex_unlock(&scst_local_mutex);

	destroy_workqueue(aen_workqueue);

	driver_unregister(&scst_local_driver);
	bus_unregister(&scst_local_lld_bus);
	root_device_unregister(scst_local_root);

	/* Now unregister the target template */
	scst_unregister_target_template(&scst_local_targ_tmpl);

	/* To make lockdep happy */
	up_write(&scst_local_exit_rwsem);

	TRACE_EXIT();
}

device_initcall(scst_local_init);
module_exit(scst_local_exit);
