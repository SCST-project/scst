/*
 * Copyright (C) 2008 Richard Sharpe
 * Copyright (C) 1992 Eric Youngdale
 * Copyright (C) 2008 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *
 * Simulate a host adapter and an SCST target adapter back to back
 *
 * Based on the scsi_debug.c driver originally by Eric Youngdale and
 * others, including D Gilbert et al
 *
 */

#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/init.h>
#ifdef CONFIG_SCST_PROC
#include <linux/proc_fs.h>
#endif
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/spinlock.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>

#define LOG_PREFIX "scst_local"

/* SCST includes ... */
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_const.h>
#include <scst/scst.h>
#include <scst/scst_debug.h>
#else
#include <scst_const.h>
#include <scst.h>
#include <scst_debug.h>
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
#define SG_MAX_SINGLE_ALLOC	(PAGE_SIZE / sizeof(struct scatterlist))
#endif

#ifndef INSIDE_KERNEL_TREE
#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
#warning "HIGHMEM kernel configurations are not supported by this module,\
 because nowadays it isn't worth the effort. Consider changing\
 VMSPLIT option or use a 64-bit configuration instead. See SCST core\
 README file for details."
#endif
#endif

#ifdef CONFIG_SCST_DEBUG
#define SCST_LOCAL_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_PID | \
	TRACE_LINE | TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL)
#else
# ifdef CONFIG_SCST_TRACING
#define SCST_LOCAL_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_SPECIAL)
# endif
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
#define trace_flag scst_local_trace_flag
static unsigned long scst_local_trace_flag = SCST_LOCAL_DEFAULT_LOG_FLAGS;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
/*
 * Provide some local definitions that are not provided for some earlier
 * kernels so we operate over a wider range of kernels
 *
 * Some time before 2.6.24 scsi_sg_count, scsi_sglist and scsi_bufflen were
 * not available. Make it available for 2.6.18 which is used still on some
 * distros, like CentOS etc.
 */
#define scsi_sg_count(cmd) ((cmd)->use_sg)
#define scsi_sglist(cmd) ((struct scatterlist *)(cmd)->request_buffer)
#define scsi_bufflen(cmd) ((cmd)->request_bufflen)
#endif

#define TRUE 1
#define FALSE 0

#define SCST_LOCAL_VERSION "1.0.0"
static const char *scst_local_version_date = "20100910";

/* Some statistics */
static atomic_t num_aborts = ATOMIC_INIT(0);
static atomic_t num_dev_resets = ATOMIC_INIT(0);
static atomic_t num_target_resets = ATOMIC_INIT(0);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31) \
    || defined(RHEL_MAJOR) && RHEL_MAJOR -0 <= 5
static int scst_local_add_default_tgt;
#else
static bool scst_local_add_default_tgt;
#endif
module_param_named(add_default_tgt, scst_local_add_default_tgt, bool, S_IRUGO);
MODULE_PARM_DESC(add_default_host, "add or not (default) on start default "
	"target scst_local_tgt with default session scst_local_host");

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

	struct list_head sessions_list_entry;
};

#define to_scst_lcl_sess(d) \
	container_of(d, struct scst_local_sess, dev)

static int __scst_local_add_adapter(struct scst_local_tgt *tgt,
	const char *initiator_name, struct scst_local_sess **out_sess,
	bool locked);
static int scst_local_add_adapter(struct scst_local_tgt *tgt,
	const char *initiator_name, struct scst_local_sess **out_sess);
static void scst_local_remove_adapter(struct scst_local_sess *sess);
static int scst_local_add_target(const char *target_name,
	struct scst_local_tgt **out_tgt);
static void __scst_local_remove_target(struct scst_local_tgt *tgt);
static void scst_local_remove_target(struct scst_local_tgt *tgt);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))

/*
 * Maintains data that is needed during command processing ...
 * We have a single element scatterlist in here in case the scst_cmnd
 * we are given has a buffer, not a scatterlist, but we only need this for
 * kernels less than 2.6.25.
 */
struct scst_local_tgt_specific {
	struct scsi_cmnd *cmnd;
	void (*done)(struct scsi_cmnd *);
	struct scatterlist sgl;
};

/*
 * We use a pool of objects maintaind by the kernel so that it is less
 * likely to have to allocate them when we are in the data path.
 *
 * Note, we only need this for kernels in which we are likely to get non
 * scatterlist requests.
 */
static struct kmem_cache *tgt_specific_pool;

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)) */

static atomic_t scst_local_sess_num = ATOMIC_INIT(0);

static LIST_HEAD(scst_local_tgts_list);
static DEFINE_MUTEX(scst_local_mutex);

static DECLARE_RWSEM(scst_local_exit_rwsem);

MODULE_AUTHOR("Richard Sharpe, Vladislav Bolkhovitin + ideas from SCSI_DEBUG");
MODULE_DESCRIPTION("SCSI+SCST local adapter driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(SCST_LOCAL_VERSION);

static int scst_local_get_sas_transport_id(struct scst_local_sess *sess,
	uint8_t **transport_id, int *len)
{
	int res = 0;
	int tr_id_size = 0;
	uint8_t *tr_id = NULL;

	TRACE_ENTRY();

	tr_id_size = 24;  /* A SAS TransportID */

	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (tr_id == NULL) {
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
	tr_id[8]  = 0x0F | (sess->number & 0xF0);
	tr_id[9]  = 0xAD;
	tr_id[10] = 0xE0;
	tr_id[11] = 0x50;

	*transport_id = tr_id;
	*len = tr_id_size;

	TRACE_DBG("Created tid '%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X'",
		tr_id[4], tr_id[5], tr_id[6], tr_id[7],
		tr_id[8], tr_id[9], tr_id[10], tr_id[11]);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_local_get_initiator_port_transport_id(
	struct scst_session *scst_sess, uint8_t **transport_id)
{
	int res = 0;
	int tr_id_size = 0;
	uint8_t *tr_id = NULL;
	struct scst_local_sess *sess;

	TRACE_ENTRY();

	if (scst_sess == NULL) {
		res = SCSI_TRANSPORTID_PROTOCOLID_SAS;
		goto out;
	}

	sess = (struct scst_local_sess *)scst_sess_get_tgt_priv(scst_sess);

	mutex_lock(&sess->tr_id_mutex);

	if (sess->transport_id == NULL) {
		res = scst_local_get_sas_transport_id(sess,
				transport_id, &tr_id_size);
		goto out_unlock;
	}

	tr_id_size = sess->transport_id_len;
	sBUG_ON(tr_id_size == 0);

	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (tr_id == NULL) {
		PRINT_ERROR("Allocation of TransportID (size %d) failed",
			tr_id_size);
		res = -ENOMEM;
		goto out;
	}

	memcpy(tr_id, sess->transport_id, sess->transport_id_len);

out_unlock:
	mutex_unlock(&sess->tr_id_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

#ifdef CONFIG_SCST_PROC

static int scst_local_proc_info(struct Scsi_Host *host, char *buffer,
				char **start, off_t offset, int length,
				int inout)
{
	int len, pos, begin;

	TRACE_ENTRY();

	if (inout == 1)
		return -EACCES;

	begin = 0;
	pos = len = sprintf(buffer, "scst_local adapter driver, version "
		"%s [%s]\nAborts=%d, Device Resets=%d, Target Resets=%d\n",
		SCST_LOCAL_VERSION, scst_local_version_date,
		atomic_read(&num_aborts), atomic_read(&num_dev_resets),
		atomic_read(&num_target_resets));
	if (pos < offset) {
		len = 0;
		begin = pos;
	}
	if (start)
		*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;

	TRACE_EXIT_RES(len);
	return len;
}

static const char *scst_local_info(struct Scsi_Host *shp)
{
	static char scst_local_info_buf[256];

	TRACE_ENTRY();

	sprintf(scst_local_info_buf, "scst_local, version %s [%s], "
		"Aborts: %d, Device Resets: %d, Target Resets: %d",
		SCST_LOCAL_VERSION, scst_local_version_date,
		atomic_read(&num_aborts), atomic_read(&num_dev_resets),
		atomic_read(&num_target_resets));

	TRACE_EXIT();
	return scst_local_info_buf;
}

#else /* CONFIG_SCST_PROC */

/**
 ** Tgtt attributes
 **/

static ssize_t scst_local_version_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
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
	__ATTR(version, S_IRUGO, scst_local_version_show, NULL);

static ssize_t scst_local_stats_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)

{
	return sprintf(buf, "Aborts: %d, Device Resets: %d, Target Resets: %d",
		atomic_read(&num_aborts), atomic_read(&num_dev_resets),
		atomic_read(&num_target_resets));
}

static struct kobj_attribute scst_local_stats_attr =
	__ATTR(stats, S_IRUGO, scst_local_stats_show, NULL);

static const struct attribute *scst_local_tgtt_attrs[] = {
	&scst_local_version_attr.attr,
	&scst_local_stats_attr.attr,
	NULL,
};

/**
 ** Tgt attributes
 **/

static ssize_t scst_local_scsi_transport_version_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	ssize_t res;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct scst_local_tgt *)scst_tgt_get_tgt_priv(scst_tgt);

	if (tgt->scsi_transport_version != 0)
		res = sprintf(buf, "0x%x\n%s", tgt->scsi_transport_version,
			SCST_SYSFS_KEY_MARK "\n");
	else
		res = sprintf(buf, "0x%x\n", 0x0BE0); /* SAS */

	up_read(&scst_local_exit_rwsem);
	return res;
}

static ssize_t scst_local_scsi_transport_version_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	ssize_t res;
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	unsigned long val;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct scst_local_tgt *)scst_tgt_get_tgt_priv(scst_tgt);

	res = strict_strtoul(buffer, 0, &val);
	if (res != 0) {
		PRINT_ERROR("strict_strtoul() for %s failed: %zd", buffer, res);
		goto out_up;
	}

	tgt->scsi_transport_version = val;

	res = size;

out_up:
	up_read(&scst_local_exit_rwsem);
	return res;
}

static struct kobj_attribute scst_local_scsi_transport_version_attr =
	__ATTR(scsi_transport_version, S_IRUGO | S_IWUSR,
		scst_local_scsi_transport_version_show,
		scst_local_scsi_transport_version_store);

static ssize_t scst_local_phys_transport_version_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	ssize_t res;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct scst_local_tgt *)scst_tgt_get_tgt_priv(scst_tgt);

	res = sprintf(buf, "0x%x\n%s", tgt->phys_transport_version,
			(tgt->phys_transport_version != 0) ?
				SCST_SYSFS_KEY_MARK "\n" : "");

	up_read(&scst_local_exit_rwsem);
	return res;
}

static ssize_t scst_local_phys_transport_version_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	ssize_t res;
	struct scst_tgt *scst_tgt;
	struct scst_local_tgt *tgt;
	unsigned long val;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_tgt = container_of(kobj, struct scst_tgt, tgt_kobj);
	tgt = (struct scst_local_tgt *)scst_tgt_get_tgt_priv(scst_tgt);

	res = strict_strtoul(buffer, 0, &val);
	if (res != 0) {
		PRINT_ERROR("strict_strtoul() for %s failed: %zd", buffer, res);
		goto out_up;
	}

	tgt->phys_transport_version = val;

	res = size;

out_up:
	up_read(&scst_local_exit_rwsem);
	return res;
}

static struct kobj_attribute scst_local_phys_transport_version_attr =
	__ATTR(phys_transport_version, S_IRUGO | S_IWUSR,
		scst_local_phys_transport_version_show,
		scst_local_phys_transport_version_store);

static const struct attribute *scst_local_tgt_attrs[] = {
	&scst_local_scsi_transport_version_attr.attr,
	&scst_local_phys_transport_version_attr.attr,
	NULL,
};

/**
 ** Session attributes
 **/

static ssize_t scst_local_transport_id_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	ssize_t res;
	struct scst_session *scst_sess;
	struct scst_local_sess *sess;
	uint8_t *tr_id;
	int tr_id_len, i;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = (struct scst_local_sess *)scst_sess_get_tgt_priv(scst_sess);

	mutex_lock(&sess->tr_id_mutex);

	if (sess->transport_id != NULL) {
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

	if (sess->transport_id == NULL)
		kfree(tr_id);

out_unlock:
	mutex_unlock(&sess->tr_id_mutex);
	up_read(&scst_local_exit_rwsem);
	return res;
}

static ssize_t scst_local_transport_id_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	ssize_t res;
	struct scst_session *scst_sess;
	struct scst_local_sess *sess;

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	scst_sess = container_of(kobj, struct scst_session, sess_kobj);
	sess = (struct scst_local_sess *)scst_sess_get_tgt_priv(scst_sess);

	mutex_lock(&sess->tr_id_mutex);

	if (sess->transport_id != NULL) {
		kfree(sess->transport_id);
		sess->transport_id = NULL;
		sess->transport_id_len = 0;
	}

	if (size == 0)
		goto out_res;

	sess->transport_id = kzalloc(size, GFP_KERNEL);
	if (sess->transport_id == NULL) {
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
	__ATTR(transport_id, S_IRUGO | S_IWUSR,
		scst_local_transport_id_show,
		scst_local_transport_id_store);

static const struct attribute *scst_local_sess_attrs[] = {
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
		if (param == NULL)
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

		res = scst_local_add_adapter(tgt, p, NULL);
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
	ssize_t res;
	char *command, *target_name, *session_name;
	struct scst_local_tgt *t, *tgt;

	TRACE_ENTRY();

	if (down_read_trylock(&scst_local_exit_rwsem) == 0)
		return -ENOENT;

	command = scst_get_next_lexem(&buf);

	target_name = scst_get_next_lexem(&buf);
	if (*target_name == '\0') {
		PRINT_ERROR("%s", "Target name required");
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
	if (tgt == NULL) {
		PRINT_ERROR("Target %s not found", target_name);
		res = -EINVAL;
		goto out_unlock;
	}

	session_name = scst_get_next_lexem(&buf);
	if (*session_name == '\0') {
		PRINT_ERROR("%s", "Session name required");
		res = -EINVAL;
		goto out_unlock;
	}

	if (strcasecmp("add_session", command) == 0) {
		res = __scst_local_add_adapter(tgt, session_name, NULL, true);
	} else if (strcasecmp("del_session", command) == 0) {
		struct scst_local_sess *s, *sess = NULL;
		list_for_each_entry(s, &tgt->sessions_list,
					sessions_list_entry) {
			if (strcmp(s->scst_sess->initiator_name, session_name) == 0) {
				sess = s;
				break;
			}
		}
		if (sess == NULL) {
			PRINT_ERROR("Session %s not found (target %s)",
				session_name, target_name);
			res = -EINVAL;
			goto out_unlock;
		}
		scst_local_remove_adapter(sess);
	}

	res = 0;

out_unlock:
	mutex_unlock(&scst_local_mutex);

out_up:
	up_read(&scst_local_exit_rwsem);

	TRACE_EXIT_RES(res);
	return res;
}

#endif /* CONFIG_SCST_PROC */

static int scst_local_abort(struct scsi_cmnd *SCpnt)
{
	struct scst_local_sess *sess;
	int ret;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(scsi_get_device(SCpnt->device->host));

	ret = scst_rx_mgmt_fn_tag(sess->scst_sess, SCST_ABORT_TASK, SCpnt->tag,
				 FALSE, &dev_reset_completion);

	/* Now wait for the completion ... */
	wait_for_completion_interruptible(&dev_reset_completion);

	atomic_inc(&num_aborts);

	if (ret == 0)
		ret = SUCCESS;

	TRACE_EXIT_RES(ret);
	return ret;
}

static int scst_local_device_reset(struct scsi_cmnd *SCpnt)
{
	struct scst_local_sess *sess;
	uint16_t lun;
	int ret;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(scsi_get_device(SCpnt->device->host));

	lun = SCpnt->device->lun;
	lun = cpu_to_be16(lun);

	ret = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_LUN_RESET,
			(const uint8_t *)&lun, sizeof(lun), FALSE,
			&dev_reset_completion);

	/* Now wait for the completion ... */
	wait_for_completion_interruptible(&dev_reset_completion);

	atomic_inc(&num_dev_resets);

	if (ret == 0)
		ret = SUCCESS;

	TRACE_EXIT_RES(ret);
	return ret;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25))
static int scst_local_target_reset(struct scsi_cmnd *SCpnt)
{
	struct scst_local_sess *sess;
	uint16_t lun;
	int ret;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(scsi_get_device(SCpnt->device->host));

	lun = SCpnt->device->lun;
	lun = cpu_to_be16(lun);

	ret = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_TARGET_RESET,
			(const uint8_t *)&lun, sizeof(lun), FALSE,
			&dev_reset_completion);

	/* Now wait for the completion ... */
	wait_for_completion_interruptible(&dev_reset_completion);

	atomic_inc(&num_target_resets);

	if (ret == 0)
		ret = SUCCESS;

	TRACE_EXIT_RES(ret);
	return ret;
}
#endif

static void copy_sense(struct scsi_cmnd *cmnd, struct scst_cmd *scst_cmnd)
{
	int scst_cmnd_sense_len = scst_cmd_get_sense_buffer_len(scst_cmnd);

	TRACE_ENTRY();

	scst_cmnd_sense_len = (SCSI_SENSE_BUFFERSIZE < scst_cmnd_sense_len ?
			       SCSI_SENSE_BUFFERSIZE : scst_cmnd_sense_len);
	memcpy(cmnd->sense_buffer, scst_cmd_get_sense_buffer(scst_cmnd),
	       scst_cmnd_sense_len);

	TRACE_BUFFER("Sense set", cmnd->sense_buffer, scst_cmnd_sense_len);

	TRACE_EXIT();
	return;
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
		if (unlikely(SCST_SENSE_VALID(scst_cmnd->sense)))
			copy_sense(cmnd, scst_cmnd);
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
static int scst_local_queuecommand(struct scsi_cmnd *SCpnt,
				   void (*done)(struct scsi_cmnd *))
	__acquires(&h->host_lock)
	__releases(&h->host_lock)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	struct scst_local_tgt_specific *tgt_specific = NULL;
#endif
	struct scst_local_sess *sess;
	struct scatterlist *sgl = NULL;
	int sgl_count = 0;
	uint16_t lun;
	struct scst_cmd *scst_cmd = NULL;
	scst_data_direction dir;

	TRACE_ENTRY();

	TRACE_DBG("lun %d, cmd: 0x%02X", SCpnt->device->lun, SCpnt->cmnd[0]);

	sess = to_scst_lcl_sess(scsi_get_device(SCpnt->device->host));

	scsi_set_resid(SCpnt, 0);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * Allocate a tgt_specific_structure. We need this in case we need
	 * to construct a single element SGL.
	 */
	tgt_specific = kmem_cache_alloc(tgt_specific_pool, GFP_ATOMIC);
	if (!tgt_specific) {
		PRINT_ERROR("Unable to create tgt_specific (size %d)",
			sizeof(*tgt_specific));
		return -ENOMEM;
	}
	tgt_specific->cmnd = SCpnt;
	tgt_specific->done = done;
#else
	/*
	 * We save a pointer to the done routine in SCpnt->scsi_done and
	 * we save that as tgt specific stuff below.
	 */
	SCpnt->scsi_done = done;
#endif

	/*
	 * Tell the target that we have a command ... but first we need
	 * to get the LUN into a format that SCST understand
	 */
	lun = SCpnt->device->lun;
	lun = cpu_to_be16(lun);
	scst_cmd = scst_rx_cmd(sess->scst_sess, (const uint8_t *)&lun,
			       sizeof(lun), SCpnt->cmnd, SCpnt->cmd_len, TRUE);
	if (!scst_cmd) {
		PRINT_ERROR("%s", "scst_rx_cmd() failed");
		return -ENOMEM;
	}

	scst_cmd_set_tag(scst_cmd, SCpnt->tag);
	switch (scsi_get_tag_type(SCpnt->device)) {
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * If the command has a request, not a scatterlist, then convert it
	 * to one. We use scsi_sg_count to isolate us from the changes from
	 * version to version
	 */
	if (scsi_sg_count(SCpnt)) {
		sgl = scsi_sglist(SCpnt);
		sgl_count = scsi_sg_count(SCpnt);
	} else {
		/*
		 * Build a one-element scatter list out of the buffer
		 * We will not even get here if the kernel version we
		 * are building on only supports scatterlists. See #if above.
		 *
		 * We use the sglist and bufflen function/macros to isolate
		 * us from kernel version differences.
		 */
		if (scsi_sglist(SCpnt)) {
			sg_init_one(&(tgt_specific->sgl),
				(const void *)scsi_sglist(SCpnt),
				scsi_bufflen(SCpnt));
			sgl	  = &(tgt_specific->sgl);
			sgl_count = 1;
		} else {
			sgl = NULL;
			sgl_count = 0;
		}
	}
#else
	sgl = scsi_sglist(SCpnt);
	sgl_count = scsi_sg_count(SCpnt);
#endif

	dir = SCST_DATA_NONE;
	switch (SCpnt->sc_data_direction) {
	case DMA_TO_DEVICE:
		dir = SCST_DATA_WRITE;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(SCpnt));
		scst_cmd_set_tgt_sg(scst_cmd, sgl, sgl_count);
		break;
	case DMA_FROM_DEVICE:
		dir = SCST_DATA_READ;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(SCpnt));
		scst_cmd_set_tgt_sg(scst_cmd, sgl, sgl_count);
		break;
	case DMA_BIDIRECTIONAL:
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 24))
		/* Some of these symbols are only defined after 2.6.24 */
		dir = SCST_DATA_BIDI;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(SCpnt));
		scst_cmd_set_expected_out_transfer_len(scst_cmd,
			scsi_in(SCpnt)->length);
		scst_cmd_set_tgt_sg(scst_cmd, scsi_in(SCpnt)->table.sgl,
			scsi_in(SCpnt)->table.nents);
		scst_cmd_set_tgt_out_sg(scst_cmd, sgl, sgl_count);
		break;
#endif
	case DMA_NONE:
	default:
		dir = SCST_DATA_NONE;
		scst_cmd_set_expected(scst_cmd, dir, 0);
		break;
	}

	/* Save the correct thing below depending on version */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	scst_cmd_set_tgt_priv(scst_cmd, tgt_specific);
#else
	scst_cmd_set_tgt_priv(scst_cmd, SCpnt);
#endif

#ifdef CONFIG_SCST_LOCAL_FORCE_DIRECT_PROCESSING
	{
		struct Scsi_Host *h = SCpnt->device->host;
		spin_unlock_irq(h->host_lock);
		scst_cmd_init_done(scst_cmd, scst_estimate_context_direct());
		spin_lock_irq(h->host_lock);
	}
#else
	/*
	 * Unfortunately, we called with IRQs disabled, so have no choice,
	 * except to pass to the thread context.
	 */
	scst_cmd_init_done(scst_cmd, SCST_CONTEXT_THREAD);
#endif

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

/* Must be called under sess->aen_lock. Drops then reacquires it inside. */
static void scst_process_aens(struct scst_local_sess *sess,
	bool cleanup_only)
{
	struct scst_aen_work_item *work_item = NULL;

	TRACE_ENTRY();

	TRACE_DBG("Target work sess %p", sess);

	while (!list_empty(&sess->aen_work_list)) {
		work_item = list_entry(sess->aen_work_list.next,
				struct scst_aen_work_item, work_list_entry);
		list_del(&work_item->work_list_entry);

		spin_unlock(&sess->aen_lock);

		if (cleanup_only)
			goto done;

		sBUG_ON(work_item->aen->event_fn != SCST_AEN_SCSI);

		/* Let's always rescan */
		scsi_scan_target(&sess->shost->shost_gendev, 0, 0,
					SCAN_WILD_CARD, 1);

done:
		scst_aen_done(work_item->aen);
		kfree(work_item);

		spin_lock(&sess->aen_lock);
	}

	TRACE_EXIT();
	return;
}

static void scst_aen_work_fn(struct work_struct *work)
{
	struct scst_local_sess *sess =
		container_of(work, struct scst_local_sess, aen_work);

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Target work %p)", work);

	spin_lock(&sess->aen_lock);
	scst_process_aens(sess, false);
	spin_unlock(&sess->aen_lock);

	TRACE_EXIT();
	return;
}

static int scst_local_report_aen(struct scst_aen *aen)
{
	int res = 0;
	int event_fn = scst_aen_get_event_fn(aen);
	struct scst_local_sess *sess;
	struct scst_aen_work_item *work_item = NULL;

	TRACE_ENTRY();

	sess = (struct scst_local_sess *)scst_sess_get_tgt_priv(
						scst_aen_get_sess(aen));
	switch (event_fn) {
	case SCST_AEN_SCSI:
		/*
		 * Allocate a work item and place it on the queue
		 */
		work_item = kzalloc(sizeof(*work_item), GFP_KERNEL);
		if (!work_item) {
			PRINT_ERROR("%s", "Unable to allocate work item "
				"to handle AEN!");
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

		schedule_work(&sess->aen_work);
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

static int scst_local_targ_detect(struct scst_tgt_template *tgt_template)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return 0;
};

static int scst_local_targ_release(struct scst_tgt *tgt)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return 0;
}

static int scst_local_targ_xmit_response(struct scst_cmd *scst_cmd)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	struct scst_local_tgt_specific *tgt_specific;
#endif
	struct scsi_cmnd *SCpnt = NULL;
	void (*done)(struct scsi_cmnd *);

	TRACE_ENTRY();

	if (unlikely(scst_cmd_aborted(scst_cmd))) {
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);
		scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);
		return SCST_TGT_RES_SUCCESS;
	}

	if (scst_cmd_get_dh_data_buff_alloced(scst_cmd) &&
	    (scst_cmd_get_data_direction(scst_cmd) & SCST_DATA_READ))
		scst_copy_sg(scst_cmd, SCST_SG_COPY_TO_TARGET);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	tgt_specific = scst_cmd_get_tgt_priv(scst_cmd);
	SCpnt = tgt_specific->cmnd;
	done = tgt_specific->done;
#else
	SCpnt = scst_cmd_get_tgt_priv(scst_cmd);
	done = SCpnt->scsi_done;
#endif

	/*
	 * This might have to change to use the two status flags
	 */
	if (scst_cmd_get_is_send_status(scst_cmd)) {
		int resid = 0, out_resid = 0;

		/* Calculate the residual ... */
		if (likely(!scst_get_resid(scst_cmd, &resid, &out_resid))) {
			TRACE_DBG("No residuals for request %p", SCpnt);
		} else {
			if (out_resid != 0)
				PRINT_ERROR("Unable to return OUT residual %d "
					"(op %02x)", out_resid, SCpnt->cmnd[0]);
		}

		scsi_set_resid(SCpnt, resid);

		/*
		 * It seems like there is no way to set out_resid ...
		 */

		(void)scst_local_send_resp(SCpnt, scst_cmd, done,
					   scst_cmd_get_status(scst_cmd));
	}

	/* Now tell SCST that the command is done ... */
	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);

	TRACE_EXIT();
	return SCST_TGT_RES_SUCCESS;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
static void scst_local_targ_on_free_cmd(struct scst_cmd *scst_cmd)
{
	struct scst_local_tgt_specific *tgt_specific;

	TRACE_ENTRY();

	tgt_specific = scst_cmd_get_tgt_priv(scst_cmd);
	kmem_cache_free(tgt_specific_pool, tgt_specific);

	TRACE_EXIT();
	return;
}
#endif

static void scst_local_targ_task_mgmt_done(struct scst_mgmt_cmd *mgmt_cmd)
{
	struct completion *compl;

	TRACE_ENTRY();

	compl = (struct completion *)scst_mgmt_cmd_get_tgt_priv(mgmt_cmd);
	if (compl)
		complete(compl);

	TRACE_EXIT();
	return;
}

static uint16_t scst_local_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	struct scst_local_tgt *tgt;

	tgt = (struct scst_local_tgt *)scst_tgt_get_tgt_priv(scst_tgt);

	if (tgt->scsi_transport_version == 0)
		return 0x0BE0; /* SAS */
	else
		return tgt->scsi_transport_version;
}

static uint16_t scst_local_get_phys_transport_version(struct scst_tgt *scst_tgt)
{
	struct scst_local_tgt *tgt;

	tgt = (struct scst_local_tgt *)scst_tgt_get_tgt_priv(scst_tgt);

	return tgt->phys_transport_version;
}

static struct scst_tgt_template scst_local_targ_tmpl = {
	.name			= "scst_local",
	.sg_tablesize		= 0xffff,
	.xmit_response_atomic	= 1,
#ifndef CONFIG_SCST_PROC
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
#endif
	.detect			= scst_local_targ_detect,
	.release		= scst_local_targ_release,
	.pre_exec		= scst_local_targ_pre_exec,
	.xmit_response		= scst_local_targ_xmit_response,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	.on_free_cmd		= scst_local_targ_on_free_cmd,
#endif
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

static struct scsi_host_template scst_lcl_ini_driver_template = {
#ifdef CONFIG_SCST_PROC
	.proc_info			= scst_local_proc_info,
	.proc_name			= SCST_LOCAL_NAME,
	.info				= scst_local_info,
#endif
	.name				= SCST_LOCAL_NAME,
	.queuecommand			= scst_local_queuecommand,
	.eh_abort_handler		= scst_local_abort,
	.eh_device_reset_handler	= scst_local_device_reset,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25))
	.eh_target_reset_handler	= scst_local_target_reset,
#endif
	.can_queue			= 256,
	.this_id			= -1,
	/* SCST doesn't support sg chaining */
	.sg_tablesize			= SG_MAX_SINGLE_ALLOC,
	.cmd_per_lun			= 32,
	.max_sectors			= 0xffff,
	/* SCST doesn't support sg chaining */
	.use_clustering			= ENABLE_CLUSTERING,
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

	hpnt = scsi_host_alloc(&scst_lcl_ini_driver_template, sizeof(*sess));
	if (NULL == hpnt) {
		PRINT_ERROR("%s", "scsi_register() failed");
		ret = -ENODEV;
		goto out;
	}

	sess->shost = hpnt;

	hpnt->max_lun = 0xFFFF;

	/*
	 * Because of a change in the size of this field at 2.6.26
	 * we use this check ... it allows us to work on earlier
	 * kernels. If we don't,  max_cmd_size gets set to 4 (and we get
	 * a compiler warning) so a scan never occurs.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	hpnt->max_cmd_len = 16;
#else
	hpnt->max_cmd_len = 260;
#endif

	ret = scsi_add_host(hpnt, &sess->dev);
	if (ret) {
		PRINT_ERROR("%s", "scsi_add_host() failed");
		ret = -ENODEV;
		scsi_host_put(hpnt);
		goto out;
	}
#ifdef CONFIG_SCST_PROC
	else {
		scsi_scan_host(hpnt);
	}
#endif

out:
	TRACE_EXIT_RES(ret);
	return ret;
}

static int scst_local_driver_remove(struct device *dev)
{
	struct scst_local_sess *sess;

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(dev);
	if (!sess) {
		PRINT_ERROR("%s", "Unable to locate sess info");
		return -ENODEV;
	}

	scsi_remove_host(sess->shost);
	scsi_host_put(sess->shost);

	TRACE_EXIT();
	return 0;
}

static int scst_local_bus_match(struct device *dev,
	struct device_driver *dev_driver)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
static void scst_local_root_release(struct device *dev)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return;
}

static struct device scst_local_root = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	.bus_id		= "scst_local_root",
#else
	.init_name	= "scst_local_root",
#endif
	.release	= scst_local_root_release,
};
#else
static struct device *scst_local_root;
#endif

static void scst_local_release_adapter(struct device *dev)
{
	struct scst_local_sess *sess;

	TRACE_ENTRY();

	sess = to_scst_lcl_sess(dev);
	if (sess == NULL)
		goto out;

	spin_lock(&sess->aen_lock);
	sess->unregistering = 1;
	scst_process_aens(sess, true);
	spin_unlock(&sess->aen_lock);

	cancel_work_sync(&sess->aen_work);

	scst_unregister_session(sess->scst_sess, TRUE, NULL);

	kfree(sess);

out:
	TRACE_EXIT();
	return;
}

static int __scst_local_add_adapter(struct scst_local_tgt *tgt,
	const char *initiator_name, struct scst_local_sess **out_sess,
	bool locked)
{
	int res;
	struct scst_local_sess *sess;

	TRACE_ENTRY();

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (NULL == sess) {
		PRINT_ERROR("Unable to alloc scst_lcl_host (size %zd)",
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
	spin_lock_init(&sess->aen_lock);
	INIT_LIST_HEAD(&sess->aen_work_list);

	sess->scst_sess = scst_register_session(tgt->scst_tgt, 0,
				initiator_name, (void *)sess, NULL, NULL);
	if (sess->scst_sess == NULL) {
		PRINT_ERROR("%s", "scst_register_session failed");
		kfree(sess);
		res = -EFAULT;
		goto out_free;
	}

	sess->dev.bus     = &scst_local_lld_bus;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	sess->dev.parent  = &scst_local_root;
#else
	sess->dev.parent = scst_local_root;
#endif
	sess->dev.release = &scst_local_release_adapter;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	snprintf(sess->dev.bus_id, sizeof(sess->dev.bus_id), initiator_name);
#else
# ifdef CONFIG_SCST_PROC
	sess->dev.init_name = sess->scst_sess->initiator_name;
# else
	sess->dev.init_name = kobject_name(&sess->scst_sess->sess_kobj);
#endif
#endif

	res = device_register(&sess->dev);
	if (res != 0)
		goto unregister_session;

#ifndef CONFIG_SCST_PROC
	res = sysfs_create_link(scst_sysfs_get_sess_kobj(sess->scst_sess),
		&sess->shost->shost_dev.kobj, "host");
	if (res != 0) {
		PRINT_ERROR("Unable to create \"host\" link for target "
			"%s", scst_get_tgt_name(tgt->scst_tgt));
		goto unregister_dev;
	}
#endif

	if (!locked)
		mutex_lock(&scst_local_mutex);
	list_add_tail(&sess->sessions_list_entry, &tgt->sessions_list);
	if (!locked)
		mutex_unlock(&scst_local_mutex);

	scsi_scan_target(&sess->shost->shost_gendev, 0, 0, SCAN_WILD_CARD, 1);

out:
	TRACE_EXIT_RES(res);
	return res;

#ifndef CONFIG_SCST_PROC
unregister_dev:
	device_unregister(&sess->dev);
#endif

unregister_session:
	scst_unregister_session(sess->scst_sess, TRUE, NULL);

out_free:
	kfree(sess);
	goto out;
}

static int scst_local_add_adapter(struct scst_local_tgt *tgt,
	const char *initiator_name, struct scst_local_sess **out_sess)
{
	return __scst_local_add_adapter(tgt, initiator_name, out_sess, false);
}

/* Must be called under scst_local_mutex */
static void scst_local_remove_adapter(struct scst_local_sess *sess)
{
	TRACE_ENTRY();

	list_del(&sess->sessions_list_entry);

	device_unregister(&sess->dev);

	TRACE_EXIT();
	return;
}

static int scst_local_add_target(const char *target_name,
	struct scst_local_tgt **out_tgt)
{
	int res;
	struct scst_local_tgt *tgt;

	TRACE_ENTRY();

	tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
	if (NULL == tgt) {
		PRINT_ERROR("Unable to alloc tgt (size %zd)", sizeof(*tgt));
		res = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&tgt->sessions_list);

	tgt->scst_tgt = scst_register_target(&scst_local_targ_tmpl, target_name);
	if (tgt->scst_tgt == NULL) {
		PRINT_ERROR("%s", "scst_register_target() failed:");
		res = -EFAULT;
		goto out_free;
	}

	scst_tgt_set_tgt_priv(tgt->scst_tgt, tgt);

	mutex_lock(&scst_local_mutex);
	list_add_tail(&tgt->tgts_list_entry, &scst_local_tgts_list);
	mutex_unlock(&scst_local_mutex);

	if (out_tgt != NULL)
		*out_tgt = tgt;

	res = 0;

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

	list_for_each_entry_safe(sess, ts, &tgt->sessions_list,
					sessions_list_entry) {
		scst_local_remove_adapter(sess);
	}

	list_del(&tgt->tgts_list_entry);

	scst_unregister_target(tgt->scst_tgt);

	kfree(tgt);

	TRACE_EXIT();
	return;
}

static void scst_local_remove_target(struct scst_local_tgt *tgt)
{
	TRACE_ENTRY();

	mutex_lock(&scst_local_mutex);
	__scst_local_remove_target(tgt);
	mutex_unlock(&scst_local_mutex);

	TRACE_EXIT();
	return;
}

static int __init scst_local_init(void)
{
	int ret;
	struct scst_local_tgt *tgt;

	TRACE_ENTRY();

#ifndef INSIDE_KERNEL_TREE
#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
	PRINT_ERROR("%s", "HIGHMEM kernel configurations are not supported. "
		"Consider changing VMSPLIT option or use a 64-bit "
		"configuration instead. See SCST core README file for "
		"details.");
	ret = -EINVAL;
	goto out;
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * Allocate a pool of structures for tgt_specific structures.
	 * We only need this if we could get non scatterlist requests
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
	tgt_specific_pool = kmem_cache_create("scst_tgt_specific",
				      sizeof(struct scst_local_tgt_specific),
				      0, SCST_SLAB_FLAGS, NULL);
#else
	tgt_specific_pool = kmem_cache_create("scst_tgt_specific",
				      sizeof(struct scst_local_tgt_specific),
				      0, SCST_SLAB_FLAGS, NULL, NULL);
#endif
	if (!tgt_specific_pool) {
		PRINT_ERROR("%s", "Unable to initialize tgt_specific_pool");
		ret = -ENOMEM;
		goto out;
	}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	ret = device_register(&scst_local_root);
	if (ret < 0) {
		PRINT_ERROR("Root device_register() error: %d", ret);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
		goto destroy_kmem;
#else
		goto out;
#endif
	}
#else
	scst_local_root = root_device_register(SCST_LOCAL_NAME);
	if (IS_ERR(scst_local_root)) {
		ret = PTR_ERR(scst_local_root);
		goto out;
	}
#endif

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

	if (!scst_local_add_default_tgt)
		goto driver_unreg;

	ret = scst_local_add_target("scst_local_tgt", &tgt);
	if (ret != 0)
		goto tgt_templ_unreg;

	ret = scst_local_add_adapter(tgt, "scst_local_host", NULL);
	if (ret != 0)
		goto tgt_unreg;

out:
	TRACE_EXIT_RES(ret);
	return ret;

tgt_unreg:
	scst_local_remove_target(tgt);

tgt_templ_unreg:
	scst_unregister_target_template(&scst_local_targ_tmpl);

driver_unreg:
	driver_unregister(&scst_local_driver);

bus_unreg:
	bus_unregister(&scst_local_lld_bus);

dev_unreg:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	device_unregister(&scst_local_root);
#else
	root_device_unregister(scst_local_root);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
destroy_kmem:
	kmem_cache_destroy(tgt_specific_pool);
#endif
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

	driver_unregister(&scst_local_driver);
	bus_unregister(&scst_local_lld_bus);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	device_unregister(&scst_local_root);
#else
	root_device_unregister(scst_local_root);
#endif

	/* Now unregister the target template */
	scst_unregister_target_template(&scst_local_targ_tmpl);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/* Free the non scatterlist pool we allocated */
	if (tgt_specific_pool)
		kmem_cache_destroy(tgt_specific_pool);
#endif

	/* To make lockdep happy */
	up_write(&scst_local_exit_rwsem);

	TRACE_EXIT();
	return;
}

device_initcall(scst_local_init);
module_exit(scst_local_exit);

