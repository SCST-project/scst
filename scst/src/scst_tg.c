/*
 *  scst_tg.c
 *
 *  SCSI target group related code.
 *
 *  Copyright (C) 2011 - 2016 Bart Van Assche <bvanassche@acm.org>.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  version 2 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/kmod.h>
#include <asm/unaligned.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_event.h>
#else
#include "scst.h"
#include "scst_event.h"
#endif
#include "scst_priv.h"
#include "scst_pres.h"

struct alua_state_and_name {
	enum scst_tg_state s;
	char *n;
};

static const struct alua_state_and_name scst_tg_state_names[] = {
	{ SCST_TG_STATE_OPTIMIZED,	"active"	},
	{ SCST_TG_STATE_NONOPTIMIZED,	"nonoptimized"	},
	{ SCST_TG_STATE_STANDBY,	"standby"	},
	{ SCST_TG_STATE_UNAVAILABLE,	"unavailable"	},
	{ SCST_TG_STATE_OFFLINE,	"offline"	},
	{ SCST_TG_STATE_TRANSITIONING,	"transitioning"	},
};

/*
 * Protects scst_dev_group_list and also dev_list and tg_list in struct
 * scst_dev_group.
 */
static DEFINE_MUTEX(scst_dg_mutex);
static LIST_HEAD(scst_dev_group_list);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31) || \
	defined(RHEL_MAJOR) && RHEL_MAJOR -0 <= 5
static int alua_invariant_check;
#else
static bool alua_invariant_check;
#endif
module_param(alua_invariant_check, bool, 0644);
MODULE_PARM_DESC(alua_invariant_check,
		 "Enables a run-time ALUA state invariant check.");

const char *scst_alua_state_name(enum scst_tg_state s)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(scst_tg_state_names); i++)
		if (scst_tg_state_names[i].s == s)
			return scst_tg_state_names[i].n;

	return NULL;
}
EXPORT_SYMBOL(scst_alua_state_name);

enum scst_tg_state scst_alua_name_to_state(const char *n)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(scst_tg_state_names); i++)
		if (strcmp(scst_tg_state_names[i].n, n) == 0)
			return scst_tg_state_names[i].s;

	return SCST_TG_STATE_UNDEFINED;
}

/* Look up a device by name. */
static struct scst_device *__lookup_dev(const char *name)
{
	struct scst_device *dev;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry)
		if (strcmp(dev->virt_name, name) == 0)
			return dev;

	return NULL;
}

/* Look up a target by name. */
static struct scst_tgt *__lookup_tgt(const char *name)
{
	struct scst_tgt_template *t;
	struct scst_tgt *tgt;

	lockdep_assert_held(&scst_mutex);

	list_for_each_entry(t, &scst_template_list, scst_template_list_entry)
		list_for_each_entry(tgt, &t->tgt_list, tgt_list_entry)
			if (strcmp(tgt->tgt_name, name) == 0)
				return tgt;

	return NULL;
}

/* Look up a target by name in the given device group. */
static struct scst_tg_tgt *__lookup_dg_tgt(struct scst_dev_group *dg,
					   const char *tgt_name)
{
	struct scst_target_group *tg;
	struct scst_tg_tgt *tg_tgt;

	lockdep_assert_held(&scst_dg_mutex);

	BUG_ON(!dg);
	BUG_ON(!tgt_name);
	list_for_each_entry(tg, &dg->tg_list, entry)
		list_for_each_entry(tg_tgt, &tg->tgt_list, entry)
			if (strcmp(tg_tgt->name, tgt_name) == 0)
				return tg_tgt;

	return NULL;
}

/* Look up a target group by name in the given device group. */
static struct scst_target_group *__lookup_tg_by_name(struct scst_dev_group *dg,
						     const char *name)
{
	struct scst_target_group *tg;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(tg, &dg->tg_list, entry)
		if (strcmp(tg->name, name) == 0)
			return tg;

	return NULL;
}

/* Look up a target group by group ID. */
static struct scst_target_group *__lookup_tg_by_group_id(struct scst_dev_group *dg,
							 uint16_t group_id)
{
	struct scst_target_group *tg;

	lockdep_assert_held(&scst_mutex);

	list_for_each_entry(tg, &dg->tg_list, entry)
		if (tg->group_id == group_id)
			return tg;

	return NULL;
}

/* Look up a target group by target port. */
static struct scst_target_group *__lookup_tg_by_tgt(struct scst_dev_group *dg,
						    const struct scst_tgt *tgt)
{
	struct scst_target_group *tg;
	struct scst_tg_tgt *tg_tgt;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(tg, &dg->tg_list, entry)
		list_for_each_entry(tg_tgt, &tg->tgt_list, entry)
			if (tg_tgt->tgt == tgt)
				return tg;

	return NULL;
}

/* Look up a device node by device pointer in the given device group. */
static struct scst_dg_dev *__lookup_dg_dev_by_dev(struct scst_dev_group *dg,
						  struct scst_device *dev)
{
	struct scst_dg_dev *dgd;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dgd, &dg->dev_list, entry)
		if (dgd->dev == dev)
			return dgd;

	return NULL;
}

/* Look up a device node by name in the given device group. */
static struct scst_dg_dev *__lookup_dg_dev_by_name(struct scst_dev_group *dg,
						   const char *name)
{
	struct scst_dg_dev *dgd;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dgd, &dg->dev_list, entry)
		if (strcmp(dgd->dev->virt_name, name) == 0)
			return dgd;

	return NULL;
}

/* Look up a device node by name in any device group. */
static struct scst_dg_dev *__global_lookup_dg_dev_by_name(const char *name)
{
	struct scst_dev_group *dg;
	struct scst_dg_dev *dgd;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dg, &scst_dev_group_list, entry) {
		dgd = __lookup_dg_dev_by_name(dg, name);
		if (dgd)
			return dgd;
	}
	return NULL;
}

/* Look up a device group by name. */
static struct scst_dev_group *__lookup_dg_by_name(const char *name)
{
	struct scst_dev_group *dg;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dg, &scst_dev_group_list, entry)
		if (strcmp(dg->name, name) == 0)
			return dg;

	return NULL;
}

/* Look up a device group by device pointer. */
static struct scst_dev_group *__lookup_dg_by_dev(struct scst_device *dev)
{
	struct scst_dev_group *dg;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dg, &scst_dev_group_list, entry)
		if (__lookup_dg_dev_by_dev(dg, dev))
			return dg;

	return NULL;
}

/*
 * Target group contents management.
 */

static void scst_release_tg_tgt(struct kobject *kobj)
{
	struct scst_tg_tgt *tg_tgt;

	tg_tgt = container_of(kobj, struct scst_tg_tgt, kobj);
	kfree(tg_tgt->name);
	kfree(tg_tgt);
}

static struct kobj_type scst_tg_tgt_ktype = {
#ifndef CONFIG_SCST_PROC
	.sysfs_ops = &scst_sysfs_ops,
#endif
	.release = scst_release_tg_tgt,
};

/*
 * Whether or not to accept a command in the ALUA standby state.
 */
static int scst_tg_accept_standby(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	switch (cmd->cdb[0]) {
	case TEST_UNIT_READY:
	case GET_EVENT_STATUS_NOTIFICATION:
	case INQUIRY:
	case MODE_SENSE:
	case MODE_SENSE_10:
	case READ_CAPACITY:
	case REPORT_LUNS:
	case REQUEST_SENSE:
	case RELEASE:
	case RELEASE_10:
	case RESERVE:
	case RESERVE_10:
	case READ_BUFFER:
	case WRITE_BUFFER:
	case MODE_SELECT:
	case MODE_SELECT_10:
	case LOG_SELECT:
	case LOG_SENSE:
	case RECEIVE_DIAGNOSTIC:
	case SEND_DIAGNOSTIC:
	case PERSISTENT_RESERVE_IN:
	case PERSISTENT_RESERVE_OUT:
		res = SCST_ALUA_CHECK_OK;
		goto out;
	case SERVICE_ACTION_IN_16:
		switch (cmd->cdb[1] & 0x1f) {
		case SAI_READ_CAPACITY_16:
			res = SCST_ALUA_CHECK_OK;
			goto out;
		}
		break;
	case MAINTENANCE_IN:
		switch (cmd->cdb[1] & 0x1f) {
		case MI_REPORT_TARGET_PGS:
			res = SCST_ALUA_CHECK_OK;
			goto out;
		}
		break;
	case MAINTENANCE_OUT:
		switch (cmd->cdb[1] & 0x1f) {
		case MO_SET_TARGET_PGS:
			res = SCST_ALUA_CHECK_OK;
			goto out;
		}
		break;
	}

	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_alua_standby));
	res = SCST_ALUA_CHECK_ERROR;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Whether or not to accept a command in the ALUA unavailable state.
 */
static int scst_tg_accept_unav(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	switch (cmd->cdb[0]) {
	case TEST_UNIT_READY:
	case GET_EVENT_STATUS_NOTIFICATION:
	case INQUIRY:
	case MODE_SENSE:
	case MODE_SENSE_10:
	case READ_CAPACITY:
	case REPORT_LUNS:
	case REQUEST_SENSE:
	case RELEASE:
	case RELEASE_10:
	case RESERVE:
	case RESERVE_10:
	case READ_BUFFER:
	case WRITE_BUFFER:
		res = SCST_ALUA_CHECK_OK;
		goto out;
	case SERVICE_ACTION_IN_16:
		switch (cmd->cdb[1] & 0x1f) {
		case SAI_READ_CAPACITY_16:
			res = SCST_ALUA_CHECK_OK;
			goto out;
		}
		break;
	case MAINTENANCE_IN:
		switch (cmd->cdb[1] & 0x1f) {
		case MI_REPORT_TARGET_PGS:
			res = SCST_ALUA_CHECK_OK;
			goto out;
		}
		break;
	case MAINTENANCE_OUT:
		switch (cmd->cdb[1] & 0x1f) {
		case MO_SET_TARGET_PGS:
			res = SCST_ALUA_CHECK_OK;
			goto out;
		}
		break;
	}

	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_alua_unav));
	res = SCST_ALUA_CHECK_ERROR;

out:
	TRACE_EXIT_RES(res);
	return res;
}

struct scst_alua_retry {
	struct scst_cmd *alua_retry_cmd;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct work_struct alua_retry_work;
#else
	struct delayed_work alua_retry_work;
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_alua_transitioning_work_fn(void *p)
{
	struct scst_alua_retry *retry = p;
#else
static void scst_alua_transitioning_work_fn(struct work_struct *work)
{
	struct scst_alua_retry *retry =
		container_of(work, struct scst_alua_retry,
			     alua_retry_work.work);
#endif
	struct scst_cmd *cmd = retry->alua_retry_cmd;

	TRACE_ENTRY();

	TRACE_DBG("Retrying transitioning cmd %p", cmd);

	spin_lock_irq(&cmd->cmd_threads->cmd_list_lock);
	list_add(&cmd->cmd_list_entry,
		&cmd->cmd_threads->active_cmd_list);
	wake_up(&cmd->cmd_threads->cmd_list_waitQ);
	spin_unlock_irq(&cmd->cmd_threads->cmd_list_lock);

	kfree(retry);

	TRACE_EXIT();
	return;
}

/*
 * Whether or not to accept a command in the ALUA transitioning state.
 */
static int scst_tg_accept_transitioning(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	switch (cmd->cdb[0]) {
	case INQUIRY:
	case READ_CAPACITY:
	case REPORT_LUNS:
	case REQUEST_SENSE:
	case READ_BUFFER:
	case WRITE_BUFFER:
		res = SCST_ALUA_CHECK_OK;
		goto out;
	case SERVICE_ACTION_IN_16:
		switch (cmd->cdb[1] & 0x1f) {
		case SAI_READ_CAPACITY_16:
			res = SCST_ALUA_CHECK_OK;
			goto out;
		}
		break;
	}

	if (cmd->already_transitioning)
		TRACE_DBG("cmd %p already transitioned checked, failing", cmd);
	else {
		struct scst_alua_retry *retry;

		TRACE_DBG("ALUA transitioning: delaying cmd %p", cmd);

		retry = kzalloc(sizeof(*retry), GFP_KERNEL);
		if (retry == NULL) {
			TRACE_DBG("Unable to allocate ALUA retry "
				"struct, failing cmd %p", cmd);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_alua_transitioning));
			res = SCST_ALUA_CHECK_ERROR;
			goto out;
		}

		/* No get is needed, because cmd is sync here */
		retry->alua_retry_cmd = cmd;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
		INIT_WORK(&retry->alua_retry_work,
			  scst_alua_transitioning_work_fn, retry);
#else
		INIT_DELAYED_WORK(&retry->alua_retry_work,
				  scst_alua_transitioning_work_fn);
#endif
		cmd->already_transitioning = 1;
		schedule_delayed_work(&retry->alua_retry_work, HZ/2);
		res = SCST_ALUA_CHECK_DELAYED;
		goto out;
	}

	scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_alua_transitioning));
	res = SCST_ALUA_CHECK_ERROR;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int (*scst_alua_filter[])(struct scst_cmd *cmd) = {
	[SCST_TG_STATE_OPTIMIZED]	= NULL,
	[SCST_TG_STATE_NONOPTIMIZED]	= NULL,
	[SCST_TG_STATE_STANDBY]		= scst_tg_accept_standby,
	[SCST_TG_STATE_UNAVAILABLE]	= scst_tg_accept_unav,
	[SCST_TG_STATE_LBA_DEPENDENT]	= NULL,
	[SCST_TG_STATE_OFFLINE]		= scst_tg_accept_unav,
	[SCST_TG_STATE_TRANSITIONING]	= scst_tg_accept_transitioning,
};

/*
 * Check whether the tgt_dev ALUA filter is consistent with the target group
 * ALUA state.
 */
static void scst_check_alua_invariant(void)
{
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_dev_group *dg;
	struct scst_target_group *tg;
	enum scst_tg_state expected_state;

#if 0
	lockdep_assert_held(&scst_mutex); /* scst_dev_list, dev_tgt_dev_list */
#endif
	lockdep_assert_held(&scst_dg_mutex);

	if (!alua_invariant_check)
		return;

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		dg = __lookup_dg_by_dev(dev);
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			tg = dg ?
			    __lookup_tg_by_tgt(dg, tgt_dev->acg_dev->acg->tgt) :
			    NULL;
			expected_state = tg ? tg->state :
				SCST_TG_STATE_OPTIMIZED;
			if (tgt_dev->alua_filter !=
				   scst_alua_filter[expected_state]) {
				PRINT_ERROR("LUN %s/%s/%s/%lld/%s: ALUA filter"
					" %p <> %p",
					tgt_dev->acg_dev->acg->tgt->tgt_name,
					tgt_dev->acg_dev->acg->acg_name ? :
					"(default)",
					tgt_dev->sess->initiator_name,
					tgt_dev->lun,
					tgt_dev->dev->virt_name ? : "(null)",
					tgt_dev->alua_filter,
					scst_alua_filter[expected_state]);
			}
		}
	}
}

/* Update the ALUA filter of a tgt_dev */
static void scst_update_tgt_dev_alua_filter(struct scst_tgt_dev *tgt_dev,
					    enum scst_tg_state state)
{
	lockdep_assert_held(&scst_dg_mutex);

	tgt_dev->alua_filter = scst_alua_filter[state];
}

/* Update the ALUA filter after an ALUA state change and generate UA */
static void scst_tg_change_tgt_dev_state(struct scst_tgt_dev *tgt_dev,
					 enum scst_tg_state state,
					 bool gen_ua)
{
	lockdep_assert_held(&scst_dg_mutex);

	TRACE_MGMT_DBG("ALUA state of tgt_dev %p has changed (gen_ua %d)",
		tgt_dev, gen_ua);

	scst_update_tgt_dev_alua_filter(tgt_dev, state);
	if (gen_ua)
		scst_gen_aen_or_ua(tgt_dev,
			SCST_LOAD_SENSE(scst_sense_asym_access_state_changed));
}

/* Initialize ALUA state of LUN tgt_dev */
void scst_tg_init_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	struct scst_dev_group *dg;
	struct scst_target_group *tg;

	mutex_lock(&scst_dg_mutex);
	dg = __lookup_dg_by_dev(tgt_dev->dev);
	if (dg) {
		tg = __lookup_tg_by_tgt(dg, tgt_dev->acg_dev->acg->tgt);
		if (tg) {
			scst_update_tgt_dev_alua_filter(tgt_dev, tg->state);
			scst_check_alua_invariant();
		}
	}
	mutex_unlock(&scst_dg_mutex);
}

/*
 * Update the ALUA filter of all tgt_devs associated with target group @tg
 * and target @tgt.
 */
static void scst_update_tgt_alua_filter(struct scst_target_group *tg,
					struct scst_tgt *tgt)
{
	struct scst_dg_dev *dgd;
	struct scst_tgt_dev *tgt_dev;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dgd, &tg->dg->dev_list, entry) {
		list_for_each_entry(tgt_dev, &dgd->dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			if (tgt_dev->acg_dev->acg->tgt == tgt)
				scst_update_tgt_dev_alua_filter(tgt_dev,
								tg->state);
		}
	}

	scst_check_alua_invariant();
}

/*
 * Reset the ALUA filter of all tgt_devs associated with target group @tg
 * and target @tgt.
 */
static void scst_reset_tgt_alua_filter(struct scst_target_group *tg,
				       struct scst_tgt *tgt)
{
	struct scst_dg_dev *dgd;
	struct scst_tgt_dev *tgt_dev;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dgd, &tg->dg->dev_list, entry) {
		list_for_each_entry(tgt_dev, &dgd->dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			if (tgt_dev->acg_dev->acg->tgt == tgt)
				scst_update_tgt_dev_alua_filter(tgt_dev,
						      SCST_TG_STATE_OPTIMIZED);
		}
	}

	scst_check_alua_invariant();
}

/**
 * scst_tg_tgt_add() - Add a target to a target group.
 */
int scst_tg_tgt_add(struct scst_target_group *tg, const char *name)
{
	struct scst_tg_tgt *tg_tgt;
	struct scst_tgt *tgt;
	int res;

	TRACE_ENTRY();
	BUG_ON(!tg);
	BUG_ON(!name);
	res = -ENOMEM;
	tg_tgt = kzalloc(sizeof(*tg_tgt), GFP_KERNEL);
	if (!tg_tgt)
		goto out;
	tg_tgt->tg = tg;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 24)
	kobject_init(&tg_tgt->kobj, &scst_tg_tgt_ktype);
#else
	kobject_init(&tg_tgt->kobj);
	tg_tgt->kobj.ktype = &scst_tg_tgt_ktype;
#endif
	tg_tgt->name = kstrdup(name, GFP_KERNEL);
	if (!tg_tgt->name)
		goto out_put;

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out_put;
	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out_unlock_scst;
	res = -EEXIST;
	tgt = __lookup_tgt(name);
	if (__lookup_dg_tgt(tg->dg, name))
		goto out_unlock_dg;
	tg_tgt->tgt = tgt;
	res = scst_tg_tgt_sysfs_add(tg, tg_tgt);
	if (res)
		goto out_unlock_dg;
	list_add_tail(&tg_tgt->entry, &tg->tgt_list);
	scst_update_tgt_alua_filter(tg, tgt);
	res = 0;
	mutex_unlock(&scst_dg_mutex);
	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock_dg:
	mutex_unlock(&scst_dg_mutex);

out_unlock_scst:
	mutex_unlock(&scst_mutex);

out_put:
	kobject_put(&tg_tgt->kobj);
	goto out;
}

static void __scst_tg_tgt_remove(struct scst_target_group *tg,
				 struct scst_tg_tgt *tg_tgt)
{
	TRACE_ENTRY();
	list_del(&tg_tgt->entry);
	scst_tg_tgt_sysfs_del(tg, tg_tgt);
	scst_reset_tgt_alua_filter(tg, tg_tgt->tgt);
	kobject_put(&tg_tgt->kobj);
	TRACE_EXIT();
}

/**
 * scst_tg_tgt_remove_by_name() - Remove a target from a target group.
 */
int scst_tg_tgt_remove_by_name(struct scst_target_group *tg, const char *name)
{
	struct scst_tg_tgt *tg_tgt;
	int res;

	TRACE_ENTRY();
	BUG_ON(!tg);
	BUG_ON(!name);
	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	tg_tgt = __lookup_dg_tgt(tg->dg, name);
	if (!tg_tgt)
		goto out_unlock;
	__scst_tg_tgt_remove(tg, tg_tgt);
	res = 0;
out_unlock:
	mutex_unlock(&scst_dg_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called from the target removal code. */
void scst_tg_tgt_remove_by_tgt(struct scst_tgt *tgt)
{
	struct scst_dev_group *dg;
	struct scst_target_group *tg;
	struct scst_tg_tgt *t, *t2;

	mutex_lock(&scst_dg_mutex);
	list_for_each_entry(dg, &scst_dev_group_list, entry)
		list_for_each_entry(tg, &dg->tg_list, entry)
			list_for_each_entry_safe(t, t2, &tg->tgt_list, entry)
				if (t->tgt == tgt)
					__scst_tg_tgt_remove(tg, t);
	mutex_unlock(&scst_dg_mutex);
}

/*
 * Target group management.
 */

static void scst_release_tg(struct kobject *kobj)
{
	struct scst_target_group *tg;

	tg = container_of(kobj, struct scst_target_group, kobj);
	kfree(tg->name);
	kfree(tg);
}

static struct kobj_type scst_tg_ktype = {
#ifndef CONFIG_SCST_PROC
	.sysfs_ops = &scst_sysfs_ops,
#endif
	.release = scst_release_tg,
};

/**
 * scst_tg_add() - Add a target group.
 */
int scst_tg_add(struct scst_dev_group *dg, const char *name)
{
	struct scst_target_group *tg;
	int res;

	TRACE_ENTRY();
	res = -ENOMEM;
	tg = kzalloc(sizeof(*tg), GFP_KERNEL);
	if (!tg)
		goto out;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 24)
	kobject_init(&tg->kobj, &scst_tg_ktype);
#else
	kobject_init(&tg->kobj);
	tg->kobj.ktype = &scst_tg_ktype;
#endif
	tg->name = kstrdup(name, GFP_KERNEL);
	if (!tg->name)
		goto out_put;
	tg->dg = dg;
	tg->state = SCST_TG_STATE_OPTIMIZED;
	INIT_LIST_HEAD(&tg->tgt_list);

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out_put;
	res = -EEXIST;
	if (__lookup_tg_by_name(dg, name))
		goto out_unlock;
	res = scst_tg_sysfs_add(dg, tg);
	if (res)
		goto out_unlock;
	list_add_tail(&tg->entry, &dg->tg_list);
	mutex_unlock(&scst_dg_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	mutex_unlock(&scst_dg_mutex);
out_put:
	kobject_put(&tg->kobj);
	goto out;
}

static void __scst_tg_remove(struct scst_dev_group *dg,
			     struct scst_target_group *tg)
{
	struct scst_tg_tgt *tg_tgt;

	TRACE_ENTRY();
	BUG_ON(!dg);
	BUG_ON(!tg);
	while (!list_empty(&tg->tgt_list)) {
		tg_tgt = list_first_entry(&tg->tgt_list, struct scst_tg_tgt,
					  entry);
		__scst_tg_tgt_remove(tg, tg_tgt);
	}
	list_del(&tg->entry);
	scst_tg_sysfs_del(tg);
	kobject_put(&tg->kobj);
	TRACE_EXIT();
}

/**
 * scst_tg_remove_by_name() - Remove a target group.
 */
int scst_tg_remove_by_name(struct scst_dev_group *dg, const char *name)
{
	struct scst_target_group *tg;
	int res;

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	tg = __lookup_tg_by_name(dg, name);
	if (!tg)
		goto out_unlock;
	__scst_tg_remove(dg, tg);
	res = 0;
out_unlock:
	mutex_unlock(&scst_dg_mutex);
out:
	return res;
}

static void scst_event_stpg_notify_fn(struct scst_event *event,
				      void *priv, int status)
{
	struct scst_dev_group *dg;
	struct scst_cmd *cmd = (struct scst_cmd *)priv;
	struct scst_event_stpg_payload *p =
		(struct scst_event_stpg_payload *)event->payload;
	struct scst_event_stpg_descr *d;
	struct scst_dg_dev *dgd;
	int i;

	TRACE_ENTRY();

	PRINT_INFO("Notification for event %u (id %d) received "
		   "with status %d (priv %p)", event->event_code,
		   event->event_id, status, priv);

	mutex_lock(&scst_mutex);
	mutex_lock(&scst_dg_mutex);

	dg = __lookup_dg_by_dev(cmd->dev);
	if (!dg) {
		PRINT_ERROR("STPG: unable to find DG for device %s",
			cmd->dev->virt_name);
		goto out_fail;
	}

	list_for_each_entry(dgd, &dg->dev_list, entry) {
		if (dgd->dev->stpg_ext_blocked) {
			TRACE_DBG("STPG: ext unblocking dev %s",
				dgd->dev->virt_name);
			scst_ext_unblock_dev(dgd->dev, true);
			dgd->dev->stpg_ext_blocked = 0;
		}
	}

	kfree(dg->stpg_transport_id);
	dg->stpg_transport_id = NULL;

	if (status != 0) {
		PRINT_ERROR("on_stpg script for device group %s failed with status %d",
			dg->name, status);
		goto out_fail;
	}

	for (i = 0, d = &p->stpg_descriptors[0]; i < p->stpg_descriptors_cnt; i++, d++) {
		struct scst_target_group *tg = __lookup_tg_by_group_id(dg, d->group_id);

		if (!tg) {
			PRINT_ERROR("STPG: unable to find TG %d", d->group_id);
			goto out_fail;
		} else if (tg->state == scst_alua_name_to_state(d->prev_state)) {
			PRINT_ERROR("on_stpg script did not change ALUA state"
				   " for device group %s / target group %s",
				   dg->name, tg->name);
			goto out_fail;
		}
	}

out_unlock:
	mutex_unlock(&scst_dg_mutex);
	mutex_unlock(&scst_mutex);

	scst_stpg_del_unblock_next(cmd);

	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_THREAD);

	TRACE_EXIT();
	return;

out_fail:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_set_target_pgs_failed));
	goto out_unlock;
}

/*
 * Update the ALUA filter of those LUNs (tgt_dev) whose target port is a member
 * of target group @tg and that export a device that is a member of the device
 * group @tg->dg.
 */
static void __scst_tg_set_state(struct scst_target_group *tg,
				enum scst_tg_state state)
{
	struct scst_dg_dev *dg_dev;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_tg_tgt *tg_tgt;
	struct scst_tgt *tgt;
	enum scst_tg_state old_state = tg->state;

	sBUG_ON(state >= ARRAY_SIZE(scst_alua_filter));
	lockdep_assert_held(&scst_dg_mutex);

	if (tg->state == state)
		return;

	tg->state = state;

	list_for_each_entry(dg_dev, &tg->dg->dev_list, entry) {
		dev = dg_dev->dev;
		if (dev->handler->on_alua_state_change_start != NULL)
			dev->handler->on_alua_state_change_start(dev, old_state, state);
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			tgt = tgt_dev->sess->tgt;
			list_for_each_entry(tg_tgt, &tg->tgt_list, entry) {
				if (tg_tgt->tgt == tgt) {
					bool gen_ua = (state != SCST_TG_STATE_TRANSITIONING);

					if ((tg->dg->stpg_rel_tgt_id == tgt_dev->sess->tgt->rel_tgt_id) &&
					    tid_equal(tg->dg->stpg_transport_id, tgt_dev->sess->transport_id))
						gen_ua = false;
					scst_tg_change_tgt_dev_state(tgt_dev,
						state, gen_ua);
					break;
				}
			}
		}
		if (dev->handler->on_alua_state_change_finish != NULL)
			dev->handler->on_alua_state_change_finish(dev, old_state, state);
	}

	scst_check_alua_invariant();

	PRINT_INFO("Changed ALUA state of %s/%s into %s", tg->dg->name,
		   tg->name, scst_alua_state_name(state));
}

int scst_tg_set_state(struct scst_target_group *tg, enum scst_tg_state state)
{
	int res;

	res = -EINVAL;
	if (state >= ARRAY_SIZE(scst_alua_filter))
		goto out;

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out;

	__scst_tg_set_state(tg, state);

	mutex_unlock(&scst_dg_mutex);
out:
	return res;
}

/*
 * Generate an ASYMMETRIC ACCESS STATE CHANGED check condition after the value
 * of the "preferred" state of a target port group has been changed. Although
 * not required by SPC-4, generating this check condition terminates an
 * initiator-side STPG loop. An initiator typically retries an STPG after
 * having received a LOGICAL UNIT NOT ACCESSIBLE, ASYMMETRIC ACCESS STATE
 * TRANSITION but stops resending an STPG when it receives an ASYMMETRIC
 * ACCESS STATE CHANGED check condition.
 */
static void __scst_gen_alua_state_changed_ua(struct scst_target_group *tg)
{
	struct scst_dg_dev *dg_dev;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_tg_tgt *tg_tgt;
	struct scst_tgt *tgt;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(dg_dev, &tg->dg->dev_list, entry) {
		dev = dg_dev->dev;
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			tgt = tgt_dev->sess->tgt;
			list_for_each_entry(tg_tgt, &tg->tgt_list, entry) {
				if (tg_tgt->tgt == tgt) {
					scst_gen_aen_or_ua(tgt_dev,
			SCST_LOAD_SENSE(scst_sense_asym_access_state_changed));
					break;
				}
			}
		}
	}
}

static void __scst_tg_set_preferred(struct scst_target_group *tg,
				    bool preferred)
{
	bool prev_preferred;

	lockdep_assert_held(&scst_dg_mutex);

	if (tg->preferred == preferred)
		return;

	prev_preferred = tg->preferred;
	tg->preferred = preferred;

	PRINT_INFO("Changed preferred state of %s/%s from %d into %d",
		   tg->dg->name, tg->name, prev_preferred,
		   preferred);

	__scst_gen_alua_state_changed_ua(tg);
}

int scst_tg_set_preferred(struct scst_target_group *tg,
				 bool preferred)
{
	int res;

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out;
	__scst_tg_set_preferred(tg, preferred);
	mutex_unlock(&scst_dg_mutex);
out:
	return res;
}

/*
 * Device group contents manipulation.
 */

/*
 * Update the ALUA filter of all tgt_devs associated with device group @dg
 * and device @dev.
 */
static void scst_update_dev_alua_filter(struct scst_dev_group *dg,
					struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;
	struct scst_target_group *tg;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			    dev_tgt_dev_list_entry) {
		tg = __lookup_tg_by_tgt(dg, tgt_dev->acg_dev->acg->tgt);
		if (tg)
			scst_update_tgt_dev_alua_filter(tgt_dev, tg->state);
	}

	scst_check_alua_invariant();
}

/*
 * Reset the ALUA filter of all tgt_devs associated with device @dev. Note:
 * each device is member of at most one device group.
 */
static void scst_reset_dev_alua_filter(struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;

	lockdep_assert_held(&scst_dg_mutex);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			    dev_tgt_dev_list_entry)
		scst_update_tgt_dev_alua_filter(tgt_dev,
						SCST_TG_STATE_OPTIMIZED);

	scst_check_alua_invariant();
}

/**
 * scst_dg_dev_add() - Add a device to a device group.
 *
 * It is verified whether 'name' refers to an existing device and whether that
 * device has not yet been added to any other device group.
 */
int scst_dg_dev_add(struct scst_dev_group *dg, const char *name)
{
	struct scst_dg_dev *dgdev;
	struct scst_device *dev;
	int res;

	res = -ENOMEM;
	dgdev = kzalloc(sizeof(*dgdev), GFP_KERNEL);
	if (!dgdev)
		goto out;

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out_free;
	res = -EEXIST;
	if (__global_lookup_dg_dev_by_name(name))
		goto out_unlock;
	res = -EINVAL;
	dev = __lookup_dev(name);
	if (!dev)
		goto out_unlock;
	dgdev->dev = dev;
	res = scst_dg_dev_sysfs_add(dg, dgdev);
	if (res)
		goto out_unlock;
	list_add_tail(&dgdev->entry, &dg->dev_list);
	scst_update_dev_alua_filter(dg, dev);
	mutex_unlock(&scst_dg_mutex);

out:
	return res;

out_unlock:
	mutex_unlock(&scst_dg_mutex);
out_free:
	kfree(dgdev);
	goto out;
}

/* scst_dg_mutex supposed to be locked */
static void __scst_dg_dev_remove(struct scst_dev_group *dg,
				 struct scst_dg_dev *dgdev)
{
	if (dgdev->dev->stpg_ext_blocked) {
		TRACE_DBG("DG %s remove: unblocking STPG ext blocked "
			"dev %s", dg->name, dgdev->dev->virt_name);
		scst_ext_unblock_dev(dgdev->dev, true);
		dgdev->dev->stpg_ext_blocked = 0;
	}
	list_del(&dgdev->entry);
	scst_dg_dev_sysfs_del(dg, dgdev);
	scst_reset_dev_alua_filter(dgdev->dev);
	kfree(dgdev);
}

/**
 * scst_dg_dev_remove_by_name() - Remove a device from a device group.
 */
int scst_dg_dev_remove_by_name(struct scst_dev_group *dg, const char *name)
{
	struct scst_dg_dev *dgdev;
	int res;

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	dgdev = __lookup_dg_dev_by_name(dg, name);
	if (!dgdev)
		goto out_unlock;
	__scst_dg_dev_remove(dg, dgdev);
	res = 0;
out_unlock:
	mutex_unlock(&scst_dg_mutex);
out:
	return res;
}

/* Called from the device removal code. */
int scst_dg_dev_remove_by_dev(struct scst_device *dev)
{
	struct scst_dev_group *dg;
	struct scst_dg_dev *dgdev;
	int res;

	res = -EINVAL;

	mutex_lock(&scst_dg_mutex);
	dg = __lookup_dg_by_dev(dev);
	if (!dg)
		goto out;
	dgdev = __lookup_dg_dev_by_dev(dg, dev);
	BUG_ON(!dgdev);
	__scst_dg_dev_remove(dg, dgdev);
	res = 0;

out:
	mutex_unlock(&scst_dg_mutex);

	return res;
}

/*
 * Device group management.
 */

static void scst_release_dg(struct kobject *kobj)
{
	struct scst_dev_group *dg;

	dg = container_of(kobj, struct scst_dev_group, kobj);
	kfree(dg->name);
	kfree(dg);
}

static struct kobj_type scst_dg_ktype = {
#ifndef CONFIG_SCST_PROC
	.sysfs_ops = &scst_sysfs_ops,
#endif
	.release = scst_release_dg,
};

/**
 * scst_dg_add() - Add a new device group object and make it visible in sysfs.
 */
int scst_dg_add(struct kobject *parent, const char *name)
{
	struct scst_dev_group *dg;
	int res;

	TRACE_ENTRY();

	res = -ENOMEM;
	dg = kzalloc(sizeof(*dg), GFP_KERNEL);
	if (!dg)
		goto out;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 24)
	kobject_init(&dg->kobj, &scst_dg_ktype);
#else
	kobject_init(&dg->kobj);
	dg->kobj.ktype = &scst_dg_ktype;
#endif
	dg->name = kstrdup(name, GFP_KERNEL);
	if (!dg->name)
		goto out_put;

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out_put;
	res = -EEXIST;
	if (__lookup_dg_by_name(name))
		goto out_unlock;
	res = -ENOMEM;
	INIT_LIST_HEAD(&dg->dev_list);
	INIT_LIST_HEAD(&dg->tg_list);
	res = scst_dg_sysfs_add(parent, dg);
	if (res)
		goto out_unlock;
	list_add_tail(&dg->entry, &scst_dev_group_list);
	mutex_unlock(&scst_dg_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	mutex_unlock(&scst_dg_mutex);
out_put:
	kobject_put(&dg->kobj);
	goto out;
}

static void __scst_dg_remove(struct scst_dev_group *dg)
{
	struct scst_dg_dev *dgdev;
	struct scst_target_group *tg;

	lockdep_assert_held(&scst_dg_mutex);

	list_del(&dg->entry);
	scst_dg_sysfs_del(dg);
	list_for_each_entry(tg, &dg->tg_list, entry)
		__scst_tg_set_state(tg, SCST_TG_STATE_OPTIMIZED);
	while (!list_empty(&dg->dev_list)) {
		dgdev = list_first_entry(&dg->dev_list, struct scst_dg_dev,
					 entry);
		__scst_dg_dev_remove(dg, dgdev);
	}
	while (!list_empty(&dg->tg_list)) {
		tg = list_first_entry(&dg->tg_list, struct scst_target_group,
				      entry);
		__scst_tg_remove(dg, tg);
	}
	kobject_put(&dg->kobj);
}

int scst_dg_remove(const char *name)
{
	struct scst_dev_group *dg;
	int res;

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	dg = __lookup_dg_by_name(name);
	if (!dg)
		goto out_unlock;
	__scst_dg_remove(dg);
	res = 0;
out_unlock:
	mutex_unlock(&scst_dg_mutex);
out:
	return res;
}

/*
 * Given a pointer to a device_groups/<dg>/devices or
 * device_groups/<dg>/target_groups kobject, return the pointer to the
 * corresponding device group.
 *
 * Note: The caller must hold a reference on the kobject to avoid that the
 * object disappears before the caller stops using the device group pointer.
 */
struct scst_dev_group *scst_lookup_dg_by_kobj(struct kobject *kobj)
{
	int res;
	struct scst_dev_group *dg;

	dg = NULL;
	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res)
		goto out;
	list_for_each_entry(dg, &scst_dev_group_list, entry)
		if (dg->dev_kobj == kobj || dg->tg_kobj == kobj)
			goto out_unlock;
	dg = NULL;
out_unlock:
	mutex_unlock(&scst_dg_mutex);
out:
	return dg;
}


/*
 * Target group module management.
 */

void scst_tg_init(void)
{
}

void scst_tg_cleanup(void)
{
	struct scst_dev_group *tg;

	mutex_lock(&scst_dg_mutex);
	while (!list_empty(&scst_dev_group_list)) {
		tg = list_first_entry(&scst_dev_group_list,
				      struct scst_dev_group, entry);
		__scst_dg_remove(tg);
	}
	mutex_unlock(&scst_dg_mutex);
}

/*
 * Functions for target group related SCSI command support.
 */

/**
 * scst_lookup_tg_id() - Look up a target port group identifier.
 * @dev: SCST device.
 * @tgt: SCST target.
 *
 * Returns a non-zero number if the lookup was successful and zero if not.
 */
uint16_t scst_lookup_tg_id(struct scst_device *dev, struct scst_tgt *tgt)
{
	struct scst_dev_group *dg;
	struct scst_target_group *tg;
	struct scst_tg_tgt *tg_tgt;
	uint16_t tg_id = 0;

	TRACE_ENTRY();
	mutex_lock(&scst_dg_mutex);
	dg = __lookup_dg_by_dev(dev);
	if (!dg)
		goto out_unlock;
	tg_tgt = __lookup_dg_tgt(dg, tgt->tgt_name);
	if (!tg_tgt)
		goto out_unlock;
	tg = tg_tgt->tg;
	BUG_ON(!tg);
	tg_id = tg->group_id;
out_unlock:
	mutex_unlock(&scst_dg_mutex);

	TRACE_EXIT_RES(tg_id);
	return tg_id;
}
EXPORT_SYMBOL_GPL(scst_lookup_tg_id);

/**
 * scst_alua_configured() - Whether implicit ALUA has been configured.
 * @dev: Pointer to the SCST device to verify.
 */
bool scst_alua_configured(struct scst_device *dev)
{
	struct scst_dev_group *dg;

	mutex_lock(&scst_dg_mutex);
	dg = __lookup_dg_by_dev(dev);
	mutex_unlock(&scst_dg_mutex);

	return dg != NULL;
}
EXPORT_SYMBOL_GPL(scst_alua_configured);

/**
 * scst_tg_get_group_info() - Build REPORT TARGET GROUPS response.
 * @buf: Pointer to a pointer to which the result buffer pointer will be set.
 * @length: Response length, including the "RETURN DATA LENGTH" field.
 * @dev: Pointer to the SCST device for which to obtain group information.
 * @data_format: Three-bit response data format specification.
 */
int scst_tg_get_group_info(void **buf, uint32_t *length,
			   struct scst_device *dev, uint8_t data_format)
{
	struct scst_dev_group *dg;
	struct scst_target_group *tg;
	struct scst_tg_tgt *tgtgt;
	struct scst_tgt *tgt;
	uint8_t *p;
	uint32_t ret_data_len;
	uint16_t rel_tgt_id;
	int res;

	TRACE_ENTRY();

	BUG_ON(!buf);
	BUG_ON(!length);

	ret_data_len = 0;

	res = -EINVAL;
	switch (data_format) {
	case 0:
		break;
	case 1:
		/* Extended header */
		ret_data_len += 4;
		break;
	default:
		goto out;
	}

	*length = 4;

	mutex_lock(&scst_dg_mutex);

	dg = __lookup_dg_by_dev(dev);
	if (dg) {
		list_for_each_entry(tg, &dg->tg_list, entry) {
			/* Target port group descriptor header. */
			ret_data_len += 8;
			list_for_each_entry(tgtgt, &tg->tgt_list, entry) {
				/* Target port descriptor. */
				ret_data_len += 4;
			}
		}
	}

	*length += ret_data_len;

	res = -ENOMEM;
	*buf = kzalloc(*length, GFP_KERNEL);
	if (!*buf)
		goto out_unlock;

	p = *buf;
	/* Return data length. */
	put_unaligned_be32(ret_data_len, p);
	p += 4;
	if (data_format == 1) {
		/* Extended header */
		*p++ = 0x10; /* format = 1 */
		*p++ = 0x00; /* implicit transition time = 0 */
		p += 2;      /* reserved */
	}

	if (!dg)
		goto done;

	list_for_each_entry(tg, &dg->tg_list, entry) {
		/* Target port group descriptor header. */
		*p++ = (tg->preferred ? SCST_TG_PREFERRED : 0) | tg->state;
		*p++ = SCST_TG_SUP_OPTIMIZED
			| SCST_TG_SUP_NONOPTIMIZED
			| SCST_TG_SUP_STANDBY
			| SCST_TG_SUP_UNAVAILABLE
			| SCST_TG_SUP_TRANSITION;
		put_unaligned_be16(tg->group_id, p);
		p += 2;
		p++;      /* reserved */
		*p++ = 2; /* status code: implicit transition */
		p++;      /* vendor specific */
		list_for_each_entry(tgtgt, &tg->tgt_list, entry)
			(*p)++; /* target port count */
		p++;
		list_for_each_entry(tgtgt, &tg->tgt_list, entry) {
			tgt = tgtgt->tgt;
			rel_tgt_id = tgt ? tgt->rel_tgt_id : tgtgt->rel_tgt_id;
			/* Target port descriptor. */
			p += 2; /* reserved */
			/* Relative target port identifier. */
			put_unaligned_be16(rel_tgt_id, p);
			p += 2;
		}
	}

done:
	WARN_ON(p - (uint8_t *)*buf != *length);

	res = 0;

out_unlock:
	mutex_unlock(&scst_dg_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_tg_get_group_info);

struct scst_stpg_wait {
	atomic_t stpg_wait_left;
	int status;
	struct scst_dev_group *dg;
	struct scst_event_entry *event_entry;
};

/* No locks */
static void scst_stpg_check_blocking_done(struct scst_stpg_wait *wait)
{
	TRACE_ENTRY();

	TRACE_DBG("wait %p, left %d", wait, atomic_read(&wait->stpg_wait_left));

	if (atomic_dec_and_test(&wait->stpg_wait_left)) {
		if (wait->status == 0)
			scst_event_queue(SCST_EVENT_STPG_USER_INVOKE,
				SCST_EVENT_SCST_CORE_ISSUER, wait->event_entry);
		else {
			wait->event_entry->event_notify_fn(&wait->event_entry->event,
				wait->event_entry->notify_fn_priv, wait->status);
		}
		kfree(wait);
	}

	TRACE_EXIT();
	return;
}

/* No locks */
static void scst_stpg_ext_blocking_done(struct scst_device *dev,
	uint8_t *data, int len)
{
	sBUG_ON(len != sizeof(data));
	scst_stpg_check_blocking_done(*((struct scst_stpg_wait **)data));
}

/**
 * scst_tg_set_group_info - SET TARGET PORT GROUPS implementation.
 *
 * Returns >=0 upon success or negative error code otherwise, for instance,
 * if either an invalid group ID has been specified or the group ID
 * of a target group with one, or more non-local target ports has been
 * specified. In the error case the cmd has its sense set.
 *
 * In case of returned 0 the command completed asynchronously, i.e. upon
 * return might be already dead!!
 */
int scst_tg_set_group_info(struct scst_cmd *cmd)
{
	struct scst_device *dev = cmd->dev;
	uint8_t *buf;
	int len;
	int i, j, res = 1, tpg_desc_count, valid_desc_count;
	struct scst_dev_group *dg;
	struct osi {
		uint16_t	       group_id;
		struct scst_target_group *tg;
		enum scst_tg_state     prev_state;
		enum scst_tg_state     new_state;
	} *osi = NULL;
	int event_entry_len, payload_len;
	struct scst_event_entry *event_entry;
	struct scst_event *event;
	struct scst_event_stpg_payload *payload;
	struct scst_event_stpg_descr *descr;

	TRACE_ENTRY();

	len = scst_get_buf_full(cmd, &buf);
	if (len < 0) {
		PRINT_ERROR("scst_get_buf_full() failed: %d", len);
		res = len;
		if (len == -ENOMEM)
			scst_set_busy(cmd);
		else
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	/*
	 * From SPC-4: "A parameter list length of zero specifies that no data
	 * shall be transferred, and that no change shall be made in the
	 * target port asymmetric access state of any target port groups or
	 * target ports".
	 */
	if (len == 0)
		goto out_put;

	tpg_desc_count = (len - 4) / 4;
	/* Check for some reasonable limit */
	if (tpg_desc_count > 64) {
		PRINT_ERROR("Too many STPG descriptors (%d) for dev %s",
			tpg_desc_count, dev->virt_name);
		res = -EINVAL;
		scst_set_invalid_field_in_cdb(cmd, 6, 0);
		goto out_put;
	}

	TRACE_DBG("tpg_desc_count %d", tpg_desc_count);

	osi = kcalloc(tpg_desc_count, sizeof(*osi), GFP_KERNEL);
	if (!osi) {
		res = -ENOMEM;
		scst_set_busy(cmd);
		goto out_put;
	}

	res = mutex_lock_interruptible(&scst_mutex);
	if (res) {
		PRINT_INFO("mutex_lock_interruptible() returned %d, finishing "
			"cmd %p", res, cmd);
		scst_set_busy(cmd);
		goto out_put;
	}

	res = mutex_lock_interruptible(&scst_dg_mutex);
	if (res) {
		PRINT_INFO("mutex_lock_interruptible() returned %d, finishing "
			"cmd %p", res, cmd);
		scst_set_busy(cmd);
		goto out_unlock_sm_fail;
	}

	dg = __lookup_dg_by_dev(dev);
	if (!dg) {
		res = -EINVAL;
		goto out_unlock_fail;
	}

	TRACE_DBG("dg %s (%p) found, dev %s", dg->name, dg, dev->virt_name);

	for (i = 4, j = 0; i + 4 <= len; i += 4, j++) {
#ifndef __CHECKER__
		/*
		 * Hide the statement below for smatch because otherwise it
		 * triggers a false positive.
		 */
		WARN_ON_ONCE(j >= tpg_desc_count);
#endif
		osi[j].new_state = buf[i] & 0x1f;
		switch (osi[j].new_state) {
		case SCST_TG_STATE_OPTIMIZED:
		case SCST_TG_STATE_NONOPTIMIZED:
		case SCST_TG_STATE_STANDBY:
		case SCST_TG_STATE_UNAVAILABLE:
		case SCST_TG_STATE_OFFLINE:
			break;
		default:
			TRACE_MGMT_DBG("Incorrect new state %d", osi[j].new_state);
			res = -EINVAL;
			goto out_unlock_fail;
		}

		osi[j].group_id = get_unaligned_be16(&buf[i + 2]);
		if (!osi[j].group_id) {
			TRACE_MGMT_DBG("Invalid group_id %d", osi[j].group_id);
			res = -EINVAL;
			goto out_unlock_fail;
		}

		osi[j].tg = __lookup_tg_by_group_id(dg, osi[j].group_id);
		if (!osi[j].tg) {
			TRACE_MGMT_DBG("No TG for group_id %d", osi[j].group_id);
			res = -ESRCH;
			goto out_unlock_fail;
		}

		if (osi[j].tg->state == SCST_TG_STATE_TRANSITIONING) {
			TRACE_MGMT_DBG("TG %p is transitioning", osi[j].tg);
			res = -EBUSY;
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_alua_transitioning));
			/* second sense will not override the set one */
			goto out_unlock_fail;
		}
		osi[j].prev_state = osi[j].tg->state;

		TRACE_DBG("j %d, group_id %u, tg %s (%p), state %d", j, osi[j].group_id,
			osi[j].tg->name, osi[j].tg, osi[j].tg->state);
	}

	mutex_unlock(&scst_dg_mutex);
	mutex_unlock(&scst_mutex);

	scst_put_buf_full(cmd, buf);

	payload_len = sizeof(*payload) + sizeof(*descr) * tpg_desc_count;
	event_entry_len = sizeof(*event_entry) + payload_len;
	event_entry = kzalloc(event_entry_len, GFP_KERNEL);
	if (event_entry == NULL) {
		PRINT_ERROR("Unable to allocate event (size %d)", event_entry_len);
		res = -ENOMEM;
		scst_set_busy(cmd);
		goto out_free;
	}

	TRACE_MEM("event_entry %p (len %d) allocated", event_entry,
		event_entry_len);

	event = &event_entry->event;
	event->payload_len = payload_len;

	payload = (struct scst_event_stpg_payload *)event->payload;
	payload->stpg_cmd_tag = cmd->tag;

	res = 1;

	if (strlen(dev->virt_name) >= sizeof(payload->device_name)) {
		PRINT_ERROR("Device name %s too long", dev->virt_name);
		goto out_too_long;
	}
	strlcpy(payload->device_name, dev->virt_name, sizeof(payload->device_name));

	valid_desc_count = 0;
	for (j = 0, descr = &payload->stpg_descriptors[0]; j < tpg_desc_count; j++) {
		if (osi[j].prev_state == osi[j].new_state)
			continue;

		if (strlen(scst_alua_state_name(osi[j].prev_state)) >= sizeof(descr->prev_state)) {
			PRINT_ERROR("prev state too long (%d)", osi[j].prev_state);
			goto out_too_long;
		}
		strlcpy(descr->prev_state, scst_alua_state_name(osi[j].prev_state),
			sizeof(descr->prev_state));

		if (strlen(scst_alua_state_name(osi[j].new_state)) >= sizeof(descr->new_state)) {
			PRINT_ERROR("new state too long (%d)", osi[j].new_state);
			goto out_too_long;
		}
		strlcpy(descr->new_state, scst_alua_state_name(osi[j].new_state),
			sizeof(descr->new_state));

		if (strlen(dg->name) >= sizeof(descr->dg_name)) {
			PRINT_ERROR("dg_name too long (%s)", dg->name);
			goto out_too_long;
		}
		strlcpy(descr->dg_name, dg->name, sizeof(descr->dg_name));

		if (strlen(osi[j].tg->name) >= sizeof(descr->tg_name)) {
			PRINT_ERROR("tg_name too long (%s)", osi[j].tg->name);
			goto out_too_long;
		}
		strlcpy(descr->tg_name, osi[j].tg->name,
			sizeof(descr->tg_name));

		descr->group_id = osi[j].group_id;

		TRACE_DBG("group_id %u, prev_state %s, new_state %s, dg_name %s, "
			"tg_name %s", descr->group_id, descr->prev_state,
			descr->new_state, descr->dg_name, descr->tg_name);

		valid_desc_count++;
		descr++;
	}

	payload->stpg_descriptors_cnt = valid_desc_count;

	if (valid_desc_count > 0) {
		struct scst_dg_dev *dgd;
		struct scst_stpg_wait *wait;
		int rc;

		dg->stpg_rel_tgt_id = cmd->tgt->rel_tgt_id;
		dg->stpg_transport_id = kmemdup(cmd->sess->transport_id,
			scst_tid_size(cmd->sess->transport_id), GFP_KERNEL);
		if (dg->stpg_transport_id == NULL) {
			PRINT_ERROR("Unable to duplicate stpg_transport_id");
			goto out_free_event;
		}

		wait = kzalloc(sizeof(*wait), GFP_KERNEL);
		if (wait == NULL) {
			PRINT_ERROR("Unable to allocate STPG wait struct "
				"(size %zd)", sizeof(*wait));
			scst_set_busy(cmd);
			res = -ENOMEM;
			goto out_free_tr_id;
		}

		atomic_set(&wait->stpg_wait_left, 1);
		wait->event_entry = event_entry;

		event_entry->event_notify_fn = scst_event_stpg_notify_fn;
		event_entry->notify_fn_priv = cmd;

		mutex_lock(&scst_dg_mutex);
		list_for_each_entry(dgd, &dg->dev_list, entry) {
			if (dgd->dev == dev)
				continue;

			TRACE_DBG("STPG: ext blocking dev %s", dgd->dev->virt_name);

			atomic_inc(&wait->stpg_wait_left);

			rc = scst_ext_block_dev(dgd->dev, scst_stpg_ext_blocking_done,
				(uint8_t *)&wait, sizeof(wait), SCST_EXT_BLOCK_STPG);
			if (rc != 0) {
				TRACE_DBG("scst_ext_block_dev() failed "
					"with %d, reverting (cmd %p)", rc, cmd);
				wait->status = rc;
				wait->dg = dg;
				atomic_dec(&wait->stpg_wait_left);
				spin_lock_bh(&dev->dev_lock);
				WARN_ON(dgd->dev->stpg_ext_blocked);
				dgd->dev->stpg_ext_blocked = 0;
				spin_unlock_bh(&dev->dev_lock);
				break;
			}
		}
		mutex_unlock(&scst_dg_mutex);

		scst_stpg_check_blocking_done(wait);
		/* !! cmd can be already dead here !! */
	} else {
		TRACE_DBG("Nothing to do");
		goto out_free_event;
	}

	res = 0;

out_free:
	kfree(osi);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock_fail:
	mutex_unlock(&scst_dg_mutex);

out_unlock_sm_fail:
	mutex_unlock(&scst_mutex);

	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_set_target_pgs_failed));

out_put:
	scst_put_buf_full(cmd, buf);
	goto out_free;

out_too_long:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_set_target_pgs_failed));
	res = -EOVERFLOW;

out_free_tr_id:
	kfree(dg->stpg_transport_id);

out_free_event:
	kfree(event_entry);
	goto out_free;
}
EXPORT_SYMBOL_GPL(scst_tg_set_group_info);
