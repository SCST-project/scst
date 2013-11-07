/*
 *  scst_tg.c
 *
 *  SCSI target group related code.
 *
 *  Copyright (C) 2011-2013 Bart Van Assche <bvanassche@acm.org>.
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
#include <asm/unaligned.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_priv.h"

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

static struct list_head scst_dev_group_list;

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	BUG_ON(!dg);
	BUG_ON(!tgt_name);
	list_for_each_entry(tg, &dg->tg_list, entry)
		list_for_each_entry(tg_tgt, &tg->tgt_list, entry)
			if (strcmp(tg_tgt->name, tgt_name) == 0)
				return tg_tgt;

	return NULL;
}

/* Look up a target group by name in the given device group. */
static struct scst_target_group *
__lookup_tg_by_name(struct scst_dev_group *dg, const char *name)
{
	struct scst_target_group *tg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	list_for_each_entry(tg, &dg->tg_list, entry)
		if (strcmp(tg->name, name) == 0)
			return tg;

	return NULL;
}

/* Look up a target group by target port. */
static struct scst_target_group *
__lookup_tg_by_tgt(struct scst_dev_group *dg, const struct scst_tgt *tgt)
{
	struct scst_target_group *tg;
	struct scst_tg_tgt *tg_tgt;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	list_for_each_entry(dg, &scst_dev_group_list, entry)
		if (strcmp(dg->name, name) == 0)
			return dg;

	return NULL;
}

/* Look up a device group by device pointer. */
static struct scst_dev_group *__lookup_dg_by_dev(struct scst_device *dev)
{
	struct scst_dev_group *dg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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
 * Whether or not to accept a command in the ALUA unavailable and transitioning
 * states.
 */
static bool scst_tg_accept(struct scst_cmd *cmd)
{
	switch (cmd->cdb[0]) {
	case TEST_UNIT_READY:
	case GET_EVENT_STATUS_NOTIFICATION:
	case INQUIRY:
	case MODE_SENSE:
	case MODE_SENSE_10:
	case READ_CAPACITY:
	case REPORT_LUNS:
	case REQUEST_SENSE:
		return true;
	case SERVICE_ACTION_IN:
		switch (cmd->cdb[1] & 0x1f) {
		case SAI_READ_CAPACITY_16:
			return true;
		}
		break;
	case MAINTENANCE_IN:
		switch (cmd->cdb[1] & 0x1f) {
		case MI_REPORT_TARGET_PGS:
			return true;
		}
		break;
	case MAINTENANCE_OUT:
		switch (cmd->cdb[1] & 0x1f) {
		case MO_SET_TARGET_PGS:
			return true;
		}
		break;
	}

	return false;
}

/*
 * Whether or not to accept a command in the ALUA unavailable state.
 */
static bool scst_tg_accept_unav(struct scst_cmd *cmd)
{
	bool process_cmd = scst_tg_accept(cmd);

	if (!process_cmd)
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_tp_unav));

	return process_cmd;
}

/*
 * Whether or not to accept a command in the ALUA transitioning state.
 */
static bool scst_tg_accept_transitioning(struct scst_cmd *cmd)
{
	bool process_cmd = scst_tg_accept(cmd);

	if (!process_cmd)
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_tp_transitioning));

	return process_cmd;
}

static bool (*scst_alua_filter[])(struct scst_cmd *cmd) = {
	[SCST_TG_STATE_OPTIMIZED]	= NULL,
	[SCST_TG_STATE_NONOPTIMIZED]	= NULL,
	[SCST_TG_STATE_STANDBY]		= NULL,
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	tgt_dev->alua_filter = scst_alua_filter[state];
}

/* Update the ALUA filter after an ALUA state change and generate UA */
static void scst_tg_change_tgt_dev_state(struct scst_tgt_dev *tgt_dev,
					 enum scst_tg_state state,
					 bool gen_ua)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	TRACE_MGMT_DBG("ALUA state of tgt_dev %p has changed", tgt_dev);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	dg = __lookup_dg_by_dev(tgt_dev->dev);
	if (dg) {
		tg = __lookup_tg_by_tgt(dg, tgt_dev->acg_dev->acg->tgt);
		if (tg) {
			scst_update_tgt_dev_alua_filter(tgt_dev, tg->state);
			scst_check_alua_invariant();
		}
	}
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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
	res = -EEXIST;
	tgt = __lookup_tgt(name);
	if (__lookup_dg_tgt(tg->dg, name))
		goto out_unlock;
	tg_tgt->tgt = tgt;
	res = scst_tg_tgt_sysfs_add(tg, tg_tgt);
	if (res)
		goto out_unlock;
	list_add_tail(&tg_tgt->entry, &tg->tgt_list);
	scst_update_tgt_alua_filter(tg, tgt);
	res = 0;
	mutex_unlock(&scst_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
out_unlock:
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
	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	tg_tgt = __lookup_dg_tgt(tg->dg, name);
	if (!tg_tgt)
		goto out_unlock;
	__scst_tg_tgt_remove(tg, tg_tgt);
	res = 0;
out_unlock:
	mutex_unlock(&scst_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Caller must hold scst_mutex. Called from the target removal code. */
void scst_tg_tgt_remove_by_tgt(struct scst_tgt *tgt)
{
	struct scst_dev_group *dg;
	struct scst_target_group *tg;
	struct scst_tg_tgt *t, *t2;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	BUG_ON(!tgt);
	list_for_each_entry(dg, &scst_dev_group_list, entry)
		list_for_each_entry(tg, &dg->tg_list, entry)
			list_for_each_entry_safe(t, t2, &tg->tgt_list, entry)
				if (t->tgt == tgt)
					__scst_tg_tgt_remove(tg, t);
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

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out_put;
	res = -EEXIST;
	if (__lookup_tg_by_name(dg, name))
		goto out_unlock;
	res = scst_tg_sysfs_add(dg, tg);
	if (res)
		goto out_unlock;
	list_add_tail(&tg->entry, &dg->tg_list);
	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	mutex_unlock(&scst_mutex);
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

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	tg = __lookup_tg_by_name(dg, name);
	if (!tg)
		goto out_unlock;
	__scst_tg_remove(dg, tg);
	res = 0;
out_unlock:
	mutex_unlock(&scst_mutex);
out:
	return res;
}

/*
 * Update the ALUA filter of those LUNs (tgt_dev) whose target port is a member
 * of target group @tg and that export a device that is a member of the device
 * group @tg->dg.
 */
static void __scst_tg_set_state(struct scst_target_group *tg,
				enum scst_tg_state state,
				struct scst_tgt *no_ua_tgt)
{
	struct scst_dg_dev *dg_dev;
	struct scst_device *dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_tg_tgt *tg_tgt;
	struct scst_tgt *tgt;

	sBUG_ON(state >= ARRAY_SIZE(scst_alua_filter));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	if (tg->state == state)
		return;

	tg->state = state;

	list_for_each_entry(dg_dev, &tg->dg->dev_list, entry) {
		dev = dg_dev->dev;
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			tgt = tgt_dev->sess->tgt;
			list_for_each_entry(tg_tgt, &tg->tgt_list, entry) {
				if (tg_tgt->tgt == tgt) {
					scst_tg_change_tgt_dev_state(tgt_dev,
						state, tgt != no_ua_tgt);
					break;
				}
			}
		}
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

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;

	__scst_tg_set_state(tg, state, NULL);

	mutex_unlock(&scst_mutex);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;
	__scst_tg_set_preferred(tg, preferred);
	mutex_unlock(&scst_mutex);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

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

	res = mutex_lock_interruptible(&scst_mutex);
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
	mutex_unlock(&scst_mutex);

out:
	return res;

out_unlock:
	mutex_unlock(&scst_mutex);
out_free:
	kfree(dgdev);
	goto out;
}

static void __scst_dg_dev_remove(struct scst_dev_group *dg,
				 struct scst_dg_dev *dgdev)
{
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

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	dgdev = __lookup_dg_dev_by_name(dg, name);
	if (!dgdev)
		goto out_unlock;
	__scst_dg_dev_remove(dg, dgdev);
	res = 0;
out_unlock:
	mutex_unlock(&scst_mutex);
out:
	return res;
}

/* Caller must hold scst_mutex. Called from the device removal code. */
int scst_dg_dev_remove_by_dev(struct scst_device *dev)
{
	struct scst_dev_group *dg;
	struct scst_dg_dev *dgdev;
	int res;

	res = -EINVAL;
	dg = __lookup_dg_by_dev(dev);
	if (!dg)
		goto out;
	dgdev = __lookup_dg_dev_by_dev(dg, dev);
	BUG_ON(!dgdev);
	__scst_dg_dev_remove(dg, dgdev);
	res = 0;
out:
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

	res = mutex_lock_interruptible(&scst_mutex);
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
	mutex_unlock(&scst_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	mutex_unlock(&scst_mutex);
out_put:
	kobject_put(&dg->kobj);
	goto out;
}

static void __scst_dg_remove(struct scst_dev_group *dg)
{
	struct scst_dg_dev *dgdev;
	struct scst_target_group *tg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&scst_mutex);
#endif

	list_del(&dg->entry);
	scst_dg_sysfs_del(dg);
	list_for_each_entry(tg, &dg->tg_list, entry)
		__scst_tg_set_state(tg, SCST_TG_STATE_OPTIMIZED, NULL);
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

	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;
	res = -EINVAL;
	dg = __lookup_dg_by_name(name);
	if (!dg)
		goto out_unlock;
	__scst_dg_remove(dg);
	res = 0;
out_unlock:
	mutex_unlock(&scst_mutex);
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
	res = mutex_lock_interruptible(&scst_mutex);
	if (res)
		goto out;
	list_for_each_entry(dg, &scst_dev_group_list, entry)
		if (dg->dev_kobj == kobj || dg->tg_kobj == kobj)
			goto out_unlock;
	dg = NULL;
out_unlock:
	mutex_unlock(&scst_mutex);
out:
	return dg;
}


/*
 * Target group module management.
 */

void scst_tg_init(void)
{
	INIT_LIST_HEAD(&scst_dev_group_list);
}

void scst_tg_cleanup(void)
{
	struct scst_dev_group *tg;

	mutex_lock(&scst_mutex);
	while (!list_empty(&scst_dev_group_list)) {
		tg = list_first_entry(&scst_dev_group_list,
				      struct scst_dev_group, entry);
		__scst_dg_remove(tg);
	}
	mutex_unlock(&scst_mutex);
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
	mutex_lock(&scst_mutex);
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
	mutex_unlock(&scst_mutex);

	TRACE_EXIT_RES(tg_id);
	return tg_id;
}
EXPORT_SYMBOL_GPL(scst_lookup_tg_id);

/**
 * scst_impl_alua_configured() - Whether implicit ALUA has been configured.
 * @dev: Pointer to the SCST device to verify.
 */
bool scst_impl_alua_configured(struct scst_device *dev)
{
	struct scst_dev_group *dg;

	mutex_lock(&scst_mutex);
	dg = __lookup_dg_by_dev(dev);
	mutex_unlock(&scst_mutex);

	return dg != NULL;
}
EXPORT_SYMBOL_GPL(scst_impl_alua_configured);

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

	mutex_lock(&scst_mutex);

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
			| SCST_TG_SUP_UNAVAILABLE;
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
	mutex_unlock(&scst_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_tg_get_group_info);
