/*
 * Copyright (c) 2013 - 2014 Fusion-io, Inc. All rights reserved.
 * Copyright (C) 2014 - 2017 SanDisk Corporation.
 *
 * Synchronization framework of persistent registration data without DLM lock.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_const.h>
#else
#include "scst.h"
#include "scst_const.h"
#endif
#include "scst_priv.h"
#include "scst_pres.h"

static int scst_no_dlm_pr_init(struct scst_device *dev, const char *cl_dev_id)
{
	return 0;
}

static void scst_no_dlm_pr_cleanup(struct scst_device *dev)
{
}

static bool scst_no_dlm_pr_is_set(struct scst_device *dev)
{
	return dev->pr_is_set;
}

static void scst_no_dlm_pr_init_reg(struct scst_device *dev,
			     struct scst_dev_registrant *reg)
{
}

static void scst_no_dlm_pr_rm_reg(struct scst_device *dev,
			   struct scst_dev_registrant *reg)
{
}

static void scst_no_dlm_pr_write_lock(struct scst_device *dev,
				      struct scst_lksb *pr_lksb)
{
	scst_pr_write_lock(dev);
}

static void scst_no_dlm_pr_write_unlock(struct scst_device *dev,
					struct scst_lksb *pr_lksb)
{
	scst_pr_write_unlock(dev);
}

static bool scst_no_dlm_reserved(struct scst_device *dev)
{
	return dev->reserved_by;
}

static void scst_no_dlm_res_lock(struct scst_device *dev,
				 struct scst_lksb *pr_lksb)
	__acquires(&dev->dev_lock)
{
	EXTRACHECKS_BUG_ON(in_irq() || irqs_disabled());
	spin_lock_bh(&dev->dev_lock);
}

static void scst_no_dlm_res_unlock(struct scst_device *dev,
				   struct scst_lksb *pr_lksb)
	__releases(&dev->dev_lock)
{
	spin_unlock_bh(&dev->dev_lock);
}

static bool scst_no_dlm_is_rsv_holder(struct scst_device *dev,
				      struct scst_session *sess)
{
	EXTRACHECKS_BUG_ON(sess == NULL);
	return dev->reserved_by == sess;
}

static bool scst_no_dlm_is_not_rsv_holder(struct scst_device *dev,
					  struct scst_session *sess)
{
	EXTRACHECKS_BUG_ON(sess == NULL);
	return dev->reserved_by && dev->reserved_by != sess;
}

static void scst_no_dlm_reserve(struct scst_device *dev,
				struct scst_session *sess)
{
	dev->reserved_by = sess;
}

const struct scst_cl_ops scst_no_dlm_cl_ops = {
	.pr_init		= scst_no_dlm_pr_init,
	.pr_cleanup		= scst_no_dlm_pr_cleanup,
	.pr_is_set		= scst_no_dlm_pr_is_set,
	.pr_init_reg		= scst_no_dlm_pr_init_reg,
	.pr_rm_reg		= scst_no_dlm_pr_rm_reg,
	.pr_write_lock		= scst_no_dlm_pr_write_lock,
	.pr_write_unlock	= scst_no_dlm_pr_write_unlock,
	.reserved		= scst_no_dlm_reserved,
	.res_lock		= scst_no_dlm_res_lock,
	.res_unlock		= scst_no_dlm_res_unlock,
	.is_rsv_holder		= scst_no_dlm_is_rsv_holder,
	.is_not_rsv_holder	= scst_no_dlm_is_not_rsv_holder,
	.reserve		= scst_no_dlm_reserve,
};
