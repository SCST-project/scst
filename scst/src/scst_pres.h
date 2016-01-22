/*
 *  scst_pres.c
 *
 *  Copyright (C) 2009 - 2010 Alexey Obitotskiy <alexeyo1@open-e.com>
 *  Copyright (C) 2009 - 2010 Open-E, Inc.
 *  Copyright (C) 2009 - 2016 Vladislav Bolkhovitin <vst@vlnb.net>
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

#ifndef SCST_PRES_H_
#define SCST_PRES_H_

#include <linux/delay.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_debug.h>
#else
#include "scst_debug.h"
#endif

/* PERSISTENT RESERVE OUT service action code */
#define PR_REGISTER				0x00
#define PR_RESERVE				0x01
#define PR_RELEASE				0x02
#define PR_CLEAR				0x03
#define PR_PREEMPT				0x04
#define PR_PREEMPT_AND_ABORT			0x05
#define PR_REGISTER_AND_IGNORE			0x06
#define PR_REGISTER_AND_MOVE			0x07

/* PERSISTENT RESERVE IN service action code */
#define PR_READ_KEYS				0x00
#define PR_READ_RESERVATION			0x01
#define PR_REPORT_CAPS				0x02
#define PR_READ_FULL_STATUS			0x03

/* Persistent reservation TYPE field */
#define TYPE_UNSPECIFIED			(-1)
#define TYPE_WRITE_EXCLUSIVE			0x01
#define TYPE_EXCLUSIVE_ACCESS			0x03
#define TYPE_WRITE_EXCLUSIVE_REGONLY		0x05
#define TYPE_EXCLUSIVE_ACCESS_REGONLY		0x06
#define TYPE_WRITE_EXCLUSIVE_ALL_REG		0x07
#define TYPE_EXCLUSIVE_ACCESS_ALL_REG		0x08

/* Persistent reservation SCOPE field */
#define SCOPE_LU				0x00

static inline bool scst_pr_type_valid(uint8_t type)
{
	switch (type) {
	case TYPE_WRITE_EXCLUSIVE:
	case TYPE_EXCLUSIVE_ACCESS:
	case TYPE_WRITE_EXCLUSIVE_REGONLY:
	case TYPE_EXCLUSIVE_ACCESS_REGONLY:
	case TYPE_WRITE_EXCLUSIVE_ALL_REG:
	case TYPE_EXCLUSIVE_ACCESS_ALL_REG:
		return true;
	default:
		return false;
	}
}

static inline void scst_pr_read_lock(struct scst_device *dev)
{
	mutex_lock(&dev->dev_pr_mutex);
}

static inline void scst_pr_read_unlock(struct scst_device *dev)
{
	mutex_unlock(&dev->dev_pr_mutex);
}

static inline void lockdep_assert_pr_read_lock_held(struct scst_device *dev)
{
	lockdep_assert_held(&dev->dev_pr_mutex);
}

static inline void scst_pr_write_lock(struct scst_device *dev)
{
	mutex_lock(&dev->dev_pr_mutex);
}

static inline void scst_pr_write_unlock(struct scst_device *dev)
{
	mutex_unlock(&dev->dev_pr_mutex);
}

static inline void lockdep_assert_pr_write_lock_held(struct scst_device *dev)
{
	lockdep_assert_held(&dev->dev_pr_mutex);
}

int scst_pr_set_file_name(struct scst_device *dev, char **prev,
			  const char *fmt, ...) __printf(3, 4);

int scst_pr_init_dev(struct scst_device *dev);
void scst_pr_clear_dev(struct scst_device *dev);

int scst_pr_init_tgt_dev(struct scst_tgt_dev *tgt_dev);
void scst_pr_clear_tgt_dev(struct scst_tgt_dev *tgt_dev);

bool scst_pr_crh_case(struct scst_cmd *cmd);
bool scst_pr_is_cmd_allowed(struct scst_cmd *cmd);

void scst_pr_register(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_register_and_ignore(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);
void scst_pr_register_and_move(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);
void scst_pr_reserve(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_release(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_clear(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_preempt(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_preempt_and_abort(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);

void scst_pr_read_keys(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_read_reservation(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);
void scst_pr_report_caps(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_read_full_status(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);

int scst_tid_size(const uint8_t *tid);
bool tid_equal(const uint8_t *tid_a, const uint8_t *tid_b);

struct scst_dev_registrant *scst_pr_find_reg(struct scst_device *dev,
	const uint8_t *transport_id, const uint16_t rel_tgt_id);
struct scst_dev_registrant *scst_pr_add_registrant(struct scst_device *dev,
						   const uint8_t *transport_id,
						   const uint16_t rel_tgt_id,
						   __be64 key,
						   bool dev_lock_locked);
void scst_pr_remove_registrant(struct scst_device *dev,
			       struct scst_dev_registrant *reg);
void scst_pr_set_holder(struct scst_device *dev,
			struct scst_dev_registrant *holder, uint8_t scope,
			uint8_t type);
void scst_pr_clear_holder(struct scst_device *dev);

#ifndef CONFIG_SCST_PROC
void scst_pr_sync_device_file(struct scst_tgt_dev *tgt_dev, struct scst_cmd *cmd);
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
void scst_pr_dump_prs(struct scst_device *dev, bool force);
#else
static inline void scst_pr_dump_prs(struct scst_device *dev, bool force) {}
#endif

#endif /* SCST_PRES_H_ */
