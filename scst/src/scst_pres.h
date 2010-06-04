/*
 *  scst_pres.c
 *
 *  Copyright (C) 2009 - 2010 Alexey Obitotskiy <alexeyo1@open-e.com>
 *  Copyright (C) 2009 - 2010 Open-E, Inc.
 *  Copyright (C) 2009 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
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

#define PR_REGISTER				0x00
#define PR_RESERVE				0x01
#define PR_RELEASE				0x02
#define PR_CLEAR				0x03
#define PR_PREEMPT				0x04
#define PR_PREEMPT_AND_ABORT			0x05
#define PR_REGISTER_AND_IGNORE			0x06
#define PR_REGISTER_AND_MOVE			0x07

#define PR_READ_KEYS				0x00
#define PR_READ_RESERVATION			0x01
#define PR_REPORT_CAPS				0x02
#define PR_READ_FULL_STATUS			0x03

#define TYPE_UNSPECIFIED			(-1)
#define TYPE_WRITE_EXCLUSIVE			0x01
#define TYPE_EXCLUSIVE_ACCESS			0x03
#define TYPE_WRITE_EXCLUSIVE_REGONLY		0x05
#define TYPE_EXCLUSIVE_ACCESS_REGONLY		0x06
#define TYPE_WRITE_EXCLUSIVE_ALL_REG		0x07
#define TYPE_EXCLUSIVE_ACCESS_ALL_REG		0x08

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

#ifndef CONFIG_SCST_PROC
int scst_pr_check_pr_path(void);
#endif

static inline bool scst_pr_read_lock(struct scst_device *dev)
{
	bool unlock = false;

	TRACE_ENTRY();

	atomic_inc(&dev->pr_readers_count);
	smp_mb__after_atomic_inc(); /* to sync with scst_pr_write_lock() */

	if (unlikely(dev->pr_writer_active)) {
		unlock = true;
		atomic_dec(&dev->pr_readers_count);
		mutex_lock(&dev->dev_pr_mutex);
	}

	TRACE_EXIT_RES(unlock);
	return unlock;
}

static inline void scst_pr_read_unlock(struct scst_device *dev, bool unlock)
{
	TRACE_ENTRY();

	if (unlikely(unlock))
		mutex_unlock(&dev->dev_pr_mutex);
	else {
		/*
		 * To sync with scst_pr_write_lock(). We need it to ensure
		 * order of our reads with the writer's writes.
		 */
		smp_mb__before_atomic_dec();
		atomic_dec(&dev->pr_readers_count);
	}

	TRACE_EXIT();
	return;
}

static inline void scst_pr_write_lock(struct scst_device *dev)
{
	TRACE_ENTRY();

	mutex_lock(&dev->dev_pr_mutex);

	dev->pr_writer_active = 1;

	/* to sync with scst_pr_read_lock() and unlock() */
	smp_mb();

	while (atomic_read(&dev->pr_readers_count) != 0) {
		TRACE_DBG("Waiting for %d readers (dev %p)",
			atomic_read(&dev->pr_readers_count), dev);
		msleep(1);
	}

	TRACE_EXIT();
	return;
}

static inline void scst_pr_write_unlock(struct scst_device *dev)
{
	TRACE_ENTRY();

	dev->pr_writer_active = 0;

	mutex_unlock(&dev->dev_pr_mutex);

	TRACE_EXIT();
	return;
}

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

#ifndef CONFIG_SCST_PROC
void scst_pr_sync_device_file(struct scst_tgt_dev *tgt_dev, struct scst_cmd *cmd);
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
void scst_pr_dump_prs(struct scst_device *dev, bool force);
#else
static inline void scst_pr_dump_prs(struct scst_device *dev, bool force) {}
#endif

#endif /* SCST_PRES_H_ */
