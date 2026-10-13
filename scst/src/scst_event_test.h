/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_EVENT_TEST_H
#define SCST_EVENT_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED

extern struct mutex scst_event_mutex;

int scst_event_get_user_payload_size(u32 *size, struct scst_event_user __user *arg);
int scst_event_get_user_size(s32 *size, const void __user *arg);
int scst_event_put_user_size(s32 size, void __user *arg);
unsigned long scst_event_copy_from_user(void *to, const void __user *from, size_t size);
unsigned long scst_event_copy_to_user(void __user *to, const void *from, size_t size);
struct scst_event_entry *scst_event_alloc_user_entry(size_t size);
void scst_event_timeout_fn(struct work_struct *work);
int scst_clone_event(const struct scst_event_entry *orig_entry,
		     struct scst_event_entry **new_event_entry);
long scst_event_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_EVENT_TEST_H */
