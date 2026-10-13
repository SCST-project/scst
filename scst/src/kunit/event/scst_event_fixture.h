/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_EVENT_FIXTURE_H
#define SCST_EVENT_FIXTURE_H

#include "../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../scst_priv.h"
#include <linux/fs.h>
#include <linux/limits.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_event.h>
#else
#include "scst_event.h"
#endif
#include "../../scst_event_priv.h"
#include "../../scst_event_test.h"

struct event_test_fixture {
	struct file file;
	struct scst_event_priv priv;
	u8 input[sizeof(struct scst_event) + SCST_MAX_PAYLOAD];
	u8 output[sizeof(struct scst_event_user) + SCST_MAX_PAYLOAD + 16];
	size_t input_size;
	s32 user_size;
	s32 needed_size;
	int read_error;
	int put_error;
	unsigned int reads;
	unsigned int puts;
	unsigned int imports;
	unsigned int exports;
	unsigned int allocations;
	size_t from_left;
	size_t to_left;
	size_t imported;
	size_t exported;
	size_t allocation_size;
	struct scst_event_entry *allocation;
	struct scst_event_entry *detached;
	bool fail_alloc;
	bool importing;
	unsigned int notifications;
	int notify_status;
	u32 notify_id;
};

/* Stubs interpret this token; it is never dereferenced as a userspace address. */

extern void __user * const event_test_arg;
struct scst_event *event_test_input(struct event_test_fixture *f, unsigned int length,
				    u32 code, const char *issuer);
long event_test_ioctl(struct event_test_fixture *f, unsigned int command);
struct scst_event_entry *event_test_queue(struct event_test_fixture *f,
					  unsigned int length, u32 id, bool notify);
void event_test_ack_input(struct event_test_fixture *f, u32 id, int status);
unsigned int event_test_list_count(struct list_head *head);
int event_test_init(struct kunit *test);
void event_test_exit(struct kunit *test);

#endif /* SCST_EVENT_FIXTURE_H */
