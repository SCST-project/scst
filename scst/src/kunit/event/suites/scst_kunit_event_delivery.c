// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_event_fixture.h"
/* Event ioctl ownership and error paths, without registering an event client. */

struct event_delivery_case {
	const char *name;
	unsigned int length;
	int delta;
	int result;
	size_t uncopied;
	bool large_buffer;
	bool zero_buffer;
	bool negative_buffer;
	bool read_fault;
	bool put_fault;
	bool notify;
	bool empty;
	bool exiting;
};

static const struct event_delivery_case event_delivery_cases[] = {
	{ .name = "empty_payload_exact_buffer" },
	{ .name = "one_byte_exact_buffer", .length = 1 },
	{ .name = "binary_payload", .length = 256 },
	{ .name = "maximum_payload", .length = SCST_MAX_PAYLOAD },
	{ .name = "larger_buffer", .length = 3, .delta = 1 },
	{ .name = "int_max_buffer", .length = 3, .large_buffer = true },
	{ .name = "zero_buffer", .zero_buffer = true, .result = -ENOSPC },
	{ .name = "negative_buffer", .negative_buffer = true, .result = -ENOSPC },
	{ .name = "short_header", .delta = -1, .result = -ENOSPC },
	{ .name = "short_payload", .length = SCST_MAX_PAYLOAD, .delta = -1,
	  .result = -ENOSPC },
	{ .name = "needed_size_write_fault", .delta = -1, .put_fault = true,
	  .result = -EFAULT },
	{ .name = "capacity_read_fault", .read_fault = true, .result = -EFAULT },
	{ .name = "full_copy_fault", .uncopied = SIZE_MAX, .result = -EFAULT },
	{ .name = "last_header_byte_fault", .uncopied = 1, .result = -EFAULT },
	{ .name = "partial_payload_fault", .length = 256, .uncopied = 128,
	  .result = -EFAULT },
	{ .name = "notify_moves_to_processing", .length = 3, .notify = true },
	{ .name = "notify_copy_fault_stays_queued", .length = 3, .notify = true,
	  .uncopied = 1, .result = -EFAULT },
	{ .name = "notify_short_buffer_stays_queued", .length = 3, .notify = true,
	  .delta = -1, .result = -ENOSPC },
	{ .name = "empty_nonblocking_queue", .empty = true, .result = -EAGAIN },
	{ .name = "client_exiting", .empty = true, .exiting = true, .result = -EINTR },
};

static void event_delivery_desc(const struct event_delivery_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(event_delivery, event_delivery_cases, event_delivery_desc);

static void event_delivery_test(struct kunit *test)
{
	const struct event_delivery_case *p = test->param_value;
	struct event_test_fixture *f = test->priv;
	struct scst_event_entry *e;
	size_t needed = sizeof(struct scst_event) + p->length;
	size_t offset = offsetof(struct scst_event_user, out_event);
	bool short_buffer, copied;
	unsigned int queued, processing;
	size_t i, bytes;

	if (!p->empty) {
		e = event_test_queue(f, p->length, 42, p->notify);
		KUNIT_ASSERT_NOT_NULL(test, e);
		memcpy(f->input, &e->event, needed);
		KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 0, 43, false));
	}
	f->user_size = needed + p->delta;
	if (p->large_buffer)
		f->user_size = INT_MAX;
	if (p->zero_buffer)
		f->user_size = 0;
	if (p->negative_buffer)
		f->user_size = -1;
	f->read_error = p->read_fault ? -EFAULT : 0;
	f->put_error = p->put_fault ? -EFAULT : 0;
	f->to_left = p->uncopied;
	f->priv.going_to_exit = p->exiting;
	short_buffer = !p->empty && !p->read_fault && (int)needed > f->user_size;
	copied = !p->empty && !p->read_fault && !short_buffer;

	KUNIT_EXPECT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), (long)p->result);
	KUNIT_EXPECT_EQ(test, f->reads, 1U);
	KUNIT_EXPECT_EQ(test, f->puts, (unsigned int)short_buffer);
	KUNIT_EXPECT_EQ(test, f->exports, (unsigned int)copied);
	KUNIT_EXPECT_EQ(test, f->notifications, 0U);
	if (short_buffer)
		KUNIT_EXPECT_EQ(test, f->needed_size, (s32)needed);
	bytes = copied ? needed - min(needed, p->uncopied) : 0;
	if (copied) {
		KUNIT_EXPECT_EQ(test, f->exported, needed);
		KUNIT_EXPECT_EQ(test, memcmp(f->output + offset, f->input, bytes), 0);
	}
	/* Neither the outer size field nor bytes after the event are exported. */
	for (i = 0; i < offset; i++)
		KUNIT_EXPECT_EQ(test, f->output[i], (u8)0xa5);
	KUNIT_EXPECT_NULL(test, memchr_inv(f->output + offset + bytes, 0xa5,
					   sizeof(f->output) - offset - bytes));
	queued = p->empty ? 0 : p->result ? 2 : 1;
	processing = p->notify && !p->result;
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, (int)queued);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.queued_events_list), queued);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.processing_events_list), processing);
	if (queued) {
		KUNIT_ASSERT_FALSE(test, list_empty(&f->priv.queued_events_list));
		e = list_first_entry(&f->priv.queued_events_list, struct scst_event_entry,
				     events_list_entry);
		KUNIT_EXPECT_EQ(test, e->event.event_id, p->result ? 42U : 43U);
	}
	if (processing) {
		KUNIT_ASSERT_FALSE(test, list_empty(&f->priv.processing_events_list));
		e = list_first_entry(&f->priv.processing_events_list, struct scst_event_entry,
				     events_list_entry);
		KUNIT_EXPECT_EQ(test, e->event.event_id, 42U);
	}
}

static void event_delivery_retry_test(struct kunit *test)
{
	struct event_test_fixture *f = test->priv;
	struct scst_event_user *output = (void *)f->output;

	KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 256, 42, false));
	KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 0, 43, false));
	f->user_size = 0;
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), (long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, f->needed_size, (s32)(sizeof(struct scst_event) + 256));
	f->user_size = f->needed_size;
	f->to_left = 1;
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, 2);
	f->to_left = 0;
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
	KUNIT_EXPECT_EQ(test, output->out_event.event_id, 42U);
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, 1);
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
	KUNIT_EXPECT_EQ(test, output->out_event.event_id, 43U);
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, 0);
	KUNIT_EXPECT_TRUE(test, list_empty(&f->priv.queued_events_list));
	KUNIT_EXPECT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), (long)-EAGAIN);
}

struct event_ack_case {
	const char *name;
	int status;
	int result;
	size_t uncopied;
	bool unknown;
	bool queued;
	bool repeat;
};

static const struct event_ack_case event_ack_cases[] = {
	{ .name = "successful_notification" },
	{ .name = "negative_status", .status = -EIO },
	{ .name = "positive_status", .status = 1 },
	{ .name = "unknown_id", .unknown = true, .result = -ENOENT },
	{ .name = "queued_event_is_not_delivered", .queued = true, .result = -ENOENT },
	{ .name = "input_copy_fault", .uncopied = SIZE_MAX, .result = -EFAULT },
	{ .name = "partial_status_copy_fault", .uncopied = 1, .result = -EFAULT },
	{ .name = "acknowledge_once", .repeat = true },
};

static void event_ack_desc(const struct event_ack_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(event_ack, event_ack_cases, event_ack_desc);

static void event_ack_test(struct kunit *test)
{
	const struct event_ack_case *p = test->param_value;
	struct event_test_fixture *f = test->priv;
	unsigned int processing = p->queued ? 0 : p->result ? 2 : 1;

	KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 3, 42, true));
	KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 3, 43, true));
	if (!p->queued) {
		KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
		KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
	}
	event_test_ack_input(f, p->unknown ? 99 : 42, p->status);
	f->from_left = p->uncopied;
	KUNIT_EXPECT_EQ(test, event_test_ioctl(f, SCST_EVENT_NOTIFY_DONE), (long)p->result);
	KUNIT_EXPECT_EQ(test, f->imported, sizeof(struct scst_event_notify_done));
	KUNIT_EXPECT_EQ(test, f->notifications, (unsigned int)!p->result);
	if (!p->result) {
		KUNIT_EXPECT_EQ(test, f->notify_status, p->status);
		KUNIT_EXPECT_EQ(test, f->notify_id, 42U);
	}
	if (p->repeat) {
		KUNIT_EXPECT_EQ(test, event_test_ioctl(f, SCST_EVENT_NOTIFY_DONE), (long)-ENOENT);
		KUNIT_EXPECT_EQ(test, f->notifications, 1U);
	}
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, p->queued ? 2 : 0);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.queued_events_list),
			p->queued ? 2U : 0U);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.processing_events_list), processing);
	if (processing) {
		const struct scst_event_entry *e;

		KUNIT_ASSERT_FALSE(test, list_empty(&f->priv.processing_events_list));
		e = list_first_entry(&f->priv.processing_events_list, struct scst_event_entry,
				     events_list_entry);
		KUNIT_EXPECT_EQ(test, e->event.event_id, p->result ? 42U : 43U);
	}
}

struct event_timeout_case {
	const char *name;
	bool delivered;
	bool copy_fault;
	bool detached;
	bool second;
};

static const struct event_timeout_case event_timeout_cases[] = {
	{ .name = "expire_queued_event", .second = true },
	{ .name = "expire_only_queued_event" },
	{ .name = "copy_fault_timeout_preserves_queued_count", .copy_fault = true, .second = true },
	{ .name = "expire_delivered_event", .delivered = true },
	{ .name = "delivered_timeout_preserves_queued_count", .delivered = true, .second = true },
	{ .name = "already_detached_event", .detached = true },
};

static void event_timeout_desc(const struct event_timeout_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(event_timeout, event_timeout_cases, event_timeout_desc);

static void event_timeout_test(struct kunit *test)
{
	const struct event_timeout_case *p = test->param_value;
	struct event_test_fixture *f = test->priv;
	struct scst_event_entry *e = event_test_queue(f, 3, 42, true);

	KUNIT_ASSERT_NOT_NULL(test, e);
	if (p->second)
		KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 0, 43, false));
	if (p->copy_fault) {
		f->to_left = 1;
		KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT),
				(long)-EFAULT);
		f->to_left = 0;
	}
	if (p->delivered)
		KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
	if (p->detached) {
		list_del_init(&e->events_list_entry);
		f->priv.queued_events_cnt--;
		f->detached = e;
	}
	/* Deterministic expiry: the delayed work was initialized but never queued. */
	scst_event_timeout_fn(&e->event_timeout_work.work);
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, (int)p->second);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.queued_events_list),
			(unsigned int)p->second);
	KUNIT_EXPECT_TRUE(test, list_empty(&f->priv.processing_events_list));
	KUNIT_EXPECT_EQ(test, f->notifications, (unsigned int)!p->detached);
	if (!p->detached) {
		KUNIT_EXPECT_EQ(test, f->notify_status, -ETIMEDOUT);
		KUNIT_EXPECT_EQ(test, f->notify_id, 42U);
	}
	event_test_ack_input(f, 42, 0);
	KUNIT_EXPECT_EQ(test, event_test_ioctl(f, SCST_EVENT_NOTIFY_DONE), (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, f->notifications, (unsigned int)!p->detached);
	if (p->second) {
		KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
		KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, 0);
		KUNIT_EXPECT_TRUE(test, list_empty(&f->priv.queued_events_list));
	}
}

static void event_timeout_preserves_processing_test(struct kunit *test)
{
	struct event_test_fixture *f = test->priv;
	struct scst_event_entry *e = event_test_queue(f, 0, 42, true);

	KUNIT_ASSERT_NOT_NULL(test, e);
	KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 0, 43, true));
	KUNIT_ASSERT_NOT_NULL(test, event_test_queue(f, 0, 44, false));
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);

	/* Expiring one delivered event must not affect either remaining list. */
	scst_event_timeout_fn(&e->event_timeout_work.work);
	KUNIT_EXPECT_EQ(test, f->notifications, 1U);
	KUNIT_EXPECT_EQ(test, f->notify_status, -ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, f->notify_id, 42U);
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, 1);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.queued_events_list), 1U);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.processing_events_list), 1U);

	event_test_ack_input(f, 43, 0);
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_NOTIFY_DONE), 0L);
	KUNIT_EXPECT_EQ(test, f->notifications, 2U);
	KUNIT_EXPECT_EQ(test, f->notify_status, 0);
	KUNIT_EXPECT_EQ(test, f->notify_id, 43U);
	KUNIT_EXPECT_TRUE(test, list_empty(&f->priv.processing_events_list));
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, 1);
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_GET_NEXT_EVENT), 0L);
	KUNIT_EXPECT_EQ(test, f->priv.queued_events_cnt, 0);
	KUNIT_EXPECT_TRUE(test, list_empty(&f->priv.queued_events_list));
}

static struct kunit_case scst_event_delivery_cases[] = {
	KUNIT_CASE_PARAM(event_delivery_test, event_delivery_gen_params),
	KUNIT_CASE(event_delivery_retry_test),
	KUNIT_CASE_PARAM(event_ack_test, event_ack_gen_params),
	KUNIT_CASE_PARAM(event_timeout_test, event_timeout_gen_params),
	KUNIT_CASE(event_timeout_preserves_processing_test),
	{}
};

scst_kunit_suite(scst_event_delivery_suite, "EVENT", "-delivery",
		 .init = event_test_init,
		 .exit = event_test_exit,
		 .test_cases = scst_event_delivery_cases,
);
