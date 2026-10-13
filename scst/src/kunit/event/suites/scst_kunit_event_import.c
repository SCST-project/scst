// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_event_fixture.h"

struct event_import_case {
	const char *name;
	int length;
	int copied_delta;
	size_t uncopied;
	int result;
	bool read_fault;
	bool alloc_fault;
	bool unterminated;
};

static const struct event_import_case event_import_cases[] = {
	{ .name = "wildcard_empty_payload" },
	{ .name = "one_byte", .length = 1 },
	{ .name = "binary_payload", .length = 256 },
	{ .name = "below_payload_limit", .length = SCST_MAX_PAYLOAD - 1 },
	{ .name = "at_payload_limit", .length = SCST_MAX_PAYLOAD },
	{ .name = "above_payload_limit", .length = SCST_MAX_PAYLOAD + 1, .result = -EINVAL },
	{ .name = "int_max_length", .length = INT_MAX, .result = -EINVAL },
	{ .name = "int_min_length", .length = INT_MIN, .result = -EINVAL },
	{ .name = "negative_length", .length = -1, .result = -EINVAL },
	{ .name = "size_read_fault", .read_fault = true, .result = -EFAULT },
	{ .name = "allocation_failure", .alloc_fault = true, .result = -ENOMEM },
	{ .name = "header_copy_fault", .uncopied = SIZE_MAX, .result = -EFAULT },
	{ .name = "last_header_byte_fault", .uncopied = 1, .result = -EFAULT },
	{ .name = "partial_payload_fault", .length = 256, .uncopied = 128, .result = -EFAULT },
	{ .name = "last_payload_byte_fault", .length = SCST_MAX_PAYLOAD,
	  .uncopied = 1, .result = -EFAULT },
	{ .name = "length_grew_during_copy", .copied_delta = 1, .result = -EINVAL },
	{ .name = "length_shrank_during_copy", .length = 1, .copied_delta = -1,
	  .result = -EINVAL },
	{ .name = "length_became_negative", .copied_delta = -1, .result = -EINVAL },
	{ .name = "length_crossed_limit_during_copy", .length = SCST_MAX_PAYLOAD,
	  .copied_delta = 1, .result = -EINVAL },
	{ .name = "unterminated_issuer", .length = 1, .unterminated = true },
};

static void event_import_desc(const struct event_import_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(event_import, event_import_cases, event_import_desc);

static void event_import_test(struct kunit *test)
{
	const struct event_import_case *p = test->param_value;
	struct event_test_fixture *f = test->priv;
	bool valid_length = p->length >= 0 && p->length <= SCST_MAX_PAYLOAD;
	unsigned int allocations = !p->read_fault && valid_length;
	unsigned int imports = allocations && !p->alloc_fault;
	struct scst_event *input = event_test_input(f, valid_length ? p->length : 0, 0, "*");
	struct scst_event_entry *e;

	f->user_size = p->length;
	input->payload_len = valid_length ? p->length + p->copied_delta : p->length;
	if (p->unterminated)
		memset(input->issuer_name, 'x', sizeof(input->issuer_name));
	f->read_error = p->read_fault ? -EFAULT : 0;
	f->fail_alloc = p->alloc_fault;
	f->from_left = p->uncopied;

	KUNIT_EXPECT_EQ(test, event_test_ioctl(f, SCST_EVENT_ALLOW_EVENT), (long)p->result);
	KUNIT_EXPECT_EQ(test, f->reads, 1U);
	KUNIT_EXPECT_EQ(test, f->allocations, allocations);
	KUNIT_EXPECT_EQ(test, f->imports, imports);
	if (allocations)
		KUNIT_EXPECT_EQ(test, f->allocation_size, sizeof(*e) + p->length);
	if (imports)
		KUNIT_EXPECT_EQ(test, f->imported, sizeof(*input) + p->length);
	KUNIT_EXPECT_EQ(test, f->priv.allowed_events_cnt, !p->result);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.allowed_events_list),
			(unsigned int)!p->result);
	if (p->result)
		return;
	KUNIT_ASSERT_FALSE(test, list_empty(&f->priv.allowed_events_list));
	e = list_first_entry(&f->priv.allowed_events_list, struct scst_event_entry,
			     events_list_entry);
	input->issuer_name[sizeof(input->issuer_name) - 1] = '\0';
	KUNIT_EXPECT_EQ(test, memcmp(&e->event, input, f->input_size), 0);
	KUNIT_EXPECT_NULL(test, e->event_notify_fn);
	KUNIT_EXPECT_NULL(test, e->notify_fn_priv);
	KUNIT_EXPECT_NULL(test, e->pqueued_events_cnt);
}

struct event_subscription_case {
	const char *name;
	unsigned int command;
	u32 code;
	const char *issuer;
	unsigned int length;
	unsigned int remaining;
	int result;
	bool different_payload;
	bool copy_fault;
};

static const struct event_subscription_case event_subscription_cases[] = {
	{ "duplicate_ignores_event_id", SCST_EVENT_ALLOW_EVENT, 1, "alpha", 3, 7, -EEXIST },
	{ "different_code", SCST_EVENT_ALLOW_EVENT, 3, "alpha", 3, 15 },
	{ "different_payload_length", SCST_EVENT_ALLOW_EVENT, 1, "alpha", 1, 15 },
	{ "different_binary_payload", SCST_EVENT_ALLOW_EVENT, 1, "alpha", 3, 15,
	  .different_payload = true },
	{ "wildcard_duplicate", SCST_EVENT_ALLOW_EVENT, 0, "*", 0, 7, -EEXIST },
	{ "remove_exact", SCST_EVENT_DISALLOW_EVENT, 1, "alpha", 3, 6 },
	{ "wildcard_code", SCST_EVENT_DISALLOW_EVENT, 0, "beta", 3, 1 },
	{ "wildcard_issuer", SCST_EVENT_DISALLOW_EVENT, 1, "*", 3, 2 },
	{ "wildcard_payload", SCST_EVENT_DISALLOW_EVENT, 1, "alpha", 0, 6 },
	{ "remove_all", SCST_EVENT_DISALLOW_EVENT, 0, "*", 0, 0 },
	{ "missing_code", SCST_EVENT_DISALLOW_EVENT, 3, "*", 0, 7, -ENOENT },
	{ "different_length_does_not_match", SCST_EVENT_DISALLOW_EVENT, 1, "alpha", 1,
	  7, -ENOENT },
	{ "different_bytes_do_not_match", SCST_EVENT_DISALLOW_EVENT, 1, "alpha", 3,
	  7, -ENOENT, .different_payload = true },
	{ "failed_disallow_preserves_subscriptions", SCST_EVENT_DISALLOW_EVENT, 0, "*", 0,
	  7, -EFAULT, .copy_fault = true },
};

static void event_subscription_desc(const struct event_subscription_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(event_subscription, event_subscription_cases, event_subscription_desc);

static void event_subscription_test(struct kunit *test)
{
	const struct event_subscription_case *p = test->param_value;
	struct event_test_fixture *f = test->priv;
	struct scst_event_entry *e;
	struct scst_event *input;
	unsigned int i, remaining = 0;

	for (i = 0; i < 3; i++) {
		input = event_test_input(f, 3, i == 1 ? 2 : 1, i ? "beta" : "alpha");
		input->event_id = i;
		KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_ALLOW_EVENT), 0L);
	}
	input = event_test_input(f, p->length, p->code, p->issuer);
	input->event_id = 3;
	if (p->different_payload)
		input->payload[2] ^= 0xff;
	f->from_left = p->copy_fault ? 1 : 0;
	KUNIT_EXPECT_EQ(test, event_test_ioctl(f, p->command), (long)p->result);
	KUNIT_EXPECT_EQ(test, f->priv.allowed_events_cnt, (int)hweight32(p->remaining));
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.allowed_events_list),
			hweight32(p->remaining));
	list_for_each_entry(e, &f->priv.allowed_events_list, events_list_entry) {
		KUNIT_ASSERT_LT(test, e->event.event_id, 4U);
		remaining |= BIT(e->event.event_id);
	}
	KUNIT_EXPECT_EQ(test, remaining, p->remaining);
}

static void event_subscription_limit_test(struct kunit *test)
{
	struct event_test_fixture *f = test->priv;
	unsigned int i;

	for (i = 1; i <= SCST_MAX_EVENTS; i++) {
		event_test_input(f, 0, i, "limit");
		KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_ALLOW_EVENT), 0L);
	}
	event_test_input(f, 0, SCST_MAX_EVENTS + 1, "limit");
	KUNIT_EXPECT_EQ(test, event_test_ioctl(f, SCST_EVENT_ALLOW_EVENT), (long)-EMFILE);
	KUNIT_EXPECT_EQ(test, f->priv.allowed_events_cnt, SCST_MAX_EVENTS);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.allowed_events_list),
			(unsigned int)SCST_MAX_EVENTS);
	event_test_input(f, 0, 1, "limit");
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_DISALLOW_EVENT), 0L);
	KUNIT_EXPECT_EQ(test, f->priv.allowed_events_cnt, SCST_MAX_EVENTS - 1);
	event_test_input(f, 0, SCST_MAX_EVENTS + 1, "limit");
	KUNIT_ASSERT_EQ(test, event_test_ioctl(f, SCST_EVENT_ALLOW_EVENT), 0L);
	KUNIT_EXPECT_EQ(test, f->priv.allowed_events_cnt, SCST_MAX_EVENTS);
	KUNIT_EXPECT_EQ(test, event_test_list_count(&f->priv.allowed_events_list),
			(unsigned int)SCST_MAX_EVENTS);
}

static const unsigned int event_clone_lengths[] = { 0, 1, 256, SCST_MAX_PAYLOAD };

static void event_clone_desc(const unsigned int *length, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "payload_%u", *length);
}

KUNIT_ARRAY_PARAM(event_clone, event_clone_lengths, event_clone_desc);

static void event_clone_test(struct kunit *test)
{
	struct event_test_fixture *f = test->priv;
	unsigned int length = *(const unsigned int *)test->param_value;
	struct scst_event_entry *original = event_test_queue(f, length, 42, false);
	struct scst_event_entry *clone;

	KUNIT_ASSERT_NOT_NULL(test, original);
	KUNIT_ASSERT_EQ(test, scst_clone_event(original, &f->detached), 0);
	clone = f->detached;
	KUNIT_ASSERT_NOT_NULL(test, clone);
	KUNIT_EXPECT_PTR_NE(test, clone, original);
	KUNIT_EXPECT_EQ(test, memcmp(&clone->event, &original->event,
				     sizeof(clone->event) + length), 0);
	KUNIT_EXPECT_NULL(test, clone->pqueued_events_cnt);
	KUNIT_EXPECT_NULL(test, clone->event_notify_fn);
	KUNIT_EXPECT_NULL(test, clone->notify_fn_priv);
	clone->event.event_id = 99;
	if (length) {
		clone->event.payload[length - 1] ^= 0xff;
		KUNIT_EXPECT_EQ(test, original->event.payload[length - 1], (u8)(length - 1));
	}
	KUNIT_EXPECT_EQ(test, original->event.event_id, 42U);
}

static struct kunit_case scst_event_import_cases[] = {
	KUNIT_CASE_PARAM(event_import_test, event_import_gen_params),
	KUNIT_CASE_PARAM(event_subscription_test, event_subscription_gen_params),
	KUNIT_CASE(event_subscription_limit_test),
	KUNIT_CASE_PARAM(event_clone_test, event_clone_gen_params),
	{}
};

scst_kunit_suite(scst_event_import_suite, "EVENT", "-import",
		 .init = event_test_init,
		 .exit = event_test_exit,
		 .test_cases = scst_event_import_cases,
);
