// SPDX-License-Identifier: GPL-2.0-only
#include "scst_event_fixture.h"

void __user * const event_test_arg = (void __user *)0x1000UL;

static int event_test_get_size(s32 *size, const void __user *arg)
{
	struct kunit *test = kunit_get_current_test();
	struct event_test_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, (__force const void *)arg,
			    (__force const void *)event_test_arg);
	f->reads++;
	if (!f->read_error)
		*size = f->user_size;
	return f->read_error;
}

/*
 * The registered callback retains the mutable parameter type required by its
 * interface.
 */
/* cppcheck-suppress constParameterCallback symbolName=arg */
static int event_test_get_payload_size(u32 *size, struct scst_event_user __user *arg)
{
	s32 value;
	int res = event_test_get_size(&value, arg);

	if (!res)
		*size = value;
	return res;
}

static int event_test_put_size(s32 size, void __user *arg)
{
	struct kunit *test = kunit_get_current_test();
	struct event_test_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, (__force const void *)arg,
			    (__force const void *)event_test_arg);
	f->puts++;
	f->needed_size = size;
	return f->put_error;
}

static struct scst_event_entry *event_test_alloc(size_t size)
{
	struct event_test_fixture *f = kunit_get_current_test()->priv;

	f->allocations++;
	f->allocation_size = size;
	f->allocation = f->fail_alloc ? NULL : kzalloc(size, GFP_KERNEL);
	return f->allocation;
}

static unsigned long event_test_copy_from(void *to, const void __user *from, size_t size)
{
	struct kunit *test = kunit_get_current_test();
	struct event_test_fixture *f = test->priv;
	size_t left = min(f->from_left, size);

	KUNIT_EXPECT_PTR_EQ(test, (__force const void *)from,
			    (__force const void *)event_test_arg);
	f->imports++;
	f->imported = size;
	/* Reject the historical entry-size copy before it can overrun the fixture. */
	if (size != f->input_size || size > sizeof(f->input)) {
		KUNIT_FAIL(test, "incorrect usercopy size: %zu, expected %zu", size, f->input_size);
		return size;
	}
	if (f->importing &&
	    (!f->allocation || to != &f->allocation->event ||
	     size + offsetof(struct scst_event_entry, event) > f->allocation_size)) {
		KUNIT_FAIL(test, "import does not fit the allocated event member");
		return size;
	}
	memcpy(to, f->input, size - left);
	/* copy_from_user() zeroes the uncopied tail. */
	memset((u8 *)to + size - left, 0, left);
	return left;
}

static unsigned long event_test_copy_to(void __user *to, const void *from, size_t size)
{
	struct kunit *test = kunit_get_current_test();
	struct event_test_fixture *f = test->priv;
	size_t offset = offsetof(struct scst_event_user, out_event);
	size_t left = min(f->to_left, size);

	KUNIT_EXPECT_EQ(test, (unsigned long)to, (unsigned long)event_test_arg + offset);
	f->exports++;
	f->exported = size;
	if (size > sizeof(struct scst_event) + SCST_MAX_PAYLOAD) {
		KUNIT_FAIL(test, "oversized event export: %zu", size);
		return size;
	}
	memcpy(f->output + offset, from, size - left);
	return left;
}

/*
 * The registered callback retains the mutable parameter type required by its
 * interface.
 */
/* cppcheck-suppress constParameterCallback symbolName=event */
static void event_test_notify(struct scst_event *event, void *data, int status)
{
	struct event_test_fixture *f = data;

	lockdep_assert_not_held(&scst_event_mutex);
	f->notifications++;
	f->notify_status = status;
	f->notify_id = event->event_id;
}

static void event_test_fill(struct scst_event *event, unsigned int length, u32 code,
			    const char *issuer, u32 id)
{
	unsigned int i;

	event->payload_len = length;
	event->event_code = code;
	event->event_id = id;
	strscpy(event->issuer_name, issuer, sizeof(event->issuer_name));
	for (i = 0; i < length; i++)
		event->payload[i] = i;
}

struct scst_event *event_test_input(struct event_test_fixture *f, unsigned int length,
				    u32 code, const char *issuer)
{
	struct scst_event *event = (void *)f->input;

	memset(f->input, 0, sizeof(f->input));
	event_test_fill(event, length, code, issuer, 77);
	f->user_size = length;
	f->input_size = sizeof(*event) + length;
	f->importing = true;
	return event;
}

long event_test_ioctl(struct event_test_fixture *f, unsigned int command)
{
	return scst_event_ioctl(&f->file, command, (unsigned long)event_test_arg);
}

struct scst_event_entry *event_test_queue(struct event_test_fixture *f,
					  unsigned int length, u32 id, bool notify)
{
	struct scst_event_entry *e = kzalloc(sizeof(*e) + length, GFP_KERNEL);

	if (!e)
		return NULL;
	event_test_fill(&e->event, length, 1, "kunit", id);
	INIT_DELAYED_WORK(&e->event_timeout_work, scst_event_timeout_fn);
	if (notify) {
		e->event_notify_fn = event_test_notify;
		e->notify_fn_priv = f;
	}
	e->pqueued_events_cnt = &f->priv.queued_events_cnt;
	list_add_tail(&e->events_list_entry, &f->priv.queued_events_list);
	f->priv.queued_events_cnt++;
	return e;
}

void event_test_ack_input(struct event_test_fixture *f, u32 id, int status)
{
	struct scst_event_notify_done n = { .event_id = id, .status = status };

	memcpy(f->input, &n, sizeof(n));
	f->input_size = sizeof(n);
	f->importing = false;
}

unsigned int event_test_list_count(const struct list_head *head)
{
	const struct list_head *pos;
	unsigned int count = 0;

	list_for_each(pos, head)
		count++;
	return count;
}

int event_test_init(struct kunit *test)
{
	struct event_test_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	test->priv = f;
	if (!f)
		return -ENOMEM;
	INIT_LIST_HEAD(&f->priv.privs_list_entry);
	INIT_LIST_HEAD(&f->priv.allowed_events_list);
	INIT_LIST_HEAD(&f->priv.queued_events_list);
	INIT_LIST_HEAD(&f->priv.processing_events_list);
	init_waitqueue_head(&f->priv.queued_events_waitq);
	f->file.private_data = &f->priv;
	f->user_size = INT_MAX;
	memset(f->output, 0xa5, sizeof(f->output));
	kunit_activate_static_stub(test, scst_event_get_user_payload_size,
				   event_test_get_payload_size);
	kunit_activate_static_stub(test, scst_event_get_user_size, event_test_get_size);
	kunit_activate_static_stub(test, scst_event_put_user_size, event_test_put_size);
	kunit_activate_static_stub(test, scst_event_alloc_user_entry, event_test_alloc);
	kunit_activate_static_stub(test, scst_event_copy_from_user, event_test_copy_from);
	kunit_activate_static_stub(test, scst_event_copy_to_user, event_test_copy_to);
	return 0;
}

static void event_test_free_list(struct list_head *head, bool work_initialized)
{
	struct scst_event_entry *e, *next;

	list_for_each_entry_safe(e, next, head, events_list_entry) {
		list_del(&e->events_list_entry);
		if (work_initialized)
			cancel_delayed_work_sync(&e->event_timeout_work);
		kfree(e);
	}
}

void event_test_exit(struct kunit *test)
{
	struct event_test_fixture *f = test->priv;

	if (!f)
		return;
	/* No entry or client is registered globally, and no work is scheduled. */
	event_test_free_list(&f->priv.allowed_events_list, false);
	event_test_free_list(&f->priv.queued_events_list, true);
	event_test_free_list(&f->priv.processing_events_list, true);
	kfree(f->detached);
	test->priv = NULL;
}
