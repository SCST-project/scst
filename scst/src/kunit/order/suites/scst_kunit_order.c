// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_targ_test.h"
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/limits.h>

#define ORDER_TEST_COMMANDS 128

struct order_test_worker {
	bool started;
	bool finished;
	struct completion done;
	struct order_test_fixture *fixture;
	unsigned int first;
};

struct order_test_fixture {
	struct scst_device dev;
	struct scst_order_data order;
	struct scst_cmd commands[ORDER_TEST_COMMANDS];
	struct completion start;
	atomic_t stop;
	struct order_test_worker workers[2];
};

static int order_test_init(struct kunit *test)
{
	struct order_test_fixture *f;
	unsigned int i;

	test->priv = NULL;
	/* Workers may outlive a failed test; KUnit must not reclaim their state. */
	f = kzalloc_obj(*f);
	if (!f)
		return -ENOMEM;
	if (!try_module_get(THIS_MODULE)) {
		kfree(f);
		return -ENODEV;
	}
	test->priv = f;
	atomic_set(&f->stop, 0);
	spin_lock_init(&f->order.sn_lock);
	spin_lock_init(&f->order.init_done_lock);
	INIT_LIST_HEAD(&f->order.skipped_sn_list);
	INIT_LIST_HEAD(&f->order.deferred_cmd_list);
	f->order.curr_sn = 100;
	f->order.expected_sn = 100;
	f->order.cur_sn_slot = f->order.sn_slots;
	f->dev.queue_alg = SCST_QUEUE_ALG_1_UNRESTRICTED_REORDER;
	f->dev.virt_name = "kunit-order";
	init_completion(&f->start);
	for (i = 0; i < ARRAY_SIZE(f->commands); i++) {
		f->commands[i].dev = &f->dev;
		f->commands[i].cur_order_data = &f->order;
		f->commands[i].queue_type = SCST_CMD_QUEUE_ORDERED;
		f->commands[i].op_name = "kunit";
	}
	for (i = 0; i < ARRAY_SIZE(f->workers); i++) {
		init_completion(&f->workers[i].done);
		f->workers[i].fixture = f;
		f->workers[i].first = i * ORDER_TEST_COMMANDS / 2;
	}
	return 0;
}

static void order_test_exit(struct kunit *test)
{
	struct order_test_fixture *f = test->priv;
	unsigned int i;

	test->priv = NULL;
	if (!f)
		return;
	atomic_set(&f->stop, 1);
	complete_all(&f->start);
	for (i = 0; i < ARRAY_SIZE(f->workers); i++) {
		struct order_test_worker *w = &f->workers[i];

		if (!w->started || w->finished)
			continue;
		if (!wait_for_completion_timeout(&w->done, 5 * HZ)) {
			/* Preserve both the data and module text until the VM is restarted. */
			scst_kunit_retain(test, "ORDER worker did not finish");
			return;
		}
	}
	kfree(f);
	module_put(THIS_MODULE);
}

static bool order_test_normal_policy(struct kunit *test)
{
	if (IS_ENABLED(CONFIG_SCST_DEBUG_SN)) {
		kunit_skip(test, "SCST_DEBUG_SN deliberately randomizes queue types");
		return false;
	}
	return true;
}

struct order_sequence_case {
	const char *name;
	const char *types;
	int sn[4]; /* Offsets from 100; -1 means no sequence number. */
};

static const struct order_sequence_case order_sequence_cases[] = {
	{ "simple", "S", { 0 } },
	{ "simple_batch", "SSSS", { 0, 0, 0, 0 } },
	{ "untagged", "U", { 0 } },
	{ "untagged_and_simple", "US", { 0, 0 } },
	{ "ordered_idle", "O", { 1 } },
	{ "ordered_batch", "OOOO", { 1, 2, 3, 4 } },
	{ "simple_then_ordered", "SO", { 0, 1 } },
	{ "ordered_then_simple", "OS", { 1, 2 } },
	{ "simple_ordered_simple", "SOS", { 0, 1, 2 } },
	{ "two_ordered_barriers", "SOOS", { 0, 1, 2, 3 } },
	{ "head_of_queue", "H", { -1 } },
	{ "head_does_not_split_simple", "SHS", { 0, -1, 0 } },
	{ "head_between_ordered", "OHO", { 1, -1, 2 } },
	{ "aca", "A", { -1 } },
	{ "aca_does_not_split_simple", "SAS", { 0, -1, 0 } },
};

static void order_sequence_desc(const struct order_sequence_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(order_sequence, order_sequence_cases, order_sequence_desc);

static void order_sequence_test(struct kunit *test)
{
	const struct order_sequence_case *p = test->param_value;
	struct order_test_fixture *f = test->priv;
	unsigned int i, ordered = 0, heads = 0;

	if (!order_test_normal_policy(test))
		return;
	for (i = 0; p->types[i]; i++) {
		struct scst_cmd *cmd = &f->commands[i];
		int expected = p->sn[i];

		switch (p->types[i]) {
		case 'S':
			cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
			break;
		case 'U':
			cmd->queue_type = SCST_CMD_QUEUE_UNTAGGED;
			break;
		case 'O':
			cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
			break;
		case 'H':
			cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
			break;
		case 'A':
			cmd->queue_type = SCST_CMD_QUEUE_ACA;
			break;
		}
		if (IS_ENABLED(CONFIG_SCST_STRICT_SERIALIZING) && p->types[i] != 'H')
			expected = ++ordered;
		scst_cmd_set_sn(cmd);
		KUNIT_EXPECT_EQ(test, !!cmd->sn_set, expected >= 0);
		if (expected >= 0)
			KUNIT_EXPECT_EQ(test, cmd->sn, 100U + expected);
		if (p->types[i] == 'H')
			heads++;
		KUNIT_EXPECT_EQ(test, !!cmd->hq_cmd_inced, p->types[i] == 'H');
		KUNIT_EXPECT_EQ(test, f->order.hq_cmd_count, (int)heads);
	}
	KUNIT_EXPECT_TRUE(test, list_empty(&f->order.deferred_cmd_list));
	KUNIT_EXPECT_TRUE(test, list_empty(&f->order.skipped_sn_list));
}

struct order_policy_case {
	const char *name;
	int queue;
	bool restricted;
	bool implicit;
	int expected;
};

static const struct order_policy_case order_policy_cases[] = {
	{ "restricted_simple", SCST_CMD_QUEUE_SIMPLE, true, false, SCST_CMD_QUEUE_ORDERED },
	{ "restricted_untagged", SCST_CMD_QUEUE_UNTAGGED, true, false, SCST_CMD_QUEUE_ORDERED },
	{ "restricted_head", SCST_CMD_QUEUE_HEAD_OF_QUEUE, true, false,
	  SCST_CMD_QUEUE_HEAD_OF_QUEUE },
	{ "implicit_head", SCST_CMD_QUEUE_SIMPLE, false, true, SCST_CMD_QUEUE_HEAD_OF_QUEUE },
	{ "implicit_head_beats_restricted", SCST_CMD_QUEUE_SIMPLE, true, true,
	  SCST_CMD_QUEUE_HEAD_OF_QUEUE },
	{ "implicit_flag_does_not_override_ordered", SCST_CMD_QUEUE_ORDERED, false, true,
	  SCST_CMD_QUEUE_ORDERED },
};

static void order_policy_desc(const struct order_policy_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(order_policy, order_policy_cases, order_policy_desc);

static void order_policy_test(struct kunit *test)
{
	const struct order_policy_case *p = test->param_value;
	struct order_test_fixture *f = test->priv;
	struct scst_cmd *cmd = f->commands;

	if (!order_test_normal_policy(test))
		return;
	cmd->queue_type = p->queue;
	cmd->op_flags = p->implicit ? SCST_IMPLICIT_HQ : 0;
	if (p->restricted)
		f->dev.queue_alg = SCST_QUEUE_ALG_0_RESTRICTED_REORDER;
	scst_cmd_set_sn(cmd);
	KUNIT_EXPECT_EQ(test, cmd->queue_type, p->expected);
	KUNIT_EXPECT_EQ(test, !!cmd->sn_set, p->expected == SCST_CMD_QUEUE_ORDERED);
	KUNIT_EXPECT_EQ(test, f->order.hq_cmd_count,
			p->expected == SCST_CMD_QUEUE_HEAD_OF_QUEUE ? 1 : 0);
}

static void order_completion_test(struct kunit *test)
{
	struct order_test_fixture *f = test->priv;
	unsigned int i;

	if (!order_test_normal_policy(test))
		return;
	if (IS_ENABLED(CONFIG_SCST_STRICT_SERIALIZING)) {
		kunit_skip(test, "SIMPLE batching is disabled by strict serialization");
		return;
	}
	f->commands[0].queue_type = SCST_CMD_QUEUE_SIMPLE;
	f->commands[1].queue_type = SCST_CMD_QUEUE_SIMPLE;
	for (i = 0; i < 3; i++)
		scst_cmd_set_sn(&f->commands[i]);
	KUNIT_EXPECT_EQ(test, f->order.pending_simple_inc_expected_sn, 1);
	KUNIT_EXPECT_EQ(test, f->order.expected_sn, 100U);
	KUNIT_EXPECT_FALSE(test, scst_inc_expected_sn(&f->commands[1]));
	KUNIT_EXPECT_EQ(test, f->order.expected_sn, 100U);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->order.sn_slots[0]), 1);
	KUNIT_EXPECT_TRUE(test, scst_inc_expected_sn(&f->commands[0]));
	KUNIT_EXPECT_EQ(test, f->order.expected_sn, 101U);
	KUNIT_EXPECT_EQ(test, f->order.pending_simple_inc_expected_sn, 0);
	KUNIT_EXPECT_TRUE(test, scst_inc_expected_sn(&f->commands[2]));
	KUNIT_EXPECT_EQ(test, f->order.expected_sn, 102U);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->order.sn_slots[0]), 0);
}

static const bool order_slot_busy[] = { false, true };

static void order_slot_desc(const bool *busy, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", *busy ? "exhausted_ring" : "wrap_to_free_slot");
}

KUNIT_ARRAY_PARAM(order_slot, order_slot_busy, order_slot_desc);

static void order_slot_test(struct kunit *test)
{
	struct order_test_fixture *f = test->priv;
	bool busy = *(const bool *)test->param_value;
	struct scst_cmd *cmd = f->commands;

	if (!order_test_normal_policy(test))
		return;
	if (IS_ENABLED(CONFIG_SCST_STRICT_SERIALIZING)) {
		kunit_skip(test, "SIMPLE slots are disabled by strict serialization");
		return;
	}
	f->order.cur_sn_slot = &f->order.sn_slots[ARRAY_SIZE(f->order.sn_slots) - 1];
	atomic_set(f->order.cur_sn_slot, 1);
	if (busy) {
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(f->order.sn_slots); i++)
			atomic_set(&f->order.sn_slots[i], 1);
	}
	f->order.prev_cmd_ordered = true;
	cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
	scst_cmd_set_sn(cmd);
	KUNIT_EXPECT_EQ(test, cmd->sn, 101U);
	KUNIT_EXPECT_EQ(test, f->order.expected_sn, 100U);
	KUNIT_EXPECT_PTR_EQ(test, cmd->sn_slot, busy ? NULL : &f->order.sn_slots[0]);
	KUNIT_EXPECT_TRUE(test, !!cmd->sn_set);
	KUNIT_EXPECT_EQ(test, f->order.prev_cmd_ordered, busy);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->order.sn_slots[0]), 1);
}

static int order_test_thread(void *data)
{
	struct order_test_worker *w = data;
	unsigned int i;

	wait_for_completion(&w->fixture->start);
	for (i = w->first; i < w->first + ORDER_TEST_COMMANDS / 2; i++) {
		if (atomic_read(&w->fixture->stop))
			break;
		scst_cmd_set_sn(&w->fixture->commands[i]);
		cond_resched();
	}
	/* Completion must not precede a return through unloadable module text. */
	kthread_complete_and_exit(&w->done, 0);
}

struct order_parallel_case {
	const char *name;
	unsigned int base;
	bool mixed;
};

static const struct order_parallel_case order_parallel_cases[] = {
	{ "ordered", 100 },
	{ "ordered-wrap", UINT_MAX - 63 },
	{ "simple-versus-ordered", 100, true },
	{ "simple-versus-ordered-wrap", UINT_MAX - 63, true },
};

static void order_parallel_desc(const struct order_parallel_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(order_parallel, order_parallel_cases, order_parallel_desc);

static void order_parallel_test(struct kunit *test)
{
	const struct order_parallel_case *p = test->param_value;
	struct order_test_fixture *f = test->priv;
	unsigned int counts[ORDER_TEST_COMMANDS + 1] = {};
	atomic_t *slots[ORDER_TEST_COMMANDS + 1] = {};
	unsigned int i, first, last, simple_groups = 0;

	if (!order_test_normal_policy(test))
		return;
	f->order.curr_sn = p->base;
	f->order.expected_sn = p->base;
	if (p->mixed)
		for (i = 0; i < ORDER_TEST_COMMANDS / 2; i++)
			f->commands[i].queue_type = SCST_CMD_QUEUE_SIMPLE;
	for (i = 0; i < ARRAY_SIZE(f->workers); i++) {
		struct task_struct *task = kthread_create(order_test_thread, &f->workers[i],
							"scst-kunit-order");

		KUNIT_ASSERT_FALSE(test, IS_ERR(task));
		f->workers[i].started = true;
		wake_up_process(task);
	}
	complete_all(&f->start);
	for (i = 0; i < ARRAY_SIZE(f->workers); i++) {
		unsigned long done = wait_for_completion_timeout(&f->workers[i].done, 5 * HZ);

		KUNIT_ASSERT_NE(test, done, 0UL);
		f->workers[i].finished = true;
	}
	for (i = 0; i < ARRAY_SIZE(f->commands); i++) {
		struct scst_cmd *cmd = &f->commands[i];
		unsigned int index = cmd->sn - p->base;

		KUNIT_ASSERT_TRUE(test, !!cmd->sn_set);
		KUNIT_ASSERT_LE(test, index, (unsigned int)ORDER_TEST_COMMANDS);
		if (counts[index]) {
			/* A barrier may never share a sequence number with another command. */
			KUNIT_EXPECT_NOT_NULL(test, cmd->sn_slot);
			KUNIT_EXPECT_PTR_EQ(test, slots[index], cmd->sn_slot);
		} else {
			slots[index] = cmd->sn_slot;
		}
		counts[index]++;
		if (i % (ORDER_TEST_COMMANDS / 2))
			KUNIT_EXPECT_GE(test, index, f->commands[i - 1].sn - p->base);
	}
	first = counts[0] ? 0 : 1;
	last = f->order.curr_sn - p->base;
	KUNIT_ASSERT_LE(test, last, (unsigned int)ORDER_TEST_COMMANDS);
	KUNIT_EXPECT_EQ(test, f->order.expected_sn, p->base + first);
	for (i = first; i <= last; i++) {
		KUNIT_EXPECT_GT(test, counts[i], 0U);
		if (slots[i]) {
			KUNIT_EXPECT_EQ(test, atomic_read(slots[i]), (int)counts[i]);
			simple_groups++;
		} else {
			KUNIT_EXPECT_EQ(test, counts[i], 1U);
		}
	}
	KUNIT_EXPECT_EQ(test, f->order.pending_simple_inc_expected_sn,
			(int)(simple_groups - !!slots[last]));
	for (i = 0; i < ARRAY_SIZE(f->commands); i++)
		scst_inc_expected_sn(&f->commands[i]);
	KUNIT_EXPECT_EQ(test, f->order.expected_sn, p->base + last + !slots[last]);
	KUNIT_EXPECT_EQ(test, f->order.pending_simple_inc_expected_sn, 0);
	for (i = 0; i < ARRAY_SIZE(f->order.sn_slots); i++)
		KUNIT_EXPECT_EQ(test, atomic_read(&f->order.sn_slots[i]), 0);
}

static struct kunit_case order_cases[] = {
	KUNIT_CASE_PARAM(order_sequence_test, order_sequence_gen_params),
	KUNIT_CASE_PARAM(order_policy_test, order_policy_gen_params),
	KUNIT_CASE(order_completion_test),
	KUNIT_CASE_PARAM(order_slot_test, order_slot_gen_params),
	KUNIT_CASE_PARAM(order_parallel_test, order_parallel_gen_params),
	{}
};

scst_kunit_suite(order_suite, "ORDER", "",
		 .init = order_test_init,
		 .exit = order_test_exit,
		 .test_cases = order_cases,
);
