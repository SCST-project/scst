// SPDX-License-Identifier: GPL-2.0-only
/* Handler callbacks belong to devices, not only mapped LUNs. */
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"

struct alua_test_device {
	struct scst_device dev;
	struct scst_dg_dev member;
	struct scst_tgt_dev mappings[3];
	struct scst_session sessions[3];
	unsigned int starts;
	unsigned int finishes;
	unsigned int order;
	unsigned int start_order;
	unsigned int finish_order;
	enum scst_tg_state start_old;
	enum scst_tg_state start_new;
	enum scst_tg_state finish_old;
	enum scst_tg_state finish_new;
};

struct alua_fixture {
	struct scst_dev_group dg;
	struct scst_target_group tg;
	struct scst_tg_tgt member;
	struct scst_tgt local;
	struct scst_tgt foreign;
	struct scst_dev_type handler;
	struct alua_test_device devices[2];
};

static void alua_start(struct scst_device *dev, enum scst_tg_state old, enum scst_tg_state new)
{
	struct alua_test_device *d = container_of(dev, struct alua_test_device, dev);

	lockdep_assert_alua_lock_held();
	d->starts++;
	d->start_order = ++d->order;
	d->start_old = old;
	d->start_new = new;
}

static void alua_finish(struct scst_device *dev, enum scst_tg_state old, enum scst_tg_state new)
{
	struct alua_test_device *d = container_of(dev, struct alua_test_device, dev);

	lockdep_assert_alua_lock_held();
	d->finishes++;
	d->finish_order = ++d->order;
	d->finish_old = old;
	d->finish_new = new;
}

struct alua_case {
	const char *name;
	unsigned int devices;
	unsigned int mappings;
	bool foreign;
	bool remote;
	bool unchanged;
	bool activate;
	bool invalid;
	bool no_start;
	bool no_finish;
};

static const struct alua_case alua_cases[] = {
	{ .name = "unmapped_device", .devices = 1 },
	{ .name = "two_unmapped_devices", .devices = 2 },
	{ .name = "only_copy_manager_mapping", .devices = 1, .foreign = true },
	{ .name = "one_mapping", .devices = 1, .mappings = 1 },
	{ .name = "two_mappings_one_callback", .devices = 1, .mappings = 2 },
	{ .name = "two_devices_with_two_mappings", .devices = 2, .mappings = 2 },
	{ .name = "foreign_and_local_mappings", .devices = 1, .mappings = 2, .foreign = true },
	{ .name = "remote_unmapped_device", .devices = 1, .remote = true },
	{ .name = "remote_with_foreign_mapping", .devices = 1, .remote = true, .foreign = true },
	{ .name = "unchanged_state", .devices = 1, .mappings = 2, .unchanged = true },
	{ .name = "start_callback_only", .devices = 1, .mappings = 2, .no_finish = true },
	{ .name = "finish_callback_only", .devices = 1, .no_start = true },
	{ .name = "handler_without_callbacks", .devices = 1, .mappings = 1,
	  .no_start = true, .no_finish = true },
	{ .name = "reactivate_unmapped_device", .devices = 1, .activate = true },
	{ .name = "invalid_state", .devices = 1, .invalid = true },
};

static void alua_desc(const struct alua_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(alua, alua_cases, alua_desc);

static void alua_callback_test(struct kunit *test)
{
	const struct alua_case *p = test->param_value;
	struct alua_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	enum scst_tg_state old = p->activate ? SCST_TG_STATE_TRANSITIONING :
		SCST_TG_STATE_OPTIMIZED;
	enum scst_tg_state new = p->unchanged || p->activate ? SCST_TG_STATE_OPTIMIZED :
		SCST_TG_STATE_TRANSITIONING;
	bool callbacks = !p->remote && !p->unchanged && !p->invalid;
	unsigned int i, j;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, f);
	f->dg.name = "kunit-dg";
	INIT_LIST_HEAD(&f->dg.dev_list);
	INIT_LIST_HEAD(&f->dg.tg_list);
	f->tg.dg = &f->dg;
	f->tg.name = "kunit-tg";
	f->tg.state = old;
	INIT_LIST_HEAD(&f->tg.tgt_list);
	list_add_tail(&f->tg.entry, &f->dg.tg_list);
	f->local.rel_tgt_id = 1;
	f->foreign.rel_tgt_id = 2;
	f->member.tgt = p->remote ? NULL : &f->local;
	list_add_tail(&f->member.entry, &f->tg.tgt_list);
	f->handler.on_alua_state_change_start = p->no_start ? NULL : alua_start;
	f->handler.on_alua_state_change_finish = p->no_finish ? NULL : alua_finish;
	for (i = 0; i < p->devices; i++) {
		struct alua_test_device *d = &f->devices[i];

		d->dev.handler = &f->handler;
		INIT_LIST_HEAD(&d->dev.dev_tgt_dev_list);
		d->member.dev = &d->dev;
		list_add_tail(&d->member.entry, &f->dg.dev_list);
		for (j = 0; j < p->mappings + p->foreign; j++) {
			d->sessions[j].tgt = p->foreign && j == 0 ? &f->foreign : &f->local;
			d->mappings[j].dev = &d->dev;
			d->mappings[j].sess = &d->sessions[j];
			list_add_tail(&d->mappings[j].dev_tgt_dev_list_entry,
				      &d->dev.dev_tgt_dev_list);
		}
	}
	/* Fixtures are never published in SCST's device/target/group lists. */
	mutex_lock(&scst_mutex);
	ret = scst_tg_set_state(&f->tg, p->invalid ? 0x7f : new);
	mutex_unlock(&scst_mutex);

	KUNIT_EXPECT_EQ(test, ret, p->invalid ? -EINVAL : 0);
	KUNIT_EXPECT_EQ(test, f->tg.state, p->invalid ? old : new);
	for (i = 0; i < p->devices; i++) {
		struct alua_test_device *d = &f->devices[i];

		KUNIT_EXPECT_EQ(test, d->starts, callbacks && !p->no_start ? 1U : 0U);
		KUNIT_EXPECT_EQ(test, d->finishes, callbacks && !p->no_finish ? 1U : 0U);
		if (d->starts) {
			KUNIT_EXPECT_EQ(test, d->start_old, old);
			KUNIT_EXPECT_EQ(test, d->start_new, new);
		}
		if (d->finishes) {
			KUNIT_EXPECT_EQ(test, d->finish_old, old);
			KUNIT_EXPECT_EQ(test, d->finish_new, new);
		}
		if (d->starts && d->finishes)
			KUNIT_EXPECT_LT(test, d->start_order, d->finish_order);
		for (j = 0; j < p->mappings + p->foreign; j++) {
			bool changed = !p->unchanged && !p->invalid &&
				d->sessions[j].tgt == &f->local;

			/* TRANSITIONING installs a filter but does not generate UA. */
			KUNIT_EXPECT_EQ(test, !!d->mappings[j].alua_filter, changed);
		}
	}
}

static struct kunit_case alua_test_cases[] = {
	KUNIT_CASE_PARAM(alua_callback_test, alua_gen_params),
	{}
};

scst_kunit_suite(alua_suite, "ALUA", "",
		 .test_cases = alua_test_cases,
);
