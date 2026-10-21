// SPDX-License-Identifier: GPL-2.0-only
#include "../../../../../scst/src/kunit/scst_kunit.h"
#include "../../isert_dbg.h"
#include "../../iser.h"
#include "../../iser_rdma_test.h"

struct iser_cq_case {
	const char *name;
	int results[3];
	unsigned int polls;
	unsigned int completions;
};

static const struct iser_cq_case iser_cq_cases[] = {
	{ "initial-io-error", { -EIO }, 1, 0 },
	{ "initial-invalid-error", { -EINVAL }, 1, 0 },
	{ "empty", { 0 }, 1, 0 },
	{ "full-then-empty", { ISER_SQ_SIZE, 0 }, 2, ISER_SQ_SIZE },
	{ "full-short-empty", { ISER_SQ_SIZE, 2, 0 }, 3, ISER_SQ_SIZE + 2 },
	{ "short-then-error", { 2, -EIO }, 2, 2 },
};

struct iser_cq_fixture {
	struct isert_cq cq;
	struct ib_cq ib_cq;
	struct ib_device device;
	unsigned int polls;
	unsigned int produced;
	unsigned int completed;
	unsigned int batch_start;
	unsigned int successes;
	unsigned int errors;
};

static int iser_cq_poll_stub(struct ib_cq *cq, int capacity, struct ib_wc *wc)
{
	struct kunit *test = kunit_get_current_test();
	const struct iser_cq_case *param = test->param_value;
	struct iser_cq_fixture *f = test->priv;
	int count, i;

	KUNIT_EXPECT_PTR_EQ(test, cq, &f->ib_cq);
	KUNIT_EXPECT_PTR_EQ(test, wc, &f->cq.wc[0]);
	KUNIT_EXPECT_EQ(test, capacity, (int)ARRAY_SIZE(f->cq.wc));
	KUNIT_EXPECT_EQ(test, f->completed, f->produced);
	if (f->polls >= param->polls) {
		KUNIT_FAIL(test, "polled after the terminal CQ result");
		return -EINVAL;
	}
	count = param->results[f->polls++];
	if (count > capacity) {
		KUNIT_FAIL(test, "poll buffer is too small for the fixture");
		return -EINVAL;
	}
	f->batch_start = f->produced;
	for (i = 0; i < count; i++) {
		wc[i].wr_id = f->produced++;
		wc[i].status = wc[i].wr_id & 1 ? IB_WC_WR_FLUSH_ERR : IB_WC_SUCCESS;
	}
	return count;
}

static void iser_cq_complete(struct ib_wc *wc, bool success)
{
	struct kunit *test = kunit_get_current_test();
	struct iser_cq_fixture *f = test->priv;

	KUNIT_ASSERT_LT(test, f->completed, f->produced);
	KUNIT_EXPECT_PTR_EQ(test, wc, &f->cq.wc[f->completed - f->batch_start]);
	KUNIT_EXPECT_EQ(test, wc->wr_id, (u64)f->completed);
	KUNIT_EXPECT_EQ(test, wc->status, success ? IB_WC_SUCCESS : IB_WC_WR_FLUSH_ERR);
	KUNIT_EXPECT_EQ(test, success, !(f->completed & 1));
	f->completed++;
	if (success)
		f->successes++;
	else
		f->errors++;
}

static void iser_cq_success_stub(struct ib_wc *wc)
{
	iser_cq_complete(wc, true);
}

static void iser_cq_error_stub(struct ib_wc *wc)
{
	iser_cq_complete(wc, false);
}

static int iser_cq_test_init(struct kunit *test)
{
	struct iser_cq_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->cq.cq = &f->ib_cq;
	f->ib_cq.device = &f->device;
	f->device.ops.poll_cq = iser_cq_poll_stub;
	kunit_activate_static_stub(test, isert_handle_wc, iser_cq_success_stub);
	kunit_activate_static_stub(test, isert_handle_wc_error, iser_cq_error_stub);
	return 0;
}

static void iser_cq_case_name(const struct iser_cq_case *param, char *desc)
{
	strscpy(desc, param->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(iser_cq, iser_cq_cases, iser_cq_case_name);

static void iser_cq_poll_test(struct kunit *test)
{
	const struct iser_cq_case *param = test->param_value;
	struct iser_cq_fixture *f = test->priv;
	int ret;

	ret = isert_poll_cq(&f->cq);
	KUNIT_EXPECT_EQ(test, ret, param->results[param->polls - 1]);
	KUNIT_EXPECT_EQ(test, f->polls, param->polls);
	KUNIT_EXPECT_EQ(test, f->completed, param->completions);
	KUNIT_EXPECT_EQ(test, f->successes, (param->completions + 1) / 2);
	KUNIT_EXPECT_EQ(test, f->errors, param->completions / 2);
}

static struct kunit_case iser_cq_test_cases[] = {
	KUNIT_CASE_PARAM(iser_cq_poll_test, iser_cq_gen_params),
	{}
};

scst_kunit_suite(iser_cq_suite, "ISER", "-cq",
		 .init = iser_cq_test_init,
		 .test_cases = iser_cq_test_cases,
);
