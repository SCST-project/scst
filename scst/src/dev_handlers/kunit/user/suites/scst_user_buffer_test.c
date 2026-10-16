// SPDX-License-Identifier: GPL-2.0-only
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/version.h>
#include "../../../../kunit/scst_kunit.h"
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_user.h>
#else
#include "scst.h"
#include "scst_user.h"
#endif
#include "../../../scst_user_priv.h"
#include "../../../scst_user_test.h"

#define USER_BUFFER_PAGES 2

struct user_buffer_case {
	const char *name;
	bool dirty;
};

static const struct user_buffer_case user_buffer_cases[] = {
	{ "dirty", true },
	{ "clean", false },
};

static void user_buffer_desc(const struct user_buffer_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(user_buffer, user_buffer_cases, user_buffer_desc);

/*
 * on_free_cmd() can release an uncached buffer in atomic context, for example
 * when iSCSI completes a command with SCST_CONTEXT_DIRECT_ATOMIC. Unmapping must
 * not sleep, including when it marks the pages dirty after a WRITE. With
 * CONFIG_DEBUG_ATOMIC_SLEEP a sleeping call here is reported as a kernel
 * diagnostic.
 */
static void user_buffer_unmap_test(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
	const struct user_buffer_case *p = test->param_value;
	struct page *pages[USER_BUFFER_PAGES];
	struct scst_user_cmd *ucmd;
	unsigned long ubuff, flags;
	int i;

	ubuff = kunit_vm_mmap(test, NULL, 0, USER_BUFFER_PAGES * PAGE_SIZE,
			      PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0);
	KUNIT_ASSERT_NE_MSG(test, ubuff, 0UL, "cannot map a user buffer");
	ucmd = kunit_kzalloc(test, sizeof(*ucmd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ucmd);

	KUNIT_ASSERT_EQ(test, dev_user_map_buf(ucmd, ubuff, USER_BUFFER_PAGES), 0);
	memcpy(pages, ucmd->data_pages, sizeof(pages));
	for (i = 0; i < USER_BUFFER_PAGES; i++) {
		KUNIT_EXPECT_TRUE(test, folio_maybe_dma_pinned(page_folio(pages[i])));
		ClearPageDirty(pages[i]);
		/* Keep the pages for the checks below once they are unpinned. */
		get_page(pages[i]);
	}

	ucmd->buf_dirty = p->dirty;
	local_irq_save(flags);
	dev_user_unmap_buf(ucmd);
	local_irq_restore(flags);

	KUNIT_EXPECT_NULL(test, ucmd->data_pages);
	for (i = 0; i < USER_BUFFER_PAGES; i++) {
		KUNIT_EXPECT_FALSE(test, folio_maybe_dma_pinned(page_folio(pages[i])));
		KUNIT_EXPECT_EQ(test, !!PageDirty(pages[i]), p->dirty);
		put_page(pages[i]);
	}
#else
	kunit_skip(test, "kunit_vm_mmap() requires Linux 6.11 or later");
#endif
}

static struct kunit_case user_buffer_test_cases[] = {
	KUNIT_CASE_PARAM(user_buffer_unmap_test, user_buffer_gen_params),
	{}
};

scst_kunit_suite(user_buffer_suite, "USER", "-buffers",
		 .test_cases = user_buffer_test_cases,
);
