/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_ISER_RDMA_TEST_H
#define SCST_ISER_RDMA_TEST_H

#ifdef INSIDE_KERNEL_TREE
#include "../../scst_test.h"
#else
#include "../../../scst/src/scst_test.h"
#endif

#ifdef SCST_KUNIT_ENABLED

struct ib_wc;
struct isert_cq;

int isert_poll_cq(struct isert_cq *cq);
void isert_handle_wc(struct ib_wc *wc);
void isert_handle_wc_error(struct ib_wc *wc);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_ISER_RDMA_TEST_H */
