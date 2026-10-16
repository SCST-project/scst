/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_SYSFS_TEST_H
#define SCST_SYSFS_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED

struct scst_acg;

ssize_t __scst_acg_black_hole_store(struct scst_acg *acg, const char *buf, size_t count);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_SYSFS_TEST_H */
