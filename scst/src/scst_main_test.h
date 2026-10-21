/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_MAIN_TEST_H
#define SCST_MAIN_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED
#include <linux/types.h>

struct scst_cmd;

char *scst_dump_cdb(char *buf, size_t buf_len, const struct scst_cmd *cmd);
#endif

#endif /* SCST_MAIN_TEST_H */
