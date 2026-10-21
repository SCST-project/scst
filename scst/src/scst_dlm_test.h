/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_DLM_TEST_H
#define SCST_DLM_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED
struct scst_pr_dlm_data;

int scst_dlm_read_nodeids(char **entries);
int scst_dlm_update_nodeids(struct scst_pr_dlm_data *pr_dlm);
#endif

#endif /* SCST_DLM_TEST_H */
