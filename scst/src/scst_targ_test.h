/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_TARG_TEST_H
#define SCST_TARG_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED

struct scst_cmd;

bool scst_cmd_overlap(struct scst_cmd *chk_cmd, struct scst_cmd *cmd);
int scst_parse_cmd(struct scst_cmd *cmd);
void scst_cmd_set_sn(struct scst_cmd *cmd);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_TARG_TEST_H */
