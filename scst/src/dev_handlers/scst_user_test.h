/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_USER_TEST_H
#define SCST_USER_TEST_H

#include "../scst_test.h"

#ifdef SCST_KUNIT_ENABLED

void dev_user_unjam_cmd(struct scst_user_cmd *ucmd, int busy, unsigned long *flags);
void dev_user_flush_pool(struct sgv_pool *pool);
int dev_user_process_cleanup(struct scst_user_dev *dev);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_USER_TEST_H */
