/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_USER_TEST_H
#define SCST_USER_TEST_H

#include "../scst_test.h"

#ifdef SCST_KUNIT_ENABLED

bool ucmd_get_check(struct scst_user_cmd *ucmd);
const u8 *dev_user_ext_cdb(const struct scst_cmd *cmd);
struct scst_cmd *dev_user_ext_cdb_get(struct scst_user_dev *dev, unsigned int cmd_h,
				    struct scst_user_cmd **user_cmd);
void dev_user_unjam_cmd(struct scst_user_cmd *ucmd, int busy, unsigned long *flags);
void dev_user_flush_pool(struct sgv_pool *pool);
int dev_user_process_cleanup(struct scst_user_dev *dev);
int dev_user_map_buf(struct scst_user_cmd *ucmd, unsigned long ubuff, int num_pg);
void dev_user_unmap_buf(struct scst_user_cmd *ucmd);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_USER_TEST_H */
