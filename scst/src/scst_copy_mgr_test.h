/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_COPY_MGR_TEST_H
#define SCST_COPY_MGR_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED

struct scst_cm_init_inq_priv;

int scst_cm_send_init_inquiry(struct scst_device *dev, unsigned int unpacked_lun,
			      struct scst_cm_init_inq_priv *priv);
unsigned int scst_cm_get_lun(const struct scst_device *dev);
int scst_cm_dev_register(struct scst_device *dev, u64 lun);
void scst_cm_dev_free_designators(const struct scst_device *dev);
void scst_cm_update_dev_start(struct scst_device *dev);
void scst_cm_update_dev_fini(struct scst_device *dev);
struct scst_acg *scst_cm_default_acg(void);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_COPY_MGR_TEST_H */
