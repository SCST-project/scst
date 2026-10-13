/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_VDISK_TEST_H
#define SCST_VDISK_TEST_H

#include "../scst_test.h"

#ifdef SCST_KUNIT_ENABLED

struct vdisk_cmd_params;

enum compl_status_e vdisk_exec_sai_16(struct vdisk_cmd_params *p);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_VDISK_TEST_H */
