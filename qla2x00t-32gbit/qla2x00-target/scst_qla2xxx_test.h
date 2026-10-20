/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_QLA2XXX_TEST_H
#define SCST_QLA2XXX_TEST_H

#ifdef INSIDE_KERNEL_TREE
#include "../../scst/scst_test.h"
#else
#include "../../scst/src/scst_test.h"
#endif

#ifdef SCST_KUNIT_ENABLED
void *sqa_alloc_cmd_map(unsigned int tag_num, size_t tag_size);
void sqa_free_cmd_map(void *map);
int sqa_init_tag_pool(struct sqa_scst_tgt *sqa_tgt, unsigned int tag_num);
void sqa_destroy_tag_pool(struct sqa_scst_tgt *sqa_tgt);
struct scst_tgt *sqa_register_target(struct scst_tgt_template *tmplate,
				     const char *name);
unsigned long *sqa_alloc_tag_bitmap(unsigned int tag_num);
int sqa_init_tag_bitmap(unsigned long **bitmap, unsigned int tag_num);
struct sqa_scst_tgt *sqa_alloc_tgt(struct scst_tgt_template *tmplate,
				   const char *name, unsigned int tag_num,
				   size_t tag_size);
void sqa_free_tgt(struct sqa_scst_tgt *sqa_tgt);
#endif

#endif /* SCST_QLA2XXX_TEST_H */
