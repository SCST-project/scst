/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_LIB_TEST_H
#define SCST_LIB_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED

struct scst_write_same_priv;

int sg_copy_elem(struct scatterlist **pdst_sg, size_t *pdst_len,
		 size_t *pdst_offs, struct scatterlist *src_sg, size_t copy_len);
int sg_cmp_elem(struct scatterlist **pdst_sg, size_t *pdst_len,
		size_t *pdst_offs, struct scatterlist *src_sg, size_t cmp_len,
		int *miscompare_offs, bool *cmp_res);

bool __scst_is_relative_target_port_id_unique(u16 id, const struct scst_tgt *t);
int scst_alloc_relative_target_port_id(u16 *id, unsigned int *next);
int scst_ws_build_write_cdb(const struct scst_write_same_priv *wsp,
			    u8 *write_cdb, s64 lba, int blocks);
int scst_ws_push_single_write(struct scst_write_same_priv *wsp, s64 lba, int blocks);
void scst_del_free_acg_dev(struct scst_acg_dev *acg_dev, bool del_sysfs);
void scst_tgt_dev_grace_period(void);
int scst_lun_cm_add(struct scst_acg_dev *acg_dev, u64 lun, unsigned int *flags);
void scst_lun_cm_del(struct scst_acg_dev *acg_dev);
int scst_lun_sysfs_create(struct scst_acg_dev *acg_dev, struct kobject *parent);
void scst_tgt_dev_sysfs_remove(struct scst_tgt_dev *tgt_dev);
void scst_free_acg(struct scst_acg *acg);
void scst_release_acg_work(struct work_struct *work);
int scst_alloc_add_tgt_dev(struct scst_session *sess,
			   struct scst_acg_dev *acg_dev, struct scst_tgt_dev **out_tgt_dev);
void scst_free_tgt_dev(struct scst_tgt_dev *tgt_dev);
void scst_sess_free_tgt_devs(struct scst_session *sess);
void scst_check_reassign_sess(struct scst_session *sess);
void scst_ext_blocker_put(struct scst_ext_blocker *b);
void scst_ext_blocking_done_fn(struct work_struct *work);
int scst_wait_ext_block_dev(struct scst_device *dev, wait_queue_head_t *w);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_LIB_TEST_H */
