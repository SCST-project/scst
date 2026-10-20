/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_LIB_PRIV_H
#define SCST_LIB_PRIV_H

struct scst_ws_sg_tail {
	struct scatterlist *sg;
	int sg_cnt;
};

struct scst_write_same_priv {
	/* Must be the first for scst_finish_internal_cmd()! */
	scst_i_finish_fn_t ws_finish_fn;

	struct scst_cmd *ws_orig_cmd;

	/* Serializes generated writes and their completions. */
	struct mutex ws_mutex;

	/* 0 len terminated */
	struct scst_data_descriptor *ws_descriptors;

	int ws_cur_descr;

	int ws_left_to_send; /* in blocks */
	s64 ws_cur_lba; /* in blocks */

	__be16 guard_tag;
	__be16 app_tag;
	u32 ref_tag;
	unsigned int dif_valid:1;
	unsigned int inc_ref_tag:1;

	int ws_max_each; /* in blocks */
	int ws_cur_in_flight; /* commands */

	struct scst_ws_sg_tail *ws_sg_tails;

	struct scatterlist *ws_sg_full;
	int ws_sg_full_cnt;
};

#endif /* SCST_LIB_PRIV_H */
