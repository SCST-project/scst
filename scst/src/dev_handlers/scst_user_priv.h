/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_USER_PRIV_H
#define SCST_USER_PRIV_H

#define DEV_USER_CMD_HASH_ORDER		6

struct scst_user_dev {
	/*
	 * Must be kept here, because it's needed on the cleanup time,
	 * when corresponding scst_dev is already dead.
	 */
	struct scst_cmd_threads udev_cmd_threads;

	/* Protected by udev_cmd_threads.cmd_list_lock */
	struct list_head ready_cmd_list;

	/*
	 * Don't need any protection or assignment in SCST_USER_SET_OPTIONS
	 * supposed to be serialized by the caller
	 */
	unsigned int blocking:1;
	unsigned int cleanup_done:1;
	unsigned int tst:3;
	unsigned int tmf_only:1;
	unsigned int queue_alg:4;
	unsigned int qerr:2;
	unsigned int tas:1;
	unsigned int swp:1;
	unsigned int d_sense:1;
	unsigned int has_own_order_mgmt:1;
	unsigned int ext_copy_remap_supported:1;

	int (*generic_parse)(struct scst_cmd *cmd);

	int def_block_size;

	struct scst_mem_lim udev_mem_lim;
	struct sgv_pool *pool;
	struct sgv_pool *pool_clust;

	uint8_t parse_type;
	uint8_t on_free_cmd_type;
	uint8_t memory_reuse_type;
	uint8_t partial_transfers_type;
	uint32_t partial_len;

	struct scst_dev_type devtype;

	/* Both protected by udev_cmd_threads.cmd_list_lock */
	unsigned int handle_counter;
	struct list_head ucmd_hash[1 << DEV_USER_CMD_HASH_ORDER];

	struct scst_device *sdev;

	int virt_id;
	struct list_head dev_list_entry;
	char name[SCST_MAX_NAME];

	struct list_head cleanup_list_entry;
	struct completion cleanup_cmpl;
};

/* Most fields are unprotected, since only one thread at time can access them */
struct scst_user_cmd {
	struct scst_cmd *cmd;
	struct scst_user_dev *dev;

	/*
	 * Note, gcc reported to have a long standing bug, when it uses 64-bit
	 * memory accesses for int bit fields, so, if any neighbor int field
	 * modified intependently to those bit fields, it must be 64-bit
	 * aligned to workaround this gcc bug!
	 */
	unsigned int buff_cached:1;
	unsigned int buf_dirty:1;
	unsigned int background_exec:1;
	unsigned int aborted:1;

	struct scst_user_cmd *buf_ucmd;

	atomic_t ucmd_ref;

	int cur_data_page;
	int num_data_pages;
	int first_page_offset;
	unsigned long ubuff;
	struct page **data_pages;
	struct sgv_pool_obj *sgv;

	/*
	 * Special flags, which can be accessed asynchronously (hence "long").
	 * Protected by udev_cmd_threads.cmd_list_lock.
	 */
	unsigned long sent_to_user:1;
	unsigned long jammed:1;
	unsigned long this_state_unjammed:1;
	unsigned long seen_by_user:1; /* here only as a small optimization */

	unsigned int state;

	struct list_head ready_cmd_list_entry;

	unsigned int h;
	struct list_head hash_list_entry;

	int user_cmd_payload_len;
	struct scst_user_get_cmd user_cmd;

	/* cmpl used only by ATTACH_SESS, mcmd used only by TM */
	union {
		struct completion *cmpl;
		struct scst_mgmt_cmd *mcmd;
	};
	int result;
};

#endif /* SCST_USER_PRIV_H */
