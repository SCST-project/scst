enum sqa_mgt_flags {
	SQA_INTERNAL_CMD = BIT_31,
};

#define SQA_DEFAULT_TAGS 2048

extern size_t qlt_add_vtarget(u64, u64, u64);
extern size_t qlt_del_vtarget(u64);

struct sqa_scst_tgt{
	struct list_head list;
	struct scst_tgt *scst_tgt;
	struct qla_tgt *qla_tgt;
	void *tgt_cmd_map;
        struct percpu_ida tgt_tag_pool;
};
