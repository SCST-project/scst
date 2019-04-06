#ifndef _TARGET_CORE_BASE_BACKPORT_H_
#define _TARGET_CORE_BASE_BACKPORT_H_

#define TRANSPORT_SENSE_BUFFER 96

enum se_cmd_flags_table {
	SCF_OVERFLOW_BIT		= 0x00001000,
	SCF_UNDERFLOW_BIT		= 0x00002000,
};

/* for sam_task_attr */
#define TCM_SIMPLE_TAG	0x20
#define TCM_HEAD_TAG	0x21
#define TCM_ORDERED_TAG	0x22
#define TCM_ACA_TAG	0x24

struct se_cmd {
	u64	tag; /* SAM command identifier aka task tag */
	u32	se_cmd_flags;
	u32	residual_count;
	u64	t_task_lba;
	int	cpuid;
};

struct se_session {
	void	*fabric_sess_ptr;
};

#endif /* _TARGET_CORE_BASE_BACKPORT_H_ */
