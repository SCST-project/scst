#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) &&	\
	!(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7)
#define QLT_USE_PERCPU_IDA 0
#define QLT_USE_SBITMAP 0
#include <linux/bitmap.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) &&	\
	!(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 8)
#define QLT_USE_PERCPU_IDA 1
#define QLT_USE_SBITMAP 0
/* See also commit 798ab48eecdf ("idr: Percpu ida") # v3.12 */
#include <linux/percpu_ida.h>
#else
#define QLT_USE_PERCPU_IDA 0
#define QLT_USE_SBITMAP 1
/* See also commit 693ba15c9202 ("scsi: Remove percpu_ida") # v4.19. */
#include <linux/sbitmap.h>
#endif

/* Driver version number */
#define Q2T_VERSION(a, b, c, d)	(((a) << 030) + ((b) << 020) + (c) << 010 + (d))
#define Q2T_VERSION_CODE	Q2T_VERSION(3, 10, 0, 0)
#define Q2T_VERSION_STRING	"3.10.0"

#define SQA_DEFAULT_TAGS 2048

extern size_t qlt_add_vtarget(u64, u64, u64);
extern size_t qlt_del_vtarget(u64);

struct sqa_scst_tgt {
	struct list_head list;
	struct scst_tgt *scst_tgt;
	struct qla_tgt *qla_tgt;
	void *tgt_cmd_map;
#if QLT_USE_PERCPU_IDA
	struct percpu_ida tgt_tag_pool;
#elif QLT_USE_SBITMAP
	struct sbitmap_queue tgt_tag_pool;
#else
	unsigned long *tgt_tag_pool;
	unsigned int tag_num;
#endif
};
