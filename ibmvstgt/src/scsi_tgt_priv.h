/* tmp - will replace with SCSI logging stuff */
#define eprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __func__, __LINE__, ##args);	\
} while (0)

#define dprintk(fmt, args...)
/* #define dprintk eprintk */

extern void scsi_tgt_if_exit(void);
extern int scsi_tgt_if_init(void);
