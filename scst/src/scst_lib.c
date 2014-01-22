/*
 *  scst_lib.c
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/cdrom.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <asm/kmap_types.h>
#include <asm/unaligned.h>
#include <linux/namei.h>
#include <linux/mount.h>

#ifndef INSIDE_KERNEL_TREE
#include <linux/version.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#include <linux/writeback.h>
#endif

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_priv.h"
#include "scst_mem.h"
#include "scst_pres.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
struct scsi_io_context {
	void *data;
	void (*done)(void *data, char *sense, int result, int resid);
	char sense[SCST_SENSE_BUFFERSIZE];
};
static struct kmem_cache *scsi_io_context_cache;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22) \
    && (!defined(RHEL_RELEASE_CODE) || RHEL_RELEASE_CODE -0 < 5 * 256 + 3) \
    && !defined(CONFIG_PPC)
static int strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}
#endif

#if !((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)) && !defined(HAVE_SG_COPY)
static int sg_copy(struct scatterlist *dst_sg, struct scatterlist *src_sg,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
	    int nents_to_copy, size_t copy_len,
	    enum km_type d_km_type, enum km_type s_km_type);
#else
	    int nents_to_copy, size_t copy_len);
#endif
#endif

static void scst_free_descriptors(struct scst_cmd *cmd);

struct scst_sdbops;

static int get_cdb_info_len_10(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_block_limit(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_read_capacity(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_serv_act_in(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_single(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_read_pos(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_prevent_allow_medium_removal(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_start_stop(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_len_3_read_elem_stat(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_len_2(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_fmt(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
	static int get_cdb_info_verify6(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_verify10(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_verify12(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_verify16(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_len_1(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_2_len_1_256(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_bidi_lba_4_len_2(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_len_3(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_len_4(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_2_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_4_len_2(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_4_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_4_len_2(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_4_len_4(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_8_len_4(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_lba_8_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_write_same10(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_write_same16(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_apt(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);
static int get_cdb_info_min(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops);

/*
+=====================================-============-======-
|  Command name                       | Operation  | Type |
|                                     |   code     |      |
|-------------------------------------+------------+------+

+=========================================================+
|Key:  M = command implementation is mandatory.           |
|      O = command implementation is optional.            |
|      V = Vendor-specific                                |
|      R = Reserved                                       |
|     ' '= DON'T use for this device                      |
+=========================================================+
*/

#define SCST_CDB_MANDATORY  'M'	/* mandatory */
#define SCST_CDB_OPTIONAL   'O'	/* optional  */
#define SCST_CDB_VENDOR     'V'	/* vendor    */
#define SCST_CDB_RESERVED   'R'	/* reserved  */
#define SCST_CDB_NOTSUPP    ' '	/* don't use */

struct scst_sdbops {
	uint8_t ops;		/* SCSI-2 op codes */
	uint8_t devkey[16];	/* Key for every device type M,O,V,R
				 * type_disk      devkey[0]
				 * type_tape      devkey[1]
				 * type_printer   devkey[2]
				 * type_processor devkey[3]
				 * type_worm      devkey[4]
				 * type_cdrom     devkey[5]
				 * type_scanner   devkey[6]
				 * type_mod       devkey[7]
				 * type_changer   devkey[8]
				 * type_commdev   devkey[9]
				 * type_reserv    devkey[A]
				 * type_reserv    devkey[B]
				 * type_raid      devkey[C]
				 * type_enclosure devkey[D]
				 * type_reserv    devkey[E]
				 * type_reserv    devkey[F]
				 */
	uint8_t info_lba_off;	/* LBA offset in cdb */
	uint8_t info_lba_len;	/* LBA length in cdb */
	uint8_t info_len_off;	/* length offset in cdb */
	uint8_t info_len_len;	/* length length in cdb */
	uint8_t info_data_direction; /* init --> target: SCST_DATA_WRITE
				   * target --> init: SCST_DATA_READ
				   * target <--> init: SCST_DATA_READ|SCST_DATA_WRITE
				   */
	uint32_t info_op_flags;	/* various flags of this opcode */
	const char *info_op_name;/* op code SCSI full name */
	int (*get_cdb_info)(struct scst_cmd *cmd, const struct scst_sdbops *sdbops);
};

static int scst_scsi_op_list[256];

#define FLAG_NONE 0

/* See also http://www.t10.org/lists/op-num.htm */
static const struct scst_sdbops scst_scsi_op_table[] = {
	/*
	 *                       +-------------------> TYPE_DISK      (0)
	 *                       |
	 *                       |+------------------> TYPE_TAPE      (1)
	 *                       ||
	 *                       ||+-----------------> TYPE_PRINTER   (2)
	 *                       |||
	 *                       |||+----------------> TYPE_PROCESSOR (3)
	 *                       ||||
	 *                       ||||+---------------> TYPE_WORM      (4)
	 *                       |||||
	 *                       |||||+--------------> TYPE_CDROM     (5)
	 *                       ||||||
	 *                       ||||||+-------------> TYPE_SCANNER   (6)
	 *                       |||||||
	 *                       |||||||+------------> TYPE_MOD       (7)
	 *                       ||||||||
	 *                       ||||||||+-----------> TYPE_CHANGER   (8)
	 *                       |||||||||
	 *                       |||||||||+----------> TYPE_COMM      (9)
	 *                       ||||||||||
	 *                       ||||||||||  +-------> TYPE_RAID      (C)
	 *                       ||||||||||  |
	 *                       ||||||||||  |+------> TYPE_ENCLOSURE (D)
	 *                       ||||||||||  ||
	 *                       ||||||||||  ||+-----> TYPE_RBC       (E)
	 *                       ||||||||||  |||
	 *                       ||||||||||  |||+----> Optical card   (F)
	 *                       ||||||||||  ||||
	 *                       ||||||||||  ||||
	 *                       0123456789ABCDEF -> TYPE_????     */

	/* 6-bytes length CDB */
	{.ops = 0x00, .devkey = "MMMMMMMMMMMMMMMM",
	 .info_op_name = "TEST UNIT READY",
	 .info_data_direction = SCST_DATA_NONE,
	 /* Let's be HQ to don't look dead under high load */
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_IMPLICIT_HQ|
			 SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x01, .devkey = " M              ",
	 .info_op_name = "REWIND",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_EXCL_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x03, .devkey = "MMMMMMMMMMMMMMMM",
	 .info_op_name = "REQUEST SENSE",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_SKIP_UA|SCST_LOCAL_CMD|
		 SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
		 SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 4, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0x04, .devkey = "M    O O        ",
	 .info_op_name = "FORMAT UNIT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_fmt},
	{.ops = 0x04, .devkey = " O              ",
	 .info_op_name = "FORMAT MEDIUM",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 .info_len_off = 3, .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x04, .devkey = "  O             ",
	 .info_op_name = "FORMAT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x05, .devkey = "VMVVVV  V       ",
	 .info_op_name = "READ BLOCK LIMITS",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_REG_RESERVE_ALLOWED|
		SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_block_limit},
	{.ops = 0x07, .devkey = "        O       ",
	 .info_op_name = "INITIALIZE ELEMENT STATUS",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x07, .devkey = "OVV O  OV       ",
	 .info_op_name = "REASSIGN BLOCKS",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x08, .devkey = "O               ",
	 .info_op_name = "READ(6)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 2,
	 .info_len_off = 4, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_lba_2_len_1_256},
	{.ops = 0x08, .devkey = " MV  O OV       ",
	 .info_op_name = "READ(6)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x08, .devkey = "         M      ",
	 .info_op_name = "GET MESSAGE(6)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x08, .devkey = "    O           ",
	 .info_op_name = "RECEIVE",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x0A, .devkey = "O               ",
	 .info_op_name = "WRITE(6)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 2,
	 .info_len_off = 4, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_lba_2_len_1_256},
	{.ops = 0x0A, .devkey = " M  O  OV       ",
	 .info_op_name = "WRITE(6)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x0A, .devkey = "  M             ",
	 .info_op_name = "PRINT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x0A, .devkey = "         M      ",
	 .info_op_name = "SEND MESSAGE(6)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x0A, .devkey = "    M           ",
	 .info_op_name = "SEND(6)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x0B, .devkey = "O   OO OV       ",
	 .info_op_name = "SEEK(6)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .info_lba_off = 2, .info_lba_len = 2,
	 .get_cdb_info = get_cdb_info_lba_2_none},
	{.ops = 0x0B, .devkey = "  O             ",
	 .info_op_name = "SLEW AND PRINT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x0C, .devkey = " VVVVV  V       ",
	 .info_op_name = "SEEK BLOCK",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x0D, .devkey = " VVVVV  V       ",
	 .info_op_name = "PARTITION",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x0F, .devkey = " OVVVV  V       ",
	 .info_op_name = "READ REVERSE",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 12, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x10, .devkey = " M V V          ",
	 .info_op_name = "WRITE FILEMARKS(6)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x10, .devkey = "  O O           ",
	 .info_op_name = "SYNCHRONIZE BUFFER",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x11, .devkey = "VMVVVV          ",
	 .info_op_name = "SPACE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|
			 SCST_WRITE_EXCL_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x12, .devkey = "MMMMMMMMMMMMMMMM",
	 .info_op_name = "INQUIRY",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_IMPLICIT_HQ|SCST_SKIP_UA|
		SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
		SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 3, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x13, .devkey = " O              ",
	 .info_op_name = "VERIFY(6)",
	 .info_data_direction = SCST_DATA_UNKNOWN,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_verify6},
	{.ops = 0x14, .devkey = " OOVVV          ",
	 .info_op_name = "RECOVER BUFFERED DATA",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 2, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x15, .devkey = "OMOOOOOOOOOOOOOO",
	 .info_op_name = "MODE SELECT(6)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_STRICTLY_SERIALIZED,
	 .info_len_off = 4, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0x16, .devkey = "MMMMMMMMMMMMMMMM",
	 .info_op_name = "RESERVE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|SCST_SERIALIZED|
			 SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x17, .devkey = "MMMMMMMMMMMMMMMM",
	 .info_op_name = "RELEASE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|SCST_SERIALIZED|
		SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
		SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x19, .devkey = " MVVVV          ",
	 .info_op_name = "ERASE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x1A, .devkey = "OMOOOOOOOOOOOOOO",
	 .info_op_name = "MODE SENSE(6)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT |
		 SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 4, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0x1B, .devkey = "      O         ",
	 .info_op_name = "SCAN",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x1B, .devkey = " O              ",
	 .info_op_name = "LOAD UNLOAD",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x1B, .devkey = "  O             ",
	 .info_op_name = "STOP PRINT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x1B, .devkey = "O   OO O    O   ",
	 .info_op_name = "START STOP UNIT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_start_stop},
	{.ops = 0x1C, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "RECEIVE DIAGNOSTIC RESULTS",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 3, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x1D, .devkey = "MMMMMMMMMMMMMMMM",
	 .info_op_name = "SEND DIAGNOSTIC",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 3, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x1E, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "PREVENT ALLOW MEDIUM REMOVAL",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_prevent_allow_medium_removal},
	{.ops = 0x1F, .devkey = "            O   ",
	 .info_op_name = "PORT STATUS",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},

	 /* 10-bytes length CDB */
	{.ops = 0x23, .devkey = "V   VV V        ",
	 .info_op_name = "READ FORMAT CAPACITY",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x24, .devkey = "    VVM         ",
	 .info_op_name = "SET WINDOW",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x25, .devkey = "M   MM M        ",
	 .info_op_name = "READ CAPACITY",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_IMPLICIT_HQ|SCST_REG_RESERVE_ALLOWED|
		SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_read_capacity},
	{.ops = 0x25, .devkey = "      O         ",
	 .info_op_name = "GET WINDOW",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x28, .devkey = "M   MMMM        ",
	 .info_op_name = "READ(10)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_len_2},
	{.ops = 0x28, .devkey = "         O      ",
	 .info_op_name = "GET MESSAGE(10)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x29, .devkey = "V   VV O        ",
	 .info_op_name = "READ GENERATION",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 8, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0x2A, .devkey = "O   MO M        ",
	 .info_op_name = "WRITE(10)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_len_2},
	{.ops = 0x2A, .devkey = "         O      ",
	 .info_op_name = "SEND MESSAGE(10)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x2A, .devkey = "      O         ",
	 .info_op_name = "SEND(10)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x2B, .devkey = " O              ",
	 .info_op_name = "LOCATE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_EXCL_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x2B, .devkey = "        O       ",
	 .info_op_name = "POSITION TO ELEMENT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x2B, .devkey = "O   OO O        ",
	 .info_op_name = "SEEK(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .get_cdb_info = get_cdb_info_lba_4_none},
	{.ops = 0x2C, .devkey = "V    O O        ",
	 .info_op_name = "ERASE(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x2D, .devkey = "V   O  O        ",
	 .info_op_name = "READ UPDATED BLOCK",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED,
	 .get_cdb_info = get_cdb_info_single},
	{.ops = 0x2E, .devkey = "O   OO O        ",
	 .info_op_name = "WRITE AND VERIFY(10)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_len_2},
	{.ops = 0x2F, .devkey = "O   OO O        ",
	 .info_op_name = "VERIFY(10)",
	 .info_data_direction = SCST_DATA_UNKNOWN,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_verify10},
	{.ops = 0x33, .devkey = "    OO O        ",
	 .info_op_name = "SET LIMITS(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x34, .devkey = " O              ",
	 .info_op_name = "READ POSITION",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_read_pos},
	{.ops = 0x34, .devkey = "      O         ",
	 .info_op_name = "GET DATA BUFFER STATUS",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x34, .devkey = "O   OO O        ",
	 .info_op_name = "PRE-FETCH",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_none},
	{.ops = 0x35, .devkey = "O   OO O        ",
	 .info_op_name = "SYNCHRONIZE CACHE(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_none},
	{.ops = 0x36, .devkey = "O   OO O        ",
	 .info_op_name = "LOCK UNLOCK CACHE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x37, .devkey = "O      O        ",
	 .info_op_name = "READ DEFECT DATA(10)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x37, .devkey = "        O       ",
	 .info_op_name = "INIT ELEMENT STATUS WRANGE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x38, .devkey = "    O  O        ",
	 .info_op_name = "MEDIUM SCAN",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 8, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0x3B, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "WRITE BUFFER",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_SMALL_TIMEOUT,
	 .info_len_off = 5, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x3C, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "READ BUFFER",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT |
		 SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 5, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x3D, .devkey = "    O  O        ",
	 .info_op_name = "UPDATE BLOCK",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED,
	 .get_cdb_info = get_cdb_info_single},
	{.ops = 0x3E, .devkey = "O   OO O        ",
	 .info_op_name = "READ LONG",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_len_2},
	{.ops = 0x3F, .devkey = "O   O  O        ",
	 .info_op_name = "WRITE LONG",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_len_2},
	{.ops = 0x40, .devkey = "OOOOOOOOOO      ",
	 .info_op_name = "CHANGE DEFINITION",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_SMALL_TIMEOUT,
	 .info_len_off = 8, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0x41, .devkey = "O               ",
	 .info_op_name = "WRITE SAME(10)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_write_same10},
	{.ops = 0x42, .devkey = "     O          ",
	 .info_op_name = "READ SUB-CHANNEL",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x42, .devkey = "O               ",
	 .info_op_name = "UNMAP",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM|SCST_DESCRIPTORS_BASED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x43, .devkey = "     O          ",
	 .info_op_name = "READ TOC/PMA/ATIP",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x44, .devkey = " M              ",
	 .info_op_name = "REPORT DENSITY SUPPORT",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
			SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x44, .devkey = "     O          ",
	 .info_op_name = "READ HEADER",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x45, .devkey = "     O          ",
	 .info_op_name = "PLAY AUDIO(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x46, .devkey = "     O          ",
	 .info_op_name = "GET CONFIGURATION",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x47, .devkey = "     O          ",
	 .info_op_name = "PLAY AUDIO MSF",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x48, .devkey = "     O          ",
	 .info_op_name = "PLAY AUDIO TRACK INDEX",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x49, .devkey = "     O          ",
	 .info_op_name = "PLAY TRACK RELATIVE(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x4A, .devkey = "     O          ",
	 .info_op_name = "GET EVENT STATUS NOTIFICATION",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x4B, .devkey = "     O          ",
	 .info_op_name = "PAUSE/RESUME",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x4C, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "LOG SELECT",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_STRICTLY_SERIALIZED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x4D, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "LOG SENSE",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_REG_RESERVE_ALLOWED|
			SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x4E, .devkey = "     O          ",
	 .info_op_name = "STOP PLAY/SCAN",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x50, .devkey = "O               ",
	 .info_op_name = "XDWRITE(10)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_len_2},
	{.ops = 0x51, .devkey = "     O          ",
	 .info_op_name = "READ DISC INFORMATION",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x51, .devkey = "O               ",
	 .info_op_name = "XPWRITE",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_lba_4_len_2},
	{.ops = 0x52, .devkey = "     O          ",
	 .info_op_name = "READ TRACK INFORMATION",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x53, .devkey = "O               ",
	 .info_op_name = "XDWRITEREAD(10)",
	 .info_data_direction = SCST_DATA_BIDI,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_bidi_lba_4_len_2},
	{.ops = 0x53, .devkey = "     O          ",
	 .info_op_name = "RESERVE TRACK",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x54, .devkey = "     O          ",
	 .info_op_name = "SEND OPC INFORMATION",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x55, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "MODE SELECT(10)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_STRICTLY_SERIALIZED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x56, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "RESERVE(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|SCST_SERIALIZED|
			SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x57, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "RELEASE(10)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|SCST_SERIALIZED|
			SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
			SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x58, .devkey = "     O          ",
	 .info_op_name = "REPAIR TRACK",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x5A, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "MODE SENSE(10)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT |
		 SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x5B, .devkey = "     O          ",
	 .info_op_name = "CLOSE TRACK/SESSION",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x5C, .devkey = "     O          ",
	 .info_op_name = "READ BUFFER CAPACITY",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0x5D, .devkey = "     O          ",
	 .info_op_name = "SEND CUE SHEET",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0x5E, .devkey = "OOOOO OOOO      ",
	 .info_op_name = "PERSISTENT RESERVE IN",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|SCST_SERIALIZED|
			SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 5, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0x5F, .devkey = "OOOOO OOOO      ",
	 .info_op_name = "PERSISTENT RESERVE OUT",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|SCST_SERIALIZED|
			SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 5, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},

	/* 16-bytes length CDB */
	{.ops = 0x80, .devkey = " O              ",
	 .info_op_name = "WRITE FILEMARKS(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x81, .devkey = "O   OO O        ",
	 .info_op_name = "REBUILD",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0x82, .devkey = "O   OO O        ",
	 .info_op_name = "REGENERATE",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0x83, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "EXTENDED COPY",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0x84, .devkey = "OOOOOOOOOOOOOOOO",
	 .info_op_name = "RECEIVE COPY RESULT",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0x85, .devkey = "O    O        O ",
	 .info_op_name = "ATA PASS-THROUGH(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .info_lba_off = 7, .info_lba_len = 6,
	 .get_cdb_info = get_cdb_info_apt},
	{.ops = 0x86, .devkey = "OOOOOOOOOO      ",
	 .info_op_name = "ACCESS CONTROL IN",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
				SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x87, .devkey = "OOOOOOOOOO      ",
	 .info_op_name = "ACCESS CONTROL OUT",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED|
				SCST_EXCL_ACCESS_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x88, .devkey = "M   MMMM        ",
	 .info_op_name = "READ(16)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 8,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_lba_8_len_4},
	{.ops = 0x8A, .devkey = "O   OO O        ",
	 .info_op_name = "WRITE(16)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 8,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_lba_8_len_4},
	{.ops = 0x8C, .devkey = " OOOOOOOOO      ",
	 .info_op_name = "READ ATTRIBUTE",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0x8D, .devkey = " OOOOOOOOO      ",
	 .info_op_name = "WRITE ATTRIBUTE",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0x8E, .devkey = "O   OO O        ",
	 .info_op_name = "WRITE AND VERIFY(16)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 8,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_lba_8_len_4},
	{.ops = 0x8F, .devkey = "O   OO O        ",
	 .info_op_name = "VERIFY(16)",
	 .info_data_direction = SCST_DATA_UNKNOWN,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 8,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_verify16},
	{.ops = 0x90, .devkey = "O   OO O        ",
	 .info_op_name = "PRE-FETCH(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 8,
	 .get_cdb_info = get_cdb_info_lba_8_none},
	{.ops = 0x91, .devkey = "O   OO O        ",
	 .info_op_name = "SYNCHRONIZE CACHE(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .info_lba_off = 2, .info_lba_len = 8,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_lba_8_none},
	{.ops = 0x91, .devkey = " M              ",
	 .info_op_name = "SPACE(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_EXCL_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x92, .devkey = "O   OO O        ",
	 .info_op_name = "LOCK UNLOCK CACHE(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x92, .devkey = " O              ",
	 .info_op_name = "LOCATE(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_EXCL_ALLOWED,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x93, .devkey = "O               ",
	 .info_op_name = "WRITE SAME(16)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 8,
	 .info_len_off = 10, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_write_same16},
	{.ops = 0x93, .devkey = " M              ",
	 .info_op_name = "ERASE(16)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0x9E, .devkey = "O               ",
	 .info_op_name = "SERVICE ACTION IN",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_serv_act_in},

	/* 12-bytes length CDB */
	{.ops = 0xA0, .devkey = "VVVVVVVVVV  M   ",
	 .info_op_name = "REPORT LUNS",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_SMALL_TIMEOUT|SCST_IMPLICIT_HQ|SCST_SKIP_UA|
			 SCST_FULLY_LOCAL_CMD|SCST_LOCAL_CMD|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xA1, .devkey = "O    O        O ",
	 .info_op_name = "ATA PASS-THROUGH(12)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .info_lba_off = 5, .info_lba_len = 3,
	 .get_cdb_info = get_cdb_info_apt},
	{.ops = 0xA1, .devkey = "     O          ",
	 .info_op_name = "BLANK",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xA2, .devkey = "OO   O          ",
	 .info_op_name = "SECURITY PROTOCOL IN",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_REG_RESERVE_ALLOWED|SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xA3, .devkey = "     O          ",
	 .info_op_name = "SEND KEY",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 8, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0xA3, .devkey = "OOO O OOOO  MO O",
	 .info_op_name = "MAINTENANCE(IN)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_min},
	{.ops = 0xA4, .devkey = "     O          ",
	 .info_op_name = "REPORT KEY",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 8, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0xA4, .devkey = "            O   ",
	 .info_op_name = "MAINTENANCE(OUT)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xA5, .devkey = "        M       ",
	 .info_op_name = "MOVE MEDIUM",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xA5, .devkey = "     O          ",
	 .info_op_name = "PLAY AUDIO(12)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xA6, .devkey = "     O  O       ",
	 .info_op_name = "EXCHANGE/LOAD/UNLOAD MEDIUM",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xA7, .devkey = "     O          ",
	 .info_op_name = "SET READ AHEAD",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xA8, .devkey = "         O      ",
	 .info_op_name = "GET MESSAGE(12)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xA8, .devkey = "O   OO O        ",
	 .info_op_name = "READ(12)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_lba_4_len_4},
	{.ops = 0xA9, .devkey = "     O          ",
	 .info_op_name = "PLAY TRACK RELATIVE(12)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xAA, .devkey = "O   OO O        ",
	 .info_op_name = "WRITE(12)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_lba_4_len_4},
	{.ops = 0xAA, .devkey = "         O      ",
	 .info_op_name = "SEND MESSAGE(12)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xAC, .devkey = "       O        ",
	 .info_op_name = "ERASE(12)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_WRITE_MEDIUM,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xAC, .devkey = "     M          ",
	 .info_op_name = "GET PERFORMANCE",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_UNKNOWN_LENGTH,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xAD, .devkey = "     O          ",
	 .info_op_name = "READ DVD STRUCTURE",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 8, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0xAE, .devkey = "O   OO O        ",
	 .info_op_name = "WRITE AND VERIFY(12)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_lba_4_len_4},
	{.ops = 0xAF, .devkey = "O   OO O        ",
	 .info_op_name = "VERIFY(12)",
	 .info_data_direction = SCST_DATA_UNKNOWN,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_EXCL_ALLOWED,
	 .info_lba_off = 2, .info_lba_len = 4,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_verify12},
	{.ops = 0xB3, .devkey = "    OO O        ",
	 .info_op_name = "SET LIMITS(12)",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xB5, .devkey = "OO   O          ",
	 .info_op_name = "SECURITY PROTOCOL OUT",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xB5, .devkey = "        O       ",
	 .info_op_name = "REQUEST VOLUME ELEMENT ADDRESS",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0xB6, .devkey = "        O       ",
	 .info_op_name = "SEND VOLUME TAG",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 9, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0xB6, .devkey = "     M         ",
	 .info_op_name = "SET STREAMING",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 9, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0xB7, .devkey = "O      O        ",
	 .info_op_name = "READ DEFECT DATA(12)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_WRITE_EXCL_ALLOWED,
	 .info_len_off = 9, .info_len_len = 1,
	 .get_cdb_info = get_cdb_info_len_1},
	{.ops = 0xB8, .devkey = "        O       ",
	 .info_op_name = "READ ELEMENT STATUS",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 7, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3_read_elem_stat},
	{.ops = 0xB9, .devkey = "     O          ",
	 .info_op_name = "READ CD MSF",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_UNKNOWN_LENGTH,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xBA, .devkey = "     O          ",
	 .info_op_name = "SCAN",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xBA, .devkey = "            O   ",
	 .info_op_name = "REDUNDANCY GROUP(IN)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xBB, .devkey = "     O          ",
	 .info_op_name = "SET SPEED",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = FLAG_NONE,
	 .get_cdb_info = get_cdb_info_none},
	{.ops = 0xBB, .devkey = "            O   ",
	 .info_op_name = "REDUNDANCY GROUP(OUT)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xBC, .devkey = "            O   ",
	 .info_op_name = "SPARE(IN)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xBD, .devkey = "     O          ",
	 .info_op_name = "MECHANISM STATUS",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 8, .info_len_len = 2,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0xBD, .devkey = "            O   ",
	 .info_op_name = "SPARE(OUT)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xBE, .devkey = "     O          ",
	 .info_op_name = "READ CD",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = SCST_TRANSFER_LEN_TYPE_FIXED,
	 .info_len_off = 6, .info_len_len = 3,
	 .get_cdb_info = get_cdb_info_len_3},
	{.ops = 0xBE, .devkey = "            O   ",
	 .info_op_name = "VOLUME SET(IN)",
	 .info_data_direction = SCST_DATA_READ,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xBF, .devkey = "     O          ",
	 .info_op_name = "SEND DVD STRUCTUE",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 8, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_2},
	{.ops = 0xBF, .devkey = "            O   ",
	 .info_op_name = "VOLUME SET(OUT)",
	 .info_data_direction = SCST_DATA_WRITE,
	 .info_op_flags = FLAG_NONE,
	 .info_len_off = 6, .info_len_len = 4,
	 .get_cdb_info = get_cdb_info_len_4},
	{.ops = 0xE7, .devkey = "        V       ",
	 .info_op_name = "INIT ELEMENT STATUS WRANGE",
	 .info_data_direction = SCST_DATA_NONE,
	 .info_op_flags = SCST_LONG_TIMEOUT,
	 .get_cdb_info = get_cdb_info_len_10}
};

#define SCST_CDB_TBL_SIZE	((int)ARRAY_SIZE(scst_scsi_op_table))

static void scst_free_tgt_dev(struct scst_tgt_dev *tgt_dev);
static void scst_check_internal_sense(struct scst_device *dev, int result,
	uint8_t *sense, int sense_len);
static void scst_queue_report_luns_changed_UA(struct scst_session *sess,
	int flags);
static void __scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags);
static void scst_alloc_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags);
static void scst_free_all_UA(struct scst_tgt_dev *tgt_dev);
static void scst_release_space(struct scst_cmd *cmd);
static void scst_clear_reservation(struct scst_tgt_dev *tgt_dev);
static int scst_alloc_add_tgt_dev(struct scst_session *sess,
	struct scst_acg_dev *acg_dev, struct scst_tgt_dev **out_tgt_dev);
static void scst_tgt_retry_timer_fn(unsigned long arg);

#ifdef CONFIG_SCST_DEBUG_TM
static void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev);
static void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev);
#else
static inline void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev) {}
static inline void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev) {}
#endif /* CONFIG_SCST_DEBUG_TM */

/**
 * scst_alloc_sense() - allocate sense buffer for command
 *
 * Allocates, if necessary, sense buffer for command. Returns 0 on success
 * and error code otherwise. Parameter "atomic" should be non-0 if the
 * function called in atomic context.
 */
int scst_alloc_sense(struct scst_cmd *cmd, int atomic)
{
	int res = 0;
	gfp_t gfp_mask = atomic ? GFP_ATOMIC : (cmd->cmd_gfp_mask|__GFP_NOFAIL);

	TRACE_ENTRY();

	if (cmd->sense != NULL)
		goto memzero;

	cmd->sense = mempool_alloc(scst_sense_mempool, gfp_mask);
	if (cmd->sense == NULL) {
		PRINT_CRIT_ERROR("Sense memory allocation failed (op %x). "
			"The sense data will be lost!!", cmd->cdb[0]);
		res = -ENOMEM;
		goto out;
	}

	cmd->sense_buflen = SCST_SENSE_BUFFERSIZE;

memzero:
	cmd->sense_valid_len = 0;
	memset(cmd->sense, 0, cmd->sense_buflen);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_alloc_sense);

/**
 * scst_alloc_set_sense() - allocate and fill sense buffer for command
 *
 * Allocates, if necessary, sense buffer for command and copies in
 * it data from the supplied sense buffer. Returns 0 on success
 * and error code otherwise.
 */
int scst_alloc_set_sense(struct scst_cmd *cmd, int atomic,
	const uint8_t *sense, unsigned int len)
{
	int res;

	TRACE_ENTRY();

	/*
	 * We don't check here if the existing sense is valid or not, because
	 * we suppose the caller did it based on cmd->status.
	 */

	res = scst_alloc_sense(cmd, atomic);
	if (res != 0) {
		PRINT_BUFFER("Lost sense", sense, len);
		goto out;
	}

	cmd->sense_valid_len = len;
	if (cmd->sense_buflen < len) {
		PRINT_WARNING("Sense truncated (needed %d), shall you increase "
			"SCST_SENSE_BUFFERSIZE? Op: %x", len, cmd->cdb[0]);
		cmd->sense_valid_len = cmd->sense_buflen;
	}

	memcpy(cmd->sense, sense, cmd->sense_valid_len);
	TRACE_BUFFER("Sense set", cmd->sense, cmd->sense_valid_len);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_alloc_set_sense);

/**
 * scst_set_cmd_error_status() - set error SCSI status
 * @cmd:	SCST command
 * @status:	SCSI status to set
 *
 * Description:
 *    Sets error SCSI status in the command and prepares it for returning it.
 *    Returns 0 on success, error code otherwise.
 */
int scst_set_cmd_error_status(struct scst_cmd *cmd, int status)
{
	int res = 0;

	TRACE_ENTRY();

	if (status == SAM_STAT_RESERVATION_CONFLICT) {
		TRACE(TRACE_SCSI|TRACE_MINOR, "Reservation conflict (dev %s, "
			"initiator %s, tgt_id %d)",
			cmd->dev ? cmd->dev->virt_name : NULL,
			cmd->sess->initiator_name, cmd->tgt->rel_tgt_id);
	}

	if (cmd->status != 0) {
		TRACE_MGMT_DBG("cmd %p already has status %x set", cmd,
			cmd->status);
		res = -EEXIST;
		goto out;
	}

	cmd->status = status;
	cmd->host_status = DID_OK;

	cmd->dbl_ua_orig_resp_data_len = cmd->resp_data_len;
	cmd->dbl_ua_orig_data_direction = cmd->data_direction;

	cmd->data_direction = SCST_DATA_NONE;
	cmd->resp_data_len = 0;
	cmd->resid_possible = 1;
	cmd->is_send_status = 1;

	cmd->completed = 1;

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_set_cmd_error_status);

static int scst_set_lun_not_supported_request_sense(struct scst_cmd *cmd,
	int key, int asc, int ascq)
{
	int res;
	int sense_len, len;
	struct scatterlist *sg;

	TRACE_ENTRY();

	if (cmd->status != 0) {
		TRACE_MGMT_DBG("cmd %p already has status %x set", cmd,
			cmd->status);
		res = -EEXIST;
		goto out;
	}

	if ((cmd->sg != NULL) && scst_sense_valid(sg_virt(cmd->sg))) {
		TRACE_MGMT_DBG("cmd %p already has sense set", cmd);
		res = -EEXIST;
		goto out;
	}

	if (cmd->sg == NULL) {
		/*
		 * If target driver preparing data buffer using tgt_alloc_data_buf()
		 * callback, it is responsible to copy the sense to its buffer
		 * in xmit_response().
		 */
		if (cmd->tgt_i_data_buf_alloced && (cmd->tgt_i_sg != NULL)) {
			cmd->sg = cmd->tgt_i_sg;
			cmd->sg_cnt = cmd->tgt_i_sg_cnt;
			TRACE_MEM("Tgt sg used for sense for cmd %p", cmd);
			goto go;
		}

		if (cmd->bufflen == 0)
			cmd->bufflen = cmd->cdb[4];

		cmd->sg = scst_alloc_sg(cmd->bufflen, GFP_ATOMIC, &cmd->sg_cnt);
		if (cmd->sg == NULL) {
			PRINT_ERROR("Unable to alloc sg for REQUEST SENSE"
				"(sense %x/%x/%x)", key, asc, ascq);
			res = 1;
			goto out;
		}

		TRACE_MEM("sg %p alloced for sense for cmd %p (cnt %d, "
			"len %d)", cmd->sg, cmd, cmd->sg_cnt, cmd->bufflen);
	}

go:
	sg = cmd->sg;
	len = sg->length;

	TRACE_MEM("sg %p (len %d) for sense for cmd %p", sg, len, cmd);

	sense_len = scst_set_sense(sg_virt(sg), len, cmd->cdb[1] & 1,
			key, asc, ascq);

	TRACE_BUFFER("Sense set", sg_virt(sg), sense_len);

	cmd->data_direction = SCST_DATA_READ;
	scst_set_resp_data_len(cmd, sense_len);

	res = 0;
	cmd->completed = 1;
	cmd->resid_possible = 1;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_set_lun_not_supported_inquiry(struct scst_cmd *cmd)
{
	int res;
	uint8_t *buf;
	struct scatterlist *sg;
	int len;

	TRACE_ENTRY();

	if (cmd->status != 0) {
		TRACE_MGMT_DBG("cmd %p already has status %x set", cmd,
			cmd->status);
		res = -EEXIST;
		goto out;
	}

	if (cmd->sg == NULL) {
		if (cmd->bufflen == 0)
			cmd->bufflen = min_t(int, 36, get_unaligned_be16(&cmd->cdb[3]));

		/*
		 * If target driver preparing data buffer using tgt_alloc_data_buf()
		 * callback, it is responsible to copy the sense to its buffer
		 * in xmit_response().
		 */
		if (cmd->tgt_i_data_buf_alloced && (cmd->tgt_i_sg != NULL)) {
			cmd->sg = cmd->tgt_i_sg;
			cmd->sg_cnt = cmd->tgt_i_sg_cnt;
			TRACE_MEM("Tgt used for INQUIRY for not supported "
				"LUN for cmd %p", cmd);
			goto go;
		}

		cmd->sg = scst_alloc_sg(cmd->bufflen, GFP_ATOMIC, &cmd->sg_cnt);
		if (cmd->sg == NULL) {
			PRINT_ERROR("%s", "Unable to alloc sg for INQUIRY "
				"for not supported LUN");
			res = 1;
			goto out;
		}

		TRACE_MEM("sg %p alloced for INQUIRY for not supported LUN for "
			"cmd %p (cnt %d, len %d)", cmd->sg, cmd, cmd->sg_cnt,
			cmd->bufflen);
	}

go:
	sg = cmd->sg;
	len = sg->length;

	TRACE_MEM("sg %p (len %d) for INQUIRY for cmd %p", sg, len, cmd);

	buf = sg_virt(sg);
	len = min_t(int, 36, len);

	memset(buf, 0, len);
	buf[0] = 0x7F; /* Peripheral qualifier 011b, Peripheral device type 1Fh */
	buf[4] = len - 4;

	TRACE_BUFFER("INQUIRY for not supported LUN set", buf, len);

	cmd->data_direction = SCST_DATA_READ;
	scst_set_resp_data_len(cmd, len);

	res = 0;
	cmd->completed = 1;
	cmd->resid_possible = 1;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/**
 * scst_set_cmd_error() - set error in the command and fill the sense buffer.
 *
 * Sets error in the command and fill the sense buffer. Returns 0 on success,
 * error code otherwise.
 */
int scst_set_cmd_error(struct scst_cmd *cmd, int key, int asc, int ascq)
{
	int res;

	TRACE_ENTRY();

	/*
	 * We need for LOGICAL UNIT NOT SUPPORTED special handling for
	 * REQUEST SENSE and INQUIRY.
	 */
	if ((key == ILLEGAL_REQUEST) && (asc == 0x25) && (ascq == 0)) {
		if (cmd->cdb[0] == REQUEST_SENSE)
			res = scst_set_lun_not_supported_request_sense(cmd,
				key, asc, ascq);
		else if (cmd->cdb[0] == INQUIRY)
			res = scst_set_lun_not_supported_inquiry(cmd);
		else
			goto do_sense;

		if (res > 0)
			goto do_sense;
		else
			goto out;
	}

do_sense:
	res = scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);
	if (res != 0)
		goto out;

	res = scst_alloc_sense(cmd, 1);
	if (res != 0) {
		PRINT_ERROR("Lost sense data (key %x, asc %x, ascq %x)",
			key, asc, ascq);
		goto out;
	}

	cmd->sense_valid_len = scst_set_sense(cmd->sense, cmd->sense_buflen,
		scst_get_cmd_dev_d_sense(cmd), key, asc, ascq);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_set_cmd_error);

static void scst_fill_field_pointer_sense(uint8_t *fp_sense, int field_offs,
	int bit_offs, bool cdb)
{
	/* Sense key specific */
	fp_sense[0] = 0x80; /* SKSV */
	if (cdb)
		fp_sense[0] |= 0x40; /* C/D */
	if ((bit_offs & SCST_INVAL_FIELD_BIT_OFFS_VALID) != 0)
		fp_sense[0] |= (8 | (bit_offs & 7));
	put_unaligned_be16(field_offs, &fp_sense[1]);
	return;
}

static int scst_set_invalid_field_in(struct scst_cmd *cmd, int field_offs,
	int bit_offs, bool cdb)
{
	int res, asc = cdb ? 0x24 : 0x26; /* inval field in CDB or param list */
	int d_sense = scst_get_cmd_dev_d_sense(cmd);

	TRACE_ENTRY();

	TRACE_DBG("cmd %p, cdb %d, bit_offs %d, field_offs %d (d_sense %d)",
		cmd, cdb, bit_offs, field_offs, d_sense);

	res = scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);
	if (res != 0)
		goto out;

	res = scst_alloc_sense(cmd, 1);
	if (res != 0) {
		PRINT_ERROR("Lost %s sense data", cdb ? "INVALID FIELD IN CDB" :
			"INVALID FIELD IN PARAMETERS LIST");
		goto out;
	}

	sBUG_ON(cmd->sense_buflen < 18);
	BUILD_BUG_ON(SCST_SENSE_BUFFERSIZE < 18);

	if (d_sense) {
		/* Descriptor format */
		cmd->sense[0] = 0x72;
		cmd->sense[1] = ILLEGAL_REQUEST;
		cmd->sense[2] = asc;
		cmd->sense[3] = 0; /* ASCQ */
		cmd->sense[7] = 8; /* additional Sense Length */
		cmd->sense[8] = 2; /* sense key specific descriptor */
		cmd->sense[9] = 6;
		scst_fill_field_pointer_sense(&cmd->sense[12], field_offs,
			bit_offs, cdb);
		cmd->sense_valid_len = 16;
	} else {
		/* Fixed format */
		cmd->sense[0] = 0x70;
		cmd->sense[2] = ILLEGAL_REQUEST;
		cmd->sense[7] = 0x0a; /* additional Sense Length */
		cmd->sense[12] = asc;
		cmd->sense[13] = 0; /* ASCQ */
		scst_fill_field_pointer_sense(&cmd->sense[15], field_offs,
			bit_offs, cdb);
		cmd->sense_valid_len = 18;
	}

	TRACE_BUFFER("Sense set", cmd->sense, cmd->sense_valid_len);

out:
	TRACE_EXIT_RES(res);
	return res;
}

int scst_set_invalid_field_in_cdb(struct scst_cmd *cmd, int field_offs,
	int bit_offs)
{
	return scst_set_invalid_field_in(cmd, field_offs, bit_offs, true);
}
EXPORT_SYMBOL(scst_set_invalid_field_in_cdb);

int scst_set_invalid_field_in_parm_list(struct scst_cmd *cmd, int field_offs,
	int bit_offs)
{
	return scst_set_invalid_field_in(cmd, field_offs, bit_offs, false);
}
EXPORT_SYMBOL(scst_set_invalid_field_in_parm_list);

/**
 * scst_set_sense() - set sense from KEY/ASC/ASCQ numbers
 *
 * Sets the corresponding fields in the sense buffer taking sense type
 * into account. Returns resulting sense length.
 */
int scst_set_sense(uint8_t *buffer, int len, bool d_sense,
	int key, int asc, int ascq)
{
	int res;

	sBUG_ON(len == 0);

	memset(buffer, 0, len);

	/*
	 * The RESPONSE CODE field shall be set to 70h in all unit attention
	 * condition sense data in which:
	 * a) the ADDITIONAL SENSE CODE field is set to 29h; or
	 * b) the additional sense code is set to MODE PARAMETERS CHANGED.
	 */
	if ((key == UNIT_ATTENTION) &&
	      ((asc == 0x29) || ((asc == 0x2A) && (ascq == 1))))
		d_sense = false;

	if (d_sense) {
		/* Descriptor format */
		if (len < 8) {
			PRINT_ERROR("Length %d of sense buffer too small to "
				"fit sense %x:%x:%x", len, key, asc, ascq);
		}

		buffer[0] = 0x72;		/* Response Code	*/
		if (len > 1)
			buffer[1] = key;	/* Sense Key		*/
		if (len > 2)
			buffer[2] = asc;	/* ASC			*/
		if (len > 3)
			buffer[3] = ascq;	/* ASCQ			*/
		res = 8;
	} else {
		/* Fixed format */
		if (len < 18) {
			PRINT_ERROR("Length %d of sense buffer too small to "
				"fit sense %x:%x:%x", len, key, asc, ascq);
		}

		buffer[0] = 0x70;		/* Response Code	*/
		if (len > 2)
			buffer[2] = key;	/* Sense Key		*/
		if (len > 7)
			buffer[7] = 0x0a;	/* Additional Sense Length */
		if (len > 12)
			buffer[12] = asc;	/* ASC			*/
		if (len > 13)
			buffer[13] = ascq;	/* ASCQ			*/
		res = 18;
	}

	TRACE_BUFFER("Sense set", buffer, res);
	return res;
}
EXPORT_SYMBOL(scst_set_sense);

/**
 * scst_analyze_sense() - analyze sense
 *
 * Returns true if sense matches to (key, asc, ascq) and false otherwise.
 * Valid_mask is one or several SCST_SENSE_*_VALID constants setting valid
 * (key, asc, ascq) values.
 */
bool scst_analyze_sense(const uint8_t *sense, int len, unsigned int valid_mask,
	int key, int asc, int ascq)
{
	bool res = false;

	/* Response Code */
	if ((scst_sense_response_code(sense) == 0x70) ||
	    (scst_sense_response_code(sense) == 0x71)) {
		/* Fixed format */

		/* Sense Key */
		if (valid_mask & SCST_SENSE_KEY_VALID) {
			if (len < 3)
				goto out;
			if (sense[2] != key)
				goto out;
		}

		/* ASC */
		if (valid_mask & SCST_SENSE_ASC_VALID) {
			if (len < 13)
				goto out;
			if (sense[12] != asc)
				goto out;
		}

		/* ASCQ */
		if (valid_mask & SCST_SENSE_ASCQ_VALID) {
			if (len < 14)
				goto out;
			if (sense[13] != ascq)
				goto out;
		}
	} else if ((scst_sense_response_code(sense) == 0x72) ||
		   (scst_sense_response_code(sense) == 0x73)) {
		/* Descriptor format */

		/* Sense Key */
		if (valid_mask & SCST_SENSE_KEY_VALID) {
			if (len < 2)
				goto out;
			if (sense[1] != key)
				goto out;
		}

		/* ASC */
		if (valid_mask & SCST_SENSE_ASC_VALID) {
			if (len < 3)
				goto out;
			if (sense[2] != asc)
				goto out;
		}

		/* ASCQ */
		if (valid_mask & SCST_SENSE_ASCQ_VALID) {
			if (len < 4)
				goto out;
			if (sense[3] != ascq)
				goto out;
		}
	} else {
		PRINT_ERROR("Unknown sense response code 0x%x",
			scst_sense_response_code(sense));
		goto out;
	}

	res = true;

out:
	TRACE_EXIT_RES((int)res);
	return res;
}
EXPORT_SYMBOL(scst_analyze_sense);

/**
 * scst_is_ua_sense() - determine if the sense is UA sense
 *
 * Returns true if the sense is valid and carrying a Unit
 * Attention or false otherwise.
 */
bool scst_is_ua_sense(const uint8_t *sense, int len)
{
	if (scst_sense_valid(sense))
		return scst_analyze_sense(sense, len,
			SCST_SENSE_KEY_VALID, UNIT_ATTENTION, 0, 0);
	else
		return false;
}
EXPORT_SYMBOL(scst_is_ua_sense);

bool scst_is_ua_global(const uint8_t *sense, int len)
{
	bool res;

	/* Changing it don't forget to change scst_requeue_ua() as well!! */

	if (scst_analyze_sense(sense, len, SCST_SENSE_ALL_VALID,
			SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed)))
		res = true;
	else
		res = false;

	return res;
}

/**
 * scst_check_convert_sense() - check sense type and convert it if needed
 *
 * Checks if sense in the sense buffer, if any, is in the correct format.
 * If not, converts it in the correct format.
 *
 * WARNING! This function converts only RESPONSE CODE, ASC and ASC codes,
 * dropping enverything else, including corresponding descriptors from
 * descriptor format sense! ToDo: fix it.
 */
void scst_check_convert_sense(struct scst_cmd *cmd)
{
	bool d_sense;

	TRACE_ENTRY();

	if ((cmd->sense == NULL) || (cmd->status != SAM_STAT_CHECK_CONDITION))
		goto out;

	d_sense = scst_get_cmd_dev_d_sense(cmd);
	if (d_sense && ((scst_sense_response_code(cmd->sense) == 0x70) ||
			(scst_sense_response_code(cmd->sense) == 0x71)) &&
	    /*
	     * The RESPONSE CODE field shall be set to 70h in all unit attention
	     * condition sense data in which:
	     * a) the ADDITIONAL SENSE CODE field is set to 29h; or
	     * b) the additional sense code is set to MODE PARAMETERS CHANGED.
	     */
	    !((cmd->sense[2] == UNIT_ATTENTION) &&
	      ((cmd->sense[12] == 0x29) ||
	       ((cmd->sense[12] == 0x2A) && (cmd->sense[13] == 1))))) {
		TRACE_MGMT_DBG("Converting fixed sense to descriptor (cmd %p)", cmd);
		if ((cmd->sense_valid_len < 18)) {
			PRINT_ERROR("Sense too small to convert (%d, "
				"type: fixed)", cmd->sense_buflen);
			goto out;
		}
		cmd->sense_valid_len = scst_set_sense(cmd->sense, cmd->sense_buflen,
			d_sense, cmd->sense[2], cmd->sense[12], cmd->sense[13]);
	} else if (!d_sense && ((scst_sense_response_code(cmd->sense) == 0x72) ||
				(scst_sense_response_code(cmd->sense) == 0x73))) {
		TRACE_MGMT_DBG("Converting descriptor sense to fixed (cmd %p)",
			cmd);
		if ((cmd->sense_buflen < 18) || (cmd->sense_valid_len < 8)) {
			PRINT_ERROR("Sense too small to convert (%d, "
				"type: descriptor, valid %d)",
				cmd->sense_buflen, cmd->sense_valid_len);
			goto out;
		}
		cmd->sense_valid_len = scst_set_sense(cmd->sense,
			cmd->sense_buflen, d_sense,
			cmd->sense[1], cmd->sense[2], cmd->sense[3]);
	}

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_check_convert_sense);

int scst_set_cmd_error_sense(struct scst_cmd *cmd, uint8_t *sense,
	unsigned int len)
{
	int res;

	TRACE_ENTRY();

	res = scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);
	if (res != 0)
		goto out;

	res = scst_alloc_set_sense(cmd, 1, sense, len);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/**
 * scst_set_busy() - set BUSY or TASK QUEUE FULL status
 *
 * Sets BUSY or TASK QUEUE FULL status depending on if this session has other
 * outstanding commands or not.
 */
void scst_set_busy(struct scst_cmd *cmd)
{
	int c = atomic_read(&cmd->sess->sess_cmd_count);

	TRACE_ENTRY();

	if ((c <= 1) || (cmd->sess->init_phase != SCST_SESS_IPH_READY))	{
		scst_set_cmd_error_status(cmd, SAM_STAT_BUSY);
		TRACE(TRACE_FLOW_CONTROL, "Sending BUSY status to initiator %s "
			"(cmds count %d, queue_type %x, sess->init_phase %d)",
			cmd->sess->initiator_name, c,
			cmd->queue_type, cmd->sess->init_phase);
	} else {
		scst_set_cmd_error_status(cmd, SAM_STAT_TASK_SET_FULL);
		TRACE(TRACE_FLOW_CONTROL, "Sending QUEUE_FULL status to "
			"initiator %s (cmds count %d, queue_type %x, "
			"sess->init_phase %d)", cmd->sess->initiator_name, c,
			cmd->queue_type, cmd->sess->init_phase);
	}

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_busy);

/**
 * scst_set_initial_UA() - set initial Unit Attention
 *
 * Sets initial Unit Attention on all devices of the session,
 * replacing default scst_sense_reset_UA
 */
void scst_set_initial_UA(struct scst_session *sess, int key, int asc, int ascq)
{
	int i;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Setting for sess %p initial UA %x/%x/%x", sess, key,
		asc, ascq);

	/* To protect sess_tgt_dev_list */
	mutex_lock(&scst_mutex);

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &sess->sess_tgt_dev_list[i];
		struct scst_tgt_dev *tgt_dev;

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			spin_lock_bh(&tgt_dev->tgt_dev_lock);
			if (!list_empty(&tgt_dev->UA_list)) {
				struct scst_tgt_dev_UA *ua;

				ua = list_first_entry(&tgt_dev->UA_list,
					typeof(*ua), UA_list_entry);
				if (scst_analyze_sense(ua->UA_sense_buffer,
						ua->UA_valid_sense_len,
						SCST_SENSE_ALL_VALID,
						SCST_LOAD_SENSE(scst_sense_reset_UA))) {
					ua->UA_valid_sense_len = scst_set_sense(
						ua->UA_sense_buffer,
						sizeof(ua->UA_sense_buffer),
						tgt_dev->dev->d_sense,
						key, asc, ascq);
				} else
					PRINT_ERROR("%s",
						"The first UA isn't RESET UA");
			} else
				PRINT_ERROR("%s", "There's no RESET UA to "
					"replace");
			spin_unlock_bh(&tgt_dev->tgt_dev_lock);
		}
	}

	mutex_unlock(&scst_mutex);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_initial_UA);

struct scst_aen *scst_alloc_aen(struct scst_session *sess,
	uint64_t unpacked_lun)
{
	struct scst_aen *aen;

	TRACE_ENTRY();

	aen = mempool_alloc(scst_aen_mempool, GFP_KERNEL);
	if (aen == NULL) {
		PRINT_ERROR("AEN memory allocation failed. Corresponding "
			"event notification will not be performed (initiator "
			"%s)", sess->initiator_name);
		goto out;
	}
	memset(aen, 0, sizeof(*aen));

	aen->sess = sess;
	scst_sess_get(sess);

	aen->lun = scst_pack_lun(unpacked_lun, sess->acg->addr_method);

out:
	TRACE_EXIT_HRES((unsigned long)aen);
	return aen;
}

void scst_free_aen(struct scst_aen *aen)
{
	TRACE_ENTRY();

	scst_sess_put(aen->sess);
	mempool_free(aen, scst_aen_mempool);

	TRACE_EXIT();
	return;
}

/* Must be called under scst_mutex */
void scst_gen_aen_or_ua(struct scst_tgt_dev *tgt_dev,
	int key, int asc, int ascq)
{
	struct scst_tgt_template *tgtt = tgt_dev->sess->tgt->tgtt;
	uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
	int sl;

	TRACE_ENTRY();

	if ((tgt_dev->sess->init_phase != SCST_SESS_IPH_READY) ||
	    (tgt_dev->sess->shut_phase != SCST_SESS_SPH_READY))
		goto out;

	if (tgtt->report_aen != NULL) {
		struct scst_aen *aen;
		int rc;

		aen = scst_alloc_aen(tgt_dev->sess, tgt_dev->lun);
		if (aen == NULL)
			goto queue_ua;

		aen->event_fn = SCST_AEN_SCSI;
		aen->aen_sense_len = scst_set_sense(aen->aen_sense,
			sizeof(aen->aen_sense), tgt_dev->dev->d_sense,
			key, asc, ascq);

		TRACE_DBG("Calling target's %s report_aen(%p)",
			tgtt->name, aen);
		rc = tgtt->report_aen(aen);
		TRACE_DBG("Target's %s report_aen(%p) returned %d",
			tgtt->name, aen, rc);
		if (rc == SCST_AEN_RES_SUCCESS)
			goto out;

		scst_free_aen(aen);
	}

queue_ua:
	TRACE_MGMT_DBG("AEN not supported, queueing plain UA (tgt_dev %p)",
		tgt_dev);
	sl = scst_set_sense(sense_buffer, sizeof(sense_buffer),
		tgt_dev->dev->d_sense, key, asc, ascq);
	scst_check_set_UA(tgt_dev, sense_buffer, sl, 0);

out:
	TRACE_EXIT();
	return;
}

/**
 * scst_capacity_data_changed() - notify SCST about device capacity change
 *
 * Notifies SCST core that dev has changed its capacity. Called under no locks.
 */
void scst_capacity_data_changed(struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	if (dev->type != TYPE_DISK) {
		TRACE_MGMT_DBG("Device type %d isn't for CAPACITY DATA "
			"CHANGED UA", dev->type);
		goto out;
	}

	TRACE_MGMT_DBG("CAPACITY DATA CHANGED (dev %p)", dev);

	mutex_lock(&scst_mutex);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			    dev_tgt_dev_list_entry) {
		scst_gen_aen_or_ua(tgt_dev,
			SCST_LOAD_SENSE(scst_sense_capacity_data_changed));
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_capacity_data_changed);

static inline bool scst_is_report_luns_changed_type(int type)
{
	switch (type) {
	case TYPE_DISK:
	case TYPE_TAPE:
	case TYPE_PRINTER:
	case TYPE_PROCESSOR:
	case TYPE_WORM:
	case TYPE_ROM:
	case TYPE_SCANNER:
	case TYPE_MOD:
	case TYPE_MEDIUM_CHANGER:
	case TYPE_RAID:
	case TYPE_ENCLOSURE:
		return true;
	default:
		return false;
	}
}

/* scst_mutex supposed to be held */
static void scst_queue_report_luns_changed_UA(struct scst_session *sess,
					      int flags)
{
	uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
	struct list_head *head;
	struct scst_tgt_dev *tgt_dev;
	int i;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Queueing REPORTED LUNS DATA CHANGED UA "
		"(sess %p)", sess);

	local_bh_disable();

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		head = &sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head,
				sess_tgt_dev_list_entry) {
			/* Lockdep triggers here a false positive.. */
			spin_lock(&tgt_dev->tgt_dev_lock);
		}
	}

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		head = &sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			int sl;

			if (!scst_is_report_luns_changed_type(
					tgt_dev->dev->type))
				continue;

			sl = scst_set_sense(sense_buffer, sizeof(sense_buffer),
				tgt_dev->dev->d_sense,
				SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed));

			__scst_check_set_UA(tgt_dev, sense_buffer,
				sl, flags | SCST_SET_UA_FLAG_GLOBAL);
		}
	}

	for (i = SESS_TGT_DEV_LIST_HASH_SIZE-1; i >= 0; i--) {
		head = &sess->sess_tgt_dev_list[i];

		list_for_each_entry_reverse(tgt_dev, head,
						sess_tgt_dev_list_entry) {
			spin_unlock(&tgt_dev->tgt_dev_lock);
		}
	}

	local_bh_enable();

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
static void scst_report_luns_changed_sess(struct scst_session *sess)
{
	int i;
	struct scst_tgt_template *tgtt = sess->tgt->tgtt;
	int d_sense = 0;
	uint64_t lun = 0;

	TRACE_ENTRY();

	if ((sess->init_phase != SCST_SESS_IPH_READY) ||
	    (sess->shut_phase != SCST_SESS_SPH_READY))
		goto out;

	TRACE_DBG("REPORTED LUNS DATA CHANGED (sess %p)", sess);

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head;
		struct scst_tgt_dev *tgt_dev;

		head = &sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head,
				sess_tgt_dev_list_entry) {
			if (scst_is_report_luns_changed_type(
					tgt_dev->dev->type)) {
				lun = tgt_dev->lun;
				d_sense = tgt_dev->dev->d_sense;
				goto found;
			}
		}
	}

found:
	if (tgtt->report_aen != NULL) {
		struct scst_aen *aen;
		int rc;

		aen = scst_alloc_aen(sess, lun);
		if (aen == NULL)
			goto queue_ua;

		aen->event_fn = SCST_AEN_SCSI;
		aen->aen_sense_len = scst_set_sense(aen->aen_sense,
			sizeof(aen->aen_sense), d_sense,
			SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed));

		TRACE_DBG("Calling target's %s report_aen(%p)",
			tgtt->name, aen);
		rc = tgtt->report_aen(aen);
		TRACE_DBG("Target's %s report_aen(%p) returned %d",
			tgtt->name, aen, rc);
		if (rc == SCST_AEN_RES_SUCCESS)
			goto out;

		scst_free_aen(aen);
	}

queue_ua:
	scst_queue_report_luns_changed_UA(sess, 0);

out:
	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
void scst_report_luns_changed(struct scst_acg *acg)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	TRACE_DBG("REPORTED LUNS DATA CHANGED (acg %s)", acg->acg_name);

	list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) {
		scst_report_luns_changed_sess(sess);
	}

	TRACE_EXIT();
	return;
}

/**
 * scst_aen_done() - AEN processing done
 *
 * Notifies SCST that the driver has sent the AEN and it
 * can be freed now. Don't forget to set the delivery status, if it
 * isn't success, using scst_set_aen_delivery_status() before calling
 * this function.
 */
void scst_aen_done(struct scst_aen *aen)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("AEN %p (fn %d) done (initiator %s)", aen,
		aen->event_fn, aen->sess->initiator_name);

	if (aen->delivery_status == SCST_AEN_RES_SUCCESS)
		goto out_free;

	if (aen->event_fn != SCST_AEN_SCSI)
		goto out_free;

	TRACE_MGMT_DBG("Delivery of SCSI AEN failed (initiator %s)",
		aen->sess->initiator_name);

	if (scst_analyze_sense(aen->aen_sense, aen->aen_sense_len,
			SCST_SENSE_ALL_VALID, SCST_LOAD_SENSE(
				scst_sense_reported_luns_data_changed))) {
		mutex_lock(&scst_mutex);
		scst_queue_report_luns_changed_UA(aen->sess,
			SCST_SET_UA_FLAG_AT_HEAD);
		mutex_unlock(&scst_mutex);
	} else {
		struct list_head *head;
		struct scst_tgt_dev *tgt_dev;
		uint64_t lun;

		lun = scst_unpack_lun((uint8_t *)&aen->lun, sizeof(aen->lun));

		mutex_lock(&scst_mutex);

		/* tgt_dev might get dead, so we need to reseek it */
		head = &aen->sess->sess_tgt_dev_list[SESS_TGT_DEV_LIST_HASH_FN(lun)];
		list_for_each_entry(tgt_dev, head,
				sess_tgt_dev_list_entry) {
			if (tgt_dev->lun == lun) {
				TRACE_MGMT_DBG("Requeuing failed AEN UA for "
					"tgt_dev %p", tgt_dev);
				scst_check_set_UA(tgt_dev, aen->aen_sense,
					aen->aen_sense_len,
					SCST_SET_UA_FLAG_AT_HEAD);
				break;
			}
		}

		mutex_unlock(&scst_mutex);
	}

out_free:
	scst_free_aen(aen);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_aen_done);

void scst_requeue_ua(struct scst_cmd *cmd, const uint8_t *buf, int size)
{
	TRACE_ENTRY();

	if (buf == NULL) {
		buf = cmd->sense;
		size = cmd->sense_valid_len;
	}

	if (scst_analyze_sense(buf, size, SCST_SENSE_ALL_VALID,
			SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed))) {
		TRACE_MGMT_DBG("Requeuing REPORTED LUNS DATA CHANGED UA "
			"for delivery failed cmd %p", cmd);
		mutex_lock(&scst_mutex);
		scst_queue_report_luns_changed_UA(cmd->sess,
			SCST_SET_UA_FLAG_AT_HEAD);
		mutex_unlock(&scst_mutex);
	} else {
		TRACE_MGMT_DBG("Requeuing UA for delivery failed cmd %p", cmd);
		scst_check_set_UA(cmd->tgt_dev, buf, size, SCST_SET_UA_FLAG_AT_HEAD);
	}

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
static void scst_check_reassign_sess(struct scst_session *sess)
{
	struct scst_acg *acg, *old_acg;
	struct scst_acg_dev *acg_dev;
	int i, rc;
	struct list_head *head;
	struct scst_tgt_dev *tgt_dev;
	bool luns_changed = false;
	bool add_failed, something_freed;

	TRACE_ENTRY();

	if (sess->shut_phase != SCST_SESS_SPH_READY)
		goto out;

	TRACE_DBG("Checking reassignment for sess %p (initiator %s)",
		sess, sess->initiator_name);

	acg = scst_find_acg(sess);
	if (acg == sess->acg) {
		TRACE_DBG("No reassignment for sess %p", sess);
		goto out;
	}

	PRINT_INFO("sess %p (initiator %s) will be reassigned from acg %s to "
		"acg %s", sess, sess->initiator_name, sess->acg->acg_name,
		acg->acg_name);

	old_acg = sess->acg;
	sess->acg = NULL; /* to catch implicit dependencies earlier */

retry_add:
	add_failed = false;
	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		bool inq_changed_ua_needed = false;

		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			head = &sess->sess_tgt_dev_list[i];

			list_for_each_entry(tgt_dev, head,
					sess_tgt_dev_list_entry) {
				if ((tgt_dev->dev == acg_dev->dev) &&
				    (tgt_dev->lun == acg_dev->lun) &&
				    (tgt_dev->acg_dev->acg_dev_rd_only == acg_dev->acg_dev_rd_only)) {
					TRACE_MGMT_DBG("sess %p: tgt_dev %p for "
						"LUN %lld stays the same",
						sess, tgt_dev,
						(unsigned long long)tgt_dev->lun);
					tgt_dev->acg_dev = acg_dev;
					goto next;
				} else if (tgt_dev->lun == acg_dev->lun) {
					TRACE_MGMT_DBG("Replacing LUN %lld",
						(long long)tgt_dev->lun);
					scst_free_tgt_dev(tgt_dev);
					inq_changed_ua_needed = 1;
					break;
				}
			}
		}

		luns_changed = true;

		TRACE_MGMT_DBG("sess %p: Allocing new tgt_dev for LUN %lld",
			sess, (unsigned long long)acg_dev->lun);

		rc = scst_alloc_add_tgt_dev(sess, acg_dev, &tgt_dev);
		if (rc == -EPERM)
			continue;
		else if (rc != 0) {
			add_failed = true;
			break;
		}

		tgt_dev->inq_changed_ua_needed = inq_changed_ua_needed;
next:
		continue;
	}

	something_freed = false;
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct scst_tgt_dev *t;
		head = &sess->sess_tgt_dev_list[i];

		list_for_each_entry_safe(tgt_dev, t, head,
					sess_tgt_dev_list_entry) {
			if (tgt_dev->acg_dev->acg != acg) {
				TRACE_MGMT_DBG("sess %p: Deleting not used "
					"tgt_dev %p for LUN %lld",
					sess, tgt_dev,
					(unsigned long long)tgt_dev->lun);
				luns_changed = true;
				something_freed = true;
				scst_free_tgt_dev(tgt_dev);
			}
		}
	}

	if (add_failed && something_freed) {
		TRACE_MGMT_DBG("sess %p: Retrying adding new tgt_devs", sess);
		goto retry_add;
	}

	sess->acg = acg;

	TRACE_DBG("Moving sess %p from acg %s to acg %s", sess,
		old_acg->acg_name, acg->acg_name);
	list_move_tail(&sess->acg_sess_list_entry, &acg->acg_sess_list);

#ifndef CONFIG_SCST_PROC
	scst_recreate_sess_luns_link(sess);
	/* Ignore possible error, since we can't do anything on it */
#endif

	if (luns_changed) {
		scst_report_luns_changed_sess(sess);

		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			head = &sess->sess_tgt_dev_list[i];

			list_for_each_entry(tgt_dev, head,
					sess_tgt_dev_list_entry) {
				if (tgt_dev->inq_changed_ua_needed) {
					TRACE_MGMT_DBG("sess %p: Setting "
						"INQUIRY DATA HAS CHANGED UA "
						"(tgt_dev %p)", sess, tgt_dev);

					tgt_dev->inq_changed_ua_needed = 0;

					scst_gen_aen_or_ua(tgt_dev,
						SCST_LOAD_SENSE(scst_sense_inquiry_data_changed));
				}
			}
		}
	}

out:
	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
void scst_check_reassign_sessions(void)
{
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	list_for_each_entry(tgtt, &scst_template_list, scst_template_list_entry) {
		struct scst_tgt *tgt;
		list_for_each_entry(tgt, &tgtt->tgt_list, tgt_list_entry) {
			struct scst_session *sess;
			list_for_each_entry(sess, &tgt->sess_list,
						sess_list_entry) {
				scst_check_reassign_sess(sess);
			}
		}
	}

	TRACE_EXIT();
	return;
}

int scst_get_cmd_abnormal_done_state(const struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	switch (cmd->state) {
	case SCST_CMD_STATE_INIT_WAIT:
	case SCST_CMD_STATE_INIT:
	case SCST_CMD_STATE_PARSE:
		if (cmd->preprocessing_only) {
			res = SCST_CMD_STATE_PREPROCESSING_DONE;
			break;
		} /* else go through */
	case SCST_CMD_STATE_DEV_DONE:
		if (cmd->internal)
			res = SCST_CMD_STATE_FINISHED_INTERNAL;
		else
			res = SCST_CMD_STATE_PRE_XMIT_RESP;
		break;

	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_MODE_SELECT_CHECKS:
		res = SCST_CMD_STATE_DEV_DONE;
		break;

	case SCST_CMD_STATE_PRE_XMIT_RESP:
		res = SCST_CMD_STATE_XMIT_RESP;
		break;

	case SCST_CMD_STATE_PREPROCESSING_DONE:
	case SCST_CMD_STATE_PREPROCESSING_DONE_CALLED:
		if (cmd->tgt_dev == NULL)
			res = SCST_CMD_STATE_PRE_XMIT_RESP;
		else
			res = SCST_CMD_STATE_PRE_DEV_DONE;
		break;

	case SCST_CMD_STATE_PREPARE_SPACE:
		if (cmd->preprocessing_only) {
			res = SCST_CMD_STATE_PREPROCESSING_DONE;
			break;
		} /* else go through */
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_DATA_WAIT:
	case SCST_CMD_STATE_TGT_PRE_EXEC:
	case SCST_CMD_STATE_EXEC_CHECK_BLOCKING:
	case SCST_CMD_STATE_EXEC_CHECK_SN:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_EXEC_WAIT:
		res = SCST_CMD_STATE_PRE_DEV_DONE;
		break;

	default:
		PRINT_CRIT_ERROR("Wrong cmd state %d (cmd %p, op %x)",
			cmd->state, cmd, cmd->cdb[0]);
		sBUG();
		/* Invalid state to suppress a compiler warning */
		res = SCST_CMD_STATE_LAST_ACTIVE;
	}

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_get_cmd_abnormal_done_state);

/**
 * scst_set_cmd_abnormal_done_state() - set command's next abnormal done state
 *
 * Sets state of the SCSI target state machine to abnormally complete command
 * ASAP.
 */
void scst_set_cmd_abnormal_done_state(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	switch (cmd->state) {
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
	case SCST_CMD_STATE_FINISHED_INTERNAL:
	case SCST_CMD_STATE_XMIT_WAIT:
		PRINT_CRIT_ERROR("Wrong cmd state %d (cmd %p, op %x)",
			cmd->state, cmd, cmd->cdb[0]);
		sBUG();
	}
#endif

	cmd->state = scst_get_cmd_abnormal_done_state(cmd);

	switch (cmd->state) {
	case SCST_CMD_STATE_INIT_WAIT:
	case SCST_CMD_STATE_INIT:
	case SCST_CMD_STATE_PARSE:
	case SCST_CMD_STATE_PREPROCESSING_DONE:
	case SCST_CMD_STATE_PREPROCESSING_DONE_CALLED:
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_DATA_WAIT:
		cmd->write_len = 0;
		cmd->resid_possible = 1;
		break;
	case SCST_CMD_STATE_TGT_PRE_EXEC:
	case SCST_CMD_STATE_EXEC_CHECK_SN:
	case SCST_CMD_STATE_EXEC_CHECK_BLOCKING:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_EXEC_WAIT:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_MODE_SELECT_CHECKS:
	case SCST_CMD_STATE_PRE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED_INTERNAL:
		break;
	default:
		PRINT_CRIT_ERROR("Wrong cmd state %d (cmd %p, op %x)",
			cmd->state, cmd, cmd->cdb[0]);
		sBUG();
		break;
	}

#ifdef CONFIG_SCST_EXTRACHECKS
	if (((cmd->state != SCST_CMD_STATE_PRE_XMIT_RESP) &&
	     (cmd->state != SCST_CMD_STATE_PREPROCESSING_DONE)) &&
		   (cmd->tgt_dev == NULL) && !cmd->internal) {
		PRINT_CRIT_ERROR("Wrong not inited cmd state %d (cmd %p, "
			"op %x)", cmd->state, cmd, cmd->cdb[0]);
		sBUG();
	}
#endif

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_set_cmd_abnormal_done_state);

void scst_zero_write_rest(struct scst_cmd *cmd)
{
	int len, offs = 0;
	uint8_t *buf;

	TRACE_ENTRY();

	len = scst_get_sg_buf_first(cmd, &buf, *cmd->write_sg,
			*cmd->write_sg_cnt);
	while (len > 0) {
		int cur_offs;

		if (offs + len <= cmd->write_len)
			goto next;
		else if (offs >= cmd->write_len)
			cur_offs = 0;
		else
			cur_offs = cmd->write_len - offs;

		memset(&buf[cur_offs], 0, len - cur_offs);

next:
		offs += len;
		scst_put_sg_buf(cmd, buf, *cmd->write_sg, *cmd->write_sg_cnt);
		len = scst_get_sg_buf_next(cmd, &buf, *cmd->write_sg,
					*cmd->write_sg_cnt);
	}

	TRACE_EXIT();
	return;
}

static void scst_adjust_sg(struct scst_cmd *cmd, struct scatterlist *sg,
	int *sg_cnt, int adjust_len)
{
	struct scatterlist *sgi;
	int i, l;

	TRACE_ENTRY();

	l = 0;
	for_each_sg(sg, sgi, *sg_cnt, i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
		TRACE_DBG("i %d, sg_cnt %d, sg %p, page_link %lx", i,
			*sg_cnt, sg, sgi->page_link);
#else
		TRACE_DBG("i %d, sg_cnt %d, sg %p, page_link %lx", i,
			*sg_cnt, sg, 0UL);
#endif
		l += sgi->length;
		if (l >= adjust_len) {
			int left = adjust_len - (l - sgi->length);
#ifdef CONFIG_SCST_DEBUG
			TRACE(TRACE_SG_OP|TRACE_MEMORY, "cmd %p (tag %llu), "
				"sg %p, sg_cnt %d, adjust_len %d, i %d, "
				"sg[j].length %d, left %d",
				cmd, (long long unsigned int)cmd->tag,
				sg, *sg_cnt, adjust_len, i,
				sgi->length, left);
#endif
			cmd->p_orig_sg_cnt = sg_cnt;
			cmd->orig_sg_cnt = *sg_cnt;
			cmd->orig_sg_entry = sgi;
			cmd->orig_entry_offs = sgi->offset;
			cmd->orig_entry_len = sgi->length;
			*sg_cnt = (left > 0) ? i+1 : i;
			sgi->length = left;
			cmd->sg_buff_modified = 1;
			break;
		}
	}

	TRACE_EXIT();
	return;
}

/**
 * scst_restore_sg_buff() - restores modified sg buffer
 *
 * Restores modified sg buffer in the original state.
 */
void scst_restore_sg_buff(struct scst_cmd *cmd)
{
	TRACE_MEM("cmd %p, sg %p, orig_sg_entry %p, orig_entry_offs %d, "
		"orig_entry_len %d, orig_sg_cnt %d", cmd, cmd->sg,
		cmd->orig_sg_entry, cmd->orig_entry_offs, cmd->orig_entry_len,
		cmd->orig_sg_cnt);
	cmd->orig_sg_entry->offset = cmd->orig_entry_offs;
	cmd->orig_sg_entry->length = cmd->orig_entry_len;
	*cmd->p_orig_sg_cnt = cmd->orig_sg_cnt;
	cmd->sg_buff_modified = 0;
}
EXPORT_SYMBOL(scst_restore_sg_buff);

/**
 * scst_set_resp_data_len() - set response data length
 *
 * Sets response data length for cmd and truncates its SG vector accordingly.
 *
 * The cmd->resp_data_len must not be set directly, it must be set only
 * using this function. Value of resp_data_len must be <= cmd->bufflen.
 */
void scst_set_resp_data_len(struct scst_cmd *cmd, int resp_data_len)
{
	TRACE_ENTRY();

	scst_check_restore_sg_buff(cmd);
	cmd->resp_data_len = resp_data_len;

	if (resp_data_len == cmd->bufflen)
		goto out;

	TRACE_DBG("cmd %p, resp_data_len %d", cmd, resp_data_len);

	if (unlikely(resp_data_len > cmd->bufflen)) {
		PRINT_ERROR("Too big response data len %d (max %d), limiting "
			"it to the max (dev %s)", resp_data_len, cmd->bufflen,
			cmd->dev ? cmd->dev->virt_name : "(no LUN)");
		/*
		 * It's a bug in the lower level code, so dump stack to know
		 * who is the cause
		 */
		dump_stack();
		cmd->resp_data_len = cmd->bufflen;
		goto out;
	}

	scst_adjust_sg(cmd, cmd->sg, &cmd->sg_cnt, resp_data_len);

	cmd->resid_possible = 1;

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_set_resp_data_len);

void scst_limit_sg_write_len(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	TRACE_MEM("Limiting sg write len to %d (cmd %p, sg %p, sg_cnt %d)",
		cmd->write_len, cmd, *cmd->write_sg, *cmd->write_sg_cnt);

	scst_check_restore_sg_buff(cmd);
	scst_adjust_sg(cmd, *cmd->write_sg, cmd->write_sg_cnt, cmd->write_len);

	TRACE_EXIT();
	return;
}

void scst_adjust_resp_data_len(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (!cmd->expected_values_set) {
		cmd->adjusted_resp_data_len = cmd->resp_data_len;
		goto out;
	}

	cmd->adjusted_resp_data_len = min(cmd->resp_data_len,
					cmd->expected_transfer_len);

	if (cmd->adjusted_resp_data_len != cmd->resp_data_len) {
		TRACE_MEM("Adjusting resp_data_len to %d (cmd %p, sg %p, "
			"sg_cnt %d)", cmd->adjusted_resp_data_len, cmd, cmd->sg,
			cmd->sg_cnt);
		scst_check_restore_sg_buff(cmd);
		scst_adjust_sg(cmd, cmd->sg, &cmd->sg_cnt,
				cmd->adjusted_resp_data_len);
	}

out:
	TRACE_EXIT();
	return;
}

/**
 * scst_cmd_set_write_not_received_data_len() - sets cmd's not received len
 *
 * Sets cmd's not received data length. Also automatically sets resid_possible.
 */
void scst_cmd_set_write_not_received_data_len(struct scst_cmd *cmd,
	int not_received)
{
	TRACE_ENTRY();

	cmd->write_not_received_set = 1;

	if (!cmd->expected_values_set) {
		/*
		 * No expected values set, so no residuals processing.
		 * It can happen if a command preliminary completed before
		 * target driver had a chance to set expected values.
		 */
		TRACE_MGMT_DBG("No expected values set, ignoring (cmd %p)", cmd);
		goto out;
	}

	cmd->resid_possible = 1;

	if ((cmd->expected_data_direction & SCST_DATA_READ) &&
	    (cmd->expected_data_direction & SCST_DATA_WRITE)) {
		cmd->write_len = cmd->expected_out_transfer_len - not_received;
		if (cmd->write_len == cmd->out_bufflen)
			goto out;
	} else if (cmd->expected_data_direction & SCST_DATA_WRITE) {
		cmd->write_len = cmd->expected_transfer_len - not_received;
		if (cmd->write_len == cmd->bufflen)
			goto out;
	}

	/*
	 * Write len now can be bigger cmd->(out_)bufflen, but that's OK,
	 * because it will be used to only calculate write residuals.
	 */

	TRACE_DBG("cmd %p, not_received %d, write_len %d", cmd, not_received,
		cmd->write_len);

	if (cmd->data_direction & SCST_DATA_WRITE)
		scst_limit_sg_write_len(cmd);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_cmd_set_write_not_received_data_len);

void scst_cmd_set_write_no_data_received(struct scst_cmd *cmd)
{
	int w;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->expected_values_set &&
		((cmd->expected_data_direction & SCST_DATA_WRITE) == 0));

	if ((cmd->expected_data_direction & SCST_DATA_READ) &&
	    (cmd->expected_data_direction & SCST_DATA_WRITE))
		w = cmd->expected_out_transfer_len;
	else
		w = cmd->expected_transfer_len;

	scst_cmd_set_write_not_received_data_len(cmd, w);

	TRACE_EXIT();
	return;
}

/**
 * __scst_get_resid() - returns residuals for cmd
 *
 * Returns residuals for command. Must not be called directly, use
 * scst_get_resid() instead.
 */
bool __scst_get_resid(struct scst_cmd *cmd, int *resid, int *bidi_out_resid)
{
	bool res;

	TRACE_ENTRY();

	*resid = 0;
	if (bidi_out_resid != NULL)
		*bidi_out_resid = 0;

	if (!cmd->expected_values_set) {
		/*
		 * No expected values set, so no residuals processing.
		 * It can happen if a command preliminary completed before
		 * target driver had a chance to set expected values.
		 */
		TRACE_MGMT_DBG("No expected values set, returning no residual "
			"(cmd %p)", cmd);
		res = false;
		goto out;
	}

	if (cmd->expected_data_direction & SCST_DATA_READ) {
		*resid = cmd->expected_transfer_len - cmd->resp_data_len;
		if ((cmd->expected_data_direction & SCST_DATA_WRITE) && bidi_out_resid) {
			if (cmd->write_len < cmd->expected_out_transfer_len)
				*bidi_out_resid = cmd->expected_out_transfer_len -
							cmd->write_len;
			else
				*bidi_out_resid = cmd->write_len - cmd->out_bufflen;
		}
	} else if (cmd->expected_data_direction & SCST_DATA_WRITE) {
		if (cmd->write_len < cmd->expected_transfer_len)
			*resid = cmd->expected_transfer_len - cmd->write_len;
		else
			*resid = cmd->write_len - cmd->bufflen;
	}

	res = true;

	TRACE_DBG("cmd %p, resid %d, bidi_out_resid %d (resp_data_len %d, "
		"expected_data_direction %d, write_len %d, bufflen %d)", cmd,
		*resid, bidi_out_resid ? *bidi_out_resid : 0, cmd->resp_data_len,
		cmd->expected_data_direction, cmd->write_len, cmd->bufflen);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(__scst_get_resid);

/* No locks */
void scst_queue_retry_cmd(struct scst_cmd *cmd)
{
	struct scst_tgt *tgt = cmd->tgt;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&tgt->tgt_lock, flags);

	tgt->retry_cmds++;

	TRACE_RETRY("Adding cmd %p to retry cmd list", cmd);
	list_add_tail(&cmd->cmd_list_entry, &tgt->retry_cmd_list);

	if (!tgt->retry_timer_active) {
		TRACE_DBG("Activating retry timer for tgt %p", tgt);
		tgt->retry_timer.expires = jiffies + SCST_TGT_RETRY_TIMEOUT;
		add_timer(&tgt->retry_timer);
		tgt->retry_timer_active = 1;
	}

	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	TRACE_EXIT();
	return;
}

/**
 * scst_update_hw_pending_start() - update commands pending start
 *
 * Updates the command's hw_pending_start as if it's just started hw pending.
 * Target drivers should call it if they received reply from this pending
 * command, but SCST core won't see it.
 */
void scst_update_hw_pending_start(struct scst_cmd *cmd)
{
	unsigned long flags;

	TRACE_ENTRY();

	/* To sync with scst_check_hw_pending_cmd() */
	spin_lock_irqsave(&cmd->sess->sess_list_lock, flags);
	cmd->hw_pending_start = jiffies;
	TRACE_MGMT_DBG("Updated hw_pending_start to %ld (cmd %p)",
		cmd->hw_pending_start, cmd);
	spin_unlock_irqrestore(&cmd->sess->sess_list_lock, flags);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_update_hw_pending_start);

/*
 * Supposed to be called under sess_list_lock, but can release/reacquire it.
 * Returns 0 to continue, >0 to restart, <0 to break.
 */
static int scst_check_hw_pending_cmd(struct scst_cmd *cmd,
	unsigned long cur_time, unsigned long max_time,
	struct scst_session *sess, unsigned long *flags,
	struct scst_tgt_template *tgtt)
{
	int res = -1; /* break */

	TRACE_DBG("cmd %p, hw_pending %d, proc time %ld, "
		"pending time %ld", cmd, cmd->cmd_hw_pending,
		(long)(cur_time - cmd->start_time) / HZ,
		(long)(cur_time - cmd->hw_pending_start) / HZ);

	if (time_before(cur_time, cmd->start_time + max_time)) {
		/* Cmds are ordered, so no need to check more */
		goto out;
	}

	if (!cmd->cmd_hw_pending) {
		res = 0; /* continue */
		goto out;
	}

	if (time_before(cur_time, cmd->hw_pending_start + max_time)) {
		res = 0; /* continue */
		goto out;
	}

	TRACE(TRACE_MGMT, "Cmd %p HW pending for too long %ld (state %x)",
		cmd, (cur_time - cmd->hw_pending_start) / HZ,
		cmd->state);

	cmd->cmd_hw_pending = 0;

	spin_unlock_irqrestore(&sess->sess_list_lock, *flags);
	tgtt->on_hw_pending_cmd_timeout(cmd);
	spin_lock_irqsave(&sess->sess_list_lock, *flags);

	res = 1; /* restart */

out:
	TRACE_EXIT_RES(res);
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_hw_pending_work_fn(void *p)
#else
static void scst_hw_pending_work_fn(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct scst_session *sess = (struct scst_session *)p;
#else
	struct scst_session *sess = container_of(work, struct scst_session,
						 hw_pending_work.work);
#endif
	struct scst_tgt_template *tgtt = sess->tgt->tgtt;
	struct scst_cmd *cmd;
	unsigned long cur_time = jiffies;
	unsigned long flags;
	unsigned long max_time = tgtt->max_hw_pending_time * HZ;

	TRACE_ENTRY();

	TRACE_DBG("HW pending work (sess %p, max time %ld)", sess, max_time/HZ);

	clear_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED, &sess->sess_aflags);

	spin_lock_irqsave(&sess->sess_list_lock, flags);

restart:
	list_for_each_entry(cmd, &sess->sess_cmd_list, sess_cmd_list_entry) {
		int rc;

		rc = scst_check_hw_pending_cmd(cmd, cur_time, max_time, sess,
					&flags, tgtt);
		if (rc < 0)
			break;
		else if (rc == 0)
			continue;
		else
			goto restart;
	}

	if (!list_empty(&sess->sess_cmd_list)) {
		/*
		 * For stuck cmds if there is no activity we might need to have
		 * one more run to release them, so reschedule once again.
		 */
		TRACE_DBG("Sched HW pending work for sess %p (max time %d)",
			sess, tgtt->max_hw_pending_time);
		set_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED, &sess->sess_aflags);
		schedule_delayed_work(&sess->hw_pending_work,
				tgtt->max_hw_pending_time * HZ);
	}

	spin_unlock_irqrestore(&sess->sess_list_lock, flags);

	TRACE_EXIT();
	return;
}

static bool __scst_is_relative_target_port_id_unique(uint16_t id,
	const struct scst_tgt *t)
{
	bool res = true;
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	list_for_each_entry(tgtt, &scst_template_list,
				scst_template_list_entry) {
		struct scst_tgt *tgt;
		list_for_each_entry(tgt, &tgtt->tgt_list, tgt_list_entry) {
			if (tgt == t)
				continue;
			if ((tgt->tgtt->is_target_enabled != NULL) &&
			     !tgt->tgtt->is_target_enabled(tgt))
				continue;
			if (id == tgt->rel_tgt_id) {
				res = false;
				break;
			}
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* scst_mutex supposed to be locked */
bool scst_is_relative_target_port_id_unique(uint16_t id,
	const struct scst_tgt *t)
{
	bool res;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);
	res = __scst_is_relative_target_port_id_unique(id, t);
	mutex_unlock(&scst_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

int gen_relative_target_port_id(uint16_t *id)
{
	int res = -EOVERFLOW;
	static unsigned long rti = SCST_MIN_REL_TGT_ID, rti_prev;

	TRACE_ENTRY();

	res = mutex_lock_interruptible(&scst_mutex);
	if (res != 0)
		goto out;

	rti_prev = rti;
	do {
		if (__scst_is_relative_target_port_id_unique(rti, NULL)) {
			*id = (uint16_t)rti++;
			res = 0;
			goto out_unlock;
		}
		rti++;
		if (rti > SCST_MAX_REL_TGT_ID)
			rti = SCST_MIN_REL_TGT_ID;
	} while (rti != rti_prev);

	PRINT_ERROR("%s", "Unable to create unique relative target port id");

out_unlock:
	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* No locks */
int scst_alloc_tgt(struct scst_tgt_template *tgtt, struct scst_tgt **tgt)
{
	struct scst_tgt *t;
	int res = 0;

	TRACE_ENTRY();

	t = kmem_cache_zalloc(scst_tgt_cachep, GFP_KERNEL);
	if (t == NULL) {
		PRINT_ERROR("%s", "Allocation of tgt failed");
		res = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&t->sess_list);
	INIT_LIST_HEAD(&t->sysfs_sess_list);
	init_waitqueue_head(&t->unreg_waitQ);
	t->tgtt = tgtt;
	t->sg_tablesize = tgtt->sg_tablesize;
	spin_lock_init(&t->tgt_lock);
	INIT_LIST_HEAD(&t->retry_cmd_list);
	init_timer(&t->retry_timer);
	t->retry_timer.data = (unsigned long)t;
	t->retry_timer.function = scst_tgt_retry_timer_fn;

#ifdef CONFIG_SCST_PROC
	res = gen_relative_target_port_id(&t->rel_tgt_id);
	if (res != 0) {
		scst_free_tgt(t);
		goto out;
	}
#else
	INIT_LIST_HEAD(&t->tgt_acg_list);
#endif

	*tgt = t;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* No locks */
void scst_free_tgt(struct scst_tgt *tgt)
{
	TRACE_ENTRY();

	kfree(tgt->tgt_name);
	kfree(tgt->tgt_comment);
#ifdef CONFIG_SCST_PROC
	kfree(tgt->default_group_name);
#endif

	kmem_cache_free(scst_tgt_cachep, tgt);

	TRACE_EXIT();
	return;
}

static void scst_init_order_data(struct scst_order_data *order_data)
{
	int i;
	spin_lock_init(&order_data->sn_lock);
	INIT_LIST_HEAD(&order_data->deferred_cmd_list);
	INIT_LIST_HEAD(&order_data->skipped_sn_list);
	order_data->curr_sn = (typeof(order_data->curr_sn))(-20);
	order_data->expected_sn = order_data->curr_sn;
	order_data->cur_sn_slot = &order_data->sn_slots[0];
	for (i = 0; i < (int)ARRAY_SIZE(order_data->sn_slots); i++)
		atomic_set(&order_data->sn_slots[i], 0);
	spin_lock_init(&order_data->init_done_lock);
	return;
}

/* Called under scst_mutex and suspended activity */
int scst_alloc_device(gfp_t gfp_mask, struct scst_device **out_dev)
{
	struct scst_device *dev;
	int res = 0;

	TRACE_ENTRY();

	dev = kmem_cache_zalloc(scst_dev_cachep, gfp_mask);
	if (dev == NULL) {
		PRINT_ERROR("%s", "Allocation of scst_device failed");
		res = -ENOMEM;
		goto out;
	}

	dev->handler = &scst_null_devtype;
#ifdef CONFIG_SCST_PER_DEVICE_CMD_COUNT_LIMIT
	atomic_set(&dev->dev_cmd_count, 0);
#endif
	scst_init_mem_lim(&dev->dev_mem_lim);
	spin_lock_init(&dev->dev_lock);
	INIT_LIST_HEAD(&dev->blocked_cmd_list);
	INIT_LIST_HEAD(&dev->dev_tgt_dev_list);
	INIT_LIST_HEAD(&dev->dev_acg_dev_list);
	dev->dev_double_ua_possible = 1;
	dev->queue_alg = SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER;

	mutex_init(&dev->dev_pr_mutex);
	dev->pr_generation = 0;
	dev->pr_is_set = 0;
	dev->pr_holder = NULL;
	dev->pr_scope = SCOPE_LU;
	dev->pr_type = TYPE_UNSPECIFIED;
	INIT_LIST_HEAD(&dev->dev_registrants_list);

	scst_init_order_data(&dev->dev_order_data);

	scst_init_threads(&dev->dev_cmd_threads);

	*out_dev = dev;

out:
	TRACE_EXIT_RES(res);
	return res;
}

void scst_free_device(struct scst_device *dev)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (!list_empty(&dev->dev_tgt_dev_list) ||
	    !list_empty(&dev->dev_acg_dev_list)) {
		PRINT_CRIT_ERROR("%s: dev_tgt_dev_list or dev_acg_dev_list "
			"is not empty!", __func__);
		sBUG();
	}
#endif

	scst_deinit_threads(&dev->dev_cmd_threads);

	kfree(dev->virt_name);
	kmem_cache_free(scst_dev_cachep, dev);

	TRACE_EXIT();
	return;
}

/**
 * scst_init_mem_lim - initialize memory limits structure
 *
 * Initializes memory limits structure mem_lim according to
 * the current system configuration. This structure should be latter used
 * to track and limit allocated by one or more SGV pools memory.
 */
void scst_init_mem_lim(struct scst_mem_lim *mem_lim)
{
	atomic_set(&mem_lim->alloced_pages, 0);
	mem_lim->max_allowed_pages =
		((uint64_t)scst_max_dev_cmd_mem << 10) >> (PAGE_SHIFT - 10);
}
EXPORT_SYMBOL_GPL(scst_init_mem_lim);

static struct scst_acg_dev *scst_alloc_acg_dev(struct scst_acg *acg,
					struct scst_device *dev, uint64_t lun)
{
	struct scst_acg_dev *res;

	TRACE_ENTRY();

	res = kmem_cache_zalloc(scst_acgd_cachep, GFP_KERNEL);
	if (res == NULL) {
		PRINT_ERROR("%s", "Allocation of scst_acg_dev failed");
		goto out;
	}

	res->dev = dev;
	res->acg = acg;
	res->lun = lun;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/*
 * The activity supposed to be suspended and scst_mutex held or the
 * corresponding target supposed to be stopped.
 */
static void scst_del_free_acg_dev(struct scst_acg_dev *acg_dev, bool del_sysfs)
{
	TRACE_ENTRY();

	TRACE_DBG("Removing acg_dev %p from acg_dev_list and dev_acg_dev_list",
		acg_dev);
	list_del(&acg_dev->acg_dev_list_entry);
	list_del(&acg_dev->dev_acg_dev_list_entry);

	if (del_sysfs)
		scst_acg_dev_sysfs_del(acg_dev);

	kmem_cache_free(scst_acgd_cachep, acg_dev);

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_add_lun(struct scst_acg *acg, struct kobject *parent,
	struct scst_device *dev, uint64_t lun, int read_only,
	bool gen_scst_report_luns_changed, struct scst_acg_dev **out_acg_dev)
{
	int res = 0;
	struct scst_acg_dev *acg_dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_session *sess;
	LIST_HEAD(tmp_tgt_dev_list);

	TRACE_ENTRY();

	INIT_LIST_HEAD(&tmp_tgt_dev_list);

	acg_dev = scst_alloc_acg_dev(acg, dev, lun);
	if (acg_dev == NULL) {
		res = -ENOMEM;
		goto out;
	}
	acg_dev->acg_dev_rd_only = read_only;

	TRACE_DBG("Adding acg_dev %p to acg_dev_list and dev_acg_dev_list",
		acg_dev);
	list_add_tail(&acg_dev->acg_dev_list_entry, &acg->acg_dev_list);
	list_add_tail(&acg_dev->dev_acg_dev_list_entry, &dev->dev_acg_dev_list);

	list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) {
		res = scst_alloc_add_tgt_dev(sess, acg_dev, &tgt_dev);
		if (res == -EPERM)
			continue;
		else if (res != 0)
			goto out_free;

		list_add_tail(&tgt_dev->extra_tgt_dev_list_entry,
			      &tmp_tgt_dev_list);
	}

	res = scst_acg_dev_sysfs_create(acg_dev, parent);
	if (res != 0)
		goto out_free;

	if (gen_scst_report_luns_changed)
		scst_report_luns_changed(acg);

	PRINT_INFO("Added device %s to group %s (LUN %lld, "
		"rd_only %d) to target %s", dev->virt_name, acg->acg_name,
		lun, read_only, acg->tgt ? acg->tgt->tgt_name : "?");

	if (out_acg_dev != NULL)
		*out_acg_dev = acg_dev;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	list_for_each_entry(tgt_dev, &tmp_tgt_dev_list,
			 extra_tgt_dev_list_entry) {
		scst_free_tgt_dev(tgt_dev);
	}
	scst_del_free_acg_dev(acg_dev, false);
	goto out;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_del_lun(struct scst_acg *acg, uint64_t lun,
	bool gen_scst_report_luns_changed)
{
	int res = 0;
	struct scst_acg_dev *acg_dev = NULL, *a;
	struct scst_tgt_dev *tgt_dev, *tt;

	TRACE_ENTRY();

	list_for_each_entry(a, &acg->acg_dev_list, acg_dev_list_entry) {
		if (a->lun == lun) {
			acg_dev = a;
			break;
		}
	}
	if (acg_dev == NULL) {
		PRINT_ERROR("Device is not found in group %s", acg->acg_name);
		res = -EINVAL;
		goto out;
	}

	list_for_each_entry_safe(tgt_dev, tt, &acg_dev->dev->dev_tgt_dev_list,
			 dev_tgt_dev_list_entry) {
		if (tgt_dev->acg_dev == acg_dev)
			scst_free_tgt_dev(tgt_dev);
	}

	scst_del_free_acg_dev(acg_dev, true);

	if (gen_scst_report_luns_changed)
		scst_report_luns_changed(acg);

	PRINT_INFO("Removed LUN %lld from group %s (target %s)",
		lun, acg->acg_name, acg->tgt ? acg->tgt->tgt_name : "?");

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* The activity supposed to be suspended and scst_mutex held */
struct scst_acg *scst_alloc_add_acg(struct scst_tgt *tgt,
	const char *acg_name, bool tgt_acg)
{
	struct scst_acg *acg;

	TRACE_ENTRY();

	acg = kzalloc(sizeof(*acg), GFP_KERNEL);
	if (acg == NULL) {
		PRINT_ERROR("%s", "Allocation of acg failed");
		goto out;
	}

	acg->tgt = tgt;
	INIT_LIST_HEAD(&acg->acg_dev_list);
	INIT_LIST_HEAD(&acg->acg_sess_list);
	INIT_LIST_HEAD(&acg->acn_list);
	cpumask_copy(&acg->acg_cpu_mask, &default_cpu_mask);
	acg->acg_name = kstrdup(acg_name, GFP_KERNEL);
	if (acg->acg_name == NULL) {
		PRINT_ERROR("%s", "Allocation of acg_name failed");
		goto out_free;
	}

#ifdef CONFIG_SCST_PROC
	acg->addr_method = tgt && tgt->tgtt ? tgt->tgtt->preferred_addr_method
		: SCST_LUN_ADDR_METHOD_PERIPHERAL;

	TRACE_DBG("Adding acg %s to scst_acg_list", acg_name);
	list_add_tail(&acg->acg_list_entry, &scst_acg_list);

	scst_check_reassign_sessions();
#else
	acg->addr_method = tgt->tgtt->preferred_addr_method;

	if (tgt_acg) {
		int rc;

		TRACE_DBG("Adding acg '%s' to device '%s' acg_list", acg_name,
			tgt->tgt_name);
		list_add_tail(&acg->acg_list_entry, &tgt->tgt_acg_list);
		acg->tgt_acg = 1;

		rc = scst_acg_sysfs_create(tgt, acg);
		if (rc != 0)
			goto out_del;
	}
#endif

out:
	TRACE_EXIT_HRES(acg);
	return acg;

#ifndef CONFIG_SCST_PROC
out_del:
	list_del(&acg->acg_list_entry);
#endif

out_free:
	kfree(acg);
	acg = NULL;
	goto out;
}

/* The activity supposed to be suspended and scst_mutex held */
void scst_del_free_acg(struct scst_acg *acg)
{
	struct scst_acn *acn, *acnt;
	struct scst_acg_dev *acg_dev, *acg_dev_tmp;

	TRACE_ENTRY();

	TRACE_DBG("Clearing acg %s from list", acg->acg_name);

	sBUG_ON(!list_empty(&acg->acg_sess_list));

	/* Freeing acg_devs */
	list_for_each_entry_safe(acg_dev, acg_dev_tmp, &acg->acg_dev_list,
			acg_dev_list_entry) {
		struct scst_tgt_dev *tgt_dev, *tt;
		list_for_each_entry_safe(tgt_dev, tt,
				 &acg_dev->dev->dev_tgt_dev_list,
				 dev_tgt_dev_list_entry) {
			if (tgt_dev->acg_dev == acg_dev)
				scst_free_tgt_dev(tgt_dev);
		}
		scst_del_free_acg_dev(acg_dev, true);
	}

	/* Freeing names */
	list_for_each_entry_safe(acn, acnt, &acg->acn_list, acn_list_entry) {
		scst_del_free_acn(acn,
			list_is_last(&acn->acn_list_entry, &acg->acn_list));
	}
	INIT_LIST_HEAD(&acg->acn_list);

#ifdef CONFIG_SCST_PROC
	list_del(&acg->acg_list_entry);
#else
	if (acg->tgt_acg) {
		TRACE_DBG("Removing acg %s from list", acg->acg_name);
		list_del(&acg->acg_list_entry);

		scst_acg_sysfs_del(acg);
	} else
		acg->tgt->default_acg = NULL;
#endif

	sBUG_ON(!list_empty(&acg->acg_sess_list));
	sBUG_ON(!list_empty(&acg->acg_dev_list));
	sBUG_ON(!list_empty(&acg->acn_list));

	kfree(acg->acg_name);
	kfree(acg);

	TRACE_EXIT();
	return;
}

#ifndef CONFIG_SCST_PROC

/* The activity supposed to be suspended and scst_mutex held */
struct scst_acg *scst_tgt_find_acg(struct scst_tgt *tgt, const char *name)
{
	struct scst_acg *acg, *acg_ret = NULL;

	TRACE_ENTRY();

	list_for_each_entry(acg, &tgt->tgt_acg_list, acg_list_entry) {
		if (strcmp(acg->acg_name, name) == 0) {
			acg_ret = acg;
			break;
		}
	}

	TRACE_EXIT();
	return acg_ret;
}

#endif

/* scst_mutex supposed to be held */
static struct scst_tgt_dev *scst_find_shared_io_tgt_dev(
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_tgt_dev *res = NULL;
	struct scst_acg *acg = tgt_dev->acg_dev->acg;
	struct scst_tgt_dev *t;

	TRACE_ENTRY();

	TRACE_DBG("tgt_dev %s (acg %p, io_grouping_type %d)",
		tgt_dev->sess->initiator_name, acg, acg->acg_io_grouping_type);

	switch (acg->acg_io_grouping_type) {
	case SCST_IO_GROUPING_AUTO:
		if (tgt_dev->sess->initiator_name == NULL)
			goto out;

		list_for_each_entry(t, &tgt_dev->dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			if ((t == tgt_dev) ||
			    (t->sess->initiator_name == NULL) ||
			    (t->active_cmd_threads == NULL))
				continue;

			TRACE_DBG("t %s", t->sess->initiator_name);

			/* We check other ACG's as well */

			if (strcmp(t->sess->initiator_name,
					tgt_dev->sess->initiator_name) == 0)
				goto found;
		}
		break;

	case SCST_IO_GROUPING_THIS_GROUP_ONLY:
		list_for_each_entry(t, &tgt_dev->dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			if ((t == tgt_dev) || (t->active_cmd_threads == NULL))
				continue;

			TRACE_DBG("t %s (acg %p)", t->sess->initiator_name,
				t->acg_dev->acg);

			if (t->acg_dev->acg == acg)
				goto found;
		}
		break;

	case SCST_IO_GROUPING_NEVER:
		goto out;

	default:
		list_for_each_entry(t, &tgt_dev->dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			if ((t == tgt_dev) || (t->active_cmd_threads == NULL))
				continue;

			TRACE_DBG("t %s (acg %p, io_grouping_type %d)",
				t->sess->initiator_name, t->acg_dev->acg,
				t->acg_dev->acg->acg_io_grouping_type);

			if (t->acg_dev->acg->acg_io_grouping_type ==
					acg->acg_io_grouping_type)
				goto found;
		}
		break;
	}

out:
	TRACE_EXIT_HRES((unsigned long)res);
	return res;

found:
	if (t->active_cmd_threads == &scst_main_cmd_threads) {
		res = t;
		TRACE_DBG("Going to share async IO context %p (res %p, "
			"ini %s, dev %s, grouping type %d)",
			t->aic_keeper->aic, res, t->sess->initiator_name,
			t->dev->virt_name,
			t->acg_dev->acg->acg_io_grouping_type);
	} else {
		res = t;
		if (!*(volatile bool*)&res->active_cmd_threads->io_context_ready) {
			TRACE_DBG("IO context for t %p not yet "
				"initialized, waiting...", t);
			msleep(100);
			goto found;
		}
		smp_rmb();
		TRACE_DBG("Going to share IO context %p (res %p, ini %s, "
			"dev %s, cmd_threads %p, grouping type %d)",
			res->active_cmd_threads->io_context, res,
			t->sess->initiator_name, t->dev->virt_name,
			t->active_cmd_threads,
			t->acg_dev->acg->acg_io_grouping_type);
	}
	goto out;
}

enum scst_dev_type_threads_pool_type scst_parse_threads_pool_type(const char *p,
	int len)
{
	enum scst_dev_type_threads_pool_type res;

	if (strncasecmp(p, SCST_THREADS_POOL_PER_INITIATOR_STR,
			min_t(int, strlen(SCST_THREADS_POOL_PER_INITIATOR_STR),
				len)) == 0)
		res = SCST_THREADS_POOL_PER_INITIATOR;
	else if (strncasecmp(p, SCST_THREADS_POOL_SHARED_STR,
			min_t(int, strlen(SCST_THREADS_POOL_SHARED_STR),
				len)) == 0)
		res = SCST_THREADS_POOL_SHARED;
	else {
		PRINT_ERROR("Unknown threads pool type %s", p);
		res = SCST_THREADS_POOL_TYPE_INVALID;
	}

	return res;
}

static int scst_ioc_keeper_thread(void *arg)
{
	struct scst_async_io_context_keeper *aic_keeper =
		(struct scst_async_io_context_keeper *)arg;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("AIC %p keeper thread %s (PID %d) started", aic_keeper,
		current->comm, current->pid);

	current->flags |= PF_NOFREEZE;

	sBUG_ON(aic_keeper->aic != NULL);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
	aic_keeper->aic = get_task_io_context(current, GFP_KERNEL, NUMA_NO_NODE);
#else
	aic_keeper->aic = get_io_context(GFP_KERNEL, -1);
#endif
#endif
	TRACE_DBG("Alloced new async IO context %p (aic %p)",
		aic_keeper->aic, aic_keeper);

	/* We have our own ref counting */
	put_io_context(aic_keeper->aic);

	/* We are ready */
	aic_keeper->aic_ready = true;
	wake_up_all(&aic_keeper->aic_keeper_waitQ);

	wait_event_interruptible(aic_keeper->aic_keeper_waitQ,
		kthread_should_stop());

	TRACE_MGMT_DBG("AIC %p keeper thread %s (PID %d) finished", aic_keeper,
		current->comm, current->pid);

	TRACE_EXIT();
	return 0;
}

/* scst_mutex supposed to be held */
int scst_tgt_dev_setup_threads(struct scst_tgt_dev *tgt_dev)
{
	int res = 0;
	struct scst_device *dev = tgt_dev->dev;
	struct scst_async_io_context_keeper *aic_keeper;

	TRACE_ENTRY();

	if (dev->threads_num < 0)
		goto out;

	if (dev->threads_num == 0) {
		struct scst_tgt_dev *shared_io_tgt_dev;
		tgt_dev->active_cmd_threads = &scst_main_cmd_threads;

		shared_io_tgt_dev = scst_find_shared_io_tgt_dev(tgt_dev);
		if (shared_io_tgt_dev != NULL) {
			aic_keeper = shared_io_tgt_dev->aic_keeper;
			kref_get(&aic_keeper->aic_keeper_kref);

			TRACE_DBG("Linking async io context %p "
				"for shared tgt_dev %p (dev %s)",
				aic_keeper->aic, tgt_dev,
				tgt_dev->dev->virt_name);
		} else {
			/* Create new context */
			aic_keeper = kzalloc(sizeof(*aic_keeper), GFP_KERNEL);
			if (aic_keeper == NULL) {
				PRINT_ERROR("Unable to alloc aic_keeper "
					"(size %zd)", sizeof(*aic_keeper));
				res = -ENOMEM;
				goto out;
			}

			kref_init(&aic_keeper->aic_keeper_kref);
			init_waitqueue_head(&aic_keeper->aic_keeper_waitQ);

			aic_keeper->aic_keeper_thr =
				kthread_run(scst_ioc_keeper_thread,
					aic_keeper, "aic_keeper");
			if (IS_ERR(aic_keeper->aic_keeper_thr)) {
				PRINT_ERROR("Error running ioc_keeper "
					"thread (tgt_dev %p)", tgt_dev);
				res = PTR_ERR(aic_keeper->aic_keeper_thr);
				goto out_free_keeper;
			}

			wait_event(aic_keeper->aic_keeper_waitQ,
				aic_keeper->aic_ready);

			TRACE_DBG("Created async io context %p "
				"for not shared tgt_dev %p (dev %s)",
				aic_keeper->aic, tgt_dev,
				tgt_dev->dev->virt_name);
		}

		tgt_dev->async_io_context = aic_keeper->aic;
		tgt_dev->aic_keeper = aic_keeper;

		res = scst_add_threads(tgt_dev->active_cmd_threads, NULL, NULL,
			tgt_dev->sess->tgt->tgtt->threads_num);
		goto out;
	}

	switch (dev->threads_pool_type) {
	case SCST_THREADS_POOL_PER_INITIATOR:
	{
		struct scst_tgt_dev *shared_io_tgt_dev;

		scst_init_threads(&tgt_dev->tgt_dev_cmd_threads);

		tgt_dev->active_cmd_threads = &tgt_dev->tgt_dev_cmd_threads;

		shared_io_tgt_dev = scst_find_shared_io_tgt_dev(tgt_dev);
		if (shared_io_tgt_dev != NULL) {
			TRACE_DBG("Linking io context %p for "
				"shared tgt_dev %p (cmd_threads %p)",
				shared_io_tgt_dev->active_cmd_threads->io_context,
				tgt_dev, tgt_dev->active_cmd_threads);
			/* It's ref counted via threads */
			tgt_dev->active_cmd_threads->io_context =
				shared_io_tgt_dev->active_cmd_threads->io_context;
		}

		res = scst_add_threads(tgt_dev->active_cmd_threads, NULL,
			tgt_dev,
			dev->threads_num + tgt_dev->sess->tgt->tgtt->threads_num);
		if (res != 0) {
			/* Let's clear here, because no threads could be run */
			tgt_dev->active_cmd_threads->io_context = NULL;
		}
		break;
	}
	case SCST_THREADS_POOL_SHARED:
	{
		tgt_dev->active_cmd_threads = &dev->dev_cmd_threads;

		res = scst_add_threads(tgt_dev->active_cmd_threads, dev, NULL,
			tgt_dev->sess->tgt->tgtt->threads_num);
		break;
	}
	default:
		PRINT_CRIT_ERROR("Unknown threads pool type %d (dev %s)",
			dev->threads_pool_type, dev->virt_name);
		sBUG();
		break;
	}

out:
	if (res == 0)
		tm_dbg_init_tgt_dev(tgt_dev);

	TRACE_EXIT_RES(res);
	return res;

out_free_keeper:
	kfree(aic_keeper);
	goto out;
}

static void scst_aic_keeper_release(struct kref *kref)
{
	struct scst_async_io_context_keeper *aic_keeper;

	TRACE_ENTRY();

	aic_keeper = container_of(kref, struct scst_async_io_context_keeper,
			aic_keeper_kref);

	kthread_stop(aic_keeper->aic_keeper_thr);

	kfree(aic_keeper);

	TRACE_EXIT();
	return;
}

/* scst_mutex supposed to be held */
void scst_tgt_dev_stop_threads(struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();

	if (tgt_dev->dev->threads_num < 0)
		goto out_deinit;

	if (tgt_dev->active_cmd_threads == &scst_main_cmd_threads) {
		/* Global async threads */
		kref_put(&tgt_dev->aic_keeper->aic_keeper_kref,
			scst_aic_keeper_release);
		tgt_dev->async_io_context = NULL;
		tgt_dev->aic_keeper = NULL;
	} else if (tgt_dev->active_cmd_threads == &tgt_dev->dev->dev_cmd_threads) {
		/* Per device shared threads */
		scst_del_threads(tgt_dev->active_cmd_threads,
			tgt_dev->sess->tgt->tgtt->threads_num);
	} else if (tgt_dev->active_cmd_threads == &tgt_dev->tgt_dev_cmd_threads) {
		/* Per tgt_dev threads */
		scst_del_threads(tgt_dev->active_cmd_threads, -1);
		scst_deinit_threads(&tgt_dev->tgt_dev_cmd_threads);
	} /* else no threads (not yet initialized, e.g.) */

out_deinit:
	tm_dbg_deinit_tgt_dev(tgt_dev);
	tgt_dev->active_cmd_threads = NULL;

	TRACE_EXIT();
	return;
}

/*
 * scst_mutex supposed to be held, there must not be parallel activity in this
 * session.
 */
static int scst_alloc_add_tgt_dev(struct scst_session *sess,
	struct scst_acg_dev *acg_dev, struct scst_tgt_dev **out_tgt_dev)
{
	int res = 0;
	int ini_sg, ini_unchecked_isa_dma, ini_use_clustering;
	struct scst_tgt_dev *tgt_dev;
	struct scst_device *dev = acg_dev->dev;
	struct list_head *head;
	int sl;
	uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	tgt_dev = kmem_cache_zalloc(scst_tgtd_cachep, GFP_KERNEL);
	if (tgt_dev == NULL) {
		PRINT_ERROR("%s", "Allocation of scst_tgt_dev failed");
		res = -ENOMEM;
		goto out;
	}

	tgt_dev->dev = dev;
	tgt_dev->lun = acg_dev->lun;
	tgt_dev->acg_dev = acg_dev;
	tgt_dev->tgt_dev_rd_only = acg_dev->acg_dev_rd_only || dev->dev_rd_only;
	tgt_dev->sess = sess;
	atomic_set(&tgt_dev->tgt_dev_cmd_count, 0);

	scst_sgv_pool_use_norm(tgt_dev);

	if (dev->scsi_dev != NULL) {
		ini_sg = dev->scsi_dev->host->sg_tablesize;
		ini_unchecked_isa_dma = dev->scsi_dev->host->unchecked_isa_dma;
		ini_use_clustering = (dev->scsi_dev->host->use_clustering ==
				ENABLE_CLUSTERING);
	} else {
		ini_sg = (1 << 15) /* infinite */;
		ini_unchecked_isa_dma = 0;
		ini_use_clustering = 0;
	}
	tgt_dev->max_sg_cnt = min(ini_sg, sess->tgt->sg_tablesize);

	if ((sess->tgt->tgtt->use_clustering || ini_use_clustering) &&
	    !sess->tgt->tgtt->no_clustering)
		scst_sgv_pool_use_norm_clust(tgt_dev);

	if (sess->tgt->tgtt->unchecked_isa_dma || ini_unchecked_isa_dma)
		scst_sgv_pool_use_dma(tgt_dev);

	TRACE_MGMT_DBG("Device %s on SCST lun=%lld",
	       dev->virt_name, (long long unsigned int)tgt_dev->lun);

	spin_lock_init(&tgt_dev->tgt_dev_lock);
	INIT_LIST_HEAD(&tgt_dev->UA_list);

	scst_init_order_data(&tgt_dev->tgt_dev_order_data);
	if (dev->tst == SCST_CONTR_MODE_SEP_TASK_SETS)
		tgt_dev->curr_order_data = &tgt_dev->tgt_dev_order_data;
	else
		tgt_dev->curr_order_data = &dev->dev_order_data;

	if (dev->handler->parse_atomic &&
	    dev->handler->dev_alloc_data_buf_atomic &&
	    (sess->tgt->tgtt->preprocessing_done == NULL)) {
		if (sess->tgt->tgtt->rdy_to_xfer_atomic)
			tgt_dev->tgt_dev_after_init_wr_atomic = 1;
	}
	if (dev->handler->dev_done_atomic &&
	    sess->tgt->tgtt->xmit_response_atomic)
		tgt_dev->tgt_dev_after_exec_atomic = 1;

	sl = scst_set_sense(sense_buffer, sizeof(sense_buffer),
		dev->d_sense, SCST_LOAD_SENSE(scst_sense_reset_UA));
	scst_alloc_set_UA(tgt_dev, sense_buffer, sl, 0);

	if (sess->tgt->tgtt->get_initiator_port_transport_id == NULL) {
		if (!list_empty(&dev->dev_registrants_list)) {
			PRINT_WARNING("Initiators from target %s can't connect "
				"to device %s, because the device has PR "
				"registrants and the target doesn't support "
				"Persistent Reservations", sess->tgt->tgtt->name,
				dev->virt_name);
			res = -EPERM;
			goto out_free;
		}
		dev->not_pr_supporting_tgt_devs_num++;
	}

	res = scst_pr_init_tgt_dev(tgt_dev);
	if (res != 0)
		goto out_dec_free;

	res = scst_tgt_dev_setup_threads(tgt_dev);
	if (res != 0)
		goto out_pr_clear;

	if (dev->handler->attach_tgt) {
		TRACE_DBG("Calling dev handler's attach_tgt(%p)", tgt_dev);
		res = dev->handler->attach_tgt(tgt_dev);
		TRACE_DBG("%s", "Dev handler's attach_tgt() returned");
		if (res != 0) {
			PRINT_ERROR("Device handler's %s attach_tgt() "
			    "failed: %d", dev->handler->name, res);
			goto out_stop_threads;
		}
	}

	res = scst_tgt_dev_sysfs_create(tgt_dev);
	if (res != 0)
		goto out_detach;

	spin_lock_bh(&dev->dev_lock);
	list_add_tail(&tgt_dev->dev_tgt_dev_list_entry, &dev->dev_tgt_dev_list);
	spin_unlock_bh(&dev->dev_lock);

	head = &sess->sess_tgt_dev_list[SESS_TGT_DEV_LIST_HASH_FN(tgt_dev->lun)];
	list_add_tail(&tgt_dev->sess_tgt_dev_list_entry, head);

	scst_tg_init_tgt_dev(tgt_dev);

	*out_tgt_dev = tgt_dev;

out:
	TRACE_EXIT_RES(res);
	return res;

out_detach:
	if (dev->handler->detach_tgt) {
		TRACE_DBG("Calling dev handler's detach_tgt(%p)",
		      tgt_dev);
		dev->handler->detach_tgt(tgt_dev);
		TRACE_DBG("%s", "Dev handler's detach_tgt() returned");
	}

out_stop_threads:
	scst_tgt_dev_stop_threads(tgt_dev);

out_pr_clear:
	scst_pr_clear_tgt_dev(tgt_dev);

out_dec_free:
	if (tgt_dev->sess->tgt->tgtt->get_initiator_port_transport_id == NULL)
		dev->not_pr_supporting_tgt_devs_num--;

out_free:
	scst_free_all_UA(tgt_dev);
	kmem_cache_free(scst_tgtd_cachep, tgt_dev);
	goto out;
}

/* No locks supposed to be held, scst_mutex - held */
void scst_nexus_loss(struct scst_tgt_dev *tgt_dev, bool queue_UA)
{
	TRACE_ENTRY();

	if (queue_UA) {
		uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
		int sl = scst_set_sense(sense_buffer, sizeof(sense_buffer),
				tgt_dev->dev->d_sense,
				SCST_LOAD_SENSE(scst_sense_nexus_loss_UA));
		scst_check_set_UA(tgt_dev, sense_buffer, sl,
			SCST_SET_UA_FLAG_AT_HEAD);
	}

	TRACE_EXIT();
	return;
}

/*
 * scst_mutex supposed to be held, there must not be parallel activity in this
 * session.
 */
static void scst_free_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	struct scst_device *dev = tgt_dev->dev;

	TRACE_ENTRY();

	spin_lock_bh(&dev->dev_lock);
	list_del(&tgt_dev->dev_tgt_dev_list_entry);
	spin_unlock_bh(&dev->dev_lock);

	list_del(&tgt_dev->sess_tgt_dev_list_entry);

	scst_tgt_dev_sysfs_del(tgt_dev);

	if (tgt_dev->sess->tgt->tgtt->get_initiator_port_transport_id == NULL)
		dev->not_pr_supporting_tgt_devs_num--;

	scst_clear_reservation(tgt_dev);
	scst_pr_clear_tgt_dev(tgt_dev);
	scst_free_all_UA(tgt_dev);

	if (dev->handler && dev->handler->detach_tgt) {
		TRACE_DBG("Calling dev handler's detach_tgt(%p)",
		      tgt_dev);
		dev->handler->detach_tgt(tgt_dev);
		TRACE_DBG("%s", "Dev handler's detach_tgt() returned");
	}

	scst_tgt_dev_stop_threads(tgt_dev);

	kmem_cache_free(scst_tgtd_cachep, tgt_dev);

	TRACE_EXIT();
	return;
}

/* scst_mutex supposed to be held */
int scst_sess_alloc_tgt_devs(struct scst_session *sess)
{
	int res = 0;
	struct scst_acg_dev *acg_dev;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	list_for_each_entry(acg_dev, &sess->acg->acg_dev_list,
			acg_dev_list_entry) {
		res = scst_alloc_add_tgt_dev(sess, acg_dev, &tgt_dev);
		if (res == -EPERM)
			continue;
		else if (res != 0)
			goto out_free;
	}

out:
	TRACE_EXIT();
	return res;

out_free:
	scst_sess_free_tgt_devs(sess);
	goto out;
}

/*
 * scst_mutex supposed to be held, there must not be parallel activity in this
 * session.
 */
void scst_sess_free_tgt_devs(struct scst_session *sess)
{
	int i;
	struct scst_tgt_dev *tgt_dev, *t;

	TRACE_ENTRY();

	/* The session is going down, no users, so no locks */
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &sess->sess_tgt_dev_list[i];
		list_for_each_entry_safe(tgt_dev, t, head,
				sess_tgt_dev_list_entry) {
			scst_free_tgt_dev(tgt_dev);
		}
		INIT_LIST_HEAD(head);
	}

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_add_acn(struct scst_acg *acg, const char *name)
{
	int res = 0;
	struct scst_acn *acn;
	char *nm;

	TRACE_ENTRY();

	list_for_each_entry(acn, &acg->acn_list, acn_list_entry) {
		if (strcmp(acn->name, name) == 0) {
			PRINT_ERROR("Name %s already exists in group %s",
				name, acg->acg_name);
			res = -EEXIST;
			goto out;
		}
	}

	acn = kzalloc(sizeof(*acn), GFP_KERNEL);
	if (acn == NULL) {
		PRINT_ERROR("%s", "Unable to allocate scst_acn");
		res = -ENOMEM;
		goto out;
	}

	acn->acg = acg;

	nm = kstrdup(name, GFP_KERNEL);
	if (nm == NULL) {
		PRINT_ERROR("%s", "Unable to allocate scst_acn->name");
		res = -ENOMEM;
		goto out_free;
	}
	acn->name = nm;

	res = scst_acn_sysfs_create(acn);
	if (res != 0)
		goto out_free_nm;

	list_add_tail(&acn->acn_list_entry, &acg->acn_list);

out:
	if (res == 0) {
		PRINT_INFO("Added name %s to group %s (target %s)", name,
			acg->acg_name, acg->tgt ? acg->tgt->tgt_name : "?");
		scst_check_reassign_sessions();
	}

	TRACE_EXIT_RES(res);
	return res;

out_free_nm:
	kfree(nm);

out_free:
	kfree(acn);
	goto out;
}

/* The activity supposed to be suspended and scst_mutex held */
void scst_del_free_acn(struct scst_acn *acn, bool reassign)
{
	TRACE_ENTRY();

	list_del(&acn->acn_list_entry);

	scst_acn_sysfs_del(acn);

	kfree(acn->name);
	kfree(acn);

	if (reassign)
		scst_check_reassign_sessions();

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
struct scst_acn *scst_find_acn(struct scst_acg *acg, const char *name)
{
	struct scst_acn *acn;

	TRACE_ENTRY();

	TRACE_DBG("Trying to find name '%s'", name);

	list_for_each_entry(acn, &acg->acn_list, acn_list_entry) {
		if (strcmp(acn->name, name) == 0) {
			TRACE_DBG("%s", "Found");
			goto out;
		}
	}
	acn = NULL;
out:
	TRACE_EXIT();
	return acn;
}

#ifdef CONFIG_SCST_PROC
/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_remove_name(struct scst_acg *acg, const char *name, bool reassign)
{
	int res = -EINVAL;
	struct scst_acn *acn;

	TRACE_ENTRY();

	list_for_each_entry(acn, &acg->acn_list, acn_list_entry) {
		if (strcmp(acn->name, name) == 0) {
			scst_del_free_acn(acn, false);
			res = 0;
			break;
		}
	}

	if (res == 0) {
		PRINT_INFO("Removed name %s from group %s (target %s)", name,
			acg->acg_name, acg->tgt ? acg->tgt->tgt_name : "?");
		if (reassign)
			scst_check_reassign_sessions();
	} else
		PRINT_ERROR("Unable to find name '%s' in group '%s'", name,
			acg->acg_name);

	TRACE_EXIT_RES(res);
	return res;
}
#endif

static struct scst_cmd *scst_create_prepare_internal_cmd(
	struct scst_cmd *orig_cmd, const uint8_t *cdb,
	unsigned int cdb_len, enum scst_cmd_queue_type queue_type)
{
	struct scst_cmd *res;
	int rc;
	gfp_t gfp_mask = scst_cmd_atomic(orig_cmd) ? GFP_ATOMIC : orig_cmd->cmd_gfp_mask;
	unsigned long flags;

	TRACE_ENTRY();

	res = scst_alloc_cmd(cdb, cdb_len, gfp_mask);
	if (res == NULL)
		goto out;

	res->cmd_threads = orig_cmd->cmd_threads;
	res->sess = orig_cmd->sess;
	res->atomic = scst_cmd_atomic(orig_cmd);
	res->internal = 1;
	res->tgtt = orig_cmd->tgtt;
	res->tgt = orig_cmd->tgt;
	res->dev = orig_cmd->dev;
	res->devt = orig_cmd->devt;
	res->tgt_dev = orig_cmd->tgt_dev;
	res->cur_order_data = orig_cmd->tgt_dev->curr_order_data;
	res->lun = orig_cmd->lun;
	res->queue_type = queue_type;
	res->data_direction = SCST_DATA_UNKNOWN;

	/*
	 * We need to keep it here to be able to abort during TM processing.
	 * They should be aborted to (1) speed up TM processing and (2) to
	 * guarantee that after a TM command finished the affected device(s)
	 * is/are in a quiescent state with all affected commands finished and
	 * others - blocked.
	 */
	spin_lock_irqsave(&res->sess->sess_list_lock, flags);
	list_add_tail(&res->sess_cmd_list_entry, &res->sess->sess_cmd_list);
	spin_unlock_irqrestore(&res->sess->sess_list_lock, flags);

	scst_sess_get(res->sess);
	if (res->tgt_dev != NULL)
		res->cpu_cmd_counter = scst_get();

	scst_set_start_time(res);

	TRACE(TRACE_SCSI, "New internal cmd %p (op 0x%x)", res, res->cdb[0]);

	rc = scst_pre_parse(res);
	sBUG_ON(rc != 0);

	res->state = SCST_CMD_STATE_PARSE;

out:
	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

int scst_prepare_request_sense(struct scst_cmd *orig_cmd)
{
	int res = 0;
	static const uint8_t request_sense[6] = {
		REQUEST_SENSE, 0, 0, 0, SCST_SENSE_BUFFERSIZE, 0
	};
	struct scst_cmd *rs_cmd;

	TRACE_ENTRY();

	if (orig_cmd->sense != NULL) {
		TRACE_MEM("Releasing sense %p (orig_cmd %p)",
			orig_cmd->sense, orig_cmd);
		mempool_free(orig_cmd->sense, scst_sense_mempool);
		orig_cmd->sense = NULL;
	}

	rs_cmd = scst_create_prepare_internal_cmd(orig_cmd,
			request_sense, sizeof(request_sense),
			SCST_CMD_QUEUE_HEAD_OF_QUEUE);
	if (rs_cmd == NULL)
		goto out_error;

	rs_cmd->tgt_i_priv = orig_cmd;

	rs_cmd->cdb[1] |= scst_get_cmd_dev_d_sense(orig_cmd);
	rs_cmd->expected_data_direction = SCST_DATA_READ;
	rs_cmd->expected_transfer_len = SCST_SENSE_BUFFERSIZE;
	rs_cmd->expected_values_set = 1;

	TRACE_MGMT_DBG("Adding REQUEST SENSE cmd %p to head of active "
		"cmd list", rs_cmd);
	spin_lock_irq(&rs_cmd->cmd_threads->cmd_list_lock);
	list_add(&rs_cmd->cmd_list_entry, &rs_cmd->cmd_threads->active_cmd_list);
	wake_up(&rs_cmd->cmd_threads->cmd_list_waitQ);
	spin_unlock_irq(&rs_cmd->cmd_threads->cmd_list_lock);

out:
	TRACE_EXIT_RES(res);
	return res;

out_error:
	res = -1;
	goto out;
}

static void scst_complete_request_sense(struct scst_cmd *req_cmd)
{
	struct scst_cmd *orig_cmd = req_cmd->tgt_i_priv;
	uint8_t *buf;
	int len;

	TRACE_ENTRY();

	sBUG_ON(orig_cmd == NULL);

	len = scst_get_buf_full(req_cmd, &buf);

	if (scsi_status_is_good(req_cmd->status) && (len > 0) &&
	    scst_sense_valid(buf) && !scst_no_sense(buf)) {
		PRINT_BUFF_FLAG(TRACE_SCSI, "REQUEST SENSE returned",
			buf, len);
		scst_alloc_set_sense(orig_cmd, scst_cmd_atomic(req_cmd), buf,
			len);
	} else {
		PRINT_ERROR("%s", "Unable to get the sense via "
			"REQUEST SENSE, returning HARDWARE ERROR");
		scst_set_cmd_error(orig_cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
	}

	if (len > 0)
		scst_put_buf_full(req_cmd, buf);

	TRACE_MGMT_DBG("Adding orig cmd %p to head of active "
		"cmd list", orig_cmd);
	spin_lock_irq(&orig_cmd->cmd_threads->cmd_list_lock);
	list_add(&orig_cmd->cmd_list_entry, &orig_cmd->cmd_threads->active_cmd_list);
	wake_up(&orig_cmd->cmd_threads->cmd_list_waitQ);
	spin_unlock_irq(&orig_cmd->cmd_threads->cmd_list_lock);

	TRACE_EXIT();
	return;
}

struct scst_write_same_priv {
	/* Must be the first for scst_finish_internal_cmd()! */
	scst_i_finish_fn_t ws_finish_fn;

	struct scst_cmd *ws_orig_cmd;

	struct mutex ws_mutex;

	int64_t ws_cur_lba; /* in blocks */
	int ws_left_to_send; /* in blocks */

	int ws_max_each;/* in blocks */
	int ws_cur_in_flight;

	int ws_sg_cnt;
	struct scatterlist *ws_sg;
};

/* ws_mutex suppose to be locked */
static int scst_ws_push_single_write(struct scst_write_same_priv *wsp,
	int64_t lba, int blocks)
{
	struct scst_cmd *ws_cmd = wsp->ws_orig_cmd;
	struct scatterlist *ws_sg = wsp->ws_sg;
	int ws_sg_cnt = wsp->ws_sg_cnt;
	int res, i;
	uint8_t write16_cdb[16];
	struct scatterlist *sg;
	int sg_cnt, len = blocks << ws_cmd->dev->block_shift;
	struct sgv_pool_obj *sgv;
	struct scst_cmd *cmd;
	int64_t cur_lba;

	TRACE_ENTRY();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &ws_cmd->cmd_flags)) ||
	    unlikely(ws_cmd->completed)) {
		TRACE_DBG("ws cmd %p aborted or completed (%d), aborting "
			"further write commands", ws_cmd, ws_cmd->completed);
		wsp->ws_left_to_send = 0;
		res = -EPIPE;
		goto out;
	}

	memset(write16_cdb, 0, sizeof(write16_cdb));
	write16_cdb[0] = WRITE_16;
	put_unaligned_be64(lba, &write16_cdb[2]);
	put_unaligned_be32(blocks, &write16_cdb[10]);

	cmd = scst_create_prepare_internal_cmd(ws_cmd, write16_cdb,
		sizeof(write16_cdb), SCST_CMD_QUEUE_SIMPLE);
	if (cmd == NULL) {
		res = -ENOMEM;
		goto out_busy;
	}

	cmd->expected_data_direction = SCST_DATA_WRITE;
	cmd->expected_transfer_len = len;
	cmd->expected_values_set = 1;

	cmd->tgt_i_priv = wsp;

	if ((ws_cmd->cdb[1] & 0x6) == 0) {
		TRACE_DBG("Using direct ws_sg %p (cnt %d)", ws_sg, ws_sg_cnt);
		sg = ws_sg;
		EXTRACHECKS_BUG_ON(blocks > ws_sg_cnt);
		sg_cnt = blocks;
		goto set_add;
	}

	sgv = NULL; /* we don't supply sgv */
	sg = sgv_pool_alloc(ws_cmd->tgt_dev->pool, len, GFP_KERNEL, 0,
			&sg_cnt, &sgv, &cmd->dev->dev_mem_lim, NULL);
	if (sg == NULL) {
		PRINT_ERROR("Unable to alloc sg for %d blocks", blocks);
		res = -ENOMEM;
		goto out_free_cmd;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
	sg_copy(sg, ws_sg, ws_sg_cnt, len, KM_USER0, KM_USER1);
#else
	sg_copy(sg, ws_sg, ws_sg_cnt, len);
#endif

	cur_lba = lba;
	for (i = 0; i < sg_cnt; i++) {
		int cur_offs = 0;
		while (cur_offs < sg[i].length) {
			uint8_t *q;
			q = &((int8_t *)(page_address(sg_page(&sg[i]))))[cur_offs];
			*((uint64_t *)q) = cur_lba;
			cur_offs += ws_cmd->dev->block_size;
			cur_lba++;
		}
	}

set_add:
	cmd->tgt_i_sg = sg;
	cmd->tgt_i_sg_cnt = sg_cnt;
	cmd->out_sgv = sgv; /* hacky, but it isn't used for WRITE(16) */
	cmd->tgt_i_data_buf_alloced = 1;

	wsp->ws_cur_lba += blocks;
	wsp->ws_left_to_send -= blocks;
	wsp->ws_cur_in_flight++;

	TRACE_DBG("Adding WRITE(16) cmd %p to active cmd list", cmd);
	spin_lock_irq(&cmd->cmd_threads->cmd_list_lock);
	list_add_tail(&cmd->cmd_list_entry, &cmd->cmd_threads->active_cmd_list);
	spin_unlock_irq(&cmd->cmd_threads->cmd_list_lock);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_cmd:
	__scst_cmd_put(cmd);

out_busy:
	scst_set_busy(ws_cmd);
	goto out;
}

static void scst_ws_finished(struct scst_write_same_priv *wsp)
{
	struct scst_cmd *ws_cmd = wsp->ws_orig_cmd;

	TRACE_ENTRY();

	TRACE_DBG("ws cmd %p finished with status %d", ws_cmd, ws_cmd->status);

	sBUG_ON(wsp->ws_cur_in_flight != 0);

	kfree(wsp->ws_sg);
	kfree(wsp);

	ws_cmd->completed = 1; /* for success */
	ws_cmd->scst_cmd_done(ws_cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_THREAD);

	TRACE_EXIT();
	return;
}

/* Must be called in a thread context and no locks */
static void scst_ws_write_cmd_finished(struct scst_cmd *cmd)
{
	struct scst_write_same_priv *wsp = cmd->tgt_i_priv;
	struct scst_cmd *ws_cmd = wsp->ws_orig_cmd;
	int rc, blocks;

	TRACE_ENTRY();

	TRACE_DBG("Write cmd %p finished (ws cmd %p, ws_cur_in_flight %d)",
		cmd, ws_cmd, wsp->ws_cur_in_flight);

	if ((ws_cmd->cdb[1] & 0x6) != 0)
		sgv_pool_free(cmd->out_sgv, &cmd->dev->dev_mem_lim);

	cmd->sg = NULL;
	cmd->sg_cnt = 0;

	mutex_lock(&wsp->ws_mutex);

	wsp->ws_cur_in_flight--;

	if (cmd->status != 0) {
		int rc;
		TRACE_DBG("Write cmd %p (ws cmd %p) finished not successfully",
			cmd, ws_cmd);
		sBUG_ON(cmd->resp_data_len != 0);
		if (cmd->status == SAM_STAT_CHECK_CONDITION)
			rc = scst_set_cmd_error_sense(ws_cmd, cmd->sense,
				cmd->sense_valid_len);
		else {
			sBUG_ON(cmd->sense != NULL);
			rc = scst_set_cmd_error_status(ws_cmd, cmd->status);
		}
		if (rc != 0) {
			/* Requeue possible UA */
			if (scst_is_ua_sense(cmd->sense, cmd->sense_valid_len))
				scst_requeue_ua(cmd, NULL, 0);
		}
	}

	if (wsp->ws_left_to_send == 0)
		goto out_check_finish;

	blocks = min_t(int, wsp->ws_left_to_send, wsp->ws_max_each);

	rc = scst_ws_push_single_write(wsp, wsp->ws_cur_lba, blocks);
	if (rc != 0)
		goto out_check_finish;

	wake_up(&ws_cmd->cmd_threads->cmd_list_waitQ);

out_unlock:
	mutex_unlock(&wsp->ws_mutex);

out:
	TRACE_EXIT();
	return;

out_check_finish:
	if (wsp->ws_cur_in_flight > 0)
		goto out_unlock;

	mutex_unlock(&wsp->ws_mutex);
	scst_ws_finished(wsp);
	goto out;
}

/* Must be called in a thread context and no locks */
static void scst_ws_gen_writes(struct scst_write_same_priv *wsp)
{
	struct scst_cmd *ws_cmd = wsp->ws_orig_cmd;
	int cnt = 0;

	TRACE_ENTRY();

	mutex_lock(&wsp->ws_mutex);

	while ((wsp->ws_left_to_send > 0) &&
	       (wsp->ws_cur_in_flight < SCST_MAX_IN_FLIGHT_INTERNAL_COMMANDS)) {
		int rc, blocks;

		blocks = min_t(int, wsp->ws_left_to_send, wsp->ws_max_each);

		rc = scst_ws_push_single_write(wsp, wsp->ws_cur_lba, blocks);
		if (rc != 0)
			goto out_err;

		cnt++;
	}

out_wake:
	if (cnt != 0)
		wake_up(&ws_cmd->cmd_threads->cmd_list_waitQ);

	mutex_unlock(&wsp->ws_mutex);

out:
	TRACE_EXIT();
	return;

out_err:
	if (wsp->ws_cur_in_flight != 0)
		goto out_wake;
	else {
		mutex_unlock(&wsp->ws_mutex);
		scst_ws_finished(wsp);
		goto out;
	}
}

/*
 * Library function to perform WRITE SAME in a generic manner. On exit, cmd
 * always completed with sense set, if necessary.
 */
void scst_write_same(struct scst_cmd *cmd)
{
	struct scst_write_same_priv *wsp;
	int i;

	TRACE_ENTRY();

	if (unlikely(cmd->data_len <= 0)) {
		scst_set_invalid_field_in_cdb(cmd, cmd->len_off, 0);
		goto out_done;
	}

	if (cmd->sg_cnt != 1) {
		PRINT_WARNING("WRITE SAME must contain only single block of data "
			"in a single SG (cmd %p)", cmd);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_parameter_value_invalid));
		goto out_done;
	}

	if (((cmd->cdb[1] & 0x6) == 0x6) || ((cmd->cdb[1] & 0xE0) != 0)) {
		scst_set_invalid_field_in_cdb(cmd, 1, 0);
		goto out_done;
	}

	if (unlikely((uint64_t)cmd->data_len > cmd->dev->max_write_same_len)) {
		PRINT_WARNING("Invalid WRITE SAME data len %lld (max allowed "
			"%lld)", (long long)cmd->data_len,
			(long long)cmd->dev->max_write_same_len);
		scst_set_invalid_field_in_cdb(cmd, cmd->len_off, 0);
		goto out_done;
	}

	wsp = kzalloc(sizeof(*wsp), GFP_KERNEL);
	if (wsp == NULL) {
		PRINT_ERROR("Unable to allocate ws_priv (size %zd, cmd %p)",
			sizeof(*wsp), cmd);
		goto out_busy;
	}

	mutex_init(&wsp->ws_mutex);
	wsp->ws_finish_fn = scst_ws_write_cmd_finished;
	wsp->ws_orig_cmd = cmd;

	wsp->ws_cur_lba = cmd->lba;
	wsp->ws_left_to_send = cmd->data_len >> cmd->dev->block_shift;
	wsp->ws_max_each = SCST_MAX_EACH_INTERNAL_IO_SIZE >> cmd->dev->block_shift;

	wsp->ws_sg_cnt = min_t(int, wsp->ws_left_to_send, wsp->ws_max_each);
	wsp->ws_sg = kmalloc(wsp->ws_sg_cnt * sizeof(*wsp->ws_sg), GFP_KERNEL);
	if (wsp->ws_sg == NULL) {
		PRINT_ERROR("Unable to alloc sg for %d entries", wsp->ws_sg_cnt);
		goto out_free;
	}
	sg_init_table(wsp->ws_sg, wsp->ws_sg_cnt);

	for (i = 0; i < wsp->ws_sg_cnt; i++) {
		sg_set_page(&wsp->ws_sg[i], sg_page(cmd->sg),
			cmd->sg->length, cmd->sg->offset);
	}

	scst_ws_gen_writes(wsp);

out:
	TRACE_EXIT();
	return;

out_free:
	kfree(wsp);

out_busy:
	scst_set_busy(cmd);

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_THREAD);
	goto out;
}
EXPORT_SYMBOL_GPL(scst_write_same);

int scst_finish_internal_cmd(struct scst_cmd *cmd)
{
	int res;
	unsigned long flags;

	TRACE_ENTRY();

	sBUG_ON(!cmd->internal);

	if (scst_cmd_atomic(cmd)) {
		TRACE_DBG("Rescheduling finished internal atomic cmd %p in a "
			"thread context", cmd);
		res = SCST_CMD_STATE_RES_NEED_THREAD;
		goto out;
	}

	spin_lock_irqsave(&cmd->sess->sess_list_lock, flags);
	list_del(&cmd->sess_cmd_list_entry);
	cmd->done = 1;
	cmd->finished = 1;
	spin_unlock_irqrestore(&cmd->sess->sess_list_lock, flags);

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		scst_done_cmd_mgmt(cmd);
		scst_finish_cmd_mgmt(cmd);
	}

	if (cmd->cdb[0] == REQUEST_SENSE)
		scst_complete_request_sense(cmd);
	else {
		scst_i_finish_fn_t f = (void *) *((unsigned long long **)cmd->tgt_i_priv);
		f(cmd);
	}

	__scst_cmd_put(cmd);

	res = SCST_CMD_STATE_RES_CONT_NEXT;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

static void scst_send_release(struct scst_device *dev)
{
	struct scsi_device *scsi_dev;
	unsigned char cdb[6];
	uint8_t sense[SCSI_SENSE_BUFFERSIZE];
	int rc, i;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL)
		goto out;

	scsi_dev = dev->scsi_dev;

	for (i = 0; i < 5; i++) {
		memset(cdb, 0, sizeof(cdb));
		cdb[0] = RELEASE;
		cdb[1] = (scsi_dev->scsi_level <= SCSI_2) ?
		    ((scsi_dev->lun << 5) & 0xe0) : 0;

		memset(sense, 0, sizeof(sense));

		TRACE(TRACE_DEBUG | TRACE_SCSI, "%s", "Sending RELEASE req to "
			"SCSI mid-level");
		rc = scsi_execute(scsi_dev, cdb, SCST_DATA_NONE, NULL, 0,
				sense, 15, 0, 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
				, NULL
#endif
				);
		TRACE_DBG("MODE_SENSE done: %x", rc);

		if (scsi_status_is_good(rc)) {
			break;
		} else {
			PRINT_ERROR("RELEASE failed: %d", rc);
			PRINT_BUFFER("RELEASE sense", sense, sizeof(sense));
			scst_check_internal_sense(dev, rc, sense,
				sizeof(sense));
		}
	}

out:
	TRACE_EXIT();
	return;
}

/* scst_mutex supposed to be held */
static void scst_clear_reservation(struct scst_tgt_dev *tgt_dev)
{
	struct scst_device *dev = tgt_dev->dev;
	int release = 0;

	TRACE_ENTRY();

	spin_lock_bh(&dev->dev_lock);
	if (scst_is_reservation_holder(dev, tgt_dev->sess)) {
		/* This is one who holds the reservation */
		scst_clear_dev_reservation(dev);
		release = 1;
	}
	spin_unlock_bh(&dev->dev_lock);

	if (release)
		scst_send_release(dev);

	TRACE_EXIT();
	return;
}

struct scst_session *scst_alloc_session(struct scst_tgt *tgt, gfp_t gfp_mask,
	const char *initiator_name)
{
	struct scst_session *sess;
	int i;

	TRACE_ENTRY();

	sess = kmem_cache_zalloc(scst_sess_cachep, gfp_mask);
	if (sess == NULL) {
		PRINT_ERROR("%s", "Allocation of scst_session failed");
		goto out;
	}

	sess->init_phase = SCST_SESS_IPH_INITING;
	sess->shut_phase = SCST_SESS_SPH_READY;
	atomic_set(&sess->refcnt, 0);
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &sess->sess_tgt_dev_list[i];
		INIT_LIST_HEAD(head);
	}
	spin_lock_init(&sess->sess_list_lock);
	INIT_LIST_HEAD(&sess->sess_cmd_list);
	sess->tgt = tgt;
	INIT_LIST_HEAD(&sess->init_deferred_cmd_list);
	INIT_LIST_HEAD(&sess->init_deferred_mcmd_list);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
	INIT_DELAYED_WORK(&sess->hw_pending_work, scst_hw_pending_work_fn);
#else
	INIT_WORK(&sess->hw_pending_work, scst_hw_pending_work_fn, sess);
#endif

#ifdef CONFIG_SCST_MEASURE_LATENCY
	spin_lock_init(&sess->lat_lock);
#endif

	sess->initiator_name = kstrdup(initiator_name, gfp_mask);
	if (sess->initiator_name == NULL) {
		PRINT_ERROR("%s", "Unable to dup sess->initiator_name");
		goto out_free;
	}

out:
	TRACE_EXIT();
	return sess;

out_free:
	kmem_cache_free(scst_sess_cachep, sess);
	sess = NULL;
	goto out;
}

void scst_free_session(struct scst_session *sess)
{
	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	scst_sess_free_tgt_devs(sess);

	TRACE_DBG("Removing sess %p from the list", sess);
	list_del(&sess->sess_list_entry);

	TRACE_DBG("Removing session %p from acg %s", sess, sess->acg->acg_name);
	list_del(&sess->acg_sess_list_entry);

	mutex_unlock(&scst_mutex);

#ifndef CONFIG_SCST_PROC
	scst_sess_sysfs_del(sess);
#endif
	if (sess->unreg_done_fn) {
		TRACE_DBG("Calling unreg_done_fn(%p)", sess);
		sess->unreg_done_fn(sess);
		TRACE_DBG("%s", "unreg_done_fn() returned");
	}

	mutex_lock(&scst_mutex);

	list_del(&sess->sysfs_sess_list_entry);

	/* Called under lock to protect from too early tgt release */
	wake_up_all(&sess->tgt->unreg_waitQ);

	/*
	 * NOTE: do not dereference the sess->tgt pointer after scst_mutex
	 * has been unlocked, because it can be already dead!!
	 */
	mutex_unlock(&scst_mutex);

	kfree(sess->transport_id);
	kfree(sess->initiator_name);
	if (sess->sess_name != sess->initiator_name)
		kfree(sess->sess_name);

	kmem_cache_free(scst_sess_cachep, sess);

	TRACE_EXIT();
	return;
}

void scst_free_session_callback(struct scst_session *sess)
{
	struct completion *c;

	TRACE_ENTRY();

	TRACE_DBG("Freeing session %p", sess);

	cancel_delayed_work_sync(&sess->hw_pending_work);

	c = sess->shutdown_compl;

	mutex_lock(&scst_mutex);
	/*
	 * Necessary to sync with other threads trying to queue AEN, which
	 * the target driver will not be able to serve and crash, because after
	 * unreg_done_fn() called its internal session data will be destroyed.
	 */
	sess->shut_phase = SCST_SESS_SPH_UNREG_DONE_CALLING;
	mutex_unlock(&scst_mutex);

	scst_free_session(sess);

	if (c)
		complete_all(c);

	TRACE_EXIT();
	return;
}

void scst_sched_session_free(struct scst_session *sess)
{
	unsigned long flags;

	TRACE_ENTRY();

	if (sess->shut_phase != SCST_SESS_SPH_SHUTDOWN) {
		PRINT_CRIT_ERROR("session %p is going to shutdown with unknown "
			"shut phase %lx", sess, sess->shut_phase);
		sBUG();
	}

	spin_lock_irqsave(&scst_mgmt_lock, flags);
	TRACE_DBG("Adding sess %p to scst_sess_shut_list", sess);
	list_add_tail(&sess->sess_shut_list_entry, &scst_sess_shut_list);
	spin_unlock_irqrestore(&scst_mgmt_lock, flags);

	wake_up(&scst_mgmt_waitQ);

	TRACE_EXIT();
	return;
}

/**
 * scst_cmd_get() - increase command's reference counter
 */
void scst_cmd_get(struct scst_cmd *cmd)
{
	__scst_cmd_get(cmd);
}
EXPORT_SYMBOL(scst_cmd_get);

/**
 * scst_cmd_put() - decrease command's reference counter
 */
void scst_cmd_put(struct scst_cmd *cmd)
{
	__scst_cmd_put(cmd);
}
EXPORT_SYMBOL(scst_cmd_put);

/**
 * scst_cmd_set_ext_cdb() - sets cmd's extended CDB and its length
 */
void scst_cmd_set_ext_cdb(struct scst_cmd *cmd,
	uint8_t *ext_cdb, unsigned int ext_cdb_len,
	gfp_t gfp_mask)
{
	unsigned int len = cmd->cdb_len + ext_cdb_len;

	TRACE_ENTRY();

	if (len <= sizeof(cmd->cdb_buf))
		goto copy;

	if (unlikely(len > SCST_MAX_LONG_CDB_SIZE)) {
		PRINT_ERROR("Too big CDB (%d)", len);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	/* It's read-mostly, so cache alignment isn't needed */
	cmd->cdb = kmalloc(len, gfp_mask);
	if (unlikely(cmd->cdb == NULL)) {
		PRINT_ERROR("Unable to alloc extended CDB (size %d)", len);
		goto out_err;
	}

	memcpy(cmd->cdb, cmd->cdb_buf, cmd->cdb_len);

copy:
	memcpy(&cmd->cdb[cmd->cdb_len], ext_cdb, ext_cdb_len);

	cmd->cdb_len = cmd->cdb_len + ext_cdb_len;

out:
	TRACE_EXIT();
	return;

out_err:
	cmd->cdb = cmd->cdb_buf;
	scst_set_busy(cmd);
	goto out;
}
EXPORT_SYMBOL(scst_cmd_set_ext_cdb);

int scst_pre_init_cmd(struct scst_cmd *cmd, const uint8_t *cdb,
	unsigned int cdb_len, gfp_t gfp_mask)
{
	int res;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	/* cmd supposed to be zeroed */
	{
		int i;
		uint8_t *b = (uint8_t *)cmd;
		for (i = 0; i < sizeof(*cmd); i++)
			EXTRACHECKS_BUG_ON(b[i] != 0);
	}
#endif

	cmd->state = SCST_CMD_STATE_INIT_WAIT;
	cmd->start_time = jiffies;
	atomic_set(&cmd->cmd_ref, 1);
	cmd->cmd_threads = &scst_main_cmd_threads;
	cmd->cmd_gfp_mask = GFP_KERNEL;
	INIT_LIST_HEAD(&cmd->mgmt_cmd_list);
	cmd->cdb = cmd->cdb_buf;
	cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
	cmd->timeout = SCST_DEFAULT_TIMEOUT;
	cmd->retries = 0;
#ifdef CONFIG_SCST_EXTRACHECKS
	/* To ensure they are inited */
	cmd->lba = SCST_DEF_LBA_DATA_LEN;
	cmd->data_len = SCST_DEF_LBA_DATA_LEN;
#endif
	cmd->is_send_status = 1;
	cmd->resp_data_len = -1;
	cmd->write_sg = &cmd->sg;
	cmd->write_sg_cnt = &cmd->sg_cnt;

	cmd->dbl_ua_orig_data_direction = SCST_DATA_UNKNOWN;
	cmd->dbl_ua_orig_resp_data_len = -1;

	if (unlikely(cdb_len == 0)) {
		PRINT_ERROR("%s", "Wrong CDB len 0, finishing cmd");
		res = -EINVAL;
		goto out;
	} else if (cdb_len <= SCST_MAX_CDB_SIZE) {
		/* Duplicate memcpy to save a branch on the most common path */
		memcpy(cmd->cdb, cdb, cdb_len);
	} else {
		if (unlikely(cdb_len > SCST_MAX_LONG_CDB_SIZE)) {
			PRINT_ERROR("Too big CDB (%d), finishing cmd", cdb_len);
			res = -EINVAL;
			goto out;
		}
		/* It's read-mostly, so cache alignment isn't needed */
		cmd->cdb = kmalloc(cdb_len, gfp_mask);
		if (unlikely(cmd->cdb == NULL)) {
			PRINT_ERROR("Unable to alloc extended CDB (size %d)",
				cdb_len);
			res = -ENOMEM;
			goto out;
		}
		memcpy(cmd->cdb, cdb, cdb_len);
	}

	cmd->cdb_len = cdb_len;

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

struct scst_cmd *scst_alloc_cmd(const uint8_t *cdb,
	unsigned int cdb_len, gfp_t gfp_mask)
{
	struct scst_cmd *cmd;
	int rc;

	TRACE_ENTRY();

	cmd = kmem_cache_zalloc(scst_cmd_cachep, gfp_mask);
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of scst_cmd failed");
		goto out;
	}

	rc = scst_pre_init_cmd(cmd, cdb, cdb_len, gfp_mask);
	if (unlikely(rc != 0))
		goto out_free;

out:
	TRACE_EXIT();
	return cmd;

out_free:
	kmem_cache_free(scst_cmd_cachep, cmd);
	cmd = NULL;
	goto out;
}

static void scst_destroy_cmd(struct scst_cmd *cmd)
{
	bool pre_alloced = cmd->pre_alloced;

	TRACE_ENTRY();

	TRACE_DBG("Destroying cmd %p", cmd);

	scst_sess_put(cmd->sess);

	/*
	 * At this point tgt_dev can be dead, but the pointer remains non-NULL
	 */
	if (likely(cmd->tgt_dev != NULL))
		scst_put(cmd->cpu_cmd_counter);

	EXTRACHECKS_BUG_ON(cmd->pre_alloced && cmd->internal);

	if ((cmd->tgtt->on_free_cmd != NULL) && likely(!cmd->internal)) {
		TRACE_DBG("Calling target's on_free_cmd(%p)", cmd);
		cmd->tgtt->on_free_cmd(cmd);
		TRACE_DBG("%s", "Target's on_free_cmd() returned");
	}

	/* At this point cmd can be already freed! */

	if (!pre_alloced)
		kmem_cache_free(scst_cmd_cachep, cmd);

	TRACE_EXIT();
	return;
}

/* No locks supposed to be held */
void scst_free_cmd(struct scst_cmd *cmd)
{
	int destroy = 1;

	TRACE_ENTRY();

	TRACE_DBG("Freeing cmd %p (tag %llu)",
		  cmd, (long long unsigned int)cmd->tag);

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
		TRACE_MGMT_DBG("Freeing aborted cmd %p", cmd);

	EXTRACHECKS_BUG_ON(cmd->unblock_dev || cmd->dec_on_dev_needed ||
		cmd->dec_pr_readers_count_needed);

	/*
	 * Target driver can already free sg buffer before calling
	 * scst_tgt_cmd_done(). E.g., scst_local has to do that.
	 */
	if (!cmd->tgt_i_data_buf_alloced)
		scst_check_restore_sg_buff(cmd);

	if (likely(cmd->dev != NULL)) {
		struct scst_dev_type *devt = cmd->devt;
		if (devt->on_free_cmd != NULL) {
			TRACE_DBG("Calling dev handler %s on_free_cmd(%p)",
				devt->name, cmd);
			devt->on_free_cmd(cmd);
			TRACE_DBG("Dev handler %s on_free_cmd() returned",
				devt->name);
		}
	}

	scst_release_space(cmd);

	if (unlikely(cmd->sense != NULL)) {
		TRACE_MEM("Releasing sense %p (cmd %p)", cmd->sense, cmd);
		mempool_free(cmd->sense, scst_sense_mempool);
		cmd->sense = NULL;
	}

	if (likely(cmd->tgt_dev != NULL)) {
		EXTRACHECKS_BUG_ON(!test_bit(SCST_CMD_INC_EXPECTED_SN_PASSED,
				      &cmd->cmd_flags) && cmd->sn_set && !cmd->out_of_sn);
		if (unlikely(cmd->out_of_sn)) {
			destroy = test_and_set_bit(SCST_CMD_CAN_BE_DESTROYED,
					&cmd->cmd_flags);
			TRACE_SN("Out of SN cmd %p (tag %llu, sn %d), "
				"destroy=%d", cmd,
				(long long unsigned int)cmd->tag,
				cmd->sn, destroy);
		}
	}

	if (unlikely(cmd->op_flags & SCST_DESCRIPTORS_BASED))
		scst_free_descriptors(cmd);

	if (cmd->cdb != cmd->cdb_buf)
		kfree(cmd->cdb);

	if (likely(destroy))
		scst_destroy_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* No locks supposed to be held. */
void scst_check_retries(struct scst_tgt *tgt)
{
	int need_wake_up = 0;

	TRACE_ENTRY();

	if (unlikely(tgt->retry_cmds > 0)) {
		struct scst_cmd *c, *tc;
		unsigned long flags;

		TRACE_RETRY("Checking retry cmd list (retry_cmds %d)",
		      tgt->retry_cmds);

		spin_lock_irqsave(&tgt->tgt_lock, flags);
		list_for_each_entry_safe(c, tc, &tgt->retry_cmd_list,
				cmd_list_entry) {
			tgt->retry_cmds--;

			TRACE_RETRY("Moving retry cmd %p to head of active "
				"cmd list (retry_cmds left %d)",
				c, tgt->retry_cmds);
			spin_lock(&c->cmd_threads->cmd_list_lock);
			list_move(&c->cmd_list_entry,
				  &c->cmd_threads->active_cmd_list);
			wake_up(&c->cmd_threads->cmd_list_waitQ);
			spin_unlock(&c->cmd_threads->cmd_list_lock);

			need_wake_up++;
			if (need_wake_up >= 20) /* "slow start" */
				break;
		}
		spin_unlock_irqrestore(&tgt->tgt_lock, flags);
	}

	TRACE_EXIT();
	return;
}

static void scst_tgt_retry_timer_fn(unsigned long arg)
{
	struct scst_tgt *tgt = (struct scst_tgt *)arg;
	unsigned long flags;

	TRACE_RETRY("Retry timer expired (retry_cmds %d)", tgt->retry_cmds);

	spin_lock_irqsave(&tgt->tgt_lock, flags);
	tgt->retry_timer_active = 0;
	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	scst_check_retries(tgt);

	spin_lock_irqsave(&tgt->tgt_lock, flags);
	if ((tgt->retry_cmds > 0) && !tgt->retry_timer_active) {
		TRACE_DBG("Reactivating retry timer for tgt %p", tgt);
		tgt->retry_timer.expires = jiffies + SCST_TGT_RETRY_TIMEOUT;
		add_timer(&tgt->retry_timer);
		tgt->retry_timer_active = 1;
	}
	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	TRACE_EXIT();
	return;
}

struct scst_mgmt_cmd *scst_alloc_mgmt_cmd(gfp_t gfp_mask)
{
	struct scst_mgmt_cmd *mcmd;

	TRACE_ENTRY();

	mcmd = mempool_alloc(scst_mgmt_mempool, gfp_mask);
	if (mcmd == NULL) {
		PRINT_CRIT_ERROR("%s", "Allocation of management command "
			"failed, some commands and their data could leak");
		goto out;
	}
	memset(mcmd, 0, sizeof(*mcmd));

	mcmd->status = SCST_MGMT_STATUS_SUCCESS;

out:
	TRACE_EXIT();
	return mcmd;
}

void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd)
{
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&mcmd->sess->sess_list_lock, flags);
	atomic_dec(&mcmd->sess->sess_cmd_count);
	spin_unlock_irqrestore(&mcmd->sess->sess_list_lock, flags);

	scst_sess_put(mcmd->sess);

	if (mcmd->mcmd_tgt_dev != NULL)
		scst_put(mcmd->cpu_cmd_counter);

	mempool_free(mcmd, scst_mgmt_mempool);

	TRACE_EXIT();
	return;
}

static bool scst_on_sg_tablesize_low(struct scst_cmd *cmd, bool out)
{
	bool res;
	int sg_cnt = out ? cmd->out_sg_cnt : cmd->sg_cnt;
	static int ll;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	if (sg_cnt > cmd->tgt->sg_tablesize) {
		/* It's the target's side business */
		goto failed;
	}

	if (cmd->devt->on_sg_tablesize_low == NULL)
		goto failed;

	res = cmd->devt->on_sg_tablesize_low(cmd);

	TRACE_DBG("on_sg_tablesize_low(%p) returned %d", cmd, res);

out:
	TRACE_EXIT_RES(res);
	return res;

failed:
	res = false;
	if ((ll < 10) || TRACING_MINOR()) {
		PRINT_INFO("Unable to complete command due to SG IO count "
			"limitation (%srequested %d, available %d, tgt lim %d)",
			out ? "OUT buffer, " : "", cmd->sg_cnt,
			tgt_dev->max_sg_cnt, cmd->tgt->sg_tablesize);
		ll++;
	}
	goto out;
}

int scst_alloc_space(struct scst_cmd *cmd)
{
	gfp_t gfp_mask;
	int res = -ENOMEM;
	int atomic = scst_cmd_atomic(cmd);
	int flags;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	gfp_mask = tgt_dev->tgt_dev_gfp_mask | (atomic ? GFP_ATOMIC : cmd->cmd_gfp_mask);

	flags = atomic ? SGV_POOL_NO_ALLOC_ON_CACHE_MISS : 0;
	if (cmd->no_sgv)
		flags |= SGV_POOL_ALLOC_NO_CACHED;

	cmd->sg = sgv_pool_alloc(tgt_dev->pool, cmd->bufflen, gfp_mask, flags,
			&cmd->sg_cnt, &cmd->sgv, &cmd->dev->dev_mem_lim, NULL);
	if (unlikely(cmd->sg == NULL))
		goto out;

	if (unlikely(cmd->sg_cnt > tgt_dev->max_sg_cnt))
		if (!scst_on_sg_tablesize_low(cmd, false))
			goto out_sg_free;

	if (cmd->data_direction != SCST_DATA_BIDI)
		goto success;

	cmd->out_sg = sgv_pool_alloc(tgt_dev->pool, cmd->out_bufflen, gfp_mask,
			 flags, &cmd->out_sg_cnt, &cmd->out_sgv,
			 &cmd->dev->dev_mem_lim, NULL);
	if (unlikely(cmd->out_sg == NULL))
		goto out_sg_free;

	if (unlikely(cmd->out_sg_cnt > tgt_dev->max_sg_cnt))
		if (!scst_on_sg_tablesize_low(cmd, true))
			goto out_out_sg_free;

success:
	res = 0;

out:
	TRACE_EXIT();
	return res;

out_out_sg_free:
	sgv_pool_free(cmd->out_sgv, &cmd->dev->dev_mem_lim);
	cmd->out_sgv = NULL;
	cmd->out_sg = NULL;
	cmd->out_sg_cnt = 0;

out_sg_free:
	sgv_pool_free(cmd->sgv, &cmd->dev->dev_mem_lim);
	cmd->sgv = NULL;
	cmd->sg = NULL;
	cmd->sg_cnt = 0;
	goto out;
}

static void scst_release_space(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (cmd->sgv == NULL) {
		if ((cmd->sg != NULL) &&
		    !(cmd->tgt_i_data_buf_alloced || cmd->dh_data_buf_alloced)) {
			TRACE_MEM("Freeing sg %p for cmd %p (cnt %d)", cmd->sg,
				cmd, cmd->sg_cnt);
			scst_free_sg(cmd->sg, cmd->sg_cnt);
			goto out_zero;
		} else
			goto out;
	}

	if (cmd->tgt_i_data_buf_alloced || cmd->dh_data_buf_alloced) {
		TRACE_MEM("%s", "*data_buf_alloced set, returning");
		goto out;
	}

	if (cmd->out_sgv != NULL) {
		sgv_pool_free(cmd->out_sgv, &cmd->dev->dev_mem_lim);
		cmd->out_sgv = NULL;
		cmd->out_sg_cnt = 0;
		cmd->out_sg = NULL;
		cmd->out_bufflen = 0;
	}

	sgv_pool_free(cmd->sgv, &cmd->dev->dev_mem_lim);

out_zero:
	cmd->sgv = NULL;
	cmd->sg_cnt = 0;
	cmd->sg = NULL;
	cmd->bufflen = 0;
	cmd->data_len = 0;

out:
	TRACE_EXIT();
	return;
}

#if !((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)) && !defined(HAVE_SG_COPY)

/*
 * Can switch to the next dst_sg element, so, to copy to strictly only
 * one dst_sg element, it must be either last in the chain, or
 * copy_len == dst_sg->length.
 */
static int sg_copy_elem(struct scatterlist **pdst_sg, size_t *pdst_len,
			size_t *pdst_offs, struct scatterlist *src_sg,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
			size_t copy_len,
			enum km_type d_km_type, enum km_type s_km_type)
#else
			size_t copy_len)
#endif
{
	int res = 0;
	struct scatterlist *dst_sg;
	size_t src_len, dst_len, src_offs, dst_offs;
	struct page *src_page, *dst_page;

	dst_sg = *pdst_sg;
	dst_len = *pdst_len;
	dst_offs = *pdst_offs;
	dst_page = sg_page(dst_sg);

	src_page = sg_page(src_sg);
	src_len = src_sg->length;
	src_offs = src_sg->offset;

	do {
		void *saddr, *daddr;
		size_t n;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
		saddr = kmap_atomic(src_page +
					 (src_offs >> PAGE_SHIFT), s_km_type) +
				    (src_offs & ~PAGE_MASK);
		daddr = kmap_atomic(dst_page +
					(dst_offs >> PAGE_SHIFT), d_km_type) +
				    (dst_offs & ~PAGE_MASK);
#else
		saddr = kmap_atomic(src_page + (src_offs >> PAGE_SHIFT)) +
			(src_offs & ~PAGE_MASK);
		daddr = kmap_atomic(dst_page + (dst_offs >> PAGE_SHIFT)) +
			(dst_offs & ~PAGE_MASK);
#endif

		if (((src_offs & ~PAGE_MASK) == 0) &&
		    ((dst_offs & ~PAGE_MASK) == 0) &&
		    (src_len >= PAGE_SIZE) && (dst_len >= PAGE_SIZE) &&
		    (copy_len >= PAGE_SIZE)) {
			copy_page(daddr, saddr);
			n = PAGE_SIZE;
		} else {
			n = min_t(size_t, PAGE_SIZE - (dst_offs & ~PAGE_MASK),
					  PAGE_SIZE - (src_offs & ~PAGE_MASK));
			n = min(n, src_len);
			n = min(n, dst_len);
			n = min_t(size_t, n, copy_len);
			memcpy(daddr, saddr, n);
		}
		dst_offs += n;
		src_offs += n;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
		kunmap_atomic(saddr, s_km_type);
		kunmap_atomic(daddr, d_km_type);
#else
		kunmap_atomic(saddr);
		kunmap_atomic(daddr);
#endif

		res += n;
		copy_len -= n;
		if (copy_len == 0)
			goto out;

		src_len -= n;
		dst_len -= n;
		if (dst_len == 0) {
			dst_sg = sg_next_inline(dst_sg);
			if (dst_sg == NULL)
				goto out;
			dst_page = sg_page(dst_sg);
			dst_len = dst_sg->length;
			dst_offs = dst_sg->offset;
		}
	} while (src_len > 0);

out:
	*pdst_sg = dst_sg;
	*pdst_len = dst_len;
	*pdst_offs = dst_offs;
	return res;
}

/**
 * sg_copy - copy one SG vector to another
 * @dst_sg:	destination SG
 * @src_sg:	source SG
 * @nents_to_copy: maximum number of entries to copy
 * @copy_len:	maximum amount of data to copy. If 0, then copy all.
 * @d_km_type:	kmap_atomic type for the destination SG
 * @s_km_type:	kmap_atomic type for the source SG
 *
 * Description:
 *    Data from the source SG vector will be copied to the destination SG
 *    vector. End of the vectors will be determined by sg_next() returning
 *    NULL. Returns number of bytes copied.
 */
static int sg_copy(struct scatterlist *dst_sg, struct scatterlist *src_sg,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
	    int nents_to_copy, size_t copy_len,
	    enum km_type d_km_type, enum km_type s_km_type)
#else
	    int nents_to_copy, size_t copy_len)
#endif
{
	int res = 0;
	size_t dst_len, dst_offs;

	if (copy_len == 0)
		copy_len = 0x7FFFFFFF; /* copy all */

	if (nents_to_copy == 0)
		nents_to_copy = 0x7FFFFFFF; /* copy all */

	dst_len = dst_sg->length;
	dst_offs = dst_sg->offset;

	do {
		int copied = sg_copy_elem(&dst_sg, &dst_len, &dst_offs,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
				src_sg, copy_len, d_km_type, s_km_type);
#else
				src_sg, copy_len);
#endif
		copy_len -= copied;
		res += copied;
		if ((copy_len == 0) || (dst_sg == NULL))
			goto out;

		nents_to_copy--;
		if (nents_to_copy == 0)
			goto out;

		src_sg = sg_next_inline(src_sg);
	} while (src_sg != NULL);

out:
	return res;
}

#endif /* !((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)
static void scsi_end_async(struct request *req, int error)
{
	struct scsi_io_context *sioc = req->end_io_data;

	TRACE_DBG("sioc %p, cmd %p", sioc, sioc->data);

	if (sioc->done)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 30)
		sioc->done(sioc->data, sioc->sense, req->errors, req->data_len);
#else
		sioc->done(sioc->data, sioc->sense, req->errors, req->resid_len);
#endif

	kmem_cache_free(scsi_io_context_cache, sioc);

	__blk_put_request(req->q, req);
	return;
}

/**
 * scst_scsi_exec_async - executes a SCSI command in pass-through mode
 * @cmd:	scst command
 * @data:	pointer passed to done() as "data"
 * @done:	callback function when done
 */
int scst_scsi_exec_async(struct scst_cmd *cmd, void *data,
	void (*done)(void *data, char *sense, int result, int resid))
{
	int res = 0;
	struct request_queue *q = cmd->dev->scsi_dev->request_queue;
	struct request *rq;
	struct scsi_io_context *sioc;
	int write = (cmd->data_direction & SCST_DATA_WRITE) ? WRITE : READ;
	gfp_t gfp = cmd->cmd_gfp_mask;
	int cmd_len = cmd->cdb_len;

	sioc = kmem_cache_zalloc(scsi_io_context_cache, gfp);
	if (sioc == NULL) {
		res = -ENOMEM;
		goto out;
	}

	rq = blk_get_request(q, write, gfp);
	if (rq == NULL) {
		res = -ENOMEM;
		goto out_free_sioc;
	}

	rq->cmd_type = REQ_TYPE_BLOCK_PC;
	rq->cmd_flags |= REQ_QUIET;

	if (cmd->sg == NULL)
		goto done;

	if (cmd->data_direction == SCST_DATA_BIDI) {
		struct request *next_rq;

		if (!test_bit(QUEUE_FLAG_BIDI, &q->queue_flags)) {
			res = -EOPNOTSUPP;
			goto out_free_rq;
		}

		res = blk_rq_map_kern_sg(rq, cmd->out_sg, cmd->out_sg_cnt, gfp);
		if (res != 0) {
			TRACE_DBG("blk_rq_map_kern_sg() failed: %d", res);
			goto out_free_rq;
		}

		next_rq = blk_get_request(q, READ, gfp);
		if (next_rq == NULL) {
			res = -ENOMEM;
			goto out_free_unmap;
		}
		rq->next_rq = next_rq;
		next_rq->cmd_type = rq->cmd_type;

		res = blk_rq_map_kern_sg(next_rq, cmd->sg, cmd->sg_cnt, gfp);
		if (res != 0) {
			TRACE_DBG("blk_rq_map_kern_sg() failed: %d", res);
			goto out_free_unmap;
		}
	} else {
		res = blk_rq_map_kern_sg(rq, cmd->sg, cmd->sg_cnt, gfp);
		if (res != 0) {
			TRACE_DBG("blk_rq_map_kern_sg() failed: %d", res);
			goto out_free_rq;
		}
	}

done:
	TRACE_DBG("sioc %p, cmd %p", sioc, cmd);

	sioc->data = data;
	sioc->done = done;

	rq->cmd_len = cmd_len;
	if (rq->cmd_len <= BLK_MAX_CDB) {
		memset(rq->cmd, 0, BLK_MAX_CDB); /* ATAPI hates garbage after CDB */
		memcpy(rq->cmd, cmd->cdb, cmd->cdb_len);
	} else
		rq->cmd = cmd->cdb;

	rq->sense = sioc->sense;
	rq->sense_len = sizeof(sioc->sense);
	rq->timeout = cmd->timeout;
	rq->retries = cmd->retries;
	rq->end_io_data = sioc;

	blk_execute_rq_nowait(rq->q, NULL, rq,
		(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE), scsi_end_async);
out:
	return res;

out_free_unmap:
	if (rq->next_rq != NULL) {
		blk_put_request(rq->next_rq);
		rq->next_rq = NULL;
	}
	blk_rq_unmap_kern_sg(rq, res);

out_free_rq:
	blk_put_request(rq);

out_free_sioc:
	kmem_cache_free(scsi_io_context_cache, sioc);
	goto out;
}
EXPORT_SYMBOL(scst_scsi_exec_async);

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30) && defined(SCSI_EXEC_REQ_FIFO_DEFINED) */

/**
 * scst_copy_sg() - copy data between the command's SGs
 *
 * Copies data between cmd->tgt_i_sg and cmd->sg in direction defined by
 * copy_dir parameter.
 */
void scst_copy_sg(struct scst_cmd *cmd, enum scst_sg_copy_dir copy_dir)
{
	struct scatterlist *src_sg, *dst_sg;
	unsigned int to_copy;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
	int atomic = scst_cmd_atomic(cmd);
#endif

	TRACE_ENTRY();

	if (copy_dir == SCST_SG_COPY_FROM_TARGET) {
		if (cmd->data_direction != SCST_DATA_BIDI) {
			src_sg = cmd->tgt_i_sg;
			dst_sg = cmd->sg;
			to_copy = cmd->bufflen;
		} else {
			TRACE_MEM("BIDI cmd %p", cmd);
			src_sg = cmd->tgt_out_sg;
			dst_sg = cmd->out_sg;
			to_copy = cmd->out_bufflen;
		}
	} else {
		src_sg = cmd->sg;
		dst_sg = cmd->tgt_i_sg;
		to_copy = cmd->adjusted_resp_data_len;
	}

	TRACE_MEM("cmd %p, copy_dir %d, src_sg %p, dst_sg %p, to_copy %lld",
		cmd, copy_dir, src_sg, dst_sg, (long long)to_copy);

	if (unlikely(src_sg == NULL) || unlikely(dst_sg == NULL) ||
	    unlikely(to_copy == 0)) {
		/*
		 * It can happened, e.g., with scst_user for cmd with delay
		 * alloc, which failed with Check Condition.
		 */
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
	sg_copy(dst_sg, src_sg, 0, to_copy,
		atomic ? KM_SOFTIRQ0 : KM_USER0,
		atomic ? KM_SOFTIRQ1 : KM_USER1);
#else
	sg_copy(dst_sg, src_sg, 0, to_copy);
#endif

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_copy_sg);

/**
 * scst_get_buf_full - return linear buffer for command
 * @cmd:	scst command
 * @buf:	pointer on the resulting pointer
 *
 * If the command's buffer >single page, it vmalloc() the needed area
 * and copies the buffer there. Returns length of the buffer or negative
 * error code otherwise.
 */
int scst_get_buf_full(struct scst_cmd *cmd, uint8_t **buf)
{
	int res = 0;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->sg_buff_vmallocated);

	if (scst_get_buf_count(cmd) > 1) {
		int len;
		uint8_t *tmp_buf;
		int full_size;

		full_size = 0;
		len = scst_get_buf_first(cmd, &tmp_buf);
		while (len > 0) {
			full_size += len;
			scst_put_buf(cmd, tmp_buf);
			len = scst_get_buf_next(cmd, &tmp_buf);
		}

		*buf = vmalloc(full_size);
		if (*buf == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "vmalloc() failed for opcode "
				"%x", cmd->cdb[0]);
			res = -ENOMEM;
			goto out;
		}
		cmd->sg_buff_vmallocated = 1;

		if (scst_cmd_get_data_direction(cmd) == SCST_DATA_WRITE) {
			uint8_t *buf_ptr;

			buf_ptr = *buf;

			len = scst_get_buf_first(cmd, &tmp_buf);
			while (len > 0) {
				memcpy(buf_ptr, tmp_buf, len);
				buf_ptr += len;

				scst_put_buf(cmd, tmp_buf);
				len = scst_get_buf_next(cmd, &tmp_buf);
			}
		}
		res = full_size;
	} else
		res = scst_get_buf_first(cmd, buf);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_get_buf_full);

/**
 * scst_get_buf_full_sense - return linear buffer for command
 * @cmd:	scst command
 * @buf:	pointer on the resulting pointer
 *
 * Does the same as scst_get_buf_full(), but in case of error
 * additionally sets in cmd status code and sense.
 */
int scst_get_buf_full_sense(struct scst_cmd *cmd, uint8_t **buf)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_get_buf_full(cmd, buf);
	if (unlikely(res < 0)) {
		PRINT_ERROR("scst_get_buf_full() failed: %d", res);
		if (res == -ENOMEM)
			scst_set_busy(cmd);
		else
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_get_buf_full_sense);

/**
 * scst_put_buf_full - unmaps linear buffer for command
 * @cmd:	scst command
 * @buf:	pointer on the buffer to unmap
 *
 * Reverse operation for scst_get_buf_full()/scst_get_buf_full_sense().
 * If the buffer was vmalloced(), it vfree() the buffer.
 */
void scst_put_buf_full(struct scst_cmd *cmd, uint8_t *buf)
{
	TRACE_ENTRY();

	if (buf == NULL)
		goto out;

	if (cmd->sg_buff_vmallocated) {
		if (scst_cmd_get_data_direction(cmd) == SCST_DATA_READ) {
			int len;
			uint8_t *tmp_buf, *buf_p;

			buf_p = buf;

			len = scst_get_buf_first(cmd, &tmp_buf);
			while (len > 0) {
				memcpy(tmp_buf, buf_p, len);
				buf_p += len;

				scst_put_buf(cmd, tmp_buf);
				len = scst_get_buf_next(cmd, &tmp_buf);
			}

		}

		cmd->sg_buff_vmallocated = 0;

		vfree(buf);
	} else
		scst_put_buf(cmd, buf);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_put_buf_full);

static const int SCST_CDB_LENGTH[8] = { 6, 10, 10, 0, 16, 12, 0, 0 };

#define SCST_CDB_GROUP(opcode)   ((opcode >> 5) & 0x7)
#define SCST_GET_CDB_LEN(opcode) SCST_CDB_LENGTH[SCST_CDB_GROUP(opcode)]

static int get_cdb_info_len_10(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->cdb_len = 10;
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	/* It supposed to be already zeroed */
	EXTRACHECKS_BUG_ON(cmd->bufflen != 0);

	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_block_limit(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;
	cmd->bufflen = 6;
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_read_capacity(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;
	cmd->bufflen = 8;
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_serv_act_in(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	int res = 0;

	TRACE_ENTRY();

	cmd->lba = 0;

	switch (cmd->cdb[1] & 0x1f) {
	case SAI_READ_CAPACITY_16:
		cmd->op_name = "READ CAPACITY(16)";
		cmd->bufflen = get_unaligned_be32(&cmd->cdb[10]);
		if (unlikely(cmd->bufflen & SCST_MAX_VALID_BUFFLEN_MASK))
			goto out_inval_bufflen10;
		cmd->op_flags |= SCST_IMPLICIT_HQ | SCST_LBA_NOT_VALID |
				SCST_REG_RESERVE_ALLOWED |
				SCST_WRITE_EXCL_ALLOWED |
				SCST_EXCL_ACCESS_ALLOWED;
		break;
	case SAI_GET_LBA_STATUS:
		cmd->op_name = "GET LBA STATUS";
		cmd->lba = get_unaligned_be64(&cmd->cdb[2]);
		cmd->bufflen = get_unaligned_be32(&cmd->cdb[10]);
		if (unlikely(cmd->bufflen & SCST_MAX_VALID_BUFFLEN_MASK))
			goto out_inval_bufflen10;
		cmd->op_flags |= SCST_WRITE_EXCL_ALLOWED;
		break;
	default:
		cmd->op_flags |= SCST_UNKNOWN_LENGTH | SCST_LBA_NOT_VALID;
		break;
	}

	cmd->data_len = cmd->bufflen;

out:
	TRACE_EXIT_RES(res);
	return res;

out_inval_bufflen10:
	PRINT_ERROR("Too big bufflen %d (op %x)", cmd->bufflen, cmd->cdb[0]);
	scst_set_invalid_field_in_cdb(cmd, 10, 0);
	res = 1;
	goto out;
}

static int get_cdb_info_single(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;
	cmd->bufflen = 1;
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_read_pos(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	int res = 0;

	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	cmd->bufflen = get_unaligned_be16(cmd->cdb + sdbops->info_len_off);

	switch (cmd->cdb[1] & 0x1f) {
	case 0:
	case 1:
	case 6:
		if (cmd->bufflen != 0) {
			PRINT_ERROR("READ POSITION: Invalid non-zero (%d) "
				"allocation length for service action %x",
				cmd->bufflen, cmd->cdb[1] & 0x1f);
			goto out_inval_field1;
		}
		break;
	}

	switch (cmd->cdb[1] & 0x1f) {
	case 0:
	case 1:
		cmd->bufflen = 20;
		break;
	case 6:
		cmd->bufflen = 32;
		break;
	case 8:
		cmd->bufflen = max(28, cmd->bufflen);
		break;
	default:
		PRINT_ERROR("READ POSITION: Invalid service action %x",
			cmd->cdb[1] & 0x1f);
		goto out_inval_field1;
	}

	cmd->data_len = cmd->bufflen;

out:
	return res;

out_inval_field1:
	scst_set_invalid_field_in_cdb(cmd, 1, 0);
	res = 1;
	goto out;
}

static int get_cdb_info_prevent_allow_medium_removal(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	cmd->data_len = 0;
	/* It supposed to be already zeroed */
	EXTRACHECKS_BUG_ON(cmd->bufflen != 0);
	if ((cmd->cdb[4] & 3) == 0)
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
	return 0;
}

static int get_cdb_info_start_stop(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	cmd->data_len = 0;
	/* It supposed to be already zeroed */
	EXTRACHECKS_BUG_ON(cmd->bufflen != 0);
	if ((cmd->cdb[4] & 0xF1) == 0x1)
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
	return 0;
}

static int get_cdb_info_len_3_read_elem_stat(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	cmd->bufflen = get_unaligned_be24(cmd->cdb + sdbops->info_len_off);
	cmd->data_len = cmd->bufflen;

	if ((cmd->cdb[6] & 0x2) == 0x2)
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
	return 0;
}

static int get_cdb_info_bidi_lba_4_len_2(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be32(cmd->cdb + sdbops->info_lba_off);
	cmd->bufflen = get_unaligned_be16(cmd->cdb + sdbops->info_len_off);
	cmd->data_len = cmd->bufflen;
	cmd->out_bufflen = cmd->bufflen;
	return 0;
}

static int get_cdb_info_fmt(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;
	if (cmd->cdb[1] & 0x10/*FMTDATA*/) {
		cmd->data_direction = SCST_DATA_WRITE;
		cmd->op_flags |= SCST_UNKNOWN_LENGTH;
		cmd->bufflen = 4096; /* guess */
	} else
		cmd->bufflen = 0;
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_verify10(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be32(cmd->cdb + sdbops->info_lba_off);
	if (cmd->cdb[1] & BYTCHK) {
		cmd->bufflen = get_unaligned_be16(cmd->cdb + sdbops->info_len_off);
		cmd->data_len = cmd->bufflen;
		cmd->data_direction = SCST_DATA_WRITE;
	} else {
		cmd->bufflen = 0;
		cmd->data_len = get_unaligned_be16(cmd->cdb + sdbops->info_len_off);
		cmd->data_direction = SCST_DATA_NONE;
	}
	return 0;
}

static int get_cdb_info_verify6(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	if (cmd->cdb[1] & BYTCHK) {
		cmd->bufflen = get_unaligned_be24(cmd->cdb + sdbops->info_len_off);
		cmd->data_len = cmd->bufflen;
		cmd->data_direction = SCST_DATA_WRITE;
	} else {
		cmd->bufflen = 0;
		cmd->data_len = get_unaligned_be24(cmd->cdb + sdbops->info_len_off);
		cmd->data_direction = SCST_DATA_NONE;
	}
	return 0;
}

static int get_cdb_info_verify12(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be32(cmd->cdb + sdbops->info_lba_off);
	if (cmd->cdb[1] & BYTCHK) {
		cmd->bufflen = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
		if (unlikely(cmd->bufflen & SCST_MAX_VALID_BUFFLEN_MASK)) {
			PRINT_ERROR("Too big bufflen %d (op %x)",
				cmd->bufflen, cmd->cdb[0]);
			scst_set_invalid_field_in_cdb(cmd, sdbops->info_len_off, 0);
			return 1;
		}
		cmd->data_len = cmd->bufflen;
		cmd->data_direction = SCST_DATA_WRITE;
	} else {
		cmd->bufflen = 0;
		cmd->data_len = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
		cmd->data_direction = SCST_DATA_NONE;
	}
	return 0;
}

static int get_cdb_info_verify16(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be64(cmd->cdb + sdbops->info_lba_off);
	if (cmd->cdb[1] & BYTCHK) {
		cmd->bufflen = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
		if (unlikely(cmd->bufflen & SCST_MAX_VALID_BUFFLEN_MASK)) {
			PRINT_ERROR("Too big bufflen %d (op %x)",
				cmd->bufflen, cmd->cdb[0]);
			scst_set_invalid_field_in_cdb(cmd, sdbops->info_len_off, 0);
			return 1;
		}
		cmd->data_len = cmd->bufflen;
		cmd->data_direction = SCST_DATA_WRITE;
	} else {
		cmd->bufflen = 0;
		cmd->data_len = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
		cmd->data_direction = SCST_DATA_NONE;
	}
	return 0;
}

static int get_cdb_info_len_1(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	cmd->bufflen = cmd->cdb[sdbops->info_len_off];
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_lba_2_len_1_256(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be16(cmd->cdb + sdbops->info_lba_off);
	/*
	 * From the READ(6) specification: a TRANSFER LENGTH field set to zero
	 * specifies that 256 logical blocks shall be read.
	 *
	 * Note: while the C standard specifies that the behavior of a
	 * computation with signed integers that overflows is undefined, the
	 * same standard guarantees that the result of a computation with
	 * unsigned integers that cannot be represented will yield the value
	 * is reduced modulo the largest value that can be represented by the
	 * resulting type.
	 */
	cmd->bufflen = (u8)(cmd->cdb[sdbops->info_len_off] - 1) + 1;
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_len_2(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;
	cmd->bufflen = get_unaligned_be16(cmd->cdb + sdbops->info_len_off);
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_len_3(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;
	cmd->bufflen = get_unaligned_be24(cmd->cdb + sdbops->info_len_off);
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_len_4(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;
	cmd->bufflen = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
	if (unlikely(cmd->bufflen & SCST_MAX_VALID_BUFFLEN_MASK)) {
		PRINT_ERROR("Too big bufflen %d (op %x)", cmd->bufflen,
			cmd->cdb[0]);
		scst_set_invalid_field_in_cdb(cmd, sdbops->info_len_off, 0);
		return 1;
	}
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->op_flags |= SCST_LBA_NOT_VALID;
	cmd->lba = 0;

	/* It supposed to be already zeroed */
	EXTRACHECKS_BUG_ON(cmd->bufflen != 0);

	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_lba_2_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be16(cmd->cdb + sdbops->info_lba_off);

	/* It supposed to be already zeroed */
	EXTRACHECKS_BUG_ON(cmd->bufflen != 0);

	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_lba_4_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be32(cmd->cdb + sdbops->info_lba_off);

	/* It supposed to be already zeroed */
	EXTRACHECKS_BUG_ON(cmd->bufflen != 0);

	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_lba_8_none(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be64(cmd->cdb + sdbops->info_lba_off);

	/* It supposed to be already zeroed */
	EXTRACHECKS_BUG_ON(cmd->bufflen != 0);

	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_lba_4_len_2(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be32(cmd->cdb + sdbops->info_lba_off);
	cmd->bufflen = get_unaligned_be16(cmd->cdb + sdbops->info_len_off);
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_lba_4_len_4(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be32(cmd->cdb + sdbops->info_lba_off);
	cmd->bufflen = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
	if (unlikely(cmd->bufflen & SCST_MAX_VALID_BUFFLEN_MASK)) {
		PRINT_ERROR("Too big bufflen %d (op %x)", cmd->bufflen,
			cmd->cdb[0]);
		scst_set_invalid_field_in_cdb(cmd, sdbops->info_len_off, 0);
		return 1;
	}
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_lba_8_len_4(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be64(cmd->cdb + sdbops->info_lba_off);
	cmd->bufflen = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
	if (unlikely(cmd->bufflen & SCST_MAX_VALID_BUFFLEN_MASK)) {
		PRINT_ERROR("Too big bufflen %d (op %x)", cmd->bufflen,
			cmd->cdb[0]);
		scst_set_invalid_field_in_cdb(cmd, sdbops->info_len_off, 0);
		return 1;
	}
	cmd->data_len = cmd->bufflen;
	return 0;
}

static int get_cdb_info_write_same10(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be32(cmd->cdb + sdbops->info_lba_off);
	cmd->bufflen = 1;
	cmd->data_len = get_unaligned_be16(cmd->cdb + sdbops->info_len_off);
	return 0;
}

static int get_cdb_info_write_same16(struct scst_cmd *cmd,
	const struct scst_sdbops *sdbops)
{
	cmd->lba = get_unaligned_be64(cmd->cdb + sdbops->info_lba_off);
	cmd->bufflen = 1;
	cmd->data_len = get_unaligned_be32(cmd->cdb + sdbops->info_len_off);
	return 0;
}

/**
 * scst_get_cdb_info_apt() - Parse ATA PASS-THROUGH CDB.
 *
 * Parse ATA PASS-THROUGH(12) and ATA PASS-THROUGH(16). See also SAT-3 for a
 * detailed description of these commands.
 */
static int get_cdb_info_apt(struct scst_cmd *cmd,
			    const struct scst_sdbops *sdbops)
{
	const u8 *const cdb = cmd->cdb;
	const u8 op         = cdb[0];
	const u8 extend     = cdb[1] & 1;
	const u8 multiple   = cdb[1] >> 5;
	const u8 protocol   = (cdb[1] >> 1) & 0xf;
	const u8 t_type     = (cdb[2] >> 4) & 1;
	const u8 t_dir      = (cdb[2] >> 3) & 1;
	const u8 byte_block = (cdb[2] >> 2) & 1;
	const u8 t_length   = cdb[2] & 3;
	int bufflen = 0;

	/*
	 * If the PROTOCOL field contains Fh (i.e., Return Response
	 * Information), then the SATL shall ignore all fields in the CDB
	 * except for the PROTOCOL field.
	 */
	if (protocol == 0xf)
		goto out;

	switch (op) {
	case ATA_12:
		switch (t_length) {
		case 0:
			bufflen = 0;
			break;
		case 1:
			bufflen = cdb[3];
			break;
		case 2:
			bufflen = cdb[4];
			break;
		case 3:
			/*
			 * Not yet implemented: "The transfer length is an
			 * unsigned integer specified in the TPSIU (see
			 * 3.1.97)."
			 */
			WARN_ON(true);
			break;
		}
		break;
	case ATA_16:
		switch (t_length) {
		case 0:
			bufflen = 0;
			break;
		case 1:
			bufflen = extend ? get_unaligned_be16(&cdb[3]) : cdb[4];
			break;
		case 2:
			bufflen = extend ? get_unaligned_be16(&cdb[5]) : cdb[6];
			break;
		case 3:
			WARN_ON(true);
			break;
		}
		break;
	}

	/* See also "Table 133 - Mapping of BYTE_BLOCK, T_TYPE, and T_LENGTH" */
	cmd->cdb_len = SCST_GET_CDB_LEN(op);
	if (t_length != 0 && byte_block != 0) {
		/*
		 * "The number of ATA logical sector size (see 3.1.16) blocks
		 * to be transferred"
		 */
		bufflen *= t_type ? cmd->dev->block_size : 512;
	}
	/*
	 * If the T_DIR bit is set to zero, then the SATL shall transfer data
	 * from the application client to the ATA device. If the T_DIR bit is
	 * set to one, then the SATL shall transfer data from the ATA device
	 * to the application client. The SATL shall ignore the T_DIR bit if
	 * the T_LENGTH field is set to zero.
	*/
	cmd->data_direction = (t_length == 0 ? SCST_DATA_NONE : t_dir ?
			       SCST_DATA_READ : SCST_DATA_WRITE);
	cmd->lba = 0;
	cmd->bufflen = bufflen << multiple;
	cmd->data_len = cmd->bufflen;
out:
	cmd->op_flags = SCST_INFO_VALID;
	return 0;
}

/* Parse MAINTENANCE IN */
static int get_cdb_info_min(struct scst_cmd *cmd,
			    const struct scst_sdbops *sdbops)
{
	switch (cmd->cdb[1] & 0x1f) {
	case MI_REPORT_IDENTIFYING_INFORMATION:
		cmd->op_name = "REPORT IDENTIFYING INFORMATION";
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
		break;
	case MI_REPORT_TARGET_PGS:
		cmd->op_name = "REPORT TARGET PORT GROUPS";
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
		break;
	case MI_REPORT_SUPPORTED_OPERATION_CODES:
		cmd->op_name = "REPORT SUPPORTED OPERATION CODES";
		cmd->op_flags |= SCST_WRITE_EXCL_ALLOWED;
		break;
	case MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS:
		cmd->op_name = "REPORT SUPPORTED TASK MANAGEMENT FUNCTIONS";
		cmd->op_flags |= SCST_WRITE_EXCL_ALLOWED;
		break;
	default:
		break;
	}

	return get_cdb_info_len_4(cmd, sdbops);
}

/**
 * scst_get_cdb_info() - fill various info about the command's CDB
 *
 * Description:
 *    Fills various info about the command's CDB in the corresponding fields
 *    in the command.
 *
 *    Returns: 0 on success, <0 if command is unknown, >0 if command
 *    is invalid.
 */
int scst_get_cdb_info(struct scst_cmd *cmd)
{
	int dev_type = cmd->dev->type;
	int i, res = 0;
	uint8_t op;
	const struct scst_sdbops *ptr = NULL;

	TRACE_ENTRY();

	op = cmd->cdb[0];	/* get clear opcode */

	TRACE_DBG("opcode=%02x, cdblen=%d bytes, dev_type=%d", op,
		SCST_GET_CDB_LEN(op), dev_type);

	i = scst_scsi_op_list[op];
	while (i < SCST_CDB_TBL_SIZE && scst_scsi_op_table[i].ops == op) {
		if (scst_scsi_op_table[i].devkey[dev_type] != SCST_CDB_NOTSUPP) {
			ptr = &scst_scsi_op_table[i];
			TRACE_DBG("op = 0x%02x+'%c%c%c%c%c%c%c%c%c%c'+<%s>",
			      ptr->ops, ptr->devkey[0],	/* disk     */
			      ptr->devkey[1],	/* tape     */
			      ptr->devkey[2],	/* printer */
			      ptr->devkey[3],	/* cpu      */
			      ptr->devkey[4],	/* cdr      */
			      ptr->devkey[5],	/* cdrom    */
			      ptr->devkey[6],	/* scanner */
			      ptr->devkey[7],	/* worm     */
			      ptr->devkey[8],	/* changer */
			      ptr->devkey[9],	/* commdev */
			      ptr->info_op_name);
			TRACE_DBG("data direction %d, op flags 0x%x, lba off %d, "
				"lba len %d, len off %d, len len %d",
				ptr->info_data_direction, ptr->info_op_flags,
				ptr->info_lba_off, ptr->info_lba_len,
				ptr->info_len_off, ptr->info_len_len);
			break;
		}
		i++;
	}

	if (unlikely(ptr == NULL)) {
		/* opcode not found or now not used */
		TRACE(TRACE_MINOR, "Unknown opcode 0x%x for type %d", op,
		      dev_type);
		cmd->op_flags |= SCST_LBA_NOT_VALID;
		res = -1;
		goto out;
	}

	cmd->cdb_len = SCST_GET_CDB_LEN(op);
	cmd->op_name = ptr->info_op_name;
	cmd->data_direction = ptr->info_data_direction;
	cmd->op_flags = ptr->info_op_flags | SCST_INFO_VALID;
	cmd->lba_off = ptr->info_lba_off;
	cmd->lba_len = ptr->info_lba_len;
	cmd->len_off = ptr->info_len_off;
	cmd->len_len = ptr->info_len_len;
	res = (*ptr->get_cdb_info)(cmd, ptr);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_get_cdb_info);

/* Packs SCST LUN back to SCSI form */
__be64 scst_pack_lun(const uint64_t lun, enum scst_lun_addr_method addr_method)
{
	uint64_t res = 0;

	if (lun) {
		res = (addr_method << 14) | (lun & 0x3fff);
		res = res << 48;
	}

	TRACE_EXIT_HRES(res >> 48);
	return cpu_to_be64(res);
}
EXPORT_SYMBOL(scst_pack_lun);

/*
 * Function to extract a LUN number from an 8-byte LUN structure in network byte
 * order (big endian). Supports three LUN addressing methods: peripheral, flat
 * and logical unit. See also SAM-2, section 4.9.4 (page 40).
 */
uint64_t scst_unpack_lun(const uint8_t *lun, int len)
{
	uint64_t res = NO_SUCH_LUN;
	int address_method;

	TRACE_ENTRY();

	TRACE_BUFF_FLAG(TRACE_DEBUG, "Raw LUN", lun, len);

	switch (len) {
	case 2:
		break;
	case 8:
		if ((*((__be64 *)lun) & cpu_to_be64(0x0000FFFFFFFFFFFFLL)) != 0)
			goto out_err;
		break;
	case 4:
		if (*((__be16 *)&lun[2]) != 0)
			goto out_err;
		break;
	case 6:
		if (*((__be32 *)&lun[2]) != 0)
			goto out_err;
		break;
	case 1:
	case 0:
		PRINT_ERROR("Illegal lun length %d, expected 2 bytes "
			    "or more", len);
		goto out;
	default:
		goto out_err;
	}

	address_method = (*lun) >> 6;	/* high 2 bits of byte 0 */
	switch (address_method) {
	case SCST_LUN_ADDR_METHOD_PERIPHERAL:
	case SCST_LUN_ADDR_METHOD_FLAT:
	case SCST_LUN_ADDR_METHOD_LUN:
		res = *(lun + 1) | (((*lun) & 0x3f) << 8);
		break;

	case SCST_LUN_ADDR_METHOD_EXTENDED_LUN:
	default:
		PRINT_ERROR("Unimplemented LUN addressing method %u",
			    address_method);
		break;
	}

out:
	TRACE_EXIT_RES((int)res);
	return res;

out_err:
	PRINT_ERROR("%s", "Multi-level LUN unimplemented");
	goto out;
}
EXPORT_SYMBOL(scst_unpack_lun);

/**
 ** Generic parse() support routines.
 ** Done via pointer on functions to avoid unneeded dereferences on
 ** the fast path.
 **/

/**
 * scst_calc_block_shift() - calculate block shift
 *
 * Calculates and returns block shift for the given sector size
 */
int scst_calc_block_shift(int sector_size)
{
	int block_shift;

	if (sector_size == 0)
		sector_size = 512;

	block_shift = ilog2(sector_size);
	WARN_ON(1 << block_shift != sector_size);

	if (block_shift < 9) {
		PRINT_ERROR("Wrong sector size %d", sector_size);
		block_shift = -1;
	}

	TRACE_EXIT_RES(block_shift);
	return block_shift;
}
EXPORT_SYMBOL_GPL(scst_calc_block_shift);

/*
 * Test whether the result of a shift-left operation would be larger than
 * what fits in a variable with the type of @a.
 */
#define shift_left_overflows(a, b)					\
	({								\
		typeof(a) _minus_one = -1LL;				\
		bool _a_is_signed = _minus_one < 0;			\
		int _shift = sizeof(1ULL) * 8 - ((b) + _a_is_signed);	\
		_shift < 0 || ((a) & ~((1ULL << _shift) - 1)) != 0;	\
	})

/**
 * scst_generic_parse() - Generic parse() for devices supporting an LBA
 */
static inline int scst_generic_parse(struct scst_cmd *cmd, const int timeout[3])
{
	const int block_shift = cmd->dev->block_shift;
	int res = -EINVAL;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(block_shift < 0);

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED) {
		/*
		 * No need for locks here, since *_detach() can not be
		 * called, when there are existing commands.
		 */
		cmd->bufflen = cmd->bufflen << block_shift;
		cmd->data_len = cmd->data_len << block_shift;
		cmd->out_bufflen = cmd->out_bufflen << block_shift;
	}

	if (unlikely(!(cmd->op_flags & SCST_LBA_NOT_VALID) &&
		     shift_left_overflows(cmd->lba, block_shift))) {
		PRINT_WARNING("offset %llu * %u >= 2**63 for device %s (len %lld)",
			   cmd->lba, 1 << block_shift, cmd->dev->virt_name,
			   cmd->data_len);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
					scst_sense_block_out_range_error));
		goto out;
	}

	cmd->timeout = timeout[cmd->op_flags & SCST_BOTH_TIMEOUTS];
	res = 0;

out:
	TRACE_DBG("res %d, bufflen %d, data_len %lld, direct %d", res,
		cmd->bufflen, (long long)cmd->data_len, cmd->data_direction);

	TRACE_EXIT_RES(res);
	return res;
}

 /**
 * scst_sbc_generic_parse() - generic SBC parsing
  *
 * Generic parse() for SBC (disk) devices
  */
int scst_sbc_generic_parse(struct scst_cmd *cmd)
{
	static const int disk_timeout[] = {
		[0] = SCST_GENERIC_DISK_REG_TIMEOUT,
		[SCST_SMALL_TIMEOUT] = SCST_GENERIC_DISK_SMALL_TIMEOUT,
		[SCST_LONG_TIMEOUT] = SCST_GENERIC_DISK_LONG_TIMEOUT,
		[SCST_BOTH_TIMEOUTS] = SCST_GENERIC_DISK_LONG_TIMEOUT,
	};
	BUILD_BUG_ON(SCST_SMALL_TIMEOUT != 1);
	BUILD_BUG_ON(SCST_LONG_TIMEOUT != 2);
	BUILD_BUG_ON(SCST_BOTH_TIMEOUTS != 3);

	return scst_generic_parse(cmd, disk_timeout);
}
EXPORT_SYMBOL_GPL(scst_sbc_generic_parse);

/**
 * scst_cdrom_generic_parse() - generic MMC parse
 *
 * Generic parse() for MMC (cdrom) devices
 */
int scst_cdrom_generic_parse(struct scst_cmd *cmd)
{
	static const int cdrom_timeout[] = {
		[0] = SCST_GENERIC_CDROM_REG_TIMEOUT,
		[SCST_SMALL_TIMEOUT] = SCST_GENERIC_CDROM_SMALL_TIMEOUT,
		[SCST_LONG_TIMEOUT] = SCST_GENERIC_CDROM_LONG_TIMEOUT,
		[SCST_BOTH_TIMEOUTS] = SCST_GENERIC_CDROM_LONG_TIMEOUT,
	};
	BUILD_BUG_ON(SCST_SMALL_TIMEOUT != 1);
	BUILD_BUG_ON(SCST_LONG_TIMEOUT != 2);
	BUILD_BUG_ON(SCST_BOTH_TIMEOUTS != 3);

	cmd->cdb[1] &= 0x1f;
	return scst_generic_parse(cmd, cdrom_timeout);
}
EXPORT_SYMBOL_GPL(scst_cdrom_generic_parse);

/**
 * scst_modisk_generic_parse() - generic MO parse
 *
 * Generic parse() for MO disk devices
 */
int scst_modisk_generic_parse(struct scst_cmd *cmd)
{
	static const int modisk_timeout[] = {
		[0] = SCST_GENERIC_MODISK_REG_TIMEOUT,
		[SCST_SMALL_TIMEOUT] = SCST_GENERIC_MODISK_SMALL_TIMEOUT,
		[SCST_LONG_TIMEOUT] = SCST_GENERIC_MODISK_LONG_TIMEOUT,
		[SCST_BOTH_TIMEOUTS] = SCST_GENERIC_MODISK_LONG_TIMEOUT,
	};
	BUILD_BUG_ON(SCST_SMALL_TIMEOUT != 1);
	BUILD_BUG_ON(SCST_LONG_TIMEOUT != 2);
	BUILD_BUG_ON(SCST_BOTH_TIMEOUTS != 3);

	cmd->cdb[1] &= 0x1f;
	return scst_generic_parse(cmd, modisk_timeout);
}
EXPORT_SYMBOL_GPL(scst_modisk_generic_parse);

/**
 * scst_tape_generic_parse() - generic tape parse
 *
 * Generic parse() for tape devices
 */
int scst_tape_generic_parse(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	if (cmd->cdb[0] == READ_POSITION) {
		int tclp = cmd->cdb[1] & 4;
		int long_bit = cmd->cdb[1] & 2;
		int bt = cmd->cdb[1] & 1;

		if ((tclp == long_bit) && (!bt || !long_bit)) {
			cmd->bufflen =
			    tclp ? POSITION_LEN_LONG : POSITION_LEN_SHORT;
			cmd->data_direction = SCST_DATA_READ;
		} else {
			cmd->bufflen = 0;
			cmd->data_direction = SCST_DATA_NONE;
		}
		cmd->data_len = cmd->bufflen;
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED && cmd->cdb[1] & 1) {
		int block_size = cmd->dev->block_size;
		cmd->bufflen = cmd->bufflen * block_size;
		cmd->data_len = cmd->data_len * block_size;
		cmd->out_bufflen = cmd->out_bufflen * block_size;
	}

	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_TAPE_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_TAPE_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_TAPE_LONG_TIMEOUT;

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_tape_generic_parse);

static int scst_null_parse(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

#if 0
	switch (cmd->cdb[0]) {
	default:
		/* It's all good */
		break;
	}
#endif

	TRACE_DBG("res %d bufflen %d direct %d",
	      res, cmd->bufflen, cmd->data_direction);

	TRACE_EXIT();
	return res;
}

/**
 * scst_changer_generic_parse() - generic changer parse
 *
 * Generic parse() for changer devices
 */
int scst_changer_generic_parse(struct scst_cmd *cmd)
{
	int res = scst_null_parse(cmd);

	if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_CHANGER_LONG_TIMEOUT;
	else
		cmd->timeout = SCST_GENERIC_CHANGER_TIMEOUT;

	return res;
}
EXPORT_SYMBOL_GPL(scst_changer_generic_parse);

/**
 * scst_processor_generic_parse - generic SCSI processor parse
 *
 * Generic parse() for SCSI processor devices
 */
int scst_processor_generic_parse(struct scst_cmd *cmd)
{
	int res = scst_null_parse(cmd);

	if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_PROCESSOR_LONG_TIMEOUT;
	else
		cmd->timeout = SCST_GENERIC_PROCESSOR_TIMEOUT;

	return res;
}
EXPORT_SYMBOL_GPL(scst_processor_generic_parse);

/**
 * scst_raid_generic_parse() - generic RAID parse
 *
 * Generic parse() for RAID devices
 */
int scst_raid_generic_parse(struct scst_cmd *cmd)
{
	int res = scst_null_parse(cmd);

	if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_RAID_LONG_TIMEOUT;
	else
		cmd->timeout = SCST_GENERIC_RAID_TIMEOUT;

	return res;
}
EXPORT_SYMBOL_GPL(scst_raid_generic_parse);

int scst_do_internal_parsing(struct scst_cmd *cmd)
{
	int res, rc;

	TRACE_ENTRY();

	switch (cmd->dev->type) {
	case TYPE_DISK:
		rc = scst_sbc_generic_parse(cmd);
		break;
	case TYPE_TAPE:
		rc = scst_tape_generic_parse(cmd);
		break;
	case TYPE_PROCESSOR:
		rc = scst_processor_generic_parse(cmd);
		break;
	case TYPE_ROM:
		rc = scst_cdrom_generic_parse(cmd);
		break;
	case TYPE_MOD:
		rc = scst_modisk_generic_parse(cmd);
		break;
	case TYPE_MEDIUM_CHANGER:
		rc = scst_changer_generic_parse(cmd);
		break;
	case TYPE_RAID:
		rc = scst_raid_generic_parse(cmd);
		break;
	default:
		PRINT_ERROR("Internal parse for type %d not supported",
			cmd->dev->type);
		goto out_hw_err;
	}

	if (rc != 0)
		goto out_abn;

	res = SCST_CMD_STATE_DEFAULT;

out:
	TRACE_EXIT();
	return res;

out_hw_err:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

out_abn:
	res = scst_get_cmd_abnormal_done_state(cmd);
	goto out;
}

/**
 ** Generic dev_done() support routines.
 ** Done via pointer on functions to avoid unneeded dereferences on
 ** the fast path.
 **/

/**
 * scst_block_generic_dev_done() - generic SBC dev_done
 *
 * Generic dev_done() for block (SBC) devices
 */
int scst_block_generic_dev_done(struct scst_cmd *cmd,
	void (*set_block_shift)(struct scst_cmd *cmd, int block_shift))
{
	int opcode = cmd->cdb[0];
	int status = cmd->status;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->is_send_status and
	 * cmd->resp_data_len based on cmd->status and cmd->data_direction,
	 * therefore change them only if necessary
	 */

	if (unlikely(opcode == READ_CAPACITY)) {
		if ((status == SAM_STAT_GOOD) || (status == SAM_STAT_CONDITION_MET)) {
			/* Always keep track of disk capacity */
			int buffer_size, sector_size, sh;
			uint8_t *buffer;

			buffer_size = scst_get_buf_full(cmd, &buffer);
			if (unlikely(buffer_size <= 0)) {
				if (buffer_size < 0) {
					PRINT_ERROR("%s: Unable to get cmd "
						"buffer (%d)",	__func__,
						buffer_size);
				}
				goto out;
			}

			sector_size = get_unaligned_be32(&buffer[4]);
			scst_put_buf_full(cmd, buffer);
			if (sector_size != 0)
				sh = scst_calc_block_shift(sector_size);
			else
				sh = 0;
			set_block_shift(cmd, sh);
			TRACE_DBG("block_shift %d", sh);
		}
	} else {
		/* It's all good */
	}

	TRACE_DBG("cmd->is_send_status=%x, cmd->resp_data_len=%d, "
	      "res=%d", cmd->is_send_status, cmd->resp_data_len, res);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_block_generic_dev_done);

/**
 * scst_tape_generic_dev_done() - generic tape dev done
 *
 * Generic dev_done() for tape devices
 */
int scst_tape_generic_dev_done(struct scst_cmd *cmd,
	void (*set_block_size)(struct scst_cmd *cmd, int block_shift))
{
	int opcode = cmd->cdb[0];
	int res = SCST_CMD_STATE_DEFAULT;
	int buffer_size, bs;
	uint8_t *buffer = NULL;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->is_send_status and
	 * cmd->resp_data_len based on cmd->status and cmd->data_direction,
	 * therefore change them only if necessary
	 */

	if (unlikely(cmd->status != SAM_STAT_GOOD))
		goto out;

	switch (opcode) {
	case MODE_SENSE:
	case MODE_SELECT:
		buffer_size = scst_get_buf_full(cmd, &buffer);
		if (unlikely(buffer_size <= 0)) {
			if (buffer_size < 0) {
				PRINT_ERROR("%s: Unable to get the buffer (%d)",
					__func__, buffer_size);
			}
			goto out;
		}
		break;
	}

	switch (opcode) {
	case MODE_SENSE:
		TRACE_DBG("%s", "MODE_SENSE");
		if ((cmd->cdb[2] & 0xC0) == 0) {
			if (buffer[3] == 8) {
				bs = get_unaligned_be24(&buffer[9]);
				set_block_size(cmd, bs);
			}
		}
		break;
	case MODE_SELECT:
		TRACE_DBG("%s", "MODE_SELECT");
		if (buffer[3] == 8) {
			bs = get_unaligned_be24(&buffer[9]);
			set_block_size(cmd, bs);
		}
		break;
	default:
		/* It's all good */
		break;
	}

	switch (opcode) {
	case MODE_SENSE:
	case MODE_SELECT:
		scst_put_buf_full(cmd, buffer);
		break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_tape_generic_dev_done);

typedef void (*scst_set_cdb_lba_fn_t)(struct scst_cmd *cmd, int64_t lba);

static void scst_set_cdb_lba1(struct scst_cmd *cmd, int64_t lba)
{
	TRACE_ENTRY();

	cmd->cdb[cmd->lba_off] = lba;

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_lba2(struct scst_cmd *cmd, int64_t lba)
{
	TRACE_ENTRY();

	put_unaligned_be16(lba, &cmd->cdb[cmd->lba_off]);

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_lba3(struct scst_cmd *cmd, int64_t lba)
{
	TRACE_ENTRY();

	put_unaligned_be24(lba, &cmd->cdb[cmd->lba_off]);

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_lba4(struct scst_cmd *cmd, int64_t lba)
{
	TRACE_ENTRY();

	put_unaligned_be32(lba, &cmd->cdb[cmd->lba_off]);

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_lba8(struct scst_cmd *cmd, int64_t lba)
{
	TRACE_ENTRY();

	put_unaligned_be64(lba, &cmd->cdb[cmd->lba_off]);

	TRACE_EXIT();
	return;
}

static const scst_set_cdb_lba_fn_t scst_set_cdb_lba_fns[9] = {
	[1] = scst_set_cdb_lba1,
	[2] = scst_set_cdb_lba2,
	[3] = scst_set_cdb_lba3,
	[4] = scst_set_cdb_lba4,
	[8] = scst_set_cdb_lba8,
};

int scst_set_cdb_lba(struct scst_cmd *cmd, int64_t lba)
{
	int res;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->op_flags & SCST_LBA_NOT_VALID);

	scst_set_cdb_lba_fns[cmd->lba_len](cmd, lba);
	res = 0;

	TRACE_DBG("cmd %p, new LBA %lld", cmd, (unsigned long long)lba);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_set_cdb_lba);

typedef void (*scst_set_cdb_transf_len_fn_t)(struct scst_cmd *cmd, int len);

static void scst_set_cdb_transf_len1(struct scst_cmd *cmd, int len)
{
	TRACE_ENTRY();

	cmd->cdb[cmd->len_off] = len;

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_transf_len2(struct scst_cmd *cmd, int len)
{
	TRACE_ENTRY();

	put_unaligned_be16(len, &cmd->cdb[cmd->len_off]);

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_transf_len3(struct scst_cmd *cmd, int len)
{
	TRACE_ENTRY();

	put_unaligned_be24(len, &cmd->cdb[cmd->len_off]);

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_transf_len4(struct scst_cmd *cmd, int len)
{
	TRACE_ENTRY();

	put_unaligned_be32(len, &cmd->cdb[cmd->len_off]);

	TRACE_EXIT();
	return;
}

static void scst_set_cdb_transf_len8(struct scst_cmd *cmd, int len)
{
	TRACE_ENTRY();

	put_unaligned_be64(len, &cmd->cdb[cmd->len_off]);

	TRACE_EXIT();
	return;
}

static const scst_set_cdb_transf_len_fn_t scst_set_cdb_transf_len_fns[9] = {
	[1] = scst_set_cdb_transf_len1,
	[2] = scst_set_cdb_transf_len2,
	[3] = scst_set_cdb_transf_len3,
	[4] = scst_set_cdb_transf_len4,
	[8] = scst_set_cdb_transf_len8,
};

int scst_set_cdb_transf_len(struct scst_cmd *cmd, int len)
{
	int res;

	TRACE_ENTRY();

	scst_set_cdb_transf_len_fns[cmd->len_len](cmd, len);
	res = 0;

	TRACE_DBG("cmd %p, new len %d", cmd, len);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_set_cdb_transf_len);

static void scst_check_internal_sense(struct scst_device *dev, int result,
	uint8_t *sense, int sense_len)
{
	TRACE_ENTRY();

	if (host_byte(result) == DID_RESET) {
		int sl;
		TRACE(TRACE_MGMT, "DID_RESET received for device %s, "
			"triggering reset UA", dev->virt_name);
		sl = scst_set_sense(sense, sense_len, dev->d_sense,
			SCST_LOAD_SENSE(scst_sense_reset_UA));
		scst_dev_check_set_UA(dev, NULL, sense, sl);
	} else if ((status_byte(result) == CHECK_CONDITION) &&
		   scst_is_ua_sense(sense, sense_len))
		scst_dev_check_set_UA(dev, NULL, sense, sense_len);

	TRACE_EXIT();
	return;
}

/**
 * scst_to_dma_dir() - translate SCST's data direction to DMA direction
 *
 * Translates SCST's data direction to DMA one from backend storage
 * perspective.
 */
enum dma_data_direction scst_to_dma_dir(int scst_dir)
{
	static const enum dma_data_direction tr_tbl[] = { DMA_NONE,
		DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_BIDIRECTIONAL, DMA_NONE };

	return tr_tbl[scst_dir];
}
EXPORT_SYMBOL(scst_to_dma_dir);

/*
 * scst_to_tgt_dma_dir() - translate SCST data direction to DMA direction
 *
 * Translates SCST data direction to DMA data direction from the perspective
 * of a target.
 */
enum dma_data_direction scst_to_tgt_dma_dir(int scst_dir)
{
	static const enum dma_data_direction tr_tbl[] = { DMA_NONE,
		DMA_FROM_DEVICE, DMA_TO_DEVICE, DMA_BIDIRECTIONAL, DMA_NONE };

	return tr_tbl[scst_dir];
}
EXPORT_SYMBOL(scst_to_tgt_dma_dir);

/*
 * Called under dev_lock and BH off.
 *
 * !! scst_unblock_aborted_cmds() must be called after this function !!
 */
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd, bool setUA)
{
	struct scst_tgt_dev *tgt_dev;
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	/* Clear RESERVE'ation, if necessary */
	scst_clear_dev_reservation(dev);
	/*
	 * There is no need to send RELEASE, since the device is going
	 * to be reset. Actually, since we can be in RESET TM
	 * function, it might be dangerous.
	 */

	dev->dev_double_ua_possible = 1;

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
		dev_tgt_dev_list_entry) {
		struct scst_session *sess = tgt_dev->sess;

#if 0 /* Clearing UAs and last sense isn't required by SAM and it
       * looks to be better to not clear them to not loose important
       * events, so let's disable it.
       */
		spin_lock_bh(&tgt_dev->tgt_dev_lock);
		scst_free_all_UA(tgt_dev);
		memset(tgt_dev->tgt_dev_sense, 0,
			sizeof(tgt_dev->tgt_dev_sense));
		spin_unlock_bh(&tgt_dev->tgt_dev_lock);
#endif

		spin_lock_irq(&sess->sess_list_lock);

		TRACE_DBG("Searching in sess cmd list (sess=%p)", sess);
		list_for_each_entry(cmd, &sess->sess_cmd_list,
					sess_cmd_list_entry) {
			if (cmd == exclude_cmd)
				continue;
			if ((cmd->tgt_dev == tgt_dev) ||
			    ((cmd->tgt_dev == NULL) &&
			     (cmd->lun == tgt_dev->lun))) {
				scst_abort_cmd(cmd, mcmd,
					(tgt_dev->sess != originator), 0);
			}
		}
		spin_unlock_irq(&sess->sess_list_lock);
	}

	if (setUA) {
		uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
		int sl = scst_set_sense(sense_buffer, sizeof(sense_buffer),
			dev->d_sense, SCST_LOAD_SENSE(scst_sense_reset_UA));
		scst_dev_check_set_local_UA(dev, exclude_cmd, sense_buffer, sl);
	}

	TRACE_EXIT();
	return;
}

/* Caller must hold tgt_dev->tgt_dev_lock. */
void scst_tgt_dev_del_free_UA(struct scst_tgt_dev *tgt_dev,
			      struct scst_tgt_dev_UA *ua)
{
	list_del(&ua->UA_list_entry);
	if (list_empty(&tgt_dev->UA_list))
		clear_bit(SCST_TGT_DEV_UA_PENDING, &tgt_dev->tgt_dev_flags);
	mempool_free(ua, scst_ua_mempool);
}

/* No locks, no IRQ or IRQ-disabled context allowed */
int scst_set_pending_UA(struct scst_cmd *cmd, uint8_t *buf, int *size)
{
	int res = 0, i;
	struct scst_tgt_dev_UA *UA_entry;
	bool first = true, global_unlock = false;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	/*
	 * RMB and recheck to sync with setting SCST_CMD_ABORTED in
	 * scst_abort_cmd() to not set UA for the being aborted cmd, hence
	 * possibly miss its delivery by a legitimate command while the UA is
	 * being requeued.
	 */
	smp_rmb();
	if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
		TRACE_MGMT_DBG("Not set pending UA for aborted cmd %p", cmd);
		res = -1;
		goto out;
	}

	spin_lock_bh(&cmd->tgt_dev->tgt_dev_lock);

again:
	/* UA list could be cleared behind us, so retest */
	if (list_empty(&cmd->tgt_dev->UA_list)) {
		TRACE_DBG("SCST_TGT_DEV_UA_PENDING set, but UA_list empty");
		res = -1;
		goto out_unlock;
	} else
		TRACE_MGMT_DBG("Setting pending UA cmd %p (tgt_dev %p, dev %s, "
			"initiator %s)", cmd->tgt_dev, cmd, cmd->dev->virt_name,
			cmd->sess->initiator_name);

	UA_entry = list_first_entry(&cmd->tgt_dev->UA_list, typeof(*UA_entry),
			      UA_list_entry);

	TRACE_DBG("next %p UA_entry %p",
	      cmd->tgt_dev->UA_list.next, UA_entry);

	if (UA_entry->global_UA && first) {
		TRACE_MGMT_DBG("Global UA %p detected", UA_entry);

		spin_unlock_bh(&cmd->tgt_dev->tgt_dev_lock);

		/*
		 * cmd won't allow to suspend activities, so we can access
		 * sess->sess_tgt_dev_list without any additional
		 * protection.
		 */

		local_bh_disable();

		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;
			list_for_each_entry(tgt_dev, head,
					sess_tgt_dev_list_entry) {
				/* Lockdep triggers here a false positive.. */
				spin_lock(&tgt_dev->tgt_dev_lock);
			}
		}

		first = false;
		global_unlock = true;
		goto again;
	}

	if (buf == NULL) {
		if (scst_set_cmd_error_sense(cmd, UA_entry->UA_sense_buffer,
				UA_entry->UA_valid_sense_len) != 0)
			goto out_unlock;
	} else {
		sBUG_ON(*size == 0);
		if (UA_entry->UA_valid_sense_len > *size) {
			TRACE(TRACE_MINOR, "%s: Being returned UA truncated "
				"to size %d (needed %d)", cmd->op_name,
				*size, UA_entry->UA_valid_sense_len);
			*size = UA_entry->UA_valid_sense_len;
		}
		TRACE_DBG("Returning UA in buffer %p (size %d)", buf, *size);
		memcpy(buf, UA_entry->UA_sense_buffer, *size);
		*size = UA_entry->UA_valid_sense_len;
	}

	cmd->ua_ignore = 1;

	list_del(&UA_entry->UA_list_entry);

	if (UA_entry->global_UA) {
		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry(tgt_dev, head,
					sess_tgt_dev_list_entry) {
				struct scst_tgt_dev_UA *ua;
				list_for_each_entry(ua, &tgt_dev->UA_list,
							UA_list_entry) {
					if (ua->global_UA &&
					    memcmp(ua->UA_sense_buffer,
					      UA_entry->UA_sense_buffer,
					      sizeof(ua->UA_sense_buffer)) == 0) {
						TRACE_MGMT_DBG("Freeing not "
							"needed global UA %p",
							ua);
						scst_tgt_dev_del_free_UA(tgt_dev,
									 ua);
						break;
					}
				}
			}
		}
	}

	mempool_free(UA_entry, scst_ua_mempool);

	if (list_empty(&cmd->tgt_dev->UA_list)) {
		clear_bit(SCST_TGT_DEV_UA_PENDING,
			  &cmd->tgt_dev->tgt_dev_flags);
	}

out_unlock:
	if (global_unlock) {
		for (i = SESS_TGT_DEV_LIST_HASH_SIZE-1; i >= 0; i--) {
			struct list_head *head = &sess->sess_tgt_dev_list[i];
			struct scst_tgt_dev *tgt_dev;
			list_for_each_entry_reverse(tgt_dev, head,
					sess_tgt_dev_list_entry) {
				spin_unlock(&tgt_dev->tgt_dev_lock);
			}
		}

		local_bh_enable();
		spin_lock_bh(&cmd->tgt_dev->tgt_dev_lock);
	}

	spin_unlock_bh(&cmd->tgt_dev->tgt_dev_lock);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Called under tgt_dev_lock and BH off, except when guaranteed that
 * there's only one user of tgt_dev.
 */
static void scst_alloc_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags)
{
	struct scst_tgt_dev_UA *UA_entry = NULL;

	TRACE_ENTRY();

	UA_entry = mempool_alloc(scst_ua_mempool, GFP_ATOMIC);
	if (UA_entry == NULL) {
		PRINT_CRIT_ERROR("%s", "UNIT ATTENTION memory "
		     "allocation failed. The UNIT ATTENTION "
		     "on some sessions will be missed");
		PRINT_BUFFER("Lost UA", sense, sense_len);
		goto out;
	}
	memset(UA_entry, 0, sizeof(*UA_entry));

	UA_entry->global_UA = (flags & SCST_SET_UA_FLAG_GLOBAL) != 0;
	if (UA_entry->global_UA)
		TRACE_MGMT_DBG("Queueing global UA %p", UA_entry);

	if (sense_len > (int)sizeof(UA_entry->UA_sense_buffer)) {
		PRINT_WARNING("Sense truncated (needed %d), shall you increase "
			"SCST_SENSE_BUFFERSIZE?", sense_len);
		sense_len = sizeof(UA_entry->UA_sense_buffer);
	}
	memcpy(UA_entry->UA_sense_buffer, sense, sense_len);
	UA_entry->UA_valid_sense_len = sense_len;

	set_bit(SCST_TGT_DEV_UA_PENDING, &tgt_dev->tgt_dev_flags);

	TRACE_MGMT_DBG("Adding new UA to tgt_dev %p (dev %s, initiator %s)",
		tgt_dev, tgt_dev->dev->virt_name, tgt_dev->sess->initiator_name);

	if (flags & SCST_SET_UA_FLAG_AT_HEAD)
		list_add(&UA_entry->UA_list_entry, &tgt_dev->UA_list);
	else
		list_add_tail(&UA_entry->UA_list_entry, &tgt_dev->UA_list);

out:
	TRACE_EXIT();
	return;
}

/* tgt_dev_lock supposed to be held and BH off */
static void __scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags)
{
	int skip_UA = 0;
	struct scst_tgt_dev_UA *UA_entry_tmp;
	int len = min_t(int, sizeof(UA_entry_tmp->UA_sense_buffer), sense_len);

	TRACE_ENTRY();

	list_for_each_entry(UA_entry_tmp, &tgt_dev->UA_list,
			    UA_list_entry) {
		if (memcmp(sense, UA_entry_tmp->UA_sense_buffer, len) == 0) {
			TRACE_DBG("UA already exists (dev %s, "
				"initiator %s)", tgt_dev->dev->virt_name,
				tgt_dev->sess->initiator_name);
			skip_UA = 1;
			break;
		}
	}

	if (skip_UA == 0)
		scst_alloc_set_UA(tgt_dev, sense, len, flags);

	TRACE_EXIT();
	return;
}

void scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags)
{
	TRACE_ENTRY();

	spin_lock_bh(&tgt_dev->tgt_dev_lock);
	__scst_check_set_UA(tgt_dev, sense, sense_len, flags);
	spin_unlock_bh(&tgt_dev->tgt_dev_lock);

	TRACE_EXIT();
	return;
}

/* Called under dev_lock and BH off */
void scst_dev_check_set_local_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len)
{
	struct scst_tgt_dev *tgt_dev, *exclude_tgt_dev = NULL;

	TRACE_ENTRY();

	if (exclude != NULL)
		exclude_tgt_dev = exclude->tgt_dev;

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			dev_tgt_dev_list_entry) {
		if (tgt_dev != exclude_tgt_dev)
			scst_check_set_UA(tgt_dev, sense, sense_len, 0);
	}

	TRACE_EXIT();
	return;
}

/*
 * Called under dev_lock and BH off. Returns true if scst_unblock_aborted_cmds()
 * should be called outside of the dev_lock.
 */
static bool __scst_dev_check_set_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len)
{
	bool res = false;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Processing UA dev %s", dev->virt_name);

	/* Check for reset UA */
	if (scst_analyze_sense(sense, sense_len, SCST_SENSE_ASC_VALID,
				0, SCST_SENSE_ASC_UA_RESET, 0)) {
		scst_process_reset(dev,
				   (exclude != NULL) ? exclude->sess : NULL,
				   exclude, NULL, false);
		res = true;
	}

	scst_dev_check_set_local_UA(dev, exclude, sense, sense_len);

	TRACE_EXIT_RES(res);
	return res;
}

void scst_dev_check_set_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len)
{
	bool rc;

	spin_lock_bh(&dev->dev_lock);
	rc = __scst_dev_check_set_UA(dev, exclude, sense, sense_len);
	spin_unlock_bh(&dev->dev_lock);

	if (rc)
		scst_unblock_aborted_cmds(NULL, NULL, dev, false);

	return;
}

/* Called under tgt_dev_lock or when tgt_dev is unused */
static void scst_free_all_UA(struct scst_tgt_dev *tgt_dev)
{
	struct scst_tgt_dev_UA *UA_entry, *t;

	TRACE_ENTRY();

	list_for_each_entry_safe(UA_entry, t,
				 &tgt_dev->UA_list, UA_list_entry) {
		TRACE_MGMT_DBG("Clearing UA for tgt_dev LUN %lld",
			       (long long unsigned int)tgt_dev->lun);
		list_del(&UA_entry->UA_list_entry);
		mempool_free(UA_entry, scst_ua_mempool);
	}
	INIT_LIST_HEAD(&tgt_dev->UA_list);
	clear_bit(SCST_TGT_DEV_UA_PENDING, &tgt_dev->tgt_dev_flags);

	TRACE_EXIT();
	return;
}

/*
 * sn_lock supposed to be locked and IRQs off. Might drop then reacquire
 * it inside.
 */
struct scst_cmd *__scst_check_deferred_commands_locked(
	struct scst_order_data *order_data, bool return_first)
	__releases(&order_data->sn_lock)
	__acquires(&order_data->sn_lock)
{
	struct scst_cmd *res = NULL, *cmd, *t;
	typeof(order_data->expected_sn) expected_sn = order_data->expected_sn;
	bool activate = !return_first, first = true, found = false;

	TRACE_ENTRY();

	if (unlikely(order_data->hq_cmd_count != 0))
		goto out;

restart:
	list_for_each_entry_safe(cmd, t, &order_data->deferred_cmd_list,
				sn_cmd_list_entry) {
		EXTRACHECKS_BUG_ON((cmd->queue_type != SCST_CMD_QUEUE_SIMPLE) &&
				   (cmd->queue_type != SCST_CMD_QUEUE_ORDERED));
		if (cmd->sn == expected_sn) {
			bool stop = (cmd->sn_slot == NULL);

			TRACE_SN("Deferred command %p (sn %d, set %d) found",
				cmd, cmd->sn, cmd->sn_set);

			order_data->def_cmd_count--;
			list_del(&cmd->sn_cmd_list_entry);

			if (activate) {
				spin_lock(&cmd->cmd_threads->cmd_list_lock);
				TRACE_SN("Adding cmd %p to active cmd list", cmd);
				list_add_tail(&cmd->cmd_list_entry,
					&cmd->cmd_threads->active_cmd_list);
				wake_up(&cmd->cmd_threads->cmd_list_waitQ);
				spin_unlock(&cmd->cmd_threads->cmd_list_lock);
				/* !! At this point cmd can be already dead !! */
			}
			if (first) {
				if (!activate)
					res = cmd;
				if (stop) {
					/*
					 * Then there can be only one command
					 * with this SN, so there's no point
					 * to iterate further.
					 */
					goto out;
				}
				first = false;
				activate = true;
			}
			found = true;
		}
	}
	if (found)
		goto out;

	list_for_each_entry(cmd, &order_data->skipped_sn_list,
				sn_cmd_list_entry) {
		EXTRACHECKS_BUG_ON(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		if (cmd->sn == expected_sn) {
			/*
			 * !! At this point any pointer in cmd, except	     !!
			 * !! cur_order_data, sn_slot and sn_cmd_list_entry, !!
			 * !! could be already destroyed!		     !!
			 */
			TRACE_SN("cmd %p (tag %llu) with skipped sn %d found",
				 cmd, (long long unsigned int)cmd->tag, cmd->sn);
			order_data->def_cmd_count--;
			list_del(&cmd->sn_cmd_list_entry);
			spin_unlock_irq(&order_data->sn_lock);
			scst_inc_expected_sn(cmd);
			if (test_and_set_bit(SCST_CMD_CAN_BE_DESTROYED,
					     &cmd->cmd_flags))
				scst_destroy_cmd(cmd);
			expected_sn = order_data->expected_sn;
			spin_lock_irq(&order_data->sn_lock);
			goto restart;
		}
	}

out:
	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

/* No locks */
struct scst_cmd *__scst_check_deferred_commands(
	struct scst_order_data *order_data, bool return_first)
{
	struct scst_cmd *res;

	TRACE_ENTRY();

	spin_lock_irq(&order_data->sn_lock);
	res = __scst_check_deferred_commands_locked(order_data, return_first);
	spin_unlock_irq(&order_data->sn_lock);

	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

void scst_unblock_deferred(struct scst_order_data *order_data,
	struct scst_cmd *out_of_sn_cmd)
{
	TRACE_ENTRY();

	if (!out_of_sn_cmd->sn_set) {
		TRACE_SN("cmd %p without sn", out_of_sn_cmd);
		goto out;
	}

	if (out_of_sn_cmd->sn == order_data->expected_sn) {
		TRACE_SN("out of sn cmd %p (expected sn %d)",
			out_of_sn_cmd, order_data->expected_sn);
		scst_inc_expected_sn(out_of_sn_cmd);
	} else {
		out_of_sn_cmd->out_of_sn = 1;
		spin_lock_irq(&order_data->sn_lock);
		order_data->def_cmd_count++;
		list_add_tail(&out_of_sn_cmd->sn_cmd_list_entry,
			      &order_data->skipped_sn_list);
		TRACE_SN("out_of_sn_cmd %p with sn %d added to skipped_sn_list"
			" (expected_sn %d)", out_of_sn_cmd, out_of_sn_cmd->sn,
			order_data->expected_sn);
		spin_unlock_irq(&order_data->sn_lock);
		/*
		 * expected_sn could change while we there, so we need to
		 * recheck deferred commands on this path as well
		 */
	}

	scst_make_deferred_commands_active(order_data);

out:
	TRACE_EXIT();
	return;
}

/* dev_lock supposed to be held and BH disabled */
void scst_block_dev(struct scst_device *dev)
{
	dev->block_count++;
	TRACE_BLOCK("Device BLOCK (new count %d), dev %s", dev->block_count,
		dev->virt_name);
}

/*
 * dev_lock supposed to be held and BH disabled. Returns true if cmd blocked,
 * hence stop processing it and go to the next command.
 */
bool __scst_check_blocked_dev(struct scst_cmd *cmd)
{
	int res = false;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->unblock_dev);
	EXTRACHECKS_BUG_ON(cmd->internal);

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
		goto out;

	if (dev->block_count > 0) {
		TRACE_BLOCK("Delaying cmd %p due to blocking "
			"(tag %llu, op %x, dev %s)", cmd,
			(long long unsigned int)cmd->tag, cmd->cdb[0],
			dev->virt_name);
		goto out_block;
	} else if ((cmd->op_flags & SCST_STRICTLY_SERIALIZED) == SCST_STRICTLY_SERIALIZED) {
		TRACE_BLOCK("cmd %p (tag %llu, op %x): blocking further "
			"cmds on dev %s due to strict serialization", cmd,
			(long long unsigned int)cmd->tag, cmd->cdb[0],
			dev->virt_name);
		scst_block_dev(dev);
		if (dev->on_dev_cmd_count > 1) {
			TRACE_BLOCK("Delaying strictly serialized cmd %p "
				"(dev %s, on_dev_cmds to wait %d)", cmd,
				dev->virt_name, dev->on_dev_cmd_count-1);
			EXTRACHECKS_BUG_ON(dev->strictly_serialized_cmd_waiting);
			dev->strictly_serialized_cmd_waiting = 1;
			goto out_block;
		} else
			cmd->unblock_dev = 1;
	} else if ((dev->dev_double_ua_possible) ||
		   ((cmd->op_flags & SCST_SERIALIZED) != 0)) {
		TRACE_BLOCK("cmd %p (tag %llu, op %x): blocking further cmds "
			"on dev %s due to %s", cmd, (long long unsigned int)cmd->tag,
			cmd->cdb[0], dev->virt_name,
			dev->dev_double_ua_possible ? "possible double reset UA" :
						      "serialized cmd");
		scst_block_dev(dev);
		cmd->unblock_dev = 1;
	} else
		TRACE_BLOCK("No blocks for device %s", dev->virt_name);

out:
	TRACE_EXIT_RES(res);
	return res;

out_block:
	if (cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE)
		list_add(&cmd->blocked_cmd_list_entry,
			      &dev->blocked_cmd_list);
	else
		list_add_tail(&cmd->blocked_cmd_list_entry,
			      &dev->blocked_cmd_list);
	res = true;
	goto out;
}

/* dev_lock supposed to be held and BH disabled */
void scst_unblock_dev(struct scst_device *dev)
{
	TRACE_ENTRY();

	TRACE_BLOCK("Device UNBLOCK(new %d), dev %s",
		dev->block_count-1, dev->virt_name);

	if (--dev->block_count == 0) {
		struct scst_cmd *cmd, *tcmd;
		unsigned long flags;

		local_irq_save(flags);
		list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
					 blocked_cmd_list_entry) {
			bool strictly_serialized;
			list_del(&cmd->blocked_cmd_list_entry);
			TRACE_BLOCK("Adding blocked cmd %p to active cmd "
					"list", cmd);
			spin_lock(&cmd->cmd_threads->cmd_list_lock);
			if (cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE)
				list_add(&cmd->cmd_list_entry,
					&cmd->cmd_threads->active_cmd_list);
			else
				list_add_tail(&cmd->cmd_list_entry,
					&cmd->cmd_threads->active_cmd_list);
			strictly_serialized = ((cmd->op_flags & SCST_STRICTLY_SERIALIZED) == SCST_STRICTLY_SERIALIZED);
			wake_up(&cmd->cmd_threads->cmd_list_waitQ);
			spin_unlock(&cmd->cmd_threads->cmd_list_lock);
			if (dev->strictly_serialized_cmd_waiting && strictly_serialized)
				break;
		}
		local_irq_restore(flags);

		dev->strictly_serialized_cmd_waiting = 0;
	}

	sBUG_ON(dev->block_count < 0);

	TRACE_EXIT();
	return;
}

/**
 * scst_obtain_device_parameters() - obtain device control parameters
 * @dev:	device to act on
 * @mode_select_cdb: original MODE SELECT CDB
 *
 * Issues a MODE SENSE for necessary pages data and sets the corresponding
 * dev's parameter from it. Parameter mode_select_cdb is pointer on original
 * MODE SELECT CDB, if this function called to refresh parameters after
 * successfully finished MODE SELECT command detected.
 *
 * Returns 0 on success and not 0 otherwise.
 */
int scst_obtain_device_parameters(struct scst_device *dev,
	const uint8_t *mode_select_cdb)
{
	int rc, i;
	uint8_t cmd[16];
	uint8_t buffer[4+0x0A];
	uint8_t sense_buffer[SCSI_SENSE_BUFFERSIZE];

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(dev->scsi_dev == NULL);

	if (mode_select_cdb != NULL) {
		if ((mode_select_cdb[2] & 0x3F) != 0x0A) {
			TRACE_DBG("Not control mode page (%x) change requested, "
				"skipping", mode_select_cdb[2] & 0x3F);
			goto out;
		}
	}

	for (i = 0; i < 5; i++) {
		/* Get control mode page */
		memset(cmd, 0, sizeof(cmd));
#if 0
		cmd[0] = MODE_SENSE_10;
		cmd[1] = 0;
		cmd[2] = 0x0A;
		cmd[8] = sizeof(buffer); /* it's < 256 */
#else
		cmd[0] = MODE_SENSE;
		cmd[1] = 8; /* DBD */
		cmd[2] = 0x0A;
		cmd[4] = sizeof(buffer);
#endif

		memset(buffer, 0, sizeof(buffer));
		memset(sense_buffer, 0, sizeof(sense_buffer));

		TRACE(TRACE_SCSI, "%s", "Doing internal MODE_SENSE");
		rc = scsi_execute(dev->scsi_dev, cmd, SCST_DATA_READ, buffer,
				sizeof(buffer), sense_buffer, 15, 0, 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
				, NULL
#endif
				);

		TRACE_DBG("MODE_SENSE done: %x", rc);

		if (scsi_status_is_good(rc)) {
			int q;

			PRINT_BUFF_FLAG(TRACE_SCSI, "Returned control mode "
				"page data", buffer, sizeof(buffer));

			dev->tst = buffer[4+2] >> 5;
			q = buffer[4+3] >> 4;
			if (q > SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER) {
				PRINT_ERROR("Too big QUEUE ALG %x, dev %s",
					dev->queue_alg, dev->virt_name);
			}
			dev->queue_alg = q;
			dev->swp = (buffer[4+4] & 0x8) >> 3;
			dev->tas = (buffer[4+5] & 0x40) >> 6;
			dev->d_sense = (buffer[4+2] & 0x4) >> 2;

			/*
			 * Unfortunately, SCSI ML doesn't provide a way to
			 * specify commands task attribute, so we can rely on
			 * device's restricted reordering only. Linux I/O
			 * subsystem doesn't reorder pass-through (PC) requests.
			 */
			dev->has_own_order_mgmt = !dev->queue_alg;

			PRINT_INFO("Device %s: TST %x, QUEUE ALG %x, SWP %x, "
				"TAS %x, D_SENSE %d, has_own_order_mgmt %d",
				dev->virt_name, dev->tst, dev->queue_alg,
				dev->swp, dev->tas, dev->d_sense,
				dev->has_own_order_mgmt);

			goto out;
		} else {
			scst_check_internal_sense(dev, rc, sense_buffer,
				sizeof(sense_buffer));
#if 0
			if ((status_byte(rc) == CHECK_CONDITION) &&
			    scst_sense_valid(sense_buffer)) {
#else
			/*
			 * 3ware controller is buggy and returns CONDITION_GOOD
			 * instead of CHECK_CONDITION
			 */
			if (scst_sense_valid(sense_buffer)) {
#endif
				PRINT_BUFF_FLAG(TRACE_SCSI, "Returned sense "
					"data", sense_buffer,
					sizeof(sense_buffer));
				if (scst_analyze_sense(sense_buffer,
						sizeof(sense_buffer),
						SCST_SENSE_KEY_VALID,
						ILLEGAL_REQUEST, 0, 0)) {
					PRINT_INFO("Device %s doesn't support "
						"MODE SENSE or control mode page",
						dev->virt_name);
					break;
				} else if (scst_analyze_sense(sense_buffer,
						sizeof(sense_buffer),
						SCST_SENSE_KEY_VALID,
						NOT_READY, 0, 0)) {
					PRINT_ERROR("Device %s not ready",
						dev->virt_name);
					break;
				}
			} else {
				PRINT_INFO("Internal MODE SENSE to "
					"device %s failed: %x",
					dev->virt_name, rc);
				PRINT_BUFF_FLAG(TRACE_SCSI, "MODE SENSE sense",
					sense_buffer, sizeof(sense_buffer));
				switch (host_byte(rc)) {
				case DID_RESET:
				case DID_ABORT:
				case DID_SOFT_ERROR:
					break;
				default:
					goto brk;
				}
				switch (driver_byte(rc)) {
				case DRIVER_BUSY:
				case DRIVER_SOFT:
					break;
				default:
					goto brk;
				}
			}
		}
	}
brk:
	PRINT_WARNING("Unable to get device's %s control mode page, using "
		"existing values/defaults: TST %x, QUEUE ALG %x, SWP %x, "
		"TAS %x, D_SENSE %d, has_own_order_mgmt %d", dev->virt_name,
		dev->tst, dev->queue_alg, dev->swp, dev->tas, dev->d_sense,
		dev->has_own_order_mgmt);

out:
	TRACE_EXIT();
	return 0;
}
EXPORT_SYMBOL_GPL(scst_obtain_device_parameters);

void scst_on_hq_cmd_response(struct scst_cmd *cmd)
{
	struct scst_order_data *order_data = cmd->cur_order_data;

	TRACE_ENTRY();

	if (!cmd->hq_cmd_inced)
		goto out;

	spin_lock_irq(&order_data->sn_lock);
	order_data->hq_cmd_count--;
	spin_unlock_irq(&order_data->sn_lock);

	EXTRACHECKS_BUG_ON(order_data->hq_cmd_count < 0);

	/*
	 * There is no problem in checking hq_cmd_count in the
	 * non-locked state. In the worst case we will only have
	 * unneeded run of the deferred commands.
	 */
	if (order_data->hq_cmd_count == 0)
		scst_make_deferred_commands_active(order_data);

out:
	TRACE_EXIT();
	return;
}

void scst_store_sense(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (scst_sense_valid(cmd->sense) &&
	    !test_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags) &&
	    (cmd->tgt_dev != NULL)) {
		struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

		TRACE_DBG("Storing sense (cmd %p)", cmd);

		spin_lock_bh(&tgt_dev->tgt_dev_lock);

		if (cmd->sense_valid_len <= sizeof(tgt_dev->tgt_dev_sense))
			tgt_dev->tgt_dev_valid_sense_len = cmd->sense_valid_len;
		else {
			tgt_dev->tgt_dev_valid_sense_len = sizeof(tgt_dev->tgt_dev_sense);
			PRINT_ERROR("Stored sense truncated to size %d "
				"(needed %d)", tgt_dev->tgt_dev_valid_sense_len,
				cmd->sense_valid_len);
		}
		memcpy(tgt_dev->tgt_dev_sense, cmd->sense,
			tgt_dev->tgt_dev_valid_sense_len);

		spin_unlock_bh(&tgt_dev->tgt_dev_lock);
	}

	TRACE_EXIT();
	return;
}

void scst_xmit_process_aborted_cmd(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("Aborted cmd %p done (cmd_ref %d)", cmd,
		atomic_read(&cmd->cmd_ref));

	scst_done_cmd_mgmt(cmd);

	if (test_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags)) {
		if (cmd->completed) {
			/* It's completed and it's OK to return its result */
			goto out;
		}

		/* For not yet inited commands cmd->dev can be NULL here */
		if (test_bit(SCST_CMD_DEVICE_TAS, &cmd->cmd_flags)) {
			TRACE_MGMT_DBG("Flag ABORTED OTHER set for cmd %p "
				"(tag %llu), returning TASK ABORTED ", cmd,
				(long long unsigned int)cmd->tag);
			scst_set_cmd_error_status(cmd, SAM_STAT_TASK_ABORTED);
		} else {
			TRACE_MGMT_DBG("Flag ABORTED OTHER set for cmd %p "
				"(tag %llu), aborting without delivery or "
				"notification",
				cmd, (long long unsigned int)cmd->tag);
			/*
			 * There is no need to check/requeue possible UA,
			 * because, if it exists, it will be delivered
			 * by the "completed" branch above.
			 */
			clear_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
		}
	}

out:
	TRACE_EXIT();
	return;
}

/**
 * scst_get_max_lun_commands() - return maximum supported commands count
 *
 * Returns maximum commands count which can be queued to this LUN in this
 * session.
 *
 * If lun is NO_SUCH_LUN, returns minimum of maximum commands count which
 * can be queued to any LUN in this session.
 *
 * If sess is NULL, returns minimum of maximum commands count which can be
 * queued to any SCST device.
 */
int scst_get_max_lun_commands(struct scst_session *sess, uint64_t lun)
{
	return SCST_MAX_TGT_DEV_COMMANDS;
}
EXPORT_SYMBOL(scst_get_max_lun_commands);

/**
 * scst_reassign_retained_sess_states() - reassigns retained states
 *
 * Reassigns retained during nexus loss states from old_sess to new_sess.
 */
void scst_reassign_retained_sess_states(struct scst_session *new_sess,
	struct scst_session *old_sess)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Reassigning retained states from old_sess %p to "
		"new_sess %p", old_sess, new_sess);

	if ((new_sess == NULL) || (old_sess == NULL)) {
		TRACE_DBG("%s", "new_sess or old_sess is NULL");
		goto out;
	}

	if (new_sess == old_sess) {
		TRACE_DBG("%s", "new_sess or old_sess are the same");
		goto out;
	}

	if ((new_sess->transport_id == NULL) ||
	    (old_sess->transport_id == NULL)) {
		TRACE_DBG("%s", "new_sess or old_sess doesn't support PRs");
		goto out;
	}

	mutex_lock(&scst_mutex);

	list_for_each_entry(dev, &scst_dev_list, dev_list_entry) {
		struct scst_tgt_dev *tgt_dev;
		struct scst_tgt_dev *new_tgt_dev = NULL, *old_tgt_dev = NULL;

		TRACE_DBG("Processing dev %s", dev->virt_name);

		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
					dev_tgt_dev_list_entry) {
			if (tgt_dev->sess == new_sess) {
				new_tgt_dev = tgt_dev;
				if (old_tgt_dev != NULL)
					break;
			}
			if (tgt_dev->sess == old_sess) {
				old_tgt_dev = tgt_dev;
				if (new_tgt_dev != NULL)
					break;
			}
		}

		if ((new_tgt_dev == NULL) || (old_tgt_dev == NULL)) {
			TRACE_DBG("new_tgt_dev %p or old_sess %p is NULL, "
				"skipping (dev %s)", new_tgt_dev, old_tgt_dev,
				dev->virt_name);
			continue;
		}

		/** Reassign regular reservations **/

		if (scst_is_reservation_holder(dev, old_sess)) {
			scst_reserve_dev(dev, new_sess);
			TRACE_DBG("Reservation reassigned from old_tgt_dev %p "
				"to new_tgt_dev %p", old_tgt_dev, new_tgt_dev);
		}

		/** Reassign PRs **/

		if ((new_sess->transport_id == NULL) ||
		    (old_sess->transport_id == NULL)) {
			TRACE_DBG("%s", "new_sess or old_sess doesn't support PRs");
			goto next;
		}

		scst_pr_write_lock(dev);

		if (old_tgt_dev->registrant != NULL) {
			TRACE_PR("Reassigning reg %p from tgt_dev %p to %p",
				old_tgt_dev->registrant, old_tgt_dev,
				new_tgt_dev);

			if (new_tgt_dev->registrant != NULL)
				new_tgt_dev->registrant->tgt_dev = NULL;

			new_tgt_dev->registrant = old_tgt_dev->registrant;
			new_tgt_dev->registrant->tgt_dev = new_tgt_dev;

			old_tgt_dev->registrant = NULL;
		}

		scst_pr_write_unlock(dev);
next:
		/** Reassign other DH specific states **/

		if (dev->handler->reassign_retained_states != NULL) {
			TRACE_DBG("Calling dev's %s reassign_retained_states(%p, %p)",
				dev->virt_name, new_tgt_dev, old_tgt_dev);
			dev->handler->reassign_retained_states(new_tgt_dev, old_tgt_dev);
			TRACE_DBG("Dev's %s reassign_retained_states() returned",
				dev->virt_name);
		}
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_reassign_retained_sess_states);

/**
 * scst_get_next_lexem() - parse and return next lexem in the string
 *
 * Returns pointer to the next lexem from token_str skipping
 * spaces and '=' character and using them then as a delimeter. Content
 * of token_str is modified by setting '\0' at the delimeter's position.
 */
char *scst_get_next_lexem(char **token_str)
{
	char *p, *q;
	static const char blank = '\0';

	if ((token_str == NULL) || (*token_str == NULL))
		return (char *)&blank;

	for (p = *token_str; (*p != '\0') && (isspace(*p) || (*p == '=')); p++)
		;

	for (q = p; (*q != '\0') && !isspace(*q) && (*q != '='); q++)
		;

	if (*q != '\0')
		*q++ = '\0';

	*token_str = q;
	return p;
}
EXPORT_SYMBOL_GPL(scst_get_next_lexem);

/**
 * scst_restore_token_str() - restore string modified by scst_get_next_lexem()
 *
 * Restores token_str modified by scst_get_next_lexem() to the
 * previous value before scst_get_next_lexem() was called. Prev_lexem is
 * a pointer to lexem returned by scst_get_next_lexem().
 */
void scst_restore_token_str(char *prev_lexem, char *token_str)
{
	if (&prev_lexem[strlen(prev_lexem)] != token_str)
		prev_lexem[strlen(prev_lexem)] = ' ';
	return;
}
EXPORT_SYMBOL_GPL(scst_restore_token_str);

/**
 * scst_get_next_token_str() - parse and return next token
 *
 * This function returns pointer to the next token strings from input_str
 * using '\n', ';' and '\0' as a delimeter. Content of input_str is
 * modified by setting '\0' at the delimeter's position.
 */
char *scst_get_next_token_str(char **input_str)
{
	char *p = *input_str;
	int i = 0;

	while ((p[i] != '\n') && (p[i] != ';') && (p[i] != '\0'))
		i++;

	if (i == 0)
		return NULL;

	if (p[i] == '\0')
		*input_str = &p[i];
	else
		*input_str = &p[i+1];

	p[i] = '\0';

	return p;
}
EXPORT_SYMBOL_GPL(scst_get_next_token_str);

static int scst_parse_unmap_descriptors(struct scst_cmd *cmd)
{
	int res = 0;
	ssize_t length = 0;
	uint8_t *address;
	int i, cnt, offset, descriptor_len, total_len;
	struct scst_data_descriptor *pd;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->cmd_data_descriptors != NULL);
	EXTRACHECKS_BUG_ON(cmd->cmd_data_descriptors_cnt != 0);

	length = scst_get_buf_full_sense(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length == 0)
			goto out;
		else
			goto out_abn;
	}

	total_len = get_unaligned_be16(&cmd->cdb[7]);
	offset = 8;

	descriptor_len = get_unaligned_be16(&address[2]);

	TRACE_DBG("total_len %d, descriptor_len %d", total_len, descriptor_len);

	if (descriptor_len == 0)
		goto out_put;

	if (unlikely((descriptor_len > (total_len - 8)) ||
		     ((descriptor_len % 16) != 0))) {
		PRINT_ERROR("Bad descriptor length: %d < %d - 8",
			descriptor_len, total_len);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out_abn_put;
	}

	cnt = descriptor_len/16;
	if (cnt == 0)
		goto out_put;

	pd = kzalloc(sizeof(*pd) * cnt, GFP_KERNEL);
	if (pd == NULL) {
		PRINT_ERROR("Unable to kmalloc UNMAP %d descriptors", cnt+1);
		scst_set_busy(cmd);
		goto out_abn_put;
	}

	TRACE_DBG("cnt %d, pd %p", cnt, pd);

	i = 0;
	while ((offset - 8) < descriptor_len) {
		struct scst_data_descriptor *d = &pd[i];
		d->sdd_lba = get_unaligned_be64(&address[offset]);
		offset += 8;
		d->sdd_blocks = get_unaligned_be32(&address[offset]);
		offset += 8;
		TRACE_DBG("i %d, lba %lld, blocks %lld", i,
			(long long)d->sdd_lba, (long long)d->sdd_blocks);
		i++;
	}

	cmd->cmd_data_descriptors = pd;
	cmd->cmd_data_descriptors_cnt = cnt;

out_put:
	scst_put_buf_full(cmd, address);

out:
	TRACE_EXIT_RES(res);
	return res;

out_abn_put:
	scst_put_buf_full(cmd, address);

out_abn:
	scst_set_cmd_abnormal_done_state(cmd);
	res = -1;
	goto out;
}

static void scst_free_unmap_descriptors(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	kfree(cmd->cmd_data_descriptors);
	cmd->cmd_data_descriptors = NULL;

	TRACE_EXIT();
	return;
}

int scst_parse_descriptors(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	switch (cmd->cdb[0]) {
	case UNMAP:
		res = scst_parse_unmap_descriptors(cmd);
		break;
	default:
		sBUG_ON(1);
		res = -1;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_free_descriptors(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	switch (cmd->cdb[0]) {
	case UNMAP:
		scst_free_unmap_descriptors(cmd);
		break;
	default:
		sBUG_ON(1);
		break;
	}

	TRACE_EXIT();
	return;
}

/* Abstract vfs_unlink() for different kernel versions (as possible) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
void scst_vfs_unlink_and_put(struct nameidata *nd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	vfs_unlink(nd->dentry->d_parent->d_inode, nd->dentry);
	dput(nd->dentry);
	mntput(nd->mnt);
#else
	vfs_unlink(nd->path.dentry->d_parent->d_inode,
		nd->path.dentry);
	path_put(&nd->path);
#endif
}
#else
void scst_vfs_unlink_and_put(struct path *path)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	vfs_unlink(path->dentry->d_parent->d_inode, path->dentry);
#else
	vfs_unlink(path->dentry->d_parent->d_inode, path->dentry, NULL);
#endif
	path_put(path);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
void scst_path_put(struct nameidata *nd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dput(nd->dentry);
	mntput(nd->mnt);
#else
	path_put(&nd->path);
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
int scst_vfs_fsync(struct file *file, loff_t loff, loff_t len)
{
	int res;

	res = sync_page_range(file->f_dentry->d_inode, file->f_mapping,
			loff, len);
	return res;
}
#endif

int scst_copy_file(const char *src, const char *dest)
{
	int res = 0;
	struct inode *inode;
	loff_t file_size, pos;
	uint8_t *buf = NULL;
	struct file *file_src = NULL, *file_dest = NULL;
	mm_segment_t old_fs = get_fs();

	TRACE_ENTRY();

	if (src == NULL || dest == NULL) {
		res = -EINVAL;
		PRINT_ERROR("%s", "Invalid persistent files path - backup "
			"skipped");
		goto out;
	}

	TRACE_DBG("Copying '%s' into '%s'", src, dest);

	set_fs(KERNEL_DS);

	file_src = filp_open(src, O_RDONLY, 0);
	if (IS_ERR(file_src)) {
		res = PTR_ERR(file_src);
		TRACE_DBG("Unable to open file '%s' - error %d", src, res);
		goto out_free;
	}

	file_dest = filp_open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(file_dest)) {
		res = PTR_ERR(file_dest);
		TRACE_DBG("Unable to open backup file '%s' - error %d", dest,
			res);
		goto out_close;
	}

	inode = file_src->f_dentry->d_inode;

	if (S_ISREG(inode->i_mode))
		/* Nothing to do */;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		PRINT_ERROR("Invalid file mode 0x%x", inode->i_mode);
		res = -EINVAL;
		set_fs(old_fs);
		goto out_skip;
	}

	file_size = inode->i_size;

	buf = vmalloc(file_size);
	if (buf == NULL) {
		res = -ENOMEM;
		PRINT_ERROR("%s", "Unable to allocate temporary buffer");
		goto out_skip;
	}

	pos = 0;
	res = vfs_read(file_src, (void __force __user *)buf, file_size, &pos);
	if (res != file_size) {
		PRINT_ERROR("Unable to read file '%s' - error %d", src, res);
		goto out_skip;
	}

	pos = 0;
	res = vfs_write(file_dest, (void __force __user *)buf, file_size, &pos);
	if (res != file_size) {
		PRINT_ERROR("Unable to write to '%s' - error %d", dest, res);
		goto out_skip;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	res = scst_vfs_fsync(file_dest, 0, file_size);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
	res = vfs_fsync(file_dest, file_dest->f_path.dentry, 0);
#else
	res = vfs_fsync(file_dest, 0);
#endif
	if (res != 0) {
		PRINT_ERROR("fsync() of the backup PR file failed: %d", res);
		goto out_skip;
	}

out_skip:
	filp_close(file_dest, NULL);

out_close:
	filp_close(file_src, NULL);

out_free:
	if (buf != NULL)
		vfree(buf);

	set_fs(old_fs);

out:
	TRACE_EXIT_RES(res);
	return res;
}

int scst_remove_file(const char *name)
{
	int res = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
	struct nameidata nd;
#else
	struct path path;
#endif
	mm_segment_t old_fs = get_fs();

	TRACE_ENTRY();

	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
	res = path_lookup(name, 0, &nd);
	if (!res)
		scst_vfs_unlink_and_put(&nd);
	else
		TRACE_DBG("Unable to lookup file '%s' - error %d", name, res);
#else
	res = kern_path(name, 0, &path);
	if (!res)
		scst_vfs_unlink_and_put(&path);
	else
		TRACE_DBG("Unable to lookup file '%s' - error %d", name, res);
#endif

	set_fs(old_fs);

	TRACE_EXIT_RES(res);
	return res;
}

static void __init scst_scsi_op_list_init(void)
{
	int i;
	uint8_t op = 0xff;

	TRACE_ENTRY();

	TRACE_DBG("tblsize=%d", SCST_CDB_TBL_SIZE);

	for (i = 0; i < 256; i++)
		scst_scsi_op_list[i] = SCST_CDB_TBL_SIZE;

	for (i = 0; i < SCST_CDB_TBL_SIZE; i++) {
		if (scst_scsi_op_table[i].ops != op) {
			op = scst_scsi_op_table[i].ops;
			scst_scsi_op_list[op] = i;
		}
	}

	TRACE_BUFFER("scst_scsi_op_list", scst_scsi_op_list,
		sizeof(scst_scsi_op_list));

	TRACE_EXIT();
	return;
}

int __init scst_lib_init(void)
{
	int res = 0;

	scst_scsi_op_list_init();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	scsi_io_context_cache = kmem_cache_create("scst_scsi_io_context",
					sizeof(struct scsi_io_context),
					__alignof__(struct scsi_io_context),
					SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN, NULL);
	if (!scsi_io_context_cache) {
		PRINT_ERROR("%s", "Can't init scsi io context cache");
		res = -ENOMEM;
		goto out;
	}

out:
#endif
	TRACE_EXIT_RES(res);
	return res;
}

void scst_lib_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	BUILD_BUG_ON(SCST_MAX_CDB_SIZE != BLK_MAX_CDB);
	BUILD_BUG_ON(SCST_SENSE_BUFFERSIZE < SCSI_SENSE_BUFFERSIZE);

	kmem_cache_destroy(scsi_io_context_cache);
#endif
}

#ifdef CONFIG_SCST_DEBUG

/**
 * scst_random() - return a pseudo-random number for debugging purposes.
 *
 * Returns a pseudo-random number for debugging purposes. Available only in
 * the DEBUG build.
 *
 * Original taken from the XFS code
 */
unsigned long scst_random(void)
{
	static int Inited;
	static unsigned long RandomValue;
	static DEFINE_SPINLOCK(lock);
	/* cycles pseudo-randomly through all values between 1 and 2^31 - 2 */
	register long rv;
	register long lo;
	register long hi;
	unsigned long flags;

	spin_lock_irqsave(&lock, flags);
	if (!Inited) {
		RandomValue = jiffies;
		Inited = 1;
	}
	rv = RandomValue;
	hi = rv / 127773;
	lo = rv % 127773;
	rv = 16807 * lo - 2836 * hi;
	if (rv <= 0)
		rv += 2147483647;
	RandomValue = rv;
	spin_unlock_irqrestore(&lock, flags);
	return rv;
}
EXPORT_SYMBOL_GPL(scst_random);
#endif /* CONFIG_SCST_DEBUG */

#ifdef CONFIG_SCST_DEBUG_TM

#define TM_DBG_STATE_ABORT		0
#define TM_DBG_STATE_RESET		1
#define TM_DBG_STATE_OFFLINE		2

#define INIT_TM_DBG_STATE		TM_DBG_STATE_ABORT

static void tm_dbg_timer_fn(unsigned long arg);

static DEFINE_SPINLOCK(scst_tm_dbg_lock);
/* All serialized by scst_tm_dbg_lock */
static struct {
	unsigned int tm_dbg_release:1;
	unsigned int tm_dbg_blocked:1;
} tm_dbg_flags;
static LIST_HEAD(tm_dbg_delayed_cmd_list);
static int tm_dbg_delayed_cmds_count;
static int tm_dbg_passed_cmds_count;
static int tm_dbg_state;
static int tm_dbg_on_state_passes;
static DEFINE_TIMER(tm_dbg_timer, tm_dbg_timer_fn, 0, 0);
static struct scst_tgt_dev *tm_dbg_tgt_dev;

static const int tm_dbg_on_state_num_passes[] = { 5, 1, 0x7ffffff };

static void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	if (tgt_dev->lun == 15) {
		unsigned long flags;

		if (tm_dbg_tgt_dev != NULL)
			tm_dbg_deinit_tgt_dev(tm_dbg_tgt_dev);

		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		tm_dbg_state = INIT_TM_DBG_STATE;
		tm_dbg_on_state_passes =
			tm_dbg_on_state_num_passes[tm_dbg_state];
		tm_dbg_tgt_dev = tgt_dev;
		PRINT_INFO("LUN %lld connected from initiator %s is under "
			"TM debugging (tgt_dev %p)",
			(unsigned long long)tgt_dev->lun,
			tgt_dev->sess->initiator_name, tgt_dev);
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	}
	return;
}

static void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	if (tm_dbg_tgt_dev == tgt_dev) {
		unsigned long flags;
		TRACE_MGMT_DBG("Deinit TM debugging tgt_dev %p", tgt_dev);
		del_timer_sync(&tm_dbg_timer);
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		tm_dbg_tgt_dev = NULL;
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	}
	return;
}

static void tm_dbg_timer_fn(unsigned long arg)
{
	TRACE_MGMT_DBG("%s", "delayed cmd timer expired");
	tm_dbg_flags.tm_dbg_release = 1;
	wake_up_all(&tm_dbg_tgt_dev->active_cmd_threads->cmd_list_waitQ);
	return;
}

/* Called under scst_tm_dbg_lock and IRQs off */
static void tm_dbg_delay_cmd(struct scst_cmd *cmd)
{
	switch (tm_dbg_state) {
	case TM_DBG_STATE_ABORT:
		if (tm_dbg_delayed_cmds_count == 0) {
			unsigned long d = 58*HZ + (scst_random() % (4*HZ));
			TRACE_MGMT_DBG("STATE ABORT: delaying cmd %p (tag %llu)"
				" for %ld.%ld seconds (%ld HZ), "
				"tm_dbg_on_state_passes=%d", cmd, cmd->tag,
				d/HZ, (d%HZ)*100/HZ, d,	tm_dbg_on_state_passes);
			mod_timer(&tm_dbg_timer, jiffies + d);
#if 0
			tm_dbg_flags.tm_dbg_blocked = 1;
#endif
		} else {
			TRACE_MGMT_DBG("Delaying another timed cmd %p "
				"(tag %llu), delayed_cmds_count=%d, "
				"tm_dbg_on_state_passes=%d", cmd, cmd->tag,
				tm_dbg_delayed_cmds_count,
				tm_dbg_on_state_passes);
			if (tm_dbg_delayed_cmds_count == 2)
				tm_dbg_flags.tm_dbg_blocked = 0;
		}
		break;

	case TM_DBG_STATE_RESET:
	case TM_DBG_STATE_OFFLINE:
		TRACE_MGMT_DBG("STATE RESET/OFFLINE: delaying cmd %p "
			"(tag %llu), delayed_cmds_count=%d, "
			"tm_dbg_on_state_passes=%d", cmd, cmd->tag,
			tm_dbg_delayed_cmds_count, tm_dbg_on_state_passes);
		tm_dbg_flags.tm_dbg_blocked = 1;
		break;

	default:
		sBUG();
	}
	/* IRQs already off */
	spin_lock(&cmd->cmd_threads->cmd_list_lock);
	list_add_tail(&cmd->cmd_list_entry, &tm_dbg_delayed_cmd_list);
	spin_unlock(&cmd->cmd_threads->cmd_list_lock);
	cmd->tm_dbg_delayed = 1;
	tm_dbg_delayed_cmds_count++;
	return;
}

/* No locks */
void tm_dbg_check_released_cmds(void)
{
	if (tm_dbg_flags.tm_dbg_release) {
		struct scst_cmd *cmd, *tc;
		spin_lock_irq(&scst_tm_dbg_lock);
		list_for_each_entry_safe_reverse(cmd, tc,
				&tm_dbg_delayed_cmd_list, cmd_list_entry) {
			TRACE_MGMT_DBG("Releasing timed cmd %p (tag %llu), "
				"delayed_cmds_count=%d", cmd, cmd->tag,
				tm_dbg_delayed_cmds_count);
			spin_lock(&cmd->cmd_threads->cmd_list_lock);
			list_move(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
			spin_unlock(&cmd->cmd_threads->cmd_list_lock);
		}
		tm_dbg_flags.tm_dbg_release = 0;
		spin_unlock_irq(&scst_tm_dbg_lock);
	}
}

/* Called under scst_tm_dbg_lock, but can drop it inside, then reget */
static void tm_dbg_change_state(unsigned long *flags)
{
	tm_dbg_flags.tm_dbg_blocked = 0;
	if (--tm_dbg_on_state_passes == 0) {
		switch (tm_dbg_state) {
		case TM_DBG_STATE_ABORT:
			TRACE_MGMT_DBG("%s", "Changing "
			    "tm_dbg_state to RESET");
			tm_dbg_state = TM_DBG_STATE_RESET;
			tm_dbg_flags.tm_dbg_blocked = 0;
			break;
		case TM_DBG_STATE_RESET:
		case TM_DBG_STATE_OFFLINE:
#ifdef CONFIG_SCST_TM_DBG_GO_OFFLINE
			    TRACE_MGMT_DBG("%s", "Changing "
				    "tm_dbg_state to OFFLINE");
			    tm_dbg_state = TM_DBG_STATE_OFFLINE;
#else
			    TRACE_MGMT_DBG("%s", "Changing "
				    "tm_dbg_state to ABORT");
			    tm_dbg_state = TM_DBG_STATE_ABORT;
#endif
			break;
		default:
			sBUG();
		}
		tm_dbg_on_state_passes =
		    tm_dbg_on_state_num_passes[tm_dbg_state];
	}

	TRACE_MGMT_DBG("%s", "Deleting timer");
	spin_unlock_irqrestore(&scst_tm_dbg_lock, *flags);
	del_timer_sync(&tm_dbg_timer);
	spin_lock_irqsave(&scst_tm_dbg_lock, *flags);
	return;
}

/* No locks */
int tm_dbg_check_cmd(struct scst_cmd *cmd)
{
	int res = 0;
	unsigned long flags;

	if (cmd->tm_dbg_immut)
		goto out;

	if (cmd->tm_dbg_delayed) {
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		TRACE_MGMT_DBG("Processing delayed cmd %p (tag %llu), "
			"delayed_cmds_count=%d", cmd, cmd->tag,
			tm_dbg_delayed_cmds_count);

		cmd->tm_dbg_immut = 1;
		tm_dbg_delayed_cmds_count--;
		if ((tm_dbg_delayed_cmds_count == 0) &&
		    (tm_dbg_state == TM_DBG_STATE_ABORT))
			tm_dbg_change_state(&flags);
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	} else if (cmd->tgt_dev && (tm_dbg_tgt_dev == cmd->tgt_dev)) {
		/* Delay 5000th command */
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		if (tm_dbg_flags.tm_dbg_blocked ||
		    (++tm_dbg_passed_cmds_count % 5000) == 0) {
			tm_dbg_delay_cmd(cmd);
			res = 1;
		} else
			cmd->tm_dbg_immut = 1;
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	}

out:
	return res;
}

/* No locks */
void tm_dbg_release_cmd(struct scst_cmd *cmd)
{
	struct scst_cmd *c;
	unsigned long flags;

	spin_lock_irqsave(&scst_tm_dbg_lock, flags);
	list_for_each_entry(c, &tm_dbg_delayed_cmd_list,
				cmd_list_entry) {
		if (c == cmd) {
			TRACE_MGMT_DBG("Abort request for "
				"delayed cmd %p (tag=%llu), moving it to "
				"active cmd list (delayed_cmds_count=%d)",
				c, c->tag, tm_dbg_delayed_cmds_count);

			if (!(in_atomic() || in_interrupt() || irqs_disabled()))
				msleep(2000);

			if (!test_bit(SCST_CMD_ABORTED_OTHER,
					    &cmd->cmd_flags)) {
				/* Test how completed commands handled */
				if (((scst_random() % 10) == 5)) {
					scst_set_cmd_error(cmd,
						SCST_LOAD_SENSE(
						scst_sense_hardw_error));
					/* It's completed now */
				}
			}

			spin_lock(&cmd->cmd_threads->cmd_list_lock);
			list_move(&c->cmd_list_entry,
				&c->cmd_threads->active_cmd_list);
			wake_up(&c->cmd_threads->cmd_list_waitQ);
			spin_unlock(&cmd->cmd_threads->cmd_list_lock);
			break;
		}
	}
	spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	return;
}

/* Might be called under scst_mutex */
void tm_dbg_task_mgmt(struct scst_device *dev, const char *fn, int force)
{
	unsigned long flags;

	if (dev != NULL) {
		if (tm_dbg_tgt_dev == NULL)
			goto out;

		if (tm_dbg_tgt_dev->dev != dev)
			goto out;
	}

	spin_lock_irqsave(&scst_tm_dbg_lock, flags);
	if ((tm_dbg_state != TM_DBG_STATE_OFFLINE) || force) {
		TRACE_MGMT_DBG("%s: freeing %d delayed cmds", fn,
			tm_dbg_delayed_cmds_count);
		tm_dbg_change_state(&flags);
		tm_dbg_flags.tm_dbg_release = 1;
		/*
		 * Used to make sure that all woken up threads see the new
		 * value.
		 */
		smp_wmb();
		if (tm_dbg_tgt_dev != NULL)
			wake_up_all(&tm_dbg_tgt_dev->active_cmd_threads->cmd_list_waitQ);
	} else {
		TRACE_MGMT_DBG("%s: while OFFLINE state, doing nothing", fn);
	}
	spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);

out:
	return;
}

int tm_dbg_is_release(void)
{
	return tm_dbg_flags.tm_dbg_release;
}
#endif /* CONFIG_SCST_DEBUG_TM */

#ifdef CONFIG_SCST_DEBUG_SN
void scst_check_debug_sn(struct scst_cmd *cmd)
{
	int old = cmd->queue_type;

	/* To simulate from time to time queue flushing */
	if (!in_interrupt() && (scst_random() % 120) == 8) {
		int t = scst_random() % 1200;
		TRACE_SN("Delaying IO on %d ms", t);
		msleep(t);
	}

	if ((scst_random() % 15) == 7)
		cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
	else if ((scst_random() % 1000) == 751)
		cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	else if ((scst_random() % 1000) == 752)
		cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;

	if (old != cmd->queue_type)
		TRACE_SN("DbgSN queue type changed for cmd %p from %d to %d",
			cmd, old, cmd->queue_type);
	return;
}
#endif /* CONFIG_SCST_DEBUG_SN */

#ifdef CONFIG_SCST_MEASURE_LATENCY

static uint64_t scst_get_usec(void)
{
	struct timespec ts;

	ktime_get_ts(&ts);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
	return ((uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec) / 1000;
#else
#if (BITS_PER_LONG > 32)
	return timespec_to_ns(&ts) / 1000;
#else
	return timespec_to_ns(&ts) >> 10;
#endif
#endif
}

void scst_set_start_time(struct scst_cmd *cmd)
{
	cmd->start = scst_get_usec();
	TRACE_DBG("cmd %p: start %lld", cmd, cmd->start);
}

void scst_set_cur_start(struct scst_cmd *cmd)
{
	cmd->curr_start = scst_get_usec();
	TRACE_DBG("cmd %p: cur_start %lld", cmd, cmd->curr_start);
}

void scst_set_parse_time(struct scst_cmd *cmd)
{
	cmd->parse_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: parse_time %lld", cmd, cmd->parse_time);
}

void scst_set_alloc_buf_time(struct scst_cmd *cmd)
{
	cmd->alloc_buf_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: alloc_buf_time %lld", cmd, cmd->alloc_buf_time);
}

void scst_set_restart_waiting_time(struct scst_cmd *cmd)
{
	cmd->restart_waiting_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: restart_waiting_time %lld", cmd,
		cmd->restart_waiting_time);
}

void scst_set_rdy_to_xfer_time(struct scst_cmd *cmd)
{
	cmd->rdy_to_xfer_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: rdy_to_xfer_time %lld", cmd, cmd->rdy_to_xfer_time);
}

void scst_set_pre_exec_time(struct scst_cmd *cmd)
{
	cmd->pre_exec_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: pre_exec_time %lld", cmd, cmd->pre_exec_time);
}

void scst_set_exec_time(struct scst_cmd *cmd)
{
	cmd->exec_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: exec_time %lld", cmd, cmd->exec_time);
}

void scst_set_dev_done_time(struct scst_cmd *cmd)
{
	cmd->dev_done_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: dev_done_time %lld", cmd, cmd->dev_done_time);
}

void scst_set_xmit_time(struct scst_cmd *cmd)
{
	cmd->xmit_time += scst_get_usec() - cmd->curr_start;
	TRACE_DBG("cmd %p: xmit_time %lld", cmd, cmd->xmit_time);
}

void scst_update_lat_stats(struct scst_cmd *cmd)
{
	uint64_t finish, scst_time, tgt_time, dev_time;
	struct scst_session *sess = cmd->sess;
	int data_len;
	int i;
	struct scst_ext_latency_stat *latency_stat, *dev_latency_stat;

	finish = scst_get_usec();

	/* Determine the IO size for extended latency statistics */
	data_len = cmd->bufflen;
	i = SCST_LATENCY_STAT_INDEX_OTHER;
	if (data_len <= SCST_IO_SIZE_THRESHOLD_SMALL)
		i = SCST_LATENCY_STAT_INDEX_SMALL;
	else if (data_len <= SCST_IO_SIZE_THRESHOLD_MEDIUM)
		i = SCST_LATENCY_STAT_INDEX_MEDIUM;
	else if (data_len <= SCST_IO_SIZE_THRESHOLD_LARGE)
		i = SCST_LATENCY_STAT_INDEX_LARGE;
	else if (data_len <= SCST_IO_SIZE_THRESHOLD_VERY_LARGE)
		i = SCST_LATENCY_STAT_INDEX_VERY_LARGE;
	latency_stat = &sess->sess_latency_stat[i];
	if (cmd->tgt_dev != NULL)
		dev_latency_stat = &cmd->tgt_dev->dev_latency_stat[i];
	else
		dev_latency_stat = NULL;

	/* Calculate the latencies */
	scst_time = finish - cmd->start - (cmd->parse_time +
		cmd->alloc_buf_time + cmd->restart_waiting_time +
		cmd->rdy_to_xfer_time + cmd->pre_exec_time +
		cmd->exec_time + cmd->dev_done_time + cmd->xmit_time);
	tgt_time = cmd->alloc_buf_time + cmd->restart_waiting_time +
		cmd->rdy_to_xfer_time + cmd->pre_exec_time;
	dev_time = cmd->parse_time + cmd->exec_time + cmd->dev_done_time;

	spin_lock_bh(&sess->lat_lock);

	/* Save the basic latency information */
	sess->scst_time += scst_time;
	sess->tgt_time += tgt_time;
	sess->dev_time += dev_time;
	sess->processed_cmds++;

	if ((sess->min_scst_time == 0) ||
	    (sess->min_scst_time > scst_time))
		sess->min_scst_time = scst_time;
	if ((sess->min_tgt_time == 0) ||
	    (sess->min_tgt_time > tgt_time))
		sess->min_tgt_time = tgt_time;
	if ((sess->min_dev_time == 0) ||
	    (sess->min_dev_time > dev_time))
		sess->min_dev_time = dev_time;

	if (sess->max_scst_time < scst_time)
		sess->max_scst_time = scst_time;
	if (sess->max_tgt_time < tgt_time)
		sess->max_tgt_time = tgt_time;
	if (sess->max_dev_time < dev_time)
		sess->max_dev_time = dev_time;

	/* Save the extended latency information */
	if (cmd->data_direction & SCST_DATA_READ) {
		latency_stat->scst_time_rd += scst_time;
		latency_stat->tgt_time_rd += tgt_time;
		latency_stat->dev_time_rd += dev_time;
		latency_stat->processed_cmds_rd++;

		if ((latency_stat->min_scst_time_rd == 0) ||
		    (latency_stat->min_scst_time_rd > scst_time))
			latency_stat->min_scst_time_rd = scst_time;
		if ((latency_stat->min_tgt_time_rd == 0) ||
		    (latency_stat->min_tgt_time_rd > tgt_time))
			latency_stat->min_tgt_time_rd = tgt_time;
		if ((latency_stat->min_dev_time_rd == 0) ||
		    (latency_stat->min_dev_time_rd > dev_time))
			latency_stat->min_dev_time_rd = dev_time;

		if (latency_stat->max_scst_time_rd < scst_time)
			latency_stat->max_scst_time_rd = scst_time;
		if (latency_stat->max_tgt_time_rd < tgt_time)
			latency_stat->max_tgt_time_rd = tgt_time;
		if (latency_stat->max_dev_time_rd < dev_time)
			latency_stat->max_dev_time_rd = dev_time;

		if (dev_latency_stat != NULL) {
			dev_latency_stat->scst_time_rd += scst_time;
			dev_latency_stat->tgt_time_rd += tgt_time;
			dev_latency_stat->dev_time_rd += dev_time;
			dev_latency_stat->processed_cmds_rd++;

			if ((dev_latency_stat->min_scst_time_rd == 0) ||
			    (dev_latency_stat->min_scst_time_rd > scst_time))
				dev_latency_stat->min_scst_time_rd = scst_time;
			if ((dev_latency_stat->min_tgt_time_rd == 0) ||
			    (dev_latency_stat->min_tgt_time_rd > tgt_time))
				dev_latency_stat->min_tgt_time_rd = tgt_time;
			if ((dev_latency_stat->min_dev_time_rd == 0) ||
			    (dev_latency_stat->min_dev_time_rd > dev_time))
				dev_latency_stat->min_dev_time_rd = dev_time;

			if (dev_latency_stat->max_scst_time_rd < scst_time)
				dev_latency_stat->max_scst_time_rd = scst_time;
			if (dev_latency_stat->max_tgt_time_rd < tgt_time)
				dev_latency_stat->max_tgt_time_rd = tgt_time;
			if (dev_latency_stat->max_dev_time_rd < dev_time)
				dev_latency_stat->max_dev_time_rd = dev_time;
		}
	} else if (cmd->data_direction & SCST_DATA_WRITE) {
		latency_stat->scst_time_wr += scst_time;
		latency_stat->tgt_time_wr += tgt_time;
		latency_stat->dev_time_wr += dev_time;
		latency_stat->processed_cmds_wr++;

		if ((latency_stat->min_scst_time_wr == 0) ||
		    (latency_stat->min_scst_time_wr > scst_time))
			latency_stat->min_scst_time_wr = scst_time;
		if ((latency_stat->min_tgt_time_wr == 0) ||
		    (latency_stat->min_tgt_time_wr > tgt_time))
			latency_stat->min_tgt_time_wr = tgt_time;
		if ((latency_stat->min_dev_time_wr == 0) ||
		    (latency_stat->min_dev_time_wr > dev_time))
			latency_stat->min_dev_time_wr = dev_time;

		if (latency_stat->max_scst_time_wr < scst_time)
			latency_stat->max_scst_time_wr = scst_time;
		if (latency_stat->max_tgt_time_wr < tgt_time)
			latency_stat->max_tgt_time_wr = tgt_time;
		if (latency_stat->max_dev_time_wr < dev_time)
			latency_stat->max_dev_time_wr = dev_time;

		if (dev_latency_stat != NULL) {
			dev_latency_stat->scst_time_wr += scst_time;
			dev_latency_stat->tgt_time_wr += tgt_time;
			dev_latency_stat->dev_time_wr += dev_time;
			dev_latency_stat->processed_cmds_wr++;

			if ((dev_latency_stat->min_scst_time_wr == 0) ||
			    (dev_latency_stat->min_scst_time_wr > scst_time))
				dev_latency_stat->min_scst_time_wr = scst_time;
			if ((dev_latency_stat->min_tgt_time_wr == 0) ||
			    (dev_latency_stat->min_tgt_time_wr > tgt_time))
				dev_latency_stat->min_tgt_time_wr = tgt_time;
			if ((dev_latency_stat->min_dev_time_wr == 0) ||
			    (dev_latency_stat->min_dev_time_wr > dev_time))
				dev_latency_stat->min_dev_time_wr = dev_time;

			if (dev_latency_stat->max_scst_time_wr < scst_time)
				dev_latency_stat->max_scst_time_wr = scst_time;
			if (dev_latency_stat->max_tgt_time_wr < tgt_time)
				dev_latency_stat->max_tgt_time_wr = tgt_time;
			if (dev_latency_stat->max_dev_time_wr < dev_time)
				dev_latency_stat->max_dev_time_wr = dev_time;
		}
	}

	spin_unlock_bh(&sess->lat_lock);

	TRACE_DBG("cmd %p: finish %lld, scst_time %lld, "
		"tgt_time %lld, dev_time %lld", cmd, finish, scst_time,
		tgt_time, dev_time);
	return;
}

#endif /* CONFIG_SCST_MEASURE_LATENCY */
