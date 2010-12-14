/*
 *  scst_lib.c
 *
 *  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
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

/* get_trans_len_x extract x bytes from cdb as length starting from off */
static int get_trans_len_1(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_1_256(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_2(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_3(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_4(struct scst_cmd *cmd, uint8_t off);

static int get_bidi_trans_len_2(struct scst_cmd *cmd, uint8_t off);

/* for special commands */
static int get_trans_len_block_limit(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_read_capacity(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_serv_act_in(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_single(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_none(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_read_pos(struct scst_cmd *cmd, uint8_t off);
static int get_trans_cdb_len_10(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_prevent_allow_medium_removal(struct scst_cmd *cmd,
	uint8_t off);
static int get_trans_len_3_read_elem_stat(struct scst_cmd *cmd, uint8_t off);
static int get_trans_len_start_stop(struct scst_cmd *cmd, uint8_t off);

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
	const char *op_name;	/* SCSI-2 op codes full name */
	uint8_t direction;	/* init   --> target: SCST_DATA_WRITE
				 * target --> init:   SCST_DATA_READ
				 */
	uint16_t flags;		/* opcode --  various flags */
	uint8_t off;		/* length offset in cdb */
	int (*get_trans_len)(struct scst_cmd *cmd, uint8_t off);
};

static int scst_scsi_op_list[256];

#define FLAG_NONE 0

static const struct scst_sdbops scst_scsi_op_table[] = {
	/*
	 *      +-------------------> TYPE_IS_DISK      (0)
	 *      |
	 *      |+------------------> TYPE_IS_TAPE      (1)
	 *      ||
	 *      || +----------------> TYPE_IS_PROCESSOR (3)
	 *      || |
	 *      || | +--------------> TYPE_IS_CDROM     (5)
	 *      || | |
	 *      || | | +------------> TYPE_IS_MOD       (7)
	 *      || | | |
	 *      || | | |+-----------> TYPE_IS_CHANGER   (8)
	 *      || | | ||
	 *      || | | ||   +-------> TYPE_IS_RAID      (C)
	 *      || | | ||   |
	 *      || | | ||   |
	 *      0123456789ABCDEF ---> TYPE_IS_????     */

	/* 6-bytes length CDB */
	{0x00, "MMMMMMMMMMMMMMMM", "TEST UNIT READY",
	 /* let's be HQ to don't look dead under high load */
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT|SCST_IMPLICIT_HQ|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_EXCL_ACCESS_ALLOWED,
	 0, get_trans_len_none},
	{0x01, " M              ", "REWIND",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x01, "O V OO OO       ", "REZERO UNIT",
	 SCST_DATA_NONE, SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x02, "VVVVVV  V       ", "REQUEST BLOCK ADDR",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT, 0, get_trans_len_none},
	{0x03, "MMMMMMMMMMMMMMMM", "REQUEST SENSE",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT|SCST_SKIP_UA|SCST_LOCAL_CMD|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 4, get_trans_len_1},
	{0x04, "M    O O        ", "FORMAT UNIT",
	 SCST_DATA_WRITE, SCST_LONG_TIMEOUT|SCST_UNKNOWN_LENGTH|SCST_WRITE_MEDIUM,
	 0, get_trans_len_none},
	{0x04, "  O             ", "FORMAT",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x05, "VMVVVV  V       ", "READ BLOCK LIMITS",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 0, get_trans_len_block_limit},
	{0x07, "        O       ", "INITIALIZE ELEMENT STATUS",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x07, "OVV O  OV       ", "REASSIGN BLOCKS",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x08, "O               ", "READ(6)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 4, get_trans_len_1_256},
	{0x08, " MV OO OV       ", "READ(6)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_WRITE_EXCL_ALLOWED,
	 2, get_trans_len_3},
	{0x08, "         M      ", "GET MESSAGE(6)",
	 SCST_DATA_READ, FLAG_NONE, 2, get_trans_len_3},
	{0x08, "    O           ", "RECEIVE",
	 SCST_DATA_READ, FLAG_NONE, 2, get_trans_len_3},
	{0x0A, "O               ", "WRITE(6)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 4, get_trans_len_1_256},
	{0x0A, " M  O  OV       ", "WRITE(6)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 2, get_trans_len_3},
	{0x0A, "  M             ", "PRINT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x0A, "         M      ", "SEND MESSAGE(6)",
	 SCST_DATA_WRITE, FLAG_NONE, 2, get_trans_len_3},
	{0x0A, "    M           ", "SEND(6)",
	 SCST_DATA_WRITE, FLAG_NONE, 2, get_trans_len_3},
	{0x0B, "O   OO OV       ", "SEEK(6)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x0B, "                ", "TRACK SELECT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x0B, "  O             ", "SLEW AND PRINT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x0C, "VVVVVV  V       ", "SEEK BLOCK",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x0D, "VVVVVV  V       ", "PARTITION",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 0, get_trans_len_none},
	{0x0F, "VOVVVV  V       ", "READ REVERSE",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_WRITE_EXCL_ALLOWED,
	 2, get_trans_len_3},
	{0x10, "VM V V          ", "WRITE FILEMARKS",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x10, "  O O           ", "SYNCHRONIZE BUFFER",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x11, "VMVVVV          ", "SPACE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|
			 SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x12, "MMMMMMMMMMMMMMMM", "INQUIRY",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT|SCST_IMPLICIT_HQ|SCST_SKIP_UA|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 4, get_trans_len_1},
	{0x13, "VOVVVV          ", "VERIFY(6)",
	 SCST_DATA_NONE, SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_VERIFY_BYTCHK_MISMATCH_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED,
	 2, get_trans_len_3},
	{0x14, "VOOVVV          ", "RECOVER BUFFERED DATA",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_WRITE_EXCL_ALLOWED,
	 2, get_trans_len_3},
	{0x15, "OMOOOOOOOOOOOOOO", "MODE SELECT(6)",
	 SCST_DATA_WRITE, SCST_IMPLICIT_ORDERED, 4, get_trans_len_1},
	{0x16, "MMMMMMMMMMMMMMMM", "RESERVE",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|
			 SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 0, get_trans_len_none},
	{0x17, "MMMMMMMMMMMMMMMM", "RELEASE",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 0, get_trans_len_none},
	{0x18, "OOOOOOOO        ", "COPY",
	 SCST_DATA_WRITE, SCST_LONG_TIMEOUT, 2, get_trans_len_3},
	{0x19, "VMVVVV          ", "ERASE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 0, get_trans_len_none},
	{0x1A, "OMOOOOOOOOOOOOOO", "MODE SENSE(6)",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 4, get_trans_len_1},
	{0x1B, "      O         ", "SCAN",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x1B, " O              ", "LOAD UNLOAD",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x1B, "  O             ", "STOP PRINT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x1B, "O   OO O    O   ", "START STOP UNIT",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_start_stop},
	{0x1C, "OOOOOOOOOOOOOOOO", "RECEIVE DIAGNOSTIC RESULTS",
	 SCST_DATA_READ, FLAG_NONE, 3, get_trans_len_2},
	{0x1D, "MMMMMMMMMMMMMMMM", "SEND DIAGNOSTIC",
	 SCST_DATA_WRITE, FLAG_NONE, 4, get_trans_len_1},
	{0x1E, "OOOOOOOOOOOOOOOO", "PREVENT ALLOW MEDIUM REMOVAL",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0,
	 get_trans_len_prevent_allow_medium_removal},
	{0x1F, "            O   ", "PORT STATUS",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},

	 /* 10-bytes length CDB */
	{0x23, "V   VV V        ", "READ FORMAT CAPACITY",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x24, "V   VVM         ", "SET WINDOW",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_3},
	{0x25, "M   MM M        ", "READ CAPACITY",
	 SCST_DATA_READ, SCST_IMPLICIT_HQ|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 0, get_trans_len_read_capacity},
	{0x25, "      O         ", "GET WINDOW",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_3},
	{0x28, "M   MMMM        ", "READ(10)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 7, get_trans_len_2},
	{0x28, "         O      ", "GET MESSAGE(10)",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x29, "V   VV O        ", "READ GENERATION",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_1},
	{0x2A, "O   MO M        ", "WRITE(10)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 7, get_trans_len_2},
	{0x2A, "         O      ", "SEND MESSAGE(10)",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x2A, "      O         ", "SEND(10)",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x2B, " O              ", "LOCATE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|
			 SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x2B, "        O       ", "POSITION TO ELEMENT",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x2B, "O   OO O        ", "SEEK(10)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x2C, "V    O O        ", "ERASE(10)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 0, get_trans_len_none},
	{0x2D, "V   O  O        ", "READ UPDATED BLOCK",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 0, get_trans_len_single},
	{0x2E, "O   OO O        ", "WRITE AND VERIFY(10)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 7, get_trans_len_2},
	{0x2F, "O   OO O        ", "VERIFY(10)",
	 SCST_DATA_NONE, SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_VERIFY_BYTCHK_MISMATCH_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED,
	 7, get_trans_len_2},
	{0x33, "O   OO O        ", "SET LIMITS(10)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x34, " O              ", "READ POSITION",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT|
			 SCST_WRITE_EXCL_ALLOWED,
	 7, get_trans_len_read_pos},
	{0x34, "      O         ", "GET DATA BUFFER STATUS",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x34, "O   OO O        ", "PRE-FETCH",
	 SCST_DATA_NONE, SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x35, "O   OO O        ", "SYNCHRONIZE CACHE",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x36, "O   OO O        ", "LOCK UNLOCK CACHE",
	 SCST_DATA_NONE, SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x37, "O      O        ", "READ DEFECT DATA(10)",
	 SCST_DATA_READ, SCST_WRITE_EXCL_ALLOWED,
	 8, get_trans_len_1},
	{0x37, "        O       ", "INIT ELEMENT STATUS WRANGE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x38, "    O  O        ", "MEDIUM SCAN",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_1},
	{0x39, "OOOOOOOO        ", "COMPARE",
	 SCST_DATA_WRITE, FLAG_NONE, 3, get_trans_len_3},
	{0x3A, "OOOOOOOO        ", "COPY AND VERIFY",
	 SCST_DATA_WRITE, FLAG_NONE, 3, get_trans_len_3},
	{0x3B, "OOOOOOOOOOOOOOOO", "WRITE BUFFER",
	 SCST_DATA_WRITE, SCST_SMALL_TIMEOUT, 6, get_trans_len_3},
	{0x3C, "OOOOOOOOOOOOOOOO", "READ BUFFER",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 6, get_trans_len_3},
	{0x3D, "    O  O        ", "UPDATE BLOCK",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED,
	 0, get_trans_len_single},
	{0x3E, "O   OO O        ", "READ LONG",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x3F, "O   O  O        ", "WRITE LONG",
	 SCST_DATA_WRITE, SCST_WRITE_MEDIUM, 7, get_trans_len_2},
	{0x40, "OOOOOOOOOO      ", "CHANGE DEFINITION",
	 SCST_DATA_WRITE, SCST_SMALL_TIMEOUT, 8, get_trans_len_1},
	{0x41, "O    O          ", "WRITE SAME",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 0, get_trans_len_single},
	{0x42, "     O          ", "READ SUB-CHANNEL",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x42, "O               ", "UNMAP",
	 SCST_DATA_WRITE, SCST_WRITE_MEDIUM, 7, get_trans_len_2},
	{0x43, "     O          ", "READ TOC/PMA/ATIP",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x44, " M              ", "REPORT DENSITY SUPPORT",
	 SCST_DATA_READ, SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 7, get_trans_len_2},
	{0x44, "     O          ", "READ HEADER",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x45, "     O          ", "PLAY AUDIO(10)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x46, "     O          ", "GET CONFIGURATION",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x47, "     O          ", "PLAY AUDIO MSF",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x48, "     O          ", "PLAY AUDIO TRACK INDEX",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x49, "     O          ", "PLAY TRACK RELATIVE(10)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x4A, "     O          ", "GET EVENT STATUS NOTIFICATION",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x4B, "     O          ", "PAUSE/RESUME",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x4C, "OOOOOOOOOOOOOOOO", "LOG SELECT",
	 SCST_DATA_WRITE, SCST_IMPLICIT_ORDERED, 7, get_trans_len_2},
	{0x4D, "OOOOOOOOOOOOOOOO", "LOG SENSE",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 7, get_trans_len_2},
	{0x4E, "     O          ", "STOP PLAY/SCAN",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x50, "                ", "XDWRITE",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x51, "     O          ", "READ DISC INFORMATION",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x51, "                ", "XPWRITE",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x52, "     O          ", "READ TRACK INFORMATION",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x53, "O               ", "XDWRITEREAD(10)",
	 SCST_DATA_READ|SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|
					 SCST_WRITE_MEDIUM,
	 7, get_bidi_trans_len_2},
	{0x53, "     O          ", "RESERVE TRACK",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x54, "     O          ", "SEND OPC INFORMATION",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x55, "OOOOOOOOOOOOOOOO", "MODE SELECT(10)",
	 SCST_DATA_WRITE, SCST_IMPLICIT_ORDERED, 7, get_trans_len_2},
	{0x56, "OOOOOOOOOOOOOOOO", "RESERVE(10)",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD,
	 0, get_trans_len_none},
	{0x57, "OOOOOOOOOOOOOOOO", "RELEASE(10)",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT|SCST_LOCAL_CMD|
			 SCST_REG_RESERVE_ALLOWED,
	 0, get_trans_len_none},
	{0x58, "     O          ", "REPAIR TRACK",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x5A, "OOOOOOOOOOOOOOOO", "MODE SENSE(10)",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 7, get_trans_len_2},
	{0x5B, "     O          ", "CLOSE TRACK/SESSION",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x5C, "     O          ", "READ BUFFER CAPACITY",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x5D, "     O          ", "SEND CUE SHEET",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_3},
	{0x5E, "OOOOO OOOO      ", "PERSISTENT RESERV IN",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT|
			 SCST_LOCAL_CMD|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 5, get_trans_len_4},
	{0x5F, "OOOOO OOOO      ", "PERSISTENT RESERV OUT",
	 SCST_DATA_WRITE, SCST_SMALL_TIMEOUT|
			 SCST_LOCAL_CMD|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 5, get_trans_len_4},

	/* 16-bytes length CDB */
	{0x80, "O   OO O        ", "XDWRITE EXTENDED",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x80, " M              ", "WRITE FILEMARKS",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0x81, "O   OO O        ", "REBUILD",
	 SCST_DATA_WRITE, SCST_WRITE_MEDIUM, 10, get_trans_len_4},
	{0x82, "O   OO O        ", "REGENERATE",
	 SCST_DATA_WRITE, SCST_WRITE_MEDIUM, 10, get_trans_len_4},
	{0x83, "OOOOOOOOOOOOOOOO", "EXTENDED COPY",
	 SCST_DATA_WRITE, SCST_WRITE_MEDIUM, 10, get_trans_len_4},
	{0x84, "OOOOOOOOOOOOOOOO", "RECEIVE COPY RESULT",
	 SCST_DATA_WRITE, FLAG_NONE, 10, get_trans_len_4},
	{0x86, "OOOOOOOOOO      ", "ACCESS CONTROL IN",
	 SCST_DATA_NONE, SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 0, get_trans_len_none},
	{0x87, "OOOOOOOOOO      ", "ACCESS CONTROL OUT",
	 SCST_DATA_NONE, SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|
			 SCST_EXCL_ACCESS_ALLOWED,
	 0, get_trans_len_none},
	{0x88, "M   MMMM        ", "READ(16)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 10, get_trans_len_4},
	{0x8A, "O   OO O        ", "WRITE(16)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 10, get_trans_len_4},
	{0x8C, "OOOOOOOOOO      ", "READ ATTRIBUTE",
	 SCST_DATA_READ, FLAG_NONE, 10, get_trans_len_4},
	{0x8D, "OOOOOOOOOO      ", "WRITE ATTRIBUTE",
	 SCST_DATA_WRITE, SCST_WRITE_MEDIUM, 10, get_trans_len_4},
	{0x8E, "O   OO O        ", "WRITE AND VERIFY(16)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 10, get_trans_len_4},
	{0x8F, "O   OO O        ", "VERIFY(16)",
	 SCST_DATA_NONE, SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_VERIFY_BYTCHK_MISMATCH_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED,
	 10, get_trans_len_4},
	{0x90, "O   OO O        ", "PRE-FETCH(16)",
	 SCST_DATA_NONE, SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x91, "O   OO O        ", "SYNCHRONIZE CACHE(16)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x91, " M              ", "SPACE(16)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|
			 SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x92, "O   OO O        ", "LOCK UNLOCK CACHE(16)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x92, " O              ", "LOCATE(16)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|
			 SCST_WRITE_EXCL_ALLOWED,
	 0, get_trans_len_none},
	{0x93, "O    O          ", "WRITE SAME(16)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 10, get_trans_len_4},
	{0x93, " M              ", "ERASE(16)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT|SCST_WRITE_MEDIUM,
	 0, get_trans_len_none},
	{0x9E, "O               ", "SERVICE ACTION IN",
	 SCST_DATA_READ, FLAG_NONE, 0, get_trans_len_serv_act_in},

	/* 12-bytes length CDB */
	{0xA0, "VVVVVVVVVV  M   ", "REPORT LUNS",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT|SCST_IMPLICIT_HQ|SCST_SKIP_UA|
			 SCST_FULLY_LOCAL_CMD|SCST_LOCAL_CMD|
			 SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 6, get_trans_len_4},
	{0xA1, "     O          ", "BLANK",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0xA3, "     O          ", "SEND KEY",
	 SCST_DATA_WRITE, FLAG_NONE, 8, get_trans_len_2},
	{0xA3, "OOOOO OOOO      ", "REPORT DEVICE IDENTIDIER",
	 SCST_DATA_READ, SCST_REG_RESERVE_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED|SCST_EXCL_ACCESS_ALLOWED,
	 6, get_trans_len_4},
	{0xA3, "            M   ", "MAINTENANCE(IN)",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_4},
	{0xA4, "     O          ", "REPORT KEY",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_2},
	{0xA4, "            O   ", "MAINTENANCE(OUT)",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_4},
	{0xA5, "        M       ", "MOVE MEDIUM",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0xA5, "     O          ", "PLAY AUDIO(12)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xA6, "     O  O       ", "EXCHANGE/LOAD/UNLOAD MEDIUM",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0xA7, "     O          ", "SET READ AHEAD",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xA8, "         O      ", "GET MESSAGE(12)",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_4},
	{0xA8, "O   OO O        ", "READ(12)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			 SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			 SCST_WRITE_EXCL_ALLOWED,
	 6, get_trans_len_4},
	{0xA9, "     O          ", "PLAY TRACK RELATIVE(12)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xAA, "O   OO O        ", "WRITE(12)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|
#ifdef CONFIG_SCST_TEST_IO_IN_SIRQ
			  SCST_TEST_IO_IN_SIRQ_ALLOWED|
#endif
			  SCST_WRITE_MEDIUM,
	 6, get_trans_len_4},
	{0xAA, "         O      ", "SEND MESSAGE(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_4},
	{0xAC, "       O        ", "ERASE(12)",
	 SCST_DATA_NONE, SCST_WRITE_MEDIUM, 0, get_trans_len_none},
	{0xAC, "     M          ", "GET PERFORMANCE",
	 SCST_DATA_READ, SCST_UNKNOWN_LENGTH, 0, get_trans_len_none},
	{0xAD, "     O          ", "READ DVD STRUCTURE",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_2},
	{0xAE, "O   OO O        ", "WRITE AND VERIFY(12)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED|SCST_WRITE_MEDIUM,
	 6, get_trans_len_4},
	{0xAF, "O   OO O        ", "VERIFY(12)",
	 SCST_DATA_NONE, SCST_TRANSFER_LEN_TYPE_FIXED|
			 SCST_VERIFY_BYTCHK_MISMATCH_ALLOWED|
			 SCST_WRITE_EXCL_ALLOWED,
	 6, get_trans_len_4},
#if 0 /* No need to support at all */
	{0xB0, "    OO O        ", "SEARCH DATA HIGH(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
	{0xB1, "    OO O        ", "SEARCH DATA EQUAL(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
	{0xB2, "    OO O        ", "SEARCH DATA LOW(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
#endif
	{0xB3, "    OO O        ", "SET LIMITS(12)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xB5, "        O       ", "REQUEST VOLUME ELEMENT ADDRESS",
	 SCST_DATA_READ, FLAG_NONE, 9, get_trans_len_1},
	{0xB6, "        O       ", "SEND VOLUME TAG",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
	{0xB6, "     M         ", "SET STREAMING",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_2},
	{0xB7, "       O        ", "READ DEFECT DATA(12)",
	 SCST_DATA_READ, SCST_WRITE_EXCL_ALLOWED,
	 9, get_trans_len_1},
	{0xB8, "        O       ", "READ ELEMENT STATUS",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_3_read_elem_stat},
	{0xB9, "     O          ", "READ CD MSF",
	 SCST_DATA_READ, SCST_UNKNOWN_LENGTH, 0, get_trans_len_none},
	{0xBA, "     O          ", "SCAN",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0xBA, "            O   ", "REDUNDANCY GROUP(IN)",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_4},
	{0xBB, "     O          ", "SET SPEED",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xBB, "            O   ", "REDUNDANCY GROUP(OUT)",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_4},
	{0xBC, "            O   ", "SPARE(IN)",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_4},
	{0xBD, "     O          ", "MECHANISM STATUS",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_2},
	{0xBD, "            O   ", "SPARE(OUT)",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_4},
	{0xBE, "     O          ", "READ CD",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 6, get_trans_len_3},
	{0xBE, "            O   ", "VOLUME SET(IN)",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_4},
	{0xBF, "     O          ", "SEND DVD STRUCTUE",
	 SCST_DATA_WRITE, FLAG_NONE, 8, get_trans_len_2},
	{0xBF, "            O   ", "VOLUME SET(OUT)",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_4},
	{0xE7, "        V       ", "INIT ELEMENT STATUS WRANGE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_cdb_len_10}
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
static void scst_unblock_cmds(struct scst_device *dev);
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
	gfp_t gfp_mask = atomic ? GFP_ATOMIC : (GFP_KERNEL|__GFP_NOFAIL);

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

	if ((cmd->sg != NULL) && SCST_SENSE_VALID(sg_virt(cmd->sg))) {
		TRACE_MGMT_DBG("cmd %p already has sense set", cmd);
		res = -EEXIST;
		goto out;
	}

	if (cmd->sg == NULL) {
		/*
		 * If target driver preparing data buffer using alloc_data_buf()
		 * callback, it is responsible to copy the sense to its buffer
		 * in xmit_response().
		 */
		if (cmd->tgt_data_buf_alloced && (cmd->tgt_sg != NULL)) {
			cmd->sg = cmd->tgt_sg;
			cmd->sg_cnt = cmd->tgt_sg_cnt;
			TRACE_MEM("Tgt sg used for sense for cmd %p", cmd);
			goto go;
		}

		if (cmd->bufflen == 0)
			cmd->bufflen = cmd->cdb[4];

		cmd->sg = scst_alloc(cmd->bufflen, GFP_ATOMIC, &cmd->sg_cnt);
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
		/*
		 * If target driver preparing data buffer using alloc_data_buf()
		 * callback, it is responsible to copy the sense to its buffer
		 * in xmit_response().
		 */
		if (cmd->tgt_data_buf_alloced && (cmd->tgt_sg != NULL)) {
			cmd->sg = cmd->tgt_sg;
			cmd->sg_cnt = cmd->tgt_sg_cnt;
			TRACE_MEM("Tgt used for INQUIRY for not supported "
				"LUN for cmd %p", cmd);
			goto go;
		}

		if (cmd->bufflen == 0)
			cmd->bufflen = min_t(int, 36, (cmd->cdb[3] << 8) | cmd->cdb[4]);

		cmd->sg = scst_alloc(cmd->bufflen, GFP_ATOMIC, &cmd->sg_cnt);
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
	TRACE_BUFFER("Sense set", cmd->sense, cmd->sense_valid_len);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_set_cmd_error);

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
	if ((sense[0] == 0x70) || (sense[0] == 0x71)) {
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
	} else if ((sense[0] == 0x72) || (sense[0] == 0x73)) {
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
	} else
		goto out;

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
	if (SCST_SENSE_VALID(sense))
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
 */
void scst_check_convert_sense(struct scst_cmd *cmd)
{
	bool d_sense;

	TRACE_ENTRY();

	if ((cmd->sense == NULL) || (cmd->status != SAM_STAT_CHECK_CONDITION))
		goto out;

	d_sense = scst_get_cmd_dev_d_sense(cmd);
	if (d_sense && ((cmd->sense[0] == 0x70) || (cmd->sense[0] == 0x71))) {
		TRACE_MGMT_DBG("Converting fixed sense to descriptor (cmd %p)",
			cmd);
		if ((cmd->sense_valid_len < 18)) {
			PRINT_ERROR("Sense too small to convert (%d, "
				"type: fixed)", cmd->sense_buflen);
			goto out;
		}
		cmd->sense_valid_len = scst_set_sense(cmd->sense, cmd->sense_buflen,
			d_sense, cmd->sense[2], cmd->sense[12], cmd->sense[13]);
	} else if (!d_sense && ((cmd->sense[0] == 0x72) ||
				(cmd->sense[0] == 0x73))) {
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

static int scst_set_cmd_error_sense(struct scst_cmd *cmd, uint8_t *sense,
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

				ua = list_entry(tgt_dev->UA_list.next,
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

	TRACE_MGMT_DBG("REPORTED LUNS DATA CHANGED (acg %s)", acg->acg_name);

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

void scst_requeue_ua(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
			SCST_SENSE_ALL_VALID,
			SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed))) {
		TRACE_MGMT_DBG("Requeuing REPORTED LUNS DATA CHANGED UA "
			"for delivery failed cmd %p", cmd);
		mutex_lock(&scst_mutex);
		scst_queue_report_luns_changed_UA(cmd->sess,
			SCST_SET_UA_FLAG_AT_HEAD);
		mutex_unlock(&scst_mutex);
	} else {
		TRACE_MGMT_DBG("Requeuing UA for delivery failed cmd %p", cmd);
		scst_check_set_UA(cmd->tgt_dev, cmd->sense,
			cmd->sense_valid_len, SCST_SET_UA_FLAG_AT_HEAD);
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
	bool add_failed, something_freed, not_needed_freed = false;

	TRACE_ENTRY();

	if (sess->shut_phase != SCST_SESS_SPH_READY)
		goto out;

	TRACE_MGMT_DBG("Checking reassignment for sess %p (initiator %s)",
		sess, sess->initiator_name);

	acg = scst_find_acg(sess);
	if (acg == sess->acg) {
		TRACE_MGMT_DBG("No reassignment for sess %p", sess);
		goto out;
	}

	TRACE_MGMT_DBG("sess %p will be reassigned from acg %s to acg %s",
		sess, sess->acg->acg_name, acg->acg_name);

	old_acg = sess->acg;
	sess->acg = NULL; /* to catch implicit dependencies earlier */

retry_add:
	add_failed = false;
	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		unsigned int inq_changed_ua_needed = 0;

		for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
			head = &sess->sess_tgt_dev_list[i];

			list_for_each_entry(tgt_dev, head,
					sess_tgt_dev_list_entry) {
				if ((tgt_dev->dev == acg_dev->dev) &&
				    (tgt_dev->lun == acg_dev->lun) &&
				    (tgt_dev->acg_dev->rd_only == acg_dev->rd_only)) {
					TRACE_MGMT_DBG("sess %p: tgt_dev %p for "
						"LUN %lld stays the same",
						sess, tgt_dev,
						(unsigned long long)tgt_dev->lun);
					tgt_dev->acg_dev = acg_dev;
					goto next;
				} else if (tgt_dev->lun == acg_dev->lun)
					inq_changed_ua_needed = 1;
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

		tgt_dev->inq_changed_ua_needed = inq_changed_ua_needed ||
						 not_needed_freed;
next:
		continue;
	}

	something_freed = false;
	not_needed_freed = true;
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
						SCST_LOAD_SENSE(scst_sense_inquery_data_changed));
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

static int scst_get_cmd_abnormal_done_state(const struct scst_cmd *cmd)
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
	case SCST_CMD_STATE_SEND_FOR_EXEC:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_REAL_EXECUTING:
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

/**
 * scst_set_cmd_abnormal_done_state() - set command's next abnormal done state
 *
 * Sets state of the SCSI target state machine to abnormally complete command
 * ASAP.
 *
 * Returns the new state.
 */
int scst_set_cmd_abnormal_done_state(struct scst_cmd *cmd)
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
	case SCST_CMD_STATE_SEND_FOR_EXEC:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_REAL_EXECUTING:
	case SCST_CMD_STATE_DEV_DONE:
	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_MODE_SELECT_CHECKS:
	case SCST_CMD_STATE_PRE_XMIT_RESP:
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

	TRACE_EXIT_RES(cmd->state);
	return cmd->state;
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
	int i, j, l;

	TRACE_ENTRY();

	l = 0;
	for (i = 0, j = 0; i < *sg_cnt; i++, j++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
		TRACE_DBG("i %d, j %d, sg_cnt %d, sg %p, page_link %lx", i, j,
			*sg_cnt, sg, sg[j].page_link);
#else
		TRACE_DBG("i %d, j %d, sg_cnt %d, sg %p, page_link %lx", i, j,
			*sg_cnt, sg, 0UL);
#endif
		if (unlikely(sg_is_chain(&sg[j]))) {
			sg = sg_chain_ptr(&sg[j]);
			j = 0;
		}
		l += sg[j].length;
		if (l >= adjust_len) {
			int left = adjust_len - (l - sg[j].length);
#ifdef CONFIG_SCST_DEBUG
			TRACE(TRACE_SG_OP|TRACE_MEMORY, "cmd %p (tag %llu), "
				"sg %p, sg_cnt %d, adjust_len %d, i %d, j %d, "
				"sg[j].length %d, left %d",
				cmd, (long long unsigned int)cmd->tag,
				sg, *sg_cnt, adjust_len, i, j,
				sg[j].length, left);
#endif
			cmd->orig_sg = sg;
			cmd->p_orig_sg_cnt = sg_cnt;
			cmd->orig_sg_cnt = *sg_cnt;
			cmd->orig_sg_entry = j;
			cmd->orig_entry_len = sg[j].length;
			*sg_cnt = (left > 0) ? j+1 : j;
			sg[j].length = left;
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
	TRACE_MEM("cmd %p, sg %p, orig_sg_entry %d, "
		"orig_entry_len %d, orig_sg_cnt %d", cmd, cmd->orig_sg,
		cmd->orig_sg_entry, cmd->orig_entry_len,
		cmd->orig_sg_cnt);
	cmd->orig_sg[cmd->orig_sg_entry].length = cmd->orig_entry_len;
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

	sBUG_ON(!cmd->expected_values_set);

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

/**
 * __scst_get_resid() - returns residuals for cmd
 *
 * Returns residuals for command. Must not be called directly, use
 * scst_get_resid() instead.
 */
bool __scst_get_resid(struct scst_cmd *cmd, int *resid, int *bidi_out_resid)
{
	TRACE_ENTRY();

	*resid = 0;
	if (bidi_out_resid != NULL)
		*bidi_out_resid = 0;

	sBUG_ON(!cmd->expected_values_set);

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

	TRACE_DBG("cmd %p, resid %d, bidi_out_resid %d (resp_data_len %d, "
		"expected_data_direction %d, write_len %d, bufflen %d)", cmd,
		*resid, bidi_out_resid ? *bidi_out_resid : 0, cmd->resp_data_len,
		cmd->expected_data_direction, cmd->write_len, cmd->bufflen);

	TRACE_EXIT_RES(1);
	return true;
}
EXPORT_SYMBOL(__scst_get_resid);

/* No locks */
int scst_queue_retry_cmd(struct scst_cmd *cmd, int finished_cmds)
{
	struct scst_tgt *tgt = cmd->tgt;
	int res = 0;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&tgt->tgt_lock, flags);
	tgt->retry_cmds++;
	/*
	 * Memory barrier is needed here, because we need the exact order
	 * between the read and write between retry_cmds and finished_cmds to
	 * not miss the case when a command finished while we queueing it for
	 * retry after the finished_cmds check.
	 */
	smp_mb();
	TRACE_RETRY("TGT QUEUE FULL: incrementing retry_cmds %d",
	      tgt->retry_cmds);
	if (finished_cmds != atomic_read(&tgt->finished_cmds)) {
		/* At least one cmd finished, so try again */
		tgt->retry_cmds--;
		TRACE_RETRY("Some command(s) finished, direct retry "
		      "(finished_cmds=%d, tgt->finished_cmds=%d, "
		      "retry_cmds=%d)", finished_cmds,
		      atomic_read(&tgt->finished_cmds), tgt->retry_cmds);
		res = -1;
		goto out_unlock_tgt;
	}

	TRACE_RETRY("Adding cmd %p to retry cmd list", cmd);
	list_add_tail(&cmd->cmd_list_entry, &tgt->retry_cmd_list);

	if (!tgt->retry_timer_active) {
		tgt->retry_timer.expires = jiffies + SCST_TGT_RETRY_TIMEOUT;
		add_timer(&tgt->retry_timer);
		tgt->retry_timer_active = 1;
	}

out_unlock_tgt:
	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	TRACE_EXIT_RES(res);
	return res;
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

	TRACE_MGMT_DBG("Cmd %p HW pending for too long %ld (state %x)",
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
static void scst_hw_pending_work_fn(struct delayed_work *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct scst_session *sess = (struct scst_session *)p;
#else
	struct scst_session *sess = container_of(work, struct scst_session,
					hw_pending_work);
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

	if (mutex_lock_interruptible(&scst_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

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

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (t == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of tgt failed");
		res = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&t->sess_list);
	init_waitqueue_head(&t->unreg_waitQ);
	t->tgtt = tgtt;
	t->sg_tablesize = tgtt->sg_tablesize;
	spin_lock_init(&t->tgt_lock);
	INIT_LIST_HEAD(&t->retry_cmd_list);
	atomic_set(&t->finished_cmds, 0);
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
#ifdef CONFIG_SCST_PROC
	kfree(tgt->default_group_name);
#endif

	kfree(tgt);

	TRACE_EXIT();
	return;
}

/* Called under scst_mutex and suspended activity */
int scst_alloc_device(gfp_t gfp_mask, struct scst_device **out_dev)
{
	struct scst_device *dev;
	int res = 0;

	TRACE_ENTRY();

	dev = kzalloc(sizeof(*dev), gfp_mask);
	if (dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
			"Allocation of scst_device failed");
		res = -ENOMEM;
		goto out;
	}

	dev->handler = &scst_null_devtype;
	atomic_set(&dev->dev_cmd_count, 0);
	atomic_set(&dev->write_cmd_count, 0);
	scst_init_mem_lim(&dev->dev_mem_lim);
	spin_lock_init(&dev->dev_lock);
	INIT_LIST_HEAD(&dev->blocked_cmd_list);
	INIT_LIST_HEAD(&dev->dev_tgt_dev_list);
	INIT_LIST_HEAD(&dev->dev_acg_dev_list);
	dev->dev_double_ua_possible = 1;
	dev->queue_alg = SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER;

	mutex_init(&dev->dev_pr_mutex);
	atomic_set(&dev->pr_readers_count, 0);
	dev->pr_generation = 0;
	dev->pr_is_set = 0;
	dev->pr_holder = NULL;
	dev->pr_scope = SCOPE_LU;
	dev->pr_type = TYPE_UNSPECIFIED;
	INIT_LIST_HEAD(&dev->dev_registrants_list);

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
	kfree(dev);

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
		TRACE(TRACE_OUT_OF_MEM,
		      "%s", "Allocation of scst_acg_dev failed");
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
	bool del_sysfs = true;

	TRACE_ENTRY();

	INIT_LIST_HEAD(&tmp_tgt_dev_list);

	acg_dev = scst_alloc_acg_dev(acg, dev, lun);
	if (acg_dev == NULL) {
		res = -ENOMEM;
		goto out;
	}
	acg_dev->rd_only = read_only;

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
	if (res != 0) {
		del_sysfs = false;
		goto out_free;
	}

	if (gen_scst_report_luns_changed)
		scst_report_luns_changed(acg);

	PRINT_INFO("Added device %s to group %s (LUN %lld, "
		"rd_only %d)", dev->virt_name, acg->acg_name,
		(long long unsigned int)lun, read_only);

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
	scst_del_free_acg_dev(acg_dev, del_sysfs);
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

	PRINT_INFO("Removed LUN %lld from group %s", (unsigned long long)lun,
		acg->acg_name);

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
		TRACE_MGMT_DBG("Going to share async IO context %p (res %p, "
			"ini %s, dev %s, grouping type %d)",
			t->aic_keeper->aic, res, t->sess->initiator_name,
			t->dev->virt_name,
			t->acg_dev->acg->acg_io_grouping_type);
	} else {
		res = t;
		if (!*(volatile bool*)&res->active_cmd_threads->io_context_ready) {
			TRACE_MGMT_DBG("IO context for t %p not yet "
				"initialized, waiting...", t);
			msleep(100);
			barrier();
			goto found;
		}
		TRACE_MGMT_DBG("Going to share IO context %p (res %p, ini %s, "
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
	aic_keeper->aic = get_io_context(GFP_KERNEL, -1);
#endif
	TRACE_MGMT_DBG("Alloced new async IO context %p (aic %p)",
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

			TRACE_MGMT_DBG("Linking async io context %p "
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

			TRACE_MGMT_DBG("Created async io context %p "
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
			TRACE_MGMT_DBG("Linking io context %p for "
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
	int i, sl;
	uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	tgt_dev = kmem_cache_zalloc(scst_tgtd_cachep, GFP_KERNEL);
	if (tgt_dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of scst_tgt_dev "
			"failed");
		res = -ENOMEM;
		goto out;
	}

	tgt_dev->dev = dev;
	tgt_dev->lun = acg_dev->lun;
	tgt_dev->acg_dev = acg_dev;
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
	spin_lock_init(&tgt_dev->thr_data_lock);
	INIT_LIST_HEAD(&tgt_dev->thr_data_list);
	spin_lock_init(&tgt_dev->sn_lock);
	INIT_LIST_HEAD(&tgt_dev->deferred_cmd_list);
	INIT_LIST_HEAD(&tgt_dev->skipped_sn_list);
	tgt_dev->curr_sn = (typeof(tgt_dev->curr_sn))(-300);
	tgt_dev->expected_sn = tgt_dev->curr_sn + 1;
	tgt_dev->num_free_sn_slots = ARRAY_SIZE(tgt_dev->sn_slots)-1;
	tgt_dev->cur_sn_slot = &tgt_dev->sn_slots[0];
	for (i = 0; i < (int)ARRAY_SIZE(tgt_dev->sn_slots); i++)
		atomic_set(&tgt_dev->sn_slots[i], 0);

	if (dev->handler->parse_atomic &&
	    dev->handler->alloc_data_buf_atomic &&
	    (sess->tgt->tgtt->preprocessing_done == NULL)) {
		if (sess->tgt->tgtt->rdy_to_xfer_atomic)
			__set_bit(SCST_TGT_DEV_AFTER_INIT_WR_ATOMIC,
				&tgt_dev->tgt_dev_flags);
	}
	if (dev->handler->dev_done_atomic &&
	    sess->tgt->tgtt->xmit_response_atomic) {
		__set_bit(SCST_TGT_DEV_AFTER_EXEC_ATOMIC,
			&tgt_dev->tgt_dev_flags);
	}

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

	if (dev->handler && dev->handler->attach_tgt) {
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
	if (dev->dev_reserved)
		__set_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags);
	spin_unlock_bh(&dev->dev_lock);

	head = &sess->sess_tgt_dev_list[SESS_TGT_DEV_LIST_HASH_FN(tgt_dev->lun)];
	list_add_tail(&tgt_dev->sess_tgt_dev_list_entry, head);

	*out_tgt_dev = tgt_dev;

out:
	TRACE_EXIT_RES(res);
	return res;

out_detach:
	if (dev->handler && dev->handler->detach_tgt) {
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

	scst_clear_reservation(tgt_dev);

#if 0 /* Clearing UAs and last sense isn't required by SAM and it looks to be
       * better to not clear them to not loose important events, so let's
       * disable it.
       */
	/* With activity suspended the lock isn't needed, but let's be safe */
	spin_lock_bh(&tgt_dev->tgt_dev_lock);
	scst_free_all_UA(tgt_dev);
	memset(tgt_dev->tgt_dev_sense, 0, sizeof(tgt_dev->tgt_dev_sense));
	spin_unlock_bh(&tgt_dev->tgt_dev_lock);
#endif

	if (queue_UA) {
		uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
		int sl = scst_set_sense(sense_buffer, sizeof(sense_buffer),
				tgt_dev->dev->d_sense,
				SCST_LOAD_SENSE(scst_sense_nexus_loss_UA));
		scst_check_set_UA(tgt_dev, sense_buffer, sl, 0);
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

	sBUG_ON(!list_empty(&tgt_dev->thr_data_list));

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
		PRINT_INFO("Added name %s to group %s", name, acg->acg_name);
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
		PRINT_INFO("Removed name '%s' from group '%s'", name,
			acg->acg_name);
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
	unsigned int cdb_len, int bufsize)
{
	struct scst_cmd *res;
	gfp_t gfp_mask = scst_cmd_atomic(orig_cmd) ? GFP_ATOMIC : GFP_KERNEL;

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
	res->tgt_dev = orig_cmd->tgt_dev;
	res->lun = orig_cmd->lun;
	res->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	res->data_direction = SCST_DATA_UNKNOWN;
	res->orig_cmd = orig_cmd;
	res->bufflen = bufsize;

	scst_sess_get(res->sess);
	if (res->tgt_dev != NULL)
		__scst_get();

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
			SCST_SENSE_BUFFERSIZE);
	if (rs_cmd == NULL)
		goto out_error;

	rs_cmd->cdb[1] |= scst_get_cmd_dev_d_sense(orig_cmd);
	rs_cmd->data_direction = SCST_DATA_READ;
	rs_cmd->expected_data_direction = rs_cmd->data_direction;
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
	struct scst_cmd *orig_cmd = req_cmd->orig_cmd;
	uint8_t *buf;
	int len;

	TRACE_ENTRY();

	sBUG_ON(orig_cmd == NULL);

	len = scst_get_buf_first(req_cmd, &buf);

	if (scsi_status_is_good(req_cmd->status) && (len > 0) &&
	    SCST_SENSE_VALID(buf) && (!SCST_NO_SENSE(buf))) {
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
		scst_put_buf(req_cmd, buf);

	TRACE_MGMT_DBG("Adding orig cmd %p to head of active "
		"cmd list", orig_cmd);
	spin_lock_irq(&orig_cmd->cmd_threads->cmd_list_lock);
	list_add(&orig_cmd->cmd_list_entry, &orig_cmd->cmd_threads->active_cmd_list);
	wake_up(&orig_cmd->cmd_threads->cmd_list_waitQ);
	spin_unlock_irq(&orig_cmd->cmd_threads->cmd_list_lock);

	TRACE_EXIT();
	return;
}

int scst_finish_internal_cmd(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	sBUG_ON(!cmd->internal);

	if (cmd->cdb[0] == REQUEST_SENSE)
		scst_complete_request_sense(cmd);

	__scst_cmd_put(cmd);

	res = SCST_CMD_STATE_RES_CONT_NEXT;

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
	if (dev->dev_reserved &&
	    !test_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags)) {
		/* This is one who holds the reservation */
		struct scst_tgt_dev *tgt_dev_tmp;
		list_for_each_entry(tgt_dev_tmp, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			clear_bit(SCST_TGT_DEV_RESERVED,
				    &tgt_dev_tmp->tgt_dev_flags);
		}
		dev->dev_reserved = 0;
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
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of scst_session failed");
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
	INIT_DELAYED_WORK(&sess->hw_pending_work,
		(void (*)(struct work_struct *))scst_hw_pending_work_fn);
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

#ifndef CONFIG_SCST_PROC
	mutex_unlock(&scst_mutex);
	scst_sess_sysfs_del(sess);
	mutex_lock(&scst_mutex);
#endif

	/*
	 * The lists delete must be after sysfs del. Otherwise it would break
	 * logic in scst_sess_sysfs_create() to avoid duplicate sysfs names.
	 */

	TRACE_DBG("Removing sess %p from the list", sess);
	list_del(&sess->sess_list_entry);
	TRACE_DBG("Removing session %p from acg %s", sess, sess->acg->acg_name);
	list_del(&sess->acg_sess_list_entry);

	/* Called under lock to protect from too early tgt release */
	wake_up_all(&sess->tgt->unreg_waitQ);

	/*
	 * NOTE: do not dereference the sess->tgt pointer after scst_mutex
	 * has been unlocked, because it can be already dead!!
	 */
	mutex_unlock(&scst_mutex);

	kfree(sess->transport_id);
	kfree(sess->initiator_name);

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

	if (sess->unreg_done_fn) {
		TRACE_DBG("Calling unreg_done_fn(%p)", sess);
		sess->unreg_done_fn(sess);
		TRACE_DBG("%s", "unreg_done_fn() returned");
	}
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

struct scst_cmd *scst_alloc_cmd(const uint8_t *cdb,
	unsigned int cdb_len, gfp_t gfp_mask)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	cmd = kmem_cache_zalloc(scst_cmd_cachep, gfp_mask);
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of scst_cmd failed");
		goto out;
	}

	cmd->state = SCST_CMD_STATE_INIT_WAIT;
	cmd->start_time = jiffies;
	atomic_set(&cmd->cmd_ref, 1);
	cmd->cmd_threads = &scst_main_cmd_threads;
	INIT_LIST_HEAD(&cmd->mgmt_cmd_list);
	cmd->cdb = cmd->cdb_buf;
	cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
	cmd->timeout = SCST_DEFAULT_TIMEOUT;
	cmd->retries = 0;
	cmd->data_len = -1;
	cmd->is_send_status = 1;
	cmd->resp_data_len = -1;
	cmd->write_sg = &cmd->sg;
	cmd->write_sg_cnt = &cmd->sg_cnt;

	cmd->dbl_ua_orig_data_direction = SCST_DATA_UNKNOWN;
	cmd->dbl_ua_orig_resp_data_len = -1;

	if (unlikely(cdb_len == 0)) {
		PRINT_ERROR("%s", "Wrong CDB len 0, finishing cmd");
		goto out_free;
	} else if (cdb_len <= SCST_MAX_CDB_SIZE) {
		/* Duplicate memcpy to save a branch on the most common path */
		memcpy(cmd->cdb, cdb, cdb_len);
	} else {
		if (unlikely(cdb_len > SCST_MAX_LONG_CDB_SIZE)) {
			PRINT_ERROR("Too big CDB (%d), finishing cmd", cdb_len);
			goto out_free;
		}
		cmd->cdb = kmalloc(cdb_len, gfp_mask);
		if (unlikely(cmd->cdb == NULL)) {
			PRINT_ERROR("Unable to alloc extended CDB (size %d)",
				cdb_len);
			goto out_free;
		}
		memcpy(cmd->cdb, cdb, cdb_len);
	}

	cmd->cdb_len = cdb_len;

out:
	TRACE_EXIT();
	return cmd;

out_free:
	kmem_cache_free(scst_cmd_cachep, cmd);
	cmd = NULL;
	goto out;
}

static void scst_destroy_put_cmd(struct scst_cmd *cmd)
{
	scst_sess_put(cmd->sess);

	/*
	 * At this point tgt_dev can be dead, but the pointer remains non-NULL
	 */
	if (likely(cmd->tgt_dev != NULL))
		__scst_put();

	scst_destroy_cmd(cmd);
	return;
}

/* No locks supposed to be held */
void scst_free_cmd(struct scst_cmd *cmd)
{
	int destroy = 1;

	TRACE_ENTRY();

	TRACE_DBG("Freeing cmd %p (tag %llu)",
		  cmd, (long long unsigned int)cmd->tag);

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Freeing aborted cmd %p (scst_cmd_count %d)",
			cmd, atomic_read(&scst_cmd_count));
	}

	sBUG_ON(cmd->unblock_dev);

	/*
	 * Target driver can already free sg buffer before calling
	 * scst_tgt_cmd_done(). E.g., scst_local has to do that.
	 */
	if (!cmd->tgt_data_buf_alloced)
		scst_check_restore_sg_buff(cmd);

	if ((cmd->tgtt->on_free_cmd != NULL) && likely(!cmd->internal)) {
		TRACE_DBG("Calling target's on_free_cmd(%p)", cmd);
		scst_set_cur_start(cmd);
		cmd->tgtt->on_free_cmd(cmd);
		scst_set_tgt_on_free_time(cmd);
		TRACE_DBG("%s", "Target's on_free_cmd() returned");
	}

	if (likely(cmd->dev != NULL)) {
		struct scst_dev_type *handler = cmd->dev->handler;
		if (handler->on_free_cmd != NULL) {
			TRACE_DBG("Calling dev handler %s on_free_cmd(%p)",
				handler->name, cmd);
			scst_set_cur_start(cmd);
			handler->on_free_cmd(cmd);
			scst_set_dev_on_free_time(cmd);
			TRACE_DBG("Dev handler %s on_free_cmd() returned",
				handler->name);
		}
	}

	scst_release_space(cmd);

	if (unlikely(cmd->sense != NULL)) {
		TRACE_MEM("Releasing sense %p (cmd %p)", cmd->sense, cmd);
		mempool_free(cmd->sense, scst_sense_mempool);
		cmd->sense = NULL;
	}

	if (likely(cmd->tgt_dev != NULL)) {
#ifdef CONFIG_SCST_EXTRACHECKS
		if (unlikely(!cmd->sent_for_exec) && !cmd->internal) {
			PRINT_ERROR("Finishing not executed cmd %p (opcode "
			    "%d, target %s, LUN %lld, sn %d, expected_sn %d)",
			    cmd, cmd->cdb[0], cmd->tgtt->name,
			    (long long unsigned int)cmd->lun,
			    cmd->sn, cmd->tgt_dev->expected_sn);
			scst_unblock_deferred(cmd->tgt_dev, cmd);
		}
#endif

		if (unlikely(cmd->out_of_sn)) {
			TRACE_SN("Out of SN cmd %p (tag %llu, sn %d), "
				"destroy=%d", cmd,
				(long long unsigned int)cmd->tag,
				cmd->sn, destroy);
			destroy = test_and_set_bit(SCST_CMD_CAN_BE_DESTROYED,
					&cmd->cmd_flags);
		}
	}

	if (cmd->cdb != cmd->cdb_buf)
		kfree(cmd->cdb);

	if (likely(destroy))
		scst_destroy_put_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* No locks supposed to be held. */
void scst_check_retries(struct scst_tgt *tgt)
{
	int need_wake_up = 0;

	TRACE_ENTRY();

	/*
	 * We don't worry about overflow of finished_cmds, because we check
	 * only for its change.
	 */
	atomic_inc(&tgt->finished_cmds);
	/* See comment in scst_queue_retry_cmd() */
	smp_mb__after_atomic_inc();
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
			if (need_wake_up >= 2) /* "slow start" */
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
		__scst_put();

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

	if (tgt_dev->dev->handler->on_sg_tablesize_low == NULL)
		goto failed;

	res = tgt_dev->dev->handler->on_sg_tablesize_low(cmd);

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

	gfp_mask = tgt_dev->gfp_mask | (atomic ? GFP_ATOMIC : GFP_KERNEL);

	flags = atomic ? SGV_POOL_NO_ALLOC_ON_CACHE_MISS : 0;
	if (cmd->no_sgv)
		flags |= SGV_POOL_ALLOC_NO_CACHED;

	cmd->sg = sgv_pool_alloc(tgt_dev->pool, cmd->bufflen, gfp_mask, flags,
			&cmd->sg_cnt, &cmd->sgv, &cmd->dev->dev_mem_lim, NULL);
	if (cmd->sg == NULL)
		goto out;

	if (unlikely(cmd->sg_cnt > tgt_dev->max_sg_cnt))
		if (!scst_on_sg_tablesize_low(cmd, false))
			goto out_sg_free;

	if (cmd->data_direction != SCST_DATA_BIDI)
		goto success;

	cmd->out_sg = sgv_pool_alloc(tgt_dev->pool, cmd->out_bufflen, gfp_mask,
			 flags, &cmd->out_sg_cnt, &cmd->out_sgv,
			 &cmd->dev->dev_mem_lim, NULL);
	if (cmd->out_sg == NULL)
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
		    !(cmd->tgt_data_buf_alloced || cmd->dh_data_buf_alloced)) {
			TRACE_MEM("Freeing sg %p for cmd %p (cnt %d)", cmd->sg,
				cmd, cmd->sg_cnt);
			scst_free(cmd->sg, cmd->sg_cnt);
			goto out_zero;
		} else
			goto out;
	}

	if (cmd->tgt_data_buf_alloced || cmd->dh_data_buf_alloced) {
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

#if !((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED))

/*
 * Can switch to the next dst_sg element, so, to copy to strictly only
 * one dst_sg element, it must be either last in the chain, or
 * copy_len == dst_sg->length.
 */
static int sg_copy_elem(struct scatterlist **pdst_sg, size_t *pdst_len,
			size_t *pdst_offs, struct scatterlist *src_sg,
			size_t copy_len,
			enum km_type d_km_type, enum km_type s_km_type)
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

		saddr = kmap_atomic(src_page +
					 (src_offs >> PAGE_SHIFT), s_km_type) +
				    (src_offs & ~PAGE_MASK);
		daddr = kmap_atomic(dst_page +
					(dst_offs >> PAGE_SHIFT), d_km_type) +
				    (dst_offs & ~PAGE_MASK);

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

		kunmap_atomic(saddr, s_km_type);
		kunmap_atomic(daddr, d_km_type);

		res += n;
		copy_len -= n;
		if (copy_len == 0)
			goto out;

		src_len -= n;
		dst_len -= n;
		if (dst_len == 0) {
			dst_sg = sg_next(dst_sg);
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
	    int nents_to_copy, size_t copy_len,
	    enum km_type d_km_type, enum km_type s_km_type)
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
				src_sg, copy_len, d_km_type, s_km_type);
		copy_len -= copied;
		res += copied;
		if ((copy_len == 0) || (dst_sg == NULL))
			goto out;

		nents_to_copy--;
		if (nents_to_copy == 0)
			goto out;

		src_sg = sg_next(src_sg);
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
	gfp_t gfp = GFP_KERNEL;
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
 * Copies data between cmd->tgt_sg and cmd->sg in direction defined by
 * copy_dir parameter.
 */
void scst_copy_sg(struct scst_cmd *cmd, enum scst_sg_copy_dir copy_dir)
{
	struct scatterlist *src_sg, *dst_sg;
	unsigned int to_copy;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	if (copy_dir == SCST_SG_COPY_FROM_TARGET) {
		if (cmd->data_direction != SCST_DATA_BIDI) {
			src_sg = cmd->tgt_sg;
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
		dst_sg = cmd->tgt_sg;
		to_copy = cmd->resp_data_len;
	}

	TRACE_MEM("cmd %p, copy_dir %d, src_sg %p, dst_sg %p, to_copy %lld",
		cmd, copy_dir, src_sg, dst_sg, (long long)to_copy);

	if (unlikely(src_sg == NULL) || unlikely(dst_sg == NULL)) {
		/*
		 * It can happened, e.g., with scst_user for cmd with delay
		 * alloc, which failed with Check Condition.
		 */
		goto out;
	}

	sg_copy(dst_sg, src_sg, 0, to_copy,
		atomic ? KM_SOFTIRQ0 : KM_USER0,
		atomic ? KM_SOFTIRQ1 : KM_USER1);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_copy_sg);

/**
 * scst_get_full_buf - return linear buffer for command
 * @cmd:	scst command
 * @buf:	pointer on the resulting pointer
 *
 * If the command's buffer >single page, it vmalloc() the needed area
 * and copies the buffer there. Returns length of the buffer or negative
 * error code otherwise.
 */
int scst_get_full_buf(struct scst_cmd *cmd, uint8_t **buf)
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
EXPORT_SYMBOL(scst_get_full_buf);

/**
 * scst_put_full_buf - unmaps linear buffer for command
 * @cmd:	scst command
 * @buf:	pointer on the buffer to unmap
 *
 * Reverse operation for scst_get_full_buf. If the buffer was vmalloced(),
 * it vfree() the buffer.
 */
void scst_put_full_buf(struct scst_cmd *cmd, uint8_t *buf)
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
EXPORT_SYMBOL(scst_put_full_buf);

static const int SCST_CDB_LENGTH[8] = { 6, 10, 10, 0, 16, 12, 0, 0 };

#define SCST_CDB_GROUP(opcode)   ((opcode >> 5) & 0x7)
#define SCST_GET_CDB_LEN(opcode) SCST_CDB_LENGTH[SCST_CDB_GROUP(opcode)]

/* get_trans_len_x extract x bytes from cdb as length starting from off */

static int get_trans_cdb_len_10(struct scst_cmd *cmd, uint8_t off)
{
	cmd->cdb_len = 10;
	cmd->bufflen = 0;
	return 0;
}

static int get_trans_len_block_limit(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = 6;
	return 0;
}

static int get_trans_len_read_capacity(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = 8;
	return 0;
}

static int get_trans_len_serv_act_in(struct scst_cmd *cmd, uint8_t off)
{
	int res = 0;

	TRACE_ENTRY();

	if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
		cmd->op_name = "READ CAPACITY(16)";
		cmd->bufflen = be32_to_cpu(get_unaligned((__be32 *)&cmd->cdb[10]));
		cmd->op_flags |= SCST_IMPLICIT_HQ | SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
	} else
		cmd->op_flags |= SCST_UNKNOWN_LENGTH;

	TRACE_EXIT_RES(res);
	return res;
}

static int get_trans_len_single(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = 1;
	return 0;
}

static int get_trans_len_read_pos(struct scst_cmd *cmd, uint8_t off)
{
	uint8_t *p = (uint8_t *)cmd->cdb + off;
	int res = 0;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 8;
	cmd->bufflen |= ((u32)p[1]);

	switch (cmd->cdb[1] & 0x1f) {
	case 0:
	case 1:
	case 6:
		if (cmd->bufflen != 0) {
			PRINT_ERROR("READ POSITION: Invalid non-zero (%d) "
				"allocation length for service action %x",
				cmd->bufflen, cmd->cdb[1] & 0x1f);
			goto out_inval;
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
		goto out_inval;
	}

out:
	return res;

out_inval:
	scst_set_cmd_error(cmd,
		SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	res = 1;
	goto out;
}

static int get_trans_len_prevent_allow_medium_removal(struct scst_cmd *cmd,
	uint8_t off)
{
	if ((cmd->cdb[4] & 3) == 0)
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
	return 0;
}

static int get_trans_len_start_stop(struct scst_cmd *cmd, uint8_t off)
{
	if ((cmd->cdb[4] & 0xF1) == 0x1)
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
	return 0;
}

static int get_trans_len_3_read_elem_stat(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 16;
	cmd->bufflen |= ((u32)p[1]) << 8;
	cmd->bufflen |= ((u32)p[2]);

	if ((cmd->cdb[6] & 0x2) == 0x2)
		cmd->op_flags |= SCST_REG_RESERVE_ALLOWED |
			SCST_WRITE_EXCL_ALLOWED | SCST_EXCL_ACCESS_ALLOWED;
	return 0;
}

static int get_trans_len_1(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = (u32)cmd->cdb[off];
	return 0;
}

static int get_trans_len_1_256(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = (u32)cmd->cdb[off];
	if (cmd->bufflen == 0)
		cmd->bufflen = 256;
	return 0;
}

static int get_trans_len_2(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 8;
	cmd->bufflen |= ((u32)p[1]);

	return 0;
}

static int get_trans_len_3(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 16;
	cmd->bufflen |= ((u32)p[1]) << 8;
	cmd->bufflen |= ((u32)p[2]);

	return 0;
}

static int get_trans_len_4(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 24;
	cmd->bufflen |= ((u32)p[1]) << 16;
	cmd->bufflen |= ((u32)p[2]) << 8;
	cmd->bufflen |= ((u32)p[3]);

	return 0;
}

static int get_trans_len_none(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = 0;
	return 0;
}

static int get_bidi_trans_len_2(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 8;
	cmd->bufflen |= ((u32)p[1]);

	cmd->out_bufflen = cmd->bufflen;

	return 0;
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

	TRACE_DBG("opcode=%02x, cdblen=%d bytes, tblsize=%d, "
		"dev_type=%d", op, SCST_GET_CDB_LEN(op), SCST_CDB_TBL_SIZE,
		dev_type);

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
			      ptr->op_name);
			TRACE_DBG("direction=%d flags=%d off=%d",
			      ptr->direction,
			      ptr->flags,
			      ptr->off);
			break;
		}
		i++;
	}

	if (unlikely(ptr == NULL)) {
		/* opcode not found or now not used */
		TRACE(TRACE_MINOR, "Unknown opcode 0x%x for type %d", op,
		      dev_type);
		res = -1;
		goto out;
	}

	cmd->cdb_len = SCST_GET_CDB_LEN(op);
	cmd->op_name = ptr->op_name;
	cmd->data_direction = ptr->direction;
	cmd->op_flags = ptr->flags | SCST_INFO_VALID;
	res = (*ptr->get_trans_len)(cmd, ptr->off);

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

/*
 * Routine to extract a lun number from an 8-byte LUN structure
 * in network byte order (BE).
 * (see SAM-2, Section 4.12.3 page 40)
 * Supports 2 types of lun unpacking: peripheral and logical unit.
 */
uint64_t scst_unpack_lun(const uint8_t *lun, int len)
{
	uint64_t res = NO_SUCH_LUN;
	int address_method;

	TRACE_ENTRY();

	TRACE_BUFF_FLAG(TRACE_DEBUG, "Raw LUN", lun, len);

	if (unlikely(len < 2)) {
		PRINT_ERROR("Illegal lun length %d, expected 2 bytes or "
			"more", len);
		goto out;
	}

	if (len > 2) {
		switch (len) {
		case 8:
			if ((*((__be64 *)lun) &
			  __constant_cpu_to_be64(0x0000FFFFFFFFFFFFLL)) != 0)
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
		default:
			goto out_err;
		}
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
	int block_shift = 0;
	int t;

	if (sector_size == 0)
		sector_size = 512;

	t = sector_size;
	while (1) {
		if ((t & 1) != 0)
			break;
		t >>= 1;
		block_shift++;
	}
	if (block_shift < 9) {
		PRINT_ERROR("Wrong sector size %d", sector_size);
		block_shift = -1;
	}

	TRACE_EXIT_RES(block_shift);
	return block_shift;
}
EXPORT_SYMBOL_GPL(scst_calc_block_shift);

/**
 * scst_sbc_generic_parse() - generic SBC parsing
 *
 * Generic parse() for SBC (disk) devices
 */
int scst_sbc_generic_parse(struct scst_cmd *cmd,
	int (*get_block_shift)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

	switch (cmd->cdb[0]) {
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = cmd->bufflen << get_block_shift(cmd);
			cmd->bufflen = 0;
			goto set_timeout;
		} else
			cmd->data_len = 0;
		break;
	default:
		/* It's all good */
		break;
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED) {
		int block_shift = get_block_shift(cmd);
		/*
		 * No need for locks here, since *_detach() can not be
		 * called, when there are existing commands.
		 */
		cmd->bufflen = cmd->bufflen << block_shift;
		cmd->out_bufflen = cmd->out_bufflen << block_shift;
	}

set_timeout:
	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_DISK_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_DISK_LONG_TIMEOUT;

	TRACE_DBG("res %d, bufflen %d, data_len %d, direct %d",
	      res, cmd->bufflen, cmd->data_len, cmd->data_direction);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_sbc_generic_parse);

/**
 * scst_cdrom_generic_parse() - generic MMC parse
 *
 * Generic parse() for MMC (cdrom) devices
 */
int scst_cdrom_generic_parse(struct scst_cmd *cmd,
	int (*get_block_shift)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

	cmd->cdb[1] &= 0x1f;

	switch (cmd->cdb[0]) {
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = cmd->bufflen << get_block_shift(cmd);
			cmd->bufflen = 0;
			goto set_timeout;
		}
		break;
	default:
		/* It's all good */
		break;
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED) {
		int block_shift = get_block_shift(cmd);
		cmd->bufflen = cmd->bufflen << block_shift;
		cmd->out_bufflen = cmd->out_bufflen << block_shift;
	}

set_timeout:
	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_CDROM_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_CDROM_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_CDROM_LONG_TIMEOUT;

	TRACE_DBG("res=%d, bufflen=%d, direct=%d", res, cmd->bufflen,
		cmd->data_direction);

	TRACE_EXIT();
	return res;
}
EXPORT_SYMBOL_GPL(scst_cdrom_generic_parse);

/**
 * scst_modisk_generic_parse() - generic MO parse
 *
 * Generic parse() for MO disk devices
 */
int scst_modisk_generic_parse(struct scst_cmd *cmd,
	int (*get_block_shift)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

	cmd->cdb[1] &= 0x1f;

	switch (cmd->cdb[0]) {
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = cmd->bufflen << get_block_shift(cmd);
			cmd->bufflen = 0;
			goto set_timeout;
		}
		break;
	default:
		/* It's all good */
		break;
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED) {
		int block_shift = get_block_shift(cmd);
		cmd->bufflen = cmd->bufflen << block_shift;
		cmd->out_bufflen = cmd->out_bufflen << block_shift;
	}

set_timeout:
	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_MODISK_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_MODISK_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_MODISK_LONG_TIMEOUT;

	TRACE_DBG("res=%d, bufflen=%d, direct=%d", res, cmd->bufflen,
		cmd->data_direction);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_modisk_generic_parse);

/**
 * scst_tape_generic_parse() - generic tape parse
 *
 * Generic parse() for tape devices
 */
int scst_tape_generic_parse(struct scst_cmd *cmd,
	int (*get_block_size)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

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
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED & cmd->cdb[1]) {
		int block_size = get_block_size(cmd);
		cmd->bufflen = cmd->bufflen * block_size;
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

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);
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
int scst_changer_generic_parse(struct scst_cmd *cmd,
	int (*nothing)(struct scst_cmd *cmd))
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
int scst_processor_generic_parse(struct scst_cmd *cmd,
	int (*nothing)(struct scst_cmd *cmd))
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
int scst_raid_generic_parse(struct scst_cmd *cmd,
	int (*nothing)(struct scst_cmd *cmd))
{
	int res = scst_null_parse(cmd);

	if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_RAID_LONG_TIMEOUT;
	else
		cmd->timeout = SCST_GENERIC_RAID_TIMEOUT;

	return res;
}
EXPORT_SYMBOL_GPL(scst_raid_generic_parse);

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

	if ((status == SAM_STAT_GOOD) || (status == SAM_STAT_CONDITION_MET)) {
		switch (opcode) {
		case READ_CAPACITY:
		{
			/* Always keep track of disk capacity */
			int buffer_size, sector_size, sh;
			uint8_t *buffer;

			buffer_size = scst_get_buf_first(cmd, &buffer);
			if (unlikely(buffer_size <= 0)) {
				if (buffer_size < 0) {
					PRINT_ERROR("%s: Unable to get the"
					" buffer (%d)",	__func__, buffer_size);
				}
				goto out;
			}

			sector_size =
			    ((buffer[4] << 24) | (buffer[5] << 16) |
			     (buffer[6] << 8) | (buffer[7] << 0));
			scst_put_buf(cmd, buffer);
			if (sector_size != 0)
				sh = scst_calc_block_shift(sector_size);
			else
				sh = 0;
			set_block_shift(cmd, sh);
			TRACE_DBG("block_shift %d", sh);
			break;
		}
		default:
			/* It's all good */
			break;
		}
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

	if (cmd->status != SAM_STAT_GOOD)
		goto out;

	switch (opcode) {
	case MODE_SENSE:
	case MODE_SELECT:
		buffer_size = scst_get_buf_first(cmd, &buffer);
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
				bs = (buffer[9] << 16) |
				    (buffer[10] << 8) | buffer[11];
				set_block_size(cmd, bs);
			}
		}
		break;
	case MODE_SELECT:
		TRACE_DBG("%s", "MODE_SELECT");
		if (buffer[3] == 8) {
			bs = (buffer[9] << 16) | (buffer[10] << 8) |
			    (buffer[11]);
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
		scst_put_buf(cmd, buffer);
		break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_tape_generic_dev_done);

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

/**
 * scst_obtain_device_parameters() - obtain device control parameters
 *
 * Issues a MODE SENSE for control mode page data and sets the corresponding
 * dev's parameter from it. Returns 0 on success and not 0 otherwise.
 */
int scst_obtain_device_parameters(struct scst_device *dev)
{
	int rc, i;
	uint8_t cmd[16];
	uint8_t buffer[4+0x0A];
	uint8_t sense_buffer[SCSI_SENSE_BUFFERSIZE];

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(dev->scsi_dev == NULL);

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
			    SCST_SENSE_VALID(sense_buffer)) {
#else
			/*
			 * 3ware controller is buggy and returns CONDITION_GOOD
			 * instead of CHECK_CONDITION
			 */
			if (SCST_SENSE_VALID(sense_buffer)) {
#endif
				PRINT_BUFF_FLAG(TRACE_SCSI, "Returned sense "
					"data", sense_buffer,
					sizeof(sense_buffer));
				if (scst_analyze_sense(sense_buffer,
						sizeof(sense_buffer),
						SCST_SENSE_KEY_VALID,
						ILLEGAL_REQUEST, 0, 0)) {
					PRINT_INFO("Device %s doesn't support "
						"MODE SENSE", dev->virt_name);
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

/* Called under dev_lock and BH off */
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd, bool setUA)
{
	struct scst_tgt_dev *tgt_dev;
	struct scst_cmd *cmd, *tcmd;

	TRACE_ENTRY();

	/* Clear RESERVE'ation, if necessary */
	if (dev->dev_reserved) {
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			TRACE_MGMT_DBG("Clearing RESERVE'ation for "
				"tgt_dev LUN %lld",
				(long long unsigned int)tgt_dev->lun);
			clear_bit(SCST_TGT_DEV_RESERVED,
				  &tgt_dev->tgt_dev_flags);
		}
		dev->dev_reserved = 0;
		/*
		 * There is no need to send RELEASE, since the device is going
		 * to be reset. Actually, since we can be in RESET TM
		 * function, it might be dangerous.
		 */
	}

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

	list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
				blocked_cmd_list_entry) {
		if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
			list_del(&cmd->blocked_cmd_list_entry);
			TRACE_MGMT_DBG("Adding aborted blocked cmd %p "
				"to active cmd list", cmd);
			spin_lock_irq(&cmd->cmd_threads->cmd_list_lock);
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
			wake_up(&cmd->cmd_threads->cmd_list_waitQ);
			spin_unlock_irq(&cmd->cmd_threads->cmd_list_lock);
		}
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

/* No locks, no IRQ or IRQ-disabled context allowed */
int scst_set_pending_UA(struct scst_cmd *cmd)
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

	TRACE_MGMT_DBG("Setting pending UA cmd %p", cmd);

	spin_lock_bh(&cmd->tgt_dev->tgt_dev_lock);

again:
	/* UA list could be cleared behind us, so retest */
	if (list_empty(&cmd->tgt_dev->UA_list)) {
		TRACE_DBG("%s",
		      "SCST_TGT_DEV_UA_PENDING set, but UA_list empty");
		res = -1;
		goto out_unlock;
	}

	UA_entry = list_entry(cmd->tgt_dev->UA_list.next, typeof(*UA_entry),
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

	if (scst_set_cmd_error_sense(cmd, UA_entry->UA_sense_buffer,
			UA_entry->UA_valid_sense_len) != 0)
		goto out_unlock;

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
						list_del(&ua->UA_list_entry);
						mempool_free(ua, scst_ua_mempool);
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

/* Called under tgt_dev_lock and BH off */
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

	TRACE_MGMT_DBG("Adding new UA to tgt_dev %p", tgt_dev);

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
	int len = min((int)sizeof(UA_entry_tmp->UA_sense_buffer), sense_len);

	TRACE_ENTRY();

	list_for_each_entry(UA_entry_tmp, &tgt_dev->UA_list,
			    UA_list_entry) {
		if (memcmp(sense, UA_entry_tmp->UA_sense_buffer, len) == 0) {
			TRACE_MGMT_DBG("%s", "UA already exists");
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

/* Called under dev_lock and BH off */
void __scst_dev_check_set_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("Processing UA dev %p", dev);

	/* Check for reset UA */
	if (scst_analyze_sense(sense, sense_len, SCST_SENSE_ASC_VALID,
				0, SCST_SENSE_ASC_UA_RESET, 0))
		scst_process_reset(dev,
				   (exclude != NULL) ? exclude->sess : NULL,
				   exclude, NULL, false);

	scst_dev_check_set_local_UA(dev, exclude, sense, sense_len);

	TRACE_EXIT();
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

/* No locks */
struct scst_cmd *__scst_check_deferred_commands(struct scst_tgt_dev *tgt_dev)
{
	struct scst_cmd *res = NULL, *cmd, *t;
	typeof(tgt_dev->expected_sn) expected_sn = tgt_dev->expected_sn;

	spin_lock_irq(&tgt_dev->sn_lock);

	if (unlikely(tgt_dev->hq_cmd_count != 0))
		goto out_unlock;

restart:
	list_for_each_entry_safe(cmd, t, &tgt_dev->deferred_cmd_list,
				sn_cmd_list_entry) {
		EXTRACHECKS_BUG_ON(cmd->queue_type ==
			SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		if (cmd->sn == expected_sn) {
			TRACE_SN("Deferred command %p (sn %d, set %d) found",
				cmd, cmd->sn, cmd->sn_set);
			tgt_dev->def_cmd_count--;
			list_del(&cmd->sn_cmd_list_entry);
			if (res == NULL)
				res = cmd;
			else {
				spin_lock(&cmd->cmd_threads->cmd_list_lock);
				TRACE_SN("Adding cmd %p to active cmd list",
					cmd);
				list_add_tail(&cmd->cmd_list_entry,
					&cmd->cmd_threads->active_cmd_list);
				wake_up(&cmd->cmd_threads->cmd_list_waitQ);
				spin_unlock(&cmd->cmd_threads->cmd_list_lock);
			}
		}
	}
	if (res != NULL)
		goto out_unlock;

	list_for_each_entry(cmd, &tgt_dev->skipped_sn_list,
				sn_cmd_list_entry) {
		EXTRACHECKS_BUG_ON(cmd->queue_type ==
			SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		if (cmd->sn == expected_sn) {
			atomic_t *slot = cmd->sn_slot;
			/*
			 * !! At this point any pointer in cmd, except !!
			 * !! sn_slot and sn_cmd_list_entry, could be	!!
			 * !! already destroyed				!!
			 */
			TRACE_SN("cmd %p (tag %llu) with skipped sn %d found",
				 cmd,
				 (long long unsigned int)cmd->tag,
				 cmd->sn);
			tgt_dev->def_cmd_count--;
			list_del(&cmd->sn_cmd_list_entry);
			spin_unlock_irq(&tgt_dev->sn_lock);
			if (test_and_set_bit(SCST_CMD_CAN_BE_DESTROYED,
					     &cmd->cmd_flags))
				scst_destroy_put_cmd(cmd);
			scst_inc_expected_sn(tgt_dev, slot);
			expected_sn = tgt_dev->expected_sn;
			spin_lock_irq(&tgt_dev->sn_lock);
			goto restart;
		}
	}

out_unlock:
	spin_unlock_irq(&tgt_dev->sn_lock);
	return res;
}

/*****************************************************************
 ** The following thr_data functions are necessary, because the
 ** kernel doesn't provide a better way to have threads local
 ** storage
 *****************************************************************/

/**
 * scst_add_thr_data() - add the current thread's local data
 *
 * Adds local to the current thread data to tgt_dev
 * (they will be local for the tgt_dev and current thread).
 */
void scst_add_thr_data(struct scst_tgt_dev *tgt_dev,
	struct scst_thr_data_hdr *data,
	void (*free_fn) (struct scst_thr_data_hdr *data))
{
	data->owner_thr = current;
	atomic_set(&data->ref, 1);
	EXTRACHECKS_BUG_ON(free_fn == NULL);
	data->free_fn = free_fn;
	spin_lock(&tgt_dev->thr_data_lock);
	list_add_tail(&data->thr_data_list_entry, &tgt_dev->thr_data_list);
	spin_unlock(&tgt_dev->thr_data_lock);
}
EXPORT_SYMBOL_GPL(scst_add_thr_data);

/**
 * scst_del_all_thr_data() - delete all thread's local data
 *
 * Deletes all local to threads data from tgt_dev
 */
void scst_del_all_thr_data(struct scst_tgt_dev *tgt_dev)
{
	spin_lock(&tgt_dev->thr_data_lock);
	while (!list_empty(&tgt_dev->thr_data_list)) {
		struct scst_thr_data_hdr *d = list_entry(
				tgt_dev->thr_data_list.next, typeof(*d),
				thr_data_list_entry);
		list_del(&d->thr_data_list_entry);
		spin_unlock(&tgt_dev->thr_data_lock);
		scst_thr_data_put(d);
		spin_lock(&tgt_dev->thr_data_lock);
	}
	spin_unlock(&tgt_dev->thr_data_lock);
	return;
}
EXPORT_SYMBOL_GPL(scst_del_all_thr_data);

/**
 * scst_dev_del_all_thr_data() - delete all thread's local data from device
 *
 * Deletes all local to threads data from all tgt_dev's of the device
 */
void scst_dev_del_all_thr_data(struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
		scst_del_all_thr_data(tgt_dev);
	}

	mutex_unlock(&scst_mutex);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_dev_del_all_thr_data);

/* thr_data_lock supposed to be held */
static struct scst_thr_data_hdr *__scst_find_thr_data_locked(
	struct scst_tgt_dev *tgt_dev, struct task_struct *tsk)
{
	struct scst_thr_data_hdr *res = NULL, *d;

	list_for_each_entry(d, &tgt_dev->thr_data_list, thr_data_list_entry) {
		if (d->owner_thr == tsk) {
			res = d;
			scst_thr_data_get(res);
			break;
		}
	}
	return res;
}

/**
 * __scst_find_thr_data() - find local to the thread data
 *
 * Finds local to the thread data. Returns NULL, if they not found.
 */
struct scst_thr_data_hdr *__scst_find_thr_data(struct scst_tgt_dev *tgt_dev,
	struct task_struct *tsk)
{
	struct scst_thr_data_hdr *res;

	spin_lock(&tgt_dev->thr_data_lock);
	res = __scst_find_thr_data_locked(tgt_dev, tsk);
	spin_unlock(&tgt_dev->thr_data_lock);

	return res;
}
EXPORT_SYMBOL_GPL(__scst_find_thr_data);

bool scst_del_thr_data(struct scst_tgt_dev *tgt_dev, struct task_struct *tsk)
{
	bool res;
	struct scst_thr_data_hdr *td;

	spin_lock(&tgt_dev->thr_data_lock);

	td = __scst_find_thr_data_locked(tgt_dev, tsk);
	if (td != NULL) {
		list_del(&td->thr_data_list_entry);
		res = true;
	} else
		res = false;

	spin_unlock(&tgt_dev->thr_data_lock);

	if (td != NULL) {
		/* the find() fn also gets it */
		scst_thr_data_put(td);
		scst_thr_data_put(td);
	}

	return res;
}

/* dev_lock supposed to be held and BH disabled */
void scst_block_dev(struct scst_device *dev)
{
	dev->block_count++;
	TRACE_MGMT_DBG("Device BLOCK(new %d), dev %p", dev->block_count, dev);
}

/* No locks */
void scst_unblock_dev(struct scst_device *dev)
{
	spin_lock_bh(&dev->dev_lock);
	TRACE_MGMT_DBG("Device UNBLOCK(new %d), dev %p",
		dev->block_count-1, dev);
	if (--dev->block_count == 0)
		scst_unblock_cmds(dev);
	spin_unlock_bh(&dev->dev_lock);
	sBUG_ON(dev->block_count < 0);
}

/* No locks */
bool __scst_check_blocked_dev(struct scst_cmd *cmd)
{
	int res = false;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(cmd->unblock_dev);

	if (unlikely(cmd->internal) && (cmd->cdb[0] == REQUEST_SENSE)) {
		/*
		 * The original command can already block the device, so
		 * REQUEST SENSE command should always pass.
		 */
		goto out;
	}

repeat:
	if (dev->block_count > 0) {
		spin_lock_bh(&dev->dev_lock);
		if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
			goto out_unlock;
		if (dev->block_count > 0) {
			TRACE_MGMT_DBG("Delaying cmd %p due to blocking "
				"(tag %llu, dev %p)", cmd,
				(long long unsigned int)cmd->tag, dev);
			list_add_tail(&cmd->blocked_cmd_list_entry,
				      &dev->blocked_cmd_list);
			res = true;
			spin_unlock_bh(&dev->dev_lock);
			goto out;
		} else {
			TRACE_MGMT_DBG("%s", "Somebody unblocked the device, "
				"continuing");
		}
		spin_unlock_bh(&dev->dev_lock);
	}

	if (dev->dev_double_ua_possible) {
		spin_lock_bh(&dev->dev_lock);
		if (dev->block_count == 0) {
			TRACE_MGMT_DBG("cmd %p (tag %llu), blocking further "
				"cmds due to possible double reset UA (dev %p)",
				cmd, (long long unsigned int)cmd->tag, dev);
			scst_block_dev(dev);
			cmd->unblock_dev = 1;
		} else {
			spin_unlock_bh(&dev->dev_lock);
			TRACE_MGMT_DBG("Somebody blocked the device, "
				"repeating (count %d)", dev->block_count);
			goto repeat;
		}
		spin_unlock_bh(&dev->dev_lock);
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	spin_unlock_bh(&dev->dev_lock);
	goto out;
}

/* Called under dev_lock */
static void scst_unblock_cmds(struct scst_device *dev)
{
	struct scst_cmd *cmd, *tcmd;
	unsigned long flags;

	TRACE_ENTRY();

	local_irq_save(flags);
	list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
				 blocked_cmd_list_entry) {
		list_del(&cmd->blocked_cmd_list_entry);
		TRACE_MGMT_DBG("Adding blocked cmd %p to active cmd list", cmd);
		spin_lock(&cmd->cmd_threads->cmd_list_lock);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_threads->active_cmd_list);
		wake_up(&cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_threads->cmd_list_lock);
	}
	local_irq_restore(flags);

	TRACE_EXIT();
	return;
}

static void __scst_unblock_deferred(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *out_of_sn_cmd)
{
	EXTRACHECKS_BUG_ON(!out_of_sn_cmd->sn_set);

	if (out_of_sn_cmd->sn == tgt_dev->expected_sn) {
		scst_inc_expected_sn(tgt_dev, out_of_sn_cmd->sn_slot);
		scst_make_deferred_commands_active(tgt_dev);
	} else {
		out_of_sn_cmd->out_of_sn = 1;
		spin_lock_irq(&tgt_dev->sn_lock);
		tgt_dev->def_cmd_count++;
		list_add_tail(&out_of_sn_cmd->sn_cmd_list_entry,
			      &tgt_dev->skipped_sn_list);
		TRACE_SN("out_of_sn_cmd %p with sn %d added to skipped_sn_list"
			" (expected_sn %d)", out_of_sn_cmd, out_of_sn_cmd->sn,
			tgt_dev->expected_sn);
		spin_unlock_irq(&tgt_dev->sn_lock);
	}

	return;
}

void scst_unblock_deferred(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *out_of_sn_cmd)
{
	TRACE_ENTRY();

	if (!out_of_sn_cmd->sn_set) {
		TRACE_SN("cmd %p without sn", out_of_sn_cmd);
		goto out;
	}

	__scst_unblock_deferred(tgt_dev, out_of_sn_cmd);

out:
	TRACE_EXIT();
	return;
}

void scst_on_hq_cmd_response(struct scst_cmd *cmd)
{
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	if (!cmd->hq_cmd_inced)
		goto out;

	spin_lock_irq(&tgt_dev->sn_lock);
	tgt_dev->hq_cmd_count--;
	spin_unlock_irq(&tgt_dev->sn_lock);

	EXTRACHECKS_BUG_ON(tgt_dev->hq_cmd_count < 0);

	/*
	 * There is no problem in checking hq_cmd_count in the
	 * non-locked state. In the worst case we will only have
	 * unneeded run of the deferred commands.
	 */
	if (tgt_dev->hq_cmd_count == 0)
		scst_make_deferred_commands_active(tgt_dev);

out:
	TRACE_EXIT();
	return;
}

void scst_store_sense(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (SCST_SENSE_VALID(cmd->sense) &&
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

	TRACE_MGMT_DBG("Aborted cmd %p done (cmd_ref %d, "
		"scst_cmd_count %d)", cmd, atomic_read(&cmd->cmd_ref),
		atomic_read(&scst_cmd_count));

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
 * scst_reassign_persistent_sess_states() - reassigns persistent states
 *
 * Reassigns persistent states from old_sess to new_sess.
 */
void scst_reassign_persistent_sess_states(struct scst_session *new_sess,
	struct scst_session *old_sess)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	TRACE_PR("Reassigning persistent states from old_sess %p to "
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
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_reassign_persistent_sess_states);

/**
 * scst_get_next_lexem() - parse and return next lexem in the string
 *
 * Returns pointer to the next lexem from token_str skipping
 * spaces and '=' character and using them then as a delimeter. Content
 * of token_str is modified by setting '\0' at the delimeter's position.
 */
char *scst_get_next_lexem(char **token_str)
{
	char *p = *token_str;
	char *q;
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

static void __init scst_scsi_op_list_init(void)
{
	int i;
	uint8_t op = 0xff;

	TRACE_ENTRY();

	for (i = 0; i < 256; i++)
		scst_scsi_op_list[i] = SCST_CDB_TBL_SIZE;

	for (i = 0; i < SCST_CDB_TBL_SIZE; i++) {
		if (scst_scsi_op_table[i].ops != op) {
			op = scst_scsi_op_table[i].ops;
			scst_scsi_op_list[op] = i;
		}
	}

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
					0, 0, NULL);
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
	if (tgt_dev->lun == 6) {
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
	/* Used to make sure that all woken up threads see the new value */
	smp_wmb();
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

/* Called under scst_tm_dbg_lock */
static void tm_dbg_change_state(void)
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
	del_timer_sync(&tm_dbg_timer);
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
			tm_dbg_change_state();
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	} else if (cmd->tgt_dev && (tm_dbg_tgt_dev == cmd->tgt_dev)) {
		/* Delay 50th command */
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		if (tm_dbg_flags.tm_dbg_blocked ||
		    (++tm_dbg_passed_cmds_count % 50) == 0) {
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
		tm_dbg_change_state();
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
	static DEFINE_SPINLOCK(lock);
	static int type;
	static int cnt;
	unsigned long flags;
	int old = cmd->queue_type;

	spin_lock_irqsave(&lock, flags);

	if (cnt == 0) {
		if ((scst_random() % 1000) == 500) {
			if ((scst_random() % 3) == 1)
				type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
			else
				type = SCST_CMD_QUEUE_ORDERED;
			do {
				cnt = scst_random() % 10;
			} while (cnt == 0);
		} else
			goto out_unlock;
	}

	cmd->queue_type = type;
	cnt--;

	if (((scst_random() % 1000) == 750))
		cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
	else if (((scst_random() % 1000) == 751))
		cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	else if (((scst_random() % 1000) == 752))
		cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;

	TRACE_SN("DbgSN changed cmd %p: %d/%d (cnt %d)", cmd, old,
		cmd->queue_type, cnt);

out_unlock:
	spin_unlock_irqrestore(&lock, flags);
	return;
}
#endif /* CONFIG_SCST_DEBUG_SN */

#ifdef CONFIG_SCST_MEASURE_LATENCY

static uint64_t scst_get_nsec(void)
{
	struct timespec ts;
	ktime_get_ts(&ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void scst_set_start_time(struct scst_cmd *cmd)
{
	cmd->start = scst_get_nsec();
	TRACE_DBG("cmd %p: start %lld", cmd, cmd->start);
}

void scst_set_cur_start(struct scst_cmd *cmd)
{
	cmd->curr_start = scst_get_nsec();
	TRACE_DBG("cmd %p: cur_start %lld", cmd, cmd->curr_start);
}

void scst_set_parse_time(struct scst_cmd *cmd)
{
	cmd->parse_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: parse_time %lld", cmd, cmd->parse_time);
}

void scst_set_alloc_buf_time(struct scst_cmd *cmd)
{
	cmd->alloc_buf_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: alloc_buf_time %lld", cmd, cmd->alloc_buf_time);
}

void scst_set_restart_waiting_time(struct scst_cmd *cmd)
{
	cmd->restart_waiting_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: restart_waiting_time %lld", cmd,
		cmd->restart_waiting_time);
}

void scst_set_rdy_to_xfer_time(struct scst_cmd *cmd)
{
	cmd->rdy_to_xfer_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: rdy_to_xfer_time %lld", cmd, cmd->rdy_to_xfer_time);
}

void scst_set_pre_exec_time(struct scst_cmd *cmd)
{
	cmd->pre_exec_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: pre_exec_time %lld", cmd, cmd->pre_exec_time);
}

void scst_set_exec_time(struct scst_cmd *cmd)
{
	cmd->exec_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: exec_time %lld", cmd, cmd->exec_time);
}

void scst_set_dev_done_time(struct scst_cmd *cmd)
{
	cmd->dev_done_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: dev_done_time %lld", cmd, cmd->dev_done_time);
}

void scst_set_xmit_time(struct scst_cmd *cmd)
{
	cmd->xmit_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: xmit_time %lld", cmd, cmd->xmit_time);
}

void scst_set_tgt_on_free_time(struct scst_cmd *cmd)
{
	cmd->tgt_on_free_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: tgt_on_free_time %lld", cmd, cmd->tgt_on_free_time);
}

void scst_set_dev_on_free_time(struct scst_cmd *cmd)
{
	cmd->dev_on_free_time += scst_get_nsec() - cmd->curr_start;
	TRACE_DBG("cmd %p: dev_on_free_time %lld", cmd, cmd->dev_on_free_time);
}

void scst_update_lat_stats(struct scst_cmd *cmd)
{
	uint64_t finish, scst_time, tgt_time, dev_time;
	struct scst_session *sess = cmd->sess;
	int data_len;
	int i;
	struct scst_ext_latency_stat *latency_stat, *dev_latency_stat;

	finish = scst_get_nsec();

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
		cmd->exec_time + cmd->dev_done_time + cmd->xmit_time +
		cmd->tgt_on_free_time + cmd->dev_on_free_time);
	tgt_time = cmd->alloc_buf_time + cmd->restart_waiting_time +
		cmd->rdy_to_xfer_time + cmd->pre_exec_time +
		cmd->xmit_time + cmd->tgt_on_free_time;
	dev_time = cmd->parse_time + cmd->exec_time + cmd->dev_done_time +
		cmd->dev_on_free_time;

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
