/*
 *  scst_cdbprobe.h
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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
 
/* Must be included in only one .c file in the project!! */

#ifndef __SCST_CDBPROBE_H
#define __SCST_CDBPROBE_H

/* get_trans_len_x extract x bytes from cdb as length starting from off */
static uint32_t get_trans_len_1(const uint8_t *cdb, uint8_t off);
static uint32_t get_trans_len_2(const uint8_t *cdb, uint8_t off);
static uint32_t get_trans_len_3(const uint8_t *cdb, uint8_t off);
static uint32_t get_trans_len_4(const uint8_t *cdb, uint8_t off);

/* for special commands */
static uint32_t get_trans_len_block_limit(const uint8_t *cdb, uint8_t off);
static uint32_t get_trans_len_read_capacity(const uint8_t *cdb, uint8_t off);
static uint32_t get_trans_len_single(const uint8_t *cdb, uint8_t off);
static uint32_t get_trans_len_none(const uint8_t *cdb, uint8_t off);

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

struct scst_sdbops
{
	uint8_t ops;		/* SCSI-2 op codes */
	uint8_t devkey[16];	/* Key for every device type M,O,V,R
				 * type_disk      devkey[0]
				 * type_tape      devkey[1]
				 * type_printer   devkey[2]
				 * type_proseccor devkey[3]
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
	uint8_t flags;		/* opcode --  various flags */
	uint8_t off;		/* length offset in cdb */
	uint32_t (*get_trans_len)(const uint8_t *cdb, uint8_t off) __attribute__ ((aligned));
}  __attribute__((packed));

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
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT, 0, get_trans_len_none},
	{0x01, " M              ", "REWIND",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x01, "O V OO OO       ", "REZERO UNIT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x02, "VVVVVV  V       ", "REQUEST BLOCK ADDR",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT, 0, get_trans_len_none},
	{0x03, "MMMMMMMMMMMMMMMM", "REQUEST SENSE",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 4, get_trans_len_1},
	{0x04, "M    O O        ", "FORMAT UNIT",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x04, "  O             ", "FORMAT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x05, "VMVVVV  V       ", "READ BLOCK LIMITS",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 0, get_trans_len_block_limit},
	{0x06, "VVVVVV  V       ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x07, "        O       ", "INITIALIZE ELEMENT STATUS",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x07, "OVV O  OV       ", "REASSIGN BLOCKS",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x08, "O               ", "READ(6)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 4, get_trans_len_1},
	{0x08, " MV OO OV       ", "READ(6)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 2, get_trans_len_3},
	{0x08, "         M      ", "GET MESSAGE(6)",
	 SCST_DATA_READ, FLAG_NONE, 2, get_trans_len_3},
	{0x08, "    O           ", "RECEIVE",
	 SCST_DATA_READ, FLAG_NONE, 2, get_trans_len_3},
	{0x09, "VVVVVV  V       ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x0A, "O               ", "WRITE(6)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 4, get_trans_len_1},
	{0x0A, " M  O  OV       ", "WRITE(6)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 2, get_trans_len_3},
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
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x0E, "VVVVVV  V       ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x0F, "VOVVVV  V       ", "READ REVERSE",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 2, get_trans_len_3},
	{0x10, "VM V V          ", "WRITE FILEMARKS",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x10, "  O O           ", "SYNCHRONIZE BUFFER",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x11, "VMVVVV          ", "SPACE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x12, "MMMMMMMMMMMMMMMM", "INQUIRY",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 4, get_trans_len_1},
	{0x13, "VOVVVV          ", "VERIFY(6)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 2, get_trans_len_3},
	{0x14, "VOOVVV          ", "RECOVER BUFFERED DATA",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 2, get_trans_len_3},
	{0x15, "OMOOOOOOOOOOOOOO", "MODE SELECT(6)",
	 SCST_DATA_WRITE, FLAG_NONE, 4, get_trans_len_1},
	{0x16, "MMMMMMMMMMMMMMMM", "RESERVE",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT, 0, get_trans_len_none},
	{0x17, "MMMMMMMMMMMMMMMM", "RELEASE",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT, 0, get_trans_len_none},
	{0x18, "OOOOOOOO        ", "COPY",
	 SCST_DATA_WRITE, SCST_LONG_TIMEOUT, 2, get_trans_len_3},
	{0x19, "VMVVVV          ", "ERASE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x1A, "OMOOOOOOOOOOOOOO", "MODE SENSE(6)",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 4, get_trans_len_1},
	{0x1B, "      O         ", "SCAN",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x1B, " O              ", "LOAD UNLOAD",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x1B, "  O             ", "STOP PRINT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x1B, "O   OO O    O   ", "STOP START UNIT",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x1C, "OOOOOOOOOOOOOOOO", "RECEIVE DIAGNOSTIC RESULTS",
	 SCST_DATA_READ, FLAG_NONE, 4, get_trans_len_1},
	{0x1D, "MMMMMMMMMMMMMMMM", "SEND DIAGNOSTIC",
	 SCST_DATA_WRITE, FLAG_NONE, 4, get_trans_len_1},
	{0x1E, "OOOOOOOOOOOOOOOO", "PREVENT ALLOW MEDIUM REMOVAL",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x1F, "            O   ", "PORT STATUS",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},

	 /* 10-bytes length CDB */
	{0x20, "V   VV V        ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x21, "V   VV V        ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x22, "V   VV V        ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x23, "V   VV V        ", "READ FORMAT CAPACITY",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x24, "V   VVM         ", "SET WINDOW",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_3},
	{0x25, "M   MM M        ", "READ CAPACITY",
	 SCST_DATA_READ, FLAG_NONE, 0, get_trans_len_read_capacity},
	{0x25, "      O         ", "GET WINDOW",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_3},
	{0x26, "V   VV          ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x27, "V   VV          ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x28, "M   MMMM        ", "READ(10)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 7, get_trans_len_2},
	{0x28, "         O      ", "GET MESSAGE(10)",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x29, "V   VV O        ", "READ GENERATION",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_1},
	{0x2A, "O   MO M        ", "WRITE(10)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 7, get_trans_len_2},
	{0x2A, "         O      ", "SEND MESSAGE(10)",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x2A, "      O         ", "SEND(10)",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x2B, " O              ", "LOCATE",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x2B, "        O       ", "POSITION TO ELEMENT",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x2B, "O   OO O        ", "SEEK(10)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x2C, "V    O O        ", "ERASE(10)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x2D, "V   O  O        ", "READ UPDATED BLOCK",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 0, get_trans_len_single},
	{0x2E, "O   OO O        ", "WRITE AND VERIFY(10)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 7, get_trans_len_2},
	{0x2F, "O   OO O        ", "VERIFY(10)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 7, get_trans_len_2},
/*
	{0x30, "O   OO O        ", "SEARCH DATA HIGH(10)",
	 SCST_DATA_NONE, SCST_UNKNOWN_LENGTH, 0, get_trans_len_none},
	{0x31, "      O         ", "OBJECT POSITION",
	 SCST_DATA_NONE, SCST_UNKNOWN_LENGTH, 0, get_trans_len_none},
	{0x31, "O   OO O        ", "SEARCH DATA EQUAL(10)",
	 SCST_DATA_NONE, SCST_UNKNOWN_LENGTH, 0, get_trans_len_none},
	{0x32, "O   OO O        ", "SEARCH DATA LOW(10)",
	 SCST_DATA_NONE, SCST_UNKNOWN_LENGTH, 0, get_trans_len_none},
*/
	{0x33, "O   OO O        ", "SET LIMITS(10)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x34, " O              ", "READ POSITION",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 7, get_trans_len_2},
	{0x34, "      O         ", "GET DATA BUFFER STATUS",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x34, "O   OO O        ", "PRE-FETCH",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x35, "O   OO O        ", "SYNCHRONIZE CACHE",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x36, "O   OO O        ", "LOCK UNLOCK CACHE",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x37, "O      O        ", "READ DEFECT DATA(10)",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_1},
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
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 0, get_trans_len_single},
	{0x3E, "O   OO O        ", "READ LONG",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x3F, "O   O  O        ", "WRITE LONG",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x40, "OOOOOOOOOO      ", "CHANGE DEFINITION",
	 SCST_DATA_WRITE, SCST_SMALL_TIMEOUT, 8, get_trans_len_1},
	{0x41, "O    O          ", "WRITE SAME",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 0, get_trans_len_single},
	{0x42, "     O          ", "READ SUB-CHANNEL",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x43, "     O          ", "READ TOC/PMA/ATIP",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
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
	 SCST_DATA_WRITE, SCST_SMALL_TIMEOUT, 7, get_trans_len_2},
	{0x4D, "OOOOOOOOOOOOOOOO", "LOG SENSE",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 7, get_trans_len_2},
	{0x4E, "     O          ", "STOP PLAY/SCAN",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x4F, "                ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x50, "                ", "XDWRITE",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x51, "     O          ", "READ DISC INFORMATION",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x51, "                ", "XPWRITE",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x52, "     O          ", "READ TRACK INFORMATION",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x53, "     O          ", "RESERVE TRACK",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x54, "     O          ", "SEND OPC INFORMATION",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x55, "OOOOOOOOOOOOOOOO", "MODE SELECT(10)",
	 SCST_DATA_WRITE, FLAG_NONE, 7, get_trans_len_2},
	{0x56, "OOOOOOOOOOOOOOOO", "RESERVE(10)",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT, 0, get_trans_len_none},
	{0x57, "OOOOOOOOOOOOOOOO", "RELEASE(10)",
	 SCST_DATA_NONE, SCST_SMALL_TIMEOUT, 0, get_trans_len_none},
	{0x58, "     O          ", "REPAIR TRACK",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x59, "                ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x5A, "OOOOOOOOOOOOOOOO", "MODE SENSE(10)",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 7, get_trans_len_2},
	{0x5B, "     O          ", "CLOSE TRACK/SESSION",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x5C, "     O          ", "READ BUFFER CAPACITY",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_2},
	{0x5D, "     O          ", "SEND CUE SHEET",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_3},
	{0x5E, "OOOOO OOOO      ", "PERSISTENT_RESERV_IN",
	 SCST_DATA_READ, FLAG_NONE, 5, get_trans_len_4},
	{0x5F, "OOOOO OOOO      ", "PERSISTENT_RESERV_OUT",
         SCST_DATA_WRITE, FLAG_NONE, 5, get_trans_len_4},

	/* 16-bytes length CDB */
	{0x80, "O   OO O        ", "XDWRITE EXTENDED",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x80, " M              ", "WRITE FILEMARKS",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x81, "O   OO O        ", "REBUILD",
	 SCST_DATA_WRITE, FLAG_NONE, 10, get_trans_len_4},
	{0x82, "O   OO O        ", "REGENERATE",
	 SCST_DATA_WRITE, FLAG_NONE, 10, get_trans_len_4},
	{0x83, "OOOOOOOOOOOOOOOO", "EXTENDED COPY",
	 SCST_DATA_WRITE, FLAG_NONE, 10, get_trans_len_4},
	{0x84, "OOOOOOOOOOOOOOOO", "RECEIVE COPY RESULT",
	 SCST_DATA_WRITE, FLAG_NONE, 10, get_trans_len_4},
	{0x86, "OOOOOOOOOO      ", "ACCESS CONTROL IN",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x87, "OOOOOOOOOO      ", "ACCESS CONTROL OUT",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x88, "M   MMMM        ", "READ(16)",
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 10, get_trans_len_4},
	{0x8A, "O   OO O        ", "WRITE(16)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 10, get_trans_len_4},
	{0x8C, "OOOOOOOOOO      ", "READ ATTRIBUTE",
	 SCST_DATA_READ, FLAG_NONE, 10, get_trans_len_4},
	{0x8D, "OOOOOOOOOO      ", "WRITE ATTRIBUTE",
	 SCST_DATA_WRITE, FLAG_NONE, 10, get_trans_len_4},
	{0x8E, "O   OO O        ", "WRITE AND VERIFY(16)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 10, get_trans_len_4},
	{0x8F, "O   OO O        ", "VERIFY(16)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 10, get_trans_len_4},
	{0x90, "O   OO O        ", "PRE-FETCH(16)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x91, "O   OO O        ", "SYNCHRONIZE CACHE(16)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x91, " M              ", "SPACE(16)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x92, "O   OO O        ", "LOCK UNLOCK CACHE(16)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0x92, " O              ", "LOCATE(16)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x93, "O    O          ", "WRITE SAME(16)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 10, get_trans_len_4},
	{0x93, " M              ", "ERASE(16)",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0x9E, "O               ", "SERVICE ACTION IN",
	 SCST_DATA_READ, FLAG_NONE, 0, get_trans_len_none},

	/* 12-bytes length CDB */
	{0xA0, "VVVVVVVVVV  M   ", "REPORT LUN",
	 SCST_DATA_READ, SCST_SMALL_TIMEOUT, 6, get_trans_len_4},
	{0xA1, "     O          ", "BLANK",
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none},
	{0xA2, "                ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xA3, "     O          ", "SEND KEY",
	 SCST_DATA_WRITE, FLAG_NONE, 8, get_trans_len_2},
	{0xA3, "OOOOO OOOO      ", "REPORT DEVICE IDENTIDIER",
	 SCST_DATA_READ, FLAG_NONE, 6, get_trans_len_4},
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
	 SCST_DATA_READ, SCST_TRANSFER_LEN_TYPE_FIXED, 6, get_trans_len_4},
	{0xA9, "     O          ", "PLAY TRACK RELATIVE(12)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xAA, "O   OO O        ", "WRITE(12)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 6, get_trans_len_4},
	{0xAA, "         O      ", "SEND MESSAGE(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 6, get_trans_len_4},
	{0xAB, "                ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xAC, "       O        ", "ERASE(12)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xAC, "     O          ", "GET PERFORMANCE",
	 SCST_DATA_READ, SCST_UNKNOWN_LENGTH, 0, get_trans_len_none},
	{0xAD, "     O          ", "READ DVD STRUCTURE",
	 SCST_DATA_READ, FLAG_NONE, 8, get_trans_len_2},
	{0xAE, "O   OO O        ", "WRITE AND VERIFY(12)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 6, get_trans_len_4},
	{0xAF, "O   OO O        ", "VERIFY(12)",
	 SCST_DATA_WRITE, SCST_TRANSFER_LEN_TYPE_FIXED, 6, get_trans_len_4},
/* No need to support at all.
	{0xB0, "    OO O        ", "SEARCH DATA HIGH(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
	{0xB1, "    OO O        ", "SEARCH DATA EQUAL(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
	{0xB2, "    OO O        ", "SEARCH DATA LOW(12)",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
*/
	{0xB3, "    OO O        ", "SET LIMITS(12)",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xB4, "                ", "",
	 SCST_DATA_NONE, FLAG_NONE, 0, get_trans_len_none},
	{0xB5, "        O       ", "REQUEST VOLUME ELEMENT ADDRESS",
	 SCST_DATA_READ, FLAG_NONE, 9, get_trans_len_1},
	{0xB6, "        O       ", "SEND VOLUME TAG",
	 SCST_DATA_WRITE, FLAG_NONE, 9, get_trans_len_1},
	{0xB6, "     O         ", "SET STREAMING",
	 SCST_DATA_WRITE, FLAG_NONE, 0, get_trans_len_none},
	{0xB7, "       O        ", "READ DEFECT DATA(12)",
	 SCST_DATA_READ, FLAG_NONE, 9, get_trans_len_1},
	{0xB8, "        O       ", "READ ELEMENT STATUS",
	 SCST_DATA_READ, FLAG_NONE, 7, get_trans_len_3},
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
	 SCST_DATA_NONE, SCST_LONG_TIMEOUT, 0, get_trans_len_none}
};

/* Notes:
	Unknown op's:
	#define SCSIOP_XDWRITE_EXTENDED		0x80
	#define SCSIOP_REBUILD			0x81
	#define SCSIOP_EA			0xea
	#define WRITE_LONG_2			0xea
*/

#define SCST_CDB_TBL_SIZE ((sizeof(scst_scsi_op_table)/sizeof(struct scst_sdbops)))

#endif /* __SCST_CDBPROBE_H */
