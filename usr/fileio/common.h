/*
 *  common.h
 *
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
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

#include <stdint.h>
#include <stddef.h>

#include <scst_user.h>

#include "debug.h"

/* 8 byte ASCII Vendor */
#define VENDOR				"SCST_USR"
/* 4 byte ASCII Product Revision Level - left aligned */
#define FIO_REV				" 300"

#define MAX_USN_LEN			(20+1) /* For '\0' */

#define INQ_BUF_SZ			128
#define EVPD				0x01
#define CMDDT				0x02

#define MSENSE_BUF_SZ			256
#define DBD				0x08	/* disable block descriptor */
#define WP				0x80	/* write protect */
#define DPOFUA				0x10	/* DPOFUA bit */
#define WCE				0x04	/* write cache enable */

#define PF				0x10	/* page format */
#define SP				0x01	/* save pages */
#define PS				0x80	/* parameter saveable */

#define	BYTE				8
#define	DEF_SECTORS			56
#define	DEF_HEADS			255

struct vdisk_tgt_dev {
	uint64_t sess_h;
};

struct vdisk_dev {
	int scst_usr_fd;
	uint32_t block_size;
	uint64_t nblocks;
	int block_shift;
	loff_t file_size;	/* in bytes */
	void *(*alloc_fn)(size_t size);

	pthread_mutex_t dev_mutex;

	/* Below flags and are protected by dev_mutex */
	unsigned int rd_only_flag:1;
	unsigned int wt_flag:1;
	unsigned int nv_cache:1;
	unsigned int o_direct_flag:1;
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int cdrom_empty:1;
	unsigned int non_blocking:1;
#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
	unsigned int debug_tm_ignore:1;
#if defined(DEBUG_TM_IGNORE_ALL)
	volatile int debug_tm_ignore_all;
#endif
#endif

	struct vdisk_tgt_dev tgt_devs[64];

	char *name;		/* Name of virtual device,
				   must be <= SCSI Model + 1 */
	char *file_name;	/* File name */
	char usn[MAX_USN_LEN];
	int type;
};

struct vdisk_cmd
{
	int fd;
	struct scst_user_get_cmd *cmd;
	struct vdisk_dev *dev;
	struct scst_user_reply_cmd *reply;
	uint8_t sense[SCST_SENSE_BUFFERSIZE];
};

/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x,y) ({ 		\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y; })

#define max(x,y) ({ 		\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y; })

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

extern int vdisk_ID;

uint32_t crc32buf(const char *buf, size_t len);

uint64_t gen_dev_id_num(const struct vdisk_dev *dev);
void *main_loop(void *arg);
