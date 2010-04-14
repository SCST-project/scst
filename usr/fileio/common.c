/*
 *  common.c
 *
 *  Copyright (C) 2007 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <inttypes.h>

#include <sys/ioctl.h>
#include <sys/poll.h>

#include <arpa/inet.h>

#include <pthread.h>

#include "common.h"

static unsigned int random_values[256] = {
	    9862592UL,  3744545211UL,  2348289082UL,  4036111983UL,
	  435574201UL,  3110343764UL,  2383055570UL,  1826499182UL,
	 4076766377UL,  1549935812UL,  3696752161UL,  1200276050UL,
	 3878162706UL,  1783530428UL,  2291072214UL,   125807985UL,
	 3407668966UL,   547437109UL,  3961389597UL,   969093968UL,
	   56006179UL,  2591023451UL,     1849465UL,  1614540336UL,
	 3699757935UL,   479961779UL,  3768703953UL,  2529621525UL,
	 4157893312UL,  3673555386UL,  4091110867UL,  2193909423UL,
	 2800464448UL,  3052113233UL,   450394455UL,  3424338713UL,
	 2113709130UL,  4082064373UL,  3708640918UL,  3841182218UL,
	 3141803315UL,  1032476030UL,  1166423150UL,  1169646901UL,
	 2686611738UL,   575517645UL,  2829331065UL,  1351103339UL,
	 2856560215UL,  2402488288UL,   867847666UL,     8524618UL,
	  704790297UL,  2228765657UL,   231508411UL,  1425523814UL,
	 2146764591UL,  1287631730UL,  4142687914UL,  3879884598UL,
	  729945311UL,   310596427UL,  2263511876UL,  1983091134UL,
	 3500916580UL,  1642490324UL,  3858376049UL,   695342182UL,
	  780528366UL,  1372613640UL,  1100993200UL,  1314818946UL,
	  572029783UL,  3775573540UL,   776262915UL,  2684520905UL,
	 1007252738UL,  3505856396UL,  1974886670UL,  3115856627UL,
	 4194842288UL,  2135793908UL,  3566210707UL,     7929775UL,
	 1321130213UL,  2627281746UL,  3587067247UL,  2025159890UL,
	 2587032000UL,  3098513342UL,  3289360258UL,   130594898UL,
	 2258149812UL,  2275857755UL,  3966929942UL,  1521739999UL,
	 4191192765UL,   958953550UL,  4153558347UL,  1011030335UL,
	  524382185UL,  4099757640UL,   498828115UL,  2396978754UL,
	  328688935UL,   826399828UL,  3174103611UL,  3921966365UL,
	 2187456284UL,  2631406787UL,  3930669674UL,  4282803915UL,
	 1776755417UL,   374959755UL,  2483763076UL,   844956392UL,
	 2209187588UL,  3647277868UL,   291047860UL,  3485867047UL,
	 2223103546UL,  2526736133UL,  3153407604UL,  3828961796UL,
	 3355731910UL,  2322269798UL,  2752144379UL,   519897942UL,
	 3430536488UL,  1801511593UL,  1953975728UL,  3286944283UL,
	 1511612621UL,  1050133852UL,   409321604UL,  1037601109UL,
	 3352316843UL,  4198371381UL,   617863284UL,   994672213UL,
	 1540735436UL,  2337363549UL,  1242368492UL,   665473059UL,
	 2330728163UL,  3443103219UL,  2291025133UL,  3420108120UL,
	 2663305280UL,  1608969839UL,  2278959931UL,  1389747794UL,
	 2226946970UL,  2131266900UL,  3856979144UL,  1894169043UL,
	 2692697628UL,  3797290626UL,  3248126844UL,  3922786277UL,
	  343705271UL,  3739749888UL,  2191310783UL,  2962488787UL,
	 4119364141UL,  1403351302UL,  2984008923UL,  3822407178UL,
	 1932139782UL,  2323869332UL,  2793574182UL,  1852626483UL,
	 2722460269UL,  1136097522UL,  1005121083UL,  1805201184UL,
	 2212824936UL,  2979547931UL,  4133075915UL,  2585731003UL,
	 2431626071UL,   134370235UL,  3763236829UL,  1171434827UL,
	 2251806994UL,  1289341038UL,  3616320525UL,   392218563UL,
	 1544502546UL,  2993937212UL,  1957503701UL,  3579140080UL,
	 4270846116UL,  2030149142UL,  1792286022UL,   366604999UL,
	 2625579499UL,   790898158UL,   770833822UL,   815540197UL,
	 2747711781UL,  3570468835UL,  3976195842UL,  1257621341UL,
	 1198342980UL,  1860626190UL,  3247856686UL,   351473955UL,
	  993440563UL,   340807146UL,  1041994520UL,  3573925241UL,
	  480246395UL,  2104806831UL,  1020782793UL,  3362132583UL,
	 2272911358UL,  3440096248UL,  2356596804UL,   259492703UL,
	 3899500740UL,   252071876UL,  2177024041UL,  4284810959UL,
	 2775999888UL,  2653420445UL,  2876046047UL,  1025771859UL,
	 1994475651UL,  3564987377UL,  4112956647UL,  1821511719UL,
	 3113447247UL,   455315102UL,  1585273189UL,  2311494568UL,
	  774051541UL,  1898115372UL,  2637499516UL,   247231365UL,
	 1475014417UL,   803585727UL,  3911097303UL,  1714292230UL,
	  476579326UL,  2496900974UL,  3397613314UL,   341202244UL,
	  807790202UL,  4221326173UL,   499979741UL,  1301488547UL,
	 1056807896UL,  3525009458UL,  1174811641UL,  3049738746UL,
};

static void exec_inquiry(struct vdisk_cmd *vcmd);
static void exec_request_sense(struct vdisk_cmd *vcmd);
static void exec_mode_sense(struct vdisk_cmd *vcmd);
static void exec_mode_select(struct vdisk_cmd *vcmd);
static void exec_read_capacity(struct vdisk_cmd *vcmd);
static void exec_read_capacity16(struct vdisk_cmd *vcmd);
static void exec_read_toc(struct vdisk_cmd *vcmd);
static void exec_prevent_allow_medium_removal(struct vdisk_cmd *vcmd);
static int exec_fsync(struct vdisk_cmd *vcmd);
static void exec_read(struct vdisk_cmd *vcmd, loff_t loff);
static void exec_write(struct vdisk_cmd *vcmd, loff_t loff);
static void exec_verify(struct vdisk_cmd *vcmd, loff_t loff);

static inline void set_cmd_error_status(struct scst_user_scsi_cmd_reply_exec *reply,
	int status)
{
	reply->status = status;
	reply->resp_data_len = 0;
	return;
}

static int set_sense(uint8_t *buffer, int len, int key, int asc, int ascq)
{
	int res = 18;

	EXTRACHECKS_BUG_ON(len < res);

	memset(buffer, 0, res);

	buffer[0] = 0x70;	/* Error Code			*/
	buffer[2] = key;	/* Sense Key			*/
	buffer[7] = 0x0a;	/* Additional Sense Length	*/
	buffer[12] = asc;	/* ASC				*/
	buffer[13] = ascq;	/* ASCQ				*/

	TRACE_BUFFER("Sense set", buffer, res);
	return res;
}

void set_cmd_error(struct vdisk_cmd *vcmd, int key, int asc, int ascq)
{
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(vcmd->cmd->subcode != SCST_USER_EXEC);

	set_cmd_error_status(reply, SAM_STAT_CHECK_CONDITION);
	reply->sense_len = set_sense(vcmd->sense, sizeof(vcmd->sense), key,
		asc, ascq);
	reply->psense_buffer = (unsigned long)vcmd->sense;

	TRACE_EXIT();
	return;
}

void set_busy(struct scst_user_scsi_cmd_reply_exec *reply)
{
	TRACE_ENTRY();

	set_cmd_error_status(reply, SAM_STAT_TASK_SET_FULL);
	TRACE_MGMT_DBG("%s", "Sending QUEUE_FULL status");

	TRACE_EXIT();
	return;
}

static int do_parse(struct vdisk_cmd *vcmd)
{
	int res = 0;
	struct scst_user_scsi_cmd_parse *cmd = &vcmd->cmd->parse_cmd;
	struct scst_user_scsi_cmd_reply_parse *reply = &vcmd->reply->parse_reply;

	TRACE_ENTRY();

	memset(reply, 0, sizeof(*reply));
	vcmd->reply->cmd_h = vcmd->cmd->cmd_h;
	vcmd->reply->subcode = vcmd->cmd->subcode;

	if (cmd->expected_values_set == 0) {
		PRINT_ERROR("%s", "Oops, expected values are not set");
		reply->bufflen = -1; /* invalid value */
		goto out;
	}

	reply->queue_type = cmd->queue_type;
	reply->data_direction = cmd->expected_data_direction;
	reply->data_len = cmd->expected_transfer_len;
	reply->bufflen = cmd->expected_transfer_len;
	reply->cdb_len = cmd->cdb_len;
	reply->op_flags = reply->op_flags;

out:
	TRACE_EXIT_RES(res);
	return res;
}

struct vdisk_tgt_dev *find_tgt_dev(struct vdisk_dev *dev, uint64_t sess_h)
{
	unsigned int i;
	struct vdisk_tgt_dev *res = NULL;

	for(i = 0; i < ARRAY_SIZE(dev->tgt_devs); i++) {
		if (dev->tgt_devs[i].sess_h == sess_h) {
			res = &dev->tgt_devs[i];
			break;
		}
	}
	return res;
}

struct vdisk_tgt_dev *find_empty_tgt_dev(struct vdisk_dev *dev)
{
	unsigned int i;
	struct vdisk_tgt_dev *res = NULL;

	for(i = 0; i < ARRAY_SIZE(dev->tgt_devs); i++) {
		if (dev->tgt_devs[i].sess_h == 0) {
			res = &dev->tgt_devs[i];
			break;
		}
	}
	return res;
}

static inline int sync_queue_type(enum scst_cmd_queue_type qt)
{
	switch(qt) {
		case SCST_CMD_QUEUE_ORDERED:
		case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
			return 1;
		default:
			return 0;
	}
}

static inline int need_pre_sync(enum scst_cmd_queue_type cur,
	enum scst_cmd_queue_type last)
{
	if (sync_queue_type(cur))
		if (!sync_queue_type(last))
			return 1;
	return 0;
}

static int do_exec(struct vdisk_cmd *vcmd)
{
	int res = 0;
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	uint64_t lba_start = 0;
	loff_t data_len = 0;
	uint8_t *cdb = cmd->cdb;
	int opcode = cdb[0];
	loff_t loff;
	int fua = 0;

	TRACE_ENTRY();

	switch(cmd->queue_type) {
	case SCST_CMD_QUEUE_ORDERED:
		TRACE(TRACE_ORDER, "ORDERED cmd_h %d", vcmd->cmd->cmd_h);
		break;
	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		TRACE(TRACE_ORDER, "HQ cmd_h %d", vcmd->cmd->cmd_h);
		break;
	default:
		break;
	}

	memset(reply, 0, sizeof(*reply));
	vcmd->reply->cmd_h = vcmd->cmd->cmd_h;
	vcmd->reply->subcode = vcmd->cmd->subcode;
	reply->reply_type = SCST_EXEC_REPLY_COMPLETED;

#ifdef DEBUG_SENSE
	if ((random() % 100000) == 75) {
		set_cmd_error(vcmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}
#endif

#ifdef DEBUG_TM_IGNORE
	if (dev->debug_tm_ignore && (random() % 10000) == 75) {
		TRACE_MGMT_DBG("Ignore cmd op %x (h=%d)", cdb[0],
			vcmd->cmd->cmd_h);
		res = 150;
		goto out;
	}
#endif

	if ((cmd->pbuf == 0) && (cmd->alloc_len != 0)) {
#ifdef DEBUG_NOMEM
		if ((random() % 100) == 75)
			cmd->pbuf = 0;
		else
#endif
			cmd->pbuf = (unsigned long)dev->alloc_fn(cmd->alloc_len);
		TRACE_MEM("Buf %"PRIx64" alloced, len %d", cmd->pbuf,
			cmd->alloc_len);
		reply->pbuf = cmd->pbuf;
		if (cmd->pbuf == 0) {
			TRACE(TRACE_OUT_OF_MEM, "Unable to allocate buffer "
				"(len %d)", cmd->alloc_len);
#ifndef DEBUG_NOMEM
			set_busy(reply);
#endif
			goto out;
		}
	}

	switch (opcode) {
	case READ_6:
	case WRITE_6:
	case VERIFY_6:
		lba_start = (((cdb[1] & 0x1f) << (BYTE * 2)) +
			     (cdb[2] << (BYTE * 1)) +
			     (cdb[3] << (BYTE * 0)));
		data_len = cmd->bufflen;
		break;
	case READ_10:
	case READ_12:
	case WRITE_10:
	case WRITE_12:
	case VERIFY:
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case VERIFY_12:
		lba_start |= ((uint64_t)cdb[2]) << 24;
		lba_start |= ((uint64_t)cdb[3]) << 16;
		lba_start |= ((uint64_t)cdb[4]) << 8;
		lba_start |= ((uint64_t)cdb[5]);
		data_len = cmd->bufflen;
		break;
	case SYNCHRONIZE_CACHE:
		lba_start |= ((uint64_t)cdb[2]) << 24;
		lba_start |= ((uint64_t)cdb[3]) << 16;
		lba_start |= ((uint64_t)cdb[4]) << 8;
		lba_start |= ((uint64_t)cdb[5]);
		data_len = ((cdb[7] << (BYTE * 1)) + (cdb[8] << (BYTE * 0)))
				<< dev->block_shift;
		if (data_len == 0)
			data_len = dev->file_size -
				((loff_t)lba_start << dev->block_shift);
		break;
	case READ_16:
	case WRITE_16:
	case WRITE_VERIFY_16:
	case VERIFY_16:
		lba_start |= ((uint64_t)cdb[2]) << 56;
		lba_start |= ((uint64_t)cdb[3]) << 48;
		lba_start |= ((uint64_t)cdb[4]) << 40;
		lba_start |= ((uint64_t)cdb[5]) << 32;
		lba_start |= ((uint64_t)cdb[6]) << 24;
		lba_start |= ((uint64_t)cdb[7]) << 16;
		lba_start |= ((uint64_t)cdb[8]) << 8;
		lba_start |= ((uint64_t)cdb[9]);
		data_len = cmd->bufflen;
		break;
	}

	loff = (loff_t)lba_start << dev->block_shift;
	TRACE_DBG("cmd %d, buf %"PRIx64", lba_start %"PRId64", loff %"PRId64
		", data_len %"PRId64, vcmd->cmd->cmd_h, cmd->pbuf, lba_start,
		(uint64_t)loff, (uint64_t)data_len);
	if ((loff < 0) || (data_len < 0) || ((loff + data_len) > dev->file_size)) {
	    	PRINT_INFO("Access beyond the end of the device "
			"(%"PRId64" of %"PRId64", len %"PRId64")", (uint64_t)loff,
			(uint64_t)dev->file_size, (uint64_t)data_len);
		set_cmd_error(vcmd, SCST_LOAD_SENSE(
				scst_sense_block_out_range_error));
		goto out;
	}

	switch (opcode) {
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		fua = (cdb[1] & 0x8);
		if (cdb[1] & 0x8) {
			TRACE(TRACE_ORDER, "FUA(%d): loff=%"PRId64", "
				"data_len=%"PRId64, fua, (uint64_t)loff,
				(uint64_t)data_len);
		}
		break;
	}

	switch (opcode) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		exec_read(vcmd, loff);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		if (!dev->rd_only_flag) {
			int do_fsync = sync_queue_type(cmd->queue_type);
			struct vdisk_tgt_dev *tgt_dev;
			enum scst_cmd_queue_type last_queue_type;

			tgt_dev = find_tgt_dev(dev, cmd->sess_h);
			if (tgt_dev == NULL) {
				PRINT_ERROR("Session %"PRIx64" not found",
					cmd->sess_h);
				set_cmd_error(vcmd,
				    SCST_LOAD_SENSE(scst_sense_hardw_error));
				goto out;
			}

			last_queue_type = tgt_dev->last_write_cmd_queue_type;
			tgt_dev->last_write_cmd_queue_type = cmd->queue_type;
			if (need_pre_sync(cmd->queue_type, last_queue_type)) {
			    	TRACE(TRACE_ORDER, "ORDERED "
			    		"WRITE(%d): loff=%"PRId64", data_len=%"
			    		PRId64, cmd->queue_type, (uint64_t)loff,
			    		(uint64_t)data_len);
			    	do_fsync = 1;
				if (exec_fsync(vcmd) != 0)
					goto out;
			}
			exec_write(vcmd, loff);
			/* O_SYNC flag is used for WT devices */
			if (do_fsync || fua)
				exec_fsync(vcmd);
		} else {
			PRINT_WARNING("Attempt to write to read-only "
				"device %s", dev->name);
			set_cmd_error(vcmd,
		    		SCST_LOAD_SENSE(scst_sense_data_protect));
		}
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		if (!dev->rd_only_flag) {
			int do_fsync = sync_queue_type(cmd->queue_type);
			struct vdisk_tgt_dev *tgt_dev;
			enum scst_cmd_queue_type last_queue_type;

			tgt_dev = find_tgt_dev(dev, cmd->sess_h);
			if (tgt_dev == NULL) {
				PRINT_ERROR("Session %"PRIx64" not found",
					cmd->sess_h);
				set_cmd_error(vcmd,
				    SCST_LOAD_SENSE(scst_sense_hardw_error));
				goto out;
			}

			last_queue_type = tgt_dev->last_write_cmd_queue_type;
			tgt_dev->last_write_cmd_queue_type = cmd->queue_type;
			if (need_pre_sync(cmd->queue_type, last_queue_type)) {
			    	TRACE(TRACE_ORDER, "ORDERED "
			    		"WRITE_VERIFY(%d): loff=%"PRId64", "
			    		"data_len=%"PRId64, cmd->queue_type,
			    		(uint64_t)loff, (uint64_t)data_len);
			    	do_fsync = 1;
				if (exec_fsync(vcmd) != 0)
					goto out;
			}
			exec_write(vcmd, loff);
			/* O_SYNC flag is used for WT devices */
			if (reply->status == 0)
				exec_verify(vcmd, loff);
			else if (do_fsync)
				exec_fsync(vcmd);
		} else {
			PRINT_WARNING("Attempt to write to read-only "
				"device %s", dev->name);
			set_cmd_error(vcmd,
				SCST_LOAD_SENSE(scst_sense_data_protect));
		}
		break;
	case SYNCHRONIZE_CACHE:
	{
		int immed = cdb[1] & 0x2;
		TRACE(TRACE_ORDER, "SYNCHRONIZE_CACHE: "
			"loff=%"PRId64", data_len=%"PRId64", immed=%d",
			(uint64_t)loff, (uint64_t)data_len, immed);
		if (immed) {
			/* ToDo: backgroung exec */
			exec_fsync(vcmd);
			break;
		} else {
			exec_fsync(vcmd);
			break;
		}
	}
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		exec_verify(vcmd, loff);
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		exec_mode_sense(vcmd);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		exec_mode_select(vcmd);
		break;
	case ALLOW_MEDIUM_REMOVAL:
		exec_prevent_allow_medium_removal(vcmd);
		break;
	case READ_TOC:
		exec_read_toc(vcmd);
		break;
	case START_STOP:
		exec_fsync(vcmd/*, 0, dev->file_size*/);
		break;
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
	case TEST_UNIT_READY:
		break;
	case INQUIRY:
		exec_inquiry(vcmd);
		break;
	case REQUEST_SENSE:
		exec_request_sense(vcmd);
		break;
	case READ_CAPACITY:
		exec_read_capacity(vcmd);
		break;
        case SERVICE_ACTION_IN:
		if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
			exec_read_capacity16(vcmd);
			break;
		}
		/* else go through */
	case REPORT_LUNS:
	default:
		TRACE_DBG("Invalid opcode %d", opcode);
		set_cmd_error(vcmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		break;
	}

out:
	TRACE_EXIT();
	return res;
}

static int do_alloc_mem(struct vdisk_cmd *vcmd)
{
	struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	int res = 0;

	TRACE_ENTRY();

	TRACE_MEM("Alloc mem (cmd %d, sess_h %"PRIx64", cdb_len %d, "
		"ext_cdb_len %d, alloc_len %d, queue_type %d, data_direction "
		"%d)", cmd->cmd_h, cmd->alloc_cmd.sess_h,
		cmd->alloc_cmd.cdb_len, cmd->alloc_cmd.ext_cdb_len,
		cmd->alloc_cmd.alloc_len, cmd->alloc_cmd.queue_type,
		cmd->alloc_cmd.data_direction);

	TRACE_BUFF_FLAG(TRACE_MEMORY, "CDB", cmd->alloc_cmd.cdb,
		cmd->alloc_cmd.cdb_len);

	memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;
#ifdef DEBUG_NOMEM
	if ((random() % 100) == 75)
		reply->alloc_reply.pbuf = 0;
	else
#endif
		reply->alloc_reply.pbuf = (unsigned long)vcmd->dev->alloc_fn(
						cmd->alloc_cmd.alloc_len);
	TRACE_MEM("Buf %"PRIx64" alloced, len %d", reply->alloc_reply.pbuf,
		cmd->alloc_cmd.alloc_len);
	if (reply->alloc_reply.pbuf == 0) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate buffer (len %d)",
			cmd->alloc_cmd.alloc_len);
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int do_cached_mem_free(struct vdisk_cmd *vcmd)
{
	struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	int res = 0;

	TRACE_ENTRY();

	TRACE_MEM("Cached mem free (cmd %x, buf %"PRIx64")", cmd->cmd_h,
		cmd->on_cached_mem_free.pbuf);

	free((void *)(unsigned long)cmd->on_cached_mem_free.pbuf);

	memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;

	TRACE_EXIT_RES(res);
	return res;
}

static int do_on_free_cmd(struct vdisk_cmd *vcmd)
{
	struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("On free cmd (cmd %d, resp_data_len %d, aborted %d, "
		"status %d, delivery_status %d)", cmd->cmd_h,
		cmd->on_free_cmd.resp_data_len, cmd->on_free_cmd.aborted,
		cmd->on_free_cmd.status, cmd->on_free_cmd.delivery_status);

	TRACE_MEM("On free cmd (cmd %d, buf %"PRIx64", buffer_cached %d)",
		cmd->cmd_h, cmd->on_free_cmd.pbuf,
		cmd->on_free_cmd.buffer_cached);

	if (!cmd->on_free_cmd.buffer_cached && (cmd->on_free_cmd.pbuf != 0)) {
		TRACE_MEM("Freeing buf %"PRIx64, cmd->on_free_cmd.pbuf);
		free((void *)(unsigned long)cmd->on_free_cmd.pbuf);
	}

	memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;

	TRACE_EXIT_RES(res);
	return res;
}

static int do_tm(struct vdisk_cmd *vcmd)
{
	struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	int res = 0;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "TM fn %d (sess_h %"PRIx64", cmd_h_to_abort %d)",
		cmd->tm_cmd.fn, cmd->tm_cmd.sess_h, cmd->tm_cmd.cmd_h_to_abort);

	memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;
	reply->result = 0;

	TRACE_EXIT_RES(res);
	return res;
}

static int do_sess(struct vdisk_cmd *vcmd)
{
	struct scst_user_get_cmd *cmd = vcmd->cmd;
	struct scst_user_reply_cmd *reply = vcmd->reply;
	int res = 0;
	struct vdisk_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	/*
	 * We are guaranteed to have one and only one command at this point,
	 * which is ATTACH_SESS/DETACH_SESS, so no protection is needed
	 */

	tgt_dev = find_tgt_dev(vcmd->dev, cmd->sess.sess_h);

	if (cmd->subcode == SCST_USER_ATTACH_SESS) {
		if (tgt_dev != NULL) {
			PRINT_ERROR("Session %"PRIx64" already exists)",
				cmd->sess.sess_h);
			res = EEXIST;
			goto reply;
		}

		tgt_dev = find_empty_tgt_dev(vcmd->dev);
		if (tgt_dev == NULL) {
			PRINT_ERROR("Too many initiators, session %"PRIx64
				" refused)", cmd->sess.sess_h);
			res = ENOMEM;
			goto reply;
		}

		tgt_dev->sess_h = cmd->sess.sess_h;
		tgt_dev->last_write_cmd_queue_type = SCST_CMD_QUEUE_SIMPLE;

		PRINT_INFO("Session from initiator %s (target %s) attached "
			"(LUN %"PRIx64", threads_num %d, rd_only %d, sess_h "
			"%"PRIx64")", cmd->sess.initiator_name,
			cmd->sess.target_name, cmd->sess.lun,
			cmd->sess.threads_num, cmd->sess.rd_only,
			cmd->sess.sess_h);
	} else {
		if (tgt_dev == NULL) {
			PRINT_ERROR("Session %"PRIx64" not found)",
				cmd->sess.sess_h);
			res = ESRCH;
			goto reply;
		}
		tgt_dev->sess_h = 0;
		PRINT_INFO("Session detached (sess_h %"PRIx64")",
			cmd->sess.sess_h);
	}

reply:
	memset(reply, 0, sizeof(*reply));
	reply->cmd_h = cmd->cmd_h;
	reply->subcode = cmd->subcode;
	reply->result = res;

	TRACE_EXIT_RES(res);
	return res;
}

static int open_dev_fd(struct vdisk_dev *dev)
{
	int res;
	int open_flags = O_LARGEFILE;

	if (dev->rd_only_flag)
		open_flags |= O_RDONLY;
	else
		open_flags |= O_RDWR;
	if (dev->o_direct_flag)
		open_flags |= O_DIRECT;
	if (dev->wt_flag)
		open_flags |= O_SYNC;

	TRACE_DBG("Opening file %s, flags 0x%x", dev->file_name, open_flags);
	res = open(dev->file_name, open_flags);

	return res;
}

void *main_loop(void *arg)
{
	int res = 0;
	struct vdisk_dev *dev = (struct vdisk_dev *)arg;
	struct scst_user_get_cmd cmd;
	struct scst_user_reply_cmd reply;
	struct vdisk_cmd vcmd = { -1, &cmd, dev, &reply, {0}};
	int scst_usr_fd = dev->scst_usr_fd;
	struct pollfd pl;

	TRACE_ENTRY();

	vcmd.fd = open_dev_fd(dev);
	if (vcmd.fd < 0) {
		res = -errno;
		PRINT_ERROR("Unable to open file %s (%s)", dev->file_name,
			strerror(-res));
		goto out;
	}

	memset(&pl, 0, sizeof(pl));
	pl.fd = scst_usr_fd;
	pl.events = POLLIN;

	cmd.preply = 0;

	while(1) {
#ifdef DEBUG_TM_IGNORE_ALL
		if (dev->debug_tm_ignore && (random() % 50000) == 55) {
			TRACE_MGMT_DBG("%s", "Ignore ALL");
			dev->debug_tm_ignore_all = 1;
		}
		if (dev->debug_tm_ignore_all) {
			/* Go Astral */
			while(1) {
				sleep(60);
			}
		}
#endif

		res = ioctl(scst_usr_fd, SCST_USER_REPLY_AND_GET_CMD, &cmd);
		if (res != 0) {
			res = errno;
			switch(res) {
			case ESRCH:
			case EBUSY:
				TRACE_MGMT_DBG("SCST_USER_REPLY_AND_GET_CMD returned "
					"%d (%s)", res, strerror(res));
				cmd.preply = 0;
			case EINTR:
				continue;
			case EAGAIN:
				TRACE_DBG("SCST_USER_REPLY_AND_GET_CMD returned "
					"EAGAIN (%d)", res);
				cmd.preply = 0;
				if (dev->non_blocking)
					break;
				else
					continue;
			default:
				PRINT_ERROR("SCST_USER_REPLY_AND_GET_CMD failed: "
					"%s (%d)", strerror(res), res);
#if 1
				continue;
#else
				goto out_close;
#endif
			}
again_poll:
			res = poll(&pl, 1, 2000);
			if (res > 0)
				continue;
			else if (res == 0)
				goto again_poll;
			else {
				res = errno;
				switch(res) {
				case ESRCH:
				case EBUSY:
				case EAGAIN:
					TRACE_MGMT_DBG("poll() returned %d "
						"(%s)", res, strerror(res));
				case EINTR:
					goto again_poll;
				default:
					PRINT_ERROR("poll() failed: %s", strerror(res));
#if 1
					goto again_poll;
#else
					goto out_close;
#endif
				}
			}
		}

		TRACE_BUFFER("Received cmd", &cmd, sizeof(cmd));

		switch(cmd.subcode) {
		case SCST_USER_EXEC:
			if (cmd.exec_cmd.data_direction & SCST_DATA_WRITE) {
				TRACE_BUFFER("Received cmd data",
					(void *)(unsigned long)cmd.exec_cmd.pbuf,
					cmd.exec_cmd.bufflen);
			}
			res = do_exec(&vcmd);
#ifdef DEBUG_TM_IGNORE
			if (res == 150) {
				cmd.preply = 0;
				continue;
			}
#endif
			if (reply.exec_reply.resp_data_len != 0) {
				TRACE_BUFFER("Reply data",
					(void *)(unsigned long)reply.exec_reply.pbuf,
					reply.exec_reply.resp_data_len);
			}
			break;

		case SCST_USER_ALLOC_MEM:
			res = do_alloc_mem(&vcmd);
			break;

		case SCST_USER_PARSE:
			res = do_parse(&vcmd);
			break;

		case SCST_USER_ON_CACHED_MEM_FREE:
			res = do_cached_mem_free(&vcmd);
			break;

		case SCST_USER_ON_FREE_CMD:
			res = do_on_free_cmd(&vcmd);
			break;

		case SCST_USER_TASK_MGMT:
			res = do_tm(&vcmd);
#if DEBUG_TM_FN_IGNORE
			if (dev->debug_tm_ignore) {
				sleep(15);
			}
#endif
			break;

		case SCST_USER_ATTACH_SESS:
		case SCST_USER_DETACH_SESS:
			res = do_sess(&vcmd);
			break;

		default:
			PRINT_ERROR("Unknown or wrong cmd subcode %x",
				cmd.subcode);
			goto out_close;
		}

		if (res != 0)
			goto out_close;

		cmd.preply = (unsigned long)&reply;
		TRACE_BUFFER("Sending reply", &reply, sizeof(reply));
	}

out_close:
	close(vcmd.fd);

out:
	PRINT_INFO("Thread %d exiting (res=%d)", gettid(), res);

	TRACE_EXIT_RES(res);
	return (void *)(long)res;
}

uint64_t gen_dev_id_num(const struct vdisk_dev *dev)
{
	unsigned int dev_id_num, i;

	for (dev_id_num = 0, i = 0; i < strlen(dev->name); i++) {
		unsigned int rv = random_values[(int)(dev->name[i])];
		/* do some rotating of the bits */
		dev_id_num ^= ((rv << i) | (rv >> (32 - i)));
	}

	return ((uint64_t)vdisk_ID << 32) | dev_id_num;
}

static void exec_inquiry(struct vdisk_cmd *vcmd)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int resp_len = 0;
	int length = cmd->bufflen;
	unsigned int i;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	uint8_t buf[INQ_BUF_SZ];

	TRACE_ENTRY();

	if (cmd->cdb[1] & CMDDT) {
		TRACE_DBG("%s", "INQUIRY: CMDDT is unsupported");
		set_cmd_error(vcmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	memset(buf, 0, sizeof(buf));
	buf[0] = dev->type;      /* type dev */
	if (buf[0] == TYPE_ROM)
		buf[1] = 0x80;      /* removable */
	/* Vital Product */
	if (cmd->cdb[1] & EVPD) {
		uint64_t dev_id_num;
		int dev_id_len;
		char dev_id_str[17];

		dev_id_num  = gen_dev_id_num(dev);
		dev_id_len = snprintf(dev_id_str, sizeof(dev_id_str), "%"PRIx64,
					dev_id_num);
		if (dev_id_len >= (signed)sizeof(dev_id_str))
			dev_id_len = sizeof(dev_id_str) - 1;
		TRACE_DBG("dev_id num %"PRIx64", str %s, len %d", dev_id_num,
			dev_id_str, dev_id_len);
		if (0 == cmd->cdb[2]) { /* supported vital product data pages */
			buf[3] = 3;
			buf[4] = 0x0; /* this page */
			buf[5] = 0x80; /* unit serial number */
			buf[6] = 0x83; /* device identification */
			resp_len = buf[3] + 4;
		} else if (0x80 == cmd->cdb[2]) { /* unit serial number */
			int usn_len = strlen(dev->usn);
			buf[1] = 0x80;
			buf[3] = usn_len;
			strncpy((char *)&buf[4], dev->usn, usn_len);
			resp_len = buf[3] + 4;
		} else if (0x83 == cmd->cdb[2]) { /* device identification */
			int num = 4;

			buf[1] = 0x83;
			/* Two identification descriptors: */
			/* T10 vendor identifier field format (faked) */
			buf[num + 0] = 0x2;	/* ASCII */
			buf[num + 1] = 0x1;	/* Vendor ID */
			memcpy(&buf[num + 4], VENDOR, 8);
			i = strlen(dev->name) + 1; /* for ' ' */
			memset(&buf[num + 12], ' ', i + dev_id_len);
			memcpy(&buf[num + 12], dev->name, i-1);
			memcpy(&buf[num + 12 + i], dev_id_str, dev_id_len);
			buf[num + 3] = 8 + i + dev_id_len;
			num += buf[num + 3];

#if 0 /* This isn't required and can be misleading, so let's disable it */
			num += 4;

			/* NAA IEEE registered identifier (faked) */
			buf[num] = 0x1;	/* binary */
			buf[num + 1] = 0x3;
			buf[num + 2] = 0x0;
			buf[num + 3] = 0x8;
			buf[num + 4] = 0x51;	/* ieee company id=0x123456 (faked) */
			buf[num + 5] = 0x23;
			buf[num + 6] = 0x45;
			buf[num + 7] = 0x60;
			buf[num + 8] = (dev_id_num >> 24);
			buf[num + 9] = (dev_id_num >> 16) & 0xff;
			buf[num + 10] = (dev_id_num >> 8) & 0xff;
			buf[num + 11] = dev_id_num & 0xff;
			num = num + 12 - 4;
#endif

			resp_len = num;
			buf[2] = (resp_len >> 8) & 0xFF;
			buf[3] = resp_len & 0xFF;
			resp_len += 4;
		} else {
			TRACE_DBG("INQUIRY: Unsupported EVPD page %x",
				cmd->cdb[2]);
			set_cmd_error(vcmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out;
		}
	} else {
		int len;

		if (cmd->cdb[2] != 0) {
			TRACE_DBG("INQUIRY: Unsupported page %x", cmd->cdb[2]);
			set_cmd_error(vcmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out;
		}

		buf[2] = 5;	/* Device complies to SPC-3 */
		buf[3] = 0x12;	/* HiSup + data in format specified in SPC */
		buf[4] = 31;/* n - 4 = 35 - 4 = 31 for full 36 byte data */
		buf[6] = 1; /* MultiP 1 */
		buf[7] = 2; /* CMDQUE 1, BQue 0 => commands queuing supported */

		/* 8 byte ASCII Vendor Identification of the target - left aligned */
		memcpy(&buf[8], VENDOR, 8);

		/* 16 byte ASCII Product Identification of the target - left aligned */
		memset(&buf[16], ' ', 16);
		len = min(strlen(dev->name), (size_t)16);
		memcpy(&buf[16], dev->name, len);

		/* 4 byte ASCII Product Revision Level of the target - left aligned */
		memcpy(&buf[32], FIO_REV, 4);
		resp_len = buf[4] + 5;
	}

	sBUG_ON(resp_len >= (int)sizeof(buf));
	if (length > resp_len)
		length = resp_len;
	memcpy(address, buf, length);
	reply->resp_data_len = length;

out:
	TRACE_EXIT();
	return;
}

static void exec_request_sense(struct vdisk_cmd *vcmd)
{
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int length = cmd->bufflen, l;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	uint8_t b[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	l = set_sense(b, sizeof(b), SCST_LOAD_SENSE(scst_sense_no_sense));

	length = min(l, length);
	memcpy(address, b, length);
	reply->resp_data_len = length;

	TRACE_EXIT();
	return;
}

/*
 * <<Following mode pages info copied from ST318451LW with some corrections>>
 *
 * ToDo: revise them
 */

static int err_recov_pg(unsigned char *p, int pcontrol)
{	/* Read-Write Error Recovery page for mode_sense */
	const unsigned char err_recov_pg[] = {0x1, 0xa, 0xc0, 11, 240, 0, 0, 0,
					      5, 0, 0xff, 0xff};

	memcpy(p, err_recov_pg, sizeof(err_recov_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(err_recov_pg) - 2);
	return sizeof(err_recov_pg);
}

static int disconnect_pg(unsigned char *p, int pcontrol)
{ 	/* Disconnect-Reconnect page for mode_sense */
	const unsigned char disconnect_pg[] = {0x2, 0xe, 128, 128, 0, 10, 0, 0,
					       0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(p, disconnect_pg, sizeof(disconnect_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(disconnect_pg) - 2);
	return sizeof(disconnect_pg);
}

static int rigid_geo_pg(unsigned char *p, int pcontrol,
	struct vdisk_dev *dev)
{
	unsigned char geo_m_pg[] = {0x04, 0x16, 0, 0, 0, DEF_HEADS, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0x3a, 0x98/* 15K RPM */, 0, 0};
	int32_t ncyl, n;
	
	memcpy(p, geo_m_pg, sizeof(geo_m_pg));
	ncyl = dev->nblocks / (DEF_HEADS * DEF_SECTORS);
	if ((dev->nblocks % (DEF_HEADS * DEF_SECTORS)) != 0)
		ncyl++;
	memcpy(&n, p + 2, sizeof(uint32_t));
	n = n | (htonl(ncyl) >> 8);
	memcpy(p + 2, &n, sizeof(uint32_t));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(geo_m_pg) - 2);
	return sizeof(geo_m_pg);
}

static int format_pg(unsigned char *p, int pcontrol,
			     struct vdisk_dev *dev)
{       /* Format device page for mode_sense */
	const unsigned char format_pg[] = {0x3, 0x16, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0x40, 0, 0, 0};

        memcpy(p, format_pg, sizeof(format_pg));
        p[10] = (DEF_SECTORS >> 8) & 0xff;
        p[11] = DEF_SECTORS & 0xff;
        p[12] = (dev->block_size >> 8) & 0xff;
        p[13] = dev->block_size & 0xff;
        if (1 == pcontrol)
                memset(p + 2, 0, sizeof(format_pg) - 2);
        return sizeof(format_pg);
}

static int caching_pg(unsigned char *p, int pcontrol,
			     struct vdisk_dev *dev)
{ 	/* Caching page for mode_sense */
	const unsigned char caching_pg[] = {0x8, 18, 0x10, 0, 0xff, 0xff, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0, 0, 0, 0, 0, 0};

	memcpy(p, caching_pg, sizeof(caching_pg));
	p[2] |= !(dev->wt_flag) ? WCE : 0;
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(caching_pg) - 2);
	return sizeof(caching_pg);
}

static int ctrl_m_pg(unsigned char *p, int pcontrol,
			    struct vdisk_dev *dev)
{ 	/* Control mode page for mode_sense */
	const unsigned char ctrl_m_pg[] = {0xa, 0xa, 0x20, 0, 0, 0x40, 0, 0,
					   0, 0, 0x2, 0x4b};

	memcpy(p, ctrl_m_pg, sizeof(ctrl_m_pg));
	if (!dev->wt_flag && !dev->nv_cache)
		p[3] |= 0x10; /* Enable unrestricted reordering */
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(ctrl_m_pg) - 2);
	return sizeof(ctrl_m_pg);
}

static int iec_m_pg(unsigned char *p, int pcontrol)
{	/* Informational Exceptions control mode page for mode_sense */
	const unsigned char iec_m_pg[] = {0x1c, 0xa, 0x08, 0, 0, 0, 0, 0,
				          0, 0, 0x0, 0x0};
	memcpy(p, iec_m_pg, sizeof(iec_m_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(iec_m_pg) - 2);
	return sizeof(iec_m_pg);
}

static void exec_mode_sense(struct vdisk_cmd *vcmd)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	uint8_t buf[MSENSE_BUF_SZ];
	int blocksize;
	uint64_t nblocks;
	unsigned char dbd, type;
	int pcontrol, pcode, subpcode;
	unsigned char dev_spec;
	int msense_6, offset = 0, len;
	unsigned char *bp;

	TRACE_ENTRY();

	blocksize = dev->block_size;
	nblocks = dev->nblocks;

	type = dev->type;    /* type dev */
	dbd = cmd->cdb[1] & DBD;
	pcontrol = (cmd->cdb[2] & 0xc0) >> 6;
	pcode = cmd->cdb[2] & 0x3f;
	subpcode = cmd->cdb[3];
	msense_6 = (MODE_SENSE == cmd->cdb[0]);
	dev_spec = (dev->rd_only_flag ? WP : 0) | DPOFUA;

	memset(buf, 0, sizeof(buf));

	if (0x3 == pcontrol) {
		TRACE_DBG("%s", "MODE SENSE: Saving values not supported");
		set_cmd_error(vcmd,
		    SCST_LOAD_SENSE(scst_sense_saving_params_unsup));
		goto out;
	}

	if (msense_6) {
		buf[1] = type;
		buf[2] = dev_spec;
		offset = 4;
	} else {
		buf[2] = type;
		buf[3] = dev_spec;
		offset = 8;
	}

	if (0 != subpcode) { /* TODO: Control Extension page */
		TRACE_DBG("%s", "MODE SENSE: Only subpage 0 is supported");
		set_cmd_error(vcmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	if (!dbd) {
		/* Create block descriptor */
		buf[offset - 1] = 0x08;		/* block descriptor length */
		if (nblocks >> 32) {
			buf[offset + 0] = 0xFF;
			buf[offset + 1] = 0xFF;
			buf[offset + 2] = 0xFF;
			buf[offset + 3] = 0xFF;
		} else {
			buf[offset + 0] = (nblocks >> (BYTE * 3)) & 0xFF;/* num blks */
			buf[offset + 1] = (nblocks >> (BYTE * 2)) & 0xFF;
			buf[offset + 2] = (nblocks >> (BYTE * 1)) & 0xFF;
			buf[offset + 3] = (nblocks >> (BYTE * 0)) & 0xFF;
		}
		buf[offset + 4] = 0;			/* density code */
		buf[offset + 5] = (blocksize >> (BYTE * 2)) & 0xFF;/* blklen */
		buf[offset + 6] = (blocksize >> (BYTE * 1)) & 0xFF;
		buf[offset + 7] = (blocksize >> (BYTE * 0)) & 0xFF;

		offset += 8;			/* increment offset */
	}

	bp = buf + offset;

	switch (pcode) {
	case 0x1:	/* Read-Write error recovery page, direct access */
		len = err_recov_pg(bp, pcontrol);
		break;
	case 0x2:	/* Disconnect-Reconnect page, all devices */
		len = disconnect_pg(bp, pcontrol);
		break;
        case 0x3:       /* Format device page, direct access */
                len = format_pg(bp, pcontrol, dev);
                break;
	case 0x4:	/* Rigid disk geometry */
		len = rigid_geo_pg(bp, pcontrol, dev);
		break;
	case 0x8:	/* Caching page, direct access */
		len = caching_pg(bp, pcontrol, dev);
		break;
	case 0xa:	/* Control Mode page, all devices */
		len = ctrl_m_pg(bp, pcontrol, dev);
		break;
	case 0x1c:	/* Informational Exceptions Mode page, all devices */
		len = iec_m_pg(bp, pcontrol);
		break;
	case 0x3f:	/* Read all Mode pages */
		len = err_recov_pg(bp, pcontrol);
		len += disconnect_pg(bp + len, pcontrol);
		len += format_pg(bp + len, pcontrol, dev);
		len += caching_pg(bp + len, pcontrol, dev);
		len += ctrl_m_pg(bp + len, pcontrol, dev);
		len += iec_m_pg(bp + len, pcontrol);
		len += rigid_geo_pg(bp + len, pcontrol, dev);
		break;
	default:
		TRACE_DBG("MODE SENSE: Unsupported page %x", pcode);
		set_cmd_error(vcmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	offset += len;

	if (msense_6)
		buf[0] = offset - 1;
	else {
		buf[0] = ((offset - 2) >> 8) & 0xff;
		buf[1] = (offset - 2) & 0xff;
	}

	sBUG_ON(offset >= (int)sizeof(buf));
	if (offset > length)
		offset = length;
	memcpy(address, buf, offset);
	reply->resp_data_len = offset;

out:
	TRACE_EXIT();
	return;
}

static int set_wt(struct vdisk_dev *dev, int wt)
{
	int res = 0;

	TRACE_ENTRY();

	if ((dev->wt_flag == wt) || dev->nullio)
		goto out;

	pthread_mutex_lock(&dev->dev_mutex);
	dev->wt_flag = wt;
	pthread_mutex_unlock(&dev->dev_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void exec_mode_select(struct vdisk_cmd *vcmd)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	int mselect_6, offset;

	TRACE_ENTRY();

	mselect_6 = (MODE_SELECT == cmd->cdb[0]);

	if (!(cmd->cdb[1] & PF) || (cmd->cdb[1] & SP)) {
		PRINT_ERROR("MODE SELECT: PF and/or SP are wrongly set "
			"(cdb[1]=%x)", cmd->cdb[1]);
		set_cmd_error(vcmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	if (mselect_6) {
		offset = 4;
	} else {
		offset = 8;
	}

	if (address[offset - 1] == 8) {
		offset += 8;
	} else if (address[offset - 1] != 0) {
		PRINT_ERROR("%s", "MODE SELECT: Wrong parameters list "
			"lenght");
		set_cmd_error(vcmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

	while (length > offset + 2) {
		if (address[offset] & PS) {
			PRINT_ERROR("%s", "MODE SELECT: Illegal PS bit");
			set_cmd_error(vcmd, SCST_LOAD_SENSE(
			    	scst_sense_invalid_field_in_parm_list));
			goto out;
		}
		if ((address[offset] & 0x3f) == 0x8) {	/* Caching page */
			if (address[offset + 1] != 18) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"caching page request");
				set_cmd_error(vcmd, SCST_LOAD_SENSE(
				    	scst_sense_invalid_field_in_parm_list));
				goto out;
			}
			if (set_wt(dev,
			      (address[offset + 2] & WCE) ? 0 : 1) != 0) {
				set_cmd_error(vcmd,
				    SCST_LOAD_SENSE(scst_sense_hardw_error));
				goto out;
			}
			break;
		}
		offset += address[offset + 1];
	}

out:
	TRACE_EXIT();
	return;
}

static void exec_read_capacity(struct vdisk_cmd *vcmd)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[READ_CAP_LEN];

	TRACE_ENTRY();

	blocksize = dev->block_size;
	nblocks = dev->nblocks;

	/* last block on the dev is (nblocks-1) */
	memset(buffer, 0, sizeof(buffer));
	if (nblocks >> 32) {
		buffer[0] = 0xFF;
		buffer[1] = 0xFF;
		buffer[2] = 0xFF;
		buffer[3] = 0xFF;
	} else {
		buffer[0] = ((nblocks - 1) >> (BYTE * 3)) & 0xFF;
		buffer[1] = ((nblocks - 1) >> (BYTE * 2)) & 0xFF;
		buffer[2] = ((nblocks - 1) >> (BYTE * 1)) & 0xFF;
		buffer[3] = ((nblocks - 1) >> (BYTE * 0)) & 0xFF;
	}
	buffer[4] = (blocksize >> (BYTE * 3)) & 0xFF;
	buffer[5] = (blocksize >> (BYTE * 2)) & 0xFF;
	buffer[6] = (blocksize >> (BYTE * 1)) & 0xFF;
	buffer[7] = (blocksize >> (BYTE * 0)) & 0xFF;

	if (length > READ_CAP_LEN)
		length = READ_CAP_LEN;
	memcpy(address, buffer, length);

	reply->resp_data_len = length;

	TRACE_EXIT();
	return;
}

static void exec_read_capacity16(struct vdisk_cmd *vcmd)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[READ_CAP16_LEN];

	TRACE_ENTRY();

	blocksize = dev->block_size;
	nblocks = dev->nblocks - 1;

	memset(buffer, 0, sizeof(buffer));

	buffer[0] = nblocks >> 56;
	buffer[1] = (nblocks >> 48) & 0xFF;
	buffer[2] = (nblocks >> 40) & 0xFF;
	buffer[3] = (nblocks >> 32) & 0xFF;
	buffer[4] = (nblocks >> 24) & 0xFF;
	buffer[5] = (nblocks >> 16) & 0xFF;
	buffer[6] = (nblocks >> 8) & 0xFF;
	buffer[7] = nblocks& 0xFF;

	buffer[8] = (blocksize >> (BYTE * 3)) & 0xFF;
	buffer[9] = (blocksize >> (BYTE * 2)) & 0xFF;
	buffer[10] = (blocksize >> (BYTE * 1)) & 0xFF;
	buffer[11] = (blocksize >> (BYTE * 0)) & 0xFF;

	switch (blocksize) {
	case 512:
		buffer[13] = 3;
		break;
	case 1024:
		buffer[13] = 2;
		break;
	case 2048:
		buffer[13] = 1;
		break;
	default:
		PRINT_ERROR("READ CAPACITY(16): Unexpected block size %d6",
			blocksize);
		/* go through */
	case 4096:
		buffer[13] = 0;
		break;
	}

	if (length > READ_CAP16_LEN)
		length = READ_CAP16_LEN;
	memcpy(address, buffer, length);

	reply->resp_data_len = length;

	TRACE_EXIT();
	return;
}

static void exec_read_toc(struct vdisk_cmd *vcmd)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int32_t off = 0;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	uint32_t nblocks;
	uint8_t buffer[4+8+8] = { 0x00, 0x0a, 0x01, 0x01, 0x00, 0x14,
				  0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

	TRACE_ENTRY();

	if (dev->type != TYPE_ROM) {
		PRINT_ERROR("%s", "READ TOC for non-CDROM device");
		set_cmd_error(vcmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out;
	}

	if (cmd->cdb[2] & 0x0e/*Format*/) {
		PRINT_ERROR("%s", "READ TOC: invalid requested data format");
		set_cmd_error(vcmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	if ((cmd->cdb[6] != 0 && (cmd->cdb[2] & 0x01)) ||
	    (cmd->cdb[6] > 1 && cmd->cdb[6] != 0xAA)) {
		PRINT_ERROR("READ TOC: invalid requested track number %x",
			cmd->cdb[6]);
		set_cmd_error(vcmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	/* ToDo when you have > 8TB ROM device. */
	nblocks = (uint32_t)dev->nblocks;

	/* Header */
	memset(buffer, 0, sizeof(buffer));
	buffer[2] = 0x01;    /* First Track/Session */
	buffer[3] = 0x01;    /* Last Track/Session */
	off = 4;
	if (cmd->cdb[6] <= 1)
        {
		/* Fistr TOC Track Descriptor */
		buffer[off+1] = 0x14; /* ADDR    0x10 - Q Sub-channel encodes current position data
					 CONTROL 0x04 - Data track, recoreded uninterrupted */
		buffer[off+2] = 0x01; /* Track Number */
		off += 8;
        }
	if (!(cmd->cdb[2] & 0x01))
        {
		/* Lead-out area TOC Track Descriptor */
		buffer[off+1] = 0x14;
		buffer[off+2] = 0xAA;     /* Track Number */
		buffer[off+4] = (nblocks >> (BYTE * 3)) & 0xFF; /* Track Start Address */
		buffer[off+5] = (nblocks >> (BYTE * 2)) & 0xFF;
		buffer[off+6] = (nblocks >> (BYTE * 1)) & 0xFF;
		buffer[off+7] = (nblocks >> (BYTE * 0)) & 0xFF;
		off += 8;
        }

	buffer[1] = off - 2;    /* Data  Length */

	if (off > length)
		off = length;
	memcpy(address, buffer, off);
	reply->resp_data_len = off;

out:
	TRACE_EXIT();
	return;
}

static void exec_prevent_allow_medium_removal(struct vdisk_cmd *vcmd)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;

	TRACE_DBG("PERSIST/PREVENT 0x%02x", cmd->cdb[4]);

	pthread_mutex_lock(&dev->dev_mutex);
	if (dev->type == TYPE_ROM)
		dev->prevent_allow_medium_removal =
			cmd->cdb[4] & 0x01 ? 1 : 0;
	else {
		PRINT_ERROR("%s", "Prevent allow medium removal for "
			"non-CDROM device");
		set_cmd_error(vcmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	}
	pthread_mutex_unlock(&dev->dev_mutex);

	return;
}

static int exec_fsync(struct vdisk_cmd *vcmd)
{
	int res = 0;
	struct vdisk_dev *dev = vcmd->dev;

	/* Hopefully, the compiler will generate the single comparison */
	if (dev->nv_cache || dev->wt_flag || dev->rd_only_flag ||
	    dev->o_direct_flag || dev->nullio)
		goto out;

	/* ToDo: use sync_file_range() instead */
	fsync(vcmd->fd);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void exec_read(struct vdisk_cmd *vcmd, loff_t loff)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	int fd = vcmd->fd;
	loff_t err;

	TRACE_ENTRY();

	TRACE_DBG("reading off %"PRId64", len %d", loff, length);
	if (dev->nullio)
		err = length;
	else {
		/* SEEK */
		err = lseek64(fd, loff, 0/*SEEK_SET*/);
		if (err != loff) {
			PRINT_ERROR("lseek trouble %"PRId64" != %"PRId64
				" (errno %d)", (uint64_t)err, (uint64_t)loff,
				errno);
			set_cmd_error(vcmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out;
		}
		/* READ */
		err = read(fd, address, length);
	}

	if ((err < 0) || (err < length)) {
		PRINT_ERROR("read() returned %"PRId64" from %d (errno %d)",
			(uint64_t)err, length, errno);
		if (err == -EAGAIN)
			set_busy(reply);
		else {
			set_cmd_error(vcmd,
			    SCST_LOAD_SENSE(scst_sense_read_error));
		}
		goto out;
	}

	reply->resp_data_len = cmd->bufflen;

out:
	TRACE_EXIT();
	return;
}

static void exec_write(struct vdisk_cmd *vcmd, loff_t loff)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	loff_t err;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	int fd = vcmd->fd;

	TRACE_ENTRY();

restart:
	TRACE_DBG("writing off %"PRId64", len %d", loff, length);

	if (dev->nullio)
		err = length;
	else {
		/* SEEK */
		err = lseek64(fd, loff, 0/*SEEK_SET*/);
		if (err != loff) {
			PRINT_ERROR("lseek trouble %"PRId64" != %"PRId64
				" (errno %d)", (uint64_t)err, (uint64_t)loff,
				errno);
			set_cmd_error(vcmd,
			    SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out;
		}

		/* WRITE */
		err = write(fd, address, length);
	}

	if (err < 0) {
		PRINT_ERROR("write() returned %"PRId64" from %d (errno %d, "
			"cmd_h %x)", err, length, errno, vcmd->cmd->cmd_h);
		if (err == -EAGAIN)
			set_busy(reply);
		else {
			set_cmd_error(vcmd,
			    SCST_LOAD_SENSE(scst_sense_write_error));
		}
		goto out;
	} else if (err < length) {
		/*
		 * Probably that's wrong, but sometimes write() returns
		 * value less, than requested. Let's restart.
		 */
		TRACE_MGMT_DBG("write() returned %d from %d", (int)err, length);
		if (err == 0) {
			PRINT_INFO("Suspicious: write() returned 0 from "
				"%d", length);
		}
		length -= err;
		goto restart;
	}

out:
	TRACE_EXIT();
	return;
}

static void exec_verify(struct vdisk_cmd *vcmd, loff_t loff)
{
	struct vdisk_dev *dev = vcmd->dev;
	struct scst_user_scsi_cmd_exec *cmd = &vcmd->cmd->exec_cmd;
	struct scst_user_scsi_cmd_reply_exec *reply = &vcmd->reply->exec_reply;
	loff_t err;
	int length = cmd->bufflen;
	uint8_t *address = (uint8_t*)(unsigned long)cmd->pbuf;
	int compare;
	int fd = vcmd->fd;
	uint8_t mem_verify[128*1024];

	TRACE_ENTRY();

	if (exec_fsync(vcmd) != 0)
		goto out;

	/*
	 * Until the cache is cleared prior the verifying, there is not
         * much point in this code. ToDo.
	 *
	 * Nevertherless, this code is valuable if the data have not read
	 * from the file/disk yet.
	 */

	/* SEEK */
	if (!dev->nullio) {
		err = lseek64(fd, loff, 0/*SEEK_SET*/);
		if (err != loff) {
			PRINT_ERROR("lseek trouble %"PRId64" != %"PRId64
				" (errno %d)", (uint64_t)err,
				(uint64_t)loff, errno);
			set_cmd_error(vcmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out;
		}
	}

	if ((length == 0) && (cmd->data_len != 0)) {
		length = cmd->data_len;
		compare = 0;
	} else
		compare = 1;

	while (length > 0) {
		int len_mem = (length > (int)sizeof(mem_verify)) ?
					(int)sizeof(mem_verify) : length;
		TRACE_DBG("Verify: length %d - len_mem %d", length, len_mem);

		if (!dev->nullio)
			err = read(fd, (char *)mem_verify, len_mem);
		else
			err = len_mem;
		if ((err < 0) || (err < len_mem)) {
			PRINT_ERROR("read() returned %"PRId64" from %d "
				"(errno %d)", (uint64_t)err, len_mem, errno);
			if (err == -EAGAIN)
				set_busy(reply);
			else {
				set_cmd_error(vcmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			goto out;
		}
		if (compare && memcmp(address, mem_verify, len_mem) != 0) {
			TRACE_DBG("Verify: error memcmp length %d", length);
			set_cmd_error(vcmd,
			    SCST_LOAD_SENSE(scst_sense_miscompare_error));
			goto out;
		}
		length -= len_mem;
		address += len_mem;
	}

	if (length < 0) {
		PRINT_ERROR("Failure: %d", length);
		set_cmd_error(vcmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	}

out:
	TRACE_EXIT();
	return;
}
