/*
 *  Copyright (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 - 2009 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation.
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
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "iscsid.h"

#define CTL_DEVICE	"/dev/iscsi-scst-ctl"

int kernel_open(int *max_data_seg_len)
{
	FILE *f;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd = -1;
	int err;
	struct iscsi_kern_register_info reg = { 0 };

	if (!(f = fopen("/proc/devices", "r"))) {
		err = -errno;
		perror("Cannot open control path to the driver");
		goto out_err;
	}

	devn = 0;
	while (!feof(f)) {
		if (!fgets(buf, sizeof (buf), f)) {
			break;
		}
		if (sscanf(buf, "%d %s", &devn, devname) != 2) {
			continue;
		}
		if (!strcmp(devname, "iscsi-scst-ctl")) {
			break;
		}
		devn = 0;
	}

	fclose(f);
	if (!devn) {
		err = -ENOENT;
		printf("cannot find iscsictl in /proc/devices - "
		     "make sure the module is loaded\n");
		goto out_err;
	}

	unlink(CTL_DEVICE);
	if (mknod(CTL_DEVICE, (S_IFCHR | 0600), (devn << 8))) {
		err = -errno;
		printf("cannot create %s %d\n", CTL_DEVICE, errno);
		goto out_err;
	}

	ctlfd = open(CTL_DEVICE, O_RDWR);
	if (ctlfd < 0) {
		err = -errno;
		printf("cannot open %s %d\n", CTL_DEVICE, errno);
		goto out_err;
	}

	reg.version = (uintptr_t)ISCSI_SCST_INTERFACE_VERSION;

	err = ioctl(ctlfd, REGISTER_USERD, &reg);
	if (err < 0) {
		err = -errno;
		log_error("Unable to register: %s. Incompatible version of the "
			"kernel module?\n", strerror(errno));
		goto out_close;
	} else {
		log_debug(0, "MAX_DATA_SEG_LEN %d", err);
		*max_data_seg_len = err;
	}

out:
	return ctlfd;

out_close:
	close(ctlfd);

out_err:
	ctlfd = err;
	goto out;
}

int kernel_target_create(u32 *tid, char *name)
{
	int err;
	struct iscsi_kern_target_info info;

	memset(&info, 0, sizeof(info));

	memcpy(info.name, name, sizeof(info.name) - 1);
	info.tid = *tid;
	if ((err = ioctl(ctrl_fd, ADD_TARGET, &info)) < 0) {
		err = -errno;
		log_error("Can't create target %u: %s\n", *tid,
			strerror(errno));
	} else
		*tid = info.tid;

	return err;
}

int kernel_target_destroy(u32 tid)
{
	struct iscsi_kern_target_info info;
	int res;

	memset(&info, 0, sizeof(info));
	info.tid = tid;

	res = ioctl(ctrl_fd, DEL_TARGET, &info);
	if (res < 0) {
		res = -errno;
		log_error("Can't destroy target %d %u\n", errno, tid);
	}

	return res;
}

int kernel_conn_destroy(u32 tid, u64 sid, u32 cid)
{
	int err;
	struct iscsi_kern_conn_info info;

	info.tid = tid;
	info.sid = sid;
	info.cid = cid;

	if ((err = ioctl(ctrl_fd, DEL_CONN, &info)) < 0) {
		err = -errno;
		log_error("Can't destroy conn %d %u\n", errno, cid);
	}

	return err;
}

int kernel_param_get(u32 tid, u64 sid, int type, struct iscsi_param *param)
{
	int err, i;
	struct iscsi_kern_param_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;
	info.param_type = type;

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_GET, &info)) < 0) {
		err = -errno;
		log_debug(1, "Can't get session param for session 0x%" PRIu64 
			" (tid %u, err %d): %s\n", sid, tid, err, strerror(errno));
	}

	if (type == key_session)
		for (i = 0; i < session_key_last; i++)
			param[i].val = info.session_param[i];
	else
		for (i = 0; i < target_key_last; i++)
			param[i].val = info.target_param[i];

	return err;
}

int kernel_param_set(u32 tid, u64 sid, int type, u32 partial,
	struct iscsi_param *param)
{
	int i, err;
	struct iscsi_kern_param_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;
	info.param_type = type;
	info.partial = partial;

	if (info.param_type == key_session)
		for (i = 0; i < session_key_last; i++)
			info.session_param[i] = param[i].val;
	else
		for (i = 0; i < target_key_last; i++)
			info.target_param[i] = param[i].val;

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_SET, &info)) < 0) {
		err = -errno;
		log_error("Can't set session param for session 0x%" PRIu64 
			" (tid %u, type %d, partial %d, err %d): %s\n", sid,
			tid, type, partial, err, strerror(errno));
	}

	return err;
}

int kernel_session_create(u32 tid, u64 sid, u32 exp_cmd_sn,
	char *name, char *user)
{
	struct iscsi_kern_session_info info;
	int res;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;
	info.exp_cmd_sn = exp_cmd_sn;
	strncpy(info.initiator_name, name, sizeof(info.initiator_name) - 1);
	strncpy(info.user_name, user, sizeof(info.user_name) - 1);

	res = ioctl(ctrl_fd, ADD_SESSION, &info);
	if (res < 0) {
		res = -errno;
		log_error("Can't create sess 0x%" PRIu64 " (tid %d, "
			"initiator %s): %s\n", sid, tid, name, strerror(errno));
	}

	return res;
}

int kernel_session_destroy(u32 tid, u64 sid)
{
	struct iscsi_kern_session_info info;
	int res;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;

	res = ioctl(ctrl_fd, DEL_SESSION, &info);
	if (res < 0) {
		res = -errno;
		log_error("Can't destroy sess 0x%" PRIu64 " (tid %d): %s\n",
			sid, tid, strerror(errno));
	}

	return res;
}

int kernel_conn_create(u32 tid, u64 sid, u32 cid, u32 stat_sn, u32 exp_stat_sn,
			     int fd, u32 hdigest, u32 ddigest)
{
	struct iscsi_kern_conn_info info;
	int res;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;
	info.cid = cid;
	info.stat_sn = stat_sn;
	info.exp_stat_sn = exp_stat_sn;
	info.fd = fd;
	info.header_digest = hdigest;
	info.data_digest = ddigest;

	res = ioctl(ctrl_fd, ADD_CONN, &info);
	if (res < 0) {
		res = -errno;
		log_error("Can't create conn %x (sess 0x%" PRIu64 ", tid %d): %s\n",
			cid, sid, tid, strerror(errno));
	}

	return res;
}
