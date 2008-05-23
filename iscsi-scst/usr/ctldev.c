/*
 *  Copyright (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 Vladislav Bolkhovitin
 *  Copyright (C) 2007 CMS Distribution Limited
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

struct session_file_operations {
	int (*target_op) (int fd, u32 tid, void *arg);
	int (*session_op) (int fd, u32 tid, u64 sid, void *arg);
	int (*connection_op) (int fd, u32 tid, u64 sid, u32 cid, void *arg);
};

static int ctrdev_open(int max_data_seg_len)
{
	FILE *f;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd = -1;
	int err;
	struct iscsi_register_info reg = { 0 };

	if (!(f = fopen("/proc/devices", "r"))) {
		perror("Cannot open control path to the driver\n");
		goto out;
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
		printf("cannot find iscsictl in /proc/devices - "
		     "make sure the module is loaded\n");
		goto out;
	}

	unlink(CTL_DEVICE);
	if (mknod(CTL_DEVICE, (S_IFCHR | 0600), (devn << 8))) {
		printf("cannot create %s %d\n", CTL_DEVICE, errno);
		goto out;
	}

	ctlfd = open(CTL_DEVICE, O_RDWR);
	if (ctlfd < 0) {
		printf("cannot open %s %d\n", CTL_DEVICE, errno);
		goto out;
	}

	reg.version = ISCSI_SCST_INTERFACE_VERSION;
	reg.max_data_seg_len = max_data_seg_len;
	err = ioctl(ctlfd, REGISTER_USERD, &reg);
	if (err < 0) {
		log_error("Unable to register: %s. Incompatible version of the "
			"kernel module?\n", strerror(errno));
		close(ctlfd);
		ctlfd = -1;
		goto out;
	}

out:
	return ctlfd;
}

static int iscsi_target_create(u32 *tid, char *name)
{
	int err;
	struct target_info info;

	memset(&info, 0, sizeof(info));

	memcpy(info.name, name, sizeof(info.name) - 1);
	info.tid = *tid;
	if ((err = ioctl(ctrl_fd, ADD_TARGET, &info)) < 0)
		log_warning("can't create a target %d %u\n", errno, info.tid);

	*tid = info.tid;
	return err;
}

static int iscsi_target_destroy(u32 tid)
{
	struct target_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;

	return ioctl(ctrl_fd, DEL_TARGET, &info);
}

static int iscsi_conn_destroy(u32 tid, u64 sid, u32 cid)
{
	int err;
	struct conn_info info;

	info.tid = tid;
	info.sid = sid;
	info.cid = cid;

	if ((err = ioctl(ctrl_fd, DEL_CONN, &info)) < 0)
		err = errno;

	return err;
}

/**
 ** ToDo: the below code is a brain damage, rewrite it.
 **/

static int __conn_close(int fd, u32 tid, u64 sid, u32 cid, void *arg)
{
	return ki->conn_destroy(tid, sid, cid);
}

static int __target_del(int fd, u32 tid, void *arg)
{
	return ki->target_destroy(tid);
}

static int proc_session_parse(int fd, struct session_file_operations *ops,
	int op_tid, void *arg)
{
	FILE *f;
	char buf[8192], *p;
	u32 tid, cid;
	u64 sid;
	int err, skip, done = 0;

	if ((f = fopen(PROC_SESSION, "r")) == NULL) {
		fprintf(stderr, "Can't open %s\n", PROC_SESSION);
		return errno;
	}

	skip = 0;
	while (fgets(buf, sizeof(buf), f)) {
		p = buf;
		while (isspace((int) *p))
			p++;

		if (!strncmp(p, "tid:", 4)) {
			if (sscanf(p, "tid:%u", &tid) != 1)
				break;
			if (op_tid != -1) {
				if (tid == op_tid)
					skip = 0;
				else {
					skip = 1;
					if (done)
						break;
					else
						continue;
				}
			}
			if (ops->target_op)
				if ((err = ops->target_op(fd, tid, arg)) < 0)
					goto out;
			continue;
		}
		if (skip)
			continue;
		if (!strncmp(p, "sid:", 4)) {
			if (sscanf(p, "sid:%" SCNu64, &sid) != 1) {
				log_error("Unknown %s sid syntax: %s\n", PROC_SESSION, p);
				break;
			}

			if (ops->session_op)
				if ((err = ops->session_op(fd, tid, sid, arg)) < 0)
					goto out;
		} else if (!strncmp(p, "cid:", 4)) {
			if (sscanf(p, "cid:%u", &cid) != 1) {
				log_error("Unknown %s cid syntax: %s\n", PROC_SESSION, p);
				break;
			}
			if (ops->connection_op)
				if ((err = ops->connection_op(fd, tid, sid, cid, arg)) < 0)
					goto out;
		} else
			log_error("Unknown %s string: %s\n", PROC_SESSION, p);

		done = 1;
	}

	err = 0;
out:
	fclose(f);

	return err;
}

static int session_retry (int fd, u32 tid, u64 sid, void *arg)
{
	return -EAGAIN;
}

static int conn_retry (int fd, u32 tid, u64 sid, u32 cid, void *arg)
{
	return -EAGAIN;
}

static int __sess_cleanup(int fd, u32 tid, void *arg)
{
	wait_4_iscsi_event(100);
	return 0;
}

static struct session_file_operations conn_close_ops = {
	.connection_op = __conn_close,
};

static struct session_file_operations conn_sess_cleanup_ops = {
	.target_op = __sess_cleanup,
};

static struct session_file_operations shutdown_wait_ops = {
	.session_op = session_retry,
	.connection_op = conn_retry,
};

static struct session_file_operations target_del_ops = {
	.target_op = __target_del,
};

int server_stop(void)
{
	conn_blocked = 1;

	proc_session_parse(ctrl_fd, &conn_close_ops, -1, NULL);

	while (proc_session_parse(ctrl_fd, &shutdown_wait_ops, -1, NULL) < 0)
		sleep(1);

	proc_session_parse(ctrl_fd, &target_del_ops, -1, NULL);

	isns_exit();

	return 0;
}

int target_destroy(u32 tid)
{
	int err;

	conn_blocked = 1;

	proc_session_parse(ctrl_fd, &conn_close_ops, tid, NULL);

	while (proc_session_parse(ctrl_fd, &shutdown_wait_ops, tid, NULL) < 0) {
		sleep(1);
	}
	proc_session_parse(ctrl_fd, &conn_sess_cleanup_ops, tid, NULL);

	err = proc_session_parse(ctrl_fd, &target_del_ops, tid, NULL);

	conn_blocked = 0;

	return err;
}

struct session_conn_close_arg {
	u64 sid;
};

static int session_conn_close(int fd, u32 tid, u64 sid, u32 cid, void *opaque)
{
	struct session_conn_close_arg *arg = (struct session_conn_close_arg *) opaque;
	int err;

	if (arg->sid == sid)
		err = ki->conn_destroy(tid, sid, cid);

	return 0;
}

struct session_file_operations session_conns_close_ops = {
	.connection_op = session_conn_close,
};

int session_conns_close(u32 tid, u64 sid)
{
	int err;
	struct session_conn_close_arg arg = {sid};

	err = proc_session_parse(ctrl_fd, &session_conns_close_ops, tid, &arg);

	return err;
}

static int iscsi_param_get(u32 tid, u64 sid, int type, struct iscsi_param *param,
	int local)
{
	int err, i;
	struct iscsi_param_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;
	info.param_type = type;

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_GET, &info)) < 0)
		log_error("Can't get session param %d %d\n", info.tid, errno);

	if (local) {
		if (type == key_session)
			for (i = 0; i < session_key_last; i++)
				param[i].local_val = info.session_param[i];
		else
			for (i = 0; i < target_key_last; i++)
				param[i].local_val = info.target_param[i];
	} else {
		if (type == key_session)
			for (i = 0; i < session_key_last; i++)
				param[i].exec_val = info.session_param[i];
		else
			for (i = 0; i < target_key_last; i++)
				param[i].exec_val = info.target_param[i];
	}

	return err;
}

static int iscsi_param_set(u32 tid, u64 sid, int type, u32 partial,
	struct iscsi_param *param, int local)
{
	int i, err;
	struct iscsi_param_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;
	info.param_type = type;
	info.partial = partial;

	if (local) {
		if (info.param_type == key_session)
			for (i = 0; i < session_key_last; i++)
				info.session_param[i] = param[i].local_val;
		else
			for (i = 0; i < target_key_last; i++)
				info.target_param[i] = param[i].local_val;
	} else {
		if (info.param_type == key_session)
			for (i = 0; i < session_key_last; i++)
				info.session_param[i] = param[i].exec_val;
		else
			for (i = 0; i < target_key_last; i++)
				info.target_param[i] = param[i].exec_val;
	}

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_SET, &info)) < 0)
		fprintf(stderr, "%d %d %u " "%" PRIu64 " %d %u\n",
			err, errno, tid, sid, type, partial);

	return err;
}

static int iscsi_session_create(u32 tid, u64 sid, u32 exp_cmd_sn,
	char *name, char *user)
{
	struct session_info info;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;
	info.exp_cmd_sn = exp_cmd_sn;
	strncpy(info.initiator_name, name, sizeof(info.initiator_name) - 1);
	strncpy(info.user_name, user, sizeof(info.user_name) - 1);

	return ioctl(ctrl_fd, ADD_SESSION, &info);
}

static int iscsi_session_destroy(u32 tid, u64 sid)
{
	struct session_info info;
	int res;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;

	do {
		res = ioctl(ctrl_fd, DEL_SESSION, &info);
	} while (res < 0 && errno == EINTR);

	return res;
}

static int iscsi_conn_create(u32 tid, u64 sid, u32 cid, u32 stat_sn, u32 exp_stat_sn,
			     int fd, u32 hdigest, u32 ddigest)
{
	struct conn_info info;

	memset(&info, 0, sizeof(info));

	info.tid = tid;
	info.sid = sid;
	info.cid = cid;
	info.stat_sn = stat_sn;
	info.exp_stat_sn = exp_stat_sn;
	info.fd = fd;
	info.header_digest = hdigest;
	info.data_digest = ddigest;

	return ioctl(ctrl_fd, ADD_CONN, &info);
}

struct iscsi_kernel_interface ioctl_ki = {
	.ctldev_open = ctrdev_open,
	.param_get = iscsi_param_get,
	.param_set = iscsi_param_set,
	.target_create = iscsi_target_create,
	.target_destroy = iscsi_target_destroy,
	.session_create = iscsi_session_create,
	.session_destroy = iscsi_session_destroy,
	.conn_create = iscsi_conn_create,
	.conn_destroy = iscsi_conn_destroy,
};

struct iscsi_kernel_interface *ki = &ioctl_ki;
