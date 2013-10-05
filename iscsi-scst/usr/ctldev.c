/*
 *  Copyright (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "iscsid.h"

#define CTL_DEVICE	"/dev/iscsi-scst-ctl"

int kernel_open(void)
{
	FILE *f;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd = -1;
	int err;
	struct iscsi_kern_register_info reg;

	if (!(f = fopen("/proc/devices", "r"))) {
		err = -errno;
		perror("Cannot open control path to the driver");
		goto out_err;
	}

	devn = 0;
	while (!feof(f)) {
		if (!fgets(buf, sizeof(buf), f)) {
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
		printf("cannot create %s %s\n", CTL_DEVICE, strerror(errno));
		goto out_err;
	}

	ctlfd = open(CTL_DEVICE, O_RDWR);
	if (ctlfd < 0) {
		err = -errno;
		printf("cannot open %s %s\n", CTL_DEVICE, strerror(errno));
		goto out_err;
	}

	memset(&reg, 0, sizeof(reg));
	reg.version = (uintptr_t)ISCSI_SCST_INTERFACE_VERSION;

	err = ioctl(ctlfd, REGISTER_USERD, &reg);
	if (err != 0) {
		err = -errno;
		log_error("Unable to register: %s. Incompatible version of the "
			"kernel module?\n", strerror(errno));
		goto out_close;
	} else {
		log_debug(0, "max_data_seg_len %d, max_queued_cmds %d",
			reg.max_data_seg_len, reg.max_queued_cmds);
		iscsi_init_params.max_data_seg_len = reg.max_data_seg_len;
		iscsi_init_params.max_queued_cmds = reg.max_queued_cmds;
	}

out:
	return ctlfd;

out_close:
	close(ctlfd);

out_err:
	ctlfd = err;
	goto out;
}

int kernel_target_create(struct target *target, u32 *tid, u32 cookie)
{
	int err, i, j;
	struct iscsi_kern_target_info info;
	struct iscsi_attr *user;
	struct iscsi_attr *portal;
	struct iscsi_kern_attr *kern_attrs;

	memset(&info, 0, sizeof(info));
	strlcpy(info.name, target->name, sizeof(info.name));
	info.tid = (tid != NULL) ? *tid : 0;
	info.cookie = cookie;

	info.attrs_num = 2;

	for (j = 0; j < session_key_last; j++) {
		if (session_keys[j].show_in_sysfs)
			info.attrs_num++;
	}
	for (j = 0; j < target_key_last; j++) {
		if (target_keys[j].show_in_sysfs)
			info.attrs_num++;
	}
	list_for_each_entry(user, &target->target_in_accounts, ulist) {
		info.attrs_num++;
	}
	list_for_each_entry(user, &target->target_out_accounts, ulist) {
		info.attrs_num++;
	}
	list_for_each_entry(portal, &target->allowed_portals, ulist) {
		info.attrs_num++;
	}

	kern_attrs = calloc(info.attrs_num, sizeof(*kern_attrs));
	if (kern_attrs == NULL) {
		err = -ENOMEM;
		goto out;
	}
	info.attrs_ptr = (unsigned long)kern_attrs;

	i = 0;

	kern_attrs[i].mode = 0644;
	strlcpy(kern_attrs[i].name, ISCSI_PER_PORTAL_ACL_ATTR_NAME,
		sizeof(ISCSI_PER_PORTAL_ACL_ATTR_NAME));
	i++;

	kern_attrs[i].mode = 0644;
	strlcpy(kern_attrs[i].name, ISCSI_TARGET_REDIRECTION_ATTR_NAME,
		sizeof(ISCSI_TARGET_REDIRECTION_ATTR_NAME));
	i++;

	for (j = 0; j < session_key_last; j++) {
		if (!session_keys[j].show_in_sysfs)
			continue;
		kern_attrs[i].mode = 0644;
		strlcpy(kern_attrs[i].name, session_keys[j].name,
			sizeof(kern_attrs[i].name));
		i++;
	}
	for (j = 0; j < target_key_last; j++) {
		if (!target_keys[j].show_in_sysfs)
			continue;
		kern_attrs[i].mode = 0644;
		strlcpy(kern_attrs[i].name, target_keys[j].name,
			sizeof(kern_attrs[i].name));
		i++;
	}
	list_for_each_entry(user, &target->target_in_accounts, ulist) {
		kern_attrs[i].mode = user->sysfs_mode;
		strlcpy(kern_attrs[i].name, user->sysfs_name,
			sizeof(kern_attrs[i].name));
		i++;
	}
	list_for_each_entry(user, &target->target_out_accounts, ulist) {
		kern_attrs[i].mode = user->sysfs_mode;
		strlcpy(kern_attrs[i].name, user->sysfs_name,
			sizeof(kern_attrs[i].name));
		i++;
	}
	list_for_each_entry(portal, &target->allowed_portals, ulist) {
		kern_attrs[i].mode = portal->sysfs_mode;
		strlcpy(kern_attrs[i].name, portal->sysfs_name,
			sizeof(kern_attrs[i].name));
		i++;
	}

	log_debug(1, "Adding target %s (attrs_num %d)", target->name,
		info.attrs_num);

	if ((err = ioctl(ctrl_fd, ADD_TARGET, &info)) < 0) {
		err = -errno;
		log_error("Can't create target %s: %s\n", target->name,
			strerror(errno));
	} else {
		target->tid = err;
		if (tid != NULL)
			*tid = err;
		err = 0;
	}

	free(kern_attrs);

out:
	return err;
}

int kernel_target_destroy(u32 tid, u32 cookie)
{
	struct iscsi_kern_target_info info;
	int res;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.cookie = cookie;

	res = ioctl(ctrl_fd, DEL_TARGET, &info);
	if (res < 0) {
		res = -errno;
		log_error("Can't destroy target %s %u\n", strerror(errno), tid);
	}

	return res;
}

#ifndef CONFIG_SCST_PROC

int kernel_attr_add(struct target *target, const char *name, u32 mode,
	u32 cookie)
{
	struct iscsi_kern_attr_info info;
	int res;

	memset(&info, 0, sizeof(info));
	if (target != NULL)
		info.tid = target->tid;
	info.cookie = cookie;

	info.attr.mode = mode;
	strlcpy(info.attr.name, name, sizeof(info.attr.name));

	res = ioctl(ctrl_fd, ISCSI_ATTR_ADD, &info);
	if (res < 0)
		res = -errno;

	return res;
}

int kernel_attr_del(struct target *target, const char *name, u32 cookie)
{
	struct iscsi_kern_attr_info info;
	int res;

	memset(&info, 0, sizeof(info));
	if (target != NULL)
		info.tid = target->tid;
	info.cookie = cookie;

	strlcpy(info.attr.name, name, sizeof(info.attr.name));

	res = ioctl(ctrl_fd, ISCSI_ATTR_DEL, &info);
	if (res < 0)
		res = -errno;

	return res;
}

int kernel_user_add(struct target *target, struct iscsi_attr *user, u32 cookie)
{
	return kernel_attr_add(target, user->sysfs_name, 0600, cookie);
}

int kernel_user_del(struct target *target, struct iscsi_attr *user, u32 cookie)
{
	return kernel_attr_del(target, user->sysfs_name, cookie);
}

#endif /* CONFIG_SCST_PROC */

int kernel_initiator_allowed(u32 tid, const char *full_initiator_name)
{
	int err;
	struct iscsi_kern_initiator_info info;

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	strlcpy(info.full_initiator_name, full_initiator_name, sizeof(info.full_initiator_name));

	if ((err = ioctl(ctrl_fd, ISCSI_INITIATOR_ALLOWED, &info)) < 0) {
		err = -errno;
		log_error("Can't find out initiator %s permissions (%s, "
			  "tid %u", full_initiator_name, strerror(errno), tid);
	}

	return err;
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
		log_debug(2, "Can't destroy conn (%s, tid %u, sid 0x%"
			  PRIx64 ", cid %u\n", strerror(errno), tid, sid, cid);
	}

	return err;
}

int kernel_params_get(u32 tid, u64 sid, int type, struct iscsi_param *params)
{
	int err, i;
	struct iscsi_kern_params_info info;

	if (sid == 0) {
		log_error("kernel_params_get(): sid must be not %d", 0);
		err = -EINVAL;
		goto out;
	}

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;
	info.params_type = type;

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_GET, &info)) < 0) {
		err = -errno;
		log_debug(1, "Can't get session params for session 0x%" PRIx64 
			" (tid %u, err %d): %s\n", sid, tid, err, strerror(errno));
	}

	if (type == key_session)
		for (i = 0; i < session_key_last; i++)
			params[i].val = info.session_params[i];
	else
		for (i = 0; i < target_key_last; i++)
			params[i].val = info.target_params[i];

out:
	return err;
}

int kernel_params_set(u32 tid, u64 sid, int type, u32 partial,
	const struct iscsi_param *params)
{
	int i, err;
	struct iscsi_kern_params_info info;

	if (sid == 0) {
		log_error("kernel_params_set(): sid must be not %d", 0);
		err = -EINVAL;
		goto out;
	}

	memset(&info, 0, sizeof(info));
	info.tid = tid;
	info.sid = sid;
	info.params_type = type;
	info.partial = partial;

	if (info.params_type == key_session)
		for (i = 0; i < session_key_last; i++)
			info.session_params[i] = params[i].val;
	else
		for (i = 0; i < target_key_last; i++)
			info.target_params[i] = params[i].val;

	if ((err = ioctl(ctrl_fd, ISCSI_PARAM_SET, &info)) < 0) {
		err = -errno;
		log_error("Can't set session params for session 0x%" PRIx64 
			" (tid %u, type %d, partial %d, err %d): %s\n", sid,
			tid, type, partial, err, strerror(errno));
	}

out:
	return err;
}

int kernel_session_create(struct connection *conn)
{
	struct iscsi_kern_session_info info;
	int res, i;
	struct target *target;

	target = target_find_by_id(conn->tid);
	if (target == NULL) {
		log_error("Target %d not found", conn->tid);
		res = -EINVAL;
		goto out;
	}

	memset(&info, 0, sizeof(info));

	info.tid = conn->tid;
	info.sid = conn->sess->sid.id64;
	info.exp_cmd_sn = conn->exp_cmd_sn;
	strlcpy(info.initiator_name, conn->sess->initiator, sizeof(info.initiator_name));

#ifdef CONFIG_SCST_PROC
	if (conn->user != NULL)
		strlcpy(info.user_name, conn->user, sizeof(info.user_name));
	else
		info.user_name[0] = '\0';
#endif

	iscsi_make_full_initiator_name(target->per_portal_acl,
		conn->sess->initiator, conn->target_portal,
		info.full_initiator_name, sizeof(info.full_initiator_name));

	for (i = 0; i < session_key_last; i++)
		info.session_params[i] = conn->session_params[i].val;

	for (i = 0; i < target_key_last; i++)
		info.target_params[i] = target->target_params[i];

	res = ioctl(ctrl_fd, ADD_SESSION, &info);
	if (res < 0) {
		res = -errno;
		log_error("Can't create sess 0x%" PRIx64 " (tid %d, "
			"initiator %s): %s\n", conn->sess->sid.id64, conn->tid,
			conn->sess->initiator, strerror(errno));
	}

out:
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
		log_debug(2, "Can't destroy sess 0x%" PRIx64 " (tid %d): %s\n",
			sid, tid, strerror(errno));
	}

	return res;
}

int kernel_conn_create(u32 tid, u64 sid, u32 cid, u32 stat_sn, u32 exp_stat_sn,
	int fd)
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

	res = ioctl(ctrl_fd, ADD_CONN, &info);
	if (res < 0) {
		res = -errno;
		log_error("Can't create conn %x (sess 0x%" PRIx64 ", tid %d): %s\n",
			cid, sid, tid, strerror(errno));
	}

	return res;
}
