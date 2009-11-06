/*
 *  Event notification code.
 *
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
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
 *
 *  Some functions are based on open-iscsi code
 *  written by Dmitry Yusupov, Alex Aizman.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "iscsid.h"

static struct sockaddr_nl src_addr, dest_addr;

static int nl_write(int fd, void *data, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = data;
	iov[1].iov_len = NLMSG_SPACE(len) - sizeof(nlh);

	nlh.nlmsg_len = NLMSG_SPACE(len);
	nlh.nlmsg_pid = getpid();
	nlh.nlmsg_flags = 0;
	nlh.nlmsg_type = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return sendmsg(fd, &msg, 0);
}

static int nl_read(int fd, void *data, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = data;
	iov[1].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void *)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return recvmsg(fd, &msg, MSG_DONTWAIT);
}

void handle_iscsi_events(int fd)
{
	struct session *session;
	struct connection *conn;
	struct iscsi_kern_event event;
	int rc;

retry:
	if ((rc = nl_read(fd, &event, sizeof(event))) < 0) {
		if (errno == EAGAIN)
			return;
		if (errno == EINTR)
			goto retry;
		log_error("read netlink fd (%d)", errno);
		exit(1);
	}

	log_debug(1, "conn %u session %#" PRIx64 " target %u, code %u",
		  event.cid, event.sid, event.tid, event.code);

	switch (event.code) {
	case E_ENABLE_TARGET:
	{
		struct target *target;
		struct iscsi_kern_target_info info;

		target = target_find_by_id(event.tid);
		if (target == NULL) {
			log_error("Target %d not found", event.tid);
			goto out;
		}

		target->tgt_enabled = 1;

		memset(&info, 0, sizeof(info));

		info.tid = event.tid;
		rc = ioctl(ctrl_fd, ENABLE_TARGET, &info);
		if (rc < 0) {
			log_error("Can't enable target %u: %s\n", event.tid,
				strerror(errno));
			goto out;
		}
		break;
	}

	case E_DISABLE_TARGET:
	{
		struct target *target;
		struct iscsi_kern_target_info info;

		target = target_find_by_id(event.tid);
		if (target == NULL) {
			log_error("Target %d not found", event.tid);
			goto out;
		}

		target->tgt_enabled = 0;

		memset(&info, 0, sizeof(info));

		info.tid = event.tid;
		rc = ioctl(ctrl_fd, DISABLE_TARGET, &info);
		if (rc < 0) {
			log_error("Can't disable target %u: %s\n", event.tid,
				strerror(errno));
			goto out;
		}
		break;
	}

	case E_CONN_CLOSE:
		session = session_find_id(event.tid, event.sid);
		if (session == NULL) {
			log_error("Session %#" PRIx64 " not found", event.sid);
			goto retry;
		}

		conn = conn_find(session, event.cid);
		if (conn == NULL) {
			log_error("Connection %x for session %#" PRIx64 " not "
				"found", event.cid, event.sid);
			goto retry;
		}

		conn_free(conn);

		if (list_empty(&session->conn_list))
			session_free(session);
		break;

	default:
		log_warning("Unknown event %u", event.code);
		exit(-1);
		break;
	}

out:
	return;
}

int nl_open(void)
{
	int nl_fd, res;

	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI_SCST);
	if (nl_fd == -1) {
		log_error("%s %d\n", __FUNCTION__, errno);
		return -1;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0; /* not in mcast groups */

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* kernel */
	dest_addr.nl_groups = 0; /* unicast */

	res = nl_write(nl_fd, NULL, 0);
	if (res < 0) {
		log_error("%s %d\n", __FUNCTION__, res);
		return res;
	}

	return nl_fd;
}
