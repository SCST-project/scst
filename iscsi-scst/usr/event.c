/*
 *  Event notification code.
 *
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
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
#include <ctype.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <arpa/inet.h>

#include <scst_const.h>

#include "iscsid.h"

#define ISCSI_ISNS_SYSFS_ACCESS_CONTROL_ENABLED	"AccessControl"

#define STATIC_ASSERT(e) ((void)sizeof(int[1-2*!(e)]))

static struct sockaddr_nl src_addr, dest_addr;

static int nl_write(int fd, void *data, int len)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh = {0};

	iov[0].iov_base = &nlh;
	iov[0].iov_len = NLMSG_HDRLEN;
	iov[1].iov_base = data;
	iov[1].iov_len = NLMSG_SPACE(len) - NLMSG_HDRLEN;

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

static int nl_read(int fd, void *data, int len, bool wait)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct nlmsghdr nlh;
	int res;

	iov[0].iov_base = &nlh;
	iov[0].iov_len = NLMSG_HDRLEN;
	iov[1].iov_base = data;
	iov[1].iov_len = NLMSG_ALIGN(len);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	res = recvmsg(fd, &msg, wait ? 0 : MSG_DONTWAIT);
	if (res > 0) {
		res -= NLMSG_HDRLEN;
		if (res < 0)
			res = -EPIPE;
		else if (res < iov[1].iov_len)
			log_error("read netlink fd (%d) error: received %d"
				  " bytes but expected %zd bytes (%d)", fd, res,
				  iov[1].iov_len, len);
	}

	return res;
}

#ifndef CONFIG_SCST_PROC

static int strncasecmp_numwild(const char *name, const char *mask)
{
	int err = -EINVAL;

	if (!strncasecmp(name, mask, strlen(name))) {
		int j;
		if (strlen(name) > strlen(mask))
			goto out;
		for (j = strlen(name); j < strlen(mask); j++) {
			if (!isdigit(mask[j]))
				goto out;
		}
		err = 0;
	}

out:
	return err;
}

static int send_mgmt_cmd_res(u32 tid, u32 cookie, u32 req_cmd, int result,
	const char *res_str)
{
	struct iscsi_kern_mgmt_cmd_res_info cinfo;
	int res;

	memset(&cinfo, 0, sizeof(cinfo));
	cinfo.tid = tid;
	cinfo.cookie = cookie;
	cinfo.req_cmd = req_cmd;
	cinfo.result = result;

	if (res_str != NULL)
		strlcpy(cinfo.value, res_str, sizeof(cinfo.value));

	log_debug(1, "Sending result %d (cookie %d)", result, cookie);

	res = ioctl(ctrl_fd, MGMT_CMD_CALLBACK, &cinfo);
	if (res != 0) {
		res = -errno;
		log_error("Can't send mgmt reply (cookie %d, result %d, "
			"res %d): %s\n", cookie, result, res, strerror(errno));
	}

	return res;
}

static int handle_e_add_target(int fd, const struct iscsi_kern_event *event)
{
	int res, rc;
	char *buf;
	int size, offs;

	if (event->param1_size == 0) {
		log_error("Incorrect E_ADD_TARGET: %s", "Target name expected");
		res = -EINVAL;
		goto out;
	}

	/* Params are not 0-terminated */

	size = strlen("Target ") + event->param1_size + 2 + event->param2_size +
		1 + NLMSG_ALIGNTO - 1;

	buf = malloc(size);
	if (buf == NULL) {
		log_error("Unable to allocate tmp buffer (size %d)", size);
		res = -ENOMEM;
		goto out;
	}

	offs = sprintf(buf, "Target ");

	while (1) {
		if ((rc = nl_read(fd, &buf[offs], event->param1_size, true)) < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			log_error("read netlink fd (%d) failed: %s", fd,
				strerror(errno));
			send_mgmt_cmd_res(0, event->cookie, E_ADD_TARGET, -errno, NULL);
			exit(1);
		}
		break;
	}

	offs += min((unsigned)rc, (unsigned)event->param1_size);
	offs += sprintf(&buf[offs], "; ");

	if (event->param2_size > 0) {
		while (1) {
			if ((rc = nl_read(fd, &buf[offs], event->param2_size, true)) < 0) {
				if ((errno == EINTR) || (errno == EAGAIN))
					continue;
				log_error("read netlink fd (%d) failed: %s", fd,
					strerror(errno));
				send_mgmt_cmd_res(0, event->cookie, E_ADD_TARGET, -errno, NULL);
				exit(1);
			}
			break;
		}
		offs += min((unsigned)rc, (unsigned)event->param2_size);
	}

	buf[offs] = '\0';

	log_debug(1, "Going to parse %s", buf);

	res = config_parse_main(buf, event->cookie);
	if (res != 0)
		goto out_free;

out_free:
	free(buf);

out:
	return res;
}

static int handle_e_del_target(int fd, const struct iscsi_kern_event *event)
{
	int res;

	log_debug(2, "Going to delete target %d", event->tid);

	res = target_del(event->tid, event->cookie);
	return res;
}

static int handle_add_user(struct target *target, int dir, char *sysfs_name,
	char *p, u32 cookie)
{
	int res;
	char *name, *pass;

	name = config_sep_string(&p);
	pass = config_sep_string(&p);

	res = __config_account_add(target, dir, name, pass, sysfs_name, 1, cookie);

	return res;
}

static int __handle_add_attr(struct target *target, struct __qelem *attrs_list,
	const char *sysfs_name_tmpl, char *p, int single_param_only, u32 cookie)
{
	int res;
	const char *name = p;
	const char *key, *val;
	struct iscsi_attr *attr;

	key = config_sep_string(&p);
	val = config_sep_string(&p);

	if (target == NULL) {
		log_error("Target expected for attr %s", name);
		res = -EINVAL;
		goto out;
	}

	if ((key == NULL) || (*key == '\0')) {
		log_error("Value expected for attr %s", name);
		res = -EINVAL;
		goto out;
	}

	if (val != NULL)
		if (*val == '\0')
			val = NULL;

	if (single_param_only) {
		if (val != NULL) {
			log_error("Only one value expected for attr %s", key);
			res = -EINVAL;
			goto out;
		}
	}

	res = iscsi_attr_create(sizeof(*attr), attrs_list, sysfs_name_tmpl, key,
			val, 0644, &attr);
	if (res != 0) {
		log_error("Unknown portal %s", key);
		goto out;
	}

	res = kernel_attr_add(target, attr->sysfs_name, attr->sysfs_mode, cookie);
	if (res != 0)
		goto out_free;

out:
	return res;

out_free:
	iscsi_attr_destroy(attr);
	goto out;
}

static int handle_add_attr(struct target *target, char *p, u32 cookie)
{
	int res, dir;
	char *pp;

	pp = config_sep_string(&p);

	dir = params_index_by_name_numwild(pp, user_keys);
	if (dir >= 0)
		res = handle_add_user(target, dir, pp, p, cookie);
	else if (strncasecmp_numwild(ISCSI_ALLOWED_PORTAL_ATTR_NAME, pp) == 0)
		res = __handle_add_attr(target, &target->allowed_portals,
				ISCSI_ALLOWED_PORTAL_ATTR_NAME, p, 1, cookie);
	else {
		log_error("Syntax error at %s", pp);
		res = -EINVAL;
		goto out;
	}

out:
	return res;
}

static int handle_del_user(struct target *target, int dir, char *p, u32 cookie)
{
	int res;
	char *name;

	name = config_sep_string(&p);

	res = config_account_del((target != NULL) ? target->tid : 0, dir,
			name, cookie);

	return res;
}

static int __handle_del_attr(struct target *target, struct __qelem *attrs_list,
	char *p, u32 cookie)
{
	int res;
	const char *key;
	struct iscsi_attr *attr;

	key = config_sep_string(&p);

	if (target == NULL) {
		log_error("Target expected for attr %s", p);
		res = -EINVAL;
		goto out;
	}

	attr = iscsi_attr_lookup_by_key(attrs_list, key);
	if (attr == NULL) {
		log_error("Unknown portal %s", key);
		res = -EINVAL;
		goto out;
	}

	res = kernel_attr_del(target, attr->sysfs_name, cookie);
	if (res != 0)
		goto out;

	iscsi_attr_destroy(attr);

out:
	return res;
}

static int handle_del_attr(struct target *target, char *p, u32 cookie)
{
	int res, dir;
	char *pp;

	pp = config_sep_string(&p);

	dir = params_index_by_name_numwild(pp, user_keys);
	if (dir >= 0)
		res = handle_del_user(target, dir, p, cookie);
	else if (strncasecmp_numwild(ISCSI_ALLOWED_PORTAL_ATTR_NAME, pp) == 0)
		res = __handle_del_attr(target, &target->allowed_portals,
				p, cookie);
	else {
		log_error("Syntax error at %s", pp);
		res = -EINVAL;
		goto out;
	}

out:
	return res;
}

static int handle_e_mgmt_cmd(int fd, const struct iscsi_kern_event *event)
{
	int res, rc;
	char *buf, *p, *pp;
	int size;

	if (event->param1_size == 0) {
		log_error("Incorrect E_MGMT_CMD: %s", "command expected");
		res = -EINVAL;
		goto out;
	}

	/* Params are not 0-terminated */

	size = NLMSG_ALIGN(event->param1_size + 1);

	buf = malloc(size);
	if (buf == NULL) {
		log_error("Unable to allocate tmp buffer (size %d)", size);
		res = -ENOMEM;
		goto out;
	}

	while (1) {
		if ((rc = nl_read(fd, buf, event->param1_size, true)) < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			log_error("read netlink fd (%d) failed: %s", fd,
				strerror(errno));
			send_mgmt_cmd_res(0, event->cookie, E_MGMT_CMD, -errno, NULL);
			exit(1);
		}
		break;
	}

	buf[min((unsigned)rc, (unsigned)event->param1_size)] = '\0';

	log_debug(1, "Going to parse %s", buf);

	p = buf;
	pp = config_sep_string(&p);
	if (strcasecmp("add_attribute", pp) == 0) {
		res = handle_add_attr(NULL, p, event->cookie);
	} else if (strcasecmp("add_target_attribute", pp) == 0) {
		struct target *target;
		pp = config_sep_string(&p);
		target = target_find_by_name(pp);
		if (target == NULL) {
			log_error("Target %s not found", pp);
			res = -ENOENT;
			goto out_free;
		}
		res = handle_add_attr(target, p, event->cookie);
	} else if (strcasecmp("del_attribute", pp) == 0) {
		res = handle_del_attr(NULL, p, event->cookie);
	} else if (strcasecmp("del_target_attribute", pp) == 0) {
		struct target *target;
		pp = config_sep_string(&p);
		target = target_find_by_name(pp);
		if (target == NULL) {
			log_error("Target %s not found", pp);
			res = -ENOENT;
			goto out_free;
		}
		res = handle_del_attr(target, p, event->cookie);
	} else {
		log_error("Syntax error at %s", pp);
		res = -EINVAL;
	}

out_free:
	free(buf);

out:
	return res;
}

static void add_key_mark(char *res_str, int res_str_len, int new_line)
{
	int offs = strlen(res_str);
	snprintf(&res_str[offs], res_str_len - offs, "%s%s\n",
		new_line ? "\n" : "", SCST_SYSFS_KEY_MARK);
	return;
}

static int handle_e_get_attr_value(int fd, const struct iscsi_kern_event *event)
{
	int res = 0, rc, idx;
	char *buf, *p, *pp;
	int size;
	struct target *target;
	char res_str[ISCSI_MAX_ATTR_VALUE_LEN];

	memset(res_str, 0, sizeof(res_str));

	if (event->param1_size == 0) {
		log_error("Incorrect E_GET_ATTR_VALUE: %s", "attr name expected");
		res = -EINVAL;
		goto out;
	}

	/* Params are not 0-terminated */

	size = NLMSG_ALIGN(event->param1_size + 1);

	buf = malloc(size);
	if (buf == NULL) {
		log_error("Unable to allocate tmp buffer (size %d)", size);
		res = -ENOMEM;
		goto out;
	}

	while (1) {
		if ((rc = nl_read(fd, buf, event->param1_size, true)) < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			log_error("read netlink fd (%d) failed: %s", fd,
				strerror(errno));
			send_mgmt_cmd_res(0, event->cookie, E_GET_ATTR_VALUE, -errno, NULL);
			exit(1);
		}
		break;
	}

	buf[min((unsigned)rc, (unsigned)event->param1_size)] = '\0';

	log_debug(1, "Going to parse name %s", buf);

	target = target_find_by_id(event->tid);

	p = buf;
	pp = config_sep_string(&p);
	if (!((idx = params_index_by_name(pp, target_keys)) < 0)) {
		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		params_val_to_str(target_keys, idx, target->target_params[idx],
			res_str, sizeof(res_str));

		if (target->target_params[idx] != target_keys[idx].local_def)
			add_key_mark(res_str, sizeof(res_str), 1);
	} else if (!((idx = params_index_by_name(pp, session_keys)) < 0)) {
		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		params_val_to_str(session_keys, idx, target->session_params[idx],
			res_str, sizeof(res_str));

		if (target->session_params[idx] != session_keys[idx].local_def)
			add_key_mark(res_str, sizeof(res_str), 1);
	} else if (!((idx = params_index_by_name_numwild(pp, user_keys)) < 0)) {
		struct iscsi_attr *user;

		user = account_lookup_by_sysfs_name(target, idx, pp);
		if (user == NULL) {
			log_error("Unknown user attribute %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		snprintf(res_str, sizeof(res_str), "%s %s\n", ISCSI_USER_NAME(user),
			ISCSI_USER_PASS(user));
		add_key_mark(res_str, sizeof(res_str), 0);
	} else if (strncasecmp_numwild(ISCSI_ALLOWED_PORTAL_ATTR_NAME, pp) == 0) {
		struct iscsi_attr *portal;

		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		portal = iscsi_attr_lookup_by_sysfs_name(&target->allowed_portals, pp);
		if (portal == NULL) {
			log_error("Unknown portal attribute %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		snprintf(res_str, sizeof(res_str), "%s\n", portal->attr_key);
		add_key_mark(res_str, sizeof(res_str), 0);
	} else if (strcasecmp(ISCSI_ENABLED_ATTR_NAME, pp) == 0) {
		if (target != NULL) {
			log_error("Not NULL target %s for global attribute %s",
				target->name, pp);
			res = -EINVAL;
			goto out_free;
		}
		snprintf(res_str, sizeof(res_str), "%d\n", iscsi_enabled);
	} else if (strcasecmp(ISCSI_PER_PORTAL_ACL_ATTR_NAME, pp) == 0) {
		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}
		snprintf(res_str, sizeof(res_str), "%d\n", target->per_portal_acl);
		if (target->per_portal_acl)
			add_key_mark(res_str, sizeof(res_str), 0);
	} else if (strcasecmp(ISCSI_TARGET_REDIRECTION_ATTR_NAME, pp) == 0) {
		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}
		if (strlen(target->redirect.addr) != 0) {
			const char *type = (target->redirect.type == ISCSI_STATUS_TGT_MOVED_TEMP) ?
						ISCSI_TARGET_REDIRECTION_VALUE_TEMP :
						ISCSI_TARGET_REDIRECTION_VALUE_PERM;
			if (target->redirect.port != ISCSI_LISTEN_PORT)
				snprintf(res_str, sizeof(res_str), "%s:%d %s\n",
					target->redirect.addr, target->redirect.port, type);
			else
				snprintf(res_str, sizeof(res_str), "%s %s\n",
					target->redirect.addr, type);
			add_key_mark(res_str, sizeof(res_str), 0);
		} else
			*res_str = '\0';
	} else if (strcasecmp(ISCSI_ISNS_SERVER_ATTR_NAME, pp) == 0) {
		if (target != NULL) {
			log_error("Not NULL target %s for global attribute %s",
				target->name, pp);
			res = -EINVAL;
			goto out_free;
		}

		if (isns_server != NULL) {
			snprintf(res_str, sizeof(res_str), "%s %s\n", isns_server,
				isns_access_control ? ISCSI_ISNS_SYSFS_ACCESS_CONTROL_ENABLED : "");
			add_key_mark(res_str, sizeof(res_str), 0);
		} else
			snprintf(res_str, sizeof(res_str), "%s\n", "");
	} else if (strcasecmp(ISCSI_ISNS_ENTITY_ATTR_NAME, pp) == 0)	{
		if (target != NULL) {
			log_error("Not NULL target %s for global attribute %s",
				target->name, pp);
			res = -EINVAL;
			goto out_free;
		}
		snprintf(res_str, sizeof(res_str), "%s", isns_entity_target_name);
	} else	{
		log_error("Unknown attribute %s", pp);
		res = -EINVAL;
		goto out_free;
	}

	send_mgmt_cmd_res(event->tid, event->cookie, E_GET_ATTR_VALUE, 0, res_str);

out_free:
	free(buf);

out:
	return res;
}

static int handle_target_redirect(struct target *target, char *p)
{
	int res = 0;
	char *addr, *type, *t, *port;
	int port_num = ISCSI_LISTEN_PORT;
	int type_num;
	union {
		struct in_addr ia4;
		struct in6_addr ia6;
	} ia;

	addr = config_sep_string(&p);
	if (*addr == '\0') {
		log_info("Target redirection for %s cleared", target->name);
		target->redirect.addr[0] = '\0';
		goto out;
	}

	type = config_sep_string(&p);
	if (*type == '\0') {
		log_error("%s", "Redirection type required");
		res = -EINVAL;
		goto out;
	}

	t = config_sep_string(&p);
	if (*t != '\0') {
		log_error("%s", "Too many arguments for redirection");
		res = -EINVAL;
		goto out;
	}

	t = strrchr(addr, ']');
	if (t != NULL)
		port = strchr(t, ':');
	else
		port = strrchr(addr, ':');
	if (port != NULL) {
		*port = '\0';
		port++;
		port_num = strtol(port, (char **) NULL, 10);
		if ((port_num <= 0) || (errno == EINVAL)) {
			log_error("Invalid port %s", port);
			res = -EINVAL;
			goto out;
		}
	}

	if (strlen(addr) >= sizeof(target->redirect.addr)) {
		log_error("Too long addr %s, max allowed %zd", addr,
			sizeof(target->redirect.addr)-1);
		res = -ERANGE;
		goto out;
	}

	if (inet_pton(AF_INET, addr, &ia) != 1) {
		char tmp[sizeof(target->redirect.addr)];
		if (*addr == '[')
			t = addr+1;
		else
			t = addr;
		strlcpy(tmp, t, strchrnul(t, ']')-t+1);
		if (inet_pton(AF_INET6, tmp, &ia) != 1) {
			log_error("Invalid addr %s", addr);
			res = -EINVAL;
			goto out;
		}
	}

	if (strcasecmp(type, ISCSI_TARGET_REDIRECTION_VALUE_TEMP) == 0) {
		log_debug(1, "Temporary redirection");
		type_num = ISCSI_STATUS_TGT_MOVED_TEMP;
	} else if (strcasecmp(type, ISCSI_TARGET_REDIRECTION_VALUE_PERM) == 0) {
		log_debug(1, "Permament redirection");
		type_num = ISCSI_STATUS_TGT_MOVED_PERM;
	} else {
		log_error("Invalid redirection type %s", type);
		res = -EINVAL;
		goto out;
	}

	log_info("Target %s %s redirected to %s:%d", target->name,
		(type_num == ISCSI_STATUS_TGT_MOVED_TEMP) ? "temporarily" : "permanently",
		addr, port_num);

	strcpy(target->redirect.addr, addr);
	target->redirect.port = port_num;
	target->redirect.type = type_num;

out:
	return res;
}

static int handle_e_set_attr_value(int fd, const struct iscsi_kern_event *event)
{
	int res = 0, rc, idx;
	char *buf, *p, *pp, *n;
	struct target *target;
	int size, offs;
	u32 val;

	if (event->param1_size == 0) {
		log_error("Incorrect E_SET_ATTR_VALUE: %s", "attr name expected");
		res = -EINVAL;
		goto out;
	}

	if (event->param2_size == 0) {
		log_error("Incorrect E_SET_ATTR_VALUE: %s", "attr value expected");
		res = -EINVAL;
		goto out;
	}

	/* Params are not 0-terminated */
	size = event->param1_size + 1 + 1 + event->param2_size + 1 +
		NLMSG_ALIGNTO - 1;

	buf = malloc(size);
	if (buf == NULL) {
		log_error("Unable to allocate tmp buffer (size %d)", size);
		res = -ENOMEM;
		goto out;
	}

	while (1) {
		if ((rc = nl_read(fd, buf, event->param1_size, true)) < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			log_error("read netlink fd (%d) failed: %s", fd,
				strerror(errno));
			send_mgmt_cmd_res(0, event->cookie, E_SET_ATTR_VALUE, -errno, NULL);
			exit(1);
		}
		break;
	}

	offs = min((unsigned)rc, (unsigned)event->param1_size);
	offs += sprintf(&buf[offs], " ");

	while (1) {
		if ((rc = nl_read(fd, &buf[offs], event->param2_size, true)) < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			log_error("read netlink fd (%d) failed: %s", fd,
				strerror(errno));
			send_mgmt_cmd_res(0, event->cookie, E_SET_ATTR_VALUE, -errno, NULL);
			exit(1);
		}
		break;
	}

	offs += min((unsigned)rc, (unsigned)event->param2_size);
	buf[offs] = '\0';

	log_debug(1, "Going to parse %s", buf);

	target = target_find_by_id(event->tid);

	p = buf;
	pp = config_sep_string(&p);
	if (!((idx = params_index_by_name(pp, target_keys)) < 0)) {
		struct iscsi_param params[target_key_last];
		struct session *session;

		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		pp = config_sep_string(&p);

		n = config_sep_string(&p);
		if (*n != '\0') {
			log_error("Unexpected parameter value %s\n", n);
			res = -EINVAL;
			goto out_free;
		}

		res = params_str_to_val(target_keys, idx, pp, &val);
		if (res < 0) {
			log_error("Wrong value %s for parameter %s\n",
				pp, target_keys[idx].name);
			goto out_free;
		}

		res = params_check_val(target_keys, idx, &val);
		if (res < 0) {
			log_error("Wrong value %u for parameter %s\n",
				val, target_keys[idx].name);
			goto out_free;
		}

		target->target_params[idx] = val;

		memset(&params, 0, sizeof(params));
		params[idx].val = val;
		list_for_each_entry(session, &target->sessions_list, slist) {
			kernel_params_set(event->tid, session->sid.id64,
				key_target, 1 << idx, params);
		}
	} else if (!((idx = params_index_by_name(pp, session_keys)) < 0)) {
		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		pp = config_sep_string(&p);

		n = config_sep_string(&p);
		if (*n != '\0') {
			log_error("Unexpected parameter value %s\n", n);
			res = -EINVAL;
			goto out_free;
		}

		res = params_str_to_val(session_keys, idx, pp, &val);
		if (res < 0) {
			log_error("Wrong value %s for parameter %s\n",
				pp, session_keys[idx].name);
			goto out_free;
		}

		res = params_check_val(session_keys, idx, &val);
		if (res < 0) {
			log_error("Wrong value %u for parameter %s\n",
				val, session_keys[idx].name);
			goto out_free;
		}

		target->session_params[idx] = val;
	} else if (!((idx = params_index_by_name_numwild(pp, user_keys)) < 0)) {
		struct iscsi_attr *user;

		user = account_lookup_by_sysfs_name(target, idx, pp);
		if (user == NULL) {
			log_error("Unknown user attribute %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		res = account_replace(target, idx, pp, p);
		if (res != 0)
			goto out_free;
	} else if (strncasecmp_numwild(ISCSI_ALLOWED_PORTAL_ATTR_NAME, pp) == 0) {
		struct iscsi_attr *portal;

		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		portal = iscsi_attr_lookup_by_sysfs_name(&target->allowed_portals, pp);
		if (portal == NULL) {
			log_error("Unknown portal attribute %s", pp);
			res = -EINVAL;
			goto out_free;
		}

		res = iscsi_attr_replace(&target->allowed_portals, pp, p);
		if (res != 0)
			goto out_free;
	} else if (strcasecmp(ISCSI_ENABLED_ATTR_NAME, pp) == 0) {
		if (target != NULL) {
			log_error("Not NULL target %s for global attribute %s",
				target->name, pp);
			res = -EINVAL;
			goto out_free;
		}
		pp = config_sep_string(&p);
		if (strcmp(pp, "1") == 0)
			iscsi_enabled = 1;
		else if (strcmp(pp, "0") == 0)
			iscsi_enabled = 0;
		else {
			log_error("Unknown value %s", pp);
			res = -EINVAL;
			goto out_free;
		}
	} else if (strcasecmp(ISCSI_PER_PORTAL_ACL_ATTR_NAME, pp) == 0) {
		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}
		pp = config_sep_string(&p);
		if (strcmp(pp, "1") == 0)
			target->per_portal_acl = 1;
		else if (strcmp(pp, "0") == 0)
			target->per_portal_acl = 0;
		else {
			log_error("Unknown value %s", pp);
			res = -EINVAL;
			goto out_free;
		}
	} else if (strcasecmp(ISCSI_TARGET_REDIRECTION_ATTR_NAME, pp) == 0) {
		if (target == NULL) {
			log_error("Target expected for attr %s", pp);
			res = -EINVAL;
			goto out_free;
		}
		res = handle_target_redirect(target, p);
		if (res != 0)
			goto out_free;
	} else if (strcasecmp(ISCSI_ISNS_SERVER_ATTR_NAME, pp) == 0) {
		if (target != NULL) {
			log_error("Not NULL target %s for global attribute %s",
				target->name, pp);
			res = -EINVAL;
			goto out_free;
		}

		if (isns_server != NULL)
			isns_exit();

		pp = config_sep_string(&p);
		if (*pp == '\0') {
			goto done;
		}

		isns_access_control = 0;
		isns_server = strdup(pp);
		if (isns_server == NULL) {
			log_error("Unable to duplicate iSNS server name %s", pp);
			res = -ENOMEM;
			goto out_free;
		}

		pp = config_sep_string(&p);
		if (strcasecmp(ISCSI_ISNS_SYSFS_ACCESS_CONTROL_ENABLED, pp) == 0) {
			pp = config_sep_string(&p);
			if (strcasecmp(pp, "No") == 0)
				isns_access_control = 0;
			else
				isns_access_control = 1;
		} else if (*pp != '\0') {
			log_error("Unknown parameter %s", pp);
			res = -EINVAL;
			goto out_free_server;
		}

		res = isns_init();
		if (res == 0) {
			struct target *t;
			int rc;

			list_for_each_entry(t, &targets_list, tlist) {
				if (!t->tgt_enabled)
					continue;
				rc = isns_target_register(t->name);
				if (rc < 0) {
					/*
					 * iSNS server can be temporary not
					 * available.
					 */
					goto out_free_isns_exit;
				}
			}
		} else
			goto out_free_server;
	} else if (strcasecmp(ISCSI_ISNS_ENTITY_ATTR_NAME, pp) == 0) {
		pp = config_sep_string(&p);
		strlcpy(isns_entity_target_name, pp, sizeof(isns_entity_target_name));
	} else	{
		log_error("Unknown attribute %s", pp);
		res = -EINVAL;
		goto out_free;
	}

done:
	send_mgmt_cmd_res(event->tid, event->cookie, E_SET_ATTR_VALUE, 0, NULL);

out_free:
	free(buf);

out:
	return res;

out_free_isns_exit:
	isns_exit();

out_free_server:
	free(isns_server);
	isns_server = NULL;
	goto out;
}

#endif /* CONFIG_SCST_PROC */

int handle_iscsi_events(int fd, bool wait)
{
	struct session *session;
	struct connection *conn;
	struct iscsi_kern_event event;
#ifndef CONFIG_SCST_PROC
	struct target *target;
#endif
	int rc;

	/*
	 * The way of handling errors by exit() is one of the worst possible,
	 * but IET developers thought it's OK. ToDo: fix somewhen.
	 */

	STATIC_ASSERT(sizeof(event) % NLMSG_ALIGNTO == 0);

retry:
	if ((rc = nl_read(fd, &event, sizeof(event), wait)) < 0) {
		if (errno == EAGAIN)
			return EAGAIN;
		if (errno == EINTR)
			goto retry;
		log_error("read netlink fd (%d) failed: %s", fd, strerror(errno));
		exit(1);
	}

	log_debug(1, "target %u, session %#" PRIx64 ", conn %u, code %u, cookie %d",
		  event.tid, event.sid, event.cid, event.code, event.cookie);

	/*
	 * Let's always report errors through send_mgmt_cmd_res(). If the error
	 * was returned by the corresponding ioctl(), it will lead to blank
	 * MGMT_CMD_CALLBACK ioctl()'s, but that's OK, because kernel will
	 * not reuse the cookie. Better to have extra return call, than no call
	 * at all.
	 */

	switch (event.code) {
#ifndef CONFIG_SCST_PROC
	case E_ADD_TARGET:
		rc = handle_e_add_target(fd, &event);
		if (rc != 0)
			send_mgmt_cmd_res(event.tid, event.cookie, E_ADD_TARGET, rc, NULL);
		break;

	case E_DEL_TARGET:
		rc = handle_e_del_target(fd, &event);
		if (rc != 0)
			send_mgmt_cmd_res(event.tid, event.cookie, E_DEL_TARGET, rc, NULL);
		break;

	case E_MGMT_CMD:
		rc = handle_e_mgmt_cmd(fd, &event);
		if (rc != 0)
			send_mgmt_cmd_res(event.tid, event.cookie, E_MGMT_CMD, rc, NULL);
		break;

	case E_ENABLE_TARGET:
		target = target_find_by_id(event.tid);
		if (target == NULL) {
			log_error("Target %d not found", event.tid);
			rc = -ENOENT;
		} else
			rc = 0;
		rc |= send_mgmt_cmd_res(event.tid, event.cookie, E_ENABLE_TARGET, rc, NULL);
		if (rc == 0) {
			target->tgt_enabled = 1;
			isns_target_register(target->name);
		}
		break;

	case E_DISABLE_TARGET:
		target = target_find_by_id(event.tid);
		if (target == NULL) {
			log_error("Target %d not found", event.tid);
			rc = -ENOENT;
		} else
			rc = 0;
		rc |= send_mgmt_cmd_res(event.tid, event.cookie, E_DISABLE_TARGET, rc, NULL);
		if (rc == 0) {
			target->tgt_enabled = 0;
			isns_target_deregister(target->name);
		}
		break;

	case E_GET_ATTR_VALUE:
		rc = handle_e_get_attr_value(fd, &event);
		if (rc != 0)
			send_mgmt_cmd_res(event.tid, event.cookie, E_GET_ATTR_VALUE, rc, NULL);
		break;

	case E_SET_ATTR_VALUE:
		rc = handle_e_set_attr_value(fd, &event);
		if (rc != 0)
			send_mgmt_cmd_res(event.tid, event.cookie, E_SET_ATTR_VALUE, rc, NULL);
		break;
#endif /* CONFIG_SCST_PROC */

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
		log_error("Unknown event %u", event.code);
		/* We might be out of sync in size */
		exit(-1);
		break;
	}

	return 0;
}

int nl_open(void)
{
	int nl_fd, res;

	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI_SCST);
	if (nl_fd == -1) {
		log_error("%s %s\n", __FUNCTION__, strerror(errno));
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
