/*
 *  iscsi_adm - manage iSCSI-SCST Target software.
 *
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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iscsid.h"
#include "iscsi_adm.h"

#define	SET_TARGET	(1 << 0)
#define	SET_SESSION	(1 << 1)
#define	SET_CONNECTION	(1 << 2)
#define	SET_USER	(1 << 4)

typedef int (user_handle_fn_t)(struct iscsi_adm_req *req, char *user, char *pass);

enum iscsi_adm_op {
	OP_NEW,
	OP_DELETE,
	OP_UPDATE,
	OP_SHOW,
};

static char program_name[] = "iscsi-scst-adm";

static struct option const long_options[] =
{
	{"op", required_argument, NULL, 'o'},
	{"tid", required_argument, NULL, 't'},
	{"sid", required_argument, NULL, 's'},
	{"cid", required_argument, NULL, 'c'},
	{"params", required_argument, NULL, 'p'},
	{"user", no_argument, NULL, 'u'},
	{"version", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI-SCST Target Administration Utility.\n\
\n\
  --op new --tid=[id] --params Name=[name]\n\
                        add a new target with [id]. [id] must not be zero.\n\
  --op delete --tid=[id]\n\
                        delete specific target with [id]. The target must\n\
                        have no active sessions.\n\
  --op show --tid=[id]\n\
                        show target parameters of target with [id].\n\
  --op show --tid=[id] --sid=[sid]\n\
                        show iSCSI parameters in effect for session [sid]. If\n\
                        [sid] is \"0\" (zero), the configured parameters\n\
                        will be displayed.\n\
  --op show --tid=[id] --user\n\
                        show list of Discovery (--tid omitted / id=0 (zero))\n\
                        or target CHAP accounts.\n\
  --op show --tid=[id] --user --params=[user]=[name]\n\
                        show CHAP account information. [user] can be\n\
                        \"IncomingUser\" or \"OutgoingUser\". If --tid is\n\
                        omitted / id=0 (zero), [user] is treated as Discovery\n\
                        user.\n\
  --op delete --tid=[id] --sid=[sid] --cid=[cid]\n\
                        delete specific connection with [cid] in a session\n\
                        with [sid] that the target with [id] has.\n\
                        If the session has no connections after\n\
                        the operation, the session will be deleted\n\
                        automatically.\n\
  --op update --tid=[id] --params=key1=value1,key2=value2,...\n\
                        change iSCSI target parameters of specific\n\
                        target with [id]. You can use parameters in iscsi-scstd.conf\n\
                        as a key.\n\
  --op new --tid=[id] --user --params=[user]=[name],Password=[pass]\n\
                        add a new account with [pass] for specific target.\n\
                        [user] could be [IncomingUser] or [OutgoingUser].\n\
                        If you don't specify a target (omit --tid option),\n\
                        you add a new account for discovery sessions.\n\
  --op delete --tid=[id] --user --params=[user]=[name]\n\
                        delete specific account having [name] of specific\n\
                        target. [user] could be [IncomingUser] or\n\
                        [OutgoingUser].\n\
                        If you don't specify a target (omit --tid option),\n\
                        you delete the account for discovery sessions.\n\
  --version             display version and exit\n\
  --help                display this help and exit\n\
\n\
Report bugs to <scst-devel@lists.sourceforge.net>.\n");
	}
	exit(status == 0 ? 0 : -1);
}

static int str_to_op(char *str)
{
	int op;

	if (!strcmp("new", str))
		op = OP_NEW;
	else if (!strcmp("delete", str))
		op = OP_DELETE;
	else if (!strcmp("update", str))
		op = OP_UPDATE;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else
		op = -1;

	return op;
}

static int iscsid_request_send(int fd, struct iscsi_adm_req *req)
{
	int err, ret;

	do {
		ret = write(fd, req, sizeof(*req));
	} while (ret < 0 && errno == EINTR);

	if (ret != sizeof(*req)) {
		err = (ret < 0) ? -errno : -EIO;
		fprintf(stderr, "%s failed: written %d, to write %d, "
			"error: %s\n", __func__, ret, err, strerror(err));
	} else
		err = 0;

	return err;
}

static int iscsid_response_recv(int fd, struct iscsi_adm_req *req, void *rsp_data,
			      int rsp_data_sz)
{
	int err, ret;
	struct iovec iov[2];
	struct iscsi_adm_rsp rsp;

	iov[0].iov_base = req;
	iov[0].iov_len = sizeof(*req);
	iov[1].iov_base = &rsp;
	iov[1].iov_len = sizeof(rsp);

	do {
		ret = readv(fd, iov, 2);
	} while (ret < 0 && errno == EINTR);

	if (ret != sizeof(rsp) + sizeof(*req)) {
		err = (ret < 0) ? -errno : -EIO;
		fprintf(stderr, "readv failed: read %d instead of %d (%s)\n",
			 ret, (int)(sizeof(rsp) + sizeof(*req)), strerror(err));
	} else
		err = rsp.err;

	if (!err && rsp_data_sz && rsp_data) {
		ret = read(fd, rsp_data, rsp_data_sz);
		if (ret != rsp_data_sz) {
			err = (ret < 0) ? -errno : -EIO;
			fprintf(stderr, "read failed: read %d instead of %d (%s)\n",
				 ret, (int)rsp_data_sz, strerror(err));
		}
	}

	return err;
}

static int iscsid_connect(void)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket() failed");
		fd = -errno;
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSI_ADM_NAMESPACE, strlen(ISCSI_ADM_NAMESPACE));

	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		fd = -errno;
		fprintf(stderr, "Unable to connect to iscsid: %s\n",
			strerror(-fd));
		goto out;
	}

out:
	return fd;
}

static int iscsid_request(struct iscsi_adm_req *req, void *rsp_data,
			int rsp_data_sz)
{
	int fd = -1, err = -EIO;

	if ((fd = iscsid_connect()) < 0) {
		err = fd;
		goto out_close;
	}

	if ((err = iscsid_request_send(fd, req)) < 0)
		goto out_report;

	err = iscsid_response_recv(fd, req, rsp_data, rsp_data_sz);

out_report:
	if (err < 0) {
		if (err == -ENOENT)
			err = -EINVAL;
		fprintf(stderr, "Request to iscsid failed: %s\n", strerror(-err));
	}

out_close:
	if (fd > 0)
		close(fd);

	return err;
}

static void show_iscsi_params(int type, struct iscsi_param *param)
{
	int i, nr, len;
	char buf[1024], *p;
	struct iscsi_key *keys;

	if (type == key_session) {
		nr = session_key_last;
		keys = session_keys;
	} else {
		nr = target_key_last;
		keys = target_keys;
	}

	for (i = 0; i < nr; i++) {
		memset(buf, 0, sizeof(buf));
		strlcpy(buf, keys[i].name, sizeof(buf));
		len = strlen(buf);
		p = buf + len;
		*p++ = '=';
		params_val_to_str(keys, i, param[i].val, p, sizeof(buf) - (len + 1));
		printf("%s\n", buf);
	}
}

static int parse_trgt_params(struct msg_trgt *msg, char *params)
{
	char *p, *q;

	while ((p = strsep(&params, ",")) != NULL) {
		int idx;
		u32 val;
		if (!*p)
			continue;
		if (!(q = strchr(p, '=')))
			continue;
		*q++ = '\0';

		if (!((idx = params_index_by_name(p, target_keys)) < 0)) {
			if (params_str_to_val(target_keys, idx, q, &val)) {
				fprintf(stderr,
					"Invalid %s value \"%s\".\n",
					target_keys[idx].name, q);
				return -EINVAL;
			}
			if (!params_check_val(target_keys, idx, &val))
				msg->target_partial |= (1 << idx);
			msg->target_params[idx].val = val;
			msg->type |= 1 << key_target;

			continue;
		}

		if (!((idx = params_index_by_name(p, session_keys)) < 0)) {
			if (params_str_to_val(session_keys, idx, q, &val)) {
				fprintf(stderr,
					"Invalid %s value \"%s\".\n",
					session_keys[idx].name, q);
				return -EINVAL;
			}
			if (!params_check_val(session_keys, idx, &val))
				msg->session_partial |= (1 << idx);
			msg->session_params[idx].val = val;
			msg->type |= 1 << key_session;

			continue;
		}
		fprintf(stderr, "Unknown parameter \"%s\".\n", p);
		return -EINVAL;
	}

	return 0;
}

static int trgt_handle(int op, u32 set, u32 tid, char *params)
{
	int err = -EINVAL;
	struct iscsi_adm_req req;

	if (!(set & SET_TARGET))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;

	switch (op) {
	case OP_NEW:
	{
		char *p = params;

		if (!params || !(p = strchr(params, '='))) {
			fprintf(stderr, "Target name required\n");
			err = -EINVAL;
			goto out;
		}
		*p++ = '\0';
		if (strcmp(params, "Name")) {
			fprintf(stderr, "Target name required\n");
			err = -EINVAL;
			goto out;
		}
		req.rcmnd = C_TRGT_NEW;
		strlcpy(req.u.trgt.name, p, sizeof(req.u.trgt.name));
		break;
	}
	case OP_DELETE:
		req.rcmnd = C_TRGT_DEL;
		break;
	case OP_UPDATE:
		req.rcmnd = C_TRGT_UPDATE;
		if ((err = parse_trgt_params(&req.u.trgt, params)) < 0)
			goto out;
		break;
	case OP_SHOW:
		req.rcmnd = C_TRGT_SHOW;
		break;
	}

	err = iscsid_request(&req, NULL, 0);
	if (!err && req.rcmnd == C_TRGT_SHOW)
		show_iscsi_params(key_target, req.u.trgt.target_params);

out:
	return err;
}

static int sess_handle(int op, u32 set, u32 tid, u64 sid, char *params)
{
	int err = -EINVAL;
	struct iscsi_adm_req req;

	if (op == OP_NEW || op == OP_UPDATE) {
		fprintf(stderr, "Unsupported.\n");
		goto out;
	}

	if (!((set & SET_TARGET) && (set & SET_SESSION)))
		goto out;

	req.tid = tid;
	req.sid = sid;
	req.u.trgt.type = key_session;

	switch (op) {
	case OP_DELETE:
		/* close all connections */
		break;
	case OP_SHOW:
		req.rcmnd = C_SESS_SHOW;
		err = iscsid_request(&req, NULL, 0);
		if (!err)
			show_iscsi_params(key_session, req.u.trgt.session_params);
		break;
	}

out:
	return err;
}

static int parse_user_params(char *params, u32 *auth_dir, char **user,
			     char **pass)
{
	char *p, *q;

	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;

		if (!(q = strchr(p, '=')))
			continue;
		*q++ = '\0';
		if (isspace(*q))
			q++;

		if (!strcasecmp(p, "IncomingUser")) {
			if (*user)
				fprintf(stderr,
					"Already specified IncomingUser %s\n",
					q);
			*user = q;
			*auth_dir = ISCSI_USER_DIR_INCOMING;
		} else if (!strcasecmp(p, "OutgoingUser")) {
			if (*user)
				fprintf(stderr,
					"Already specified OutgoingUser %s\n",
					q);
			*user = q;
			*auth_dir = ISCSI_USER_DIR_OUTGOING;
		} else if (!strcasecmp(p, "Password")) {
			if (*pass)
				fprintf(stderr,
					"Already specified Password %s\n", q);
			*pass = q;
		} else {
			fprintf(stderr, "Unknown parameter \"%s\"\n", p);
			return -EINVAL;
		}
	}
	return 0;
}

static void show_account(int auth_dir, char *user, char *pass)
{
	char buf[(ISCSI_NAME_LEN  + 1) * 2] = {0};

	snprintf(buf, ISCSI_NAME_LEN, "%s", user);
	if (pass)
		snprintf(buf + strlen(buf), ISCSI_NAME_LEN, " %s", pass);

	printf("%sUser %s\n", (auth_dir == ISCSI_USER_DIR_INCOMING) ?
	       "Incoming" : "Outgoing", buf);
}

static int user_handle_show_user(struct iscsi_adm_req *req, char *user)
{
	int err;

	req->rcmnd = C_ACCT_SHOW;
	strlcpy(req->u.acnt.u.user.name, user, sizeof(req->u.acnt.u.user.name));

	err = iscsid_request(req, NULL, 0);
	if (!err)
		show_account(req->u.acnt.auth_dir, req->u.acnt.u.user.name,
			     req->u.acnt.u.user.pass);

	return err;
}

static int user_handle_show_list(struct iscsi_adm_req *req)
{
	int i, err, retry;
	size_t buf_sz = 0;
	char *buf;

	req->u.acnt.auth_dir = ISCSI_USER_DIR_INCOMING;
	req->rcmnd = C_ACCT_LIST;

	do {
		retry = 0;

		buf_sz = buf_sz ? buf_sz : ISCSI_NAME_LEN;

		buf = calloc(buf_sz, sizeof(char *));
		if (!buf) {
			fprintf(stderr, "Memory allocation failed\n");
			return -ENOMEM;
		}

		req->u.acnt.u.list.alloc_len = buf_sz;

		err = iscsid_request(req, buf, buf_sz);
		if (err) {
			free(buf);
			break;
		}

		if (req->u.acnt.u.list.overflow) {
			buf_sz = ISCSI_NAME_LEN * (req->u.acnt.u.list.count +
						   req->u.acnt.u.list.overflow);
			retry = 1;
			free(buf);
			continue;
		}

		for (i = 0; i < req->u.acnt.u.list.count; i++)
			show_account(req->u.acnt.auth_dir,
				     &buf[i * ISCSI_NAME_LEN], NULL);

		if (req->u.acnt.auth_dir == ISCSI_USER_DIR_INCOMING) {
			req->u.acnt.auth_dir = ISCSI_USER_DIR_OUTGOING;
			buf_sz = 0;
			retry = 1;
		}

		free(buf);

	} while (retry);

	return err;
}

static int user_handle_show(struct iscsi_adm_req *req, char *user, char *pass)
{
	if (pass)
		fprintf(stderr, "Ignoring specified password\n");

	if (user)
		return user_handle_show_user(req, user);
	else
		return user_handle_show_list(req);
}

static int user_handle_new(struct iscsi_adm_req *req, char *user, char *pass)
{
	if (!user || !pass) {
		fprintf(stderr, "Username and password must be specified\n");
		return -EINVAL;
	}

	req->rcmnd = C_ACCT_NEW;

	strlcpy(req->u.acnt.u.user.name, user, sizeof(req->u.acnt.u.user.name));
	strlcpy(req->u.acnt.u.user.pass, pass, sizeof(req->u.acnt.u.user.pass));

	return iscsid_request(req, NULL, 0);
}

static int user_handle_del(struct iscsi_adm_req *req, char *user, char *pass)
{
	if (!user) {
		fprintf(stderr, "Username must be specified\n");
		return -EINVAL;
	}

	if (pass)
		fprintf(stderr, "Ignoring specified password\n");

	req->rcmnd = C_ACCT_DEL;

	strlcpy(req->u.acnt.u.user.name, user, sizeof(req->u.acnt.u.user.name));

	return iscsid_request(req, NULL, 0);
}

static int user_handle(int op, u32 set, u32 tid, char *params)
{
	int err = -EINVAL;
	char *user = NULL, *pass = NULL;
	struct iscsi_adm_req req;
	static user_handle_fn_t *user_handle_fn[] = {
		user_handle_new,
		user_handle_del,
		NULL,
		user_handle_show,
	}, *fn;

	if (set & ~(SET_TARGET | SET_USER))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;

	err = parse_user_params(params, &req.u.acnt.auth_dir, &user, &pass);
	if (err)
		goto out;

	if ((op >= sizeof(user_handle_fn)/sizeof(user_handle_fn[0])) ||
	    ((fn = user_handle_fn[op]) == NULL)) {
		fprintf(stderr, "Unsupported\n");
		goto out;
	}

	err = fn(&req, user, pass);

out:
	return err;
}

static int conn_handle(int op, u32 set, u32 tid, u64 sid, u32 cid, char *params)
{
	int err = -EINVAL;
	struct iscsi_adm_req req;

	if (op == OP_NEW || op == OP_UPDATE) {
		fprintf(stderr, "Unsupported.\n");
		goto out;
	}

	if (!((set & SET_TARGET) && (set & SET_SESSION) && (set & SET_CONNECTION)))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;
	req.sid = sid;
	req.cid = cid;

	switch (op) {
	case OP_DELETE:
		req.rcmnd = C_CONN_DEL;
		break;
	case OP_SHOW:
		req.rcmnd = C_CONN_SHOW;
		/* TODO */
		break;
	}

	err = iscsid_request(&req, NULL, 0);
out:
	return err;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int err = -EINVAL, op = -1;
	u32 tid = 0, cid = 0, set = 0;
	u64 sid = 0;
	char *params = NULL;

	while ((ch = getopt_long(argc, argv, "o:t:s:c:l:p:uvh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'o':
			op = str_to_op(optarg);
			break;
		case 't':
			tid = strtoul(optarg, NULL, 0);
			set |= SET_TARGET;
			break;
		case 's':
			sid = strtoull(optarg, NULL, 0);
			set |= SET_SESSION;
			break;
		case 'c':
			cid = strtoul(optarg, NULL, 0);
			set |= SET_CONNECTION;
			break;
		case 'p':
			params = optarg;
			break;
		case 'u':
			set |= SET_USER;
			break;
		case 'v':
			printf("%s version %s\n", program_name, ISCSI_VERSION_STRING);
			exit(0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(-1);
		}
	}

	if (op < 0) {
		fprintf(stderr, "You must specify the operation type\n");
		goto out;
	}

	if (optind < argc) {
		fprintf(stderr, "unrecognized: ");
		while (optind < argc)
			fprintf(stderr, "%s", argv[optind++]);
		fprintf(stderr, "\n");
		usage(-1);
	}

	if (set & SET_USER)
		err = user_handle(op, set, tid, params);
	else if (set & SET_CONNECTION)
		err = conn_handle(op, set, tid, sid, cid, params);
	else if (set & SET_SESSION)
		err = sess_handle(op, set, tid, sid, params);
	else if (set & SET_TARGET)
		err = trgt_handle(op, set, tid, params);
	else
		usage(-1);

out:
	return err;
}
