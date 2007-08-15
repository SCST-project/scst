/*
 * iscsi_adm - manage iSCSI Enterprise Target software.
 *
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
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
iSCSI Enterprise Target Administration Utility.\n\
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
  --op delete --tid=[id] --sid=[sid] --cid=[cid]\n\
                        delete specific connection with [cid] in a session\n\
                        with [sid] that the target with [id] has.\n\
                        If the session has no connections after\n\
                        the operation, the session will be deleted\n\
                        automatically.\n\
  --op delete           stop all activity.\n\
  --op update --tid=[id] --params=key1=value1,key2=value2,...\n\
                        change SCST iSCSI target parameters of specific\n\
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
Report bugs to <iscsitarget-devel@sourceforge.net>.\n");
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
		fprintf(stderr, "%s %d %d %d\n", __FUNCTION__, __LINE__, ret,
			err);
	} else
		err = 0;

	return err;
}

static int iscsid_response_recv(int fd, struct iscsi_adm_req *req)
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
		fprintf(stderr, "%s %d %d %d\n", __FUNCTION__, __LINE__, ret,
			err);
	} else
		err = rsp.err;

	return err;
}

static int iscsid_connect(void)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSI_ADM_NAMESPACE, strlen(ISCSI_ADM_NAMESPACE));

	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)))
		fd = -errno;

	return fd;
}

static int iscsid_request(struct iscsi_adm_req *req)
{
	int fd = -1, err = -EIO;

	if ((fd = iscsid_connect()) < 0) {
		err = fd;
		goto out;
	}

	if ((err = iscsid_request_send(fd, req)) < 0)
		goto out;

	err = iscsid_response_recv(fd, req);

out:
	if (fd > 0)
		close(fd);

	if (err < 0)
		fprintf(stderr, "%s.\n", strerror(-err));

	return err;
}

static void show_iscsi_param(int type, struct iscsi_param *param)
{
	int i, nr;
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
		strcpy(buf, keys[i].name);
		p = buf + strlen(buf);
		*p++ = '=';
		param_val_to_str(keys, i, param[i].local_val, p);
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

		if (!((idx = param_index_by_name(p, target_keys)) < 0)) {
			if (param_str_to_val(target_keys, idx, q, &val)) {
				fprintf(stderr,
					"Invalid %s value \"%s\".\n",
					target_keys[idx].name, q);
				return -EINVAL;
			}
			if (!param_check_val(target_keys, idx, &val))
				msg->target_partial |= (1 << idx);
			msg->target_param[idx].local_val = val;
			msg->type |= 1 << key_target;

			continue;
		}

		if (!((idx = param_index_by_name(p, session_keys)) < 0)) {
			if (param_str_to_val(session_keys, idx, q, &val)) {
				fprintf(stderr,
					"Invalid %s value \"%s\".\n",
					session_keys[idx].name, q);
				return -EINVAL;
			}
			if (!param_check_val(session_keys, idx, &val))
				msg->session_partial |= (1 << idx);
			msg->session_param[idx].local_val = val;
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

		if (!params || !(p = strchr(params, '=')))
			goto out;
		*p++ = '\0';
		if (strcmp(params, "Name"))
			goto out;
		req.rcmnd = C_TRGT_NEW;
		strncpy(req.u.trgt.name, p, sizeof(req.u.trgt.name) - 1);
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

	err = iscsid_request(&req);
	if (!err && req.rcmnd == C_TRGT_SHOW)
		show_iscsi_param(key_target, req.u.trgt.target_param);

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
		err = iscsid_request(&req);
		if (!err)
			show_iscsi_param(key_session, req.u.trgt.session_param);
		break;
	}

out:
	return err;
}

static int user_handle(int op, u32 set, u32 tid, char *params)
{
	int err = -EINVAL;
	char *p, *q, *user = NULL, *pass = NULL;
	struct iscsi_adm_req req;

	if (set & ~(SET_TARGET | SET_USER))
		goto out;

	memset(&req, 0, sizeof(req));
	req.tid = tid;

	switch (op) {
	case OP_NEW:
		req.rcmnd = C_ACCT_NEW;
		break;
	case OP_DELETE:
		req.rcmnd = C_ACCT_DEL;
		break;
	case OP_UPDATE:
	case OP_SHOW:
		fprintf(stderr, "Unsupported.\n");
		goto out;
	}

	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;

		if (!(q = strchr(p, '=')))
			continue;
		*q++ = '\0';
		if (isspace(*q))
			q++;

		if (!strcasecmp(p, "IncomingUser")) {
			if (user)
				fprintf(stderr, "Already specified user %s\n", q);
			user = q;
			req.u.acnt.auth_dir = AUTH_DIR_INCOMING;
		} else if (!strcasecmp(p, "OutgoingUser")) {
			if (user)
				fprintf(stderr, "Already specified user %s\n", q);
			user = q;
			req.u.acnt.auth_dir = AUTH_DIR_OUTGOING;
		} else if (!strcasecmp(p, "Password")) {
			if (pass)
				fprintf(stderr, "Already specified pass %s\n", q);
			pass = q;
		} else {
			fprintf(stderr, "Unknown parameter %p\n", q);
			goto out;
		}
	}

	if ((op == OP_NEW && ((user && !pass) || (!user && pass) || (!user && !pass))) ||
	    (op == OP_DELETE && ((!user && pass) || (!user && !pass)))) {
		fprintf(stderr,
			"You need to specify a user and its password %s %s\n", pass, user);
		goto out;
	}

	strncpy(req.u.acnt.user, user, sizeof(req.u.acnt.user) - 1);
	if (pass)
		strncpy(req.u.acnt.pass, pass, sizeof(req.u.acnt.pass) - 1);

	err = iscsid_request(&req);
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

	err = iscsid_request(&req);
out:
	return err;
}

static int sys_handle(int op, u32 set, char *params)
{
	int err = -EINVAL;
	struct iscsi_adm_req req;

	memset(&req, 0, sizeof(req));

	switch (op) {
	case OP_NEW:
		break;
	case OP_DELETE:
		req.rcmnd = C_SYS_DEL;
		break;
	case OP_UPDATE:
		break;
	case OP_SHOW:
		break;
	}

	err = iscsid_request(&req);

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
			tid = strtoul(optarg, NULL, 10);
			set |= SET_TARGET;
			break;
		case 's':
			sid = strtoull(optarg, NULL, 10);
			set |= SET_SESSION;
			break;
		case 'c':
			cid = strtoul(optarg, NULL, 10);
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
	else if (!set)
		err = sys_handle(op, set, params);
	else
		usage(-1);

out:
	return err;
}
