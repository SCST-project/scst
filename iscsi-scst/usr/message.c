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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iscsid.h"
#include "iscsi_adm.h"

int iscsi_adm_request_listen(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSI_ADM_NAMESPACE,
		strlen(ISCSI_ADM_NAMESPACE));

	if ((err = bind(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0)
		return err;

	if ((err = listen(fd, 32)) < 0)
		return err;

	return fd;
}

static void iscsi_adm_request_exec(struct iscsi_adm_req *req, struct iscsi_adm_rsp *rsp)
{
	int err = 0;

	log_debug(1, "%u %u %" PRIu64 " %u %u", req->rcmnd, req->tid,
		  req->sid, req->cid, req->lun);

	switch (req->rcmnd) {
	case C_TRGT_NEW:
		err = cops->target_add(&req->tid, req->u.trgt.name);
		break;
	case C_TRGT_DEL:
		err = cops->target_del(req->tid);
		break;
	case C_TRGT_UPDATE:
		if (req->u.trgt.type & (1 << key_session))
			err = cops->param_set(req->tid, req->sid,
					      key_session,
					      req->u.trgt.session_partial,
					      req->u.trgt.session_param);

		if (err < 0)
			goto out;

		if (req->u.trgt.type & (1 << key_target))
			err = cops->param_set(req->tid, req->sid, key_target,
					      req->u.trgt.target_partial,
					      req->u.trgt.target_param);
		break;
	case C_TRGT_SHOW:
		err = ki->param_get(req->tid, req->sid, key_target,
				    req->u.trgt.target_param, 0);
		break;

	case C_SESS_NEW:
	case C_SESS_DEL:
	case C_SESS_UPDATE:
		break;
	case C_SESS_SHOW:
		err = ki->param_get(req->tid, req->sid, key_session,
				    req->u.trgt.session_param, 0);
		break;

	case C_CONN_NEW:
	case C_CONN_DEL:
		conn_blocked = 1;
		err = ki->conn_destroy(req->tid, req->sid, req->cid);
		sleep(1);
		conn_blocked = 0;
		break;
	case C_CONN_UPDATE:
	case C_CONN_SHOW:
		break;

	case C_ACCT_NEW:
		err = cops->account_add(req->tid, req->u.acnt.auth_dir, req->u.acnt.user,
					req->u.acnt.pass);
		break;
	case C_ACCT_DEL:
		err = cops->account_del(req->tid, req->u.acnt.auth_dir, req->u.acnt.user);
		break;
	case C_ACCT_UPDATE:
	case C_ACCT_SHOW:
		break;
	case C_SYS_NEW:
		break;
	case C_SYS_DEL:
		err = server_stop();
		break;
	case C_SYS_UPDATE:
	case C_SYS_SHOW:
		break;
	default:
		break;
	}

out:
	rsp->err = err;
}

int iscsi_adm_request_handle(int accept_fd)
{
	struct sockaddr addr;
	struct ucred cred;
	int fd, err;
	socklen_t len;
	struct iscsi_adm_req req;
	struct iscsi_adm_rsp rsp;
	struct iovec iov[2];

	memset(&rsp, 0, sizeof(rsp));
	len = sizeof(addr);
	if ((fd = accept(accept_fd, (struct sockaddr *) &addr, &len)) < 0) {
		if (errno == EINTR)
			err = -EINTR;
		else
			err = -EIO;

		goto out;
	}

	len = sizeof(cred);
	if ((err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void *) &cred, &len)) < 0) {
		rsp.err = -EPERM;
		goto send;
	}

	if (cred.uid || cred.gid) {
		rsp.err = -EPERM;
		goto send;
	}

	if ((err = read(fd, &req, sizeof(req))) != sizeof(req)) {
		if (err >= 0)
			err = -EIO;
		goto out;
	}

	iscsi_adm_request_exec(&req, &rsp);

send:
	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);
	iov[1].iov_base = &rsp;
	iov[1].iov_len = sizeof(rsp);

	err = writev(fd, iov, 2);
out:
	if (fd > 0)
		close(fd);
	return err;
}
