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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

static void iscsi_adm_request_exec(struct iscsi_adm_req *req, struct iscsi_adm_rsp *rsp,
				void **rsp_data, size_t *rsp_data_sz)
{
	int err = 0;

	log_debug(1, "request %u, tid %u, sid 0x%" PRIx64 ", cid %u, lun %u",
		req->rcmnd, req->tid, req->sid, req->cid, req->lun);

	switch (req->rcmnd) {
	case C_TRGT_NEW:
		err = config_target_create(&req->tid, req->u.trgt.name);
		break;
	case C_TRGT_DEL:
		err = config_target_destroy(req->tid);
		break;
	case C_TRGT_UPDATE:
		if (req->u.trgt.type & (1 << key_session))
			err = config_params_set(req->tid, req->sid,
					      key_session,
					      req->u.trgt.session_partial,
					      req->u.trgt.session_params);

		if (err < 0)
			goto out;

		if (req->u.trgt.type & (1 << key_target))
			err = config_params_set(req->tid, req->sid, key_target,
					      req->u.trgt.target_partial,
					      req->u.trgt.target_params);
		break;
	case C_TRGT_SHOW:
		err = config_params_get(req->tid, req->sid, key_target,
				    req->u.trgt.target_params);
		break;

	case C_SESS_NEW:
	case C_SESS_DEL:
	case C_SESS_UPDATE:
		break;
	case C_SESS_SHOW:
		err = config_params_get(req->tid, req->sid, key_session,
				    req->u.trgt.session_params);
		break;

	case C_CONN_NEW:
		break;
	case C_CONN_DEL:
		conn_blocked = 1;
		err = kernel_conn_destroy(req->tid, req->sid, req->cid);
		conn_blocked = 0;
		break;
	case C_CONN_UPDATE:
	case C_CONN_SHOW:
		break;

	case C_ACCT_NEW:
		err = config_account_add(req->tid, req->u.acnt.auth_dir,
					req->u.acnt.u.user.name,
					req->u.acnt.u.user.pass, NULL, 0);
		break;
	case C_ACCT_DEL:
		err = config_account_del(req->tid, req->u.acnt.auth_dir,
					req->u.acnt.u.user.name, 0);
		break;
	case C_ACCT_LIST:
		*rsp_data = malloc(req->u.acnt.u.list.alloc_len);
		if (!*rsp_data) {
			err = -ENOMEM;
			break;
		}

		*rsp_data_sz = req->u.acnt.u.list.alloc_len;
		memset(*rsp_data, 0x0, *rsp_data_sz);

		err = config_account_list(req->tid, req->u.acnt.auth_dir,
					 &req->u.acnt.u.list.count,
					 &req->u.acnt.u.list.overflow,
					 *rsp_data, *rsp_data_sz);
		break;
	case C_ACCT_UPDATE:
		break;
	case C_ACCT_SHOW:
		err = config_account_query(req->tid, req->u.acnt.auth_dir,
					  req->u.acnt.u.user.name,
					  req->u.acnt.u.user.pass);
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
	struct iovec iov[3];
	void *rsp_data = NULL;
	size_t rsp_data_sz;

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

	iscsi_adm_request_exec(&req, &rsp, &rsp_data, &rsp_data_sz);

send:
	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);
	iov[1].iov_base = &rsp;
	iov[1].iov_len = sizeof(rsp);
	iov[2].iov_base = rsp.err ? NULL : rsp_data;
	iov[2].iov_len = iov[2].iov_base ? rsp_data_sz : 0;

	err = writev(fd, iov, 2 + !!iov[2].iov_len);
out:
	if (fd > 0)
		close(fd);
	if (rsp_data)
		free(rsp_data);

	return err;
}
