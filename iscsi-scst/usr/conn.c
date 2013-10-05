/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "iscsid.h"

#define ISCSI_CONN_NEW		1
#define ISCSI_CONN_EXIT		5

struct connection *conn_alloc(void)
{
	struct connection *conn;
	unsigned int session_params[session_key_last];
	int i;

	conn = malloc(sizeof(*conn));
	if (conn == NULL)
		goto out;

	memset(conn, 0, sizeof(*conn));
	conn->state = STATE_FREE;
	INIT_LIST_HEAD(&conn->rsp_buf_list);

	params_set_defaults(session_params, session_keys);

	for (i = 0; i < session_key_last; i++)
		conn->session_params[i].val = session_params[i];

out:
	return conn;
}

void conn_free(struct connection *conn)
{
	list_del(&conn->clist);
	free(conn->initiator);
	free(conn->target_portal);
	free(conn->user);
	free(conn);
	return;
}

void conn_pass_to_kern(struct connection *conn, int fd)
{
	int err;

	log_debug(1, "fd %d, cid %u, stat_sn %u, exp_stat_sn %u sid %" PRIx64,
		fd, conn->cid, conn->stat_sn, conn->exp_stat_sn, conn->sid.id64);

	err = kernel_conn_create(conn->tid, conn->sess->sid.id64, conn->cid,
			      conn->stat_sn, conn->exp_stat_sn, fd);

	if (err == 0)
		conn->passed_to_kern = 1;

	/* We don't need to return err, because we are going to close conn anyway */
	return;
}

void conn_read_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_READ_BHS;
	conn->buffer = (void *)&conn->req.bhs;
	conn->rwsize = BHS_SIZE;
	return;
}

void conn_write_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_WRITE_BHS;
	memset(&conn->rsp, 0, sizeof(conn->rsp));
	conn->buffer = (void *)&conn->rsp.bhs;
	conn->rwsize = BHS_SIZE;
	return;
}

void conn_free_rsp_buf_list(struct connection *conn)
{
	struct buf_segment *seg, *tmp;

	list_for_each_entry_safe(seg, tmp, &conn->rsp_buf_list, entry) {
		list_del(&seg->entry);
		free(seg);
	}

	conn->rsp.datasize = 0;
	conn->rsp.data = NULL;
	return;
}

void conn_free_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_FREE;
	if (conn->req.ahs) {
		free(conn->req.ahs);
		conn->req.ahs = NULL;
	}
	if (conn->rsp.ahs) {
		free(conn->rsp.ahs);
		conn->rsp.ahs = NULL;
	}
	conn_free_rsp_buf_list(conn);
	return;
}
