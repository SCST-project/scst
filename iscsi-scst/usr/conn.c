/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2008 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
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

	if (!(conn = malloc(sizeof(*conn))))
		return NULL;

	memset(conn, 0, sizeof(*conn));
	conn->state = STATE_FREE;
	param_set_defaults(conn->session_param, session_keys);
	INIT_LIST_HEAD(&conn->rsp_buf_list);

	return conn;
}

void conn_free(struct connection *conn)
{
	free(conn->initiator);
	free(conn->user);
	free(conn);
}

int conn_test(struct connection *conn)
{
	FILE *f;
	char buf[8192], *p;
	u32 tid, t_tid, cid, t_cid;
	u64 sid, t_sid;
	int err = -ENOENT, find = 0;

	t_tid = conn->tid;
	t_sid = conn->session->sid.id64;
	t_cid = conn->cid;

	if ((f = fopen(PROC_SESSION, "r")) == NULL) {
		fprintf(stderr, "Can't open %s\n", PROC_SESSION);
		return -errno;
	}

	while (fgets(buf, sizeof(buf), f)) {
		p = buf;
		while (isspace((int) *p))
			p++;

		if (!strncmp(p, "tid:", 4)) {
			if (sscanf(p, "tid:%u", &tid) != 1) {
				err = -EIO;
				goto out;
			}
			if (tid == t_tid)
				find = 1;
			else
				find = 0;
		} else if (!strncmp(p, "sid:", 4)) {
			if (!find)
				continue;
			if (sscanf(p, "sid:%" SCNu64, &sid) != 1) {
				err = -EIO;
				goto out;
			}

			if (sid == t_sid)
				find = 1;
			else
				find = 0;
		} else if (!strncmp(p, "cid:", 4)) {
			if (!find)
				continue;
			if (sscanf(p, "cid:%u", &cid) != 1) {
				err = -EIO;
				goto out;
			}

			if (cid == t_cid) {
				err = 0;
				goto out;
			}
		}
	}

out:
	fclose(f);

	return err;
}

void conn_take_fd(struct connection *conn, int fd)
{
	int err;
	log_debug(1, "conn_take_fd: %d %u %u %u %" PRIx64,
		  fd, conn->cid, conn->stat_sn, conn->exp_stat_sn, conn->sid.id64);

	conn->session->conn_cnt++;

	err = ki->conn_create(conn->tid, conn->session->sid.id64, conn->cid,
			      conn->stat_sn, conn->exp_stat_sn, fd,
			      conn->session_param[key_header_digest].exec_val,
			      conn->session_param[key_data_digest].exec_val);

	return;
}

void conn_read_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_READ_BHS;
	conn->buffer = (void *)&conn->req.bhs;
	conn->rwsize = BHS_SIZE;
}

void conn_write_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_WRITE_BHS;
	memset(&conn->rsp, 0, sizeof(conn->rsp));
	conn->buffer = (void *)&conn->rsp.bhs;
	conn->rwsize = BHS_SIZE;
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
}
