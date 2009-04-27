/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2009 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <errno.h>

#include "iscsid.h"

static int session_alloc(u32 tid, struct session **psess)
{
	struct session *session;
	struct target *target = target_find_by_id(tid);
	int res = 0;

	if (!target) {
		log_error("tid %x not found", tid);
		res = -ENOENT;
		goto out;
	}

	if (!(session = malloc(sizeof(*session)))) {
		res = -ENOMEM;
		goto out;
	}

	memset(session, 0, sizeof(*session));

	session->target = target;
	INIT_LIST_HEAD(&session->slist);
	insque(&session->slist, &target->sessions_list);

	*psess = session;

out:
	return res;
}

struct session *session_find_name(u32 tid, const char *iname, union iscsi_sid sid)
{
	struct session *session;
	struct target *target;

	if (!(target = target_find_by_id(tid))) {
		log_error("Target tid %d not found", tid);
		return NULL;
	}

	log_debug(1, "Finding session %s, sid %#" PRIx64, iname, sid.id64);

	list_for_each_entry(session, &target->sessions_list, slist) {
		if (!memcmp(sid.id.isid, session->sid.id.isid, 6) &&
		    !strcmp(iname, session->initiator))
			return session;
	}

	return NULL;
}

struct session *session_find_id(u32 tid, u64 sid)
{
	struct session *session;
	struct target *target;

	if (!(target = target_find_by_id(tid)))
		return NULL;

	log_debug(1, "Searching for sid %#" PRIx64, sid);

	list_for_each_entry(session, &target->sessions_list, slist) {
		if (session->sid.id64 == sid)
			return session;
	}

	return NULL;
}

int session_create(struct connection *conn)
{
	/* We are single threaded, so it desn't need any protection */
	static u16 tsih = 1;
	struct session *session;
	char *user;
	int res = 0;

	res = session_alloc(conn->tid, &session);
	if (res != 0) {
		log_error("session_alloc() failed: %d", res);
		goto out;
	}

	session->sid = conn->sid;
	session->sid.id.tsih = tsih;
	INIT_LIST_HEAD(&session->conn_list);

	insque(&conn->clist, &session->conn_list);
	conn->sess = session;

	conn->sess->initiator = strdup(conn->initiator);
	if (conn->sess->initiator == NULL) {
		res = -errno;
		log_error("strdup() failed: %d", res);
		goto out_free;
	}

	while (1) {
		struct session *s;

		s = session_find_id(conn->tid, session->sid.id64);
		if (s != NULL)
			break;

		log_debug(1, "tsih %x already exists", session->sid.id.tsih);
		session->sid.id.tsih++;
	}
	tsih = session->sid.id.tsih + 1;

	log_debug(1, "sid %#" PRIx64, session->sid.id64);

	if (conn->user != NULL)
		user = conn->user;
	else
		user = "";

	res = kernel_session_create(conn->tid, session->sid.id64, conn->exp_cmd_sn,
			session->initiator, user);
	if (res != 0)
		goto out_free;

	res = kernel_param_set(conn->tid, session->sid.id64, key_session, 0,
		conn->session_param);
	if (res != 0)
		goto out_destroy;

out:
	return res;

out_destroy:
	kernel_session_destroy(conn->tid, session->sid.id64);

out_free:
	session_free(session);
	conn->sess = NULL;
	goto out;
}

void session_free(struct session *session)
{
	log_debug(1, "Freeing session sid %#"PRIx64, session->sid.id64);

	if (!session->sid.id.tsih)
		kernel_session_destroy(session->target->tid, session->sid.id64);

	if (session->target)
		remque(&session->slist);

	free(session->initiator);
	free(session);
}

struct connection *conn_find(struct session *session, u16 cid)
{
	struct connection *conn;

	list_for_each_entry(conn, &session->conn_list, clist) {
		if (conn->cid == cid)
			return conn;
	}

	return NULL;
}
