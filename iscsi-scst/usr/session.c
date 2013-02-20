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
	list_add_tail(&session->slist, &target->sessions_list);

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

static bool session_id_exists(u32 tid, u64 sid, struct session *exclude)
{
	struct session *session;
	struct target *target;

	if (!(target = target_find_by_id(tid)))
		return false;

	log_debug(1, "Searching for sid %#" PRIx64, sid);

	list_for_each_entry(session, &target->sessions_list, slist) {
		if ((session->sid.id64 == sid) && (session != exclude))
			return true;
	}

	return false;
}

int session_create(struct connection *conn)
{
	/* We are single threaded, so it doesn't need any protection */
	static u16 tsih = 1;
	struct session *session;
	int res = 0;

	res = session_alloc(conn->tid, &session);
	if (res != 0) {
		log_error("session_alloc() failed: %d", res);
		goto out;
	}

	session->sid = conn->sid;
	session->sid.id.tsih = tsih;
	INIT_LIST_HEAD(&session->conn_list);

	list_add_tail(&conn->clist, &session->conn_list);
	conn->sess = session;

	conn->sess->initiator = strdup(conn->initiator);
	if (conn->sess->initiator == NULL) {
		res = -errno;
		log_error("strdup() failed: %d", res);
		goto out_free;
	}

	while (1) {
		bool e;

		e = session_id_exists(conn->tid, session->sid.id64, session);
		if (!e)
			break;

		log_debug(1, "tsih %x already exists", session->sid.id.tsih);
		session->sid.id.tsih++;
	}
	tsih = session->sid.id.tsih + 1;

	log_debug(1, "sid %#" PRIx64, session->sid.id64);

	res = kernel_session_create(conn);
	if (res != 0)
		goto out_free;

out:
	return res;

out_free:
	list_del_init(&conn->clist);
	assert(list_empty(&session->conn_list));
	session_free(session);
	conn->sess = NULL;
	goto out;
}

void session_free(struct session *session)
{
	log_debug(1, "Freeing session sid %#"PRIx64, session->sid.id64);

	kernel_session_destroy(session->target->tid, session->sid.id64);

	if (session->target) {
		struct target *target = session->target;

		target->sessions_count--;
		log_debug(1, "target %s, sessions_count %d", target->name,
			target->sessions_count);

		list_del(&session->slist);
	}

	free(session->initiator);
	free(session);
	return;
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
