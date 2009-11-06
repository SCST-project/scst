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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "iscsid.h"

struct __qelem targets_list = LIST_HEAD_INIT(targets_list);

void target_list_build(struct connection *conn, char *addr, char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (name && strcmp(target->name, name))
			continue;
		if (config_initiator_access(target->tid, conn->fd) ||
		    isns_scn_access(target->tid, conn->fd, conn->initiator))
			continue;

		text_key_add(conn, "TargetName", target->name);
		text_key_add(conn, "TargetAddress", addr);
	}
}

u32 target_find_id_by_name(const char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcasecmp(target->name, name))
			return target->tid;
	}

	return 0;
}

struct target *target_find_by_name(const char *name)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcasecmp(target->name, name))
			return target;
	}

	return NULL;
}

struct target *target_find_by_id(u32 tid)
{
	struct target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (target->tid == tid)
			return target;
	}

	return NULL;
}

static void all_accounts_del(u32 tid, int dir)
{
	char name[ISCSI_NAME_LEN], pass[ISCSI_NAME_LEN];

	memset(name, 0, sizeof(name));

	for (; config_account_query(tid, dir, name, pass) != -ENOENT;
		memset(name, 0, sizeof(name))) {
		config_account_del(tid, dir, name);
	}

}

int target_del(u32 tid)
{
	struct target *target = target_find_by_id(tid);
	int err = kernel_target_destroy(tid);

	if (err < 0 && err != -ENOENT)
		return err;
	else if (!err && !target)
		/* A leftover kernel object was cleaned up - don't complain. */
		return 0;

	if (!target)
		return -ENOENT;

	remque(&target->tlist);

	if (!list_empty(&target->sessions_list)) {
		log_error("%s: target %u still has sessions\n", __FUNCTION__,
			  tid);
		exit(-1);
	}

	all_accounts_del(tid, AUTH_DIR_INCOMING);
	all_accounts_del(tid, AUTH_DIR_OUTGOING);

	isns_target_deregister(target->name);
	free(target);

	return 0;
}

int target_add(u32 *tid, char *name)
{
	struct target *target;
	int err;
	struct iscsi_param tgt_params[target_key_last];
	struct iscsi_param sess_params[session_key_last];

	if (!name)
		return -EINVAL;

	if (!(target = malloc(sizeof(*target))))
		return -ENOMEM;

	memset(target, 0, sizeof(*target));
	memcpy(target->name, name, sizeof(target->name) - 1);

	if ((err = kernel_target_create(tid, name)) < 0)
		goto out_free;

	param_set_defaults(tgt_params, target_keys);
	err = kernel_param_set(*tid, 0, key_target, 0, tgt_params);
	if (err != 0)
		goto out_destroy;

	param_set_defaults(sess_params, session_keys);
	err = kernel_param_set(*tid, 0, key_session, 0, sess_params);
	if (err != 0)
		goto out_destroy;

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	INIT_LIST_HEAD(&target->isns_head);
	target->tid = *tid;
#ifdef CONFIG_SCST_PROC
	target->tgt_enabled = 1;
#endif
	insque(&target->tlist, &targets_list);

	isns_target_register(name);

out:
	return err;

out_destroy:
	kernel_target_destroy(*tid);

out_free:
	free(target);
	goto out;
}
