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

int target_del(u32 tid, u32 cookie)
{
	struct target *target;
	int err;

	err = kernel_target_destroy(tid, cookie);

	if (err < 0 && err != -ENOENT)
		return err;

	target = target_find_by_id(tid);
	if (!err && !target)
		/* A leftover kernel object was cleaned up - don't complain. */
		return 0;

	if (!target)
		return -ENOENT;

	list_del(&target->tlist);

	if (!list_empty(&target->sessions_list)) {
		log_error("%s: target %u still has sessions\n", __FUNCTION__,
			  tid);
		exit(-1);
	}

	isns_target_deregister(target->name);

	target_free(target);

	return 0;
}

void target_free(struct target *target)
{
	accounts_free(&target->target_in_accounts);
	accounts_free(&target->target_out_accounts);

	free(target);
	return;
}

int target_create(const char *name, struct target **out_target)
{
	int res = 0;
	struct target *target;

	if (name == NULL) {
		res = EINVAL;
		goto out;
	}

	target = malloc(sizeof(*target));
	if (target == NULL) {
		res = -ENOMEM;
		goto out;
	}

	memset(target, 0, sizeof(*target));
	memcpy(target->name, name, sizeof(target->name) - 1);

	params_set_defaults(target->target_params, target_keys);
	params_set_defaults(target->session_params, session_keys);

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	INIT_LIST_HEAD(&target->target_in_accounts);
	INIT_LIST_HEAD(&target->target_out_accounts);
	INIT_LIST_HEAD(&target->isns_head);

	*out_target = target;

out:
	return res;
}

int target_add(struct target *target, u32 *tid, u32 cookie)
{
	int err;

	if (target_find_by_name(target->name)) {
		log_error("duplicated target %s", target->name);
		err = -EEXIST;
		goto out;
	}

	err = kernel_target_create(target, tid, cookie);
	if (err != 0)
		goto out;

#ifdef CONFIG_SCST_PROC
	target->tgt_enabled = 1;
#endif
	list_add_tail(&target->tlist, &targets_list);

	isns_target_register(target->name);

out:
	return err;
}
