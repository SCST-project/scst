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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "iscsid.h"

struct __qelem targets_list = LIST_HEAD_INIT(targets_list);

const char *iscsi_make_full_initiator_name(int per_portal_acl,
	const char *initiator_name, const char *target_portal,
	char *buf, int size)
{
	if (per_portal_acl)
		snprintf(buf, size, "%s#%s", initiator_name,
			target_portal);
	else
		snprintf(buf, size, "%s", initiator_name);

	return buf;
}

/*
 * Written by Jack Handy - jakkhandy@hotmail.com
 * Taken by Gennadiy Nerubayev <parakie@gmail.com> from
 * http://www.codeproject.com/KB/string/wildcmp.aspx. No license attached
 * to it, and it's posted on a free site; assumed to be free for use.
 *
 * Added the negative sign support - VLNB
 *
 * Also see comment for wildcmp().
 *
 * SCST core also has a copy of this code, so fixing a bug here, don't forget
 * to fix the copy too!
 */
static int __wildcmp(const char *wild, const char *string, int recursion_level)
{
	const char *cp = NULL, *mp = NULL;

	while ((*string) && (*wild != '*')) {
		if ((*wild == '!') && (recursion_level == 0))
			return !__wildcmp(++wild, string, ++recursion_level);

		if ((tolower(*wild) != tolower(*string)) && (*wild != '?'))
			return 0;

		wild++;
		string++;
	}

	while (*string) {
		if ((*wild == '!') && (recursion_level == 0))
			return !__wildcmp(++wild, string, ++recursion_level);

		if (*wild == '*') {
			if (!*++wild)
				return 1;

			mp = wild;
			cp = string+1;
		} else if ((tolower(*wild) == tolower(*string)) || (*wild == '?')) {
			wild++;
			string++;
		} else {
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*')
		wild++;

	return !*wild;
}

/*
 * Returns true if string "string" matches pattern "wild", false otherwise.
 * Pattern is a regular DOS-type pattern, containing '*' and '?' symbols.
 * '*' means match all any symbols, '?' means match only any single symbol.
 *
 * For instance:
 * if (wildcmp("bl?h.*", "blah.jpg")) {
 *   // match
 *  } else {
 *   // no match
 *  }
 *
 * Also it supports boolean inversion sign '!', which does boolean inversion of
 * the value of the rest of the string. Only one '!' allowed in the pattern,
 * other '!' are treated as regular symbols. For instance:
 * if (wildcmp("bl!?h.*", "blah.jpg")) {
 *   // no match
 *  } else {
 *   // match
 *  }
 *
 * Also see comment for __wildcmp().
 */
static int wildcmp(const char *wild, const char *string)
{
	return __wildcmp(wild, string, 0);
}

int target_portal_allowed(struct target *target,
	const char *target_portal, const char *initiator_name)
{
	int res;
	char full_initiator_name[ISCSI_FULL_NAME_LEN];

	if (!list_empty(&target->allowed_portals)) {
		struct iscsi_attr *attr;

		res = 0;
		list_for_each_entry(attr, &target->allowed_portals, ulist) {
			if (wildcmp(attr->attr_key, target_portal)) {
				res = 1;
				break;
			}
		}
		if (res == 0)
			goto out;
	}

	res = kernel_initiator_allowed(target->tid,
		iscsi_make_full_initiator_name(target->per_portal_acl,
			initiator_name, target_portal,
			full_initiator_name, sizeof(full_initiator_name)));
	if (res < 0)
		res = 0; /* false */

out:
	return res;
}

static int is_addr_loopback(char *addr)
{
	struct in_addr ia;
	struct in6_addr ia6;

	if (inet_pton(AF_INET, addr, &ia) == 1)
		return !strncmp(addr, "127.", 4);

	if (inet_pton(AF_INET6, addr, &ia6) == 1)
		return IN6_IS_ADDR_LOOPBACK(&ia6);

	return 0;
}

static int is_addr_unspecified(char *addr)
{
	struct in_addr ia;
	struct in6_addr ia6;

	if (inet_pton(AF_INET, addr, &ia) == 1)
		return (ia.s_addr == 0);

	if (inet_pton(AF_INET6, addr, &ia6) == 1)
		return IN6_IS_ADDR_UNSPECIFIED(&ia6);

	return 0;
}

static void target_print_addr(struct connection *conn, char *addr, int family)
{
	char taddr[NI_MAXHOST + NI_MAXSERV + 5];

	snprintf(taddr, sizeof(taddr),
		(family == AF_INET) ? "%s:%d,1" : "[%s]:%d,1",
							addr, server_port);

	text_key_add(conn, "TargetAddress", taddr);
}

static void target_list_build_ifaddrs(struct connection *conn,
	struct target *target, char *exclude_addr, int family)
{
	struct ifaddrs *ifaddr, *ifa;
	char if_addr[NI_MAXHOST];

	getifaddrs(&ifaddr);

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		int sa_family = ifa->ifa_addr->sa_family;

		if (sa_family == family) {
			if (getnameinfo(ifa->ifa_addr, (family == AF_INET) ?
						sizeof(struct sockaddr_in) :
						sizeof(struct sockaddr_in6),
					if_addr, sizeof(if_addr),
					NULL, 0, NI_NUMERICHOST))
				continue;

			if (strcmp(exclude_addr, if_addr) &&
			    !is_addr_loopback(if_addr) &&
			    target_portal_allowed(target, if_addr, conn->initiator))
				target_print_addr(conn, if_addr, family);
		}
	}

	freeifaddrs(ifaddr);
	return;
}

void target_list_build(struct connection *conn, char *target_name)
{
	struct target *target;
	struct sockaddr_storage ss1, ss2;
	socklen_t slen = sizeof(struct sockaddr_storage);
	char portal[NI_MAXHOST];
	int family, i;

	if (getsockname(conn->fd, (struct sockaddr *) &ss1, &slen)) {
		log_error("getsockname failed: %m");
		return;
	}
	family = ss1.ss_family;

	list_for_each_entry(target, &targets_list, tlist) {
		if (target_name && strcmp(target->name, target_name))
			continue;

		if (!target->tgt_enabled ||
		    !isns_scn_access_allowed(target->tid, conn->initiator) ||
		    !config_initiator_access_allowed(target->tid, conn->fd) ||
		    !target_portal_allowed(target, conn->target_portal, conn->initiator))
			continue;

		text_key_add(conn, "TargetName", target->name);
		target_print_addr(conn, conn->target_portal, family);

		for (i = 0; i < LISTEN_MAX && poll_array[i].fd; i++) {
			slen = sizeof(struct sockaddr_storage);

			if (getsockname(poll_array[i].fd,
					(struct sockaddr *) &ss2, &slen))
				continue;

			if (getnameinfo((struct sockaddr *) &ss2, slen, portal,
					sizeof(portal), NULL, 0, NI_NUMERICHOST))
				continue;

			if (ss2.ss_family != family)
				continue;

			if (is_addr_unspecified(portal))
				target_list_build_ifaddrs(conn, target,
					conn->target_portal, family);
			else if (strcmp(conn->target_portal, portal) &&
				 !is_addr_loopback(portal) &&
				 target_portal_allowed(target, portal,
				 		conn->initiator))
					target_print_addr(conn, portal, family);
		}
	}
	return;
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

	while (1) {
		/* We might need to handle session(s) removal event(s) from the kernel */
		while (handle_iscsi_events(nl_fd, false) == 0);

		if (list_empty(&target->sessions_list))
			break;

		/* We have not yet received session(s) removal event(s), so keep waiting */
		log_debug(1, "Target %d has sessions, keep waiting", tid);
		usleep(50000);
	}

	/*
	 * Remove target from the list after waiting for all sessions
	 * deleted, because we are looking for this target in list during
	 * each session delete.
	 */
	list_del(&target->tlist);

	if (target->tgt_enabled)
		isns_target_deregister(target->name);

	target_free(target);

	return 0;
}

void target_free(struct target *target)
{
	accounts_free(&target->target_in_accounts);
	accounts_free(&target->target_out_accounts);

	iscsi_attrs_free(&target->allowed_portals);

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
	INIT_LIST_HEAD(&target->allowed_portals);
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

#ifdef CONFIG_SCST_PROC
	isns_target_register(target->name);
#endif

out:
	return err;
}

bool target_redirected(struct target *target, struct connection *conn)
{
	bool res = false, rc;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sa;
	socklen_t slen = sizeof(sa);
	char tmp[NI_MAXHOST + 1];
	char addr[NI_MAXHOST + 3];
	char redirect[NI_MAXHOST + NI_MAXSERV + 4];
	char *p;

	if (strlen(target->redirect.addr) == 0)
		goto out;

	rc = getsockname(conn->fd, (struct sockaddr *)&sa.sa, &slen);
	if (rc != 0) {
		log_error("getsockname() failed: %s", strerror(errno));
		goto out;
	}

	rc = getnameinfo(&sa.sa, sizeof(sa), tmp, sizeof(tmp), NULL, 0, NI_NUMERICHOST);
	if (rc != 0) {
		log_error("getnameinfo() failed: %s", get_error_str(rc));
		goto out;
	}

	if ((p = strrchr(tmp, '%')))
		*p = '\0';

	if (sa.sa.sa_family == AF_INET6)
		snprintf(addr, sizeof(addr), "[%s]", tmp);
	else
		snprintf(addr, sizeof(addr), "%s", tmp);

	snprintf(redirect, sizeof(redirect), "%s:%d", target->redirect.addr,
		target->redirect.port);

	if (strcmp(target->redirect.addr, addr)) {
		text_key_add(conn, "TargetAddress", redirect);
		res = true;
	}

out:
	return res;
}
