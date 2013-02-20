/*
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iscsid.h"

#define BUFSIZE		4096
#define CONFIG_FILE	"/etc/iscsi-scstd.conf"

/*
 * Index must match ISCSI_USER_DIR_* and ISCSI_USER_DIR_OUTGOING must
 * be the last to confirm expectations of __config_account_add()!!
 */
struct iscsi_key user_keys[] = {
	{"IncomingUser",},
	{"OutgoingUser",},
	{NULL,},
};

static struct __qelem discovery_users_in = LIST_HEAD_INIT(discovery_users_in);
static struct __qelem discovery_users_out = LIST_HEAD_INIT(discovery_users_out);

struct iscsi_attr *iscsi_attr_lookup_by_sysfs_name(
	struct __qelem *attrs_list, const char *sysfs_name)
{
	struct iscsi_attr *attr;

	list_for_each_entry(attr, attrs_list, ulist) {
		if (!strcmp(attr->sysfs_name, sysfs_name))
			return attr;
	}

	return NULL;
}

struct iscsi_attr *iscsi_attr_lookup_by_key(
	struct __qelem *attrs_list, const char *key)
{
	struct iscsi_attr *attr;

	list_for_each_entry(attr, attrs_list, ulist) {
		if (!strcmp(attr->attr_key, key))
			return attr;
	}

	return NULL;
}

static void __iscsi_attr_destroy(struct iscsi_attr *attr, int del)
{
	if (!attr)
		return;

	if (del)
		list_del(&attr->ulist);

	free((void *)attr->attr_key);
	free((void *)attr->attr_value);
	free(attr);
	return;
}

void iscsi_attr_destroy(struct iscsi_attr *attr)
{
	__iscsi_attr_destroy(attr, 1);
}

void iscsi_attrs_free(struct __qelem *attrs_list)
{
	struct iscsi_attr *attr, *t;

	list_for_each_entry_safe(attr, t, attrs_list, ulist) {
		iscsi_attr_destroy(attr);
	}

	return;
}

int iscsi_attr_create(int attr_size, struct __qelem *attrs_list,
	const char *sysfs_name_tmpl, const char *key, const char *val,
	u32 mode, struct iscsi_attr **res_attr)
{
	int res = 0;
	struct iscsi_attr *attr;
	int num = 0;

	if (iscsi_attr_lookup_by_key(attrs_list, key) != NULL) {
		log_error("Attribute %s already exists", key);
		res = -EINVAL;
		goto out;
	}

	attr = malloc(attr_size);
	if (attr == NULL)
		goto out;

	memset(attr, 0, attr_size);

	attr->attr_key = strdup(key);
	if (attr->attr_key == NULL) {
		log_error("Unable to duplicate attr_key %s", key);
		res = -ENOMEM;
		goto out_free;
	}

	if ((val != NULL) && (*val != '\0')) {
		attr->attr_value = strdup(val);
		if (attr->attr_value == NULL) {
			log_error("Unable to duplicate attr_value %s", val);
			res = -ENOMEM;
			goto out_free;
		}
	}

	attr->sysfs_mode = mode;

	if (sysfs_name_tmpl == NULL)
		goto add;

	if (sysfs_name_tmpl != NULL) {
		strlcpy(attr->sysfs_name, sysfs_name_tmpl, sizeof(attr->sysfs_name));
		if (iscsi_attr_lookup_by_sysfs_name(attrs_list, attr->sysfs_name) == NULL)
			goto add;
	}

	while (1) {
		if (num == 0)
			num++;
		snprintf(attr->sysfs_name, sizeof(attr->sysfs_name),
			"%s%d", sysfs_name_tmpl, num);
		if (iscsi_attr_lookup_by_sysfs_name(attrs_list, attr->sysfs_name) == NULL)
			break;
		num++;
	}

add:
	list_add_tail(attr, attrs_list);

	*res_attr = attr;

out:
	return res;

out_free:
	__iscsi_attr_destroy(attr, 0);
	goto out;
}

int iscsi_attr_replace(struct __qelem *attrs_list, const char *sysfs_name,
	char *raw_value)
{
	int res = 0;
	struct iscsi_attr *attr, *a;
	char *key, *val, *new_key, *new_val;

	key = config_sep_string(&raw_value);
	val = config_sep_string(&raw_value);

	attr = iscsi_attr_lookup_by_sysfs_name(attrs_list, sysfs_name);
	if (attr == NULL) {
		log_error("Unknown parameter %s\n", sysfs_name);
		res = -EINVAL;
		goto out;
	}

	a = iscsi_attr_lookup_by_key(attrs_list, key);

	if ((a != NULL) && (a != attr)) {
		log_error("Attr %s (sysfs_name %s) already exists\n", key,
			a->sysfs_name);
		res = -EEXIST;
		goto out;
	}

	new_key = strdup(key);
	if (new_key == NULL) {
		log_error("Unable to duplicate attr_key %s", key);
		res = -ENOMEM;
		goto out;
	}

	if ((val != NULL) && (*val != '\0')) {
		new_val = strdup(val);
		if (new_val == NULL) {
			log_error("Unable to duplicate attr_value %s", val);
			res = -ENOMEM;
			free(new_key);
			goto out;
		}
	} else
		new_val = NULL;

	free((void *)attr->attr_key);
	attr->attr_key = new_key;

	free((void *)attr->attr_value);
	attr->attr_value = new_val;

out:
	return res;
}

static struct __qelem *account_list_get(struct target *target, int dir)
{
	struct __qelem *list = NULL;

	if (target != NULL) {
		list = (dir == ISCSI_USER_DIR_INCOMING) ?
			&target->target_in_accounts : &target->target_out_accounts;
	} else
		list = (dir == ISCSI_USER_DIR_INCOMING) ?
			&discovery_users_in : &discovery_users_out;

	return list;
}

char *config_sep_string(char **pp)
{
	char *p = *pp;
	char *q;
	static char blank = '\0';

	if ((pp == NULL) || (*pp == NULL))
		return &blank;

	for (p = *pp; isspace(*p) || (*p == '='); p++)
		;

	for (q = p; (*q != '\0') && !isspace(*q) && (*q != '='); q++)
		;

	if (*q != '\0')
		*q++ = '\0';

	*pp = q;
	return p;
}

static char *config_gets(char *buf, int size, const char *data, int *offset)
{
	int offs = *offset, i = 0;

	while ((i < size-1) && (data[offs] != '\n') && (data[offs] != ';') && (data[offs] != '\0'))
		buf[i++] = data[offs++];

	if ((i == 0) && (data[offs] == '\0'))
		return NULL;

	if (data[offs] != '\0')
		offs++;

	*offset = offs;
	buf[i] = '\0';

	return buf;
}

int accounts_empty(u32 tid, int dir)
{
	struct target *target;
	struct __qelem *list;

	if (tid) {
		target = target_find_by_id(tid);
		if (target == NULL)
			return 0;
	} else
		target = NULL;

	list = account_list_get(target, dir);

	return list_empty(list);
}

static struct iscsi_attr *__account_lookup_by_name(struct target *target,
	int dir, const char *name)
{
	struct __qelem *list;

	list = account_list_get(target, dir);

	return iscsi_attr_lookup_by_key(list, name);
}

static struct iscsi_attr *account_lookup_by_name(u32 tid, int dir, const char *name)
{
	struct target *target;

	if (tid) {
		target = target_find_by_id(tid);
		if (target == NULL)
			return NULL;
	} else
		target = NULL;

	return __account_lookup_by_name(target, dir, name);
}

struct iscsi_attr *account_get_first(u32 tid, int dir)
{
	struct target *target;
	struct __qelem *list;
	struct iscsi_attr *user;

	if (tid) {
		target = target_find_by_id(tid);
		if (target == NULL)
			return NULL;
	} else
		target = NULL;

	list = account_list_get(target, dir);

	list_for_each_entry(user, list, ulist) {
		return user;
	}

	return NULL;
}

struct iscsi_attr *account_lookup_by_sysfs_name(struct target *target,
	int dir, const char *sysfs_name)
{
	struct __qelem *list;

	list = account_list_get(target, dir);

	return iscsi_attr_lookup_by_sysfs_name(list, sysfs_name);
}

int config_account_query(u32 tid, int dir, const char *name, char *pass)
{
	struct iscsi_attr *user;

	if (!(user = account_lookup_by_name(tid, dir, name)))
		return -ENOENT;

	strlcpy(pass, ISCSI_USER_PASS(user), ISCSI_NAME_LEN);

	return 0;
}

int config_account_list(u32 tid, int dir, u32 *cnt, u32 *overflow,
	char *buf, size_t buf_sz)
{
	struct target *target;
	struct __qelem *list;
	struct iscsi_attr *user;

	*cnt = *overflow = 0;

	if (tid) {
		target = target_find_by_id(tid);
		if (target == NULL)
			return -ENOENT;
	} else
		target = NULL;

	list = account_list_get(target, dir);

	if (!list)
		return -ENOENT;

	list_for_each_entry(user, list, ulist) {
		if (buf_sz >= ISCSI_NAME_LEN) {
			strlcpy(buf, ISCSI_USER_NAME(user), ISCSI_NAME_LEN);
			buf_sz -= ISCSI_NAME_LEN;
			buf += ISCSI_NAME_LEN;
			*cnt += 1;
		} else
			*overflow += 1;
	}

	return 0;
}

static void account_destroy(struct iscsi_attr *user)
{
	iscsi_attr_destroy(user);
	return;
}

void accounts_free(struct __qelem *accounts_list)
{
	iscsi_attrs_free(accounts_list);
	return;
}

int config_account_del(u32 tid, int dir, char *name, u32 cookie)
{
	struct iscsi_attr *user;
	int res = 0;
	struct target *target;

	if (!name) {
		log_error("%s", "Name expected");
		res = -EINVAL;
		goto out;
	}

	if (tid) {
		target = target_find_by_id(tid);
		if (target == NULL) {
			log_error("Target %d not found", tid);
			res = -ESRCH;
			goto out;
		}
	} else
		target = NULL;

	user = __account_lookup_by_name(target, dir, name);
	if (user == NULL) {
		log_error("User %s not found", name);
		res = -ENOENT;
		goto out;
	}

	log_debug(1, "Deleting %s user %s (%p, target %s, sysfs name %s)",
		(dir == ISCSI_USER_DIR_OUTGOING) ? "outgoing" : "incoming",
		ISCSI_USER_NAME(user), user, target ? target->name : "discovery",
		user->sysfs_name);

#ifndef CONFIG_SCST_PROC
	res = kernel_user_del(target, user, cookie);
	if (res != 0)
		goto out;
#endif

	account_destroy(user);

out:
	return res;
}

static int account_create(struct __qelem *list, const char *sysfs_name,
	const char *name, const char *pass, struct iscsi_attr **res_user)
{
	return iscsi_attr_create(sizeof(struct iscsi_attr), list, sysfs_name,
			name, pass, 0600, res_user);
}

int account_replace(struct target *target, int direction,
	const char *sysfs_name, char *value)
{
	struct __qelem *list;

	list = account_list_get(target, direction);

	return iscsi_attr_replace(list, sysfs_name, value);
}

int __config_account_add(struct target *target, int dir, char *name,
	char *pass, char *sysfs_name, int send_to_kern, u32 cookie)
{
	int err = 0;
	struct iscsi_attr *user;
	struct __qelem *list;

	if (!name || !pass || (*name == '\0') || (*pass == '\0')) {
		log_error("%s", "Name or password is NULL");
		err = -EINVAL;
		goto out;
	}

	/* Check for minimum RFC defined value */
	if (strlen(pass) < 12) {
		log_error("Secret for user %s is too short. At least 12 bytes "
			"are required\n", name);
		err = -EINVAL;
		goto out;
	}

	if (dir > ISCSI_USER_DIR_OUTGOING) {
		log_error("Wrong direction %d\n", dir);
		err = -EINVAL;
		goto out;
	}

	if (sysfs_name == NULL)
		sysfs_name = (dir == ISCSI_USER_DIR_OUTGOING) ?
				user_keys[ISCSI_USER_DIR_OUTGOING].name :
				user_keys[ISCSI_USER_DIR_INCOMING].name;

	list = account_list_get(target, dir);

	if (dir == ISCSI_USER_DIR_OUTGOING) {
		struct iscsi_attr *old;
		list_for_each_entry(old, list, ulist) {
			log_warning("Only one outgoing %s account is "
				"supported. Replacing the old one.\n",
				target ? "target" : "discovery");
			account_destroy(old);
			break;
		}
	}

	err = account_create(list, sysfs_name, name, pass, &user);
	if (err != 0)
		goto out;

#ifndef CONFIG_SCST_PROC
	if (send_to_kern && (sysfs_name != NULL)) {
		err = kernel_user_add(target, user, cookie);
		if (err != 0)
			goto out_destroy;
	}
#endif

	log_debug(1, "User %s (%p, sysfs name %s) added to target %s "
		"(direction %s)", ISCSI_USER_NAME(user), user, user->sysfs_name,
		target ? target->name : "discovery",
		(dir == ISCSI_USER_DIR_OUTGOING) ? "outgoing" : "incoming");

out:
	return err;

#ifndef CONFIG_SCST_PROC
out_destroy:
#endif
	account_destroy(user);
	goto out;
}

int config_account_add(u32 tid, int dir, char *name, char *pass, char *sysfs_name,
	u32 cookie)
{
	int err = 0;
	struct target *target;

	if (tid) {
		target = target_find_by_id(tid);
		if (target == NULL) {
			err = -ENOENT;
			goto out;
		}
	} else
		target = NULL;

	err = __config_account_add(target, dir, name, pass, sysfs_name, 1, cookie);

out:
	return err;
}

/*
 * Access control code
 */

static int netmask_match_v6(struct sockaddr *sa1, struct sockaddr *sa2, uint32_t mbit)
{
	uint16_t mask, a1[8], a2[8];
	int i;

	for (i = 0; i < 8; i++) {
		a1[i] = ntohs(((struct sockaddr_in6 *) sa1)->sin6_addr.s6_addr16[i]);
		a2[i] = ntohs(((struct sockaddr_in6 *) sa2)->sin6_addr.s6_addr16[i]);
	}

	for (i = 0; i < mbit / 16; i++)
		if (a1[i] ^ a2[i])
			return 0;

	if (mbit % 16) {
		mask = ~((1 << (16 - (mbit % 16))) - 1);
		if ((mask & a1[mbit / 16]) ^ (mask & a2[mbit / 16]))
			return 0;
	}

	return 1;
}

static int netmask_match_v4(struct sockaddr *sa1, struct sockaddr *sa2, uint32_t mbit)
{
	uint32_t s1, s2, mask = ~((1 << (32 - mbit)) - 1);

	s1 = htonl(((struct sockaddr_in *) sa1)->sin_addr.s_addr);
	s2 = htonl(((struct sockaddr_in *) sa2)->sin_addr.s_addr);

	if (~mask & s1)
		return 0;

	if (!((mask & s2) ^ (mask & s1)))
		return 1;

	return 0;
}

static int netmask_match(struct sockaddr *sa1, struct sockaddr *sa2, char *buf)
{
	unsigned long mbit;
	uint8_t family = sa1->sa_family;

	mbit = strtoul(buf, NULL, 0);
	if (mbit == ULONG_MAX ||
	    (family == AF_INET && mbit > 31) ||
	    (family == AF_INET6 && mbit > 127))
		return 0;

	if (family == AF_INET)
		return netmask_match_v4(sa1, sa2, mbit);

	return netmask_match_v6(sa1, sa2, mbit);
}

static int address_match(struct sockaddr *sa1, struct sockaddr *sa2)
{
	if (sa1->sa_family == AF_INET)
		return ((struct sockaddr_in *) sa1)->sin_addr.s_addr ==
			((struct sockaddr_in *) sa2)->sin_addr.s_addr;
	else {
		struct in6_addr *a1, *a2;

		a1 = &((struct sockaddr_in6 *) sa1)->sin6_addr;
		a2 = &((struct sockaddr_in6 *) sa2)->sin6_addr;

		return (a1->s6_addr32[0] == a2->s6_addr32[0] &&
			a1->s6_addr32[1] == a2->s6_addr32[1] &&
			a1->s6_addr32[2] == a2->s6_addr32[2] &&
			a1->s6_addr32[3] == a2->s6_addr32[3]);
	}

	return 0;
}

static int __initiator_match(int fd, char *str)
{
	struct sockaddr_storage from;
	struct addrinfo hints, *res;
	socklen_t len;
	char *p, *q;
	int err = 0;

	len = sizeof(from);
	if (getpeername(fd, (struct sockaddr *) &from, &len) < 0)
		return 0;

	while ((p = strsep(&str, ","))) {
		while (isblank(*p))
			p++;

		if (!strcmp(p, "ALL"))
			return 1;

		if (*p == '[') {
			p++;
			if (!(q = strchr(p, ']')))
				return 0;
			*(q++) = '\0';
		} else
			q = p;

		if ((q = strchr(q, '/')))
			*(q++) = '\0';

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST;

		if (getaddrinfo(p, NULL, &hints, &res) < 0)
			return 0;

		if (q)
			err = netmask_match(res->ai_addr,
					    (struct sockaddr *) &from, q);
		else
			err = address_match(res->ai_addr,
					    (struct sockaddr *) &from);

		freeaddrinfo(res);

		if (err)
			break;
	}

	return err;
}

static int initiator_match(u32 tid, int fd, char *filename)
{
	int err = 0;
	FILE *fp;
	char buf[BUFSIZE], *p;

	if (!(fp = fopen(filename, "r")))
		return err;

	/*
	 * Every time we are called, we read the file. So we don't need to
	 * implement the 'reload feature'. It's slow, but that doesn't matter.
	 */
	while ((p = fgets(buf, sizeof(buf), fp))) {
		if (!p || *p == '#')
			continue;

		p = &buf[strlen(buf) - 1];
		if (*p != '\n')
			continue;
		*p = '\0';

		p = buf;
		while (!isblank(*p) && (*p != '\0'))
			p++;
		if (*p == '\0')
			continue;

		*p = '\0';
		p++;

		if (target_find_id_by_name(buf) != tid && strcmp(buf, "ALL"))
			continue;

		err = __initiator_match(fd, p);
		break;
	}

	fclose(fp);
	return err;
}

int config_initiator_access_allowed(u32 tid, int fd)
{
	if (initiator_match(tid, fd, "/etc/initiators.deny") &&
	    !initiator_match(tid, fd, "/etc/initiators.allow"))
		return 0;
	else
		return 1;
}

/*
 * Main configuration code
 */

int config_target_create(u32 *tid, char *name)
{
	int err;
	struct target *target;

	err = target_create(name, &target);
	if (err != 0)
		goto out;

	err = target_add(target, tid, 0);
	if (err != 0)
		goto out_free;

out:
	return err;

out_free:
	target_free(target);
	goto out;
}

int config_target_destroy(u32 tid)
{
	int err;

	if ((err = target_del(tid, 0)) < 0)
		return err;

	return err;
}

int config_params_get(u32 tid, u64 sid, int type, struct iscsi_param *params)
{
	int err, i;
	struct target *target;

	if (sid != 0) {
		err = kernel_params_get(tid, sid, type, params);
		goto out;
	}

	err = 0;

	target = target_find_by_id(tid);
	if (target == NULL) {
		log_error("target %d not found", tid);
		err = -EINVAL;
		goto out;
	}

	if (type == key_session) {
		for (i = 0; i < session_key_last; i++)
			params[i].val = target->session_params[i];
	} else {
		for (i = 0; i < target_key_last; i++)
			params[i].val = target->target_params[i];
	}

out:
	return err;
}

int config_params_set(u32 tid, u64 sid, int type, u32 partial,
	struct iscsi_param *params)
{
	int err, i;
	struct target *target;

	if (sid != 0) {
		err = kernel_params_set(tid, sid, type, partial, params);
		goto out;
	}

	err = 0;

	target = target_find_by_id(tid);
	if (target == 0) {
		log_error("target %d not found", tid);
		err = -EINVAL;
		goto out;
	}

	if (partial == 0)
		partial = (typeof(partial))-1;

	if (type == key_session) {
		for (i = 0; i < session_key_last; i++) {
			if (partial & (1 << i)) {
				err = params_check_val(session_keys, i, &params[i].val);
				if (err < 0) {
					log_error("Wrong value %u for parameter %s\n",
						params[i].val, session_keys[i].name);
					goto out;
				}
			}
		}
		for (i = 0; i < session_key_last; i++) {
			if (partial & (1 << i))
				target->session_params[i] = params[i].val;
		}
	} else {
		for (i = 0; i < target_key_last; i++) {
			if (partial & (1 << i)) {
				err = params_check_val(target_keys, i, &params[i].val);
				if (err < 0) {
					log_error("Wrong value %u for parameter %s\n",
						params[i].val, target_keys[i].name);
					goto out;
				}
			}
		}
		for (i = 0; i < target_key_last; i++) {
			if (partial & (1 << i))
				target->target_params[i] = params[i].val;
		}
	}

out:
	return err;
}

int config_parse_main(const char *data, u32 cookie)
{
	char buf[BUFSIZE];
	char *p, *q, *n;
	int idx, offset = 0;
	u32 val;
	int res = 0;
	struct target *target = NULL;
	int global_section = 1; /* supposed to be bool and true */
	int parsed_something = 0; /* supposed to be bool and false */
	int stop_on_errors = (cookie != 0);

	while (config_gets(buf, sizeof(buf), data, &offset)) {
		parsed_something = 1;
		/*
		 * If stop_on_errors is false, let's always continue parsing
		 * and only report errors.
		 */
		if (stop_on_errors && (res != 0))
			goto out_target_free;

		q = buf;
		p = config_sep_string(&q);
		if ((*p == '#') || (*p == '\0'))
			continue;

		if (!strcasecmp(p, "Target")) {
			global_section = 0;

			if (target != NULL) {
				res = target_add(target, NULL, cookie);
				if (res != 0)
					target_free(target);
			}

			target = NULL;
			p = config_sep_string(&q);
			if (*p == '\0') {
				log_error("Target name required on %s\n", q);
				continue;
			}

			n = config_sep_string(&q);
			if (*n != '\0') {
				log_error("Unexpected parameter value %s\n", n);
				res = -EINVAL;
				continue;
			}

			log_debug(1, "Creating target %s", p);
			res = target_create(p, &target);
			if (res != 0)
				goto out;
		} else if (!strcasecmp(p, "Alias") && target) {
			;
		} else if (!((idx = params_index_by_name(p, target_keys)) < 0) && (target != NULL)) {
			char *str = config_sep_string(&q);

			n = config_sep_string(&q);
			if (*n != '\0') {
				log_error("Unexpected parameter value %s\n", n);
				res = -EINVAL;
				continue;
			}

			res = params_str_to_val(target_keys, idx, str, &val);
			if (res < 0) {
				log_error("Wrong value %s for parameter %s\n",
					str, target_keys[idx].name);
				continue;
			}

			res = params_check_val(target_keys, idx, &val);
			if (res < 0) {
				log_error("Wrong value %u for parameter %s\n",
					val, target_keys[idx].name);
				continue;
			}
			target->target_params[idx] = val;
		} else if (!((idx = params_index_by_name(p, session_keys)) < 0) && (target != NULL)) {
			char *str = config_sep_string(&q);

			n = config_sep_string(&q);
			if (*n != '\0') {
				log_error("Unexpected parameter value %s\n", n);
				res = -EINVAL;
				continue;
			}

			res = params_str_to_val(session_keys, idx, str, &val);
			if (res < 0) {
				log_error("Wrong value %s for parameter %s\n",
					str, session_keys[idx].name);
				continue;
			}

			res = params_check_val(session_keys, idx, &val);
			if (res < 0) {
				log_error("Wrong value %u for parameter %s\n",
					val, session_keys[idx].name);
				continue;
			}
			target->session_params[idx] = val;
		} else if (!((idx = params_index_by_name_numwild(p, user_keys)) < 0) &&
			   ((target != NULL) || global_section)) {
			char *name, *pass;

			name = config_sep_string(&q);
			pass = config_sep_string(&q);

			n = config_sep_string(&q);
			if (*n != '\0') {
				log_error("Unexpected parameter value %s\n", n);
				res = -EINVAL;
				continue;
			}

			res = __config_account_add(target, idx, name, pass, p,
					(target == 0), 0);
			if (res < 0)
				continue;
		} else if (global_section &&
			   (!strcasecmp(p, ISCSI_ISNS_SERVER_ATTR_NAME) ||
			    !strcasecmp(p, ISCSI_ISNS_ACCESS_CONTROL_ATTR_NAME)))
			continue;
		else {
			log_error("Unknown or unexpected param: %s\n", p);
			res = -EINVAL;
			continue;
		}
	}

	if (stop_on_errors && (res != 0))
		goto out_target_free;

	if (target != NULL) {
		res = target_add(target, NULL, cookie);
		if (res != 0)
			goto out_target_free;
	}

out:
	if (stop_on_errors) {
		if ((res == 0) && !parsed_something)
			res = -ENOENT;
	} else
		res = 0;

	return res;

out_target_free:
	if (target != NULL)
		target_free(target);
	goto out;
}

static int config_isns_load(const char *config)
{
	char buf[BUFSIZE];
	int offset = 0;
	char *p, *q;

	while (config_gets(buf, sizeof(buf), config, &offset)) {
		q = buf;
		p = config_sep_string(&q);
		if ((*p == '\0') || (*p == '#'))
			continue;
		if (!strcasecmp(p, ISCSI_ISNS_SERVER_ATTR_NAME)) {
			isns_server = strdup(config_sep_string(&q));
		} else if (!strcasecmp(p, ISCSI_ISNS_ACCESS_CONTROL_ATTR_NAME)) {
			char *str = config_sep_string(&q);
			if (!strcasecmp(str, "No"))
				isns_access_control = 0;
			else
				isns_access_control = 1;
		}
	}

	return 0;
}

int config_load(const char *config_name)
{
	int i, err = 0, rc;
	int config;
	const char *cname;
	int size;
	char *buf;

	if (config_name != NULL)
		cname = config_name;
	else
		cname = CONFIG_FILE;

	config = open(cname, O_RDONLY);
	if (config == -1) {
		if ((errno == ENOENT) && (config_name == NULL)) {
#ifdef CONFIG_SCST_PROC
			log_debug(3, "Default config file %s not found",
				CONFIG_FILE);
#endif
			goto out;
		} else {
			err = -errno;
			log_error("Open config file %s failed: %s", cname,
				strerror(errno));
			goto out;
		}
	}

	size = lseek(config, 0, SEEK_END);
	if (size < 0) {
		err = -errno;
		log_error("lseek() failed: %s", strerror(errno));
		goto out_close;
	}

	buf = malloc(size+1);
	if (buf == NULL) {
		err = -ENOMEM;
		log_error("malloc() failed: %s", strerror(-err));
		goto out_close;
	}

	rc = lseek(config, 0, SEEK_SET);
	if (rc < 0) {
		err = -errno;
		log_error("lseek() failed: %s", strerror(errno));
		goto out_free;
	}

	i = 0;
	do {
		rc = read(config, &buf[i], size - i);
		if (rc < 0) {
			err = -errno;
			log_error("read() failed: %s", strerror(errno));
			goto out_free;
		} else if (rc == 0)
			break;
		i += rc;
	} while (i < size);

	size = i;
	buf[size] = '\0';

	err = config_isns_load(buf);
	if ((err == 0) && (isns_server != NULL)) {
		int rc = isns_init();
		if (rc != 0) {
			log_error("iSNS server %s init failed: %d", isns_server, rc);
			isns_exit();
		}
	}

	config_parse_main(buf, 0);

out_free:
	free(buf);

out_close:
	close(config);

out:
	return err;
}
