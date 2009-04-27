/*
 * iSNS functions
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2007 - 2009 Vladislav Bolkhovitin
 * Copyright (C) 2007 - 2009 ID7 Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "iscsid.h"
#include "isns_proto.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUFSIZE (1 << 18)

struct isns_io {
	char *buf;
	int offset;
};

struct isns_qry_mgmt {
	char name[ISCSI_NAME_LEN];
	uint16_t transaction;
	struct __qelem qlist;
};

struct isns_initiator {
	char name[ISCSI_NAME_LEN];
	struct __qelem ilist;
};

static LIST_HEAD(qry_list);
static uint16_t scn_listen_port;
static int use_isns, use_isns_ac, isns_fd, scn_listen_fd, scn_fd;
static struct isns_io isns_rx, scn_rx;
static char *rxbuf;
static uint16_t transaction;
static uint32_t current_timeout = 30; /* seconds */
static char eid[ISCSI_NAME_LEN];
static uint8_t ip[16]; /* SCST iSCSI supports only one portal */
static struct sockaddr_storage ss;

int isns_scn_access(uint32_t tid, int fd, char *name)
{
	struct isns_initiator *ini;
	struct target *target = target_find_by_id(tid);

	if (!use_isns || !use_isns_ac)
		return 0;

	if (!target)
		return -EPERM;

	list_for_each_entry(ini, &target->isns_head, ilist) {
		if (!strcmp(ini->name, name))
			return 0;
	}
	return -EPERM;
}

static int isns_get_ip(int fd)
{
	int err, i;
	uint32_t addr;
	struct sockaddr_storage lss;
	socklen_t slen = sizeof(lss);

	err = getsockname(fd, (struct sockaddr *) &lss, &slen);
	if (err) {
		log_error("getsockname error: %s!", gai_strerror(err));
		return err;
	}

	err = getnameinfo((struct sockaddr *) &lss, sizeof(lss),
			  eid, sizeof(eid), NULL, 0, 0);
	if (err) {
		log_error("getaddrinfo error: %s!", gai_strerror(err));
		return err;
	}

	switch (lss.ss_family) {
	case AF_INET:
		addr = (((struct sockaddr_in *) &lss)->sin_addr.s_addr);

		ip[10] = ip[11] = 0xff;
		ip[15] = 0xff & (addr >> 24);
		ip[14] = 0xff & (addr >> 16);
		ip[13] = 0xff & (addr >> 8);
		ip[12] = 0xff & addr;
		break;
	case AF_INET6:
		for (i = 0; i < ARRAY_SIZE(ip); i++)
			ip[i] = ((struct sockaddr_in6 *) &lss)->sin6_addr.s6_addr[i];
		break;
	}

	return 0;
}

static int isns_connect(void)
{
	int fd, err;

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_error("unable to create (%s) %d!", strerror(errno),
			  ss.ss_family);
		return -1;
	}

	err = connect(fd, (struct sockaddr *) &ss, sizeof(ss));
	if (err < 0) {
		log_error("unable to connect (%s) %d!", strerror(errno),
			  ss.ss_family);
		close(fd);
		return -1;
	}

	log_error("%s %d: new connection %d", __func__, __LINE__, fd);

	if (!strlen(eid)) {
		err = isns_get_ip(fd);
		if (err) {
			close(fd);
			return -1;
		}
	}

	isns_fd = fd;
	isns_set_fd(fd, scn_listen_fd, scn_fd);

	return fd;
}

static void isns_hdr_init(struct isns_hdr *hdr, uint16_t function,
			  uint16_t length, uint16_t flags,
			  uint16_t trans, uint16_t sequence)
{
	hdr->version = htons(0x0001);
	hdr->function = htons(function);
	hdr->length = htons(length);
	hdr->flags = htons(flags);
	hdr->transaction = htons(trans);
	hdr->sequence = htons(sequence);
}

static int isns_tlv_set(struct isns_tlv **tlv, uint32_t tag, uint32_t length,
			void *value)
{
	if (length)
		memcpy((*tlv)->value, value, length);
	if (length % ISNS_ALIGN)
		length += (ISNS_ALIGN - (length % ISNS_ALIGN));

	(*tlv)->tag = htonl(tag);
	(*tlv)->length = htonl(length);

	length += sizeof(struct isns_tlv);
	*tlv = (struct isns_tlv *) ((char *) *tlv + length);

	return length;
}

static int isns_scn_deregister(char *name)
{
	int err;
	uint16_t flags, length = 0;
	char buf[2048];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;

	if (!isns_fd)
		if (isns_connect() < 0)
			return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name) + 1,
			       name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name) + 1,
			       name);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define correct_scn_flag_endiannes(x)						\
{								\
	x = (x & 0x55555555) << 1 | (x & 0xaaaaaaaa) >> 1;	\
	x = (x & 0x33333333) << 2 | (x & 0xcccccccc) >> 2;	\
	x = (x & 0x0f0f0f0f) << 4 | (x & 0xf0f0f0f0) >> 4;	\
	x = (x & 0x00ff00ff) << 8 | (x & 0xff00ff00) >> 8;	\
	x = (x & 0x0000ffff) << 16 | (x & 0xffff0000) >> 16;	\
}
#else
#define correct_scn_flag_endiannes(x) { }
#endif

static int isns_scn_register(void)
{
	int err;
	uint16_t flags, length = 0;
	uint32_t scn_flags;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	struct target *target;

	if (list_empty(&targets_list))
		return 0;

	if (!isns_fd)
		if (isns_connect() < 0)
			return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	target = list_entry(targets_list.q_forw, struct target, tlist);

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME,
			       strlen(target->name) + 1, target->name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME,
			       strlen(target->name) + 1, target->name);
	length += isns_tlv_set(&tlv, 0, 0, 0);

	scn_flags = ISNS_SCN_FLAG_INITIATOR | ISNS_SCN_FLAG_OBJECT_REMOVE |
		ISNS_SCN_FLAG_OBJECT_ADDED | ISNS_SCN_FLAG_OBJECT_UPDATED;
	correct_scn_flag_endiannes(scn_flags);
	scn_flags = htonl(scn_flags);

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_SCN_BITMAP,
			       sizeof(scn_flags), &scn_flags);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_REG, length, flags, ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

static int isns_attr_query(char *name)
{
	int err;
	uint16_t flags, length = 0;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	struct target *target;
	uint32_t node = htonl(ISNS_NODE_INITIATOR);
	struct isns_qry_mgmt *mgmt;

	if (list_empty(&targets_list))
		return 0;

	if (!isns_fd)
		if (isns_connect() < 0)
			return 0;

	mgmt = malloc(sizeof(*mgmt));
	if (!mgmt)
		return 0;
	insque(&mgmt->qlist, &qry_list);

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	if (name)
		snprintf(mgmt->name, sizeof(mgmt->name), "%s", name);
	else {
		mgmt->name[0] = '\0';
		target = list_entry(targets_list.q_forw, struct target, tlist);
		name = target->name;
	}

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name) + 1,
			       name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE,
			       sizeof(node), &node);
	length += isns_tlv_set(&tlv, 0, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_IP_ADDRESS, 0, 0);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_QRY, length, flags,
		      ++transaction, 0);
	mgmt->transaction = transaction;

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

static int isns_deregister(void)
{
	int err;
	uint16_t flags, length = 0;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	struct target *target;

	if (list_empty(&targets_list))
		return 0;

	if (!isns_fd)
		if (isns_connect() < 0)
			return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	target = list_entry(targets_list.q_forw, struct target, tlist);

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME,
			       strlen(target->name) + 1, target->name);
	length += isns_tlv_set(&tlv, 0, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER,
			       strlen(eid) + 1, eid);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));
	return 0;
}

int isns_target_register(char *name)
{
	char buf[4096];
	uint16_t flags = 0, length = 0;
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	uint32_t port = htonl(server_port);
	uint32_t node = htonl(ISNS_NODE_TARGET);
	uint32_t type = htonl(2);
	struct target *target;
	int err, initial = list_length_is_one(&targets_list);

	if (!use_isns)
		return 0;

	if (!isns_fd)
		if (isns_connect() < 0)
			return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

        target = list_entry(targets_list.q_back, struct target, tlist);
        length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME,
			       strlen(target->name) + 1, target->name);

	length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER,
			       strlen(eid) + 1, eid);

	length += isns_tlv_set(&tlv, 0, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER,
			       strlen(eid) + 1, eid);
	if (initial) {
		length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_PROTOCOL,
				       sizeof(type), &type);
		length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_IP_ADDRESS,
				       sizeof(ip), &ip);
		length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_PORT,
				       sizeof(port), &port);
		flags = ISNS_FLAG_REPLACE;

		if (scn_listen_port) {
			uint32_t sport = htonl(scn_listen_port);
			length += isns_tlv_set(&tlv, ISNS_ATTR_SCN_PORT,
					       sizeof(sport), &sport);
		}
	}

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name) + 1,
			       name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE,
			       sizeof(node), &node);

	flags |= ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_REG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

	if (scn_listen_port)
		isns_scn_register();

	isns_attr_query(name);

	return 0;
}

static void free_all_acl(struct target *target)
{
	struct isns_initiator *ini;

	while (!list_empty(&target->isns_head)) {
		ini = list_entry(target->isns_head.q_forw, typeof(*ini), ilist);
		remque(&ini->ilist);
	}
}

int isns_target_deregister(char *name)
{
	char buf[4096];
	uint16_t flags, length = 0;
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	int err, last = list_empty(&targets_list);
	struct target *target;

	target = target_find_by_name(name);
	if (target)
		free_all_acl(target);

	if (!use_isns)
		return 0;

	if (!isns_fd)
		if (isns_connect() < 0)
			return 0;

	isns_scn_deregister(name);

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name) + 1,
			       name);
	length += isns_tlv_set(&tlv, 0, 0, 0);
	if (last)
		length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER,
				       strlen(eid) + 1, eid);
	else
		length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME,
				       strlen(name) + 1, name);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

static int recv_hdr(int fd, struct isns_io *rx, struct isns_hdr *hdr)
{
	int err;

	if (rx->offset < sizeof(*hdr)) {
		err = read(fd, rx->buf + rx->offset,
			   sizeof(*hdr) - rx->offset);
		if (err < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return -EAGAIN;
			log_error("header read error %d %d %d %d",
				  fd, err, errno, rx->offset);
			return -1;
		} else if (err == 0)
			return -1;

		log_debug(1, "header %d %d bytes!", fd, err);
		rx->offset += err;

		if (rx->offset < sizeof(*hdr)) {
			log_debug(1, "header wait %d %d", rx->offset, err);
			return -EAGAIN;
		}
	}

	return 0;
}

#define get_hdr_param(hdr, function, length, flags, transaction, sequence)	\
{										\
	function = ntohs(hdr->function);					\
	length = ntohs(hdr->length);						\
	flags = ntohs(hdr->flags);						\
	transaction = ntohs(hdr->transaction);					\
	sequence = ntohs(hdr->sequence);					\
}

static int recv_pdu(int fd, struct isns_io *rx, struct isns_hdr *hdr)
{
	uint16_t function, length, flags, transaction, sequence;
	int err;

	err = recv_hdr(fd, rx, hdr);
	if (err)
		return err;

	/* Now we got a complete header */
	get_hdr_param(hdr, function, length, flags, transaction, sequence);
	log_debug(1, "got a header %x %u %x %u %u", function, length, flags,
		  transaction, sequence);

	if (length + sizeof(*hdr) > BUFSIZE) {
		log_error("ToDo: we cannot handle this yet %u!", length);
		return -1;
	}

	if (rx->offset < length + sizeof(*hdr)) {
		err = read(fd, rx->buf + rx->offset,
			   length + sizeof(*hdr) - rx->offset);
		if (err < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return -EAGAIN;
			log_error("pdu read error %d %d %d %d",
				  fd, err, errno, rx->offset);
			return -1;
		} else if (err == 0)
			return -1;

		log_debug(1, "pdu %u %u", fd, err);
		rx->offset += err;

		if (rx->offset < length + sizeof(*hdr)) {
			log_error("pdu wait %d %d", rx->offset, err);
			return -EAGAIN;
		}
	}

	/* Now we got everything. */
	rx->offset = 0;

	return 0;
}

#define print_unknown_pdu(hdr)						\
{									\
	uint16_t function, length, flags, transaction, sequence;	\
	get_hdr_param(hdr, function, length, flags, transaction,	\
		      sequence)						\
	log_error("%s %d: unknown function %x %u %x %u %u",		\
		  __func__, __LINE__,				\
		  function, length, flags, transaction, sequence);	\
}

static char *print_scn_pdu(struct isns_hdr *hdr)
{
	struct isns_tlv *tlv = (struct isns_tlv *) hdr->pdu;
	uint16_t function, length, flags, transaction, sequence;
	char *name = NULL;

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	while (length) {
		uint32_t vlen = ntohl(tlv->length);

		switch (ntohl(tlv->tag)) {
		case ISNS_ATTR_ISCSI_NAME:
			log_error("scn name: %u, %s", vlen, (char *) tlv->value);
			if (!name)
				name = (char *) tlv->value;
			break;
		case ISNS_ATTR_TIMESTAMP:
			/* log_error("%u : %u : %" PRIx64, ntohl(tlv->tag), vlen, */
			/* *((uint64_t *) tlv->value)); */
			break;
		case ISNS_ATTR_ISCSI_SCN_BITMAP:
			log_error("scn bitmap : %x", *((uint32_t *) tlv->value));
			break;
		}

		length -= (sizeof(*tlv) + vlen);
		tlv = (struct isns_tlv *) ((char *) tlv->value + vlen);
	}

	return name;
}

static void qry_rsp_handle(struct isns_hdr *hdr)
{
	struct isns_tlv *tlv;
	uint16_t function, length, flags, transaction, sequence;
	uint32_t status = (uint32_t) (*hdr->pdu);
	struct isns_qry_mgmt *mgmt, *n;
	struct target *target;
	struct isns_initiator *ini;
	char *name = NULL;

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	list_for_each_entry_safe(mgmt, n, &qry_list, qlist) {
		if (mgmt->transaction == transaction) {
			remque(&mgmt->qlist);
			goto found;
		}
	}

	log_error("%s %d: transaction not found %u",
		  __func__, __LINE__, transaction);

	return;
found:

	if (status) {
		log_error("%s %d: error response %u",
			  __func__, __LINE__, status);

		goto free_qry_mgmt;
	}

	if (!strlen(mgmt->name)) {
		log_debug(1, "%s %d: skip %u",
			  __func__, __LINE__, transaction);
		goto free_qry_mgmt;
	}

	target = target_find_by_name(mgmt->name);
	if (!target) {
		log_error("%s %d: invalid tid %s",
			  __func__, __LINE__, mgmt->name);
		goto free_qry_mgmt;
	}

	free_all_acl(target);

	/* skip status */
	tlv = (struct isns_tlv *) ((char *) hdr->pdu + 4);
	length -= 4;

	while (length) {
		uint32_t vlen = ntohl(tlv->length);

		switch (ntohl(tlv->tag)) {
		case ISNS_ATTR_ISCSI_NAME:
			name = (char *) tlv->value;
			break;
		case ISNS_ATTR_ISCSI_NODE_TYPE:
			if (ntohl(*(tlv->value)) == ISNS_NODE_INITIATOR && name) {
				log_error("%s %d: %s", __func__, __LINE__,
					  (char *) name);
				ini = malloc(sizeof(*ini));
				if (!ini)
					goto free_qry_mgmt;
				snprintf(ini->name, sizeof(ini->name), "%s",
					 name);
				insque(&ini->ilist, &target->isns_head);
			} else
				name = NULL;
			break;
		default:
			name = NULL;
			break;
		}

		length -= (sizeof(*tlv) + vlen);
		tlv = (struct isns_tlv *) ((char *) tlv->value + vlen);
	}

free_qry_mgmt:
	free(mgmt);
}

int isns_handle(int is_timeout, int *timeout)
{
	int err;
	struct isns_io *rx = &isns_rx;
	struct isns_hdr *hdr = (struct isns_hdr *) rx->buf;
	uint32_t result;
	uint16_t function, length, flags, transaction, sequence;
	char *name = NULL;

	if (is_timeout)
		return isns_attr_query(NULL);

	err = recv_pdu(isns_fd, rx, hdr);
	if (err) {
		if (err == -EAGAIN)
			return err;
		log_debug(1, "%s %d: close connection %d", __func__, __LINE__,
			  isns_fd);
		close(isns_fd);
		isns_fd = 0;
		isns_set_fd(0, scn_listen_fd, scn_fd);
		return err;
	}

	get_hdr_param(hdr, function, length, flags, transaction, sequence);
	result = ntohl((uint32_t) hdr->pdu[0]);

	switch (function) {
	case ISNS_FUNC_DEV_ATTR_REG_RSP:
		break;
	case ISNS_FUNC_DEV_ATTR_QRY_RSP:
		qry_rsp_handle(hdr);
		break;
	case ISNS_FUNC_DEV_DEREG_RSP:
	case ISNS_FUNC_SCN_REG_RSP:
		break;
	case ISNS_FUNC_SCN:
		name = print_scn_pdu(hdr);
		if (name) {
			log_error("%s %d: %s", __func__, __LINE__, name);
			isns_attr_query(name);
		}
		break;
	default:
		print_unknown_pdu(hdr);
	}

	return 0;
}

static int scn_accept_connection(void)
{
	struct sockaddr_storage from;
	socklen_t slen;
	int fd, err, opt = 1;

	slen = sizeof(from);
	fd = accept(scn_listen_fd, (struct sockaddr *) &from, &slen);
	if (fd < 0) {
		log_error("%s %d: accept error: %s", __func__, __LINE__,
			  strerror(errno));
		return -errno;
	}
	log_error("Accept scn connection %d", fd);

	err = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	if (err)
		log_error("%s %d: %s\n", __func__, __LINE__,
			  strerror(errno));
	/* not critical, so ignore. */

	scn_fd = fd;
	isns_set_fd(isns_fd, scn_listen_fd, scn_fd);

	return 0;
}

static void send_scn_rsp(char *name, uint16_t transaction)
{
	char buf[1024];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	uint16_t flags, length = 0;
	int err;

	memset(buf, 0, sizeof(buf));
	*((uint32_t *) hdr->pdu) = 0;
	tlv = (struct isns_tlv *) ((char *) hdr->pdu + 4);
	length +=4;

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name) + 1,
			       name);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_RSP, length, flags, transaction, 0);

	err = write(scn_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));
}

int isns_scn_handle(int is_accept)
{
	int err;
	struct isns_io *rx = &scn_rx;
	struct isns_hdr *hdr = (struct isns_hdr *) rx->buf;
	uint16_t function, length, flags, transaction, sequence;
	char *name = NULL;

	log_error("%s %d: %d", __func__, __LINE__, is_accept);

	if (is_accept)
		return scn_accept_connection();

	err = recv_pdu(scn_fd, rx, hdr);
	if (err) {
		if (err == -EAGAIN)
			return err;
		log_debug(1, "%s %d: close connection %d", __func__, __LINE__,
			  scn_fd);
		close(scn_fd);
		scn_fd = 0;
		isns_set_fd(isns_fd, scn_listen_fd, 0);
		return err;
	}

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	switch (function) {
	case ISNS_FUNC_SCN:
		name = print_scn_pdu(hdr);
		break;
	default:
		print_unknown_pdu(hdr);
	}

	if (name) {
		send_scn_rsp(name, transaction);
		isns_attr_query(name);
	}

	return 0;
}

static int scn_init(char *addr)
{
	int fd, opt, err;
	struct sockaddr_storage lss;
	socklen_t slen;

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_error("%s %d: %s\n", __func__, __LINE__, strerror(errno));
		return -errno;
	}

	opt = 1;
	if (ss.ss_family == AF_INET6) {
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
		if (err)
			log_error("%s %d: %s\n", __func__, __LINE__,
				  strerror(errno));
		goto out;
	}

	err = listen(fd, 5);
	if (err) {
		log_error("%s %d: %s\n", __func__, __LINE__, strerror(errno));
		goto out;
	}

	slen = sizeof(lss);
	err = getsockname(fd, (struct sockaddr *) &lss, &slen);
	if (err) {
		log_error("%s %d: %s\n", __func__, __LINE__, strerror(errno));
		goto out;
	}

	/* protocol independent way ? */
	if (lss.ss_family == AF_INET6)
		scn_listen_port = ntohs(((struct sockaddr_in6 *) &lss)->sin6_port);
	else
		scn_listen_port = ntohs(((struct sockaddr_in *) &lss)->sin_port);

	log_error("scn listen port %u %d %d\n", scn_listen_port, fd, err);
out:
	if (err)
		close(fd);
	else {
		scn_listen_fd = fd;
		isns_set_fd(isns_fd, scn_listen_fd, scn_fd);
	}

	return err;
}

int isns_init(char *addr, int isns_ac)
{
	int err;
	char port[8];
	struct addrinfo hints, *res;

	snprintf(port, sizeof(port), "%d", ISNS_PORT);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(addr, (char *) &port, &hints, &res);
	if (err) {
		log_error("getaddrinfo error: %s, %s", gai_strerror(err), addr);
		return -1;
	}
	memcpy(&ss, res->ai_addr, sizeof(ss));
	freeaddrinfo(res);

	rxbuf = calloc(2, BUFSIZE);
	if (!rxbuf) {
		log_error("oom!");
		return -1;
	}

	scn_init(addr);

	isns_rx.buf = rxbuf;
	isns_rx.offset = 0;
	scn_rx.buf = rxbuf + BUFSIZE;
	scn_rx.offset = 0;

	use_isns = 1;
	use_isns_ac = isns_ac;

	return current_timeout * 1000;
}

void isns_exit(void)
{
	struct target *target;

	if (!use_isns)
		return;

	list_for_each_entry(target, &targets_list, tlist)
		isns_scn_deregister(target->name);

	isns_deregister();
	/* we can't receive events any more. */
	isns_set_fd(0, 0, 0);

	if (isns_fd)
		close(isns_fd);
	if (scn_listen_fd)
		close(scn_listen_fd);
	if (scn_fd)
		close(scn_fd);

	free(rxbuf);
}
