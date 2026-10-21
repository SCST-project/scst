/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Keep both production handlers; no socket or daemon entry point is invoked. */
#include "isns.c"

static void check(bool condition, int line, const char *expression)
{
	if (!condition) {
		fprintf(stderr, "line %d: %s\n", line, expression);
		exit(EXIT_FAILURE);
	}
}

#define CHECK(condition) check(!!(condition), __LINE__, #condition)

static struct target probe_target;

void __log(const char *func, int line, int prio, int level, const char *fmt, ...)
{
}

struct target *target_find_by_name(const char *name)
{
	return strcmp(name, probe_target.name) == 0 ? &probe_target : NULL;
}

struct guarded_pdu {
	void *mapping;
	size_t size;
	struct isns_hdr *hdr;
};

static int make_pdu(struct guarded_pdu *pdu, size_t length)
{
	long page = sysconf(_SC_PAGESIZE);

	CHECK(page > 0 && length + sizeof(*pdu->hdr) < (size_t)page);
	pdu->size = 2 * (size_t)page;
	pdu->mapping = mmap(NULL, pdu->size, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(pdu->mapping != MAP_FAILED);
	CHECK(mprotect((char *)pdu->mapping + page, page, PROT_NONE) == 0);
	/* Any read or write past the declared payload reaches the guard page. */
	pdu->hdr = (struct isns_hdr *)((char *)pdu->mapping + page -
				      sizeof(*pdu->hdr) - length);
	memset(pdu->hdr, 0, sizeof(*pdu->hdr) + length);
	pdu->hdr->length = htons(length);
	pdu->hdr->transaction = htons(17);
	return 0;
}

static void put_tlv(void *buffer, uint32_t tag, uint32_t length, const void *value)
{
	struct isns_tlv *tlv = buffer;

	tlv->tag = htonl(tag);
	tlv->length = htonl(length);
	if (value)
		memcpy(tlv->value, value, length);
}

static int check_short_scn(void)
{
	size_t length;

	for (length = 0; length < sizeof(struct isns_tlv); length++) {
		struct guarded_pdu pdu;

		CHECK(make_pdu(&pdu, length) == 0);
		CHECK(!print_scn_pdu(pdu.hdr));
		CHECK(munmap(pdu.mapping, pdu.size) == 0);
	}
	return 0;
}

static int check_scn(const char *scenario)
{
	struct guarded_pdu pdu;
	uint32_t bitmap = htonl(1);
	bool valid = strcmp(scenario, "scn-valid") == 0;
	bool delimiter = strcmp(scenario, "scn-delimiter") == 0;
	bool tail = strcmp(scenario, "scn-tail") == 0;
	bool unaligned = strcmp(scenario, "scn-unaligned") == 0;
	bool oversized = strcmp(scenario, "scn-oversized") == 0;
	size_t length = valid ? 24 : delimiter ? 20 : tail ? 16 : unaligned ? 9 : 12;
	char *name;

	CHECK(valid || delimiter || tail || unaligned || oversized ||
	      strcmp(scenario, "scn-truncated") == 0);
	CHECK(make_pdu(&pdu, length) == 0);
	if (valid) {
		put_tlv(pdu.hdr->pdu, ISNS_ATTR_ISCSI_NAME, 4, "new");
		put_tlv((char *)pdu.hdr->pdu + 12, ISNS_ATTR_ISCSI_SCN_BITMAP, 4, &bitmap);
	} else if (delimiter) {
		put_tlv(pdu.hdr->pdu, 0, 0, NULL);
		put_tlv((char *)pdu.hdr->pdu + 8, ISNS_ATTR_ISCSI_NAME, 4, "new");
	} else if (tail) {
		put_tlv(pdu.hdr->pdu, ISNS_ATTR_ISCSI_NAME, 4, "oldX");
	} else {
		put_tlv(pdu.hdr->pdu, ISNS_ATTR_ISCSI_NAME,
			oversized ? UINT32_MAX : unaligned ? 1 : 8, NULL);
	}
	name = print_scn_pdu(pdu.hdr);
	if (valid || delimiter) {
		CHECK(name && strcmp(name, "new") == 0);
	} else {
		CHECK(!name);
		if (tail)
			CHECK(memcmp((char *)pdu.hdr->pdu + 8, "oldX", 4) == 0);
	}
	CHECK(munmap(pdu.mapping, pdu.size) == 0);
	return 0;
}

static int check_query(size_t length, const char *scenario)
{
	struct guarded_pdu pdu;
	struct isns_initiator *original, *current;
	struct isns_qry_mgmt *mgmt;
	uint32_t node_type = htonl(ISNS_NODE_INITIATOR);
	bool valid = strcmp(scenario, "query-valid") == 0;
	bool tail = strcmp(scenario, "query-tail") == 0;

	CHECK(make_pdu(&pdu, length) == 0);
	INIT_LIST_HEAD(&qry_list);
	INIT_LIST_HEAD(&probe_target.isns_head);
	snprintf(probe_target.name, sizeof(probe_target.name), "target");
	original = calloc(1, sizeof(*original));
	mgmt = calloc(1, sizeof(*mgmt));
	CHECK(original && mgmt);
	snprintf(original->name, sizeof(original->name), "old");
	list_add_tail(&original->ilist, &probe_target.isns_head);
	mgmt->transaction = 17;
	snprintf(mgmt->name, sizeof(mgmt->name), "%s", probe_target.name);
	list_add_tail(&mgmt->qlist, &qry_list);
	if (valid || tail) {
		put_tlv((char *)pdu.hdr->pdu + 4, ISNS_ATTR_ISCSI_NAME, 4, "new");
		put_tlv((char *)pdu.hdr->pdu + 16, ISNS_ATTR_ISCSI_NODE_TYPE, 4, &node_type);
	} else if (strcmp(scenario, "query-oversized") == 0) {
		put_tlv((char *)pdu.hdr->pdu + 4, ISNS_ATTR_ISCSI_NAME, UINT32_MAX, NULL);
	} else if (strcmp(scenario, "query-error") == 0) {
		pdu.hdr->pdu[0] = htonl(3);
	}
	qry_rsp_handle(pdu.hdr);
	CHECK(list_empty(&qry_list));
	CHECK(!list_empty(&probe_target.isns_head));
	current = list_entry(probe_target.isns_head.q_forw, struct isns_initiator, ilist);
	CHECK(current->ilist.q_forw == &probe_target.isns_head);
	CHECK(strcmp(current->name, valid ? "new" : "old") == 0);
	if (!valid)
		CHECK(current == original);
	free_all_acl(&probe_target);
	CHECK(munmap(pdu.mapping, pdu.size) == 0);
	return 0;
}

int main(int argc, char **argv)
{
	const char *scenario;
	size_t length;

	CHECK(argc == 2);
	scenario = argv[1];
	if (strcmp(scenario, "scn-short") == 0) {
		CHECK(check_short_scn() == 0);
	} else if (strncmp(scenario, "scn-", 4) == 0) {
		CHECK(check_scn(scenario) == 0);
	} else if (strcmp(scenario, "query-short") == 0) {
		for (length = 0; length < 4; length++)
			CHECK(check_query(length, scenario) == 0);
	} else if (strcmp(scenario, "query-short-tlv") == 0) {
		for (length = 5; length < 12; length++)
			CHECK(check_query(length, scenario) == 0);
	} else if (strcmp(scenario, "query-valid") == 0) {
		CHECK(check_query(28, scenario) == 0);
	} else if (strcmp(scenario, "query-tail") == 0) {
		CHECK(check_query(32, scenario) == 0);
	} else if (strcmp(scenario, "query-oversized") == 0) {
		CHECK(check_query(12, scenario) == 0);
	} else if (strcmp(scenario, "query-error") == 0) {
		CHECK(check_query(4, scenario) == 0);
	} else {
		CHECK(0);
	}
	puts("ok");
	return 0;
}
