/* SPDX-License-Identifier: GPL-2.0-only */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int probe_open(const char *path, int flags, ...);
static ssize_t probe_read(int fd, void *buf, size_t size);
static int probe_close(int fd);

/* Compile the production implementation; only the entropy I/O is replaced. */
#define open probe_open
#define read probe_read
#define close probe_close
#include "chap.c"
#undef open
#undef read
#undef close

static void check(bool condition, int line, const char *expression)
{
	if (!condition) {
		fprintf(stderr, "line %d: %s\n", line, expression);
		exit(EXIT_FAILURE);
	}
}

#define CHECK(condition) check(!!(condition), __LINE__, #condition)

static const char *scenario;
static unsigned int opens, closes, reads, current_reads;
static unsigned int challenge_keys;
static char encoded[CHAP_CHALLENGE_MAX * 2 + 8];
static unsigned char fill;

static bool is_case(const char *name)
{
	return strcmp(scenario, name) == 0;
}

static int probe_open(const char *path, int flags, ...)
{
	if (strcmp(path, "/dev/urandom") || flags != O_RDONLY) {
		fprintf(stderr, "unexpected entropy open\n");
		exit(2);
	}
	opens++;
	current_reads = 0;
	if (is_case("open-error")) {
		errno = EACCES;
		return -1;
	}
	return 123;
}

static ssize_t probe_read(int fd, void *buf, size_t size)
{
	if (fd != 123 || !size || size > sizeof(unsigned int)) {
		fprintf(stderr, "unexpected entropy read\n");
		exit(2);
	}
	reads++;
	current_reads++;
	if (is_case("interrupted-short") && reads == 1) {
		errno = EINTR;
		return -1;
	}
	if (is_case("read-error") ||
	    (is_case("payload-error") && opens == 2 && current_reads == 2)) {
		errno = EIO;
		return -1;
	}
	if (is_case("eof") || (is_case("partial-eof") && current_reads == 2))
		return 0;
	if ((is_case("interrupted-short") && reads == 2) ||
	    (is_case("partial-eof") && current_reads == 1) ||
	    (is_case("payload-error") && opens == 2 && current_reads == 1))
		size = 1;
	memset(buf, fill, size);
	return size;
}

static int probe_close(int fd)
{
	if (fd != 123) {
		fprintf(stderr, "unexpected entropy close\n");
		exit(2);
	}
	closes++;
	return 0;
}

char *text_key_find(struct connection *conn, const char *key)
{
	static char algorithm[2];

	/* CHAP negotiation parses a writable value with strsep(). */
	memcpy(algorithm, "5", sizeof(algorithm));

	return strcmp(key, "CHAP_A") == 0 ? algorithm : NULL;
}

void text_key_add(struct connection *conn, const char *key, const char *value)
{
	if (strcmp(key, "CHAP_C") == 0) {
		challenge_keys++;
		snprintf(encoded, sizeof(encoded), "%s", value);
	}
}

bool af_alg_supported(char *algorithm)
{
	return false;
}

int main(int argc, char **argv)
{
	struct connection conn = { 0 };
	bool success;
	unsigned int value, i;
	int result;

	CHECK(argc == 2);
	scenario = argv[1];
	success = is_case("zero") || is_case("high-bit") || is_case("interrupted-short");
	CHECK(success || is_case("open-error") || is_case("read-error") ||
	      is_case("eof") || is_case("partial-eof") || is_case("payload-error"));
	fill = is_case("zero") ? 0 : 0xff;
	value = fill ? UINT_MAX : 0;
	result = chap_initiator_auth_create_challenge(&conn);
	if (success) {
		CHECK(result == 0);
		CHECK(conn.auth.chap.challenge_size >= CHAP_CHALLENGE_MAX / 2);
		CHECK(conn.auth.chap.challenge_size < CHAP_CHALLENGE_MAX);
		CHECK(conn.auth.chap.challenge_size == value % (CHAP_CHALLENGE_MAX / 2) +
		      CHAP_CHALLENGE_MAX / 2);
		CHECK(challenge_keys == 1);
		CHECK(strlen(encoded) == 2 + 2 * conn.auth.chap.challenge_size);
		CHECK(strncmp(encoded, "0x", 2) == 0);
		for (i = 0; i < conn.auth.chap.challenge_size; i++) {
			CHECK((unsigned char)conn.auth.chap.challenge[i] == fill);
			CHECK(encoded[2 + 2 * i] == (fill ? 'f' : '0'));
			CHECK(encoded[3 + 2 * i] == (fill ? 'f' : '0'));
		}
		CHECK(opens == 1 + conn.auth.chap.challenge_size);
	} else {
		CHECK(result == CHAP_TARGET_ERROR);
		CHECK(challenge_keys == 0);
		CHECK(!conn.auth.chap.challenge);
		CHECK(conn.auth.chap.challenge_size == 0);
	}
	CHECK(closes == opens - (is_case("open-error") ? 1 : 0));
	if (is_case("interrupted-short"))
		CHECK(reads == opens + 2);
	if (is_case("partial-eof"))
		CHECK(reads == 2);
	if (is_case("payload-error"))
		CHECK(opens == 2 && reads == 3);
	free(conn.auth.chap.challenge);
	puts("ok");
	return 0;
}
