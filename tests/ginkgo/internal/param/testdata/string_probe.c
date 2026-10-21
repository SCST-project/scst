/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Compile the production helper without starting the daemon. */
#include "param.c"

static void check(bool condition, int line, const char *expression)
{
	if (!condition) {
		fprintf(stderr, "line %d: %s\n", line, expression);
		exit(EXIT_FAILURE);
	}
}

#define CHECK(condition) check(!!(condition), __LINE__, #condition)

int main(int argc, char **argv)
{
	char *source_mapping, *destination_mapping, *source, *destination;
	const char *expected = NULL;
	ssize_t result;
	size_t capacity, copied, i;
	long page = sysconf(_SC_PAGESIZE);
	bool truncated;

	CHECK(argc == 2 && page > 16);
	truncated = strcmp(argv[1], "truncated") == 0 ||
		strcmp(argv[1], "one-byte") == 0;
	if (strcmp(argv[1], "zero") == 0) {
		capacity = 0;
	} else if (strcmp(argv[1], "one-byte") == 0) {
		capacity = 1;
	} else if (strcmp(argv[1], "empty") == 0) {
		capacity = 8;
		expected = "";
	} else if (strcmp(argv[1], "fits") == 0) {
		capacity = 8;
		expected = "abc";
	} else if (strcmp(argv[1], "exact-fit") == 0) {
		capacity = 4;
		expected = "abc";
	} else {
		CHECK(truncated);
		capacity = 8;
	}

	source_mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	destination_mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(source_mapping != MAP_FAILED && destination_mapping != MAP_FAILED);
	CHECK(mprotect(source_mapping + page, page, PROT_NONE) == 0);
	CHECK(mprotect(destination_mapping + page, page, PROT_NONE) == 0);
	source = source_mapping + page - capacity;
	destination = destination_mapping + page - capacity;
	destination[-1] = 0x5a;
	if (capacity) {
		memset(source, 'x', capacity);
		memset(destination, 0x5a, capacity);
		if (expected)
			memcpy(source, expected, strlen(expected) + 1);
	}

	/* A source without a NUL ends exactly at the inaccessible page. */
	result = iscsi_strscpy(destination, source, capacity);
	CHECK(destination[-1] == 0x5a);
	if (!capacity) {
		CHECK(result == -E2BIG);
	} else if (truncated) {
		CHECK(result == -E2BIG);
		for (i = 0; i < capacity - 1; i++)
			CHECK(destination[i] == 'x');
		CHECK(destination[capacity - 1] == '\0');
	} else {
		copied = strlen(expected) + 1;
		CHECK(result == (ssize_t)copied - 1);
		CHECK(memcmp(destination, expected, copied) == 0);
		for (i = copied; i < capacity; i++)
			CHECK(destination[i] == 0x5a);
	}
	CHECK(munmap(source_mapping, 2 * page) == 0);
	CHECK(munmap(destination_mapping, 2 * page) == 0);
	puts("ok");
	return 0;
}
