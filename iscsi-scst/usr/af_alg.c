// SPDX-License-Identifier: GPL-2.0-only
/*
 *  af_alg - wrapper functions to call AF_ALG hash algorithms.
 *
 *  Copyright (C) 2025 Brian Meagher <brian.meagher@ixsystems.com>
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

#include "af_alg.h"

#include <sys/socket.h>
#include <linux/if_alg.h>
#include <string.h>
#include <sys/param.h>
#include <stdbool.h>

int af_alg_init(const char *algorithm)
{
	int sockfd, datafd, algo_len;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};

	algo_len = strlen(algorithm);
	if (algo_len >= sizeof(sa.salg_name))
		return -1;

	sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sockfd == -1)
		return -1;

	/* +1 for null-terminator */
	memcpy(sa.salg_name, algorithm, algo_len + 1);

	if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		close(sockfd);
		return -1;
	}

	datafd = accept(sockfd, NULL, 0);
	if (datafd < 0) {
		close(sockfd);
		return -1;
	}
	close(sockfd);
	return datafd;
}

void af_alg_update(int datafd, const void *data_in, size_t len)
{
	send(datafd, data_in, len, MSG_MORE);
}

ssize_t af_alg_final(int datafd, void *out, size_t len)
{
	char buffer[1024];
	ssize_t bytes;

	send(datafd, NULL, 0, 0);

	bytes = recv(datafd, buffer, sizeof(buffer), 0);
	memcpy(out, buffer, MIN(len, bytes));
	return bytes;
}

bool af_alg_supported(char *alg)
{
	int sock = af_alg_init(alg);

	if (sock < 0)
		return false;
	close(sock);
	return true;
}
