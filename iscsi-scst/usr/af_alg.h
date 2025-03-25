/* SPDX-License-Identifier: GPL-2.0-only */
/*
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

#ifndef SCST_AF_ALG_H
#define SCST_AF_ALG_H

#include <unistd.h>
#include <stdbool.h>

#define SCST_AF_ALG_SHA256_NAME  "sha256"
#define SCST_AF_ALG_SHA3_256_NAME  "sha3-256"

int af_alg_init(const char *algorithm);
int af_alg_update(int datafd, const void *data_in, size_t len);
ssize_t af_alg_final(int datafd, void *out, size_t len);
bool af_alg_supported(char *alg);

#endif
