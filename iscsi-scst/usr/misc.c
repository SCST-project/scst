/*
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
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

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <string.h>
#include <errno.h>

#include "iscsid.h"

void set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);

	if (res != -1) {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			log_warning("unable to set fd flags (%s)!", strerror(errno));
	} else
		log_warning("unable to get fd flags (%s)!", strerror(errno));
}

void sock_set_keepalive(int sock, int timeout)
{
	if (timeout) { /* timeout [s] */
		int opt = 2;

		if (setsockopt(sock, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt)))
			log_warning("unable to set TCP_KEEPCNT on server socket (%s)!", strerror(errno));

		if (setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, &timeout, sizeof(timeout)))
			log_warning("unable to set TCP_KEEPIDLE on server socket (%s)!", strerror(errno));

		opt = 3;
		if (setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)))
			log_warning("unable to set KEEPINTVL on server socket (%s)!", strerror(errno));

		opt = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)))
			log_warning("unable to set SO_KEEPALIVE on server socket (%s)!", strerror(errno));
	}
}

