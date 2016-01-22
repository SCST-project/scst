/*
 *  Copyright (C) 2007 - 2016 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2016 SanDisk Corporation
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "iscsid.h"

int driver_major(const char *dev)
{
	FILE *f;
	char devname[256];
	char buf[256];
	int devn;

	f = fopen("/proc/devices", "r");
	if (!f) {
		devn = -errno;
		perror("Cannot open control path to the driver");
		goto out;
	}

	devn = -ENOENT;
	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "%d %s", &devn, devname) == 2 &&
		    devn > 0 && strcmp(devname, dev) == 0)
			break;
		devn = -ENOENT;
	}
	fclose(f);

	if (devn < 0)
		printf("cannot find %s in /proc/devices - "
		     "make sure the module is loaded\n", dev);

out:
	return devn;
}

int create_and_open_dev(const char *dev, int readonly)
{
	char devname[256];
	int devn;
	int ctlfd = -1;
	int err;
	int flags;

	devn = driver_major(dev);
	if (devn < 0) {
		err = devn;
		goto out;
	}

	sprintf(devname, "/dev/%s", dev);

	unlink(devname);
	if (mknod(devname, (S_IFCHR | 0600), (devn << 8))) {
		err = -errno;
		printf("cannot create %s %s\n", devname, strerror(errno));
		goto out;
	}

	if (readonly)
		flags = O_RDONLY;
	else
		flags = O_RDWR;

	err = ctlfd = open(devname, flags);
	if (ctlfd < 0) {
		err = -errno;
		printf("cannot open %s %s\n", devname, strerror(errno));
		goto out;
	}

out:
	return err;
}

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

