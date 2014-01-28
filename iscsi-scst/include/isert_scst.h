#ifndef _ISERT_SCST_U_H
#define _ISERT_SCST_U_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/socket.h>
#else
#include <sys/uio.h>
#include <sys/socket.h>
#endif

struct isert_addr_info {
	struct sockaddr_storage addr;
	size_t addr_len;
};

#define ISERT_MAX_PORTALS	32

#define SET_LISTEN_ADDR		_IOW('y', 0, struct isert_addr_info)
#define RDMA_CORK		_IOW('y', 1, int)
#define GET_PORTAL_ADDR		_IOW('y', 2, struct isert_addr_info)
#define DISCOVERY_SESSION		_IOW('y', 3, int)

#endif
