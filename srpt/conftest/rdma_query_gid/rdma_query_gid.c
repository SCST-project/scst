#include <linux/module.h>
#include <rdma/ib_cache.h>

static int modinit(void)
{
	return rdma_query_gid(NULL, 0, 0, NULL);
}

module_init(modinit);
