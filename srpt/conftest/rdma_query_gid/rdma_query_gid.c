#include <linux/module.h>
#include <rdma/ib_cache.h>

static int __init modinit(void)
{
	return rdma_query_gid(NULL, 0, 0, NULL);
}

module_init(modinit);

MODULE_LICENSE("GPL");
