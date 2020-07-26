#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int __init modinit(void)
{
	return ib_query_device(NULL, NULL);
}

module_init(modinit);

MODULE_LICENSE("GPL");
