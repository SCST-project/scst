#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int __init modinit(void)
{
	return rdma_destroy_ah(NULL, 0) != 0;

}

module_init(modinit);
MODULE_LICENSE("GPL");
