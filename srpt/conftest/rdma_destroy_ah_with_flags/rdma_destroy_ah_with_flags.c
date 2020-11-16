#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int __init modinit(void)
{
	rdma_destroy_ah(NULL, 0);

	return 0;
}

module_init(modinit);
MODULE_LICENSE("GPL");

MODULE_LICENSE("GPL");
