#include <linux/module.h>
#include <rdma/ib_verbs.h>

#undef ib_sg_dma_len

static int __init modinit(void)
{
	return ib_sg_dma_len != NULL;
}

module_init(modinit);

MODULE_LICENSE("GPL");
