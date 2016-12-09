#include <linux/module.h>
#include <rdma/ib_verbs.h>

static struct ib_device *dev;

static int modinit(void)
{
	return dev->dma_ops != NULL;
}

module_init(modinit);
