#include <linux/module.h>
#include <linux/stddef.h>
#include <rdma/ib_verbs.h>

static int modinit(void)
{
	return offsetof(struct ib_pd, local_dma_lkey);
}

module_init(modinit);
