#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int modinit(void)
{
	return ib_dma_mapping_error(NULL, 0) != 0;
}

module_init(modinit);
