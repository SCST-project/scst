#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int modinit(void)
{
	return rdma_destroy_ah(NULL) != 0;

}

module_init(modinit);
