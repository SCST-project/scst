#include <linux/module.h>
#include <rdma/rdma_cm.h>

static int modinit(void)
{
	return rdma_create_id(NULL, NULL, NULL, 0, 0) != NULL;

}

module_init(modinit);
