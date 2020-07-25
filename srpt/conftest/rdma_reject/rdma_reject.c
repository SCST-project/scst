#include <linux/module.h>
#include <rdma/rdma_cm.h>

static struct rdma_cm_id id;

static int __init modinit(void)
{
	return rdma_reject(&id, NULL, 0, 0);
}

module_init(modinit);
