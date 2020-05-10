#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int __init modinit(void)
{
	return (uintptr_t)ib_query_device;
}

module_init(modinit);
