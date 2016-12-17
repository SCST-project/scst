#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int modinit(void)
{
	return ib_query_device(NULL, NULL);
}

module_init(modinit);
