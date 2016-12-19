#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int modinit(void)
{
	return IB_EVENT_GID_CHANGE;
}

module_init(modinit);
