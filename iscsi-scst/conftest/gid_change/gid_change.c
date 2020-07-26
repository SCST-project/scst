#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int __init modinit(void)
{
	return IB_EVENT_GID_CHANGE;
}

module_init(modinit);

MODULE_LICENSE("GPL");
