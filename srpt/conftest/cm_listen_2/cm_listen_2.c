#include <linux/module.h>
#include <rdma/ib_cm.h>

static int __init modinit(void)
{
	return ib_cm_listen(NULL, 0, 0);
}

module_init(modinit);

MODULE_LICENSE("GPL");
