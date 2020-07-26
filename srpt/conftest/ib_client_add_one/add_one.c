#include <linux/module.h>
#include <rdma/rdma_cm.h>

static int add_one(struct ib_device *device)
{
	return 0;
}

static struct ib_client test_client = {
	.add = add_one,
};

static int __init modinit(void)
{
	return ib_register_client(&test_client);
}

module_init(modinit);

MODULE_LICENSE("GPL");
