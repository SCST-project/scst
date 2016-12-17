#include <linux/module.h>
#include <rdma/ib_verbs.h>

static void client_remove(struct ib_device *dev, void *client_data)
{
}

static int modinit(void)
{
	struct ib_client c = { .remove = client_remove };

	return (uintptr_t)c.remove;
}

module_init(modinit);
