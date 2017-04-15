#include <linux/module.h>
#include <rdma/ib_verbs.h>

static void remove_one(struct ib_device *device, void *client_data)
{
}

static int modinit(void)
{
	struct ib_client c = { .remove = remove_one };

	return c.remove != NULL;
}

module_init(modinit);
