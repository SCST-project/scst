#include <linux/module.h>
#include <rdma/ib_cm.h>

static int modinit(void)
{
	return ib_cm_listen(NULL, 0, 0, NULL);
}

module_init(modinit);
