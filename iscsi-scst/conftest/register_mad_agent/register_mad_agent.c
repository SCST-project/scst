#include <linux/module.h>
#include <rdma/ib_mad.h>

static int modinit(void)
{
	struct ib_mad_agent *a;

	a = ib_register_mad_agent(NULL, 0, 0, NULL, 0, NULL, NULL, NULL, 0);

	return a != 0;
}

module_init(modinit);
