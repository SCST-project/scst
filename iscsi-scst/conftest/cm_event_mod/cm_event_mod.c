#include <linux/module.h>
#include <rdma/ib_cm.h>

static int h(struct ib_cm_id *cm_id, const struct ib_cm_event *event)
{
	return 0;
}

static int modinit(void)
{
	return ib_create_cm_id(NULL, h, NULL) != NULL;
}

module_init(modinit);
