#include <linux/module.h>

static int modinit(void)
{
	return KCFLAGS_MACRO;
}

module_init(modinit);
