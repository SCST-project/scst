#include <linux/module.h>

static int modinit(void)
{
	return PRE_CFLAGS_MACRO;
}

module_init(modinit);
