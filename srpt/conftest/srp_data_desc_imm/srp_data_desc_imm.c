#include <linux/module.h>
#include <scsi/srp.h>

static int modinit(void)
{
	return SRP_DATA_DESC_IMM;
}

module_init(modinit);
