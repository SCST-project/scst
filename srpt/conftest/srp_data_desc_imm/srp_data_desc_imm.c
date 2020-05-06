#include <linux/module.h>
#include <scsi/srp.h>

static int __init modinit(void)
{
	return SRP_DATA_DESC_IMM;
}

module_init(modinit);
