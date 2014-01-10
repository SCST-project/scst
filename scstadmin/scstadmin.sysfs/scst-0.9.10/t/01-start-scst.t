#!perl

use strict;
use Test;

BEGIN {
    plan tests => ($> == 0) ? 3 : 0;
}

if ($> == 0) {
    ok(system("killall iscsi-scstd >/dev/null 2>&1; " .
	      "modprobe -r scst_local; " .
	      "modprobe -r iscsi-scst; " .
	      "modprobe -r ib_srpt; " .
	      "modprobe -r qla2x00tgt; " .
	      "modprobe -r qla2xxx_scst; " .
	      "modprobe -r scst_vdisk"), 0);

    ok(!(-d "/sys/module/scst"));

    ok(system("modprobe scst_local add_default_tgt=0 && " .
	      "modprobe iscsi-scst && " .
	      "modprobe ib_srpt && " .
	      "modprobe qla2x00tgt && " .
	      "modprobe scst_vdisk && " .
	      "iscsi-scstd"), 0);
}
