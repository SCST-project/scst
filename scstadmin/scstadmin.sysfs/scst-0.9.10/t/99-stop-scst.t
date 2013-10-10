#!perl

use strict;
use Test;

BEGIN {
    plan tests => 2;
}

if ($> == 0) {
    ok(system("killall iscsi-scstd; " .
	      "modprobe -r scst_local; " .
	      "modprobe -r iscsi-scst; " .
	      "modprobe -r ib_srpt; " .
	      "modprobe -r qla2x00tgt; " .
	      "modprobe -r qla2xxx_scst; " .
	      "modprobe -r scst_vdisk"), 0);
    ok(!(-d "/sys/module/scst"));
} else {
    ok(1);
}
