#!perl

use strict;
use Test;

BEGIN {
    plan tests => ($> == 0) ? 2 : 0;
}

if ($> == 0) {
    system("/etc/init.d/scst stop");
    ok(!(-d "/sys/module/scst"));

    ok(system("modprobe scst_local add_default_tgt=0 && " .
	      "modprobe iscsi-scst && " .
	      "modprobe scst_vdisk && " .
	      "/usr/local/sbin/iscsi-scstd"), 0);
}
