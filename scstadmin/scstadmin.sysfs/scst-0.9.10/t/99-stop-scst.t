#!perl

use strict;
use Test;

BEGIN {
    plan tests => 1;
}

if ($> == 0) {
    system("/etc/init.d/scst stop");
    ok(!(-d "/sys/module/scst"));
} else {
    ok(1);
}
