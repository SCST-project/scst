#!perl

use strict;
use warnings;
use Test;

BEGIN {
    plan tests => 7 + ($> == 0 ? 8 : 0);
}

use SCST::SCST;

sub getScstThreadCount {
    my $SCST = shift;
    my ($scstAttributes, $errorString) = $SCST->scstAttributes();
    my $threadHash = $scstAttributes->{'threads'};
    return exists($threadHash->{'keys'}) ? $threadHash->{'keys'}->{'0'}->{'value'} : $threadHash->{'value'};
}

my $_DEBUG_ = 0;

my $SCST = eval { new SCST::SCST($_DEBUG_) };
die("Creation of SCST object failed") if (!defined($SCST));

# Missing `attribute` and `value` arguments.
ok($SCST->setScstAttribute(), 1);

# `attribute` argument is an empty string.
ok($SCST->setScstAttribute(''), 1);

# `attribute` argument is not an existing attribute and the `value` argument is
# missing.
ok($SCST->setScstAttribute('no-such-attribute'), 1);

# `attribute` argument is not an existing attribute.
ok($SCST->setScstAttribute('no-such-attribute', '1'),
   $SCST->SCST_C_BAD_ATTRIBUTES);

# Attempt to modify a read-only attribute.
ok($SCST->setScstAttribute('last_sysfs_mgmt_res', '1'),
   $SCST->SCST_C_ATTRIBUTE_STATIC);

my $threads = getScstThreadCount($SCST);
ok(ref(\$threads), "SCALAR");
ok(defined($threads));

# $> represents the effective user ID of this process.
if ($> == 0) {
    ok($SCST->setScstAttribute('threads', $threads + 1), 0);

    ok(getScstThreadCount($SCST), $threads + 1);

    ok($SCST->setScstAttribute('threads', $threads), 0);

    ok(getScstThreadCount($SCST), $threads);

    ok($SCST->setScstAttribute('measure_latency', undef), 1);

    ok($SCST->setScstAttribute('measure_latency', ""),
       $SCST->SCST_C_SETATTR_FAIL);

    ok($SCST->setScstAttribute('measure_latency', "."),
       $SCST->SCST_C_SETATTR_FAIL);

    ok($SCST->setScstAttribute('measure_latency', "0"), 0);
}
