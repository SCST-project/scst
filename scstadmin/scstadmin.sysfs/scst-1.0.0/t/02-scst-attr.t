#!perl

use strict;
use Test;

BEGIN {
    plan tests => 6 + ($> == 0 ? 4 : 0);
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

ok($SCST->setScstAttribute(), 1);

ok($SCST->setScstAttribute('no-such-attribute'), 1);

ok($SCST->setScstAttribute('no-such-attribute', '1'),
   $SCST->SCST_C_BAD_ATTRIBUTES);

ok($SCST->setScstAttribute('last_sysfs_mgmt_res', '1'),
   $SCST->SCST_C_ATTRIBUTE_STATIC);

my $threads = getScstThreadCount($SCST);
ok(ref(\$threads), "SCALAR");
ok(defined($threads));

if ($> == 0) {
    ok($SCST->setScstAttribute('threads', $threads + 1), 0);

    ok(getScstThreadCount($SCST), $threads + 1);

    ok($SCST->setScstAttribute('threads', $threads), 0);

    ok(getScstThreadCount($SCST), $threads);
}
