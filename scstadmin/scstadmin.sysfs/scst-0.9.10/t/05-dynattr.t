#!perl

use strict;
use Test;

BEGIN {
    plan tests => 57;
}

use Data::Dumper;
use SCST::SCST;

sub setup {
    my $SCST = shift;

    my %drivers = map { $_ => 1 } @{$SCST->drivers()};
    ok(exists($drivers{'iscsi'}));
    ok(exists($drivers{'scst_local'}));

    ok($SCST->openDevice("vdisk_fileio", "disk01",
			 { 'filename' => '/proc/cpuinfo' }), 0);

    ok($SCST->addVirtualTarget('iscsi', 'tgt1'), 0);

    ok($SCST->addLun('iscsi', 'tgt1', 'disk01', 0, { }), 0);
}

sub testDriverDynAttr {
    my $SCST = shift;

    ok($SCST->driverDynamicAttributes(), undef);
    ok($SCST->driverDynamicAttributes('no-such-driver'), undef);
    ok($SCST->{'err_string'},
       "driverDynamicAttributes(): Driver 'no-such-driver' is not available");
    ok(Dumper($SCST->driverDynamicAttributes('scst_local')), Dumper({}));
    ok(Dumper($SCST->driverDynamicAttributes('iscsi')),
       Dumper({ 'IncomingUser' => '', 'OutgoingUser' => '' }));
    ok($SCST->checkDriverDynamicAttributes('no-such-driver'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->checkDriverDynamicAttributes('no-such-driver', { }),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->checkDriverDynamicAttributes('scst_local', { }), 0);
    ok($SCST->checkDriverDynamicAttributes('iscsi', { }), 0);
    ok($SCST->checkDriverDynamicAttributes('iscsi',
					   { 'IncomingUser' => ''}), 0);
    ok($SCST->checkDriverDynamicAttributes('iscsi',
					   { 'IncomingUser' => '',
					     'OutgoingUser' => '' }), 0);
    ok($SCST->checkDriverDynamicAttributes('iscsi',
					   { 'IncomingUser' => '',
					     'OutgoingUser' => '',
					     'NoSuchAttribute' => '' }), 1);

    ok($SCST->addDriverDynamicAttribute(), $SCST->SCST_C_DRV_ADDATTR_FAIL);
    ok($SCST->addDriverDynamicAttribute('no-such-driver', '', ''),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->addDriverDynamicAttribute('iscsi', 'no-such-attribute', ''),
       $SCST->SCST_C_DRV_BAD_ATTRIBUTES);
    ok($SCST->addDriverDynamicAttribute('iscsi', 'IncomingUser',
					'bar 12CharSecret'), 0);
    ok($SCST->addDriverDynamicAttribute('iscsi', 'IncomingUser',
					'joe 12charsecret'), 0);
    ok(Dumper($SCST->driverAttributes('iscsi')->{'IncomingUser'}),
       Dumper({ 'keys' => { '0' => { 'value' => 'bar 12CharSecret' },
	                    '1' => { 'value' => 'joe 12charsecret' } },
	        'static' => 0 }));
    ok($SCST->removeDriverDynamicAttribute(), $SCST->SCST_C_DRV_REMATTR_FAIL);
    ok($SCST->removeDriverDynamicAttribute('no-such-driver', '', ''),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->removeDriverDynamicAttribute('iscsi', 'no-such-attribute', ''),
       $SCST->SCST_C_DRV_BAD_ATTRIBUTES);
    ok($SCST->removeDriverDynamicAttribute('iscsi', 'IncomingUser',
					   'joe 12charsecret'), 0);
    ok($SCST->removeDriverDynamicAttribute('iscsi', 'IncomingUser',
					   'bar 12CharSecret'), 0);
    ok(!exists($SCST->driverAttributes('iscsi')->{'IncomingUser'}));
}

sub testTargetDynAttr {
    my $SCST = shift;

    ok($SCST->targetDynamicAttributes(), undef);
    ok($SCST->targetDynamicAttributes('no-such-driver'), undef);
    ok($SCST->{'err_string'},
       "targetDynamicAttributes(): Driver 'no-such-driver' is not available");
    ok(Dumper($SCST->targetDynamicAttributes('scst_local')), Dumper({}));
    ok(Dumper($SCST->targetDynamicAttributes('iscsi')),
       Dumper({ 'IncomingUser' => '',
		'OutgoingUser' => '',
		'allowed_portal' => '' }));
    ok($SCST->checkTargetDynamicAttributes('no-such-driver'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->checkTargetDynamicAttributes('no-such-driver', { }),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->checkTargetDynamicAttributes('scst_local', { }), 0);
    ok($SCST->checkTargetDynamicAttributes('iscsi', { }), 0);
    ok($SCST->checkTargetDynamicAttributes('iscsi',
					   { 'IncomingUser' => ''}), 0);
    ok($SCST->checkTargetDynamicAttributes('iscsi',
					   { 'IncomingUser' => '',
					     'OutgoingUser' => '' }), 0);
    ok($SCST->checkTargetDynamicAttributes('iscsi',
					   { 'IncomingUser' => '',
					     'OutgoingUser' => '',
					     'NoSuchAttribute' => '' }), 1);

    ok($SCST->addTargetDynamicAttribute(), $SCST->SCST_C_TGT_ADDATTR_FAIL);
    ok($SCST->addTargetDynamicAttribute('no-such-driver', '', '', ''),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->addTargetDynamicAttribute('iscsi', 'no-such-target', '', ''),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->addTargetDynamicAttribute('iscsi', 'tgt1', 'no-such-attribute',
					'', ''),
       $SCST->SCST_C_TGT_BAD_ATTRIBUTES);
    ok($SCST->addTargetDynamicAttribute('iscsi', 'tgt1', 'IncomingUser',
					'bar 12CharSecret'), 0);
    ok($SCST->addTargetDynamicAttribute('iscsi', 'tgt1', 'IncomingUser',
					'joe 12charsecret'), 0);
    ok(Dumper($SCST->targetAttributes('iscsi', 'tgt1')->{'IncomingUser'}),
       Dumper({ 'keys' => { '0' => { 'value' => 'bar 12CharSecret' },
	                    '1' => { 'value' => 'joe 12charsecret' } },
	        'static' => 0 }));
    ok($SCST->removeTargetDynamicAttribute(), $SCST->SCST_C_TGT_REMATTR_FAIL);
    ok($SCST->removeTargetDynamicAttribute('no-such-driver', '', '', ''),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->removeTargetDynamicAttribute('iscsi', 'no-such-target', '', ''),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->removeTargetDynamicAttribute('iscsi', 'tgt1', 'no-such-attribute',
					   ''),
       $SCST->SCST_C_TGT_BAD_ATTRIBUTES);
    ok($SCST->removeTargetDynamicAttribute('iscsi', 'tgt1', 'IncomingUser',
					   'joe 12charsecret'), 0);
    ok($SCST->removeTargetDynamicAttribute('iscsi', 'tgt1', 'IncomingUser',
					   'bar 12CharSecret'), 0);
    ok(!exists($SCST->targetAttributes('iscsi', 'tgt1')->{'IncomingUser'}));
}

sub teardown {
    my $SCST = shift;

    ok($SCST->removeVirtualTarget('iscsi', 'tgt1'), 0);
    ok($SCST->closeDevice("vdisk_fileio", "disk01"), 0);
}

my $_DEBUG_ = 0;

my $SCST = eval { new SCST::SCST($_DEBUG_) };
die("Creation of SCST object failed") if (!defined($SCST));

setup($SCST);
testDriverDynAttr($SCST);
testTargetDynAttr($SCST);
teardown($SCST);
