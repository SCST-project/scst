#!perl

use strict;
use Test;

BEGIN {
    plan tests => 62;
}

use Data::Dumper;
use SCST::SCST;

sub setup {
    my $SCST = shift;

    my ($drivers, $errorString) = $SCST->drivers();
    my %drivers = map { $_ => 1 } @{$drivers};
    ok(exists($drivers{'iscsi'}));
    ok(exists($drivers{'scst_local'}));

    ok($SCST->openDevice("vdisk_fileio", "disk01",
			 { 'filename' => '/proc/cpuinfo' }), 0);
    ok($SCST->openDevice("vdisk_fileio", "disk02",
			 { 'filename' => '/proc/cpuinfo' }), 0);
    ok($SCST->openDevice("vdisk_fileio", "disk03",
			 { 'filename' => '/proc/cpuinfo' }), 0);
    ok($SCST->openDevice("vdisk_fileio", "disk04",
			 { 'filename' => '/proc/cpuinfo' }), 0);

    ok($SCST->addVirtualTarget('scst_local', 'local1'), 0);

    ok($SCST->addLun('scst_local', 'local1', 'disk01', 0, { }), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk02', 1, { }), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk03', 2, { }), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk04', 3, { }), 0);
}

sub test {
    my $SCST = shift;

    ok(Dumper($SCST->deviceGroups()), Dumper([], undef));

    ok($SCST->addDeviceGroup('dg1'), 0);
    ok($SCST->addDeviceGroup('dg2'), 0);
    ok($SCST->addDeviceGroup('dg3'), 0);
    ok($SCST->addDeviceGroup('dg4'), 0);

    ok(Dumper($SCST->deviceGroups()),
       Dumper(['dg1', 'dg2', 'dg3', 'dg4'], undef));

    ok(Dumper($SCST->deviceGroupDevices()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->deviceGroupDevices('dg1')), Dumper([], undef));
    ok($SCST->addDeviceGroupDevice('dg1', 'disk01'), 0);
    ok($SCST->addDeviceGroupDevice('dg1', 'disk01'),
       $SCST->SCST_C_DGRP_DEVICE_EXISTS);
    ok($SCST->addDeviceGroupDevice('dg2', 'disk02'), 0);
    ok($SCST->addDeviceGroupDevice('dg2', 'disk01'),
       $SCST->SCST_C_DGRP_DEVICE_OTHER);
    ok($SCST->addDeviceGroupDevice('dg3', 'disk03'), 0);
    ok($SCST->addDeviceGroupDevice('dg4', 'disk04'), 0);
    ok(Dumper($SCST->deviceGroupDevices('dg1')), Dumper(['disk01'], undef));
    ok(Dumper($SCST->deviceGroupDevices('dg2')), Dumper(['disk02'], undef));
    ok(Dumper($SCST->deviceGroupDevices('dg3')), Dumper(['disk03'], undef));
    ok(Dumper($SCST->deviceGroupDevices('dg4')), Dumper(['disk04'], undef));

    ok(Dumper($SCST->targetGroups()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->targetGroups('no-such-device-group')),
       Dumper(undef, "targetGroups(): Device group 'no-such-device-group'" .
	      " does not exist"));
    ok(Dumper($SCST->targetGroups('dg1')), Dumper([], undef));

    ok(Dumper($SCST->targetGroupTargets()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->targetGroupTargets('no-such-device-group')),
       Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->targetGroupTargets('no-such-device-group', 'tg1')),
       Dumper(undef, "targetGroupTargets(): Device group 'no-such-device-".
	      "group' does not exist"));
    ok(Dumper($SCST->targetGroupTargets('dg1', 'no-such-target-group')),
       Dumper(undef, "targetGroupTargets(): Target group 'no-such-target-".
	      "group' does not exist"));
    ok(Dumper($SCST->targetGroupTargets('dg1', 'tg1')), Dumper(undef,
	      "targetGroupTargets(): Target group 'tg1' does not exist"));
    ok($SCST->addTargetGroup(), $SCST->SCST_C_DGRP_ADD_GRP_FAIL);
    ok($SCST->addTargetGroup('no-such-device-group', 'tg1'),
       $SCST->SCST_C_DEV_GRP_NO_GROUP);
    ok($SCST->addTargetGroup('dg1', 'tg1'), 0);
    ok($SCST->addTargetGroup('dg1', 'tg1'), $SCST->SCST_C_DGRP_GROUP_EXISTS);
    ok($SCST->addTargetGroup('dg1', 'tg2'), 0);

    my ($tga, $errorString) = $SCST->targetGroupAttributes('dg1', 'tg1');
    ok(Dumper($tga->{'group_id'}),
       Dumper({ 'keys' => { '0' => { 'value' => '0' } }, 'static' => 0 }));
    ok($SCST->setTargetGroupAttribute('dg1', 'tg1', 'group_id', 7), 0);
    ($tga, $errorString) = $SCST->targetGroupAttributes('dg1', 'tg1');
    ok(Dumper($tga->{'group_id'}),
       Dumper({ 'keys' => { '0' => { 'value' => '7' } }, 'static' => 0 }));

    ok($SCST->addTargetGroupTarget(), $SCST->SCST_C_TGRP_ADD_TGT_FAIL);
    ok($SCST->addTargetGroupTarget('no-such-device-group', 'tg1', 'tgt1'),
       $SCST->SCST_C_DEV_GRP_NO_GROUP);
    ok($SCST->addTargetGroupTarget('dg1', 'no-such-target-group', 'tgt1'),
       $SCST->SCST_C_DGRP_NO_GROUP);
    ok($SCST->addTargetGroupTarget('dg1', 'tg1', 'tgt1'), 0);
    ok($SCST->addTargetGroupTarget('dg1', 'tg1', 'tgt1'),
       $SCST->SCST_C_TGRP_TGT_EXISTS);
    ok($SCST->addTargetGroupTarget('dg1', 'tg2', 'tgt2'), 0);

    my $tgta;
    ($tgta, $errorString) =
	$SCST->targetGroupTargetAttributes('dg1', 'tg1', 'tgt1');
    ok(Dumper($tgta->{'rel_tgt_id'}),
       Dumper({ 'keys' => { '0' => { 'value' => '0' } }, 'static' => 0 }));
    ok($SCST->setTargetGroupTargetAttribute('dg1', 'tg1', 'tgt1', 'rel_tgt_id',
					    8), 0);
    ($tgta, $errorString) =
	$SCST->targetGroupTargetAttributes('dg1', 'tg1', 'tgt1');
    ok(Dumper($tgta->{'rel_tgt_id'}),
       Dumper({ 'keys' => { '0' => { 'value' => '8' } }, 'static' => 0 }));

    ok($SCST->removeDeviceGroup('dg1'), 0);
    ok($SCST->removeDeviceGroup('dg2'), 0);
    ok($SCST->removeDeviceGroup('dg3'), 0);
    ok($SCST->removeDeviceGroup('dg4'), 0);

    ok(Dumper($SCST->deviceGroups()), Dumper([], undef));
}

sub teardown {
    my $SCST = shift;

    ok($SCST->removeVirtualTarget('scst_local', 'local1'), 0);
    ok($SCST->closeDevice("vdisk_fileio", "disk01"), 0);
    ok($SCST->closeDevice("vdisk_fileio", "disk02"), 0);
}

my $_DEBUG_ = 0;

my $SCST = eval { new SCST::SCST($_DEBUG_) };
die("Creation of SCST object failed") if (!defined($SCST));

setup($SCST);
test($SCST);
teardown($SCST);
