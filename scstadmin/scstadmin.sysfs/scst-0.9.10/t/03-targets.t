#!perl

use strict;
use Test;

BEGIN {
    plan tests => 177;
}

use Data::Dumper;
use SCST::SCST;

sub addTargets {
    my $SCST = shift;

    ok(Dumper($SCST->targets('no-such-driver')),
       Dumper(undef, "targets(): Driver 'no-such-driver' is not available"));

    my ($drivers, $errorString) = $SCST->drivers();
    my %drivers = map { $_ => 1 } @{$drivers};
    ok(exists($drivers{'iscsi'}));
    ok(exists($drivers{'scst_local'}));

    my $all_hw_tgt = 1;
    for my $driver (@{$drivers}) {
	my ($targets, $errorString) = $SCST->targets($driver);
	for my $target (@{$targets}) {
	    if ($SCST->targetType($driver, $target) !=
		$SCST::SCST::TGT_TYPE_HARDWARE) {
		$all_hw_tgt = undef;
	    }
	}
    }
    ok($all_hw_tgt);

    ok(Dumper($SCST->targets()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->targets('no-such-driver')),
       Dumper(undef, "targets(): Driver 'no-such-driver' is not available"));
    ok(Dumper($SCST->targets('scst_local')), Dumper([], undef));
    ok(Dumper($SCST->targets('iscsi')), Dumper([], undef));

    ok($SCST->addVirtualTarget('no-such-driver', ''),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->removeVirtualTarget('no-such-driver', ''),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->addVirtualTarget('scst_local', 'local1'), 0);
    ok(Dumper($SCST->targetType()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->targetType('scst_local')),
       Dumper(undef, "Too few arguments"));
    ok($SCST->targetType('scst_local', 'no-such-target'),
       $SCST::SCST::TGT_TYPE_VIRTUAL);
    ok($SCST->targetType('scst_local', 'local1'),
       $SCST::SCST::TGT_TYPE_VIRTUAL);
    ok(Dumper($SCST->targets('scst_local')), Dumper(['local1'], undef));
    ok($SCST->removeVirtualTarget('scst_local', 'local2'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok(Dumper($SCST->targets('scst_local')), Dumper(['local1'], undef));
    ok($SCST->removeVirtualTarget('scst_local', 'local1'), 0);
    ok(Dumper($SCST->targets('scst_local')), Dumper([], undef));
    ok($SCST->addVirtualTarget('scst_local', 'local1',
			       { 'session_name' => 'local1' }), 0);
    ok($SCST->addVirtualTarget('scst_local', 'local2',
			       { 'session_name' => 'local2' }), 0);
    ok(Dumper($SCST->targets('scst_local')),
       Dumper(['local1', 'local2'], undef));

    ok($SCST->targetExists(), 0);
    ok($SCST->targetExists('no-such-driver'), 0);
    ok($SCST->targetExists('no-such-driver', ''), 0);
    ok($SCST->targetExists('scst_local', 'no-such-target'), 0);
    ok($SCST->targetExists('scst_local', '.'), 0);
    ok($SCST->targetExists('scst_local', '..'), 0);
    ok($SCST->targetExists('scst_local', 'module'), 0);
    ok($SCST->targetExists('scst_local', 'local1'), 1);
}

sub sessTest {
    my $SCST = shift;

    ok(Dumper($SCST->sessions()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->sessions('scst_local')),
       Dumper(undef, "Too few arguments"));
    my ($s, $errorString) = $SCST->sessions('scst_local', 'local1');
    ok(Dumper(sort(keys(%$s))), Dumper('local1'));
    ok($s->{'local1'}->{'commands'}->{'value'}, '0');
}

sub driverDynamicAttributesTest {
    my $SCST = shift;

    ok(Dumper($SCST->driverDynamicAttributes()),
       Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->driverDynamicAttributes('no-such-driver')),
       Dumper(undef, "driverDynamicAttributes(): Driver 'no-such-driver' is " .
	       "not available"));
    ok(Dumper($SCST->driverDynamicAttributes('scst_local')),
       Dumper({}, undef));
}

sub iniGrpTest {
    my $SCST = shift;

    ok(Dumper($SCST->groups()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->groups('scst_local')),
       Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->groups('scst_local', 'local1')), Dumper([], undef));

    ok($SCST->addGroup(), $SCST->SCST_C_GRP_ADD_FAIL);
    ok($SCST->addGroup('no-such-driver', 'local1', 'group1'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->addGroup('scst_local', 'no-such-target', 'group1'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->addGroup('scst_local', 'local1', 'group1'), 0);
    ok($SCST->addGroup('scst_local', 'local1', 'group1'),
       $SCST->SCST_C_GRP_EXISTS);
    ok($SCST->addGroup('scst_local', 'local1', 'group2'), 0);
    ok($SCST->addGroup('scst_local', 'local1', 'group3'), 0);
    ok(Dumper($SCST->groups('scst_local', 'local1')),
       Dumper(['group1', 'group2', 'group3'], undef));

    ok($SCST->groupExists(), 0);
    ok($SCST->groupExists('no-such-driver', '', ''), 0);
    ok($SCST->groupExists('scst_local', 'no-such-target', ''), 0);
    ok($SCST->groupExists('scst_local', 'local1', 'no-such-group'), 0);
    ok($SCST->groupExists('scst_local', 'local1', 'group1'), 1);

    ok($SCST->removeGroup(), $SCST->SCST_C_GRP_REM_FAIL);
    ok($SCST->removeGroup('no-such-driver', 'local1', 'group1'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->removeGroup('scst_local', 'no-such-target', 'group1'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->removeGroup('scst_local', 'local1', 'group1'), 0);
    ok($SCST->removeGroup('scst_local', 'local1', 'group1'),
       $SCST->SCST_C_GRP_NO_GROUP);
    ok($SCST->removeGroup('scst_local', 'local1', 'group2'), 0);
    ok($SCST->removeGroup('scst_local', 'local1', 'group3'), 0);
    ok(Dumper($SCST->groups('scst_local', 'local1')), Dumper([], undef));

    ok($SCST->addGroup('scst_local', 'local1', 'group1'), 0);
    ok($SCST->addInitiator('scst_local', 'local1', 'group1'),
       $SCST->SCST_C_GRP_ADD_INI_FAIL);
    ok($SCST->addInitiator('no-such-driver', 'local1', 'group1', 'ini1'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->addInitiator('scst_local', 'no-such-target', 'group1', 'ini1'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->addInitiator('scst_local', 'local1', 'no-such-group', 'ini1'),
       $SCST->SCST_C_GRP_NO_GROUP);
    ok($SCST->addInitiator('scst_local', 'local1', 'group1', 'ini1'), 0);
    ok($SCST->addInitiator('scst_local', 'local1', 'group1', 'ini2'), 0);
    ok($SCST->addInitiator('scst_local', 'local1', 'group1', 'ini1'),
       $SCST->SCST_C_GRP_INI_EXISTS);
    ok(Dumper($SCST->initiators()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->initiators('scst_local')),
       Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->initiators('scst_local', 'local1')),
       Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->initiators('scst_local', 'local1', 'group1')),
       Dumper(['ini1', 'ini2'], undef));

    ok($SCST->initiatorExists(), 0);
    ok($SCST->initiatorExists('no-such-driver', '', '', ''), 0);
    ok($SCST->initiatorExists('scst_local', 'no-such-target', '', ''), 0);
    ok($SCST->initiatorExists('scst_local', 'local1', 'no-such-group', ''), 0);
    ok($SCST->initiatorExists('scst_local', 'local1', 'group1', 'no-such-ini'),
       0);
    ok($SCST->initiatorExists('scst_local', 'local1', 'group1', 'ini1'), 1);

    ok($SCST->addGroup('scst_local', 'local1', 'group2'), 0);
    ok($SCST->moveInitiator('scst_local', 'local1', 'group1', 'group2', 'ini1'),
       0);
    ok($SCST->initiatorExists('scst_local', 'local1', 'group1', 'ini1'), 0);
    ok($SCST->initiatorExists('scst_local', 'local1', 'group2', 'ini1'), 1);
    ok($SCST->moveInitiator('scst_local', 'local1', 'group2', 'group1', 'ini1'),
       0);
    ok($SCST->initiatorExists('scst_local', 'local1', 'group1', 'ini1'), 1);
    ok($SCST->initiatorExists('scst_local', 'local1', 'group2', 'ini1'), 0);

    ok($SCST->removeGroup('scst_local', 'local1', 'group2'), 0);
    ok($SCST->removeInitiator('no-such-driver', 'local1', 'group1'),
       $SCST->SCST_C_GRP_REM_INI_FAIL);
    ok($SCST->removeInitiator('no-such-driver', 'local1', 'group1', 'ini1'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->removeInitiator('scst_local', 'no-such-target', 'group1', 'ini1'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->removeInitiator('scst_local', 'local1', 'no-such-group', 'ini1'),
       $SCST->SCST_C_GRP_NO_GROUP);
    ok($SCST->removeInitiator('scst_local', 'local1', 'group1', 'ini1'), 0);
    ok($SCST->removeInitiator('scst_local', 'local1', 'group1', 'ini2'), 0);
    ok($SCST->removeInitiator('scst_local', 'local1', 'group1', 'ini2'),
	$SCST->SCST_C_GRP_NO_INI);
    ok(Dumper($SCST->initiators('scst_local', 'local1', 'group1')),
       Dumper([], undef));
    ok($SCST->removeGroup('scst_local', 'local1', 'group1'), 0);
}

sub lunReadOnly {
    my $SCST = shift;
    my $driver = shift;
    my $target = shift;
    my $lun = shift;

    my ($a, $errorString) = $SCST->lunAttributes($driver, $target, $lun);
    my $roHash = $a->{'read_only'};
    return exists($roHash->{'keys'}) ? $roHash->{'keys'}->{'0'}->{'value'} :
	$roHash->{'value'};
}

sub lunTest {
    my $SCST = shift;

    ok($SCST->openDevice("no-such-handler", "disk01", { }),
       $SCST->SCST_C_HND_NO_HANDLER);
    ok($SCST->openDevice("vdisk_fileio", "disk01", undef),
       $SCST->SCST_C_DEV_OPEN_FAIL);
    ok($SCST->openDevice("vdisk_fileio", "disk01", { }),
       $SCST->SCST_C_DEV_OPEN_FAIL);
    ok($SCST->openDevice("vdisk_fileio", "disk01",
			 { 'filename' => '/proc/cpuinfo' }), 0);
    ok(Dumper($SCST->devicesByHandler("vdisk_fileio")),
       Dumper(["disk01"], undef));
    ok($SCST->openDevice("vdisk_fileio", "disk01",
			 { 'filename' => '/proc/cpuinfo' }),
       $SCST->SCST_C_DEV_EXISTS);
    ok($SCST->openDevice("vdisk_fileio", "disk02",
			 { 'filename' => '/proc/cpuinfo' }), 0);

    ok($SCST->addLun('scst_local', 'local1', 'disk01', 0),
       $SCST->SCST_C_TGT_ADD_LUN_FAIL);
    ok($SCST->addLun('scst_local', 'local3', 'disk01', 0, { }),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->addLun('scst_local', 'local1', 'disk01', 0, { }), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk02', 1, { }), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk01', 2, { }), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk02', 3, { }), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk01', 3, { }),
       $SCST->SCST_C_TGT_LUN_EXISTS);

    ok($SCST->lunExists(), 0);
    ok($SCST->lunExists('scst_local'), 0);
    ok($SCST->lunExists('scst_local', 'local1'), 0);
    ok($SCST->lunExists('no-such-driver', 'local1', 0),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->lunExists('scst_local', 'no-such-target', 0),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->lunExists('scst_local', 'local1', 99), 0);
    ok($SCST->lunExists('scst_local', 'local1', 0), 1);

    ok($SCST->addGroup('scst_local', 'local1', 'group1'), 0);
    ok($SCST->addInitiator('scst_local', 'local1', 'group1', 'ini1'), 0);

    ok($SCST->addLun('scst_local', 'local1', 'disk01', 0, undef, 'group1'),
       $SCST->SCST_C_GRP_ADD_LUN_FAIL);
    ok($SCST->addLun('scst_local', 'local1', 'disk01', 0, { }, 'group1'), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk02', 2, { }, 'group1'), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk01', 4, { }, 'group1'), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk02', 6, { }, 'group1'), 0);
    ok($SCST->addLun('scst_local', 'local1', 'disk01', 6, { }, 'group1'),
       $SCST->SCST_C_GRP_LUN_EXISTS);

    ok($SCST->lunExists('no-such-driver', 'local1', 0, 'group1'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->lunExists('scst_local', 'no-such-target', 0, 'group1'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->lunExists('scst_local', 'local1', 99, 'group1'), 0);
    ok($SCST->lunExists('scst_local', 'local1', 0, 'no-such-group'),
       $SCST->SCST_C_GRP_NO_GROUP);
    ok($SCST->lunExists('scst_local', 'local1', 0, 'group1'), 1);

    ok(Dumper($SCST->luns()), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->luns('scst_local')), Dumper(undef, "Too few arguments"));
    ok(Dumper($SCST->luns('no-such-driver', 'local1')),
       Dumper(undef, "luns(): Driver 'no-such-driver' is not available"));
    ok(Dumper($SCST->luns('scst_local', 'no-such-target')),
       Dumper(undef, "luns(): Target 'no-such-target' is not available"));
    ok(Dumper($SCST->luns('scst_local', 'local1')),
       Dumper({ '0' => 'disk01', '1' => 'disk02', '2' => 'disk01',
		'3' => 'disk02' }, undef));
    ok(Dumper($SCST->luns('scst_local', 'local1', 'group1')),
       Dumper({ '0' => 'disk01', '2' => 'disk02', '4' => 'disk01',
		'6' => 'disk02' }, undef));

    ok(lunReadOnly($SCST, 'scst_local', 'local1', 0), '0');
    ok($SCST->setLunAttribute(), $SCST->SCST_C_LUN_SETATTR_FAIL);
    ok($SCST->setLunAttribute('no-such-driver', 'local1', 0, 'read_only', '1'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->setLunAttribute('scst_local', 'no-such-target', 0, 'read_only', '1'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->setLunAttribute('scst_local', 'local1', 99, 'read_only', '1'),
       $SCST->SCST_C_TGT_NO_LUN);
    ok($SCST->setLunAttribute('scst_local', 'local1', 0, 'read_only', '1'),
       $SCST->SCST_C_LUN_ATTRIBUTE_STATIC);
    ok(lunReadOnly($SCST, 'scst_local', 'local1', 0), '0');
    ok(lunReadOnly($SCST, 'scst_local', 'local1', 0, 'group1'), '0');
    ok($SCST->setLunAttribute('scst_local', 'local1', 0, 'read_only', '1', 'no-such-group'),
       $SCST->SCST_C_GRP_NO_GROUP);
    ok($SCST->setLunAttribute('scst_local', 'local1', 99, 'read_only', '1', 'group1'),
       $SCST->SCST_C_GRP_NO_LUN);
    ok($SCST->setLunAttribute('scst_local', 'local1', 0, 'read_only', '1', 'group1'),
       $SCST->SCST_C_LUN_ATTRIBUTE_STATIC);
    ok(lunReadOnly($SCST, 'scst_local', 'local1', 0, 'group1'), '0');

    ok($SCST->replaceLun('scst_local', 'local1', 0, 'disk02', {}), 0);
    ok(Dumper($SCST->luns('scst_local', 'local1')),
       Dumper({ '0' => 'disk02', '1' => 'disk02', '2' => 'disk01',
		'3' => 'disk02' }, undef));
    ok($SCST->replaceLun('scst_local', 'local1', 0, 'disk01', {}), 0);
    ok(Dumper($SCST->luns('scst_local', 'local1')),
       Dumper({ '0' => 'disk01', '1' => 'disk02', '2' => 'disk01',
		'3' => 'disk02' }, undef));

    ok($SCST->clearLuns(undef, undef), $SCST->SCST_C_TGT_CLR_LUN_FAIL);
    ok($SCST->clearLuns(undef, undef, 'group1'),
       $SCST->SCST_C_GRP_CLR_LUN_FAIL);
    ok($SCST->removeLun(undef, undef, undef), $SCST->SCST_C_TGT_ADD_LUN_FAIL);
    ok($SCST->removeLun('no-such-driver', 'local1', '0'),
       $SCST->SCST_C_DRV_NO_DRIVER);
    ok($SCST->removeLun('scst_local', 'no-such-target', '0'),
       $SCST->SCST_C_TGT_NO_TARGET);
    ok($SCST->removeLun(undef, undef, undef, 'group1'),
       $SCST->SCST_C_GRP_REM_LUN_FAIL);
    ok($SCST->removeLun('scst_local', 'local1', '4'), $SCST->SCST_C_TGT_NO_LUN);
    ok($SCST->removeLun('scst_local', 'local1', '8', 'group1'),
       $SCST->SCST_C_GRP_NO_LUN);
    ok($SCST->clearLuns('scst_local', 'local1'), 0);
    ok(Dumper($SCST->luns('scst_local', 'local1')), Dumper({ }, undef));
    ok(Dumper($SCST->luns('scst_local', 'local1', 'group1')),
       Dumper({ '0' => 'disk01', '2' => 'disk02', '4' => 'disk01',
		'6' => 'disk02' }, undef));
    ok($SCST->removeLun('scst_local', 'local1', '4', 'group1'), 0);
    ok(Dumper($SCST->luns('scst_local', 'local1', 'group1')),
       Dumper({ '0' => 'disk01', '2' => 'disk02', '6' => 'disk02' }, undef));
    ok($SCST->clearLuns('scst_local', 'local1', 'group1'), 0);
    ok(Dumper($SCST->luns('scst_local', 'local1', 'group1')),
       Dumper({ }, undef));

    ok($SCST->removeInitiator('scst_local', 'local1', 'group1', 'ini1'), 0);
    ok($SCST->removeGroup('scst_local', 'local1', 'group1'), 0);

    ok($SCST->closeDevice("no-such-handler", "disk01"),
       $SCST->SCST_C_HND_NO_HANDLER);
    ok($SCST->closeDevice("vdisk_fileio", "disk02"), 0);
    ok($SCST->closeDevice("vdisk_fileio", "disk01"), 0);
    ok($SCST->closeDevice("vdisk_fileio", "disk01"),
       $SCST->SCST_C_DEV_NO_DEVICE);
}

sub remTargets {
    my $SCST = shift;

    ok($SCST->removeVirtualTarget('scst_local', 'local2'), 0);
    ok($SCST->removeVirtualTarget('scst_local', 'local1'), 0);
    ok(Dumper($SCST->targets('scst_local')), Dumper([], undef));
}

my $_DEBUG_ = 0;

my $SCST = eval { new SCST::SCST($_DEBUG_) };
die("Creation of SCST object failed") if (!defined($SCST));

addTargets($SCST);
sessTest($SCST);
driverDynamicAttributesTest($SCST);
iniGrpTest($SCST);
lunTest($SCST);
remTargets($SCST);
