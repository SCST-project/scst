#!perl

use strict;
use warnings;
use Cwd qw(abs_path);
use File::Basename;
use File::Spec;
use Test;

my $testdir;
my $scstadmin_pm_dir;
my $scstadmin_dir;
my $scstadmin;
my $redirect_file;
my $redirect;

BEGIN {
    $redirect_file = "/tmp/scstadmin-test-09-output.txt";
    unlink($redirect_file);
    $testdir = dirname(abs_path($0));
    $scstadmin_pm_dir = dirname($testdir);
    $scstadmin_dir = dirname($scstadmin_pm_dir);
    $scstadmin = File::Spec->catfile($scstadmin_dir, "scstadmin");
    unless(grep /blib/, @INC) {
	unshift(@INC, File::Spec->catdir($scstadmin_pm_dir, "lib"));
    }
    plan tests => 43;
}

use SCST::SCST;

sub setup {
    my $SCST = shift;

    my ($drivers, $errorString) = $SCST->drivers();
    my %drivers = map { $_ => 1 } @{$drivers};
    ok(exists($drivers{'ib_srpt'}));
}

# Run shell command $1 and return what it wrote to stdout and stderr as a
# string.
sub run {
    my ($cmd) = @_;
    my $tmpfile = File::Spec->catfile(File::Spec->tmpdir(),
				      "scstadmin-test-07-$$-3");
    my $res;
    my $rc;

    $rc = system("$cmd >$tmpfile 2>&1");
    if (!open(my $file, $tmpfile)) {
	$res = "failed to read $tmpfile";
    } else {
	local $/ = undef;
	binmode $file;
	$res = <$file>;
	if (!defined($res)) {
	    $res = "";
	}
	close $file;
    }
    unlink($tmpfile);
    return $res;
}

sub testInvalidArgs {
    ok(run("$scstadmin -open_dev -handler h -set_scst_attr $redirect"),
       "Please specify only one non-query operation at a time.\n");
    ok(run("$scstadmin -clear_config $redirect"),
       "Please specify -force with -clear_config.\n");
    ok(run("$scstadmin -list_tgrp $redirect"),
       "Please specify -dev_group with -list_tgrp.\n");
    ok(run("$scstadmin -list_tgt_attr t $redirect"),
       "Please specify -driver with -list_tgt_attr.\n");
    ok(run("$scstadmin -list_grp_attr g $redirect"),
       "Please specify -driver, -target and group with -list_grp_attr.\n");
    ok(run("$scstadmin -list_lun_attr l $redirect"),
       "Please specify -driver and -target with -list_lun_attr.\n");
    ok(run("$scstadmin -list_init_attr i $redirect"),
       "Please specify -driver, -target and -group with -list_init_attr.\n");
    ok(run("$scstadmin -list_tgrp_attr tg $redirect"),
       "Please specify -dev_group with -list_tgrp_attr.\n");
    ok(run("$scstadmin -list_ttgt_attr tt $redirect"),
       "Please specify -dev_group and -tgt_group with -list_ttgt_attr.\n");
    ok(run("$scstadmin -set_scst_attr $redirect"),
       "Please specify -attributes with -set_scst_attr.\n");
    ok(run("$scstadmin -set_hnd_attr h $redirect"),
       "Please specify -attributes with -set_hnd_attr.\n");
    ok(run("$scstadmin -set_dev_attr d $redirect"),
       "Please specify -attributes with -set_dev_attr.\n");
    ok(run("$scstadmin -set_dgrp_attr dg $redirect"),
       "Please specify -attributes with -set_dgrp_attr.\n");
    ok(run("$scstadmin -set_tgrp_attr tg $redirect"),
       "Please specify -dev_group and -attributes with -set_tgrp_attr.\n");
    ok(run("$scstadmin -set_drv_attr d $redirect"),
       "Please specify -attributes with -set_drv_attr.\n");
    ok(run("$scstadmin -set_tgt_attr t $redirect"),
       "Please specify -driver and -attributes with -set_tgt_attr.\n");
    ok(run("$scstadmin -set_lun_attr l $redirect"),
       "Please specify -driver -target -group and -attributes with -set_lun_attr.\n");
    ok(run("$scstadmin -set_init_attr i $redirect"),
       "Please specify -driver -target -group and -attributes with -set_init_attr.\n");
    ok(run("$scstadmin -add_drv_attr d $redirect"),
       "Please specify -attributes with -add_drv_attr.\n");
    ok(run("$scstadmin -add_tgt_attr t $redirect"),
       "Please specify -driver and -attributes with -add_tgt_attr.\n");
    ok(run("$scstadmin -rem_drv_attr d $redirect"),
       "Please specify -attributes with -rem_drv_attr.\n");
    ok(run("$scstadmin -rem_tgt_attr t $redirect"),
       "Please specify -driver and -attributes with -rem_tgt_attr.\n");
    ok(run("$scstadmin -open_dev d $redirect"),
       "Please specify -handler with -open_dev/-close_dev.\n");
    ok(run("$scstadmin -close_dev d $redirect"),
       "Please specify -handler with -open_dev/-close_dev.\n");
    ok(run("$scstadmin -add_target t $redirect"),
       "Please specify -driver with -add_target.\n");
    ok(run("$scstadmin -rem_target t $redirect"),
       "Please specify -driver with -rem_target.\n");
    ok(run("$scstadmin -add_group g $redirect"),
       "Please specify -driver and -target with -add_group/-rem_group.\n");
    ok(run("$scstadmin -rem_group g $redirect"),
       "Please specify -driver and -target with -add_group/-rem_group.\n");
    ok(run("$scstadmin -add_init i $redirect"),
       "Please specify -driver -target and -group with -add_init/-rem_init/-clear_inits.\n");
    ok(run("$scstadmin -rem_init i $redirect"),
       "Please specify -driver -target and -group with -add_init/-rem_init/-clear_inits.\n");
    ok(run("$scstadmin -clear_inits $redirect"),
       "Please specify -driver -target and -group with -add_init/-rem_init/-clear_inits.\n");
    ok(run("$scstadmin -move_init i $redirect"),
       "Please specify -driver -target -group and -to with -move_init.\n");
    ok(run("$scstadmin -add_lun l $redirect"),
       "Please specify -driver -target and -device with -add_lun/-replace_lun.\n");
    ok(run("$scstadmin -replace_lun l $redirect"),
       "Please specify -driver -target and -device with -add_lun/-replace_lun.\n");
    ok(run("$scstadmin -rem_lun l $redirect"),
       "Please specify -driver and -target with -rem_lun/-clear_luns.\n");
    ok(run("$scstadmin -clear_luns $redirect"),
       "Please specify -driver and -target with -rem_lun/-clear_luns.\n");
    ok(run("$scstadmin -add_dgrp_dev dg $redirect"),
       "Please specify -dev_group with -add_dgrp_dev/-rem_dgrp_dev.\n");
    ok(run("$scstadmin -rem_dgrp_dev dg $redirect"),
       "Please specify -dev_group with -add_dgrp_dev/-rem_dgrp_dev.\n");
    ok(run("$scstadmin -add_tgrp tg $redirect"),
       "Please specify -dev_group with -add_tgrp/-rem_tgrp.\n");
    ok(run("$scstadmin -rem_tgrp tg $redirect"),
       "Please specify -dev_group with -add_tgrp/-rem_tgrp.\n");
    ok(run("$scstadmin -add_tgrp_tgt t $redirect"),
       "Please specify -dev_group and -tgt_group with -add_tgrp_tgt/-rem_tgrp_tgt.\n");
    ok(run("$scstadmin -rem_tgrp_tgt t $redirect"),
       "Please specify -dev_group and -tgt_group with -add_tgrp_tgt/-rem_tgrp_tgt.\n");
}

my $_DEBUG_ = 0;
if ($_DEBUG_) {
    $redirect = ">>$redirect_file";
    open(my $logfile, '>>', $redirect_file);
    select $logfile;
} else {
    $redirect = ">/dev/null";
}

my $SCST = eval { new SCST::SCST($_DEBUG_) };
die("Creation of SCST object failed") if (!defined($SCST));

setup($SCST);

testInvalidArgs;

