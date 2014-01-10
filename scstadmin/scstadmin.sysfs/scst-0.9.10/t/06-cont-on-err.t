#!perl

use strict;
use Cwd qw(abs_path);
use File::Basename;
use File::Spec;
use Test;

my $testdir;
my $scstadmin_pm_dir;
my $scstadmin_dir;
my $scstadmin;

BEGIN {
    $testdir = dirname(abs_path($0));
    $scstadmin_pm_dir = dirname($testdir);
    $scstadmin_dir = dirname($scstadmin_pm_dir);
    $scstadmin = File::Spec->catfile($scstadmin_dir, "scstadmin");
    unless(grep /blib/, @INC) {
	unshift(@INC, File::Spec->catdir($scstadmin_pm_dir, "lib"));
    }
    plan tests => 2;
}

use Data::Dumper;
use SCST::SCST;
use File::Temp qw/tempfile/;

sub setup {
    my $SCST = shift;

    my ($drivers, $errorString) = $SCST->drivers();
    my %drivers = map { $_ => 1 } @{$drivers};
    ok(exists($drivers{'ib_srpt'}));
}

sub testRestoreConfig {
    my $to_be_restored = shift;
    my $expected = shift;
    my $tmpfilename1 = File::Spec->catfile(File::Spec->tmpdir(),
					   "scstadmin-test-06-$$-1");
    my $tmpfilename2 = File::Spec->catfile(File::Spec->tmpdir(),
					   "scstadmin-test-06-$$-2");

    system("$scstadmin -clear_config -force -noprompt -no_lip >/dev/null");
    system("$scstadmin -cont_on_err -no_lip -config $to_be_restored" .
	   " >/dev/null");
    system("$scstadmin -write_config $tmpfilename1 >/dev/null");
    system("awk 'BEGIN {t = 0 } /^TARGET_DRIVER.*{\$/ { if (\$0 != \"TARGET_DRIVER scst_local {\") t = 1 } /^}\$/ { if (t == 1) t = 2 } /^\$/ { if (t == 2) { t = 3 } } /^./ { if (t == 3) { t = 0 } } { if (t == 0) print }' <$tmpfilename1 >$tmpfilename2");
    my $compare_result = system("diff -u $tmpfilename2 $expected");
    ok($compare_result, 0);
    if ($compare_result == 0) {
	unlink($tmpfilename2);
	unlink($tmpfilename1);
    }
}

my $_DEBUG_ = 0;

my $SCST = eval { new SCST::SCST($_DEBUG_) };
die("Creation of SCST object failed") if (!defined($SCST));

setup($SCST);

testRestoreConfig(File::Spec->catfile($testdir, "to-be-restored.conf"),
		  File::Spec->catfile($testdir, "after-restore.conf"));

