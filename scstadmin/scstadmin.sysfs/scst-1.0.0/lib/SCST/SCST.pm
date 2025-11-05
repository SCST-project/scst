# -*- mode: perl; perl-indent-level: 8; indent-tabs-mode: t -*-

package SCST::SCST;

# Author:	Mark R. Buechler
# License:	GPLv2
# Copyright (c) 2005-2011 Mark R. Buechler
# Copyright (c) 2011-2019 Bart Van Assche <bvanassche@acm.org>.

use strict;
use warnings;
use 5.005;
use Fcntl ':mode';
use File::Spec;
use IO::Handle;
use IO::File;
use Carp qw(cluck);

use POSIX;

use constant {
TRUE             => 1,
FALSE            => 0,

SCST_ROOT        => '/sys/kernel/scst_tgt',

# Root-level
SCST_SGV         => 'sgv',
SCST_HANDLERS    => 'handlers',
SCST_DEVICES     => 'devices',
SCST_TARGETS     => 'targets',
SCST_DEV_GROUPS  => 'device_groups',
SCST_QUEUE_RES   => 'last_sysfs_mgmt_res',

# Device group specific
SCST_DG_DEVICES  => 'devices',
SCST_DG_TGROUPS  => 'target_groups',

# Target specific
SCST_GROUPS      => 'ini_groups',
SCST_INITIATORS  => 'initiators',
SCST_SESSIONS    => 'sessions',
SCST_LUNS        => 'luns',

# Files
SCST_MGMT_IO     => 'mgmt',
SCST_VERSION_IO  => 'version',
SCST_TRACE_IO    => 'trace_level',
SCST_RESYNC_IO   => 'resync_size',
SCST_T10_IO      => 't10_dev_id',

# Module return codes
SCST_C_FATAL_ERROR          => 2,
SCST_C_BAD_ATTRIBUTES       => 7,
SCST_C_ATTRIBUTE_STATIC     => 8,
SCST_C_SETATTR_FAIL         => 9,

SCST_C_HND_NO_HANDLER       => 10,
SCST_C_HND_BAD_ATTRIBUTES   => 17,
SCST_C_HND_ATTRIBUTE_STATIC => 18,
SCST_C_HND_SETATTR_FAIL     => 19,

SCST_C_DEV_NO_DEVICE        => 20,
SCST_C_DEV_EXISTS           => 21,
SCST_C_DEV_OPEN_FAIL        => 22,
SCST_C_DEV_CLOSE_FAIL       => 23,
SCST_C_DEV_BAD_ATTRIBUTES   => 27,
SCST_C_DEV_ATTRIBUTE_STATIC => 28,
SCST_C_DEV_SETATTR_FAIL     => 29,

SCST_C_DRV_NO_DRIVER        => 30,
SCST_C_DRV_NOTVIRT          => 31,
SCST_C_DRV_SETATTR_FAIL     => 34,
SCST_C_DRV_ADDATTR_FAIL     => 35,
SCST_C_DRV_REMATTR_FAIL     => 36,
SCST_C_DRV_BAD_ATTRIBUTES   => 37,
SCST_C_DRV_ATTRIBUTE_STATIC => 38,
SCST_C_DRV_SETATTR_FAIL     => 39,

SCST_C_TGT_NO_TARGET        => 40,
SCST_C_TGT_EXISTS           => 41,
SCST_C_TGT_ADD_FAIL         => 42,
SCST_C_TGT_REM_FAIL         => 43,
SCST_C_TGT_SETATTR_FAIL     => 44,
SCST_C_TGT_ADDATTR_FAIL     => 45,
SCST_C_TGT_REMATTR_FAIL     => 46,
SCST_C_TGT_NO_LUN           => 47,
SCST_C_TGT_ADD_LUN_FAIL     => 48,
SCST_C_TGT_LUN_EXISTS       => 49,
SCST_C_TGT_BAD_ATTRIBUTES   => 50,
SCST_C_TGT_ATTRIBUTE_STATIC => 51,
SCST_C_TGT_SETATTR_FAIL     => 52,
SCST_C_TGT_CLR_LUN_FAIL     => 53,
SCST_C_TGT_BUSY             => 54,

SCST_C_GRP_NO_GROUP         => 60,
SCST_C_GRP_EXISTS           => 61,
SCST_C_GRP_ADD_FAIL         => 62,
SCST_C_GRP_REM_FAIL         => 63,

SCST_C_GRP_NO_LUN           => 70,
SCST_C_GRP_LUN_EXISTS       => 71,
SCST_C_GRP_ADD_LUN_FAIL     => 72,
SCST_C_GRP_REM_LUN_FAIL     => 73,
SCST_C_GRP_CLR_LUN_FAIL     => 75,
SCST_C_GRP_BAD_ATTRIBUTES   => 77,
SCST_C_GRP_ATTRIBUTE_STATIC => 78,
SCST_C_GRP_SETATTR_FAIL     => 79,

SCST_C_GRP_NO_INI           => 80,
SCST_C_GRP_INI_EXISTS       => 81,
SCST_C_GRP_ADD_INI_FAIL     => 82,
SCST_C_GRP_REM_INI_FAIL     => 83,
SCST_C_GRP_MOV_INI_FAIL     => 84,
SCST_C_GRP_CLR_INI_FAIL     => 85,

SCST_C_LUN_DEV_EXISTS       => 91,
SCST_C_LUN_RPL_DEV_FAIL     => 96,
SCST_C_LUN_BAD_ATTRIBUTES   => 97,
SCST_C_LUN_ATTRIBUTE_STATIC => 98,
SCST_C_LUN_SETATTR_FAIL     => 99,

SCST_C_INI_BAD_ATTRIBUTES   => 100,
SCST_C_INI_ATTRIBUTE_STATIC => 101,
SCST_C_INI_SETATTR_FAIL     => 102,

SCST_C_NO_SESSION           => 110,
SCST_C_SESSION_CLOSE_FAIL   => 111,

SCST_C_DEV_GRP_NO_GROUP     => 120,
SCST_C_DEV_GRP_EXISTS       => 121,
SCST_C_DEV_GRP_ADD_FAIL     => 122,
SCST_C_DEV_GRP_REM_FAIL     => 123,

SCST_C_ALUA_BAD_ATTRIBUTES   => 125,
SCST_C_ALUA_ATTRIBUTE_STATIC => 126,
SCST_C_ALUA_SETATTR_FAIL     => 127,

SCST_C_DGRP_ADD_DEV_FAIL    => 130,
SCST_C_DGRP_REM_DEV_FAIL    => 131,
SCST_C_DGRP_NO_DEVICE       => 132,
SCST_C_DGRP_DEVICE_EXISTS   => 133,
SCST_C_DGRP_ADD_GRP_FAIL    => 134,
SCST_C_DGRP_REM_GRP_FAIL    => 135,
SCST_C_DGRP_NO_GROUP        => 136,
SCST_C_DGRP_GROUP_EXISTS    => 137,
SCST_C_DGRP_DEVICE_OTHER    => 138,

SCST_C_DGRP_BAD_ATTRIBUTES   => 140,
SCST_C_DGRP_ATTRIBUTE_STATIC => 141,
SCST_C_DGRP_SETATTR_FAIL     => 142,

SCST_C_TGRP_BAD_ATTRIBUTES   => 150,
SCST_C_TGRP_ATTRIBUTE_STATIC => 151,
SCST_C_TGRP_SETATTR_FAIL     => 152,

SCST_C_TGRP_ADD_TGT_FAIL     => 160,
SCST_C_TGRP_REM_TGT_FAIL     => 161,
SCST_C_TGRP_NO_TGT           => 162,
SCST_C_TGRP_TGT_EXISTS       => 163,

SCST_C_TGRP_TGT_BAD_ATTR     => 170,
SCST_C_TGRP_TGT_ATTR_STATIC  => 171,
SCST_C_TGRP_TGT_SETATTR_FAIL => 172,
};

my %VERBOSE_ERROR = (
(SCST_C_FATAL_ERROR)          => 'A fatal error occurred. See "dmesg" for more information.',
(SCST_C_BAD_ATTRIBUTES)       => 'Bad attributes given for SCST.',
(SCST_C_ATTRIBUTE_STATIC)     => 'SCST attribute specified is static',
(SCST_C_SETATTR_FAIL)         => 'Failed to set a SCST attribute. See "dmesg" for more information.',

(SCST_C_HND_NO_HANDLER)       => 'No such handler exists.',
(SCST_C_HND_BAD_ATTRIBUTES)   => 'Bad attributes given for handler.',
(SCST_C_HND_ATTRIBUTE_STATIC) => 'Handler attribute given is static.',
(SCST_C_HND_SETATTR_FAIL)     => 'Failed to set handler attribute. See "dmesg" for more information.',

(SCST_C_DEV_NO_DEVICE)        => 'No such device exists.',
(SCST_C_DEV_EXISTS)           => 'Device already exists.',
(SCST_C_DEV_OPEN_FAIL)        => 'Failed to open device. See "dmesg" for more information.',
(SCST_C_DEV_CLOSE_FAIL)       => 'Failed to close device. See "dmesg" for more information.',
(SCST_C_DEV_BAD_ATTRIBUTES)   => 'Bad attributes given for device.',
(SCST_C_DEV_ATTRIBUTE_STATIC) => 'Device attribute specified is static.',
(SCST_C_DEV_SETATTR_FAIL)     => 'Failed to set device attribute. See "dmesg" for more information.',

(SCST_C_DRV_NO_DRIVER)        => 'No such driver exists.',
(SCST_C_DRV_NOTVIRT)          => 'Driver is incapable of dynamically adding/removing targets or attributes.',
(SCST_C_DRV_ADDATTR_FAIL)     => 'Failed to add driver dynamic attribute. See "dmesg" for more information.',
(SCST_C_DRV_REMATTR_FAIL)     => 'Failed to remove driver dymanic attribute. See "dmesg" for more information.',
(SCST_C_DRV_BAD_ATTRIBUTES)   => 'Bad attributes given for driver.',
(SCST_C_DRV_ATTRIBUTE_STATIC) => 'Driver attribute specified is static.',
(SCST_C_DRV_SETATTR_FAIL)     => 'Failed to set driver attribute. See "dmesg" for more information.',

(SCST_C_TGT_NO_TARGET)        => 'No such target exists.',
(SCST_C_TGT_EXISTS)           => 'Target already exists.',
(SCST_C_TGT_ADD_FAIL)         => 'Failed to add target. See "dmesg" for more information.',
(SCST_C_TGT_REM_FAIL)         => 'Failed to remove target. See "dmesg" for more information.',
(SCST_C_TGT_SETATTR_FAIL)     => 'Failed to set target attribute. See "dmesg" for more information.',
(SCST_C_TGT_ADDATTR_FAIL)     => 'Failed to add target dynamic attribute. See "dmesg" for more information.',
(SCST_C_TGT_REMATTR_FAIL)     => 'Failed to remove target dynamic attribute. See "dmesg" for more information.',
(SCST_C_TGT_NO_LUN)           => 'No such LUN exists.',
(SCST_C_TGT_ADD_LUN_FAIL)     => 'Failed to add LUN to target. See "dmesg" for more information.',
(SCST_C_TGT_LUN_EXISTS)       => 'LUN already exists.',
(SCST_C_TGT_BAD_ATTRIBUTES)   => 'Bad attributes given for target.',
(SCST_C_TGT_ATTRIBUTE_STATIC) => 'Target attribute specified is static.',
(SCST_C_TGT_SETATTR_FAIL)     => 'Failed to set target attribute. See "dmesg" for more information.',
(SCST_C_TGT_CLR_LUN_FAIL)     => 'Failed to clear LUNs from target. See "dmesg" for more information.',
(SCST_C_TGT_BUSY)             => 'Failed to remove target - target has active sessions. See "dmesg" for more information.',

(SCST_C_GRP_NO_GROUP)         => 'No such group exists.',
(SCST_C_GRP_EXISTS)           => 'Group already exists.',
(SCST_C_GRP_ADD_FAIL)         => 'Failed to add group. See "dmesg" for more information.',
(SCST_C_GRP_REM_FAIL)         => 'Failed to remove group. See "dmesg" for more information.',

(SCST_C_GRP_NO_LUN)           => 'No such LUN exists.',
(SCST_C_GRP_LUN_EXISTS)       => 'LUN already exists.',
(SCST_C_GRP_ADD_LUN_FAIL)     => 'Failed to add LUN to group. See "dmesg" for more information.',
(SCST_C_GRP_REM_LUN_FAIL)     => 'Failed to remove LUN. See "dmesg" for more information.',
(SCST_C_GRP_CLR_LUN_FAIL)     => 'Failed to clear LUNs from group. See "dmesg" for more information.',
(SCST_C_GRP_BAD_ATTRIBUTES)   => 'Bad attributes given for group.',
(SCST_C_GRP_ATTRIBUTE_STATIC) => 'Group attribute specified is static.',
(SCST_C_GRP_SETATTR_FAIL)     => 'Failed to set group attribute. See "dmesg" for more information.',

(SCST_C_GRP_NO_INI)           => 'No such initiator exists.',
(SCST_C_GRP_INI_EXISTS)       => 'Initiator already exists.',
(SCST_C_GRP_ADD_INI_FAIL)     => 'Failed to add initiator. See "dmesg" for more information.',
(SCST_C_GRP_REM_INI_FAIL)     => 'Failed to remove initiator. See "dmesg" for more information.',
(SCST_C_GRP_MOV_INI_FAIL)     => 'Failed to move initiator. See "dmesg" for more information.',
(SCST_C_GRP_CLR_INI_FAIL)     => 'Failed to clear initiators. See "dmesg" for more information.',

(SCST_C_LUN_DEV_EXISTS)       => 'Device already exists for LUN.',
(SCST_C_LUN_RPL_DEV_FAIL)     => 'Failed to replace device for LUN. See "dmesg" for more information.',
(SCST_C_LUN_BAD_ATTRIBUTES)   => 'Bad attributes for LUN.',
(SCST_C_LUN_ATTRIBUTE_STATIC) => 'LUN attribute specified is static.',
(SCST_C_LUN_SETATTR_FAIL)     => 'Failed to set LUN attribute. See "dmesg" for more information.',

(SCST_C_INI_BAD_ATTRIBUTES)   => 'Bad attributes for initiator.',
(SCST_C_INI_ATTRIBUTE_STATIC) => 'Initiator attribute specified is static.',
(SCST_C_INI_SETATTR_FAIL)     => 'Failed to set initiator attribute. See "dmesg" for more information.',

(SCST_C_NO_SESSION)           => 'Session not found for driver/target.',
(SCST_C_SESSION_CLOSE_FAIL)   => 'Failed to close session.',

(SCST_C_DEV_GRP_NO_GROUP)     => 'No such device group exists.',
(SCST_C_DEV_GRP_EXISTS)       => 'Device group already exists.',
(SCST_C_DEV_GRP_ADD_FAIL)     => 'Failed to add device group. See "dmesg" for more information.',
(SCST_C_DEV_GRP_REM_FAIL)     => 'Failed to remove device group. See "dmesg" for more information.',

(SCST_C_DGRP_ADD_DEV_FAIL)    => 'Failed to add device to device group. See "dmesg" for more information.',
(SCST_C_DGRP_REM_DEV_FAIL)    => 'Failed to remove device from device group. See "dmesg" for more information.',
(SCST_C_DGRP_NO_DEVICE)       => 'No such device in device group.',
(SCST_C_DGRP_DEVICE_EXISTS)   => 'Device already exists within device group.',
(SCST_C_DGRP_ADD_GRP_FAIL)    => 'Failed to add target group to device group. See "dmesg" for more information.',
(SCST_C_DGRP_REM_GRP_FAIL)    => 'Failed to remove target group from device group. See "dmesg" for more information.',
(SCST_C_DGRP_NO_GROUP)        => 'No such target group exists within device group.',
(SCST_C_DGRP_GROUP_EXISTS)    => 'Target group already exists within device group.',
(SCST_C_DGRP_DEVICE_OTHER)    => 'Device is already assigned to another device group.',

(SCST_C_DGRP_BAD_ATTRIBUTES)   => 'Bad attributes for device group.',
(SCST_C_DGRP_ATTRIBUTE_STATIC) => 'Device group attribute specified is static.',
(SCST_C_DGRP_SETATTR_FAIL)     => 'Failed to set device group attribute. See "dmesg" for more information.',

(SCST_C_TGRP_BAD_ATTRIBUTES)   => 'Bad attributes for target group.',
(SCST_C_TGRP_ATTRIBUTE_STATIC) => 'Target group attribute specified is static.',
(SCST_C_TGRP_SETATTR_FAIL)     => 'Failed to set target group attribute. See "dmesg" for more information.',

(SCST_C_TGRP_ADD_TGT_FAIL)     => 'Failed to add target to target group.',
(SCST_C_TGRP_REM_TGT_FAIL)     => 'Failed to remove target from target group.',
(SCST_C_TGRP_NO_TGT)           => 'No such target exists within target group.',
(SCST_C_TGRP_TGT_EXISTS)       => 'Target already exists within target group.',

(SCST_C_TGRP_TGT_BAD_ATTR)     => 'Bad attributes for target group target.',
(SCST_C_TGRP_TGT_ATTR_STATIC)  => 'Target group target attribute specified is static.',
(SCST_C_TGRP_TGT_SETATTR_FAIL) => 'Failed to set target group target attribute. See "dmesg" for more information.',
);

use vars qw(@ISA @EXPORT $VERSION);

use vars qw($TGT_TYPE_HARDWARE $TGT_TYPE_VIRTUAL);

$VERSION = '1.0.0';

$TGT_TYPE_HARDWARE = 1;
$TGT_TYPE_VIRTUAL  = 2;

my $TIMEOUT = 300; # Command execution timeout

my $_SCST_MIN_MAJOR_   = 2;
my $_SCST_MIN_MINOR_   = 0;
my $_SCST_MIN_RELEASE_ = 0;

sub SCST_ROOT_DIR {
	return SCST_ROOT;
}

sub SCST_SGV_DIR {
	return SCST_ROOT . '/sgv';
}

sub SCST_QUEUE_RES_PATH {
	return SCST_ROOT . '/' . SCST_QUEUE_RES;
}

# Device handlers.
sub SCST_HANDLERS_DIR {
	return SCST_ROOT . '/' . SCST_HANDLERS;
}

# Device instances.
sub SCST_DEVICES_DIR {
	return SCST_ROOT . '/' . SCST_DEVICES;
}

# Target drivers.
sub SCST_TARGETS_DIR {
	return SCST_ROOT . '/' . SCST_TARGETS;
}

# ALUA Device groups.
sub SCST_DEV_GROUP_DIR {
	return SCST_ROOT . '/' . SCST_DEV_GROUPS;
}

sub new {
	my $this = shift;
	my $debug = shift;
	my $badVersion = 1;

	my $class = ref($this) || $this;
	my $self = {};

	bless($self, $class);

	$self->{'debug'} = $debug;

	my $rawVersion = $self->scstVersion();

	die("Failed to obtain SCST version information. Are the SCST modules loaded?\n")
	  if (!defined($rawVersion));

	my ($scstVersion) = ($rawVersion =~ /(\d+\.\d+\.\d+)/);

	die("Failed to parse SCST version from '$rawVersion'\n")
	  if (!defined($scstVersion));

	my($major, $minor, $release) = split(/\./, $scstVersion, 3);

	($release, undef) = split(/\-/, $release) if ($release =~ /\-/);

	$badVersion = 0 if (($major > $_SCST_MIN_MAJOR_) ||
			    (($major == $_SCST_MIN_MAJOR_) && ($minor > $_SCST_MIN_MINOR_)) ||
			    (($major == $_SCST_MIN_MAJOR_) && ($minor == $_SCST_MIN_MINOR_) &&
			     ($release >= $_SCST_MIN_RELEASE_)));

	die("This module requires at least SCST version $_SCST_MIN_MAJOR_\.$_SCST_MIN_MINOR_\.".
	      "$_SCST_MIN_RELEASE_ and version $scstVersion was found") if ($badVersion);

	return $self;
}

# Returns 1 if and only if the owner of a file is not allowed to write to a
# file.
sub readOnly {
	my ($path) = @_;
	my $mode = (stat($path))[2];

	if (!defined($mode)) {
		cluck("invalid path $path");
		return undef;
	}
	return ($mode & S_IWUSR) == 0;
}

sub scstVersion {
	my $self = shift;

	my ($attributes, $errorString) = $self->scstAttributes();

	return undef if (!defined($attributes));
	return $$attributes{'version'}->{'value'};
}

sub scstAttributes {
	my $self = shift;
	my %attributes = ( );

	my $pHandle = new IO::Handle;
	my $_path = SCST_ROOT_DIR();
	if (!(opendir $pHandle, $_path)) {
		return (undef, "scstAttributes(): Unable to read directory '$_path': $!");
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path(SCST_ROOT_DIR(), $attribute);
		my $mode = (stat($pPath))[2];

		if (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if (($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "scsiAttributes(): Unable to read ".
					  "scst attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				if ($attribute eq SCST_TRACE_IO) {
					$attributes{$attribute}->{'value'} = $value;
					my @possible;
					$value = '';
					my $start = FALSE;
					while (my $line = <$io>) {
						$start = TRUE if ($line !~ /\[/);
						$value .= $line if ($start);
					}
					$value =~ s/\n//g;

					if ($value =~ /\[(.*)\]/) {
						$value = $1;

						foreach my $t (split(/\,/, $value)) {
							$t =~ s/^\s+//; $t =~ s/\s+$//;
							push @possible, $t;
						}
					}
					$attributes{$attribute}->{'set'} = \@possible;
				} else {
					if ($is_key) {
						$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
					} else {
						$attributes{$attribute}->{'value'} = $value;
					}
				}
				close $io;

				$attributes{$attribute}->{'static'} = $is_static;
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

# Older Perl versions complain if the argument of length() is undefined. Hence
# this function that checks whether its arguments are defined and not empty.
sub valid {
	for my $arg (@_) {
		return FALSE if (!defined($arg) || $arg eq "");
	}
	return TRUE;
}

# Convert e.g. EINVAL into "EINVAL".
sub my_strerror {
	my ($errorcode) = @_;

	return $errorcode if (!defined($errorcode));
	for my $errstr (keys(%!)) {
		my $err = eval($errstr);
		return $errstr if (defined($err) and $err == $errorcode);
	}
	return $errorcode;
}

sub setAttrFailed {
	my ($path, $bytes, $no_such_attr, $is_static, $failed) = @_;

	print STDERR "(" . my_strerror(-$bytes) . ") ";
	return $no_such_attr if !(-f $path);
	return $is_static if readOnly($path);
	return $failed;
}

sub setScstAttribute {
	my $self = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($attribute) || !defined($value));

	# There is a space between the unary minus sign and ENOENT because
	# without that space older Perl versions report the following warning:
	# Ambiguous use of -ENOENT resolved as -&ENOENT() at
	# /usr/share/perl5/vendor_perl/SCST/SCST.pm line 497.
	my $bytes = - ENOENT;
	my $path = make_path(SCST_ROOT_DIR(), $attribute);
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}
	return setAttrFailed($path, $bytes, SCST_C_BAD_ATTRIBUTES,
			     SCST_C_ATTRIBUTE_STATIC, SCST_C_SETATTR_FAIL);
}

sub drivers {
	my $self = shift;
	my $dHandle = new IO::Handle;
	my $_path = SCST_TARGETS_DIR();
	my @drivers;

	if (opendir($dHandle, $_path)) {
		foreach my $driver (readdir($dHandle)) {
			next if ($driver eq '.' || $driver eq '..');

			if (-d make_path(SCST_TARGETS_DIR(), $driver)) {
				push @drivers, $driver;
			}
		}
		@drivers = sort(@drivers);
		close $dHandle;
	} else {
		return (undef, "drivers(): Unable to read directory '$_path': $!");
	}

	return (\@drivers, undef);
}


sub targets {
	my $self = shift;
	my $driver = shift;

	return (undef, "Too few arguments") if (!valid($driver));

	my $tHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver);
	if (opendir $tHandle, $_path) {
		my @targets;

		foreach my $target (readdir($tHandle)) {
			next if ($target eq '.' || $target eq '..' ||
				 $target eq 'module');

			if (-d make_path(SCST_TARGETS_DIR(), $driver,
					 $target)) {
				push @targets, $target;
			}
		}
		close $tHandle;
		@targets = sort(@targets);
		return (\@targets, undef);
	}
	my $errorString;
	if ($self->driverExists($driver) != TRUE) {
		$errorString = "targets(): Driver '$driver' is not available";
	} else {
		$errorString = "targets(): Unable to read directory '$_path': $!";
	}

	return (undef, $errorString);
}

sub groups {
	my $self = shift;
	my $driver = shift;
	my $target = shift;

	return (undef, "Too few arguments") if (!valid($driver, $target));

	my $gHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
			      SCST_GROUPS);

	if (opendir $gHandle, $_path) {
		my @groups;

		foreach my $group (readdir($gHandle)) {
			next if ($group eq '.' || $group eq '..');

			if (-d make_path(SCST_TARGETS_DIR(), $driver,
					 $target, SCST_GROUPS, $group)) {
				push @groups, $group;
			}
		}
		close $gHandle;
		@groups = sort(@groups);
		return (\@groups, undef);
	}

	my $errorString;
	if ($self->driverExists($driver) != TRUE) {
		$errorString = "groups(): Driver '$driver' is not available";
	} elsif ($self->targetExists($driver, $target) != TRUE) {
		$errorString = "groups(): Target '$target' is not available";
	} else {
		$errorString = "groups(): Unable to read directory '$_path': $!";
	}
	return (undef, $errorString);
}

sub initiators {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my @initiators;
	my $errorString;

	return (undef, "Too few arguments")
	    if (!valid($driver, $target, $group));

	my $iHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			      $group, SCST_INITIATORS);
	if (!(opendir $iHandle, $_path)) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "initiators(): Driver '$driver' is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "initiators(): Target '$target' is not available";
		} elsif ($self->groupExists($driver, $target, $group) != TRUE) {
			$errorString = "initiators(): Group '$group' does not exist";
		} else {
			$errorString = "initiators(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $initiator (readdir($iHandle)) {
		next if (($initiator eq '.') || ($initiator eq '..'));
		next if ($initiator eq SCST_MGMT_IO);

		push @initiators, $initiator;
	}

	close $iHandle;

	return (\@initiators, undef);
}

sub luns {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($driver, $target));

	my $_path;

	if (valid($group)) {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_GROUPS, $group, SCST_LUNS);
	} else {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_LUNS);
	}

	my $lHandle = new IO::Handle;

	if (!(opendir $lHandle, $_path)) {
		if (valid($group) &&
		    $self->groupExists($driver, $target, $group) != TRUE) {
			$errorString = "initiators(): Group '$group' does not exist";
		} elsif ($self->driverExists($driver) != TRUE) {
			$errorString = "luns(): Driver '$driver' is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "luns(): Target '$target' is not available";
		} else {
			$errorString = "luns(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	my %luns;

	foreach my $lun (readdir($lHandle)) {
		next if (($lun eq '.') || ($lun eq '..'));

		my $lPath = make_path($_path, $lun);

		if (-d $lPath) {
			my $_lHandle = new IO::Handle;

			if (!(opendir $_lHandle, $lPath)) {
				return (undef, "luns(): Unable to read directory '$lPath': $!");
			}

			foreach my $attribute (readdir($_lHandle)) {
				my $pPath = make_path($lPath, $attribute);

				if (-l $pPath) {
					my $linked = readlink($pPath);
					$linked =~ s/.*\///;
					$luns{$lun} = $linked;
				}
			}

			close $_lHandle;
		}
	}

	close $lHandle;

	return \%luns;
}

sub aluaAttributes {
	my $self = shift;
	my %attributes = ( );

	my $pHandle = new IO::Handle;
	my $_path = SCST_DEV_GROUP_DIR();
	if (!(opendir $pHandle, $_path)) {
		return (undef, "deviceGroupsAttributes(): Unable to read directory '$_path': $!");
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO || $attribute eq 'uevent');
		my $pPath = make_path(SCST_DEV_GROUP_DIR(), $attribute);
		my $mode = (stat($pPath))[2];

		if (!($mode & S_IRUSR)) {
			$attributes{$attribute}->{'static'} = FALSE;
			$attributes{$attribute}->{'value'} = undef;
		} else {
			my $is_static = !($mode & S_IWUSR);
			my $io = new IO::File $pPath, O_RDONLY;

			if (!$io) {
				return (undef, "aluaAttributes(): Unable to read device attribute '$attribute': $!");
			}

			my $value = <$io>;
			$value = "" if (!defined($value));
			chomp $value;

			my $second_line = <$io>;
			$second_line = "" if (!defined($second_line));
			if ($second_line =~ /\[key\]/) {
				my $key = 0;
				if ($attribute =~ /^([^\d]+)(\d+)$/) {
					$attribute = $1;
					$key = $2;
				}
				$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
			} else {
				$attributes{$attribute}->{'value'} = $value;
			}
			close $io;

			$attributes{$attribute}->{'static'} = $is_static;
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub deviceGroups {
	my $self = shift;
	my @groups;

	my $dHandle = new IO::Handle;
	my $_path = SCST_DEV_GROUP_DIR();
	if (!(opendir $dHandle, $_path)) {
		return (undef, "deviceGroups(): Unable to read directory '$_path': $!");
	}

	foreach my $group (readdir($dHandle)) {
		next if (($group eq '.') || ($group eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group)) {
			push @groups, $group;
		}
	}

	close $dHandle;
	@groups = sort(@groups);
	return (\@groups, undef);
}

sub deviceGroupDevices {
	my $self = shift;
	my $group = shift;
	my @devices;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($group));

	my $dHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES);
	if (!(opendir $dHandle, $_path)) {
		if ($self->deviceGroupExists($group) != TRUE) {
			$errorString = "deviceGroupDevices(): Device group '$group' does not exist";
		} else {
			$errorString = "deviceGroupDevices(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $device (readdir($dHandle)) {
		next if (($device eq '.') || ($device eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES, $device)) {
			push @devices, $device;
		}
	}

	close $dHandle;

	return (\@devices, undef);
}

sub targetGroups {
	my $self = shift;
	my $group = shift;
	my @tgroups;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($group));

	my $dHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS);
	if (!(opendir $dHandle, $_path)) {
		if ($self->deviceGroupExists($group) != TRUE) {
			$errorString = "targetGroups(): Device group '$group' does not exist";
		} else {
			$errorString = "targetGroups(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $tgroup (readdir($dHandle)) {
		next if (($tgroup eq '.') || ($tgroup eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup)) {
			push @tgroups, $tgroup;
		}
	}

	close $dHandle;

	return (\@tgroups, undef);
}

sub targetGroupTargets {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my @targets;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($group, $tgroup));

	my $dHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup);
	if (!(opendir $dHandle, $_path)) {
		if ($self->deviceGroupExists($group) != TRUE) {
			$errorString = "targetGroupTargets(): Device group '$group' does not exist";
		} elsif ($self->targetGroupExists($group, $tgroup) != TRUE) {
			$errorString = "targetGroupTargets(): Target group '$tgroup' does not exist";
		} else {
			$errorString = "targetGroupTargets(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $tgt (readdir($dHandle)) {
		next if (($tgt eq '.') || ($tgt eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup, $tgt)) {
			push @targets, $tgt;
		}
	}

	close $dHandle;

	@targets = sort(@targets);

	return (\@targets, undef);
}

sub driverExists {
	my $self = shift;
	my $driver = shift;
	my $dHandle = new IO::Handle;
	my $result;

	$result = valid($driver) &&
	    opendir($dHandle, make_path(SCST_TARGETS_DIR(), $driver));
	close $dHandle if ($result);

	return $result ? TRUE : FALSE;
}

sub driverDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my %attributes = ( );
	my $available;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($driver));

	my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
					SCST_MGMT_IO), O_RDONLY;

	if (!$io) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "driverDynamicAttributes(): Driver '$driver' ".
			    "is not available";
		} else {
			$errorString = "driverDynamicAttributes(): Unable to open mgmt ".
			    "interface for driver '$driver': $!";
		}
		return (undef, $errorString);
	}

	while (my $in = <$io>) {
		if ($in =~ /^The following target driver attributes available\:/) {
			(undef, $available) = split(/\:/, $in, 2);
			$available =~ s/\.$//;
		}
	}
	close $io;

	if ($available) {
		foreach my $attribute (split(/\,/, $available)) {
			$attribute =~ s/^\s+//;
			$attribute =~ s/\s+$//;
			$attributes{$attribute} = '';
		}
	}

	return (\%attributes, undef);
}

sub checkDriverDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my $check = shift;

	return TRUE if (!valid($driver));

	my ($available, $errorString) = $self->driverDynamicAttributes($driver);

	if (!defined($available)) {
		my $rc = $self->driverExists($driver);
		return SCST_C_DRV_NO_DRIVER if (!$rc);
		return $rc if ($rc > 1);

		return SCST_C_FATAL_ERROR;
	}

	return FALSE if (!defined($check));

	if (ref($check) eq 'HASH') {
		foreach my $attribute (keys %{$check}) {
			if (!defined($$available{$attribute})) {
				return TRUE;
			}
		}
	} else {
		if (!defined($$available{$check})) {
			return TRUE;
		}
	}

	return FALSE;
}

sub addDriverDynamicAttribute {
	my $self = shift;
	my $driver = shift;
	my $attribute = shift;
	my $value = shift;

	return SCST_C_DRV_ADDATTR_FAIL if (!valid($driver, $attribute) ||
					   !defined($value));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	$cmd .= "add_attribute $attribute $value";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$rc = $self->checkDriverDynamicAttributes($driver, $attribute);
	return SCST_C_DRV_BAD_ATTRIBUTES if ($rc == 1);
	return $rc if ($rc > 1);

	return SCST_C_DRV_ADDATTR_FAIL;
}

sub removeDriverDynamicAttribute {
	my $self = shift;
	my $driver = shift;
	my $attribute = shift;
	my $value = shift;

	return SCST_C_DRV_REMATTR_FAIL if (!valid($driver, $attribute) ||
					   !defined($value));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	$cmd .= "del_attribute $attribute $value";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$rc = $self->checkDriverDynamicAttributes($driver, $attribute);
	return SCST_C_DRV_BAD_ATTRIBUTES if ($rc == 1);
	return $rc if ($rc > 1);

	return SCST_C_DRV_REMATTR_FAIL;
}

sub targetExists {
	my $self = shift;
	my $driver = shift;
	my $target = shift;

	return valid($driver, $target) &&
	    $target ne '.' && $target ne '..' && $target ne 'module' &&
	    (-d make_path(SCST_TARGETS_DIR(), $driver, $target)) ? TRUE : FALSE;
}

sub driverIsVirtualCapable {
	my $self = shift;
	my $driver = shift;
	my $path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	return (-w $path) ? TRUE : FALSE;
}

sub targetType {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($driver, $target));

	if ($self->driverIsVirtualCapable($driver)) {
		my $attribs;
		($attribs, $errorString) = $self->targetAttributes($driver, $target);

		if (defined($$attribs{'hw_target'}) &&
		    ($$attribs{'hw_target'}->{'value'} == TRUE)) {
			return $TGT_TYPE_HARDWARE;
		} else {
			return $TGT_TYPE_VIRTUAL;
		}
	}

	return $TGT_TYPE_HARDWARE;
}

sub addVirtualTarget {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $attributes = shift;

	my $o_string = "";
	foreach my $attribute (keys %{$attributes}) {
		if (ref($$attributes{$attribute}) eq 'ARRAY') {
			foreach my $value (@{$$attributes{$attribute}}) {
				$o_string .= "$attribute=$value;";
			}
		} else {
			my $value = $$attributes{$attribute};
			$o_string .= "$attribute=$value;";
		}
	}

	$o_string =~ s/\s$//;

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	$cmd .= "add_target $target $o_string";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_EXISTS if ($rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$rc = $self->checkTargetCreateAttributes($driver, $attributes);
	return SCST_C_TGT_BAD_ATTRIBUTES if ($rc == TRUE);
	return $rc if ($rc > 1);

	return SCST_C_TGT_ADD_FAIL;
}

sub targetDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my %attributes = ( );
	my $available;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($driver));

	my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
					SCST_MGMT_IO), O_RDONLY;

	if (!$io) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "targetDynamicAttributes(): Driver '$driver' ".
			    "is not available";
		} else {
			$errorString = "targetDynamicAttributes(): Unable to open mgmt ".
			    "interface for driver '$driver': $!";
		}
		return (undef, $errorString);
	}

	while (my $in = <$io>) {
		if ($in =~ /^The following target attributes available\:/) {
			(undef, $available) = split(/\:/, $in, 2);
			$available =~ s/\.$//;
		}
	}
	close $io;

	if ($available) {
		foreach my $attribute (split(/\,/, $available)) {
			$attribute =~ s/^\s+//;
			$attribute =~ s/\s+$//;
			$attributes{$attribute} = '';
		}
	}

	return (\%attributes, undef);
}

sub checkTargetDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my $check = shift;

	my ($available, $errorString) = $self->targetDynamicAttributes($driver);

	if (!defined($available)) {
		my $rc = $self->driverExists($driver);
		return SCST_C_DRV_NO_DRIVER if (!$rc);
		return $rc if ($rc > 1);

		return SCST_C_FATAL_ERROR;
	}

	return FALSE if (!defined($check));

	if (ref($check) eq 'HASH') {
		foreach my $attribute (keys %{$check}) {
			if (!defined($$available{$attribute})) {
				return TRUE;
			}
		}
	} else {
		if (!defined($$available{$check})) {
			return TRUE;
		}
	}

	return FALSE;
}

sub addTargetDynamicAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $attribute = shift;
	my $value = shift;

	return SCST_C_TGT_ADDATTR_FAIL
	    if (!valid($driver, $target, $attribute) || !defined($value));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	$cmd .= "add_target_attribute $target $attribute $value";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$rc = $self->checkTargetDynamicAttributes($driver, $attribute);
	return SCST_C_TGT_BAD_ATTRIBUTES if ($rc == 1);
	return $rc if ($rc > 1);

	return SCST_C_TGT_ADDATTR_FAIL;
}

sub removeTargetDynamicAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $attribute = shift;
	my $value = shift;

	return SCST_C_TGT_REMATTR_FAIL
	    if (!valid($driver, $target, $attribute) || !defined($value));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	$cmd .= "del_target_attribute $target $attribute $value";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$rc = $self->checkTargetDynamicAttributes($driver, $attribute);
	return SCST_C_TGT_BAD_ATTRIBUTES if ($rc == 1);
	return $rc if ($rc > 1);

	return SCST_C_TGT_REMATTR_FAIL;
}

sub removeVirtualTarget {
	my $self = shift;
	my $driver = shift;
	my $target = shift;

	# May fail if the target does not have an 'enabled' attribute as is the
	# case for e.g. the 'scst_local' driver.
	$self->enableTarget($driver, $target, FALSE);

	my ($sessions, $errorString) = $self->sessions($driver, $target);

	my %can_close;
	foreach my $session (keys %{$sessions}) {
		if (defined($$sessions{$session}->{'force_close'})) {
			$can_close{$session}++;
			my $rc = $self->closeSession($driver, $target, $session);
			return $rc if ($rc);
		}
	}

	if (scalar keys %can_close) {
		my $has_sessions = 1;
		my $now = time();
		while ($has_sessions && (($now + $TIMEOUT) > time())) {
			($sessions, $errorString) = $self->sessions($driver, $target);

			foreach my $session (keys %can_close) {
				if (!defined($$sessions{$session})) {
					delete $can_close{$session};
				}
			}

			$has_sessions = scalar keys %can_close;
			sleep 1 if ($has_sessions);
		}

		return SCST_C_TGT_BUSY if ($has_sessions);
	}

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	$cmd .= "del_target $target";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	return SCST_C_TGT_REM_FAIL;
}

sub groupExists {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	return FALSE if (!valid($driver, $target, $group));

	my ($groups, $errorString) = $self->groups($driver, $target);

	if (!defined($groups)) {
		my $rc = $self->targetExists($driver, $target);
		return FALSE if (!$rc);
		return $rc if ($rc > 1);

		return SCST_C_FATAL_ERROR;
	}

	foreach my $_group (@{$groups}) {
		return TRUE if ($group eq $_group);
	}

	return FALSE;
}

sub initiatorExists {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;

	return FALSE if (!valid($driver, $target, $group, $initiator));

	my ($initiators, $errorString) = $self->initiators($driver, $target, $group);

	if (!defined($initiators)) {
		my $rc = $self->groupExists($driver, $target, $group);
		return FALSE if (!$rc);
		return $rc if ($rc > 1);

		return SCST_C_FATAL_ERROR;
	}

	foreach my $_initiator (@{$initiators}) {
		return TRUE if ($initiator eq $_initiator);
	}

	return FALSE;
}

sub lunExists {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $group = shift;

	return FALSE if (!valid($driver, $target, $lun));

	my ($luns, $errorString) = $self->luns($driver, $target, $group);

	if (!defined($luns)) {
		my $rc = $self->driverExists($driver);
		return SCST_C_DRV_NO_DRIVER if (!$rc);
		return $rc if ($rc > 1);

		$rc = $self->targetExists($driver, $target);
		return SCST_C_TGT_NO_TARGET if (!$rc);
		return $rc if ($rc > 1);

		if (defined($group)) {
			my $rc = $self->groupExists($driver, $target, $group);
			return SCST_C_GRP_NO_GROUP if (!$rc);
			return $rc if ($rc > 1);
		}
		return SCST_C_FATAL_ERROR;
	}

	foreach my $_lun (keys %{$luns}) {
		return TRUE if ($lun == $_lun);
	}

	return FALSE;
}

sub addGroup {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	return SCST_C_GRP_ADD_FAIL if (!valid($driver, $target, $group));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			  SCST_MGMT_IO);
	$cmd .= "create $group";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	return SCST_C_GRP_ADD_FAIL;
}

sub removeGroup {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	return SCST_C_GRP_REM_FAIL if (!valid($driver, $target, $group));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			  SCST_MGMT_IO);
	$cmd .= "del $group";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_GRP_REM_FAIL;
}

sub addDeviceGroup {
	my $self = shift;
	my $group = shift;

	return SCST_C_DEV_GRP_ADD_FAIL if (!valid($group));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), SCST_MGMT_IO);
	$cmd .= "create $group";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return $rc == TRUE ? SCST_C_DEV_GRP_EXISTS : $rc > 1 ? $rc :
	    SCST_C_DEV_GRP_ADD_FAIL;
}

sub removeDeviceGroup {
	my $self = shift;
	my $group = shift;

	return SCST_C_DEV_GRP_REM_FAIL if (!valid($group));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), SCST_MGMT_IO);
	$cmd .= "del $group";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DEV_GRP_REM_FAIL;
}

sub addDeviceGroupDevice {
	my $self = shift;
	my $group = shift;
	my $device = shift;
	my $dgroups;
	my $errorString;

	return SCST_C_DGRP_ADD_DEV_FAIL if (!valid($group, $device));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES,
			  SCST_MGMT_IO);
	$cmd .= "add $device";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->deviceExists($device);
        return SCST_C_DEV_NO_DEVICE if (!$rc);
        return $rc if ($rc > 1);

	$rc = $self->deviceGroupDeviceExists($group, $device);
	return SCST_C_DGRP_DEVICE_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	# Check all device groups for this device
	($dgroups, $errorString) = $self->deviceGroups();
	foreach my $dgroup (@{$dgroups}) {
		my $devs;

		($devs, $errorString) = $self->deviceGroupDevices($dgroup);
		foreach my $dev (@{$devs}) {
			return SCST_C_DGRP_DEVICE_OTHER if ($dev eq $device);
		}
	}

	return SCST_C_DGRP_ADD_DEV_FAIL;
}

sub addTargetGroup {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;

	return SCST_C_DGRP_ADD_GRP_FAIL if (!valid($group, $tgroup));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
			  SCST_MGMT_IO);
	$cmd .= "add $tgroup";

	my $bytes = - ENONENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_GROUP_EXISTS if ($rc == TRUE);
	return $rc > 1 ? $rc : SCST_C_DGRP_ADD_GRP_FAIL;
}

sub addTargetGroupTarget {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;

	return SCST_C_TGRP_ADD_TGT_FAIL
	    if (!valid($group, $tgroup, $tgt));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
			  $tgroup, SCST_MGMT_IO);
	$cmd .= "add $tgt";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupTargetExists($group, $tgroup, $tgt);
	return $rc == TRUE ? SCST_C_TGRP_TGT_EXISTS : $rc > 1 ? $rc : SCST_C_TGRP_ADD_TGT_FAIL;
}

sub removeDeviceGroupDevice {
	my $self = shift;
	my $group = shift;
	my $device = shift;

	return SCST_C_DGRP_REM_DEV_FAIL if (!valid($group, $device));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES,
			  SCST_MGMT_IO);
	$cmd .= "del $device";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->deviceExists($device);
        return SCST_C_DEV_NO_DEVICE if (!$rc);
        return $rc if ($rc > 1);

	$rc = $self->deviceGroupDeviceExists($group, $device);
	return SCST_C_DGRP_NO_DEVICE if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DGRP_REM_DEV_FAIL;
}

sub removeTargetGroup {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;

	return SCST_C_DGRP_REM_GRP_FAIL if (!valid($group, $tgroup));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
			  SCST_MGMT_IO);
	$cmd .= "del $tgroup";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DGRP_REM_GRP_FAIL;
}

sub removeTargetGroupTarget {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;

	return SCST_C_TGRP_REM_TGT_FAIL if (!valid($group, $tgroup, $tgt));

	my ($path, $cmd);
	$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
			  $tgroup, SCST_MGMT_IO);
	$cmd .= "del $tgt";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupTargetExists($group, $tgroup, $tgt);
	return SCST_C_TGRP_NO_TGT if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_TGRP_REM_TGT_FAIL;
}

sub addInitiator {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;

	return SCST_C_GRP_ADD_INI_FAIL
	    if (!valid($driver, $target, $group, $initiator));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			  $group, SCST_INITIATORS, SCST_MGMT_IO);
	$cmd .= "add $initiator";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	return SCST_C_GRP_REM_INI_FAIL
	    if (!valid($driver, $target, $initiator));

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->initiatorExists($driver, $target, $group, $initiator);
	return SCST_C_GRP_INI_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	return SCST_C_GRP_ADD_INI_FAIL;
}

sub removeInitiator {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;

	return SCST_C_GRP_REM_INI_FAIL
	    if (!valid($driver, $target, $group, $initiator));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			  $group, SCST_INITIATORS, SCST_MGMT_IO);
	$cmd .= "del $initiator";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->initiatorExists($driver, $target, $group, $initiator);
	return SCST_C_GRP_NO_INI if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_GRP_REM_INI_FAIL;
}

sub moveInitiator {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $from = shift;
	my $to = shift;
	my $initiator = shift;

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			  $from, SCST_INITIATORS, SCST_MGMT_IO);
	$cmd .= "move $initiator $to";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $from);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $to);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->initiatorExists($driver, $target, $from, $initiator);
	return SCST_C_GRP_NO_INI if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->initiatorExists($driver, $target, $to, $initiator);
	return SCST_C_GRP_INI_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	return SCST_C_GRP_MOV_INI_FAIL;
}

sub clearInitiators {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			  $group, SCST_INITIATORS, SCST_MGMT_IO);
	$cmd .= "clear";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_GRP_CLR_INI_FAIL;
}

sub addLun {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $device = shift;
	my $lun = shift;
	my $attributes = shift;
	my $group = shift;

	my $err = valid($group) ? SCST_C_GRP_ADD_LUN_FAIL :
	    SCST_C_TGT_ADD_LUN_FAIL;

	return $err if (!valid($driver, $target, $device, $lun, $attributes));

	my $o_string = "";
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value;";
	}

	$o_string =~ s/\s$//;

	my ($path, $cmd);
	if (valid($group)) {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_LUNS, SCST_MGMT_IO);
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_LUNS, SCST_MGMT_IO);
	}

	$cmd .= "add $device $lun $o_string";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	if (valid($group)) {
		my $rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);
	}

	my $rc = $self->lunExists($driver, $target, $lun, $group);
	return (valid($group) ? SCST_C_GRP_LUN_EXISTS :
		SCST_C_TGT_LUN_EXISTS) if ($rc == TRUE);
	return $rc if ($rc > 1);

	$rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->deviceOpen($device);
	return SCST_C_DEV_NO_DEVICE if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->checkLunCreateAttributes($driver, $target, $attributes, $group);
	return SCST_C_LUN_BAD_ATTRIBUTES if ($rc == TRUE);
	return $rc if ($rc > 1);

	return $err;
}

sub removeLun {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $group = shift;

	my $err = valid($group) ? SCST_C_GRP_REM_LUN_FAIL :
	    SCST_C_TGT_ADD_LUN_FAIL;

	return $err if (!valid($driver, $target, $lun));

	my ($path, $cmd);
	if (valid($group)) {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_LUNS,
				  SCST_MGMT_IO);
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_LUNS, SCST_MGMT_IO);
	}
	$cmd .= "del $lun";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	if (valid($group)) {
		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);
	}

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return (valid($group) ? SCST_C_GRP_NO_LUN :
		SCST_C_TGT_NO_LUN) if (!$rc);
	return $rc if ($rc > 1);

	return $err;
}

sub replaceLun {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $device = shift;
	my $attributes = shift;
	my $group = shift;

	my $err;

	return TRUE if (!valid($lun));

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	if (valid($group)) {
		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);

		$err = SCST_C_GRP_NO_LUN;
	} else {
		$err = SCST_C_TGT_NO_LUN;
	}

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return $err if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->deviceOpen($device);
	return SCST_C_DEV_NO_DEVICE if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->checkLunCreateAttributes($driver, $target, $attributes, $group);
	return SCST_C_LUN_BAD_ATTRIBUTES if ($rc == TRUE);
	return $rc if ($rc > 1);

	my ($luns, $errorString) = $self->luns($driver, $target, $group);

	return SCST_C_LUN_DEV_EXISTS if ($$luns{$lun} eq $device);

	my $o_string = "";
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value;";
	}

	$o_string =~ s/\s$//;

	my ($path, $cmd);
	if (defined($group)) {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_LUNS,
				  SCST_MGMT_IO);
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_LUNS, SCST_MGMT_IO);
	}
	$cmd .= "replace $device $lun $o_string";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	return SCST_C_LUN_RPL_DEV_FAIL;
}

sub clearLuns {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	my $err = valid($group) ? SCST_C_GRP_CLR_LUN_FAIL :
	    SCST_C_TGT_CLR_LUN_FAIL;

	return $err if (!valid($driver, $target));

	my ($path, $cmd);
	if (valid($group)) {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_LUNS,
				  SCST_MGMT_IO);
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_LUNS, SCST_MGMT_IO);
	}
	$cmd .= "clear";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	if (valid($group)) {
		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);
	}

	return $err;
}

sub deviceHandler {
	my $self = shift;
	my $device = shift;

	return undef if (!valid($device));

	my $handler = readlink(make_path(SCST_DEVICES_DIR(), $device,
					 'handler'));
	$handler =~ s/.*\///;
	return $handler;
}

sub devices {
	my $self = shift;
	my $handler = shift;
	my @devices;

	my $dHandle = new IO::Handle;
	my $_path = !valid($handler) ? SCST_DEVICES_DIR() :
	    make_path(SCST_HANDLERS_DIR(), $handler);
	if (!(opendir $dHandle, $_path)) {
		return (undef, "devices(): Unable to read directory '$_path': $!");
	}

	foreach my $device (readdir($dHandle)) {
		next if ($device eq '.' || $device eq '..');

		my $isdev = (-d make_path(SCST_DEVICES_DIR(), $device));
		if ($isdev && (!valid($handler) ||
			       $handler eq $self->deviceHandler($device))) {
			push @devices, $device;
		}
	}

	close $dHandle;

	return (\@devices, undef);
}

sub deviceOpen {
	my $self = shift;
	my $device = shift;

	return FALSE if (!valid($device));

	my ($devices, $errorString) = $self->devices();

	return SCST_C_FATAL_ERROR if (!valid($devices));

	foreach my $_device (@{$devices}) {
		return TRUE if ($device eq $_device);
	}

	return FALSE;
}

sub deviceAttributes {
	my $self = shift;
	my $device = shift;
	my %attributes = ( );
	my $errorString;
	my $dca;

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEVICES_DIR(), $device);
	if (!(opendir $pHandle, $_path)) {
		if ($self->deviceOpen($device) != TRUE) {
			$errorString = "deviceAttributes(): Device '$device' is not open";
		} else {
			$errorString = "deviceAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	($dca, $errorString) = $self->deviceCreateAttributes($self->deviceHandler($device));

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO || $attribute eq 'uevent');
		my $pPath = make_path(SCST_DEVICES_DIR(), $device, $attribute);
		my $mode = (stat($pPath))[2];

		if ($attribute eq 'exported') {
			my $eHandle = new IO::Handle;
			opendir $eHandle, make_path(SCST_DEVICES_DIR(),
						    $device, $attribute);

			foreach my $export (readdir($eHandle)) {
				next if (($export eq '.') || ($export eq '..'));

				my $linked = readlink make_path($pPath, $export);

				my $t = SCST_TARGETS;
				my $g = SCST_GROUPS;
				my $l = SCST_LUNS;
				my ($driver, $target, $group, $lun) = "" x 4;

				if ($linked =~ /^(\.\.\/)*$t\/([^\/]+)\/([^\/]+)\/$g\/([^\/]+)\/$l\/(\d+)$/) {
					$driver = $2;
					$target = $3;
					$group = $4;
					$lun = $5;
				} elsif ($linked =~ /^(\.\.\/)*$t\/([^\/]+)\/([^\/]+)\/$l\/(\d+)$/) {
					$driver = $2;
					$target = $3;
					$group = "";
					$lun = $4;
				} else {
					print("internal error: could not parse $linked\n");
					next;
				}
				next if ($driver eq 'copy_manager');
				$attributes{$attribute}->{'value'}->{$driver}->{$target}->{$group} = $lun;
			}
			if ($attributes{$attribute}->{'value'}) {
				$attributes{$attribute}->{'static'} = TRUE;
			}
			close $eHandle;
		} elsif ($attribute eq 'handler') {
			my $linked = readlink $pPath;

			$linked =~ s/.*\///;
			$attributes{$attribute}->{'static'} = TRUE;
			$attributes{$attribute}->{'value'} = $linked;
		} elsif ($attribute eq 'scsi_device') {
			my $linked = readlink $pPath;

			$linked =~ s/.*\///;
			$attributes{$attribute}->{'static'} = TRUE;
			$attributes{$attribute}->{'value'} = $linked;
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if ($attribute eq 'cpu_mask' ||
				    $attribute eq 'filename' ||
				    $attribute eq 'threads_num' ||
				    $attribute eq 'threads_pool_type' ||
				    ($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "deviceAttributes(): Unable to read ".
					  "device attribute '$attribute': $!");
				}

				my ($value, $is_key) = split("\n", _sysread($io) , 2);
				close $io;
				$value = "" if (!defined($value));
				chomp $value;

				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				if ($attribute eq 'type') {
					my($type, $type_string) = split(/\s\-\s/, $value, 2);
					$attributes{$attribute}->{'value'} = $type;
					$attributes{'type_string'}->{'value'} = $type_string;
					$attributes{'type_string'}->{'static'} = TRUE;
				} else {
					if ($is_key) {
						$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
					} else {
						$attributes{$attribute}->{'value'} = $value;
					}
				}

				$attributes{$attribute}->{'static'} = $is_static;
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub driverAttributes {
	my $self = shift;
	my $driver = shift;
	my %attributes = ( );
	my $errorString;

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver);
	if (!(opendir $pHandle, $_path)) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "driverAttributes(): Driver '$driver' is not available";
		} else {
			$errorString = "driverAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path(SCST_TARGETS_DIR(), $driver, $attribute);
		my $mode = (stat($pPath))[2];

		if (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if (($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "driverAttributes(): Unable to read ".
					  "driver attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				if ($attribute eq SCST_TRACE_IO) {
					$attributes{$attribute}->{'value'} = $value;
					my @possible;
					$value = '';
					my $start = FALSE;
					while (my $line = <$io>) {
						$start = TRUE if ($line !~ /\[/);
						$value .= $line if ($start);
					}
					$value =~ s/\n//g;

					if ($value =~ /\[(.*)\]/) {
						$value = $1;

						foreach my $t (split(/\,/, $value)) {
							$t =~ s/^\s+//; $t =~ s/\s+$//;
							push @possible, $t;
						}
					}
					$attributes{$attribute}->{'set'} = \@possible;
				} else {
					if ($is_key) {
						$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
					} else {
						$attributes{$attribute}->{'value'} = $value;
					}
				}
				close $io;

				$attributes{$attribute}->{'static'} = $is_static;
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub setDriverAttribute {
	my $self = shift;
	my $driver = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($attribute) || !defined($value));

	my $path = make_path(SCST_TARGETS_DIR(), $driver, $attribute);

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_DRV_BAD_ATTRIBUTES,
			     SCST_C_DRV_ATTRIBUTE_STATIC,
			     SCST_C_DRV_SETATTR_FAIL);
}

sub targetAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my %attributes = ( );
	my $errorString;

	return (undef, "Too few arguments") if (!valid($driver, $target));

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target);
	if (!(opendir $pHandle, $_path)) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "targetAttributes(): Driver '$driver' is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "targetAttributes(): Target '$target' is not available";
		} else {
			$errorString = "targetAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO || $attribute eq 'uevent');
		my $pPath = make_path(SCST_TARGETS_DIR(), $driver, $target,
				      $attribute);
		my $mode = (stat($pPath))[2];

		if ($attribute eq 'host') {
			my $linked = readlink($pPath);

			$linked =~ s/.*\///;
			$attributes{$attribute}->{'static'} = TRUE;
			$attributes{$attribute}->{'value'} = $linked;
		} elsif ($driver eq 'scst_local' && $attribute eq 'sessions') {
			my $_session_path = make_path($_path, $attribute);
			my $pSessHandle = new IO::Handle;
			if (!(opendir $pSessHandle, $_session_path)) {
				return (undef, "targetAttributes(): Unable to read directory '$_session_path': $!");
			}
			my $key = 0;
			foreach my $e (readdir($pSessHandle)) {
				next if ($e eq '.' || $e eq '..');
				$attributes{'session_name'}->{'keys'}->{$key}->{'value'} = $e;
				$key++;
			}
		} elsif (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if ($attribute eq 'enabled' ||
				    $attribute eq 'cpu_mask' ||
				    ($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "targetAttributes(): Unable to read ".
					  "target attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				close $io;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				$attributes{$attribute}->{'static'} = $is_static;

				if ($is_key) {
					$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
				} else {
					$attributes{$attribute}->{'value'} = $value;
				}
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub setTargetAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($driver, $target, $attribute) ||
			!defined($value));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, $attribute);
	$cmd = $value;

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $cmd > $path\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_TGT_BAD_ATTRIBUTES,
			     SCST_C_TGT_ATTRIBUTE_STATIC,
			     SCST_C_TGT_SETATTR_FAIL);
}

sub groupAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my %attributes = ( );
	my $errorString;

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			      $group);
	if (!(opendir $pHandle, $_path)) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "groupAttributes(): Driver '$driver' is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "groupAttributes(): Target '$target' is not available";
		} elsif ($self->groupExists($driver, $target, $group) != TRUE) {
			$errorString = "groupAttributes(): Group '$group' does not exist";
		} else {
			$errorString = "groupAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path(SCST_TARGETS_DIR(), $driver, $target,
				      SCST_GROUPS, $group, $attribute);
		my $mode = (stat($pPath))[2];

		if (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if ($attribute eq 'cpu_mask' ||
				    ($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "groupAttributes(): Unable to read ".
					  "group attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				close $io;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				$attributes{$attribute}->{'static'} = $is_static;

				if ($is_key) {
					$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
				} else {
					$attributes{$attribute}->{'value'} = $value;
				}
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub setGroupAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($attribute) || !defined($value));

	my ($path, $cmd);
	$path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			  $group, $attribute);
	$cmd .= $value;

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $cmd > $path\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_GRP_BAD_ATTRIBUTES,
			     SCST_C_GRP_ATTRIBUTE_STATIC,
			     SCST_C_GRP_SETATTR_FAIL);
}

sub lunAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $group = shift;
	my $errorString;
	my %attributes = ( );

	my ($_path, $luncrattr);

	if (valid($group)) {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_GROUPS, $group, SCST_LUNS, $lun);
		($luncrattr, $errorString) =
		    $self->lunCreateAttributes($driver, $target, $group);
	} else {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_LUNS, $lun);
		($luncrattr, $errorString) = $self->lunCreateAttributes($driver, $target);
	}

	my $pHandle = new IO::Handle;
	if (!(opendir $pHandle, $_path)) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "lunAttributes(): Driver '$driver' is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "lunAttributes(): Target '$target' is not available";
		} elsif (valid($group) &&
			 $self->groupExists($driver, $target, $group) != TRUE) {
			$errorString = "lunAttributes(): Group '$group' does not exist";
		} elsif ($self->lunExists($driver, $target, $lun, $group) != TRUE) {
			$errorString = "lunAttributes(): LUN '$lun' does not exist";
		} else {
			$errorString = "lunAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path($_path, $attribute);
		my $mode = (stat($pPath))[2];

		if ($attribute eq 'device') {
			my $linked = readlink($pPath);

			$linked =~ s/.*\///;
			$attributes{$attribute}->{'static'} = TRUE;
			$attributes{$attribute}->{'value'} = $linked;
		} elsif (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if (($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "lunAttributes(): Unable to read ".
					  "lun attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				close $io;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				$attributes{$attribute}->{'static'} = $is_static;

				if ($is_key) {
					$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
				} else {
					$attributes{$attribute}->{'value'} = $value;
				}
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub setLunAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $attribute = shift;
	my $value = shift;
	my $group = shift;

	return SCST_C_LUN_SETATTR_FAIL
	    if (!valid($driver, $target, $lun, $attribute) || !defined($value));

	my $path;

	if (valid($group)) {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_LUNS, $lun,
				  $attribute);
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_LUNS, $lun, $attribute);
	}

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	if (valid($group)) {
		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);
	}

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return (valid($group) ? SCST_C_GRP_NO_LUN :
		SCST_C_TGT_NO_LUN) if (!$rc);
	return $rc if ($rc > 1);

	my ($attributes, $errorString) = $self->lunAttributes($driver, $target, $lun, $group);

	return SCST_C_LUN_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_LUN_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	return SCST_C_LUN_SETATTR_FAIL;
}

sub initiatorAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;
	my %attributes = ( );
	my $errorString;

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			      $group, SCST_INITIATORS, $initiator);
	if (!(opendir $pHandle, $_path)) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "initiatorAttributes(): Driver '$driver' is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "initiatorAttributes(): Target '$target' is not available";
		} elsif ($self->groupExists($driver, $target, $group) != TRUE) {
			$errorString = "initiatorAttributes(): Group '$group' does not exist";
		} elsif ($self->initiatorExists($driver, $target, $group, $initiator) != TRUE) {
			$errorString = "initiatorAttributes(): Initiator '$initiator' does not exist";
		} else {
			$errorString = "initiatorAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path(SCST_TARGETS_DIR(), $driver, $target,
				      SCST_GROUPS, $group, SCST_INITIATORS,
				      $initiator, $attribute);
		my $mode = (stat($pPath))[2];
		if (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if (($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "initiatorAttributes(): Unable to read ".
					  "initiator attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				close $io;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				$attributes{$attribute}->{'static'} = $is_static;

				if ($is_key) {
					$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
				} else {
					$attributes{$attribute}->{'value'} = $value;
				}
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub setInitiatorAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($attribute) || !defined($value));

	my $path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			     $group, SCST_LUNS, $initiator, $attribute);

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->initiatorExists($driver, $target, $group, $initiator);
	return SCST_C_GRP_NO_INI if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_INI_SETATTR_FAIL;
}

sub deviceGroupAttributes {
	my $self = shift;
	my $group = shift;
	my %attributes = ( );
	my $errorString;

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group);
	if (!(opendir $pHandle, $_path)) {
		if ($self->deviceGroupExists($group) != TRUE) {
			$errorString = "deviceGroupAttributes(): Device group '$group' does not exist";
		} else {
			$errorString = "deviceGroupAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path(SCST_DEV_GROUP_DIR(), $group, $attribute);
		my $mode = (stat($pPath))[2];
		if (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if (($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "deviceGroupAttributes(): Unable to read ".
					  "device group attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				close $io;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				$attributes{$attribute}->{'static'} = $is_static;

				if ($is_key) {
					$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
				} else {
					$attributes{$attribute}->{'value'} = $value;
				}
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub targetGroupAttributes {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my %attributes = ( );
	my $errorString;

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup);
	if (!(opendir $pHandle, $_path)) {
		if ($self->deviceGroupExists($group) != TRUE) {
			$errorString = "targetGroupAttributes(): Device group '$group' does not exist";
		} elsif ($self->targetGroupExists($group, $tgroup) != TRUE) {
			$errorString = "targetGroupAttributes(): Target Group '$tgroup' does not exist";
		} else {
			$errorString = "targetGroupAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup, $attribute);
		my $mode = (stat($pPath))[2];
		if (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if (($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "targetGroupAttributes(): Unable to read ".
					  "target group attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				close $io;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				$attributes{$attribute}->{'static'} = $is_static;

				if ($is_key) {
					$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
				} else {
					$attributes{$attribute}->{'value'} = $value;
				}
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub targetGroupTargetAttributes {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;
	my $local_tgt = shift;
	my %attributes = ( );
	my $errorString;

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup, $tgt);
	if (-l $_path && !$local_tgt) {
		return (\%attributes, undef);
	}

	if (!(opendir $pHandle, $_path)) {
		if ($self->deviceGroupExists($group) != TRUE) {
			$errorString = "targetGroupTargetAttributes(): Device group '$group' does not exist";
		} elsif ($self->targetGroupExists($group, $tgroup) != TRUE) {
			$errorString = "targetGroupTargetAttributes(): Target Group '$tgroup' does not exist";
		} elsif ($self->targetGroupTargetExists($group, $tgroup, $tgt) != TRUE) {
			$errorString = "targetGroupTargetAttributes(): Target '$tgt' does not exist";
		} else {
			$errorString = "targetGroupTargetAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($pHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO);
		my $pPath = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
				      $tgroup, $tgt, $attribute);
		my $mode = (stat($pPath))[2];
		if (-d $pPath) {
			# Skip directories
		} else {
			if (!(($mode & S_IRUSR) >> 6)) {
				$attributes{$attribute}->{'static'} = FALSE;
				$attributes{$attribute}->{'value'} = undef;
			} else {
				my $is_static;
				if (($mode & S_IWUSR) >> 6) {
					$is_static = FALSE;
				} else {
					$is_static = TRUE;
				}

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "targetGroupTargetAttributes(): Unable to read ".
					  "target group target attribute '$attribute': $!");
				}

				my $value = <$io>;
				$value = "" if (!defined($value));
				chomp $value;

				my $is_key = <$io>;
				close $io;
				$is_key = $is_key && $is_key =~ /\[key\]/;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /^([^\d]+)(\d+)$/) {
						$attribute = $1;
						$key = $2;
					}
				}

				next if ($attribute eq SCST_MGMT_IO);

				$attributes{$attribute}->{'static'} = $is_static;

				if ($is_key) {
					$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
				} else {
					$attributes{$attribute}->{'value'} = $value;
				}
			}
		}
	}

	close $pHandle;

	return (\%attributes, undef);
}

sub setAluaAttribute {
	my $self = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($attribute) || !defined($value));

	my $bytes = - ENOENT;
	my $path = make_path(SCST_DEV_GROUP_DIR(), $attribute);
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $value > $path\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	return setAttrFailed($path, $bytes, SCST_C_ALUA_BAD_ATTRIBUTES,
			     SCST_C_ALUA_ATTRIBUTE_STATIC,
			     SCST_C_ALUA_SETATTR_FAIL);
}

sub setDeviceGroupAttribute {
	my $self = shift;
	my $group = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($attribute) || !defined($value));

	my $bytes = - ENOENT;
	my $path = make_path(SCST_DEV_GROUP_DIR(), $group, $attribute);
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_DGRP_BAD_ATTRIBUTES,
			     SCST_C_DGRP_ATTRIBUTE_STATIC,
			     SCST_C_DGRP_SETATTR_FAIL);
}

sub setTargetGroupAttribute {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if !valid($group, $tgroup, $attribute) || !defined($value);

	my $bytes = - ENOENT;
	my $path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup, $attribute);
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_TGRP_BAD_ATTRIBUTES,
			     SCST_C_TGRP_ATTRIBUTE_STATIC,
			     SCST_C_TGRP_SETATTR_FAIL);
}

sub setTargetGroupTargetAttribute {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($group, $tgroup, $tgt, $attribute) ||
			!defined($value));

	my $bytes = - ENOENT;
	my $path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
			     $tgroup, $tgt, $attribute);
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupTargetExists($group, $tgroup, $tgt);
	return SCST_C_TGRP_NO_TGT if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_TGRP_TGT_BAD_ATTR,
			     SCST_C_TGRP_TGT_ATTR_STATIC,
			     SCST_C_TGRP_TGT_SETATTR_FAIL);
}

sub handlers {
	my $self = shift;
	my @handlers;

	my $hHandle = new IO::Handle;
	my $_path = SCST_HANDLERS_DIR();
	if (!(opendir $hHandle, $_path)) {
		return (undef, "handlers(): Unable to read directory '$_path': $!");
	}

	foreach my $handler (readdir($hHandle)) {
		next if (($handler eq '.') || ($handler eq '..'));

		if (-d make_path(SCST_HANDLERS_DIR(), $handler)) {
			push @handlers, $handler;
		}
	}

	close $hHandle;

	@handlers = sort(@handlers);

	return (\@handlers, undef);
}

sub handlerExists {
	my $self = shift;
	my $handler = shift;

	return FALSE if (!valid($handler));

	my ($handlers, $errorString) = $self->handlers();

	return SCST_C_FATAL_ERROR if (!defined($handlers));

	foreach my $_handler (@{$handlers}) {
		return TRUE if ($handler eq $_handler);
	}

	return FALSE;
}

sub setHandlerAttribute {
	my $self = shift;
	my $handler = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!valid($attribute) || !defined($value));

	my $bytes = - ENOENT;
	my $path = make_path(SCST_HANDLERS_DIR(), $handler, $attribute);
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $path -> $attribute = $value\n";
		} else {
			$value .= "\n";
			$bytes = _syswrite($io, $value, length($value));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->handlerExists($handler);
	return SCST_C_HND_NO_HANDLER if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_HND_BAD_ATTRIBUTES,
			     SCST_C_HND_ATTRIBUTE_STATIC,
			     SCST_C_HND_SETATTR_FAIL);
}

sub handlerAttributes {
	my $self = shift;
	my $handler = shift;
	my %attributes = ( );
	my $errorString;
	my $a;

	($a, $errorString) = devices($self, $handler);
	$attributes{'devices'}->{'value'} = $a;

	my $hHandle = new IO::Handle;
	my $_path = make_path(SCST_HANDLERS_DIR(), $handler);
	if (!(opendir $hHandle, $_path)) {
		if ($self->handlerExists($handler) != TRUE) {
			$errorString = "handlerAttributes(): Handler '$handler' is not available";
		} else {
			$errorString = "handlerAttributes(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $attribute (readdir($hHandle)) {
		next if ($attribute eq '.' || $attribute eq '..' ||
			 $attribute eq SCST_MGMT_IO || $attribute eq 'uevent' ||
			 $attribute eq 'module');
		my $pPath = make_path(SCST_HANDLERS_DIR(), $handler, $attribute);
		my $mode = (stat($pPath))[2];

		my $is_static;
		if (($mode & S_IWUSR) >> 6) {
			$is_static = FALSE;
		} else {
			$is_static = TRUE;
		}

		my $path = make_path(SCST_HANDLERS_DIR(), $handler, $attribute);

		my $io = new IO::File $path, O_RDONLY;

		if (!$io) {
			return (undef, "handlerAttributes(): Unable to read handler attribute ".
			  "'$attribute': $!");
		}

		my $value = <$io>;
		$value = "" if (!defined($value));
		chomp $value;

		my $is_key = <$io>;
		$is_key = $is_key && $is_key =~ /\[key\]/;

		my $key = 0;
		if ($is_key) {
			if ($attribute =~ /^([^\d]+)(\d+)$/) {
				$attribute = $1;
				$key = $2;
			}
		}

		if ($attribute eq SCST_MGMT_IO) {
			$attributes{$attribute}->{'static'} = TRUE;
			$attributes{$attribute}->{'value'} = $value;
			next;
		}

		if (!(($mode & S_IRUSR) >> 6)) {
			$attributes{$attribute}->{'static'} = FALSE;
			$attributes{$attribute}->{'value'} = undef;
		} elsif ($attribute eq SCST_TRACE_IO) {
			$attributes{$attribute}->{'value'} = $value;
			my @possible;
			$value = '';
			my $start = FALSE;
			while (my $line = <$io>) {
				$start = TRUE if ($line !~ /\[/);
				$value .= $line if ($start);
			}
			$value =~ s/\n//g;

			if ($value =~ /\[(.*)\]/) {
				$value = $1;

				foreach my $t (split(/\,/, $value)) {
					$t =~ s/^\s+//; $t =~ s/\s+$//;
					push @possible, $t;
				}
			}
			$attributes{$attribute}->{'set'} = \@possible;
		} elsif ($attribute eq 'type') {
			my($type, $type_string) = split(/\s\-\s/, $value, 2);
			$attributes{$attribute}->{'value'} = $type;
			$attributes{'type_string'}->{'value'} = $type_string;
			$attributes{'type_string'}->{'static'} = TRUE;
		} else {
			if ($is_key) {
				$attributes{$attribute}->{'keys'}->{$key}->{'value'} = $value;
			} else {
				$attributes{$attribute}->{'value'} = $value;
			}
		}

		$attributes{$attribute}->{'static'} = $is_static;

		close $io;
	}

	close $hHandle;

	$attributes{'devices'}->{'static'} = TRUE;

	return (\%attributes, undef);
}

sub deviceExists {
	my $self = shift;
	my $device = shift;

	my ($handlers, $errorString) = $self->handlers();

	return SCST_C_FATAL_ERROR if (!defined($handlers));

	foreach my $handler (@{$handlers}) {
		return TRUE if $self->handlerDeviceExists($handler, $device);
	}

	return FALSE;
}

sub handlerDeviceExists {
	my $self = shift;
	my $handler = shift;
	my $device = shift;

	my ($devices, $errorString) = $self->devicesByHandler($handler);

	if (!defined($devices)) {
		my $rc = $self->handlerExists($handler);
		return FALSE if (!$rc);
		return $rc if ($rc > 1);

		return SCST_C_FATAL_ERROR;
	}

	foreach my $_device (@{$devices}) {
		return TRUE if ($_device eq $device);
	}

	return FALSE;
}

sub devicesByHandler {
	my $self = shift;
	my $handler = shift;
	my $errorString;
	my $attributes;

	($attributes, $errorString) = $self->handlerAttributes($handler);
	if (!defined($attributes)) {
		if ($self->handlerExists($handler) != TRUE) {
			$errorString = "devicesByHandler(): Handler '$handler' is not available";
		} else {
			$errorString = "devicesByHandler() failed";
		}
		return (undef, $errorString);
	}

	return (\@{$$attributes{'devices'}->{'value'}}, undef);
}

sub checkDeviceCreateAttributes {
	my $self = shift;
	my $handler = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my ($available, $errorString) = $self->deviceCreateAttributes($handler);

	if (!defined($available)) {
		my $rc = $self->handlerExists($handler);
		return SCST_C_HND_NO_HANDLER if (!$rc);
		return $rc if ($rc > 1);
		return SCST_C_FATAL_ERROR;
	}

	if (ref($check) eq 'HASH') {
		foreach my $attribute (keys %{$check}) {
			if (!defined($$available{$attribute})) {
				return TRUE;
			}
		}
	} else {
		if (!defined($$available{$check})) {
			return TRUE;
		}
	}

	return FALSE;
}

sub deviceCreateAttributes {
	my $self = shift;
	my $handler = shift;
	my $available;
	my %attributes = ( );
	my $errorString;

	return (undef, "missing handler argument") if (!valid($handler));

	my $io = new IO::File make_path(SCST_HANDLERS_DIR(), $handler,
					SCST_MGMT_IO), O_RDONLY;

	if (!$io) {
		if ($self->handlerExists($handler) != TRUE) {
			$errorString = "deviceCreateAttributes(): Handler '$handler' ".
			    "is not available";
		} else {
			$errorString = "deviceCreateAttributes(): Unable to open mgmt ".
			    "interface for handler '$handler': $!";
		}
		return (undef, $errorString);
	}

	while (my $in = <$io>) {
		if ($in =~ /^The following parameters available\:/) {
			(undef, $available) = split(/\:/, $in, 2);
			$available =~ s/\.$//;
		}
	}
	close $io;

	if ($available) {
		foreach my $attribute (split(/\,/, $available)) {
			$attribute =~ s/^\s+//;
			$attribute =~ s/\s+$//;
			$attributes{$attribute} = '';
		}
	}

	return (\%attributes, undef);
}

sub openDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $attributes = shift;

	return SCST_C_DEV_OPEN_FAIL
	    if (!valid($handler, $device, $attributes));

	my $o_string = "";
	## Special case cluster_mode as we want to set it after t10_dev_id
	my $cm_string = "";
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		if ($attribute eq "cluster_mode") {
			$cm_string = "$attribute=$value;";
		} else {
			$o_string .= "$attribute=$value;";
		}
	}
	$o_string .= $cm_string;

	$o_string =~ s/\s$//;

	my ($path, $cmd);
	$path = make_path(SCST_HANDLERS_DIR(), $handler, SCST_MGMT_IO);
	$cmd .= "add_device $device $o_string";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $errno = $!;

	my $rc = $self->handlerExists($handler);
	return SCST_C_HND_NO_HANDLER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->checkDeviceCreateAttributes($handler, $attributes);
	return SCST_C_DEV_BAD_ATTRIBUTES if ($rc == TRUE);
	return $rc if ($rc > 1);

	$rc = $self->handlerDeviceExists($handler, $device);
	return SCST_C_DEV_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	return SCST_C_DEV_OPEN_FAIL if ($errno == EINVAL);

	return SCST_C_FATAL_ERROR;
}

sub closeDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;

	return SCST_C_DEV_CLOSE_FAIL if (!valid($handler, $device));

	my ($path, $cmd);
	$path = make_path(SCST_HANDLERS_DIR(), $handler, SCST_MGMT_IO);
	$cmd .= "del_device $device";

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $errno = $!;

	my $rc = $self->handlerExists($handler);
	return SCST_C_HND_NO_HANDLER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->handlerDeviceExists($handler, $device);
	return SCST_C_DEV_NO_DEVICE if ($rc != TRUE);
	return $rc if ($rc > 1);

	return SCST_C_FATAL_ERROR;
}

sub setDeviceAttribute {
	my $self = shift;
	my $device = shift;
	my $attribute = shift;
	my $value = shift;

	my ($path, $cmd);
	$path = make_path(SCST_DEVICES_DIR(), $device, $attribute);
	$cmd .= $value;

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		if ($self->{'debug'}) {
			print "DBG($$): $cmd > $path\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}

	my $rc = $self->deviceOpen($device);
	return SCST_C_DEV_NO_DEVICE if (!$rc);
	return $rc if ($rc > 1);

	return setAttrFailed($path, $bytes, SCST_C_DEV_BAD_ATTRIBUTES,
			     SCST_C_DEV_ATTRIBUTE_STATIC,
			     SCST_C_DEV_SETATTR_FAIL);
}

sub checkTargetCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my ($available, $errorString) = $self->targetCreateAttributes($driver);

	if (!defined($available)) {
		my $rc = $self->driverExists($driver);
		return SCST_C_DRV_NO_DRIVER if (!$rc);
		return $rc if ($rc > 1);
		return SCST_C_FATAL_ERROR;
	}

	if (ref($check) eq 'HASH') {
		foreach my $attribute (keys %{$check}) {
			if (!defined($$available{$attribute})) {
				return TRUE;
			}
		}
	} else {
		if (!defined($$available{$check})) {
			return TRUE;
		}
	}

	return FALSE;
}

sub targetCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $available;
	my %attributes = ( );
	my $errorString;

	my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
					SCST_MGMT_IO), O_RDONLY;

	if (!$io) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "targetCreateAttributes(): Driver '$driver' ".
			    "is not available";
		} else {
			$errorString = "targetCreateAttributes(): Unable to open driver mgmt ".
			    "interface for driver '$driver': $!";
		}
		return (undef, $errorString);
	}

	while (my $in = <$io>) {
		if ($in =~ /^The following parameters available\:/) {
			(undef, $available) = split(/\:/, $in, 2);
			$available =~ s/\.$//;
		}
	}
	close $io;

	if ($available) {
		foreach my $attribute (split(/\,/, $available)) {
			$attribute =~ s/^\s+//;
			$attribute =~ s/\s+$//;
			$attributes{$attribute} = '';
		}
	}

	return (\%attributes, undef);
}

sub enableTarget {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $enable = shift;

	$enable = TRUE if ($enable);

	return $self->setTargetAttribute($driver, $target, 'enabled', $enable);
}

sub resyncDevice {
	my $self = shift;
	my $device = shift;

	return $self->setDeviceAttribute($device, 'resync_size', 1);
}

sub setT10DeviceId {
	my $self = shift;
	my $device = shift;
	my $t10_id = shift;

	return $self->setDeviceAttribute($device, 't10_dev_id', $t10_id);
}

sub deviceGroupExists {
	my $self = shift;
	my $group = shift;

	my ($groups, $errorString) = $self->deviceGroups();

	return SCST_C_FATAL_ERROR if (!defined($groups));

	foreach my $_group (@{$groups}) {
		return TRUE if ($group eq $_group);
	}

	return FALSE;
}

sub deviceGroupDeviceExists {
	my $self = shift;
	my $group = shift;
	my $device = shift;

	my ($devices, $errorString) = $self->deviceGroupDevices($group);

	if (!defined($devices)) {
		return SCST_C_FATAL_ERROR;
	}

	foreach my $_device (@{$devices}) {
		return TRUE if ($device eq $_device);
	}

	return FALSE;
}

sub targetGroupExists {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;

	my ($tgroups, $errorString) = $self->targetGroups($group);

	if (!defined($tgroups)) {
		return SCST_C_FATAL_ERROR;
	}

	foreach my $_tgroup (@{$tgroups}) {
		return TRUE if ($tgroup eq $_tgroup);
	}

	return FALSE;
}

sub targetGroupTargetExists {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;

	my ($targets, $errorString) = $self->targetGroupTargets($group, $tgroup);

	if (!defined($targets)) {
		return SCST_C_FATAL_ERROR;
	}

	foreach my $_tgt (@{$targets}) {
		return TRUE if ($tgt eq $_tgt);
	}

	return FALSE;
}

sub checkLunCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $check = shift;
	my $group = shift;

	return FALSE if (!defined($check));

	my ($available, $errorString) = $self->lunCreateAttributes($driver, $target, $group);

	if (!defined($available)) {
		my $rc = $self->driverExists($driver);
		return SCST_C_DRV_NO_DRIVER if (!$rc);
		return $rc if ($rc > 1);

		$rc = $self->targetExists($driver, $target);
		return SCST_C_TGT_NO_TARGET if (!$rc);
		return $rc if ($rc > 1);

		if ($group) {
			$rc = $self->groupExists($driver, $target, $group);
			return SCST_C_GRP_NO_GROUP if (!$rc);
			return $rc if ($rc > 1);
		}

		return SCST_C_FATAL_ERROR;
	}

	if (ref($check) eq 'HASH') {
		foreach my $attribute (keys %{$check}) {
			if (!defined($$available{$attribute})) {
				return TRUE;
			}
		}
	} else {
		if (!defined($$available{$check})) {
			return TRUE;
		}
	}

	return FALSE;
}

sub lunCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $available;
	my %attributes = ( );
	my $errorString;

	my $_path;

	if (valid($group)) {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_GROUPS, $group, SCST_LUNS,
				   SCST_MGMT_IO);
	} else {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_LUNS, SCST_MGMT_IO);
	}

	my $io = new IO::File $_path, O_RDONLY;

	if (!$io) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "lunCreateAttributes(): Driver '$driver' ".
			    "is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "lunCreateAttributes(): Target '$target' ".
			    "is not available";
		} elsif (valid($group) &&
			 $self->groupExists($driver, $target, $group) != TRUE) {
			$errorString = "lunCreateAttributes(): Group '$group' ".
			    "does not exist";
		} else {
			$errorString = "lunCreateAttributes(): Unable to open luns mgmt ".
			    "interface for group '$group': $!";
		}
		return (undef, $errorString);
	}

	while (my $in = <$io>) {
		if ($in =~ /^The following parameters available\:/) {
			(undef, $available) = split(/\:/, $in, 2);
			$available =~ s/\.$//;
		}
	}
	close $io;

	if ($available) {
		foreach my $attribute (split(/\,/, $available)) {
			$attribute =~ s/^\s+//;
			$attribute =~ s/\s+$//;
			$attributes{$attribute} = '';
		}
	}
	return (\%attributes, undef);
}

sub checkInitiatorCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my ($available, $errorString) = $self->initiatorCreateAttributes($driver, $target, $group);

	if (!defined($available)) {
		my $rc = $self->driverExists($driver);
		return SCST_C_DRV_NO_DRIVER if (!$rc);
		return $rc if ($rc > 1);

		$rc = $self->targetExists($driver, $target);
		return SCST_C_TGT_NO_TARGET if (!$rc);
		return $rc if ($rc > 1);

		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);

		return SCST_C_FATAL_ERROR;
	}

	if (ref($check) eq 'HASH') {
		foreach my $attribute (keys %{$check}) {
			if (!defined($$available{$attribute})) {
				return TRUE;
			}
		}
	} else {
		if (!defined($$available{$check})) {
			return TRUE;
		}
	}

	return FALSE;
}

sub initiatorCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $available;
	my %attributes = ( );
	my $errorString;

	my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
					$target, SCST_GROUPS, $group,
					SCST_INITIATORS, SCST_MGMT_IO),
	    O_RDONLY;

	if (!$io) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "initiatorCreateAttributes(): Driver '$driver' ".
			    "is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "initiatorCreateAttributes(): Target '$target' ".
			    "is not available";
		} elsif ($self->groupExists($driver, $target, $group) != TRUE) {
			$errorString = "initiatorCreateAttributes(): Group '$group' ".
			    "does not exist";
		} else {
			$errorString = "initiatorCreateAttributes(): Unable to open initiators mgmt ".
			    "interface for group '$group': $!";
		}
		return (undef, $errorString);
	}

	while (my $in = <$io>) {
		if ($in =~ /^The following parameters available\:/) {
			(undef, $available) = split(/\:/, $in, 2);
			$available =~ s/\.$//;
		}
	}
	close $io;

	if ($available) {
		foreach my $attribute (split(/\,/, $available)) {
			$attribute =~ s/^\s+//;
			$attribute =~ s/\s+$//;
			$attributes{$attribute} = '';
		}
	}

	return (\%attributes, undef);
}

sub sessions {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my %_sessions;
	my $errorString;

	return (undef, "Too few arguments") if (!valid($driver, $target));

	my $sHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
			      SCST_SESSIONS);
	if (!(opendir $sHandle, $_path)) {
		if ($self->driverExists($driver) != TRUE) {
			$errorString = "sessions(): Driver '$driver' ".
			    "is not available";
		} elsif ($self->targetExists($driver, $target) != TRUE) {
			$errorString = "sessions(): Target '$target' ".
			    "is not available";
		} else {
			$errorString = "sessions(): Unable to read directory '$_path': $!";
		}
		return (undef, $errorString);
	}

	foreach my $session (readdir($sHandle)) {
		next if (($session eq '.') || ($session eq '..'));
		my $pHandle = new IO::Handle;
		my $sPath = make_path($_path, $session);
		if (!(opendir $pHandle, $sPath)) {
			return (undef, "sessions(): Unable to read directory '$_path': $!");
		}

		foreach my $attribute (readdir($pHandle)) {
			next if ($attribute eq '.' || $attribute eq '..' ||
				 $attribute eq SCST_MGMT_IO);
			my $pPath = make_path($sPath, $attribute);

			if ($attribute eq 'luns') {
				my $linked = readlink $pPath;
				my $g = SCST_GROUPS;
				my $l = SCST_LUNS;
				if (defined($linked) &&
				    $linked =~ /\.\.\/\.\.\/$g\/(.*)\/$l/) {
					my $group = $1;
					$_sessions{$session}->{$attribute} =
					  $self->luns($driver, $target, $group);
				}
			} else {
				my $mode = (stat($pPath))[2];
				if (!$mode) {
					$mode = 0;
				}
				if (-d $pPath) {
					# Skip directories
				} else {
					if (!(($mode & S_IRUSR) >> 6)) {
						$_sessions{$session}->{$attribute}->{'static'} = FALSE;
						$_sessions{$session}->{$attribute}->{'value'} = undef;
					} else {
						my $is_static;
						if (($mode & S_IWUSR) >> 6) {
							$is_static = FALSE;
						} else {
							$is_static = TRUE;
						}

						my $io = new IO::File $pPath, O_RDONLY;

						if (!$io) {
							return (undef,
								"sessions(): Unable to read ".
								"session attribute '$attribute': $!");
						}

						my $value = <$io>;
						$value = "" if (!defined($value));
						chomp $value;
						close $io;

						$_sessions{$session}->{$attribute}->{'value'} = $value;
						$_sessions{$session}->{$attribute}->{'static'} = $is_static;
					}
				}
			}
		}
		close $pHandle;
	}
	close $sHandle;

	return (\%_sessions, undef);
}

sub closeSession {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $session = shift;

	my ($sessions, $errorString) = $self->sessions($driver, $target);

	return SCST_C_NO_SESSION if (!defined($$sessions{$session}));

	# If it's not closable, silently return
	return FALSE if (!defined($$sessions{$session}->{'force_close'}));

	my $path = make_path(SCST_TARGETS_DIR(), $driver, $target,
			     SCST_SESSIONS, $session, 'force_close');

	my $bytes = - ENOENT;
	my $io = new IO::File $path, O_WRONLY;
	if ($io) {
		my $cmd = "1";
		if ($self->{'debug'}) {
			print "DBG($$): $cmd\n";
		} else {
			$bytes = _syswrite($io, $cmd, length($cmd));
		}
		close $io;
		return FALSE if ($self->{'debug'} || $bytes > 0);
	}
	return SCST_C_SESSION_CLOSE_FAIL;
}

sub sgvStats {
	my $self = shift;
	my %stats;

	my $sHandle = new IO::Handle;
	my $_path = SCST_SGV_DIR();
	if (!(opendir $sHandle, $_path)) {
		return (undef, "svgStats(): Unable to read directory '$_path': $!");
	}

	foreach my $stat (readdir($sHandle)) {
		next if (($stat eq '.') || ($stat eq '..'));

		my $sPath = make_path(SCST_SGV_DIR(), $stat);

		if (-d $sPath) {
			my $lHandle = new IO::Handle;
			if (!(opendir $lHandle, $sPath)) {
				return (undef, "svgStats(): Unable to read directory '$sPath': $!");
			}

			foreach my $lief (readdir($lHandle)) {
				my $pPath = make_path($sPath, $lief);

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					return (undef, "sgvStats(): Unable to read ".
					  "sgv stat '$stat/$lief': $!");
				}

				my $buffer;
				while (my $value = <$io>) {
					$buffer .= $value;
				}
				close $io;

				$stats{$stat}->{$lief} = $buffer;
			}
			close $lHandle;
		} else {
			my $io = new IO::File $sPath, O_RDONLY;

			if (!$io) {
				return (undef, "sgvStats(): Unable to read ".
					"sgv stat '$stat': $!");
			}

			my $buffer;
			while (my $value = <$io>) {
				$buffer .= $value;
			}
			close $io;

			$stats{$stat} = $buffer;
		}
	}
	close $sHandle;

	return (\%stats, undef);
}

sub errorString {
	my $self = shift;
	my $rc = shift;

	return defined($rc) ? $VERBOSE_ERROR{$rc} : undef;
}

# Read from the SCST sysfs file $1. Return either the data read or undef if
# reading failed.
sub _sysread {
	my $io = shift;
	my $deadline = time() + $TIMEOUT;
	my $result;

	while (time() < $deadline) {
		my $bytes = sysread($io, $result, 4096);
		last if (defined($bytes) || $! != EAGAIN);
		sleep 1;
	}

	return $result;
}

# Write the first $3 bytes of $2 into the SCST sysfs file $1. Return either
# the number of bytes written or -errno if writing failed.
sub _syswrite {
	my $io = shift;
	my $cmd = shift;
	my $length = shift;
	my $now = time();

	my $res_file = SCST_QUEUE_RES_PATH();

	my $bytes = syswrite($io, $cmd, $length);
	$bytes = -$! if (!defined($bytes));

	if (defined($res_file) && $bytes == - EAGAIN) {
		my $res_io = new IO::File $res_file, O_RDONLY;

		if (!$res_io) {
			cluck("FATAL: Failed opening $res_file: $!");
			return - ENOENT;
		}

		my $res_val;

		while (($now + $TIMEOUT) > time()) {
			if (!defined(sysread($res_io, $res_val, 8)) &&
			    $! == EAGAIN) {
				sleep 1;
			} else {
				last;
			}
		}

		close $res_io;

		if (!defined($res_val)) {
			my $_cmd = $cmd; chomp $_cmd;
			cluck("Timeout while waiting for command '$_cmd' to complete");
		} elsif ($res_val == 0) {
			$bytes = $length;
		}
	}

	return $bytes;
}

sub make_path {
	return File::Spec->catdir(@_);
}

;1 __END__

=head1 NAME

SCST::SCST - Generic SCST methods.

=head1 SYNOPSIS

    use SCST::SCST;

    $p = SCST::SCST->new();

    print "Using SCST version".$p->scstVersion()."\n";

    undef $p;

=head1 DESCRIPTION

Generic SCST methods.

=head2 Methods

=over 5

=item SCST::SCST->new();

Create a new SCST object. If the argument $debug is non-zero no changes
will be made.

Arguments: (bool) $debug

Returns: (object) $new

=item SCST::SCST->scstVersion();

Returns the version of SCST running.

Arguments: void

Returns: (string) $version

=back

=head1 WARNING

None at this time.

=head1 NOTES

None at this time.

=cut
