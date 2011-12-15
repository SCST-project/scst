# -*- mode: perl; perl-indent-level: 8; indent-tabs-mode: t -*-

package SCST::SCST;

# Author:	Mark R. Buechler
# License:	GPLv2
# Copyright (c) 2005-2011 Mark R. Buechler
# Copyright (c) 2011 Bart Van Assche <bvanassche@acm.org>.

use 5.005;
use Fcntl ':mode';
use IO::Handle;
use IO::File;
use strict;
use Carp qw(cluck);

use POSIX;

use constant {
TRUE             => 1,
FALSE            => 0,

SCST_ROOT_OLD    => '/sys/kernel/scst_tgt',
SCST_ROOT_NEW    => '/sys/devices/scst',

# Root-level
SCST_SGV         => 'sgv',
# Root level, old sysfs interface
SCST_HANDLERS    => 'handlers',
SCST_DEVICES     => 'devices',
SCST_TARGETS     => 'targets',
SCST_DEV_GROUPS  => 'device_groups',
SCST_QUEUE_RES   => 'last_sysfs_mgmt_res',
# Root level, new sysfs interface
IN_SCST_HANDLERS => 'device_driver',
IN_SCST_DEVICES  => 'device',
IN_SCST_TARGETS  => 'target_driver',
IN_SCST_DEV_GROUPS => 'device_groups',
SCST_ADD_TGT        => 'add_target',
SCST_ADD_TGT_PARAMS => 'add_target_parameters',
SCST_TGTT_ATTR      => 'driver_attributes',
SCST_TGT_ATTR       => 'target_attributes',
SCST_ADD_DEV_PARAMS => 'add_device_parameters',
SCST_PARAM_ATTR     => 'parameters',

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
(SCST_C_FATAL_ERROR)          => 'A fatal error occured. See "dmesg" for more information.',
(SCST_C_BAD_ATTRIBUTES)       => 'Bad attributes given for SCST.',
(SCST_C_ATTRIBUTE_STATIC)     => 'SCST attribute specified is static',
(SCST_C_SETATTR_FAIL)         => 'Failed to set a SCST attribute. See "demsg" for more information.',

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

$VERSION = 0.9.10;

$TGT_TYPE_HARDWARE = 1;
$TGT_TYPE_VIRTUAL  = 2;

my $TIMEOUT = 300; # Command execution timeout

my $_SCST_MIN_MAJOR_   = 2;
my $_SCST_MIN_MINOR_   = 0;
my $_SCST_MIN_RELEASE_ = 0;

sub new_sysfs_interface {
	return !(-d SCST_ROOT_OLD);
}

sub SCST_ROOT_DIR {
	return -d SCST_ROOT_OLD ? SCST_ROOT_OLD : SCST_ROOT_NEW;
}

sub SCST_SGV_DIR {
	return SCST_ROOT_DIR() . '/sgv'
}

sub SCST_QUEUE_RES_PATH {
	return -d SCST_ROOT_OLD ? SCST_ROOT_OLD . '/' . SCST_QUEUE_RES : undef;
}

# Device handlers.
sub SCST_HANDLERS_DIR {
	if (-d SCST_ROOT_OLD) {
		return SCST_ROOT_OLD . '/' . SCST_HANDLERS;
	} else {
		return '/sys/bus/scst_tgt_dev/drivers';
	}
}

# Device instances.
sub SCST_DEVICES_DIR {
	if (-d SCST_ROOT_OLD) {
		return SCST_ROOT_OLD . '/' . SCST_DEVICES;
	} else {
		return '/sys/bus/scst_tgt_dev/devices';
	}
}

# Target drivers.
sub SCST_TARGETS_DIR {
	if (-d SCST_ROOT_OLD) {
		return SCST_ROOT_OLD . '/' . SCST_TARGETS;
	} else {
		return '/sys/bus/scst_target/drivers';
	}
}

# ALUA Device groups.
sub SCST_DEV_GROUP_DIR {
	return make_path(SCST_ROOT_DIR(), SCST_DEV_GROUPS);
}

sub new {
	my $this = shift;
	my $debug = shift;
	my $badVersion = 1;

	my $class = ref($this) || $this;
	my $self = {};

	bless($self, $class);

	$self->{'debug'} = $debug;

	my $scstVersion = $self->scstVersion();

	die("Failed to obtain SCST version information. Are the SCST modules loaded?\n")
	  if (!defined($scstVersion));

	($scstVersion, undef) = split(/\-/, $scstVersion);
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

sub scstVersion {
	my $self = shift;

	my $attributes = $self->scstAttributes();

	return undef if (!defined($attributes));
	return $$attributes{'version'}->{'value'};
}

sub scstAttributes {
	my $self = shift;
	my %attributes;

	my $pHandle = new IO::Handle;
	my $_path = SCST_ROOT_DIR();
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "scstAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "scsiAttributes(): Unable to read ".
					  "scst attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

				$attributes{$attribute}->{'static'} = $is_static;
			}
		}
	}

	return \%attributes;
}

sub setScstAttribute {
	my $self = shift;
	my $attribute = shift;
	my $value = shift;

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->scstAttributes();

	return SCST_C_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my $path = make_path(SCST_ROOT_DIR(), $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_SETATTR_FAIL;
}

sub drivers {
	my $self = shift;
	my @drivers;

	my $dHandle = new IO::Handle;
	my $_path = SCST_TARGETS_DIR();
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "drivers(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $driver (readdir($dHandle)) {
		next if (($driver eq '.') || ($driver eq '..'));

		if (-d make_path(SCST_TARGETS_DIR(), $driver)) {
			push @drivers, $driver;
		}
	}

	close $dHandle;

	return \@drivers;
}


sub targets {
	my $self = shift;
	my $driver = shift;
	my @targets;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "targets(): Driver '$driver' is not available";
		return undef;
	}

	my $tHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver);
	if (!(opendir $tHandle, $_path)) {
		$self->{'err_string'} = "targets(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $target (readdir($tHandle)) {
		next if ($target eq '.' || $target eq '..' ||
			 $target eq 'module');

		if (-d make_path(SCST_TARGETS_DIR(), $driver, $target)) {
			push @targets, $target;
		}
	}

	close $tHandle;

	return \@targets;
}

sub groups {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my @groups;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "groups(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "groups(): Target '$target' is not available";
		return undef;
	}

	my $gHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
			      SCST_GROUPS);
	if (!(opendir $gHandle, $_path)) {
		$self->{'err_string'} = "groups(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $group (readdir($gHandle)) {
		next if (($group eq '.') || ($group eq '..'));

		if (-d make_path(SCST_TARGETS_DIR(), $driver,
				 $target, SCST_GROUPS, $group)) {
			push @groups, $group;
		}
	}

	close $gHandle;

	return \@groups;
}

sub initiators {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my @initiators;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "initiators(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "initiators(): Target '$target' is not available";
		return undef;
	}

	if ($self->groupExists($driver, $target, $group) != TRUE) {
		$self->{'err_string'} = "initiators(): Group '$group' does not exist";
		return undef;
	}

	my $iHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			      $group, SCST_INITIATORS);
	if (!(opendir $iHandle, $_path)) {
		$self->{'err_string'} = "initiators(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $initiator (readdir($iHandle)) {
		next if (($initiator eq '.') || ($initiator eq '..'));
		next if ($initiator eq SCST_MGMT_IO);

		push @initiators, $initiator;
	}

	close $iHandle;

	return \@initiators;
}

sub luns {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my %luns;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "luns(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "luns(): Target '$target' is not available";
		return undef;
	}

	my $_path;

	if ($group) {
		if ($self->groupExists($driver, $target, $group) != TRUE) {
			$self->{'err_string'} = "initiators(): Group '$group' does not exist";
			return undef;
		}

		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_GROUPS, $group, SCST_LUNS);
	} else {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_LUNS);
	}

	my $lHandle = new IO::Handle;

	if (!(opendir $lHandle, $_path)) {
		$self->{'err_string'} = "luns(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $lun (readdir($lHandle)) {
		next if (($lun eq '.') || ($lun eq '..'));

		my $lPath = make_path($_path, $lun);

		if (-d $lPath) {
			my $_lHandle = new IO::Handle;

			if (!(opendir $_lHandle, $lPath)) {
				$self->{'err_string'} = "luns(): Unable to read directory '$lPath': $!";
				return undef;
			}

			foreach my $attribute (readdir($_lHandle)) {
				my $pPath = make_path($lPath, $attribute);

				if (-l $pPath) {
					my $linked = readlink($pPath);
					$linked =~ s/.*\///;
					$luns{$lun} = $linked;
				}
			}
		}
	}

	close $lHandle;

	return \%luns;
}

sub deviceGroups {
	my $self = shift;
	my @groups;

	my $dHandle = new IO::Handle;
	my $_path = SCST_DEV_GROUP_DIR();
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "deviceGroups(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $group (readdir($dHandle)) {
		next if (($group eq '.') || ($group eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group)) {
			push @groups, $group;
		}
	}

	close $dHandle;

	return \@groups;
}

sub deviceGroupDevices {
	my $self = shift;
	my $group = shift;
	my @devices;

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "deviceGroupDevices(): Device group '$group' does not exist";
		return undef;
	}

	my $dHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES);
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "deviceGroupDevices(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $device (readdir($dHandle)) {
		next if (($device eq '.') || ($device eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES, $device)) {
			push @devices, $device;
		}
	}

	close $dHandle;

	return \@devices;
}

sub targetGroups {
	my $self = shift;
	my $group = shift;
	my @tgroups;

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "targetGroups(): Device group '$group' does not exist";
		return undef;
	}

	my $dHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS);
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "targetGroups(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $tgroup (readdir($dHandle)) {
		next if (($tgroup eq '.') || ($tgroup eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup)) {
			push @tgroups, $tgroup;
		}
	}

	close $dHandle;

	return \@tgroups;
}

sub targetGroupTargets {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my @targets;

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "targetGroupTargets(): Device group '$group' does not exist";
		return undef;
	}

	if ($self->targetGroupExists($group, $tgroup) != TRUE) {
		$self->{'err_string'} = "targetGroupTargets(): Target group '$tgroup' does not exist";
		return undef;
	}

	my $dHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup);
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "targetGroupTargets(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $tgt (readdir($dHandle)) {
		next if (($tgt eq '.') || ($tgt eq '..'));

		if (-d make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup, $tgt)) {
			push @targets, $tgt;
		}
	}

	close $dHandle;

	return \@targets;
}

sub driverExists {
	my $self = shift;
	my $driver = shift;

	my $drivers = $self->drivers();

	return SCST_C_FATAL_ERROR if (!defined($drivers));

	foreach my $_driver (@{$drivers}) {
		return TRUE if ($driver eq $_driver);
	}

	return FALSE;
}

sub driverDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my %attributes;
	my $available;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "driverDynamicAttributes(): Driver '$driver' ".
		  "is not available";
		return undef;
	}

	if (new_sysfs_interface()) {
		my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
						SCST_TGTT_ATTR), O_RDONLY;
		if ($io) {
			while (my $attribute = <$io>) {
				chomp($attribute);
				$attributes{$attribute} = '';
			}
		}
	} else {
		my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
						SCST_MGMT_IO), O_RDONLY;

		if (!$io) {
			$self->{'err_string'} = "driverDynamicAttributes(): Unable to open mgmt ".
			    "interface for driver '$driver': $!";
			return undef;
		}

		while (my $in = <$io>) {
			if ($in =~ /^The following target driver attributes available\:/) {
				(undef, $available) = split(/\:/, $in, 2);
				$available =~ s/\.$//;
			}
		}

		if ($available) {
			foreach my $attribute (split(/\,/, $available)) {
				$attribute =~ s/^\s+//;
				$attribute =~ s/\s+$//;
				$attributes{$attribute} = '';
			}
		}
	}

	return \%attributes;
}

sub checkDriverDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if (!$rc > 1);

	my $available = $self->driverDynamicAttributes($driver);

	return SCST_C_FATAL_ERROR if (!defined($available));

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

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$rc = $self->checkDriverDynamicAttributes($driver, $attribute);
	return SCST_C_DRV_BAD_ATTRIBUTES if ($rc == 1);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	}
	$cmd .= "add_attribute $attribute $value";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DRV_ADDATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DRV_ADDATTR_FAIL;

}

sub removeDriverDynamicAttribute {
	my $self = shift;
	my $driver = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$rc = $self->checkDriverDynamicAttributes($driver, $attribute);
	return SCST_C_DRV_BAD_ATTRIBUTES if ($rc == 1);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	}
	$cmd .= "del_attribute $attribute $value";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DRV_REMATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DRV_REMATTR_FAIL;
}

sub targetExists {
	my $self = shift;
	my $driver = shift;
	my $target = shift;

	return FALSE if (!defined($target));

	my $rc = $self->driverExists($driver);

	return FALSE if (!$rc);
	return $rc if ($rc > 1);

	my $targets = $self->targets($driver);

	return SCST_C_FATAL_ERROR if (!defined($targets));

	foreach my $_target (@{$targets}) {
		return TRUE if ($target eq $_target);
	}

	return FALSE;
}

sub driverIsVirtualCapable {
	my $self = shift;
	my $driver = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	if (new_sysfs_interface()) {
		my $path = make_path(SCST_TARGETS_DIR(), $driver, SCST_ADD_TGT);
		my $io = new IO::File $path, O_RDONLY;
		if ($io) {
			my $line = <$io>;
			chomp($line);
			return $line eq '1';
		}
		return FALSE;
	} else {
		my $path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
		return (-w $path) ? TRUE : FALSE;
	}
}

sub targetType {
	my $self = shift;
	my $driver = shift;
	my $target = shift;

	if ($self->driverIsVirtualCapable($driver)) {
		my $attribs = $self->targetAttributes($driver, $target);

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

	my $o_string;
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
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	}
	$cmd .= "add_target $target $o_string";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_ADD_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGT_ADD_FAIL;
}

sub targetDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my %attributes;
	my $available;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "targetDynamicAttributes(): Driver '$driver' ".
		  "is not available";
		return undef;
	}

	if (new_sysfs_interface()) {
		my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
						SCST_TGT_ATTR), O_RDONLY;
		if ($io) {
			while (my $attribute = <$io>) {
				chomp($attribute);
				$attributes{$attribute} = '';
			}
		}
	} else {
		my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
						SCST_MGMT_IO), O_RDONLY;

		if (!$io) {
			$self->{'err_string'} = "targetDynamicAttributes(): Unable to open mgmt ".
			    "interface for driver '$driver': $!";
			return undef;
		}

		while (my $in = <$io>) {
			if ($in =~ /^The following target attributes available\:/) {
				(undef, $available) = split(/\:/, $in, 2);
				$available =~ s/\.$//;
			}
		}

		if ($available) {
			foreach my $attribute (split(/\,/, $available)) {
				$attribute =~ s/^\s+//;
				$attribute =~ s/\s+$//;
				$attributes{$attribute} = '';
			}
		}
	}

	return \%attributes;
}

sub checkTargetDynamicAttributes {
	my $self = shift;
	my $driver = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if (!$rc > 1);

	my $available = $self->targetDynamicAttributes($driver);

	return SCST_C_FATAL_ERROR if (!defined($available));

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

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	}
	$cmd .= "add_target_attribute $target $attribute $value";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_ADDATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGT_ADDATTR_FAIL;
}

sub removeTargetDynamicAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $attribute = shift;
	my $value = shift;

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

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	}
	$cmd .= "del_target_attribute $target $attribute $value";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_REMATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGT_REMATTR_FAIL;
}

sub removeVirtualTarget {
	my $self = shift;
	my $driver = shift;
	my $target = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	return SCST_C_DRV_NOTVIRT if (!$self->driverIsVirtualCapable($driver));

	$self->enableTarget($driver, $target, FALSE);

	my $sessions = $self->sessions($driver, $target);

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
			$sessions = $self->sessions($driver, $target);

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
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, SCST_MGMT_IO);
	}
	$cmd .= "del_target $target";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_REM_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return SCST_C_TGT_BUSY if ($bytes == -1);
	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGT_REM_FAIL;
}

sub groupExists {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	return FALSE if (!defined($group));

	my $rc = $self->targetExists($driver, $target);

	return FALSE if (!$rc);
	return $rc if ($rc > 1);

	my $groups = $self->groups($driver, $target);

	return SCST_C_FATAL_ERROR if (!defined($groups));

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

	return FALSE if (!defined($initiator));

	my $rc = $self->groupExists($driver, $target, $group);

	return FALSE if (!$rc);
	return $rc if ($rc > 1);

	my $initiators = $self->initiators($driver, $target, $group);

	return SCST_C_FATAL_ERROR if (!defined($initiators));

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

	return FALSE if (!defined($lun));


	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_EXISTS if (!$rc);
	return $rc if ($rc > 1);

	if ($group) {
		my $rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);
	}

	my $luns = $self->luns($driver, $target, $group);

	return SCST_C_FATAL_ERROR if (!defined($luns));

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

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target,
					 SCST_GROUPS) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, SCST_MGMT_IO);
	}
	$cmd .= "create $group";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_ADD_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_GRP_ADD_FAIL;
}

sub removeGroup {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target,
					 SCST_GROUPS) . " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, SCST_MGMT_IO);
	}
	$cmd .= "del $group";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_REM_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_GRP_REM_FAIL;
}

sub addDeviceGroup {
	my $self = shift;
	my $group = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), SCST_MGMT_IO);
	}
	$cmd .= "create $group";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DEV_GRP_ADD_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DEV_GRP_ADD_FAIL;
}

sub removeDeviceGroup {
	my $self = shift;
	my $group = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), SCST_MGMT_IO);
	}
	$cmd .= "del $group";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DEV_GRP_REM_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DEV_GRP_REM_FAIL;
}

sub addDeviceGroupDevice {
	my $self = shift;
	my $group = shift;
	my $device = shift;

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
	my $dgroups = $self->deviceGroups();

	foreach my $dgroup (@{$dgroups}) {
		my $devs = $self->deviceGroupDevices($dgroup);

		foreach my $dev (@{$devs}) {
			return SCST_C_DGRP_DEVICE_OTHER if ($dev eq $device);
		}
	}

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS, $group,
					 SCST_DG_DEVICES) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES, SCST_MGMT_IO);
	}
	$cmd .= "add $device";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DGRP_ADD_DEV_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DGRP_ADD_DEV_FAIL;
}

sub addTargetGroup {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_GROUP_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS, $group,
					 SCST_DG_TGROUPS) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, SCST_MGMT_IO);
	}
	$cmd .= "add $tgroup";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DGRP_ADD_GRP_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DGRP_ADD_GRP_FAIL;
}

sub addTargetGroupTarget {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupTargetExists($group, $tgroup, $tgt);
	return SCST_C_TGRP_TGT_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS, $group,
					 SCST_DG_TGROUPS, $tgroup) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
				  $tgroup, SCST_MGMT_IO);
	}
	$cmd .= "add $tgt";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGRP_ADD_TGT_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGRP_ADD_TGT_FAIL;
}

sub removeDeviceGroupDevice {
	my $self = shift;
	my $group = shift;
	my $device = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->deviceExists($device);
        return SCST_C_DEV_NO_DEVICE if (!$rc);
        return $rc if ($rc > 1);

	$rc = $self->deviceGroupDeviceExists($group, $device);
	return SCST_C_DGRP_NO_DEVICE if (!$rc);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS, $group,
					 SCST_DG_DEVICES) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_DEVICES, SCST_MGMT_IO);
	}
	$cmd .= "del $device";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DGRP_REM_DEV_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DGRP_REM_DEV_FAIL;
}

sub removeTargetGroup {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS, $group,
					 SCST_DG_TGROUPS) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, SCST_MGMT_IO);
	}
	$cmd .= "del $tgroup";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DGRP_REM_GRP_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DGRP_REM_GRP_FAIL;
}

sub removeTargetGroupTarget {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupTargetExists($group, $tgroup, $tgt);
	return SCST_C_TGRP_NO_TGT if (!$rc);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEV_GROUPS, $group,
					 SCST_DG_TGROUPS, $tgroup) . " ";
	} else {
		$path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
				  $tgroup, SCST_MGMT_IO);
	}
	$cmd .= "del $tgt";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGRP_REM_TGT_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGRP_REM_TGT_FAIL;
}

sub addInitiator {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;

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

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target,
					 SCST_GROUPS, $group, SCST_INITIATORS) .
					     " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_INITIATORS,
				  SCST_MGMT_IO);
	}
	$cmd .= "add $initiator";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_ADD_INI_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_GRP_ADD_INI_FAIL;
}

sub removeInitiator {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;

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

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target,
					 SCST_GROUPS, $group, SCST_INITIATORS) .
					     " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_INITIATORS,
				  SCST_MGMT_IO);
	}
	$cmd .= "del $initiator";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_REM_INI_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_GRP_REM_INI_FAIL;
}

sub moveInitiator {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $from = shift;
	my $to = shift;
	my $initiator = shift;

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

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target,
					 SCST_GROUPS, $from, SCST_INITIATORS) .
					     " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $from, SCST_INITIATORS,
				  SCST_MGMT_IO);
	}
	$cmd .= "move $initiator $to";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_MOV_INI_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_GRP_MOV_INI_FAIL;
}

sub clearInitiators {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target,
					 SCST_GROUPS, $group, SCST_INITIATORS) .
					     " ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_INITIATORS,
				  SCST_MGMT_IO);
	}
	$cmd .= "clear";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_CLR_INI_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
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

	my $err;
	my $err2;

	my $rc = $self->driverExists($driver);
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

	if ($group) {
		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);

		$err  = SCST_C_GRP_ADD_LUN_FAIL;
		$err2 = SCST_C_GRP_LUN_EXISTS;

	} else {
		$err  = SCST_C_TGT_ADD_LUN_FAIL;
		$err2 = SCST_C_TGT_LUN_EXISTS;
	}

	return $err if (!defined($lun));

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return $err2 if ($rc == TRUE);
	return $rc if ($rc > 1);

	my $o_string;
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value; ";
	}

	$o_string =~ s/\s$//;

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		if ($group) {
			$cmd = "in " .
			    make_path(IN_SCST_TARGETS, $driver, $target,
				      SCST_GROUPS, $group, SCST_LUNS) . " ";
		} else {
			$cmd = "in " . make_path(IN_SCST_TARGETS, $driver,
						 $target, SCST_LUNS) . " ";
		}
	} else {
		if ($group) {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_GROUPS, $group, SCST_LUNS,
					  SCST_MGMT_IO);
		} else {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_LUNS, SCST_MGMT_IO);
		}
	}
	$cmd .= "add $device $lun $o_string";

	my $io = new IO::File $path, O_WRONLY;

	return $err if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return $err;
}

sub removeLun {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $group = shift;

	my $err;
	my $err2;

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

		$err  = SCST_C_GRP_REM_LUN_FAIL;
		$err2 = SCST_C_GRP_NO_LUN;
	} else {
		$err  = SCST_C_TGT_ADD_LUN_FAIL;
		$err2 = SCST_C_TGT_NO_LUN;
	}

	return $err if (!defined($lun));

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return $err2 if (!$rc);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		if ($group) {
			$cmd = "in " . make_path(IN_SCST_TARGETS, $driver,
						 $target, SCST_GROUPS, $group,
						 SCST_LUNS) . " ";
		} else {
			$cmd = "in " . make_path(IN_SCST_TARGETS, $driver,
						 $target, SCST_LUNS) . " ";
		}
	} else {
		if ($group) {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_GROUPS, $group, SCST_LUNS,
					  SCST_MGMT_IO);
		} else {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_LUNS, SCST_MGMT_IO);
		}
	}
	$cmd .= "del $lun";

	my $io = new IO::File $path, O_WRONLY;

	return $err if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
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

	return TRUE if (!defined($lun));

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

	my $luns = $self->luns($driver, $target, $group);

	return SCST_C_LUN_DEV_EXISTS if ($$luns{$lun} eq $device);

	my $o_string;
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value; ";
	}

	$o_string =~ s/\s$//;

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		if ($group) {
			$cmd = "in " . make_path(IN_SCST_TARGETS, $driver,
						 $target, SCST_GROUPS,
						 $group, SCST_LUNS) . " ";
		} else {
			$cmd = "in " . make_path(IN_SCST_TARGETS, $driver,
						 $target, SCST_LUNS) . " ";
		}
	} else {
		if ($group) {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_GROUPS, $group, SCST_LUNS,
					  SCST_MGMT_IO);
		} else {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_LUNS, SCST_MGMT_IO);
		}
	}
	$cmd .= "replace $device $lun $o_string";

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_LUN_RPL_DEV_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_LUN_RPL_DEV_FAIL;
}

sub clearLuns {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;

	my $err;

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

		$err = SCST_C_GRP_CLR_LUN_FAIL;
	} else {
		$err = SCST_C_TGT_CLR_LUN_FAIL
	}

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		if ($group) {
			$cmd = "in " .
			    make_path(IN_SCST_TARGETS, $driver, $target,
				      SCST_GROUPS, $group, SCST_LUNS) . " ";
		} else {
			$cmd = "in " . make_path(IN_SCST_TARGETS, $driver,
						 $target, SCST_LUNS) . " ";
		}
	} else {
		if ($group) {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_GROUPS, $group, SCST_LUNS,
					  SCST_MGMT_IO);
		} else {
			$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					  SCST_LUNS, SCST_MGMT_IO);
		}
	}
	$cmd .= "clear";

	my $io = new IO::File $path, O_WRONLY;

	return $err if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_GRP_CLR_LUN_FAIL;
}

sub deviceHandler {
	my $self = shift;
	my $device = shift;

	my $handler = readlink(make_path(SCST_DEVICES_DIR(), $device,
				new_sysfs_interface() ? 'driver' : 'handler'));
	$handler =~ s/.*\///;
	return $handler;
}

sub devices {
	my $self = shift;
	my $handler = shift;
	my @devices;

	my $dHandle = new IO::Handle;
	my $_path = new_sysfs_interface() || !defined($handler) ?
	    SCST_DEVICES_DIR() : make_path(SCST_HANDLERS_DIR(), $handler);
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "devices(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $device (readdir($dHandle)) {
		next if ($device eq '.' || $device eq '..');

		my $isdev = (new_sysfs_interface() ||
			     -d make_path(SCST_DEVICES_DIR(), $device));
		if ($isdev && (!defined($handler) || 
			       $handler eq $self->deviceHandler($device))) {
			push @devices, $device;
		}
	}

	close $dHandle;

	return \@devices;
}

sub deviceOpen {
	my $self = shift;
	my $device = shift;

	return FALSE if (!defined($device));

	my $devices = $self->devices();

	return SCST_C_FATAL_ERROR if (!defined($devices));

	foreach my $_device (@{$devices}) {
		return TRUE if ($device eq $_device);
	}

	return FALSE;
}

sub deviceAttributes {
	my $self = shift;
	my $device = shift;
	my %attributes;

	if ($self->deviceOpen($device) != TRUE) {
		$self->{'err_string'} = "deviceAttributes(): Device '$device' is not open";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEVICES_DIR(), $device);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "deviceAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	my $dca = $self->deviceCreateAttributes($self->deviceHandler($device));

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

				my $g = SCST_GROUPS;
				my $l = SCST_LUNS;

				if ($linked =~ /.*\/(.+)\/(.+)\/$g\/(.+)\/$l\/(\d+)/) {
					my $driver = $1;
					my $target = $2;
					my $group = $3;
					my $lun = $4;

					$attributes{$attribute}->{'value'}->{$driver}->{$target}->{$group} = $lun;
				}

				$attributes{$attribute}->{'static'} = TRUE;
			}
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
					$self->{'err_string'} = "deviceAttributes(): Unable to read ".
					  "device attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() &&
				    (!$is_static || defined($$dca{$attribute}))
				    || ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub driverAttributes {
	my $self = shift;
	my $driver = shift;
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "driverAttributes(): Driver '$driver' is not available";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "driverAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "driverAttributes(): Unable to read ".
					  "driver attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

				$attributes{$attribute}->{'static'} = $is_static;
			}
		}
	}

	return \%attributes;
}

sub setDriverAttribute {
	my $self = shift;
	my $driver = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->driverAttributes($driver);

	return SCST_C_DRV_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_DRV_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my $path = make_path(SCST_TARGETS_DIR(), $driver, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DRV_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DRV_SETATTR_FAIL;
}

sub targetAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "targetAttributes(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "targetAttributes(): Target '$target' is not available";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "targetAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "targetAttributes(): Unable to read ".
					  "target attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub setTargetAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->targetAttributes($driver, $target);

	return SCST_C_TGT_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_TGT_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my ($path, $cmd);
	if (new_sysfs_interface() &&
	    ($attribute eq 'enabled' || $attribute eq 'cpu_mask')) {
		$path = make_path(SCST_ROOT_DIR, SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target) .
		    " " . ($attribute eq 'enabled' ?
			   ($value eq '1' ? 'enable' : 'disable') :
			   "set_$attribute $value");
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  $attribute);
		$cmd = $value;
	}

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $cmd > $path\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGT_SETATTR_FAIL;
}

sub groupAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "groupAttributes(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "groupAttributes(): Target '$target' is not available";
		return undef;
	}

	if ($self->groupExists($driver, $target, $group) != TRUE) {
		$self->{'err_string'} = "groupAttributes(): Group '$group' does not exist";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			      $group);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "groupAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "groupAttributes(): Unable to read ".
					  "group attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub setGroupAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->groupAttributes($driver, $target, $group);

	return SCST_C_GRP_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_GRP_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my ($path, $cmd);
	if (new_sysfs_interface() && $attribute eq 'cpu_mask') {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_TARGETS, $driver, $target,
					 SCST_GROUPS, $group) .
					     " set_$attribute ";
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, $attribute);
	}
	$cmd .= $value;

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $cmd > $path\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_GRP_SETATTR_FAIL;
}

sub lunAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $group = shift;
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "lunAttributes(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "lunAttributes(): Target '$target' is not available";
		return undef;
	}

	my ($_path, $luncrattr);

	if ($group) {
		if ($self->groupExists($driver, $target, $group) != TRUE) {
			$self->{'err_string'} = "lunAttributes(): Group '$group' does not exist";
			return undef;
		}

		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_GROUPS, $group, SCST_LUNS, $lun);
		$luncrattr = $self->lunCreateAttributes($driver, $target,
							$group);
	} else {
		$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				   SCST_LUNS, $lun);
		$luncrattr = $self->lunCreateAttributes($driver, $target);
	}

	if ($self->lunExists($driver, $target, $lun, $group) != TRUE) {
		$self->{'err_string'} = "lunAttributes(): LUN '$lun' does not exist";
		return undef;
	}

	my $pHandle = new IO::Handle;
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "lunAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "lunAttributes(): Unable to read ".
					  "lun attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() &&
				    (!$is_static ||
				     defined($$luncrattr{$attribute})) ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub setLunAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $lun = shift;
	my $attribute = shift;
	my $value = shift;
	my $group = shift;

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	my $path;

	if ($group) {
		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);

		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_GROUPS, $group, SCST_LUNS, $lun,
				  $attribute);
	} else {
		$path = make_path(SCST_TARGETS_DIR(), $driver, $target,
				  SCST_LUNS, $lun, $attribute);
	}

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return SCST_C_GRP_NO_LUN if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->lunAttributes($driver, $target, $group, $lun);

	return SCST_C_LUN_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_LUN_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_LUN_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_LUN_SETATTR_FAIL;
}

sub initiatorAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "initiatorAttributes(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "initiatorAttributes(): Target '$target' is not available";
		return undef;
	}

	if ($self->groupExists($driver, $target, $group) != TRUE) {
		$self->{'err_string'} = "initiatorAttributes(): Group '$group' does not exist";
		return undef;
	}

	if ($self->initiatorExists($driver, $target, $group, $initiator) != TRUE) {
		$self->{'err_string'} = "initiatorAttributes(): Initiator '$initiator' does not exist";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			      $group, SCST_INITIATORS, $initiator);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "initiatorAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "initiatorAttributes(): Unable to read ".
					  "initiator attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub setInitiatorAttribute {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $initiator = shift;
	my $attribute = shift;
	my $value = shift;

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

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->initiatorAttributes($driver, $target, $group, $initiator);

	return SCST_C_INI_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_INI_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my $path = make_path(SCST_TARGETS_DIR(), $driver, $target, SCST_GROUPS,
			     $group, SCST_LUNS, $initiator, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_INI_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_INI_SETATTR_FAIL;
}

sub deviceGroupAttributes {
	my $self = shift;
	my $group = shift;
	my %attributes;

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "targetGroupAttributes(): Device group '$group' does not exist";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "deviceGroupAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "deviceGroupAttributes(): Unable to read ".
					  "device group attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub targetGroupAttributes {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my %attributes;

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "targetGroupAttributes(): Device group '$group' does not exist";
		return undef;
	}

	if ($self->targetGroupExists($group, $tgroup) != TRUE) {
		$self->{'err_string'} = "targetGroupAttributes(): Target Group '$tgroup' does not exist";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "targetGroupAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "targetGroupAttributes(): Unable to read ".
					  "target group attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub targetGroupTargetAttributes {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;
	my %attributes;

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "targetGroupTargetAttributes(): Device group '$group' does not exist";
		return undef;
	}

	if ($self->targetGroupExists($group, $tgroup) != TRUE) {
		$self->{'err_string'} = "targetGroupTargetAttributes(): Target Group '$tgroup' does not exist";
		return undef;
	}

	if ($self->targetGroupTargetExists($group, $tgroup, $tgt) != TRUE) {
		$self->{'err_string'} = "targetGroupTargetAttributes(): Target '$tgt' does not exist";
		return undef;
	}

	my $pHandle = new IO::Handle;
	my $_path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup, $tgt);
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "targetGroupTargetAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
					$self->{'err_string'} = "targetGroupTargetAttributes(): Unable to read ".
					  "target group target attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = new_sysfs_interface() && !$is_static ||
				    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

				my $key = 0;
				if ($is_key) {
					if ($attribute =~ /.*(\d+)$/) {
						$key = $1;
						$attribute =~ s/\d+$//;
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

	return \%attributes;
}

sub setDeviceGroupAttribute {
	my $self = shift;
	my $group = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->deviceGroupAttributes($group);

	return SCST_C_DGRP_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_DGRP_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my $path = make_path(SCST_DEV_GROUP_DIR(), $group, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DGRP_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DGRP_SETATTR_FAIL;
}

sub setTargetGroupAttribute {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->targetGroupAttributes($group, $tgroup);

	return SCST_C_TGRP_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_TGRP_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my $path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS, $tgroup, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGRP_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGRP_SETATTR_FAIL;
}

sub setTargetGroupTargetAttribute {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;
	my $tgt = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->deviceGroupExists($group);
	return SCST_C_DEV_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupExists($group, $tgroup);
	return SCST_C_DGRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetGroupTargetExists($group, $tgroup, $tgt);
	return SCST_C_TGRP_NO_TGT if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->targetGroupTargetAttributes($group, $tgroup, $tgt);

	return SCST_C_TGRP_TGT_BAD_ATTR if (!defined($$attributes{$attribute}));
	return SCST_C_TGRP_TGT_ATTR_STATIC if ($$attributes{$attribute}->{'static'});

	my $path = make_path(SCST_DEV_GROUP_DIR(), $group, SCST_DG_TGROUPS,
			     $tgroup, $tgt, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGRP_TGT_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_TGRP_TGT_SETATTR_FAIL;
}

sub handlers {
	my $self = shift;
	my @handlers;

	my $hHandle = new IO::Handle;
	my $_path = SCST_HANDLERS_DIR();
	if (!(opendir $hHandle, $_path)) {
		$self->{'err_string'} = "handlers(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $handler (readdir($hHandle)) {
		next if (($handler eq '.') || ($handler eq '..'));

		if (-d make_path(SCST_HANDLERS_DIR(), $handler)) {
			push @handlers, $handler;
		}
	}

	close $hHandle;

	return \@handlers;
}

sub handlerExists {
	my $self = shift;
	my $handler = shift;

	return FALSE if (!defined($handler));

	my $handlers = $self->handlers();

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

	my $rc = $self->handlerExists($handler);
	return SCST_C_HND_NO_HANDLER if (!$rc);
	return $rc if ($rc > 1);

	return TRUE if (!defined($attribute) || !defined($value));

	my $attributes = $self->handlerAttributes($handler);

	return SCST_C_HND_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_HND_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my $path = make_path(SCST_HANDLERS_DIR(), $handler, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_HND_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_HND_SETATTR_FAIL;
}

sub handlerAttributes {
	my $self = shift;
	my $handler = shift;
	my %attributes;

	if ($self->handlerExists($handler) != TRUE) {
		$self->{'err_string'} = "handlerAttributes(): Handler '$handler' is not available";
		return undef;
	}

	$attributes{'devices'}->{'value'} = devices($self, $handler);

	my $hHandle = new IO::Handle;
	my $_path = make_path(SCST_HANDLERS_DIR(), $handler);
	if (!(opendir $hHandle, $_path)) {
		$self->{'err_string'} = "handlerAttributes(): Unable to read directory '$_path': $!";
		return undef;
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
			$self->{'err_string'} = "handlerAttributes(): Unable to read handler attribute ".
			  "'$attribute': $!";
			return undef;
		}

		my $value = <$io>;
		chomp $value;

		my $is_key = <$io>;
		$is_key = new_sysfs_interface() && !$is_static ||
		    ($is_key =~ /\[key\]/) ? TRUE : FALSE;

		my $key = 0;
		if ($is_key) {
			if ($attribute =~ /.*(\d+)$/) {
				$key = $1;
				$attribute =~ s/\d+$//;
			}
		}

		next if ($attribute eq SCST_MGMT_IO);

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

	$attributes{'devices'}->{'static'} = TRUE;

	return \%attributes;
}

sub deviceExists {
	my $self = shift;
	my $device = shift;

	my $handlers = $self->handlers();

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

	my $rc = $self->handlerExists($handler);

	return FALSE if (!$rc);
	return $rc if ($rc > 1);

	my $devices = $self->devicesByHandler($handler);

	return SCST_C_FATAL_ERROR if (!defined($devices));

	foreach my $_device (@{$devices}) {
		return TRUE if ($_device eq $device);
	}

	return FALSE;
}

sub devicesByHandler {
	my $self = shift;
	my $handler = shift;

	if ($self->handlerExists($handler) != TRUE) {
		$self->{'err_string'} = "devicesByHandler(): Handler '$handler' is not available";
		return undef;
	}

	my $attributes = $self->handlerAttributes($handler);

	return undef if (!defined($attributes));
	return \@{$$attributes{'devices'}->{'value'}};
}

sub checkDeviceCreateAttributes {
	my $self = shift;
	my $handler = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my $rc = $self->handlerExists($handler);
	return SCST_C_HND_NO_HANDLER if (!$rc);
	return $rc if (!$rc > 1);

	my $available = $self->deviceCreateAttributes($handler);

	return SCST_C_FATAL_ERROR if (!defined($available));

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
	my %attributes;

	if ($self->handlerExists($handler) != TRUE) {
		$self->{'err_string'} = "deviceCreateAttributes(): Handler '$handler' ".
		  "is not available";
		return undef;
	}

	if (new_sysfs_interface()) {
		my $io = new IO::File make_path(SCST_HANDLERS_DIR(), $handler,
						SCST_ADD_DEV_PARAMS), O_RDONLY;

		while (my $attribute = <$io>) {
			chomp($attribute);
			$attributes{$attribute} = '';
		}
	} else {
		my $io = new IO::File make_path(SCST_HANDLERS_DIR(), $handler,
						SCST_MGMT_IO), O_RDONLY;

		if (!$io) {
			$self->{'err_string'} = "deviceCreateAttributes(): Unable to open mgmt ".
			    "interface for handler '$handler': $!";
			return undef;
		}

		while (my $in = <$io>) {
			if ($in =~ /^The following parameters available\:/) {
				(undef, $available) = split(/\:/, $in, 2);
				$available =~ s/\.$//;
			}
		}

		if ($available) {
			foreach my $attribute (split(/\,/, $available)) {
				$attribute =~ s/^\s+//;
				$attribute =~ s/\s+$//;
				$attributes{$attribute} = '';
			}
		}
	}

	return \%attributes;
}

sub openDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $attributes = shift;

	my $rc = $self->handlerExists($handler);
	return SCST_C_HND_NO_HANDLER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->checkDeviceCreateAttributes($handler, $attributes);
	return SCST_C_DEV_BAD_ATTRIBUTES if ($rc == TRUE);
	return $rc if ($rc > 1);

	$rc = $self->handlerDeviceExists($handler, $device);
	return SCST_C_DEV_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	my $o_string;
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value; ";
	}

	$o_string =~ s/\s$//;

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_HANDLERS, $handler) . " ";
	} else {
		$path = make_path(SCST_HANDLERS_DIR(), $handler, SCST_MGMT_IO);
	}
	$cmd .= "add_device $device $o_string";

	my $io = new IO::File $path, O_WRONLY;

	if (!$io) {
		$self->{'err_string'} = "openDevice(): Unable to open mgmt interface for ".
		  "handler '$handler': $!";
		return SCST_C_FATAL_ERROR;
	}

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DEV_OPEN_FAIL;
}

sub closeDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;

	my $rc = $self->handlerExists($handler);
	return SCST_C_HND_NO_HANDLER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->handlerDeviceExists($handler, $device);
	return SCST_C_DEV_NO_DEVICE if ($rc != TRUE);
	return $rc if ($rc > 1);

	my ($path, $cmd);
	if (new_sysfs_interface()) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_HANDLERS, $handler) . " ";
	} else {
		$path = make_path(SCST_HANDLERS_DIR(), $handler, SCST_MGMT_IO);
	}
	$cmd .= "del_device $device";

	my $io = new IO::File $path, O_WRONLY;

	if (!$io) {
		$self->{'err_string'} = "closeDevice(): Unable to open mgmt interface for handler ".
		  "'$handler': $!";
		return SCST_C_FATAL_ERROR;
	}

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DEV_CLOSE_FAIL;
}

sub setDeviceAttribute {
	my $self = shift;
	my $device = shift;
	my $attribute = shift;
	my $value = shift;

	my $rc = $self->deviceOpen($device);
	return SCST_C_DEV_NO_DEVICE if (!$rc);
	return $rc if ($rc > 1);

	my $attributes = $self->deviceAttributes($device);

	return SCST_C_FATAL_ERROR if (!defined($attributes));

	return SCST_C_DEV_BAD_ATTRIBUTES if (!defined($$attributes{$attribute}));
	return SCST_C_DEV_ATTRIBUTE_STATIC if ($$attributes{$attribute}->{'static'});

	my ($path, $cmd);
	if (new_sysfs_interface() &&
	    ($attribute eq 'filename' ||
	     $attribute eq 'threads_num' ||
	     $attribute eq 'threads_pool_type')) {
		$path = make_path(SCST_ROOT_DIR(), SCST_MGMT_IO);
		$cmd = "in " . make_path(IN_SCST_DEVICES, $device) . " set_$attribute ";
	} else {
		$path = make_path(SCST_DEVICES_DIR(), $device, $attribute);
	}
	$cmd .= $value;

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DEV_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $cmd > $path\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	close $io;

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_DEV_SETATTR_FAIL;
}

sub checkTargetCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	my $available = $self->targetCreateAttributes($driver);

	return SCST_C_FATAL_ERROR if (!defined($available));

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
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "targetCreateAttributes(): Driver '$driver' ".
		  "is not available";
		return undef;
	}

	if (new_sysfs_interface()) {
		my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
						SCST_ADD_TGT_PARAMS), O_RDONLY;
		while (my $attribute = <$io>) {
			chomp($attribute);
			$attributes{$attribute} = '';
		}
	} else {
		my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
						SCST_MGMT_IO), O_RDONLY;

		if (!$io) {
			$self->{'err_string'} = "targetCreateAttributes(): Unable to open driver mgmt ".
			    "interface for driver '$driver': $!";
			return undef;
		}

		while (my $in = <$io>) {
			if ($in =~ /^The following parameters available\:/) {
				(undef, $available) = split(/\:/, $in, 2);
				$available =~ s/\.$//;
			}
		}

		if ($available) {
			foreach my $attribute (split(/\,/, $available)) {
				$attribute =~ s/^\s+//;
				$attribute =~ s/\s+$//;
				$attributes{$attribute} = '';
			}
		}
	}

	return \%attributes;
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

	my $groups = $self->deviceGroups();

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

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "deviceGroupDeviceExists(): Device group '$group' does not exist";
		return undef;
	}

	my $devices = $self->deviceGroupDevices($group);

	return SCST_C_FATAL_ERROR if (!defined($devices));

	foreach my $_device (@{$devices}) {
		return TRUE if ($device eq $_device);
	}

	return FALSE;
}

sub targetGroupExists {
	my $self = shift;
	my $group = shift;
	my $tgroup = shift;

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "targetGroupExists(): Device group '$group' does not exist";
		return undef;
	}

	my $tgroups = $self->targetGroups($group);

	return SCST_C_FATAL_ERROR if (!defined($tgroups));

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

	if ($self->deviceGroupExists($group) != TRUE) {
		$self->{'err_string'} = "targetGroupTargetExists(): Device group '$group' does not exist";
		return undef;
	}

	if ($self->targetGroupExists($group, $tgroup) != TRUE) {
		$self->{'err_string'} = "targetGroupTargetExists(): Target group '$tgroup' does not exist";
		return undef;
	}

	my $targets = $self->targetGroupTargets($group, $tgroup);

	return SCST_C_FATAL_ERROR if (!defined($targets));

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

	my $available = $self->lunCreateAttributes($driver, $target, $group);

	return SCST_C_FATAL_ERROR if (!defined($available));

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
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "lunCreateAttributes(): Driver '$driver' ".
		  "is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "lunCreateAttributes(): Target '$target' ".
		  "is not available";
		return undef;
	}

	my $_path;

	if (new_sysfs_interface()) {
		if ($group) {
			if ($self->groupExists($driver, $target, $group) != TRUE) {
				$self->{'err_string'} = "lunCreateAttributes(): Group '$group' ".
				    "does not exist";
				return undef;
			}

			$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					   SCST_GROUPS, $group, SCST_LUNS,
					   SCST_PARAM_ATTR);
		} else {
			$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					   SCST_LUNS, SCST_PARAM_ATTR);
		}

		my $io = new IO::File $_path, O_RDONLY;
		while (my $attribute = <$io>) {
			chomp($attribute);
			$attributes{$attribute} = '';
		}
	} else {
		if ($group) {
			if ($self->groupExists($driver, $target, $group) != TRUE) {
				$self->{'err_string'} = "lunCreateAttributes(): Group '$group' ".
				    "does not exist";
				return undef;
			}

			$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					   SCST_GROUPS, $group, SCST_LUNS,
					   SCST_MGMT_IO);
		} else {
			$_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
					   SCST_LUNS, SCST_MGMT_IO);
		}

		my $io = new IO::File $_path, O_RDONLY;

		if (!$io) {
			$self->{'err_string'} = "lunCreateAttributes(): Unable to open luns mgmt ".
			    "interface for group '$group': $!";
			return undef;
		}

		while (my $in = <$io>) {
			if ($in =~ /^The following parameters available\:/) {
				(undef, $available) = split(/\:/, $in, 2);
				$available =~ s/\.$//;
			}
		}

		if ($available) {
			foreach my $attribute (split(/\,/, $available)) {
				$attribute =~ s/^\s+//;
				$attribute =~ s/\s+$//;
				$attributes{$attribute} = '';
			}
		}
	}
	return \%attributes;
}

sub checkInitiatorCreateAttributes {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $group = shift;
	my $check = shift;

	return FALSE if (!defined($check));

	my $rc = $self->driverExists($driver);
	return SCST_C_DRV_NO_DRIVER if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->targetExists($driver, $target);
	return SCST_C_TGT_NO_TARGET if (!$rc);
	return $rc if ($rc > 1);

	$rc = $self->groupExists($driver, $target, $group);
	return SCST_C_GRP_NO_GROUP if (!$rc);
	return $rc if ($rc > 1);

	my $available = $self->initiatorCreateAttributes($driver, $target, $group);

	return SCST_C_FATAL_ERROR if (!defined($available));

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
	my %attributes;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "initiatorCreateAttributes(): Driver '$driver' ".
		  "is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "initiatorCreateAttributes(): Target '$target' ".
		  "is not available";
		return undef;
	}

	if ($self->groupExists($driver, $target, $group) != TRUE) {
		$self->{'err_string'} = "initiatorCreateAttributes(): Group '$group' ".
		  "does not exist";
		return undef;
	}

	if (new_sysfs_interface()) {
		# Do nothing - there are no initiator attributes (yet).
	} else {
		my $io = new IO::File make_path(SCST_TARGETS_DIR(), $driver,
						$target, SCST_GROUPS, $group,
						SCST_INITIATORS, SCST_MGMT_IO),
				O_RDONLY;

		if (!$io) {
			$self->{'err_string'} = "initiatorCreateAttributes(): Unable to open initiators mgmt ".
			    "interface for group '$group': $!";
			return undef;
		}

		while (my $in = <$io>) {
			if ($in =~ /^The following parameters available\:/) {
				(undef, $available) = split(/\:/, $in, 2);
				$available =~ s/\.$//;
			}
		}

		if ($available) {
			foreach my $attribute (split(/\,/, $available)) {
				$attribute =~ s/^\s+//;
				$attribute =~ s/\s+$//;
				$attributes{$attribute} = '';
			}
		}
	}

	return \%attributes;
}

sub sessions {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my %_sessions;

	if ($self->driverExists($driver) != TRUE) {
		$self->{'err_string'} = "sessions(): Driver '$driver' ".
		  "is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "sessions(): Target '$target' ".
		  "is not available";
		return undef;
	}

	my $sHandle = new IO::Handle;
	my $_path = make_path(SCST_TARGETS_DIR(), $driver, $target,
			      SCST_SESSIONS);
	if (!(opendir $sHandle, $_path)) {
		$self->{'err_string'} = "sessions(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $session (readdir($sHandle)) {
		next if (($session eq '.') || ($session eq '..'));
		my $pHandle = new IO::Handle;
		my $sPath = make_path($_path, $session);
		if (!(opendir $pHandle, $sPath)) {
			$self->{'err_string'} = "sessions(): Unable to read directory '$_path': $!";
			return undef;
		}

		foreach my $attribute (readdir($pHandle)) {
			next if ($attribute eq '.' || $attribute eq '..' ||
				 $attribute eq SCST_MGMT_IO);
			my $pPath = make_path($sPath, $attribute);

			if ($attribute eq 'luns') {
				my $linked = readlink $pPath;
				my $g = SCST_GROUPS;
				my $l = SCST_LUNS;
				if ($linked =~ /\.\.\/\.\.\/$g\/(.*)\/$l/) {
					my $group = $1;
					$_sessions{$session}->{$attribute} =
					  $self->luns($driver, $target, $group);
				}
			} else {
				my $mode = (stat($pPath))[2];
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
							$self->{'err_string'} = "sessions(): Unable to read ".
							  "session attribute '$attribute': $!";
							return undef;
						}

						my $value = <$io>;
						chomp $value;

						$_sessions{$session}->{$attribute}->{'value'} = $value;
						$_sessions{$session}->{$attribute}->{'static'} = $is_static;
					}
				}
			}
		}
	}

	return \%_sessions;
}

sub closeSession {
	my $self = shift;
	my $driver = shift;
	my $target = shift;
	my $session = shift;

	my $sessions = $self->sessions($driver, $target);

	return SCST_C_NO_SESSION if (!defined($$sessions{$session}));

	# If it's not closable, silently return
	return FALSE if (!defined($$sessions{$session}->{'force_close'}));

	my $path = make_path(SCST_TARGETS_DIR(), $driver, $target,
			     SCST_SESSIONS, $session, 'force_close');

	my $io = new IO::File $path, O_WRONLY;

	my $cmd = "1";

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $cmd\n";
	} else {
		$bytes = _syswrite($io, $cmd, length($cmd));
	}

	return FALSE if ($self->{'debug'} || $bytes);
	return SCST_C_SESSION_CLOSE_FAIL;
}

sub sgvStats {
	my $self = shift;
	my %stats;

	my $sHandle = new IO::Handle;
	my $_path = SCST_SGV_DIR();
	if (!(opendir $sHandle, $_path)) {
		$self->{'err_string'} = "svgStats(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $stat (readdir($sHandle)) {
		next if (($stat eq '.') || ($stat eq '..'));

		my $sPath = make_path(SCST_SGV_DIR(), $stat);

		if (-d $sPath) {
			my $lHandle = new IO::Handle;
			if (!(opendir $lHandle, $sPath)) {
				$self->{'err_string'} = "svgStats(): Unable to read directory '$sPath': $!";
				return undef;
			}

			foreach my $lief (readdir($lHandle)) {
				my $pPath = make_path($sPath, $lief);

				my $io = new IO::File $pPath, O_RDONLY;

				if (!$io) {
					$self->{'err_string'} = "sgvStats(): Unable to read ".
					  "sgv stat '$stat/$lief': $!";
					return undef;
				}

				my $buffer;
				while (my $value = <$io>) {
					$buffer .= $value;
				}

				$stats{$stat}->{$lief} = $buffer;
			}
		} else {
			my $io = new IO::File $sPath, O_RDONLY;

			if (!$io) {
				$self->{'err_string'} = "sgvStats(): Unable to read ".
				  "sgv stat '$stat': $!";
				return undef;
			}

			my $buffer;
			while (my $value = <$io>) {
				$buffer .= $value;
			}

			$stats{$stat} = $buffer;
		}
	}

	return \%stats;
}

sub errorString {
	my $self = shift;
	my $rc = shift;

	return $VERBOSE_ERROR{$rc} if (defined($rc));
	return undef if (!$self->{'err_string'});

	my $string = $self->{'err_string'};
	$self->{'err_string'} = undef;

	return $string;
}

sub _syswrite {
	my $io = shift;
	my $cmd = shift;
	my $length = shift;
	my $now = time();

	my $res_file = SCST_QUEUE_RES_PATH();

	my $bytes = syswrite($io, $cmd, $length);

	if (!defined($bytes) && defined($res_file)) {
		if ($! == EAGAIN) {
			my $res = new IO::File $res_file, O_RDONLY;

			if (!$res) {
				cluck("FATAL: Failed opening $res_file: $!");
				return undef;
			}

			my $wait = TRUE;
			my $result;

			while ($wait && (($now + $TIMEOUT) > time())) {
				sysread($res, $result, 8);
				$wait = FALSE if ($! != EAGAIN);
				sleep 1;
			}

			if ($wait) {
				my $_cmd = $cmd; chomp $_cmd;
				cluck("Timeout while waiting for command '$_cmd' to complete");
				$bytes = undef;
			} else {
				$bytes = length($cmd) if ($result == 0);
			}

			close $res;
		} elsif ($! == EBUSY) {
			return -1;
		}
	}

	return $bytes;
}

sub make_path {
	my $path;

	foreach my $element (@_) {
		if ($path && rindex($path, '/') != length($path) - 1) {
			$path .= '/';
		}
		$path .= $element;
	}

	return $path;
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
