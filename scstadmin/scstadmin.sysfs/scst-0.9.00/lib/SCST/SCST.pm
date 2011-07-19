package SCST::SCST;

# Author:	Mark R. Buechler
# License:	GPLv2
# Copyright (c) 2005-2010 Mark R. Buechler

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

SCST_ROOT        => '/sys/kernel/scst_tgt',

# Root-level
SCST_HANDLERS    => 'handlers',
SCST_DEVICES     => 'devices',
SCST_TARGETS     => 'targets',
SCST_SGV         => 'sgv',
SCST_QUEUE_RES   => 'last_sysfs_mgmt_res',

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
);

use vars qw(@ISA @EXPORT $VERSION);

use vars qw($TGT_TYPE_HARDWARE $TGT_TYPE_VIRTUAL);

$VERSION = 0.9.00;

$TGT_TYPE_HARDWARE = 1;
$TGT_TYPE_VIRTUAL  = 2;

my $TIMEOUT = 300; # Command execution timeout

my $_SCST_MIN_MAJOR_   = 2;
my $_SCST_MIN_MINOR_   = 0;
my $_SCST_MIN_RELEASE_ = 0;

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
	my $_path = mkpath(SCST_ROOT); 
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "scstAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $attribute (readdir($pHandle)) {
		next if (($attribute eq '.') || ($attribute eq '..'));
		my $pPath = mkpath(SCST_ROOT, $attribute);
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
				$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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

	my $path = mkpath(SCST_ROOT, $attribute);

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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS);
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "drivers(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $driver (readdir($dHandle)) {
		next if (($driver eq '.') || ($driver eq '..'));

		if (-d mkpath(SCST_ROOT, SCST_TARGETS, $driver)) {
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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver);
	if (!(opendir $tHandle, $_path)) {
		$self->{'err_string'} = "targets(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $target (readdir($tHandle)) {
		next if (($target eq '.') || ($target eq '..'));

		if (-d mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target)) {
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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS);
	if (!(opendir $gHandle, $_path)) {
		$self->{'err_string'} = "groups(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $group (readdir($gHandle)) {
		next if (($group eq '.') || ($group eq '..'));

		if (-d mkpath(SCST_ROOT, SCST_TARGETS, $driver,
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
		$self->{'err_string'} = "groups(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "groups(): Target '$target' is not available";
		return undef;
	}

	if ($self->groupExists($driver, $target, $group) != TRUE) {
		$self->{'err_string'} = "initiators(): Group '$group' does not exist";
		return undef;
	}

	my $iHandle = new IO::Handle;
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
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
		$self->{'err_string'} = "groups(): Driver '$driver' is not available";
		return undef;
	}

	if ($self->targetExists($driver, $target) != TRUE) {
		$self->{'err_string'} = "groups(): Target '$target' is not available";
		return undef;
	}

	my $_path;

	if ($group) {
		if ($self->groupExists($driver, $target, $group) != TRUE) {
			$self->{'err_string'} = "initiators(): Group '$group' does not exist";
			return undef;
		}

		$_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, SCST_LUNS);
	} else {
		$_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_LUNS);
	}

	my $lHandle = new IO::Handle;

	if (!(opendir $lHandle, $_path)) {
		$self->{'err_string'} = "luns(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $lun (readdir($lHandle)) {
		next if (($lun eq '.') || ($lun eq '..'));

		my $lPath = mkpath($_path, $lun);

		if (-d $lPath) {
			my $_lHandle = new IO::Handle;

			if (!(opendir $_lHandle, $lPath)) {
				$self->{'err_string'} = "luns(): Unable to read directory '$lPath': $!";
				return undef;
			}

			foreach my $attribute (readdir($_lHandle)) {
				my $pPath = mkpath($lPath, $attribute);

				if (-l $pPath) {
					my $linked = readlink($pPath);

					my $d = SCST_DEVICES;

					if ($linked =~ /.*\/$d\/(.*)/) {
						$luns{$lun} = $1;
					}
				}
			}
		}
	}

	close $lHandle;

	return \%luns;
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

	my $io = new IO::File mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO), O_RDONLY;

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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DRV_ADDATTR_FAIL if (!$io);

	my $cmd = "add_attribute $attribute $value\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DRV_REMATTR_FAIL if (!$io);

	my $cmd = "del_attribute $attribute $value\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return FALSE if (!defined($io));
	return TRUE;
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_ADD_FAIL if (!$io);

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
	my $cmd = "add_target $target $o_string\n";
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

	my $io = new IO::File mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO), O_RDONLY;

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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_ADDATTR_FAIL if (!$io);

	my $cmd = "add_target_attribute $target $attribute $value\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_REMATTR_FAIL if (!$io);

	my $cmd = "del_target_attribute $target $attribute $value\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_REM_FAIL if (!$io);

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

	my $cmd = "del_target $target\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target,
	  SCST_GROUPS, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_ADD_FAIL if (!$io);

	my $cmd = "create $group\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target,
	  SCST_GROUPS, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_REM_FAIL if (!$io);

	my $cmd = "del $group\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
	  $group, SCST_INITIATORS, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_ADD_INI_FAIL if (!$io);

	my $cmd = "add $initiator\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
	  $group, SCST_INITIATORS, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_REM_INI_FAIL if (!$io);

	my $cmd = "del $initiator\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
	  $from, SCST_INITIATORS, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_MOV_INI_FAIL if (!$io);

	my $cmd = "move $initiator $to\n";
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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
	  $group, SCST_INITIATORS, SCST_MGMT_IO);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_CLR_INI_FAIL if (!$io);

	my $cmd = "clear\n";
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

	my $err  = SCST_C_TGT_ADD_LUN_FAIL;
	my $err2 = SCST_C_TGT_LUN_EXISTS;

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

	my $path;

	if ($group) {
		$rc = $self->groupExists($driver, $target, $group);
		return SCST_C_GRP_NO_GROUP if (!$rc);
		return $rc if ($rc > 1);

		$err  = SCST_C_GRP_ADD_LUN_FAIL;
		$err2 = SCST_C_GRP_LUN_EXISTS;

		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, SCST_LUNS, SCST_MGMT_IO);
	} else {
		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_LUNS, SCST_MGMT_IO);
	}

	return $err if (!defined($lun));

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return $err2 if ($rc == TRUE);
	return $rc if ($rc > 1);

	my $io = new IO::File $path, O_WRONLY;

	return $err if (!$io);

	my $o_string;
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value; ";
	}

	$o_string =~ s/\s$//;
	my $cmd = "add $device $lun $o_string\n";

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

	my $err  = SCST_C_TGT_ADD_LUN_FAIL;
	my $err2 = SCST_C_TGT_NO_LUN;

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

		$err  = SCST_C_GRP_REM_LUN_FAIL;
		$err2 = SCST_C_GRP_NO_LUN;

		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, SCST_LUNS, SCST_MGMT_IO);
	} else {
		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_LUNS, SCST_MGMT_IO);
	}

	return $err if (!defined($lun));

	$rc = $self->lunExists($driver, $target, $lun, $group);
	return $err2 if (!$rc);
	return $rc if ($rc > 1);

	my $io = new IO::File $path, O_WRONLY;

	return $err if (!$io);

	my $cmd = "del $lun\n";
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

	my $err = SCST_C_TGT_NO_LUN;

	return TRUE if (!defined($lun));

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

		$err = SCST_C_GRP_NO_LUN;

		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, SCST_LUNS, SCST_MGMT_IO);
	} else {
		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_LUNS, SCST_MGMT_IO);
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

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_LUN_RPL_DEV_FAIL if (!$io);

	my $o_string;
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value; ";
	}

	$o_string =~ s/\s$//;
	my $cmd = "replace $device $lun $o_string\n";
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

	my $err = SCST_C_TGT_CLR_LUN_FAIL;

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

		$err = SCST_C_GRP_CLR_LUN_FAIL;

		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, SCST_LUNS, SCST_MGMT_IO);
	} else {
		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_LUNS, SCST_MGMT_IO);
	}

	my $io = new IO::File $path, O_WRONLY;

	return $err if (!$io);

	my $cmd = "clear\n";
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

sub devices {
	my $self = shift;
	my @devices;

	my $dHandle = new IO::Handle;
	my $_path = mkpath(SCST_ROOT, SCST_DEVICES);
	if (!(opendir $dHandle, $_path)) {
		$self->{'err_string'} = "devices(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $device (readdir($dHandle)) {
		next if (($device eq '.') || ($device eq '..'));

                if (-d mkpath(SCST_ROOT, SCST_DEVICES, $device)) {
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
	my $_path = mkpath(SCST_ROOT, SCST_DEVICES, $device); 
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "deviceAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $attribute (readdir($pHandle)) {
		next if (($attribute eq '.') || ($attribute eq '..'));
		my $pPath = mkpath(SCST_ROOT, SCST_DEVICES, $device, $attribute);
		my $mode = (stat($pPath))[2];

		if ($attribute eq 'exported') {
			my $eHandle = new IO::Handle;
			opendir $eHandle, mkpath(SCST_ROOT, SCST_DEVICES,
			  $device, $attribute);

			foreach my $export (readdir($eHandle)) {
				next if (($export eq '.') || ($export eq '..'));

				my $linked = readlink mkpath($pPath, $export);

				my $t = SCST_TARGETS;
				my $g = SCST_GROUPS;
				my $l = SCST_LUNS;

				if ($linked =~ /\.\.\/\.\.\/$t\/(.+)\/(.+)\/$g\/(.+)\/$l\/(\d+)/) {
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

			my $h = SCST_HANDLERS;

			if ($linked =~ /\.\.\/\.\.\/$h\/(.*)/) {
				my $handler = $1;
				$attributes{$attribute}->{'static'} = TRUE;
				$attributes{$attribute}->{'value'} = $handler;
			}
		} elsif ($attribute eq 'scsi_device') {
			my $linked = readlink $pPath;

			$linked =~ s/^\.\.\/\.\.\/\.\.\/\.\.\//\/sys\//;

			$attributes{$attribute}->{'static'} = TRUE;
			$attributes{$attribute}->{'value'} = $linked;
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
					$self->{'err_string'} = "deviceAttributes(): Unable to read ".
					  "device attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver); 
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "driverAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $attribute (readdir($pHandle)) {
		next if (($attribute eq '.') || ($attribute eq '..'));
		my $pPath = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $attribute);
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
				$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $attribute);

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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target); 
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "targetAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $attribute (readdir($pHandle)) {
		next if (($attribute eq '.') || ($attribute eq '..'));
		my $pPath = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, $attribute);
		my $mode = (stat($pPath))[2];

		if ($attribute eq 'host') {
			my $linked = readlink($pPath);

			$linked =~ s/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\//\/sys\//;

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
					$self->{'err_string'} = "targetAttributes(): Unable to read ".
					  "target attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_TGT_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS, $group); 
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "groupAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $attribute (readdir($pHandle)) {
		next if (($attribute eq '.') || ($attribute eq '..'));
		my $pPath = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, $attribute);
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
					$self->{'err_string'} = "groupAttributes(): Unable to read ".
					  "group attribute '$attribute': $!";
					return undef;
				}

				my $value = <$io>;
				chomp $value;

				my $is_key = <$io>;
				$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
	   $group, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_GRP_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
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

	my $_path;

	if ($group) {
		if ($self->groupExists($driver, $target, $group) != TRUE) {
			$self->{'err_string'} = "lunAttributes(): Group '$group' does not exist";
			return undef;
		}

		$_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, SCST_LUNS, $lun); 
	} else {
		$_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_LUNS, $lun); 
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
		next if (($attribute eq '.') || ($attribute eq '..'));
		my $pPath = mkpath($_path, $attribute);
		my $mode = (stat($pPath))[2];

		if ($attribute eq 'device') {
			my $linked = readlink($pPath);

			my $r = SCST_ROOT;

			$linked =~ s/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\//\/$r\//;
			$linked =~ s/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\//\/$r\//;
			$linked =~ s/^\/+/\//;

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
				$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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

		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		   $group, SCST_LUNS, $lun, $attribute);
	} else {
		$path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_LUNS, $lun, $attribute);
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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
	  $group, SCST_INITIATORS, $initiator); 
	if (!(opendir $pHandle, $_path)) {
		$self->{'err_string'} = "initiatorAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $attribute (readdir($pHandle)) {
		next if (($attribute eq '.') || ($attribute eq '..'));
		my $pPath = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
		  $group, SCST_INITIATORS, $initiator, $attribute);
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
				$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_GROUPS,
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

sub handlers {
	my $self = shift;
	my @handlers;

	my $hHandle = new IO::Handle;
	my $_path = mkpath(SCST_ROOT, SCST_HANDLERS);
	if (!(opendir $hHandle, $_path)) {
		$self->{'err_string'} = "handlers(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $handler (readdir($hHandle)) {
		next if (($handler eq '.') || ($handler eq '..'));

		if (-d mkpath(SCST_ROOT, SCST_HANDLERS, $handler)) {
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

	my $path = mkpath(SCST_ROOT, SCST_HANDLERS, $handler, $attribute);

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

	my $hHandle = new IO::Handle;
	my $_path = mkpath(SCST_ROOT, SCST_HANDLERS, $handler);
	if (!(opendir $hHandle, $_path)) {
		$self->{'err_string'} = "handlerAttributes(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $attribute (readdir($hHandle)) {
		next if (($attribute eq '.') || ($attribute eq '..'));
		next if ($attribute eq SCST_MGMT_IO);
		my $pPath = mkpath(SCST_ROOT, SCST_HANDLERS, $handler, $attribute);
		my $mode = (stat($pPath))[2];

		if (-d $pPath) {
			push @{$attributes{'devices'}->{'value'}}, $attribute;
			next;
		}

		my $is_static;
		if (($mode & S_IWUSR) >> 6) {
			$is_static = FALSE;
		} else {
			$is_static = TRUE;
		}

		my $path = mkpath(SCST_ROOT, SCST_HANDLERS, $handler, $attribute);

		my $io = new IO::File $path, O_RDONLY;

		if (!$io) {
			$self->{'err_string'} = "handlerAttributes(): Unable to read handler attribute ".
			  "'$attribute': $!";
			return undef;
		}

		my $value = <$io>;
		chomp $value;

		my $is_key = <$io>;
		$is_key = ($is_key =~ /\[key\]/) ? TRUE : FALSE;

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

	my $io = new IO::File mkpath(SCST_ROOT, SCST_HANDLERS, $handler, SCST_MGMT_IO), O_RDONLY;

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

	my $io = new IO::File mkpath(SCST_ROOT, SCST_HANDLERS, $handler, SCST_MGMT_IO), O_WRONLY;

	if (!$io) {
		$self->{'err_string'} = "openDevice(): Unable to open mgmt interface for ".
		  "handler '$handler': $!";
		return SCST_C_FATAL_ERROR;
	}

	$rc = $self->handlerDeviceExists($handler, $device);
	return SCST_C_DEV_EXISTS if ($rc == TRUE);
	return $rc if ($rc > 1);

	my $o_string;
	foreach my $attribute (keys %{$attributes}) {
		my $value = $$attributes{$attribute};
		$o_string .= "$attribute=$value; ";
	}

	$o_string =~ s/\s$//;
	my $cmd = "add_device $device $o_string\n";

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

	my $io = new IO::File mkpath(SCST_ROOT, SCST_HANDLERS, $handler, SCST_MGMT_IO), O_WRONLY;

	if (!$io) {
		$self->{'err_string'} = "closeDevice(): Unable to open mgmt interface for handler ".
		  "'$handler': $!";
		return SCST_C_FATAL_ERROR;
	}

	$rc = $self->handlerDeviceExists($handler, $device);
	return SCST_C_DEV_NO_DEVICE if ($rc != TRUE);
	return $rc if ($rc > 1);

	my $cmd = "del_device $device\n";

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

	my $path = mkpath(SCST_ROOT, SCST_DEVICES, $device, $attribute);

	my $io = new IO::File $path, O_WRONLY;

	return SCST_C_DEV_SETATTR_FAIL if (!$io);

	my $bytes;

	if ($self->{'debug'}) {
		print "DBG($$): $path -> $attribute = $value\n";
	} else {
		$bytes = _syswrite($io, $value, length($value));
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

	my $io = new IO::File mkpath(SCST_ROOT, SCST_TARGETS, $driver, SCST_MGMT_IO), O_RDONLY;

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

	if ($group) {
		if ($self->groupExists($driver, $target, $group) != TRUE) {
			$self->{'err_string'} = "lunCreateAttributes(): Group '$group' ".
			  "does not exist";
			return undef;
		}

		$_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target,
		  SCST_GROUPS, $group, SCST_LUNS, SCST_MGMT_IO), O_RDONLY;
	} else {
		$_path =  mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target,
		  SCST_LUNS, SCST_MGMT_IO), O_RDONLY;
	}

	my $io = new IO::File $_path;

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

	my $io = new IO::File mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target,
	  SCST_GROUPS, $group, SCST_INITIATORS, SCST_MGMT_IO), O_RDONLY;

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
	my $_path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_SESSIONS); 
	if (!(opendir $sHandle, $_path)) {
		$self->{'err_string'} = "sessions(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $session (readdir($sHandle)) {
		next if (($session eq '.') || ($session eq '..'));
		my $pHandle = new IO::Handle;
		my $sPath = mkpath($_path, $session);
		if (!(opendir $pHandle, $sPath)) {
			$self->{'err_string'} = "sessions(): Unable to read directory '$_path': $!";
			return undef;
		}

		foreach my $attribute (readdir($pHandle)) {
			next if (($attribute eq '.') || ($attribute eq '..'));
			my $pPath = mkpath($sPath, $attribute);

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

	my $path = mkpath(SCST_ROOT, SCST_TARGETS, $driver, $target, SCST_SESSIONS, $session, 'force_close'); 

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
	my $_path = mkpath(SCST_ROOT, SCST_SGV);
	if (!(opendir $sHandle, $_path)) {
		$self->{'err_string'} = "svgStats(): Unable to read directory '$_path': $!";
		return undef;
	}

	foreach my $stat (readdir($sHandle)) {
		next if (($stat eq '.') || ($stat eq '..'));

		my $sPath = mkpath(SCST_ROOT, SCST_SGV, $stat);

		if (-d $sPath) {
			my $lHandle = new IO::Handle;
			if (!(opendir $lHandle, $sPath)) {
				$self->{'err_string'} = "svgStats(): Unable to read directory '$sPath': $!";
				return undef;
			}

			foreach my $lief (readdir($lHandle)) {
				my $pPath = mkpath($sPath, $lief);

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

	my $res_file =  mkpath(SCST_ROOT, SCST_QUEUE_RES);

	my $bytes = syswrite($io, $cmd, $length);

	if (!defined($bytes)) {
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

sub mkpath {
	my $path;

	foreach my $element (@_) {
		$path .= "/$element";
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
