package SCST::SCST;

# Author:	Mark R. Buechler
# Copyright (c) 2005, 2006 Mark R. Buechler

use 5.005;
use IO::Handle;
use IO::File;
use strict;
use Carp;

my $TRUE  = 1;
my $FALSE = 0;

my $_SCST_DIR_           = '/proc/scsi_tgt';
my $_SCST_IO_            = $_SCST_DIR_.'/scsi_tgt';
my $_SCST_CDROM_IO_      = $_SCST_DIR_.'/dev_cdrom/dev_cdrom';
my $_SCST_CHANGER_IO_    = $_SCST_DIR_.'/dev_changer/dev_changer';
my $_SCST_DISK_IO_       = $_SCST_DIR_.'/dev_disk/dev_disk';
my $_SCST_DISK_FILE_IO_  = $_SCST_DIR_.'/disk_fileio/disk_fileio';
my $_SCST_CDROM_FILE_IO_ = $_SCST_DIR_.'/cdrom_fileio/cdrom_fileio';
my $_SCST_DISKP_IO_      = $_SCST_DIR_.'/dev_disk_perf/dev_disk_perf';
my $_SCST_MODISK_IO_     = $_SCST_DIR_.'/dev_modisk/dev_modisk';
my $_SCST_MODISKP_IO_    = $_SCST_DIR_.'/dev_modisk_perf/dev_modisk_perf';
my $_SCST_TAPE_IO_       = $_SCST_DIR_.'/dev_tape/dev_tape';
my $_SCST_TAPEP_IO_      = $_SCST_DIR_.'/dev_tape_perf/dev_tape_perf';
my $_SCST_GROUPS_DIR_    = $_SCST_DIR_.'/groups';
my $_SCST_SGV_STATS_     = $_SCST_DIR_.'/sgv';
my $_SCST_SESSIONS_      = $_SCST_DIR_.'/sessions';
my $_SCST_VERSION_IO_    = $_SCST_DIR_.'/version';

my $_SCST_USERS_IO_      = 'names';
my $_SCST_DEVICES_IO_    = 'devices';

my @_AVAILABLE_OPTIONS_  = ('WRITE_THROUGH', 'O_DIRECT', 'READ_ONLY', 'NULLIO', 'NV_CACHE');

use vars qw(@ISA @EXPORT $VERSION $CDROM_TYPE $CHANGER_TYPE $DISK_TYPE $DISKFILE_TYPE
            $CDROMFILE_TYPE $DISKPERF_TYPE $MODISK_TYPE $MODISKPERF_TYPE $TAPE_TYPE
            $TAPEPERF_TYPE);

$CDROM_TYPE      = 1;
$CHANGER_TYPE    = 2;
$DISK_TYPE       = 3;
$DISKFILE_TYPE   = 4;
$CDROMFILE_TYPE  = 5;
$DISKPERF_TYPE   = 6;
$MODISK_TYPE     = 7;
$MODISKPERF_TYPE = 8;
$TAPE_TYPE       = 9;
$TAPEPERF_TYPE   = 10;

$VERSION = 0.6;

my $_SCST_MIN_MAJOR_   = 0;
my $_SCST_MIN_MINOR_   = 9;
my $_SCST_MIN_RELEASE_ = 5;

my %_IO_MAP_ = ($CDROM_TYPE => $_SCST_CDROM_IO_,
		$CHANGER_TYPE => $_SCST_CHANGER_IO_,
		$DISK_TYPE => $_SCST_DISK_IO_,
		$DISKFILE_TYPE => $_SCST_DISK_FILE_IO_,
		$CDROMFILE_TYPE => $_SCST_CDROM_FILE_IO_,
		$DISKPERF_TYPE => $_SCST_DISKP_IO_,
		$MODISK_TYPE => $_SCST_MODISK_IO_,
		$MODISKPERF_TYPE => $_SCST_MODISKP_IO_,
		$TAPE_TYPE => $_SCST_TAPE_IO_,
		$TAPEPERF_TYPE => $_SCST_TAPEP_IO_);

my %_TYPE_MAP_ = ('dev_cdrom' => $CDROM_TYPE,
		  'dev_changer' => $CHANGER_TYPE,
		  'dev_disk' => $DISK_TYPE,
		  'disk_fileio' => $DISKFILE_TYPE,
		  'cdrom_fileio' => $CDROMFILE_TYPE,
		  'dev_disk_perf' => $DISKPERF_TYPE,
		  'dev_modisk' => $MODISK_TYPE,
		  'dev_modisk_perf' => $MODISKPERF_TYPE,
		  'dev_tape' => $TAPE_TYPE,
		  'dev_tape_perf' => $TAPEPERF_TYPE);

sub new {
	my $this = shift;
	my $debug = shift;
	my $badVersion = $TRUE;
	
	my $class = ref($this) || $this;
	my $self = {};

	bless($self, $class);

	$self->{'debug'} = $debug if $debug;

	my $scstVersion = $self->scstVersion();

	my($major, $minor, $release) = split(/\./, $scstVersion, 3);

	$badVersion = $FALSE if (($major > $_SCST_MIN_MAJOR_) ||
				 (($major == $_SCST_MIN_MAJOR_) && ($minor > $_SCST_MIN_MINOR_)) ||
				 (($major == $_SCST_MIN_MAJOR_) && ($minor == $_SCST_MIN_MINOR_) && ($release >= $_SCST_MIN_RELEASE_)));

	croak("This module requires at least SCST version $_SCST_MIN_MAJOR_\.$_SCST_MIN_MINOR_\.".
	      "$_SCST_MIN_RELEASE_ and version $scstVersion was found") if ($badVersion);

	return $self;
}

sub scstVersion {
	my $self = shift;

	my $io = new IO::File $_SCST_VERSION_IO_, O_RDONLY;
	return $TRUE if (!$io);

	my $version = <$io>;
	chomp $version;

	return $version;
}

sub groups {
	my $self = shift;
	my @groups;
	my $dirHandle = new IO::Handle;

	opendir $dirHandle, $_SCST_GROUPS_DIR_ or return undef;
      
	foreach my $entry (readdir($dirHandle)) {
		next if (($entry eq '.') || ($entry eq '..'));

		push @groups, $entry;
	}

	close $dirHandle;

	return \@groups;
}

sub groupExists {
	my $self = shift;
	my $group = shift;
	my $groups = $self->groups();

	foreach my $_group (@{$groups}) {
		return $TRUE if ($group eq $_group);
	}

	return $FALSE;
}

sub addGroup {
	my $self = shift;
	my $group = shift;

	return 2 if ($self->groupExists($group));

	my $io = new IO::File $_SCST_IO_, O_WRONLY;
	return $TRUE if (!$io);

	my $cmd = "add_group $group\n";

	if ($self->{'debug'}) {
		print "DBG($$): $_SCST_IO_ -> $cmd\n";
	} else {
		print $io $cmd;
	}

	close $io;

	return $FALSE if ($self->{'debug'});
	return !$self->groupExists($group);
}

sub removeGroup {
	my $self = shift;
	my $group = shift;

	return 2 if (!$self->groupExists($group));

	my $io = new IO::File $_SCST_IO_, O_WRONLY;
	return $TRUE if (!$io);

	my $cmd = "del_group $group\n";

	if ($self->{'debug'}) {
		print "DBG($$): $_SCST_IO_ -> $cmd\n";
	} else {
		print $io $cmd;
	}

	close $io;

	return $FALSE if ($self->{'debug'});
	return $self->groupExists($group);
}

sub sgvStats {
	my $self = shift;
	my $io = new IO::File $_SCST_SGV_STATS_, O_RDONLY;
	my %stats;
	my $first = $TRUE;

	return undef if (!$io);

	while (my $line = <$io>) {
		chomp $line;

		if ($first || !$line) {
			$first = $FALSE;
			next;
		}

		my $size;
		my $stat;
		my $hit;
		my $total;

		if ($line !~ /^\s/) {
			($stat, $hit, $total) = split(/\s+/, $line);

			$size = 'ALL';
			if ($stat eq 'big') {
				$total = $hit;
				$hit = -1;
			}
		} else {
			(undef, $stat, $hit, $total) = split(/\s+/, $line);

			if ($stat =~ /(\d+)K$/) {
				$size = $1;
				$stat =~ s/\-$size\K//;
			}
		}

		$stats{$stat}->{$size}->{'HITS'} = $hit;
		$stats{$stat}->{$size}->{'TOTAL'} = $total;
	}

	close $io;

	return \%stats;
}

sub sessions {
	my $self = shift;
	my $io = new IO::File $_SCST_SESSIONS_, O_RDONLY;
	my %sessions;
	my $first = $TRUE;

	return undef if (!$io);

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = $FALSE;
			next;
		}

		my($target, $user, $group, $commands) = split(/\s+/, $line);

		$sessions{$target}->{$group}->{$user} = $commands;
	}

	close $io;

	return \%sessions;
}

sub devices {
	my $self = shift;
	my $io = new IO::File $_SCST_IO_, O_RDONLY;
	my %devices;
	my $first = $TRUE;

	return undef if (!$io);

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = $FALSE;
			next;
		}

		my($vname, $handler) = split(/\s+/, $line);
		$devices{$vname} = $_TYPE_MAP_{$handler};
	}

	close $io;

	return \%devices;
}

sub handlerDevices {
	my $self = shift;
	my $handler = shift;
	my $handler_io = $_IO_MAP_{$handler};
	my $first = $TRUE;
	my %devices;

	return undef if (!$handler_io);
	return undef if (!$self->handlerExists($handler));

	my $io = new IO::File $handler_io, O_RDONLY;
	return undef if (!$io);

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = $FALSE;
			next;
		}

		my ($vname, $size, $blocksize, $options, $path) = split(/\s+/, $line);

		if ($options =~ /^\//) {
			$path = $options;
			$options = "";
		}

		$devices{$vname}->{'OPTIONS'} = $self->cleanupString($options);
		$devices{$vname}->{'SIZE'} = $self->cleanupString($size);
		$devices{$vname}->{'PATH'} = $self->cleanupString($path);
		$devices{$vname}->{'BLOCKSIZE'} = $self->cleanupString($blocksize);
	}

	close $io;

	return \%devices;
}

sub handlerDeviceExists {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $devices = $self->handlerDevices($handler);

	return -1 if (!defined($devices));
	return $TRUE if (defined($$devices{$device}));

	return $FALSE;
}

sub openDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $path = shift;
	my $options = shift;
	my $blocksize = shift;
	my $handler_io = $_IO_MAP_{$handler};

	return $TRUE if ($self->checkOptions($options));
	return $TRUE if (!$handler_io);
	return $TRUE if (!$self->handlerExists($handler));
	return 2 if ($self->handlerDeviceExists($handler, $device));

	$options = $self->cleanupString($options);

	my $cmd = "open $device $path $blocksize $options\n";

	$cmd = $self->cleanupString($cmd);

	my $rc = $self->handler_private($handler_io, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);
	return !$self->handlerDeviceExists($handler, $device);
}

sub closeDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $path = shift;
	my $handler_io = $_IO_MAP_{$handler};

	return $TRUE if (!$handler_io);
	return $TRUE if (!$self->handlerExists($handler));
	return 2 if (!$self->handlerDeviceExists($handler, $device));

	my $cmd = "close $device $path\n";

	my $rc = $self->handler_private($handler_io, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);
	return $self->handlerDeviceExists($handler, $device);
}

sub userExists {
	my $self = shift;
	my $user = shift;
	my $group = shift;

	my $users = $self->users($group);

	return -1 if (!defined($users));

	foreach my $_user (@{$users}) {
		return $TRUE if ($user eq $_user);
	}

	return $FALSE;
}

sub users {
	my $self = shift;
	my $group = shift;
	my @users;

	return undef if (!$self->groupExists($group));

	my $io = new IO::File $_SCST_GROUPS_DIR_."/$group/".$_SCST_USERS_IO_, O_RDONLY;
	return undef if (!$io);

	while (my $line = <$io>) {
		chomp $line;
		
		push @users, $line;
	}

	close $io;

	return \@users;
}

sub addUser {
	my $self = shift;
	my $user = shift;
	my $group = shift;

	return $TRUE if (!$self->groupExists($group));
	return 2 if ($self->userExists($user, $group));

	my $cmd = "add $user\n";

	my $rc = $self->group_private($group, $_SCST_USERS_IO_, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);
	return !$self->userExists($user, $group);
}

sub removeUser {
	my $self = shift;
	my $user = shift;
	my $group = shift;

	return $TRUE if (!$self->groupExists($group));
	return 2 if (!$self->userExists($user, $group));

	my $cmd = "del $user\n";

	my $rc = $self->group_private($group, $_SCST_USERS_IO_, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);
	return $self->userExists($user, $group);
}

sub clearUsers {
	my $self = shift;
	my $group = shift;

	return $TRUE if (!$self->groupExists($group));

	my $cmd = "clear\n";

	my $rc = $self->group_private($group, $_SCST_USERS_IO_, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);

	my $users = $self->users($group);

	return ($#{$users} + 1);
}

sub handlerExists {
	my $self = shift;
	my $handler = shift;
	my $handlers = $self->handlers();

	foreach my $_handler (@{$handlers}) {
		return $TRUE if ($handler eq $_handler);
	}

	return $FALSE;
}

sub handlers {
	my $self = shift;
	my @handlers;

	my $dirHandle = new IO::Handle;

	opendir $dirHandle, $_SCST_DIR_ or return undef;

	foreach my $entry (readdir($dirHandle)) {
		next if (($entry eq '.') || ($entry eq '..'));

		if ((-d $_SCST_DIR_.'/'.$entry ) && (-f $_SCST_DIR_.'/'.$entry.'/type')) {
			push @handlers, $_TYPE_MAP_{$entry} if ($_TYPE_MAP_{$entry});
		}
	}

	close $dirHandle;

	return \@handlers;
}

sub groupDeviceExists {
	my $self = shift;
	my $device = shift;
	my $group = shift;
	my $lun = shift;
	my $devices = $self->groupDevices($group);

	return -1 if (!defined($devices));

	if (defined($lun)) {
		return $TRUE if ($$devices{$device} eq $lun);
	} else {
		return $TRUE if (defined($$devices{$device}));
	}

	return $FALSE;
}

sub groupDevices {
	my $self = shift;
	my $group = shift;
	my %devices;
	my $first = $TRUE;

	return undef if (!$self->groupExists($group));

	my $io = new IO::File $_SCST_GROUPS_DIR_."/$group/".$_SCST_DEVICES_IO_, O_RDONLY;
	return undef if (!$io);

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = $FALSE;
			next;
		}

		my($vname, $lun) = split(/\s+/, $line);
		
		$devices{$vname} = $lun;
	}

	close $io;

	return \%devices;
}

sub assignDeviceToGroup {
	my $self = shift;
	my $device = shift;
	my $group = shift;
	my $lun = shift;

	return $TRUE if (!$self->groupExists($group));
	return 2 if ($self->groupDeviceExists($device, $group, $lun));

	my $cmd = "add $device $lun\n";

	my $rc = $self->group_private($group, $_SCST_DEVICES_IO_, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);
	return !$self->groupDeviceExists($device, $group, $lun);
}

sub assignDeviceToHandler {
	my $self = shift;
	my $device = shift;
	my $handler = shift;
	my $handler_io = $_IO_MAP_{$handler};
	
	return $TRUE if (!$handler_io);
	return $TRUE if (!$self->handlerExists($handler));
	return 2 if ($self->handlerDeviceExists($handler, $device));

	my $cmd = "assign $device $handler\n";

	my $rc = $self->scst_private($cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if($rc);
	return !$self->handlerDeviceExists($handler, $device);
}

sub removeDeviceFromGroup {
	my $self = shift;
	my $device = shift;
	my $group = shift;

	return $TRUE if (!$self->groupExists($group));
	return 2 if (!$self->groupDeviceExists($device, $group));

	my $cmd = "del $device\n";

	my $rc = $self->group_private($group, $_SCST_DEVICES_IO_, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);
	return $self->groupDeviceExists($device, $group);
}

sub clearGroupDevices {
	my $self = shift;
	my $group = shift;

	return $TRUE if (!$self->groupExists($group));

	my $cmd = "clear\n";

	my $rc = $self->group_private($group, $_SCST_DEVICES_IO_, $cmd);

	return $FALSE if ($self->{'debug'});
	return $rc if ($rc);

	my $devices = $self->groupDevices($group);

	return (keys %{$devices});
}

sub handler_private {
	my $self = shift;
	my $handler_io = shift;
	my $cmd = shift;

	my $io = new IO::File $handler_io, O_WRONLY;
	return $TRUE if (!$io);

	if ($self->{'debug'}) {
		print "DBG($$): '$handler_io' -> '$cmd'\n";
	} else {
		print $io "$cmd\0";
	}

	close $io;

	return $FALSE;
}

sub scst_private {
	my $self = shift;
	my $cmd = shift;

	my $io = new IO::File $_SCST_IO_, O_WRONLY;
        return $TRUE if (!$io);

	if ($self->{'debug'}) {
		print "DBG($$): '$_SCST_IO_' -> '$cmd'\n";
	} else {
		print $io "$cmd\0";
	}

	close $io;

	return $FALSE;
}

sub group_private {
	my $self = shift;
	my $group = shift;
	my $file = shift;
	my $cmd = shift;

	my $io = new IO::File $_SCST_GROUPS_DIR_."/$group/".$file, O_WRONLY;
	return $TRUE if (!$io);

	if ($self->{'debug'}) {
		print "DBG($$): $_SCST_GROUPS_DIR_/$group/$file -> $cmd\n";
	} else {
		print $io "$cmd\0";
	}

	close $io;

	return $FALSE;
}

sub checkOptions {
	my $self = shift;
	my $options = shift;

	return if (!$options);

	foreach my $option (split(/\s+/, $options)) {
		foreach my $avail (@_AVAILABLE_OPTIONS_) {
			return $FALSE if ($avail eq $option);
		}
	}

	return $TRUE;
}

sub cleanupString {
	my $self = shift;
	my $string = shift;

	$string =~ s/^\s+//;
	$string =~ s/\s+$//;

	return $string;
}

;1 __END__

=head1 NAME

SCST::SCST - Generic SCST methods.

=head1 SYNOPSIS

    use SCST::SCST;

    $p = SCST::SCST->new();
    
    print "Using SCST version".$p->scstVersion()."\n";
    
    if ($p->handlerDeviceExists($SCST::SCST::DISKFILE_TYPE)) {
         print "openDevice() failed\n"
           if ($p->openDevice($SCST::SCST::DISKFILE_TYPE, 'DISK01', '/vdisk/disk01.dsk'));
    }
    
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

=item SCST::SCST->groups();

Returns a list of security groups configured.

Arguments: void

Returns: (array ref) $groups

=item SCST::SCST->groupExists();

Checks for a specified group's existance.

Arguments: (string) $group

Returns: (boolean) $groupExists

=item SCST::SCST->addGroup();

Adds a security group to SCST's configuration. Returns 0 upon success, 1 if
unsuccessfull and  2 if the group already exists.

Arguments: (string) $group

Returns: (int) $success

=item SCST::SCST->removeGroup();

Removes a group from SCST's configuration. Returns 0 upon success, 1 if
unsuccessfull and 2 if group does not exist.

=item SCST::SCST->sgvStats();

Returns a hash of stats gathered from /proc/scsi_tgt/sgv.

Arguments: void

Returns: (hash ref) $stats

Hash Layout: See /proc/scsi_tgt/sgv for tokens. This methods simply hashes
what's found there and returns it with no further processing.

=item SCST::SCST->sessions();

Returns a hash of current SCST initiator sessions. 

Arguments: void

Returns: (hash ref) $sessions

Hash Layout: See /proc/scsi_tgt/sessions for tokens. This methods simply hashes
what's found there and returns it with no further processing.

=item SCST::SCST->devices();

Returns a hash of devices configured without regard to device handler.

Arguments: void

Returns: (hash ref) $devices

Hash Layout: (string) $device = (int) $handler

=item SCST::SCST->handlerDevices();

Returns a hash of devices configured for a specified device handler.

Arguments: (int) $handler

Returns: (hash ref) $devices

Hash Layout: (string) $device -> SIZE = (int) $deviceSize
             (string) $device -> PATH = (string) $devicePath
             (string) $device -> OPTIONS = (string) $options (comma seperated)

=item SCST::SCST->handlerDeviceExists();

Checks for a specified device is configured for a specified device handler.

Arguments: (int) $handler, (string) $device

Returns: (boolean) $deviceExists

=item SCST::SCST->openDevice();

Opens an already existing specified device for the specified device handler.
Returns 0 upon success, 1 if unsuccessfull and 2 if the device already exists.

Available options for the parameter $options are: WRITE_THROUGH, READ_ONLY, O_DIRECT

Arguments: (int) $handler, (string) $device, (string) $path [, (string) $options]

Returns: (int) $success

=item SCST::SCST->closeDevice();

Closes an open device configured for the specified device handler. Returns
0 upon success, 1 if unsuccessfull and 2 of the device does not exist.

Arguments: (int) $handler, (string) $device, (string) $path

Returns: (int) $success

=item SCST::SCST->userExists();

Checks for a specified user with the specified security group.

Arguments: (string) $user, (string) $group

Returns (boolean) $userExists

=item SCST::SCST->users();

Returns a list of users configured for a given security group.

Arguments: (string) $group

Returns: (hash ref) $users

=item SCST::SCST->addUser();

Adds the specified user to the specified security group. Returns 0
upon success, 1 if unsuccessfull and 2 if the user already exists.

Arguments: (string) $user, (string) $group

Returns: (int) $success

=item SCST::SCST->removeUser();

Removed the specified user from the specified security group. Returns
0 upon success, 1 if unsuccessfull and 2 if the user does not exist.

Arguments: (string) $user, (string) $group

Returns: (int) $success

=item SCST::SCST->clearUsers();

Removes all users from the specified security group. Returns 0 upon
success or 1 if unsuccessfull.

Arguments: (string) $group

Returns: (int) $success

=item SCST::SCST->handlerExists();

Checks if a specified device handler exists within SCST's configuration.

Arguments: (int) $handler

Returns: (boolean) $handlerExists

=item SCST::SCST->handlers();

Returns a list of configured device handlers.

Arguments: void

Returns: (array ref) $handlers

=item SCST::SCST->groupDeviceExists();

Checks if a specified device is assigned to a specified security group.
If the optional $lun argument is specified, this method also matches
the lun.

Arguments: (string) $device, (string) $group [, (int) $lun]

Returns: (boolean) $deviceExists

=item SCST::SCST->groupDevices();

Returns a hash if devices assigned to the specified security group.

Arguments: (string) $group

Returns: (hash ref) $devices

Hash Layout: (string) $device = (int) $lun

=item SCST::SCST->assignDeviceToGroup();

Assigns the specified device to the specified security group. Returns
0 upon success, 1 if unsuccessfull and 2 if the device has already
been assigned to the specified security group.

Arguments: (string) $device, (string) $group, (int) $lun

Returns: (int) $success

=item SCST::SCST->assignDeviceToHandler();

Assigns specified device to specified handler. Returns 0 upon success,
1 if unsuccessfull and 2 if the specified device is already assigned to
the specified handler.

Arguments: (string) $device, (string) $handler

Returns: (int) $success

=item SCST::SCST->removeDeviceFromGroup();

Removes the specified device from the specified security group. Returns
0 upon success, 1 if unsuccessfull and 2 if the device has not been
assigned to the specified security group.

Arguments: (string) $device, (string) $group

Returns: (int) $success

=item SCST::SCST->clearGroupDevices();

Removes all devices from the specified security group. Returns 0 upon
success or 1 if unsuccessfull.

Arguments: (string) $group

Returns: (int) $success

=back

=head1 WARNING

None at this time.

=head1 NOTES

If the $debug parameter is specified on package new(), no actions are 
performed. Rather they are printed to STDOUT and 0 is returned.

Available Device Handlers:

CDROM_TYPE,
CHANGER_TYPE,
DISK_TYPE,
DISKFILE_TYPE,
CDROMFILE_TYPE,
DISKPERF_TYPE,
MODISK_TYPE,
MODISKPERF_TYPE,
TAPE_TYPE,
TAPEPERF_TYPE

To specify a device handler to a method, use the following syntax:

$SCST::SCST::<handler type>

For example:

$SCST::SCST::MODISK_TYPE

=cut
