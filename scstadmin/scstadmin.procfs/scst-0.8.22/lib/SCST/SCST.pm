package SCST::SCST;

# Author:	Mark R. Buechler
# License:	GPLv2
# Copyright (c) 2005-2009 Mark R. Buechler

use 5.005;
use IO::Handle;
use IO::File;
use strict;
use Carp qw(cluck);

my $_SCST_DIR_           = '/proc/scsi_tgt';
my $_SCST_IO_            = $_SCST_DIR_.'/scsi_tgt';
my $_SCST_VDISK_IO_      = $_SCST_DIR_.'/vdisk/vdisk';
my $_SCST_VCDROM_IO_     = $_SCST_DIR_.'/vcdrom/vcdrom';
my $_SCST_GROUPS_DIR_    = $_SCST_DIR_.'/groups';
my $_SCST_SGV_STATS_     = $_SCST_DIR_.'/sgv';
my $_SCST_SESSIONS_      = $_SCST_DIR_.'/sessions';
my $_SCST_VERSION_IO_    = $_SCST_DIR_.'/version';

my $_SCST_USERS_IO_      = 'names';
my $_SCST_DEVICES_IO_    = 'devices';

use vars qw(@ISA @EXPORT $VERSION $CDROM_TYPE $CHANGER_TYPE $DISK_TYPE $VDISK_TYPE
            $VCDROM_TYPE $DISKPERF_TYPE $MODISK_TYPE $MODISKPERF_TYPE $TAPE_TYPE
            $TAPEPERF_TYPE $PROCESSOR_TYPE $IOTYPE_PHYSICAL $IOTYPE_VIRTUAL
            $IOTYPE_PERFORMANCE);

$CDROM_TYPE         = 1;
$CHANGER_TYPE       = 2;
$DISK_TYPE          = 3;
$VDISK_TYPE         = 4;
$VCDROM_TYPE        = 5;
$DISKPERF_TYPE      = 6;
$MODISK_TYPE        = 7;
$MODISKPERF_TYPE    = 8;
$TAPE_TYPE          = 9;
$TAPEPERF_TYPE      = 10;
$PROCESSOR_TYPE     = 11;

$IOTYPE_PHYSICAL    = 100;
$IOTYPE_VIRTUAL     = 101;
$IOTYPE_PERFORMANCE = 102;

$VERSION = '0.8.22';

my $_SCST_MIN_MAJOR_   = 2;
my $_SCST_MIN_MINOR_   = 0;
my $_SCST_MIN_RELEASE_ = 0;

my %_IO_MAP_ = ($VDISK_TYPE => $_SCST_VDISK_IO_,
		$VCDROM_TYPE => $_SCST_VCDROM_IO_);

my %_TYPE_MAP_ = ('dev_cdrom' => $CDROM_TYPE,
		  'dev_changer' => $CHANGER_TYPE,
		  'dev_disk' => $DISK_TYPE,
		  'vdisk' => $VDISK_TYPE,
		  'vcdrom' => $VCDROM_TYPE,
		  'dev_disk_perf' => $DISKPERF_TYPE,
		  'dev_modisk' => $MODISK_TYPE,
		  'dev_modisk_perf' => $MODISKPERF_TYPE,
		  'dev_tape' => $TAPE_TYPE,
		  'dev_tape_perf' => $TAPEPERF_TYPE,
		  'dev_processor' => $PROCESSOR_TYPE);

my %_REVERSE_MAP_ = ($CDROM_TYPE => 'dev_cdrom',
		     $CHANGER_TYPE => 'dev_changer',
		     $DISK_TYPE => 'dev_disk',
		     $VDISK_TYPE => 'vdisk',
		     $VCDROM_TYPE => 'vcdrom',
		     $DISKPERF_TYPE => 'dev_disk_perf',
		     $MODISK_TYPE => 'dev_modisk',
		     $MODISKPERF_TYPE => 'dev_modisk_perf',
		     $TAPE_TYPE => 'dev_tape',
		     $TAPEPERF_TYPE => 'dev_tape_perf',
		     $PROCESSOR_TYPE => 'dev_processor');

my %_IO_TYPES_ = ($CDROM_TYPE => $IOTYPE_PHYSICAL,
		  $CHANGER_TYPE => $IOTYPE_PHYSICAL,
		  $DISK_TYPE => $IOTYPE_PHYSICAL,
		  $VDISK_TYPE => $IOTYPE_VIRTUAL,
		  $VCDROM_TYPE => $IOTYPE_VIRTUAL,
		  $DISKPERF_TYPE => $IOTYPE_PERFORMANCE,
		  $MODISK_TYPE => $IOTYPE_PHYSICAL,
		  $MODISKPERF_TYPE => $IOTYPE_PERFORMANCE,
		  $TAPE_TYPE => $IOTYPE_PHYSICAL,
		  $TAPEPERF_TYPE => $IOTYPE_PERFORMANCE,
		  $PROCESSOR_TYPE => $IOTYPE_PHYSICAL);

my %_HANDLER_ALIASES_ = ('vdisk_blk'     => 'vdisk',
			 'vdisk_fileio'  => 'vdisk',
			 'vdisk_blockio' => 'vdisk',
			 'vdisk_nullio'  => 'vdisk');

my %_OPEN_OPTIONS_ = ('WRITE_THROUGH' => 'WRITE_THROUGH',
		      'WT'	      => 'WRITE_THROUGH',
		      'O_DIRECT'      => 'O_DIRECT',
	 	      'DR'	      => 'O_DIRECT',
		      'READ_ONLY'     => 'READ_ONLY',
		      'RO'	      => 'READ_ONLY',
		      'NULLIO'        => 'NULLIO',
		      'NIO'	      => 'NULLIO',
		      'NV_CACHE'      => 'NV_CACHE',
		      'NV'            => 'NV_CACHE',
		      'BLOCKIO'       => 'BLOCKIO',
		      'BIO'           => 'BLOCKIO',
		      'REMOVABLE'     => 'REMOVABLE',
		      'RM'	      => 'REMOVABLE');

my %_ASSIGN_OPTIONS_ = ('READ_ONLY'   => 'READ_ONLY',
			'RO'          => 'READ_ONLY');

my %_OPTIONS_BY_TYPE_ = ('OPEN',      => \%_OPEN_OPTIONS_,
			 'ASSIGN'     => \%_ASSIGN_OPTIONS_);

sub new {
	my $this = shift;
	my $debug = shift;
	my $badVersion = 1;
	
	my $class = ref($this) || $this;
	my $self = {};

	bless($self, $class);

	$self->{'debug'} = $debug;

	my $scstVersion = $self->scstVersion();

	die("Failed to obtain SCST version information. Is the scst module loaded?\n")
	  if ($scstVersion == -1);

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

	my $io = new IO::File $_SCST_VERSION_IO_, O_RDONLY;
	return -1 if (!$io);

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
		return 1 if ($group eq $_group);
	}

	return 0;
}

sub addGroup {
	my $self = shift;
	my $group = shift;

	return 2 if ($self->groupExists($group));

	my $io = new IO::File $_SCST_IO_, O_WRONLY;

	if (!$io) {
		$self->{'error'} = "addGroup(): Failed to open handler IO '$_SCST_IO_'";
		return 1;
	}

	my $cmd = "add_group $group\n";

	if ($self->{'debug'}) {
		print "DBG($$): $_SCST_IO_ -> $cmd\n";
	} else {
		print $io $cmd;
	}

	close $io;

	return 0 if ($self->{'debug'});
	return !$self->groupExists($group);
}

sub removeGroup {
	my $self = shift;
	my $group = shift;

	return 2 if (!$self->groupExists($group));

	my $io = new IO::File $_SCST_IO_, O_WRONLY;

	if (!$io) {
		$self->{'error'} = "removeGroup(): Failed to open handler IO '$_SCST_IO_'";
		return 1;
	}

	my $cmd = "del_group $group\n";

	if ($self->{'debug'}) {
		print "DBG($$): $_SCST_IO_ -> $cmd\n";
	} else {
		print $io $cmd;
	}

	close $io;

	return 0 if ($self->{'debug'});
	return $self->groupExists($group);
}

sub renameGroup {
	my $self = shift;
	my $oldName = shift;
	my $newName = shift;

	if (!$self->groupExists($oldName)) {
		$self->{'error'} = "renameGroup(): Group '$oldName' doesn't exist";
		return 1;
	}

	return 2 if ($self->groupExists($newName));

	my $io = new IO::File $_SCST_IO_, O_WRONLY;

	if (!$io) {
		$self->{'error'} = "renameGroup(): Failed to open handler IO '$_SCST_IO_'";
		return 1;
	}

	my $cmd = "rename_group $oldName $newName\n";

	if ($self->{'debug'}) {
		print "DBG($$): $_SCST_IO_ -> $cmd\n";
	} else {
		print $io $cmd;
	}

	close $io;

	return 0 if ($self->{'debug'});
	return !$self->groupExists($newName);
}

sub sgvStats {
	my $self = shift;
	my $io = new IO::File $_SCST_SGV_STATS_, O_RDONLY;
	my %stats;
	my $first = 1;

	if (!$io) {
		$self->{'error'} = "sgvStats(): Failed to open handler IO '$_SCST_IO_'";
		return undef;
	}

	while (my $line = <$io>) {
		chomp $line;

		if ($first || !$line) {
			$first = 0;
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
	my $first = 1;

	if (!$io) {
		$self->{'error'} = "sessions(): Failed to open handler IO '$_SCST_IO_'";
		return undef;
	}

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = 0;
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
	my $first = 1;

	if (!$io) {
		$self->{'error'} = "devices(): Failed to open handler IO '$_SCST_IO_'";
		return undef;
	}

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = 0;
			next;
		}

		my($vname, $handler) = split(/\s+/, $line);

		$handler = $_HANDLER_ALIASES_{$handler} if ($_HANDLER_ALIASES_{$handler});
		$devices{$vname} = $_TYPE_MAP_{$handler};
	}

	close $io;

	return \%devices;
}

sub handlerDevices {
	my $self = shift;
	my $handler = shift;
	my $handler_io = $_IO_MAP_{$handler};
	my $first = 1;
	my $handler_name = $_REVERSE_MAP_{$handler};
	my %devices;

	if (!$handler_io) {
		$self->{'error'} = "handlerDevices(): Failed to open handler IO '$handler_io'".
		  " or handler '$handler_name' ($handler) invalid";
		return undef;
	}

	if (!$self->handlerExists($handler)) {
		$self->{'error'} = "handlerDevices(): Handler '$handler_name' ($handler) does not exist";
		return undef;
	}

	my $io = new IO::File $handler_io, O_RDONLY;

	if (!$io) {
		print "\nWARNING: handlerDevices(): Failed to open handler IO $handler_io, assuming disabled.\n\n";
		return \%devices; # Return an empty hash
	}

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = 0;
			next;
		}

		my ($vname, $size, $blocksize, $options, $path, $t10_id) =
		  ($line =~ '(\S+)\s+(\S+)\s+(\S+)\s+(.*?)\s+(/\S+)\s+(.*)$');

		$t10_id = cleanupString($t10_id);

		if ($options =~ /^\//) {
			$t10_id = $path;
			$path = $options;
			$options = "";
		}

		if ($t10_id =~ /^\//) {
			$options .= " ".$path;
			$path = $t10_id;
			$t10_id = "";
		}

		my $options_t;
		foreach my $option (split(/\s/, cleanupString($options))) {
			if (defined($_OPEN_OPTIONS_{$option})) {
				$options_t .= $_OPEN_OPTIONS_{$option}.',';
			} else {
				cluck("WARNING: Unknown option '$option', please update your SCST version");
			}
		}

		$options_t =~ s/\,$//;

		$devices{$vname}->{'OPTIONS'} = $options_t;

		$devices{$vname}->{'SIZE'} = cleanupString($size);
		$devices{$vname}->{'PATH'} = cleanupString($path);
		$devices{$vname}->{'BLOCKSIZE'} = cleanupString($blocksize);
		$devices{$vname}->{'T10_DEVICE_ID'} = $t10_id;
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
	return 1 if (defined($$devices{$device}));

	return 0;
}

sub handlerType {
	my $self = shift;
	my $handler = shift;
	my $type = $_IO_TYPES_{$handler};
	my $handler_name = $_REVERSE_MAP_{$handler};

	if (!$type) {
		$self->{'error'} = "handlerType(): Handler type for handler '$handler_name'".
		  " ($handler) not defined";
		return undef;
	}

	return $type;
}

sub openDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $path = shift;
	my $options = shift;
	my $blocksize = shift;
	my $handler_io = $_IO_MAP_{$handler};
	my $handler_name = $_REVERSE_MAP_{$handler};
	my $valid_opts;

	($options, $valid_opts) = $self->checkOptions($options, 'OPEN');

	if (!$valid_opts) {
		$self->{'error'} = "openDevice(): Invalid option(s) '$options' given for device '$device'";
		return 1;
	}

	if (!$handler_io) {
		$self->{'error'} = "openDevice(): Failed to open handler IO '$handler_io' or ".
		  "handler '$handler_name' ($handler) invalid";
		return 1;
	}

	if (!$self->handlerExists($handler)) {
		$self->{'error'} = "openDevice(): Handler '$handler_name' ($handler) does not exist";
		return 1;
	}

	if ($self->handlerDeviceExists($handler, $device)) {
		$self->{'error'} = "openDevice(): Device '$device' is already open";
		return 2;
	}

	$options = cleanupString($options);
	$options =~ s/,/ /g;

	my $cmd = "open $device $path $blocksize $options\n";

	$cmd = cleanupString($cmd);

	my $rc = $self->handler_private($handler_io, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = !$self->handlerDeviceExists($handler, $device);

	if ($rc) {
		$self->{'error'} = "openDevice(): An error occured while opening device '$device'. ".
		  "See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub closeDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $path = shift;
	my $handler_io = $_IO_MAP_{$handler};
	my $handler_name = $_REVERSE_MAP_{$handler};

	if (!$handler_io) {
		$self->{'error'} = "closeDevice(): Failed to open handler IO '$handler_io'".
		  " or handler '$handler_name' ($handler) invalid";
		return 1;
	}

	if (!$self->handlerExists($handler)) {
		$self->{'error'} = "closeDevice(): Handler '$handler_name' ($handler) does not exist";
		return 1;
	}

	if (!$self->handlerDeviceExists($handler, $device)) {
		$self->{'error'} = "closeDevice(): Device '$device' is not open";
		return 2;
	}

	my $cmd = "close $device $path\n";

	my $rc = $self->handler_private($handler_io, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = $self->handlerDeviceExists($handler, $device);

	if ($rc) {
		$self->{'error'} = "closeDevice(): An error occured while closing device '$device'. ".
		  "See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub resyncDevice {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $handler_io = $_IO_MAP_{$handler};
	my $handler_name = $_REVERSE_MAP_{$handler};

	if (!$handler_io) {
		$self->{'error'} = "resyncDevice(): Failed to open handler IO '$handler_io'".
		  " or handler '$handler_name' ($handler) invalid";
		return 1;
	}

	if (!$self->handlerExists($handler)) {
		$self->{'error'} = "resyncDevice(): Handler '$handler_name' ($handler) does not exist";
		return 1;
	}

	if (!$self->handlerDeviceExists($handler, $device)) {
		$self->{'error'} = "resyncDevice(): Device '$device' does not exist";
		return 2;
	}

	my $cmd = "resync_size $device\n";

	my $rc = $self->handler_private($handler_io, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	return $rc;
}

sub setT10DeviceId {
	my $self = shift;
	my $handler = shift;
	my $device = shift;
	my $t10_id = shift;
	my $handler_io = $_IO_MAP_{$handler};

	if (!$handler_io) {
		$self->{'error'} = "setT10DeviceId(): Failed to open handler IO $handler_io or handler $handler invalid";
		return 1;
	}

	if (!$self->handlerExists($handler)) {
		$self->{'error'} = "setT10DeviceId(): Handler $handler does not exist";
		return 1;
	}

	if (!$self->handlerDeviceExists($handler, $device)) {
		$self->{'error'} = "setT10DeviceId(): Device $device is not open";
		return 2;
	}

	my $cmd = "set_t10_dev_id $device $t10_id\n";

	my $rc = $self->handler_private($handler_io, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	my $devices = $self->handlerDevices($handler);

	if ($$devices{$device}->{'T10_DEVICE_ID'} ne $t10_id) {
                $self->{'error'} = "setT10DeviceId(): An error occured while setting T10 device ID to '$t10_id' ".
		  "for device '$device'. See dmesg/kernel log for more information.";
		return 1;
	}
}

sub userExists {
	my $self = shift;
	my $user = shift;
	my $group = shift;

	my $users = $self->users($group);

	return -1 if (!defined($users));

	foreach my $_user (@{$users}) {
		return 1 if ($user eq $_user);
	}

	return 0;
}

sub users {
	my $self = shift;
	my $group = shift;
	my @users;

	return undef if (!$self->groupExists($group));

	my $io = new IO::File $_SCST_GROUPS_DIR_."/$group/".$_SCST_USERS_IO_, O_RDONLY;

	if (!$io) {
		$self->{'error'} = "users(): Failed to open handler IO '".$_SCST_GROUPS_DIR_.
		  "/$group/".$_SCST_USERS_IO_."'";
		return undef;
	}

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

	if (!$self->groupExists($group)) {
		$self->{'error'} = "addUser(): Group '$group' does not exist";
		return 1;
	}

	if ($self->userExists($user, $group)) {
		$self->{'error'} = "addUser(): User '$user' already exists in group '$group'";
		return 2;
	}

	my $cmd = "add $user\n";

	my $rc = $self->group_private($group, $_SCST_USERS_IO_, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = !$self->userExists($user, $group);

	if ($rc) {
		$self->{'error'} = "addUser(): An error occured while adding user '$user' to group '$group'. ".
		  "See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub removeUser {
	my $self = shift;
	my $user = shift;
	my $group = shift;

	if (!$self->groupExists($group)) {
		$self->{'error'} = "removeUser(): Group '$group' does not exist";
		return 1;
	}

	if (!$self->userExists($user, $group)) {
		$self->{'error'} = "removeUser(): User '$user' does not exist in group '$group'";
		return 2;
	}

	my $cmd = "del $user\n";

	my $rc = $self->group_private($group, $_SCST_USERS_IO_, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = $self->userExists($user, $group);

	if ($rc) {
		$self->{'error'} = "removeUser(): An error occured while removing user '$user' ".
		  "from group '$group'. See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub moveUser {
	my $self = shift;
	my $user = shift;
	my $fromGroup = shift;
	my $toGroup = shift;

	if (!$self->groupExists($fromGroup)) {
		$self->{'error'} = "moveUser(): Group '$fromGroup' does not exist";
		return 1;
	}

	if (!$self->groupExists($toGroup)) {
		$self->{'error'} = "moveUser(): Group '$toGroup' does not exist";
		return 1;
	}

	if (!$self->userExists($user, $fromGroup)) {
		$self->{'error'} = "addUser(): User '$user' doesn't exist in group '$fromGroup'";
		return 1;
	}

	if ($self->userExists($user, $toGroup)) {
		$self->{'error'} = "addUser(): User '$user' already exists in group '$toGroup'";
		return 2;
	}

	my $cmd = "move $user $toGroup\n";

	my $rc = $self->group_private($fromGroup, $_SCST_USERS_IO_, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = !$self->userExists($user, $toGroup);

	if ($rc) {
		$self->{'error'} = "addUser(): An error occured while moving user '$user' from group '$fromGroup' ".
		  "to group '$toGroup'. See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub clearUsers {
	my $self = shift;
	my $group = shift;

	if (!$self->groupExists($group)) {
		$self->{'error'} = "clearUsers(): Group '$group' does not exist";
		return 1;
	}

	my $cmd = "clear\n";

	my $rc = $self->group_private($group, $_SCST_USERS_IO_, $cmd);

	return 0 if ($self->{'debug'});

	if ($rc) {
		$self->{'error'} = "clearUsers(): An error occured while clearing users from ".
		  "group '$group'. See dmesg/kernel log for more information.";
		return $rc;
	}

	my $users = $self->users($group);

	return ($#{$users} + 1);
}

sub handlerExists {
	my $self = shift;
	my $handler = shift;

	my $handlers = $self->handlers();

	foreach my $_handler (@{$handlers}) {
		return 1 if ($handler eq $_handler);
	}

	return 0;
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
		return 1 if ($$devices{$device} eq $lun);
	} else {
		return 1 if (defined($$devices{$device}));
	}

	return 0;
}

sub groupDevices {
	my $self = shift;
	my $group = shift;
	my %devices;
	my $first = 1;

	if (!$self->groupExists($group)) {
		$self->{'error'} = "groupDevices(): Group '$group' does not exist";
		return undef;
	}

	my $io = new IO::File $_SCST_GROUPS_DIR_."/$group/".$_SCST_DEVICES_IO_, O_RDONLY;

	if (!$io) {
		$self->{'error'} = "groupDevices(): Failed to open handler IO '".$_SCST_GROUPS_DIR_.
		  "/$group/".$_SCST_DEVICES_IO_."'";
		return undef;
	}

	while (my $line = <$io>) {
		chomp $line;

		if ($first) {
			$first = 0;
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
	my $options = shift;
	my $valid_opts;

	($options, $valid_opts) = $self->checkOptions($options, 'ASSIGN');

	if (!$valid_opts) {
		$self->{'error'} = "assignDeviceToGroup(): Invalid option(s) '$options' given for ".
		  "device '$device' in assignment";
		return 1;
	}

	if (!$self->groupExists($group)) {
		$self->{'error'} = "assignDeviceToGroup(): Group '$group' does not exist";
		return 1;
	}

	if ($self->groupDeviceExists($device, $group, $lun)) {
		$self->{'error'} = "assignDeviceToGroup(): Device '$device' is already ".
		  "assigned to group '$group'";
		return 2;
	}

	$options = cleanupString($options);
	$options =~ s/,/ /g;

	my $cmd = "add $device $lun $options\n";

	my $rc = $self->group_private($group, $_SCST_DEVICES_IO_, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = !$self->groupDeviceExists($device, $group, $lun);

	if ($rc) {
		$self->{'error'} = "assignDeviceToGroup(): An error occured while assigning device '$device' ".
		  "to group '$group'. See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub replaceDeviceInGroup {
	my $self = shift;
	my $newDevice = shift;
	my $group = shift;
	my $lun = shift;
	my $options = shift;
	my $valid_opts;

	($options, $valid_opts) = $self->checkOptions($options, 'ASSIGN');

	if (!$valid_opts) {
		$self->{'error'} = "replaceDeviceInGroup(): Invalid option(s) '$options' given for ".
		  "device '$newDevice'";
		return 1;
	}

	if (!$self->groupExists($group)) {
		$self->{'error'} = "replaceDeviceInGroup(): Group '$group' does not exist";
		return 1;
	}

	if ($self->groupDeviceExists($newDevice, $group, $lun)) {
		$self->{'error'} = "replaceDeviceInGroup(): Device '$newDevice' is already ".
		  "assigned to group '$group'";
		return 2;
	}

	$options = cleanupString($options);
	$options =~ s/,/ /g;

	my $cmd = "replace $newDevice $lun $options\n";

	my $rc = $self->group_private($group, $_SCST_DEVICES_IO_, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = !$self->groupDeviceExists($newDevice, $group, $lun);

	if ($rc) {
		$self->{'error'} = "replaceDeviceInGroup(): An error occured while replacing lun '$lun' with ".
		  " device '$newDevice' in group '$group'. See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub assignDeviceToHandler {
	my $self = shift;
	my $device = shift;
	my $handler = shift;
	my $handler_io = $_IO_MAP_{$handler};
	my $handler_name = $_REVERSE_MAP_{$handler};

	if (!$handler_io) {
		$self->{'error'} = "assignDeviceToHandler(): Failed to open handler IO '$handler_io' or ".
		  "handler '$handler_name' ($handler) invalid";
		return 1;
	}

	if (!$self->handlerExists($handler)) {
		$self->{'error'} = "assignDeviceToHandler(): Handler '$handler_name' ($handler) does not exist";
		return 1;
	}

	if ($self->handlerDeviceExists($handler, $device)) {
		$self->{'error'} = "assignDeviceToHandler(): Device '$device' is already assigned".
		  " to handler '$handler_name' ($handler)";
		return 2;
	}

	my $cmd = "assign $device $handler_name\n";

	my $rc = $self->scst_private($cmd);

	return 0 if ($self->{'debug'});
	return $rc if($rc);

	$rc = !$self->handlerDeviceExists($handler, $device);

	if ($rc) {
		$self->{'error'} = "assignDeviceToHandler(): An error occured while assigning device '$device' ".
		  "to handler '$handler_name' ($handler). See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub removeDeviceFromGroup {
	my $self = shift;
	my $device = shift;
	my $group = shift;

	if (!$self->groupExists($group)) {
		$self->{'error'} = "removeDeviceFromGroup(): Group '$group' does not exist";
		return 1;
	}

	if (!$self->groupDeviceExists($device, $group)) {
		$self->{'error'} = "removeDeviceFromGroup(): Device '$device' does not exist in group '$group'";
		return 2;
	}

	my $cmd = "del $device\n";

	my $rc = $self->group_private($group, $_SCST_DEVICES_IO_, $cmd);

	return 0 if ($self->{'debug'});
	return $rc if ($rc);

	$rc = $self->groupDeviceExists($device, $group);

	if ($rc) {
		$self->{'error'} = "removeDeviceFromGroup(): An error occured while removing device '$device' ".
		  "from group '$group'. See dmesg/kernel log for more information.";
	}

	return $rc;
}

sub clearGroupDevices {
	my $self = shift;
	my $group = shift;

	return 1 if (!$self->groupExists($group));

	my $cmd = "clear\n";

	my $rc = $self->group_private($group, $_SCST_DEVICES_IO_, $cmd);

	return 0 if ($self->{'debug'});

	if ($rc) {
		$self->{'error'} = "clearGroupDevices(): An error occured while clearing devices from ".
		  "group '$group'. See dmesg/kernel log for more information.";
		return $rc;
	}

	my $devices = $self->groupDevices($group);

	return (keys %{$devices});
}

sub handler_private {
	my $self = shift;
	my $handler_io = shift;
	my $cmd = shift;

	my $io = new IO::File $handler_io, O_WRONLY;

	if (!$io) {
		cluck("WARNING: SCST/SCST.pm: Failed to open handler IO $handler_io, assuming disabled");
		return 0;
	}

	if ($self->{'debug'}) {
		print "DBG($$): '$handler_io' -> '$cmd'\n";
	} else {
		print $io "$cmd\0";
	}

	close $io;

	return 0;
}

sub scst_private {
	my $self = shift;
	my $cmd = shift;

	my $io = new IO::File $_SCST_IO_, O_WRONLY;

	if (!$io) {
		$self->{'error'} = "SCST/SCST.pm: Failed to open handler IO '$_SCST_IO_'";
		return 1;
	}

	if ($self->{'debug'}) {
		print "DBG($$): '$_SCST_IO_' -> '$cmd'\n";
	} else {
		print $io "$cmd\0";
	}

	close $io;

	return 0;
}

sub group_private {
	my $self = shift;
	my $group = shift;
	my $file = shift;
	my $cmd = shift;

	my $io = new IO::File $_SCST_GROUPS_DIR_."/$group/".$file, O_WRONLY;

	if (!$io) {
		$self->{'error'} = "SCST/SCST.pm: Failed to open handler IO '".$_SCST_GROUPS_DIR_."/$group/".$file."'";
		return 1;
	}

	if ($self->{'debug'}) {
		print "DBG($$): $_SCST_GROUPS_DIR_/$group/$file -> $cmd\n";
	} else {
		print $io "$cmd\0";
	}

	close $io;

	return 0;
}

sub checkOptions {
	my $self = shift;
	my $options = shift;
	my $type = shift;
	my $o_string;
	my $b_string;
	my $bad = 0;

	return undef, 1 if (!$options || !$type);

	my $_options_ = $_OPTIONS_BY_TYPE_{$type};

	foreach my $option (split(/[\s+|\,]/, $options)) {
		my $map = $$_options_{$option};

		if (!$map) {
			$bad = 1;
			$b_string .= ",$option";
		} else {
			$o_string .= ",$map";
		}
	}

	if ($bad) {
		$b_string =~ s/^\,//;
		return $b_string, 0;
	}

	$o_string =~ s/^\,//;

	return $o_string, 1;
}

sub errorString {
	my $self = shift;

	return undef if (!$self->{'error'});

	my $string = $self->{'error'};
	$self->{'error'} = undef;

	return $string;
}

sub cleanupString {
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
    
    if ($p->handlerDeviceExists($SCST::SCST::VDISK_TYPE)) {
         print "openDevice() failed\n"
           if ($p->openDevice($SCST::SCST::VDISK_TYPE, 'DISK01', '/vdisk/disk01.dsk'));
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

=item SCST::SCST->renameGroup();

Renames an already existing group. Returns 0 upon success, 1 if unsuccessfull
or 2 if the new group name already exists.

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

=item SCST::SCST->handlerType();

Return the handler type for the specified handler. Handler types are:

  SCST::SCST::IOTYPE_PHYSICAL
  SCST::SCST::IOTYPE_VIRTUAL
  SCST::SCST::IOTYPE_PERFORMANCE

Arguments: (int) $handler

Returns: (int) $handler_type

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

=item SCST::SCST->setT10DeviceId();

Changes the T10 device ID for the specified device and handler. Returns
0 upon success, 1 if unsuccessfull and 2 of the device does not exist.

Arguments: (int) $handler, (string) $device, (string) $t10_dev_id

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

=item SCST::SCST->moveUser();

Moves a user from one group to another. Both groups must be defined
and user must already exist in the first group. Returns 0 upon
success, 1 if unsuccessfull and 2 if the user already exists in the
second group.

Arguments: (string) $user, (string) $fromGroup, (string) $toGroup

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

Arguments: (string) $device, (string) $group, (int) $lun [, (string) $options]

Returns: (int) $success

=item SCST::SCST->replaceDeviceInGroup();

Replaces an already assigned device to the specified lun in a
specified security group with $newDevice. Returns 0 upon success, 1
if unsuccessfull and 2 if the device has already been assigned to
the specified security group.

Arguments: (string) $newDevice, (string) $group, (int) $lun [, (string) $options]

Returns (int) $success

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

=item SCST::SCST->errorString();

Contains a description of the last error occured or undef if no error
has occured or if this method has already been called once since the
last error.

Arguments: (void)

Returns: (string) $error_string

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
VDISK_TYPE,
VCDROM_TYPE,
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
