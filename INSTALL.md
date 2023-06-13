# Building and installing SCST

## Prerequisites

If the following packages have not yet been installed, install these now:

    bzip2
    gcc
    kernel-devel or kernel-default-devel
    kernel-modules-extra (only on Fedora)
    libelf-dev, libelf-devel or elfutils-libelf-devel
    libperl-dev or perl-devel
    make
    perl
    perl-Data-Dumper
    perl-ExtUtils-MakeMaker (not needed on Debian systems)
    rpm-build (only on RPM-based systems)
    tar

## Building SCST

The next step is to build and install SCST. How to do that depends on whether
or not your Linux distribution supports a package manager:

    make 2release
    if rpm -q glibc >/dev/null 2>&1; then
        rm -rf {,scstadmin/}rpmbuilddir
        make rpm
        sudo rpm -U $PWD/{,scstadmin/}rpmbuilddir/RPMS/*/*.rpm
    elif dpkg-query -s libc-bin >/dev/null 2>&1; then
        sudo apt install build-essential debhelper devscripts gcc make lintian quilt
        sudo apt install linux-headers-$(uname -r) || sudo apt install pve-headers-$(uname -r)
        make dpkg
        sudo dpkg -i $PWD/dpkg/{scst,iscsi-scst,scstadmin}_*.deb
    else
        make 2release
        BUILD_2X_MODULE=y CONFIG_SCSI_QLA_FC=y CONFIG_SCSI_QLA2XXX_TARGET=y make all
        sudo BUILD_2X_MODULE=y CONFIG_SCSI_QLA_FC=y CONFIG_SCSI_QLA2XXX_TARGET=y make -C "$PWD" install
    fi

Since the above step installs several kernel modules into directory
/lib/modules/$(uname -r), that step has to be repeated every time a new kernel
or a kernel update has been installed. If you want to avoid this, install the
scst-dkms package instead of the scst package.

For example, if you want to have dkms support for your SCST rpm install, then
you would use the following command to make your SCST packages:

    make rpm-dkms

or

    make scst-dkms-rpm

make rpm-dkms also builds scstadmin packages in addition to the SCST dkms
packages. Both make commands will create rpm packages that will cause SCST to be
automatically rebuilt and installed every time a new kernel version is
installed and booted for which the SCST kernel modules had not yet been built
so that SCST rpm packages will not need to be rebuilt after each kernel update.

## Configuring SCST

The easiest way to configure SCST is to create a configuration file
/etc/scst.conf and by using scstadmin to load that configuration file. The
/etc/init.d/scst script uses scstadmin to load the /etc/scst.conf file. The
following information is present in /etc/scst.conf:

* Which local storage has to be exported by SCST, e.g. a file, block device or
  SCSI device.
* Through which storage adapter ports SCST allows access to the local
  storage.
* Which initiator systems are allowed to log in.

For more information about scst.conf, see also
scstadmin/scstadmin.sysfs/man5/scst.conf.5.

Loading the SCST kernel modules and applying the /etc/scst.conf configuration
file is possible as follows:

    /etc/init.d/scst restart

After SCST has been loaded, configuration changes can be applied without
unloading and reloading the SCST kernel modules:

    scstadmin -config /etc/scst.conf

After the SCST configuration has been changed via scstadmin or by modifying the
SCST sysfs attributes, the new configuration can be saved e.g. as follows:

    scstadmin -write_config /etc/scst.conf.new

More information about the device handler and target driver sysfs attributes
can be found in the scst/README document. More detailed instructions about
iSCSI, QLogic FC, SRP and FCoE configuration can be found in the following
documents:

* iscsi-scst/README
* qla2x00t/doc/qla2x00t-howto.html
* srpt/README
* fcst/README
