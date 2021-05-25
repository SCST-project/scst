# Overview

This is the source code repository of the SCST project. SCST is a collection
of Linux kernel drivers that implement SCSI target functionality. The SCST
project includes:

1. The SCST core in the scst/ subdirectory.
2. A tool for loading, saving and modifying the SCST configuration in
   directory scstadmin/.
3. Several SCSI target drivers in the directories iscsi-scst/, qla2x00t/,
   srpt/, scst_local/ and fcst/.
4. User space programs in the usr/ subdirectory, e.g. fileio_tgt.
5. Various documentation in the doc/ subdirectory.

Instructions for building and installing SCST are available in the INSTALL.md
file.

## QLogic target driver

Two QLogic target drivers are included in the SCST project. The driver in
the qla2x00t directory is a very stable driver that supports up to 16 Gb/s
adapters. It is very stable, well tested and actively used in many production
setups.

There is also a newer driver that supports 32 Gb/s FC in the qla2x00t-32gbit
directory. That driver has not yet reached the same maturity level as the
old qla2x00t driver. It can be enabled by setting `QLA_32GBIT=y` variable
while compiling.

Vladislav Bolkhovitin <vst@vlnb.net>, http://scst.sourceforge.net
