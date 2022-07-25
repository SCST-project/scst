<a href="https://scan.coverity.com/projects/scst-project">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/25131.svg"/>
</a>

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

Two QLogic target drivers are included in the SCST project.

The default driver is located in qla2x00t-32gbit directory and it supports up
to 32 Gb/s FC. It is the newer one.

May anyone wish to switch back to the older driver that only supported up to
16 Gb/s adapters, it is located in qla2x00t directory. To make use of the
older driver build scst with environment variable `QLA_32GBIT=no` set.

Vladislav Bolkhovitin <vst@vlnb.net>, http://scst.sourceforge.net

## Sourceforge achievements
<p align="middle">
<img src="./www/images/sourceforge_badges/oss-users-love-us-white.svg" width="125" />
<img src="./www/images/sourceforge_badges/oss-community-choice-white.svg" width="125" />
<img src="./www/images/sourceforge_badges/oss-sf-favorite-white.svg" width="125" />
<img src="./www/images/sourceforge_badges/oss-community-leader-white.svg" width="125" />
<img src="./www/images/sourceforge_badges/oss-open-source-excellence-white.svg" width="125" />
</p>
