#!/usr/bin/perl -w
#
# Makefile for the SCST-SCST perl module
#

use ExtUtils::MakeMaker;

WriteMakefile(
        'NAME'          => 'SCST-SCST',
        'VERSION_FROM'  => 'lib/SCST/SCST.pm',
        'AUTHOR'        => 'Mark R. Buechler <Mark.Buechler@gmail.com>',
        'PREREQ_PM'     => {},
);
