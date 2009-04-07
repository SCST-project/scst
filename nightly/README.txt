
This directory (nightly/) contains a simple, automatic build-and-test
system for SCST, intended to be run by cron.

Note (importantly) it doesn't test the sources in the tree of which
this directory is a part (viz, nightly/..).  Instead it checks out
a complete new tree, builds and tests that independently of the
existing tree.

To use, choose a tag, probably a machine name, and run

   bin/nightly <tag>

and supply the following two config files:

- conf/<tag>.conf:  this is sourced by the 'nightly' script, and can define
  any or all of the following environment variables:

  ABT_DETAILS: describes the machine in more detail, eg. the OS.  The default
    is empty.
  ABT_EVAL: if provided, it must be the name of a shell script that executes
    the shell command $1 with arguments $2 .. ${$#}. Allows to compile and
    run the SCST regression tests on another system than the system the
    'nightly' script runs on. It is assumed that the remote system shares the
    local filesystem tree through e.g. NFS. It is the responsibility of the
    shell script to set the remote working directory such that it matches the
    local current directory ($PWD).
  ABT_JOBS: allows parallel builds -- it's passed as the argument to "make
    -j" when building SCST and the tests.  The default is 1.
  ABT_KERNELS: kernel version numbers to test SCST against.
  ABT_TMPDIR: absolute path in which temporary files will be stored.

- conf/<tag>.sendmail:  this should be a script that sends an email to the
  desired recipient (eg. the scst-developers list).  It takes three
  command line arguments.  The first is the email subject line, the second
  is the name of the file containing the email's body (showing the tests
  that failed, and the difference between now and 24 hours ago), the third
  is the name of the file containing all the diffs (which can be made into
  an attachment, for example).

CREDITS

The automatic build-and-test infrastructure for the SCST project reuses some
ideas and shell script code from a similar infrastructure in the Valgrind project.
