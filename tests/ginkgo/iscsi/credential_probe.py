# SPDX-License-Identifier: GPL-2.0-only
"""Control the writer's umask and probe saved credentials as an unprivileged UID.

SCST operations remain in the real scstadmin invoked by the shared runner.
Unexpected errors fail the helper; only EACCES counts as access denial.
"""
import errno
import os
import stat
import sys


def read_file(path):
    try:
        with open(path, "rb") as source:
            return source.read()
    except OSError as error:
        if error.errno != errno.EACCES:
            raise
        return None


def main():
    operation, directory = sys.argv[1:3]
    public = os.path.join(directory, "public-control")
    if operation == "save":
        os.umask(0o022)
        with open(public, "xb") as output:
            output.write(b"public\n")
        if stat.S_IMODE(os.stat(public).st_mode) != 0o644:
            raise RuntimeError("filesystem permissions do not reflect umask 022")
        # No shell interpolation, mocks, or test-side config serialization.
        os.execvp(sys.argv[3], sys.argv[3:])
    elif operation == "read":
        os.setgroups([])
        os.setresgid(65534, 65534, 65534)
        os.setresuid(65534, 65534, 65534)
        if (os.getresuid() != (65534,) * 3 or
                os.getresgid() != (65534,) * 3 or os.getgroups()):
            raise RuntimeError("failed to drop reader credentials")
        if read_file(public) != b"public\n":
            raise RuntimeError("reader cannot reach a public file in the directory")
        if read_file(os.path.join(directory, "private-control")) is not None:
            raise RuntimeError("reader can access a root-only control file")
        contents = read_file(os.path.join(directory, "saved.conf"))
        if contents is None:
            print("denied")
        elif sys.argv[3].encode("ascii") in contents:
            print("exposed")
        else:
            raise RuntimeError("readable config does not contain the test secret")
    else:
        raise ValueError("unknown credential probe operation")


if __name__ == "__main__":
    main()
