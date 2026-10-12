# SPDX-License-Identifier: GPL-2.0-only
"""Carry binary sg output and fio job text over the existing argv transport.

The caller supervises the entire process group, including the child. A child
signal is propagated so that the command runner latches uncertain execution.
"""
import base64
import json
import os
import signal
import subprocess
import sys
import tempfile


def main():
    request = json.loads(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="scst-dataio-") as directory:
        argv = request["argv"]
        if "fio_config" in request:
            path = os.path.join(directory, "verify.fio")
            with open(path, "w", encoding="ascii") as output:
                output.write(request["fio_config"])
            argv = ["fio", "--output-format=json", "--eta=never", path]
        result = subprocess.run(
            argv, input=base64.b64decode(request.get("input", "")),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=directory,
            env=dict(os.environ, LC_ALL="C"))
        if result.returncode < 0:
            os.kill(os.getpid(), signal.SIGKILL)
        print(json.dumps({"exit_code": result.returncode,
                          "data": base64.b64encode(result.stdout).decode("ascii"),
                          "stderr": result.stderr.decode("utf-8", errors="replace")}))


if __name__ == "__main__":
    main()
