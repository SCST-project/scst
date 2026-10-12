# SPDX-License-Identifier: GPL-2.0-only
"""One SSH connection owns a host lock and executes bounded argv requests."""
import fcntl
import json
import os
import selectors
import signal
import subprocess
import sys
import time

LIMIT = 1024 * 1024


def reply(value):
    print(json.dumps(value), flush=True)


def execute(request):
    result = {"exit_code": -1, "stdout": "", "stderr": ""}
    process = None
    try:
        argv = request["argv"]
        timeout = request["timeout"]
        if not argv or not all(isinstance(arg, str) for arg in argv):
            raise ValueError("invalid argv")
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600:
            raise ValueError("invalid timeout")
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
            env=dict(os.environ, LC_ALL="C"))
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError("remote command timed out; state is uncertain")
                for key, _ in selector.select(min(0.1, deadline - time.monotonic())):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    stream = streams[key.data]
                    room = LIMIT - len(stream)
                    stream.extend(data[:room])
                    if len(data) > room:
                        raise ValueError("remote output limit exceeded")
        result["exit_code"] = process.wait(timeout=1)
        if result["exit_code"] < 0:
            raise RuntimeError("remote command terminated by signal")
    except Exception as error:
        result["execution_error"] = str(error)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    finally:
        if process is not None:
            for name, data in streams.items():
                result[name] = data.decode("utf-8", errors="replace")
            process.stdout.close()
            process.stderr.close()
    return result


def main():
    try:
        # Keep the inode: removing a lock file would let another run bypass it.
        lock = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as source:
            boot_id = source.read().strip()
        reply({"uid": os.geteuid(), "boot_id": boot_id})
    except Exception as error:
        reply({"execution_error": str(error)})
        return
    blocked = None
    for line in sys.stdin:
        try:
            result = ({"execution_error": blocked} if blocked else
                      execute(json.loads(line)))
        except Exception as error:
            result = {"execution_error": str(error)}
        blocked = result.get("execution_error")
        reply(result)
    os.close(lock)


if __name__ == "__main__":
    main()
