"""Process and report helpers for the analyzer drivers."""

import contextlib
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

PROGRESS_INTERVAL = 5
SPINNER_INTERVAL = 0.1
SPINNER_FRAMES = "|/-\\"
VERBOSE = os.environ.get("V", "0") not in {"", "0"}


def show_log(path, label="Full log"):
    print(f"  {label}: {Path(path).resolve()}", file=sys.stderr, flush=True)


class Progress:
    """Animate only a quiet child; redirected output gets periodic plain lines."""

    def __init__(self, label, *, quiet=True):
        self.label = label
        self.started = time.monotonic()
        self.animated = (bool(label) and quiet and sys.stderr.isatty()
                         and os.environ.get("TERM") != "dumb")
        self.interval = SPINNER_INTERVAL if self.animated else PROGRESS_INTERVAL
        self.frame = 0
        self.visible = False

    def update(self):
        elapsed = int(time.monotonic() - self.started)
        if self.animated:
            elapsed -= elapsed % PROGRESS_INTERVAL
            frame = SPINNER_FRAMES[self.frame % len(SPINNER_FRAMES)]
            text = f"  {frame} {self.label}  {elapsed // 60:02}:{elapsed % 60:02}"
            width = shutil.get_terminal_size().columns
            print("\r\033[2K" + text[:max(1, width - 1)], end="", file=sys.stderr, flush=True)
            self.frame += 1
        else:
            print(f"  {self.label}: running ({elapsed}s elapsed)", file=sys.stderr, flush=True)
        self.visible = True

    def clear(self):
        if self.animated and self.visible:
            print("\r\033[2K", end="", file=sys.stderr, flush=True)

    def finish(self, status):
        self.clear()
        if self.visible:
            elapsed = int(time.monotonic() - self.started)
            print(f"  {self.label}: finished ({elapsed}s, exit {status})",
                  file=sys.stderr, flush=True)


def jobserver_fds(env):
    """Forward an inherited pipe jobserver without acquiring its tokens."""
    matches = re.findall(r"--jobserver-(?:auth|fds)=(\S+)", env.get("MAKEFLAGS", ""))
    if not matches or not re.fullmatch(r"\d+,\d+", matches[-1]):
        return ()
    descriptors = tuple(map(int, matches[-1].split(",")))
    try:
        for descriptor in descriptors:
            if (not os.get_inheritable(descriptor)
                    or not stat.S_ISFIFO(os.fstat(descriptor).st_mode)):
                return ()
    except OSError:
        return ()
    return descriptors


def start(command, *, env=None, **kwargs):
    environment = os.environ if env is None else env
    if VERBOSE:
        print("  $ " + shlex.join(map(str, command)), file=sys.stderr, flush=True)
    return subprocess.Popen(command, env=environment, start_new_session=True,
                            pass_fds=jobserver_fds(environment), **kwargs)


def stop(process):
    """Stop the owned process group, including children of an exited driver."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def exit_status(returncode):
    return returncode if returncode >= 0 else 128 - returncode


def run(command, *, input=None, check=False, progress=None, **kwargs):
    if input is not None:
        kwargs["stdin"] = subprocess.PIPE
    process = start(command, **kwargs)
    indicator = Progress(progress, quiet=kwargs.get("stdout") is not None
                         and kwargs.get("stderr") is not None)
    try:
        if indicator.animated:
            indicator.update()
        while True:
            try:
                stdout, stderr = process.communicate(
                    input, timeout=indicator.interval if progress else None)
                break
            except subprocess.TimeoutExpired:
                # communicate retains pending input and output across retries.
                input = None
                indicator.update()
    except BaseException:
        indicator.clear()
        stop(process)
        raise
    result = subprocess.CompletedProcess(command, exit_status(process.returncode), stdout, stderr)
    indicator.finish(result.returncode)
    if check:
        result.check_returncode()
    return result


def log_path(root, name, *, truncate=True):
    path = root / ".cache/lint" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if truncate:
        path.write_bytes(b"")
    return path


def copy_output(path, output=None):
    destination = output if output is not None else sys.stderr.buffer
    with Path(path).open("rb") as stream:
        shutil.copyfileobj(stream, destination)
    destination.flush()


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def entrypoint(main):
    global VERBOSE
    VERBOSE = VERBOSE or "--verbose" in sys.argv[1:]
    sys.argv[1:] = [arg for arg in sys.argv[1:] if arg != "--verbose"]

    def interrupt(signum, _frame):
        raise Interrupted(signum)

    signal.signal(signal.SIGTERM, interrupt)
    try:
        return main()
    except Interrupted as error:
        return 128 + error.signum
    except KeyboardInterrupt:
        return 130
    except subprocess.CalledProcessError as error:
        print(f"Command failed ({error.returncode}): {error.cmd}", file=sys.stderr)
        return error.returncode
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
