"""Process and report helpers for the analyzer drivers."""

import contextlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import fcntl
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

PROGRESS_INTERVAL = 30
SPINNER_INTERVAL = 0.1
SPINNER_FRAMES = "|/-\\"
VERBOSE = os.environ.get("V", "0") not in {"", "0"}


def report_section(title, lines, *, collapsed=False):
    """Format report sections with optional folding in GitHub Actions."""
    body = lines if isinstance(lines, str) else "\n".join(lines)
    if collapsed and os.environ.get("GITHUB_ACTIONS") == "true" and not VERBOSE:
        return f"\n::group::{title}\n{body.rstrip()}\n::endgroup::\n"
    return f"\n--- {title} ---\n{body.rstrip()}\n"


def print_phase(tool, phase):
    print(f"\n{'=' * 72}\n{phase} | {tool}\n{'=' * 72}\n", flush=True)


def parser_runtime():
    from importlib.metadata import PackageNotFoundError, version

    packages = []
    for name in ("tree-sitter", "tree-sitter-c"):
        try:
            release = version(name)
        except PackageNotFoundError:
            release = "unknown"
        packages.append(f"{name} {release}")
    return f"Parser runtime: Python {sys.version.split()[0]}; " + "; ".join(packages)


def show_log(path, label="Full log"):
    print(f"  {label}: {Path(path).resolve()}", file=sys.stderr, flush=True)


class Progress:
    """Animate only a quiet child; redirected output gets periodic plain lines."""

    def __init__(self, label, *, quiet=True, stream=None):
        self.label = label
        self.stream = sys.stderr if stream is None else stream
        self.started = time.monotonic()
        self.animated = (bool(label) and quiet and self.stream.isatty()
                         and os.environ.get("TERM") != "dumb")
        self.interval = SPINNER_INTERVAL if self.animated else PROGRESS_INTERVAL
        self.frame = 0
        self.visible = False

    def update(self):
        elapsed = int(time.monotonic() - self.started)
        label = self.label() if callable(self.label) else self.label
        if self.animated:
            frame = SPINNER_FRAMES[self.frame % len(SPINNER_FRAMES)]
            text = f"  {frame} {label}  {elapsed // 60:02}:{elapsed % 60:02} total"
            width = shutil.get_terminal_size().columns
            print("\r\033[2K" + text[:max(1, width - 1)], end="", file=self.stream, flush=True)
            self.frame += 1
        else:
            print(f"  {label}: running ({elapsed}s total elapsed)", file=self.stream, flush=True)
        self.visible = True

    def clear(self):
        if self.animated and self.visible:
            print("\r\033[2K", end="", file=self.stream, flush=True)

    def finish(self, status):
        self.clear()
        if self.visible:
            elapsed = int(time.monotonic() - self.started)
            label = self.label() if callable(self.label) else self.label
            print(f"  {label}: finished ({elapsed}s total elapsed, exit {status})",
                  file=self.stream, flush=True)


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
    descriptors = set(kwargs.pop("pass_fds", ())) | set(jobserver_fds(environment))
    return subprocess.Popen(command, env=environment, start_new_session=True,
                            pass_fds=tuple(sorted(descriptors)), **kwargs)


@contextlib.contextmanager
def report_lock(root, tool):
    """Serialize direct and Make runs until the parent finishes its report."""
    path = root / ".cache/lint" / f"{tool}.report.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.environ.get("LINT_REPORT_LOCK_TOOL") == tool:
        # Reuse the parent's open file description. Opening the same lock
        # again would deadlock; an environment flag alone is not ownership.
        try:
            descriptor = int(os.environ.get("LINT_REPORT_LOCK_FD", ""))
            if descriptor < 3 or not os.path.samestat(os.fstat(descriptor), path.stat()):
                raise ValueError("Wrong report lock descriptor")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ValueError) as error:
            raise ValueError("Invalid inherited analyzer report lock") from error
        yield descriptor
    else:
        with path.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield stream.fileno()


def stop(process, *, timeout=2):
    """Stop the owned process group, including children of an exited driver."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def exit_status(returncode):
    return returncode if returncode >= 0 else 128 - returncode


def run(command, *, input=None, check=False, progress=None, progress_stream=None,
        timeout=None, cancel_timeout=2, **kwargs):
    if input is not None:
        kwargs["stdin"] = subprocess.PIPE
    process = start(command, **kwargs)
    deadline = time.monotonic() + timeout if timeout is not None else None
    indicator = Progress(progress, quiet=kwargs.get("stdout") is not None
                         and kwargs.get("stderr") is not None, stream=progress_stream)
    # Python 3.12 can stop writing pending stdin after a communicate timeout.
    # Keep one I/O operation running while the main thread updates progress.
    with ThreadPoolExecutor(max_workers=1) as executor:
        try:
            if indicator.animated:
                indicator.update()
            communication = executor.submit(process.communicate, input)
            while True:
                remaining = deadline - time.monotonic() if deadline is not None else None
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                wait = indicator.interval if progress else remaining
                if remaining is not None and wait is not None:
                    wait = min(wait, remaining)
                try:
                    stdout, stderr = communication.result(timeout=wait)
                    break
                except FutureTimeout:
                    if progress:
                        indicator.update()
        except BaseException:
            indicator.clear()
            # Close the process group's pipes before joining the I/O worker.
            stop(process, timeout=cancel_timeout)
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
    except subprocess.TimeoutExpired as error:
        print(f"Command timed out after {error.timeout}s: {error.cmd}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        print(f"Command failed ({error.returncode}): {error.cmd}", file=sys.stderr)
        return error.returncode
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
