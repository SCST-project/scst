"""Serialize analyzer builds and retain evidence of native CHECK invocations."""

from contextlib import contextmanager
from collections import Counter
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

from lint_common import run
from sparse_smatch.native import checker_command
from lint_scope import in_scope, tracked_sources


@contextmanager
def build_lock(root):
    path = root / ".cache/lint/kbuild.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def validate_checker(root, tool, log):
    """Fail before a module build if the selected kernel rejects the checker."""
    checker_command(tool)  # Require the executable and native data even on old kernels.
    kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR") or
                  f"/lib/modules/{os.environ.get('KVER') or os.uname().release}/build")
    if not (kernel / "Makefile").is_file():
        raise ValueError(f"kernel build tree not found: {kernel}")
    probe = kernel / "scripts/checker-valid.sh"
    if not probe.exists():
        return  # Older supported kernels have no capability probe.
    command = [sys.executable, str(root / "scripts/sparse_smatch/check.py"), tool]
    # checker-valid.sh filters native output and can lose the native status in
    # a pipeline. Record both independently, just like ordinary CHECK steps.
    with tempfile.TemporaryDirectory(prefix="scst-checker-probe-") as directory:
        record = Path(directory) / "probe.json"
        record.write_text(json.dumps({"returncode": 2}))
        env = dict(os.environ, SCST_LINT_PROBE_RECORD=str(record), SCST_LINT_PROBE_LOG=str(log))
        result = run([str(probe), *command, *shlex.split(os.environ.get("CHECKFLAGS", ""))],
                     cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        native_status = json.loads(record.read_text())["returncode"]
    with log.open("ab") as output:
        output.write(f"Kbuild checker validation: {probe}\n".encode())
        output.write(result.stdout)
        output.write(f"Native probe exit status: {native_status}\n".encode())
    if result.returncode or native_status or result.stdout.strip() != b"1":
        raise ValueError(f"{tool} is incompatible with {probe}; module build was not started")


def collect(root, tool, directory, log):
    """Retain CHECK exits even when the enclosing Kbuild discards them."""
    env = dict(os.environ, SCST_LINT_RECORDS=str(directory))
    checker = shlex.join([sys.executable, str(root / "scripts/sparse_smatch/check.py"), tool])
    command = ["make", "--no-silent", "-k", "-C", str(root), "lint-kbuild",
               "C=2", "V=0", "CHECK=" + checker]
    with log.open("ab") as output:
        result = run(command, env=env, stdout=output, stderr=subprocess.STDOUT,
                     progress=f"{tool.capitalize()} Kbuild")
    records = [json.loads(path.read_text()) for path in sorted(Path(directory).glob("*.json"))]
    return result.returncode, records


def unchecked_invocations(root, tool, log, records):
    """Detect a CHECK whose adapter never managed to leave a record."""
    checked = Counter(Path(row["file"]) for row in records)
    sources = set(tracked_sources(root, tool)) | set(checked)
    announced = Counter()
    for line in log.read_text(errors="replace").splitlines():
        match = re.fullmatch(r"\s+CHECK\s+(?:\[M\]\s+)?(.+\.c)\s*", line)
        if not match:
            continue
        path = Path(match[1])
        if path.is_absolute():
            candidates = {path.resolve()} if in_scope(path, root, tool) else set()
        else:
            candidates = {source for source in sources
                          if source.as_posix().endswith("/" + path.as_posix())}
        if len(candidates) > 1:
            raise ValueError(f"ambiguous Kbuild CHECK path: {path}")
        announced.update(candidates)
    return sorted(map(str, (announced - checked).elements()))
