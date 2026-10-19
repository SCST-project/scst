#!/usr/bin/env python3
"""Check whole SCST C files with native Checkpatch and no diagnostic filters."""

import argparse
from collections import Counter
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_common import copy_output, entrypoint, log_path, run, show_log  # noqa: E402
from lint_scope import select_sources  # noqa: E402

TOTAL = re.compile(r"total: (\d+) errors, (\d+) warnings, (\d+) checks, \d+ lines checked")
COMPLETE = re.compile(r"(.+) has (?:style problems, please review|"
                      r"no obvious style problems and is ready for submission)\.")
DIAGNOSTIC = re.compile(r"^(ERROR|WARNING|CHECK):([^:\n]+): ?(.*)$", re.MULTILINE)


def checker_path():
    kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR") or
                  f"/lib/modules/{os.environ.get('KVER') or os.uname().release}/build")
    directory = Path(os.environ.get("CHECKPATCH_PATH") or kernel / "scripts").resolve()
    for name in ("checkpatch.pl", "spelling.txt", "const_structs.checkpatch"):
        if not (directory / name).is_file():
            raise ValueError(f"missing Checkpatch tool/data: {directory / name}")
    return directory / "checkpatch.pl"


def native_report(text, stderr, status, selected):
    """Require matching native totals and completion for every requested file."""
    diagnostics = Counter(match[1] for match in DIAGNOSTIC.finditer(text))
    totals = [tuple(map(int, match.groups())) for line in text.splitlines()
              if (match := TOTAL.fullmatch(line))]
    completed = Counter(str(Path(match[1]).resolve()) for line in text.splitlines()
                        if (match := COMPLETE.fullmatch(line)))
    expected = Counter(str(path.resolve()) for path in selected)
    failures = []
    if stderr:
        failures.append("native stderr: " + stderr.rstrip())
    if status not in (0, 1):
        failures.append(f"native exit status {status}")
    if len(totals) != len(selected):
        failures.append(f"expected {len(selected)} native totals, got {len(totals)}")
    for index, severity in enumerate(("ERROR", "WARNING", "CHECK")):
        if sum(row[index] for row in totals) != diagnostics[severity]:
            failures.append(f"native {severity} total does not match retained diagnostics")
    for name, count in (expected - completed).items():
        failures.append(f"missing {count} native completion record(s) for {name}")
    for name, count in (completed - expected).items():
        failures.append(f"unexpected {count} native completion record(s) for {name}")
    remaining = sum(diagnostics.values())
    if status in (0, 1) and status != int(bool(remaining)):
        failures.append("native exit status disagrees with diagnostic totals")
    return {"native_status": status, "counts": dict(diagnostics), "remaining": remaining,
            "failures": failures, "complete": not failures,
            "completed_files": sorted(completed)}


def check(tool, selected, log):
    git_dir = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse",
                                       "--absolute-git-dir"], text=True).strip()
    # Native Checkpatch writes/deletes CamelCase caches in cwd. Its own
    # configuration search must not import a user's --ignore or --fix flags.
    with tempfile.TemporaryDirectory(prefix="checkpatch-", dir=log.parent) as temporary:
        directory = Path(temporary)
        (directory / ".checkpatch.conf").write_text("")
        stdout = directory / "stdout"
        stderr = directory / "stderr"
        env = dict(os.environ, CHECKPATCH_CONFIG_DIR=str(directory),
                   GIT_DIR=git_dir, GIT_WORK_TREE=str(ROOT))
        command = [str(tool), "--no-tree", "--root=" + str(ROOT), "--strict", "--show-types",
                   "--color=never", "--no-fix", "--no-fix-inplace", "--file", *map(str, selected)]
        try:
            with stdout.open("wb") as output, stderr.open("wb") as errors:
                result = run(command, cwd=directory, env=env, stdout=output, stderr=errors,
                             progress=f"Checkpatch ({len(selected)} files)")
        finally:
            with log.open("ab") as stream:
                for path in (stdout, stderr):
                    if path.exists():
                        copy_output(path, stream)
        return native_report(stdout.read_text(errors="replace"), stderr.read_text(errors="replace"),
                             result.returncode, selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("DIFFBR") or None)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    with log_path(ROOT, "checkpatch.lock", truncate=False).open("a") as lock:
        # Serialize this report without blocking independent Kbuild analyzers.
        fcntl.flock(lock, fcntl.LOCK_EX)
        log = log_path(ROOT, "checkpatch.log")
        report = log.with_suffix(".json")
        summary = {"tool": "checkpatch", "run_id": os.environ.get("SCST_LINT_RUN_ID"),
                   "outcome": "incomplete", "exit_code": 2, "remaining": 0,
                   "checked_files": [], "selected_files": []}
        report.write_text(json.dumps(summary, indent=2) + "\n")
        show_log(log)
        try:
            selected = select_sources(ROOT, args.files, args.base, "checkpatch")
            summary["selected_files"] = [path.relative_to(ROOT).as_posix() for path in selected]
            if not selected:
                print("No eligible Checkpatch inputs; analysis skipped.")
                summary.update(outcome="skipped", exit_code=0)
                return 0
            summary.update(check(checker_path(), selected, log))
            if not summary["complete"]:
                print("Checkpatch analysis is incomplete:\n" + "\n".join(summary["failures"]),
                      file=sys.stderr)
                return 2
            summary["checked_files"] = summary["selected_files"]
            status = int(bool(summary["remaining"]))
            summary.update(outcome="findings" if status else "clean", exit_code=status)
            print(f"Checkpatch: {len(selected)} files, {summary['remaining']} diagnostic(s).")
            return status
        finally:
            report.write_text(json.dumps(summary, indent=2) + "\n")
            if os.environ.get("LINT_DEFER_REPORTS") != "1":
                copy_output(log)
            show_log(log)


if __name__ == "__main__":
    sys.exit(entrypoint(main))
