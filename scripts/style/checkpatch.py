#!/usr/bin/env python3
"""Check whole SCST C files with native Checkpatch and source-bound exceptions."""

import argparse
from collections import Counter
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
from analyzer_report import show_result  # noqa: E402
from lint_common import copy_output, entrypoint, log_path, report_lock, run, show_log  # noqa: E402
from lint_scope import select_sources, tracked_sources  # noqa: E402
from analyzer_policy import load_policy  # noqa: E402
from style.exceptions import apply_exceptions, source_exceptions  # noqa: E402

TOTAL = re.compile(r"total: (\d+) errors, (\d+) warnings, (?:(\d+) checks, )?\d+ lines checked")
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
    totals = [tuple(int(value or 0) for value in match.groups()) for line in text.splitlines()
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
        policy = load_policy("checkpatch")
        command = [str(tool), "--no-tree", "--root=" + str(ROOT), "--strict", "--show-types",
                   "--color=never", "--no-fix", "--no-fix-inplace",
                   "--max-line-length=" + str(policy["max_line_length"]),
                   "--file", *map(str, selected)]
        if not policy["strict"]:
            command.remove("--strict")
        if policy["disabled_checks"]:
            command.append("--ignore=" + ",".join(x["id"] for x in policy["disabled_checks"]))
        sources = {p.relative_to(ROOT).as_posix(): p.read_text(errors="surrogateescape")
                   for p in selected}
        symbol_sources = {p.relative_to(ROOT).as_posix(): p.read_text(errors="surrogateescape")
                          for p in tracked_sources(ROOT, "checkpatch")}
        symbol_sources.update(sources)
        entries = [e for name, source in symbol_sources.items()
                   for e in source_exceptions(source, name)
                   if name in sources or e.get("symbol")]
        try:
            with stdout.open("wb") as output, stderr.open("wb") as errors:
                result = run(command, cwd=directory, env=env, stdout=output, stderr=errors,
                             progress=f"Checkpatch ({len(selected)} files)")
        finally:
            with log.open("ab") as stream:
                for path in (stdout, stderr):
                    if path.exists():
                        copy_output(path, stream)
        native = stdout.read_bytes()
        record = native_report(native.decode(errors="replace"), stderr.read_text(errors="replace"),
                               result.returncode, selected)
        filtered, exempt, _ = apply_exceptions(native, ROOT, sources, policy,
                                                symbol_sources=symbol_sources)
        display = log.with_suffix(".selected.log")
        display.write_bytes(filtered + stderr.read_bytes())
        # Tool failures and missing per-file totals remain blocking even when
        # every ordinary finding has an applicable source exception.
        record.update(findings=record["remaining"], ignored=sum(exempt.values()),
                      remaining=record["remaining"] - sum(exempt.values()),
                      exception_counts=dict(exempt), inline_exceptions=entries,
                      selected_log=str(display))
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    with report_lock(ROOT, "checkpatch"):
        log = log_path(ROOT, "checkpatch.log")
        report = log.with_suffix(".json")
        summary = {"tool": "checkpatch", "run_id": os.environ.get("SCST_LINT_RUN_ID"),
                   "outcome": "incomplete", "exit_code": 2, "remaining": 0,
                   "checked_files": [], "selected_files": []}
        report.write_text(json.dumps(summary, indent=2) + "\n")
        show_log(log)
        try:
            selected = select_sources(ROOT, args.files, "checkpatch")
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
        except BaseException as error:
            summary.setdefault("failures", []).append(str(error) or type(error).__name__)
            raise
        finally:
            report.write_text(json.dumps(summary, indent=2) + "\n")
            if os.environ.get("LINT_DEFER_REPORTS") != "1":
                show_result(summary, log)
            show_log(log)


if __name__ == "__main__":
    sys.exit(entrypoint(main))
