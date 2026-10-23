#!/usr/bin/env python3
"""Run Sparse or Smatch through SCST Kbuild and retain complete diagnostic logs."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_common import copy_output, entrypoint, log_path, show_log  # noqa: E402
from lint_kbuild import build_lock, collect, unchecked_invocations, validate_checker  # noqa: E402
from lint_scope import select_sources  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("sparse", "smatch"))
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    with build_lock(ROOT):
        log = log_path(ROOT, args.tool + ".log")
        report = log.with_suffix(".json")
        summary = {"tool": args.tool, "outcome": "incomplete", "exit_code": 2,
                   "run_id": os.environ.get("SCST_LINT_RUN_ID"),
                   "kunit_test": os.environ.get("KUNIT_TEST", "n"),
                   "log": str(log), "selected_files": []}
        # Replace the previous result before any preparation that can fail.
        report.write_text(json.dumps(summary, indent=2) + "\n")
        show_log(log)
        try:
            selected = select_sources(ROOT, args.files, args.tool)
            summary["selected_files"] = [p.relative_to(ROOT).as_posix() for p in selected]
            if not selected:
                print("No module C files selected; no analysis requested.")
                summary.update(outcome="skipped", exit_code=0)
                return 0
            validate_checker(ROOT, args.tool, log)
            # Keep the pre-spawn and completed records, including on interruption.
            directory = Path(tempfile.mkdtemp(prefix=args.tool + "-checks-", dir=log.parent))
            summary["records_directory"] = str(directory)
            status, records = collect(ROOT, args.tool, directory, log)
            checked = {Path(row["file"]) for row in records}
            summary["checked_files"] = sorted(path.relative_to(ROOT).as_posix() for path in checked)
            missing = ([str(path) for path in selected if path.suffix == ".c" and path not in checked]
                       if args.files else [])
            unrecorded = unchecked_invocations(ROOT, args.tool, log, records)
            errors = sum(row["errors"] for row in records)
            findings = sum(row["findings"] for row in records)
            ignored = sum(len(row["ignored"]) for row in records)
            remaining = findings - ignored
            summary.update(make_status=status, translation_units=len(records),
                           errors=errors, findings=findings, ignored=ignored, remaining=remaining,
                           unchecked_files=missing, unrecorded_checks=unrecorded)
            if missing:
                print("Selected sources absent from this build configuration:\n" +
                      "\n".join(missing), file=sys.stderr)
            adapter_failed = any(line.startswith(b"SCST checker failed:")
                                 for line in log.read_bytes().splitlines())
            if unrecorded:
                print("Kbuild CHECK steps without records:\n" + "\n".join(unrecorded), file=sys.stderr)
            if (status or not records or errors or missing or unrecorded or adapter_failed or
                    any(row["returncode"] for row in records)):
                print(f"{args.tool}: incomplete analysis (make={status}, "
                      f"checker invocations={len(records)}, errors={errors}).", file=sys.stderr)
                return 2
            result = 1 if remaining else 0
            summary.update(outcome="findings" if remaining else "clean", exit_code=result)
            print(f"{args.tool}: {len(records)} translation units, {findings} diagnostic(s), "
                  f"{ignored} ignored, {remaining} remaining.")
            return result
        finally:
            report.write_text(json.dumps(summary, indent=2) + "\n")
            if os.environ.get("LINT_DEFER_REPORTS") != "1":
                copy_output(log)
            show_log(log)


if __name__ == "__main__":
    sys.exit(entrypoint(main))
