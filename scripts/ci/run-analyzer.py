#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one analyzer Make target with CI coverage and failure checks."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from analyzer_policy import source_policy  # noqa: E402
from analyzer_report import markdown_block  # noqa: E402
from lint_common import entrypoint, report_lock, run  # noqa: E402
from style.checkpatch import checker_path  # noqa: E402

TOOLS = {"sparse": "sparse", "smatch": "smatch", "coccicheck": "spatch", "cppcheck": "cppcheck",
         "checkpatch": "checkpatch.pl"}


def complete_native_report(report):
    tool = report.get("tool")
    if tool == "checkpatch":
        checked = report.get("checked_files")
        completed = report.get("completed_files")
        remaining, ignored = report.get("remaining"), report.get("ignored", 0)
        findings = report.get("findings", remaining)
        return (all(type(value) is int and value >= 0 for value in (remaining, ignored, findings)) and
                findings == remaining + ignored and
                report.get("complete") is True and not report.get("failures") and
                report.get("native_status") == int(bool(findings)) and
                isinstance(checked, list) and bool(checked) and
                checked == report.get("selected_files") and
                isinstance(completed, list) and
                sorted(str((ROOT / path).resolve()) for path in checked) == sorted(completed))
    if tool in {"sparse", "smatch"}:
        return (bool(report.get("translation_units")) and report.get("make_status") == 0 and
                report.get("errors") == 0 and not report.get("unchecked_files") and
                not report.get("unrecorded_checks"))
    if tool == "coccicheck":
        rules = report.get("rules")
        return (isinstance(rules, list) and bool(rules) and all(
            row.get("complete") is True and row.get("native_status") == 0 and
            not row.get("failures") and row.get("handled") for row in rules))
    if tool == "cppcheck":
        profiles = report.get("profiles")
        return (report.get("kernel_make_status") == 0 and
                report.get("userspace_make_status") == 0 and
                not report.get("unchecked_files") and not report.get("unrecorded_checks") and
                isinstance(profiles, list) and len(profiles) == 2 and
                {row.get("profile") for row in profiles} == {"kernel", "userspace"} and all(
                    row.get("complete") is True and row.get("native_status") in {0, 3} and
                    not row.get("failures") and row.get("translation_units") and
                    row.get("checked_files") for row in profiles))
    return False


def job_status(make_status, report):
    """Return 0 for clean scans, 1 for findings and 2 for incomplete analysis."""
    status = report.get("exit_code")
    if (report.get("tool") not in TOOLS or
            type(status) is not int or status not in (0, 1) or
            make_status != (2 if status else 0) or
            report.get("outcome") != ("findings" if status else "clean") or
            not complete_native_report(report) or
            not isinstance(report.get("checked_files"), list)):
        return 2
    remaining = report.get("remaining")
    if type(remaining) is not int or remaining < 0 or bool(status) != bool(remaining):
        return 2
    tool = report["tool"]
    scope = source_policy(tool)
    excluded = {rule["path"] for rule in scope["exclude_directories"]}
    roots = [root for root in scope["source_roots"] if root not in excluded]
    checked = report["checked_files"]
    if (any(not any(path.startswith(root + "/") for path in checked) for root in roots) or
            not any("/kunit/" in path for path in checked)):
        print("CI requires analysis records for every module component and KUnit sources, "
              "plus userspace where selected by policy.",
              file=sys.stderr)
        return 2
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=tuple(TOOLS))
    args = parser.parse_args()
    # Keep the same report protected through the final CI coverage gate.
    with report_lock(ROOT, args.tool) as lock_fd:
        return analyze(args.tool, lock_fd)


def analyze(tool, lock_fd):
    kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR", ""))
    config_path = kernel / ".config"
    config = config_path.read_text() if config_path.is_file() else ""
    if tool != "checkpatch":
        if not (kernel / "Module.symvers").is_file():
            raise ValueError("Set KDIR to a prepared kernel build tree with Module.symvers")
        if not any(line in {"CONFIG_KUNIT=y", "CONFIG_KUNIT=m"} for line in config.splitlines()):
            raise ValueError("The CI analysis kernel must enable CONFIG_KUNIT")
    executable = str(checker_path()) if tool == "checkpatch" else shutil.which(TOOLS[tool])
    if not executable:
        raise ValueError(f"{tool} is not installed")
    directory = ROOT / ".cache/lint"
    directory.mkdir(parents=True, exist_ok=True)
    provenance = Path("/usr/local/share/scst-ci") / (tool + "-source.txt")
    # Keep the existing preparation gate; the common Make frontend owns
    # metadata and the human-readable report for both local and CI runs.
    subprocess.check_output([executable, "--version"], text=True)
    (directory / "kernel.config").write_text(config)
    models = provenance.with_name("smatch-data.sha256")
    if tool == "smatch" and models.exists():
        shutil.copyfile(models, directory / "smatch-data.sha256")
    identity = str(uuid.uuid4())
    env = dict(os.environ, KDIR=str(kernel.resolve()), SCST_LINT_KDIR=str(kernel.resolve()),
               KUNIT_TEST="y", KUNIT_LABEL="ALL", LINT_DEFER_REPORTS="1",
               CPPCHECK_PROJECT="", CPPCHECK_USERSPACE_PROJECT="",
               SCST_LINT_RUN_ID=identity, SCST_LINT_CI_WRAPPER="1",
               LINT_REPORT_LOCK_TOOL=tool, LINT_REPORT_LOCK_FD=str(lock_fd))
    report = {}
    frontend = {}
    try:
        # Make maps both findings and driver failures to 2. The current run's
        # report distinguishes them; neither a failed make nor a report alone
        # is sufficient to classify the run as completed source findings.
        # The frontend in turn gives the driver time to stop native children.
        result = run(["make", "-j2", tool, f"KDIR={kernel.resolve()}",
                      "KUNIT_TEST=y", "KUNIT_LABEL=ALL", "WERROR=n"], cwd=ROOT, env=env,
                     pass_fds=(lock_fd,), cancel_timeout=20)
    finally:
        path = directory / f"{tool}.json"
        if path.exists():
            try:
                candidate = json.loads(path.read_text())
            except ValueError:
                candidate = None
            if (isinstance(candidate, dict) and candidate.get("run_id") == identity and
                    candidate.get("tool") == tool):
                report = candidate
        path = directory / f"{tool}.run.json"
        if path.exists():
            try:
                frontend = json.loads(path.read_text())
            except ValueError:
                frontend = {}
    status = job_status(result.returncode, report)
    # Make also maps a failed report frontend to 2; do not mistake that failure
    # for completed source findings just because a native report exists.
    if (not isinstance(frontend, dict) or frontend.get("run_id") != identity or
            frontend.get("tool") != tool or frontend.get("status") != status or
            frontend.get("state") != report.get("outcome")):
        status = 2
    if status == 1:
        print(f"::error::{tool}: {report['remaining']} source finding(s); "
              "analysis completed.")
    summary = (f"CI validation: {'PASS' if status == 0 else 'FAIL'}; {tool}: "
               f"outcome={report.get('outcome', 'missing')}, "
               f"remaining={report.get('remaining', 'unknown')}, "
               f"make exit={result.returncode}, job exit={status}\n")
    print(summary, end="")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            detail = directory / f"{tool}.summary.md"
            if (isinstance(frontend, dict) and detail.is_file() and
                    frontend.get("run_id") == identity and frontend.get("status") == status and
                    (status in (0, 1) or frontend.get("state") == "incomplete")):
                stream.write(detail.read_text())
            stream.write(markdown_block(summary))
    return status


if __name__ == "__main__":
    sys.exit(entrypoint(main))
