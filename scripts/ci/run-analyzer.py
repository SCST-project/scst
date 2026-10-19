#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one analyzer Make target with CI coverage and failure checks."""

import argparse
import hashlib
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
from lint_common import copy_output, entrypoint, run  # noqa: E402

TOOLS = {"sparse": "sparse", "smatch": "smatch", "coccicheck": "spatch", "cppcheck": "cppcheck"}


def complete_native_report(report):
    tool = report.get("tool")
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


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def job_status(make_status, report):
    """Only a completed scan with source findings may become advisory."""
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
    # Temporary rollout policy: completed source findings are advisory.
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=tuple(TOOLS))
    args = parser.parse_args()
    kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR", ""))
    if not (kernel / "Module.symvers").is_file():
        raise ValueError("Set KDIR to a prepared kernel build tree with Module.symvers")
    config = (kernel / ".config").read_text()
    if not any(line in {"CONFIG_KUNIT=y", "CONFIG_KUNIT=m"} for line in config.splitlines()):
        raise ValueError("The CI analysis kernel must enable CONFIG_KUNIT")
    executable = shutil.which(TOOLS[args.tool])
    if not executable:
        raise ValueError(f"{args.tool} is not installed")
    directory = ROOT / ".cache/lint"
    directory.mkdir(parents=True, exist_ok=True)
    provenance = Path("/usr/local/share/scst-ci") / (args.tool + "-source.txt")
    environment = {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "kernel": str(kernel.resolve()), "kernel_config_sha256": digest(kernel / ".config"),
        "tool": executable, "tool_sha256": digest(Path(executable)),
        "version": subprocess.check_output([executable, "--version"], text=True).strip(),
        "source_provenance": provenance.read_text() if provenance.exists() else "unavailable",
        "kunit_test": "y",
    }
    environment_text = json.dumps(environment, indent=2) + "\n"
    (directory / f"{args.tool}.environment.json").write_text(environment_text)
    print(environment_text, flush=True)
    (directory / "kernel.config").write_text(config)
    models = provenance.with_name("smatch-data.sha256")
    if args.tool == "smatch" and models.exists():
        shutil.copyfile(models, directory / "smatch-data.sha256")
    policy = subprocess.check_output([sys.executable, "-B", str(ROOT / "scripts/analyzer_policy.py"),
                                      "show", args.tool, "--format=json"], text=True)
    (directory / f"{args.tool}.policy.json").write_text(policy)
    print(policy, flush=True)
    identity = str(uuid.uuid4())
    env = dict(os.environ, KDIR=str(kernel.resolve()), SCST_LINT_KDIR=str(kernel.resolve()),
               KUNIT_TEST="y", KUNIT_LABEL="ALL", DIFFBR="", LINT_DEFER_REPORTS="1",
               SCST_LINT_RUN_ID=identity)
    report = {}
    try:
        # Make maps both findings and driver failures to 2. The current run's
        # report distinguishes them; neither a failed make nor a report alone
        # is sufficient to classify the run as completed source findings.
        result = run(["make", "-j2", args.tool, f"KDIR={kernel.resolve()}",
                      "KUNIT_TEST=y", "KUNIT_LABEL=ALL", "DIFFBR=", "WERROR=n"], cwd=ROOT, env=env)
    finally:
        path = directory / f"{args.tool}.json"
        if path.exists():
            candidate = json.loads(path.read_text())
            if (isinstance(candidate, dict) and candidate.get("run_id") == identity and
                    candidate.get("tool") == args.tool):
                report = candidate
                log = directory / f"{args.tool}.log"
                if log.exists():
                    print(f"\nFull report: {log}", flush=True)
                    copy_output(log, sys.stdout.buffer)
    status = job_status(result.returncode, report)
    if status == 0 and report["exit_code"] == 1:
        print(f"::warning::{args.tool}: {report['remaining']} source finding(s); "
              "temporary report mode, analysis completed.")
    summary = (f"{args.tool}: outcome={report.get('outcome', 'missing')}, "
               f"remaining={report.get('remaining', 'unknown')}, "
               f"make exit={result.returncode}, job exit={status}\n")
    print(summary, end="")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write(summary)
    return status


if __name__ == "__main__":
    sys.exit(entrypoint(main))
