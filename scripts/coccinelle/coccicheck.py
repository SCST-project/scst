#!/usr/bin/env python3
"""Run native kernel report rules without rewriting SCST sources or macros."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_common import copy_output, entrypoint, log_path, run, show_log  # noqa: E402
from lint_kbuild import build_lock  # noqa: E402
from lint_scope import select_sources  # noqa: E402

REPORT = re.compile(r"^\s*virtual\s+(\w+\s*,\s*)*report([\s,]|$)", re.MULTILINE)
# Do not match progress mentioning timeout.c or a function named timeout.
FAILURE = re.compile(
    r"^\s*(?:(?:parse|parsing|lexical|semantic|syntax|type|fatal|internal) error\b|"
    r"(?:warning|error|EXN)\s*:|uncaught exception\b|"
    r"Traceback \(most recent call last\):|(?:TIMEOUT|Not_found)\s*$|"
    r"timeout \(we abort\)(?::|$)|Timeout at |timed out(?:\s|:|$)|"
    r"\S+: (?:lexical|parse|semantic) error:|=\s*error in |"
    r"An error occurred when attempting to transform some files\.)", re.IGNORECASE)
PYTHON_WARNING = re.compile(r"^[^:\r\n]+:\d+: [A-Za-z]\w*Warning:")
STARTED = "SCST_COCCI_STARTED"
COMPLETE = "SCST_COCCI_COMPLETE"
FINDING = "SCST_COCCI_FINDING"


def metadata(text, name):
    match = re.search(r"^//[^\S\n]*" + name + r":[^\S\n]*(.*)$", text, re.MULTILINE)
    return match[1] if match else ""


def rule_options(text):
    options = shlex.split(metadata(text, "Options"))
    for option in options:
        if (option.split("=", 1)[0] in {
                "--jobs", "--max", "--index", "--file-groups", "--dir", "--cocci-file",
                "--in-place", "--out-place", "--suffix", "--patch", "-D", "-U"}
                or option.startswith("-o")):
            raise ValueError(f"rule changes wrapper selection or report mode: {option}")
    # Native quiet flags hide parser errors and per-input handling records.
    return [option for option in options if option not in {"--quiet", "--very-quiet", "-q"}]


def instrument_rule(text, destination):
    first = re.search(r"^@", text, re.MULTILINE)
    if not first:
        raise ValueError("Coccinelle rule has no semantic patch")
    initialize = f'''@initialize:python@
@@
import coccilib.report
scst_native_report = coccilib.report.print_report
def scst_report(*args, **kwargs):
    scst_native_report(*args, **kwargs)
    print("{FINDING}", flush=True)
coccilib.report.print_report = scst_report
print("{STARTED}", flush=True)

'''
    finalize = f'\n@finalize:python@\n@@\nprint("{COMPLETE}", flush=True)\n'
    destination.write_text(text[:first.start()] + initialize + text[first.start():] + finalize)


def coverage(output, selected, native_status):
    lines = output.splitlines()
    handled = {Path(line.removeprefix("HANDLING: ")).resolve()
               for line in lines if line.startswith("HANDLING: ")}
    failures = [line for line in lines if FAILURE.search(line) or PYTHON_WARNING.search(line)]
    if lines.count(STARTED) != 1 or lines.count(COMPLETE) != 1:
        failures.append("rule initialization/finalization did not complete exactly once")
    missing = sorted(str(path) for path in set(selected) - handled)
    failures.extend(f"no native handling record for {path}" for path in missing)
    # Some rules print locations directly instead of using coccilib.report.
    locations = sum(bool(re.match(r"^.+:\d+(?::\d+(?:-\d+)?)?:", line))
                    for line in lines if not PYTHON_WARNING.search(line))
    findings = max(lines.count(FINDING), locations)
    return {"native_status": native_status, "findings": findings,
            "handled": sorted(str(path) for path in handled & set(selected)),
            "failures": failures, "complete": not native_status and not failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    # Also serialize log replacement by concurrent invocations in this worktree.
    with build_lock(ROOT):
        log = log_path(ROOT, "coccicheck.log")
        report = log.with_suffix(".json")
        summary = {"tool": "coccicheck", "run_id": os.environ.get("SCST_LINT_RUN_ID"),
                   "outcome": "incomplete", "exit_code": 2, "rules": [],
                   "remaining": 0, "checked_files": []}
        report.write_text(json.dumps(summary, indent=2) + "\n")
        show_log(log)
        try:
            selected = select_sources(ROOT, args.files, "coccicheck")
            summary["selected_files"] = [p.relative_to(ROOT).as_posix() for p in selected]
            if not selected:
                print("No eligible Coccinelle inputs; analysis skipped.")
                summary.update(outcome="skipped", exit_code=0)
                return 0
            spatch = shutil.which("spatch")
            if not spatch:
                raise ValueError("spatch is not installed")
            kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR") or
                          f"/lib/modules/{os.uname().release}/build")
            directory = kernel / "scripts/coccinelle"
            paths = sorted(directory.rglob("*.cocci"))
            if not paths:
                raise ValueError(f"no kernel Coccinelle rules in {directory}")
            with log.open("ab") as stream:
                result = run([spatch, "--version"], stdout=stream, stderr=subprocess.STDOUT)
            if result.returncode:
                raise ValueError(f"spatch version probe failed: {result.returncode}")
            version = log.read_bytes()
            match = re.search(rb"^spatch version (\S+)", version, re.MULTILINE)
            version = match[1].decode() if match else ""
            rules = []
            for path in paths:
                text = path.read_text()
                if not REPORT.search(text):
                    with log.open("a") as stream:
                        stream.write(f"Skip rule without report mode: {path}\n")
                    continue
                required = metadata(text, "Requires")
                if required and (not version or run(
                        ["sort", "-CV"], input=f"{required}\n{version}\n".encode()).returncode):
                    raise ValueError(f"{path} requires spatch {required}; installed: {version}")
                rules.append((path, text, rule_options(text)))
            if not rules:
                raise ValueError("no kernel Coccinelle rules declare report mode")
            with tempfile.TemporaryDirectory(prefix="coccicheck-", dir=log.parent) as temporary:
                work = Path(temporary)
                groups = work / "files"
                if any("\n" in str(p) or "\r" in str(p) for p in selected):
                    raise ValueError("Coccinelle file groups cannot represent newline paths")
                groups.write_text("\n\n".join(map(str, selected)) + "\n")
                for index, (path, text, options) in enumerate(rules, 1):
                    rule = work / "report.cocci"
                    instrument_rule(text, rule)
                    output = work / "native.log"
                    command = [spatch, *options, "--parse-error-msg", "--show-trying",
                               "--disable-worth-trying-opt", "--no-show-diff", "-D", "report",
                               "--cocci-file", str(rule), "--file-groups", str(groups)]
                    with log.open("a") as stream:
                        stream.write(f"\nRule {index}/{len(rules)}: {path}\n")
                    try:
                        with output.open("wb") as stream:
                            result = run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                         progress=f"Coccinelle {index}/{len(rules)} {path.name}")
                    finally:
                        with log.open("ab") as stream:
                            copy_output(output, stream)
                    record = coverage(output.read_text(errors="replace"), selected,
                                      result.returncode)
                    summary["rules"].append({"rule": str(path), **record})
                    summary["remaining"] += record["findings"]
                    report.write_text(json.dumps(summary, indent=2) + "\n")
            if any(not record["complete"] for record in summary["rules"]):
                print("Coccinelle analysis is incomplete; inspect the full log and rule records.",
                      file=sys.stderr)
                return 2
            summary["checked_files"] = summary["selected_files"]
            status = int(bool(summary["remaining"]))
            summary.update(outcome="findings" if status else "clean", exit_code=status)
            print(f"Coccinelle: {len(rules)} rules, {len(selected)} inputs, "
                  f"{summary['remaining']} finding(s).")
            return status
        finally:
            report.write_text(json.dumps(summary, indent=2) + "\n")
            if os.environ.get("LINT_DEFER_REPORTS") != "1":
                copy_output(log)
            show_log(log)


if __name__ == "__main__":
    sys.exit(entrypoint(main))
