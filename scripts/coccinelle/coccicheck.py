#!/usr/bin/env python3
"""Run native kernel report rules with explicit exceptions and macro coverage limits."""

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
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from analyzer_report import show_result  # noqa: E402
from lint_common import copy_output, entrypoint, log_path, report_lock, run, show_log  # noqa: E402
from lint_kbuild import build_lock  # noqa: E402
from lint_scope import in_scope, select_sources  # noqa: E402
from analyzer_policy import load_policy  # noqa: E402
from coccinelle.compat import adapt  # noqa: E402
from coccinelle.frontend import macro_definition_error  # noqa: E402
from coccinelle.model import prepare as prepare_model  # noqa: E402
from coccinelle.exceptions import source_exceptions, match_exception  # noqa: E402

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
                "--in-place", "--out-place", "--suffix", "--patch", "-D", "-U",
                "--filter-define-error", "--filter-msg-define-error", "--filter-msg"}
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


def coverage(output, selected, native_status, *, rule="", entries=()):
    lines = output.splitlines()
    handled = {Path(line.removeprefix("HANDLING: ")).resolve()
               for line in lines if line.startswith("HANDLING: ")}
    failures, limits, notices = [], [], []
    policy = load_policy("coccicheck")
    macro_policy = policy["macro_definition_errors"]
    index = 0
    while index < len(lines):
        limitation = macro_definition_error(ROOT, lines, index) if macro_policy["enabled"] else None
        if limitation and in_scope(ROOT / limitation[1]["file"], ROOT, "coccicheck"):
            index, item = limitation
            limits.append(dict(item, reason=macro_policy["reason"]))
            continue
        line = lines[index]
        notice = next((item for item in policy["tool_warnings"] if item["id"] == rule
                       and re.fullmatch(item["pattern"], line)), None)
        if notice and PYTHON_WARNING.search(line):
            notices.append(dict(message=line, reason=notice["reason"]))
        elif FAILURE.search(line) or PYTHON_WARNING.search(line):
            failures.append(line)
        index += 1
    if lines.count(STARTED) != 1 or lines.count(COMPLETE) != 1:
        failures.append("rule initialization/finalization did not complete exactly once")
    missing = sorted(str(path) for path in set(selected) - handled)
    failures.extend(f"no native handling record for {path}" for path in missing)
    # Some rules print locations directly instead of using coccilib.report.
    locations = sum(bool(re.match(r"^.+:\d+(?::\d+(?:-\d+)?)?:", line))
                    for line in lines if not PYTHON_WARNING.search(line))
    findings = max(lines.count(FINDING), locations)
    diagnostics = []
    for line in lines:
        match = re.fullmatch(r"(.+?):(\d+):(?:(\d+(?:-\d+)?):)?\s*(.*)", line)
        if not match or PYTHON_WARNING.search(line):
            continue
        name, number, column, message = match.groups()
        try:
            name = (ROOT / name).resolve().relative_to(ROOT).as_posix()
        except ValueError:
            pass
        exception = match_exception(entries, rule, name, int(number))
        diagnostics.append(dict(file=name, line=int(number), message=message,
                                native=line, exception=exception))
    ignored = sum(bool(row["exception"]) for row in diagnostics)
    return {"native_status": native_status, "findings": findings,
            "remaining": findings - ignored, "ignored": ignored, "diagnostics": diagnostics,
            "coverage_limits": limits, "tool_warnings": notices,
            "handled": sorted(str(path) for path in handled & set(selected)),
            "failures": failures, "complete": not native_status and not failures}


def effective_options(command, directory):
    result = run([*command, "--print-options-only"], stdout=subprocess.PIPE,
                 stderr=subprocess.STDOUT)
    directory.write_bytes(result.stdout)
    lines = result.stdout.decode(errors="replace").splitlines()
    options = [shlex.split(line.removeprefix("options: ")) for line in lines
               if line.startswith("options: ")]
    if result.returncode or len(options) != 1:
        raise ValueError(f"Cannot verify effective Coccinelle options: {directory}")
    effective = options[0][1:]
    expected = [*command[1:], "--print-options-only"]
    if effective != expected:
        raise ValueError("Implicit Coccinelle configuration changes the invocation; move its "
                         f"options to SPflags for validation: {directory}")
    return effective


def publish_progress(current, total, rule):
    """Expose the current rule without mixing progress into native evidence."""
    if not os.environ.get("SCST_LINT_PROGRESS"):
        return
    path = Path(os.environ["SCST_LINT_PROGRESS"])
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(dict(run_id=os.environ.get("SCST_LINT_RUN_ID"),
                                         current=current, total=total, rule=rule.name)) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    # Also serialize log replacement by concurrent invocations in this worktree.
    with report_lock(ROOT, "coccicheck"), build_lock(ROOT):
        log = log_path(ROOT, "coccicheck.log")
        report = log.with_suffix(".json")
        summary = {"tool": "coccicheck", "run_id": os.environ.get("SCST_LINT_RUN_ID"),
                   "outcome": "incomplete", "exit_code": 2, "rules": [],
                   "remaining": 0, "ignored": 0, "checked_files": []}
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
            policy = load_policy("coccicheck")
            summary["skipped_rules"] = []
            for path in paths:
                text = path.read_text()
                if not REPORT.search(text):
                    if not policy["skip_non_report_rules"]:
                        raise ValueError(f"rule has no report mode: {path}")
                    summary["skipped_rules"].append(str(path))
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
            entries = [entry for path in selected for entry in source_exceptions(
                path.read_text(), path.relative_to(ROOT).as_posix())]
            known = {path.stem for path in paths}
            for entry in entries:
                if entry["rule"] not in known:
                    raise ValueError(f"Unknown Coccinelle rule: {entry['rule']}")
            if len({path.stem for path, _, _ in rules}) != len(rules):
                raise ValueError("Coccinelle rule basenames must be unique")
            summary["inline_exceptions"] = entries
            # Generated inputs, native streams and adaptations are evidence.
            work = Path(tempfile.mkdtemp(prefix="coccicheck-", dir=log.parent))
            summary["records_directory"] = str(work)
            groups = work / "files"
            if any("\n" in str(p) or "\r" in str(p) for p in selected):
                raise ValueError("Coccinelle file groups cannot represent newline paths")
            groups.write_text("\n\n".join(map(str, selected)) + "\n")
            for index, (path, text, options) in enumerate(rules, 1):
                publish_progress(index, len(rules), path)
                started = time.monotonic()
                rule = work / f"{index:03d}-{path.name}"
                shutil.copyfile(path, work / f"{index:03d}-original.cocci")
                text, adaptation = adapt(path, text)
                instrument_rule(text, rule)
                rule.with_suffix(".json").write_text(json.dumps(adaptation, indent=2) + "\n")
                output = work / f"{index:03d}-native.log"
                command = [spatch, *options, "--parse-error-msg", "--show-trying",
                           "--disable-worth-trying-opt", "--no-show-diff", "-D", "report",
                           "--cocci-file", str(rule)]
                command = prepare_model(spatch, command, work / f"{index:03d}-builtins.h")
                effective_options(command, work / f"{index:03d}-options.log")
                command += ["--file-groups", str(groups)]
                (work / f"{index:03d}-command.json").write_text(json.dumps(command) + "\n")
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
                                  result.returncode, rule=path.stem,
                                  entries=entries)
                summary["rules"].append({"rule": str(path), "adaptation": adaptation,
                                         "duration_seconds": time.monotonic() - started, **record})
                summary["remaining"] += record["remaining"]
                summary["ignored"] += record["ignored"]
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
