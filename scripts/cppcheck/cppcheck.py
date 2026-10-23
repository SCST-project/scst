#!/usr/bin/env python3
"""Run Cppcheck on fresh kernel and userspace commands without project models."""

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
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_common import copy_output, entrypoint, log_path, run, show_log  # noqa: E402
from lint_kbuild import build_lock, collect, unchecked_invocations  # noqa: E402
from lint_scope import select_sources  # noqa: E402

INCOMPLETE = {"syntaxError", "unknownMacro", "internalAstError", "internalError",
              "preprocessorErrorDirective", "noValidConfiguration", "cppcheckError",
              "directiveAsMacroParameter", "missingInclude", "missingIncludeSystem",
              "toomanyconfigs"}


def native_result(xml, progress, checkers, status, expected, root):
    failures = []
    diagnostics = []
    try:
        document = ET.fromstring(xml)
        if document.tag != "results" or document.get("version") != "2" or (
                document.find("cppcheck") is None or document.find("errors") is None):
            raise ValueError("unexpected Cppcheck XML structure")
        for error in document.findall("errors/error"):
            if not error.get("id") or not error.get("severity") or error.get("msg") is None:
                raise ValueError("incomplete Cppcheck diagnostic")
            diagnostics.append({**error.attrib,
                                "locations": [location.attrib for location in error.findall("location")]})
            if error.get("id") in INCOMPLETE:
                failures.append(f"{error.get('id')}: {error.get('msg')}")
    except (ET.ParseError, ValueError) as error:
        failures.append(f"invalid or incomplete XML report: {error}")
    if status not in {0, 3} or (status == 3 and not diagnostics):
        failures.append(f"unexpected native status: {status}")
    if ("No critical errors encountered." not in checkers or
            "There were critical errors" in checkers or
            not re.search(r"^Yes\s+\S+", checkers, re.MULTILINE)):
        failures.append("missing checker coverage or critical native errors")
    checked = set()
    for line in progress.splitlines():
        match = re.match(r"^Checking (.+?\.c)(?: |:).*\.\.\.$", line)
        if match:
            checked.add((root / match[1]).resolve())
        if re.match(r"^(?:cppcheck: (?:error|warning):|Failed to|Internal error)", line):
            failures.append(line)
    missing = sorted(str(path) for path in set(expected) - checked)
    failures.extend(f"no native checking record for {path}" for path in missing)
    return {"native_status": status, "diagnostics": diagnostics, "failures": failures,
            "checked_files": sorted(str(path) for path in checked & set(expected)),
            "remaining": len(diagnostics), "complete": not failures}


def capture_userspace(directory, log):
    env = dict(os.environ, SCST_LINT_RECORDS=str(directory))
    compiler = shlex.join([sys.executable, str(HERE / "capture.py"), "userspace"])
    command = ["make", "--no-silent", "-k", "-B", "-C", str(ROOT), "lint-userspace",
               "CC=" + compiler]
    with log.open("ab") as stream:
        result = run(command, env=env, stdout=stream, stderr=subprocess.STDOUT,
                     progress="Cppcheck userspace build context")
    records = [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]
    return result.returncode, records


def project_entry(record):
    """Resolve paths from the compiler cwd, not the analyzer's cwd.

    Native project import leaves forced includes relative and does not use
    -isystem paths in its own frontend. Pass the same real headers via -I.
    Keep the original command untouched in the capture record.
    """
    directory = Path(record["directory"])
    arguments = iter(record["arguments"])
    normalized = []
    system_includes = []
    for argument in arguments:
        option = next((flag for flag in ("-isystem", "-include", "-I")
                       if argument.startswith(flag)), None)
        if option is None:
            normalized.append(argument)
            continue
        value = argument[len(option):] or next(arguments, "")
        if not value:
            raise ValueError(f"missing operand for compiler option {option}")
        path = directory / value
        if option != "-include" or path.is_file():
            value = str(path.resolve())
        if option == "-isystem":
            system_includes.extend(["-I", value])
        else:
            normalized.extend([option, value])
    # GCC searches explicit system directories after every ordinary -I path.
    normalized.extend(system_includes)
    return {"file": record["file"], "directory": str(directory), "arguments": normalized}


def analyze(profile, records, directory, log):
    project = directory / f"{profile}.json"
    # Keep each distinct compiler context, including repeated files with
    # different definitions. Do not strip include paths or rewrite headers.
    commands = {json.dumps(project_entry(row), sort_keys=True) for row in records}
    project.write_text("[\n" + ",\n".join(sorted(commands)) + "\n]\n")
    stdout = directory / f"{profile}.stdout"
    xml = directory / f"{profile}.xml"
    checkers = directory / f"{profile}.checkers"
    checkers.write_text("")
    command = ["cppcheck", "--project=" + str(project), "--enable=all", "--inconclusive",
               "--check-level=exhaustive", "--force", "--xml", "--xml-version=2",
               "--error-exitcode=3", "--checkers-report=" + str(checkers)]
    try:
        with stdout.open("wb") as output, xml.open("wb") as errors:
            result = run(command, cwd=ROOT, stdout=output, stderr=errors,
                         env=dict(os.environ, NO_COLOR="1"), progress=f"Cppcheck {profile}")
    finally:
        with log.open("ab") as stream:
            stream.write(f"\nCppcheck {profile}: {shlex.join(command)}\n".encode())
            for path in (stdout, xml, checkers):
                if path.exists():
                    copy_output(path, stream)
    record = native_result(xml.read_text(errors="replace"), stdout.read_text(errors="replace"),
                           checkers.read_text(errors="replace"), result.returncode,
                           [Path(row["file"]) for row in records], ROOT)
    return {"profile": profile, "translation_units": len(commands), **record}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    with build_lock(ROOT):
        log = log_path(ROOT, "cppcheck.log")
        report = log.with_suffix(".json")
        summary = {"tool": "cppcheck", "run_id": os.environ.get("SCST_LINT_RUN_ID"),
                   "outcome": "incomplete", "exit_code": 2, "profiles": [],
                   "remaining": 0, "checked_files": []}
        report.write_text(json.dumps(summary, indent=2) + "\n")
        show_log(log)
        try:
            selected = select_sources(ROOT, args.files, "cppcheck")
            summary["selected_files"] = [p.relative_to(ROOT).as_posix() for p in selected]
            if not selected:
                print("No eligible Cppcheck inputs; analysis skipped.")
                summary.update(outcome="skipped", exit_code=0)
                return 0
            if not shutil.which("cppcheck"):
                raise ValueError("cppcheck is not installed")
            with log.open("ab") as stream:
                result = run(["cppcheck", "--version"], stdout=stream, stderr=subprocess.STDOUT)
            if result.returncode:
                raise ValueError(f"cppcheck version probe failed: {result.returncode}")
            # Fresh records prevent stale incremental-build state from implying
            # coverage. Retain commands and native reports for diagnosis.
            directory = Path(tempfile.mkdtemp(prefix="cppcheck-", dir=log.parent))
            summary["records_directory"] = str(directory)
            kernel_records = directory / "kernel"
            user_records = directory / "userspace"
            kernel_records.mkdir()
            user_records.mkdir()
            checker = [sys.executable, str(HERE / "capture.py"), "kernel"]
            kernel_status, kernel = collect(ROOT, "cppcheck", kernel_records, log, checker=checker)
            missing_checks = unchecked_invocations(ROOT, "cppcheck", log, kernel)
            user_status, userspace = capture_userspace(user_records, log)
            records = kernel + userspace
            captured = {Path(row["file"]) for row in records}
            missing = ([str(path) for path in selected if path.suffix == ".c" and path not in captured]
                       if args.files else [])
            summary.update(kernel_make_status=kernel_status, userspace_make_status=user_status,
                           unchecked_files=missing, unrecorded_checks=missing_checks)
            if (kernel_status or user_status or not kernel or not userspace or missing or
                    missing_checks or any(row["returncode"] for row in records)):
                raise ValueError("incomplete Cppcheck build context; inspect the build log and summary")
            for profile, rows in (("kernel", kernel), ("userspace", userspace)):
                result = analyze(profile, rows, directory, log)
                summary["profiles"].append(result)
                summary["remaining"] += result["remaining"]
                report.write_text(json.dumps(summary, indent=2) + "\n")
            if any(not row["complete"] for row in summary["profiles"]):
                print("Cppcheck analysis is incomplete; inspect the full native reports.", file=sys.stderr)
                return 2
            summary["checked_files"] = sorted(path.relative_to(ROOT).as_posix() for path in captured)
            status = int(bool(summary["remaining"]))
            summary.update(outcome="findings" if status else "clean", exit_code=status)
            print(f"Cppcheck: {len(captured)} files, {summary['remaining']} diagnostic(s).")
            return status
        finally:
            report.write_text(json.dumps(summary, indent=2) + "\n")
            if os.environ.get("LINT_DEFER_REPORTS") != "1":
                copy_output(log)
            show_log(log)


if __name__ == "__main__":
    sys.exit(entrypoint(main))
