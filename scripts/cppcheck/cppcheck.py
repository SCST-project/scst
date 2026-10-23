#!/usr/bin/env python3
"""Run Cppcheck on fresh kernel and userspace commands with reviewed models and native source exceptions."""

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
from analyzer_report import show_result  # noqa: E402
from lint_common import copy_output, entrypoint, log_path, report_lock, run, show_log  # noqa: E402
from lint_kbuild import build_lock  # noqa: E402
from lint_scope import in_scope, select_sources, tracked_sources  # noqa: E402
from analyzer_policy import load_policy, inline_inventory  # noqa: E402
from cppcheck.compiler import CompilerContext  # noqa: E402
from compile_commands import collect as export_commands, read_database  # noqa: E402
from cppcheck.kbuild import adapt, owned_source  # noqa: E402
from cppcheck.exceptions import validate_ids, unmatched_advice, excluded_sources, excluded_diagnostic  # noqa: E402
from cppcheck.system_headers import include_advice, matches_include  # noqa: E402

INCOMPLETE = {"syntaxError", "unknownMacro", "internalAstError", "internalError",
              "preprocessorErrorDirective", "noValidConfiguration", "cppcheckError",
              "directiveAsMacroParameter", "missingInclude", "missingIncludeSystem",
              "toomanyconfigs"}


def checker_inventory(text, version):
    """Describe native execution records, without changing coverage or findings."""
    rows = []
    for match in re.finditer(r"^(Yes|No)\s+([A-Za-z_]\w*::\w+)(?:[ \t]+require:([^\n]*))?[ \t]*$",
                             text, re.MULTILINE):
        active, name, requirements = match.groups()
        row = dict(name=name, active=active == "Yes", requirements=(requirements or "").strip())
        if not row["active"]:
            reason = "Reason not established from the native inventory"
            # Audited against 2.22.0 runChecks()/checker guards. Native require:
            # lists prerequisites, not the condition which caused a return.
            # checkCoutCerrMisusage even says 'c' while returning for C inputs.
            if version == "2.22.0":
                cpp = (any(req in {"c++", "c++03", "c++11"}
                           for req in row["requirements"].split(",")) or
                       name.startswith(("CheckStl::", "CheckExceptionSafety::")) or
                       (name.startswith("CheckClass::") and
                        name != "CheckClass::checkCtuOneDefinitionRule") or
                       name in {"CheckIO::checkCoutCerrMisusage", "CheckMemoryLeakInClass::check",
                                "CheckMemoryLeakNoVar::checkForUnsafeArgAlloc",
                                "CheckPostfixOperator::postfixOperator"})
                if cpp:
                    reason = "C++-specific checks (inputs are C)"
                elif name == "CheckOther::checkInterlockedDecrement":
                    reason = "Windows-specific checks (target is Linux)"
                elif name == "CheckUnusedFunctions::check":
                    # analyseWholeProgram(settings, logger, buildDir) performs
                    # this check without the logChecker call in check().
                    reason = "Build-directory unusedFunction pass is not registered in this inventory"
            row["reason"] = reason
        rows.append(row)
    return dict(version=version, checkers=rows)


def native_result(xml, progress, checkers, status, expected, root, advice=(), excluded=None):
    failures = []
    diagnostics = []
    version = None
    try:
        document = ET.fromstring(xml)
        if document.tag != "results" or document.get("version") != "2" or (
                document.find("cppcheck") is None or document.find("errors") is None):
            raise ValueError("unexpected Cppcheck XML structure")
        version = document.find("cppcheck").get("version")
        for error in document.findall("errors/error"):
            if not error.get("id") or not error.get("severity") or error.get("msg") is None:
                raise ValueError("incomplete Cppcheck diagnostic")
            diagnostics.append({**error.attrib,
                                "locations": [location.attrib for location in error.findall("location")]})
            row = diagnostics[-1]
            row["advisory"] = diagnostic_advice(root, row, advice)
            row["excluded"] = excluded_diagnostic(root, row, excluded or {})
            if error.get("id") in INCOMPLETE and not row["advisory"]:
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
    completed = []
    for line in progress.splitlines():
        match = re.match(r"^Checking (.+?\.c)(?: |:).*\.\.\.$", line)
        if match:
            checked.add((root / match[1]).resolve())
        match = re.match(r"^(\d+)/(\d+) files checked", line)
        if match:
            completed.append(tuple(map(int, match.groups())))
        if re.match(r"^(?:cppcheck: (?:error|warning):|Failed to|Internal error)", line):
            failures.append(line)
    remaining = sum(not (row.get("advisory") or row.get("excluded")) for row in diagnostics)
    unmatched = any(row["id"] == "unmatchedSuppression" and row.get("advisory")
                    for row in diagnostics)
    if status == 3 and not remaining and not unmatched:
        failures.append("native findings exit without active findings or validated unmatched declarations")
    missing = sorted(str(path) for path in set(expected) - checked)
    failures.extend(f"no native checking record for {path}" for path in missing)
    failures.extend(f"unexpected native input: {path}" for path in sorted(checked - set(expected)))
    if len(set(expected)) > 1 and not any(
            done == total and done >= len(set(expected)) for done, total in completed):
        failures.append("native completion counter does not cover all inputs")
    return {"native_status": status, "diagnostics": diagnostics, "failures": failures,
            "checker_inventory": checker_inventory(checkers, version),
            "checked_files": sorted(str(path) for path in checked & set(expected)),
            "findings": len(diagnostics),
            "advisories": sum(bool(row.get("advisory")) for row in diagnostics),
            "excluded": sum(bool(row.get("excluded")) for row in diagnostics),
            "remaining": remaining, "complete": not failures,
            "native_status_reason": ("validated unmatched inline declarations"
                                     if status == 3 and not remaining and unmatched and not failures else None)}


def diagnostic_advice(root, row, advice):
    """Keep advice visible; unknown includes and frontend failures remain blocking."""
    if row["id"] == "checkersReport" and row["severity"] == "information" and re.fullmatch(
            r"Active checkers: \d+/\d+", row["msg"]) and not row["locations"]:
        return "Native checker inventory; coverage is validated independently."
    if row["severity"] != "information":
        return None
    for location in row["locations"]:
        if "file" not in location or not location.get("line", "").isdigit():
            continue
        path = (root / location["file"]).resolve()
        name = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
        for rule in advice:
            if rule["id"] != row["id"]:
                continue
            if "header" in rule and matches_include(rule, name, int(location["line"]), row["msg"]):
                return rule["reason"]
            if ("unmatched_id" in rule and name == rule["file"] and
                    int(location["line"]) == rule["line"] and
                    row["msg"] == f"Unmatched suppression: {rule['unmatched_id']}"):
                return rule["reason"]
    return None


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


def analyze(profile, records, directory, log, entries=()):
    project = directory / f"{profile}.json"
    # Keep each distinct compiler context, including repeated files with
    # different definitions. Preserve the raw database before model adaptation.
    commands = {json.dumps(project_entry(row), sort_keys=True) for row in records}
    project.write_text("[\n" + ",\n".join(sorted(commands)) + "\n]\n")
    context_dir = directory / (profile + "-context")
    context_dir.mkdir()
    paths = set(tracked_sources(ROOT, "cppcheck")) | {HERE / "kernel.h"}
    compiler = CompilerContext(context_dir, paths)
    adapted = context_dir / "adapted.json"
    adaptation = adapt(ROOT, project, adapted, compiler=compiler, module=profile == "kernel")
    compiler_contexts = compiler.save()
    policy = load_policy("cppcheck")
    scope = {**policy, "omitted_system_headers": [group for group in policy["omitted_system_headers"]
                                                if profile in group["profiles"]]}
    outside = excluded_sources(ROOT, policy)
    advice = include_advice(ROOT, paths | {ROOT / name for name in outside}, scope)
    advice += unmatched_advice(entries, policy)
    # Native notices stay in XML; only their exit-code effect is disabled.
    exit_advice = context_dir / "exitcode.suppressions"
    exit_advice.write_text("".join(f"{rule['id']}:{ROOT / rule['file']}:{rule['line']}\n"
                                 for rule in advice if "header" in rule) +
                           "".join(f"*:{ROOT / name}\n" for name in sorted(outside)))
    invocation = context_dir / "invocation.json"
    details = dict(state="preparing", profile=profile, adaptation=adaptation,
                   compiler_contexts=compiler_contexts, advisory_rules=advice, excluded_sources=outside)
    invocation.write_text(json.dumps(details, indent=2) + "\n")
    stdout = directory / f"{profile}.stdout"
    xml = directory / f"{profile}.xml"
    checkers = directory / f"{profile}.checkers"
    checkers.write_text("")
    # Retain a fresh per-profile build directory so parallel
    # analysis still runs whole-program checks, including unusedFunction.
    command = ["cppcheck", "-j", str(os.cpu_count() or 1),
               "--cppcheck-build-dir=" + str(context_dir),
               "--project=" + str(adapted), "--enable=all", "--inconclusive",
               "--inline-suppr", "--exitcode-suppressions=" + str(exit_advice),
               "--platform=" + str(context_dir / "platform.xml"),
               "--library=" + ("gnu," + str(HERE / "kernel.cfg") if profile == "kernel" else "gnu,posix"),
               "--check-level=exhaustive", "--xml", "--xml-version=2",
               "--error-exitcode=3", "--checkers-report=" + str(checkers)]
    if profile == "kernel":
        command += ["--include=" + str(HERE / "kernel.h")]
    details.update(state="started", command=command, native_status=None)
    invocation.write_text(json.dumps(details, indent=2) + "\n")
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
                           [Path(row["file"]) for row in records], ROOT, advice, outside)
    details.update(state="complete", **record)
    invocation.write_text(json.dumps(details, indent=2) + "\n")
    return {"profile": profile, "translation_units": len(commands),
            "adaptation": adaptation, "compiler_contexts": compiler_contexts, **record}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    with report_lock(ROOT, "cppcheck"), build_lock(ROOT):
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
            entries = inline_inventory(ROOT, "cppcheck")
            summary["inline_exceptions"] = entries
            if not shutil.which("cppcheck"):
                raise ValueError("cppcheck is not installed")
            with log.open("ab") as stream:
                result = run(["cppcheck", "--version"], stdout=stream, stderr=subprocess.STDOUT)
            if result.returncode:
                raise ValueError(f"cppcheck version probe failed: {result.returncode}")
            catalogue = run(["cppcheck", "--errorlist"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
            (log.parent / "cppcheck.errorlist.xml").write_bytes(catalogue.stdout)
            (log.parent / "cppcheck.errorlist.stderr").write_bytes(catalogue.stderr)
            if catalogue.returncode or catalogue.stderr:
                raise ValueError("Cppcheck diagnostic catalogue failed; inspect cppcheck.errorlist.*")
            validate_ids(entries, catalogue.stdout)
            # Fresh records prevent stale incremental-build state from implying
            # coverage. Retain commands and native reports for diagnosis.
            directory = Path(tempfile.mkdtemp(prefix="cppcheck-", dir=log.parent))
            summary["records_directory"] = str(directory)
            variables = {"kernel": "CPPCHECK_PROJECT", "userspace": "CPPCHECK_USERSPACE_PROJECT"}
            projects = {name: os.environ.get(variable) for name, variable in variables.items()}
            shared = directory / "compile_commands.json"
            # Keep build messages separate from the XML appended by Cppcheck.
            build_log = directory / "build.log"
            summary["build_log"] = str(build_log)
            try:
                if not all(projects.values()):
                    summary["compiler_context"] = export_commands(
                        ROOT, shared, log=log, context=directory / "context.json", locked=True)
            finally:
                build_log.write_bytes(log.read_bytes())
            summary["context_mode"] = "external" if any(projects.values()) else "fresh"
            profiles = {}
            for profile in variables:
                project = Path(projects[profile]).resolve() if projects[profile] else shared
                database_entries = read_database(project, ROOT)
                profiles[profile] = []
                for row in database_entries:
                    source = Path(row["file"])
                    userspace_source = (source.is_relative_to(ROOT / "usr") or
                                        source.is_relative_to(ROOT / "iscsi-scst/usr"))
                    selected_source = (owned_source(ROOT, source) if profile == "kernel" else
                                       userspace_source and in_scope(source, ROOT, "cppcheck"))
                    if selected_source:
                        profiles[profile].append(row)
                if not profiles[profile]:
                    raise ValueError(f"No {profile} inputs in compilation database: {project}")
            kernel, userspace = profiles["kernel"], profiles["userspace"]
            captured = {Path(row["file"]) for row in kernel + userspace}
            missing = ([str(path) for path in selected if path.suffix == ".c" and path not in captured]
                       if args.files else [])
            summary.update(kernel_make_status=0, userspace_make_status=0,
                           unchecked_files=missing, unrecorded_checks=[])
            if missing:
                raise ValueError("Selected inputs are absent from the compiler database")
            for profile, rows in (("kernel", kernel), ("userspace", userspace)):
                result = analyze(profile, rows, directory, log, entries)
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
