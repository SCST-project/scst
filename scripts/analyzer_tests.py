#!/usr/bin/env python3
"""Run analyzer fixtures and native model probes without building or loading SCST."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import unittest

sys.dont_write_bytecode = True
from compile_commands import write_json
from lint_common import entrypoint, run

ROOT = Path(__file__).resolve().parents[1]
SUITE_DIRS = {"tests", "style", "sparse_smatch", "cppcheck", "coccinelle"}
# Temporary, explicit exceptions for the upstream Coccinelle variadic bug.
# Match both the test identity and reason; unrelated skips still fail CI.
KNOWN_SKIPS = {
    ("scripts/coccinelle/test_models.py", "NativeModelTests." + name):
        "Coccinelle loses variadic macro arguments; awaiting an upstream fix"
    for name in (
        "test_current_kunit_suite_macro_retains_initializer",
        "test_current_kunit_suite_macro_retains_all_variadic_fields",
        "test_current_kunit_suite_macro_accepts_an_empty_initializer_tail",
        "test_native_variadics_keep_all_arguments_without_a_fixed_prefix",
    )
}


def suites(root):
    names = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z", "scripts"], text=True).split("\0")
    return sorted(name for name in names if len(Path(name).parts) == 3
                  and Path(name).parts[1] in SUITE_DIRS and Path(name).match("test_*.py"))


def passed(row, status, suite=None):
    if not (isinstance(row, dict) and status == 0 and row.get("state") == "passed"
            and type(row.get("tests")) is int and type(row.get("skipped")) is int
            and 0 <= row["skipped"] < row["tests"]
            and all(row.get(key) == 0 for key in ("failures", "errors", "expected_failures"))):
        return False
    details = row.get("skip_details", [])
    if not isinstance(details, list) or len(details) != row["skipped"]:
        return False
    seen = set()
    for item in details:
        if not (isinstance(item, dict) and isinstance(item.get("test"), str)
                and isinstance(item.get("reason"), str)):
            return False
        if (item["test"] in seen
                or KNOWN_SKIPS.get((suite, item["test"])) != item["reason"]):
            return False
        seen.add(item["test"])
    return True


def run_suite(path, output):
    """A fresh interpreter isolates imports and keeps import-time exits incomplete."""
    row = dict(state="started", tests=0, failures=0, errors=0, skipped=0,
               skip_details=[], expected_failures=0)
    write_json(output, row)
    try:
        sys.path.insert(0, str(path.parent))
        spec = importlib.util.spec_from_file_location("_analyzer_test", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromModule(module))
        row.update(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                   skipped=len(result.skipped), expected_failures=len(result.expectedFailures),
                   skip_details=[dict(test=test.id().removeprefix("_analyzer_test."), reason=reason)
                                 for test, reason in result.skipped])
        row["state"] = "passed" if result.wasSuccessful() else "failed"
        try:
            suite = path.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            suite = None
        if not passed(row, 0, suite):
            row["state"] = "failed"
            print("Required analyzer tests must execute and pass; "
                  "only declared upstream skips are allowed.")
    except Exception as error:
        traceback.print_exc()
        row.update(state="failed", error=str(error))
    finally:
        write_json(output, row)
    return int(row["state"] != "passed")


def environment():
    # Test fixtures own their build/report overrides and temporary repositories.
    kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR") or
                  f"/lib/modules/{os.environ.get('KVER') or os.uname().release}/build").resolve()
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("CI_", "GITHUB_", "LINT_", "SCST_LINT_", "GIT_"))
           and key not in {"MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "GNUMAKEFLAGS",
                           "CPPCHECK_PROJECT", "CPPCHECK_USERSPACE_PROJECT", "CHECKPATCH_PATH"}}
    env.update(PYTHONDONTWRITEBYTECODE="1", KDIR=str(kernel), SCST_LINT_KDIR=str(kernel),
               CHECKPATCH_PATH=str(kernel / "scripts"))
    return env


def prerequisites(env):
    missing = [tool for tool in ("git", "make", "cc", "cpp", "perl", "cppcheck", "spatch")
               if not shutil.which(tool)]
    kernel = Path(env["KDIR"])
    for name in ("scripts/checkpatch.pl", "scripts/spelling.txt", "scripts/const_structs.checkpatch",
                 "scripts/coccinelle/api/stream_open.cocci",
                 "scripts/coccinelle/misc/add_namespace.cocci"):
        if not (kernel / name).is_file():
            missing.append(str(kernel / name))
    if missing:
        raise ValueError("Missing analyzer-test prerequisites: " + ", ".join(missing))


def execute(root):
    reports = root / ".cache/lint"
    reports.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="analyzer-tests-", dir=reports))
    manifest = directory / "tests.json"
    report = dict(state="started", suites=[], failures=[])
    write_json(manifest, report)
    started = time.monotonic()
    print(f"Analyzer tests: Python {sys.version.split()[0]}; reports: {directory}", flush=True)
    try:
        selected = suites(root)
        if not selected:
            raise ValueError("No tracked analyzer test suites found")
        env = environment()
        prerequisites(env)
        print(f"Kernel tools: {env['KDIR']}; {len(selected)} test suites", flush=True)
        for name in selected:
            stem = name.replace("/", "_").removesuffix(".py")
            log, result_file = directory / (stem + ".log"), directory / (stem + ".json")
            before = time.monotonic()
            status = None
            with log.open("w") as stream:
                try:
                    process = run([sys.executable, "-B", str(Path(__file__).resolve()),
                                   "--suite", str(root / name), "--result", str(result_file)],
                                  cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                  timeout=300, progress=name)
                    status = process.returncode
                except subprocess.TimeoutExpired:
                    stream.write("Required analyzer test suite timed out.\n")
            try:
                row = json.loads(result_file.read_text())
            except (OSError, ValueError):
                row = None
            success = passed(row, status, name)
            if not isinstance(row, dict):
                row = dict(state="incomplete", tests=0, skipped=0)
            row.update(file=name, state="passed" if success else "failed", status=status,
                       seconds=round(time.monotonic() - before, 1), log=str(log))
            report["suites"].append(row)
            write_json(manifest, report)
            print(f"  {'PASS' if success else 'FAIL'} {name}: {row.get('tests', 0)} tests, "
                  f"{row.get('skipped', 0)} skipped ({row['seconds']}s)", flush=True)
            if success:
                for item in row.get("skip_details", []):
                    print(f"    SKIP {item['test']}: {item['reason']}", flush=True)
            else:
                print(log.read_text(errors="replace"), flush=True)
        report["state"] = "passed" if all(row["state"] == "passed"
                                          for row in report["suites"]) else "failed"
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        report["failures"].append(str(error))
        print(f"Analyzer tests: {error}", file=sys.stderr, flush=True)
    finally:
        if report["state"] == "started":
            report["state"] = "incomplete"
        report["seconds"] = round(time.monotonic() - started, 1)
        write_json(manifest, report)
        summary = (f"Analyzer tests: {report['state'].upper()}; "
                   f"{sum(row.get('tests', 0) for row in report['suites'])} tests; "
                   f"{sum(row.get('skipped', 0) for row in report['suites'])} skipped; "
                   f"{report['seconds']}s\nReports: {directory}\n")
        print(summary, end="", flush=True)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            path = Path(os.environ["GITHUB_STEP_SUMMARY"])
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a") as stream:
                stream.write("```text\n" + summary + "```\n")
    return int(report["state"] != "passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--result", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if bool(args.suite) != bool(args.result):
        parser.error("--suite and --result must be supplied together")
    return run_suite(args.suite, args.result) if args.suite else execute(ROOT)


if __name__ == "__main__":
    sys.exit(entrypoint(main))
