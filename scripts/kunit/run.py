#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Capture and report a local run of already-built SCST KUnit modules."""

import argparse
from collections import Counter
import errno
import fcntl
import gzip
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent / "upstream"))
import kunit_parser  # noqa: E402
from kunit_printer import Printer  # noqa: E402

DEFAULT_MODULE_LIST = Path(__file__).resolve().parents[2] / ".kunit-modules"
DEBUGFS = Path("/sys/kernel/debug/kunit")
MODULE_METADATA = ("version", "description", "author", "license", "git_commit",
                   "build_date", "build_number", "kver", "arch_type", "srcversion", "vermagic")


class RunError(Exception):
    """Execution or evidence is incomplete."""


def kernel_diagnostics(messages):
    signatures = (
        "WARNING:", "BUG:", "Oops:", "Kernel panic", "KASAN:", "KCSAN:",
        "UBSAN:", "kernel BUG at", "general protection fault",
        "Unable to handle kernel", "Call Trace:", "Call trace:", "Backtrace:",
    )
    groups = []
    active = False
    oops_seen = False
    fault = False
    for line in messages:
        signature = any(s in line for s in signatures) or re.search(
            r"(?:soft|hard) LOCKUP|blocked for more than|rcu:.*stall", line, re.IGNORECASE)
        trace = any(s in line for s in ("Call Trace:", "Call trace:", "Backtrace:"))
        oops = line.startswith("Oops:")
        # #PF and architecture-specific register lines are part of an Oops,
        # not KTAP comments. Keep the block until test output resumes.
        ktap = re.match(r"\s*(?:#(?:\s|$)|(?:not ok|ok) \d|\d+\.\.|KTAP version)", line)
        continuation = active and (trace or (oops and fault and not oops_seen))
        if signature and not continuation:
            groups.append(line)
            active = True
            oops_seen = oops
            fault = any(s in line for s in ("BUG:", "kernel BUG at", "general protection fault",
                                            "Unable to handle kernel"))
        elif active and not ktap:
            groups[-1] += "\n" + line
            oops_seen |= oops
        else:
            active = False
    return groups


def test_tree(test):
    return {"name": test.name, "status": test.status.name,
            "counts": vars(test.counts), "log": test.log, "skip_reason": test.skip_reason,
            "children": [test_tree(child) for child in test.subtests]}


def associate_parameter_logs(test, block):
    """Attach diagnostics before an unplanned first parameter to that case.

    The upstream parser keeps these on the parent. Move only an unambiguous
    source span ending at the first leaf result; retain all other parent logs.
    Plans, results and parser validation are unchanged.
    """
    for child in test.subtests:
        associate_parameter_logs(child, block)
    if not test.subtests or test.expected_count is not None or test.subtests[0].subtests:
        return
    headers = [i for i, line in enumerate(block)
               if line.strip() == f"# Subtest: {test.name}"]
    if len(headers) != 1:
        return
    source = kunit_parser.LineStream(iter(enumerate(block[headers[0] + 1:], start=1)))
    leading = kunit_parser.parse_diagnostic(source)
    result = kunit_parser.TEST_RESULT.match(source.peek()) if source else None
    if (not leading or not result or int(result[2]) != 1 or
            result[4].strip() != test.subtests[0].name):
        return
    positions = [i for i in range(len(test.log) - len(leading) + 1)
                 if test.log[i:i + len(leading)] == leading]
    if len(positions) == 1:
        start = positions[0]
        del test.log[start:start + len(leading)]
        test.subtests[0].log[:0] = leading


def log_problems(messages, suite=None):
    """Reject execution outside the active suite without parsing kmsg as results."""
    errors = []
    headers, endings = [], []
    for line in messages:
        header = re.fullmatch(r" {0,4}# Subtest: (\S.*?)\s*", line)
        ending = re.fullmatch(r"(?:not ok|ok) \d+ (?:- )?(.*?)(?: #.*)?", line)
        if header:
            headers.append(header[1])
        if ending:
            endings.append(ending[1])
        if suite is None and re.match(r"\s*(?:KTAP version|# Subtest:|(?:not ok|ok) \d|\d+\.\.)", line):
            errors.append("Unexpected KUnit execution outside a selected suite")
            break
    if suite is not None and (any(name != suite for name in headers + endings)
                              or len(headers) > 1 or len(endings) > 1):
        errors.append(f"Unexpected KUnit execution while running {suite}")
    if any("SCST_KUNIT_RETAINED:" in line for line in messages):
        errors.append("Unfinished test work retained fixture and module; inspect the VM")
    return errors


def analyse(documents, expected, messages=()):
    """Parse one complete debugfs KTAP document per suite; kmsg supplies diagnostics."""
    retained = [line for line in messages if "SCST_KUNIT_RETAINED:" in line]
    errors = ["Unfinished test work retained fixture and module; inspect the VM"] if retained else []
    if missing := sorted(set(expected) - documents.keys()):
        errors.append("Missing suite results: " + ", ".join(missing))
    if unexpected := sorted(documents.keys() - set(expected)):
        errors.append("Unexpected suite results: " + ", ".join(unexpected))
    results = []
    counts = dict.fromkeys(("passed", "failed", "skipped", "crashed", "errors"), 0)
    details = io.StringIO()
    for name, document in documents.items():
        block = document.splitlines()
        lines = kunit_parser.LineStream(iter(enumerate(block, start=1)))
        parse_output = io.StringIO()
        parsed = kunit_parser.parse_test(lines, 0, [], False, Printer(output=parse_output))
        valid = (block[:2] == ["KTAP version 1", "1..1"] and parsed.expected_count == 1
                 and len(parsed.subtests) == 1 and parsed.subtests[0].name == name
                 and not parsed.counts.errors and not parsed.counts.crashed
                 and not any(line.strip() for line in lines))
        for suite in parsed.subtests:
            valid &= bool(suite.subtests) or suite.status == kunit_parser.TestStatus.SKIPPED
            if not suite.name:
                # Identify missing output in progress and failure summaries.
                suite.name = name
            for case in suite.subtests:
                associate_parameter_logs(case, block)
            results.append(test_tree(suite))
        if not valid:
            errors.append(f"Incomplete or invalid debugfs KTAP for {name}")
            details.write(parse_output.getvalue())
        else:
            kunit_parser.print_test(parsed.subtests[0], False, Printer(output=details))
        for key in counts:
            counts[key] += getattr(parsed.counts, key)
        if "SCST_KUNIT_RETAINED:" in document and not retained:
            errors.append("Unfinished test work retained fixture and module; inspect the VM")
    failed = any(s["status"] == "FAILURE" for s in results) or counts["failed"] > 0
    status = ("ERROR" if errors else "FAIL" if failed else
              "PASS" if counts["passed"] else "SKIP")
    return {"test_status": status, "suites": results, "counts": counts,
            "parse_errors": errors, "retained_fixtures": retained,
            "diagnostics": kernel_diagnostics(messages)}, details.getvalue()


class KernelLog:
    """Read only new /dev/kmsg records, checking the sequence for overruns."""

    def __init__(self, directory):
        self.fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
        try:
            os.lseek(self.fd, 0, os.SEEK_END)
            self.raw = (directory / "kernel.log").open("wb")
        except BaseException:
            os.close(self.fd)
            raise
        self.sequence = None
        self.messages = []
        self.previous_kernel = False

    def accept(self, record):
        self.raw.write(record)
        self.raw.flush()
        try:
            header, body = record.split(b";", 1)
            fields = header.split(b",")
            priority, sequence, timestamp = map(int, fields[:3])
            flags = fields[3]
            if min(priority, sequence, timestamp) < 0:
                raise ValueError("negative kmsg metadata")
        except (ValueError, IndexError) as exc:
            raise RunError("Malformed /dev/kmsg record; see kernel.log") from exc
        if self.sequence is not None and sequence != self.sequence + 1:
            raise RunError(f"Lost kernel log records between {self.sequence} and {sequence}")
        self.sequence = sequence
        # Userspace cannot write LOG_KERN records. Keep injected messages in
        # the raw evidence, but do not let them supply test results/diagnostics.
        if priority >> 3:
            self.previous_kernel = False
            return
        escaped = body.split(b"\n", 1)[0]
        decoded = re.sub(rb"\\x([0-9a-fA-F]{2})",
                         lambda match: bytes([int(match[1], 16)]), escaped)
        lines = decoded.decode("utf-8", errors="replace").split("\n")
        if b"c" in flags and self.previous_kernel and self.messages:
            self.messages[-1] += lines.pop(0)
        self.messages.extend(lines)
        self.previous_kernel = True

    def drain(self):
        # Bound each batch so a noisy system cannot defeat the command timeout.
        for _ in range(256):
            try:
                record = os.read(self.fd, 1024 * 1024)
            except BlockingIOError:
                return False
            except OSError as exc:
                if exc.errno == errno.EPIPE:
                    raise RunError("Kernel log overrun; results are incomplete") from exc
                raise
            if not record:
                raise RunError("Kernel log closed unexpectedly")
            self.accept(record)
        return True

    def close(self):
        os.close(self.fd)
        self.raw.close()


def command(argv, capture, directory, timeout, report):
    if argv[0] in ("modprobe", "insmod", "rmmod"):
        print("Running: " + shlex.join(argv), flush=True)
    with (directory / "commands.log").open("ab", buffering=0) as output:
        output.write(("\n$ " + shlex.join(argv) + "\n").encode())
        output_start = output.tell()
        process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        operation = {"argv": argv, "pid": process.pid, "returncode": None}
        report["commands"].append(operation)
        deadline = time.monotonic() + timeout
        while True:
            capture.drain()
            operation["returncode"] = process.poll()
            # The child can print and exit after the first drain. Read again
            # after observing its exit before declaring the log complete.
            if operation["returncode"] is not None and not capture.drain():
                if operation["returncode"]:
                    # Keep a bounded error excerpt; commands.log retains all output.
                    with (directory / "commands.log").open("rb") as source:
                        source.seek(max(output_start, os.fstat(source.fileno()).st_size - 4096))
                        operation["output"] = source.read().decode("utf-8", errors="replace").strip()
                return operation["returncode"]
            if time.monotonic() >= deadline:
                raise RunError(f"Timed out waiting for PID {process.pid}; it may still be running. "
                               "No automatic unload will be attempted")
            time.sleep(0.02)


def collect_suite(trigger, capture, directory, timeout, report):
    """Bound the trigger and results read together; keep the raw document on disk."""
    suite = trigger.parent.name
    output = directory / "ktap" / f"{suite}.ktap"
    code = command([sys.executable, "-c",
                    "import pathlib,shutil,sys\n"
                    "p=pathlib.Path(sys.argv[2])\n"
                    "p.write_text('run\\n')\n"
                    "with p.with_name('results').open('rb') as src, open(sys.argv[1], 'wb') as dst:\n"
                    "    shutil.copyfileobj(src, dst)\n",
                    str(output), str(trigger)], capture, directory, timeout, report)
    if output.is_file():
        report.setdefault("suite_results", {})[suite] = output.read_text(errors="replace")
    return code


def command_error(report, operation, code):
    output = report["commands"][-1].get("output", "") if report["commands"] else ""
    message = f"{operation} exited with {code}"
    return RunError(message + ("\n" + output if output else "; see commands.log"))


def module_info(module):
    info = {}
    for field in ("name", "scst_kunit_suite", "depends", *MODULE_METADATA):
        result = subprocess.run(["modinfo", "-F", field, str(module)], text=True,
                                capture_output=True, timeout=10, check=True)
        info[field] = result.stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", info["name"]):
        raise RunError("Invalid module name")
    info["name"] = info["name"].replace("-", "_")
    labels = {}
    for record in info["scst_kunit_suite"].splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*):(scst-[A-Za-z0-9_-]+)", record)
        if not match or match[1] == "ALL" or match[2] in labels:
            raise RunError("Invalid SCST label manifest; rebuild with kunit-build")
        labels[match[2]] = match[1]
    if not labels:
        raise RunError("Module has no KUnit label manifest; rebuild with kunit-build")
    info["suites"] = list(labels)
    info["labels"] = labels
    dependencies = info["depends"].split(",") if info["depends"] else []
    if any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", name) for name in dependencies):
        raise RunError(f"Invalid dependencies for {info['name']}")
    info["depends"] = [name.replace("-", "_") for name in dependencies]
    return info


def parse_labels(value):
    labels = value.split()
    if not labels or any(re.fullmatch(r"[A-Z][A-Z0-9_]*", label) is None for label in labels):
        raise ValueError("Select labels with --labels '<labels>' or --labels ALL")
    if "ALL" in labels and len(labels) != 1:
        raise ValueError("ALL must be used alone")
    return sorted(set(labels))


def select_modules(inventory, labels):
    names = [item["name"] for item in inventory]
    if len(names) != len(set(names)):
        raise RunError("Duplicate module")
    suites = [suite for item in inventory for suite in item["suites"]]
    if not suites or len(suites) != len(set(suites)):
        raise RunError("Modules must have a nonempty, unique suite manifest")
    available = {label for item in inventory for label in item["labels"].values()}
    if labels != ["ALL"] and set(labels) - available:
        raise RunError(f"Labels absent from supplied modules: {sorted(set(labels) - available)}")
    by_name = {item["name"]: item for item in inventory}
    ordered = []
    visited = set()
    visiting = set()

    def visit(name):
        if name in visiting:
            raise RunError(f"Cyclic module dependency at {name}")
        if name in visited:
            return
        visiting.add(name)
        item = by_name[name]
        for dependency in item["depends"]:
            if dependency in by_name:
                visit(dependency)
            elif dependency == "scst":
                raise RunError(f"Supply scst.ko from the same build as {name}")
        visiting.remove(name)
        visited.add(name)
        ordered.append(item)

    for item in inventory:
        item["selected_suites"] = [suite for suite in item["suites"]
                                   if labels == ["ALL"] or item["labels"][suite] in labels]
    for item in inventory:
        if item["selected_suites"]:
            visit(item["name"])
    return ordered


def kernel_config():
    release = platform.release()
    for path in (Path("/proc/config.gz"), Path(f"/boot/config-{release}"),
                 Path(f"/lib/modules/{release}/build/.config")):
        if not path.is_file():
            continue
        source = gzip.open(path, "rt") if path.suffix == ".gz" else path.open()
        with source:
            values = {}
            for line in source:
                if line.startswith("CONFIG_") and "=" in line:
                    key, value = line.strip().split("=", 1)
                    values[key] = value
                elif re.fullmatch(r"# CONFIG_\w+ is not set\n?", line):
                    values[line.split()[1]] = "n"
        return values
    raise RunError("Cannot read running kernel configuration; provide /proc/config.gz "
                   "or /boot/config-<release>")


def check_kunit_interfaces():
    if not DEBUGFS.is_dir():
        raise RunError("Mount debugfs at /sys/kernel/debug and enable CONFIG_KUNIT_DEBUGFS")
    # NULL and an empty charp are different: an empty glob selects no suites,
    # while an empty action is an unknown action. Attribute filters may be empty.
    neutral = {"action": ("(null)",), "filter_glob": ("(null)", "*", "*.*"),
               "filter": ("(null)", ""), "filter_action": ("(null)", "")}
    for name, allowed in neutral.items():
        value = Path(f"/sys/module/kunit/parameters/{name}").read_text().removesuffix("\n")
        if value not in allowed:
            raise RunError(f"kunit.{name}={value!r} prevents unfiltered suite registration; "
                           "use KUnit without action or filters (filter_glob=*.* is also valid)")


def check_preloaded_kunit():
    for name, expected, allowed in (("enable", "1", ("y", "1")), ("autorun", "0", ("n", "0"))):
        path = Path(f"/sys/module/kunit/parameters/{name}")
        try:
            value = path.read_text().strip()
        except OSError as exc:
            raise RunError(f"Cannot verify preloaded KUnit: {path.name} is unreadable.\n"
                           "Module left unchanged. If it is unused, run 'rmmod kunit' as root, "
                           "then retry; the runner will load it with enable=1 autorun=0.") from exc
        if value.lower() not in allowed:
            raise RunError(f"Preloaded kunit.{name}={value!r}; require {name}={expected}. "
                           "Module left unchanged; correct its parameters before retrying")
    check_kunit_interfaces()


def check_kernel():
    config = kernel_config()
    if config.get("CONFIG_KUNIT") not in ("y", "m"):
        raise RunError("The running kernel requires CONFIG_KUNIT=y or m")
    if "CONFIG_KUNIT_AUTORUN_ENABLED" not in config:
        raise RunError("The kernel lacks native KUnit autorun control; use the latest upstream kernel")
    if config.get("CONFIG_KUNIT_DEBUGFS") != "y":
        raise RunError("Enable CONFIG_KUNIT_DEBUGFS in the test kernel")
    if config["CONFIG_KUNIT"] == "m":
        if Path("/sys/module/kunit").exists():
            check_preloaded_kunit()
            return "preloaded"
        if shutil.which("modprobe") is None:
            raise RunError("Required command not found: modprobe")
        return "load"
    if Path("/sys/module/kunit/initstate").exists():
        raise RunError("Running KUnit does not match the built-in kernel configuration")
    options = {}
    for token in shlex.split(Path("/proc/cmdline").read_text()):
        if token == "--":
            break
        key, _, value = token.partition("=")
        options[key.replace("-", "_")] = value.lower()
    if options.get("kunit.autorun") not in ("0", "n", "no", "false"):
        raise RunError("Boot the test VM with kunit.autorun=0 before running SCST tests")
    enabled = options.get("kunit.enable", config.get("CONFIG_KUNIT_DEFAULT_ENABLED", "n").lower())
    if enabled not in ("1", "y", "yes", "true"):
        raise RunError("KUnit is disabled; boot with kunit.enable=1")
    check_kunit_interfaces()
    return "built-in"


def prepare_dependencies(inventory, capture, directory, timeout, report):
    # Use installed kernel modules only for external prerequisites. SCST owners
    # come from the supplied build, and KUnit has its own parameter/ownership rules.
    names = sorted({name for item in inventory for name in item["depends"]}
                   - {item["name"] for item in inventory} - {"kunit"})
    report["dependencies"] = names
    for name in names:
        if Path(f"/sys/module/{name}").exists():
            continue
        if shutil.which("modprobe") is None:
            raise RunError(f"Required command not found: modprobe (dependency {name})")
        code = command(["modprobe", "--ignore-install", name], capture, directory, timeout, report)
        if code:
            raise command_error(report, f"Loading dependency {name}", code)
        if log_problems(capture.messages) or kernel_diagnostics(capture.messages):
            raise RunError(f"Unexpected kernel output while loading dependency {name}; execution stopped")


def unload_owned_kunit(capture, directory, timeout, report):
    report["kunit_state"] = "unloading"
    log_start = len(capture.messages)
    code = command(["rmmod", "kunit"], capture, directory, timeout, report)
    if code:
        report["kunit_state"] = "retained"
        raise command_error(report, "Could not unload runner-owned kunit", code)
    if Path("/sys/module/kunit").exists():
        report["kunit_state"] = "retained"
        raise RunError("Could not unload runner-owned kunit: module remains present after rmmod")
    report["kunit_state"] = "unloaded"
    if problems := log_problems(capture.messages[log_start:]):
        raise RunError("; ".join(problems))


def execute(modules, timeout, directory, report, labels, verbose=False):
    if os.geteuid() != 0:
        raise RunError("Module execution requires root in the prepared test environment")
    for tool in ("modinfo", "insmod", "rmmod"):
        if shutil.which(tool) is None:
            raise RunError(f"Required command not found: {tool}")
    inventory = [module_info(path) | {"path": str(path), "state": "not attempted"}
                 for path in modules]
    report["modules"] = inventory
    inventory = select_modules(inventory, labels)
    report["expected_suites"] = [suite for item in inventory for suite in item["selected_suites"]]
    report["started_suites"] = []
    if len({item["vermagic"] for item in inventory}) != 1:
        raise RunError("Modules have different vermagic values; rebuild them for the same kernel")
    for name in (item["name"] for item in inventory):
        if Path(f"/sys/module/{name}").exists():
            raise RunError(f"{name} is already loaded; refusing to disturb it")
    kernel_mode = check_kernel()
    report["kunit_state"] = "not loaded" if kernel_mode == "load" else kernel_mode
    capture = KernelLog(directory)
    try:
        prepare_dependencies(inventory, capture, directory, timeout, report)
        if kernel_mode == "load":
            report["kunit_state"] = "loading"
            # Fail if another process loaded KUnit in the meantime: modprobe
            # otherwise succeeds without applying the requested parameters.
            code = command(["modprobe", "--first-time", "--ignore-install", "kunit",
                            "enable=1", "autorun=0"], capture, directory, timeout, report)
            if code:
                raise command_error(report, "modprobe kunit", code)
            report["kunit_state"] = "retained"
            check_kunit_interfaces()
            if log_problems(capture.messages):
                raise RunError("Unexpected KUnit results during preparation; execution stopped")
            if kernel_diagnostics(capture.messages):
                report["stop_reason"] = "kernel diagnostics while preparing KUnit"
                return
        documents = report.setdefault("suite_results", {})
        (directory / "ktap").mkdir()
        for item in inventory:
            report["module_state"] = item["state"] = "loading"
            log_start = len(capture.messages)
            code = command(["insmod", item["path"]], capture, directory, timeout, report)
            if code:
                error = command_error(report, f"insmod {item['name']}", code)
                if not Path(f"/sys/module/{item['name']}").exists():
                    item["state"] = "not loaded"
                    present = any(Path(f"/sys/module/{entry['name']}").exists() for entry in inventory)
                    report["module_state"] = "retained" if present else "not loaded"
                    if (code > 0 and kernel_mode == "load" and not present and not report["started_suites"]
                            and not log_problems(capture.messages) and not kernel_diagnostics(capture.messages)):
                        try:
                            unload_owned_kunit(capture, directory, timeout, report)
                        except (RunError, OSError) as exc:
                            raise RunError(f"{error}\nCleanup: {exc}") from exc
                raise error
            report["module_state"] = item["state"] = "retained"
            if problems := log_problems(capture.messages[log_start:]):
                raise RunError("; ".join(problems))
            if kernel_diagnostics(capture.messages):
                report["stop_reason"] = f"kernel diagnostics while loading {item['name']}"
                return
            for suite in item["selected_suites"]:
                trigger = DEBUGFS / suite / "run"
                if not trigger.is_file():
                    raise RunError(f"Missing KUnit run interface for {suite}; modules retained")
                # A debugfs write blocks in KUnit. Use a child so the parent can
                # drain kmsg and enforce its deadline without unloading live work.
                report["started_suites"].append(suite)
                log_start = len(capture.messages)
                code = collect_suite(trigger, capture, directory, timeout, report)
                if code:
                    raise command_error(report, f"Execution or results read of {suite}", code)
                if problems := log_problems(capture.messages[log_start:], suite):
                    raise RunError("; ".join(problems))
                tests, _ = analyse(documents, report["started_suites"], capture.messages)
                show_suites(tests, report)
                if tests["parse_errors"]:
                    raise RunError("Incomplete or unexpected tests; modules retained for inspection")
                if tests["diagnostics"]:
                    report["stop_reason"] = f"kernel diagnostics during {suite}"
                    return
        for item in reversed(inventory):
            report["module_state"] = item["state"] = "unloading"
            log_start = len(capture.messages)
            code = command(["rmmod", item["name"]], capture, directory, timeout, report)
            if code:
                raise RunError(f"rmmod {item['name']} exited with {code}; see commands.log")
            if Path(f"/sys/module/{item['name']}").exists():
                raise RunError(f"{item['name']} remains loaded after rmmod")
            item["state"] = "unloaded"
            if problems := log_problems(capture.messages[log_start:]):
                raise RunError("; ".join(problems))
            if kernel_diagnostics(capture.messages):
                report["module_state"] = "retained" if any(
                    item["state"] != "unloaded" for item in inventory) else "unloaded"
                return
        report["module_state"] = "unloaded"
        if kernel_mode == "load":
            unload_owned_kunit(capture, directory, timeout, report)
    finally:
        report["messages"] = capture.messages
        capture.close()


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("modules", nargs="*", type=Path,
                        help="test modules and their SCST dependencies; order is determined from modinfo")
    parser.add_argument("--labels", default="ALL", type=parse_labels,
                        help="space-separated labels to run, or ALL (default: ALL)")
    parser.add_argument("--config", type=Path, help="TOML configuration file")
    parser.add_argument("--timeout", type=float, help="seconds per suite or module operation (default: 300)")
    parser.add_argument("--output", type=Path, help="parent for unique report directories")
    parser.add_argument("--verbose", action=argparse.BooleanOptionalAction, default=None,
                        help="print all cases; full details are always saved in report.txt")
    args = parser.parse_args(argv)
    config = args.config or Path(".kunit-run.toml")
    settings = {}
    if args.config or config.exists():
        with config.open("rb") as source:
            settings = tomllib.load(source)
        if settings.keys() - {"module", "modules", "timeout_seconds", "output_dir", "verbose"}:
            parser.error("Config accepts only modules, module, timeout_seconds, output_dir and verbose")
        if "module" in settings and "modules" in settings:
            parser.error("Use either module or modules in config")
    timeout = args.timeout if args.timeout is not None else settings.get("timeout_seconds", 300)
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout < 86400):
        parser.error("Timeout must be positive and less than 86400 seconds")
    for field in ("module", "output_dir"):
        if field in settings and (not isinstance(settings[field], str) or not settings[field]):
            parser.error(f"Config {field} must be a nonempty path")
    configured = settings.get("modules", [settings["module"]] if "module" in settings else None)
    if configured is not None and (not isinstance(configured, list) or not configured or
                                  any(not isinstance(path, str) or not path for path in configured)):
        parser.error("Config modules must be a nonempty array of paths")
    module_base = Path.cwd()
    if args.modules:
        modules = args.modules
    elif configured is not None:
        modules = [Path(path) for path in configured]
        module_base = config.parent
    else:
        if not DEFAULT_MODULE_LIST.is_file():
            parser.error("No KUnit build recorded; run make kunit-build or specify module paths")
        paths = DEFAULT_MODULE_LIST.read_text().splitlines()
        if not paths or any(not path.strip() for path in paths):
            parser.error("Invalid KUnit module list; rerun make kunit-build")
        modules = [Path(path) for path in paths]
        module_base = DEFAULT_MODULE_LIST.parent
    output = args.output or Path(settings.get("output_dir", "kunit-results"))
    output = output.expanduser()
    resolved = []
    for module in modules:
        module = module.expanduser()
        if not module.is_absolute():
            module = module_base / module
        if not module.is_file():
            parser.error(f"Module not found: {module}")
        resolved.append(module.resolve())
    if args.output is None and "output_dir" in settings and not output.is_absolute():
        output = config.parent / output
    if "verbose" in settings and not isinstance(settings["verbose"], bool):
        parser.error("Config verbose must be a boolean")
    verbose = args.verbose if args.verbose is not None else settings.get("verbose", False)
    return resolved, timeout, output.resolve(), verbose, args.labels


def show_suites(tests, report):
    """Print progress without interleaving case diagnostics with the suite list."""
    printed = report.setdefault("printed_suites", [])
    for suite in tests["suites"]:
        if suite["name"] not in printed:
            print(color_console(f"[{test_status(suite)}] {suite['name']}"), flush=True)
            printed.append(suite["name"])


def test_status(test):
    return {"SUCCESS": "PASS", "FAILURE": "FAIL", "SKIPPED": "SKIP",
            "TEST_CRASHED": "CRASH"}.get(test["status"], "ERROR")


def case_log_lines(log):
    """Normalize assertion blocks without flattening their value indentation."""
    block = []
    margin = None
    for line in log:
        assertion = re.match(r"([ \t]*)# .*: (?:EXPECTATION|ASSERTION) FAILED at ", line)
        if assertion or (margin is not None and line.strip() and not line.startswith(margin)):
            # printk and assertion messages can start at column zero even
            # when the KUnit assertion itself has a nesting prefix.
            yield from textwrap.dedent("\n".join(block)).splitlines()
            block = []
            margin = assertion[1] if assertion else None
        block.append(line)
    yield from textwrap.dedent("\n".join(block)).splitlines()


def case_details(tests, verbose=False):
    """Group failed cases after progress; keep diagnostics within their case."""
    diagnostic_lines = {line for block in tests["diagnostics"] for line in block.splitlines()}
    bookkeeping = re.compile(r"\s*# (?:module: .*|(?:.*: )?pass:\d+ fail:\d+ skip:\d+ total:\d+)\s*$")

    def describe(test, path="", root=False):
        name = f"{path}/{test['name']}" if path else test["name"]
        status = test_status(test)
        lines = []
        if verbose or status not in ("PASS", "SKIP"):
            log = [line for line in test["log"] if line not in diagnostic_lines
                   and (verbose or not bookkeeping.fullmatch(line))]
            if (not root and not test["children"]) or log or test["skip_reason"]:
                # A parent's status aggregates its children; don't repeat FAIL
                # for it merely because one of its parameters failed.
                if not root:
                    heading = name if test["children"] else f"[{status}] {name}"
                    lines.append("  " + heading)
                if test["skip_reason"]:
                    lines.append("    " + test["skip_reason"])
                lines.extend("    " + line if line else "" for line in case_log_lines(log))
                lines.append("")
        for child in test["children"]:
            lines.extend(describe(child, "" if root else name))
        return lines

    lines = []
    for suite in tests["suites"]:
        body = describe(suite, root=True)
        if body:
            lines.extend([suite["name"], *body])
    return (["Cases:" if verbose else "Failures:", "", *lines] if lines else [])


def module_metadata(modules):
    """Describe the supplied artifacts using their embedded build information."""
    lines = []
    for module in modules:
        fields = [(field, module.get(field)) for field in MODULE_METADATA if module.get(field)]
        if not fields:
            continue
        lines.append(f"Module: {module['name']}")
        for field, value in fields:
            lines.extend(textwrap.wrap(f"  {field}: {' '.join(value.split())}", width=100,
                                       subsequent_indent="    ", break_long_words=False,
                                       break_on_hyphens=False))
        lines.append("")
    return lines


def core_metadata(modules):
    """Keep the normal summary focused on identifying the SCST build."""
    core = next((item for item in modules if item["name"] == "scst"), {})
    fields = (("version", "SCST"), ("git_commit", "Commit"),
              ("build_number", "Build number"), ("build_date", "Build date"),
              ("kver", "Built for kernel"), ("arch_type", "Architecture"))
    return [f"{label}: {' '.join(core[field].split())}" for field, label in fields if core.get(field)]


def finish(report, directory, verbose=False):
    messages = report.pop("messages", [])
    expected = report.get("expected_suites", [])
    started = report.get("started_suites", expected if report["module_state"] != "not attempted" else [])
    documents = report.pop("suite_results", {})
    tests, details = analyse(documents, started, messages)
    report["not_run_suites"] = [suite for suite in expected if suite not in started]
    if not started and not tests["suites"]:
        tests["test_status"] = "NOT_RUN"
    report.update(tests)
    report["errors"].extend(tests["parse_errors"])
    if report["not_run_suites"] and not report["errors"] and not tests["diagnostics"]:
        report["errors"].append("Execution stopped before all selected suites were started")
    if report["errors"]:
        report["status"] = "ERROR"
    elif tests["diagnostics"]:
        report["status"] = "FAIL"
    elif report["not_run_suites"] or not tests["suites"] or report["module_state"] != "unloaded":
        report["status"] = "ERROR"
    elif tests["test_status"] == "FAIL":
        report["status"] = "FAIL"
    else:
        report["status"] = tests["test_status"]
    counts = report["counts"]
    events = len(tests["diagnostics"])
    lines = [f"Result: {report['status']}",
             f"Tests: {report['test_status']} ({counts['passed']} passed, {counts['failed']} failed, "
             f"{counts['skipped']} skipped, {counts['crashed']} crashed, {counts['errors']} parse errors)",
             f"Suites: {len(started)}/{len(expected)} started, {len(report['not_run_suites'])} not run",
             f"Kernel diagnostics: {events} " + ("event" if events == 1 else "events"),
             f"Modules: {report['module_state']}"]
    lines.extend(f"Module {item['name']}: {item.get('state', 'unknown')}" for item in report.get("modules", []))
    if "kunit_state" in report:
        lines.append(f"KUnit: {report['kunit_state']}")
    if "labels" in report:
        lines.append("Labels: " + " ".join(report["labels"]))
    if "kernel" in report:
        lines.append(f"Kernel: {report['kernel']} ({report['architecture']})")
    if "elapsed_seconds" in report:
        lines.append(f"Elapsed: {report['elapsed_seconds']} seconds")
    lines.extend("Error: " + error for error in report["errors"])
    for headline, count in Counter(block.splitlines()[0] for block in tests["diagnostics"]).items():
        lines.append(f"Kernel: {headline}" + (f" ({count} events)" if count > 1 else ""))
    if tests["diagnostics"]:
        lines.append("Full kernel diagnostics: messages.log and report.txt")
    lines.extend("NOT_RUN: " + suite for suite in report["not_run_suites"])
    summary = "\n".join(lines) + "\n"
    metadata = "\n".join(module_metadata(report.get("modules", [])))
    diagnostics = "\n\n".join(tests["diagnostics"])
    def successful_logs(test, parent=""):
        name = f"{parent}/{test['name']}" if parent else test["name"]
        if test["status"] in ("SUCCESS", "SKIPPED"):
            for line in test["log"]:
                yield f"{name}: {line}"
        for child in test["children"]:
            yield from successful_logs(child, name)
    logs = "\n".join(line for suite in tests["suites"] for line in successful_logs(suite))
    (directory / "messages.log").write_text("\n".join(messages) + "\n")
    (directory / "report.txt").write_text(details + "\n" + logs + "\n" + summary + metadata + "\n\n" + diagnostics + "\n")
    saved = {key: value for key, value in report.items() if key != "printed_suites"}
    (directory / "result.json").write_text(json.dumps(saved, indent=2) + "\n")
    show_suites(tests, report)
    modules = report.get("modules", [])
    summary_lines = case_details(tests, verbose)
    metadata_lines = module_metadata(modules) if verbose else core_metadata(modules)
    summary_lines.extend(metadata_lines)
    if metadata_lines and summary_lines[-1]:
        summary_lines.append("")
    if "kernel" in report:
        summary_lines.append(f"Runtime kernel: {report['kernel']} ({report['architecture']})")
    if verbose:
        summary_lines.extend(f"Module {item['name']}: {item.get('state', 'unknown')}"
                             for item in report.get("modules", []))
    if report.get("labels"):
        summary_lines.append("Labels: " + " ".join(report["labels"]))
    if summary_lines and summary_lines[-1]:
        summary_lines.append("")
    missing = len(report["not_run_suites"])
    not_run = f"{missing} " + ("suite" if missing == 1 else "suites") + " not run"
    if reason := report.get("stop_reason"):
        summary_lines.append(f"Stopped: {reason}; {not_run}")
    elif events and report["not_run_suites"]:
        summary_lines.append(f"Stopped: kernel diagnostics; {not_run}")
    for error in report["errors"]:
        wrapped = textwrap.wrap("Error: " + " ".join(error.split()), width=88,
                                subsequent_indent="  ")
        summary_lines.extend(wrapped if verbose else wrapped[:6])
        if not verbose and len(wrapped) > 6:
            summary_lines.append("  ... full error in report.txt")
    if started or tests["suites"]:
        extra = ""
        if counts["crashed"] or counts["errors"]:
            extra = f", {counts['crashed']} crashed, {counts['errors']} parse errors"
        summary_lines.append(f"Tests:   {tests['test_status']} - {counts['passed']} passed, "
                             f"{counts['failed']} failed, {counts['skipped']} skipped{extra}")
        summary_lines.append(f"Suites:  {len(started)}/{len(expected)} started, "
                             f"{len(report['not_run_suites'])} not run")
    else:
        summary_lines.append(f"Tests:   NOT_RUN ({not_run})")
    kernel_status = "FAIL" if events else "ERROR" if report["errors"] else "PASS"
    if not events and not started and not report.get("commands"):
        kernel_status = "NOT_RUN"
    summary_lines.append(f"Kernel:  {kernel_status} - {events} diagnostic "
                         + ("event" if events == 1 else "events"))
    if verbose:
        summary_lines.extend(tests["diagnostics"])
        summary_lines.extend("NOT_RUN: " + suite for suite in report["not_run_suites"])
    elif events:
        headlines = Counter(block.splitlines()[0] for block in tests["diagnostics"])
        for headline, count in list(headlines.items())[:3]:
            summary_lines.append("  " + headline + (f" ({count} events)" if count > 1 else ""))
        summary_lines.append("  Full diagnostics: messages.log and report.txt")
    state = f"Modules: {report['module_state']}"
    if "kunit_state" in report:
        state += f"; KUnit {report['kunit_state']}"
    summary_lines.append(state)
    elapsed = f" ({report['elapsed_seconds']:.2f}s)" if "elapsed_seconds" in report else ""
    summary_lines.append(f"Result:  {report['status']}{elapsed}")
    print("\n" + color_console("\n".join(summary_lines)) + f"\nReports: {directory}")

    return {"PASS": 0, "SKIP": 0, "FAIL": 1, "ERROR": 2}[report["status"]]


def color_console(text):
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return text
    colors = {"PASS": 32, "SUCCESS": 32, "FAIL": 31, "FAILURE": 31, "ERROR": 31,
              "BUG": 31, "CRASH": 31, "WARNING": 33, "SKIP": 33, "SKIPPED": 33, "NOT_RUN": 33,
              "retained": 33}
    return re.sub(r"\b(" + "|".join(colors) + r")\b",
                  lambda match: f"\033[{colors[match[0]]}m{match[0]}\033[0m", text)


def main(argv=None):
    try:
        modules, timeout, parent, verbose, labels = arguments(argv)
    except (OSError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-"), dir=parent))
    report = {"status": "ERROR", "module_paths": [str(path) for path in modules],
              "labels": labels, "module_state": "not attempted",
              "kernel": platform.release(), "architecture": platform.machine(),
              "errors": [], "commands": []}
    print(f"Reports: {directory}", flush=True)
    started = time.monotonic()
    try:
        # Serialize only this runner. Other module administration must stay idle.
        fd = os.open("/run/lock/scst-kunit.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RunError("Another SCST KUnit runner holds the lock") from exc
            execute(modules, timeout, directory, report, labels, verbose)
    except KeyboardInterrupt:
        report["errors"].append("Interrupted; module operations may still be running; inspect their PIDs")
    except (RunError, OSError, ValueError, subprocess.SubprocessError) as exc:
        report["errors"].append(str(exc))
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return finish(report, directory, verbose)


if __name__ == "__main__":
    sys.exit(main())
