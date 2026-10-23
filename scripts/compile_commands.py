#!/usr/bin/env python3
"""Export real compiler commands for SCST and Cppcheck."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_common import entrypoint, run, show_log  # noqa: E402
from lint_kbuild import build_lock, collect as collect_checks, unchecked_invocations  # noqa: E402


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    temporary.replace(path)


def source_files(arguments, profile, root):
    if profile == "kernel":
        candidates = arguments[-1:]
    elif "-c" in arguments:
        candidates = [arg for arg in arguments if arg.endswith(".c") and not arg.startswith("-")]
    else:
        return []
    return [path for arg in candidates if (path := Path(arg).resolve()).is_file()
            and path.is_relative_to(root) and not path.name.endswith(".mod.c")]


def record(directory, arguments, profile):
    for source in source_files(arguments, profile, ROOT):
        with tempfile.NamedTemporaryFile(dir=directory, suffix=".json", delete=False) as stream:
            path = Path(stream.name)
        entry = {"directory": str(Path.cwd()), "file": str(source),
                 "arguments": arguments, "state": "started", "returncode": 2}
        write_json(path, entry)
        entry.update(state="complete", returncode=0)
        write_json(path, entry)


def load_records(directory):
    records = [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]
    if not records:
        raise ValueError(f"No compilation records: {directory}")
    for row in records:
        if (row.get("state") != "complete" or row.get("returncode") != 0 or
                not Path(row["directory"]).is_absolute() or not Path(row["file"]).is_absolute() or
                not row.get("arguments")):
            raise ValueError(f"Unfinished or invalid compilation record in {directory}")
    return records


def read_database(path, root):
    entries = json.loads(path.read_text())
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"Empty or invalid compilation database: {path}")
    result = []
    for entry in entries:
        directory = Path(entry["directory"])
        source = (directory / entry["file"]).resolve()
        if (not directory.is_absolute() or not source.is_file() or
                not source.is_relative_to(root) or source.suffix != ".c" or
                source.name.endswith(".mod.c")):
            raise ValueError(f"Invalid compiler input in {path}: {source}")
        args = entry.get("arguments") or shlex.split(entry.get("command", ""))
        if not args:
            raise ValueError(f"Missing compiler command in {path}: {source}")
        result.append({"directory": str(directory), "file": str(source), "arguments": args})
    return result


def module_database(root, checks, directory, log):
    """Use Kbuild's own .cmd reader, retaining each CHECK's actual compiler cwd."""
    kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR") or
                  f"/lib/modules/{os.environ.get('KVER') or os.uname().release}/build").resolve()
    generator = kernel / "scripts/clang-tools/gen_compile_commands.py"
    if not generator.is_file():
        raise ValueError(f"Kernel compilation database generator not found: {generator}")
    entries = []
    for index, cwd in enumerate(sorted({row["directory"] for row in checks})):
        if Path(cwd).resolve() == kernel:
            raise ValueError("Legacy external-module Kbuild layout is unsupported; use the current "
                             "analysis kernel selected in scripts/ci/kernel.env")
        output = directory / f"kernel-{index}.json"
        # Match Kbuild's compile_commands.json target: modules.order and .mod
        # enumerate current objects, excluding stale .cmd files from old configs.
        order = Path(cwd) / "modules.order"
        if not order.is_file():
            raise ValueError(f"Kbuild module inventory not found: {order}")
        command = [sys.executable, str(generator), "-d", cwd, "-o", str(output), str(order)]
        invocation = directory / f"kernel-{index}.invocation.json"
        evidence = {"command": command, "directory": cwd, "state": "started", "status": None}
        write_json(invocation, evidence)
        with log.open("ab") as stream:
            status = run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT).returncode
        write_json(invocation, dict(evidence, state="complete", status=status))
        if status:
            raise ValueError(f"Kbuild compiler database export failed: {log}")
        entries.extend(read_database(output, root))
    expected, actual = Counter(row["file"] for row in checks), Counter(row["file"] for row in entries)
    if actual != expected:
        raise ValueError(f"Incomplete compiler database: missing={list((expected - actual).elements())} "
                         f"unexpected={list((actual - expected).elements())}")
    return entries


def collect(root, output, *, log=None, context=None, locked=False):
    """Publish one database only after fresh kernel and CLI inventories complete."""
    if not locked:
        with build_lock(root):
            return collect(root, output, log=log, context=context, locked=True)
    output = output.resolve()
    cache = root / ".cache/lint/compile-commands"
    cache.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=cache))
    checks, cli = directory / "checks", directory / "cli"
    checks.mkdir()
    cli.mkdir()
    log = log or directory / "build.log"
    manifest = directory / "context.json"
    result = {"state": "started", "directory": str(directory), "kernel_make_status": None,
              "userspace_make_status": None, "inputs": [], "failures": [], "log": str(log)}
    write_json(manifest, result)
    if context:
        write_json(context, result)
    show_log(log, "Compilation database build log")
    try:
        checker = [sys.executable, str(Path(__file__).resolve()),
                   "record-check", str(checks)]
        result["kernel_make_status"], _ = collect_checks(
            root, "compile-commands", checks, log, checker=checker, checkflags="")
        if result["kernel_make_status"]:
            raise ValueError(f"Compilation database build failed: {log}")
        records = load_records(checks)
        sources = {root / os.fsdecode(name) for name in subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-z", "--", "*.c"]).split(b"\0") if name}
        missing = unchecked_invocations(root, "common", log, records, source_inputs=sources)
        if missing:
            raise ValueError(f"Unrecorded Kbuild CHECK invocations: {missing}")
        entries = module_database(root, records, directory, log)
        command = ["make", "--no-silent", "-C", str(root), "compile-commands-cli",
                   "COMPILE_COMMANDS_DIR=" + str(cli)]
        with log.open("ab") as stream:
            result["userspace_make_status"] = run(command, stdout=stream, stderr=subprocess.STDOUT,
                                                   progress="CLI compiler command export").returncode
        if result["userspace_make_status"]:
            raise ValueError(f"CLI compiler command export failed: {log}")
        entries += [{key: row[key] for key in ("directory", "file", "arguments")}
                    for row in load_records(cli)]
        entries.sort(key=lambda row: (row["file"], row["directory"]))
        write_json(output, entries)
        result.update(state="complete", total_commands=len(entries),
                      inputs=sorted({row["file"] for row in entries}))
        print(f"Compilation database: {len(entries)} C commands; {output}", flush=True)
        return result
    except BaseException as error:
        result.update(state="failed", failures=[str(error) or type(error).__name__])
        raise
    finally:
        write_json(manifest, result)
        if context:
            write_json(context, result)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"record", "record-check"}:
        arguments = sys.argv[3:]
        if arguments[:1] == ["--"]:
            arguments = arguments[1:]
        record(Path(sys.argv[2]), arguments, "kernel" if sys.argv[1] == "record-check" else "userspace")
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "compile_commands.json")
    args = parser.parse_args()
    collect(ROOT, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(entrypoint(main))
