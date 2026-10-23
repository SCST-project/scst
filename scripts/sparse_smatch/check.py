#!/usr/bin/env python3
"""Kbuild CHECK adapter: preserve diagnostics and record every attempted check."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_scope import in_scope  # noqa: E402
from analyzer_policy import load_policy  # noqa: E402
from sparse_smatch.records import write_record
from sparse_smatch.native import checker_command  # noqa: E402

DIAGNOSTIC = re.compile(
    rb"^(?:.+?:\d+(?::\d+)?(?::| (?P<function>[^ ]+\(\)))\s+|(?:[^:\s]+:\s*)?)"
    rb"(?P<severity>(?:fatal )?error|warn(?:ing)?):", re.M | re.I)
TRUNCATED = re.compile(rb"\b(?:warning|error): too many (?:warnings|errors)\b", re.I)
SMATCH_WARNING = re.compile(
    rb"(?P<file>.+):\d+ (?P<function>\w+)\(\) warn: (?P<message>[^\r\n]+)")
KERNEL_WARNING = re.compile(rb"(?P<file>.+):\d+:\d+: warning: (?P<message>[^\r\n]+)")


def kernel_header(arguments, relative):
    """Resolve one external header from Kbuild's forced kernel config include."""
    headers = set()
    for option, value in zip(arguments, arguments[1:]):
        if option != "-include":
            continue
        config = Path(value).resolve()
        if config.parts[-3:] != ("include", "linux", "kconfig.h") or not config.is_file():
            continue
        header = (config.parents[2] / relative).resolve()
        if not header.is_relative_to(ROOT) and header.is_file():
            headers.add(header)
    # Ambiguous or missing context must not broaden an exception.
    return next(iter(headers)) if len(headers) == 1 else None


def ignored_warning(tool, line, headers):
    """Return the reviewed exception, without removing the raw diagnostic."""
    policy = load_policy(tool)
    if match := KERNEL_WARNING.fullmatch(line):
        for rule in policy["kernel_exceptions"]:
            if (headers[rule["header"]] is not None and
                    Path(os.fsdecode(match["file"])).resolve() == headers[rule["header"]] and
                    os.fsdecode(match["message"]) == rule["message"]):
                return {"diagnostic": os.fsdecode(line), "reason": rule["reason"]}
    if tool != "smatch" or not (match := SMATCH_WARNING.fullmatch(line)):
        return None
    try:
        source = Path(os.fsdecode(match["file"])).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return None
    for rule in policy["source_exceptions"]:
        if (source == rule["file"] and os.fsdecode(match["function"]) == rule["function"] and
                os.fsdecode(match["message"]) == rule["message"]):
            return {"diagnostic": os.fsdecode(line), "reason": rule["reason"]}
    return None


def main():
    tool, *arguments = sys.argv[1:]
    if tool not in ("sparse", "smatch") or not arguments:
        raise ValueError("Kbuild did not supply a translation unit")
    policy = load_policy(tool)
    source = Path(arguments[-1])
    # The kernel's checker-valid.sh uses an external temporary input without
    # a .c suffix. It must reach the real checker, not succeed as a scope skip.
    if not source.resolve().is_relative_to(ROOT):
        command = checker_command(tool)
        if record := os.environ.get("SCST_LINT_PROBE_RECORD"):
            result = subprocess.run([*command, *arguments], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            with Path(os.environ["SCST_LINT_PROBE_LOG"]).open("ab") as output:
                output.write(result.stdout)
            Path(record).write_text(json.dumps({"returncode": result.returncode}))
            sys.stdout.buffer.write(result.stdout)
            return result.returncode if result.returncode >= 0 else 128 - result.returncode
        os.execv(command[0], [*command, *arguments])
    if source.suffix != ".c" or not in_scope(source, ROOT, tool):
        return 0
    source = source.resolve()
    record = {"directory": str(Path.cwd()), "file": str(source),
              "arguments": ["cc", *arguments], "returncode": 2,
              "findings": 0, "ignored": [], "errors": 0, "state": "started"}
    # Kbuild can discard CHECK's exit status. Leave a failed record even if
    # spawning the tool fails or this adapter is interrupted before completion.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False,
                                     dir=os.environ["SCST_LINT_RECORDS"]) as output:
        json.dump(record, output)
        record_path = Path(output.name)
    command = [*checker_command(tool), *arguments[:-1], "-fmax-warnings=unlimited", arguments[-1]]
    record["checker_arguments"] = command
    native_log = record_path.with_suffix(".log")
    record["log"] = str(native_log)
    write_record(record_path, record)
    # Stream before waiting: a killed checker must leave its partial evidence.
    with native_log.open("wb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    output = native_log.read_bytes()
    sys.stdout.buffer.write(output)
    diagnostics = [match for line in output.splitlines()
                   if (match := DIAGNOSTIC.match(line))]
    headers = {rule["header"]: kernel_header(arguments, rule["header"])
               for rule in policy["kernel_exceptions"]}
    record.update(returncode=result.returncode, state="complete", findings=len(diagnostics),
                  ignored=[entry for item in diagnostics
                           if (entry := ignored_warning(tool, item.string, headers))],
                  errors=sum(b"error" in item["severity"].lower() and not item["function"]
                             for item in diagnostics) + bool(TRUNCATED.search(output)))
    # Smatch's "file:line function() error:" is a source finding; frontend
    # "file:line:column: error:" means parsing failed, even with a zero exit.
    write_record(record_path, record)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"SCST checker failed: {error}", file=sys.stderr)
        sys.exit(2)
