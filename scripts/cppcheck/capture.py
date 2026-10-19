#!/usr/bin/env python3
"""Record Kbuild CHECK arguments or successful userspace compiler invocations."""

import json
import os
from pathlib import Path
import shlex
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_common import entrypoint, run  # noqa: E402
from lint_scope import in_scope  # noqa: E402


def source_files(arguments, profile, root):
    if profile == "kernel":
        candidates = arguments[-1:]
    elif "-c" in arguments:
        candidates = [arg for arg in arguments if arg.endswith(".c") and not arg.startswith("-")]
    else:
        return []
    return [Path(arg).resolve() for arg in candidates
            if Path(arg).is_file() and in_scope(Path(arg), root, "cppcheck")]


def main():
    profile, *arguments = sys.argv[1:]
    if profile not in {"kernel", "userspace"}:
        raise ValueError(f"unknown capture profile: {profile}")
    sources = source_files(arguments, profile, ROOT)
    compiler = shlex.split(os.environ.get("SCST_LINT_CC", "cc"))
    if not compiler:
        raise ValueError("empty userspace compiler command")
    # Kernel CHECK receives the real c_flags. It only records; Kbuild still
    # invokes its own compiler. Do not run Sparse or add __CHECKER__ definitions.
    command = (["cc"] if profile == "kernel" else compiler) + arguments
    records = []
    for source in sources:
        path = Path(os.environ["SCST_LINT_RECORDS"]) / f"{uuid.uuid4()}.json"
        record = {"file": str(source), "directory": str(Path.cwd()), "arguments": command,
                  "profile": profile, "returncode": 2}
        path.write_text(json.dumps(record) + "\n")
        records.append((path, record))
    status = run(command).returncode if profile == "userspace" else 0
    for path, record in records:
        record["returncode"] = status
        path.write_text(json.dumps(record) + "\n")
    return status


if __name__ == "__main__":
    sys.exit(entrypoint(main))
