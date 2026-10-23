#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "tree-sitter==0.25.2",
#     "tree-sitter-c==0.24.1",
# ]
# ///

"""Check mechanically enforceable SCST code style rules in C sources."""

import argparse
import fcntl
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import tree_sitter as ts
import tree_sitter_c

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lint_scope import select_sources  # noqa: E402
from lint_common import entrypoint, log_path, show_log  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[2]
VISIBILITY = (b"SCST_KUNIT_VISIBLE", b"SCST_KUNIT_VISIBLE_INLINE", b"VISIBLE_IF_KUNIT")
CONDITIONALS = {"preproc_if", "preproc_ifdef", "preproc_elif", "preproc_elifdef", "preproc_else"}


@dataclass(frozen=True)
class Violation:
    line: int
    column: int
    rule: str
    message: str


def code_nodes(root: ts.Node):
    """Visit code in every conditional branch, excluding directive contents."""
    stack = [root]
    while stack:
        node = stack.pop()
        hidden = []
        if node.type.startswith("preproc_"):
            if node.type not in CONDITIONALS:
                continue
            hidden = [node.child_by_field_name("condition"), node.child_by_field_name("name")]
        yield node
        stack.extend(child for child in reversed(node.children) if child not in hidden)


def check_source(source: bytes, parser: ts.Parser) -> list[Violation]:
    if not any(annotation in source for annotation in VISIBILITY):
        return []

    code = bytearray(source)
    annotations = []
    for node in code_nodes(parser.parse(source).root_node):
        if node.type == "comment":
            # Mask comments without moving the source offsets used for diagnostics.
            code[node.start_byte:node.end_byte] = b" " * (node.end_byte - node.start_byte)
        elif node.type in {"identifier", "type_identifier"} and node.text in VISIBILITY:
            annotations.append(node)

    violations = []
    for node in annotations:
        start = source.rfind(b"\n", 0, node.start_byte) + 1
        end = source.find(b"\n", node.end_byte)
        if end == -1:
            end = len(source)
        if code[start:end].strip() != node.text:
            row, column = node.start_point
            violations.append(Violation(
                row + 1, column + 1, "SCS.1",
                f"place {node.text.decode()} on a line of its own"))
    return violations


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="*", type=Path, metavar="FILE",
                    help="C source/header files; default: tracked project C sources and headers")
    args = ap.parse_args(argv)

    with log_path(REPOSITORY, "scs_lint.lock", truncate=False).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        log = log_path(REPOSITORY, "scs_lint.log")
        report = {"tool": "scs_lint", "outcome": "incomplete", "exit_code": 2,
                  "remaining": 0, "selected_files": [], "checked_files": []}
        show_log(log)
        try:
            paths = select_sources(REPOSITORY, args.files, "scs_lint")
            report["selected_files"] = [path.relative_to(REPOSITORY).as_posix() for path in paths]
            parser = ts.Parser(ts.Language(tree_sitter_c.language()))
            with log.open("a") as output:
                for path in paths:
                    for violation in check_source(path.read_bytes(), parser):
                        message = (f"{path}:{violation.line}:{violation.column}: error: "
                                   f"{violation.rule}: {violation.message}")
                        print(message)
                        output.write(message + "\n")
                        report["remaining"] += 1
                    report["checked_files"].append(path.relative_to(REPOSITORY).as_posix())
                status = int(bool(report["remaining"]))
                report.update(outcome=("findings" if status else "clean") if paths else "skipped",
                              exit_code=status)
                summary = f"{report['remaining']} violation(s), {len(paths)} file(s) checked"
                if not paths:
                    summary += "; no eligible inputs, skipped"
                print(summary, file=sys.stderr)
                output.write(summary + "\n")
            return status
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            message = f"scs_lint: {exc}"
            print(message, file=sys.stderr)
            with log.open("a") as output:
                output.write(message + "\n")
            return 2
        finally:
            log.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(entrypoint(main))
