#!/usr/bin/env python3
"""Run focused non-build checks selected by one committed range."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

WORKFLOW_DIR = Path(__file__).resolve().parent
RUFF_VERSION = "0.12.8"
CHECK_BLOCKED_RETURN_CODE = 2
CommandRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]


class LintError(Exception):
    """An unavailable Git prerequisite."""


class LintRangeError(Exception):
    """An invalid committed range."""


def git(
    repository: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        raise LintError(f"git command failed: {' '.join(args)}: {detail}") from exc


def git_predicate(repository: Path, *args: str) -> bool:
    result = git(repository, *args, check=False)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise LintError(f"git command failed: {' '.join(args)}: {result.stderr.strip()}")


def changed_paths(repository: Path, base: str, head: str) -> list[str]:
    if not git_predicate(repository, "merge-base", "--is-ancestor", base, head):
        raise LintRangeError("base is not an ancestor of head")
    result = git(repository, "diff", "--name-only", "-z", "--no-renames", f"{base}..{head}")
    return sorted(path for path in result.stdout.split("\0") if path)


def is_agent_config_path(path: str) -> bool:
    return (
        path == "AGENTS.md"
        or path.endswith("/AGENTS.md")
        or path == "CLAUDE.md"
        or path.endswith("/CLAUDE.md")
        or path.startswith(".agents/")
        or path.startswith(".codex/agents/")
        or path == "doc/AGENT_HARNESS.md"
        or (path.startswith("doc/AGENT_WORKFLOW") and path.endswith(".md"))
    )


def run_command(command: Sequence[str], repository: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        list(command),
        cwd=repository,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def execute_check(
    name: str,
    command: Sequence[str],
    repository: Path,
    runner: CommandRunner,
    blocked_returncodes: frozenset[int] = frozenset(),
) -> dict[str, Any]:
    try:
        completed = runner(command, repository)
    except OSError as exc:
        return {"name": name, "output": str(exc), "status": "BLOCKED"}
    if completed.returncode == 0:
        status = "PASS"
    elif completed.returncode in blocked_returncodes:
        status = "BLOCKED"
    else:
        status = "FAIL"
    return {
        "name": name,
        "output": completed.stdout.strip() if completed.returncode else "",
        "status": status,
    }


def combined_status(checks: Sequence[dict[str, Any]]) -> str:
    statuses = {check["status"] for check in checks}
    if "BLOCKED" in statuses:
        return "BLOCKED"
    if "FAIL" in statuses:
        return "FAIL"
    return "PASS" if checks else "NOT_APPLICABLE"


def run_selected_checks(
    repository: Path,
    paths: Sequence[str],
    *,
    runner: CommandRunner = run_command,
) -> dict[str, Any]:
    python_paths = sorted(
        path for path in paths if path.endswith(".py") and (repository / path).is_file()
    )
    agent_config_changed = any(is_agent_config_path(path) for path in paths)
    python_checks: list[dict[str, Any]] = []
    agent_checks: list[dict[str, Any]] = []

    if python_paths:
        python_checks.append(
            execute_check(
                "python-ruff",
                [
                    "uvx",
                    "--from",
                    f"ruff=={RUFF_VERSION}",
                    "ruff",
                    "check",
                    "--config",
                    str(WORKFLOW_DIR / "ruff.toml"),
                    "--",
                    *python_paths,
                ],
                repository,
                runner,
                frozenset({2, 127}),
            )
        )

    if agent_config_changed:
        agent_checks.extend(
            [
                execute_check(
                    "agent-instructions",
                    [
                        sys.executable,
                        str(WORKFLOW_DIR / "check.py"),
                        "instructions",
                        "--repository",
                        str(repository),
                    ],
                    repository,
                    runner,
                    frozenset({CHECK_BLOCKED_RETURN_CODE}),
                ),
                execute_check(
                    "workflow-unittest",
                    [
                        sys.executable,
                        "-m",
                        "unittest",
                        "discover",
                        "-s",
                        str(WORKFLOW_DIR),
                        "-p",
                        "test_*.py",
                    ],
                    repository,
                    runner,
                ),
            ]
        )

    checks = [*python_checks, *agent_checks]
    return {
        "agent_config_changed": agent_config_changed,
        "agent_config_lint": combined_status(agent_checks),
        "checks": checks,
        "python_files": python_paths,
        "python_lint": combined_status(python_checks),
        "status": combined_status(checks),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        repository = Path(
            git(args.repository, "rev-parse", "--show-toplevel").stdout.strip()
        ).resolve()
        result = run_selected_checks(repository, changed_paths(repository, args.base, args.head))
    except LintRangeError as exc:
        result = {"error": str(exc), "status": "FAIL"}
    except LintError as exc:
        result = {"error": str(exc), "status": "BLOCKED"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"PASS", "NOT_APPLICABLE"} else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
