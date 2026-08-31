#!/usr/bin/env python3
"""Read-only Git and agent-instruction checks for the SCST patch workflow."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

USER_FACING_SKILLS = frozenset({"scst-develop-task", "scst-validate-series"})


class CheckError(Exception):
    """An invalid check input or repository diagnostic."""


class CheckBlocked(Exception):
    """An unavailable prerequisite that prevents a reliable check."""


class CheckArgumentParser(argparse.ArgumentParser):
    """Argument parser that keeps failures in the machine-readable result path."""

    def error(self, message: str) -> None:
        raise CheckError(message)


def git_failure(args: tuple[str, ...], detail: str) -> str:
    message = f"git command failed: {' '.join(args)}"
    return f"{message}: {detail}" if detail else message


def git(repository: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
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
        raise CheckBlocked(git_failure(args, detail)) from exc


def git_predicate(repository: Path, *args: str) -> bool:
    result = git(repository, *args, check=False)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise CheckBlocked(git_failure(args, result.stderr.strip()))


def resolve_commit(repository: Path, value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise CheckError(f"commit must be a literal full SHA: {value}")
    result = git(repository, "cat-file", "-t", value)
    if result.stdout.strip() != "commit":
        raise CheckError(f"object is not a commit: {value}")
    return value


def check_snapshot(
    repository: Path,
    base: str,
    head: str,
    *,
    allow_empty: bool = False,
    require_no_untracked: bool = False,
) -> dict[str, Any]:
    resolved_base = resolve_commit(repository, base)
    resolved_head = resolve_commit(repository, head)
    errors: list[str] = []

    if resolved_base == resolved_head and not allow_empty:
        errors.append("empty commit range")

    if not git_predicate(
        repository,
        "merge-base",
        "--is-ancestor",
        resolved_base,
        resolved_head,
    ):
        errors.append("base is not an ancestor of head")

    current = git(repository, "rev-parse", "HEAD").stdout.strip()
    if current != resolved_head:
        errors.append(f"stale snapshot: HEAD={current}, expected={resolved_head}")

    for cached, message in (
        (False, "unstaged tracked changes are present"),
        (True, "staged tracked changes are present"),
    ):
        args = ["diff"]
        if cached:
            args.append("--cached")
        args.extend(["--quiet", "--ignore-submodules=untracked"])
        if not git_predicate(repository, *args):
            errors.append(message)

    if require_no_untracked:
        untracked = git(repository, "ls-files", "--others", "--exclude-standard", "-z")
        if untracked.stdout:
            errors.append("untracked files are present")

    return {
        "base": resolved_base,
        "errors": errors,
        "head": resolved_head,
        "status": "PASS" if not errors else "FAIL",
    }


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CheckBlocked(f"cannot read {path}: {exc}") from exc
    except UnicodeError as exc:
        raise CheckError(f"cannot read {path}: {exc}") from exc


def parse_skill_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    text = read_text(path)
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise CheckError(f"{path}: missing YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise CheckError(f"{path}: unterminated YAML frontmatter") from exc

    fields: dict[str, str] = {}
    for line in lines[1:end]:
        match = re.fullmatch(r"([a-z_]+):\s*(.+)", line)
        if match is None or match.group(1) in fields:
            raise CheckError(f"{path}: invalid YAML frontmatter line: {line}")
        fields[match.group(1)] = match.group(2).strip().strip('"')
    if set(fields) != {"name", "description"}:
        raise CheckError(f"{path}: frontmatter requires only name and description")
    return fields, "\n".join(lines[end + 1 :])


def tracked_paths(repository: Path) -> set[str]:
    result = git(repository, "ls-files", "-z")
    return {path for path in result.stdout.split("\0") if path}


def implicit_invocation_disabled(metadata: str) -> bool:
    lines = metadata.splitlines()
    policy_indexes = [index for index, line in enumerate(lines) if line == "policy:"]
    if len(policy_indexes) != 1:
        return False

    values: list[str] = []
    for nested in lines[policy_indexes[0] + 1 :]:
        if nested and not nested[0].isspace():
            break
        if nested.startswith("  allow_implicit_invocation:"):
            values.append(nested)
    return values == ["  allow_implicit_invocation: false"]


def top_level_section_count(metadata: str, section: str) -> int:
    return metadata.splitlines().count(f"{section}:")


def instruction_errors(repository: Path) -> list[str]:
    errors: list[str] = []
    tracked = tracked_paths(repository)
    skill_paths = sorted(
        path
        for path in tracked
        if re.fullmatch(r"\.agents/skills/[^/]+/SKILL\.md", path)
    )
    for skill_path in skill_paths:
        skill_file = repository / skill_path
        try:
            fields, body = parse_skill_frontmatter(skill_file)
        except CheckError as exc:
            errors.append(str(exc))
            continue

        name = fields["name"]
        if name != skill_file.parent.name or re.fullmatch(r"[a-z0-9-]{1,64}", name) is None:
            errors.append(f"{skill_file}: invalid skill name: {name}")
        if not name.startswith("scst-"):
            errors.append(f"{skill_file}: skill name must use the scst- namespace: {name}")
        if not fields["description"].strip():
            errors.append(f"{skill_file}: empty description")

        skill_directory = skill_file.parent.relative_to(repository).as_posix()
        reference_prefix = f"{skill_directory}/references/"
        reference_paths = sorted(
            path
            for path in tracked
            if path.startswith(reference_prefix)
            and path.endswith(".md")
            and "/" not in path[len(reference_prefix) :]
        )
        for reference_path in reference_paths:
            relative = f"references/{Path(reference_path).name}"
            if relative not in body:
                errors.append(f"{skill_file}: unreferenced resource: {relative}")

        for relative in sorted(set(re.findall(r"references/[A-Za-z0-9._/-]+\.md", body))):
            target = (skill_file.parent / relative).resolve()
            try:
                target_path = target.relative_to(repository).as_posix()
            except ValueError:
                target_path = ""
            if (
                skill_file.parent.resolve() not in target.parents
                or target_path not in tracked
                or not target.is_file()
            ):
                errors.append(f"{skill_file}: missing reference: {relative}")

        metadata_path = f"{skill_directory}/agents/openai.yaml"
        metadata = repository / metadata_path
        if metadata_path not in tracked:
            errors.append(f"{metadata}: missing skill metadata")
            continue

        metadata_text = read_text(metadata)
        interface_count = top_level_section_count(metadata_text, "interface")
        if name in USER_FACING_SKILLS:
            if interface_count != 1:
                errors.append(f"{metadata}: user-facing skill must define one interface")
            elif f"${name}" not in metadata_text:
                errors.append(f"{metadata}: default prompt does not mention ${name}")
        elif interface_count:
            errors.append(f"{metadata}: internal skill metadata must not define interface")
        if not implicit_invocation_disabled(metadata_text):
            errors.append(f"{metadata}: implicit invocation must be disabled")

    role_paths = sorted(
        path
        for path in tracked
        if re.fullmatch(r"\.codex/agents/[^/]+\.toml", path)
    )
    if not role_paths:
        errors.append(f"{repository / '.codex' / 'agents'}: no tracked agent roles")

    for role_relative in role_paths:
        role_path = repository / role_relative
        expected_name = role_path.stem
        try:
            role = tomllib.loads(read_text(role_path))
        except (CheckError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{role_path}: invalid TOML: {exc}")
            continue
        if role.get("name") != expected_name:
            errors.append(f"{role_path}: role name does not match {expected_name}")
        description = role.get("description")
        if not isinstance(description, str) or not description.strip():
            errors.append(f"{role_path}: description is empty")
        instructions = role.get("developer_instructions")
        if not isinstance(instructions, str) or not instructions.strip():
            errors.append(f"{role_path}: developer_instructions is empty")
        if expected_name in {"scst_harness_evaluator", "scst_reviewer"}:
            if role.get("sandbox_mode") != "read-only":
                errors.append(f"{role_path}: sandbox_mode must be read-only")

    return errors


def check_instructions(repository: Path) -> dict[str, Any]:
    errors = instruction_errors(repository)
    return {"errors": errors, "status": "PASS" if not errors else "FAIL"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = CheckArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--repository", required=True, type=Path)
    snapshot.add_argument("--base", required=True)
    snapshot.add_argument("--head", required=True)
    snapshot.add_argument("--allow-empty", action="store_true")
    snapshot.add_argument("--require-no-untracked", action="store_true")

    instructions = subparsers.add_parser("instructions")
    instructions.add_argument("--repository", required=True, type=Path)
    return parser.parse_args(argv)


def run_check(args: argparse.Namespace) -> dict[str, Any]:
    try:
        repository = Path(
            git(args.repository, "rev-parse", "--show-toplevel").stdout.strip()
        ).resolve()
        if args.command == "snapshot":
            result = check_snapshot(
                repository,
                args.base,
                args.head,
                allow_empty=args.allow_empty,
                require_no_untracked=args.require_no_untracked,
            )
        else:
            result = check_instructions(repository)
    except CheckBlocked as exc:
        result = {"errors": [str(exc)], "status": "BLOCKED"}
    except CheckError as exc:
        result = {"errors": [str(exc)], "status": "FAIL"}
    return result


def run(argv: list[str]) -> dict[str, Any]:
    try:
        args = parse_args(argv)
    except CheckError as exc:
        return {"errors": [str(exc)], "status": "FAIL"}
    return run_check(args)


def main(argv: list[str]) -> int:
    result = run(argv)
    print(json.dumps(result, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[result["status"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
