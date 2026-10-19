"""Shared, tracked C source scope for SCST analyzers."""

import os
import subprocess
from pathlib import Path

from analyzer_policy import source_policy


def in_scope(path: Path, root: Path, tool="common") -> bool:
    policy = source_policy(tool)
    try:
        # Neither an alias nor its destination may widen the source scope.
        names = (Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root))).as_posix(),
                 path.resolve().relative_to(root.resolve()).as_posix())
    except ValueError:
        return False
    return all(name.startswith(tuple(directory + "/" for directory in policy["source_roots"]))
               and Path(name).suffix in policy["source_suffixes"]
               and not any(name.endswith(rule["suffix"]) for rule in policy["exclude_suffixes"])
               and not any(name.startswith(rule["path"] + "/")
                           for rule in policy["exclude_directories"])
               for name in names)


def glob_literal(value: str) -> str:
    """Quote literal policy paths for Git's glob pathspecs."""
    return "".join({"[": "[[]", "*": "[*]", "?": "[?]"}.get(char, char) for char in value)


def git_pathspecs(tool="common") -> list[str]:
    policy = source_policy(tool)
    return [*(f":(top,glob){glob_literal(directory)}/**/*{suffix}"
              for directory in policy["source_roots"] for suffix in policy["source_suffixes"]),
            *(f":(top,exclude,glob)**/*{rule['suffix']}" for rule in policy["exclude_suffixes"]),
            *(f":(top,exclude,glob){glob_literal(rule['path'])}/**"
              for rule in policy["exclude_directories"])]


def git_names(root: Path, *arguments: str) -> list[str]:
    output = subprocess.check_output(["git", "-C", str(root), *arguments])
    return [os.fsdecode(name) for name in output.split(b"\0") if name]


def tracked_sources(root: Path, tool="common") -> list[Path]:
    roots = [f":(top,literal){directory}" for directory in source_policy(tool)["source_roots"]]
    names = git_names(root, "ls-files", "--cached", "-z", "--", *roots)
    return sorted({root / name for name in names
                   if in_scope(root / name, root, tool) and (root / name).is_file()})


def resolve_base(root: Path, base: str) -> str:
    """Require one commit before passing a user-supplied base to Git diff."""
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--verify", "--end-of-options",
         f"{base}^{{commit}}"], text=True).strip()


def changed_sources(root: Path, base: str, tool="common") -> list[Path]:
    revision = resolve_base(root, base)
    names = git_names(root, "diff", "--no-renames", "--name-only", "-z",
                      "--diff-filter=d", revision, "--", *git_pathspecs(tool))
    return sorted({root / name for name in names
                   if in_scope(root / name, root, tool) and (root / name).is_file()})


def select_sources(root: Path, files: list[Path], base: str | None, tool="common") -> list[Path]:
    if files and base:
        raise ValueError("select files or a Git base, not both")
    if files:
        for path in files:
            if not path.is_file() or not in_scope(path, root, tool):
                raise ValueError(f"not a project C source/header: {path}")
        return sorted({path.resolve() for path in files})
    return changed_sources(root, base, tool) if base else tracked_sources(root, tool)
