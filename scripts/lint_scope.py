"""Shared, tracked C source scope for SCST analyzers."""

import os
import subprocess
from pathlib import Path

from analyzer_policy import source_policy


def in_scope(path: Path, root: Path, tool="common", *, policy=None) -> bool:
    policy = source_policy(tool) if policy is None else policy
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


def git_names(root: Path, *arguments: str) -> list[str]:
    try:
        output = subprocess.check_output(["git", "-C", str(root), *arguments],
                                         stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise ValueError(f"Git source selection failed: {detail or error}") from error
    return [os.fsdecode(name) for name in output.split(b"\0") if name]


def tracked_sources(root: Path, tool="common") -> list[Path]:
    roots = [f":(top,literal){directory}" for directory in source_policy(tool)["source_roots"]]
    names = git_names(root, "ls-files", "--cached", "-z", "--", *roots)
    return sorted({root / name for name in names
                   if in_scope(root / name, root, tool) and (root / name).is_file()})


def select_sources(root: Path, files: list[Path], tool="common") -> list[Path]:
    if files:
        for path in files:
            if not path.is_file() or not in_scope(path, root, tool):
                raise ValueError(f"not a project C source/header: {path}")
        return sorted({path.resolve() for path in files})
    return tracked_sources(root, tool)
