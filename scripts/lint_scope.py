"""Shared, tracked C source scope for SCST analyzers."""

import os
import subprocess
from pathlib import Path

SOURCE_DIRS = ("scst", "iscsi-scst", "qla2x00t-32gbit/qla2x00-target",
               "srpt", "fcst", "scst_local", "usr")
# Compiler capability probes are intentionally not ordinary product code.
EXCLUDE_DIRS = ("iscsi-scst/conftest", "srpt/conftest")


def in_scope(path: Path, root: Path) -> bool:
    try:
        # Neither an alias nor its destination may widen the source scope.
        names = (Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root))).as_posix(),
                 path.resolve().relative_to(root.resolve()).as_posix())
    except ValueError:
        return False
    return all(name.startswith(tuple(directory + "/" for directory in SOURCE_DIRS))
               and Path(name).suffix in {".c", ".h"} and not name.endswith(".mod.c")
               and not any(name.startswith(directory + "/") for directory in EXCLUDE_DIRS)
               for name in names)


def git_pathspecs() -> list[str]:
    return [*(f":(top){directory}/*.[ch]" for directory in SOURCE_DIRS),
            ":(top,exclude)*.mod.c",
            *(f":(top,exclude){directory}/**" for directory in EXCLUDE_DIRS)]


def git_names(root: Path, *arguments: str) -> list[str]:
    output = subprocess.check_output(["git", "-C", str(root), *arguments])
    return [os.fsdecode(name) for name in output.split(b"\0") if name]


def tracked_sources(root: Path) -> list[Path]:
    names = git_names(root, "ls-files", "--cached", "-z", "--", *SOURCE_DIRS)
    return sorted({root / name for name in names
                   if in_scope(root / name, root) and (root / name).is_file()})


def changed_sources(root: Path, base: str) -> list[Path]:
    names = git_names(root, "diff", "--no-renames", "--name-only", "-z",
                      "--diff-filter=d", base, "--", *git_pathspecs())
    return sorted({root / name for name in names
                   if in_scope(root / name, root) and (root / name).is_file()})


def select_sources(root: Path, files: list[Path], base: str | None) -> list[Path]:
    if files and base:
        raise ValueError("select files or a Git base, not both")
    if files:
        for path in files:
            if not path.is_file() or not in_scope(path, root):
                raise ValueError(f"not a project C source/header: {path}")
        return sorted({path.resolve() for path in files})
    return changed_sources(root, base) if base else tracked_sources(root)
