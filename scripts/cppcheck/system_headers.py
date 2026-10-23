"""Compile exact include-site advice from the reviewed system-header policy."""

import json
import re
import shlex
from pathlib import Path

INCLUDE = re.compile(r"^\s*#\s*include\s*<([^>]+)>")
NOTICE = re.compile(r"Include file: <([^>]+)> not found\.")


def include_sites(root, source, group):
    """Bind a reviewed header name to its actual file and line."""
    result = []
    name = source.relative_to(root).as_posix() if source.is_relative_to(root) else str(source)
    for line, text in enumerate(source.read_text(errors="replace").splitlines(), 1):
        match = INCLUDE.match(text)
        if match and match[1] in group["headers"]:
            result.append({"id": "missingIncludeSystem", "line": line, "file": name,
                           "header": match[1], "reason": group["reason"]})
    return result


def include_advice(root, sources, policy):
    """Keep unknown names and quoted project includes blocking."""
    result = []
    for source in sorted(set(sources)):
        groups = [group for group in policy["omitted_system_headers"]
                  if not group["dependency_headers"] and
                  any(source.is_relative_to(root / name) for name in group["source_roots"])]
        for group in groups:
            result.extend(include_sites(root, source, group))
    return result


def dependency_advice(root, project, profile_root, policy, include_args=()):
    """Resolve exact dependency headers through this profile's compiler inputs."""
    groups = [group for group in policy["omitted_system_headers"]
              if group["dependency_headers"] and profile_root in group["source_roots"]]
    result, seen = [], set()
    for entry in json.loads(project.read_text()) if groups else ():
        directory = Path(entry["directory"])
        args = entry.get("arguments") or shlex.split(entry["command"])
        paths = []
        it = iter([*include_args, *args])
        for arg in it:
            if arg in ("-I", "-isystem"):
                paths.append((directory / next(it)).resolve())
            elif arg.startswith("-I"):
                paths.append((directory / arg[2:]).resolve())
            elif arg.startswith("-isystem"):
                paths.append((directory / arg[len("-isystem"):]).resolve())
        for index, group in enumerate(groups):
            for header in group["dependency_headers"]:
                source = next((path / header for path in paths if (path / header).is_file()), None)
                if source is None:
                    continue
                source = source.resolve()
                # Never extend this exception to project-owned replacements.
                if source.is_relative_to(root) or (index, source) in seen:
                    continue
                seen.add((index, source))
                result.extend(dict(rule, dependency_header=header)
                              for rule in include_sites(root, source, group))
    return result


def matches_include(rule, name, line, message):
    """Require the exact emitted site and header, not just a diagnostic ID."""
    notice = NOTICE.match(message)
    return (rule["file"] == name and rule["line"] == line and
            notice is not None and rule["header"] == notice[1])
