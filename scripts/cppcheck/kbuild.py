"""Adapt captured SCST build commands for Cppcheck."""

import json
import re
import shlex
from pathlib import Path

from lint_scope import in_scope


def owned_source(root, source):
    return (source.suffix == ".c" and in_scope(source, root, "cppcheck")
            and not source.is_relative_to(root / "usr")
            and not source.is_relative_to(root / "iscsi-scst/usr"))


def defines(header: Path) -> list[str]:
    return ["-D" + match[1] + "=" + match[2] for match in
            re.finditer(r"^#define (\S+) ?(.*)$", header.read_text(), re.MULTILINE)]


def adapt(root: Path, project: Path, output: Path, *, compiler=None, module=True):
    entries = json.loads(project.read_text())
    result = []
    omitted, configurations = set(), set()
    out_of_tree = []
    userspace = []
    for entry in entries:
        directory = Path(entry["directory"]).resolve()
        source = (directory / entry["file"]).resolve()
        if not (owned_source(root, source) if module else in_scope(source, root, "cppcheck")):
            continue
        args = entry.get("arguments")
        if args is None:
            args = shlex.split(entry["command"])
        kept = ["cc"]
        headers = set()
        includes = []
        kernel_roots = set()
        it = iter(args[1:])
        for argument in it:
            if argument in ("-D", "-U"):
                kept.append(argument + next(it))
            elif argument.startswith(("-D", "-U")):
                kept.append(argument)
            elif argument == "-include":
                header = (directory / next(it)).resolve()
                includes.append(("-include", header))
                if header.name == "kconfig.h" and header.parent.name == "linux":
                    kernel_roots.add(header.parents[2])
                    headers.add(header.parent.parent / "generated/autoconf.h")
            elif argument.startswith(("-I", "-isystem")):
                prefix = "-isystem" if argument.startswith("-isystem") else "-I"
                path = next(it) if argument == prefix else argument[len(prefix):]
                include = (directory / path).resolve()
                includes.append(("-I", include))
                for name in ("generated/autoconf.h", "generated/uapi/linux/version.h"):
                    if (include / name).is_file():
                        headers.add(include / name)
                        kernel_roots.add(include.parent)
        for option, path in includes:
            if not module or not any(path.is_relative_to(kernel) for kernel in kernel_roots):
                kept.extend((option, str(path)))
            else:
                omitted.add(str(path))
        configurations.update(map(str, headers))
        # Analyze project code with the selected configuration, not kernel header bodies.
        # Keep their CONFIG_* and version macros, which select real compatibility paths.
        config = [define for header in sorted(headers) for define in defines(header)]
        context = compiler.get(entry) if compiler else None
        if context:
            config = [*context["definitions"], "-std=" + context["standard"], *config]
            if module:
                config += context["kernel_byte_order"]
            else:
                config += compiler.userspace_definitions(entry)
                userspace.append(str(source))
        # This database comes from an external module build. Do not let --force
        # invent an in-tree build with different, unavailable SCST include paths.
        # An explicit build definition or undefinition still takes precedence.
        if not any(re.match(r"-[DU]INSIDE_KERNEL_TREE(?:=|$)", flag)
                   for flag in [*config, *kept]):
            kept.append("-UINSIDE_KERNEL_TREE")
            out_of_tree.append(str(source))
        # Shared headers in the CLI profile must keep their userspace
        # branch rather than a --force-invented kernel implementation.
        if not module and not any(re.match(r"-[DU]__KERNEL__(?:=|$)", flag)
                                  for flag in [*config, *kept]):
            kept.append("-U__KERNEL__")
        result.append({"directory": str(directory), "file": str(source),
                       "arguments": [*kept[:1], *config, *kept[1:], "-c", str(source)]})
    if not result:
        raise ValueError("compilation database contains no selected C inputs")
    output.write_text(json.dumps(result, indent=2) + "\n")
    return {"omitted_kernel_paths": sorted(omitted),
            "configuration_headers": sorted(configurations),
            "out_of_tree_inputs": sorted(out_of_tree),
            "userspace_macro_inputs": sorted(userspace)}
