"""Derive Cppcheck's target and compiler builtins from real compiler commands."""

import json
import re
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path

from lint_common import run

FEATURE = re.compile(r"\b(__has_attribute|__has_builtin)\s*\(\s*([A-Za-z_]\w*)\s*\)")
DEFINE = re.compile(r"^#define (\S+) ?(.*)$", re.MULTILINE)
SIZES = {"short": "SHORT", "int": "INT", "long": "LONG", "long-long": "LONG_LONG",
         "float": "FLOAT", "double": "DOUBLE", "long-double": "LONG_DOUBLE",
         "pointer": "POINTER", "size_t": "SIZE_T", "wchar_t": "WCHAR_T"}
TARGET_MACROS = {"__BYTE_ORDER", "__LITTLE_ENDIAN", "__BIG_ENDIAN", "__PDP_ENDIAN",
                 "__BYTE_ORDER__", "__ORDER_LITTLE_ENDIAN__", "__ORDER_BIG_ENDIAN__",
                 "__ORDER_PDP_ENDIAN__"}


def source_probe_command(entry):
    """Preprocess the real userspace input, preserving its header and macro context."""
    kept = []
    it = iter(arguments(entry))
    for arg in it:
        if arg in {"-o", "-MF", "-MT", "-MQ", "-MJ"}:
            next(it)
        elif arg in {"-c", "-S", "-E", "-M", "-MM", "-MD", "-MMD", "-MP", "-MG"}:
            continue
        elif arg.startswith(("-Wp,-M", "-save-temps")):
            continue
        else:
            kept.append(arg)
    return [*kept, "-dM", "-E"]


def target_definitions(output):
    # Retain the historical SCST byte-order and Linux-UAPI context. Do not
    # inject every project macro: doing that would replace real source bodies.
    return [f"-D{name}={value}" for name, value in DEFINE.findall(output)
            if name in TARGET_MACROS or name.startswith(("LINUX_VERSION_", "KERNEL_VERSION("))]


def kernel_byte_order(macros):
    """Recover asm/byteorder.h selectors from the actual compiler target."""
    def value(name):
        seen = set()
        while name in macros and name not in seen:
            seen.add(name)
            name = macros[name]
        return int(re.sub(r"[UL]+$", "", name), 0)

    order = value("__BYTE_ORDER__")
    for selected, other in (("LITTLE", "BIG"), ("BIG", "LITTLE")):
        if order == value(f"__ORDER_{selected}_ENDIAN__"):
            return [f"-D__{selected}_ENDIAN={order}", f"-D__{selected}_ENDIAN_BITFIELD=1",
                    f"-U__{other}_ENDIAN", f"-U__{other}_ENDIAN_BITFIELD"]
    raise ValueError("Unsupported kernel byte order in compiler context")


def arguments(entry):
    return entry.get("arguments") or shlex.split(entry["command"])


def probe_command(entry):
    """Keep target/dialect options; never reuse output, dependency or include recipes.

    Source -D/-U and forced project configuration are reapplied by the database
    adapter, after compiler builtins. They must not contaminate the builtin probe.
    """
    args = arguments(entry)
    if not args or Path(args[0]).name in {"ccache", "sccache", "env"}:
        raise ValueError("Compiler database must name the compiler directly")
    kept = [args[0]]
    it = iter(args[1:])
    for arg in it:
        if arg.startswith("@"):
            raise ValueError("Expand compiler response files before importing the database")
        if arg in {"-D", "-U", "-I", "-isystem", "-iquote", "-idirafter", "-include",
                   "-imacros", "-o", "-MF", "-MT", "-MQ", "-MJ", "-x"}:
            next(it)
        elif arg in {"--sysroot", "-isysroot", "-target", "--target", "-B"}:
            kept.extend((arg, next(it)))
        elif arg.startswith(("-D", "-U", "-I", "-W", "-g", "-o", "-M")):
            continue
        elif arg in {"-c", "-S", "-E", "-pipe", "-fstack-usage", "-save-temps"}:
            continue
        elif arg.startswith(("-f", "-m", "-O", "-std=", "--sysroot=", "--target=",
                             "-B")) or arg in {"-ansi", "-pthread", "-undef", "-nostdinc", "-pg"}:
            kept.append(arg)
        elif arg.startswith("-"):
            raise ValueError(f"Unsupported compiler context option: {arg}")
        elif (Path(entry["directory"]) / arg).resolve() != (
                Path(entry["directory"]) / entry["file"]).resolve():
            raise ValueError(f"Unexpected compiler operand: {arg}")
    return kept


def features(paths):
    result = set()
    for path in paths:
        for line in path.read_text(errors="replace").splitlines():
            if re.match(r"\s*#\s*define\s+__has_(attribute|builtin)\b", line):
                continue
            result.update(FEATURE.findall(line))
    return sorted(result)


def platform(macros):
    """Reject missing sizes rather than silently using the analyzer host ABI."""
    result = {"default-sign": "u" if "__CHAR_UNSIGNED__" in macros else "s",
              "char_bit": int(macros["__CHAR_BIT__"]),
              "sizeof": {key: int(macros[f"__SIZEOF_{macro}__"])
                         for key, macro in SIZES.items()}}
    # The companion compiler assertion verifies this independently of Cppcheck.
    result["sizeof"]["bool"] = 1
    if result["char_bit"] <= 0 or any(size <= 0 for size in result["sizeof"].values()):
        raise ValueError("Invalid compiler type widths")
    return result


def write_platform(path, value):
    root = ET.Element("platform")
    for key in ("default-sign", "char_bit"):
        ET.SubElement(root, key).text = str(value[key])
    sizes = ET.SubElement(root, "sizeof")
    for key, size in value["sizeof"].items():
        ET.SubElement(sizes, key).text = str(size)
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


class CompilerContext:
    """Cache identical probes within one invocation, retaining all raw evidence."""

    def __init__(self, directory, paths):
        self.directory = directory
        self.features = features(paths)
        self.contexts = {}
        self.source_contexts = {}
        self.target = None

    def run(self, command, cwd, source, stem):
        prefix = self.directory / stem
        prefix.with_suffix(".c").write_text(source)
        prefix.with_suffix(".json").write_text(json.dumps(
            {"command": command, "directory": str(cwd), "status": None, "state": "started"},
            indent=2) + "\n")
        evidence = {"command": command, "directory": str(cwd), "status": None,
                    "state": "failed"}
        try:
            with prefix.with_suffix(".stdout.log").open("wb") as output, \
                    prefix.with_suffix(".stderr.log").open("wb") as errors:
                result = run(command, input=source.encode(), cwd=cwd, stdout=output,
                             stderr=errors, timeout=60)
            evidence.update(status=result.returncode, state="complete")
        except BaseException as error:
            evidence["failure"] = str(error) or type(error).__name__
            raise
        finally:
            prefix.with_suffix(".json").write_text(json.dumps(evidence, indent=2) + "\n")
        if result.returncode:
            raise ValueError(f"Compiler context probe failed: {prefix}.stderr.log")
        return prefix.with_suffix(".stdout.log").read_text()

    def userspace_definitions(self, entry):
        command = source_probe_command(entry)
        cwd = str(Path(entry["directory"]).resolve())
        key = (cwd, *command)
        if key not in self.source_contexts:
            name = f"userspace-{len(self.source_contexts) + 1}"
            output = self.run(command, cwd, "", name)
            self.source_contexts[key] = {"file": entry["file"], "command": command,
                                         "directory": cwd, "definitions": target_definitions(output)}
        return self.source_contexts[key]["definitions"]

    def get(self, entry):
        command = probe_command(entry)
        cwd = str(Path(entry["directory"]).resolve())
        key = (cwd, *command)
        if key in self.contexts:
            return self.contexts[key]
        name = f"compiler-{len(self.contexts) + 1}"
        output = self.run([*command, "-dM", "-E", "-x", "c", "-"], cwd, "", name + "-builtins")
        macros = dict(DEFINE.findall(output))
        target = platform(macros)
        if self.target is not None and self.target != target:
            raise ValueError("Mixed compiler ABIs in one profile; analyze them separately")
        self.run([*command, "-fsyntax-only", "-x", "c", "-"], cwd,
                 '_Static_assert(sizeof(_Bool) == 1, "unsupported bool size");\n', name + "-abi")
        self.target = target
        source = "".join(f"SCST_FEATURE_{i} {query}({value})\n"
                         for i, (query, value) in enumerate(self.features))
        output = self.run([*command, "-E", "-P", "-x", "c", "-"], cwd, source, name + "-features")
        values = dict(re.findall(r"^SCST_FEATURE_(\d+) (\d+)$", output, re.MULTILINE))
        if len(values) != len(self.features):
            raise ValueError(f"Incomplete compiler feature results: {name}-features.stdout.log")
        # Token-paste dispatch keeps only compiler-probed literal queries supported.
        definitions = [f"-D{key}={value}" for key, value in macros.items()]
        for query in sorted({query for query, _ in self.features}):
            definitions.append(f"-D{query}(x)=SCSTCHECK{query}_##x")
        feature_values = []
        for i, (query, value) in enumerate(self.features):
            definitions.append(f"-DSCSTCHECK{query}_{value}={values[str(i)]}")
            feature_values.append({"query": query, "argument": value, "value": int(values[str(i)])})
        version = self.run([command[0], "--version"], cwd, "", name + "-version").splitlines()[0]
        stdc = re.sub(r"[UL]+$", "", macros.get("__STDC_VERSION__", "0"))
        standard = {"0": "c89", "199409": "c89", "199901": "c99", "201112": "c11",
                    "201710": "c17", "202000": "c23", "202311": "c23"}.get(stdc)
        if standard is None:
            raise ValueError(f"Unsupported C standard: {stdc}")
        context = {"id": name, "compiler": version, "command": command, "directory": cwd,
                   "platform": target, "standard": standard, "features": feature_values,
                   "definitions": definitions, "kernel_byte_order": kernel_byte_order(macros)}
        self.contexts[key] = context
        return context

    def save(self):
        if self.target is None:
            raise ValueError("No compiler target context collected")
        path = self.directory / "platform.xml"
        write_platform(path, self.target)
        records = [{key: value for key, value in row.items() if key != "definitions"}
                   for row in self.contexts.values()]
        (self.directory / "compiler-context.json").write_text(json.dumps(records, indent=2) + "\n")
        (self.directory / "userspace-context.json").write_text(
            json.dumps(list(self.source_contexts.values()), indent=2) + "\n")
        return records
