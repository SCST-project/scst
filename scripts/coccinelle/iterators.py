"""Expand current iterator definitions without native opaque iterator hints."""

import functools
import json
import re
import shutil
import subprocess
from pathlib import Path

from lint_common import run
from coccinelle.source import single_definition

CATALOG = Path(__file__).with_suffix(".json")


@functools.lru_cache(maxsize=None)
def definitions(root):
    result = []
    catalog = json.loads(CATALOG.read_text())
    for path, names in catalog.items():
        for name in names:
            entry = single_definition(root, dict(file=path, name=name))
            if entry["parameters"] is None:
                raise ValueError(f"Expected a function-like iterator: {path}: {name}")
            result.append(entry)
    return result


@functools.lru_cache(maxsize=None)
def models(root):
    entries = definitions(root)
    if not entries:
        return []
    cpp = shutil.which("cpp")
    if not cpp:
        raise ValueError("Coccinelle iterator models require cpp")
    source = "\n".join(entry["definition"] for entry in entries) + "\n"
    for index, entry in enumerate(entries):
        # The sole GNU variadic iterator is retained verbatim below; the probe
        # argument only allows cpp to validate and delimit the complete batch.
        arguments = entry["parameters"].replace("cond...", "cond")
        source += f"SCST_COCCI_BEGIN_{index}\n{entry['name']}({arguments})\n"
    source += "SCST_COCCI_END\n"
    expanded = run([cpp, "-P", "-undef", "-nostdinc", "-"], input=source.encode(),
                   stdout=subprocess.PIPE, check=True).stdout.decode()
    result = []
    for index, entry in enumerate(entries):
        match = re.search(r"SCST_COCCI_BEGIN_" + str(index)
                          + r"\n(.*?)(?=SCST_COCCI_BEGIN_|SCST_COCCI_END)", expanded, re.S)
        if not match:
            raise ValueError(f"Missing preprocessed iterator: {entry['name']}")
        body = match[1].strip()
        if "..." in entry["parameters"]:
            # Preserve GNU comma swallowing for both empty and nonempty calls.
            body = entry["body"]
        result.append(dict(entry, expansion=body))
    return result


def native_definitions(root):
    # The native GNU-extension annotation prevents opaque iterator inference.
    # Unlike a helper macro, it disappears before parser recovery can split a
    # function at an unindented declaration and lose its body.
    lines = []
    for entry in models(root):
        lines.append(f"#define {entry['name']}({entry['parameters']}) "
                     f"__extension__ {entry['expansion']}")
    return "\n".join(lines) + "\n"
