#!/usr/bin/env python3
"""Extend native Coccinelle parser hints without replacing installed models."""

import functools
import re
import subprocess
from pathlib import Path

from coccinelle.iterators import native_definitions
from coccinelle.source import single_definition
from lint_common import run

# Retain installed parser hints and add only SCST-specific syntax contracts.
MACROS = Path(__file__).with_name("macros.h")
SOURCE_MACROS = {
    "scst/src/kunit/scst_kunit.h": ["scst_kunit_suite"],
    "iscsi-scst/kernel/session.c": ["ISCSI_SESS_BOOL_PARAM_ATTR", "ISCSI_SESS_INT_PARAM_ATTR",
                                    "ISCSI_SESS_DIGEST_PARAM_ATTR"],
    "scst/src/scst_sysfs.c": ["SCST_TGT_SYSFS_STAT_ATTR", "SCST_SESS_SYSFS_STAT_ATTR", "SCST_LAT_ATTR"],
    "iscsi-scst/kernel/kunit/suites/iscsi_tx_test.c": ["TX_RESULTS"],
    "scst/include/scst.h": ["SCST_OPCODE_DESCRIPTORS"],
}


def source_definitions(root):
    """Keep current SCST declaration bodies visible at their call sites."""
    return "\n".join(single_definition(root, dict(file=path, name=name))["definition"]
                     for path, names in SOURCE_MACROS.items() for name in names)


@functools.lru_cache(maxsize=None)
def installed_builtins(spatch):
    help_text = run([spatch, "--help"], stdout=subprocess.PIPE, check=True).stdout.decode()
    match = re.search(r"^\s*--macro-file-builtins\s+.*\(default=(.+)\)\s*$",
                      help_text, re.MULTILINE)
    if not match:
        raise ValueError("Coccinelle did not identify its default macro builtins")
    return Path(match[1])


def prepare(spatch, options, destination):
    """Preserve the selected native builtins and append project parser hints."""
    source = None
    retained = []
    arguments = iter(options)
    for option in arguments:
        if option == "--macro-file-builtins":
            value = next(arguments, None)
            if not value or value.startswith("-"):
                raise ValueError("Coccinelle --macro-file-builtins requires a file")
            source = Path(value)
        elif option.startswith("--macro-file-builtins="):
            source = Path(option.split("=", 1)[1])
        else:
            retained.append(option)
    if source is None:
        source = installed_builtins(spatch)
    root = Path(__file__).resolve().parents[2]
    destination.write_bytes(source.read_bytes() + b"\n" + MACROS.read_bytes()
                            + native_definitions(root).encode() + source_definitions(root).encode() + b"\n")
    return [*retained, "--macro-file-builtins", str(destination)]
