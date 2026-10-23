"""Regressions for compiler-derived Cppcheck platform and feature context."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cppcheck.compiler import (  # noqa: E402
    CompilerContext, features, kernel_byte_order, probe_command,
    source_probe_command, target_definitions,
)
from cppcheck.kbuild import adapt  # noqa: E402

BUILTINS = """#define __CHAR_BIT__ 8
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#define __ORDER_LITTLE_ENDIAN__ 1234
#define __ORDER_BIG_ENDIAN__ 4321
#define __CHAR_UNSIGNED__ 1
#define __SIZEOF_SHORT__ 2
#define __SIZEOF_INT__ 4
#define __SIZEOF_LONG__ 8
#define __SIZEOF_LONG_LONG__ 8
#define __SIZEOF_FLOAT__ 4
#define __SIZEOF_DOUBLE__ 8
#define __SIZEOF_LONG_DOUBLE__ 16
#define __SIZEOF_POINTER__ 8
#define __SIZEOF_SIZE_T__ 8
#define __SIZEOF_WCHAR_T__ 2
#define __STDC_VERSION__ 201112L
"""


class CompilerContextTest(unittest.TestCase):
    def test_kernel_endian_selectors_follow_target_not_host(self):
        macros = {"__ORDER_LITTLE_ENDIAN__": "1234", "__ORDER_BIG_ENDIAN__": "4321"}
        for selected, other in (("LITTLE", "BIG"), ("BIG", "LITTLE")):
            with self.subTest(selected=selected):
                macros["__BYTE_ORDER__"] = f"__ORDER_{selected}_ENDIAN__"
                definitions = kernel_byte_order(macros)
                self.assertIn(f"-D__{selected}_ENDIAN_BITFIELD=1", definitions)
                self.assertIn(f"-U__{other}_ENDIAN", definitions)
                self.assertIn(f"-D__{selected}_ENDIAN={macros[macros['__BYTE_ORDER__']]}",
                              definitions)
        for value in ("3412", "unknown", "__BYTE_ORDER__"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                kernel_byte_order(dict(macros, __BYTE_ORDER__=value))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.header = self.root / "owned.h"
        self.header.write_text("#define __has_attribute(x) 0\n"
                               "#if __has_attribute(alloc_size)\n#endif\n")
        self.entry = {"directory": str(self.root), "file": "source.c",
                      "arguments": ["gcc", "-fshort-wchar", "-funsigned-char", "-std=gnu11",
                                    "-Iheaders", "-DPRIVATE=1", "-include", "config.h",
                                    "-Wp,-MMD,out.d", "-c", "source.c", "-o", "source.o"]}

    def outputs(self, command, cwd, source, stem):
        if stem.endswith("-builtins"):
            return BUILTINS
        if stem.endswith("-features"):
            return "SCST_FEATURE_0 1\n"
        if stem.endswith("-version"):
            return "gcc fixture\n"
        return ""

    def test_query_preserves_abi_flags_without_build_side_effects(self):
        self.assertEqual(probe_command(self.entry),
                         ["gcc", "-fshort-wchar", "-funsigned-char", "-std=gnu11"])
        self.assertEqual(features([self.header]), [("__has_attribute", "alloc_size")])

    def test_target_differs_from_unix64_and_feature_is_not_forced_off(self):
        context = CompilerContext(self.root, [self.header])
        with patch.object(context, "run", side_effect=self.outputs) as run:
            value = context.get(self.entry)
            context.get(self.entry)
            self.assertEqual(run.call_count, 4)
        context.save()
        self.assertEqual(value["platform"]["default-sign"], "u")
        self.assertEqual(value["platform"]["sizeof"]["wchar_t"], 2)
        self.assertEqual(value["standard"], "c11")
        self.assertIn("-DSCSTCHECK__has_attribute_alloc_size=1", value["definitions"])
        records = json.loads((self.root / "compiler-context.json").read_text())
        self.assertEqual(records[0]["features"][0]["value"], 1)
        self.assertNotIn("definitions", records[0])

    def test_incomplete_or_mixed_context_cannot_fall_back_to_host_sizes(self):
        context = CompilerContext(self.root, [self.header])
        with patch.object(context, "run", side_effect=self.outputs):
            context.get(self.entry)
        other = dict(self.entry, arguments=["other-cc", "-c", "source.c"])
        def different(command, cwd, source, stem):
            return self.outputs(command, cwd, source, stem).replace(
                "#define __SIZEOF_WCHAR_T__ 2", "#define __SIZEOF_WCHAR_T__ 4")
        with patch.object(context, "run", side_effect=different), self.assertRaisesRegex(
                ValueError, "Mixed compiler ABIs"):
            context.get(other)
        context = CompilerContext(self.root, [self.header])
        with patch.object(context, "run", return_value=""), self.assertRaises(KeyError):
            context.get(self.entry)

    def test_derived_database_preserves_config_and_does_not_change_raw_commands(self):
        module = self.root / "scst"
        module.mkdir()
        source = module / "sample.c"
        source.write_text("int value;\n")
        include = self.root / "kernel/include"
        for name, content in (("linux/kconfig.h", ""),
                              ("generated/autoconf.h", "#define CONFIG_KUNIT 1\n"),
                              ("generated/uapi/linux/version.h", "#define LINUX_VERSION_CODE 1\n")):
            header = include / name
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(content)
        entry = dict(self.entry, file=str(source))
        entry["arguments"] = ["gcc", "-I" + str(include), "-I" + str(module),
                              "-include", str(include / "linux/kconfig.h"),
                              "-DSCST_FIXTURE=1", "-c", str(source)]
        raw = self.root / "raw.json"
        raw.write_text(json.dumps([entry]))
        original = raw.read_bytes()
        context = CompilerContext(self.root, [self.header])
        derived = self.root / "derived.json"
        with patch.object(context, "run", side_effect=self.outputs):
            metadata = adapt(self.root, raw, derived, compiler=context)
        args = json.loads(derived.read_text())[0]["arguments"]
        self.assertEqual(raw.read_bytes(), original)
        self.assertIn("-DCONFIG_KUNIT=1", args)
        self.assertIn("-DSCST_FIXTURE=1", args)
        self.assertIn(str(module), args)
        self.assertNotIn(str(include), args)
        self.assertIn(str(include), metadata["omitted_kernel_paths"])
        self.assertIn("-UINSIDE_KERNEL_TREE", args)
        self.assertEqual(metadata["out_of_tree_inputs"], [str(source)])

    def test_explicit_kernel_build_mode_and_userspace_are_preserved(self):
        source = self.root / "scst/sample.c"
        source.parent.mkdir()
        source.write_text("int value;\n")
        raw, derived = self.root / "raw.json", self.root / "derived.json"
        for flags, module in ((["-DINSIDE_KERNEL_TREE=1"], True),
                              (["-D", "INSIDE_KERNEL_TREE"], True),
                              (["-UINSIDE_KERNEL_TREE"], True), ([], False)):
            with self.subTest(flags=flags, module=module):
                raw.write_text(json.dumps([dict(self.entry, file=str(source),
                    arguments=["gcc", *flags, "-c", str(source)])]))
                metadata = adapt(self.root, raw, derived, module=module)
                args = json.loads(derived.read_text())[0]["arguments"]
                self.assertEqual("-UINSIDE_KERNEL_TREE" in args,
                                 "-UINSIDE_KERNEL_TREE" in flags or not module)
                self.assertEqual(bool(metadata["out_of_tree_inputs"]), not module)
                self.assertEqual("-U__KERNEL__" in args, not module)

    def test_compiler_failure_does_not_publish_a_successful_context(self):
        context = CompilerContext(self.root, [self.header])
        with patch.object(context, "run", side_effect=ValueError("probe failed")), \
                self.assertRaisesRegex(ValueError, "probe failed"):
            context.get(self.entry)
        self.assertFalse((self.root / "platform.xml").exists())

    def test_userspace_macro_probe_preserves_real_headers_without_object_outputs(self):
        args = source_probe_command(self.entry)
        self.assertIn("-Iheaders", args)
        self.assertIn("-DPRIVATE=1", args)
        self.assertIn("config.h", args)
        self.assertIn("source.c", args)
        self.assertNotIn("-c", args)
        self.assertNotIn("source.o", args)
        self.assertNotIn("-Wp,-MMD,out.d", args)
        self.assertEqual(args[-2:], ["-dM", "-E"])
        definitions = target_definitions("#define __BYTE_ORDER __LITTLE_ENDIAN\n"
            "#define __LITTLE_ENDIAN 1234\n#define LINUX_VERSION_CODE 123\n"
            "#define KERNEL_VERSION(a,b,c) (((a)<<16)+((b)<<8)+(c))\n"
            "#define PROJECT_BODY(x) ignored(x)\n")
        self.assertEqual(len(definitions), 4)
        self.assertIn("-D__BYTE_ORDER=__LITTLE_ENDIAN", definitions)
        self.assertFalse(any("PROJECT_BODY" in item for item in definitions))

    def test_userspace_macro_context_is_per_source_and_failure_propagates(self):
        context = CompilerContext(self.root, [self.header])
        with patch.object(context, "run", return_value="#define __BYTE_ORDER 1234\n") as run:
            context.userspace_definitions(self.entry)
            context.userspace_definitions(self.entry)
            other = dict(self.entry, file="other.c", arguments=["gcc", "-c", "other.c"])
            context.userspace_definitions(other)
            self.assertEqual(run.call_count, 2)
        with patch.object(context, "run", side_effect=ValueError("preprocess failed")):
            with self.assertRaisesRegex(ValueError, "preprocess failed"):
                context.userspace_definitions(dict(self.entry, arguments=["gcc", "-c", "bad.c"]))


class CompilerProbeFailureTests(unittest.TestCase):
    def test_timeout_retains_partial_streams_and_failed_invocation(self):
        import subprocess
        from lint_common import run as native_run
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context = CompilerContext(root, [])
            command = [sys.executable, '-c',
                       "import os,time; os.write(1,b'partial output\\n'); "
                       "os.write(2,b'partial error\\n'); time.sleep(30)"]
            def bounded_run(*args, **kwargs):
                kwargs['timeout'] = 1
                return native_run(*args, **kwargs)
            with patch('cppcheck.compiler.run', side_effect=bounded_run), \
                    self.assertRaises(subprocess.TimeoutExpired):
                context.run(command, root, '', 'failed-probe')
            self.assertEqual((root / 'failed-probe.stdout.log').read_text(), 'partial output\n')
            self.assertEqual((root / 'failed-probe.stderr.log').read_text(), 'partial error\n')
            evidence = json.loads((root / 'failed-probe.json').read_text())
            self.assertEqual(evidence['state'], 'failed')
            self.assertIsNone(evidence['status'])
            self.assertIn('timed out', evidence['failure'])


if __name__ == "__main__":
    unittest.main()
