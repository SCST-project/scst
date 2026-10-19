"""Cppcheck report/capture fixtures without native analysis or compilation."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer_policy import read_policy
from cppcheck.capture import source_files
from cppcheck.cppcheck import native_result, project_entry


class CppcheckTests(unittest.TestCase):
    def setUp(self):
        self.source = Path("/tmp/scst/scst/src/file.c")
        self.progress = f"Checking {self.source} ...\n"
        self.checkers = "No critical errors encountered.\nYes  CheckOther::checkSomething\n"

    def report(self, diagnostics="", status=0, progress=None, checkers=None):
        xml = ('<?xml version="1.0"?><results version="2"><cppcheck version="2.22"/>'
               f'<errors>{diagnostics}</errors></results>')
        return native_result(xml, self.progress if progress is None else progress,
                             self.checkers if checkers is None else checkers,
                             status, [self.source], Path("/tmp/scst"))

    def test_valid_empty_report_requires_native_coverage(self):
        self.assertTrue(self.report()["complete"])
        for kwargs in ({"progress": ""}, {"checkers": ""}, {"status": 1}, {"status": 3},
                       {"checkers": "There were critical errors (syntaxError).\nYes Check\n"}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.report(**kwargs)["complete"])

    def test_relative_progress_and_configuration_suffix(self):
        self.assertTrue(self.report(progress="Checking scst/src/file.c: CONFIG_X=1...\n")["complete"])

    def test_findings_are_preserved(self):
        diagnostic = '<error id="nullPointer" severity="error" msg="Null pointer"/>'
        result = self.report(diagnostic, 3)
        self.assertTrue(result["complete"])
        self.assertEqual(result["remaining"], 1)
        self.assertEqual(result["diagnostics"][0]["id"], "nullPointer")

    def test_native_zero_with_parser_failure_is_incomplete(self):
        for identifier in ("syntaxError", "unknownMacro", "missingIncludeSystem", "internalError"):
            with self.subTest(identifier=identifier):
                diagnostic = f'<error id="{identifier}" severity="error" msg="Cannot analyze"/>'
                self.assertFalse(self.report(diagnostic)["complete"])

    def test_malformed_and_partial_xml_are_incomplete(self):
        for xml in ("", "<results/>", '<results version="2"><cppcheck/><errors>',
                    '<results version="2"><cppcheck/><errors><error/></errors></results>'):
            with self.subTest(xml=xml):
                self.assertFalse(native_result(xml, self.progress, self.checkers, 0,
                                               [self.source], Path("/tmp/scst"))["complete"])

    def test_capture_requires_compile_and_shared_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "usr/fileio/file.c"
            source.parent.mkdir(parents=True)
            source.touch()
            self.assertEqual(source_files(["-c", str(source)], "userspace", root), [source])
            self.assertEqual(source_files(["-M", str(source)], "userspace", root), [])
            self.assertEqual(source_files(["-Iinclude", str(source)], "kernel", root), [source])
            outside = root / "qla2x00t/legacy.c"
            outside.parent.mkdir()
            outside.touch()
            self.assertEqual(source_files([str(outside)], "kernel", root), [])

    def test_basic_policy_rejects_models_and_suppressions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            policy = {"version": 1, "notes": ["Native commands."]}
            path.write_text(json.dumps(policy))
            self.assertEqual(read_policy(path, "cppcheck"), policy)
            for field in ("models", "suppressions", "source_exceptions"):
                path.write_text(json.dumps({**policy, field: []}))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    read_policy(path, "cppcheck")

    def test_project_retains_real_headers_relative_to_compiler_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "include").mkdir()
            (root / "include/config.h").touch()
            arguments = ["cc", "-Iinclude", "-isystem", "system", "-include", "include/config.h",
                         "-D__KERNEL__", "-c", "file.c"]
            record = {"directory": str(root), "file": str(root / "file.c"), "arguments": arguments}
            entry = project_entry(record)
            self.assertEqual(entry["arguments"], ["cc", "-I", str(root / "include"),
                             "-include", str(root / "include/config.h"),
                             "-D__KERNEL__", "-c", "file.c", "-I", str(root / "system")])
            self.assertEqual(record["arguments"], arguments)


if __name__ == "__main__":
    unittest.main()
