"""Cppcheck report/capture fixtures without native analysis or compilation."""

import json
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer_policy import read_policy, load_policy
from compile_commands import source_files
from cppcheck.cppcheck import checker_inventory, native_result, project_entry
import cppcheck.cppcheck as driver


class CppcheckTests(unittest.TestCase):
    def test_build_stream_is_retained_before_native_xml_even_on_build_failure(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sources = [root / 'scst/core.c', root / 'usr/fileio/main.c']
                for source in sources:
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text('int value;\n')

                def export(*args, log, **kwargs):
                    with log.open('a') as output:
                        output.write('warning: build context\n  compiler details\n')
                    if failed:
                        raise ValueError('fixture build failed')
                    return {'state': 'complete'}

                def analyze(profile, rows, directory, log, entries):
                    with log.open('a') as output:
                        output.write('<error verbose="Warning: native advice"/>\n')
                    return {'complete': True, 'remaining': 0}

                with contextlib.ExitStack() as stack:
                    for override in (
                            patch.object(driver, 'ROOT', root),
                            patch.object(driver, 'select_sources', return_value=sources),
                            patch.object(driver, 'inline_inventory', return_value=[]),
                            patch.object(driver.shutil, 'which', return_value='/fixture/cppcheck'),
                            patch.object(driver, 'run', return_value=subprocess.CompletedProcess(
                                ['cppcheck'], 0, b'<results/>', b'')),
                            patch.object(driver, 'validate_ids'),
                            patch.object(driver, 'export_commands', side_effect=export),
                            patch.object(driver, 'read_database', return_value=[
                                {'file': str(source)} for source in sources]),
                            patch.object(driver, 'analyze', side_effect=analyze),
                            patch.object(sys, 'argv', ['cppcheck.py']),
                            patch.dict(os.environ, {'LINT_DEFER_REPORTS': '1',
                                                    'CPPCHECK_PROJECT': '',
                                                    'CPPCHECK_USERSPACE_PROJECT': ''}),
                            contextlib.redirect_stdout(io.StringIO()),
                            contextlib.redirect_stderr(io.StringIO())):
                        stack.enter_context(override)
                    if failed:
                        with self.assertRaisesRegex(ValueError, 'fixture build failed'):
                            driver.main()
                    else:
                        self.assertEqual(driver.main(), 0)
                report = json.loads((root / '.cache/lint/cppcheck.json').read_text())
                build = Path(report['build_log']).read_text()
                self.assertIn('compiler details', build)
                self.assertNotIn('<error', build)
                self.assertEqual(report['outcome'], 'incomplete' if failed else 'clean')
                native = (root / '.cache/lint/cppcheck.log').read_text()
                self.assertEqual('<error' in native, not failed)

    def setUp(self):
        self.source = Path("/tmp/scst/scst/src/file.c")
        self.progress = f"Checking {self.source} ...\n"
        self.checkers = "No critical errors encountered.\nYes  CheckOther::checkSomething\n"

    def report(self, diagnostics="", status=0, progress=None, checkers=None, advice=()):
        xml = ('<?xml version="1.0"?><results version="2"><cppcheck version="2.22"/>'
               f'<errors>{diagnostics}</errors></results>')
        return native_result(xml, self.progress if progress is None else progress,
                             self.checkers if checkers is None else checkers,
                             status, [self.source], Path("/tmp/scst"), advice)

    def test_valid_empty_report_requires_native_coverage(self):
        self.assertTrue(self.report()["complete"])
        for kwargs in ({"progress": ""}, {"checkers": ""}, {"status": 1}, {"status": 3},
                       {"checkers": "There were critical errors (syntaxError).\nYes Check\n"}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.report(**kwargs)["complete"])

    def test_relative_progress_and_configuration_suffix(self):
        self.assertTrue(self.report(progress="Checking scst/src/file.c: CONFIG_X=1...\n")["complete"])

    def test_native_coverage_requires_completion_and_rejects_unexpected_inputs(self):
        xml = '<results version="2"><cppcheck/><errors/></results>'
        second = self.source.with_name("other.c")
        progress = self.progress + f"Checking {second} ...\n"
        for suffix, complete in (("", False), ("1/2 files checked\n", False),
                                 ("2/2 files checked\n", True)):
            with self.subTest(suffix=suffix):
                result = native_result(xml, progress + suffix, self.checkers, 0,
                                       [self.source, second], Path("/tmp/scst"))
                self.assertEqual(result["complete"], complete)
        self.assertFalse(self.report(progress=progress)["complete"])

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

    def test_validated_unmatched_notice_never_excuses_frontend_or_coverage_failure(self):
        notice = ('<error id="unmatchedSuppression" severity="information" '
                  'msg="Unmatched suppression: unusedFunction">'
                  '<location file="scst/src/file.c" line="4"/></error>')
        advice = [{"id": "unmatchedSuppression", "file": "scst/src/file.c", "line": 4,
                   "unmatched_id": "unusedFunction", "reason": "Validated source declaration."}]
        result = self.report(notice, 3, advice=advice)
        self.assertTrue(result["complete"])
        self.assertEqual(result["remaining"], 0)
        self.assertEqual(result["advisories"], 1)
        self.assertFalse(self.report(notice, 3, progress="", advice=advice)["complete"])
        error = '<error id="syntaxError" severity="error" msg="Cannot parse"/>'
        self.assertFalse(self.report(notice + error, 3, advice=advice)["complete"])
        self.assertEqual(self.report(notice, 3)["remaining"], 1)
        self.assertEqual(self.report(notice.replace('line="4"', 'line="5"'), 3,
                                     advice=advice)["remaining"], 1)

    def test_inventory_alone_cannot_explain_native_findings_exit(self):
        inventory = '<error id="checkersReport" severity="information" msg="Active checkers: 12/20"/>'
        self.assertTrue(self.report(inventory)["complete"])
        self.assertFalse(self.report(inventory, 3)["complete"])

    def test_checker_inventory_keeps_native_states_and_explains_c_profile(self):
        native = ("No critical errors encountered.\n"
                  "Yes  CheckNullPointer::nullPointer\n"
                  "No   CheckClass::checkConst   require:style,inconclusive\n"
                  "No   CheckBool::checkAssignBoolToFloat   require:style,c++\n"
                  "No   CheckIO::checkCoutCerrMisusage   require:c\n"
                  "No   CheckOther::checkInterlockedDecrement   require:windows-platform\n"
                  "No   CheckUnusedFunctions::check   require:unusedFunction\n"
                  "No   CheckOther::newCheck   require:warning\n"
                  "No   CheckClass::checkCtuOneDefinitionRule\n")
        inventory = checker_inventory(native, "2.22.0")
        rows = inventory["checkers"]
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row["active"] for row in rows), 1)
        self.assertEqual(rows[3]["requirements"], "c")
        for row in rows[1:4]:
            self.assertIn("C++-specific", row["reason"])
        self.assertIn("Windows-specific", rows[4]["reason"])
        self.assertIn("not registered", rows[5]["reason"])
        self.assertFalse(rows[5]["active"])
        for row in rows[6:]:
            self.assertIn("Reason not established", row["reason"])
        future = checker_inventory(native, "2.23.0")
        for row in future["checkers"][1:]:
            self.assertIn("Reason not established", row["reason"])

    def test_inventory_explanations_do_not_excuse_native_failures(self):
        xml = ('<results version="2"><cppcheck version="2.22.0"/>'
               '<errors><error id="syntaxError" severity="error" msg="Cannot parse"/></errors>'
               '</results>')
        native = self.checkers + 'No   CheckUnusedFunctions::check   require:unusedFunction\n'
        result = native_result(xml, self.progress, native, 0, [self.source], Path('/tmp/scst'))
        self.assertFalse(result['complete'])
        self.assertEqual(result['remaining'], 1)
        rows = result['checker_inventory']['checkers']
        self.assertIn('not registered', rows[-1]['reason'])
        self.assertFalse(rows[-1]['active'])

    def test_malformed_and_partial_xml_are_incomplete(self):
        for xml in ("", "<results/>", '<results version="2"><cppcheck/><errors>',
                    '<results version="2"><cppcheck/><errors><error/></errors></results>'):
            with self.subTest(xml=xml):
                self.assertFalse(native_result(xml, self.progress, self.checkers, 0,
                                               [self.source], Path("/tmp/scst"))["complete"])

    def test_export_requires_compile_but_keeps_non_analyzed_sources(self):
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
            self.assertEqual(source_files([str(outside)], "kernel", root), [outside])

    def test_policy_rejects_unreviewed_suppression_switches(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            policy = load_policy("cppcheck")
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
