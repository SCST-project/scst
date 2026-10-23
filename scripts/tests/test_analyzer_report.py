"""Reporting must retain evidence without participating in outcome classification."""

from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer_report import build_diagnostics, markdown_block, render


class AnalyzerReportTests(unittest.TestCase):
    def test_pahole_notices_retain_context_and_do_not_change_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "smatch.log"
            notice = ("warning: pahole version differs\n"
                      "  The kernel was built with: 130\n  You are using: 132\n")
            log.write_text(notice + "  CHECK module.c\n" + notice)
            report = dict(tool="smatch", outcome="clean", exit_code=0, remaining=0,
                          ignored=0, make_status=0, checked_files=["module.c"], translation_units=1)
            text = render(report, log)
            self.assertIn("Smatch: PASS; analysis clean (exit 0)", text)
            self.assertIn("The kernel was built with: 130", text)
            self.assertIn("Repeated 2 times", text)
            self.assertNotIn("  CHECK module.c", text)
            self.assertEqual(report["exit_code"], 0)
            self.assertEqual(log.read_text().count("warning: pahole"), 2)

    def test_failed_build_without_a_standard_error_retains_its_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "cppcheck.log"
            log.write_text("Package libnl-3.0 was not found in the pkg-config search path.\n")
            self.assertIn("libnl-3.0", "\n".join(build_diagnostics(log, failed=True)))

    def test_advice_is_visible_and_distinct_from_active_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "cppcheck.log"
            log.touch()
            report = dict(tool="cppcheck", outcome="findings", exit_code=1, remaining=1,
                          checked_files=["scst/file.c"], inline_exceptions=[{}, {}], profiles=[{
                              "profile": "kernel", "complete": True, "native_status": 3,
                              "translation_units": 1, "failures": [], "diagnostics": [
                                  {"id": "nullPointer", "severity": "error", "msg": "Null pointer",
                                   "locations": [{"file": "scst/file.c", "line": "10"}]},
                                  {"id": "unmatchedSuppression", "advisory": "Validated declaration."},
                              ]}])
            text = render(report, log)
            self.assertIn("Inline exception declarations: 2 (not suppression hits)", text)
            self.assertIn("scst/file.c:10: error: Null pointer [nullPointer]", text)
            self.assertIn("1 x unmatchedSuppression: Validated declaration.", text)
            self.assertIn("complete=True, native exit=3", text)


    def test_cppcheck_counts_findings_once_and_keeps_each_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'cppcheck.log'
            log.touch()
            report = dict(tool='cppcheck', outcome='findings', exit_code=1, remaining=1,
                          profiles=[dict(profile='kernel', complete=True, native_status=3,
                                         translation_units=1, diagnostics=[dict(
                                             id='nullPointer', severity='error', msg='Null pointer',
                                             locations=[dict(file='first.c', line=1),
                                                        dict(file='second.c', line=2, info='Called here')])])])
            text = render(report, log)
            self.assertIn('1 error: [nullPointer]', text)
            self.assertIn('first.c:1:', text)
            self.assertIn('second.c:2:', text)
            self.assertIn('Called here', text)

    def test_cppcheck_xml_is_not_a_build_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'cppcheck.log'
            log.write_text('<error verbose="Warning: native advice"/>')
            build = Path(tmp) / 'build.log'
            build.write_text('warning: pahole version differs\n  compiler context\n')
            report = dict(tool='cppcheck', outcome='clean', exit_code=0, remaining=0,
                          build_log=str(build), profiles=[])
            text = render(report, log)
            self.assertIn('pahole version differs', text)
            self.assertIn('compiler context', text)
            self.assertNotIn('<error', text)

    def test_checker_notes_and_exceptions_are_separate_from_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = root / 'check.log'
            note = 'source.c: note: in included file:\n'
            ignored = 'header.h:2:3: warning: reviewed layout'
            finding = 'source.c:7 fn() warn: retained finding'
            native.write_text(note + ignored + '\n' + finding + '\n')
            (root / 'check.json').write_text(json.dumps(dict(
                state='complete', returncode=0, log=str(native),
                ignored=[dict(diagnostic=ignored, reason='Exact reviewed header.')]
            )))
            report = dict(tool='smatch', outcome='findings', exit_code=1, remaining=1,
                          records_directory=str(root), ignored=1)
            text = render(report, native)
            active = text.split('--- Active diagnostics ---')[1].split('--- Coverage')[0]
            self.assertIn(finding, active)
            self.assertNotIn('in included file', active)
            self.assertNotIn(ignored, active)
            self.assertNotIn('Build/environment messages', text)
            self.assertIn('1 x tool message: source.c: note:', text)
            self.assertIn('Exact reviewed header.', text)

    def test_checkpatch_groups_categories_without_dropping_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'checkpatch.log'
            log.write_text('WARNING:AVOID_BUG: Do not crash\n#2: FILE: source.c:2:\n'
                           '+BUG();\n\nCHECK:LINE_SPACING: Blank line\n#4: FILE: source.c:4:\n'
                           '+return;\n\n')
            report = dict(tool='checkpatch', outcome='findings', exit_code=1, remaining=2)
            text = render(report, log)
            self.assertIn('1 warning: [AVOID_BUG]', text)
            self.assertIn('1 check: [LINE_SPACING]', text)
            self.assertIn('+BUG();', text)
            self.assertIn('source.c:4:', text)

    def test_coccinelle_rule_coverage_and_skips_remain_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'coccicheck.log'
            log.touch()
            report = dict(tool='coccicheck', outcome='clean', exit_code=0, remaining=0,
                          rules=[dict(rule='rules/alloc.cocci', complete=True, native_status=0,
                                      handled=['source.c'])], skipped_rules=['rules/patch-only.cocci'])
            text = render(report, log)
            self.assertIn('Semantic rules: 1 run; 1 skipped without report mode', text)
            self.assertIn('patch-only.cocci (no report mode)', text)
            self.assertIn('alloc.cocci: complete=True', text)

    def test_native_exit_explanations_and_checker_counts_are_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'native.log'
            log.touch()
            report = dict(tool='cppcheck', outcome='clean', exit_code=0, remaining=0,
                          checked_files=['scst/src/kunit/test.c'], profiles=[dict(
                              profile='kernel', complete=True, native_status=3, translation_units=1,
                              native_status_reason='validated unmatched inline declarations',
                              diagnostics=[dict(id='checkersReport', severity='information',
                                                advisory='Native checker inventory',
                                                msg='Active checkers: 108/164')])])
            text = render(report, log)
            self.assertIn('Checked translation units (.c): 1; including 1 KUnit translation units', text)
            self.assertIn('Native exit explanation: validated unmatched inline declarations', text)
            self.assertIn('kernel: Active checkers: 108/164', text)
            self.assertNotIn('x checkersReport', text)
            report = dict(tool='checkpatch', outcome='clean', exit_code=0, remaining=0,
                          native_status=1, ignored=12, checked_files=['scst/src/kunit/test.h'])
            text = render(report, log)
            self.assertIn('12 exempted, 0 active', text)
            self.assertIn('Checked source files (.c and .h): 1; including 1 KUnit files', text)

    def test_cppcheck_inventory_explains_no_entries_without_promoting_them_to_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'native.log'
            log.touch()
            inventory = dict(version='2.22.0', checkers=[
                dict(name='CheckNullPointer::nullPointer', active=True, requirements=''),
                dict(name='CheckIO::checkCoutCerrMisusage', active=False, requirements='c',
                     reason='C++-specific checks (inputs are C)'),
                dict(name='CheckUnusedFunctions::check', active=False, requirements='unusedFunction',
                     reason='Build-directory unusedFunction pass is not registered in this inventory'),
                dict(name='CheckOther::newCheck', active=False, requirements='warning',
                     reason='Reason not established from the native inventory'),
            ])
            profiles = [dict(profile=name, complete=True, native_status=0, translation_units=1,
                             checker_inventory=inventory, diagnostics=[dict(
                                 id='checkersReport', advisory='Native checker inventory',
                                 msg='Active checkers: 1/4')]) for name in ('kernel', 'userspace')]
            report = dict(tool='cppcheck', outcome='clean', exit_code=0, remaining=0, profiles=profiles)
            before = json.dumps(report)
            for markdown in (False, True):
                with self.subTest(markdown=markdown), patch.dict('os.environ', GITHUB_ACTIONS='true'), \
                        patch('lint_common.VERBOSE', False):
                    text = render(report, log, markdown=markdown)
                    heading = ('<details><summary>Checker inventory: kernel, userspace</summary>'
                               if markdown else '::group::Checker inventory: kernel, userspace')
                    self.assertIn(heading, text)
                    self.assertEqual(text.count('Active checkers: 1/4'), 2)
                    self.assertIn('3 checkers not reported active', text)
                    self.assertIn('1 x C++-specific checks (inputs are C)', text)
                    self.assertIn('1 x Reason not established', text)
                    self.assertEqual(text.count('CheckIO::checkCoutCerrMisusage:'), 1)
                    self.assertIn('native require:c', text)
                    self.assertIn('not registered in this inventory', text)
                    self.assertIn('Cppcheck: PASS; analysis clean (exit 0)', text)
                    self.assertEqual(json.dumps(report), before)

    def test_btf_messages_are_folded_without_hiding_build_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'build.log'
            raw = ('Skipping BTF generation for first.ko due to unavailability of vmlinux\n'
                   'Skipping BTF generation for second.ko due to unavailability of vmlinux\n'
                   'warning: compiler versions differ\n  compiler details\n')
            log.write_text(raw)
            report = dict(tool='sparse', outcome='clean', exit_code=0, remaining=0)
            with patch.dict('os.environ', {'GITHUB_ACTIONS': 'true'}), \
                    patch('lint_common.VERBOSE', False):
                text = render(report, log)
            self.assertIn('BTF generation skipped for 2 modules', text)
            self.assertIn('::group::BTF details', text)
            self.assertIn('second.ko', text)
            self.assertIn('--- Build/environment messages ---', text)
            self.assertIn('compiler details', text)
            self.assertEqual(log.read_text(), raw)

    def test_coccinelle_notices_and_macro_coverage_limits_remain_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'native.log'
            log.touch()
            report = dict(tool='coccicheck', outcome='clean', exit_code=0, remaining=0,
                          rules=[dict(rule='do_div.cocci', complete=True, native_status=0,
                                      handled=['source.c'], duration_seconds=3.5,
                                      tool_warnings=[dict(message='<string>:33: SyntaxWarning: notice',
                                                          reason='Upstream compatibility')],
                                      coverage_limits=[dict(file='source.h', line=2, name='MACRO',
                                                            message='parse error',
                                                            reason='A standalone definition is not checked.')])])
            for github in ('', 'true'):
                for verbose in (False, True):
                    with (self.subTest(github=github, verbose=verbose),
                          patch.dict('os.environ', {'GITHUB_ACTIONS': github}),
                          patch('lint_common.VERBOSE', verbose)):
                        text = render(report, log)
                        folded = github == 'true' and not verbose
                        heading = ('::group::Macro coverage limitations' if folded else
                                   '--- Macro coverage limitations ---')
                        self.assertIn(heading, text)
                        self.assertEqual('::group::' in text, folded)
                        self.assertIn('do_div.cocci: <string>:33: SyntaxWarning: notice', text)
                        self.assertIn('duration=3.5s', text)
                        self.assertIn('1 occurrences; 1 definitions', text)
                        self.assertIn('no synthetic macro contexts are checked', text)
                        self.assertIn('source.h:2: parse error [MACRO] (1 occurrences)', text)
                        self.assertIn('A standalone definition is not checked.', text)
                        self.assertNotIn('Macro context coverage', text)

    def test_markdown_keeps_diagnostics_literal_and_has_no_workflow_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'native.log'
            log.touch()
            message = 'source.c:2:1: error: SCS.1: ``` </details> **text**'
            report = dict(tool='scs_lint', outcome='findings', exit_code=1, remaining=1,
                          checked_files=['source.c'], diagnostics=[dict(native=message, rule='SCS.1')])
            with patch.dict('os.environ', {'GITHUB_ACTIONS': 'true'}):
                text = render(report, log, markdown=True)
            self.assertIn('**Active diagnostics**', text)
            self.assertIn('````text\n' + message + '\n````', text)
            self.assertNotIn('::group::', text)
            self.assertIn('SCS: FAIL', text)
            self.assertTrue(markdown_block('plain').startswith('```text\n'))


if __name__ == "__main__":
    unittest.main()
