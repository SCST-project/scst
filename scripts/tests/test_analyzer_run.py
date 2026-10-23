"""Common console lifecycle without compiling or running a native analyzer."""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyzer_run
import lint_common


class FrontendTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for override in (patch.object(analyzer_run, 'ROOT', self.root),
                         patch.object(analyzer_run, 'metadata', return_value={}),
                         patch.object(analyzer_run, 'policy_snapshot', return_value={}),
                         patch.object(analyzer_run, 'print_metadata'),
                         patch.dict(os.environ, {'SCST_LINT_RUN_ID': 'current', 'GITHUB_ACTIONS': '',
                                                 'GITHUB_STEP_SUMMARY': '',
                                                 'SCST_LINT_CI_WRAPPER': ''})):
            override.start()
            self.addCleanup(override.stop)
        self.cache = self.root / '.cache/lint'
        self.cache.mkdir(parents=True)
        self.child = self.root / 'driver.py'

    def execute(self, report=None, status=0, extra=''):
        body = "import json, os, signal, sys\nfrom pathlib import Path\n"
        body += f"cache = Path({str(self.cache)!r})\n"
        body += "os.write(1, b'raw stdout\\x00\\xff\\n'); os.write(2, b'raw stderr\\n')\n"
        if report is not None:
            body += f"report = {report!r}\n"
            body += "(cache / 'scs_lint.json').write_text(json.dumps(report))\n"
            body += "(cache / 'scs_lint.log').write_bytes(b'native\\x00\\xff\\n')\n"
        header = (f"import sys\nsys.path.insert(0, {str(Path(analyzer_run.__file__).parent)!r})\n"
                  "from pathlib import Path\nfrom lint_common import report_lock\n"
                  f"with report_lock(Path({str(self.root)!r}), 'scs_lint'):\n")
        self.child.write_text(header + textwrap.indent(body + extra + f'\nsys.exit({status})\n', '    '))
        output = io.StringIO()
        with (patch.object(analyzer_run, 'driver_command', return_value=[sys.executable, str(self.child)]),
              contextlib.redirect_stdout(output), contextlib.redirect_stderr(output)):
            code = analyzer_run.execute('scs_lint')
        return code, output.getvalue()

    def report(self, **changes):
        return dict(tool='scs_lint', run_id='current', outcome='clean', exit_code=0,
                    remaining=0, checked_files=['scst/source.c'], diagnostics=[], **changes)

    def test_one_lifecycle_and_raw_evidence_for_a_clean_run(self):
        code, output = self.execute(self.report())
        self.assertEqual(code, 0, output)
        for phase in ('Start', 'Run', 'Result', 'Reports'):
            self.assertEqual(output.count(phase + ' | scs_lint'), 1)
        self.assertIn('SCS: PASS; analysis clean', output)
        self.assertNotIn('raw stdout', output)
        self.assertEqual((self.cache / 'scs_lint.execution.log').read_bytes(),
                         b'raw stdout\x00\xff\nraw stderr\n')
        self.assertEqual((self.cache / 'scs_lint.log').read_bytes(), b'native\x00\xff\n')
        self.assertEqual(json.loads((self.cache / 'scs_lint.run.json').read_text())['status'], 0)

    def test_report_is_locked_through_reading_rendering_and_publication(self):
        def assert_locked():
            # A separate open file description must not be able to replace
            # the direct driver's fixed report after that driver has exited.
            probe = """
import fcntl, sys
with open(sys.argv[1], 'a') as stream:
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(42)
sys.exit(0)
"""
            result = subprocess.run([sys.executable, '-B', '-c', probe,
                                     str(self.cache / 'scs_lint.report.lock')],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 42, result.stderr)

        def protected(function):
            def wrapper(*args, **kwargs):
                assert_locked()
                return function(*args, **kwargs)
            return wrapper

        with (patch.object(analyzer_run, 'current_report',
                           side_effect=protected(analyzer_run.current_report)) as read,
              patch.object(analyzer_run, 'render', side_effect=protected(analyzer_run.render)) as render,
              patch.object(analyzer_run, 'print_reports',
                           side_effect=protected(analyzer_run.print_reports)) as publish,
              patch.object(analyzer_run, 'run', wraps=lint_common.run) as run):
            code, output = self.execute(self.report())
        self.assertEqual(code, 0, output)
        self.assertEqual((read.call_count, render.call_count, publish.call_count), (1, 2, 1))
        self.assertEqual(run.call_args.kwargs['cancel_timeout'], 10)

    def test_findings_have_locations_and_keep_native_exit_status(self):
        report = self.report()
        report.update(outcome='findings', exit_code=1, remaining=1,
                      diagnostics=[{'native': 'scst/source.c:1:1: error: SCS.1: visibility',
                                    'rule': 'SCS.1'}])
        code, output = self.execute(report, 1)
        self.assertEqual(code, 1, output)
        self.assertIn('SCS: FAIL; analysis findings', output)
        self.assertIn('1 error: [SCS.1]', output)
        self.assertIn('scst/source.c:1:1:', output)

    def test_skip_is_not_reported_as_a_completed_pass(self):
        report = self.report()
        report.update(outcome='skipped', checked_files=[])
        code, output = self.execute(report)
        self.assertEqual(code, 0, output)
        self.assertIn('SCS: SKIP', output)
        self.assertIn('no analysis performed', output)

    def test_missing_foreign_or_malformed_reports_fail_closed(self):
        for value in (None, [], {'tool': 'smatch', 'run_id': 'current'},
                      {'tool': 'scs_lint', 'run_id': 'previous'}):
            with self.subTest(value=value):
                (self.cache / 'scs_lint.json').unlink(missing_ok=True)
                code, output = self.execute(value)
                self.assertEqual(code, 2, output)
                self.assertNotIn('SCS: PASS', output)
                self.assertIn('Execution failure context', output)
                self.assertNotIn('Machine report:', output)

    def test_exit_mismatch_cannot_pass(self):
        code, output = self.execute(self.report(), 7)
        self.assertEqual(code, 2, output)
        self.assertIn('exit status disagrees', output)
        self.assertNotIn('SCS: PASS', output)

    def test_render_failure_is_recorded_as_incomplete(self):
        report = self.report()
        report['diagnostics'] = [{'unexpected': 'shape'}]
        code, output = self.execute(report)
        self.assertEqual(code, 2, output)
        self.assertNotIn('SCS: PASS', output)
        self.assertEqual(json.loads((self.cache / 'scs_lint.run.json').read_text())['status'], 2)

    def test_interrupted_native_child_preserves_signal_and_output(self):
        code, output = self.execute(extra='os.kill(os.getpid(), signal.SIGTERM)')
        self.assertEqual(code, 128 + signal.SIGTERM, output)
        self.assertIn('analysis interrupted', output)
        self.assertIn(b'raw stdout', (self.cache / 'scs_lint.execution.log').read_bytes())

    def test_preparation_failure_does_not_advertise_previous_metadata(self):
        (self.cache / 'scs_lint.environment.json').write_text('old')
        with patch.object(analyzer_run, 'metadata', side_effect=ValueError('tool unavailable')):
            code, output = self.execute()
        self.assertEqual(code, 2, output)
        self.assertIn('tool unavailable', output)
        self.assertNotIn('Tool and checkout:', output)

    def test_scs_publishes_findings_and_coverage_in_the_job_summary(self):
        report = self.report()
        report.update(outcome='findings', exit_code=1, remaining=1,
                      diagnostics=[dict(native='scst/source.c:4:1: error: SCS.1: visibility',
                                        rule='SCS.1')])
        summary = self.root / 'github-summary'
        with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}):
            code, _ = self.execute(report, 1)
        self.assertEqual(code, 1)
        text = summary.read_text()
        self.assertIn('scst/source.c:4:1:', text)
        self.assertIn('Coverage and completion', text)
        self.assertNotIn('::group::', text)
        self.assertEqual(text, (self.cache / 'scs_lint.summary.md').read_text())

    def test_failed_run_cannot_publish_the_previous_markdown_result(self):
        self.execute(self.report())
        summary = self.root / 'github-summary'
        with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}):
            code, _ = self.execute(None, 2)
        self.assertEqual(code, 2)
        self.assertIn('analysis incomplete', summary.read_text())
        self.assertNotIn('SCS: PASS', summary.read_text())

    def test_progress_uses_only_the_current_runs_rule(self):
        path = self.cache / 'coccicheck.progress.json'
        record = dict(run_id='current', current=12, total=75, rule='do_div.cocci')
        path.write_text(json.dumps(record))
        self.assertEqual(analyzer_run.progress_label('coccicheck', path, 'current'),
                         'coccicheck: analysis (current rule 12/75 do_div.cocci)')
        self.assertEqual(analyzer_run.progress_label('coccicheck', path, 'next'),
                         'coccicheck: analysis')
        for invalid in ([], dict(record, rule='bad\nname.cocci'), dict(record, current=76)):
            path.write_text(json.dumps(invalid))
            self.assertEqual(analyzer_run.progress_label('coccicheck', path, 'current'),
                             'coccicheck: analysis')


class MetadataTests(unittest.TestCase):
    def test_build_defaults_and_overrides_are_described(self):
        defaults = analyzer_run.build_configuration({})
        self.assertIn('newer QLogic tree', defaults['QLA_32GBIT'])
        self.assertIn('Kbuild default', defaults['ARCH'])
        self.assertEqual(analyzer_run.build_configuration({'ARCH': 'arm64'})['ARCH'], 'arm64')

    def test_scs_does_not_present_launcher_version_as_analyzer_version(self):
        ok = lambda value: dict(status=0, output=value)
        data = dict(commit=ok('revision'), branch=ok(''), worktree=ok(''), kernel=None,
                    tool='/bin/uv', version=ok('uv 0.13.1'), tool_sha256='launcher-sha',
                    driver='scripts/scs_lint/scs_lint.py', driver_sha256='driver-sha',
                    source_provenance='SCST checkout', configuration={}, environment_tools={})
        output = io.StringIO()
        with (contextlib.redirect_stdout(output),
              patch.object(analyzer_run, 'policy_lines', return_value=[])):
            analyzer_run.print_metadata('scs_lint', data, {'policy_file': 'policy.json'})
        text = output.getvalue()
        self.assertIn('Runtime launcher: /bin/uv; uv 0.13.1', text)
        self.assertIn('Driver SHA256: driver-sha', text)
        self.assertNotIn('Version: uv', text)
        self.assertNotIn('Kernel build tree:', text)
        self.assertNotIn('Build configuration:', text)


class SectionTests(unittest.TestCase):
    def test_folding_is_github_specific_and_keeps_all_details(self):
        for github, verbose in (('', False), ('true', False), ('true', True)):
            with (self.subTest(github=github, verbose=verbose),
                  patch.dict(os.environ, {'GITHUB_ACTIONS': github}),
                  patch.object(lint_common, 'VERBOSE', verbose)):
                text = lint_common.report_section('Details', ['first', 'last'], collapsed=True)
                self.assertIn('first\nlast', text)
                self.assertEqual('::group::' in text, github == 'true' and not verbose)
                active = lint_common.report_section('Active diagnostics', ['finding'])
                self.assertNotIn('::group::', active)


if __name__ == '__main__':
    unittest.main()
