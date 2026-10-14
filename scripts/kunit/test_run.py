# SPDX-License-Identifier: GPL-2.0-only
"""Userspace runner checks. No test loads a module or opens /dev/kmsg."""

import contextlib
import errno
import io
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import run

PASS = ['    # Subtest: scst-LIB', '    1..1',
        '    ok 1 scst_lun_flat_encoding', 'ok 7 - scst-LIB']
FAIL = [line.replace('ok ', 'not ok ') if 'ok ' in line else line for line in PASS]
SKIP = [line + ' # SKIP unavailable' if 'ok ' in line else line for line in PASS]
VDISK_PASS = [line.replace('scst-LIB', 'scst-VDISK-capacity') for line in PASS]
OOPS = ['BUG: kernel NULL pointer dereference, address: 0000000000000000',
        '#PF: supervisor write access in kernel mode', 'PGD 0 P4D 0',
        'Oops: Oops: 0002 [#1] SMP NOPTI', 'CPU: 0 PID: 1 Comm: kunit_try_catch',
        'Tainted: [D]=DIE, [N]=TEST', 'RIP: 0010:test_case+0x10/0x20 [scst]',
        'Call Trace:', ' <TASK>', ' kunit_try_run_case+0x10/0x20 [kunit]', ' </TASK>',
        '---[ end trace 00000000 ]---', 'RIP: 0010:test_case+0x10/0x20 [scst]']


def document(lines):
    """Wrap a suite body in the envelope and numbering supplied by debugfs."""
    return "\n".join(['KTAP version 1', '1..1',
                       *[re.sub(r'^(not ok|ok) \d+ ', r'\1 1 ', line) for line in lines]]) + "\n"


def evidence(lines, suite='scst-LIB'):
    return {'messages': lines, 'suite_results': {suite: document(lines)}}


def analyse(lines, expected):
    return run.analyse({expected[0]: document(lines)}, expected, lines)


def report():
    return {'modules': [{'name': 'scst', 'suites': ['scst-LIB']}], 'module_state': 'not attempted',
            'commands': [], 'errors': [], 'expected_suites': ['scst-LIB']}


class ParseTests(unittest.TestCase):
    def test_module_output_and_statuses(self):
        for lines, status in ((PASS, 'PASS'), (FAIL, 'FAIL'), (SKIP, 'SKIP')):
            with self.subTest(status=status):
                parsed, _ = analyse(lines, ['scst-LIB'])
                self.assertEqual(parsed['test_status'], status)
                self.assertFalse(parsed['parse_errors'])

    def test_kernel_output_does_not_supply_test_results(self):
        parsed, _ = run.analyse({}, ['scst-LIB'], PASS)
        self.assertEqual(parsed['test_status'], 'ERROR')
        self.assertEqual(parsed['counts']['passed'], 0)
        parsed, _ = run.analyse({'scst-LIB': document(PASS)}, ['scst-LIB'],
                                ['SCST initializing', *FAIL, 'SCST unloaded'])
        self.assertEqual(parsed['test_status'], 'PASS')
        self.assertEqual(parsed['counts']['passed'], 1)

    def test_parameterized_case(self):
        lines = [PASS[0], '    1..1', '        KTAP version 1',
                 '        # Subtest: boundary', '        1..2',
                 '        ok 1 zero', '        not ok 2 maximum',
                 '    not ok 1 boundary', 'not ok 2 - scst-LIB']
        parsed, _ = analyse(lines, ['scst-LIB'])
        self.assertEqual(parsed['test_status'], 'FAIL')
        self.assertEqual(parsed['counts']['failed'], 1)

    def test_skip_reasons_are_preserved(self):
        parsed, details = analyse(SKIP, ['scst-LIB'])
        suite = parsed['suites'][0]
        self.assertEqual(suite['skip_reason'], 'unavailable')
        self.assertEqual(suite['children'][0]['skip_reason'], 'unavailable')
        self.assertIn('unavailable', details)

    def test_parser_output_is_local_to_each_run(self):
        console = io.StringIO()
        with contextlib.redirect_stdout(console):
            _, first = analyse(PASS, ['scst-LIB'])
            _, second = analyse(VDISK_PASS, ['scst-VDISK-capacity'])
        self.assertEqual(console.getvalue(), '')
        self.assertIn('scst_lun_flat_encoding', first)
        self.assertNotIn('scst-VDISK-capacity', first)
        self.assertIn('scst-VDISK-capacity', second)

    def test_bad_evidence_cannot_pass(self):
        cases = [[], PASS[:-1], PASS[:2] + PASS[3:], PASS + PASS,
                 [line.replace('1..1', '1..2') for line in PASS],
                 [line.replace('ok 1 scst_', 'ok 2 scst_') for line in PASS],
                 [PASS[0], '    1..0', PASS[-1]],
                 [line.replace('scst-LIB', 'scst-unexpected') for line in PASS]]
        for lines in cases:
            with self.subTest(lines=lines):
                parsed, _ = analyse(lines, ['scst-LIB'])
                self.assertEqual(parsed['test_status'], 'ERROR')

    def test_missing_compiled_suite(self):
        parsed, _ = analyse(PASS, ['scst-LIB', 'scst-extra'])
        self.assertEqual(parsed['test_status'], 'ERROR')

    def test_trailing_results_and_foreign_suite_cannot_pass(self):
        for extra in ([PASS[-1]], ['    not ok 2 stray'], ['    1..99'],
                      ['    # Subtest: foreign-suite'],
                      [line.replace('scst-LIB', 'foreign-suite') for line in PASS]):
            with self.subTest(extra=extra):
                parsed, _ = analyse(PASS + extra, ['scst-LIB'])
                self.assertEqual(parsed['test_status'], 'ERROR')

    def test_parameter_name_does_not_become_a_suite(self):
        logs = [PASS[0], '    1..1', '        # Subtest: scst-parameter',
                '        1..1', '        ok 1 value', '    ok 1 scst-parameter', PASS[-1]]
        parsed, _ = analyse(logs, ['scst-LIB'])
        self.assertEqual(parsed['test_status'], 'PASS')
        self.assertEqual(len(parsed['suites']), 1)

    def test_separate_debugfs_documents(self):
        parsed, _ = run.analyse({'scst-LIB': document(PASS),
                                'scst-VDISK-capacity': document(VDISK_PASS)},
                               ['scst-LIB', 'scst-VDISK-capacity'])
        self.assertEqual(parsed['test_status'], 'PASS')
        self.assertEqual(parsed['counts']['passed'], 2)

    def test_native_envelope_and_suite_identity_are_validated(self):
        good = document(PASS)
        for text in ('', 'garbage', good.replace('KTAP version 1', 'KTAP version 99'),
                     good.replace('1..1', '1..2', 1), good.replace('1..1', '1..0', 1),
                     good.replace('ok 1 - scst-LIB', 'ok 2 - scst-LIB'),
                     good + good, good + 'ok 2 stray\n', good + 'trailing garbage\n',
                     document(suite_log('scst-OTHER'))):
            with self.subTest(text=text):
                parsed, _ = run.analyse({'scst-LIB': text}, ['scst-LIB'])
                self.assertEqual(parsed['test_status'], 'ERROR')

    def test_entire_suite_skip_without_cases(self):
        text = 'KTAP version 1\n1..1\nok 1 scst-LIB # SKIP unavailable\n'
        parsed, _ = run.analyse({'scst-LIB': text}, ['scst-LIB'])
        self.assertEqual(parsed['test_status'], 'SKIP')
        self.assertEqual(parsed['suites'][0]['skip_reason'], 'unavailable')

    def test_missing_debugfs_body_identifies_the_incomplete_suite(self):
        parsed, _ = run.analyse({'scst-LIB': 'KTAP version 1\n1..1\n'}, ['scst-LIB'])
        self.assertEqual(parsed['test_status'], 'ERROR')
        self.assertEqual(parsed['suites'][0]['name'], 'scst-LIB')

    def test_diagnostic_groups_include_trace_without_consuming_results(self):
        warning = ['WARNING: CPU: 0 PID: 1 at example', 'CPU: 0 PID: 1 Comm: insmod',
                   'Call Trace:', ' <TASK>', ' example+0x1/0x2', ' </TASK>',
                   '---[ end trace 00000000 ]---']
        parsed, _ = analyse(warning + PASS + ['unrelated', 'BUG: another failure'], ['scst-LIB'])
        self.assertEqual(parsed['diagnostics'], ['\n'.join(warning), 'BUG: another failure'])
        self.assertEqual(parsed['counts']['passed'], 1)

    def test_oops_header_and_trace_form_one_event(self):
        logs = FAIL[:2] + OOPS + ['    # assertion detail'] + FAIL[2:]
        parsed, _ = analyse(logs, ['scst-LIB'])
        self.assertEqual(parsed['diagnostics'], ['\n'.join(OOPS)])
        self.assertEqual(parsed['counts']['failed'], 1)
        self.assertEqual(run.kernel_diagnostics(OOPS + OOPS), ['\n'.join(OOPS)] * 2)

    def test_independent_oops_warning_and_bare_trace_are_not_merged(self):
        first = ['WARNING: unrelated', 'Call Trace:', ' warning_frame']
        oops = OOPS[3:]
        logs = first + oops + PASS + ['Call Trace:', ' bare_frame']
        self.assertEqual(run.kernel_diagnostics(logs),
                         ['\n'.join(first), '\n'.join(oops), 'Call Trace:\n bare_frame'])

    def test_crash_console_is_brief_and_artifacts_keep_full_evidence(self):
        logs = FAIL[:2] + OOPS + ['    # assertion detail'] + FAIL[2:]
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                result = report() | {**evidence(logs), 'module_state': 'retained',
                                     'started_suites': ['scst-LIB'],
                                     'expected_suites': ['scst-LIB', 'scst-VDISK-capacity']}
                console = io.StringIO()
                with contextlib.redirect_stdout(console):
                    self.assertEqual(run.finish(result, Path(tmp), verbose), 1)
                output = console.getvalue()
                self.assertIn('Kernel:  FAIL - 1 diagnostic event', output)
                self.assertIn('1/2 started, 1 not run', output)
                self.assertEqual('NOT_RUN: scst-VDISK-capacity' in output, verbose)
                self.assertIn('  [FAIL] scst_lun_flat_encoding', output)
                self.assertIn('assertion detail', output)
                self.assertEqual('Call Trace:' in output, verbose)
                self.assertFalse(result['parse_errors'])
                for artifact in ('messages.log', 'report.txt', 'result.json'):
                    content = (Path(tmp) / artifact).read_text()
                    self.assertIn('test_case+0x10/0x20', content)
                    self.assertIn('assertion detail', content)
                self.assertEqual(result['not_run_suites'], ['scst-VDISK-capacity'])

    def test_repeated_diagnostic_headlines_are_summarized(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = report() | {**evidence(OOPS + OOPS + PASS), 'module_state': 'retained'}
            console = io.StringIO()
            with contextlib.redirect_stdout(console):
                self.assertEqual(run.finish(result, Path(tmp)), 1)
            self.assertIn('Kernel:  FAIL - 2 diagnostic events', console.getvalue())
            self.assertIn('  ' + OOPS[0] + ' (2 events)', console.getvalue())
            self.assertNotIn('Call Trace:', console.getvalue())

    def test_unstarted_selection_cannot_pass_without_a_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            result = report() | {**evidence(PASS), 'module_state': 'unloaded',
                                 'started_suites': ['scst-LIB'],
                                 'expected_suites': ['scst-LIB', 'scst-VDISK-capacity']}
            self.assertEqual(run.finish(result, Path(tmp)), 2)
            self.assertIn('Execution stopped', result['errors'][0])
            self.assertEqual(result['not_run_suites'], ['scst-VDISK-capacity'])

    def test_preflight_console_is_compact_and_full_report_keeps_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            names = [f'scst-suite-{i}' for i in range(15)]
            result = report() | {'expected_suites': names,
                                 'errors': ['Cannot verify preloaded KUnit: enable is unreadable.\n'
                                            'Module left unchanged. Leave KUnit unloaded before retrying.']}
            console = io.StringIO()
            with contextlib.redirect_stdout(console):
                self.assertEqual(run.finish(result, Path(tmp)), 2)
            output = console.getvalue()
            self.assertIn('Tests:   NOT_RUN (15 suites not run)', output)
            self.assertNotIn('NOT_RUN: scst-suite-', output)
            self.assertNotIn('0 passed', output)
            self.assertLess(len(output.splitlines()), 10)
            saved = (Path(tmp) / 'report.txt').read_text()
            self.assertTrue(all('NOT_RUN: ' + name in saved for name in names))

    def test_color_is_terminal_only_and_reports_remain_plain(self):
        for tty, disabled in ((True, False), (False, False), (True, True)):
            with self.subTest(tty=tty, disabled=disabled), tempfile.TemporaryDirectory() as tmp:
                console = io.StringIO()
                environment = {'TERM': 'xterm'} | ({'NO_COLOR': ''} if disabled else {})
                with contextlib.redirect_stdout(console), patch.object(console, 'isatty', return_value=tty), \
                        patch.dict(os.environ, environment, clear=True):
                    sample = run.color_console('PASS FAIL NOT_RUN')
                    run.finish(report() | {**evidence(PASS), 'module_state': 'unloaded'}, Path(tmp))
                colored = tty and not disabled
                for color in (31, 32, 33):
                    self.assertEqual(f'\033[{color}m' in sample, colored)
                self.assertEqual('\033[' in console.getvalue(), colored)
                for name in ('messages.log', 'report.txt', 'result.json'):
                    self.assertNotIn('\033[', (Path(tmp) / name).read_text())

    def test_console_modes_preserve_full_report(self):
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                result = report() | {**evidence(PASS), 'module_state': 'unloaded'}
                console = io.StringIO()
                with contextlib.redirect_stdout(console):
                    self.assertEqual(run.finish(result, Path(tmp), verbose), 0)
                self.assertEqual('scst_lun_flat_encoding' in console.getvalue(), verbose)
                self.assertIn('scst_lun_flat_encoding', (Path(tmp) / 'report.txt').read_text())
                self.assertIn('scst-LIB', console.getvalue())

    def test_failed_case_is_visible_in_default_console_and_json(self):
        logs = FAIL[:2] + ['    # assertion detail'] + FAIL[2:]
        with tempfile.TemporaryDirectory() as tmp:
            result = report() | {**evidence(logs), 'module_state': 'unloaded'}
            console = io.StringIO()
            with contextlib.redirect_stdout(console):
                self.assertEqual(run.finish(result, Path(tmp)), 1)
            self.assertIn('  [FAIL] scst_lun_flat_encoding', console.getvalue())
            self.assertIn('assertion detail', console.getvalue())
            data = json.loads((Path(tmp) / 'result.json').read_text())
            self.assertIn('assertion detail', '\n'.join(data['suites'][0]['children'][0]['log']))

    def test_parameter_failure_details_are_visible_with_and_without_a_plan(self):
        for planned in (False, True):
            for verbose in (False, True):
                with self.subTest(planned=planned, verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                    logs = [PASS[0], '    1..1', '        KTAP version 1',
                            '        # Subtest: boundary']
                    if planned:
                        logs.append('        1..3')
                    logs += ['    # first parameter assertion detail', '        not ok 1 first',
                             '    # second parameter assertion detail', '        not ok 2 second',
                             '        ok 3 third', '    not ok 1 boundary', 'not ok 1 scst-LIB']
                    result = report() | {**evidence(logs), 'module_state': 'unloaded'}
                    with contextlib.redirect_stdout(io.StringIO()) as console:
                        self.assertEqual(run.finish(result, Path(tmp), verbose), 1)
                        # Incremental output and final reporting must not duplicate diagnostics.
                        run.show_suites(result, result)
                    output = console.getvalue()
                    for parameter in ('first', 'second'):
                        detail = f'{parameter} parameter assertion detail'
                        self.assertEqual(output.count(detail), 1)
                        self.assertIn(f'[FAIL] boundary/{parameter}', output)
                        self.assertIn(detail, (Path(tmp) / 'report.txt').read_text())
                        self.assertIn(detail, (Path(tmp) / 'result.json').read_text())
                        case = result['suites'][0]['children'][0]['children'][
                            0 if parameter == 'first' else 1]
                        self.assertIn(detail, '\n'.join(case['log']))
                        heading = f'  [FAIL] boundary/{parameter}\n'
                        section = output.split(heading, 1)[1].split('\n\n', 1)[0]
                        self.assertIn(detail, section)
                    parent = result['suites'][0]['children'][0]
                    self.assertNotIn('first parameter assertion detail', '\n'.join(parent['log']))
                    self.assertEqual('[PASS] boundary/third' in output, verbose)
                    self.assertEqual(result['counts']['failed'], 2)
                    self.assertEqual(result['counts']['passed'], 1)
                    self.assertFalse(result['errors'])

    def test_progress_precedes_grouped_failures_and_keeps_assertion_indentation(self):
        logs = [PASS[0], '    1..1', '        # Subtest: boundary',
                '        # first assertion', '        Expected value == 1, but',
                '            value == 0', '            1 == 1', '        not ok 1 first',
                '        # second assertion', '        not ok 2 second',
                '    # boundary: pass:0 fail:2 skip:0 total:2', '    not ok 1 boundary',
                '    # module: scst', '    # Totals: pass:0 fail:2 skip:0 total:2',
                'not ok 1 scst-LIB']
        with tempfile.TemporaryDirectory() as tmp:
            result = report() | {**evidence(logs),
                                 'suite_results': {'scst-LIB': document(logs),
                                                   'scst-VDISK-capacity': document(VDISK_PASS)}, 'module_state': 'unloaded',
                                 'expected_suites': ['scst-LIB', 'scst-VDISK-capacity']}
            parsed, _ = analyse(logs, ['scst-LIB'])
            with contextlib.redirect_stdout(io.StringIO()) as console:
                run.show_suites(parsed, result)
                self.assertEqual(console.getvalue(), '[FAIL] scst-LIB\n')
                self.assertEqual(run.finish(result, Path(tmp)), 1)
            output = console.getvalue()
            self.assertEqual(output.count('[FAIL] scst-LIB'), 1)
            self.assertLess(output.index('[PASS] scst-VDISK-capacity'), output.index('Failures:'))
            self.assertIn('Failures:\n\nscst-LIB\n  [FAIL] boundary/first\n', output)
            self.assertIn('    Expected value == 1, but\n        value == 0\n        1 == 1', output)
            self.assertIn('\n\n  [FAIL] boundary/second\n', output)
            self.assertNotIn('[FAIL] boundary\n', output)
            self.assertNotIn('# Totals:', output)
            self.assertNotIn('# module:', output)
            self.assertNotIn('pass:0 fail:2', output)
            self.assertIn('# Totals:', (Path(tmp) / 'report.txt').read_text())

    def test_mixed_printk_and_assertions_keep_consistent_console_indentation(self):
        for verbose in (False, True):
            for indent in ('', '    ', '        '):
                with self.subTest(verbose=verbose, indent=indent), tempfile.TemporaryDirectory() as tmp:
                    diagnostic = ['[42]: scst: ***ERROR***: injected backend error',
                                  indent + '# boundary: EXPECTATION FAILED at suite.c:42',
                                  indent + 'Expected actual == wanted, but',
                                  indent + '    actual == 0 (0x0)',
                                  indent + '    wanted == 1 (0x1)',
                                  'custom assertion message', '  continuation of the message',
                                  indent + '# boundary: ASSERTION FAILED at suite.c:43',
                                  indent + 'Expected rc == 0, but',
                                  indent + '    rc == -1 (0xffffffffffffffff)']
                    logs = [PASS[0], '    1..1', '        # Subtest: boundary',
                            *diagnostic, '        not ok 1 first',
                            *diagnostic, '        not ok 2 second',
                            '    not ok 1 boundary', 'not ok 1 scst-LIB']
                    result = report() | {**evidence(logs), 'module_state': 'unloaded'}
                    with contextlib.redirect_stdout(io.StringIO()) as console:
                        self.assertEqual(run.finish(result, Path(tmp), verbose), 1)
                    output = console.getvalue()
                    expected = ('    # boundary: EXPECTATION FAILED at suite.c:42\n'
                                '    Expected actual == wanted, but\n'
                                '        actual == 0 (0x0)\n'
                                '        wanted == 1 (0x1)\n'
                                '    custom assertion message\n'
                                '      continuation of the message\n'
                                '    # boundary: ASSERTION FAILED at suite.c:43\n'
                                '    Expected rc == 0, but\n'
                                '        rc == -1 (0xffffffffffffffff)')
                    for parameter in ('first', 'second'):
                        section = output.split(f'  [FAIL] boundary/{parameter}\n', 1)[1]
                        self.assertIn(expected, section.split('\n\n', 1)[0])
                    self.assertEqual(result['counts']['failed'], 2)
                    saved = json.loads((Path(tmp) / 'result.json').read_text())
                    cases = saved['suites'][0]['children'][0]['children']
                    self.assertEqual([case['log'] for case in cases], [diagnostic, diagnostic])
                    self.assertEqual((Path(tmp) / 'messages.log').read_text(), '\n'.join(logs) + '\n')

    def test_passing_first_parameter_logs_do_not_leak_into_failed_parent(self):
        logs = [PASS[0], '    1..1', '        # Subtest: boundary',
                '    # expected negative-path message', '        ok 1 first',
                '    # actual failure', '        not ok 2 second',
                '    # parent teardown detail', '    not ok 1 boundary', 'not ok 1 scst-LIB']
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                result = report() | {**evidence(logs), 'module_state': 'unloaded'}
                with contextlib.redirect_stdout(io.StringIO()) as console:
                    self.assertEqual(run.finish(result, Path(tmp), verbose), 1)
                output = console.getvalue()
                self.assertEqual('expected negative-path message' in output, verbose)
                self.assertIn('parent teardown detail', output)
                parent = result['suites'][0]['children'][0]
                self.assertEqual(parent['log'], ['    # parent teardown detail'])
                self.assertEqual(parent['children'][0]['log'], ['    # expected negative-path message'])
                self.assertEqual(parent['children'][1]['log'], ['    # actual failure'])
                self.assertIn('expected negative-path message', (Path(tmp) / 'report.txt').read_text())

    def test_parameter_plan_validation_is_not_changed_by_log_association(self):
        for plan in ('        1..3', '        1..1'):
            logs = [PASS[0], '    1..1', '        # Subtest: boundary', plan,
                    '    # first failure', '        not ok 1 first',
                    '        ok 2 second', '    not ok 1 boundary', 'not ok 1 scst-LIB']
            parsed, _ = analyse(logs, ['scst-LIB'])
            self.assertEqual(parsed['test_status'], 'ERROR')
            self.assertTrue(parsed['parse_errors'])

    def test_module_metadata_defaults_and_full_reports(self):
        metadata = {'version': '3.11.0-pre', 'description': 'SCSI target core',
                    'author': 'SCST contributors', 'license': 'GPL', 'git_commit': 'a' * 40,
                    'build_date': '2026-10-13 12:00:00 UTC', 'build_number': '42',
                    'kver': '7.2.9', 'arch_type': 'x86_64', 'srcversion': 'ABC123',
                    'vermagic': '7.2.9 SMP preempt mod_unload'}
        for verbose in (False, True):
            for failed in (False, True):
                with self.subTest(verbose=verbose, failed=failed), tempfile.TemporaryDirectory() as tmp:
                    result = report() | {**evidence(FAIL if failed else PASS), 'module_state': 'unloaded',
                                         'kernel': '7.2.9-test', 'architecture': 'x86_64'}
                    result['modules'][0].update(metadata)
                    console = io.StringIO()
                    with contextlib.redirect_stdout(console):
                        self.assertEqual(run.finish(result, Path(tmp), verbose), int(failed))
                    output = console.getvalue()
                    saved = (Path(tmp) / 'report.txt').read_text()
                    data = json.loads((Path(tmp) / 'result.json').read_text())
                    self.assertEqual(output.count('Module: scst\n'), int(verbose))
                    self.assertIn('\n\n' + ('Module: scst' if verbose else 'SCST: 3.11.0-pre'), output)
                    last_field = 'vermagic' if verbose else 'arch_type'
                    self.assertIn(metadata[last_field] + '\n\nRuntime kernel:', output)
                    self.assertIn('Runtime kernel: 7.2.9-test (x86_64)', output)
                    self.assertIn(('Module scst: unknown' if verbose else
                                   'Runtime kernel: 7.2.9-test (x86_64)') + '\n\nTests:', output)
                    for key, value in metadata.items():
                        labels = {'version': 'SCST', 'git_commit': 'Commit',
                                  'build_number': 'Build number', 'build_date': 'Build date',
                                  'kver': 'Built for kernel', 'arch_type': 'Architecture'}
                        if verbose:
                            self.assertIn(f'  {key}: {value}', output)
                        elif key in labels:
                            self.assertIn(f'{labels[key]}: {value}', output)
                        else:
                            self.assertNotIn(f'{key}:', output)
                        self.assertIn(f'  {key}: {value}', saved)
                        self.assertEqual(data['modules'][0][key], value)

    def test_each_module_keeps_its_own_metadata_and_missing_fields_are_optional(self):
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                result = report() | {**evidence(PASS), 'module_state': 'unloaded',
                                     'modules': [{'name': 'scst', 'version': '3.11.0-pre',
                                                  'git_commit': 'CORE'},
                                                 {'name': 'scst_vdisk', 'version': '3.11.0-pre',
                                                  'srcversion': 'HANDLER', 'git_commit': ''}]}
                with contextlib.redirect_stdout(io.StringIO()) as console:
                    self.assertEqual(run.finish(result, Path(tmp), verbose), 0)
                output = console.getvalue()
                self.assertEqual(output.count('version: 3.11.0-pre'), 2 if verbose else 0)
                self.assertEqual('SCST: 3.11.0-pre' in output, not verbose)
                self.assertEqual('Module: scst_vdisk' in output, verbose)
                self.assertEqual('srcversion: HANDLER' in output, verbose)
                self.assertIn('git_commit: CORE' if verbose else 'Commit: CORE', output)
                self.assertNotIn('build_date:', output)
                if verbose:
                    self.assertIn('git_commit: CORE\n\nModule: scst_vdisk', output)
                else:
                    self.assertIn('Commit: CORE\n\nTests:', output)
                saved = (Path(tmp) / 'report.txt').read_text()
                core, handler = saved.split('Module: scst_vdisk', 1)
                self.assertIn('git_commit: CORE', core)
                self.assertIn('srcversion: HANDLER', handler)
                self.assertNotIn('git_commit:', handler)
                data = json.loads((Path(tmp) / 'result.json').read_text())
                self.assertEqual(data['modules'][1]['srcversion'], 'HANDLER')

    def test_verbose_shows_optional_case_logs_without_changing_results(self):
        logs = PASS[:2] + ['    # scst_lun_flat_encoding: encoded LUN = 0x5234'] + PASS[2:]
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                console = io.StringIO()
                with contextlib.redirect_stdout(console):
                    run.finish(report() | {**evidence(logs), 'module_state': 'unloaded'}, Path(tmp), verbose)
                self.assertEqual('encoded LUN' in console.getvalue(), verbose)
                self.assertIn('encoded LUN', (Path(tmp) / 'report.txt').read_text())
                self.assertIn('Tests:   PASS', console.getvalue())

    def test_kernel_diagnostics(self):
        for message in ('WARNING: at scst', 'BUG: KASAN: use-after-free',
                        'watchdog: BUG: soft lockup', 'rcu: detected stalls',
                        'INFO: task insmod blocked for more than 120 seconds'):
            with self.subTest(message=message):
                parsed, _ = analyse(PASS + [message], ['scst-LIB'])
                self.assertEqual(parsed['diagnostics'], [message])

    def test_reports_and_exit_codes(self):
        for lines, state, errors, expected in ((PASS, 'unloaded', [], 0),
                (FAIL, 'unloaded', [], 1), (SKIP, 'unloaded', [], 0),
                (PASS[:-1], 'retained', [], 2),
                (PASS, 'loading', ['timeout'], 2),
                (PASS + ['# SCST_KUNIT_RETAINED: worker'], 'retained', [], 2),
                (PASS + ['WARNING: test'], 'retained', [], 1),
                (PASS + ['BUG: unload'], 'unloaded', [], 1)):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                result = report() | {**evidence(lines), 'module_state': state, 'errors': errors}
                if lines[-1].startswith(('WARNING:', 'BUG:')):
                    result['suite_results'] = {'scst-LIB': document(PASS)}
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(run.finish(result, Path(tmp)), expected)
                data = json.loads((Path(tmp) / 'result.json').read_text())
                self.assertNotIn('messages', data)
                self.assertTrue((Path(tmp) / 'report.txt').is_file())

    def test_preflight_failure_reports_not_run_without_missing_results(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            result = report() | {'errors': ['KUnit preparation failed']}
            self.assertEqual(run.finish(result, Path(tmp)), 2)
            self.assertEqual(result['test_status'], 'NOT_RUN')
            self.assertEqual(result['errors'], ['KUnit preparation failed'])
            self.assertFalse(result['parse_errors'])
            self.assertEqual(result['expected_suites'], ['scst-LIB'])


class DebugfsTests(unittest.TestCase):
    def test_trigger_then_read_preserves_exact_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'ktap').mkdir()
            suite = directory / 'scst-LIB'
            suite.mkdir()
            trigger = suite / 'run'
            trigger.touch()
            text = document(FAIL)
            (suite / 'results').write_text(text)
            capture = Mock()
            capture.drain.return_value = False
            result = report()
            self.assertEqual(run.collect_suite(trigger, capture, directory, 10, result), 0)
            self.assertEqual(trigger.read_text(), 'run\n')
            self.assertEqual((directory / 'ktap/scst-LIB.ktap').read_text(), text)
            self.assertEqual(result['suite_results'], {'scst-LIB': text})
            self.assertEqual(len(result['commands']), 1)

    def test_read_error_is_recorded_without_using_kernel_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'ktap').mkdir()
            suite = directory / 'scst-LIB'
            suite.mkdir()
            trigger = suite / 'run'
            trigger.touch()
            capture = Mock(messages=PASS)
            capture.drain.return_value = False
            result = report()
            self.assertNotEqual(run.collect_suite(trigger, capture, directory, 10, result), 0)
            self.assertIn('FileNotFoundError', result['commands'][0]['output'])
            self.assertNotIn('suite_results', result)

    def test_result_read_shares_the_command_timeout(self):
        child = Mock(pid=42)
        child.poll.return_value = None
        capture = Mock()
        capture.drain.return_value = False
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(run.subprocess, 'Popen', return_value=child), \
                patch.object(run.time, 'monotonic', side_effect=[0, 11]):
            result = report()
            with self.assertRaisesRegex(run.RunError, 'PID 42'):
                run.collect_suite(Path(tmp) / 'scst-LIB/run', capture, Path(tmp), 10, result)
            self.assertEqual(len(result['commands']), 1)
            self.assertIn("with_name('results')", result['commands'][0]['argv'][2])
            child.wait.assert_not_called()

    def test_unexpected_execution_and_retained_work_are_rejected(self):
        for lines in (PASS, ['KTAP version 1'], ['1..1'], ['ok 1 scst-LIB # SKIP reason']):
            self.assertTrue(run.log_problems(lines))
        for lines in (PASS + PASS, VDISK_PASS, ['ok 1 foreign'], ['# SCST_KUNIT_RETAINED: worker']):
            self.assertTrue(run.log_problems(lines, 'scst-LIB'))
        self.assertFalse(run.log_problems(PASS, 'scst-LIB'))
        self.assertFalse(run.log_problems(['ordinary SCST message']))


class CaptureTests(unittest.TestCase):
    def test_failed_command_keeps_bounded_stderr_without_prior_commands(self):
        child = Mock(pid=42)
        child.poll.return_value = 1
        capture = Mock()
        capture.drain.return_value = False
        def start(argv, **kwargs):
            kwargs['stdout'].write(b'x' * 5000 + b'\ninsmod: Unknown symbol dlm_new_lockspace\n')
            return child
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'commands.log').write_text('old command output\n')
            result = report()
            with patch.object(run.subprocess, 'Popen', side_effect=start):
                self.assertEqual(run.command(['insmod', 'test.ko'], capture, directory, 10, result), 1)
            error = str(run.command_error(result, 'insmod scst', 1))
            self.assertIn('Unknown symbol dlm_new_lockspace', error)
            self.assertNotIn('old command output', error)
            self.assertLessEqual(len(result['commands'][0]['output']), 4096)
            self.assertGreater((directory / 'commands.log').stat().st_size, 5000)

    def capture(self):
        capture = run.KernelLog.__new__(run.KernelLog)
        capture.raw = io.BytesIO()
        capture.sequence = None
        capture.messages = []
        capture.previous_kernel = False
        capture.fd = 987
        return capture

    def test_sequence_and_raw_evidence(self):
        capture = self.capture()
        capture.accept(b'6,100,10,-;first\n')
        capture.accept(b'6,101,11,-;second\n SUBSYSTEM=test\n')
        self.assertEqual(capture.messages, ['first', 'second'])
        with self.assertRaisesRegex(run.RunError, 'Lost kernel log records'):
            capture.accept(b'6,103,12,-;after gap\n')
        self.assertIn(b'after gap', capture.raw.getvalue())

    def test_read_overrun(self):
        with patch.object(run.os, 'read', side_effect=OSError(errno.EPIPE, 'overrun')):
            with self.assertRaisesRegex(run.RunError, 'overrun'):
                self.capture().drain()

    def test_injected_results_are_raw_evidence_only(self):
        capture = self.capture()
        for number, line in enumerate(PASS + ['BUG: injected', 'SCST_KUNIT_RETAINED: injected']):
            capture.accept(f'14,{number},10,-;{line}\n'.encode())
        parsed, _ = analyse(capture.messages, ['scst-LIB'])
        self.assertEqual(parsed['test_status'], 'ERROR')
        self.assertFalse(parsed['diagnostics'])
        self.assertFalse(parsed['retained_fixtures'])
        self.assertIn(b'injected', capture.raw.getvalue())
        with self.assertRaisesRegex(run.RunError, 'Lost kernel log records'):
            capture.accept(b'6,7,11,-;gap after ignored userspace\n')

    def test_fragments_escapes_and_extended_headers(self):
        capture = self.capture()
        capture.accept(b'6,1,10,-,extra;    # Subtest: scst-\n')
        capture.accept(b'6,2,11,c;LIB\n')
        capture.accept(b'6,3,12,-;    1..1\n')
        capture.accept(b'6,4,13,-;    ok 1 escaped_\\x5c_name\n')
        capture.accept(b'6,5,14,-;ok 7 - scst-LIB\n')
        parsed, _ = analyse(capture.messages, ['scst-LIB'])
        self.assertEqual(parsed['test_status'], 'PASS')
        self.assertIn('escaped_\\_name', capture.messages[2])
        self.assertIn(b'\\x5c', capture.raw.getvalue())

    def test_userspace_record_breaks_fragment_chain(self):
        capture = self.capture()
        capture.accept(b'6,1,10,-;first\n')
        capture.accept(b'14,2,11,-;ignored\n')
        capture.accept(b'6,3,12,c;fragment\n')
        self.assertEqual(capture.messages, ['first', 'fragment'])

    def test_malformed_metadata_preserves_raw_record(self):
        for record in (b'6,1,10;missing flags\n', b'-1,1,10,-;priority\n',
                       b'6,-1,10,-;sequence\n', b'6,1,bad,-;timestamp\n'):
            with self.subTest(record=record):
                capture = self.capture()
                with self.assertRaises(run.RunError):
                    capture.accept(record)
                self.assertEqual(capture.raw.getvalue(), record)

    def test_malformed_record(self):
        with self.assertRaisesRegex(run.RunError, 'Malformed'):
            self.capture().accept(b'not a kmsg record')

    def test_timeout_does_not_kill_or_unload(self):
        child = Mock(pid=42)
        child.poll.return_value = None
        capture = Mock()
        capture.drain.return_value = False
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(run.subprocess, 'Popen', return_value=child), \
                patch.object(run.time, 'monotonic', side_effect=[0, 11]):
            with self.assertRaisesRegex(run.RunError, 'PID 42'):
                run.command(['insmod', 'test.ko'], capture, Path(tmp), 10, report())
        child.kill.assert_not_called()
        child.terminate.assert_not_called()
        child.wait.assert_not_called()

    def test_command_reads_messages_printed_between_drain_and_exit(self):
        pending, messages = [], []
        def drain():
            messages.extend(pending)
            pending.clear()
            return False
        def exited():
            pending.append('WARNING: final module message')
            return 0
        child = Mock(pid=42)
        child.poll.side_effect = exited
        capture = Mock()
        capture.drain.side_effect = drain
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(run.subprocess, 'Popen', return_value=child):
            self.assertEqual(run.command(['rmmod', 'test'], capture, Path(tmp), 10, report()), 0)
        self.assertEqual(messages, ['WARNING: final module message'])
        self.assertFalse(pending)


def manifest(name='scst', labels=None, vermagic='test-kernel', depends=None):
    if labels is None:
        labels = {'scst-LIB': 'LIB'}
    if depends is None:
        depends = () if name == 'scst' else ('scst',)
    return {'name': name, 'suites': list(labels), 'labels': labels, 'vermagic': vermagic, 'depends': list(depends)}


def suite_log(suite):
    return [line.replace('scst-LIB', suite) for line in PASS]


class LifecycleTests(unittest.TestCase):
    def test_label_manifest_validation(self):
        for records, valid in [('LIB:scst-LIB', True), ('LIB:scst-LIB\nCM:scst-CM', True),
                               ('', False), ('scst-LIB', False), ('LIB:../bad', False),
                               ('LIB:scst-LIB\nCM:scst-LIB', False), ('ALL:scst-LIB', False)]:
            fields = {'name': 'scst', 'vermagic': 'test-kernel', 'scst_kunit_suite': records,
                      'version': '3.11', 'srcversion': 'ABC123', 'depends': 'dlm,kunit'}
            with self.subTest(records=records), patch.object(run.subprocess, 'run',
                    side_effect=lambda argv, **kw: Mock(stdout=fields.get(argv[2], ""))):
                if valid:
                    info = run.module_info(Path('/mock/scst.ko'))
                    self.assertEqual(info['labels'], {r.split(':')[1]: r.split(':')[0] for r in records.splitlines()})
                    self.assertEqual(info['version'], '3.11')
                else:
                    with self.assertRaises(run.RunError):
                        run.module_info(Path('/mock/scst.ko'))

    def test_metadata_comes_from_the_requested_module_file(self):
        fields = {'name': 'scst', 'scst_kunit_suite': 'LIB:scst-LIB', 'depends': '',
                  'version': '3.11.0-pre', 'git_commit': 'embedded-commit',
                  'build_number': '0', 'vermagic': 'test-kernel'}
        path = Path('/mock/test modules/scst.ko')
        with patch.object(run.subprocess, 'run',
                          side_effect=lambda argv, **kw: Mock(stdout=fields.get(argv[2], ''))) as query:
            info = run.module_info(path)
        self.assertEqual(info['git_commit'], 'embedded-commit')
        self.assertEqual(info['build_number'], '0')
        self.assertEqual(info['build_date'], '')
        self.assertEqual(info['labels'], {'scst-LIB': 'LIB'})
        for call in query.call_args_list:
            self.assertEqual(call.args[0][:2], ['modinfo', '-F'])
            self.assertEqual(call.args[0][-1], str(path))
        self.assertEqual({call.args[0][2] for call in query.call_args_list},
                         set(run.MODULE_METADATA) | {'name', 'scst_kunit_suite', 'depends'})

    def execute(self, logs=None, labels=None, inventory=None, load_logs=None,
                loaded=(), missing=(), failure=None, unload_warning=False, preflight=None,
                kernel_mode='built-in', interface_error=None, remains=(),
                fail_loaded=False, failure_code=1, cleanup_failure=False, observe=None, results=None, label_config=None):
        result = report()
        capture = Mock(messages=[])
        inventory = inventory or [manifest()]
        logs = {'scst-LIB': PASS} if logs is None else logs
        load_logs = load_logs or {}
        present = set(loaded)
        labels = ['ALL'] if labels is None else labels
        def operation(argv, *args):
            if observe:
                observe(argv)
            if argv[0] == 'modprobe':
                name = 'kunit' if '--first-time' in argv else argv[-1]
                if name == 'kunit':
                    self.assertEqual(argv, ['modprobe', '--first-time', '--ignore-install', 'kunit',
                                           'enable=1', 'autorun=0'])
                else:
                    self.assertEqual(argv, ['modprobe', '--ignore-install', name])
                capture.messages.extend(load_logs.get(name, []))
            elif argv[0] == 'insmod':
                name = Path(argv[1]).stem
                capture.messages.extend(load_logs.get(name, []))
            elif argv[0] == 'rmmod':
                name = argv[1]
                self.assertEqual(argv, ['rmmod', name])
                if unload_warning:
                    capture.messages.append('WARNING: at module exit')
            else:
                name = Path(argv[-1]).parent.name
                capture.messages.extend(logs.get(name, []))
            if failure == (argv[0], name) or failure == ('suite', name):
                if fail_loaded:
                    present.add(name)
                if isinstance(failure_code, Exception):
                    raise failure_code
                return failure_code
            if cleanup_failure and argv == ['rmmod', 'kunit']:
                return 1
            if argv[0] in ('modprobe', 'insmod'):
                self.assertNotIn(name, present)
                present.add(name)
            elif argv[0] == 'rmmod' and name not in remains:
                present.discard(name)
            elif argv[0] not in ('modprobe', 'insmod', 'rmmod'):
                text = results[name] if results is not None and name in results else document(logs.get(name, []))
                Path(argv[-2]).write_text(text)
            return 0
        with tempfile.TemporaryDirectory() as tmp:
            debugfs = Path(tmp) / 'kunit'
            debugfs.mkdir()
            for item in inventory:
                for suite in item['suites']:
                    path = debugfs / suite
                    path.mkdir(exist_ok=True)
                    if suite not in missing:
                        (path / 'run').touch()
            with patch.object(run.os, 'geteuid', return_value=0), \
                    patch.object(run.shutil, 'which', return_value='/mock/tool'), \
                    patch.object(run, 'module_info', side_effect=inventory), \
                    patch.object(run, 'check_kernel', side_effect=preflight, return_value=kernel_mode), \
                    patch.object(run, 'check_kunit_interfaces', side_effect=interface_error), \
                    patch.object(run, 'DEBUGFS', debugfs), \
                    patch.object(Path, 'exists', lambda p: str(p) in ['/sys/module/' + n for n in present]), \
                    patch.object(run, 'KernelLog', return_value=capture), \
                    patch.object(run, 'command', side_effect=operation) as command:
                try:
                    run.execute([Path('/mock/' + i['name'] + '.ko') for i in inventory],
                                10, Path(tmp), result, labels,
                                label_config=label_config or run.DEFAULT_LABEL_CONFIG)
                except (run.RunError, ValueError) as exc:
                    result['errors'].append(str(exc))
        operations = []
        for call in command.call_args_list:
            argv = call.args[0]
            operations.append(('modprobe', 'kunit' if '--first-time' in argv else argv[-1]) if argv[0] == 'modprobe' else
                              (argv[0], Path(argv[1]).stem) if argv[0] == 'insmod' else
                              (argv[0], argv[1]) if argv[0] == 'rmmod' else
                              ('suite', Path(argv[-1]).parent.name))
        return result, operations, capture

    @staticmethod
    def both_manifests():
        return [manifest(), manifest('scst_vdisk', {'scst-VDISK-capacity': 'VDISK'})]

    def test_complete_pass_fail_and_skip_allow_cleanup(self):
        for messages in (PASS, FAIL, SKIP):
            result, operations, capture = self.execute({'scst-LIB': messages})
            self.assertEqual(result['module_state'], 'unloaded')
            self.assertEqual(operations, [('insmod', 'scst'), ('suite', 'scst-LIB'), ('rmmod', 'scst')])
            capture.close.assert_called_once()

    def test_debugfs_is_authoritative_even_without_printk_results(self):
        for text, failed in ((document(PASS), False), (document(FAIL), True)):
            result, operations, _ = self.execute(logs={}, results={'scst-LIB': text})
            self.assertFalse(result['errors'])
            self.assertEqual(result['suite_results']['scst-LIB'], text)
            self.assertEqual(operations[-1], ('rmmod', 'scst'))
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.finish(result, Path(tmp)), int(failed))

    def test_valid_printk_cannot_hide_broken_debugfs_results(self):
        for text in ('', document(PASS[:-1]), document(VDISK_PASS), document(PASS) * 2):
            result, operations, _ = self.execute(logs={'scst-LIB': PASS},
                results={'scst-LIB': text}, inventory=self.both_manifests())
            self.assertTrue(result['errors'])
            self.assertEqual(operations, [('insmod', 'scst'), ('suite', 'scst-LIB')])
            self.assertEqual(result['suite_results']['scst-LIB'], text)

    def test_oops_in_kernel_log_stops_after_complete_debugfs_pass(self):
        result, operations, _ = self.execute(logs={'scst-LIB': OOPS},
            results={'scst-LIB': document(PASS)}, inventory=self.both_manifests())
        self.assertEqual(operations, [('insmod', 'scst'), ('suite', 'scst-LIB')])
        self.assertEqual(result['stop_reason'], 'kernel diagnostics during scst-LIB')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.finish(result, Path(tmp)), 1)

    def test_results_stream_before_next_owner_without_summary_duplicates(self):
        console = io.StringIO()
        def observe(argv):
            if argv[0] == 'insmod' and argv[1].endswith('scst_vdisk.ko'):
                self.assertIn('[FAIL] scst-LIB', console.getvalue())
        with contextlib.redirect_stdout(console):
            result, operations, _ = self.execute(
                {'scst-LIB': FAIL, 'scst-VDISK-capacity': VDISK_PASS},
                inventory=self.both_manifests(), observe=observe)
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(run.finish(result, Path(tmp)), 1)
                saved = json.loads((Path(tmp) / 'result.json').read_text())
                self.assertNotIn('printed_suites', saved)
        self.assertEqual(console.getvalue().count('[FAIL] scst-LIB'), 1)
        self.assertEqual(console.getvalue().count('[PASS] scst-VDISK-capacity'), 1)
        self.assertEqual(operations[-2:], [('rmmod', 'scst_vdisk'), ('rmmod', 'scst')])

    def test_oops_stops_before_next_suite_and_explains_why(self):
        inventory = [manifest('scst', {'scst-LIB': 'LIB', 'scst-CDB': 'CDB'})]
        console = io.StringIO()
        with contextlib.redirect_stdout(console):
            result, operations, _ = self.execute({'scst-LIB': FAIL[:2] + OOPS + FAIL[2:]},
                                                 inventory=inventory, kernel_mode='load')
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(run.finish(result, Path(tmp)), 1)
        self.assertEqual(operations, [('modprobe', 'kunit'), ('insmod', 'scst'), ('suite', 'scst-LIB')])
        self.assertEqual(result['not_run_suites'], ['scst-CDB'])
        self.assertIn('Stopped: kernel diagnostics during scst-LIB; 1 suite not run', console.getvalue())
        self.assertEqual(result['kunit_state'], 'retained')

    def test_modular_kunit_is_owned_until_scst_cleanup_finishes(self):
        for messages in (PASS, FAIL, SKIP):
            result, operations, _ = self.execute(logs={'scst-LIB': messages}, kernel_mode='load')
            self.assertFalse(result['errors'])
            self.assertEqual(operations, [('modprobe', 'kunit'), ('insmod', 'scst'),
                                         ('suite', 'scst-LIB'), ('rmmod', 'scst'), ('rmmod', 'kunit')])
            self.assertEqual(result['kunit_state'], 'unloaded')

    def test_external_dependencies_precede_kunit_and_preloaded_ones_are_reused(self):
        inventory = [manifest(depends=('dlm', 'kunit'))]
        result, operations, _ = self.execute(inventory=inventory, kernel_mode='load')
        self.assertFalse(result['errors'])
        self.assertEqual(operations[:3], [('modprobe', 'dlm'), ('modprobe', 'kunit'), ('insmod', 'scst')])
        self.assertNotIn(('rmmod', 'dlm'), operations)
        result, operations, _ = self.execute(inventory=inventory, kernel_mode='load', loaded=('dlm',))
        self.assertFalse(result['errors'])
        self.assertNotIn(('modprobe', 'dlm'), operations)

    def test_only_selected_owners_prepare_external_dependencies(self):
        inventory = [manifest(depends=('dlm', 'kunit')),
                     manifest('scst_vdisk', {'scst-VDISK-capacity': 'VDISK'}, depends=('scst', 'dlm', 'crc32c')),
                     manifest('scst_user', {'scst-USER-cleanup': 'USER'}, depends=('scst', 'unselected_dep'))]
        result, operations, _ = self.execute(inventory=inventory, labels=['VDISK'],
                                             logs={'scst-VDISK-capacity': VDISK_PASS})
        self.assertFalse(result['errors'])
        self.assertEqual([name for op, name in operations if op == 'modprobe'], ['crc32c', 'dlm'])
        self.assertEqual([name for op, name in operations if op == 'insmod'], ['scst', 'scst_vdisk'])

    def test_dependency_failure_or_diagnostics_stop_before_kunit_loading(self):
        for options in ({'failure': ('modprobe', 'dlm')},
                        {'load_logs': {'dlm': ['WARNING: dependency initialization']}},
                        {'load_logs': {'dlm': PASS}}):
            result, operations, _ = self.execute(inventory=[manifest(depends=('dlm',))],
                                                 kernel_mode='load', **options)
            self.assertTrue(result['errors'])
            self.assertEqual(operations, [('modprobe', 'dlm')])
            self.assertEqual(result['kunit_state'], 'not loaded')

    def test_failed_initial_load_releases_only_runner_owned_kunit(self):
        for mode in ('load', 'preloaded', 'built-in'):
            result, operations, _ = self.execute(kernel_mode=mode, failure=('insmod', 'scst'),
                                                 loaded=('kunit',) if mode == 'preloaded' else ())
            self.assertIn('insmod scst', result['errors'][0])
            self.assertEqual(result['module_state'], 'not loaded')
            self.assertEqual(('rmmod', 'kunit') in operations, mode == 'load')
            self.assertEqual(result['kunit_state'], 'unloaded' if mode == 'load' else mode)

    def test_unsafe_failed_load_does_not_unload_kunit(self):
        for options in ({'load_logs': {'scst': ['WARNING: init failed']}},
                        {'load_logs': {'scst': PASS}}, {'fail_loaded': True},
                        {'failure_code': -9}, {'failure_code': run.RunError('lost records')},
                        {'failure_code': run.RunError('timeout; child still running')}):
            result, operations, _ = self.execute(kernel_mode='load', failure=('insmod', 'scst'), **options)
            self.assertTrue(result['errors'])
            self.assertNotIn(('rmmod', 'kunit'), operations)
            self.assertEqual(result['kunit_state'], 'retained')

    def test_failed_cleanup_keeps_original_load_error(self):
        result, operations, _ = self.execute(kernel_mode='load', failure=('insmod', 'scst'), cleanup_failure=True)
        self.assertEqual(operations[-1], ('rmmod', 'kunit'))
        self.assertEqual(result['kunit_state'], 'retained')
        self.assertTrue(any('insmod scst' in error for error in result['errors']))
        self.assertTrue(any('Could not unload' in error for error in result['errors']))

    def test_preloaded_kunit_is_preserved_after_pass_fail_and_skip(self):
        for messages in (PASS, FAIL, SKIP):
            with self.subTest(messages=messages):
                result, operations, _ = self.execute(kernel_mode='preloaded', loaded=('kunit',),
                                                     logs={'scst-LIB': messages})
                self.assertFalse(result['errors'])
                self.assertEqual(result['kunit_state'], 'preloaded')
                self.assertEqual(operations, [('insmod', 'scst'), ('suite', 'scst-LIB'), ('rmmod', 'scst')])

    def test_preloaded_kunit_is_preserved_after_operation_errors(self):
        for failure in (('insmod', 'scst'), ('suite', 'scst-LIB'), ('rmmod', 'scst')):
            with self.subTest(failure=failure):
                result, operations, _ = self.execute(kernel_mode='preloaded', loaded=('kunit',),
                                                     failure=failure)
                self.assertTrue(result['errors'])
                self.assertEqual(result['kunit_state'], 'preloaded')
                self.assertEqual(operations[-1], failure)
                self.assertFalse(any(name == 'kunit' for op, name in operations))

    def test_kunit_preparation_failure_stops_before_loading_scst(self):
        for options in ({'failure': ('modprobe', 'kunit')},
                        {'interface_error': run.RunError('no run interface')},
                        {'load_logs': {'kunit': PASS}},
                        {'load_logs': {'kunit': ['WARNING: KUnit startup']}}):
            with self.subTest(options=options):
                result, operations, _ = self.execute(kernel_mode='load', **options)
                self.assertEqual(operations, [('modprobe', 'kunit')])
                self.assertEqual(result['module_state'], 'not attempted')

    def test_unsafe_scst_results_preserve_owned_and_preloaded_kunit(self):
        for messages in (PASS[:-1], PASS + ['WARNING: in test'],
                         PASS + ['# SCST_KUNIT_RETAINED: worker']):
            for mode in ('load', 'preloaded'):
                with self.subTest(messages=messages, mode=mode):
                    result, operations, _ = self.execute(kernel_mode=mode, logs={'scst-LIB': messages},
                        loaded=('kunit',) if mode == 'preloaded' else ())
                    self.assertEqual(result['kunit_state'], 'preloaded' if mode == 'preloaded' else 'retained')
                    self.assertFalse(any(op == 'rmmod' for op, name in operations))

    def test_kunit_cleanup_failure_cannot_pass(self):
        for options in ({'failure': ('rmmod', 'kunit')}, {'remains': ('kunit',)}):
            with self.subTest(options=options):
                result, operations, _ = self.execute(kernel_mode='load', **options)
                self.assertEqual(operations[-1], ('rmmod', 'kunit'))
                self.assertEqual(result['module_state'], 'unloaded')
                self.assertIn('Could not unload', result['errors'][0])
                with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(run.finish(result, Path(tmp)), 2)
                self.assertEqual(result['test_status'], 'PASS')

    def test_final_kunit_cleanup_does_not_hide_unexpected_execution(self):
        for messages in (PASS, ['# SCST_KUNIT_RETAINED: worker']):
            capture = Mock(messages=[])
            def operation(*args):
                capture.messages.extend(messages)
                return 0
            with tempfile.TemporaryDirectory() as tmp, \
                    patch.object(run, 'command', side_effect=operation), \
                    patch.object(Path, 'exists', return_value=False):
                with self.assertRaises(run.RunError):
                    run.unload_owned_kunit(capture, Path(tmp), 10, report())

    def test_selected_handler_does_not_execute_dependency_tests(self):
        inventory = self.both_manifests() + [manifest('scst_user', {'scst-USER-cleanup': 'USER'})]
        result, operations, _ = self.execute({'scst-VDISK-capacity': VDISK_PASS}, labels=['VDISK'],
                                             inventory=inventory, loaded=('scst_user',))
        self.assertFalse(result['errors'])
        self.assertEqual(operations, [('insmod', 'scst'), ('insmod', 'scst_vdisk'),
            ('suite', 'scst-VDISK-capacity'), ('rmmod', 'scst_vdisk'), ('rmmod', 'scst')])
        self.assertEqual(result['expected_suites'], ['scst-VDISK-capacity'])
        self.assertEqual(result['modules'][2]['state'], 'not attempted')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.finish(result, Path(tmp)), 0)

    def test_composite_selection_loads_dependencies_and_runs_each_suite_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'custom labels.toml'
            config.write_text('[IO]\nlabels = ["VDISK"]\nsuites = ["scst-LIB"]\n')
            result, operations, _ = self.execute(
                {'scst-LIB': PASS, 'scst-VDISK-capacity': VDISK_PASS},
                inventory=list(reversed(self.both_manifests())), labels=['IO', 'VDISK'],
                label_config=config)
            self.assertFalse(result['errors'])
            self.assertEqual(operations, [('insmod', 'scst'), ('suite', 'scst-LIB'),
                ('insmod', 'scst_vdisk'), ('suite', 'scst-VDISK-capacity'),
                ('rmmod', 'scst_vdisk'), ('rmmod', 'scst')])
            self.assertEqual(result['label_config'], str(config))
            self.assertEqual(result['composite_labels']['IO']['suites'], ['scst-LIB'])

    def test_exact_suite_group_does_not_run_other_suites_in_its_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'labels.toml'
            config.write_text('[CAPACITY]\nsuites = ["scst-VDISK-capacity"]\n')
            inventory = [manifest(), manifest('scst_vdisk',
                {'scst-VDISK-capacity': 'VDISK', 'scst-VDISK-sync': 'VDISK'})]
            result, operations, _ = self.execute({'scst-VDISK-capacity': VDISK_PASS},
                inventory=inventory, labels=['CAPACITY'], label_config=config)
            self.assertFalse(result['errors'])
            self.assertEqual([name for op, name in operations if op == 'suite'], ['scst-VDISK-capacity'])
            self.assertEqual([name for op, name in operations if op == 'insmod'], ['scst', 'scst_vdisk'])

    def test_incomplete_composite_is_rejected_before_any_module_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'labels.toml'
            for definition in ('labels = ["LIB", "VDISK"]',
                               'suites = ["scst-LIB", "scst-VDISK-capacity"]'):
                config.write_text('[IO]\n' + definition)
                result, operations, _ = self.execute(labels=['IO'], label_config=config,
                                                     kernel_mode='load')
                self.assertIn('absent', result['errors'][0])
                self.assertEqual(operations, [])
                self.assertEqual(result['module_state'], 'not attempted')

    def test_multiple_labels_and_nonmatching_suite_names(self):
        labels = {'scst-LIB': 'LIB', 'scst-CM': 'CM', 'scst-LIFECYCLE': 'LIFECYCLE',
                  'scst-LIFECYCLE-blocking': 'LIFECYCLE'}
        selected = ['scst-CM', 'scst-LIFECYCLE', 'scst-LIFECYCLE-blocking']
        result, operations, _ = self.execute({s: suite_log(s) for s in selected},
            labels=['CM', 'LIFECYCLE'], inventory=[manifest(labels=labels)])
        self.assertEqual([name for op, name in operations if op == 'suite'], selected)
        self.assertEqual(result['module_state'], 'unloaded')

    def test_incomplete_unexpected_and_retained_results_stop_execution(self):
        for messages in (PASS[:-1], [], PASS + PASS, PASS + VDISK_PASS,
                         PASS + ['# SCST_KUNIT_RETAINED: worker']):
            result, operations, _ = self.execute({'scst-LIB': messages}, inventory=self.both_manifests())
            self.assertTrue(result['errors'])
            self.assertEqual(operations, [('insmod', 'scst'), ('suite', 'scst-LIB')])
            self.assertEqual(result['modules'][1]['state'], 'not attempted')

    def test_automatic_execution_is_an_error(self):
        result, operations, _ = self.execute(load_logs={'scst': PASS})
        self.assertTrue(result['errors'])
        self.assertEqual(operations, [('insmod', 'scst')])

    def test_diagnostics_stop_after_load_or_suite(self):
        for options in ({'load_logs': {'scst': ['BUG: core init']}},
                        {'logs': {'scst-LIB': PASS + ['WARNING: in test']},
                         'results': {'scst-LIB': document(PASS)}}):
            result, operations, _ = self.execute(inventory=self.both_manifests(), **options)
            self.assertEqual(result['module_state'], 'retained')
            self.assertFalse(any(op == 'rmmod' or name == 'scst_vdisk' for op, name in operations))
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.finish(result, Path(tmp)), 1)
                self.assertFalse(result['parse_errors'])
                expected = ['scst-LIB', 'scst-VDISK-capacity'] if 'load_logs' in options else ['scst-VDISK-capacity']
                self.assertEqual(result['not_run_suites'], expected)

    def test_missing_run_interface_retains_module(self):
        result, operations, _ = self.execute(missing=('scst-LIB',))
        self.assertIn('Missing KUnit run interface', result['errors'][0])
        self.assertEqual(operations, [('insmod', 'scst')])

    def test_preflight_and_loaded_module_errors_prevent_operations(self):
        for options in ({'loaded': ('scst',)}, {'preflight': run.RunError('bad VM')}):
            result, operations, _ = self.execute(**options)
            self.assertTrue(result['errors'])
            self.assertEqual(operations, [])

    def test_unknown_label_and_bad_module_sets_prevent_operations(self):
        core, handler = self.both_manifests()
        for inventory, labels in [([core], ['UNKNOWN']), ([core, core], ['ALL']),
                                  ([handler], ['VDISK']),
                                  ([manifest(labels={})], ['ALL']),
                                  ([core, manifest('qla2xxx_scst')], ['ALL']),
                                  ([core, manifest('scst_vdisk')], ['ALL'])]:
            result, operations, _ = self.execute(inventory=inventory, labels=labels)
            self.assertTrue(result['errors'])
            self.assertEqual(operations, [])

    def test_two_modules_execute_and_cleanup_in_dependency_order(self):
        result, operations, _ = self.execute({'scst-LIB': PASS, 'scst-VDISK-capacity': VDISK_PASS},
                                             inventory=self.both_manifests())
        self.assertEqual(operations, [('insmod', 'scst'), ('suite', 'scst-LIB'),
            ('insmod', 'scst_vdisk'), ('suite', 'scst-VDISK-capacity'), ('rmmod', 'scst_vdisk'), ('rmmod', 'scst')])
        self.assertEqual(result['module_state'], 'unloaded')

    def test_dependency_metadata_orders_new_owners_and_transitive_dependencies(self):
        core = manifest()
        middle = manifest('scst_extra', {'scst-EXTRA': 'EXTRA'})
        leaf = manifest('scst_new', {'scst-NEW': 'NEW'}, depends=('scst_extra',))
        result, operations, _ = self.execute({'scst-NEW': suite_log('scst-NEW')},
            inventory=[leaf, middle, core], labels=['NEW'])
        self.assertFalse(result['errors'])
        self.assertEqual(operations, [('insmod', 'scst'), ('insmod', 'scst_extra'),
            ('insmod', 'scst_new'), ('suite', 'scst-NEW'), ('rmmod', 'scst_new'),
            ('rmmod', 'scst_extra'), ('rmmod', 'scst')])

    def test_dependency_cycles_prevent_module_operations(self):
        core = manifest(depends=('scst_vdisk',))
        handler = manifest('scst_vdisk', {'scst-VDISK': 'VDISK'})
        result, operations, _ = self.execute(inventory=[handler, core])
        self.assertIn('Cyclic module dependency', result['errors'][0])
        self.assertEqual(operations, [])

    def test_new_module_owners_need_only_a_valid_manifest(self):
        fields = {'name': 'scst-new', 'scst_kunit_suite': 'NEW_LABEL:scst-NEW_LABEL',
                  'depends': 'scst-extra,kunit', 'vermagic': 'test-kernel'}
        with patch.object(run.subprocess, 'run',
                          side_effect=lambda argv, **kw: Mock(stdout=fields.get(argv[2], ''))):
            info = run.module_info(Path('/mock/scst-new.ko'))
        self.assertEqual(info['name'], 'scst_new')
        self.assertEqual(info['depends'], ['scst_extra', 'kunit'])
        self.assertEqual(info['labels'], {'scst-NEW_LABEL': 'NEW_LABEL'})

    def test_all_module_owners(self):
        names = ['scst', 'scst_vdisk', 'scst_user', 'iscsi_scst']
        inventory = [manifest(name, {f'scst-test-{i}': f'TEST{i}'}) for i, name in enumerate(names)]
        for failed in (False, True):
            with self.subTest(failed=failed):
                logs = {f'scst-test-{i}': suite_log(f'scst-test-{i}') for i in range(len(names))}
                if failed:
                    logs['scst-test-0'] = [line.replace('scst-LIB', 'scst-test-0') for line in FAIL]
                result, operations, _ = self.execute(logs, inventory=inventory)
                self.assertFalse(result['errors'])
                self.assertEqual([name for op, name in operations if op == 'insmod'], names)
                self.assertEqual([name for op, name in operations if op == 'suite'], list(logs))
                self.assertEqual([name for op, name in operations if op == 'rmmod'], list(reversed(names)))
                with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(run.finish(result, Path(tmp)), int(failed))
                self.assertEqual(result['not_run_suites'], [])
                self.assertEqual(result['counts']['failed'], int(failed))
                self.assertEqual(result['counts']['passed'], len(names) - int(failed))

    def test_each_selected_suite_must_finish(self):
        labels = {s: 'VDISK' for s in ('scst-VDISK-capacity', 'scst-VDISK-io', 'scst-VDISK-sync')}
        for completed in range(4):
            logs = {s: suite_log(s) for s in list(labels)[:completed]}
            result, operations, _ = self.execute(logs, labels=['VDISK'],
                inventory=[manifest(), manifest('scst_vdisk', labels)])
            self.assertEqual(result['module_state'], 'unloaded' if completed == 3 else 'retained')
            self.assertEqual(len([op for op in operations if op[0] == 'suite']), min(3, completed + 1))
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.finish(result, Path(tmp)), 0 if completed == 3 else 2)
                self.assertEqual(result['not_run_suites'], list(labels)[completed + 1:])
                if completed < 3:
                    self.assertTrue(result['parse_errors'])

    def test_kernel_mismatch_rejected_before_loading(self):
        inventory = self.both_manifests()
        inventory[1]['vermagic'] = 'different-kernel'
        result, operations, _ = self.execute(inventory=inventory)
        self.assertIn('vermagic', result['errors'][0])
        self.assertEqual(operations, [])

    def test_operation_failures_retain_dependencies(self):
        for failure in [('insmod', 'scst'), ('suite', 'scst-LIB'), ('insmod', 'scst_vdisk'),
                        ('suite', 'scst-VDISK-capacity'), ('rmmod', 'scst_vdisk')]:
            result, operations, _ = self.execute({'scst-LIB': PASS, 'scst-VDISK-capacity': VDISK_PASS},
                inventory=self.both_manifests(), failure=failure)
            self.assertTrue(result['errors'])
            self.assertEqual(operations[-1], failure)
            self.assertNotEqual(result['module_state'], 'unloaded')

    def test_unload_warning_stops_before_core_cleanup(self):
        result, operations, _ = self.execute({'scst-LIB': PASS, 'scst-VDISK-capacity': VDISK_PASS},
            inventory=self.both_manifests(), unload_warning=True)
        self.assertEqual(operations[-1], ('rmmod', 'scst_vdisk'))
        self.assertEqual(result['module_state'], 'retained')

    def test_interruption_preserves_log(self):
        capture = Mock(messages=PASS[:2])
        result = report()
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(run.os, 'geteuid', return_value=0), \
                patch.object(run.shutil, 'which', return_value='/mock/tool'), \
                patch.object(run, 'module_info', return_value=manifest()), \
                patch.object(Path, 'exists', return_value=False), \
                patch.object(run, 'check_kernel'), \
                patch.object(run, 'KernelLog', return_value=capture), \
                patch.object(run, 'command', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                run.execute([Path('/mock/scst.ko')], 10, Path(tmp), result, ['LIB'])
        self.assertEqual(result['messages'], PASS[:2])
        capture.close.assert_called_once()

    def test_main_retains_reports_after_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            module = directory / 'scst.ko'
            module.touch()
            real_open = os.open
            def local_lock(path, flags, mode=0o777):
                self.assertEqual(path, '/run/lock/scst-kunit.lock')
                return real_open(directory / 'lock', flags, mode)
            with patch.object(run.os, 'open', side_effect=local_lock), \
                    patch.object(run, 'execute', side_effect=run.RunError('operation failed')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.main([str(module), '--labels', 'LIB', '--output', str(directory)]), 2)
            data = json.loads(next(directory.glob('*/result.json')).read_text())
            self.assertIn('operation failed', data['errors'])
            self.assertEqual(data['labels'], ['LIB'])
            self.assertEqual(data['status'], 'ERROR')


class KernelSetupTests(unittest.TestCase):
    def check(self, config=None, cmdline='kunit.autorun=0 kunit.enable=1', filters=None,
              module=False, debugfs=True, modprobe=True, parameters=None):
        settings = {'CONFIG_KUNIT': 'y', 'CONFIG_KUNIT_DEBUGFS': 'y', 'CONFIG_KUNIT_AUTORUN_ENABLED': 'y',
                    'CONFIG_KUNIT_DEFAULT_ENABLED': 'y'}
        settings.update(config or {})
        settings = {key: value for key, value in settings.items() if value is not None}
        filters = filters or {}
        parameters = parameters or {}
        def read(path, *args, **kwargs):
            if str(path) == '/proc/cmdline':
                return cmdline
            self.assertTrue(str(path).startswith('/sys/module/kunit/parameters/'))
            if path.name in ('enable', 'autorun'):
                value = parameters.get(path.name, FileNotFoundError(str(path)))
                if isinstance(value, OSError):
                    raise value
                return value
            return filters.get(path.name, '(null)\n')
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(run, 'DEBUGFS', Path(tmp) if debugfs else Path(tmp) / 'missing'), \
                patch.object(run, 'kernel_config', return_value=settings), \
                patch.object(run.shutil, 'which', return_value='/mock/modprobe' if modprobe else None), \
                patch.object(Path, 'exists', return_value=module), \
                patch.object(Path, 'read_text', read):
            return run.check_kernel()

    def test_prepared_kernel_and_neutral_parameters(self):
        self.check()
        self.check(cmdline='kunit.autorun=1 kunit.autorun=0')
        self.check(filters={'filter_glob': '(null)'})
        self.check(config={'CONFIG_KUNIT_AUTORUN_ENABLED': 'n'})
        for glob in ('*', '*.*'):
            self.check(filters={'filter_glob': glob, 'filter': '', 'filter_action': ''})

    def test_modular_kunit_preparation(self):
        self.assertEqual(self.check(config={'CONFIG_KUNIT': 'm'}, cmdline=''), 'load')
        with self.assertRaisesRegex(run.RunError, 'modprobe'):
            self.check(config={'CONFIG_KUNIT': 'm'}, modprobe=False)

    def test_preloaded_kunit_uses_effective_parameters(self):
        for values in ({'enable': 'Y\n', 'autorun': 'N\n'}, {'enable': '1\n', 'autorun': '0\n'}):
            with self.subTest(values=values):
                self.assertEqual(self.check(config={'CONFIG_KUNIT': 'm', 'CONFIG_KUNIT_DEFAULT_ENABLED': 'n'},
                    module=True, parameters=values, cmdline='kunit.enable=0 kunit.autorun=1',
                    modprobe=False), 'preloaded')

    def test_preloaded_kunit_rejects_incompatible_parameters(self):
        for name, invalid in (('enable', 'N'), ('autorun', 'Y'), ('enable', ''), ('autorun', 'unknown')):
            with self.subTest(name=name, invalid=invalid), self.assertRaisesRegex(run.RunError,
                    'Preloaded kunit.' + name + '.*Module left unchanged'):
                self.check(config={'CONFIG_KUNIT': 'm'}, module=True,
                           parameters={'enable': 'Y', 'autorun': 'N', name: invalid})

    def test_preloaded_kunit_rejects_hidden_or_unreadable_parameters(self):
        for name in ('enable', 'autorun'):
            for problem in (FileNotFoundError('hidden'), PermissionError('denied')):
                with self.subTest(name=name, problem=problem), self.assertRaisesRegex(run.RunError,
                        '(?s)Cannot verify preloaded KUnit.*' + name + '.*rmmod kunit'):
                    self.check(config={'CONFIG_KUNIT': 'm'}, module=True,
                               parameters={'enable': 'Y', 'autorun': 'N', name: problem})

    def test_preloaded_kunit_still_requires_debugfs_and_neutral_filters(self):
        for options in ({'debugfs': False}, {'filters': {'action': 'list'}},
                        {'filters': {'filter_glob': 'scst-LIB*'}}, {'filters': {'filter_glob': ''}},
                        {'filters': {'filter': 'speed=slow'}}, {'filters': {'filter_action': 'skip'}}):
            with self.subTest(options=options), self.assertRaises(run.RunError):
                self.check(config={'CONFIG_KUNIT': 'm'}, module=True,
                           parameters={'enable': 'Y', 'autorun': 'N'}, **options)

    def test_unsafe_or_unverifiable_setup_is_rejected(self):
        for options in ({'config': {'CONFIG_KUNIT': 'n'}}, {'module': True}, {'debugfs': False},
                        {'config': {'CONFIG_KUNIT_AUTORUN_ENABLED': None}},
                        {'config': {'CONFIG_KUNIT_DEBUGFS': 'n'}},
                        {'cmdline': ''}, {'cmdline': 'kunit.autorun=0 kunit.autorun=1'},
                        {'cmdline': '-- kunit.autorun=0'}, {'cmdline': 'kunit.autorun=0 kunit.enable=0'}):
            with self.subTest(options=options), self.assertRaises(run.RunError):
                self.check(**options)
        for name in ('action', 'filter_glob', 'filter', 'filter_action'):
            with self.subTest(name=name), self.assertRaises(run.RunError):
                self.check(filters={name: 'custom'})
        for name in ('action', 'filter_glob'):
            with self.subTest(name=name), self.assertRaises(run.RunError):
                self.check(filters={name: ''})

    def test_config_reader_preserves_unset_options(self):
        source = 'CONFIG_KUNIT=y\n# CONFIG_KUNIT_AUTORUN_ENABLED is not set\n'
        with patch.object(Path, 'is_file', lambda p: str(p) == '/proc/config.gz'), \
                patch.object(run.gzip, 'open', return_value=io.StringIO(source)):
            values = run.kernel_config()
        self.assertEqual(values['CONFIG_KUNIT'], 'y')
        self.assertEqual(values['CONFIG_KUNIT_AUTORUN_ENABLED'], 'n')
        with patch.object(Path, 'is_file', return_value=False), self.assertRaises(run.RunError):
            run.kernel_config()


class ConfigurationTests(unittest.TestCase):
    @staticmethod
    def arguments(args):
        return run.arguments(['--labels', 'LIB', *args])

    def test_labels_default_to_all_and_explicit_values_are_normalized(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp) / 'scst.ko'
            module.touch()
            self.assertEqual(run.arguments([str(module)])[-1], ['ALL'])
        for args in (['--labels', ''], ['--labels', 'ALL LIB'], ['--labels', 'lib']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run.arguments(args)
        self.assertEqual(run.parse_labels('LIB LIB VDISK'), ['LIB', 'VDISK'])
        self.assertEqual(run.parse_labels('ALL'), ['ALL'])

    def test_default_uses_recorded_build_in_dependency_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            core, handler = root / 'core.ko', root / 'handler with spaces.ko'
            core.touch()
            handler.touch()
            (root / 'stale.ko').touch()
            modules = root / '.kunit-modules'
            modules.write_text('core.ko\nhandler with spaces.ko\n')
            config = root / 'settings.toml'
            config.write_text('timeout_seconds=12\nverbose=true\n')
            with patch.object(run, 'DEFAULT_MODULE_LIST', modules):
                selected, timeout, _, verbose, _, labels = self.arguments(['--config', str(config)])
            self.assertEqual(selected, [core, handler])
            self.assertEqual(timeout, 12)
            self.assertTrue(verbose)

    def test_explicit_paths_then_config_override_recorded_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            configured, explicit = root / 'configured.ko', root / 'explicit.ko'
            configured.touch()
            explicit.touch()
            config = root / 'settings.toml'
            config.write_text('modules=["configured.ko"]\n')
            modules = root / '.kunit-modules'
            modules.write_text('missing-stale-module.ko\n')
            with patch.object(run, 'DEFAULT_MODULE_LIST', modules):
                self.assertEqual(self.arguments(['--config', str(config)])[0], [configured])
                self.assertEqual(self.arguments([str(explicit), '--config', str(config)])[0],
                                 [explicit])

    def test_missing_invalid_or_stale_build_list_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'settings.toml'
            config.touch()
            modules = root / '.kunit-modules'
            for content in (None, '', '\n', 'missing.ko\n'):
                if content is not None:
                    modules.write_text(content)
                with self.subTest(content=content), patch.object(run, 'DEFAULT_MODULE_LIST', modules), \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    self.arguments(['--config', str(config)])

    def test_config_paths_and_cli_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'scst.ko').touch()
            config = directory / 'settings.toml'
            config.write_text('module="scst.ko"\noutput_dir="reports"\ntimeout_seconds=9\n')
            module, timeout, output, verbose, _, labels = self.arguments(['--config', str(config)])
            self.assertFalse(verbose)
            self.assertEqual(module, [directory / 'scst.ko'])
            self.assertEqual(output, directory / 'reports')
            self.assertEqual(timeout, 9)
            self.assertEqual(self.arguments(['--config', str(config), '--timeout', '2'])[1], 2)
            for value in ('nan', 'inf', '0', '-1'):
                with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.arguments(['--config', str(config), '--timeout', value])

    def test_verbose_cli_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'scst.ko').touch()
            config = directory / 'settings.toml'
            config.write_text('module="scst.ko"\nverbose=true\n')
            args = ['--config', str(config)]
            self.assertTrue(self.arguments(args)[3])
            self.assertFalse(self.arguments(args + ['--no-verbose'])[3])
            config.write_text('module="scst.ko"\nverbose=false\n')
            self.assertTrue(self.arguments(args + ['--verbose'])[3])
            config.write_text('module="scst.ko"\nverbose="yes"\n')
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.arguments(args)

    def test_multiple_module_config_and_cli_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            core, handler = directory / 'scst.ko', directory / 'scst_vdisk.ko'
            core.touch()
            handler.touch()
            config = directory / 'settings.toml'
            config.write_text('modules=["scst.ko", "scst_vdisk.ko"]\n')
            self.assertEqual(self.arguments(['--config', str(config)])[0], [core, handler])
            self.assertEqual(self.arguments([str(core), '--config', str(config)])[0], [core])
            self.assertEqual(self.arguments([str(core), str(handler)])[0], [core, handler])
            for settings in ('modules=[]', 'modules="scst.ko"', 'modules=[1]',
                             'module="scst.ko"\nmodules=["scst.ko"]'):
                config.write_text(settings)
                with self.subTest(settings=settings), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.arguments(['--config', str(config)])


if __name__ == '__main__':
    unittest.main()
