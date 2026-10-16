# SPDX-License-Identifier: GPL-2.0-only
"""Supervisor failure contracts; no SCST, module operations or real VM access."""

from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import vm


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.manifest = dict(commit='a' * 40, suite='kunit', kernel='test-kernel')

    def completion(self, **changes):
        result = dict(self.manifest, mode='smoke', token='this-run', exit_code=0,
                      running_kernel='test-kernel')
        result.update(changes)
        (self.output / 'completion.json').write_text(json.dumps(result))

    def test_clean_qemu_exit_without_completion_is_not_success(self):
        with self.assertRaisesRegex(vm.VMError, 'completion'):
            vm.validate_completion(self.output, 'smoke', 'this-run', self.manifest)

    def test_report_must_match_this_boot_build_and_kernel(self):
        for changes in ({'token': 'old-run'}, {'commit': 'b' * 40},
                        {'running_kernel': 'wrong-kernel'}, {'exit_code': 1}):
            with self.subTest(changes=changes):
                self.completion(**changes)
                with self.assertRaises(vm.VMError):
                    vm.validate_completion(self.output, 'smoke', 'this-run', self.manifest)

    def test_complete_smoke_boot(self):
        self.completion()
        vm.validate_completion(self.output, 'smoke', 'this-run', self.manifest)

    def test_kernel_panic_survives_missing_guest_report(self):
        (self.output / 'target.serial.log').write_text(
            '[1.0] Kernel panic - not syncing: test crash\n[1.1] Call Trace:\n')
        self.assertTrue(vm.diagnostics(self.output))

    def test_initiator_crash_is_not_hidden_by_target(self):
        (self.output / 'initiator.serial.log').write_text('[1.0] BUG: unable to handle page fault\n')
        self.assertTrue(vm.diagnostics(self.output))

    def test_daemon_warning_is_not_a_kernel_fault(self):
        (self.output / 'initiator.serial.log').write_text(
            '[120.175797] bash[481]: WARNING: daemon configuration\n')
        self.assertFalse(vm.diagnostics(self.output))

    def test_boot_failure_has_a_shorter_deadline(self):
        target = Mock()
        target.poll.return_value = None
        with self.assertRaisesRegex(vm.VMError, 'boot deadline'):
            vm.wait_guest(target, None, float('inf'), self.output / 'ready',
                          self.output / 'release', self.output / 'started', 0)

    def test_deadline_does_not_depend_on_guest_response(self):
        target = Mock()
        target.poll.return_value = None
        with self.assertRaisesRegex(vm.VMError, 'deadline'):
            vm.wait_guest(target, None, 0, self.output / 'ready', self.output / 'release')

    def test_peer_loss_aborts_target_wait(self):
        target, peer = Mock(), Mock()
        target.poll.return_value = None
        peer.poll.return_value = 0
        with self.assertRaisesRegex(vm.VMError, 'initiator exited'):
            vm.wait_guest(target, peer, float('inf'), self.output / 'ready', self.output / 'release')

    def test_stuck_qemu_is_killed_after_term(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('qemu', 5), 0]
        with patch('vm.os.killpg') as kill:
            vm.stop(process)
        self.assertEqual(kill.call_count, 2)

    def test_all_skipped_kunit_is_not_a_pass(self):
        self.completion(mode='kunit')
        results = self.output / 'kunit/run'
        results.mkdir(parents=True)
        (results / 'result.json').write_text(json.dumps(dict(
            status='SKIP', counts=dict(passed=0), not_run_suites=[], module_state='unloaded')))
        with self.assertRaisesRegex(vm.VMError, 'KUnit did not complete'):
            vm.validate_completion(self.output, 'kunit', 'this-run', self.manifest)

    def test_ginkgo_requires_both_transport_reports(self):
        self.manifest['suite'] = 'ginkgo'
        self.completion(mode='ginkgo')
        with self.assertRaisesRegex(vm.VMError, 'both local and iSCSI'):
            vm.validate_completion(self.output, 'ginkgo', 'this-run', self.manifest)

    def test_ginkgo_cannot_pass_with_empty_or_failed_transport(self):
        self.manifest['suite'] = 'ginkgo'
        self.completion(mode='ginkgo')
        for group in ('local', 'iscsi'):
            (self.output / 'ginkgo' / group).mkdir(parents=True)
        for succeeded, count, state in ((True, 0, 'passed'), (False, 8, 'failed'),
                                        (True, 8, 'skipped'), (True, 8, 'passed')):
            with self.subTest(succeeded=succeeded, count=count, state=state):
                for group in ('local', 'iscsi'):
                    (self.output / 'ginkgo' / group / 'report.json').write_text(json.dumps([
                        dict(SuiteSucceeded=succeeded if group == 'iscsi' else True,
                             SuiteConfig=dict(LabelFilter=''),
                             PreRunStats=dict(SpecsThatWillRun=count if group == 'iscsi' else 31),
                             SpecReports=[dict(LeafNodeType='BeforeSuite', State='passed'),
                                          dict(LeafNodeType='It', State=state)])]))
                if succeeded and count and state == 'passed':
                    vm.validate_completion(self.output, 'ginkgo', 'this-run', self.manifest)
                else:
                    with self.assertRaisesRegex(vm.VMError, 'incomplete or failed Ginkgo'):
                        vm.validate_completion(self.output, 'ginkgo', 'this-run', self.manifest)

    def test_ginkgo_rejects_unexpected_filter_in_either_transport(self):
        self.manifest['suite'] = 'ginkgo'
        self.completion(mode='ginkgo')
        for group in ('local', 'iscsi'):
            (self.output / 'ginkgo' / group).mkdir(parents=True)
        for expected, actual in (('basic || smoke', ''), ('', 'basic || smoke')):
            for mismatched in ('local', 'iscsi'):
                with self.subTest(expected=expected, mismatched=mismatched):
                    for group in ('local', 'iscsi'):
                        (self.output / 'ginkgo' / group / 'report.json').write_text(json.dumps([
                            dict(SuiteSucceeded=True, PreRunStats=dict(SpecsThatWillRun=2),
                                 SuiteConfig=dict(LabelFilter=actual if group == mismatched else expected),
                                 SpecReports=[dict(LeafNodeType='It', State='passed')])]))
                    with self.assertRaisesRegex(vm.VMError, 'label filter differs'):
                        vm.validate_completion(self.output, 'ginkgo', 'this-run', self.manifest,
                                               expected)

    def test_ginkgo_filter_is_written_to_guest_input_before_boot(self):
        for index, label in enumerate(('', 'basic || smoke')):
            with self.subTest(label=label):
                work = self.output / f'work-{index}'
                output = self.output / f'output-{index}'
                work.mkdir()
                output.mkdir()
                process = Mock()
                process.poll.return_value = 0

                def boot(*args, **kwargs):
                    self.assertEqual((work / 'target/ginkgo-label').read_text(), label)
                    return process

                with patch('vm.subprocess.run'), patch('vm.subprocess.Popen', side_effect=boot), \
                        ExitStack() as stack:
                    vm.launch(stack, self.output, work, output, 'target', 'ginkgo',
                              'this-run', 'tcg', ginkgo_label=label)


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / 'image'
        self.image.mkdir()
        self.output = self.root / 'results'

    def run_guest(self, mode, console=None, exit_code=0, completion='valid',
                  error=None, serial=None, ginkgo_label=''):
        manifest = dict(commit='a' * 40, suite=mode, kernel='test-kernel')
        (self.image / 'image.json').write_text(json.dumps(manifest))

        def launch(stack, image, work, output, role, guest_mode, token, accel, network,
                   ginkgo_label=''):
            directory = output / role
            directory.mkdir()
            if network:
                network.touch()
            (output / f'{role}.serial.log').write_text((serial or {}).get(role, 'boot log\n'))
            if role == 'target':
                if console is not None:
                    (directory / 'tests.log').write_bytes(console)
                if completion == 'valid':
                    (directory / 'completion.json').write_text(json.dumps(dict(
                        manifest, mode=mode, token=token, exit_code=exit_code,
                        running_kernel=manifest['kernel'])))
                elif completion == 'malformed':
                    (directory / 'completion.json').write_text('{')
                if mode == 'kunit':
                    report = directory / 'kunit/run/result.json'
                    report.parent.mkdir(parents=True)
                    report.write_text(json.dumps(dict(status='PASS', counts=dict(passed=2),
                                                      not_run_suites=[], module_state='unloaded')))
                else:
                    for transport in ('local', 'iscsi'):
                        report = directory / 'ginkgo' / transport / 'report.json'
                        report.parent.mkdir(parents=True)
                        report.write_text(json.dumps([dict(
                            SuiteSucceeded=True, PreRunStats=dict(SpecsThatWillRun=2),
                            SuiteConfig=dict(LabelFilter=ginkgo_label),
                            SpecReports=[dict(LeafNodeType='It', State='passed')])]))
            return Mock()

        stdout = io.StringIO()
        with patch('vm.launch', side_effect=launch), patch('vm.configure_ssh'), \
                patch('vm.wait_guest', side_effect=error), redirect_stdout(stdout):
            result = vm.run(self.image, self.output, mode, 10, 'tcg', ginkgo_label)
        self.assertEqual(json.loads((self.output / 'result.json').read_text()), result)
        if console is not None:
            self.assertEqual((self.output / 'target/tests.log').read_bytes(), console)
        return result, stdout.getvalue()

    def test_kunit_success_prints_suites_and_counts(self):
        result, output = self.run_guest('kunit', console=(
            b'[PASS] scst-LIB\nTests: PASS - 2 passed, 0 failed, 1 skipped\nResult: PASS\n'))
        self.assertEqual(result['status'], 'PASS')
        self.assertIn('[PASS] scst-LIB', output)
        self.assertIn('2 passed, 0 failed, 1 skipped', output)
        self.assertIn('kunit: PASS', output)
        self.assertNotIn('boot log', output)

    def test_ginkgo_success_prints_both_transport_summaries(self):
        result, output = self.run_guest('ginkgo', console=(
            b'Running Suite: local\n2 Passed | 0 Failed\n'
            b'Running Suite: iSCSI\n2 Passed | 0 Failed\n'))
        self.assertEqual(result['status'], 'PASS')
        self.assertIn('Running Suite: local', output)
        self.assertIn('Running Suite: iSCSI', output)
        self.assertEqual(output.count('2 Passed | 0 Failed'), 2)
        self.assertIn('ginkgo: PASS', output)
        self.assertIn('Label filter: <all>', output)
        self.assertEqual(result['ginkgo_label'], '')

    def test_ginkgo_label_sets_reach_both_suites_and_are_reported(self):
        for label, expression in (('basic || smoke', 'basic || smoke'),
                                  ('ci-pr', 'basic || smoke'), ('ci-push', '!race')):
            with self.subTest(label=label):
                self.output = self.root / label
                result, output = self.run_guest('ginkgo', ginkgo_label=label)
                self.assertEqual(result['status'], 'PASS')
                self.assertEqual(result['ginkgo_label'], expression)
                self.assertIn(f'Label filter: {expression}', output)

    def test_failed_tests_print_assertions_and_preserve_failed_verdict(self):
        for mode in ('kunit', 'ginkgo'):
            with self.subTest(mode=mode):
                self.output = self.root / mode
                result, output = self.run_guest(mode, exit_code=1, console=(
                    b'[FAIL] failing_test\nExpected 2 to equal 3\n'))
                self.assertEqual(result['status'], 'ERROR')
                self.assertIn('failing_test', output)
                self.assertIn('Expected 2 to equal 3', output)
                self.assertIn('Error: guest failed', output)
                self.assertIn(f'{mode}: ERROR', output)

    def test_crash_before_tests_prints_diagnostics_without_a_guest_report(self):
        serial = '[1.0] Kernel panic - not syncing: test crash\n' + 'noise\n' * 100
        result, output = self.run_guest('kunit', completion='missing', serial={'target': serial})
        self.assertEqual(result['status'], 'ERROR')
        self.assertIn('No guest test output was saved', output)
        self.assertIn('missing or invalid guest completion report', output)
        self.assertIn('Kernel panic - not syncing: test crash', output)
        self.assertEqual((self.output / 'target.serial.log').read_text(), serial)

    def test_malformed_completion_does_not_hide_partial_test_output(self):
        result, output = self.run_guest('kunit', completion='malformed',
                                        console=b'[PASS] scst-LIB\npartial \xff')
        self.assertEqual(result['status'], 'ERROR')
        self.assertIn('[PASS] scst-LIB', output)
        self.assertIn('partial \ufffd', output)
        self.assertIn('missing or invalid guest completion report', output)

    def test_timeout_prints_bounded_tails_from_both_guests(self):
        serial = {'target': 'early boot\n' + 'x' * 70000 + '\n' + 'progress\n' * 100,
                  'initiator': 'initiator connection lost\n'}
        result, output = self.run_guest('ginkgo', console=b'Running Suite: local\n',
                                        error=vm.VMError('guest deadline expired'), serial=serial)
        self.assertEqual(result['status'], 'ERROR')
        self.assertIn('Running Suite: local', output)
        self.assertIn('guest deadline expired', output)
        self.assertIn('target.serial.log: last 80 lines', output)
        self.assertIn('initiator.serial.log: last 80 lines', output)
        self.assertIn('initiator connection lost', output)
        self.assertNotIn('early boot', output)
        self.assertEqual(output.count('  progress\n'), 80)
        self.assertLess(len(output), 2000)
        for role, log in serial.items():
            self.assertEqual((self.output / f'{role}.serial.log').read_text(), log)


if __name__ == '__main__':
    unittest.main()
