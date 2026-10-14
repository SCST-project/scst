# SPDX-License-Identifier: GPL-2.0-only
"""Build and execution selection checks using inert kernel and runner fixtures."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from inventory import source_suites
from labels import load_composites

ROOT = Path(__file__).resolve().parents[2]
MODULES = re.findall(r'[\w/-]+\.ko', (ROOT / 'scst/src/kunit/modules.mk').read_text())
SOURCE_FILES = sorted({path for module in MODULES
                       for path in (ROOT / module).parent.joinpath('kunit').rglob('*.c')})
SUITES = source_suites(SOURCE_FILES)
LABELS = sorted(set(SUITES.values()) | load_composites().keys())
ENTRY_POINTS = [entry for entry in ('', 'scst', 'scst/src', 'scst/src/dev_handlers', 'iscsi-scst')
                if 'kunit/select.mk' in (ROOT / entry / 'Makefile').read_text()]
OWNERS = {
    'scst': ('scst/src', 'scst/kernel/in-tree/Makefile.scst'),
    'scst_vdisk': ('scst/src/dev_handlers', 'scst/kernel/in-tree/Makefile.dev_handlers'),
    'scst_user': ('scst/src/dev_handlers', 'scst/kernel/in-tree/Makefile.dev_handlers'),
    'iscsi-scst': ('iscsi-scst/kernel', 'iscsi-scst/kernel/Makefile.in-kernel'),
}


class SelectionTests(unittest.TestCase):
    def inspect_kbuild(self, owner, options, in_tree=False):
        directory, native = OWNERS[owner]
        directory = ROOT / directory
        entry = ROOT / native if in_tree else directory / 'Kbuild'
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            makefile = tmp / 'inspect.mk'
            makefile.write_text(f'src := {directory}\nsrctree := {tmp}\n'
                                f'include {entry}\n'
                                f'inspect:;@echo "objects=$({owner}-y) flags=$(ccflags-y)"\n')
            return subprocess.run(['make', '-s', '-f', str(makefile), 'inspect',
                                   'KBUILD_EXTMOD=' + ('' if in_tree else 'external'), *options],
                                  capture_output=True, text=True)

    def test_common_switch_links_all_owner_suites(self):
        observed = set()
        for owner in sorted(OWNERS):
            for enabled in ('y', 'n'):
                with self.subTest(owner=owner, enabled=enabled):
                    result = self.inspect_kbuild(owner, ['CONFIG_KUNIT=y',
                        'CONFIG_SCST_KUNIT_TEST=' + enabled])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    objects = result.stdout.split('objects=', 1)[1].split(' flags=', 1)[0].split()
                    tests = [obj for obj in objects if obj.startswith('kunit/')]
                    self.assertEqual(bool(tests), enabled == 'y')
                    for obj in tests:
                        source = ROOT / OWNERS[owner][0] / Path(obj).with_suffix('.c')
                        self.assertTrue(source.is_file(), source)
                        for suite, label in source_suites([source]).items():
                            self.assertEqual(SUITES[suite], label)
                            observed.add(suite)
                    if enabled == 'n':
                        self.assertNotIn('SCST_KUNIT_ENABLED', result.stdout)
        self.assertEqual(observed, set(SUITES))

    def test_logging_switch_preserves_suite_inventory(self):
        for owner in sorted(OWNERS):
            for tests in ('y', 'n'):
                outputs = []
                for log in ('y', 'n'):
                    result = self.inspect_kbuild(owner, ['CONFIG_KUNIT=y',
                        'CONFIG_SCST_KUNIT_TEST=' + tests, 'CONFIG_SCST_KUNIT_LOG=' + log])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    outputs.append(result.stdout.split(' flags=', 1)[0])
                    self.assertEqual('-DSCST_KUNIT_LOG_ENABLED=1' in result.stdout, tests == log == 'y')
                    self.assertEqual('-DSCST_KUNIT_LOG_ENABLED=0' in result.stdout, tests == 'y' and log == 'n')
                self.assertEqual(*outputs)

    def test_kernel_support_and_normal_build(self):
        for owner in sorted(OWNERS):
            for kunit in ('y', 'm', 'n', ''):
                with self.subTest(owner=owner, kunit=kunit):
                    result = self.inspect_kbuild(owner, ['CONFIG_SCST_KUNIT_TEST=y',
                                                        'CONFIG_KUNIT=' + kunit])
                    self.assertEqual(result.returncode == 0, kunit in ('y', 'm'), result.stderr)
            result = self.inspect_kbuild(owner, ['CONFIG_KUNIT=', 'CONFIG_SCST_KUNIT_TEST=n'])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('kunit/', result.stdout)

    def test_plain_in_tree_build_never_links_tests(self):
        for owner in sorted(OWNERS):
            with self.subTest(owner=owner):
                result = self.inspect_kbuild(owner, ['CONFIG_KUNIT=y',
                    'CONFIG_SCST_KUNIT_TEST=y', 'CONFIG_SCST_KUNIT_LOG=y'], in_tree=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('kunit/', result.stdout)
                self.assertNotIn('SCST_KUNIT_ENABLED', result.stdout)

    def test_runtime_labels_do_not_change_test_objects(self):
        for owner in sorted(OWNERS):
            baseline = self.inspect_kbuild(owner, ['CONFIG_KUNIT=y', 'CONFIG_SCST_KUNIT_TEST=y'])
            for label in LABELS:
                result = self.inspect_kbuild(owner, ['CONFIG_KUNIT=y', 'CONFIG_SCST_KUNIT_TEST=y',
                                                     'KUNIT_LABEL=' + label])
                self.assertEqual(result.stdout, baseline.stdout)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_kbuild_clean_does_not_require_kernel_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            makefile = Path(tmp) / 'Makefile.clean'
            makefile.write_text(f'src := {ROOT}/scst/src\n'
                                f'include {ROOT}/scst/src/Kbuild\n'
                                'inspect:;@:\n')
            result = subprocess.run(['make', '-s', '-f', str(makefile), 'inspect',
                                     'CONFIG_SCST_KUNIT_TEST=y', 'CONFIG_KUNIT=',
                                     'KBUILD_EXTMOD=external'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_make_lists_all_suites_regardless_of_runtime_labels(self):
        for selection in (None, '', 'ALL', 'LIB', 'LIB LIB', 'UNKNOWN', 'ALL LIB', 'ALL ALL'):
            for directory in ENTRY_POINTS:
                with self.subTest(selection=selection, directory=directory):
                    command = ['make', '-s', 'kunit-list']
                    if selection is not None:
                        command.append('KUNIT_LABEL=' + selection)
                    result = subprocess.run(command, cwd=ROOT / directory, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('Available KUNIT_LABEL: ' + ' '.join(LABELS) + ' ALL', result.stdout)
                    listed = {line.strip() for line in result.stdout.splitlines() if line.startswith('  ')}
                    self.assertTrue({f'{label}: {suite}' for suite, label in SUITES.items()} <= listed)
                    self.assertIn('Composite labels:', result.stdout)
                    self.assertIn('  IO: Command decoding, UNMAP and virtual disk checks', result.stdout)
                    self.assertNotIn('Selected', result.stdout)
                    self.assertNotIn('Flags:', result.stdout)

    def runner_arguments(self, *options, selection='LIB'):
        env = {key: value for key, value in os.environ.items()
               if key not in ('TEST', 'TEST_LOG', 'KUNIT_LABEL', 'MAKEFLAGS', 'MFLAGS')
               and not key.startswith('KUNIT_') and not key.endswith('_KUNIT_TEST')}
        if selection is not None:
            env['KUNIT_LABEL'] = selection
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / 'capture.py'
            capture.write_text('import json, sys\nprint(json.dumps(sys.argv[1:]))\n')
            result = subprocess.run(['make', '-s', 'kunit-run',
                f'PYTHON={sys.executable} {capture}', *options],
                cwd=ROOT, env=env, capture_output=True, text=True)
        return result, json.loads(result.stdout) if result.returncode == 0 else []

    def test_list_and_run_accept_the_same_label_configuration(self):
        with tempfile.TemporaryDirectory(prefix='kunit labels ') as tmp:
            config = Path(tmp) / 'custom labels.toml'
            config.write_text('[CAPACITY]\nsuites = ["scst-VDISK-capacity"]\n')
            option = f'KUNIT_ARGS=--label-config "{config}"'
            result = subprocess.run(['make', '-s', 'kunit-list', 'KUNIT_LABEL=UNKNOWN', option],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('CAPACITY', result.stdout.splitlines()[1])
            self.assertNotIn('Selected', result.stdout)
            self.assertTrue(result.stdout.endswith('  CAPACITY:\n    scst-VDISK-capacity\n'))
            result, args = self.runner_arguments(option, selection='CAPACITY')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(args, ['scripts/kunit/run.py', '--labels', 'CAPACITY',
                                    '--label-config', str(config)])

    def test_runner_defaults_to_all_and_receives_explicit_labels(self):
        result, args = self.runner_arguments(selection=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ['scripts/kunit/run.py', '--labels', 'ALL'])
        # Runtime validation uses the supplied modules, not this source tree.
        for selection in ('LIB', 'ALL', 'LIB LIB', '', 'UNKNOWN', 'ALL LIB'):
            result, args = self.runner_arguments(selection=selection)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(args, ['scripts/kunit/run.py', '--labels', selection])
        for option in ('STRESS=HT', 'PERF=HT'):
            result, args = self.runner_arguments(option, selection=None)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('not implemented', result.stderr)
            self.assertEqual(args, [])

    def test_runner_preserves_paths_and_extra_arguments(self):
        result, args = self.runner_arguments(
            'KUNIT_ARGS="/tmp/test modules/core.ko" "/tmp/test modules/handler.ko" '
            '--config "/tmp/test config.toml" --timeout 12 --verbose --output "run results"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ['scripts/kunit/run.py', '--labels', 'LIB',
            '/tmp/test modules/core.ko', '/tmp/test modules/handler.ko',
            '--config', '/tmp/test config.toml', '--timeout', '12', '--verbose',
            '--output', 'run results'])

    def test_obsolete_options_are_rejected_instead_of_silently_running_all(self):
        for option in ('TEST=LIB', 'KUNIT_LABELS=LIB', 'TEST_LOG=y', 'KUNIT_MODULE=/tmp/core.ko',
                       'KUNIT_MODULES=/tmp/core.ko', 'KUNIT_VERBOSE=y',
                       'KUNIT_CONFIG=test.toml', 'KUNIT_TIMEOUT=1', 'KUNIT_OUTPUT=logs'):
            result, _ = self.runner_arguments(option, selection=None)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Use KUNIT_LABEL and KUNIT_ARGS', result.stderr)

    def build_components(self, *options, fail='', goals=('kunit-build',), selection=None,
                         uid='1000', missing=False, run_status=0):
        # Exercise real component recipes against an inert kernel Makefile.
        # All generated headers, module stand-ins and runner records stay here.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = ['Makefile', 'scst/Makefile', 'scst/src/Makefile',
                     'scst/src/kunit/modules.mk', 'scst/src/kunit/select.mk',
                     'scripts/kunit/inventory.py', 'scripts/kunit/labels.py', 'scripts/kunit/labels.toml',
                     'scst/include/scst.h', 'scst/include/scst_const.h',
                     'scst/include/scst_user.h', 'iscsi-scst/Makefile',
                     'iscsi-scst/include/iscsi_scst.h',
                     'iscsi-scst/conftest/sock_recvmsg/sock_recvmsg.c',
                     'iscsi-scst/conftest/sock_recvmsg/Kbuild']
            for path in paths:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                if (ROOT / path).is_file():
                    shutil.copyfile(ROOT / path, target)
            (root / 'scst/src/dev_handlers').mkdir()
            (root / 'scst/src/certs').mkdir()
            (root / 'scst/src/certs/Makefile').write_text('all:;@:\n')
            (root / 'iscsi-scst/kernel').mkdir()
            for path in SOURCE_FILES:
                target = root / path.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
            (root / 'iscsi-scst/conftest/sock_recvmsg/result-kunit-build-test.txt').write_text(
                '-DSOCK_RECVMSG_HAS_FOUR_ARGS=0\n')
            kdir = root / 'kernel'
            (kdir / 'include/config').mkdir(parents=True)
            (kdir / 'include/config/kernel.release').write_text('kunit-build-test\n')
            fields = ['$(patsubst $(KUNIT_TEST_ROOT)/%,%,$(M))', '$(KUNIT_LABEL)', '$(KDIR)',
                      '$(KVER)', '$(ARCH)', '$(CROSS_COMPILE)', '$(CC)',
                      '$(PASS_CC_TO_MAKE)', '$(WERROR)']
            fields += ['$(CONFIG_SCST_KUNIT_TEST)', '$(CONFIG_SCST_KUNIT_LOG)']
            fields += ['$@']
            (kdir / 'Makefile').write_text(
                '.PHONY: all scst.ko scst_vdisk.ko scst_user.ko iscsi-scst.ko\n'
                'all scst.ko scst_vdisk.ko scst_user.ko iscsi-scst.ko:\n'
                '\t@test "$(M)" = "$(KUNIT_TEST_ROOT)/scst/src" || '
                'test -f "$(KUNIT_TEST_ROOT)/scst/src/Module.symvers"\n'
                "\t@printf '%s\\n' '" + '|'.join(fields) + "' >> \"$${KUNIT_TEST_LOG}\"\n" +
                '\t@echo build >> "$${KUNIT_TEST_EVENTS}"\n'
                '\t@test "$(FAIL_COMPONENT)" != "$(M:$(KUNIT_TEST_ROOT)/%=%)"\n'
                '\t@touch "$(M)/Module.symvers"\n'
                '\t@if [ "$(MISSING_MODULE)" != y ]; then touch "$(M)/$@"; fi\n')
            binary = root / 'bin'
            binary.mkdir()
            scripts = {
                'id': '#!/bin/sh\nprintf "%s\\n" "$KUNIT_TEST_UID"\n',
                'sudo': '#!/bin/sh\necho sudo >> "$KUNIT_TEST_EVENTS"\nexec "$@"\n',
                'runner': f'#!{sys.executable}\nimport json, os, pathlib, sys\n'
                          'if sys.argv[1].endswith("inventory.py"):\n'
                          '    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])\n'
                          'with open(os.environ["KUNIT_TEST_EVENTS"], "a") as log:\n'
                          '    log.write("runner\\n")\n'
                          'pathlib.Path(os.environ["KUNIT_TEST_ARGS"]).write_text('
                          'json.dumps(sys.argv[1:]))\n'
                          'sys.exit(int(os.environ["KUNIT_TEST_RUN_STATUS"]))\n',
            }
            for name, source in scripts.items():
                target = binary / name
                target.write_text(source)
                target.chmod(0o755)
            records, events, args = root / 'build.log', root / 'events.log', root / 'args.json'
            module_list = root / '.kunit-modules'
            module_list.write_text('old.ko\n')
            env = {key: value for key, value in os.environ.items()
                   if key not in ('TEST', 'TEST_LOG', 'KUNIT_LABEL', 'MAKEFLAGS', 'MFLAGS', 'KDIR', 'KVER', 'STRESS', 'PERF')
                   and not key.startswith('KUNIT_') and not key.endswith('_KUNIT_TEST')}
            env.update(PATH=str(binary) + os.pathsep + env['PATH'],
                       KUNIT_TEST_ROOT=str(root), KUNIT_TEST_LOG=str(records),
                       KUNIT_TEST_EVENTS=str(events), KUNIT_TEST_ARGS=str(args),
                       KUNIT_TEST_UID=uid, KUNIT_TEST_RUN_STATUS=str(run_status))
            if selection is not None:
                env['KUNIT_LABEL'] = selection
            result = subprocess.run(['make', '-s', '-j4', *goals, 'KDIR=' + str(kdir),
                                     'ARCH=arm64', 'CROSS_COMPILE=aarch64-linux-gnu-',
                                     'CC=clang', 'PASS_CC_TO_MAKE=y', 'WERROR=y',
                                     'OFED_FLAVOR=in-tree', 'OFED_KERNEL_IB_DEVEL_RPM_INSTALLED=false',
                                     'OFED_COMPAT_RDMA_DEVEL_RPM_INSTALLED=false',
                                     'PYTHON=' + str(binary / 'runner'),
                                     'FAIL_COMPONENT=' + fail,
                                     'MISSING_MODULE=' + ('y' if missing else 'n'), *options],
                                    cwd=root, env=env, capture_output=True, text=True)
            rows = ([line.split('|') for line in records.read_text().splitlines()]
                    if records.exists() else [])
            for row in rows:
                self.assertEqual(row[2:9], [str(kdir), 'kunit-build-test', 'arm64',
                                           'aarch64-linux-gnu-', 'clang', 'y', 'y'])
            modules = module_list.read_text().splitlines() if module_list.exists() else None
            operations = events.read_text().splitlines() if events.exists() else []
            arguments = json.loads(args.read_text()) if args.exists() else []
            return result, rows, modules, operations, arguments

    def assert_full_build(self, result, rows, modules):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(modules, MODULES)
        self.assertEqual(rows[0][0], 'scst/src')
        self.assertEqual(rows[0][-1], 'scst.ko')
        self.assertEqual(sorted(row[0] + '/' + row[-1] for row in rows), sorted(MODULES))
        self.assertTrue(all(row[9] == 'y' for row in rows), rows)

    def test_full_build_for_root_and_regular_user(self):
        for uid in ('0', '1000'):
            result, rows, modules, events, args = self.build_components(uid=uid)
            self.assert_full_build(result, rows, modules)
            self.assertNotIn('sudo', events)
            self.assertFalse(args)

    def test_labels_do_not_limit_build(self):
        for selection in ('LIB', 'ALL', ''):
            result, rows, modules, _, _ = self.build_components('KUNIT_LABEL=' + selection)
            self.assert_full_build(result, rows, modules)

    def test_normal_build_keeps_tests_disabled(self):
        for selection in (None, 'LIB'):
            result, rows, _, events, _ = self.build_components(goals=('scst',), selection=selection)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(rows)
            self.assertTrue(all(row[9] == 'n' for row in rows))
            self.assertNotIn('sudo', events)

    def test_public_build_and_logging_options_reach_all_owners(self):
        for enabled in ('y', 'n'):
            result, rows, modules, _, _ = self.build_components('KUNIT_LOG=' + enabled)
            self.assert_full_build(result, rows, modules)
            self.assertTrue(all(row[10] == enabled for row in rows), rows)
        result, rows, _, _, _ = self.build_components('KUNIT_TEST=y', 'KUNIT_LOG=y', goals=('scst',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(rows)
        self.assertTrue(all(row[9:11] == ['y', 'y'] for row in rows), rows)

    def test_invalid_build_switch_and_categories(self):
        for option in ('KUNIT_TEST=n', 'KUNIT_TEST=bad', 'KUNIT_TEST=', 'KUNIT_LOG=bad', 'KUNIT_LOG=', 'STRESS=HT', 'PERF=HT'):
            result, rows, _, events, _ = self.build_components(option)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(rows, [])
            self.assertEqual(events, [])

    def test_run_does_not_build_or_elevate(self):
        for uid in ('1000', '0'):
            result, rows, _, events, args = self.build_components('KUNIT_LABEL=LIB', goals=('kunit-run',), uid=uid)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(rows, [])
            self.assertEqual(events, ['runner'])
            self.assertEqual(args, ['scripts/kunit/run.py', '--labels', 'LIB'])

    def test_combined_target_orders_full_build_and_selected_execution(self):
        for uid in ('0', '1000'):
            result, rows, modules, events, args = self.build_components('KUNIT_LABEL=LIB',
                'KUNIT_ARGS="/tmp/test modules/core.ko" --output "run results"',
                goals=('kunit-test',), uid=uid)
            self.assert_full_build(result, rows, modules)
            self.assertEqual(events, ['build'] * len(rows) + ['runner'])
            self.assertEqual(args, ['scripts/kunit/run.py', '--labels', 'LIB', '/tmp/test modules/core.ko',
                                    '--output', 'run results'])

    def test_combined_target_leaves_label_validation_to_runner(self):
        for selection in ('', 'UNKNOWN'):
            result, rows, modules, events, args = self.build_components(
                goals=('kunit-test',), selection=selection, run_status=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(modules)
            self.assertTrue(rows)
            self.assertEqual(events, ['build'] * len(rows) + ['runner'])
            self.assertEqual(args, ['scripts/kunit/run.py', '--labels', selection])

    def test_combined_target_defaults_to_all_after_successful_build(self):
        result, rows, modules, events, args = self.build_components(goals=('kunit-test',))
        self.assert_full_build(result, rows, modules)
        self.assertEqual(events, ['build'] * len(rows) + ['runner'])
        self.assertEqual(args, ['scripts/kunit/run.py', '--labels', 'ALL'])

    def test_failed_or_incomplete_build_prevents_execution(self):
        for options in ({'fail': 'scst/src'}, {'missing': True}):
            result, _, modules, events, args = self.build_components('KUNIT_LABEL=LIB', goals=('kunit-test',), **options)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(modules)
            self.assertNotIn('sudo', events)
            self.assertFalse(args)

    def test_runner_failure_propagates(self):
        result, _, _, events, _ = self.build_components('KUNIT_LABEL=LIB', goals=('kunit-test',), run_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events[-1], 'runner')
        self.assertNotIn('sudo', events)


if __name__ == '__main__':
    unittest.main()
