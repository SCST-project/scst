# SPDX-License-Identifier: GPL-2.0-only
"""Build and execution selection checks using inert kernel and runner fixtures."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from inventory import source_suites

ROOT = Path(__file__).resolve().parents[2]
MODULES = re.findall(r'[\w/-]+\.ko', (ROOT / 'scst/src/kunit/modules.mk').read_text())
SOURCE_FILES = sorted({path for module in MODULES
                       for path in (ROOT / module).parent.joinpath('kunit').rglob('*.c')})
SUITES = source_suites(SOURCE_FILES)
LABELS = sorted(set(SUITES.values()))
ENTRY_POINTS = [entry for entry in ('', 'scst', 'scst/src', 'scst/src/dev_handlers', 'iscsi-scst')
                if 'kunit/select.mk' in (ROOT / entry / 'Makefile').read_text()]
OWNERS = {
    'scst': ('scst/src', 'scst/kernel/in-tree/Makefile.scst'),
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

    def test_make_lists_runtime_selection_without_config_flags(self):
        for selection, valid in [('', False), ('ALL', True), ('LIB LIB', True),
                                 ('UNKNOWN', False), ('ALL LIB', False), ('ALL ALL', False)]:
            for directory in ENTRY_POINTS:
                with self.subTest(selection=selection, directory=directory):
                    result = subprocess.run(['make', '-s', 'kunit-list', 'KUNIT_LABEL=' + selection],
                        cwd=ROOT / directory, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, valid, result.stderr)
                    if valid:
                        expected = ' '.join(LABELS) if selection == 'ALL' else ' '.join(sorted(set(selection.split())))
                        self.assertIn('Selected: ' + (expected or '(none)'), result.stdout)
                        self.assertNotIn('Flags:', result.stdout)


if __name__ == '__main__':
    unittest.main()
