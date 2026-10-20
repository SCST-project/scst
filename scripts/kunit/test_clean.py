# SPDX-License-Identifier: GPL-2.0-only
"""Exercise cleanup recipes in temporary trees without touching real modules."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = next(line.split(':=', 1)[1].split()
                  for line in (ROOT / 'scst/src/kunit/modules.mk').read_text().splitlines()
                  if line.startswith('SCST_KUNIT_COMPONENTS := '))


class CleanTests(unittest.TestCase):
    def check_clean(self, directory, goal, fail=False, tooling=True):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path in ('Makefile', 'scst/Makefile', 'scst/src/Makefile',
                         'scst/src/dev_handlers/Makefile', 'scst/src/kunit/select.mk',
                         'scst/src/kunit/modules.mk', 'scst/include/scst_const.h',
                         'iscsi-scst/Makefile', 'iscsi-scst/usr/Makefile',
                         'qla2x00t-32gbit/Makefile',
                         'qla2x00t-32gbit/qla2x00-target/Makefile'):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, target)
            # Other components are deliberately inert; kunit-clean must not visit them.
            for component in ('srpt', 'scst_local', 'fcst', 'usr', 'scstadmin'):
                target = root / component
                target.mkdir(parents=True, exist_ok=True)
                (target / 'Makefile').write_text('clean extraclean:;@rm -f visited.o\n')
                (target / 'visited.o').touch()
            kernel = root / 'kernel'
            kernel.mkdir()
            (kernel / 'Makefile').write_text(
                'clean:\n'
                '\t@test "$(FAIL_CLEAN)" != y\n'
                '\t@find "$(M)" -type f \\( -name "*.o" -o -name "*.ko" \\) -delete\n')
            artifacts = ['scst/src/scst.ko', 'scst/src/kunit/lib/suites/test.o',
                         'scst/src/dev_handlers/scst_vdisk.ko',
                         'scst/src/dev_handlers/kunit/vdisk/suites/test.o',
                         'iscsi-scst/kernel/iscsi-scst.ko',
                         'iscsi-scst/kernel/kunit/suites/test.o',
                         'qla2x00t-32gbit/qla2xxx_scst.ko',
                         'qla2x00t-32gbit/qla_os.o',
                         'qla2x00t-32gbit/qla2x00-target/qla2x00tgt.ko',
                         'qla2x00t-32gbit/qla2x00-target/kunit/suites/test.o']
            metadata = ['.kunit-modules', '.kunit-modules.tmp']
            if tooling:
                metadata += ['scripts/kunit/__pycache__/run.pyc',
                             'scripts/kunit/upstream/__pycache__/kunit_parser.pyc']
            generated = ['scst/include/build_mode.h', 'scst/include/build_mode.h.tmp',
                         'scst/include/scst_itf_ver.h',
                         'iscsi-scst/include/iscsi_scst_itf_ver.h',
                         'iscsi-scst/conftest/sock_recvmsg/result-test.txt']
            preserved = ['.kunit-run.toml', 'kunit-results/run/report.txt',
                         'scst/build_mode', 'scst/src/kunit/lib/suites/test.c']
            for path in artifacts + metadata + generated + preserved:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('preserve me\n' if path in preserved else '')
            env = {key: value for key, value in os.environ.items()
                   if key not in ('MAKEFLAGS', 'MFLAGS', 'KDIR', 'KVER')
                   and not key.startswith(('KUNIT_', 'CONFIG_SCST_KUNIT_'))}
            result = subprocess.run(['make', '-s', '-j4', '-C', str(root / directory), goal,
                                     'KDIR=' + str(kernel), 'KVER=test',
                                     'FAIL_CLEAN=' + ('y' if fail else 'n'),
                                     'OFED_FLAVOR=in-tree',
                                     'OFED_KERNEL_IB_DEVEL_RPM_INSTALLED=false',
                                     'OFED_COMPAT_RDMA_DEVEL_RPM_INSTALLED=false'],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, not fail, result.stdout + result.stderr)
            for path in metadata:
                self.assertFalse((root / path).exists(), path)
            if not tooling:
                self.assertFalse((root / 'scripts').exists())
            for path in preserved:
                self.assertEqual((root / path).read_text(), 'preserve me\n', path)
            if not fail and directory == '' and goal in ('clean', 'extraclean', 'kunit-clean'):
                for path in artifacts + generated:
                    self.assertFalse((root / path).exists(), path)
            if goal == 'kunit-clean':
                self.assertTrue((root / 'srpt/visited.o').exists())

    def test_top_level_cleanup_removes_build_state_and_preserves_reports(self):
        for goal in ('kunit-clean', 'clean', 'extraclean'):
            with self.subTest(goal=goal):
                self.check_clean('', goal)

    def test_component_cleanup_invalidates_module_list(self):
        for directory in ('scst', 'scst/src', 'scst/src/dev_handlers', 'iscsi-scst',
                          'qla2x00t-32gbit/qla2x00-target'):
            if directory != 'scst' and 'kunit/select.mk' not in (ROOT / directory / 'Makefile').read_text():
                continue
            for goal in ('clean', 'extraclean'):
                with self.subTest(directory=directory, goal=goal):
                    self.check_clean(directory, goal)
        for goal in ('scst_clean', 'scst_extraclean', 'iscsi_clean', 'iscsi_extraclean'):
            if goal.startswith('iscsi_') and 'iscsi-scst' not in COMPONENTS:
                continue
            with self.subTest(goal=goal):
                self.check_clean('', goal)

    def test_failed_cleanup_still_invalidates_module_list(self):
        self.check_clean('', 'kunit-clean', fail=True)

    def test_cleanup_without_packaged_tooling(self):
        # Debian DKMS ships module sources without the scripts/ directory.
        for directory in ('', 'scst', 'scst/src', 'iscsi-scst'):
            if directory and 'kunit/select.mk' not in (ROOT / directory / 'Makefile').read_text():
                continue
            for goal in ('clean', 'extraclean'):
                with self.subTest(directory=directory, goal=goal):
                    self.check_clean(directory, goal, tooling=False)
        self.check_clean('', 'kunit-clean', tooling=False)


if __name__ == '__main__':
    unittest.main()
