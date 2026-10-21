# SPDX-License-Identifier: GPL-2.0-only
"""Check that generated kernel patches retain only ordinary SCST code."""

from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GeneratorTests(unittest.TestCase):
    def specialize(self, source, version, blank, variables=()):
        patch = ('--- /dev/null\t2026-10-21\n'
                 '+++ linux/drivers/scst/probe.c\t2026-10-21\n'
                 f'@@ -0,0 +1,{len(source)} @@\n' +
                 ''.join('+' + line + '\n' for line in source))
        command = [str(ROOT / 'scripts/kernel/specialize-patch'),
                   '-v', 'kernel_version=' + version,
                   '-v', f'blank_deleted_code={blank}']
        for variable in variables:
            command.extend(['-v', variable])
        result = subprocess.run(command, input=patch, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Applying the patch also verifies its rewritten hunk counts.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'drivers/scst').mkdir(parents=True)
            applied = subprocess.run(
                ['patch', '--batch', '-s', '-p1', '-d', str(root)],
                input=result.stdout, capture_output=True, text=True)
            self.assertEqual(applied.returncode, 0,
                             applied.stdout + applied.stderr + result.stdout)
            output = (root / 'drivers/scst/probe.c').read_text().splitlines()
        return [line for line in output if line]

    def test_specialize_preserves_branch_selection_with_indented_directives(self):
        for version, branch in [('3.18', 'legacy'), ('7.3', 'modern')]:
            for indent, gap in [('', ''), (' ', ' '), ('\t', ''), ('\t ', ' \t')]:
                for blank in (0, 1):
                    with self.subTest(version=version, indent=indent, gap=gap, blank=blank):
                        directive = indent + '#' + gap
                        source = [
                            directive + 'if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)',
                            'int modern;',
                            directive + 'else',
                            'int legacy;',
                            directive + 'endif',
                            directive + 'ifdef CONFIG_SCST_SPECIALIZE_TEST',
                            directive + 'if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)',
                            'int nested_modern;',
                            directive + 'else',
                            'int nested_legacy;',
                            directive + 'endif',
                            directive + 'endif',
                            directive + 'if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)',
                            'int unsupported;',
                            directive + 'elif defined(CONFIG_SCST_SPECIALIZE_TEST)',
                            'int optional;',
                            directive + 'endif',
                            'int tail;',
                        ]
                        self.assertEqual(self.specialize(source, version, blank), [
                            f'int {branch};',
                            directive + 'ifdef CONFIG_SCST_SPECIALIZE_TEST',
                            f'int nested_{branch};',
                            directive + 'endif',
                            '#if defined(CONFIG_SCST_SPECIALIZE_TEST)',
                            'int optional;',
                            directive + 'endif',
                            'int tail;',
                        ])

    def test_specialize_selects_flush_api_with_vendor_arithmetic(self):
        # Match vdisk_blockio_flush(), including its continued conditions.
        source = [
            '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) && \\',
            '\t(!defined(RHEL_MAJOR) || RHEL_MAJOR - 0 < 8 || \\',
            '\t RHEL_MAJOR - 0 == 8 && RHEL_MINOR - 0 < 4)',
            'res = blkdev_issue_flush(bdev, gfp_mask, NULL);',
            '#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) && \\',
            '\t(!defined(RHEL_MAJOR) || RHEL_MAJOR - 0 < 8 || \\',
            '\t RHEL_MAJOR - 0 == 8 && RHEL_MINOR - 0 < 6)',
            'res = blkdev_issue_flush(bdev, gfp_mask);',
            '#else',
            'res = blkdev_issue_flush(bdev);',
            '#endif',
        ]
        cases = [
            ('3.18', (), 'bdev, gfp_mask, NULL'),
            ('5.7', (), 'bdev, gfp_mask, NULL'),
            ('5.8', (), 'bdev, gfp_mask'),
            ('5.11', (), 'bdev, gfp_mask'),
            ('5.12', (), 'bdev'),
            ('6.18.57', (), 'bdev'),
            ('7.3', (), 'bdev'),
            ('3.10', ('RHEL_MAJOR=7', 'RHEL_MINOR=9'), 'bdev, gfp_mask, NULL'),
            ('4.18', ('RHEL_MAJOR=8', 'RHEL_MINOR=3'), 'bdev, gfp_mask, NULL'),
            ('4.18', ('RHEL_MAJOR=8', 'RHEL_MINOR=4'), 'bdev, gfp_mask'),
            ('4.18', ('RHEL_MAJOR=8', 'RHEL_MINOR=5'), 'bdev, gfp_mask'),
            ('4.18', ('RHEL_MAJOR=8', 'RHEL_MINOR=6'), 'bdev'),
            ('5.14', ('RHEL_MAJOR=9', 'RHEL_MINOR=0'), 'bdev'),
        ]
        for version, variables, arguments in cases:
            for subtraction in ('-0', '- 0'):
                for blank in (0, 1):
                    with self.subTest(version=version, variables=variables,
                                      subtraction=subtraction, blank=blank):
                        fixture = [line.replace('- 0', subtraction) for line in source]
                        self.assertEqual(self.specialize(fixture, version, blank, variables),
                                         [f'res = blkdev_issue_flush({arguments});'])

    def test_specialize_treats_absent_vendor_versions_as_zero(self):
        for macro in ('RHEL_MAJOR', 'RHEL_MINOR', 'RHEL_RELEASE_CODE',
                      'MOFED_MAJOR', 'MOFED_MINOR'):
            for subtraction in ('', ' -0', ' - 0'):
                for blank in (0, 1):
                    with self.subTest(macro=macro, subtraction=subtraction, blank=blank):
                        source = [
                            f'#if defined({macro}) || {macro}{subtraction} != 0',
                            'int vendor;',
                            '#else',
                            'int upstream;',
                            '#endif',
                        ]
                        self.assertEqual(self.specialize(source, '6.18.57', blank),
                                         ['int upstream;'])

    def test_qla_helpers_resolve_siblings_but_keep_caller_outputs(self):
        with tempfile.TemporaryDirectory(prefix='qla helpers ') as tmp:
            root = Path(tmp)
            scripts = root / 'scripts' / 'kernel'
            scripts.mkdir(parents=True)
            driver = root / 'driver'
            driver.mkdir()
            for name in ('extract-qla2xxx-orig', 'generate-qla2xxx-in-tree-patches'):
                shutil.copy2(ROOT / 'scripts/kernel' / name, scripts / name)
            # Substitute only the downloader. Exercise both relocated scripts,
            # with an empty cache, without a network call or host cache access.
            (scripts / 'kernel-functions').write_text('''#!/bin/bash
download_and_extract_kernel_tree() {
    mkdir -p linux-7.3/drivers/scsi/qla2xxx linux-7.3/include/trace/events
    for name in Kconfig qla.c Makefile; do
        echo upstream > "linux-7.3/drivers/scsi/qla2xxx/$name"
    done
    echo upstream > linux-7.3/include/trace/events/qla.h
}
''')
            for name in ('Kconfig', 'qla.c', 'local.h', 'Makefile_in-tree',
                         'include/trace/events/qla.h'):
                path = driver / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('scst\n')
            result = subprocess.run([str(scripts / 'generate-qla2xxx-in-tree-patches'),
                                     '7.3^vendor'], cwd=driver, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            patches = driver / 'in-tree-patches' / '7.3'
            self.assertEqual({p.name for p in patches.iterdir()},
                             {'Kconfig.patch', 'qla.c.patch', 'local.h.patch',
                              'Makefile.patch', 'qla.h.patch'})
            for path in patches.iterdir():
                self.assertIn('+scst\n', path.read_text())
            self.assertIn('-upstream\n', (patches / 'qla.h.patch').read_text())
            self.assertIn('Makefile_in-tree', (patches / 'Makefile.patch').read_text())
            self.assertFalse((scripts / 'qla2xxx-orig').exists())
            self.assertFalse((driver / 'qla2xxx-orig/linux-7.3').exists())
            self.assertTrue((driver / 'qla2xxx-orig/7.3/include/trace/events/qla.h').is_file())

    def test_plain_kernel_patch_keeps_private_headers_without_test_builds(self):
        # Generate real SCST patches in an isolated source tree.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ignored = shutil.ignore_patterns('certs', '__pycache__', 'qla2xxx-orig',
                                             'in-tree-patches', '*.o', '*.ko', '*.cmd',
                                             '*.mod*', '*.priv', 'Module.symvers')
            for directory in ('scripts', 'scst', 'iscsi-scst', 'qla2x00t', 'qla2x00t-32gbit',
                              'srpt', 'fcst', 'scst_local', 'doc'):
                shutil.copytree(ROOT / directory, root / directory, ignore=ignored)
            # QLogic patch preparation downloads upstream kernel sources. It is
            # outside this SCST export check and must not depend on host caches.
            for name in ('qla2x00t/generate-in-tree-patches',
                         'scripts/kernel/generate-qla2xxx-in-tree-patches'):
                prepare = root / name
                prepare.write_text('#!/bin/sh\nexit 0\n')
                prepare.chmod(0o755)
            result = subprocess.run(['bash', 'scripts/kernel/generate-kernel-patch', '-s', '7.2'],
                                    cwd=root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        files = set(re.findall(r'^\+\+\+ linux-[^/]+/(\S+)', result.stdout, re.M))
        self.assertIn('drivers/scst/scst_main.c', files)
        self.assertNotIn('CONFIG_SCST_KUNIT_TEST', result.stdout)
        self.assertNotIn('CONFIG_SCST_KUNIT_LOG', result.stdout)
        self.assertFalse(any('/kunit/' in path for path in files))
        owners = {'scst/src': 'drivers/scst',
                  'scst/src/dev_handlers': 'drivers/scst/dev_handlers',
                  'iscsi-scst/kernel': 'drivers/scst/iscsi-scst',
                  'iscsi-scst/kernel/isert-scst': 'drivers/scst/iscsi-scst/isert-scst',
                  'qla2x00t-32gbit/qla2x00-target': 'drivers/scsi/qla2xxx'}
        for source_dir, target_dir in owners.items():
            for header in (ROOT / source_dir).glob('*_test.h'):
                self.assertIn(str(PurePosixPath(target_dir) / header.name), files)
            for source in (ROOT / source_dir).glob('*.[ch]'):
                self.assertNotRegex(source.read_text(), r'(?m)^#include "[^"\n]*kunit/', str(source))
        self.assertIn('drivers/scst/scst_test.h', files)


if __name__ == '__main__':
    unittest.main()
