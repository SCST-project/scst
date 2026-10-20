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
                  'qla2x00t-32gbit/qla2x00-target': 'drivers/scsi/qla2xxx'}
        for source_dir, target_dir in owners.items():
            for header in (ROOT / source_dir).glob('*_test.h'):
                self.assertIn(str(PurePosixPath(target_dir) / header.name), files)
            for source in (ROOT / source_dir).glob('*.[ch]'):
                self.assertNotRegex(source.read_text(), r'(?m)^#include "[^"\n]*kunit/', str(source))
        self.assertIn('drivers/scst/scst_test.h', files)


if __name__ == '__main__':
    unittest.main()
