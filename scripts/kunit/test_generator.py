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
            for directory in ('qla2x00t', 'qla2x00t-32gbit'):
                prepare = root / directory / 'generate-in-tree-patches'
                prepare.write_text('#!/bin/sh\nexit 0\n')
                prepare.chmod(0o755)
            result = subprocess.run(['bash', 'scripts/generate-kernel-patch', '-s', '7.2'],
                                    cwd=root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        files = set(re.findall(r'^\+\+\+ linux-[^/]+/(\S+)', result.stdout, re.M))
        self.assertIn('drivers/scst/scst_main.c', files)
        self.assertNotIn('CONFIG_SCST_KUNIT_TEST', result.stdout)
        self.assertNotIn('CONFIG_SCST_KUNIT_LOG', result.stdout)
        self.assertFalse(any('/kunit/' in path for path in files))
        owners = {'scst/src': 'drivers/scst',
                  'scst/src/dev_handlers': 'drivers/scst/dev_handlers',
                  'iscsi-scst/kernel': 'drivers/scst/iscsi-scst'}
        for source_dir, target_dir in owners.items():
            for header in (ROOT / source_dir).glob('*_test.h'):
                self.assertIn(str(PurePosixPath(target_dir) / header.name), files)
            for source in (ROOT / source_dir).glob('*.[ch]'):
                self.assertNotRegex(source.read_text(), r'(?m)^#include "[^"\n]*kunit/', str(source))
        self.assertIn('drivers/scst/scst_test.h', files)


if __name__ == '__main__':
    unittest.main()
