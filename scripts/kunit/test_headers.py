# SPDX-License-Identifier: GPL-2.0-only
"""Keep test access declarations out of ordinary SCST compilation."""

from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HeaderTests(unittest.TestCase):
    def test_normal_headers_do_not_require_kernel_or_test_types(self):
        directories = ('scst/src', 'scst/src/dev_handlers', 'iscsi-scst/kernel',
                       'qla2x00t-32gbit/qla2x00-target')
        headers = sorted(header for directory in directories
                         for header in (ROOT / directory).glob('*_test.h'))
        self.assertTrue(headers)
        source = ''.join(f'#include "{header}"\n' for header in headers)
        # Kernel KUnit support alone must not expose SCST test declarations.
        for options in ([], ['-DCONFIG_KUNIT=1'], ['-DCONFIG_KUNIT_MODULE=1']):
            with self.subTest(options=options):
                result = subprocess.run(['cc', '-E', '-P', '-x', 'c', *options, '-'],
                                        input=source, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), '')


if __name__ == '__main__':
    unittest.main()
