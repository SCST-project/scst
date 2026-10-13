# SPDX-License-Identifier: GPL-2.0-only
"""Source discovery must work before building and without kernel access."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from inventory import source_suites


class SourceInventoryTests(unittest.TestCase):
    def test_commented_registrations_do_not_add_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'suite.c'
            path.write_text('''/*
scst_kunit_suite(example, "EXAMPLE", "", .test_cases = cases);
*/
// scst_kunit_suite(old, "OLD", "", .test_cases = cases);
scst_kunit_suite(actual, /* label */ "LIB", "", .test_cases = cases);
''')
            self.assertEqual(source_suites([path]), {'scst-LIB': 'LIB'})

    def test_new_labels_are_discovered_without_a_registry_or_module(self):
        with tempfile.TemporaryDirectory(prefix='kunit sources ') as tmp:
            root = Path(tmp)
            (root / 'suite.c').write_text('''
scst_kunit_suite(example, "NEW_LABEL", "-boundary",
    .test_cases = cases,
);
scst_kunit_suite(second, "NEW_LABEL", "", .test_cases = other_cases);
''')
            self.assertEqual(source_suites(root.glob('*.c')), {
                'scst-NEW_LABEL-boundary': 'NEW_LABEL', 'scst-NEW_LABEL': 'NEW_LABEL'})
            command = [sys.executable, str(Path(__file__).with_name('inventory.py')),
                       '--labels', 'NEW_LABEL', str(root)]
            result = subprocess.run(command, cwd=tmp, env=dict(os.environ, PATH=''),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Selected: NEW_LABEL', result.stdout)
            self.assertIn('scst-NEW_LABEL-boundary', result.stdout)

    def test_duplicate_names_and_reserved_labels_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'suite.c'
            for source in ('scst_kunit_suite(a, "ALL", "", .test_cases = cases);',
                           'scst_kunit_suite(a, "LIB", "", .test_cases = cases);\n'
                           'scst_kunit_suite(b, "LIB", "", .test_cases = cases);'):
                with self.subTest(source=source):
                    path.write_text(source)
                    with self.assertRaises(ValueError):
                        source_suites([path])


if __name__ == '__main__':
    unittest.main()
