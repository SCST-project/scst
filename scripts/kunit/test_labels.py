# SPDX-License-Identifier: GPL-2.0-only
"""Composite selection checks using source/module inventories, without a kernel."""

from pathlib import Path
import tempfile
import unittest

from labels import expand_labels, load_composites


class LabelTests(unittest.TestCase):
    SUITES = {'scst-CDB': 'CDB', 'scst-LIB': 'LIB', 'scst-VDISK-capacity': 'VDISK',
              'scst-VDISK-io': 'VDISK', 'scst-VDISK-sync': 'VDISK'}

    def load(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'labels.toml'
            path.write_text(text)
            return load_composites(path)

    def test_union_preserves_inventory_order_and_deduplicates(self):
        composites = self.load('''
[IO]
description = "Command and virtual disk checks"
labels = ["VDISK", "CDB", "CDB"]
suites = ["scst-VDISK-io"]
[CAPACITY]
suites = ["scst-VDISK-capacity"]
''')
        self.assertEqual(expand_labels(self.SUITES, ['IO', 'CAPACITY', 'VDISK'], composites),
                         ['scst-CDB', 'scst-VDISK-capacity', 'scst-VDISK-io', 'scst-VDISK-sync'])
        self.assertEqual(expand_labels(self.SUITES, ['CAPACITY'], composites), ['scst-VDISK-capacity'])
        self.assertEqual(expand_labels(self.SUITES, ['ALL'], composites), list(self.SUITES))
        self.assertEqual(expand_labels(self.SUITES, ['LIB'], composites), ['scst-LIB'])

    def test_base_labels_need_no_configuration(self):
        self.assertEqual(self.load(''), {})
        self.assertEqual(expand_labels({'scst-NEW': 'NEW'}, ['NEW'], {}), ['scst-NEW'])

    def test_unknown_or_missing_members_never_select_a_partial_group(self):
        for definition in ('labels = ["CDB", "MISSING"]',
                           'suites = ["scst-CDB", "scst-missing"]'):
            composites = self.load('[IO]\n' + definition)
            for selected in (['IO'], ['LIB', 'IO']):
                with self.subTest(definition=definition, selected=selected), self.assertRaisesRegex(
                        ValueError, 'IO: .*absent'):
                    expand_labels(self.SUITES, selected, composites)
            # Unselected sets must not prevent a run using a subset of modules.
            self.assertEqual(expand_labels(self.SUITES, ['LIB'], composites), ['scst-LIB'])
            self.assertEqual(expand_labels(self.SUITES, ['ALL'], composites), list(self.SUITES))

    def test_namespace_conflicts_are_errors_even_for_all(self):
        composites = self.load('[VDISK]\nlabels = ["CDB"]')
        for selected in (['VDISK'], ['CDB'], ['ALL']):
            with self.subTest(selected=selected), self.assertRaisesRegex(ValueError, 'conflict'):
                expand_labels(self.SUITES, selected, composites)

    def test_invalid_configurations(self):
        for text in ('x = 1', '[ALL]\nlabels = ["CDB"]', '[lower]\nlabels = ["CDB"]',
                     '[IO]', '[IO]\nlabels = []\nsuites = []', '[IO]\nunknown = []',
                     '[IO]\nlabels = "CDB"', '[IO]\nlabels = [1]',
                     '[IO]\nsuites = [false]', '[IO]\nsuites = ["scst-*.case"]',
                     '[IO]\nsuites = ["../results"]', '[IO]\nlabels = ["ALL"]',
                     '[IO]\nlabels = ["IO"]', '[IO]\nlabels = ["OTHER"]\n[OTHER]\nlabels = ["CDB"]',
                     '[IO]\nlabels = ["CDB"]\ndescription = 1',
                     '[IO]\nlabels = ["CDB"]\ndescription = "line\\nline"',
                     '[IO]\nlabels = ["CDB"]\n[IO]\nlabels = ["LIB"]'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)

    def test_invalid_selections(self):
        for selected in ([], ['UNKNOWN'], ['ALL', 'LIB'], ['ALL', 'ALL']):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                expand_labels(self.SUITES, selected, {})


if __name__ == '__main__':
    unittest.main()
