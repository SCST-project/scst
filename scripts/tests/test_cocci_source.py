#!/usr/bin/env python3
"""Read current source definitions without accepting commented or ambiguous macros."""

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coccinelle.source import macros, single_definition


class SourceTests(unittest.TestCase):
    def tearDown(self):
        macros.cache_clear()

    def test_logical_definitions_keep_literals_and_source_positions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "fixture.h").write_text(
                '/*\n#define HIDDEN 1\n*/\n'
                '#define VALUE "text"\n'
                '#define EACH(i) \\\n for (i = 0; i < 3; i++)\n')
            entries = macros(root, "fixture.h")
            self.assertEqual([entry["name"] for entry in entries], ["VALUE", "EACH"])
            self.assertIsNone(entries[0]["parameters"])
            self.assertEqual(entries[0]["body"], '"text"')
            self.assertEqual(entries[1]["parameters"], "i")
            self.assertEqual((entries[1]["start"], entries[1]["end"]), (5, 6))
            self.assertEqual(entries[1]["body"], "for (i = 0; i < 3; i++)")
            with self.assertRaisesRegex(ValueError, "Missing Coccinelle macro"):
                single_definition(root, dict(file="fixture.h", name="HIDDEN"))

    def test_unterminated_continuation_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "fixture.h").write_text("#define BROKEN \\\n")
            with self.assertRaisesRegex(ValueError, "Unterminated macro continuation"):
                macros(root, "fixture.h")


if __name__ == "__main__":
    unittest.main()
