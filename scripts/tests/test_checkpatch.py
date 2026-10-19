"""Checkpatch protocol fixtures without a kernel build or source rewrites."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from style.checkpatch import native_report


class CheckpatchTests(unittest.TestCase):
    def setUp(self):
        self.first = Path("/tmp/scst/first.c")
        self.second = Path("/tmp/scst/second.c")
        self.clean = ("total: 0 errors, 0 warnings, 0 checks, 1 lines checked\n"
                      f"{self.first} has no obvious style problems and is ready for submission.\n")
        self.warning = ("WARNING:SPDX_LICENSE_TAG: Missing SPDX tag\n"
                        "total: 0 errors, 1 warnings, 0 checks, 1 lines checked\n"
                        f"{self.first} has style problems, please review.\n")

    def test_completed_clean_file(self):
        report = native_report(self.clean, "", 0, [self.first])
        self.assertTrue(report["complete"])
        self.assertEqual(report["remaining"], 0)

    def test_source_warning_is_retained(self):
        report = native_report(self.warning, "", 1, [self.first])
        self.assertTrue(report["complete"])
        self.assertEqual(report["remaining"], 1)
        self.assertEqual(report["counts"], {"WARNING": 1})

    def test_unreadable_second_file_cannot_hide_behind_first_file(self):
        for status, text in ((0, self.clean), (1, self.warning)):
            with self.subTest(status=status):
                report = native_report(text, "diff: second.c: Permission denied", status,
                                       [self.first, self.second])
                self.assertFalse(report["complete"])
                self.assertTrue(any("native stderr" in item for item in report["failures"]))
                self.assertTrue(any("completion" in item for item in report["failures"]))

    def test_missing_duplicate_and_unknown_completions_fail(self):
        for text, files in ((self.clean, [self.first, self.second]),
                            (self.clean + self.clean, [self.first, self.second]),
                            (self.clean, [self.second]), ("", [self.first])):
            with self.subTest(text=text, files=files):
                self.assertFalse(native_report(text, "", 0, files)["complete"])

    def test_native_failure_and_unaccounted_diagnostics_fail(self):
        for text, stderr, status in ((self.clean, "Perl failed", 0), (self.clean, "", 2),
                                     (self.warning, "", 0), (self.clean, "", 1),
                                     (self.warning.replace("1 warnings", "0 warnings"), "", 1),
                                     (self.warning.split("\n", 1)[1], "", 1)):
            with self.subTest(text=text, stderr=stderr, status=status):
                self.assertFalse(native_report(text, stderr, status, [self.first])["complete"])


if __name__ == "__main__":
    unittest.main()
