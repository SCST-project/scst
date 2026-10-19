"""Native-log fixtures; no spatch, kernel build or SCST execution."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer_policy import read_policy
from coccinelle.coccicheck import COMPLETE, FINDING, STARTED, coverage, rule_options


class CoccinelleTests(unittest.TestCase):
    def setUp(self):
        self.source = Path("/tmp/scst/timeout.c")
        self.log = f"{STARTED}\nHANDLING: {self.source}\ntrying timeout\n{COMPLETE}\n"

    def test_progress_is_not_a_timeout(self):
        result = coverage(self.log, [self.source], 0)
        self.assertTrue(result["complete"])
        self.assertEqual(result["findings"], 0)

    def test_zero_exit_does_not_hide_parser_failure(self):
        for diagnostic in ("parse error near token foo", "timeout (we abort): rule.cocci",
                           "EXN: Not_found", "module.py:10: SyntaxWarning: bad escape"):
            with self.subTest(diagnostic=diagnostic):
                self.assertFalse(coverage(self.log + diagnostic, [self.source], 0)["complete"])

    def test_native_exit_and_missing_coverage_fail(self):
        for log, status in ((self.log, 1), (self.log.replace(STARTED, ""), 0),
                            (self.log.replace(COMPLETE, ""), 0),
                            (self.log.replace("HANDLING: ", ""), 0)):
            with self.subTest(log=log, status=status):
                self.assertFalse(coverage(log, [self.source], status)["complete"])

    def test_rule_report_is_a_finding_not_a_tool_failure(self):
        result = coverage(self.log + f"{self.source}:8:1-3: WARNING: unused\n{FINDING}\n",
                          [self.source], 0)
        self.assertTrue(result["complete"])
        self.assertEqual(result["findings"], 1)

    def test_direct_report_without_hook_is_retained(self):
        self.assertEqual(coverage(self.log + f"{self.source}:8:1: unused\n",
                                  [self.source], 0)["findings"], 1)

    def test_rule_cannot_hide_logs_or_select_workers(self):
        self.assertEqual(rule_options("// Options: --quiet --include-headers"),
                         ["--include-headers"])
        for option in ("--jobs=2", "--in-place", "--suffix=.new", "--dir=other", "-oout"):
            with self.subTest(option=option), self.assertRaises(ValueError):
                rule_options("// Options: " + option)

    def test_basic_policy_rejects_diagnostic_filters(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            policy = {"version": 1, "notes": ["Native report rules."]}
            path.write_text(json.dumps(policy))
            self.assertEqual(read_policy(path, "coccicheck"), policy)
            policy["source_exceptions"] = []
            path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):
                read_policy(path, "coccicheck")


if __name__ == "__main__":
    unittest.main()
