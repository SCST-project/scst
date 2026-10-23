"""Native-log fixtures; no spatch, kernel build or SCST execution."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer_policy import read_policy, load_policy
from coccinelle.coccicheck import (COMPLETE, FINDING, STARTED, ROOT, coverage,
                                  publish_progress, rule_options)
from coccinelle.exceptions import source_exceptions
from coccinelle.compat import adapt


class CoccinelleTests(unittest.TestCase):
    def setUp(self):
        self.source = Path("/tmp/scst/timeout.c")
        self.log = f"{STARTED}\nHANDLING: {self.source}\ntrying timeout\n{COMPLETE}\n"

    def test_progress_is_not_a_timeout(self):
        result = coverage(self.log, [self.source], 0)
        self.assertTrue(result["complete"])
        self.assertEqual(result["findings"], 0)

    def test_namespace_report_adaptation_requires_exact_reviewed_rule(self):
        path = Path(__file__).with_name("fixtures") / "add_namespace.cocci"
        original = path.read_text()
        text, evidence = adapt(path, original)
        self.assertNotIn("declarer name MODULE_IMPORT_NS;", text)
        self.assertIn("@script:python depends on report@\n@@", text)
        self.assertTrue(evidence["changes"])
        for changed in (original + "\n", original.replace("// Dummy rule", "// Updated rule")):
            with self.subTest(changed=changed):
                text, evidence = adapt(path, changed)
                self.assertEqual(text, changed)
                self.assertFalse(evidence["changes"])

    def test_separate_rationale_requires_an_adjacent_comment(self):
        marker = "/* coccinelle-suppress mini_lock ; See the contract above. */\n"
        source = "/*\n * Return the caller-owned lock held.\n */\n" + marker + "return ret;\n"
        entry, = source_exceptions(source, "scst/a.c")
        self.assertEqual(entry["reason"], "Return the caller-owned lock held.")
        for prefix in ("", "/* Unrelated. */\nwork();\n", marker):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                source_exceptions(prefix + marker + "return ret;\n", "scst/a.c")

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

    def test_macro_limit_retains_evidence_and_requires_rule_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "scst/fixture.h"
            source.parent.mkdir()
            definition = "#define EACH(i) for (i = 0; i < 3; i++)"
            source.write_text(definition + "\n")
            error = (f"parse error\n = error in {source}; set verbose_parsing for more info\n"
                     f"badcount: 1\nBAD:!!!!! {definition}\n")
            log = f"{STARTED}\nHANDLING: {source}\n{error}{COMPLETE}\n"
            with patch('coccinelle.coccicheck.ROOT', root):
                result = coverage(log, [source], 0)
                self.assertTrue(result['complete'])
                self.assertEqual(result['findings'], 0)
                item, = result['coverage_limits']
                self.assertEqual((item['file'], item['name'], item['line']),
                                 ('scst/fixture.h', 'EACH', 1))
                self.assertEqual(item['excerpt'], error.splitlines())
                for broken, status in ((log, 1), (log.replace(COMPLETE, ''), 0),
                                       (log.replace(f'HANDLING: {source}\n', ''), 0),
                                       (log + 'parse error near invocation\n', 0)):
                    with self.subTest(log=broken, status=status):
                        self.assertFalse(coverage(broken, [source], status)['complete'])
                policy = dict(load_policy('coccicheck'), macro_definition_errors={
                    'enabled': False, 'reason': 'Strict fixture'})
                with patch('coccinelle.coccicheck.load_policy', return_value=policy):
                    self.assertFalse(coverage(log, [source], 0)['complete'])
            outside = root / 'qla2x00t/fixture.h'
            outside.parent.mkdir()
            outside.write_text(definition + '\n')
            with patch('coccinelle.coccicheck.ROOT', root):
                result = coverage(log.replace(str(source), str(outside)), [outside], 0)
                self.assertFalse(result['complete'])
                self.assertFalse(result['coverage_limits'])

    def test_rule_exception_does_not_excuse_a_parser_failure(self):
        source = ("/* coccinelle-suppress one_rule ; Reviewed ownership. */\ncall();\n")
        entries = source_exceptions(source, "fixture.c")
        log = self.log + f"{ROOT / 'fixture.c'}:2:1: finding\n{FINDING}\n"
        result = coverage(log, [self.source], 0, rule="one_rule", entries=entries)
        self.assertEqual((result["remaining"], result["ignored"]), (0, 1))
        self.assertTrue(result["complete"])
        self.assertFalse(coverage(log + "parse error\n", [self.source], 0,
                                  rule="one_rule", entries=entries)["complete"])
        self.assertEqual(coverage(log, [self.source], 0,
                                  rule="other_rule", entries=entries)["remaining"], 1)

    def test_rule_cannot_hide_logs_or_select_workers(self):
        self.assertEqual(rule_options("// Options: --quiet --include-headers"),
                         ["--include-headers"])
        for option in ("--jobs=2", "--in-place", "--suffix=.new", "--dir=other", "-oout"):
            with self.subTest(option=option), self.assertRaises(ValueError):
                rule_options("// Options: " + option)

    def test_progress_record_identifies_the_run_and_current_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'progress.json'
            with patch.dict(os.environ, {'SCST_LINT_PROGRESS': str(path),
                                         'SCST_LINT_RUN_ID': 'current'}):
                publish_progress(12, 75, Path('/kernel/do_div.cocci'))
            self.assertEqual(json.loads(path.read_text()),
                             dict(run_id='current', current=12, total=75, rule='do_div.cocci'))
            self.assertFalse(path.with_suffix('.tmp').exists())

    def test_policy_rejects_unreviewed_diagnostic_filters(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            policy = dict(load_policy("coccicheck"))
            path.write_text(json.dumps(policy))
            self.assertEqual(read_policy(path, "coccicheck"), policy)
            for value in ({'enabled': 'yes', 'reason': 'fixture'},
                          {'enabled': True, 'reason': ''}, {'enabled': True}):
                path.write_text(json.dumps(dict(policy, macro_definition_errors=value)))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    read_policy(path, 'coccicheck')
            policy["source_exceptions"] = []
            path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):
                read_policy(path, "coccicheck")


if __name__ == "__main__":
    unittest.main()
