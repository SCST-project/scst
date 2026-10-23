"""Reject incomplete suites and undeclared skips without native tools."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyzer_tests as driver


class AnalyzerTestsTests(unittest.TestCase):
    def test_known_skip_requires_exact_suite_test_reason_and_count(self):
        suite = "scripts/coccinelle/test_models.py"
        test = "NativeModelTests.test_current_kunit_suite_macro_retains_initializer"
        reason = "Coccinelle loses variadic macro arguments; awaiting an upstream fix"
        row = dict(state="passed", tests=2, failures=0, errors=0, skipped=1,
                   expected_failures=0, skip_details=[dict(test=test, reason=reason)])
        self.assertTrue(driver.passed(row, 0, suite))
        for other_suite in (None, "scripts/cppcheck/test_models.py"):
            with self.subTest(suite=other_suite):
                self.assertFalse(driver.passed(row, 0, other_suite))
        self.assertFalse(driver.passed(row, 1, suite))
        for change in (
            dict(skip_details=[]),
            dict(skip_details=[dict(test=test, reason="missing tool")]),
            dict(skip_details=[dict(test="NativeModelTests.test_other", reason=reason)]),
            dict(skip_details=[dict(test=test)]),
            dict(skip_details=None),
            dict(tests=3, skipped=2, skip_details=row["skip_details"] * 2),
            dict(skipped=0),
            dict(skipped=-1),
            dict(tests=1),
            dict(errors=1),
        ):
            with self.subTest(change=change):
                self.assertFalse(driver.passed({**row, **change}, 0, suite))

    def test_child_records_known_skip_and_keeps_other_tests_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "scripts/coccinelle/test_models.py"
            source.parent.mkdir(parents=True)
            result = root / "result.json"
            method = "test_current_kunit_suite_macro_retains_initializer"
            reason = "Coccinelle loses variadic macro arguments; awaiting an upstream fix"
            for body, status in (("pass", 0), ("self.fail('unrelated failure')", 1)):
                with self.subTest(body=body):
                    source.write_text(
                        "import unittest\nclass NativeModelTests(unittest.TestCase):\n"
                        f" @unittest.skip({reason!r})\n def {method}(self):\n"
                        "  self.fail('must not run while skipped')\n"
                        f" def test_unrelated(self):\n  {body}\n")
                    with patch.object(driver, "ROOT", root), \
                            patch.object(sys, "path", list(sys.path)), patch.dict(sys.modules), \
                            contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(driver.run_suite(source, result), status)
                    row = json.loads(result.read_text())
                    self.assertEqual(row["tests"], 2)
                    self.assertEqual(row["skipped"], 1)
                    self.assertEqual(row["skip_details"], [
                        dict(test="NativeModelTests." + method, reason=reason)])
                    self.assertEqual(driver.passed(row, status, source.relative_to(root).as_posix()),
                                     status == 0)

    def test_child_rejects_failures_skips_expected_failures_and_empty_suites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, result = root / "test_fixture.py", root / "result.json"
            cases = (
                ("self.assertTrue(True)", "", 0),
                ("self.fail('fixture failure')", "", 1),
                ("self.skipTest('missing tool')", "", 1),
                ("self.fail('known failure')", " @unittest.expectedFailure\n", 1),
            )

            def invoke():
                return subprocess.run([sys.executable, "-B", driver.__file__, "--suite",
                                       str(source), "--result", str(result)],
                                      capture_output=True, text=True, timeout=10)

            for body, decorator, status in cases:
                with self.subTest(body=body, decorator=decorator):
                    source.write_text("import unittest\nclass Fixture(unittest.TestCase):\n" +
                                      decorator + " def test_case(self):\n  " + body + "\n")
                    process = invoke()
                    self.assertEqual(process.returncode, status, process.stderr)
                    self.assertEqual(driver.passed(json.loads(result.read_text()), status),
                                     status == 0)
            for body in ("", "raise ImportError('missing dependency')", "raise SystemExit(0)"):
                with self.subTest(body=body):
                    source.write_text(body)
                    result.write_text('{"state":"passed","tests":1}')
                    process = invoke()
                    self.assertFalse(driver.passed(json.loads(result.read_text()), process.returncode))

    def test_failed_and_aborted_children_do_not_skip_later_suites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "scripts/tests"
            folder.mkdir(parents=True)
            files = []
            for index, body in enumerate(("self.fail('failure')", None, "self.assertTrue(True)")):
                path = folder / f"test_{index}.py"
                path.write_text("raise SystemExit(0)" if body is None else
                                "import unittest\nclass Fixture(unittest.TestCase):\n"
                                " def test_case(self):\n  " + body + "\n")
                files.append(path.relative_to(root).as_posix())
            with patch.object(driver, "suites", return_value=files), \
                    patch.object(driver, "prerequisites"), \
                    patch.dict(os.environ, GITHUB_STEP_SUMMARY=""), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(driver.execute(root), 1)
            report = json.loads(next((root / ".cache/lint").glob(
                "analyzer-tests-*/tests.json")).read_text())
            self.assertEqual(report["state"], "failed")
            self.assertEqual([row["state"] for row in report["suites"]],
                             ["failed", "failed", "passed"])

    def test_selection_only_includes_tracked_analyzer_suites(self):
        names = ("scripts/tests/test_a.py\0scripts/cppcheck/test_models.py\0"
                 "scripts/coccinelle/test_rules.py\0scripts/style/test_native.py\0"
                 "scripts/kunit/test_run.py\0scripts/scs_lint/test_scs_lint.py\0"
                 "scripts/cppcheck/fixtures/test_input.py\0scripts/local.py\0")
        with patch.object(driver.subprocess, "check_output", return_value=names):
            self.assertEqual(driver.suites(Path("/repo")), [
                "scripts/coccinelle/test_rules.py", "scripts/cppcheck/test_models.py",
                "scripts/style/test_native.py", "scripts/tests/test_a.py"])

    def test_missing_tools_fail_instead_of_skipping_native_tests(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(driver.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "Missing analyzer-test prerequisites:.*cppcheck"):
                driver.prerequisites({"KDIR": temporary})

    def test_environment_isolates_make_git_and_outer_reports(self):
        with patch.dict(os.environ, {"KDIR": "/selected/kernel", "GITHUB_ACTIONS": "true",
                                     "MAKEFLAGS": "--jobserver-auth=3,4", "GIT_DIR": "/outer/git",
                                     "SCST_LINT_RUN_ID": "outer", "LINT_DEFER_REPORTS": "1",
                                     "CPPCHECK_PROJECT": "/stale/commands.json"}, clear=True):
            env = driver.environment()
        self.assertEqual(env["SCST_LINT_KDIR"], "/selected/kernel")
        self.assertEqual(env["CHECKPATCH_PATH"], "/selected/kernel/scripts")
        for name in ("GITHUB_ACTIONS", "MAKEFLAGS", "GIT_DIR", "SCST_LINT_RUN_ID",
                     "LINT_DEFER_REPORTS", "CPPCHECK_PROJECT"):
            self.assertNotIn(name, env)


if __name__ == "__main__":
    unittest.main()
