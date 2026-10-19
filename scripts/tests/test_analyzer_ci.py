"""Exercise Make exit mapping and CI reports without a build or container."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


class AnalyzerCiTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scst-analyzer-ci-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        repository = Path(__file__).resolve().parents[2]
        shutil.copytree(repository / "scripts", self.root / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "make").symlink_to(shutil.which("make"))
        # Exercise real GNU Make's mapping of recipe failures to status 2.
        # The fixture driver below produces reports without compiling SCST.
        (self.root / "Makefile").write_text(
            "SHELL := /bin/sh\n.PHONY: sparse smatch coccicheck cppcheck\n"
            "sparse smatch coccicheck cppcheck:\n"
            f"\t@{shlex.quote(sys.executable)} -B scripts/sparse_smatch/smp.py $@\n"
            "\t@exit $(FIXTURE_MAKE_TAIL_EXIT)\n")
        for name in ("git", "sparse", "smatch", "spatch", "cppcheck"):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\nprint('fixture-version')\n")
            path.chmod(0o755)
        kernel = self.root / "kernel"
        kernel.mkdir()
        (kernel / "Module.symvers").touch()
        (kernel / ".config").write_text("CONFIG_KUNIT=y\n")
        self.env = dict(os.environ, KDIR=str(kernel), SCST_LINT_KDIR=str(kernel),
                        PATH=str(self.bin), MAKEFLAGS="", MFLAGS="", MAKEOVERRIDES="",
                        GNUMAKEFLAGS="", FIXTURE_STATUS="0", FIXTURE_MAKE_TAIL_EXIT="0",
                        FIXTURE_OUTCOME="clean", FIXTURE_COVERAGE="full")
        self.env.pop("GITHUB_STEP_SUMMARY", None)
        driver = self.root / "scripts/sparse_smatch/smp.py"
        driver.write_text('''import json, os, sys
from pathlib import Path
root = Path(__file__).resolve().parents[2]
assert os.environ['KUNIT_TEST'] == 'y'
assert os.environ['KUNIT_LABEL'] == 'ALL'
assert os.environ['DIFFBR'] == ''
assert os.environ['LINT_DEFER_REPORTS'] == '1'
status = int(os.environ['FIXTURE_STATUS'])
directory = root / '.cache/lint'
directory.mkdir(parents=True, exist_ok=True)
tool = sys.argv[1]
if os.environ.get('FIXTURE_NO_REPORT'):
    sys.exit(2)
checked = [p + '/fixture.c' for p in ('scst', 'iscsi-scst',
    'qla2x00t-32gbit/qla2x00-target', 'srpt', 'fcst', 'scst_local')]
checked += ['scst/src/kunit/fixture.c']
if tool in ('coccicheck', 'cppcheck'):
    checked += ['usr/fileio/fixture.c', 'iscsi-scst/usr/fixture.c']
if os.environ['FIXTURE_COVERAGE'] != 'full':
    checked = checked[:1]
report = dict(tool=os.environ.get('FIXTURE_REPORT_TOOL', tool), run_id=os.environ['SCST_LINT_RUN_ID'],
    outcome=os.environ['FIXTURE_OUTCOME'], exit_code=status, make_status=0,
    errors=0, unchecked_files=[], unrecorded_checks=[],
    translation_units=len(checked), checked_files=checked,
    remaining=1 if status == 1 else 0)
report['rules'] = [dict(complete=True, native_status=0, failures=[], handled=checked)]
report['kernel_make_status'] = report['userspace_make_status'] = 0
report['profiles'] = [dict(profile=profile, complete=True, native_status=0, failures=[],
    translation_units=1, checked_files=checked) for profile in ('kernel', 'userspace')]
if os.environ.get('FIXTURE_NATIVE_INCOMPLETE'):
    report['rules'][0]['complete'] = False
    report['profiles'][0]['complete'] = False
if os.environ.get('FIXTURE_STALE'):
    report['run_id'] = 'previous run'
(directory / (tool + '.json')).write_text(json.dumps(report))
(directory / (tool + '.log')).write_text('raw diagnostic fixture\\n')
print('summary fixture')
sys.exit(status)
''')

    def run_ci(self, tool="sparse"):
        return subprocess.run([sys.executable, "-B", str(self.root / "scripts/ci/run-analyzer.py"),
                               tool], cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=10)

    def test_only_completed_findings_can_be_advisory(self):
        for tool in ("sparse", "smatch", "coccicheck", "cppcheck"):
            for status, outcome, expected in (
                    (0, "clean", 0), (1, "findings", 0), (2, "incomplete", 2),
                    (1, "incomplete", 2), (0, "skipped", 2), (0, "findings", 2)):
                with self.subTest(tool=tool, status=status, outcome=outcome):
                    self.env.update(FIXTURE_STATUS=str(status), FIXTURE_OUTCOME=outcome)
                    result = self.run_ci(tool)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.count("raw diagnostic fixture"), 1)
                    self.assertEqual("::warning::" in result.stdout,
                                     outcome == "findings" and expected == 0)
                    self.assertIn(f"make exit={2 if status else 0}", result.stdout)

    def test_make_failure_after_clean_analysis_cannot_pass(self):
        self.env["FIXTURE_MAKE_TAIL_EXIT"] = "7"
        result = self.run_ci()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("make exit=2, job exit=2", result.stdout)

    def test_basic_analyzers_cannot_downgrade_incomplete_native_reports(self):
        self.env.update(FIXTURE_STATUS="1", FIXTURE_OUTCOME="findings", FIXTURE_NATIVE_INCOMPLETE="1")
        for tool in ("coccicheck", "cppcheck"):
            with self.subTest(tool=tool):
                result = self.run_ci(tool)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("::warning::", result.stdout)

    def test_make_failure_without_a_new_report_cannot_reuse_previous_results(self):
        self.assertEqual(self.run_ci().returncode, 0)
        self.env["FIXTURE_NO_REPORT"] = "1"
        result = self.run_ci()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("raw diagnostic fixture", result.stdout)

    def test_report_from_another_tool_is_not_accepted(self):
        self.env["FIXTURE_REPORT_TOOL"] = "smatch"
        result = self.run_ci("sparse")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("raw diagnostic fixture", result.stdout)

    def test_missing_components_or_kunit_cannot_pass(self):
        self.env["FIXTURE_COVERAGE"] = "partial"
        result = self.run_ci()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("every module component and KUnit", result.stderr)

    def test_previous_report_is_not_printed_or_accepted(self):
        self.env["FIXTURE_STALE"] = "1"
        result = self.run_ci()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("raw diagnostic fixture", result.stdout)

    def test_failed_preparation_does_not_dump_old_logs(self):
        self.assertEqual(self.run_ci().returncode, 0)
        (self.root / "kernel/.config").write_text("# CONFIG_KUNIT is not set\n")
        result = self.run_ci()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("raw diagnostic fixture", result.stdout)


if __name__ == "__main__":
    unittest.main()
