"""Exercise checker execution failures even when Kbuild returns success."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class KbuildDriverTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="scst analyzer ")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        shutil.copytree(ROOT / "scripts", self.root / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__"))
        subprocess.run(["git", "init", "-q", "--template=", str(self.root)], check=True)
        self.source = self.root / "scst/source.c"
        self.source.parent.mkdir()
        self.source.write_text("int untouched;\n")
        subprocess.run(["git", "-C", str(self.root), "add", "scst"], check=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        data = self.bin / "smatch_data"
        data.mkdir()
        (data / "kernel.unreachable.turn_off").touch()
        self.kernel = self.root / "kernel"
        self.kernel.mkdir()
        (self.kernel / "Makefile").touch()
        (self.bin / "git").symlink_to(shutil.which("git"))
        self.program("sparse", """
import os, sys
print(os.environ.get('TEST_DIAGNOSTIC', ''), file=sys.stderr)
sys.exit(int(os.environ.get('TEST_CHECK_EXIT', '0')))
""")
        self.program("make", """
import os, shlex, subprocess, sys
from pathlib import Path
root = Path(sys.argv[sys.argv.index('-C') + 1])
if not os.environ.get('TEST_NO_CHECK'):
    print('  CHECK ' + str(root / 'scst/source.c'), flush=True)
    checker = next(arg[6:] for arg in sys.argv if arg.startswith('CHECK='))
    includes = ['-include', os.environ['TEST_KERNEL_CONFIG']] if os.environ.get('TEST_KERNEL_CONFIG') else []
    # Intentionally discard the checker status, as some Kbuild versions do.
    subprocess.run([*shlex.split(checker), '-fmax-warnings=1', *includes,
                    str(root / 'scst/source.c')], cwd=root)
sys.exit(int(os.environ.get('TEST_BUILD_EXIT', '0')))
""")
        self.env = dict(os.environ, PATH=str(self.bin), DIFFBR="", MAKEFLAGS="",
                        PYTHONDONTWRITEBYTECODE="1", SCST_LINT_KDIR=str(self.kernel),
                        SMATCH_DATA_DIR=str(data))
        self.env.pop("LINT_DEFER_REPORTS", None)
        for name in ("TEST_DIAGNOSTIC", "TEST_CHECK_EXIT", "TEST_BUILD_EXIT", "TEST_NO_CHECK",
                     "TEST_KERNEL_CONFIG"):
            self.env.pop(name, None)

    def program(self, name, source):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + source)
        path.chmod(0o755)

    def analyze(self, *arguments, tool="sparse"):
        return subprocess.run([sys.executable, str(self.root / "scripts/sparse_smatch/smp.py"),
                               tool, *arguments], env=self.env, cwd=self.root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_clean_completed_check_and_findings(self):
        result = self.analyze()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env["TEST_DIAGNOSTIC"] = "scst/source.c:1:2: warning: retained finding"
        result = self.analyze()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"retained finding", result.stdout + result.stderr)
        self.assertIn("retained finding", (self.root / ".cache/lint/sparse.log").read_text())
        self.assertEqual(self.source.read_text(), "int untouched;\n")

    def test_build_checker_and_missing_execution_fail(self):
        for name in ("TEST_BUILD_EXIT", "TEST_CHECK_EXIT", "TEST_NO_CHECK"):
            with self.subTest(name=name):
                self.env[name] = "7"
                result = self.analyze()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.env.pop(name)

    def test_parser_errors_fail_even_when_checker_returns_zero(self):
        for diagnostic in ("include/kernel.h:12:9: error: static assertion failed",
                           "sparse: error: unable to parse input",
                           "source.c:12:9: warning: too many warnings"):
            self.env["TEST_DIAGNOSTIC"] = diagnostic
            result = self.analyze()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(b"errors=1", result.stderr)

    def test_unlimited_warnings_override_a_lower_kbuild_limit(self):
        self.program("sparse", """
import sys
assert '-fmax-warnings=1' in sys.argv, sys.argv
assert sys.argv[-2] == '-fmax-warnings=unlimited', sys.argv
""")
        self.assertEqual(self.analyze().returncode, 0)

    def test_partial_startup_failure_is_not_hidden_by_other_completed_checks(self):
        self.source.with_name("second.c").write_text("int other;\n")
        self.program("make", """
import shlex, subprocess, sys
from pathlib import Path
root = Path(sys.argv[sys.argv.index('-C') + 1])
checker = next(arg[6:] for arg in sys.argv if arg.startswith('CHECK='))
subprocess.run([*shlex.split(checker), str(root / 'scst/source.c')], cwd=root)
(root / 'bin/sparse').unlink()
subprocess.run([*shlex.split(checker), str(root / 'scst/second.c')], cwd=root)
# Kbuild returned success despite the second CHECK failing to start.
""")
        result = self.analyze()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"SCST checker failed", result.stderr)
        self.assertIn(b"checker invocations=2", result.stderr)

    def test_missing_tool_and_invalid_base_fail(self):
        self.assertNotEqual(self.analyze("--base", "missing").returncode, 0)
        (self.bin / "sparse").unlink()
        self.assertNotEqual(self.analyze().returncode, 0)

    def test_explicit_input_missing_from_build_is_not_a_clean_result(self):
        source = self.source.with_name("disabled.c")
        source.write_text("int disabled;\n")
        result = self.analyze(str(source))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"absent from this build configuration", result.stderr)

    def test_smatch_uses_native_kernel_model_and_preserves_findings(self):
        self.program("smatch", """
import sys
assert '-p=kernel' in sys.argv
print('scst/source.c:1 example() warn: retained smatch finding')
print('scst/source.c:2 example() error: source defect')
""")
        result = subprocess.run([sys.executable, str(self.root / "scripts/sparse_smatch/smp.py"),
                                 "smatch"], env=self.env, cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"retained smatch finding", result.stderr)
        self.assertIn(b"source defect", result.stderr)
        self.assertIn(b"2 diagnostic(s)", result.stdout)

    def test_generated_metadata_is_not_counted_as_checked(self):
        records = self.root / "records"
        records.mkdir()
        env = dict(self.env, SCST_LINT_RECORDS=str(records))
        result = subprocess.run([sys.executable, str(self.root / "scripts/sparse_smatch/check.py"),
                                 "sparse", str(self.root / "scst/source.mod.c")],
                                env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(records.iterdir()), [])

    def test_probe_rejection_prevents_the_build(self):
        probe = self.kernel / "scripts/checker-valid.sh"
        probe.parent.mkdir()
        probe.write_text(f"#!{sys.executable}\nprint('0')\n")
        probe.chmod(0o755)
        result = self.analyze()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"module build was not started", result.stderr)
        self.assertEqual(list((self.root / ".cache/lint").glob("sparse-checks-*")), [])

    def test_external_probe_reaches_the_native_checker(self):
        with tempfile.NamedTemporaryFile(prefix="scst-checker-probe-") as probe:
            self.env["TEST_CHECK_EXIT"] = "7"
            result = subprocess.run(
                [sys.executable, str(self.root / "scripts/sparse_smatch/check.py"),
                 "sparse", probe.name], env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 7, result.stderr)

    def test_probe_preserves_native_failure_and_raw_output(self):
        probe = self.kernel / "scripts/checker-valid.sh"
        probe.parent.mkdir()
        probe.write_text(f"#!{sys.executable}\n" + '''
import subprocess, sys, tempfile
with tempfile.NamedTemporaryFile() as source:
    result = subprocess.run([*sys.argv[1:], source.name], capture_output=True)
# Model a probe that discards native output and status in a pipeline.
print('1')
''')
        probe.chmod(0o755)
        self.env["TEST_CHECK_EXIT"] = "7"
        self.env["TEST_DIAGNOSTIC"] = "native probe failure"
        result = self.analyze()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"module build was not started", result.stderr)
        self.assertIn("native probe failure", (self.root / ".cache/lint/sparse.log").read_text())

    def test_records_and_ignored_reasons_survive_the_run(self):
        import json

        self.env["TEST_DIAGNOSTIC"] = "scst/source.c:1:2: warning: retained finding"
        self.assertEqual(self.analyze().returncode, 1)
        summary = json.loads((self.root / ".cache/lint/sparse.json").read_text())
        self.assertEqual(summary["outcome"], "findings")
        records = list(Path(summary["records_directory"]).glob("*.json"))
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0].read_text())["findings"], 1)

    def test_check_without_an_adapter_record_is_incomplete(self):
        source = self.source.with_name("second.c")
        source.write_text("int other;\n")
        # The native CHECK never reached Python, so no failure record exists.
        text = (self.bin / "make").read_text()
        for path in (source, self.source):
            with self.subTest(path=path):
                changed = text.replace("sys.exit(int(os.environ.get('TEST_BUILD_EXIT', '0')))",
                                       f"print('  CHECK {path}', flush=True)")
                (self.bin / "make").write_text(changed)
                result = self.analyze()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b"CHECK steps without records", result.stderr)

    def test_reviewed_smatch_irq_warnings_remain_in_raw_log(self):
        shutil.copyfile(self.bin / "sparse", self.bin / "smatch")
        (self.bin / "smatch").chmod(0o755)
        for source, function in (
                ("scst/src/dev_handlers/scst_user_main.c", "dev_user_unjam_cmd"),
                ("scst/src/dev_handlers/kunit/user/suites/scst_user_cleanup_test.c",
                 "user_reply_test")):
            for path in (source, str(self.root / source)):
                with self.subTest(path=path):
                    warning = f"{path}:123 {function}() warn: mixing irqsave and irq"
                    self.env["TEST_DIAGNOSTIC"] = warning
                    result = self.analyze(tool="smatch")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(b"1 diagnostic(s), 1 ignored, 0 remaining", result.stdout)
                    self.assertIn(warning, (self.root / ".cache/lint/smatch.log").read_text())
                    # Sparse and native failures cannot be excused by a Smatch exception.
                    self.assertEqual(self.analyze().returncode, 1)
                    self.env["TEST_CHECK_EXIT"] = "7"
                    self.assertEqual(self.analyze(tool="smatch").returncode, 2)
                    self.env.pop("TEST_CHECK_EXIT")

    def test_smatch_irq_exceptions_preserve_near_misses_and_frontend_errors(self):
        shutil.copyfile(self.bin / "sparse", self.bin / "smatch")
        (self.bin / "smatch").chmod(0o755)
        warning = ("scst/src/dev_handlers/scst_user_main.c:123 "
                   "dev_user_unjam_cmd() warn: mixing irqsave and irq")
        self.env["TEST_DIAGNOSTIC"] = warning
        for diagnostic, status in (
                (warning.replace("scst/src/dev_handlers/", "scst/other/"), 1),
                (warning.replace("dev_user_unjam_cmd()", "other()"), 1),
                (warning + " extra detail", 1),
                (warning.replace("warn:", "error:"), 1),
                ("/outside/" + warning, 1),
                ("source.c:12:9: error: failed to parse", 2),
                ("source.c:12:9: warning: too many warnings", 2)):
            with self.subTest(diagnostic=diagnostic):
                self.env["TEST_DIAGNOSTIC"] = warning + "\n" + diagnostic
                result = self.analyze(tool="smatch")
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn(diagnostic.encode(), result.stdout + result.stderr)
                if status == 1:
                    self.assertIn(b"2 diagnostic(s), 1 ignored, 1 remaining", result.stdout)

    def kernel_headers(self, directory):
        config = directory / "include/linux/kconfig.h"
        header = directory / "include/uapi/scsi/fc/fc_els.h"
        for path in (config, header):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        return config, header

    def test_fc_exception_matches_only_the_configured_external_header(self):
        tmp = tempfile.TemporaryDirectory(prefix="scst kernel headers ")
        self.addCleanup(tmp.cleanup)
        config, header = self.kernel_headers(Path(tmp.name))
        self.env["TEST_KERNEL_CONFIG"] = str(config)
        warning = f"{header}:1152:37: warning: array of flexible structures"
        shutil.copy2(self.bin / "sparse", self.bin / "smatch")
        for tool in ("sparse", "smatch"):
            with self.subTest(tool=tool):
                self.env["TEST_DIAGNOSTIC"] = warning
                result = self.analyze(tool=tool)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"1 diagnostic(s), 1 ignored, 0 remaining", result.stdout)
                self.assertIn(warning, (self.root / f".cache/lint/{tool}.log").read_text())
                for diagnostic, status in (
                        (warning.replace("fc_els.h", "other.h"), 1),
                        (warning + " extra detail", 1),
                        (warning.replace("warning:", "error:"), 2)):
                    self.env["TEST_DIAGNOSTIC"] = warning + "\n" + diagnostic
                    result = self.analyze(tool=tool)
                    self.assertEqual(result.returncode, status, result.stderr)
                    if status == 1:
                        self.assertIn(b"2 diagnostic(s), 1 ignored, 1 remaining", result.stdout)
                self.env["TEST_DIAGNOSTIC"] = warning
                self.env["TEST_CHECK_EXIT"] = "7"
                self.assertEqual(self.analyze(tool=tool).returncode, 2)
                self.env.pop("TEST_CHECK_EXIT")

        self.env.pop("TEST_KERNEL_CONFIG")
        self.assertEqual(self.analyze().returncode, 1)
        other_config, _ = self.kernel_headers(Path(tmp.name) / "other kernel")
        self.env["TEST_KERNEL_CONFIG"] = str(other_config)
        self.assertEqual(self.analyze().returncode, 1)

        # Even a matching forced include must not excuse repository headers.
        config, header = self.kernel_headers(self.root / "scst/kernel")
        self.env["TEST_KERNEL_CONFIG"] = str(config)
        self.env["TEST_DIAGNOSTIC"] = f"{header}:1152:37: warning: array of flexible structures"
        self.assertEqual(self.analyze().returncode, 1)


if __name__ == "__main__":
    unittest.main()
