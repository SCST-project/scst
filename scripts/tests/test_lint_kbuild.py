"""Check analyzer build locking and CHECK evidence without compiling SCST."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lint_kbuild import build_lock, collect, unchecked_invocations


class CheckEvidenceTests(unittest.TestCase):
    def test_capture_can_clear_sparse_flags_without_changing_analyzers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = root / "records"
            records.mkdir()
            for flags in (None, ""):
                with self.subTest(flags=flags), patch("lint_kbuild.run", return_value=Mock(
                        returncode=0)) as run:
                    self.assertEqual(collect(root, "cppcheck", records, root / "log",
                                             checker=["capture"], checkflags=flags), (0, []))
                    command = run.call_args.args[0]
                    self.assertEqual([arg for arg in command if arg.startswith("CHECKFLAGS=")],
                                     [] if flags is None else ["CHECKFLAGS="])
                    self.assertIn("C=2", command)

    def check(self, text, records):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "iscsi-scst/kernel/config.c"
            user = root / "iscsi-scst/usr/config.c"
            log = root / "build.log"
            log.write_text(text.format(root=root))
            rows = [{"file": str(root / name)} for name in records]
            with patch("lint_kbuild.tracked_sources", return_value=[kernel, user]):
                return [Path(name).relative_to(root).as_posix()
                        for name in unchecked_invocations(root, "cppcheck", log, rows)]

    def test_module_directory_disambiguates_userspace_basename(self):
        self.assertEqual(self.check(
            "make[4]: Entering directory '{root}/iscsi-scst/kernel'\n"
            "  CHECK config.c\n"
            "make[4]: Leaving directory '{root}/iscsi-scst/kernel'\n",
            ["iscsi-scst/kernel/config.c"]), [])

    def test_module_directory_identifies_missing_check_record(self):
        self.assertEqual(self.check(
            "make[4]: Entering directory '{root}/iscsi-scst/kernel'\n"
            "  CHECK config.c\n", []), ["iscsi-scst/kernel/config.c"])

    def test_directory_exit_does_not_reuse_old_context(self):
        with self.assertRaisesRegex(ValueError, "ambiguous Kbuild CHECK path"):
            self.check("make[4]: Entering directory '{root}/iscsi-scst/kernel'\n"
                       "make[4]: Leaving directory '{root}/iscsi-scst/kernel'\n"
                       "  CHECK config.c\n", ["iscsi-scst/kernel/config.c"])

    def test_parallel_ambiguous_directories_still_fail(self):
        with self.assertRaisesRegex(ValueError, "ambiguous Kbuild CHECK path"):
            self.check("make[4]: Entering directory '{root}/iscsi-scst/kernel'\n"
                       "make[4]: Entering directory '{root}/iscsi-scst/usr'\n"
                       "  CHECK config.c\n", ["iscsi-scst/kernel/config.c"])

    def test_repeated_check_requires_a_record_for_each_invocation(self):
        self.assertEqual(self.check(
            "make[4]: Entering directory '{root}/iscsi-scst/kernel'\n"
            "  CHECK config.c\n  CHECK config.c\n",
            ["iscsi-scst/kernel/config.c"]), ["iscsi-scst/kernel/config.c"])


class BuildLockTests(unittest.TestCase):
    def try_lock(self, path):
        script = """
import fcntl, sys
with open(sys.argv[1], 'a') as lock:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(7)
"""
        return subprocess.run([sys.executable, "-c", script, str(path)],
                              capture_output=True, timeout=5)

    def test_competing_process_cannot_acquire_held_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ".cache/lint/kbuild.lock"
            with build_lock(root):
                inode = path.stat().st_ino
                result = self.try_lock(path)
                self.assertEqual(result.returncode, 7, result.stderr)
            result = self.try_lock(path)
            self.assertEqual(result.returncode, 0, result.stderr)
            with build_lock(root):
                self.assertEqual(path.stat().st_ino, inode)
                result = self.try_lock(path)
                self.assertEqual(result.returncode, 7, result.stderr)

    def test_exception_releases_the_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "build failed"):
                with build_lock(root):
                    raise ValueError("build failed")
            result = self.try_lock(root / ".cache/lint/kbuild.lock")
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
