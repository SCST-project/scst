"""Check analyzer build locking without invoking a compiler or SCST."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lint_kbuild import build_lock


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
