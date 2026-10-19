#!/usr/bin/env python3
"""Check process, progress and raw-log contracts shared by analyzer drivers."""

import contextlib
import io
import os
import pty
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from lint_common import Progress, copy_output, jobserver_fds, log_path, run  # noqa: E402


class LogTest(unittest.TestCase):
    def test_log_creation_append_and_reset_preserve_raw_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = log_path(root, "fixture.log")
            self.assertEqual(log, root / ".cache/lint/fixture.log")
            self.assertEqual(log.read_bytes(), b"")
            raw = b"diagnostic\x00\xff\r\n"
            log.write_bytes(raw)
            self.assertEqual(log_path(root, "fixture.log", truncate=False), log)
            output = io.BytesIO()
            copy_output(log, output)
            self.assertEqual(output.getvalue(), raw)
            self.assertEqual(log.read_bytes(), raw)
            self.assertEqual(log_path(root, "fixture.log"), log)
            self.assertEqual(log.read_bytes(), b"")


class ProcessTest(unittest.TestCase):
    def test_progress_is_live_and_preserves_piped_data_and_failure(self):
        for check in (False, True):
            with self.subTest(check=check), tempfile.TemporaryDirectory() as directory:
                release = Path(directory) / "release"

                class Progress(io.StringIO):
                    def write(self, text):
                        size = super().write(text)
                        if self.getvalue().count("running (") >= 2:
                            release.touch()
                        return size

                script = """
import os, sys, time
from pathlib import Path
payload = sys.stdin.buffer.read()
deadline = time.monotonic() + 5
while not Path(sys.argv[1]).exists():
    if time.monotonic() > deadline:
        sys.exit(99)
    time.sleep(0.01)
os.write(1, payload)
os.write(2, b'diagnostic\\x00\\xff')
sys.exit(7)
"""
                payload = b"input\x00\xff" * 20000
                progress = Progress()
                with patch("lint_common.PROGRESS_INTERVAL", 0.02), \
                        contextlib.redirect_stderr(progress):
                    try:
                        result = run([sys.executable, "-c", script, str(release)],
                                     input=payload, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, progress="Fixture", check=check)
                    except subprocess.CalledProcessError as error:
                        self.assertTrue(check)
                        result = error
                    else:
                        self.assertFalse(check)
                self.assertEqual(result.returncode, 7)
                self.assertEqual(result.stdout, payload)
                self.assertEqual(result.stderr, b"diagnostic\x00\xff")
                self.assertGreaterEqual(progress.getvalue().count("Fixture: running ("), 2)

    def test_fast_process_does_not_print_periodic_progress(self):
        progress = io.StringIO()
        with contextlib.redirect_stderr(progress):
            result = run([sys.executable, "-c", "pass"], progress="Fixture")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(progress.getvalue(), "")

    def test_terminal_spinner_is_live_and_separate_from_child_output(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            child = """
import os, sys, time
from pathlib import Path
deadline = time.monotonic() + 5
while not Path(sys.argv[1]).exists():
    if time.monotonic() > deadline:
        sys.exit(99)
    time.sleep(0.01)
os.write(1, b'raw\\x00\\xff')
os.write(2, b'diagnostic\\n')
sys.exit(7)
"""
            script = """
import subprocess, sys
sys.path.insert(0, sys.argv[1])
from lint_common import entrypoint, run
def main():
    result = run([sys.executable, '-c', sys.argv[2], sys.argv[3]],
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, progress='Fixture')
    sys.stdout.buffer.write(result.stdout + result.stderr)
    return result.returncode
sys.exit(entrypoint(main))
"""
            master, slave = pty.openpty()
            process = subprocess.Popen(
                [sys.executable, "-B", "-c", script, str(SCRIPTS), child, str(release)],
                stdout=subprocess.PIPE, stderr=slave, env=dict(os.environ, TERM="xterm"))
            os.close(slave)
            display = b""
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(master, selectors.EVENT_READ)
                    deadline = time.monotonic() + 5
                    while display.count(b"\r\x1b[2K") < 2:
                        self.assertGreater(deadline - time.monotonic(), 0, display)
                        if selector.select(timeout=0.1):
                            display += os.read(master, 4096)
                    self.assertIsNone(process.poll())
                    release.touch()
                    stdout, _ = process.communicate(timeout=5)
                    while selector.select(timeout=0.1):
                        try:
                            chunk = os.read(master, 4096)
                        except OSError:
                            break  # A closed PTY reports EIO on Linux.
                        if not chunk:
                            break
                        display += chunk
                self.assertEqual(process.returncode, 7, display)
                self.assertEqual(stdout, b"raw\x00\xffdiagnostic\n")
                self.assertIn(b"| Fixture", display)
                self.assertIn(b"/ Fixture", display)
                self.assertIn(b"exit 7)", display)
                self.assertNotIn(b"running (", display)
            finally:
                release.touch()
                if process.poll() is None:
                    process.terminate()
                process.communicate(timeout=5)
                os.close(master)

    def test_plain_progress_updates_every_five_seconds(self):
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream), \
                patch("lint_common.time.monotonic", side_effect=(10, 15)):
            progress = Progress("Fixture")
            self.assertEqual(progress.interval, 5)
            progress.update()
        self.assertEqual(stream.getvalue(), "  Fixture: running (5s elapsed)\n")

    def test_dumb_terminal_does_not_receive_escape_sequences(self):
        stream = io.StringIO()
        with patch.object(stream, "isatty", return_value=True), \
                patch.dict(os.environ, TERM="dumb"), contextlib.redirect_stderr(stream):
            progress = Progress("Fixture")
            progress.update()
            progress.finish(0)
        self.assertNotIn("\r", stream.getvalue())
        self.assertNotIn("\033", stream.getvalue())

    def test_interrupted_spinner_clears_its_line_and_stops_child(self):
        stream = io.StringIO()
        with patch.object(stream, "isatty", return_value=True), \
                patch.dict(os.environ, TERM="xterm"), contextlib.redirect_stderr(stream), \
                patch("lint_common.start") as start, patch("lint_common.stop") as stop:
            start.return_value.communicate.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                run(["fixture"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    progress="Fixture")
            stop.assert_called_once_with(start.return_value)
        self.assertTrue(stream.getvalue().endswith("\r\033[2K"))

    def test_inherited_pipe_jobserver_survives_python_driver(self):
        reader, writer = os.pipe()
        try:
            os.set_inheritable(reader, True)
            os.set_inheritable(writer, True)
            env = dict(os.environ, MAKEFLAGS=f"-j --jobserver-auth={reader},{writer}")
            script = ("import os,sys; r,w=map(int,sys.argv[1:]); "
                      "os.write(w,b'token'); assert os.read(r,5)==b'token'")
            result = run([sys.executable, "-c", script, str(reader), str(writer)],
                         env=env, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 0, result.stderr)
            # FIFO jobservers must not forward a superseded pipe specification.
            env["MAKEFLAGS"] += " --jobserver-auth=fifo:/tmp/make-test"
            self.assertEqual(jobserver_fds(env), ())
        finally:
            os.close(reader)
            os.close(writer)

    def test_stale_jobserver_numbers_do_not_forward_reused_log_descriptors(self):
        with tempfile.TemporaryFile() as first, tempfile.TemporaryFile() as second:
            env = {"MAKEFLAGS": f"--jobserver-auth={first.fileno()},{second.fileno()}"}
            self.assertEqual(jobserver_fds(env), ())

    def test_child_signal_keeps_shell_exit_status_and_raw_log(self):
        with tempfile.TemporaryFile() as output:
            result = run([sys.executable, "-c",
                          "import os,signal; os.write(1,b'out\\xff\\n'); "
                          "os.write(2,b'err\\r\\n'); os.kill(os.getpid(),signal.SIGTERM)"],
                         stdout=output, stderr=subprocess.STDOUT, progress="Fixture")
            self.assertEqual(result.returncode, 143)
            output.seek(0)
            self.assertEqual(output.read(), b"out\xff\nerr\r\n")

    def test_terminating_driver_also_stops_child_and_grandchild(self):
        with tempfile.TemporaryDirectory(prefix="scst-lint-signal.") as directory:
            root = Path(directory)
            grandchild = root / "grandchild.py"
            grandchild.write_text("""
import signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
def stop(signum, frame):
    (root / 'grandchild-stopped').touch()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
(root / 'grandchild-ready').touch()
while True:
    time.sleep(1)
""")
            child = root / "child.py"
            child.write_text("""
import signal, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
process = subprocess.Popen([sys.executable, str(root / 'grandchild.py'), str(root)])
stopping = False
def stop(signum, frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
(root / 'child-ready').touch()
process.wait()
if stopping:
    (root / 'child-stopped').touch()
""")
            script = ("import sys; sys.path.insert(0, sys.argv[1]); "
                      "from lint_common import entrypoint, run; "
                      "sys.exit(entrypoint(lambda: run([sys.executable,sys.argv[2],"
                      "sys.argv[3]], progress='Fixture').returncode))")
            process = subprocess.Popen([sys.executable, "-B", "-c", script,
                                        str(SCRIPTS), str(child), str(root)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while (not all((root / name).exists() for name in
                               ("child-ready", "grandchild-ready")) and process.poll() is None):
                    if time.monotonic() > deadline:
                        self.fail("grandchild did not start")
                    time.sleep(0.01)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143, stdout + stderr)
                self.assertTrue((root / "child-stopped").exists())
                self.assertTrue((root / "grandchild-stopped").exists())
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
