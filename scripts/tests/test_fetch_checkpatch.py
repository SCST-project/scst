"""Check source acquisition with fake network clients and real file operations."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "ci/fetch-checkpatch"
FILES = ("scripts/checkpatch.pl", "scripts/spelling.txt", "scripts/const_structs.checkpatch",
         "Documentation/dev-tools/checkpatch.rst")


class FetchCheckpatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scst-checkpatch-fetch-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("timeout", "dirname", "mktemp", "mkdir", "rm", "chmod", "sha256sum", "mv"):
            (self.bin / name).symlink_to(shutil.which(name))
        # PATH contains no real Git or curl: these tests cannot access the network.
        client = '''import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
log = Path(os.environ['FETCH_LOG'])
calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
with log.open('a') as stream:
    stream.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
if name == 'git':
    attempts = sum(row[0] == 'git' for row in calls)
    if attempts < int(os.environ.get('FETCH_GIT_FAILURES', '0')):
        sys.exit(128)
    print(os.environ['FETCH_REVISION'] + '\\trefs/heads/master')
elif name == 'curl':
    url = next(arg for arg in sys.argv if arg.startswith('https://'))
    if os.environ.get('FETCH_FAIL_FILE') and url.endswith(os.environ['FETCH_FAIL_FILE']):
        sys.exit(22)
    output = Path(sys.argv[sys.argv.index('--output') + 1])
    output.write_text('' if url.endswith(os.environ.get('FETCH_EMPTY_FILE', '/absent')) else url + '\\n')
'''
        for name in ("git", "curl", "sleep"):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n" + client)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin), FETCH_LOG=str(self.root / "calls.jsonl"),
                        FETCH_REVISION="1" * 40, FETCH_GIT_FAILURES="0",
                        FETCH_FAIL_FILE="", FETCH_EMPTY_FILE="/absent")
        self.bash = shutil.which("bash")

    def fetch(self, name):
        return subprocess.run([self.bash, str(SCRIPT), str(self.root / name)], env=self.env,
                              text=True, capture_output=True, timeout=10)

    def calls(self):
        path = Path(self.env["FETCH_LOG"])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_each_invocation_resolves_master_and_fetches_a_consistent_complete_set(self):
        for index in (1, 2):
            revision = str(index) * 40
            self.env["FETCH_REVISION"] = revision
            result = self.fetch(f"snapshot-{index}")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            destination = self.root / f"snapshot-{index}"
            for name in FILES:
                self.assertEqual((destination / name).read_text(),
                                 f"https://raw.githubusercontent.com/torvalds/linux/{revision}/{name}\n")
            self.assertTrue(os.access(destination / FILES[0], os.X_OK))
            provenance = (destination / "scripts/checkpatch-source.txt").read_text()
            self.assertIn(f"Commit: {revision}\n", provenance)
            self.assertIn("Ref: refs/heads/master\n", provenance)
            for name in FILES:
                self.assertIn("  " + name + "\n", provenance)
            self.assertFalse(list(self.root.glob(f"snapshot-{index}.*")))
        queries = [row for row in self.calls() if row[0] == "git"]
        self.assertEqual(len(queries), 2)
        for query in queries:
            self.assertEqual(query[-4:], ["ls-remote", "--exit-code",
                                         "https://github.com/torvalds/linux.git", "refs/heads/master"])

    def test_reference_resolution_retries_then_succeeds_or_preserves_failure(self):
        for failures, status, downloads in ((2, 0, 4), (3, 128, 0)):
            with self.subTest(failures=failures):
                Path(self.env["FETCH_LOG"]).unlink(missing_ok=True)
                self.env["FETCH_GIT_FAILURES"] = str(failures)
                result = self.fetch(f"retry-{failures}")
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                calls = self.calls()
                self.assertEqual(sum(row[0] == "git" for row in calls), 3)
                self.assertEqual(sum(row[0] == "curl" for row in calls), downloads)
                self.assertEqual([row for row in calls if row[0] == "sleep"],
                                 [["sleep", "10"], ["sleep", "20"]])
                self.assertEqual((self.root / f"retry-{failures}").exists(), status == 0)
                self.assertFalse(list(self.root.glob(f"retry-{failures}.*")))

    def test_failed_or_empty_asset_does_not_publish_partial_tools(self):
        for mode in ("FETCH_FAIL_FILE", "FETCH_EMPTY_FILE"):
            with self.subTest(mode=mode):
                self.env[mode] = FILES[-1]
                result = self.fetch(mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / mode).exists())
                self.assertFalse(list(self.root.glob(mode + ".*")))
                self.env[mode] = "/absent"

    def test_existing_destination_is_preserved_without_network_requests(self):
        destination = self.root / "existing"
        destination.mkdir()
        (destination / "keep").write_text("original")
        result = self.fetch("existing")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual((destination / "keep").read_text(), "original")
        self.assertFalse(self.calls())


if __name__ == "__main__":
    unittest.main()
