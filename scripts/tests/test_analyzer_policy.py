"""Exercise policy validation and its effect on source selection."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyzer_policy
from lint_scope import changed_sources, git_names, git_pathspecs, in_scope
from lint_scope import select_sources, tracked_sources


class PolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="scst-policy-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "common.json"
        self.policy = analyzer_policy.read_policy(analyzer_policy.POLICY_PATH)

    def save(self, policy):
        self.path.write_text(json.dumps(policy), encoding="utf-8")

    def activate(self, policy):
        self.save(policy)
        override = patch.object(analyzer_policy, "POLICY_PATH", self.path)
        override.start()
        self.addCleanup(override.stop)
        analyzer_policy.load_policy.cache_clear()
        self.addCleanup(analyzer_policy.load_policy.cache_clear)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args])

    def source(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int example(void);\n", encoding="utf-8")
        self.git("add", "-f", "--", name)
        return path

    def test_rejects_broken_or_missing_policy(self):
        with self.assertRaises(OSError):
            analyzer_policy.read_policy(self.path)
        for text in ("{", '{"version": 1, "version": 1}',
                     json.dumps(self.policy).replace('"path": "srpt/conftest"',
                                                     '"path": "srpt/conftest", "path": "srpt"')):
            with self.subTest(text=text):
                self.path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    analyzer_policy.read_policy(self.path)

    def test_rejects_invalid_fields_and_rules(self):
        invalid = [
            {"version": True}, {"version": 2}, {"unknown": []},
            {"source_roots": []}, {"source_roots": "scst"},
            {"source_roots": ["scst", "scst"]},
            {"source_suffixes": [".c", ".c"]}, {"source_suffixes": [".py"]},
            {"exclude_directories": [{"path": "scst", "reason": " "}]},
            {"exclude_directories": [{"path": "scst"}]},
            {"exclude_directories": [{"path": "scst", "reason": "example", "typo": True}]},
            {"exclude_directories": [{"path": "scst", "reason": "example"}] * 2},
            {"exclude_suffixes": [{"suffix": "*.mod.c", "reason": "example"}]},
            {"exclude_suffixes": [{"suffix": ".mod.c", "reason": "example"}] * 2},
            {"notes": [None]},
        ]
        for directory in ("/scst", ".", "..", "scst/..", "./scst", "scst/", "scst//src",
                          "scst/./src", "scst\\src", "scst\nsrc"):
            invalid.append({"source_roots": [directory]})
            invalid.append({"exclude_directories": [{"path": directory, "reason": "example"}]})
        for change in invalid:
            with self.subTest(change=change):
                self.save({**self.policy, **change})
                with self.assertRaises(ValueError):
                    analyzer_policy.read_policy(self.path)
        for key in self.policy:
            with self.subTest(missing=key):
                policy = dict(self.policy)
                del policy[key]
                self.save(policy)
                with self.assertRaises(ValueError):
                    analyzer_policy.read_policy(self.path)

    def test_policy_errors_do_not_become_empty_selections(self):
        self.activate({**self.policy, "version": 2})
        for select in (lambda: in_scope(self.root / "outside.c", self.root),
                       lambda: tracked_sources(self.root), git_pathspecs):
            with self.assertRaisesRegex(ValueError, "unsupported policy version"):
                select()

    def test_policy_drives_all_selectors_with_literal_paths(self):
        policy = copy.deepcopy(self.policy)
        policy["source_roots"] = ["source [ab]?* tree"]
        policy["source_suffixes"] = [".h"]
        policy["exclude_directories"] = [{"path": "source [ab]?* tree/probes [12]",
                                          "reason": "Fixture probes"}]
        policy["exclude_suffixes"] = [{"suffix": ".generated.h", "reason": "Fixture output"}]
        self.activate(policy)
        self.git("init", "-q", "--template=")
        kept = self.source("source [ab]?* tree/sub/kept.h")
        direct = self.source("source [ab]?* tree/direct.h")
        excluded = [self.source(name) for name in (
            "source [ab]?* tree/sub/other.c", "source [ab]?* tree/sub/output.generated.h",
            "source [ab]?* tree/probes [12]/probe.h", "source aXX tree/other.h", "scst/old.h")]
        expected = sorted([kept, direct])
        # Environment variables must not add exclusions outside the policy.
        with patch.dict(os.environ, {"IGNORE_DIRS": policy["source_roots"][0],
                                     "IGNORE_PATTERNS": ".*"}):
            self.assertEqual(tracked_sources(self.root), expected)
            self.assertEqual(select_sources(self.root, expected, None), expected)
        names = git_names(self.root, "ls-files", "--cached", "-z", "--", *git_pathspecs())
        self.assertEqual(sorted(self.root / name for name in names), expected)
        for path in excluded:
            self.assertFalse(in_scope(path, self.root))
            with self.assertRaises(ValueError):
                select_sources(self.root, [path], None)
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.org",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "base")
        for path in [*expected, *excluded]:
            path.write_text("int changed(void);\n", encoding="utf-8")
        self.assertEqual(changed_sources(self.root, "HEAD"), expected)

    def test_native_exceptions_require_exact_fields_and_unique_keys(self):
        path = analyzer_policy.POLICY_PATH.with_name("smatch.json")
        policy = analyzer_policy.read_policy(path, "smatch")
        for field in ("file", "function", "message", "reason"):
            changed = copy.deepcopy(policy)
            changed["source_exceptions"][0][field] = ""
            self.save(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                analyzer_policy.read_policy(self.path, "smatch")
        changed = copy.deepcopy(policy)
        changed["source_exceptions"].append(changed["source_exceptions"][0])
        self.save(changed)
        with self.assertRaisesRegex(ValueError, "duplicate source_exceptions"):
            analyzer_policy.read_policy(self.path, "smatch")
        self.save(policy)
        with self.assertRaisesRegex(ValueError, "only for Smatch"):
            analyzer_policy.read_policy(self.path, "sparse")


class PolicyCliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="scst-policy-cli-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.scripts = self.root / "scripts"
        (self.scripts / "policy").mkdir(parents=True)
        source = analyzer_policy.POLICY_PATH.parent.parent
        for name in ("analyzer_policy.py", "lint_scope.py", "policy/common.json",
                     "policy/sparse.json", "policy/smatch.json", "policy/coccicheck.json",
                     "policy/cppcheck.json", "policy/checkpatch.json", "policy/scs_lint.json"):
            shutil.copyfile(source / name, self.scripts / name)

    def run_cli(self, *args):
        # Deliberately run away from the repository root: policy paths belong
        # to the script, not to the caller's working directory.
        return subprocess.run([sys.executable, "-B", str(self.scripts / "analyzer_policy.py"),
                               *args], cwd=self.scripts, text=True, capture_output=True)

    def test_show_and_validate_need_no_git_repository_or_analyzers(self):
        expected = json.loads((self.scripts / "policy/common.json").read_text())
        shown = self.run_cli("show", "common", "--format=json")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertEqual(json.loads(shown.stdout)["configured_policy"], expected)
        text = self.run_cli("show")
        self.assertEqual(text.returncode, 0, text.stderr)
        for rule in (*expected["exclude_directories"], *expected["exclude_suffixes"]):
            self.assertIn(rule["reason"], text.stdout)
        self.assertIn("no analyzer has run", text.stdout)
        valid = self.run_cli("validate", "--format=json")
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertTrue(json.loads(valid.stdout)["valid"])

    def test_files_use_the_script_repository_and_shared_scope(self):
        subprocess.run(["git", "-C", str(self.root), "init", "-q", "--template="], check=True)
        empty = self.run_cli("files")
        self.assertEqual(empty.returncode, 0, empty.stderr)
        self.assertIn("No eligible tracked inputs", empty.stdout)
        expected = ["scst/core.c", "scst/kunit/test.c"]
        for name in (*expected, "qla2x00t/legacy.c", "scst/new.c"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("int example(void);\n")
            if name != "scst/new.c":
                subprocess.run(["git", "-C", str(self.root), "add", "--", name], check=True)
        result = self.run_cli("files", "--format=json")
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads(result.stdout)
        self.assertEqual(inventory["selected_tracked_files"], expected)
        self.assertEqual(inventory["count"], len(expected))

    def test_native_report_includes_every_exception_and_effective_exclusion(self):
        for tool, count in (("sparse", 0), ("smatch", 2)):
            with self.subTest(tool=tool):
                result = self.run_cli("show", tool, "--format=json")
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                policy = report["configured_policy"]
                self.assertEqual(len(policy["source_exceptions"]), count)
                self.assertEqual(len(policy["kernel_exceptions"]), 1)
                excluded = {r["path"] for r in report["effective_source_policy"]["exclude_directories"]}
                self.assertEqual(excluded, {"iscsi-scst/conftest", "srpt/conftest",
                                            "usr", "iscsi-scst/usr"})

    def test_configuration_and_inventory_errors_fail_visibly(self):
        unknown = self.run_cli("show", "unknown-tool")
        self.assertEqual(unknown.returncode, 2)
        no_git = self.run_cli("files", "--format=json")
        self.assertEqual(no_git.returncode, 2)
        self.assertEqual(no_git.stdout, "")
        self.assertIn("analyzer policy:", no_git.stderr)
        (self.scripts / "policy/common.json").unlink()
        for action in ("show", "files", "validate"):
            with self.subTest(action=action):
                missing = self.run_cli(action, "--format=json")
                self.assertEqual(missing.returncode, 2)
                self.assertEqual(missing.stdout, "")
                self.assertIn("analyzer policy:", missing.stderr)
        (self.scripts / "policy/common.json").write_text('{"version": true}')
        broken = self.run_cli("validate")
        self.assertEqual(broken.returncode, 2)
        self.assertEqual(broken.stdout, "")
        self.assertIn("analyzer policy:", broken.stderr)

    def test_basic_analyzers_inherit_common_scope_without_exceptions(self):
        common = json.loads((self.scripts / "policy/common.json").read_text())
        for tool in ("coccicheck", "cppcheck", "checkpatch", "scs_lint"):
            with self.subTest(tool=tool):
                result = self.run_cli("show", tool, "--format=json")
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["effective_source_policy"], common)
                self.assertEqual(set(report["configured_policy"]), {"version", "notes"})


if __name__ == "__main__":
    unittest.main()
