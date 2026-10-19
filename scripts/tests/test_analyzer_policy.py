"""Exercise policy validation and its effect on source selection."""

import copy
import json
import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
