"""Exercise tracked and explicit source selection against Git."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lint_scope import in_scope, select_sources, tracked_sources


class ScopeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="scst scope [paths] ")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.git("init", "-q", "--template=")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args])

    def source(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int example(void);\n")
        self.git("add", "-f", "--", name)
        return path

    def test_tracked_and_explicit_scope_agree(self):
        kept = ("scst/src/core.c", "scst/src/kunit/test.c", "iscsi-scst/usr/user.c",
                "qla2x00t-32gbit/qla2x00-target/scst_qla2xxx.c",
                "qla2x00t-32gbit/qla2x00-target/scst_qla2xxx.h", "srpt/src/driver.c",
                "fcst/name with spaces.c", "usr/fileio/main.c", "scst_local/local.c")
        excluded = ("scripts/example.c", "scst/src/generated.mod.c",
                    "srpt/conftest/probe/main.c", "iscsi-scst/conftest/main.c",
                    "qla2x00t/qla2xxx-orig/main.c", "qla2x00t/old.c",
                    "qla2x00t/qla2x00-target/scst_qla2xxx.c",
                    "qla2x00t-32gbit/qla_target.c", "qla2x00t-32gbit/qla_target.h",
                    "qla2x00t-32gbit/qla2xxx-orig/main.c")
        for name in (*kept, *excluded):
            self.assertEqual(in_scope(self.source(name), self.root), name in kept)
        self.assertEqual(set(tracked_sources(self.root)), {self.root / n for n in kept})
        self.assertEqual(set(select_sources(self.root, [self.root / n for n in kept])),
                         {self.root / n for n in kept})
        for name in excluded:
            with self.subTest(name=name), self.assertRaises(ValueError):
                select_sources(self.root, [self.root / name])

    def test_alias_cannot_reinclude_qlogic_sources(self):
        kept = self.source("scst/kept.c")
        excluded = self.source("qla2x00t-32gbit/qla_target.c")
        for name, target in (("scst/vendor.c", excluded),
                             ("qla2x00t-32gbit/alias.c", kept)):
            alias = self.root / name
            alias.symlink_to(target)
            self.assertFalse(in_scope(alias, self.root))
            with self.assertRaises(ValueError):
                select_sources(self.root, [alias])

    def test_deleted_untracked_and_escaping_links(self):
        kept = self.source("scst/kept.c")
        self.source("scst/deleted.c").unlink()
        outside = self.root / "outside.c"
        outside.write_text("int outside;\n")
        alias = self.root / "scst/alias.c"
        alias.symlink_to(outside)
        self.git("add", "scst/alias.c")
        new = self.root / "scst/new.c"
        new.write_text("int fresh;\n")
        self.assertEqual(tracked_sources(self.root), [kept])
        self.assertEqual(select_sources(self.root, [new]), [new])
        with self.assertRaises(ValueError):
            select_sources(self.root, [alias])

    def test_default_selection_ignores_legacy_diff_environment(self):
        source = self.source("scst/core.c")
        with patch.dict(os.environ, {"DIFFBR": "missing-reference"}):
            self.assertEqual(select_sources(self.root, []), [source])

    def test_git_failure_preserves_diagnostics_in_the_callers_error(self):
        empty = self.root / "not-a-repository"
        empty.mkdir()
        with patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(self.root)}):
            with self.assertRaisesRegex(ValueError, "Git source selection failed:.*not a git repository"):
                tracked_sources(empty)

    def test_analyzer_commands_reject_removed_base_option(self):
        scripts = Path(__file__).resolve().parents[1]
        for command in (("sparse_smatch/smp.py", "sparse"),
                        ("sparse_smatch/smp.py", "smatch"),
                        ("style/checkpatch.py",), ("cppcheck/cppcheck.py",),
                        ("coccinelle/coccicheck.py",)):
            with self.subTest(command=command):
                result = subprocess.run(
                    [sys.executable, "-B", str(scripts / command[0]), *command[1:],
                     "--base", "HEAD"], cwd=self.root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("unrecognized arguments: --base", result.stderr)


if __name__ == "__main__":
    unittest.main()
