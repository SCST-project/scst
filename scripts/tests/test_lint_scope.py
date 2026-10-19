"""Exercise source selection against Git, including paths and renames."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lint_scope import changed_sources, git_pathspecs, in_scope, select_sources, tracked_sources


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

    def test_full_and_patch_scope_agree(self):
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
        names = self.git("diff", "--cached", "--name-only", "-z", "--", *git_pathspecs())
        self.assertEqual({os.fsdecode(n) for n in names.split(b"\0") if n}, set(kept))
        for name in excluded:
            with self.subTest(name=name), self.assertRaises(ValueError):
                select_sources(self.root, [self.root / name], None)
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.org",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "base")
        for name in (*kept, *excluded):
            (self.root / name).write_text("int changed(void);\n")
        self.assertEqual(set(changed_sources(self.root, "HEAD")), {self.root / n for n in kept})

    def test_alias_cannot_reinclude_qlogic_sources(self):
        kept = self.source("scst/kept.c")
        excluded = self.source("qla2x00t-32gbit/qla_target.c")
        for name, target in (("scst/vendor.c", excluded),
                             ("qla2x00t-32gbit/alias.c", kept)):
            alias = self.root / name
            alias.symlink_to(target)
            self.assertFalse(in_scope(alias, self.root))
            with self.assertRaises(ValueError):
                select_sources(self.root, [alias], None)

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
        self.assertEqual(select_sources(self.root, [new], None), [new])
        with self.assertRaises(ValueError):
            select_sources(self.root, [alias], None)

    def test_diff_checks_new_name_and_rejects_bad_base(self):
        self.source("scst/before.c")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.org",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "base")
        self.git("mv", "scst/before.c", "scst/after.c")
        self.assertEqual(changed_sources(self.root, "HEAD"), [self.root / "scst/after.c"])
        with self.assertRaises(subprocess.CalledProcessError):
            changed_sources(self.root, "missing-reference")

    def test_diff_requires_one_commit_even_when_the_worktree_is_clean(self):
        source = self.source("scst/core.c")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.org",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "base")
        for base in ("--quiet", "--exit-code", "--cached", "HEAD..HEAD", "HEAD^{tree}"):
            with self.subTest(base=base), self.assertRaises(subprocess.CalledProcessError):
                changed_sources(self.root, base)
        self.git("tag", "baseline")
        self.assertEqual(changed_sources(self.root, "baseline"), [])
        source.write_text("int changed(void);\n")
        self.assertEqual(changed_sources(self.root, "baseline"), [source])


if __name__ == "__main__":
    unittest.main()
