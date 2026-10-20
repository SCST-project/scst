#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "tree-sitter==0.25.2",
#     "tree-sitter-c==0.24.1",
# ]
# ///

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tree_sitter as ts
import tree_sitter_c
from scs_lint import check_source, main


class KUnitVisibilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = ts.Parser(ts.Language(tree_sitter_c.language()))

    def violations(self, src: bytes) -> list:
        return check_source(src, self.parser)

    def test_rejects_shared_type_signature_and_attribute_lines(self):
        for declaration in (
                b"SCST_KUNIT_VISIBLE void\nfn(void)",
                b"SCST_KUNIT_VISIBLE void fn(void)",
                b"SCST_KUNIT_VISIBLE __printf(1, 2)\nvoid fn(const char *fmt, ...)",
                b"__maybe_unused SCST_KUNIT_VISIBLE\nvoid fn(void)"):
            with self.subTest(declaration=declaration):
                errors = self.violations(declaration + b"\n{\n}\n")
                self.assertEqual(len(errors), 1)
                self.assertEqual(errors[0].line, 1)
                self.assertEqual(errors[0].rule, "SCS.1")

    def test_accepts_standalone_definition_and_prototype(self):
        src = (b"SCST_KUNIT_VISIBLE\nvoid fn(void) {}\n"
               b"SCST_KUNIT_VISIBLE\nvoid other(void);\n")
        self.assertEqual(self.violations(src), [])

    def test_checks_inline_wrapper_and_direct_kernel_annotation(self):
        for annotation in (b"SCST_KUNIT_VISIBLE_INLINE", b"VISIBLE_IF_KUNIT"):
            self.assertEqual(self.violations(annotation + b"\nvoid fn(void);\n"), [])
            self.assertEqual(len(self.violations(annotation + b" void fn(void);\n")), 1)

    def test_does_not_enforce_attribute_layout(self):
        src = (b"SCST_KUNIT_VISIBLE\n"
               b"__printf(1, 2) void fn(const char *fmt, ...);\n")
        self.assertEqual(self.violations(src), [])

    def test_ignores_comments_literals_and_macro_definitions(self):
        src = (b"/* SCST_KUNIT_VISIBLE void fn(void); */\n"
               b"// SCST_KUNIT_VISIBLE void fn(void);\n"
               b'const char *text = "SCST_KUNIT_VISIBLE void";\n'
               b"#define SCST_KUNIT_VISIBLE static\n"
               b"#define VISIBILITY SCST_KUNIT_VISIBLE\n")
        self.assertEqual(self.violations(src), [])

    def test_allows_comments_beside_macro_without_hiding_code(self):
        src = (b"/* before */ SCST_KUNIT_VISIBLE /* after */\nvoid fn(void);\n"
               b"SCST_KUNIT_VISIBLE // after\nvoid other(void);\n"
               b"SCST_KUNIT_VISIBLE /* note */ void bad(void);\n")
        self.assertEqual([error.line for error in self.violations(src)], [5])

    def test_handles_last_line_without_newline(self):
        errors = self.violations(b"SCST_KUNIT_VISIBLE void fn(void);")
        self.assertEqual([(error.line, error.column) for error in errors], [(1, 1)])

    def test_checks_all_preprocessor_branches(self):
        src = (b"#if 0\n"
               b"SCST_KUNIT_VISIBLE void inactive(void);\n"
               b"#else\nSCST_KUNIT_VISIBLE void active(void);\n#endif\n")
        self.assertEqual([error.line for error in self.violations(src)], [2, 4])

    def test_ignores_multiline_directives_and_macro_bodies(self):
        src = (b"#define DECLARE() \\\n"
               b"SCST_KUNIT_VISIBLE void fn(void);\n"
               b"#if defined(SCST_KUNIT_VISIBLE) && \\\n"
               b"    SCST_KUNIT_VISIBLE\n"
               b"SCST_KUNIT_VISIBLE void bad(void);\n"
               b"#elif defined(SCST_KUNIT_VISIBLE)\n"
               b"SCST_KUNIT_VISIBLE\nvoid good(void);\n"
               b"#endif\n"
               b"#undef SCST_KUNIT_VISIBLE\n")
        self.assertEqual([error.line for error in self.violations(src)], [5])

    def test_keeps_positions_after_multiline_comment(self):
        src = (b"/* SCST_KUNIT_VISIBLE\ncomment */\n"
               b"    SCST_KUNIT_VISIBLE void bad(void);\n")
        self.assertEqual([(error.line, error.column) for error in self.violations(src)], [(3, 5)])


class CommandTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="scs-lint-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        environment = mock.patch.dict("os.environ", {"DIFFBR": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def source(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run_lint(self, files, base=None):
        out = io.StringIO()
        err = io.StringIO()
        with (contextlib.redirect_stdout(out), contextlib.redirect_stderr(err),
              mock.patch("scs_lint.REPOSITORY", self.root)):
            status = main([str(path) for path in files] + (["--base", base] if base else []))
        return status, out.getvalue(), err.getvalue()

    def report(self):
        return json.loads((self.root / ".cache/lint/scs_lint.json").read_text())

    def test_reports_bad_file_and_checks_other_files(self):
        bad = self.source("scst/bad.c", "SCST_KUNIT_VISIBLE void bad(void);\n")
        good = self.source("scst/good.h", "SCST_KUNIT_VISIBLE\nvoid good(void);\n")
        status, out, err = self.run_lint([good, bad])
        self.assertEqual(status, 1)
        self.assertIn(f"{bad}:1:1: error: SCS.1:", out)
        self.assertNotIn(str(good), out)
        self.assertIn("1 violation(s), 2 file(s) checked", err)
        self.assertEqual(self.report()["outcome"], "findings")
        self.assertEqual(self.report()["checked_files"], ["scst/bad.c", "scst/good.h"])
        self.assertEqual(self.report()["exit_code"], 1)

    def test_accepts_explicit_untracked_file_and_deduplicates(self):
        path = self.source("scst/new.c", "SCST_KUNIT_VISIBLE\nvoid good(void);\n")
        status, out, err = self.run_lint([path, path])
        self.assertEqual((status, out), (0, ""))
        self.assertIn("0 violation(s), 1 file(s) checked", err)

    def test_explicit_outside_scope_is_an_error(self):
        path = self.source("scripts/example.c", "SCST_KUNIT_VISIBLE void bad(void);\n")
        status, out, err = self.run_lint([path])
        self.assertEqual(status, 2)
        self.assertIn("not a project C source/header", err)

    def test_default_skips_working_tree_deletions(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        source = self.source("scst/deleted.c", "int deleted(void);\n")
        subprocess.run(["git", "-C", str(self.root), "add", str(source)], check=True)
        source.unlink()
        status, out, err = self.run_lint([])
        self.assertEqual((status, out), (0, ""))
        self.assertIn("0 file(s) checked", err)
        self.assertEqual(self.report()["outcome"], "skipped")

    def test_changed_files_only_and_no_source_changes_skip(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        changed = self.source("scst/changed.c", "SCST_KUNIT_VISIBLE\nvoid good(void);\n")
        unchanged = self.source("scst/unchanged.h", "SCST_KUNIT_VISIBLE void bad(void);\n")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.com", "commit", "-qm", "Fixture"],
                       check=True)
        self.assertEqual(self.run_lint([], base="HEAD")[0], 0)
        self.assertEqual(self.report()["outcome"], "skipped")
        changed.write_text("SCST_KUNIT_VISIBLE void changed(void);\n")
        status, out, _ = self.run_lint([], base="HEAD")
        self.assertEqual(status, 1)
        self.assertNotIn(str(unchanged), out)
        self.assertEqual(self.report()["checked_files"], ["scst/changed.c"])

    def test_unreadable_file_preserves_earlier_findings_but_fails_analysis(self):
        first = self.source("scst/a.c", "SCST_KUNIT_VISIBLE void bad(void);\n")
        second = self.source("scst/z.c", "void other(void);\n")
        read_bytes = Path.read_bytes

        def read(path):
            if path == second:
                raise PermissionError("cannot read z.c")
            return read_bytes(path)

        with mock.patch.object(Path, "read_bytes", read):
            status, out, err = self.run_lint([first, second])
        self.assertEqual(status, 2)
        self.assertIn("SCS.1", out)
        self.assertIn("cannot read z.c", err)
        self.assertEqual(self.report()["outcome"], "incomplete")
        self.assertEqual(self.report()["checked_files"], ["scst/a.c"])
        self.assertEqual(self.report()["remaining"], 1)
        log = (self.root / ".cache/lint/scs_lint.log").read_text()
        self.assertIn("SCS.1", log)
        self.assertIn("cannot read z.c", log)

    def test_invalid_input_is_not_a_clean_result(self):
        unsupported = self.source("example.txt", "void good(void);\n")
        for path in (self.root / "missing.c", unsupported, self.root):
            with self.subTest(path=path):
                status, out, err = self.run_lint([path])
                self.assertEqual((status, out), (2, ""))
                self.assertIn("not a project C source/header", err)
                self.assertNotIn("0 violation(s)", err)

    def test_unavailable_default_repository_is_an_error(self):
        self.root = self.root / "missing"
        status, out, err = self.run_lint([])
        self.assertEqual((status, out), (2, ""))
        self.assertIn("scs_lint:", err)


if __name__ == "__main__":
    unittest.main()
