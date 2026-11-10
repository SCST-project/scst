# SPDX-License-Identifier: GPL-2.0-only
"""Exercise kernel preparation with real patch/make and temporary fixtures."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HELPERS = Path(__file__).resolve().with_name("kernel-functions")
PATCH = """--- a/example
+++ b/example
@@ -1,3 +1,3 @@
 before
-old
+new
 after
"""
LEXER = """#include "srcpos.h"
#include "dtc-parser.tab.h"

YYLTYPE yylloc;
extern bool treesource_error;

/* CAUTION: this will stop working if we ever use yyless() or yyunput() */
"""
SUBCMD = """static inline void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret && !size)
		ret = realloc(ptr, 1);
	if (!ret) {
		ret = realloc(ptr, size);
		if (!ret && !size)
			ret = realloc(ptr, 1);
		if (!ret)
			die("Out of memory, realloc failed");
	}
	return ret;
}
"""
SUBCMD_FIXED = """static inline void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret)
		die("Out of memory, realloc failed");
	return ret;
}
"""


class KernelPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scst kernel preparation ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def run_helper(self, command, patch=None):
        return subprocess.run(
            ["bash", "-c", 'source "$1" || exit; ' + command, "test", str(HELPERS)],
            cwd=self.root, input=patch, text=True, capture_output=True, timeout=30,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.root.rglob("*.rej")), [])

    def test_apply_and_skip_already_applied_patch(self):
        path = self.write("example", "before\nold\nafter\n")
        for _ in range(2):
            self.assert_success(self.run_helper("apply_kernel_compat_patch", PATCH))
            self.assertEqual(path.read_text(), "before\nnew\nafter\n")

    def test_conflicting_patch_does_not_partially_modify_files(self):
        first = self.write("example", "before\nold\nafter\n")
        second = self.write("conflict", "unrelated\n")
        patch = PATCH + PATCH.replace("example", "conflict")
        result = self.run_helper("apply_kernel_compat_patch", patch)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("neither applies nor is already applied", result.stderr)
        self.assertEqual(first.read_text(), "before\nold\nafter\n")
        self.assertEqual(second.read_text(), "unrelated\n")
        self.assertEqual(list(self.root.rglob("*.rej")), [])

    def test_missing_patch_target_is_an_error(self):
        result = self.run_helper("apply_kernel_compat_patch", PATCH)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "example").exists())

    def test_stable_backports_and_partial_dtc_backport(self):
        lexer = self.write("scripts/dtc/dtc-lexer.l", LEXER.replace("YYLTYPE yylloc;\n", ""))
        shipped = self.write("scripts/dtc/dtc-lexer.lex.c_shipped", LEXER)
        subcmd = self.write("tools/lib/subcmd/subcmd-util.h", SUBCMD_FIXED)
        for _ in range(2):
            self.assert_success(self.run_helper("patch_kernel 4.9.337"))
            self.assertEqual(lexer.read_text(), LEXER.replace("YYLTYPE yylloc;\n", ""))
            self.assertEqual(shipped.read_text(), lexer.read_text())
            self.assertEqual(subcmd.read_text(), SUBCMD_FIXED)

    def test_apply_missing_backports_without_shipped_lexer(self):
        lexer = self.write("scripts/dtc/dtc-lexer.l", LEXER)
        subcmd = self.write("tools/lib/subcmd/subcmd-util.h", SUBCMD)
        self.assert_success(self.run_helper("patch_kernel 4.9"))
        self.assertNotIn("YYLTYPE yylloc;", lexer.read_text())
        self.assertEqual(subcmd.read_text(), SUBCMD_FIXED)

    def test_absent_optional_sources_are_skipped(self):
        self.assert_success(self.run_helper("patch_kernel 4.9"))

    def test_old_lexer_without_treesource_error(self):
        original = LEXER.replace("extern bool treesource_error;\n", "")
        lexer = self.write("scripts/dtc/dtc-lexer.l", original)
        for _ in range(2):
            self.assert_success(self.run_helper("patch_kernel 4.9"))
            self.assertEqual(lexer.read_text(), original.replace("YYLTYPE yylloc;\n", ""))

    def test_patch_kernel_propagates_patch_failure(self):
        self.write("scripts/dtc/dtc-lexer.l", "unexpected source\n")
        subcmd = self.write("tools/lib/subcmd/subcmd-util.h", SUBCMD)
        result = self.run_helper("patch_kernel 4.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(subcmd.read_text(), SUBCMD)

    def test_purgatory_preserves_dialect_without_tracing_flags(self):
        path = self.write("arch/x86/purgatory/Makefile", "KBUILD_CFLAGS := -Os -ffreestanding\n")
        for _ in range(2):
            self.assert_success(self.run_helper("preserve_purgatory_c_standard"))
        self.assertEqual(path.read_text().count("$(filter -std=%,$(KBUILD_CFLAGS))"), 1)
        for dialect in ("gnu89", "gnu11", "gnu17"):
            with self.subTest(dialect=dialect):
                self.write("Makefile", f"KBUILD_CFLAGS := -std={dialect} -pg -fstack-protector\n"
                           "include arch/x86/purgatory/Makefile\n"
                           "all:\n\t@echo $(KBUILD_CFLAGS)\n")
                result = subprocess.run(["make", "-s"], cwd=self.root, capture_output=True,
                                        text=True, timeout=30)
                self.assert_success(result)
                self.assertEqual(result.stdout.strip(), f"-std={dialect} -Os -ffreestanding")

    def test_modern_and_explicit_purgatory_flags_are_unchanged(self):
        for flags in ("$(filter-out -pg,$(KBUILD_CFLAGS))", "-std=gnu11 -Os"):
            with self.subTest(flags=flags):
                original = "KBUILD_CFLAGS := " + flags + "\n"
                path = self.write("arch/x86/purgatory/Makefile", original)
                self.assert_success(self.run_helper("preserve_purgatory_c_standard"))
                self.assertEqual(path.read_text(), original)


if __name__ == "__main__":
    unittest.main()
