#!/usr/bin/env python3
"""Protect the source exception inventory without reimplementing native matching."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cppcheck.exceptions import PROTECTED_IDS, source_exceptions, excluded_sources, excluded_diagnostic  # noqa: E402


class SourceExceptionsTest(unittest.TestCase):
    def parse(self, source):
        return source_exceptions(source, "scst/sample.c")

    def test_qlogic_scope_preserves_target_and_frontend_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("qla2x00t/legacy.h", "qla2x00t-32gbit/base.h",
                         "qla2x00t-32gbit/qla2x00-target/owned.h"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            policy = {"excluded_diagnostic_sources": [
                {"directory": "qla2x00t", "keep": [], "reason": "Legacy driver."},
                {"directory": "qla2x00t-32gbit", "keep": ["qla2x00t-32gbit/qla2x00-target"],
                 "reason": "Upstream driver."},
            ]}
            outside = excluded_sources(root, policy)
            self.assertEqual(set(outside), {"qla2x00t/legacy.h", "qla2x00t-32gbit/base.h"})
            diagnostic = {"id": "constVariablePointer", "locations": [{"file": "qla2x00t-32gbit/base.h"}]}
            self.assertEqual(excluded_diagnostic(root, diagnostic, outside), "Upstream driver.")
            for identifier in PROTECTED_IDS:
                self.assertIsNone(excluded_diagnostic(root, dict(diagnostic, id=identifier), outside))
            diagnostic["locations"].append({"file": "qla2x00t-32gbit/qla2x00-target/owned.h"})
            self.assertIsNone(excluded_diagnostic(root, diagnostic, outside))

    def test_native_inline_reason_and_symbol(self):
        entry, = self.parse(
            "/* cppcheck-suppress constParameterPointer symbolName=buf ; Writes via a page. */\n"
            "void write_buffer(char *buf);\n")
        self.assertEqual((entry["line"], entry["end_line"]), (2, 2))
        self.assertEqual(entry["symbol"], "buf")
        self.assertEqual(entry["reason"], "Writes via a page.")

    def test_inline_reason_does_not_fall_back_to_an_unrelated_comment(self):
        with self.assertRaisesRegex(ValueError, "requires a reason"):
            self.parse("/* Unrelated description. */\n"
                       "/* cppcheck-suppress unusedFunction ;  */\nvoid f(void);\n")

    def test_native_range_needs_a_matching_end(self):
        source = ("/* cppcheck-suppress-begin unusedFunction ; Optional debug API. */\n"
                  "void debug(void) {}\n"
                  "/* cppcheck-suppress-end unusedFunction */\nvoid outside(void) {}\n")
        entry, = self.parse(source)
        self.assertEqual((entry["line"], entry["end_line"]), (2, 2))
        with self.assertRaisesRegex(ValueError, "unterminated"):
            self.parse(source.replace("/* cppcheck-suppress-end unusedFunction */", ""))

    def test_line_macro_block_and_file_have_distinct_scopes(self):
        source = """/* File contract. */
/* cppcheck-suppress-file constParameterCallback */
/* The expansion exposes its writable backing store. */
/* cppcheck-suppress-macro constVariablePointer symbolName=buf */
/* CHECKPATCH: ignore COMPLEX_MACRO -- declaration */
#define BUFFER char *buf = storage
/* Both lines belong to a multiline declaration. */
/* cppcheck-suppress-begin constParameterPointer symbolName=arg */
void callback(
    char *arg);
/* cppcheck-suppress-end constParameterPointer symbolName=arg */
/* A retained error contract. */
/* cppcheck-suppress knownConditionTrueFalse */

/* A comment between the annotation and its target is native syntax. */
if (rc) return rc;
"""
        entries = self.parse(source)
        self.assertEqual([entry["scope"] for entry in entries],
                         ["file", "macro", "block", "line"])
        self.assertEqual([(entry["line"], entry["end_line"]) for entry in entries],
                         [(1, 16), (6, 6), (9, 10), (16, 16)])
        self.assertIn("expansions of BUFFER", entries[1]["target"])
        self.assertEqual(entries[1]["symbol"], "buf")
        self.assertEqual(entries[2]["end_comment_line"], 11)
        self.assertEqual(entries[3]["reason"], "A retained error contract.")

    def test_strings_are_not_suppressions(self):
        self.assertEqual(self.parse(
            'const char *s = "/* cppcheck-suppress syntaxError */";\n'), [])

    def test_multiline_reason_and_movement_keep_the_binding(self):
        source = """/*
 * Address conversion hides writes.
 * The buffer must remain writable.
 */
/* cppcheck-suppress constParameterPointer symbolName=buf */
void write_buffer(char *buf);
"""
        entry, = self.parse(source)
        moved, = self.parse("/* A new header. */\n\n" + source)
        self.assertEqual(moved["line"], entry["line"] + 2)
        self.assertEqual(entry["reason"],
                         "Address conversion hides writes. The buffer must remain writable.")
        self.assertEqual(entry["reason"], moved["reason"])

    def test_malformed_or_overbroad_annotations_fail(self):
        examples = [
            "/* cppcheck-suppress unusedFunction */\nvoid f(void);\n",
            "/* Reason. */\n/* cppcheck-suppress * */\nvoid f(void);\n",
            "/* Reason. */\n// cppcheck-suppress unusedFunction\nvoid f(void);\n",
            "/* Reason. */\n/* cppcheck-suppress-begin unusedFunction */\nvoid f(void);\n",
            "/* cppcheck-suppress-end unusedFunction */\n",
            "/* Reason. */\n/* cppcheck-suppress-macro unusedFunction */\nvoid f(void);\n",
            "int code;\n/* Reason. */\n/* cppcheck-suppress-file unusedFunction */\nint end;\n",
            "/* Reason. */\n/* cppcheck-suppress unusedFunction */\n",
            "/* Reason. */\n/* cppcheck-suppress-begin unusedFunction */\n"
            "/* cppcheck-suppress-end unusedFunction */\nvoid f(void);\n",
            "/* Reason. */\n/* cppcheck-suppress unusedFunction */ int f(void);\n",
        ]
        for source in examples:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.parse(source)

    def test_analysis_integrity_diagnostics_cannot_be_suppressed(self):
        for rule in PROTECTED_IDS:
            for suffix in ("", "-file", "-macro", "-begin"):
                with self.subTest(rule=rule, suffix=suffix), self.assertRaisesRegex(
                        ValueError, "analysis integrity"):
                    self.parse(f"/* Reason. */\n/* cppcheck-suppress{suffix} {rule} */\n"
                               "#define NEXT 1\n")

    def test_blocks_require_the_same_symbol_at_both_ends(self):
        with self.assertRaisesRegex(ValueError, "unmatched suppression end"):
            self.parse("/* Reason. */\n"
                       "/* cppcheck-suppress-begin constParameterPointer symbolName=one */\n"
                       "void f(char *one);\n"
                       "/* cppcheck-suppress-end constParameterPointer symbolName=two */\n")


if __name__ == "__main__":
    unittest.main()
