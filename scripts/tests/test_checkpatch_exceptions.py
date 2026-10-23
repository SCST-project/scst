#!/usr/bin/env python3
"""Check source binding without invoking Checkpatch or building the module."""

import copy
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer_policy import load  # noqa: E402
from style.exceptions import (  # noqa: E402
    apply_exceptions,
    effective_totals,
    source_exceptions,
)

MARKER = "/* CHECKPATCH: ignore COMPLEX_MACRO -- expands to initializer entries */\n"


class EffectiveTotalsTest(unittest.TestCase):
    def test_exempt_and_active_inputs_get_independent_totals(self):
        native = (
            "EXEMPT:COMPLEX_MACRO: declaration\n"
            "total: 1 errors, 0 warnings, 0 checks, 3 lines checked\n"
            "NOTE: For some of the reported defects, checkpatch may be able to\n"
            "      mechanically convert to the typical style using --fix or --fix-inplace.\n"
            "scst/a.h has style problems, please review.\n"
            "WARNING:SPACING: real finding\n"
            "#1: FILE: scst/b.c:1:\n+int  value;\n"
            "total: 0 errors, 1 warnings, 0 checks, 1 lines checked\n"
            "scst/b.c has style problems, please review.\n"
        )
        effective = effective_totals(native)
        self.assertIn("0 errors, 0 warnings, 0 checks; 1 exempt diagnostics", effective)
        self.assertIn("0 errors, 1 warnings, 0 checks; 0 exempt diagnostics", effective)
        self.assertIn("WARNING:SPACING: real finding\n#1: FILE: scst/b.c:1:", effective)
        self.assertNotIn("has style problems", effective)
        self.assertNotIn("--fix", effective)
        self.assertIn("total (before exemptions): 1 errors", effective)

    def test_unknown_tool_output_is_not_removed(self):
        self.assertEqual(effective_totals("unexpected checker failure\n"),
                         "unexpected checker failure\n")


class SourceExceptionsTest(unittest.TestCase):
    def test_comment_diagnostic_binds_comment_and_keeps_neighbours_visible(self):
        source = (
            "/* Keep the portable fallthrough comment. */\n"
            "/* checkpatch-suppress PREFER_FALLTHROUGH ; See the contract above. */\n"
            "/* fall through */\n"
            "case 2: work();\n"
            "/* fall through */\n")
        entry, = source_exceptions(source, "scst/a.c")
        self.assertEqual((entry["line"], entry["end_line"]), (3, 3))
        for line, rule, expected in ((1, "PREFER_FALLTHROUGH", True),
                                     (2, "PREFER_FALLTHROUGH", True),
                                     (3, "PREFER_FALLTHROUGH", True),
                                     (5, "PREFER_FALLTHROUGH", False),
                                     (2, "TYPO_SPELLING", False)):
            with self.subTest(line=line, rule=rule):
                report = (f"CHECK:{rule}: diagnostic\n#1: FILE: scst/a.c:{line}:\n"
                          f"+{source.splitlines()[line - 1]}\n\n"
                          "total: 0 errors, 0 warnings, 1 checks, 5 lines checked\n")
                _, counts, accounted = apply_exceptions(
                    report.encode(), Path("/repo"), {"scst/a.c": source})
                self.assertEqual(bool(counts), expected)
                self.assertEqual(accounted, expected)

    def test_quoted_title_exception_covers_only_the_following_comment(self):
        source = ("/* checkpatch-suppress TYPO_SPELLING ; Verbatim upstream title. */\n"
                  "/* See also commit: a title\n * with a historic typo.\n */\n"
                  "int typo;\n")
        entry, = source_exceptions(source, "scst/a.c")
        self.assertEqual((entry["line"], entry["end_line"]), (2, 4))

    def test_explicit_scopes_use_the_cppcheck_comment_convention(self):
        source = (
            "/* checkpatch-suppress-file CAMELCASE ; Upstream ABI names. */\n"
            "/* checkpatch-suppress-macro COMPLEX_MACRO ; Initializer entries. */\n"
            "#define ENTRIES ONE, \\\n"
            "    TWO\n"
            "/* checkpatch-suppress-begin LONG_LINE ; Aligned table. */\n"
            "struct entry table[] = {\n    { 1 },\n};\n"
            "/* checkpatch-suppress-end LONG_LINE */\n"
            "/* checkpatch-suppress VOLATILE ; Signal handler flag. */\n"
            "volatile int flag;\n")
        entries = source_exceptions(source, "scst/a.h")
        self.assertEqual([entry["scope"] for entry in entries],
                         ["file", "macro", "block", "line"])
        self.assertEqual([(entry["line"], entry["end_line"]) for entry in entries],
                         [(1, 11), (3, 4), (6, 8), (11, 11)])
        self.assertEqual(entries[2]["end_comment_line"], 9)

    def test_explicit_range_cannot_accept_missing_or_truncated_context(self):
        begin = "/* checkpatch-suppress-begin LONG_LINE ; Aligned table. */\n"
        end = "/* checkpatch-suppress-end LONG_LINE */\n"
        for source in (end, begin + "int a;\n", begin + end + "int a;\n",
                       begin + "int a;\n\0\nint b;\n" + end,
                       begin + "int a;\n" + begin + "int b;\n" + end):
            with self.subTest(source=source), self.assertRaises(ValueError):
                source_exceptions(source, "scst/a.c")

    def test_sense_block_accepts_only_tuple_definitions_and_comments(self):
        source = (
            "/* checkpatch-suppress-begin COMPLEX_MACRO ; Sense tuple arguments. */\n"
            "/* Key, ASC, ASCQ. */\n"
            "#define first NO_SENSE, 0, 0x00\n\n"
            "#define second ILLEGAL_REQUEST, 0xff, 255 /* Maximum byte values. */\n"
            "/* checkpatch-suppress-end COMPLEX_MACRO */\n"
            "#define outside ONE, TWO\n")
        for prefix in ("", "/* Moved. */\n\n"):
            with self.subTest(prefix=prefix):
                entry, = source_exceptions(prefix + source, "scst/a.h")
                offset = prefix.count("\n")
                self.assertEqual((entry["scope"], entry["line"], entry["end_line"]),
                                 ("block", 3 + offset, 5 + offset))

    def test_sense_block_rejects_unrelated_or_invalid_replacement_text(self):
        begin = "/* checkpatch-suppress-begin COMPLEX_MACRO ; Sense tuple arguments. */\n"
        end = "/* checkpatch-suppress-end COMPLEX_MACRO */\n"
        valid = "#define valid NOT_READY, 0x04, 0x01\n"
        for invalid in (
                "#define bad(x) NOT_READY, 0, 0\n",
                "#define bad NOT_READY, 0\n",
                "#define bad NOT_READY, 0, 0, 0\n",
                "#define bad UNKNOWN_KEY, 0, 0\n",
                "#define bad NOT_READY, 256, 0\n",
                "#define bad NOT_READY, 0, 0x100\n",
                "#define bad NOT_READY, -1, 0\n",
                "#define bad NOT_READY, 0 + 1, 0\n",
                "#define bad NOT_READY, call(), 0\n",
                '#define bad NOT_READY, "hidden" 0, 0\n',
                "#define bad NOT_READY, 'x', 0\n",
                "#define bad NOT_READY, \\\n0, 0\n",
                "#if 0\n#define bad ONE, TWO\n#endif\n",
                "int unrelated;\n",
                '"hidden before the first definition"\n'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                source_exceptions(begin + invalid + valid + end, "scst/a.h")
        with self.assertRaises(ValueError):
            source_exceptions(begin + "/* No definitions. */\n" + end, "scst/a.h")

    def test_constant_blocks_keep_neighbouring_and_other_rules_visible(self):
        for rule, definition in (("COMPLEX_MACRO", "#define sense NOT_READY, 0x04, 0"),
                                  ("BIT_MACRO", "#define flag (1U << 3)")):
            source = (f"{definition}\n"
                      f"/* checkpatch-suppress-begin {rule} ; Constant group. */\n"
                      f"{definition}\n"
                      f"/* checkpatch-suppress-end {rule} */\n"
                      f"{definition}\n")
            for line, reported, expected in ((1, rule, False), (3, rule, True),
                                              (5, rule, False), (3, "SPACING", False)):
                with self.subTest(rule=rule, line=line, reported=reported):
                    report = (f"WARNING:{reported}: diagnostic\n"
                              f"#1: FILE: scst/a.h:{line}:\n+{definition}\n\n"
                              "total: 0 errors, 1 warnings, 0 checks, 5 lines checked\n")
                    _, counts, accounted = apply_exceptions(
                        report.encode(), Path("/repo"), {"scst/a.h": source})
                    self.assertEqual(bool(counts), expected)
                    self.assertEqual(accounted, expected)

    def test_plain_suppression_does_not_implicitly_expand_to_a_macro(self):
        source = ("/* checkpatch-suppress SPACING ; Token expression. */\n"
                  "#define EXPR \\\n    ONE+TWO\n")
        entry, = source_exceptions(source, "scst/a.h")
        self.assertEqual((entry["scope"], entry["line"], entry["end_line"]), ("line", 2, 2))

    def test_binds_one_whole_macro_after_movement(self):
        source = MARKER + "#define FIRST \\\n\tONE, \\\n\tTWO\n#define SECOND THREE, FOUR\n"
        for prefix in ("", "/* Moved. */\n\n"):
            entry, = source_exceptions(prefix + source, "scst/moved.h")
            offset = prefix.count("\n")
            self.assertEqual((entry["macro"], entry["line"], entry["end_line"]),
                             ("FIRST", 2 + offset, 4 + offset))
            self.assertEqual(entry["reason"], "expands to initializer entries")

    def test_literals_are_not_exception_comments(self):
        source = 'const char *s = "' + MARKER.strip() + '";\n#define FIRST ONE, TWO\n'
        self.assertEqual(source_exceptions(source, "scst/sample.c"), [])

    def test_rejects_invalid_or_detached_markers(self):
        for source in (
                MARKER.replace("COMPLEX_MACRO", "spacing") + "#define FIRST ONE, TWO\n",
                MARKER.replace("expands to initializer entries", " ") + "#define FIRST ONE, TWO\n",
                MARKER + "\n#define FIRST ONE, TWO\n",
                MARKER + "int value;\n#define FIRST ONE, TWO\n",
                "int value; " + MARKER + "#define FIRST ONE, TWO\n",
                "#define OUTER \\\n" + MARKER + "#define FIRST ONE, TWO\n",
                "/* CHECKPATCH: ignore COMPLEX_MACRO -- unfinished\n",
                MARKER + "/* #define FIRST ONE, TWO */\n",
                MARKER + "#define FIRST ONE, \\",
                MARKER):
            with self.subTest(source=source), self.assertRaises(ValueError):
                source_exceptions(source, "scst/sample.c")

    def test_next_line_does_not_exempt_a_neighbour_or_another_rule(self):
        source = ("/* CHECKPATCH: ignore VOLATILE -- signal handler flag */\n"
                  "volatile int flag;\nvolatile int other;\n")
        def report(rule, line, code):
            return (f"WARNING:{rule}: diagnostic\n#1: FILE: scst/a.c:{line}:\n"
                    f"+{code}\n\ntotal: 0 errors, 1 warnings, 0 checks, 3 lines checked\n").encode()
        for rule, line, code, expected in (
                ("VOLATILE", 2, "volatile int flag;", True),
                ("VOLATILE", 3, "volatile int other;", False),
                ("SPACING", 2, "volatile int flag;", False),
                ("VOLATILE", 2, "volatile int changed;", False)):
            with self.subTest(rule=rule, line=line, code=code):
                selected, exempt, accounted = apply_exceptions(
                    report(rule, line, code), Path("/repo"), {"scst/a.c": source})
                self.assertEqual(accounted, expected)
                self.assertEqual(bool(exempt), expected)
                self.assertEqual(b"EXEMPT:" in selected, expected)

    def test_stacked_rules_bind_the_same_complete_macro(self):
        source = (MARKER + "/* CHECKPATCH: ignore SPACING -- operator tokens */\n"
                  "#define FIRST \\\n\tONE, TWO\n#define SECOND THREE, FOUR\n")
        entries = source_exceptions(source, "scst/a.h")
        self.assertEqual([entry["rule"] for entry in entries], ["COMPLEX_MACRO", "SPACING"])
        self.assertTrue(all(entry["line"] == 3 and entry["end_line"] == 4 for entry in entries))

    def test_context_rules_verify_both_source_lines(self):
        source = ("int count;\n/* CHECKPATCH: ignore LINE_SPACING -- declaration */\n"
                  "DECLARE(value);\n")
        report = ("WARNING:LINE_SPACING: diagnostic\n#3: FILE: scst/a.c:3:\n"
                  "+/* CHECKPATCH: ignore LINE_SPACING -- declaration */\n"
                  "+DECLARE(value);\n\ntotal: 0 errors, 1 warnings, 0 checks, 3 lines checked\n")
        self.assertTrue(apply_exceptions(report.encode(), Path("/repo"),
                                         {"scst/a.c": source})[2])
        patch_context = report.replace("+/* CHECKPATCH:", " /* CHECKPATCH:").encode()
        self.assertTrue(apply_exceptions(patch_context, Path("/repo"),
                                         {"scst/a.c": source})[2])
        stale = report.replace("+DECLARE(value)", "+DECLARE(other)").encode()
        self.assertFalse(apply_exceptions(stale, Path("/repo"), {"scst/a.c": source})[2])

    def test_layout_exception_is_scoped_and_requires_exact_source(self):
        policy = copy.deepcopy(load("checkpatch"))
        policy["macro_body_layouts"] = [{"file_glob": "scst/*", "macro": "FIXTURE_STATE_TABLE",
                                        "first_entry_pattern": r"FIXTURE_ENTRY\(.*",
                                        "reason": "Fixture declaration table."}]
        source = "FIXTURE_STATE_TABLE(table, 0,\n\tFIXTURE_ENTRY(next, 0)\n);\n"
        report = ("CHECK:PARENTHESIS_ALIGNMENT: Alignment should match open parenthesis\n"
                  "#2: FILE: scst/a.c:2:\n+FIXTURE_STATE_TABLE(table, 0,\n"
                  "+\tFIXTURE_ENTRY(next, 0)\n\n"
                  "total: 0 errors, 0 warnings, 1 checks, 3 lines checked\n")
        def check(text, code, path="scst/a.c"):
            return apply_exceptions(text.encode(), Path("/repo"), {path: code}, policy)[2]
        self.assertTrue(check(report, source))
        for old, new in (("FIXTURE_STATE_TABLE", "ordinary_call"),
                         ("FIXTURE_ENTRY", "ordinary_entry"), ("+\t", "+  "),
                         ("PARENTHESIS_ALIGNMENT", "SPACING")):
            with self.subTest(old=old):
                changed = report.replace(old, new)
                self.assertFalse(check(changed, source.replace(old, new)))
        self.assertFalse(check(report, source.replace("next", "changed")))
        self.assertFalse(check(report.replace("scst/a.c", "tools/a.c"), source, "tools/a.c"))
        policy["macro_body_layouts"] = []
        self.assertFalse(check(report, source))


    def test_file_exception_requires_a_complete_header_and_reports_its_scope(self):
        marker = "/* CHECKPATCH: ignore-file CAMELCASE -- mirror upstream names */\n"
        source = "/* License. */\n" + marker + "#ifndef A_H\nint inputSize;\n#endif\n"
        entry, = source_exceptions(source, "scst/a.h")
        self.assertEqual((entry["scope"], entry["target"], entry["line"], entry["end_line"]),
                         ("file", "scst/a.h", 1, 5))
        for prefix in ("int preceding;\n", "#ifndef A_H\n", "\0\n"):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                source_exceptions(prefix + marker + "int inputSize;\n", "scst/a.h")

    def test_block_tracks_nested_delimiters_and_ignores_literals(self):
        marker = "/* CHECKPATCH: ignore-block LONG_LINE -- aligned rows */\n"
        source = (marker + "static const struct entry entries[] = {\n"
                  '    { .text = "};", .value = CALL((1 + 2), (int[]){3, 4}) },\n'
                  "    /* }; does not close the initializer. */\n"
                  "};\nint neighbour;\n")
        entry, = source_exceptions(source, "scst/a.c")
        self.assertEqual((entry["scope"], entry["target"], entry["line"], entry["end_line"]),
                         ("block", "entries", 2, 5))
        for kind in ("struct", "union", "enum"):
            body = "int field;" if kind != "enum" else "VALUE,"
            entry, = source_exceptions(marker + f"{kind} item {{ {body} }};\n",
                                       "scst/a.h")
            self.assertEqual(entry["target"], f"{kind} item")
        entry, = source_exceptions(
            marker + "typedef union { struct { int x; } member; } __orio_packed value_t;\n",
            "scst/a.h")
        self.assertEqual(entry["target"], "typedef value_t")

    def test_block_rejects_ambiguous_or_incomplete_constructs(self):
        marker = "/* CHECKPATCH: ignore-block LONG_LINE -- aligned rows */\n"
        for code in ("void function(void) {}\n", "int plain;\n",
                     "struct forward;\nstruct later { int field; };\n",
                     "struct item {\nint field;\n", "struct item { int field; }\n",
                     "struct item { int field; }; int other;\n",
                     "struct item {\n\0\n};\n",
                     "struct item {\n#if ENABLED\nint field;\n#endif\n};\n",
                     "int table[] = { CALL(1, 2] };\n"):
            with self.subTest(code=code), self.assertRaises(ValueError):
                source_exceptions(marker + code, "scst/a.h")

    def test_scoped_exceptions_do_not_leak_to_other_rules_files_or_blocks(self):
        for action in ("ignore-file", "ignore-block"):
            source = (f"/* CHECKPATCH: {action} LONG_LINE -- aligned rows */\n"
                      "struct item {\n    int field;\n};\nint neighbour;\n")
            for rule, path, line, quoted, expected in (
                    ("LONG_LINE", "scst/a.h", 3, "    int field;", True),
                    ("LONG_LINE_COMMENT", "scst/a.h", 3, "    int field;", False),
                    ("LONG_LINE", "scst/other.h", 3, "    int field;", False),
                    ("LONG_LINE", "scst/a.h", 3, "    int changed;", False),
                    ("LONG_LINE", "scst/a.h", 5, "int neighbour;", action == "ignore-file")):
                report = (f"CHECK:{rule}: diagnostic\n#1: FILE: {path}:{line}:\n"
                          f"+{quoted}\n\ntotal: 0 errors, 0 warnings, 1 checks, 5 lines checked\n")
                with self.subTest(action=action, rule=rule, path=path, line=line):
                    selected, _, accounted = apply_exceptions(
                        report.encode(), Path("/repo"), {"scst/a.h": source})
                    self.assertEqual(accounted, expected)
                    self.assertEqual(b"EXEMPT:" in selected, expected)

    def test_stacked_block_rules_and_incomplete_source(self):
        markers = ("/* CHECKPATCH: ignore-block LONG_LINE -- aligned rows */\n"
                   "/* CHECKPATCH: ignore-block LONG_LINE_COMMENT -- field descriptions */\n")
        entries = source_exceptions(markers + "struct item {\nint field;\n};\n", "scst/a.h")
        self.assertTrue(all(entry["line"] == 3 and entry["end_line"] == 5 for entry in entries))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            source_exceptions(markers + "struct item {\nint field;\n", "scst/a.h")



class WrappedExceptionsTest(unittest.TestCase):
    def test_wrapped_reason_binds_only_the_following_source_line(self):
        marker = ("/*\n * checkpatch-suppress\n * LONG_LINE ; Keep the complete\n"
                  " * diagnostic searchable.\n */\n")
        source = marker + "TRACE_DBG(message);\nTRACE_DBG(other);\n"
        entry, = source_exceptions(source, "scst/a.c")
        self.assertEqual((entry["line"], entry["end_line"]), (6, 6))
        self.assertEqual(entry["reason"], "Keep the complete diagnostic searchable.")
        for line, text, expected in ((6, "TRACE_DBG(message);", True),
                                      (7, "TRACE_DBG(other);", False)):
            report = (f"CHECK:LONG_LINE: Long diagnostic\n"
                      f"#{line}: FILE: scst/a.c:{line}:\n+{text}\n\n"
                      "total: 0 errors, 0 warnings, 1 checks, 7 lines checked\n")
            self.assertEqual(apply_exceptions(report.encode(), Path("/repo"),
                                             {"scst/a.c": source})[2], expected)
        for code in ("call(); " + source, source.replace(" */\n", " */ call();\n")):
            with self.subTest(code=code), self.assertRaises(ValueError):
                source_exceptions(code, "scst/a.c")

    def test_unterminated_end_marker_is_not_repaired_by_normalization(self):
        source = ("/* checkpatch-suppress-begin LONG_LINE ; Layout. */\n"
                  "call();\n/* checkpatch-suppress-end LONG_LINE")
        with self.assertRaisesRegex(ValueError, "standalone"):
            source_exceptions(source, "scst/a.c")


class SymbolExceptionsTest(unittest.TestCase):
    def test_reviewed_symbol_does_not_waive_new_names_or_other_rules(self):
        anchor = ("/* checkpatch-suppress-symbol CAMELCASE symbolName=knownName ; Public ABI. */\n"
                  "void knownName(void);\n")
        source = "knownName(newName);\n"
        for rule, symbol, expected in (("CAMELCASE", "knownName", True),
                                       ("CAMELCASE", "newName", False),
                                       ("OTHER", "knownName", False)):
            report = (f"CHECK:{rule}: Avoid CamelCase: <{symbol}>\n"
                      "#1: FILE: scst/use.c:1:\n+knownName(newName);\n\n"
                      "total: 0 errors, 0 warnings, 1 checks, 1 lines checked\n")
            _, counts, accounted = apply_exceptions(
                report.encode(), Path('/repo'), {'scst/use.c': source},
                symbol_sources={'scst/api.h': anchor})
            self.assertEqual(bool(counts), expected)
            self.assertEqual(accounted, expected)
        changed = anchor.replace('void knownName', 'void otherName')
        with self.assertRaises(ValueError):
            source_exceptions(changed, 'scst/api.h')

    def test_symbol_scope_requires_one_exact_identifier_and_camelcase_rule(self):
        for marker in ('CAMELCASE', 'VOLATILE symbolName=knownName',
                       'CAMELCASE symbolName=known.*'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                source_exceptions(f'/* checkpatch-suppress-symbol {marker} ; ABI. */\n'
                                  'void knownName(void);\n', 'scst/api.h')

    def test_anchor_line_cannot_exempt_an_unrelated_identifier(self):
        source = ('/* checkpatch-suppress-symbol CAMELCASE symbolName=knownName ; ABI. */\n'
                  'knownName(newName);\n')
        report = ('CHECK:CAMELCASE: Avoid CamelCase: <newName>\n'
                  '#1: FILE: scst/api.h:2:\n+knownName(newName);\n\n'
                  'total: 0 errors, 0 warnings, 1 checks, 2 lines checked\n')
        self.assertFalse(apply_exceptions(report.encode(), Path('/repo'),
                                         {'scst/api.h': source})[1])


if __name__ == "__main__":
    unittest.main()
