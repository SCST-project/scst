#!/usr/bin/env python3
"""Keep macro coverage limits from absorbing failures in ordinary source code."""

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coccinelle.frontend import macro_definition_error
from coccinelle.source import macros


class FrontendTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.addCleanup(macros.cache_clear)
        self.definition = "#define EACH(i) for (i = 0; i < 3; i++)"
        (self.root / "fixture.h").write_text(self.definition + "\n")
        self.lines = ["parse error ",
                      " = error in fixture.h; set verbose_parsing for more info",
                      "badcount: 1", "BAD:!!!!! " + self.definition, "HANDLING: next.c"]

    def test_only_the_complete_current_definition_is_a_coverage_limit(self):
        end, record = macro_definition_error(self.root, self.lines, 0)
        self.assertEqual(end, 4)
        self.assertEqual((record["file"], record["name"], record["line"]),
                         ("fixture.h", "EACH", 1))
        self.assertEqual(record["message"], "parse error")
        self.assertEqual(record["excerpt"], self.lines[:end])
        variants = [
            ["lexical error", *self.lines[1:]],
            ["semantic error unknown problem", *self.lines[1:]],
            [self.lines[0], self.lines[1].replace("fixture.h", "missing.h"), *self.lines[2:]],
            [self.lines[0], self.lines[1].replace("fixture.h", "../fixture.h"), *self.lines[2:]],
            [*self.lines[:3], "BAD:!!!!! EACH(i) { work(); }", self.lines[-1]],
            [*self.lines[:4], "bad: void lost_function(void) { work(); }", self.lines[-1]],
            [*self.lines[:4], "BAD:!!!!! void lost_function(void) { work(); }", self.lines[-1]],
            [*self.lines[:3], "BAD:!!!!! " + self.definition.replace("3", "4"), self.lines[-1]],
        ]
        for lines in variants:
            with self.subTest(lines=lines):
                self.assertIsNone(macro_definition_error(self.root, lines, 0))

    def test_definition_error_must_not_cover_a_preceding_lost_function(self):
        for prefix, allowed in (("void lost(void) {", False),
                                ("int lost = 1;", False),
                                ("void previous(void);", True), ("};", True)):
            with self.subTest(prefix=prefix):
                (self.root / "fixture.h").write_text(prefix + "\n" + self.definition + "\n")
                macros.cache_clear()
                lines = [*self.lines[:3], "bad: " + prefix, "BAD:!!!!! " + self.definition]
                result = macro_definition_error(self.root, lines, 0)
                self.assertEqual(result is not None, allowed)

    def test_multiline_definition_must_be_complete(self):
        definition = "#define EACH(i) \\\n for (i = 0; i < 3; i++)"
        (self.root / "fixture.h").write_text(definition + "\n")
        first, last = definition.splitlines()
        lines = [*self.lines[:3], "bad: " + first, "BAD:!!!!! " + last]
        self.assertIsNotNone(macro_definition_error(self.root, lines, 0))
        partial = [*self.lines[:3], "BAD:!!!!! " + last]
        self.assertIsNone(macro_definition_error(self.root, partial, 0))

    def test_storage_class_definition_is_limited_without_a_macro_name_allowlist(self):
        (self.root / "fixture.h").write_text("#define PRIVATE static\n")
        lines = ["semantic error storage class specified for macro type decl",
                 *self.lines[1:3], "BAD:!!!!! #define PRIVATE static"]
        result = macro_definition_error(self.root, lines, 0)
        self.assertEqual(result[1]["name"], "PRIVATE")

    def test_commented_definition_is_not_a_coverage_limit(self):
        (self.root / "fixture.h").write_text("/*\n" + self.definition + "\n*/\n")
        self.assertIsNone(macro_definition_error(self.root, self.lines, 0))


if __name__ == "__main__":
    unittest.main()
