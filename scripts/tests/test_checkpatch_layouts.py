"""Keep source-form exceptions narrower than their native diagnostic rules."""

import copy
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer_policy import load  # noqa: E402
from style.exceptions import apply_exceptions  # noqa: E402
from style.layouts import source_layouts  # noqa: E402


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.policy = copy.deepcopy(load("checkpatch"))

    def locations(self, source, name="scst/a.c"):
        return source_layouts(source, name, self.policy)

    def test_complete_version_predicates_include_continuations_and_vendor_guards(self):
        source = ("#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 97) || \\\n"
                  " (defined(RHEL_MAJOR) && RHEL_MAJOR - 0 == 9 && RHEL_MINOR - 0 >= 7) || \\\n"
                  " (defined(UTS_UBUNTU_RELEASE_ABI) && \\\n"
                  "  LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(6, 8, 0) >> 8 && \\\n"
                  "  UTS_UBUNTU_RELEASE_ABI - 0 >= 147))\n"
                  "int body;\n"
                  "#elif !defined(FMODE_FSNOTIFY_HSM) && \\\n"
                  " RHEL_RELEASE_CODE - 0 < RHEL_RELEASE_VERSION(9, 7)\n"
                  "#endif\n")
        expected = {("CONSTANT_COMPARISON", n) for n in (*range(1, 6), 7, 8)}
        self.assertEqual(set(self.locations(source)), expected)
        self.assertEqual(set(self.locations("/* Moved. */\n" + source)),
                         {(rule, line + 1) for rule, line in expected})
        self.assertTrue(self.locations("#if(LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0))\n"))
        self.assertTrue(self.locations("#if LINUX_VERSION_CODE /* version */ < KERNEL_VERSION(6, 0, 0)\n"))
        self.assertTrue(self.locations("#if LINUX_VERSION_CODE /\\\n* version */ < KERNEL_VERSION(6, 0, 0)\n"))

    def test_version_policy_rejects_partial_unknown_or_mixed_expressions(self):
        comparison = "LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)"
        for expression in (
                comparison + " && 0 < value", comparison + " || ordinary()",
                comparison + " && CONFIG_UNKNOWN", comparison + " || 1",
                "(" + comparison, comparison + ")", comparison + " + 1",
                comparison + " ? 0 : 1", comparison + "; int unrelated;",
                comparison.replace("6, 0, 0", "major, 0, 0"),
                comparison.replace("6, 0, 0", "6, 0"),
                comparison.replace("KERNEL_VERSION", "OTHER_VERSION"),
                comparison.replace("LINUX_VERSION_CODE", "SOME_VERSION_CODE"),
                comparison.replace("LINUX_VERSION_CODE", "!LINUX_VERSION_CODE"),
                "LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(6, 0, 0)",
                "LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(6, 0, 0) >> 16",
                'RHEL_MAJOR - 0 == "hidden" 9', "RHEL_MAJOR == '9'",
                "RHEL_MAJOR == 9 + 1", "RHEL_MAJOR == 09",
                "defined(FEATURE)", comparison + " && defined(123)"):
            with self.subTest(expression=expression):
                self.assertFalse(self.locations("#if " + expression + "\n"))
        for source in (
                "if (" + comparison + ") work();\n",
                "#define condition " + comparison + "\n",
                "#define body \\\n#if " + comparison + "\n",
                "/*\n#if " + comparison + "\n*/\n",
                "/\\\n*\n#if " + comparison + "\n*/\n",
                "/* hidden *\\\n/ 0 < value && \\\n#if " + comparison + "\n",
                'const char *text = "#if ' + comparison + '";\n',
                "// Hidden directive \\\n#if " + comparison + "\n",
                "#if " + comparison + " && \\\n",
                "#if " + comparison + " && \\\n 0 < value\n"):
            with self.subTest(source=source):
                self.assertFalse(self.locations(source))

    def test_logging_policy_only_covers_the_format_literal_at_the_end_of_a_line(self):
        literal = '"' + "Long searchable message " * 6 + '"'
        for ending in (",", ");"):
            source = "\tPRINT_ERROR(" + literal + ending + "\n"
            self.assertEqual(set(self.locations(source)), {("LONG_LINE_STRING", 1)})
        for source in (
                "\tunknown_log(" + literal + ");\n",
                "\tPRINT_ERROR(" + literal + ", value);\n",
                "\tPRINT_ERROR(flag, " + literal + ");\n",
                "\tPRINT_ERROR(" + literal + "); work();\n",
                "\tPRINT_ERROR(variable_format);\n",
                'PRINT_ERROR("short");\n',
                "const char *text = " + literal + ";\n",
                "/*\nPRINT_ERROR(" + literal + ");\n*/\n",
                "/\\\n*\nPRINT_ERROR(" + literal + ");\n*/\n",
                "// Hidden call \\\nPRINT_ERROR(" + literal + ");\n",
                "\t" * 13 + "PRINT_ERROR(" + literal + ");\n",
                'PRINT_ERROR("' + "x" * 120 + '\\");\n'):
            with self.subTest(source=source):
                self.assertFalse(self.locations(source))
        source = "log_error(" + literal + ",\n"
        self.assertTrue(self.locations(source, "iscsi-scst/usr/a.c"))
        self.assertFalse(self.locations(source, "scst/a.c"))

    def test_native_location_rule_source_and_complete_context_must_match(self):
        sources = [
            ("CONSTANT_COMPARISON", "#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)\n"),
            ("LONG_LINE_STRING", 'TRACE_DBG("' + "message " * 20 + '");\n'),
        ]
        for rule, source in sources:
            report = (f"CHECK:{rule}: diagnostic\n#1: FILE: scst/a.c:1:\n+{source}\n"
                      "total: 0 errors, 0 warnings, 1 checks, 1 lines checked\n")
            def check(text, code):
                return apply_exceptions(text.encode(), Path("/repo"),
                                        {"scst/a.c": code}, self.policy)[1]
            with self.subTest(rule=rule):
                self.assertTrue(check(report, source))
                self.assertFalse(check(report.replace(rule, "SPACING"), source))
                self.assertFalse(check(report.replace("scst/a.c:1", "scst/a.c:2"), source))
                self.assertFalse(check(report, "/* Moved. */\n" + source))
        self.policy["version_comparisons"]["code_macros"] = []
        self.policy["logging_calls"] = []
        for _, source in sources:
            self.assertFalse(self.locations(source))


if __name__ == "__main__":
    unittest.main()
