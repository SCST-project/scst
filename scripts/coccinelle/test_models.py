"""Require native semantic matches inside SCST parser models and iterators."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from coccinelle.coccicheck import coverage, instrument_rule
from coccinelle.model import prepare

# Remove these skips when upstream preserves C99 and GNU variadic arguments.
VARIADIC_SKIP = "Coccinelle loses variadic macro arguments; awaiting an upstream fix"


class NativeModelTests(unittest.TestCase):
    def check(self, source, pattern="probe@p(...)", expected=1, definitions=""):
        spatch = shutil.which("spatch")
        self.assertTrue(spatch, "spatch is required")
        with tempfile.TemporaryDirectory(prefix="scst-cocci-model-") as temporary:
            root = Path(temporary)
            path = root / "fixture.c"
            path.write_text(source)
            groups = root / "files"
            groups.write_text(str(path) + "\n")
            rule = root / "finding.cocci"
            instrument_rule("virtual report\n@r@\nposition p;\n@@\n" + pattern +
                            "\n@script:python depends on report@\np << r.p;\n@@\n"
                            'coccilib.report.print_report(p[0], "model finding")\n', rule)
            options = prepare(spatch, [], root / "builtins.h")
            if definitions:
                with (root / "builtins.h").open("a") as stream:
                    stream.write(definitions + "\n")
            result = subprocess.run(
                [spatch, "--cocci-file", str(rule), "-D", "report", "--no-includes",
                 "--no-show-diff", "--parse-error-msg", "--show-trying",
                 "--disable-worth-trying-opt", *options, "--file-groups", str(groups)],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=30)
            report = coverage(result.stdout, [path], result.returncode)
            self.assertTrue(report["complete"], result.stdout)
            self.assertFalse(report["coverage_limits"], result.stdout)
            self.assertEqual(report["findings"], expected, result.stdout)
            self.assertEqual(len(report["diagnostics"]), expected, result.stdout)
            self.assertEqual(path.read_text(), source)

    def test_kunit_annotations_retain_function_bodies(self):
        for annotation in ("SCST_KUNIT_VISIBLE", "SCST_KUNIT_VISIBLE_INLINE"):
            with self.subTest(annotation=annotation):
                self.check(annotation + "\nvoid fixture(void) { probe(); }\n")
                self.check(annotation + "\nvoid fixture(void) { other(); }\n", expected=0)

    def test_trace_exit_is_not_a_return_statement(self):
        self.check("void fixture(void) { TRACE_EXIT(); }\n", pattern="return@p;", expected=0)
        self.check("void fixture(void) { TRACE_EXIT(); return; }\n", pattern="return@p;")

    def test_cpu_iterator_retains_its_body(self):
        source = "void fixture(void) { int cpu; for_each_possible_cpu(cpu) { probe(); } }\n"
        self.check(source)
        self.check(source.replace("probe();", "other();"), expected=0)

    def test_current_sysfs_macro_retains_generated_function(self):
        source = 'ISCSI_SESS_BOOL_PARAM_ATTR(initial_r2t, "InitialR2T");\n'
        self.check(source, pattern="iscsi_get_bool_value@p(...)")
        self.check(source, pattern="unexpected_callback@p(...)", expected=0)

    @unittest.skip(VARIADIC_SKIP)
    def test_current_kunit_suite_macro_retains_initializer(self):
        source = ('struct kunit_suite { const char *name; int fixture_value; };\n'
                  'scst_kunit_suite(example, "LIB", "", .fixture_value = 17);\n')
        self.check(source, pattern="17@p")
        self.check(source, pattern="19@p", expected=0)

    @unittest.skip(VARIADIC_SKIP)
    def test_current_kunit_suite_macro_retains_all_variadic_fields(self):
        source = ('struct kunit_suite { const char *name; int first; int last; };\n'
                  'scst_kunit_suite(example, "LIB", "",\n'
                  '                 .first = 17, .last = sizeof((int[]){ 19, 23 }),);\n')
        # Finding only the first argument would miss a broken variadic binder.
        for value in (17, 19, 23):
            with self.subTest(value=value):
                self.check(source, pattern=f"{value}@p")
        self.check(source, pattern="29@p", expected=0)

    @unittest.skip(VARIADIC_SKIP)
    def test_current_kunit_suite_macro_accepts_an_empty_initializer_tail(self):
        declaration = "static struct kunit_suite example@p = { ... };"
        for tail in ("", ","):
            with self.subTest(tail=tail):
                source = ('struct kunit_suite { const char *name; };\n'
                          f'scst_kunit_suite(example, "LIB", ""{tail});\n')
                self.check(source, pattern=declaration)
                self.check(source, pattern="17@p", expected=0)

    @unittest.skip(VARIADIC_SKIP)
    def test_native_variadics_keep_all_arguments_without_a_fixed_prefix(self):
        for parameters, body in (("...", "__VA_ARGS__"), ("values...", "values")):
            definition = f"#define SCST_VALUES({parameters}) int scst_values[] = {{ {body} }}"
            for value in (17, 23):
                with self.subTest(parameters=parameters, value=value):
                    self.check("SCST_VALUES(17, 23,);\n", pattern=f"{value}@p",
                               definitions=definition)
            self.check("SCST_VALUES(17, 23,);\n", pattern="29@p", expected=0,
                       definitions=definition)


if __name__ == "__main__":
    unittest.main()
