"""Exercise private kernel rule adaptations with native positive and negative matches."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from coccinelle.coccicheck import coverage, instrument_rule, rule_options
from coccinelle.compat import adapt
from coccinelle.model import prepare


class NativeRuleTests(unittest.TestCase):
    def check(self, name, source, expected):
        spatch = shutil.which("spatch")
        self.assertTrue(spatch, "spatch is required")
        kernel = Path(os.environ.get("SCST_LINT_KDIR") or os.environ.get("KDIR") or
                      f"/lib/modules/{os.uname().release}/build")
        original = kernel / "scripts/coccinelle" / name
        before = original.read_bytes()
        text, _ = adapt(original, before.decode())
        with tempfile.TemporaryDirectory(prefix="scst-cocci-rule-") as temporary:
            root = Path(temporary)
            path = root / "fixture.c"
            path.write_text(source)
            groups = root / "files"
            groups.write_text(str(path) + "\n")
            rule = root / original.name
            instrument_rule(text, rule)
            options = prepare(spatch, rule_options(text), root / "builtins.h")
            result = subprocess.run(
                [spatch, "--cocci-file", str(rule), "-D", "report", *options,
                 "--no-show-diff", "--parse-error-msg", "--show-trying",
                 "--disable-worth-trying-opt", "--file-groups", str(groups)],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=30)
            report = coverage(result.stdout, [path], result.returncode, rule=original.stem)
            self.assertTrue(report["complete"], result.stdout)
            self.assertFalse(report["coverage_limits"], result.stdout)
            self.assertEqual(report["findings"], expected, result.stdout)
            self.assertEqual(path.read_text(), source)
        self.assertEqual(original.read_bytes(), before)

    def test_stream_open_keeps_opener_and_seek_requirements(self):
        for opener, seek in (("nonseekable_open", "noop_llseek"),
                             ("nonseekable_open", None),
                             ("other_open", "noop_llseek"),
                             ("nonseekable_open", "other_llseek")):
            with self.subTest(opener=opener, seek=seek):
                source = (
                    "int open_stream(struct inode *i, struct file *f) {\n"
                    f"return {opener}(i, f);\n}}\n"
                    "ssize_t reader(struct file *f, char *buf, size_t len, loff_t *pos) {\n"
                    "return consume(buf, len);\n}\n"
                    "static struct file_operations ops = { .open = open_stream, .read = reader,\n"
                    + (f".llseek = {seek},\n" if seek else "") + "};\n")
                self.check("api/stream_open.cocci", source,
                           int(opener == "nonseekable_open" and seek != "other_llseek"))

    def test_namespace_report_does_not_break_a_compatibility_undef(self):
        self.check("misc/add_namespace.cocci",
                   '#undef MODULE_IMPORT_NS\n#define MODULE_IMPORT_NS(ns)\n'
                   'MODULE_IMPORT_NS("SCST");\nint fixture(void) { return 0; }\n', 0)


if __name__ == "__main__":
    unittest.main()
