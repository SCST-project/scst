"""Require real Cppcheck to retain findings through the production kernel models."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cppcheck.compiler import CompilerContext
from cppcheck.cppcheck import INCOMPLETE

HERE = Path(__file__).resolve().parent


class NativeModelTests(unittest.TestCase):
    def check(self, source, expected=None, *, expected_lines=None):
        cppcheck, cc = shutil.which("cppcheck"), shutil.which("cc")
        self.assertTrue(cppcheck and cc, "cppcheck and a C compiler are required")
        with tempfile.TemporaryDirectory(prefix="scst-cppcheck-model-") as temporary:
            root = Path(temporary)
            try:
                self.check_fixture(root, source, cppcheck, cc, expected, expected_lines)
            except Exception:
                # The suite log outlives TemporaryDirectory. Include the probe
                # commands and complete output before cleanup removes them.
                for path in sorted(root.iterdir()):
                    if path.is_file():
                        print(f"\n--- Model fixture: {path.name} ---", file=sys.stderr)
                        print(path.read_text(errors="replace"), file=sys.stderr, flush=True)
                raise

    def check_fixture(self, root, source, cppcheck, cc, expected, expected_lines):
        path = root / "fixture.c"
        path.write_text(source)
        compiler = CompilerContext(root, [path, HERE / "kernel.h"])
        context = compiler.get({"directory": str(root), "file": str(path),
                                "arguments": [cc, "-std=gnu11", "-c", str(path)]})
        compiler.save()
        result = subprocess.run(
            [cppcheck, "--std=" + context["standard"],
             "--platform=" + str(root / "platform.xml"), *context["definitions"],
             "--enable=warning,portability", "--inconclusive", "--inline-suppr",
             "--check-level=exhaustive", "--error-exitcode=3", "--xml", "--xml-version=2",
             "--library=gnu," + str(HERE / "kernel.cfg"),
             "--include=" + str(HERE / "kernel.h"), str(path)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(path.read_text(), source)
        output = result.stdout + result.stderr
        try:
            document = ET.fromstring(result.stderr)
        except ET.ParseError:
            self.fail(output)
        self.assertEqual(document.tag, "results", output)
        self.assertIsNotNone(document.find("errors"), output)
        ids = {row.get("id") for row in document.findall("errors/error")}
        self.assertFalse(ids & INCOMPLETE, output)
        self.assertEqual(result.returncode, 3 if expected else 0, output)
        if expected:
            self.assertIn(expected, ids, output)
            if expected_lines is not None:
                locations = [location for row in document.findall("errors/error")
                             if row.get("id") == expected for location in row.findall("location")]
                self.assertTrue(any(location.get("file") == str(path) and
                                    int(location.get("line", "0")) in expected_lines
                                    for location in locations), output)
        else:
            self.assertFalse(ids, output)

    def test_valid_allocations_are_not_reported(self):
        self.check("""
void fixture(void)
{
    int *p = kmalloc_obj(*p, 0);
    if (!p) return;
    *p = 17;
    kfree(p);
}
int *create(void) { return kzalloc_obj(int, 0); }
void array(void)
{
    int *p = kmalloc_objs(int, 4, 0);
    if (!p) return;
    p[3] = 17;
    kfree(p);
}
""")

    def test_allocations_still_report_leaks_and_use_after_free(self):
        cases = (
            ("void fixture(void) { kzalloc_obj(int, 0); }", "leakReturnValNotUsed"),
            ("int fixture(void) { int *p = kmalloc_obj(int, 0); "
             "if (!p) return 0; kfree(p); return *p; }", "deallocret"),
            ("void fixture(void) { int *p = kmalloc_obj(int, 0); "
             "if (!p) return; *p = 1; }", "memleak"),
        )
        for source, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                self.check(source, diagnostic)

    def test_container_access_and_list_loop_bodies_remain_visible(self):
        declarations = """
struct list_head { struct list_head *next, *prev; };
struct item { struct list_head link; int values[2]; };
"""
        cases = (
            "void fixture(struct list_head *member) { "
            "struct item *item = container_of(member, struct item, link); item->values[3] = 1; }",
            "void fixture(struct list_head *head) { struct item *item; "
            "list_for_each_entry(item, head, link) { item->values[3] = 1; } }",
            "void fixture(struct list_head *head) { struct item *item, *next; "
            "list_for_each_entry_safe(item, next, head, link) { item->values[3] = 1; } }",
        )
        for source in cases:
            with self.subTest(source=source):
                self.check(declarations + source, "arrayIndexOutOfBounds")
                self.check(declarations + source.replace("values[3]", "values[1]"))

    def test_cpu_and_scatterlist_loop_bodies_remain_visible(self):
        cases = ("""
int nr_cpu_ids;
void *cpu_possible_mask;
void fixture(void)
{
    int cpu;
    int values[2];
    for_each_possible_cpu(cpu) { values[3] = 1; }
}
""", """
struct scatterlist { int values[2]; };
void fixture(struct scatterlist *head)
{
    struct scatterlist *sg;
    int i;
    for_each_sg(head, sg, 1, i) { sg->values[3] = 1; }
}
""")
        for source in cases:
            with self.subTest(source=source):
                self.check(source, "arrayIndexOutOfBounds")
                self.check(source.replace("values[3]", "values[1]"))

    def test_trace_assignment_body_remains_visible(self):
        source = """
struct payload { int value; };
DECLARE_EVENT_CLASS(sample,
    TP_PROTO(struct payload *payload), TP_ARGS(payload),
    TP_STRUCT__entry(__array(int, values, 2)),
    TP_fast_assign(__entry->values[3] = payload->value;),
    TP_printk("%d", payload->value)
);
DEFINE_EVENT(sample, sample_event,
    TP_PROTO(struct payload *payload), TP_ARGS(payload)
);
void fixture(struct payload *payload) { trace_sample_event(payload); }
"""
        # The only invalid access is in TP_fast_assign. Macro expansion may
        # locate it at the invocation or at the argument carrying the body.
        lines = source.splitlines()
        invocation = range(lines.index("DECLARE_EVENT_CLASS(sample,") + 1,
                           lines.index(");") + 2)
        self.check(source, "arrayIndexOutOfBounds", expected_lines=invocation)
        self.check(source.replace("values[3]", "values[1]"))


if __name__ == "__main__":
    unittest.main()
