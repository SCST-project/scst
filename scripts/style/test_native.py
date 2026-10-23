"""Check the completion protocol against real Checkpatch, without changing sources."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from style.checkpatch import checker_path, native_report


class NativeCheckpatchTests(unittest.TestCase):
    def test_strict_and_non_strict_results_and_unreadable_inputs(self):
        tool = checker_path()
        with tempfile.TemporaryDirectory(prefix="scst-checkpatch-model-") as temporary:
            root = Path(temporary)
            (root / ".checkpatch.conf").write_text("")
            source = root / "fixture.c"
            env = dict(os.environ, CHECKPATCH_CONFIG_DIR=str(root))
            cases = (
                ("clean", "int scst_model_value;\n", None),
                ("warning", 'void scst_model_print(void)\n{\n\tprintk("probe\\n");\n}\n',
                 "WARNING:PRINTK_WITHOUT_KERN_LEVEL:"),
                # In --file mode AVOID_BUG is a CHECK, visible only with --strict.
                ("check", "void scst_model_check(int value)\n{\n\tBUG_ON(value);\n}\n",
                 "CHECK:AVOID_BUG:"),
            )
            for strict in (False, True):
                for name, body, diagnostic in cases:
                    with self.subTest(strict=strict, case=name):
                        source.write_text("// SPDX-License-Identifier: GPL-2.0-only\n\n" + body)
                        command = [str(tool), "--no-tree", "--show-types", "--color=never",
                                   "--no-fix", "--no-fix-inplace", "--file"]
                        if strict:
                            command.append("--strict")
                        result = subprocess.run([*command, str(source)], cwd=root, env=env,
                                                capture_output=True, text=True, timeout=30)
                        report = native_report(result.stdout, result.stderr, result.returncode,
                                               [source])
                        self.assertTrue(report["complete"], result.stdout + result.stderr)
                        visible = diagnostic is not None and (name != "check" or strict)
                        expected = {diagnostic.split(":", 1)[0]: 1} if visible else {}
                        self.assertEqual(report["counts"], expected, report)
                        self.assertEqual(report["remaining"], int(visible), report)
                        if visible:
                            self.assertIn(diagnostic, result.stdout)
                        elif diagnostic:
                            self.assertNotIn(diagnostic, result.stdout)
                        missing = root / "missing.c"
                        result = subprocess.run([*command, str(source), str(missing)],
                                                cwd=root, env=env, capture_output=True,
                                                text=True, timeout=30)
                        report = native_report(result.stdout, result.stderr, result.returncode,
                                               [source, missing])
                        self.assertFalse(report["complete"], report)
                        self.assertTrue(any("completion" in item for item in report["failures"]))


if __name__ == "__main__":
    unittest.main()
