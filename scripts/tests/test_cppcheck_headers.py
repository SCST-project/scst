#!/usr/bin/env python3
"""Keep omitted-header advice tied to exact, reviewed include sites."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cppcheck.system_headers import dependency_advice, include_advice, matches_include  # noqa: E402


class HeaderAdviceTest(unittest.TestCase):
    def test_exact_site_name_and_angle_brackets_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "scst/sample.c"
            source.parent.mkdir()
            source.write_text('#include <linux/types.h>\n#include "linux/types.h"\n'
                              '#include <linux/misspelled_types.h>\n')
            policy = {"omitted_system_headers": [{"source_roots": ["scst"],
                       "headers": ["linux/types.h"], "dependency_headers": [],
                       "reason": "Kernel model."}]}
            rules = include_advice(root, [source], policy)
            self.assertEqual(len(rules), 1)
            rule = rules[0]
            self.assertEqual((rule["file"], rule["line"]), ("scst/sample.c", 1))
            text = "Include file: <linux/types.h> not found."
            self.assertTrue(matches_include(rule, "scst/sample.c", 1, text))
            self.assertFalse(matches_include(rule, "scst/sample.c", 2, text))
            self.assertFalse(matches_include(rule, "tools/sample.c", 1, text))
            self.assertFalse(matches_include(rule, "scst/sample.c", 1,
                                            text.replace("types.h", "misspelled_types.h")))
            source.write_text("/* Moved include. */\n" + source.read_text())
            self.assertEqual(include_advice(root, [source], policy)[0]["line"], 2)

    def test_dependency_advice_resolves_exact_external_headers_per_cli_context(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            installed = base / "include path"
            header = installed / "netlink/netlink.h"
            header.parent.mkdir(parents=True)
            header.write_text('#include <stdio.h>\n#include <unknown.h>\n'
                              '#include "stdio.h"\n')
            other = header.with_name("other.h")
            other.write_text('#include <stdio.h>\n')
            source = root / "usr/fileio/main.c"
            source.parent.mkdir(parents=True)
            source.write_text('#include <stdio.h>\n')
            policy = {"omitted_system_headers": [{
                "source_roots": ["usr/fileio", "usr/events"],
                "dependency_headers": ["netlink/netlink.h"], "headers": ["stdio.h"],
                "reason": "Reviewed dependency include."}]}
            project = root / "commands.json"
            entry = {"directory": str(root), "file": str(source),
                     "arguments": ["cc", "-I", str(installed), "-c", str(source)]}
            project.write_text(json.dumps([entry, entry]))
            rules = dependency_advice(root, project, "usr/fileio", policy)
            self.assertEqual(len(rules), 1)
            rule = rules[0]
            self.assertEqual((rule["file"], rule["line"]), (str(header), 1))
            self.assertEqual(rule["dependency_header"], "netlink/netlink.h")
            self.assertTrue(matches_include(rule, str(header), 1,
                                           "Include file: <stdio.h> not found."))
            self.assertFalse(matches_include(rule, str(other), 1,
                                            "Include file: <stdio.h> not found."))
            self.assertEqual(dependency_advice(root, project, "scst", policy), [])
            self.assertEqual(include_advice(root, [source], policy), [])

            entry["arguments"] = ["cc", "-c", str(source)]
            project.write_text(json.dumps([entry]))
            self.assertEqual(dependency_advice(root, project, "usr/fileio", policy), [])
            self.assertEqual(dependency_advice(root, project, "usr/fileio", policy,
                                              ["-I" + str(installed)]), rules)

            # A project-owned replacement must not inherit an external exception.
            replacement = root / "include/netlink/netlink.h"
            replacement.parent.mkdir(parents=True)
            replacement.write_text(header.read_text())
            entry["arguments"] = ["cc", "-Iinclude", "-isystem", str(installed),
                                  "-c", str(source)]
            project.write_text(json.dumps([entry]))
            self.assertEqual(dependency_advice(root, project, "usr/fileio", policy), [])


if __name__ == "__main__":
    unittest.main()
