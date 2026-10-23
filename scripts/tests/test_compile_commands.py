"""Shared database completeness and CLI recipe fixtures; no SCST compilation."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import compile_commands as commands


class CompileCommandsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "scst/sample.c"
        self.source.parent.mkdir()
        self.source.write_text("int value;\n")
        self.entry = {"directory": str(self.source.parent), "file": str(self.source),
                      "arguments": ["gcc", "-c", "sample.c", "-o", "sample.o"]}
        self.database = self.root / "compile_commands.json"

    def test_database_rejects_invalid_sources_and_keeps_distinct_commands(self):
        commands.write_json(self.database, [self.entry, dict(self.entry, arguments=[
            "gcc", "-DSECOND=1", "-c", "sample.c"])])
        self.assertEqual(len(commands.read_database(self.database, self.root)), 2)
        for entry in (dict(self.entry, directory="scst"),
                      dict(self.entry, file="missing.c"),
                      dict(self.entry, arguments=[]),
                      dict(self.entry, file=__file__)):
            with self.subTest(entry=entry):
                commands.write_json(self.database, [entry])
                with self.assertRaises(ValueError):
                    commands.read_database(self.database, self.root)

    def test_unfinished_record_is_not_a_successful_export(self):
        directory = self.root / "records"
        directory.mkdir()
        for state, status in (("started", 2), ("complete", 1)):
            commands.write_json(directory / "record.json",
                                dict(self.entry, state=state, returncode=status))
            with self.assertRaisesRegex(ValueError, "Unfinished"):
                commands.load_records(directory)
        commands.write_json(directory / "record.json",
                            dict(self.entry, state="complete", returncode=0))
        self.assertEqual(len(commands.load_records(directory)), 1)

    def test_failed_build_preserves_published_database_and_records_failure(self):
        self.database.write_text("previous complete database\n")
        with patch.object(commands, "collect_checks", return_value=(2, [])):
            with self.assertRaisesRegex(ValueError, "build failed"):
                commands.collect(self.root, self.database)
        self.assertEqual(self.database.read_text(), "previous complete database\n")
        manifest = next((self.root / ".cache/lint/compile-commands").glob("run-*/context.json"))
        result = json.loads(manifest.read_text())
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["kernel_make_status"], 2)
        self.assertTrue(result["failures"])

    def test_native_database_must_match_check_inventory(self):
        kernel = self.root / "kernel"
        generator = kernel / "scripts/clang-tools/gen_compile_commands.py"
        generator.parent.mkdir(parents=True)
        generator.touch()
        log = self.root / "build.log"
        log.touch()
        (self.source.parent / "modules.order").touch()
        def generate(command, **kwargs):
            output = Path(command[command.index("-o") + 1])
            commands.write_json(output, [self.entry])
            return subprocess.CompletedProcess(command, 0)
        with patch.dict(os.environ, {"SCST_LINT_KDIR": str(kernel)}), \
                patch.object(commands, "run", side_effect=generate):
            self.assertEqual(commands.module_database(
                self.root, [self.entry], self.root, log), [self.entry])
            with self.assertRaisesRegex(ValueError, "Incomplete compiler database"):
                commands.module_database(self.root, [self.entry, self.entry], self.root, log)

    def test_legacy_kernel_cwd_cannot_select_an_unrelated_module_inventory(self):
        kernel = self.root / "kernel"
        generator = kernel / "scripts/clang-tools/gen_compile_commands.py"
        generator.parent.mkdir(parents=True)
        generator.touch()
        (kernel / "modules.order").touch()
        with patch.dict(os.environ, {"SCST_LINT_KDIR": str(kernel)}), \
                patch.object(commands, "run") as run:
            with self.assertRaisesRegex(ValueError, "Legacy external-module Kbuild layout"):
                commands.module_database(self.root, [dict(self.entry, directory=str(kernel))],
                                         self.root, self.root / "build.log")
            run.assert_not_called()

    def test_cli_export_uses_real_recipe_without_invoking_compiler(self):
        repository = Path(__file__).resolve().parents[2]
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("compile_commands.py", "compile_commands.mk"):
            shutil.copy2(repository / "scripts" / name, scripts / name)
        component = self.root / "usr/fileio"
        component.mkdir(parents=True)
        shutil.copy2(repository / "usr/fileio/Makefile", component / "Makefile")
        (component / "sample.c").touch()
        records = self.root / "records"
        records.mkdir()
        result = subprocess.run(["make", "--no-print-directory", "-C", str(component),
            "compile-commands", "SRCS_F=sample.c", "CC=compiler-must-not-run",
            "LOCAL_CFLAGS=-DTEST_CONTEXT=1", "COMPILE_COMMANDS_DIR=" + str(records)],
            env=dict(os.environ, PYTHONPATH=str(repository / "scripts"), PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        entry, = commands.load_records(records)
        self.assertEqual(entry["arguments"][0], "compiler-must-not-run")
        self.assertIn("-DTEST_CONTEXT=1", entry["arguments"])
        self.assertEqual(entry["file"], str(component / "sample.c"))
        self.assertFalse((component / "sample.o").exists())

    def test_cli_cleanup_does_not_require_packaged_export_tooling(self):
        repository = Path(__file__).resolve().parents[2]
        for name in ("iscsi-scst/usr", "usr/fileio", "usr/stpgd", "usr/events"):
            with self.subTest(component=name):
                component = self.root / name
                component.mkdir(parents=True, exist_ok=True)
                shutil.copy2(repository / name / "Makefile", component / "Makefile")
                result = subprocess.run(["make", "--no-print-directory", "-C", str(component),
                                         "clean"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
