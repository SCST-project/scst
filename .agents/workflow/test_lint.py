#!/usr/bin/env python3
"""Unit tests for range-selected workflow lint."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import unittest
from pathlib import Path
from typing import Sequence
from unittest import mock

import lint


class RecordingRunner:
    def __init__(
        self,
        failing_name: str | None = None,
        failing_returncode: int = 1,
    ) -> None:
        self.commands: list[list[str]] = []
        self.failing_name = failing_name
        self.failing_returncode = failing_returncode

    def __call__(
        self, command: Sequence[str], repository: Path
    ) -> subprocess.CompletedProcess[str]:
        del repository
        recorded = list(command)
        self.commands.append(recorded)
        failed = self.failing_name is not None and self.failing_name in recorded
        return subprocess.CompletedProcess(
            recorded,
            self.failing_returncode if failed else 0,
            stdout="diagnostic" if failed else "",
        )


class WorkflowLintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Path(__file__).resolve().parents[2]

    def test_agent_path_selection_is_narrow(self) -> None:
        self.assertTrue(lint.is_agent_config_path("AGENTS.md"))
        self.assertTrue(lint.is_agent_config_path("scst/CLAUDE.md"))
        self.assertTrue(lint.is_agent_config_path(".agents/skills/scst-example/SKILL.md"))
        self.assertTrue(lint.is_agent_config_path("doc/AGENT_HARNESS.md"))
        self.assertFalse(lint.is_agent_config_path("README.md"))
        self.assertFalse(lint.is_agent_config_path("doc/scst_pg.sgml"))

    def test_python_change_runs_only_ruff(self) -> None:
        with mock.patch.object(Path, "is_file", return_value=True):
            result = lint.run_selected_checks(
                self.repository,
                ["scripts/example.py"],
                runner=RecordingRunner(),
            )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["python_lint"], "PASS")
        self.assertEqual(result["agent_config_lint"], "NOT_APPLICABLE")
        self.assertEqual([item["name"] for item in result["checks"]], ["python-ruff"])

    def test_agent_change_runs_objective_checks_and_tests(self) -> None:
        result = lint.run_selected_checks(
            self.repository,
            [".agents/skills/scst-example/SKILL.md"],
            runner=RecordingRunner(),
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["agent_config_lint"], "PASS")
        self.assertEqual(
            [item["name"] for item in result["checks"]],
            ["agent-instructions", "workflow-unittest"],
        )

    def test_agent_python_change_runs_both_groups(self) -> None:
        result = lint.run_selected_checks(
            self.repository,
            [".agents/workflow/check.py"],
            runner=RecordingRunner(failing_name="instructions"),
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["python_lint"], "PASS")
        self.assertEqual(result["agent_config_lint"], "FAIL")
        self.assertEqual(len(result["checks"]), 3)

    def test_blocked_instruction_check_is_preserved(self) -> None:
        result = lint.run_selected_checks(
            self.repository,
            ["AGENTS.md"],
            runner=RecordingRunner(
                failing_name="instructions",
                failing_returncode=lint.CHECK_BLOCKED_RETURN_CODE,
            ),
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["agent_config_lint"], "BLOCKED")

    def test_deleted_agent_python_still_checks_instructions(self) -> None:
        result = lint.run_selected_checks(
            self.repository,
            [".agents/workflow/deleted.py"],
            runner=RecordingRunner(),
        )
        self.assertEqual(result["python_files"], [])
        self.assertEqual(result["python_lint"], "NOT_APPLICABLE")
        self.assertEqual(result["agent_config_lint"], "PASS")

    def test_changed_paths_preserves_deletions_and_disables_renames(self) -> None:
        merge_base = subprocess.CompletedProcess([], 0, stdout="")
        diff = subprocess.CompletedProcess(
            [],
            0,
            stdout=".agents/skills/source/SKILL.md\0archive/SKILL.md\0",
        )
        with mock.patch.object(lint, "git", side_effect=[merge_base, diff]) as git:
            paths = lint.changed_paths(self.repository, "base", "head")
        self.assertEqual(paths, [".agents/skills/source/SKILL.md", "archive/SKILL.md"])
        self.assertIn("--no-renames", git.call_args_list[1].args)

    def test_non_ancestor_range_is_failure(self) -> None:
        repository = subprocess.CompletedProcess([], 0, stdout=str(self.repository))
        non_ancestor = subprocess.CompletedProcess([], 1, stdout="", stderr="")
        output = io.StringIO()

        with (
            mock.patch.object(lint, "git", side_effect=[repository, non_ancestor]),
            contextlib.redirect_stdout(output),
        ):
            returncode = lint.main(
                [
                    "--repository",
                    str(self.repository),
                    "--base",
                    "base",
                    "--head",
                    "head",
                ]
            )

        self.assertEqual(returncode, 1)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"error": "base is not an ancestor of head", "status": "FAIL"},
        )

    def test_ancestor_check_error_is_blocked(self) -> None:
        repository = subprocess.CompletedProcess([], 0, stdout=str(self.repository))
        unavailable = subprocess.CompletedProcess(
            [],
            128,
            stdout="",
            stderr="simulated git failure",
        )
        output = io.StringIO()

        with (
            mock.patch.object(lint, "git", side_effect=[repository, unavailable]),
            contextlib.redirect_stdout(output),
        ):
            returncode = lint.main(
                [
                    "--repository",
                    str(self.repository),
                    "--base",
                    "base",
                    "--head",
                    "head",
                ]
            )

        self.assertEqual(returncode, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")
        self.assertIn("simulated git failure", output.getvalue())

    def test_unrelated_change_is_not_applicable(self) -> None:
        result = lint.run_selected_checks(
            self.repository,
            ["scst/example.c"],
            runner=RecordingRunner(),
        )
        self.assertEqual(result["status"], "NOT_APPLICABLE")
        self.assertEqual(result["checks"], [])


if __name__ == "__main__":
    unittest.main()
