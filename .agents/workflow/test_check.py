#!/usr/bin/env python3
"""Unit tests for objective workflow checks."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check


def run(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


class GitRepositoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        run(self.repository, "init", "-q")
        run(self.repository, "config", "user.email", "test@example.com")
        run(self.repository, "config", "user.name", "Test User")
        (self.repository / "tracked.txt").write_text("one\n", encoding="utf-8")
        run(self.repository, "add", "tracked.txt")
        run(self.repository, "-c", "commit.gpgsign=false", "commit", "-qm", "initial")
        self.base = run(self.repository, "rev-parse", "HEAD")
        (self.repository / "tracked.txt").write_text("two\n", encoding="utf-8")
        run(self.repository, "add", "tracked.txt")
        run(self.repository, "-c", "commit.gpgsign=false", "commit", "-qm", "second")
        self.head = run(self.repository, "rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, *args: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            returncode = check.main(list(args))
        return returncode, json.loads(output.getvalue())

    def test_snapshot_accepts_clean_range_and_untracked_files(self) -> None:
        (self.repository / "local.txt").write_text("local\n", encoding="utf-8")
        result = check.check_snapshot(self.repository, self.base, self.head)
        self.assertEqual(result["status"], "PASS")

    def test_snapshot_rejects_empty_range_by_default(self) -> None:
        result = check.check_snapshot(self.repository, self.head, self.head)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("empty commit range", result["errors"])

    def test_snapshot_allows_empty_initial_range_when_explicitly_requested(self) -> None:
        result = check.check_snapshot(
            self.repository,
            self.head,
            self.head,
            allow_empty=True,
        )
        self.assertEqual(result["status"], "PASS")

    def test_snapshot_rejects_untracked_files_when_required(self) -> None:
        (self.repository / "forgotten.txt").write_text("forgotten\n", encoding="utf-8")
        result = check.check_snapshot(
            self.repository,
            self.base,
            self.head,
            require_no_untracked=True,
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("untracked files are present", result["errors"])

    def test_snapshot_rejects_tracked_changes(self) -> None:
        (self.repository / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        result = check.check_snapshot(self.repository, self.base, self.head)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("unstaged tracked changes are present", result["errors"])

    def test_snapshot_rejects_non_ancestor_base(self) -> None:
        result = check.check_snapshot(self.repository, self.head, self.base)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("base is not an ancestor of head", result["errors"])

    def test_snapshot_blocks_on_git_predicate_errors(self) -> None:
        real_git = check.git

        for failing_prefix in (
            ("merge-base", "--is-ancestor"),
            ("diff", "--quiet"),
        ):
            with self.subTest(command=failing_prefix):

                def failing_git(
                    repository: Path,
                    *args: str,
                    check: bool = True,
                ) -> subprocess.CompletedProcess[str]:
                    if args[: len(failing_prefix)] == failing_prefix:
                        return subprocess.CompletedProcess(
                            ["git", *args],
                            128,
                            stdout="",
                            stderr="simulated git failure",
                        )
                    return real_git(repository, *args, check=check)

                with mock.patch.object(check, "git", side_effect=failing_git):
                    result = check.run_check(
                        check.parse_args(
                            [
                                "snapshot",
                                "--repository",
                                str(self.repository),
                                "--base",
                                self.base,
                                "--head",
                                self.head,
                            ]
                        )
                    )

                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("simulated git failure", result["errors"][0])

    def test_snapshot_blocks_when_commit_is_unavailable(self) -> None:
        returncode, result = self.run_cli(
            "snapshot",
            "--repository",
            str(self.repository),
            "--base",
            "0" * 40,
            "--head",
            self.head,
        )
        self.assertEqual(returncode, 2)
        self.assertEqual(result["status"], "BLOCKED")

    def test_snapshot_rejects_invalid_commit_input(self) -> None:
        result = check.run_check(
            check.parse_args(
                [
                    "snapshot",
                    "--repository",
                    str(self.repository),
                    "--base",
                    "HEAD",
                    "--head",
                    self.head,
                ]
            )
        )
        self.assertEqual(result["status"], "FAIL")

    def test_snapshot_rejects_existing_non_commit_object(self) -> None:
        blob = run(
            self.repository,
            "hash-object",
            "-w",
            "tracked.txt",
        )
        returncode, result = self.run_cli(
            "snapshot",
            "--repository",
            str(self.repository),
            "--base",
            blob,
            "--head",
            self.head,
        )
        self.assertEqual(returncode, 1)
        self.assertEqual(result["status"], "FAIL")

    def test_cli_reports_invalid_arguments_as_failure(self) -> None:
        returncode, result = self.run_cli(
            "snapshot",
            "--repository",
            str(self.repository),
            "--base",
            self.base,
        )
        self.assertEqual(returncode, 1)
        self.assertEqual(result["status"], "FAIL")

    def test_result_branch_uses_recorded_base_without_touching_checkout(self) -> None:
        workflow_file = self.repository / "new-workflow-helper.py"
        workflow_file.write_text("new workflow\n", encoding="utf-8")
        run(self.repository, "add", workflow_file.name)
        run(self.repository, "-c", "commit.gpgsign=false", "commit", "-qm", "workflow")
        workflow_tip = run(self.repository, "rev-parse", "HEAD")
        recorded_ref = run(self.repository, "symbolic-ref", "HEAD")

        run(self.repository, "branch", "old-checkout", self.head)
        run(self.repository, "switch", "-q", "old-checkout")
        (self.repository / "tracked.txt").write_text("user change\n", encoding="utf-8")
        (self.repository / "untracked.txt").write_text("keep\n", encoding="utf-8")
        self.assertFalse(workflow_file.exists())
        self.assertEqual(
            run(self.repository, "symbolic-ref", "HEAD"),
            "refs/heads/old-checkout",
        )
        self.assertNotEqual(run(self.repository, "symbolic-ref", "HEAD"), recorded_ref)

        tree = run(self.repository, "rev-parse", f"{workflow_tip}^{{tree}}")
        later_tip = run(
            self.repository,
            "commit-tree",
            tree,
            "-p",
            workflow_tip,
            "-m",
            "later target update",
        )
        run(self.repository, "update-ref", recorded_ref, later_tip, workflow_tip)

        resolved = run(self.repository, "rev-parse", "--verify", f"{recorded_ref}^{{commit}}")
        self.assertEqual(resolved, later_tip)
        run(self.repository, "config", "--local", "scst.chatBranchPrefix", "test-user")
        prefix = run(
            self.repository,
            "config",
            "--local",
            "--get-all",
            "scst.chatBranchPrefix",
        )
        result_branch = f"{prefix}/result-branch-a1b2c3"
        run(self.repository, "check-ref-format", f"refs/heads/{result_branch}")

        with tempfile.TemporaryDirectory(prefix="task-result-") as temporary:
            worktree = Path(temporary) / "scst"
            run(
                self.repository,
                "worktree",
                "add",
                "-q",
                "-b",
                result_branch,
                str(worktree),
                resolved,
            )
            self.assertEqual(
                run(worktree, "symbolic-ref", "HEAD"),
                f"refs/heads/{result_branch}",
            )
            self.assertEqual(run(worktree, "rev-parse", "HEAD"), later_tip)
            run(self.repository, "worktree", "remove", str(worktree))

        self.assertEqual(
            run(self.repository, "symbolic-ref", "HEAD"),
            "refs/heads/old-checkout",
        )
        self.assertEqual(run(self.repository, "rev-parse", "HEAD"), self.head)
        self.assertEqual((self.repository / "tracked.txt").read_text(), "user change\n")
        self.assertEqual((self.repository / "untracked.txt").read_text(), "keep\n")

    def test_detached_checkout_has_no_symbolic_branch_default(self) -> None:
        run(self.repository, "switch", "-q", "--detach", self.head)
        symbolic = subprocess.run(
            ["git", "-C", str(self.repository), "symbolic-ref", "--quiet", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(symbolic.returncode, 0)
        self.assertEqual(symbolic.stdout, "")


class InstructionCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Path(__file__).resolve().parents[2]

    def test_repository_instructions_pass(self) -> None:
        self.assertEqual(check.check_instructions(self.repository)["status"], "PASS")

    def test_unavailable_instruction_file_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            skill_file = skill / "SKILL.md"
            skill_file.write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            skill_file.unlink()
            result = check.run(
                ["instructions", "--repository", str(root)]
            )
        self.assertEqual(result["status"], "BLOCKED")

    def test_invalid_instruction_encoding_is_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            skill_file = skill / "SKILL.md"
            skill_file.write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            skill_file.write_bytes(b"\xff")
            result = check.run(
                ["instructions", "--repository", str(root)]
            )
        self.assertEqual(result["status"], "FAIL")

    def test_unnamespaced_repository_skill_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            errors = check.instruction_errors(root)
        self.assertTrue(
            any(
                "skill name must use the scst- namespace: example" in error
                for error in errors
            )
        )

    def test_namespaced_repository_skill_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            errors = check.instruction_errors(root)
        self.assertEqual(errors, [])

    def test_missing_reference_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n\n"
                "Read `references/missing.md`.\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            errors = check.instruction_errors(root)
        self.assertTrue(any("missing reference" in error for error in errors))

    def test_unreferenced_resource_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            references = skill / "references"
            references.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            (references / "unused.md").write_text("# Unused\n", encoding="utf-8")
            self._write_role_config(root)
            errors = check.instruction_errors(root)
        self.assertTrue(any("unreferenced resource" in error for error in errors))

    def test_role_name_mismatch_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_role_config(root, role_name="wrong")
            errors = check.instruction_errors(root)
        self.assertTrue(any("role name does not match" in error for error in errors))

    def test_missing_skill_metadata_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root, write_skill_metadata=False)
            errors = check.instruction_errors(root)
        self.assertTrue(any("missing skill metadata" in error for error in errors))

    def test_user_facing_skill_requires_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-develop-task"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-develop-task\ndescription: Develop a task.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            errors = check.instruction_errors(root)
        self.assertTrue(
            any("user-facing skill must define one interface" in error for error in errors)
        )

    def test_internal_skill_interface_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            metadata = skill / "agents" / "openai.yaml"
            metadata.write_text(
                'interface:\n  default_prompt: "Use $scst-example."\n\n'
                "policy:\n  allow_implicit_invocation: false\n",
                encoding="utf-8",
            )
            errors = check.instruction_errors(root)
        self.assertTrue(
            any(
                "internal skill metadata must not define interface" in error
                for error in errors
            )
        )

    def test_missing_role_description_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_role_config(root, role_description="")
            errors = check.instruction_errors(root)
        self.assertTrue(any("description is empty" in error for error in errors))

    def test_read_only_role_requires_read_only_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_role_config(root, sandbox_mode="workspace-write")
            errors = check.instruction_errors(root)
        self.assertTrue(any("sandbox_mode must be read-only" in error for error in errors))

    def test_implicit_skill_invocation_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            metadata = skill / "agents" / "openai.yaml"
            metadata.write_text(
                "policy:\n  allow_implicit_invocation: true\n",
                encoding="utf-8",
            )
            errors = check.instruction_errors(root)
        self.assertTrue(any("implicit invocation must be disabled" in error for error in errors))

    def test_nested_implicit_invocation_policy_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            metadata = skill / "agents" / "openai.yaml"
            metadata.write_text(
                "policy:\n  nested:\n    allow_implicit_invocation: false\n",
                encoding="utf-8",
            )
            errors = check.instruction_errors(root)
        self.assertTrue(any("implicit invocation must be disabled" in error for error in errors))

    def test_untracked_instruction_files_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / ".agents" / "skills" / "scst-example"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: scst-example\ndescription: Example skill.\n---\n",
                encoding="utf-8",
            )
            self._write_role_config(root)
            references = skill / "references"
            references.mkdir()
            (references / "unused.md").write_text("# Untracked\n", encoding="utf-8")
            untracked = root / ".agents" / "skills" / "untracked"
            untracked.mkdir()
            (untracked / "SKILL.md").write_text("invalid\n", encoding="utf-8")
            errors = check.instruction_errors(root)
        self.assertEqual(errors, [])

    @staticmethod
    def _write_role_config(
        root: Path,
        role_name: str = "scst_reviewer",
        *,
        role_description: str = "Review one range.",
        sandbox_mode: str = "read-only",
        write_skill_metadata: bool = True,
    ) -> None:
        if write_skill_metadata:
            for skill in (root / ".agents" / "skills").glob("*/SKILL.md"):
                metadata = skill.parent / "agents" / "openai.yaml"
                metadata.parent.mkdir()
                metadata.write_text(
                    "policy:\n  allow_implicit_invocation: false\n",
                    encoding="utf-8",
                )
        agents = root / ".codex" / "agents"
        agents.mkdir(parents=True)
        (agents / "scst_reviewer.toml").write_text(
            f'name = "{role_name}"\n'
            f'description = "{role_description}"\n'
            f'sandbox_mode = "{sandbox_mode}"\n'
            'developer_instructions = "Review."\n',
            encoding="utf-8",
        )
        run(root, "init", "-q")
        run(root, "add", ".")


if __name__ == "__main__":
    unittest.main()
