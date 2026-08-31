---
name: scst-lint-patch
description: Internal non-build SCST lint gate run by the implementation owner or the scst-validate-series main agent for one exact committed range.
---

# Run the SCST lint gate

Run this skill in the agent that owns the current implementation or in the main agent
selected by `$scst-validate-series`; never start a lint subagent. Resolve the exact
repository root, require a non-empty `base..head`, and run:

```sh
python3 <REPOSITORY_ROOT>/.agents/workflow/check.py snapshot \
  --repository <REPOSITORY_ROOT> \
  --base <base> \
  --head <head>
```

This standalone lint check ignores unrelated untracked paths. Run every applicable
independent check after the first failure. A missing prerequisite is `BLOCKED`; an
unwaived diagnostic is `FAIL`.

Allow a waiver only for an exact user constraint, confirmed false positive, required
ABI/API layout, correctness, or a local style exception whose removal would materially
reduce clarity. Record the command, diagnostic, commit, `path:line`, and rationale.

## Checks

1. Run `git diff --check <base>..<head>` from `<REPOSITORY_ROOT>`.
2. Run `./scripts/checkpatch_commits <base>` from `<REPOSITORY_ROOT>`. The snapshot
   preflight binds worktree `HEAD` to `<head>`, so this checks every commit in the exact
   range through the repository-native wrapper.
3. Inspect changed C and headers against Linux kernel style and every applicable
   `AGENTS.md`. Account for kernel-version, stable-backport, and vendor-kernel
   compatibility where the range touches compatibility code.
4. Run `shellcheck` once for existing tracked changed files whose shebang selects Bash.
5. From `<REPOSITORY_ROOT>`, run:

   ```sh
   python3 .agents/workflow/lint.py \
     --repository <REPOSITORY_ROOT> \
     --base <base> \
     --head <head>
   ```

   It owns changed-Python selection, pinned Ruff, objective instruction and role checks,
   and focused harness helper unit tests.
6. Validate every commit as a self-contained semantic unit and inspect its message for a
   concise English subject and an accurate explanation when one is needed. The
   repository-native checkpatch run remains authoritative for mechanical commit-message
   diagnostics.

With no matching files, report `NOT_APPLICABLE` without probing an optional tool. This
gate may run its focused harness helper tests, but it does not run product builds,
product runtime tests, regression tests, module operations, or build-based analyzers.

Report:

```text
LINT_EXECUTOR: <agent role>
DIFF_CHECK: <PASS|WAIVED|FAIL|BLOCKED>
CHECKPATCH: <PASS|WAIVED|FAIL|BLOCKED>
CODE_STYLE: <PASS|WAIVED|FAIL|NOT_APPLICABLE|BLOCKED>
SHELLCHECK: <PASS|WAIVED|FAIL|NOT_APPLICABLE|BLOCKED>
PYTHON_LINT: <PASS|WAIVED|FAIL|NOT_APPLICABLE|BLOCKED>
AGENT_CONFIG_LINT: <PASS|WAIVED|FAIL|NOT_APPLICABLE|BLOCKED>
COMMIT_STYLE: <PASS|WAIVED|FAIL|BLOCKED>
LINT_COVERAGE: <COMPLETE|BLOCKED>
LINT_STATUS: <PASS|FAIL|BLOCKED>
```

Any incomplete component makes the gate `BLOCKED`; otherwise any unwaived failure makes
it `FAIL`. Use `PASS` only when every applicable component passed or has a reported valid
waiver. For an implementation-owner invocation, fold fixes into owning commits and rerun
the entire gate for the new head. For an `$scst-validate-series` invocation, never modify
the validated range; return the lint status and findings to the caller. Never review a
head whose lint is not `PASS`.
