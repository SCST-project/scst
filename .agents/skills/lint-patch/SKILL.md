---
name: lint-patch
description: >-
  Lint an exact committed SCST patch range in the main agent before
  independent review. Use after creating a reviewable snapshot, before every
  reviewer attempt, or when the user requests lint for commits. Do not use as
  a build or runtime-test substitute, and never delegate lint to a subagent.
---

# Lint an SCST patch

Execute this skill directly in the main agent. Never spawn a lint subagent.
Receive exact `base` and `head` commits and run every applicable independent
component even when another component fails, so the report contains the full
diagnostic set.

## Preflight the range and snapshot

1. Resolve both inputs as commits with `git rev-parse --verify`.
2. Require a non-empty `base..head` range.
3. Require `git merge-base --is-ancestor "$base" "$head"` to succeed.
4. Require current `HEAD` to equal `head` because the tracked
   `scripts/checkpatch_commits` interface checks `base..HEAD`.
5. Require the index and tracked working-tree files to match committed
   `head`. Preserve unrelated untracked and ignored files and do not treat
   them as a blocker.
6. Read applicable `AGENTS.md` files and confirm every command from the
   current tracked tree before running it.

Return `BLOCKED` for an invalid range, mismatched tracked snapshot, missing
required infrastructure, or incomplete coverage.

## Run all lint components

Run at least these components:

1. Run `git diff --check "$base" "$head" --` for the exact range.
2. Run `./scripts/checkpatch_commits "$base"`. This is the tracked SCST
   entry point for every commit in `base..HEAD`; the preflight makes
   `HEAD == head`. Do not invent options or use an untracked helper.
3. If the range changes a tracked Bash script in `scripts/`,
   `scripts/run-shellcheck` itself, or the `shellcheck` target in the
   top-level `Makefile`, run `./scripts/run-shellcheck` from the repository
   root. A missing `shellcheck` is `BLOCKED` in that case; report
   `NOT_APPLICABLE` for other ranges.
4. Manually verify Linux kernel coding style for every changed kernel C and
   header file. Use the diff plus enough surrounding code to judge context.
5. Inspect every commit as an independently reviewable semantic unit. Check
   its subject and body against applicable repository rules and current SCST
   history, including concise imperative wording and established prefixes.

Add a file-type-specific check only when the current SCST tree provides a
tracked, established entry point and its usage has been confirmed. Never run
an automatic formatter that modifies source files.

Do not run builds, runtime tests, benchmarks, module operations, sparse,
smatch, another heavyweight analyzer, or any command that changes live SCST,
a service, transport, sysfs, hardware, or device state.

## Classify diagnostics

- Inspect all output instead of stopping at the first failure.
- Treat a diagnostic caused by changed code, configuration, or lint rules as
  a patch diagnostic.
- When a diagnostic may predate the range, compare the relevant path and
  line at `base` and `head` with read-only Git commands. Report a confirmed
  pre-existing diagnostic as a non-blocking baseline.
- Treat all unwaived patch diagnostics as failures.
- Waive a diagnostic only for a demonstrated false positive or when the
  suggested change conflicts with correctness, a required ABI layout, or the
  applicable code style. Report its diagnostic, commit, path, line, and
  justification.

During authorized patch development, fix every patch-introduced diagnostic,
amend or fix up the appropriate logical commit, update `head`, and rerun the
complete range. For standalone lint without authorization to edit, report
only the result.

## Report the lint gate

End with exactly one marker block:

```text
LINT_EXECUTOR: main
DIFF_CHECK: <PASS|FAIL|BLOCKED>
CHECKPATCH: <PASS|WAIVED|FAIL|NOT_APPLICABLE|BLOCKED>
SHELLCHECK: <PASS|FAIL|NOT_APPLICABLE|BLOCKED>
CODE_STYLE: <PASS|FAIL|NOT_APPLICABLE|BLOCKED>
COMMIT_STYLE: <PASS|FAIL|BLOCKED>
LINT_BASELINE: <CLEAN|PRESENT|BLOCKED>
LINT_COVERAGE: <COMPLETE|BLOCKED>
LINT_STATUS: <PASS|FAIL|BLOCKED>
```

Use `PASS` only with complete coverage and no unwaived patch diagnostics.
Use `FAIL` for a completely evaluated range with an unwaived patch
diagnostic. Use `BLOCKED` for infrastructure failure or incomplete coverage.
