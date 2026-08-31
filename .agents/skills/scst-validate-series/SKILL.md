---
name: scst-validate-series
description: User-facing opt-in validation workflow for running every standard non-build SCST gate on one complete committed patch series. Use only when the user explicitly asks for final full-series validation after development and the exact range plus its retained TASK_CONTRACT are available; it runs snapshot checks, full lint, author inspection, and one independent read-only review without fixing or publishing the patch.
---

# Validate one complete SCST patch series

Do not modify the validated commits, branch refs, or tracked content. Do not invoke this
skill automatically, implement fixes, merge, rebase, push, or start an implementation
worker. Return every finding to the user for a separate decision.

## Require exact inputs

Require the canonical repository root, literal full `SERIES_BASE` and `SERIES_HEAD`
commits, and the complete main-agent-owned `TASK_CONTRACT` retained from development.
Record the user's validation request in `ACCEPTED_DECISIONS`, then preserve the contract
unchanged through every gate. Do not reconstruct a missing contract, infer a range from
a branch name, or accept an empty or non-ancestral range.

Run validation from a clean worktree whose `HEAD` equals `SERIES_HEAD`. Reuse an existing
registered worktree only when it is clean, contains no untracked files, and has no active
Git operation. Otherwise create a unique parent under `/tmp` and add a detached raw
worktree at `SERIES_HEAD`. Record whether this skill owns that temporary worktree; never
remove a caller-owned worktree.

Before gates, run:

```sh
python3 <VALIDATION_WORKTREE>/.agents/workflow/check.py snapshot \
  --repository <VALIDATION_WORKTREE> \
  --base <SERIES_BASE> \
  --head <SERIES_HEAD> \
  --require-no-untracked
```

## Run all non-build gates

1. Apply `$scst-lint-patch` in the main agent to the exact
   `SERIES_BASE..SERIES_HEAD`. Do not start a lint subagent.
2. Continue only after complete lint `PASS`. Inspect the complete committed diff for
   task satisfaction, scope, call paths, error and cleanup paths, cross-component
   contracts, and relevant tests.
3. Apply `$scst-review-patch` once with the unchanged `TASK_CONTRACT` and exact range.
   Freeze the range while the reviewer runs.
4. Require the reviewer output contract, complete coverage, applied task input, and
   `PASS`. Re-run the exact snapshot after review.

This bundle does not compile the product or run product runtime tests, benchmarks,
module operations, build-based analyzers, or destructive tests.

## Report and clean up

Report the exact repository and range, snapshot, lint, author inspection, review status,
confirmed findings, and validation limitations. Use overall `PASS` only when every gate
passes on the unchanged range. A gate failure is `FAIL`; an unavailable prerequisite,
missing contract, ambiguous range, incomplete gate, or cleanup uncertainty is
`BLOCKED`.

If this skill created the validation worktree, remove it only after rechecking that it is
clean, has no active Git operation, and still selects `SERIES_HEAD`. Verify it is no
longer registered, then remove the exact temporary parent only when empty. Preserve and
report the path on any identity, cleanliness, ownership, or cleanup failure.
