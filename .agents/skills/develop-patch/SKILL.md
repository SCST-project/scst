---
name: develop-patch
description: >-
  Develop minimal, reviewable SCST patches from task contract through
  committed lint and independent review. Use for bug fixes, new behavior, and
  refactoring that require file changes. Do not use for standalone review,
  lint-only requests, or read-only investigation.
---

# Develop an SCST patch

Execute this workflow in the main agent.

## Record the contract and design

Before implementation, record the user's requirements without inventing
exceptions:

```text
TASK_CONTRACT:
GOAL:
ACCEPTANCE:
NON_GOALS:
ALLOWED_EXCEPTIONS:
FORBIDDEN_CHANGES:
```

Use `None` for an unspecified value. Apply exceptions literally and do not
extend them by analogy. Ask for clarification only when ambiguity would
materially change scope or outcome.

Before the first reviewable snapshot, record:

```text
SUPPORTED_SCENARIO:
DESIGN:
KNOWN_LIMITATIONS:
```

Derive `SUPPORTED_SCENARIO` from the task contract. Keep `DESIGN` to the
smallest complete mechanism that satisfies acceptance. Do not relabel a
patch-introduced correctness or regression defect as a known limitation.

## Develop the patch

1. Inspect `git status`, including ignored state, and preserve every
   pre-existing tracked, untracked, ignored, generated, and secret path.
2. Record the starting commit as exact `base` unless the user supplied a
   different base.
3. Read every applicable `AGENTS.md` from the repository root to each file
   that may change.
4. Inspect the current implementation, call paths, interfaces, tests,
   Makefiles, compatibility checks, and Git history needed by the task.
5. For interface, ABI, configuration, or output changes, trace every affected
   producer, consumer, parser, and test.
6. Implement the smallest complete patch satisfying the task contract. Avoid
   unrelated cleanup, speculative hardening, and premature architectural
   expansion.
7. Inspect the complete diff and run `git diff --check`.
8. Create a reviewable commit or logical commit series unless the user
   explicitly requested an uncommitted patch. Keep each commit a coherent,
   independently reviewable semantic unit and exclude unrelated worktree
   state.
9. Record the committed snapshot as exact `head`.
10. Invoke `$lint-patch` directly in the main agent for the complete
    `base..head` range.
11. Do not start review until the current head has `LINT_STATUS: PASS`.
12. Invoke `$review-patch` for the same `base..head`, repository path, and
    unchanged `TASK_CONTRACT`.
13. Wait for the terminal reviewer result before modifying the patch.
14. If a required change modifies `head`, amend or fix up the appropriate
    logical commit, update `head`, rerun the complete lint gate, and start a
    new independent review only after lint passes.

Run builds or runtime tests only when the user explicitly requests them and
the applicable `AGENTS.md` permits the exact operation. They remain outside
this base workflow. Otherwise report both as `NOT_REQUESTED`.

## Bound the review cycle

Allow no more than three reviewer attempts for one `TASK_CONTRACT`. Count an
attempt only when `scst_reviewer` actually starts for a specific `head`. Lint
reruns do not consume attempts.

### Attempt 1

- Start only after lint passes.
- Review the full current `base..head`.
- On `PASS`, finish the review cycle.
- On `FAIL`, collect every finding before modifying the patch.
- Fix findings required by `GOAL`, `ACCEPTANCE`, or correctness of
  `SUPPORTED_SCENARIO`. Do not expand scope for optional hardening.
- Amend or fix up the appropriate commits, update `head`, and rerun the full
  lint gate before attempt 2.

### Attempt 2

- Review the complete updated range.
- On `FAIL`, do not immediately apply another sequence of isolated fixes.
- Re-read `TASK_CONTRACT`, `SUPPORTED_SCENARIO`, `DESIGN`,
  `KNOWN_LIMITATIONS`, the full diff, and findings from both attempts.
- Group findings by root cause and determine whether the design has grown
  beyond the task.
- Prefer simplifying the patch to the smallest correct design.
- Stop with `BLOCKED` if a new user decision is required.
- Otherwise make at most one final coherent snapshot update, rerun the full
  lint gate, and start attempt 3 only after lint passes.

### Attempt 3

- Treat this as the final independent review. Never start a fourth automatic
  reviewer.
- `PASS` permits successful completion.
- On `FAIL`, classify every remaining finding. Finish with `BLOCKED` if any
  finding violates `GOAL`, `ACCEPTANCE`, or `SUPPORTED_SCENARIO` correctness.
- Record a finding outside the supported scenario as a known limitation only
  when it does not contradict the task contract. The reviewer result remains
  `FAIL`; accept it only under this final-attempt rule.
- On `BLOCKED`, finish with `BLOCKED`.

Any change to `head` invalidates all lint and review results for the previous
snapshot. Always restart validation with `$lint-patch`. Never run lint and
review in parallel.

## Report the result

Use only:

```text
DEVELOP_STATUS: <SUCCESS|BLOCKED>
```

Require all of the following for `SUCCESS`:

- `GOAL`, `ACCEPTANCE`, and `SUPPORTED_SCENARIO` are satisfied.
- The current `head` has `LINT_STATUS: PASS`.
- The final reviewer result is acceptable under the bounded-cycle rules.
- Every remaining limitation is explicitly documented.

Include the following in the final report:

- exact `base` and final `head`;
- `DEVELOP_STATUS`, lint status, reviewer status, and reviewer attempt count;
- task-specific exceptions and lint waivers;
- checks actually executed;
- build and test status, normally `NOT_REQUESTED`;
- all `KNOWN_LIMITATIONS`.
