---
name: develop-patch
description: >-
  Develop minimal SCST patches from task contract through committed lint and
  independent review. Allow a separate experimental path with mandatory lint
  and deferred review for explicitly temporary, low-risk diagnostics. Use for
  bug fixes, new behavior, refactoring, and temporary instrumentation that
  require file changes. Do not use for standalone review, lint-only requests,
  or read-only investigation.
---

# Develop an SCST patch

Execute this workflow in the main agent.

## Record the task contract

Before investigation, record the user's requirements without inventing
exceptions:

```text
TASK_CONTRACT:
GOAL:
ACCEPTANCE:
NON_GOALS:
ALLOWED_EXCEPTIONS:
FORBIDDEN_CHANGES:
```

`GOAL` and `ACCEPTANCE` must describe the required result and its minimal
verifiable conditions and cannot be `None`. Use `None` for any other
unspecified field.

`NON_GOALS` describes scenarios and behavior outside the current scope, while
`FORBIDDEN_CHANGES` describes prohibited mechanisms, paths, and change
boundaries. Do not duplicate an item in both fields. Apply exceptions
literally and do not extend them by analogy. Ask for clarification only when
ambiguity would materially change scope or outcome.

After recording `TASK_CONTRACT`, change it only in response to a new user
decision. Do not change it during investigation or implementation, and never
adjust it merely to pass lint or review.

## Select the patch phase

After `TASK_CONTRACT` and before investigation, record:

```text
PATCH_PHASE: <EXPERIMENTAL|REVIEWABLE>
REVIEW_POLICY: <DEFERRED|REQUIRED>
```

Only `EXPERIMENTAL/DEFERRED` and `REVIEWABLE/REQUIRED` are valid pairs.
`PATCH_PHASE` determines reviewer policy, not lint policy: the complete
`$lint-patch` gate is mandatory for every committed snapshot in both phases.

Use `EXPERIMENTAL` only when the user explicitly requests temporary diagnostic
or test instrumentation, or a short-lived hypothesis check, and all of these
conditions hold:

- the patch is not intended for merge, handoff, or another permanent use;
- changes are limited to observability or easily removable test scaffolding
  and do not alter supported behavior;
- the patch does not change an external or internal interface or contract,
  ABI, UAPI, sysfs, configuration, a parser or machine-readable output,
  persistent or in-memory state, build, CI, generation, delivery, or release
  configuration;
- the patch does not affect data integrity, a security boundary, memory or
  resource lifetime, reference counting, locking, concurrency, teardown,
  rollback, cancellation, error semantics, or destructive operations.

Use `REVIEW_POLICY: DEFERRED` for `EXPERIMENTAL`. This defers review until the
result becomes a permanent patch; it does not waive final review. An explicit
user request for review promotes the patch to `REVIEWABLE/REQUIRED`. When
uncertain, use `REVIEWABLE`; a small diff alone does not make a patch
experimental.

Classify independent commit ranges separately and do not combine experimental
and reviewable commits in one gate range. If experimental scope expands beyond
the boundaries above, announce promotion to `REVIEWABLE` before making further
changes. Never downgrade the phase after a lint or reviewer finding to bypass
a gate.

## Record the minimal design

For `REVIEWABLE`, record this block before the first reviewable snapshot:

```text
SUPPORTED_SCENARIO:
DESIGN:
KNOWN_LIMITATIONS:
```

Derive `SUPPORTED_SCENARIO` from the task contract. Choose the smallest
complete `DESIGN` that satisfies `ACCEPTANCE`. Do not narrow the supported
scenario after a finding or relabel a correctness or regression defect
introduced by the patch as a known limitation.

## Common preparation

1. Inspect `git status`, including ignored state, and preserve every existing
   tracked, untracked, ignored, generated, and secret path.
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

Run builds or runtime tests only when the user explicitly requests them and
the applicable `AGENTS.md` permits the exact operation. They remain outside
this base workflow. Otherwise report both as `NOT_REQUESTED`.

## Experimental path

For `PATCH_PHASE: EXPERIMENTAL`:

1. Implement the shortest patch for the specified check without adding
   production guarantees beyond `TASK_CONTRACT`.
2. Create a separate commit so the patch can be removed or rewritten
   unambiguously. Do not combine it with a permanent change. Record exact
   `base` and `head` commits.
3. Read the complete `git diff <base>..<head>` and run
   `git diff --check <base>..<head>`.
4. Invoke `$lint-patch` directly in the main agent for the complete exact
   range. On `FAIL`, fix every diagnostic without a waiver, update `head`, and
   repeat the complete lint gate. Do not finish without `LINT_STATUS: PASS`
   for the current `head`.
5. Do not start a reviewer while the patch remains within the experimental
   boundaries and the user has not explicitly requested review. On an
   explicit review request, first promote the patch to `REVIEWABLE/REQUIRED`
   and use the reviewable path.
6. Record:

```text
LINT_STATUS: <PASS|FAIL|BLOCKED>
REVIEW_STATUS: DEFERRED_EXPERIMENTAL
REVIEW_ATTEMPTS: 0
```

Any change to `head` invalidates lint and the results of requested optional
gates for the previous snapshot. Repeat the applicable checks for the new
exact range. Any diagnostic that is neither fixed nor covered by a justified
waiver, or any unreliable validation, requires `BLOCKED`, not deferred
review.

## Reviewable path

For `PATCH_PHASE: REVIEWABLE`:

1. Inspect the complete diff and run `git diff --check`.
2. Create a reviewable commit or logical commit series unless the user
   explicitly requested an uncommitted patch. Keep each commit a coherent,
   independently reviewable semantic unit and exclude unrelated worktree
   state.
3. Record the committed snapshot as exact `head`. For an explicitly requested
   uncommitted patch, stop before the committed-only gates and report them as
   `BLOCKED` unless the user separately changes acceptance.
4. Invoke `$lint-patch` directly in the main agent for the complete
   `base..head` range.
5. Do not start review until the current `head` has `LINT_STATUS: PASS`.
6. Invoke `$review-patch` for the same `base..head`, repository path, and
   unchanged `TASK_CONTRACT`.
7. Wait for the terminal reviewer result before modifying the patch.
8. If a required change modifies `head`, amend or fix up the appropriate
   logical commit, update `head`, rerun the complete lint gate, and start a
   new independent review only after lint passes.

## Bound the review cycle

Use this cycle only for `REVIEW_POLICY: REQUIRED`. Allow no more than three
reviewer attempts for one `TASK_CONTRACT`. Count an attempt only when
`scst_reviewer` actually starts for a specific `head`. Lint reruns do not
consume attempts.

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
- Reread `TASK_CONTRACT`, `SUPPORTED_SCENARIO`, `DESIGN`,
  `KNOWN_LIMITATIONS`, the complete diff, and findings from both attempts.
- Group findings by root cause and determine whether the design has grown
  beyond the task.
- Prefer simplifying the patch to the smallest correct design.
- Finish with `BLOCKED` if a new user decision is required.
- Otherwise make at most one final coherent snapshot update, rerun the full
  lint gate, and start attempt 3 only after lint passes.

### Attempt 3

- Treat this as the final independent review. Never automatically start a
  fourth reviewer.
- `PASS` permits successful completion.
- On `FAIL`, classify every remaining finding. Finish with `BLOCKED` if any
  finding violates `GOAL`, `ACCEPTANCE`, or correctness of
  `SUPPORTED_SCENARIO`.
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

For `SUCCESS` in both phases, require:

- `GOAL` and `ACCEPTANCE` are satisfied;
- the current `head` has `LINT_STATUS: PASS`;
- every explicitly requested optional gate reports `PASS` or a justified
  `NOT_APPLICABLE`.

For `EXPERIMENTAL`, also require the patch to remain within every experimental
boundary and the result to contain `REVIEW_STATUS: DEFERRED_EXPERIMENTAL` and
`REVIEW_ATTEMPTS: 0`.

For `REVIEWABLE`, also require:

- `SUPPORTED_SCENARIO` is satisfied;
- the final reviewer result is acceptable under the bounded-cycle rules;
- every remaining limitation is explicitly documented.

Include the following in the final report:

- `PATCH_PHASE` and `REVIEW_POLICY`;
- exact `base` and final `head`;
- `DEVELOP_STATUS`, lint status, reviewer status, and reviewer attempt count;
- task-specific exceptions and lint waivers;
- checks actually executed;
- build and test status, normally `NOT_REQUESTED`;
- all `KNOWN_LIMITATIONS`, or `None` for an experimental patch.
