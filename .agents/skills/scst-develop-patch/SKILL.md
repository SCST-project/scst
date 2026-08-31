---
name: scst-develop-patch
description: Internal implementation, commit, lint, and optional review layer invoked by scst-develop-in-worktree with one TASK_CONTRACT and exact isolated result context.
---

# Implement one isolated SCST patch series

Use this internal layer only when `$scst-develop-in-worktree` supplies the complete current
`TASK_CONTRACT` unchanged and exact `TASK_RESULT_CONTEXT`. Do not accept a direct user or
personal-guidance entry, create another contract, secondary task summary, implementation
plan, or task interpretation, or repeat top-level task-shaping policy.

Before editing, require the supplied `PATCH_BASE`, `START_RESULT_TIP`, `RESULT_REF`,
`WORKTREE_PATH`, and mode to match the clean isolated worktree identity established by
the lifecycle. Tracked or untracked WIP, a context mismatch, or a pre-existing active
Git operation is `BLOCKED`; do not fall back to the process's current commit or a
non-isolated checkout.

## Implement and inspect

1. Read every applicable `AGENTS.md` and the relevant code, tests, configuration,
   executable build or validation recipes, and maintained documentation.
2. Inspect producers, consumers, strict parsers, and tests for every interface or format
   change. Use CodeGraph only as an optional navigation aid.
3. Implement the smallest coherent result. Do not add unrelated refactoring,
   speculative abstractions, optional hardening, or support outside the contract.
4. Explain a non-obvious design in normal task communication. Do not create a separate
   design artifact or implementation plan.
5. Inspect the complete diff before committing, including task satisfaction, scope,
   call paths, error and cleanup paths, cross-component consistency, and tests.
6. Create the smallest semantic commit series permitted by the task. Keep repository-
   maintained prose and commit messages in English.
7. Apply `$scst-lint-patch` in the implementation-owning agent to the exact committed
   `PATCH_BASE..PATCH_HEAD`. Fold fixes into their owning commits and rerun the complete
   lint gate.
8. Inspect the complete committed diff again after lint.
9. Only when `ACCEPTED_DECISIONS` records an explicit user request for independent
   review and no reviewer has started since that request, apply `$scst-review-patch` with
   the same `TASK_CONTRACT` unchanged and exact range.

The workflow does not compile the product or run product runtime tests, benchmarks,
module operations, or build-based analyzers. Report that boundary explicitly.

## Review result

Do not invoke a reviewer by default. An explicit user request for independent review in
the current `ACCEPTED_DECISIONS` authorizes the next invocation after lint and author
inspection, including when the request precedes the completed patch. Treat the request
as consumed when the reviewer starts. Without an unconsumed request, set
`REVIEW: NOT_RUN`; this does not block a `READY` handoff.

After a requested review returns `FAIL` or `BLOCKED`, do not return `PATCH_HANDOFF`, edit
the patch, or automatically invoke another reviewer. Preserve the exact `PATCH_BASE`,
reviewed `PATCH_HEAD`, result ref, worktree, and findings; report them to the main agent
and user, then wait for a user decision.

When the user later accepts corrections, continue this same patch context and keep the
original `PATCH_BASE`. Record the decision in `ACCEPTED_DECISIONS`, apply only the
accepted corrections, fold them into their owning commits, and rerun complete lint and
author inspection for `PATCH_BASE..PATCH_HEAD`. Keep the resulting `TASK_CONTRACT`
unchanged for any subsequently requested review. Do not classify the work as a later
increment or reset the gate base to the previously failed head. Accepted corrections do
not authorize another reviewer invocation. A changed reviewed head requires a fresh user
request before another reviewer starts. Every committed range change invalidates prior
lint and review evidence.

Return a `BLOCKED` handoff when a requested review has not passed and the user ends the
attempt, or when the workflow cannot continue.

## Return the handoff

Return this handoff to the calling workflow:

```text
PATCH_HANDOFF:
STATUS: <READY|BLOCKED>
PATCH_BASE: <full commit>
PATCH_HEAD: <full commit|none>
LINT: <PASS|FAIL|BLOCKED|NOT_RUN>
REVIEW: <PASS|FAIL|BLOCKED|NOT_RUN>
LIMITATIONS: compilation and runtime validation were not performed; <other limitations|none>
```

Before return, run:

```sh
python3 <WORKTREE_PATH>/.agents/workflow/check.py snapshot \
  --repository <WORKTREE_PATH> \
  --base <PATCH_BASE> \
  --head <PATCH_HEAD> \
  --require-no-untracked
```

`READY` requires a non-empty clean range, lint `PASS`, and either `REVIEW: NOT_RUN` when
the user did not request review or `REVIEW: PASS` when review was requested. Incomplete
required evidence produces a preserved `BLOCKED` result. In a blocked handoff, use
`LINT: FAIL` for a complete gate with an unwaived diagnostic and reserve `LINT: BLOCKED`
for incomplete lint evidence.
