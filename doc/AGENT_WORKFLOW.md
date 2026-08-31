# AI-assisted development workflow

This guide explains the repository's minimal opt-in AI-assisted development workflow.
Operational instructions live in applicable `AGENTS.md`, `.agents/skills/`, and
`.codex/agents/` files. Harness design principles live in
[`AGENT_HARNESS.md`](AGENT_HARNESS.md).

## Sources of truth

- The user's original request and later explicit decisions define the task.
- Current code, tests, build logic, and configuration define product behavior.
- Applicable `AGENTS.md` files provide stable repository and component context.
- `scst-develop-task` owns discussion, the task contract, implementation, and delivery.
- It invokes `scst-develop-in-worktree` for the result branch and raw-worktree lifecycle.
- That lifecycle invokes `scst-develop-patch` for implementation, semantic commits, lint,
  author inspection, and optional independent review.
- `scst-lint-patch` owns the mandatory lint gate. `scst-review-patch` owns the review gate
  when the user explicitly requests it.
- `scst-validate-series` is the separate user-facing entry point that composes every
  standard non-build gate for one complete committed series.
- After explicit worker delegation, `scst-explain-worker-patch` provides the walkthrough.
- For a concrete harness-failure candidate, `scst-assess-harness-incident` invokes the
  read-only evaluator and returns its assessment to the main agent.

An agent summary never replaces the original user input.

## Invocation policy

Repository skills are opt-in capabilities, not repository-wide defaults. Users or
user-scoped personal guidance may select only a user-facing workflow. `scst-develop-task`
is the development entry point. `scst-validate-series` is the explicit final full-series
validation entry point. Their internal skills are invoked only by their owning workflow
and carry explicit metadata that disables implicit invocation; that metadata does not
make them supported user entry points.

Personal guidance should route to the repository entry point instead of copying its
operational instructions. This keeps shared behavior reviewable in Git without imposing
one developer's automation policy on every contributor.

## Lifecycle

```text
original request and explicit decisions
        -> main-agent-owned TASK_CONTRACT
        -> repository context
        -> isolated result branch and raw worktree
        -> implementation and semantic commits
        -> deterministic lint and author inspection
        -> optional independent read-only review when requested
        -> ready or preserved blocked result
        -> optional main-agent push
        -> verified worktree cleanup
        -> final workflow report
```

The baseline uses one implementation owner, one result branch, and no more than one raw
worktree for the task at a time. It has no automatic implementation worker, semantic
routing formula, or parallel-lane accounting.

Every gate applies to one exact committed range. Any committed change invalidates prior
lint and review evidence for that range.

## Explicit full-series validation

`scst-validate-series` runs only after an explicit user request. It requires the retained
complete `TASK_CONTRACT` plus literal full base and head commits for one non-empty series;
it neither reconstructs missing task intent nor infers the range from a branch name.

The main agent uses an existing clean worktree at the exact head or creates a temporary
detached raw worktree without changing refs. It runs the exact snapshot, complete
`scst-lint-patch`, author inspection of the full range, and one `scst-review-patch` call in
that order. A lint failure prevents review. The series remains frozen and read-only;
findings return to the user rather than being fixed automatically.

Report each gate and the overall `PASS`, `FAIL`, or `BLOCKED` result without introducing
another machine-readable handoff schema. Remove only a clean temporary worktree created
by the validation skill; never remove the caller's worktree or alter user WIP.

## Personal development workflow

The main agent reads the project, discusses behavior and architectural decisions in the
user's language, and creates one concise `TASK_CONTRACT` containing only:

```text
ORIGINAL_REQUEST:
<the user's original request verbatim>

DISCUSSION_RECORD:
<material task-shaping context, alternatives, rationale, constraints, and risks>

ACCEPTED_DECISIONS:
<required behavior, prohibitions, non-goals, and the current increment>
```

`ORIGINAL_REQUEST` is the authoritative initial input. A later explicit user decision
recorded in `ACCEPTED_DECISIONS` may clarify or supersede it and controls the current
result. `DISCUSSION_RECORD` provides rationale and disambiguation but cannot silently add
requirements. It is not a transcript or an unexplained summary.

The main agent shows the complete current contract before tracked implementation. It may
continue in the same turn when the existing request already authorizes the scope. It
returns to discussion when a material design choice, scope expansion, unresolved
observable behavior, validation waiver, or separate destructive-operation authorization
requires a user decision.

Standard worktree, commit, lint, review, snapshot, build/runtime-boundary, report, and
push procedures remain in their owning roles and skills. Their evidence is reported in
`PATCH_HANDOFF`, not copied into the contract. Implementation and review receive the same
complete current contract unchanged and create no second contract, design artifact, or
implementation plan.

One run owns one coherent outcome represented by one or more semantic commits. The main
agent bounds independent outcomes into reviewable increments and implements only the
current authorized increment. Later accepted increments reuse the same result branch.

The main agent may start `scst_worker` only after explicit user delegation. The worker
receives the repository path, selected local base, and unchanged contract in a fresh
context. It owns implementation, lint, author inspection, and any explicitly requested
review for its result but never pushes. `scst-explain-worker-patch` then accounts for
end-to-end behavior, every changed function or equivalent artifact, risks, and
validation before the main agent returns only user-accepted corrections to that same
worker.

For a concrete harness-failure candidate, the read-only evaluator receives clearly
labeled initial and candidate evidence: each applicable unchanged contract, exact range,
raw observations, and handoff when one exists. If review paused the workflow before
handoff, that evidence instead includes the preserved result context, lint status, raw
reviewer output and findings, and the reason no handoff exists. When both refer to one
increment, the evidence is supplied once. The evaluator returns a rejection or a
journal-ready confirmed assessment. Only the main agent may record it through a separate
tracked workflow, and a harness fix requires separate user authorization.

## Project knowledge and design

Before analyzing, reviewing, or changing a subtree, read every applicable `AGENTS.md`
and the maintained documents they route to. Inspect relevant current code, tests,
configuration, and, when needed and permitted, history. CodeGraph is an optional
navigation aid for cross-component relationships, not a validation gate.

Interfaces and machine-readable formats shared by the core, target drivers, user-space
daemons, management tools, and tests form one snapshot contract. Investigate their
producers, consumers, strict parsers, and tests together.

Choose the smallest design that satisfies the contract. Do not add unrelated refactoring,
speculative abstractions, optional hardening, or future support. Explain a non-obvious
design in normal task communication.

## Isolation and result branches

At task start, capture only the initial symbolic local branch as the default base. An
explicitly named local base overrides it. Switching the stable checkout later changes
neither value. Resolve the selected base commit only when tracked implementation starts.

Read the result-branch prefix only from repository-local `scst.chatBranchPrefix` Git
configuration. Require one valid value and no fallback. The first tracked increment
creates a unique `<configured-prefix>/<short-topic>-<short-id>` branch from the exact base
tip and checks it out in a raw Git worktree. Later accepted work for the same task reuses
that result branch.

Never switch, detach, restore, repair, or otherwise modify the stable checkout. Preserve
its tracked and untracked WIP. Require the isolated result worktree to be fully clean,
including no untracked files, before handoff.

An append-mode initial snapshot explicitly allows an empty range because implementation
has not started. A rewrite-mode initial snapshot instead verifies the non-empty range
from the last preserved commit through the current result tip. Every committed-range and
final snapshot rejects an empty range. The workflow verifies exact worktree registration,
symbolic result ref, `HEAD`, ancestry, tracked state, and untracked state through the
commands in the lifecycle skill.

Append mode and no push are defaults. Rewriting result-branch history requires explicit
authorization and never rewrites the base. Only the main agent may perform an explicitly
authorized push. That optional protocol binds one remote name, exact push URL, remote
result ref, and observed tip; it rechecks the tip immediately before pushing and uses an
exact lease for both existing and absent refs. It never redirects to the base branch.
Each exact URL/ref pair is treated as a first publication unless a prior successful push
report from the same task proves that it published the current start result tip to that
pair.

## Result handling

Successful cleanup begins only after a validated `PATCH_HANDOFF` with `STATUS: READY`.
It rechecks the exact range, ref, `HEAD`, cleanliness, and absence of an active Git
operation, then removes only the recorded result worktree. It retains the result branch
for user-controlled integration and never updates the base.

A result is preserved when it has changes or commits, an active Git operation, a failed
identity check, or uncertain ownership or recovery state. Report the path, result ref,
head, status, and exact preservation reason. An untouched blocked worktree may be removed
only through the bounded checks in `blocked-cleanup.md`.

## Lint and author inspection

The implementation-owning agent inspects the complete diff before committing and again
after lint. It checks task satisfaction, scope, call paths, error and cleanup paths,
producer/consumer consistency, and relevant tests. This is an author check, not a review
verdict. Any requested independent review follows that inspection on the unchanged head.

`scst-lint-patch` validates the exact committed range with:

- `git diff --check`;
- the repository-native per-commit `scripts/checkpatch_commits` gate;
- C and header style inspection when applicable;
- ShellCheck for changed Bash scripts;
- pinned Ruff for changed Python;
- objective instruction and standalone role checks;
- focused harness helper unit tests when agent workflow files change; and
- commit structure and message validation.

The focused helper tests validate deterministic harness code; they are distinct from
product builds and runtime tests. Language-specific checks run only for matching tracked
files. Diff checking, checkpatch, and commit validation apply to every non-empty range.

## Independent review

After lint passes, `scst_reviewer` receives only the unchanged current `TASK_CONTRACT` and
exact committed range. It remains read-only, inspects the complete patch and surrounding
context, and reports concrete defects or a missing checkable artifact required for
changed behavior. The standard absence of product compilation or runtime execution is
not itself a finding.

Do not invoke the reviewer by default. An explicit user request recorded in the current
`ACCEPTED_DECISIONS` authorizes the next invocation after lint and author inspection,
including when the request precedes the completed patch. The request is consumed when
the reviewer starts. Without an unconsumed request, `PATCH_HANDOFF` reports
`REVIEW: NOT_RUN`, and the result may be `READY` when the other required evidence passes.

A requested review that returns `FAIL` or `BLOCKED` pauses before `PATCH_HANDOFF`,
preserves the original gate base, reviewed head, result ref, worktree, and findings, and
returns control to the user without automatic edits or another reviewer call.

Any later accepted corrections continue in that same patch context with the original
gate base. Fold them into their owning commits and rerun complete lint and author
inspection for the full range. Do not treat reviewer-driven corrections as a later
increment or reset the gate base to the failed head. Accepted corrections do not
authorize another reviewer invocation. A changed reviewed head requires a fresh user
request before another reviewer starts. When review was requested, only `PASS` permits
`READY`.

Unavailable personal kernel guidance does not block review. The reviewer continues from
repository code and documentation and reports `KERNEL_CONTEXT: unavailable`.

## Validation boundary

The workflow stops after deterministic lint and author inspection, plus independent
review when explicitly requested. It does not compile the product, load or run kernel
modules, or exercise product runtime behavior. Every handoff and final report states
that limitation explicitly.

## Final workflow report

Report:

- base ref, result ref, exact range, and semantic commits;
- lint evidence, review status, and any confirmed findings;
- explicit absence of compilation and runtime validation plus other limitations;
- that the base ref was not integrated or updated;
- authorized push evidence or `NOT_REQUESTED`; and
- worktree cleanup status and every preserved path.

`PATCH_HANDOFF` is the baseline machine-readable workflow result. Add another result
schema only when a real consumer and observed failure justify it.

## Evolving the workflow

Use concrete task failures and repeated corrections to choose improvements. Put stable
project facts in `AGENTS.md`, conditional procedure in a concise skill or reference, and
observable repeatable checks in scripts or CI. Record durable incidents in
[`AGENT_HARNESS_CASES.md`](AGENT_HARNESS_CASES.md); do not maintain a speculative
duplicate backlog.
