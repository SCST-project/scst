---
name: scst-develop-task
description: Discuss and deliver one iterative SCST patch series owned by the main agent. Use when user-scoped personal guidance selects this workflow; reserve scst_worker for explicit user-requested delegation.
---

# Develop an SCST task in the main agent

The main agent owns task discussion, the current `TASK_CONTRACT`, implementation, and
result delivery. Do not start an implementation worker automatically.

## Shape the task

1. Read the applicable `AGENTS.md`, code, tests, and maintained documentation.
2. For kernel code or a kernel-facing interface, load the available `$kernel` skill. If
   it is not listed, use `kernel/SKILL.md` from a standard personal skill root when
   present. Skip kernel guidance only when the task is clearly confined to non-kernel
   material.
3. Discuss the current behavior, desired behavior, architectural decisions,
   alternatives, and risks in the user's language. Prefer plain explanations and define
   necessary technical terms.
4. Identify one coherent patch series. Before each implementation, make only the next
   small reviewable behavioral increment explicit. Do not pre-commit later increments
   to an agent-invented decomposition.
5. Take implementation authorization from the user's original request and later
   explicit decisions. Do not require a separate start phrase when the request already
   authorizes the scope and no material decision remains unresolved.

Create and maintain one concise main-agent-owned `TASK_CONTRACT` for the series. It
contains only `ORIGINAL_REQUEST`, `DISCUSSION_RECORD`, and `ACCEPTED_DECISIONS`.
`ORIGINAL_REQUEST` preserves the user's original task verbatim. `DISCUSSION_RECORD`
captures only task-shaping context: relevant alternatives and why they were accepted or
rejected, plus constraints and risks that affected the result. It is neither a
conversation transcript nor an unexplained final summary; omit repetition and intermediate
speculation, and preserve exact controlling wording only when the wording itself matters.

`ACCEPTED_DECISIONS` is normative. Record the required behavior, material prohibitions
and non-goals, and the current increment there. Include validation only for an explicit
task-specific user decision, authorization, prohibition, or waiver. `ORIGINAL_REQUEST`
is the authoritative initial input. A later explicit user decision recorded in
`ACCEPTED_DECISIONS` may clarify or supersede it and controls the current result.
`DISCUSSION_RECORD` provides rationale and disambiguation without silently adding
requirements. An unresolved material decision blocks tracked implementation. Update the
contract only as discussion produces accepted results, corrections, or another
user-approved increment. Do not add an implementation plan.

Show the complete current `TASK_CONTRACT` before starting tracked implementation.
Showing it does not itself require a pause: continue in the same turn when the existing
request already authorizes its scope and the contract only records the accepted task. Ask
for a decision when the contract would add a material choice, expand scope or authority,
leave observable behavior, protocol, or ownership unresolved, or require a validation
waiver or separate destructive-operation authorization.

Do not restate standard worktree, commit, lint, review, snapshot,
build/runtime-boundary, report, or push instructions in the contract. The selected
workflows own those procedures and report their evidence through `PATCH_HANDOFF`.

## Implement and deliver

Apply `$scst-develop-in-worktree` yourself with the complete current `TASK_CONTRACT`
unchanged. Do not create another contract, implementation plan, or task interpretation.
Choose the implementation, minimum necessary abstraction,
and semantic commit breakdown from repository sources. Implement only the current
approved increment and reuse the same result branch for later accepted increments and
corrections in the series.

Before editing, stop and return to task discussion if the agreed increment is
technically artificial, would create a knowingly invalid intermediate result, forces
premature architecture, or contains a material ambiguity. Preserve the existing
result-branch, lint, independent-review, correction, and handoff behavior owned by the
selected workflows.

## Explicit delegation

Start `scst_worker` only when the user explicitly requests implementation delegation.
Pass it the repository path, selected local base, and complete current `TASK_CONTRACT`
unchanged with `fork_turns="none"`. Do not select delegation automatically.

For an explicitly delegated result, apply `$scst-explain-worker-patch` before requesting
corrections and send only user-accepted findings to that worker.

Apply `$scst-assess-harness-incident` only when the user or patch analysis identifies a
candidate harness failure.
