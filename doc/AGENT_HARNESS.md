# Agent harness development principles

This document defines how maintainers evolve the repository's AI-agent harness. It is
guidance for both people and agents working on `AGENTS.md`, skills, agent roles, and
their supporting tools. The operational workflow remains in the applicable
`AGENTS.md`, `.agents/skills/`, and `.codex/` files.

## Goal

The harness should help a capable engineer unfamiliar with SCST make a small, correct,
reviewable change with evidence. It should expose project knowledge, safe tools, and
clear boundaries without prescribing implementation choices that depend on the task.

Prefer the smallest harness that works on real repository tasks. A larger prompt,
state machine, schema, or tool is not an improvement unless it fixes an observed problem
without causing a larger loss of flexibility, context, or maintainability.

## Sources of truth

Use these sources in this order:

1. The user's original request and later explicit decisions. An agent-written summary
   may clarify them but never replaces or weakens them.
2. Current code, tests, build logic, and configuration. They define actual behavior.
3. Architecture, style, and component documentation maintained with the code.
4. Applicable `AGENTS.md` files, which route agents to repository-specific knowledge,
   invariants, hazards, and validation entry points.
5. Applicable skills and agent-role instructions, which define reusable workflow and
   specialized-role authority for a class of task.

When these sources conflict, stop on a material ambiguity instead of silently choosing
the interpretation that makes the current patch easiest to complete.

## Put information in the right layer

### `AGENTS.md`

Keep stable repository-specific context:

- component ownership and architectural boundaries;
- authoritative files and documentation;
- cross-component contracts that are easy to miss;
- destructive operations and local safety constraints; and
- the repository's supported validation entry points.

Do not copy generic software-engineering advice, long command transcripts, current
symbol inventories, or implementation details that are cheaper to discover from code.
Add a nested `AGENTS.md` only when its subtree has material local context not already
covered by an ancestor.

### Skills

Keep a skill concise and focused on its trigger, authority, required sequence, stopping
conditions, and conditional resources. Assume the model already knows how to investigate
and write code. Preserve freedom where several correct designs are possible.

Move a fragile, repeatable operation into a script. Move a long conditional protocol or
domain reference into a directly linked `references/` file and load it only when that
path is active. Do not duplicate the same rule between skills or between a skill and a
reference.

Do not add status vocabularies, attempt accounting, routing formulas, or schemas merely
to make prose look formal. Add structure only when another tool consumes it or a real
failure demonstrates that free text is unreliable.

### Scripts and CI

Use code for facts it can observe deterministically, such as:

- exact commits, ancestry, refs, changed paths, and tracked cleanliness;
- syntax, formatting, configuration, and schema validation;
- builds, deployments, tests, and artifact provenance; and
- mechanically checkable repository invariants.

Do not encode semantic judgment as a simulator and then treat its unit tests as evidence
that an LLM will make the same decision. A script can validate the shape of an agent's
claim, but it cannot prove that the claim or the underlying patch is correct unless it
observes independent evidence.

Use an MCP tool when the operation needs an external service, typed remote capability,
or long-running pipeline. A repository-local script is preferable for checks that people
and CI should also run directly. Moving the same implementation behind MCP does not by
itself make it more reliable.

### Reviewer roles

Give the reviewer the same complete main-agent-owned `TASK_CONTRACT` that controlled
implementation, unchanged, together with the exact committed range. Do not replace or
supplement it with another task interpretation. `ORIGINAL_REQUEST` is the authoritative
initial input; a later explicit user decision recorded in `ACCEPTED_DECISIONS` may
clarify or supersede it and controls the current result.

Keep the reviewer read-only and independent from the implementation discussion. Ask it
for concrete defects and regressions, not optional redesign or generic hardening.

## Task size and scope

One run should own one coherent outcome that can be understood and reviewed as a whole.
Do not implement an open-ended backlog or "as much as possible" list as one patch task.
When a request contains multiple independent outcomes or requires several unrelated
architectural decisions, propose bounded series and work on only the current agreed
series.

The main agent owns one `TASK_CONTRACT` containing only `ORIGINAL_REQUEST`,
`DISCUSSION_RECORD`, and `ACCEPTED_DECISIONS`.
`ORIGINAL_REQUEST` preserves the user's task verbatim. `DISCUSSION_RECORD` concisely
preserves material context, relevant alternatives and their rationale, and constraints
or risks; it is not a transcript or a bare final summary. `ACCEPTED_DECISIONS`
normatively records the required behavior, material prohibitions and non-goals, and
current increment. `ORIGINAL_REQUEST` is the authoritative initial input; a later
explicit user decision recorded in `ACCEPTED_DECISIONS` may clarify or supersede it and
controls the current result. Record validation only for an explicit task-specific user
decision, authorization, prohibition, or waiver. Standard lint, review, snapshot,
build/runtime-boundary, worktree, commit, report, and push procedures remain in the
main-agent role and selected workflows; their evidence remains outside the contract in
`PATCH_HANDOFF`, or in preserved exact review evidence while a non-passing requested
review has paused the workflow before handoff. The discussion record disambiguates but
cannot silently add requirements. Implementation and review use the same current
contract unchanged and create no secondary task summary or implementation plan. Explain
a non-obvious design in normal task communication; do not maintain a separate design
artifact when that is sufficient.

## Validation and trust

The default patch loop is:

```text
original request -> repository context -> minimal patch series -> semantic commits
                 -> deterministic lint -> author diff inspection
                 -> optional independent review when requested -> report
```

The default does not invoke a reviewer. One independent read-only review runs only when
the user explicitly requests it for the current task. That request may precede the
completed patch, authorizes the next reviewer invocation, and is consumed when the
reviewer starts. A requested review that returns `FAIL` or `BLOCKED` pauses before
handoff, preserves the original gate base and reviewed snapshot, and returns findings to
the user without automatic edits or another review. Later accepted corrections remain
in that same patch context so validation continues to cover the complete original range;
reviewing a changed head requires a fresh user request.

For an explicit final full-series check, `scst-validate-series` composes the existing
exact snapshot check, complete lint gate, author inspection, and independent review. It
remains read-only, requires the retained task contract and literal committed range, and
does not become part of the default development path.

Bind every gate to an exact committed range. Any semantic change invalidates earlier
lint and review evidence for that range.

Lint and any requested review reduce risk but do not replace compilation or runtime
tests. This workflow does not provide that validation, and every handoff and final report
must say so without implying that product behavior was exercised.

## How to improve the harness

Use real work before speculative machinery:

1. Observe a concrete failure, repeated correction, avoidable delay, or missing fact.
2. Preserve the raw request, patch, review, and validation evidence needed to explain it.
3. Decide whether the smallest fix belongs in project documentation, an instruction, a
   deterministic check, or a stronger tool.
4. Change one behavior at a time and keep rollback easy.
5. Exercise the change on later real tasks before making the workflow more elaborate.

## Current baseline

The intentionally small baseline keeps:

- repository and component knowledge in `AGENTS.md` and project documentation;
- opt-in repository skills with implicit invocation disabled;
- one selectable main-agent implementation path on one result branch in an isolated raw
  Git worktree;
- one user-selectable main-agent task workflow with one task contract shared unchanged
  by implementation and review;
- one explicitly selected read-only full-series validation bundle;
- project lint plus focused Python and agent-configuration checks;
- one opt-in independent read-only reviewer invoked only by explicit user request;
- exact Git identity plus result-branch and worktree cleanup checks; and
- an explicit validation limitation because the workflow does not compile or run the
  product.

User-scoped personal guidance may select the repository workflow by default for one
developer. Keep that preference outside the repository and route to the maintained skills
instead of copying their instructions.

The project does not activate the task workflow or implementation workers implicitly.
Additional orchestration-result schemas beyond `PATCH_HANDOFF`, semantic routing
formulas, and synthetic decision simulators are not part of the baseline. Add them only
through a small reviewable patch backed by a real observed need.
