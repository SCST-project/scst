---
name: review-patch
description: >-
  Orchestrate one independent scst_reviewer pass over an exact committed SCST
  patch range after lint passes. Use for the review gate in patch development
  or an explicitly requested committed-range review. Do not use for
  uncommitted diffs, implementation, lint, builds, or tests, and never invoke
  it from scst_reviewer.
---

# Review an SCST patch

Execute this orchestration gate only in the main agent. Receive exact `base`,
`head`, repository path, and this unchanged contract:

```text
TASK_CONTRACT:
GOAL:
ACCEPTANCE:
NON_GOALS:
ALLOWED_EXCEPTIONS:
FORBIDDEN_CHANGES:
```

## Preflight the review

1. Resolve `base` and `head` as commits and require `base` to be an ancestor
   of `head`.
2. Require a non-empty range and review committed `base..head`, never an
   uncommitted working-tree diff.
3. Parse `.codex/agents/scst_reviewer.toml` with a read-only TOML parser.
4. Require valid TOML, `name = "scst_reviewer"`, a non-empty description,
   non-empty `developer_instructions`, and `sandbox_mode = "read-only"`.
5. Require the `scst_reviewer` custom agent type to be available. If it is
   unavailable, return `BLOCKED`; never substitute `default`, `worker`,
   `explorer`, or another generic agent.

## Run exactly one reviewer

1. Spawn exactly one `scst_reviewer` with `fork_turns="none"` and a unique
   task name.
2. Pass only the repository path, exact `base..head`, and unchanged
   `TASK_CONTRACT` needed to perform the review.
3. Do not pass expected findings, suspicions, or the main agent's verdict.
4. Do not modify the patch while review is running.
5. Do not run lint, build, tests, or another quality gate inside the
   reviewer.
6. Wait for the terminal reviewer result.

## Validate the result

Require exactly one final marker block with these five lines and allowed
values:

```text
AGENT_ROLE: scst_reviewer
KERNEL_CONTEXT: <loaded|unavailable|not-applicable>
TASK_CONTRACT: <applied|default|ambiguous>
REVIEW_COVERAGE: <COMPLETE|BLOCKED>
REVIEW_STATUS: <PASS|FAIL|BLOCKED>
```

Treat missing, duplicate, malformed, or contradictory markers as `BLOCKED`.
Require `REVIEW_COVERAGE: COMPLETE` for `PASS` or `FAIL`. Require
`REVIEW_STATUS: BLOCKED` when the contract is ambiguous or coverage is
blocked. The gate passes only with `REVIEW_STATUS: PASS`.

Any change to `head` invalidates the result. Run `$lint-patch` for the new
head before starting another independent reviewer attempt.
