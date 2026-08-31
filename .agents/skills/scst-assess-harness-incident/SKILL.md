---
name: scst-assess-harness-incident
description: Internal read-only assessment of one concrete SCST agent-harness failure candidate, returning journal-ready evidence to the main agent.
---

# Assess a harness incident

Start one `scst_harness_evaluator` with `fork_turns="none"`. Give it clearly labeled
evidence for the initial series increment and the increment that exposed the candidate.
Each set contains the unchanged applicable `TASK_CONTRACT`, exact `base..head`, and
`PATCH_HANDOFF` when it exists. Also include accepted-result context for the candidate
increment when applicable.

When a requested review paused an increment before `PATCH_HANDOFF`, supply the preserved
`TASK_RESULT_CONTEXT`, lint status for the exact range, raw reviewer output and findings,
and an explicit statement that no handoff exists because review paused the workflow.

When both increments are the same, pass one evidence set instead of duplicating it.
Include raw user and main-agent observations and relevant delegated-worker answers. Do
not pass a journal base, proposed classification, expected root cause, or preferred fix.

Accept either a reasoned rejection or a confirmed assessment containing complete
journal-ready evidence and a replay oracle. The evaluator creates no branch, file, or
commit. The main agent preserves the returned assessment and alone may record a confirmed
entry in `doc/AGENT_HARNESS_CASES.md` through a separate tracked workflow. A harness fix
is another user-authorized task.
