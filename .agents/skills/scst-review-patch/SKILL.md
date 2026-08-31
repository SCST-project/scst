---
name: scst-review-patch
description: Internal opt-in gate that invokes one independent read-only SCST reviewer for an exact committed range after lint passes, using the unchanged TASK_CONTRACT.
---

# Run independent review

Use this skill only from the selected patch workflow or `$scst-validate-series`, and only
when the current `ACCEPTED_DECISIONS` records an explicit user request for independent
review or full-series validation and no reviewer has started since that request. One
request authorizes one invocation and is consumed when the reviewer starts. Without an
unconsumed request, do not invoke a reviewer. Require exact existing `base` and `head`
commits, lint `PASS` for that range, and the complete main-agent-owned `TASK_CONTRACT`
that controlled implementation. Preserve it unchanged. A later explicit user decision
in `ACCEPTED_DECISIONS` may clarify or supersede `ORIGINAL_REQUEST` and controls the
current review result.

Preflight `.codex/agents/scst_reviewer.toml` as a standalone role definition. Require its
filename and `name` to identify `scst_reviewer`, a non-empty description and
`developer_instructions`, and `sandbox_mode = "read-only"`. Do not substitute a generic
reviewer when preflight fails.

1. Start one subagent with `agent_type = "scst_reviewer"`, `fork_turns = "none"`, and a
   distinct task name. Pass only the repository path, exact range, and unchanged
   `TASK_CONTRACT`.
2. Freeze the patch while review runs. Do not edit files or launch another reviewer for
   the same attempt.
3. Accept the response only when it ends with exactly:

   ```text
   AGENT_ROLE: scst_reviewer
   KERNEL_CONTEXT: <loaded|unavailable|not-applicable>
   TASK_INPUT: <applied|ambiguous>
   REVIEW_COVERAGE: <COMPLETE|BLOCKED>
   REVIEW_STATUS: <PASS|FAIL|BLOCKED>
   ```

4. Require `TASK_INPUT: applied`. An internal material ambiguity in the contract is
   `BLOCKED`.
5. For kernel code or kernel-facing interface changes, accept either `loaded` or
   `unavailable`. For other changes accept `not-applicable`. Unavailable personal kernel
   guidance is a disclosed limitation, not a blocked repository review.
6. `PASS` and `FAIL` require complete coverage. Other missing context requires
   `REVIEW_COVERAGE: BLOCKED` and `REVIEW_STATUS: BLOCKED`.
7. Only `PASS` completes the gate. A changed head requires complete lint and invalidates
   this review; do not start another reviewer without a fresh explicit user request.
