---
name: scst-explain-worker-patch
description: Internal read-only walkthrough invoked by scst-develop-task after an explicitly delegated SCST worker returns an exact committed patch.
---

# Explain a worker patch

Remain read-only. Require the same complete main-agent-owned `TASK_CONTRACT` that
controlled the worker, unchanged, and the exact `base..head`. Inspect the full diff,
surrounding code, callers, contracts, tests, and relevant history. For kernel code or a
kernel-facing interface, use an available `$kernel` skill as supplemental context. If
none is available, continue from repository-local sources and disclose
`KERNEL_CONTEXT: unavailable`.

Explain the patch in the user's language and in this order:

1. Describe the end-to-end behavior before and after the patch.
2. Account for every changed function. Explain its purpose, prior behavior, change,
   reason, connection to the wider flow, risks, and validation.
3. Cover non-function changes such as data structures, tests, configuration, and
   documentation with the same level of completeness.
4. Separate observed facts, reasonable inferences, and concerns. Define necessary
   technical terms instead of presenting a list of internal names.

Ask the worker factual questions when intent cannot be established from the patch. Do
not request edits yet. Discuss all concerns with the user, then return only accepted
findings to the same explicitly delegated worker through the main-agent workflow.

This walkthrough supports the user's decision and manual diff reading; it does not
replace either the user or an explicitly requested independent `scst_reviewer` review.
