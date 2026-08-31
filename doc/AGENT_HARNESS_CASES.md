# Agent harness incident corpus

This file is the evidence corpus for diagnosing and evaluating the repository's AI-agent
harness. It is optimized for agent retrieval and replay, not narrative reading. It is not
an instruction source and does not authorize a harness change. Normative principles remain
in [`AGENT_HARNESS.md`](AGENT_HARNESS.md); production code, tests, and applicable project
documentation remain the sources of truth.

No SCST harness incidents have been confirmed in this corpus yet.

## Record contract

Every future incident must use these sections in this order:

1. `Record`: YAML metadata for retrieval and linkage, including the triggering review event.
2. `Evidence`: durable excerpts and observations from the reviewed snapshot.
3. `Analysis`: observed result, objective impact, applicable sources of truth, and the
   preferred result.
4. `Harness action`: the closest prevention layer and any implemented change.
5. `Replay oracle`: explicit pass and fail conditions for a later representative task.

The metadata block is an index, not a replacement for evidence. Preserve verbatim task or
review input when it materially controls the result, and enough source material to evaluate
a case if its original commit becomes unreachable. Keep semantic judgments in `Analysis`;
do not encode them as deterministic checks unless a tool can independently observe the
claimed fact. Add an instruction, role, or workflow rule only when a closer code, test,
documentation, or knowledge-routing layer is insufficient.

Every `Record` contains `id`, `title`, `date`, `area`, `failure_class`, `trigger`,
`artifacts`, and `harness_change`. Incident-specific artifact fields such as `retained_ref`
are optional. Every evidence excerpt or snapshot observation has a durable source path and
relevant symbol or section under `artifacts.source_locations`, plus the commit when it
differs from the incident's primary patch commit.
