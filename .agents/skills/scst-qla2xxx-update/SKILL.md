---
name: scst-qla2xxx-update
description: Update SCST's qla2x00t-32gbit driver from a pinned upstream Linux release using the repository qla2xxx tracker. Use for upstream import planning, patch series, merge-resolution review, and separate SCST adaptations; nightly kernel-list maintenance is separate.
---

# Update qla2xxx from Linux

Use the repository's `scripts/kernel/qla2xxx.py`; read
[its guide](../../../doc/QLA2XXX-UPSTREAM.md) for current commands and
report semantics. Follow applicable `AGENTS.md` and `CONTRIBUTING.md`.
A request to inspect or plan remains read-only. A request to update authorizes
local import, adaptation, commits, and compile checks; it does not authorize
publication or live HBA/module operations.

## Establish the update

- Inspect status, worktrees, branch divergence, and the user's requested base.
  Develop on `qla2x00t-32gbit` unless the user selects another branch. Preserve
  existing work when switching; rebase only when requested. Delete only
  temporary branches known to belong to this work and authorized for removal.
- Resolve the Linux release tag to its full commit and verify it against the
  official Torvalds repository. Use the local Linux Git mirror without
  changing its checkout or deleting its untracked/generated files.
- Pin SCST's initial HEAD and an explicit exclusive upstream base. The latest
  provenance marker is a discovery hint, not proof of complete prior imports.
  Check it against the previous update record and inspect baseline tree
  differences. Report unresolved historical markers instead of guessing.
- Keep a durable output directory outside the source tree for exports, review
  decisions, before/after comparisons, and validation logs. Reuse the same
  pinned base and target when resuming; choose a new export directory. Do not
  commit per-release reports or decisions. Revalidate stored SCST SHAs after
  rebasing; provenance markers alone do not replace the external review record.

Run from the SCST root with the selected arguments:

```sh
python3 scripts/kernel/qla2xxx.py history --linux <linux-repo> \
  --since <base-sha> --to <target-sha> --json
python3 scripts/kernel/qla2xxx.py diff --linux <linux-repo> \
  --to <target-sha> --json
python3 scripts/kernel/qla2xxx.py audit --linux <linux-repo> \
  --to <target-sha> --kernel-version <version> --blame --json
python3 scripts/kernel/qla2xxx.py export --linux <linux-repo> \
  --since <base-sha> --to <target-sha> --output <new-directory>
```

## Import and adapt as separate commits

- Read the manifest in dependency order, including entries omitted from
  `series`. Review outside-path dependencies and remerge output; do not skip
  merges just because `git format-patch` does not export them.
- Import each ordinary upstream change as its own commit. Patches already
  have SCST paths and use ordinary `git am`, without `-p4`. Preserve upstream
  author/date, attribution, the `qla2x00t-32gbit:` prefix, and full upstream
  marker. For conflicts, inspect the complete upstream change and current
  SCST implementation; resolve and use `git am --continue`.
- Keep upstream intent and SCST adaptation separate. Import the upstream
  change first, including a manual transplant when necessary. Put new or
  changed SCST-specific code, kernel backports, feature guards, target-adapter
  changes in a subsequent separate commit.
  Temporary compilation failures between those commits are acceptable.
  Minimal context relocation needed to represent the upstream change belongs
  in the import; new compatibility or SCST behavior does not.
- Preserve existing SCST behavior while resolving overlapping contexts; do
  not replace a file wholesale with upstream. When one conflict contains
  both upstream and SCST work, stage the upstream portion first and then
  commit the remaining adaptation. Explain the separation in commit bodies.
- Review a merge's actual resolution at its position in the series. If an
  earlier transplant already reproduces it, record a `resolved` decision
  pointing to that SCST commit and explain why. Otherwise make a separate
  resolution commit, preserving the upstream merge reference.
- Do not label a clean application as semantic validation. Audit changes to
  shared structures, IOCB sizes/strides, DMA buffers, queue wraparound,
  interrupt handling, completion ownership, and teardown against both
  initiator and SCST target consumers. Inspect `qla2x00-target/`, not just
  files directly touched by upstream. Verify actual readers/checks before
  changing interface magic: the newer tree's QLA2XXX_*_MAGIC definitions are
  currently unused, unlike the legacy tree's registration handshake. A stale
  header comment alone does not justify a bump.
- Put generic kernel compatibility in the existing compatibility mechanism
  when appropriate. Check API availability and the maintained kernel matrix;
  do not infer it from a remembered kernel version. Evaluate legacy-tree
  impact without mechanically porting the newer hardware series there.
- For an already equivalent or inapplicable change, retain an explicit
  decision with code/history evidence. Do not manufacture an empty import
  or claim a change is present based solely on matching subjects.

## Complete the update

- Rerun history with the original upstream base, target, current SCST HEAD,
  and decisions. Account for every ordinary commit and relevant merge.
  Compare the resulting tree to the target and the pre-import local delta;
  explain remaining differences rather than requiring byte equality.
- Run `audit` on committed snapshots before and after the import. Inspect raw
  diffs and residual hunks, including SCST-only adapter files and Linux-only
  files. Kernel projection only removes decidable branches; do not invent
  vendor/config defines to suppress the remaining diff. Unknown conditions
  and classification hints require review. Use blame to locate last editors,
  then inspect history and callers to explain behavior changes. Report
  substantial defaults, capability and control-flow differences separately
  from mechanical backports; token equality is not semantic proof.
- Run the tool tests if its behavior changed, plus the repository's required
  diff, `make checkpatch` and commit-message checks. Inspect imported diagnostics
  individually; do not rewrite upstream patches merely to hide existing
  warnings or extend ignore lists.
- Compile core and both newer QLogic modules against the target kernel, using
  an inspected prepared kernel tree and the current Make targets. Use
  separate build state for additional kernels. Check older supported API
  boundaries affected by this series when suitable kernel trees are available.
  Record missing prerequisites and the exact compiled head/configuration.
- Keep any fixes discovered by builds in separate SCST/backport commits.
  Recheck the affected final tree after corrections. Kernel compilation,
  isolated tool tests, and live FC runtime evidence remain distinct.
- Report the branch, initial/final SHAs, source release/SHA, imports,
  adaptations, merge decisions, remaining differences, and actual checks.
  Preserve the update record and decisions so the next release has an audited
  starting point. Do not advance that point while candidates remain unresolved.
