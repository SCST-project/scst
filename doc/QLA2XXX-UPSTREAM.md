# Tracking upstream qla2xxx

`scripts/kernel/qla2xxx.py` inspects a local Linux Git repository, compares
committed driver snapshots, and prepares mail patches for `qla2x00t-32gbit`.
It requires Python 3.8 or later and Git 2.36 or later (`--remerge-diff`).
It uses only the Python standard library and Git. Run it with `python3`.

The tool does not fetch, change branches, apply patches, create commits, or
access hardware. `history`, `diff` and `audit` inspect Git objects; `export` writes a
new output directory. Uncommitted and generated files are not comparison
inputs. Both repositories must have complete histories (no shallow or partial
clones) and the required objects available locally. Update the Linux mirror
separately.

## Choose snapshots and inspect history

From the SCST repository root:

```sh
python3 scripts/kernel/qla2xxx.py history \
    --linux /path/to/linux --to v7.3
```

`--to` is required. Use a release tag or a commit, rather than a moving
branch, for a reproducible update. The tool resolves the Linux target and
`--scst-ref` (default `HEAD`) to full commit IDs before inspection. Use
`--scst /path/to/scst` to select another repository; the default is the
repository containing the script, independent of the caller's directory.

Without `--since`, the tool suggests the latest resolvable upstream marker
in the selected SCST driver's history as the exclusive starting point. A
later local change with the same subject prefix does not move that point.
An unresolved, ambiguous, or reverted latest import requires an explicit
`--since`. The base must be an ancestor of the Linux target.

**A marker proves recorded provenance, not completeness or equivalence.**
For an audited update, explicitly select the last fully reviewed upstream
release or commit. This also finds missing changes older than a selectively
imported recent fix:

```sh
python3 scripts/kernel/qla2xxx.py history \
    --linux /path/to/linux --since <reviewed-upstream-sha> --to v7.3 --json
```

History uses full traversal with merge simplification and reverse
topological ordering. It follows both `drivers/scsi/qla2xxx/` and
`include/trace/events/qla.h`; unrelated merge scaffolding is omitted.
Remaining merges are reported separately. Two-parent merges have their
`--remerge-diff` inspected; an empty result is reported, not treated as
proof of semantic equivalence. Octopus merges require manual inspection.

The report records full upstream and SCST IDs, authors, paths, changes
outside the mapped paths, and these statuses:

| Status | Meaning |
| --- | --- |
| `pending` | No corresponding provenance marker or explicit decision. This does not prove that equivalent code is absent. |
| `recorded` | At least one SCST commit contains `[ commit <sha> upstream ]`. Abbreviated historical markers are resolved in Linux. |
| `review` | A recorded import has a later standard Git revert. Inspect it, including any subsequent revert of that revert. |
| `skip` | An explicit reviewed decision says the change is inapplicable, with a reason. |
| `resolved` | An explicit decision identifies a reachable SCST commit implementing the result, with a reason. |

Merge and dependency review flags are independent of these statuses.
Custom reverts without the standard `This reverts commit ...` message and
later edits that undo an import are not automatically recognizable. Use
tree comparisons and code review to verify the remaining differences.

## Compare trees

```sh
python3 scripts/kernel/qla2xxx.py diff --linux /path/to/linux --to v7.3
python3 scripts/kernel/qla2xxx.py diff --linux /path/to/linux --to v7.3 \
    --path qla_os.c --patch
```

The default report classifies files as `identical`, `different`,
`linux-only`, or `scst-only`, comparing blob IDs and modes. `--json` provides
the same inventory with full snapshot IDs. Repeat `--path` to select files
relative to `qla2x00t-32gbit/`. `--patch` shows a textual review diff in the
Linux-to-SCST direction; it is not an import patch. Binary files are reported
as binary differences. Invalid UTF-8 in review output is replaced for display.

| Linux path | SCST path |
| --- | --- |
| `drivers/scsi/qla2xxx/*` | `qla2x00t-32gbit/*` |
| `drivers/scsi/qla2xxx/Makefile` | `qla2x00t-32gbit/Makefile_in-tree` |
| `include/trace/events/qla.h` | `qla2x00t-32gbit/include/trace/events/qla.h` |

The out-of-tree `Makefile`, SCST adapter, compatibility changes, and other
SCST-only files remain visible. A nonempty diff is expected; it is not by
itself evidence of a missing upstream fix. The legacy `qla2x00t` tree is
outside this tool's scope.

## Audit the remaining differences

```sh
python3 scripts/kernel/qla2xxx.py audit --linux /path/to/linux --to v7.3 \
    --kernel-version 7.3 --blame --json > /path/outside/scst/audit.json
python3 scripts/kernel/qla2xxx.py audit --linux /path/to/linux --to v7.3 \
    --kernel-version 7.3 --path qla_os.c --patch
```

`audit` keeps the same file inventory and pinned snapshots as `diff`. For
each changed text file, JSON includes the full Linux-to-SCST diff and added
and removed line counts. C files also get a token comparison, retaining
literal values and operators while ignoring comments and ordinary layout.
Preprocessor directives retain internal whitespace because macro definition
and stringification rules can make it significant. Non-C, binary, encoding
and mode differences remain explicit review items.

Without a profile, this is only a lexical comparison. `--kernel-version`
adds an explicit `LINUX_VERSION_CODE` assumption and understands constant
`KERNEL_VERSION(a,b,c)` calls. `--define NAME=integer` and `--undef NAME`
are repeatable assumptions about effective macro values at their uses.
They do not load a kernel configuration or follow includes. Do not assume
that a missing vendor/configuration symbol is undefined. Supply these facts
only when verified for the intended build; all assumptions appear in JSON.

The projection evaluates a limited integer/boolean subset (`defined`,
comparisons, `!`, `&&`, `||`, `+`, `-` and parentheses). Unsupported syntax
and unknown macros stay unknown. Local definitions invalidate matching
external assumptions; local macros are not expanded. Decidable nested
conditions can be simplified inside an unknown outer branch. JSON records
conditional decisions with original line numbers, including unknown groups
and invalidated assumptions. The full raw diff remains available even for
discarded branches. This is deliberately more conservative than compilation.

| Assessment | Meaning |
| --- | --- |
| `identical` | Same committed blob and mode. |
| `lexical-only` | Differences vanish in the token view. |
| `equal-under-profile` | Remaining tokens match after the explicit projection. |
| `residual-review` | Token differences remain in shared C sources. |
| `*-review` | File presence, mode, encoding, binary or non-C difference needs review. |

Residual hunks retain original line spans and approximate function hints.
`--patch` displays these spans; it is review output, not an applicable patch.
Hints distinguish SCST integration, compatibility candidates, assignments or
control flow that may change behavior, and otherwise unexplained changes.
**Every residual hunk still requires review.** A version guard can contain
behavior changes; an unconditional change can be a backport. `--blame` adds
the last SCST editors of changed lines, not necessarily the commits that
introduced the divergence; deletions need separate history inspection.

Neither token equality nor projection proves semantic C equivalence. Macro
expansion, stringification, includes, compiler options and line-sensitive
macros can matter. The counts describe textual/token changes, not a percentage
of behavior changed. `shared_c_totals` excludes files present on only one
side, so the entire SCST adapter does not inflate the shared-driver totals.
Inspect that adapter separately as part of target integration review.

## Export candidates

```sh
python3 scripts/kernel/qla2xxx.py export \
    --linux /path/to/linux --since <reviewed-upstream-sha> --to v7.3 \
    --output /path/to/new-qla-v7.3-bundle
```

The output parent must exist and the output directory must not exist.
Existing files, directories, and symlinks are never replaced. Preparation
failures do not publish a bundle. A successful bundle contains:

- Numbered mail patches with SCST paths, the `qla2x00t-32gbit:` subject
  prefix, original author/date/message trailers, and a full upstream marker.
  Git generates the diffs, including binary content, additions, deletions,
  and mode changes. Renames are represented as deletion plus addition.
- `series`: ordered filenames of ordinary candidates without mixed-path or
  revert warnings. This is an inventory, not approval to apply them blindly.
- `review/`: merge-resolution text and both the complete original patch and
  mapped candidate for mixed-path or reverted imports. These candidates are
  deliberately absent from `series`; inspect external dependencies before
  deciding whether and how to use them. Merge diffs are review material,
  not patches suitable for `git am`.
- `manifest.json`: pinned inputs, path mapping, status of every candidate,
  review flags, decisions, exported paths, and SHA-256 artifact checksums.

`recorded`, `skip`, and `resolved` entries remain in the manifest but are
not exported again. An octopus merge has a review entry with all parent
IDs, without an automatically generated resolution patch.

After review, individual exported patches use ordinary root-relative paths:

```sh
git am /path/to/new-qla-v7.3-bundle/0001-<upstream-id>.patch
```

No `-p4` or `--directory` is needed. A conflict requires adaptation and
`git am --continue`; clean application still requires review of SCST target
semantics and compatibility. The tool does not supply upstream blobs for
three-way application. Preserve the provenance marker when adapting a patch.

Keep new SCST behavior and compatibility backports in separate commits after
the upstream import. Only minimal context relocation belongs in the import;
intermediate commits may fail to compile. Validate the final adapted series.
The repository skill is
[`scst-qla2xxx-update`](../.agents/skills/scst-qla2xxx-update/SKILL.md).

## Record reviewed exceptions and continue

Optional `--decisions /path/to/decisions.json` is accepted by `history` and
`export`. This file is maintained explicitly; the tool never advances an
import boundary or marks a review completed on its own.

```json
{
  "version": 1,
  "decisions": {
    "<full-upstream-commit-sha>": {
      "status": "skip",
      "reason": "Explain why this change is inapplicable to SCST."
    },
    "<another-full-upstream-commit-sha>": {
      "status": "resolved",
      "reason": "Explain the separate adaptation or merge resolution.",
      "scst_commit": "<full-scst-commit-sha>"
    }
  }
}
```

Replace the placeholders with actual full commit IDs. A resolution commit
must be reachable from `--scst-ref`; a detected revert invalidates that
decision. Unknown fields and empty reasons are errors. Decisions for later
Linux releases can coexist in the same file, but only those reachable from
the selected target affect its report. Reasons and resolution evidence must
be reconsidered when SCST's implementation changes.

On resumption, rerun with the **same explicit `--since` and `--to`**, the
updated SCST ref, and a new output directory. Imported commits will be
recognized through their markers; reviewed exceptions remain in the
decisions file. Keep the manifest and decisions with the update's review
records **outside the source tree**, together with audits and validation logs.
Do not commit per-release reports or decisions to the repository. After a
rebase, revalidate any stored SCST commit IDs. Advance the reviewed boundary only after accounting for all
entries and inspecting the final tree differences.

## Validation and limits

The tool reports and exports; it does not establish that an update is
correct, buildable, or complete before its chosen base. Follow
[CONTRIBUTING.md](../CONTRIBUTING.md) for commit checks and builds, and the
[QLogic guidance](../qla2x00t-32gbit/AGENTS.md) for target integration and
hardware boundaries. Export success is not build or runtime evidence.

Run the tool's integration tests without Linux sources or an HBA:

```sh
python3 -m unittest discover -s scripts/kernel -p 'test_qla2xxx.py' -v
```

The tests create temporary Git repositories, including conflicts, reverts,
mixed-path changes, and binary files. They apply generated patches only to
those fixtures and verify metadata and resulting files.
