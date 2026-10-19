# Repository scripts

The tools are grouped by purpose. Existing Make targets keep their names;
direct callers of a relocated script must use its new directory below.

| Directory | Tools and entry points |
| --- | --- |
| `source/` | `list-source-files`, `list-non-source-files`, `clean-source-tree`, `list-double-blank-lines`, and `run-shellcheck` (`make shellcheck`). |
| `kernel/` | `generate-kernel-patch`, `generate-patched-kernel`, `run-regression-tests`, `kernel-matrix`, `qla2xxx.py`, `sign-modules`, patch filters, and shared kernel/RPM helpers. |
| `release/` | `generate-release-archive` (`make release-archive`), `build-rpm-artifacts` (`make rpm-artifacts`), `prepare-package-release`, and `update-version`. |
| `runtime/` | `monitor-interrupt-rate`, `monitor-memory-usage`, `blockdev-perftest`, and `test-persistent-reservation`. |
| `ci/` | CI image and guest preparation, VM execution, and associated configuration. |
| `kunit/` | KUnit inventory, labels, runner, and tooling tests; see [the KUnit guide](../doc/KUNIT.md). |

The existing `checkpatch`, `checkpatch_commits`, `checkpatch_diff`, and
`checkpatch_scan` entry points remain directly under `scripts/`. The wrapper's
diagnostic ignore list is in `checkpatch`; whole-tree scan exclusions are in
`checkpatch_scan`. The kernel regression runner retains its separate analyzer
commands and filtering. Moving the tools does not change these policies.

Use Make targets from the repository root unless a component workflow says
otherwise. Direct scripts retain their working-directory conventions:
`generate-kernel-patch` and `update-version` use the SCST root, while archive
generation and source inventory use the requested or current source directory.
Module Makefiles invoke `sign-modules` from the directory containing modules.
Consult each script's argument handling before invoking it.

`kernel/run-regression-tests` prepares kernel trees and runs compilation,
checkpatch, sparse, and smatch according to its options. The maintained kernel
matrix is `ABT_KERNELS` in `nightly/conf/nightly.conf`; the CI subset is selected
through `kernel/kernel-matrix` and `.github/kernel-matrix.conf`.

`kernel/qla2xxx.py` tracks upstream QLogic commits, compares committed Linux
and SCST driver trees, audits residual differences with an optional kernel
profile, and exports mail patches with SCST paths. It uses
local repositories and never applies patches itself. See
[Tracking upstream qla2xxx](../doc/QLA2XXX-UPSTREAM.md) for commands, provenance,
merge review, and resuming an update.

`kernel/extract-qla2xxx-orig` and `kernel/generate-qla2xxx-in-tree-patches`
prepare upstream sources and full driver diffs for kernel embedding. Invoke
them from `qla2x00t-32gbit/` with a kernel version argument; source caches and
generated patches remain there. `generate-kernel-patch` calls the latter.
These helpers can download sources; they are separate from the read-only
Git tracker. The legacy `qla2x00t/` helpers retain their existing locations.

Some helpers modify source trees, generated artifacts, or live devices:
`source/clean-source-tree` removes untracked and ignored files; kernel helpers
can download, patch, build, or sign; release helpers can update versions or
write packages. Runtime benchmarks and reservation exercises require a
deliberately selected disposable device. The runtime monitors only observe
host counters. See the root [repository guidance](../AGENTS.md) for operational
boundaries.

Follow [the local checks](../CONTRIBUTING.md#local-checks) when editing tools.
`make shellcheck` selects Bash scripts under all of `scripts/` using paths
recorded in `HEAD`. Check newly added or renamed paths explicitly before
committing; sourced libraries, POSIX shell scripts, and callers outside
`scripts/` also need the checks described there.
