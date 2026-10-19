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
| `policy/` | Reviewed shared analyzer input policy; exclusions carry their reasons. |
| `tests/` | Isolated regression fixtures for the shared analyzer helpers (`make lint-test`). |

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

## Shared analyzer source scope

`lint_scope.py` reads [policy/common.json](policy/common.json) for full, diff
and explicit-file selection. The loader rejects invalid or missing policy;
there are no environment-based extra exclusions. Existing checkpatch wrappers
and the kernel regression runner still use their own selection and filtering.

| Input | Shared policy |
| --- | --- |
| `scst/`, `iscsi-scst/`, `srpt/`, `fcst/`, `scst_local/`, `usr/` | Include `.c` and `.h` files, subject to the exclusions below. |
| `qla2x00t-32gbit/qla2x00-target/` | Include the newer driver's SCST target portion. |
| KUnit sources under the included directories | Include regardless of the current `KUNIT_TEST` build setting. |
| `qla2x00t/` | Exclude the entire legacy QLogic tree. |
| The rest of `qla2x00t-32gbit/` | Exclude the upstream driver, including top-level `qla_target.c` and `qla_target.h`. |
| `iscsi-scst/conftest/`, `srpt/conftest/` | Exclude compiler capability probes. |
| Names ending in `.mod.c` | Exclude generated module metadata, even when explicitly requested. |
| Other directories and extensions | Outside the shared source scope. |

These are input exclusions. The helper does not filter diagnostic text or
discard findings from headers included by selected files. Selecting KUnit
sources does not enable them in a build; that needs the build configuration.

Full selection reads existing working-tree files listed in the Git index,
including staged new files. Missing and untracked files are omitted.

Diff selection compares a base with the working tree, including staged and
unstaged changes. It selects whole current files, checks rename destinations,
and skips deleted and untracked files. The base must resolve to one commit;
options, ranges, tree objects and unknown revisions are rejected.

Explicit files may be untracked, but must exist and be within the same scope.
They cannot be combined with a diff base. Both a path and its resolved symlink
destination must be in scope. Results are sorted and deduplicated.
An empty selection means there are no eligible inputs, not a completed scan.

## Shared process and log helpers

`lint_common.py` handles process-group cleanup, exit statuses and Make's
parallel jobserver. Drivers must check command results or use `check=True`.
The entry-point helper supports command tracing with `V=1` or `--verbose`.
Progress is separate from captured analyzer output.

Drivers save complete stdout/stderr under `.cache/lint/`. The helpers preserve
raw bytes without filtering. Reusing a log name replaces the previous report
by default; callers can preserve it with `truncate=False`. There is no automatic
log archive.

## Shared analyzer build lock

Drivers that modify build state must hold `lint_kbuild.build_lock(root)` while
resetting build logs and preparing or running the build. It serializes callers
within one worktree using `.cache/lint/kbuild.lock`; ordinary builds that do
not acquire it remain unprotected. Keep the lock file in place: closing its
descriptor releases the lock, including on exceptions.

## Dependencies and tooling tests

Shared analyzer tooling requires Linux, Git and Python 3.10+, using only the
Python standard library. Run its fixtures from the repository root:

```sh
make lint-test                  # PYTHON defaults to python3
```

The fixtures use temporary repositories, files and child processes. They do
not build SCST, load modules or access live devices.
