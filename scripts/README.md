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
| `sparse_smatch/` | Native Kbuild analyzers (`make sparse`, `make smatch`) and CHECK records. |
| `coccinelle/` | Kernel semantic-patch report rules (`make coccicheck`). |
| `cppcheck/` | Native analysis using captured compiler commands (`make cppcheck`). |
| `style/` | Whole-file Checkpatch analysis (`make checkpatch`). |
| `scs_lint/` | SCST code style rules (`make scs_lint`); see [SCS](../doc/scs.md). |
| `tests/` | Isolated regression fixtures for the shared analyzer helpers (`make lint-test`). |

Use Make targets from the repository root unless a component workflow says
otherwise. Direct scripts retain their working-directory conventions:
`generate-kernel-patch` and `update-version` use the SCST root, while archive
generation and source inventory use the requested or current source directory.
Module Makefiles invoke `sign-modules` from the directory containing modules.
Consult each script's argument handling before invoking it.

`kernel/run-regression-tests` prepares kernel trees and runs compatibility
builds. Static analyzers have separate Make targets and CI jobs. The maintained
kernel matrix is `ABT_KERNELS` in `nightly/conf/nightly.conf`; the CI subset is
selected through `kernel/kernel-matrix` and `.github/kernel-matrix.conf`.

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

Kernel-based analysis targets the current kernel selected in
[`ci/kernel.env`](ci/kernel.env). Older kernels remain supported for SCST builds,
but are outside analyzer compatibility support. Compilation database export
requires the current per-module Kbuild layout.

`lint_scope.py` reads [policy/common.json](policy/common.json) for full and
explicit-file selection. The loader rejects invalid or missing policy;
there are no environment-based extra exclusions.

Inspect the shared policy and eligible tracked files without running analyzers:

```sh
make analyzer-policy
make analyzer-policy ANALYZER_FORMAT=json
python3 -B scripts/analyzer_policy.py files
python3 -B scripts/analyzer_policy.py validate
```

The Python commands also accept `--format=json` and a policy name: `common`,
`sparse`, `smatch`, `coccicheck`, `cppcheck`, `checkpatch` or `scs_lint`.
Use `make analyzer-policy ANALYZER=smatch` to see the
effective input scope, source exception declarations and model hashes. A file
inventory does not establish analysis or build coverage. Declaration counts
are not suppression hit counts; native Cppcheck does not report hit counts.

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
discard findings from headers included by selected files. Cppcheck separately
classifies legacy/upstream QLogic header findings outside scope; the nested
SCST target and all frontend failures remain blocking. Selecting KUnit
sources does not enable them in a build; that needs the build configuration.

Full selection reads existing working-tree files listed in the Git index,
including staged new files. Missing and untracked files are omitted.

Explicit files may be untracked, but must exist and be within the same scope.
Both a path and its resolved symlink destination must be in scope.
Results are sorted and deduplicated.
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

## Sparse and Smatch

```sh
make -j8 sparse KDIR=/path/to/kernel/build KUNIT_TEST=y
make -j8 smatch KDIR=/path/to/kernel/build KUNIT_TEST=y
python3 -B scripts/sparse_smatch/smp.py sparse scst/src/scst_lib.c
```

These targets build the configured kernel modules with `C=2`, without
installing or loading them. The scope above applies, excluding userspace;
the upstream QLogic base is built only as a dependency. `KUNIT_TEST=y`
includes KUnit suites and requires a kernel with KUnit support.

Both targets analyze the full configured build. An explicitly selected C file
absent from the build is an error.

Source findings and incomplete analysis fail the targets. The Python driver
returns 0 for clean runs or empty selections, 1 for findings and 2 for
incomplete analysis; GNU Make maps recipe failures to 2.

Logs and JSON summaries are in `.cache/lint/{sparse,smatch}.{log,json}`.
Logs retain ignored warnings; summaries count total, ignored and remaining
findings and link to per-file results. A new run replaces its log and summary
but retains earlier per-file results.

Diagnostic exceptions are listed in [sparse.json](policy/sparse.json) and
[smatch.json](policy/smatch.json):

- Both tools: `array of flexible structures` in the build kernel's
  `include/uapi/scsi/fc/fc_els.h`.
- Smatch: `mixing irqsave and irq` in `dev_user_unjam_cmd()` in
  `scst/src/dev_handlers/scst_user_main.c`, and `user_reply_test()` in
  `scst/src/dev_handlers/kunit/user/suites/scst_user_cleanup_test.c`.
  Both choose matching IRQ operations under the same condition, which
  Smatch does not track across the pair.

Exceptions match exact paths, messages and functions where applicable.
There are no free-form ignore patterns; inspect reasons with
`make analyzer-policy ANALYZER=smatch`.

Install Sparse and Smatch with matching `smatch_data`. Use `SMATCH_DATA_DIR`
if Smatch cannot find its installed data. The selected kernel must accept
the checker; recent kernels may require a newer frontend.

Build the CI tool environment with:

```sh
docker build -f scripts/ci/analyzers.Dockerfile -t scst-analyzers:local .
```

Tool revisions are in [ci/analyzers.env](ci/analyzers.env); kernel headers
and checksums are in `ci/kernel.env` and `ci/kernel.SHA256SUMS`. The image
includes the [Smatch frontend fix](sparse_smatch/patches/typeof-address-space.patch)
needed for current kernel RCU headers. Tool provenance is recorded under
`/usr/local/share/scst-ci/` inside the image.

## Coccinelle

```sh
make coccicheck KDIR=/path/to/kernel/build
```

Install `spatch` with Python support and kernel sources containing
`scripts/coccinelle/`. Rules declaring `report` mode run on the shared source
scope, including userspace and KUnit files; other rules are listed as skipped.
No build is needed. The wrapper extends installed parser hints with SCST
contracts and current source definitions, without pinned macro hashes.
CI installs Fedora's `coccinelle` package without a version pin. Native model
tests for variadic macro arguments are temporarily skipped pending an upstream
Coccinelle fix; their names and reasons remain visible in analyzer-test reports.
Macro bodies and `_Generic` associations are not exhaustively analyzed;
there are no synthetic macro context checks. Errors matching a complete
standalone macro definition are retained as explicit coverage limitations.
Call-site errors, partial definitions, surrounding-code errors, missing
handling records and unfinished rules remain blocking.
Private rule copies retain report counters and record the narrow
`stream_open.cocci` compatibility adaptation. Native rules remain unchanged. Findings return
1; incomplete analysis returns 2 (Make maps either failure to 2).
Full output and per-rule coverage are in `.cache/lint/coccicheck.{log,json}`.

## Cppcheck

```sh
make -j8 cppcheck KDIR=/path/to/kernel/build KUNIT_TEST=y
```

The target requires Cppcheck with `--check-level` and `--checkers-report`
support, a prepared kernel with `scripts/clang-tools/gen_compile_commands.py`
and SCST build dependencies. Cppcheck shares its command collector
with `make compile-commands`: Kbuild supplies actual compiler commands from
`.cmd` files, checked against fresh `CHECK` records; userspace Makefiles export
their compile recipes without building executables. Kernel and userspace are
analyzed separately. Nothing is installed or loaded. KUnit coverage follows
`KUNIT_TEST` and the kernel configuration.
The database defines the build configuration;
the wrapper does not add `--force` to explore unrelated configurations.

`make compile-commands KUNIT_TEST=y` writes `compile_commands.json`; override
`COMPILE_COMMANDS` to choose another path. The export includes configured
sources even outside analyzer policy. Cppcheck applies its scope afterwards.
Set `CPPCHECK_PROJECT` and `CPPCHECK_USERSPACE_PROJECT` to reuse that database;
external database freshness is the caller's responsibility. CI always collects
fresh commands.

The target runs the full configured analysis, including header consumers.
Explicit C files absent from the build cause a failure.
Raw compiler commands are retained. Adapted inputs preserve project headers
and selected configuration macros; compiler probes supply the target ABI and
feature queries. Userspace preprocessing retains the real byte-order and Linux
UAPI version macros, as in the historical SCST integration. Kernel header bodies
are replaced by the partial contracts
in `cppcheck/kernel.h` and `kernel.cfg`. This does not check kernel ABI, RCU
or locking semantics.

Native inline exceptions are validated against `cppcheck --errorlist`.
Reviewed system-header omissions and exact unmatched-declaration notices
remain visible as advice. Unknown includes, unknown suppression IDs, parser
failures and missing checker coverage still fail the run. Source findings return 1 and incomplete analysis returns 2; Make
maps both to 2. Full logs and the summary are in `.cache/lint/cppcheck.{log,json}`;
the summary links to captured commands, native XML and checker coverage.

## Checkpatch

```sh
make checkpatch KDIR=/path/to/kernel/build
make checkpatch CHECKPATCH_PATH=/path/to/kernel/scripts
```

The target checks whole C files and headers selected by the common policy,
including userspace and KUnit. It needs the kernel's `checkpatch.pl`,
`spelling.txt` and `const_structs.checkpatch`,
but no compilation or KUnit-enabled kernel. `CHECKPATCH_PATH` overrides `KDIR`.

Native `--strict` checks use the global exceptions in
[policy/checkpatch.json](policy/checkpatch.json): invariant assertions,
kernel-version checks and commit-submission metadata. Commit messages have
separate Conform checks. Local `.checkpatch.conf` files are not loaded.
Policy also recognizes complete `#if`/`#elif` expressions comparing the listed
version macros, and format-only long lines in the listed logging calls.
Version predicates allow `defined` guards, Boolean grouping, vendor `- 0`
forms and matching `>> 8` series comparisons. Unknown expressions remain checked.
Logging exceptions require a literal format argument ending the line; other
arguments, unrelated calls and ordinary long strings remain checked.
Other exceptions use source comments. All exceptions apply only after native
coverage and totals are checked; raw diagnostics and policy reasons remain visible.
Source files are never rewritten.
Findings return 1; missing per-file completion, inconsistent totals, stderr
or tool failures return 2. Make maps both failures to 2. Complete output and
coverage are in `.cache/lint/checkpatch.{log,json}`.

A reviewed interface spelling can use
`checkpatch-suppress-symbol CAMELCASE symbolName=Name ; reason` in a standalone
C comment before a use or declaration of that exact identifier. This exception
applies to that name across selected files, avoiding Checkpatch's first-use
ordering dependency. Other names and diagnostic categories remain checked;
removing or renaming the annotated identifier invalidates the declaration.

`COMPLEX_MACRO` begin/end blocks accept only object-like sense-key, ASC, ASCQ
definitions, one per line, with byte-valued ASC/ASCQ. Comments are allowed;
unrelated code or expressions invalidate the block. Other macro exceptions
must remain attached to individual definitions.

## Source exceptions and provenance

Use a standalone comment immediately before the relevant construct:

```c
/* checkpatch-suppress CONST_STRUCT ; Older kernels require a mutable registration object. */
/* cppcheck-suppress constParameterCallback symbolName=cmd ; Keep the callback ABI. */
/* coccinelle-suppress rule_name ; Explain the reviewed exception. */
```

The parsers also support bounded `-begin`/`-end` blocks, `-macro` and `-file`
where the tool supports them; every declaration requires a reason. File
exceptions affect one named diagnostic, not all findings. The current
Checkpatch file exceptions cover portable ABI integer types and unchanged
legacy license headers. Cppcheck and Coccinelle have no file-wide exceptions.
Checkpatch comment diagnostics attach to the next comment; other line
exceptions attach to the next code line. A longer rationale can precede
the marker, which then refers to it with `See the contract above.`. Checkpatch
markers and reasons may also wrap across a standalone `/* ... */` comment.

SCST contracts and reviewed exceptions come from the frozen historical branch
at `ee5e4173fff7`. Changed historical contexts require a fresh review before
reattaching an exception.
Use the policy inventory above for the complete current list and reasons.

## SCST code style

`make scs_lint` checks [SCS.1](../doc/scs.md#scs1-kunit-visibility-annotations):
KUnit visibility annotations belong on their own line. It uses the common
source policy and checks every preprocessor branch, including KUnit sources.
There are no additional exclusions or diagnostic exceptions.

Use `scripts/scs_lint/run_scs_lint.sh path/to/file.c` for explicit inputs.
The wrapper needs `uv` and Python 3.11+; uv supplies the pinned Tree-sitter
dependencies. No kernel build is needed. Reports are saved in
`.cache/lint/scs_lint.{log,json}`. Findings return 1; incomplete analysis
returns 2 (Make maps both to 2). Empty input is a skip.
`make scs-lint-test` runs the isolated style-rule and CLI fixtures.

## Analyzer CI

The [workflow](../.github/workflows/analyzers.yml) runs on pushes to `master`
and manual dispatch. Separate jobs run `make sparse`, `make smatch`,
`make checkpatch`, `make coccicheck` and `make cppcheck`, including KUnit sources.
`Analyzer script tests` runs `make lint-test`; it does not execute SCST
tests. A parallel `SCST code style` job runs `make scs_lint` without a kernel
build. The container jobs retain reports from `.cache/lint/` for seven days.

CI fails on findings remaining after policy exceptions, just like local Make
targets. The native-analyzer runner returns 1 for completed analysis with
findings and 2 for build/tool failures, incomplete analysis or missing KUnit
coverage.

## Dependencies and tooling tests

Shared analyzer tooling requires Linux, Git and Python 3.10+, using only the
Python standard library. Run its fixtures from the repository root:

```sh
make lint-test                  # PYTHON defaults to python3
```

The fixtures use temporary repositories, files and child processes. They do
not build SCST, load modules or access live devices.
