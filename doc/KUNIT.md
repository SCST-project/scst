# SCST KUnit tests

KUnit checks SCST functions using private fixtures and simulated dependencies.
Use a current kernel with native KUnit; API backports are not supported.
Normal builds leave tests disabled and do not require KUnit headers.

For GitHub Actions, see [CI](CI.md).

## Requirements

Build against a configured and prepared kernel tree with `CONFIG_KUNIT=y/m`.
The iSER test module also requires `CONFIG_INFINIBAND=y/m`.
Run tests in a disposable VM: ordinary SCST initialization discovers SCSI devices.
The runner requires Python 3.11+, kmod utilities, native KUnit autorun control,
`CONFIG_DEBUG_FS=y`, `CONFIG_KUNIT_DEBUGFS=y`, and debugfs mounted at
`/sys/kernel/debug`. The running kernel configuration must be readable through
`/proc/config.gz`, `/boot/config-$(uname -r)`, or
`/lib/modules/$(uname -r)/build/.config`.

For built-in KUnit, boot with `kunit.enable=1 kunit.autorun=0`. For modular
KUnit, install `kunit.ko` matching the running kernel; the runner loads it with
`enable=1 autorun=0`. Leave KUnit's action and filters unset; `filter_glob=*.*`
is also valid. An explicitly empty glob selects no suites.

An already-loaded KUnit must expose valid parameters through sysfs. The runner
rejects invalid or unreadable settings and leaves that module unchanged. If
the kernel hides `enable` or `autorun`, start with KUnit unloaded so the runner
can supply the required parameters itself.

## Build and run

| Target | Purpose |
| --- | --- |
| `kunit-build` | Build all test-owning modules and their dependencies. |
| `kunit-clean` | Clean those component builds and tooling caches; preserve run reports and settings. |
| `kunit-run` | Run selected suites from already-built modules. Requires root. |
| `kunit-test` | Build, then run after successful compilation, including under `make -j`. Requires root. |

```sh
make kunit-build KDIR=/path/to/kernel-build
sudo make kunit-run
```

`kunit-build` sets `KUNIT_TEST=y`. Ordinary builds default to `KUNIT_TEST=n`;
use `make scst KUNIT_TEST=y` to include tests in a core and handler build.
KUnit is supported only by out-of-tree module builds.

Out-of-tree test builds keep the current SCST build mode (`2debug`, `2release`
or `2perf`); a clean tree defaults to debug. KUnit does not change this mode.

Run `make kunit-clean KDIR=/path/to/kernel-build` to clean the test module
builds. Ordinary clean targets also remove KUnit build metadata. Reports and
`.kunit-run.toml` are preserved.

## Labels and logging

`KUNIT_LABEL` selects execution only; every test is compiled. The default `ALL`
runs every suite in the supplied module set. Select space-separated base or
composite labels, or `ALL` alone. Selected sets are combined and each suite
runs once. Empty, unknown or unavailable selections are errors.
`make kunit-list` always shows all source labels, composite descriptions and
their suites, regardless of `KUNIT_LABEL`, without a build, root privileges
or loaded modules. The runner validates selection against the supplied `.ko`
files. Base labels come directly from suite registrations:

| Module | Labels |
| --- | --- |
| `scst.ko` | `ALUA CDB CM EVENT LIB LIFECYCLE ORDER TM UNMAP` |
| `scst_vdisk.ko` | `VDISK` |
| `scst_user.ko` | `USER` |
| `iscsi-scst.ko` | `ISCSI` |
| `isert-scst.ko` | `ISER` |
| `qla2x00tgt.ko` | `QLA` |

`ISER` selects `scst-ISER-cq`, which tests CQ poll errors, batch sizes and
completion ordering inside `isert-scst.ko` using private RDMA fixtures.
No RDMA device is needed. Detecting out-of-bounds pointer formation on a
negative poll result additionally requires kernel `CONFIG_UBSAN_BOUNDS=y`.

`QLA` selects `scst-QLA-pool`, which tests the SCST-owned command/tag helpers inside
`qla2x00tgt.ko`. The build and runner include its matching `qla2xxx_scst.ko`
dependency. Use a disposable VM without a passed-through QLogic HBA:
module initialization still runs. Fixtures stub target registration and
check resource unwinding and destruction; hardware session teardown
requires separate validation.
The fallback bitmap allocation and exhaustion cases also run on current kernels,
even though the normal driver uses sbitmap there. They check word boundaries,
allocation failure, a full or empty pool, and reuse of the last valid tag.

The runner reads suite metadata and dependencies from the modules and loads selected
owners in dependency order. Supply all required SCST modules from the same build;
their argument order does not matter. Modules without suites are accepted only as
dependencies of supplied test owners. For example, `KUNIT_LABEL=VDISK` loads core and
vdisk but runs only VDISK suites. Unselected suites are not counted as skipped.

```sh
sudo make kunit-run KUNIT_LABEL="UNMAP VDISK"
sudo make -j kunit-test KDIR=/path/to/kernel-build KUNIT_LABEL=LIB
```

Composite labels are defined in [labels.toml](../scripts/kunit/labels.toml).
For example, `KUNIT_LABEL=IO` combines `CDB`, `UNMAP` and `VDISK`. Add a table
with base labels, exact suite names, or both:

```toml
[COMMANDS]
description = "Command decoding and virtual disk capacity"
labels = ["CDB"]
suites = ["scst-VDISK-capacity"]
```

Names must be uppercase and cannot replace a base label or `ALL`. References
to other composites and case filters are not supported. Every member of a
selected composite must exist in the supplied module set; missing members
are errors before module operations. Unselected composites do not require
their modules. Original suite names and base labels remain unchanged.

To use a different file, pass `KUNIT_ARGS='--label-config "/path/to/labels.toml"'`
to either `kunit-list` or `kunit-run`. This replaces the default composite
configuration. The selected definitions and expanded suites are recorded in
`result.json`.

`KUNIT_LOG=y` includes optional `scst_kunit_log()` messages emitted during tests;
it defaults to `n` and requires rebuilding. To display these messages, run with
`KUNIT_ARGS=--verbose`. Assertion failure diagnostics are always enabled.

## Runner options

Pass runner options through `KUNIT_ARGS`; `--help` lists them. For example:

```sh
sudo make kunit-run KUNIT_ARGS='--timeout 120 --verbose'
sudo make kunit-run KUNIT_ARGS='--config "/tmp/test settings.toml"'
sudo make kunit-run KUNIT_LABEL=VDISK \
    KUNIT_ARGS='"/tmp/test modules/scst.ko" "/tmp/test modules/scst_vdisk.ko"'
```

Copy [config.example.toml](../scripts/kunit/config.example.toml) to
`.kunit-run.toml` for persistent settings. Command-line options override it.
Module paths come from positional arguments, then the configuration's `modules`
array, then `.kunit-modules` saved by the last successful build. When copying
a build to a VM, include this list and preserve its relative module paths.
Quote each explicit path containing spaces separately.

## Results and cleanup

Suites register without executing on module load; the runner starts selected
suites through debugfs and reads each suite's `results` after its `run` write
completes. Triggering and reading share the operation timeout. The console
shows suite status, groups failure reasons by suite, and identifies the SCST
build and running kernel. `--verbose` adds case logs and full diagnostics;
`NO_COLOR` disables terminal colors.

Each run saves logs, module metadata and JSON/text reports under
`kunit-results/`; `--output` changes the parent directory. Read `report.txt`
for details, `messages.log` for kernel diagnostics and `commands.log` for
module-operation errors. Raw debugfs results are saved as `ktap/<suite>.ktap`,
including incomplete documents. Kernel logs supply diagnostics and detect
unexpected execution; test results come only from debugfs. Full reports are
saved regardless of verbosity.
The runner exits with `0` for PASS/SKIP, `1` for FAIL and `2` for ERROR;
Make reports a failed recipe with its own nonzero exit status.

Completed assertion failures allow subsequent suites to run. Kernel diagnostics
such as an Oops, missing results, lost logs or retained fixtures stop module
operations. Inspect the reports before retrying; the runner never forces
module removal or clears kernel logs.

After completed tests, SCST modules are unloaded in reverse dependency order.
KUnit is removed only if the runner loaded it and SCST cleanup completed;
preloaded KUnit is left unchanged. External dependencies such as `dlm` are
loaded with `modprobe` and left loaded. A clean failure before SCST loads also
releases runner-owned KUnit; incomplete execution can retain modules.

## Add a suite

Keep suites and fixtures under their owning component's `kunit/` directory;
share fixtures only when multiple suites use them. Compile suites as separate
objects. To add a case to an existing suite, add its function and `KUNIT_CASE()`
entry; no build changes are needed. For a new suite:

1. Create its source file and register it with `scst_kunit_suite()`:

   ```c
   scst_kunit_suite(example_suite, "LIB", "-example",
                    .test_cases = example_cases,
   );
   ```

2. Add its object to the owning module's list in `scst/src/kunit/objects.mk`.

The registration supplies the native suite name (`scst-LIB-example` above) and
label metadata. Use a literal uppercase label and an empty or hyphen-prefixed
suffix. Base labels need no separate registration in Makefiles or the runner.
Keep registrations outside preprocessor conditionals so the source list is accurate.
Init-section suites cannot run through debugfs after initialization.

A new test-owning module additionally needs its Kbuild integration and a path in
`scst/src/kunit/modules.mk`; new build components must provide `kunit-build`.
Dependency ordering comes from the built modules, without a Python owner list.

Keep private implementation types in `*_priv.h` and test access declarations
in `*_test.h` beside the owning `.c` file. Guard test declarations with
`SCST_KUNIT_ENABLED`; keep forward declarations needed by ordinary builds in
the `.c` file. Fixtures stay under `kunit/` as `*_fixture.{h,c}`.
`scst/src/scst_test.h` supplies `SCST_KUNIT_VISIBLE` and task-scoped
`SCST_KUNIT_REDIRECT`; normal builds retain static functions and disabled
redirects. Test interfaces are not installed headers or module exports.

Fixtures must tolerate failed initialization and assertions. Bound worker
waits; unfinished work must retain its state and module reference and report
`scst_kunit_retain()`. Document known failures of enabled regression cases and
their execution requirements. Storage and transport integration belongs in
[component tests](../tests/ginkgo/README.md); upstream QLogic initiator/HBA
code is out of scope.

Tooling checks use temporary files and mocked operations, without SCST access:

```sh
python3 -m unittest discover -s scripts/kunit -p 'test_*.py'
```
