# Contributing to SCST

SCST follows the [Linux kernel coding style][coding-style] for C code and
[Submitting patches][submitting-patches] for commit-message structure. The
rules below describe SCST-specific additions and exceptions.

## Code style

- Preserve the naming and diagnostic conventions of the component being
  changed, including its existing `TRACE_*` and `PRINT_*` macros. The shared
  definitions are in `scst/include/scst_debug.h`.
- Use `make checkpatch`. Its global exceptions are recorded with reasons in
  `scripts/policy/checkpatch.json`; local exceptions belong beside the source.
  A disabled diagnostic is not a general style exemption.

## Commit messages

`Signed-off-by:` is optional in SCST. Commit messages are checked separately
from source style, using Conform and review.

Use a prefix from the registry below in the kernel-style subject:

```text
scst_vdisk: Refresh thin provisioning after backend changes
scripts: Add commit message checks
```

Choose the most specific registered prefix that describes the change. Add a
new prefix and its scope to this registry before using it. Existing history
contains aliases and ad hoc path prefixes; their presence alone does not
register them for new commits. Standard Git-generated merge and revert
subjects retain their usual form.

### Prefix registry

| Prefix | Scope |
| --- | --- |
| `scst` | Core changes spanning several core components. |
| `scst_main` | Core registration, initialization and lifecycle. |
| `scst_lib` | Core command and device helpers. |
| `scst_targ` | Core command execution and target processing. |
| `scst_mem` | Core memory and scatter-gather allocation. |
| `scst_sysfs` | Core sysfs interfaces. |
| `scst_pres` | Persistent reservations. |
| `scst_dlm` | Cluster and DLM integration. |
| `scst_event` | Core event interface. |
| `scst_copy_mgr` | Copy manager. |
| `scst_debug` | Shared tracing and diagnostics. |
| `scst_vdisk` | Virtual disk handlers. |
| `scst_user` | User-space device-handler interface. |
| `scst_disk`, `scst_tape`, `dev_handlers` | Physical disk, tape, or shared device-handler changes. |
| `scst/include/backport.h` | Shared kernel compatibility helpers. |
| `iscsi-scst`, `iscsi-scstd`, `isert-scst` | iSCSI target, control daemon, or iSER transport. |
| `qla2x00t-32gbit`, `qla2x00t` | Newer or legacy QLogic tree, respectively. |
| `srpt`, `fcst`, `scst_local` | SRP, FCoE, or local target driver. |
| `scstadmin` | Configuration utility, Perl library and service integration. |
| `scripts` | Repository development and maintenance scripts. |
| `tests` | Component tests and their framework. |
| `kunit` | KUnit infrastructure, tooling and unit tests. |
| `build` | Build system and packaging. |
| `dpkg` | Debian package generation. |
| `nightly build` | Nightly kernel matrix and automation. |
| `.github/workflows` | GitHub Actions workflows. |
| `docs`, `www` | Project documentation or website material. |
| `.gitignore` | Repository ignore rules. |

For new commits, use `srpt` instead of the historical `ib_srpt`,
`.github/workflows` instead of `github`, and `build` instead of `Makefile`,
`Makefiles` or `kbuild`. If a change spans several areas, select the area that
motivated it rather than combining prefixes with commas. An established
subarea may follow the prefix, for example `qla2x00t-32gbit: target: ...`.

## Local checks

Run applicable checks from the repository root before submitting a change.
Use the resolved base commit of the series as `<base>`, rather than a moving
branch name. Inspect the final diff, including new and untracked files intended
for the patch. No Git hooks are installed.

| Change | Required local checks |
| --- | --- |
| Any change | `git diff --check <base>`. |
| Prepared commits | Conform as described below; review prefixes against the registry above. |
| C sources or headers | `make checkpatch`; this checks the complete maintained source scope. |
| Shell scripts or sourced shell files | Syntax checks and ShellCheck as described below. |
| Python files | `python3 -m py_compile <changed-files>`. |
| Go files | `gofmt -l <changed-files>` must produce no output; follow component guidance. |

Fix diagnostics introduced by the change; report any remaining diagnostic
with its location and reason. Do not extend ignore lists just to pass.
Record the checked base and HEAD, commands, results and checks not run. A
missing tool or failed invocation is not a passed check. After changing code
or commit messages, rerun the affected checks on the final version.

### Shell scripts

For Bash files, run `bash -n <file>` for each file and
`shellcheck -x -P SCRIPTDIR <changed-files>`. For POSIX shell files, use
`sh -n` and ShellCheck's `sh` dialect. Check sourced files with the caller's
dialect if they have no shebang. Include new files and files outside
`scripts/`: `make shellcheck` covers only Bash scripts under `scripts/`
whose paths already exist in `HEAD`.

### Commit checks

Commit checks use [Conform][conform] (`v0.1.0-alpha.30` was used to validate
this configuration), available as `conform` on `PATH`. `.conform.yaml`
checks the kernel-style subject length and trailing punctuation. Prefix
selection and the explanation of the change require review. Conventional
Commits validation is deliberately disabled because SCST prefixes include
hyphens, spaces and paths.

For a nonempty linear series with an ancestor base, run
`conform enforce --revision-range <base>..HEAD` from the repository root.
Conform's range traversal in the version above does not work in linked Git
worktrees. In a linked worktree, or for a history containing merges, check
each non-merge commit in `<base>..HEAD` using a message file outside the
repository:

```sh
git show -s --format=%B <commit> > <message-file>
conform enforce --commit-msg-file <message-file>
```

Checkpatch requires a kernel `scripts/` directory containing `checkpatch.pl`
and its companion data files. Set `KDIR` to select a kernel build tree or
`CHECKPATCH_PATH` to use another prepared scripts directory. Record
the kernel/tool version with the result when it affects diagnostics.

### Analyzer tooling

Run `make lint-test` for isolated analyzer-tooling fixtures and
`make analyzer-tests` for native model probes in the analyzer environment. See the
[scripts guide](scripts/README.md#shared-analyzer-source-scope) for source
selection, exact exclusions and tooling requirements.

## Builds and tests

Use the narrowest applicable target from the top-level or component Makefile.
[INSTALL.md](INSTALL.md) covers build prerequisites and installation;
`make help` lists targets and variables. Build and packaging workflows live
in `.github/workflows/ci.yml` and `.github/workflows/coverity.yml`.

- [KUnit](doc/KUNIT.md) checks kernel functions with private fixtures and
  simulated dependencies. Its guide covers module builds, VM execution,
  fixture cleanup and userspace checks for the runner.
- [Ginkgo component tests](tests/ginkgo/README.md) exercise management,
  SCSI commands and data I/O through a configured SCST target.
  `make ginkgo-check` checks the framework only; follow the guide before
  running tests that load modules or access storage.

`make sparse` and `make smatch` analyze the configured modules; use
`KUNIT_TEST=y` to include KUnit sources. Their policies and reports are described
in the [scripts guide](scripts/README.md#sparse-and-smatch).

`scripts/kernel/run-regression-tests` checks kernel compatibility through
compilation. It downloads or prepares kernel trees and is
separate from the analyzer targets above. The nightly support matrix is
`ABT_KERNELS` in `nightly/conf/nightly.conf`; CI exercises a subset in
`.github/workflows/run_regression_tests.yaml`.

Report static checks, compilation and executed tests separately. Static
checks do not establish build or runtime correctness. Documentation-only
and instruction-only changes do not require a build or a live test run.

[coding-style]: https://docs.kernel.org/process/coding-style.html
[submitting-patches]: https://docs.kernel.org/process/submitting-patches.html
[conform]: https://github.com/siderolabs/conform
