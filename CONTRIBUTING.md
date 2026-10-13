# Contributing to SCST

SCST follows the [Linux kernel coding style][coding-style] for C code and
[Submitting patches][submitting-patches] for commit-message structure. The
rules below describe SCST-specific additions and exceptions.

## Code style

- Preserve the naming and diagnostic conventions of the component being
  changed, including its existing `TRACE_*` and `PRINT_*` macros. The shared
  definitions are in `scst/include/scst_debug.h`.
- Use the repository's `scripts/checkpatch` wrapper. Its ignore list records
  the diagnostics disabled for SCST; do not copy that list into another
  configuration. A disabled diagnostic is not a general style exemption.

## Commit messages

`Signed-off-by:` is optional in SCST. This matches the `MISSING_SIGN_OFF` and
`NO_AUTHOR_SIGN_OFF` exclusions in `scripts/checkpatch`.

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

[AGENTS.md](AGENTS.md#validation) lists the checks to run before handing off
work. The same commands can be run manually; no Git hooks are installed.

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

A failed invocation does not count as a successful check.

Checkpatch requires a kernel `scripts/` directory containing `checkpatch.pl`
and its companion data files. The wrapper defaults to the running kernel's
build tree; set `CHECKPATCH_PATH` to use another prepared directory. Record
the kernel/tool version with the result when it affects diagnostics.

[coding-style]: https://docs.kernel.org/process/coding-style.html
[submitting-patches]: https://docs.kernel.org/process/submitting-patches.html
[conform]: https://github.com/siderolabs/conform
