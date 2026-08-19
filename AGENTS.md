# SCST Repository Guidance

## Scope and context

This file supplies repository-wide context. Before changing a file, read every
`AGENTS.md` from the repository root down to that file; a nested file adds
component-specific rules and does not replace this one. Start by checking
`git status` and preserve unrelated tracked, untracked, ignored, and generated
worktree state.

SCST is a Linux SCSI target stack. The repository contains a kernel target
core, device handlers, transport target drivers, configuration software, and
user-space handlers and daemons.

## Architecture map

- `scst/` owns the SCST core, built-in device handlers, exported kernel
  interfaces, kernel/user ABI headers, and in-tree Kbuild/Kconfig integration.
- `iscsi-scst/` owns the iSCSI target: its SCST kernel driver, control daemon,
  protocol/control interfaces, and optional iSER transport.
- `qla2x00t-32gbit/` is the default, newer QLogic FC target/initiator source
  tree for the top-level out-of-tree build; `qla2x00t/` is the alternative
  legacy tree selected there with `QLA_32GBIT=no`. Generated in-tree patches
  select a tree independently in `scripts/generate-kernel-patch`; inspect its
  current target-kernel condition. The trees are alternatives, not
  interchangeable copies.
- `srpt/`, `fcst/`, and `scst_local/` own the SRP/RDMA, FCoE/libfc, and local
  loopback target drivers respectively.
- `usr/` owns user-space SCST ABI consumers: the `scst_user` file handler,
  ALUA state-change daemon, and event example.
- `scstadmin/` owns the configuration grammar, sysfs discovery and mutation,
  service integration, and configuration application policy.
- `scripts/` owns source, patch, release, checkpatch, regression, and
  performance helpers. `doc/` contains design and ABI references; `www/`
  contains website material. `debian/`, spec templates, `nightly/`, and
  `.github/workflows/` own packaging, nightly, and CI integration.

## Cross-component contracts

- `scst/include/scst.h` is the current target-driver and device-handler
  registration/lifecycle contract. `scst/include/scst_const.h`,
  `scst/include/scst_sgv.h`, `scst/include/scst_debug.h`, and
  `scst/include/backport.h` are shared support interfaces. `backport.h` is the
  common kernel-API compatibility layer used by the core and external modules;
  its availability checks must account for upstream releases, stable-series
  backports, and vendor kernels rather than only `LINUX_VERSION_CODE`. Changes
  require an audit of all in-tree consumers, including every target driver and
  device handler; do not infer callback context, command ownership, teardown
  ordering, or API availability from an old document.
- `scst/include/scst_user.h` plus `scst/src/dev_handlers/scst_user.c` define
  the `/dev/scst_user` ABI consumed by `usr/fileio/`.
  `scst/include/scst_event.h` plus `scst/src/scst_event.c` define the event ABI
  consumed by `usr/events/` and `usr/stpgd/`. Update producers and consumers
  together and preserve explicit version checks where present.
- `scst/SysfsRules`, current sysfs implementations, and the `[key]` metadata
  convention define the user-visible control contract. Target drivers and
  handlers produce it; `scstadmin` discovers and consumes it. Keep management
  operations generic and preserve configuration ordering, especially creating
  objects before attributes/LUNs and enabling a target last.
- `/etc/scst.conf` is produced and consumed by `scstadmin` and service
  integration. iSCSI configuration additionally crosses the kernel/daemon
  control boundary in `iscsi-scst/`. Treat grammar, names, defaults, and
  emitted sysfs values as compatibility-sensitive user interfaces.
- SCSI command, task-management, data-transfer, cancellation, session, and
  target teardown ownership crosses the core/transport boundary. Exact rules
  live in the current `scst.h` callback comments and each driver's receive,
  completion, abort, and unregister paths.
- T10 protection information crosses the core, supporting device handlers,
  and PI-capable target drivers. Use `scst/T10-PI` to locate the concepts, then
  verify capabilities, data and PI scatterlists, actions, and ownership in the
  current `scst.h` declarations and implementations on both sides.

## Verification order and compatibility

This hierarchy is a routing and safety guide, not an interface specification.
Resolve a claim by inspecting the nearest current implementation first:

- Current tracked code, installed/shared headers, and comments next to the
  implementation define actual behavior and interfaces. Executable
  `Makefile`, Kbuild, Kconfig, scripts, and CI definitions define actual build,
  generation, and validation behavior.
- Use `README.md` and `INSTALL.md` for orientation and workflows, and
  `README.clang`, `README.cross-compilation`, `README.module-signing`, design
  documents, and component READMEs for rationale and special cases. Recheck
  every operational or interface claim against current code and recipes.
- Use Git history to explain compatibility intent or an otherwise unclear
  boundary. If prose and implementation differ, do not change behavior merely
  to match prose or copy the discrepancy here; report it and update the
  appropriate source or document when that work is in scope.
- `AGENTS.md` records ownership, coupling, risk, and where to investigate. It
  must not be used as evidence for a callback, field, default, command, path,
  kernel capability, or supported workflow without checking the referenced
  implementation or documentation.

The top-level `Makefile` coordinates `KDIR`, `KVER`, `PASS_CC_TO_MAKE`,
`PKG_BUILD_MODE`, `QLA_32GBIT`, and the component order: core, iSCSI, the
selected QLA tree, SRPT, local, FCST, user programs, then `scstadmin`. Kernel
builds consume `ARCH` and `CROSS_COMPILE`; programs under `usr/` use `CC`
directly, and `scstadmin` uses Perl MakeMaker. Verify propagation in the
current top-level and component recipes before assuming a variable applies to
the whole tree.

- `doc/scst_pg.sgml` and `doc/scst_user_spec.sgml` are design and ABI
  explanations; verify copied declarations and layouts against current
  headers and code.
- `ABT_KERNELS` in `nightly/conf/nightly.conf` is the maintained, canonical
  list of supported upstream and distribution kernels. `nightly/bin/nightly`
  passes it to `scripts/run-regression-tests`; the GitHub Actions regression
  matrix is a practical subset, not the complete support list. Treat changes
  to `ABT_KERNELS` as support-policy changes and keep duplicated CI entries
  aligned where applicable.
- Do not turn historical minimum-kernel claims into policy. Use the nightly
  list, compatibility code/conftests, build recipes, and relevant Git history
  to decide whether a compatibility path is still required. Preserve
  user-visible configuration and ABI behavior unless a deliberate
  compatibility change is in scope.

## Generated state

Consult `.gitignore` and the producing Makefile/script before editing an
unfamiliar file. Never hand-edit generated interface/version headers such as
`scst/include/scst_itf_ver.h`, `scst/include/build_mode.h`, or
`iscsi-scst/include/iscsi_scst_itf_ver.h`; conftest results; MakeMaker output;
module-signing keys; `Module.symvers`; kernel/user objects, modules, binaries,
or dependency files; packaging trees/spec output; release archives; or QLogic
source-extraction and generated in-tree-patch output. Change the source or
recipe and regenerate only when regeneration is part of the task. Treat
`scst/src/certs/*.priv` as generated secrets: never display their contents,
publish, commit, upload, or pass them to certificate-enrollment tooling; only
the public certificate is an enrollment input.

## Validation

- Use the narrowest real entry point from the top-level/component Makefiles.
  The top-level build and packaging workflows are represented by
  `.github/workflows/ci.yml` and `.github/workflows/coverity.yml`.
- Kernel-style checks use `scripts/checkpatch`, `scripts/checkpatch_diff`, or
  `scripts/checkpatch_commits`. The kernel compatibility, compile, sparse, and
  smatch workflow is `scripts/run-regression-tests` as configured by
  `.github/workflows/run_regression_tests.yaml`; it is heavyweight, downloads
  or prepares kernel trees, and is not a quick unit test.
- There is no repository-wide lightweight unit-test target. Read a local
  `AGENTS.md` before using a component `test` target. For instruction-only or
  documentation-only changes, inspect the full diff and run
  `git diff --check`; do not build merely to validate prose.
- Never use an untracked local helper as an established project entry point.

## Safety boundaries

Without explicit authorization for the exact host, devices, transports, and
configuration, do not:

- install or uninstall files, sign/enroll keys, run DKMS/package installation,
  call `depmod`, or start/stop/reload system services;
- load, unload, or reload modules with `modprobe`, `insmod`, or `rmmod`;
- write SCST or initiator sysfs, apply/save live configuration, or change DLM,
  ALUA, persistent-reservation, or HA state;
- export or write a real block device or backing file, create a target, LUN,
  session, login, portal, or initiator connection;
- change iSCSI, FC/FCoE, QLogic HBA, InfiniBand, RoCE, iWARP, or other RDMA
  state, including resets, LIPs, discovery, or fabric logins;
- run destructive/stress/performance tests, especially scripts that write
  devices, create filesystems, drop caches, alter CPU policy, access remote
  hosts, inject faults, or exercise module/service teardown.
