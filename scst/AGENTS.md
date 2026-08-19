# SCST Core and Device Handlers

## Ownership

This directory owns the SCST kernel core, its in-tree device handlers, common
headers, persistent-reservation/DLM integration, sysfs implementation, and
Kbuild/Kconfig integration. It does not own transport-specific protocol state,
the `scstadmin` configuration parser, or user-space handler behavior.

## Where to verify interfaces

- Start with `include/scst.h` and its current callback comments for target
  templates, device types, sessions, commands, task management, transfer
  callbacks, execution context, and registration/unregistration. Verify a
  change against the definitions and call sites that implement the contract.
- `include/scst_const.h`, `include/scst_sgv.h`, `include/scst_debug.h`, and
  `include/backport.h` are shared with external modules. `src/Makefile`,
  `src/Kbuild`, `src/dev_handlers/Kbuild`, and the Kconfig/Makefile in-tree
  files own build composition and compatibility plumbing.
- `SysfsRules` plus `src/scst_sysfs.c`, `src/scst_tg.c`, `src/scst_targ.c`,
  and handler sysfs code define the control surface consumed by `scstadmin`.
- `include/scst_user.h`/`src/dev_handlers/scst_user.c` and
  `include/scst_event.h`/`src/scst_event.c` are kernel/user ABI pairs.
  `doc/scst_user_spec.sgml` and `doc/scst_pg.sgml` are explanatory references,
  not substitutes for current code.
- `T10-PI` explains the protection-information boundary. Verify its interface
  details in current `_dif_` declarations and implementations, and audit the
  supporting handler and every PI-capable target driver together.
- `src/scst_dlm.c` and `src/scst_pres.c` implement DLM-backed persistent-
  reservation handling. Use `README.dlm` and `README.drbd` for background, not
  as deployment scripts. Verify `cluster_mode`, lockspace naming, and
  `t10_dev_id` behavior in current code; SCST does not own membership, quorum,
  fencing, or resource-manager policy.

Headers installed by `src/Makefile` are shared interfaces, even when most
consumers are in this repository. Everything under `src/` that is not exported
through those headers or sysfs is internal unless current code establishes
otherwise.

## Change boundaries

- A change to `scst.h` or shared constants requires auditing every target
  driver, every device handler, generated interface hashes, and out-of-tree
  compatibility implications. Do not bypass or hard-code the interface
  version mechanism.
- A `scst_user.h` or `scst_event.h` change must update its kernel producer and
  all `usr/` consumers together. Keep fixed-width layout, compat-ioctl, buffer
  ownership, and explicit version checks intact where they exist; do not make
  an unversioned event-layout change silently.
- A sysfs name, `[key]` marker, management command, ordering rule, or default
  is also a `scstadmin` compatibility change. Audit save, parse, compare, and
  apply paths before changing it.
- Device handlers own SCSI command parsing/execution and backend semantics;
  the core owns generic command/session lifecycle. Preserve the documented
  atomic-versus-thread context, completion-once, abort/cancellation, reference,
  and unregister contracts. Re-derive exact locking and callback sequences
  from current code for each change.

## Kernel compatibility and backports

`include/backport.h` is the shared compatibility layer for kernel APIs used by
the core, handlers, and target drivers. Keep its entries grouped and sorted by
the upstream header that owns the API, as required by the file prologue. Model
actual API availability: inspect the upstream introduction, stable-series
backports, and relevant RHEL, UEK, SUSE, or Ubuntu differences instead of
assuming that the base kernel version is sufficient.

- For a generic kernel helper or type, keep normal call sites on the current
  API and put the narrow compatibility wrapper, alias, or fallback in
  `backport.h` when that matches existing practice. Keep behavior-specific
  branches and component capability probes, such as RDMA conftests, with the
  component that owns them.
- `backport.h` is included through `scst.h` and `scst_debug.h` and is installed
  for external module builds. Audit the core, device handlers, all target
  drivers, and installed-header consumers after changing it. Do not assume
  that the generated interface hash detects every installed-header change;
  verify the current hash inputs in `src/Makefile`.
- `scripts/generate-kernel-patch` includes this header in generated in-tree
  patches, and `scripts/specialize-patch` evaluates recognized compatibility
  predicates. Audit both scripts when adding a new predicate form or vendor
  feature macro.
- Use the root-defined `ABT_KERNELS` matrix in `nightly/conf/nightly.conf` as
  the support boundary. Do not remove an old compatibility branch based only
  on a README minimum or mainline age; first confirm that no listed upstream
  or distribution kernel needs it. Backport changes call for focused
  multi-kernel regression coverage around the affected version boundary and
  representative vendor kernels.

## Generated files and validation

`include/scst_itf_ver.h` is generated from interface header hashes;
`include/build_mode.h`, `build_mode`, signing keys under `src/certs/`,
`Module.symvers`, objects, modules, and dependency metadata are build state.
Do not edit them manually. Build-mode targets change generated state. Private
keys under `src/certs/` are secrets; their contents must not be displayed, and
the keys must not be committed, uploaded, or supplied to enrollment tools.

The focused compile entry point is top-level `make scst` (or the component
Makefile with the same `KDIR`/toolchain assumptions). Kernel-style and
multi-kernel checks are the repository scripts and CI workflows named in the
root instructions. No separate lightweight core unit-test target exists.

Never install/load the core or handlers, configure sysfs, attach/export
devices, enable debug fault injection, or exercise DLM/HA/persistent-
reservation state without explicit environment and device authorization.
