# SCST Local Target

## Ownership and interfaces

This directory owns the `scst_local` loopback target: it presents SCST-exported
LUNs back to the same kernel through the SCSI midlayer. `scst_local.c` owns the
SCST target template, local SCSI host/command bridge, target/session management,
TransportID attributes, error handling, and teardown. `Kbuild`, `Makefile`, and
`in-tree/` own out-of-tree and in-tree composition.

Start with `scst/include/scst.h` for the common target-driver contract and
`scst/SysfsRules` for common configuration conventions, then verify both in
their current implementations. `README` documents the local sysfs additions
and the user-space-target use case, but exact locking and lifecycle behavior
must be read from current code.

## Change boundaries

- One command crosses both the local SCSI initiator lifecycle and the SCST
  target lifecycle. Preserve completion-once, abort/reset, queueing, sense/data,
  session, device-release, and target-unregister ownership across both sides.
- Session/adapter removal interacts with SCST and device-model locks. Re-derive
  the current lock order and deferred-release requirements before changing
  close or teardown paths; do not call device removal while holding a lock that
  the callback path can reacquire.
- Sysfs management commands and target/session attributes are consumed by
  `scstadmin`. Audit parser/serializer/discovery behavior for changes. A shared
  SCST callback change still requires all target drivers to be checked.

## Generated files, validation, and safety

Objects, modules, `Module.symvers`, and dependency metadata are generated.
The focused compile entry point is top-level `make scst_local` or this
component's Makefile; no component unit-test target exists.

This driver can expose storage recursively on the same host. Never load it,
create local targets/sessions/LUNs, mount or use returned devices, or run abort/
reset/teardown tests without explicit authorization. In particular, preserve
the backing-mode restrictions implemented by the current I/O and allocation
paths; use `README` to locate the risk, not as a substitute for checking the
code. Unsafe local use can recurse into memory reclaim and deadlock or corrupt
the backing storage.
