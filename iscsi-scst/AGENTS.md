# iSCSI-SCST

## Ownership and boundaries

This directory owns the SCST iSCSI target across kernel and user space:
`kernel/` implements the target and network data path, `usr/` implements
`iscsi-scstd` and its control/configuration logic, `include/` holds their
shared control interfaces, and `kernel/isert-scst/` adds the optional iSER/RDMA
transport. It depends on the SCST core and does not own generic SCST LUN/device
semantics or the top-level `scst.conf` grammar.

## Where to verify behavior

- `include/iscsi_scst.h` is the shared kernel/daemon ioctl and netlink ABI.
  `kernel/config.c`, `kernel/event.c`, `usr/ctldev.c`, and `usr/event.c` are
  its principal producers/consumers. Preserve fixed-width layout, compat
  handling, and `ISCSI_SCST_INTERFACE_VERSION` registration checks.
- `kernel/iscsi_hdr.h` and `usr/iscsi_hdr.h` express the same wire protocol in
  environment-specific forms; they are not generated copies. Audit both sides
  for a protocol PDU, field, digest, or byte-order change.
- `include/iscsit_transport.h` is the private kernel transport boundary used
  by the base iSCSI code and iSER. Changes require auditing both
  implementations.
- Verify behavior in current code, `Makefile`, Kbuild/Kconfig files, and
  conftests. Use `README`, HOWTOs, and man pages to locate workflows and
  compatibility intent, then recheck their commands, defaults, and interfaces
  against the implementation. The daemon is part of the functioning target,
  not a replaceable convenience utility.
- `usr/config.c` implements the retained `/etc/iscsi-scstd.conf` parser, and
  `usr/iscsi_adm.c` implements the legacy runtime administration client. Treat
  both as compatibility interfaces. New persistent configuration belongs to
  `scstadmin` and `/etc/scst.conf`, whose grammar is outside this directory.

## Coupled changes

- Change the kernel and daemon together for control messages, target/session/
  connection parameters, authentication policy, events, or daemon-open state.
  Keep the generated interface hash/version check; never edit
  `include/iscsi_scst_itf_ver.h` directly.
- Sysfs attributes and `[key]` metadata are consumed by `scstadmin`; audit its
  discovery, write, and configuration serialization paths when changing them.
- Command receive, write-data completion, response, abort, task management,
  connection close, session unregister, and target teardown cross the SCST and
  network lifecycles. Re-derive exact reference, locking, and completion order
  from current kernel code and `scst/include/scst.h`.
- iSER compatibility is selected by RDMA/OFED conftests and symbols. Do not
  replace feature tests with an assumed kernel-version boundary.

## Generated files, validation, and safety

Conftest results/build logs, the interface-version header, `.depend*`, objects,
modules, `Module.symvers`, and `usr/iscsi-scstd`/`usr/iscsi-scst-adm` are build
artifacts. Change their sources or recipes instead.

The focused compile entry point is top-level `make iscsi` or `make -C
iscsi-scst`; it builds both user and kernel parts and may run compatibility
conftests. There is no component unit-test target; use repository CI,
checkpatch, and regression entry points as appropriate.

Do not install or run the daemon, open portals, apply iSCSI configuration,
create targets/sessions/connections, perform discovery/login/logout, manipulate
CHAP secrets, or alter TCP, network-namespace, iSER, or RDMA state without
explicit authorization for both endpoints and the network. Legacy
`iscsi-scst-adm` account operations can expose CHAP secrets through process
arguments and shell history; do not invoke them with real credentials unless
that exposure and cleanup are explicitly accepted.
