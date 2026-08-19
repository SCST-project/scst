# FCST

## Ownership and interfaces

This directory owns the SCST FCoE target built on the kernel libfc stack.
`ft_scst.c` is the SCST target-template boundary, `ft_sess.c` owns libfc local/
remote port to SCST target/session mapping, `ft_cmd.c` and `ft_io.c` own FCP
command/data/response processing, and `fcst.h` is the private shared interface.
It depends on both SCST and libfc; it does not own generic FCoE initiator/DCB
configuration.

`Kbuild`, `Kconfig`, and `Makefile` define the in-tree/out-of-tree build,
SCST symbol dependency, and libfc compatibility selection. Current source and
kernel headers implement the behavior; use `README` to locate operational
workflows and verify every example against them.

## Change boundaries

- Preserve command ownership across libfc exchanges/frames and SCST commands.
  Data buffers cannot be released until their asynchronous libfc consumer is
  finished; audit response, write-data, abort, timeout, and task-management
  completion paths together.
- Port/session lookup and teardown use mutex, RCU, and kref lifetimes while
  libfc notifications and SCST unregister callbacks interact. Re-derive exact
  lock, grace-period, reference, and callback order from current code.
- SCST API or sysfs changes require the repository-wide target-driver and
  `scstadmin` audits. libfc API adaptation belongs in the established build/
  compatibility boundary, not in user-visible configuration.

## Generated files, validation, and safety

Objects, modules, `Module.symvers`, and dependency metadata are generated.
The focused compile entry point is top-level `make fcst` or this component's
Makefile; no component unit-test target exists.

Do not load/unload FCST or FCoE modules, configure DCB/FCoE interfaces, enable
FC ports/targets, expose LUNs, create fabric sessions, issue a LIP/reset, or
run traffic/teardown tests without authorization for the exact host, CNA,
Ethernet fabric, initiators, and storage.
