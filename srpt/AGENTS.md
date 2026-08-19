# SRPT

## Ownership and sources of truth

This directory owns the `ib_srpt` SCST target over SRP on InfiniBand and,
through RDMA/CM, RoCE or iWARP. `src/ib_srpt.c` and `src/ib_srpt.h` own the
transport, channel/session, RDMA, command, and teardown implementation.
`src/Kbuild`, `src/Kconfig`, `Makefile`, and `conftest/` own its in-tree,
out-of-tree, distribution-RDMA, and OFED compatibility.

`session-management.txt` is a useful lifecycle design reference and `README`
describes configuration. Verify exact states, callbacks, and supported APIs in
current code and conftests. `README_in-tree` and `README.ofed` are historical
integration procedures. `Testing.txt` is a privileged maintainer checklist
with historical steps, not an automated test suite, and
`Measurement-Results.txt` is a hardware-specific historical snapshot; none of
these establishes current kernel, OFED, test, or performance policy.

## Change boundaries

- The driver depends on SCST target/session APIs and RDMA core/CM/IB APIs.
  Preserve SCST and RDMA object references across login/relogin, QP completion,
  data transfer, abort/task management, disconnect, session unregister, port
  removal, and module exit.
- Completion, CM callbacks, async events, work, and SCST callbacks can race.
  Re-derive current channel state, mutex/spinlock context, completion-once, QP
  drain, and asynchronous free ordering from code for every lifecycle change.
- Keep RDMA/OFED conftests as capability probes. Do not replace them with
  unverified kernel- or vendor-version assumptions.
- Changes to SCST callbacks or sysfs `[key]` attributes require the repository-
  wide driver and `scstadmin` audits described in the root instructions.

## Generated files, validation, and safety

`conftest/*/result-*.txt`, conftest build logs, objects, modules,
`Module.symvers`, and dependency metadata are generated. The focused compile
entry point is top-level `make srpt` or this component's Makefile; the build
runs compatibility conftests. There is no safe local unit-test target.

The procedures in `Testing.txt` include module/service churn, sysfs writes,
remote initiator logins, resets, fault injection, filesystems, stress I/O, and
device-overwriting benchmarks. Run none of them without explicit disposable
target/initiator, HCA ports, fabric, devices, and recovery authorization. Do
not install OFED, change RDMA state, or load/unload SRP modules implicitly.
