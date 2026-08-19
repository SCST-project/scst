# Newer QLogic FC Target Tree

## Ownership and architecture

This is the default QLogic tree selected by the top-level out-of-tree build.
The in-tree patch generator has independent target-kernel selection logic in
`scripts/generate-kernel-patch`. This directory contains a vendor-derived
qla2xxx initiator/HBA driver, its target-mode integration, and the SCST adapter
under `qla2x00-target/`. It is maintained separately from the legacy
`qla2x00t/` tree; verify hardware-support claims in the current device table
and probe code rather than treating either README as an inventory.

- `qla2x00-target/scst_qla2xxx.c` is the SCST target-template adapter.
  `qla2x00-target/qla_tgt.c` and the root `qla_target.c` implement the QLogic
  target side; `qla_target.h` is the internal initiator/target callback and
  data-layout boundary.
- The remaining root qla2xxx sources own HBA probing, firmware/mailbox, fabric,
  interrupt, reset, initiator, and hardware compatibility behavior.
- `Makefile`, `qla2x00-target/Makefile`, Kbuild/Kconfig files, and
  `Makefile_in-tree` own out-of-tree/in-tree composition. The SCST adapter
  depends on the matching qla2xxx module and `scst/src/Module.symvers`.

## Change boundaries

- Preserve the two-module symbol and callback boundary. When changing a
  visible interface or shared data layout in `qla_target.h`, audit both halves
  and the interface-magic convention documented in that header.
- SCST command receive, DMA/data transfer, response, abort/SRR/task management,
  session deletion, target disable, HBA reset, and module teardown form one
  asynchronous lifetime. Re-derive exact lock order, references, workqueue
  ownership, cancellation, and completion-once behavior from current code and
  `scst/include/scst.h`; do not summarize the state machine here.
- A shared SCST target API or sysfs change requires auditing every target
  driver. A QLogic-specific fix should be evaluated for `qla2x00t/`, but must
  not be copied mechanically because the two trees have different internals
  and hardware scope.
- Preserve kernel/backport feature handling in current build/code; do not use
  a version-only shortcut where the tree already has a feature test.

## Generated files, validation, and safety

Objects, modules, `Module.symvers`, dependency metadata, extracted upstream
qla2xxx trees, and generated in-tree patch sets are artifacts. Do not edit
them or run extraction/patch-generation helpers unless that regeneration is
explicitly requested. Use the top-level selected-QLogic build or this
component's Makefile for compile validation; no hardware unit-test target is
provided.

Never load/unload this driver, bind an HBA, enable target mode, expose WWPNs or
LUNs, log into a fabric, issue a LIP/reset, flash/query firmware through active
hardware, or run teardown/error-injection tests without authorization for the
exact host, HBA ports, fabric, initiators, and backing devices.
