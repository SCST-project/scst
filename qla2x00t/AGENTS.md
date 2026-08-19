# Legacy QLogic FC Target Tree

## Ownership and architecture

This is the legacy QLogic qla2xxx/SCST target tree selected by the top-level
out-of-tree build with `QLA_32GBIT=no`; it is not that build's default. The
in-tree patch generator has independent target-kernel selection logic in
`scripts/generate-kernel-patch`. This directory contains a patched
initiator/HBA source tree plus the SCST target addon in `qla2x00-target/`.
Treat its hardware scope and behavior as distinct from
`qla2x00t-32gbit/`.

- `qla2x00-target/qla2x00t.c` owns the SCST target template and transport
  lifecycle. `qla2x_tgt_def.h`/`qla2x_tgt.h` define the private callback and
  shared-data boundary between the initiator and target halves.
- The root qla2xxx sources own HBA, firmware, fabric, interrupt, reset, and
  initiator behavior. `Makefile`, `qla2x00-target/Makefile`, Kbuild/Kconfig
  files, and in-tree recipes own module composition and kernel compatibility.
- Out-of-tree target mode uses matching qla2xxx and target modules plus SCST
  symbols; preserve `BUILD_2X_MODULE` and `Module.symvers` assumptions.

## Change boundaries

- Audit both halves for callback signature, shared structure, ownership, or
  module-order changes, and update the interface-magic convention documented
  in `qla2x_tgt_def.h` when its visible boundary changes. Keep SCST command/
  session/target references valid across receive, DMA, response, abort/task
  management, fabric logout, HBA reset, and unregister; derive exact locks and
  teardown sequence from current code.
- A shared SCST API/sysfs change requires auditing all target drivers. Evaluate
  QLogic-specific fixes for the newer tree too, but do not mechanically port
  code between different driver generations.
- Use the README and HOWTO to locate operational concepts, but verify hardware
  support in `qla2xxx_pci_tbl[]` in `qla_os.c` and NPIV behavior in the current
  target-template callbacks. Do not import claims from another revision or
  from the newer tree without code and history support.

## Generated files, validation, and safety

`qla2xxx-orig/`, `in-tree-patches/`, modules, objects, `Module.symvers`, and
dependency files are generated/extracted output. Never hand-edit them or run
download/extraction/patch-generation scripts unless explicitly requested.
Compile through the selected top-level QLogic target or this component's
Makefile; there is no hardware unit-test target.

Do not load/unload modules, bind or reset an HBA, enable target mode, expose
WWPNs/LUNs, change fabric sessions, issue LIPs, or run hardware teardown tests
without approval for the exact host, HBA ports, fabric, initiators, and storage.
