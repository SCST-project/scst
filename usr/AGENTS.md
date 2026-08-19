# SCST User-Space Programs

## Ownership and interfaces

This directory owns C programs that consume SCST kernel/user interfaces:

- `fileio/` implements a user-space device handler over `/dev/scst_user`.
  `scst/include/scst_user.h` and
  `scst/src/dev_handlers/scst_user.c` own the kernel side of that ABI.
- `stpgd/` consumes SCST events and dispatches ALUA state transitions through
  `scst_on_stpg`. `events/` is a small event-API example and is not part of the
  default `usr/Makefile` build/install set.
- `scst/include/scst_event.h` and `scst/src/scst_event.c` own the event ABI.

These programs do not own generic SCST configuration, backend kernel handler
semantics, or target transport protocols.

## Change boundaries

- Update user and kernel producers/consumers together for any ioctl, event,
  structure layout, command/subcommand, flag, error, or version change. Keep
  fixed-width types, 32/64-bit compatibility, interface versioning where
  present, and ownership/reuse rules for shared buffers and commands.
- For `fileio`, trace registration, memory mapping/allocation, command receive,
  execution, completion, exception, abort, and unregister paths before changing
  lifetime behavior. Use current code and `doc/scst_user_spec.sgml`; do not
  rely on the document alone.
- For `stpgd`, treat event filtering and the external helper invocation as a
  cluster/control boundary. Changes may alter ALUA state on multiple nodes.

## Generated files, validation, and safety

`fileio_tgt`, `stpgd`, the optional `events` binary, `.depend*`, objects, and
installed files are generated artifacts. Build through `usr/Makefile` or the
focused top-level `make usr`; the default build covers `fileio` and `stpgd`,
not `events`. These programs use `CC` directly; kernel `ARCH` and
`CROSS_COMPILE` settings do not by themselves select a user-space cross
compiler. There is no local unit-test target.

Do not run these programs against `/dev/scst_user`, install them, invoke
`scst_on_stpg`, or change ALUA/cluster state without explicit authorization.
Do not point a handler at a real backing file or block device unless the exact
storage and destructive-test scope are approved.
