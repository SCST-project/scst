# scstadmin

## Ownership and verification map

This directory owns the `scstadmin` command, SCST Perl module, configuration
grammar and serialization, live sysfs discovery/mutation, and init/systemd
integration. It does not define kernel attributes or transport semantics.

- `scstadmin` is a tracked symlink to `scstadmin.sysfs/`.
  `scstadmin.sysfs/scstadmin` is the current parser, comparison, ordering, and
  apply implementation.
- `scstadmin.sysfs/scst-1.0.0/lib/SCST/SCST.pm` owns sysfs discovery and
  low-level mutations. `scst/SysfsRules` and current kernel sysfs code define
  the producer side.
- `scstadmin.sysfs/man5/scst.conf.5` and
  `scstadmin.sysfs/man1/scstadmin.1` document the public format and CLI. Verify
  details against the current parser before changing behavior; the manpage
  date is not proof that the parser is unchanged.
- `Makefile`, `scstadmin.sysfs/Makefile`,
  `scstadmin.sysfs/scst-1.0.0/Makefile.PL`, packaging templates, and service
  scripts implement build/install integration.

## Compatibility and coupled changes

- Treat stanza names, nesting, quoting/comments, attribute spelling, defaults,
  warning/error behavior, and emitted ordering as user-visible compatibility
  contracts. Current code still recognizes a deprecated format; do not remove
  or silently reinterpret it without an explicit migration decision.
- Discovery must remain driven by sysfs and `[key]` metadata. Do not hard-code
  a transport's dynamic attributes into generic code when the kernel can
  describe them.
- Changes to kernel management commands, attributes, defaults, or enablement
  order require auditing `SCST.pm` and the read/write/compare/apply paths.
  Conversely, grammar changes must be checked against service startup,
  examples, manpages, all target drivers, and iSCSI daemon requirements.
- Applying a partial configuration can affect live targets not named by the
  file. Preserve the explicit `-force` boundary and inspect Git history when
  changing reconciliation/removal behavior.

## Generated files, validation, and safety

Perl MakeMaker output under `scstadmin.sysfs/scst-1.0.0/`, including
`Makefile`, `Makefile.old`, `blib/`, `MYMETA.*`, and `pm_to_blib`, is
generated. Packaging trees/spec output, archives, and installed-script
substitutions are generated too. Do not edit them manually.

The component `make test` is not an isolated parser unit suite: its tests can
kill/start daemons, load/unload modules, and create/remove live SCST objects.
`scstadmin -check_config` also requires root and a live SCST sysfs view. Run
neither without explicit authorization for a disposable SCST test host.

Do not invoke configuration apply/write/clear operations, service scripts,
module management, LIP/reset helpers, or tests against a real host without an
approved configuration and recovery plan.
