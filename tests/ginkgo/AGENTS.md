# SCST Component Tests

Use [README.md](README.md) for setup, configuration, commands and recovery.
`suite/` owns local tests, `iscsi/` owns target/SSH-initiator tests, and
`internal/` owns shared configuration, execution and fixtures.

## Interfaces and lifecycle

- Management operations and assertions use `scstadmin`, never direct sysfs or
  Perl-library calls. A rejection covers the whole management chain, not
  necessarily a kernel check. Check operation errors even with exit status 0.
- Initiator management uses `iscsiadm` over SSH.
- Use shared command runners with contexts, timeouts, logs and failure handling.
  Execution failures must not satisfy assertions for expected rejections.
- Keep ownership and cleanup explicit for configuration, backing files,
  sessions, node/iface records, the daemon and modules. Restore changed global
  settings; never use global initiator logout, deletion or service restarts
  as cleanup. Global SCST clearing belongs only to explicit clear-config tests.
- Failed cleanup or uncertain command completion must stop subsequent specs.
  Uncertain initiator state must prevent target teardown. Preserve artifacts
  and residual resources for inspection instead of forcing cleanup.
- Prepare only selected transport groups; complete local teardown before
  iSCSI setup. Module loading and unloading belong to the suite lifecycle.

## Validation

`make ginkgo-check` checks the framework; `ginkgo-list` and `ginkgo-config`
check selection and configuration without SCST or remote-host access.
Live targets load or replace modules and mutate storage on selected hosts;
the root authorization rules apply. Dry runs do not validate SCST behavior.
Keep generated `results/` and local profiles out of commits.
