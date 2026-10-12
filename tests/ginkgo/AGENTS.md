# SCST Component Tests

Use [README.md](README.md) for setup, configuration, commands and recovery.
`suite/` owns local tests; `internal/` owns shared configuration, execution
and fixtures.

## Interfaces and lifecycle

- Management operations and assertions use `scstadmin`, never direct sysfs or
  Perl-library calls. A rejection covers the whole management chain, not
  necessarily a kernel check. Check operation errors even with exit status 0.
- Use shared command runners with contexts, timeouts, logs and failure handling.
  Execution failures must not satisfy assertions for expected rejections.
- Keep ownership and cleanup explicit for configuration, sessions and modules.
  Restore changed global settings; global SCST clearing belongs only to
  explicit clear-config tests.
- Failed cleanup or uncertain command completion must stop subsequent specs.
  Preserve artifacts and residual resources for inspection instead of forcing
  cleanup.
- Module loading and unloading belong to the suite lifecycle.

## Validation

`make ginkgo-check` checks the framework; `ginkgo-list` and `ginkgo-config`
check selection and configuration without SCST access.
Live targets load or replace modules and mutate storage on the test host;
the root authorization rules apply. Dry runs do not validate SCST behavior.
Keep generated `results/` and local profiles out of commits.
