# SCST KUnit tooling

Read [the KUnit guide](../../doc/KUNIT.md). The runner owns module execution,
log capture and reporting; kernel fixtures belong beside their owning module.
`upstream/` is a pinned public Linux parser: preserve its provenance and keep
SCST-specific behavior outside it.

Missing results, lost log records, retained fixtures and kernel diagnostics
must not become a pass. Preserve evidence on errors; never force module
removal or clear logs. Both console modes must retain full report artifacts.
Userspace regression tests must use temporary files and mocked module/log
operations. Running them does not authorize loading SCST on the host.
